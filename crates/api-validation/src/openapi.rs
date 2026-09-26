use anyhow::{bail, ensure, Context, Result};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use storage::hash;
use url::Url;

use crate::{
    canonical_http_url, make_probe_id, materialize_request_url, normalize_media_type,
    ApiValidationPlan, MediaContract, NormalizedOpenApi, NormalizedSchema, OperationContract,
    OperationSelector, ReceiptLineage, ResponseContract, StatusSelector, UnsupportedKeyword,
    ValidationBounds, API_VALIDATION_SCHEMA_VERSION,
};

/// Transient parser input. The document bytes are parsed into contracts and
/// hashed but are never retained in the normalized output.
pub struct OpenApiDocumentInput<'a> {
    pub source_url: &'a str,
    pub document: &'a [u8],
    pub receipt: ReceiptLineage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpenApiVersion {
    V2,
    V3,
}

pub fn normalize_openapi(
    input: OpenApiDocumentInput<'_>,
    plan: &ApiValidationPlan,
) -> Result<NormalizedOpenApi> {
    let plan = plan.canonicalized()?;
    ensure!(
        input.document.len() <= usize::try_from(plan.bounds.max_document_bytes)?,
        "OpenAPI document exceeds max_document_bytes"
    );
    ensure!(!input.document.is_empty(), "OpenAPI document is empty");
    ensure!(
        canonical_http_url(input.source_url)? == input.source_url,
        "OpenAPI source URL is not canonical"
    );
    input.receipt.validate()?;

    let root = parse_document(input.document)?;
    let root_object = root
        .as_object()
        .context("OpenAPI document root must be an object")?;
    let version = detect_version(root_object)?;
    let selectors: Vec<_> = plan
        .selectors
        .iter()
        .filter(|selector| selector.openapi_source_url == input.source_url)
        .cloned()
        .collect();
    ensure!(
        !selectors.is_empty(),
        "plan has no selector for this OpenAPI source URL"
    );

    let paths = root_object
        .get("paths")
        .and_then(Value::as_object)
        .context("OpenAPI paths must be an object")?;
    let mut ref_state = RefState::new(&plan.bounds);
    let mut operations = Vec::with_capacity(selectors.len());
    for selector in selectors {
        selector.validate()?;
        let path_value = paths
            .get(&selector.path)
            .with_context(|| format!("selected path not found: {}", selector.path))?;
        let path_value = resolve_direct_ref(&root, path_value, &mut ref_state, 0)?;
        let path_object = path_value
            .as_object()
            .context("selected OpenAPI path item must be an object")?;
        let operation_value = path_object
            .get(selector.method.as_lowercase())
            .with_context(|| {
                format!(
                    "selected operation not found: {} {}",
                    selector.method.as_lowercase(),
                    selector.path
                )
            })?;
        let operation_value = resolve_direct_ref(&root, operation_value, &mut ref_state, 0)?;
        let operation = operation_value
            .as_object()
            .context("selected OpenAPI operation must be an object")?;
        validate_operation_id(&selector, operation)?;
        reject_authenticated_operation(root_object, operation)?;
        reject_required_inputs(&root, path_object, operation, &plan.bounds, &mut ref_state)?;
        let server_url = match version {
            OpenApiVersion::V3 => {
                v3_server_url(input.source_url, root_object, path_object, operation)?
            }
            OpenApiVersion::V2 => v2_server_url(input.source_url, root_object, operation)?,
        };
        let responses = normalize_responses(
            version,
            &root,
            root_object,
            operation,
            &plan.bounds,
            &mut ref_state,
            &selector,
        )?;
        let request_url = materialize_request_url(&server_url, &selector.path)?;
        let probe_id = make_probe_id(&selector, &server_url, &request_url, &responses)?;
        operations.push(OperationContract {
            selector,
            probe_id,
            server_url,
            request_url,
            responses,
        });
    }
    operations.sort_by(|left, right| left.selector.cmp(&right.selector));

    let normalized = NormalizedOpenApi {
        schema_version: API_VALIDATION_SCHEMA_VERSION,
        source_url: input.source_url.to_owned(),
        document_hash: hash(input.document),
        source_receipt: input.receipt,
        operations,
    };
    normalized.validate()?;
    Ok(normalized)
}

fn parse_document(bytes: &[u8]) -> Result<Value> {
    if let Ok(json) = serde_json::from_slice(bytes) {
        return Ok(json);
    }
    serde_yaml::from_slice(bytes).context("document is neither valid OpenAPI JSON nor YAML")
}

fn detect_version(root: &Map<String, Value>) -> Result<OpenApiVersion> {
    match (root.get("swagger"), root.get("openapi")) {
        (Some(Value::String(version)), None) if version == "2.0" => Ok(OpenApiVersion::V2),
        (None, Some(Value::String(version))) if valid_v3_version(version) => Ok(OpenApiVersion::V3),
        (Some(_), Some(_)) => bail!("document ambiguously declares Swagger and OpenAPI versions"),
        _ => bail!("unsupported or missing OpenAPI version"),
    }
}

fn valid_v3_version(version: &str) -> bool {
    let parts: Vec<_> = version.split('.').collect();
    matches!(parts.as_slice(), ["3", "0" | "1"])
        || matches!(
            parts.as_slice(),
            ["3", "0" | "1", patch]
                if !patch.is_empty() && patch.bytes().all(|byte| byte.is_ascii_digit())
        )
}

fn validate_operation_id(
    selector: &OperationSelector,
    operation: &Map<String, Value>,
) -> Result<()> {
    let declared = operation.get("operationId").and_then(Value::as_str);
    if let Some(expected) = &selector.operation_id {
        ensure!(
            declared == Some(expected.as_str()),
            "selected operationId does not match the OpenAPI operation"
        );
    }
    if let Some(operation_id) = declared {
        ensure!(
            !operation_id.trim().is_empty() && operation_id.len() <= 512,
            "OpenAPI operationId is invalid"
        );
    }
    Ok(())
}

fn reject_authenticated_operation(
    root: &Map<String, Value>,
    operation: &Map<String, Value>,
) -> Result<()> {
    let Some(security) = operation.get("security").or_else(|| root.get("security")) else {
        return Ok(());
    };
    let requirements = security
        .as_array()
        .context("effective OpenAPI security must be an array")?;
    let anonymous_only = requirements
        .iter()
        .all(|requirement| requirement.as_object().is_some_and(Map::is_empty));
    ensure!(
        anonymous_only,
        "authenticated OpenAPI operations are not eligible for unauthenticated validation"
    );
    Ok(())
}

fn reject_required_inputs(
    root: &Value,
    path: &Map<String, Value>,
    operation: &Map<String, Value>,
    bounds: &ValidationBounds,
    ref_state: &mut RefState<'_>,
) -> Result<()> {
    let mut effective = BTreeMap::new();
    merge_parameters(
        root,
        path.get("parameters"),
        bounds,
        ref_state,
        &mut effective,
    )?;
    merge_parameters(
        root,
        operation.get("parameters"),
        bounds,
        ref_state,
        &mut effective,
    )?;
    ensure!(
        effective.values().all(|required| !required),
        "operation requires request parameters and is not an input-free probe"
    );

    if let Some(request_body) = operation.get("requestBody") {
        let request_body = resolve_direct_ref(root, request_body, ref_state, 0)?;
        let request_body = request_body
            .as_object()
            .context("OpenAPI requestBody must be an object")?;
        let required = optional_bool(request_body.get("required"), "requestBody.required")?;
        ensure!(
            !required,
            "operation requires a request body and is not an input-free probe"
        );
    }
    Ok(())
}

fn merge_parameters(
    root: &Value,
    value: Option<&Value>,
    bounds: &ValidationBounds,
    ref_state: &mut RefState<'_>,
    effective: &mut BTreeMap<(String, String), bool>,
) -> Result<()> {
    let Some(value) = value else {
        return Ok(());
    };
    let parameters = value
        .as_array()
        .context("OpenAPI parameters must be an array")?;
    ensure!(
        parameters.len() <= usize::try_from(bounds.max_properties)?,
        "parameter count exceeds max_properties"
    );
    let mut level = BTreeSet::new();
    for parameter in parameters {
        let parameter = resolve_direct_ref(root, parameter, ref_state, 0)?;
        let parameter = parameter
            .as_object()
            .context("OpenAPI parameter must be an object")?;
        let name = parameter
            .get("name")
            .and_then(Value::as_str)
            .context("OpenAPI parameter name is missing")?;
        let location = parameter
            .get("in")
            .and_then(Value::as_str)
            .context("OpenAPI parameter location is missing")?;
        ensure!(
            !name.is_empty() && name.len() <= 4_096 && location.len() <= 64,
            "OpenAPI parameter identity is invalid"
        );
        let key = (name.to_owned(), location.to_owned());
        ensure!(
            level.insert(key.clone()),
            "duplicate parameter in one OpenAPI parameter list"
        );
        let declared_required = optional_bool(parameter.get("required"), "parameter.required")?;
        let required = location == "path" || declared_required;
        effective.insert(key, required);
    }
    Ok(())
}

fn optional_bool(value: Option<&Value>, field: &str) -> Result<bool> {
    match value {
        None => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => bail!("{field} must be a boolean"),
    }
}

fn v3_server_url(
    source_url: &str,
    root: &Map<String, Value>,
    path: &Map<String, Value>,
    operation: &Map<String, Value>,
) -> Result<String> {
    let servers = operation
        .get("servers")
        .or_else(|| path.get("servers"))
        .or_else(|| root.get("servers"));
    let raw_url = match servers {
        None => "/",
        Some(value) => {
            let array = value
                .as_array()
                .context("OpenAPI servers must be an array")?;
            ensure!(
                array.len() == 1,
                "OpenAPI server selection is absent or ambiguous"
            );
            let server = array[0]
                .as_object()
                .context("OpenAPI server must be an object")?;
            ensure!(
                server
                    .get("variables")
                    .and_then(Value::as_object)
                    .is_none_or(Map::is_empty),
                "variable OpenAPI servers are not executable"
            );
            server
                .get("url")
                .and_then(Value::as_str)
                .context("OpenAPI server URL is missing")?
        }
    };
    ensure!(
        !raw_url.contains('{') && !raw_url.contains('}'),
        "variable OpenAPI servers are not executable"
    );
    resolve_server_url(source_url, raw_url)
}

fn v2_server_url(
    source_url: &str,
    root: &Map<String, Value>,
    operation: &Map<String, Value>,
) -> Result<String> {
    let source = Url::parse(source_url)?;
    let schemes = operation.get("schemes").or_else(|| root.get("schemes"));
    let scheme = match schemes {
        None => source.scheme(),
        Some(value) => {
            let array = value
                .as_array()
                .context("Swagger schemes must be an array")?;
            ensure!(array.len() == 1, "Swagger scheme selection is ambiguous");
            array[0]
                .as_str()
                .context("Swagger scheme must be a string")?
        }
    };
    ensure!(
        matches!(scheme, "http" | "https"),
        "unsupported Swagger scheme"
    );
    let host = match root.get("host") {
        Some(Value::String(host)) => host.clone(),
        Some(_) => bail!("Swagger host must be a string"),
        None => {
            let mut value = source.host_str().unwrap_or_default().to_owned();
            if let Some(port) = source.port() {
                value.push(':');
                value.push_str(&port.to_string());
            }
            value
        }
    };
    let base_path = match root.get("basePath") {
        Some(Value::String(path)) => path.as_str(),
        Some(_) => bail!("Swagger basePath must be a string"),
        None => "/",
    };
    ensure!(
        !host.contains(['{', '}']) && !base_path.contains(['{', '}']),
        "variable Swagger servers are not executable"
    );
    ensure!(
        base_path.starts_with('/') && !base_path.contains(['?', '#']),
        "Swagger basePath must be an absolute path"
    );
    resolve_server_url(source_url, &format!("{scheme}://{host}{base_path}"))
}

fn resolve_server_url(source_url: &str, raw: &str) -> Result<String> {
    let source = Url::parse(source_url)?;
    let resolved = match Url::parse(raw) {
        Ok(url) => url,
        Err(url::ParseError::RelativeUrlWithoutBase) => source.join(raw)?,
        Err(error) => return Err(error.into()),
    };
    ensure!(
        resolved.query().is_none() && resolved.fragment().is_none(),
        "OpenAPI server URL must not contain query or fragment components"
    );
    canonical_http_url(resolved.as_str())
}

#[allow(clippy::too_many_arguments)]
fn normalize_responses(
    version: OpenApiVersion,
    root: &Value,
    root_object: &Map<String, Value>,
    operation: &Map<String, Value>,
    bounds: &ValidationBounds,
    ref_state: &mut RefState<'_>,
    selector: &OperationSelector,
) -> Result<Vec<ResponseContract>> {
    let responses = operation
        .get("responses")
        .and_then(Value::as_object)
        .context("selected operation responses must be an object")?;
    ensure!(!responses.is_empty(), "selected operation has no responses");
    ensure!(
        responses.len() <= usize::try_from(bounds.max_properties)?,
        "response contract count exceeds max_properties"
    );
    let mut normalized = Vec::with_capacity(responses.len());
    for (status_text, response_value) in responses {
        let status = parse_status(status_text)?;
        let response_value = resolve_direct_ref(root, response_value, ref_state, 0)?;
        let response = response_value
            .as_object()
            .context("OpenAPI response must be an object")?;
        let media = match version {
            OpenApiVersion::V3 => {
                normalize_v3_media(root, response, bounds, ref_state, selector, status_text)?
            }
            OpenApiVersion::V2 => normalize_v2_media(
                root,
                root_object,
                operation,
                response,
                bounds,
                ref_state,
                selector,
                status_text,
            )?,
        };
        normalized.push(ResponseContract { status, media });
    }
    normalized.sort_by(|left, right| left.status.cmp(&right.status));
    Ok(normalized)
}

fn parse_status(input: &str) -> Result<StatusSelector> {
    if input.eq_ignore_ascii_case("default") {
        return Ok(StatusSelector::Default);
    }
    if input.len() == 3
        && input.as_bytes()[0].is_ascii_digit()
        && input.as_bytes()[1..]
            .iter()
            .all(|byte| matches!(byte, b'X' | b'x'))
    {
        let hundred = u16::from(input.as_bytes()[0] - b'0');
        ensure!(
            (1..=5).contains(&hundred),
            "response status class out of range"
        );
        return Ok(StatusSelector::Class { hundred });
    }
    let status: u16 = input.parse().context("invalid OpenAPI response status")?;
    ensure!(
        (100..=599).contains(&status),
        "response status out of range"
    );
    Ok(StatusSelector::Exact { status })
}

fn normalize_v3_media(
    root: &Value,
    response: &Map<String, Value>,
    bounds: &ValidationBounds,
    ref_state: &mut RefState<'_>,
    selector: &OperationSelector,
    status: &str,
) -> Result<Vec<MediaContract>> {
    let Some(content_value) = response.get("content") else {
        return Ok(Vec::new());
    };
    let content = content_value
        .as_object()
        .context("OpenAPI response content must be an object")?;
    ensure!(
        content.len() <= usize::try_from(bounds.max_properties)?,
        "response media count exceeds max_properties"
    );
    let mut media = Vec::with_capacity(content.len());
    for (media_type, entry_value) in content {
        let canonical_media = normalize_media_type(media_type)?;
        let entry = entry_value
            .as_object()
            .context("OpenAPI media entry must be an object")?;
        let location = format!(
            "paths.{}.{}.responses.{status}.content.{canonical_media}.schema",
            selector.path,
            selector.method.as_lowercase()
        );
        let (schema, mut unsupported) = match entry.get("schema") {
            Some(schema) => {
                let parsed = parse_schema(
                    root,
                    schema,
                    bounds,
                    ref_state,
                    0,
                    &location,
                    &mut Vec::new(),
                )?;
                (Some(parsed.schema), parsed.unsupported)
            }
            None => (None, Vec::new()),
        };
        for keyword in entry.keys().filter(|key| key.as_str() != "schema") {
            unsupported.push(UnsupportedKeyword {
                location: format!(
                    "paths.{}.{}.responses.{status}.content.{canonical_media}",
                    selector.path,
                    selector.method.as_lowercase()
                ),
                keyword: keyword.clone(),
            });
        }
        if canonical_media.contains('*') {
            unsupported.push(UnsupportedKeyword {
                location: format!(
                    "paths.{}.{}.responses.{status}.content.{canonical_media}",
                    selector.path,
                    selector.method.as_lowercase()
                ),
                keyword: "wildcard_media_type".to_owned(),
            });
        }
        canonicalize_unsupported(&mut unsupported);
        media.push(MediaContract {
            media_type: canonical_media,
            schema,
            unsupported,
        });
    }
    media.sort_by(|left, right| left.media_type.cmp(&right.media_type));
    ensure!(
        media
            .windows(2)
            .all(|pair| pair[0].media_type != pair[1].media_type),
        "response media types are ambiguous after normalization"
    );
    Ok(media)
}

#[allow(clippy::too_many_arguments)]
fn normalize_v2_media(
    root: &Value,
    root_object: &Map<String, Value>,
    operation: &Map<String, Value>,
    response: &Map<String, Value>,
    bounds: &ValidationBounds,
    ref_state: &mut RefState<'_>,
    selector: &OperationSelector,
    status: &str,
) -> Result<Vec<MediaContract>> {
    let produces = operation
        .get("produces")
        .or_else(|| root_object.get("produces"));
    let mut media_types = match produces {
        Some(value) => value
            .as_array()
            .context("Swagger produces must be an array")?
            .iter()
            .map(|value| {
                normalize_media_type(
                    value
                        .as_str()
                        .context("Swagger produces entry must be a string")?,
                )
            })
            .collect::<Result<Vec<_>>>()?,
        None if response.contains_key("schema") => vec!["*/*".to_owned()],
        None => Vec::new(),
    };
    media_types.sort();
    media_types.dedup();
    ensure!(
        media_types.len() <= usize::try_from(bounds.max_properties)?,
        "Swagger produces count exceeds max_properties"
    );
    let location = format!(
        "paths.{}.{}.responses.{status}.schema",
        selector.path,
        selector.method.as_lowercase()
    );
    let parsed = response
        .get("schema")
        .map(|schema| {
            parse_schema(
                root,
                schema,
                bounds,
                ref_state,
                0,
                &location,
                &mut Vec::new(),
            )
        })
        .transpose()?;
    let mut output = Vec::with_capacity(media_types.len());
    for media_type in media_types {
        let mut unsupported = parsed
            .as_ref()
            .map(|parsed| parsed.unsupported.clone())
            .unwrap_or_default();
        if produces.is_none() && response.contains_key("schema") {
            unsupported.push(UnsupportedKeyword {
                location: location.clone(),
                keyword: "missing_produces".to_owned(),
            });
        }
        if media_type.contains('*') {
            unsupported.push(UnsupportedKeyword {
                location: location.clone(),
                keyword: "wildcard_media_type".to_owned(),
            });
        }
        canonicalize_unsupported(&mut unsupported);
        output.push(MediaContract {
            media_type,
            schema: parsed.as_ref().map(|parsed| parsed.schema.clone()),
            unsupported,
        });
    }
    Ok(output)
}

#[derive(Clone)]
struct ParsedSchema {
    schema: NormalizedSchema,
    unsupported: Vec<UnsupportedKeyword>,
}

#[allow(clippy::too_many_arguments)]
fn parse_schema(
    root: &Value,
    value: &Value,
    bounds: &ValidationBounds,
    ref_state: &mut RefState<'_>,
    depth: u16,
    location: &str,
    ref_stack: &mut Vec<String>,
) -> Result<ParsedSchema> {
    ensure!(
        depth <= bounds.max_schema_depth,
        "schema depth ceiling exceeded"
    );
    ref_state.schema_nodes = ref_state.schema_nodes.saturating_add(1);
    ensure!(
        ref_state.schema_nodes <= bounds.max_schema_nodes,
        "schema node ceiling exceeded"
    );
    let object = value
        .as_object()
        .context("OpenAPI schema must be an object")?;
    if let Some(reference) = object.get("$ref") {
        let reference = reference.as_str().context("schema $ref must be a string")?;
        validate_local_ref(reference)?;
        ensure!(
            ref_stack.len() < usize::from(bounds.max_ref_depth),
            "$ref depth ceiling exceeded"
        );
        ensure!(
            !ref_stack.iter().any(|entry| entry == reference),
            "cyclic local $ref detected: {reference}"
        );
        ref_state.consume_ref()?;
        ref_stack.push(reference.to_owned());
        let target = resolve_pointer(root, reference)?;
        let mut parsed = parse_schema(
            root,
            target,
            bounds,
            ref_state,
            depth + 1,
            reference,
            ref_stack,
        )?;
        ref_stack.pop();
        for keyword in object.keys().filter(|key| key.as_str() != "$ref") {
            parsed.unsupported.push(UnsupportedKeyword {
                location: location.to_owned(),
                keyword: keyword.clone(),
            });
        }
        canonicalize_unsupported(&mut parsed.unsupported);
        return Ok(parsed);
    }

    let declared_type = object.get("type").and_then(Value::as_str);
    let mut unsupported = Vec::new();
    if object.contains_key("type") && declared_type.is_none() {
        unsupported.push(UnsupportedKeyword {
            location: location.to_owned(),
            keyword: "type:non_string".to_owned(),
        });
    }
    let schema = match declared_type {
        None => {
            if !object.contains_key("type")
                && (object.contains_key("properties")
                    || object.contains_key("required")
                    || object.contains_key("items"))
            {
                unsupported.push(UnsupportedKeyword {
                    location: location.to_owned(),
                    keyword: "missing_type".to_owned(),
                });
            }
            NormalizedSchema::Any
        }
        Some("null") => NormalizedSchema::Null,
        Some("boolean") => NormalizedSchema::Boolean,
        Some("integer") => NormalizedSchema::Integer,
        Some("number") => NormalizedSchema::Number,
        Some("string") => NormalizedSchema::String,
        Some("object") => {
            let properties = match object.get("properties") {
                None => BTreeMap::new(),
                Some(value) => {
                    let entries = value
                        .as_object()
                        .context("schema properties must be an object")?;
                    ensure!(
                        entries.len() <= usize::try_from(bounds.max_properties)?,
                        "schema property ceiling exceeded"
                    );
                    let mut properties = BTreeMap::new();
                    for (name, child) in entries {
                        let child_location = format!("{location}.properties.{name}");
                        let parsed = parse_schema(
                            root,
                            child,
                            bounds,
                            ref_state,
                            depth + 1,
                            &child_location,
                            ref_stack,
                        )?;
                        unsupported.extend(parsed.unsupported);
                        properties.insert(name.clone(), parsed.schema);
                    }
                    properties
                }
            };
            let required = match object.get("required") {
                None => Vec::new(),
                Some(value) => {
                    let values = value
                        .as_array()
                        .context("schema required must be an array")?;
                    ensure!(
                        values.len() <= usize::try_from(bounds.max_properties)?,
                        "required property ceiling exceeded"
                    );
                    let mut required = values
                        .iter()
                        .map(|value| {
                            value
                                .as_str()
                                .map(str::to_owned)
                                .context("required property must be a string")
                        })
                        .collect::<Result<Vec<_>>>()?;
                    let original_len = required.len();
                    required.sort();
                    required.dedup();
                    ensure!(
                        required.len() == original_len,
                        "required properties contain duplicates"
                    );
                    ensure!(
                        required.iter().all(|name| properties.contains_key(name)),
                        "required property is absent from properties"
                    );
                    required
                }
            };
            NormalizedSchema::Object {
                required,
                properties,
            }
        }
        Some("array") => {
            let items = match object.get("items") {
                Some(items) => parse_schema(
                    root,
                    items,
                    bounds,
                    ref_state,
                    depth + 1,
                    &format!("{location}.items"),
                    ref_stack,
                )?,
                None => {
                    unsupported.push(UnsupportedKeyword {
                        location: location.to_owned(),
                        keyword: "missing_items".to_owned(),
                    });
                    ParsedSchema {
                        schema: NormalizedSchema::Any,
                        unsupported: Vec::new(),
                    }
                }
            };
            unsupported.extend(items.unsupported);
            NormalizedSchema::Array {
                items: Box::new(items.schema),
            }
        }
        Some(_) => {
            unsupported.push(UnsupportedKeyword {
                location: location.to_owned(),
                keyword: "type:unsupported".to_owned(),
            });
            NormalizedSchema::Any
        }
    };
    let executable_keywords: &[&str] = match declared_type {
        Some("object") => &["type", "required", "properties"],
        Some("array") => &["type", "items"],
        Some("null" | "boolean" | "integer" | "number" | "string") => &["type"],
        _ => &[],
    };
    for keyword in object
        .keys()
        .filter(|key| key.as_str() != "type" && !executable_keywords.contains(&key.as_str()))
    {
        unsupported.push(UnsupportedKeyword {
            location: location.to_owned(),
            keyword: keyword.clone(),
        });
    }
    canonicalize_unsupported(&mut unsupported);
    Ok(ParsedSchema {
        schema,
        unsupported,
    })
}

fn canonicalize_unsupported(entries: &mut Vec<UnsupportedKeyword>) {
    entries.sort();
    entries.dedup();
}

struct RefState<'a> {
    bounds: &'a ValidationBounds,
    ref_nodes: u32,
    schema_nodes: u32,
}

impl<'a> RefState<'a> {
    fn new(bounds: &'a ValidationBounds) -> Self {
        Self {
            bounds,
            ref_nodes: 0,
            schema_nodes: 0,
        }
    }

    fn consume_ref(&mut self) -> Result<()> {
        self.ref_nodes = self.ref_nodes.saturating_add(1);
        ensure!(
            self.ref_nodes <= self.bounds.max_ref_nodes,
            "$ref node ceiling exceeded"
        );
        Ok(())
    }
}

fn resolve_direct_ref<'a>(
    root: &'a Value,
    value: &'a Value,
    state: &mut RefState<'_>,
    depth: u16,
) -> Result<&'a Value> {
    let mut current = value;
    let mut current_depth = depth;
    let mut seen = BTreeSet::new();
    loop {
        ensure!(
            current_depth <= state.bounds.max_ref_depth,
            "$ref depth ceiling exceeded"
        );
        let Some(object) = current.as_object() else {
            return Ok(current);
        };
        let Some(reference_value) = object.get("$ref") else {
            return Ok(current);
        };
        let reference = reference_value
            .as_str()
            .context("OpenAPI $ref must be a string")?;
        validate_local_ref(reference)?;
        ensure!(
            seen.insert(reference),
            "cyclic local $ref detected: {reference}"
        );
        state.consume_ref()?;
        current = resolve_pointer(root, reference)?;
        current_depth = current_depth.saturating_add(1);
    }
}

fn validate_local_ref(reference: &str) -> Result<()> {
    ensure!(
        reference == "#" || reference.starts_with("#/"),
        "remote or non-pointer $ref is not executable: {reference}"
    );
    Ok(())
}

fn resolve_pointer<'a>(root: &'a Value, reference: &str) -> Result<&'a Value> {
    if reference == "#" {
        return Ok(root);
    }
    root.pointer(&reference[1..])
        .with_context(|| format!("unresolved local $ref: {reference}"))
}
