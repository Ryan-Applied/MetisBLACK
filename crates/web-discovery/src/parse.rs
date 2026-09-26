use crate::contract::{
    canonical_http_url, DeclaredOperation, DiscoveryBounds, EvidenceState, FormControlShape,
    FormShape, OmissionReason, RobotsDirective, RobotsDirectiveKind, SourceLineage,
};
use anyhow::{anyhow, bail, Context, Result};
use regex::Regex;
use serde_json::Value;
use std::{collections::BTreeMap, sync::OnceLock};
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CandidateReference {
    pub raw: String,
    pub resolved: Option<String>,
    pub kind: crate::contract::ResourceKind,
    pub failure: Option<OmissionReason>,
}

#[derive(Debug, Default)]
pub(crate) struct ParsedDocument {
    pub candidates: Vec<CandidateReference>,
    pub forms: Vec<FormShape>,
    pub operations: Vec<DeclaredOperation>,
    pub robots: Vec<RobotsDirective>,
    pub omissions: Vec<(String, OmissionReason, String)>,
}

pub(crate) fn parse_html(
    source_url: &str,
    body: &str,
    bounds: &DiscoveryBounds,
    lineage: &SourceLineage,
) -> Result<ParsedDocument> {
    static LINK_TAG: OnceLock<Regex> = OnceLock::new();
    static FORM_TAG: OnceLock<Regex> = OnceLock::new();
    static CONTROL_TAG: OnceLock<Regex> = OnceLock::new();
    static SCRIPT_BLOCK: OnceLock<Regex> = OnceLock::new();
    let link_tag = LINK_TAG.get_or_init(|| {
        Regex::new(r"(?is)<\s*(a|link|script)\b([^>]*)>").expect("valid link-tag regex")
    });
    let form_tag = FORM_TAG
        .get_or_init(|| Regex::new(r"(?is)<\s*form\b([^>]*)>").expect("valid form-tag regex"));
    let control_tag = CONTROL_TAG.get_or_init(|| {
        Regex::new(r"(?is)<\s*(input|button|textarea|select)\b([^>]*)>")
            .expect("valid control-tag regex")
    });
    let script_block = SCRIPT_BLOCK.get_or_init(|| {
        Regex::new(r"(?is)<\s*script\b[^>]*>(.*?)<\s*/\s*script\s*>")
            .expect("valid script-block regex")
    });

    let mut parsed = ParsedDocument::default();
    let reference_limit = usize::try_from(bounds.max_references_per_document)?;
    for capture in link_tag.captures_iter(body).take(reference_limit + 1) {
        let tag = capture[1].to_ascii_lowercase();
        let attributes = attributes(&capture[2]);
        let (attribute, kind) = if tag == "script" {
            ("src", crate::contract::ResourceKind::JavaScript)
        } else {
            ("href", crate::contract::ResourceKind::Automatic)
        };
        if let Some(value) = attributes.get(attribute) {
            parsed
                .candidates
                .push(resolve_reference(source_url, value, kind));
        }
    }

    for script in script_block.captures_iter(body) {
        if parsed.candidates.len() > reference_limit {
            break;
        }
        parsed.candidates.extend(js_references(
            source_url,
            &script[1],
            bounds.max_references_per_document.saturating_sub(
                u32::try_from(parsed.candidates.len())
                    .unwrap_or(bounds.max_references_per_document),
            ),
        ));
    }

    let form_limit = usize::try_from(bounds.max_forms_per_document)?;
    for (index, capture) in form_tag.captures_iter(body).enumerate() {
        if index >= form_limit {
            parsed.omissions.push((
                source_url.to_owned(),
                OmissionReason::FormLimit,
                format!("form limit {} reached", bounds.max_forms_per_document),
            ));
            break;
        }
        let form_attributes = attributes(&capture[1]);
        let method = form_attributes
            .get("method")
            .map(|method| method.trim().to_ascii_uppercase())
            .filter(|method| !method.is_empty())
            .unwrap_or_else(|| "GET".to_owned());
        let raw_action = form_attributes
            .get("action")
            .map(String::as_str)
            .unwrap_or(source_url);
        let action = resolve_reference(
            source_url,
            raw_action,
            crate::contract::ResourceKind::Automatic,
        );
        let action_url = action
            .resolved
            .clone()
            .unwrap_or_else(|| raw_action.to_owned());
        parsed.candidates.push(action);

        let block_start = capture.get(0).map(|matched| matched.end()).unwrap_or(0);
        let remainder = &body[block_start..];
        let lower = remainder.to_ascii_lowercase();
        let block_end = lower.find("</form").unwrap_or(remainder.len());
        let block = &remainder[..block_end];
        let control_limit = usize::try_from(bounds.max_controls_per_form)?;
        let mut controls = Vec::new();
        for (control_index, control) in control_tag.captures_iter(block).enumerate() {
            if control_index >= control_limit {
                parsed.omissions.push((
                    action_url.clone(),
                    OmissionReason::FormControlLimit,
                    format!(
                        "form control limit {} reached",
                        bounds.max_controls_per_form
                    ),
                ));
                break;
            }
            let tag = control[1].to_ascii_lowercase();
            let values = attributes(&control[2]);
            let control_type = values
                .get("type")
                .map(|value| value.trim().to_ascii_lowercase())
                .filter(|value| !value.is_empty())
                .unwrap_or(tag);
            controls.push(FormControlShape {
                name: values.get("name").cloned().filter(|name| !name.is_empty()),
                control_type,
                required: values.contains_key("required"),
            });
        }
        controls.sort();
        controls.dedup();
        parsed.forms.push(FormShape {
            source_url: source_url.to_owned(),
            index: u32::try_from(index)?,
            method,
            action_url,
            controls,
            state: EvidenceState::Observed,
            lineage: lineage.clone(),
        });
    }
    bounded_candidates(&mut parsed, bounds);
    Ok(parsed)
}

pub(crate) fn parse_javascript(
    source_url: &str,
    body: &str,
    bounds: &DiscoveryBounds,
) -> ParsedDocument {
    let mut parsed = ParsedDocument {
        candidates: js_references(source_url, body, bounds.max_references_per_document),
        ..ParsedDocument::default()
    };
    bounded_candidates(&mut parsed, bounds);
    parsed
}

fn js_references(source_url: &str, body: &str, maximum: u32) -> Vec<CandidateReference> {
    static URL_LITERAL: OnceLock<Regex> = OnceLock::new();
    let regex = URL_LITERAL.get_or_init(|| {
        Regex::new(r#"(?s)["']((?:https?://|//|/|\./|\.\./)[^"'\\\r\n]{1,2048})["']"#)
            .expect("valid JavaScript URL-literal regex")
    });
    let limit = usize::try_from(maximum).unwrap_or(20_000);
    regex
        .captures_iter(body)
        .take(limit.saturating_add(1))
        .map(|capture| {
            resolve_reference(
                source_url,
                &capture[1].replace("\\/", "/"),
                crate::contract::ResourceKind::Automatic,
            )
        })
        .collect()
}

pub(crate) fn parse_robots(
    source_url: &str,
    body: &str,
    bounds: &DiscoveryBounds,
    lineage: &SourceLineage,
) -> ParsedDocument {
    let mut parsed = ParsedDocument::default();
    let directive_limit = usize::try_from(bounds.max_references_per_document).unwrap_or(20_000);
    for (line_index, line) in body.lines().enumerate() {
        if line_index >= directive_limit {
            parsed.omissions.push((
                source_url.to_owned(),
                OmissionReason::ReferenceLimit,
                format!(
                    "robots directive limit {} reached",
                    bounds.max_references_per_document
                ),
            ));
            break;
        }
        let content = line.split('#').next().unwrap_or_default().trim();
        let Some((name, value)) = content.split_once(':') else {
            continue;
        };
        let value = value.trim();
        let kind = match name.trim().to_ascii_lowercase().as_str() {
            "allow" => RobotsDirectiveKind::Allow,
            "disallow" => RobotsDirectiveKind::Disallow,
            "sitemap" => RobotsDirectiveKind::Sitemap,
            _ => continue,
        };
        let expected_kind = if kind == RobotsDirectiveKind::Sitemap {
            crate::contract::ResourceKind::Sitemap
        } else {
            crate::contract::ResourceKind::Automatic
        };
        let reference = if value.is_empty() {
            None
        } else {
            Some(resolve_reference(source_url, value, expected_kind))
        };
        let resolved_url = reference
            .as_ref()
            .and_then(|reference| reference.resolved.clone());
        // `Disallow` is policy information, not a crawl declaration. Sitemaps
        // are fetchable declarations; Allow is retained without inventing a URL.
        if kind == RobotsDirectiveKind::Sitemap {
            if let Some(reference) = reference {
                parsed.candidates.push(reference);
            }
        }
        parsed.robots.push(RobotsDirective {
            source_url: source_url.to_owned(),
            kind,
            value: value.to_owned(),
            resolved_url,
            state: EvidenceState::Observed,
            lineage: lineage.clone(),
        });
    }
    bounded_candidates(&mut parsed, bounds);
    parsed
}

pub(crate) fn parse_sitemap(
    source_url: &str,
    body: &str,
    bounds: &DiscoveryBounds,
) -> Result<ParsedDocument> {
    static LOCATION: OnceLock<Regex> = OnceLock::new();
    let lower = body.to_ascii_lowercase();
    if !lower.contains("<urlset") && !lower.contains("<sitemapindex") {
        bail!("sitemap XML lacks urlset or sitemapindex root");
    }
    let kind = if lower.contains("<sitemapindex") {
        crate::contract::ResourceKind::Sitemap
    } else {
        crate::contract::ResourceKind::Automatic
    };
    let location = LOCATION.get_or_init(|| {
        Regex::new(r"(?is)<\s*loc\s*>\s*([^<]+?)\s*<\s*/\s*loc\s*>")
            .expect("valid sitemap location regex")
    });
    let mut parsed = ParsedDocument::default();
    let limit = usize::try_from(bounds.max_references_per_document)?;
    for capture in location.captures_iter(body).take(limit.saturating_add(1)) {
        parsed.candidates.push(resolve_reference(
            source_url,
            &decode_entities(&capture[1]),
            kind,
        ));
    }
    bounded_candidates(&mut parsed, bounds);
    Ok(parsed)
}

pub(crate) fn parse_openapi(
    source_url: &str,
    body: &str,
    bounds: &DiscoveryBounds,
    lineage: &SourceLineage,
) -> Result<ParsedDocument> {
    let trimmed = body.trim_start();
    let mut parsed = if trimmed.starts_with('{') {
        parse_openapi_json(source_url, body, lineage)?
    } else {
        parse_openapi_yaml(source_url, body, lineage)?
    };
    parsed.operations.sort();
    parsed.operations.dedup();
    let limit = usize::try_from(bounds.max_openapi_operations)?;
    if parsed.operations.len() > limit {
        parsed.operations.truncate(limit);
        parsed.omissions.push((
            source_url.to_owned(),
            OmissionReason::OpenApiOperationLimit,
            format!(
                "OpenAPI operation limit {} reached",
                bounds.max_openapi_operations
            ),
        ));
    }
    Ok(parsed)
}

#[derive(Debug)]
struct ApiDescription {
    version: ApiVersion,
    base_urls: Vec<String>,
    operations: Vec<(String, String, Option<String>)>,
    remote_refs: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApiVersion {
    V2,
    V3,
}

fn parse_openapi_json(
    source_url: &str,
    body: &str,
    lineage: &SourceLineage,
) -> Result<ParsedDocument> {
    let root: Value = serde_json::from_str(body).context("invalid OpenAPI JSON")?;
    let object = root
        .as_object()
        .ok_or_else(|| anyhow!("OpenAPI JSON root must be an object"))?;
    let version = if object
        .get("swagger")
        .and_then(Value::as_str)
        .is_some_and(|value| value.starts_with("2."))
    {
        ApiVersion::V2
    } else if object
        .get("openapi")
        .and_then(Value::as_str)
        .is_some_and(|value| value.starts_with("3."))
    {
        ApiVersion::V3
    } else {
        bail!("unsupported or absent OpenAPI version");
    };
    let base_urls = json_base_urls(source_url, object, version);
    let mut operations = Vec::new();
    if let Some(paths) = object.get("paths").and_then(Value::as_object) {
        for (path, path_item) in paths {
            if let Some(methods) = path_item.as_object() {
                for (method, operation) in methods {
                    if !is_http_method(method) {
                        continue;
                    }
                    let operation_id = operation
                        .as_object()
                        .and_then(|value| value.get("operationId"))
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned);
                    operations.push((method.to_ascii_uppercase(), path.clone(), operation_id));
                }
            }
        }
    }
    let mut remote_refs = Vec::new();
    collect_json_remote_refs(&root, &mut remote_refs, 0);
    build_api_document(
        source_url,
        ApiDescription {
            version,
            base_urls,
            operations,
            remote_refs,
        },
        lineage,
    )
}

fn json_base_urls(
    source_url: &str,
    object: &serde_json::Map<String, Value>,
    version: ApiVersion,
) -> Vec<String> {
    if version == ApiVersion::V3 {
        let values: Vec<_> = object
            .get("servers")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|server| server.get("url").and_then(Value::as_str))
            .filter_map(|server| resolve_server(source_url, server))
            .collect();
        if !values.is_empty() {
            return values;
        }
    } else if let Some(host) = object.get("host").and_then(Value::as_str) {
        let source_scheme = Url::parse(source_url)
            .ok()
            .map(|url| url.scheme().to_owned())
            .unwrap_or_else(|| "https".to_owned());
        let schemes: Vec<_> = object
            .get("schemes")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        let scheme = schemes.first().copied().unwrap_or(&source_scheme);
        let base_path = object
            .get("basePath")
            .and_then(Value::as_str)
            .unwrap_or("/");
        return vec![format!(
            "{}://{}{}",
            scheme.trim_end_matches(':'),
            host.trim_end_matches('/'),
            normalize_base_path(base_path)
        )];
    }
    vec![source_origin(source_url)]
}

fn collect_json_remote_refs(value: &Value, refs: &mut Vec<String>, depth: u16) {
    if depth > 128 {
        return;
    }
    match value {
        Value::Object(object) => {
            if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
                if is_remote_ref(reference) {
                    refs.push(reference.to_owned());
                }
            }
            for child in object.values() {
                collect_json_remote_refs(child, refs, depth + 1);
            }
        }
        Value::Array(array) => {
            for child in array {
                collect_json_remote_refs(child, refs, depth + 1);
            }
        }
        _ => {}
    }
}

fn parse_openapi_yaml(
    source_url: &str,
    body: &str,
    lineage: &SourceLineage,
) -> Result<ParsedDocument> {
    let mut version = None;
    let mut base_path = String::new();
    let mut host = None;
    let mut schemes = Vec::new();
    let mut servers = Vec::new();
    let mut remote_refs = Vec::new();
    let mut operations = Vec::new();
    let mut paths_indent = None;
    let mut servers_indent = None;
    let mut schemes_indent = None;
    let mut current_path: Option<(usize, String)> = None;
    let mut current_operation: Option<(usize, usize)> = None;

    for raw_line in body.lines() {
        if raw_line.trim().is_empty() || raw_line.trim_start().starts_with('#') {
            continue;
        }
        if raw_line.contains('\t') {
            bail!("OpenAPI YAML indentation cannot contain tabs");
        }
        let indent = raw_line.len() - raw_line.trim_start_matches(' ').len();
        let content = strip_yaml_comment(raw_line.trim());
        if content.is_empty() {
            continue;
        }
        let Some((raw_key, raw_value)) = content.split_once(':') else {
            if let Some(server_indent) = servers_indent {
                if indent > server_indent {
                    if let Some(url) = content.strip_prefix("- url:") {
                        servers.push(yaml_scalar(url));
                    }
                }
            }
            if let Some(scheme_indent) = schemes_indent {
                if indent > scheme_indent {
                    if let Some(scheme) = content.strip_prefix('-') {
                        schemes.push(yaml_scalar(scheme));
                    }
                }
            }
            continue;
        };
        let key = yaml_scalar(raw_key);
        let value = yaml_scalar(raw_value);
        if key == "$ref" && is_remote_ref(&value) {
            remote_refs.push(value.clone());
        }
        if indent == 0 {
            current_path = None;
            current_operation = None;
            servers_indent = None;
            schemes_indent = None;
            match key.as_str() {
                "swagger" if value.starts_with("2.") => version = Some(ApiVersion::V2),
                "openapi" if value.starts_with("3.") => version = Some(ApiVersion::V3),
                "basePath" => base_path = value,
                "host" => host = Some(value),
                "paths" => paths_indent = Some(indent),
                "servers" => servers_indent = Some(indent),
                "schemes" => {
                    schemes_indent = Some(indent);
                    schemes.extend(parse_inline_yaml_list(&value));
                }
                _ => {}
            }
            continue;
        }
        if let Some(server_indent) = servers_indent {
            if indent > server_indent && (key == "- url" || key == "url") {
                servers.push(value.clone());
            }
        }
        if let Some(path_indent) = paths_indent {
            if indent > path_indent && key.starts_with('/') {
                current_path = Some((indent, key.clone()));
                current_operation = None;
                continue;
            }
            if let Some((current_indent, path)) = &current_path {
                if indent > *current_indent && is_http_method(&key) {
                    operations.push((key.to_ascii_uppercase(), path.clone(), None));
                    current_operation = Some((indent, operations.len() - 1));
                    continue;
                }
            }
            if key == "operationId" {
                if let Some((operation_indent, index)) = current_operation {
                    if indent > operation_indent {
                        operations[index].2 = Some(value.clone());
                    }
                }
            }
        }
    }

    let version = version.ok_or_else(|| anyhow!("unsupported or absent OpenAPI version"))?;
    let base_urls = match version {
        ApiVersion::V3 if !servers.is_empty() => servers
            .iter()
            .filter_map(|server| resolve_server(source_url, server))
            .collect(),
        ApiVersion::V2 if host.is_some() => {
            let scheme = schemes
                .first()
                .cloned()
                .unwrap_or_else(|| Url::parse(source_url).unwrap().scheme().to_owned());
            vec![format!(
                "{}://{}{}",
                scheme.trim_end_matches(':'),
                host.unwrap().trim_end_matches('/'),
                normalize_base_path(&base_path)
            )]
        }
        _ => vec![source_origin(source_url)],
    };
    build_api_document(
        source_url,
        ApiDescription {
            version,
            base_urls,
            operations,
            remote_refs,
        },
        lineage,
    )
}

fn build_api_document(
    source_url: &str,
    description: ApiDescription,
    lineage: &SourceLineage,
) -> Result<ParsedDocument> {
    let mut parsed = ParsedDocument::default();
    let mut bases = description.base_urls;
    bases.sort();
    bases.dedup();
    if bases.is_empty() {
        bases.push(source_origin(source_url));
    }
    for (method, path, operation_id) in description.operations {
        let resolved_url_template = bases
            .first()
            .map(|base| join_url_template(base, &path))
            .filter(|value| !value.contains("${"));
        parsed.operations.push(DeclaredOperation {
            source_url: source_url.to_owned(),
            method,
            path_template: path,
            resolved_url_template,
            operation_id,
            state: EvidenceState::Declared,
            lineage: lineage.clone(),
        });
    }
    for reference in description.remote_refs {
        parsed.omissions.push((
            reference.clone(),
            OmissionReason::RemoteReference,
            "remote OpenAPI references are recorded but never fetched implicitly".to_owned(),
        ));
    }
    let _ = description.version;
    Ok(parsed)
}

fn attributes(input: &str) -> BTreeMap<String, String> {
    static ATTRIBUTE: OnceLock<Regex> = OnceLock::new();
    let regex = ATTRIBUTE.get_or_init(|| {
        Regex::new(
            r#"(?is)([a-z_:][-a-z0-9_:.]*)\s*(?:=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?"#,
        )
        .expect("valid HTML attribute regex")
    });
    regex
        .captures_iter(input)
        .map(|capture| {
            let value = capture
                .get(2)
                .or_else(|| capture.get(3))
                .or_else(|| capture.get(4))
                .map(|value| decode_entities(value.as_str()))
                .unwrap_or_default();
            (capture[1].to_ascii_lowercase(), value)
        })
        .collect()
}

fn resolve_reference(
    source_url: &str,
    raw: &str,
    kind: crate::contract::ResourceKind,
) -> CandidateReference {
    let value = decode_entities(raw.trim());
    if value.is_empty() {
        return CandidateReference {
            raw: raw.to_owned(),
            resolved: None,
            kind,
            failure: Some(OmissionReason::MalformedReference),
        };
    }
    let base = match Url::parse(source_url) {
        Ok(base) => base,
        Err(_) => {
            return CandidateReference {
                raw: value,
                resolved: None,
                kind,
                failure: Some(OmissionReason::MalformedReference),
            };
        }
    };
    let joined = match Url::parse(&value) {
        Ok(url) => url,
        Err(url::ParseError::RelativeUrlWithoutBase) => match base.join(&value) {
            Ok(url) => url,
            Err(_) => {
                return CandidateReference {
                    raw: value,
                    resolved: None,
                    kind,
                    failure: Some(OmissionReason::MalformedReference),
                };
            }
        },
        Err(_) => {
            return CandidateReference {
                raw: value,
                resolved: None,
                kind,
                failure: Some(OmissionReason::MalformedReference),
            };
        }
    };
    if !matches!(joined.scheme(), "http" | "https") {
        return CandidateReference {
            raw: value,
            resolved: None,
            kind,
            failure: Some(OmissionReason::UnsupportedScheme),
        };
    }
    CandidateReference {
        raw: value,
        resolved: canonical_http_url(joined.as_str()).ok(),
        kind,
        failure: None,
    }
}

fn bounded_candidates(parsed: &mut ParsedDocument, bounds: &DiscoveryBounds) {
    parsed.candidates.sort();
    parsed.candidates.dedup();
    let limit = usize::try_from(bounds.max_references_per_document).unwrap_or(20_000);
    if parsed.candidates.len() > limit {
        parsed.candidates.truncate(limit);
        parsed.omissions.push((
            "document references".to_owned(),
            OmissionReason::ReferenceLimit,
            format!(
                "reference limit {} reached",
                bounds.max_references_per_document
            ),
        ));
    }
}

fn decode_entities(value: &str) -> String {
    value
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

fn is_http_method(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "get" | "put" | "post" | "delete" | "options" | "head" | "patch" | "trace"
    )
}

fn is_remote_ref(value: &str) -> bool {
    value.starts_with("http://") || value.starts_with("https://") || value.starts_with("//")
}

fn source_origin(source_url: &str) -> String {
    Url::parse(source_url)
        .map(|url| url.origin().ascii_serialization())
        .unwrap_or_else(|_| source_url.to_owned())
}

fn resolve_server(source_url: &str, server: &str) -> Option<String> {
    if server.contains('{') || server.contains('}') {
        return None;
    }
    Url::parse(source_url)
        .ok()?
        .join(server)
        .ok()
        .and_then(|url| canonical_http_url(url.as_str()).ok())
}

fn normalize_base_path(value: &str) -> String {
    if value.is_empty() || value == "/" {
        String::new()
    } else {
        format!("/{}", value.trim_matches('/'))
    }
}

fn join_url_template(base: &str, path: &str) -> String {
    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

fn strip_yaml_comment(value: &str) -> &str {
    let mut single = false;
    let mut double = false;
    for (index, character) in value.char_indices() {
        match character {
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            '#' if !single && !double => return value[..index].trim_end(),
            _ => {}
        }
    }
    value
}

fn yaml_scalar(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() >= 2
        && ((trimmed.starts_with('"') && trimmed.ends_with('"'))
            || (trimmed.starts_with('\'') && trimmed.ends_with('\'')))
    {
        trimmed[1..trimmed.len() - 1].to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn parse_inline_yaml_list(value: &str) -> Vec<String> {
    value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .map(|value| {
            value
                .split(',')
                .map(yaml_scalar)
                .filter(|value| !value.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::DiscoveryBounds;
    use storage::hash;

    fn lineage() -> SourceLineage {
        SourceLineage::Receipt {
            receipt_id: "receipt-1".to_owned(),
            receipt_content_hash: hash(b"receipt"),
            body_hash: hash(b"body"),
            source_url: "https://example.test/index".to_owned(),
        }
    }

    #[test]
    fn html_extracts_shapes_without_values() {
        let body = r#"
            <a href="/a">a</a><script src='/app.js'></script>
            <script>fetch('/api/items')</script>
            <form action="/login" method="post">
              <input name="username" value="sensitive">
              <input name="password" type="password" required>
            </form>
        "#;
        let parsed = parse_html(
            "https://example.test/",
            body,
            &DiscoveryBounds::default(),
            &lineage(),
        )
        .unwrap();
        assert_eq!(parsed.forms.len(), 1);
        assert_eq!(parsed.forms[0].method, "POST");
        assert_eq!(parsed.forms[0].controls.len(), 2);
        assert!(!serde_json::to_string(&parsed.forms)
            .unwrap()
            .contains("sensitive"));
        assert!(parsed.candidates.iter().any(
            |candidate| candidate.resolved.as_deref() == Some("https://example.test/api/items")
        ));
    }

    #[test]
    fn json_and_yaml_openapi_extract_operations_and_remote_refs() {
        let json = r#"{
          "openapi":"3.0.3",
          "servers":[{"url":"/api"}],
          "paths":{"/users":{"get":{"operationId":"listUsers"}}},
          "components":{"schemas":{"X":{"$ref":"https://remote.test/x.json"}}}
        }"#;
        let from_json = parse_openapi(
            "https://example.test/openapi.json",
            json,
            &DiscoveryBounds::default(),
            &lineage(),
        )
        .unwrap();
        assert_eq!(from_json.operations[0].method, "GET");
        assert_eq!(
            from_json.operations[0].resolved_url_template.as_deref(),
            Some("https://example.test/api/users")
        );
        assert_eq!(from_json.omissions[0].1, OmissionReason::RemoteReference);

        let yaml = r#"
swagger: "2.0"
host: api.example.test
basePath: /v2
schemes: [https]
paths:
  /pets:
    post:
      operationId: createPet
      responses: {}
definitions:
  Thing:
    $ref: https://remote.test/thing.yaml
"#;
        let from_yaml = parse_openapi(
            "https://example.test/swagger.yaml",
            yaml,
            &DiscoveryBounds::default(),
            &lineage(),
        )
        .unwrap();
        assert_eq!(
            from_yaml.operations[0].operation_id.as_deref(),
            Some("createPet")
        );
        assert_eq!(
            from_yaml.operations[0].resolved_url_template.as_deref(),
            Some("https://api.example.test/v2/pets")
        );
        assert_eq!(from_yaml.omissions[0].1, OmissionReason::RemoteReference);
    }
}
