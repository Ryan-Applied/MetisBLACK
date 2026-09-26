mod common;

use api_validation::*;
use common::*;

fn normalize(
    document: &[u8],
    validation_plan: &ApiValidationPlan,
) -> anyhow::Result<NormalizedOpenApi> {
    normalize_openapi(
        OpenApiDocumentInput {
            source_url: SOURCE,
            document,
            receipt: receipt("source", 'd'),
        },
        validation_plan,
    )
}

#[test]
fn json_and_yaml_v3_normalize_to_the_same_operation_contract() {
    let yaml = br##"
openapi: 3.0.3
info: {title: fixture, version: "1"}
servers:
  - url: https://api.example.test/v1
paths:
  /users:
    get:
      operationId: listUsers
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema: {$ref: "#/components/schemas/Payload"}
        "204": {description: empty}
components:
  schemas:
    Payload:
      type: object
      required: [id, tags]
      properties:
        id: {type: integer}
        tags:
          type: array
          items: {type: string}
"##;
    let json = normalize(v3_document(), &plan()).unwrap();
    let yaml = normalize(yaml, &plan()).unwrap();
    assert_ne!(json.document_hash, yaml.document_hash);
    assert_eq!(json.operations, yaml.operations);
    assert_eq!(
        json.operations[0].canonical_hash().unwrap(),
        yaml.operations[0].canonical_hash().unwrap()
    );
    assert!(json.operations[0].probe_id.starts_with("api-schema-"));
    assert_eq!(json.operations[0].probe_id.len(), 75);
    assert_eq!(
        json.operations[0].canonical_hash().unwrap(),
        "f2e358329c08ec75a2f77723667914f63f17eab85f006caaf14846710b357387"
    );
}

#[test]
fn v2_json_normalizes_responses_and_exact_base_path_url() {
    let document = br##"{
      "swagger":"2.0",
      "info":{"title":"fixture","version":"1"},
      "schemes":["https"],
      "host":"api.example.test",
      "basePath":"/v2/base",
      "produces":["application/json"],
      "paths":{"/users":{"get":{
        "operationId":"listUsers",
        "responses":{"200":{"description":"ok","schema":{"type":"array","items":{"type":"integer"}}}}
      }}}
    }"##;
    let normalized = normalize(document, &plan()).unwrap();
    let operation = &normalized.operations[0];
    assert_eq!(operation.server_url, "https://api.example.test/v2/base");
    assert_eq!(
        operation.request_url,
        "https://api.example.test/v2/base/users"
    );
    assert_eq!(
        operation.responses[0].media[0].media_type,
        "application/json"
    );
    assert!(matches!(
        operation.responses[0].media[0].schema,
        Some(NormalizedSchema::Array { .. })
    ));
}

#[test]
fn v2_json_and_yaml_normalize_to_the_same_operation_contract() {
    let json = br##"{
      "swagger":"2.0",
      "info":{"title":"fixture","version":"1"},
      "schemes":["https"],
      "host":"api.example.test",
      "basePath":"/v2/base",
      "produces":["application/json"],
      "paths":{"/users":{"get":{
        "operationId":"listUsers",
        "responses":{"200":{"description":"ok","schema":{"type":"array","items":{"type":"integer"}}}}
      }}}
    }"##;
    let yaml = br##"
swagger: "2.0"
info: {title: fixture, version: "1"}
schemes: [https]
host: api.example.test
basePath: /v2/base
produces: [application/json]
paths:
  /users:
    get:
      operationId: listUsers
      responses:
        "200":
          description: ok
          schema:
            type: array
            items: {type: integer}
"##;
    let json = normalize(json, &plan()).unwrap();
    let yaml = normalize(yaml, &plan()).unwrap();
    assert_ne!(json.document_hash, yaml.document_hash);
    assert_eq!(json.operations, yaml.operations);
}

#[test]
fn v3_relative_server_base_path_is_preserved_when_materializing_request() {
    let document = br##"{
      "openapi":"3.1.0",
      "servers":[{"url":"../gateway/v3/"}],
      "paths":{"/users":{"get":{"operationId":"listUsers","responses":{"204":{"description":"ok"}}}}}
    }"##;
    let normalized = normalize(document, &plan()).unwrap();
    let operation = &normalized.operations[0];
    assert_eq!(operation.server_url, "https://api.example.test/gateway/v3/");
    assert_eq!(
        operation.request_url,
        "https://api.example.test/gateway/v3/users"
    );
    assert_eq!(
        materialize_request_url("https://api.example.test/root/base/", "/health").unwrap(),
        "https://api.example.test/root/base/health"
    );
}

#[test]
fn ambiguous_and_variable_servers_are_rejected() {
    let ambiguous = br##"{
      "openapi":"3.0.3",
      "servers":[{"url":"https://a.example.test"},{"url":"https://b.example.test"}],
      "paths":{"/users":{"get":{"operationId":"listUsers","responses":{"204":{"description":"ok"}}}}}
    }"##;
    assert!(normalize(ambiguous, &plan())
        .unwrap_err()
        .to_string()
        .contains("ambiguous"));

    let variable = br##"{
      "openapi":"3.0.3",
      "servers":[{"url":"https://{tenant}.example.test","variables":{"tenant":{"default":"a"}}}],
      "paths":{"/users":{"get":{"operationId":"listUsers","responses":{"204":{"description":"ok"}}}}}
    }"##;
    assert!(normalize(variable, &plan())
        .unwrap_err()
        .to_string()
        .contains("variable"));

    assert!(materialize_request_url("https://api.example.test/v1", "/users/{id}").is_err());
}

#[test]
fn local_refs_resolve_but_remote_and_cyclic_refs_fail_closed() {
    normalize(v3_document(), &plan()).unwrap();

    let remote = br##"{
      "openapi":"3.0.3","servers":[{"url":"https://api.example.test"}],
      "paths":{"/users":{"get":{"operationId":"listUsers","responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"$ref":"https://schemas.example.test/payload.json"}}}}}}}}
    }"##;
    assert!(normalize(remote, &plan())
        .unwrap_err()
        .to_string()
        .contains("remote"));

    let unused_remote = br##"{
      "openapi":"3.0.3","servers":[{"url":"https://api.example.test"}],
      "paths":{"/users":{"get":{"operationId":"listUsers","responses":{"204":{"description":"ok"}}}}},
      "components":{"schemas":{"Unused":{"$ref":"https://schemas.example.test/unused.json"}}}
    }"##;
    normalize(unused_remote, &plan()).unwrap();

    let example_payload_ref = br##"{
      "openapi":"3.0.3","servers":[{"url":"https://api.example.test"}],
      "paths":{"/users":{"get":{"operationId":"listUsers","responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"type":"object"},"example":{"$ref":"https://payload.example.test/not-a-schema-ref"}}}}}}}}
    }"##;
    let normalized = normalize(example_payload_ref, &plan()).unwrap();
    assert!(normalized.operations[0].responses[0].media[0]
        .unsupported
        .iter()
        .any(|entry| entry.keyword == "example"));

    let cycle = br##"{
      "openapi":"3.0.3","servers":[{"url":"https://api.example.test"}],
      "paths":{"/users":{"get":{"operationId":"listUsers","responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/A"}}}}}}}},
      "components":{"schemas":{"A":{"$ref":"#/components/schemas/B"},"B":{"$ref":"#/components/schemas/A"}}}
    }"##;
    assert!(normalize(cycle, &plan())
        .unwrap_err()
        .to_string()
        .contains("cyclic"));
}

#[test]
fn reachable_non_string_refs_fail_closed() {
    let malformed = br##"{
      "openapi":"3.0.3",
      "servers":[{"url":"https://api.example.test/v1"}],
      "paths":{"/users":{"get":{
        "operationId":"listUsers",
        "responses":{"200":{"description":"ok","content":{
          "application/json":{"schema":{"$ref":7,"type":"string"}}
        }}}
      }}}
    }"##;
    assert!(normalize(malformed, &plan()).is_err());
}

#[test]
fn ref_depth_node_schema_and_document_caps_are_enforced() {
    let chain = br##"{
      "openapi":"3.0.3","servers":[{"url":"https://api.example.test"}],
      "paths":{"/users":{"get":{"operationId":"listUsers","responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/A"}}}}}}}},
      "components":{"schemas":{"A":{"$ref":"#/components/schemas/B"},"B":{"type":"string"}}}
    }"##;
    let mut bounded = plan();
    bounded.bounds.max_ref_depth = 1;
    assert!(normalize(chain, &bounded).is_err());

    let mut bounded = plan();
    bounded.bounds.max_ref_nodes = 1;
    assert!(normalize(chain, &bounded).is_err());

    let mut bounded = plan();
    bounded.bounds.max_schema_nodes = 1;
    assert!(normalize(v3_document(), &bounded).is_err());

    let mut bounded = plan();
    bounded.bounds.max_document_bytes = 10;
    assert!(normalize(v3_document(), &bounded).is_err());
}

#[test]
fn unsupported_schema_keywords_are_explicit_and_never_executed() {
    let document = br##"{
      "openapi":"3.0.3","servers":[{"url":"https://api.example.test"}],
      "paths":{"/users":{"get":{"operationId":"listUsers","responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"type":"string","format":"uuid","enum":["secret-value"]}}}}}}}}
    }"##;
    let normalized = normalize(document, &plan()).unwrap();
    let unsupported = &normalized.operations[0].responses[0].media[0].unsupported;
    assert_eq!(
        unsupported
            .iter()
            .map(|entry| entry.keyword.as_str())
            .collect::<Vec<_>>(),
        vec!["enum", "format"]
    );
    let encoded = serde_json::to_string(&normalized).unwrap();
    assert!(!encoded.contains("secret-value"));
}

#[test]
fn non_string_types_and_inapplicable_structural_keywords_are_explicitly_unsupported() {
    let document = br##"{
      "openapi":"3.1.0","servers":[{"url":"https://api.example.test"}],
      "paths":{"/users":{"get":{"operationId":"listUsers","responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"type":["string","null"],"properties":{"hidden":{"type":"string"}}}}}}}}}}
    }"##;
    let normalized = normalize(document, &plan()).unwrap();
    let keywords: Vec<_> = normalized.operations[0].responses[0].media[0]
        .unsupported
        .iter()
        .map(|entry| entry.keyword.as_str())
        .collect();
    assert_eq!(keywords, vec!["properties", "type:non_string"]);

    let attacker_type = br##"{
      "openapi":"3.1.0","servers":[{"url":"https://api.example.test"}],
      "paths":{"/users":{"get":{"operationId":"listUsers","responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"type":"attacker-controlled-secret"}}}}}}}}
    }"##;
    let normalized = normalize(attacker_type, &plan()).unwrap();
    let encoded = serde_json::to_string(&normalized).unwrap();
    assert!(!encoded.contains("attacker-controlled-secret"));
    assert!(encoded.contains("type:unsupported"));
}

#[test]
fn operation_id_and_source_selector_must_match_exactly() {
    let mut wrong_id = plan();
    wrong_id.selectors[0].operation_id = Some("otherOperation".to_owned());
    assert!(normalize(v3_document(), &wrong_id).is_err());

    let mut wrong_source = plan();
    wrong_source.selectors[0].openapi_source_url = "https://api.example.test/other.yaml".to_owned();
    assert!(normalize(v3_document(), &wrong_source).is_err());
}

#[test]
fn authenticated_operations_fail_closed_but_explicit_empty_override_is_eligible() {
    let secured = br##"{
      "openapi":"3.0.3","security":[{"bearerAuth":[]}],
      "servers":[{"url":"https://api.example.test"}],
      "paths":{"/users":{"get":{"operationId":"listUsers","responses":{"204":{"description":"ok"}}}}}
    }"##;
    assert!(normalize(secured, &plan())
        .unwrap_err()
        .to_string()
        .contains("authenticated"));

    let overridden = br##"{
      "openapi":"3.0.3","security":[{"bearerAuth":[]}],
      "servers":[{"url":"https://api.example.test"}],
      "paths":{"/users":{"get":{"operationId":"listUsers","security":[],"responses":{"204":{"description":"ok"}}}}}
    }"##;
    normalize(overridden, &plan()).unwrap();

    let anonymous_requirement = br##"{
      "openapi":"3.0.3","security":[{}],
      "servers":[{"url":"https://api.example.test"}],
      "paths":{"/users":{"get":{"operationId":"listUsers","responses":{"204":{"description":"ok"}}}}}
    }"##;
    normalize(anonymous_requirement, &plan()).unwrap();

    let operation_secured = br##"{
      "swagger":"2.0","security":[],"schemes":["https"],"host":"api.example.test",
      "paths":{"/users":{"get":{"operationId":"listUsers","security":[{"apiKey":[]}],"responses":{"204":{"description":"ok"}}}}}
    }"##;
    assert!(normalize(operation_secured, &plan()).is_err());

    let malformed = br##"{
      "openapi":"3.0.3","security":"none","servers":[{"url":"https://api.example.test"}],
      "paths":{"/users":{"get":{"operationId":"listUsers","responses":{"204":{"description":"ok"}}}}}
    }"##;
    assert!(normalize(malformed, &plan()).is_err());
}

#[test]
fn malformed_versions_and_swagger_server_fields_fail_closed() {
    for version in ["3.0.", "3.0.secret", "3.1.beta", "3.2.0"] {
        let document = format!(
            r##"{{
              "openapi":"{version}","servers":[{{"url":"https://api.example.test"}}],
              "paths":{{"/users":{{"get":{{"operationId":"listUsers","responses":{{"204":{{"description":"ok"}}}}}}}}}}
            }}"##
        );
        assert!(
            normalize(document.as_bytes(), &plan()).is_err(),
            "{version}"
        );
    }

    let bad_host = br##"{
      "swagger":"2.0","host":7,"basePath":"/v2",
      "paths":{"/users":{"get":{"operationId":"listUsers","responses":{"204":{"description":"ok"}}}}}
    }"##;
    assert!(normalize(bad_host, &plan()).is_err());

    let bad_base = br##"{
      "swagger":"2.0","host":"api.example.test","basePath":false,
      "paths":{"/users":{"get":{"operationId":"listUsers","responses":{"204":{"description":"ok"}}}}}
    }"##;
    assert!(normalize(bad_base, &plan()).is_err());
}

#[test]
fn required_parameters_and_request_bodies_are_not_input_free_probes() {
    let required_parameter = br##"{
      "openapi":"3.0.3","servers":[{"url":"https://api.example.test"}],
      "paths":{"/users":{"parameters":[{"name":"tenant","in":"query","required":true,"schema":{"type":"string"}}],"get":{"operationId":"listUsers","responses":{"204":{"description":"ok"}}}}}
    }"##;
    assert!(normalize(required_parameter, &plan())
        .unwrap_err()
        .to_string()
        .contains("parameters"));

    let overridden_optional = br##"{
      "openapi":"3.0.3","servers":[{"url":"https://api.example.test"}],
      "paths":{"/users":{"parameters":[{"name":"tenant","in":"query","required":true,"schema":{"type":"string"}}],"get":{"operationId":"listUsers","parameters":[{"name":"tenant","in":"query","required":false,"schema":{"type":"string"}}],"responses":{"204":{"description":"ok"}}}}}
    }"##;
    normalize(overridden_optional, &plan()).unwrap();

    let required_path = br##"{
      "openapi":"3.0.3","servers":[{"url":"https://api.example.test"}],
      "paths":{"/users":{"get":{"operationId":"listUsers","parameters":[{"name":"tenant","in":"path","required":false,"schema":{"type":"string"}}],"responses":{"204":{"description":"ok"}}}}}
    }"##;
    assert!(normalize(required_path, &plan()).is_err());

    let required_body = br##"{
      "openapi":"3.0.3","servers":[{"url":"https://api.example.test"}],
      "paths":{"/users":{"get":{"operationId":"listUsers","requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object"}}}},"responses":{"204":{"description":"ok"}}}}}
    }"##;
    assert!(normalize(required_body, &plan())
        .unwrap_err()
        .to_string()
        .contains("request body"));

    let optional_body = br##"{
      "openapi":"3.0.3","servers":[{"url":"https://api.example.test"}],
      "paths":{"/users":{"get":{"operationId":"listUsers","requestBody":{"required":false,"content":{"application/json":{"schema":{"type":"object"}}}},"responses":{"204":{"description":"ok"}}}}}
    }"##;
    normalize(optional_body, &plan()).unwrap();
}
