#![allow(dead_code)]

use api_validation::{
    normalize_openapi, ActualResponseObservation, ApiValidationPlan, JsonShapeCapture,
    NormalizedOpenApi, OpenApiDocumentInput, OperationContract, OperationSelector, ReceiptLineage,
    SafeMethod, ValidationBounds, API_VALIDATION_SCHEMA_VERSION,
};
use serde_json::Value;

pub const SOURCE: &str = "https://api.example.test/spec/openapi.yaml";

pub fn receipt(id: &str, digest: char) -> ReceiptLineage {
    ReceiptLineage {
        receipt_id: id.to_owned(),
        receipt_content_hash: digest.to_string().repeat(64),
    }
}

pub fn selector() -> OperationSelector {
    OperationSelector {
        discovery_plan_hash: "a".repeat(64),
        openapi_source_url: SOURCE.to_owned(),
        method: SafeMethod::Get,
        path: "/users".to_owned(),
        operation_id: Some("listUsers".to_owned()),
    }
}

pub fn plan() -> ApiValidationPlan {
    ApiValidationPlan {
        schema_version: API_VALIDATION_SCHEMA_VERSION,
        plan_id: "api-contract-fixture".to_owned(),
        selectors: vec![selector()],
        bounds: ValidationBounds::default(),
    }
}

pub fn v3_document() -> &'static [u8] {
    br##"{
      "openapi":"3.0.3",
      "info":{"title":"fixture","version":"1"},
      "servers":[{"url":"https://api.example.test/v1"}],
      "paths":{"/users":{"get":{
        "operationId":"listUsers",
        "responses":{
          "200":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Payload"}}}},
          "204":{"description":"empty"}
        }
      }}},
      "components":{"schemas":{"Payload":{
        "type":"object",
        "required":["id","tags"],
        "properties":{
          "id":{"type":"integer"},
          "tags":{"type":"array","items":{"type":"string"}}
        }
      }}}
    }"##
}

pub fn normalized() -> NormalizedOpenApi {
    normalize_openapi(
        OpenApiDocumentInput {
            source_url: SOURCE,
            document: v3_document(),
            receipt: receipt("source-receipt", 'b'),
        },
        &plan(),
    )
    .unwrap()
}

pub fn operation() -> OperationContract {
    normalized().operations.remove(0)
}

pub fn observation(
    operation: &OperationContract,
    status: u16,
    media_type: Option<&str>,
    body: Option<Value>,
    receipt_id: &str,
) -> ActualResponseObservation {
    let capture = body
        .as_ref()
        .map(|value| JsonShapeCapture::from_json(value, &ValidationBounds::default()).unwrap());
    ActualResponseObservation {
        selector: operation.selector.clone(),
        probe_id: operation.probe_id.clone(),
        contract_hash: operation.canonical_hash().unwrap(),
        status,
        media_type: media_type.map(str::to_owned),
        json_shape: capture.as_ref().map(|capture| capture.shape.clone()),
        body_present: body.is_some(),
        body_truncated: false,
        malformed_json: false,
        shape_truncated: capture.is_some_and(|capture| capture.truncated),
        receipt: receipt(receipt_id, 'c'),
    }
}
