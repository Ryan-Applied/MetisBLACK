use anyhow::Result;
use domain::{Control, ExpertOverrides, ProviderConfig};
use metisblack_providers::{decode_call, Provider, Requested, ToolCall};
use serde_json::json;

fn expert(controls: Vec<Control>) -> ExpertOverrides {
    ExpertOverrides {
        controls,
        reason: "Authorized provider regression fixture".into(),
        actor: "test-operator".into(),
        acknowledged: true,
        ..Default::default()
    }
}
fn config(kind: &str, endpoint: &str) -> ProviderConfig {
    ProviderConfig {
        kind: kind.into(),
        model: "fixture".into(),
        endpoint: endpoint.into(),
        key_env: None,
        timeout_seconds: 1,
        max_output_tokens: 256,
    }
}
#[test]
fn provider_capability_network_and_secret_controls_are_isolated() -> Result<()> {
    for (control, configuration) in [
        (
            Control::ProviderCapabilities,
            config("custom-provider", "https://example.test"),
        ),
        (
            Control::Network,
            config("openai-compatible", "http://example.test"),
        ),
        (
            Control::SecretExposure,
            config("openai-compatible", "https://user:fixture@example.test"),
        ),
    ] {
        assert!(Provider::new(configuration.clone()).is_err());
        assert!(Provider::with_overrides(configuration.clone(), expert(vec![control])).is_ok());
        assert!(Provider::with_overrides(
            configuration.clone(),
            expert(vec![Control::DataSampling])
        )
        .is_err());
        let mut all = expert(vec![]);
        all.unsafe_all = true;
        assert!(Provider::with_overrides(configuration, all).is_ok());
    }
    Ok(())
}
#[test]
fn supported_proofs_are_decoded_without_manual_coercion() -> Result<()> {
    let call = ToolCall {
        id: "fixture".into(),
        name: "submit_finding".into(),
        arguments: json!({"title":"Missing header","description":"Fixture","severity":"low","severity_justification":"Defense in depth","location":"https://example.test","impact":"Review","remediation":"Configure header","receipt_ids":["receipt-fixture"],"proof":{"kind":"missing_header","url":"https://example.test","header":"content-security-policy"}}),
    };
    let Requested::Candidate(c) = decode_call(&call)? else {
        panic!("candidate expected")
    };
    assert!(matches!(c.proof, domain::Proof::MissingHeader { .. }));
    Ok(())
}

#[tokio::test]
async fn direct_provider_api_requires_authorization_before_network_io() -> Result<()> {
    for controls in [
        vec![],
        vec![Control::Network],
        vec![Control::ProviderCapabilities],
    ] {
        let mut provider = Provider::with_overrides(
            config("openai-compatible", "https://example.test"),
            expert(controls),
        )?;
        let error = provider.complete(&[], &[]).await.unwrap_err();
        assert!(error.to_string().contains("require authorization"));
    }
    Ok(())
}
