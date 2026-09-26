//! Deterministic subprocess fixture. This binary is for integration tests only.

use serde_json::{json, Value};
use std::{
    env,
    io::{self, Read},
    process::{Command, Stdio},
    thread,
    time::Duration,
};

fn main() {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    if arguments
        .iter()
        .any(|argument| argument == "--descendant-pipe-holder")
    {
        thread::sleep(Duration::from_secs(15));
        return;
    }
    if arguments.iter().any(|argument| argument == "--version") {
        println!("fake-subscription-cli claude codex 1.2.3");
        return;
    }
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .expect("read fixture stdin");
    let request: Value =
        serde_json::from_str(&input).unwrap_or_else(|_| json!({"fixture":"valid"}));
    let fixture = request
        .get("fixture")
        .and_then(Value::as_str)
        .unwrap_or("valid");
    match fixture {
        "invalid" => print!("this is not json"),
        "trailing" => println!("{}\ntrailing prose", valid_result()),
        "oversized" => println!(
            "{}",
            json!({"type":"result","result":"x".repeat(1024 * 1024)})
        ),
        "sleep" => {
            let milliseconds = request
                .get("milliseconds")
                .and_then(Value::as_u64)
                .unwrap_or(5_000);
            thread::sleep(Duration::from_millis(milliseconds));
            println!("{}", valid_result());
        }
        "descendant_pipe" => {
            spawn_descendant_pipe_holder();
            println!("{}", valid_result());
        }
        "events" => {
            let count = request.get("count").and_then(Value::as_u64).unwrap_or(5);
            for index in 0..count {
                println!("{}", json!({"type":"progress","index":index}));
            }
            println!("{}", valid_result());
        }
        "turns" => {
            let count = request.get("count").and_then(Value::as_u64).unwrap_or(5);
            for index in 0..count {
                println!("{}", json!({"type":"turn.started","index":index}));
            }
            println!("{}", valid_result());
        }
        "environment" => {
            let variables = env::vars().collect::<std::collections::BTreeMap<_, _>>();
            println!(
                "{}",
                json!({"type":"result","result":json!({"text":serde_json::to_string(&variables).unwrap(),"calls":[]}).to_string()})
            );
        }
        "secret" => {
            let secret = env::var("HTTPS_PROXY").unwrap_or_default();
            eprintln!("proxy token={secret}");
            println!(
                "{}",
                json!({"type":"result","result":json!({"text":format!("observed {secret}"),"calls":[]}).to_string()})
            );
        }
        "arguments" => println!(
            "{}",
            json!({"type":"result","result":json!({"text":serde_json::to_string(&arguments).unwrap(),"calls":[]}).to_string()})
        ),
        "native_tool" => {
            if arguments.first().is_some_and(|argument| argument == "exec") {
                println!(
                    "{}",
                    json!({"type":"item.completed","item":{"id":"native-1","type":"tool_call","name":"http_get","arguments":{"url":"https://example.invalid"}}})
                );
            } else {
                println!(
                    "{}",
                    json!({"type":"assistant","message":{"content":[{"type":"tool_use","id":"native-1","name":"http_get","input":{"url":"https://example.invalid"}}]}})
                );
            }
            println!(
                "{}",
                json!({"type":"result","result":json!({"text":"native operation observed","calls":[]}).to_string()})
            );
        }
        "failure" => {
            eprintln!("fixture failure");
            std::process::exit(23);
        }
        _ => println!("{}", valid_result()),
    }
}

// The intentional orphan is the adversarial condition under test: it keeps
// inherited pipe handles open after the directly spawned fixture exits.
#[allow(clippy::zombie_processes)]
fn spawn_descendant_pipe_holder() {
    Command::new(env::current_exe().expect("fixture executable path"))
        .arg("--descendant-pipe-holder")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn compiled descendant pipe holder");
}

fn valid_result() -> Value {
    json!({
        "type":"result",
        "result":json!({
            "text":"fixture complete",
            "calls":[{"id":"call-1","name":"finish","arguments":{"reason":"done"}}],
            "input_tokens":11,
            "output_tokens":7,
            "cost_microusd":42
        }).to_string(),
        "usage":{"input_tokens":11,"output_tokens":7},
        "total_cost_usd":0.000042
    })
}
