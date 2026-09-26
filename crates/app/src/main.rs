use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use domain::{
    BrowserRunConfig, ChainRunConfig, Control, ExpertOverrides, Mode, ModelPanelConfig,
    NetworkRule, ProviderConfig, RunConfig, RunSnapshot, Severity,
};
use std::{
    io::{self, IsTerminal, Write},
    path::PathBuf,
    sync::atomic::Ordering,
};

#[derive(Parser, Debug)]
#[command(
    name = "metisblack",
    version,
    about = "Evidence-backed authorized security assessment"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    #[arg(long, global = true)]
    json: bool,
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[arg(long, global = true)]
    output: Option<PathBuf>,
    #[arg(long, global = true)]
    authorize: bool,
    #[arg(long, global = true)]
    dry_run: bool,
    #[arg(long, global = true)]
    provider: Option<String>,
    #[arg(long, global = true)]
    model: Option<String>,
    #[arg(long, global = true)]
    endpoint: Option<String>,
    #[arg(long, global = true)]
    key_env: Option<String>,
    #[arg(long, global = true)]
    playbooks: Option<PathBuf>,
    /// Heterogeneous model-panel JSON configuration.
    #[arg(long, global = true)]
    model_panel: Option<PathBuf>,
    /// Typed exploit-chain JSON configuration.
    #[arg(long, global = true)]
    chains: Option<PathBuf>,
    #[arg(long, global = true)]
    fail_on: Option<String>,
    #[arg(long, global = true)]
    include_operator_accepted: bool,
    #[arg(long, global = true)]
    unsafe_all: bool,
    #[arg(long = "override", global = true, value_delimiter = ',')]
    overrides: Vec<String>,
    #[arg(long, global = true)]
    override_reason: Option<String>,
    #[arg(long, global = true)]
    override_actor: Option<String>,
    #[arg(long, global = true)]
    acknowledge_unsafe: bool,
}
#[derive(Debug, Args)]
struct Targets {
    #[arg(required = true)]
    targets: Vec<String>,
}
#[derive(Debug, Subcommand)]
enum Command {
    Accept {
        run_dir: PathBuf,
        finding_id: String,
    },
    Tool {
        run_dir: PathBuf,
        #[arg(long)]
        request: PathBuf,
    },
    Run(Targets),
    Browser {
        target: String,
        #[arg(long, default_value = "http://127.0.0.1:9515")]
        webdriver: String,
        #[arg(long, default_value = "chrome")]
        browser: String,
        #[arg(long)]
        headed: bool,
        #[arg(long)]
        accept_insecure_certificates: bool,
        #[arg(long)]
        allow_raw_javascript: bool,
        #[arg(long)]
        allow_downloads: bool,
        #[arg(long)]
        plan: Option<PathBuf>,
        /// Authenticated multi-role browser workflow JSON.
        #[arg(long)]
        workflow: Option<PathBuf>,
    },
    Whitebox {
        path: PathBuf,
    },
    Greybox {
        path: PathBuf,
        #[arg(long)]
        url: String,
    },
    Host {
        target: String,
        #[arg(long, value_delimiter = ',', default_value = "22,80,443")]
        ports: Vec<u16>,
    },
    Cloud {
        path: PathBuf,
        #[arg(long)]
        account: String,
    },
    CloudLive {
        plan: PathBuf,
    },
    Aitest(Targets),
    Skills {
        path: PathBuf,
    },
    Pr {
        path: PathBuf,
        #[arg(long)]
        base: String,
        #[arg(long, default_value = "HEAD")]
        head: String,
    },
    Retest {
        run_dir: PathBuf,
        finding_id: String,
    },
    Resume {
        run_dir: PathBuf,
        /// Explicitly allow a failed browser/cloud/panel stage to repeat I/O.
        #[arg(long)]
        retry_failed_stages: bool,
    },
    Inspect {
        run_dir: PathBuf,
    },
    Demo,
    Tui {
        target: String,
    },
    Models,
    Controls,
    Agents {
        #[command(subcommand)]
        action: AgentCommand,
    },
    Integrations {
        config: PathBuf,
        run_dir: PathBuf,
        #[arg(long)]
        publish: bool,
    },
}
#[derive(Debug, Subcommand)]
enum AgentCommand {
    Builtins,
    Import {
        source: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Validate {
        path: PathBuf,
    },
    List {
        path: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let result = if cli.command.is_none() {
        repl().await
    } else {
        dispatch(cli).await
    };
    match result {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!(
                "error: {}",
                storage::Redactor::default().text(&format!("{e:#}"))
            );
            std::process::exit(2);
        }
    }
}
fn output_path(cli: &Cli) -> Result<PathBuf> {
    Ok(cli
        .output
        .clone()
        .unwrap_or_else(|| PathBuf::from("runs").join(format!("run-{}", domain::now_ms()))))
}
fn overrides(cli: &Cli) -> Result<ExpertOverrides> {
    let controls = cli
        .overrides
        .iter()
        .map(|s| {
            serde_json::from_value::<Control>(serde_json::json!(s.replace('-', "_")))
                .with_context(|| format!("unknown override {s}; run `metisblack controls`"))
        })
        .collect::<Result<Vec<_>>>()?;
    let value = ExpertOverrides {
        controls,
        unsafe_all: cli.unsafe_all,
        reason: cli.override_reason.clone().unwrap_or_default(),
        actor: cli.override_actor.clone().unwrap_or_default(),
        acknowledged: cli.acknowledge_unsafe,
        timestamp_ms: domain::now_ms(),
    };
    value.validate()?;
    Ok(value)
}
fn configure(cli: &Cli, mode: Mode, targets: Vec<String>) -> Result<RunConfig> {
    let mut c = if let Some(path) = &cli.config {
        let c: RunConfig = storage::read_json(path)?;
        anyhow::ensure!(c.mode == mode, "config mode must match command");
        c
    } else {
        orchestrator::default_config(mode, targets, output_path(cli)?)?
    };
    if let Some(out) = &cli.output {
        c.output_dir = out.clone();
    }
    c.authorized |= cli.authorize;
    if cli.unsafe_all || !cli.overrides.is_empty() {
        c.overrides = overrides(cli)?;
    } else {
        c.overrides.validate()?;
    }
    if let Some(kind) = &cli.provider {
        let endpoint = cli.endpoint.clone().unwrap_or_else(|| {
            match kind.as_str() {
                "anthropic" => "https://api.anthropic.com",
                "gemini" => "https://generativelanguage.googleapis.com",
                "ollama" => "http://localhost:11434",
                "llamacpp" => "http://localhost:8080/v1",
                _ => "https://api.openai.com/v1",
            }
            .into()
        });
        c.provider = Some(ProviderConfig {
            kind: kind.clone(),
            model: cli.model.clone().context("--provider requires --model")?,
            endpoint,
            key_env: cli.key_env.clone(),
            timeout_seconds: 60,
            max_output_tokens: 4096,
        });
    }
    if cli.playbooks.is_some() {
        c.playbooks = cli.playbooks.clone();
    }
    if let Some(path) = &cli.model_panel {
        c.model_panel = Some(storage::read_json::<ModelPanelConfig>(path)?);
    }
    if let Some(path) = &cli.chains {
        c.chains = Some(storage::read_json::<ChainRunConfig>(path)?);
    }
    Ok(c)
}
async fn dispatch(cli: Cli) -> Result<i32> {
    let command = cli.command.as_ref().context("command required")?;
    match command {
        Command::Models => {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::json!({"providers":["openai","openai-compatible","anthropic","gemini","ollama","llamacpp","mock"],"capabilities":{"tool_calling":true,"streaming":false,"token_telemetry":true,"cost_telemetry":false},"subscription":"Available only via explicit expert shell/tool-capability/sandbox overrides; no trusted subscription adapter is advertised."})
                )?
            );
            return Ok(0);
        }
        Command::Controls => {
            println!("{}", serde_json::to_string_pretty(Control::ALL)?);
            return Ok(0);
        }
        Command::Agents { action } => {
            let library = match action {
                AgentCommand::Builtins => agent_library::Library::builtins(),
                AgentCommand::Import { source, output } => {
                    agent_library::import_legacy(source, output)?
                }
                AgentCommand::Validate { path } | AgentCommand::List { path } => {
                    agent_library::Library::load(path)?
                }
            };
            let value = if matches!(action, AgentCommand::List { .. } | AgentCommand::Builtins) {
                serde_json::to_value(&library)?
            } else {
                serde_json::json!({"valid":true,"total":library.playbooks.len(),"categories":library.categories(),"warnings":library.playbooks.iter().flat_map(|b|b.warnings.iter().map(|w|format!("{}: {w}",b.id))).collect::<Vec<_>>()})
            };
            println!("{}", serde_json::to_string_pretty(&value)?);
            return Ok(0);
        }
        Command::Integrations {
            config,
            run_dir,
            publish,
        } => {
            let c: integrations::IntegrationConfig = storage::read_json(config)?;
            let mut run: RunSnapshot = storage::read_json(&run_dir.join("run-manifest.json"))?;
            let extra = optional_overrides(&cli)?;
            saved_banner(run_dir, extra.as_ref())?;
            if *publish {
                if cli.authorize {
                    run.config.authorized = true;
                    run.decisions.push(serde_json::json!({"action":"authorization","authorized":true,"timestamp_ms":domain::now_ms()}));
                }
                integrations::publish_with_overrides(&c, &run, extra).await?;
                println!("Published assessment summary.");
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&integrations::payload(&c, &run)?)?
                );
            }
            return Ok(0);
        }
        Command::Inspect { run_dir } => {
            let run: RunSnapshot = storage::read_json(&run_dir.join("run-manifest.json"))?;
            return summarize(&cli, &run);
        }
        Command::Retest {
            run_dir,
            finding_id,
        } => {
            let extra = optional_overrides(&cli)?;
            saved_banner(run_dir, extra.as_ref())?;
            let run =
                orchestrator::retest_with_overrides(run_dir, finding_id, cli.authorize, extra)
                    .await?;
            return summarize(&cli, &run);
        }
        Command::Resume {
            run_dir,
            retry_failed_stages,
        } => {
            let extra = optional_overrides(&cli)?;
            saved_banner(run_dir, extra.as_ref())?;
            let mut engine = orchestrator::Engine::resume(run_dir)?;
            if cli.authorize {
                engine.authorize()?;
            }
            if let Some(extra) = extra {
                engine.apply_overrides(extra)?;
            }
            if *retry_failed_stages {
                engine.retry_failed_stages()?;
            }
            let run = execute(engine, false).await?;
            return summarize(&cli, &run);
        }
        Command::Demo => {
            let output = output_path(&cli)?;
            let run = orchestrator::local_demo(&output).await?;
            return summarize(&cli, &run);
        }
        Command::Accept {
            run_dir,
            finding_id,
        } => {
            let extra = overrides(&cli)?;
            saved_banner(run_dir, Some(&extra))?;
            return summarize(
                &cli,
                &orchestrator::accept_finding(run_dir, finding_id, extra)?,
            );
        }
        Command::Tool { run_dir, request } => {
            let action: domain::ToolAction = storage::read_json(request)?;
            let extra = optional_overrides(&cli)?;
            saved_banner(run_dir, extra.as_ref())?;
            let run =
                orchestrator::execute_saved_tool(run_dir, action, cli.authorize, extra).await?;
            return summarize(&cli, &run);
        }
        _ => {}
    }
    let (mode, targets) = match command {
        Command::Run(t) => (Mode::Blackbox, t.targets.clone()),
        Command::Browser { target, .. } => (Mode::Browser, vec![target.clone()]),
        Command::Aitest(t) => (Mode::Ai, t.targets.clone()),
        Command::Whitebox { path } => (Mode::Whitebox, vec![path.display().to_string()]),
        Command::Greybox { url, .. } => (Mode::Greybox, vec![url.clone()]),
        Command::Skills { path } => (Mode::Skills, vec![path.display().to_string()]),
        Command::Cloud { path, .. } => (Mode::Cloud, vec![path.display().to_string()]),
        Command::CloudLive { plan } => {
            let plan: orchestrator::LiveCloudPlan = storage::read_json(plan)?;
            (
                Mode::CloudLive,
                orchestrator::live_cloud_scope_ids(&plan.scope),
            )
        }
        Command::Pr { path, .. } => (Mode::Pr, vec![path.display().to_string()]),
        Command::Host { target, .. } => (Mode::Host, vec![target.clone()]),
        Command::Tui { target } => (Mode::Blackbox, vec![target.clone()]),
        _ => unreachable!(),
    };
    let mut config = configure(&cli, mode, targets)?;
    match command {
        Command::Browser {
            webdriver,
            browser,
            headed,
            accept_insecure_certificates,
            allow_raw_javascript,
            allow_downloads,
            plan,
            workflow,
            ..
        } => {
            config.browser = Some(BrowserRunConfig {
                webdriver_endpoint: webdriver.clone(),
                browser: browser.clone(),
                headless: !headed,
                accept_insecure_certificates: *accept_insecure_certificates,
                allow_raw_javascript: *allow_raw_javascript,
                allow_downloads: *allow_downloads,
                plan: plan.clone(),
                workflow: workflow.clone(),
            });
        }
        Command::Greybox { path, .. } => config.source_root = Some(path.clone()),
        Command::Pr { base, head, .. } => {
            config.base_ref = Some(base.clone());
            config.head_ref = Some(head.clone());
        }
        Command::Cloud { account, .. } => config.scope.cloud_accounts.push(account.clone()),
        Command::CloudLive { plan } => {
            let live_plan: orchestrator::LiveCloudPlan = storage::read_json(plan)?;
            config.cloud_plan = Some(plan.clone());
            for scope_id in orchestrator::live_cloud_scope_ids(&live_plan.scope) {
                if !config.scope.cloud_accounts.contains(&scope_id) {
                    config.scope.cloud_accounts.push(scope_id);
                }
            }
        }
        Command::Host { target, ports } => {
            config.scope.network.push(NetworkRule {
                host: target.clone(),
                subdomains: false,
                ports: ports.clone(),
                paths: vec!["/".into()],
            });
            config.scope.allow_private = target == "localhost"
                || target
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|i| i.is_loopback());
        }
        _ => {}
    }
    config.validate()?;
    if config.overrides.active() {
        eprintln!(
            "EXPERT OVERRIDES ACTIVE — actor: {} — reason: {}\nDisabled controls: {:?}",
            config.overrides.actor,
            config.overrides.reason,
            config.overrides.disabled_controls()
        );
    }
    if cli.dry_run {
        println!("{}", serde_json::to_string_pretty(&config)?);
        return Ok(0);
    }
    if mode.has_network()
        && !config.authorized
        && !config.overrides.disables(Control::Authorization)
        && io::stdin().is_terminal()
    {
        eprint!(
            "Authorize assessment of {}? Type AUTHORIZE: ",
            config.targets.join(", ")
        );
        io::stderr().flush()?;
        let mut answer = String::new();
        io::stdin().read_line(&mut answer)?;
        config.authorized = answer.trim() == "AUTHORIZE";
    }
    let run = execute(
        orchestrator::Engine::new(config)?,
        matches!(command, Command::Tui { .. }),
    )
    .await?;
    summarize(&cli, &run)
}
fn summarize(cli: &Cli, run: &RunSnapshot) -> Result<i32> {
    unsafe_banner(&run.config.overrides);
    let counts = reporting::counts(run);
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &serde_json::json!({"run_id":run.id,"status":run.status,"counts":counts,"output_dir":run.config.output_dir,"expert_overrides":run.config.overrides})
            )?
        );
    } else {
        println!("Run {}: {:?}\n{} confirmed · {} needs review · {} rejected · {} fixed · {} operator-accepted\nReports: {}",run.id,run.status,counts.confirmed,counts.needs_review,counts.rejected,counts.fixed,counts.operator_accepted,run.config.output_dir.display());
    }
    if let Some(threshold) = &cli.fail_on {
        let severity: Severity =
            serde_json::from_value(serde_json::json!(threshold.to_lowercase()))
                .context("invalid severity")?;
        if integrations::gate_trips_with_operator(
            &run.findings,
            severity,
            run.config.mode == Mode::Pr,
            cli.include_operator_accepted,
        ) {
            return Ok(1);
        }
    }
    Ok(if run.status == domain::RunStatus::Failed {
        2
    } else if run.status == domain::RunStatus::Cancelled {
        130
    } else {
        0
    })
}
fn optional_overrides(cli: &Cli) -> Result<Option<ExpertOverrides>> {
    if cli.unsafe_all || !cli.overrides.is_empty() {
        Ok(Some(overrides(cli)?))
    } else {
        Ok(None)
    }
}
fn unsafe_banner(value: &ExpertOverrides) {
    if value.active() {
        eprintln!(
            "EXPERT OVERRIDES ACTIVE — {} — {}\nDisabled controls: {:?}",
            value.actor,
            value.reason,
            value.disabled_controls()
        );
    }
}
fn saved_banner(root: &std::path::Path, extra: Option<&ExpertOverrides>) -> Result<()> {
    if let Some(o) = extra {
        unsafe_banner(o);
    } else {
        let run: RunSnapshot = storage::read_json(&root.join("run-manifest.json"))?;
        unsafe_banner(&run.config.overrides);
    }
    Ok(())
}
async fn execute(mut engine: orchestrator::Engine, tui: bool) -> Result<RunSnapshot> {
    let control = engine.control.clone();
    let output = engine.snapshot.config.output_dir.clone();
    let task = engine.run();
    tokio::pin!(task);
    if tui {
        ui(task.as_mut(), &control, &output).await
    } else {
        tokio::select! {result=task.as_mut()=>result,_=tokio::signal::ctrl_c()=>{control.cancel.store(true,Ordering::SeqCst);task.await}}
    }
}
async fn ui<F>(
    mut task: std::pin::Pin<&mut F>,
    control: &orchestrator::RunControl,
    output: &std::path::Path,
) -> Result<RunSnapshot>
where
    F: std::future::Future<Output = Result<RunSnapshot>>,
{
    use crossterm::{
        event::{self, Event, KeyCode},
        execute,
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    };
    use ratatui::{
        backend::CrosstermBackend,
        widgets::{Block, Borders, Paragraph},
        Terminal,
    };
    anyhow::ensure!(io::stdout().is_terminal(), "TUI requires a terminal");
    enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    let result=async{let mut tick=tokio::time::interval(std::time::Duration::from_millis(200));loop{tokio::select!{result=task.as_mut()=>return result,_=tick.tick()=>{
  let text=match storage::read_json::<RunSnapshot>(&output.join("run-manifest.json")){Ok(run)=>{let c=reporting::counts(&run);format!("Run {}\nStatus: {:?}\nConfirmed: {}  Needs review: {}  Receipts: {}\n\np: pause and checkpoint   q: cancel\n\n{}",run.id,run.status,c.confirmed,c.needs_review,run.receipt_ids.len(),run.findings.iter().map(|f|format!("{:?} {:?}: {}",f.state,f.candidate.severity,f.candidate.title)).collect::<Vec<_>>().join("\n"))},Err(_)=>"Starting assessment…".into()};
  terminal.draw(|f|f.render_widget(Paragraph::new(text).block(Block::default().borders(Borders::ALL).title("MetisBLACK Mission Control")),f.area()))?;
  if event::poll(std::time::Duration::ZERO)?{if let Event::Key(k)=event::read()?{match k.code{KeyCode::Char('q')=>control.cancel.store(true,Ordering::SeqCst),KeyCode::Char('p')=>control.pause.store(true,Ordering::SeqCst),_=>{}}}}
 }}}}.await;
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}
async fn repl() -> Result<i32> {
    println!("MetisBLACK {} — enter CLI commands, help, or quit. Paths containing spaces require the ordinary CLI.",domain::VERSION);
    loop {
        print!("metisblack> ");
        io::stdout().flush()?;
        let mut line = String::new();
        if io::stdin().read_line(&mut line)? == 0 {
            break;
        }
        let line = line.trim();
        if matches!(line, "quit" | "exit") {
            break;
        }
        if line.is_empty() {
            continue;
        }
        let args = std::iter::once("metisblack").chain(line.split_whitespace());
        match Cli::try_parse_from(args) {
            Ok(cli) => {
                if cli.command.is_some() {
                    if let Err(e) = dispatch(cli).await {
                        eprintln!(
                            "error: {}",
                            storage::Redactor::default().text(&e.to_string())
                        );
                    }
                }
            }
            Err(e) => eprintln!("{e}"),
        }
    }
    Ok(0)
}
