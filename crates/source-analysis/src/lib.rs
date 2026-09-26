//! Deterministic inventory, bounded source context, conservative intra-file flows,
//! and merge-base-aware Git context. Flow analysis is lexical—not compiler-grade
//! or whole-program analysis—and never establishes exploitability by itself.
pub mod flow;
use anyhow::{bail, ensure, Context, Result};
use domain::{Candidate, Proof, Severity};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use storage::{hash, Redactor};
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceFile {
    pub path: PathBuf,
    pub relative_path: String,
    pub language: String,
    pub kind: String,
    pub bytes: u64,
    pub hash: String,
    pub lines: usize,
    pub chunks: Vec<SourceChunk>,
    pub dependencies: Vec<Dependency>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceChunk {
    pub start_line: usize,
    pub end_line: usize,
    pub text: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Inventory {
    pub files: Vec<SourceFile>,
    pub skipped: Vec<String>,
    pub total_bytes: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceSignal {
    pub path: PathBuf,
    pub line: usize,
    pub rule: String,
    pub source_hash: String,
    pub excerpt: String,
    pub automatically_verifiable: bool,
}

fn excluded(path: &Path) -> bool {
    path.components().any(|c| {
        let s = c.as_os_str().to_string_lossy().to_lowercase();
        [
            ".git",
            "target",
            "node_modules",
            "vendor",
            ".venv",
            "venv",
            ".ssh",
            ".aws",
            ".metisblack",
            "runs",
            ".env",
        ]
        .contains(&s.as_str())
            || s.ends_with(".pem")
            || s.ends_with(".key")
            || s.ends_with(".vault")
            || (s.starts_with(".env.") && !s.ends_with("example") && !s.ends_with("sample"))
    })
}
fn classify(path: &Path) -> (&'static str, &'static str) {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_lowercase();
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    if [
        "package.json",
        "cargo.toml",
        "cargo.lock",
        "go.mod",
        "go.sum",
        "pom.xml",
        "gemfile",
        "gemfile.lock",
        "composer.json",
        "composer.lock",
        "pyproject.toml",
        "poetry.lock",
        "pdm.lock",
        "uv.lock",
        "yarn.lock",
        "pnpm-lock.yaml",
        "package-lock.json",
        "packages.lock.json",
        "packages.config",
        "pipfile",
        "pipfile.lock",
    ]
    .contains(&name.as_str())
        || name.starts_with("requirements")
        || name.ends_with(".csproj")
        || name.ends_with(".gradle")
        || name == "build.gradle.kts"
    {
        return ("manifest", "manifest");
    }
    if name.starts_with("dockerfile")
        || [
            "tf", "tfvars", "yaml", "yml", "toml", "ini", "conf", "config", "json", "xml",
        ]
        .contains(&ext)
    {
        return ("configuration", "config");
    }
    match ext {
        "rs" => ("rust", "source"),
        "py" => ("python", "source"),
        "js" | "jsx" | "mjs" | "cjs" => ("javascript", "source"),
        "ts" | "tsx" => ("typescript", "source"),
        "go" => ("go", "source"),
        "java" | "kt" => ("jvm", "source"),
        "cs" => ("csharp", "source"),
        "php" => ("php", "source"),
        "rb" => ("ruby", "source"),
        "c" | "h" | "cpp" => ("c", "source"),
        "sh" | "ps1" => ("shell", "source"),
        "html" | "vue" | "svelte" => ("template", "source"),
        "sql" => ("sql", "migration"),
        "md" | "txt" | "rst" => ("text", "documentation"),
        _ => ("text", "other"),
    }
}
pub fn inventory(root: &Path, max_total_bytes: u64) -> Result<Inventory> {
    inventory_with_overrides(root, max_total_bytes, &domain::ExpertOverrides::default())
}
pub fn inventory_with_overrides(
    root: &Path,
    max_total_bytes: u64,
    overrides: &domain::ExpertOverrides,
) -> Result<Inventory> {
    overrides.validate()?;
    let root = root.canonicalize()?;
    let base = if root.is_file() {
        root.parent().context("file parent")?
    } else {
        root.as_path()
    };
    let mut out = Inventory::default();
    let mut paths = vec![];
    for entry in WalkDir::new(&root)
        .follow_links(overrides.disables(domain::Control::FilesystemRoots))
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|e| {
            overrides.disables(domain::Control::SecretExposure)
                || !excluded(e.path().strip_prefix(base).unwrap_or(e.path()))
        })
    {
        let entry = entry?;
        if entry.file_type().is_symlink() {
            out.skipped
                .push(format!("{}: symlink", entry.path().display()));
            continue;
        }
        if entry.file_type().is_file() {
            paths.push(entry.into_path());
        }
    }
    for path in paths {
        let rel = path.strip_prefix(base)?.to_string_lossy().to_string();
        let size = fs::metadata(&path)?.len();
        if !overrides.disables(domain::Control::DataSampling)
            && (size > 1_048_576 || out.total_bytes + size > max_total_bytes)
        {
            out.skipped.push(format!("{rel}: byte budget"));
            continue;
        }
        let bytes = fs::read(&path)?;
        let Ok(text) = std::str::from_utf8(&bytes) else {
            out.skipped.push(format!("{rel}: binary/non-UTF8"));
            continue;
        };
        if text.contains('\0') {
            out.skipped.push(format!("{rel}: binary"));
            continue;
        }
        let (language, kind) = classify(&path);
        let lines: Vec<_> = text.lines().collect();
        let redactor = Redactor::with_override(overrides);
        let chunks = lines
            .chunks(120)
            .enumerate()
            .map(|(i, ls)| SourceChunk {
                start_line: i * 120 + 1,
                end_line: i * 120 + ls.len(),
                text: redactor.text(&ls.join("\n")),
            })
            .collect();
        let dependencies = if kind == "manifest" {
            parse_dependencies(&path, text, &redactor)
        } else {
            vec![]
        };
        out.total_bytes += size;
        out.files.push(SourceFile {
            path,
            relative_path: rel,
            language: language.into(),
            kind: kind.into(),
            bytes: size,
            hash: hash(&bytes),
            lines: lines.len(),
            chunks,
            dependencies,
        });
    }
    Ok(out)
}
fn dependency_source(spec: &str) -> Option<String> {
    let trimmed = spec.trim();
    let lower = trimmed.to_ascii_lowercase();
    if ["git+", "git://", "http://", "https://", "file:", "link:"]
        .iter()
        .any(|prefix| lower.starts_with(prefix))
    {
        Some(trimmed.into())
    } else if lower.starts_with("workspace:") {
        Some("workspace".into())
    } else {
        None
    }
}

fn push_dependency(
    out: &mut Vec<Dependency>,
    name: impl Into<String>,
    version: impl Into<String>,
    ecosystem: &str,
    source: Option<String>,
    scope: Option<&str>,
) {
    let name = name.into();
    if name.trim().is_empty() {
        return;
    }
    out.push(Dependency {
        name,
        version: version.into(),
        ecosystem: ecosystem.into(),
        source,
        scope: scope.map(str::to_owned),
    });
}

fn json_dependencies(
    value: &serde_json::Value,
    keys: &[(&str, &str)],
    ecosystem: &str,
    out: &mut Vec<Dependency>,
) {
    for (key, scope) in keys {
        if let Some(dependencies) = value[*key].as_object() {
            for (name, spec) in dependencies {
                let version = spec
                    .as_str()
                    .or_else(|| spec["version"].as_str())
                    .unwrap_or_default();
                let source = dependency_source(version).or_else(|| {
                    ["git", "path", "file", "url"]
                        .into_iter()
                        .find_map(|field| spec[field].as_str())
                        .map(str::to_owned)
                });
                push_dependency(out, name, version, ecosystem, source, Some(scope));
            }
        }
    }
}

fn parse_package_lock(value: &serde_json::Value, out: &mut Vec<Dependency>) {
    if let Some(packages) = value["packages"].as_object() {
        for (path, metadata) in packages {
            if path.is_empty() {
                continue;
            }
            let name = metadata["name"].as_str().map(str::to_owned).or_else(|| {
                path.rsplit_once("node_modules/")
                    .map(|(_, package)| package.to_owned())
            });
            if let Some(name) = name {
                let version = metadata["version"].as_str().unwrap_or_default();
                let source = metadata["resolved"]
                    .as_str()
                    .map(str::to_owned)
                    .or_else(|| dependency_source(version));
                push_dependency(out, name, version, "npm", source, Some("locked"));
            }
        }
    } else if let Some(dependencies) = value["dependencies"].as_object() {
        for (name, metadata) in dependencies {
            let version = metadata["version"].as_str().unwrap_or_default();
            push_dependency(
                out,
                name,
                version,
                "npm",
                metadata["resolved"].as_str().map(str::to_owned),
                Some("locked"),
            );
        }
    }
}

fn unquote(input: &str) -> &str {
    input.trim().trim_matches(|c| matches!(c, '\'' | '"'))
}

fn inline_value(input: &str, key: &str) -> Option<String> {
    let pattern = Regex::new(&format!(
        r#"(?:^|[{{,])\s*{}\s*=\s*[\"']([^\"']+)[\"']"#,
        regex::escape(key)
    ))
    .expect("escaped inline key");
    pattern
        .captures(input)
        .and_then(|capture| capture.get(1))
        .map(|value| value.as_str().to_owned())
}

fn parse_cargo_toml(text: &str, out: &mut Vec<Dependency>) {
    let assignment = Regex::new(r#"^\s*[\"']?([^\"'=\s]+)[\"']?\s*=\s*(.+?)\s*$"#)
        .expect("cargo assignment regex");
    let mut scope: Option<String> = None;
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or_default().trim();
        if line.starts_with('[') && line.ends_with(']') {
            let section = &line[1..line.len() - 1];
            scope = if section == "dependencies"
                || section == "dev-dependencies"
                || section == "build-dependencies"
                || section.ends_with(".dependencies")
                || section.ends_with(".dev-dependencies")
                || section.ends_with(".build-dependencies")
            {
                Some(section.to_owned())
            } else {
                None
            };
            continue;
        }
        let Some(group) = scope.as_deref() else {
            continue;
        };
        let Some(capture) = assignment.captures(line) else {
            continue;
        };
        let name = capture[1].to_owned();
        let spec = capture[2].trim();
        if spec.starts_with('{') {
            let version = inline_value(spec, "version").unwrap_or_else(|| {
                if spec.contains("workspace = true") {
                    "workspace".into()
                } else {
                    String::new()
                }
            });
            let source = inline_value(spec, "git")
                .map(|git| format!("git+{git}"))
                .or_else(|| inline_value(spec, "path").map(|path| format!("file:{path}")))
                .or_else(|| {
                    inline_value(spec, "registry").map(|registry| format!("registry:{registry}"))
                })
                .or_else(|| (version == "workspace").then(|| "workspace".into()));
            push_dependency(out, name, version, "cargo", source, Some(group));
        } else {
            let version = unquote(spec);
            push_dependency(
                out,
                name,
                version,
                "cargo",
                dependency_source(version),
                Some(group),
            );
        }
    }
}

fn parse_cargo_lock(text: &str, out: &mut Vec<Dependency>) {
    let mut name = None;
    let mut version = None;
    let mut source = None;
    let flush = |name: &mut Option<String>,
                 version: &mut Option<String>,
                 source: &mut Option<String>,
                 out: &mut Vec<Dependency>| {
        if let Some(package) = name.take() {
            push_dependency(
                out,
                package,
                version.take().unwrap_or_default(),
                "cargo",
                source.take(),
                Some("locked"),
            );
        }
    };
    for line in text.lines().map(str::trim) {
        if line == "[[package]]" {
            flush(&mut name, &mut version, &mut source, out);
        } else if let Some(value) = line.strip_prefix("name = ") {
            name = Some(unquote(value).into());
        } else if let Some(value) = line.strip_prefix("version = ") {
            version = Some(unquote(value).into());
        } else if let Some(value) = line.strip_prefix("source = ") {
            source = Some(unquote(value).into());
        }
    }
    flush(&mut name, &mut version, &mut source, out);
}

fn parse_python_requirements(text: &str, out: &mut Vec<Dependency>, scope: &str) {
    let direct = Regex::new(r"^([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*@\s*([^\s;]+)")
        .expect("python direct dependency regex");
    let requirement = Regex::new(
        r"^([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*((?:===|==|~=|!=|<=|>=|<|>).+?)?(?:\s*;.*)?$",
    )
    .expect("python requirement regex");
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or_default().trim();
        if line.is_empty() || line.starts_with('-') {
            continue;
        }
        if let Some(capture) = direct.captures(line) {
            push_dependency(
                out,
                &capture[1],
                "",
                "pypi",
                Some(capture[2].into()),
                Some(scope),
            );
        } else if let Some(capture) = requirement.captures(line) {
            push_dependency(
                out,
                &capture[1],
                capture.get(2).map(|m| m.as_str()).unwrap_or_default(),
                "pypi",
                None,
                Some(scope),
            );
        }
    }
}

fn parse_pyproject(text: &str, out: &mut Vec<Dependency>) {
    let arrays = Regex::new(r"(?s)(?:^|\n)\s*dependencies\s*=\s*\[(.*?)\]")
        .expect("pyproject dependency array regex");
    let quoted = Regex::new(r#"[\"']([^\"']+)[\"']"#).expect("quoted requirement regex");
    for array in arrays.captures_iter(text) {
        for requirement in quoted.captures_iter(&array[1]) {
            parse_python_requirements(&requirement[1], out, "runtime");
        }
    }

    let assignment =
        Regex::new(r#"^\s*([A-Za-z0-9_.-]+)\s*=\s*(.+?)\s*$"#).expect("poetry assignment regex");
    let mut scope = None;
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or_default().trim();
        if line.starts_with('[') && line.ends_with(']') {
            let section = &line[1..line.len() - 1];
            scope = if section == "tool.poetry.dependencies" {
                Some("runtime")
            } else if section.contains("poetry.group") && section.ends_with(".dependencies") {
                Some("development")
            } else {
                None
            };
            continue;
        }
        let Some(group) = scope else { continue };
        let Some(capture) = assignment.captures(line) else {
            continue;
        };
        if &capture[1] == "python" {
            continue;
        }
        let spec = capture[2].trim();
        let (version, source) = if spec.starts_with('{') {
            let version = inline_value(spec, "version").unwrap_or_default();
            let source = inline_value(spec, "git")
                .map(|git| format!("git+{git}"))
                .or_else(|| inline_value(spec, "path").map(|path| format!("file:{path}")))
                .or_else(|| inline_value(spec, "url"));
            (version, source)
        } else {
            let version = unquote(spec).to_owned();
            let source = dependency_source(&version);
            (version, source)
        };
        push_dependency(&mut *out, &capture[1], version, "pypi", source, Some(group));
    }
}

fn parse_python_toml_lock(text: &str, out: &mut Vec<Dependency>) {
    let mut name = None;
    let mut version = None;
    let mut source = None;
    let flush = |name: &mut Option<String>,
                 version: &mut Option<String>,
                 source: &mut Option<String>,
                 out: &mut Vec<Dependency>| {
        if let Some(package) = name.take() {
            push_dependency(
                out,
                package,
                version.take().unwrap_or_default(),
                "pypi",
                source.take(),
                Some("locked"),
            );
        }
    };
    for line in text.lines().map(str::trim) {
        if line == "[[package]]" {
            flush(&mut name, &mut version, &mut source, out);
        } else if let Some(value) = line.strip_prefix("name = ") {
            name = Some(unquote(value).into());
        } else if let Some(value) = line.strip_prefix("version = ") {
            version = Some(unquote(value).into());
        } else if let Some(value) = line.strip_prefix("source = ") {
            source = Some(unquote(value).into());
        }
    }
    flush(&mut name, &mut version, &mut source, out);
}

fn parse_pipfile(text: &str, out: &mut Vec<Dependency>) {
    let assignment = Regex::new(r#"^\s*([A-Za-z0-9_.-]+)\s*=\s*[\"']([^\"']+)[\"']"#)
        .expect("pipfile assignment regex");
    let mut scope = None;
    for line in text.lines().map(str::trim) {
        if line == "[packages]" {
            scope = Some("runtime");
        } else if line == "[dev-packages]" {
            scope = Some("development");
        } else if line.starts_with('[') {
            scope = None;
        } else if let (Some(group), Some(capture)) = (scope, assignment.captures(line)) {
            push_dependency(
                out,
                &capture[1],
                &capture[2],
                "pypi",
                dependency_source(&capture[2]),
                Some(group),
            );
        }
    }
}

fn xml_tag(block: &str, tag: &str) -> Option<String> {
    Regex::new(&format!(
        r"(?s)<{0}[^>]*>\s*(.*?)\s*</{0}>",
        regex::escape(tag)
    ))
    .expect("escaped XML tag")
    .captures(block)
    .map(|capture| capture[1].trim().to_owned())
}

fn parse_maven(text: &str, out: &mut Vec<Dependency>) {
    let block =
        Regex::new(r"(?s)<dependency\b[^>]*>(.*?)</dependency>").expect("maven dependency regex");
    for capture in block.captures_iter(text) {
        let body = &capture[1];
        let Some(artifact) = xml_tag(body, "artifactId") else {
            continue;
        };
        let group = xml_tag(body, "groupId").unwrap_or_default();
        let version = xml_tag(body, "version").unwrap_or_default();
        let scope = xml_tag(body, "scope").unwrap_or_else(|| "compile".into());
        push_dependency(
            out,
            format!("{group}:{artifact}"),
            version,
            "maven",
            None,
            Some(&scope),
        );
    }
}

fn parse_nuget(text: &str, out: &mut Vec<Dependency>) {
    let reference = Regex::new(
        r#"(?i)<(?:PackageReference|package)\b[^>]*(?:Include|id)\s*=\s*[\"']([^\"']+)[\"'][^>]*(?:Version|version)\s*=\s*[\"']([^\"']+)[\"']"#,
    )
    .expect("nuget reference regex");
    for capture in reference.captures_iter(text) {
        push_dependency(out, &capture[1], &capture[2], "nuget", None, Some("direct"));
    }
}

fn parse_dependencies(path: &Path, text: &str, redactor: &Redactor) -> Vec<Dependency> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let mut out = vec![];
    match name.as_str() {
        "package.json" | "composer.json" => {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
                let ecosystem = if name == "package.json" {
                    "npm"
                } else {
                    "composer"
                };
                json_dependencies(
                    &value,
                    &[
                        ("dependencies", "runtime"),
                        ("devDependencies", "development"),
                        ("peerDependencies", "peer"),
                        ("optionalDependencies", "optional"),
                        ("require", "runtime"),
                        ("require-dev", "development"),
                    ],
                    ecosystem,
                    &mut out,
                );
            }
        }
        "package-lock.json" => {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
                parse_package_lock(&value, &mut out);
            }
        }
        "cargo.toml" => parse_cargo_toml(text, &mut out),
        "cargo.lock" => parse_cargo_lock(text, &mut out),
        "pyproject.toml" => parse_pyproject(text, &mut out),
        "poetry.lock" | "pdm.lock" | "uv.lock" => parse_python_toml_lock(text, &mut out),
        "pipfile" => parse_pipfile(text, &mut out),
        "pipfile.lock" => {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
                json_dependencies(
                    &value,
                    &[("default", "runtime"), ("develop", "development")],
                    "pypi",
                    &mut out,
                );
            }
        }
        "go.mod" | "go.sum" => {
            let go = Regex::new(r"(?m)^\s*(?:require\s+)?([\w.-]+/[\w./-]+)\s+(v[^\s]+)")
                .expect("go dependency regex");
            for capture in go.captures_iter(text) {
                push_dependency(
                    &mut out,
                    &capture[1],
                    &capture[2],
                    "go",
                    None,
                    Some(if name == "go.sum" {
                        "checksum"
                    } else {
                        "require"
                    }),
                );
            }
        }
        "pom.xml" => parse_maven(text, &mut out),
        "packages.config" => parse_nuget(text, &mut out),
        value if value.ends_with(".csproj") => parse_nuget(text, &mut out),
        value if value.starts_with("requirements") => {
            parse_python_requirements(text, &mut out, "runtime")
        }
        "gemfile.lock" => {
            let gem =
                Regex::new(r"(?m)^\s{4}([A-Za-z0-9_.-]+) \(([^)]+)\)").expect("gem lock regex");
            for capture in gem.captures_iter(text) {
                push_dependency(
                    &mut out,
                    &capture[1],
                    &capture[2],
                    "rubygems",
                    None,
                    Some("locked"),
                );
            }
        }
        "gemfile" => {
            let gem =
                Regex::new(r#"(?m)^\s*gem\s+[\"']([^\"']+)[\"'](?:\s*,\s*[\"']([^\"']+)[\"'])?"#)
                    .expect("gemfile regex");
            for capture in gem.captures_iter(text) {
                push_dependency(
                    &mut out,
                    &capture[1],
                    capture.get(2).map(|m| m.as_str()).unwrap_or_default(),
                    "rubygems",
                    None,
                    Some("runtime"),
                );
            }
        }
        value if value.ends_with(".gradle") || value == "build.gradle.kts" => {
            let gradle = Regex::new(
                r#"(?m)^\s*(implementation|api|compileOnly|runtimeOnly|testImplementation)\s*\(?[\"']([^:\"']+):([^:\"']+):([^\"']+)[\"']"#,
            )
            .expect("gradle dependency regex");
            for capture in gradle.captures_iter(text) {
                push_dependency(
                    &mut out,
                    format!("{}:{}", &capture[2], &capture[3]),
                    &capture[4],
                    "maven",
                    None,
                    Some(&capture[1]),
                );
            }
        }
        _ => {}
    }
    let mut seen = BTreeSet::new();
    out.retain(|dependency| {
        seen.insert((
            dependency.name.clone(),
            dependency.version.clone(),
            dependency.ecosystem.clone(),
            dependency.source.clone(),
            dependency.scope.clone(),
        ))
    });
    for dependency in &mut out {
        dependency.name = redactor.text(&dependency.name);
        dependency.version = redactor.text(&dependency.version);
        dependency.source = dependency
            .source
            .as_deref()
            .map(|value| redactor.text(value));
    }
    out
}

pub fn scan(inventory: &Inventory) -> Result<Vec<SourceSignal>> {
    scan_with_overrides(inventory, &domain::ExpertOverrides::default())
}

pub fn scan_with_overrides(
    inventory: &Inventory,
    overrides: &domain::ExpertOverrides,
) -> Result<Vec<SourceSignal>> {
    overrides.validate()?;
    let redactor = Redactor::with_override(overrides);
    let mut signals = vec![];
    for file in &inventory.files {
        let bytes = fs::read(&file.path)?;
        ensure!(hash(&bytes) == file.hash, "source changed during review");
        let text = std::str::from_utf8(&bytes)?;
        for (index, line) in text.lines().enumerate() {
            for rule in [
                "tls-verification-disabled",
                "dynamic-request-evaluation",
                "shell-request-execution",
                "public-cloud-acl",
                "privileged-container",
                "untrusted-workflow-checkout",
                "workflow-command-execution",
            ] {
                if rule_matches(rule, line) {
                    signals.push(SourceSignal {
                        path: file.path.clone(),
                        line: index + 1,
                        rule: rule.into(),
                        source_hash: file.hash.clone(),
                        excerpt: redactor.text(line),
                        automatically_verifiable: rule == "tls-verification-disabled",
                    });
                }
            }
        }
    }
    Ok(signals)
}

fn code_line(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    if trimmed.is_empty()
        || trimmed.starts_with('#')
        || trimmed.starts_with("//")
        || trimmed.starts_with("/*")
        || trimmed.starts_with('*')
        || trimmed.starts_with("<!--")
    {
        return None;
    }
    Some(trimmed)
}

/// Retains identifiers and punctuation while removing quoted literals and trailing comments.
/// This keeps single-line source/sink rules from firing on examples, logging, and documentation.
fn executable_shape(line: &str) -> String {
    let mut output = String::with_capacity(line.len());
    let mut quote = None;
    let mut escaped = false;
    let mut chars = line.chars().peekable();
    while let Some(character) = chars.next() {
        if let Some(delimiter) = quote {
            output.push(' ');
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == delimiter {
                quote = None;
            }
            continue;
        }
        if matches!(character, '\'' | '"' | '`') {
            quote = Some(character);
            output.push(' ');
        } else if character == '#' || (character == '/' && chars.peek() == Some(&'/')) {
            break;
        } else {
            output.push(character);
        }
    }
    output
}

pub fn rule_matches(rule: &str, line: &str) -> bool {
    let Some(t) = code_line(line) else {
        return false;
    };
    match rule {
        "tls-verification-disabled" => Regex::new(
            r"\brequests\.(?:get|post|put|delete|patch|head|options|request)\s*\([^\n#]*\bverify\s*=\s*False\b",
        )
        .expect("rule regex")
        .is_match(t),
        "dynamic-request-evaluation" => {
            let code = executable_shape(t);
            Regex::new(r"\b(?:eval|Function)\s*\([^\n)]*\b(?:request|req)\s*(?:\.|\[)")
                .expect("rule regex")
                .is_match(&code)
        }
        "shell-request-execution" => {
            let code = executable_shape(t);
            Regex::new(
                r"\b(?:exec|execSync|spawn|spawnSync|system|popen|run|Popen|call|check_output)\s*\([^\n)]*\b(?:request|req)\s*(?:\.|\[)",
            )
            .expect("rule regex")
            .is_match(&code)
        }
        "public-cloud-acl" => Regex::new(
            r#"(?i)(?:acl\s*[:=]\s*[\"']?public-read\b|member\s*[:=]\s*[\"']?allUsers\b|(?:cidr|cidr_blocks?|source_ranges?)\s*[:=].*\b0\.0\.0\.0/0\b)"#,
        )
        .expect("rule regex")
        .is_match(t),
        "privileged-container" => Regex::new(r"(?i)\bprivileged\s*[:=]\s*true\b")
            .expect("rule regex")
            .is_match(t),
        "untrusted-workflow-checkout" => {
            Regex::new(r"^pull_request_target\s*:")
                .expect("rule regex")
                .is_match(t)
                || Regex::new(r"\bpull_request_target\s*:\s*(?:\{|\[|$)")
                    .expect("rule regex")
                    .is_match(t)
        }
        "workflow-command-execution" => {
            t.contains("n8n-nodes-base.executeCommand")
                || t.contains("--dangerously-bypass-approvals-and-sandbox")
        }
        _ => false,
    }
}
pub fn source_candidate(signal: &SourceSignal, receipt_id: String) -> Candidate {
    let (title, severity, cwe, impact, remediation) = match signal.rule.as_str() {
        "tls-verification-disabled" => (
            "TLS certificate verification disabled",
            Severity::Medium,
            "CWE-295",
            "The cited requests call disables server certificate authentication.",
            "Remove verify=False and configure a trusted CA bundle.",
        ),
        "dynamic-request-evaluation" => (
            "Request data reaches dynamic evaluation",
            Severity::High,
            "CWE-95",
            "Potential execution of untrusted input; reachability and sanitization require review.",
            "Replace evaluation with a constrained parser and explicit allowed operations.",
        ),
        "shell-request-execution" => (
            "Request data reaches process execution",
            Severity::High,
            "CWE-78",
            "Potential command injection; full data flow requires review.",
            "Use typed APIs and avoid building commands from request data.",
        ),
        _ => (
            "Configuration requires security review",
            Severity::Medium,
            "CWE-693",
            "The cited configuration may expose a privileged operation or public resource.",
            "Verify scope and business need; restrict access and privileges.",
        ),
    };
    Candidate{title:title.into(),description:format!("Rule {} matched a captured source line. {}",signal.rule,signal.excerpt),severity,severity_justification:"Severity reflects the explicit configuration or unvalidated source-to-sink lead; no live exploit is asserted.".into(),cvss:None,cwe:vec![cwe.into()],owasp:vec![],mitre:vec![],location:format!("{}:{}",signal.path.display(),signal.line),payload:String::new(),impact:impact.into(),remediation:remediation.into(),confidence:if signal.automatically_verifiable{0.9}else{0.55},auth_context:"source review".into(),test_identity:None,receipt_ids:vec![receipt_id],screenshots:vec![],chains_from:vec![],proof:if signal.automatically_verifiable{Proof::SourceRule{path:signal.path.clone(),line:signal.line,rule:signal.rule.clone(),source_hash:signal.source_hash.clone()}}else{Proof::Manual{procedure:"Trace callers, user control, sanitizers and deployment configuration; reproduce the smallest safe proof.".into()}}}
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DiffStatus {
    Added,
    Modified,
    Deleted,
    Renamed,
    TypeChanged,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiffFileChange {
    pub status: DiffStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_path: Option<String>,
    #[serde(default)]
    pub changed_lines: Vec<(usize, usize)>,
    #[serde(default)]
    pub patch: String,
    #[serde(default)]
    pub content_omitted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffContext {
    pub merge_base: String,
    pub head: String,
    pub changed_lines: BTreeMap<String, Vec<(usize, usize)>>,
    pub deleted_files: Vec<String>,
    #[serde(default)]
    pub files: Vec<DiffFileChange>,
}
impl DiffContext {
    pub fn introduced(&self, relative: &str, line: usize) -> bool {
        self.changed_lines.get(relative).is_some_and(|ranges| {
            ranges
                .iter()
                .any(|(start, end)| (*start..=*end).contains(&line))
        })
    }

    /// A deterministic, bounded representation suitable for provider context.
    pub fn provider_context(&self, max_bytes: usize) -> String {
        if max_bytes == 0 {
            return String::new();
        }
        let mut context = format!("merge-base: {}\nhead: {}\n", self.merge_base, self.head);
        for file in &self.files {
            let status = match file.status {
                DiffStatus::Added => "added",
                DiffStatus::Modified => "modified",
                DiffStatus::Deleted => "deleted",
                DiffStatus::Renamed => "renamed",
                DiffStatus::TypeChanged => "type-changed",
            };
            context.push_str(&format!(
                "\nfile: {status} old={:?} new={:?} changed={:?} omitted={}\n",
                file.old_path, file.new_path, file.changed_lines, file.content_omitted
            ));
            context.push_str(&file.patch);
            if !file.patch.ends_with('\n') {
                context.push('\n');
            }
            if context.len() >= max_bytes {
                truncate_utf8(&mut context, max_bytes);
                break;
            }
        }
        truncate_utf8(&mut context, max_bytes);
        context
    }
}

fn truncate_utf8(value: &mut String, max_bytes: usize) {
    if value.len() <= max_bytes {
        return;
    }
    let mut boundary = max_bytes;
    while boundary > 0 && !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value.truncate(boundary);
}
fn git(repo: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .arg("--no-pager")
        .arg("-c")
        .arg("core.hooksPath=/dev/null")
        .arg("-c")
        .arg("core.fsmonitor=false")
        .arg("-c")
        .arg("diff.external=")
        .arg("-C")
        .arg(repo)
        .args(args)
        .env_remove("GIT_EXTERNAL_DIFF")
        .env_remove("GIT_CONFIG_COUNT")
        .output()
        .context("git unavailable")?;
    ensure!(
        output.status.success(),
        "git read operation failed: {}",
        Redactor::default().text(&String::from_utf8_lossy(&output.stderr))
    );
    Ok(output.stdout)
}
fn resolve(repo: &Path, reference: &str) -> Result<String> {
    ensure!(
        !reference.starts_with('-') && !reference.contains(['\0', '\n']),
        "invalid Git reference"
    );
    let bytes = git(
        repo,
        &["rev-parse", "--verify", &format!("{reference}^{{commit}}")],
    )?;
    let id = String::from_utf8(bytes)?.trim().to_owned();
    ensure!(
        id.len() >= 40 && id.chars().all(|c| c.is_ascii_hexdigit()),
        "invalid commit ID"
    );
    Ok(id)
}
fn nul_field<'a>(fields: &mut impl Iterator<Item = &'a [u8]>) -> Result<String> {
    let bytes = fields
        .next()
        .context("truncated NUL-delimited Git output")?;
    Ok(std::str::from_utf8(bytes)
        .context("Git path is not valid UTF-8")?
        .to_owned())
}

fn changed_ranges(patch: &str) -> Result<Vec<(usize, usize)>> {
    let hunk = Regex::new(r"(?m)^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")?;
    let mut ranges = vec![];
    for capture in hunk.captures_iter(patch) {
        let start: usize = capture[1].parse()?;
        let count = capture
            .get(2)
            .map(|value| value.as_str().parse())
            .transpose()?
            .unwrap_or(1);
        if count > 0 {
            ranges.push((start, start + count - 1));
        }
    }
    Ok(ranges)
}

pub fn diff_context(repo: &Path, base: &str, head: &str) -> Result<DiffContext> {
    diff_context_with_overrides(repo, base, head, &domain::ExpertOverrides::default())
}

pub fn diff_context_with_overrides(
    repo: &Path,
    base: &str,
    head: &str,
    overrides: &domain::ExpertOverrides,
) -> Result<DiffContext> {
    overrides.validate()?;
    let base = resolve(repo, base)?;
    let head = resolve(repo, head)?;
    let merge_base = String::from_utf8(git(repo, &["merge-base", &base, &head])?)?
        .trim()
        .to_owned();
    let names = git(
        repo,
        &[
            "diff",
            "--name-status",
            "-z",
            "-M",
            "--no-ext-diff",
            "--no-textconv",
            &merge_base,
            &head,
            "--",
        ],
    )?;
    let mut fields = names
        .split(|byte| *byte == 0)
        .filter(|field| !field.is_empty());
    let mut files = vec![];
    let mut changed_lines = BTreeMap::<String, Vec<(usize, usize)>>::new();
    let mut deleted_files = vec![];
    let redactor = Redactor::with_override(overrides);
    while let Some(status_bytes) = fields.next() {
        let status_text = std::str::from_utf8(status_bytes).context("invalid Git status")?;
        let code = status_text.chars().next().context("empty Git status")?;
        let (status, old_path, new_path) = match code {
            'A' => (DiffStatus::Added, None, Some(nul_field(&mut fields)?)),
            'M' => {
                let path = nul_field(&mut fields)?;
                (DiffStatus::Modified, Some(path.clone()), Some(path))
            }
            'D' => (DiffStatus::Deleted, Some(nul_field(&mut fields)?), None),
            'R' | 'C' => (
                DiffStatus::Renamed,
                Some(nul_field(&mut fields)?),
                Some(nul_field(&mut fields)?),
            ),
            'T' => {
                let path = nul_field(&mut fields)?;
                (DiffStatus::TypeChanged, Some(path.clone()), Some(path))
            }
            other => bail!("unsupported Git diff status {other}"),
        };
        let display_path = new_path
            .as_deref()
            .or(old_path.as_deref())
            .unwrap_or_default();
        let secret_path = excluded(Path::new(display_path));
        let content_omitted = secret_path && !overrides.disables(domain::Control::SecretExposure);
        let mut patch = if content_omitted {
            "[content omitted by secret-exposure policy]\n".into()
        } else {
            let mut arguments = vec![
                "diff",
                "-M",
                "--no-ext-diff",
                "--no-textconv",
                "--unified=0",
                "--src-prefix=a/",
                "--dst-prefix=b/",
                &merge_base,
                &head,
                "--",
            ];
            if let Some(path) = old_path.as_deref() {
                arguments.push(path);
            }
            if let Some(path) = new_path.as_deref() {
                if old_path.as_deref() != Some(path) {
                    arguments.push(path);
                }
            }
            redactor.text(&String::from_utf8_lossy(&git(repo, &arguments)?))
        };
        if !overrides.disables(domain::Control::DataSampling) {
            truncate_utf8(&mut patch, 256 * 1024);
        }
        let ranges = if content_omitted || status == DiffStatus::Deleted {
            vec![]
        } else {
            changed_ranges(&patch)?
        };
        if let Some(path) = new_path.as_ref() {
            if !ranges.is_empty() {
                changed_lines.insert(path.clone(), ranges.clone());
            }
        }
        if status == DiffStatus::Deleted {
            if let Some(path) = old_path.as_ref() {
                deleted_files.push(path.clone());
            }
        }
        files.push(DiffFileChange {
            status,
            old_path,
            new_path,
            changed_lines: ranges,
            patch,
            content_omitted,
        });
    }
    Ok(DiffContext {
        merge_base,
        head,
        changed_lines,
        deleted_files,
        files,
    })
}
pub fn export_commit(repo: &Path, commit: &str, destination: &Path) -> Result<()> {
    export_commit_with_overrides(
        repo,
        commit,
        destination,
        &domain::ExpertOverrides::default(),
    )
}

#[cfg(unix)]
fn write_snapshot_symlink(path: &Path, target: &[u8]) -> Result<()> {
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt, os::unix::fs::symlink};

    let parent = path.parent().context("snapshot symlink requires parent")?;
    storage::secure_dir(parent)?;
    ensure!(
        fs::symlink_metadata(path).is_err(),
        "snapshot path already exists"
    );
    symlink(OsStr::from_bytes(target), path)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_snapshot_symlink(_path: &Path, _target: &[u8]) -> Result<()> {
    bail!("Git symlink export is unavailable on this platform")
}

/// Materializes a commit under the same expert-override policy used by inventory.
/// Integrity constraints on the destination and Git tree paths are never bypassed.
pub fn export_commit_with_overrides(
    repo: &Path,
    commit: &str,
    destination: &Path,
    overrides: &domain::ExpertOverrides,
) -> Result<()> {
    overrides.validate()?;
    let commit = resolve(repo, commit)?;
    match fs::symlink_metadata(destination) {
        Ok(_) => bail!("snapshot destination already exists"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let parent = destination
        .parent()
        .context("snapshot destination needs parent")?;
    storage::secure_dir(parent)?;
    let staging = parent.join(storage::random_id(".source-snapshot")?);
    storage::secure_dir(&staging)?;
    let tree = git(repo, &["ls-tree", "-rz", "--full-tree", &commit])?;
    let result = (|| {
        let mut total = 0u64;
        for entry in tree
            .split(|byte| *byte == 0)
            .filter(|entry| !entry.is_empty())
        {
            let text = std::str::from_utf8(entry).context("Git tree path is not valid UTF-8")?;
            let (meta, path) = text.split_once('\t').context("invalid Git tree")?;
            let fields: Vec<_> = meta.split_whitespace().collect();
            if fields.len() != 3 || fields[1] != "blob" {
                continue;
            }
            let relative = Path::new(path);
            if excluded(relative) && !overrides.disables(domain::Control::SecretExposure) {
                continue;
            }
            ensure!(
                !relative.is_absolute()
                    && !relative
                        .components()
                        .any(|component| matches!(component, std::path::Component::ParentDir)),
                "invalid tree path"
            );
            let is_regular = fields[0].starts_with("100");
            let is_symlink = fields[0] == "120000";
            if !(is_regular || is_symlink && overrides.disables(domain::Control::FilesystemRoots)) {
                continue;
            }
            let size = String::from_utf8(git(repo, &["cat-file", "-s", fields[2]])?)?
                .trim()
                .parse::<u64>()?;
            if !overrides.disables(domain::Control::DataSampling) && size > 1_048_576 {
                continue;
            }
            total = total.checked_add(size).context("snapshot size overflow")?;
            if !overrides.disables(domain::Control::DataSampling) && total > 50 * 1024 * 1024 {
                bail!("PR snapshot exceeds 50MiB budget");
            }
            let bytes = git(repo, &["cat-file", "blob", fields[2]])?;
            if is_symlink {
                write_snapshot_symlink(&staging.join(relative), &bytes)?;
            } else {
                storage::atomic_write(&staging.join(relative), &bytes)?;
            }
        }
        fs::rename(&staging, destination)?;
        Ok(())
    })();
    if result.is_err() && staging.exists() {
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::{Control, ExpertOverrides};

    fn override_controls(controls: Vec<Control>) -> ExpertOverrides {
        ExpertOverrides {
            controls,
            unsafe_all: false,
            reason: "source analysis regression test".into(),
            actor: "test-operator".into(),
            acknowledged: true,
            timestamp_ms: 1,
        }
    }

    fn write(path: &Path, contents: &str) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, contents)?;
        Ok(())
    }

    fn git_test(repo: &Path, arguments: &[&str]) -> Result<String> {
        let output = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(arguments)
            .output()?;
        ensure!(
            output.status.success(),
            "git {:?} failed: {}",
            arguments,
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(String::from_utf8(output.stdout)?)
    }

    fn init_repo(repo: &Path) -> Result<()> {
        git_test(repo, &["init", "--quiet"])?;
        git_test(
            repo,
            &["config", "user.email", "source-analysis@example.test"],
        )?;
        git_test(repo, &["config", "user.name", "Source Analysis Test"])?;
        Ok(())
    }

    fn commit(repo: &Path, message: &str) -> Result<String> {
        git_test(repo, &["add", "-A"])?;
        git_test(repo, &["commit", "--quiet", "-m", message])?;
        Ok(git_test(repo, &["rev-parse", "HEAD"])?.trim().into())
    }

    #[test]
    fn inventories_manifests_and_skills() -> Result<()> {
        let d = tempfile::tempdir()?;
        for name in [
            "package.json",
            "Cargo.toml",
            "Cargo.lock",
            "requirements.txt",
            "go.mod",
            "pom.xml",
            "Gemfile.lock",
            "Dockerfile",
            "workflow.json",
            "SKILL.md",
        ] {
            fs::write(d.path().join(name), "{}")?;
        }
        let i = inventory(d.path(), 100_000)?;
        assert_eq!(i.files.len(), 10);
        assert!(i.files.iter().any(|f| f.relative_path == "SKILL.md"));
        Ok(())
    }

    #[test]
    fn parses_ecosystems_with_versions_sources_and_scopes() -> Result<()> {
        let directory = tempfile::tempdir()?;
        write(
            &directory.path().join("package.json"),
            r#"{"dependencies":{"react":"^19.0.0","internal":"workspace:*"},"devDependencies":{"vitest":"3.0.0"}}"#,
        )?;
        write(
            &directory.path().join("Cargo.toml"),
            r#"[dependencies]
serde = "1"
widget = { version = "2", git = "https://example.test/widget.git" }
local = { path = "../local" }
[dev-dependencies]
tempfile = "3"
"#,
        )?;
        write(
            &directory.path().join("Cargo.lock"),
            r#"[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        )?;
        write(
            &directory.path().join("requirements.txt"),
            "flask==3.1.0\nprivate-lib @ git+https://example.test/lib.git@main\n",
        )?;
        write(
            &directory.path().join("go.mod"),
            "module example.test/app\nrequire example.com/dependency v1.2.3\n",
        )?;
        write(
            &directory.path().join("pom.xml"),
            "<project><dependencies><dependency><groupId>org.example</groupId><artifactId>core</artifactId><version>4.5.6</version><scope>runtime</scope></dependency></dependencies></project>",
        )?;
        write(
            &directory.path().join("pyproject.toml"),
            "[project]\ndependencies = [\"httpx>=0.28\"]\n[tool.poetry.dependencies]\npython = \"^3.12\"\npendulum = { version = \"^3\", git = \"https://example.test/pendulum.git\" }\n",
        )?;
        write(
            &directory.path().join("app.csproj"),
            r#"<Project><ItemGroup><PackageReference Include="Dapper" Version="2.1.0" /></ItemGroup></Project>"#,
        )?;
        let inventory = inventory(directory.path(), 1_000_000)?;
        let dependencies: Vec<_> = inventory
            .files
            .iter()
            .flat_map(|file| file.dependencies.iter())
            .collect();
        let find = |name: &str, ecosystem: &str| {
            dependencies
                .iter()
                .copied()
                .find(|dependency| dependency.name == name && dependency.ecosystem == ecosystem)
                .unwrap_or_else(|| panic!("missing {ecosystem} dependency {name}"))
        };
        assert_eq!(find("react", "npm").version, "^19.0.0");
        assert_eq!(find("internal", "npm").source.as_deref(), Some("workspace"));
        assert_eq!(find("vitest", "npm").scope.as_deref(), Some("development"));
        assert_eq!(find("widget", "cargo").version, "2");
        assert_eq!(
            find("widget", "cargo").source.as_deref(),
            Some("git+https://example.test/widget.git")
        );
        assert!(dependencies.iter().any(|dependency| {
            dependency.name == "serde"
                && dependency.ecosystem == "cargo"
                && dependency.scope.as_deref() == Some("dependencies")
        }));
        assert_eq!(find("flask", "pypi").version, "==3.1.0");
        assert_eq!(
            find("private-lib", "pypi").source.as_deref(),
            Some("git+https://example.test/lib.git@main")
        );
        assert_eq!(find("example.com/dependency", "go").version, "v1.2.3");
        assert_eq!(
            find("org.example:core", "maven").scope.as_deref(),
            Some("runtime")
        );
        assert_eq!(find("httpx", "pypi").version, ">=0.28");
        assert_eq!(find("Dapper", "nuget").version, "2.1.0");
        Ok(())
    }

    #[test]
    fn inventory_overrides_are_independent_and_auditable() -> Result<()> {
        let directory = tempfile::tempdir()?;
        write(
            &directory.path().join(".env"),
            "api_key=abcdefghijklmnopqrstuv\n",
        )?;
        write(&directory.path().join("large.txt"), "1234567890")?;

        let defaults = inventory(directory.path(), 5)?;
        assert!(defaults.files.is_empty());
        assert!(defaults
            .skipped
            .iter()
            .any(|entry| entry.contains("byte budget")));

        let exposure = override_controls(vec![Control::SecretExposure, Control::DataSampling]);
        let protected = inventory_with_overrides(directory.path(), 5, &exposure)?;
        let environment = protected
            .files
            .iter()
            .find(|file| file.relative_path == ".env")
            .context("secret-exposure override did not include .env")?;
        assert!(environment.chunks[0].text.contains("[REDACTED]"));
        assert!(protected
            .files
            .iter()
            .any(|file| file.relative_path == "large.txt"));

        let raw = override_controls(vec![
            Control::SecretExposure,
            Control::SecretRedaction,
            Control::DataSampling,
        ]);
        let unredacted = inventory_with_overrides(directory.path(), 5, &raw)?;
        assert!(unredacted
            .files
            .iter()
            .find(|file| file.relative_path == ".env")
            .context("raw .env missing")?
            .chunks[0]
            .text
            .contains("abcdefghijklmnopqrstuv"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn filesystem_root_override_controls_symlink_traversal() -> Result<()> {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        write(&outside.path().join("outside.txt"), "outside")?;
        symlink(
            outside.path().join("outside.txt"),
            root.path().join("linked.txt"),
        )?;
        let protected = inventory(root.path(), 10_000)?;
        assert!(protected.files.is_empty());
        let bypass = override_controls(vec![Control::FilesystemRoots]);
        let followed = inventory_with_overrides(root.path(), 10_000, &bypass)?;
        assert!(followed
            .files
            .iter()
            .any(|file| file.relative_path == "linked.txt"));
        Ok(())
    }

    #[test]
    fn source_rules_reject_comments_strings_and_similar_identifiers() {
        assert!(rule_matches(
            "tls-verification-disabled",
            "requests.get(url, verify=False)"
        ));
        assert!(!rule_matches(
            "tls-verification-disabled",
            "# requests.get(url, verify=False)"
        ));
        assert!(!rule_matches(
            "tls-verification-disabled",
            "requests.get(url, verify=True)"
        ));
        assert!(rule_matches(
            "dynamic-request-evaluation",
            "result = eval(request.form['expression'])"
        ));
        assert!(!rule_matches(
            "dynamic-request-evaluation",
            r#"logger.info("eval(req.body)")"#
        ));
        assert!(!rule_matches(
            "dynamic-request-evaluation",
            "safe_parse(value) // eval(req.body)"
        ));
        assert!(rule_matches(
            "shell-request-execution",
            "subprocess.run(req.body, shell=True)"
        ));
        assert!(!rule_matches(
            "shell-request-execution",
            "executor(req.body)"
        ));
        assert!(rule_matches(
            "public-cloud-acl",
            "cidr_blocks = [\"0.0.0.0/0\"]"
        ));
        assert!(!rule_matches(
            "public-cloud-acl",
            "description = \"example address 0.0.0.0/0\""
        ));
    }

    #[test]
    fn scan_honors_secret_redaction_override() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let token = "abcdefghijklmnopqrstuv";
        write(
            &directory.path().join("app.py"),
            &format!("requests.get(url, verify=False, api_key=\"{token}\")\n"),
        )?;
        let inventory = inventory(directory.path(), 10_000)?;
        let protected = scan(&inventory)?;
        assert!(protected[0].excerpt.contains("[REDACTED]"));
        assert!(!protected[0].excerpt.contains(token));
        let bypass = override_controls(vec![Control::SecretRedaction]);
        let raw = scan_with_overrides(&inventory, &bypass)?;
        assert!(raw[0].excerpt.contains(token));
        Ok(())
    }

    #[test]
    fn changed_line_membership() {
        let d = DiffContext {
            merge_base: "a".into(),
            head: "b".into(),
            changed_lines: BTreeMap::from([("a.py".into(), vec![(10, 12)])]),
            deleted_files: vec![],
            files: vec![],
        };
        assert!(d.introduced("a.py", 11));
        assert!(!d.introduced("a.py", 9));
    }

    #[test]
    fn diff_context_tracks_rename_delete_and_weird_paths() -> Result<()> {
        let directory = tempfile::tempdir()?;
        init_repo(directory.path())?;
        write(&directory.path().join("rename me.txt"), "same content\n")?;
        write(&directory.path().join("delete-me.txt"), "obsolete\n")?;
        let weird = "odd\tname\nline.rs";
        write(&directory.path().join(weird), "fn old() {}\n")?;
        let base = commit(directory.path(), "base")?;

        fs::rename(
            directory.path().join("rename me.txt"),
            directory.path().join("renamed file.txt"),
        )?;
        fs::remove_file(directory.path().join("delete-me.txt"))?;
        write(
            &directory.path().join(weird),
            "fn old() {}\nfn added() {}\n",
        )?;
        write(&directory.path().join("added.rs"), "fn added() {}\n")?;
        let head = commit(directory.path(), "head")?;

        let context = diff_context(directory.path(), &base, &head)?;
        assert_eq!(context.head, head);
        assert!(context.deleted_files.contains(&"delete-me.txt".into()));
        assert!(context.files.iter().any(|file| {
            file.status == DiffStatus::Renamed
                && file.old_path.as_deref() == Some("rename me.txt")
                && file.new_path.as_deref() == Some("renamed file.txt")
        }));
        assert!(context.files.iter().any(|file| {
            file.status == DiffStatus::Deleted && file.old_path.as_deref() == Some("delete-me.txt")
        }));
        assert!(context.files.iter().any(|file| {
            file.status == DiffStatus::Added && file.new_path.as_deref() == Some("added.rs")
        }));
        assert!(context.introduced(weird, 2));
        let provider = context.provider_context(100_000);
        assert!(provider.contains("file: renamed"));
        assert!(provider.contains("file: deleted"));
        assert!(provider.contains("fn added()"));
        assert!(context.provider_context(32).len() <= 32);
        Ok(())
    }

    #[test]
    fn diff_secret_content_requires_separate_exposure_and_redaction_overrides() -> Result<()> {
        let directory = tempfile::tempdir()?;
        init_repo(directory.path())?;
        write(&directory.path().join("README.md"), "base\n")?;
        let base = commit(directory.path(), "base")?;
        let token = "abcdefghijklmnopqrstuv";
        write(
            &directory.path().join(".env"),
            &format!("api_key={token}\n"),
        )?;
        let head = commit(directory.path(), "secret")?;

        let protected = diff_context(directory.path(), &base, &head)?;
        assert!(protected.files[0].content_omitted);
        assert!(!protected.files[0].patch.contains(token));

        let exposure = override_controls(vec![Control::SecretExposure]);
        let redacted = diff_context_with_overrides(directory.path(), &base, &head, &exposure)?;
        assert!(!redacted.files[0].content_omitted);
        assert!(redacted.files[0].patch.contains("[REDACTED]"));
        assert!(!redacted.files[0].patch.contains(token));

        let raw = override_controls(vec![Control::SecretExposure, Control::SecretRedaction]);
        let unredacted = diff_context_with_overrides(directory.path(), &base, &head, &raw)?;
        assert!(unredacted.files[0].patch.contains(token));
        Ok(())
    }

    #[test]
    fn export_commit_is_recursive_and_atomically_refuses_existing_destination() -> Result<()> {
        let repository = tempfile::tempdir()?;
        init_repo(repository.path())?;
        write(
            &repository.path().join("nested/deeper/file.txt"),
            "nested\n",
        )?;
        write(&repository.path().join("nested/odd\tname.txt"), "odd\n")?;
        write(&repository.path().join(".env"), "api_key=not-exported\n")?;
        let head = commit(repository.path(), "nested")?;
        let output = tempfile::tempdir()?;
        let snapshot = output.path().join("snapshot");
        export_commit(repository.path(), &head, &snapshot)?;
        assert_eq!(
            fs::read_to_string(snapshot.join("nested/deeper/file.txt"))?,
            "nested\n"
        );
        assert_eq!(
            fs::read_to_string(snapshot.join("nested/odd\tname.txt"))?,
            "odd\n"
        );
        assert!(!snapshot.join(".env").exists());
        let error = export_commit(repository.path(), &head, &snapshot).unwrap_err();
        assert!(error.to_string().contains("already exists"));
        assert_eq!(
            fs::read_to_string(snapshot.join("nested/deeper/file.txt"))?,
            "nested\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let broken = output.path().join("broken-snapshot-link");
            symlink(output.path().join("missing-target"), &broken)?;
            let error = export_commit(repository.path(), &head, &broken).unwrap_err();
            assert!(error.to_string().contains("already exists"));
            assert!(fs::symlink_metadata(&broken)?.file_type().is_symlink());
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn export_overrides_are_exact_isolated_and_unsafe_all_is_explicit() -> Result<()> {
        use std::os::unix::fs::symlink;

        let repository = tempfile::tempdir()?;
        init_repo(repository.path())?;
        write(&repository.path().join("visible.txt"), "visible\n")?;
        write(&repository.path().join("large.txt"), &"x".repeat(1_048_577))?;
        write(
            &repository.path().join(".env"),
            "api_key=export-override-secret\n",
        )?;
        symlink("visible.txt", repository.path().join("linked.txt"))?;
        let head = commit(repository.path(), "override fixtures")?;
        let output = tempfile::tempdir()?;

        let sampling = output.path().join("sampling");
        export_commit_with_overrides(
            repository.path(),
            &head,
            &sampling,
            &override_controls(vec![Control::DataSampling]),
        )?;
        assert!(sampling.join("large.txt").is_file());
        assert!(!sampling.join(".env").exists());
        assert!(fs::symlink_metadata(sampling.join("linked.txt")).is_err());

        let exposure = output.path().join("exposure");
        export_commit_with_overrides(
            repository.path(),
            &head,
            &exposure,
            &override_controls(vec![Control::SecretExposure]),
        )?;
        assert_eq!(
            fs::read_to_string(exposure.join(".env"))?,
            "api_key=export-override-secret\n"
        );
        assert!(!exposure.join("large.txt").exists());
        assert!(fs::symlink_metadata(exposure.join("linked.txt")).is_err());

        let roots = output.path().join("filesystem-roots");
        export_commit_with_overrides(
            repository.path(),
            &head,
            &roots,
            &override_controls(vec![Control::FilesystemRoots]),
        )?;
        assert!(fs::symlink_metadata(roots.join("linked.txt"))?
            .file_type()
            .is_symlink());
        assert_eq!(fs::read_to_string(roots.join("linked.txt"))?, "visible\n");
        assert!(!roots.join("large.txt").exists());
        assert!(!roots.join(".env").exists());

        let adjacent = output.path().join("adjacent-secret-redaction");
        export_commit_with_overrides(
            repository.path(),
            &head,
            &adjacent,
            &override_controls(vec![Control::SecretRedaction]),
        )?;
        assert!(!adjacent.join("large.txt").exists());
        assert!(!adjacent.join(".env").exists());
        assert!(fs::symlink_metadata(adjacent.join("linked.txt")).is_err());

        let all = output.path().join("unsafe-all");
        let unsafe_all = ExpertOverrides {
            controls: vec![],
            unsafe_all: true,
            reason: "explicit unsafe-all snapshot regression".into(),
            actor: "test-operator".into(),
            acknowledged: true,
            timestamp_ms: 1,
        };
        export_commit_with_overrides(repository.path(), &head, &all, &unsafe_all)?;
        assert!(all.join("large.txt").is_file());
        assert!(all.join(".env").is_file());
        assert!(fs::symlink_metadata(all.join("linked.txt"))?
            .file_type()
            .is_symlink());
        Ok(())
    }
}
