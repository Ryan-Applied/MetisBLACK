//! Conservative language-aware intra-file flow tracing.
//!
//! This module deliberately implements a bounded lexical foundation rather than
//! pretending to be a compiler. It ignores comments and quoted literals, tracks
//! simple assignments and call propagation, and emits a path only when both an
//! HTTP-input source and a supported sink are present in the same file. A
//! `Traceable` result means the lexical hops are explicit; it does **not** mean a
//! vulnerability is verified. Calls whose behavior is unknown produce
//! `NeedsReview` paths.
use super::{Inventory, SourceFile};
use anyhow::{ensure, Context, Result};
use domain::ExpertOverrides;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};
use storage::{hash, Redactor};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct SourcePoint {
    pub path: PathBuf,
    pub line: usize,
    pub end_line: usize,
    pub column: usize,
    pub excerpt: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    HttpParameter,
    HttpBody,
    HttpHeader,
    HttpCookie,
    HttpPath,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SinkKind {
    Sql,
    Command,
    File,
    Request,
    Eval,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SanitizerKind {
    NumericCoercion,
    ShellEscaping,
    PathBasename,
    SqlParameterization,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlowSource {
    pub kind: SourceKind,
    pub point: SourcePoint,
    pub expression: String,
    pub variable: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlowSink {
    pub kind: SinkKind,
    pub point: SourcePoint,
    pub expression: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlowSanitizer {
    pub kind: SanitizerKind,
    pub point: SourcePoint,
    pub expression: String,
    pub protects: BTreeSet<SinkKind>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnknownHop {
    pub point: SourcePoint,
    pub expression: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FlowHop {
    Assignment {
        from: String,
        to: String,
        point: SourcePoint,
    },
    CallPropagation {
        function: String,
        from: String,
        to: String,
        point: SourcePoint,
    },
    Sanitizer(FlowSanitizer),
    Unknown(UnknownHop),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FlowStatus {
    /// Every intra-file lexical hop was explicit. This is not exploit verification.
    Traceable,
    /// Source and sink are traceable, but at least one call or bounded statement is ambiguous.
    NeedsReview,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlowPath {
    pub id: String,
    pub language: String,
    pub source_hash: String,
    pub source: FlowSource,
    pub sink: FlowSink,
    pub hops: Vec<FlowHop>,
    pub status: FlowStatus,
    pub limitation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlowAnalysis {
    pub path: PathBuf,
    pub language: String,
    pub source_hash: String,
    pub analyzed_lines: usize,
    pub paths: Vec<FlowPath>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlowAnalysisConfig {
    pub max_lines: usize,
    pub max_statement_lines: usize,
    pub max_hops: usize,
    pub max_paths: usize,
}
impl Default for FlowAnalysisConfig {
    fn default() -> Self {
        Self {
            max_lines: 20_000,
            max_statement_lines: 16,
            max_hops: 32,
            max_paths: 500,
        }
    }
}
impl FlowAnalysisConfig {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.max_lines > 0
                && self.max_statement_lines > 0
                && self.max_hops > 0
                && self.max_paths > 0,
            "flow-analysis bounds must be positive"
        );
        ensure!(
            self.max_lines <= 1_000_000
                && self.max_statement_lines <= 1_000
                && self.max_hops <= 10_000
                && self.max_paths <= 100_000,
            "flow-analysis bounds are unreasonably large"
        );
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct Statement {
    shape: String,
    original: String,
    start_line: usize,
    end_line: usize,
    truncated: bool,
}

struct AnalysisContext<'a> {
    path: &'a Path,
    language: &'a str,
    source_hash: &'a str,
    config: &'a FlowAnalysisConfig,
    redactor: &'a Redactor,
}

#[derive(Debug, Clone)]
struct TaintValue {
    source: FlowSource,
    hops: Vec<FlowHop>,
    protected: BTreeSet<SinkKind>,
    ambiguous: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LexMode {
    Normal,
    Quote(char),
    Triple(char),
    BlockComment,
}

#[derive(Debug, Clone)]
struct Match<T> {
    value: T,
    start: usize,
    expression: String,
}

/// Analyze a source file from an inventory, rechecking its immutable content hash.
pub fn analyze_file_flows(file: &SourceFile, config: &FlowAnalysisConfig) -> Result<FlowAnalysis> {
    analyze_file_flows_with_overrides(file, config, &ExpertOverrides::default())
}

pub fn analyze_file_flows_with_overrides(
    file: &SourceFile,
    config: &FlowAnalysisConfig,
    overrides: &ExpertOverrides,
) -> Result<FlowAnalysis> {
    let bytes = fs::read(&file.path)?;
    ensure!(
        hash(&bytes) == file.hash,
        "source changed during flow analysis"
    );
    let text = std::str::from_utf8(&bytes)?;
    analyze_source_flows_with_overrides(
        &file.path,
        &file.language,
        &file.hash,
        text,
        config,
        overrides,
    )
}

/// Analyze all supported source files in deterministic inventory order.
pub fn analyze_inventory_flows(
    inventory: &Inventory,
    config: &FlowAnalysisConfig,
) -> Result<Vec<FlowAnalysis>> {
    analyze_inventory_flows_with_overrides(inventory, config, &ExpertOverrides::default())
}

pub fn analyze_inventory_flows_with_overrides(
    inventory: &Inventory,
    config: &FlowAnalysisConfig,
    overrides: &ExpertOverrides,
) -> Result<Vec<FlowAnalysis>> {
    config.validate()?;
    overrides.validate()?;
    let mut files: Vec<_> = inventory
        .files
        .iter()
        .filter(|file| file.kind == "source" && supported_language(&file.language))
        .collect();
    files.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    files
        .into_iter()
        .map(|file| analyze_file_flows_with_overrides(file, config, overrides))
        .collect()
}

/// Analyze caller-supplied text. `source_hash` must match `text`, preventing a
/// result from being attributed to different content.
pub fn analyze_source_flows(
    path: &Path,
    language: &str,
    source_hash: &str,
    text: &str,
    config: &FlowAnalysisConfig,
) -> Result<FlowAnalysis> {
    analyze_source_flows_with_overrides(
        path,
        language,
        source_hash,
        text,
        config,
        &ExpertOverrides::default(),
    )
}

pub fn analyze_source_flows_with_overrides(
    path: &Path,
    language: &str,
    source_hash: &str,
    text: &str,
    config: &FlowAnalysisConfig,
    overrides: &ExpertOverrides,
) -> Result<FlowAnalysis> {
    overrides.validate()?;
    let redactor = Redactor::with_override(overrides);
    analyze_source_flows_with_redactor(path, language, source_hash, text, config, &redactor)
}

fn analyze_source_flows_with_redactor(
    path: &Path,
    language: &str,
    source_hash: &str,
    text: &str,
    config: &FlowAnalysisConfig,
    redactor: &Redactor,
) -> Result<FlowAnalysis> {
    config.validate()?;
    ensure!(
        source_hash == hash(text.as_bytes()),
        "flow source hash mismatch"
    );
    let normalized_language = normalize_language(language);
    let total_lines = text.lines().count();
    let analyzed_lines = total_lines.min(config.max_lines);
    let mut limitations = vec![
        "Conservative lexical, intra-file and scope-insensitive analysis only; no whole-program, type-system, framework, runtime, or exploitability claim.".into(),
    ];
    if !supported_language(&normalized_language) {
        limitations.push(format!(
            "Language {normalized_language} is not supported by the lexical flow foundation."
        ));
        return Ok(FlowAnalysis {
            path: path.to_owned(),
            language: normalized_language,
            source_hash: source_hash.into(),
            analyzed_lines: 0,
            paths: vec![],
            limitations,
        });
    }
    if total_lines > analyzed_lines {
        limitations.push(format!(
            "Analysis stopped at line {analyzed_lines} of {total_lines} due to max_lines."
        ));
    }
    let bounded_text = text
        .lines()
        .take(analyzed_lines)
        .collect::<Vec<_>>()
        .join("\n");
    let shapes = executable_shapes(&bounded_text, &normalized_language);
    let (statements, truncated_statements) =
        logical_statements(&bounded_text, &shapes, config.max_statement_lines);
    if truncated_statements > 0 {
        limitations.push(format!(
            "{truncated_statements} logical statement(s) exceeded max_statement_lines and any resulting path is needs-review."
        ));
    }
    let mut state = BTreeMap::<String, TaintValue>::new();
    let mut paths = vec![];
    let context = AnalysisContext {
        path,
        language: &normalized_language,
        source_hash,
        config,
        redactor,
    };
    for statement in statements {
        if is_function_boundary(&statement.shape, &normalized_language) {
            // Do not carry local variables into a different function. This
            // intentionally sacrifices interprocedural recall to avoid inventing
            // a cross-function dataflow edge.
            state.clear();
        }
        process_statement(&context, &statement, &mut state, &mut paths)?;
        if paths.len() >= config.max_paths {
            limitations.push(format!(
                "Path output stopped at configured max_paths={}.",
                config.max_paths
            ));
            break;
        }
    }
    paths.sort_by(|a, b| {
        a.sink
            .point
            .line
            .cmp(&b.sink.point.line)
            .then(a.source.point.line.cmp(&b.source.point.line))
            .then(a.sink.kind.cmp(&b.sink.kind))
            .then(a.id.cmp(&b.id))
    });
    let mut seen = BTreeSet::new();
    paths.retain(|path| seen.insert(path.id.clone()));
    paths.truncate(config.max_paths);
    Ok(FlowAnalysis {
        path: path.to_owned(),
        language: normalized_language,
        source_hash: source_hash.into(),
        analyzed_lines,
        paths,
        limitations,
    })
}

fn supported_language(language: &str) -> bool {
    matches!(
        normalize_language(language).as_str(),
        "python"
            | "javascript"
            | "typescript"
            | "go"
            | "jvm"
            | "csharp"
            | "php"
            | "ruby"
            | "rust"
            | "c"
    )
}
fn normalize_language(language: &str) -> String {
    match language.to_ascii_lowercase().as_str() {
        "java" | "kotlin" => "jvm".into(),
        "js" | "jsx" | "mjs" | "cjs" => "javascript".into(),
        "ts" | "tsx" => "typescript".into(),
        "cs" | "c#" => "csharp".into(),
        "rb" => "ruby".into(),
        other => other.into(),
    }
}

fn executable_shapes(text: &str, language: &str) -> Vec<String> {
    let hash_comment = matches!(language, "python" | "ruby" | "php");
    let mut mode = LexMode::Normal;
    let mut escaped = false;
    let mut lines = vec![String::new()];
    let chars: Vec<_> = text.chars().collect();
    let mut index = 0;
    while index < chars.len() {
        let character = chars[index];
        if character == '\n' {
            lines.push(String::new());
            if matches!(mode, LexMode::Quote(_)) {
                mode = LexMode::Normal;
            }
            escaped = false;
            index += 1;
            continue;
        }
        let next = chars.get(index + 1).copied();
        match mode {
            LexMode::BlockComment => {
                lines.last_mut().expect("shape line").push(' ');
                if character == '*' && next == Some('/') {
                    lines.last_mut().expect("shape line").push(' ');
                    index += 2;
                    mode = LexMode::Normal;
                } else {
                    index += 1;
                }
            }
            LexMode::Quote(delimiter) => {
                lines.last_mut().expect("shape line").push(' ');
                if escaped {
                    escaped = false;
                } else if character == '\\' && delimiter != '`' {
                    escaped = true;
                } else if character == delimiter {
                    mode = LexMode::Normal;
                }
                index += 1;
            }
            LexMode::Triple(delimiter) => {
                lines.last_mut().expect("shape line").push(' ');
                if character == delimiter
                    && next == Some(delimiter)
                    && chars.get(index + 2) == Some(&delimiter)
                {
                    lines.last_mut().expect("shape line").push_str("  ");
                    index += 3;
                    mode = LexMode::Normal;
                } else {
                    index += 1;
                }
            }
            LexMode::Normal => {
                if character == '/' && next == Some('*') {
                    lines.last_mut().expect("shape line").push_str("  ");
                    index += 2;
                    mode = LexMode::BlockComment;
                } else if character == '/' && next == Some('/') || character == '#' && hash_comment
                {
                    while index < chars.len() && chars[index] != '\n' {
                        lines.last_mut().expect("shape line").push(' ');
                        index += 1;
                    }
                } else if matches!(character, '\'' | '"')
                    && next == Some(character)
                    && chars.get(index + 2) == Some(&character)
                {
                    lines.last_mut().expect("shape line").push_str("   ");
                    index += 3;
                    mode = LexMode::Triple(character);
                } else if matches!(character, '\'' | '"' | '`') {
                    lines.last_mut().expect("shape line").push(' ');
                    index += 1;
                    mode = LexMode::Quote(character);
                } else {
                    lines.last_mut().expect("shape line").push(character);
                    index += 1;
                }
            }
        }
    }
    lines
}

fn logical_statements(
    original: &str,
    shapes: &[String],
    max_statement_lines: usize,
) -> (Vec<Statement>, usize) {
    let originals: Vec<_> = original.lines().collect();
    let mut out = vec![];
    let mut shape = String::new();
    let mut raw = String::new();
    let mut start = 1;
    let mut depth = 0isize;
    let mut truncated = false;
    let mut truncated_count = 0;
    for (index, clean) in shapes.iter().enumerate() {
        let line = index + 1;
        if shape.is_empty() {
            start = line;
        } else {
            shape.push('\n');
            raw.push('\n');
        }
        shape.push_str(clean);
        raw.push_str(originals.get(index).copied().unwrap_or_default());
        for character in clean.chars() {
            match character {
                '(' | '[' => depth += 1,
                ')' | ']' => depth = (depth - 1).max(0),
                _ => {}
            }
        }
        let span = line - start + 1;
        if span >= max_statement_lines && (depth > 0 || continuation(clean)) {
            truncated = true;
            truncated_count += 1;
            depth = 0;
        }
        if depth == 0 && (!continuation(clean) || truncated) {
            if !shape.trim().is_empty() {
                out.push(Statement {
                    shape: std::mem::take(&mut shape),
                    original: std::mem::take(&mut raw),
                    start_line: start,
                    end_line: line,
                    truncated,
                });
            } else {
                shape.clear();
                raw.clear();
            }
            truncated = false;
        }
    }
    if !shape.trim().is_empty() {
        if depth > 0 || continuation(shape.lines().last().unwrap_or_default()) {
            truncated = true;
            truncated_count += 1;
        }
        out.push(Statement {
            shape,
            original: raw,
            start_line: start,
            end_line: shapes.len(),
            truncated,
        });
    }
    (out, truncated_count)
}
fn continuation(line: &str) -> bool {
    let trimmed = line.trim_end();
    ["\\", "=", "+", ".", ",", "&&", "||", "|", "?", ":="]
        .iter()
        .any(|suffix| trimmed.ends_with(suffix))
}

fn process_statement(
    context: &AnalysisContext<'_>,
    statement: &Statement,
    state: &mut BTreeMap<String, TaintValue>,
    paths: &mut Vec<FlowPath>,
) -> Result<()> {
    let path = context.path;
    let language = context.language;
    let source_hash = context.source_hash;
    let config = context.config;
    let redactor = context.redactor;
    let assignment = assignment(&statement.shape);
    if let Some((variable, rhs, rhs_offset)) = assignment.as_ref() {
        let direct_source = detect_sources(language, rhs).into_iter().next();
        let mut inputs = referenced_taints(rhs, state);
        inputs.sort_by_key(|(_, offset)| *offset);
        let sanitizer =
            detect_sanitizer(rhs, statement, path, rhs_offset.saturating_add(0), redactor);
        let new_value = if let Some(source_match) = direct_source {
            let offset = rhs_offset + source_match.start;
            let source = FlowSource {
                kind: source_match.value,
                point: point(path, statement, offset, redactor),
                expression: source_match.expression,
                variable: Some(variable.clone()),
            };
            let mut value = TaintValue {
                source,
                hops: vec![],
                protected: BTreeSet::new(),
                ambiguous: statement.truncated,
            };
            if statement.truncated {
                value.hops.push(FlowHop::Unknown(UnknownHop {
                    point: point(path, statement, 0, redactor),
                    expression: compact(&statement.original),
                    reason: "logical statement exceeded configured bound".into(),
                }));
            }
            if let Some(sanitizer) = sanitizer.clone() {
                value.protected.extend(&sanitizer.protects);
                value.hops.push(FlowHop::Sanitizer(sanitizer));
            } else if let Some(function) = enclosing_call_at(rhs, source_match.start) {
                if !known_passthrough(&function) {
                    value.ambiguous = true;
                    value.hops.push(FlowHop::Unknown(UnknownHop {
                        point: point(path, statement, rhs_offset + source_match.start, redactor),
                        expression: compact(rhs),
                        reason: format!("behavior of call {function} is unknown"),
                    }));
                }
            }
            Some(value)
        } else if let Some((from, _)) = inputs.first() {
            let mut value = state.get(from).cloned().context("taint disappeared")?;
            let assignment_point = point(path, statement, 0, redactor);
            value.hops.push(FlowHop::Assignment {
                from: from.clone(),
                to: variable.clone(),
                point: assignment_point.clone(),
            });
            if inputs.len() > 1 {
                value.ambiguous = true;
                value.hops.push(FlowHop::Unknown(UnknownHop {
                    point: assignment_point.clone(),
                    expression: compact(rhs),
                    reason: "multiple tainted values merged; only the first deterministic provenance is retained".into(),
                }));
            }
            if let Some(sanitizer) = sanitizer.clone() {
                value.protected.extend(&sanitizer.protects);
                value.hops.push(FlowHop::Sanitizer(sanitizer));
            } else if let Some(function) = enclosing_call(rhs, from) {
                if known_passthrough(&function) {
                    value.hops.push(FlowHop::CallPropagation {
                        function,
                        from: from.clone(),
                        to: variable.clone(),
                        point: assignment_point,
                    });
                } else {
                    value.ambiguous = true;
                    value.hops.push(FlowHop::Unknown(UnknownHop {
                        point: assignment_point,
                        expression: compact(rhs),
                        reason: format!("behavior of call {function} is unknown"),
                    }));
                }
            }
            if statement.truncated {
                value.ambiguous = true;
            }
            if value.hops.len() >= config.max_hops {
                value.hops.truncate(config.max_hops.saturating_sub(1));
                value.ambiguous = true;
                value.hops.push(FlowHop::Unknown(UnknownHop {
                    point: point(path, statement, 0, redactor),
                    expression: compact(rhs),
                    reason: "flow exceeded configured max_hops".into(),
                }));
            }
            Some(value)
        } else {
            None
        };
        if let Some(value) = new_value {
            state.insert(variable.clone(), value);
        } else {
            // A clean reassignment shadows and kills earlier provenance.
            state.remove(variable);
        }
    }

    for sink_match in detect_sinks(language, &statement.shape) {
        let sink = FlowSink {
            kind: sink_match.value,
            point: point(path, statement, sink_match.start, redactor),
            expression: sink_match.expression,
        };
        let sink_slice = &statement.shape[sink_match.start..];
        let direct_sources = detect_sources(language, sink_slice);
        for source_match in direct_sources {
            if direct_source_is_sanitized(sink.kind, sink_slice, source_match.start, redactor) {
                continue;
            }
            if sink.kind == SinkKind::Sql && parameterized_sql(sink_slice, source_match.start) {
                continue;
            }
            let source = FlowSource {
                kind: source_match.value,
                point: point(
                    path,
                    statement,
                    sink_match.start + source_match.start,
                    redactor,
                ),
                expression: source_match.expression,
                variable: None,
            };
            let mut hops = vec![];
            let status = if statement.truncated {
                hops.push(FlowHop::Unknown(UnknownHop {
                    point: point(path, statement, 0, redactor),
                    expression: compact(&statement.original),
                    reason: "logical statement exceeded configured bound".into(),
                }));
                FlowStatus::NeedsReview
            } else {
                FlowStatus::Traceable
            };
            paths.push(make_path(
                language,
                source_hash,
                source,
                sink.clone(),
                hops,
                status,
            )?);
        }
        for (variable, value) in state.iter() {
            let Some(variable_offset) = identifier_offset(sink_slice, variable) else {
                continue;
            };
            if value.protected.contains(&sink.kind) {
                continue;
            }
            if sink.kind == SinkKind::Sql && parameterized_sql(sink_slice, variable_offset) {
                continue;
            }
            let mut source = value.source.clone();
            if source.variable.is_none() {
                source.variable = Some(variable.clone());
            }
            let status = if value.ambiguous
                || value
                    .hops
                    .iter()
                    .any(|hop| matches!(hop, FlowHop::Unknown(_)))
                || statement.truncated
            {
                FlowStatus::NeedsReview
            } else {
                FlowStatus::Traceable
            };
            paths.push(make_path(
                language,
                source_hash,
                source,
                sink.clone(),
                value.hops.clone(),
                status,
            )?);
        }
    }
    Ok(())
}

fn make_path(
    language: &str,
    source_hash: &str,
    source: FlowSource,
    sink: FlowSink,
    hops: Vec<FlowHop>,
    status: FlowStatus,
) -> Result<FlowPath> {
    let limitation = match status {
        FlowStatus::Traceable => {
            "Lexically traceable within one file; runtime reachability and exploitability remain unverified."
        }
        FlowStatus::NeedsReview => {
            "Source and sink are present, but an unknown or bounded lexical hop requires manual review."
        }
    };
    let identity = serde_json::to_vec(&(language, source_hash, &source, &sink, &hops, status))?;
    Ok(FlowPath {
        id: format!("flow-{}", hash(&identity)),
        language: language.into(),
        source_hash: source_hash.into(),
        source,
        sink,
        hops,
        status,
        limitation: limitation.into(),
    })
}

fn point(path: &Path, statement: &Statement, offset: usize, redactor: &Redactor) -> SourcePoint {
    let prefix = &statement.shape[..offset.min(statement.shape.len())];
    let line_offset = prefix.bytes().filter(|byte| *byte == b'\n').count();
    let line = statement.start_line + line_offset;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix.chars().count() + 1, |(_, tail)| {
            tail.chars().count() + 1
        });
    let excerpt = statement
        .original
        .lines()
        .nth(line_offset)
        .unwrap_or_default();
    SourcePoint {
        path: path.to_owned(),
        line,
        end_line: statement.end_line,
        column,
        excerpt: redactor.text(excerpt.trim()),
    }
}

fn assignment(shape: &str) -> Option<(String, String, usize)> {
    let regex = Regex::new(
        r"(?s)^\s*(?:(?:let|const|var|final|static|public|private|protected|readonly|String|string|int|long|object|auto)\s+)?(?:[A-Za-z_][A-Za-z0-9_<>,.?\[\]]*\s+)?(?P<lhs>\$?[A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*[A-Za-z_][A-Za-z0-9_<>,.?\[\]]*)?\s*(?::=|=)\s*(?P<rhs>.+)$",
    )
    .expect("assignment regex");
    let captures = regex.captures(shape)?;
    let lhs = captures.name("lhs")?.as_str().to_owned();
    let rhs_match = captures.name("rhs")?;
    // Exclude comparisons and arrow syntax that the intentionally small parser
    // cannot treat as assignments.
    let before_rhs = &shape[..rhs_match.start()];
    if before_rhs.trim_end().ends_with("==")
        || before_rhs.trim_end().ends_with("!=")
        || before_rhs.trim_end().ends_with(">=")
        || before_rhs.trim_end().ends_with("<=")
        || before_rhs.trim_end().ends_with("=>")
    {
        return None;
    }
    Some((lhs, rhs_match.as_str().to_owned(), rhs_match.start()))
}

fn is_function_boundary(shape: &str, language: &str) -> bool {
    let trimmed = shape.trim_start();
    if trimmed.starts_with("new ") {
        return false;
    }
    match language {
        "python" | "ruby" => Regex::new(r"^(?:async\s+)?def\s+[A-Za-z_]")
            .expect("function boundary regex")
            .is_match(trimmed),
        "javascript" | "typescript" | "php" => {
            Regex::new(r"^(?:export\s+)?(?:async\s+)?function\s+[A-Za-z_$]")
                .expect("function boundary regex")
                .is_match(trimmed)
        }
        "go" => Regex::new(r"^func\s+(?:\([^)]*\)\s*)?[A-Za-z_]")
            .expect("function boundary regex")
            .is_match(trimmed),
        "jvm" | "csharp" => Regex::new(
            r"^(?:(?:public|private|protected|internal|static|final|async|virtual|override)\s+)*(?:[A-Za-z_][A-Za-z0-9_<>,.?\[\]]*\s+)+[A-Za-z_][A-Za-z0-9_]*\s*\(",
        )
        .expect("function boundary regex")
        .is_match(trimmed),
        "rust" => Regex::new(r"^(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+[A-Za-z_]")
            .expect("function boundary regex")
            .is_match(trimmed),
        "c" => Regex::new(r"^(?:[A-Za-z_][A-Za-z0-9_*]*\s+)+[A-Za-z_][A-Za-z0-9_]*\s*\(")
            .expect("function boundary regex")
            .is_match(trimmed),
        _ => false,
    }
}

fn detect_sources(language: &str, shape: &str) -> Vec<Match<SourceKind>> {
    let patterns: &[(&str, SourceKind)] = match language {
        "python" => &[
            (
                r"\brequest\.(?:args|form|values|query_params)\b",
                SourceKind::HttpParameter,
            ),
            (
                r"\brequest\.(?:json|data|body)\b|\brequest\.get_json\s*\(",
                SourceKind::HttpBody,
            ),
            (r"\brequest\.headers\b", SourceKind::HttpHeader),
            (r"\brequest\.cookies\b", SourceKind::HttpCookie),
            (r"\brequest\.(?:path|view_args)\b", SourceKind::HttpPath),
        ],
        "javascript" | "typescript" => &[
            (
                r"\b(?:req|request)\.(?:query|params)\b|\bevent\.queryStringParameters\b",
                SourceKind::HttpParameter,
            ),
            (
                r"\b(?:req|request)\.body\b|\bctx\.request\.body\b",
                SourceKind::HttpBody,
            ),
            (r"\b(?:req|request)\.headers\b", SourceKind::HttpHeader),
            (r"\b(?:req|request)\.cookies\b", SourceKind::HttpCookie),
            (r"\b(?:req|request)\.(?:path|url)\b", SourceKind::HttpPath),
        ],
        "go" => &[
            (
                r"\b(?:r|req)\.(?:FormValue|PostFormValue)\s*\(|\b(?:r|req)\.URL\.Query\s*\(",
                SourceKind::HttpParameter,
            ),
            (r"\b(?:r|req)\.Body\b", SourceKind::HttpBody),
            (
                r"\b(?:r|req)\.Header\.(?:Get|Values)\s*\(",
                SourceKind::HttpHeader,
            ),
            (r"\b(?:r|req)\.Cookie\s*\(", SourceKind::HttpCookie),
            (r"\b(?:r|req)\.URL\.Path\b", SourceKind::HttpPath),
        ],
        "jvm" => &[
            (
                r"\b(?:request|req)\.getParameter(?:Values|Map)?\s*\(",
                SourceKind::HttpParameter,
            ),
            (
                r"\b(?:request|req)\.(?:getInputStream|getReader)\s*\(",
                SourceKind::HttpBody,
            ),
            (r"\b(?:request|req)\.getHeader\s*\(", SourceKind::HttpHeader),
            (
                r"\b(?:request|req)\.getCookies\s*\(",
                SourceKind::HttpCookie,
            ),
            (
                r"\b(?:request|req)\.(?:getPathInfo|getRequestURI)\s*\(",
                SourceKind::HttpPath,
            ),
        ],
        "csharp" => &[
            (
                r"\bRequest\.(?:Query|Form|RouteValues)\b",
                SourceKind::HttpParameter,
            ),
            (r"\bRequest\.Body\b", SourceKind::HttpBody),
            (r"\bRequest\.Headers\b", SourceKind::HttpHeader),
            (r"\bRequest\.Cookies\b", SourceKind::HttpCookie),
            (r"\bRequest\.Path\b", SourceKind::HttpPath),
        ],
        "php" => &[
            (r"\$_(?:GET|POST|REQUEST)\b", SourceKind::HttpParameter),
            (r"\bgetallheaders\s*\(", SourceKind::HttpHeader),
            (r"\$_COOKIE\b", SourceKind::HttpCookie),
            (r"\$_SERVER\b", SourceKind::HttpPath),
        ],
        "ruby" => &[
            (
                r"\bparams\s*\[|\brequest\.params\b",
                SourceKind::HttpParameter,
            ),
            (r"\brequest\.body\b", SourceKind::HttpBody),
            (r"\brequest\.(?:headers|env)\b", SourceKind::HttpHeader),
            (r"\bcookies\s*\[", SourceKind::HttpCookie),
            (r"\brequest\.(?:path|url)\b", SourceKind::HttpPath),
        ],
        "rust" => &[
            (r"\b(?:Query|Form|Path)\s*\(", SourceKind::HttpParameter),
            (r"\bJson\s*\(", SourceKind::HttpBody),
            (r"\bheaders\s*\(\s*\)", SourceKind::HttpHeader),
        ],
        "c" => &[
            (
                r"\b(?:query_param|request_param|cgi_get)\s*\(",
                SourceKind::HttpParameter,
            ),
            (r"\brequest_body\b", SourceKind::HttpBody),
            (r"\brequest_header\s*\(", SourceKind::HttpHeader),
        ],
        _ => &[],
    };
    pattern_matches(shape, patterns)
}

fn detect_sinks(language: &str, shape: &str) -> Vec<Match<SinkKind>> {
    let mut patterns: Vec<(&str, SinkKind)> = vec![(
        r"\b(?:eval|class_eval|module_eval)\s*\(|\bnew\s+Function\s*\(",
        SinkKind::Eval,
    )];
    match language {
        "python" => patterns.extend([
            (r"\.(?:execute|executemany|executescript)\s*\(", SinkKind::Sql),
            (r"\b(?:os\.(?:system|popen)|subprocess\.(?:run|Popen|call|check_output))\s*\(", SinkKind::Command),
            (r"\b(?:open|send_file|send_from_directory)\s*\(", SinkKind::File),
            (r"\b(?:requests\.(?:get|post|put|patch|delete|request)|urllib\.request\.urlopen|httpx\.(?:get|post|request))\s*\(", SinkKind::Request),
        ]),
        "javascript" | "typescript" => patterns.extend([
            (r"\.(?:query|execute)\s*\(", SinkKind::Sql),
            (r"\b(?:exec|execSync|spawn|spawnSync)\s*\(", SinkKind::Command),
            (r"\b(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream)\s*\(", SinkKind::File),
            (r"\bfetch\s*\(|\baxios(?:\.(?:get|post|put|patch|delete|request))?\s*\(", SinkKind::Request),
        ]),
        "go" => patterns.extend([
            (r"\.(?:Query|QueryContext|Exec|ExecContext)\s*\(", SinkKind::Sql),
            (r"\bexec\.Command(?:Context)?\s*\(", SinkKind::Command),
            (r"\b(?:os\.(?:Open|OpenFile|ReadFile|WriteFile|Create)|ioutil\.(?:ReadFile|WriteFile))\s*\(", SinkKind::File),
            (r"\b(?:http\.(?:Get|Post|NewRequest|NewRequestWithContext)|client\.Do)\s*\(", SinkKind::Request),
        ]),
        "jvm" => patterns.extend([
            (r"\.(?:executeQuery|executeUpdate|execute)\s*\(", SinkKind::Sql),
            (r"\b(?:Runtime\.getRuntime\s*\(\s*\)\.exec|new\s+ProcessBuilder)\s*\(", SinkKind::Command),
            (r"\bnew\s+File\s*\(|\bFiles\.(?:read|write|newInputStream|newOutputStream)\s*\(", SinkKind::File),
            (r"\b(?:new\s+URL|HttpRequest\.newBuilder)\s*\(", SinkKind::Request),
        ]),
        "csharp" => patterns.extend([
            (r"\bnew\s+(?:SqlCommand|NpgsqlCommand)\s*\(", SinkKind::Sql),
            (r"\bProcess\.(?:Start)\s*\(", SinkKind::Command),
            (r"\bFile\.(?:ReadAllText|ReadAllBytes|WriteAllText|WriteAllBytes|Open|Delete)\s*\(", SinkKind::File),
            (r"\bHttpClient\.(?:GetAsync|PostAsync|SendAsync)\s*\(|\bnew\s+Uri\s*\(", SinkKind::Request),
        ]),
        "php" => patterns.extend([
            (r"\b(?:mysqli_query|pg_query|mysql_query)\s*\(|->(?:query|exec)\s*\(", SinkKind::Sql),
            (r"\b(?:shell_exec|system|passthru|popen|proc_open)\s*\(", SinkKind::Command),
            (r"\b(?:fopen|readfile|file_get_contents|file_put_contents|unlink)\s*\(", SinkKind::File),
            (r"\bcurl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,|\bcurl_init\s*\(", SinkKind::Request),
        ]),
        "ruby" => patterns.extend([
            (r"\.(?:execute|exec_query)\s*\(", SinkKind::Sql),
            (r"\b(?:system|spawn|exec)\s*\(|\bOpen3\.(?:capture2|capture3|popen3)\s*\(", SinkKind::Command),
            (r"\bFile\.(?:read|write|open|delete)\s*\(", SinkKind::File),
            (r"\b(?:URI\.open|Net::HTTP\.(?:get|post)|RestClient\.(?:get|post))\s*\(", SinkKind::Request),
        ]),
        "rust" => patterns.extend([
            (r"\.(?:query|execute)\s*\(", SinkKind::Sql),
            (r"\bCommand::new\s*\(", SinkKind::Command),
            (r"\b(?:File::open|fs::read|fs::write)\s*\(", SinkKind::File),
            (r"\b(?:reqwest::get|Client::get|Client::post)\s*\(", SinkKind::Request),
        ]),
        "c" => patterns.extend([
            (r"\b(?:sqlite3_exec|mysql_query)\s*\(", SinkKind::Sql),
            (r"\b(?:system|popen|execl|execv)\s*\(", SinkKind::Command),
            (r"\b(?:fopen|open|unlink)\s*\(", SinkKind::File),
            (r"\bcurl_easy_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,", SinkKind::Request),
        ]),
        _ => {}
    }
    let mut matches = pattern_matches(shape, &patterns);
    matches.sort_by_key(|matched| (matched.start, matched.value));
    matches
}

fn pattern_matches<T: Copy>(shape: &str, patterns: &[(&str, T)]) -> Vec<Match<T>> {
    let mut matches = vec![];
    for (pattern, value) in patterns {
        let regex = Regex::new(pattern).expect("static flow pattern");
        for found in regex.find_iter(shape) {
            matches.push(Match {
                value: *value,
                start: found.start(),
                expression: compact(found.as_str()),
            });
        }
    }
    matches.sort_by_key(|matched| matched.start);
    matches
}

fn detect_sanitizer(
    rhs: &str,
    statement: &Statement,
    path: &Path,
    rhs_offset: usize,
    redactor: &Redactor,
) -> Option<FlowSanitizer> {
    let patterns: &[(&str, SanitizerKind, &[SinkKind])] = &[
        (
            r"\b(?:int|parseInt|Integer\.parseInt|Long\.parseLong|Convert\.ToInt32|strconv\.(?:Atoi|ParseInt)|Integer|to_i|filter_var)\s*\(",
            SanitizerKind::NumericCoercion,
            &[
                SinkKind::Sql,
                SinkKind::Command,
                SinkKind::File,
                SinkKind::Request,
                SinkKind::Eval,
            ],
        ),
        (
            r"\b(?:shlex\.quote|Shellwords\.escape|escapeshellarg)\s*\(",
            SanitizerKind::ShellEscaping,
            &[SinkKind::Command],
        ),
        (
            r"\b(?:os\.path\.basename|filepath\.Base|Path\.GetFileName|basename|File\.basename)\s*\(",
            SanitizerKind::PathBasename,
            &[SinkKind::File],
        ),
    ];
    for (pattern, kind, protects) in patterns {
        if let Some(found) = Regex::new(pattern).expect("sanitizer regex").find(rhs) {
            return Some(FlowSanitizer {
                kind: *kind,
                point: point(path, statement, rhs_offset + found.start(), redactor),
                expression: compact(found.as_str()),
                protects: protects.iter().copied().collect(),
            });
        }
    }
    None
}

fn direct_source_is_sanitized(
    kind: SinkKind,
    sink_slice: &str,
    source_offset: usize,
    redactor: &Redactor,
) -> bool {
    detect_sanitizer(
        &sink_slice[..source_offset.min(sink_slice.len())],
        &Statement {
            shape: sink_slice.into(),
            original: sink_slice.into(),
            start_line: 1,
            end_line: 1,
            truncated: false,
        },
        Path::new("<direct>"),
        0,
        redactor,
    )
    .is_some_and(|sanitizer| sanitizer.protects.contains(&kind))
}

fn referenced_taints(rhs: &str, state: &BTreeMap<String, TaintValue>) -> Vec<(String, usize)> {
    state
        .keys()
        .filter_map(|variable| {
            identifier_offset(rhs, variable).map(|offset| (variable.clone(), offset))
        })
        .collect()
}

fn identifier_offset(text: &str, identifier: &str) -> Option<usize> {
    let regex = Regex::new(&format!(
        r"(?:^|[^A-Za-z0-9_$])({})(?:$|[^A-Za-z0-9_$])",
        regex::escape(identifier)
    ))
    .expect("escaped identifier regex");
    regex
        .captures(text)
        .and_then(|captures| captures.get(1))
        .map(|matched| matched.start())
}

fn enclosing_call(rhs: &str, variable: &str) -> Option<String> {
    let variable_offset = identifier_offset(rhs, variable)?;
    enclosing_call_at(rhs, variable_offset)
}
fn enclosing_call_at(rhs: &str, offset: usize) -> Option<String> {
    let prefix = &rhs[..offset.min(rhs.len())];
    let regex =
        Regex::new(r"([A-Za-z_$][A-Za-z0-9_$.:>\-]*)\s*\([^()]*$").expect("call propagation regex");
    regex
        .captures(prefix)
        .and_then(|captures| captures.get(1))
        .map(|matched| matched.as_str().to_owned())
}
fn known_passthrough(function: &str) -> bool {
    let tail = function
        .rsplit(['.', ':', '>'])
        .find(|part| !part.is_empty())
        .unwrap_or(function);
    matches!(
        tail,
        "str"
            | "String"
            | "toString"
            | "ToString"
            | "Sprintf"
            | "sprintf"
            | "format"
            | "trim"
            | "strip"
            | "lower"
            | "upper"
            | "join"
            | "Join"
    )
}

fn parameterized_sql(sink_slice: &str, variable_offset: usize) -> bool {
    let trimmed = sink_slice.trim_start();
    if !(trimmed.starts_with(".execute(")
        || trimmed.starts_with(".executemany(")
        || trimmed.starts_with(".query("))
    {
        return false;
    }
    let Some(open) = sink_slice.find('(') else {
        return false;
    };
    let mut depth = 0isize;
    for (offset, character) in sink_slice
        .char_indices()
        .skip_while(|(offset, _)| *offset <= open)
    {
        match character {
            '(' | '[' => depth += 1,
            ')' | ']' => depth -= 1,
            ',' if depth == 0 => return variable_offset > offset,
            _ => {}
        }
    }
    false
}

fn compact(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analyze(language: &str, text: &str) -> Result<FlowAnalysis> {
        analyze_source_flows(
            Path::new("fixture.source"),
            language,
            &hash(text.as_bytes()),
            text,
            &FlowAnalysisConfig::default(),
        )
    }

    #[test]
    fn positive_assignment_and_unknown_call_paths_are_typed() -> Result<()> {
        let result = analyze(
            "python",
            "user = request.args.get('id')\nquery = user\ncursor.execute('SELECT ' + query)\ncmd = custom(request.form['cmd'])\nsubprocess.run(cmd, shell=True)\n",
        )?;
        assert_eq!(result.paths.len(), 2);
        assert_eq!(result.paths[0].sink.kind, SinkKind::Sql);
        assert_eq!(result.paths[0].status, FlowStatus::Traceable);
        assert_eq!(result.paths[1].sink.kind, SinkKind::Command);
        assert_eq!(result.paths[1].status, FlowStatus::NeedsReview);
        assert!(result.paths[1]
            .hops
            .iter()
            .any(|hop| matches!(hop, FlowHop::Unknown(_))));
        Ok(())
    }

    #[test]
    fn sanitizer_breaks_matching_sink_flow() -> Result<()> {
        let result = analyze(
            "python",
            "raw = request.args.get('id')\nsafe = int(raw)\ncursor.execute('SELECT ' + safe)\n",
        )?;
        assert!(result.paths.is_empty());
        Ok(())
    }

    #[test]
    fn clean_reassignment_shadows_taint() -> Result<()> {
        let result = analyze(
            "javascript",
            "let target = req.query.url;\ntarget = defaultUrl;\nfetch(target);\n",
        )?;
        assert!(result.paths.is_empty());
        Ok(())
    }

    #[test]
    fn comments_and_strings_are_ignored() -> Result<()> {
        let result = analyze(
            "javascript",
            "// const x = req.query.x; fetch(x);\nconst sample = \"fetch(req.query.x)\";\n/* const y = req.body; */ exec(y);\n",
        )?;
        assert!(result.paths.is_empty());
        Ok(())
    }

    #[test]
    fn excerpt_redaction_honors_only_the_explicit_secret_redaction_override() -> Result<()> {
        let text = "password = request.args.get('password')\nos.system(password)\n";
        let default = analyze("python", text)?;
        assert!(default.paths[0].source.point.excerpt.contains("[REDACTED]"));

        let overrides = ExpertOverrides {
            controls: vec![domain::Control::SecretRedaction],
            unsafe_all: false,
            reason: "authorized fixture verification".into(),
            actor: "source-flow-test".into(),
            acknowledged: true,
            timestamp_ms: 1,
        };
        let overridden = analyze_source_flows_with_overrides(
            Path::new("fixture.source"),
            "python",
            &hash(text.as_bytes()),
            text,
            &FlowAnalysisConfig::default(),
            &overrides,
        )?;
        assert!(overridden.paths[0]
            .source
            .point
            .excerpt
            .contains("password ="));
        assert!(!overridden.paths[0]
            .source
            .point
            .excerpt
            .contains("[REDACTED]"));
        Ok(())
    }

    #[test]
    fn multiline_trace_and_statement_bound_are_explicit() -> Result<()> {
        let text =
            "value = request.args.get(\n  'id'\n)\ncursor.execute(\n  'SELECT ' + value\n)\n";
        let traceable = analyze("python", text)?;
        assert_eq!(traceable.paths.len(), 1);
        assert_eq!(traceable.paths[0].status, FlowStatus::Traceable);
        let bounded = analyze_source_flows(
            Path::new("bounded.py"),
            "python",
            &hash(text.as_bytes()),
            text,
            &FlowAnalysisConfig {
                max_statement_lines: 2,
                ..FlowAnalysisConfig::default()
            },
        )?;
        assert!(bounded
            .limitations
            .iter()
            .any(|limitation| limitation.contains("exceeded")));
        assert!(!bounded.paths.is_empty());
        assert!(bounded
            .paths
            .iter()
            .all(|path| path.status == FlowStatus::NeedsReview));
        Ok(())
    }

    #[test]
    fn parameterized_sql_and_cross_function_state_do_not_create_paths() -> Result<()> {
        let parameterized = analyze(
            "python",
            "cursor.execute('SELECT * FROM t WHERE id = ?', [request.args.get('id')])\n",
        )?;
        assert!(parameterized.paths.is_empty());
        let separate_functions = analyze(
            "python",
            "def first():\n  x = request.args.get('id')\ndef second():\n  cursor.execute('SELECT ' + x)\n",
        )?;
        assert!(separate_functions.paths.is_empty());
        Ok(())
    }

    #[test]
    fn language_fixtures_cover_supported_http_sources_and_sink_families() -> Result<()> {
        let fixtures = [
            (
                "javascript",
                "x = req.query.url; fetch(x);",
                SinkKind::Request,
            ),
            (
                "typescript",
                "const x = req.body.code; eval(x);",
                SinkKind::Eval,
            ),
            (
                "go",
                "x := r.FormValue(\"cmd\")\nexec.Command(\"sh\", x)",
                SinkKind::Command,
            ),
            (
                "jvm",
                "String x = request.getParameter(\"path\");\nnew File(x);",
                SinkKind::File,
            ),
            (
                "csharp",
                "string x = Request.Query[\"q\"];\nnew SqlCommand(x);",
                SinkKind::Sql,
            ),
            (
                "php",
                "$x = $_GET['q'];\nmysqli_query($db, $x);",
                SinkKind::Sql,
            ),
            ("ruby", "x = params[:name]\nFile.read(x)", SinkKind::File),
        ];
        for (language, text, sink) in fixtures {
            let result = analyze(language, text)?;
            assert!(
                result.paths.iter().any(|path| path.sink.kind == sink),
                "missing {language:?} {sink:?} path: {result:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn output_is_deterministic() -> Result<()> {
        let text = "a = request.args.get('a')\nb = a\nopen(b)\ncursor.execute('x' + b)\n";
        let first = analyze("python", text)?;
        let second = analyze("python", text)?;
        assert_eq!(first, second);
        let ids: Vec<_> = first.paths.iter().map(|path| &path.id).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        // IDs themselves need not be source-order sorted, but the full repeated
        // analysis above must be byte-for-byte deterministic.
        assert_eq!(ids.len(), sorted.len());
        Ok(())
    }
}
