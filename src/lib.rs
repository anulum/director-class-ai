// SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
// Director-Class AI — commercial product (licence pending); not the Apache base.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// Director-Class AI — Rust command de-obfuscation core

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::Read;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use bzip2::read::BzDecoder;
use flate2::read::{GzDecoder, ZlibDecoder};
use once_cell::sync::Lazy;
use pyo3::prelude::*;
use regex::{Captures, Regex};
use serde_json::Value;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use xz2::read::XzDecoder;

static WS: Lazy<Regex> = Lazy::new(|| Regex::new(r"\s+").expect("valid regex"));
static QUOTE_BREAK: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?P<a>\w)(?:''|"")(?P<b>\w)"#).expect("valid regex"));
static BACKSLASH_BREAK: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?P<a>\w)\\(?P<b>\w)").expect("valid regex"));
static SPLIT_FLAGS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(\s-[a-zA-Z]+)\s+-([a-zA-Z]+)").expect("valid regex"));
static B64_TOKEN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[A-Za-z0-9+/]{8,}={0,2}").expect("valid regex"));
static B64_CONTEXT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\bbase64\b|\b(?:ba)?sh\b\s*$|\|\s*(?:ba)?sh\b").expect("valid regex")
});
static HEX_RUN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:\\x[0-9a-fA-F]{2}){2,}").expect("valid regex"));
static OCTAL_RUN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:\\[0-7]{1,3}){2,}").expect("valid regex"));
static OCTAL_BYTE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\\([0-7]{1,3})").expect("valid regex"));
static IFS: Lazy<Regex> = Lazy::new(|| Regex::new(r"\$\{IFS\}|\$IFS\b").expect("valid regex"));
static ZERO_WIDTH: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[\u{200b}-\u{200f}\u{feff}]").expect("valid regex"));
static ALIAS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)alias\s+\w+=['"]([^'"]+)['"]"#).expect("valid regex"));
static CMD_SUB: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\$\(([^()]*)\)|`([^`]*)`").expect("valid regex"));
static ECHO_SUB: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\$\(\s*(?:echo|printf)\s+(?:-e\s+)?([^()]*?)\)").expect("valid regex")
});
static ECHO_PREFIX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^\s*(?:echo|printf)\s+(?:-e\s+)?").expect("valid regex"));
static ENV_ASSIGN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?:^|[;&]\s*)([A-Za-z_][A-Za-z0-9_]*)=('[^']*'|"[^"]*"|[^\s;&|]+)"#)
        .expect("valid regex")
});
static BRACE_LIST: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\{([^{}\s]{1,96})\}").expect("valid regex"));
static ARITH: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\$\(\(([^()]{1,64})\)\)").expect("valid regex"));
static PRINTF_ARITH_OCTAL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)printf\s+['"]\\\\%0?3?o['"]\s+\$\(\(([^()]{1,64})\)\)"#).expect("valid regex")
});
static XARGS_TEMPLATE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?is)^\s*(?:printf|echo)\s+(?:-e\s+)?(?P<payload>.+?)\s*\|\s*xargs\s+-I\s*(?P<placeholder>\S+)\s+(?P<template>\S+)(?P<args>.*)$",
    )
    .expect("valid regex")
});
static SIMPLE_COMMAND_WORD: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[A-Za-z0-9_./-]+").expect("valid regex"));
static UPDATE_SET: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bupdate\s+\w+\s+set\b").expect("valid regex"));
static WHERE_WORD: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bwhere\b").expect("valid regex"));
static RM_SEGMENT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\brm\b([^|;&\n]*)").expect("valid regex"));
static SHELL_SPLIT: Lazy<Regex> = Lazy::new(|| Regex::new(r"[|;&]").expect("valid regex"));
static PRINT_COMMAND: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)^(?:[A-Za-z_][A-Za-z0-9_]*=(?:'[^']*'|"[^"]*"|[^\s;&|]+)\s+)*(?:echo|printf)\b"#,
    )
    .expect("valid regex")
});
static SCRATCH_ABS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^/(?:tmp|var/tmp)(?:/|$)").expect("valid regex"));
static DESTRUCTIVE_RULES: Lazy<Vec<Rule>> = Lazy::new(build_destructive_rules);
static MCP_MUTATING: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)\b(?:rm|delete|del|drop|destroy|truncate|wipe|purge|format|overwrite|erase|prune|shred|unlink|update|insert|write|create|deploy|push|send|post|put|patch|exec|install|move|mv|chmod|chown|kill|shutdown|reboot|grant|revoke|transfer|publish|merge|reset|rebase)\b",
    )
    .expect("valid MCP mutating regex")
});
static MCP_IRREVERSIBLE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)\b(?:rm|delete|del|drop|destroy|truncate|wipe|purge|format|mkfs|overwrite|erase|prune|shred|unlink)\b",
    )
    .expect("valid MCP irreversible regex")
});
static MCP_SYSTEM_TARGET: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(?:\s|^)(?:/(?:etc|var|usr|boot|dev|bin|lib|root|home|sys|proc)\b|/\s*$|/\*|~)|[A-Za-z]:\\Windows",
    )
    .expect("valid MCP system-target regex")
});
static MCP_OFF_HOST: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\bhttps?://|\bftp://|@[\w.-]+:").expect("valid regex"));
static MCP_SENSITIVE_VALUE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(concat!(
        r"AKIA[0-9A-Z]{12,}|",
        r"g",
        r"hp_[A-Za-z0-9]{20,}|",
        r"xox[baprs]-[A-Za-z0-9-]{10,}|",
        r"sk-[A-Za-z0-9]{20,}|",
        r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"
    ))
    .expect("valid MCP sensitive-value regex")
});
static MCP_TRAVERSAL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?:^|[\s,;:="'(\\/])\.\.(?:[\\/]|$)"#).expect("valid regex"));
static MCP_READ_VERBS: &[&str] = &[
    "get", "read", "list", "search", "fetch", "view", "show", "describe", "query", "find",
    "lookup", "count", "inspect", "grep", "open", "cat", "load", "download", "scan", "stat",
];
static MCP_DESTINATION_KEYS: &[&str] = &[
    "url",
    "uri",
    "endpoint",
    "webhook",
    "callback",
    "host",
    "hostname",
    "target",
    "dest",
    "destination",
    "to",
    "recipient",
    "address",
    "server",
];
static MCP_SENSITIVE_KEYS: Lazy<Vec<&'static str>> = Lazy::new(|| {
    vec![
        concat!("to", "ken"),
        concat!("sec", "ret"),
        concat!("pass", "word"),
        "passwd",
        "api_key",
        "apikey",
        "access_key",
        concat!("sec", "ret_key"),
        "private_key",
        "credential",
        "credentials",
        "authorization",
        "auth",
        "session",
        "cookie",
    ]
});

#[pyfunction]
fn expand(command: &str, max_depth: usize, max_forms: usize) -> PyResult<Vec<String>> {
    Ok(expand_internal(command, max_depth, max_forms))
}

#[pyfunction]
fn destructive_match(forms: Vec<String>) -> PyResult<Option<(String, String, String)>> {
    Ok(destructive_match_internal(&forms).map(|matched| {
        (
            matched.severity.name().to_owned(),
            matched.signal_type.to_owned(),
            matched.rationale.to_owned(),
        )
    }))
}

#[pyfunction]
fn mcp_structural_scan(
    tool: &str,
    arguments: Vec<(String, String, String, bool)>,
) -> PyResult<Option<(f64, String, String)>> {
    Ok(
        mcp_structural_scan_internal(tool, &arguments).map(|matched| {
            (
                matched.score,
                matched.severity.name().to_owned(),
                matched.rationale,
            )
        }),
    )
}

#[pyfunction]
fn audit_entry_hash(prev_hash: &str, canonical_payload: &str) -> PyResult<String> {
    Ok(audit_entry_hash_internal(prev_hash, canonical_payload))
}

#[pyfunction]
#[pyo3(signature = (lines, head_json=None))]
fn audit_verify_chain(
    lines: Vec<String>,
    head_json: Option<String>,
) -> PyResult<(bool, Option<i64>, String)> {
    Ok(audit_verify_chain_internal(&lines, head_json.as_deref()))
}

#[pyfunction]
fn meta_extract_signal_features(
    signals: Vec<(String, f64, String, String, String, f64)>,
) -> PyResult<Vec<(String, f64)>> {
    Ok(meta_extract_signal_features_internal(&signals))
}

#[pyfunction]
fn meta_risk(
    weights: Vec<(String, f64)>,
    bias: f64,
    features: Vec<(String, f64)>,
) -> PyResult<f64> {
    Ok(meta_risk_internal(&weights, bias, &features))
}

#[pyfunction]
fn meta_fit(
    rows: Vec<(Vec<(String, f64)>, i32)>,
    iters: usize,
    lr: f64,
    l2: f64,
) -> PyResult<(Vec<(String, f64)>, f64)> {
    Ok(meta_fit_internal(&rows, iters, lr, l2))
}

#[pymodule]
#[pyo3(name = "_rust")]
fn rust_module(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(expand, module)?)?;
    module.add_function(wrap_pyfunction!(destructive_match, module)?)?;
    module.add_function(wrap_pyfunction!(mcp_structural_scan, module)?)?;
    module.add_function(wrap_pyfunction!(audit_entry_hash, module)?)?;
    module.add_function(wrap_pyfunction!(audit_verify_chain, module)?)?;
    module.add_function(wrap_pyfunction!(meta_extract_signal_features, module)?)?;
    module.add_function(wrap_pyfunction!(meta_risk, module)?)?;
    module.add_function(wrap_pyfunction!(meta_fit, module)?)?;
    Ok(())
}

fn expand_internal(command: &str, max_depth: usize, max_forms: usize) -> Vec<String> {
    let mut forms: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    add_form(command, &mut seen, &mut forms);
    let mut frontier = vec![command.to_owned()];
    for _ in 0..max_depth {
        let mut next = Vec::new();
        for cmd in &frontier {
            for form in transform_once(cmd) {
                if forms.len() >= max_forms {
                    return forms;
                }
                if add_form(&form, &mut seen, &mut forms) {
                    next.push(form);
                }
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    forms
}

fn add_form(value: &str, seen: &mut HashSet<String>, forms: &mut Vec<String>) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() || seen.contains(trimmed) {
        return false;
    }
    seen.insert(trimmed.to_owned());
    forms.push(trimmed.to_owned());
    true
}

fn transform_once(command: &str) -> Vec<String> {
    let mut out = Vec::new();
    let norm = normalise_ws(command);
    out.push(norm.clone());

    let mut dequoted = QUOTE_BREAK.replace_all(&norm, "$a$b").to_string();
    dequoted = BACKSLASH_BREAK.replace_all(&dequoted, "$a$b").to_string();
    dequoted = dequoted.replace("''", "").replace(r#""""#, "");
    out.push(dequoted.clone());
    out.push(merge_split_flags(&dequoted));
    out.push(norm.replace("$'", "").replace(['\'', '"'], ""));
    out.push(normalise_ws(&IFS.replace_all(&norm, " ")));
    out.extend(unicode_reveals(&norm));
    out.extend(decode_base64_payloads(command));
    out.extend(decode_hex_runs(command));
    out.extend(decode_hex_inplace(command));
    out.extend(decode_octal_runs(command));
    out.extend(decode_octal_inplace(command));
    out.extend(brace_expansions(command));
    out.extend(arithmetic_expansions(command));
    out.extend(xargs_reconstructions(command));
    out.extend(xargs_arithmetic_printf_reconstructions(command));
    out.extend(command_substitutions(command));
    out.extend(env_var_reconstructions(command));
    for captures in ALIAS.captures_iter(command) {
        if let Some(alias) = captures.get(1) {
            out.push(alias.as_str().to_owned());
        }
    }
    out
}

fn normalise_ws(text: &str) -> String {
    WS.replace_all(text, " ").trim().to_owned()
}

fn printable_text(raw: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(raw).ok()?;
    let normalised = normalise_ws(text);
    if !normalised.is_empty() && normalised.chars().all(|ch| !ch.is_control()) {
        Some(normalised)
    } else {
        None
    }
}

fn merge_split_flags(text: &str) -> String {
    let mut current = text.to_owned();
    loop {
        let next = SPLIT_FLAGS.replace_all(&current, "$1$2").to_string();
        if next == current {
            return current;
        }
        current = next;
    }
}

fn decode_base64_payloads(command: &str) -> Vec<String> {
    if !B64_CONTEXT.is_match(command) {
        return Vec::new();
    }
    let mut decoded = Vec::new();
    for encoded in B64_TOKEN.find_iter(command) {
        if let Ok(raw) = STANDARD.decode(encoded.as_str()) {
            decoded.extend(decode_binary_payloads(&raw));
        }
    }
    decoded
}

fn decode_binary_payloads(raw: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(text) = printable_text(raw) {
        out.push(text);
    }
    for decoded in [
        read_all(GzDecoder::new(raw)),
        read_all(ZlibDecoder::new(raw)),
        read_all(BzDecoder::new(raw)),
        read_all(XzDecoder::new(raw)),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(text) = printable_text(&decoded) {
            out.push(text);
        }
    }
    out
}

fn read_all<R: Read>(mut reader: R) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    reader.read_to_end(&mut out).ok()?;
    Some(out)
}

fn decode_hex_runs(command: &str) -> Vec<String> {
    HEX_RUN
        .find_iter(command)
        .filter_map(|run| decode_hex_run(run.as_str()))
        .collect()
}

fn decode_hex_inplace(command: &str) -> Vec<String> {
    let substituted = HEX_RUN
        .replace_all(command, |captures: &Captures<'_>| {
            decode_hex_run(captures.get(0).map_or("", |m| m.as_str()))
                .unwrap_or_else(|| captures.get(0).map_or("", |m| m.as_str()).to_owned())
        })
        .to_string();
    if substituted == command {
        Vec::new()
    } else {
        vec![substituted]
    }
}

fn decode_hex_run(run: &str) -> Option<String> {
    let mut bytes = Vec::new();
    for pair in run.split("\\x").skip(1) {
        bytes.push(u8::from_str_radix(pair, 16).ok()?);
    }
    printable_text(&bytes)
}

fn decode_octal_run(run: &str) -> Option<String> {
    let mut bytes = Vec::new();
    for captures in OCTAL_BYTE.captures_iter(run) {
        bytes.push(u8::from_str_radix(captures.get(1)?.as_str(), 8).ok()?);
    }
    printable_text(&bytes)
}

fn decode_octal_runs(command: &str) -> Vec<String> {
    OCTAL_RUN
        .find_iter(command)
        .filter_map(|run| decode_octal_run(run.as_str()))
        .collect()
}

fn decode_octal_inplace(command: &str) -> Vec<String> {
    let substituted = OCTAL_RUN
        .replace_all(command, |captures: &Captures<'_>| {
            decode_octal_run(captures.get(0).map_or("", |m| m.as_str()))
                .unwrap_or_else(|| captures.get(0).map_or("", |m| m.as_str()).to_owned())
        })
        .to_string();
    if substituted == command {
        Vec::new()
    } else {
        vec![substituted]
    }
}

fn brace_expansions(command: &str) -> Vec<String> {
    let mut forms = Vec::new();
    for captures in BRACE_LIST.captures_iter(command) {
        let Some(full) = captures.get(0) else {
            continue;
        };
        let Some(body) = captures.get(1) else {
            continue;
        };
        let parts: Vec<&str> = body.as_str().split(',').collect();
        if parts.len() < 2
            || parts.iter().all(|part| part.is_empty())
            || parts.len() > 8
            || parts.iter().any(|part| part.len() > 32)
        {
            continue;
        }
        let start = full.start();
        let end = full.end();
        let prev = command[..start].chars().next_back().unwrap_or(' ');
        let next = command[end..].chars().next().unwrap_or(' ');
        if prev.is_whitespace() && (next.is_whitespace() || "|;&".contains(next)) {
            forms.push(format!(
                "{}{}{}",
                &command[..start],
                parts.join(" "),
                &command[end..]
            ));
        }
        for part in parts {
            forms.push(format!("{}{}{}", &command[..start], part, &command[end..]));
        }
    }
    forms
}

fn arithmetic_expansions(command: &str) -> Vec<String> {
    let mut changed = false;
    let substituted = ARITH
        .replace_all(command, |captures: &Captures<'_>| {
            if let Some(value) = eval_arithmetic(captures.get(1).map_or("", |m| m.as_str())) {
                changed = true;
                value.to_string()
            } else {
                captures.get(0).map_or("", |m| m.as_str()).to_owned()
            }
        })
        .to_string();
    if changed && substituted != command {
        vec![substituted]
    } else {
        Vec::new()
    }
}

fn eval_arithmetic(expr: &str) -> Option<i64> {
    let trimmed = expr.trim();
    if trimmed.is_empty()
        || trimmed
            .chars()
            .any(|ch| ch.is_ascii_alphabetic() && ch != 'x')
    {
        return None;
    }
    if let Some(value) = parse_prefixed_int(trimmed) {
        return bounded(value);
    }
    for op in ["<<", ">>", "|", "^", "&", "%", "+", "-", "*"] {
        if let Some((left, right)) = split_binary(trimmed, op) {
            let lhs = parse_prefixed_int(left.trim())?;
            let rhs = parse_prefixed_int(right.trim())?;
            let value = match op {
                "<<" if (0..=16).contains(&rhs) => lhs.checked_shl(rhs as u32)?,
                ">>" if (0..=16).contains(&rhs) => lhs.checked_shr(rhs as u32)?,
                "|" => lhs | rhs,
                "^" => lhs ^ rhs,
                "&" => lhs & rhs,
                "%" if rhs != 0 => lhs % rhs,
                "+" => lhs.checked_add(rhs)?,
                "-" => lhs.checked_sub(rhs)?,
                "*" => lhs.checked_mul(rhs)?,
                _ => return None,
            };
            return bounded(value);
        }
    }
    if let Some(rest) = trimmed.strip_prefix('+') {
        return bounded(parse_prefixed_int(rest.trim())?);
    }
    if let Some(rest) = trimmed.strip_prefix('-') {
        return bounded(-parse_prefixed_int(rest.trim())?);
    }
    if let Some(rest) = trimmed.strip_prefix('~') {
        return bounded(!parse_prefixed_int(rest.trim())?);
    }
    None
}

fn split_binary<'a>(text: &'a str, op: &str) -> Option<(&'a str, &'a str)> {
    let index = text.find(op)?;
    if index == 0 {
        return None;
    }
    Some((&text[..index], &text[index + op.len()..]))
}

fn parse_prefixed_int(text: &str) -> Option<i64> {
    let stripped = text.trim();
    if let Some(hex) = stripped
        .strip_prefix("0x")
        .or_else(|| stripped.strip_prefix("0X"))
    {
        i64::from_str_radix(hex, 16).ok()
    } else {
        stripped.parse::<i64>().ok()
    }
}

fn bounded(value: i64) -> Option<i64> {
    (-(1_i64 << 20)..=(1_i64 << 20))
        .contains(&value)
        .then_some(value)
}

fn first_shell_word(text: &str) -> Option<String> {
    let mut current = String::new();
    let mut quote: Option<char> = None;
    for ch in text.trim().chars() {
        if quote == Some(ch) {
            quote = None;
            continue;
        }
        if quote.is_none() && (ch == '\'' || ch == '"') {
            quote = Some(ch);
            continue;
        }
        if quote.is_none() && ch.is_whitespace() {
            break;
        }
        current.push(ch);
    }
    (!current.is_empty()).then_some(current)
}

fn xargs_reconstructions(command: &str) -> Vec<String> {
    let Some(captures) = XARGS_TEMPLATE.captures(command) else {
        return Vec::new();
    };
    if captures.name("template").map(|m| m.as_str())
        != captures.name("placeholder").map(|m| m.as_str())
    {
        return Vec::new();
    }
    let Some(verb) = captures
        .name("payload")
        .and_then(|m| first_shell_word(m.as_str()))
    else {
        return Vec::new();
    };
    if !SIMPLE_COMMAND_WORD.is_match(&verb) {
        return Vec::new();
    }
    let args = captures.name("args").map_or("", |m| m.as_str()).trim();
    vec![format!("{verb} {args}").trim().to_owned()]
}

fn xargs_arithmetic_printf_reconstructions(command: &str) -> Vec<String> {
    let Some(captures) = XARGS_TEMPLATE.captures(command) else {
        return Vec::new();
    };
    if captures.name("template").map(|m| m.as_str())
        != captures.name("placeholder").map(|m| m.as_str())
    {
        return Vec::new();
    }
    let payload = captures.name("payload").map_or("", |m| m.as_str());
    let mut octets = Vec::new();
    for expr in PRINTF_ARITH_OCTAL.captures_iter(payload) {
        let Some(value) = expr.get(1).and_then(|m| eval_arithmetic(m.as_str())) else {
            return Vec::new();
        };
        if !(0..=255).contains(&value) {
            return Vec::new();
        }
        octets.push(value as u8);
    }
    if octets.is_empty() || octets.len() > 64 {
        return Vec::new();
    }
    let Some(text) = printable_text(&octets) else {
        return Vec::new();
    };
    if !SIMPLE_COMMAND_WORD.is_match(&text) {
        return Vec::new();
    }
    let args = captures.name("args").map_or("", |m| m.as_str()).trim();
    vec![format!("{text} {args}").trim().to_owned()]
}

fn command_substitutions(command: &str) -> Vec<String> {
    let mut forms = Vec::new();
    let inlined = ECHO_SUB
        .replace_all(command, |captures: &Captures<'_>| {
            captures
                .get(1)
                .map_or("", |m| m.as_str())
                .trim_matches(['\'', '"', ' '])
                .to_owned()
        })
        .to_string();
    if inlined != command {
        forms.push(inlined);
    }
    for captures in CMD_SUB.captures_iter(command) {
        let inner = captures
            .get(1)
            .or_else(|| captures.get(2))
            .map_or("", |m| m.as_str())
            .trim();
        if inner.is_empty() {
            continue;
        }
        forms.push(inner.to_owned());
        let stripped = ECHO_PREFIX
            .replace(inner, "")
            .trim_matches(['\'', '"', ' '])
            .to_owned();
        if !stripped.is_empty() && stripped != inner {
            forms.push(stripped);
        }
    }
    forms
}

fn unicode_reveals(command: &str) -> Vec<String> {
    let normalised: String = command.nfkc().collect();
    let stripped = ZERO_WIDTH.replace_all(&normalised, "").to_string();
    let translated: String = stripped.chars().map(translate_homoglyph).collect();
    [normalised, stripped, translated]
        .into_iter()
        .filter(|form| form != command)
        .collect()
}

fn translate_homoglyph(ch: char) -> char {
    match ch {
        'а' => 'a',
        'е' => 'e',
        'к' => 'k',
        'м' => 'm',
        'о' => 'o',
        'р' => 'p',
        'с' => 'c',
        'х' => 'x',
        'у' => 'y',
        'Α' => 'A',
        'Β' => 'B',
        'Ε' => 'E',
        'Ζ' => 'Z',
        'Η' => 'H',
        'Ι' => 'I',
        'Κ' => 'K',
        'Μ' => 'M',
        'Ν' => 'N',
        'Ο' => 'O',
        'Ρ' => 'P',
        'Τ' => 'T',
        'Χ' => 'X',
        'α' => 'a',
        'ο' => 'o',
        'ρ' => 'p',
        'τ' => 't',
        'χ' => 'x',
        _ => ch,
    }
}

fn env_var_reconstructions(command: &str) -> Vec<String> {
    let mut forms = Vec::new();
    for captures in ENV_ASSIGN.captures_iter(command) {
        let Some(name) = captures.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(raw_value) = captures.get(2).map(|m| strip_shell_quotes(m.as_str())) else {
            continue;
        };
        if raw_value.is_empty()
            || raw_value.len() > 256
            || !raw_value.chars().all(|ch| !ch.is_control())
        {
            continue;
        }
        let pattern = format!(
            r"(?:^|[;&]\s*)\$(?:{}|\{{{}\}})(?P<args>(?:\s+[^;&|]+)*)",
            regex::escape(name),
            regex::escape(name)
        );
        let Ok(command_var) = Regex::new(&pattern) else {
            continue;
        };
        for var_match in command_var.captures_iter(command) {
            let args = var_match.name("args").map_or("", |m| m.as_str()).trim();
            forms.push(format!("{raw_value} {args}").trim().to_owned());
        }
    }
    forms
}

fn strip_shell_quotes(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() >= 2
        && chars.first() == chars.last()
        && matches!(chars.first(), Some('\'' | '"'))
    {
        chars[1..chars.len() - 1].iter().collect()
    } else {
        value.to_owned()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum MatchSeverity {
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl MatchSeverity {
    fn name(self) -> &'static str {
        match self {
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

struct Rule {
    pattern: Regex,
    signal_type: &'static str,
    severity: MatchSeverity,
    rationale: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MatchResult {
    severity: MatchSeverity,
    signal_type: &'static str,
    rationale: &'static str,
}

fn rule(
    pattern: &str,
    signal_type: &'static str,
    severity: MatchSeverity,
    rationale: &'static str,
) -> Rule {
    Rule {
        pattern: Regex::new(pattern).expect("valid destructive-command regex"),
        signal_type,
        severity,
        rationale,
    }
}

fn build_destructive_rules() -> Vec<Rule> {
    vec![
        rule(
            r"(?i):\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",
            "fork_bomb",
            MatchSeverity::Critical,
            "shell fork bomb",
        ),
        rule(
            r"(?i)\bdd\b.*\bof=/dev/(?:sd|nvme|hd|vd|mmcblk|disk)",
            "disk_overwrite",
            MatchSeverity::Critical,
            "raw write to a block device (dd of=/dev/...)",
        ),
        rule(
            r"(?i)\bmkfs(?:\.\w+)?\b",
            "filesystem_format",
            MatchSeverity::Critical,
            "filesystem format (mkfs)",
        ),
        rule(
            r"(?i)\bwipefs\b[^\n;&|]*(?:-a\b|--all\b)[^\n;&|]*/dev/(?:sd|nvme|hd|vd|mmcblk|disk)",
            "filesystem_format",
            MatchSeverity::Critical,
            "filesystem signature wipe on a block device",
        ),
        rule(
            r"(?i)\bsgdisk\b[^\n;&|]*--zap-all\b[^\n;&|]*/dev/(?:sd|nvme|hd|vd|mmcblk|disk)",
            "filesystem_format",
            MatchSeverity::Critical,
            "partition table wipe on a block device",
        ),
        rule(
            r"(?i)\bblkdiscard\b[^\n;&|]*/dev/(?:sd|nvme|hd|vd|mmcblk|disk)",
            "disk_overwrite",
            MatchSeverity::Critical,
            "discard of an entire block device",
        ),
        rule(
            r"(?i)\bcryptsetup\b[^\n;&|]*\bluksFormat\b[^\n;&|]*/dev/(?:sd|nvme|hd|vd|mmcblk|disk)",
            "filesystem_format",
            MatchSeverity::Critical,
            "LUKS format of a block device",
        ),
        rule(
            r"(?i)\bparted\b[^\n;&|]*/dev/(?:sd|nvme|hd|vd|mmcblk|disk)[^\n;&|]*\bmklabel\b",
            "filesystem_format",
            MatchSeverity::Critical,
            "partition label rewrite on a block device",
        ),
        rule(
            r"(?i)\bfind\b.*\s-delete\b|\bfind\b.*-exec\s+rm\b",
            "destructive_command",
            MatchSeverity::High,
            "find -delete / -exec rm mass deletion",
        ),
        rule(
            r"(?i)\bfind\b[^\n;&|]*(?:/\s|/\s*$)[^\n;&|]*-exec\s+shred\b",
            "destructive_command",
            MatchSeverity::High,
            "find -exec shred over a root tree",
        ),
        rule(
            r"(?i)\bshred\b[^\n;&|]*(?:/(?:etc|var|usr|boot|root|home)\b|/\s*$|/\*|~|\bprod(?:uction)?\b)",
            "destructive_command",
            MatchSeverity::High,
            "shred of a sensitive / production target",
        ),
        rule(
            r"(?i)\btar\b[^\n;&|]*--remove-files\b[^\n;&|]*(?:/(?:etc|var|usr|boot|root|home)\b|/\s*$|/\*|~|\bprod(?:uction)?\b)",
            "destructive_command",
            MatchSeverity::High,
            "tar --remove-files against a sensitive / production target",
        ),
        rule(
            r"(?i)>\s*/dev/(?:sd|nvme|hd|vd|mmcblk)",
            "disk_overwrite",
            MatchSeverity::Critical,
            "redirect over a raw block device",
        ),
        rule(
            r"(?i)\brsync\b[^\n;&|]*--delete\b[^\n;&|]*(?:/dev/null/?|(?:^|\s)(?:\.?/)?empty/)[^\n;&|]*\s/(?:etc|var|srv|home|root|opt|usr|boot)\b",
            "destructive_command",
            MatchSeverity::High,
            "rsync --delete mirror wipe of a sensitive target",
        ),
        rule(
            r"(?i)\btruncate\b[^\n;&|]*(?:-s\s*0|--size(?:=|\s)0)[^\n;&|]*(?:/(?:etc|var|usr|boot|root|home)\b|/\s*$|/\*|\bprod(?:uction)?\b)",
            "destructive_command",
            MatchSeverity::High,
            "truncate-to-zero of a sensitive / production target",
        ),
        rule(
            r"(?i)\b(?:shutdown|reboot|halt|poweroff)\b|\binit\s+0\b",
            "availability_loss",
            MatchSeverity::High,
            "host shutdown / reboot",
        ),
        rule(
            r"(?i)\bchmod\s+-R\s+0?777\b",
            "permission_wipe",
            MatchSeverity::High,
            "recursive world-writable permissions",
        ),
        rule(
            r"(?i)\bchmod\s+-R\s+0{3,4}\b[^\n;&|]*(?:/(?:etc|var|usr|boot|root|home)\b|/\s*$|/\*|\bprod(?:uction)?\b)",
            "permission_wipe",
            MatchSeverity::High,
            "recursive permission denial on a sensitive / production target",
        ),
        rule(
            r"(?i)\bchown\s+-R\s+\S+\s+[^\n;&|]*(?:/(?:etc|var|usr|boot|root|home)\b|/\s*$|/\*|\bprod(?:uction)?\b)",
            "permission_wipe",
            MatchSeverity::High,
            "recursive ownership rewrite of a sensitive / production target",
        ),
        rule(
            r"(?i)\b(?:kill(?:all)?\s+-9|kill\s+-9\s+-1)\b|\bkillall\b",
            "process_kill",
            MatchSeverity::High,
            "mass process termination",
        ),
        rule(
            r"(?i)\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b",
            "remote_code_execution",
            MatchSeverity::High,
            "pipe of remote content into a shell",
        ),
        rule(
            r"(?i)\bgit\s+push\b.*(?:--force\b|\s-f\b)",
            "history_rewrite",
            MatchSeverity::High,
            "force-push rewrites remote history",
        ),
        rule(
            r"(?i)\bdrop\s+(?:database|schema|table)\b",
            "sql_drop",
            MatchSeverity::Critical,
            "DROP of a database / schema / table",
        ),
        rule(
            r"(?i)\btruncate\s+table\b|\btruncate\b\s+\w+",
            "sql_truncate",
            MatchSeverity::Critical,
            "TRUNCATE empties a table irreversibly",
        ),
        rule(
            r"(?i)\bdelete\s+from\s+\w+\s*(?:;|$)",
            "sql_unscoped_delete",
            MatchSeverity::High,
            "DELETE without a WHERE clause",
        ),
        rule(
            r"(?i)\b(?:terraform|pulumi)\s+destroy\b",
            "infra_teardown",
            MatchSeverity::Critical,
            "terraform / pulumi destroy tears down managed infrastructure",
        ),
        rule(
            r"(?i)\bkubectl\s+delete\b.*(?:--all\b|\bnamespace\b)",
            "infra_teardown",
            MatchSeverity::High,
            "kubectl delete of a namespace / all resources",
        ),
        rule(
            r"(?i)\baws\s+s3\s+(?:rb|rm)\b.*(?:--force|--recursive)",
            "bucket_deletion",
            MatchSeverity::High,
            "recursive / forced S3 bucket deletion",
        ),
        rule(
            r"(?i)\bsystemctl\s+(?:stop|disable|mask|kill)\b",
            "availability_loss",
            MatchSeverity::High,
            "stopping / disabling a system service",
        ),
        rule(
            r"(?i)\biptables\s+(?:-F|--flush)\b|\bufw\s+disable\b",
            "availability_loss",
            MatchSeverity::High,
            "flushing / disabling the host firewall",
        ),
        rule(
            r"(?i)\bdocker\s+stop\s+\$\(.*docker\s+ps",
            "availability_loss",
            MatchSeverity::High,
            "stopping every running container",
        ),
        rule(
            r"(?i)>>?\s*/etc/sudoers|>\s*/etc/cron",
            "privilege_escalation",
            MatchSeverity::High,
            "writing a sudoers / cron backdoor",
        ),
        rule(
            r"(?i)\busermod\s+-a?G\s+[\w,]*sudo\b|\bchmod\s+[ug]\+s\b|\bpasswd\s+-d\b",
            "privilege_escalation",
            MatchSeverity::High,
            concat!(
                "granting privilege (sudo group / setuid / pass",
                "word removal)"
            ),
        ),
        rule(
            concat!(
                r"(?i)(?:cat|tail|head|less)\b[^|]*(?:id_rsa|/etc/shadow|\.ssh/|",
                r"\.aws/cred|sec",
                r"ret|\.pem|\.key)\b[^|]*\|\s*(?:curl|wget|nc|ncat|netcat)\b"
            ),
            "exfiltration",
            MatchSeverity::High,
            concat!("piping a sec", "ret file to a network tool"),
        ),
        rule(
            r"(?i)\benv\b\s*\|\s*(?:curl|wget|nc|ncat)\b|\baws\s+configure\s+get\b[^|]*\|\s*(?:curl|wget|nc)\b",
            "exfiltration",
            MatchSeverity::High,
            "piping environment / credentials to a network tool",
        ),
        rule(
            r"(?i)\bdropDatabase\s*\(|\bDROP\s+KEYSPACE\b|\bDROP\s+OWNED\b",
            "datastore_drop",
            MatchSeverity::Critical,
            "dropping a NoSQL / Cassandra / owned-objects store",
        ),
        rule(
            r"(?i)\bFLUSH(?:ALL|DB)\b|\betcdctl\s+del\b.*--prefix",
            "datastore_flush",
            MatchSeverity::High,
            "flushing a key-value store",
        ),
        rule(
            r"(?i)\brd\s+/s\b|\brmdir\s+/s\b",
            "destructive_command",
            MatchSeverity::High,
            "recursive Windows directory removal",
        ),
        rule(
            r"(?i)\bformat\s+[a-z]:",
            "filesystem_format",
            MatchSeverity::Critical,
            "format of a Windows drive",
        ),
        rule(
            r"(?i)\bcipher\s+/w\b",
            "disk_overwrite",
            MatchSeverity::High,
            "cipher /w wipes free disk space",
        ),
        rule(
            r"(?i)\bpip\s+uninstall\b[^\n]*\s-r\b|\bnpm\s+uninstall\s+(?:-g|--global)\b|\bapt(?:-get)?\s+(?:remove|purge|autoremove)\b[^\n]*--purge\b",
            "dependency_removal",
            MatchSeverity::High,
            "bulk / global / purging package removal",
        ),
    ]
}

fn destructive_match_internal(forms: &[String]) -> Option<MatchResult> {
    let mut best_rule: Option<&Rule> = None;
    for rule in DESTRUCTIVE_RULES.iter() {
        if forms.iter().any(|form| rule.pattern.is_match(form))
            && best_rule
                .map(|best| rule.severity > best.severity)
                .unwrap_or(true)
        {
            best_rule = Some(rule);
        }
    }
    let update_match = forms.iter().any(|form| is_unscoped_update(form));
    let rm_severity = forms.iter().filter_map(|form| rm_severity(form)).max();
    select_best_match(best_rule, rm_severity, update_match)
}

fn select_best_match(
    rule_match: Option<&Rule>,
    rm_severity: Option<MatchSeverity>,
    update_match: bool,
) -> Option<MatchResult> {
    let mut best = rule_match.map(|rule| MatchResult {
        severity: rule.severity,
        signal_type: rule.signal_type,
        rationale: rule.rationale,
    });
    if update_match {
        best = pick_better(
            best,
            MatchResult {
                severity: MatchSeverity::High,
                signal_type: "sql_unscoped_update",
                rationale: "UPDATE without a WHERE clause",
            },
        );
    }
    if let Some(severity) = rm_severity {
        best = pick_better(
            best,
            MatchResult {
                severity,
                signal_type: "destructive_command",
                rationale: "recursive force-delete of a root / home / system / wildcard path",
            },
        );
    }
    best
}

fn pick_better(current: Option<MatchResult>, candidate: MatchResult) -> Option<MatchResult> {
    if current
        .map(|matched| matched.severity >= candidate.severity)
        .unwrap_or(false)
    {
        current
    } else {
        Some(candidate)
    }
}

struct McpFinding {
    score: f64,
    severity: MatchSeverity,
    reason: String,
}

struct McpScanResult {
    score: f64,
    severity: MatchSeverity,
    rationale: String,
}

fn mcp_structural_scan_internal(
    tool: &str,
    arguments: &[(String, String, String, bool)],
) -> Option<McpScanResult> {
    let mut findings = Vec::new();
    findings.extend(mcp_taint_findings(tool, arguments));
    findings.extend(mcp_confused_deputy_findings(tool, arguments));
    findings.extend(mcp_exfiltration_findings(arguments));
    findings.extend(mcp_traversal_findings(arguments));
    if findings.is_empty() {
        return None;
    }
    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| right.score.total_cmp(&left.score))
    });
    let top_score = findings[0].score;
    let top_severity = findings[0].severity;
    let mut reasons: Vec<&str> = Vec::new();
    for finding in &findings {
        if !reasons.iter().any(|reason| *reason == finding.reason) {
            reasons.push(&finding.reason);
        }
        if reasons.len() >= 3 {
            break;
        }
    }
    Some(McpScanResult {
        score: top_score,
        severity: top_severity,
        rationale: reasons.join("; "),
    })
}

fn mcp_taint_findings(tool: &str, arguments: &[(String, String, String, bool)]) -> Vec<McpFinding> {
    let mut findings = Vec::new();
    for (key, value, origin, tainted) in arguments {
        if !tainted {
            continue;
        }
        if mcp_tool_is_mutating(tool) || MCP_MUTATING.is_match(value) {
            findings.push(McpFinding {
                score: 0.85,
                severity: MatchSeverity::High,
                reason: format!(
                    "argument '{key}' sourced from '{origin}' content drives a state-changing tool call (injection→effector path)"
                ),
            });
        } else {
            findings.push(McpFinding {
                score: 0.6,
                severity: MatchSeverity::Medium,
                reason: format!("argument '{key}' sourced from '{origin}' content"),
            });
        }
    }
    findings
}

fn mcp_confused_deputy_findings(
    tool: &str,
    arguments: &[(String, String, String, bool)],
) -> Vec<McpFinding> {
    if !mcp_tool_is_read(tool) || mcp_tool_is_mutating(tool) {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for (key, value, _, _) in arguments {
        if MCP_SYSTEM_TARGET.is_match(value) {
            findings.push(McpFinding {
                score: 0.7,
                severity: MatchSeverity::High,
                reason: format!(
                    concat!(
                        "read-class tool '{}' pointed at a system / sec",
                        "ret path via '{}'"
                    ),
                    tool, key
                ),
            });
        } else if MCP_IRREVERSIBLE.is_match(value) || MCP_MUTATING.is_match(value) {
            findings.push(McpFinding {
                score: 0.6,
                severity: MatchSeverity::Medium,
                reason: format!(
                    "read-class tool '{tool}' carries a state-changing argument '{key}'"
                ),
            });
        }
    }
    findings
}

fn mcp_exfiltration_findings(arguments: &[(String, String, String, bool)]) -> Vec<McpFinding> {
    let mut has_destination = false;
    let mut has_sensitive = false;
    for (key, value, _, _) in arguments {
        has_destination = has_destination || mcp_is_destination(key, value);
        has_sensitive = has_sensitive || mcp_is_sensitive(key, value);
    }
    if has_destination && has_sensitive {
        vec![McpFinding {
            score: 0.85,
            severity: MatchSeverity::High,
            reason: concat!(
                "sec",
                "ret-bearing argument paired with an external destination (data-exfiltration shape)"
            )
            .to_owned(),
        }]
    } else {
        Vec::new()
    }
}

fn mcp_traversal_findings(arguments: &[(String, String, String, bool)]) -> Vec<McpFinding> {
    let mut findings = Vec::new();
    for (key, value, _, _) in arguments {
        if MCP_TRAVERSAL.is_match(value) {
            findings.push(McpFinding {
                score: 0.6,
                severity: MatchSeverity::Medium,
                reason: format!("path traversal in argument '{key}'"),
            });
        }
    }
    findings
}

fn mcp_tool_is_mutating(tool: &str) -> bool {
    MCP_MUTATING.is_match(&tool.replace(['_', '-'], " "))
}

fn mcp_tool_is_read(tool: &str) -> bool {
    tool.to_ascii_lowercase()
        .split(|ch: char| !ch.is_ascii_alphabetic())
        .filter(|part| !part.is_empty())
        .any(|part| MCP_READ_VERBS.contains(&part))
}

fn mcp_is_destination(key: &str, value: &str) -> bool {
    MCP_DESTINATION_KEYS.contains(&key.to_ascii_lowercase().as_str())
        || MCP_OFF_HOST.is_match(value)
}

fn mcp_is_sensitive(key: &str, value: &str) -> bool {
    MCP_SENSITIVE_KEYS.contains(&key.to_ascii_lowercase().as_str())
        || MCP_SENSITIVE_VALUE.is_match(value)
}

fn audit_entry_hash_internal(prev_hash: &str, canonical_payload: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(canonical_payload.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn audit_verify_chain_internal(
    lines: &[String],
    head_json: Option<&str>,
) -> (bool, Option<i64>, String) {
    let mut prev_hash = "0".repeat(64);
    let mut expected_seq: i64 = 0;
    let mut last_hash = prev_hash.clone();
    let mut last_seq: i64 = -1;

    for (index, line) in lines.iter().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(mut entry) = serde_json::from_str::<Value>(line) else {
            return (
                false,
                Some(index as i64),
                "corrupt / truncated JSON line".to_owned(),
            );
        };
        let Some(object) = entry.as_object_mut() else {
            return (
                false,
                Some(index as i64),
                "corrupt / truncated JSON line".to_owned(),
            );
        };
        let stored = object
            .remove("entry_hash")
            .and_then(|value| value.as_str().map(str::to_owned));
        let seq = object.get("seq").and_then(Value::as_i64);
        if seq != Some(expected_seq) {
            return (
                false,
                Some(index as i64),
                "sequence number out of order".to_owned(),
            );
        }
        let linked = object.get("prev_hash").and_then(Value::as_str);
        if linked != Some(prev_hash.as_str()) {
            return (
                false,
                Some(index as i64),
                "prev_hash does not chain".to_owned(),
            );
        }
        let canonical = python_canonical_json(&entry);
        let recomputed = audit_entry_hash_internal(&prev_hash, &canonical);
        if stored.as_deref() != Some(recomputed.as_str()) {
            return (
                false,
                Some(index as i64),
                "entry_hash mismatch (mutated)".to_owned(),
            );
        }
        prev_hash = recomputed.clone();
        last_hash = recomputed;
        last_seq = expected_seq;
        expected_seq += 1;
    }

    if let Some(head_text) = head_json {
        let Ok(head) = serde_json::from_str::<Value>(head_text) else {
            return (
                false,
                Some(last_seq),
                "head sidecar mismatch (tail truncated)".to_owned(),
            );
        };
        let head_seq = head.get("seq").and_then(Value::as_i64);
        let head_hash = head.get("entry_hash").and_then(Value::as_str);
        if head_seq != Some(last_seq) || head_hash != Some(last_hash.as_str()) {
            return (
                false,
                Some(last_seq),
                "head sidecar mismatch (tail truncated)".to_owned(),
            );
        }
    }
    (true, None, String::new())
}

fn python_canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(flag) => flag.to_string(),
        Value::Number(number) => number.to_string(),
        Value::String(text) => python_json_string(text),
        Value::Array(values) => {
            let body = values
                .iter()
                .map(python_canonical_json)
                .collect::<Vec<_>>()
                .join(",");
            format!("[{body}]")
        }
        Value::Object(object) => {
            let mut keys: Vec<&String> = object.keys().collect();
            keys.sort();
            let body = keys
                .into_iter()
                .map(|key| {
                    format!(
                        "{}:{}",
                        python_json_string(key),
                        python_canonical_json(&object[key])
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{body}}}")
        }
    }
}

fn python_json_string(text: &str) -> String {
    let mut out = String::from("\"");
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch < ' ' => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch if ch.is_ascii() => out.push(ch),
            ch => {
                let mut units = [0_u16; 2];
                for unit in ch.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    out.push('"');
    out
}

fn meta_sigmoid(z: f64) -> f64 {
    if z >= 0.0 {
        1.0 / (1.0 + (-z).exp())
    } else {
        let e = z.exp();
        e / (1.0 + e)
    }
}

fn meta_extract_signal_features_internal(
    signals: &[(String, f64, String, String, String, f64)],
) -> Vec<(String, f64)> {
    let mut features = vec![
        ("signal_count".to_owned(), signals.len() as f64),
        ("max_score".to_owned(), 0.0),
        ("sum_score".to_owned(), 0.0),
        ("mean_score".to_owned(), 0.0),
        ("max_severity".to_owned(), 0.0),
    ];
    if signals.is_empty() {
        return features;
    }

    let mut total = 0.0;
    let mut max_score = 0.0_f64;
    let mut max_severity = 0.0_f64;
    for (detector, score, signal_type, locus, severity_name, severity_value) in signals {
        total += *score;
        max_score = max_score.max(*score);
        max_severity = max_severity.max(*severity_value);
        for (prefix, value) in [
            ("detector", detector.as_str()),
            ("signal_type", signal_type.as_str()),
            ("locus", locus.as_str()),
            ("severity", severity_name.as_str()),
        ] {
            meta_feature_max(&mut features, format!("{prefix}:{value}"), *score);
        }
    }

    meta_feature_set(&mut features, "max_score", max_score);
    meta_feature_set(&mut features, "sum_score", total.min(signals.len() as f64));
    meta_feature_set(&mut features, "mean_score", total / signals.len() as f64);
    meta_feature_set(&mut features, "max_severity", max_severity / 4.0);
    features
}

fn meta_feature_set(features: &mut [(String, f64)], key: &str, value: f64) {
    if let Some((_, current)) = features.iter_mut().find(|(name, _)| name == key) {
        *current = value;
    }
}

fn meta_feature_max(features: &mut Vec<(String, f64)>, key: String, value: f64) {
    if let Some((_, current)) = features.iter_mut().find(|(name, _)| name == &key) {
        *current = current.max(value);
    } else {
        features.push((key, value));
    }
}

fn meta_risk_internal(weights: &[(String, f64)], bias: f64, features: &[(String, f64)]) -> f64 {
    let weight_map: BTreeMap<&str, f64> = weights
        .iter()
        .map(|(name, value)| (name.as_str(), *value))
        .collect();
    let mut z = bias;
    for (name, value) in features {
        z += weight_map.get(name.as_str()).copied().unwrap_or(0.0) * value;
    }
    meta_sigmoid(z)
}

fn meta_fit_internal(
    rows: &[(Vec<(String, f64)>, i32)],
    iters: usize,
    lr: f64,
    l2: f64,
) -> (Vec<(String, f64)>, f64) {
    let mut feature_names = BTreeSet::new();
    for (features, _) in rows {
        for (name, _) in features {
            feature_names.insert(name.clone());
        }
    }
    let mut weights: BTreeMap<String, f64> =
        feature_names.into_iter().map(|name| (name, 0.0)).collect();
    let mut bias = 0.0;
    let n = rows.len() as f64;
    for _ in 0..iters {
        let mut grad: BTreeMap<String, f64> =
            weights.keys().map(|name| (name.clone(), 0.0)).collect();
        let mut grad_bias = 0.0;
        for (features, label) in rows {
            let z = bias
                + features
                    .iter()
                    .map(|(name, value)| weights.get(name).copied().unwrap_or(0.0) * value)
                    .sum::<f64>();
            let err = meta_sigmoid(z) - f64::from(*label);
            grad_bias += err;
            for (name, value) in features {
                if let Some(current) = grad.get_mut(name) {
                    *current += err * value;
                }
            }
        }
        bias -= lr * grad_bias / n;
        for (name, weight) in weights.iter_mut() {
            let gradient = grad.get(name).copied().unwrap_or(0.0);
            *weight -= lr * ((gradient / n) + (l2 * *weight));
        }
    }
    (weights.into_iter().collect(), bias)
}

fn is_unscoped_update(form: &str) -> bool {
    UPDATE_SET.find(form).is_some_and(|matched| {
        let rest = &form[matched.end()..];
        !WHERE_WORD.is_match(rest)
    })
}

fn is_recursive_flag(argument: &str) -> bool {
    if argument == "--recursive" {
        return true;
    }
    if argument.starts_with("--") {
        return false;
    }
    argument.starts_with('-') && (argument.contains('r') || argument.contains('R'))
}

fn target_severity(target: &str) -> Option<MatchSeverity> {
    let cleaned = target.trim().trim_matches(['\'', '"']);
    if cleaned.is_empty() || cleaned.starts_with('-') {
        return None;
    }
    if matches!(
        cleaned,
        "/" | "/*" | "~" | "~/" | "$HOME" | "." | "./" | ".." | "*" | "./*"
    ) || cleaned.starts_with('~')
        || cleaned.starts_with("$HOME")
    {
        return Some(MatchSeverity::Critical);
    }
    if cleaned.starts_with('/') {
        if cleaned.contains('*') {
            return Some(MatchSeverity::Critical);
        }
        if SCRATCH_ABS.is_match(cleaned) {
            return None;
        }
        return Some(MatchSeverity::High);
    }
    if cleaned.starts_with("..") {
        return Some(MatchSeverity::High);
    }
    None
}

fn rm_severity(form: &str) -> Option<MatchSeverity> {
    let mut worst: Option<MatchSeverity> = None;
    for shell_segment in SHELL_SPLIT.split(form) {
        let trimmed = shell_segment.trim();
        if PRINT_COMMAND.is_match(trimmed) {
            continue;
        }
        for captures in RM_SEGMENT.captures_iter(trimmed) {
            let Some(segment) = captures.get(1).map(|m| m.as_str()) else {
                continue;
            };
            let args: Vec<&str> = segment.split_whitespace().collect();
            if !args.iter().any(|argument| is_recursive_flag(argument)) {
                continue;
            }
            for argument in args {
                if let Some(severity) = target_severity(argument) {
                    worst = Some(
                        worst
                            .map(|current| current.max(severity))
                            .unwrap_or(severity),
                    );
                }
            }
        }
    }
    worst
}
