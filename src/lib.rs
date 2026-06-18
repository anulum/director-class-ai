// SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
// Director-Class AI — commercial product (licence pending); not the Apache base.
// © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
// © Code 2020–2026 Miroslav Šotek. All rights reserved.
// ORCID: 0009-0009-3560-0851
// Contact: www.anulum.li | protoscience@anulum.li
// Director-Class AI — Rust command de-obfuscation core

use std::collections::HashSet;
use std::io::Read;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use bzip2::read::BzDecoder;
use flate2::read::{GzDecoder, ZlibDecoder};
use once_cell::sync::Lazy;
use pyo3::prelude::*;
use regex::{Captures, Regex};
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

#[pyfunction]
fn expand(command: &str, max_depth: usize, max_forms: usize) -> PyResult<Vec<String>> {
    Ok(expand_internal(command, max_depth, max_forms))
}

#[pymodule]
#[pyo3(name = "_rust")]
fn rust_module(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(expand, module)?)?;
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
