// CleanReach — Tauri library root. Desktop runs this through
// src/main.rs; Android/iOS load this same code as a library target
// (Tauri mobile builds require a lib target — a bin-only crate fails
// Android builds with "no library targets found in package").
// All cleaning runs in cr-core on the user's own device; the UI only
// collects the list and renders results. Lists are never sent anywhere.

use cr_core::*;
use std::time::Duration;

/// Full pipeline JSON for the Dashboard + Lanes screens. Also returns
/// every export's content so the UI can save any lane in one click.
#[tauri::command]
async fn clean_list(
    list_text: String,
    check_mx: Option<bool>,
    region: Option<String>,
    disposable_extra: Option<String>,
) -> Result<String, String> {
    if list_text.trim().is_empty() {
        return Err("paste or drop a list first".to_string());
    }
    let report = tauri::async_runtime::spawn_blocking(move || {
        let mut disp = DisposableSet::builtin();
        if let Some(extra) = &disposable_extra {
            if !extra.trim().is_empty() {
                disp.add_list(extra);
            }
        }
        let mut opts = CleanOptions::new();
        opts.check_mx = check_mx.unwrap_or(false);
        if let Some(r) = region {
            if !r.trim().is_empty() {
                opts.default_region = r;
            }
        }
        cr_core::clean_list(&list_text, &disp, &opts)
    })
    .await
    .map_err(|e| e.to_string())?;
    let exports: Vec<String> = report
        .all_exports()
        .iter()
        .map(|(name, content)| {
            format!(
                "{{\"name\":\"{}\",\"content\":\"{}\"}}",
                escape_json(name),
                escape_json(content)
            )
        })
        .collect();
    Ok(format!(
        "{{\"report\":{},\"exports\":[{}]}}",
        report.to_json(),
        exports.join(",")
    ))
}

#[tauri::command]
async fn check_domain(domain: String) -> Result<String, String> {
    let health = tauri::async_runtime::spawn_blocking(move || {
        domain_health(&domain, "8.8.8.8:53", Duration::from_secs(5))
    })
    .await
    .map_err(|e| e.to_string())?;
    Ok(format!(
        "{{\"health\":{},\"verdict\":\"{}\"}}",
        health.to_json(),
        escape_json(&health.verdict())
    ))
}

#[tauri::command]
fn validate_phone_cmd(number: String, region: Option<String>) -> Result<String, String> {
    let v = validate_phone(&number, region.as_deref().unwrap_or("GB"));
    Ok(format!(
        "{{\"input\":\"{}\",\"e164\":{},\"country\":{},\"national\":{},\"status\":\"{}\",\"line_type\":\"{}\",\"reason\":\"{}\"}}",
        escape_json(&v.input),
        match &v.e164 { Some(s) => format!("\"{}\"", escape_json(s)), None => "null".to_string() },
        match &v.country { Some(s) => format!("\"{}\"", escape_json(s)), None => "null".to_string() },
        match &v.national { Some(s) => format!("\"{}\"", escape_json(s)), None => "null".to_string() },
        match v.status { PhoneStatus::Valid => "valid", PhoneStatus::Invalid => "invalid", PhoneStatus::Unknown => "unknown" },
        escape_json(&v.line_type),
        escape_json(&v.reason)
    ))
}

/// File toolkit: split pasted lines into chunk texts.
#[tauri::command]
fn split_list(list_text: String, size: usize) -> Result<String, String> {
    if size == 0 {
        return Err("chunk size must be at least 1".to_string());
    }
    let lines: Vec<String> = list_text
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    let chunks = split_lines(&lines, size);
    let parts: Vec<String> = chunks
        .iter()
        .enumerate()
        .map(|(i, c)| {
            format!(
                "{{\"name\":\"part-{:03}.txt\",\"content\":\"{}\"}}",
                i + 1,
                escape_json(&c.join("\n"))
            )
        })
        .collect();
    Ok(format!("{{\"parts\":[{}]}}", parts.join(",")))
}

/// File toolkit: merge several pasted lists into one deduped list.
#[tauri::command]
fn merge_lists_cmd(list_texts: Vec<String>) -> Result<String, String> {
    let refs: Vec<&str> = list_texts.iter().map(|s| s.as_str()).collect();
    let merged = merge_lists(&refs);
    Ok(format!(
        "{{\"count\":{},\"content\":\"{}\"}}",
        merged.len(),
        escape_json(&merged.join("\n"))
    ))
}

/// Save an export file to the device's Downloads folder (falling back
/// to Documents, then the app data dir) and return its full path.
/// Browser-style blob downloads silently do nothing inside Android's
/// WebView, so exports go through the native side where they always
/// land on disk.
#[tauri::command]
fn save_export(
    app: tauri::AppHandle,
    filename: String,
    content: Option<String>,
) -> Result<String, String> {
    use tauri::Manager;
    let bytes = content.unwrap_or_default().into_bytes();
    let dir = app
        .path()
        .download_dir()
        .or_else(|_| app.path().document_dir())
        .or_else(|_| app.path().app_data_dir())
        .map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let safe: String = filename
        .chars()
        .filter(|c| c.is_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .collect();
    let path = dir.join(if safe.is_empty() {
        "export.txt".to_string()
    } else {
        safe
    });
    std::fs::write(&path, bytes).map_err(|e| e.to_string())?;
    Ok(path.display().to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            clean_list,
            check_domain,
            validate_phone_cmd,
            split_list,
            merge_lists_cmd,
            save_export
        ])
        .run(tauri::generate_context!())
        .expect("error while running CleanReach");
}
