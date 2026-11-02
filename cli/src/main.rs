//! cleanreach CLI — same cr-core engine as the app.
//!
//! Usage:
//!   cleanreach clean <input.csv|txt> [--out DIR] [--mx] [--region GB|US|CA]
//!                    [--disposable-list FILE] [--smtp-probe]  (probe OFF by default)
//!   cleanreach extract <file...>          emails from messy text
//!   cleanreach split <file> <size> [--out DIR]
//!   cleanreach merge <file...>            one de-duplicated list on stdout
//!   cleanreach phone <number> [--region GB|US|CA]
//!   cleanreach domain <domain>            A/MX/SPF/DMARC health
//!
//! Position: clean only lists you own or are authorized to use.

use cr_core::*;
use std::process::ExitCode;
use std::time::Duration;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("cleanreach: {e}");
            ExitCode::FAILURE
        }
    }
}

fn read(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.windows(2).find(|w| w[0] == name).map(|w| w[1].as_str())
}
fn has(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn run(args: &[String]) -> Result<(), String> {
    let cmd = args.first().map(|s| s.as_str()).unwrap_or("help");
    match cmd {
        "clean" => cmd_clean(&args[1..]),
        "extract" => {
            let texts: Vec<String> = args[1..].iter().map(|p| read(p)).collect::<Result<_, _>>()?;
            let refs: Vec<&str> = texts.iter().map(|s| s.as_str()).collect();
            for e in extract_from_texts(&refs) {
                println!("{e}");
            }
            Ok(())
        }
        "split" => {
            if args.len() < 3 {
                return Err("split needs <file> <size>".into());
            }
            let text = read(&args[1])?;
            let size: usize = args[2].parse().map_err(|_| "size must be a number")?;
            let lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
            let out_dir = flag(args, "--out").unwrap_or("split-out");
            std::fs::create_dir_all(out_dir).map_err(|e| e.to_string())?;
            let chunks = split_lines(&lines, size);
            for (i, chunk) in chunks.iter().enumerate() {
                let path = format!("{out_dir}/part-{:03}.txt", i + 1);
                std::fs::write(&path, chunk.join("\n") + "\n").map_err(|e| e.to_string())?;
                println!("{path} ({} lines)", chunk.len());
            }
            Ok(())
        }
        "merge" => {
            let texts: Vec<String> = args[1..]
                .iter()
                .filter(|a| !a.starts_with("--"))
                .map(|p| read(p))
                .collect::<Result<_, _>>()?;
            let refs: Vec<&str> = texts.iter().map(|s| s.as_str()).collect();
            for line in merge_lists(&refs) {
                println!("{line}");
            }
            Ok(())
        }
        "phone" => {
            if args.len() < 2 {
                return Err("phone needs <number>".into());
            }
            let region = flag(args, "--region").unwrap_or("GB");
            let v = validate_phone(&args[1], region);
            println!("input:    {}", v.input);
            println!("status:   {:?}", v.status);
            println!("e164:     {}", v.e164.as_deref().unwrap_or("-"));
            println!("country:  {}", v.country.as_deref().unwrap_or("-"));
            println!("national: {}", v.national.as_deref().unwrap_or("-"));
            println!("line_type: {} (honest: no carrier lookup)", v.line_type);
            println!("reason:   {}", v.reason);
            Ok(())
        }
        "domain" => {
            if args.len() < 2 {
                return Err("domain needs <domain>".into());
            }
            let resolver = flag(args, "--resolver").unwrap_or("8.8.8.8:53");
            let h = domain_health(&args[1], resolver, Duration::from_secs(5));
            println!("{}", h.to_json());
            println!("verdict: {}", h.verdict());
            Ok(())
        }
        "help" | "--help" | "-h" => {
            println!("CleanReach — free contact hygiene studio (CLI)\n");
            println!("  cleanreach clean <input> [--out DIR] [--mx] [--region GB|US|CA] [--disposable-list FILE] [--smtp-probe]");
            println!("  cleanreach extract <file...>");
            println!("  cleanreach split <file> <size> [--out DIR]");
            println!("  cleanreach merge <file...>");
            println!("  cleanreach phone <number> [--region GB|US|CA]");
            println!("  cleanreach domain <domain> [--resolver 8.8.8.8:53]");
            println!("\nclean writes: results.json, clean.csv, disposable.csv, role.csv,");
            println!("invalid.csv, risky.csv, consented_phones.csv, summary.md");
            println!("Disposable/temp addresses are removed from clean.csv by default.");
            println!("The SMTP probe is OFF unless --smtp-probe is passed explicitly.");
            Ok(())
        }
        other => Err(format!("unknown command '{other}' — try: cleanreach help")),
    }
}

fn cmd_clean(args: &[String]) -> Result<(), String> {
    let input = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .ok_or("clean needs an input file")?;
    let text = read(input)?;
    let mut disp = DisposableSet::builtin();
    if let Some(path) = flag(args, "--disposable-list") {
        disp.add_list(&read(path)?);
        eprintln!("disposable domains loaded: {}", disp.len());
    }
    let mut opts = CleanOptions::new();
    opts.check_mx = has(args, "--mx");
    if let Some(r) = flag(args, "--region") {
        opts.default_region = r.to_string();
    }
    if let Some(r) = flag(args, "--resolver") {
        opts.resolver = r.to_string();
    }
    let report = clean_list(&text, &disp, &opts);
    if has(args, "--smtp-probe") {
        eprintln!("--smtp-probe: probing clean-lane addresses (conservative, one RCPT each)");
        for c in &report.contacts {
            if let Some(e) = &c.email {
                if e.lane.in_clean_export() {
                    let (ok, note) = smtp_probe(&e.email, Duration::from_secs(8));
                    eprintln!("  {} -> {} ({})", e.email, if ok { "accepted" } else { "not proven" }, note);
                }
            }
        }
    }
    let out_dir = flag(args, "--out").unwrap_or("cleanreach-out");
    std::fs::create_dir_all(out_dir).map_err(|e| e.to_string())?;
    for (name, content) in report.all_exports() {
        std::fs::write(format!("{out_dir}/{name}"), content).map_err(|e| e.to_string())?;
    }
    print!("{}", report.summary_md());
    println!("exports written to {out_dir}/");
    Ok(())
}
