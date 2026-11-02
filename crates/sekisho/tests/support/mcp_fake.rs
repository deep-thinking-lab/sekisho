use std::io::{self, BufRead, Write};

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        let Some(id) = line
            .split("\"id\":")
            .nth(1)
            .map(|tail| tail.trim_start().split([',', '}']).next().unwrap().trim())
        else {
            continue;
        };
        let result = if line.contains("\"initialize\"") {
            r#"{"protocolVersion":"2025-03-26","capabilities":{"tools":{}},"serverInfo":{"name":"stdio-fake","version":"1"}}"#.to_owned()
        } else if line.contains("\"tools/list\"") {
            r#"{"tools":[{"name":"read","inputSchema":{"type":"object"}}]}"#.to_owned()
        } else if line.contains("\"tools/call\"") {
            if line.contains("\"oversize\":true") {
                writeln!(stdout, r#"{{"jsonrpc":"2.0","id":{id},"result":{{"content":[{{"type":"text","text":"{}"}}]}}}}"#, "x".repeat(4 * 1024 * 1024 + 1)).unwrap();
                stdout.flush().unwrap();
                continue;
            }
            let mut environment: Vec<_> = std::env::vars()
                .map(|(key, value)| format!("{key}={value}"))
                .collect();
            environment.sort();
            let clean = environment == ["ONLY_CONFIGURED=yes"];
            format!(
                r#"{{"content":[{{"type":"text","text":"{}"}}],"isError":{}}}"#,
                if clean {
                    "ONLY_CONFIGURED=yes"
                } else {
                    "unexpected inherited environment"
                },
                !clean
            )
        } else {
            continue;
        };
        writeln!(stdout, r#"{{"jsonrpc":"2.0","id":{id},"result":{result}}}"#).unwrap();
        stdout.flush().unwrap();
    }
}
