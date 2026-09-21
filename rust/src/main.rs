//! Standalone verifier binary -- the Rust counterpart of the Python/C#/Java CLIs.
//!
//!     ledgerrag-verify <response.json>

use std::process::ExitCode;

use ledger_rag::{verify_response, QueryResponse};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        println!("usage: ledgerrag-verify <response.json>");
        return ExitCode::from(2);
    }
    let data = match std::fs::read_to_string(&args[1]) {
        Ok(text) => text,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(2);
        }
    };
    let resp: QueryResponse = match serde_json::from_str(&data) {
        Ok(parsed) => parsed,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(2);
        }
    };
    let result = match verify_response(&resp) {
        Ok(result) => result,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(2);
        }
    };
    if result.verified {
        println!("\u{2705} VERIFIED (Rust)");
    } else {
        println!("\u{274c} TAMPERED / INVALID (Rust)");
    }
    match serde_json::to_string_pretty(&result) {
        Ok(json) => println!("{json}"),
        Err(err) => eprintln!("{err}"),
    }
    if result.verified {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
