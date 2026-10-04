use std::io::Read;
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    #[cfg(windows)]
    if args
        .first()
        .is_some_and(|arg| arg == "internal-experimental-helper")
    {
        let result = (|| -> anyhow::Result<()> {
            anyhow::ensure!(args.len() == 3, "invalid internal helper arguments");
            pi_windows_sandbox::broker::helper_main(&args[1], args[2].parse()?)
        })();
        if let Err(error) = result {
            eprintln!("helper failed: {error}");
            std::process::exit(1);
        }
        return;
    }
    if args == ["status"] {
        println!(
            "{}",
            serde_json::json!({"schemaVersion":1,"backend":"pi-windows-sandbox","nativeValidated":pi_windows_sandbox::NATIVE_VALIDATED,"platformSupported":cfg!(windows)})
        );
        return;
    }
    let result = (|| -> anyhow::Result<()> {
        anyhow::ensure!(args == ["run"], "usage: pi-windows-sandbox status|run");
        let mut input = Vec::new();
        std::io::stdin()
            .take(1024 * 1024 + 1)
            .read_to_end(&mut input)?;
        anyhow::ensure!(input.len() <= 1024 * 1024, "request too large");
        let request: pi_windows_sandbox::protocol::RunRequest = serde_json::from_slice(&input)?;
        request.validate()?;
        anyhow::bail!("NATIVE_VALIDATION_REQUIRED: dedicated-account broker, policy admission and Windows enforcement matrix are not validated; execution is disabled");
    })();
    if let Err(error) = result {
        let message = error.to_string();
        let code = if message.starts_with("NATIVE_VALIDATION_REQUIRED") {
            "NATIVE_VALIDATION_REQUIRED"
        } else {
            "INVALID_REQUEST"
        };
        println!(
            "{}",
            serde_json::json!({"type":"error","code":code,"message":message})
        );
        std::process::exit(1);
    }
}
