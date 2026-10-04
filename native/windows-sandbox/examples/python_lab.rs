//! Fixed-command disposable Windows lab only. Production CLI remains disabled.
#[cfg(windows)]
#[path = "python_lab/windows.rs"]
mod windows;
fn main() {
    #[cfg(windows)]
    let result = windows::main();
    #[cfg(not(windows))]
    let result: anyhow::Result<()> = Err(anyhow::anyhow!(
        "BLOCKED: this lab requires disposable Windows"
    ));
    if let Err(error) = result {
        eprintln!("LAB_FAILED: {error:#}");
        std::process::exit(1);
    }
}
