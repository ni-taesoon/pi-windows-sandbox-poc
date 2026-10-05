//! Fixed, diagnostic-only DLL loading comparison. Never a production fallback.
#[path = "minimal_load_comparison/output.rs"]
mod output;
#[cfg(windows)]
#[path = "minimal_load_comparison/windows.rs"]
mod windows;

fn main() {
    #[cfg(all(windows, feature = "lab-minimal-load-comparison"))]
    let result = windows::main();
    #[cfg(not(all(windows, feature = "lab-minimal-load-comparison")))]
    let result: anyhow::Result<()> = Err(anyhow::anyhow!(
        "BLOCKED: dedicated Windows lab-minimal-load-comparison build required"
    ));
    if let Err(error) = result {
        eprintln!("MINIMAL_LOAD_COMPARISON_INCOMPLETE: {error:#}");
        std::process::exit(1);
    }
}
