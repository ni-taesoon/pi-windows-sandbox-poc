//! Default-off, fixed Python isolation acceptance laboratory; never a product fallback.
#[cfg(all(windows, feature = "lab-python-isolation-acceptance"))]
#[path = "python_isolation_acceptance/windows.rs"]
mod windows;
fn main() {
    #[cfg(all(windows, feature = "lab-python-isolation-acceptance"))]
    let result = windows::main();
    #[cfg(not(all(windows, feature = "lab-python-isolation-acceptance")))]
    let result: anyhow::Result<()> = Err(anyhow::anyhow!("BLOCKED: Windows standalone lab-python-isolation-acceptance build required"));
    if let Err(error) = result { eprintln!("PYTHON_ISOLATION_ACCEPTANCE_INCOMPLETE: {error:#}"); std::process::exit(1); }
}
