use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LoadObservation {
    schema_version: u32,
    library: String,
    pub loaded: bool,
    pub preloaded: bool,
    win32_error: u32,
}

pub fn parse(exit_code: u32, stdout: &[u8], stderr: &[u8]) -> Result<LoadObservation> {
    ensure!(stdout.len() <= 1024 && stderr.is_empty(), "unexpected loader output");
    let observed: LoadObservation = serde_json::from_slice(stdout)?;
    ensure!(observed.schema_version == 1, "unexpected loader schema");
    ensure!(observed.library == r"C:\Windows\System32\bcrypt.dll", "unexpected DLL");
    ensure!(
        (observed.loaded && observed.win32_error == 0 && exit_code == 0)
            || (!observed.loaded && observed.win32_error != 0 && exit_code == 1),
        "loader observation/exit status mismatch"
    );
    Ok(observed)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn payload(loaded: bool, error: u32) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"schemaVersion":1,
            "library":r"C:\Windows\System32\bcrypt.dll", "loaded":loaded,
            "win32Error":error, "preloaded":false})).unwrap()
    }
    #[test]
    fn accepts_success_and_observed_load_failure() {
        assert!(parse(0, &payload(true, 0), b"").unwrap().loaded);
        assert!(!parse(1, &payload(false, 1114), b"").unwrap().loaded);
    }
    #[test]
    fn preserves_preloaded_as_separate_observation() {
        let mut value: serde_json::Value = serde_json::from_slice(&payload(true, 0)).unwrap();
        value["preloaded"] = serde_json::json!(true);
        let result = parse(0, &serde_json::to_vec(&value).unwrap(), b"").unwrap();
        assert!(result.loaded && result.preloaded);
    }
    #[test]
    fn rejects_missing_truncated_or_contradictory_results() {
        for (code, data, error) in [
            (0, Vec::new(), b"".as_slice()),
            (0xc0000142, payload(false, 1114), b"".as_slice()),
            (0, payload(false, 1114), b"".as_slice()),
            (1, payload(true, 0), b"".as_slice()),
            (1, payload(false, 0), b"".as_slice()),
            (0, payload(true, 0), b"warning".as_slice()),
            (0, vec![b' '; 1025], b"".as_slice()),
        ] { assert!(parse(code, &data, error).is_err()); }
        let mut data = payload(true, 0);
        data.pop();
        assert!(parse(0, &data, b"").is_err());
    }
    #[test]
    fn rejects_extra_records_fields_or_wrong_library() {
        let good = payload(true, 0);
        let mut duplicate = good.clone(); duplicate.extend(&good);
        assert!(parse(0, &duplicate, b"").is_err());
        let mut value: serde_json::Value = serde_json::from_slice(&good).unwrap();
        value["extra"] = serde_json::json!(true);
        assert!(parse(0, &serde_json::to_vec(&value).unwrap(), b"").is_err());
        value.as_object_mut().unwrap().remove("extra");
        value["library"] = serde_json::json!("bcrypt.dll");
        assert!(parse(0, &serde_json::to_vec(&value).unwrap(), b"").is_err());
    }
}
