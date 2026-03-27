//! Integration tests for `nono policy` subcommands.
//!
//! These run as separate processes, so they are fully isolated from unit tests.

use std::process::Command;

fn nono_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nono"))
}

#[test]
fn test_groups_list_output() {
    let output = nono_bin()
        .args(["policy", "groups", "--all-platforms"])
        .output()
        .expect("failed to run nono");

    assert!(output.status.success(), "expected exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("deny_credentials"),
        "expected deny_credentials in output, got:\n{stdout}"
    );
}

#[test]
fn test_groups_detail_output() {
    let output = nono_bin()
        .args(["policy", "groups", "deny_credentials"])
        .output()
        .expect("failed to run nono");

    assert!(output.status.success(), "expected exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(".ssh"),
        "expected .ssh in deny_credentials detail, got:\n{stdout}"
    );
    assert!(
        stdout.contains(".aws"),
        "expected .aws in deny_credentials detail, got:\n{stdout}"
    );
}

#[test]
fn test_groups_unknown_exits_error() {
    let output = nono_bin()
        .args(["policy", "groups", "nonexistent_group_xyz"])
        .output()
        .expect("failed to run nono");

    assert!(!output.status.success(), "expected non-zero exit");
}

#[test]
fn test_profiles_list_output() {
    let output = nono_bin()
        .args(["policy", "profiles"])
        .output()
        .expect("failed to run nono");

    assert!(output.status.success(), "expected exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("claude-code"),
        "expected claude-code in profiles list, got:\n{stdout}"
    );
    assert!(
        stdout.contains("default"),
        "expected default in profiles list, got:\n{stdout}"
    );
}

#[test]
fn test_show_profile_output() {
    let output = nono_bin()
        .args(["policy", "show", "default"])
        .output()
        .expect("failed to run nono");

    assert!(output.status.success(), "expected exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Security groups"),
        "expected Security groups section, got:\n{stdout}"
    );
}

#[test]
fn test_show_profile_json() {
    let output = nono_bin()
        .args(["policy", "show", "default", "--json"])
        .output()
        .expect("failed to run nono");

    assert!(output.status.success(), "expected exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout).expect("expected valid JSON output");
    assert!(
        val.get("security").is_some(),
        "expected security key in JSON"
    );
}

#[test]
fn test_diff_output() {
    let output = nono_bin()
        .args(["policy", "diff", "default", "claude-code"])
        .output()
        .expect("failed to run nono");

    assert!(output.status.success(), "expected exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains('+'),
        "expected + lines in diff output, got:\n{stdout}"
    );
}

#[test]
fn test_validate_valid_profile() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("valid-profile.json");
    std::fs::write(
        &path,
        r#"{
            "meta": { "name": "test", "description": "test profile" },
            "security": { "groups": ["deny_credentials"] },
            "workdir": { "access": "readwrite" }
        }"#,
    )
    .expect("write");

    let output = nono_bin()
        .args(["policy", "validate", path.to_str().expect("path")])
        .output()
        .expect("failed to run nono");

    assert!(
        output.status.success(),
        "expected exit 0 for valid profile, stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_validate_invalid_group() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("bad-profile.json");
    std::fs::write(
        &path,
        r#"{
            "meta": { "name": "test" },
            "security": { "groups": ["fake_group_that_does_not_exist"] }
        }"#,
    )
    .expect("write");

    let output = nono_bin()
        .args(["policy", "validate", path.to_str().expect("path")])
        .output()
        .expect("failed to run nono");

    assert!(
        !output.status.success(),
        "expected non-zero exit for invalid group"
    );
}

#[test]
fn test_groups_json() {
    let output = nono_bin()
        .args(["policy", "groups", "--json", "--all-platforms"])
        .output()
        .expect("failed to run nono");

    assert!(output.status.success(), "expected exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout).expect("expected valid JSON output");
    assert!(val.is_array(), "expected JSON array");
    let arr = val.as_array().expect("array");
    assert!(arr.len() > 10, "expected many groups in JSON output");
}
