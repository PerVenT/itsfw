use std::process::Command;

fn main() {
    println!("cargo:rustc-rerun-if-env-changed=ITSFW_BUILD_VERSION");
    println!("cargo:rustc-rerun-if-changed=.git/HEAD");
    println!("cargo:rustc-rerun-if-changed=.git/refs/tags");

    let version = std::env::var("ITSFW_BUILD_VERSION")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(git_describe_version)
        .unwrap_or_else(|| format!("v{}", env!("CARGO_PKG_VERSION")));

    println!("cargo:rustc-env=ITSFW_VERSION={version}");
}

fn git_describe_version() -> Option<String> {
    let output = Command::new("git")
        .args([
            "-c",
            "safe.directory=*",
            "describe",
            "--tags",
            "--always",
            "--dirty",
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let raw = String::from_utf8(output.stdout).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}
