//! Byte identities shared by the build and the independent execution verifier.
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn file(path: &Path) -> Result<String, String> {
    Ok(digest(
        &std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?,
    ))
}

pub fn source(root: &Path) -> Result<(String, Vec<PathBuf>), String> {
    let mut paths = Vec::new();
    for args in [
        vec!["ls-files", "-z", "--cached", "--recurse-submodules"],
        vec!["ls-files", "-z", "--others", "--exclude-standard"],
    ] {
        let mut command = std::process::Command::new("git");
        for (name, _) in std::env::vars_os() {
            if name.as_encoded_bytes().starts_with(b"GIT") {
                command.env_remove(name);
            }
        }
        let output = command
            .args(["--no-replace-objects", "-c", "core.fsmonitor=false"])
            .args(args)
            .current_dir(root)
            .output()
            .map_err(|e| format!("source inventory: {e}"))?;
        if !output.status.success() {
            return Err("cannot inventory source files".into());
        }
        for name in output.stdout.split(|b| *b == 0).filter(|n| !n.is_empty()) {
            let name = std::str::from_utf8(name).map_err(|_| "non-UTF8 source path")?;
            // Tracker lifecycle is not a build input. Its identity is recorded by the caller.
            if !name.starts_with(".beads/") {
                let path = root.join(name);
                if path.is_dir() && name == "spec" {
                    paths.extend(source(&path)?.1);
                } else {
                    paths.push(path);
                }
            }
        }
    }
    paths.sort();
    paths.dedup();
    Ok((tree(root, &paths, true)?, paths))
}

/// Broad source-enumerated contracts, including tracked absences and new inputs.
/// Shared application dependencies remain bound by the complete source identity.
pub fn validation_contracts(
    root: &Path,
    paths: &[PathBuf],
) -> Result<std::collections::BTreeMap<&'static str, String>, String> {
    let mut result = std::collections::BTreeMap::new();
    for (name, component) in [
        ("native_producer_and_validator", "tracer"),
        ("shell_driver_and_validator", "scripts"),
    ] {
        let members: Vec<_> = paths
            .iter()
            .filter(|p| p.starts_with(root.join(component)))
            .cloned()
            .collect();
        if members.is_empty() {
            return Err("empty validation contract source set".into());
        }
        result.insert(name, tree(root, &members, true)?);
    }
    Ok(result)
}

fn tree(root: &Path, paths: &[PathBuf], source: bool) -> Result<String, String> {
    let mut hash = Sha256::new();
    hash.update(b"tau-tracer-tree-v2\0");
    for path in paths {
        let name = path
            .strip_prefix(root)
            .map_err(|_| "identity path outside root")?;
        hash.update(name.as_os_str().as_encoded_bytes());
        hash.update([0]);
        let meta = match std::fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(error) if source && error.kind() == std::io::ErrorKind::NotFound => {
                // A tracked deletion is part of the current source state. It must
                // differ from both the old bytes and an untracked absent path.
                hash.update(b"absent\0");
                continue;
            }
            Err(error) => return Err(format!("{}: {error}", path.display())),
        };
        if !meta.is_file() || meta.file_type().is_symlink() {
            return Err(format!("nonregular identity input: {}", path.display()));
        }
        hash.update(b"file\0");
        hash.update(meta.len().to_le_bytes());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            hash.update((meta.permissions().mode() & 0o777).to_le_bytes());
        }
        hash.update(std::fs::read(path).map_err(|e| e.to_string())?);
    }
    Ok(format!("{:x}", hash.finalize()))
}

pub fn directory(root: &Path) -> Result<String, String> {
    let kind = std::fs::symlink_metadata(root)
        .map_err(|e| e.to_string())?
        .file_type();
    if !kind.is_dir() || kind.is_symlink() {
        return Err("nonregular artifact identity input".into());
    }
    fn walk(root: &Path, paths: &mut Vec<PathBuf>) -> Result<(), String> {
        for entry in std::fs::read_dir(root).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let kind = entry.file_type().map_err(|e| e.to_string())?;
            if kind.is_dir() {
                walk(&entry.path(), paths)?;
            } else if kind.is_file() {
                paths.push(entry.path());
            } else {
                return Err("nonregular artifact identity input".into());
            }
        }
        Ok(())
    }
    let mut paths = Vec::new();
    walk(root, &mut paths)?;
    if paths.is_empty() {
        return Err("empty artifact directory".into());
    }
    paths.sort();
    tree(root, &paths, false)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #[test]
    fn artifact_root_must_be_a_real_directory() {
        use std::os::fd::AsRawFd;
        let directory =
            std::fs::File::open(concat!(env!("CARGO_MANIFEST_DIR"), "/../www")).unwrap();
        let link = std::path::PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(
            super::directory(&link)
                .unwrap_err()
                .contains("nonregular artifact")
        );
    }
}
