//! A session bus that accepts the connection but never answers must not
//! hang store creation when `connect-timeout` is set.
//!
//! The store is created in a child process (this test binary, run again)
//! whose `DBUS_SESSION_BUS_ADDRESS` points at a socket nobody answers, so
//! the test process's own environment is left alone. The parent kills the
//! child if it does not finish, so a regression fails instead of hanging.
#![cfg(unix)]

use std::collections::HashMap;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use dbus_secret_service_keyring_store::Store;
use keyring_core::Error;

const CHILD: &str = "DBUS_SECRET_SERVICE_KEYRING_STORE_SILENT_BUS_CHILD";

#[test]
fn silent_bus_gives_platform_failure() {
    if std::env::var_os(CHILD).is_some() {
        let start = Instant::now();
        let config = HashMap::from([("connect-timeout", "1")]);
        let result = Store::new_with_configuration(&config);
        let elapsed = start.elapsed();
        match result {
            Err(Error::PlatformFailure(err)) => {
                assert!(err.to_string().contains("Timed out"), "{err}")
            }
            other => panic!("expected a PlatformFailure, got {other:?}"),
        }
        assert!(elapsed < Duration::from_secs(5), "took {elapsed:?}");
        return;
    }
    let dir = std::env::temp_dir().join(format!("dss-keyring-store-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("bus");
    let _ = std::fs::remove_file(&path);
    // The kernel completes connect() for the backlog, but nothing is ever read.
    let _listener = UnixListener::bind(&path).unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "silent_bus_gives_platform_failure"])
        .env(CHILD, "1")
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!(
                "unix:path={}",
                escape_address_value(path.as_os_str().as_bytes())
            ),
        )
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if start.elapsed() > Duration::from_secs(20) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("store creation did not return within 20 seconds");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let _ = std::fs::remove_dir_all(&dir);
    let mut output = String::new();
    let _ = child.stdout.take().unwrap().read_to_string(&mut output);
    assert!(status.success(), "child failed: {status}\n{output}");
}

/// Escape a value for a D-Bus address, as libdbus does.
fn escape_address_value(bytes: &[u8]) -> String {
    let mut escaped = String::with_capacity(bytes.len());
    for &byte in bytes {
        if byte.is_ascii_alphanumeric() || b"-_/\\*.".contains(&byte) {
            escaped.push(char::from(byte));
        } else {
            escaped.push_str(&format!("%{byte:02x}"));
        }
    }
    escaped
}
