//! Bounded, serialized uRPF reconciliation. FIB read errors are not empty FIBs.
//! Status/readback proves installation, not packet delivery; the latter is tested
//! by the isolated calibration runner. No probes are sent by production Agents.
use super::*;
use std::os::unix::process::CommandExt;
use std::process::Output;
use std::time::Instant;

const OUTPUT_LIMIT: usize = 8 * 1024 * 1024;

pub(super) fn command_timeout() -> Duration {
    Duration::from_millis(
        env::var("SAVOP_DATA_PLANE_COMMAND_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(2000)
            .clamp(100, 30000),
    )
}

fn drain(mut reader: impl Read) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buffer = [0; 8192];
    let mut exceeded = false;
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        if out.len() + count <= OUTPUT_LIMIT {
            out.extend_from_slice(&buffer[..count]);
        } else {
            exceeded = true;
        }
    }
    if exceeded {
        Err(std::io::Error::other("command output exceeds 8 MiB"))
    } else {
        Ok(out)
    }
}

pub(super) fn run_command(cmd: &mut Command, timeout: Duration) -> Result<Output, String> {
    let name = cmd.get_program().to_string_lossy().to_string();
    let mut child = cmd
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{name}: spawn failed: {e}"))?;
    let out = child.stdout.take().ok_or("missing stdout")?;
    let err = child.stderr.take().ok_or("missing stderr")?;
    let stdout = thread::spawn(move || drain(out));
    let stderr = thread::spawn(move || drain(err));
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if start.elapsed() < timeout => thread::sleep(Duration::from_millis(10)),
            Ok(None) => break Err(format!("{name}: timeout after {} ms", timeout.as_millis())),
            Err(e) => break Err(format!("{name}: wait failed: {e}")),
        }
    };
    // Linux: the child is leader of a fresh process group created above.
    // Kill that group only, including any pipe-holding descendants, then reap.
    // Never use a caller-supplied PID or the Agent's own process group here.
    unsafe extern "C" {
        fn kill(pid: i32, signal: i32) -> i32;
    }
    unsafe { kill(-(child.id() as i32), 9) };
    let _ = child.wait();
    let out = stdout.join().map_err(|_| "stdout reader panicked")?;
    let err = stderr.join().map_err(|_| "stderr reader panicked")?;
    let status = status?;
    Ok(Output {
        status,
        stdout: out.map_err(|e| format!("{name}: stdout failed: {e}"))?,
        stderr: err.map_err(|e| format!("{name}: stderr failed: {e}"))?,
    })
}

pub(super) fn checked_request(body: &str) -> Result<Option<Value>, String> {
    if body.trim().is_empty() {
        return Ok(None);
    }
    let value: Value = serde_json::from_str(body).map_err(|e| format!("invalid JSON: {e}"))?;
    if !value.is_object() {
        return Err("request must be a JSON object".to_string());
    }
    for name in ["dry_run", "install"] {
        if value.get(name).is_some_and(|v| !v.is_boolean()) {
            return Err(format!("{name} must be boolean"));
        }
    }
    for name in ["active_app", "app"] {
        if value.get(name).is_some_and(|v| !v.is_string()) {
            return Err(format!("{name} must be a string"));
        }
    }
    Ok(Some(value))
}

fn parse_routes(bytes: &[u8], family: u8) -> Result<Vec<KernelRoute>, String> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|e| format!("invalid FIB JSON: {e}"))?;
    let items = value.as_array().ok_or("FIB JSON must be an array")?;
    let mut routes = Vec::new();
    for item in items {
        let raw = value_string(item, "dst").ok_or("FIB route missing dst")?;
        let prefix = if raw == "default" {
            if family == 4 {
                "0.0.0.0/0".into()
            } else {
                "::/0".into()
            }
        } else {
            normalize_prefix_text(&raw)
        };
        if prefix_family(&prefix) != Some(family) {
            return Err(format!("invalid IPv{family} route prefix: {raw}"));
        }
        // Refuse unsupported ECMP/nhid instead of silently omitting interfaces.
        // The present calibration only qualifies single selected nexthops.
        if item.get("nexthops").is_some() || item.get("nhid").is_some() {
            return Err("ECMP/nhid FIB routes are not supported by this installer".into());
        }
        let interface_name = value_string(item, "dev");
        let route_type = value_string(item, "type");
        if route_type.as_deref().unwrap_or("unicast") == "unicast" && interface_name.is_none() {
            return Err("unicast FIB route missing dev".into());
        }
        routes.push(KernelRoute {
            family,
            prefix,
            interface_name,
            route_type,
            gateway: value_string(item, "gateway").or_else(|| value_string(item, "via")),
            protocol: value_string(item, "protocol"),
            scope: value_string(item, "scope"),
        });
    }
    Ok(routes)
}

fn checked_kernel_routes() -> Result<Vec<KernelRoute>, String> {
    let mut routes = Vec::new();
    for (family, flag) in [(4, "-4"), (6, "-6")] {
        let output = run_command(
            Command::new("ip").args(["-j", flag, "route", "show", "table", "main"]),
            command_timeout(),
        )?;
        if !output.status.success() {
            return Err(format!(
                "IPv{family} FIB read failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        routes.extend(parse_routes(&output.stdout, family)?);
    }
    Ok(routes)
}

fn canonicalize_nft(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.remove("handle");
            if let Some(Value::Object(counter)) = map.get_mut("counter") {
                counter.remove("packets");
                counter.remove("bytes");
            }
            for child in map.values_mut() {
                canonicalize_nft(child);
            }
        }
        Value::Array(items) => {
            items.retain(|v| v.get("metainfo").is_none());
            for child in items {
                canonicalize_nft(child);
            }
        }
        _ => {}
    }
}

fn fingerprint(bytes: &[u8], expected_hash: Option<u64>) -> Result<u64, String> {
    let mut value: Value =
        serde_json::from_slice(bytes).map_err(|e| format!("invalid nft JSON: {e}"))?;
    let entries = value
        .get("nftables")
        .and_then(Value::as_array)
        .ok_or("missing nftables array")?;
    if !entries.iter().any(|entry| {
        let Some(table) = entry.get("table") else {
            return false;
        };
        table["name"] == NFT_TABLE
            && table["family"] == "inet"
            && expected_hash.is_none_or(|h| table["comment"] == format!("savop-plan-{h:016x}"))
    }) {
        return Err("installed nft table/plan marker mismatch".into());
    }
    canonicalize_nft(&mut value);
    let mut hash = DefaultHasher::new();
    value.to_string().hash(&mut hash);
    Ok(hash.finish())
}

pub(super) fn installed_fingerprint(expected: Option<u64>) -> Result<Option<u64>, String> {
    let out = run_command(
        Command::new("nft").args(["-j", "list", "table", "inet", NFT_TABLE]),
        command_timeout(),
    )?;
    if !out.status.success() {
        let error = String::from_utf8_lossy(&out.stderr);
        if error.contains("No such file") {
            return Ok(None);
        }
        return Err(format!("nft readback failed: {error}"));
    }
    fingerprint(&out.stdout, expected).map(Some)
}

fn retry_delay(interval: u64, errors: u32) -> u64 {
    interval
        .clamp(100, 10000)
        .saturating_mul(1 << errors.min(5))
        .min(10000)
}

impl Agent {
    pub(super) fn resume_data_plane(&self) {
        if let Ok(mut status) = self.data_plane.lock() {
            status.paused = false;
            status.consecutive_errors = 0;
        }
    }

    pub(super) fn pause_and_remove_data_plane(&self) -> Result<(), String> {
        let _operation = self
            .data_plane_operation
            .lock()
            .map_err(|_| "operation_lock_poisoned")?;
        {
            let mut status = self
                .data_plane
                .lock()
                .map_err(|_| "data_plane_lock_poisoned")?;
            status.paused = true;
            status.phase = "paused".into();
        }
        // A failed deletion stays paused; it is never reported as success.
        let result = delete_nft_table().and_then(|()| {
            if installed_fingerprint(None)?.is_some() {
                Err("nft table still present after disable".into())
            } else {
                Ok(())
            }
        });
        let mut status = self
            .data_plane
            .lock()
            .map_err(|_| "data_plane_lock_poisoned")?;
        if let Err(error) = &result {
            status.last_error = Some(error.clone());
            status.error_count += 1;
            status.phase = "paused_error".into();
        } else {
            status.last_hash = None;
            status.installed_fingerprint = None;
            status.last_result = None;
            status.last_error = None;
            status.consecutive_errors = 0;
            status.last_verified = Some(now_secs());
        }
        result
    }

    pub(super) fn reconcile_data_plane(&self) -> u64 {
        let Ok(_operation) = self.data_plane_operation.lock() else {
            return 1000;
        };
        let (enabled, dry_run, active_app, interval) = self.data_plane_auto_config();
        let interval = interval.clamp(100, 30000);
        {
            let Ok(mut status) = self.data_plane.lock() else {
                return 1000;
            };
            status.enabled = enabled;
            status.dry_run = dry_run;
            status.active_app = active_app.clone();
            status.interval_ms = interval;
            status.last_check = Some(now_secs());
            if status.paused || !enabled {
                if !status.paused {
                    status.phase = "idle".into();
                }
                return interval;
            }
            status.phase = "checking".into();
        }
        let result = (|| {
            let app = active_app.ok_or("auto update needs active_app")?;
            if !matches!(app.as_str(), "strict_urpf" | "loose_urpf") {
                return Err(
                    "automatic installation currently supports strict/loose uRPF only".into(),
                );
            }
            let plan = self.build_data_plane_plan(&app, dry_run)?;
            if !dry_run {
                let previous = self
                    .data_plane
                    .lock()
                    .map_err(|_| "data_plane_lock_poisoned")?
                    .clone();
                // Read back even on an unchanged FIB: missing or edited tables
                // must be repaired. A readback error is not evidence of absence.
                let installed = installed_fingerprint(None)?;
                if previous.last_hash == Some(plan.hash)
                    && installed.is_some()
                    && previous.installed_fingerprint == installed
                {
                    let mut status = self
                        .data_plane
                        .lock()
                        .map_err(|_| "data_plane_lock_poisoned")?;
                    status.skip_count += 1;
                    status.last_verified = Some(now_secs());
                    status.phase = "in_sync".into();
                    return Ok(());
                }
            }
            self.apply_data_plane_plan(plan)?;
            if dry_run {
                self.data_plane
                    .lock()
                    .map_err(|_| "data_plane_lock_poisoned")?
                    .phase = "dry_run".into();
            }
            Ok::<(), String>(())
        })();
        let Ok(mut status) = self.data_plane.lock() else {
            return interval;
        };
        match result {
            Ok(()) => {
                status.last_error = None;
                status.consecutive_errors = 0;
                interval
            }
            Err(error) => {
                self.log(&format!("automatic data-plane update failed: {error}"));
                status.error_count += 1;
                status.consecutive_errors = status.consecutive_errors.saturating_add(1);
                status.last_error = Some(error);
                status.phase = "retry_wait".into();
                retry_delay(interval, status.consecutive_errors)
            }
        }
    }

    pub(super) fn with_checked_sav_rules<R>(
        &self,
        app: &str,
        consume: impl FnOnce(&BTreeMap<String, SavRule>) -> Result<R, String>,
    ) -> Result<R, String> {
        if !matches!(app, "strict_urpf" | "loose_urpf") {
            // Legacy manual paths remain available, but are not auto-qualified.
            return self.with_sav_rules_for_app(app, consume);
        }
        let mut caches = self
            .urpf_caches
            .lock()
            .map_err(|_| "urpf_cache_lock_poisoned")?;
        let (config, links) = {
            let state = self.state.lock().map_err(|_| "state_lock_poisoned")?;
            (state.config.clone(), state.links.clone())
        };
        if !config.config_loaded {
            return Err("configuration not loaded".into());
        }
        let ignored: Vec<_> = if config.use_ignore_nets {
            config
                .ignore_nets
                .iter()
                .filter_map(|p| parse_prefix(p))
                .collect()
        } else {
            Vec::new()
        };
        let routes: Vec<_> = checked_kernel_routes()?
            .into_iter()
            .filter(|r| should_keep_route(r, config.ignore_private, &ignored))
            .collect();
        sav_apps::with_sav_rules(
            &sav_apps::AppContext {
                config: &config,
                routes: &routes,
                bird_routes: &[],
                links: &links,
            },
            app,
            Some(&mut caches),
            consume,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_kills_pipe_holding_descendant() {
        let start = Instant::now();
        let error = run_command(
            Command::new("sh").args(["-c", "sleep 10 & wait"]),
            Duration::from_millis(60),
        )
        .unwrap_err();
        assert!(error.contains("timeout"));
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn command_drains_pipes_without_deadlock() {
        let output = run_command(
            Command::new("sh").args(["-c", "head -c 100000 /dev/zero; echo error >&2; exit 7"]),
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(output.stdout.len(), 100000);
        assert_eq!(output.status.code(), Some(7));
        assert_eq!(output.stderr, b"error\n");
    }

    #[test]
    fn fib_errors_are_not_empty_snapshots() {
        for bad in [
            r#"{}"#,
            r#"[{}]"#,
            r#"[{"dst":"wrong","dev":"eth_1"}]"#,
            r#"[{"dst":"198.18.0.0/24"}]"#,
            r#"[{"dst":"::/0","dev":"eth_1"}]"#,
            r#"[{"dst":"198.18.0.0/24","nexthops":[]}]"#,
        ] {
            assert!(parse_routes(bad.as_bytes(), 4).is_err(), "{bad}");
        }
        assert!(parse_routes(b"[]", 4).unwrap().is_empty());
    }

    #[test]
    fn fib_parses_ipv4_ipv6_and_blackholes() {
        assert_eq!(
            parse_routes(br#"[{"dst":"default","dev":"eth_1"}]"#, 4).unwrap()[0].prefix,
            "0.0.0.0/0"
        );
        assert_eq!(
            parse_routes(br#"[{"dst":"default","dev":"eth_1"}]"#, 6).unwrap()[0].prefix,
            "::/0"
        );
        assert!(parse_routes(br#"[{"dst":"198.18.0.0/24","type":"blackhole"}]"#, 4).is_ok());
    }

    #[test]
    fn nft_fingerprint_ignores_only_volatile_fields() {
        let initial = json!({"nftables":[{"metainfo":{"version":"x"}},{"table":{"name":"savop","family":"inet","comment":"savop-plan-0000000000000001","handle":1}},{"rule":{"handle":2,"expr":[{"counter":{"packets":0,"bytes":0}},{"accept":null}]}}]});
        let mut changed = initial.clone();
        changed["nftables"][2]["rule"]["handle"] = json!(50);
        changed["nftables"][2]["rule"]["expr"][0]["counter"]["packets"] = json!(100);
        let hash = fingerprint(initial.to_string().as_bytes(), Some(1)).unwrap();
        assert_eq!(
            hash,
            fingerprint(changed.to_string().as_bytes(), Some(1)).unwrap()
        );
        changed["nftables"][2]["rule"]["expr"][1] = json!({"drop":null});
        assert_ne!(
            hash,
            fingerprint(changed.to_string().as_bytes(), Some(1)).unwrap()
        );
        assert!(fingerprint(initial.to_string().as_bytes(), Some(2)).is_err());
    }

    #[test]
    fn rejects_invalid_write_requests() {
        for bad in [
            "bad",
            "null",
            "[]",
            r#"{"dry_run":"false"}"#,
            r#"{"app":1}"#,
        ] {
            assert!(checked_request(bad).is_err());
        }
        assert!(checked_request("").unwrap().is_none());
        assert!(checked_request(r#"{"dry_run":true}"#).is_ok());
    }

    #[test]
    fn retry_is_bounded_and_increases() {
        assert_eq!(retry_delay(200, 1), 400);
        assert_eq!(retry_delay(200, 2), 800);
        assert_eq!(retry_delay(u64::MAX, u32::MAX), 10000);
    }
}
