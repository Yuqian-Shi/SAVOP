use sav_agent::paths::SavopLayout;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};

fn main() {
    let code = match run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err}");
            1
        }
    };
    std::process::exit(code);
}

fn run() -> Result<i32, String> {
    let layout = SavopLayout::load()?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || matches!(args[0].as_str(), "help" | "--help" | "-h") {
        print_help();
        return Ok(0);
    }

    match args[0].as_str() {
        "paths" => {
            layout.print();
            Ok(0)
        }
        "doctor" => Ok(doctor(&layout)),
        "lab" => lab_command(&layout, &args[1..]),
        "router" => router_command(&layout, &args[1..]),
        "topology" => topology_command(&layout, &args[1..]),
        "image" => image_command(&layout, &args[1..]),
        other => Err(format!("unknown command `{other}`; run `savop help`")),
    }
}

fn print_help() {
    println!(
        "SAVOP CLI\n\n\
Usage:\n  savop paths\n  savop doctor\n  savop router build\n  savop lab run [CONFIG]\n  savop lab bench [CONFIG ...]\n  savop lab generate [CONFIG] [--out DIR] [sav_lab_gen args...]\n  savop topology slice [sav_itdk_slice args...]\n  savop image build [base|runtime|all]\n\n\
The CLI reads savop.toml and hides repository-internal paths from normal workflows."
    );
}

fn lab_command(layout: &SavopLayout, args: &[String]) -> Result<i32, String> {
    let Some(command) = args.first().map(String::as_str) else {
        return Err(
            "missing lab command; use `savop lab run`, `savop lab bench`, or `savop lab generate`"
                .to_string(),
        );
    };
    match command {
        "run" => {
            let mut pass = args[1..].to_vec();
            if pass.is_empty() {
                pass.push("5_nodes_v6.json".to_string());
            }
            run_shell_script(&layout.lab_dir.join("bench_scale.sh"), &pass, layout)
        }
        "bench" => run_shell_script(
            &layout.lab_dir.join("bench_fib_window.sh"),
            &args[1..],
            layout,
        ),
        "generate" => {
            let pass = normalize_lab_generate_args(layout, &args[1..]);
            run_tool(layout, "sav_lab_gen", &pass)
        }
        other => Err(format!("unknown lab command `{other}`")),
    }
}

fn router_command(layout: &SavopLayout, args: &[String]) -> Result<i32, String> {
    let Some(command) = args.first().map(String::as_str) else {
        return Err("missing router command; use `savop router build`".to_string());
    };
    match command {
        "build" => run_shell_script(&layout.lab_dir.join("build_router.sh"), &args[1..], layout),
        other => Err(format!("unknown router command `{other}`")),
    }
}

fn topology_command(layout: &SavopLayout, args: &[String]) -> Result<i32, String> {
    let Some(command) = args.first().map(String::as_str) else {
        return Err("missing topology command; use `savop topology slice`".to_string());
    };
    match command {
        "slice" => {
            let pass = normalize_topology_slice_args(layout, &args[1..]);
            run_tool(layout, "sav_itdk_slice", &pass)
        }
        other => Err(format!("unknown topology command `{other}`")),
    }
}

fn image_command(layout: &SavopLayout, args: &[String]) -> Result<i32, String> {
    let Some(command) = args.first().map(String::as_str) else {
        return Err(
            "missing image command; use `savop image build [base|runtime|all]`".to_string(),
        );
    };
    match command {
        "build" => {
            let target = args.get(1).map(String::as_str).unwrap_or("runtime");
            match target {
                "base" => docker_build(layout, "savop_base", "savop_base"),
                "runtime" => docker_build(layout, "savop_runtime_clab", "savop_runtime_clab"),
                "all" => {
                    let first = docker_build(layout, "savop_base", "savop_base")?;
                    if first != 0 {
                        return Ok(first);
                    }
                    docker_build(layout, "savop_runtime_clab", "savop_runtime_clab")
                }
                other => Err(format!("unknown image target `{other}`")),
            }
        }
        other => Err(format!("unknown image command `{other}`")),
    }
}

fn docker_build(layout: &SavopLayout, dockerfile: &str, tag: &str) -> Result<i32, String> {
    let file = layout.lab_dir.join("dockerfiles").join(dockerfile);
    let mut command = Command::new("docker");
    command
        .arg("build")
        .arg("-f")
        .arg(file)
        .arg(&layout.lab_dir)
        .arg("-t")
        .arg(tag);
    run_status(&mut command, layout)
}

fn normalize_lab_generate_args(layout: &SavopLayout, args: &[String]) -> Vec<String> {
    if args.is_empty() {
        return vec![
            "--config".to_string(),
            layout
                .config_dir
                .join("5_nodes_v6.json")
                .display()
                .to_string(),
        ];
    }
    if args[0].starts_with('-') {
        return args.to_vec();
    }
    let mut out = Vec::with_capacity(args.len() + 1);
    out.push("--config".to_string());
    out.push(layout.resolve_config_arg(&args[0]).display().to_string());
    out.extend_from_slice(&args[1..]);
    out
}

fn normalize_topology_slice_args(layout: &SavopLayout, args: &[String]) -> Vec<String> {
    let mut out = args.to_vec();
    if !has_flag(args, "--itdk-dir") {
        out.push("--itdk-dir".to_string());
        out.push(
            layout
                .raw_topology_dir
                .join("caida_itdk/2025-03")
                .display()
                .to_string(),
        );
    }
    if !has_flag(args, "--out-dir") {
        out.push("--out-dir".to_string());
        out.push(layout.itdk_slice_dir.display().to_string());
    }
    out
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|arg| arg == flag)
}

fn run_tool(layout: &SavopLayout, name: &str, args: &[String]) -> Result<i32, String> {
    let bin = layout.resolve_binary(name);
    if !bin.exists() {
        return Err(format!(
            "missing `{}`; build from repo root with `cargo build --release --workspace --bins`",
            bin.display()
        ));
    }
    run_program(&bin, args, layout)
}

fn run_program(program: &Path, args: &[String], layout: &SavopLayout) -> Result<i32, String> {
    let mut command = Command::new(program);
    command.args(args);
    run_status(&mut command, layout)
}

fn run_shell_script(script: &Path, args: &[String], layout: &SavopLayout) -> Result<i32, String> {
    let mut command = Command::new("bash");
    command.arg(script);
    command.args(args);
    run_status(&mut command, layout)
}

fn run_status(command: &mut Command, layout: &SavopLayout) -> Result<i32, String> {
    command.current_dir(&layout.root);
    command.env("SAVOP_ROOT", &layout.root);
    command.env("SAVOP_AGENT_DIR", &layout.agent_dir);
    command.env("SAVOP_LAB_DIR", &layout.lab_dir);
    command.env("SAVOP_ROUTER_DIR", &layout.router_dir);
    command.env("SAVOP_CONFIG_DIR", &layout.config_dir);
    command.env("SAVOP_RESULTS_DIR", &layout.results_dir);
    command.env("SAVOP_RAW_TOPOLOGY_DIR", &layout.raw_topology_dir);
    command.env("SAVOP_ITDK_SLICE_DIR", &layout.itdk_slice_dir);
    command.env("SAVOP_RUN_DIR", &layout.run_dir);
    command.env("SAVOP_BENCH_WORK_DIR", &layout.bench_work_dir);
    let status = command
        .status()
        .map_err(|err| format!("failed to run command: {err}"))?;
    Ok(exit_code(status))
}

fn exit_code(status: ExitStatus) -> i32 {
    status.code().unwrap_or(1)
}

fn doctor(layout: &SavopLayout) -> i32 {
    let checks = [
        ("root", &layout.root),
        ("agent_dir", &layout.agent_dir),
        ("lab_dir", &layout.lab_dir),
        ("router_dir", &layout.router_dir),
        ("config_dir", &layout.config_dir),
        ("results_dir", &layout.results_dir),
        ("raw_topology_dir", &layout.raw_topology_dir),
        ("itdk_slice_dir", &layout.itdk_slice_dir),
        ("run_dir", &layout.run_dir),
        ("bench_work_dir", &layout.bench_work_dir),
    ];
    let mut ok = true;
    for (name, path) in checks {
        let exists = path.exists();
        println!(
            "{name}: {}{}",
            path.display(),
            if exists { "" } else { " (missing)" }
        );
        if matches!(
            name,
            "root" | "agent_dir" | "lab_dir" | "router_dir" | "config_dir"
        ) && !exists
        {
            ok = false;
        }
    }
    for bin in [
        "savop",
        "sav_agent",
        "sav_lab_gen",
        "sav_route_probe",
        "sav_table_probe",
        "sav_itdk_slice",
    ] {
        let path = layout.resolve_binary(bin);
        let exists = path.exists();
        println!(
            "bin {bin}: {}{}",
            path.display(),
            if exists { "" } else { " (missing)" }
        );
        if !exists {
            ok = false;
        }
    }
    for bin in ["bird", "birdc", "birdcl"] {
        let path = layout.router_dir.join(bin);
        let exists = path.exists();
        println!(
            "router {bin}: {}{}",
            path.display(),
            if exists {
                ""
            } else {
                " (missing; run `savop router build`)"
            }
        );
        if !exists {
            ok = false;
        }
    }
    for tool in ["bash", "docker", "containerlab", "jq", "ip"] {
        let exists = command_available(tool);
        println!("tool {tool}: {}", if exists { "found" } else { "missing" });
        if !exists {
            ok = false;
        }
    }
    match docker_image_exists("savop_runtime_clab") {
        Some(true) => println!("docker image savop_runtime_clab: found"),
        Some(false) => {
            println!("docker image savop_runtime_clab: missing; run `savop image build runtime`");
            ok = false;
        }
        None => println!("docker image savop_runtime_clab: skipped; docker unavailable"),
    }
    if ok {
        0
    } else {
        1
    }
}

fn command_available(name: &str) -> bool {
    let status = if cfg!(windows) {
        Command::new("where.exe")
            .arg(name)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
    } else {
        Command::new("sh")
            .arg("-c")
            .arg(format!("command -v {name} >/dev/null 2>&1"))
            .status()
    };
    status.map(|status| status.success()).unwrap_or(false)
}

fn docker_image_exists(tag: &str) -> Option<bool> {
    if !command_available("docker") {
        return None;
    }
    let status = Command::new("docker")
        .arg("image")
        .arg("inspect")
        .arg(tag)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()?;
    Some(status.success())
}
