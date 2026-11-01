use anyhow::{ensure, Context, Result};
use clap::{Parser, Subcommand};
use external_agent::{
    config::{Config, Health, Limits, Mode, Target},
    engine, measurement,
    results::Report,
    vectors::{lab, registry::Registry},
};
#[cfg(feature = "experimental-receiver")]
use std::net::{IpAddr, SocketAddr};
use std::{
    io::Write,
    path::{Path, PathBuf},
};
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(
    version,
    about = "Bounded YAML-configured sender for network protocol validation"
)]
struct Cli {
    #[arg(long, global = true)]
    catalog: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Vectors {
        #[command(subcommand)]
        command: VectorCommand,
    },
    Validate {
        #[arg(long)]
        config: PathBuf,
    },
    Run {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Report {
        #[arg(long)]
        input: PathBuf,
        #[arg(long, default_value="json", value_parser=["json"])]
        format: String,
    },
    Profiles {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    /// Create loopback example configurations.
    Demo {
        #[arg(long, default_value = "local-demo")]
        directory: PathBuf,
    },
    /// Write one offline, documentation-address IPv4/ICMP PCAP; does not transmit.
    Fixture {
        #[arg(long)]
        output: PathBuf,
    },
    MeasurementKeygen {
        #[arg(long)]
        key_file: PathBuf,
    },
    #[cfg(feature = "experimental-receiver")]
    Receiver {
        #[arg(long, default_value = "127.0.0.1:9000")]
        bind: SocketAddr,
        #[arg(long)]
        allow_peer: IpAddr,
        #[arg(long)]
        run_id: String,
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long, default_value_t = 1000)]
        expected_probes: u64,
        #[arg(long, default_value_t = 180)]
        duration: u64,
        #[arg(long)]
        output: PathBuf,
    },
    #[cfg(feature = "experimental-receiver")]
    Compare {
        #[arg(long)]
        sender: PathBuf,
        #[arg(long)]
        receiver: PathBuf,
        #[arg(long)]
        key_file: PathBuf,
    },
}

#[derive(Subcommand)]
enum VectorCommand {
    /// Count protocol implementations and offline entries separately for L3/L4/L7.
    Coverage,
    List {
        #[arg(long)]
        category: Option<String>,
        #[arg(long)]
        layer: Option<String>,
        #[arg(long)]
        json: bool,
    },
    Info {
        id: String,
    },
}

#[derive(Subcommand)]
enum ProfileCommand {
    List,
    Create {
        #[arg(long, default_value = "basic", value_parser = ["basic", "sophisticated", "researcher", "hacker", "l4", "high-priority"])]
        preset: String,
        #[arg(long)]
        directory: PathBuf,
    },
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, value)?;
    writeln!(&mut stdout)?;
    Ok(())
}

fn reserve_output(path: &Path) -> Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create new report {}", path.display()))
}

fn write_json<T: serde::Serialize>(mut file: std::fs::File, value: &T) -> Result<()> {
    serde_json::to_writer_pretty(&mut file, value)?;
    writeln!(&mut file)?;
    file.sync_all()?;
    Ok(())
}

fn cancellation() -> Result<CancellationToken> {
    let cancel = CancellationToken::new();
    let token = cancel.clone();
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::spawn(async move {
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
            token.cancel();
        });
    }
    #[cfg(not(unix))]
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        token.cancel();
    });
    Ok(cancel)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cli = Cli::parse();
    let registry = if let Some(path) = &cli.catalog {
        Registry::read(path)?
    } else {
        Registry::bundled()?
    };
    match cli.command {
        Command::Vectors {
            command: VectorCommand::Coverage,
        } => print_json(&registry.coverage())?,
        Command::Vectors {
            command:
                VectorCommand::List {
                    category,
                    layer,
                    json,
                },
        } => {
            let entries: Vec<_> = registry
                .list()
                .filter(|v| {
                    category
                        .as_ref()
                        .is_none_or(|c| v.category.eq_ignore_ascii_case(c))
                        && layer
                            .as_ref()
                            .is_none_or(|l| v.layer.eq_ignore_ascii_case(l))
                })
                .collect();
            if json {
                print_json(&entries)?;
            } else {
                println!(
                    "{:<12} {:<4} {:<8} {:<17} {:<14} NAME",
                    "ID", "OSI", "FAMILY", "MODE", "BACKEND"
                );
                for v in entries {
                    println!(
                        "{:<12} {:<4} {:<8} {:<17} {:<14} {}",
                        v.id,
                        v.layer,
                        v.category,
                        serde_json::to_value(v.mode)?.as_str().unwrap_or("?"),
                        serde_json::to_value(v.backend)?.as_str().unwrap_or("?"),
                        v.name
                    );
                }
            }
        }
        Command::Vectors {
            command: VectorCommand::Info { id },
        } => print_json(registry.get(&id)?)?,
        Command::Validate { config } => {
            let config = Config::read(&config)?;
            engine::validate(&config, &registry)?;
            print_json(
                &serde_json::json!({"valid":true,"mode":config.mode,"vectors":config.vectors}),
            )?;
        }
        Command::Run { config, output } => {
            let config = Config::read(&config)?;
            engine::validate(&config, &registry)?;
            let file = reserve_output(&output)?;
            let report = engine::run(config, registry, cancellation()?).await?;
            write_json(file, &report)?;
            print_json(
                &serde_json::json!({"report":output,"termination_reason":report.termination_reason,"metrics":report.metrics}),
            )?;
        }
        Command::Report { input, format: _ } => {
            let report: Report = serde_json::from_slice(&std::fs::read(input)?)?;
            print_json(&report)?;
        }
        Command::Demo { directory } => demo(&directory)?,
        Command::Profiles {
            command: ProfileCommand::List,
        } => print_json(&external_agent::profiles::list()?)?,
        Command::Profiles {
            command: ProfileCommand::Create { preset, directory },
        } => print_json(&external_agent::profiles::create(&preset, &directory)?)?,
        Command::Fixture { output } => lab::write_fixture_pcap(&output)?,
        Command::MeasurementKeygen { key_file } => println!("{}", measurement::keygen(&key_file)?),
        #[cfg(feature = "experimental-receiver")]
        Command::Receiver {
            bind,
            allow_peer,
            run_id,
            key_file,
            expected_probes,
            duration,
            output,
        } => {
            let file = reserve_output(&output)?;
            let report = measurement::receive(
                measurement::ReceiverConfig {
                    bind,
                    allowed_peer: allow_peer,
                    run_id,
                    key_file,
                    expected_probes,
                    duration_seconds: duration,
                },
                cancellation()?,
            )
            .await?;
            write_json(file, &report)?;
            print_json(&report)?;
        }
        #[cfg(feature = "experimental-receiver")]
        Command::Compare {
            sender,
            receiver,
            key_file,
        } => {
            let sender = serde_json::from_slice(&std::fs::read(sender)?)?;
            let receiver = serde_json::from_slice(&std::fs::read(receiver)?)?;
            print_json(&measurement::compare(
                &sender,
                &receiver,
                &measurement::read_key(&key_file)?,
            )?)?;
        }
    }
    Ok(())
}

fn demo(directory: &Path) -> Result<()> {
    ensure!(!directory.exists(), "demo directory must be new");
    std::fs::create_dir_all(directory)?;
    let directory = directory.canonicalize()?;
    let run_id = measurement::keygen(&directory.join("measurement.key"))?;
    let target = |port| Target {
        ip: "127.0.0.1".parse().expect("loopback"),
        port,
        server_name: None,
    };
    let limits = Limits {
        duration_seconds: 150,
        probes_per_second: 10,
        concurrency: 8,
        bandwidth_bytes_per_second: 65536,
        max_probes: 1000,
        timeout_ms: 500,
    };
    for (name, vector, port) in [
        ("delivery", "UDP-010", 9000),
        ("tcp", "TCP-001", 9001),
        ("http", "HTTP-001", 9002),
        ("udp", "UDP-001", 9000),
    ] {
        let mut config = Config {
            protocol: Default::default(),
            vectors: vec![vector.into()],
            mode: Mode::LiveValidation,
            target: Some(target(port)),
            limits: limits.clone(),
            kill_switch: directory.join("STOP"),
            controller_lease: None,
            measurement: (vector == "UDP-010").then(|| measurement::MeasurementConfig {
                run_id: run_id.clone(),
                key_file: directory.join("measurement.key"),
                await_ack: false,
            }),
            health: Health::default(),
        };
        if vector != "UDP-010" {
            config.limits.max_probes = 5;
            config.limits.duration_seconds = 10;
        }
        let mut file = reserve_output(&directory.join(format!("{name}.yaml")))?;
        file.write_all(serde_yaml::to_string(&config)?.as_bytes())?;
    }
    print_json(&serde_json::json!({"directory":directory,"run_id":run_id,
        "note":"sender-only loopback examples; UDP delivery is not inferred from local send acceptance"}))
}
