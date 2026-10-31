//! Local YAML presets. Creating a preset never opens network sockets.
use crate::{config::Config, measurement};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path};

#[derive(Deserialize)]
struct Bundle {
    schema_version: u32,
    presets: BTreeMap<String, Vec<String>>,
    configs: BTreeMap<String, Config>,
}

fn bundle() -> Result<Bundle> {
    let bundle: Bundle = serde_json::from_str(include_str!("../vectors/profiles/bundle.json"))?;
    ensure!(
        bundle.schema_version == 1,
        "unsupported profile bundle schema"
    );
    Ok(bundle)
}

pub fn list() -> Result<BTreeMap<String, Vec<String>>> {
    Ok(bundle()?.presets)
}

#[derive(Serialize)]
pub struct Created {
    pub preset: String,
    pub directory: std::path::PathBuf,
    pub configs: Vec<String>,
    pub note: &'static str,
}

pub fn create(preset: &str, directory: &Path) -> Result<Created> {
    let bundle = bundle()?;
    let ids = bundle
        .presets
        .get(preset)
        .context("unknown preset; use profiles list")?;
    ensure!(!directory.exists(), "profile directory must be new");
    if let Some(parent) = directory.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::create_dir(directory)?;
    let run_id = if ids.iter().any(|id| id == "UDP-010") {
        Some(measurement::keygen(&directory.join("measurement.key"))?)
    } else {
        None
    };
    let mut copied_ca = false;
    for id in ids {
        let mut config = bundle
            .configs
            .get(id)
            .context("profile references a missing case")?
            .clone();
        if let Some(measurement) = &mut config.measurement {
            measurement.run_id = run_id.as_ref().context("measurement key missing")?.clone();
        }
        if let Some(ca) = &mut config.protocol.tls_ca {
            if !copied_ca {
                std::fs::write(
                    directory.join("ca.der"),
                    include_bytes!("../tests/fixtures/tls/ca.der"),
                )?;
                copied_ca = true;
            }
            ca.file = "ca.der".into();
        }
        std::fs::write(
            directory.join(format!("{id}.yaml")),
            serde_yaml::to_string(&config)?,
        )?;
    }
    let created = Created {
        preset: preset.into(), directory: directory.canonicalize()?,
        configs: ids.iter().map(|id| format!("{id}.yaml")).collect(),
        note: "Loopback examples; one case per YAML. Network cases need matching services. Raw cases require Linux/CAP_NET_RAW. No traffic was sent.",
    };
    std::fs::write(
        directory.join("index.json"),
        serde_json::to_vec_pretty(&created)?,
    )?;
    Ok(created)
}
