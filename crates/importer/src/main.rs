//! `weebo-stalwart-importer`: links existing Stalwart objects to the CRs
//! describing them (see the crate's documentation).

use std::io::Read;
use std::path::PathBuf;

use adapters_outbound::gateway_factory::http_client;
use adapters_outbound::{JmapClient, JmapGateway, KubeClusterReader};
use anyhow::Context;
use api::common::TlsOptions;
use application::ports::ClusterReader;
use clap::Parser;
use importer::{apply_all, parse, plan, rotation_nonce, to_yaml};
use kube::Client;

#[derive(Parser, Debug)]
#[command(
    name = "weebo-stalwart-importer",
    version,
    about = "Link existing Stalwart objects (domains, accounts, groups, lists) to the weebo-stalwart CRs describing them"
)]
struct Args {
    /// Stalwart base URL (same form as `StalwartInstance.spec.url`).
    #[arg(long, env = "STALWART_URL")]
    url: String,
    /// An API key reading domains, accounts and lists (the operator's).
    #[arg(long, env = "STALWART_TOKEN", hide_env_values = true)]
    token: String,
    /// The CRs to link, as YAML (repeatable; `-` reads stdin).
    #[arg(long = "file", short = 'f', required = true)]
    files: Vec<PathBuf>,
    /// Namespace of the namespaced CRs that name none.
    #[arg(long, short, default_value = "default")]
    namespace: String,
    /// Apply the CRs in the current kube context and seed their status,
    /// instead of printing them.
    #[arg(long)]
    apply: bool,
    /// With `--apply`: also take over CRs that exist but own nothing yet
    /// (`StalwartObjectAlreadyExists`) — make sure their operator is not
    /// creating the object at the same time.
    #[arg(long, requires = "apply")]
    force: bool,
    /// PEM bundle trusted on top of the system roots (a Stalwart behind a
    /// private CA).
    #[arg(long, env = "STALWART_CA_FILE")]
    ca_file: Option<PathBuf>,
    /// Skip TLS verification (testing only).
    #[arg(long)]
    insecure_skip_verify: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Two providers are linked (ring, aws-lc-rs): pick one. `Err`: already
    // installed, which is as good.
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        eprintln!("note: a rustls crypto provider was already installed");
    }
    let args = Args::parse();

    let mut yaml = String::new();
    for file in &args.files {
        if file.as_os_str() == "-" {
            std::io::stdin().read_to_string(&mut yaml)?;
        } else {
            yaml.push_str(
                &std::fs::read_to_string(file)
                    .with_context(|| format!("reading {}", file.display()))?,
            );
        }
        yaml.push_str("\n---\n");
    }
    let crs = parse(&yaml, &args.namespace)?;

    let ca = match &args.ca_file {
        Some(path) => {
            Some(std::fs::read(path).with_context(|| format!("reading {}", path.display()))?)
        }
        None => None,
    };
    if args.insecure_skip_verify {
        eprintln!("warning: TLS verification disabled");
    }
    let tls = TlsOptions {
        insecure_skip_verify: args.insecure_skip_verify,
        ..Default::default()
    };
    let http = http_client(&tls, ca.as_deref()).map_err(|e| anyhow::anyhow!(e))?;
    let client = JmapClient::new(&args.url, args.token.trim(), http)?;
    let gateway = JmapGateway::new(client);

    // The cluster: to read the `StalwartDomain`s already linked (and, with
    // `--apply`, to write). Without `--apply`, an unreachable one only
    // limits the input to domains it carries.
    let kube = match Client::try_default().await {
        Ok(kube) => Some(kube),
        Err(e) if !args.apply => {
            eprintln!("warning: no cluster ({e}): StalwartDomains must be in the input");
            None
        }
        Err(e) => return Err(e).context("connecting to Kubernetes"),
    };
    let reader = kube.clone().map(KubeClusterReader::new);
    let cluster = reader.as_ref().map(|r| r as &dyn ClusterReader);
    let (planned, refused) = plan(crs, &gateway, cluster, &rotation_nonce()).await;
    for r in &refused {
        eprintln!("error: {}: {}", r.cr, r.why);
    }

    match (args.apply, kube) {
        (true, Some(kube)) => {
            let summary = apply_all(&kube, &planned, args.force).await;
            eprintln!(
                "{} linked, {} already linked, {} failed",
                summary.adopted,
                summary.skipped,
                summary.failed + refused.len()
            );
            anyhow::ensure!(
                summary.failed == 0 && refused.is_empty(),
                "{} CR(s) could not be linked",
                summary.failed + refused.len()
            );
        }
        _ => {
            print!("{}", to_yaml(&planned)?);
            anyhow::ensure!(
                refused.is_empty(),
                "{} CR(s) could not be linked",
                refused.len()
            );
        }
    }
    Ok(())
}
