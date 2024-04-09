mod message;
mod rlpx;

use anyhow::{bail, Context, Result};
use clap::Parser;
use rand::thread_rng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::str::FromStr;
use tokio::net::TcpStream;
use url::Url;

// Run `cargo run -- --enode-url enode://6f20afbe4397e51b717a7c1ad3095e79aee48c835eebd9237a3e8a16951ade1fe0e66e981e30ea269849fcb6ba03d838da37f524fabd2a557474194a2e2604fa@18.221.100.27:31002`

#[derive(Parser, Debug)]
#[command(long_about = None)]
struct Args {
    #[arg(long)]
    enode_url: Url,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if args.enode_url.scheme() != "enode" {
        bail!("enode scheme only supported");
    }

    let Some(host) = args.enode_url.host() else {
        bail!("no host in enode url");
    };

    // gives false positives (due to a bug?)
    // if let Host::Domain(d) = host {
    //     bail!("domain in enode url");
    // };

    let Some(port) = args.enode_url.port() else {
        bail!("no port in enode url");
    };

    let recipient_public_key_str = format!("04{}", args.enode_url.username());
    let recipient_public_key =
        PublicKey::from_str(&recipient_public_key_str).context("malformed node id")?;

    let transport = TcpStream::connect(&format!("{host}:{port}")).await?;

    let mut rng = thread_rng();
    let secp = Secp256k1::new();
    let private_key = SecretKey::new(&mut rng);

    let (_conn, hello) = rlpx::RlpxConnection::initiate_handshake(
        rng,
        secp,
        transport,
        private_key,
        recipient_public_key,
    )
    .await
    .context("enode handshake failed")?;

    println!("performed handshake with '{}'", hello.client_id);

    Ok(())
}
