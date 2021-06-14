use std::net::{IpAddr, Ipv4Addr};

use anyhow::Result;
use clap::Clap;
use ed25519_dalek::Signer;
use rand::RngCore;
use ton_api::{ton, IntoBoxed};

#[derive(Clone, Debug, Clap)]
pub struct Arguments {
    #[clap(short, long)]
    pub address: Option<Ipv4Addr>,

    #[clap(short, long)]
    pub port: u16,

    #[clap(short, long)]
    pub key: Option<String>,

    #[clap(long)]
    pub yaml: bool,
}

fn main() {
    let args: Arguments = Arguments::parse();

    if let Err(e) = run(args) {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}

fn run(args: Arguments) -> Result<()> {
    let address = match parse_address(args.address) {
        Ok(address) => address,
        Err(_) => return Err(GenDhtError::FailedToGetAddress.into()),
    };

    let key = match parse_key(args.key.as_deref()) {
        Ok(key) => key,
        Err(_) => return Err(GenDhtError::InvalidKey.into()),
    };

    let dht_node = {
        let node = make_dht_node(address, args.port, key)?;
        serde_json::json!({
            "@type": "dht.node",
            "id": {
                "@type": "pub.ed25519",
                "key": base64::encode(&node.id.key().unwrap().0)
            },
            "addr_list": {
                "@type": "adnl.addressList",
                "addrs": [
                    {
                        "@type": "adnl.address.udp",
                        "ip": convert_address(address),
                        "port": args.port
                    }
                ],
                "version": node.addr_list.version,
                "reinit_date": node.addr_list.reinit_date,
                "priority": node.addr_list.priority,
                "expire_at": node.addr_list.expire_at
            },
            "version": node.version,
            "signature": base64::encode(&node.signature.0)
        })
    };

    let output = if args.yaml {
        serde_yaml::to_string(&dht_node).unwrap()
    } else {
        serde_json::to_string_pretty(&dht_node).unwrap()
    };
    println!("{}", output);

    Ok(())
}

fn make_dht_node(
    address: Ipv4Addr,
    port: u16,
    key: ed25519_dalek::SecretKey,
) -> Result<ton::dht::node::Node> {
    let public_key = ed25519_dalek::PublicKey::from(&key);

    let mut dht_node = ton::dht::node::Node {
        id: ton::pub_::publickey::Ed25519 {
            key: ton::int256(public_key.to_bytes()),
        }
        .into_boxed(),
        addr_list: ton::adnl::addresslist::AddressList {
            addrs: vec![ton::adnl::address::address::Udp {
                ip: convert_address(address),
                port: port as ton::int,
            }
            .into_boxed()]
            .into(),
            ..Default::default()
        },
        version: -1,
        ..Default::default()
    };

    let data = {
        let mut data = Vec::new();
        ton_api::Serializer::new(&mut data)
            .write_boxed(&dht_node.clone().into_boxed())
            .map_err(|_| GenDhtError::FailedToSignData)?;
        data
    };

    let key_pair = ed25519_dalek::Keypair {
        secret: key,
        public: public_key,
    };
    let signature = key_pair.sign(&data);

    dht_node.signature = ton::bytes(signature.to_bytes().to_vec());

    Ok(dht_node)
}

fn parse_address(address: Option<Ipv4Addr>) -> Result<Ipv4Addr> {
    if let Some(address) = address {
        return Ok(address);
    }

    let runtime = tokio::runtime::Runtime::new()?;

    let ip = std::thread::spawn(move || {
        runtime
            .block_on(
                external_ip::ConsensusBuilder::new()
                    .add_sources(external_ip::get_http_sources::<external_ip::Sources>())
                    .build()
                    .get_consensus(),
            )
            .unwrap()
    })
    .join()
    .unwrap();

    match ip {
        IpAddr::V4(addr) => Ok(addr),
        _ => Err(GenDhtError::FailedToGetAddress.into()),
    }
}

fn parse_key(key: Option<&str>) -> Result<ed25519_dalek::SecretKey> {
    let bytes = match key {
        Some(key) if key.len() == 64 => hex::decode(&key)?,
        Some(key) if key.len() == 44 => base64::decode(&key)?,
        Some(_) => return Err(GenDhtError::InvalidKey.into()),
        None => {
            let mut bytes = vec![0; 32];
            rand::thread_rng().fill_bytes(&mut bytes);
            bytes
        }
    };
    let key = ed25519_dalek::SecretKey::from_bytes(&bytes)?;
    Ok(key)
}

fn convert_address(address: Ipv4Addr) -> i32 {
    let [a, b, c, d] = address.octets();
    ((a as u32) << 24 | (b as u32) << 16 | (c as u32) << 8 | (d as u32)) as i32
}

#[derive(thiserror::Error, Debug)]
enum GenDhtError {
    #[error("Failed to get address")]
    FailedToGetAddress,
    #[error("Invalid key")]
    InvalidKey,
    #[error("Failed to sign data")]
    FailedToSignData,
}
