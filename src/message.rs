use alloy_rlp::{RlpDecodable, RlpEncodable};
use secp256k1::constants::UNCOMPRESSED_PUBLIC_KEY_SIZE;

/// Cryptographic nonce.
type Nonce = [u8; 32];

/// Uncompressed 512-bit public key.
pub type PublicKey = [u8; UNCOMPRESSED_PUBLIC_KEY_SIZE - 1];

/// Message signature with trailing recovery id.
pub type Signature = [u8; UNCOMPRESSED_PUBLIC_KEY_SIZE];

/// RLPx auth handshake message.
#[derive(Debug, RlpDecodable, RlpEncodable)]
pub(crate) struct AuthMessage {
    pub sig: Signature,
    pub initiator_pubk: PublicKey,
    pub initiator_nonce: Nonce,
    pub auth_vsn: u32, // must be 4
}

impl AuthMessage {
    /// Create a new AuthBodyMessage instance.
    pub fn new(sig: Signature, initiator_pubk: PublicKey, initiator_nonce: Nonce) -> Self {
        Self {
            sig,
            initiator_pubk,
            initiator_nonce,
            auth_vsn: 4,
        }
    }
}

/// RLPx ack handshake message.
#[derive(Debug, RlpDecodable, RlpEncodable)]
pub(crate) struct AckMessage {
    pub recipient_ephemeral_pubk: PublicKey,
    pub recipient_nonce: Nonce,
    pub ack_vsn: u32, // must be 4
}

/// RLPx hello handshake message.
#[derive(Debug, RlpDecodable, RlpEncodable)]
pub struct HelloMessage {
    pub protocol_version: u32, // must be 5
    pub client_id: String,
    pub capabilities: Vec<HelloCapability>,
    pub listen_port: u16, // deprecated
    pub node_id: PublicKey,
}

impl HelloMessage {
    /// Create a new HelloMessage instance.
    pub fn new(client_id: String, eth_version: u32, node_id: PublicKey) -> Self {
        Self {
            protocol_version: 5,
            client_id,
            capabilities: vec![HelloCapability {
                cap: "eth".to_owned(),
                cap_version: eth_version,
            }],
            listen_port: 0,
            node_id,
        }
    }
}

/// P2P connection capability.
#[derive(Debug, RlpDecodable, RlpEncodable)]
pub(crate) struct HelloCapability {
    pub cap: String, // not longer than 8 characters
    pub cap_version: u32,
}
