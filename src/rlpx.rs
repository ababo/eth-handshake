use crate::message::{AckMessage, AuthMessage, HelloMessage};
use aes::{
    cipher::{BlockEncrypt, KeyIvInit, StreamCipher},
    Aes128, Aes256, Aes256Enc,
};
use alloy_rlp::{BytesMut, Decodable, Encodable, Error as RlpError};
use cipher::block_padding::NoPadding;
use concat_kdf::derive_key_into;
use ctr::Ctr64BE;
use hmac::{Hmac, Mac as HmacMac};
use primitive_types::U256;
use rand::Rng;
use secp256k1::{
    constants::UNCOMPRESSED_PUBLIC_KEY_SIZE, ecdh::shared_secret_point, Message, PublicKey,
    Secp256k1, SecretKey, Signing,
};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// RLPx operation error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("disconnected")]
    Disconnected,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed message ({0})")]
    MalformedMessage(String),
    #[error("rlp error: {0}")]
    Rlp(#[from] RlpError),
    #[error("secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),
}

/// RLPx operation result.
pub type Result<T> = std::result::Result<T, Error>;

/// Asynchronous RLPx transport.
pub trait Transport: AsyncReadExt + AsyncWriteExt + Unpin {}

/// TODO: Consider redefining via trait alias when stabilized.
impl<T: AsyncReadExt + AsyncWriteExt + Unpin> Transport for T {}

type EncKey = [u8; 16];
type Hash128 = [u8; 16];
type Hash256 = [u8; 32];
type Iv = [u8; 16];
type Mac = [u8; 32];
type Nonce = [u8; 32];
type SharedSecret = [u8; 32];
type Tag = [u8; 32];

trait Length {
    const LEN: usize;
}

impl<T, const LENGTH: usize> Length for [T; LENGTH] {
    const LEN: usize = LENGTH;
}

const MSG_ID_HELLO: u32 = 0x0;
const MSG_ID_DISCONNECT: u32 = 0x1;

const ECIES_WRAPPER_LEN: usize = UNCOMPRESSED_PUBLIC_KEY_SIZE + Iv::LEN + Tag::LEN;

const ETH_VERSION: u32 = 68;

const HEADER_DATA: [u8; 3] = [0xc2, 0x80, 0x80];

const SECP256K1_UNCOMPRESSED: u8 = 0x4;

/// RLPx connection for Ethereum node p2p communication.
pub struct RlpxConnection<T: Transport> {
    transport: T,
    aes_in: Ctr64BE<Aes256>,
    aes_out: Ctr64BE<Aes256>,
    mac_secret: Hash256,
    mac_in: Keccak256,
    mac_out: Keccak256,
}

impl<T: Transport> RlpxConnection<T> {
    /// Initiate handshake with a recipient party.
    pub async fn initiate_handshake<R: Rng, S: Signing>(
        mut rng: R,
        secp: Secp256k1<S>,
        mut transport: T,
        private_key: SecretKey,
        remote_public_key: PublicKey,
    ) -> Result<(Self, HelloMessage)> {
        let nonce: Nonce = rng.gen();

        let auth = Self::create_auth(&mut rng, &secp, &nonce, &private_key, &remote_public_key);
        let encrypted_auth = Self::encrypt(&mut rng, &secp, &remote_public_key, &auth);
        transport.write_u16(encrypted_auth.len() as u16).await?;
        transport.write_all(&encrypted_auth).await?;

        let encrypted_ack_len = transport.read_u16().await?;
        let mut encrypted_ack = vec![0; encrypted_ack_len as usize];
        transport.read_exact(&mut encrypted_ack).await?;
        let ack = Self::decrypt(&private_key, &encrypted_ack).unwrap();
        let (remote_ephemeral_public_key, remote_nonce) = Self::parse_ack(&ack)?;
        let ephemeral_shared_secret =
            Self::create_shared_secret(&remote_ephemeral_public_key, &private_key);

        let mut conn = Self::setup_framing(
            true,
            transport,
            nonce,
            remote_nonce,
            ephemeral_shared_secret,
            (encrypted_ack, encrypted_auth),
        );

        let public_key = private_key.public_key(&secp).serialize_uncompressed();
        let public_key_512 = (&public_key[1..]).try_into().unwrap();
        conn.send_hello(HelloMessage::new(
            "handshake-test".to_owned(),
            ETH_VERSION,
            public_key_512,
        ))
        .await?;

        let (msg_id, data) = conn.read_frame().await?;

        match msg_id {
            MSG_ID_DISCONNECT => Err(Error::Disconnected),
            MSG_ID_HELLO => {
                let mut data_view = data.as_ref();
                let hello_msg = HelloMessage::decode(&mut data_view)?;
                Ok((conn, hello_msg))
            }
            _ => Err(Error::MalformedMessage(format!(
                "unexpected msg id {msg_id}"
            ))),
        }
    }

    fn create_auth<R: Rng, S: Signing>(
        rng: &mut R,
        secp: &Secp256k1<S>,
        nonce: &Nonce,
        private_key: &SecretKey,
        remote_public_key: &PublicKey,
    ) -> Vec<u8> {
        let shared_secret = Self::create_shared_secret(remote_public_key, private_key);
        let sig_digest = U256::from(nonce) ^ U256::from(shared_secret);
        let sig_digest_msg = Message::from_digest(sig_digest.into());
        let (recovery_id, signature) = secp
            .sign_ecdsa_recoverable(&sig_digest_msg, private_key)
            .serialize_compact();
        let mut sig = [0u8; 65];
        sig[..64].copy_from_slice(&signature);
        sig[64] = recovery_id.to_i32() as u8;

        let public_key = private_key.public_key(secp).serialize_uncompressed();
        let public_key_512 = (&public_key[1..]).try_into().unwrap();
        let mut rlp_buffer = BytesMut::new();
        AuthMessage::new(sig, public_key_512, *nonce).encode(&mut rlp_buffer);

        // At least 100 bytes pf padding to distinguish from pre-EIP-8 handshakes.
        let padding_len: usize = rng.gen_range(100..200);
        let mut auth_body = vec![0; rlp_buffer.len() + padding_len];
        auth_body[..rlp_buffer.len()].copy_from_slice(&rlp_buffer);

        auth_body
    }

    fn create_shared_secret(
        remote_public_key: &PublicKey,
        private_key: &SecretKey,
    ) -> SharedSecret {
        (&shared_secret_point(remote_public_key, private_key)[..32])
            .try_into()
            .unwrap()
    }

    fn encrypt<R: Rng, S: Signing>(
        rng: &mut R,
        secp: &Secp256k1<S>,
        remote_public_key: &PublicKey,
        data: &[u8],
    ) -> Vec<u8> {
        const OVERHEAD: usize = UNCOMPRESSED_PUBLIC_KEY_SIZE + 16 /* IV */ + 32 /* MAC */;
        let wrapped_encrypted_len = data.len() + OVERHEAD;

        let mut wrapped_encrypted_data = Vec::with_capacity(wrapped_encrypted_len);

        let ephemeral_private_key = SecretKey::new(&mut *rng);
        let ephemeral_public_key = ephemeral_private_key
            .public_key(secp)
            .serialize_uncompressed();
        wrapped_encrypted_data.extend_from_slice(&ephemeral_public_key[..]);

        let iv: Iv = rng.gen();
        wrapped_encrypted_data.extend_from_slice(iv.as_slice());

        wrapped_encrypted_data.extend_from_slice(data);

        let (enc_key, mac) = Self::derive_enc_key_mac(&ephemeral_private_key, remote_public_key);

        let encrypted_data = &mut wrapped_encrypted_data[UNCOMPRESSED_PUBLIC_KEY_SIZE + iv.len()..];

        let mut encryptor = Ctr64BE::<Aes128>::new(&enc_key.into(), &iv.into());
        encryptor.apply_keystream(encrypted_data);

        let tag = Self::derive_tag(&iv, &mac, encrypted_data);
        wrapped_encrypted_data.extend_from_slice(tag.as_ref());

        wrapped_encrypted_data
    }

    fn derive_enc_key_mac(private_key: &SecretKey, remote_public_key: &PublicKey) -> (EncKey, Mac) {
        let mut key = [0u8; 32];
        let shared_secret = Self::create_shared_secret(remote_public_key, private_key);
        derive_key_into::<Sha256>(&shared_secret, &[], &mut key).unwrap();
        let enc_key = &key[..16];
        let mac = Sha256::digest(&key[16..]);
        (enc_key.try_into().unwrap(), *mac.as_ref())
    }

    fn derive_tag(iv: &Iv, mac: &Mac, msg: &[u8]) -> Tag {
        let mut hmac = Hmac::<Sha256>::new_from_slice(mac).unwrap();
        hmac.update(iv.as_slice());
        hmac.update(msg);
        hmac.update(&((msg.len() + ECIES_WRAPPER_LEN) as u16).to_be_bytes());
        hmac.finalize().into_bytes().into()
    }

    fn decrypt(private_key: &SecretKey, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < UNCOMPRESSED_PUBLIC_KEY_SIZE {
            return Err(Error::MalformedMessage(
                "not enough space for public key in ack".to_owned(),
            ));
        }

        let (ephemeral_public_key_bytes, iv_msg_tag) = data.split_at(UNCOMPRESSED_PUBLIC_KEY_SIZE);
        let ephemeral_public_key = PublicKey::from_slice(ephemeral_public_key_bytes)?;

        let Some(tag_index) = iv_msg_tag.len().checked_sub(Tag::LEN) else {
            return Err(Error::MalformedMessage(
                "not enough space for tag in ack".to_owned(),
            ));
        };

        let (iv_msg, tag) = iv_msg_tag.split_at(tag_index);
        if iv_msg.len() < Iv::LEN {
            return Err(Error::MalformedMessage(
                "not enough space for iv in ack".to_owned(),
            ));
        }

        let (iv, msg) = iv_msg.split_at(Iv::LEN);

        let (enc_key, mac) = Self::derive_enc_key_mac(private_key, &ephemeral_public_key);

        let derived_tag = Self::derive_tag(&iv.try_into().unwrap(), &mac, msg);
        if derived_tag != tag {
            return Err(Error::MalformedMessage("bad ack tag".to_owned()));
        }

        let mut decrypted_msg = msg.to_vec();
        let mut decryptor = Ctr64BE::<Aes128>::new((&enc_key).into(), iv.into());
        decryptor.apply_keystream(&mut decrypted_msg);
        Ok(decrypted_msg)
    }

    fn parse_ack(data: &[u8]) -> Result<(PublicKey, Nonce)> {
        let mut data_view = data;
        let ack = AckMessage::decode(&mut data_view)?;

        let mut remote_ephemeral_public_key_bytes = [0u8; UNCOMPRESSED_PUBLIC_KEY_SIZE];
        remote_ephemeral_public_key_bytes[0] = SECP256K1_UNCOMPRESSED;
        remote_ephemeral_public_key_bytes[1..].copy_from_slice(&ack.recipient_ephemeral_pubk);
        let remote_ephemeral_public_key =
            PublicKey::from_slice(&remote_ephemeral_public_key_bytes)?;

        Ok((remote_ephemeral_public_key, ack.recipient_nonce))
    }

    fn setup_framing(
        for_initiator: bool,
        transport: T,
        nonce: Nonce,
        remote_nonce: Nonce,
        ephemeral_shared_secret: SharedSecret,
        in_out_init_msgs: (Vec<u8>, Vec<u8>),
    ) -> Self {
        let mut hash = Keccak256::new();
        if for_initiator {
            hash.update(remote_nonce);
            hash.update(nonce);
        } else {
            hash.update(nonce);
            hash.update(remote_nonce);
        }
        let hash_nonce = hash.finalize();

        let mut hash = Keccak256::new();
        hash.update(ephemeral_shared_secret);
        hash.update(hash_nonce);
        let shared_secret = hash.finalize();

        let mut hash = Keccak256::new();
        hash.update(ephemeral_shared_secret);
        hash.update(shared_secret);
        let aes_secret = hash.finalize();

        let iv = Iv::default();
        let aes_in = Ctr64BE::<Aes256>::new(&aes_secret, &iv.into());
        let aes_out = Ctr64BE::<Aes256>::new(&aes_secret, &iv.into());

        let mut hash = Keccak256::new();
        hash.update(ephemeral_shared_secret);
        hash.update(aes_secret);
        let mac_secret: Hash256 = hash.finalize().into();

        let mut mac_in = Keccak256::new();
        let input: Hash256 = (U256::from(&mac_secret) ^ U256::from(&nonce)).into();
        mac_in.update(input);
        mac_in.update((in_out_init_msgs.0.len() as u16).to_be_bytes());
        mac_in.update(&in_out_init_msgs.0);

        let mut mac_out = Keccak256::new();
        let input: Hash256 = (U256::from(&mac_secret) ^ U256::from(&remote_nonce)).into();
        mac_out.update(input);
        mac_out.update((in_out_init_msgs.1.len() as u16).to_be_bytes());
        mac_out.update(&in_out_init_msgs.1);

        Self {
            transport,
            aes_in,
            aes_out,
            mac_secret,
            mac_in,
            mac_out,
        }
    }

    async fn send_hello(&mut self, message: HelloMessage) -> Result<()> {
        let mut rlp_buffer = BytesMut::new();
        message.encode(&mut rlp_buffer);
        self.write_frame(MSG_ID_HELLO, &rlp_buffer).await
    }

    async fn write_frame(&mut self, msg_id: u32, msg_data: &[u8]) -> Result<()> {
        let mut frame_data = BytesMut::new();
        msg_id.encode(&mut frame_data);
        frame_data.extend_from_slice(msg_data);

        let mut header = BytesMut::new();
        header.extend_from_slice(&(frame_data.len() as u64).to_be_bytes()[5..]);
        header.extend_from_slice(&HEADER_DATA);
        header.resize(align(header.len(), 16), 0);

        self.aes_out.apply_keystream(&mut header);
        mac_apply_header(&self.mac_secret, &mut self.mac_out, &header);
        let tag = mac_read(&self.mac_out);

        self.transport.write_all(&header).await?;
        self.transport.write_all(tag.as_slice()).await?;

        frame_data.resize(align(frame_data.len(), 16), 0);
        self.aes_out.apply_keystream(&mut frame_data);
        mac_apply_data(&self.mac_secret, &mut self.mac_out, &frame_data);
        let tag = mac_read(&self.mac_out);

        self.transport.write_all(&frame_data).await?;
        self.transport.write_all(tag.as_slice()).await?;

        Ok(())
    }

    async fn read_frame(&mut self) -> Result<(u32, Vec<u8>)> {
        let mut buffer = [0; 16];
        self.transport.read_exact(&mut buffer).await?;

        mac_apply_header(&self.mac_secret, &mut self.mac_in, &buffer);
        let mac = mac_read(&self.mac_in);

        self.aes_in.apply_keystream(&mut buffer);
        let len = ((buffer[0] as usize) << 16) | ((buffer[1] as usize) << 8) | buffer[2] as usize;

        self.transport.read_exact(&mut buffer).await?;
        if mac != buffer {
            return Err(Error::MalformedMessage("bad header mac".to_owned()));
        }

        let mut frame_data = vec![0; align(len, 16)];
        self.transport.read_exact(&mut frame_data).await?;

        mac_apply_data(&self.mac_secret, &mut self.mac_in, &frame_data);
        let mac = mac_read(&self.mac_in);

        self.aes_in.apply_keystream(&mut frame_data);
        frame_data.resize(len, 0);

        let mut frame_data_view = frame_data.as_ref();
        let msg_id = u32::decode(&mut frame_data_view)?;

        self.transport.read_exact(&mut buffer).await?;
        if mac != buffer {
            return Err(Error::MalformedMessage("bad frame mac".to_owned()));
        }

        Ok((msg_id, frame_data_view.to_vec()))
    }
}

#[inline]
fn align(size: usize, to: usize) -> usize {
    ((size - 1) / to + 1) * to
}

fn mac_apply_header(secret: &Hash256, hash: &mut Keccak256, header: &[u8]) {
    use aes::cipher::KeyInit;

    let mut mac = mac_read(hash);

    let aes = Aes256Enc::new_from_slice(secret).unwrap();
    aes.encrypt_padded::<NoPadding>(&mut mac, Hash128::LEN)
        .unwrap();

    for i in 0..header.len() {
        mac[i] ^= header[i];
    }

    hash.update(mac);
}

fn mac_apply_data(secret: &Hash256, hash: &mut Keccak256, data: &[u8]) {
    use aes::cipher::KeyInit;

    hash.update(data);

    let mut mac = mac_read(hash);
    let prev_mac = mac;

    let aes = Aes256Enc::new_from_slice(secret).unwrap();
    aes.encrypt_padded::<NoPadding>(&mut mac, Hash128::LEN)
        .unwrap();
    for i in 0..16 {
        mac[i] ^= prev_mac[i];
    }

    hash.update(mac);
}

fn mac_read(hash: &Keccak256) -> Hash128 {
    let mac: Hash128 = (&hash.clone().finalize()[..Hash128::LEN])
        .try_into()
        .unwrap();
    mac
}
