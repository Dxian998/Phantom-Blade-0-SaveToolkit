use aes_gcm::aead::{Aead, Generate, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{bail, Context, Result};

pub const MAGIC: &[u8; 4] = b"PBZS";

// Static Master Tables from PBZ.exe (.rdata at 0x14C1C8748 and 0x14C1C8728)
pub const TABLE_A: [u8; 32] = [
    0xf9, 0x29, 0x5b, 0x79, 0x5f, 0x2d, 0x10, 0x12,
    0xbe, 0xa5, 0x64, 0xd9, 0xf9, 0x84, 0x94, 0x43,
    0xac, 0xf0, 0x7e, 0x18, 0xda, 0x4c, 0x34, 0xf0,
    0xe6, 0x99, 0x9f, 0x26, 0xe0, 0xd1, 0x42, 0x56,
];

pub const TABLE_B: [u8; 32] = [
    0xec, 0x88, 0xa5, 0x76, 0x0a, 0xcd, 0xfb, 0x3b,
    0x30, 0xd9, 0xf0, 0xb8, 0xad, 0x07, 0xc5, 0x2a,
    0xc6, 0xda, 0x79, 0x18, 0x37, 0x61, 0x23, 0x4a,
    0xf9, 0x1e, 0x8b, 0x71, 0x08, 0x28, 0x7c, 0x7b,
];

// AES key derivation (sub_1468F6E80)
#[inline]
pub fn derive_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    for (i, (a, b)) in TABLE_A.iter().zip(TABLE_B.iter()).enumerate() {
        key[i] = a ^ b;
    }
    key
}

// Unseals a V1 AES-256-GCM container (sub_146902580)
// Container Layout:
// 0x00..0x04: "PBZS"
// 0x04: Version (1)
// 0x05: Key ID (1)
// 0x06..0x08: Flags (0x00, 0x00)
// 0x08..0x14: Nonce (12 bytes)
// 0x14..0x24: Authentication Tag (16 bytes)
// 0x24..End: Ciphertext
pub fn unseal_v1(ctnr: &[u8]) -> Result<Vec<u8>> {
    if ctnr.len() < 36 {
        bail!("V1 ctnr too short: {} bytes (minimum 36)", ctnr.len());
    }
    if &ctnr[0..4] != MAGIC {
        bail!("Invalid container magic: {:?}", &ctnr[0..4]);
    }
    if ctnr[4] != 1 {
        bail!("Unsupported ctnr version: {}", ctnr[4]);
    }
    if ctnr[5] != 1 {
        bail!("Unsupported Key ID: {}", ctnr[5]);
    }

    let nonce_bytes = &ctnr[8..20];
    let tag_bytes = &ctnr[20..36];
    let ciphertext_bytes = &ctnr[36..];

    let key = derive_key();
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow::anyhow!("Failed to initialize AES-256-GCM cipher: {e}"))?;

    let nonce = Nonce::try_from(nonce_bytes)
        .context("Invalid nonce length")?;

    let mut payload = Vec::with_capacity(ciphertext_bytes.len() + 16);
    payload.extend_from_slice(ciphertext_bytes);
    payload.extend_from_slice(tag_bytes);

    let plaintext = cipher.decrypt(&nonce, payload.as_ref())
        .context("AES-256-GCM auth failed (tampered/corrupt save payload)")?;

    Ok(plaintext)
}

// Seals a plaintext buffer into a V1 AES-256-GCM container
pub fn seal_v1(plaintext: &[u8], key_id: u8) -> Result<Vec<u8>> {
    let key = derive_key();
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow::anyhow!("Failed to initialize AES-256-GCM cipher: {e}"))?;

    let nonce = Nonce::generate();

    let ct_with_tag = cipher.encrypt(&nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("AES-256-GCM encryption failed: {e}"))?;

    let ct_len = ct_with_tag.len() - 16;
    let ciphertext = &ct_with_tag[..ct_len];
    let tag = &ct_with_tag[ct_len..];

    let mut ctnr = Vec::with_capacity(36 + ct_len);
    ctnr.extend_from_slice(MAGIC);
    ctnr.push(1); // version 1
    ctnr.push(key_id);
    ctnr.extend_from_slice(&[0, 0]); // flags
    ctnr.extend_from_slice(nonce.as_slice());
    ctnr.extend_from_slice(tag);
    ctnr.extend_from_slice(ciphertext);

    Ok(ctnr)
}
