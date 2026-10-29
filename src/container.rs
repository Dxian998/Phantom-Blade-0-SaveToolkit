use crate::crypto::{seal_v1, unseal_v1, MAGIC};
use crate::oodle::Oodle;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SlotMetadata {
    pub name: String,
    pub codec_type: u8,
    pub flags: u8,
    pub uncompressed_size: u32,
    pub payload_offset: u32,
    pub block_size: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u8,
    pub flags: u8,
    pub slot_count: u16,
    pub slots: Vec<SlotMetadata>,
}

#[inline]
pub fn detect_format(data: &[u8]) -> u8 {
    if data.len() < 5 || &data[0..4] != MAGIC {
        return 0;
    }
    data[4]
}

pub fn unpack_v1(data: &[u8]) -> Result<String> {
    let plaintext = unseal_v1(data)?;
    if plaintext.len() < 4 {
        bail!("V1 plaintext payload too short for length prefix");
    }
    let str_len = u32::from_le_bytes(
        plaintext[0..4]
            .try_into()
            .context("Failed to parse 4-byte length prefix")?,
    ) as usize;

    let mut payload = &plaintext[4..];
    if payload.len() > str_len {
        payload = &payload[..str_len];
    }
    while let Some(&0) = payload.last() {
        payload = &payload[..payload.len() - 1];
    }
    let text = String::from_utf8(payload.to_vec())
        .context("V1 payload is not valid UTF-8 text")?;
    Ok(text)
}

pub fn pack_v1(json_text: &str) -> Result<Vec<u8>> {
    let mut raw_bytes = json_text.as_bytes().to_vec();
    raw_bytes.push(0);
    let len_prefix = (raw_bytes.len() as u32).to_le_bytes();

    let mut plaintext = Vec::with_capacity(4 + raw_bytes.len());
    plaintext.extend_from_slice(&len_prefix);
    plaintext.extend_from_slice(&raw_bytes);

    seal_v1(&plaintext, 1)
}

pub fn unpack_v3(data: &[u8]) -> Result<(Manifest, BTreeMap<String, Vec<u8>>)> {
    if data.len() < 12 {
        bail!("V3 save data too short for container header ({} bytes)", data.len());
    }
    if &data[0..4] != MAGIC || data[4] != 3 {
        bail!("Invalid V3 container header magic or version");
    }

    let flags = data[5];
    let slot_count = u16::from_le_bytes(
        data[6..8]
            .try_into()
            .context("Failed to parse slot count")?,
    );
    let dir_size = u32::from_le_bytes(
        data[8..12]
            .try_into()
            .context("Failed to parse directory size")?,
    ) as usize;

    if data.len() < 12 + dir_size {
        bail!("Truncated V3 file: directory requires {} bytes, file is {}", 12 + dir_size, data.len());
    }

    let dir_ctnr = &data[12..12 + dir_size];
    let decrypted_dir = unseal_v1(dir_ctnr)
        .context("Failed to unseal V3 directory ctnr (corrupt or tampered)")?;

    // Verify header mirror (sub_1468FC4DD)
    if decrypted_dir.len() < 12 || &decrypted_dir[..12] != &data[..12] {
        bail!("Directory header verification mirror mismatch (directed slot-loss detection)");
    }

    let mut slots_meta = Vec::with_capacity(slot_count as usize);
    let mut pos = 12;

    for slot_idx in 0..slot_count {
        if pos + 2 > decrypted_dir.len() {
            bail!("Directory buffer overflow at slot descriptor {}", slot_idx);
        }
        let name_len = u16::from_le_bytes(
            decrypted_dir[pos..pos + 2]
                .try_into()
                .context("Failed to parse slot name length")?,
        ) as usize;
        pos += 2;
        if pos + name_len + 14 > decrypted_dir.len() {
            bail!("Directory entry out of bounds for slot {}", slot_idx);
        }
        let name = String::from_utf8_lossy(&decrypted_dir[pos..pos + name_len]).to_string();
        pos += name_len;

        let codec_type = decrypted_dir[pos];
        let slot_flags = decrypted_dir[pos + 1];
        let uncompressed_size = u32::from_le_bytes(
            decrypted_dir[pos + 2..pos + 6]
                .try_into()
                .context("Failed to parse slot uncompressed size")?,
        );
        let payload_offset = u32::from_le_bytes(
            decrypted_dir[pos + 6..pos + 10]
                .try_into()
                .context("Failed to parse slot payload offset")?,
        );
        let block_size = u32::from_le_bytes(
            decrypted_dir[pos + 10..pos + 14]
                .try_into()
                .context("Failed to parse slot block size")?,
        );
        pos += 14;

        slots_meta.push(SlotMetadata {
            name,
            codec_type,
            flags: slot_flags,
            uncompressed_size,
            payload_offset,
            block_size,
        });
    }

    let payload_base = 12 + dir_size;
    let mut slots_content = BTreeMap::new();

    for s in &slots_meta {
        let slot_start = payload_base + s.payload_offset as usize;
        let slot_end = slot_start + s.block_size as usize;
        if slot_end > data.len() {
            bail!("Slot '{}' payload out of file bounds", s.name);
        }

        let slot_ctnr = &data[slot_start..slot_end];
        let decrypted_slot = unseal_v1(slot_ctnr)
            .with_context(|| format!("Failed to unseal slot '{}'", s.name))?;

        let decompressed = match s.codec_type {
            2 => {
                let oodle = Oodle::get().context("Oodle engine required for decompressing slot")?;
                oodle.decompress_data(&decrypted_slot, s.uncompressed_size as usize)?
            }
            0 => {
                // Raw payload prefixed with 0xCC 0x0A
                if decrypted_slot.len() >= 2 && decrypted_slot[0] == 0xCC && decrypted_slot[1] == 0x0A {
                    decrypted_slot[2..].to_vec()
                } else {
                    decrypted_slot
                }
            }
            _ => decrypted_slot,
        };

        slots_content.insert(s.name.clone(), decompressed);
    }

    let manifest = Manifest {
        version: 3,
        flags,
        slot_count,
        slots: slots_meta,
    };

    Ok((manifest, slots_content))
}

pub fn pack_v3(manifest: &Manifest, slots_content: &BTreeMap<String, Vec<u8>>) -> Result<Vec<u8>> {
    let mut sealed_slots = Vec::new();
    let mut updated_slots = Vec::new();
    let mut cur_offset = 0u32;

    for s_meta in &manifest.slots {
        let raw_bytes = slots_content
            .get(&s_meta.name)
            .with_context(|| format!("Missing content for slot '{}'", s_meta.name))?;

        let codec_type = s_meta.codec_type;
        let uncompressed_size = raw_bytes.len() as u32;

        let slot_ctnr = match codec_type {
            2 => {
                let oodle = Oodle::get().context("Oodle engine required for compressing slot")?;
                let compressed = oodle.compress_data(raw_bytes, 4)?;
                seal_v1(&compressed, 1)?
            }
            _ => {
                let mut uncomp = Vec::with_capacity(2 + raw_bytes.len());
                uncomp.extend_from_slice(&[0xCC, 0x0A]);
                uncomp.extend_from_slice(raw_bytes);
                seal_v1(&uncomp, 1)?
            }
        };

        let block_size = slot_ctnr.len() as u32;
        sealed_slots.push(slot_ctnr);

        updated_slots.push(SlotMetadata {
            name: s_meta.name.clone(),
            codec_type,
            flags: s_meta.flags,
            uncompressed_size,
            payload_offset: cur_offset,
            block_size,
        });

        cur_offset += block_size;
    }

    // Build directory body
    let mut dir_body = Vec::new();
    for s in &updated_slots {
        let name_bytes = s.name.as_bytes();
        dir_body.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        dir_body.extend_from_slice(name_bytes);
        dir_body.push(s.codec_type);
        dir_body.push(s.flags);
        dir_body.extend_from_slice(&s.uncompressed_size.to_le_bytes());
        dir_body.extend_from_slice(&s.payload_offset.to_le_bytes());
        dir_body.extend_from_slice(&s.block_size.to_le_bytes());
    }

    // Directory ctnr size is 12 (mirror) + dir_body.len() + 36 (V1 ctnr overhead)
    let decrypted_dir_len = 12 + dir_body.len();
    let dir_ctnr_len = (decrypted_dir_len + 36) as u32;

    let slot_count = updated_slots.len() as u16;
    let mut outer_header = [0u8; 12];
    outer_header[0..4].copy_from_slice(MAGIC);
    outer_header[4] = 3; // Version 3
    outer_header[5] = manifest.flags;
    outer_header[6..8].copy_from_slice(&slot_count.to_le_bytes());
    outer_header[8..12].copy_from_slice(&dir_ctnr_len.to_le_bytes());

    let mut dir_plaintext = Vec::with_capacity(12 + dir_body.len());
    dir_plaintext.extend_from_slice(&outer_header);
    dir_plaintext.extend_from_slice(&dir_body);

    let dir_ctnr = seal_v1(&dir_plaintext, 1)?;

    let mut output = Vec::new();
    output.extend_from_slice(&outer_header);
    output.extend_from_slice(&dir_ctnr);
    for ctnr in sealed_slots {
        output.extend_from_slice(&ctnr);
    }

    Ok(output)
}
