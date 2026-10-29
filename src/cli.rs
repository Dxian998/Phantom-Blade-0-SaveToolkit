use crate::container::{detect_format, pack_v1, pack_v3, unpack_v1, unpack_v3, Manifest};
use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub struct Cli;

impl Cli {
    pub fn run() -> Result<()> {
        let args: Vec<String> = std::env::args().collect();
        if args.len() < 2 {
            Self::print_usage();
            return Ok(());
        }

        match args[1].to_lowercase().as_str() {
            "unpack" | "-u" | "--unpack" | "decrypt" | "-d" => {
                if args.len() < 3 {
                    bail!("Usage: pbz-savecrypt unpack <input.sav> [output_dir]");
                }
                let input_path = Path::new(&args[2]);
                let out_dir = if args.len() > 3 {
                    PathBuf::from(&args[3])
                } else {
                    let stem = input_path.file_stem().unwrap_or_default().to_string_lossy();
                    input_path.with_file_name(format!("{}_unpacked", stem))
                };
                Self::cmd_unpack(input_path, &out_dir)
            }
            "pack" | "-p" | "--pack" | "encrypt" | "-e" => {
                if args.len() < 4 {
                    bail!("Usage: pbz-savecrypt pack <input_dir> <output.sav>");
                }
                let input_dir = Path::new(&args[2]);
                let output_path = Path::new(&args[3]);
                Self::cmd_pack(input_dir, output_path)
            }
            "verify" | "-v" | "--verify" => {
                if args.len() < 3 {
                    bail!("Usage: pbz-savecrypt verify <input.sav>");
                }
                let input_path = Path::new(&args[2]);
                Self::cmd_verify(input_path)
            }
            "help" | "--help" | "-h" => {
                Self::print_usage();
                Ok(())
            }
            cmd => {
                bail!("Unknown command: '{}'. Run 'pbz-savecrypt help' for usage.", cmd);
            }
        }
    }

    fn print_usage() {
        println!("pbz-savecrypt - Project PBZ Save Cryptography & Container Tool");
        println!();
        println!("Usage:");
        println!("  pbz-savecrypt unpack <input.sav> [output_dir]");
        println!("  pbz-savecrypt pack <input_dir> <output.sav>");
        println!("  pbz-savecrypt verify <input.sav>");
    }

    fn cmd_unpack(input_path: &Path, out_dir: &Path) -> Result<()> {
        let data = fs::read(input_path)
            .with_context(|| format!("Failed to read {:?}", input_path))?;

        let ver = detect_format(&data);
        println!("File:         {}", input_path.display());
        println!("File Size:    {} bytes", data.len());

        fs::create_dir_all(out_dir)
            .with_context(|| format!("Failed to create directory {:?}", out_dir))?;

        match ver {
            1 => {
                println!("Container:    V1 (Single-slot Settings)");
                let json_text = unpack_v1(&data)?;
                let out_file = out_dir.join("setting.json");
                fs::write(&out_file, &json_text)?;

                let manifest = serde_json::json!({
                    "version": 1,
                    "target": "setting.json"
                });
                fs::write(out_dir.join("manifest.json"), serde_json::to_string_pretty(&manifest)?)?;

                println!("Decrypted:    {} bytes", json_text.len());
                println!("Saved to:     {}", out_file.display());
            }
            3 => {
                println!("Container:    V3 (Multi-slot Archive)");
                let (manifest, slots) = unpack_v3(&data)?;
                let manifest_json = serde_json::to_string_pretty(&manifest)?;
                fs::write(out_dir.join("manifest.json"), manifest_json)?;

                println!("Directory:    {} slots (authenticated)", slots.len());
                for (name, content) in &slots {
                    let safe_name = name.replace(['/', '\\'], "_");
                    let out_file = out_dir.join(format!("{}.json", safe_name));
                    
                    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(content) {
                        let pretty = serde_json::to_string_pretty(&val)?;
                        fs::write(&out_file, pretty)?;
                    } else {
                        fs::write(&out_file, content)?;
                    }
                    println!("  - {:<18} ({} bytes)", name, content.len());
                }
                println!("Extracted to: {}", out_dir.display());
            }
            _ => bail!("Unrecognized save container magic (expected PBZS)"),
        }

        Ok(())
    }

    fn cmd_pack(input_dir: &Path, output_path: &Path) -> Result<()> {
        let manifest_path = input_dir.join("manifest.json");
        if !manifest_path.exists() {
            bail!("Missing manifest.json in {:?}", input_dir);
        }

        let manifest_raw = fs::read_to_string(&manifest_path)?;
        let manifest_val: serde_json::Value = serde_json::from_str(&manifest_raw)?;
        let ver = manifest_val["version"].as_u64().unwrap_or(3) as u8;

        println!("Source:       {}", input_dir.display());

        let output_bytes = match ver {
            1 => {
                println!("Container:    V1 (Single-slot Settings)");
                let target_name = manifest_val["target"].as_str().unwrap_or("setting.json");
                let json_text = fs::read_to_string(input_dir.join(target_name))?;
                pack_v1(&json_text)?
            }
            3 => {
                println!("Container:    V3 (Multi-slot Archive)");
                let manifest: Manifest = serde_json::from_str(&manifest_raw)?;
                let mut slots_content = BTreeMap::new();
                for s in &manifest.slots {
                    let safe_name = s.name.replace(['/', '\\'], "_");
                    let slot_file = input_dir.join(format!("{}.json", safe_name));
                    let raw_bytes = fs::read(&slot_file)
                        .with_context(|| format!("Missing slot file {:?}", slot_file))?;
                    slots_content.insert(s.name.clone(), raw_bytes);
                }
                println!("Slots Packed: {}", manifest.slots.len());
                pack_v3(&manifest, &slots_content)?
            }
            _ => bail!("Unsupported container version: {}", ver),
        };

        fs::write(output_path, &output_bytes)?;
        println!("Saved to:     {} ({} bytes)", output_path.display(), output_bytes.len());
        Ok(())
    }

    fn cmd_verify(input_path: &Path) -> Result<()> {
        let data = fs::read(input_path)?;
        let ver = detect_format(&data);
        println!("File:         {}", input_path.display());
        println!("File Size:    {} bytes", data.len());

        match ver {
            1 => {
                println!("Container:    V1 (Single-slot Settings)");
                let payload = unpack_v1(&data)?;
                println!("Payload Size: {} bytes", payload.len());
                println!("Verification: SUCCESS (AES-256-GCM auth valid)");
            }
            3 => {
                println!("Container:    V3 (Multi-slot Archive)");
                let (manifest, slots) = unpack_v3(&data)?;
                println!("Directory:    VALID (Mirror & GCM auth match)");
                println!("Slots ({}):", slots.len());
                for s in &manifest.slots {
                    let status = if slots.contains_key(&s.name) { "OK" } else { "MISSING" };
                    println!("  - {:<18} {:>6} bytes uncompressed, {:>5} bytes block [{}]", s.name, s.uncompressed_size, s.block_size, status);
                }
                println!("Verification: SUCCESS (All slots authenticated & decompressed)");
            }
            _ => bail!("Verification: FAILED (Invalid save container magic)"),
        }
        Ok(())
    }
}
