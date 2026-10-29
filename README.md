# PBZ-SaveCrypt

A standalone save crypto toolkit CLI for **Phantom Blade Zero** (UE5).

---

## Features
- **V1Container Support**: Unpack and repack single container settings saves (`PBZLocalSetting.sav`, `PBZSharedSetting.sav`).
- **V3Container Support**: Unpack and repack compound multi slot progression saves (`PBZSaveGame.sav`, realtime and periodic backups).

- **Oodle Decompressor**: Fully decompresses and compresses slot blocks via dynamic `oo2core_9_win64.dll` loading.

## Usage

### 1. Unpack a Save Game Archive
Unpacks any `.sav` file into human-readable JSON files and a `manifest.json`:
```bash
pbz-savecrypt unpack "..PBZ\ProjectPBZ\Saved\SaveGames\Steam\<SteamID>>\PBZSaveGame.sav"
```

Output:
```
PBZSaveGame_unpacked/
  ├── manifest.json
  ├── __Advanced__.json
  ├── AutoSave0.json
  └── __Achievements__.json
```

### 2. Repack into an Authentic Encrypted Save
Compresses and cryptographically seals the edited JSON files back into a valid save container:
```bash
pbz-savecrypt pack "PBZSaveGame_unpacked" "PBZSaveGame_modified.sav"
```

### 3. Verify Container Integrity
Validates AES-GCM auth tags, directory header mirrors, and Oodle decompression without modifying files:
```bash
pbz-savecrypt verify "PBZSaveGame.sav"
```

## Oodle Lib Requirement
For V3 containers with compressed slots, `oo2core_9_win64.dll` must be placed in the same directory as `pbz-savecrypt.exe` (or in the current working directory).

