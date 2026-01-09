# AndScanner +

## Install

apt dependencies for extractor:

```bash
sudo apt install unace unrar zip unzip p7zip-full p7zip-rar sharutils rar uudeview mpack arj cabextract rename liblzma-dev python3-pip brotli lz4
```

sync pip dependencies for both projects:

```bash
uv sync
```

- extractor pip dependencies are in `android_extractor/README_old.md`


## Run

### Run Extractor

A demo shell command is at `scripts/run_extractor.sh`

```bash
bash scripts/run_extractor.sh
```

#### Instructions for Using the ext_rom.py

```bash
uv run ext_rom.py <rom_path> <rom_ext>
# <rom_path>  
# Path to the firmware, typically ending with .zip or .ozip for Android firmware.  
# Supports unpacking firmware from various brands, including Xiaomi, Huawei, Samsung, OPPO, VIVO, ZTE, etc.  

# <rom_ext>  
# Path where the extracted firmware files will be stored. 

# This script unpacks the firmware, using extractor.sh to extract .img files and ext2rd to process the .img files.
```


### Run Patch Checker

```
scripts/run-checker.sh
```

Rely on a unpacked rom dump.