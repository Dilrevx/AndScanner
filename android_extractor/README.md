## Introduction
The firmware unpacking tool

## Environmental Dependencies
1. Please refer to the README_old.md file in this folder.  
2. For best results, ensure the version of Python’s protobuf is 3.20.0. Higher versions may cause failures.

## Instructions for Using the ext_rom.py
```
python3|python ext_rom.py <rom_path> <rom_ext>
# <rom_path>  
# Path to the firmware, typically ending with .zip or .ozip for Android firmware.  
# Supports unpacking firmware from various brands, including Xiaomi, Huawei, Samsung, OPPO, VIVO, ZTE, etc.  

# <rom_ext>  
# Path where the extracted firmware files will be stored. 

# This script unpacks the firmware, using extractor.sh to extract .img files and ext2rd to process the .img files.
```

