## Introduction
This tool is designed for CVE vulnerability detection on unpacked firmware.

## Environmental Dependencies
Refer to the contents of README_old.md for installation instructions.

## Directory Structure
``` 

android_patch_check/
├── analysis
│   ├── TestEngine.py              # Main file called during project execution
│   ├── TestEngine_original.py     # Original version of the TestEngine.py file
│   └── TestEngine_dex_expend.py   # Modified version of TestEngine.py for DEX file detection
│                                  # Note: Absolute paths in the file may need adjustments
│
├── assets
│   ├── check_file_list            # Detailed CVE information for each API level (release date, risk level, affected files, etc.)
│   ├── chunks                     # Resource files required for patch detection
│   ├── lib                        # JSON dependency library
│   ├── allTestSuites.json         # Main resource index file used during execution, containing resource file indexes for each API level
│   ├── allTestSuites_2303_expand.json    # Deprecated
│   ├── allTestSuites_2303_offical.json   # Official latest version of the resource index file released in March 2023
│   ├── allTestSuites_original.json       # Old resource index file (from 2021)
│   ├── basic_test.jar             # Adds support for DEX detection
│   ├── checklist_2303_offical.json       # Maps affected files for each API level CVE
│   └── vuln_level.json            # Risk level of each CVE
│
│
├── main_dump.py                   # Patch detection for firmware from Android Dumps
└── main_add.py                    # Patch detection for self-unpacked firmware
```

## Usage Instructions
1，The patch detection scripts are main_dump.py and main_add.py. The main.py file is the original launch script provided by the project.
2，The entry function for running the scripts is `brand_cve_check()`
