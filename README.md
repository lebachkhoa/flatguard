# Flatguard

A command-line security auditing tool for [Flatpak](https://flatpak.org/) applications on Linux. Flatguard scans all installed Flatpak apps, parses their permission metadata, and flags potentially dangerous permissions using a Security Rules set — with color-coded terminal output for quick review.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Security Rules](#security-rules)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Building](#building)
- [Usage](#usage)
- [Running Tests](#running-tests)
- [Example Output](#example-output)
- [Changelog](#changelog)
- [License](#license)

---

## Overview

Flatpak sandboxes applications, but many apps request excessive permissions that users may not be aware of. Flatguard works in two stages:

1. **Parse** — reads each app's INI `metadata` file (permissions)
2. **Audit** — matches permissions against a security rule set, adjusting severity based on the app's declared purpose

Results are printed to the terminal with color-coded `CRITICAL` / `WARNING` / `INFO` labels (red/yellow/cyan).

---

## Features

- Automatically discovers installed Flatpak apps under `$XDG_DATA_HOME/flatpak/app/` or `~/.local/share/flatpak/app/` and `/var/lib/flatpak/app/`
- Parses INI-style Flatpak `metadata` files using [SimpleIni](https://github.com/brofield/simpleini)
- Full CLI interface with `--audit`, `--list`, `--json`, `--help`, `--version`
- Color-coded output: **RED** for `CRITICAL`, **YELLOW** for `WARNING`, **CYAN** for `INFO`
- Detects dangerous permission combinations (COMBO_01..COMBO_04) and reports them as `CRITICAL`.
- Unit-tested with [Google Test](https://github.com/google/googletest)

---

## Security Rules

| Rule ID | Default Severity | Permission Checked    | Description                                                   |
|---------|------------------|-----------------------|---------------------------------------------------------------|
| DEV_01  | CRITICAL         | `devices=all`         | App can access all hardware devices (webcam, microphone, etc.)|
| FS_01   | INFO             | `filesystems=home`    | App can read and write your personal home directory           |
| FS_02   | CRITICAL         | `filesystems=host`    | App has access to the entire host OS filesystem               |
| SOC_01  | INFO             | `sockets=x11`         | X11 protocol is insecure and allows keylogging                |
| NET_01  | INFO             | `shared=network`      | App can communicate over the internet                         |
| DBUS_01 | WARNING          | `sockets=session-bus` | App can talk to other apps — potential sandbox escape         |

### Combo (risk) rules

Flatguard also detects dangerous permission *combinations* that greatly increase risk. These "combo" rules are reported as `CRITICAL`:

- `COMBO_01`: `network + home` — App can exfiltrate personal files over the internet.
- `COMBO_02`: `network + host` — App can exfiltrate the entire host filesystem.
- `COMBO_03`: `network + x11` — App can capture keystrokes (keylogging) and transmit them remotely.
- `COMBO_04`: `network + devices=all` — App can stream webcam/microphone over the internet.

---

## Project Structure

```
flatguard/
├── src/
│   ├── main.cpp               # Entry point: CLI parsing, scan, audit, print
│   ├── color.h                # ANSI color codes for terminal output
│   ├── flatpak/
│   │   ├── parser.h           # AppPermissions struct, FlatpakParser declarations
│   │   ├── parser.cpp         # INI metadata parser, system scan
│   │   ├── override.h         # applyOverrides declaration
│   │   └── override.cpp       # Applies system/user Flatpak overrides to permissions
│   ├── audit/
│   │   ├── auditor.h          # SecurityRule / AuditIssue structs, built-in rules
│   │   └── auditor.cpp        # Context-aware rule-matching logic
│   └── utils/
│       ├── ini_utils.h        # parsePermissionsFromIni declaration
│       └── ini_utils.cpp      # Shared INI parsing utilities
├── tests/
│   ├── test_parser.cpp        # Unit tests for the metadata parser
│   ├── test_override.cpp      # Unit tests for the override module
│   └── test_auditor.cpp       # Unit tests for the auditor
├── third_party/
│   ├── SimpleIni.h            # Header-only INI parser
│   └── cxxopts.hpp            # Header-only CLI argument parser
└── CMakeLists.txt             # Build configuration
```

---

## Requirements

| Dependency  | Version | Notes                                                              |
|-------------|---------|--------------------------------------------------------------------|
| CMake       | ≥ 3.10  | Build system                                                       |
| GCC / Clang | C++17   | Requires `std::filesystem` support                                 |
| Internet    | —       | Required on first build to fetch GoogleTest via CMake `FetchContent` |

All other dependencies (SimpleIni, cxxopts) are bundled in `third_party/` — no extra installation needed.

> Flatpak itself does **not** need to be installed to build or run the tests. It is only needed for a real system scan.

---

## Building

```bash
# Clone the repository
git clone https://github.com/lebachkhoa/flatguard
cd flatguard

# Create and enter the build directory
mkdir build && cd build

# Configure and build
cmake ..
make
```

This produces four binaries inside `build/`:

| Binary          | Description                         |
|-----------------|-------------------------------------|
| `flatguard`     | The main CLI tool                   |
| `test_parser`   | Unit tests for the parser module    |
| `test_override` | Unit tests for the override module  |
| `test_auditor`  | Unit tests for the auditor module   |

---

### Install system-wide (optional)

If you want to install `flatguard` so it can be run like a normal system command (e.g. `flatguard` from any shell), you can use CMake's `install` target. The project installs the `flatguard` executable to `$(CMAKE_INSTALL_PREFIX)/bin` (by default `/usr/local/bin`).

Example:

```bash
cd build
cmake ..
make
sudo make install

# Now you can run flatguard from anywhere:
flatguard --help
```

To uninstall (if you used the default prefix):

```bash
sudo rm /usr/local/bin/flatguard
```

---

## Usage

```bash
cd build

# Audit all installed Flatpak apps (default)
./flatguard
./flatguard --audit all

# Audit a single app by its ID
./flatguard --audit org.mozilla.firefox

# Output results as JSON (pipe-friendly)
./flatguard --json
./flatguard --audit org.mozilla.firefox --json

# List all installed Flatpak apps
./flatguard --list

# Show help
./flatguard --help

# Show version
./flatguard --version
```

---

### CLI Reference

| Flag                    | Short | Description                                        |
|-------------------------|-------|----------------------------------------------------|
| `--audit <app-id\|all>` | `-a`  | Audit a specific app or all apps (default: `all`)  |
| `--json`                | `-j`  | Output audit results in JSON format                |
| `--list`                | `-l`  | List all installed Flatpak applications            |
| `--help`                | `-h`  | Show help message                                  |
| `--version`             | —     | Show version information                           |

---

## Running Tests

```bash
cd build

./test_parser
./test_override
./test_auditor
```

Or using CTest:

```bash
cd build
ctest --output-on-failure
```

Expected output:

```
    Start 1: TestParser
1/3 Test #1: TestParser .......................   Passed    0.00 sec
    Start 2: TestAuditor
2/3 Test #2: TestAuditor ......................   Passed    0.00 sec
    Start 3: TestOverride
3/3 Test #3: TestOverride .....................   Passed    0.00 sec
```

---

## Example Output
```
$ ./flatguard --audit all

Application: org.mozilla.firefox
--------------------------------------------------
[+] Permissions Summary:
    - Shared:   network, ipc
    - Sockets:  x11, wayland, pulseaudio, fallback-x11, pcsc, cups
    - Devices:  all
    - Files:    xdg-config/gtk-3.0:ro, xdg-download, /run/.heim_org.h5l.kcm-socket, xdg-run/speech-dispatcher:ro

[!] Security Findings:
  [CRITICAL] DEV_01: App can access all hardware devices (webcam, etc.)
  [INFO]     SOC_01: X11 protocol is insecure and allows keylogging.
  [INFO]     NET_01: App can communicate over the internet.
  [CRITICAL] COMBO_03: App can capture keystrokes and transmit them remotely.
  [CRITICAL] COMBO_04: App can stream webcam/microphone over the internet.
--------------------------------------------------

Application: com.github.tchx84.Flatseal
--------------------------------------------------
[+] Permissions Summary:
    - Shared:   ipc
    - Sockets:  x11, wayland, fallback-x11
    - Devices:  dri
    - Files:    xdg-data/flatpak/overrides:create, /var/lib/flatpak/app:ro, xdg-data/flatpak/app:ro

[!] Security Findings:
  [INFO]     SOC_01: X11 protocol is insecure and allows keylogging.
--------------------------------------------------
```

**JSON output (`--json`):**
```json
$ ./flatguard --audit org.mozilla.firefox --json
[
  {
    "appId": "org.mozilla.firefox",
    "permissions": {
      "shared": ["network", "ipc"],
      "sockets": ["x11", "wayland", "pulseaudio", "fallback-x11", "pcsc", "cups"],
      "devices": "all",
      "files": ["xdg-config/gtk-3.0:ro", "xdg-download", "/run/.heim_org.h5l.kcm-socket", "xdg-run/speech-dispatcher:ro"]
    },
    "issues": [
      {
        "ruleId": "DEV_01",
        "severity": "CRITICAL",
        "description": "App can access all hardware devices (webcam, etc.)"
      },
      {
        "ruleId": "SOC_01",
        "severity": "INFO",
        "description": "X11 protocol is insecure and allows keylogging."
      },
      {
        "ruleId": "NET_01",
        "severity": "INFO",
        "description": "App can communicate over the internet."
      },
      {
        "ruleId": "COMBO_03",
        "severity": "CRITICAL",
        "description": "App can capture keystrokes and transmit them remotely."
      },
      {
        "ruleId": "COMBO_04",
        "severity": "CRITICAL",
        "description": "App can stream webcam/microphone over the internet."
      }
    ]
  }
]
```

---

## Changelog

### v0.1.1 — 2026-03-08

#### Fixed
- **Override resolution**: `applyOverrides` now correctly resolves both system-level (`/var/lib/flatpak/overrides/`) and per-user (`$XDG_DATA_HOME/flatpak/overrides/` or `~/.local/share/flatpak/overrides/`) override files, and applies them in the correct order (system first, user second).
- **Override token handling**: Denial tokens prefixed with `!` (e.g. `!network`) now properly remove the matching permission from the base permission list.
- **Path handling consistency**: All file path operations now use `std::filesystem::path` throughout the codebase (`parseMetadata`, `scanSystem`, `applyOverrides`), eliminating fragile manual string concatenation.
- **CLI argument validation**: Passing subcommand-style arguments without `--` (e.g. `flatguard audit <id>`) now emits a clear error with a suggested fix instead of silently auditing all apps.

#### Internal
- Extracted shared INI parsing logic into `src/utils/ini_utils.cpp`.
- Added `test_override` unit test binary covering override resolution and token merging.

---

### v0.1.0 — Initial release

- Scan all installed Flatpak apps from system and user paths.
- Parse INI `metadata` files for permissions (shared, sockets, devices, filesystems).
- Audit permissions against 6 security rules + 4 combo rules.
- Color-coded terminal output (`CRITICAL` / `WARNING` / `INFO`).
- CLI flags: `--audit`, `--list`, `--json`, `--help`, `--version`.
- Unit tests for parser and auditor modules.

---

## License

This project is licensed under the **GNU General Public License v3.0**.  
See the [LICENSE](LICENSE) file for details.
