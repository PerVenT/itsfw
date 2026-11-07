<p align="center">
  <img src="assets/logo.svg" alt="it's.fw logo" width="800" />
</p>

# it's.fw — Interactive Terminal Firewall for Windows

**it's.fw** is a fast, lightweight, and modern terminal-based firewall for Windows. Built on the Zero-Trust security model (blocking unapproved traffic by default), it gives you real-time visibility and instant control over which applications can access the network.

Gain complete control over what reaches the Internet and immediately detect stealthy background telemetry.

---

## Quick Installation

Install or update `it's.fw` with a single command in PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1
```

> **What does the installer do?**
> - Copies the standalone executable to your user directory: `~/.local/bin/itsfw.exe`.
> - Automatically adds `~/.local/bin` to your User `PATH`, allowing you to run `itsfw` from any command prompt or terminal.

---

## How to Launch

Because `it's.fw` manages native network rules via the Windows Filtering Platform (WFP), it requires **Administrator** privileges.

Open Windows Terminal as Administrator and run:
```powershell
itsfw
```

Or launch it directly with elevated privileges:
```powershell
powershell -Command "Start-Process itsfw -Verb RunAs"
```

---

## Key Features

- **Live Knocking Monitor**: When an app attempts an unapproved outbound connection, it is instantly highlighted in amber (`Knocking`), allowing you to immediately approve or block it.
- **LAN vs. Internet Zoning**: Grant an app access strictly to your local network (e.g., local network printers, media servers, or development clusters) while blocking it from public Internet access.
- **Listening Port Inspector**: Quickly inspect processes listening on open ports (`LISTEN`), and safely terminate unwanted services on the fly (`k` / Kill PID).
- **Native OS Compatibility**: All created rules are registered directly with Windows Defender Firewall (under the `itsfw` group) and instantly appear in the native Windows MMC snap-in (`wf.msc`).

---

## Hotkeys & Controls

| Key | Action |
|---|---|
| `Tab` | Toggle traffic direction: Outbound (`Outbound`) ↔ Inbound (`Inbound`) |
| `1` .. `4` | Quick filters: **[1]** All Apps, **[2]** Knocking (Blocked Attempts), **[3]** Allowed, **[4]** Blocked |
| `/` | Smart search by app name or inspect open ports (type `/:` or `/:80`) |
| `k` | Terminate process (Kill PID) in listening port mode |
| `Enter` | Open quick interactive rule builder for the selected app |
| `A` | Allow application full network access (LAN + Internet) |
| `L` | Allow application access only to local network (LAN Only) |
| `D` | Deny / block application network access |
| `T` | Toggle color palette (Monokai Pro Ristretto / Gruvbox Dark Soft) |
| `F` | Toggle global default outbound blocking policy (Zero-Trust Mode) |
| `Q` / `Esc` | Quit `it's.fw` |

---

## Building from Source (Developers)

Building from source requires **GNU Make** and **Podman** or **Docker** (a native Windows Rust toolchain is not required):

```bash
# Build the cross-compilation builder container:
make image

# Compile the release binary (x86_64-pc-windows-gnu):
make build-windows

# Package release archive with SHA256 checksums into dist/:
make release

# Run isolated E2E verification safely inside Windows Sandbox:
make sandbox-test
```
