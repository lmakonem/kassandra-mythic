# Kassandra

[![CI](https://github.com/lmakonem/kassandra-mythic/actions/workflows/ci.yml/badge.svg)](https://github.com/lmakonem/kassandra-mythic/actions/workflows/ci.yml)

**Kassandra** is a [Mythic](https://github.com/its-a-feature/Mythic) C2 agent written in **Rust**, packaged as a **Python payload-type container**. It targets **Windows x86_64**, cross-compiled from Linux via `x86_64-pc-windows-gnu`. Build as **EXE**, **DLL**, or **shellcode** (Donut).

## Installation

### Pre-built image (recommended)

CI publishes a ready-to-run image to GHCR on every push to main. No local Rust build needed.

```bash
cd /path/to/Mythic
sudo ./mythic-cli install github https://github.com/lmakonem/kassandra-mythic
```

Then set the remote image in Mythic's `.env` so it pulls instead of building:

```bash
echo 'kassandra_remote_image=ghcr.io/lmakonem/kassandra-mythic:latest' >> .env
sudo ./mythic-cli start kassandra
```

### Build from source

```bash
git clone https://github.com/lmakonem/kassandra-mythic.git
cd /path/to/Mythic
sudo ./mythic-cli install folder /path/to/kassandra-mythic
sudo ./mythic-cli start kassandra
```

**Case note:** `mythic-cli` may create `InstalledServices/Kassandra` while Docker Compose expects lowercase `kassandra`. Rename if needed:

```bash
sudo mv InstalledServices/Kassandra InstalledServices/kassandra
sudo docker compose build kassandra && sudo docker compose up -d kassandra
```

## Features

### BusyWork evasion ([BusyWork](https://github.com/PatchRequest/BusyWork))

Replaces fixed-cadence `sleep()` with **real, varied work** (compute, memory, WinAPI, registry, crypto) so callback intervals do not look like pure idle-then-act beacons.

| API | Role |
|-----|------|
| `idle()` | One full-intensity burst between tasking rounds + short jittered yield. Main callback-interval surface. |
| `churn()` | Always Low, COMPUTE and MEMORY only. Light noise at feature boundaries (not on every HTTP POST). |
| `startup_delay()` | One burst at configured intensity before first check-in. |

Operator-selectable levels: **off / low / medium / high / ultra**. Real program data is fed via `feed()` (UUID, host, paths, outputs). C2 transport path does not run BusyWork: heavy work stays in `idle()` so Medium/High remain usable without starving tasking.

### Runtime-configurable sleep

The `sleep` command is a builtin (always loaded, no per-callback load step). It accepts two parameters:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `interval` | Number | 60 | Callback interval in seconds |
| `jitter` | Number | 10 | Jitter percentage (0-100) |

```
sleep 30 20          # 30s interval, 20% jitter
sleep 120            # 120s interval, default 10% jitter
```

The agent updates its internal `RwLock<u64>` statics and sends the new `sleep_info` back to Mythic on the next checkin, so the UI reflects the change immediately. No recompile required. Builder stamps `%CALLBACK_INTERVAL%` / `%CALLBACK_JITTER%` from C2 profile params at build time for the initial values.

### Indirect syscalls ([CallGhost](https://github.com/PatchRequest/CallGhost))

Halo's Gate SSN resolution with SSN caching, used across:

- Check-in (host / user / PID)
- Process list and selfclone
- Reflective loader / mem wipe / local Nt helpers
- Self-delete
- BOF loader injection primitives

```rust
syscall!(indirect, NtFoo, /* args */);
```

### Process hardening (`selfprotect`)

Sets a restrictive process DACL (deny Everyone generic-all; allow System + owner) so casual handle opens against the implant process fail. Failures are silent (no `eprintln`).

### In-memory BOF / .NET execution

Loader code is **not** linked into the agent binary:

1. Standalone `bof_loader.dll` / `dot_loader.dll` built in Docker, placed in `/opt/loaders/`
2. Agent downloads loaders from C2, stores them **XOR-encrypted** in memory (`loader_cache`)
3. Reflective load, execute, wipe (`mem_wipe`)

| Piece | Notes |
|-------|-------|
| BOF | Forked/renamed coffee-ldr style loader |
| .NET | `clroxide`-based `dot-loader` with error surfacing (CLR errors returned as `[dot-loader error] ...` instead of silent exit code) |
| Python | Subprocess worker (`--worker-py`) |
| `loadLoader` | Pre-stage loaders from `/opt/loaders/` into agent memory (temporal separation from execution) |

### Built-in BOF / .NET catalog (188 pre-built tools, zero operator upload)

Docker **catalog-builder** stage compiles tools from pinned upstream commits into `/opt/kassandra_catalog/` + `manifest.json`.

| Source | Type | Prefix | Count |
|--------|------|--------|-------|
| [TrustedSec CS-SA-BOF](https://github.com/trustedsec/CS-Situational-Awareness-BOF) | BOF | `tsec_` | 64 |
| [Outflank C2-Tool-Collection](https://github.com/outflanknl/C2-Tool-Collection) | BOF | `oflnk_` | 24 |
| [Flangvik SharpCollection](https://github.com/Flangvik/SharpCollection) | .NET | `sharp_` | 100 |

- **`listRemote [filter]`** server-side only (no agent round-trip)
- **`executeRemote -tool_name <name> [-parameters ...]`** container resolves tool by name from `manifest.json`, auto-uploads binary to Mythic, rewrites task to `executeBOF` or `executeDOT`

```
listRemote kerb
executeRemote -tool_name tsec_whoami
executeRemote -tool_name sharp_seatbelt -parameters "-group=system"
```

### C2 transports

Priority dispatch in `transport.rs`:

1. **Tailscale** (feature) embedded tsnet / WireGuard via Go FFI; HTTP or raw TCP inside the tunnel; optional DoH
2. **S3** SigV4, bootstrap to per-execution IAM creds, optional AES-256-CBC + HMAC-SHA256 (EKE)
3. **HTTP** Mythic HTTP profile; body `base64(uuid || json)`

Translation container **`KassandraTranslator`** is a JSON pass-through (`mythic_encrypts = false`).

### Proxy and pivot

- SOCKS via Mythic (port 1080 included in `MYTHIC_SERVER_DYNAMIC_PORTS`; docker-compose port mapping added)
- Pivot listeners (`start_pivot` / `stop_pivot` / `list_pivot`)

### Core agent ops

| Command | Description |
|---------|-------------|
| `ls` / `cd` / `pwd` / `mkdir` / `rm` / `mv` / `cp` / `touch` | Filesystem operations (`cd` handles both absolute and relative paths) |
| `upload` / `download` | File transfer |
| `ps` / `psw` | Process listing (standard and wide) |
| `screenshot` | Screen capture |
| `selfdelete` | Remove agent from disk |
| `selfclone` | Spawn a second agent (see below) |
| `ping` | Connectivity check |
| `sleep` | Runtime callback interval and jitter (see above) |
| `exit` | Clean shutdown |

### `selfclone`: Early Bird + PPID spoof

Spawn a **second agent** without a direct parent/child link to the current implant.

| Mode | Default | Behavior |
|------|---------|----------|
| **`earlybird`** | yes | Mythic loads this payload's artifact; if PE, Donut to PIC. Agent: `CreateProcessW(host, CREATE_SUSPENDED)`, write shellcode, `NtQueueApcThread`, `NtResumeThread`. |
| **`process`** | no | Legacy: `CreateProcessW` of the on-disk module path. |

| Arg | Default | Meaning |
|-----|---------|---------|
| `parent` | `explorer.exe` | Process name for PPID spoof. Special: **`self`** = no spoof (host is a real child of this agent). |
| `host` | `C:\Windows\System32\RuntimeBroker.exe` | Sacrificial image (earlybird only) |

```
selfclone
selfclone -parent explorer.exe -host C:\Windows\System32\RuntimeBroker.exe
selfclone -parent self
selfclone -mode process -parent explorer.exe
```

### Shellcode output ([Donut](https://github.com/TheWover/donut))

Build `output=shellcode` and the agent is compiled as a normal EXE, then converted to position-independent shellcode with Donut. That same Donut path is reused at runtime by **`selfclone earlybird`** when the callback's payload is still a PE.

| Setting | Options | Default |
|---------|---------|---------|
| `shellcode_format` | Binary, Base64, C, Ruby, Python, Powershell, C#, Hex | Binary |
| `shellcode_bypass` | None / Abort on fail / Continue on fail | Continue on fail |

Flow (payload build): **cargo EXE, PE OPSEC audit, Donut (`-x3 -k2 -f... -b...`), `.bin`**. Authenticode is skipped for shellcode output.

## Build parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `output` | exe / dll / shellcode | exe | Payload format |
| `shellcode_format` | see above | Binary | Donut format (only if `output=shellcode`) |
| `shellcode_bypass` | see above | Continue on fail | Donut AMSI/WLDP/ETW bypass (only if `output=shellcode`) |
| `adjust_filename` | bool | true | Auto extension (`.exe` / `.dll` / `.bin`) |
| `chunk_size` | string | 4096 | Upload/download chunk size |
| `busywork_intensity` | off / low / medium / high / ultra | medium | BusyWork intensity for idle / startup |
| `no_console` | bool | true | `windows_subsystem = windows` |
| `debug_log` | bool | false | Lab only: lifecycle log to `%TEMP%\kassandra_debug.log` |
| `tailscale_protocol` | http / tcp | http | Protocol inside WireGuard |
| `doh` | off / cloudflare / google / custom | off | DoH for Tailscale DNS |
| `doh_url` | string | | Custom DoH URL when `doh=custom` |

**Production defaults:** `no_console=true`, `busywork=medium`, `debug_log=false`.
**Lab:** prefer `debug_log=true` and `busywork=off` or `low` while debugging tasking.

### Cargo features

| Feature | Effect |
|---------|--------|
| `tailscale` | Tailscale transport + link Go FFI |
| `no_console` | Hide console window |
| `debug_log` | Enable `dlog!` file logging (otherwise compile-time no-op) |

## Architecture

```
checkin (CallGhost syscalls for host/user/pid)
    -> main loop:
         get_tasking  ->  handleTask  ->  idle() BusyWork
```

Reflective path:

```
loadLoader / on-demand download
    -> XOR cache -> reflective_loader -> execute_bof / execute_dot -> mem wipe
```

## Build performance

Payload builds use a **pre-warmed dependency cache** (same pattern as Sliver's persistent GOCACHE).
The Dockerfile compiles all 245 Rust dependencies into `/opt/kassandra_cache` at image build time
using a dummy crate with the real `Cargo.toml` and `Cargo.lock`. At payload generation time, only
the `kassandra` crate itself recompiles (the source that changes via `%PLACEHOLDER%` stamping in
`config.rs`).

| Scenario | Time |
|----------|------|
| First build (no cache, e.g. `docker build --no-cache`) | ~10 min |
| Subsequent payload builds (warm cache) | ~15-30s |
| After adding/removing a dependency | partial rebuild, new dep only |

Concurrent builds are serialized via a file lock (`/opt/kassandra_cache.lock`) so multiple
payload generations don't corrupt the shared target directory.

## Release profile notes

- `lto = false`: fat LTO reduces binary size but increases EDR hit rate in lab testing; size is controlled through feature/dep selection instead.
- `panic = "abort"`: required for the `no_console` feature (Windows GUI subsystem). MinGW cross-compiled binaries with `windows_subsystem = "windows"` crash at process init when panic-unwind is active; aborting removes the unwind tables and the dependency on DWARF2 EH init ordering.

## Runtime paths (container-internal)

These paths are inside the Kassandra Docker container and require no operator configuration:

| Path | Contents |
|------|----------|
| `/opt/kassandra_catalog/manifest.json` | Tool manifest (name, type, filename) |
| `/opt/kassandra_catalog/bof/` | Compiled `.x64.o` BOF files |
| `/opt/kassandra_catalog/dotnet/` | `.exe` assemblies |
| `/opt/loaders/bof_loader.dll` | BOF loader DLL (Windows, compiled by Dockerfile) |
| `/opt/loaders/dot_loader.dll` | .NET CLR loader DLL (Windows, compiled by Dockerfile) |

## Repository layout

```
config.json                          # mythic-cli install config
Payload_Type/Kassandra/
  Dockerfile                         # catalog-builder + runtime (+ Donut)
  build_catalog.sh
  main.py
  requirements.txt
  translator/translator.py           # JSON pass-through translator
  Kassandra/
    agent_functions/                  # Mythic commands + builder.py
    agent_code/kassandra/             # Rust implant
      src/                            # main, tasking, transport, features
      loaders/                        # bof-loader, dot-loader (cdylib)
      tailscale_ffi/                  # Go tsnet wrapper
```

## Known limitations

- **WMI-backed .NET checks fail in hosted CLR**: Seatbelt `SystemInfo`, `WmiEvent*`, and other WMI-dependent checks return `ERROR: Error running command` when run via `executeRemote`/`executeDOT`. This is a `rustclr` hosted-CLR constraint. Non-WMI checks work: `DotNet`, `OsInfo`, `LocalGroups`, `LogonSessions`, `NonstandardProcesses`, `AMSI`, etc.
- **`executeRemote` parameters**: always pass a JSON object, never a CLI-style string: `{"tool_name": "sharp_seatbelt", "parameters": "DotNet"}`.

## CI

GitHub Actions runs three checks on every push to `main` and on pull requests:

1. **lint-python**: syntax-checks all `agent_functions/*.py` files against `mythic-container`
2. **check-rust**: `cargo check` with the pinned nightly toolchain, both default and `no_console,debug_log` feature sets
3. **docker-build**: full container image build (catalog + toolchain + loaders)

## Related repos

- [BusyWork](https://github.com/PatchRequest/BusyWork): intensity work engine (`bump/windows-0.61`)
- [CallGhost](https://github.com/PatchRequest/CallGhost): indirect syscalls

## Credits

Based on [Kassandra](https://github.com/PatchRequest/Kassandra) by [@PatchRequest](https://github.com/PatchRequest).

Thanks to [@Yeeb1](https://github.com/Yeeb1) for the [awss3](https://github.com/Yeeb1/awss3) S3 C2 profile, [Tailscale C2](https://github.com/Yeeb1/mythic_tailscale), and agent improvements.

Thanks to MalDevAcademy, VX-Underground, @ZkClown, and Ze_Asimovitch for training, archives, and inspiration in the red-team community.

## Disclaimer

Educational and authorized red-team use only. Do not use without proper authorization.

## License

Kassandra agent: see upstream license. Catalog tools: see `/opt/kassandra_catalog/licenses/` inside
the built container for per-collection LICENSE files (TrustedSec Apache-2.0, Outflank BSD-2,
SharpCollection MIT/individual).
