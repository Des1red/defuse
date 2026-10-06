# Defuse

Defuse is a defensive malware inspection and removal tool written in Go.

It inspects the local system for running processes, network activity, persistence mechanisms, and target-related IP indicators. Suspicious activity is correlated into targets which can then be selectively eradicated and verified.

The project follows a simple rule:

> Detect first, correlate evidence, then remove only the selected target and its confirmed artifacts.

Defuse currently supports inspection and eradication on both Linux and Windows.

---

## Features

### Process Inspection

Defuse enumerates running processes and collects information such as:

- PID
- Parent PID
- Process name
- Executable path
- Command line

Process relationships are used during correlation so related activity can be grouped into a single target instead of producing many disconnected alerts.

---

### Network Inspection

Defuse collects active network information including:

- PID
- Local address
- Local port
- Remote address
- Remote port
- Connection state

Network activity is associated with processes by PID and can also be associated with related child processes during correlation.

Public network activity contributes additional evidence to target scoring.

A network connection alone is not enough to classify a process as malicious.

---

### IP Indicator Extraction

Defuse can extract IP indicators associated with a correlated target.

Sources include:

- Live target network connections
- Related-process network connections
- Process command lines
- Persistence values
- IPv4 strings embedded in the target executable
- IPv4 strings embedded in suspicious related executables

Both normal ASCII strings and simple UTF-16 encoded strings are inspected.

Example:

```text
Correlation Results
-------------------
└─ Target #1 [MEDIUM] maltrack.exe
   ├─ PID: 8140
   ├─ Path: C:\Users\root\Documents\maltrack\maltrack.exe
   ├─ Findings
   │  ├─ [persistence] persistence mechanism references the running process
   │  └─ [path] process executes from a user-writable location
   ├─ IP Indicators
   │  └─ 127.0.0.1
   └─ Persistence
      ...
```

An IP indicator does not necessarily mean that Defuse observed a live connection to that address.

For example, an address may have been extracted statically from the target executable.

Live connections remain separately visible under the target's `Connections` section.

---

## Persistence Detection

Defuse scans common persistence mechanisms.

### Linux

Supported persistence sources include:

- Desktop autostart entries
- systemd services
- systemd timers
- cron entries

### Windows

Supported persistence sources include:

- Run / RunOnce registry keys
- Startup entries
- Windows services
- Scheduled tasks
- Winlogon persistence
- AppInit DLLs
- Image File Execution Options

Windows registry collection checks both relevant 32-bit and 64-bit registry views where applicable.

---

## Correlation Engine

Defuse does not treat every collected artifact as malware.

Inspection data is correlated into a `Target` using multiple signals.

Examples include:

- Persistence referencing a running process
- Execution from suspicious writable locations
- External network activity
- Related suspicious processes
- Parent / child process relationships
- Shared executable paths
- Related persistence mechanisms
- Deleted executable mappings on Linux
- System-process masquerading

A target contains:

```text
Process
Connections
IP Addresses
Persistence
Related Processes
Findings
Confidence
```

Example:

```text
Correlation Results
-------------------
└─ Target #1 [HIGH] hydra
   ├─ PID: 8365
   ├─ Path: /home/kali/.config/autostart/hydra
   ├─ Command: /home/kali/.config/autostart/hydra
   ├─ Findings
   │  ├─ [persistence] persistence mechanism references the running process
   │  ├─ [path] process executes from a suspicious writable location
   │  └─ [process_cluster] related process activity also triggered suspicious behavior
   ├─ Persistence
   │  ├─ [autostart] hydra.desktop
   │  └─ [service] session-helper.service
   └─ Related Processes
      ├─ xmessage
      ├─ dbus-proxy
      ├─ dconf-service
      └─ gvfs-daemon
```

---

## Process Clustering

Defuse evaluates processes individually and then clusters related suspicious activity.

This prevents one malware execution chain from being reported as many unrelated targets.

Clustering considers relationships such as:

- Parent / child relationships
- Persistence-backed root processes
- Related suspicious processes
- Shared target artifacts
- Related network activity

Persistence-backed processes are preferred as the root of a cluster where possible.

---

## Confidence Levels

Targets are assigned a confidence level based on the evidence available.

```text
LOW
MEDIUM
HIGH
```

A suspicious writable path alone should not carry the same weight as a process that also has persistence, suspicious related processes, or other supporting evidence.

Defuse combines multiple signals before raising confidence.

---

## Orphaned Persistence Detection

Defuse can detect suspicious persistence that points to an executable that no longer exists.

For example:

```text
~/.config/autostart/example.desktop
        ↓
~/.config/autostart/example
        ↓
file does not exist
```

This can indicate incomplete malware cleanup or abandoned persistence.

To reduce false positives, Defuse does not automatically treat every broken persistence entry as malicious.

Orphan detection also considers whether the persistence mechanism or referenced executable is associated with a suspicious or user-writable location.

Example:

```text
Correlation Results
-------------------
└─ Target #1 [LOW] example
   ├─ Path: /home/user/.config/autostart/example
   ├─ Findings
   │  └─ [orphaned_persistence]
   │     persistence references an executable that does not exist
   └─ Persistence
      └─ [autostart] example.desktop
```

Broken operating-system or legitimate application entries are therefore less likely to become false-positive targets.

---

# Eradication

Eradication operates only on the target explicitly selected by the user.

The Linux and Windows implementations use the same high-level safety model but use platform-specific APIs where required.

---

## Process Validation

Before destructive actions are performed, Defuse validates the live process identity against the process recorded during inspection.

Executable paths are preferred when available.

This reduces the risk of acting on a PID that has been reused by a different process.

---

## Linux Eradication

The Linux eradication flow is:

```text
Validate target processes
        ↓
Freeze target process cluster
        ↓
Remove persistence
        ↓
Terminate target process cluster
        ↓
Sweep for matching respawns
        ↓
Remove confirmed executable artifacts
        ↓
Verify cleanup
```

### Coordinated Freeze

Linux target processes are frozen using:

```text
SIGSTOP
```

The process cluster is frozen before persistence removal to reduce the opportunity for malware to restore persistence or recreate artifacts while cleanup is taking place.

### Process Termination

Validated target processes are terminated using:

```text
SIGKILL
```

### Linux Persistence Removal

Supported cleanup includes:

- Desktop autostart entries
- systemd services
- systemd timers
- cron persistence

---

## Windows Eradication

The Windows eradication flow is:

```text
Validate target processes
        ↓
Terminate target process cluster
        ↓
Remove target persistence
        ↓
Sweep for matching respawns
        ↓
Terminate matching respawns
        ↓
Remove confirmed executable artifacts
        ↓
Verify cleanup
```

Windows uses native process APIs rather than Unix signals.

### Windows Process Termination

Target processes are opened using the Windows process APIs and terminated only after identity validation.

Defuse does not terminate processes globally by executable name.

### Windows Persistence Removal

Supported cleanup includes:

- Run / RunOnce registry values
- Startup entries
- Windows services
- Scheduled tasks
- Winlogon persistence
- AppInit DLL persistence
- Image File Execution Options debugger persistence

Persistence cleanup is targeted to entries associated with the selected target.

For sensitive shared values such as Winlogon, Defuse removes the malicious target reference instead of blindly deleting the entire value.

For example:

```text
Before:

C:\WINDOWS\system32\userinit.exe,C:\Users\root\Documents\maltrack\maltrack.exe

After:

C:\WINDOWS\system32\userinit.exe,
```

The legitimate Windows component is preserved.

---

## Respawn Sweep

Defuse performs an additional sweep for processes executing from confirmed target executable paths.

This helps detect a target that recreated itself during the cleanup window.

Matching processes are terminated before file removal continues.

---

## File Removal

Confirmed executable artifacts associated with the selected target are removed.

Defuse does not recursively delete entire directories.

Trusted system locations are filtered to reduce the risk that legitimate operating-system executables are removed simply because they were launched by a suspicious process.

Related-process files are also subject to suspicious-path checks before becoming deletion candidates.

---

## Verification

Cleanup is not considered successful simply because removal functions returned without an error.

Defuse verifies that:

- Target processes are gone
- Matching executable processes have not respawned
- Target persistence entries are gone
- Intended target files are gone

A successful cleanup ends with:

```text
verify:          target #1 [success]
Verification:    passed
```

---

# Shared Detection Logic

Logic that can safely behave the same across supported platforms is kept under the shared engine package.

Examples include:

- Process relationship discovery
- Process-to-network correlation
- Related-process network correlation
- Public-address detection
- Suspicious-path policy entry points
- Target IP indicator extraction

Platform-specific path behavior remains separated through Go build tags.

For example:

```text
internal/engines/shared/
├── connections.go
├── network.go
├── processes.go
├── indicators.go
├── paths_linux.go
└── paths_windows.go
```

This allows Linux and Windows to share the same high-level API while still applying operating-system-specific path rules.

---

# Architecture

Defuse keeps collection, correlation, eradication, storage, and presentation separated.

```text
cmd
│
├── user interaction
│
internal
├── controller.go
│
├── engines
│   ├── inspect
│   │   ├── inspect_linux.go
│   │   ├── inspect_windows.go
│   │   └── internal
│   │       ├── linux
│   │       └── windows
│   │
│   ├── eradicate
│   │   ├── eradicate_linux.go
│   │   ├── eradicate_windows.go
│   │   └── internal
│   │       ├── linux
│   │       └── windows
│   │
│   └── shared
│       ├── connections.go
│       ├── network.go
│       ├── processes.go
│       ├── indicators.go
│       ├── paths_linux.go
│       └── paths_windows.go
│
├── knowledge
├── models
└── output
```

---

## Knowledge

`knowledge.Data` acts as the shared source of truth for collected inspection results, selected targets, and eradication results.

Core objects include:

```text
Process
Connection
Persistence
Finding
Target
Action
InspectResult
EradicateResult
```

The engines return structured results while the controller stores those results in knowledge.

Output code reads those structures rather than collecting operating-system information directly.

---

## Platform Separation

Operating-system-specific implementations use Go build tags.

Linux:

```go
//go:build linux
```

Windows:

```go
//go:build windows
```

Fallback implementations use:

```go
//go:build !windows && !linux
```

This keeps Linux and Windows implementation details isolated while preserving the same high-level engine interface.

---

# Build

Build for the current platform:

```bash
go build ./...
```

Run static checks:

```bash
go vet ./...
```

Build for Linux:

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
go build -o defuse .
```

Build for Windows:

```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
go build -o defuse.exe .
```

---

# Testing

Defuse has been tested inside isolated virtual machines against controlled malware samples.

Malware testing should only be performed in systems specifically created for malware analysis.

---

## Linux Test

Linux inspection and eradication were tested against a custom lab malware sample named Hydra.

The test covered:

- Autostart persistence
- User systemd service persistence
- Multiple related processes
- Repeated child process spawning
- Helper executables in user-writable paths
- Deleted executable mappings
- Persistence removal
- Process termination
- Respawn sweeping
- Artifact removal
- Post-cleanup verification
- Clean rescanning after eradication

Observed test sequence:

```text
Before malware:

Persistence: 91
Targets: 0

With malware:

Persistence: 93
Targets: 1

Eradication:

Verification: passed

After cleanup:

Persistence: 91
Targets: 0
```

---

## Windows Test

Windows inspection and eradication were tested against the Fynloski / Mal-Track lab sample in an isolated Windows virtual machine.

### Clean Baseline

Before execution:

```text
Processes: 156
Connections: 67
Persistence: 269
Targets: 0
```

No suspicious target was detected.

The legitimate Winlogon `Userinit` value was:

```text
C:\WINDOWS\system32\userinit.exe,
```

### Malware Execution

After execution, Defuse identified:

```text
Target #1 [MEDIUM] maltrack.exe
PID: 8140
Path: C:\Users\root\Documents\maltrack\maltrack.exe
```

The target triggered:

```text
[persistence] persistence mechanism references the running process
[path] process executes from a user-writable location
```

Defuse also extracted:

```text
IP Indicators
└─ 127.0.0.1
```

### Observed Persistence

Fynloski created a current-user Run entry:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run

Mal-Track =
C:\Users\root\Documents\maltrack\maltrack.exe
```

It also modified the Winlogon `Userinit` value:

```text
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon

C:\WINDOWS\system32\userinit.exe,C:\Users\root\Documents\maltrack\maltrack.exe
```

### Eradication Result

Defuse performed:

```text
validate:              PID 8140 maltrack.exe [success]
terminate:             PID 8140 maltrack.exe [success]
remove_persistence:    registry Mal-Track [success]
remove_persistence:    winlogon Userinit [success]
remove_file:           C:\Users\root\Documents\maltrack\maltrack.exe [success]
verify:                target #1 [success]

Verification:          passed
```

Independent post-eradication checks confirmed:

- `maltrack.exe` was no longer running
- The `Mal-Track` Run value no longer existed
- Winlogon `Userinit` contained only the legitimate Windows entry
- `maltrack.exe` no longer existed on disk

---

## Malware Analysis Lab Safety

Testing was performed in isolated virtual machines.

During controlled Windows malware testing:

- VM network connectivity was disabled
- Host/shared-folder access was disconnected before malware execution
- Malware samples remained inside the dedicated analysis VM
- Security software exclusions were used only where required for controlled execution
- Security protections were restored after testing

Defuse is not intended to replace endpoint security software.

The purpose of the malware samples is to validate Defuse's detection, correlation, remediation, and verification behavior.

---

# Reports

Defuse saves inspection and eradication results to report files.

Example:

```text
Report saved: reports\defuse-20261006-043157.txt
```

Reports provide evidence of:

- Process discovery
- Network inspection
- Persistence inspection
- Target correlation
- Findings
- IP indicators
- Eradication actions
- Verification results

These reports can be used as supporting evidence during malware-analysis exercises and security audits.

---

# Safety Model

Defuse is intentionally conservative about destructive actions.

Important design rules include:

- Never kill processes globally by name
- Validate process identity before destructive actions
- Operate only on the selected target
- Remove only persistence correlated with that target
- Preserve legitimate portions of shared persistence values
- Avoid deleting trusted system executables
- Avoid recursive directory deletion
- Filter related-process file candidates
- Sweep for target respawns before file deletion
- Verify cleanup after eradication
- Treat weak evidence as low confidence rather than automatically malicious

Defuse is intended for defensive analysis and cleanup on systems you own or are explicitly authorized to inspect.

---

# Current Status

## Linux

Implemented and tested:

- Process inspection
- Network inspection
- Persistence inspection
- IP indicator extraction
- Correlation
- Confidence scoring
- Process clustering
- Orphaned persistence detection
- Target selection
- Process validation
- Process freezing
- Persistence eradication
- Process termination
- Respawn sweeping
- File removal
- Verification
- Report generation

## Windows

Implemented and tested:

- Process inspection
- Network inspection
- Persistence inspection
- IP indicator extraction
- Correlation
- Confidence scoring
- Process clustering
- Orphaned persistence detection
- Target selection
- Process validation
- Persistence eradication
- Process termination
- Respawn sweeping
- File removal
- Verification
- Report generation

---

# Ethical Use

Defuse was designed as a defensive security tool.

Its purpose is to:

- Identify suspicious local activity
- Correlate malware-related evidence
- Explain why a target was considered suspicious
- Remove confirmed malicious artifacts
- Verify that cleanup succeeded

It is not designed to deploy malware, gain unauthorized access, maintain unauthorized persistence, or interfere with systems outside the user's authorization.

---

# Disclaimer

Defuse is a defensive security project.

Use it only on systems you own or have explicit authorization to inspect and modify.

Malware testing should be performed inside an isolated lab environment such as a disposable virtual machine.