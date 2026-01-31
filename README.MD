# Linux Process Monitor

A robust C++ application for detecting suspicious processes on Linux systems with intelligent whitelist filtering to reduce false positives from legitimate software.


## Features

- **Fake System Process Detection**: Identifies malware masquerading as legitimate kernel processes
- **Whitelist with directories and txt files**: You can manually add or remove paths for whitelists
- **Temporary Directory Execution**: Flags processes running from `/tmp`, `/var/tmp`, or `/dev/shm`
- **Hidden Path Detection**: Detects processes running from hidden directories
- **Deleted Executable Detection**: Finds processes whose executable has been deleted (common rootkit behavior)
- **Suspicious Character Detection**: Identifies unusual characters in process names
- **Empty Command Line Detection**: Flags user processes with suspicious empty command lines
- **Intelligent Whitelist**: Automatically filters common legitimate applications
- **RAII Design**: Memory-safe with proper resource management
- **Colored Output**: Easy-to-read terminal output with color coding
- **Verbose Mode**: Detailed logging for debugging and analysis


## Detection Heuristics

The tool uses multiple heuristics to identify suspicious processes:

1. **Fake System Processes**: Processes with system-like names (e.g., `kworker`, `ksoftirqd`) but running as user processes
2. **Temporary Directories**: Executables running from temporary locations (outside home directory)
3. **Hidden Directories**: Processes running from directories starting with `.` (excluding whitelisted paths)
4. **Deleted Executables**: Running processes whose executable file has been deleted
5. **Empty Command Lines**: User-space processes (PID ≥ 1000) with no command line arguments
6. **Suspicious Characters**: Process names containing non-printable or shell metacharacters

## Requirements

- Linux operating system 
- C++17 compatible compiler (GCC 7+ or Clang 5+)
- Standard build tools (`make`)

## Installation

### Build from source:

```bash

# Git Clone
git clone https://github.com/azeryusifzade/process_monitor.git

# Select the directory
cd process_monitor/src

# Compile
make

# Run
./process_monitor
```

## Usage

### Basic Usage

Scan for suspicious processes (with whitelist filtering):
```bash
./process_monitor
```

### Command Line Options

```
Options:
  -h, --help                    Show help message
  -v, --verbose                 Enable verbose output (shows detection reasons)
  -a, --all                     Show all processes (not just suspicious)
  -p, --pid <pid>               Show information for specific PID
  -m, --min-pid <num>           Minimum PID for empty cmdline check (default: 1000)
  --no-color                    Disable colored output
  --no-whitelist                Disable whitelist filtering (show all detections)
  --add-whitelist-name <name>   Add process name to whitelist
  --add-whitelist-path <path>   Add path prefix to whitelist
  --add-whitelist-name-path <n:p>     Add name with required path (SECURE) 
  --whitelist-file <file>     Load whitelist from file 
  --whitelist-dir <dir>       Load whitelists from directory 
```

### Examples

**Normal scan with whitelist filtering:**
```bash
./process_monitor
```

**Verbose scan with detailed output:**
```bash
./process_monitor -v
```

**See all detections (no whitelist):**
```bash
./process_monitor --no-whitelist
```

**Add custom whitelist entries:**
```bash
./process_monitor --add-whitelist-name myapp --add-whitelist-path /opt/myapp
```

**Show all processes:**
```bash
./process_monitor -a
```

**Check specific process:**
```bash
./process_monitor -p 1234
```

**Disable colors (for logging):**
```bash
./process_monitor --no-color > scan_results.txt
```

## Understanding Results

### Clean System Output
```
✓ No suspicious processes detected

=== SCAN SUMMARY ===

Total processes scanned: 373
Suspicious processes found: 0 ✓
```

### Suspicious Activity Detected
```
=== SUSPICIOUS PROCESSES DETECTED ===

[SUSPICIOUS PROCESS]
  PID:       12345
  Name:      kworkr  (note the typo - likely fake)
  UID:       1000
  Path:      /tmp/malware
  Command:   /tmp/malware --hidden
  State:     S (sleeping)

=== SCAN SUMMARY ===

Total processes scanned: 373
Suspicious processes found: 1 (review recommended)
```

### Whitelist in Action (Verbose Mode)
```bash
./process_monitor -v
```
Shows messages like:
```
[WHITELIST] Process name 'steam' is whitelisted
[WHITELIST] Path '~/.local/share/Steam/...' is whitelisted
```

## Whitelist Management

### Viewing Whitelist Behavior

Run with verbose mode to see what's being filtered:
```bash
./process_monitor -v
```

### Disabling Whitelist Temporarily

To see all detections including false positives:
```bash
./process_monitor --no-whitelist
```

### Adding Custom Entries

For a one-time scan with custom whitelisting:
```bash
./process_monitor --add-whitelist-name my_custom_app \
                  --add-whitelist-path /opt/custom
```

For directory of whitelist:
```bash
./process_monitor --whitelist-dir ./whitelist.d/
```

### Modifying Default Whitelist

Edit `process.cpp` and modify the `loadDefaultWhitelists()` function to add permanent entries.

## Exit Codes
- `0`: No suspicious processes found
- `1`: Suspicious processes detected
- `2`: Error occurred during scanning

## Security Considerations

### False Positives vs False Negatives

**The whitelist reduces false positives** from legitimate software like:
- Game clients (Steam, Epic Games)
- IDEs and development tools
- Web browsers
- Communication applications

**However, sophisticated malware could:**
- Use whitelisted names (mitigated by checking path + UID + cmdline)
- Run from whitelisted directories (unlikely for /opt, /usr)
- Evade detection with advanced techniques

**Best Practice**: Review all detections, especially:
- High severity alerts (5+ suspicious processes)
- Processes from truly suspicious locations (/tmp outside home)
- Deleted executables
- Fake system process names

### Permissions

Some process information may require elevated privileges:
- Process command lines are readable by all users
- Process UIDs are readable by all users
- Some `/proc` entries may be restricted

**Note**: Running as root is not required for basic functionality.

### When to Investigate

Investigate immediately if you see:
1. **Deleted executables** - Almost always malware
2. **Truly suspicious /tmp usage** - Executables in system /tmp (not ~/.cache/tmp)
3. **Multiple unknown processes** - Pattern of unusual activity
4. **Processes with shell metacharacters** - Injection attempts

Don't panic over:
1. Steam/game client processes
2. VS Code extensions
3. Snap/Flatpak apps in unusual paths
4. Development tools

## Performance

- Scanning 500+ processes typically takes < 100ms
- Low memory footprint (< 10MB)
- No background processes or daemons
- Suitable for periodic scanning or integration into monitoring systems

## Integration

### Cron Job (Hourly Scan)
```bash
0 * * * * /usr/local/bin/process_monitor --no-color >> /var/log/process_monitor.log 2>&1
```

### Alert on Detection
```bash
#!/bin/bash
if ! /usr/local/bin/process_monitor; then
    echo "Suspicious processes detected on $(hostname)" | mail -s "Security Alert" admin@example.com
fi
```

### Systemd Timer
Create `/etc/systemd/system/process-monitor.service`:
```ini
[Unit]
Description=Process Monitor Scanner
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/process_monitor -v
StandardOutput=journal
StandardError=journal
```

Create `/etc/systemd/system/process-monitor.timer`:
```ini
[Unit]
Description=Run Process Monitor hourly

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
```

Enable with:
```bash
sudo systemctl enable --now process-monitor.timer
```

## Troubleshooting

### Too Many False Positives?

1. **Make sure whitelist is enabled** (default):
   ```bash
   ./process_monitor -v  # Should show whitelist filtering
   ```

2. **Add your applications to whitelist**:
   ```bash
   ./process_monitor --add-whitelist-name your_app
   ```

3. **Check verbose output** to see why something is flagged:
   ```bash
   ./process_monitor -v
   ```

### No Processes Found?

- Check permissions: `ls -la /proc/1`
- Run with sudo for complete access (usually not needed)
- Verify /proc is mounted: `mount | grep proc`

### Compilation Errors?

- Ensure C++17 support: `g++ --version`
- Install build tools: `sudo apt install build-essential`
- Clean and rebuild: `make clean && make`

## Development

### Building Debug Version
```bash
make debug
```

### Running Tests
```bash
# Test with whitelist
make run-verbose

# Test without whitelist (see all detections)
make run-no-whitelist
```

### Code Structure
- **process.h/cpp**: Core monitoring logic and whitelist system
- **utils.h/cpp**: Utility functions including home directory detection
- **main.cpp**: CLI interface and output formatting


## License

This software is provided as-is for educational and security research purposes.

## Disclaimer

This tool is for legitimate security monitoring and research only. Users are responsible for compliance with applicable laws. Always obtain authorization before scanning systems.

## Author

Yusifzade Azer

January 2026
