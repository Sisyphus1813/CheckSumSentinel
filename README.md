# CheckSumSentinel (css)

> **Status:** A major refactor is planned soon for changes to scope and capabilities.

CheckSumSentinel (css) is a Rust project designed to automatically fetch, store, and monitor known malicious file hashes and YARA rules from open source threat intelligence feeds. It integrates with `systemd` services and timers to continuously update hash sets and provide a daemonized monitoring process that checks directories for compromised files.

---

## Installation

### Requirements

- Any systemd enabled Linux distribution
- Rust
- D-Bus (for desktop notifications)

### Steps

```bash
# Clone the repository
git clone https://github.com/Sisyphus1813/checksumsentinel.git
cd CheckSumSentinel

# Run installer
sudo chmod +x install.sh
./install.sh
```

Installation script will:

- Ask wether you intend to run the application as a monitoring service or only a oneshot scanner.
- Build the Rust binary.
- Deploy the appropriate systemd services and timers.
- Resolve SELinux context issues.
- Enable systemd automatic updates and (if applicable) background scanning.

---

## Usage

### Scanning a file

To do a single scan:

```bash
css scan /path/to/file_to_scan
```

Single scan command only takes a single file at this time -- this will be expanded to take dirs in the future.

### Monitoring Daemon

Enable continuous monitoring:

```bash
sudo systemctl enable --now css.service
```

Stop monitoring:

```bash
sudo systemctl disable --now css.service
```

### Directory Configuration

If running as a systemd daemon, css reads directories to monitor from `/etc/css/directories_monitor.json`.\
Default: monitors the current user's Downloads directory (`/home/<user>/Downloads/`).

An example file:

```json
{
  "directories": ["/home/user/Downloads", "/var/log", "/tmp/test"]
}
```

Directories are monitored **recursively**, meaning all subdirectories will also be watched for new file creation events.

---

### Update Threat Info

Manual update:

```bash
sudo css update --recent
sudo css update --persistent
sudo css update --yara
```

Flags can be combined:

```bash
sudo css update --recent --persistent --yara
sudo css update -r -p -y
```

To use `systemd` timers:

```bash
sudo systemctl enable --now css-update-recent.timer
sudo systemctl enable --now css-update-persistent.timer
```

Note that the system timers currently only update stored hashes. Yara rules must be updated manually from time to time (I reccomend once a month). Yara rule updates are not currently set up as a system service because the only polled source currently only updates sporatically. This will be mitigated or fixed in a future update.

## Data Storage

- **Hash files**: `/var/lib/css/hashes/` — All files in this directory are loaded and merged. Each file should contain one hash per line (MD5, SHA1, or SHA256).
- **YARA rules**: `/var/lib/css/yara_rules/` — All `.yar` files in this directory are compiled, saved, and used for scanning.
- **Configuration**: `/etc/css/directories_monitor.json` — JSON file specifying directories to monitor.

---

## Scan Output

When scanning files CSS reports:

- **File information**: Name, path, and computed hashes (MD5, SHA1, SHA256)
- **Hash match status**: Whether any computed hash matches a known malicious hash
- **YARA match status**: Whether any YARA rules matched, including the rule identifiers
- **Verdict**: Summary indicating whether malicious indicators were detected

In background/daemon mode, results are displayed as desktop notifications. When doing a single scan, results are printed to the console.

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository.
2. Create a feature branch.
3. Submit a pull request with detailed description.

Bug reports and feature requests are encouraged via GitHub Issues.

---

## Help wanted!!

At this stage, the project does not yet include a comprehensive or verified **testing corpus** for validation of detection accuracy. This means that while the scanning logic and rule integration have been implemented, broader real-world testing across diverse samples remains limited.

If you maintain or have access to a **reliable, well-curated testing corpus** of files suitable for open research or tool evaluation, your contribution would be invaluable. We welcome **pull requests** that:

- Introduce or reference safe, shareable sample sets
- Add reproducible test cases or corpus integration scripts
- Improve coverage or validation of rule-based and hash-based detections

Please ensure any submitted corpus data complies with applicable laws and does not contain live, active malware. The goal is to expand testing responsibly while improving the tool's accuracy and robustness for all users.

---

## Project Structure

```
├── src/
│   ├── arg.rs                      # CLI argument parsing using clap
│   ├── checks.rs                   # Performs the core functionality by computing hashes, and checking the file for either a matching malicious hash or YARA rule.
│   ├── daemon.rs                   # Handles the filesystem watcher component
│   ├── data_handling.rs            # Manages configuration, loading monitored directories, known file hashes, and compiling YARA rules from stored sources
│   ├── main.rs                     # Serves as the program entry point
│   ├── poll_sources.rs             # Fetches malicious hash feeds and YARA rules from remote sources
│   └── user_notification.rs        # Handles sending desktop notifications and returning results to console
│
├── systemd/
│   ├── no-daemon/                         # Alternative unit files if you don't want to run the watcher daemon
│   │   ├── css-update-persistent.service  # Service triggered by persistent.timer — updates full hash set
│   │   └── css-update-recent.service      # Service triggered by recent.timer — updates only recent feeds
│   │
│   ├── css-update-persistent.service # Service triggered by persistent.timer — updates full hash set
│   ├── css-update-persistent.timer   # Timer: runs daily to refresh persistent hash feeds
│   ├── css-update-recent.service     # Service triggered by recent.timer — updates only recent feeds
│   ├── css-update-recent.timer       # Timer: runs every 3 hours to refresh recent hash feeds
│   └── css.service                   # Long-running systemd service for the `checksum-sentinel` watcher binary
│
├── Cargo.lock                        # Rust lockfile: pins exact dependency versions
├── Cargo.toml                        # Rust project manifest and dependencies
├── install.sh                        # Installer script: builds binary, moves systemd units, enables timers, fixes SELinux labels
└── README.md                         # Project documentation (this file)

```

---

## Security Notes

- CheckSumSentinel does **not** differentiate between Windows/Linux malware; it currently only notifies you when a known malicious hash or file with a matching YARA rule is found, regardless of target platform. At present it does not move files to containment. Work is in progress to integrate CheckSumSentinel with SELinux and AppArmor to automatically move files to containment if they are flagged with bad hashes or matching YARA rules.
- All services must run as **root** to monitor system-wide directories and write to /etc/ and /var/ directories.
- Desktop notifications require a running D-Bus session; if unavailable, results are logged instead.

---

## License

This project is licensed under the GNU General Public License (GPL v3).\
See the [LICENSE](LICENSE) file for full details.
