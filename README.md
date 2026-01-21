# Security Guardian (Noxis) — Behavior-Based Ransomware Early Warning for Android

Defense-in-depth prototype focused on non-root behavior detection, network interception, and rapid response.

## Key capabilities (implemented)
- **Network interception (VpnService, Kotlin)**: SNI/DNS/HTTP-level ad/tracker/malicious domain blocking; PII leak regex detection; download buffering with size/entropy heuristics.
- **Download monitoring (DownloadManager, Kotlin)**: Tracks all downloads, inspects file magic/entropy/ransom-note patterns/filenames, quarantines suspicious files (SAF when available, local fallback).
- **File system surveillance (FileObserver, Kotlin)**: Monitors shared/public folders; entropy sampling on modifications; honeypot files as tripwires; snapshots via SAF/local before risky writes.
- **Behavior-based ransomware detection (Kotlin + TensorFlow Lite)**: Heuristics for mass modifications, extension bursts, high-entropy writes, mass deletes, rapid create→modify; ML classifier for confidence scoring; trusted-app whitelisting to reduce false positives.
- **File tracking & periodic scanning**: SHA-256 tracking of all downloads; hourly rescans of common user dirs; threat events on suspicious findings.
- **Quarantine & response (best-effort)**: Network isolation via VPN blocklist; attempt to stop background processes; app-data quarantine (SAF snapshot/local copy); threat state persisted.
- **Package/permission oversight**: Install/replace/remove broadcast watcher; flags suspicious permissions (overlay, delete-packages, admin); APK sanity checks (magic bytes, size).
- **UI & notifications (Material Design)**: Dashboard, Threats list/detail with evidence, Protection toggles (realtime/VPN/ransomware/ad-blocker/max-detection), Network insights (blocked domains, PII leaks, ad stats). Foreground notifications for detections.
- **Persistence**: Room DB for threat events and snapshot metadata (with structured ThreatEvidence); SharedPreferences for stats/toggles/blocklists/quarantine info; app-private quarantine store; SAF-backed copies when permitted.

## Not fully implemented / limitations
- **Threat intelligence**: Only minimal in-memory domain seeds; no persistent TI DB, no hash/IP reputation feeds, no cloud sync.
- **Install blocking**: Android restrictions prevent pre-install blocking; alerts only.
- **Process termination/uninstall**: Full reliability requires Device Owner/Admin; no root. System apps cannot be stopped.
- **HTTPS visibility**: Domain/SNI/metadata-based; payload not decrypted.
- **UsageStats**: Basic hooks; not deep per-app anomaly scoring.

## Architecture overview
- **Core services**: RansomwareProtectionService (orchestrator); VPNInterceptionService (network enforcement).
- **Detection engine**: Behavior heuristics + TensorFlow Lite classifier; trusted-app filtering.
- **Monitoring modules**: Download monitor; File system monitor with honeypots and snapshots; File tracker with periodic scans; Package monitor; PII leak tracker.
- **Data layer**: Room (ThreatEvent, SnapshotMetadata + ThreatEvidence converter); SharedPreferences for live stats and toggles; SAF for snapshots/quarantine when granted.
- **UI layer**: Dashboard, Threats, Protection controls, Network insights, Threat detail actions.

## Permissions & setup
- Requires: VpnService consent, file/storage access (SAF for broader folders/quarantine/snapshots), Notifications, (optional) Accessibility for overlay detection/automation.
- Recommended: Run on a physical device for realistic storage/network behavior.

## Build & run
1) Open in Android Studio; let Gradle sync.
2) Run on device. On first launch, grant requested permissions (VPN, file access, notifications; optionally accessibility).
3) Enable Protection/Ad Blocker in the Protection tab; VPN will start for network enforcement.

Command line:
```bash
./gradlew assembleDebug   # or assembleRelease
```

## Operational flow (high level)
1) **Network ingress**: VPN intercepts traffic → domain/blocklist/YouTube ad checks → PII scan → suspicious downloads buffered/analyzed.
2) **Downloads**: Completed downloads inspected; suspicious files quarantined; all files tracked (hash + metadata).
3) **File activity**: FileObserver events + entropy sampling + honeypot trips → behavior engine + ML.
4) **Detection**: Heuristics + classifier → ThreatEvent persisted with ThreatEvidence → notification/UI.
5) **Response**: Best-effort process stop (if privileged), VPN block, data quarantine snapshot, user-facing actions in Threat detail.

## Data captured per threat
- Type/severity/confidence, indicators, structured evidence (entropy spikes, rename counts, honeypot touched, ransom-note flags, etc.), timestamps, status.

## Next steps (future work)
- Add persistent threat intelligence DB (domains/IPs/file hashes), cloud feed sync, reputation scoring/expiry.
- Deeper UsageStats-driven behavior scoring.
- Stronger install-time guardrails where platform allows.

