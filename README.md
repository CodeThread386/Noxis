# Security Guardian (Noxis) — Ransomware Early Warning Prototype

This project implements a **behavior-based ransomware early warning system** for Android.

## What works (core deliverables)

- **Behavior-based detection framework**
  - Detects **ransom-note drops**, **suspicious extension renames** (e.g. `.encrypted/.locked`), **burst mass modifications**, and **high-entropy overwrite patterns** (encryption-like writes).
  - Monitors:
    - App-accessible storage (app private + app external folder) continuously
    - Optional **user-selected folder** via Storage Access Framework (SAF) with persisted permission

- **Real-time alerting**
  - Runs as a **foreground service**: `RansomwareDetectionService`
  - Writes alerts to Room as `ThreatEvent(type="RANSOMWARE")`
  - Shows alerts in the app under **Threats** and **Ransomware** tabs

- **Prototype recovery**
  - Stores a rolling backup copy (best-effort) for files it can read before suspicious changes.
  - Rollback is supported where the app has write access (app-scoped files, and some SAF URIs if granted).

- **Evaluation harness**
  - `RansomwareTestActivity` generates benign vs ransomware-like bursts in app external storage to validate detection and measure responsiveness.

## How to run

1. Open in Android Studio
2. Sync Gradle
3. Run on a device (recommended; emulator works but file behavior differs by OEM)
4. In the app:
   - Go to **Ransomware** tab
   - (Optional) Pick a folder to monitor (SAF)
   - Open **Test harness** and generate ransomware-like burst
   - Watch **Threats** tab populate with `RANSOMWARE` detections

## Release APK

In Android Studio: **Build → Generate Signed Bundle / APK…**

Or command line (needs JDK + `JAVA_HOME` set):

```bash
./gradlew assembleRelease
```

