# Combined DFIR field expansion

Open **COC-Technician-Menu.cmd > Automated playbooks > Advanced APK / images /
logs / signatures**. The preceding Specialist field review submenu retains the
prepared URL, MSG, decoding, execution, remote-access, cloud, ransomware-file and
coverage workflows. All are included in one update from installed release 0.7.0.

## New package readiness

| Tool | Included behavior | Acceptance boundary |
|---|---|---|
| JADX 1.5.6 | Native CLI decompilation, supervised GUI entry; existing portable Java | Known generated Java JAR decompiled with expected marker. GUI and real APK DEX acceptance pending. |
| Apktool 3.0.3 | Decode-only acquired APK manifest review | Generated binary Android manifest parsed with expected package and permission. No APK installed or executed. |
| Cutter 2.5.0 | Complete official Windows distribution and guide | Startup failed with exit 3236495362; reference-only, no automatic launch or policy workaround. Bundled VC redistributable was not run. |
| TestDisk / PhotoRec 7.2 | Official Windows distribution; fixed RAW-image-only PhotoRec profile | Session requires elevation; actual carving/partition examination not accepted here. No automatic TestDisk launch. |
| Apple UnifiedLogs iterator 0.7.0 | Offline acquired logarchive parsing | Help/startup passed; missing companions refused. Real logarchive decoding not accepted. |
| YARA Forge full 20261011 | Full rule set with fixed offline scanner | Rules compiled and harmless input scanned. Neither matches nor absence establish a verdict. |
| MWCP 3.16.1 / Malduck 4.4.1 | Isolated Python packages and fixed static COC parser | Known plaintext URL reported through MWCP; Malduck hashes and optional PE structure. No universal malware-family extraction, arbitrary plugins, decryption or emulation. |
| TLSH Java | Pinned Trend Micro implementation, built with bundled JDK and fixed helper | Identical files produce distance zero; changed fixture produces nonzero distance. Small/low-variation inputs explicitly unsupported. |
| Thumbcache Viewer GUI 1.0.4.0 / CMD 1.0.2.1 | Official Windows tools, source/license notes | CMD startup and invalid database refusal observed. Valid-cache and GUI acceptance pending; guide entry only. |
| MITRE ATTACK / LOLBAS | Pinned official sources and offline search | Known certutil reference found. Descriptions/examples remain inert untrusted text. |

Third-party code and licenses are retained. Hash provenance appears in
`COC/manifests/combined-acquisition.json`. TestDisk and Thumbcache packages have
recorded local hashes and official HTTPS provenance; independent publisher checksum
matching is not claimed for those packages. Other primary GitHub assets matched
release digests; all 64 added Python distributions matched PyPI SHA-256 metadata.

## Automated operations

- **APK**: 1-5 files, 64 MiB each, at most 2000 ZIP members/256 MiB expanded data.
  Reject duplicate/traversing/link paths and excessive compression ratios. Decode
  manifests with Apktool and inspect package/permissions. If DEX exists, invoke
  the fixed JADX CLI, never its GUI main class. APK signature entries are an
  inventory only, not signature validation. No APK rebuild, installation or execution.
- **Carve**: exactly one regular acquired RAW working-image file, extension .img,
  .dd or .raw, maximum 2 GiB. Whole-image signature carving to a separate case
  output. No raw-device path, partition rewrite or source repair. Requires an
  already elevated authorized session; the menu does not elevate itself. This
  workflow is implemented but real carving acceptance remains pending.
- **AppleLogs**: up to 2000 files/8 GiB, acquired complete logarchive with tracev3,
  timesync, dsc and UUIDText companions. Native parser uses log-archive mode only,
  JSONL output and a case-local bookmark. Empty output is incomplete. Privacy
  redaction and unsupported Apple objects cannot be reconstructed by this toolkit.
- **YaraFull**: 1-20 acquired files, 16 MiB each. Recompile the pinned full rules
  within the bounded worker, 60-second match timeout, at most 200 matches per file.
  Large rules increase latency; use existing fast screening for ordinary triage.
- **Config**: 1-20 files/16 MiB each. Fixed MWCP COC parser extracts up to 100
  plaintext HTTP(S) strings; Malduck computes SHA-256 and reads PE structure if
  present. No URL requests, malware execution, family-specific decoding, user
  plugins or automatic recursive extraction. Unknown/obfuscated configurations
  remain outside this fixed parser's coverage.
- **Similarity**: 2-20 files/16 MiB each, official TLSH Java 128-bucket default.
  Distances are comparative leads. Exact input SHA-256 values remain in inventory;
  TLSH does not replace integrity hashes and a threshold is not attribution.
- **Reference**: a 1-128 character phrase; search pinned ATTACK techniques and
  LOLBAS records locally. At most 100 results with truncation labelled. No command
  examples execute and no external reference URL is visited.

External steps have 120-second timeouts (carving 300), 256 MiB per-step output
guards and a 15-minute batch scheduling cap. Java heaps are limited to 256-768 MiB.
Case output is checked against a 2 GiB cap between steps. The output watchdog is
periodic, so quotas are not strict operating-system limits. Use a protected analysis
volume with adequate reserve; this is static parsing, not a malware sandbox.
Source hashes are compared before and after successful analysis. Any failure stays
PARTIAL with logs. Existing Core generates activity logs, reports and artifact hashes.

Java/native tools may leave ordinary host execution artifacts. Runtime caches and
working directories are redirected into the case where supported; no forensic
sterility or zero-host-write guarantee is made. Review hostile input on an isolated
analysis workstation. GUI internal actions are supervised and not automatically logged.

## Scope retained

The shared console-layout module, root CMD and Core module are unchanged. Existing
boot images, SIFT, REMnux, tools and unknown USB files are preserved. Old blocked
statuses for capa, ExifTool, ClamAV, RegRipper and hashdeep are not cleared.
KAPE remains excluded pending appropriate licensing. Speakeasy/another VM and
bulk unreviewed symbol packs were deferred as documented in the selection plan.
No live malware library, sample execution, boot testing, VM import, security-policy
change, driver or service installation was performed.

## Reproducibility and practice

`COC/practice/advanced` contains generated harmless APK/JAR/config/similarity
fixtures. The APK contains a compiled binary manifest and no application code;
JADX decompilation is separately tested against the generated Java JAR. No mobile
device, emulator or Android OS is needed or used. TLSH upstream sources and the
fixed Java helper are retained for audit; no Gradle build hooks were run.

Source projects: https://github.com/skylot/jadx ; https://github.com/iBotPeaches/Apktool ;
https://github.com/rizinorg/cutter ; https://www.cgsecurity.org/ ;
https://github.com/mandiant/macos-UnifiedLogs ; https://github.com/YARAHQ/yara-forge ;
https://github.com/dod-cyber-crime-center/DC3-MWCP ; https://github.com/CERT-Polska/malduck ;
https://github.com/trendmicro/tlsh ; https://thumbcacheviewer.github.io/ ;
https://github.com/mitre-attack/attack-stix-data ; https://github.com/LOLBAS-Project/LOLBAS
