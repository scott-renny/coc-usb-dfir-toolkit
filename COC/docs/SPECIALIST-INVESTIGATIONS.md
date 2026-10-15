# Specialist offline investigations — USB 02

Open **COC-Technician-Menu.cmd > Automated playbooks > Specialist offline investigations**. The approved emblem, colors and centering are retained. These workflows use acquired working copies, separate protected output storage and one owner authorization reference. Nothing here installs a host driver, boots a system, executes an evidence attachment or uploads a case.

## Available workflows

| Menu | Workflow | Boundaries and outputs |
|---|---|---|
| 1 | Email / phishing, PST and OST | EML headers, text excerpts, URL/domain/email/IP strings, hashed attachments, Office/PDF screening. libpff worker inventories up to 500 messages and extracts up to 100 attachments / 50 MiB. Per attachment: 25 MiB. EML: 25 MiB/message. MSG containers, deleted-mail recovery and cryptographic email-authentication verification are not implemented. |
| 2 | Linux evidence review | Text/JSON journal exports, auth/secure/audit logs, cron, systemd definitions, sshd configuration, authorized_keys and shell history. Source path and line retained. Binary journals and compressed rotations are explicit gaps. No Linux collector is run. |
| 3 | Windows persistence review | Acquired text, CSV, JSON, XML and REG exports: Registry startup, services, scheduled tasks, startup folders and selected event references. A matching string is a review lead, not maliciousness. Binary hives require existing RECmd/RegistryExplorer examination first. |
| 4 | Cross-case comparison | Select a parent of 2–10 finalized cases. Verify each case, then compare exact hashes, filenames, domains, email addresses, IPv4 addresses and URLs with source references. Maximum combined verification scope: 16 GiB. Comparison input and new case output must be separate trees. Common names/domains are weak leads, not attribution. |
| 5 | COC handoff export | Verify one finalized case and copy selected reports/metadata into a new COC-handoff folder. Original status and original artifact-manifest hash remain explicit. A separate handoff manifest covers the exported files. This is a generic offline package, not a deployed COC API connector. Raw evidence is not copied or uploaded. |
| 6 | Restartable verified transfer | Select an acquired source and a separate protected staging folder. Initially the staging folder must be empty. Later runs require its exact original scope/state and verify completed files before skipping them. Mismatches and unexpected owner files are preserved. Recovery is by completed file, not by byte offset. Partial files are retained. The receipt records authority, hashes, destination and clock uncertainty; it is unsigned. A stale lock requires owner inspection. |
| 7 | SQLite Dissect | Parse verified working copies of SQLite and WAL/SHM/rollback companions. Strict format checks remain enabled; no carving by default. Working set capped at 128 MiB. The original database files are not opened for writes. |
| 8 | RDP cache | ANSSI bmc-tools parses acquired bcache*.bmc / cache????.bin. Input cap: 128 MiB; 1,000 bitmap tiles per file. No generated images means coverage is not established. Cache images alone do not establish the user, remote endpoint, session time or action. |
| 9 | Offline Windows memory | Existing Volatility 3, offline mode, selected JPCERT/CC symbols, case-local cache and JSON process listing. Up to four acquired files / 32 GiB. Exact symbol matching is required; missing symbols or unsupported images remain failures. No memory acquisition or host process scanning. |
| 10 | Takajo investigation views | Validate Hayabusa JSONL schema, then produce computer stacking and scheduled-task timelines. EVTX inputs are first converted with the existing Hayabusa using JSONL/super-verbose output. No VirusTotal, web server or credential-extraction commands are exposed. |
| 11 | Takajo process tree | Same offline input path, plus one explicitly entered Sysmon process GUID. Only the fixed process-tree command is allowed. Requires relevant Sysmon process-creation records; generic logs cannot supply them. |
| 12 | Practice | Generate entirely synthetic email, Linux auth log, persistence export, SQLite database, RDP bitmap cache, Hayabusa JSONL and DNS/HTTP PCAP in a new synthetic case. Run parsers and check expected observations. No network packets are sent and no executables from fixtures are run. |
| 13 | This guide | Documentation only. |
| 14 | SQLite recovery carving | Same protected working-copy process, with explicit carving/freelist flags. Upstream marks some recovery features under development. A completed run does not guarantee deleted records were recovered. Preserve CSVs, logs and source hashes for review. |

Most acquired input folders are limited to 200 files / 8 GiB. EML analysis is capped at 128 MiB combined, with bounded header/body excerpts. Text examination is capped at 2 MiB/file and 10,000 observations. Individual parser processes have a 120-second timeout and a 256 MiB output cap; parser batches stop at the case-output budget. Excess scope is recorded as unsupported/PARTIAL. Select smaller working sets when needed. Case protection is owner attestation, not an automatic encryption check.

## Reports and evidence preservation

The established activity.log, errors.log, events.jsonl, run.json, summary.json, report.html and artifact-manifest.json remain in use. New raw outputs include findings.html/findings.json, indicators.json, parser stdout/stderr, transfer-receipt.json, practice-assertions.json or the COC-handoff package. These files are case data and must remain protected.

COMPLETE means the selected operation completed within its scope. It does not mean a device is clean, an indicator is malicious, an original PARTIAL case is repaired or evidence custody is authenticated. Reports preserve coverage gaps and original statuses. HTML observations are escaped and have a restrictive content policy. Third-party CSV/log output is untrusted; review formula-like cell values before opening raw CSVs in spreadsheets. Do not edit finalized case files; create a new closeout/review run.

## Packages and acceptance

- **Takajo 2.16.1:** official Windows package, fixed offline commands. Help and synthetic computer/task analysis were exercised. Process-tree mode and native-EVTX conversion require case-specific acceptance; they are not claimed as fully validated against real incident logs.
- **SQLite Dissect 1.0.0:** official PyPI wheel and dependencies in a separate InvestigationPackages folder. Existing Python packages are not replaced. Basic database and initialized-database WAL/recovery acceptance are tracked in specialist-validation.json. A newly initialized database whose base header still has encoding zero failed in the upstream parser and remains an explicit limitation. Some upstream Python syntax warnings remain in stderr and are not silently removed. Evidence headers are not repaired or strict checks relaxed.
- **libpff-python 20260926:** official compatible Windows wheel. Import and invalid-file refusal were exercised. No known-valid PST/OST evidence fixture was available, so successful real mailbox parsing/attachment extraction is not certified.
- **ANSSI bmc-tools:** pinned publisher commit and license. A generated RDP8 cache produced the expected synthetic bitmap. This is format-level acceptance, not reconstruction of a real remote session.
- **Windows symbols:** pinned JPCERT/CC collection with 298 schema-validated ntkrnlmp/tcpip tables. This is a selected collection, not every Windows build. Volatility is forced offline and uses case-local cache storage.
- **MemProcFS 5.19:** official ZIP under COC/lab/MemProcFS. Transport only. No host installation, mounting, DMA use, live-memory access or driver acceptance was performed. Use a separately prepared authorized analysis workstation with publisher dependencies reviewed there.
- **SIFT:** complete publisher OVA under COC/lab/SIFT. It matched SANS SHA-256 **69960210f92f2329ea69c648c971c23d6bd42568de66586ee4b8273797b9c860**, and the staged copy matched too. VM import/startup and forensic acceptance remain untested. Do not connect an imported appliance to production networks before separate lab preparation and credential review.

Prior capa/ExifTool/ClamAV/RegRipper/hashdeep limitations remain in the readiness records. New packages do not remove or bypass those restrictions. USB 01 remains the general support/recovery drive. USB 02 owns acquired-evidence investigation and documented handoff. Boot testing on the owner's systems remains excluded.

## Sources and provenance

- https://github.com/Yamato-Security/takajo/releases/tag/v2.16.1
- https://github.com/dod-cyber-crime-center/sqlite-dissect
- https://pypi.org/project/sqlite-dissect/1.0.0/
- https://github.com/libyal/libpff
- https://pypi.org/project/libpff-python/20260926/
- https://github.com/ANSSI-FR/bmc-tools
- https://github.com/JPCERTCC/Windows-Symbol-Tables
- https://github.com/ufrisk/MemProcFS/releases/tag/v5.19
- https://www.sans.org/tools/sift-workstation

The specialist acquisition, wheel-digest, symbol and validation manifests record exact versions and limits. GitHub/HTTPS provenance and local hashes are not equivalent to a signed release or an authenticated chain of custody. Keep the trusted-workstation manifest digest independently.
