# COC USB #2 — response and reconstruction

Release 0.10.1 extends the installed DFIR toolkit. USB #1's approved centered COC menu, case core, root launcher, Ventoy layout and boot images are preserved. Open **COC-Technician-Menu.cmd → Automated playbooks → 7. Response / reconstruction playbooks**. The new **Automated playbooks → 8** operations manager adds guided incidents, harmless practice, handoff, freshness and generated-log retention; see OPERATIONS-MANAGER.md. It is included in the same installer 16, not a separate update.

## Automation already included

The toolkit already includes assessment/incident/practice playbooks, acquired-evidence batch analysis, incident timelines, case intake and closeout, specialist offline investigations, email/URL/cloud review, and advanced APK/YARA/configuration/similarity workflows. These remain available. This release adds six bounded response profiles rather than replacing working playbooks.

Every Windows response profile uses the existing case engine: authority reference, RUN confirmation, separate protected destination, run lock, activity log, run metadata, source inventory where applicable, findings, HTML report, artifact hashes and verification. A failed/unsupported parser remains PARTIAL. Completing a parser does not establish that an incident investigation is complete. These are selected workflows, not an unattended all-tools sweep.

| New menu selection | What actually runs | Limits |
|---|---|---|
| Automated server incident runbook | Inventory/SHA256 → access-log parsing → coverage/count review → source recheck → case closeout/report | Acquired access logs only; analyst follow-up is documented, not silently executed |
| Server log review | IIS W3C `#Fields:` and Apache/Nginx combined format; JSON, CSV, counts and rejected-line coverage | 1–20 text logs, 16 MiB each, 100,000 lines; custom log formats remain unsupported |
| Python-package extraction | COC bounded CArchive parser; indexed `.bin` members and original-name/hash map | One file ≤64 MiB; 2,000 members; 128 MiB expanded; no sample execution, unmarshal or recursive PYZ decoding |
| Container image review | Existing Dissect opens acquired Docker/OCI tar and extracts users | One ordinary image tar; 5,000 records; no container startup or live engine queries; compatible OS required |
| Case correlation | Verify 2–10 finalized COC cases before/after; exact SHA256/IPv4 text links, selected CSV timestamp events | 5,000 input files/8 GiB; text files ≤4 MiB; 20,000 occurrences/events; not a universal timeline importer |
| LIVE host snapshot | Portable osqueryi, eight fixed bounded queries | Separate LIVE confirmation; system/OS/processes/listeners/connections/services/startup/users; 5,000 rows/query; table/permission coverage varies |

The live profile launches only osqueryi. It installs no daemon/service, event publisher or extensions. Query SQL is fixed in `response_pipeline.py` and saved in the case. No arbitrary SQL or remote enrollment is offered. Running any live tool changes host state; this is triage, not a forensic image. The full live collection has not been run on the owner's host. Only version startup and a constant synthetic SQL query were exercised.

Server records preserve original timestamp text, source hash and line. IIS W3C timestamps use that format's UTC convention; combined logs use their explicit offset. Neither proves the host clock was accurate. Correlation keeps unknown/naive/ambiguous times unknown, preserves original records and records no inferred clock adjustment. Shared indicators are investigative leads, not attribution or maliciousness verdicts. CSVs are data: import as text in spreadsheet software to avoid interpreting evidence as formulas.

## Python extractor readiness

PyInstaller Extractor NG 2026.07.03 is included with upstream source and GPL license. Native help and information-only inspection passed on the harmless fixture after selecting a writable temporary folder; default session temporary storage had initially failed. Full upstream extraction remains supervised-lab only and unaccepted. The COC automated extractor is independent: it validates all CArchive entries, rejects unsafe names and symlink/unknown entry types, bounds decompression and writes indexed outputs. Original module names remain metadata. Nested PYZ archives stay opaque for later examination in an isolated analysis lab. Extracted data must never be double-clicked or imported.

## Offline lab packages: actual payloads, separate host

`COC/lab/Offline-Analysis/` now contains actual pinned Linux/amd64 OCI image archives for **Zeek**, **Suricata**, and **Plaso**, not just download links. `images.json` records repository, immutable manifest/config IDs, archive SHA256 and provenance. Zeek and Plaso come from project publisher repositories. Suricata comes from the **jasonish community-maintainer image**, not an OISF-signed image. Digests establish byte integrity; no image-signature verification is claimed. Layer contents were inspected statically for expected executable paths.

The supplied `coc-lab-analyze.py` requires a separately prepared **non-root Linux account, Python ≥3.11 and rootless Podman**. No engine is installed by the toolkit. No WSL/VM is started on this workstation. Loading an image changes the analysis host's container storage; logs record the operation. Reserve at least 5 GiB in the case destination plus separate engine storage. Use a maintained, isolated analysis host; these restrictions do not make containers a malware detonation sandbox.

Commands accept one acquired file ≤2 GiB, a case ID, authority and existing protected case parent outside the toolkit. Use absolute paths. Copy the practice PCAP to a separate working-input folder first. Examples on that Linux host, with paths adjusted to its mount point:

```text
python3 /media/usb/COC/lab/Offline-Analysis/coc-lab-analyze.py zeek --input /cases/input/capture.pcap --output-parent /cases/output --case-id CASE001 --authority "Owner incident authorization" --run

python3 /media/usb/COC/lab/Offline-Analysis/coc-lab-analyze.py suricata --input /cases/input/capture.pcap --output-parent /cases/output --case-id CASE001 --authority "Owner incident authorization" --rules /media/usb/COC/lab/Offline-Analysis/emerging-open.rules --run

python3 /media/usb/COC/lab/Offline-Analysis/coc-lab-analyze.py plaso --input /cases/input/working-image.img --output-parent /cases/output --case-id CASE001 --authority "Owner incident authorization" --run
```

The runner verifies the archive, loads it and checks its immutable image ID before analysis. Fixed commands use readonly evidence/root filesystem, no network, no capabilities, no new privileges, no host devices/ports, rootless identity, limited CPU/memory/PIDs, bounded temporary storage and a case-only writable bind. Zeek reads PCAP; Suricata reads PCAP with explicitly selected local rules; Plaso creates storage and exports a CSV with psort. The runner enforces a 15-minute step/2 GiB output cap, removes only its named container, rehashes source and writes result/report/artifact manifest. Engine image caches remain on the analysis host for deliberate owner management.

ET Open Suricata 8.0 rules are included as a pinned publisher-HTTPS snapshot. Review the rule file/license and date before operational use; rule compilation and coverage have **not** been runtime-tested here. The separate COC practice rule matches only example.invalid DNS and is for harmless validation. Rules are never refreshed online during a run. Zeek `-C` ignores checksum mismatches typical of acquired captures; analysts must record that choice when checksum evidence matters.

## Verification and acceptance

Local validation covers synthetic access logs, safe and unsafe CArchive cases, a synthetic Linux container user record, finalized-case correlation, restricted command planning, osquery version/constant-query startup, Windows case artifacts and updater copy safeguards. See `COC/manifests/response-validation.json`.

Pending: rootless Podman image load/actual Zeek/Suricata/Plaso processing on a compatible lab host; ET Open rule compilation; full LIVE host table coverage; arbitrary real evidence and native upstream extractor readiness. Previously documented capa/Cutter/ExifTool/RegRipper/hashdeep/ClamAV limitations remain. No boot testing is required or performed on the owner's systems. Nothing here authorizes input execution, live packet capture, raw-disk acquisition, credential collection, containment or cloud upload.

Lab acceptance: on a disposable prepared Linux host, copy the harmless practice PCAP outside the toolkit; run Zeek and Suricata with the COC practice rule; check DNS/HTTP outputs and example.invalid alert, source hash and artifact manifest. Run Plaso against a known harmless acquired fixture and inspect timeline/CSV; confirm networking is disabled and host input unchanged. Record actual engine/image versions and failures. Keep status pending until these operations succeed; static command tests cannot establish runtime readiness.

## Sources

- osquery portable shell and flags: https://osquery.readthedocs.io/en/stable/introduction/using-osqueryi/ and https://osquery.readthedocs.io/en/latest/installation/cli-flags/
- PyInstaller Extractor NG: https://github.com/pyinstxtractor/pyinstxtractor-ng
- Dissect supported targets: https://docs.dissect.tools/en/latest/supported-targets.html
- Zeek project image: https://hub.docker.com/r/zeek/zeek
- Suricata community image: https://github.com/jasonish/docker-suricata
- Plaso image build: https://github.com/log2timeline/plaso/tree/main/config/docker
- ET Open snapshot: https://rules.emergingthreats.net/open/suricata-8.0/emerging.rules.tar.gz

## Update and rollback

Run the matching workstation `16-INSTALL-RESPONSE-PLAYBOOKS.cmd` only after the release is prepared. The updater verifies the known Lexar identity, existing Ventoy layout, installed 0.9 baseline, every changed source/target ownership and space. It backs up replaced owned files, preserves unknown edits, copies additively, commits the manifest last and reads changes back. Minimum free reserve: 10 GiB. No boot partitions, disk layout, USB #1 or other drives are modified. A failed copy is diagnosed/resumed against known hashes; do not format or rerun the original installer. Backup contains the previous manifest and replaced files; restoration requires review of exact installed/backup hashes before any rollback writes. No automatic rollback deletes new files.
