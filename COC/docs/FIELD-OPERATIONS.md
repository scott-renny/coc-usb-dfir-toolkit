# COC USB 02 field operations

Use COC-Technician-Menu.cmd. The approved USB 01 emblem, colors and centering are preserved.

## Six workflows

1. Automated playbooks > Case intake / closeout / toolkit readiness > Evidence intake: copy an acquired working folder into a newly created case, compare SHA-256 before/after and read back every destination. Limit: 200 files / 8 GiB. This copies file contents, not NTFS alternate streams, ACLs, deleted space or disk structure. Use an accepted acquisition tool for disk imaging.
2. Acquired-evidence automation > Combined Windows incident timeline: run the existing artifact parsers and Hayabusa against acquired working copies. CSV correlation retains the source file/row and original timestamp. Only explicit timezone offsets are normalized. Naive times remain unresolved; rows are observations, not established causation.
3. Acquired-evidence automation > Suspicious executable or document assessment: executable identification, bstrings, FLOSS, Office/PDF screening and the small local reviewed YARA set. Inputs are never executed. Rules are low-confidence review leads, not malware verdicts. YARA inputs are limited to 10 MiB; larger inputs are explicitly unsupported for that step. capa remains excluded because application control blocked it.
4. Acquired-evidence automation > Offline packet-capture assessment: capinfos, protocol/conversation statistics, DNS and cleartext HTTP request tables. DNS/HTTP stdout logs are quoted CSV; treat spreadsheet formula-like values as untrusted. TLS/QUIC contents are not decrypted. NetworkMiner remains available for supervised reconstruction; no automatic extraction of executable payloads.
5. Case operations > Case closeout: verify every listed artifact, reject unmanifested files and combine source raw CSVs into a new review run. Keep the original case untouched. The original collection status and analyst notes are retained. COMPLETE for the closeout means verification/report generation completed; it does not clear an original PARTIAL status. Limit: 50,000 artifacts / 16 GiB.
6. Case operations > Full toolkit integrity and readiness: hash every release file, including ISOs and VM/installer transport packages, and write a readiness report. This can take several minutes. It performs no tool startup, downloads or updates. Compare the release-manifest hash against the independently retained workstation reference.

All workflows require an authorization reference and an existing protected output destination outside both input and toolkit. Protection is operator attestation, not an encryption test. Normal activity, errors, structured events, run metadata, reports and final artifact hashes use the established COC format. A failure keeps partial output and produces PARTIAL status. Do not edit a finalized case; add notes through a new closeout run.

## Added packages and readiness

- bulk_extractor 2.2.0: official Windows executable matched publisher SHA256SUMS. The menu exposes a bounded email/URL feature profile using acquired file copies, two threads and restricted scanners. Help and harmless-input acceptance are tracked separately in field-startup-checks.json. Large disk images belong in a separate forensic workstation workflow.
- RegRipper: official repository pinned to a commit, application/plugins/license retained. Windows startup failed with DLL relocation error. Reference-only, no automatic launch or alternate-runtime workaround. Existing RECmd and RegistryExplorer remain the operational Registry tools.
- hashdeep 4.4: official Windows package and license retained. Windows startup failed with DLL relocation error. Reference-only. The case-transfer workflow uses the packaged Python SHA-256 implementation and is not advertised as a successful hashdeep audit.
- FakeNet-NG 3.5: official archive under COC/lab/FakeNet-NG. Transport only. Never launched by the field menu.
- FTK Imager 8.3.0.27: current official publisher ZIP under COC/installers/FTK-Imager. Installer signature evidence is bundled. This is not a portable installation and no driver, CodeMeter prerequisite or service was installed. Use a separately prepared authorized forensic workstation and review publisher license requirements there.
- SIFT: the specialist expansion now includes the complete publisher OVA, matched to SANS SHA-256 and staged-copy verification. It is transport only; see SPECIALIST-INVESTIGATIONS.md for VM and acceptance boundaries.
- Existing capa, ExifTool and ClamAV limitations remain unresolved; no security-policy bypass. Existing Velociraptor version startup passed; acquisition itself remains unvalidated.

## Acquisition and laboratory safeguards

Record case ID, authority, operator, device identifiers, source condition, source/destination, physical write-blocker details where required, start/end UTC and clock uncertainty. Hash acquired images and verify destination read-back. An ordinary USB drive and software read-only setting are not a hardware write blocker. Store disk/RAM acquisitions on separate protected case storage; preserve the toolkit's 10 GiB reserve.

FakeNet-NG belongs in a disposable, isolated malware-analysis VM. Preserve a clean snapshot; disable shared clipboard/folders and host-integrated features, detach the production/LAN/Internet network, and use a dedicated internal lab network. Import the package only into that lab, review its configuration and privileges there, and validate with benign traffic before any suspect execution. The field menu only opens this guide; it does not configure isolation or install its driver. REMnux/FLARE-VM packages and references do not establish a validated sandbox. No live malware samples are included.

USB 01 remains the general support/recovery drive. USB 02 owns acquired-evidence analysis and incident reporting. No automatic uploads to COC systems, public scanners or cloud services. Export reviewed reports through the established approved custody process. No boot testing on the owner's systems is included.

## Sources

- https://github.com/simsong/bulk_extractor/releases/tag/v2.2.0
- https://github.com/keydet89/RegRipper3.0
- https://github.com/jessek/hashdeep/releases/tag/v4.4
- https://github.com/mandiant/flare-fakenet-ng/releases/tag/v3.5
- https://www.exterro.com/ftk-downloads/ftk-imager-8-3
- https://www.sans.org/tools/sift-workstation

## Updating and rollback

The field expansion updater validates physical identity, the installed 0.5.2 baseline, source hashes and every changed destination. It preserves replaced files in a workstation backup and copies the new release manifest last. A partial update must be rerun with the same staged release; do not run old installers or format the drive. Restoration requires the verified backup and exact prior hashes. No unattended updater runs from USB 02.
