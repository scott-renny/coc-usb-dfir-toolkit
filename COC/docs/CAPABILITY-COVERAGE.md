# USB #2 capability map

Purpose: digital forensics, incident response and malware examination. USB #1
remains the general technician/recovery drive. This toolkit supplies offline
analysis and authorized acquisition options; it is not a deployed SOC or a
universal evidence repository. Refer to field-readiness.json for each tool's
actual acceptance status. Packaging is not proof of operational readiness.

| Investigation need | Included routes and tools |
|---|---|
| Windows artifact parsing | Zimmerman parsers, Registry Explorer, RECmd, Dissect |
| Event hunting and timeline review | Hayabusa, Chainsaw, Sigma, Takajo, Timeline Explorer |
| Collection and triage | Velociraptor, DFIR-ORC, Acquire; authority gates remain required |
| Linux/Unix collection | UAC and acquire-only AVML variants; unexecuted transport packages |
| Windows and Linux text/configuration examination | Existing persistence/Linux reviews and native artifact parsers |
| Memory | Volatility 3, selected Windows symbols, WinPmem; MemProcFS transport |
| Disk images and recovery | FTK Imager and Autopsy installers; CAINE/SIFT environments; acquisition acceptance pending |
| Browser and mobile | Hindsight, ALEAPP/iLEAPP and browser-profile workflow |
| Email and phishing | Bounded EML/PST/OST review, new MSG review, Unfurl URL interpretation |
| Document and script examination | oletools, Didier Stevens tools, decoded-data workflow |
| Executable and managed-code examination | Ghidra/Java, DIE, PE-bear, dnSpyEx, FLOSS, GoReSym, ImHex |
| Live process examination | Existing supervised process tools; host changes and authority considered separately |
| Isolated dynamic analysis | REMnux, FakeNet-NG, debuggers; use separate authorized lab, never automatic detonation |
| Network evidence | Wireshark/TShark, NetworkMiner, fixed offline PCAP summaries |
| SQLite and RDP artifacts | SQLite Dissect working-copy/WAL workflow, bmc-tools |
| Cloud incidents | New AWS/Microsoft export review; no live cloud collection, login or API integration |
| Ransomware | New descriptive file/note triage plus existing timeline/static tools; no universal decryptor claim |
| Correlation and case administration | Existing comparison, verified transfer/resume, closeout and COC metadata export |
| Coverage and verification | New supplied-evidence coverage report, release manifests, case artifact verification |

## Combined expansion

The advanced submenu adds JADX/Apktool for Android application examination,
PhotoRec working-image carving, an Apple UnifiedLogs parser, YARA Forge full
signatures, fixed MWCP/Malduck plaintext indicators, TLSH comparison and pinned
ATTACK/LOLBAS search. Cutter and Thumbcache packages are also included with their
actual readiness limits. See COMBINED-FIELD-TOOLS.md before using these entries.
The complete package includes the held enrichment update directly from installed
0.7.0; update 14 is superseded by the combined installer.

## Intentional boundaries

- Preserve the 10 GiB minimum free-space reserve; large images and VM working
  disks belong on a separate protected evidence/analysis volume.
- Do not add another copy of a suite merely because a VM already contains it.
  Native offline tools are worthwhile where they avoid needing that VM.
- No malware specimen library, automatic sample execution, credential theft,
  password attacks, network exploitation or public sample upload workflows.
- No universal ransomware decryption bundle: applicability must match the family
  and a verified copy of evidence. Never attempt repair/decryption on originals.
- Enterprise servers, paid/licensed tools and tools requiring owner accounts are
  not silently installed or represented as ready.
- capa, ExifTool, ClamAV, RegRipper and hashdeep retain their documented runtime
  limitations. Adding a package does not remove an earlier blocked status.
- Boot testing is excluded at the owner's request. Real memory, mailbox varieties,
  acquisition and VM acceptance remain separate checks on authorized equipment.

## Source references for the new review logic

- Microsoft process-creation event 4688:
  https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4688
- AWS CloudTrail record format:
  https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
- Microsoft Graph sign-in schema:
  https://learn.microsoft.com/graph/api/resources/signin?view=graph-rest-1.0
- CISA ransomware response and volatile-evidence guidance:
  https://www.cisa.gov/stopransomware/ransomware-guide

Source references explain field semantics; they do not certify the custom code.
Local validation and remaining gaps are recorded in enrichment-validation.json.

## Response and reconstruction expansion

Release 0.10 adds bounded Python CArchive extraction, fixed-query authorized osquery live snapshots, access-log review and server runbook, Dissect container users and finalized-case correlation. Actual pinned offline Zeek/Suricata/Plaso images and ET Open rules are staged with a separate Linux rootless-Podman runner. See RESPONSE-PLAYBOOKS.md and response-validation.json. Native PyInstaller Extractor NG help/info passed; full upstream extraction and lab/full live queries remain unaccepted. Existing menu style and capability limitations are preserved.

## Field operations usability and retention

Prepared 0.10.1 also adds guided offline incident steps, three harmless expected-result practice checks, evidence handoff templates, an offline rules/tool freshness dashboard and a generated-case-log manager. Cleanup requires preview, selected paths, typed plan confirmation and a verified full original-case archive; manifests and audit lineage are retained. No owner log cleanup has run. See OPERATIONS-MANAGER.md and operations-validation.json.
