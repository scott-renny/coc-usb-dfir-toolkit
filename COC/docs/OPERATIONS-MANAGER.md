# Field operations manager

Open **COC-Technician-Menu.cmd → Automated playbooks → 8. Guided incidents / practice / handoff / log manager**. The log manager is also available directly from **Logs and reports → 2**. Shared centered menu styling, case core, boot payloads and previous playbooks are preserved.

## Guided incident selector

Choose suspected malware, phishing/email, compromised server, suspicious acquired network traffic, or acquired evidence. The selector first saves a case containing a fixed recommended plan. Each offered step requires a separate **RUN**, **SKIP** or **REVIEW** decision and its own acquired working-copy folder. Other input stops the sequence. Only allowlisted existing offline launchers/profiles are offered; no arbitrary executable, live collection, containment, remediation or automatic input execution is included.

Executed steps receive separate normal COC cases. A step is recorded completed only when its case reports COMPLETE and its artifact verification succeeds. PARTIAL cases and exceptions are recorded failed. Skipped, analyst-review and unattempted/planned steps remain explicit. The final progress case links executed case paths and manifest digests. A completed parser is not an incident-resolution verdict. If the shell is forcibly terminated, preserve the initial plan and any individual cases; a final summary may not exist.

Routes: malware → suspicious-file static assessment/configuration review; phishing → EML/email analysis and extracted URL review; server → acquired access-log runbook and event timeline; network → acquired PCAP assessment; evidence → verified file-copy intake and acquired working-copy triage. Each step can require different acquired inputs. File-copy intake does not preserve a whole disk or all NTFS metadata. Volatile acquisition and containment remain separate authorized decisions.

## One-click harmless practice check

Select an existing protected output parent, case ID and authority, then RUN. Three workflows process bundled harmless fixtures: server-log runbook, data-only Python CArchive extraction, and synthetic Linux container user examination. The runner asserts expected IP, extracted bytes and user record, rather than accepting an exit code alone. It collects native parser stdout/stderr and finalizes the practice case with logs, JSON/HTML reports and artifact hashes.

Temporary input copies are created in a tool-owned sibling folder and removed afterward. The bundled originals remain unchanged. The process performs no host inventory or live queries, no boot operation, and no container engine startup. It does not prove real-evidence, GUI, memory acquisition, upstream full extraction or offline lab engine readiness. Any failed assertion or parser remains PARTIAL.

## Evidence handoff packet

Select one finalized COC case and a separate protected output parent. The original is verified before and after packet creation and is not modified. The packet contains an evidence index, original manifest and its SHA256, case run/profile/authority/module details, staged toolkit version inventory, analyst notes, unresolved-finding reminders, recipient verification instructions and an uncompleted custody-transfer form.

The form is explicitly **NOT TRANSFERRED**. Human identities, time, method, protection, purpose and recipient verification must be completed during the actual handoff. No sending/upload occurs. Staged versions do not prove which tool binary processed a particular artifact; use each run's logs, commands and toolkit digest. Hashes establish local integrity, not authenticated custody. The packet references the original case; it is not another complete evidence copy.

## Tool and rules freshness dashboard

Creates offline JSON and HTML reports from the release, catalog, actual readiness records and pinned offline-image/rule provenance. It displays staged versions, release build time, image digests, known rule snapshot date/age and existing blocked/pending states. Upstream version/date/currency that has not been checked is explicitly UNKNOWN. Host clock accuracy is unverified; a future snapshot produces unknown age rather than a negative freshness claim.

This is an inventory-based dashboard, not a new dependency probe or vulnerability scanner. It neither downloads nor updates anything. Use the existing full toolkit integrity/readiness operation separately, and perform deliberate publisher checks on a trusted workstation when preparing an update. No tool is labelled current merely because its package is present.

## Generated case log manager

This manager does **not** clear Windows Event Logs, acquired target-system logs, evidence, build/install transcripts, arbitrary folders, reports, notes or rollback backups. It manages only a verified, finalized COC case's generated `activity.log`, `errors.log`, `events.jsonl`, and allowlisted raw parser `stdout.log`/`stderr.log`. Input/evidence/verified-copy/extracted/retention trees are excluded. There is no scheduled or automatic cleanup.

1. Choose a finalized case outside the executable toolkit. Use a **different protected parent** for the maintenance case, so the manager can exclusively lock the original case parent against normal COC sessions. Active sessions, changed artifacts, unknown files, reparse/symlink paths and non-finalized cases are refused.
2. Preview lists candidate paths, sizes and a plan digest. Default/back keeps everything. Preview creates only a separate maintenance report and uses the case-parent session lock; it removes nothing.
3. **Archive only** creates a complete ZIP of the original case, including its manifest, and verifies every member by SHA256. It keeps all originals. The ZIP uses stored entries and **is not encrypted**: choose a protected mounted archive destination. Local storage only; network archives are not enabled.
4. **Archive and clean selected generated logs** accepts displayed numbers or ALL. It shows the exact selected paths and bytes, asks for the retention reason, and requires `DELETE <full-preview-plan-digest>` typed exactly. Cancelling, an invalid selection, stale preview, failed archive or insufficient space removes nothing.
5. The complete archive is verified before any deletion. Scope: case ≤8 GiB, plus at least 1 GiB archive-destination reserve. Original file hashes and the original manifest are checked again. Only selected allowlisted log files are removed, not directories or evidence. There is no recursive deletion or shell command expansion.
6. The original manifest is preserved under a unique `retention/` subfolder alongside a cleanup receipt recording reason, time, selected paths/hashes, archive path/hash and original manifest digest. A revised current artifact manifest accounts for the documented removals and retained receipt. The revised case is verified before success is reported. The external maintenance case records both manifest digests and the archive verification.

Cleaning deliberately changes the active case's content and manifest hash. The verified archive preserves original file contents and existing case records; it is not a filesystem image and does not preserve all ACLs, alternate streams or filesystem metadata. Compare its digest with an independently retained reference when transferring it. Use **Archive only** when the original case must remain immutable. This is ordinary file removal, **not secure erasure**; flash storage and backups may retain content. Cleanup need not save space overall because the full archive remains. Archives are never silently deleted.

On an interrupted cleanup, the manager attempts to restore only missing logs that this operation removed, from its verified archive, without overwriting any file that appeared or changed. It retains an interrupted receipt and maintenance diagnostic. Such a case remains **review required** and may intentionally fail normal integrity verification until its retained original manifest, archive and receipts are reconciled. Never rerun blindly, delete the receipt, or treat an interrupted revision as accepted.

## Validation and limits

See `COC/manifests/operations-validation.json` and workstation `COC-USB2-Response-Local-Acceptance.json`. Tests use only synthetic cases and include cancellation/stale confirmation, changed/untracked artifact refusal, active case/competing manager locks, archive failure, interrupted deletion recovery, evidence exclusions, successful selected cleanup with manifest lineage, handoff immutability and unknown freshness dates. The normal operator menu and guided execution receive separate validation records; do not substitute static parsing for interactive/runtime acceptance.
