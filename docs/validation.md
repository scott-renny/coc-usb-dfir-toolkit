# Validation and release evidence

See [the sanitized record](validation-summary.json). Installation/read-back completed at the UTC time in that record. Public material omits the local transcript, backup path and physical device identity.

| Layer | Evidence | Remaining limit |
|---|---|---|
| Local Python suite | 128 tests passed, 25 new operations tests | Executed with staged private dependencies; not an out-of-box public-clone result |
| Case integration | Seven operations cases and five response cases finalized and artifact-verified | Synthetic inputs; real-evidence acceptance remains separate |
| Guided decisions | Completed/skipped, failed/review and unattempted states tested | Step-launch boundary mocked; real case core/verification used |
| Retention | Wrong/stale confirmation, owner edits, untracked artifacts, active/competing sessions, failed/tampered archive, interrupted recovery and successful revision checked | Only synthetic case logs removed; no owner log cleanup performed |
| Latest release | 35 changed files and 28 image blobs independently hashed; 49 menu references checked | Unchanged large payloads retained their earlier hashes |
| USB deployment | Owner updater reported changed-file copied/read-back success; 18.58 GiB measured free | Latest update did not rehash the entire installed USB |
| Native startup | osquery version/constant SQL; extractor help/synthetic information-only; three practice parser expectations | Full live query pack and upstream full extraction unaccepted |
| Lab/GUI | Payload integrity and restricted command planning | Actual lab processing/rule compilation and broad GUI acceptance pending |
| Boot | Excluded by owner | No boot-compatibility claim |

Core retained limitations include Application Control blocking capa; reference-only or pending dependency states for Cutter, ExifTool, RegRipper, hashdeep and ClamAV; and real acquisition/VM acceptance. Use the full readiness catalog for each tool. File hashes do not establish that a tool is safe, operationally compatible, or forensically validated for every input.

The original installed manifest SHA256 is preserved in the sanitized summary for comparison. It identifies a private installed release; it is not a manifest for this smaller public source edition. No image/package authenticity signature or independent certification is claimed.
