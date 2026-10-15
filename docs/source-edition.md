# Public source edition and setup boundary

This repository shares original engineering source and documentation. It deliberately omits the operative installed release manifest, hardware-specific updater, all vendor binaries/runtime packages, ISOs, forensic evidence, raw logs and lab images. It will not install or recreate the private USB automatically. The source launchers normally require the full verified staged layout and release manifest and should refuse a bare public clone.

Use an isolated development environment to review code. Do not weaken execution policy, Application Control, antivirus or Secure Boot to run it. Obtain dependencies from their current publishers, review licenses and digests, stage the expected paths, prepare an independently pinned release manifest and validate on authorized fixtures before operational use. Never copy a device identity from another system. Privileged acquisition, live host collection, encryption, engine installation and boot tests remain separate owner decisions.

Source layout preserves `COC/launchers/windows`, `COC/launchers/linux`, selected tests, catalog/readiness metadata and the small offline-lab runner. Only the three bundled response fixtures are included; other tests can require additional synthetic fixtures, runtime/vendor packages or Windows. The 128-test result describes the staged installed-project build, not a claim that all tests run from this public clone.

The stdlib-only CArchive/log parser tests can be explored with `python -B -m unittest discover -s COC/tests -p test_response.py` from the repository root. That test module includes platform-neutral planning checks and does not execute evidence or run a container engine. Full operations tests require catalog/manifest context deliberately omitted from this source edition. Review setup and test code before execution.

Publisher pointers: osquery https://github.com/osquery/osquery ; PyInstaller Extractor NG https://github.com/pyinstxtractor/pyinstxtractor-ng ; Dissect https://github.com/fox-it/dissect ; Zimmerman tools https://ericzimmerman.github.io/ ; Ghidra https://github.com/NationalSecurityAgency/ghidra ; Zeek https://github.com/zeek/zeek ; Suricata https://suricata.io/ ; Plaso https://github.com/log2timeline/plaso ; SIFT https://www.sans.org/tools/sift-workstation/ ; REMnux https://remnux.org/ . These references do not transfer licensing or support obligations to this project.

Public-source check: the 20 stdlib response/parser tests were also run from this standalone repository and passed during publication preparation. This is separate from the 128-test staged-toolkit result.

