# VMware vCenter log4j workaround
Basic script to patch VMware vCenter log4j vulnerability CVE-2021-44228

Usage:
- Apply workarounds and verify: `cve-workaround`
- Run verification only: `cve workaround -v`

Quick and dirty:
- SSH to vCenter
- Run `shell`
- Paste entire contents of script
- Type `cve`, hit tab, enter

Detects version and applies the relevant workarounds.

Happy to hear any bugs / issues.
