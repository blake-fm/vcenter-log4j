# VMware vCenter log4j workaround
Basic script to workaround VMware vCenter log4j vulnerability CVE-2021-44228, as per the [VMware KB article](https://kb.vmware.com/s/article/87081).

### Usage
Apply workarounds and verify
```
cve-workaround
```
Run verification only
```
cve-workaround -v
```

### Quick and dirty
- SSH to vCenter
- Run `shell`
- Paste entire [contents of script](https://raw.githubusercontent.com/blake-fm/vcenter-log4j/main/log4j-vcenter-6.5-7.0-workaround.sh)
- Type `cve`, hit tab, enter

### Notes

Detects version and applies the relevant workarounds.  Skips and reports per workaround step, if it thinks that workaround has been applied - re-execute safe.

Happy to hear any bugs / issues.
