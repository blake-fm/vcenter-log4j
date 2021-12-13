# VMware vCenter log4j workaround
Script to workaround VMware vCenter log4j vulnerability CVE-2021-44228, as per the [VMware KB article](https://kb.vmware.com/s/article/87081).

2021-12-13 02:09 UTC - Added Secure Token & Identity Management services
2021-12-13 12:46 UTC - Added PSC Client for 6.5 - see below

## Quick and dirty
- SSH to vCenter
- Run `shell`
- Paste entire [contents of script](https://raw.githubusercontent.com/blake-fm/vcenter-log4j/main/log4j-vcenter-6.5-7.0-workaround.sh)
- Type `cve`, hit tab, enter

And you're done.

## What it does
- Automatically detects the version and required steps
- Backs up existing files to .bak files
- Applies the workarounds recommended by VMware
- Skips any steps that are already applied
- Reports status as it goes
- Provides a summary at the end - verification is more accurate / granular than the KB steps

### What it does..n't
- PSC Client.. ish - see below

### If you don't like quick and dirty..
Apply workarounds and verify
```
cve-workaround
```
Run verification only
```
cve-workaround -v
```
Rollback - very basic, copies the .bak files over the patched files, restarts the services, and prints status messages.
```
cve-workaround -rollback
```
PSC Client Service for 6.5 - 100% untested.  Any feedback is welcome.
```
cve-workaround -sprayandpray65
```

### Notes
Detects version and applies the relevant workarounds.  Skips and reports per workaround step, if it thinks that workaround has been applied (safe to re-execute).

#### Services not starting / permissions fix
During my own testing - apply, rollback, re-re-re-apply - I ran across some issues with permissions on 6.7, which prevented some vCenter services from starting (and I still can't find any evidence of an actual error message being logged).  Should you experience similar behaviour, this is the hammer I have been using to beat things into submission.
```
chmod 754 /usr/lib/vmware-vmon/java-wrapper-vmon
chown root:cis /usr/lib/vmware-vmon/java-wrapper-vmon
chmod 644 /usr/lib/vmware-updatemgr/bin/jetty/start.ini
chown updatemgr:updatemgr /usr/lib/vmware-updatemgr/bin/jetty/start.ini
chmod 440 /usr/lib/vmware/common-jars/log4j-core-2.8.2.jar
chown root:cis /usr/lib/vmware/common-jars/log4j-core-2.8.2.jar
chmod 755 /usr/lib/vmware-cm/lib/log4j-core.jar
chown cm:cis /usr/lib/vmware-cm/lib/log4j-core.jar
```

Happy to hear any bugs / issues.
