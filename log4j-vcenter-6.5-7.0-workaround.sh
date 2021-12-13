# Applies recommendations in: https://kb.vmware.com/s/article/87081
# Should work for all versions, tested on 6.7 and 7.0 U3b
#
# Apply patch: cve-workaround
# Other documentation: https://github.com/blake-fm/vcenter-log4j
#
# Code style is awful; I'm aware.  It was fast and my bash is rusty.
#
# - Blake Marlow
vCenterVersion=$(vpxd -v | sed -r 's/.+ ([0-9]\.[0-9]).*/\1/')

cve-workaround () {
  if [ "$1" == "-rollback" ]; then
    printf "Rollback - are you sure you want to do this? [y/n] "
    read userInput
    [ ${userInput::1} == "y" ] || [ ${userInput::1} == "Y" ] && internal-rollback
    return 0
  elif [ "$1" != "-v" ]; then
    internal-apply-workaround "$1"
  fi
  internal-verify-workaround
}
internal-apply-workaround () {
  # vMON Service
  currService="vMON Service"
  currFile="/usr/lib/vmware-vmon/java-wrapper-vmon"
  if internal-target-file-exists; then
    if [ $(grep '^log4j_arg="-Dlog4j2.formatMsgNoLookups=true"$' $currFile | wc -l) -ne 0 ]; then
      logmsg -skip
    elif internal-create-backup-and-verify; then
      if grep '^exec $java_start_bin $jvm_dynargs $security_dynargs $original_args$' $currFile.bak > /dev/null; then
        sed -e 's/^exec $java_start_bin $jvm_dynargs $security_dynargs $original_args$/# Workaround CVE-2021-44228\nlog4j_arg="-Dlog4j2.formatMsgNoLookups=true"\nexec \$java_start_bin \$jvm_dynargs \$log4j_arg \$security_dynargs \$original_args\n# END Workaround CVE-2021-44228/' $currFile.bak > $currFile
      fi
      if grep '^exec $java_start_bin $jvm_dynargs "$@"$' $currFile.bak > /dev/null; then
        sed -e 's/^exec $java_start_bin $jvm_dynargs "$@"$/# Workaround CVE-2021-44228\nlog4j_arg="-Dlog4j2.formatMsgNoLookups=true"\nexec \$java_start_bin \$jvm_dynargs \$log4j_arg "\$@"\n# END Workaround\n/' $currFile.bak > $currFile
      fi
      logmsg -big "Stopping $currService - this will take a while..."
      service-control --stop --all
      logmsg -big "Services stopped, restarting - this will take even longer..."
      service-control --start --all
    fi
  fi

  # Update Manager Service
  if [ $vCenterVersion == '7.0' ]; then
    currService="Update Manager Service"
    currFile="/usr/lib/vmware-updatemgr/bin/jetty/start.ini"
    if internal-target-file-exists; then
      if [ $(grep 'Dlog4j2\.formatMsgNoLookups=true' $currFile | wc -l) -ne 0 ]; then
        logmsg -skip
      else
        internal-create-backup-and-verify && echo '# Workaround CVE-2021-44228
-Dlog4j2.formatMsgNoLookups=true
# END WORKAROUND' >> $currFile
        internal-restart-service vmware-updatemgr
      fi
    fi
  fi

  # Analytics Service
  currService="Analytics Service"
  currFile="/usr/lib/vmware/common-jars/log4j-core-2.8.2.jar"
  if internal-target-file-exists; then
    if [ $(grep -i jndilookup $currFile | wc -l) -eq 0 ]; then
      logmsg -skip
    else
      internal-create-backup-and-verify && zip -q -d $currFile org/apache/logging/log4j/core/lookup/JndiLookup.class
      internal-restart-service vmware-analytics
    fi
  elif [ $vCenterVersion == '6.7' ]; then
    logmsg -warn "6.7 detected: Certain versions of 6.7 do not require this workaround.  VMware have changed their minds at least 3 times in 24hrs on this - check KB87081 for guidance.  Sorry.  =/"
  fi

  # DBCC Utility
  if [ $vCenterVersion == '7.0' ]; then
    currService="DBCC Utility"
    currFile="/usr/lib/vmware-dbcc/lib/log4j-core-2.8.2.jar"
    if internal-target-file-exists; then
      if [ $(grep -i jndilookup $currFile | wc -l) -eq 0 ]; then
        logmsg -skip
      else
        internal-create-backup-and-verify && zip -q -d $currFile org/apache/logging/log4j/core/lookup/JndiLookup.class
        flog "$currService" "No restart required."
      fi
    fi
  fi

  # CM Service
  if [ $vCenterVersion == '6.7' ] || [ $vCenterVersion == '6.5' ]; then
    currService="CM service"
    currFile="/usr/lib/vmware-cm/lib/log4j-core.jar"
    if internal-target-file-exists; then
      if [ $(grep -i jndilookup $currFile | wc -l) -eq 0 ]; then
        logmsg -skip
      else
        internal-create-backup-and-verify && zip -q -d $currFile org/apache/logging/log4j/core/lookup/JndiLookup.class
        internal-restart-service vmware-cm
      fi
    fi
  fi

  if [ $vCenterVersion == '6.7' ] || [ $vCenterVersion == '6.5' ]; then
    # Secure Token Service
    currService="Secure Token Service"
    currFile="/etc/rc.d/init.d/vmware-stsd"
    if internal-target-file-exists; then
      if [ $(grep -E '^[ ]+-Dlog4j2.formatMsgNoLookups=true \\$' $currFile | wc -l) -gt 0 ]; then
        logmsg -skip
      else
        internal-create-backup-and-verify && sed -r 's#([ ]+)(-Dauditlog.dir=/var/log/audit/sso-events  \\)#\1\2\n\1-Dlog4j2.formatMsgNoLookups=true \\#' $currFile.bak > $currFile
        internal-restart-service vmware-stsd
      fi
    fi
    # Identity Management Service
    currService="Identity Management Service"
    currFile="/etc/rc.d/init.d/vmware-sts-idmd"
    if internal-target-file-exists; then
      if [ $(grep -E '^[ ]+-Dlog4j2.formatMsgNoLookups=true \\$' $currFile | wc -l) -gt 0 ]; then
        logmsg -skip
      else
        internal-create-backup-and-verify && sed -r 's#([ ]+)(-Dlog4j.configurationFile=file://\$PREFIX/share/config/log4j2.xml \\)#\1\2\n\1-Dlog4j2.formatMsgNoLookups=true \\#' $currFile.bak > $currFile
        internal-restart-service vmware-sts-idmd
      fi
    fi
  fi

  # PSC Client Service
  if [ "$1" == "-sprayandpray65" ] && [ $vCenterVersion == '6.5' ]; then
    currService="PSC Client Service"
    currFile="/etc/rc.d/init.d/vmware-psc-client"
    if internal-target-file-exists; then
      if [ $(grep -E '^[ ]+-Dlog4j2.formatMsgNoLookups=true \\$' $currFile | wc -l) -gt 0 ]; then
        logmsg -skip
      else
        internal-create-backup-and-verify && sed -r 's#([ ]+)(-Djava.io.tmpdir="\$CATALINA_BASE/temp" \\)#\1\2\n\1-Dlog4j2.formatMsgNoLookups=true \\#' $currFile.bak > $currFile
        internal-restart-service vmware-psc-client
      fi
    fi
  fi
}
internal-target-file-exists () {
  if [ -f $currFile ]; then
    flog "$currService" "Detected"
    return 0
  else
    logmsg -error "Could not detect $currService"
    return 1
  fi
}
internal-create-backup-and-verify () {
  flog "$currService" "Applying workaround..."
  cp -aiv $currFile{,.bak}
  if [ -f $currFile.bak ]; then
    return 0
  else
    logmsg -error "$currService: Backup file not detected - skipping this workaround."
    return 1
  fi
}
internal-verify-workaround () {
  # vMON
  rawProcCount=$(ps auxww | grep '/usr/java/jre-vmware' | wc -l)
  trueProcCount=$(ps auxww | grep '\-Dlog4j2.formatMsgNoLookups=true' | wc -l)
  logmsg -big "Verification:"
  logmsg -big "Number of processes running formatMsgNoLookups=true: $trueProcCount"
  if [ $rawProcCount -eq $trueProcCount ]; then
    logmsg -confirm "vMON - All JRE processes are running workaround."
  else
    logmsg -error "Process count mismatch.  Got $rawProcCount JRE processes, but confirmed $trueProcCount.  Confirm using: ps auxww | grep formatMsgNoLookups"
  fi

  if [ $vCenterVersion == '7.0' ]; then
    # Update Manager
    cd /usr/lib/vmware-updatemgr/bin/jetty/
    if [ $(java -jar start.jar --list-config 2>/dev/null | grep 'log4j2\.formatMsgNoLookups = true (' | wc -l) -ne 0 ]; then
      logmsg -confirm "Update Manager workaround."
    else
      logmsg -error "Update Manager workaround may have failed.  Manually confirm using: cd /usr/lib/vmware-updatemgr/bin/jetty/ && java -jar start.jar --list-config"
    fi
    cd - >/dev/null
    # DBCC
    if [ $(grep -i jndilookup /usr/lib/vmware-dbcc/lib/log4j-core-2.8.2.jar | wc -l) -eq 0 ]; then
      logmsg -confirm "DBCC Utility workaround."
    else
      logmsg -error "DBCC Utility reports that JndiLookup has not been removed."
    fi
  fi

  # Analytics
  if [ $vCenterVersion == '6.7' ] || [ $vCenterVersion == '7.0' ]; then
    if [ -f /usr/lib/vmware/common-jars/log4j-core-2.8.2.jar ]; then
      analyticsCount=$(grep -i jndilookup /usr/lib/vmware/common-jars/log4j-core-2.8.2.jar | wc -l)
      if [ $analyticsCount -eq 0 ]; then
        logmsg -confirm "Analytics Service workaround."
      else
        logmsg -error "Analytics Service reports that JndiLookup has not been removed."
      fi
    else
      logmsg -warn "Skipping Analytics check - Analytics Service was not detected - ignore if version is newer than 6.7 P05."
    fi
  fi

  if [ $vCenterVersion == '6.7' ] || [ $vCenterVersion == '6.5' ]; then
    # CM Service
    cmCount=$(grep -i jndilookup /usr/lib/vmware-cm/lib/log4j-core.jar | wc -l)
    if [ $cmCount -eq 0 ]; then
      logmsg -confirm "CM Service workaround."
    else
      logmsg -error "CM Service reports that JndiLookup has not been removed."
    fi
    # Secure Token Service
    currService="Secure Token Service"
    internal-check-process "vmware-stsd"
    # Identity Management Service
    currService="Identity Management Service"
    internal-check-process "vmware-sts-idmd"
    # PSC Client Service
    if [ $vCenterVersion == '6.5' ]; then
      currService="PSC Client Service"
      internal-check-process "vmware-psc-client"
    fi
  fi
}
internal-rollback () {
  # vMON
  currService="vMON Service"
  currFile="/usr/lib/vmware-vmon/java-wrapper-vmon"
  internal-restore-and-restart "--all"

  # Update Manager
  currService="Update Manager Service"
  currFile="/usr/lib/vmware-updatemgr/bin/jetty/start.ini"
  internal-restore-and-restart "vmware-updatemgr"

  # Analytics
  currService="Analytics Service"
  currFile="/usr/lib/vmware/common-jars/log4j-core-2.8.2.jar"
  internal-restore-and-restart "vmware-analytics"

  # DBCC Utility
  currService="DBCC Utility"
  currFile="/usr/lib/vmware-dbcc/lib/log4j-core-2.8.2.jar"
  internal-restore-and-restart -noservice

  # CM Service
  currService="CM service"
  currFile="/usr/lib/vmware-cm/lib/log4j-core.jar"
  internal-restore-and-restart "vmware-cm"

  # Secure Token Service
  currService="Secure Token Service"
  currFile="/etc/rc.d/init.d/vmware-stsd"
  internal-restore-and-restart "vmware-stsd"

  # Identity Management Service
  currService="Identity Management Service"
  currFile="/etc/rc.d/init.d/vmware-sts-idmd"
  internal-restore-and-restart "vmware-sts-idmd"

  # PSC Client Service
  currService="PSC Client Service"
  currFile="/etc/rc.d/init.d/vmware-psc-client"
  internal-restore-and-restart "vmware-psc-client"
}
internal-restore-and-restart () {
  if [ -f $currFile.bak ]; then
    flog "$currService" "Rolling back..."
    cp -av $currFile{.bak,}
    if [ $1 != "-noservice" ]; then
      internal-restart-service "$1"
    else
      flog "$currService" "No restart required."
    fi
  else
    flog "$currService" "Nothing to roll back."
  fi
}
internal-restart-service () {
  flog "$currService" "Restarting service..."
  service-control --stop $1
  service-control --start $1
}
internal-check-process () {
  rawProcCount=$(($(ps auxww | grep " $1 " | wc -l) - 1))
  trueProcCount=$(($(ps auxww | grep " $1 .*-Dlog4j2.formatMsgNoLookups=true " | wc -l) - 1))
  if [ $trueProcCount -gt 0 ]; then
    if [ $rawProcCount -eq $trueProcCount ]; then
      logmsg -confirm "$currService - all $trueProcCount processes are running workaround."
    else
      logmsg -error "Process count mismatch.  Got $rawProcCount $currService processes, but confirmed $trueProcCount.  Confirm using: ps auxww | grep formatMsgNoLookups"
    fi
  else
    logmsg -warn "$currService is not running."
  fi
}
# Logging system
logmsg () {
  case $1 in
    -confirm)
      flog "Confirmed" "$2" ;;
    -error)
      flog "ERROR" "$2" ;;
    -warn)
      flog "WARNING" "$2" ;;
    -skip)
      flog "SKIPPED" "Workaround already applied to $currFile" ;;
    -big)
      printf "\n%s\n\n" "$2" ;;
  esac
}
# Formatted logger
flog () { printf "%-30s %s\n" "$1" "$2"; }
