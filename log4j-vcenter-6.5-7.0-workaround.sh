# Applies recommendations in: https://kb.vmware.com/s/article/87081
# Should work for all versions, tested on 6.7 and 7.0 U3b
#
# Easiest usage is just copy/paste the whole thing into bash, and run:
# cve-workaround
#
# To run verify only (no changes even if patch is not detected):
# cve-workaround -v
#
# Does not run a section if it detects that the fix is *PROBABLY* already applied.
#
# Code style is awful; I'm aware.  It was fast and my bash is rusty.
#
# - Blake Marlow
vCenterVersion=$(vpxd -v | sed -r 's/.+ ([0-9]\.[0-9]).*/\1/')

# Formatted logger
flog () {
  printf "%-30s %s\n" "$1" "$2"
}
# Logging system
logmsg () {
  case $1 in
    -confirm)
      flog "Confirmed" "$2"
      ;;
    -error)
      flog "ERROR" "$2"
      ;;
    -warn)
      flog "WARNING" "$2"
      ;;
    -skip)
      flog "SKIPPED" "Workaround already applied to $currFile"
      ;;
    -big)
      printf "\n%s\n\n" "$2"
      ;;
    -detected)
      flog "$currService" "Detected"
      ;;
    -apply)
      flog "$currService" "Applying workaround..."
      ;;
    -restart)
      flog "$currService" "Restarting service..."
      ;;
    -rollback)
      flog "$currService" "Rolling back..."
      ;;
    -norollback)
      flog "$currService" "Nothing to roll back."
      ;;
    -backupmissing)
      flog "$currService" "Backup file not detected - cancelling this workaround."
      ;;
    *)
      flog "$1" "$2"
      ;;
  esac
}
verify-workaround () {
  # vMON
  rawProcCount=$(ps auxww | grep '/usr/java/jre-vmware' | wc -l)
  trueProcCount=$(ps auxww | grep '\-Dlog4j2.formatMsgNoLookups=true' | wc -l)
  logmsg -big "Verification:"
  logmsg "Number of processes running formatMsgNoLookups=true: $trueProcCount"
  if [ $rawProcCount -eq $trueProcCount ]; then
    logmsg -confirm "vMON - All JRE processes are running workaround."
  else
    logmsg -error "Process count mismatch.  Got $rawProcCount JRE processes, but confirmed $trueProcCount.  Confirm using: ps aux | grep formatMsgNoLookups"
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

  # CM Service
  if [ $vCenterVersion == '6.7' ] || [ $vCenterVersion == '6.5' ]; then
    cmCount=$(grep -i jndilookup /usr/lib/vmware-cm/lib/log4j-core.jar | wc -l)
    if [ $cmCount -eq 0 ]; then
      logmsg -confirm "CM Service workaround."
    else
      logmsg -error "CM Service reports that JndiLookup has not been removed."
    fi
  # Secure Token Service
    currService="Secure Token Service"
    intr-check-process "vmware-stsd"
  # Identity Management Service
    currService="Identity Management Service"
    intr-check-process "vmware-sts-idmd"
  fi

}
intr-check-process () {
  svcName=$1
  rawProcCount=$(($(ps auxww | grep " $svcName " | wc -l) - 1))
  trueProcCount=$(($(ps auxww | grep " $svcName .*-Dlog4j2.formatMsgNoLookups=true " | wc -l) - 1))
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
apply-workaround () {
  # vMON Service
  currService="vMON Service"
  currFile="/usr/lib/vmware-vmon/java-wrapper-vmon"
  if [ -f $currFile ]; then
    logmsg -detected
    if [ $(grep '^log4j_arg="-Dlog4j2.formatMsgNoLookups=true"$' $currFile | wc -l) -ne 0 ]; then
      logmsg -skip
    else
      logmsg -apply
      cp -aiv $currFile{,.bak}
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
  else
    logmsg -error "Could not detect $currService."
  fi

  # Update Manager Service
  if [ $vCenterVersion == '7.0' ]; then
    currService="Update Manager Service"
    currFile="/usr/lib/vmware-updatemgr/bin/jetty/start.ini"
    if [ -f $currFile ]; then
      logmsg -detected
      if [ $(grep 'Dlog4j2\.formatMsgNoLookups=true' $currFile | wc -l) -ne 0 ]; then
        logmsg -skip
      else
        logmsg -apply
        cp -aiv $currFile{,.bak}
        echo '# Workaround CVE-2021-44228
-Dlog4j2.formatMsgNoLookups=true
# END WORKAROUND' >> $currFile
        intr-restart-service vmware-updatemgr
      fi
    else
      logmsg -error "Could not detect $currService."
    fi
  fi

  # Analytics Service
  currService="Analytics Service"
  currFile="/usr/lib/vmware/common-jars/log4j-core-2.8.2.jar"
  if [ -f $currFile ]; then
    logmsg -detected
    if [ $(grep -i jndilookup $currFile | wc -l) -eq 0 ]; then
      logmsg -skip
    else
      logmsg -apply
      cp -aiv $currFile{,.bak}
      zip -q -d $currFile org/apache/logging/log4j/core/lookup/JndiLookup.class
      intr-restart-service vmware-analytics
    fi
  elif [ $vCenterVersion == '7.0' ]; then
    logmsg -error "Could not detect $currService."
  elif [ $vCenterVersion == '6.7' ]; then
    logmsg -warn "$currService not detected - ignore if version is newer than 6.7 P05."
  fi

  # DBCC Utility
  currService="DBCC Utility"
  currFile="/usr/lib/vmware-dbcc/lib/log4j-core-2.8.2.jar"
  if [ $vCenterVersion == '7.0' ]; then
    if [ -f $currFile ]; then
      logmsg -detected
      if [ $(grep -i jndilookup $currFile | wc -l) -eq 0 ]; then
        logmsg -skip
      else
        logmsg -apply
        cp -aiv $currFile{,.bak}
        zip -q -d $currFile org/apache/logging/log4j/core/lookup/JndiLookup.class
        logmsg "$currService" "No restart required."
      fi
    else
      logmsg -error "Could not detect $currService"
    fi
  fi

  # CM Service
  currService="CM service"
  currFile="/usr/lib/vmware-cm/lib/log4j-core.jar"
  if [ $vCenterVersion == '6.7' ] || [ $vCenterVersion == '6.5' ]; then
    if [ -f $currFile ]; then
      logmsg -detected
      if [ $(grep -i jndilookup $currFile | wc -l) -eq 0 ]; then
        logmsg -skip
      else
        logmsg -apply
        cp -aiv $currFile{,.bak}
        zip -q -d $currFile org/apache/logging/log4j/core/lookup/JndiLookup.class
        intr-restart-service vmware-cm
      fi
    else
      logmsg -error "Could not detect $currService"
    fi
  fi

  # Secure Token Service
  currService="Secure Token Service"
  currFile="/etc/rc.d/init.d/vmware-stsd"
  if [ $vCenterVersion == '6.7' ] || [ $vCenterVersion == '6.5' ]; then
    if [ -f $currFile ]; then
      logmsg -detected
      if [ $(grep -E '^[ ]+-Dlog4j2.formatMsgNoLookups=true \\$' $currFile | wc -l) -gt 0 ]; then
        logmsg -skip
      else
        logmsg -apply
        cp -aiv $currFile{,.bak}
        if [ -f $currFile.bak ]; then
          sed -r 's#([ ]+)(-Dauditlog.dir=/var/log/audit/sso-events  \\)#\1\2\n\1-Dlog4j2.formatMsgNoLookups=true \\#' $currFile.bak > $currFile
        else
          logmsg -backupmissing
        fi
        intr-restart-service vmware-stsd
      fi
    else
      logmsg -error "Could not detect $currService"
    fi
  fi

  # Identity Management Service
  currService="Identity Management"
  currFile="/etc/rc.d/init.d/vmware-sts-idmd"
  if [ $vCenterVersion == '6.7' ] || [ $vCenterVersion == '6.5' ]; then
    if [ -f $currFile ]; then
      logmsg -detected
      if [ $(grep -E '^[ ]+-Dlog4j2.formatMsgNoLookups=true \\$' $currFile | wc -l) -gt 0 ]; then
        logmsg -skip
      else
        logmsg -apply
        cp -aiv $currFile{,.bak}
        if [ -f $currFile.bak ]; then
          sed -r 's#([ ]+)(-Dlog4j.configurationFile=file://\$PREFIX/share/config/log4j2.xml \\)#\1\2\n\1-Dlog4j2.formatMsgNoLookups=true \\#' $currFile.bak > $currFile
        else
          logmsg -backupmissing
        fi
        intr-restart-service vmware-sts-idmd
      fi
    else
      logmsg -error "Could not detect $currService"
    fi
  fi

  printf "\n\n\n"
}
intr-restart-service () {
        logmsg -restart
        service-control --stop $1
        service-control --start $1
}
rollback-workaround () {
  # vMON
  currService="vMON Service"
  currFile="/usr/lib/vmware-vmon/java-wrapper-vmon"
  intr-rollback "--all"

  # Update Manager
  currService="Update Manager Service"
  currFile="/usr/lib/vmware-updatemgr/bin/jetty/start.ini"
  intr-rollback "vmware-updatemgr"

  # Analytics
  currService="Analytics Service"
  currFile="/usr/lib/vmware/common-jars/log4j-core-2.8.2.jar"
  intr-rollback "vmware-analytics"

  # DBCC Utility
  currService="DBCC Utility"
  currFile="/usr/lib/vmware-dbcc/lib/log4j-core-2.8.2.jar"
  intr-rollback -noservice

  # CM Service
  currService="CM service"
  currFile="/usr/lib/vmware-cm/lib/log4j-core.jar"
  intr-rollback "vmware-cm"

  # Secure Token Service
  currService="Secure Token Service"
  currFile="/etc/rc.d/init.d/vmware-stsd"
  intr-rollback "vmware-stsd"

  # Identity Management Service
  currService="Identity Management Service"
  currFile="/etc/rc.d/init.d/vmware-sts-idmd"
  intr-rollback "vmware-sts-idmd"
}
intr-rollback () {
  if [ -f $currFile.bak ]; then
    logmsg -rollback
    cp -av $currFile{.bak,}
    if [ $1 != "-noservice" ]; then
      # if [ $vCenterVersion == 6.5 ]; then
        intr-restart-service
      # else
      #   service-control --restart $1
      # fi
    else
      logmsg "$currService" "No restart required."
    fi
  else
    logmsg -norollback
  fi
}
cve-workaround () {
  if [ "$1" == "-rollback" ]; then
    printf "Rollback - are you sure you want to do this? [y/n] "
    read userInput
    if [ ${userInput::1} == "y" ] || [ ${userInput::1} == "Y" ]; then
      rollback-workaround
    else
      logmsg "Happy to hear that.  Exiting."
    fi
  return
  elif [ "$1" != "-v" ]; then
    apply-workaround
  fi

  verify-workaround
}
