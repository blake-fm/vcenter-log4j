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
  printf "%-25s %s\n" "$1" "$2"
}
# Removes the scarty 
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
      flog "SKIPPED" "$2"
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
    *)
      flog "$1" "$2"
      ;;
  esac
}
verify-workaround () {
  # vMON
  rawProcCount=$(ps auxww | grep '/usr/java/jre-vmware/bin/' | wc -l)
  trueProcCount=$(ps auxww | grep '\-Dlog4j2.formatMsgNoLookups=true' | wc -l)
  logmsg -big "Verification:"
  logmsg "Number of processes running formatMsgNoLookups=true: $trueProcCount"
  if [ $rawProcCount -eq $trueProcCount ]; then
    logmsg -confirm "vMON - All JRE processes are running workaround."
  else
    logmsg -error "Process count mismatch.  Got $rawProcCount JRE processes, but confirmed $trueProcCount.  Confirm using: ps aux | grep formatMsgNoLookups"
  fi

  # Update Manager
  if [ $vCenterVersion == '7.0' ]; then
    cd /usr/lib/vmware-updatemgr/bin/jetty/
    javaCount=$(java -jar start.jar --list-config 2>/dev/null | grep 'log4j2\.formatMsgNoLookups = true (' | wc -l)
    cd - >/dev/null
    if [ $javaCount -ne 0 ]; then
      logmsg -confirm "Update Manager workaround."
    else
      logmsg -error "Update Manager workaround may have failed.  Manually confirm using: cd /usr/lib/vmware-updatemgr/bin/jetty/ && java -jar start.jar --list-config"
    fi
  fi

  # DBCC
  if [ $vCenterVersion == '7.0' ]; then
    dbccCount=$(grep -i jndilookup /usr/lib/vmware-dbcc/lib/log4j-core-2.8.2.jar | wc -l)
    if [ $dbccCount -eq 0 ]; then
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
  fi
}
apply-workaround () {
  # vMON Service
  currService="vMON Service"
  currFile="/usr/lib/vmware-vmon/java-wrapper-vmon"
  if [ -f $currFile ]; then
    logmsg -detected
    if [ $(grep '^log4j_arg="-Dlog4j2.formatMsgNoLookups=true"$' $currFile | wc -l) -ne 0 ]; then
      logmsg -skip "Workaround already applied to $currFile"
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
        logmsg -skip "Workaround already applied to $currFile"
      else
        logmsg -apply
        cp -aiv $currFile{,.bak}
        echo '# Workaround CVE-2021-44228
-Dlog4j2.formatMsgNoLookups=true
# END WORKAROUND' >> $currFile
        logmsg -restart
        service-control --restart vmware-updatemgr
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
      logmsg -skip "Workaround already applied to $currFile"
    else
      logmsg -apply
      cp -aiv $currFile{,.bak}
      zip -q -d $currFile org/apache/logging/log4j/core/lookup/JndiLookup.class
      logmsg -restart
      service-control --restart vmware-analytics
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
        logmsg -skip "Workaround already applied to $currFile"
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
        logmsg -skip "Workaround already applied to $currFile"
      else
        logmsg -apply
        cp -aiv $currFile{,.bak}
        zip -q -d $currFile org/apache/logging/log4j/core/lookup/JndiLookup.class
        logmsg -restart
        service-control --restart vmware-cm
      fi
    else
      logmsg -error "Could not detect $currService"
    fi
  fi
  printf "\n\n\n"
}
rollback-workaround () {
  # vMON
  currService="vMON Service"
  currFile="/usr/lib/vmware-vmon/java-wrapper-vmon"
  if [ -f $currFile.bak ]; then
    logmsg -rollback
    cp -av $currFile{.bak,}
    logmsg -restart
    service-control --stop --all
    service-control --start --all
  else
    logmsg -norollback
  fi

  # Update Manager
  currService="Update Manager Service"
  currFile="/usr/lib/vmware-updatemgr/bin/jetty/start.ini"
  if [ -f $currFile.bak ]; then
    logmsg -rollback
    cp -av $currFile{.bak,}
    logmsg -restart
    service-control --restart vmware-updatemgr
  else
    logmsg -norollback
  fi

  # Analytics
  currService="Analytics Service"
  currFile="/usr/lib/vmware/common-jars/log4j-core-2.8.2.jar"
  if [ -f $currFile.bak ]; then
    logmsg -rollback
    cp -av $currFile{.bak,}
    logmsg -restart
    service-control --restart vmware-analytics
  else
    logmsg -norollback
  fi

  # DBCC Utility
  currService="DBCC Utility"
  currFile="/usr/lib/vmware-dbcc/lib/log4j-core-2.8.2.jar"
  if [ -f $currFile.bak ]; then
    logmsg -rollback
    cp -av $currFile{.bak,}
    logmsg "$currService" "No restart required."
  else
    logmsg -norollback
  fi

  # CM Service
  currService="CM service"
  currFile="/usr/lib/vmware-cm/lib/log4j-core.jar"
  if [ -f $currFile.bak ]; then
    logmsg -rollback
    cp -av $currFile{.bak,}
    logmsg -restart
    service-control --restart vmware-cm
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
