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

logmsg () {
  printf "%-20s %s\n" "$1" "$2"
}
biglogmsg () {
  printf "\n%s\n\n" "$1"
}
cve-workaround () {
  version=$(vpxd -v | sed -r 's/.+ ([0-9]\.[0-9]).*/\1/')

  if [ "$1" != "-v" ]; then
    # vMON Service
    currService="vMON Service"
    if [ -f /usr/lib/vmware-vmon/java-wrapper-vmon ]; then
      logmsg "$currService" "Detected"
      if [ $(grep "Dlog4j2\.formatMsgNoLookups=true" /usr/lib/vmware-vmon/java-wrapper-vmon | wc -l) -ne 0 ]; then
        logmsg "SKIPPED" "Workaround already applied to /usr/lib/vmware-vmon/java-wrapper-vmon"
      else
        logmsg "$currService" "Applying workaround..."
        cp -iv /usr/lib/vmware-vmon/java-wrapper-vmon{,.bak}
        if grep 'exec $java_start_bin $jvm_dynargs $security_dynargs $original_args' /usr/lib/vmware-vmon/java-wrapper-vmon.bak > /dev/null; then
          sed -e 's/exec $java_start_bin $jvm_dynargs $security_dynargs $original_args/# Workaround CVE-2021-44228\nlog4j_arg="-Dlog4j2.formatMsgNoLookups=true"\nexec \$java_start_bin \$jvm_dynargs \$log4j_arg \$security_dynargs \$original_args\n# END Workaround CVE-2021-44228/' /usr/lib/vmware-vmon/java-wrapper-vmon.bak > /usr/lib/vmware-vmon/java-wrapper-vmon
        fi
        if grep 'exec $java_start_bin $jvm_dynargs "$@"' /usr/lib/vmware-vmon/java-wrapper-vmon.bak > /dev/null; then
          sed -e 's/exec $java_start_bin $jvm_dynargs "$@"/# Workaround CVE-2021-44228\nlog4j_arg="-Dlog4j2.formatMsgNoLookups=true"\nexec \$java_start_bin \$jvm_dynargs \$log4j_arg "\$@"\n# END Workaround\n/' /usr/lib/vmware-vmon/java-wrapper-vmon.bak > /usr/lib/vmware-vmon/java-wrapper-vmon
        fi
        biglogmsg "Stopping $currService - this will take a while..."
        service-control --stop --all
        biglogmsg "Services stopped, restarting - this will take even longer..."
        service-control --start --all
      fi
    else
      logmsg "ERROR" "Could not detect $currService."
    fi

    # Update Manager Service
    currService="Update Manager Service"
    if [ $version == '7.0' ]; then
      if [ -f /usr/lib/vmware-updatemgr/bin/jetty/start.ini ]; then
        logmsg "$currService" "Detected"
        if [ $(grep 'Dlog4j2\.formatMsgNoLookups=true' /usr/lib/vmware-updatemgr/bin/jetty/start.ini | wc -l) -ne 0 ]; then
          logmsg "SKIPPED" "Workaround already applied to /usr/lib/vmware-updatemgr/bin/jetty/start.ini"
        else
          logmsg "$currService" "Applying workaround..."
          cp -iv /usr/lib/vmware-updatemgr/bin/jetty/start.ini{,.bak}
          echo '# Workaround CVE-2021-44228
-Dlog4j2.formatMsgNoLookups=true
# END WORKAROUND' >> /usr/lib/vmware-updatemgr/bin/jetty/start.ini
          biglogmsg "$currService" "Restarting..."
          service-control --restart vmware-updatemgr
        fi
      else
        logmsg "ERROR" "Could not detect $currService."
      fi
    fi

    # Analytics Service
    currService="Analytics Service"
    if [ -f /usr/lib/vmware/common-jars/log4j-core-2.8.2.jar ]; then
      logmsg "$currService" "Detected"
      if [ $(grep -i jndilookup /usr/lib/vmware/common-jars/log4j-core-2.8.2.jar | wc -l) -eq 0 ]; then
        logmsg "SKIPPED" "Workaround already applied to /usr/lib/vmware/common-jars/log4j-core-2.8.2.jar"
      else
        logmsg "$currService" "Applying workaround..."
        cp -iv /usr/lib/vmware/common-jars/log4j-core-2.8.2.jar{,.bak}
        zip -q -d /usr/lib/vmware/common-jars/log4j-core-2.8.2.jar org/apache/logging/log4j/core/lookup/JndiLookup.class
        biglogmsg "$currService" "Restarting..."
        service-control --restart vmware-analytics
      fi
    elif [ $version == '7.0' ]; then
      logmsg "ERROR" "Could not detect $currService."
    elif [ $version == '6.7' ]; then
      logmsg "WARNING" "$currService not detected - ignore if version is newer than 6.7 P05."
    fi

    # DBCC Utility
    currService="DBCC Utility"
    if [ $version == '7.0' ]; then
      logmsg "$currService" "Detected"
      if [ $(grep -i jndilookup /usr/lib/vmware-dbcc/lib/log4j-core-2.8.2.jar | wc -l) -eq 0 ]; then
        logmsg "SKIPPED" "Workaround already applied to /usr/lib/vmware-dbcc/lib/log4j-core-2.8.2.jar"
      else
        logmsg "$currService" "Applying workaround..."
        cp -iv /usr/lib/vmware-dbcc/lib/log4j-core-2.8.2.jar{,.bak}
        zip -q -d /usr/lib/vmware-dbcc/lib/log4j-core-2.8.2.jar org/apache/logging/log4j/core/lookup/JndiLookup.class
        biglogmsg "$currService" "No restart required."
      fi
    fi

    # CM Service
    currService="CM service"
    if [ $version == '6.7' ] || [ $version == '6.5' ]; then
      logmsg "$currService" "Detected"
      if [ $(grep -i jndilookup /usr/lib/vmware-cm/lib/log4j-core.jar | wc -l) -eq 0 ]; then
        logmsg "SKIPPED" "Workaround already applied to /usr/lib/vmware-cm/lib/log4j-core.jar"
      else
        logmsg "$currService" "Applying workaround..."
        cp -iv /usr/lib/vmware-cm/lib/log4j-core.jar{,.bak}
        zip -q -d /usr/lib/vmware-cm/lib/log4j-core.jar org/apache/logging/log4j/core/lookup/JndiLookup.class
        biglogmsg "$currService" "Restarting..."
        service-control --restart vmware-cm
      fi
    fi
    printf "\n\n\n"
  fi

  # Verify

  # vMON
  rawProcCount=$(ps auxww | grep '/usr/java/jre-vmware/bin/' | wc -l)
  trueProcCount=$(ps auxww | grep formatMsgNoLookups=true | wc -l)
  biglogmsg "Verification:"
  logmsg "Number of processes running formatMsgNoLookups=true: $trueProcCount"
  if [ $rawProcCount -eq $trueProcCount ]; then
    logmsg "Confirmed" "vMON - All JRE processes are running workaround."
  else
    logmsg "ERROR" "Process count mismatch.  Confirm using: ps auxww | grep formatMsgNoLookups"
  fi

  if [ $version == '7.0' ]; then
    cd /usr/lib/vmware-updatemgr/bin/jetty/
    javaCount=$(java -jar start.jar --list-config | grep 'log4j2\.formatMsgNoLookups = true (' | wc -l)
    cd -
    if [ $javaCount -ne 0 ]; then
      logmsg "Confirmed" "Update Manager workaround."
    else
      logmsg "ERROR" "Update Manager workaround may have failed.  Manually confirm using: cd /usr/lib/vmware-updatemgr/bin/jetty/ && java -jar start.jar --list-config"
    fi

    # DBCC
    dbccCount=$(grep -i jndilookup /usr/lib/vmware-dbcc/lib/log4j-core-2.8.2.jar | wc -l)
    if [ $dbccCount -eq 0 ]; then
      logmsg "Confirmed" "DBCC Utility workaround."
    else
      logmsg "ERROR" "DBCC Utility reports that JndiLookup has not been removed."
    fi
  fi

  if [ $version == '6.7' ] || [ $version == '7.0' ]; then
    if [ -f /usr/lib/vmware/common-jars/log4j-core-2.8.2.jar ]; then
      # Analytics
      analyticsCount=$(grep -i jndilookup /usr/lib/vmware/common-jars/log4j-core-2.8.2.jar | wc -l)
      if [ $analyticsCount -eq 0 ]; then
        logmsg "Confirmed" "Analytics Service workaround."
      else
        logmsg "ERROR" "Analytics Service reports that JndiLookup has not been removed."
      fi
    else
      logmsg "WARNING" "Skipping Analytics check - Analytics Service was not detected - ignore if version is newer than 6.7 P05."
    fi
  fi

  # CM Service
  if [ $version == '6.7' ] || [ $version == '6.5' ]; then
    cmCount=$(grep -i jndilookup /usr/lib/vmware-cm/lib/log4j-core.jar | wc -l)
    if [ $cmCount -eq 0 ]; then
      logmsg "Confirmed" "CM Service workaround."
    else
      logmsg "ERROR" "CM Service reports that JndiLookup has not been removed."
    fi
  fi
}
