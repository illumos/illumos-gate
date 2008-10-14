#!/bin/ksh
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#######################################################################
#
#   This file contains system setup requirements for scm.
#
#   For systems before Solaris 10 it should be located in /etc/init.d
#   directory with the following links:
#
#       ln /etc/init.d/scm /etc/rc0.d/K84scm
#       ln /etc/init.d/scm /etc/rc2.d/S002scm
#
#    For Solaris 10 or later systems this script is run as part of SVC by
#    svc.startd and should be located in /lib/svc/method
#
#USAGE="Usage: $0 { start | stop }
#
#######################################################################

SVCS=/usr/bin/svcs
DSCFG_DEPEND_NOCHK="/tmp/.dscfgadm_pid"
OS_MINOR=`/usr/bin/uname -r | /usr/bin/cut -d '.' -f2`

. /lib/svc/share/smf_include.sh

# Make sure prior SMF dependents are not 'online'
# $1 = name of SMF service to validate dependents
#
do_smf_depends ()
{
  times=0
  count=1

  if [ $OS_MINOR -ge 11 ]
  then
	return 0
  elif [ -f $DSCFG_DEPEND_NOCHK ]
  then
	for pid in `pgrep dscfgadm`
	do
		if [ `grep -c $pid $DSCFG_DEPEND_NOCHK` -gt 0 ]
		then
			return 0
		fi
	done
  elif [ `ps -ef | grep preremove | grep -c SUNWscmu` -gt 0 ]
  then
 	return 0

  fi

  while [ $count -ne 0 ]
  do
    count=`$SVCS -o STATE -D $1 2>>/dev/null | grep "^online" | wc -l`
    if [ $count -ne 0 ]
    then
      # Output banner after waiting first 5 seconds
      #
      if [ $times -eq 1 ]
      then
        echo "Waiting for $1 dependents to be 'offline'"
        $SVCS -D $1 2>>/dev/null | grep "^online"
      fi

      # Has it been longer then 5 minutes? (60 * 5 secs.)
      #
      if [ $times -eq 60 ]
      then
          echo "Error: Failed waiting for $1 dependents to be 'offline'"
          $SVCS -D $1 2>>/dev/null | grep "^online"
	  exit $SMF_EXIT_ERR_FATAL
      fi

      # Now sleep, giving other services time to stop
      #
      sleep 5
      times=`expr $times + 1`
    fi
  done
  return 0
}

set_system_type()
{
	CLINFO=/usr/sbin/clinfo
	ESMSBIN=/usr/sbin
	SCMBIN=/usr/sbin
	ESMSCMLIB=/usr/lib
	SCMLIB=/usr/lib
	DSCFG_LOCKDB=/etc/dscfg_lockdb
}

do_stopsdbc ()
{
    if [ ! -r /dev/sdbc ]
    then
	return
    fi

    ${SCMBIN}/scmadm -d
    if [ $? -ne 0 ] ; then
	# If the disable failed that means we have pinned data.
	echo "Cache Not Deconfigured"
    fi
}

do_stopnskernd ()
{
  ps -e | grep -w nskernd > /dev/null 2>&1
  if [ $? -eq 0 ] ; then
    # make sure that all data services are unloaded before stopping
    # nskernd - cannot stop nskernd when its threads could be in use
    # Note: sv is unloadable, but its threadset is shutdown in the
    # final close(9e) call.
    stop=1
    for m in ste rdc rdcsrv ii sdbc ; do
      mid=`/usr/sbin/modinfo | grep -w $m | awk '{print $1}' -`
      if [ -z "$mid" ] ; then
	continue	# not loaded
      fi
      /usr/sbin/modunload -i $mid > /dev/null 2>&1
      if [ $? -ne 0 ] ; then
	stop=0
	break
      fi
    done

    # kill nskernd if we can
    pid=`ps -e | grep -w nskernd | sed -e 's/^  *//' -e 's/ .*//'`
    if [ $stop -eq 1 ] ; then
      if [ -n "$pid" ] ; then
        kill -15 $pid
      fi
    fi
  fi

  if [ -r /dev/ncall -a -x $ESMSCMLIB/ncalladm ]
  then
    $ESMSCMLIB/ncalladm -d
  fi
}

do_stopdscfglockd ()
{
  pid=`ps -e | grep -w dscfgloc | sed -e 's/^  *//' -e 's/ .*//'`
  if [ -n "$pid" ] ; then
    kill -15 $pid
  fi
}

do_stop ()
{
  do_smf_depends "system/nws_scm"
  do_stopsdbc
  do_stopnskernd
  do_stopdscfglockd
}

do_nskernd ()
{
  if [ -x $ESMSCMLIB/ncalladm ]
  then
    $ESMSCMLIB/ncalladm -e
  fi

  ps -e | grep -w nskernd > /dev/null 2>&1
  if [ $? -ne 0 ] ; then
    ${SCMLIB}/nskernd
    if [ $? -ne 0 ] ; then
      echo "Error: Unable to start nskernd"
      exit $SMF_EXIT_ERR_FATAL
    fi
  fi
}

do_dscfglockd ()
{
	ps -e | grep -w dscfgloc > /dev/null 2>&1
	if [ $? -ne 0 ]
	then
		rm -f /var/tmp/.cfglockd.pid
	else
		# dscfglockd already running
		return
	fi

	if ${CLINFO}
	then
		#
		# create or update the dscfg_lockdb file
		#

		# create clean tmpnodelist
		NODELIST=/tmp/$$.dscfg_nodelist
		rm -f $NODELIST >/dev/null 2>&1
		touch $NODELIST

		if [ -x /usr/cluster/bin/scstat ]
		then
			# get valid names in cluster
			/usr/cluster/bin/scstat -n | grep node: | \
			    awk '{print $3}' >> $NODELIST
			if [ ! -f $DSCFG_LOCKDB ]
			then
				printf "In clustered environment.\n"
				printf "creating per node dscfg_lockdb database"
				printf " with following nodenames:\n"
				cat $NODELIST
				cp $NODELIST $DSCFG_LOCKDB
			else
				# check if there are any changes
				diff $NODELIST $DSCFG_LOCKDB > /dev/null
				if [ $? != 0 ]
				then
					printf "The cluster node names have "
					printf "changed. Updating dscfg_lockdb "
					printf "database.\n"
					printf "Previous node names:\n"
					cat $DSCFG_LOCKDB
					printf "New node names:\n"
					cat $NODELIST
					rm -f $DSCFG_LOCKDB
					cp $NODELIST $DSCFG_LOCKDB
				fi
			fi
		else
			# we're in a cluster, but scstat is not available
			printf "In clustered environment.\n"
			printf "Required configuration file, $DSCFG_LOCKDB\n"
			printf "was not properly populated with the cluster "
			printf "nodenames.\nThis file needs to be manually"
			printf "updated with the cluster\nnodenames before "
			printf "reboot.  Refer to Sun Storage Availability\n"
			printf "Suite Installation Guide for details.\n"
		fi

		# clustered start of dscfglockd
		if [ -f $DSCFG_LOCKDB ]
		then
			printf "Starting dscfglockd\n"
			${SCMLIB}/dscfglockd -f $DSCFG_LOCKDB
		else
			printf "WARNING: Mis-Configuration of Availability "
			printf "Suite for Sun Cluster\n"
			printf "WARNING: Can't find configuration file for "
			printf "dscfglockd\n"
		fi

		rm -f $NODELIST
	fi
  
}

do_sdbc ()
{
      ${SCMBIN}/scmadm  -e
}


do_start ()
{
  # do nothing if we do not have a dscfg
  if [ ! -f /etc/dscfg_local ]
  then
      echo "Cannot find Availability Suite configuration location"
      exit $SMF_EXIT_ERR_NOSMF
  fi

  #
  # Ordering:
  #	dscfglockd	-- locking must be present before any dscfg access
  #	nskernd		-- starts infrastructure (nskernd, ncall).
  #	sdbc		-- start the cache itself
  #
  do_dscfglockd
  do_nskernd
  do_sdbc
}


do_usage ()
{
  echo "Usage: $0"
  echo "   start"
  echo "   stop"
  exit 1
}

set_system_type

USED=0
ACTION=
CLUSTERTAG=

case $# in 
'0')
     do_usage
     ;;
'1') 
     ACTION=$1
     USED=1
     ;;
'2')
     ACTION=$1
     CLUSTERTAG="$2"
     USED=1
     exit 0
     ;;
'*')
     do_usage
     ;;
esac

if [ $USED = 0 ] ; then
     do_usage
fi

if [ $ACTION = "start" ] ; then
  do_start
elif [ $ACTION = "stop" ] ; then
  do_stop
else 
  do_usage
fi

exit $SMF_EXIT_OK
