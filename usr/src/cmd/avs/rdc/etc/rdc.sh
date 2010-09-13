#!/bin/sh
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
# SNDR start script
#
# Description:	This is the SNDR start script. It must be located
#		in /etc/init.d with links to the appropriate rc2.d and
#		rc0.d files.
#		It can also be used to start or stop a specified cluster
#		resource group when invoked from the data service cluster
#		failover script.
#
#
#
PATH=/etc:/bin
RDCBOOT="/usr/sbin/sndrboot"
USAGE="Usage: $0 {start|stop} [cluster_resource]"
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
   elif [ `ps -ef | grep preremove | grep -c SUNWrdcu` -gt 0 ]
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

CLINFO=/usr/sbin/clinfo

killproc() {            # kill the named process(es)
        pid=`/usr/bin/ps -e |
             /usr/bin/grep -w $1 |
             /usr/bin/sed -e 's/^  *//' -e 's/ .*//'`
        [ "$pid" != "" ] && kill $pid
}


case "$1" in
'start')
	COPT=

	if [ -x ${RDCBOOT} ]
	then
		if ${CLINFO}
		then
			if [ "$2" != "" ]
			then
	 			${RDCBOOT} -r -C $2
			else
				# SNDR 3.2 SetIDs fixup
				${RDCBOOT} -C post-patch-setids -r -s

				COPT="-C -"
				${RDCBOOT} ${COPT} -r
			fi
		else
			# non-clustered start
			${RDCBOOT} -r
		fi
	fi
	;;

'stop')
	COPT=

	if [ ! -r /dev/rdc ]
	then
		RDCBOOT=/usr/bin/true
	fi
	
        do_smf_depends "system/nws_rdc"

	if [ -x ${RDCBOOT} ]
	then
		if ${CLINFO}
		then
			if [ "$2" != "" ]
			then
				${RDCBOOT} -s -C $2
			else
				COPT="-C -"
				${RDCBOOT} ${COPT} -s

				echo "killing SNDR daemons"
				killproc sndrd
				killproc sndrsync
			fi
		else
			# non-clustered stop

			${RDCBOOT} -s

			echo "killing SNDR daemons"
			killproc sndrd
			killproc sndrsync
		fi
	else
		# no sndr boot command, kill daemon anyway

		echo "killing SNDR daemons"
		killproc sndrd
		killproc sndrsync
	fi

	;;

*)
	echo $USAGE
	exit 1
	;;
esac
exit $SMF_EXIT_OK
