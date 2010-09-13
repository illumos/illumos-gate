#!/sbin/sh
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

[ ! -d /usr/sbin -o ! -d /usr/bin ] && exit

# Constants

SVBOOT=/usr/sbin/svboot
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
  elif [ `ps -ef | grep preremove | grep -c SUNWspsvu` -gt 0 ]
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

# main program

if [ ! -x $SVBOOT ]
then
	echo "$0: cannot find $SVBOOT"
	exit $SMF_EXIT_MON_OFFLINE
fi

case "$1" in
'start')

	$SVBOOT -r
	;;

'stop')

	do_smf_depends "system/nws_sv"

	$SVBOOT -s
	;;

*)
	echo "Usage: $0 { start | stop }"
	exit $SMF_EXIT_MON_OFFLINE
	;;
esac

exit $SMF_EXIT_OK
