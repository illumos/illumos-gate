#!/sbin/sh
#
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
#	Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
#	Use is subject to license terms.
#
#	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
#	  All Rights Reserved

#
# Copyright 2017, OmniTI Computer Consulting, Inc. All rights reserved.
#

#	Sequence performed to change the init state of a machine.  Only allows
#	transitions to states 0,1,5,6,s,S (i.e.: down or administrative states).

#	This procedure checks to see if you are permitted and allows an
#	interactive shutdown.  The actual change of state, killing of
#	processes and such are performed by the new init state, say 0,
#	and its /sbin/rc0.

usage() {
	echo "Usage: $0 [ -y ] [ -g<grace> ] [ -i<initstate> ] [ message ]"
	exit 1
}

notify() {
	/usr/sbin/wall -a <<-!
	$*
	!
	# We used to do rwall here if showmounts had any output, but
	# rwall is a potential security hole, and it could block this, so
	# we don't bother with it anymore.
}

nologin=/etc/nologin

# Set the PATH so that to guarentee behavior of shell built in commands
# (such as echo).

PATH=/usr/sbin:/usr/bin:/sbin

# Initial sanity checks:
#	Make sure /usr is mounted
#	Check the user id (only root can run shutdown)

if [ ! -d /usr/bin ]
then
	echo "$0:  /usr is not mounted.  Mount /usr or use init to shutdown."
	exit 1
fi

if [ -x /usr/bin/id ]
then
	eval `/usr/bin/id  |  /usr/bin/sed 's/[^a-z0-9=].*//'`
	if [ "${uid:=0}" -ne 0 ]
	then
	        echo "$0:  Only root can run $0"
		exit 2
	fi
else
	echo "$0:  can't check user id."
	exit 2
fi

# Get options (defaults immediately below):

grace=60
askconfirmation=yes
initstate=s

while getopts g:i:y? c
do
	case $c in
	g)
		case $OPTARG in
		*[!0-9]* )
			echo "$0: -g requires a numeric option"
			usage
			;;
		[0-9]* )
			grace=$OPTARG
			;;
		esac
		;;
	i)
		case $OPTARG in
		[Ss0156])
			initstate=$OPTARG
			;;
		[234abcqQ])
			echo "$0: Initstate $OPTARG is not for system shutdown"
			exit 1
			;;
		*)
			echo "$0: $OPTARG is not a valid initstate"
			usage
			;;
		esac
		;;
	y)
		askconfirmation=
		;;
	\?)	usage
		;;
	esac
done
shift $(($OPTIND - 1))

echo '\nShutdown started.    \c'
/usr/bin/date
echo

NODENAME=`uname -n`

cd /

trap "rm $nologin >/dev/null 2>&1 ;exit 1"  1 2 15

# If other users are on the system (and any grace period is given), warn them.

for i in 7200 3600 1800 1200 600 300 120 60 30 10; do
	if [ ${grace} -gt $i ]
	then
		hours=$((${grace} / 3600))
		minutes=$((${grace} % 3600 / 60))
		seconds=$((${grace} % 60))
		time=""
		if [ ${hours} -gt 1 ]
		then
			time="${hours} hours "
		elif [ ${hours} -eq 1 ]
		then
			time="1 hour "
		fi
		if [ ${minutes} -gt 1 ]
		then
			time="${time}${minutes} minutes "
		elif [ ${minutes} -eq 1 ]
		then
			time="${time}1 minute "
		fi
		if [ ${hours} -eq 0 -a ${seconds} -gt 0 ]
		then
			if [ ${seconds} -eq 1 ]
			then
				time="${time}${seconds} second"
			else
				time="${time}${seconds} seconds"
			fi
		fi

		(notify \
"The system ${NODENAME} will be shut down in ${time}
$*")

		rm $nologin >/dev/null 2>&1
		cat > $nologin <<-!

			NO LOGINS: System going down in ${time}
			$*

		!

		/usr/bin/sleep $((${grace} - $i))
		grace=$i
	fi
done

# Confirm that we really want to shutdown.

if [ ${askconfirmation} ]
then
	echo "Do you want to continue? (y or n):   \c"
	read b
	if [ "$b" != "y" ]
	then
		notify "False Alarm:  The system ${NODENAME} will not be brought down."
		echo 'Shutdown aborted.'
		rm $nologin >/dev/null 2>&1
		exit 1
	fi
fi

# Final shutdown message, and sleep away the final 10 seconds (or less).

(notify \
"THE SYSTEM ${NODENAME} IS BEING SHUT DOWN NOW ! ! !
Log off now or risk your files being damaged
$*")

if [ ${grace} -gt 0 ]
then
	/usr/bin/sleep ${grace}
fi

# Go to the requested initstate.


echo "Changing to init state $initstate - please wait"

# We might be racing with a system that's still booting.
# Before starting init, check to see if smf(5) is running.  The easiest way
# to do this is to check for the existence of the repository service door.

i=0
# Try three times, sleeping one second each time...
while [ ! -e /etc/svc/volatile/repository_door -a $i -lt 3 ]; do
	sleep 1
	i=$(($i + 1))
done

if [ ! -e /etc/svc/volatile/repository_door ]; then
	notify "Could not find repository door, init-state change may fail!"
fi

/sbin/init ${initstate}
