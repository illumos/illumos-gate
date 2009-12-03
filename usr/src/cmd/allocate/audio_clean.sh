#! /bin/sh
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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# This is the audio_clean program.
# 
# Following is the syntax for calling the script:
#	scriptname [-s|-f|-i|-I] devicename [-A|-D] [username] [zonename]
#           [zonepath]
#
# $1:	-s for standard cleanup by a user
#	-f for forced cleanup by an administrator
#	-i for boot-time initialization (when the system is booted with -r)
#	-I to suppress error/warning messages; the script is run in the '-i'
#	mode
#
# $2:	devicename - device to be allocated/deallocated, e.g., sr0
#
# $3:	-A if cleanup is for allocation, or -D if cleanup is for deallocation.
#
# $4:	username - run the script as this user, rather than as the caller.
#
# $5:	zonename - zone in which device to be allocated/deallocated
#
# $6:	zonepath - root path of zonename
#
# Unless the clean script is being called for boot-time
# initialization, it may communicate with the user via stdin and
# stdout.  To communicate with the user via CDE dialogs, create a
# script or link with the same name, but with ".windowing" appended.
# For example, if the clean script specified in device_allocate is
# /etc/security/xyz_clean, that script must use stdin/stdout.  If a
# script named /etc/security/xyz_clean.windowing exists, it must use
# dialogs.  To present dialogs to the user, the dtksh script
# /etc/security/lib/wdwmsg may be used.
#
# This particular script, audio_clean, will work using stdin/stdout, or
# using dialogs.  A symbolic link audio_clean.windowing points to
# audio_clean.


trap "" INT TERM QUIT TSTP ABRT

USAGE="usage: $0 [-s|-f|-i|-I] devicename [-A|-D][username][zonename][zonepath]"
PATH="/usr/bin:/usr/sbin"
WDWMSG="/etc/security/lib/wdwmsg"
MODE="allocate"

if [ `basename $0` != `basename $0 .windowing` ]; then
  WINDOWING="yes"
else
  WINDOWING="no"
fi

#
# 		*** Shell Function Declarations ***
#

msg() {
  	if [ "$WINDOWING" = "yes" ]; then
	  if [ $MODE = "allocate" ]; then
	    TITLE="Audio Device Allocation"
	    else
	    TITLE="Audio Device Dellocation"
	  fi
	  $WDWMSG "$*" "$TITLE" OK 
	else  
	  echo "$*"
	fi
}

fail_msg() {
	if [ "$MODE" = "allocate" ]; then
		msg "$0: Allocate of $DEVICE failed."
	else
		msg "$0: Deallocate of $DEVICE failed."
	fi
	exit 1
}

#
# 	Main program
#

# Check syntax, parse arguments.

while getopts ifsI c
do
	case $c in
	i)
		FLAG=$c;;
	f)
		FLAG=$c;;
	s)
		FLAG=$c;;
	I)
		FLAG=i
		silent=y;;
	\?)  msg $USAGE
      	     exit 1;;
	esac
done

shift `expr $OPTIND - 1`

DEVICE=$1
if [ "$2" = "-A" ]; then
	MODE="allocate"
elif [ "$2" = "-D" ]; then
	MODE="deallocate"
fi
if [ "$MODE" != "allocate" -a "$MODE" != "deallocate" ]; then
	msg $USAGE
	exit 1
fi
ZONENAME=$4
ZONEPATH=$5
SAVEDIR=/etc/security/audio
MAP=`dminfo -v -n $DEVICE`
DEVICE=`echo $MAP | cut -f1 -d:`
TYPE=`echo $MAP | cut -f2 -d:`
FILES=`echo $MAP | cut -f3 -d:`

if [ ! -d ${SAVEDIR} ]
then
    /usr/bin/mkdir -m 0755 -p ${SAVEDIR} || fail_msg
    /usr/bin/chown root:sys ${SAVEDIR} || fail_msg
fi

for d in $FILES
do
    x="`expr $d : '/dev/mixer[0-9][0-9]*'`"
    if [ "$x" -ne 0 ] ; then
	DEVNM=$d
	break
    fi
done
SAVEFILE="${SAVEDIR}/`basename ${DEVNM}`"

if [ "${FLAG}" = "i" -a ! -r "${SAVEFILE}" ]
then
    /usr/bin/audioctl save-controls -d ${DEVNM} -f ${SAVEFILE} || fail_msg
else
    /usr/bin/audioctl load-controls -d ${DEVNM} ${SAVEFILE} || fail_msg
fi

exit 0
