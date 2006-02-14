#!/bin/sh
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 1990, 1991 Sun Microsystems, Inc.  All Rights Reserved.
#
#
#ident	"%Z%%M%	%I%	%E% SMI"

# This script calls the restore scripts in each task's directory, *.restore
# to restore the system back to the condition before ASET was ever run.
#
# It also deschedules ASET if it is scheduled.

myname=`expr $0 : ".*/\(.*\)" \| $0`

fail()
{
   echo
   echo "$myname: failed:"
   echo $*
   exit 1
}

dflag=false
if [ $# -gt 0 ]
then
	while getopts d: c
	do
		case $c in
		d)	dflag=true;
			case $OPTARG in
			"" | -*)
				usageerr=true;
				break;;
			*)	ASETDIR=$OPTARG;
			esac;;
		\?)	usageerr=true;
			break;;
		esac
	done
fi

if [ "$usageerr" = "true" ]
then
	echo
	echo "Usage: aset.restore [-d aset_dir]"
	exit 1
fi

# the -d option has the highest priority
if [ "$dflag" = "false" ]
then
	# then check the environment
	if [ "$ASETDIR" = "" ]
	then
		# otherwise set to the default value
		ASETDIR=/usr/aset
	fi
fi

if [ ! -d $ASETDIR ]
then
	echo
	echo "ASET startup unsuccessful:"
	echo "Working directory $ASETDIR missing"
	exit 2
fi

# expand the working directory to the full path
ASETDIR=`$ASETDIR/util/realpath $ASETDIR`
if [ "$ASETDIR" = "" ]
then
	echo
	echo "ASET startup unsuccessful:"
	echo "Cannot expand $ASETDIR to full pathname."
	exit 2
fi
export ASETDIR

echo
echo "$myname: beginning restoration ..."

# get user id 
UID=`id | sed -n 's/uid=\([0-9]*\).*/\1/p'` 
export UID 
 
if [ "$UID" -ne 0 ]
then
   fail "Permission Denied."
fi

# Set level to null
ASETSECLEVEL=null
PREV_ASETSECLEVEL=`/usr/ucb/tail -1 $ASETDIR/archives/asetseclevel.arch`
export ASETSECLEVEL PREV_ASETSECLEVEL

for restore_script in $ASETDIR/tasks/*.restore
do
   echo;echo "Executing $restore_script"
   $restore_script
done

schedule=`/bin/crontab -l root | /bin/grep "aset "`
if [ "$schedule" != "" ]
then
   echo
   echo "Descheduling ASET from crontab file..."
   echo "The following is the ASET schedule entry to be deleted:"
   echo "$schedule"
   echo "Proceed to deschedule: (y/n) \c"
   read answer
   if [ "$answer" = "y" ]
   then
      /bin/crontab -l root | /bin/grep -v "aset " | crontab
   fi
fi

echo
echo "Resetting security level from $PREV_ASETSECLEVEL to null."
echo "null" >> $ASETDIR/archives/asetseclevel.arch
echo
echo "$myname: restoration completed."
