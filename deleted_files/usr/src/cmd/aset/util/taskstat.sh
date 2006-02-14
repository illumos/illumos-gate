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
# sccsid = @(#) taskstat 1.2 1/3/91 11:13:05

# Show status of ASET tasks that are still running.

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
			*)	asetdir=$OPTARG;
			esac;;
		\?)	usageerr=true;
			break;;
		esac
	done
fi

if [ "$usageerr" = "true" ]
then
	echo
	echo "Usage: taskstat [-d aset_dir]"
	exit 1
fi

# the -d option has the highest priority
if [ "$dflag" = "false" ]
then
	# then check the environment
	if [ "$ASETDIR" -ne "" ]
	then
		asetdir=$ASETDIR
	else
		# otherwise set to the default value
		asetdir=/usr/aset
	fi
fi

if test ! -d $asetdir
then
	echo
	echo "ASET startup unsuccessful:"
	echo "Working directory $asetdir missing"
	exit 2
fi

# expand the working directory to the full path
asetdir=`$asetdir/util/realpath $asetdir`
if [ "$asetdir" = "" ]
then
	echo
	echo "ASET startup unsuccessful:"
	echo "Cannot expand $asetdir to full pathname."
	exit 2
fi

eval `grep "^TASKS" ${asetdir}/asetenv`

if [ "$TASKS" = "" ]
then
   echo
   echo "Task list undefined. Check ${asetdir}/asetenv file."
   exit 1
fi

if [ ! -h ${asetdir}/reports/latest ]
then
	echo
	echo "The reports directory under $asetdir is not well established."
	echo "taskstat failed."
	exit 1
fi

if [ ! -s ${asetdir}/reports/latest/taskstatus ]
then
	echo
	echo "Cannot find task status file."
	exit 1
fi

echo
echo "Checking ASET tasks status ... "

done=""
notdone=""

for task in $TASKS
do
	if grep -s $task ${asetdir}/reports/latest/taskstatus
	then
		done="$done $task"
	else
		notdone="$notdone $task"
	fi
done

if [ "$done" != "" ]
then
	echo
	echo "The following tasks are done:"
	for task in $done
	do
		echo "	$task"
	done
fi

if [ "$notdone" != "" ]
then
	echo
	echo "The following tasks are not done:"
	for task in $notdone
	do
		echo "	$task"
	done
else
	echo
	echo "All tasks have completed."
fi
