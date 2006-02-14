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

# This is the startup script to invoke all ASET utilities.
# option:
#	-n user@host	notify user at machine host: send output
#			to that user thru e-mail. If this option is
#			not specified, the output is sent to stdout.
#	-d aset_dir	working directory for ASET
#	-l sec_level	security level = low/med/high
#	-u user_file	specify file of users to check environment
#	-p		periodic schedule

# clean up upon exit
clean_up()
{
	if [ "$nflag" = "true" -a "$user" != "" ]
	then
		# find a mail program
		if [ -x /usr/ucb/mail ]
		then
			/usr/ucb/mail -s "ASET Execution Log" $user < $log
		elif [ -x /bin/mail ]
		then
			/bin/mail $user < $log
		else
			echo
			echo "ASET failed: no mail program found." \
			> /dev/console
			exit 3
		fi
	else
		$CAT $log > /dev/tty 2>&1
	fi
	$RM $log
}

print_usage()
{
	echo
	echo "ASET failed."
	echo "Usage: aset [-n user[@host]]"
	echo "            [-d aset_dir]"
	echo "            [-l sec_level]"
	echo "            [-u user_file]"
	echo "            [-p]"
}

get_prev_level()
# Get security level of previous ASET execution.
# Get_prev_level sets PREV_ASETSECLEVEL and exports it.
# If it fails to get a valid previous level, it sets the variable to "null".
{
	arch=${ASETDIR}/archives/asetseclevel.arch
	if [ ! -s $arch ]
	then
		PREV_ASETSECLEVEL=null
	else
		PREV_ASETSECLEVEL=`/usr/ucb/tail -1 $arch`
		case $PREV_ASETSECLEVEL in
		low | med | high)
	        	;;
		*)	
			PREV_ASETSECLEVEL=null;;
		esac
	fi
	export PREV_ASETSECLEVEL
}

downgrading()
# downgrading - decide whether we are downgrading security level.
# return:   0 - yes, downgrading
#           1 - no, not downgrading
#           2 - can't decide
{
	if [ "$PREV_ASETSECLEVEL" = "" -o "$ASETSECLEVEL" = "" ]
	then
		echo
		echo "Cannot decide current and previous security levels." 
   		return 2
	fi

	case $PREV_ASETSECLEVEL in
	high)
   		if [ "$ASETSECLEVEL" != "high" ]
   		then
			return 0
		fi;;
	med)
		if [ "$ASETSECLEVEL" = "low" -o "$ASETSECLEVEL" = "null" ]
   		then
      			return 0
   		fi;;
	low)
		if [ "$ASETSECLEVEL" = "null" ]
   		then
      			return 0
   		fi;;
	*)
		return 1;;
	esac
	return 1
}


#------------------------------------------------------------ initialization
banner='                ======= ASET Execution Log ======= '
usageerr=false
nflag=false
lflag=false
dflag=false
myname=aset
log=/tmp/asetlog

#--------------------------------------------------------- process arguments
if [ $# -gt 0 ]
then
	while getopts n:pd:l:u: c
	do
		case $c in
		n)	nflag=true;
			case $OPTARG in
			"" | -*)
				user=""
				usageerr=true;
				break;;
			*) 	user=$OPTARG;;
			esac
			newargs="$newargs -n $OPTARG";;
		p)	pflag=true;;
		d)	dflag=true;
			case $OPTARG in
			"" | -*)
				usageerr=true;
				break;;
			*)	ASETDIR=$OPTARG;;
			esac;;
		l)	lflag=true;
			case $OPTARG in
			"" | -*)
				usageerr=true;
				break;;
			*)	ASETSECLEVEL=$OPTARG;;
			esac
			newargs="$newargs -l $OPTARG";;
		u)	uflag=true;
			case $OPTARG in
			"" | -*)
				usageerr=true;
				break;;
			*)	CHECK_USERS=$OPTARG;;
			esac
			newargs="$newargs -u $OPTARG";;
		\?)	usageerr=true;
			break;;
		esac
	done
fi

#----------------------------------------------------------- check arguments
if [ "$usageerr" = "true" ]
then
	print_usage
	exit 1
fi

# redirect stdout to logfile
exec > $log 2>&1
trap clean_up 0

# print banner
echo $banner

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

# check the -u argument
if [ "$uflag" = "true" ]
then
	if [ ! -r $CHECK_USERS ]
	then
		echo
		echo "ASET startup unsuccessful:"
		echo "File $CHECK_USERS doesn't exist or is not readable."
		exit 2
	else
		export CHECK_USERS
	fi
fi

# the -l option has the highest priority
if [ "$lflag" = "false" ]
then
	# then test the environment
	if [ "$ASETSECLEVEL" = "" ]
	then
		# otherwise set the default value
		ASETSECLEVEL=low
	fi

fi
export ASETSECLEVEL

# get user id 
UID=`id | sed -n 's/uid=\([0-9]*\).*/\1/p'` 
export UID 

# check the environment file
envfile=$ASETDIR/asetenv
if [ ! -f $envfile ]
then
	echo
	echo "ASET startup unsuccessful:"
	echo "Environment file asetenv not found in $ASETDIR"
	exit 2
fi

# invoke the environment script
. $ASETDIR/asetenv

# check -p option argument from asetenv
if [ "$pflag" = "true" ]
then
	if [ "$PERIODIC_SCHEDULE" = "" ]
	then
		echo
		echo "ASET startup unsuccessful:"
		echo "Schecule undefined for periodic invocation."
		echo "No tasks executed or scheduled. Check asetenv file."
		exit 2
	fi
fi

# report security level, time and working directory
echo
echo "ASET running at security level $ASETSECLEVEL"
echo
echo "Machine = `uname -n`; Current time = $TIMESTAMP"
echo
echo "$myname: Using $ASETDIR as working directory"

#--------------------------------------------------------- execute the tasks
if [ "$pflag" = "true" ]
then
# if -p option then just schedule cron for periodic invocation
	
	tmpcrontab=${ASETDIR}/tmp/tmpcrontab.$$
	$CRONTAB -l > $tmpcrontab
	if $GREP -s "aset" $tmpcrontab
	then
		echo
		echo "Warning! Duplicate ASET execution scheduled."
		echo "         Check crontab file."
	fi

	echo "$PERIODIC_SCHEDULE ${ASETDIR}/aset $newargs -d ${ASETDIR}"  \
		>> $tmpcrontab
	$CRONTAB $tmpcrontab
	echo
	echo "ASET execution scheduled through cron."

	$RM -f $tmpcrontab
	$CAT $log > $REPORT/execution.log
else
# start tasks in the list

	# get the security level set at last execution.
	get_prev_level
	if downgrading
	then
		DOWNGRADE=true
		echo
		echo "Downgrading security level: "
		echo "Previous level = $PREV_ASETSECLEVEL; \c"
		echo "Current level = $ASETSECLEVEL"
	else
		DOWNGRADE=false
	fi
	export DOWNGRADE

	if [ "$TASKS" = "" ]
	then
	   echo
	   echo "Tasklist undefined. No task performed."
	   exit
	fi

	echo
	echo "Executing task list ..."

	for task in $TASKS
	do
	   echo "	$task"
	done

	for task in $TASKS
	do
	   (/bin/sh ${ASETDIR}/tasks/${task} \
		> ${REPORT}/${task}.rpt 2>&1; \
		echo "Task $task is done." >> ${REPORT}/taskstatus)
	done &

	echo
	echo "All tasks executed. Some background tasks may still be running."
	echo
	echo "Run ${ASETDIR}/util/taskstat to check their status:"
	echo "     ${ASETDIR}/util/taskstat     [aset_dir]"
	echo
	echo "where aset_dir is ASET's operating directory,\c"
	echo "currently=${ASETDIR}."
	echo
	echo "When the tasks complete, the reports can be found in:"
	echo "     ${ASETDIR}/reports/latest/*.rpt"
	echo "You can view them by:"
	echo "     more ${ASETDIR}/reports/latest/*.rpt"

	# update security level
	echo "$ASETSECLEVEL" >> ${ASETDIR}/archives/asetseclevel.arch

	# leave a copy of execution log
	$CAT $log > $REPORT/execution.log
fi

# Done
exit 0
