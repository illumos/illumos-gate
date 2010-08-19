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
#
# Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
#

# This shell script warns the administrator when there are problems or
# potential problems with the audit daemon.  The default script sends
# a message to the machine console in the case where there
# is no audit space available.  It has comments in a few places where
# additional actions might be appropriate (eg. clearing some space).
#
#---------------------------------------------------------------------------
# send mail and generate syslog output
#
# $MESSAGE and $SUBJECT are set by the caller
#
# edit this function to omit syslog or mail output.
#---------------------------------------------------------------------------
send_msg() {
	MAILER=/usr/bin/mailx
	SED=/usr/bin/sed
	LOGCMD="$LOGGER -p daemon.alert"

	ADDRESS=audit_warn		# standard alias for audit alerts

	# turn off redirect to /dev/null to see sendmail output
	/usr/lib/sendmail -bv $ADDRESS > /dev/null

	if [ $? -ne 0 ]
	then
		$LOGCMD "The $ADDRESS mail alias is not defined"
		ADDRESS=root
	fi

	if [ -z "$COUNT" -o "0$COUNT" -eq 1 ]
	then
		echo "$0: $MESSAGE" | $MAILER -s "$SUBJECT" $ADDRESS
	fi

	STRIPPEDMSG=`echo "$MESSAGE" | $SED -e "s/\n/ /g"`
	$LOGCMD $STRIPPEDMSG
}

# If you change this script, script debug should first be done via the
# command line, so input errors are output via "echo," but syslog
# debug messages are better for testing from auditd since the echo
# output would be lost.  For testing with auditd, replace
# 'DEBUG_OUT="echo"' with 'DEBUG_OUT="$LOGGER -p daemon.debug"'

LOGGER="/usr/bin/logger"
DEBUG_OUT="echo"

# Check usage
if [ "$#" -lt "1" -o "$#" -gt "5" ]
then
	$DEBUG_OUT "Usage: $0 <option> [<args>]"
	exit 1
fi

# Process args
while [ -n "$1" ]
do

	SUBJECT="AUDIT DAEMON WARNING ($1)"

	case "$1" in 

	"soft" )	# Check soft arg
			# One audit filesystem has filled to the soft limit
			# that is configured in the audit service.

			if [ ! -n "$2" ]
			then
				$DEBUG_OUT "$0: Need filename arg with 'soft'!"
				exit 1
			else
				FILE=$2
			fi

			# Set message
			MESSAGE="Soft limit exceeded in file $FILE."
			send_msg

			break
			;;

	"allsoft" )	# Check all soft arg
			# All the audit filesystems have filled to the soft
			# limit set up in the audit service configuration.

			# Set message
			MESSAGE="Soft limit exceeded on all filesystems."
			send_msg

			break
			;;

	"hard" )	# Check hard arg
			# One audit filesystem has filled completely.

			if [ ! -n "$2" ]
			then
				$DEBUG_OUT "$0: Need filename arg with 'hard'!"
				exit 1
			else
				FILE=$2
			fi

			# Set message
			MESSAGE="Hard limit exceeded in file $FILE."
			send_msg

			break
			;;

	"allhard" )	# Check all hard arg
			# All the audit filesystems have filled completely.
			# The audit daemon will remain in a loop sleeping
			# and checking for space until some space is freed.

			if [ ! -n "$2" ]
			then
				$DEBUG_OUT "$0: Need count arg with 'allhard'!"
				exit 1
			else
				COUNT=$2
			fi

			# Set message
			MESSAGE="Hard limit exceeded on all filesystems. (count=$COUNT)"

			send_msg

			# This might be a place to make space in the
			# audit file systems.

			break
			;;

	"ebusy" )	# Check ebusy arg
			# The audit daemon is already running and can not
			# be started more than once.

			# Set message
			MESSAGE="The audit daemon is already running on this system."
			send_msg

			break
			;;

	"tmpfile" )	# Check tmpfile arg
			# The tmpfile used by the audit daemon (binfile) could
			# not be opened even unlinked or symlinked.
			# This error will cause the audit daemon to exit at
			# start.  If it occurs later the audit daemon will
			# attempt to carry on.

			if [ ! -n "$2" ]
			then
				$DEBUG_OUT "$0: Need error string arg with 'tmpfile'!"
				exit 1
			else
				ERROR=$2
			fi
			# Set message
			MESSAGE="The audit daemon is unable to update /var/run, error=$ERROR.\n This implies a serious problem."

			send_msg

			break
			;;

	"nostart" )	# Check no start arg

			# auditd attempts to set the audit state; if
			# it fails, it exits with a "nostart" code.
			# The most likely cause is that the kernel
			# audit module did not load due to a
			# configuration error.  auditd is not running.
			#
			# The audit daemon can not be started until
			# the error is corrected and the system is
			# rebooted.

			MESSAGE="audit failed to start because it cannot read or\
 write the system's audit state. This may be due to a configuration error.\n\n\
Must reboot to start auditing!"

			send_msg

			break
			;;

	"auditoff" )	# Check audit off arg
			# Someone besides the audit daemon called the
			# system call auditon to "turn auditing off"
			# by setting the state to AUC_NOAUDIT.  This
			# will cause the audit daemon to exit.

			# Set message
			MESSAGE="Auditing has been turned off unexpectedly."
			send_msg

			break
			;;

	"postsigterm" )	# Check post sigterm arg
			# While the audit daemon was trying to shutdown
			# in an orderly fashion (corresponding to audit -t)
			# it got another signal or an error.  Some records
			# may not have been written.

			# Set message
			MESSAGE="Received some signal or error while writing\
 audit records after SIGTERM.  Some audit records may have been lost."
			send_msg

			break
			;;

	"plugin" )	# Check plugin arg

			# There is a problem loading a plugin or a plugin
			# has reported a serious error.
			# Output from the plugin is either blocked or halted.

			if [ ! -n "$2" ]
			then
				$DEBUG_OUT "$0: Need plugin name arg with 'plugin'!"
				exit 1
			else
				PLUGNAME=$2
			fi

			if [ ! -n "$3" ]
			then
				$DEBUG_OUT "$0: Need error arg with 'plugin'!"
				exit 1
			else
				ERROR=$3
			fi

			if [ ! -n "$4" ]
			then
				$DEBUG_OUT "$0: Need text arg with 'plugin'!"
				exit 1
			else
				TEXT=$4
			fi

			if [ ! -n "$5" ]
			then
				$DEBUG_OUT "$0: Need count arg with 'plugin'!"
				exit 1
			else
				COUNT=$5
				if [ $COUNT -eq 1 ]; then
					S=""
				else
					S="s"
				fi
			fi

			# Set message
			MESSAGE="The audit daemon has experienced the\
 following problem with loading or executing plugins:\n\n\
$PLUGNAME: $ERROR\n\
$TEXT\n\
This message has been displayed $COUNT time$S."
			send_msg
			break
			;;
	
	* )		# Check other args
			$DEBUG_OUT "$0: Arg not recognized: $1"
			exit 1
			;;

	esac

	shift
done

exit 0
