#!/bin/sh
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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"

# The -c and -u options are used by system configruation.
USAGE="$0 [-c|-u]"
TEXTDOMAIN="SUNW_OST_OSCMD"
export TEXTDOMAIN

# As of Oct. 1, 1995, any new system shipped will have root
# property "energystar-v2" defined in its prom.
ESTAR_PROP="energystar-v2"

# Power Management configuration file
PWR_CONF=/etc/power.conf
SHUTDOWN_PATTERN="autoshutdown[ 	]"
TMP=/var/run/tmp1.$$

# If this flag is present, user will be asked the autoshutdown
# question again even when autoshutdown is already configured.
ASK_AGAIN_FLAG=/etc/.PM_RECONFIGURE

# This is provided for auto-install.
# If either of the files is present, autoshutdown will be configured
# accordingly silently.
SHUTDOWN_ENABLE_FLAG=/autoshutdown
SHUTDOWN_DISABLE_FLAG=/noautoshutdown

# Autoshutdown is not supported on diskless systems.
IS_DISKLESS=""

# Default autoshutdown setup.
DEFAULT_IDLE_TIME="30"
DEFAULT_START_TIME="9:00"
DEFAULT_FINISH_TIME="9:00"

# Currently autoshutdown setup in the configuration file.
CURRENT_IDLE_TIME=""
CURRENT_START_TIME=""
CURRENT_FINISH_TIME=""
CURRENT_BEHAVIOR=""

# Autoshutdown confirmation message to be prompted in the question1.
# In the following message, each escape sequence requires three
# backslashes to prevent the interpretation by the shell and gettext
# before being passed to ckyorn.  In the message catalog, each message
# will have two backslashes.
MSG1=`gettext '\\\tAfter 30 minutes of idle time on this system, your system \
state\\\n\\\twill automatically be saved to disk, and the system will \
power-off.\\\n\\\n\\\tLater, when you want to use the system again, and \
you turn the power\\\n\\\tback on, your system will be restored to its \
previous state,\\\n\\\tincluding all the programs that you were running.\
\\\n\\\n\\\tDo you want this automatic power-saving shutdown?\\\n\
\\\t(If this system is used as a server, answer n)'` 

# Message to be prompted in question2.
# In the following message, each escape sequence requires three
# backslashes to prevent the interpretation by the shell and gettext
# before being passed to ckyorn.  In the message catalog, each message
# will have two backslashes.
MSG2=`gettext '\\\tDo you want the system to ask about this again, when \
you next reboot?\\\n\\\t(This gives you the chance to try it before deciding \
whether\\\n\\\tto keep it.)'`

# The autoshutdown comment to be put into the power management config file.
SHUTDOWN_COMMENT="# Auto-Shutdown\t\tIdle(min)\tStart/Finish(hh:mm)\tBehavior"

# Set up path.
PATH="/usr/bin:/usr/sbin:${PATH}"
export PATH

#
# Get current autoshutdown setup.
#
get_behavior() {
	grep -s "$SHUTDOWN_PATTERN" $PWR_CONF > /dev/null
	if [ $? = 0 ]; then
		set - `grep "$SHUTDOWN_PATTERN" $PWR_CONF`
		CURRENT_IDLE_TIME=$2
		CURRENT_START_TIME=$3
		CURRENT_FINISH_TIME=$4
		CURRENT_BEHAVIOR=$5
	fi
}

#
# Set the autoshutdown behavior in the configuration file.
# The autoshutdown token can be preceded by spaces.
# The resulting configuration will be based on the first autoshutdown
# line if there is more than one in the configuration file.
#
set_behavior() {
	BEHAVIOR="$1"

	grep -s "$SHUTDOWN_PATTERN" $PWR_CONF > /dev/null
	if [ $? = 0 ]; then
		set - `grep "$SHUTDOWN_PATTERN" $PWR_CONF`
		CURRENT_IDLE_TIME=$2
		CURRENT_START_TIME=$3
		CURRENT_FINISH_TIME=$4
		CURRENT_BEHAVIOR=$5
	fi

	if [ "$BEHAVIOR" = "unconfigured" ]; then
		IDLE=$DEFAULT_IDLE_TIME
		START=$DEFAULT_START_TIME
		FINISH=$DEFAULT_FINISH_TIME
	else {
		if [ "$CURRENT_IDLE_TIME" = "" ]; then
			IDLE="$DEFAULT_IDLE_TIME"
		else
			IDLE="$CURRENT_IDLE_TIME"
		fi

		if [ "$CURRENT_START_TIME" = "" ]; then
			START="$DEFAULT_START_TIME"
		else
			START="$CURRENT_START_TIME"
		fi

		if [ "$CURRENT_FINISH_TIME" = "" ]; then
			FINISH="$DEFAULT_FINISH_TIME"
		else
			FINISH="$CURRENT_FINISH_TIME"
		fi
	} fi

	grep -v "# Auto-Shutdown[	]" $PWR_CONF | grep -v "$SHUTDOWN_PATTERN" > $TMP
	echo $SHUTDOWN_COMMENT >> $TMP
	echo "autoshutdown\t\t${IDLE}\t\t${START} ${FINISH}\t\t${BEHAVIOR}" >> \
		$TMP
	cp $TMP $PWR_CONF
	rm $TMP
}

#
# Print out the Energystar guidelines.
#
print_estar_guidelines() {
	echo
	echo "`gettext '\t================================================================'`"
	echo "`gettext '\tThis system is configured to conserve energy.'`"
        echo "`gettext '\t================================================================'`"
}

#
# Ask user for autoshutdown confirmation.
#
question1() {
        ans=`ckyorn -Q -d y -p "$1"`
	case $ans in
		y|yes|Y|Yes|YES)
			set_behavior shutdown
			echo
			echo "`gettext '\tAutoshutdown remains enabled.'`"
			break
			;;
		n|no|N|No|NO)
			set_behavior noshutdown
			echo
			echo "`gettext '\tAutoshutdown has been disabled.'`"
			break
			;;
	esac
}

#
# Ask user whether they want to be asked about the question again during
# next reboot.
#
question2() {
        ans=`ckyorn -Q -d n -p "$1"`
	case $ans in
		y|yes|Y|Yes|YES)
			touch $ASK_AGAIN_FLAG
			echo "`gettext '\n\tThe system will ask you about automatic shutdown at the next reboot.'`"
			break
			;;
		n|no|N|No|NO)
			rm -f $ASK_AGAIN_FLAG
			echo "`gettext '\n\tThe system will not ask you again about automatic shutdown.'`"
			break
			;;
	esac
}


################
#     Main     #
################

#
# Exit if /etc/power.conf does not exist or is not writable.
#
if [ ! -f $PWR_CONF -o ! -w $PWR_CONF ]; then
	exit 1
fi


#
# Usage: sysidpm [-c|-u]
#
if [ $# -gt 1 ]; then
	echo $USAGE
	exit 1
fi


#
# The postinstall script of some power management package should have
# added this command into the application list in /etc/.sysidconfig.apps.
# System configuration and unconfiguration will call those applications
# with option -c and -u respectively.
#
if [ $# -eq 1 ]; then
	case $1 in
		-c)	# Does not need to do anything.
			exit 0 ;;
		-u)
			# Reset the behavior back to unconfigured state.
			set_behavior unconfigured

			# Remove the statefile line too.
			grep -v statefile $PWR_CONF > $TMP
			cp $TMP $PWR_CONF
			rm $TMP

			exit 0 ;;
		*)
			echo $USAGE
			exit 1 ;;
	esac		
fi


#
# Get current autoshutdown setup.
#
get_behavior

#
# If this is a diskless system, silently disable autoshutdown and exit.
#
ROOT_FSTYPE=`df -n / | (read w1 w2 w3; echo $w3)`
if [ $ROOT_FSTYPE != "ufs" ]; then
	set_behavior noshutdown
	exit 0
fi


#
# If /autoshutdown is present, silently enable autoshutdown and exit.
#
if [ -f $SHUTDOWN_ENABLE_FLAG ]; then
	set_behavior shutdown
	rm $SHUTDOWN_ENABLE_FLAG
	exit 0
fi

#
# If /noautoshutdown is present, silently disable autoshutdown and
# exit.
#
if [ -f $SHUTDOWN_DISABLE_FLAG ]; then
	set_behavior noshutdown
	rm $SHUTDOWN_DISABLE_FLAG
	exit 0
fi


#
# If this is an EnergyStar compliant system, the default should
# have autoshutdown enabled. However we don't want to surprise
# users, so let's confirm with the user.
#
prtconf -vp | grep -s -w ${ESTAR_PROP} > /dev/null
if [ $? = 0 ]; then
	if [ "$CURRENT_BEHAVIOR" = "unconfigured" -o -f $ASK_AGAIN_FLAG ]; then
		print_estar_guidelines
		question1 "$MSG1"
		question2 "$MSG2"
		# Currently, we do not have documentation for changing and 
		# setting workstation energy-saving features.  When we do, 
		# gettext messages should be emitting here. see CR6520924
		#
		echo
	fi
	exit 0
fi

#
# The rest of the cases will have 'default' autoshutdown behavior.
#
if [ "$CURRENT_BEHAVIOR" = "unconfigured" ]; then
	set_behavior default
	exit 0
fi

#
# We are here because either the autoshutdown line has been
# removed or the behavior has been configured. It can be a result
# of upgrade. In that case, the configuration file should not
# be changed. Let's exit.
exit 0
