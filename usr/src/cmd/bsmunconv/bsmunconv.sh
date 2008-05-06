#! /bin/sh
#
#
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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

PROG=bsmunconv
TEXTDOMAIN="SUNW_OST_OSCMD"
export TEXTDOMAIN

# Perform required permission checks, depending on value of LOCAL_ROOT
# (whether we are converting the active OS or just alternative boot
# environments).
permission()
{
cd /usr/lib
ZONE=`/sbin/zonename`
if [ ! "$ZONE" = "global" -a "$LOCAL_ROOT" = "true" ]
then
	form=`gettext "%s: ERROR: you must be in the global zone to run this script."`
	printf "${form}\n" $PROG
	exit 1
fi

WHO=`id | cut -f1 -d" "`
if [ ! "$WHO" = "uid=0(root)" ]
then
	form=`gettext "%s: ERROR: you must be super-user to run this script."`
	printf "${form}\n" $PROG
	exit 1
fi

set -- `/usr/bin/who -r`
RUNLEVEL="$3"
if [ "$RUNLEVEL" -ne "S" -a "$LOCAL_ROOT" = "true" ]
then
	form=`gettext "%s: ERROR: this script should be run at run level S."`
	printf "${form}\n" $PROG
	form=`gettext "Are you sure you want to continue? [y/n]"`
	echo "$form \c"
	read RESP
	case $RESP in
		`gettext "n"`*|`gettext "N"`* ) exit 1 ;;
	esac
fi

RESP="x"
while [ "$RESP" != `gettext "y"` -a "$RESP" != `gettext "n"` ]
do
gettext "This script is used to disable Solaris Auditing and device allocation.\n"
form=`gettext "Would you like to continue now? [y/n]"`
echo "$form \c"
read RESP
done

if [ "$RESP" = `gettext "n"` ]
then
	form=`gettext "%s: INFO: aborted, due to user request."`
	printf "${form}\n" $PROG
	exit 2
fi
}

bsmunconvert()
{
# Turn off device allocation. This is not currently done for alternate
# boot environments.
if [ -z "$ROOT" -o "$ROOT" = "/" ]
then
	/usr/sbin/devfsadm -d
fi

# disable auditd service on next boot
cat >> ${ROOT}/var/svc/profile/upgrade <<SVC_UPGRADE
/usr/sbin/svcadm disable system/auditd 
SVC_UPGRADE

# Restore default policy for removable and hotpluggable volumes
rm -f ${ROOT}/etc/hal/fdi/policy/30user/90-solaris-device-allocation.fdi

# Turn off auditing in the loadable module

if [ -f ${ROOT}/etc/system ]
then
	form=`gettext "%s: INFO: removing c2audit:audit_load from %s/etc/system."`
	printf "${form}\n" $PROG $ROOT
	grep -v "c2audit:audit_load" ${ROOT}/etc/system > /tmp/etc.system.$$
	mv /tmp/etc.system.$$ ${ROOT}/etc/system
else
	form=`gettext "%s: ERROR: can't find %s/etc/system."`
	printf "${form}\n" $PROG $ROOT
	form=`gettext "%s: ERROR: audit module may not be disabled."`
	printf "${form}\n" $PROG
fi

# If we are currently converting the active host (${ROOT}="/") we will
# need to ensure that cron is not running. cron should not be running
# at run-level S, but it may have been started by hand.

if [ -z "$ROOT" -o "$ROOT" = "/" ]
then
	/usr/bin/pgrep -u root -f /usr/sbin/cron > /dev/null
	if [ $? -eq 0 ]; then
		form=`gettext "%s: INFO: stopping the cron daemon."`
		printf "${form}\n" $PROG

		/usr/sbin/svcadm disable -t system/cron
	fi
fi

rm -f ${ROOT}/var/spool/cron/atjobs/*.au
rm -f ${ROOT}/var/spool/cron/crontabs/*.au

}

# main

if [ $# -eq 0 ]
then

	# converting local root, perform all permission checks
	LOCAL_ROOT=true
	permission

	# begin conversion
	ROOT=
	bsmunconvert
	echo
	gettext "Solaris Auditing and device allocation has been disabled.\n"
	gettext "Reboot the system now to come up without these features.\n"
else

	# determine if local root is being converted ("/" passed on
	# command line), if so, full permission check required
	LOCAL_ROOT=false
	for ROOT in $@
	do
		if [ "$ROOT" = "/" ]
		then
			LOCAL_ROOT=true
		fi
	done

	# perform required permission checks (depending on value of
	# LOCAL_ROOT)
	permission

	for ROOT in $@
	do
		bsmunconvert $ROOT
	done

	echo
	gettext "Solaris Auditing and device allocation has been disabled.\n"
	gettext "Reboot each system that was disabled to come up without these features.\n"
fi

exit 0

