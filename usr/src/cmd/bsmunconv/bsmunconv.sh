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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

PROG=bsmunconv
TEXTDOMAIN="SUNW_OST_OSCMD"
export TEXTDOMAIN

permission()
{
cd /usr/lib
ZONE=`/sbin/zonename`
if [ ! "$ZONE" = "global" ]
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
if [ "$RUNLEVEL" -ne "S" ]
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
gettext "This script is used to disable the Basic Security Module (BSM).\n"
form=`gettext "Shall we continue the reversion to a non-BSM system now? [y/n]"`
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

# turn off device allocation
/usr/sbin/devfsadm -d

# disable auditd service
/usr/sbin/svcadm disable system/auditd 

# restore volume manager startup on next boot using the
# previous state saved by bsmconv.sh
state="enable"
if [ -f ${ROOT}/etc/security/spool/vold.state ]; then 
	prev_state=`cat ${ROOT}/etc/security/spool/vold.state`
	if [ ${prev_state} != "online" ]; then
		state="disable"
	fi
fi
touch  ${ROOT}/var/svc/profile/upgrade
cat >> ${ROOT}/var/svc/profile/upgrade <<SVC_UPGRADE
svcadm ${state} svc:/system/filesystem/volfs:default
SVC_UPGRADE

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

# Even though cron should not be running at run-level 1, it may have
# been started by hand.

/usr/bin/pgrep -u root -f /usr/sbin/cron > /dev/null
if [ $? -eq 0 ]; then
	form=`gettext "%s: INFO: stopping the cron daemon."`
	printf "${form}\n" $PROG

	/usr/sbin/svcadm disable -t system/cron
fi

rm -f /var/spool/cron/atjobs/*.au
rm -f /var/spool/cron/crontabs/*.au

}

# main

permission

if [ $# -eq 0 ]
then
	ROOT=
	bsmunconvert
	echo
	gettext "The Basic Security Module has been disabled.\n"
	gettext "Reboot this system now to come up without BSM.\n"
else
	for ROOT in $@
	do
		bsmunconvert $ROOT
	done
	echo
	gettext "The Basic Security Module has been disabled.\n"
	gettext "Reboot each system that was disabled to come up without BSM.\n"
fi

exit 0

