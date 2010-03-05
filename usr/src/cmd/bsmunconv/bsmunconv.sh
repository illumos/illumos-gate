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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG=bsmunconv
PATH=/usr/sbin:/usr/bin:/sbin

TEXTDOMAIN="SUNW_OST_OSCMD"
export TEXTDOMAIN
ZONENAME=/sbin/zonename
DEVFSADM=/usr/sbin/devfsadm


# Perform required permission checks, depending on value of LOCAL_ROOT
# (whether we are converting the active OS or just alternative boot
# environments).
permission()
{
cd /usr/lib
ZONE=`${ZONENAME}`
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

RESP="x"
while [ "$RESP" != `gettext "y"` -a "$RESP" != `gettext "n"` ]
do
gettext "This script is used to disable device allocation.\n"
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

# disable device allocation

dev_allocation_unconvert()
{
# Turn off device allocation. This is not currently done for alternate
# boot environments.
if [ -z "$ROOT" -o "$ROOT" = "/" ]
then
	${DEVFSADM} -d
fi

# Restore default policy for removable and hotpluggable volumes
rm -f ${ROOT}/etc/hal/fdi/policy/30user/90-solaris-device-allocation.fdi
}

# main

if [ $# -eq 0 ]
then

	# converting local root, perform all permission checks
	LOCAL_ROOT=true
	permission

	# begin conversion
	ROOT=

	dev_allocation_unconvert

	echo
	gettext "Device allocation has been disabled. Reboot the system now\n"
	gettext "to come up without this feature.\n"
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
		dev_allocation_unconvert $ROOT
	done

	echo
	gettext "Device allocation has been disabled. Reboot each non-local\n"
	gettext "system that was disabled to come up without this feature.\n"
fi

exit 0

