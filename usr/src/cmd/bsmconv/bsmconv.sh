#! /bin/sh
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

PROG=bsmconv

TEXTDOMAIN="SUNW_OST_OSCMD"
export TEXTDOMAIN

DEVALLOC=/etc/security/device_allocate
DEVMAPS=/etc/security/device_maps
DEVFSADM=/usr/sbin/devfsadm
MKDEVALLOC=/usr/sbin/mkdevalloc
MKDEVMAPS=/usr/sbin/mkdevmaps
ZONENAME=/sbin/zonename

# Perform required permission checks, depending on value of LOCAL_ROOT
# (whether we are converting the active OS or just alternative boot
# environments).
permission()
{
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
gettext "This script is used to enable device allocation.\n"
form=`gettext "Shall we continue with the conversion now? [y/n]"`
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

# Do some sanity checks to see if the arguments to bsmconv
# are, in fact, root directories for clients.
sanity_check()
{
for ROOT in $@
do
	if [ -d $ROOT -a -w $ROOT -a -f $ROOT/etc/system -a -d $ROOT/usr ]
	then
		# There is a root directory to write to,
		# so we can potentially complete the conversion.
		:
	else
		form=`gettext "%s: ERROR: %s doesn't look like a client's root."`
		printf "${form}\n" $PROG $ROOT
		form=`gettext "%s: ABORTED: nothing done."`
		printf "${form}\n" $PROG
		exit 4
	fi
done
}

# dev_allocation_convert
#	All the real work gets done in this function

dev_allocation_convert()
{
# Prevent automount of removable and hotpluggable volumes
# by forcing volume.ignore HAL property on all such volumes.
if [ -d ${ROOT}/etc/hal/fdi ] ; then
	cat > ${ROOT}/etc/hal/fdi/policy/30user/90-solaris-device-allocation.fdi <<FDI
<?xml version="1.0" encoding="UTF-8"?>
<deviceinfo version="0.2">
  <device>
    <match key="info.capabilities" contains="volume">
      <match key="@block.storage_device:storage.removable" bool="true">
        <merge key="volume.ignore" type="bool">true</merge>
      </match>
      <match key="@block.storage_device:storage.hotpluggable" bool="true">
        <merge key="volume.ignore" type="bool">true</merge>
      </match>
    </match>
  </device>
</deviceinfo>
FDI
fi

# Initialize device allocation

form=`gettext "%s: INFO: initializing device allocation."`
printf "${form}\n" $PROG

# Need to determine if Trusted Extensions is enabled.  This is tricky
# because we need to know if TX will be active on the boot following
# bsmconv.  Check the setting in etc/system (other methods won't work
# because TX is likely not yet fully active.)
#
grep "^[ 	]*set[ 	][ 	]*sys_labeling[ 	]*=[ 	]*1" \
    $ROOT/etc/system > /dev/null 2>&1

if [ $? = 0 ]; then
	# Trusted Extensions is enabled (but possibly not yet booted).
	# This is not currently done for alternate boot environments.
	if [ -z "$ROOT" -o "$ROOT" = "/" ]
	then
		${DEVFSADM} -e
	fi
else
	if [ ! -f ${ROOT}/${DEVALLOC} ]
	then
		${MKDEVALLOC} > ${ROOT}/$DEVALLOC
	fi
	if [ ! -f ${ROOT}/${DEVMAPS} ]
	then
		${MKDEVMAPS} > ${ROOT}/$DEVMAPS
	fi
fi
}

# main loop

sanity_check $@
if [ $# -eq 0 ]
then
	# converting local root, perform all permission checks
	LOCAL_ROOT=true
	permission

	ROOT=
	
	dev_allocation_convert

	echo
	gettext "Device allocation is ready. If there were any errors, please\n"
	gettext "fix them now. Reboot this system now to come up with device\n"
	gettext "allocation enabled."
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
		form=`gettext "%s: INFO: converting boot environment %s ..."`
		printf "${form}\n" $PROG $ROOT
		dev_allocation_convert $ROOT
		form=`gettext "%s: INFO: done with boot environment %s"`
		printf "${form}\n" $PROG $ROOT
	done

	echo
	gettext "Device allocation is ready. If there were any errors,\n"
	gettext "please fix them now. Reboot each non-local system\n"
	gettext "converted to come up with device allocation enabled.\n"
fi

exit 0
