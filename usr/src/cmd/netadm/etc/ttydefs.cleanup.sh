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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.

TMP=${FLASH_ROOT}/tmp/SUNWcsr.ttydefs.$$
TTYDEFS_FILE=${FLASH_ROOT}/etc/ttydefs

# If the system is an SPARC-Enterprise system,
# then the /etc/ttydefs file must include the correct console entry.
isSparcEnterprise()
{
	# Add the crtscts flag for the console settings if needed.
	if [ ! "`grep '^console:.* crtscts:' ${TTYDEFS_FILE}`" ] ; then
		sed -e "/^console:.*onlcr:/ {
			s/onlcr:/onlcr crtscts:/
			}" ${TTYDEFS_FILE} > ${TMP}
		# Update the ttydefs file
		cp ${TMP} ${TTYDEFS_FILE}
		rm -f ${TMP}
	fi
}

# Restore the ttydefs file to the default
defaultPlatform()
{
	if [ "`grep '^console:.* crtscts:' ${TTYDEFS_FILE}`" ] ; then
		sed -e "/^console:.* crtscts:/ {
		s/ crtscts:/:/
		}" ${TTYDEFS_FILE} > ${TMP}
		# Update the ttydefs file
		cp ${TMP} ${TTYDEFS_FILE}
		rm -f ${TMP}
	fi
}

# Determine action for the appropriate system
PLATFORM_TOKEN=`prtconf -b | awk '/^name:/ { print $2 }'`
case "$PLATFORM_TOKEN"
in
	SUNW,SPARC-Enterprise)
		isSparcEnterprise
		;;
	*)
		defaultPlatform
		;;
esac

exit 0
