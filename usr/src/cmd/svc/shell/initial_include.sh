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
# Copyright 2012 OmniTI Computer Consulting, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# set system hostname
#
set_hostname()
{
	/bin/hostname "$1"
	echo "$1" > /etc/nodename
}

#
# set system timezone
#
set_timezone()
{
	sed -i -e "s:^TZ=.*:TZ=${1}:" /etc/default/init
}

#
# sc_profile_timezone
#
sc_profile_timezone()
{
	FILE=${1}
	if [ -z "${FILE}" ]; then
		FILE=/etc/svc/profile/site/sc_profile.xml
	fi
	if [ -f "${FILE}" ]; then
		NEWTZ=`awk -F'"' '/name="localtime"/{print $6;}' "${FILE}"`
		if [ -n "${NEWTZ}" ]; then
			set_timezone ${NEWTZ}
		fi
	fi
}
