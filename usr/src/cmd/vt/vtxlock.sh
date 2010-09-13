#!/sbin/sh
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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# $1 is the display to be locked.
# /var/xauth/$1 is a symbolic link to the actual xauth file.
#

XSCREENSAVER_LOCK=/usr/openwin/bin/xscreensaver-command
XSCREENSAVER_LOCKARGS="-lock"
XSCREENSAVER_CHECKARGS="-time"
XSCREENSAVER_LOCKED="locked"

OTHER_LOCK=/usr/openwin/bin/xlock
OTHER_LOCKARGS="-mode blank"

XLSATOMS="/usr/openwin/bin/xlsatoms"
XLSATOMS_ARGS="-name"
CDE_ATOM=_DT_SM_PREFERENCES
GNOME_ATOM=GNOME_SM_DESKTOP
XSCREENSAVER_ATOM=SCREENSAVER

DISPLAY=:$1; export DISPLAY
XAUTHORITY=/var/xauth/$1; export XAUTHORITY

#
# Note that these text strings we're greping are not localized.
#

#
# Is it GNOME?
#
if ${XLSATOMS} ${XLSATOMS_ARGS} ${GNOME_ATOM} 2>/dev/null \
    | grep -w ${GNOME_ATOM} >/dev/null; then
	#
	# Is it xscreensaver?
	#
	# xscreensaver
	if [ -x ${XSCREENSAVER_LOCK} ]; then
		${XSCREENSAVER_LOCK} ${XSCREENSAVER_CHECKARGS} 2>/dev/null \
		    | grep -w ${XSCREENSAVER_LOCKED} >/dev/null && exit 0

		${XSCREENSAVER_LOCK} ${XSCREENSAVER_LOCKARGS} >/dev/null 2>&1 &
		exit 0
	fi
fi

#
# Is it CDE?
#
if ${XLSATOMS} ${XLSATOMS_ARGS} ${CDE_ATOM} 2>/dev/null \
    | grep -w ${CDE_ATOM} >/dev/null; then
	exit 0
fi

# In other situations, use xlock as default.
if [ -x ${OTHER_LOCK} ]; then
	${OTHER_LOCK} ${OTHER_LOCKARGS} &
	exit 0
fi

exit 0
