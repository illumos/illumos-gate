#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
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
#ident	"%Z%%M%	%I%	%E% SMI"

#
# Extract MACROs from .msg file
# The MACROs which are referenced by MSG_INTL() go to CATA_MSG_INTL_LIST
# The MACROs which are referenced by MSG_ORIG() go to CATA_MSG_ORIG_LIST
#

BEGIN {
	# skip == 0
	#	The MACRO will not be recorded
	skip = 0

	# which == 0
	#	Collecting MACRO's in between _START_ and _END_
	# which == 1
	#	Collecting MACRO's in after _END_
	which = 0
}

#
# If the MACROs are surrounded by _CHKMSG_SKIP_BEGIN_ and
# _CHKMSG_SKIP_END_, these MACRO will not be recorded for checking.
# It is assumed that the use of MACRO are checked by developers.
#
/_CHKMSG_SKIP_BEGIN_/ {
	if ($3 == mach)
		skip = 1
}
/_CHKMSG_SKIP_END_/ {
	if ($3 == mach)
		skip = 0
}

/^@/ {
	dontprint = 0

	if ($2 == "_START_") {
		which = 0
		dontprint = 1
	} else if ($2 == "_END_") {
		which = 1
		dontprint = 1
	} else if (match($2, "MSG_ID_") != 0) {
		dontprint = 1
	}

	if (skip == 1 || dontprint == 1)
		next

	if (which == 0)
		print $2 >> "CATA_MSG_INTL_LIST"
	else
		print $2 >> "CATA_MSG_ORIG_LIST"
}
