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
# ident	"%Z%%M%	%I%	%E% SMI"

@ _START_

# Message file for cmd/sgs/moe.

@ MSG_ID_MOE

# Usage Messages

@ MSG_ARG_USAGE		"usage: %s [-c] [-32 | -64] [-s | -v] path\n\
			 \t[-c]\t\tdisplay the class of object\n\
			 \t[-32]\t\tonly expand 32-bit objects\n\
			 \t[-64]\t\tonly expand 64-bit objects\n\
			 \t[-s]\t\tsuppress all messages\n\
			 \t[-v]\t\tverbose (show error messages)\n"

@ MSG_PRE_32		"32-bit: "
@ MSG_PRE_64		"64-bit: "

@ _END_

@ MSG_STR_OPTIONS	"c3:6:l:sv"
@ MSG_STR_EMPTY		""

@ MSG_FMT_SIMPLE	"%s%s\n"
@ MSG_FMT_VERBOSE	"%s: %s%s\n";

@ MSG_SUNW_OST_SGS	"SUNW_OST_SGS"
