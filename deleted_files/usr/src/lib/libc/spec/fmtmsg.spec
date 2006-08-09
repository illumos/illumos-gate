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
#

function	addsev
declaration	int addsev(int int_val, const char *string)
version		SUNW_0.8
exception	$return == -1
end

function	addseverity
declaration	int addseverity(int severity, const char *string)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
exception	$return == MM_NOTOK
end

function	_addseverity
weak		addseverity
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end

function	fmtmsg
include		<fmtmsg.h>
declaration	int fmtmsg(long classification, const char *label, \
			int severity, const char *text, const char *action, \
			const char *tag)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
exception	$return== MM_NOTOK || $return == MM_NOMSG || $return == MM_NOCON
end

function	_fmtmsg
weak		fmtmsg 
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
end
