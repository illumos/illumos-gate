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

function	fprintf 
include		<stdio.h>
declaration	int fprintf(FILE *_RESTRICT_KYWD strm, \
			const char *_RESTRICT_KYWD format, ... )
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 \
		amd64=SUNW_0.7
errno		EFBIG 
exception	$return == -1
end

function	printf 
include		<stdio.h>
declaration	int printf(const char *_RESTRICT_KYWD format, ... )
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
errno		EFBIG 
exception	$return == -1
end

function	sprintf 
include		<stdio.h>
declaration	int sprintf(char *_RESTRICT_KYWD s, \
			const char *_RESTRICT_KYWD format, ... )
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
errno		EFBIG 
exception	$return == -1
end

function	vfprintf 
include		<stdio.h>, <stdarg.h>
declaration	int vfprintf(FILE *_RESTRICT_KYWD stream, \
			const char *_RESTRICT_KYWD format, va_list ap)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
errno		EFBIG 
exception	
end

function	vprintf 
include		<stdio.h>, <stdarg.h>
declaration	int vprintf(const char *_RESTRICT_KYWD format, va_list ap)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
errno		EFBIG 
exception	
end

function	vsprintf 
include		<stdio.h>, <stdarg.h>
declaration	int vsprintf(char *_RESTRICT_KYWD s, \
			const char *_RESTRICT_KYWD format, va_list ap)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7  \
		amd64=SUNW_0.7
errno		EFBIG 
exception	
end

function	fwprintf
include		<stdio.h>, <wchar.h>
declaration	int fwprintf(FILE *_RESTRICT_KYWD stream, \
		const wchar_t *_RESTRICT_KYWD format, ...)
version		SUNW_1.18
end

function	wprintf
include		<stdio.h>, <wchar.h>
declaration	int wprintf(const wchar_t *_RESTRICT_KYWD format, ...)
version		SUNW_1.18
end
