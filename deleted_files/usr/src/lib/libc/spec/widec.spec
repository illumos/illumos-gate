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
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libc/spec/widec.spec

function	fgetws
include		<stdio.h>, <widec.h>
declaration	wchar_t *fgetws(wchar_t *_RESTRICT_KYWD s, int n, \
		FILE *_RESTRICT_KYWD stream)
version		SUNW_1.1
errno		EOVERFLOW
exception	$return == 0
end

function	getws
include		<stdio.h>, <widec.h>
declaration	wchar_t *getws(wchar_t *s)
version		SUNW_1.1
errno		EOVERFLOW
exception	$return == 0
end

function	putws
include		<stdio.h>, <widec.h>
declaration	int putws(const wchar_t *s)
version		SUNW_1.1
exception	$return == EOF
end

function	wscasecmp
include		<widec.h>
declaration	int wscasecmp(const wchar_t *s1, const wchar_t *s2)
version		SUNW_1.1
end

function	wscol
include		<widec.h>
declaration	int wscol(const wchar_t *s)
version		SUNW_1.1
end

function	wsdup
include		<widec.h>
declaration	wchar_t *wsdup(const wchar_t *s)
version		SUNW_1.1
exception	$return == 0
end

function	wsncasecmp
include		<widec.h>
declaration	int wsncasecmp(const wchar_t *s1, const wchar_t *s2, size_t n)
version		SUNW_1.1
end

function	wsprintf
include		<stdio.h>, <widec.h>
declaration	int wsprintf(wchar_t *s, const char *format, ... )
version		SUNW_1.1
exception	$return < 0
end

function	wsscanf
include		<stdio.h>, <widec.h>
declaration	int wsscanf(wchar_t *s, const char *format, ... )
version		SUNW_1.1
exception	$return < 0
end
