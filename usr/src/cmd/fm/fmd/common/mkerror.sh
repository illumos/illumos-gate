#!/bin/sh
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
#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"

#pragma ident	"%Z%%M%	%I%	%E% SMI"

input="`cat`"
[ -z "$input" ] && exit 1

echo "\
/*\n\
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.\n\
 * Use is subject to license terms.\n\
 */\n\
\n\
#pragma ident\t\"%Z%%M%\t%I%\t%E% SMI\"\n\
\n\
#include <strings.h>
#include <fmd_error.h>
\n\
static const char *const _fmd_ereports[] = {"

pattern='^[ ]*EFMD_\([A-Z0-9_]*\).*,*'
replace='	"ereport.fm.fmd.\1",'

echo "$input" | sed -n "s/$pattern/$replace/p" | tr '[A-Z]' '[a-z]' || exit 1

echo "\
};\n\
\n\
static const char *const _fmd_errstrs[] = {"

pattern='^[ ]*EFMD_[A-Z0-9_]*.*\* \(.*\) \*.*'
replace='	"\1",'

echo "$input" | sed -n "s/$pattern/$replace/p" || exit 1

echo "\
};\n\
\n\
static const int _fmd_nereports =\n\
    sizeof (_fmd_ereports) / sizeof (_fmd_ereports[0]);\n\
\n\
static const int _fmd_nerrstrs =\n\
    sizeof (_fmd_errstrs) / sizeof (_fmd_errstrs[0]);\n\
\n\
const char *
fmd_errclass(int err)
{
	const char *c;

	if (err >= EFMD_UNKNOWN && (err - EFMD_UNKNOWN) < _fmd_nereports)
		c = _fmd_ereports[err - EFMD_UNKNOWN];
	else
		c = _fmd_ereports[0];

	return (c);
}

const char *
fmd_strerror(int err)
{
	const char *s;

	if (err >= EFMD_UNKNOWN && (err - EFMD_UNKNOWN) < _fmd_nerrstrs)
		s = _fmd_errstrs[err - EFMD_UNKNOWN];
	else if (err < 0 || (s = strerror(err)) == NULL)
		s = _fmd_errstrs[0];

	return (s);
}

int
fmd_set_errno(int err)
{
	errno = err;
	return (-1);
}"

exit 0
