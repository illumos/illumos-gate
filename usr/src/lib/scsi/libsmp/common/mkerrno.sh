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
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
#

echo "\
/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#pragma ident\t\"@(#)mkerrno.sh\t1.2\t08/07/31\tSMI\"

#include <strings.h>
#include <scsi/libsmp.h>

static const struct {
\tchar *name;\t\t/* error name */
\tchar *msg;\t\t/* error message */
} _smp_errstr[] = {"

pattern='^	\(ESMP_[A-Z0-9_]*\),*'
replace='	{ "\1",'
open='	\/\* '
openrepl='"'
close=' \*\/$'
closerepl='" },'

( sed -n "s/$pattern/$replace/p" | sed -n "s/$open/$openrepl/p" |
    sed -n "s/$close/$closerepl/p" ) || exit 1

echo "\
};\n\
\n\
static int _smp_nerrno = sizeof (_smp_errstr) /\n\
    sizeof (_smp_errstr[0]);\n\
\n\
const char *
smp_strerror(smp_errno_t err)
{
	return (err < 0 || err >= _smp_nerrno ? \"unknown error\" :
	     _smp_errstr[err].msg);
}

const char *
smp_errname(smp_errno_t err)
{
	return (err < 0 || err >= _smp_nerrno ? NULL :
	     _smp_errstr[err].name);
}

smp_errno_t
smp_errcode(const char *name)
{
	smp_errno_t err;

	for (err = 0; err < _smp_nerrno; err++) {
		if (strcmp(name, _smp_errstr[err].name) == 0)
			return (err);
	}

	return (ESMP_UNKNOWN);
}"

exit 0
