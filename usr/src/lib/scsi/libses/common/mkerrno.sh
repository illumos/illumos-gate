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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"

echo "/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident\t\"%Z%%M%\t%I%\t%E% SMI\"

#include <strings.h>
#include <scsi/libses.h>

static const struct {
\tchar *se_name;\t\t/* error name */
\tchar *se_msg;\t\t/* error message */
} _ses_errstr[] = {"

pattern='^	\(ESES_[A-Z0-9_]*\),*'
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
static int _ses_nerrno = sizeof (_ses_errstr) / sizeof (_ses_errstr[0]);\n\
\n\
const char *
ses_strerror(ses_errno_t err)
{
	return (err < 0 || err >= _ses_nerrno ? \"unknown error\" :
	     _ses_errstr[err].se_msg);
}

const char *
ses_errname(ses_errno_t err)
{
	return (err < 0 || err >= _ses_nerrno ? NULL :
	     _ses_errstr[err].se_name);
}

ses_errno_t
ses_errcode(const char *name)
{
	ses_errno_t err;

	for (err = 0; err < _ses_nerrno; err++) {
		if (strcmp(name, _ses_errstr[err].se_name) == 0)
			return (err);
	}

	return (ESES_UNKNOWN);
}"

exit 0
