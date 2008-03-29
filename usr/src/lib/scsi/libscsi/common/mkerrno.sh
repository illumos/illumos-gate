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
#ident	"%Z%%M%	%I%	%E% SMI"

echo "\
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident\t\"%Z%%M%\t%I%\t%E%\tSMI\"

#include <strings.h>
#include <scsi/libscsi.h>

static const struct {
\tchar *name;\t\t/* error name */
\tchar *msg;\t\t/* error message */
} _libscsi_errstr[] = {"

pattern='^	\(ESCSI_[A-Z0-9_]*\),*'
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
static int _libscsi_nerrno = sizeof (_libscsi_errstr) /\n\
    sizeof (_libscsi_errstr[0]);\n\
\n\
const char *
libscsi_strerror(libscsi_errno_t err)
{
	return (err < 0 || err >= _libscsi_nerrno ? \"unknown error\" :
	     _libscsi_errstr[err].msg);
}

const char *
libscsi_errname(libscsi_errno_t err)
{
	return (err < 0 || err >= _libscsi_nerrno ? NULL :
	     _libscsi_errstr[err].name);
}

libscsi_errno_t
libscsi_errcode(const char *name)
{
	libscsi_errno_t err;

	for (err = 0; err < _libscsi_nerrno; err++) {
		if (strcmp(name, _libscsi_errstr[err].name) == 0)
			return (err);
	}

	return (ESCSI_UNKNOWN);
}"

exit 0
