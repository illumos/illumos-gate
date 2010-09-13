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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"


echo "/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <locale.h>
#include <libintl.h>
#include <ucode/ucode_errno.h>
#include <stdlib.h>

static const struct {
\tchar *uce_name;\t\t/* error name */
\tchar *uce_msg;\t\t/* error message */
} _ucode_errstr[] = {
/*
 * TRANSLATION_NOTE
 * The following message strings that begin with EM_ do not
 * need to be translated.
 */
"
pattern='^	\(EM_[A-Z0-9_]*\),*'
replace='	{ "\1", '
open='	\/\* '
openrepl='"'
close=' \*\/$'
closerepl='" },'
( sed -n "s/$pattern/$replace/p" < $1 | sed -n "s/$open/$openrepl/p" | 
    sed -n "s/$close/$closerepl/p" ) || exit 1

echo "\
};\n\
\n\
static int _ucode_nerrno = sizeof (_ucode_errstr) / sizeof (_ucode_errstr[0]);\n\
\n\
const char *
ucode_strerror(ucode_errno_t errno)
{
	return (errno < 0 || errno >= _ucode_nerrno ?
	     gettext(\"unknown error\") :
	     gettext(_ucode_errstr[errno].uce_msg));
}

const char *
ucode_errname(ucode_errno_t errno)
{
	return (errno < 0 || errno >= _ucode_nerrno ? NULL :
	     gettext(_ucode_errstr[errno].uce_name));
}"

exit 0
