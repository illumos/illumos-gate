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
# ident	"%Z%%M%	%I%	%E% SMI"

echo "/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident\t\"@(#)mkelemtype.sh\t1.1\t07/01/19 SMI\"

#include <sys/types.h>
#include <string.h>
#include <scsi/libses.h>

static const struct {
\tses2_element_type_t se_type;\t/* element type */
\tconst char *se_name;\t\t/* element type name */
} _ses_elemtypestr[] = {"

pattern='^	\(SES_ET_\([A-Z0-9_]*\)\).*'
replace='	{ \1, "\2" },'

( sed -n "s/$pattern/$replace/p" ) || exit 1

echo "\
};\n\
\n\
static uint_t _ses_nelemtypes =\n\
    sizeof (_ses_elemtypestr) / sizeof (_ses_elemtypestr[0]);\n\
\n\
const char *
ses_element_type_name(uint64_t type)
{
	uint_t t;

	for (t = 0; t < _ses_nelemtypes; t++) {
		if (_ses_elemtypestr[t].se_type == type)
			return (_ses_elemtypestr[t].se_name);
	}

	return (NULL);
}"

exit 0
