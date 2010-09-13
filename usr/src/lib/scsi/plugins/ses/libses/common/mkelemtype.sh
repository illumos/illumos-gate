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
# Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
#

echo "/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <string.h>
#include <scsi/libses.h>
#include <scsi/plugins/ses/vendor/sun.h>

static const struct {
\tint se_type;\t/* element type */
\tconst char *se_name;\t\t/* element type name */
} _ses_elemtypestr[] = {"

pattern='^	\(SES_ET_\([A-Z0-9_]*\)\).*'
replace='	{ \1, "\2" },'
pattern2=', "SUNW_'
replace2=', "'

( for file in $*
  do 
    cat $file | sed -n "s/$pattern/$replace/p" | sed "s/$pattern2/$replace2/"
  done ) || exit 1

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
