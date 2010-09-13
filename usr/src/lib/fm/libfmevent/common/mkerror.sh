#!/bin/ksh -p
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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

cat <<EOM
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file was generated during make.
 */

#include <fm/libfmevent.h>

static const char *_fmev_errstrs[] = {
EOM

pattern='^    \(FMEVERR_[A-Z0-9_]*\).*\/\* *\(.*\) *\*\/.*'
replace='	"\2" \/\* \1 \*\/,'

sed -n "s/$pattern/$replace/p" $1 || exit 1

cat <<EOM
};

static const int _fmev_nerrs =
    sizeof (_fmev_errstrs) / sizeof (_fmev_errstrs[0]);

const char *
fmev_strerror(fmev_err_t err)
{
	const char *s;

	if (err >= FMEVERR_UNKNOWN && (err - FMEVERR_UNKNOWN < _fmev_nerrs))
		s = _fmev_errstrs[err - FMEVERR_UNKNOWN];
	else
		s = _fmev_errstrs[0];

	return (s);
}
EOM
