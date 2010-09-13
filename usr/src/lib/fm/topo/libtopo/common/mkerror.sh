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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"@(#)mkerror.sh	1.1	06/02/11 SMI"

#pragma ident	"%Z%%M%	%I%	%E% SMI"


input="`cat`"
[ -z "$input" ] && exit 1

if [ $1 = "liberrors" ] ; then
echo "\
/*\n\
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.\n\
 * Use is subject to license terms.\n\
 */\n\
\n\
#pragma ident\t\"@(#)mkerror.sh\t1.2\t05/06/08 SMI\"\n\
\n\
#include <strings.h>
#include <topo_error.h>
#include <topo_mod.h>

\n\
static const char *const _topo_errstrs[] = {"

pattern='^[ ]*ETOPO_[A-Z0-9_]*.*\* \(.*\) \*.*'
replace='	"\1",'

echo "$input" | sed -n "s/$pattern/$replace/p" || exit 1

echo "\
};\n\
\n\
static const int _topo_nerrstrs =\n\
    sizeof (_topo_errstrs) / sizeof (_topo_errstrs[0]);\n\
\n\

int
topo_hdl_errno(topo_hdl_t *thp)
{
	return (thp->th_errno);
}

int
topo_hdl_seterrno(topo_hdl_t *thp, int err)
{
	thp->th_errno = err;
	return (-1);
}

const char *
topo_hdl_errmsg(topo_hdl_t *thp)
{
	return (topo_strerror(thp->th_errno));
}"

elif [ $1 = "properrors" ] ; then

echo "\
\n\
static const char *const _topo_properrstrs[] = {"

pattern='^[ ]*ETOPO_PROP_[A-Z0-9_]*.*\* \(.*\) \*.*'
replace='	"\1",'

echo "$input" | sed -n "s/$pattern/$replace/p" || exit 1

echo "\
};\n\
\n\
static const int _topo_nproperrstrs =\n\
    sizeof (_topo_properrstrs) / sizeof (_topo_properrstrs[0]);"

elif [ $1 = "methoderrors" ] ; then

echo "\
\n\
static const char *const _topo_methoderrstrs[] = {"

pattern='^[ ]*ETOPO_METHOD_[A-Z0-9_]*.*\* \(.*\) \*.*'
replace='	"\1",'

echo "$input" | sed -n "s/$pattern/$replace/p" || exit 1

echo "\
};\n\
\n\
static const int _topo_nmethoderrstrs =\n\
    sizeof (_topo_methoderrstrs) / sizeof (_topo_methoderrstrs[0]);"

elif [ $1 = "fmrierrors" ] ; then

echo "\
\n\
static const char *const _topo_fmrierrstrs[] = {"

pattern='^[ ]*ETOPO_FMRI_[A-Z0-9_]*.*\* \(.*\) \*.*'
replace='	"\1",'

echo "$input" | sed -n "s/$pattern/$replace/p" || exit 1

echo "\
};\n\
\n\
static const int _topo_nfmrierrstrs =\n\
    sizeof (_topo_fmrierrstrs) / sizeof (_topo_fmrierrstrs[0]);"

elif [ $1 = "hdlerrors" ] ; then

echo "\
\n\
static const char *const _topo_hdlerrstrs[] = {"

pattern='^[ ]*ETOPO_HDL_[A-Z0-9_]*.*\* \(.*\) \*.*'
replace='	"\1",'

echo "$input" | sed -n "s/$pattern/$replace/p" || exit 1

echo "\
};\n\
\n\
static const int _topo_nhdlerrstrs =\n\
    sizeof (_topo_hdlerrstrs) / sizeof (_topo_hdlerrstrs[0]);"

else

echo "\
\n\
static const char *const _topo_moderrstrs[] = {"

pattern='^[ ]*EMOD_[A-Z0-9_]*.*\* \(.*\) \*.*'
replace='	"\1",'

echo "$input" | sed -n "s/$pattern/$replace/p" || exit 1

echo "\
};\n\
static const int _topo_nmoderrstrs =\n\
    sizeof (_topo_moderrstrs) / sizeof (_topo_moderrstrs[0]);\n\
\n\

int
topo_mod_errno(topo_mod_t *mp)
{
	return (mp->tm_errno);
}

int
topo_mod_seterrno(topo_mod_t *mp, int err)
{
	mp->tm_errno = err;
	return (-1);
}

const char *
topo_mod_errmsg(topo_mod_t *mp)
{
	return (topo_strerror(mp->tm_errno));
}

const char *
topo_strerror(int err)
{
	const char *s;

	if (err >= ETOPO_UNKNOWN && (err - ETOPO_UNKNOWN) < _topo_nerrstrs)
		s = _topo_errstrs[err - ETOPO_UNKNOWN];
	else if (err >= EMOD_UNKNOWN && (err - EMOD_UNKNOWN) <
	    _topo_nmoderrstrs)
		s = _topo_moderrstrs[err - EMOD_UNKNOWN];
	else if (err >= ETOPO_PROP_UNKNOWN && (err - ETOPO_PROP_UNKNOWN) <
	    _topo_nproperrstrs)
		s = _topo_properrstrs[err - ETOPO_PROP_UNKNOWN];
	else if (err >= ETOPO_METHOD_UNKNOWN && (err - ETOPO_METHOD_UNKNOWN) <
	    _topo_nmethoderrstrs)
		s = _topo_methoderrstrs[err - ETOPO_METHOD_UNKNOWN];
	else if (err >= ETOPO_HDL_UNKNOWN && (err - ETOPO_HDL_UNKNOWN) <
	    _topo_nhdlerrstrs)
		s = _topo_hdlerrstrs[err - ETOPO_HDL_UNKNOWN];
	else if (err >= ETOPO_FMRI_UNKNOWN && (err - ETOPO_FMRI_UNKNOWN) <
	    _topo_nfmrierrstrs)
		s = _topo_fmrierrstrs[err - ETOPO_FMRI_UNKNOWN];
	else
		s = _topo_errstrs[0];

	return (s);
}"

fi

exit 0
