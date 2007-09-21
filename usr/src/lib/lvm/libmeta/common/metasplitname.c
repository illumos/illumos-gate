/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * split and splice name
 */

#include <meta.h>

int
splitname(char *name, md_splitname *spn)
{
	size_t prefixlen;
	size_t suffixlen;
	char	*lastslash;
	int	retval = METASPLIT_SUCCESS;

	lastslash = strrchr(name, '/');
	if (lastslash != NULL) {
		prefixlen = lastslash - name;
		suffixlen = (strlen(name) - prefixlen) - 1; /* slash dropped */
	} else {
		prefixlen = 0;
		suffixlen = strlen(name);
	}
	if (prefixlen > MD_MAXPREFIX)
		return (METASPLIT_LONGPREFIX);

	if (suffixlen > MD_MAXSUFFIX) {
		lastslash = META_LONGDISKNAME_STR;
		prefixlen = 0;
		suffixlen = strlen(lastslash);
		(void) memcpy(SPN_SUFFIX(spn).suf_data, lastslash, suffixlen);
		SPN_SUFFIX(spn).suf_len = suffixlen;
		retval = METASPLIT_LONGDISKNAME;
	} else {
		(void) memcpy(SPN_SUFFIX(spn).suf_data, lastslash + 1,
		    suffixlen);
		SPN_SUFFIX(spn).suf_len = suffixlen;
	}

	(void) memcpy(SPN_PREFIX(spn).pre_data, name, prefixlen);
	SPN_PREFIX(spn).pre_len = prefixlen;

	return (retval);
}

char *
splicename(md_splitname *spn)
{
	char *name;
	char *suffix;
	size_t prefixlen;
	size_t suffixlen;

	prefixlen = SPN_PREFIX(spn).pre_len;
	suffixlen = SPN_SUFFIX(spn).suf_len;
	name = Malloc(prefixlen + suffixlen + 2);
	(void) memcpy(name, SPN_PREFIX(spn).pre_data, prefixlen);
	name[prefixlen] = '/';
	suffix = name + (prefixlen + 1);
	(void) memcpy(suffix, SPN_SUFFIX(spn).suf_data, suffixlen);
	name[prefixlen + suffixlen + 1] = 0;
	return (name);
}
