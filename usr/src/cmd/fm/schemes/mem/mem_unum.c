/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <mem.h>
#include <fm/fmd_fmri.h>

#include <string.h>
#include <strings.h>
#include <ctype.h>

/*
 * Given a DIMM or bank unum, mem_unum_burst will break it apart into individual
 * DIMM names.  If it's a DIMM, one name will be returned.  If it's a bank, the
 * unums for the individual DIMMs will be returned.
 *
 * Plain J-number DIMM and bank unums are simple.  J DIMMs have one J number.  J
 * banks have multiple whitespace-separated J numbers.
 *
 * The others are more complex, and consist of a common portion c, a colon, and
 * a DIMM-specific portion d.  DIMMs are of the form "c: d", while banks are of
 * the form "c: d d ...".  The patterns are designed to handle the complex case,
 * but also handle the simple ones as an afterthought.  bd_pat is used to
 * match specific styles of unum.  In bd_pat, the first %n indicates the end of
 * the common portion ("c" above).  The second %n marks the beginning of the
 * repetitive portion ("d" above).  The third %n is used to determine whether or
 * not the entire pattern matched.  bd_reppat is used to match instances of the
 * repetitive part.
 *
 * sscanf is your disturbingly powerful friend.
 */

typedef struct bank_dimm {
	const char *bd_pat;
	const char *bd_reppat;
} bank_dimm_t;

static const bank_dimm_t bank_dimm[] = {
	{ "%n%nJ%*4d%n",			" J%*4d%n" },
	{ "MB/P%*d/%nB%*d:%n%n",		" B%*d/D%*d%n" },
	{ "MB/P%*d/%nB%*d/D%*d:%n%n",		" B%*d/D%*d%n" },
	{ "C%*d/P%*d/%nB%*d:%n%n",		" B%*d/D%*d%n" },
	{ "C%*d/P%*d/%nB%*d/D%*d:%n%n",		" B%*d/D%*d%n" },
	{ "Slot %*c: %n%nJ%*4d%n",		" J%*4d%n" },
	{ "%n%nDIMM%*d%n",			" DIMM%*d%n" },
	{ "MB/%nDIMM%*d MB/DIMM%*d: %n%n",	" DIMM%*d%n" },
	{ "MB/%nDIMM%*d:%n%n",			" DIMM%*d%n" },
	{ NULL }
};

/*
 * Returns 0 (with dimmsp and ndimmsp set) if the unum could be bursted, -1
 * otherwise.
 */
int
mem_unum_burst(const char *pat, char ***dimmsp, size_t *ndimmsp)
{
	const bank_dimm_t *bd;
	char **dimms = NULL, **newdimms;
	size_t ndimms = 0;
	const char *c;

	for (bd = bank_dimm; bd->bd_pat != NULL; bd++) {
		int replace, start, matched;
		char dimmname[64];

		replace = start = matched = -1;
		(void) sscanf(pat, bd->bd_pat, &replace, &start, &matched);
		if (matched == -1)
			continue;

		(void) strlcpy(dimmname, pat, sizeof (dimmname));

		c = pat + start;
		while (*c != '\0') {
			int dimmlen = -1;

			(void) sscanf(c, bd->bd_reppat, &dimmlen);
			if (dimmlen == -1)
				break;

			while (*c == ' ') {
				c++;
				dimmlen--;
			}

			if (dimmlen > sizeof (dimmname) - replace)
				break;

			(void) strlcpy(dimmname + replace, c, dimmlen + 1);

			newdimms = fmd_fmri_alloc(sizeof (char *) *
			    (ndimms + 1));
			if (ndimms != 0) {
				bcopy(dimms, newdimms, sizeof (char *) *
				    ndimms);
				fmd_fmri_free(dimms, sizeof (char *) * ndimms);
			}
			newdimms[ndimms++] = fmd_fmri_strdup(dimmname);
			dimms = newdimms;

			c += dimmlen;

			if (*c != ' ' && *c != '\0')
				break;
		}

		if (*c != '\0')
			break;

		*dimmsp = dimms;
		*ndimmsp = ndimms;

		return (0);
	}

	mem_strarray_free(dimms, ndimms);
	return (fmd_fmri_set_errno(EINVAL));
}

/*
 * The unum containership operation is designed to tell the caller whether a
 * given FMRI contains another.  In the case of this plugin, we tell the caller
 * whether a given memory FMRI (usually a bank) contains another (usually a
 * DIMM).  We do this in one of two ways, depending on the platform.  For most
 * platforms, we can use the bursting routine to generate the list of member
 * unums from the container unum.  Membership can then be determined by
 * searching the bursted list for the containee's unum.
 *
 * Some platforms, however, cannot be bursted, as their bank unums do not
 * contain all of the information needed to generate the complete list of
 * member DIMM unums.  For these unums, we must make do with a substring
 * comparison.
 */

static int
unum_contains_bypat(const char *erunum, const char *eeunum)
{
	char **ernms, **eenms;
	uint_t nernms, neenms;
	int i, j, rv = 1;

	if (mem_unum_burst(erunum, &ernms, &nernms) < 0)
		return (fmd_fmri_set_errno(EINVAL));
	if (mem_unum_burst(eeunum, &eenms, &neenms) < 0) {
		mem_strarray_free(ernms, nernms);
		return (fmd_fmri_set_errno(EINVAL));
	}

	for (i = 0; i < neenms; i++) {
		for (j = 0; j < nernms; j++) {
			if (strcmp(eenms[i], ernms[j]) == 0)
				break;
		}

		if (j == nernms) {
			/*
			 * This DIMM was not found in the container.
			 */
			rv = 0;
			break;
		}
	}

	mem_strarray_free(ernms, nernms);
	mem_strarray_free(eenms, neenms);

	return (rv);
}

static int
unum_strip_one_jnum(const char *unum, uint_t *endp)
{
	char *c;
	int i;

	if ((c = strrchr(unum, 'J')) == NULL)
		return (0);

	while (c > unum && isspace(c[-1]))
		c--;

	(void) sscanf(c, " J%*[0-9] %n", &i);
	if (i == 0 || (uintptr_t)(c - unum) + i != strlen(unum))
		return (0);

	*endp = (uint_t)(c - unum);
	return (1);
}


static int
unum_contains_bysubstr(const char *erunum, const char *eeunum)
{
	uint_t erlen, eelen;

	/*
	 * This comparison method is only known to work on specific types of
	 * unums.  Check for those types here.
	 */
	if ((strncmp(erunum, "/N", 2) != 0 && strncmp(erunum, "/IO", 3) != 0 &&
	    strncmp(erunum, "/SB", 3) != 0) ||
	    (strncmp(eeunum, "/N", 2) != 0 && strncmp(eeunum, "/IO", 3) != 0 &&
	    strncmp(eeunum, "/SB", 3) != 0))
		return (fmd_fmri_set_errno(EINVAL));

	erlen = unum_strip_one_jnum(erunum, &erlen) ? erlen : strlen(erunum);
	eelen = unum_strip_one_jnum(eeunum, &eelen) ? eelen : strlen(eeunum);

	return (strncmp(erunum, eeunum, MIN(erlen, eelen)) == 0);
}

typedef int unum_cmptor_f(const char *, const char *);

static unum_cmptor_f *const unum_cmptors[] = {
	unum_contains_bypat,
	unum_contains_bysubstr
};

int
mem_unum_contains(const char *erunum, const char *eeunum)
{
	static int cmptor = 0;
	int rc;

	while (isspace(*erunum))
		erunum++;
	while (isspace(*eeunum))
		eeunum++;

	if ((rc = unum_cmptors[cmptor](erunum, eeunum)) >= 0)
		return (rc);

	if ((rc = unum_cmptors[cmptor == 0](erunum, eeunum)) >= 0) {
		/*
		 * We succeeded with the non-default comparator.  Change the
		 * default so we use the correct one next time.
		 */
		cmptor = (cmptor == 0);
	}

	return (rc);
}
