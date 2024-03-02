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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2019 Peter Tribble.
 */

#include <mem.h>
#include <fm/fmd_fmri.h>
#include <fm/libtopo.h>

#include <string.h>
#include <strings.h>
#include <ctype.h>

#define	ISHCUNUM(unum) (strncmp(unum, "hc:/", 4) == 0)

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
 *
 * The "bd_subst" element of the bank_dimm structure was added for Ontario
 * in order to accommodate its bank string names.  Previously, to convert
 * from a bank representation <common piece> <dimm1> <dimm2> ...
 * we concatenated the common piece with each dimm-specific piece in turn,
 * possibly deleting some characters in between.  Ontario is the first
 * platform which requires that characters be substituted (like a vi s/1/2/)
 * in place of characters deleted.  "bd_subst" represents the character(s)
 * to be substituted between the common piece and each dimm-specific piece
 * as part of the bursting.  For prior platforms, this value is skipped.
 *
 * Example:
 * input: "MB/CMP0/CH3: R1/D0/J1901 R1/D1/J2001"
 * outputs: "MB/CMP0/CH3/R1/D0/J1901", "MB/CMP0/CH3/R1/D1/J2001"
 */

typedef struct bank_dimm {
	const char *bd_pat;
	const char *bd_reppat;
	const char *bd_subst;
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
	{ "MB/CMP%*d/CH%*d%n:%n%n",		" R%*d/D%*d/J%*4d%n",	"/" },
	{ "MB/CMP%*d/CH%*d%n%n%n",		"/R%*d/D%*d/J%*4d%n" },
	{ "MB/C%*d/P%*d/%nB%*d:%n%n",		" B%*d/D%*d%n" },
	{ "MB/C%*d/P%*d/%nB%*d/D%*d:%n%n",	" B%*d/D%*d%n" },
	{ "/MBU_A/MEMB%*d/%n%nMEM%*d%*1c%n",	" MEM%*d%*1c%n" },
	{ "/MBU_B/MEMB%*d/%n%nMEM%*d%*1c%n",	" MEM%*d%*1c%n" },
	{ "/MBU_A/%n%nMEM%*d%*1c%n",		" MEM%*d%*1c%n" },
	{ "/CMU%*2d/%n%nMEM%*2d%*1c%n",		" MEM%*2d%*1c%n" },
	{ "MB/CMP%*d/BR%*d%n:%n%n",		" CH%*d/D%*d/J%*4d%n", "/" },
	{ "%n%nMB/CMP%*d/BR%*d/CH%*d/D%*d/J%*4d%n",
	    "MB/CMP%*d/BR%*d/CH%*d/D%*d/J%*4d%n" },
	{ "%n%nMB/CMP%*d/BR%*d/CH%*d/D%*d%n", "MB/CMP%*d/BR%*d/CH%*d/D%*d%n" },
	{ "MB/CPU%*d/CMP%*d/BR%*d%n:%n%n",	" CH%*d/D%*d/J%*4d%n", "/"},
	{ "MB/MEM%*d/CMP%*d/BR%*d%n:%n%n",	" CH%*d/D%*d/J%*4d%n", "/"},
	{ "%n%nMB/MEM%*d/CMP%*d/BR%*d/CH%*d/D%*d/J%*4d%n",
	    "MB/MEM%*d/CMP%*d/BR%*d/CH%*d/D%*d/J%*4d%n" },
	{ "%n%nMB/CPU%*d/CMP%*d/BR%*d/CH%*d/D%*d/J%*4d%n",
	    "MB/CPU%*d/CMP%*d/BR%*d/CH%*d/D%*d/J%*4d%n" },
	{ "%n%nMB/MEM%*d/CMP%*d/BR%*d/CH%*d/D%*d%n",
	    "MB/MEM%*d/CMP%*d/BR%*d/CH%*d/D%*d%n"  },
	{ "%n%nMB/CPU%*d/CMP%*d/BR%*d/CH%*d/D%*d%n",
	    "MB/CPU%*d/CMP%*d/BR%*d/CH%*d/D%*d%n"  },
	{ NULL }
};

/*
 * Burst Serengeti-style unums.
 * A DIMM unum string is expected to be in this form:
 * "[/N0/]SB12/P0/B0/D2 [J13500]"
 * A bank unum string is expected to be in this form:
 * "[/N0/]SB12/P0/B0 [J13500, ...]"
 */
static int
mem_unum_burst_sgsc(const char *pat, char ***dimmsp, size_t *ndimmsp)
{
	char buf[64];
	char **dimms;
	char *base;
	const char *c;
	char *copy;
	size_t copysz;
	int i;

	/*
	 * No expansion is required for a DIMM unum
	 */
	if (strchr(pat, 'D') != NULL) {
		dimms = fmd_fmri_alloc(sizeof (char *));
		dimms[0] = fmd_fmri_strdup(pat);
		*dimmsp = dimms;
		*ndimmsp = 1;
		return (0);
	}

	/*
	 * strtok is destructive so we need to work with
	 * a copy and keep track of the size allocated.
	 */
	copysz = strlen(pat) + 1;
	copy = fmd_fmri_alloc(copysz);
	(void) strcpy(copy, pat);

	base = strtok(copy, " ");

	/* There are four DIMMs in a bank */
	dimms = fmd_fmri_alloc(sizeof (char *) * 4);

	for (i = 0; i < 4; i++) {
		(void) snprintf(buf, sizeof (buf), "%s/D%d", base, i);

		if ((c = strtok(NULL, " ")) != NULL) {
			size_t len = strlen(buf);

			(void) snprintf(buf + len, sizeof (buf) - len,
			    " %s", c);
		}

		dimms[i] = fmd_fmri_strdup(buf);
	}

	fmd_fmri_free(copy, copysz);

	*dimmsp = dimms;
	*ndimmsp = 4;
	return (0);
}


/*
 * Returns 0 (with dimmsp and ndimmsp set) if the unum could be bursted, -1
 * otherwise.
 */
static int
mem_unum_burst_pattern(const char *pat, char ***dimmsp, size_t *ndimmsp)
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
		if (bd->bd_subst != NULL) {
			(void) strlcpy(dimmname+replace, bd->bd_subst,
			    sizeof (dimmname) - strlen(bd->bd_subst));
			replace += strlen(bd->bd_subst);
		}

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

	/*
	 * Set errno to ENOTSUP and return -1. This allows support for DIMMs
	 * with unknown unum strings and/or serial numbers. The only consumer
	 * of mem_unum_burst_pattern() that cares/checks for the returned
	 * errno is fmd_fmri_expand().
	 */
	return (fmd_fmri_set_errno(ENOTSUP));
}

int
mem_unum_burst(const char *pat, char ***dimmsp, size_t *ndimmsp)
{
	const char *platform = fmd_fmri_get_platform();

	/*
	 * Call mem_unum_burst_sgsc() for Serengeti and
	 * Lightweight 8 platforms.  Call mem_unum_burst_pattern()
	 * for all other platforms.
	 */
	if (strcmp(platform, "SUNW,Sun-Fire") == 0 ||
	    strcmp(platform, "SUNW,Netra-T12") == 0)
		return (mem_unum_burst_sgsc(pat, dimmsp, ndimmsp));
	else
		return (mem_unum_burst_pattern(pat, dimmsp, ndimmsp));
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
	size_t nernms, neenms;
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
	int nojnumstrip = 0;

	/*
	 * This comparison method is only known to work on specific types of
	 * unums.  Check for those types here.
	 */
	if ((strncmp(erunum, "/N", 2) != 0 && strncmp(erunum, "/IO", 3) != 0 &&
	    strncmp(erunum, "/SB", 3) != 0) ||
	    (strncmp(eeunum, "/N", 2) != 0 && strncmp(eeunum, "/IO", 3) != 0 &&
	    strncmp(eeunum, "/SB", 3) != 0)) {
		if (ISHCUNUM(erunum) && ISHCUNUM(eeunum)) {
			nojnumstrip = 1;
			erlen = strlen(erunum);
			eelen = strlen(eeunum);
		} else {
			return (fmd_fmri_set_errno(EINVAL));
		}
	}

	if (!nojnumstrip) {
		erlen = unum_strip_one_jnum(erunum, &erlen) ?
		    erlen : strlen(erunum);
		eelen = unum_strip_one_jnum(eeunum, &eelen) ?
		    eelen : strlen(eeunum);
	}

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

/*
 * If an asru has a unum string that is an hc path string then return
 * a new nvl (to be freed by the caller) that is a duplicate of the
 * original but with an additional member of a reconstituted hc fmri.
 */
int
mem_unum_rewrite(nvlist_t *nvl, nvlist_t **rnvl)
{
	int err;
	char *unumstr;
	nvlist_t *unum;
	struct topo_hdl *thp;

	if (nvlist_lookup_string(nvl, FM_FMRI_MEM_UNUM, &unumstr) != 0 ||
	    !ISHCUNUM(unumstr))
		return (0);

	if ((thp = fmd_fmri_topo_hold(TOPO_VERSION)) == NULL)
		return (EINVAL);

	if (topo_fmri_str2nvl(thp, unumstr, &unum, &err) != 0) {
		fmd_fmri_topo_rele(thp);
		return (EINVAL);
	}

	fmd_fmri_topo_rele(thp);

	if ((err = nvlist_dup(nvl, rnvl, 0)) != 0) {
		nvlist_free(unum);
		return (err);
	}

	err = nvlist_add_nvlist(*rnvl, FM_FMRI_MEM_UNUM "-fmri", unum);
	nvlist_free(unum);

	if (err != 0)
		nvlist_free(*rnvl);

	return (err);
}
