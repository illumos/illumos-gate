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
 *	priv_str_xlate.c - Privilege translation routines.
 */

#pragma weak _priv_str_to_set = priv_str_to_set
#pragma weak _priv_set_to_str = priv_set_to_str
#pragma weak _priv_gettext = priv_gettext

#include "lint.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <strings.h>
#include <errno.h>
#include <string.h>
#include <locale.h>
#include <sys/param.h>
#include <priv.h>
#include <alloca.h>
#include <locale.h>
#include "libc.h"
#include "../i18n/_loc_path.h"
#include "priv_private.h"

priv_set_t *
priv_basic(void)
{
	priv_data_t *d;

	LOADPRIVDATA(d);

	return (d->pd_basicset);
}

/*
 *	Name:	priv_str_to_set()
 *
 *	Description:	Given a buffer with privilege strings, the
 *	equivalent privilege set is returned.
 *
 *	Special tokens recognized: all, none, basic and "".
 *
 *	On failure, this function returns NULL.
 *	*endptr == NULL and errno set: resource error.
 *	*endptr != NULL: parse error.
 */
priv_set_t *
priv_str_to_set(const char *priv_names,
		const char *separators,
		const char **endptr)
{

	char *base;
	char *offset;
	char *last;
	priv_set_t *pset = NULL;
	priv_set_t *zone;
	priv_set_t *basic;

	if (endptr != NULL)
		*endptr = NULL;

	if ((base = libc_strdup(priv_names)) == NULL ||
	    (pset = priv_allocset()) == NULL) {
		/* Whether base is NULL or allocated, this works */
		libc_free(base);
		return (NULL);
	}

	priv_emptyset(pset);
	basic = priv_basic();
	zone = privdata->pd_zoneset;

	/* This is how to use strtok_r nicely in a while loop ... */
	last = base;

	while ((offset = strtok_r(NULL, separators, &last)) != NULL) {
		/*
		 * Search for these special case strings.
		 */
		if (basic != NULL && strcasecmp(offset, "basic") == 0) {
			priv_union(basic, pset);
		} else if (strcasecmp(offset, "none") == 0) {
			priv_emptyset(pset);
		} else if (strcasecmp(offset, "all") == 0) {
			priv_fillset(pset);
		} else if (strcasecmp(offset, "zone") == 0) {
			priv_union(zone, pset);
		} else {
			boolean_t neg = (*offset == '-' || *offset == '!');
			int privid;
			int slen;

			privid = priv_getbyname(offset +
			    ((neg || *offset == '+') ? 1 : 0));
			if (privid < 0) {
				slen = offset - base;
				libc_free(base);
				priv_freeset(pset);
				if (endptr != NULL)
					*endptr = priv_names + slen;
				errno = EINVAL;
				return (NULL);
			} else {
				if (neg)
					PRIV_DELSET(pset, privid);
				else
					PRIV_ADDSET(pset, privid);
			}
		}
	}

	libc_free(base);
	return (pset);
}

/*
 *	Name:	priv_set_to_str()
 *
 *	Description:	Given a set of privileges, list of privileges are
 *	returned in privilege numeric order (which can be an ASCII sorted
 *	list as our implementation allows renumbering.
 *
 *	String "none" identifies an empty privilege set, and string "all"
 *	identifies a full set.
 *
 *	A pointer to a buffer is returned which needs to be freed by
 *	the caller.
 *
 *	Several types of output are supported:
 *		PRIV_STR_PORT		- portable output: basic,!basic
 *		PRIV_STR_LIT		- literal output
 *		PRIV_STR_SHORT		- shortest output
 *
 * NOTE: this function is called both from inside the library for the
 * current environment and from outside the library using an externally
 * generated priv_data_t * in order to analyze core files.  It should
 * return strings which can be free()ed by applications and it should
 * not use any data from the current environment except in the special
 * case that it is called from within libc, with a NULL priv_data_t *
 * argument.
 */

char *
__priv_set_to_str(
	priv_data_t *d,
	const priv_set_t *pset,
	char separator,
	int flag)
{
	const char *pstr;
	char *res, *resp;
	int i;
	char neg = separator == '!' ? '-' : '!';
	priv_set_t *zone;
	boolean_t all;
	boolean_t use_libc_data = (d == NULL);

	if (use_libc_data)
		LOADPRIVDATA(d);

	if (flag != PRIV_STR_PORT && __priv_isemptyset(d, pset))
		return (strdup("none"));
	if (flag != PRIV_STR_LIT && __priv_isfullset(d, pset))
		return (strdup("all"));

	/* Safe upper bound: global info contains all NULL separated privs */
	res = resp = alloca(d->pd_pinfo->priv_globalinfosize);

	/*
	 * Compute the shortest form; i.e., the form with the fewest privilege
	 * tokens.
	 * The following forms are possible:
	 *	literal: priv1,priv2,priv3
	 *		tokcount = present
	 *	port: basic,!missing_basic,other
	 *		tokcount = 1 + present - presentbasic + missingbasic
	 *	zone: zone,!missing_zone
	 *		tokcount = 1 + missingzone
	 *	all: all,!missing1,!missing2
	 *		tokcount = 1 + d->pd_nprivs - present;
	 *
	 * Note that zone and all forms are identical in the global zone;
	 * in that case (or any other where the token count is the same),
	 * all is preferred.  Also, the zone form is only used when the
	 * indicated privileges are a subset of the zone set.
	 */

	if (use_libc_data)
		LOCKPRIVDATA();

	if (flag == PRIV_STR_SHORT) {
		int presentbasic, missingbasic, present, missing;
		int presentzone, missingzone;
		int count;

		presentbasic = missingbasic = present = 0;
		presentzone = missingzone = 0;
		zone = d->pd_zoneset;

		for (i = 0; i < d->pd_nprivs; i++) {
			int mem = PRIV_ISMEMBER(pset, i);
			if (d->pd_basicset != NULL &&
			    PRIV_ISMEMBER(d->pd_basicset, i)) {
				if (mem)
					presentbasic++;
				else
					missingbasic++;
			}
			if (zone != NULL && PRIV_ISMEMBER(zone, i)) {
				if (mem)
					presentzone++;
				else
					missingzone++;
			}
			if (mem)
				present++;
		}
		missing = d->pd_nprivs - present;

		if (1 - presentbasic + missingbasic < 0) {
			flag = PRIV_STR_PORT;
			count = present + 1 - presentbasic + missingbasic;
		} else {
			flag = PRIV_STR_LIT;
			count = present;
		}
		if (count >= 1 + missing) {
			flag = PRIV_STR_SHORT;
			count = 1 + missing;
			all = B_TRUE;
		}
		if (present == presentzone && 1 + missingzone < count) {
			flag = PRIV_STR_SHORT;
			all = B_FALSE;
		}
	}

	switch (flag) {
	case PRIV_STR_LIT:
		*res = '\0';
		break;
	case PRIV_STR_PORT:
		(void) strcpy(res, "basic");
		if (d->pd_basicset == NULL)
			flag = PRIV_STR_LIT;
		break;
	case PRIV_STR_SHORT:
		if (all)
			(void) strcpy(res, "all");
		else
			(void) strcpy(res, "zone");
		break;
	default:
		if (use_libc_data)
			UNLOCKPRIVDATA();
		return (NULL);
	}
	res += strlen(res);

	for (i = 0; i < d->pd_nprivs; i++) {
		/* Map the privilege to the next one sorted by name */
		int priv = d->pd_setsort[i];

		if (PRIV_ISMEMBER(pset, priv)) {
			switch (flag) {
			case PRIV_STR_SHORT:
				if (all || PRIV_ISMEMBER(zone, priv))
					continue;
				break;
			case PRIV_STR_PORT:
				if (PRIV_ISMEMBER(d->pd_basicset, priv))
					continue;
				break;
			case PRIV_STR_LIT:
				break;
			}
			if (res != resp)
				*res++ = separator;
		} else {
			switch (flag) {
			case PRIV_STR_LIT:
				continue;
			case PRIV_STR_PORT:
				if (!PRIV_ISMEMBER(d->pd_basicset, priv))
					continue;
				break;
			case PRIV_STR_SHORT:
				if (!all && !PRIV_ISMEMBER(zone, priv))
					continue;
				break;
			}
			if (res != resp)
				*res++ = separator;
			*res++ = neg;
		}
		pstr = __priv_getbynum(d, priv);
		(void) strcpy(res, pstr);
		res += strlen(pstr);
	}
	if (use_libc_data)
		UNLOCKPRIVDATA();
	/* Special case the set with some high bits set */
	return (strdup(*resp == '\0' ? "none" : resp));
}

/*
 * priv_set_to_str() is defined to return a string that
 * the caller must deallocate with free(3C).  Grr...
 */
char *
priv_set_to_str(const priv_set_t *pset, char separator, int flag)
{
	return (__priv_set_to_str(NULL, pset, separator, flag));
}

static char *
do_priv_gettext(const char *priv, const char *file)
{
	char buf[8*1024];
	boolean_t inentry = B_FALSE;
	FILE	*namefp;

	namefp = fopen(file, "rF");
	if (namefp == NULL)
		return (NULL);

	/*
	 * parse the file; it must have the following format
	 * Lines starting with comments "#"
	 * Lines starting with non white space with one single token:
	 * the privileges; white space indented lines which are the
	 * description; no empty lines are allowed in the description.
	 */
	while (fgets(buf, sizeof (buf), namefp) != NULL) {
		char *lp;		/* pointer to the current line */

		if (buf[0] == '#')
			continue;

		if (buf[0] == '\n') {
			inentry = B_FALSE;
			continue;
		}

		if (inentry)
			continue;

		/* error; not skipping; yet line starts with white space */
		if (isspace((unsigned char)buf[0]))
			goto out;

		/* Trim trailing newline */
		buf[strlen(buf) - 1] = '\0';

		if (strcasecmp(buf, priv) != 0) {
			inentry = B_TRUE;
			continue;
		}

		lp = buf;
		while (fgets(lp, sizeof (buf) - (lp - buf), namefp) != NULL) {
			char *tstart;	/* start of text */
			int len;

			/* Empty line or start of next entry terminates */
			if (*lp == '\n' || !isspace((unsigned char)*lp)) {
				*lp = '\0';
				(void) fclose(namefp);
				return (strdup(buf));
			}

			/* Remove leading white space */
			tstart = lp;
			while (*tstart != '\0' &&
			    isspace((unsigned char)*tstart)) {
				tstart++;
			}

			len = strlen(tstart);
			(void) memmove(lp, tstart, len + 1);
			lp += len;

			/* Entry to big; prevent fgets() loop */
			if (lp == &buf[sizeof (buf) - 1])
				goto out;
		}
		if (lp != buf) {
			*lp = '\0';
			(void) fclose(namefp);
			return (strdup(buf));
		}
	}
out:
	(void) fclose(namefp);
	return (NULL);
}

/*
 * priv_gettext() is defined to return a string that
 * the caller must deallocate with free(3C).  Grr...
 */
char *
priv_gettext(const char *priv)
{
	char file[MAXPATHLEN];
	locale_t curloc;
	const char *loc;
	char	*ret;

	/* Not a valid privilege */
	if (priv_getbyname(priv) < 0)
		return (NULL);

	curloc = uselocale(NULL);
	loc = current_locale(curloc, LC_MESSAGES);

	if (snprintf(file, sizeof (file),
	    _DFLT_LOC_PATH "%s/LC_MESSAGES/priv_names", loc) < sizeof (file)) {
		ret = do_priv_gettext(priv, (const char *)file);
		if (ret != NULL)
			return (ret);
	}

	/* If the path is too long or can't be opened, punt to default */
	ret = do_priv_gettext(priv, "/etc/security/priv_names");
	return (ret);
}
