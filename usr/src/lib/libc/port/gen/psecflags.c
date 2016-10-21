/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/* Copyright 2015, Richard Lowe. */

#include "lint.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <sys/proc.h>
#include <sys/procset.h>
#include <sys/syscall.h>
#include <sys/secflags.h>

extern int __psecflagsset(procset_t *, psecflagwhich_t, secflagdelta_t *);

int
psecflags(idtype_t idtype, id_t id, psecflagwhich_t which,
    secflagdelta_t *delta)
{
	procset_t procset;

	setprocset(&procset, POP_AND, idtype, id, P_ALL, 0);

	return (__psecflagsset(&procset, which, delta));
}

int
secflags_parse(const secflagset_t *defaults, const char *flags,
    secflagdelta_t *ret)
{
	char *flag;
	char *s, *ss;
	boolean_t current = B_FALSE;

	/* Guarantee a clean base */
	bzero(ret, sizeof (*ret));

	if ((ss = s = strdup(flags)) == NULL)
		return (-1);	/* errno set for us */


	while ((flag = strsep(&s, ",")) != NULL) {
		secflag_t sf = 0;
		boolean_t del = B_FALSE;

		if (strcasecmp(flag, "default") == 0) {
			if (defaults != NULL) {
				secflags_union(&ret->psd_add, defaults);
			} else {
				free(ss);
				errno = EINVAL;
				return (-1);
			}
			continue;
		} else if (strcasecmp(flag, "all") == 0) {
			secflags_fullset(&ret->psd_add);
			continue;
		} else if (strcasecmp(flag, "none") == 0) {
			secflags_fullset(&ret->psd_rem);
			continue;
		} else if (strcasecmp(flag, "current") == 0) {
			current = B_TRUE;
			continue;
		}

		if ((flag[0] == '-') || (flag[0] == '!')) {
			flag++;
			del = B_TRUE;
		} else if (flag[0] == '+') {
			flag++;
		}

		if ((secflag_by_name(flag, &sf)) != B_TRUE) {
			free(ss);
			errno = EINVAL;
			return (-1);
		}

		if (del)
			secflag_set(&(ret->psd_rem), sf);
		else
			secflag_set(&(ret->psd_add), sf);
	}

	/*
	 * If we're not using the current flags, this is strict assignment.
	 * Negatives "win".
	 */
	if (!current) {
		secflags_copy(&ret->psd_assign, &ret->psd_add);
		secflags_difference(&ret->psd_assign, &ret->psd_rem);
		ret->psd_ass_active = B_TRUE;
		secflags_zero(&ret->psd_add);
		secflags_zero(&ret->psd_rem);
	}

	free(ss);
	return (0);
}
