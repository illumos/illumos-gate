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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <priv.h>
#include <string.h>
#include <libgen.h>
#include <errno.h>
#include <libintl.h>
#include <sys/devpolicy.h>
#include <sys/modctl.h>
#include "message.h"
#include "plcysubr.h"

/* Cannot include devfsadm_impl.h because of static definitions */
#define	err_print	devfsadm_errprint
extern void err_print(char *, ...);

#define	PLCY_CHUNK	128

/*
 * devpolicy sort order sorts on three items to help the kernel;
 * the kernel will verify but not sort.
 *
 *	1) major number - but default major will be first in sorted output
 *	2) wildcard or not - non wildcard entries are sorted first.
 *		2a) Expanded minor numbers first (empty name sorts first).
 *		2b) Named minors.
 *	3) length of wildcard entry - longest pattern first
 *
 * The last rule allows patterns such as *ctl and * to be used both
 * unambiguously instead of current bogosities as found in /etc/minor_perm:
 *	rtvc:ctl 0644 root sys
 *	rtvc:rtvcctl* 0644 root sys
 *	rtvc:rtvc[!ctl]* 0666 root sys
 *
 * The last pattern only works by accident.
 *
 * This would simply become (in sorted order):
 *	rtvc:ctl
 *	rtvc:rtvcctl*
 *	rtvc:*
 */

static int
qcmp(const void *a, const void *b)
{
	const devplcysys_t *pa = a;
	const devplcysys_t *pb = b;
	int wilda, wildb;

	/* sort on major number, default major first in sort output */
	if (pa->dps_maj == DEVPOLICY_DFLT_MAJ)
		return (-1);
	if (pb->dps_maj == DEVPOLICY_DFLT_MAJ)
		return (1);

	if (pa->dps_maj > pb->dps_maj)
		return (1);
	else if (pa->dps_maj < pb->dps_maj)
		return (-1);

	wilda = strchr(pa->dps_minornm, '*') != NULL;
	wildb = strchr(pb->dps_minornm, '*') != NULL;

	/* sort the entry with the wildcard last */
	if (wilda != wildb)
		return (wilda - wildb);

	/* entries without wildcards compare with strcmp() */
	if (wilda == 0)
		return (strcmp(pa->dps_minornm, pb->dps_minornm));

	/* shortest wildcard last */
	return ((int)(strlen(pb->dps_minornm) - strlen(pa->dps_minornm)));
}

static int
loadprivs(const char *infile)
{
	char *line, *col;
	FILE *in;
	struct fileentry *fep;
	int res = 0;

	in = fopen(infile, "r");

	if (in == NULL)
		return (0);

	while ((fep = fgetline(in)) != NULL && fep->entry != NULL) {
		line = fep->entry;

		if (*line == '\0')
			continue;

		line[strlen(line)-1] = '\0';

		col = strchr(line, ':');

		if (col != NULL) {
			major_t maj;
			*col = '\0';

			if (modctl(MODGETMAJBIND, line, col - line + 1, &maj)
			    != 0)
				continue;

			line = col + 1;
		}

		if (modctl(MODALLOCPRIV, line) != 0) {
			(void) err_print("modctl(MODALLOCPRIV, %s): %s\n",
				line, strerror(errno));
			res = -1;
		}
	}
	return (res);
}

static int
loadpolicy(const char *infile)
{
	char *line;
	int nalloc = 0, cnt = 0;
	char *mem = NULL;
	devplcysys_t *dp, *dflt = NULL;
	FILE *in;
	struct fileentry *fep;
	int res;

	char *maj;
	char *tok;
	char *min;

	in = fopen(infile, "r");

	if (in == NULL) {
		err_print(OPEN_FAILED, infile, strerror(errno));
		return (-1);
	}

	while ((fep = fgetline(in)) != NULL && fep->entry != NULL) {
		line = fep->entry;
		if (cnt >= nalloc) {
			nalloc += PLCY_CHUNK;
			mem = realloc(mem, nalloc * devplcysys_sz);
			if (mem == NULL) {
				err_print(MALLOC_FAILED,
					nalloc * devplcysys_sz);
				return (-1);
			}

			/* Readjust pointer to dflt after realloc */
			if (dflt != NULL)
				/* LINTED: alignment */
				dflt = (devplcysys_t *)mem;
		}
		maj = strtok(line, "\n\t ");

		if (maj == NULL)
			continue;

		/* LINTED: alignment */
		dp = (devplcysys_t *)(mem + devplcysys_sz * cnt);

		if (strcmp(maj, "*") == 0) {
			if (dflt != NULL) {
				err_print(DPLCY_ONE_DFLT, infile);
				return (-1);
			}
			(void) memset(dp, 0, devplcysys_sz);
			dp->dps_maj = DEVPOLICY_DFLT_MAJ;
			dflt = dp;
		} else {
			if (dflt == NULL) {
				err_print(DPLCY_FIRST, infile);
				return (-1);
			}

			(void) memcpy(dp, dflt, devplcysys_sz);

			min = strchr(maj, ':');

			if (min != NULL) {
				*min++ = '\0';
				if (strchr(min, ':') != NULL) {
					(void) fprintf(stderr,
					    "Too many ``:'' in entry\n");
					return (-1);
				}
			} else
				min = "*";

			/* Silently ignore unknown devices. */
			if (modctl(MODGETMAJBIND, maj, strlen(maj) + 1,
			    &dp->dps_maj) != 0)
				continue;

			if (*min == '(') {
				/* Numeric minor range */
				char type;

				if (parse_minor_range(min, &dp->dps_lomin,
				    &dp->dps_himin, &type) == -1) {
					err_print(INVALID_MINOR, min);
					return (-1);
				}
				dp->dps_isblock = type == 'b';
			} else {
				if (strlen(min) >= sizeof (dp->dps_minornm)) {
					err_print(MINOR_TOO_LONG, maj, min);
					return (-1);
				}
				(void) strcpy(dp->dps_minornm, min);
			}
		}

		while (tok = strtok(NULL, "\n\t ")) {
			if (parse_plcy_token(tok, dp)) {
				err_print(BAD_ENTRY, fep->startline,
					fep->orgentry);
				return (-1);
			}
		}
		cnt++;
	}
	if (fep == NULL) {
		if (feof(in))
			err_print(UNEXPECTED_EOF, infile);
		else
			err_print(NO_MEMORY);
		return (-1);
	}
	qsort(mem, cnt, devplcysys_sz, qcmp);

	if ((res = modctl(MODSETDEVPOLICY, cnt, devplcysys_sz, mem)) != 0)
		err_print("modctl(MODSETDEVPOLICY): %s\n", strerror(errno));

	return (res);
}

int
load_devpolicy(void)
{
	int res;

	devplcy_init();

	res = loadprivs(EXTRA_PRIVS);
	res += loadpolicy(DEV_POLICY);

	return (res);
}
