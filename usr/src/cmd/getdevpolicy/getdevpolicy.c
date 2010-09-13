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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <priv.h>
#include <string.h>
#include <libgen.h>
#include <errno.h>
#include <sys/devpolicy.h>
#include <sys/modctl.h>
#include <sys/vnode.h>
#include <sys/stat.h>

static char *progname;

static const priv_impl_info_t *pi;
static size_t sz;

static void
fatalerr(const char *s)
{
	(void) fprintf(stderr, "%s: %s: %s\n", progname, s, strerror(errno));
	exit(1);
	/* NOTREACHED */
}

static void
fatal(const char *s)
{
	(void) fprintf(stderr, "%s: %s\n", progname, s);
	exit(1);
	/* NOTREACHED */
}

static void
printpolicy(const devplcysys_t *ds)
{
	char *ss;

	ss = priv_set_to_str(DEVPLCYSYS_RDP(ds, pi), ',', PRIV_STR_SHORT);
	(void) printf("\t"DEVPLCY_TKN_RDP"=%s\n", ss);
	free(ss);
	ss = priv_set_to_str(DEVPLCYSYS_WRP(ds, pi), ',', PRIV_STR_SHORT);
	(void) printf("\t"DEVPLCY_TKN_WRP"=%s\n", ss);
	free(ss);
}

static void
getpolicy(void)
{
	int nitems = 0;
	char *mem = NULL;
	int i;
	devplcysys_t *ds;
	char major[256];

	if (modctl(MODGETDEVPOLICY, &nitems, sz, mem) == 0 || errno != ENOMEM)
		fatalerr("modctl(MODGETDEVPOLICY)");

	mem = malloc(nitems * sz);
	if (mem == NULL)
		fatal("Out of memory");

	if (modctl(MODGETDEVPOLICY, &nitems, sz, mem) != 0)
		fatalerr("modctl");

	for (i = 0; i < nitems; i++) {
		/* LINTED: alignment */
		ds = (devplcysys_t *)(mem + i * sz);
		if (i == 0) {
			(void) printf("DEFAULT");
		} else {
			if (modctl(MODGETNAME, major, sizeof (major),
			    &ds->dps_maj) != 0)
				continue;
			(void) printf("%s:", major);
			if (ds->dps_minornm[0] != '\0') {
				(void) printf("%s", ds->dps_minornm);
			} else {
				/* (minor[-minor]) */
				(void) printf("(%u", (uint_t)ds->dps_lomin);
				if (ds->dps_lomin != ds->dps_himin)
					(void) printf("-%u",
						(uint_t)ds->dps_himin);
				(void) putchar(')');
				if (ds->dps_isblock)
					(void) putchar('b');
				else
					(void) putchar('c');
			}
		}
		(void) putchar('\n');
		printpolicy(ds);
	}
}

static void
getdevpolicy(const char *dev)
{
	devplcysys_t *ds;

	ds = malloc(sz);

	if (ds == NULL)
		fatal("Out of memory");

	if (modctl(MODGETDEVPOLICYBYNAME, sz, ds, dev) != 0)
		fatalerr("modctl");

	(void) printf("%s\n", dev);
	printpolicy(ds);
	free(ds);
}

int
main(int argc, char **argv)
{
	progname = basename(argv[0]);

	if ((pi = getprivimplinfo()) == NULL)
		fatalerr("getprivimplinfo");

	sz = DEVPLCYSYS_SZ(pi);

	if (argc == 1) {
		getpolicy();
		return (0);
	}

	while (*++argv != NULL)
		getdevpolicy(*argv);

	return (0);
}
