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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <libintl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <kstat.h>
#include <locale.h>
#include <sys/fs/cachefs_log.h>
#include "stats.h"

void usage(char *);
void pr_err(char *, ...);

static int zflag;
char *prog;

static void print_stats(stats_cookie_t *, cachefs_kstat_key_t *, int);

int
main(int argc, char **argv)
{
	int rc = 0;
	int i, c, errflg = 0;
	stats_cookie_t *sc = NULL;
	cachefs_kstat_key_t *key;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif /* TEXT_DOMAIN */
	(void) textdomain(TEXT_DOMAIN);

	if (prog = strrchr(argv[0], '/'))
		++prog;
	else
		prog = argv[0];

	while ((c = getopt(argc, argv, "z")) != EOF)
		switch (c) {
		case 'z':
			++zflag;
			break;

		case '?':
		default:
			++errflg;
			break;
		}

	if (errflg) {
		usage(NULL);
		rc = -1;
		goto out;
	}

	/*
	 * handle multiple mountpoints specified on command line
	 */

	for (i = optind; i < argc; i++) {
		if ((sc = stats_create_mountpath(argv[i], prog)) == NULL) {
			pr_err(gettext("Cannot use %s"), argv[i]);
			rc = 1;
			continue;
		}

		if (stats_inerror(sc)) {
			pr_err(stats_errorstr(sc));
			rc = stats_errno(sc);
			continue;
		}
		print_stats(sc, key = stats_getkey(sc), zflag);
		if (stats_inerror(sc)) {
			pr_err(stats_errorstr(sc));
			rc = stats_errno(sc);
		}

		stats_destroy(sc);
		free(key);
	}

	/*
	 * handle the case where no mountpoints were specified,
	 * i.e. show stats for all.
	 */

	if (optind >= argc) {
		sc = stats_create_unbound(prog);

		while ((key = stats_next(sc)) != NULL) {
			if (! key->ks_mounted) {
				free(key);
				continue;
			}

			print_stats(sc, key, zflag);
			if (stats_inerror(sc)) {
				pr_err(stats_errorstr(sc));
				rc = stats_errno(sc);
			}
			free(key);
		}
		stats_destroy(sc);
	}

out:
	return (rc);
}

static void
print_stats(stats_cookie_t *sc, cachefs_kstat_key_t *key, int zero)
{
	uint_t misses, passes, fails, modifies;
	uint_t hitp, passtotal;
	uint_t gccount;
	u_longlong_t hits;

	hits = (u_longlong_t)stats_hits(sc);
	misses = stats_misses(sc);
	if (hits + misses != 0)
		hitp = (uint_t)((100 * hits) / (hits + misses));
	else
		hitp = 100;

	passes = stats_passes(sc);
	fails = stats_fails(sc);
	passtotal = passes + fails;

	modifies = stats_modifies(sc);

	gccount = stats_gc_count(sc);

	printf("\n    %s\n", (char *)(uintptr_t)key->ks_mountpoint);
	printf(gettext(
		"\t         cache hit rate: %5u%% (%llu hits, %u misses)\n"),
		hitp, hits, misses);
	printf(gettext("\t     consistency checks: %6d (%d pass, %d fail)\n"),
	    passtotal, passes, fails);
	printf(gettext("\t               modifies: %6d\n"), modifies);
	printf(gettext("\t     garbage collection: %6d\n"), gccount);
	if (gccount != 0) {
		time_t gctime = stats_gc_time(sc);
		time_t before = stats_gc_before(sc);
		time_t after = stats_gc_after(sc);

		if (gctime != (time_t)0)
			printf(gettext("\tlast garbage collection: %s"),
			    ctime(&gctime));
	}

	if (zero)
		(void) stats_zero_stats(sc);
}


/*
 *
 *			usage
 *
 * Description:
 *	Prints a short usage message.
 * Arguments:
 *	msgp	message to include with the usage message
 * Returns:
 * Preconditions:
 */

void
usage(char *msgp)
{
	if (msgp) {
		pr_err("%s", msgp);
	}

	fprintf(stderr,
	    gettext("Usage: cachefsstat [ -z ] [ path ... ]\n"));
}

/*
 *
 *			pr_err
 *
 * Description:
 *	Prints an error message to stderr.
 * Arguments:
 *	fmt	printf style format
 *	...	arguments for fmt
 * Returns:
 * Preconditions:
 *	precond(fmt)
 */

void
pr_err(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) fprintf(stderr, gettext("cachefsstat: "));
	(void) vfprintf(stderr, fmt, ap);
	(void) fprintf(stderr, "\n");
	va_end(ap);
}
