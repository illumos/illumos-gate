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
#include <stdarg.h>
#include <libintl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <kstat.h>
#include <sys/fs/cachefs_log.h>
#include <string.h>
#include <assert.h>
#include <ndbm.h>
#include <malloc.h>
#include <locale.h>
#include "stats.h"

void usage(char *);
void pr_err(char *, ...);

static int aflag = 0;

int
main(int argc, char **argv)
{
	int rc = 0;
	int c, errflg = 0;
	int len1, len2;
	char *ar, *progname;
	void *record;
	caddr_t vfsp;
	char *path;

	stats_cookie_t *sc = NULL;

	datum key;
	struct cachefs_log_logfile_header *lh;

	mount_info *mip;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif /* TEXT_DOMAIN */
	(void) textdomain(TEXT_DOMAIN);

	if (progname = strrchr(argv[0], '/'))
		++progname;
	else
		progname = argv[0];

	if ((sc = stats_create_unbound(progname)) == NULL) {
		pr_err(gettext("Cannot initialize stats library\n"));
		rc = 1;
		goto out;
	}

	while ((c = getopt(argc, argv, "a")) != EOF)
		switch (c) {
		case 'a':
			++aflag;
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

	path = argv[optind];

	if (stats_log_logfile_open(sc, path) != 0) {
		pr_err(stats_errorstr(sc));
		rc = 1;
		goto out;
	}
	lh = stats_log_getheader(sc);

	if (lh->lh_errno != 0)
		printf(gettext("warning: problem writing logfile: %s\n\n"),
		    strerror(lh->lh_errno));

	if (aflag) {
		while (record = stats_log_logfile_read(sc, NULL)) {
			ar = stats_log_record_toascii(sc, record);
			if (ar == NULL)
				break;
			puts(ar);
			free(record);
		}
		if (stats_inerror(sc))
			pr_err(stats_errorstr(sc));
		goto out;
	}

	stats_dbm_open(sc);
	stats_dbm_rm(sc);
	if (stats_inerror(sc)) {
		pr_err(stats_errorstr(sc));
		rc = stats_errno(sc);
		goto out;
	}

	stats_log_compute_wssize(sc);

	if (stats_inerror(sc)) {
		pr_err(stats_errorstr(sc));
		rc = stats_errno(sc);
		goto out;
	}

	for (key = stats_dbm_firstkey(sc);
	    key.dptr != NULL;
	    key = stats_dbm_nextkey(sc)) {
		if (key.dsize != sizeof (vfsp))
			continue;

		memcpy((caddr_t) &vfsp, key.dptr, sizeof (vfsp));
		mip = stats_dbm_fetch_byvfsp(sc, vfsp);
		if (mip == NULL)
			continue;
		if (! mip->mi_used)
			continue;

		printf("\n    %s\n", mip->mi_path);
		if (! mip->mi_mounted)
			printf("    (currently unmounted)\n");
		printf("\t       end size: %17lldk\n", mip->mi_current / 1024);
		printf("\thigh water size: %17lldk\n", mip->mi_high / 1024);
		free(mip);
	}

	printf(gettext("\n    total for cache\n"));
	printf(gettext("\t   initial size: %17lldk\n"),
	    (u_offset_t)(stats_log_wssize_init(sc) *
		lh->lh_maxbsize / (u_offset_t) 1024));
	printf(gettext("\t       end size: %17lldk\n"),
	    (u_offset_t)(stats_log_wssize_current(sc) / 1024));
	printf(gettext("\thigh water size: %17lldk\n"),
	    (u_offset_t)(stats_log_wssize_high(sc) / 1024));

	if (stats_inerror(sc)) {
		pr_err(stats_errorstr(sc));
		rc = stats_errno(sc);
	}

out:
	stats_dbm_close(sc);
	stats_destroy(sc);

	return (rc);
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
	    gettext("Usage: cachefswssize logfile\n"));
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
	(void) fprintf(stderr, gettext("cachefswssize: "));
	(void) vfprintf(stderr, fmt, ap);
	(void) fprintf(stderr, "\n");
	va_end(ap);
}
