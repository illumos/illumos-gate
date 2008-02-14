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
 * smbfs umount
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <unistd.h>
#include <kstat.h>
#include <rpc/rpc.h>
#include <sys/mnttab.h>
#include <sys/mount.h>
#include <sys/mntent.h>
#include <errno.h>
#include <locale.h>
#include <fslib.h>
#include <priv.h>

#define	RET_OK	0
#define	RET_ERR	32

static void pr_err(const char *fmt, ...);
static void usage();
static int smbfs_unmount(char *, int);
static struct extmnttab *mnttab_find();

static char *myname;
static char typename[64];

int
main(int argc, char *argv[])
{
	extern int optind;
	int c;
	int umnt_flag = 0;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	myname = strrchr(argv[0], '/');
	myname = myname ? myname+1 : argv[0];
	(void) sprintf(typename, "smbfs %s", myname);
	argv[0] = typename;

	/*
	 * Set options
	 */
	while ((c = getopt(argc, argv, "f")) != EOF) {
		switch (c) {
		case 'f':
			umnt_flag |= MS_FORCE; /* forced unmount is desired */
			break;
		default:
			usage();
			exit(RET_ERR);
		}
	}
	if (argc - optind != 1) {
		usage();
		exit(RET_ERR);
	}

	return (smbfs_unmount(argv[optind], umnt_flag));
}

static void
pr_err(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) fprintf(stderr, "%s: ", typename);
	(void) vfprintf(stderr, fmt, ap);
	(void) fflush(stderr);
	va_end(ap);
}

static void
usage()
{
	(void) fprintf(stderr,
	    gettext("Usage: smbfs umount [-o opts] {//server/share | dir}\n"));
	exit(RET_ERR);
}

static int
smbfs_unmount(char *pathname, int umnt_flag)
{
	struct extmnttab *mntp;

	mntp = mnttab_find(pathname);
	if (mntp) {
		pathname = mntp->mnt_mountp;
	}

	if (umount2(pathname, umnt_flag) < 0) {
		pr_err(gettext("%s: %s\n"), pathname, strerror(errno));
		return (RET_ERR);
	}

	return (RET_OK);
}

/*
 *  Find the mnttab entry that corresponds to "name".
 *  We're not sure what the name represents: either
 *  a mountpoint name, or a special name (server:/path).
 *  Return the last entry in the file that matches.
 */
static struct extmnttab *
mnttab_find(dirname)
	char *dirname;
{
	FILE *fp;
	struct extmnttab mnt;
	struct extmnttab *res = NULL;

	fp = fopen(MNTTAB, "r");
	if (fp == NULL) {
		pr_err("%s: %s\n", MNTTAB, strerror(errno));
		return (NULL);
	}
	while (getextmntent(fp, &mnt, sizeof (struct extmnttab)) == 0) {
		if (strcmp(mnt.mnt_mountp, dirname) == 0 ||
		    strcmp(mnt.mnt_special, dirname) == 0) {
			if (res)
				fsfreemnttab(res);
			res = fsdupmnttab(&mnt);
		}
	}

	fclose(fp);
	return (res);
}
