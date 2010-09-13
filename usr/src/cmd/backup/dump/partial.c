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
 * Copyright (c) 1998,2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "dump.h"
#include <ftw.h>
#include <ulimit.h>

static int partial;

#ifdef __STDC__
static dev_t devfromopts(struct mntent *);
static int lf_mark_root(dev_t, char *);
static int lf_ftw_mark(const char *, const struct stat64 *, int);
static void markino(ino_t);
#else
static dev_t devfromopts();
static int lf_mark_root();
static int lf_ftw_mark();
static void markino();
#endif

void
#ifdef __STDC__
partial_check(void)
#else
partial_check()
#endif
{
	struct mntent *mnt;
	struct stat64 st;

	if (stat64(disk, &st) < 0 ||
	    (st.st_mode & S_IFMT) == S_IFCHR ||
	    (st.st_mode & S_IFMT) == S_IFBLK)
		return;

	partial_dev = st.st_dev;

	setmnttab();
	while (mnt = getmnttab()) {
		st.st_dev = devfromopts(mnt);
		if (st.st_dev == NODEV &&
		    stat64(mnt->mnt_dir, &st) < 0)
			continue;
		if (partial_dev == st.st_dev) {
			if (disk_dynamic) {
				/* LINTED: disk is not NULL */
				free(disk);
			}
			disk = rawname(mnt->mnt_fsname);
			disk_dynamic = (disk != mnt->mnt_fsname);

			partial = 1;
			incno = '0';
			uflag = 0;
			return;
		}
	}
	msg(gettext("`%s' is not on a locally mounted filesystem\n"), disk);
	dumpabort();
	/*NOTREACHED*/
}

/*
 *  The device id for the mount should be available in
 *  the mount option string as "dev=%04x".  If it's there
 *  extract the device id and avoid having to stat.
 */
static dev_t
devfromopts(mnt)
	struct mntent *mnt;
{
	char *str;

	str = hasmntopt(mnt, MNTINFO_DEV);
	if (str != NULL && (str = strchr(str, '=')))
		return ((dev_t)strtol(str + 1, (char **)NULL, 16));

	return (NODEV);
}

int
partial_mark(argc, argv)
	int argc;
	char **argv;
{
	char *path;
	struct stat64 st;

	if (partial == 0)
		return (1);

	while (--argc >= 0) {
		path = *argv++;

		if (stat64(path, &st) < 0 ||
			st.st_dev != partial_dev) {
			msg(gettext("`%s' is not on dump device `%s'\n"),
				path, disk);
			dumpabort();
			/*NOTREACHED*/
		}

		if (lf_mark_root(partial_dev, path)) {
			msg(gettext(
			    "Cannot find filesystem mount point for `%s'\n"),
			    path);
			dumpabort();
			/*NOTREACHED*/
		}

		/* LINTED this ulimit will always be < INT_MAX */
		if (lf_lftw(path, lf_ftw_mark, (int)ulimit(UL_GDESLIM, 0) / 2)
		    < 0) {
			int saverr = errno;
			msg(gettext("Error in %s (%s)\n"),
				"ftw", strerror(saverr));
			dumpabort();
			/*NOTREACHED*/
		}
	}

	return (0);
}

/* mark directories between target and root */
static int
lf_mark_root(dev, path)
	dev_t dev;
	char *path;
{
	struct stat64 st;
	char dotdot[MAXPATHLEN + 16];
	char *slash;

	if (strlen(path) > sizeof (dotdot))
		return (1);

	(void) strcpy(dotdot, path);

	if (stat64(dotdot, &st) < 0)
		return (1);

	/* if target is a regular file, find directory */
	if ((st.st_mode & S_IFMT) != S_IFDIR)
		if (slash = strrchr(dotdot, '/'))
			/* "/file" -> "/" */
			if (slash == dotdot)
				slash[1] = 0;
			/* "dir/file" -> "dir" */
			else
				slash[0] = 0;
		else
			/* "file" -> "." */
			(void) strcpy(dotdot, ".");

	/* keep marking parent until we hit mount point */
	do {
		if (stat64(dotdot, &st) < 0 ||
			(st.st_mode & S_IFMT) != S_IFDIR ||
			st.st_dev != dev)
			return (1);
		markino(st.st_ino);
		if (strlen(dotdot) > (sizeof (dotdot) - 4))
			return (1);
		(void) strcat(dotdot, "/..");
	} while (st.st_ino != 2);

	return (0);
}

/*ARGSUSED*/
static int
lf_ftw_mark(name, st, flag)
#ifdef __STDC__
	const char *name;
	const struct stat64 *st;
#else
	char *name;
	struct stat64 *st;
#endif
	int flag;
{
	if (flag != FTW_NS) {
		/* LINTED ufs only uses the lower 32 bits */
		markino((ino_t)st->st_ino);
	}
	return (0);
}

static void
markino(i)
	ino_t i;
{
	struct dinode *dp;

	dp = getino(ino = i);
	mark(dp);
}
