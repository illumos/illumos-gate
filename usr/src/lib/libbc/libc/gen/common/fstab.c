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
 * Copyright 1990 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fstab.h>
#include <stdio.h>
#include <ctype.h>
#include <mntent.h>

static	struct fstab *pfs;
static	FILE *fs_file;

static int
fstabscan(struct fstab *fs)
{
	struct mntent *mnt;

	/* skip over all filesystem types except '4.2', 'swap' & 'ignore' */
	while (((mnt = getmntent(fs_file)) != NULL) &&
		!((strcmp(mnt->mnt_type, MNTTYPE_42) == 0) ||
		  (strcmp(mnt->mnt_type, MNTTYPE_SWAP) == 0) ||
		  (strcmp(mnt->mnt_type, MNTTYPE_IGNORE) == 0)))
                continue;
	if (mnt == NULL)
		return (EOF);
	fs->fs_spec = mnt->mnt_fsname;
	fs->fs_file = mnt->mnt_dir;
	if (strcmp(mnt->mnt_type, MNTTYPE_IGNORE) == 0) {
		strcpy(mnt->mnt_opts, FSTAB_XX);
	} else if (strcmp(mnt->mnt_type, MNTTYPE_SWAP) == 0) {
		strcpy(mnt->mnt_opts, FSTAB_SW);
	} else if (hasmntopt(mnt, MNTOPT_RO)) {
		strcpy(mnt->mnt_opts, FSTAB_RO);
	} else if (hasmntopt(mnt, MNTOPT_QUOTA)) {
		strcpy(mnt->mnt_opts, FSTAB_RQ);
	} else {
		strcpy(mnt->mnt_opts, FSTAB_RW);
	}
	fs->fs_type = mnt->mnt_opts;
	fs->fs_freq = mnt->mnt_freq;
	fs->fs_passno = mnt->mnt_passno;
	return (5);
}

int
setfsent(void)
{

	if (fs_file)
		endfsent();
	if ((fs_file = setmntent(FSTAB, "r")) == NULL) {
		fs_file = 0;
		return (0);
	}
	return (1);
}

int
endfsent(void)
{

	if (fs_file) {
		endmntent(fs_file);
		fs_file = 0;
	}
	return (1);
}

struct fstab *
getfsent(void)
{
	int nfields;

	if ((fs_file == 0) && (setfsent() == 0))
		return ((struct fstab *)0);
	if (pfs == 0) {
		pfs = (struct fstab *)malloc(sizeof (struct fstab));
		if (pfs == 0)
			return (0);
	}
	nfields = fstabscan(pfs);
	if (nfields == EOF || nfields != 5)
		return ((struct fstab *)0);
	return (pfs);
}

struct fstab *
getfsspec(char *name)
{
	struct fstab *fsp;

	if (setfsent() == 0)	/* start from the beginning */
		return ((struct fstab *)0);
	while((fsp = getfsent()) != 0)
		if (strcmp(fsp->fs_spec, name) == 0)
			return (fsp);
	return ((struct fstab *)0);
}

struct fstab *
getfsfile(char *name)
{
	struct fstab *fsp;

	if (setfsent() == 0)	/* start from the beginning */
		return ((struct fstab *)0);
	while ((fsp = getfsent()) != 0)
		if (strcmp(fsp->fs_file, name) == 0)
			return (fsp);
	return ((struct fstab *)0);
}

struct fstab *
getfstype(char *type)
{
	struct fstab *fs;

	if (setfsent() == 0)
		return ((struct fstab *)0);
	while ((fs = getfsent()) != 0)
		if (strcmp(fs->fs_type, type) == 0)
			return (fs);
	return ((struct fstab *)0);
}
