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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	"lint.h"
#include	<mtlib.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<errno.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/vfstab.h>
#include	<string.h>
#include	<thread.h>
#include	<synch.h>
#include	<strings.h>
#include	<libc.h>
#include	"tsd.h"


#define	GETTOK_R(xx, ll, tmp)\
	if ((vp->xx = (char *)strtok_r(ll, sepstr, tmp)) == NULL)\
		return (VFS_TOOFEW);\
	if (strcmp(vp->xx, dash) == 0)\
		vp->xx = NULL
#define	GETTOK(xx, ll)\
	if ((vp->xx = strtok(ll, sepstr)) == NULL)\
		return (VFS_TOOFEW);\
	if (strcmp(vp->xx, dash) == 0)\
		vp->xx = NULL
#define	DIFF(xx)\
	(vrefp->xx != NULL && (vgetp->xx == NULL ||\
	    strcmp(vrefp->xx, vgetp->xx) != 0))
#define	SDIFF(xx, typem, typer)\
	(vgetp->xx == NULL || stat64(vgetp->xx, &statb) == -1 ||\
	(statb.st_mode & S_IFMT) != typem ||\
	    statb.st_rdev != typer)

static const char	sepstr[] = " \t\n";
static const char	dash[] = "-";

static int	getline(char *, FILE *);

int
getvfsspec(FILE *fd, struct vfstab *vgetp, char *special)
{
	int	ret, bstat;
	mode_t	bmode;
	dev_t	brdev;
	struct stat64	statb;


	if (special && stat64(special, &statb) == 0 &&
		((bmode = (statb.st_mode & S_IFMT)) == S_IFBLK ||
		bmode == S_IFCHR)) {
		bstat = 1;
		brdev = statb.st_rdev;
	} else
		bstat = 0;

	while ((ret = getvfsent(fd, vgetp)) == 0 &&
	    ((bstat == 0 &&
	    (special != NULL && (vgetp->vfs_special == NULL ||
	    strcmp(special, vgetp->vfs_special) != 0))) ||
	    (bstat == 1 &&
	    (vgetp->vfs_special == NULL ||
	    stat64(vgetp->vfs_special, &statb) == -1 ||
	    (statb.st_mode & S_IFMT) != bmode ||
	    statb.st_rdev != brdev))))
		;
	return (ret);
}

int
getvfsfile(FILE *fd, struct vfstab *vp, char *mountp)
{
	struct vfstab	vv;

	bzero(&vv, (size_t)sizeof (vv));
	vv.vfs_mountp = mountp;
	return (getvfsany(fd, vp, &vv));
}

int
getvfsany(FILE *fd, struct vfstab *vgetp, struct vfstab *vrefp)
{
	int	ret, bstat, cstat;
	mode_t	bmode, cmode;
	dev_t	brdev, crdev;
	struct stat64	statb;
	off64_t start = ftello64(fd);

	/* Match by straight strcmp */
	while ((ret = getvfsent(fd, vgetp)) == 0 &&
		(DIFF(vfs_special) || DIFF(vfs_fsckdev) ||
		DIFF(vfs_mountp) ||
		DIFF(vfs_fstype) ||
		DIFF(vfs_fsckpass) ||
		DIFF(vfs_automnt) ||
		DIFF(vfs_mntopts)))
		;

	/* If something other than EOF, return it */
	if (ret != -1)
		return (ret);

	/*
	 * Go back to the original location in the file and try to
	 * match the devices by doing stat's (retains compatibility
	 * with original getvfsany).
	 */
	(void) fseeko64(fd, start, SEEK_SET);

	if (vrefp->vfs_special && stat64(vrefp->vfs_special, &statb) == 0 &&
		((bmode = (statb.st_mode & S_IFMT)) == S_IFBLK ||
		bmode == S_IFCHR)) {
		bstat = 1;
		brdev = statb.st_rdev;
	} else
		bstat = 0;

	if (vrefp->vfs_fsckdev && stat64(vrefp->vfs_fsckdev, &statb) == 0 &&
		((cmode = (statb.st_mode & S_IFMT)) == S_IFBLK ||
		cmode == S_IFCHR)) {
		cstat = 1;
		crdev = statb.st_rdev;
	} else
		cstat = 0;

	while ((ret = getvfsent(fd, vgetp)) == 0 &&
		((bstat == 0 && DIFF(vfs_special)) ||
		(bstat == 1 && SDIFF(vfs_special, bmode, brdev)) ||
		(cstat == 0 && DIFF(vfs_fsckdev)) ||
		(cstat == 1 && SDIFF(vfs_fsckdev, cmode, crdev)) ||
		DIFF(vfs_mountp) ||
		DIFF(vfs_fstype) ||
		DIFF(vfs_fsckpass) ||
		DIFF(vfs_automnt) ||
		DIFF(vfs_mntopts)))
		;
	return (ret);
}

int
getvfsent(FILE *fd, struct vfstab *vp)
{
	int	ret;
	char	*tmp, *line;

	line = tsdalloc(_T_GETVFSENT, VFS_LINE_MAX, NULL);
	if (line == NULL)
		return (0);

	/* skip leading spaces and comments */
	if ((ret = getline(line, fd)) != 0)
		return (ret);

	/* split up each field */
	GETTOK_R(vfs_special, line, &tmp);
	GETTOK_R(vfs_fsckdev, NULL, &tmp);
	GETTOK_R(vfs_mountp, NULL, &tmp);
	GETTOK_R(vfs_fstype, NULL, &tmp);
	GETTOK_R(vfs_fsckpass, NULL, &tmp);
	GETTOK_R(vfs_automnt, NULL, &tmp);
	GETTOK_R(vfs_mntopts, NULL, &tmp);

	/* check for too many fields */
	if (strtok_r(NULL, sepstr, &tmp) != NULL)
		return (VFS_TOOMANY);

	return (0);
}

static int
getline(char *lp, FILE *fd)
{
	char	*cp;

	while ((lp = fgets(lp, VFS_LINE_MAX, fd)) != NULL) {
		if (strlen(lp) == VFS_LINE_MAX-1 && lp[VFS_LINE_MAX-2] != '\n')
			return (VFS_TOOLONG);

		for (cp = lp; *cp == ' ' || *cp == '\t'; cp++)
			;

		if (*cp != '#' && *cp != '\n')
			return (0);
	}
	return (-1);
}
