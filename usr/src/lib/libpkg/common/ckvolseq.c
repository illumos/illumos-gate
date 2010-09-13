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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */



#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include "pkgstrct.h"
#include "pkglib.h"
#include "pkglibmsgs.h"
#include "pkglocale.h"

#define	PKGMAP	"pkgmap"
#define	PKGINFO	"pkginfo"

int
ckvolseq(char *dir, int part, int nparts)
{
	static struct cinfo cinfo;
	char	ftype, path[PATH_MAX];

	if (part > 0) {
		ftype = 'f';
		if (part == 1) {
			/*
			 * save stats about content information of pkginfo
			 * file in order to verify multi-volume packages
			 */
			cinfo.cksum = cinfo.size = cinfo.modtime = (-1L);
			(void) snprintf(path, sizeof (path), "%s/pkginfo", dir);
			if (cverify(0, &ftype, path, &cinfo, 1)) {
				logerr(pkg_gt(ERR_BADPKGINFO), path);
				logerr(getErrbufAddr());
				return (1);
			}
			(void) snprintf(path, sizeof (path), "%s/pkgmap", dir);
			if (access(path, 0)) {
				logerr(pkg_gt(ERR_NOPKGMAP), path);
				return (2);
			}
		} else {
			/* temp fix due to summit problem */
			cinfo.modtime = (-1);

			/* pkginfo file doesn't match first floppy */
			(void) snprintf(path, sizeof (path), "%s/pkginfo", dir);
			if (cverify(0, &ftype, path, &cinfo, 1)) {
				logerr(pkg_gt(MSG_CORRUPT));
				logerr(getErrbufAddr());
				return (1);
			}
		}
	} else
		part = (-part);

	/*
	 * each volume in a multi-volume package must
	 * contain either the root.n or reloc.n directories
	 */
	if (nparts != 1) {
		/* look for multi-volume specification */
		(void) snprintf(path, sizeof (path), "%s/root.%d", dir, part);
		if (access(path, 0) == 0)
			return (0);
		(void) snprintf(path, sizeof (path), "%s/reloc.%d", dir, part);
		if (access(path, 0) == 0)
			return (0);
		if (part == 1) {
			(void) snprintf(path, sizeof (path), "%s/install",
								dir, part);
			if (access(path, 0) == 0)
				return (0);
		}
		if (nparts) {
			logerr(pkg_gt(MSG_SEQ));
			return (2);
		}
	}
	return (0);
}
