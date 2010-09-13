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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	All Rights Reserved	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.3 */

#include	<sys/types.h>
#include	<sys/stat.h>
#include	<stdio.h>
#include	<unistd.h>
#include	<userdefs.h>

#define	GRPTMP		"/etc/gtmp"
#define	GRPBUFSIZ	5120

int
add_group(group, gid)
char *group;	/* name of group to add */
gid_t gid;		/* gid of group to add */
{
	FILE *etcgrp;		/* /etc/group file */
	FILE *etctmp;		/* temp file */
	int o_mask;		/* old umask value */
	int newdone = 0;	/* set true when new entry done */
	struct stat sb;		/* stat buf to copy modes */
	char buf[GRPBUFSIZ];

	if ((etcgrp = fopen(GROUP, "r")) == NULL) {
		return (EX_UPDATE);
	}

	if (fstat(fileno(etcgrp), &sb) < 0) {
		/* If we can't get mode, take a default */
		sb.st_mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH;
	}

	o_mask = umask(077);
	etctmp = fopen(GRPTMP, "w+");
	(void) umask(o_mask);

	if (etctmp == NULL) {
		fclose(etcgrp);
		return (EX_UPDATE);
	}

	if (fchmod(fileno(etctmp), sb.st_mode) != 0 ||
	    fchown(fileno(etctmp), sb.st_uid, sb.st_gid) != 0 ||
	    lockf(fileno(etctmp), F_LOCK, 0) != 0) {
		fclose(etcgrp);
		fclose(etctmp);
		unlink(GRPTMP);
		return (EX_UPDATE);
	}

	while (fgets(buf, GRPBUFSIZ, etcgrp) != NULL) {
		/* Check for NameService reference */
		if (!newdone && (buf[0] == '+' || buf[0] == '-')) {
			(void) fprintf(etctmp, "%s::%u:\n", group, gid);
			newdone = 1;
		}

		fputs(buf, etctmp);
	}


	(void) fclose(etcgrp);

	if (!newdone) {
		(void) fprintf(etctmp, "%s::%u:\n", group, gid);
	}

	if (rename(GRPTMP, GROUP) < 0) {
		fclose(etctmp);
		unlink(GRPTMP);
		return (EX_UPDATE);
	}

	(void) fclose(etctmp);


	return (EX_SUCCESS);
}
