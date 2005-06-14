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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <ctype.h>
#include <grp.h>
#include <unistd.h>
#include <string.h>
#include <userdefs.h>
#include <stdlib.h>
#include "users.h"
#include "messages.h"

/* lint error-killers: */
int errmsg(int, int);

/* Delete a group from the GROUP file */
int
del_group(char *group)
{
	int deleted;
	FILE *e_fptr, *t_fptr;
	struct group *grpstruct;
	char tname[] = "/etc/gtmp.XXXXXX";
	int fd;
	struct stat sbuf;
	boolean_t haserr;
	int line = 1;

	if ((e_fptr = fopen(GROUP, "r")) == NULL)
		return (EX_UPDATE);

	if (fstat(fileno(e_fptr), &sbuf) != 0)
		return (EX_UPDATE);

	if ((fd = mkstemp(tname)) == -1)
		return (EX_UPDATE);

	if ((t_fptr = fdopen(fd, "w")) == NULL) {
		(void) close(fd);
		(void) unlink(tname);
		return (EX_UPDATE);
	}

	/*
	 * Get ownership and permissions correct
	 */

	if (fchmod(fd, sbuf.st_mode) != 0 ||
	    fchown(fd, sbuf.st_uid, sbuf.st_gid) != 0) {
		(void) fclose(t_fptr);
		(void) unlink(tname);
		return (EX_UPDATE);
	}

	/* loop thru GROUP looking for the one to delete */
	deleted = 0;

	while ((grpstruct = fgetgrent(e_fptr)) != NULL) {

		/* check to see if group is one to delete */
		if (strcmp(grpstruct->gr_name, group) == 0)
			deleted = 1;
		else
			putgrent(grpstruct, t_fptr);
		line++;
	}

	haserr = !feof(e_fptr);

	if (haserr)
		errmsg(M_SYNTAX, line);

	(void) fclose(e_fptr);

	if (fclose(t_fptr) != 0 || haserr) {
		/* GROUP file contains bad entries or write failed. */
		(void) unlink(tname);
		return (EX_UPDATE);
	}

	/* If deleted, update GROUP file */
	if (deleted) {
		if (rename(tname, GROUP) != 0) {
			(void) unlink(tname);
			return (EX_UPDATE);
		}
		return (EX_SUCCESS);
	} else {
		(void) unlink(tname);
		return (EX_NAME_NOT_EXIST);
	}
}
