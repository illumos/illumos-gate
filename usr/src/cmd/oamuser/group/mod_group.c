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
#include <stdio.h>
#include <ctype.h>
#include <grp.h>
#include <sys/stat.h>
#include <unistd.h>
#include <userdefs.h>
#include <strings.h>
#include <stdlib.h>
#include "users.h"
#include "messages.h"

/* lint error-killers: */
void errmsg(int, int);

/* Modify group to new gid and/or new name */
int
mod_group(char *group, gid_t gid, char *newgroup)
{
	int modified = 0;
	int fd;
	char tname[] = "/etc/gtmp.XXXXXX";
	FILE *e_fptr, *t_fptr;
	struct group *g_ptr;
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

	while ((g_ptr = fgetgrent(e_fptr)) != NULL) {

		/* check to see if group is one to modify */
		if (strcmp(g_ptr->gr_name, group) == 0) {
			if (newgroup != NULL)
				g_ptr->gr_name = newgroup;
			if (gid != -1)
				g_ptr->gr_gid = gid;
			modified++;
		}
		putgrent(g_ptr, t_fptr);
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

	if (modified) {
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
