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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <grp.h>
#include <unistd.h>

/*
 * putgrent()	function to write a group structure to a file
 *		supports the use of group names that with + or -
 */
void
putgrent(struct group *grpstr, FILE *to)
{
	char **memptr;		/* member vector pointer */

	if (grpstr->gr_name[0] == '+' || grpstr->gr_name[0] == '-') {
		/*
		 * if the groupname starts with either a '+' or '-' then
		 * write out what we can as best as we can
		 * we assume that fgetgrent() set gr_gid to 0 so
		 * write a null entry instead of 0
		 * This should not break /etc/nsswitch.conf for any of
		 * "group: compat", "group: files", "group: nis"
		 *
		 */
		(void) fprintf(to, "%s:%s:", grpstr->gr_name,
			grpstr->gr_passwd != NULL ? grpstr->gr_passwd : "");

		if (grpstr->gr_gid == 0) {
			(void) fprintf(to, ":");
		} else {
			(void) fprintf(to, "%ld:", grpstr->gr_gid);
		}

		memptr = grpstr->gr_mem;

		while (memptr != NULL && *memptr != NULL) {
			(void) fprintf(to, "%s", *memptr);
			memptr++;
			if (memptr != NULL && *memptr != NULL)
				(void) fprintf(to, ",");
		}

		(void) fprintf(to, "\n");
	} else {
		/*
		 * otherwise write out all the fields in the group structure
		 *
		 */
		(void) fprintf(to, "%s:%s:%ld:", grpstr->gr_name,
			grpstr->gr_passwd, grpstr->gr_gid);

		memptr = grpstr->gr_mem;

		while (*memptr != NULL) {
			(void) fprintf(to, "%s", *memptr);
			memptr++;
			if (*memptr != NULL)
				(void) fprintf(to, ",");
		}

		(void) fprintf(to, "\n");
	}
}
