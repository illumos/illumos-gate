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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <grp.h>
#include <unistd.h>
#include <userdefs.h>
#include <errno.h>
#include <limits.h>
#include "users.h"
#include "messages.h"

#define	MYBUFSIZE (LINE_MAX)
	/* Corresponds to MYBUFSIZE in grpck.c, BUFCONST in nss_dbdefs.c */

int
edit_group(char *login, char *new_login, gid_t gids[], int overwrite)
{
	char **memptr;
	char t_name[] = "/etc/gtmp.XXXXXX";
	int fd;
	FILE *e_fptr, *t_fptr;
	struct group *g_ptr;	/* group structure from fgetgrent */
	int i;
	int modified = 0;
	struct stat sbuf;

	int bufsize, g_length, sav_errno;
	long g_curr = 0L;
	char *g_string, *new_g_string, *gstr_off;

	if ((e_fptr = fopen(GROUP, "r")) == NULL)
		return (EX_UPDATE);

	if (fstat(fileno(e_fptr), &sbuf) != 0) {
		(void) fclose(e_fptr);
		return (EX_UPDATE);
	}

	if ((fd = mkstemp(t_name)) == -1) {
		(void) fclose(e_fptr);
		return (EX_UPDATE);
	}

	if ((t_fptr = fdopen(fd, "w")) == NULL) {
		(void) close(fd);
		(void) unlink(t_name);
		(void) fclose(e_fptr);
		return (EX_UPDATE);
	}

	/*
	 * Get ownership and permissions correct
	 */

	if (fchmod(fd, sbuf.st_mode) != 0 ||
	    fchown(fd, sbuf.st_uid, sbuf.st_gid) != 0) {
		(void) fclose(t_fptr);
		(void) fclose(e_fptr);
		(void) unlink(t_name);
		return (EX_UPDATE);
	}

	g_curr = ftell(e_fptr);

	/* Make TMP file look like we want GROUP file to look */

	bufsize = MYBUFSIZE;
	if ((g_string = malloc(bufsize)) == NULL) {
		(void) fclose(t_fptr);
		(void) fclose(e_fptr);
		(void) unlink(t_name);
		return (EX_UPDATE);
	}
	/*
	 * bufsize contains the size of the currently allocated buffer
	 * buffer size, which is initially MYBUFSIZE but when a line
	 * greater than MYBUFSIZE is encountered then bufsize gets increased
	 * by MYBUFSIZE.
	 * g_string always points to the beginning of the buffer (even after
	 * realloc()).
	 * gstr_off = g_string + MYBUFSIZE * (n), where n >= 0.
	 */
	while (!feof(e_fptr) && !ferror(e_fptr)) {
		g_length = 0;
		gstr_off = g_string;
		while (fgets(gstr_off, (bufsize - g_length), e_fptr) != NULL) {
			g_length += strlen(gstr_off);
			if (g_string[g_length - 1] == '\n' || feof(e_fptr))
				break;
			new_g_string = realloc(g_string, (bufsize + MYBUFSIZE));
			if (new_g_string == NULL) {
				free(g_string);
				(void) fclose(t_fptr);
				(void) fclose(e_fptr);
				(void) unlink(t_name);
				return (EX_UPDATE);
			}
			bufsize += MYBUFSIZE;
			g_string = new_g_string;
			gstr_off = g_string + g_length;
		}
		if (g_length == 0) {
			continue;
		}

		/* While there is another group string */

		(void) fseek(e_fptr, g_curr, SEEK_SET);
		errno = 0;
		g_ptr = fgetgrent(e_fptr);
		sav_errno = errno;
		g_curr = ftell(e_fptr);

		if (g_ptr == NULL) {
			/* tried to parse a group string over MYBUFSIZ char */
			if (sav_errno == ERANGE)
				errmsg(M_GROUP_ENTRY_OVF);
			else
				errmsg(M_READ_ERROR);

			modified = 0; /* bad group file: cannot rebuild */
			break;
		}

		/* first delete the login from the group, if it's there */
		if (overwrite || !gids) {
			if (g_ptr->gr_mem != NULL) {
				for (memptr = g_ptr->gr_mem; *memptr;
				    memptr++) {
					if (strcmp(*memptr, login) == 0) {
						/* Delete this one */
						char **from = memptr + 1;

						g_length -= (strlen(*memptr)+1);

						do {
							*(from - 1) = *from;
						} while (*from++);

						modified++;
						break;
					}
				}
			}
		}

		/* now check to see if group is one to add to */
		if (gids) {
			for (i = 0; gids[i] != -1; i++) {
				if (g_ptr->gr_gid == gids[i]) {
					/* Find end */
					for (memptr = g_ptr->gr_mem; *memptr;
						memptr++)
						;
					g_length += strlen(new_login ?
							new_login : login)+1;

					*memptr++ = new_login ?
						new_login : login;
					*memptr = NULL;

					modified++;
				}
			}
		}
		putgrent(g_ptr, t_fptr);
	}
	free(g_string);

	(void) fclose(e_fptr);

	if (fclose(t_fptr) != 0) {
		(void) unlink(t_name);
		return (EX_UPDATE);
	}

	/* Now, update GROUP file, if it was modified */
	if (modified) {
		if (rename(t_name, GROUP) != 0) {
			(void) unlink(t_name);
			return (EX_UPDATE);
		}
		return (EX_SUCCESS);
	} else {
		(void) unlink(t_name);
		return (EX_SUCCESS);
	}
}
