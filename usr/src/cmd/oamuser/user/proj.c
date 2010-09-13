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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/stat.h>
#include <project.h>
#include <unistd.h>
#include <userdefs.h>
#include <errno.h>
#include <nss_dbdefs.h>
#include "users.h"
#include "messages.h"

int
edit_project(char *login, char *new_login, projid_t projids[], int overwrite)
{
	char **memptr;
	char t_name[] = "/etc/projtmp.XXXXXX";
	FILE *e_fptr, *t_fptr;
	struct project *p_ptr;
	struct project p_work;
	char workbuf[NSS_LINELEN_PROJECT];
	int i, modified = 0;
	struct stat sbuf;
	int p_length;
	char p_string[NSS_LINELEN_PROJECT];
	long p_curr = 0;
	int exist;
	int fd;

	if ((e_fptr = fopen(PROJF_PATH, "r")) == NULL) {
		return (EX_UPDATE);
	}

	if (fstat(fileno(e_fptr), &sbuf) != 0)
		return (EX_UPDATE);

	if ((fd = mkstemp(t_name)) < 0) {
		return (EX_UPDATE);
	}

	if ((t_fptr = fdopen(fd, "w+")) == NULL) {
		(void) close(fd);
		(void) unlink(t_name);
		return (EX_UPDATE);
	}

	/*
	 * Get ownership and permissions correct
	 */

	if (fchmod(fd, sbuf.st_mode) != 0 ||
	    fchown(fd, sbuf.st_uid, sbuf.st_gid) != 0) {
		(void) fclose(t_fptr);
		(void) unlink(t_name);
		return (EX_UPDATE);
	}

	p_curr = ftell(e_fptr);

	/* Make TMP file look like we want project file to look */

	while (fgets(p_string, NSS_LINELEN_PROJECT - 1, e_fptr)) {
		/* While there is another group string */

		p_length = strlen(p_string);
		(void) fseek(e_fptr, p_curr, SEEK_SET);
		p_ptr = fgetprojent(e_fptr, &p_work, &workbuf,
		    sizeof (workbuf));
		p_curr = ftell(e_fptr);

		if (p_ptr == NULL) {
			/*
			 * tried to parse a proj string over
			 * NSS_LINELEN_PROJECT chars
			 */
			errmsg(M_PROJ_ENTRY_OVF, NSS_LINELEN_PROJECT);
			modified = 0; /* bad project file: cannot rebuild */
			break;
		}

		/* first delete the login from the project, if it's there */
		if (overwrite || !projids) {
			if (p_ptr->pj_users != NULL) {
				for (memptr = p_ptr->pj_users; *memptr;
				    memptr++) {
					if (strcmp(*memptr, login) == 0) {
						/* Delete this one */
						char **from = memptr + 1;
						p_length -= (strlen(*memptr)+1);
						do {
							*(from - 1) = *from;
						} while (*from++);

						modified++;
						break;
					}
				}
			}
		}

		/* now check to see if project is one to add to */
		if (projids) {
			for (i = 0; projids[i] != -1; i++) {
				if (p_ptr->pj_projid == projids[i]) {
					/* Scan for dups */
					exist = 0;
					for (memptr = p_ptr->pj_users; *memptr;
					    memptr++) {
						if (strncmp(*memptr, new_login ?
						    new_login : login,
						    strlen(*memptr)) == 0)
							exist++;
					}
					p_length += strlen(new_login ?
					    new_login : login) + 1;

					if (p_length >=
					    NSS_LINELEN_PROJECT - 1) {
						errmsg(M_PROJ_ENTRY_OVF,
						    NSS_LINELEN_PROJECT);
						break;
					} else {
						if (!exist) {
						*memptr++ = new_login ?
						    new_login : login;
						*memptr = NULL;
						modified++;
						}
					}
				}
			}
		}
		putprojent(p_ptr, t_fptr);
	}

	(void) fclose(e_fptr);
	(void) fclose(t_fptr);

	/* Now, update project file, if it was modified */
	if (modified && rename(t_name, PROJF_PATH) < 0) {
		(void) unlink(t_name);
		return (EX_UPDATE);
	}

	(void) unlink(t_name);
	return (EX_SUCCESS);
}
