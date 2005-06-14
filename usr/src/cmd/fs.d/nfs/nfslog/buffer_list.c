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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <syslog.h>
#include <libintl.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include "nfslogd.h"
#include "../lib/nfslogtab.h"
#include "buffer_list.h"

static int buildbuffer_list(struct buffer_ent **, timestruc_t *);
static void free_buffer_ent(struct buffer_ent *);
static struct buffer_ent *findbuffer(struct buffer_ent *, char *);
static void free_sharepnt_list(struct sharepnt_ent *);
static void free_sharepnt_ent(struct sharepnt_ent *);
#ifdef	DEBUG
static void print_sharepnt_list(struct sharepnt_ent *);
#endif
static struct sharepnt_ent *findsharepnt(struct sharepnt_ent *, char *,
	struct sharepnt_ent **);

/*
 * Builds the buffer list from NFSLOGTAB and returns it in *listpp.
 * Returns 0 on success, non-zero error code otherwise.
 */
int
getbuffer_list(struct buffer_ent **listpp, timestruc_t *lu)
{
	*listpp = NULL;
	return (buildbuffer_list(listpp, lu));
}

/*
 * If NFSLOGTAB has not been modified since the last time we read it,
 * it simply returns the same buffer list, otherwise it re-reads NFSLOGTAB
 * and rebuilds the list.
 * No NFSLOGTAB is not treated as an error.
 * Returns 0 on success, non-zero error code otherwise
 */
int
checkbuffer_list(struct buffer_ent **listpp, timestruc_t *lu)
{
	struct stat st;
	int error = 0;

	if (stat(NFSLOGTAB, &st) == -1) {
		error = errno;
		if (error != ENOENT) {
			syslog(LOG_ERR, gettext("Can't stat %s - %s"),
				NFSLOGTAB, strerror(error));
			error = 0;
		}
		return (error);
	}

	if (lu->tv_sec == st.st_mtim.tv_sec &&
	    lu->tv_nsec == st.st_mtim.tv_nsec)
		return (0);

	free_buffer_list(listpp);	/* free existing list first */
	return (buildbuffer_list(listpp, lu));
}

/*
 * Does the actual work of reading NFSLOGTAB, and building the
 * buffer list. If *be_head already contains entries, it will
 * update the list with new information.
 * Returns 0 on success, non-zero error code otherwise.
 */
static int
buildbuffer_list(struct buffer_ent **be_head, timestruc_t *lu)
{
	FILE *fd;
	struct buffer_ent *be_tail = NULL, *bep;
	struct sharepnt_ent *se_tail = NULL, *sep;
	struct logtab_ent *lep;
	struct stat st;
	int error = 0, res;

	if ((fd = fopen(NFSLOGTAB, "r+")) == NULL) {
		error = errno;
		if (error != ENOENT) {
			syslog(LOG_ERR, gettext("%s - %s\n"), NFSLOGTAB,
				strerror(error));
			error = 0;
		}
		return (error);
	}

	if (lockf(fileno(fd), F_LOCK, 0L) < 0) {
		error = errno;
		syslog(LOG_ERR, gettext("cannot lock %s - %s\n"), NFSLOGTAB,
			strerror(error));
		(void) fclose(fd);
		return (error);
	}

	assert(*be_head == NULL);
	while ((res = logtab_getent(fd, &lep)) > 0) {
		if (bep = findbuffer(*be_head, lep->le_buffer)) {
			/*
			 * Add sharepnt to buffer list
			 */
			if (sep = findsharepnt(bep->be_sharepnt,
			    lep->le_path, &se_tail)) {
				/*
				 * Sharepoint already in list,
				 * update its state.
				 */
				sep->se_state = lep->le_state;
			} else {
				/*
				 * Need to add to sharepoint list
				 */
				sep = (struct sharepnt_ent *)
					malloc(sizeof (*sep));
				if (sep == NULL) {
					error = ENOMEM;
					goto errout;
				}
				(void) memset(sep, 0, sizeof (*sep));

				sep->se_name = strdup(lep->le_path);
				if (sep->se_name == NULL) {
					error = ENOMEM;
					goto errout;
				}
				sep->se_state = lep->le_state;

				assert(se_tail != NULL);
				assert(se_tail->se_next == NULL);
				se_tail->se_next = sep;
			}
		} else {
			/*
			 * Add new buffer to list
			 */
			bep = (struct buffer_ent *)malloc(sizeof (*bep));
			if (bep == NULL) {
				error = ENOMEM;
				goto errout;
			}
			(void) memset(bep, 0, sizeof (*bep));

			bep->be_name = strdup(lep->le_buffer);
			if (bep->be_name == NULL) {
				error = ENOMEM;
				goto errout;
			}

			if (*be_head == NULL)
				*be_head = bep;
			else
				be_tail->be_next = bep;
			be_tail = bep;

			bep->be_sharepnt = (struct sharepnt_ent *)
				malloc(sizeof (*(bep->be_sharepnt)));
			(void) memset(bep->be_sharepnt, 0,
				sizeof (*(bep->be_sharepnt)));

			if (bep->be_sharepnt == NULL) {
				error = ENOMEM;
				goto errout;
			}
			bep->be_sharepnt->se_name = strdup(lep->le_path);
			if (bep->be_sharepnt->se_name == NULL) {
				error = ENOMEM;
				goto errout;
			}
			bep->be_sharepnt->se_state = lep->le_state;
		}
	}

	if (res < 0) {
		error = EIO;
		goto errout;
	}

	/*
	 * Get modification time while we have the file locked.
	 */
	if (lu) {
		if ((error = fstat(fileno(fd), &st)) == -1) {
			syslog(LOG_ERR, gettext("Can't stat %s"), NFSLOGTAB);
			goto errout;
		}
		*lu = st.st_mtim;
	}

	(void) fclose(fd);
	return (error);

errout:
	(void) fclose(fd);
	if (lep)
		logtab_ent_free(lep);
	free_buffer_list(be_head);
	assert(*be_head == NULL);
	syslog(LOG_ERR, gettext("cannot read %s: %s\n"), NFSLOGTAB,
		strerror(error));

	return (error);
}

/*
 * Removes the entry from the buffer list and frees it.
 */
void
remove_buffer_ent(struct buffer_ent **be_listpp, struct buffer_ent *bep)
{
	struct buffer_ent *p, *prev;

	for (p = prev = *be_listpp; p != NULL; p = p->be_next) {
		if (p == bep) {
			if (p == *be_listpp)
				*be_listpp = (*be_listpp)->be_next;
			else
				prev->be_next = bep->be_next;
			free_buffer_ent(bep);
			break;
		}
		prev = p;
	}
}

/*
 * Frees the buffer list.
 */
void
free_buffer_list(struct buffer_ent **be_listpp)
{
	struct buffer_ent *bep, *nextp;

	for (bep = *be_listpp; bep != NULL; bep = nextp) {
		nextp = bep->be_next;
		free_buffer_ent(bep);
	}
	*be_listpp = NULL;
}

static void
free_buffer_ent(struct buffer_ent *bep)
{
	assert(bep != NULL);
	if (debug)
		(void) printf("freeing %s\n", bep->be_name);
	if (bep->be_name != NULL)
		free(bep->be_name);
	if (bep->be_sharepnt != NULL)
		free_sharepnt_list(bep->be_sharepnt);
	free(bep);
}

static void
free_sharepnt_list(struct sharepnt_ent *sep_listp)
{
	struct sharepnt_ent *nextp;

	for (; sep_listp != NULL; sep_listp = nextp) {
		nextp = sep_listp->se_next;
		free_sharepnt_ent(sep_listp);
	}
	free(sep_listp);
}

/*
 * Removes the entry from the sharepnt list and frees it.
 */
void
remove_sharepnt_ent(struct sharepnt_ent **se_listpp, struct sharepnt_ent *sep)
{
	struct sharepnt_ent *p, *prev;

	for (p = prev = *se_listpp; p != NULL; p = p->se_next) {
		if (p == sep) {
			if (p == *se_listpp)
				*se_listpp = (*se_listpp)->se_next;
			else
				prev->se_next = sep->se_next;
			free_sharepnt_ent(sep);
			break;
		}
		prev = p;
	}
}

static void
free_sharepnt_ent(struct sharepnt_ent *sep)
{
	assert(sep != NULL);
	if (debug)
		(void) printf("freeing %s\n", sep->se_name);
	if (sep->se_name != NULL)
		free(sep->se_name);
	free(sep);
}

#ifdef DEBUG
void
printbuffer_list(struct buffer_ent *bep)
{
	for (; bep != NULL; bep = bep->be_next) {
		(void) printf("%s\n", bep->be_name);
		if (bep->be_sharepnt != NULL)
			print_sharepnt_list(bep->be_sharepnt);
	}
}

static void
print_sharepnt_list(struct sharepnt_ent *sep)
{
	for (; sep != NULL; sep = sep->se_next)
		(void) printf("\t(%d) %s\n", sep->se_state, sep->se_name);
}
#endif

/*
 * Returns a pointer to the buffer matching 'name', NULL otherwise.
 */
static struct buffer_ent *
findbuffer(struct buffer_ent *bep, char *name)
{
	for (; bep != NULL; bep = bep->be_next) {
		if (strcmp(bep->be_name, name) == 0)
			return (bep);
	}
	return (NULL);
}

/*
 * Returns a pointer the sharepoint entry matching 'name'.
 * Otherwise, it sets '*se_tail' to the last element of the list
 * to make insertion of new element easier, and returns NULL.
 */
static struct sharepnt_ent *
findsharepnt(
	struct sharepnt_ent *sep,
	char *name,
	struct sharepnt_ent **se_tail)
{
	struct sharepnt_ent *tail;

	for (; sep != NULL; sep = sep->se_next) {
		if (strcmp(sep->se_name, name) == 0)
			return (sep);
		tail = sep;
	}
	*se_tail = tail;
	return (NULL);
}
