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

/*
 * Manipulates the nfslogtab
 */

#ifndef _REENTRANT
#define	_REENTRANT
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <utmpx.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include "nfslogtab.h"

#ifndef	LINTHAPPY
#define	LINTHAPPY
#endif

static void logtab_ent_list_free(struct logtab_ent_list *);

/*
 * Retrieves the next entry from nfslogtab.
 * Assumes the file is locked.
 * '*lepp' points to the new entry if successful.
 * Returns:
 *      > 0  valid entry
 *      = 0  end of file
 *      < 0  error
 */
int
logtab_getent(FILE *fd, struct logtab_ent **lepp)
{
	char line[MAXBUFSIZE + 1];
	char *p;
	char *lasts, *tmp;
	char *w = " \t";
	struct logtab_ent *lep = NULL;
	int error = 0;

	if ((lep = (struct logtab_ent *)malloc(sizeof (*lep))) == NULL) {
		return (-1);
	}
	(void) memset((char *)lep, 0, sizeof (*lep));

	if ((p = fgets(line, MAXBUFSIZE, fd)) == NULL)  {
		error = 0;
		goto errout;
	}

	line[strlen(line) - 1] = '\0';

	tmp = (char *)strtok_r(p, w, &lasts);
	if (tmp == NULL) {
		error = -1;
		goto errout;
	}
	if ((lep->le_buffer = strdup(tmp)) == NULL) {
		error = -1;
		goto errout;
	}

	tmp = (char *)strtok_r(NULL, w, &lasts);
	if (tmp == NULL) {
		error = -1;
		goto errout;
	}
	if ((lep->le_path = strdup(tmp)) == NULL) {
		error = -1;
		goto errout;
	}

	tmp = (char *)strtok_r(NULL, w, &lasts);
	if (tmp == NULL) {
		error = -1;
		goto errout;
	}
	if ((lep->le_tag = strdup(tmp)) == NULL) {
		error = -1;
		goto errout;
	}

	tmp = (char *)strtok_r(NULL, w, &lasts);
	if (tmp == NULL) {
		error = -1;
		goto errout;
	}
	lep->le_state = atoi(tmp);

	*lepp = lep;
	return (1);

errout:
	logtab_ent_free(lep);

	return (error);
}

/*
 * Append an entry to the logtab file.
 */
int
logtab_putent(FILE *fd, struct logtab_ent *lep)
{
	int r;

	if (fseek(fd, 0L, SEEK_END) < 0)
		return (errno);

	r = fprintf(fd, "%s\t%s\t%s\t%d\n",
		lep->le_buffer,
		lep->le_path,
		lep->le_tag,
		lep->le_state);

	return (r);
}

#ifndef	LINTHAPPY
/*
 * Searches the nfslogtab file looking for the next entry which matches
 * the search criteria. The search is continued at the current position
 * in the nfslogtab file.
 * If 'buffer' != NULL, then buffer is matched.
 * If 'path' != NULL, then path is matched.
 * If 'tag' != NULL, then tag is matched.
 * If 'state' != -1, then state is matched.
 * 'buffer', 'path' and 'tag' can all be non-NULL, which means the entry must
 * satisfy all requirements.
 *
 * Returns 0 on success, ENOENT otherwise.
 * If found, '*lepp' points to the matching entry, otherwise '*lepp' is
 * undefined.
 */
static int
logtab_findent(FILE *fd, char *buffer, char *path, char *tag, int state,
		struct logtab_ent **lepp)
{
	boolean_t found = B_FALSE;

	while (!found && (logtab_getent(fd, lepp) > 0)) {
		found = B_TRUE;
		if (buffer != NULL)
			found = strcmp(buffer, (*lepp)->le_buffer) == 0;
		if (path != NULL)
			found = found && (strcmp(path, (*lepp)->le_path) == 0);
		if (tag != NULL)
			found = found && (strcmp(tag, (*lepp)->le_tag) == 0);
		if (state != -1)
			found = found && (state == (*lepp)->le_state);
		if (!found)
			logtab_ent_free(*lepp);
	}

	return (found ? 0 : ENOENT);
}
#endif

/*
 * Remove all entries which match the search criteria.
 * If 'buffer' != NULL, then buffer is matched.
 * If 'path' != NULL, then path is matched.
 * If 'tag' != NULL, then tag is matched.
 * If 'state' != -1, then state is matched.
 * 'buffer', 'path' and 'tag' can all be non-NULL, which means the entry must
 * satisfy all requirements.
 * The file is assumed to be locked.
 * Read the entries into a linked list of logtab_ent structures
 * minus the entries to be removed, then truncate the nfslogtab
 * file and write it back to the file from the linked list.
 *
 * On success returns 0, -1 otherwise.
 * Entry not found is treated as success since it was going to be removed
 * anyway.
 */
int
logtab_rement(FILE *fd, char *buffer, char *path, char *tag, int state)
{
	struct logtab_ent_list *head = NULL, *tail = NULL, *tmpl;
	struct logtab_ent *lep;
	int remcnt = 0;		/* remove count */
	int error = 0;
	boolean_t found;

	rewind(fd);
	while ((error = logtab_getent(fd, &lep)) > 0) {
		found = B_TRUE;
		if (buffer != NULL)
			found = strcmp(buffer, lep->le_buffer) == 0;
		if (path != NULL)
			found = found && (strcmp(path, lep->le_path) == 0);
		if (tag != NULL)
			found = found && (strcmp(tag, lep->le_tag) == 0);
		if (state != -1)
			found = found && (state == lep->le_state);
		if (found) {
			remcnt++;
			logtab_ent_free(lep);
		} else {
			tmpl = (struct logtab_ent_list *)
				malloc(sizeof (struct logtab_ent));
			if (tmpl == NULL) {
				error = ENOENT;
				break;
			}

			tmpl->lel_le = lep;
			tmpl->lel_next = NULL;
			if (head == NULL) {
				/*
				 * empty list
				 */
				head = tail = tmpl;
			} else {
				/*
				 * Add to the end of the list and remember
				 * the new last element.
				 */
				tail->lel_next = tmpl;
				tail = tmpl;	/* remember the last element */
			}
		}
	}

	if (error)
		goto deallocate;

	if (remcnt == 0) {
		/*
		 * Entry not found, nothing to do
		 */
		goto deallocate;
	}

	if (ftruncate(fileno(fd), 0) < 0) {
		error = -1;
		goto deallocate;
	}

	for (tmpl = head; tmpl != NULL; tmpl = tmpl->lel_next)
		(void) logtab_putent(fd, tmpl->lel_le);

deallocate:
	logtab_ent_list_free(head);

	return (error);
}

/*
 * Deactivate all entries matching search criteria.
 * If 'buffer' != NULL then match buffer.
 * If 'path' != NULL then match path.
 * If 'tag' != NULL then match tag.
 * Note that 'buffer', 'path' and 'tag' can al be non-null at the same time.
 *
 * Rewrites the nfslogtab file with the updated state for each entry.
 * Assumes the nfslogtab file has been locked for writing.
 * Returns 0 on success, -1 on failure.
 */
int
logtab_deactivate(FILE *fd, char *buffer, char *path, char *tag)
{
	struct logtab_ent_list *lelp, *head = NULL, *tail = NULL;
	struct logtab_ent *lep;
	boolean_t found;
	int error = 0;
	int count = 0;

	rewind(fd);
	while ((error = logtab_getent(fd, &lep)) > 0) {
		found = B_TRUE;
		if (buffer != NULL)
			found = strcmp(buffer, lep->le_buffer) == 0;
		if (path != NULL)
			found = found && (strcmp(path, lep->le_path) == 0);
		if (tag != NULL)
			found = found && (strcmp(tag, lep->le_tag) == 0);
		if (found && (lep->le_state == LES_ACTIVE)) {
			count++;
			lep->le_state = LES_INACTIVE;
		}

		lelp = (struct logtab_ent_list *)
			malloc(sizeof (struct logtab_ent));
		if (lelp == NULL) {
			error = ENOENT;
			break;
		}

		lelp->lel_le = lep;
		lelp->lel_next = NULL;
		if (head == NULL) {
			/*
			 * empty list
			 */
			head = tail = lelp;
		} else {
			/*
			 * Add to the end of the list and remember
			 * the new last element.
			 */
			tail->lel_next = lelp;
			tail = lelp;	/* remember the last element */
		}
	}

	if (error)
		goto deallocate;

	if (count == 0) {
		/*
		 * done
		 */
		error = 0;
		goto deallocate;
	}

	if (ftruncate(fileno(fd), 0) < 0) {
		error = -1;
		goto deallocate;
	}

	for (lelp = head; lelp != NULL; lelp = lelp->lel_next)
		(void) logtab_putent(fd, lelp->lel_le);

deallocate:
	logtab_ent_list_free(head);

	return (error);
}

/*
 * Deactivates all entries if nfslogtab exists and is older than boot time
 * This will only happen the first time it is called.
 * Assumes 'fd' has been locked by the caller.
 * Returns 0 on success, otherwise -1.
 */
int
logtab_deactivate_after_boot(FILE *fd)
{
	struct stat st;
	struct utmpx *utmpxp;
	int error = 0;

	if ((fstat(fileno(fd), &st) == 0) &&
	    ((utmpxp = getutxent()) != NULL) &&
	    (utmpxp->ut_xtime > st.st_mtime)) {
		if (logtab_deactivate(fd, NULL, NULL, NULL))
			error = -1;
	}

	return (error);
}

void
logtab_ent_free(struct logtab_ent *lep)
{
	if (lep->le_buffer)
		free(lep->le_buffer);
	if (lep->le_path)
		free(lep->le_path);
	if (lep->le_tag)
		free(lep->le_tag);
	free(lep);
}

static void
logtab_ent_list_free(struct logtab_ent_list *head)
{
	struct logtab_ent_list *lelp, *next;

	if (head == NULL)
		return;

	for (lelp = head; lelp != NULL; lelp = next) {
		if (lelp->lel_le != NULL)
			logtab_ent_free(lelp->lel_le);
		next = lelp->lel_next;
		free(lelp);
	}
}
