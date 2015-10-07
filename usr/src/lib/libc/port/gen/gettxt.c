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

#pragma weak _gettxt = gettxt

#include "lint.h"
#include "libc.h"
#include <mtlib.h>
#include <ctype.h>
#include <string.h>
#include <locale.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <pfmt.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <thread.h>
#include "../i18n/_locale.h"
#include "../i18n/_loc_path.h"

#define	MESSAGES 	"/LC_MESSAGES/"
#define	DB_NAME_LEN	15

#define	handle_return(s)	\
	((char *)((s) != NULL && *(s) != '\0' ? (s) : not_found))

extern char cur_cat[];
extern rwlock_t _rw_cur_cat;

static mutex_t	gettxt_lock = DEFAULTMUTEX;
static const char	*not_found = "Message not found!!\n";
static const char	*loc_C = "C";

struct db_list {
	char	db_name[DB_NAME_LEN];	/* name of the message file */
	uintptr_t	addr;		/* virtual memory address */
	struct db_list	*next;
};

struct db_cache {
	char	*loc;
	struct db_list	*info;
	struct db_cache	*next;
};

static struct db_cache	*db_cache;

char *
gettxt(const char *msg_id, const char *dflt_str)
{
	struct db_cache	*dbc;
	struct db_list	*dbl;
	char 	msgfile[DB_NAME_LEN];	/* name of static shared library */
	int	msgnum;			/* message number */
	char	pathname[PATH_MAX];	/* full pathname to message file */
	int	fd;
	struct stat64	sb;
	void	*addr;
	char	*tokp;
	size_t	name_len;
	char	*curloc;
	locale_t	loc;

	if ((msg_id == NULL) || (*msg_id == '\0')) {
		return (handle_return(dflt_str));
	}

	/* parse msg_id */
	if (((tokp = strchr(msg_id, ':')) == NULL) || *(tokp+1) == '\0')
		return (handle_return(dflt_str));
	if ((name_len = (tokp - msg_id)) >= DB_NAME_LEN)
		return (handle_return(dflt_str));
	if (name_len > 0) {
		(void) strncpy(msgfile, msg_id, name_len);
		msgfile[name_len] = '\0';
	} else {
		lrw_rdlock(&_rw_cur_cat);
		if (cur_cat == NULL || *cur_cat == '\0') {
			lrw_unlock(&_rw_cur_cat);
			return (handle_return(dflt_str));
		}
		/*
		 * We know the following strcpy is safe.
		 */
		(void) strcpy(msgfile, cur_cat);
		lrw_unlock(&_rw_cur_cat);
	}
	while (*++tokp) {
		if (!isdigit((unsigned char)*tokp))
			return (handle_return(dflt_str));
	}
	msgnum = atoi(msg_id + name_len + 1);
	loc = uselocale(NULL);
	curloc = current_locale(loc, LC_MESSAGES);

	lmutex_lock(&gettxt_lock);

try_C:
	dbc = db_cache;
	while (dbc) {
		if (strcmp(curloc, dbc->loc) == 0) {
			dbl = dbc->info;
			while (dbl) {
				if (strcmp(msgfile, dbl->db_name) == 0) {
					/* msgfile found */
					lmutex_unlock(&gettxt_lock);
					goto msgfile_found;
				}
				dbl = dbl->next;
			}
			/* not found */
			break;
		}
		dbc = dbc->next;
	}
	if (dbc == NULL) {
		/* new locale */
		if ((dbc = lmalloc(sizeof (struct db_cache))) == NULL) {
			lmutex_unlock(&gettxt_lock);
			return (handle_return(dflt_str));
		}
		if ((dbc->loc = lmalloc(strlen(curloc) + 1)) == NULL) {
			lfree(dbc, sizeof (struct db_cache));
			lmutex_unlock(&gettxt_lock);
			return (handle_return(dflt_str));
		}
		dbc->info = NULL;
		(void) strcpy(dbc->loc, curloc);
		/* connect dbc to the dbc list */
		dbc->next = db_cache;
		db_cache = dbc;
	}
	if ((dbl = lmalloc(sizeof (struct db_list))) == NULL) {
		lmutex_unlock(&gettxt_lock);
		return (handle_return(dflt_str));
	}

	if (snprintf(pathname, sizeof (pathname),
	    _DFLT_LOC_PATH "%s" MESSAGES "%s", dbc->loc, msgfile) >=
	    sizeof (pathname)) {
		lfree(dbl, sizeof (struct db_list));
		lmutex_unlock(&gettxt_lock);
		return (handle_return(dflt_str));
	}
	if ((fd = open(pathname, O_RDONLY)) == -1 ||
	    fstat64(fd, &sb) == -1 ||
	    (addr = mmap(NULL, (size_t)sb.st_size, PROT_READ, MAP_SHARED,
	    fd, 0L)) == MAP_FAILED) {
		if (fd != -1)
			(void) close(fd);
		lfree(dbl, sizeof (struct db_list));

		if (strcmp(dbc->loc, "C") == 0) {
			lmutex_unlock(&gettxt_lock);
			return (handle_return(dflt_str));
		}
		/* Change locale to C */
		curloc = (char *)loc_C;
		goto try_C;
	}
	(void) close(fd);

	/* save file name, memory address, fd and size */
	(void) strcpy(dbl->db_name, msgfile);
	dbl->addr = (uintptr_t)addr;

	/* connect dbl to the dbc->info list */
	dbl->next = dbc->info;
	dbc->info = dbl;

	lmutex_unlock(&gettxt_lock);

msgfile_found:
	/* check if msgnum out of domain */
	if (msgnum <= 0 || msgnum > *(int *)dbl->addr)
		return (handle_return(dflt_str));
	/* return pointer to message */
	return ((char *)(dbl->addr +
	    *(int *)(dbl->addr + msgnum * sizeof (int))));
}
