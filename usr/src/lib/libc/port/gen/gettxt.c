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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma weak Msgdb = _Msgdb
#pragma weak gettxt = _gettxt

#include "synonyms.h"
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
#include "../i18n/_locale.h"
#include "../i18n/_loc_path.h"

#define	MAXDB	10	/* maximum number of data bases per program */
#define	MESSAGES 	"/LC_MESSAGES/"
#define	DB_NAME_LEN	15

char 	*handle_return(const char *);

/* support multiple versions of a package */

char	*Msgdb = (char *)NULL;

static	char	*saved_locale = NULL;
static  const	char	*not_found = "Message not found!!\n";

static	struct	db_info {
	char	db_name[DB_NAME_LEN];	/* name of the message file */
	uintptr_t	addr;		/* virtual memory address */
	size_t  length;
} *db_info;

static	int	db_count;   	/* number of currently accessible data bases */

char *
gettxt(const char *msg_id, const char *dflt_str)
{
	char  msgfile[DB_NAME_LEN];	/* name of static shared library */
	int   msgnum;			/* message number */
	char  pathname[PATH_MAX];	/* full pathname to message file */
	int   i;
	int   new_locale = 0;
	int   fd;
	struct stat64 sb;
	void	*addr;
	char   *tokp;
	size_t   name_len;
	char	*curloc;

	if ((msg_id == NULL) || (*msg_id == NULL)) {
		return (handle_return(dflt_str));
	}

	/* first time called, allocate space */
	if (!db_info) {
		if ((db_info = (struct db_info *) \
		    malloc(MAXDB * sizeof (struct db_info))) == NULL)
			return (handle_return(dflt_str));
	}

	/* parse msg_id */

	if (((tokp = strchr(msg_id, ':')) == NULL) || *(tokp+1) == '\0')
		return (handle_return(dflt_str));
	if ((name_len = (tokp - msg_id)) >= DB_NAME_LEN)
		return (handle_return(dflt_str));
	if (name_len) {
		(void) strncpy(msgfile, msg_id, name_len);
		msgfile[name_len] = '\0';
	} else {
		if (Msgdb && strlen(Msgdb) < DB_NAME_LEN)
			(void) strcpy(msgfile, Msgdb);
		else {
			char *p;
			p = (char *)setcat((const char *)0);
			if ((p != NULL) && strlen(p) < DB_NAME_LEN)
				(void) strcpy(msgfile, p);
			else
				return (handle_return(dflt_str));
		}
	}
	while (*++tokp)
		if (!isdigit(*tokp))
			return (handle_return(dflt_str));
	msgnum = atoi(msg_id + name_len + 1);

	/* Has locale been changed? */

	curloc = setlocale(LC_MESSAGES, NULL);
	if (saved_locale != NULL && strcmp(curloc, saved_locale) == 0) {
		for (i = 0; i < db_count; i++)
			if (strcmp(db_info[i].db_name, msgfile) == 0)
				break;
	} else { /* new locale - clear everything */
		if (saved_locale)
			free(saved_locale);
		/*
		 * allocate at least 2 bytes, so that we can copy "C"
		 * without re-allocating the saved_locale.
		 */
		if ((saved_locale = malloc(strlen(curloc)+2)) == NULL)
			return (handle_return(dflt_str));
		(void) strcpy(saved_locale, curloc);
		for (i = 0; i < db_count; i++) {
			(void) munmap((void *)db_info[i].addr,
			    db_info[i].length);
			(void) strcpy(db_info[i].db_name, "");
			new_locale++;
		}
		db_count = 0;
	}
	if (new_locale || i == db_count) {
		if (db_count == MAXDB)
			return (handle_return(dflt_str));
		if (snprintf(pathname, sizeof (pathname),
			_DFLT_LOC_PATH "%s" MESSAGES "%s",
			saved_locale, msgfile) >= sizeof (pathname)) {
			return (handle_return(dflt_str));
		}
		if ((fd = open(pathname, O_RDONLY)) == -1 ||
			fstat64(fd, &sb) == -1 ||
				(addr = mmap(0, (size_t)sb.st_size,
					PROT_READ, MAP_SHARED,
						fd, 0)) == MAP_FAILED) {
			if (fd != -1)
				(void) close(fd);
			if (strcmp(saved_locale, "C") == 0)
				return (handle_return(dflt_str));

			/* Change locale to C */

			if (snprintf(pathname, sizeof (pathname),
				_DFLT_LOC_PATH "C" MESSAGES "%s",
				msgfile) >= sizeof (pathname)) {
				return (handle_return(dflt_str));
			}

			for (i = 0; i < db_count; i++) {
				(void) munmap((void *)db_info[i].addr,
							db_info[i].length);
				(void) strcpy(db_info[i].db_name, "");
			}
			db_count = 0;
			if ((fd = open(pathname, O_RDONLY)) != -1 &&
				fstat64(fd, &sb) != -1 &&
					(addr = mmap(0, (size_t)sb.st_size,
						PROT_READ, MAP_SHARED,
						fd, 0)) != MAP_FAILED) {
				(void) strcpy(saved_locale, "C");
			} else {
				if (fd != -1)
					(void) close(fd);
				return (handle_return(dflt_str));
			}
		}
		if (fd != -1)
			(void) close(fd);

		/* save file name, memory address, fd and size */

		(void) strcpy(db_info[db_count].db_name, msgfile);
		db_info[db_count].addr = (uintptr_t)addr;
		db_info[db_count].length = (size_t)sb.st_size;
		i = db_count;
		db_count++;
	}
	/* check if msgnum out of domain */
	if (msgnum <= 0 || msgnum > *(int *)(db_info[i].addr))
		return (handle_return(dflt_str));
	/* return pointer to message */
	return ((char *)(db_info[i].addr + *(int *)(db_info[i].addr
		+ msgnum * sizeof (int))));
}

char *
handle_return(const char *dflt_str)
{
	return ((char *)(dflt_str && *dflt_str ? dflt_str : not_found));
}
