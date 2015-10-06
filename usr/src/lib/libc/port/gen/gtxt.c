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

/* __gtxt(): Common part to gettxt() and pfmt()	*/

#pragma	weak _setcat = setcat

#include "lint.h"
#include "libc.h"
#include <mtlib.h>
#include <sys/types.h>
#include <string.h>
#include <locale.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <synch.h>
#include <pfmt.h>
#include <thread.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include "../i18n/_locale.h"
#include "../i18n/_loc_path.h"

#define	MESSAGES "/LC_MESSAGES/"
static const char *def_locale = "C";
static const char *not_found = "Message not found!!\n";
static struct db_info *db_info;
static int db_count, maxdb;

struct db_info {
	char	db_name[DB_NAME_LEN];	/* Name of the message file */
	uintptr_t	addr;		/* Virtual memory address   */
	size_t	length;
	char	*saved_locale;
	char	flag;
};

#define	DB_EXIST	1		/* The catalogue exists	   */
#define	DB_OPEN		2		/* Already tried to open   */

/* Minimum number of open catalogues */
#define	MINDB		3

char cur_cat[DB_NAME_LEN];
rwlock_t _rw_cur_cat = DEFAULTRWLOCK;


/*
 * setcat(cat): Specify the default catalogue.
 * Return a pointer to the local copy of the default catalogue
 */
const char *
setcat(const char *cat)
{
	lrw_wrlock(&_rw_cur_cat);
	if (cat) {
		if (((strchr(cat, '/') != NULL)) ||
		    ((strchr(cat, ':') != NULL))) {
			cur_cat[0] = '\0';
			goto out;
		}
		(void) strncpy(cur_cat, cat, sizeof (cur_cat) - 1);
		cur_cat[sizeof (cur_cat) - 1] = '\0';
	}
out:
	lrw_unlock(&_rw_cur_cat);
	return (cur_cat[0] ? cur_cat : NULL);
}

/*
 * load a message catalog which specified with current locale,
 * and catalog name.
 */
static struct db_info *
load_db(const char *curloc, const char *catname, int *err)
{
	char pathname[PATH_MAX];
	struct	stat64 sb;
	caddr_t	addr;
	struct db_info *db;
	int fd;
	int i;

	*err = 0;

	/* First time called, allocate space */
	if (!db_info) {
		if ((db_info =
		    libc_malloc(MINDB * sizeof (struct db_info))) == NULL) {
			*err = 1;
			return (NULL);
		}
		maxdb = MINDB;
	}

	for (i = 0; i < db_count; i++) {
		if (db_info[i].flag == 0)
			break;
	}
	/* New catalogue */
	if (i == db_count) {
		if (db_count == maxdb) {
			if ((db = libc_realloc(db_info,
			    ++maxdb * sizeof (struct db_info))) == NULL) {
				*err = 1;
				return (NULL);
			}
			db_info = db;
		}
		db_count++;
	}
	db = &db_info[i];
	db->flag = 0;
	(void) strcpy(db->db_name, catname);
	db->saved_locale = libc_strdup(curloc);
	if (db->saved_locale == NULL) {
		*err = 1;
		return (NULL);
	}
	db->flag = DB_OPEN;
	if (snprintf(pathname, sizeof (pathname),
	    _DFLT_LOC_PATH "%s" MESSAGES "%s",
	    db->saved_locale, db->db_name) >= sizeof (pathname)) {
		/*
		 * We won't set err here, because an invalid locale is not
		 * the fatal condition, but we can fall back to "C"
		 * locale.
		 */
		return (NULL);
	}
	if ((fd = open(pathname, O_RDONLY)) != -1 &&
	    fstat64(fd, &sb) != -1 &&
	    (addr = mmap(0, (size_t)sb.st_size, PROT_READ, MAP_SHARED,
	    fd, 0)) != MAP_FAILED) {
		db->flag |= DB_EXIST;
		db->addr = (uintptr_t)addr;
		db->length = (size_t)sb.st_size;
	}
	if (fd != -1)
		(void) close(fd);
	return (db);
}

/*
 * unmap the message catalog, and release the db_info slot.
 */
static void
unload_db(struct db_info *db)
{
	if ((db->flag & (DB_OPEN|DB_EXIST)) ==
	    (DB_OPEN|DB_EXIST)) {
		(void) munmap((caddr_t)db->addr, db->length);
	}
	db->flag = 0;
	if (db->saved_locale)
		libc_free(db->saved_locale);
	db->saved_locale = NULL;
}

/*
 * go through the db_info, and find out a db_info slot regarding
 * the given current locale and catalog name.
 * If db is not NULL, then search will start from top of the array,
 * otherwise it will start from the next of given db.
 * If curloc is set to NULL, then return a cache without regards of
 * locale.
 */
static struct db_info *
lookup_cache(struct db_info *db, const char *curloc, const char *catname)
{
	if (db_info == NULL)
		return (NULL);

	if (db == NULL)
		db = db_info;
	else
		db++;

	for (; db < &db_info[db_count]; db++) {
		if (db->flag == 0)
			continue;
		if (strcmp(db->db_name, catname) == 0) {
			if (curloc == NULL ||
			    (db->saved_locale != NULL &&
			    strcmp(db->saved_locale, curloc) == 0)) {
				return (db);
			}
		}
	}
	return (NULL);
}

static int
valid_msg(struct db_info *db, int id)
{
	if (db == NULL || (db->flag & DB_EXIST) == 0)
		return (0);

	/* catalog has been loaded */
	if (id != 0 && id <= *(int *)(db->addr))
		return (1);

	/* not a valid id */
	return (0);
}

static char *
msg(struct db_info *db, int id)
{
	return ((char *)(db->addr + *(int *)(db->addr +
	    id * sizeof (int))));
}

/*
 * __gtxt(catname, id, dflt): Return a pointer to a message.
 *	catname is the name of the catalog. If null, the default catalog is
 *		used.
 *	id is the numeric id of the message in the catalogue
 *	dflt is the default message.
 *
 *	Information about non-existent catalogues is kept in db_info, in
 *	such a way that subsequent calls with the same catalogue do not
 *	try to open the catalogue again.
 */
const char *
__gtxt(const char *catname, int id, const char *dflt)
{
	char	*curloc;
	struct db_info *db;
	int	err;
	locale_t loc;

	/* Check for invalid message id */
	if (id < 0)
		return (not_found);
	if (id == 0)
		return ((dflt && *dflt) ? dflt : not_found);

	/*
	 * If catalogue is unspecified, use default catalogue.
	 * No catalogue at all is an error
	 */
	if (!catname || !*catname) {
		lrw_rdlock(&_rw_cur_cat);
		if (cur_cat == NULL || !*cur_cat) {
			lrw_unlock(&_rw_cur_cat);
			return (not_found);
		}
		catname = cur_cat;
		lrw_unlock(&_rw_cur_cat);
	}

	loc = uselocale(NULL);
	curloc = current_locale(loc, LC_MESSAGES);

	/* First look up the cache */
	db = lookup_cache(NULL, curloc, catname);
	if (db != NULL) {
		/*
		 * The catalog has been loaded, and if id seems valid,
		 * then just return.
		 */
		if (valid_msg(db, id))
			return (msg(db, id));

		/*
		 * seems given id is out of bound or does not exist. In this
		 * case, we need to look up a message for the "C" locale as
		 * documented in the man page.
		 */
		db = lookup_cache(NULL, def_locale, catname);
		if (db == NULL) {
			/*
			 * Even the message catalog for the "C" has not been
			 * loaded.
			 */
			db = load_db(def_locale, catname, &err);
			if (err)
				return (not_found);
		}
		if (valid_msg(db, id))
			return (msg(db, id));
		/* no message found */
		return ((dflt && *dflt) ? dflt : not_found);
	}

	/*
	 * The catalog has not been loaded or even has not
	 * attempted to be loaded, invalidate all caches related to
	 * the catname for possibly different locale.
	 */
	db = NULL;
	while ((db = lookup_cache(db, NULL, catname)) != NULL)
		unload_db(db);

	/*
	 * load a message catalog for the requested locale.
	 */
	db = load_db(curloc, catname, &err);
	if (err)
		return (not_found);
	if (valid_msg(db, id))
		return (msg(db, id));

	/*
	 * If the requested catalog is either not exist or message
	 * id is invalid, then try to load from "C" locale.
	 */
	db = load_db(def_locale, catname, &err);
	if (err)
		return (not_found);

	if (valid_msg(db, id))
		return (msg(db, id));

	/* no message found */
	return ((dflt && *dflt) ? dflt : not_found);
}
