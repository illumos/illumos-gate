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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Code to maintain the runtime and on-disk filehandle mapping table for
 * nfslog.
 */

#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include <nfs/nfs.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>
#include <dirent.h>
#include <ndbm.h>
#include <time.h>
#include <libintl.h>
#include <sys/types.h>
#include <nfs/nfs.h>
#include <nfs/nfs_log.h>
#include "fhtab.h"
#include "nfslogd.h"

#define	ROUNDUP32(val)		(((val) + 3) & ~3)

/*
 * It is important that this string not match the length of the
 * file handle key length NFS_FHMAXDATA
 */
#define	DB_VERSION_STRING	"NFSLOG_DB_VERSION"
#define	DB_VERSION		"1"

#define	MAX_PRUNE_REC_CNT	100000

fhandle_t	public_fh = { 0 };

struct db_list {
	fsid_t		fsid;		/* filesystem fsid */
	char		*path;		/* dbm filepair path */
	DBM		*db;		/* open dbm database */
	bool_t		getall;		/* TRUE if all dbm for prefix open */
	struct db_list	*next;		/* next db */
};

static struct db_list *db_fs_list = NULL;
static	char	err_str[] = "DB I/O error has occurred";
struct link_keys {
	fh_secondary_key	lnkey;
	int			lnsize;
	struct link_keys	*next;
};
extern int debug;
extern time_t mapping_update_interval;
extern time_t prune_timeout;

static int fill_link_key(char *linkkey, fhandle_t *dfh, char *name);
static struct db_list *db_get_db(char *fhpath, fsid_t *fsid, int *errorp,
	int create_flag);
static struct db_list *db_get_all_databases(char *fhpath, bool_t getall);
static void debug_print_fhlist(FILE *fp, fhlist_ent *fhrecp);
static void debug_print_linkinfo(FILE *fp, linkinfo_ent *fhrecp);
static void debug_print_key(FILE *fp, char *str1, char *str2, char *key,
	int ksize);
static void debug_print_key_and_data(FILE *fp, char *str1, char *str2,
	char *key, int ksize, char *data, int dsize);
static int store_record(struct db_list *dbp, void *keyaddr, int keysize,
	void *dataaddr, int datasize, char *str);
static void *fetch_record(struct db_list *dbp, void *keyaddr, int keysize,
	void *dataaddr, int *errorp, char *str);
static int delete_record(struct db_list *dbp, void *keyaddr, int keysize,
	char *str);
static int db_update_fhrec(struct db_list *dbp, void *keyaddr, int keysize,
	fhlist_ent *fhrecp, char *str);
static int db_update_linkinfo(struct db_list *dbp, void *keyaddr, int keysize,
	linkinfo_ent *linkp, char *str);
static fhlist_ent *create_primary_struct(struct db_list *dbp, fhandle_t *dfh,
	char *name, fhandle_t *fh, uint_t flags, fhlist_ent *fhrecp,
	int *errorp);
static fhlist_ent *db_add_primary(struct db_list *dbp, fhandle_t *dfh,
	char *name, fhandle_t *fh, uint_t flags, fhlist_ent *fhrecp,
	int *errorp);
static linkinfo_ent *get_next_link(struct db_list *dbp, char *linkkey,
	int *linksizep, linkinfo_ent *linkp, void **cookiep,
	int *errorp, char *msg);
static void free_link_cookies(void *cookie);
static void add_mc_path(struct db_list *dbp, fhandle_t *dfh, char *name,
	fhlist_ent *fhrecp, linkinfo_ent *linkp, int *errorp);
static linkinfo_ent *create_link_struct(struct db_list *dbp, fhandle_t *dfh,
	char *name, fhlist_ent *fhrecp, int *errorp);
static int db_add_secondary(struct db_list *dbp, fhandle_t *dfh, char *name,
	fhandle_t *fh, fhlist_ent *fhrecp);
static linkinfo_ent *update_next_link(struct db_list *dbp, char *nextkey,
	int nextsize, char *prevkey, int prevsize, int *errorp);
static int update_prev_link(struct db_list *dbp, char *nextkey, int nextsize,
	char *prevkey, int prevsize);
static linkinfo_ent *update_linked_list(struct db_list *dbp, char *nextkey,
	int nextsize, char *prevkey, int prevsize, int *errorp);
static int db_update_primary_new_head(struct db_list *dbp,
	linkinfo_ent *dellinkp, linkinfo_ent *nextlinkp, fhlist_ent *fhrecp);
static int delete_link_by_key(struct db_list *dbp, char *linkkey,
	int *linksizep, int *errorp, char *errstr);
static int delete_link(struct db_list *dbp, fhandle_t *dfh, char *name,
	char *nextlinkkey, int *nextlinksizep, int *errorp, char *errstr);

/*
 * The following functions do the actual database I/O. Currently use DBM.
 */

/*
 * The "db_*" functions are functions that access the database using
 * database-specific calls. Currently the only database supported is
 * dbm. Because of the limitations of this database, in particular when
 * it comes to manipulating records with the same key, or using multiple keys,
 * the following design decisions have been made:
 *
 *	Each file system has a separate dbm file, which are kept open as
 *		accessed, listed in a linked list.
 *	Two possible access mode are available for each file - either by
 *		file handle, or by directory file handle and name. Since
 *		dbm does not allow multiple keys, we will have a primary
 *		and secondary key for each file/link.
 *	The primary key is the pair (inode,gen) which can be obtained
 *		from the file handle. This points to a record with
 *		the full file handle and the secondary key (dfh-key,name)
 *		for one of the links.
 *	The secondary key is the pair (dfh-key,name) where dfh-key is
 *		the primary key for the directory and the name is the
 *		link name. It points to a record that contains the primary
 *		key for the file and to the previous and next hard link
 *		found for this file (if they exist).
 *
 * Summary of operations:
 *	Adding a new file: Create the primary record and secondary (link)
 *		record and add both to the database. The link record
 *		would have prev and next links set to NULL.
 *
 *	Adding a link to a file in the database: Add the link record,
 *		to the head of the links list (i.e. prev = NULL, next =
 *		secondary key recorded in the primary record). Update
 *		the primary record to point to the new link, and the
 *		secondary record for the old head of list to point to new.
 *
 *	Deleting a file: Delete the link record. If it is the last link
 *		then mark the primary record as deleted but don't delete
 *		that one from the database (in case some clients still
 *		hold the file handle). If there are other links, and the
 *		deleted link is the head of the list (in the primary
 *		record), update the primary record with the new head.
 *
 *	Renaming a file: Add the new link and then delete the old one.
 *
 *	Lookup by file handle (read, write, lookup, etc.) - fetch primary rec.
 *	Lookup by dir info (delete, link, rename) - fetch secondary rec.
 *
 *	XXX NOTE: The code is written single-threaded. To make it multi-
 *	threaded, the following considerations must be made:
 *	1. Changes/access to the db list must be atomic.
 *	2. Changes/access for a specific file handle must be atomic
 *	   (example: deleting a link may affect up to 4 separate database
 *	   entries: the deleted link, the prev and next links if exist,
 *	   and the filehandle entry, if it points to the deleted link -
 *	   these changes must be atomic).
 */

/*
 * Create a link key given directory fh and name
 */
static int
fill_link_key(char *linkkey, fhandle_t *dfh, char *name)
{
	int	linksize, linksize32;

	(void) memcpy(linkkey, &dfh->fh_data, dfh->fh_len);
	(void) strcpy(&linkkey[dfh->fh_len], name);
	linksize = dfh->fh_len + strlen(name) + 1;
	linksize32 = ROUNDUP32(linksize);
	if (linksize32 > linksize)
		bzero(&linkkey[linksize], linksize32 - linksize);
	return (linksize32);
}

/*
 * db_get_db - gets the database for the filesystem, or creates one
 * if none exists. Return the pointer for the database in *dbpp if success.
 * Return 0 for success, error code otherwise.
 */
static struct db_list *
db_get_db(char *fhpath, fsid_t *fsid, int *errorp, int create_flag)
{
	struct db_list	*p, *newp;
	char		fsidstr[30];
	datum		key, data;

	*errorp = 0;
	for (p = db_fs_list;
		(p != NULL) && memcmp(&p->fsid, fsid, sizeof (*fsid));
		p = p->next);
	if (p != NULL) {
		/* Found it */
		return (p);
	}
	/* Create it */
	if ((newp = calloc(1, sizeof (*newp))) == NULL) {
		*errorp = errno;
		syslog(LOG_ERR, gettext(
			"db_get_db: malloc db failed: Error %s"),
			strerror(*errorp));
		return (NULL);
	}
	(void) sprintf(fsidstr, "%08x%08x", fsid->val[0], fsid->val[1]);
	if ((newp->path = malloc(strlen(fhpath) + 2 + strlen(fsidstr)))
		== NULL) {
		*errorp = errno;
		syslog(LOG_ERR, gettext(
			"db_get_db: malloc dbpath failed: Error %s"),
			strerror(*errorp));
		goto err_exit;
	}
	(void) sprintf(newp->path, "%s.%s", fhpath, fsidstr);
	/*
	 * The open mode is masked by UMASK.
	 */
	if ((newp->db = dbm_open(newp->path, create_flag | O_RDWR, 0666))
		== NULL) {
		*errorp = errno;
		syslog(LOG_ERR, gettext(
			"db_get_db: dbm_open db '%s' failed: Error %s"),
			newp->path, strerror(*errorp));
		if (*errorp == 0)	/* should not happen but may */
			*errorp = -1;
		goto err_exit;
	}
	/*
	 * Add the version identifier (have to check first in the
	 * case the db exists)
	 */
	key.dptr = DB_VERSION_STRING;
	key.dsize = strlen(DB_VERSION_STRING);
	data = dbm_fetch(newp->db, key);
	if (data.dptr == NULL) {
		data.dptr = DB_VERSION;
		data.dsize = strlen(DB_VERSION);
		(void) dbm_store(newp->db, key, data, DBM_INSERT);
	}

	(void) memcpy(&newp->fsid, fsid, sizeof (*fsid));
	newp->next = db_fs_list;
	db_fs_list = newp;
	if (debug > 1) {
		(void) printf("db_get_db: db %s opened\n", newp->path);
	}
	return (newp);

err_exit:
	if (newp != NULL) {
		if (newp->db != NULL) {
			dbm_close(newp->db);
		}
		if (newp->path != NULL) {
			free(newp->path);
		}
		free(newp);
	}
	return (NULL);
}

/*
 * db_get_all_databases - gets the database for any filesystem. This is used
 * when any database will do - typically to retrieve the path for the
 * public filesystem. If any database is open - return the first one,
 * otherwise, search for it using fhpath. If getall is TRUE, open all
 * matching databases, and mark them (to indicate that all such were opened).
 * Return the pointer for a matching database if success.
 */
static struct db_list *
db_get_all_databases(char *fhpath, bool_t getall)
{
	char		*dirptr, *fhdir, *fhpathname;
	int		len, error;
	DIR		*dirp;
	struct dirent	*dp;
	fsid_t		fsid;
	struct db_list	*dbp, *ret_dbp;

	for (dbp = db_fs_list; dbp != NULL; dbp = dbp->next) {
		if (strncmp(fhpath, dbp->path, strlen(fhpath)) == 0)
			break;
	}
	if (dbp != NULL) {
		/*
		 * if one database for that prefix is open, and  either only
		 * one is needed, or already opened all such databases,
		 * return here without exhaustive search
		 */
		if (!getall || dbp->getall)
			return (dbp);
	}
	if ((fhdir = strdup(fhpath)) == NULL) {
		syslog(LOG_ERR, gettext(
			"db_get_all_databases: strdup '%s' Error '%s*'"),
			fhpath, strerror(errno));
		return (NULL);
	}
	fhpathname = NULL;
	ret_dbp = NULL;
	if ((dirptr = strrchr(fhdir, '/')) == NULL) {
		/* no directory */
		goto exit;
	}
	if ((fhpathname = strdup(&dirptr[1])) == NULL) {
		syslog(LOG_ERR, gettext(
			"db_get_all_databases: strdup '%s' Error '%s*'"),
			&dirptr[1], strerror(errno));
		goto exit;
	}
	/* Terminate fhdir string at last '/' */
	dirptr[1] = '\0';
	/* Search the directory */
	if (debug > 2) {
		(void) printf("db_get_all_databases: search '%s' for '%s*'\n",
			fhdir, fhpathname);
	}
	if ((dirp = opendir(fhdir)) == NULL) {
		syslog(LOG_ERR, gettext(
			"db_get_all_databases: opendir '%s' Error '%s*'"),
			fhdir, strerror(errno));
		goto exit;
	}
	len = strlen(fhpathname);
	while ((dp = readdir(dirp)) != NULL) {
		if (strncmp(fhpathname, dp->d_name, len) == 0) {
			dirptr = &dp->d_name[len + 1];
			if (*(dirptr - 1) != '.') {
				continue;
			}
			(void) sscanf(dirptr, "%08lx%08lx",
			    (ulong_t *)&fsid.val[0], (ulong_t *)&fsid.val[1]);
			dbp = db_get_db(fhpath, &fsid, &error, 0);
			if (dbp != NULL) {
				ret_dbp = dbp;
				if (!getall)
					break;
				dbp->getall = TRUE;
			}
		}
	}
	(void) closedir(dirp);
exit:
	if (fhpathname != NULL)
		free(fhpathname);
	if (fhdir != NULL)
		free(fhdir);
	return (ret_dbp);
}

static void
debug_print_key(FILE *fp, char *str1, char *str2, char *key, int ksize)
{
	(void) fprintf(fp, "%s: %s key (%d) ", str1, str2, ksize);
	debug_opaque_print(fp, key, ksize);
	/* may be inode,name - try to print the fields */
	if (ksize >= NFS_FHMAXDATA) {
		(void) fprintf(fp, ": inode ");
		debug_opaque_print(fp, &key[2], sizeof (int));
		(void) fprintf(fp, ", gen ");
		debug_opaque_print(fp, &key[2 + sizeof (int)], sizeof (int));
		if (ksize > NFS_FHMAXDATA) {
			(void) fprintf(fp, ", name '%s'", &key[NFS_FHMAXDATA]);
		}
	}
	(void) fprintf(fp, "\n");
}

static void
debug_print_linkinfo(FILE *fp, linkinfo_ent *linkp)
{
	if (linkp == NULL)
		return;
	(void) fprintf(fp, "linkinfo:\ndfh: ");
	debug_opaque_print(fp, (void *)&linkp->dfh, sizeof (linkp->dfh));
	(void) fprintf(fp, "\nname: '%s'", LN_NAME(linkp));
	(void) fprintf(fp, "\nmtime 0x%x, atime 0x%x, flags 0x%x, reclen %d\n",
		linkp->mtime, linkp->atime, linkp->flags, linkp->reclen);
	(void) fprintf(fp, "offsets: fhkey %d, name %d, next %d, prev %d\n",
		linkp->fhkey_offset, linkp->name_offset, linkp->next_offset,
		linkp->prev_offset);
	debug_print_key(fp, "fhkey", "", LN_FHKEY(linkp), LN_FHKEY_LEN(linkp));
	debug_print_key(fp, "next", "", LN_NEXT(linkp), LN_NEXT_LEN(linkp));
	debug_print_key(fp, "prev", "", LN_PREV(linkp), LN_PREV_LEN(linkp));
}

static void
debug_print_fhlist(FILE *fp, fhlist_ent *fhrecp)
{
	if (fhrecp == NULL)
		return;
	(void) fprintf(fp, "fhrec:\nfh: ");
	debug_opaque_print(fp, (void *)&fhrecp->fh, sizeof (fhrecp->fh));
	(void) fprintf(fp, "name '%s', dfh: ", fhrecp->name);
	debug_opaque_print(fp, (void *)&fhrecp->dfh, sizeof (fhrecp->dfh));
	(void) fprintf(fp, "\nmtime 0x%x, atime 0x%x, flags 0x%x, reclen %d\n",
		fhrecp->mtime, fhrecp->atime, fhrecp->flags, fhrecp->reclen);
}

static void
debug_print_key_and_data(FILE *fp, char *str1, char *str2, char *key,
	int ksize, char *data, int dsize)
{
	debug_print_key(fp, str1, str2, key, ksize);
	(void) fprintf(fp, " ==> (%p,%d)\n", (void *)data, dsize);
	if (ksize > NFS_FHMAXDATA) {
		linkinfo_ent inf;
		/* probably a link struct */
		(void) memcpy(&inf, data, sizeof (linkinfo_ent));
		debug_print_linkinfo(fp, &inf);
	} else if (ksize == NFS_FHMAXDATA) {
		fhlist_ent inf;
		/* probably an fhlist struct */
		(void) memcpy(&inf, data, sizeof (linkinfo_ent));
		debug_print_fhlist(fp, &inf);
	} else {
		/* don't know... */
		debug_opaque_print(fp, data, dsize);
	}
}

/*
 * store_record - store the record in the database and return 0 for success
 * or error code otherwise.
 */
static int
store_record(struct db_list *dbp, void *keyaddr, int keysize, void *dataaddr,
	int datasize, char *str)
{
	datum	key, data;
	int	error;
	char	*errfmt = "store_record: dbm_store failed, Error: %s\n";
	char	*err;

	errno = 0;
	key.dptr = keyaddr;
	key.dsize = keysize;
	data.dptr = dataaddr;
	data.dsize = datasize;

	if (debug > 2) {
		debug_print_key_and_data(stdout, str, "dbm_store:\n    ",
			key.dptr, key.dsize, data.dptr, data.dsize);
	}
	if (dbm_store(dbp->db, key, data, DBM_REPLACE) < 0) {
		/* Could not store */
		error = dbm_error(dbp->db);
		dbm_clearerr(dbp->db);

		if (error) {
			if (errno)
				err = strerror(errno);
			else {
				err = err_str;
				errno = EIO;
			}
		} else { /* should not happen but sometimes does */
			err = err_str;
			errno = -1;
		}
		if (debug) {
			debug_print_key(stderr, str, "store_record:"
				"dbm_store:\n", key.dptr, key.dsize);
			(void) fprintf(stderr, errfmt, err);
		} else
			syslog(LOG_ERR, gettext(errfmt), err);
		return (errno);
	}
	return (0);
}

/*
 * fetch_record - fetch the record from the database and return 0 for success
 * and errno for failure.
 * dataaddr is an optional valid address for the result. If dataaddr
 * is non-null, then that memory is already alloc'd. Else, alloc it, and
 * the caller must free the returned struct when done.
 */
static void *
fetch_record(struct db_list *dbp, void *keyaddr, int keysize, void *dataaddr,
	int *errorp, char *str)
{
	datum	key, data;
	char	*errfmt = "fetch_record: dbm_fetch failed, Error: %s\n";
	char	*err;

	errno = 0;
	*errorp = 0;
	key.dptr = keyaddr;
	key.dsize = keysize;

	data = dbm_fetch(dbp->db, key);
	if (data.dptr == NULL) {
		/* see if there is a database error */
		if (dbm_error(dbp->db)) {
			/* clear and report the database error */
			dbm_clearerr(dbp->db);
			*errorp = EIO;
			err = strerror(*errorp);
			syslog(LOG_ERR, gettext(errfmt), err);
		} else {
			/* primary record not in database */
			*errorp = ENOENT;
		}
		if (debug > 3) {
			err = strerror(*errorp);
			debug_print_key(stderr, str, "fetch_record:"
				"dbm_fetch:\n", key.dptr, key.dsize);
			(void) fprintf(stderr, errfmt, err);
		}
		return (NULL);
	}

	/* copy to local struct because dbm may return non-aligned pointers */
	if ((dataaddr == NULL) &&
	    ((dataaddr = malloc(data.dsize)) == NULL)) {
		*errorp = errno;
		syslog(LOG_ERR, gettext(
			"%s: dbm_fetch - malloc %ld: Error %s"),
			str, data.dsize, strerror(*errorp));
		return (NULL);
	}
	(void) memcpy(dataaddr, data.dptr, data.dsize);
	if (debug > 3) {
		debug_print_key_and_data(stdout, str, "fetch_record:"
			"dbm_fetch:\n", key.dptr, key.dsize,
			dataaddr, data.dsize);
	}
	*errorp = 0;
	return (dataaddr);
}

/*
 * delete_record - delete the record from the database and return 0 for success
 * or error code for failure.
 */
static int
delete_record(struct db_list *dbp, void *keyaddr, int keysize, char *str)
{
	datum	key;
	int	error = 0;
	char	*errfmt = "delete_record: dbm_delete failed, Error: %s\n";
	char	*err;

	errno = 0;
	key.dptr = keyaddr;
	key.dsize = keysize;

	if (debug > 2) {
		debug_print_key(stdout, str, "delete_record:"
			"dbm_delete:\n", key.dptr, key.dsize);
	}
	if (dbm_delete(dbp->db, key) < 0) {
		error = dbm_error(dbp->db);
		dbm_clearerr(dbp->db);

		if (error) {
			if (errno)
				err = strerror(errno);
			else {
				err = err_str;
				errno = EIO;
			}
		} else { /* should not happen but sometimes does */
			err = err_str;
			errno = -1;
		}
		if (debug) {
			debug_print_key(stderr, str, "delete_record:"
				"dbm_delete:\n", key.dptr, key.dsize);
			(void) fprintf(stderr, errfmt, err);
		} else
			syslog(LOG_ERR, gettext(errfmt), err);
	}
	return (errno);
}

/*
 * db_update_fhrec - puts fhrec in db with updated atime if more than
 * mapping_update_interval seconds passed. Return 0 if success, error otherwise.
 */
static int
db_update_fhrec(struct db_list *dbp, void *keyaddr, int keysize,
	fhlist_ent *fhrecp, char *str)
{
	time_t	cur_time = time(0);

	if (difftime(cur_time, fhrecp->atime) >= mapping_update_interval) {
		fhrecp->atime = cur_time;
		return (store_record(dbp, keyaddr, keysize,
				fhrecp, fhrecp->reclen, str));
	}
	return (0);
}

/*
 * db_update_linkinfo - puts linkinfo in db with updated atime if more than
 * mapping_update_interval seconds passed. Return 0 if success, error otherwise.
 */
static int
db_update_linkinfo(struct db_list *dbp, void *keyaddr, int keysize,
	linkinfo_ent *linkp, char *str)
{
	time_t	cur_time = time(0);

	if (difftime(cur_time, linkp->atime) >= mapping_update_interval) {
		linkp->atime = cur_time;
		return (store_record(dbp, keyaddr, keysize,
				linkp, linkp->reclen, str));
	}
	return (0);
}

/*
 * create_primary_struct - add primary record to the database.
 * Database must be open when this function is called.
 * If success, return the added database entry. fhrecp may be used to
 * provide an existing memory area, else malloc it. If failed, *errorp
 * contains the error code and return NULL.
 */
static fhlist_ent *
create_primary_struct(struct db_list *dbp, fhandle_t *dfh, char *name,
	fhandle_t *fh, uint_t flags, fhlist_ent *fhrecp, int *errorp)
{
	int		reclen, reclen1;
	fhlist_ent	*new_fhrecp = fhrecp;

	reclen1 = offsetof(fhlist_ent, name) + strlen(name) + 1;
	reclen = ROUNDUP32(reclen1);
	if (fhrecp == NULL) {	/* allocated the memory */
		if ((new_fhrecp = malloc(reclen)) == NULL) {
			*errorp = errno;
			syslog(LOG_ERR, gettext(
				"create_primary_struct: malloc %d Error %s"),
				reclen, strerror(*errorp));
			return (NULL);
		}
	}
	/* Fill in the fields */
	(void) memcpy(&new_fhrecp->fh, fh, sizeof (*fh));
	(void) memcpy(&new_fhrecp->dfh, dfh, sizeof (*dfh));
	new_fhrecp->flags = flags;
	if (dfh == &public_fh)
		new_fhrecp->flags |= PUBLIC_PATH;
	else
		new_fhrecp->flags &= ~PUBLIC_PATH;
	new_fhrecp->mtime = time(0);
	new_fhrecp->atime = new_fhrecp->mtime;
	(void) strcpy(new_fhrecp->name, name);
	if (reclen1 < reclen) {
		bzero((char *)((uintptr_t)new_fhrecp + reclen1),
			reclen - reclen1);
	}
	new_fhrecp->reclen = reclen;
	*errorp = store_record(dbp, &fh->fh_data, fh->fh_len, new_fhrecp,
			new_fhrecp->reclen, "create_primary_struct");
	if (*errorp != 0) {
		/* Could not store */
		if (fhrecp == NULL)	/* caller did not supply pointer */
			free(new_fhrecp);
		return (NULL);
	}
	return (new_fhrecp);
}

/*
 * db_add_primary - add primary record to the database.
 * If record already in and live, return it (even if for a different link).
 * If in database but marked deleted, replace it. If not in database, add it.
 * Database must be open when this function is called.
 * If success, return the added database entry. fhrecp may be used to
 * provide an existing memory area, else malloc it. If failed, *errorp
 * contains the error code and return NULL.
 */
static fhlist_ent *
db_add_primary(struct db_list *dbp, fhandle_t *dfh, char *name, fhandle_t *fh,
	uint_t flags, fhlist_ent *fhrecp, int *errorp)
{
	fhlist_ent	*new_fhrecp;
	fh_primary_key	fhkey;

	if (debug > 2)
		(void) printf("db_add_primary entered: name '%s'\n", name);

	bcopy(&fh->fh_data, fhkey, fh->fh_len);
	new_fhrecp = fetch_record(dbp, fhkey, fh->fh_len, (void *)fhrecp,
			errorp, "db_add_primary");
	if (new_fhrecp != NULL) {
		/* primary record is in the database */
		/* Update atime if needed */
		*errorp = db_update_fhrec(dbp, fhkey, fh->fh_len, new_fhrecp,
				"db_add_primary put fhrec");
		if (debug > 2)
			(void) printf("db_add_primary exits(2): name '%s'\n",
				name);
		return (new_fhrecp);
	}
	/* primary record not in database - create it */
	new_fhrecp = create_primary_struct(dbp, dfh, name, fh, flags,
			fhrecp, errorp);
	if (new_fhrecp == NULL) {
		/* Could not store */
		if (debug > 2)
			(void) printf(
				"db_add_primary exits(1): name '%s' Error %s\n",
				name, ((*errorp >= 0) ? strerror(*errorp) :
					"Unknown"));

		return (NULL);
	}
	if (debug > 2)
		(void) printf("db_add_primary exits(0): name '%s'\n", name);
	return (new_fhrecp);
}

/*
 * get_next_link - get and check the next link in the chain.
 * Re-use space if linkp param non-null. Also set *linkkey and *linksizep
 * to values for next link (*linksizep set to 0 if last link).
 * cookie is used to detect corrupted link entries XXXXXXX
 * Return the link pointer or NULL if none.
 */
static linkinfo_ent *
get_next_link(struct db_list *dbp, char *linkkey, int *linksizep,
	linkinfo_ent *linkp, void **cookiep, int *errorp, char *msg)
{
	int	linksize, nextsize;
	char	*nextkey;
	linkinfo_ent *new_linkp = linkp;
	struct link_keys *lnp;

	linksize = *linksizep;
	if (linksize == 0)
		return (NULL);
	*linksizep = 0;
	new_linkp = fetch_record(dbp, linkkey, linksize, (void *)linkp,
			errorp, msg);
	if (new_linkp == NULL)
		return (NULL);

	/* Set linkkey to point to next record */
	nextsize = LN_NEXT_LEN(new_linkp);
	if (nextsize == 0)
		return (new_linkp);

	/* Add this key to the cookie list */
	if ((lnp = malloc(sizeof (struct link_keys))) == NULL) {
		syslog(LOG_ERR, gettext("get_next_key: malloc error %s\n"),
			strerror(errno));
		if ((new_linkp != NULL) && (linkp == NULL))
			free(new_linkp);
		return (NULL);
	}
	(void) memcpy(lnp->lnkey, linkkey, linksize);
	lnp->lnsize = linksize;
	lnp->next = *(struct link_keys **)cookiep;
	*cookiep = (void *)lnp;

	/* Make sure record does not point to itself or other internal loops */
	nextkey = LN_NEXT(new_linkp);
	for (; lnp != NULL; lnp = lnp->next) {
		if ((nextsize == lnp->lnsize) && (memcmp(
			lnp->lnkey, nextkey, nextsize) == 0)) {

			/*
			 * XXX This entry's next pointer points to
			 * itself. This is only a work-around, remove
			 * this check once bug 4203186 is fixed.
			 */
			if (debug) {
				(void) fprintf(stderr,
				"%s: get_next_link: last record invalid.\n",
					msg);
				debug_print_key_and_data(stderr, msg,
					"invalid rec:\n ", linkkey, linksize,
					(char *)new_linkp, new_linkp->reclen);
			}
			/* Return as if this is the last link */
			return (new_linkp);
		}
	}
	(void) memcpy(linkkey, nextkey, nextsize);
	*linksizep = nextsize;
	return (new_linkp);
}

/*
 * free_link_cookies - free the cookie list
 */
static void
free_link_cookies(void *cookie)
{
	struct link_keys *dellnp, *lnp;

	lnp = (struct link_keys *)cookie;
	while (lnp != NULL) {
		dellnp = lnp;
		lnp = lnp->next;
		free(dellnp);
	}
}

/*
 * add_mc_path - add a mc link to a file that has other links. Add it at end
 * of linked list. Called when it's known there are other links.
 */
static void
add_mc_path(struct db_list *dbp, fhandle_t *dfh, char *name,
	fhlist_ent *fhrecp, linkinfo_ent *linkp, int *errorp)
{
	fh_secondary_key	linkkey;
	int			linksize, len;
	linkinfo_ent		lastlink, *lastlinkp;
	void			*cookie;

	linksize = fill_link_key(linkkey, &fhrecp->dfh, fhrecp->name);
	cookie = NULL;
	do {
		lastlinkp = get_next_link(dbp, linkkey, &linksize, &lastlink,
				&cookie, errorp, "add_mc_path");
	} while (linksize > 0);
	free_link_cookies(cookie);
	/* reached end of list */
	if (lastlinkp == NULL) {
		/* nothing to do */
		if (debug > 1) {
			(void) fprintf(stderr, "add_mc_path link is null\n");
		}
		return;
	}
	/* Add new link after last link */
	/*
	 * next - link key for the next in the list - add at end so null.
	 * prev - link key for the previous link in the list.
	 */
	linkp->prev_offset = linkp->next_offset;	/* aligned */
	linksize = fill_link_key(LN_PREV(linkp), &lastlinkp->dfh,
				LN_NAME(lastlinkp));
	linkp->reclen = linkp->prev_offset + linksize;	/* aligned */

	/* Add the link information to the database */
	linksize = fill_link_key(linkkey, dfh, name);
	*errorp = store_record(dbp, linkkey, linksize,
			linkp, linkp->reclen, "add_mc_path");
	if (*errorp != 0)
		return;

	/* Now update previous last link to point forward to new link */
	/* Copy prev link out since it's going to be overwritten */
	linksize = LN_PREV_LEN(lastlinkp);
	(void) memcpy(linkkey, LN_PREV(lastlinkp), linksize);
	/* Update previous last link to point to new one */
	len = fill_link_key(LN_NEXT(lastlinkp), dfh, name);
	lastlinkp->prev_offset = lastlinkp->next_offset + len;	/* aligned */
	(void) memcpy(LN_PREV(lastlinkp), linkkey, linksize);
	lastlinkp->reclen = lastlinkp->prev_offset + linksize;
	/* Update the link information to the database */
	linksize = fill_link_key(linkkey, &lastlinkp->dfh, LN_NAME(lastlinkp));
	*errorp = store_record(dbp, linkkey, linksize,
			lastlinkp, lastlinkp->reclen, "add_mc_path prev");
}

/*
 * create_link_struct - create the secondary struct.
 * (dfh,name) is the secondary key, fhrec is the primary record for the file
 * and linkpp is a place holder for the record (could be null).
 * Insert the record to the database.
 * Return 0 if success, error otherwise.
 */
static linkinfo_ent *
create_link_struct(struct db_list *dbp, fhandle_t *dfh, char *name,
	fhlist_ent *fhrecp, int *errorp)
{
	fh_secondary_key	linkkey;
	int			len, linksize;
	linkinfo_ent		*linkp;

	if ((linkp = malloc(sizeof (linkinfo_ent))) == NULL) {
		*errorp = errno;
		syslog(LOG_ERR, gettext(
			"create_link_struct: malloc failed: Error %s"),
			strerror(*errorp));
		return (NULL);
	}
	if (dfh == &public_fh)
		linkp->flags |= PUBLIC_PATH;
	else
		linkp->flags &= ~PUBLIC_PATH;
	(void) memcpy(&linkp->dfh, dfh, sizeof (*dfh));
	linkp->mtime = time(0);
	linkp->atime = linkp->mtime;
	/* Calculate offsets of variable fields */
	/* fhkey - primary key (inode/gen) */
	/* name - component name (in directory dfh) */
	linkp->fhkey_offset = ROUNDUP32(offsetof(linkinfo_ent, varbuf));
	len = fill_link_key(LN_FHKEY(linkp), &fhrecp->fh, name);
	linkp->name_offset = linkp->fhkey_offset + fhrecp->fh.fh_len;
	linkp->next_offset = linkp->fhkey_offset + len;	/* aligned */
	/*
	 * next - link key for the next link in the list - NULL if it's
	 * the first link. If this is the public fs, only one link allowed.
	 * Avoid setting a multi-component path as primary path,
	 * unless no choice.
	 */
	len = 0;
	if (memcmp(&fhrecp->dfh, dfh, sizeof (*dfh)) ||
	    strcmp(fhrecp->name, name)) {
		/* different link than the one that's in the record */
		if (dfh == &public_fh) {
			/* parent is public fh - either multi-comp or root */
			if (memcmp(&fhrecp->fh, &public_fh,
				sizeof (public_fh))) {
				/* multi-comp path */
				add_mc_path(dbp, dfh, name, fhrecp, linkp,
						errorp);
				if (*errorp != 0) {
					free(linkp);
					return (NULL);
				}
				return (linkp);
			}
		} else {
			/* new link to a file with a different one already */
			len = fill_link_key(LN_NEXT(linkp), &fhrecp->dfh,
				fhrecp->name);
		}
	}
	/*
	 * prev - link key for the previous link in the list - since we
	 * always insert at the front of the list, it's always initially NULL.
	 */
	linkp->prev_offset = linkp->next_offset + len;	/* aligned */
	linkp->reclen = linkp->prev_offset;

	/* Add the link information to the database */
	linksize = fill_link_key(linkkey, dfh, name);
	*errorp = store_record(dbp, linkkey, linksize, linkp, linkp->reclen,
			"create_link_struct");
	if (*errorp != 0) {
		free(linkp);
		return (NULL);
	}
	return (linkp);
}

/*
 * db_add_secondary - add secondary record to the database (for the directory
 * information).
 * Assumes this is a new link, not yet in the database, and that the primary
 * record is already in.
 * If fhrecp is non-null, then fhrecp is the primary record.
 * Database must be open when this function is called.
 * Return 0 if success, error code otherwise.
 */
static int
db_add_secondary(struct db_list *dbp, fhandle_t *dfh, char *name,
	fhandle_t *fh, fhlist_ent *fhrecp)
{
	int			nextsize, len, error;
	linkinfo_ent		nextlink, *newlinkp, *nextlinkp;
	uint_t			fhflags;
	char			*nextaddr;
	fhlist_ent		*new_fhrecp = fhrecp;
	fh_primary_key		fhkey;

	if (debug > 2)
		(void) printf("db_add_secondary entered: name '%s'\n", name);

	bcopy(&fh->fh_data, fhkey, fh->fh_len);
	if (fhrecp == NULL) {
		/* Fetch the primary record */
		new_fhrecp = fetch_record(dbp, fhkey, fh->fh_len, NULL,
				&error, "db_add_secondary primary");
		if (new_fhrecp == NULL) {
			return (error);
		}
	}
	/* Update fhrec atime if needed */
	error = db_update_fhrec(dbp, fhkey, fh->fh_len, new_fhrecp,
			"db_add_secondary primary");
	fhflags = new_fhrecp->flags;
	/* now create and insert the secondary record */
	newlinkp = create_link_struct(dbp, dfh, name, new_fhrecp, &error);
	if (fhrecp == NULL) {
		free(new_fhrecp);
		new_fhrecp = NULL;
	}
	if (newlinkp == NULL) {
		if (debug > 2)
			(void) printf("create_link_struct '%s' Error %s\n",
				name, ((error >= 0) ? strerror(error) :
					"Unknown"));
		return (error);
	}
	nextsize = LN_NEXT_LEN(newlinkp);
	if (nextsize == 0) {
		/* No next - can exit now */
		if (debug > 2)
			(void) printf("db_add_secondary: no next link\n");
		free(newlinkp);
		return (0);
	}

	/*
	 * Update the linked list to point to new head: replace head of
	 * list in the primary record, then update previous secondary record
	 * to point to new head
	 */
	new_fhrecp = create_primary_struct(dbp, dfh, name, fh, fhflags,
			new_fhrecp, &error);
	if (new_fhrecp == NULL) {
		if (debug > 2)
			(void) printf(
				"db_add_secondary: replace primary failed\n");
		free(newlinkp);
		return (error);
	} else if (fhrecp == NULL) {
		free(new_fhrecp);
	}

	/*
	 * newlink is the new head of the list, with its "next" pointing to
	 * the old head, and its "prev" pointing to NULL. We now need to
	 * modify the "next" entry to have its "prev" point to the new entry.
	 */
	nextaddr = LN_NEXT(newlinkp);
	if (debug > 2) {
		debug_print_key(stderr, "db_add_secondary", "next key\n    ",
			nextaddr, nextsize);
	}
	/* Get the next link entry from the database */
	nextlinkp = fetch_record(dbp, nextaddr, nextsize, (void *)&nextlink,
			&error, "db_add_secondary next link");
	if (nextlinkp == NULL) {
		if (debug > 2)
			(void) printf(
				"db_add_secondary: fetch next link failed\n");
		free(newlinkp);
		return (error);
	}

	/*
	 * since the "prev" field is the only field to be changed, and it's
	 * the last in the link record, we only need to modify it (and reclen).
	 * Re-use link to update the next record.
	 */
	len = fill_link_key(LN_PREV(nextlinkp), dfh, name);
	nextlinkp->reclen = nextlinkp->prev_offset + len;
	error = store_record(dbp, nextaddr, nextsize, nextlinkp,
			nextlinkp->reclen, "db_add_secondary");
	if (debug > 2)
		(void) printf(
			"db_add_secondary exits(%d): name '%s'\n", error, name);
	free(newlinkp);
	return (error);
}

/*
 * Update the next link to point to the new prev.
 * Return 0 for success, error code otherwise.
 * If successful, and nextlinkpp is non-null,
 * *nextlinkpp contains the record for the next link, since
 * we may will it if the primary record should be updated.
 */
static linkinfo_ent *
update_next_link(struct db_list *dbp, char *nextkey, int nextsize,
	char *prevkey, int prevsize, int *errorp)
{
	linkinfo_ent	*nextlinkp, *linkp1;

	if ((nextlinkp = malloc(sizeof (linkinfo_ent))) == NULL) {
		*errorp = errno;
		syslog(LOG_ERR, gettext(
			"update_next_link: malloc next Error %s"),
			strerror(*errorp));
		return (NULL);
	}
	linkp1 = nextlinkp;
	nextlinkp = fetch_record(dbp, nextkey, nextsize, nextlinkp,
			errorp, "update next");
	/* if there is no next record - ok */
	if (nextlinkp == NULL) {
		/* Return no error */
		*errorp = 0;
		free(linkp1);
		return (NULL);
	}
	/* Set its prev to the prev of the deleted record */
	nextlinkp->reclen = ROUNDUP32(nextlinkp->reclen -
				LN_PREV_LEN(nextlinkp) + prevsize);
	/* Change the len and set prev */
	if (prevsize > 0) {
		(void) memcpy(LN_PREV(nextlinkp), prevkey, prevsize);
	}
	/* No other changes needed because prev is last field */
	*errorp = store_record(dbp, nextkey, nextsize, nextlinkp,
			nextlinkp->reclen, "update_next");
	if (*errorp != 0) {
		free(nextlinkp);
		nextlinkp = NULL;
	}
	return (nextlinkp);
}

/*
 * Update the prev link to point to the new next.
 * Return 0 for success, error code otherwise.
 */
static int
update_prev_link(struct db_list *dbp, char *nextkey, int nextsize,
	char *prevkey, int prevsize)
{
	linkinfo_ent	prevlink, *prevlinkp;
	int		diff, error;

	/* Update its next to the given one */
	prevlinkp = fetch_record(dbp, prevkey, prevsize, &prevlink, &error,
			"update prev");
	/* if error there is no next record - ok */
	if (prevlinkp == NULL) {
		return (0);
	}
	diff = nextsize - LN_NEXT_LEN(prevlinkp);
	prevlinkp->reclen = ROUNDUP32(prevlinkp->reclen + diff);
	/* Change the len and set next - may push prev */
	if (diff != 0) {
		char	*ptr = LN_PREV(prevlinkp);

		prevlinkp->prev_offset += diff;
		(void) memcpy(LN_PREV(prevlinkp), ptr, LN_PREV_LEN(prevlinkp));
	}
	if (nextsize > 0) {
		(void) memcpy(LN_NEXT(prevlinkp), nextkey, nextsize);
	}
	/* Store updated record */
	error = store_record(dbp, prevkey, prevsize, prevlinkp,
			prevlinkp->reclen, "update_prev");
	return (error);
}

/*
 * update_linked_list - update the next link to point back to prev, and vice
 * versa. Normally called by delete_link to drop the deleted link from the
 * linked list of hard links for the file. next and prev are the keys of next
 * and previous links for the deleted link in the list (could be NULL).
 * Return 0 for success, error code otherwise.
 * If successful, and nextlinkpp is non-null,
 * return the record for the next link, since
 * if the primary record should be updated we'll need it. In this case,
 * actually allocate the space for it because we can't tell otherwise.
 */
static linkinfo_ent *
update_linked_list(struct db_list *dbp, char *nextkey, int nextsize,
	char *prevkey, int prevsize, int *errorp)
{
	linkinfo_ent	*nextlinkp = NULL;

	*errorp = 0;
	if (nextsize > 0) {
		nextlinkp = update_next_link(dbp, nextkey, nextsize,
				prevkey, prevsize, errorp);
		if (nextlinkp == NULL) {
			/* not an error if no next link */
			if (*errorp != 0) {
				if (debug > 1) {
					(void) fprintf(stderr,
						"update_next_link Error %s\n",
					((*errorp >= 0) ? strerror(*errorp) :
						"Unknown"));
				}
				return (NULL);
			}
		}
	}
	if (prevsize > 0) {
		*errorp = update_prev_link(dbp, nextkey, nextsize,
				prevkey, prevsize);
		if (*errorp != 0) {
			if (debug > 1) {
				(void) fprintf(stderr,
					"update_prev_link Error %s\n",
					((*errorp >= 0) ? strerror(*errorp) :
					"Unknown"));
			}
			if (nextlinkp != NULL)
				free(nextlinkp);
			nextlinkp = NULL;
		}
	}
	return (nextlinkp);
}

/*
 * db_update_primary_new_head - Update a primary record that the head of
 * the list is deleted. Similar to db_add_primary, but the primary record
 * must exist, and is always replaced with one pointing to the new link,
 * unless it does not point to the deleted link. If the link we deleted
 * was the last link, the delete the primary record as well.
 * Return 0 for success, error code otherwise.
 */
static int
db_update_primary_new_head(struct db_list *dbp, linkinfo_ent *dellinkp,
	linkinfo_ent *nextlinkp, fhlist_ent *fhrecp)
{
	int			error;
	char			*name, *next_name;
	fhandle_t		*dfh;
	fh_primary_key		fhkey;

	dfh = &dellinkp->dfh;
	name = LN_NAME(dellinkp);
	/* If the deleted link was not the head of the list, we are done */
	if (memcmp(&fhrecp->dfh, dfh, sizeof (*dfh)) ||
	    strcmp(fhrecp->name, name)) {
		/* should never be here... */
		if (debug > 1) {
			(void) fprintf(stderr,
				"db_update_primary_new_head: primary "
				"is for [%s,", name);
			debug_opaque_print(stderr, (void *)dfh, sizeof (*dfh));
			(void) fprintf(stderr, "], not [%s,", fhrecp->name);
			debug_opaque_print(stderr, (void *)&fhrecp->dfh,
				sizeof (fhrecp->dfh));
			(void) fprintf(stderr, "]\n");
		}
		return (0);	/* not head of list so done */
	}
	/* Set the head to nextkey if exists. Otherwise, mark file as deleted */
	bcopy(&fhrecp->fh.fh_data, fhkey, fhrecp->fh.fh_len);
	if (nextlinkp == NULL) {
		/* last link */
		/* remove primary record from database */
		(void) delete_record(dbp,
			fhkey, fhrecp->fh.fh_len,
			"db_update_primary_new_head: fh delete");
		return (0);
	} else {
		/*
		 * There are still "live" links, so update the primary record.
		 */
		next_name = LN_NAME(nextlinkp);
		fhrecp->reclen = ROUNDUP32(offsetof(fhlist_ent, name) +
					strlen(next_name) + 1);
		/* Replace link data with the info for the next link */
		(void) memcpy(&fhrecp->dfh, &nextlinkp->dfh,
			sizeof (nextlinkp->dfh));
		(void) strcpy(fhrecp->name, next_name);
	}
	/* not last link */
	fhrecp->mtime = time(0);
	fhrecp->atime = fhrecp->mtime;
	error = store_record(dbp,
			fhkey, fhrecp->fh.fh_len, fhrecp,
			fhrecp->reclen, "db_update_primary_new_head: fh");
	return (error);
}

/*
 * Exported functions
 */

/*
 * db_add - add record to the database. If dfh, fh and name are all here,
 * add both primary and secondary records. If fh is not available, don't
 * add anything...
 * Assumes this is a new file, not yet in the database and that the record
 * for fh is already in.
 * Return 0 for success, error code otherwise.
 */
int
db_add(char *fhpath, fhandle_t *dfh, char *name, fhandle_t *fh, uint_t flags)
{
	struct db_list	*dbp = NULL;
	fhlist_ent	fhrec, *fhrecp;
	int		error = 0;

	if (fh == NULL) {
		/* nothing to add */
		return (EINVAL);
	}
	if (fh == &public_fh) {
		dbp = db_get_all_databases(fhpath, FALSE);
	} else {
		dbp = db_get_db(fhpath, &fh->fh_fsid, &error, O_CREAT);
	}
	for (; dbp != NULL; dbp = ((fh != &public_fh) ? NULL : dbp->next)) {
		if (debug > 3) {
			(void) printf("db_add: name '%s', db '%s'\n",
				name, dbp->path);
		}
		fhrecp = db_add_primary(dbp, dfh, name, fh, flags,
				&fhrec, &error);
		if (fhrecp == NULL) {
			continue;
		}
		if ((dfh == NULL) || (name == NULL)) {
			/* Can't add link information */
			syslog(LOG_ERR, gettext(
				"db_add: dfh %p, name %p - invalid"),
				(void *)dfh, (void *)name);
			error = EINVAL;
			continue;
		}
		if (fh == &public_fh) {
			while ((fhrecp != NULL) && strcmp(name, fhrecp->name)) {
				/* Replace the public fh rather than add link */
				error = db_delete_link(fhpath, dfh,
						fhrecp->name);
				fhrecp = db_add_primary(dbp, dfh, name, fh,
						flags, &fhrec, &error);
			}
			if (fhrecp == NULL) {
				continue;
			}
		}
		error = db_add_secondary(dbp, dfh, name, fh, fhrecp);
		if (fhrecp != &fhrec) {
			free(fhrecp);
		}
	}
	return (error);
}

/*
 * db_lookup - search the database for the file identified by fh.
 * Return the entry in *fhrecpp if found, or NULL with error set otherwise.
 */
fhlist_ent *
db_lookup(char *fhpath, fhandle_t *fh, fhlist_ent *fhrecp, int *errorp)
{
	struct db_list	*dbp;
	fh_primary_key	fhkey;

	if ((fhpath == NULL) || (fh == NULL) || (errorp == NULL)) {
		if (errorp != NULL)
			*errorp = EINVAL;
		return (NULL);
	}
	*errorp = 0;
	if (fh == &public_fh) {
		dbp = db_get_all_databases(fhpath, FALSE);
	} else {
		dbp = db_get_db(fhpath, &fh->fh_fsid, errorp, O_CREAT);
	}
	if (dbp == NULL) {
		/* Could not get or create database */
		return (NULL);
	}
	bcopy(&fh->fh_data, fhkey, fh->fh_len);
	fhrecp = fetch_record(dbp, fhkey, fh->fh_len, fhrecp,
			errorp, "db_lookup");
	/* Update fhrec atime if needed */
	if (fhrecp != NULL) {
		*errorp = db_update_fhrec(dbp, fhkey, fh->fh_len, fhrecp,
				"db_lookup");
	}
	return (fhrecp);
}

/*
 * db_lookup_link - search the database for the file identified by (dfh,name).
 * If the link was found, use it to search for the primary record.
 * Return 0 and set the entry in *fhrecpp if found, return error otherwise.
 */
fhlist_ent *
db_lookup_link(char *fhpath, fhandle_t *dfh, char *name, fhlist_ent *fhrecp,
	int *errorp)
{
	struct db_list		*dbp;
	fh_secondary_key	linkkey;
	linkinfo_ent		*linkp;
	int			linksize, fhkeysize;
	char			*fhkey;

	if ((fhpath == NULL) || (dfh == NULL) || (name == NULL) ||
		(errorp == NULL)) {
		if (errorp != NULL)
			*errorp = EINVAL;
		return (NULL);
	}
	*errorp = 0;
	if (dfh == &public_fh) {
		dbp = db_get_all_databases(fhpath, FALSE);
	} else {
		dbp = db_get_db(fhpath, &dfh->fh_fsid, errorp, O_CREAT);
	}
	if (dbp == NULL) {
		/* Could not get or create database */
		return (NULL);
	}
	/* Get the link record */
	linksize = fill_link_key(linkkey, dfh, name);
	linkp = fetch_record(dbp, linkkey, linksize, NULL, errorp,
			"db_lookup_link link");
	if (linkp != NULL) {
		/* Now use link to search for fh entry */
		fhkeysize = LN_FHKEY_LEN(linkp);
		fhkey = LN_FHKEY(linkp);
		fhrecp = fetch_record(dbp, fhkey, fhkeysize,
				(void *)fhrecp, errorp, "db_lookup_link fh");
		/* Update fhrec atime if needed */
		if (fhrecp != NULL) {
			*errorp = db_update_fhrec(dbp, fhkey, fhkeysize, fhrecp,
				"db_lookup_link fhrec");
		}
		/* Update link atime if needed */
		*errorp = db_update_linkinfo(dbp, linkkey, linksize, linkp,
			"db_lookup_link link");
		free(linkp);
	} else {
		fhrecp = NULL;
	}
	return (fhrecp);
}

/*
 * delete_link - delete the requested link from the database. If it's the
 * last link in the database for that file then remove the primary record
 * as well. *errorp contains the returned error code.
 * Return ENOENT if link not in database and 0 otherwise.
 */
static int
delete_link_by_key(struct db_list *dbp, char *linkkey, int *linksizep,
	int *errorp, char *errstr)
{
	int			nextsize, prevsize, fhkeysize, linksize;
	char			*nextkey, *prevkey, *fhkey;
	linkinfo_ent		*dellinkp, *nextlinkp;
	fhlist_ent		*fhrecp, fhrec;

	*errorp = 0;
	linksize = *linksizep;
	/* Get the link record */
	dellinkp = fetch_record(dbp, linkkey, linksize, NULL, errorp, errstr);
	if (dellinkp == NULL) {
		/*
		 * Link not in database.
		 */
		if (debug > 2) {
			debug_print_key(stderr, errstr,
				"link not in database\n",
				linkkey, linksize);
		}
		*linksizep = 0;
		return (ENOENT);
	}
	/*
	 * Possibilities:
	 * 1. Normal case - only one link to delete: the link next and
	 *    prev should be NULL, and fhrec's name/dfh are same
	 *    as the link. Remove the link and fhrec.
	 * 2. Multiple hard links, and the deleted link is the head of
	 *    the list. Remove the link and replace the link key in
	 *    the primary record to point to the new head.
	 * 3. Multiple hard links, and the deleted link is not the
	 *    head of the list (not the same as in fhrec) - just
	 *    delete the link and update the previous and next records
	 *    in the links linked list.
	 */

	/* Get next and prev keys for linked list updates */
	nextsize = LN_NEXT_LEN(dellinkp);
	nextkey = ((nextsize > 0) ? LN_NEXT(dellinkp) : NULL);
	prevsize = LN_PREV_LEN(dellinkp);
	prevkey = ((prevsize > 0) ? LN_PREV(dellinkp) : NULL);
	/* Update the linked list for the file */
	nextlinkp = update_linked_list(dbp, nextkey, nextsize,
			prevkey, prevsize, errorp);
	if ((nextlinkp == NULL) && (*errorp != 0)) {
		free(dellinkp);
		*linksizep = 0;
		return (0);
	}
	/* Delete link record */
	*errorp = delete_record(dbp, linkkey, linksize, errstr);
	/* Get the primary key */
	fhkeysize = LN_FHKEY_LEN(dellinkp);
	fhkey = LN_FHKEY(dellinkp);
	fhrecp = fetch_record(dbp, fhkey, fhkeysize,
		&fhrec, errorp, errstr);
	if (fhrecp == NULL) {
		/* Should never happen */
		if (debug > 1) {
			debug_print_key(stderr, errstr,
				"fetch primary for ", linkkey, linksize);
			(void) fprintf(stderr, " Error %s\n",
			((*errorp >= 0) ? strerror(*errorp) : "Unknown"));
		}
	} else if ((*errorp == 0) && (prevsize <= 0)) {
		/* This is the head of the list update primary record */
		*errorp = db_update_primary_new_head(dbp, dellinkp,
				nextlinkp, fhrecp);
	} else {
		/* Update fhrec atime if needed */
		*errorp = db_update_fhrec(dbp, fhkey, fhkeysize, fhrecp,
				errstr);
	}
	*linksizep = nextsize;
	if (nextsize > 0)
		(void) memcpy(linkkey, nextkey, nextsize);
	if (nextlinkp != NULL)
		free(nextlinkp);
	free(dellinkp);
	return (0);
}

/*
 * delete_link - delete the requested link from the database. If it's the
 * last link in the database for that file then remove the primary record
 * as well. If nextlinkkey/sizep are non-null, copy the key and key size of
 * the next link in the chain into them (this would save a dbm_fetch op).
 * Return ENOENT if link not in database and 0 otherwise, with *errorp
 * containing the returned error if any from the delete_link ops.
 */
static int
delete_link(struct db_list *dbp, fhandle_t *dfh, char *name,
	char *nextlinkkey, int *nextlinksizep, int *errorp, char *errstr)
{
	int	linkerr;

	*errorp = 0;
	if ((nextlinkkey != NULL) && (nextlinksizep != NULL)) {
		*nextlinksizep = fill_link_key(nextlinkkey, dfh, name);
		linkerr = delete_link_by_key(dbp, nextlinkkey, nextlinksizep,
				errorp, errstr);
	} else {
		int			linksize;
		fh_secondary_key	linkkey;

		linksize = fill_link_key(linkkey, dfh, name);
		linkerr = delete_link_by_key(dbp, linkkey, &linksize,
				errorp, errstr);
	}
	return (linkerr);
}

/*
 * db_delete_link - search the database for the file system for link.
 * Delete the link from the database. If this is the "primary" link,
 * set the primary record for the next link. If it's the last one,
 * delete the primary record.
 * Return 0 for success, error code otherwise.
 */
int
db_delete_link(char *fhpath, fhandle_t *dfh, char *name)
{
	struct db_list		*dbp;
	int			error = 0;

	if ((fhpath == NULL) || (dfh == NULL) || (name == NULL)) {
		return (EINVAL);
	}
	if (dfh == &public_fh) {
		dbp = db_get_all_databases(fhpath, TRUE);
	} else {
		dbp = db_get_db(fhpath, &dfh->fh_fsid, &error, O_CREAT);
	}
	for (; dbp != NULL; dbp = ((dfh == &public_fh) ? dbp->next : NULL)) {
		(void) delete_link(dbp, dfh, name, NULL, NULL, &error,
			"db_delete_link link");
	}
	return (error);
}

#ifdef DEBUG
/*
 * db_delete - Deletes the fhrec corresponding to the fh. Use only
 * for repairing the fhtable, not for normal handling.
 * Return 0 for success, error code otherwise.
 */
int
db_delete(char *fhpath, fhandle_t *fh)
{
	struct db_list		*dbp;
	int			error = 0;

	if ((fhpath == NULL) || (fh == NULL)) {
		return (EINVAL);
	}
	if (fh == &public_fh) {
		dbp = db_get_all_databases(fhpath, TRUE);
	} else {
		dbp = db_get_db(fhpath, &fh->fh_fsid, &error, O_CREAT);
	}
	for (; dbp != NULL; dbp = ((fh == &public_fh) ? dbp->next : NULL)) {
		/* Get the link record */
		(void) delete_record(dbp, &fh->fh_data, fh->fh_len,
			"db_delete: fh delete");
	}
	return (error);
}
#endif  /* DEBUG */

/*
 * db_rename_link - search the database for the file system for link.
 * Add the new link and delete the old link from the database.
 * Return 0 for success, error code otherwise.
 */
int
db_rename_link(char *fhpath, fhandle_t *from_dfh, char *from_name,
	fhandle_t *to_dfh, char *to_name)
{
	int			error;
	struct db_list		*dbp;
	fhlist_ent		fhrec, *fhrecp;

	if ((fhpath == NULL) || (from_dfh == NULL) || (from_name == NULL) ||
		(to_dfh == NULL) || (to_name == NULL)) {
		return (EINVAL);
	}
	if (from_dfh == &public_fh) {
		dbp = db_get_all_databases(fhpath, FALSE);
	} else {
		dbp = db_get_db(fhpath, &from_dfh->fh_fsid, &error, O_CREAT);
	}
	for (; dbp != NULL;
		dbp = ((from_dfh != &public_fh) ? NULL : dbp->next)) {
		/* find existing link */
		fhrecp = db_lookup_link(fhpath, from_dfh, from_name, &fhrec,
				&error);
		if (fhrecp == NULL) {
			/* Could not find the link */
			continue;
		}
		/* Delete the old link (if last primary record not deleted) */
		error = db_delete_link(fhpath, from_dfh, from_name);
		if (error == 0) {
			error = db_add(fhpath, to_dfh, to_name, &fhrecp->fh,
					fhrecp->flags);
		}
	}
	return (error);
}

/*
 * db_print_all_keys: prints all keys for a given filesystem. If fsidp is
 * NULL, print for all filesystems covered by fhpath.
 */
void
db_print_all_keys(char *fhpath, fsid_t *fsidp, FILE *fp)
{
	struct db_list	*dbp;
	datum		key;
	int		error, len;
	char		strkey[NFS_FHMAXDATA + MAXNAMELEN];
	db_record	rec;
	void		*ptr;

	if ((fhpath == NULL) ||
	    ((fsidp != NULL) && (fsidp == &public_fh.fh_fsid)))
		return;
	if (fsidp == NULL) {
		(void) db_get_all_databases(fhpath, TRUE);
		dbp = db_fs_list;
	} else {
		dbp = db_get_db(fhpath, fsidp, &error, 0);
	}
	if (dbp == NULL) {
		/* Could not get or create database */
		return;
	}
	len = strlen(fhpath);
	for (; dbp != NULL; dbp = ((fsidp != NULL) ? NULL : dbp->next)) {
		if (strncmp(fhpath, dbp->path, len))
			continue;
		(void) fprintf(fp,
			"\nStart print database for fsid 0x%x 0x%x\n",
			dbp->fsid.val[0], dbp->fsid.val[1]);
		(void) fprintf(fp, "=============================\n");
		for (key = dbm_firstkey(dbp->db); key.dptr != NULL;
			key = dbm_nextkey(dbp->db)) {
			(void) memcpy(strkey, key.dptr, key.dsize);
			debug_print_key(fp, "", "", strkey, key.dsize);
			if (debug < 2)
				continue;
			ptr = fetch_record(dbp, key.dptr, key.dsize,
					(void *)&rec, &error, "db_prt_keys");
			if (ptr == NULL)
				continue;
			if (key.dsize == NFS_FHMAXDATA) {
				/* fhrec */
				debug_print_fhlist(fp, &rec.fhlist_rec);
			} else if (key.dsize > NFS_FHMAXDATA) {
				/* linkinfo */
				debug_print_linkinfo(fp, &rec.link_rec);
			}
			(void) fprintf(fp, "-----------------------------\n");
		}
		(void) fprintf(fp, "End print database for fsid 0x%x 0x%x\n",
			dbp->fsid.val[0], dbp->fsid.val[1]);
	}
}

void
debug_opaque_print(FILE *fp, void *buf, int size)
{
	int		bufoffset = 0;
	char		debug_str[200];

	if ((buf == NULL) || (size <= 0))
		return;

	nfslog_opaque_print_buf(buf, size, debug_str, &bufoffset, 200);
	(void) fprintf(fp, debug_str);
}

/*
 * links_timedout() takes a primary records and searches all of its
 * links to see if they all have access times that are older than
 * the 'prune_timeout' value.  TRUE if all links are old and FALSE
 * if there is just one link that has an access time which is recent.
 */
static int
links_timedout(struct db_list *pdb, fhlist_ent *pfe, time_t ts)
{
	fh_secondary_key	linkkey;
	linkinfo_ent		*linkp, link_st;
	int			error;
	int			linksize;
	void			*cookie;

	/* Get the link record */
	linksize = fill_link_key(linkkey, &pfe->dfh, pfe->name);
	cookie = NULL;
	do {
		linkp = get_next_link(pdb, linkkey, &linksize, &link_st,
				&cookie, &error, "links_timedout");
		if ((linkp != NULL) &&
			(difftime(ts, linkp->atime) <= prune_timeout)) {
			/* update primary record to have an uptodate time */
			pfe = fetch_record(pdb, (void *)&pfe->fh.fh_data,
					pfe->fh.fh_len, NULL, &error,
					"links_timedout");
			if (pfe == NULL) {
				syslog(LOG_ERR, gettext(
				"links_timedout: fetch fhrec error %s\n"),
				strerror(error));
			} else {
				if (difftime(pfe->atime, linkp->atime) < 0) {
					/* update fhrec atime */
					pfe->atime = linkp->atime;
					(void) store_record(pdb,
						(void *)&pfe->fh.fh_data,
						pfe->fh.fh_len, pfe,
						pfe->reclen, "links_timedout");
				}
				free(pfe);
			}
			free_link_cookies(cookie);
			return (FALSE);
		}
	} while (linksize > 0);

	free_link_cookies(cookie);
	return (TRUE);
}

/*
 * prune_dbs() will search all of the open databases looking for records
 * that have not been accessed in the last 'prune_timeout' seconds.
 * This search is done on the primary records and a list of potential
 * timeout candidates is built.  The reason for doing this is to not
 * disturb the underlying dbm_firstkey()/dbm_nextkey() sequence; we
 * want to search all of the records in the database.
 * Once we have our candidate list built, we examine each of those
 * item's links to check if the links have been accessed within the
 * 'prune_timeout' seconds.  If neither the primary nor any its links
 * have been accessed, then all of those records are removed/deleted
 * from the database.
 */
int
prune_dbs(char *fhpath)
{
	struct db_list		*pdb;
	datum			key;
	db_record		*ptr;
	struct fhlist_ent 	*pfe;
	int			error, linkerr, linksize;
	time_t			cur_time = time(0);
	fh_secondary_key	linkkey;
	struct thelist {
		struct thelist *next;
		db_record *ptr;
	} 			thelist, *ptl;
	int	cnt = 0;

	if (fhpath != NULL)
		(void) db_get_all_databases(fhpath, TRUE);

	thelist.next = NULL;
	/*
	 * Search each of the open databases
	 */
	for (pdb = db_fs_list; pdb; pdb = pdb->next) {
	    do {
		/* Check each record in the database */
		for (key = dbm_firstkey(pdb->db); key.dptr != NULL;
		    key = dbm_nextkey(pdb->db)) {
			/* We're only interested in primary records */
			if (key.dsize != NFS_FHMAXDATA)
				continue;	/* probably a link record */
			ptr = fetch_record(pdb, key.dptr, key.dsize,
					NULL, &error, "dump_db");
			if (ptr == NULL)
				continue;
			/*
			 * If this record is a primary record and it is
			 * not an export point or a public file handle path,
			 * check it for a ancient access time.
			 */
			if ((ptr->fhlist_rec.flags &
				    (EXPORT_POINT | PUBLIC_PATH)) ||
			    (difftime(cur_time, ptr->fhlist_rec.atime) <=
					prune_timeout)) {
				/* Keep this record in the database */
				free(ptr);
			} else {
				/* Found one?  Save off info about it */
				ptl = malloc(sizeof (struct thelist));
				if (ptl == NULL) {
					syslog(LOG_ERR, gettext(
				"prune_dbs: malloc failed, error %s\n"),
						strerror(errno));
					break;
				}
				ptl->ptr = ptr;
				ptl->next = thelist.next;
				thelist.next = ptl;
				cnt++;	/* count how many records allocated */
				if (cnt > MAX_PRUNE_REC_CNT) {
					/* Limit number of records malloc'd */
					if (debug)
						(void) fprintf(stderr,
				"prune_dbs: halt search - too many records\n");
					break;
				}
			}
		}

		/*
		 * Take the saved records and check their links to make
		 * sure that they have not been accessed as well.
		 */
		for (ptl = thelist.next; ptl; ptl = thelist.next) {
			thelist.next = ptl->next;
			/* Everything timed out? */
			pfe = &(ptl->ptr->fhlist_rec);
			if (links_timedout(pdb,	pfe, cur_time)) {

				/*
				 * Iterate until we run out of links.
				 * We have to do this since there can be
				 * multiple links to a primary record and
				 * we need to delete one at a time.
				 */
				/* Delete the link and get the next */
				linkerr = delete_link(pdb,
						&pfe->dfh, pfe->name, linkkey,
						&linksize, &error, "dump_db");
				while ((linksize > 0) && !(error || linkerr)) {
					/* Delete the link and get the next */
					linkerr = delete_link_by_key(pdb,
						linkkey, &linksize,
						&error, "dump_db");
					if (error || linkerr) {
						break;
					}
				}
				if (linkerr) {
					/* link not in database, primary is */
					/* Should never happen */
					if (debug > 1) {
						(void) fprintf(stderr,
					"prune_dbs: Error primary exists ");
						debug_opaque_print(stderr,
							(void *)&pfe->fh,
							sizeof (pfe->fh));
						(void) fprintf(stderr, "\n");
					}
					if (debug)
						syslog(LOG_ERR, gettext(
					"prune_dbs: Error primary exists\n"));
					(void) delete_record(pdb,
					&pfe->fh.fh_data, pfe->fh.fh_len,
					"prune_dbs: fh delete");
				}
			}
			/* Make sure to free the pointers used in the list */
			free(ptl->ptr);
			free(ptl);
			cnt--;
		}
		thelist.next = NULL;
	    } while (key.dptr != NULL);
	}
	return (0);
}
