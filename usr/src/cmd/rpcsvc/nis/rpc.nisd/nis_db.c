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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Ported from
 *	"@(#)nis_db.c 1.42 91/03/21 Copyr 1990 Sun Micro";
 *
 * This module contains the glue routines between the actual database
 * code and the NIS+ server. Presumably they are the routines that should
 * be exported in the shared library, but they may be at too high a level.
 */

#include <stdio.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <malloc.h>
#include <rpcsvc/nis_db.h>
#include "nis_proc.h"
#include <lber.h>
#include <ldap.h>
#include "ldap_xdr.h"
#include "ldap_util.h"
#include "nisdb_mt.h"
#include "ldap_parse.h"

static nis_error __create_table(char *, nis_object *);

extern bool_t xdr_nis_object();
extern bool_t xdr_nis_name();
extern bool_t xdr_nis_oid();
extern bool_t xdr_objdata(XDR *, objdata*);
extern bool_t xdr_entry_col(XDR*, entry_col *);
extern char *relative_name();
extern db_status	__db_defer(char *);
extern db_status	__db_commit(char *);
extern db_status	__db_rollback(char *);
extern db_result	*__db_list_entries(char *, int, nis_attr *, bool_t);
extern db_status	__db_configure(char *);
int			retrieveDone(__nisdb_retry_t *refreshRetry,
					__nisdb_retry_t *retrieveretry,
					int nisPlusStat, int ldapStat,
					nis_error *outStat);
int			storeDone(__nisdb_retry_t *storeRetry,
					int nisPlusStat, int ldapStat,
					nis_error *outStat);
extern db_result *__db_add_entry_nosync(char *, int, nis_attr *, entry_obj *);
extern db_result *__db_remove_entry_nosync(char *, int, nis_attr *);
extern db_result *__db_add_entry_nolog(char *, int, nis_attr *, entry_obj *);
static int clear_checkpoint_list_nolock(void);

typedef struct table_list_entry {
	char			*table;
	struct table_list_entry	*next;
} table_list_entry_t;

static table_list_entry_t	*table_list = 0;
DECLMUTEXLOCK(table_list);

static int			mark_for_sync(char *);

NIS_HASH_TABLE *table_cache = NULL;

/*
 * Locking of the database is implemented here. We use a two level locking
 * mechanism:
 *
 *	(1) Directories
 *
 *		Write lock	Must have full access to the directory,
 *				and prevent any other access.
 *
 *		Read lock	Make sure we get to do our stuff without
 *				interaction with someone that may modify
 *				the directory.
 *
 *	(2) Tables
 *
 *		Write lock	Any operation that modifies the table or
 *				data in the table.
 *
 *		Read lock	Any other operation on the table.
 *
 * Much of this functionality relies on the implicit locking and condition
 * signaling provided by our private implementation of NIS_HASH_TABLEs.
 */

/*
 * If the database is MT safe, 'RO' should be '1' (meaning, really
 * do just read-only locking); otherwise, it should be '-1' to always
 * use exclusive locks.
 */
#define	RO	1
#define	WR	-1

static NIS_HASH_TABLE	dirlocks = NIS_HASH_TABLE_MT_INIT;

/* Stored in the 'dirlocks' list */
typedef struct {
	NIS_HASH_ITEM	item;
	NIS_HASH_TABLE	tablelocks;
	__nis_defer_t	defer;
} dirlock_t;

/* Stored in the 'tablelocks' list */
typedef struct {
	NIS_HASH_ITEM	item;
	__nis_defer_t	defer;
} tablelock_t;

#define	LOCK_DIRECTORY(name, rw, status, msg)		\
	{ \
		int	trylock = (ldapConfig.exclusiveWaitMode == block) ? \
					0 : 1; \
		status = NIS_SUCCESS; \
		if (__nis_lock_db_directory(name, rw, &trylock, msg) == 0) { \
			if (trylock == -1) { \
				status = NIS_TRYAGAIN; \
			} else { \
				status = NIS_SYSTEMERROR; \
			} \
		} \
	}

#define	ULOCK_DIRECTORY(name, rw, msg)	\
			(void) __nis_ulock_db_directory(name, rw, 0, msg)

#define	LOCK_TABLE_NORET(name, rw, status, msg)		\
	{ \
		int	trylock = (ldapConfig.exclusiveWaitMode == block) ? \
					0 : 1; \
		status = NIS_SUCCESS; \
		if (__nis_lock_db_table(name, rw, &trylock, msg) == 0) { \
			if (trylock == -1) { \
				status = NIS_TRYAGAIN; \
			} else { \
				status = NIS_SYSTEMERROR; \
			} \
		} \
	}

#define	LOCK_TABLE(name, rw, res, status, msg)	\
	{ \
		int	trylock = (ldapConfig.exclusiveWaitMode == block) ? \
					0 : 1; \
		if (__nis_lock_db_table(name, rw, &trylock, msg) == 0) { \
			if (trylock == -1) { \
				status = NIS_TRYAGAIN; \
			} else { \
				status = NIS_SYSTEMERROR; \
			} \
			return (res); \
		} \
	}

#define	ULOCK_TABLE(name, rw, msg) \
				(void) __nis_ulock_db_table(name, rw, 0, msg)

#define	ULOCK_TABLE_REMCOND(name, rw, condition, msg)	\
		(void) __nis_ulock_db_table(name, rw, (condition), msg)

static const char	*rootname = ".";

static char *
__dirname(nis_name name) {

	if (name == 0 || (name = strchr(name, '.')) == 0 ||
			*(++name) == '\0') {
		name = (char *)rootname;
	}

	return (name);
}

void *
__nis_lock_db_directory(nis_name name, int readwrite, int *trylock, char *msg) {

	dirlock_t	*dirlock;
	char		namebuf[NIS_MAXNAMELEN * 2];

	name = __dirname(name);

	if ((dirlock = (dirlock_t *)__nis_find_item_mt(name, &dirlocks,
						readwrite, trylock)) == 0) {
		if (trylock != 0 && *trylock == -1) {
			MT_LOG(1, (LOG_WARNING,
				"%d: db directory %s lock deferred \"%s\"",
			pthread_self(), MT_LOCK_TYPE(readwrite), name));
			return (0);
		}
		/* Doesn't exist; create one */
		if ((dirlock = malloc(sizeof (*dirlock))) == 0) {
			return (0);
		}
		if ((dirlock->item.name = strdup(name)) == 0) {
			free(dirlock);
			return (0);
		}
		__nis_init_hash_table(&dirlock->tablelocks, 0);
		dirlock->defer = d_none;
		if (__nis_insert_item_mt((NIS_HASH_ITEM *)dirlock, &dirlocks,
					readwrite) == 0) {
			free(dirlock->item.name);
			free(dirlock);
			/*
			 * nis_insert_item() => 0 could mean that the item
			 * already exists (i.e., someone else created it),
			 * so we'll try to find it one last time.
			 */
			if ((dirlock = (dirlock_t *)__nis_find_item_mt(name,
					&dirlocks, readwrite, trylock)) == 0) {
				return (0);
			}
		}
		MT_LOG(1, (LOG_NOTICE, "db directory lock created \"%s\"",
				name));
	}

	MT_LOG(1, (LOG_NOTICE, "%d: acquired db directory %s lock \"%s\"",
			pthread_self(), MT_LOCK_TYPE(readwrite), name));
	return (dirlock);
}

int
__nis_ulock_db_directory(nis_name name, int readwrite, int remove, char *msg) {

	dirlock_t	*dirlock;
	char		namebuf[NIS_MAXNAMELEN * 2];

	name = __dirname(name);

	if ((dirlock = (dirlock_t *)__nis_find_item_mt(name, &dirlocks,
						readwrite, 0)) != 0) {
		/* Only remove if table list is empty and not in defer mode */
		if (remove && dirlock->tablelocks.first == 0 &&
				dirlock->defer == d_none) {
			NIS_HASH_ITEM	*item;
			item = __nis_remove_item_mt(name, &dirlocks);
			if (item != 0) {
				free(item->name);
				free(item);
			}
			MT_LOG(1, (LOG_NOTICE,
				"%d: db dir %s lock removed \"%s\"",
			pthread_self(), MT_LOCK_TYPE(readwrite), name));
		} else {
			/*
			 * The __nis_lock_db_directory() call incremented the
			 * refcount on the item, and we've just incremented it
			 * again via __nis_find_item_mt(). Thus, we double the
			 * refcount to be released for __nis_release_item.
			 */
			if (__nis_release_item(dirlock, &dirlocks,
					2*readwrite)) {
				MT_LOG(1, (LOG_NOTICE,
				"%d: db dir %s lock released \"%s\"",
				pthread_self(), MT_LOCK_TYPE(readwrite), name));
			} else {
				MT_LOG(1, (LOG_WARNING,
				"%d: error releasing dirlock item for \"%s\"",
						pthread_self(), name));
			}
		}

		return (1);
	}

	MT_LOG(1, (LOG_ERR, "%d: db dir %s lock not found (unlock) \"%s\"",
		pthread_self(), MT_LOCK_TYPE(readwrite), name));

	return (0);
}

/*
 * Note that the 'trylock' semantics only apply to the directory in which
 * the table resides, not to the table itself.
 */
int
__nis_lock_db_table(nis_name name, int readwrite, int *trylock, char *msg) {

	dirlock_t	*dirlock;
	tablelock_t	*tablelock;
	char		*tablename = name;

	if ((dirlock = (dirlock_t *)__nis_lock_db_directory(name, 1, trylock,
			name)) == 0)
		return (0);

	if ((tablelock = (tablelock_t *)__nis_find_item_mt(tablename,
				&dirlock->tablelocks, readwrite, 0)) == 0) {
		if ((tablelock = malloc(sizeof (*tablelock))) == 0) {
			(void) __nis_ulock_db_directory(name, 1, 0, name);
			return (0);
		}
		if ((tablelock->item.name = strdup(tablename)) == 0) {
			free(tablelock);
			(void) __nis_ulock_db_directory(name, 1, 0, name);
			return (0);
		}
		tablelock->defer = d_none;
		if (__nis_insert_item_mt((NIS_HASH_ITEM *)tablelock,
			&dirlock->tablelocks, readwrite) == 0) {
			free(tablelock->item.name);
			free(tablelock);
			/* Some other thread may have created it */
			if ((tablelock = (tablelock_t *)__nis_find_item_mt(
			tablename, &dirlock->tablelocks, readwrite, 0)) == 0) {
				(void) __nis_ulock_db_directory(name, 1, 0,
								name);
				return (0);
			}
		}
		/* If directory is in defer mode, make the table so as well */
		if (dirlock->defer == d_defer && tablelock->defer == d_none) {
			db_status	stat = __db_defer(tablelock->item.name);
			if (stat == DB_SUCCESS || stat == DB_NOTFOUND) {
				tablelock->defer = d_defer;
			} else {
#ifdef	NIS_MT_DEBUG
				abort();
#endif	/* NIS_MT_DEBUG */
				MT_LOG(1, (LOG_WARNING,
					"%d: defer DB error %d for \"%s\"",
					pthread_self(), stat,
					tablelock->item.name));
			}
		}
		MT_LOG(1, (LOG_NOTICE, "%d: db table lock created \"%s\"",
				pthread_self(), name));
	}
	/*
	 * We've got the item, so we're done. Hang on to the read-only
	 * directory lock so that an exclusive access to the directory
	 * (probably a checkpoint) must wait for us to be done with the table.
	 */
	MT_LOG(1, (LOG_NOTICE, "%d: db table %s lock acquired \"%s\"",
			pthread_self(), MT_LOCK_TYPE(readwrite),  name));
	return (1);
}

int
__nis_ulock_db_table(nis_name name, int readwrite, int remove, char *msg) {

	dirlock_t	*dirlock;
	tablelock_t	*tablelock;
	char		*tablename = name;

	/*
	 * At this point, we should be holding a read-only lock on the
	 * directory entry, so we just obtain it without any additional
	 * locking.
	 */
	dirlock = (dirlock_t *)__nis_lock_db_directory(name, 0, 0, name);
	if (dirlock == 0) {
		return (0);
	}

	if ((tablelock = (tablelock_t *)__nis_find_item_mt(tablename,
			&dirlock->tablelocks, readwrite, 0)) != 0) {
		if (remove && readwrite == WR && tablelock->defer == d_none) {
			NIS_HASH_ITEM	*item;
			item = __nis_remove_item_mt(tablename,
					&dirlock->tablelocks);
			if (item != 0) {
				free(item->name);
				free(item);
			}
			MT_LOG(1, (LOG_NOTICE,
					"%d: removed db table lock \"%s\"",
					pthread_self(), tablename));
		} else {
			/*
			 * Normally, if the directory is in defer mode, the
			 * table would have been put in defer mode during the
			 * table lock. However, if the operation that acquired
			 * the lock also created the table, it couldn't be
			 * deferred back then, so we do it now instead.
			 */
			if (dirlock->defer == d_defer &&
					tablelock->defer == d_none) {
				db_status	s;
				s = __db_defer(tablelock->item.name);
				if (s == DB_SUCCESS) {
					tablelock->defer = d_defer;
				} else if (s != DB_NOTFOUND) {
					MT_LOG(1, (LOG_WARNING,
					"%d: defer DB error %d for \"%s\"",
						pthread_self(), s,
						tablelock->item.name));
				}
			}
			(void) __nis_release_item((NIS_HASH_ITEM *)tablelock,
				&dirlock->tablelocks, 2*readwrite);
			MT_LOG(1, (LOG_NOTICE,
				"%d: released db %s table lock \"%s\"",
			pthread_self(), MT_LOCK_TYPE(readwrite), tablename));
		}
	}

	MT_LOG(dirlock == 0, (LOG_ERR,
				"%d: could not find %s lock (unlock) \"%s\"",
			pthread_self(), MT_LOCK_TYPE(readwrite), tablename));

	return (__nis_ulock_db_directory(name, 1, 0, name));
}

/*
 * Set the directory (and any known tables) to be deferred.
 * If there's a failure attempting to defer a table, we try
 * to rollback those deferred so far, and return the failure.
 */
db_status
db_defer(nis_name name) {

	dirlock_t	*dirlock;
	db_status	stat = DB_SUCCESS;

	if ((dirlock = __nis_lock_db_directory(name, WR, NULL, "db_defer")) ==
			0)
		return (DB_NOTFOUND);

	/*
	 * If the directory isn't already in defer mode, make it so.
	 */
	if (dirlock->defer == d_none) {
		tablelock_t	*t;
		db_status	s;

		dirlock->defer = d_defer;

		/* Traverse table locks and set defer mode */
		for (t = (tablelock_t *)dirlock->tablelocks.first;
				t != 0 && stat == DB_SUCCESS;
				t = (tablelock_t *)t->item.nxt_item) {
			if (t->defer == d_none) {
				s = __db_defer(t->item.name);
				/*
				 * DB_NOTFOUND is OK; the tablelocks list is
				 * out of date. Don't mark the table deferred,
				 * though, because it doesn't exist in the DB.
				 */
				if (s == DB_SUCCESS) {
					t->defer = d_defer;
				} else if (s != DB_NOTFOUND) {
					/* Remember the first failure */
					if (stat == DB_SUCCESS)
						stat = s;
#ifdef	NIS_MT_DEBUG
					abort();
#endif	/* NIS_MT_DEBUG */
					MT_LOG(1, (LOG_WARNING,
				"%d: defer DB error %d for table \"%s\"",
						pthread_self(), s,
						t->item.name));
				}
			}
		}

		if (stat != DB_SUCCESS) {
			/* Try to rollback deferred tables */
			for (t = (tablelock_t *)dirlock->tablelocks.first;
					t != 0;
					t = (tablelock_t *)t->item.nxt_item) {
				if (t->defer == d_defer) {
					s = __db_rollback(t->item.name);
					if (s == DB_SUCCESS) {
						t->defer = d_none;
					} else {
#ifdef	NIS_MT_DEBUG
						abort();
#endif	/* NIS_MT_DEBUG */
						MT_LOG(1, (LOG_WARNING,
				"%d: rollback DB error %d for table \"%s\"",
						pthread_self(), s,
						t->item.name));
					}
				}
			}
			dirlock->defer = d_none;
		}
	}

	if (__nis_ulock_db_directory(name, WR, 0, "db_defer") == 0) {
		MT_LOG(1, (LOG_WARNING,
				"%d: db_defer: error unlocking \"%s\"",
				pthread_self(), name));
	}

	return (stat);
}

static db_status
__db_undefer(nis_name name, __nis_defer_t mode) {

	dirlock_t	*dirlock;
	tablelock_t	*t;
	db_status	stat = DB_SUCCESS;

	if (mode != d_commit && mode != d_rollback)
		return (DB_BADQUERY);

	if ((dirlock = __nis_lock_db_directory(name, WR, 0, "db_undefer")) == 0)
		return (DB_NOTFOUND);

	/* Commit or rollback deferred table changes */
	for (t = (tablelock_t *)dirlock->tablelocks.first;
			t != 0;
			t = (tablelock_t *)t->item.nxt_item) {
		db_status	s;

		if (t->defer == d_defer) {
			if (mode == d_commit)
				s = __db_commit(t->item.name);
			else
				s = __db_rollback(t->item.name);
			/*
			 * DB_NOTFOUND is OK; just means that the tablelocks
			 * list is out-of-date.
			 */
			if (s == DB_SUCCESS || s == DB_NOTFOUND) {
				t->defer = d_none;
			} else {
				/* Keep first err */
				if (stat == DB_SUCCESS)
					stat = s;
				MT_LOG(1, (LOG_WARNING,
					"%d: %s DB error %d for table \"%s\"",
						pthread_self(),
				(mode == d_commit) ? "commit" : "rollback",
						s, t->item.name));
			}
		}
	}
	/*
	 * Even if there were errors un-deferring one or more of the tables,
	 * we still want to set the directory undeferred. Otherwise, we'd
	 * continue to defer any new (meaning a tablelocks entry added)
	 * tables.
	 */
	dirlock->defer = d_none;

	if (__nis_ulock_db_directory(name, WR, 0, "db_undefer") == 0) {
		MT_LOG(1, (LOG_WARNING,
				"%d: db_undefer: error unlocking \"%s\"",
				pthread_self(), name));
	}

	return (stat);
}

db_status
db_commit(nis_name name) {
	return (__db_undefer(name, d_commit));
}

db_status
db_rollback(nis_name name) {
	return (__db_undefer(name, d_rollback));
}

/*
 * Free resources associated with a db_result structure
 */
static void
free_db_result(db_result *dr)
{
	int	i;

	if (dr == 0)
		return;

	if (dr->status != DB_SUCCESS) {
		/* Can't have valid objects */
		free(dr);
		return;
	}

	for (i = 0; i < dr->objects.objects_len; i++)
		free_entry(dr->objects.objects_val[i]);
	free(dr->objects.objects_val);
	free(dr);
}

static void
free_nis_db_result(nis_db_result *res)
{
	/* We do not free obj here because it is cached in table_cache */
	XFREE(res);
}

static nis_error
map_db_status_to_nis_status(db_status dstatus)
{
	switch (dstatus) {
	case DB_SUCCESS:
		return (NIS_SUCCESS);
	case DB_NOTFOUND:
		return (NIS_NOTFOUND);
	case DB_BADTABLE:
		return (NIS_NOSUCHTABLE);
	case DB_MEMORY_LIMIT:
		return (NIS_NOMEMORY);
	case DB_STORAGE_LIMIT:
		return (NIS_NOFILESPACE);
	case DB_NOTUNIQUE:
		return (NIS_NAMEEXISTS);
	case DB_BADQUERY:
		return (NIS_BADREQUEST);
	case DB_BADOBJECT:
		return (NIS_BADOBJECT);
	case DB_INTERNAL_ERROR:
	default:
		return (NIS_SYSTEMERROR);
	}
}

/*
 * This function converts the internal format entries of the DB into
 * a list of nis_objects that the server understands. The object returned may
 * be destroyed with nis_destroy_object();
 *
 * Notes : When listing directories the list function expects to see entry
 *	   objects and this function will mangle regular objects into entry
 *	   objects. The entry has one column which contains the binary
 *	   equivalent of what the type would have been if it hadn't been
 *	   mangled.
 *
 *	   When dumping directories we need the objects intact so we set mangle
 *	   to false and return the real objects.
 */
static obj_list *
cvt2object(
	nis_name	tablename,	/* table which has these entries */
	entry_obj	*ep[],
	uint_t		num,
	int		*got,
	int		mangle)	/* Make non-entry objects into psuedo entries */
{
	register obj_list	*oa; 		/* object array 	*/
	nis_object		*tmp;		/* Temporary object(s) 	*/
	XDR			xdrs; 		/* temporary xdr stream */
	int			status,		/* XDR op status 	*/
				curr_obj,	/* Current Object 	*/
				i, j, mc;
	entry_obj		*eo; 		/* tmp, makes life easier */
	entry_col		*ec;
	unsigned long		etype;		/* for fake entries */
	struct table_item 	*te;		/* Table cache entry	*/
	struct nis_object	*tobj;		/* Table nis_object 	*/

	*got = 0; /* Number of objects decoded */
	te = __nis_find_item_mt(tablename, table_cache, RO, 0);
	if (te == NULL) {
		/* Do a db_lookup() so that cache is populated */
		nis_db_result *dbres;

		if (((dbres = db_lookup(tablename)) == NULL) ||
		    (dbres->status != NIS_SUCCESS))
			tobj = NULL;
		else
			tobj = dbres->obj;
		/* dbres is freed automatically during cleanup */
	} else {
		tobj = te->ibobj;
	}
	oa = (obj_list *)XCALLOC(num, sizeof (obj_list));
	if (oa == NULL) {
		if (te != 0)
			__nis_release_item(te, table_cache, RO);
		return (NULL);
	}

	curr_obj = 0;
	for (i = 0; i < num; i++) {
		if (! ep[i]) {
			syslog(LOG_ERR,
			    "cvt2object: NULL Object in database, ignored.");
			continue;
		}
		ec = ep[i]->en_cols.en_cols_val;
		mc = ep[i]->en_cols.en_cols_len;
		/*
		 * Set up a memory stream pointing at the first column value
		 * which contains the XDR encoded NIS+ object.  The second
		 * column contains the name of the NIS+ object.
		 */
		xdrmem_create(&xdrs, ec->ENVAL, ec->ENLEN, XDR_DECODE);
		tmp = (nis_object *)XCALLOC(1, sizeof (nis_object));
		if (tmp == NULL) {
			/* I'll return with the current list of objects */
		if (te != 0)
			__nis_release_item(te, table_cache, RO);
			return (oa);
		}
		/*
		 * Decode it into the object structure.  If some fields
		 * are NULL, fill in appropriate values from the table
		 * nis_object structure.
		 *
		 * If the entry object has type "IN_DIRECTORY" then it
		 * is a NIS+ directory we are listing else it is
		 * an ENTRY Object.  For ENTRY objects, we call our
		 * special xdr_nis_fetus_object() which knows how to
		 * reconstruct the entry object from the given info.
		 * XXX: _any_ other value we are hosed.  If it is 0 or a
		 * NULL string, it denotes that it is an entry object.
		 */
		if (((ep[i]->en_type == 0) || (ep[i]->en_type[0] == 0)) && tobj)
			status = xdr_nis_fetus_object(&xdrs, tmp, tobj);
		else
			status = xdr_nis_object(&xdrs, tmp);
		/*
		 * POLICY : What to do about undecodeable objects ?
		 * ANSWER : Leave it blank and continue. (soft failure)
		 */
		if (! status) {
			syslog(LOG_ERR,
		    "cvt2object: Corrupted object ('%s') in database %s",
					ec[1].ENVAL, tablename);
			XFREE(tmp);
			continue;
		}

		/*
		 * If the entry object has type 0 or "IN_TABLE" then it
		 * is an entry object.  If it has type "IN_DIRECTORY" then it
		 * is a NIS+ directory that we are listing.
		 * XXX: _any_ other value we are hosed.
		 */
		if ((ep[i]->en_type == 0) || (ep[i]->en_type[0] == 0) ||
		    strcmp(ep[i]->en_type, "IN_TABLE") == 0) {
			if (__type_of(tmp) != NIS_ENTRY_OBJ) {
				syslog(LOG_ERR,
	"cvt2object: Corrupt database, entry expected for %s", ec[1].ENVAL);
				xdr_free(xdr_nis_object, (char *)tmp);
				XFREE(tmp);
				continue;
			}
			/*
			 * Set the column fields appropriately. Copy all the
			 * col entry pointers to the new entry object.  We are
			 * mucking around with the list returned by
			 * db_list_entries - UNCLEAN, UNCLEAN!
			 */
			eo = &(tmp->EN_data);
			eo->en_cols.en_cols_len = mc - 1;
			eo->en_cols.en_cols_val = XMALLOC((mc - 1) *
							(sizeof (entry_col)));
			if (eo->en_cols.en_cols_val == NULL) {
				xdr_free(xdr_nis_object, (char *)tmp);
				XFREE(tmp);
				if (te != 0)
					__nis_release_item(te, table_cache,
								RO);
				return (oa);
			}
			for (j = 1; j < mc; j++) {
				eo->en_cols.en_cols_val[j-1] =
					ep[i]->en_cols.en_cols_val[j];
			}
			/* We set len to 1, so that other cols are not freed */
			ep[i]->en_cols.en_cols_len = 1;
		} else if (mangle) {
			/* Convert this dir object into a "fake" entry object */
			etype = htonl(__type_of(tmp)); /* save the old type */
			/* first free the object specific data */
			xdr_free(xdr_objdata, (char *)&tmp->zo_data);
			memset(&tmp->zo_data, 0, sizeof (objdata));
			/* Now fake a entry object */
			__type_of(tmp) = NIS_ENTRY_OBJ;
			eo = &(tmp->EN_data);
			eo->en_type = strdup("NIS object"); /* special type */
			if (eo->en_type == NULL) {
				xdr_free(xdr_nis_object, (char *)tmp);
				if (te != 0)
					__nis_release_item(te, table_cache,
								RO);
				return (oa);
			}
			ec = (entry_col *) XMALLOC(sizeof (entry_col));
			if (ec == NULL) {
				xdr_free(xdr_nis_object, (char *)tmp);
				if (te != 0)
					__nis_release_item(te, table_cache,
								RO);
				return (oa);
			}
			eo->en_cols.en_cols_len = 1;
			eo->en_cols.en_cols_val = ec;
			ec[0].ec_flags = EN_BINARY + EN_XDR;
			ec[0].ENVAL = XMALLOC(4);
			if (ec[0].ENVAL == NULL) {
				xdr_free(xdr_nis_object, (char *)tmp);
				if (te != 0)
					__nis_release_item(te, table_cache,
								RO);
				return (oa);
			}
			ec[0].ENLEN = 4;
			memcpy(ec[0].ENVAL, (char *)&etype, 4);
		}
		oa[curr_obj++].o = tmp;
		(*got)++; /* Add one to the total */
	}

	if (te != 0)
		__nis_release_item(te, table_cache, RO);
	return	(oa);
}

/*
 * Release hash item. Intended for use by the cleanup code, executed
 * when the thread is about to return to the RPC dispatch.
 */
void
tableCacheReleaseRO(void *ptr) {
	struct table_item	*te = ptr;

	if (te != 0)
		(void) __nis_release_item(te, table_cache, RO);
}

/*
 * Destroy a table cache item.
 */
void
destroyTableCacheItem(void *item) {
	struct table_item	*ti = item;

	if (ti != 0) {
		free(ti->ti_item.name);
		nis_destroy_object(ti->ibobj);
		free(ti);
	}
}

/*
 * Return value if allocation of nis_db_result return value fails. Must
 * not be freed, of course, but that's OK since callers already expect
 * that to happen through the cleanup code.
 */
static nis_db_result	__no_mem_nis_db_result = {NIS_NOMEMORY, 0, 0};

/*
 * The following routines implement the database operations on the namespace.
 * The database only understands tables, so it is up these routines to
 * "fake out" the database and to build a table that defines the namespace
 * that we are serving. The format of this table is fixed.  It consists of
 * a table with two columns, the first being the object (XDR encoded)
 * and the second being the "name" of the object.
 *
 * Note : All of these routines assume they are passed "full" NIS+ names
 * Note : The fake entry structure is the way it is to be compatible with
 *	the cvt2object() function above.
 *
 * Lookup NIS+ objects in the namespace that are stored as entries in a
 * table by the same name as the directory being served. These entries
 * have two columns, column 0 is the object data and column 1 is the
 * object name.
 */
nis_db_result *
db_lookup_deferred(nis_name name, bool_t useDeferred)
{
	int		status;
	nis_attr	attr;
	db_result	*dbres;
	register entry_col *ec;
	XDR		xdrs;
	nis_db_result	*res;
	char		*table; 	/* The table path name	*/
	char		tblbuf[NIS_MAXNAMELEN * 2]; /* table path buf */
	struct table_item *te;		/* Table cache entry	*/
	int		triedLDAP;
	char		*myself = "db_lookup_deferred";

	if (verbose)
		syslog(LOG_INFO, "db_lookup: Looking for %s%s", name,
			useDeferred ? " in deferred DB" : "");

	if ((res = (nis_db_result *) XCALLOC(1, sizeof (nis_db_result))) == 0)
		return (&__no_mem_nis_db_result);
	add_cleanup(free_nis_db_result, (void *)(res), "db_lookup result");

	if (!table_cache) {
		table_cache = (NIS_HASH_TABLE *)
			XCALLOC(1, sizeof (NIS_HASH_TABLE));
		if (!table_cache) {
			syslog(LOG_ERR, "db_lookup: out of memory");
			res->status = NIS_NOMEMORY;
			return (res);
		}
		__nis_init_hash_table(table_cache, destroyTableCacheItem);
	}

	LOCK_TABLE(name, RO, res, res->status, name);

	/*
	 * Now we check the cache to see if we have it cached locally.
	 */
	te = __nis_find_item_mt(name, table_cache, RO, 0);
	if (te) {
		if (verbose)
			syslog(LOG_INFO, "db_lookup: table cache hit");
		res->status = NIS_SUCCESS;
		/* Defer release of item */
		add_cleanup(tableCacheReleaseRO, te, "table obj from cache");
		ULOCK_TABLE(name, RO, name);
		res->obj = te->ibobj;
		return (res);
	}

	table = internal_table_name(nis_domain_of(name), tblbuf);
	/* This happens when we're looking for directory objects. */
	if (! table) {
		res->status = NIS_NOSUCHTABLE;
		ULOCK_TABLE(name, RO, name);
		return (res);
	}
	attr.zattr_ndx = "name";
	attr.ZAVAL = nis_leaf_of(name);
	attr.ZALEN = strlen(attr.ZAVAL)+1;

	if (verbose)
		syslog(LOG_INFO, "db_lookup: looking up %s in table %s",
						attr.ZAVAL, table);
	__start_clock(1);

	{
		nisdb_tsd_t	fallback, *tsd = __nisdb_get_tsd();
		__nisdb_retry_t	refreshRetry = ldapDBTableMapping.
							refreshErrorRetry;
		__nisdb_retry_t	retrieveRetry = ldapDBTableMapping.
							retrieveErrorRetry;

		if (tsd == 0) {
			logmsg(MSG_NOMEM, LOG_ERR,
	"%s: No memory for TSD; unable to get full status for DB operation",
				myself);
			tsd = &fallback;
		}

		triedLDAP = 0;
		while (1) {
			/* Establish default status (success) */
			tsd->nisPlusStat = NIS_SUCCESS;
			tsd->ldapStat = LDAP_SUCCESS;
			dbres = __db_list_entries(table, 1, &attr,
						useDeferred);
			if (dbres == 0) {
				res->status = NIS_NOMEMORY;
				break;
			} else {
				int	rd;

				res->status =
				map_db_status_to_nis_status(dbres->status);
				if (res->status == NIS_SUCCESS &&
					tsd->ldapStat == LDAP_SUCCESS &&
					tsd->nisPlusStat == NIS_SUCCESS)
					break;
				/* Unlock while we (possibly) sleep */
				ULOCK_TABLE(name, RO, name);
				rd = retrieveDone(&refreshRetry,
						&retrieveRetry,
						tsd->nisPlusStat,
						tsd->ldapStat, &res->status);
				LOCK_TABLE(name, RO, res, res->status, name);
				if (rd) {
					/*
					 * If we failed because there was
					 * no such entry in the directory,
					 * try to get the entry from LDAP.
					 * If successful, look in the dir
					 * again.
					 */
					if (!triedLDAP && res->status ==
							NIS_NOTFOUND) {
						db_status	dstat;
						int		lstat;
						char		*intName;

						triedLDAP = 1;
						intName = internalTableName(
									name);
						if (intName == 0) {
							res->status =
								NIS_NOMEMORY;
							break;
						}
						refreshRetry =
					ldapDBTableMapping.refreshErrorRetry;
						retrieveRetry =
					ldapDBTableMapping.retrieveErrorRetry;
						do {
							tsd->nisPlusStat =
								NIS_SUCCESS;
							tsd->ldapStat =
								LDAP_SUCCESS;
							dstat =
							dbCreateFromLDAP(
							intName, &lstat);

							res->status =
					map_db_status_to_nis_status(dstat);

							rd = retrieveDone(
							&refreshRetry,
							&retrieveRetry,
							NIS_SUCCESS,
							lstat,
							&res->status);
						} while (!rd);
						free(intName);
						if (dstat == DB_SUCCESS)
							continue;
						else if (lstat ==
							LDAP_NO_SUCH_OBJECT) {
							res->status =
								NIS_NOTFOUND;
							logmsg(MSG_NOTIMECHECK,
								LOG_INFO,
						"%s: no LDAP data for \"%s\"",
								name);
						} else if (lstat !=
								LDAP_SUCCESS) {
							logmsg(MSG_NOTIMECHECK,
								LOG_WARNING,
						"%s: LDAP error for \"%s\": %s",
							myself, name,
							ldap_err2string(lstat));
						}
					}
					break;
				}
			}
			free_db_result(dbres);
		}
		res->ticks = __stop_clock(1);
	}

	if (res->status == NIS_SUCCESS || res->status == NIS_CACHEEXPIRED) {
		/* ASSERT(dbres->objects.objects_len == 1); */

		/*
		 * convert from XDR format that the DB returns to
		 * the nis_object format
		 */
		ec = dbres->objects.objects_val[0]->en_cols.en_cols_val;

		xdrmem_create(&xdrs, ec->ENVAL, ec->ENLEN, XDR_DECODE);
		res->obj = (nis_object *)XCALLOC(1, sizeof (nis_object));
		if (!(res->obj))
			res->status = NIS_NOMEMORY;
		else {
			status = xdr_nis_object(&xdrs, res->obj);
			if (! status) {
				syslog(LOG_ERR, "db_lookup: Corrupt object %s",
						name);
				XFREE(res->obj);
				res->obj = NULL;
				res->status = NIS_SYSTEMERROR;
			}
		}
	}

	if (verbose && dbres)
		syslog(LOG_INFO, "db_lookup: exit status is %d", dbres->status);

	if (res->obj) {
		int		doRead;
		__nis_buffer_t	b = {0, 0};

		/*
		 * If the object is read-mapped from LDAP, we don't want
		 * to cache it in the table_cache.
		 */
		bp2buf("db_lookup_deferred", &b, "%s.%s",
			res->obj->zo_name, res->obj->zo_domain);
		if ((__type_of(res->obj) == NIS_TABLE_OBJ) &&
			useDeferred &&
			(getObjMapping(b.buf, 0, 1, &doRead, 0) == 0 ||
			!doRead) &&
			strstr(name, "org_dir")) {
			/*
			 * Cache the table objects in the "org_dir"
			 * dir.  We want to cache only the "org_dir" tables
			 * instead of caching all zillions of tables.
			 */
			te = (struct table_item *)XCALLOC(1, sizeof (*te));
			if (te) {
				te->ti_item.name = (nis_name) strdup(name);
				if (te->ti_item.name == NULL) {
					add_cleanup(nis_destroy_object,
					    (void *)(res->obj),
					    "db_lookup result");
					free(te);
				} else {
					te->ibobj = res->obj;
					(void) __nis_insert_item_mt(te,
						table_cache, 0);
					if (verbose)
						syslog(LOG_INFO,
						"Added %s to the table cache",
							name);
				}
			} else {
				add_cleanup(nis_destroy_object,
				    (void *)(res->obj), "db_lookup result");
			}
		} else {
			add_cleanup(nis_destroy_object,
				    (void *)(res->obj), "db_lookup result");
		}
		if (b.buf != 0)
			free(b.buf);
	}

	free_db_result(dbres);
	ULOCK_TABLE(name, RO, name);
	return (res);
}

nis_db_result *
db_lookup(nis_name name) {
	return (db_lookup_deferred(name, TRUE));
}

/*
 * __db_add()
 *
 * The internal version of db_add, this one doesn't add an entry into
 * the log.  This function converts the nis_object into a DB style object
 * and then adds it to the database.
 */
nis_error
__db_add(
	nis_name	name,
	nis_object	*obj,
	int		modop)	 /* Modify operation flag */
{
	nis_attr	attr;
	int		i;
	db_result	*dbres;
	entry_col	ecols[2];
	entry_obj	entry;
	char		*table;
	uchar_t		*buf;
	nis_error	res;
	XDR		xdrs;
	char		tblbuf[NIS_MAXNAMELEN * 2];
	char		*myself = "__db_add";

	if (verbose)
		syslog(LOG_INFO, "__db_add: attempting to %s %s",
			modop? "modify" : "add", name);

	LOCK_TABLE(name, WR, res, res, name);

	if ((__type_of(obj) == NIS_TABLE_OBJ) && (!modop)) {
		if ((res = __create_table(name, obj)) != NIS_SUCCESS) {
			ULOCK_TABLE(name, WR, name);
			syslog((res != NIS_NAMEEXISTS) ? LOG_ERR : LOG_INFO,
	    "__db_add: Unable to create database for NIS+ table %s: %s.",
				    name, nis_sperrno(res));
			return (res);
		}
	}

	table = internal_table_name(nis_domain_of(name), tblbuf);
	if (! table) {
		ULOCK_TABLE(name, WR, name);
		return (NIS_BADNAME);
	}

	i = xdr_sizeof(xdr_nis_object, obj);
	buf = __get_xdr_buf(i);
	xdrmem_create(&xdrs, (char *)buf, i, XDR_ENCODE);
	i = xdr_nis_object(&xdrs, obj);
	if (! i) {
		ULOCK_TABLE(name, WR, name);
		syslog(LOG_ERR, "__db_add: cannot encode object %s", name);
		return (NIS_SYSTEMERROR);
	}

	/* Now we cons up an entry for this object in the name space */
	entry.en_type			= "IN_DIRECTORY";
	entry.en_cols.en_cols_len	= 2;
	entry.en_cols.en_cols_val	= ecols;
	ecols[0].ec_flags		= EN_XDR + EN_MODIFIED;
	ecols[0].ENVAL			= (char *)buf;
	ecols[0].ENLEN			= xdr_getpos(&xdrs);
	ecols[1].ec_flags		= EN_MODIFIED;
	ecols[1].ENVAL			= nis_leaf_of(name);
	ecols[1].ENLEN			= strlen(ecols[1].ENVAL)+1;
	attr.zattr_ndx = "name";
	attr.ZAVAL = ecols[1].ENVAL;
	attr.ZALEN = ecols[1].ENLEN;

	{
		nisdb_tsd_t	fallback, *tsd = __nisdb_get_tsd();
		__nisdb_retry_t	storeRetry = ldapDBTableMapping.
							storeErrorRetry;

		if (tsd == 0) {
			logmsg(MSG_NOMEM, LOG_ERR,
	"%s: No memory for TSD; unable to get full status for DB operation",
				myself);
			tsd = &fallback;
		}

		while (1) {
			/* Establish default status (success) */
			tsd->nisPlusStat = NIS_SUCCESS;
			tsd->ldapStat = LDAP_SUCCESS;
			dbres = db_add_entry(table, 1, &attr, &entry);
			if (dbres == 0) {
				res = NIS_NOMEMORY;
				break;
			} else {
				int	rd;

				res = map_db_status_to_nis_status(dbres->
								status);
				if (res == NIS_SUCCESS &&
					tsd->ldapStat == LDAP_SUCCESS &&
					tsd->nisPlusStat == NIS_SUCCESS)
					break;
				/* Unlock while we (possibly) sleep */
				ULOCK_TABLE(name, WR, name);
				rd = storeDone(&storeRetry, tsd->nisPlusStat,
						tsd->ldapStat, &res);
				LOCK_TABLE(name, WR, res, res, name);
				if (rd)
					break;
			}
			free_db_result(dbres);
		}
	}

	switch (res) {
	    case NIS_NOMEMORY:
	    case NIS_NOFILESPACE:
	    case NIS_SYSTEMERROR:
	    case NIS_UNAVAIL:
		break;	/* these are expected */
	    case NIS_SUCCESS:
		if (modop) {
			/* Flush various cached objects */
			switch __type_of(obj) {
			    case NIS_TABLE_OBJ:
				flush_tablecache(name);
				break;
			    case NIS_DIRECTORY_OBJ:
				flush_dircache(name, (directory_obj *)NULL);
				break;
			    case NIS_GROUP_OBJ:
				flush_groupcache(name);
				break;
			    default:
				break;
			}
		}
		(void) mark_for_sync(table);
		break;
	    default:
		syslog(LOG_ERR, "__db_add: unexpected database result %d",
								dbres->status);
		break;
	}

	free_db_result(dbres);
	if (res == NIS_SUCCESS) {
		multival_invalidate(obj);
	}
	ULOCK_TABLE(name, WR, name);
	return (res);
}

/*
 * db_add()
 *
 * External wrapper for the real db_add function. This one creates a
 * transaction log entry. The internal one skips the log transaction.
 */
nis_db_result *
db_add(
	nis_name	name,
	nis_object	*obj,
	int		mod_op)
{
#define	res		__nis_get_tsd()->db_add_res
	log_entry le;	/* A log entry */

	memset((char *)&res, 0, sizeof (res));
	memset((char *)&le, 0, sizeof (le));
	if (verbose) {
		if (mod_op == 0)
			syslog(LOG_INFO, "db_add: Adding object %s", name);
		else
			syslog(LOG_INFO, "db_add: Modifying object %s", name);
	}

	LOCK_TABLE(name, WR, &res, res.status, name);

	le.le_time = obj->zo_oid.mtime;
	if (mod_op)
		le.le_type = MOD_NAME_NEW;
	else
		le.le_type = ADD_NAME;
	le.le_name = name;
	le.le_object = *obj;
	add_update(&le);
	__start_clock(1);
	res.status = __db_add(name, obj, mod_op);
	res.ticks = __stop_clock(1);
	if (verbose || (res.status != NIS_SUCCESS))
		syslog(LOG_INFO, "db_add: returning %s",
			nis_sperrno(res.status));
	ULOCK_TABLE(name, WR, name);
	return (&res);
}

#undef	res

nis_error
__db_remove(
	nis_name	name,		/* Name of object to remove	*/
	nis_object	*obj)		/* Its type (for deleting tables) */
{
	nis_attr	attr;
	char		*table;
	db_result	*dbres;
	nis_error	res;
	char		tblbuf[NIS_MAXNAMELEN * 2];
	int		table_deleted = 0;
	char		*myself = "__db_remove";

	LOCK_TABLE(name, WR, res, res, name);
	if (__type_of(obj) == NIS_TABLE_OBJ) {
		table = internal_table_name(name, tblbuf);
		if (! table) {
			ULOCK_TABLE(name, WR, name);
			return (NIS_BADNAME);
		}

		/* First make sure the table is empty */

		{
			nisdb_tsd_t	fallback, *tsd = __nisdb_get_tsd();
			__nisdb_retry_t	refreshRetry = ldapDBTableMapping.
							refreshErrorRetry;
			__nisdb_retry_t	retrieveRetry = ldapDBTableMapping.
							retrieveErrorRetry;

			if (tsd == 0) {
				logmsg(MSG_NOMEM, LOG_ERR,
	"%s: No memory for TSD; unable to get full status for DB operation",
					myself);
				tsd = &fallback;
			}

			while (1) {
				/* Establish default status (success) */
				tsd->nisPlusStat = NIS_SUCCESS;
				tsd->ldapStat = LDAP_SUCCESS;
				dbres = db_first_entry(table, 0, NULL);
				if (dbres == 0) {
					break;
				} else {
					nis_error	err;
					int		rd;

					err = map_db_status_to_nis_status(
								dbres->status);
					if (err == NIS_SUCCESS &&
					tsd->ldapStat == LDAP_SUCCESS &&
					tsd->nisPlusStat == NIS_SUCCESS)
					break;
					ULOCK_TABLE(name, WR, name);
					rd = retrieveDone(&refreshRetry,
							&retrieveRetry,
							tsd->nisPlusStat,
							tsd->ldapStat, &err);
					LOCK_TABLE(name, WR, err, err, name);
					if (rd)
						break;
				}
				free_db_result(dbres);
			}
		}

		if (dbres == 0 || dbres->status == DB_MEMORY_LIMIT) {
			free_db_result(dbres);
			ULOCK_TABLE(name, WR, name);
			return (NIS_NOMEMORY);
		} else if (dbres->status == DB_SUCCESS) {
			free(dbres->nextinfo.db_next_desc_val); /* cookie */
			free_db_result(dbres);
			ULOCK_TABLE(name, WR, name);
			return (NIS_NOTEMPTY);
		} else if (dbres->status == DB_NOTFOUND) {
			if ((res = db_destroy(name)) != NIS_SUCCESS)
			    syslog(LOG_WARNING,
				"__db_remove: Unable to destroy table %s: %s.",
				    table, nis_sperrno(res));
			else
				table_deleted = 1;
		} else {
			/*
			 * POLICY : What should we do, remove the object?
			 *	    or abort() because the database is
			 *	    inconsistent.
			 * ANSWER : Notify the system operator, and continue
			 *	    to remove the table object.
			 */
			syslog(LOG_ERR,
			    "__db_remove: table %s not in dictionary (err=%d)",
			    table, dbres->status);
			if ((res = db_destroy(name)) != NIS_SUCCESS)
			    syslog(LOG_WARNING,
				"__db_remove: Unable to destroy table %s: %s.",
				    table, nis_sperrno(res));
			else
				table_deleted = 1;
		}
		free_db_result(dbres);
	}

	table = internal_table_name(nis_domain_of(name), tblbuf);
	if (! table) {
		ULOCK_TABLE(name, WR, name);
		return (NIS_BADNAME);
	}

	attr.zattr_ndx = "name";
	attr.ZAVAL = nis_leaf_of(name);
	attr.ZALEN = strlen(attr.ZAVAL)+1;

	{
		nisdb_tsd_t	fallback, *tsd = __nisdb_get_tsd();
		__nisdb_retry_t	storeRetry = ldapDBTableMapping.
							storeErrorRetry;

		if (tsd == 0) {
			logmsg(MSG_NOMEM, LOG_ERR,
	"%s: No memory for TSD; unable to get full status for DB operation",
				myself);
			tsd = &fallback;
		}

		while (1) {
			/* Establish default status (success) */
			tsd->nisPlusStat = NIS_SUCCESS;
			tsd->ldapStat = LDAP_SUCCESS;
			dbres = db_remove_entry(table, 1, &attr);
			if (dbres == 0) {
				res = NIS_NOMEMORY;
				break;
			} else {
				int		rd;

				res = map_db_status_to_nis_status(dbres->
								status);
				if (res == NIS_SUCCESS &&
					tsd->ldapStat == LDAP_SUCCESS &&
					tsd->nisPlusStat == NIS_SUCCESS)
					break;
				ULOCK_TABLE(name, WR, name);
				rd = storeDone(&storeRetry, tsd->nisPlusStat,
						tsd->ldapStat, &res);
				LOCK_TABLE(name, WR, res, res, name);
				if (rd)
					break;
			}
			free_db_result(dbres);
		}
	}

	switch (res) {
	    case NIS_NOMEMORY:
	    case NIS_NOFILESPACE:
	    case NIS_SYSTEMERROR:
	    case NIS_UNAVAIL:
		break;	/* these are expected */
	    case NIS_SUCCESS:
		/* Flush various cached objects */
		switch __type_of(obj) {
		    case NIS_TABLE_OBJ:
			flush_tablecache(name);
			break;
		    case NIS_DIRECTORY_OBJ:
			flush_dircache(name, (directory_obj *)NULL);
			break;
		    case NIS_GROUP_OBJ:
			flush_groupcache(name);
			break;
		    default:
			break;
		}
		(void) mark_for_sync(table);
		break;
	    default:
		syslog(LOG_ERR,
			"__db_remove: unexpected result from database %d",
								dbres->status);
		break;
	}

	free_db_result(dbres);
	if (res == NIS_SUCCESS) {
		multival_invalidate(obj);
	}
	ULOCK_TABLE_REMCOND(name, WR, table_deleted && res == NIS_SUCCESS,
			name);
	return (res);
}

nis_db_result *
db_remove(
	nis_name	name,		/* Name of object to remove */
	nis_object	*obj,		/* Its type (for deleting tables) */
	ulong_t		xid_time)	/* Time of "this" transaction */
{
#define	res		__nis_get_tsd()->db_remove_res
	log_entry le;			/* A log entry */

	memset((char *)&res, 0, sizeof (res));
	memset((char *)&le, 0, sizeof (le));
	if (verbose)
		syslog(LOG_INFO, "db_remove: removing %s from the namespace",
									name);
	LOCK_TABLE(name, WR, &res, res.status, name);

	le.le_time = xid_time;
	le.le_type = REM_NAME;
	le.le_name = name;
	le.le_object = *obj;
	add_update(&le);
	__start_clock(1);
	res.status = __db_remove(name, obj);
	res.ticks = __stop_clock(1);
	if (verbose || (res.status != NIS_SUCCESS))
		syslog(LOG_INFO, "db_remove: returning %s",
						nis_sperrno(res.status));
	ULOCK_TABLE(name, WR, name);
	return (&res);
}

#undef	res

static nis_db_list_result	__no_memory_db_list_result = {
								NIS_NOMEMORY,
								0, 0, 0
};

/*
 * db_list(table, numattrs, attrs)
 *
 * function to call the database list function. When called we know that
 * object is "readable" by the principal.
 *
 */

static nis_db_list_result *
db_list_x(
	nis_name	name,	/* Table we are listing 	*/
	int		na,	/* Number of attributes 	*/
	nis_attr	*a,	/* An array of attributes 	*/
	ulong_t		flags)
{
	int		i;
	nis_error	err;
	char		*table; /* internal table name */
	char		tblbuf[NIS_MAXNAMELEN * 2]; /* table path buf */
	db_result	*dbres;
	nis_db_list_result *res;
	int		got;
	int		nm = 0;
	nis_object	*o;
	nis_object	*tobj;
	nis_db_result	*tres;
	char		*myself = "db_list_x";

	res = (nis_db_list_result *)XCALLOC(1, sizeof (nis_db_list_result));
	if ((flags & FN_NORAGS) == 0) {
		if (res == 0)
			return (&__no_memory_db_list_result);
		add_cleanup(free_db_list, (void *)res, "db_list result");
	}
	got = 0;
	table =  internal_table_name(name, tblbuf);
	if (! table) {
		res->status = NIS_BADNAME;
		return (res);
	}

	if (verbose)
		syslog(LOG_INFO, "db_list: listing %s", table);

	LOCK_TABLE(name, RO, res, res->status, name);

	__start_clock(1);
	tres = db_lookup(name);
	if (tres == NULL) {
		res->ticks = __stop_clock(1);
		ULOCK_TABLE(name, RO, name);
		res->status = NIS_NOMEMORY;
		res->numo = 0;
		res->objs = NULL;
		return (res);
	}
	if (tres->status == NIS_SUCCESS) {
		tobj = tres->obj;
	} else if (tres->status == NIS_NOSUCHTABLE) {
		/* this happens on top directory in server's database */
		tobj = NULL;
	} else {
		res->ticks = __stop_clock(1);
		ULOCK_TABLE(name, RO, name);
		res->status = tres->status;
		res->numo = 0;
		res->objs = NULL;
		return (res);
	}

	/* check for multival searches */
	if (tobj) {
		err = multival_attr(tobj, a, &na, &nm);
		if (err != NIS_SUCCESS) {
			res->ticks = __stop_clock(1);
			ULOCK_TABLE(name, RO, name);
			res->status = err;
			return (res);
		}
	}

	/*
	 *  If we have regular attributes or if we have no attributes
	 *  at all (na == 0 && nm == 0), search the normal way.
	 */
	if (na || nm == 0) {
		{
			nisdb_tsd_t	fallback, *tsd = __nisdb_get_tsd();
			__nisdb_retry_t	refreshRetry = ldapDBTableMapping.
							refreshErrorRetry;
			__nisdb_retry_t	retrieveRetry = ldapDBTableMapping.
							retrieveErrorRetry;

			if (tsd == 0) {
				logmsg(MSG_NOMEM, LOG_ERR,
	"%s: No memory for TSD; unable to get full status for DB operation",
					myself);
				tsd = &fallback;
			}

			while (1) {
				/* Establish default status (success) */
				tsd->nisPlusStat = NIS_SUCCESS;
				tsd->ldapStat = LDAP_SUCCESS;
				dbres = db_list_entries(table, na, a);
				if (dbres == 0) {
					res->status = NIS_NOMEMORY;
					break;
				} else {
					int	rd;

					res->status =
				map_db_status_to_nis_status(dbres->status);
					if (res->status == NIS_SUCCESS &&
						tsd->ldapStat ==
							LDAP_SUCCESS &&
						tsd->nisPlusStat ==
							NIS_SUCCESS)
						break;
					ULOCK_TABLE(name, RO, name);
					rd = retrieveDone(&refreshRetry,
							&retrieveRetry,
							tsd->nisPlusStat,
						tsd->ldapStat, &res->status);
					LOCK_TABLE(name, RO, res, res->status,
							name);
					if (rd)
						break;
				}
				free_db_result(dbres);
			}
		}

		res->ticks = __stop_clock(1);
		/* Process the entries into "objects" */
		switch (res->status) {
		    case NIS_NOMEMORY:
			break;
		    case NIS_SUCCESS:
		    case NIS_CACHEEXPIRED:
			/* Convert from database format to NIS+ object format */
			res->objs = cvt2object(name, dbres->objects.objects_val,
					dbres->objects.objects_len, &got, 1);
			if (got > 0) {
				res->numo = got;
				res->status = NIS_SUCCESS;
			} else {
				res->numo = 0;
				res->status = NIS_NOTFOUND;
				res->objs = NULL;
			}
			break;
		    case NIS_NOTFOUND:
		    case NIS_TRYAGAIN:
		    case NIS_UNAVAIL:
		    case NIS_NOSUCHNAME:
			res->numo = 0;
			res->objs = NULL;
			break;
		    default:
			strcpy(tblbuf, "[");
			for (i = 0; i < na; i++) {
				if (i != 0)
					strcat(tblbuf, ",");
				strcat(tblbuf, a[i].zattr_ndx);
				strcat(tblbuf, "=");
				strncat(tblbuf,
					a[i].zattr_val.zattr_val_val,
					a[i].zattr_val.zattr_val_len);
			}
			strcat(tblbuf, "],");
			strcat(tblbuf, name);
			syslog(LOG_ERR,
				"Database search failed on %s, status = %d",
				tblbuf, dbres->status);
			break;
		}
		if (verbose)
			syslog(LOG_INFO,
				"db_list: returning status = %d, entries = %d",
				res->status, got);
		free_db_result(dbres);
	} else {
		res->ticks = __stop_clock(1);
	}

	/*
	 *  If we have multival attributes and regular attributes,
	 *  filter out the objects gotten above that don't match
	 *  on the multival columns.  If there were no regular
	 *  attributes, then list based only on the multival columns.
	 */
	if (nm) {
		if (na) {
			for (i = 0; i < res->numo; i++) {
				o = res->objs[i].o;
				if (multival_filter(tobj, nm, a + na, o)) {
					nis_destroy_object(o);
					res->objs[i].o = NULL;
				}
			}
		} else {
			/* na = 0 */
			multival_list(tobj, nm, a, res);
		}
	}

	ULOCK_TABLE(name, RO, name);
	return (res);
}

nis_db_list_result *
db_list(
	nis_name	name,	/* Table we are listing 	*/
	int		na,	/* Number of attributes 	*/
	nis_attr	*a)	/* An array of attributes 	*/
{
	return (db_list_x(name, na, a, 0));
}

nis_db_list_result *
db_list_flags(
	nis_name	name,	/* Table we are listing 	*/
	int		na,	/* Number of attributes 	*/
	nis_attr	*a,	/* An array of attributes 	*/
	ulong_t		flags)
{
	return (db_list_x(name, na, a, flags));
}

/*
 * This function has to release all of the components that were allocated
 * by db_list above.
 */
void
free_db_list(nis_db_list_result	*list)
{
	int	i;

	if (list == NULL)
		return;
	for (i = 0; i < list->numo; i++) {
		if (list->objs[i].o)
			nis_destroy_object(list->objs[i].o);
	}
	if ((list->objs) && (list->numo))
		XFREE(list->objs); /* Free the entire array */
	free(list);
}

static nis_fn_result	__no_memory_fn_result = {
							NIS_NOMEMORY,
							0, {0}, 0
};

/*
 * nis_fn_result *db_firstib(name)
 *
 * Get the "first" entry from a table. Note this function returns an opaque
 * "cookie" that has what ever state the underlying database needs to
 * find the next entry in a chain of entries. Since it is specific to the
 * underlying database it is opaque to this interface.
 */
nis_fn_result *
db_firstib(
	nis_name	name,	/* Table name		*/
	int		na,	/* Number of attributes */
	nis_attr	*a,	/* Attribute list	*/
	int		flags,	/* Mangle objects into entries */
	char		*table)
{
	db_result	*dbres;
	obj_list	*olist;
	int		got;
	char		tblbuf[NIS_MAXNAMELEN * 2];
	nis_fn_result	*res;
	char		*myself = "db_firstib";

	res = (nis_fn_result *)XCALLOC(1, sizeof (nis_fn_result));
	if ((flags & FN_NORAGS) == 0) {
		if (res == 0)
			return (&__no_memory_fn_result);
		add_cleanup((void (*)())XFREE, (char *)res, "fn (first) res");
	}
	if (! table)
		table = internal_table_name(name, tblbuf);
	if (! table) {
		res->status = NIS_BADNAME;
		return (res);
	}

	if (verbose)
		syslog(LOG_INFO, "db_firstib: Fetching first entry from %s",
							table);
	LOCK_TABLE(name, RO, res, res->status, name);
	__start_clock(1);

	{
		nisdb_tsd_t	fallback, *tsd = __nisdb_get_tsd();
		__nisdb_retry_t	refreshRetry = ldapDBTableMapping.
						refreshErrorRetry;
		__nisdb_retry_t	retrieveRetry = ldapDBTableMapping.
						retrieveErrorRetry;

		if (tsd == 0) {
			logmsg(MSG_NOMEM, LOG_ERR,
	"%s: No memory for TSD; unable to get full status for DB operation",
				myself);
			tsd = &fallback;
		}

		while (1) {
			/* Establish default status (success) */
			tsd->nisPlusStat = NIS_SUCCESS;
			tsd->ldapStat = LDAP_SUCCESS;
			dbres = db_first_entry(table, na, a);
			if (dbres == 0) {
				break;
			} else {
				int		rd;

				res->status = map_db_status_to_nis_status(
							dbres->status);
				if (res->status == NIS_SUCCESS &&
					tsd->ldapStat == LDAP_SUCCESS &&
					tsd->nisPlusStat == NIS_SUCCESS)
					break;
				ULOCK_TABLE(name, RO, name);
				rd = retrieveDone(&refreshRetry,
						&retrieveRetry,
						tsd->nisPlusStat,
						tsd->ldapStat, &res->status);
				LOCK_TABLE(name, RO, res, res->status, name);
				if (rd)
					break;
			}
			free_db_result(dbres);
		}
	}

	switch (res->status) {
	    case NIS_NOMEMORY:
	    case NIS_NOTFOUND:
	    case NIS_TRYAGAIN:
	    case NIS_UNAVAIL:
	    case NIS_NOSUCHNAME:
		break;	/* expected */
	    case NIS_BADREQUEST:
		if ((flags & FN_NOERROR) == 0)
			syslog(LOG_ERR,
				"db_firstib: Table: '%s', Bad Attribute",
				name);
		break;
	    case NIS_NOSUCHTABLE:
		if ((flags & FN_NOERROR) == 0)
			syslog(LOG_ERR,
				"db_firstib: Missing table '%s'", name);
		break;
	    case NIS_SUCCESS:
	    case NIS_CACHEEXPIRED:
		/* ASSERT(dbres->objects.objects_len == 1); */
		/* Convert the entry into a NIS+ object */
		olist = cvt2object(name, dbres->objects.objects_val, 1, &got,
						(FN_MANGLE & flags));
		if ((olist == NULL) || (got > 1)) {
			syslog(LOG_ERR, "db_firstib: Database is corrupt.");
			res->status = NIS_SYSTEMERROR;
		} else {
			res->obj = olist->o; /* Now that's nice and clear! */
			if ((flags & FN_NORAGS) == 0)
				add_cleanup(nis_destroy_object,
					(char *)res->obj, "firstib object.");
			XFREE(olist); /* free list struct but not obj in it */
		}
		/* Now clone the nextinfo cookie */
		res->cookie.n_len = dbres->nextinfo.db_next_desc_len;
		res->cookie.n_bytes = (char *)XMALLOC(res->cookie.n_len);
		memcpy(res->cookie.n_bytes, dbres->nextinfo.db_next_desc_val,
					    dbres->nextinfo.db_next_desc_len);
		free(dbres->nextinfo.db_next_desc_val);
		dbres->nextinfo.db_next_desc_val = 0;
		if (res->obj == NULL) {
			syslog(LOG_ERR, "db_firstib: Object not found.");
			res->status = NIS_SYSTEMERROR;
		}
		break;

	    default:
		if ((flags & FN_NOERROR) == 0)
			syslog(LOG_ERR,
				"db_firstib: Unexpected database result %d.",
								dbres->status);
		break;
	}
	/* Don't need this anymore */
	free_db_result(dbres);
	if (verbose)
		syslog(LOG_INFO, "db_firstib: returning status of %s",
						nis_sperrno(res->status));
	ULOCK_TABLE(name, RO, name);
	return (res); /* Return it finally */
}

/*
 * nis_fn_result *db_nextib(name, cookie)
 *
 * Get the "next" entry from a table.
 */
nis_fn_result *
db_nextib(
	nis_name	name,
	netobj		*cookie,
	int		flags,
	char		*table)
{
	nis_fn_result 	*res;
	db_result	*dbres;
	obj_list	*olist;
	int		got;
	char		tblbuf[NIS_MAXNAMELEN * 2];
	char		*myself = "db_nextib";

	res = (nis_fn_result *)XCALLOC(1, sizeof (nis_fn_result));
	if ((flags & FN_NORAGS) == 0) {
		if (res == 0)
			return (&__no_memory_fn_result);
		add_cleanup((void (*)())XFREE, (char *)res, "fn (next) res");
	}
	if (! table)
		table = internal_table_name(name, tblbuf);
	if (! table) {
		res->status = NIS_BADNAME;
		return (res);
	}
	if (verbose)
		syslog(LOG_INFO, "db_nextib: Fetching entry from %s", table);
	__start_clock(1);
	LOCK_TABLE(name, RO, res, res->status, name);

	{
		nisdb_tsd_t	fallback, *tsd = __nisdb_get_tsd();
		__nisdb_retry_t	refreshRetry = ldapDBTableMapping.
						refreshErrorRetry;
		__nisdb_retry_t	retrieveRetry = ldapDBTableMapping.
						retrieveErrorRetry;

		if (tsd == 0) {
			logmsg(MSG_NOMEM, LOG_ERR,
	"%s: No memory for TSD; unable to get full status for DB operation",
				myself);
			tsd = &fallback;
		}

		while (1) {
			/* Establish default status (success) */
			tsd->nisPlusStat = NIS_SUCCESS;
			tsd->ldapStat = LDAP_SUCCESS;
			dbres = db_next_entry(table, (db_next_desc *)cookie);
			if (dbres == 0) {
				break;
			} else {
				int		rd;

				res->status = map_db_status_to_nis_status(
							dbres->status);
				if (res->status == NIS_SUCCESS &&
					tsd->ldapStat == LDAP_SUCCESS &&
					tsd->nisPlusStat == NIS_SUCCESS)
					break;
				ULOCK_TABLE(name, RO, name);
				rd = retrieveDone(&refreshRetry,
						&retrieveRetry,
						tsd->nisPlusStat,
						tsd->ldapStat, &res->status);
				LOCK_TABLE(name, RO, res, res->status, name);
				if (rd)
					break;
			}
			free_db_result(dbres);
		}
	}

	switch (res->status) {
	    case NIS_NOMEMORY:
	    case NIS_NOTFOUND:
	    case NIS_TRYAGAIN:
	    case NIS_UNAVAIL:
	    case NIS_NOSUCHNAME:
		break;
	    case NIS_BADREQUEST:
		if ((flags & FN_NOERROR) == 0)
			syslog(LOG_ERR,
		    "db_nextib: Bad Attribute in Table: '%s'",
						name);
		break;
	    case NIS_NOSUCHTABLE:
		if ((flags & FN_NOERROR) == 0)
			syslog(LOG_ERR,
		    "db_nextib: Missing table object '%s'",
							name);
		break;
	    case NIS_SUCCESS:
	    case NIS_CACHEEXPIRED:
		/* ASSERT(dbres->objects.objects_len == 1); */
		olist = cvt2object(name, dbres->objects.objects_val, 1, &got,
						(flags & FN_MANGLE));
		if ((olist == NULL) || (got > 1)) {
			syslog(LOG_ERR, "db_nextib: Database is corrupt.");
			res->status = NIS_SYSTEMERROR;
		} else {
			res->obj = olist->o;
			if ((flags & FN_NORAGS) == 0)
				add_cleanup(nis_destroy_object,
					(char *)res->obj, "nextib object");
			XFREE(olist);
		}
		/* Now clone the nextinfo cookie */
		res->cookie.n_len = dbres->nextinfo.db_next_desc_len;
		res->cookie.n_bytes = (char *)XMALLOC(res->cookie.n_len);
		memcpy(res->cookie.n_bytes, dbres->nextinfo.db_next_desc_val,
					    dbres->nextinfo.db_next_desc_len);
		free(dbres->nextinfo.db_next_desc_val);
		if (res->obj == NULL)
			res->status = NIS_SYSTEMERROR;
		break;
	    default:
		if ((flags & FN_NOERROR) == 0)
			syslog(LOG_ERR,
		    "db_nextib: Unexpected database result %d",
						dbres->status);
		break;
	}
	/* Don't need this anymore */
	free_db_result(dbres);
	if (verbose)
		syslog(LOG_INFO, "db_nextib: returning status of %s",
						nis_sperrno(res->status));
	ULOCK_TABLE(name, RO, name);
	return (res); /* Return it finally */
}

/*
 * db_flush()
 *
 * Flush any pending "next" entries from a list returned by firstib.
 */
void
db_flush(
	nis_name	name,		/* table name */
	netobj		*cookie)	/* The next_desc */
{
	char	*table;
	db_result *dbres;
	char	tblbuf[NIS_MAXNAMELEN * 2];

	table = internal_table_name(name, tblbuf);
	if (! table)
		return;
	if (verbose)
		syslog(LOG_INFO, "db_flush: Flushing queued entries from %s",
								table);
	{
		int	trylock = 1;
		if (__nis_lock_db_table(name, RO, &trylock, name) == 0) {
			return;
		}
	}

	dbres = db_reset_next_entry(table, (db_next_desc *)cookie);
	if (dbres && dbres->status != DB_SUCCESS) {
		syslog(LOG_ERR, "Unable to flush '%s'", table);
	}
	free_db_result(dbres);
	ULOCK_TABLE(name, RO, name);
}

/*
 * Add an entry to a table, we assume we've already sanitized the
 * data.
 */
static nis_error
__db_addib_x(
	nis_name	name,		/* Name of the table. */
	int		numattr,	/* Number of attributes */
	nis_attr	*attrs,		/* array of attributes */
	nis_object	*obj,		/* Entry to add to the table */
	int		skiplog,	/* if true, don't log action */
	int		nosync)
{
	entry_obj	eo; 		/* our "fake" entry */
	entry_col	*oec, 		/* our objects columns  */
			*ec; 		/* our objects columns  */
	int		i, mc, bufsize;	/* counters		*/
	db_result	*dbres;
	XDR		xdrs;		/* XDR stream		*/
	uchar_t		*buf;
	char		*table;
	nis_error	res;
	struct table_item 	*te;	/* Table cache entry	*/
	struct nis_object	*tobj;	/* Table nis_object 	*/
	char		tblbuf[NIS_MAXNAMELEN * 2]; /* table path buf */
	char		*myself = "__db_addib_x";

	/* Get the number of columns and the pointer to their data */
	mc = obj->EN_data.en_cols.en_cols_len;
	oec = obj->EN_data.en_cols.en_cols_val;

	ec = __get_entry_col(mc+1); /* get some temp storage */

	if (ec == NULL) {
		return (NIS_NOMEMORY);
	}

	table = internal_table_name(name, tblbuf);
	if (! table)
		return (NIS_BADNAME);
	if (verbose)
		syslog(LOG_INFO, "__db_addib: Adding an entry to table %s",
							table);

	LOCK_TABLE(name, WR, res, res, name);
	te = __nis_find_item_mt(name, table_cache, RO, 0);
	if (te == NULL) {
		/* Do a db_lookup() so that cache is populated */
		nis_db_result *dbres;

		if (((dbres = db_lookup_deferred(name, FALSE)) == NULL) ||
		    (dbres->status != NIS_SUCCESS)) {
			ULOCK_TABLE(name, WR, name);
			syslog(LOG_ERR,
			"__db_addib: could not find table object for %s",
				name);
			return (NIS_NOSUCHTABLE);	/* XXX: Error number */
		}
		tobj = dbres->obj;
		/* dbres is freed automatically during cleanup */
	} else
		tobj = te->ibobj;

	/* Build up our temporary entry object */
	eo.en_type = NULL; /* used by cvt2obj - denotes non IN_DIRECTORY */
	eo.en_cols.en_cols_len = mc + 1;
	eo.en_cols.en_cols_val = ec;

	/* Copy the entry value pointers, offset by 1 */
	for (i = 0; i < mc; i++)
		ec[i+1] = oec[i];

	/*
	 * To prevent the XDR function from making a copy of
	 * the entry columns, we set the columns structure to
	 * 0 (ie no column data)
	 */
	obj->EN_data.en_cols.en_cols_len  = 0;	  /* Neuter it	*/
	obj->EN_data.en_cols.en_cols_val  = NULL; /* Neuter it	*/

	/* Make a fetus object from a FULL object */
	bufsize = xdr_sizeof(xdr_nis_object, obj);
	buf = __get_xdr_buf(bufsize);
	if (buf == NULL) {
		if (te != 0)
			__nis_release_item(te, table_cache, RO);
		ULOCK_TABLE(name, WR, name);
		syslog(LOG_ERR, "__db_addib: out of memory!");
		return (NIS_NOMEMORY);
	}

	xdrmem_create(&xdrs, (char *)buf, bufsize, XDR_ENCODE);
	if (! xdr_nis_fetus_object(&xdrs, obj, tobj)) {
		if (te != 0)
			__nis_release_item(te, table_cache, RO);
		ULOCK_TABLE(name, WR, name);
		syslog(LOG_ERR, "__db_addib: Failure to encode entry.");
		return (NIS_SYSTEMERROR);
	}

	/* Un-neuter it so that it can be properly freed */
	obj->EN_data.en_cols.en_cols_len  = mc;
	obj->EN_data.en_cols.en_cols_val  = oec;
	ec[0].ENVAL    = (char *)buf;	/* Point to encoded one	*/
	ec[0].ENLEN    = xdr_getpos(&xdrs);
	ec[0].ec_flags = EN_BINARY+EN_XDR;

	{
		nisdb_tsd_t	fallback, *tsd = __nisdb_get_tsd();
		__nisdb_retry_t	storeRetry = ldapDBTableMapping.
							storeErrorRetry;

		if (tsd == 0) {
			logmsg(MSG_NOMEM, LOG_ERR,
	"%s: No memory for TSD; unable to get full status for DB operation",
				myself);
			tsd = &fallback;
		}

		while (1) {
			/* Establish default status (success) */
			tsd->nisPlusStat = NIS_SUCCESS;
			tsd->ldapStat = LDAP_SUCCESS;

			if (skiplog)
				dbres = __db_add_entry_nolog(table, numattr,
								attrs, &eo);
			else if (nosync)
				dbres = __db_add_entry_nosync(table, numattr,
								attrs, &eo);
			else
				dbres = db_add_entry(table, numattr,
								attrs, &eo);
			if (dbres == 0) {
				res = NIS_NOMEMORY;
				break;
			} else {
				int	rd;

				res = map_db_status_to_nis_status(dbres->
								status);
				if (res == NIS_SUCCESS &&
					tsd->ldapStat == LDAP_SUCCESS &&
					tsd->nisPlusStat == NIS_SUCCESS)
					break;
				/* Unlock while we (possibly) sleep */
				ULOCK_TABLE(name, WR, name);
				rd = storeDone(&storeRetry, tsd->nisPlusStat,
						tsd->ldapStat, &res);
				LOCK_TABLE(name, WR, res, res, name);
				if (rd)
					break;
			}
			free_db_result(dbres);
		}
	}

	switch (res) {
	    case NIS_NOMEMORY:
	    case NIS_NOFILESPACE:
	    case NIS_SYSTEMERROR:
	    case NIS_UNAVAIL:
		break;
	    case NIS_SUCCESS:
		(void) mark_for_sync(table);
		break;
	    default:
		syslog(LOG_ERR, "__db_addib: Unexpected database result %d.",
						dbres->status);
		break;
	}
	if (verbose)
		syslog(LOG_INFO, "__db_addib: done. (%d)", res);
	free_db_result(dbres);
	if (res == NIS_SUCCESS) {
		multival_invalidate(obj);
	}
	if (te != 0)
		__nis_release_item(te, table_cache, RO);
	ULOCK_TABLE(name, WR, name);
	return (res);
}

nis_error
__db_addib(
	nis_name	name,		/* Name of the table. */
	int		numattr,	/* Number of attributes */
	nis_attr	*attrs,		/* array of attributes */
	nis_object	*obj)		/* Entry to add to the table */
{
	return (__db_addib_x(name, numattr, attrs, obj, 0, 0));
}

nis_error
__db_addib_nolog(
	nis_name	name,		/* Name of the table. */
	int		numattr,	/* Number of attributes */
	nis_attr	*attrs,		/* array of attributes */
	nis_object	*obj)		/* Entry to add to the table */
{
	return (__db_addib_x(name, numattr, attrs, obj, 1, 0));
}

nis_error
__db_addib_nosync(
	nis_name	name,		/* Name of the table. */
	int		numattr,	/* Number of attributes */
	nis_attr	*attrs,		/* array of attributes */
	nis_object	*obj)		/* Entry to add to the table */
{
	return (__db_addib_x(name, numattr, attrs, obj, 0, 1));
}

static	nis_db_result	__no_memory_db_result = {NIS_NOMEMORY, 0, 0};

/*
 * Add an entry to a table, we assume we've already sanitized the
 * data.
 */
nis_db_result *
db_addib(
	nis_name	name,		/* Name of the table.	*/
	int		numattr,	/* Number of attributes	*/
	nis_attr	*attrs,		/* array of attributes	*/
	nis_object	*obj,		/* Entry to add to the table */
	nis_object	*tobj)		/* Table to add it too.	*/
{
	nis_attr	*attr_list;
	int		i, mc, na;
	table_col	*tc;
	entry_col	*ec;
	nis_db_result	*res;
	log_entry	le;

	/*
	 * First we create a fully specified entry list, with a
	 * set of attribute/values to go with it.
	 */
	res = (nis_db_result *)XCALLOC(1, sizeof (nis_db_result));
	if (res == 0)
		return (&__no_memory_db_result);
	add_cleanup((void (*)())XFREE, (char *)res, "db_addib result");
	memset((char *)&le, 0, sizeof (le));
	LOCK_TABLE(name, WR, res, res->status, name);
	mc = tobj->TA_data.ta_cols.ta_cols_len;
	tc = tobj->TA_data.ta_cols.ta_cols_val;
	ec = obj->EN_data.en_cols.en_cols_val;
	attr_list = __get_attrs(mc);
	if (attr_list == NULL) {
		ULOCK_TABLE(name, WR, name);
		res->status = NIS_NOMEMORY;
		return (res);
	}
	for (i = 0, na = 0; i < mc; i++) {
		if ((tc[i].tc_flags & TA_SEARCHABLE) != 0) {
			attr_list[na].zattr_ndx = tc[i].tc_name;
			attr_list[na].ZAVAL = ec[i].ENVAL;
			attr_list[na].ZALEN = ec[i].ENLEN;
			na++;
		}
	}
	le.le_name = name;
	le.le_object = *obj;
	le.le_attrs.le_attrs_len = na;
	le.le_attrs.le_attrs_val = attr_list;
	le.le_type = ADD_IBASE;
	le.le_time = obj->zo_oid.mtime;
	add_update(&le);
	__start_clock(1);
	res->status = __db_addib(name, na, attr_list, obj);
	res->ticks = __stop_clock(1);
	if (res->status != NIS_SUCCESS)
		syslog(LOG_ERR, "db_addib: unable to add entry to %s", name);
	ULOCK_TABLE(name, WR, name);
	return (res);
}

nis_error
__db_remib_x(
	nis_name	name,
	int		nattr,
	nis_attr	*attrs,
	int		nosync)
{
	nis_error 	res;
	db_result	*dbres;
	char		*table;
	char		tblbuf[NIS_MAXNAMELEN * 2];
	char		*myself = "__db_remib_x";

	table = internal_table_name(name, tblbuf);
	if (! table)
		return (NIS_BADNAME);

	if (verbose)
		syslog(LOG_INFO,
			"__db_remib: Removing an entry from table %s", table);

	LOCK_TABLE(name, WR, res, res, name);

	{
		nisdb_tsd_t	fallback, *tsd = __nisdb_get_tsd();
		__nisdb_retry_t	storeRetry = ldapDBTableMapping.
							storeErrorRetry;

		if (tsd == 0) {
			logmsg(MSG_NOMEM, LOG_ERR,
	"%s: No memory for TSD; unable to get full status for DB operation",
				myself);
			tsd = &fallback;
		}

		while (1) {
			/* Establish default status (success) */
			tsd->nisPlusStat = NIS_SUCCESS;
			tsd->ldapStat = LDAP_SUCCESS;

			if (nosync)
				dbres = __db_remove_entry_nosync(table, nattr,
								attrs);
			else
				dbres = db_remove_entry(table, nattr, attrs);
			if (dbres == 0) {
				res = NIS_NOMEMORY;
				break;
			} else {
				int	rd;

				res = map_db_status_to_nis_status(dbres->
								status);
				if (res == NIS_SUCCESS &&
					tsd->ldapStat == LDAP_SUCCESS &&
					tsd->nisPlusStat == NIS_SUCCESS)
					break;
				/* Unlock while we (possibly) sleep */
				ULOCK_TABLE(name, WR, name);
				rd = storeDone(&storeRetry, tsd->nisPlusStat,
						tsd->ldapStat, &res);
				LOCK_TABLE(name, WR, res, res, name);
				if (rd)
					break;
			}
			free_db_result(dbres);
		}
	}

	switch (res) {
	case NIS_NOMEMORY:
	case NIS_NOFILESPACE:
	case NIS_SYSTEMERROR:
	case NIS_UNAVAIL:
		break;
	case NIS_SUCCESS:
		(void) mark_for_sync(table);
		break;
	case NIS_NOTFOUND:
		/* this occurs when applying log updates */
		res = NIS_SUCCESS;
		break;
	default:
		syslog(LOG_ERR, "__db_remib: Unexpected database result %d.",
								dbres->status);
		break;
	}
	if (verbose)
		syslog(LOG_INFO, "__db_remib: done. (%d)", res);
	free_db_result(dbres);
	if (res == NIS_SUCCESS) {
		nis_db_result *tres;

		tres = db_lookup_deferred(name, FALSE);
		multival_invalidate(tres->obj);
	}
	ULOCK_TABLE(name, WR, name);
	return (res);
}

nis_error
__db_remib(
	nis_name	name,
	int		nattr,
	nis_attr	*attrs)
{
	return (__db_remib_x(name, nattr, attrs, 0));
}

nis_error
__db_remib_nosync(
	nis_name	name,
	int		nattr,
	nis_attr	*attrs)
{
	return (__db_remib_x(name, nattr, attrs, 1));
}

/*
 * The remove operation. Since it can remove multiple entries we pass it
 * the list for the log entries.
 */
nis_db_result *
db_remib(
	nis_name	name,
	int		nattrs,
	nis_attr	*attrs,
	obj_list	*olist,
	int		numo,
	nis_object	*tobj,
	ulong_t		xid_time)
{
	nis_attr	*attr_list;
	int		i, j, mc, na;
	table_col	*tc;
	entry_col	*ec;
	nis_db_result	*res;
	log_entry	le;
	int		*amap;

	/*
	 * First we create a fully specified entry list, with a
	 * set of attribute/values to go with it.
	 */
	res = (nis_db_result *)XCALLOC(1, sizeof (nis_db_result));
	if (res == 0)
		return (&__no_memory_db_result);
	add_cleanup((void (*)())XFREE, (char *)res, "db_remib result");
	LOCK_TABLE(name, WR, res, res->status, name);
	memset((char *)&le, 0, sizeof (le));
	mc = tobj->TA_data.ta_cols.ta_cols_len;
	tc = tobj->TA_data.ta_cols.ta_cols_val;
	na = 0; /* Actual attrs */
	attr_list = __get_attrs(mc);
	/* Cheat and allocate a "static" array */
	amap = (int *)__get_xdr_buf(sizeof (int) * mc);

	if (attr_list == NULL) {
		ULOCK_TABLE(name, WR, name);
		res->status = NIS_NOMEMORY;
		return (res);
	}
	for (i = 0, na = 0; i < mc; i++) {
		if ((tc[i].tc_flags & TA_SEARCHABLE) != 0) {
			attr_list[na].zattr_ndx = tc[i].tc_name;
			amap[na] = i;
			na++;
		}
	}

	/* Add log updates for all of the entries that will be removed */
	for (i = 0; i < numo; i++) {
		ec = olist[i].o->EN_data.en_cols.en_cols_val;
		for (j = 0; j < na; j++) {
			attr_list[j].ZAVAL = ec[amap[j]].ENVAL;
			attr_list[j].ZALEN = ec[amap[j]].ENLEN;
		}
		le.le_name = name;
		le.le_object = *(olist[i].o);
		le.le_attrs.le_attrs_len = na;
		le.le_attrs.le_attrs_val = attr_list;
		le.le_type = REM_IBASE;
		le.le_time = xid_time;
		add_update(&le);
	}
	__start_clock(1);
	res->status = __db_remib(name, nattrs, attrs);
	res->ticks = __stop_clock(1);
	if (res->status != NIS_SUCCESS)
		syslog(LOG_ERR, "db_remib: unable to remove entry from %s",
			name);
	ULOCK_TABLE(name, WR, name);
	return (res);
}


/*
 * __create_table()
 *
 * Create the underlying database table that supports the current database.
 */
static nis_error
__create_table(
	char		*table,
	nis_object	*obj)
{
	table_obj	fake, *t;	/* Fake table object here. */
	table_col	*tc = NULL; 	/* Fake columns data */
	int		i;

	/* Assume locking done by caller */

	t = &(obj->TA_data);
	tc = __get_table_col(t->ta_cols.ta_cols_len+1);
	if (tc == NULL)
		return (NIS_NOMEMORY);

	for (i = 0; i < t->ta_cols.ta_cols_len; i++) {
		if (t->ta_cols.ta_cols_val[i].tc_flags & TA_SEARCHABLE)
			break;
	}
	if (i == t->ta_cols.ta_cols_len) {
		if (verbose)
			syslog(LOG_INFO,
		"Cannot create table: %s: no searchable columns.", table);
		return (NIS_BADOBJECT);
	}

	/* Copy the important parts of the table structure over */
	fake = obj->TA_data;
	/* Now shift the columns right by 1 */
	for (i = 0; i < fake.ta_cols.ta_cols_len; i++) {
		tc[i+1] = fake.ta_cols.ta_cols_val[i];
	}
	tc[0].tc_name   = NULL; /* NO name for the entry column */
	tc[0].tc_flags  = TA_XDR+TA_BINARY;
	tc[0].tc_rights = 0; /* only the server sees them */
	fake.ta_cols.ta_cols_len++; /* Add one to this */
	fake.ta_cols.ta_cols_val = tc; /* fixup this */
	return (db_create(table, &fake));
}

static cp_result mem_err = {NIS_NOMEMORY, 0, 0};

/*
 * do_checkpoint
 *
 * This function checkpoints the table named, or all tables
 * that the server has if no table is named.
 *
 * NB: This can be time consuming so the server should fork
 *	a readonly child to handle requests while we're out here.
 *
 * This function returns NIS_SUCCESS if all tables were
 * checkpointed and return NIS_PARTIAL otherwise.
 */
static cp_result *
do_checkpoint(
	nis_name	name)	/* name of directory to checkpoint */
{
	int			status;
	cp_result		*res;
	char			*table;
	char			tblbuf[NIS_MAXNAMELEN * 2];

	res = (cp_result *) XCALLOC(1, sizeof (cp_result));
	if (! res)
		return (&mem_err);
	add_cleanup((void (*)())XFREE, (char *)res, "do_chkpt result");

	if (name == NULL)
		table = NULL;
	else
		table = internal_table_name(name, tblbuf);
	if (verbose)
		syslog(LOG_INFO, "Checkpointing table '%s'",
			table ? table : "(all)");
	if (table == 0)
		name = ".";
	LOCK_TABLE(name, WR, res, res->cp_status, name);

	__start_clock(1);
	status = db_checkpoint(table);
	res->cp_dticks = __stop_clock(1);
	if (status != DB_SUCCESS) {
		syslog(LOG_ERR,
		"db_checkpoint: Unable to checkpoint table '%s' because %s",
			(table ? table : "(all)"),
			nis_sperrno(map_db_status_to_nis_status(status)));
		res->cp_status = NIS_PARTIAL;
	} else
		res->cp_status = NIS_SUCCESS;

	ULOCK_TABLE(name, WR, name);
	return (res);
}

/*
 * do_checkpoint_dir
 *
 * This function checkpoints all of the tables in a named directory
 * and the directory itself.
 * This is accomplished by iterating over the directory and then
 * checkpointing anything that looks like a table.
 *
 * NB: This can be time consuming so the server should have forked
 *	a read only child to handle requests while we're out here.
 *
 * This function returns returns NIS_SUCCESS if all tables were
 * checkpointed and returne NIS_PARTIAL if only some of them were.
 */
static cp_result *
do_checkpoint_dir(
	nis_name	name)	/* name of directory to checkpoint */
{
	int			status, err;
	cp_result		*res;
	char			*table;
	char			tblname[NIS_MAXNAMELEN];
	netobj			cookie;
	nis_fn_result		*fnr;
	char			tblbuf[NIS_MAXNAMELEN * 2];

	if (! name)
		return (NULL); /* name is required */

	res = (cp_result *) XCALLOC(1, sizeof (cp_result));
	if (! res)
		return (&mem_err);

	add_cleanup((void (*)())XFREE, (char *)res, "do_chkpt result");

	if (verbose)
		syslog(LOG_INFO, "Checkpointing directory '%s'", name);

	err = 0;
	fnr = db_firstib(name, 0, NULL, FN_NORAGS, NULL);
	cookie = fnr->cookie;
	res->cp_dticks = fnr->ticks;
	/* First, do directory itself. */
	if (fnr->status == NIS_NOTFOUND || fnr->status == NIS_SUCCESS) {
		table = internal_table_name(name, tblbuf);
		__start_clock(1);
		if (verbose)
			syslog(LOG_INFO, "Checkpointing directory '%s'",
				table);
		LOCK_DIRECTORY(name, WR, res->cp_status, name);
		if (res->cp_status == NIS_SUCCESS) {
			status = db_checkpoint(table);
			res->cp_dticks += __stop_clock(1);
			if (status != DB_SUCCESS) {
				syslog(LOG_ERR,
			"db_checkpoint: Unable to checkpoint '%s' because %s",
					(name ? name : "(null)"),
					nis_sperrno(map_db_status_to_nis_status(
								status)));
				err++;
			}
		} else {
			res->cp_dticks += __stop_clock(1);
			syslog(LOG_ERR,
			"db_checkpoint: Unable to checkpoint '%s' because %s",
				(name ? name : "(null)"), res->cp_status);
			err++;
		}
		ULOCK_DIRECTORY(name, WR, name);
	}

	/* Do each table or directory within directory. */
	while (fnr->status == NIS_SUCCESS) {
		if (__type_of(fnr->obj) == NIS_TABLE_OBJ ||
		    __type_of(fnr->obj) == NIS_DIRECTORY_OBJ) {
			sprintf(tblname, "%s.%s", fnr->obj->zo_name,
						fnr->obj->zo_domain);
			table = internal_table_name(tblname, tblbuf);
			__start_clock(1);
			if (verbose)
				syslog(LOG_INFO, "Checkpointing table '%s'",
					table);
			LOCK_TABLE_NORET(tblname, WR, res->cp_status,
					tblname);
			if (res->cp_status == NIS_SUCCESS) {
				status = db_checkpoint(table);
				res->cp_dticks += __stop_clock(1);
				/*
				 * We ignore DB_BADTABLE errors because we might
				 * not serve the contents of the directory.
				 */
				if (status != DB_SUCCESS &&
						status != DB_BADTABLE) {
					syslog(LOG_ERR,
			"db_checkpoint: Unable to checkpoint '%s' because %s",
						(tblname ? tblname : "(null)"),
						nis_sperrno(
						map_db_status_to_nis_status(
								status)));
					err++;
				}
				ULOCK_TABLE(tblname, WR, name);
			} else {
				res->cp_dticks += __stop_clock(1);
				syslog(LOG_ERR,
			"db_checkpoint: Unable to checkpoint '%s' because %s",
			(tblname ? tblname : "(null)"), res->cp_status);
				err++;
			}
		}
		nis_destroy_object(fnr->obj);
		XFREE(fnr);
		/* note the call to nextib frees the old cookie! */
		fnr = db_nextib(name, &cookie, FN_NORAGS, NULL);
		cookie = fnr->cookie;
	}
	XFREE(fnr);
	if (err)
		res->cp_status = NIS_PARTIAL;
	else
		res->cp_status = NIS_SUCCESS;
	return (res);
}

/*
 * nis_checkpoint_svc maintains a list of directories to be
 * checkpointed, call do_checkpoint_dir on items on that list.
 * Otherwise, call do_checkpoint(NULL) to checkpoint entire database.
 */

int
checkpoint_db()
{
	ping_item	*cp, *nxt;
	cp_result	*res;

	LOCK_LIST(&checkpoint_list, "checkpoint_db(checkpoint_list)");
	cp = (ping_item *)(checkpoint_list.first);

	/* No directories specified; checkpoint entire database. */

	if (cp == NULL || checkpoint_all) {
		res = do_checkpoint(NULL);
		clear_checkpoint_list_nolock();
		checkpoint_all = 0;
		/* res is on cleanup list; no need to free. */
		ULOCK_LIST(&checkpoint_list, "checkpoint_db(checkpoint_list)");
		return (1);
	}

	for (cp; cp; cp = nxt) {
		nxt = (ping_item *)(cp->item.nxt_item);
		res = do_checkpoint_dir(cp->item.name);
		if (res->cp_status != NIS_SUCCESS) {
			syslog(LOG_WARNING,
		"checkpoint_db: unable to completely checkpoint %s because %s",
				(cp->item.name ? cp->item.name : "(null)"),
				nis_sperrno(res->cp_status));
		}
		/* ignore status.  Can try checkpoint later if not complete. */
		(void) nis_remove_item(cp->item.name, &checkpoint_list);
		XFREE(cp->item.name);
		if (cp->obj)
			nis_destroy_object(cp->obj);
		XFREE(cp);
	}
	ULOCK_LIST(&checkpoint_list, "checkpoint_db(checkpoint_list)");
	return (1);
}

int
checkpoint_table(char *name)
{
	char *table;
	db_status status;
	char tblbuf[NIS_MAXNAMELEN * 2];
	int ret = 0;

	{
		nis_error	dummy;
		LOCK_TABLE(name, WR, dummy, ret, name);
	}
	table = internal_table_name(name, tblbuf);
	status = db_checkpoint(table);
	if (status != DB_SUCCESS) {
		syslog(LOG_ERR,
		"checkpoint_table: Unable to checkpoint table %s because %s",
			(table ? table : "(null)"),
			nis_sperrno(map_db_status_to_nis_status(status)));
	} else {
		ret = 1;
	}
	ULOCK_TABLE(name, WR, name);
	return (ret);
}

/*
 * Remove all items from checkpoint list. List must be locked by caller.
 */
static int
clear_checkpoint_list_nolock(void)
{
	ping_item	*cp, *nxt;

	for (cp = (ping_item *)(checkpoint_list.first); cp; cp = nxt) {
		nxt = (ping_item *)(cp->item.nxt_item);
		(void) nis_remove_item(cp->item.name, &checkpoint_list);
		XFREE(cp->item.name);
		if (cp->obj)
			nis_destroy_object(cp->obj);
		XFREE(cp);
	}
	return (1);
}

int
clear_checkpoint_list(void) {
	int	ret;

	LOCK_LIST(&checkpoint_list, "clear_checkpoint_list(checkpoint_list)");
	ret = clear_checkpoint_list_nolock();
	ULOCK_LIST(&checkpoint_list, "clear_checkpoint_list(checkpoint_list)");

	return (ret);
}

/*
 * Returns NIS_SUCCESS if table exists; NIS_NOSUCHTABLE if it does not exist.
 * Otherwise, return error returned by database.
 */
nis_error
db_find_table(nis_name name)
{
	char tblbuf[NIS_MAXNAMELEN * 2];
	char *table = internal_table_name(name, tblbuf);
	db_status dstatus;

	if (!table) {
		return (NIS_BADNAME);
	}

	{
		nis_error	ret;
		LOCK_TABLE(name, RO, ret, ret, name);
	}
	dstatus = db_table_exists(table);
	ULOCK_TABLE(name, RO, name);
	return (map_db_status_to_nis_status(dstatus));
}


nis_error
db_create(nis_name name, table_obj *obj)
{
	char tblbuf[NIS_MAXNAMELEN * 2];
	char *table = internal_table_name(name, tblbuf);
	db_status dstatus;
	nis_error err;
	char *myself = "db_create";

	if (! table) {
		return (NIS_BADNAME);
	}

	LOCK_TABLE(name, WR, err, err, name);

	{
		nisdb_tsd_t	fallback, *tsd = __nisdb_get_tsd();
		__nisdb_retry_t	storeRetry = ldapDBTableMapping.
							storeErrorRetry;

		if (tsd == 0) {
			logmsg(MSG_NOMEM, LOG_ERR,
	"%s: No memory for TSD; unable to get full status for DB operation",
				myself);
			tsd = &fallback;
		}

		while (1) {
			int	rd;

			/* Establish default status (success) */
			tsd->nisPlusStat = NIS_SUCCESS;
			tsd->ldapStat = LDAP_SUCCESS;
			dstatus = db_create_table(table, obj);
			err = map_db_status_to_nis_status(dstatus);
			if (dstatus == DB_SUCCESS &&
					tsd->ldapStat == LDAP_SUCCESS &&
					tsd->nisPlusStat == NIS_SUCCESS)
				break;
			ULOCK_TABLE(name, WR, name);
			rd = storeDone(&storeRetry, tsd->nisPlusStat,
						tsd->ldapStat, &err);
			LOCK_TABLE(name, WR, err, err, name);
			if (rd)
				break;
		}
	}

	if (dstatus == DB_SUCCESS)
		(void) mark_for_sync(table);
	err = map_db_status_to_nis_status(dstatus);
	ULOCK_TABLE_REMCOND(name, WR, dstatus != DB_SUCCESS, name);
	return (err);
}

nis_error
db_destroy(nis_name name)
{
	char tblbuf[NIS_MAXNAMELEN * 2];
	char *table = internal_table_name(name, tblbuf);
	db_status dstatus;
	nis_error err;
	char *myself = "db_destroy";

	if (! table) {
		return (NIS_BADNAME);
	}

	LOCK_TABLE(name, WR, err, err, name);

	{
		nisdb_tsd_t	fallback, *tsd = __nisdb_get_tsd();
		__nisdb_retry_t	storeRetry = ldapDBTableMapping.
							storeErrorRetry;

		if (tsd == 0) {
			logmsg(MSG_NOMEM, LOG_ERR,
	"%s: No memory for TSD; unable to get full status for DB operation",
				myself);
			tsd = &fallback;
		}

		while (1) {
			int	rd;

			/* Establish default status (success) */
			tsd->nisPlusStat = NIS_SUCCESS;
			tsd->ldapStat = LDAP_SUCCESS;
			dstatus = db_destroy_table(table);
			err = map_db_status_to_nis_status(dstatus);
			if (dstatus == DB_SUCCESS &&
					tsd->ldapStat == LDAP_SUCCESS &&
					tsd->nisPlusStat == NIS_SUCCESS)
				break;
			ULOCK_TABLE(name, WR, name);
			rd = storeDone(&storeRetry, tsd->nisPlusStat,
						tsd->ldapStat, &err);
			LOCK_TABLE(name, WR, err, err, name);
			if (rd)
				break;
		}
	}

	if (dstatus == DB_SUCCESS)
		(void) mark_for_sync(table);
	ULOCK_TABLE_REMCOND(name, WR, dstatus == DB_SUCCESS, name);
	return (err);
}

static int
mark_for_sync(char *table) {

	table_list_entry_t	*te;
	int			ret = 0;

	MUTEXLOCK(table_list, "mark_for_sync(table_list)");

	for (te = table_list; te != 0; te = te->next) {
		if (strcmp(te->table, table) == 0)
			break;
	}
	if (te == 0 && (te = malloc(sizeof (table_list_entry_t)+
			strlen(table)+1)) != 0) {
		te->table = (char *)((ulong_t)te + sizeof (*te));
		(void) strcpy(te->table, table);
		te->next = table_list;
		table_list = te;
	} else if (te == 0) {
		syslog(LOG_WARNING,
		"mark_for_sync: could not add sync entry for \"%s\"\n", table);
		ret = ENOMEM;
	}

	MUTEXUNLOCK(table_list, "mark_for_sync(table_list)");

	return (ret);
}

int
nis_db_sync_log(void) {

	table_list_entry_t	*te;
	int			ret = 0;
	db_status		stat;

	MUTEXLOCK(table_list, "nis_db_sync_log(table_list)");

	while ((te = table_list) != 0) {
		if ((stat = db_sync_log(te->table)) != DB_SUCCESS) {
			if (verbose)
				syslog(LOG_INFO,
				"nis_db_sync_log: error %d syncing \"%s\"",
				stat, te->table);
			ret++;
		}
		table_list = te->next;
		free(te);
	}

	MUTEXUNLOCK(table_list, "nis_db_sync_log(table_list)");

	return (ret);
}

nis_error
db_configure(char *table) {
	db_status	stat;

	stat = __db_configure(table);
	return (map_db_status_to_nis_status(stat));
}

/*
 * Given an input NIS+ and LDAP status, perform appropriate actions
 * according to retrieveError/refreshError. May set '*outStat'.
 */
int
retrieveDone(__nisdb_retry_t *refreshRetry, __nisdb_retry_t *retrieveRetry,
		int nisPlusStat, int ldapStat, nis_error *outStat) {

	if (ldapStat == LDAP_NO_SUCH_OBJECT) {
		*outStat = NIS_NOTFOUND;
		return (1);
	} else if (ldapStat != LDAP_SUCCESS) {
		/* Tried LDAP, didn't work => retrieve error */
		if (ldapDBTableMapping.retrieveError == use_cached) {
			/* Use refresh error actions */
			if ((ldapDBTableMapping.refreshError ==
						continue_using ||
					ldapDBTableMapping.refreshError ==
						continue_using_retry) &&
					nisPlusStat == NIS_CACHEEXPIRED) {
				*outStat = NIS_SUCCESS;
				return (1);
			} else if (ldapDBTableMapping.refreshError ==
						continue_using ||
					ldapDBTableMapping.refreshError ==
						ref_retry ||
					ldapDBTableMapping.refreshError ==
						continue_using_retry) {
				return (!__nis_retry_sleep(refreshRetry, 0));
			} else if (ldapDBTableMapping.refreshError ==
					cache_expired) {
				*outStat = NIS_CACHEEXPIRED;
				return (1);
			} else {
				*outStat = NIS_TRYAGAIN;
				return (1);
			}
		} else if (ldapDBTableMapping.retrieveError == ret_retry) {
			return (!__nis_retry_sleep(retrieveRetry, 0));
		} else if (ldapDBTableMapping.retrieveError == try_again) {
			*outStat = NIS_TRYAGAIN;
			return (1);
		} else if (ldapDBTableMapping.retrieveError == ret_unavail) {
			*outStat = NIS_UNAVAIL;
			return (1);
		} else if (ldapDBTableMapping.retrieveError == no_such_name) {
			*outStat = NIS_NOSUCHNAME;
			return (1);
		}
	} else if (nisPlusStat != NIS_SUCCESS) {
		if (nisPlusStat == NIS_CACHEEXPIRED &&
				(ldapDBTableMapping.refreshError ==
						continue_using ||
					ldapDBTableMapping.refreshError ==
						continue_using_retry))
			*outStat = NIS_SUCCESS;
		else
			*outStat = nisPlusStat;
		return (1);
	}

	/* Both NIS+ and LDAP status OK => done */
	return (1);
}

/*
 * Given an input NIS+ and LDAP status, perform appropriate actions
 * according to storeError. May set '*outStat'.
 */
int
storeDone(__nisdb_retry_t *storeRetry, int nisPlusStat, int ldapStat,
		nis_error *outStat) {

	if (ldapStat != LDAP_SUCCESS) {
		if (ldapDBTableMapping.storeError == sto_retry) {
			return (!__nis_retry_sleep(storeRetry, 0));
		} else if (ldapDBTableMapping.storeError == system_error) {
			*outStat = NIS_SYSTEMERROR;
			return (1);
		} else if (ldapDBTableMapping.storeError == sto_unavail) {
			*outStat = NIS_UNAVAIL;
			return (1);
		}
	} else if (nisPlusStat != NIS_SUCCESS) {
		*outStat = nisPlusStat;
		return (1);
	}

	/* Both NIS+ and LDAP status OK => done */
	return (1);
}

extern int	loadAllLDAP(int, void *, db_status *);

/*
 * Up-/down-loads LDAP data, depending on the value of
 * ldapConfig.initialUpdate. Returns 0 if the rpc.nisd
 * can start serving data, 1 if it should exit, -1 if
 * there was an error during the load.
 */
int
loadLDAPdata(void) {
	void		*prevCookie, *cookie = 0;
	int		stat, rd;
	db_status	dstat;
	nis_error	nerr;
	__nisdb_retry_t	refresh, retrieve, store;
	char		*myself = "loadLDAPdata";

	refresh = ldapDBTableMapping.refreshErrorRetry;
	retrieve = ldapDBTableMapping.retrieveErrorRetry;
	store = ldapDBTableMapping.storeErrorRetry;

	while (1) {
		switch (ldapConfig.initialUpdate) {
		case ini_none:
			logmsg(MSG_NOTIMECHECK, LOG_INFO,
				"No up-/down-load to/from LDAP");
			return (0);
		case from_ldap:
		case from_ldap_update_only:
			logmsg(MSG_NOTIMECHECK, LOG_INFO,
				"Down-loading data from LDAP");
			prevCookie = cookie;
			stat = loadAllLDAP(1, &cookie, &dstat);
			nerr = map_db_status_to_nis_status(dstat);
			rd = retrieveDone(&refresh, &retrieve,
					nerr, stat, &nerr);
			break;
		case to_ldap:
		case to_ldap_update_only:
			logmsg(MSG_NOTIMECHECK, LOG_INFO,
				"Up-loading data to LDAP");
			prevCookie = cookie;
			stat = loadAllLDAP(0, &cookie, &dstat);
			nerr = map_db_status_to_nis_status(dstat);
			rd = storeDone(&store, nerr, stat, &nerr);
			break;
		default:
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"%s: Unknown initial update option %d",
				myself, ldapConfig.initialUpdate);
			return (-1);
		}

		/*
		 * If we're done (rd != 0), tell the caller if the rpc.nisd
		 * should exit or continue running.
		 */
		if (rd) {
			if (stat != LDAP_SUCCESS || dstat != DB_SUCCESS) {
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"%s: LDAP status 0x%x, DB status %d",
					myself, stat, dstat);
				return (-1);
			}
			switch (ldapConfig.initialUpdate) {
			case from_ldap:
			case to_ldap:
				logmsg(MSG_NOTIMECHECK, LOG_INFO,
					"LDAP load done; continuing");
				return (0);
			case from_ldap_update_only:
			case to_ldap_update_only:
				logmsg(MSG_NOTIMECHECK, LOG_INFO,
					"LDAP load done; terminating");
				return (1);
			default:
				logmsg(MSG_NOTIMECHECK, LOG_INFO,
				"LDAP load internal error; terminating");
				return (-1);
			}
		}

		/*
		 * If the value of the cookie has changed, we've managed
		 * to move on to another mapping, so we reset the retry
		 * structures.
		 */
		if (cookie != prevCookie) {
			refresh = ldapDBTableMapping.refreshErrorRetry;
			retrieve = ldapDBTableMapping.retrieveErrorRetry;
			store = ldapDBTableMapping.storeErrorRetry;
		}
	}

	/* NOTREACHED */
	return (-1);
}
