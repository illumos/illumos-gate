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
 *	db_table.cc
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2015 RackTop Systems.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <stdlib.h>		/* srand48() */
#include <lber.h>
#include <ldap.h>
#include "db_headers.h"
#include "db_table.h"
#include "db_pickle.h"    /* for dump and load */
#include "db_entry.h"
#include "nisdb_mt.h"

#include "ldap_parse.h"
#include "ldap_util.h"
#include "ldap_map.h"
#include "ldap_xdr.h"
#include "nis_hashitem.h"
#include "nisdb_ldap.h"
#include "nis_parse_ldap_conf.h"

static time_t	maxTimeT;

/*
 * Find the largest (positive) value of time_t.
 *
 * If time_t is unsigned, the largest possible value is just ~0.
 * However, if it's signed, then ~0 is negative. Since lint (for
 * sure), and perhaps the compiler too, dislike comparing an
 * unsigned quantity to see if it's less than zero, we compare
 * to one instead. If negative, the largest possible value is
 * th inverse of 2**(N-1), where N is the number of bits in a
 * time_t.
 */
extern "C" {
static void
__setMaxTimeT(void)
{
	unsigned char	b[sizeof (time_t)];
	int		i;

	/* Compute ~0 for an unknown length integer */
	for (i = 0; i < sizeof (time_t); i++) {
		b[i] = 0xff;
	}
	/* Set maxTimeT to ~0 of appropriate length */
	(void) memcpy(&maxTimeT, b, sizeof (time_t));

	if (maxTimeT < 1)
		maxTimeT = ~(1L<<((8*sizeof (maxTimeT))-1));
}
#pragma init(__setMaxTimeT)
}

/* How much to grow table by */
#define	DB_TABLE_GROWTH_INCREMENT 1024

/* 0'th not used; might be confusing. */
#define	DB_TABLE_START 1

/* prevents wrap around numbers from being passed */
#define	CALLOC_LIMIT 536870911

/* Initial table sizes to use before using 1K increments. */
/* This helps conserve memory usage when there are lots of small tables. */
static int tabsizes[] = {
	16,
	128,
	512,
	DB_TABLE_GROWTH_INCREMENT,
	0
	};

/* Returns the next size to use for table */
static long unsigned
get_new_table_size(long unsigned oldsize)
{
	long unsigned newsize = 0, n;
	if (oldsize == 0)
		newsize = tabsizes[0];
	else {
		for (n = 0; newsize = tabsizes[n++]; )
			if (oldsize == newsize) {
				newsize = tabsizes[n];	/* get next size */
				break;
			}
		if (newsize == 0)
			newsize = oldsize + DB_TABLE_GROWTH_INCREMENT;
	}
	return (newsize);
}


/* destructor */
db_free_list::~db_free_list()
{
	WRITELOCKV(this, "w db_free_list::~db_free_list");
	reset();   /* free list entries */
	DESTROYRW(free_list);
}

void
db_free_list::reset()
{
	db_free_entry *current, *nextentry;

	WRITELOCKV(this, "w db_free_list::reset");
	for (current = head; current != NULL; ) {
		nextentry = current->next;
		delete current;
		current = nextentry;
	}
	head = NULL;
	count = 0;
	WRITEUNLOCKV(this, "wu db_free_list::reset");
}

/* Returns the location of a free entry, or NULL, if there aren't any. */
entryp
db_free_list::pop()
{
	WRITELOCK(this, NULL, "w db_free_list::pop");
	if (head == NULL) {
		WRITEUNLOCK(this, NULL, "wu db_free_list::pop");
		return (NULL);
	}
	db_free_entry* old_head = head;
	entryp found = head->where;
	head = head->next;
	delete old_head;
	--count;
	WRITEUNLOCK(this, found, "wu db_free_list::pop");
	return (found);
}

/*
 * Adds given location to the free list.
 * Returns TRUE if successful, FALSE otherwise (when out of memory).
*/
bool_t
db_free_list::push(entryp tabloc)
{
	db_free_entry * newentry = new db_free_entry;

	WRITELOCK(this, FALSE, "w db_free_list::push");
	if (newentry == NULL) {
		WRITEUNLOCK(this, FALSE, "wu db_free_list::push");
	    FATAL3("db_free_list::push: cannot allocation space",
		    DB_MEMORY_LIMIT, FALSE);
	}
	newentry->where = tabloc;
	newentry->next = head;
	head = newentry;
	++count;
	WRITEUNLOCK(this, TRUE, "wu db_free_list::push");
	return (TRUE);
}

/*
 * Returns in a vector the information in the free list.
 * Vector returned is of form: [n free cells][n1][n2][loc1], ..[locn].
 * Leave the first 'n' cells free.
 * n1 is the number of entries that should be in the freelist.
 * n2 is the number of entries actually found in the freelist.
 * [loc1...locn] are the entries.   n2 <= n1 because we never count beyond n1.
 * It is up to the caller to free the returned vector when it is through.
*/
long *
db_free_list::stats(int nslots)
{
	long	realcount = 0,
		i,
		liststart = nslots,		// start of freelist
		listend = nslots+count+2;	// end of freelist
	db_free_entry_p current = head;

	READLOCK(this, NULL, "r db_free_list::stats");

	long *answer = (long *)malloc((int)(listend)*sizeof (long));
	if (answer == 0) {
		READUNLOCK(this, NULL, "ru db_free_list::stats");
		FATAL3("db_free_list::stats:  cannot allocation space",
		    DB_MEMORY_LIMIT, NULL);
	}

	answer[liststart] = count;  /* size of freelist */

	for (i = liststart+2; i < listend && current != NULL; i++) {
		answer[i] = current->where;
		current = current->next;
		++realcount;
	}

	answer[liststart+1] = realcount;
	READUNLOCK(this, answer, "ru db_free_list::stats");
	return (answer);
}


/* Set default values for the mapping structure */
void
db_table::initMappingStruct(__nisdb_table_mapping_t *m) {
	if (m == 0)
		return;

	m->initTtlLo = (ldapDBTableMapping.initTtlLo > 0) ?
			ldapDBTableMapping.initTtlLo : (3600-1800);
	m->initTtlHi = (ldapDBTableMapping.initTtlHi > 0) ?
			ldapDBTableMapping.initTtlHi : (3600+1800);
	m->ttl = (ldapDBTableMapping.ttl > 0) ?
			ldapDBTableMapping.ttl : 3600;
	m->enumExpire = 0;
	m->fromLDAP = FALSE;
	m->toLDAP = FALSE;
	m->isMaster = FALSE;
	m->retrieveError = ldapDBTableMapping.retrieveError;
	m->retrieveErrorRetry.attempts =
		ldapDBTableMapping.retrieveErrorRetry.attempts;
	m->retrieveErrorRetry.timeout =
		ldapDBTableMapping.retrieveErrorRetry.timeout;
	m->storeError = ldapDBTableMapping.storeError;
	m->storeErrorRetry.attempts =
		ldapDBTableMapping.storeErrorRetry.attempts;
	m->storeErrorRetry.timeout =
		ldapDBTableMapping.storeErrorRetry.timeout;
	m->storeErrorDisp = ldapDBTableMapping.storeErrorDisp;
	m->refreshError = ldapDBTableMapping.refreshError;
	m->refreshErrorRetry.attempts =
		ldapDBTableMapping.refreshErrorRetry.attempts;
	m->refreshErrorRetry.timeout =
		ldapDBTableMapping.refreshErrorRetry.timeout;
	m->matchFetch = ldapDBTableMapping.matchFetch;

	if (mapping.expire != 0)
		free(mapping.expire);
	m->expire = 0;

	if (m->tm != 0)
		free(m->tm);
	m->tm = 0;

	/*
	 * The 'objType' field obviously indicates the type of object.
	 * However, we also use it to tell us if we've retrieved mapping
	 * data from LDAP or not; in the latter case, 'objType' is
	 * NIS_BOGUS_OBJ. For purposes of maintaining expiration times,
	 * we may need to know if the object is a table or a directory
	 * _before_ we've retrieved any mapping data. Hence the 'expireType'
	 * field, which starts as NIS_BOGUS_OBJ (meaning, don't know, assume
	 * directory for now), and later is set to NIS_DIRECTORY_OBJ
	 * (always keep expiration data, in case one of the dir entries
	 * is mapped) or NIS_TABLE_OBJ (only need expiration data if
	 * tha table is mapped).
	 */
	m->objType = NIS_BOGUS_OBJ;
	m->expireType = NIS_BOGUS_OBJ;
	if (m->objName != 0)
		free(m->objName);
	m->objName = 0;
}

void
db_table::db_table_ldap_init(void) {

	INITRW(table);

	enumMode.flag = 0;
	enumCount.flag = 0;
	enumIndex.ptr = 0;
	enumArray.ptr = 0;

	mapping.expire = 0;
	mapping.tm = 0;
	mapping.objName = 0;
	mapping.isDeferredTable = FALSE;
	(void) mutex_init(&mapping.enumLock, 0, 0);
	mapping.enumTid = 0;
	mapping.enumStat = -1;
	mapping.enumDeferred = 0;
	mapping.enumEntries = 0;
	mapping.enumTime = 0;
}

/* db_table constructor */
db_table::db_table() : freelist()
{
	tab = NULL;
	table_size = 0;
	last_used = 0;
	count = 0;

	db_table_ldap_init();
	initMappingStruct(&mapping);

/*  grow(); */
}

/*
 * db_table destructor:
 * 1.  Get rid of contents of freelist
 * 2.  delete all entries hanging off table
 * 3.  get rid of table itself
*/
db_table::~db_table()
{
	WRITELOCKV(this, "w db_table::~db_table");
	reset();
	DESTROYRW(table);
}

/* reset size and pointers */
void
db_table::reset()
{
	int i, done = 0;

	WRITELOCKV(this, "w db_table::reset");
	freelist.reset();

	/* Add sanity check in case of table corruption */
	if (tab != NULL) {
		for (i = 0;
			i <= last_used && i < table_size && done < count;
			i++) {
			if (tab[i]) {
				free_entry(tab[i]);
				++done;
			}
		}
	}

	delete tab;
	table_size = last_used = count = 0;
	tab = NULL;
	sfree(mapping.expire);
	mapping.expire = NULL;
	mapping.objType = NIS_BOGUS_OBJ;
	mapping.expireType = NIS_BOGUS_OBJ;
	sfree(mapping.objName);
	mapping.objName = 0;
	/* Leave other values of the mapping structure unchanged */
	enumMode.flag = 0;
	enumCount.flag = 0;
	sfree(enumIndex.ptr);
	enumIndex.ptr = 0;
	sfree(enumArray.ptr);
	enumArray.ptr = 0;
	WRITEUNLOCKV(this, "wu db_table::reset");
}

db_status
db_table::allocateExpire(long oldSize, long newSize) {
	time_t			*newExpire;

	newExpire = (time_t *)realloc(mapping.expire,
				newSize * sizeof (mapping.expire[0]));
	if (newExpire != NULL) {
		/* Initialize new portion */
		(void) memset(&newExpire[oldSize], 0,
				(newSize-oldSize) * sizeof (newExpire[0]));
		mapping.expire = newExpire;
	} else {
		return (DB_MEMORY_LIMIT);
	}

	return (DB_SUCCESS);
}

db_status
db_table::allocateEnumArray(long oldSize, long newSize) {
	entry_object	**newEnumArray;
	const char	*myself = "db_table::allocateEnumArray";

	if (enumCount.flag > 0) {
		if (enumIndex.ptr == 0) {
			enumIndex.ptr = (entryp *)am(myself, enumCount.flag *
						sizeof (entryp));
			if (enumIndex.ptr == 0)
				return (DB_MEMORY_LIMIT);
		}
		oldSize = 0;
		newSize = enumCount.flag;
	}
	newEnumArray = (entry_object **)realloc(enumArray.ptr,
			newSize * sizeof (entry_object *));
	if (newEnumArray != 0 && newSize > oldSize) {
		(void) memcpy(&newEnumArray[oldSize], &tab[oldSize],
			(newSize-oldSize) * sizeof (entry_object *));
		enumArray.ptr = newEnumArray;
	} else if (newEnumArray == 0) {
		return (DB_MEMORY_LIMIT);
	}

	return (DB_SUCCESS);
}

/* Expand the table.  Fatal error if insufficient memory. */
void
db_table::grow()
{
	WRITELOCKV(this, "w db_table::grow");
	long oldsize = table_size;
	entry_object_p *oldtab = tab;
	long i;

	table_size = get_new_table_size(oldsize);

#ifdef DEBUG
	fprintf(stderr, "db_table GROWING to %d\n", table_size);
#endif

	if (table_size > CALLOC_LIMIT) {
		table_size = oldsize;
		WRITEUNLOCKV(this, "wu db_table::grow");
		FATAL("db_table::grow: table size exceeds calloc limit",
			DB_MEMORY_LIMIT);
	}

//  if ((tab = new entry_object_p[table_size]) == NULL)
	if ((tab = (entry_object_p*)
		calloc((unsigned int) table_size,
			sizeof (entry_object_p))) == NULL) {
		tab = oldtab;		// restore previous table info
		table_size = oldsize;
		WRITEUNLOCKV(this, "wu db_table::grow");
		FATAL("db_table::grow: cannot allocate space", DB_MEMORY_LIMIT);
	}

	/*
	 * For directories, we may need the expire time array even if the
	 * directory itself isn't mapped. If the objType and expireType both
	 * are bogus, we don't  know yet if this is a table or a directory,
	 * and must proceed accordingly.
	 */
	if (mapping.objType == NIS_DIRECTORY_OBJ ||
			mapping.expireType != NIS_TABLE_OBJ ||
			mapping.fromLDAP) {
		db_status stat = allocateExpire(oldsize, table_size);
		if (stat != DB_SUCCESS) {
			free(tab);
			tab = oldtab;
			table_size = oldsize;
			WRITEUNLOCKV(this, "wu db_table::grow expire");
			FATAL(
		"db_table::grow: cannot allocate space for expire", stat);
		}
	}

	if (oldtab != NULL) {
		for (i = 0; i < oldsize; i++) { // transfer old to new
			tab[i] = oldtab[i];
		}
		delete oldtab;
	}

	if (enumMode.flag) {
		db_status stat = allocateEnumArray(oldsize, table_size);
		if (stat != DB_SUCCESS) {
			free(tab);
			tab = oldtab;
			table_size = oldsize;
			WRITEUNLOCKV(this, "wu db_table::grow enumArray");
			FATAL(
		"db_table::grow: cannot allocate space for enumArray", stat);
		}
	}

	WRITEUNLOCKV(this, "wu db_table::grow");
}

/*
 * Return the first entry in table, also return its position in
 * 'where'.  Return NULL in both if no next entry is found.
 */
entry_object*
db_table::first_entry(entryp * where)
{
	ASSERTRHELD(table);
	if (count == 0 || tab == NULL) {  /* empty table */
		*where = NULL;
		return (NULL);
	} else {
		entryp i;
		for (i = DB_TABLE_START;
			i < table_size && i <= last_used; i++) {
			if (tab[i] != NULL) {
				*where = i;
				return (tab[i]);
			}
		}
	}
	*where = NULL;
	return (NULL);
}

/*
 * Return the next entry in table from 'prev', also return its position in
 * 'newentry'.  Return NULL in both if no next entry is found.
 */
entry_object *
db_table::next_entry(entryp prev, entryp* newentry)
{
	long i;

	ASSERTRHELD(table);
	if (prev >= table_size || tab == NULL || tab[prev] == NULL)
		return (NULL);
	for (i = prev+1; i < table_size && i <= last_used; i++) {
		if (tab[i] != NULL) {
			*newentry = i;
			return (tab[i]);
		}
	}
	*newentry = NULL;
	return (NULL);
}

/* Return entry at location 'where', NULL if location is invalid. */
entry_object *
db_table::get_entry(entryp where)
{
	ASSERTRHELD(table);
	if (where < table_size && tab != NULL && tab[where] != NULL)
		return (tab[where]);
	else
		return (NULL);
}

void
db_table::setEntryExp(entryp where, entry_obj *obj, int initialLoad) {
	nis_object		*o;
	const char		*myself = "db_table::setEntryExp";

	/*
	 * If we don't know what type of object this is yet, we
	 * can find out now. If it's a directory, the pseudo-object
	 * in column zero will have the type "IN_DIRECTORY";
	 * otherwise, it's a table object.
	 */
	if (mapping.expireType == NIS_BOGUS_OBJ) {
		if (obj != 0) {
			if (obj->en_type != 0 &&
				strcmp(obj->en_type, "IN_DIRECTORY") == 0) {
				mapping.expireType = NIS_DIRECTORY_OBJ;
			} else {
				mapping.expireType = NIS_TABLE_OBJ;
				if (!mapping.fromLDAP) {
					free(mapping.expire);
					mapping.expire = 0;
				}
			}
		}
	}

	/* Set the entry TTL */
	if (mapping.expire != NULL) {
		struct timeval	now;
		time_t		lo, hi, ttl;

		(void) gettimeofday(&now, NULL);
		if (mapping.expireType == NIS_TABLE_OBJ) {
			lo = mapping.initTtlLo;
			hi = mapping.initTtlHi;
			ttl = mapping.ttl;
			/* TTL == 0 means always expired */
			if (ttl == 0)
				ttl = -1;
		} else {
			__nis_table_mapping_t	*t = 0;

			o = unmakePseudoEntryObj(obj, 0);
			if (o != 0) {
				__nis_buffer_t	b = {0, 0};

				bp2buf(myself, &b, "%s.%s",
					o->zo_name, o->zo_domain);
				t = getObjMapping(b.buf, 0, 1, 0, 0);
				sfree(b.buf);
				nis_destroy_object(o);
			}

			if (t != 0) {
				lo = t->initTtlLo;
				hi = t->initTtlHi;
				ttl = t->ttl;
				/* TTL == 0 means always expired */
				if (ttl == 0)
					ttl = -1;
			} else {
				/*
				 * No expiration time initialization
				 * data. Cook up values that will
				 * result in mapping.expire[where]
				 * set to maxTimeT.
				 */
				hi = lo = ttl = maxTimeT - now.tv_sec;
			}
		}

		if (initialLoad) {
			int	interval = hi - lo + 1;
			if (interval <= 1) {
				mapping.expire[where] = now.tv_sec + lo;
			} else {
				srand48(now.tv_sec);
				mapping.expire[where] = now.tv_sec +
							(lrand48() % interval);
			}
			if (mapping.enumExpire == 0 ||
					mapping.expire[where] <
							mapping.enumExpire)
				mapping.enumExpire = mapping.expire[where];
		} else {
			mapping.expire[where] = now.tv_sec + ttl;
		}
	}
}

/*
 * Add given entry to table in first available slot (either look in freelist
 * or add to end of table) and return the the position of where the record
 * is placed. 'count' is incremented if entry is added. Table may grow
 * as a side-effect of the addition. Copy is made of input.
*/
entryp
db_table::add_entry(entry_object *obj, int initialLoad) {
	/*
	 * We're returning an index of the table array, so the caller
	 * should hold a lock until done with the index. To save us
	 * the bother of upgrading to a write lock, it might as well
	 * be a write lock to begin with.
	 */
	ASSERTWHELD(table);
	entryp where = freelist.pop();
	if (where == NULL) {				/* empty freelist */
		if (last_used >= (table_size-1))	/* full (> is for 0) */
			grow();
		where = ++last_used;
	}
	if (tab != NULL) {
		++count;
		setEntryExp(where, obj, initialLoad);

		if (enumMode.flag)
			enumTouch(where);
		tab[where] = new_entry(obj);
		return (where);
	} else {
		return (NULL);
	}
}

/*
 * Replaces object at specified location by given entry.
 * Returns TRUE if replacement successful; FALSE otherwise.
 * There must something already at the specified location, otherwise,
 * replacement fails. Copy is not made of the input.
 * The pre-existing entry is freed.
 */
bool_t
db_table::replace_entry(entryp where, entry_object * obj)
{
	ASSERTWHELD(table);
	if (where < DB_TABLE_START || where >= table_size ||
	    tab == NULL || tab[where] == NULL)
		return (FALSE);
	/* (Re-)set the entry TTL */
	setEntryExp(where, obj, 0);

	if (enumMode.flag)
		enumTouch(where);
	free_entry(tab[where]);
	tab[where] = obj;
	return (TRUE);
}

/*
 * Deletes entry at specified location.  Returns TRUE if location is valid;
 * FALSE if location is invalid, or the freed location cannot be added to
 * the freelist.  'count' is decremented if the deletion occurs.  The object
 * at that location is freed.
 */
bool_t
db_table::delete_entry(entryp where)
{
	bool_t	ret = TRUE;

	ASSERTWHELD(table);
	if (where < DB_TABLE_START || where >= table_size ||
	    tab == NULL || tab[where] == NULL)
		return (FALSE);
	if (mapping.expire != NULL) {
		mapping.expire[where] = 0;
	}
	if (enumMode.flag)
		enumTouch(where);
	free_entry(tab[where]);
	tab[where] = NULL;    /* very important to set it to null */
	--count;
	if (where == last_used) { /* simple case, deleting from end */
		--last_used;
		return (TRUE);
	} else {
		return (freelist.push(where));
	}
	return (ret);
}

/*
 * Returns statistics of table.
 * [vector_size][table_size][last_used][count][freelist].
 * It is up to the caller to free the returned vector when it is through.
 * The free list is included if 'fl' is TRUE.
*/
long *
db_table::stats(bool_t include_freelist)
{
	long *answer;

	READLOCK(this, NULL, "r db_table::stats");
	if (include_freelist)
		answer = freelist.stats(3);
	else {
		answer = (long *)malloc(3*sizeof (long));
	}

	if (answer) {
		answer[0] = table_size;
		answer[1] = last_used;
		answer[2] = count;
	}
	READUNLOCK(this, answer, "ru db_table::stats");
	return (answer);
}

bool_t
db_table::configure(char *tablePath) {
	long		i;
	struct timeval	now;
	const char	*myself = "db_table::configure";

	(void) gettimeofday(&now, NULL);

	WRITELOCK(this, FALSE, "db_table::configure w");

	/* (Re-)initialize from global info */
	initMappingStruct(&mapping);

	/* Retrieve table mapping for this table */
	mapping.tm = (__nis_table_mapping_t *)__nis_find_item_mt(
					tablePath, &ldapMappingList, 0, 0);
	if (mapping.tm != 0) {
		__nis_object_dn_t	*odn = mapping.tm->objectDN;

		/*
		 * The mapping.fromLDAP and mapping.toLDAP fields serve as
		 * quick-references that tell us if mapping is enabled.
		 * Hence, initialize them appropriately from the table
		 * mapping objectDN.
		 */
		while (odn != 0 && (!mapping.fromLDAP || !mapping.toLDAP)) {
			if (odn->read.scope != LDAP_SCOPE_UNKNOWN)
				mapping.fromLDAP = TRUE;
			if (odn->write.scope != LDAP_SCOPE_UNKNOWN)
				mapping.toLDAP = TRUE;
			odn = (__nis_object_dn_t *)odn->next;
		}

		/* Set the timeout values */
		mapping.initTtlLo = mapping.tm->initTtlLo;
		mapping.initTtlHi = mapping.tm->initTtlHi;
		mapping.ttl = mapping.tm->ttl;

		mapping.objName = sdup(myself, T, mapping.tm->objName);
		if (mapping.objName == 0 && mapping.tm->objName != 0) {
			WRITEUNLOCK(this, FALSE,
				"db_table::configure wu objName");
			FATAL3("db_table::configure objName",
				DB_MEMORY_LIMIT, FALSE);
		}
	}

	/*
	 * In order to initialize the expiration times, we need to know
	 * if 'this' represents a table or a directory. To that end, we
	 * find an entry in the table, and invoke setEntryExp() on it.
	 * As a side effect, setEntryExp() will examine the pseudo-object
	 * in the entry, and set the expireType accordingly.
	 */
	if (tab != 0) {
		for (i = 0; i <= last_used; i++) {
			if (tab[i] != NULL) {
				setEntryExp(i, tab[i], 1);
				break;
			}
		}
	}

	/*
	 * If mapping from an LDAP repository, make sure we have the
	 * expiration time array.
	 */
	if ((mapping.expireType != NIS_TABLE_OBJ || mapping.fromLDAP) &&
			mapping.expire == NULL && table_size > 0 && tab != 0) {
		db_status stat = allocateExpire(0, table_size);
		if (stat != DB_SUCCESS) {
			WRITEUNLOCK(this, FALSE,
				"db_table::configure wu expire");
			FATAL3("db_table::configure expire",
				stat, FALSE);
		}
	} else if (mapping.expireType == NIS_TABLE_OBJ && !mapping.fromLDAP &&
			mapping.expire != NULL) {
		/* Not using expiration times */
		free(mapping.expire);
		mapping.expire = NULL;
	}

	/*
	 * Set initial expire times for entries that don't already have one.
	 * Establish the enumeration expiration time to be the minimum of
	 * all expiration times in the table, though no larger than current
	 * time plus initTtlHi.
	 */
	if (mapping.expire != NULL) {
		int	interval = mapping.initTtlHi - mapping.initTtlLo + 1;
		time_t	enumXp = now.tv_sec + mapping.initTtlHi;

		if (interval > 1)
			srand48(now.tv_sec);
		for (i = 0; i <= last_used; i++) {
			if (tab[i] != NULL && mapping.expire[i] == 0) {
				if (mapping.expireType == NIS_TABLE_OBJ) {
					if (interval > 1)
						mapping.expire[i] =
							now.tv_sec +
							(lrand48() % interval);
					else
						mapping.expire[i] =
							now.tv_sec +
							mapping.initTtlLo;
				} else {
					setEntryExp(i, tab[i], 1);
				}
			}
			if (enumXp > mapping.expire[i])
				enumXp = mapping.expire[i];
		}
		mapping.enumExpire = enumXp;
	}

	WRITEUNLOCK(this, FALSE, "db_table::configure wu");

	return (TRUE);
}

/* Return TRUE if the entry at 'loc' hasn't expired */
bool_t
db_table::cacheValid(entryp loc) {
	bool_t		ret;
	struct timeval	now;

	(void) gettimeofday(&now, 0);

	READLOCK(this, FALSE, "db_table::cacheValid r");

	if (loc < 0 || loc >= table_size || tab == 0 || tab[loc] == 0)
		ret = FALSE;
	else if (mapping.expire == 0 || mapping.expire[loc] >= now.tv_sec)
		ret = TRUE;
	else
		ret = FALSE;

	READUNLOCK(this, ret, "db_table::cacheValid ru");

	return (ret);
}

/*
 * If the supplied object has the same content as the one at 'loc',
 * update the expiration time for the latter, and return TRUE.
 */
bool_t
db_table::dupEntry(entry_object *obj, entryp loc) {
	if (obj == 0 || loc < 0 || loc >= table_size || tab == 0 ||
			tab[loc] == 0)
		return (FALSE);

	if (sameEntry(obj, tab[loc])) {
		setEntryExp(loc, tab[loc], 0);

		if (enumMode.flag > 0)
			enumTouch(loc);
		return (TRUE);
	}

	return (FALSE);
}

/*
 * If enumeration mode is enabled, we keep a shadow array that initially
 * starts out the same as 'tab'. Any update activity (add, remove, replace,
 * or update timestamp) for an entry in the table means we delete the shadow
 * array pointer. When ending enumeration mode, we return the shadow array.
 * Any non-NULL entries in the array have not been updated since the start
 * of the enum mode.
 *
 * The indended use is for enumeration of an LDAP container, where we
 * will update all entries that currently exist in LDAP. The entries we
 * don't update are those that don't exist in LDAP, and thus should be
 * removed.
 *
 * Note that any LDAP query strictly speaking can be a partial enumeration
 * (i.e., return more than one match). Since the query might also have
 * matched multiple local DB entries, we need to do the same work as for
 * enumeration for any query. In order to avoid having to work on the
 * whole 'tab' array for simple queries (which we expect usually will
 * match just one or at most a few entries), we have a "reduced" enum mode,
 * where the caller supplies a count of the number of DB entries (derived
 * from db_mindex::satisfy_query() or similar), and then uses enumSetup()
 * to specify which 'tab' entries we're interested in.
 */
void
db_table::setEnumMode(long enumNum) {
	const char	*myself = "setEnumMode";

	enumMode.flag++;
	if (enumMode.flag == 1) {
		db_status	stat;

		if (enumNum < 0)
			enumNum = 0;
		else if (enumNum >= table_size)
			enumNum = table_size;

		enumCount.flag = enumNum;

		stat = allocateEnumArray(0, table_size);

		if (stat != DB_SUCCESS) {
			enumMode.flag = 0;
			enumCount.flag = 0;
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
		"%s: No memory for enum check array; entry removal disabled",
				myself);
		}
	}
}

void
db_table::clearEnumMode(void) {
	if (enumMode.flag > 0) {
		enumMode.flag--;
		if (enumMode.flag == 0) {
			sfree(enumArray.ptr);
			enumArray.ptr = 0;
			if (enumCount.flag > 0) {
				sfree(enumIndex.ptr);
				enumIndex.ptr = 0;
				enumCount.flag = 0;
			}
		}
	}
}

entry_object **
db_table::endEnumMode(long *numEa) {
	if (enumMode.flag > 0) {
		enumMode.flag--;
		if (enumMode.flag == 0) {
			entry_obj	**ea = (entry_object **)enumArray.ptr;
			long		nea;

			enumArray.ptr = 0;

			if (enumCount.flag > 0) {
				nea = enumCount.flag;
				enumCount.flag = 0;
				sfree(enumIndex.ptr);
				enumIndex.ptr = 0;
			} else {
				nea = table_size;
			}

			if (numEa != 0)
				*numEa = nea;

			return (ea);
		}
	}

	if (numEa != 0)
		*numEa = 0;

	return (0);
}

/*
 * Set the appropriate entry in the enum array to NULL.
 */
void
db_table::enumTouch(entryp loc) {
	if (loc < 0 || loc >= table_size)
		return;

	if (enumMode.flag > 0) {
		if (enumCount.flag < 1) {
			((entry_object **)enumArray.ptr)[loc] = 0;
		} else {
			int	i;

			for (i = 0; i < enumCount.flag; i++) {
				if (loc == ((entryp *)enumIndex.ptr)[i]) {
					((entry_object **)enumArray.ptr)[i] = 0;
					break;
				}
			}
		}
	}
}

/*
 * Add the entry indicated by 'loc' to the enumIndex array, at 'index'.
 */
void
db_table::enumSetup(entryp loc, long index) {
	if (enumMode.flag == 0 || loc < 0 || loc >= table_size ||
			index < 0 || index >= enumCount.flag)
		return;

	((entryp *)enumIndex.ptr)[index] = loc;
	((entry_object **)enumArray.ptr)[index] = tab[loc];
}

/*
 * Touch, i.e., update the expiration time for the entry. Also, if enum
 * mode is in effect, mark the entry used for enum purposes.
 */
void
db_table::touchEntry(entryp loc) {
	if (loc < 0 || loc >= table_size || tab == 0 || tab[loc] == 0)
		return;

	setEntryExp(loc, tab[loc], 0);

	enumTouch(loc);
}

/* ************************* pickle_table ********************* */
/* Does the actual writing to/from file specific for db_table structure. */
/*
 * This was a static earlier with the func name being transfer_aux. The
 * backup and restore project needed this to copy files over.
 */
bool_t
transfer_aux_table(XDR* x, pptr dp)
{
	return (xdr_db_table(x, (db_table*) dp));
}

class pickle_table: public pickle_file {
    public:
	pickle_table(char *f, pickle_mode m) : pickle_file(f, m) {}

	/* Transfers db_table structure pointed to by dp to/from file. */
	int transfer(db_table* dp)
	{ return (pickle_file::transfer((pptr) dp, &transfer_aux_table)); }
};

/*
 * Writes the contents of table, including the all the entries, into the
 * specified file in XDR format.  May need to change this to use APPEND
 * mode instead.
 */
int
db_table::dump(char *file)
{
	int	ret;
	READLOCK(this, -1, "r db_table::dump");
	pickle_table f(file, PICKLE_WRITE);   /* may need to use APPEND mode */
	int status = f.transfer(this);

	if (status == 1)
		ret = -1;
	else
		ret = status;
	READUNLOCK(this, ret, "ru db_table::dump");
}

/* Constructor that loads in the table from the given file */
db_table::db_table(char *file)  : freelist()
{
	pickle_table f(file, PICKLE_READ);
	tab = NULL;
	table_size = last_used = count = 0;

	/* load  table */
	if (f.transfer(this) < 0) {
		/* fell through, something went wrong, initialize to null */
		tab = NULL;
		table_size = last_used = count = 0;
		freelist.init();
	}

	db_table_ldap_init();
	initMappingStruct(&mapping);
}

/* Returns whether location is valid. */
bool_t db_table::entry_exists_p(entryp i) {
	bool_t	ret = FALSE;
	READLOCK(this, FALSE, "r db_table::entry_exists_p");
	if (tab != NULL && i < table_size)
		ret = tab[i] != NULL;
	READUNLOCK(this, ret, "ru db_table::entry_exists_p");
	return (ret);
}

/* Empty free list */
void db_free_list::init() {
	WRITELOCKV(this, "w db_free_list::init");
	head = NULL;
	count = 0;
	WRITEUNLOCKV(this, "wu db_free_list::init");
}
