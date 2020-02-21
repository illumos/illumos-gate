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
 *	db_index.cc
 *
 *  Copyright 1988-2002 Sun Microsystems, Inc.  All rights reserved.
 *  Use is subject to license terms.
 */

#include <stdio.h>
#include <malloc.h>
#include "db_headers.h"
#include "db_index.h"
#include "db_pickle.h"

#include "nisdb_mt.h"
#include "nisdb_rw.h"

static int hashsizes[] = {		/* hashtable sizes */
	11,
	113,
	337,
	977,
	2053,
	4073,
	8011,
	16001,
	0
};

// prevents wrap around numbers from being passed
#define	CALLOC_LIMIT 536870911

/* Constructor: creates empty index. */
db_index::db_index()
{
	tab = NULL;
	table_size = 0;
	count = 0;
	case_insens = FALSE;
	INITRW(index);
/*  grow(); */
}


/* Destructor: deletes index, including all associated db_index_entry. */
db_index::~db_index()
{
	WRITELOCKV(this, "w db_index::~db_index");
	reset();
	DESTROYRW(index);
}

/* Get rid of table and all associated entries, and reset counters */
void
db_index::reset()
{
	db_index_entry * curr, *n;
	int i;

	WRITELOCKV(this, "w db_index::reset");
	/* Add sanity test in case table was corrupted */
	if (tab != NULL) {
		for (i = 0; i < table_size; i++) {	// go through table
			curr = tab[i];
			while (curr != NULL) {		// go through bucket
				n = curr->getnextentry();
				delete curr;
				curr = n;
			}
		}
	}

	delete tab;				// get rid of table itself

	tab = NULL;
	table_size = count = 0;
	WRITEUNLOCKV(this, "wu db_index::reset");
}


/*
 * Initialize index according to the specification of the key descriptor
 * Currently, only affects case_insens flag of index.
 */
void
db_index::init(db_key_desc * k)
{
	WRITELOCKV(this, "w db_index::init");
	if ((k->key_flags)&DB_KEY_CASE)
		case_insens = TRUE;
	WRITEUNLOCKV(this, "wu db_index::init");
}

/* Returns the next size to use for the hash table */
static long unsigned
get_next_hashsize(long unsigned oldsize)
{
	long unsigned newsize = 0, n;
	if (oldsize == 0)
		newsize = hashsizes[0];
	else {
		for (n = 0; newsize = hashsizes[n++]; )
			if (oldsize == newsize) {
				newsize = hashsizes[n];	/* get next size */
				break;
			}
		if (newsize == 0)
			newsize = oldsize * 2 + 1;	/* just double */
	}
	return (newsize);
}

/*
 * Grow the current hashtable upto the next size.
 *    The contents of the existing hashtable is copied to the new one and
 *    relocated according to its hashvalue relative to the new size.
 *    Old table is deleted after the relocation.
 */
void
db_index::grow()
{
	long unsigned oldsize = table_size, i;
	db_index_entry_p * oldtab = tab;

	WRITELOCKV(this, "w db_index::grow");
	table_size = get_next_hashsize(table_size);

#ifdef DEBUG
	if (debug > 3)
		fprintf(ddt, "savehash GROWING to %d\n", table_size);
#endif

	if (table_size > CALLOC_LIMIT) {
		table_size = oldsize;
		WRITEUNLOCKV(this,
			"wu db_index::grow: table size exceeds calloc limit");
		FATAL("db_index::grow: table size exceeds calloc limit",
			DB_MEMORY_LIMIT);
	}

	if ((tab = (db_index_entry_p*)
		calloc((unsigned int) table_size,
			sizeof (db_index_entry_p))) == NULL) {
		tab = oldtab;		// restore previous table info
		table_size = oldsize;
		WRITEUNLOCKV(this,
			"wu db_index::grow: cannot allocate space");
		FATAL("db_index::grow: cannot allocate space", DB_MEMORY_LIMIT);
	}

	if (oldtab != NULL) {		// must transfer contents of old to new
		for (i = 0; i < oldsize; i++) {
			oldtab[i]->relocate(tab, table_size);
		}
		delete oldtab;		// delete old hashtable
	}
	WRITEUNLOCKV(this, "wu db_index::grow");
}

/*
 * Look up given index value in hashtable.
 * Return pointer to db_index_entries that match the given value, linked
 * via the 'next_result' pointer.  Return in 'how_many_found' the size
 * of this list. Return NULL if not found.
 */
db_index_entry *
db_index::lookup(item *index_value, long *how_many_found,
		db_table *table, bool_t checkTTL)
{
	register unsigned long hval;
	unsigned long bucket;
	db_index_entry	*ret;

	READLOCK(this, NULL, "r db_index::lookup");
	if (index_value == NULL || table_size == 0 || tab == NULL) {
		READUNLOCK(this, NULL, "ru db_index::lookup");
		return (NULL);
	}
	hval = index_value->get_hashval(case_insens);
	bucket = hval % table_size;

	db_index_entry_p fst = tab[bucket ];

	if (fst != NULL)
		ret = fst->lookup(case_insens, hval,
					index_value, how_many_found);
	else
		ret = NULL;

	if (ret != NULL && checkTTL && table != NULL) {
		if (!table->cacheValid(ret->getlocation()))
			ret = NULL;
	}

	READUNLOCK(this, ret, "ru db_index::lookup");
	return (ret);
}

/*
 * Remove the entry with the given index value and location 'recnum'.
 * If successful, return DB_SUCCESS; otherwise DB_NOTUNIQUE if index_value
 * is null; DB_NOTFOUND if entry is not found.
 * If successful, decrement count of number of entries in hash table.
 */
db_status
db_index::remove(item* index_value, entryp recnum)
{
	register unsigned long hval;
	unsigned long bucket;
	register db_index_entry *fst;
	db_status	ret;

	if (index_value == NULL)
		return (DB_NOTUNIQUE);
	WRITELOCK(this, DB_LOCK_ERROR, "w db_index::remove");
	if (table_size == 0 || tab == NULL) {
		WRITEUNLOCK(this, DB_NOTFOUND, "wu db_index::remove");
		return (DB_NOTFOUND);
	}
	hval = index_value->get_hashval(case_insens);

	bucket = hval % table_size;

	fst = tab[bucket];
	if (fst == NULL)
		ret = DB_NOTFOUND;
	else if (fst->remove(&tab[bucket], case_insens, hval, index_value,
			recnum)) {
		--count;
		ret = DB_SUCCESS;
	} else
		ret = DB_NOTFOUND;
	WRITEUNLOCK(this, ret, "wu db_index::remove");
	return (ret);
}

/*
 * Add a new index entry with the given index value and location 'recnum'.
 * Return DB_NOTUNIQUE, if entry with identical index_value and recnum
 * already exists.  If entry is added, return DB_SUCCESS.
 * Increment count of number of entries in index table and grow table
 * if number of entries equals size of table.
 * Note that a copy of index_value is made for new entry.
 */
db_status
db_index::add(item* index_value, entryp recnum)
{
	register unsigned long hval;

	if (index_value == NULL)
		return (DB_NOTUNIQUE);

	hval = index_value->get_hashval(case_insens);

	WRITELOCK(this, DB_LOCK_ERROR, "w db_index::add");
	if (tab == NULL) grow();

	db_index_entry_p fst, newbucket;
	unsigned long bucket;
	bucket = hval %table_size;
	fst = tab[bucket];
	if (fst == NULL)  { /* Empty bucket */
		if ((newbucket = new db_index_entry(hval, index_value,
				recnum, tab[bucket])) == NULL) {
			WRITEUNLOCK(this, DB_MEMORY_LIMIT,
				"wu db_index::add");
			FATAL3("db_index::add: cannot allocate space",
				DB_MEMORY_LIMIT, DB_MEMORY_LIMIT);
		}
		tab[bucket] = newbucket;
	} else if (fst->add(&tab[bucket], case_insens,
				hval, index_value, recnum)) {
		/* do nothing */
	} else {
		WRITEUNLOCK(this, DB_NOTUNIQUE, "wu db_index::add");
		return (DB_NOTUNIQUE);
	}

	/* increase hash table size if number of entries equals table size */
	if (++count > table_size)
		grow();

	WRITEUNLOCK(this, DB_SUCCESS, "wu db_index::add");
	return (DB_SUCCESS);
}

/* ************************* pickle_index ********************* */

/* Does the actual writing to/from file specific for db_index structure. */
static bool_t
transfer_aux(XDR* x, pptr ip)
{
	return (xdr_db_index(x, (db_index*) ip));
}

class pickle_index: public pickle_file {
    public:
	pickle_index(char *f, pickle_mode m) : pickle_file(f, m) {}

	/* Transfers db_index structure pointed to by dp to/from file. */
	int transfer(db_index* dp)
		{ return (pickle_file::transfer((pptr) dp, &transfer_aux)); }
};

/* Dumps this index to named file. */
int
db_index::dump(char *file)
{
	int	ret;
	pickle_index f(file, PICKLE_WRITE);

	WRITELOCK(this, -1, "w db_index::dump");
	int status =  f.transfer(this);

	if (status == 1)
		ret = -1; /* cannot open for write */
	else
		ret = status;
	WRITEUNLOCK(this, ret, "wu db_index::dump");
	return (ret);
}

/*
 * Constructor: creates index by loading it from the specified file.
 * If loading fails, creates empty index.
 */
db_index::db_index(char *file)
{
	pickle_index f(file, PICKLE_READ);
	tab = NULL;
	table_size = count = 0;

	/* load new hashbuf */
	if (f.transfer(this) < 0) {
		/* Load failed; reset. */
		tab = NULL;
		table_size = count = 0;
	}

	INITRW(index);
}


/*
 * Return in 'tsize' the table_size, and 'tcount' the number of entries
 * in the table.
 */
void
db_index::stats(long *tsize, long *tcount)
{
	READLOCKV(this, "r db_index::stats");
	*tsize = table_size;
	*tcount = count;
	READUNLOCKV(this, "ru db_index::stats");
}

/* Print all entries in the table. */
void
db_index::print()
{
	long i;

	READLOCKV(this, "r db_index::print");
	/* Add sanity check in case table corrupted */
	if (tab != NULL) {
		for (i = 0; i < table_size; i++) {
			if (tab[i] != NULL)
				tab[i]->print_all();
		}
	}
	READUNLOCKV(this, "ru db_index::print");
}

/*
 * Moves an index from an xdr index. Upon completion, original index's tab
 * will be NULL.
 */

db_status
db_index::move_xdr_db_index(db_index *orig)
{
	table_size = orig->table_size;
	orig->table_size = 0;
	count = orig->count;
	orig->count = 0;
	case_insens = orig->case_insens;
	tab = orig->tab;
	orig->tab = NULL;

	return (DB_SUCCESS);
}
