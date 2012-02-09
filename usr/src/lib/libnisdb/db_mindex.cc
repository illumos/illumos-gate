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
 *	db_mindex.cc
 *
 *  Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 *  Use is subject to license terms.
 */

#include <stdio.h>

#include <malloc.h>
#include <strings.h>
#include <string.h>
#include <sys/param.h>
#include "db_headers.h"
#include "db.h"
#include "db_mindex.h"
#include "db_pickle.h"
#include "nisdb_mt.h"
#include "nisdb_ldap.h"
#include "ldap_nisdbquery.h"
#include "ldap_map.h"
#include "ldap_ruleval.h"
#include "ldap_scheme.h"
#include "ldap_parse.h"
#include "nis_hashitem.h"

/*
 *  Constructor:  Create new table using scheme defintion supplied.
 *  (Make copy of scheme and keep it with table.)
 */
db_mindex::db_mindex(db_scheme *how, char *tablePath) : rversion()
{
	noWriteThrough.flag = 0;
	noLDAPquery.flag = 0;
	initialLoad.flag = 0;
	objPath.ptr = NULL;
	init(how);
	if (tablePath != NULL)
		configure(tablePath);
}

/* Constructor:  Create empty table (no scheme, no table or indices). */
db_mindex::db_mindex() : rversion()
{
	scheme = NULL;
	table = NULL;
	indices.indices_len = 0;
	indices.indices_val = NULL;
	noWriteThrough.flag = 0;
	noLDAPquery.flag = 0;
	initialLoad.flag = 0;
	objPath.ptr = NULL;
	INITRW(mindex);
}

db_mindex::~db_mindex()
{
	reset();   /* get rid of data structures first */
	DESTROYRW(mindex);
}

/*
 * Initialize table using information given in scheme 'how'.
 * Record the scheme for later use (make copy of it);
 * create the required number of indices; and create table for storing
 * entries.
 */
void
db_mindex::init(db_scheme * how)
{
	scheme = new db_scheme(how);		// make copy
	if (scheme == NULL)
		FATAL("db_mindex::init: could not allocate space for scheme",
			DB_MEMORY_LIMIT);

	if (scheme->numkeys() == 0) {
	    WARNING("db_mindex::init: empty scheme encountered");
	    /* what action should we take here? */
	}

	indices.indices_len = how->numkeys();
	db_key_desc * keys = how->keyloc();
	int i;

	/* homogeneous indices for now */
	indices.indices_val = new db_index[indices.indices_len];
	if (indices.indices_val == NULL) {
		delete scheme;
		indices.indices_len = 0;
		scheme = NULL;
		FATAL("db_mindex::init: could not allocate space for indices",
			DB_MEMORY_LIMIT);
	}
	for (i = 0; i < indices.indices_len; i++) {
		indices.indices_val[i].init(&(keys[i]));
	}
	table = new db_table();
	if (table == NULL) {
		delete scheme;
		scheme = NULL;
		delete indices.indices_val;
		indices.indices_val = NULL;
		indices.indices_len = 0;
		FATAL("db_mindex::init: could not allocate space for table",
			DB_MEMORY_LIMIT);
	}
	rversion.zero();
	INITRW(mindex);
	objPath.ptr = NULL;
}

/* empty associated tables associated */
void
db_mindex::reset_tables()
{
	int i;

	WRITELOCKV(this, "w db_mindex::reset_tables");
	/* Add sanity check in case of table corruption */
	if (indices.indices_val != NULL) {
		for (i = 0; i < indices.indices_len; i++) {
			indices.indices_val[i].reset();
		}
	}
	if (table) table->reset();
	WRITEUNLOCKV(this, "wu db_mindex::reset_tables");
}


/*
 * Return a list of index_entries that satsify the given query 'q'.
 * Return the size of the list in 'count'. Return NULL if list is empty.
 * Return in 'valid' FALSE if query is not well formed.
*/
db_index_entry_p
db_mindex::satisfy_query(db_query *q, long *count, bool_t *valid) {
	return (satisfy_query(q, count, valid, FALSE));
}

db_index_entry_p
db_mindex::satisfy_query(db_query *q, long *count, bool_t *valid,
			bool_t fromLDAP) {
	db_index_entry_p	ret;
	bool_t			validRequest;
	int			queryRes;

	/* Make sure we have somewhere to store the "request valid" status */
	if (valid == NULL)
		valid = &validRequest;

	/* Prepare for a failed lock */
	*count = 0;
	*valid = FALSE;

	READLOCK(this, NULL, "r db_mindex::satisfy_query");

	/*
	 * Only get data from LDAP if the caller requested it,
	 * and if we're mapping for this table.
	 */
	fromLDAP = (fromLDAP && !noLDAPquery.flag &&
		(table->mapping.fromLDAP ||
			table->mapping.objType != NIS_TABLE_OBJ));

	/*
	 * If we always fetch data from LDAP for query's, then do so now,
	 * before invoking the "real" satisfy_query().
	 */
	if (fromLDAP && table->mapping.matchFetch == mat_always) {
		int	lockcode = 0;

		READLOCKNR(table, lockcode,
				"r db_mindex::satisfy_query table");
		if (lockcode != 0) {
			READUNLOCK(this, NULL, "ru db_mindex::satisfy_query");
			return (NULL);
		}

		queryRes = queryLDAP(q, 0, 1);

		READUNLOCKNR(table, lockcode,
				"ru db_mindex::satisfy_query table");
		if (lockcode != 0) {
			READUNLOCK(this, NULL, "ru db_mindex::satisfy_query");
			return (NULL);
		}
		if (queryRes != LDAP_SUCCESS) {
			/* queryLDAP() sets error codes etc. */
			READUNLOCK(this, NULL, "ru db_mindex::satisfy_query");
			return (NULL);
		}

	}

	ret = satisfy_query_dbonly(q, count, fromLDAP ? TRUE : FALSE, valid);

	/* If we found it, or if we're not mapping, return */
	if (ret != NULL || !fromLDAP) {
		READUNLOCK(this, NULL, "ru db_mindex::satisfy_query");
		return (ret);
	} else if (ret == NULL && !(*valid)) {
		/* No result, and the request wasn't valid */
		READUNLOCK(this, NULL, "ru db_mindex::satisfy_query");
		return (NULL);
	}

	/* Get data from LDAP */
	if (table->mapping.matchFetch != mat_never) {
		queryRes = queryLDAP(q, 0, 1);
	} else {
		/*
		 * We'll now go on to check for an un-expired entry again,
		 * even though we're pretty sure that won't work (already
		 * did that, and nothing's changed). However, we accept that
		 * slight inefficiency in the interest of keeping the code
		 * simple; we expect 'mat_never' to be used very rarely.
		 */
		queryRes = LDAP_SUCCESS;
	}

	if (queryRes == LDAP_SUCCESS) {
		/*
		 * Check if we've got a match now. If not, try one
		 * last time for an expired match.
		 */
		ret = satisfy_query_dbonly(q, count, TRUE, valid);
		if (ret == NULL) {
			ret = satisfy_query_dbonly(q, count, FALSE, valid);
		}
	} else {
		/*
		 * Check if we have an expired entry; if so, return
		 * it with an appropriate status.
		 */
		ret = satisfy_query_dbonly(q, count, FALSE, valid);
	}

	READUNLOCK(this, NULL, "ru db_mindex::satisfy_query");

	return (ret);
}

db_index_entry_p
db_mindex::satisfy_query_dbonly(db_query *q, long *count,
				bool_t checkExpire, bool_t *valid)
{
	db_index_entry_p oldres = NULL, newres;
	int i, curr_ind;
	long num_new, num_old = 0;
	int limit = q->size();
	db_qcomp * comps = q->queryloc();

	if (valid) *valid = TRUE;   /* True to begin with. */

	/* Add sanity check in case table corrupted */
	if (indices.indices_len != 0 && indices.indices_val == NULL) {
		WARNING("db_mindex::satisfy_query: table has no indices");
		if (valid) *valid = FALSE;
		*count = 0;
		return (NULL);
	}

	for (i = 0; i < limit; i++) {
		if ((curr_ind = comps[i].which_index) < indices.indices_len) {
			newres = indices.indices_val[curr_ind].lookup(
					comps[i].index_value, &num_new,
					table, checkExpire);
			if (newres == NULL) {
				*count = 0;
				return (NULL);
			}
			if (oldres == NULL) {
				oldres = newres;
				num_old = num_new;
			} else {
				oldres = newres->join(num_new, num_old,
							oldres, &num_old);
				if (oldres == NULL) {
					*count = 0;
					return (NULL);
				}
			}
		} else {
			WARNING("db_mindex::satisfy_query: index out of range");
			if (valid) *valid = FALSE;
			*count = 0;
			return (NULL);
		}
	}
	*count = num_old;
	return (oldres);
}

/*
 * Returns an array of size 'count' of 'entry_object_p's, pointing to
 * copies of entry_objects named by the result list of db_index_entries 'res'.
 * Sets db_status 'statp' if error encountered; otherwise, leaves it unchanged.
*/
entry_object_p *
db_mindex::prepare_results(int count, db_index_entry_p res, db_status *statp)
{
	READLOCK(this, NULL, "r db_mindex::prepare_results");
	READLOCK2(table, NULL, "r table db_mindex::prepare_results", this);
	entry_object_p * entries = new entry_object_p[count];
	int i;

	if (entries == NULL) {
		READUNLOCK2(this, table, NULL, NULL,
	"ru db_mindex::prepare_results: could not allocate space",
	"ru table db_mindex::prepare_results: could not allocate space");
		FATAL3("db_mindex::prepare_results: could not allocate space",
			DB_MEMORY_LIMIT, NULL);
	}

	for (i = 0; i < count; i++) {
		if (res == NULL) {
			int j;
			for (j = 0; j < i; j++) // cleanup
				free_entry(entries[j]);
			syslog(LOG_ERR,
				"db_mindex::prepare_results: incorrect count");
			*statp = DB_INTERNAL_ERROR;
		} else {
			entries[i] =
				new_entry(table->get_entry(res->getlocation()));
			res = res->getnextresult();
		}
	}
	READUNLOCK2(this, table, entries, entries,
			"ru db_mindex::prepare_results",
			"ru db_mindex::prepare_results");

	return (entries);
}

/*
 * Returns a newly created db_query structure containing the index values
 * as obtained from the record named by 'recnum'.  The record itself, along
 * with information on the schema definition of this table, will determine
 * which values are extracted from the record and placed into the result.
 * Returns NULL if recnum is not a valid entry.
 * Note that space is allocated for the query and the index values
 * (i.e. do not share pointers with strings in 'obj'.)
 */
db_query *
db_mindex::extract_index_values_from_record(entryp recnum)
{
	db_query	*ret;

	ret = extract_index_values_from_object(table->get_entry(recnum));
	return (ret);
}

/*
 * Returns a newly created db_query containing the index values as
 * obtained from the given object.  The object itself,
 * along with information on the scheme given, will determine
 * which values are extracted from the object and placed into the query.
 * Returns an empty query if 'obj' is not a valid entry.
 * Note that space is allocated for the query and the index values
 * (i.e. do not share pointers with strings in 'obj'.)
*/
db_query *
db_mindex::extract_index_values_from_object(entry_object_p obj)
{
	READLOCK(this, NULL, "r db_mindex::extract_index_values_from_object");
	if (scheme->numkeys() != indices.indices_len) { // probably built wrong
		syslog(LOG_ERR,
	    "number of keys (%d) does not equal number of indices (%d)",
	    scheme->numkeys(), indices.indices_len);
		READUNLOCK(this, NULL,
			"ru db_mindex::extract_index_values_from_object");
		return (new db_query());	// null query
	} else if (obj == NULL) {
		READUNLOCK(this, NULL,
			"ru db_mindex::extract_index_values_from_object");
		return (NULL);
	} else {
		db_query* answer = new db_query(scheme, obj);
		if (answer) {
			/*
			 * XXX If the unlock fails, and we return NULL,
			 * we leak 'answer'. On the other hand, if we
			 * return 'answer', the object may remain locked,
			 * but the caller doesn't know that anything
			 * went wrong.
			 */
			READUNLOCK(this, NULL,
			"ru db_mindex::extract_index_values_from_object");
			return (answer);
		} else {
			FATAL3("db_mindex::extract: could not allocate space",
				DB_MEMORY_LIMIT, NULL);
		}
	}
	READUNLOCK(this, NULL,
		"ru db_mindex::extract_index_values_from_object");
	return (NULL);
}

/*
 * Returns the first entry found in the table by setting 'answer' to
 * point to the a copy of entry_object.  Returns DB_SUCCESS if found;
 * DB_NOTFOUND otherwise.
*/
db_status
db_mindex::first(entryp *where, entry_object ** answer)
{
	db_status	ret = DB_SUCCESS;

	/*
	 * table->first_entry() returns a pointer into the table, so
	 * we must keep the table read locked until we've copied the
	 * entry_object. In order to maintain lock integrity, we must
	 * lock the db_mindex (this) before the db_table (table).
	 */
	READLOCK(this, DB_LOCK_ERROR, "r db_mindex::first");
	READLOCK2(table, DB_LOCK_ERROR, "r table db_mindex::first", this);
	if (table->mapping.fromLDAP) {
		struct timeval	now;
		(void) gettimeofday(&now, NULL);
		if (now.tv_sec >= table->mapping.enumExpire) {
			int queryRes = queryLDAP(0, 0, 1);
			if (queryRes == LDAP_SUCCESS)
				table->mapping.enumExpire = now.tv_sec +
					table->mapping.ttl;
			else {
				READUNLOCK2(this, table,
					DB_LOCK_ERROR, DB_LOCK_ERROR,
					"ru db_mindex::first LDAP",
					"ru table db_mindex::first LDAP");
				return (DB_INTERNAL_ERROR);
			}
		}
	}
	entry_object_p ptr = table->first_entry(where);
	if (ptr == NULL)
		ret = DB_NOTFOUND;
	else
		*answer = new_entry(ptr);
	READUNLOCK2(this, table, ret, ret,
		"ru db_mindex::first", "ru table db_mindex::first");
	return (ret);
}

/*
 * Returns the next entry in the table after 'previous' by setting 'answer' to
 * point to copy of the entry_object.  Returns DB_SUCCESS if 'previous' is
 * valid and next entry is found; DB_NOTFOUND otherwise.  Sets 'where' to
 * location of where entry is found for input as subsequent 'next' operation.
*/
db_status
db_mindex::next(entryp previous, entryp *where, entry_object **answer)
{
	db_status	ret = DB_SUCCESS;

	READLOCK(this, DB_LOCK_ERROR, "r db_mindex::next");
	READLOCK2(table, DB_LOCK_ERROR, "r db_mindex::next", this);
	if (!(table->entry_exists_p(previous)))
		ret = DB_NOTFOUND;
	else {
		entry_object * ptr = table->next_entry(previous, where);
		if (ptr == NULL)
			ret = DB_NOTFOUND;
		else
			*answer = new_entry(ptr);
	}
	READUNLOCK2(this, table, ret, ret,
		"ru db_mindex::next", "ru table db_mindex::next");
	return (ret);
}

static void
delete_result_list(db_next_index_desc* orig)
{
	db_next_index_desc* curr, *save_next;
	for (curr = orig; curr != NULL; 0) {
		save_next = curr->next;
		delete curr;
		curr = save_next;
	}
}


static db_next_index_desc *
copy_result_list(db_index_entry* orig)
{
	db_next_index_desc *head = NULL, *curr;
	db_index_entry *current;

	for (current = orig; current != NULL;
		current = current->getnextresult()) {
		curr = new db_next_index_desc(current->getlocation(), head);
		if (curr == NULL) {
			FATAL3(
			"db_mindex::copy_result_list: could not allocate space",
			DB_MEMORY_LIMIT, NULL);
		}
		head = curr;  // list is actually reversed
	}
	return (head);
}

/*
 * Delete the given list of results; used when no longer interested in
 * the results of the first/next query that returned this list.
 */
db_status
db_mindex::reset_next(db_next_index_desc *orig)
{
	if (orig == NULL)
		return (DB_NOTFOUND);

	delete_result_list(orig);
	return (DB_SUCCESS);
}

/*
* Finds entry that satisfy the query 'q'.  Returns the first answer by
* setting the pointer 'answer' to point to a copy of it.  'where' is set
* so that the other answers could be gotten by passing 'where' to 'next'
* successively.   Note that the answer is a  pointer to a copy of the entry.
* Returns DB_SUCCESS if search was successful; DB_NOTFOUND otherwise.
 */
db_status
db_mindex::first(db_query *q,
		db_next_index_desc **where, entry_object ** answer)
{
	READLOCK(this, DB_LOCK_ERROR, "r db_mindex::first");
	READLOCK2(table, DB_LOCK_ERROR, "r table db_mindex::first", this);
	long count;
	bool_t valid_query;
	db_status	ret = DB_SUCCESS;
	db_index_entry * rp = satisfy_query(q, &count, &valid_query, TRUE);

	if (valid_query != TRUE)
		ret =  DB_BADQUERY;
	else if (rp == NULL) {
		*answer = NULL;
		ret = DB_NOTFOUND;
	} else {
		*where = copy_result_list(rp);

		entry_object_p ptr = table->get_entry((*where)->location);
		if (ptr == NULL)
			ret = DB_NOTFOUND;
		else
			*answer = new_entry(ptr);
	}
	READUNLOCK2(this, table, ret, ret,
		"ru db_mindex::first", "ru table db_mindex::first");
	return (ret);
}

/*
 * Returns the next entry in the table after 'previous' by setting 'answer' to
 * point to copy of the entry_object.  Next is next in chain of answers found
 * in previous first search with query.   Returns DB_SUCCESS if 'previous' is
 * valid and next entry is found; DB_NOTFOUND otherwise.  Sets 'where' to
 * location of where entry is found for input as subsequent 'next' operation.
*/
db_status
db_mindex::next(db_next_index_desc *previous, db_next_index_desc **where,
		entry_object **answer)
{
	READLOCK(this, DB_LOCK_ERROR, "r db_mindex::next");
	READLOCK2(table, DB_LOCK_ERROR, "r table db_mindex::next", this);
	db_status	ret = DB_SUCCESS;

	if (previous == NULL)
		ret = DB_NOTFOUND;
	else {
		// should further check validity of 'previous' pointer
		*where = previous->next;
		delete previous;    // delete previous entry
		if (*where == NULL)
			ret = DB_NOTFOUND;
		else {
			entry_object * ptr =
				table->get_entry((*where)->location);
			if (ptr == NULL)
				ret = DB_NOTFOUND;
			else {
				*answer = new_entry(ptr);
				ret = DB_SUCCESS;
			}
		}
	}
	READUNLOCK2(this, table, ret, ret,
		"ru db_mindex::next", "ru table db_mindex::next");
	return (ret);
}

/*
 * Finds entry that satisfy the query 'q'.  Returns the answer by
 * setting the pointer 'rp' to point to the list of answers.
 * Note that the answers are pointers to the COPIES of entries.
 * Returns the number of answers find in 'count'.
 * Returns DB_SUCCESS if search found at least one answer;
 * returns DB_NOTFOUND if none is found.
*/
db_status
db_mindex::lookup(db_query *q, long *count, entry_object_p **result)
{
	bool_t valid_query;
	db_index_entry * rp = satisfy_query(q, count, &valid_query, TRUE);
	db_status stat = DB_SUCCESS;

	if (valid_query != TRUE)
		return (DB_BADQUERY);

	if (rp == NULL) {
		*result = NULL;
		return (DB_NOTFOUND);
	}

	*result = prepare_results((int)*count, rp, &stat);

	return (stat);
}

/*
 * Return all entries within table.  Returns the answer by
 * setting the pointer 'rp' to point to the list of answers.
 * Note that the answers are pointers to copies of the entries.
 * Returns the number of answers find in 'count'.
 * Returns DB_SUCCESS if search found at least one answer;
 * returns DB_NOTFOUND if none is found.
*/
db_status
db_mindex::all(long *count, entry_object_p **result)
{
	entry_object *ptr;
	entryp where;
	long how_many, i;
	int	lret = 0;

	if (table == NULL) {
		*result = NULL;
		return (DB_NOTFOUND);
	}

	READLOCK(this, DB_LOCK_ERROR, "r db_mindex::all");
	/* Read lock 'table' while we're traversing it */
	READLOCKNR(table, lret, "r table db_mindex::all");
	if (lret != 0) {
		READUNLOCK(this, DB_LOCK_ERROR, "ru db_mindex::all");
		return (DB_LOCK_ERROR);
	}

	if (table->mapping.fromLDAP) {
		struct timeval	now;
		(void) gettimeofday(&now, NULL);
		if (now.tv_sec >= table->mapping.enumExpire) {
			int	queryRes = queryLDAP(0, 0, 1);
			if (queryRes != LDAP_SUCCESS) {
				READUNLOCKNR(table, lret,
					"ru table db_mindex::all LDAP");
				READUNLOCK(this, DB_LOCK_ERROR,
					"ru db_mindex::all LDAP");
				return (DB_INTERNAL_ERROR);
			}
		}
	}

	if ((how_many = table->fullness()) <= 0) {
		/*
		 * Set '*count' so that the caller avoids putting garbage
		 * in an 'objects_len' field.
		 */
		*count = 0;
		*result = NULL;
		READUNLOCKNR(table, lret, "ru table db_mindex::all");
		READUNLOCK(this, DB_NOTFOUND, "ru db_mindex::all");
		return (DB_NOTFOUND);
	}

	entry_object_p * answer = new entry_object_p[how_many];
	if (answer == NULL) {
		READUNLOCKNR(table, lret, "ru table db_mindex::all");
		READUNLOCK(this, DB_MEMORY_LIMIT, "ru db_mindex::all");
		FATAL3("db_mindex::all: could not allocate space",
			DB_MEMORY_LIMIT, DB_MEMORY_LIMIT);
	}

	*count = how_many;

	ptr = table->first_entry(&where);
	if (ptr != NULL)
		answer[0] = new_entry(ptr);
	else {
		WARNING("db_mindex::all: null first entry found in all");
		answer[0] = NULL;
	}
	for (i = 1; i < how_many; i++) {
		ptr = table->next_entry(where, &where);
		if (ptr != NULL)
			answer[i] = new_entry(ptr);
		else {
			WARNING(
			    "db_mindex::all: null internal entry found in all");
			answer[i] = NULL; /* Answer gets null too. -CM */
		}
	}

	READUNLOCKNR(table, lret, "ru table db_mindex::all");

	*result = answer;
	READUNLOCK(this, DB_SUCCESS, "ru db_mindex::all");
	return (DB_SUCCESS);
}

/*
 * Remove the entry identified by 'recloc' from:
 * 1.  all indices, as obtained by extracting the index values from the entry
 * 2.  table where entry is stored.
*/
db_status
db_mindex::remove_aux(entryp recloc)
{
	int i, curr_ind;
	db_status	res = DB_SUCCESS;

	WRITELOCK(this, DB_LOCK_ERROR, "w db_mindex::remove_aux");
	/* get index values of this record */
	db_query * cq = extract_index_values_from_record(recloc);
	if (cq == NULL) {
		WRITEUNLOCK(this, DB_MEMORY_LIMIT, "wu db_mindex::remove_aux");
		FATAL3("db_mindex::remove_aux: could not allocate space",
			DB_MEMORY_LIMIT, DB_MEMORY_LIMIT);
	}
	if (cq->size() != indices.indices_len) { /* something is wrong */
		delete cq; // clean up
		syslog(LOG_ERR,
	    "db_mindex::remove_aux: record contains wrong number of indices");
		WRITEUNLOCK(this, DB_INTERNAL_ERROR,
			"wu db_mindex::remove_aux");
		return (DB_INTERNAL_ERROR);
	}

	if (!noWriteThrough.flag) {
		nis_object	*o = 0;
		entry_object    *e = table->get_entry(recloc);
		int		queryRes, doingModify;

		/*
		 * If the removal is part of a modify operation, we
		 * defer the LDAP update until the modified NIS+ object
		 * is added back.
		 */
		if (saveOldObjForModify((entry_obj *)e, &doingModify) == 0)
			res = DB_INTERNAL_ERROR;

		if (res == DB_SUCCESS && !doingModify) {
			/*
			 * If we're removing a directory entry, and the
			 * entry is LDAP-mapped, but the directory isn't,
			 * we need a copy of the entry object in order
			 * to remove if from LDAP.
			 */
			if (e != 0 && e->en_type != 0 &&
					strcmp(e->en_type, "IN_DIRECTORY") == 0)
				o = unmakePseudoEntryObj(e, 0);
			queryRes = removeLDAP(cq, o);
			if (queryRes != LDAP_SUCCESS) {
				if (table->mapping.storeErrorDisp == abandon)
					res = DB_INTERNAL_ERROR;
			}
			if (o != 0)
				nis_destroy_object(o);
		}
	}

	if (res == DB_SUCCESS) {
		db_qcomp * comps = cq->queryloc();

		/* Add sanity check in case of corrupted table */
		if (indices.indices_val != NULL) {
			/* update indices */
			for (i = 0; i < indices.indices_len; i++) {
				/* unnec. if sorted */
				curr_ind = comps[i].which_index;
				indices.indices_val[curr_ind].remove(
						comps[i].index_value, recloc);
			}
		}

		/* update table where record is stored */
		table->delete_entry(recloc);
	}

	/* delete query */
	delete cq;

	WRITEUNLOCK(this, DB_SUCCESS, "wu db_mindex::remove_aux");

	return (res);
}

/*
 * Removes the entry in the table named by given query 'q'.
 * If a NULL query is supplied, all entries in table are removed.
 * Returns DB_NOTFOUND if no entry is found.
 * Returns DB_SUCCESS if one entry is found; this entry is removed from
 * its record storage, and it is also removed from all the indices of the
 * table. If more than one entry satisfying 'q' is found, all are removed.
 */
db_status
db_mindex::remove(db_query *q)
{
	long count = 0;
	db_index_entry *rp;
	db_status rstat;
	bool_t valid_query;

	WRITELOCK(this, DB_LOCK_ERROR, "w db_mindex::remove");
	WRITELOCK2(table, DB_LOCK_ERROR, "w table db_mindex::remove", this);
	if (q == NULL)  {  /* remove all entries in table */
		if (table->mapping.toLDAP && !noWriteThrough.flag) {
			int	queryRes = removeLDAP(q, 0);
#ifdef	NISDB_LDAP_DEBUG
			if (queryRes != LDAP_SUCCESS)
				abort();
#endif	/* NISDB_LDAP_DEBUG */
		}
		if (table != NULL && table->getsize() > 0) {
			reset_tables();
			WRITEUNLOCK2(table, this, DB_SUCCESS, DB_SUCCESS,
					"wu table db_mindex::remove",
					"wu db_mindex::remove");
			return (DB_SUCCESS);
		} else {
			WRITEUNLOCK2(table, this, DB_NOTFOUND, DB_NOTFOUND,
					"wu table db_mindex::remove",
					"wu db_mindex::remove");
			return (DB_NOTFOUND);
		}
	}

	rp = satisfy_query(q, &count, &valid_query, FALSE);

	if (valid_query != TRUE) {
		WRITEUNLOCK2(table, this, DB_BADQUERY, DB_BADQUERY,
			"wu table db_mindex::remove", "wu db_mindex::remove");
		return (DB_BADQUERY);
	}

	if (count == 0) {	/* not found */
		WRITEUNLOCK2(table, this, DB_NOTFOUND, DB_NOTFOUND,
			"wu table db_mindex::remove", "wu db_mindex::remove");
		return (DB_NOTFOUND);
	} else if (count == 1) {	/* found, update indices  */
		db_status	s;

		s = remove_aux(rp->getlocation());

		WRITEUNLOCK2(table, this, s, s,
			"wu table db_mindex::remove", "wu db_mindex::remove");
		return (s);
	} else {		/* ambiguous, remove all entries */
		int i;
		db_index_entry *next_entry;
		for (i = 0; i < count; i++) {
			if (rp == NULL) {
				syslog(LOG_ERR,
			"db_mindex::remove:  incorrect number of indices");
				WRITEUNLOCK2(table, this, DB_INTERNAL_ERROR,
					DB_INTERNAL_ERROR,
					"wu table db_mindex::remove",
					"wu db_mindex::remove");
				return (DB_INTERNAL_ERROR);
			}

			next_entry = rp->getnextresult(); // save before removal
			rstat = remove_aux(rp->getlocation());
			if (rstat != DB_SUCCESS) {
				WRITEUNLOCK2(table, this, rstat, rstat,
					"wu table db_mindex::remove",
					"wu db_mindex::remove");
				return (rstat);
			}
			rp = next_entry;		// go on to next
		}
		WRITEUNLOCK2(table, this, DB_SUCCESS, DB_SUCCESS,
			"wu table db_mindex::remove", "wu db_mindex::remove");
		return (DB_SUCCESS);
	}
}

/*
 * Add copy of given entry to table.  Entry is identified by query 'q'.
 * The entry (if any) satisfying the query is first deleted, then
 *  added to the indices (using index values extracted form the given entry)
 * and the table.
 * Returns DB_NOTUNIQUE if more than one entry satisfies the query.
 * Returns DB_NOTFOUND if query is not well-formed.
 * Returns DB_SUCCESS if entry can be added.
*/
db_status
db_mindex::add(db_query *q, entry_object * obj)
{
	long count = 0;
	int i, curr_ind;
	bool_t valid;
	db_index_entry *rp = NULL;
	db_status rstat;
	const char	*myself = "db_mindex::add";

	/*
	 *  The argument q is only NULL when we know that there are
	 *  no objects in the database that match the object.
	 */
	WRITELOCK(this, DB_LOCK_ERROR, "w db_mindex::add");
	WRITELOCK2(table, DB_LOCK_ERROR, "w table db_mindex::add", this);
	if (q) {
		rp = satisfy_query(q, &count, &valid, FALSE);
		if (!valid) {
			WRITEUNLOCK2(this, table, DB_LOCK_ERROR, DB_LOCK_ERROR,
					"wu db_mindex::add",
					"wu table db_mindex::add");
			return (DB_BADQUERY);
		}
	}
	if (count == 1) {	/* found, first delete */
		rstat = remove_aux(rp->getlocation());
		if (rstat != DB_SUCCESS) {
			WRITEUNLOCK2(this, table, rstat, rstat,
				"wu db_mindex::add",
				"wu table db_mindex::add");
			return (rstat);
		}
		count = 0;	/* fall through to add */
	}

	if (count == 0) { 	/* not found, insert */
		/* add object to table */
		entryp recloc = table->add_entry(obj, initialLoad.flag);
		/* get index values of this object, might be same as 'q' */
		db_query *cq = extract_index_values_from_object(obj);
		if (cq == NULL) {
			table->delete_entry(recloc);
			WRITEUNLOCK2(this, table,
				DB_MEMORY_LIMIT, DB_MEMORY_LIMIT,
				"wu db_mindex::add DB_MEMORY_LIMIT",
				"wu table db_mindex::add DB_MEMORY_LIMIT");
			FATAL3("db_mindex::add: could not allocate space for",
				DB_MEMORY_LIMIT, DB_MEMORY_LIMIT);
		}
		if (cq ->size() != indices.indices_len) { /* something wrong */
			table->delete_entry(recloc);
			delete cq; // clean up
			syslog(LOG_ERR,
		    "db_mindex::add: record contains wrong number of indices");
			WRITEUNLOCK2(this, table,
				DB_INTERNAL_ERROR, DB_INTERNAL_ERROR,
				"wu db_mindex::add DB_INTERNAL_ERROR",
				"wu table db_mindex::add DB_INTERNAL_ERROR");
			return (DB_INTERNAL_ERROR);
		}
		db_qcomp * comps = cq->queryloc();

		/* update indices */
		if (indices.indices_val != NULL) {
			for (i = 0; i < indices.indices_len; i++) {
				curr_ind = comps[i].which_index;
				indices.indices_val[curr_ind].add(
					comps[i].index_value, recloc);
			}
		}
		delete cq;  // clean up
		if (!noWriteThrough.flag) {
			int		queryRes;
			entry_object	*e = 0;

			if (retrieveOldObjForModify((entry_obj **)&e) == 0) {
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
			"%s: Error retrieving old object for LDAP update",
					myself);
				return (DB_INTERNAL_ERROR);
			}

			queryRes = storeLDAP(q, obj, 0, e, 0);
			if (queryRes != LDAP_SUCCESS) {
				if (table->mapping.storeErrorDisp == abandon) {
					WRITEUNLOCK2(this, table,
						DB_INTERNAL_ERROR,
						DB_INTERNAL_ERROR,
						"wu db_mindex::add LDAP",
						"wu table db_mindex::add LDAP");
					return (DB_INTERNAL_ERROR);
				} else {
					logmsg(MSG_NOTIMECHECK, LOG_WARNING,
						"%s: LDAP store failed: %s",
						myself,
						ldap_err2string(queryRes));
				}
			}
		}
		rstat = DB_SUCCESS;
	} else  /* ambiguous */
		rstat = DB_NOTUNIQUE;

	WRITEUNLOCK2(this, table, rstat, rstat,
			"wu db_mindex::add",
			"wu table db_mindex::add");
	return (rstat);
}

/* ************************* pickle_mindex ********************* */
/* Does the actual writing to/from file specific for db_mindex structure. */
static bool_t
transfer_aux(XDR* x, pptr rp)
{
	return (xdr_db_mindex(x, (db_mindex*) rp));
}

class pickle_mindex: public pickle_file {
    public:
	pickle_mindex(char *f, pickle_mode m) : pickle_file(f, m) {}

	/* Transfers db_mindex structure pointed to by dp to/from file. */
	int transfer(db_mindex* dp)
		{
			int	ret;

			WRITELOCK(dp, -1, "w pickle_mindex::transfer");
			ret = pickle_file::transfer((pptr) dp, &transfer_aux);
			WRITEUNLOCK(dp, ret, "wu pickle_mindex::transfer");
			return (ret);
		}
};

/* Write this structure (table, indices, scheme) into the specified file. */
int
db_mindex::dump(char *file)
{
	pickle_mindex f(file, PICKLE_WRITE);
	int status = f.transfer(this);

	if (status == 1)
		return (-1); /* could not open for write */
	else
		return (status);
}

/*
 * Reset the table by: deleting all the indices, table of entries, and its
 * scheme.
*/
void
db_mindex::reset()
{
	WRITELOCKV(this, "w db_mindex::reset");
	reset_tables();   /* clear table contents first */

	if (indices.indices_val) {
		delete [] indices.indices_val;
		indices.indices_val = NULL;
	}
	if (table) { delete table; table = NULL;  }
	if (scheme) { delete scheme; scheme = NULL;  }
	indices.indices_len = 0;
	rversion.zero();
	if (objPath.ptr != 0) {
		free(objPath.ptr);
		objPath.ptr = 0;
	}
	WRITEUNLOCKV(this, "wu db_mindex::reset");
}

/*
 * Initialize table using information from specified file.
 * The table is first 'reset', then the attempt to load from the file
 * is made.  If the load failed, the table is again reset.
 * Therefore, the table will be modified regardless of the success of the
 * load.  Returns 0 if successful, 1 if DB disk file couldn't be opened,
 * -1 for various other failures.
*/
int
db_mindex::load(char *file)
{
	pickle_mindex f(file, PICKLE_READ);
	int status;
	int	init_table = (this->table == NULL);
	int	init_scheme = (this->scheme == NULL);

	WRITELOCK(this, -1, "w db_mindex::load");
	reset();

	/* load new mindex */
	if ((status = f.transfer(this)) != 0) {
		/* load failed.  Reset. */
		reset();
	}

	/* Initialize the 'scheme' locking */
	if (status == 0 && this->scheme != 0 && init_scheme) {
		/*
		 * Since we've added fields to the db_scheme that aren't
		 * read from disk, we need to re-allocate so that the
		 * db_scheme instance is large enough.
		 */
		db_scheme	*tmpscheme = new db_scheme();
		if (tmpscheme != 0) {
			(void) memcpy(tmpscheme, this->scheme,
					this->scheme->oldstructsize());
			free(this->scheme);
			this->scheme = tmpscheme;
		} else {
			status = -1;
		}
	}
	/*
	 * If the 'table' field was NULL before the load, but not now,
	 * initialize the table locking and mapping.
	 */
	if (status == 0 && this->table != 0 && init_table) {
		/*
		 * As for the db_scheme, make sure the db_table is large
		 * enough.
		 */
		db_table	*tmptable = new db_table();
		if (tmptable != 0) {
			(void) memcpy(tmptable, this->table,
					this->table->oldstructsize());
			free(this->table);
			this->table = tmptable;
			(void) this->configure(file);
		} else {
			status = -1;
		}
	}

	if (status == 0 && this->indices.indices_val != NULL) {
		/*
		 * Recreate the db_index instance so that it is
		 * correctly initialized.
		 */
		db_index *tmp_indices;
		int	n_index = this->indices.indices_len;

		tmp_indices = new db_index[n_index];
		if (tmp_indices != NULL) {
			for (int i = 0; i < n_index; i++) {
			    if (tmp_indices[i].move_xdr_db_index
				(&this->indices.indices_val[i]) != DB_SUCCESS) {
					status = -1;
					break;
			    }
			}
			free(this->indices.indices_val);
			this->indices.indices_val = tmp_indices;
			this->indices.indices_len = n_index;
		} else {
			status = -1;
		}
	}

	WRITEUNLOCK(this, status, "wu db_mindex::load");
	return (status);
}

/*
 * Prints statistics of the table.  This includes the size of the table,
 * the number of entries, and the index sizes.
 */
void
db_mindex::print_stats()
{
	long size, count, i;
	long *stats = table->stats(TRUE);

	printf("table_size = %d\n", stats[0]);
	printf("last_used = %d\n", stats[1]);
	printf("count = %d\n", stats[2]);
	printf("free list size = %d\n", stats[3]);
	printf("free list count = %d\n", stats[4]);

	for (i = 5; i < 5+stats[4]; i++) {
		printf("%d, ", stats[i]);
	}
	printf("\n");
	free((char *)stats);

	/* Add sanity check in case of corrupted table */
	if (indices.indices_val == NULL) {
		printf("No indices to print\n");
		return;
	}
	for (i = 0; i < indices.indices_len; i++) {
		printf("***** INDEX %d ******\n", i);
		indices.indices_val[i].stats(&size, &count);
		printf("index table size = %d\ncount = %d\n", size, count);
	}
}

/* Prints statistics about all indices of table. */
void
db_mindex::print_all_indices()
{
	int i;

	READLOCKV(this, "r db_mindex::print_all_indices");
	/* Add sanity check in case of corrupted table */
	if (indices.indices_val == NULL) {
		printf("No indices to print\n");
		READUNLOCKV(this, "ru db_mindex::print_all_indices");
		return;
	}
	for (i = 0; i < indices.indices_len; i++) {
		printf("***** INDEX %d ******\n", i);
		indices.indices_val[i].print();
	}
	READUNLOCKV(this, "ru db_mindex::print_all_indices");
}

/* Prints statistics about indices identified by 'n'. */
void
db_mindex::print_index(int n)
{
	READLOCKV(this, "r db_mindex::print_index");
	if (n >= 0 && n < indices.indices_len)
		indices.indices_val[n].print();
	READUNLOCKV(this, "ru db_mindex::print_index");
}
