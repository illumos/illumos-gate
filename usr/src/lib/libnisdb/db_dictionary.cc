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
 *	db_dictionary.cc
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "db_headers.h"
#include "db_entry.h"
#include "db_dictionary.h"
#include "db_dictlog.h"
#include "db_vers.h"
#include "nisdb_mt.h"
#include "nisdb_rw.h"
#include "ldap_parse.h"
#include "ldap_map.h"
#include "nis_hashitem.h"
#include "ldap_util.h"
#include "nis_db.h"
#include <rpcsvc/nis.h>

#include <stdio.h>
#include <string.h>
#include <malloc.h>
#ifdef TDRPC
#include <sysent.h>
#endif
#include <unistd.h>
#include <syslog.h>
#include <rpc/rpc.h>

typedef bool_t	(*db_func)(XDR *, db_table_desc *);

extern db_dictionary *InUseDictionary;
extern db_dictionary *FreeDictionary;

/* *************** dictionary version ****************** */

#define	DB_MAGIC 0x12340000
#define	DB_MAJOR 0
#define	DB_MINOR 10
#define	DB_VERSION_0_9	(DB_MAGIC|(DB_MAJOR<<8)|9)
#define	DB_ORIG_VERSION	DB_VERSION_0_9
#define	DB_CURRENT_VERSION (DB_MAGIC|DB_MAJOR<<8|DB_MINOR)

vers db_update_version;   /* Note 'global' for all dbs. */

#define	INMEMORY_ONLY 1

/*
 * Checks for valid version.  For now, there are two:
 * DB_VERSION_ORIG was the ORIGINAL one with major = 0, minor = 9
 * DB_CURRENT_VERSION is the latest one with changes in the database format
 *	for entry objects and the change in the dictionary format.
 *
 * Our current implementation can support both versions.
 */
static inline bool_t
db_valid_version(u_int vers)
{
	return ((vers == DB_CURRENT_VERSION) || (vers == DB_ORIG_VERSION));
}

static char *
db_version_str(u_int vers)
{
	static char vstr[128];
	u_int d_major =  (vers&0x0000ff00)>>8;
	u_int d_minor =  (vers&0x000000ff);

	sprintf(vstr, "SunSoft, SSM, Version %d.%d", d_major, d_minor);
	return (vstr);
}

/*
 * Special XDR version that checks for a valid version number.
 * If we don't find an acceptable version, exit immediately instead
 * of continuing to xdr rest of dictionary, which might lead to
 * a core dump if the formats between versions are incompatible.
 * In the future, there might be a switch to determine versions
 * and their corresponding XDR routines for the rest of the dictionary.
 */
extern "C" {
bool_t
xdr_db_dict_version(XDR *xdrs, db_dict_version *objp)
{
	if (xdrs->x_op == XDR_DECODE) {
		if (!xdr_u_int(xdrs, (u_int*) objp) ||
		    !db_valid_version(((u_int) *objp))) {
			syslog(LOG_ERR,
	"db_dictionary: invalid dictionary format! Expecting %s",
				db_version_str(DB_CURRENT_VERSION));
			fprintf(stderr,
	"db_dictionary: invalid dictionary format! Expecting %s\n",
				db_version_str(DB_CURRENT_VERSION));
			exit(1);
		}
	} else if (!xdr_u_int(xdrs, (u_int*) objp))
		return (FALSE);
	return (TRUE);
}

void
make_zero(vers* v)
{
	v->zero();
}


};


/* ******************* dictionary data structures *************** */

/* Delete contents of single db_table_desc pointed to by 'current.' */
static void
delete_table_desc(db_table_desc *current)
{
	if (current->table_name != NULL) delete current->table_name;
	if (current->scheme != NULL) delete current->scheme;
	if (current->database != NULL) delete current->database;
	delete current;
}

/* Create new table descriptor using given table name and table_object. */
db_status
db_dictionary::create_table_desc(char *tab, table_obj* zdesc,
				db_table_desc** answer)
{
	db_table_desc *newtab;
	if ((newtab = new db_table_desc) == NULL) {
		FATAL3(
	    "db_dictionary::add_table: could not allocate space for new table",
		DB_MEMORY_LIMIT, DB_MEMORY_LIMIT);
	}

	newtab->database = NULL;
	newtab->table_name = NULL;
	newtab->next = NULL;

	if ((newtab->scheme = new db_scheme(zdesc)) == NULL) {
		delete_table_desc(newtab);
		FATAL3(
	"db_dictionary::add_table: could not allocate space for scheme",
		DB_MEMORY_LIMIT, DB_MEMORY_LIMIT);
	}

	if (newtab->scheme->numkeys() == 0) {
		WARNING(
	"db_dictionary::add_table: could not translate table_obj to scheme");
		delete_table_desc(newtab);
		return (DB_BADOBJECT);
	}

	if ((newtab->table_name = strdup(tab)) == NULL) {
		delete_table_desc(newtab);
		FATAL3(
	    "db_dictionary::add_table: could not allocate space for table name",
		DB_MEMORY_LIMIT, DB_MEMORY_LIMIT);
	}

	if (answer)
		*answer = newtab;
	return (DB_SUCCESS);
}


/* Delete list of db_table_desc pointed to by 'head.' */
static void
delete_bucket(db_table_desc *head)
{
	db_table_desc * nextone, *current;

	for (current = head; current != NULL; current = nextone) {
		nextone = current->next;	// remember next
		delete_table_desc(current);
	}
}

static void
delete_dictionary(db_dict_desc *dict)
{
	db_table_desc* bucket;
	int i;
	if (dict) {
		if (dict->tables.tables_val) {
			/* delete each bucket */
			for (i = 0; i < dict->tables.tables_len; i++)
				bucket = dict->tables.tables_val[i];
				if (bucket)
					delete_bucket(bucket);
			/* delete table */
			delete dict->tables.tables_val;
		}
		/* delete dictionary */
		delete dict;
	}
}

/* Relocate bucket starting with this entry to new hashtable 'new_tab'. */
static void
relocate_bucket(db_table_desc* bucket,
		db_table_desc_p *new_tab, unsigned long hashsize)
{
	db_table_desc_p np, next_np, *hp;

	for (np = bucket; np != NULL; np = next_np) {
		next_np = np->next;
		hp = &new_tab[np->hashval % hashsize];
		np->next = *hp;
		*hp = np;
	}
}

/*
 * Return pointer to entry with same hash value and table_name
 * as those supplied.  Returns NULL if not found.
 */
static db_status
enumerate_bucket(db_table_desc* bucket, db_status(*func)(db_table_desc *))
{
	db_table_desc_p np;
	db_status status;

	for (np = bucket; np != NULL; np = np->next) {
		status = (func)(np);
		if (status != DB_SUCCESS)
			return (status);
	}
	return (DB_SUCCESS);
}


/*
 * Return pointer to entry with same hash value and table_name
 * as those supplied.  Returns NULL if not found.
 */
static db_table_desc_p
search_bucket(db_table_desc* bucket, unsigned long hval, char *target)
{
	db_table_desc_p np;

	for (np = bucket; np != NULL; np = np->next) {
		if (np->hashval == hval &&
		    strcmp(np->table_name, target) == 0) {
			break;
		}
	}
	return (np);
}


/*
 * Remove entry with the specified hashvalue and target table name.
 * Returns 'TRUE' if successful, FALSE otherwise.
 * If the entry being removed is at the head of the list, then
 * the head is updated to reflect the removal. The storage for the
 * entry is freed if desired.
 */
static bool_t
remove_from_bucket(db_table_desc_p bucket,
		db_table_desc_p *head, unsigned long hval, char *target,
		bool_t free_storage)
{
	db_table_desc_p np, dp;

	/* Search for it in the bucket */
	for (dp = np = bucket; np != NULL; np = np->next) {
		if (np->hashval == hval &&
		    strcmp(np->table_name, target) == 0) {
			break;
		} else {
			dp = np;
		}
	}

	if (np == NULL)
		return (FALSE);	// cannot delete if it is not there

	if (dp == np) {
		*head = np->next;	// deleting head of bucket
	} else {
		dp->next = np->next;	// deleting interior link
	}
	if (free_storage)
		delete_table_desc(np);

	return (TRUE);
}


/*
 * Add given entry to the bucket pointed to by 'bucket'.
 * If an entry with the same table_name is found, no addition
 * is done.  The entry is added to the head of the bucket.
 */
static bool_t
add_to_bucket(db_table_desc_p bucket, db_table_desc **head, db_table_desc_p td)
{
	db_table_desc_p curr, prev;
	register char *target_name;
	unsigned long target_hval;
	target_name = td->table_name;
	target_hval = td->hashval;

	/* Search for it in the bucket */
	for (prev = curr = bucket; curr != NULL; curr = curr->next) {
		if (curr->hashval == target_hval &&
		    strcmp(curr->table_name, target_name) == 0) {
			break;
		} else {
			prev = curr;
		}
	}

	if (curr != NULL)
		return (FALSE);  /* duplicates not allowed */

	curr = *head;
	*head = td;
	td->next = curr;
	return (TRUE);
}


/* Print bucket starting with this entry. */
static void
print_bucket(db_table_desc *head)
{
	db_table_desc *np;
	for (np = head; np != NULL; np = np->next) {
		printf("%s: %d\n", np->table_name, np->hashval);
	}
}

static db_status
print_table(db_table_desc *tbl)
{
	if (tbl == NULL)
		return (DB_BADTABLE);
	printf("%s: %d\n", tbl->table_name, tbl->hashval);
	return (DB_SUCCESS);
}


static int hashsizes[] = {		/* hashtable sizes */
	11,
	53,
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

/* Returns the next size to use for the hash table */
static unsigned int
get_next_hashsize(long unsigned oldsize)
{
	long unsigned newsize, n;
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
 * The contents of the existing hashtable is copied to the new one and
 * relocated according to its hashvalue relative to the new size.
 * Old table is deleted after the relocation.
 */
static void
grow_dictionary(db_dict_desc_p dd)
{
	unsigned int oldsize, i, new_size;
	db_table_desc_p * oldtab, *newtab;

	oldsize = dd->tables.tables_len;
	oldtab = dd->tables.tables_val;

	new_size = get_next_hashsize(oldsize);

	if (new_size > CALLOC_LIMIT) {
		FATAL("db_dictionary::grow: table size exceeds calloc limit",
			DB_MEMORY_LIMIT);
	}

	if ((newtab = (db_table_desc_p*)
		calloc((unsigned int) new_size,
			sizeof (db_table_desc_p))) == NULL) {
		FATAL("db_dictionary::grow: cannot allocate space",
			DB_MEMORY_LIMIT);
	}

	if (oldtab != NULL) {		// must transfer contents of old to new
		for (i = 0; i < oldsize; i++) {
			relocate_bucket(oldtab[i], newtab, new_size);
		}
		delete oldtab;		// delete old hashtable
	}

	dd->tables.tables_val = newtab;
	dd->tables.tables_len = new_size;
}

#define	HASHSHIFT	3
#define	HASHMASK	0x1f

static u_int
get_hashval(char *value)
{
	int i, len;
	u_int hval = 0;

	len = strlen(value);
	for (i = 0; i < len; i++) {
		hval = ((hval<<HASHSHIFT)^hval);
		hval += (value[i] & HASHMASK);
	}

	return (hval);
}

static db_status
enumerate_dictionary(db_dict_desc *dd, db_status (*func) (db_table_desc*))
{
	int i;
	db_table_desc *bucket;
	db_status status;

	if (dd == NULL)
		return (DB_SUCCESS);

	for (i = 0; i < dd->tables.tables_len; i++) {
		bucket = dd->tables.tables_val[i];
		if (bucket) {
			status = enumerate_bucket(bucket, func);
			if (status != DB_SUCCESS)
				return (status);
		}
	}

	return (DB_SUCCESS);
}


/*
 * Look up target table_name in hashtable and return its db_table_desc.
 * Return NULL if not found.
 */
static db_table_desc *
search_dictionary(db_dict_desc *dd, char *target)
{
	register unsigned long hval;
	unsigned long bucket;

	if (target == NULL || dd == NULL || dd->tables.tables_len == 0)
		return (NULL);

	hval = get_hashval(target);
	bucket = hval % dd->tables.tables_len;

	db_table_desc_p fst = dd->tables.tables_val[bucket];

	if (fst != NULL)
		return (search_bucket(fst, hval, target));
	else
		return (NULL);
}

/*
 * Remove the entry with the target table_name from the dictionary.
 * If successful, return DB_SUCCESS; otherwise DB_NOTUNIQUE if target
 * is null; DB_NOTFOUND if entry is not found.
 * If successful, decrement count of number of entries in hash table.
 */
static db_status
remove_from_dictionary(db_dict_desc *dd, char *target, bool_t remove_storage)
{
	register unsigned long hval;
	unsigned long bucket;
	register db_table_desc *fst;

	if (target == NULL)
		return (DB_NOTUNIQUE);
	if (dd == NULL || dd->tables.tables_len == 0)
		return (DB_NOTFOUND);
	hval = get_hashval(target);
	bucket = hval % dd->tables.tables_len;
	fst = dd->tables.tables_val[bucket];
	if (fst == NULL)
		return (DB_NOTFOUND);
	if (remove_from_bucket(fst, &dd->tables.tables_val[bucket],
			hval, target, remove_storage)) {
		--(dd->count);
		return (DB_SUCCESS);
	} else
		return (DB_NOTFOUND);
}

/*
 * Add a new db_table_desc to the dictionary.
 * Return DB_NOTUNIQUE, if entry with identical table_name
 * already exists.  If entry is added, return DB_SUCCESS.
 * Increment count of number of entries in index table and grow table
 * if number of entries equals size of table.
 *
 * Inputs: db_dict_desc_p dd	pointer to dictionary to add to.
 *	   db_table_desc *td	pointer to table entry to be added. The
 * 				db_table_desc.next field will be altered
 *				without regard to it's current setting.
 *				This means that if next points to a list of
 *				table entries, they may be either linked into
 *				the dictionary unexpectly or cut off (leaked).
 */
static db_status
add_to_dictionary(db_dict_desc_p dd, db_table_desc *td)
{
	register unsigned long hval;
	char *target;

	if (dd == NULL)
		return (DB_NOTFOUND);

	if (td == NULL)
		return (DB_NOTFOUND);
	target = td->table_name;
	if (target == NULL)
		return (DB_NOTUNIQUE);

	hval = get_hashval(target);

	if (dd->tables.tables_val == NULL)
		grow_dictionary(dd);

	db_table_desc_p fst;
	unsigned long bucket;
	bucket = hval % dd->tables.tables_len;
	fst = dd->tables.tables_val[bucket];
	td->hashval = hval;
	if (fst == NULL)  { /* Empty bucket */
		dd->tables.tables_val[bucket] = td;
	} else if (!add_to_bucket(fst, &dd->tables.tables_val[bucket], td)) {
			return (DB_NOTUNIQUE);
		}

	/* increase hash table size if number of entries equals table size */
	if (++(dd->count) > dd->tables.tables_len)
		grow_dictionary(dd);

	return (DB_SUCCESS);
}

/* ******************* pickling routines for dictionary ******************* */


/* Does the actual writing to/from file specific for db_dict_desc structure. */
static bool_t
transfer_aux(XDR* x, pptr tbl)
{
	return (xdr_db_dict_desc_p(x, (db_dict_desc_p *) tbl));
}

class pickle_dict_desc: public pickle_file {
    public:
	pickle_dict_desc(char *f, pickle_mode m) : pickle_file(f, m) {}

	/* Transfers db_dict_desc structure pointed to by dp to/from file. */
	int transfer(db_dict_desc_p * dp)
		{ return (pickle_file::transfer((pptr) dp, &transfer_aux)); }
};

/* ************************ dictionary methods *************************** */

db_dictionary::db_dictionary()
{
	dictionary = NULL;
	initialized = FALSE;
	filename = NULL;
	tmpfilename = NULL;
	logfilename = NULL;
	logfile = NULL;
	logfile_opened = FALSE;
	changed = FALSE;
	INITRW(dict);
	READLOCKOK(dict);
}

/*
 * This routine clones an entire hash bucket chain. If you clone a
 * data dictionary entry with the ->next pointer set, you will get a
 * clone of that entry, as well as the entire linked list. This can cause
 * pain if you then pass the cloned bucket to routines such as
 * add_to_dictionary(), which do not expect nor handle dictionary hash
 * entries with the ->next pointer set. You might either get duplicate
 * entires or lose entries. If you wish to clone the entire bucket chain
 * and add it to a new dictionary, loop through the db_table_desc->next list
 * and call add_to_dictionary() for each item.
 */
int
db_dictionary::db_clone_bucket(db_table_desc *bucket, db_table_desc **clone)
{
	u_long		size;
	XDR		xdrs;
	char		*bufin = NULL;

	READLOCK(this, DB_LOCK_ERROR, "r db_dictionary::db_clone_bucket");
	db_func use_this = xdr_db_table_desc;
	size = xdr_sizeof((xdrproc_t) use_this, (void *) bucket);
	bufin = (char *) calloc(1, (size_t) size * sizeof (char));
	if (!bufin) {
		READUNLOCK(this, DB_MEMORY_LIMIT,
			"db_dictionary::insert_modified_table: out of memory");
		FATAL3("db_dictionary::insert_modified_table: out of memory",
			DB_MEMORY_LIMIT, 0);
	}
	xdrmem_create(&xdrs, bufin, (size_t) size, XDR_ENCODE);
	if (!xdr_db_table_desc(&xdrs, bucket)) {
		free(bufin);
		xdr_destroy(&xdrs);
		READUNLOCK(this, DB_MEMORY_LIMIT,
		"db_dictionary::insert_modified_table: xdr encode failed");
		FATAL3(
		"db_dictionary::insert_modified_table: xdr encode failed.",
		DB_MEMORY_LIMIT, 0);
	}
	*clone = (db_table_desc *) calloc(1, (size_t) size * sizeof (char));
	if (!*clone) {
		xdr_destroy(&xdrs);
		free(bufin);
		READUNLOCK(this, DB_MEMORY_LIMIT,
			"db_dictionary::insert_modified_table: out of memory");
		FATAL3("db_dictionary::insert_modified_table: out of memory",
			DB_MEMORY_LIMIT, 0);
	}

	xdrmem_create(&xdrs, bufin, (size_t) size, XDR_DECODE);
	if (!xdr_db_table_desc(&xdrs, *clone)) {
		free(bufin);
		free(*clone);
		xdr_destroy(&xdrs);
		READUNLOCK(this, DB_MEMORY_LIMIT,
		"db_dictionary::insert_modified_table: xdr encode failed");
		FATAL3(
		"db_dictionary::insert_modified_table: xdr encode failed.",
		DB_MEMORY_LIMIT, 0);
	}
	free(bufin);
	xdr_destroy(&xdrs);
	READUNLOCK(this, DB_LOCK_ERROR, "ru db_dictionary::db_clone_bucket");
	return (1);
}


int
db_dictionary::change_table_name(db_table_desc *clone, char *tok, char *repl)
{
	char 	*newname;
	char	*loc_end, *loc_beg;

	WRITELOCK(this, DB_LOCK_ERROR, "w db_dictionary::change_table_name");
	while (clone) {
		/*
		 * Special case for a tok="". This is used for the
		 * nisrestore(1M), when restoring a replica in another
		 * domain. This routine is used to change the datafile 
		 * names in the data.dict (see bugid #4031273). This will not
		 * effect massage_dict(), since it never generates an empty
		 * string for tok.
		 */
		if (strlen(tok) == 0) {
			strcat(clone->table_name, repl);
			clone = clone->next;
			continue;
		}
		newname = (char *) calloc(1, sizeof (char) *
				strlen(clone->table_name) +
				strlen(repl) - strlen(tok) + 1);
		if (!newname) {
			WRITEUNLOCK(this, DB_MEMORY_LIMIT,
			"db_dictionary::change_table_name: out of memory");
		    FATAL3("db_dictionary::change_table_name: out of memory.",
				DB_MEMORY_LIMIT, 0);
		}
		if (loc_beg = strstr(clone->table_name, tok)) {
			loc_end = loc_beg + strlen(tok);
			int s = loc_beg - clone->table_name;
			memcpy(newname, clone->table_name, s);
			strcat(newname + s, repl);
			strcat(newname, loc_end);
			free(clone->table_name);
			clone->table_name = newname;
		} else {
			free(newname);
		}
		clone = clone->next;
	}
	WRITEUNLOCK(this, DB_LOCK_ERROR,
			"wu db_dictionary::change_table_name");
	return (1);
}


#ifdef	curdict
#undef	curdict
#endif
/*
 * A function to initialize the temporary dictionary from the real
 * dictionary.
 */
bool_t
db_dictionary::inittemp(char *dictname, db_dictionary& curdict)
{
	int status;
	db_table_desc_p	*newtab;

	db_shutdown();

	WRITELOCK(this, FALSE, "w db_dictionary::inittemp");
	if (initialized) {
		/* Someone else got in between db_shutdown() and lock() */
		WRITEUNLOCK(this, FALSE, "wu db_dictionary::inittemp");
		return (TRUE);
	}

	pickle_dict_desc f(dictname, PICKLE_READ);
	filename = strdup(dictname);
	if (filename == NULL) {
		WRITEUNLOCK(this, FALSE,
			"db_dictionary::inittemp: could not allocate space");
		FATAL3("db_dictionary::inittemp: could not allocate space",
			DB_MEMORY_LIMIT, FALSE);
	}
	int len = strlen(filename);
	tmpfilename = new char[len+5];
	if (tmpfilename == NULL) {
		delete filename;
		WRITEUNLOCK(this, FALSE,
			"db_dictionary::inittemp: could not allocate space");
		FATAL3("db_dictionary::inittemp: could not allocate space",
			DB_MEMORY_LIMIT, FALSE);
	}
	logfilename = new char[len+5];
	if (logfilename == NULL) {
		delete filename;
		delete tmpfilename;
		WRITEUNLOCK(this, FALSE,
			"db_dictionary::inittemp: cannot allocate space");
		FATAL3("db_dictionary::inittemp: cannot allocate space",
			DB_MEMORY_LIMIT, FALSE);
	}

	sprintf(tmpfilename, "%s.tmp", filename);
	sprintf(logfilename, "%s.log", filename);
	unlink(tmpfilename);  /* get rid of partial checkpoints */
	dictionary = NULL;

	if ((status = f.transfer(&dictionary)) < 0) {
		initialized = FALSE;
	} else if (status == 1) { /* no dictionary exists, create one */
		dictionary = new db_dict_desc;
		if (dictionary == NULL) {
			WRITEUNLOCK(this, FALSE,
			"db_dictionary::inittemp: could not allocate space");
			FATAL3(
			"db_dictionary::inittemp: could not allocate space",
			DB_MEMORY_LIMIT, FALSE);
		}
		dictionary->tables.tables_len =
				curdict.dictionary->tables.tables_len;
		if ((newtab = (db_table_desc_p *) calloc(
			(unsigned int) dictionary->tables.tables_len,
			sizeof (db_table_desc_p))) == NULL) {
			WRITEUNLOCK(this, FALSE,
			"db_dictionary::inittemp: cannot allocate space");
			FATAL3(
			"db_dictionary::inittemp: cannot allocate space",
			DB_MEMORY_LIMIT, 0);
		}
		dictionary->tables.tables_val = newtab;
		dictionary->count = 0;
		dictionary->impl_vers = curdict.dictionary->impl_vers;
		initialized = TRUE;
	} else	/* dictionary loaded successfully */
		initialized = TRUE;

	if (initialized == TRUE) {
		changed = FALSE;
		reset_log();
	}

	WRITEUNLOCK(this, FALSE, "wu db_dictionary::inittemp");
	return (initialized);
}


/*
 * This method replaces the token string specified with the replacment
 * string specified. It assumes that at least one and only one instance of
 * the token exists. It is the responsibility of the caller to ensure that
 * the above assumption stays valid.
 */
db_status
db_dictionary::massage_dict(char *newdictname, char *tok, char *repl)
{
	int		retval;
	u_int		i, tbl_count;
	db_status	status;
	db_table_desc 	*bucket, *np, *clone, *next_np;
	char		tail[NIS_MAXNAMELEN];
	db_dictionary	*tmpptr;

	WRITELOCK(this, DB_LOCK_ERROR, "w db_dictionary::massage_dict");
	if (dictionary == NULL) {
		WRITEUNLOCK(this, DB_INTERNAL_ERROR,
		"db_dictionary::massage_dict: uninitialized dictionary file");
		FATAL3(
		"db_dictionary::massage_dict: uninitialized dictionary file.",
		DB_INTERNAL_ERROR, DB_INTERNAL_ERROR);
	}

	if ((tbl_count = dictionary->count) == 0) {
		WRITEUNLOCK(this, DB_SUCCESS,
				"wu db_dictionary::massage_dict");
		return (DB_SUCCESS);
	}

	/* First checkpoint */
	if ((status = checkpoint()) != DB_SUCCESS) {
		WRITEUNLOCK(this, status, "wu db_dictionary::massage_dict");
		return (status);
	}

#ifdef DEBUG
	enumerate_dictionary(dictionary, &print_table);
#endif

	/* Initialize the free dictionary so that we can start populating it */
	FreeDictionary->inittemp(newdictname, *this);

	for (i = 0; i < dictionary->tables.tables_len; i++) {
		bucket = dictionary->tables.tables_val[i];
		if (bucket) {
			np = bucket;
			while (np != NULL) {
				next_np = np->next;
				retval = db_clone_bucket(np, &clone);
				if (retval != 1) {
					WRITEUNLOCK(this, DB_INTERNAL_ERROR,
					"wu db_dictionary::massage_dict");
					return (DB_INTERNAL_ERROR);
				}
				if (change_table_name(clone, tok, repl) == -1) {
					delete_table_desc(clone);
					WRITEUNLOCK(this, DB_INTERNAL_ERROR,
					"wu db_dictionary::massage_dict");
					return (DB_INTERNAL_ERROR);
				}
				/*
				 * We know we don't have a log file, so we will
				 * just add to the in-memory database and dump
				 * all of it once we are done.
				 */
				status = add_to_dictionary
						(FreeDictionary->dictionary,
						clone);
				if (status != DB_SUCCESS) {
					delete_table_desc(clone);
					WRITEUNLOCK(this, DB_INTERNAL_ERROR,
					"wu db_dictionary::massage_dict");
					return (DB_INTERNAL_ERROR);
				}
				status = remove_from_dictionary(dictionary,
							np->table_name, TRUE);
				if (status != DB_SUCCESS) {
					delete_table_desc(clone);
					WRITEUNLOCK(this, DB_INTERNAL_ERROR,
					"wu db_dictionary::massage_dict");
					return (DB_INTERNAL_ERROR);
				}
				np = next_np;
			}
		}
	}

	if (FreeDictionary->dump() != DB_SUCCESS) {
		WRITEUNLOCK(this, DB_INTERNAL_ERROR,
				"wu db_dictionary::massage_dict");
		FATAL3(
		"db_dictionary::massage_dict: Unable to dump new dictionary.",
		DB_INTERNAL_ERROR, DB_INTERNAL_ERROR);
	}

	/*
	 * Now, shutdown the inuse dictionary and update the FreeDictionary
	 * and InUseDictionary pointers as well. Also, delete the old dictionary
	 * file.
	 */
	unlink(filename); /* There shouldn't be a tmpfile or logfile */
	db_shutdown();
	tmpptr = InUseDictionary;
	InUseDictionary = FreeDictionary;
	FreeDictionary = tmpptr;
	WRITEUNLOCK(this, DB_LOCK_ERROR, "wu db_dictionary::massage_dict");
	return (DB_SUCCESS);
}


db_status
db_dictionary::merge_dict(db_dictionary& tempdict, char *tok, char *repl)
{

	db_status	dbstat = DB_SUCCESS;

	db_table_desc	*tbl = NULL, *clone = NULL, *next_td = NULL;
	int		retval, i;

	WRITELOCK(this, DB_LOCK_ERROR, "w db_dictionary::merge_dict");

	for (i = 0; i < tempdict.dictionary->tables.tables_len; ++i) {
		tbl = tempdict.dictionary->tables.tables_val[i];
		if (!tbl)
			continue;
		retval = db_clone_bucket(tbl, &clone);
		if (retval != 1) {
			WRITEUNLOCK(this, DB_INTERNAL_ERROR,
					"wu db_dictionary::merge_dict");
			return (DB_INTERNAL_ERROR);
		}
		while (clone) {
			next_td = clone->next;
			clone->next = NULL;
			if ((tok) &&
				(change_table_name(clone, tok, repl) == -1)) {
				delete_table_desc(clone);
				if (next_td)
					delete_table_desc(next_td);
				WRITEUNLOCK(this, DB_INTERNAL_ERROR,
					"wu db_dictionary::merge_dict");
				return (DB_INTERNAL_ERROR);
			}
			
			dbstat = add_to_dictionary(dictionary, clone);
			if (dbstat == DB_NOTUNIQUE) {
				/* Overide */
				dbstat = remove_from_dictionary(dictionary,
						clone->table_name, TRUE);
				if (dbstat != DB_SUCCESS) {
					WRITEUNLOCK(this, dbstat,
					"wu db_dictionary::merge_dict");
					return (dbstat);
				}
				dbstat = add_to_dictionary(dictionary,
								clone);
			} else {
				if (dbstat != DB_SUCCESS) {
					WRITEUNLOCK(this, dbstat,
					"wu db_dictionary::merge_dict");
					return (dbstat);
				}
			}
			clone = next_td;
		}
	}
/*
 * If we were successful in merging the dictionaries, then mark the
 * dictionary changed, so that it will be properly checkpointed and
 * dumped to disk.
 */
	if (dbstat == DB_SUCCESS)
		changed = TRUE;
	WRITEUNLOCK(this, DB_LOCK_ERROR, "wu db_dictionary::merge_dict");
	return (dbstat);
}

int
db_dictionary::copyfile(char *infile, char *outfile)
{
	db_table_desc	*tbl = NULL;
	db	*dbase;
	int	ret;

	READLOCK(this, DB_LOCK_ERROR, "r db_dictionary::copyfile");
	/*
	 * We need to hold the read-lock until the dump() is done.
	 * However, we must avoid the lock migration (read -> write)
	 * that would happen in find_table() if the db must be loaded.
	 * Hence, look first look for an already loaded db.
	 */
	dbase  = find_table(infile, &tbl, TRUE, TRUE, FALSE);
	if (dbase == NULL) {
		/* Release the read-lock, and try again, allowing load */
		READUNLOCK(this, DB_LOCK_ERROR, "ru db_dictionary::copyfile");
		dbase  = find_table(infile, &tbl, TRUE, TRUE, TRUE);
		if (dbase == NULL)
			return (DB_NOTFOUND);
		/*
		 * Read-lock again, and get a 'tbl' we can use since we're
		 * still holding the lock.
		 */
		READLOCK(this, DB_LOCK_ERROR, "r db_dictionary::copyfile");
		dbase  = find_table(infile, &tbl, TRUE, TRUE, FALSE);
		if (dbase == NULL) {
			READUNLOCK(this, DB_NOTFOUND,
					"ru db_dictionary::copyfile");
			return (DB_NOTFOUND);
		}
	}
	ret = tbl->database->dump(outfile) ? DB_SUCCESS : DB_INTERNAL_ERROR;
	READUNLOCK(this, ret, "ru db_dictionary::copyfile");
	return (ret);
}


bool_t
db_dictionary::extract_entries(db_dictionary& tempdict, char **fs, int fscnt)
{
	int		i, retval;
	db_table_desc	*tbl, *clone;
	db_table_desc	tbl_ent;
	db_status	dbstat;

	READLOCK(this, FALSE, "r db_dictionary::extract_entries");
	for (i = 0; i < fscnt; ++i) {
		tbl = find_table_desc(fs[i]);
		if (!tbl) {
			syslog(LOG_DEBUG,
				"extract_entries: no dictionary entry for %s",
				fs[i]);
			READUNLOCK(this, FALSE,
					"ru db_dictionary::extract_entries");
			return (FALSE);
		} else {
			tbl_ent.table_name = tbl->table_name;
			tbl_ent.hashval = tbl->hashval;
			tbl_ent.scheme = tbl->scheme;
			tbl_ent.database = tbl->database;
			tbl_ent.next = NULL;
		}
		retval = db_clone_bucket(&tbl_ent, &clone);
		if (retval != 1) {
			syslog(LOG_DEBUG,
			"extract_entries: unable to clone entry for %s",
			fs[i]);
			READUNLOCK(this, FALSE,
					"ru db_dictionary::extract_entries");
			return (FALSE);
		}
		dbstat = add_to_dictionary(tempdict.dictionary, clone);
		if (dbstat != DB_SUCCESS) {
			delete_table_desc(clone);
			READUNLOCK(this, FALSE,
					"ru db_dictionary::extract_entries");
			return (FALSE);
		}
	}
	if (tempdict.dump() != DB_SUCCESS) {
		READUNLOCK(this, FALSE,
				"ru db_dictionary::extract_entries");
		return (FALSE);
	}
	READUNLOCK(this, FALSE,
			"ru db_dictionary::extract_entries");
	return (TRUE);
}


/*
 * Initialize dictionary from contents in 'file'.
 * If there is already information in this dictionary, it is removed.
 * Therefore, regardless of whether the load from the file succeeds,
 * the contents of this dictionary will be altered.  Returns
 * whether table has been initialized successfully.
 */
bool_t
db_dictionary::init(char *file)
{
	int status;

	WRITELOCK(this, FALSE, "w db_dictionary::init");
	db_shutdown();

	pickle_dict_desc f(file, PICKLE_READ);
	filename = strdup(file);
	if (filename == NULL) {
		WRITEUNLOCK(this, FALSE,
			"db_dictionary::init: could not allocate space");
		FATAL3("db_dictionary::init: could not allocate space",
			DB_MEMORY_LIMIT, FALSE);
	}
	int len = strlen(filename);
	tmpfilename = new char[len+5];
	if (tmpfilename == NULL) {
		delete filename;
		WRITEUNLOCK(this, FALSE,
			"db_dictionary::init: could not allocate space");
		FATAL3("db_dictionary::init: could not allocate space",
			DB_MEMORY_LIMIT, FALSE);
	}
	logfilename = new char[len+5];
	if (logfilename == NULL) {
		delete filename;
		delete tmpfilename;
		WRITEUNLOCK(this, FALSE,
				"db_dictionary::init: cannot allocate space");
		FATAL3("db_dictionary::init: cannot allocate space",
			DB_MEMORY_LIMIT, FALSE);
	}

	sprintf(tmpfilename, "%s.tmp", filename);
	sprintf(logfilename, "%s.log", filename);
	unlink(tmpfilename);  /* get rid of partial checkpoints */
	dictionary = NULL;

	/* load dictionary */
	if ((status = f.transfer(&dictionary)) < 0) {
	    initialized = FALSE;
	} else if (status == 1) {  /* no dictionary exists, create one */
	    dictionary = new db_dict_desc;
	    if (dictionary == NULL) {
		WRITEUNLOCK(this, FALSE,
			"db_dictionary::init: could not allocate space");
		FATAL3("db_dictionary::init: could not allocate space",
			DB_MEMORY_LIMIT, FALSE);
	    }
	    dictionary->tables.tables_len = 0;
	    dictionary->tables.tables_val = NULL;
	    dictionary->count = 0;
	    dictionary->impl_vers = DB_CURRENT_VERSION;
	    initialized = TRUE;
	} else  /* dictionary loaded successfully */
	    initialized = TRUE;

	if (initialized == TRUE) {
	    int num_changes = 0;
	    changed = FALSE;
	    reset_log();
	    if ((num_changes = incorporate_log(logfilename)) < 0)
		syslog(LOG_ERR,
			"incorporation of dictionary logfile '%s' failed",
			logfilename);
	    changed = (num_changes > 0);
	}

	WRITEUNLOCK(this, initialized, "wu db_dictionary::init");
	return (initialized);
}

/*
 * Execute log entry 'j' on the dictionary identified by 'dict' if the
 * version of j is later than that of the dictionary.  If 'j' is executed,
 * 'count' is incremented and the dictionary's verison is updated to
 * that of 'j'.
 * Returns TRUE always for valid log entries; FALSE otherwise.
 */
static bool_t
apply_log_entry(db_dictlog_entry *j, char *dictchar, int *count)
{
	db_dictionary *dict = (db_dictionary*) dictchar;

	WRITELOCK(dict, FALSE, "w apply_log_entry");
	if (db_update_version.earlier_than(j->get_version())) {
		++ *count;
#ifdef DEBUG
		j->print();
#endif /* DEBUG */
		switch (j->get_action()) {
		case DB_ADD_TABLE:
			dict->add_table_aux(j->get_table_name(),
				j->get_table_object(), INMEMORY_ONLY);
			// ignore status
			break;

		case DB_REMOVE_TABLE:
			dict->delete_table_aux(j->get_table_name(),
							INMEMORY_ONLY);
			// ignore status
			break;

		default:
			WARNING("db::apply_log_entry: unknown action_type");
			WRITEUNLOCK(dict, FALSE, "wu apply_log_entry");
			return (FALSE);
		}
		db_update_version.assign(j->get_version());
	}

	WRITEUNLOCK(dict, TRUE, "wu apply_log_entry");
	return (TRUE);
}

int
db_dictionary::incorporate_log(char *file_name)
{
	db_dictlog f(file_name, PICKLE_READ);
	int	ret;

	WRITELOCK(this, -1, "w db_dictionary::incorporate_log");
	setNoWriteThrough();
	ret = f.execute_on_log(&(apply_log_entry), (char *) this);
	clearNoWriteThrough();
	WRITEUNLOCK(this, -1, "wu db_dictionary::incorporate_log");
	return (ret);
}


/* Frees memory of filename and tables.  Has no effect on disk storage. */
db_status
db_dictionary::db_shutdown()
{
	WRITELOCK(this, DB_LOCK_ERROR, "w db_dictionary::db_shutdown");
	if (!initialized) {
		WRITEUNLOCK(this, DB_LOCK_ERROR,
				"wu db_dictionary::db_shutdown");
		return (DB_SUCCESS); /* DB_NOTFOUND? */
	}

	if (filename) {
		delete filename;
		filename = NULL;
	}
	if (tmpfilename) {
		delete tmpfilename;
		tmpfilename = NULL;
	}
	if (logfilename) {
		delete logfilename;
		logfilename = NULL;
	}
	if (dictionary) {
		delete_dictionary(dictionary);
		dictionary = NULL;
	}
	initialized = FALSE;
	changed = FALSE;
	reset_log();

	WRITEUNLOCK(this, DB_LOCK_ERROR, "wu db_dictionary::db_shutdown");
	return (DB_SUCCESS);
}

/*
 * Dump contents of this dictionary (minus the database representations)
 * to its file. Returns 0 if operation succeeds, -1 otherwise.
 */
int
db_dictionary::dump()
{
	int status;

	READLOCK(this, -1, "r db_dictionary::dump");
	if (!initialized) {
		READUNLOCK(this, -1, "ru db_dictionary::dump");
		return (-1);
	}

	unlink(tmpfilename);  /* get rid of partial dumps */
	pickle_dict_desc f(tmpfilename, PICKLE_WRITE);

	status = f.transfer(&dictionary); 	/* dump table descs */
	if (status != 0) {
		WARNING("db_dictionary::dump: could not write out dictionary");
	} else if (rename(tmpfilename, filename) < 0) {
		WARNING_M("db_dictionary::dump: could not rename temp file: ");
		status = -1;
	}

	READUNLOCK(this, -1, "ru db_dictionary::dump");
	return (status);
}

/*
 * Write out in-memory copy of dictionary to file.
 * 1.  Update major version.
 * 2.  Dump contents to temporary file.
 * 3.  Rename temporary file to real dictionary file.
 * 4.  Remove log file.
 * A checkpoint is done only if it has changed since the previous checkpoint.
 * Returns DB_SUCCESS if checkpoint was successful; error code otherwise
 */
db_status
db_dictionary::checkpoint()
{
	WRITELOCK(this, DB_LOCK_ERROR, "w db_dictionary::checkpoint");

	if (changed == FALSE) {
		WRITEUNLOCK(this, DB_LOCK_ERROR,
				"wu db_dictionary::checkpoint");
		return (DB_SUCCESS);
	}

	vers *oldv = new vers(db_update_version);	// copy
	vers * newv = db_update_version.nextmajor();	// get next version
	db_update_version.assign(newv);			// update version
	delete newv;

	if (dump() != 0) {
		WARNING_M(
		    "db_dictionary::checkpoint: could not dump dictionary: ");
		db_update_version.assign(oldv);  // rollback
		delete oldv;
		WRITEUNLOCK(this, DB_INTERNAL_ERROR,
			"wu db_dictionary::checkpoint");
		return (DB_INTERNAL_ERROR);
	}
	unlink(logfilename);	/* should do atomic rename and log delete */
	reset_log();		/* should check for what? */
	delete oldv;
	changed = FALSE;
	WRITEUNLOCK(this, DB_LOCK_ERROR, "wu db_dictionary::checkpoint");
	return (DB_SUCCESS);
}

/* close existing logfile and delete its structure */
int
db_dictionary::reset_log()
{
	WRITELOCK(this, -1, "w db_dictionary::reset_log");
	/* try to close old log file */
	/* doesnot matter since we do synchronous writes only */
	if (logfile != NULL) {
		if (logfile_opened == TRUE) {
			if (logfile->close() < 0) {
				WARNING_M(
			"db_dictionary::reset_log: could not close log file: ");
			}
		}
		delete logfile;
		logfile = NULL;
	}
	logfile_opened = FALSE;
	WRITEUNLOCK(this, -1, "wu db_dictionary::reset_log");
	return (0);
}

/* close existing logfile, but leave its structure if exists */
int
db_dictionary::close_log()
{
	WRITELOCK(this, -1, "w db_dictionary::close_log");
	if (logfile != NULL && logfile_opened == TRUE) {
		logfile->close();
	}
	logfile_opened = FALSE;
	WRITEUNLOCK(this, -1, "wu db_dictionary::close_log");
	return (0);
}

/* open logfile, creating its structure if it does not exist */
int
db_dictionary::open_log()
{
	WRITELOCK(this, -1, "w db_dictionary::open_log");
	if (logfile == NULL) {
		if ((logfile = new db_dictlog(logfilename, PICKLE_APPEND)) ==
				NULL) {
			WRITEUNLOCK(this, -1, "wu db_dictionary::open_log");
			FATAL3(
			"db_dictionary::reset_log: cannot allocate space",
				DB_MEMORY_LIMIT, -1);
		}
	}

	if (logfile_opened == TRUE) {
		WRITEUNLOCK(this, -1, "wu db_dictionary::open_log");
		return (0);
	}

	if ((logfile->open()) == FALSE) {
		WARNING_M("db_dictionary::open_log: could not open log file: ");
		delete logfile;
		logfile = NULL;
		WRITEUNLOCK(this, -1, "wu db_dictionary::open_log");
		return (-1);
	}

	logfile_opened = TRUE;
	WRITEUNLOCK(this, -1, "wu db_dictionary::open_log");
	return (0);
}

/*
 * closes any open log files for all tables in dictionary or 'tab'.
 * "tab" is an optional argument.
 */
static int close_standby_list();

db_status
db_dictionary::db_standby(char *tab)
{
	db_table_desc *tbl;

	WRITELOCK(this, DB_LOCK_ERROR, "w db_dictionary::db_standby");
	if (!initialized) {
		WRITEUNLOCK(this, DB_BADDICTIONARY,
				"wu db_dictionary::db_standby");
		return (DB_BADDICTIONARY);
	}

	if (tab == NULL) {
	    close_log();  // close dictionary log
	    close_standby_list();
	    WRITEUNLOCK(this, DB_LOCK_ERROR, "wu db_dictionary::db_standby");
	    return (DB_SUCCESS);
	}

	if ((tbl = find_table_desc(tab)) == NULL) {
	    WRITEUNLOCK(this, DB_LOCK_ERROR, "wu db_dictionary::db_standby");
	    return (DB_BADTABLE);
	}

	if (tbl->database != NULL)
	    tbl->database->close_log();
	WRITEUNLOCK(this, DB_LOCK_ERROR, "wu db_dictionary::db_standby");
	return (DB_SUCCESS);
}

/*
 * Returns db_table_desc of table name 'tab'.  'prev', if supplied,
 * is set to the entry located ahead of 'tab's entry in the dictionary.
 */
db_table_desc*
db_dictionary::find_table_desc(char *tab)
{
	db_table_desc	*ret;

	READLOCK(this, NULL, "r db_dictionary::find_table_desc");
	if (initialized)
		ret = search_dictionary(dictionary, tab);
	else
		ret = NULL;

	READUNLOCK(this, ret, "r db_dictionary::find_table_desc");
	return (ret);
}

db_table_desc *
db_dictionary::find_table_desc(char *tab, bool_t searchDeferred) {
	db_table_desc	*ret = NULL;

	READLOCK(this, NULL, "r db_dictionary::find_table_desc_d");

	/* If desired, look in the deferred dictionary first */
	if (initialized && searchDeferred && deferred.dictionary != NULL)
		ret = search_dictionary(deferred.dictionary, tab);

	/* No result yet => search the "normal" dictionary */
	if (ret == NULL)
		ret = find_table_desc(tab);

	READUNLOCK(this, ret, "r db_dictionary::find_table_desc_d");
	return (ret);
}

db *
db_dictionary::find_table(char *tab, db_table_desc **where) {
	/* Most operations should use the deferred dictionary if it exists */
	return (find_table(tab, where, TRUE, TRUE, TRUE));
}

db *
db_dictionary::find_table(char *tab, db_table_desc **where,
				bool_t searchDeferred) {
	return (find_table(tab, where, searchDeferred, TRUE, TRUE));
}

db *
db_dictionary::find_table(char *tab, db_table_desc **where,
				bool_t searchDeferred, bool_t doLDAP,
				bool_t doLoad) {
	db			*res;
	int			lstat;
	db_status		dstat;
	const char		*myself = "db_dictionary::find_table";

	res = find_table_noLDAP(tab, where, searchDeferred, doLoad);
	/* If found, or shouldn't try LDAP, we're done */
	if (res != 0 || !doLDAP)
		return (res);

	/* See if we can retrieve the object from LDAP */
	dstat = dbCreateFromLDAP(tab, &lstat);
	if (dstat != DB_SUCCESS) {
		if (dstat == DB_NOTFOUND) {
			if (lstat != LDAP_SUCCESS) {
				logmsg(MSG_NOTIMECHECK, LOG_INFO,
					"%s: LDAP error for \"%s\": %s",
					myself, NIL(tab),
					ldap_err2string(lstat));
			}
		} else {
			logmsg(MSG_NOTIMECHECK, LOG_INFO,
				"%s: DB error %d for \"%s\"",
				myself, dstat, NIL(tab));
		}
		return (0);
	}

	/* Try the dictionary again */
	res = find_table_noLDAP(tab, where, searchDeferred, doLoad);

	return (res);
}

/*
 * Return database structure of table named by 'tab'.
 * If 'where' is set, set it to the table_desc of 'tab.'
 * If the database is loaded in from stable store if it has not been loaded.
 * If it cannot be loaded, it is initialized using the scheme stored in
 * the table_desc.  NULL is returned if the initialization fails.
 */
db *
db_dictionary::find_table_noLDAP(char *tab, db_table_desc **where,
				bool_t searchDeferred, bool_t doLoad)
{
	if (!initialized)
		return (NULL);

	db_table_desc* tbl;
	db *dbase = NULL;
	int		lret;

	READLOCK(this, NULL, "r db_dictionary::find_table");
	tbl = find_table_desc(tab, searchDeferred);
	if (tbl == NULL) {
		READUNLOCK(this, NULL, "ru db_dictionary::find_table");
		return (NULL);		// not found
	}

	if (tbl->database != NULL || !doLoad) {
		if (tbl->database && where) *where = tbl;
		READUNLOCK(this, NULL, "ru db_dictionary::find_table");
		return (tbl->database);  // return handle
	}

	READUNLOCK(this, NULL, "ru db_dictionary::find_table");
	WRITELOCK(this, NULL, "w db_dictionary::find_table");
	/* Re-check; some other thread might have loaded the db */
	if (tbl->database != NULL) {
		if (where) *where = tbl;
		WRITEUNLOCK(this, NULL, "wu db_dictionary::find_table");
		return (tbl->database);  // return handle
	}

	// need to load in/init database
	dbase = new db(tab);

	if (dbase == NULL) {
		WRITEUNLOCK(this, NULL,
			"db_dictionary::find_table: could not allocate space");
		FATAL3("db_dictionary::find_table: could not allocate space",
			DB_MEMORY_LIMIT, NULL);
	}

	/*
	 * Lock the newly created 'dbase', so we can release the general
	 * db_dictionary lock.
	 */
	WRITELOCKNR(dbase, lret, "w dbase db_dictionary::find_table");
	if (lret != 0) {
		WRITEUNLOCK(this, NULL,
			"db_dictionary::find_table: could not lock dbase");
		FATAL3("db_dictionary::find_table: could not lock dbase",
			DB_LOCK_ERROR, NULL);
	}
	/* Assign tbl->database, and then release the 'this' lock */
	tbl->database = dbase;
	WRITEUNLOCK(this, NULL, "wu db_dictionary::find_table");

	if (dbase->load()) {			// try to load in database
		if (where) *where = tbl;
		WRITEUNLOCK(dbase, dbase, "wu dbase db_dictionary::find_table");
		return (dbase);
	}

	delete dbase;
	tbl->database = NULL;
	WARNING("db_dictionary::find_table: could not load database");
	return (NULL);
}

/* Log action to be taken on the  dictionary and update db_update_version. */

db_status
db_dictionary::log_action(int action, char *tab, table_obj *tobj)
{
	WRITELOCK(this, DB_LOCK_ERROR, "w db_dictionary::log_action");

	vers *newv = db_update_version.nextminor();
	db_dictlog_entry le(action, newv, tab, tobj);

	if (open_log() < 0) {
		delete newv;
		WRITEUNLOCK(this, DB_STORAGE_LIMIT,
				"wu db_dictionary::log_action");
		return (DB_STORAGE_LIMIT);
	}

	if (logfile->append(&le) < 0) {
		WARNING_M("db::log_action: could not add log entry: ");
		close_log();
		delete newv;
		WRITEUNLOCK(this, DB_STORAGE_LIMIT,
				"wu db_dictionary::log_action");
		return (DB_STORAGE_LIMIT);
	}

	db_update_version.assign(newv);
	delete newv;
	changed = TRUE;

	WRITEUNLOCK(this, DB_LOCK_ERROR, "wu db_dictionary::log_action");
	return (DB_SUCCESS);
}

// For a complete 'delete' operation, we want the following behaviour:
// 1. If there is an entry in the log, the physical table exists and is
//    stable.
// 2. If there is no entry in the log, the physical table may or may not
//    exist.

db_status
db_dictionary::delete_table_aux(char *tab, int mode)
{
	db_status	ret;

	WRITELOCK(this, DB_LOCK_ERROR, "w db_dictionary::delete_table_aux");
	if (!initialized) {
		WRITEUNLOCK(this, DB_LOCK_ERROR,
				"wu db_dictionary::delete_table_aux");
		return (DB_BADDICTIONARY);
	}

	db_table_desc *tbl;
	if ((tbl = find_table_desc(tab)) == NULL) { // table not found
		WRITEUNLOCK(this, DB_LOCK_ERROR,
				"wu db_dictionary::delete_table_aux");
		return (DB_NOTFOUND);
	}

	if (mode != INMEMORY_ONLY) {
		int need_free = 0;

		// Update log.
		db_status status = log_action(DB_REMOVE_TABLE, tab);
		if (status != DB_SUCCESS) {
			WRITEUNLOCK(this, status,
				"wu db_dictionary::delete_table_aux");
			return (status);
		}

		// Remove physical structures
		db *dbase = tbl->database;
		if (dbase == NULL) {	// need to get desc to access files
			dbase = new db(tab);
			need_free = 1;
		}
		if (dbase == NULL) {
			WARNING(
		"db_dictionary::delete_table: could not create db structure");
			WRITEUNLOCK(this, DB_MEMORY_LIMIT,
					"wu db_dictionary::delete_table_aux");
			return (DB_MEMORY_LIMIT);
		}
		dbase->remove_files();	// remove physical files
		if (need_free)
			delete dbase;
	}

	// Remove in-memory structures
	ret = remove_from_dictionary(dictionary, tab, TRUE);
	WRITEUNLOCK(this, ret, "wu db_dictionary::delete_table_aux");
	return (ret);
}

/*
 * Delete table with given name 'tab' from dictionary.
 * Returns error code if table does not exist or if dictionary has not been
 * initialized.   Dictionary is updated to stable store if deletion is
 * successful.  Fatal error occurs if dictionary cannot be saved.
 * Returns DB_SUCCESS if dictionary has been updated successfully.
 * Note that the files associated with the table are also removed.
 */
db_status
db_dictionary::delete_table(char *tab)
{
	return (delete_table_aux(tab, !INMEMORY_ONLY));
}

// For a complete 'add' operation, we want the following behaviour:
// 1. If there is an entry in the log, then the physical table exists and
//    has been initialized properly.
// 2. If there is no entry in the log, the physical table may or may not
//    exist.  In this case, we don't really care because we cannot get at
//    it.  The next time we add a table with the same name to the dictionary,
//    it will be initialized properly.
// This mode is used when the table is first created.
//
// For an INMEMORY_ONLY operation, only the internal structure is created and
// updated.  This mode is used when the database gets loaded and the internal
// dictionary gets updated from the log entries.

db_status
db_dictionary::add_table_aux(char *tab, table_obj* tobj, int mode)
{
	db_status	ret;

	WRITELOCK(this, DB_LOCK_ERROR, "w db_dictionary::add_table_aux");
	if (!initialized) {
		WRITEUNLOCK(this, DB_LOCK_ERROR,
				"wu db_dictionary::add_table_aux");
		return (DB_BADDICTIONARY);
	}

	if (find_table_desc(tab) != NULL) {
		WRITEUNLOCK(this, DB_LOCK_ERROR,
				"wu db_dictionary::add_table_aux");
		return (DB_NOTUNIQUE);		// table already exists
	}

	// create data structures for table
	db_table_desc *new_table = 0;
	db_status status = create_table_desc(tab, tobj, &new_table);

	if (status != DB_SUCCESS) {
		WRITEUNLOCK(this, DB_LOCK_ERROR,
				"wu db_dictionary::add_table_aux");
		return (status);
	}

	if (mode != INMEMORY_ONLY) {
		// create physical structures for table
		new_table->database = new db(tab);
		if (new_table->database == NULL) {
			delete_table_desc(new_table);
			WRITEUNLOCK(this, DB_MEMORY_LIMIT,
		"db_dictionary::add_table: could not allocate space for db");
			FATAL3(
		    "db_dictionary::add_table: could not allocate space for db",
			DB_MEMORY_LIMIT, DB_MEMORY_LIMIT);
		}
		if (new_table->database->init(new_table->scheme) == 0) {
			WARNING(
	"db_dictionary::add_table: could not initialize database from scheme");
			new_table->database->remove_files();
			delete_table_desc(new_table);
			WRITEUNLOCK(this, DB_STORAGE_LIMIT,
				"wu db_dictionary::add_table_aux");
			return (DB_STORAGE_LIMIT);
		}

		// update 'external' copy of dictionary
		status = log_action(DB_ADD_TABLE, tab, tobj);

		if (status != DB_SUCCESS) {
			new_table->database->remove_files();
			delete_table_desc(new_table);
			WRITEUNLOCK(this, status,
					"wu db_dictionary::add_table_aux");
			return (status);
		}
	}

	// finally, update in-memory copy of dictionary
	ret = add_to_dictionary(dictionary, new_table);
	WRITEUNLOCK(this, ret, "wu db_dictionary::add_table_aux");
	return (ret);
}

/*
 * Add table with given name 'tab' and description 'zdesc' to dictionary.
 * Returns error code if table already exists, or if no memory can be found
 * to store the descriptor, or if dictionary has not been intialized.
 * Dictionary is updated to stable store if addition is successful.
 * Fatal error occurs if dictionary cannot be saved.
 * Returns DB_SUCCESS if dictionary has been updated successfully.
*/
db_status
db_dictionary::add_table(char *tab, table_obj* tobj)
{
	return (add_table_aux(tab, tobj, !INMEMORY_ONLY));
}

/*
 * Translate given NIS attribute list to a db_query structure.
 * Return FALSE if dictionary has not been initialized, or
 * table does not have a scheme (which should be a fatal error?).
 */
db_query*
db_dictionary::translate_to_query(db_table_desc* tbl, int numattrs,
				nis_attr* attrlist)
{
	READLOCK(this, NULL, "r db_dictionary::translate_to_query");
	if (!initialized ||
		tbl->scheme == NULL || numattrs == 0 || attrlist == NULL) {
		READUNLOCK(this, NULL, "ru db_dictionary::translate_to_query");
		return (NULL);
	}

	db_query *q = new db_query(tbl->scheme, numattrs, attrlist);
	if (q == NULL) {
		READUNLOCK(this, NULL,
			"db_dictionary::translate: could not allocate space");
		FATAL3("db_dictionary::translate: could not allocate space",
			DB_MEMORY_LIMIT, NULL);
	}

	if (q->size() == 0) {
		delete q;
		READUNLOCK(this, NULL, "ru db_dictionary::translate_to_query");
		return (NULL);
	}
	READUNLOCK(this, NULL, "ru db_dictionary::translate_to_query");
	return (q);
}

static db_table_names gt_answer;
static int gt_posn;

static db_status
get_table_name(db_table_desc* tbl)
{
	if (tbl)
		return (DB_BADTABLE);

	if (gt_posn < gt_answer.db_table_names_len)
		gt_answer.db_table_names_val[gt_posn++] =
			strdup(tbl->table_name);
	else
		return (DB_BADTABLE);

	return (DB_SUCCESS);
}


/*
 * Return the names of tables in this dictionary.
 * XXX This routine is used only for testing only;
 *	if to be used for real, need to free memory sensibly, or
 *	caller of get_table_names should have freed them.
 */
db_table_names*
db_dictionary::get_table_names()
{
	READLOCK(this, NULL, "r db_dictionary::get_table_names");
	gt_answer.db_table_names_len = dictionary->count;
	gt_answer.db_table_names_val = new db_table_namep[dictionary->count];
	gt_posn = 0;
	if ((gt_answer.db_table_names_val) == NULL) {
		READUNLOCK(this, NULL,
	"db_dictionary::get_table_names: could not allocate space for names");
		FATAL3(
	"db_dictionary::get_table_names: could not allocate space for names",
		DB_MEMORY_LIMIT, NULL);
	}

	enumerate_dictionary(dictionary, &get_table_name);
	READUNLOCK(this, NULL, "ru db_dictionary::get_table_names");
	return (&gt_answer);
}

static db_status
db_checkpoint_aux(db_table_desc *current)
{
	db *dbase;
	int status;

	if (current == NULL)
		return (DB_BADTABLE);

	if (current->database == NULL) {  /* need to load it in */
		dbase = new db(current->table_name);
		if (dbase == NULL) {
			FATAL3(
		    "db_dictionary::db_checkpoint: could not allocate space",
			DB_MEMORY_LIMIT, DB_MEMORY_LIMIT);
		}
		if (dbase->load() == 0) {
			syslog(LOG_ERR,
			"db_dictionary::db_checkpoint: could not load table %s",
							current->table_name);
			delete dbase;
			return (DB_BADTABLE);
		}
		status = dbase->checkpoint();
		delete dbase;  // unload
	} else
	    status = current->database->checkpoint();

	if (status == 0)
		return (DB_STORAGE_LIMIT);
	return (DB_SUCCESS);
}

/* Like db_checkpoint_aux except only stops on LIMIT errors */
static db_status
db_checkpoint_aux_cont(db_table_desc *current)
{
	db_status status = db_checkpoint_aux(current);

	if (status == DB_STORAGE_LIMIT || status == DB_MEMORY_LIMIT)
		return (status);
	else
		return (DB_SUCCESS);
}

db_status
db_dictionary::db_checkpoint(char *tab)
{
	db_table_desc *tbl;
	db_status	ret;
	bool_t		init;

	READLOCK(this, DB_LOCK_ERROR, "r db_dictionary::db_checkpoint");
	init = initialized;
	READUNLOCK(this, DB_LOCK_ERROR, "ru db_dictionary::db_checkpoint");
	if (!init)
		return (DB_BADDICTIONARY);

	checkpoint();	// checkpoint dictionary first

	READLOCK(this, DB_LOCK_ERROR, "r db_dictionary::db_checkpoint");

	if (tab == NULL) {
	    ret = enumerate_dictionary(dictionary, &db_checkpoint_aux_cont);
	    READUNLOCK(this, ret, "ru db_dictionary::db_checkpoint");
	    return (ret);
	}

	if ((tbl = find_table_desc(tab)) == NULL) {
		READUNLOCK(this, DB_LOCK_ERROR,
				"ru db_dictionary::db_checkpoint");
	    return (DB_BADTABLE);
	}

	ret = db_checkpoint_aux(tbl);
	READUNLOCK(this, ret, "ru db_dictionary::db_checkpoint");
	return (ret);
}

/* *********************** db_standby **************************** */
/* Deal with list of tables that need to be 'closed' */

#define	OPENED_DBS_CHUNK	12
static db	**db_standby_list;
static uint_t	db_standby_size = 0;
static uint_t	db_standby_count = 0;
DECLMUTEXLOCK(db_standby_list);

/*
 * Returns 1 if all databases on the list could be closed, 0
 * otherwise.
 */
static int
close_standby_list()
{
	db		*database;
	int		i, ret;
	const char	*myself = "close_standby_list";

	MUTEXLOCK(db_standby_list, "close_standby_list");

	if (db_standby_count == 0) {
		MUTEXUNLOCK(db_standby_list, "close_standby_list");
		return (1);
	}

	for (i = 0, ret = 0; i < db_standby_size; i++) {
		if ((database = db_standby_list[i])) {
			/*
			 * In order to avoid a potential dead-lock, we
			 * check to see if close_log() would be able to
			 * lock the db; if not, just skip the db.
			 */
			int	lockok;

			TRYWRITELOCK(database, lockok,
				"try w db_dictionary::close_standby_list");

			if (lockok == 0) {
				database->close_log(1);
				db_standby_list[i] = (db*)NULL;
				--db_standby_count;
				WRITEUNLOCK(database, db_standby_count == 0,
					"db_dictionary::close_standby_list");
				if (db_standby_count == 0) {
					ret = 1;
					break;
				}
			} else if (lockok != EBUSY) {
				logmsg(MSG_NOTIMECHECK, LOG_INFO,
					"%s: try-lock error %d",
					myself, lockok);
			} /* else it's EBUSY; skip to the next one */
		}
	}

	MUTEXUNLOCK(db_standby_list, "close_standby_list");

	return (ret);
}

/*
 * Add given database to list of databases that have been opened for updates.
 * If size of list exceeds maximum, close opened databases first.
 */

int
add_to_standby_list(db* database)
{
	int		i;
	const char	*myself = "add_to_standby_list";

	MUTEXLOCK(db_standby_list, "add_to_standby_list");

	if (database == 0) {
		MUTEXUNLOCK(db_standby_list, "add_to_standby_list");
		return (1);
	}

	/* Try to keep the list below OPENED_DBS_CHUNK */
	if (db_standby_count >= OPENED_DBS_CHUNK) {
		MUTEXUNLOCK(db_standby_list, "add_to_standby_list");
		close_standby_list();
		MUTEXLOCK(db_standby_list, "add_to_standby_list");
	}

	if (db_standby_count >= db_standby_size) {
		db	**ndsl = (db **)realloc(db_standby_list,
					(db_standby_size+OPENED_DBS_CHUNK) *
						sizeof (ndsl[0]));

		if (ndsl == 0) {
			MUTEXUNLOCK(db_standby_list, "add_to_standby_list");
			logmsg(MSG_NOMEM, LOG_ERR,
				"%s: realloc(%d) => NULL",
				myself, (db_standby_size+OPENED_DBS_CHUNK) *
				sizeof (ndsl[0]));
			return (0);
		}

		db_standby_list = ndsl;

		for (i = db_standby_size; i < db_standby_size+OPENED_DBS_CHUNK;
				i++)
			db_standby_list[i] = 0;

		db_standby_size += OPENED_DBS_CHUNK;
	}

	for (i = 0; i < db_standby_size; i++) {
		if (db_standby_list[i] == (db*)NULL) {
			db_standby_list[i] = database;
			++db_standby_count;
			MUTEXUNLOCK(db_standby_list, "add_to_standby_list");
			return (1);
		}
	}

	MUTEXUNLOCK(db_standby_list, "add_to_standby_list");

	return (0);
}

int
remove_from_standby_list(db* database)
{
	int i;

	MUTEXLOCK(db_standby_list, "remove_from_standby_list");

	if (database == 0) {
		MUTEXUNLOCK(db_standby_list, "remove_from_standby_list");
		return (1);
	}

	for (i = 0; i < db_standby_size; i++) {
		if ((database == db_standby_list[i])) {
			db_standby_list[i] = (db*)NULL;
			--db_standby_count;
			MUTEXUNLOCK(db_standby_list,
					"remove_from_standby_list");
			return (1);
		}
	}

	MUTEXUNLOCK(db_standby_list, "remove_from_standby_list");

	return (0);
}

/* Release space for copied dictionary */
static void
db_release_dictionary(db_dict_desc_p d) {

	int	i;

	if (d != NULL) {
		for (i = 0; i < d->tables.tables_len; i++) {
			db_table_desc_p	n, t = d->tables.tables_val[i];
			while (t != NULL) {
				n = t->next;
				delete_table_desc(t);
				t = n;
			}
		}
		delete d;
	}

	return;
}

/*
 * Make a copy of the dictionary
 */
db_dict_desc_p
db_dictionary::db_copy_dictionary(void) {

	db_dict_desc_p	tmp;
	int		i, ok = 1, count = 0;

	WRITELOCK(this, NULL, "db_dictionary::db_copy_dictionary w");

	if (dictionary == NULL) {
		WRITEUNLOCK(this, NULL,
			"db_dictionary::db_copy_dictionary wu");
		return (NULL);
	}

	tmp = new db_dict_desc;
	if (tmp == NULL) {
		WRITEUNLOCK(this, NULL,
			"db_dictionary::db_copy_dictionary wu: no memory");
		return (NULL);
	}

	tmp->tables.tables_val = (db_table_desc_p *)calloc(
						tmp->tables.tables_len,
					sizeof (tmp->tables.tables_val[0]));
	if (tmp->tables.tables_val == NULL) {
		delete tmp;
		WRITEUNLOCK(this, NULL,
			"db_dictionary::db_copy_dictionary wu: no memory");
		return (NULL);
	}

	tmp->impl_vers = dictionary->impl_vers;
	tmp->tables.tables_len = 0;
	tmp->count = 0;

	/* For each table ... */
	for (i = 0; ok && i < dictionary->tables.tables_len; i++) {
		db_table_desc_p	tbl = NULL,
				t = dictionary->tables.tables_val[i];
		/* ... and each bucket in the chain ... */
		while (ok && t != NULL) {
			db_table_desc_p		n, savenext = t->next;
			t->next = NULL;
			if (db_clone_bucket(t, &n)) {
				if (tbl != NULL) {
					tbl->next = n;
				} else {
					tmp->tables.tables_val[i] = n;
				}
				tbl = n;
				tmp->count++;
			} else {
				ok = 0;
			}
			t->next = savenext;
		}
		tmp->tables.tables_len++;
	}

	if (ok) {
#ifdef	NISDB_LDAP_DEBUG
		if ((tmp->tables.tables_len !=
				dictionary->tables.tables_len) ||
			(tmp->count != dictionary->count))
			abort();
#endif	/* NISDB_LDAP_DEBUG */
	} else {
		db_release_dictionary(tmp);
		tmp = NULL;
	}

	return (tmp);
}

/*
 * Set deferred commit mode. To do this, we make a copy of the table
 * (structures and data), and put that on the deferred dictionary list.
 * This list is used for lookups during a resync, so clients continue
 * to see the pre-resync data. Meanwhile, any changes (including table
 * deletes) are done to the (temporarily hidden to clients) table in
 * the normal dictionary.
 */
db_status
db_dictionary::defer(char *table) {
	db_status	ret = DB_SUCCESS;
	WRITELOCK(this, DB_LOCK_ERROR, "w db_dictionary::defer");
	db_table_desc	*tbl = find_table_desc(table);
	int		res;
	const char	*myself = "db_dictionary::defer";

	if (tbl != NULL) {
		db_table_desc	*clone, *savenext = tbl->next;
		/*
		 * Only want to clone one db_table_desc, so temporarily
		 * unlink the tail.
		 */
		tbl->next = NULL;
		res = db_clone_bucket(tbl, &clone);
		/* Restore link to tail */
		tbl->next = savenext;
		if (res == 1) {
			db_status	stat;
			if (deferred.dictionary == NULL) {
				deferred.dictionary = new db_dict_desc;
				if (deferred.dictionary == NULL) {
					WRITEUNLOCK(this, DB_MEMORY_LIMIT,
						"wu db_dictionary::defer");
					return (DB_MEMORY_LIMIT);
				}
				deferred.dictionary->tables.tables_len = 0;
				deferred.dictionary->tables.tables_val = NULL;
				deferred.dictionary->count = 0;
				deferred.dictionary->impl_vers =
							DB_CURRENT_VERSION;
			}
			ret = DB_SUCCESS;
			/* Initialize and load the database for the clone */
			if (clone->database == 0) {
				clone->database = new db(table);
				if (clone->database != 0) {
					if (clone->database->load()) {
						logmsg(MSG_NOTIMECHECK,
#ifdef	NISDB_LDAP_DEBUG
							LOG_WARNING,
#else
							LOG_INFO,
#endif	/* NISDB_LDAP_DEBUG */
					"%s: Clone DB for \"%s\" loaded",
							myself, NIL(table));
					} else {
						logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"%s: Error loading clone DB for \"%s\"",
							myself, NIL(table));
						delete clone->database;
						clone->database = 0;
						ret = DB_INTERNAL_ERROR;
					}
				} else {
					logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"%s: Unable to clone DB for \"%s\"",
						myself, NIL(table));
					ret = DB_MEMORY_LIMIT;
				}
			}
			if (clone->database != 0) {
				clone->database->markDeferred();
				stat = add_to_dictionary(deferred.dictionary,
							clone);
				ret = stat;
				if (stat != DB_SUCCESS) {
					delete clone->database;
					clone->database = 0;
					delete clone;
					if (stat == DB_NOTUNIQUE) {
						/* Already deferred */
						ret = DB_SUCCESS;
					}
				}
			} else {
				delete clone;
				/* Return value already set above */
			}
		} else {
			ret = DB_INTERNAL_ERROR;
		}
	} else {
		ret = DB_NOTFOUND;
	}
	WRITEUNLOCK(this, ret, "wu db_dictionary::defer");
	return (ret);
}

/*
 * Unset deferred commit mode and roll back changes; doesn't recover the
 * disk data, but that's OK, since we only want to be able to continue
 * serving the table until we can try a full dump again.
 *
 * The rollback is done by removing (and deleting) the updated table from
 * the dictionary, and then moving the saved table from the deferred
 * dictionary list to the actual one.
 */
db_status
db_dictionary::rollback(char *table) {
	db_status	ret = DB_SUCCESS;
	WRITELOCK(this, DB_LOCK_ERROR, "w db_dictionary::rollback");
	db_table_desc	*old = search_dictionary(deferred.dictionary, table);
	db_table_desc	*upd = search_dictionary(dictionary, table);

	if (old == NULL) {
		WRITEUNLOCK(this, DB_NOTFOUND, "wu db_dictionary::rollback");
		return (DB_NOTFOUND);
	}

	/*
	 * Remove old incarnation from deferred dictionary. We already hold
	 * a pointer ('old') to it, so don't delete.
	 */
	ret = remove_from_dictionary(deferred.dictionary, table, FALSE);
	if (ret != DB_SUCCESS) {
#ifdef	NISDB_LDAP_DEBUG
		abort();
#endif	/* NISDB_LDAP_DEBUG */
		WRITEUNLOCK(this, ret, "wu db_dictionary::rollback");
		return (ret);
	}

	if (old->database != 0)
		old->database->unmarkDeferred();

	/*
	 * Remove updated incarnation from dictionary. If 'upd' is NULL,
	 * the table has been removed while we were in deferred mode, and
	 * that's OK; we just need to retain the old incarnation.
	 */
	if (upd != NULL) {
		ret = remove_from_dictionary(dictionary, table, FALSE);
		if (ret != DB_SUCCESS) {
#ifdef	NISDB_LDAP_DEBUG
			abort();
#endif	/* NISDB_LDAP_DEBUG */
			/*
			 * Cut our losses; delete old incarnation, and leave
			 * updated one in place.
			 */
			delete_table_desc(old);
			WRITEUNLOCK(this, ret, "wu db_dictionary::rollback");
			return (ret);
		}
		/* Throw away updates */
		delete_table_desc(upd);
	}

	/* (Re-)insert old incarnation in the dictionary */
	ret = add_to_dictionary(dictionary, old);
	if (ret != DB_SUCCESS) {
#ifdef	NISDB_LDAP_DEBUG
		abort();
#endif	/* NISDB_LDAP_DEBUG */
		/* At least avoid memory leak */
		delete_table_desc(old);
		syslog(LOG_ERR,
	"db_dictionary::rollback: rollback error %d for \"%s\"", ret, table);
	}
		
	WRITEUNLOCK(this, ret, "wu db_dictionary::rollback");
	return (ret);
}

/*
 * Commit changes. Done by simply removing and deleting the pre-resync
 * data from the deferred dictionary.
 */
db_status
db_dictionary::commit(char *table) {
	db_status	ret = DB_SUCCESS;
	WRITELOCK(this, DB_LOCK_ERROR, "w db_dictionary::commit");
	db_table_desc	*old = search_dictionary(deferred.dictionary, table);

	if (old == NULL) {
		/* Fine (we hope); nothing to do */
		WRITEUNLOCK(this, ret, "wu db_dictionary::commit");
		return (DB_SUCCESS);
	}

	ret = remove_from_dictionary(deferred.dictionary, table, FALSE);
	if (ret == DB_SUCCESS)
		delete_table_desc(old);
#ifdef	NISDB_LDAP_DEBUG
	else
		abort();
#endif	/* NISDB_LDAP_DEBUG */

	WRITEUNLOCK(this, ret, "wu db_dictionary::commit");
	return (ret);
}

/*
 * The noWriteThrough flag is used to prevent modifies/updates to LDAP
 * while we're incorporating log data into the in-memory tables.
 */
void
db_dictionary::setNoWriteThrough(void) {
	ASSERTWHELD(this->dict);
	noWriteThrough.flag++;
}

void
db_dictionary::clearNoWriteThrough(void) {
	ASSERTWHELD(this->dict);
	if (noWriteThrough.flag > 0)
		noWriteThrough.flag--;
#ifdef	NISDB_LDAP_DEBUG
	else
		abort();
#endif	/* NISDB_LDAP_DEBUG */
}
