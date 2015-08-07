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
 *	db_mindex_c.x
 *
 * Copyright 2015 Gary Mills
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#if RPC_XDR
%#include "ldap_xdr.h"
%#include "nis_clnt.h"
#endif /* RPC_XDR */

#if RPC_HDR
%#ifndef _DB_MINDEX_H
%#define _DB_MINDEX_H

#ifdef USINGC
%#include "db_vers_c.h"
%#include "db_table_c.h"
%#include "db_index_entry_c.h"
%#include "db_index_c.h"
%#include "db_scheme_c.h"
%#include "db_query_c.h"
#else
%#include "db_vers.h"
%#include "db_table.h"
%#include "db_index_entry.h"
%#include "db_index.h"
%#include "db_scheme.h"
%#include "db_query.h"
#endif /* USINGC */
%#include "ldap_parse.h"
%#include "nisdb_rw.h"
%#include "ldap_xdr.h"
#endif /* RPC_HDR */

#if RPC_HDR
%struct db_next_index_desc {
%  entryp location;
%  struct db_next_index_desc *next;

#ifndef USINGC  
%  db_next_index_desc( entryp loc, struct db_next_index_desc *n )
%    { location = loc; next = n; }
#endif /* USINGC */

%};
#endif /* RPC_HDR */


#if RPC_HDR || RPC_XDR
#ifdef USINGC

struct db_mindex {
  vers rversion;
  db_index indices<>;                /* indices[num_indices] */
  db_table *table;
  db_scheme *scheme;
  __nisdb_ptr_t objPath;
  __nisdb_flag_t noWriteThrough;
  __nisdb_flag_t noLDAPquery;
  __nisdb_flag_t initialLoad;
  __nisdb_ptr_t dbptr;
  __nisdb_rwlock_t mindex_rwlock;
};
typedef struct db_mindex  * db_mindex_p;

typedef	string	strP<>;

struct xdr_nis_object_s {
	int		xversion;
	nis_object	*obj;
	strP		dirEntry<>;
};
typedef struct xdr_nis_object_s	xdr_nis_object_t;

#endif /* USINGC */
#endif /* RPC_HDR */

#ifndef USINGC
#ifdef RPC_HDR
%
%struct xdr_nis_object_s {
%	int				version;
%	nis_object			*obj;
%	struct {
%		uint_t	dirEntry_len;
%		char	**dirEntry_val;
%	}				dirEntry;
%};
%typedef struct xdr_nis_object_s	xdr_nis_object_t;
%
%class db_mindex {
%  vers rversion;
%//  int num_indices;
%//  db_index * indices;                /* indices[num_indices] */
%  struct {
%   int indices_len;
%   db_index *indices_val;
%  } indices;
%  db_table *table;
%  db_scheme *scheme;
%  __nisdb_ptr_t objPath;
%  __nisdb_flag_t noWriteThrough;
%  __nisdb_flag_t noLDAPquery;
%  __nisdb_flag_t initialLoad;
%  __nisdb_ptr_t dbptr;
%  STRUCTRWLOCK(mindex);
%
%/* Return a list of index_entries that satsify the given query 'q'.
%   Return the size of the list in 'count'. Return NULL if list is empty.
%   Return in 'valid' FALSE if query is not well formed. */
%  db_index_entry_p satisfy_query(db_query *, long *, bool_t *valid,
%					bool_t fromLDAP = FALSE);
%  db_index_entry_p satisfy_query(db_query *, long *, bool_t *valid = NULL);
%
%/* Returns a newly db_query containing the index values as
%   obtained from the given object.  The object itself, 
%   along with information on the scheme given, will determine 
%   which values are extracted from the object and placed into the query.
%   Returns an empty query if 'obj' is not a valid entry.
%   Note that space is allocated for the query and the index values 
%   (i.e. do not share pointers with strings in 'obj'.) */
%  db_query * extract_index_values_from_object( entry_object * ); 
%
%/* Returns a newly created db_query structure containing the index values
%   as obtained from the record named by 'recnum'.  The record itself, along
%   with information on the schema definition of this table, will determine
%   which values are extracted from the record and placed into the result.
%   Returns NULL if recnum is not a valid entry.
%   Note that space is allocated for the query and the index values 
%   (i.e. do not share pointers with strings in 'obj'.) */
%  db_query * extract_index_values_from_record( entryp );
%
%/* Returns an array of size 'count' of 'entry_object_p's, pointing to
%   copies of entry_objects named by the result list of db_index_entries 'res'.
%*/
%  entry_object_p * prepare_results( int, db_index_entry_p, db_status* );
%
%/* Remove the entry identified by 'recloc' from:
%   1.  all indices, as obtained by extracting the index values from the entry
%   2.  table where entry is stored. */
%  db_status remove_aux( entryp );
%
%/*  entry_object * get_record( entryp );*/
% public:
%
%/* Constructor:  Create empty table (no scheme, no table or indices). */
%  db_mindex();
%
%/* Constructor:  Create new table using scheme defintion supplied.
%   (Make copy of scheme and keep it with table.) */
%  db_mindex(db_scheme *, char *tablePath);
%
%/* destructor */
%  ~db_mindex();
%
%  db_index_entry_p satisfy_query_dbonly(db_query *, long *,
%					bool_t checkExpire,
%					bool_t *valid = NULL);
%
%/* Returns whether there table is valid (i.e. has scheme). */
%  bool_t good() { return scheme != NULL && table != NULL; }
%
%/* Change the version of the table to the one given. */
%  void change_version( vers *v ) {  rversion.assign( v );}
%
%/* Return the current version of the table. */
%  vers *get_version()  { return( &rversion ); }
%
%/* Reset contents of tables by: deleting indice entries, table entries */
%  void reset_tables();
%
%/* Reset the table by: deleting all the indices, table of entries, and its
%   scheme. Reset version to 0 */
%  void reset();
%
%/* Initialize table using information from specified file.
%   The table is first 'reset', then the attempt to load from the file
%   is made.  If the load failed, the table is again reset.
%   Therefore, the table will be modified regardless of the success of the 
%   load.  Returns TRUE if successful, FALSE otherwise. */
%  int load( char * );
%
%/* Initialize table using information given in scheme 'how'.
%   Record the scheme for later use (make copy of it);
%   create the required number of indices; and create table for storing 
%   entries.
%   The 'tablePath' is passed on to db_table in order to obtain the
%   NIS+/LDAP mapping information (if any). */
%  void init( db_scheme *);
%
%/* Write this structure (table, indices, scheme) into the specified file. */
%  int dump( char *);
%
%/* Removes the entry in the table named by given query 'q'.
%   If a NULL query is supplied, all entries in table are removed.
%   Returns DB_NOTFOUND if no entry is found.
%   Returns DB_SUCCESS if one entry is found; this entry is removed from
%   its record storage, and it is also removed from all the indices of the
%   table. If more than one entry satisfying 'q' is found, all are removed. */
%  db_status remove( db_query *);
%
%/* Add copy of given entry to table.  Entry is identified by query 'q'.
%   The entry (if any) satisfying the query is first deleted, then
%   added to the indices (using index values extracted form the given entry)
%   and the table.
%   Returns DB_NOTUNIQUE if more than one entry satisfies the query.
%   Returns DB_NOTFOUND if query is not well-formed.
%   Returns DB_SUCCESS if entry can be added.  */
%  db_status add( db_query *, entry_object* );
%
%
%/* Finds entry that satisfy the query 'q'.  Returns the answer by
%   setting the pointer 'rp' to point to the list of answers.
%   Note that the answers are pointers to copies of the entries.
%   Returns the number of answers find in 'count'.  
%   Returns DB_SUCCESS if search found at least one answer; 
%   returns DB_NOTFOUND if none is found. */
%  db_status lookup( db_query *, long *, entry_object_p ** );
%
%/* Returns the next entry in the table after 'previous' by setting 'answer' to
%   point to a copy of the entry_object.  Returns DB_SUCCESS if 'previous' 
%   is valid and next entry is found; DB_NOTFOUND otherwise.  Sets 'where' 
%   to location of where entry is found for input as subsequent 'next' 
%   operation. */
%  db_status next( entryp, entryp *, entry_object ** );
%
%/* Returns the next entry in the table after 'previous' by setting 'answer' to
%   point to a copy of the entry_object.  Returns DB_SUCCESS if 'previous' 
%   is valid and next entry is found; DB_NOTFOUND otherwise.  Sets 'where' 
%   to location of where entry is found for input as subsequent 'next' 
%   operation. */
%  db_status next( db_next_index_desc*, db_next_index_desc **, entry_object ** );
%
%/* Returns the first entry found in the table by setting 'answer' to
%   a copy of the entry_object.  Returns DB_SUCCESS if found; 
%   DB_NOTFOUND otherwise.  */
%  db_status first( entryp*, entry_object ** );
%
%/* Returns the first entry that satisfies query by setting 'answer' to
%   a copy of the entry_object.  Returns DB_SUCCESS if found; 
%   DB_NOTFOUND otherwise.  */
%  db_status first( db_query *, db_next_index_desc **, entry_object ** );
%
% /* Delete the given list of results; used when no longer interested in 
%    the results of the first/next query that returned this list.     */
%  db_status reset_next( db_next_index_desc *orig );
%
%/* Return all entries within table.  Returns the answer by
%   setting the pointer 'rp' to point to the list of answers.
%   Note that the answers are pointers to copies of the entries.
%   Returns the number of answers find in 'count'.  
%   Returns DB_SUCCESS if search found at least one answer; 
%   returns DB_NOTFOUND if none is found. */
%  db_status all( long *, entry_object_p ** );
%
%  /* for debugging */
%/* Prints statistics of the table.  This includes the size of the table,
%   the number of entries, and the index sizes. */
%  void print_stats();
%
%/* Prints statistics about all indices of table. */
%  void print_all_indices();
%
%
%/* Prints statistics about indices identified by 'n'. */
%  void print_index( int n );
%
%/* Configure LDAP mapping */
%  bool_t configure (char *objName);
%
%/* Mark this instance deferred */
%  void markDeferred(void) {
%	if (table != NULL) table->markDeferred();
%  }
%/* Remove deferred mark */
%  void unmarkDeferred(void) {
%	if (table != NULL) table->unmarkDeferred();
%  }
%
%/* Retrieve, remove, or store data from/in/to LDAP */
%  int queryLDAP(db_query *, char *, int);
%  int entriesFromLDAP(__nis_table_mapping_t *, db_query *, db_query *,
%			char *, nis_object *, int);
%
%  int removeLDAP(db_query *, nis_object *o);
%
%  int storeObjLDAP(__nis_table_mapping_t *t, nis_object *o);
%  int storeLDAP(db_query *, entry_obj *, nis_object *, entry_obj *,
%		char *dbId);
%
%/* Set/clear no-write-through flag */
%  void setNoWriteThrough(void);
%  void clearNoWriteThrough(void);
%
%/* Set/clear no-LDAP-query flag */
%  void setNoLDAPquery(void);
%  void clearNoLDAPquery(void);
%
%/* Set/clear initialLoad flag */
%  void setInitialLoad(void);
%  void clearInitialLoad(void);
%
%/* Store/retrieve pointer to parent 'db' class instance */
%  void setDbPtr(void *ptr);
%  void *getDbPtr(void);
%
%/* Get pointer to private 'table' field */
%  db_table *getTable(void);
%
%/*
% * Update table entry per the (entry_object *). If 'replace' is set,
% * the entry is replaced or added; otherwise, it is removed.
% */
%  int updateTableEntry(entry_object *e, int replace, char *tableName,
%			nis_object *obj, nis_object *tobj, uint32_t ttime,
%			int *xid);
%
%/* Touch the indicated entry */
%  bool_t touchEntry(entry_object *e);
%  bool_t touchEntry(db_query *q);
%
%/* Return the 'scheme' pointer */
%  db_scheme *getScheme(void) {return (scheme);}
%
%/* RW lock functions */
%
%  int tryacqexcl(void) {
%	return (TRYWLOCK(mindex));
%  }
%
%  int acqexcl(void) {
%	return (WLOCK(mindex));
%  }
%
%  int relexcl(void) {
%	return (WULOCK(mindex));
%  }
%
%  int acqnonexcl(void) {
%	return (RLOCK(mindex));
%  }
%
%  int relnonexcl(void) {
%	return (RULOCK(mindex));
%  }
%};
%#ifdef __cplusplus
%extern "C" bool_t xdr_db_mindex(XDR*, db_mindex*);
%#elif __STDC__
%extern bool_t xdr_db_mindex(XDR*, db_mindex*);
%#endif
%typedef class db_mindex * db_mindex_p;
#endif /* RPC_HDR */
#endif /* USINGC */

#if RPC_HDR
%#endif /* _DB_MINDEX_H */
#endif /* RPC_HDR */
