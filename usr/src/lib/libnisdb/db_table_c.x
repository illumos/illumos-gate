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
 *	db_table_c.x
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

%#pragma ident	"%Z%%M%	%I%	%E% SMI"

#if RPC_HDR
%#ifndef _DB_TABLE_H
%#define _DB_TABLE_H

#ifdef USINGC
%#include "db_query_c.h"
%#include "db_scheme_c.h"
#else
%#include "db_query.h"
%#include "db_scheme.h"
#endif /* USINGC */
#endif /* RPC_HDR */
%
%#include "nisdb_ldap.h"
%#include "nisdb_rw.h"
%#include "ldap_parse.h"
%#include "ldap_map.h"
%#include "ldap_util.h"
%#include "ldap_nisdbquery.h"
%#include "ldap_print.h"
%#include "ldap_xdr.h"
%
typedef long entryp;      /* specifies location of an entry within table */

struct db_free_entry {
  entryp where;
  struct db_free_entry *next;
};

typedef struct db_free_entry * db_free_entry_p;

#if RPC_HDR || RPC_XDR
#ifdef USINGC
struct db_free_list {
  db_free_entry_p head;
  long count;
  __nisdb_rwlock_t free_list_rwlock;
};
typedef struct db_free_list * db_free_list_p;
#endif /* USINGC */
#endif /* RPC_HDR */

#ifndef USINGC
#ifdef RPC_HDR
%class db_free_list {
%  db_free_entry_p head;
%  long count;
%  STRUCTRWLOCK(free_list);
% public:
%  db_free_list() {   /* free list constructor */
%	head = NULL;
%	count = 0;
%	INITRW(free_list);
%  }
% 
%  ~db_free_list();
%
%  void reset();   /* empty contents of free list */
%
%  void init();		/* Empty free list */
%
%/* Returns the location of a free entry, or NULL, if there aren't any. */
%  entryp pop();
%
%/* Adds given location to the free list.  
%   Returns TRUE if successful, FALSE otherwise (when out of memory). */
%  bool_t push( entryp );
%
%/* Returns in a vector the information in the free list.
%   Vector returned is of form: <n free cells><n1><n2><loc1>,..<locn>.
%   Leave the first 'n' cells free.
%   n1 is the number of entries that should be in the freelist.
%   n2 is the number of entries actually found in the freelist.
%   <loc1...locn> are the entries.   n2 <= n1 because we never count beyond n1.
%   It is up to the caller to free the returned vector when he is through. */
% long* stats( int n );
%
%/* Locking methods */
%
%  int acqexcl(void) {
%	return (WLOCK(free_list));
%  }
%
%  int relexcl(void) {
%	return (WULOCK(free_list));
%  }
%
%  int acqnonexcl(void) {
%	return (RLOCK(free_list));
%  }
%
%  int relnonexcl(void) {
%	return (RULOCK(free_list));
%  }
%};
#endif /* RPC_HDR */
#endif /* USINGC */

#if RPC_HDR || RPC_XDR
#ifdef USINGC
struct db_table
{
  entry_object_p tab <>;
  long last_used;        /* last entry used; maintained for quick insertion */
  long count;            /* measures fullness of table */
  db_free_list freelist;
  __nisdb_rwlock_t table_rwlock;
  __nisdb_flag_t enumMode;
  __nisdb_ptr_t  enumArray;
  __nis_table_mapping_t mapping;
};
typedef struct db_table * db_table_p;

#endif /* USINGC */
#endif /* RPC_HDR */

#ifndef USINGC
#ifdef RPC_HDR
%class db_table
%{
%  long table_size;
%  entry_object_p *tab;   /* pointer to array of pointers to entry objects */
%  long last_used;        /* last entry used; maintained for quick insertion */
%  long count;            /* measures fullness of table */
%  db_free_list freelist;
%  STRUCTRWLOCK(table);
%  __nisdb_flag_t enumMode;
%  __nisdb_flag_t enumCount;
%  __nisdb_ptr_t  enumIndex;
%  __nisdb_ptr_t  enumArray;
%
%  void grow();           /* Expand the table.  
%			    Fatal error if insufficient error. */
%
%/* Allocate expiration time array */
%  db_status allocateExpire(long oldSize, long newSize);
%
% public:
%  __nisdb_table_mapping_t mapping;
%
%  db_table();            /* constructor for brand new, empty table. */
%  db_table( char * );    /* constructor for creating a table by loading
%			    in an existing one. */
%
%/* Init of LDAP/MT portion of class instance */
%  void db_table_ldap_init(void);
%/* Size of the non-MT/LDAP portion of the db_table structure */
%  ulong_t oldstructsize(void) {
%	return ((ulong_t)&(this->table_rwlock) - (ulong_t)this);
%  }
%/* Mark this instance as deferred */
%  void markDeferred(void) {
%	mapping.isDeferredTable = TRUE;
%  }
%/* Remove deferred mark */
%  void unmarkDeferred(void) {
%	mapping.isDeferredTable = FALSE;
%  }
%
%/* Return the current 'tab' */
%  entry_object_p *gettab() { ASSERTRHELD(table); return (tab); };
%/* Return how many entries there are in table. */
%  long fullness() { return count; }
%
%/* Deletes table, entries, and free list */
%  ~db_table();
%
%  int tryacqexcl(void) {
%	return (TRYWLOCK(table));
%  }
%
%  int acqexcl(void) {
%	return (WLOCK(table));
%  }
%
%  int relexcl(void) {
%	return (WULOCK(table));
%  }
%
%  int acqnonexcl(void) {
%	return (RLOCK(table));
%  }
%
%  int relnonexcl(void) {
%	return (RULOCK(table));
%  }
%
%/* empties table by deleting all entries and other associated data structures */
%   void reset();
%
%  int dump( char *);
%
%/* Returns whether location is valid. */
%  bool_t entry_exists_p( entryp i );
%
%/* Returns table size. */
%  long getsize()  { return table_size; }
%
%/* Returns the first entry in table, also return its position in
%   'where'.  Return NULL in both if no next entry is found. */
%  entry_object_p first_entry( entryp * where );
%
%/* Returns the next entry in table from 'prev', also return its position in
%   'newentry'.  Return NULL in both if no next entry is found. */
%  entry_object_p next_entry( entryp, entryp* );
%
%/* Returns entry at location 'where', NULL if location is invalid. */
%  entry_object_p get_entry( entryp );
%
%/* Adds given entry to table in first available slot (either look in freelist
%   or add to end of table) and return the the position of where the record
%   is placed. 'count' is incremented if entry is added. Table may grow
%   as a side-effect of the addition. Copy is made of the input. */
%  entryp add_entry(entry_object_p, int);
%
% /* Replaces object at specified location by given entry.  
%   Returns TRUE if replacement successful; FALSE otherwise.
%   There must something already at the specified location, otherwise,
%   replacement fails. Copy is not made of the input. 
%   The pre-existing entry is freed.*/
%  bool_t replace_entry( entryp, entry_object_p );
%
%/* Deletes entry at specified location.  Returns TRUE if location is valid;
%   FALSE if location is invalid, or the freed location cannot be added to 
%   the freelist.  'count' is decremented if the deletion occurs.  The object
%   at that location is freed. */
%  bool_t delete_entry( entryp );
%
%/* Returns statistics of table.
%   <table_size><last_used><count>[freelist].
%   It is up to the caller to free the returned vector when his is through
%   The free list is included if 'fl' is TRUE. */
%long * stats( bool_t fl );
%
%/* Configure LDAP mapping */
%  bool_t configure(char *objName);
%
%/* Initialize the mapping structure with default values */
%  void initMappingStruct(__nisdb_table_mapping_t *mapping);
%
%/* Check if entry at 'loc' is valid (not expired) */
%  bool_t cacheValid(entryp loc);
%
%/* Update expiration time if supplied object same as the one at 'loc' */
%  bool_t dupEntry(entry_object *obj, entryp loc);
%
%/* Set expiration time for entry */
%  void setEntryExp(entryp where, entry_object *obj, int initialLoad);
%
%/* Enable enum mode */
%  void setEnumMode(long count);
%/* Clear enum mode */
%  void clearEnumMode(void);
%/* End enum mode, return array of untouched entries */
%  entry_object **endEnumMode(long *numEa);
%/* Mark the indicated entry used for enum purposes */
%  void enumTouch(entryp loc);
%/* Add entry to enumIndex array */
%  void enumSetup(entryp loc, long index);
%/* Touch the indicated entry */
%  void touchEntry(entryp loc);
%
%  db_status allocateEnumArray(long oldSize, long newSize);
%};
%#ifdef __cplusplus
%extern "C" bool_t xdr_db_table( XDR*, db_table*);
%#elif __STDC__
%extern bool_t xdr_db_table(XDR*, db_table*);
%#endif
%typedef class db_table * db_table_p;
#endif /* RPC_HDR */
#endif /* USINGC */

#if RPC_HDR
%#endif /* _DB_TABLE_H */
#endif /* RPC_HDR */
