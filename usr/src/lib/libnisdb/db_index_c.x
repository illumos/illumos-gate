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
 *	db_index_c.x
 *
 *  Copyright 2015 Gary Mills
 *  Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 *  Use is subject to license terms.
 */

#if RPC_XDR
%#include "ldap_xdr.h"
#endif /* RPC_XDR */

#if RPC_HDR
%#ifndef _DB_INDEX_H
%#define _DB_INDEX_H

%
%/* db_index is a hash table with separate overflow buckets. */
%


#ifdef USINGC
%#include "db_item_c.h"
%#include "db_index_entry_c.h"
%#include "db_table_c.h"
%#include "db_scheme_c.h"
#else
%#include "db_item.h"
%#include "db_index_entry.h"
%#include "db_table.h"
%#include "db_scheme.h"
#endif /* USINGC */
#endif /* RPC_HDR */
%
%#include "nisdb_rw.h"
%
#if RPC_HDR || RPC_XDR
#ifdef USINGC
struct db_index {
  db_index_entry_p tab<>;
  int count;
  bool case_insens;
  __nisdb_rwlock_t index_rwlock;
};
typedef struct db_index * db_index_p;
#endif /* USINGC */
#endif /* RPC_HDR */

#ifndef USINGC
#ifdef RPC_HDR
%class db_index  {
%  long table_size;
%  db_index_entry_p *tab;
%  int count;
%  bool_t case_insens;
%  STRUCTRWLOCK(index);
%
%/* Grow the current hashtable upto the next size.
%   The contents of the existing hashtable is copied to the new one and
%   relocated according to its hashvalue relative to the new size.
%   Old table is deleted after the relocation. */
%  void grow();
%
%/* Clear the chains created in db_index_entrys */
%/*  void clear_results();*/
% public:
%
%/* Constructor: creates empty index. */
%  db_index();
%
%/* Constructor: creates index by loading it from the specified file.
%   If loading fails, creates empty index. */
%  db_index( char *);
%
%/* Destructor: deletes index, including all associated db_index_entry. */
%  ~db_index();
%
%/* Empty table (deletes index, including all associated db_index_entry) */
%  void reset();
%
%/* Initialize index according to the specification of the key descriptor.
%   Currently, only affects case_insens flag of index. */
%  void init( db_key_desc * );
%
%/* Moves an index from an xdr index */
%  db_status move_xdr_db_index(db_index *orig);
%
%/* Dumps this index to named file. */
%  int dump( char *);
%
%
%/* Look up given index value in hashtable. 
%  Return pointer to db_index_entries that match the given value, linked
%  via the 'next_result' pointer.  Return in 'how_many_found' the size 
%  of this list. Return NULL if not found. */
%  db_index_entry *lookup(item *, long *, db_table *, bool_t);
%
%/* Remove the entry with the given index value and location 'recnum'.
%   If successful, return DB_SUCCESS; otherwise DB_NOTUNIQUE if index_value
%   is null; DB_NOTFOUND if entry is not found.
%   If successful, decrement count of number of entries in hash table. */
%  db_status remove( item*, entryp );
%
%/* Add a new index entry with the given index value and location 'recnum'.
%   Return DB_NOTUNIQUE, if entry with identical index_value and recnum 
%   already exists.  If entry is added, return DB_SUCCESS.
%   Increment count of number of entries in index table and grow table
%   if table is more than half full.
%   Note that a copy of index_value is made for new entry. */
%  db_status add( item*, entryp );
%
%/* Return in 'tsize' the table_size, and 'tcount' the number of entries
%   in the table. */
%  void stats( long* tsize, long* tcount);
%
%
%/* Print all entries in the table. */
%  void print();
%
%/* Locking methods */
%
%  int acqexcl(void) {
%	return (WLOCK(index));
%  }
%
%  int relexcl(void) {
%	return (WULOCK(index));
%  }
%
%  int acqnonexcl(void) {
%	return (RLOCK(index));
%  }
%
%  int relnonexcl(void) {
%	return (RULOCK(index));
%  }
%};
%#ifdef __cplusplus
%extern "C" bool_t xdr_db_index(XDR *, db_index *);
%#elif __STDC__
%extern bool_t xdr_db_index(XDR *, db_index *);
%#endif
%typedef class db_index * db_index_p;
#endif /* RPC_HDR */
#endif /* USINGC */

#if RPC_HDR
%#endif /* _DB_INDEX_H */
#endif /* RPC_HDR */
