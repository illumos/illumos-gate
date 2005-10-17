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
 *	db_index_entry_c.x
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

%#pragma ident	"%Z%%M%	%I%	%E% SMI"

#if RPC_HDR

%#ifndef _DB_INDEX_ENTRY_H
%#define _DB_INDEX_ENTRY_H

%
% /* db_index_entry is an entry in the hashtable.  db_index_entries can be
%    linked in one of two ways:
%    * via the 'next' pointer and form the hash bucket
%    * via the 'nextresult' pointer and form a chain of results.
%    Each entry contains the key, the hash value of key, and location
%    information  'entryp'
%    entryp is location information.
%    It might be pointer to an in core entry, or an indirect pointer
%    identifying the location of an entry somewhere in memory (e.g.
%    if there was a table where all complete entries are stored) --- this
%    is desirable, for example, for XDR operations on a multi-indexed table;
%    or, if used in conjunction with NetISAM, it may be the record number. */
%/* *** notes */
%/* remember to set next_result to null first if using XDR. */

#ifdef USINGC
%#include "db_item_c.h"
%#include "db_table_c.h"   /* contains definition of entryp */
%typedef void *nullptr;
#else
%#include "db_item.h"
%#include "db_table.h"   /* contains definition of entryp */
#endif /* USIGNC */
#endif /* RPC_HDR */


#if RPC_HDR || RPC_XDR
#ifdef USINGC
struct db_index_entry {
  unsigned long hashval;
  item *key;
  entryp location;  
  db_index_entry* next;
#ifdef USINGC
  nullptr next_result; 
#else
  db_index_entry* next_result; 
#endif
};
typedef struct db_index_entry * db_index_entry_p;
#endif /* USINGC */
#endif /* RPC_HDR */

#ifndef USINGC
#ifdef RPC_HDR
%class db_index_entry {
%  unsigned long hashval;
%  item *key;
%  entryp location;  
%  db_index_entry* next;
%  db_index_entry* next_result; 
% public:
%
%/* Constructor:  create an entry using given string and location info. */
%  db_index_entry( char* name, int nlen, entryp location );
%
%/* Constructor:  create an entry using the given info.  
%   A copy of the key is made.  New entry is added to head of list of 'n'. */
%  db_index_entry( unsigned long hval, item *, entryp, db_index_entry *n);
%
%/* Destructor:  deletes key and itself.  Assumes that deletion of 
%   object at location is done elsewhere (beforehand) */
%  ~db_index_entry() {delete key; } 
%
%/* Relocate bucket starting with this entry to new hashtable 'new_tab'. */
%  void relocate( db_index_entry**, unsigned long );
%
%/* Join two lists (entry as identified by its 'location' occurs on both list,
%   then it is included in the list returned).  
%   Returns pointer to resulting list; size of list
%   returned in 'newsize'.  List is chained using the 'nextresult' pointer. */
%  db_index_entry* join( long size1, long size2, db_index_entry *list2, 
%		       long * newsize );
%
%/* Returns pointer to a list of index entries with the same hash value and
%   key as those given.  Returns in 'how_many' the number of entries in the
%   list returned.  The list is linked by the 'next_result' field of the
%   index entries.  These may be changed after the next call to 'lookup'
%   or 'join'. */
%  db_index_entry* lookup( bool_t, unsigned long, item*, long *);
%
%/* Return pointer to index entry with same hash value, same key,
%   and same record number as those supplied.  Returns NULL if not found. */
%  db_index_entry* lookup( bool_t, unsigned long, item*, entryp ); //name entry
%
%/* Return the next entry in the bucket starting with this entry
%   with the same hashvalue, key and location as this entry. */
%  db_index_entry* getnext( bool_t, unsigned long, item*, entryp );
%
%/* Return the next entry in the bucket. */
%  db_index_entry* getnextentry() {return next;}
%
%/* Return the next entry in the 'next_result' chain. */
%  db_index_entry* getnextresult() {return next_result;}
%
%/* Return the location field of this entry. */
%  entryp getlocation() {return location;}
%
%/* Assign the given pointer as the next result after this entry. */
%  void addresult( db_index_entry * nr ) { next_result = nr; }
%
%/* Return the pointer to the key of this entry. */
%  item * get_key() {return key;}
%
%/* Remove entry with the specified hashvalue, key, and record number.
%   Returns 'TRUE' if successful, FALSE otherwise.
%   If the entry being removed is at the head of the list, then
%   the head is updated to reflect the removal. The storage for the index
%   entry is freed. The record pointed to by 'recnum' must be removed
%   through another means.  All that is updated in this operation is the
%   index. */
%  bool_t remove( db_index_entry **, bool_t, unsigned long, item *, entryp );
%
%/* Replace the 'location' field of the index entry with the given one. */
%  void replace( entryp ep ) {location = ep;}
%
%/* Create and add an entry with the given hashvalue, key value, and record 
%   location, to the bucket pointed to by 'hashvalue'.
%   If an entry with the same identical information is found, no addition
%   is done.  If an entry with the same hashvalue and key value is found,
%   the entry is added after the first entry with this property.  Otherwise,
%   the entry is added to the head of the bucket.  This way, entries
%   with the same hashvalue and key are not scattered throughout the bucket
%   but they occur together. Copy is made of given key. */
%  bool_t add( db_index_entry **oldhead, bool_t, unsigned long hval, item *, 
%	    entryp );
%		      
%/* Print this entry to stdout. */
%  void print();
%
%/* Print bucket starting with this entry. */
%  void print_all();
%
%/* Print result list starting with this entry. */
%  void print_results();
%};
%typedef class db_index_entry * db_index_entry_p;
#endif /* RPC_HDR */
#endif /* USINGC */

#if RPC_HDR
%#endif /* _DB_INDEX_ENTRY_H */
#endif /* RPC_HDR */
