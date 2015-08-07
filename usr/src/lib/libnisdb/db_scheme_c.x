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
 *	db_scheme_c.x
 *
 * Copyright 2015 Gary Mills
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#if RPC_XDR
%#include "ldap_xdr.h"
#endif /* RPC_XDR */

#if RPC_HDR
%#ifndef _DB_SCHEMA_H
%#define _DB_SCHEMA_H

#ifdef USINGC
%#include "db_item_c.h"
%#include "db_entry_c.h"
#else
%#include "db_item.h"
%#include "db_entry.h"
#endif /* USINGC */

const DB_KEY_CASE = TA_CASE;

#endif /* RPC_HDR */
%
%#include "nisdb_rw.h"
%
%/* Positional information of where field starts within record 
%   and its maximum length in terms of bytes. */
struct db_posn_info {
  short int start_column;
  short int max_len;
};

%/* Description of a key */
struct db_key_desc {
  item *key_name;
  unsigned long key_flags;  /* corresponds to tc_flags in table_col defn */
  int column_number;        /* column within data structure */
  db_posn_info where;       /* where within record entry is 'key' located */
  short int store_type;     /* ISAM or SS ?  maybe useless */
};

%/* Description of the data field. */
struct db_data_desc {
  db_posn_info where;       /* where within record entry is 'data' located */
  short int store_type;     /* ISAM or SS ? maybe useless */
};

%/* A scheme is a description of the fields of a table. */

#if RPC_HDR || RPC_XDR
#ifdef USINGC

struct db_scheme {
  db_key_desc keys<>;
  short int max_columns;  /* applies to data only ? */
  db_data_desc data;
  __nisdb_rwlock_t scheme_rwlock;
};

typedef struct db_scheme  * db_scheme_p;
#endif /* USINGC */
#endif /* RPC_HDR */

#ifndef USINGC
#ifdef RPC_HDR
%
%class db_scheme {
% protected:
%  struct {
%	int keys_len;
%	db_key_desc *keys_val;
%  } keys;
%  short int max_columns;  /* applies to data only ? */
%  db_data_desc data;
%  STRUCTRWLOCK(scheme);
%
% public:
%/* Accessor: return number of keys in scheme. */
%  int numkeys() { return keys.keys_len; }
%
%/* Accessor:  return location of array of key_desc's. */
%  db_key_desc* keyloc () { return keys.keys_val; }
%  
%/* Constructor:  create empty scheme */
%  db_scheme() {
%	keys.keys_len = 0;
%	keys.keys_val = NULL;
%	(void) __nisdb_rwinit(&scheme_rwlock);
%  }
%
%/* Constructor:  create new scheme by making copy of 'orig'.
%   All items within old scheme are also copied (i.e. no shared pointers). */
%  db_scheme( db_scheme* orig );
%
%/* Constructor:  create new sheme by using information in 'zdesc'. */
%  db_scheme( table_obj * );
%
%/* Destructor:  delete all keys associated with scheme and scheme itself. */
%  ~db_scheme();
%
%/* Free space occupied by columns. */
%  void clear_columns( int );
%
%/* Predicate:  return whether given string is one of the index names
%   of this scheme.  If so, return in 'result' the index's number. */
%  bool_t find_index( char*, int* );
%
%/* Print out description of table. */
%  void print();
%
%/* Size of the non-MT/LDAP portion of the db_scheme structure */
%  ulong_t oldstructsize(void) {
%	return ((ulong_t)&(this->scheme_rwlock) - (ulong_t)this);
%  }
%
%/* Locking methods */
%
%  int acqexcl(void) {
%	return (WLOCK(scheme));
%  }
%
%  int relexcl(void) {
%	return (WULOCK(scheme));
%  }
%
%  int acqnonexcl(void) {
%	return (RLOCK(scheme));
%  }
%
%  int relnonexcl(void) {
%	return (RULOCK(scheme));
%  }
%};

%typedef class db_scheme * db_scheme_p;
#endif /* RPC_HDR */
#endif /* USINGC */

#if RPC_HDR
%#endif /* _DB_SCHEMA_H */

#endif /* RPC_HDR */
