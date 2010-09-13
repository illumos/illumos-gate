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
 *	db_log_entry_c.x
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

%#pragma ident	"%Z%%M%	%I%	%E% SMI"

#if RPC_HDR
%#ifndef _DB_LOG_ENTRY_H
%#define _DB_LOG_ENTRY_H

%
%/* A log entry that describes an action to be performed and its parameters. */
%
#endif /* RPC_HDR */

#if RPC_HDR || RPC_XDR
#ifdef USINGC
%#include "db_vers_c.h"
%#include "db_query_c.h"
%#include "db_entry_c.h"
#else
%#include "db_vers.h"
%#include "db_query.h"
%#include "db_entry.h"
#endif /* USINGC */
#endif /* RPC_HDR */

#if RPC_HDR || RPC_XDR
#ifdef USINGC
struct db_log_entry {
  vers aversion;                    /* version of log entry */
  db_action action;                 /* action to be invoked */
  db_query *query;                  /* query supplied with action (if any) */
  entry_object *object;             /* object involved in action (if any) */
  struct db_log_entry *next;        /* Used in constructing list */
  vers bversion;                    /* sanity check */
};
typedef  struct db_log_entry* db_log_entry_p;
#endif /* USINGC */
#endif /* RPC_HDR */

#ifndef USINGC
#ifdef RPC_HDR
%class db_log_entry {
%  vers aversion;                     /* version of log entry */
%  db_action action;                  /* action to be invoked */
%  db_query *query;                   /* query supplied with action (if any) */
%  entry_object *object;              /* object involved in action (if any) */
%  db_log_entry *next;                /* Used in constructing list */
%  vers bversion;                     /* sanity check */
% public:
%
%/*Constructor:  Create an empty log entry, with no query and not object */
%  db_log_entry() { query = NULL, object = NULL; next = NULL; }
%
%/*Constructor:  Create a log entry using the given parameters.  Note that
%  pointers to db_query and entry_object are simply assigned, not copied. */
%  db_log_entry( db_action, vers *, db_query *, entry_object*);
%
%  ~db_log_entry();
%
%/* Print to stdout this log entry */
%  void print();
%
%/* Accessor: return version of log entry */
%  vers *get_version()  { return( &aversion ); }
%
%/* Accessor: return pointer to action of log entry */
%  db_action get_action()  { return( action ); }
%
%/* Accessor:  return pointer to query part of log entry */
%  db_query *get_query()  { return( query ); }
%
%/* Predicate:  return whether log entry is complete and not truncated */
%  bool_t sane() { return( aversion.equal( &bversion ) ); }
%
%/* Accessor:  return pointer to copy of object in log entry */
%  entry_object *get_object()  { return( object ); }
%
%/* Accessor:  return pointer to copy of object in log entry */
%  db_log_entry * getnextptr()  { return( next ); }
%
%/* Accessor:  return pointer to copy of object in log entry */
%  void setnextptr( db_log_entry *p )  { next = p; }
%};
%#ifdef __cplusplus
%extern "C" bool_t xdr_db_log_entry(XDR*, db_log_entry*);
%#elif __STDC__
%extern bool_t xdr_db_log_entry(XDR*, db_log_entry*);
%#endif
%typedef class db_log_entry * db_log_entry_p;
#endif /* RPC_HDR */
#endif /* USINGC */

struct db_log_list {
  db_log_entry_p list<>;
};
  
#if RPC_HDR
%#endif /* _DB_LOG_ENTRY_H */
#endif /* RPC_HDR */
