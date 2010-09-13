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
 *	db_c.x
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

%#pragma ident	"%Z%%M%	%I%	%E% SMI"

#if RPC_HDR
%#ifndef _DB_DB_H
%#define _DB_DB_H

#ifdef USINGC
%#include "db_mindex_c.h"
%#include "db_vers_c.h"
%#include "db_entry_c.h"
#else
%#include "nisdb_rw.h"
%#include "db_log.h"
%#include "db_mindex.h"
%#include "db_vers.h"
%#include "db_entry.h"
%#include "db_scheme.h"
#endif /* USINGC */
#endif /* RPC_HDR */

#if RPC_HDR || RPC_XDR 
#ifdef USINGC
struct db {
  char* logfilename;
  char* dbfilename;
  char* tmpfilename;
  db_log *logfile;
  db_mindex internal_db;
  bool logfile_opened;
  bool changed;
  __nisdb_rwlock_t db_rwlock;
};
#endif /* USINGC */
#endif /* RPC_HDR */

#ifndef USINGC
#ifdef RPC_HDR 
%class db {
%  char* logfilename;
%  char* dbfilename;
%  char* tmpfilename;
%  db_log *logfile;
%  db_mindex internal_db;
%  bool_t logfile_opened;
%  bool_t changed;
%  STRUCTRWLOCK(db);
%
%/* Delete old log file and descriptor */
%  int reset_log();
%
%/* Open log file (and creates descriptor) if it has not been opened */
%  int open_log(bool_t copylog);
%
%/* Incorporate updates in log to database already loaded.
%   Does not affect "logfile" */
%  int incorporate_log( char * );
%
%/* Execute the specified action using the rest of the arguments as input.
%   Return  a structure db_result containing the result. */
%  db_result * exec_action( db_action, db_query *, entry_object *, 
%			  db_next_desc *previous );
% public:
%/*  Log the given action and execute it.
%    The minor version of the database is updated after the action has
%    been executed and the database is flagged as being changed.
%    Return the structure db_result, or NULL if the loggin failed or the
%    action is unknown. */
%  db_result * log_action( db_action, db_query *, entry_object * );
%
%  /* closes log file if opened */
%  /* removes self from list of dbs have opened files */
%  int close_log(int bypass_standby = 0);
%
%/* Constructor:  Create a database using the given name, 'dbname.'
%   The database is stored in a file named 'dbname'.
%   The log file is stored in a file named 'dbname'.log.
%   A temporary file 'dbname'.tmp is also used.   */
%  db( char * );
%
%/* Destructor:  deletes filenames and logfile descriptor. 
%   Note that associated files should be removed separately.  */
%  ~db();
%
%/* Write out in-memory copy of database to file.
%   1.  Update major version.
%   2.  Dump contents to temporary file.
%   3.  Rename temporary file to real database file.
%   4.  Remove log file. 
%   A checkpoint is done only if it has changed since the previous checkpoint.
%   Returns TRUE if checkpoint was successful; FALSE otherwise. */
%  bool_t checkpoint();
%
%/* Load database and incorporate any logged updates into the loaded copy.
%   Return TRUE if load succeeds; FALSE otherwise. */
%  bool_t load();
%
%/* Dump this database to a file. 
%   Return TRUE if dump succeeds; FALSE otherwise. */
%  bool_t dump(char *outfile) {return (internal_db.dump(outfile));};
%
%/* Initialize the database using table scheme 's'.
%   Because the 'scheme' must be 'remembered' between restarts,
%   after the initialization, the empty database is checkpointed to record
%   the scheme. Returns TRUE if initialization succeeds; FALSE otherwise. */
%  bool_t init( db_scheme *s );
%
%/* Print out the database's statistics. */
%  void print()    { internal_db.print_stats();}
%
%/* Return whether the database has changed since its previous checkpoint. */
%  bool_t changedp() { return changed;}
%
%/* Return the version of the database. */
%  vers* get_version() { return internal_db.get_version(); }
%
%
%/* Execute 'action' using the rest of the arguments as input.
%   Return the result of the operation in a db_result structure;
%   Return NULL if the request is unknown.
%   If the action involves updates (ADD and REMOVE), it is logged first. */
%  db_result* execute( db_action, db_query *, entry_object *, 
%			  db_next_desc* previous );
%
%/* Execute log entry 'j' on this db.  'j' is executed if its version is
%   later than that of the database; if executed, the database's version
%   will be changed to that of 'j', regardless of the status of the operation.
%   Returns TRUE if 'j' was executed;   FALSE if it was not.
%   Log entry is added to this database's log if log_entry is applied. */
%  bool_t execute_log_entry( db_log_entry * );
%
%/* Return structure db_log_list containing entries that are later
%   than the version 'v' given.  */
%  db_log_list * get_log_entries_since( vers * );
%
%/* Sync the table log file */
%  db_status	sync_log();
%
%/* Delete all files associated with database. */
%  int remove_files();
%
%  /* for debugging */
%/* Print information on all indices of the database to stdout. */
%  void print_all_indices() {internal_db.print_all_indices();}
%
%/* Print information on specified index of the the database to stdout. */
%  void print_index( int n ) {internal_db.print_index( n ); }
%
%/* Mark this instance deferred */
%  void markDeferred(void) {
%	internal_db.markDeferred();
%  }
%
%/* Remove defer marking */
%  void unmarkDeferred(void) {
%	internal_db.unmarkDeferred();
%  }
%
%/* Exclusive access to this instance */
%  int acqexcl(void) {
%	return (WLOCK(db));
%  }
%
%/* Non-blocking exclusive access */
%  int tryacqexcl(void) {
%	return (TRYWLOCK(db));
%  }
%
%/* Release exclusive access */
%  int relexcl(void) {
%	return (WULOCK(db));
%  }
%
%/* Non-exclusive (readonly) access to this instance */
%  int acqnonexcl(void) {
%	return (RLOCK(db));
%  }
%
%/* Release non-exlusive access */
%  int relnonexcl(void) {
%	return (RULOCK(db));
%  }
%
%/* Destroy instance lock */
%  int destroylock(void) {
%	return (DESTROYRW(db));
%  }
%
%/* Pass configuration information to the db_mindex */
%  bool_t configure(char *objName);
%
%/* Export a pointer to the db_mindex structure */
%  db_mindex *mindex(void);
%};
%
%typedef class db * dbp;
#endif /* USINGC */
#endif /* RPC_HDR */

#if RPC_HDR
%#endif /* _DB_DB_H */
#endif /* RPC_HDR */
