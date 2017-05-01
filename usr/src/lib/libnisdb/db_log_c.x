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
 *	db_log_c.x
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#if RPC_HDR
%#ifndef _DB_LOG_H
%#define _DB_LOG_H

#ifdef USINGC
%#include "db_log_entry_c.h"
#else
%#include "db_pickle.h"
%#include "db_log_entry.h"
#endif /* USINGC */
#endif /* RPC_HDR */
%
%#include "nisdb_rw.h"
%
#ifndef USINGC
#ifdef RPC_HDR
%class db_log: public pickle_file {
% private:
%	int	syncstate;	/* 0 if changes xfrd to <table>.log */
%	char	*tmplog;	/* <table>.log.tmp */
%	char	*stablelog;	/* <table>.log.stable */
%	char	*oldlog;	/* remember name of <table>.log */
%	STRUCTRWLOCK(log);
%
% public:
%
%/* Constructor:  create log file; default is PICKLE_READ mode. */
%  db_log( char* f, pickle_mode m = PICKLE_READ ): pickle_file(f, m) {
%	syncstate = 0;
%	tmplog = stablelog = oldlog = 0;
%	INITRW(log);
%  }
%
%  ~db_log(void) {
%	DESTROYRW(log);
%  }
%
%/* Execute given function 'func' on log.
%  function takes as arguments: pointer to log entry, character pointer to 
%  another argument, and pointer to an integer, which is used as a counter.
%  'func' should increment this value for each successful application.
%  The log is traversed until either 'func' returns FALSE, or when the log
%  is exhausted.  The second argument to 'execute_on_log' is passed as the
%  second argument to 'func'. The third argument, 'clean' determines whether
%  the log entry is deleted after the function has been applied.
%  Returns the number of times that 'func' incremented its third argument. */
%  int execute_on_log( bool_t(* f) (db_log_entry *, char *, int *), 
%		      char *, bool_t = TRUE );
%
%
%/* Print contents of log file to stdout */
%  int print();
%
%/* Make copy of current log to log pointed to by 'f'. */  
%  int copy( db_log*);
%
%/*Rewinds current log */
%  int rewind();
%
%/*Append given log entry to log. */
%  int append( db_log_entry * );
%
%/* Flush and sync log file. */
%  int sync_log();
%
%/* Return the next element in current log; return NULL if end of log or error.
%   Log must have been opened for READ. */
%  db_log_entry *get();
%
%/*  bool_t dump( pptr ) {return TRUE;}*/     // does nothing.
%
%/* Open log file */
%  bool_t open(void);
%/* Close log file */
%  int	close();
%/* Do we need to copy the log file */
%  bool_t copylog;
%
%/* Locking methods */
%
%  int acqexcl(void) {
%	return (WLOCK(log));
%  }
%
%  int relexcl(void) {
%	return (WULOCK(log));
%  }
%
%  int acqnonexcl(void) {
%	return (RLOCK(log));
%  }
%
%  int relnonexcl(void) {
%	return (RULOCK(log));
%  }
%};
#endif /* RPC_HDR */
#endif /* USINGC */

#if RPC_HDR
%#endif /* _DB_LOG_H */
#endif /* RPC_HDR */
