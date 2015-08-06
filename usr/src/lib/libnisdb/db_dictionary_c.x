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
 *	db_dictionary_c.x
 *
 * Copyright 2015 Gary Mills
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
 
#if RPC_XDR
%#include "xdr_nullptr.h"
#endif /* RPC_XDR */
 
#if RPC_HDR
%#ifndef _DB_DICTIONARY_H
%#define _DB_DICTIONARY_H

#ifdef USINGC
%#include "nisdb_rw.h"
%#include "nisdb_ldap.h"
%#include "db_entry_c.h"
%#include "db_scheme_c.h"
%#include "db_vers_c.h"
%#include "ldap_xdr.h"
%typedef void *nullptr;
%typedef u_int db_dict_version;
#else
%#include "nisdb_rw.h"
%#include "nisdb_ldap.h"
%#include "db_entry.h"
%#include "db_scheme.h"
%#include "db.h"
%#include "db_vers.h"
%#include "db_dictlog.h"
%#include "ldap_xdr.h"
#endif /* USINGC */
#endif /* RPC_HDR */

struct db_table_desc {
  string table_name<NIS_MAXNAMELEN>;
  u_long hashval;
  db_scheme * scheme;
#ifdef USINGC
  nullptr database;   /* for XDR, keep database from descriptor */
#else
  db *database;        /* for program use in c++ code */
#endif /* USINGC */
  db_table_desc *next;
};
typedef struct db_table_desc * db_table_desc_p;

/* Defining own version of xdr_db_dict_version */
#if RPC_HDR
#ifndef USINGC
typedef u_int db_dict_version;
%bool_t xdr_db_dict_version();
#endif /* USINGC */

typedef char * db_table_namep;
typedef db_table_namep db_table_names<>;

/* Defining own version of xdr_db_dict_desc */
#ifndef USINGC
struct db_dict_desc {
	db_dict_version impl_vers;
	db_table_desc_p tables<>;
	int count;
};
#else
%struct db_dict_desc {
%	db_dict_version impl_vers;
%	struct {
%		u_int tables_len;
%		db_table_desc_p *tables_val;
%	} tables;
%	int count;
%};
%typedef struct db_dict_desc db_dict_desc;
%bool_t xdr_db_dict_desc();
#endif /* USINGC */

#endif

typedef struct db_dict_desc * db_dict_desc_p;

#if	RPC_HDR
struct __nisdb_dictionary_defer_struct {
	db_dict_desc		*dictionary;	/* Old incarnation */
};
typedef struct __nisdb_dictionary_defer_struct	__nisdb_dictionary_defer_t;
#ifdef	USINGC
%bool_t xdr___nisdb_dictionary_defer_t();
#endif	/* USINGC */
#endif

#ifndef USINGC
#ifdef RPC_HDR
%class db_dictionary {
%  db_dict_desc_p dictionary;
%  bool_t initialized;
%  char* filename;
%  char* tmpfilename;
%  char* logfilename;
%  db_dictlog *logfile;
%  bool_t logfile_opened;
%  bool_t changed;
%  __nisdb_dictionary_defer_t deferred;
%  __nisdb_flag_t noWriteThrough;
%  STRUCTRWLOCK(dict);
%
%/* Dump contents of this dictionary (minus the database representation)
%     to its file. Returns 0 if operation succeeds, -1 otherwise. */
%  int dump();
%
%/* Delete old log file and descriptor */
%  int reset_log();
%
%/* Open log file (and creates descriptor) if it has not been opened */
%  int open_log();
%
%/* Incorporate updates in log to dictionary already loaded.
%   Does not affect "logfile" */
%  int incorporate_log( char * );
%
%  /* closes log file if opened */
%  int close_log();
%
%/*  Log the given action and execute it.
%    The minor version of the dictionary is updated after the action has
%    been executed and the dictionary is flagged as being changed.
%    Return the structure db_result, or NULL if the loggin failed or the
%    action is unknown. */
%  db_status log_action(int, char* table, table_obj* tobj =0);
%
%  db_status create_table_desc(char* table_name, table_obj* table_desc,
%			       db_table_desc**);
%
%  db_dict_desc_p db_copy_dictionary(void);
%
% public:
%/* Constructor:  creates an empty, uninitialized dictionary. */
%  db_dictionary();
%
%/* Destructor: noop. Use db_shutdown if you really want to clean up. */
%  ~db_dictionary() {}
%
%  db_status merge_dict (db_dictionary&, char *, char *);
%
%  db_status massage_dict (char *, char *, char *);
%  int	     db_clone_bucket (db_table_desc *, db_table_desc_p *);
%  int	     change_table_name (db_table_desc *, char *, char *);
%  bool_t    extract_entries (db_dictionary&, char **, int );
%
%/* Real destructor: deletes filename and table descriptors */
%  db_status db_shutdown();
%
%/*  Initialize dictionary from contents in 'file'.
%    If there is already information in this dictionary, it is removed.
%    Therefore, regardless of whether the load from the file succeeds,
%    the contents of this dictionary will be altered.  Returns
%    whether table has been initialized successfully. */
%  bool_t init( char* fname );
%  bool_t inittemp( char* fname, db_dictionary&);
%
%/* closes any open log files for all tables in dictionary or 'tab'.
%   "tab" is an optional argument.
% */
%   db_status db_standby( char* tab = 0 );
%
%/* Write out in-memory copy of dictionary to file.
%   1.  Update major version.
%   2.  Dump contents to temporary file.
%   3.  Rename temporary file to real dictionary file.
%   4.  Remove log file. 
%   A checkpoint is done only if it has changed since the previous checkpoint.
%   Returns TRUE if checkpoint was successful; FALSE otherwise. */
%  db_status checkpoint();
%
%/*  Checkpoints table specified by 'tab', or all tables if 'tab' is 0. */
%   db_status db_checkpoint( char* tab = 0 );

%/* Add table with given name 'tab' and description 'zdesc' to dictionary.
%   Returns error code if table already exists, or if no memory can be found
%   to store the descriptor, or if dictionary has not been intialized.  
%   Dictionary is updated to stable store before addition.
%   Fatal error occurs if dictionary cannot be saved.
%   Returns DB_SUCCESS if dictionary has been updated successfully. */
%  db_status add_table_aux(char* table_name, table_obj* table_desc, int mode);
%
%/* Delete table with given name 'tab' from dictionary.
%   Returns error code if table does not exist or if dictionary has not been 
%   initialized.   Dictionary is updated to stable store if deletion is 
%   successful.  Fatal error occurs if dictionary cannot be saved.   
%   Returns DB_SUCCESS if dictionary has been updated successfully.
%   Note that the files associated with the table are also removed.  */
%  db_status delete_table_aux( char* table_name, int mode );
%
%  db_status add_table( char* table_name, table_obj* table_desc );
%  int copyfile( char* infile, char *outfile);
%
%  db_status delete_table( char* table_name );
%
%/* Return database structure of table named by 'table_name'.
%   If 'where' is set, set it to the table_desc of 'table_name.'
%   The database is loaded in from stable store if it has not been loaded.
%   If it cannot be loaded, it is initialized using the scheme stored in
%   the table_desc.  NULL is returned if the initialization fails.   */
%  db* find_table( char* table_name, db_table_desc ** where = NULL );
%
%  db *find_table(char *table_name, db_table_desc **where,
%			bool_t searchDeferred);
%  db *find_table(char *table_name, db_table_desc **where,
%			bool_t searchDeferred, bool_t doLDAP,
%			bool_t doLoad);
%
%  db *find_table_noLDAP(char *table_name, db_table_desc **where,
%			bool_t searchDeferred, bool_t doLoad);
%
%/* Returns db_table_desc of table name 'tab'.
%   Use this if you do not want table to be loaded. */
%  db_table_desc * find_table_desc( char* table_name );
%
%  db_table_desc * find_table_desc(char *table_name, bool_t searchDeferred);
%
%/* Translate given nis attribute list to a db_query structure. 
%   Return FALSE if dictionary has not been initialized, or 
%   table does not have a scheme (which should be a fatal error?). */
%  db_query * translate_to_query( db_table_desc*, int, nis_attr * );
%
%/* Return an array of strings of table names of all tables in dictionary. */
%   db_table_names * get_table_names(); 
%
%/* Set/clear no-write-through flag */
%  void setNoWriteThrough(void);
%  void clearNoWriteThrough(void);
%
%/* Locking */
%  int acqexcl(void) {
%	return(WLOCK(dict));
%  }
%
%  int relexcl(void) {
%	return (WULOCK(dict));
%  }
%
%  int acqnonexcl(void) {
%	return (RLOCK(dict));
%  }
%
%  int relnonexcl(void) {
%	return (RULOCK(dict));
%  }
%
%/* Set deferred commit mode; intended for replica resync */
%  db_status defer(char *table);
%
%/* Commit deferred changes; intended for replica resync */
%  db_status commit(char *table);
%
%/* Roll back deferred changes; intended for replica resync */
%  db_status rollback(char *table);
%};
%#ifdef __STDC__
%extern "C" bool_t xdr_db_table_desc_p(XDR *, db_table_desc_p *); 
%extern "C" bool_t xdr_db_table_desc(XDR *, db_table_desc *); 
%extern "C" bool_t xdr_db_dict_desc_p(XDR *, db_dict_desc_p *); 
%extern "C" bool_t xdr_db_table_namep(XDR *, db_table_namep *); 
%extern "C" bool_t xdr_db_table_names(XDR *, db_table_names *); 
%#endif

#endif /* RPC_HDR */
#endif /* USINGC */

#if RPC_HDR
%#endif /* _DB_DICTIONARY_H */
#endif /* RPC_HDR */

