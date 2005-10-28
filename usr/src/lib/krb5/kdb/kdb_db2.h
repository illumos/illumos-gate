#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * lib/kdb/kdb_db2.h
 *
 * Copyright 1997 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * KDC Database backend definitions for Berkely DB.
 */
#ifndef KRB5_KDB_DB2_H

/* renaming kludge */
#define krb5_db2_db_set_name		krb5_db_set_name
#define krb5_db2_db_set_nonblocking	krb5_db_set_nonblocking
#define krb5_db2_db_init		krb5_db_init
#define krb5_db2_db_fini		krb5_db_fini
#define krb5_db2_db_get_age		krb5_db_get_age
#define krb5_db2_db_create		krb5_db_create
#define krb5_db2_db_destroy		krb5_db_destroy
#define krb5_db2_db_rename		krb5_db_rename
#define krb5_db2_db_get_principal	krb5_db_get_principal
#define krb5_db2_db_free_principal	krb5_db_free_principal
#define krb5_db2_db_put_principal	krb5_db_put_principal
#define krb5_db2_db_delete_principal	krb5_db_delete_principal
#define krb5_db2_db_iterate		krb5_db_iterate
#define krb5_db2_db_lock		krb5_db_lock
#define krb5_db2_db_unlock		krb5_db_unlock
#define krb5_db2_db_set_lockmode	krb5_db_set_lockmode
#define krb5_db2_db_close_database	krb5_db_close_database
#define krb5_db2_db_open_database	krb5_db_open_database
#define krb5_db2_db_set_mkey		krb5_db_set_mkey
#define krb5_db2_db_get_mkey		krb5_db_get_mkey

typedef struct _krb5_db2_context {
    krb5_boolean        db_inited;      /* Context initialized          */
    char *              db_name;        /* Name of database             */
    DB *		db;		/* DB handle			*/
    krb5_boolean	hashfirst;	/* Try hash database type first	*/
    char *              db_lf_name;     /* Name of lock file            */
    int                 db_lf_file;     /* File descriptor of lock file */
    time_t              db_lf_time;     /* Time last updated            */
    int                 db_locks_held;  /* Number of times locked       */
    int                 db_lock_mode;   /* Last lock mode, e.g. greatest*/
    krb5_boolean        db_nb_locks;    /* [Non]Blocking lock modes     */
    krb5_keyblock      *db_master_key;  /* Master key of database       */
} krb5_db2_context;

#define KRB5_DB2_MAX_RETRY 5

#define KDB2_LOCK_EXT ".ok"

krb5_error_code krb5_db2_db_set_name 
	(krb5_context,
		   char * );
krb5_error_code krb5_db2_db_init 
	(krb5_context);
krb5_error_code krb5_db2_db_fini 
	(krb5_context);
krb5_error_code krb5_db2_db_get_age 
	(krb5_context,
		   char *,
		   time_t * );
krb5_error_code krb5_db2_db_create 
	(krb5_context,
		   char *,
		   krb5_int32);
krb5_error_code krb5_db2_db_destroy 
	(krb5_context,
		   char * );
krb5_error_code krb5_db2_db_rename 
	(krb5_context,
		   char *,
		   char * );
krb5_error_code krb5_db2_db_get_principal 
	(krb5_context,
		   krb5_const_principal,
		   krb5_db_entry *,
		   int *,
		   krb5_boolean * );
void krb5_db2_db_free_principal 
	(krb5_context,
		   krb5_db_entry *,
		   int );
krb5_error_code krb5_db2_db_put_principal 
	(krb5_context,
		   krb5_db_entry *,
		   int * );
krb5_error_code krb5_db2_db_iterate
    	(krb5_context,
		   krb5_error_code (*) (krb5_pointer,
					          krb5_db_entry *),
	           krb5_pointer );
krb5_error_code krb5_db2_db_set_nonblocking 
	(krb5_context,
		   krb5_boolean,
		   krb5_boolean * );
krb5_boolean krb5_db2_db_set_lockmode
	(krb5_context,
		   krb5_boolean );
krb5_error_code krb5_db2_db_open_database 
	(krb5_context);
krb5_error_code krb5_db2_db_close_database 
	(krb5_context);

#endif /* KRB5_KDB_DB2_H */
