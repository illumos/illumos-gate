#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * include/krb5/kdb_dbm.h
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * KDC Database interface definitions.
 */


#ifndef KRB5_KDB5_DBM__
#define KRB5_KDB5_DBM__

#if !defined(macintosh) && !defined(_MSDOS) && !defined(_WIN32)
	
/* exclusive or shared lock flags */
#define	KRB5_DBM_SHARED		0
#define	KRB5_DBM_EXCLUSIVE	1

#define KRB5_DB_SHARED 		KRB5_DBM_SHARED
#define KRB5_DB_EXCLUSIVE	KRB5_DBM_EXCLUSIVE

/* #define these to avoid an indirection function; for future implementations,
   these may be redirected from a dispatch table/routine */
#define krb5_dbm_db_set_name krb5_db_set_name
#define krb5_dbm_db_set_nonblocking krb5_db_set_nonblocking
#define krb5_dbm_db_init krb5_db_init
#define krb5_dbm_db_fini krb5_db_fini
#define krb5_dbm_db_get_age krb5_db_get_age
#define krb5_dbm_db_create krb5_db_create
#define krb5_dbm_db_destroy kdb5_db_destroy
#define krb5_dbm_db_rename krb5_db_rename
#define krb5_dbm_db_get_principal krb5_db_get_principal
#define krb5_dbm_db_free_principal krb5_db_free_principal
#define krb5_dbm_db_put_principal krb5_db_put_principal
#define krb5_dbm_db_delete_principal krb5_db_delete_principal
#define krb5_dbm_db_iterate krb5_db_iterate
#define krb5_dbm_db_lock krb5_db_lock
#define krb5_dbm_db_unlock krb5_db_unlock
#define krb5_dbm_db_set_lockmode krb5_db_set_lockmode
#define krb5_dbm_db_close_database krb5_db_close_database
#define krb5_dbm_db_open_database krb5_db_open_database

/* libkdb.spec */
krb5_error_code krb5_dbm_db_set_name 
	KRB5_PROTOTYPE((krb5_context,
		   char * ));
krb5_error_code krb5_dbm_db_init 
	KRB5_PROTOTYPE((krb5_context));
krb5_error_code krb5_dbm_db_fini 
	KRB5_PROTOTYPE((krb5_context));
krb5_error_code krb5_dbm_db_get_age 
	KRB5_PROTOTYPE((krb5_context,
		   char *,
		   time_t * ));
krb5_error_code krb5_dbm_db_create 
	KRB5_PROTOTYPE((krb5_context,
		   char * ));
krb5_error_code krb5_dbm_db_destroy 
	KRB5_PROTOTYPE((krb5_context,
		   char * ));
krb5_error_code krb5_dbm_db_rename 
	KRB5_PROTOTYPE((krb5_context,
		   char *,
		   char * ));
krb5_error_code krb5_dbm_db_get_principal 
	KRB5_PROTOTYPE((krb5_context,
		   krb5_const_principal,
		   krb5_db_entry *,
		   int *,
		   krb5_boolean * ));
void krb5_dbm_db_free_principal 
	KRB5_PROTOTYPE((krb5_context,
		   krb5_db_entry *,
		   int ));
krb5_error_code krb5_dbm_db_delete_principal 
	KRB5_PROTOTYPE((krb5_context,
		   krb5_const_principal,
		   int * ));
krb5_error_code krb5_dbm_db_put_principal 
	KRB5_PROTOTYPE((krb5_context,
		   krb5_db_entry *,
		   int * ));
krb5_error_code krb5_dbm_db_iterate
    	KRB5_PROTOTYPE((krb5_context,
		   krb5_error_code (*) KRB5_PROTOTYPE((krb5_pointer,
					          krb5_db_entry *)),
	           krb5_pointer ));
krb5_error_code krb5_dbm_db_set_nonblocking 
	KRB5_PROTOTYPE((krb5_context,
		   krb5_boolean,
		   krb5_boolean * ));
krb5_boolean krb5_dbm_db_set_lockmode
	KRB5_PROTOTYPE((krb5_context,
		   krb5_boolean ));
krb5_error_code krb5_dbm_db_open_database 
	KRB5_PROTOTYPE((krb5_context));
krb5_error_code krb5_dbm_db_close_database 
	KRB5_PROTOTYPE((krb5_context));

#endif /* !defined(macintosh) && !defined(_MSDOS) && !defined(WIN32) */
#endif /* KRB5_KDB5_DBM__ */
