/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/gss_mechs/mech_krb5/include/krb5/kdb_dbc.h
 * Copyright 1995 by the Massachusetts Institute of Technology.
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * KDC Database context definitions.
 */


#ifndef KRB5_KDB5_DBC__
#define KRB5_KDB5_DBC__

#if !defined(_MACINTOSH) && !defined(_MSDOS)

#include "kdb.h"
	
/* Per-database context. */
typedef struct __krb5_db_context {
    krb5_boolean        db_inited;      /* Context initialized          */
    char *              db_name;        /* Name of database             */
    DBM *               db_dbm_ctx;     /* DBM context for database     */
    char *              db_lf_name;     /* Name of lock file            */
    int                 db_lf_file;     /* File descriptor of lock file */
    time_t              db_lf_time;     /* Time last updated            */
    int                 db_locks_held;  /* Number of times locked       */
    int                 db_lock_mode;   /* Last lock mode, e.g. greatest*/
    krb5_boolean        db_nb_locks;    /* [Non]Blocking lock modes     */
    krb5_encrypt_block *db_master_key;  /* Master key of database       */
    kdb5_dispatch_table *db_dispatch;   /* Dispatch table               */
} krb5_db_context;

krb5_error_code krb5_ktkdb_resolve
        KRB5_PROTOTYPE((krb5_context, krb5_db_context *, krb5_keytab *));

krb5_error_code krb5_dbm_db_set_mkey
        KRB5_PROTOTYPE((krb5_context,krb5_db_context *,krb5_encrypt_block *));

krb5_error_code krb5_dbm_db_get_mkey
        KRB5_PROTOTYPE((krb5_context,krb5_encrypt_block **));

#endif /* !defined(_MACINTOSH) && !defined(_MSDOS) */
#endif /* KRB5_KDB5_DBM__ */
