/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _KDB_HDR_H
#define	_KDB_HDR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <krb5.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This header is required to solve a conflict with
 * usr/src/lib/gss_mechs/mech_krb5/include/krb5/kdb_dbm.h
 * which creates numerous defines like ....
 * #define krb5_dbm_db_fini krb5_db_fini
 * that break the spec file creation and resolution process.
 *
 * lib/kdb/kdb_hdr.h
 */

#ifndef __KADM5_ADMIN_H__
struct _kadm5_config_params; 
typedef struct _kadm5_config_params kadm5_config_params;
#endif

#if defined(KRB5_NO_CONST) || (defined(__ultrix) && !defined(__GNUC__))
#define krb5_const
#else
#define krb5_const const
#endif

typedef struct _krb5_keysalt {
    krb5_int16            type;
    krb5_data             data;                 /* Length, data */
} krb5_keysalt;

typedef struct _krb5_tl_data {
    struct _krb5_tl_data* tl_data_next;         /* NOT saved */
    krb5_int16            tl_data_type;
    krb5_int16            tl_data_length;
    krb5_octet          * tl_data_contents;
} krb5_tl_data;

typedef struct _krb5_key_data {
    krb5_int16            key_data_ver;         /* Version */
    krb5_int16            key_data_kvno;        /* Key Version */
    krb5_int16            key_data_type[2];     /* Array of types */
    krb5_int16            key_data_length[2];   /* Array of lengths */
    krb5_octet          * key_data_contents[2]; /* Array of pointers */
} krb5_key_data;

typedef struct _krb5_db_entry_new {
    krb5_magic            magic;                /* NOT saved */
    krb5_int16            len;
    krb5_flags            attributes;
    krb5_deltat           max_life;
    krb5_deltat           max_renewable_life;
    krb5_timestamp        expiration;           /* When the client expires */
    krb5_timestamp        pw_expiration;        /* When its passwd expires */
    krb5_timestamp        last_success;         /* Last successful passwd */
    krb5_timestamp        last_failed;          /* Last failed passwd attempt */
    krb5_kvno             fail_auth_count;      /* # of failed passwd attempt */
    krb5_int16            n_tl_data;
    krb5_int16            n_key_data;
    krb5_int16            e_length;             /* Length of extra data */
    krb5_octet          * e_data;               /* Extra data to be saved */

    krb5_principal        princ;                /* Length, data */
    krb5_tl_data        * tl_data;              /* Linked list */
    krb5_key_data       * key_data;             /* Array */
} krb5_db_entry;

#include "krb5/adm.h"
#include "db-ndbm.h"

#ifndef __P
#if defined(__STDC__) || defined(__cplusplus)
#define __P(protos)     protos          /* full-blown ANSI C */
#else   /* !(__STDC__ || __cplusplus) */
#define __P(protos)     ()              /* traditional C preprocessor */
#endif
#endif /* no __P from system */

#ifndef __P
#if defined(__STDC__) || defined(__cplusplus)
#define __P(protos)     protos          /* full-blown ANSI C */
#else   /* !(__STDC__ || __cplusplus) */
#define __P(protos)     ()              /* traditional C preprocessor */
#endif
#endif /* no __P from system */

typedef struct _kdb5_dispatch_table {
    char *      kdb5_db_mech_name;
    char *      kdb5_db_index_ext;
    char *      kdb5_db_data_ext;
    char *      kdb5_db_lock_ext;
    DBM *       (*kdb5_dbm_open) KRB5_NPROTOTYPE((const char *, int, int));
    void        (*kdb5_dbm_close) KRB5_NPROTOTYPE((DBM *));
    datum       (*kdb5_dbm_fetch) KRB5_NPROTOTYPE((DBM *, datum));
    datum       (*kdb5_dbm_firstkey) KRB5_NPROTOTYPE((DBM *));
    datum       (*kdb5_dbm_nextkey) KRB5_NPROTOTYPE((DBM *));
    int         (*kdb5_dbm_delete) KRB5_NPROTOTYPE((DBM *, datum));
    int         (*kdb5_dbm_store) KRB5_NPROTOTYPE((DBM *, datum, datum, int));
    int         (*kdb5_dbm_dirfno) KRB5_NPROTOTYPE((DBM *));
    int         (*kdb5_dbm_pagfno) KRB5_NPROTOTYPE((DBM *));
} kdb5_dispatch_table;

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

#ifdef	__cplusplus
}
#endif

#endif	/* !_KDB_HDR_H */
