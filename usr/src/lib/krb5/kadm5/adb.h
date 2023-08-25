/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * Data Types for policy and principal information that
 * exists in the respective databases.
 *
 * $Header$
 *
 * This file was originally created with rpcgen.
 * It has been hacked up since then.
 */

#ifndef __ADB_H__
#define __ADB_H__
#include <sys/types.h>
#include <rpc/types.h>	/* SUNWresync121 - no need to change to gssrpc/ */
#include "k5-int.h"
#include <krb5/kdb.h>
#include <db.h>
#include <kadm5/admin.h>
#include <kdb/adb_err.h>
#include <com_err.h>

typedef	long		osa_adb_ret_t;

#define OSA_ADB_POLICY_DB_MAGIC	0x12345A00
#define OSA_ADB_PRINC_DB_MAGIC	0x12345B00

#define OSA_ADB_SHARED		0x7001
#define OSA_ADB_EXCLUSIVE	0x7002
#define OSA_ADB_PERMANENT	0x7003

#define OSA_ADB_PRINC_VERSION_MASK	0x12345C00
#define OSA_ADB_PRINC_VERSION_1		0x12345C01
#define OSA_ADB_POLICY_VERSION_MASK	0x12345D00
#define OSA_ADB_POLICY_VERSION_1	0x12345D01

typedef struct _osa_adb_db_lock_ent_t {
     FILE	*lockfile;
     char	*filename;
     int	refcnt, lockmode, lockcnt;
     krb5_context context;
} osa_adb_lock_ent, *osa_adb_lock_t;

typedef struct _osa_adb_db_ent_t {
     int	magic;
     DB		*db;
     HASHINFO	info;
     BTREEINFO	btinfo;
     char	*filename;
     osa_adb_lock_t lock;
     int	opencnt;
} osa_adb_db_ent, *osa_adb_db_t, *osa_adb_princ_t, *osa_adb_policy_t;

/* an osa_pw_hist_ent stores all the key_datas for a single password */
typedef struct _osa_pw_hist_t {
     int n_key_data;
     krb5_key_data *key_data;
} osa_pw_hist_ent, *osa_pw_hist_t;

typedef struct _osa_princ_ent_t {
    int				version;
    char			*policy;
    long			aux_attributes;
    unsigned int		old_key_len;
    unsigned int		old_key_next;
    krb5_kvno			admin_history_kvno;
    osa_pw_hist_ent		*old_keys;
} osa_princ_ent_rec, *osa_princ_ent_t;

typedef struct _osa_policy_ent_t {
    int		version;
    char	*name;
    uint32_t	pw_min_life;
    uint32_t	pw_max_life;
    uint32_t	pw_min_length;
    uint32_t	pw_min_classes;
    uint32_t	pw_history_num;
    uint32_t	policy_refcnt;
} osa_policy_ent_rec, *osa_policy_ent_t;

typedef	void	(*osa_adb_iter_princ_func) (void *, osa_princ_ent_t);
typedef	void	(*osa_adb_iter_policy_func) (void *, osa_policy_ent_t);


/*
 * Return Code (the rest are in adb_err.h)
 */

#define OSA_ADB_OK		0

/*
 * xdr functions
 */
bool_t		xdr_osa_princ_ent_rec(XDR *xdrs, osa_princ_ent_t objp);
bool_t		xdr_osa_policy_ent_rec(XDR *xdrs, osa_policy_ent_t objp);
bool_t		xdr_osa_pw_hist_ent(XDR *xdrs, osa_pw_hist_ent *objp);
bool_t          xdr_krb5_key_data(XDR *xdrs, krb5_key_data *objp);

/*
 * Functions
 */

osa_adb_ret_t	osa_adb_create_db(char *filename, char *lockfile, int magic);
osa_adb_ret_t	osa_adb_destroy_db(char *filename, char *lockfile, int magic);
osa_adb_ret_t   osa_adb_rename_db(char *filefrom, char *lockfrom,
				  char *fileto, char *lockto, int magic);
osa_adb_ret_t   osa_adb_rename_policy_db(kadm5_config_params *fromparams,
					 kadm5_config_params *toparams);
osa_adb_ret_t	osa_adb_init_db(osa_adb_db_t *dbp, char *filename,
				char *lockfile, int magic);
osa_adb_ret_t	osa_adb_fini_db(osa_adb_db_t db, int magic);
osa_adb_ret_t	osa_adb_get_lock(osa_adb_db_t db, int mode);
osa_adb_ret_t	osa_adb_release_lock(osa_adb_db_t db);
osa_adb_ret_t	osa_adb_open_and_lock(osa_adb_princ_t db, int locktype);
osa_adb_ret_t	osa_adb_close_and_unlock(osa_adb_princ_t db);

osa_adb_ret_t	osa_adb_create_policy_db(kadm5_config_params *params);
osa_adb_ret_t	osa_adb_destroy_policy_db(kadm5_config_params *params);
osa_adb_ret_t	osa_adb_open_princ(osa_adb_princ_t *db, char *filename);
osa_adb_ret_t	osa_adb_open_policy(osa_adb_policy_t *db,
				    kadm5_config_params *rparams);
osa_adb_ret_t	osa_adb_close_princ(osa_adb_princ_t db);
osa_adb_ret_t	osa_adb_close_policy(osa_adb_policy_t db);
osa_adb_ret_t	osa_adb_create_princ(osa_adb_princ_t db,
				 osa_princ_ent_t entry);
osa_adb_ret_t	osa_adb_create_policy(osa_adb_policy_t db,
				      osa_policy_ent_t entry);
osa_adb_ret_t	osa_adb_destroy_princ(osa_adb_princ_t db,
				      kadm5_princ_t name);
osa_adb_ret_t	osa_adb_destroy_policy(osa_adb_policy_t db,
				       kadm5_policy_t name);
osa_adb_ret_t	osa_adb_get_princ(osa_adb_princ_t db,
				  kadm5_princ_t name,
				  osa_princ_ent_t *entry);
osa_adb_ret_t	osa_adb_get_policy(osa_adb_policy_t db,
				   kadm5_policy_t name,
				   osa_policy_ent_t *entry);
osa_adb_ret_t	osa_adb_put_princ(osa_adb_princ_t db,
				  osa_princ_ent_t entry);
osa_adb_ret_t	osa_adb_put_policy(osa_adb_policy_t db,
				   osa_policy_ent_t entry);
osa_adb_ret_t	osa_adb_iter_policy(osa_adb_policy_t db,
				    osa_adb_iter_policy_func func,
				    void * data);
osa_adb_ret_t	osa_adb_iter_princ(osa_adb_princ_t db,
				       osa_adb_iter_princ_func func,
				       void *data);
void		osa_free_policy_ent(osa_policy_ent_t val);
void		osa_free_princ_ent(osa_princ_ent_t val);
#endif /* __ADB_H__ */
