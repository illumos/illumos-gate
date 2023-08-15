/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 *
 *	Openvision retains the copyright to derivative works of
 *	this source code.  Do *NOT* create a derivative of this
 *	source code before consulting with your legal department.
 *	Do *NOT* integrate *ANY* of this source code into another
 *	product before consulting with your legal department.
 *
 *	For further information, read the top-level Openvision
 *	copyright which is contained in the top-level MIT Kerberos
 *	copyright.
 *
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 *
 */


/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved
 *
 * $Header$
 */

/*
 * This header file is used internally by the Admin API server
 * libraries and Admin server.  IF YOU THINK YOU NEED TO USE THIS FILE
 * FOR ANYTHING, YOU'RE ALMOST CERTAINLY WRONG.
 */

#ifndef __KADM5_SERVER_INTERNAL_H__
#define __KADM5_SERVER_INTERNAL_H__

#ifdef HAVE_MEMORY_H
#include    <memory.h>
#endif
#include    <stdlib.h>
#include    <errno.h>
#include    "k5-int.h"
#include    <krb5/kdb.h>
#include    <kadm5/admin.h>
#include    <rpc/xdr.h>
#include    "admin_internal.h"

typedef struct _kadm5_server_handle_t {
	krb5_ui_4	magic_number;
	krb5_ui_4	struct_version;
	krb5_ui_4	api_version;
	krb5_context	context;
	krb5_principal	current_caller;
	kadm5_config_params  params;
	struct _kadm5_server_handle_t *lhandle;
        char **db_args;
	krb5_keyblock	master_keyblock;
} kadm5_server_handle_rec, *kadm5_server_handle_t;

#define OSA_ADB_PRINC_VERSION_1  0x12345C01

typedef struct _osa_pw_hist_t {
  int n_key_data;
  krb5_key_data *key_data;
} osa_pw_hist_ent, *osa_pw_hist_t;

typedef struct _osa_princ_ent_t {
  int                         version;
  char                        *policy;
  long                        aux_attributes;
  unsigned int                old_key_len;
  unsigned int                old_key_next;
  krb5_kvno                   admin_history_kvno;
  osa_pw_hist_ent             *old_keys;
} osa_princ_ent_rec, *osa_princ_ent_t;


kadm5_ret_t    adb_policy_init(kadm5_server_handle_t handle);
kadm5_ret_t    adb_policy_close(kadm5_server_handle_t handle);
kadm5_ret_t    passwd_check(kadm5_server_handle_t handle,
			    char *pass, int use_policy,
			    kadm5_policy_ent_t policy,
			    krb5_principal principal);
kadm5_ret_t    principal_exists(krb5_principal principal);
krb5_error_code	    kdb_init_master(kadm5_server_handle_t handle,
				    char *r, int from_keyboard);
krb5_error_code	    kdb_init_hist(kadm5_server_handle_t handle,
				  char *r);
krb5_error_code     kdb_get_entry(kadm5_server_handle_t handle,
				  krb5_principal principal, krb5_db_entry *kdb,
				  osa_princ_ent_rec *adb);
krb5_error_code     kdb_free_entry(kadm5_server_handle_t handle,
				   krb5_db_entry *kdb, osa_princ_ent_rec *adb);
krb5_error_code     kdb_put_entry(kadm5_server_handle_t handle,
				  krb5_db_entry *kdb, osa_princ_ent_rec *adb);
krb5_error_code     kdb_delete_entry(kadm5_server_handle_t handle,
				     krb5_principal name);
krb5_error_code     kdb_iter_entry(kadm5_server_handle_t handle,
				   char *match_entry,
				   void (*iter_fct)(void *, krb5_principal),
				   void *data);

int		    init_dict(kadm5_config_params *);
int		    find_word(const char *word);
void		    destroy_dict(void);

/* XXX this ought to be in libkrb5.a, but isn't */
kadm5_ret_t krb5_copy_key_data_contents(krb5_context context,
					krb5_key_data *from,
					krb5_key_data *to);
kadm5_ret_t krb5_free_key_data_contents(krb5_context context,
					krb5_key_data *key);

/*
 * *Warning*
 * *Warning*	    This is going to break if we
 * *Warning*	    ever go multi-threaded
 * *Warning*
 */
extern	krb5_principal	current_caller;

/*
 * Why is this (or something similar) not defined *anywhere* in krb5?
 */
#define KSUCCESS	0
#define WORD_NOT_FOUND	1

/*
 * all the various mask bits or'd together
 */

#define	ALL_PRINC_MASK \
 (KADM5_PRINCIPAL | KADM5_PRINC_EXPIRE_TIME | KADM5_PW_EXPIRATION | \
  KADM5_LAST_PWD_CHANGE | KADM5_ATTRIBUTES | KADM5_MAX_LIFE | \
  KADM5_MOD_TIME | KADM5_MOD_NAME | KADM5_KVNO | KADM5_MKVNO | \
  KADM5_AUX_ATTRIBUTES | KADM5_POLICY_CLR | KADM5_POLICY | \
  KADM5_MAX_RLIFE | KADM5_TL_DATA | KADM5_KEY_DATA)

#define ALL_POLICY_MASK \
 (KADM5_POLICY | KADM5_PW_MAX_LIFE | KADM5_PW_MIN_LIFE | \
  KADM5_PW_MIN_LENGTH | KADM5_PW_MIN_CLASSES | KADM5_PW_HISTORY_NUM | \
  KADM5_REF_COUNT)

#define SERVER_CHECK_HANDLE(handle) \
{ \
	kadm5_server_handle_t srvr = \
	     (kadm5_server_handle_t) handle; \
 \
	if (! srvr->current_caller) \
		return KADM5_BAD_SERVER_HANDLE; \
	if (! srvr->lhandle) \
	        return KADM5_BAD_SERVER_HANDLE; \
}

#define CHECK_HANDLE(handle) \
     GENERIC_CHECK_HANDLE(handle, KADM5_OLD_SERVER_API_VERSION, \
			  KADM5_NEW_SERVER_API_VERSION) \
     SERVER_CHECK_HANDLE(handle)

bool_t          xdr_osa_princ_ent_rec(XDR *xdrs, osa_princ_ent_t objp);

void
osa_free_princ_ent(osa_princ_ent_t val);

#endif /* __KADM5_SERVER_INTERNAL_H__ */
