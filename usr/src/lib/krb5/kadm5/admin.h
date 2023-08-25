/*
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	__KADM5_ADMIN_H__
#define	__KADM5_ADMIN_H__


#ifdef __cplusplus
extern "C" {
#endif

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
 * lib/kadm5/admin.h
 *
 * Copyright 2001 by the Massachusetts Institute of Technology.
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
 */
/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved
 *
 * $Header$
 */

#include	<sys/types.h>
#include	<rpc/types.h>
#include	<rpc/rpc.h>
#include	<k5-int.h>
#include	<krb5.h>
#include	<krb5/kdb.h>
#include	<com_err.h>
#include	<kadm5/kadm_err.h>
#include	<kadm5/chpass_util_strings.h>

#define KADM5_ADMIN_SERVICE_P	"kadmin@admin"
/*
 * Solaris Kerberos:
 * The kadmin/admin principal is unused on Solaris. This principal is used
 * in AUTH_GSSAPI but Solaris doesn't support AUTH_GSSAPI. RPCSEC_GSS can only
 * be used with host-based principals.
 *
 */
/* #define KADM5_ADMIN_SERVICE	"kadmin/admin" */
#define KADM5_CHANGEPW_SERVICE_P	"kadmin@changepw"
#define KADM5_CHANGEPW_SERVICE	"kadmin/changepw"
#define KADM5_HIST_PRINCIPAL	"kadmin/history"
#define KADM5_ADMIN_HOST_SERVICE "kadmin"
#define KADM5_CHANGEPW_HOST_SERVICE "changepw"
#define KADM5_KIPROP_HOST_SERVICE "kiprop"

typedef krb5_principal	kadm5_princ_t;
typedef	char		*kadm5_policy_t;
typedef long		kadm5_ret_t;
typedef int rpc_int32;
typedef unsigned int rpc_u_int32;

#define KADM5_PW_FIRST_PROMPT \
	(error_message(CHPASS_UTIL_NEW_PASSWORD_PROMPT))
#define KADM5_PW_SECOND_PROMPT \
	(error_message(CHPASS_UTIL_NEW_PASSWORD_AGAIN_PROMPT))

/*
 * Successful return code
 */
#define KADM5_OK	0

/*
 * Field masks
 */

/* kadm5_principal_ent_t */
#define KADM5_PRINCIPAL		0x000001
#define KADM5_PRINC_EXPIRE_TIME	0x000002
#define KADM5_PW_EXPIRATION	0x000004
#define KADM5_LAST_PWD_CHANGE	0x000008
#define KADM5_ATTRIBUTES	0x000010
#define KADM5_MAX_LIFE		0x000020
#define KADM5_MOD_TIME		0x000040
#define KADM5_MOD_NAME		0x000080
#define KADM5_KVNO		0x000100
#define KADM5_MKVNO		0x000200
#define KADM5_AUX_ATTRIBUTES	0x000400
#define KADM5_POLICY		0x000800
#define KADM5_POLICY_CLR	0x001000
/* version 2 masks */
#define KADM5_MAX_RLIFE		0x002000
#define KADM5_LAST_SUCCESS	0x004000
#define KADM5_LAST_FAILED	0x008000
#define KADM5_FAIL_AUTH_COUNT	0x010000
#define KADM5_KEY_DATA		0x020000
#define KADM5_TL_DATA		0x040000
#ifdef notyet /* Novell */
#define KADM5_CPW_FUNCTION      0x080000
#define KADM5_RANDKEY_USED      0x100000
#endif
#define KADM5_LOAD		0x200000
/* Solaris Kerberos: adding support for key history in LDAP KDB */
#define KADM5_KEY_HIST		0x400000

/* all but KEY_DATA and TL_DATA */
#define KADM5_PRINCIPAL_NORMAL_MASK 0x01ffff


/* kadm5_policy_ent_t */
#define KADM5_PW_MAX_LIFE	0x004000
#define KADM5_PW_MIN_LIFE	0x008000
#define KADM5_PW_MIN_LENGTH	0x010000
#define KADM5_PW_MIN_CLASSES	0x020000
#define KADM5_PW_HISTORY_NUM	0x040000
#define KADM5_REF_COUNT		0x080000

/* kadm5_config_params */
#define KADM5_CONFIG_REALM		0x0000001
#define KADM5_CONFIG_DBNAME		0x0000002
#define KADM5_CONFIG_MKEY_NAME		0x0000004
#define KADM5_CONFIG_MAX_LIFE		0x0000008
#define KADM5_CONFIG_MAX_RLIFE		0x0000010
#define KADM5_CONFIG_EXPIRATION		0x0000020
#define KADM5_CONFIG_FLAGS		0x0000040
#define KADM5_CONFIG_ADMIN_KEYTAB	0x0000080
#define KADM5_CONFIG_STASH_FILE		0x0000100
#define KADM5_CONFIG_ENCTYPE		0x0000200
#define KADM5_CONFIG_ADBNAME		0x0000400
#define KADM5_CONFIG_ADB_LOCKFILE	0x0000800
#define KADM5_CONFIG_PROFILE		0x0001000
#define KADM5_CONFIG_ACL_FILE		0x0002000
#define KADM5_CONFIG_KADMIND_PORT	0x0004000
#define KADM5_CONFIG_ENCTYPES		0x0008000
#define KADM5_CONFIG_ADMIN_SERVER	0x0010000
#define KADM5_CONFIG_DICT_FILE		0x0020000
#define KADM5_CONFIG_MKEY_FROM_KBD	0x0040000
#define KADM5_CONFIG_KPASSWD_PORT	0x0080000
#define KADM5_CONFIG_KPASSWD_SERVER	0x0100000
#define	KADM5_CONFIG_KPASSWD_PROTOCOL	0x0200000
#define	KADM5_CONFIG_IPROP_ENABLED	0x0400000
#define	KADM5_CONFIG_ULOG_SIZE		0x0800000
#define	KADM5_CONFIG_POLL_TIME		0x1000000

/* password change constants */
#define	KRB5_KPASSWD_SUCCESS		0
#define	KRB5_KPASSWD_MALFORMED		1
#define	KRB5_KPASSWD_HARDERROR		2
#define	KRB5_KPASSWD_AUTHERROR		3
#define	KRB5_KPASSWD_SOFTERROR		4
#define	KRB5_KPASSWD_ACCESSDENIED	5
#define	KRB5_KPASSWD_BAD_VERSION	6
#define	KRB5_KPASSWD_INITIAL_FLAG_NEEDED	7
#define	KRB5_KPASSWD_POLICY_REJECT	8
#define	KRB5_KPASSWD_BAD_PRINCIPAL	9
#define	KRB5_KPASSWD_ETYPE_NOSUPP	10

/*
 * permission bits
 */
#define KADM5_PRIV_GET		0x01
#define KADM5_PRIV_ADD		0x02
#define KADM5_PRIV_MODIFY	0x04
#define KADM5_PRIV_DELETE	0x08

/*
 * API versioning constants
 */
#define KADM5_MASK_BITS		0xffffff00

#define KADM5_STRUCT_VERSION_MASK	0x12345600
#define KADM5_STRUCT_VERSION_1	(KADM5_STRUCT_VERSION_MASK|0x01)
#define KADM5_STRUCT_VERSION	KADM5_STRUCT_VERSION_1

#define KADM5_API_VERSION_MASK	0x12345700
#define KADM5_API_VERSION_1	(KADM5_API_VERSION_MASK|0x01)
#define KADM5_API_VERSION_2	(KADM5_API_VERSION_MASK|0x02)

#ifdef KRB5_DNS_LOOKUP
/*
 * Name length constants for DNS lookups
 */
#define	MAX_HOST_NAMELEN 256
#define	MAX_DNS_NAMELEN (15*(MAX_HOST_NAMELEN + 1)+1)
#endif /* KRB5_DNS_LOOKUP */

typedef struct _kadm5_principal_ent_t_v2 {
	krb5_principal	principal;
	krb5_timestamp	princ_expire_time;
	krb5_timestamp	last_pwd_change;
	krb5_timestamp	pw_expiration;
	krb5_deltat	max_life;
	krb5_principal	mod_name;
	krb5_timestamp	mod_date;
	krb5_flags	attributes;
	krb5_kvno	kvno;
	krb5_kvno	mkvno;
	char		*policy;
	long		aux_attributes;

	/* version 2 fields */
	krb5_deltat max_renewable_life;
        krb5_timestamp last_success;
        krb5_timestamp last_failed;
        krb5_kvno fail_auth_count;
	krb5_int16 n_key_data;
	krb5_int16 n_tl_data;
        krb5_tl_data *tl_data;
	krb5_key_data *key_data;
} kadm5_principal_ent_rec_v2, *kadm5_principal_ent_t_v2;

typedef struct _kadm5_principal_ent_t_v1 {
	krb5_principal	principal;
	krb5_timestamp	princ_expire_time;
	krb5_timestamp	last_pwd_change;
	krb5_timestamp	pw_expiration;
	krb5_deltat	max_life;
	krb5_principal	mod_name;
	krb5_timestamp	mod_date;
	krb5_flags	attributes;
	krb5_kvno	kvno;
	krb5_kvno	mkvno;
	char		*policy;
	long		aux_attributes;
} kadm5_principal_ent_rec_v1, *kadm5_principal_ent_t_v1;

#if USE_KADM5_API_VERSION == 1
typedef struct _kadm5_principal_ent_t_v1
     kadm5_principal_ent_rec, *kadm5_principal_ent_t;
#else
typedef struct _kadm5_principal_ent_t_v2
     kadm5_principal_ent_rec, *kadm5_principal_ent_t;
#endif

typedef struct _kadm5_policy_ent_t {
	char		*policy;
	long		pw_min_life;
	long		pw_max_life;
	long		pw_min_length;
	long		pw_min_classes;
	long		pw_history_num;
	long		policy_refcnt;
} kadm5_policy_ent_rec, *kadm5_policy_ent_t;

/*
 * New types to indicate which protocol to use when sending
 * password change requests
 */
typedef enum {
	KRB5_CHGPWD_RPCSEC,
	KRB5_CHGPWD_CHANGEPW_V2
} krb5_chgpwd_prot;

/*
 * Data structure returned by kadm5_get_config_params()
 */
typedef struct _kadm5_config_params {
     long		mask;
     char *		realm;
     int		kadmind_port;
     int		kpasswd_port;

     char *		admin_server;
#ifdef notyet /* Novell */ /* ABI change? */
     char *		kpasswd_server;
#endif

     char *		dbname;
     char *		admin_dbname;
     char *		admin_lockfile;
     char *		admin_keytab;
     char *		acl_file;
     char *		dict_file;

     int		mkey_from_kbd;
     char *		stash_file;
     char *		mkey_name;
     krb5_enctype	enctype;
     krb5_deltat	max_life;
     krb5_deltat	max_rlife;
     krb5_timestamp	expiration;
     krb5_flags		flags;
     krb5_key_salt_tuple *keysalts;
     krb5_int32		num_keysalts;
     char 			*kpasswd_server;

     krb5_chgpwd_prot	kpasswd_protocol;
     bool_t			iprop_enabled;
     int			iprop_ulogsize;
     char			*iprop_polltime;
} kadm5_config_params;

/***********************************************************************
 * This is the old krb5_realm_read_params, which I mutated into
 * kadm5_get_config_params but which old code (kdb5_* and krb5kdc)
 * still uses.
 ***********************************************************************/

/*
 * Data structure returned by krb5_read_realm_params()
 */
typedef struct __krb5_realm_params {
    char *		realm_profile;
    char *		realm_dbname;
    char *		realm_mkey_name;
    char *		realm_stash_file;
    char *		realm_kdc_ports;
    char *		realm_kdc_tcp_ports;
    char *		realm_acl_file;
    krb5_int32		realm_kadmind_port;
    krb5_enctype	realm_enctype;
    krb5_deltat		realm_max_life;
    krb5_deltat		realm_max_rlife;
    krb5_timestamp	realm_expiration;
    krb5_flags		realm_flags;
    krb5_key_salt_tuple	*realm_keysalts;
    unsigned int	realm_reject_bad_transit:1;
    unsigned int	realm_kadmind_port_valid:1;
    unsigned int	realm_enctype_valid:1;
    unsigned int	realm_max_life_valid:1;
    unsigned int	realm_max_rlife_valid:1;
    unsigned int	realm_expiration_valid:1;
    unsigned int	realm_flags_valid:1;
    unsigned int	realm_reject_bad_transit_valid:1;
    krb5_int32		realm_num_keysalts;
} krb5_realm_params;

/*
 * functions
 */

kadm5_ret_t
kadm5_get_adm_host_srv_name(krb5_context context,
                           const char *realm, char **host_service_name);

kadm5_ret_t
kadm5_get_cpw_host_srv_name(krb5_context context,
                           const char *realm, char **host_service_name);

#if USE_KADM5_API_VERSION > 1
krb5_error_code kadm5_get_config_params(krb5_context context,
					int use_kdc_config,
					kadm5_config_params *params_in,
					kadm5_config_params *params_out);

krb5_error_code kadm5_free_config_params(krb5_context context,
					 kadm5_config_params *params);

krb5_error_code kadm5_free_realm_params(krb5_context kcontext,
					kadm5_config_params *params);

krb5_error_code kadm5_get_admin_service_name(krb5_context, char *,
					     char *, size_t);
#endif

kadm5_ret_t    kadm5_init(char *client_name, char *pass,
			  char *service_name,
#if USE_KADM5_API_VERSION == 1
			  char *realm,
#else
			  kadm5_config_params *params,
#endif
			  krb5_ui_4 struct_version,
			  krb5_ui_4 api_version,
			  char **db_args,
			  void **server_handle);
kadm5_ret_t    kadm5_init_with_password(char *client_name,
					char *pass,
					char *service_name,
#if USE_KADM5_API_VERSION == 1
					char *realm,
#else
					kadm5_config_params *params,
#endif
					krb5_ui_4 struct_version,
					krb5_ui_4 api_version,
					char **db_args,
					void **server_handle);
kadm5_ret_t    kadm5_init_with_skey(char *client_name,
				    char *keytab,
				    char *service_name,
#if USE_KADM5_API_VERSION == 1
				    char *realm,
#else
				    kadm5_config_params *params,
#endif
				    krb5_ui_4 struct_version,
				    krb5_ui_4 api_version,
				    char **db_args,
				    void **server_handle);
#if USE_KADM5_API_VERSION > 1
kadm5_ret_t    kadm5_init_with_creds(char *client_name,
				     krb5_ccache cc,
				     char *service_name,
				     kadm5_config_params *params,
				     krb5_ui_4 struct_version,
				     krb5_ui_4 api_version,
				     char **db_args,
				     void **server_handle);
#endif
kadm5_ret_t    kadm5_lock(void *server_handle);
kadm5_ret_t    kadm5_unlock(void *server_handle);
kadm5_ret_t    kadm5_flush(void *server_handle);
kadm5_ret_t    kadm5_destroy(void *server_handle);
kadm5_ret_t    kadm5_check_min_life(void *server_handle,	/* Solaris Kerberos */
			      krb5_principal principal,
			      char *msg_ret,
			      unsigned int msg_len);
kadm5_ret_t    kadm5_create_principal(void *server_handle,
				      kadm5_principal_ent_t ent,
				      long mask, char *pass);
kadm5_ret_t    kadm5_create_principal_3(void *server_handle,
					kadm5_principal_ent_t ent,
					long mask,
					int n_ks_tuple,
					krb5_key_salt_tuple *ks_tuple,
					char *pass);
kadm5_ret_t    kadm5_delete_principal(void *server_handle,
				      krb5_principal principal);
kadm5_ret_t    kadm5_modify_principal(void *server_handle,
				      kadm5_principal_ent_t ent,
				      long mask);
kadm5_ret_t    kadm5_rename_principal(void *server_handle,
				      krb5_principal,krb5_principal);
#if USE_KADM5_API_VERSION == 1
kadm5_ret_t    kadm5_get_principal(void *server_handle,
				   krb5_principal principal,
				   kadm5_principal_ent_t *ent);
#else
kadm5_ret_t    kadm5_get_principal(void *server_handle,
				   krb5_principal principal,
				   kadm5_principal_ent_t ent,
				   long mask);
#endif
kadm5_ret_t    kadm5_chpass_principal(void *server_handle,
				      krb5_principal principal,
				      char *pass);
kadm5_ret_t    kadm5_chpass_principal_3(void *server_handle,
					krb5_principal principal,
					krb5_boolean keepold,
					int n_ks_tuple,
					krb5_key_salt_tuple *ks_tuple,
					char *pass);
#if USE_KADM5_API_VERSION == 1
kadm5_ret_t    kadm5_randkey_principal(void *server_handle,
				       krb5_principal principal,
				       krb5_keyblock **keyblock);
#else

/*
 * Solaris Kerberos:
 * this routine is only implemented in the client library.
 */
kadm5_ret_t    kadm5_randkey_principal_old(void *server_handle,
				    krb5_principal principal,
				    krb5_keyblock **keyblocks,
				    int *n_keys);

kadm5_ret_t    kadm5_randkey_principal(void *server_handle,
				       krb5_principal principal,
				       krb5_keyblock **keyblocks,
				       int *n_keys);
kadm5_ret_t    kadm5_randkey_principal_3(void *server_handle,
					 krb5_principal principal,
					 krb5_boolean keepold,
					 int n_ks_tuple,
					 krb5_key_salt_tuple *ks_tuple,
					 krb5_keyblock **keyblocks,
					 int *n_keys);
#endif
kadm5_ret_t    kadm5_setv4key_principal(void *server_handle,
					krb5_principal principal,
					krb5_keyblock *keyblock);

kadm5_ret_t    kadm5_setkey_principal(void *server_handle,
				      krb5_principal principal,
				      krb5_keyblock *keyblocks,
				      int n_keys);

kadm5_ret_t    kadm5_setkey_principal_3(void *server_handle,
					krb5_principal principal,
					krb5_boolean keepold,
					int n_ks_tuple,
					krb5_key_salt_tuple *ks_tuple,
					krb5_keyblock *keyblocks,
					int n_keys);

kadm5_ret_t    kadm5_decrypt_key(void *server_handle,
				 kadm5_principal_ent_t entry, krb5_int32
				 ktype, krb5_int32 stype, krb5_int32
				 kvno, krb5_keyblock *keyblock,
				 krb5_keysalt *keysalt, int *kvnop);

kadm5_ret_t    kadm5_create_policy(void *server_handle,
				   kadm5_policy_ent_t ent,
				   long mask);
/*
 * kadm5_create_policy_internal is not part of the supported,
 * exposed API.  It is available only in the server library, and you
 * shouldn't use it unless you know why it's there and how it's
 * different from kadm5_create_policy.
 */
kadm5_ret_t    kadm5_create_policy_internal(void *server_handle,
					    kadm5_policy_ent_t
					    entry, long mask);
kadm5_ret_t    kadm5_delete_policy(void *server_handle,
				   kadm5_policy_t policy);
kadm5_ret_t    kadm5_modify_policy(void *server_handle,
				   kadm5_policy_ent_t ent,
				   long mask);
/*
 * kadm5_modify_policy_internal is not part of the supported,
 * exposed API.  It is available only in the server library, and you
 * shouldn't use it unless you know why it's there and how it's
 * different from kadm5_modify_policy.
 */
kadm5_ret_t    kadm5_modify_policy_internal(void *server_handle,
					    kadm5_policy_ent_t
					    entry, long mask);
#if USE_KADM5_API_VERSION == 1
kadm5_ret_t    kadm5_get_policy(void *server_handle,
				kadm5_policy_t policy,
				kadm5_policy_ent_t *ent);
#else
kadm5_ret_t    kadm5_get_policy(void *server_handle,
				kadm5_policy_t policy,
				kadm5_policy_ent_t ent);
#endif
kadm5_ret_t    kadm5_get_privs(void *server_handle,
			       long *privs);

kadm5_ret_t    kadm5_chpass_principal_util(void *server_handle,
					   krb5_principal princ,
					   char *new_pw,
					   char **ret_pw,
					   char *msg_ret,
					   unsigned int msg_len);

kadm5_ret_t    kadm5_free_principal_ent(void *server_handle,
					kadm5_principal_ent_t
					ent);
kadm5_ret_t    kadm5_free_policy_ent(void *server_handle,
				     kadm5_policy_ent_t ent);

kadm5_ret_t    kadm5_get_principals(void *server_handle,
				    char *exp, char ***princs,
				    int *count);

kadm5_ret_t    kadm5_get_policies(void *server_handle,
				  char *exp, char ***pols,
				  int *count);

#if USE_KADM5_API_VERSION > 1
kadm5_ret_t    kadm5_free_key_data(void *server_handle,
				   krb5_int16 *n_key_data,
				   krb5_key_data *key_data);
#endif

kadm5_ret_t    kadm5_free_name_list(void *server_handle, char **names,
				    int count);

krb5_error_code kadm5_init_krb5_context (krb5_context *);

#if USE_KADM5_API_VERSION == 1
/*
 * OVSEC_KADM_API_VERSION_1 should be, if possible, compile-time
 * compatible with KADM5_API_VERSION_2.  Basically, this means we have
 * to continue to provide all the old ovsec_kadm function and symbol
 * names.
 */

#define OVSEC_KADM_ACLFILE		"/krb5/ovsec_adm.acl"
#define	OVSEC_KADM_WORDFILE		"/krb5/ovsec_adm.dict"

#define OVSEC_KADM_ADMIN_SERVICE	"ovsec_adm/admin"
#define OVSEC_KADM_CHANGEPW_SERVICE	"ovsec_adm/changepw"
#define OVSEC_KADM_HIST_PRINCIPAL	"ovsec_adm/history"

typedef krb5_principal	ovsec_kadm_princ_t;
typedef krb5_keyblock	ovsec_kadm_keyblock;
typedef	char		*ovsec_kadm_policy_t;
typedef long		ovsec_kadm_ret_t;

enum	ovsec_kadm_salttype { OVSEC_KADM_SALT_V4, OVSEC_KADM_SALT_NORMAL };
enum	ovsec_kadm_saltmod  { OVSEC_KADM_MOD_KEEP, OVSEC_KADM_MOD_V4, OVSEC_KADM_MOD_NORMAL };

#define OVSEC_KADM_PW_FIRST_PROMPT \
	((char *) error_message(CHPASS_UTIL_NEW_PASSWORD_PROMPT))
#define OVSEC_KADM_PW_SECOND_PROMPT \
	((char *) error_message(CHPASS_UTIL_NEW_PASSWORD_AGAIN_PROMPT))

/*
 * Successful return code
 */
#define OVSEC_KADM_OK	0

/*
 * Create/Modify masks
 */
/* principal */
#define OVSEC_KADM_PRINCIPAL		0x000001
#define OVSEC_KADM_PRINC_EXPIRE_TIME	0x000002
#define OVSEC_KADM_PW_EXPIRATION	0x000004
#define OVSEC_KADM_LAST_PWD_CHANGE	0x000008
#define OVSEC_KADM_ATTRIBUTES		0x000010
#define OVSEC_KADM_MAX_LIFE		0x000020
#define OVSEC_KADM_MOD_TIME		0x000040
#define OVSEC_KADM_MOD_NAME		0x000080
#define OVSEC_KADM_KVNO			0x000100
#define OVSEC_KADM_MKVNO		0x000200
#define OVSEC_KADM_AUX_ATTRIBUTES	0x000400
#define OVSEC_KADM_POLICY		0x000800
#define OVSEC_KADM_POLICY_CLR		0x001000
/* policy */
#define OVSEC_KADM_PW_MAX_LIFE		0x004000
#define OVSEC_KADM_PW_MIN_LIFE		0x008000
#define OVSEC_KADM_PW_MIN_LENGTH	0x010000
#define OVSEC_KADM_PW_MIN_CLASSES	0x020000
#define OVSEC_KADM_PW_HISTORY_NUM	0x040000
#define OVSEC_KADM_REF_COUNT		0x080000

/*
 * permission bits
 */
#define OVSEC_KADM_PRIV_GET	0x01
#define OVSEC_KADM_PRIV_ADD	0x02
#define OVSEC_KADM_PRIV_MODIFY	0x04
#define OVSEC_KADM_PRIV_DELETE	0x08

/*
 * API versioning constants
 */
#define OVSEC_KADM_MASK_BITS		0xffffff00

#define OVSEC_KADM_STRUCT_VERSION_MASK	0x12345600
#define OVSEC_KADM_STRUCT_VERSION_1	(OVSEC_KADM_STRUCT_VERSION_MASK|0x01)
#define OVSEC_KADM_STRUCT_VERSION	OVSEC_KADM_STRUCT_VERSION_1

#define OVSEC_KADM_API_VERSION_MASK	0x12345700
#define OVSEC_KADM_API_VERSION_1	(OVSEC_KADM_API_VERSION_MASK|0x01)


typedef struct _ovsec_kadm_principal_ent_t {
	krb5_principal	principal;
	krb5_timestamp	princ_expire_time;
	krb5_timestamp	last_pwd_change;
	krb5_timestamp	pw_expiration;
	krb5_deltat	max_life;
	krb5_principal	mod_name;
	krb5_timestamp	mod_date;
	krb5_flags	attributes;
	krb5_kvno	kvno;
	krb5_kvno	mkvno;
	char		*policy;
	long		aux_attributes;
} ovsec_kadm_principal_ent_rec, *ovsec_kadm_principal_ent_t;

typedef struct _ovsec_kadm_policy_ent_t {
	char		*policy;
	long		pw_min_life;
	long		pw_max_life;
	long		pw_min_length;
	long		pw_min_classes;
	long		pw_history_num;
	long		policy_refcnt;
} ovsec_kadm_policy_ent_rec, *ovsec_kadm_policy_ent_t;

/*
 * functions
 */
ovsec_kadm_ret_t    ovsec_kadm_init(char *client_name, char *pass,
				    char *service_name, char *realm,
				    krb5_ui_4 struct_version,
				    krb5_ui_4 api_version,
				    char **db_args,
				    void **server_handle);
ovsec_kadm_ret_t    ovsec_kadm_init_with_password(char *client_name,
						  char *pass,
						  char *service_name,
						  char *realm,
						  krb5_ui_4 struct_version,
						  krb5_ui_4 api_version,
						  char ** db_args,
						  void **server_handle);
ovsec_kadm_ret_t    ovsec_kadm_init_with_skey(char *client_name,
					      char *keytab,
					      char *service_name,
					      char *realm,
					      krb5_ui_4 struct_version,
					      krb5_ui_4 api_version,
					      char **db_args,
					      void **server_handle);
ovsec_kadm_ret_t    ovsec_kadm_flush(void *server_handle);
ovsec_kadm_ret_t    ovsec_kadm_destroy(void *server_handle);
ovsec_kadm_ret_t    ovsec_kadm_create_principal(void *server_handle,
						ovsec_kadm_principal_ent_t ent,
						long mask, char *pass);
ovsec_kadm_ret_t    ovsec_kadm_delete_principal(void *server_handle,
						krb5_principal principal);
ovsec_kadm_ret_t    ovsec_kadm_modify_principal(void *server_handle,
						ovsec_kadm_principal_ent_t ent,
						long mask);
ovsec_kadm_ret_t    ovsec_kadm_rename_principal(void *server_handle,
						krb5_principal,krb5_principal);
ovsec_kadm_ret_t    ovsec_kadm_get_principal(void *server_handle,
					     krb5_principal principal,
					     ovsec_kadm_principal_ent_t *ent);
ovsec_kadm_ret_t    ovsec_kadm_chpass_principal(void *server_handle,
						krb5_principal principal,
						char *pass);
ovsec_kadm_ret_t    ovsec_kadm_randkey_principal(void *server_handle,
						 krb5_principal principal,
						 krb5_keyblock **keyblock);
ovsec_kadm_ret_t    ovsec_kadm_create_policy(void *server_handle,
					     ovsec_kadm_policy_ent_t ent,
					     long mask);
/*
 * ovsec_kadm_create_policy_internal is not part of the supported,
 * exposed API.  It is available only in the server library, and you
 * shouldn't use it unless you know why it's there and how it's
 * different from ovsec_kadm_create_policy.
 */
ovsec_kadm_ret_t    ovsec_kadm_create_policy_internal(void *server_handle,
						      ovsec_kadm_policy_ent_t
						      entry, long mask);
ovsec_kadm_ret_t    ovsec_kadm_delete_policy(void *server_handle,
					     ovsec_kadm_policy_t policy);
ovsec_kadm_ret_t    ovsec_kadm_modify_policy(void *server_handle,
					     ovsec_kadm_policy_ent_t ent,
					     long mask);
/*
 * ovsec_kadm_modify_policy_internal is not part of the supported,
 * exposed API.  It is available only in the server library, and you
 * shouldn't use it unless you know why it's there and how it's
 * different from ovsec_kadm_modify_policy.
 */
ovsec_kadm_ret_t    ovsec_kadm_modify_policy_internal(void *server_handle,
						      ovsec_kadm_policy_ent_t
						      entry, long mask);
ovsec_kadm_ret_t    ovsec_kadm_get_policy(void *server_handle,
					  ovsec_kadm_policy_t policy,
					  ovsec_kadm_policy_ent_t *ent);
ovsec_kadm_ret_t    ovsec_kadm_get_privs(void *server_handle,
					 long *privs);

ovsec_kadm_ret_t    ovsec_kadm_chpass_principal_util(void *server_handle,
						     krb5_principal princ,
						     char *new_pw,
						     char **ret_pw,
						     char *msg_ret);

ovsec_kadm_ret_t    ovsec_kadm_free_principal_ent(void *server_handle,
						  ovsec_kadm_principal_ent_t
						  ent);
ovsec_kadm_ret_t    ovsec_kadm_free_policy_ent(void *server_handle,
					       ovsec_kadm_policy_ent_t ent);

ovsec_kadm_ret_t ovsec_kadm_free_name_list(void *server_handle,
					   char **names, int count);

ovsec_kadm_ret_t    ovsec_kadm_get_principals(void *server_handle,
					      char *exp, char ***princs,
					      int *count);

ovsec_kadm_ret_t    ovsec_kadm_get_policies(void *server_handle,
					    char *exp, char ***pols,
					    int *count);

#define OVSEC_KADM_FAILURE KADM5_FAILURE
#define OVSEC_KADM_AUTH_GET KADM5_AUTH_GET
#define OVSEC_KADM_AUTH_ADD KADM5_AUTH_ADD
#define OVSEC_KADM_AUTH_MODIFY KADM5_AUTH_MODIFY
#define OVSEC_KADM_AUTH_DELETE KADM5_AUTH_DELETE
#define OVSEC_KADM_AUTH_INSUFFICIENT KADM5_AUTH_INSUFFICIENT
#define OVSEC_KADM_BAD_DB KADM5_BAD_DB
#define OVSEC_KADM_DUP KADM5_DUP
#define OVSEC_KADM_RPC_ERROR KADM5_RPC_ERROR
#define OVSEC_KADM_NO_SRV KADM5_NO_SRV
#define OVSEC_KADM_BAD_HIST_KEY KADM5_BAD_HIST_KEY
#define OVSEC_KADM_NOT_INIT KADM5_NOT_INIT
#define OVSEC_KADM_UNK_PRINC KADM5_UNK_PRINC
#define OVSEC_KADM_UNK_POLICY KADM5_UNK_POLICY
#define OVSEC_KADM_BAD_MASK KADM5_BAD_MASK
#define OVSEC_KADM_BAD_CLASS KADM5_BAD_CLASS
#define OVSEC_KADM_BAD_LENGTH KADM5_BAD_LENGTH
#define OVSEC_KADM_BAD_POLICY KADM5_BAD_POLICY
#define OVSEC_KADM_BAD_PRINCIPAL KADM5_BAD_PRINCIPAL
#define OVSEC_KADM_BAD_AUX_ATTR KADM5_BAD_AUX_ATTR
#define OVSEC_KADM_BAD_HISTORY KADM5_BAD_HISTORY
#define OVSEC_KADM_BAD_MIN_PASS_LIFE KADM5_BAD_MIN_PASS_LIFE
#define OVSEC_KADM_PASS_Q_TOOSHORT KADM5_PASS_Q_TOOSHORT
#define OVSEC_KADM_PASS_Q_CLASS KADM5_PASS_Q_CLASS
#define OVSEC_KADM_PASS_Q_DICT KADM5_PASS_Q_DICT
#define OVSEC_KADM_PASS_REUSE KADM5_PASS_REUSE
#define OVSEC_KADM_PASS_TOOSOON KADM5_PASS_TOOSOON
#define OVSEC_KADM_POLICY_REF KADM5_POLICY_REF
#define OVSEC_KADM_INIT KADM5_INIT
#define OVSEC_KADM_BAD_PASSWORD KADM5_BAD_PASSWORD
#define OVSEC_KADM_PROTECT_PRINCIPAL KADM5_PROTECT_PRINCIPAL
#define OVSEC_KADM_BAD_SERVER_HANDLE KADM5_BAD_SERVER_HANDLE
#define OVSEC_KADM_BAD_STRUCT_VERSION KADM5_BAD_STRUCT_VERSION
#define OVSEC_KADM_OLD_STRUCT_VERSION KADM5_OLD_STRUCT_VERSION
#define OVSEC_KADM_NEW_STRUCT_VERSION KADM5_NEW_STRUCT_VERSION
#define OVSEC_KADM_BAD_API_VERSION KADM5_BAD_API_VERSION
#define OVSEC_KADM_OLD_LIB_API_VERSION KADM5_OLD_LIB_API_VERSION
#define OVSEC_KADM_OLD_SERVER_API_VERSION KADM5_OLD_SERVER_API_VERSION
#define OVSEC_KADM_NEW_LIB_API_VERSION KADM5_NEW_LIB_API_VERSION
#define OVSEC_KADM_NEW_SERVER_API_VERSION KADM5_NEW_SERVER_API_VERSION
#define OVSEC_KADM_SECURE_PRINC_MISSING KADM5_SECURE_PRINC_MISSING
#define OVSEC_KADM_NO_RENAME_SALT KADM5_NO_RENAME_SALT

#endif /* USE_KADM5_API_VERSION == 1 */

#define MAXPRINCLEN 125

void trunc_name(size_t *len, char **dots);

krb5_chgpwd_prot _kadm5_get_kpasswd_protocol(void *server_handle);
kadm5_ret_t	kadm5_chpass_principal_v2(void *server_handle,
					krb5_principal princ,
					char *new_password,
					kadm5_ret_t *srvr_rsp_code,
					krb5_data *srvr_msg);

void handle_chpw(krb5_context context, int s, void *serverhandle,
			kadm5_config_params *params);

#ifdef __cplusplus
}
#endif

#endif	/* __KADM5_ADMIN_H__ */
