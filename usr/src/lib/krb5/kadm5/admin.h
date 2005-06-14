/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	__KADM5_ADMIN_H__
#define	__KADM5_ADMIN_H__

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved
 *
 * $Header: /cvs/krbdev/krb5/src/lib/kadm5/admin.h,v 1.43.2.1 2000/05/19 22:24:14 raeburn Exp $
 */

#include	<sys/types.h>
#include	<rpc/types.h>
#include	<rpc/rpc.h>
#include	<krb5.h>
#include	<k5-int.h>
#include	<com_err.h>
#include	<kadm5/kadm_err.h>
#include	<kadm5/adb_err.h>
#include	<kadm5/chpass_util_strings.h>

#define	KADM5_ADMIN_SERVICE_P	"kadmin@admin"
#define	KADM5_ADMIN_SERVICE	"kadmin/admin"
#define	KADM5_CHANGEPW_SERVICE_P	"kadmin@changepw"
#define	KADM5_CHANGEPW_SERVICE	"kadmin/changepw"
#define	KADM5_HIST_PRINCIPAL	"kadmin/history"
#define	KADM5_ADMIN_HOST_SERVICE "kadmin"
#define	KADM5_CHANGEPW_HOST_SERVICE "changepw"
#define	KADM5_KIPROP_HOST_SERVICE "kiprop"

typedef krb5_principal	kadm5_princ_t;
typedef	char		*kadm5_policy_t;
typedef long		kadm5_ret_t;
typedef int rpc_int32;
typedef unsigned int rpc_u_int32;

#define	KADM5_PW_FIRST_PROMPT \
	((char *)error_message(CHPASS_UTIL_NEW_PASSWORD_PROMPT))
#define	KADM5_PW_SECOND_PROMPT \
	((char *)error_message(CHPASS_UTIL_NEW_PASSWORD_AGAIN_PROMPT))

/*
 * Succsessfull return code
 */
#define	KADM5_OK	0

/*
 * Field masks
 */

/* kadm5_principal_ent_t */
#define	KADM5_PRINCIPAL		0x000001
#define	KADM5_PRINC_EXPIRE_TIME	0x000002
#define	KADM5_PW_EXPIRATION	0x000004
#define	KADM5_LAST_PWD_CHANGE	0x000008
#define	KADM5_ATTRIBUTES	0x000010
#define	KADM5_MAX_LIFE		0x000020
#define	KADM5_MOD_TIME		0x000040
#define	KADM5_MOD_NAME		0x000080
#define	KADM5_KVNO		0x000100
#define	KADM5_MKVNO		0x000200
#define	KADM5_AUX_ATTRIBUTES	0x000400
#define	KADM5_POLICY		0x000800
#define	KADM5_POLICY_CLR	0x001000
/* version 2 masks */
#define	KADM5_MAX_RLIFE		0x002000
#define	KADM5_LAST_SUCCESS	0x004000
#define	KADM5_LAST_FAILED	0x008000
#define	KADM5_FAIL_AUTH_COUNT	0x010000
#define	KADM5_KEY_DATA		0x020000
#define	KADM5_TL_DATA		0x040000
/* all but KEY_DATA and TL_DATA */
#define	KADM5_PRINCIPAL_NORMAL_MASK 0x01ffff

/* kadm5_policy_ent_t */
#define	KADM5_PW_MAX_LIFE	0x004000
#define	KADM5_PW_MIN_LIFE	0x008000
#define	KADM5_PW_MIN_LENGTH	0x010000
#define	KADM5_PW_MIN_CLASSES	0x020000
#define	KADM5_PW_HISTORY_NUM	0x040000
#define	KADM5_REF_COUNT		0x080000

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
#define	KADM5_PRIV_GET		0x01
#define	KADM5_PRIV_ADD		0x02
#define	KADM5_PRIV_MODIFY	0x04
#define	KADM5_PRIV_DELETE	0x08

/*
 * API versioning constants
 */
#define	KADM5_MASK_BITS		0xffffff00

#define	KADM5_STRUCT_VERSION_MASK	0x12345600
#define	KADM5_STRUCT_VERSION_1	(KADM5_STRUCT_VERSION_MASK|0x01)
#define	KADM5_STRUCT_VERSION	KADM5_STRUCT_VERSION_1

#define	KADM5_API_VERSION_MASK	0x12345700
#define	KADM5_API_VERSION_1	(KADM5_API_VERSION_MASK|0x01)
#define	KADM5_API_VERSION_2	(KADM5_API_VERSION_MASK|0x02)

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


typedef struct _kadm5_principal_ent_t_v2
kadm5_principal_ent_rec, *kadm5_principal_ent_t;

typedef struct _kadm5_policy_ent_t {
	char		*policy;
	long		pw_min_life;
	long		pw_max_life;
	long		pw_min_length;
	long		pw_min_classes;
	long		pw_history_num;
	long		policy_refcnt;
} kadm5_policy_ent_rec, *kadm5_policy_ent_t;

typedef struct __krb5_key_salt_tuple {
     krb5_enctype	ks_enctype;
     krb5_int32		ks_salttype;
} krb5_key_salt_tuple;

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
	char 		*realm;
	char 		*profile;
	int		kadmind_port;
	char 		*admin_server;
	char 		*dbname;
	char 		*admin_dbname;
	char 		*admin_lockfile;
	char 		*admin_keytab;
	char 		*acl_file;
	char 		*dict_file;
	int		mkey_from_kbd;
	char 		*stash_file;
	char 		*mkey_name;
	krb5_enctype	enctype;
	krb5_deltat	max_life;
	krb5_deltat	max_rlife;
	krb5_timestamp	expiration;
	krb5_flags		flags;
	krb5_key_salt_tuple 	*keysalts;
	krb5_int32		num_keysalts;
	char 			*kpasswd_server;
	int			kpasswd_port;
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
    char *realm_profile;
    char *realm_dbname;
    char *realm_mkey_name;
    char *realm_stash_file;
    char *realm_kdc_ports;
    char *realm_kdc_tcp_ports;
    char *realm_acl_file;
    krb5_int32		realm_kadmind_port;
    krb5_enctype	realm_enctype;
    krb5_deltat		realm_max_life;
    krb5_deltat		realm_max_rlife;
    krb5_timestamp	realm_expiration;
    krb5_flags		realm_flags;
    krb5_key_salt_tuple	*realm_keysalts;
    unsigned int	realm_kadmind_port_valid:1;
    unsigned int	realm_enctype_valid:1;
    unsigned int	realm_max_life_valid:1;
    unsigned int	realm_max_rlife_valid:1;
    unsigned int	realm_expiration_valid:1;
    unsigned int	realm_flags_valid:1;
    unsigned int	realm_filler:7;
    krb5_int32		realm_num_keysalts;
} krb5_realm_params;

/*
 * functions
 */


kadm5_ret_t
kadm5_get_master(krb5_context context, const char *realm, char **master);

kadm5_ret_t
kadm5_get_adm_host_srv_name(krb5_context context,
			    const char *realm, char **host_service_name);

kadm5_ret_t
kadm5_get_cpw_host_srv_name(krb5_context context,
			    const char *realm, char **host_service_name);

krb5_error_code kadm5_get_config_params(krb5_context context,
					char *kdcprofile, char *kdcenv,
					kadm5_config_params *params_in,
					kadm5_config_params *params_out);

/* SUNWresync121 XXX */
krb5_error_code kadm5_free_config_params(krb5_context context,
					kadm5_config_params *params);

krb5_error_code kadm5_free_realm_params(krb5_context kcontext,
					kadm5_config_params *params);

kadm5_ret_t    kadm5_init(char *client_name, char *pass,
			char *service_name,
			kadm5_config_params *params,
			krb5_ui_4 struct_version,
			krb5_ui_4 api_version,
			void **server_handle);

kadm5_ret_t    kadm5_init_with_password(char *client_name,
					char *pass, 
					char *service_name,
					kadm5_config_params *params,
					krb5_ui_4 struct_version,
					krb5_ui_4 api_version,
					void **server_handle);
kadm5_ret_t    kadm5_init_with_skey(char *client_name,
				    char *keytab,
				    char *service_name,
				    kadm5_config_params *params,
				    krb5_ui_4 struct_version,
				    krb5_ui_4 api_version,
				    void **server_handle);

kadm5_ret_t    kadm5_init_with_creds(char *client_name,
				     krb5_ccache cc,
				     char *service_name,
				     kadm5_config_params *params,
				     krb5_ui_4 struct_version,
				     krb5_ui_4 api_version,
				     void **server_handle);
kadm5_ret_t    kadm5_flush(void *server_handle);
kadm5_ret_t    kadm5_destroy(void *server_handle);
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
				    krb5_principal, krb5_principal);

kadm5_ret_t    kadm5_get_principal(void *server_handle,
				krb5_principal principal,
				kadm5_principal_ent_t ent,
				long mask);

kadm5_ret_t    kadm5_chpass_principal(void *server_handle,
				      krb5_principal principal,
				      char *pass);
kadm5_ret_t    kadm5_chpass_principal_3(void *server_handle,
					krb5_principal principal,
					krb5_boolean keepold,
					int n_ks_tuple,
					krb5_key_salt_tuple *ks_tuple,
					char *pass);

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

kadm5_ret_t    kadm5_get_policy(void *server_handle,
				kadm5_policy_t policy,
				kadm5_policy_ent_t ent);

kadm5_ret_t    kadm5_get_privs(void *server_handle,
			    long *privs);

kadm5_ret_t    kadm5_chpass_principal_util(void *server_handle,
					   krb5_principal princ,
					   char *new_pw, 
					   char **ret_pw,
					   char *msg_ret,
					   int msg_len);

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


kadm5_ret_t    kadm5_free_key_data(void *server_handle,
				   krb5_int16 *n_key_data,
				   krb5_key_data *key_data);

kadm5_ret_t kadm5_free_name_list(void *server_handle,
				char **names, int count);


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
