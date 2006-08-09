#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/krb5/kadm5/srv/spec/kadm5srv.spec
#
# Interface definition for libkadm5srv.so.1
#

function	__kadm5_get_priv
declaration	kadm5_ret_t __kadm5_get_priv(void *server_handle, long *privs, gss_name_t client)
version		SUNWprivate_1.1
end

function	acl_check
include		<gssapi_krb5.h>, "server_acl.h"
declaration	krb5_boolean acl_check(krb5_context kcontext, gss_name_t caller, krb5_int32 opmask, krb5_principal principal, restriction_t **restriction)
version		SUNWprivate_1.1
end

function	 acl_finish
include		"k5-int.h", "server_acl.h"
declaration	void acl_finish(krb5_context kcontext, int debug_level)
version		SUNWprivate_1.1
end

function	acl_init
include		"k5-int.h", "server_acl.h"
declaration	krb5_error_code acl_init(krb5_context kcontext, int debug_level, char *acl_file)
version		SUNWprivate_1.1
end

function	adb_policy_close
include		"k5-int.h", "adb.h"
declaration	kadm5_ret_t adb_policy_close(kadm5_server_handle_t handle)
version		SUNWprivate_1.1
end

function	adb_policy_init
include		"k5-int.h", "adb.h"
declaration	kadm5_ret_t adb_policy_init(kadm5_server_handle_t handle)
version		SUNWprivate_1.1
end

function	destroy_dict
declaration	void destroy_dict(void)
version		SUNWprivate_1.1
end

function	find_word
declaration	int find_word(const char *word)
version		SUNWprivate_1.1
end

function	free_history_entry
include		"k5-int.h", "adb.h"
declaration	void free_history_entry(krb5_context context, osa_pw_hist_ent *hist)
version		SUNWprivate_1.1
end

function	get_either_iter
declaration	void get_either_iter(void *data, char *name)
version		SUNWprivate_1.1
end

function	get_pols_iter
include		"adb.h", "server_internal.h"
declaration	void get_pols_iter(void *data, osa_policy_ent_t entry)
version		SUNWprivate_1.1
end

function	get_princs_iter
include		"k5-int.h", "adb.h"
declaration	void get_princs_iter(void *data, krb5_principal princ)
version		SUNWprivate_1.1
end

function	glob_to_regexp
declaration	kadm5_ret_t glob_to_regexp(char *glob, char *realm, char **regexp)
version		SUNWprivate_1.1
end

function	handle_chpw
declaration	void handle_chpw(krb5_context context, int s, void *serverhandle, kadm5_config_params *params)
version		SUNWprivate_1.1
end

data		hist_db
include		"k5-int.h", "adb.h"
declaration	krb5_db_entry hist_db
version		SUNWprivate_1.1
end

data		hist_encblock
include		"k5-int.h", "adb.h"
declaration	krb5_encrypt_block hist_encblock
version		SUNWprivate_1.1
end

data		hist_key
include		"k5-int.h", "adb.h"
declaration	krb5_keyblock hist_key
version		SUNWprivate_1.1
end

data		hist_kvno
include		"k5-int.h", "adb.h"
declaration	krb5_kvno hist_kvno
version		SUNWprivate_1.1
end

data		hist_princ
include		"k5-int.h", "adb.h"
declaration	krb5_principal hist_princ
version		SUNWprivate_1.1
end

function	krb5_klog_close 
include		"k5-int.h"
declaration	void krb5_klog_close(krb5_context kcontext)
version		SUNWprivate_1.1
end

function	krb5_klog_init 
include		"k5-int.h"
declaration	krb5_error_code krb5_klog_init(krb5_context kcontext, char *ename, char *whoami, krb5_boolean do_com_err)
version		SUNWprivate_1.1
end

function	krb5_klog_syslog 
declaration	int krb5_klog_syslog(int priority, const char *format, int val)
version		SUNWprivate_1.1
end

function	krb5_klog_reopen 
declaration	void krb5_klog_reopen(krb5_context kcontext)
version		SUNWprivate_1.1
end

function	init_dict
include		"k5-int.h", "adb.h"
declaration	int init_dict(kadm5_config_params *params)
version		SUNWprivate_1.1
end

function	kadm5_get_master
include		"k5-int.h", "adb.h"
declaration	kadm5_ret_t kadm5_get_master(krb5_context context, const char *realm, char **master)
version		SUNWprivate_1.1
end

function	kadm5_get_adm_host_srv_name
include		"admin.h"
declaration	kadm5_ret_t kadm5_get_adm_host_srv_name(krb5_context context, const char *realm, char **host_service_name)
version		SUNWprivate_1.1
end

function	kadm5_get_cpw_host_srv_name
include		"admin.h"
declaration	kadm5_ret_t kadm5_get_cpw_host_srv_name(krb5_context context, const char *realm, char **host_service_name)
version		SUNWprivate_1.1
end

function	kadm5_get_kiprop_host_srv_name
include		"admin.h"
declaration	kadm5_ret_t kadm5_get_kiprop_host_srv_name(krb5_context context, const char *realm, char **host_service_name)
version		SUNWprivate_1.1
end

function	kadm5_chpass_principal
include		"server_internal.h"
declaration	kadm5_ret_t kadm5_chpass_principal(void *server_handle, krb5_principal principal, char *passwd)
version		SUNWprivate_1.1
end

function        kadm5_chpass_principal_v2
include         "server_internal.h"
declaration     kadm5_ret_t kadm5_chpass_principal_v2(void *server_handle, krb5_principal principal, char *passwd, kadm5_ret_t *srvr_rsp_code, krb5_data *srvr_msg)
version         SUNWprivate_1.1
end

function	_kadm5_get_kpasswd_protocol
include		"server_internal.h"
declaration	krb5_chgpwd_prot _kadm5_get_kpasswd_protocol(void *handle)
version		SUNWprivate_1.1
end

function	kadm5_chpass_principal_util
include		"server_internal.h"
declaration	kadm5_ret_t kadm5_chpass_principal_util(void *server_handle, krb5_principal princ, char *new_pw, char **ret_pw, char *msg_ret, int msg_len)
version		SUNWprivate_1.1
end

function	kadm5_create_policy
include		"adb.h", "server_internal.h"
declaration	kadm5_ret_t kadm5_create_policy(void *server_handle, kadm5_policy_ent_t entry, long mask)
version		SUNWprivate_1.1
end

function	kadm5_create_policy_internal
include		"adb.h", "server_internal.h"
declaration	kadm5_ret_t kadm5_create_policy_internal(void *server_handle, kadm5_policy_ent_t entry, long mask)
version		SUNWprivate_1.1
end

function	kadm5_create_principal
include		"adb.h", "k5-int.h", "server_internal.h"
declaration	kadm5_ret_t kadm5_create_principal(void *server_handle, kadm5_principal_ent_t entry, long mask, char *password)
version		SUNWprivate_1.1
end

function	kadm5_decrypt_key
include		"adb.h", "k5-int.h", "server_internal.h"
declaration	kadm5_ret_t kadm5_decrypt_key(void *server_handle, kadm5_principal_ent_t entry, krb5_int32 ktype, krb5_int32 stype, krb5_int32 kvno, krb5_keyblock *keyblock, krb5_keysalt *keysalt, int *kvnop)
version		SUNWprivate_1.1
end

function	kadm5_delete_policy
include		"adb.h", "server_internal.h"
declaration	kadm5_ret_t kadm5_delete_policy(void *server_handle, kadm5_policy_t name)
version		SUNWprivate_1.1
end

function	kadm5_delete_principal
include		"adb.h", "k5-int.h", "server_internal.h"
declaration	kadm5_ret_t kadm5_delete_principal(void *server_handle, krb5_principal principal)
version		SUNWprivate_1.1
end

function	kadm5_destroy
declaration	kadm5_ret_t kadm5_destroy(void *server_handle)
version		SUNWprivate_1.1
end

function	kadm5_flush
declaration	kadm5_ret_t kadm5_flush(void *server_handle)
version		SUNWprivate_1.1
end

function	kadm5_free_config_params
declaration	krb5_error_code kadm5_free_config_params(krb5_context context, kadm5_config_params *params)
version		SUNWprivate_1.1
end

function	kadm5_free_name_list
include		"server_internal.h"
declaration	kadm5_ret_t kadm5_free_name_list(void *server_handle, char **names, int count)
version		SUNWprivate_1.1
end

function	kadm5_free_policy_ent
include		"server_internal.h"
declaration	kadm5_ret_t kadm5_free_policy_ent(void *server_handle, kadm5_policy_ent_t val)
version		SUNWprivate_1.1
end

function	kadm5_free_principal_ent
include		"server_internal.h"
declaration	kadm5_ret_t kadm5_free_principal_ent(void *server_handle, kadm5_principal_ent_t val)
version		SUNWprivate_1.1
end

function	kadm5_get_config_params
include		"k5-int.h"
declaration	krb5_error_code kadm5_get_config_params(krb5_context context, char *kdcprofile, char *kdcenv, kadm5_config_params  *params_in, kadm5_config_params *params_out)
version		SUNWprivate_1.1
end

function	kadm5_get_either
include		"adb.h", "server_internal.h"
declaration	kadm5_ret_t kadm5_get_either(int princ, void *server_handle, char *exp, char ***princs, int *count)
version		SUNWprivate_1.1
end

function	kadm5_get_policies
include		"adb.h", "server_internal.h"
declaration	kadm5_ret_t kadm5_get_policies(void *server_handle, char *exp, char ***pols, int *count)
version		SUNWprivate_1.1
end

function	kadm5_get_policy
include		"adb.h", "server_internal.h"
declaration	kadm5_ret_t kadm5_get_policy(void *server_handle, kadm5_policy_t name, kadm5_policy_ent_t entry)
version		SUNWprivate_1.1
end

function	kadm5_get_principal
include		"adb.h", "k5-int.h", "server_internal.h"
declaration	kadm5_ret_t kadm5_get_principal(void *server_handle, krb5_principal principal, kadm5_principal_ent_t entry, long in_mask)
version		SUNWprivate_1.1
end

function	kadm5_get_principals
include		"adb.h", "server_internal.h"
declaration	kadm5_ret_t kadm5_get_principals(void *server_handle, char *exp, char ***princs, int *count)
version		SUNWprivate_1.1
end

function	kadm5_init
include		"server_internal.h"
declaration	kadm5_ret_t kadm5_init(char *client_name, char *pass, char *service_name, kadm5_config_params *params_in, krb5_ui_4 struct_version, krb5_ui_4 api_version, void **server_handle)
version		SUNWprivate_1.1
end

function	kadm5_init_with_creds
include		"server_internal.h"
declaration	kadm5_ret_t kadm5_init_with_creds(char *client_name, krb5_ccache ccache, char *service_name, kadm5_config_params *params, krb5_ui_4 struct_version, krb5_ui_4 api_version, void **server_handle)
version		SUNWprivate_1.1
end

function	kadm5_init_with_password
include		"server_internal.h"
declaration	kadm5_ret_t kadm5_init_with_password(char *client_name, char *pass, char *service_name, kadm5_config_params *params, krb5_ui_4 struct_version, krb5_ui_4 api_version, void **server_handle)
version		SUNWprivate_1.1
end

function	kadm5_init_with_skey
include		"server_internal.h"
declaration	kadm5_ret_t kadm5_init_with_skey(char *client_name, char *keytab, char *service_name, kadm5_config_params *params, krb5_ui_4 struct_version, krb5_ui_4 api_version, void **server_handle)
version		SUNWprivate_1.1
end

function	kadm5_modify_policy
include		"adb.h", "server_internal.h"
declaration	kadm5_ret_t kadm5_modify_policy(void *server_handle, kadm5_policy_ent_t entry, long mask)
version		SUNWprivate_1.1
end

function	kadm5_modify_policy_internal
include		"adb.h", "server_internal.h"
declaration	kadm5_ret_t kadm5_modify_policy_internal(void *server_handle, kadm5_policy_ent_t entry, long mask)
version		SUNWprivate_1.1
end

function	kadm5_modify_principal
include		"adb.h", "k5-int.h", "server_internal.h"
declaration	kadm5_ret_t kadm5_modify_principal(void *server_handle, kadm5_principal_ent_t entry, long mask)
version		SUNWprivate_1.1
end

function	kadm5_randkey_principal
include		"adb.h", "k5-int.h", "server_internal.h"
declaration	kadm5_ret_t kadm5_randkey_principal(void *server_handle, krb5_principal principal, krb5_keyblock **keyblocks, int *n_keys)
version		SUNWprivate_1.1
end

function	kadm5_rename_principal
include		"adb.h", "k5-int.h", "server_internal.h"
declaration	kadm5_ret_t kadm5_rename_principal(void *server_handle, krb5_principal source, krb5_principal target)
version		SUNWprivate_1.1
end

function	kdb_delete_entry
declaration	krb5_error_code kdb_delete_entry(kadm5_server_handle_t handle, krb5_principal name)
version		SUNWprivate_1.1
end

function	kdb_free_entry
include		"k5-int.h", "server_internal.h"
declaration	krb5_error_code kdb_free_entry(kadm5_server_handle_t handle, krb5_db_entry *kdb, osa_princ_ent_rec *adb)
version		SUNWprivate_1.1
end

function	kdb_get_entry
include		"k5-int.h", "server_internal.h"
declaration	krb5_error_code kdb_get_entry(kadm5_server_handle_t handle, krb5_principal principal, krb5_db_entry *kdb, osa_princ_ent_rec *adb)
version		SUNWprivate_1.1
end

function	kdb_init_hist
include		"k5-int.h", "server_internal.h"
declaration	krb5_error_code kdb_init_hist(kadm5_server_handle_t handle, char *r)
version		SUNWprivate_1.1
end

function	kdb_init_master
include		"k5-int.h", "server_internal.h"
declaration	krb5_error_code kdb_init_master(kadm5_server_handle_t handle, char *r, int from_keyboard)
version		SUNWprivate_1.1
end

function	kdb_iter_entry
include		"k5-int.h", "server_internal.h"
declaration	krb5_error_code kdb_iter_entry(kadm5_server_handle_t handle, void (*iter_fct)(void *, krb5_principal), void *data)
version		SUNWprivate_1.1
end

function	kdb_put_entry
include		"k5-int.h", "server_internal.h"
declaration	krb5_error_code kdb_put_entry(kadm5_server_handle_t handle, krb5_db_entry *kdb, osa_princ_ent_rec *adb)
version		SUNWprivate_1.1
end

function	krb5_aprof_finish
include		"k5-int.h"
declaration	krb5_error_code krb5_aprof_finish(krb5_pointer acontext)
version		SUNWprivate_1.1
end

function	krb5_aprof_get_deltat
include		"k5-int.h"
declaration	krb5_error_code krb5_aprof_get_deltat(krb5_pointer acontext, const char **hierarchy, krb5_boolean uselast, krb5_deltat *deltatp)
version		SUNWprivate_1.1
end

function	krb5_aprof_get_int32
include		"k5-int.h"
declaration	krb5_error_code krb5_aprof_get_int32(krb5_pointer acontext, const char **hierarchy, krb5_boolean uselast, krb5_int32 *intp)
version		SUNWprivate_1.1
end

function	krb5_aprof_get_string
include		"k5-int.h"
declaration	krb5_error_code krb5_aprof_get_string(krb5_pointer acontext, const char **hierarchy, krb5_boolean uselast, char **stringp)
version		SUNWprivate_1.1
end

function	krb5_aprof_getvals
include		"k5-int.h"
declaration	krb5_error_code krb5_aprof_getvals(krb5_pointer acontext, const char **hierarchy, char ***retdata)
version		SUNWprivate_1.1
end

function	krb5_aprof_init
include		"k5-int.h"
declaration	krb5_error_code krb5_aprof_init(char *fname, char *envname, krb5_pointer *acontextp)
version		SUNWprivate_1.1
end

function	krb5_copy_key_data_contents
include		"adb.h", "k5-int.h", "server_internal.h"
declaration	kadm5_ret_t krb5_copy_key_data_contents(krb5_context context, krb5_key_data *from, krb5_key_data *to)
version		SUNWprivate_1.1
end

function	krb5_flags_to_string
include		"k5-int.h", "admin_internal.h"
declaration	krb5_error_code krb5_flags_to_string(krb5_flags flags, const char * sep, char * buffer, size_t buflen)
version		SUNWprivate_1.1
end

function	krb5_free_key_data_contents
include		"adb.h", "k5-int.h", "server_internal.h"
declaration	kadm5_ret_t krb5_free_key_data_contents(krb5_context context, krb5_key_data *key)
version		SUNWprivate_1.1
end

function	krb5_free_realm_params
include		"k5-int.h"
declaration	krb5_error_code krb5_free_realm_params(krb5_context kcontext, krb5_realm_params *rparams)
version		SUNWprivate_1.1
end

function	krb5_input_flag_to_string
include		"k5-int.h", "admin_internal.h"
declaration	krb5_error_code krb5_input_flag_to_string(int flag, char * buffer, size_t buflen)
version		SUNWprivate_1.1
end

function	krb5_keysalt_is_present
include		"k5-int.h", "admin_internal.h"
declaration	krb5_boolean krb5_keysalt_is_present(krb5_key_salt_tuple *ksaltlist, krb5_int32 nksalts, krb5_enctype enctype, krb5_int32 salttype)
version		SUNWprivate_1.1
end

function	krb5_keysalt_iterate
# declaration	krb5_error_code krb5_keysalt_iterate(krb5_key_salt_tuple *ksaltlist, krb5_int32 nksalt, krb5_boolean ignoresalt, krb5_error_code (*iterator) KRB5_NPROTOTYPE((krb5_key_salt_tuple *, krb5_pointer)), krb5_pointer arg)
declaration	krb5_error_code krb5_keysalt_iterate(krb5_key_salt_tuple *ksaltlist, krb5_int32 nksalt, krb5_boolean ignoresalt, krb5_error_code *iterator, krb5_pointer arg)
version		SUNWprivate_1.1
end

function	krb5_read_realm_params
include		"k5-int.h"
declaration	krb5_error_code krb5_read_realm_params(krb5_context kcontext, char *realm, char *kdcprofile, char *kdcenv, krb5_realm_params**rparamp)
version		SUNWprivate_1.1
end

function	krb5_string_to_flags
include		"k5-int.h", "admin_internal.h"
declaration	krb5_error_code krb5_string_to_flags(char * string, const char  * positive, const char * negative, krb5_flags * flagsp)
version		SUNWprivate_1.1
end

function	krb5_string_to_keysalts
include		"k5-int.h", "admin_internal.h"
declaration	krb5_error_code krb5_string_to_keysalts(char *string, const char *tupleseps, const char *ksaltseps, krb5_boolean dups, krb5_key_salt_tuple **ksaltp, krb5_int32 *nksaltp)
version		SUNWprivate_1.1
end

data		master_db
declaration	krb5_db_entry master_db
version		SUNWprivate_1.1
end

data		master_princ
declaration	krb5_principal master_princ
version		SUNWprivate_1.1
end

function	osa_adb_close_and_unlock
declaration	osa_adb_ret_t osa_adb_close_and_unlock(osa_adb_princ_t db)
version		SUNWprivate_1.1
end

function	osa_adb_close_policy
declaration	osa_adb_ret_t osa_adb_close_policy(osa_adb_princ_t db)
version		SUNWprivate_1.1
end

function	osa_adb_create_db
include		"adb.h"
declaration	osa_adb_ret_t osa_adb_create_db(char *filename, char *lockfilename, int magic)
version		SUNWprivate_1.1
end

function	osa_adb_create_policy
include		"adb.h"
declaration	osa_adb_ret_t osa_adb_create_policy(osa_adb_policy_t db, osa_policy_ent_t entry)
version		SUNWprivate_1.1
end

function	osa_adb_create_policy_db
include		"adb.h"
declaration	osa_adb_ret_t osa_adb_create_policy_db(kadm5_config_params *params)
version		SUNWprivate_1.1
end

function	osa_adb_destroy_db
include		"adb.h"
declaration	osa_adb_ret_t osa_adb_destroy_db(char *filename, char *lockfilename, int magic)
version		SUNWprivate_1.1
end

function	osa_adb_destroy_policy
include		"adb.h"
declaration	osa_adb_ret_t osa_adb_destroy_policy(osa_adb_policy_t db, kadm5_policy_t name)
version		SUNWprivate_1.1
end

function	osa_adb_destroy_policy_db
include		"adb.h"
declaration	osa_adb_ret_t osa_adb_destroy_policy_db(kadm5_config_params *params)
version		SUNWprivate_1.1
end

function	osa_adb_fini_db
include		"adb.h"
declaration	osa_adb_ret_t osa_adb_fini_db(osa_adb_db_t db, int magic)
version		SUNWprivate_1.1
end

function	osa_adb_get_lock
include		"adb.h"
declaration	osa_adb_ret_t osa_adb_get_lock(osa_adb_db_t db, int mode)
version		SUNWprivate_1.1
end

function	osa_adb_get_policy
include		"adb.h"
declaration	osa_adb_ret_t osa_adb_get_policy(osa_adb_policy_t db, kadm5_policy_t name, osa_policy_ent_t *entry)
version		SUNWprivate_1.1
end

function	osa_adb_init_db
declaration	osa_adb_ret_t osa_adb_init_db(osa_adb_db_t *dbp, char *filename, char *lockfilename, int magic)
version		SUNWprivate_1.1
end

function	osa_adb_iter_policy
include		"adb.h"
declaration	osa_adb_ret_t osa_adb_iter_policy(osa_adb_policy_t db, osa_adb_iter_policy_func func, void *data)
version		SUNWprivate_1.1
end

function	osa_adb_open_and_lock
include		"adb.h"
declaration	osa_adb_ret_t osa_adb_open_and_lock(osa_adb_princ_t db, int locktype)
version		SUNWprivate_1.1
end

function	osa_adb_open_policy
include		"adb.h"
declaration	osa_adb_ret_t osa_adb_open_policy(osa_adb_princ_t *dbp, kadm5_config_params *rparams)
version		SUNWprivate_1.1
end

function	osa_adb_put_policy
include		"adb.h"
declaration	osa_adb_ret_t osa_adb_put_policy(osa_adb_policy_t db, osa_policy_ent_t entry)
version		SUNWprivate_1.1
end

function	osa_adb_release_lock
include		"adb.h"
declaration	osa_adb_ret_t osa_adb_release_lock(osa_adb_db_t db)
version		SUNWprivate_1.1
end

function	osa_adb_rename_db
include		"adb.h"
declaration	osa_adb_ret_t osa_adb_rename_db(char *filefrom, char *lockfrom, char *fileto, char *lockto, int magic)
version		SUNWprivate_1.1
end

function	osa_adb_rename_policy_db
include		"adb.h"
declaration	osa_adb_ret_t osa_adb_rename_policy_db(kadm5_config_params *fromparams, kadm5_config_params *toparams)
version		SUNWprivate_1.1
end

function	osa_free_policy_ent
include		"adb.h"
declaration	void osa_free_policy_ent(osa_policy_ent_t val)
version		SUNWprivate_1.1
end

function	osa_free_princ_ent
include		"adb.h"
declaration	void osa_free_princ_ent(osa_princ_ent_t val)
version		SUNWprivate_1.1
end

function	passwd_check
include		"k5-int.h"
declaration	kadm5_ret_t passwd_check(kadm5_server_handle_t handle, char *password, int use_policy, kadm5_policy_ent_t pol, krb5_principal principal)
version		SUNWprivate_1.1
end

function	xdr_chpass_arg
include		"k5-int.h"
declaration	bool_t xdr_chpass_arg(XDR *xdrs, chpass_arg *objp)
version		SUNWprivate_1.1
end

function	xdr_chrand_arg
include		"k5-int.h"
declaration	bool_t xdr_chrand_arg(XDR *xdrs, chrand_arg *objp)
version		SUNWprivate_1.1
end

function	xdr_chrand_ret
include		"k5-int.h"
declaration	bool_t xdr_chrand_ret(XDR *xdrs, chrand_ret *objp)
version		SUNWprivate_1.1
end

function	xdr_cpol_arg
include		"k5-int.h"
declaration	bool_t xdr_cpol_arg(XDR *xdrs, cpol_arg *objp)
version		SUNWprivate_1.1
end

function	xdr_cprinc_arg
include		"k5-int.h"
declaration	bool_t xdr_cprinc_arg(XDR *xdrs, cprinc_arg *objp)
version		SUNWprivate_1.1
end

function	xdr_dpol_arg
include		"k5-int.h"
declaration	bool_t xdr_dpol_arg(XDR *xdrs, dpol_arg *objp)
version		SUNWprivate_1.1
end

function	xdr_dprinc_arg
include		"k5-int.h"
declaration	bool_t xdr_dprinc_arg(XDR *xdrs, dprinc_arg *objp)
version		SUNWprivate_1.1
end

function	xdr_generic_ret
include		"k5-int.h"
declaration	bool_t xdr_generic_ret(XDR *xdrs, generic_ret *objp)
version		SUNWprivate_1.1
end

function	xdr_getprivs_ret
include		"k5-int.h"
declaration	bool_t xdr_getprivs_ret(XDR *xdrs, getprivs_ret *objp)
version		SUNWprivate_1.1
end

function	xdr_gpol_arg
include		"k5-int.h"
declaration	bool_t xdr_gpol_arg(XDR *xdrs, gpol_arg *objp)
version		SUNWprivate_1.1
end

function	xdr_gpol_ret
include		"k5-int.h"
declaration	bool_t xdr_gpol_ret(XDR *xdrs, gpol_ret *objp)
version		SUNWprivate_1.1
end

function	xdr_gpols_arg
include		"k5-int.h"
declaration	bool_t xdr_gpols_arg(XDR *xdrs, gpols_arg *objp)
version		SUNWprivate_1.1
end

function	xdr_gpols_ret
include		"k5-int.h"
declaration	bool_t xdr_gpols_ret(XDR *xdrs, gpols_ret *objp)
version		SUNWprivate_1.1
end

function	xdr_gprinc_arg
include		"k5-int.h"
declaration	bool_t xdr_gprinc_arg(XDR *xdrs, gprinc_arg *objp)
version		SUNWprivate_1.1
end

function	xdr_gprinc_ret
include		"k5-int.h"
declaration	bool_t xdr_gprinc_ret(XDR *xdrs, gprinc_ret *objp)
version		SUNWprivate_1.1
end

function	xdr_gprincs_arg
include		"k5-int.h"
declaration	bool_t xdr_gprincs_arg(XDR *xdrs, gprincs_arg *objp)
version		SUNWprivate_1.1
end

function	xdr_gprincs_ret
include		"k5-int.h"
declaration	bool_t xdr_gprincs_ret(XDR *xdrs, gprincs_ret *objp)
version		SUNWprivate_1.1
end

function	xdr_kadm5_policy_ent_rec
include		"k5-int.h"
declaration	bool_t xdr_kadm5_policy_ent_rec(XDR *xdrs, kadm5_policy_ent_rec *objp)
version		SUNWprivate_1.1
end

function	xdr_kadm5_principal_ent_rec
include		"k5-int.h"
declaration	bool_t xdr_kadm5_principal_ent_rec(XDR *xdrs, kadm5_principal_ent_rec *objp)
version		SUNWprivate_1.1
end

function	xdr_kadm5_principal_ent_rec_v1
include		"k5-int.h"
declaration	bool_t xdr_kadm5_principal_ent_rec_v1(XDR *xdrs, kadm5_principal_ent_rec *objp)
version		SUNWprivate_1.1
end

function	xdr_kadm5_ret_t
include		"k5-int.h"
declaration	bool_t xdr_kadm5_ret_t(XDR *xdrs, kadm5_ret_t *objp)
version		SUNWprivate_1.1
end

function	xdr_krb5_deltat
include		"k5-int.h"
declaration	bool_t xdr_krb5_deltat(XDR *xdrs, krb5_deltat *objp)
version		SUNWprivate_1.1
end

function	xdr_krb5_enctype
include		"k5-int.h"
declaration	bool_t xdr_krb5_enctype(XDR *xdrs, krb5_enctype *objp)
version		SUNWprivate_1.1
end

function	xdr_krb5_flags
include		"k5-int.h"
declaration	bool_t xdr_krb5_flags(XDR *xdrs, krb5_flags *objp)
version		SUNWprivate_1.1
end

function	xdr_krb5_int16
include		"k5-int.h"
declaration	bool_t xdr_krb5_int16(XDR *xdrs, krb5_int16 *objp)
version		SUNWprivate_1.1
end

function	xdr_krb5_key_data
include		"k5-int.h"
declaration	bool_t xdr_krb5_key_data(XDR *xdrs, krb5_key_data *objp)
version		SUNWprivate_1.1
end

function	xdr_krb5_key_data_nocontents
include		"k5-int.h"
declaration	bool_t xdr_krb5_key_data_nocontents(XDR *xdrs, krb5_key_data *objp)
version		SUNWprivate_1.1
end

function	xdr_krb5_keyblock
include		"k5-int.h"
declaration	bool_t xdr_krb5_keyblock(XDR *xdrs, krb5_keyblock *objp)
version		SUNWprivate_1.1
end

function	xdr_krb5_kvno
include		"k5-int.h"
declaration	bool_t xdr_krb5_kvno(XDR *xdrs, krb5_kvno *objp)
version		SUNWprivate_1.1
end

function	xdr_krb5_octet
include		"k5-int.h"
declaration	bool_t xdr_krb5_octet(XDR *xdrs, krb5_octet *objp)
version		SUNWprivate_1.1
end

function	xdr_krb5_principal
include		"k5-int.h"
declaration	bool_t xdr_krb5_principal(XDR *xdrs, krb5_principal *objp)
version		SUNWprivate_1.1
end

function	xdr_krb5_timestamp
include		"k5-int.h"
declaration	bool_t xdr_krb5_timestamp(XDR *xdrs, krb5_timestamp *objp)
version		SUNWprivate_1.1
end

function	xdr_krb5_tl_data
include		"k5-int.h"
declaration	bool_t xdr_krb5_tl_data(XDR *xdrs, krb5_tl_data **tl_data_head)
version		SUNWprivate_1.1
end

function	xdr_krb5_ui_4
include		"k5-int.h"
declaration	bool_t xdr_krb5_ui_4(XDR *xdrs, krb5_ui_4 *objp)
version		SUNWprivate_1.1
end

function	xdr_mpol_arg
include		"k5-int.h"
declaration	bool_t xdr_mpol_arg(XDR *xdrs, mpol_arg *objp)
version		SUNWprivate_1.1
end

function	xdr_mprinc_arg
include		"k5-int.h"
declaration	bool_t xdr_mprinc_arg(XDR *xdrs, mprinc_arg *objp)
version		SUNWprivate_1.1
end

function	xdr_nullstring
include		"k5-int.h"
declaration	bool_t xdr_nullstring(XDR *xdrs, char **objp)
version		SUNWprivate_1.1
end

function	xdr_nulltype
include		"k5-int.h"
declaration	bool_t xdr_nulltype(XDR *xdrs, void **objp, xdrproc_t proc)
version		SUNWprivate_1.1
end

function	xdr_osa_policy_ent_rec
include		"adb.h", "admin_xdr.h"
declaration	bool_t xdr_osa_policy_ent_rec(XDR *xdrs, osa_policy_ent_t objp)
version		SUNWprivate_1.1
end

function	xdr_osa_princ_ent_rec
include		"k5-int.h"
declaration	bool_t xdr_osa_princ_ent_rec(XDR *xdrs, osa_princ_ent_t objp)
version		SUNWprivate_1.1
end

function	xdr_osa_pw_hist_ent
include		"k5-int.h"
declaration	bool_t xdr_osa_pw_hist_ent(XDR *xdrs, osa_pw_hist_ent *objp)
version		SUNWprivate_1.1
end

function	xdr_rprinc_arg
include		"k5-int.h"
declaration	bool_t xdr_rprinc_arg(XDR *xdrs, rprinc_arg *objp)
version		SUNWprivate_1.1
end

function	xdr_ui_4
include		"k5-int.h"
declaration	bool_t xdr_ui_4(XDR *xdrs, krb5_ui_4 *objp)
version		SUNWprivate_1.1
end

function	xdralloc_create
include		"admin.h"
declaration	void xdralloc_create(register XDR *xdrs, enum xdr_op op)
version		SUNWprivate_1.1
end

function	xdralloc_getdata
include		"admin.h"
declaration	caddr_t xdralloc_getdata(XDR *xdrs)
version		SUNWprivate_1.1
end

function	xdralloc_release
include		"admin.h"
declaration	void xdralloc_release(XDR *xdrs)
version		SUNWprivate_1.1
end

function	acl_impose_restrictions
declaration	krb5_error_code acl_impose_restrictions(\
			krb5_context kcontext,\
			kadm5_principal_ent_rec *recp,\
			long *maskp,\
			restriction_t *rp)
version		SUNWprivate_1.1
end

function	kadm5_create_principal_3
declaration	kadm5_ret_t    kadm5_create_principal_3(void *server_handle,\
					kadm5_principal_ent_t ent,\
					long mask,\
					int n_ks_tuple,\
					krb5_key_salt_tuple *ks_tuple,\
					char *pass)
version		SUNWprivate_1.1
end

function	kadm5_chpass_principal_3
declaration	kadm5_ret_t    kadm5_chpass_principal_3(void *server_handle,\
					krb5_principal principal,\
					krb5_boolean keepold,\
					int n_ks_tuple,\
					krb5_key_salt_tuple *ks_tuple,\
					char *pass)
version		SUNWprivate_1.1
end

function	kadm5_randkey_principal_3
declaration	kadm5_ret_t    kadm5_randkey_principal_3(void *server_handle,\
					 krb5_principal principal,\
					 krb5_boolean keepold,\
					 int n_ks_tuple,\
					 krb5_key_salt_tuple *ks_tuple,\
					 krb5_keyblock **keyblocks,\
					 int *n_keys)
version		SUNWprivate_1.1
end

function	kadm5_setkey_principal
declaration	kadm5_ret_t    kadm5_setkey_principal(void *server_handle,\
				      krb5_principal principal,\
				      krb5_keyblock *keyblocks,\
				      int n_keys)
version		SUNWprivate_1.1
end

function	kadm5_setkey_principal_3
declaration	kadm5_ret_t    kadm5_setkey_principal_3(void *server_handle,\
					krb5_principal principal,\
					krb5_boolean keepold,\
					int n_ks_tuple,\
					krb5_key_salt_tuple *ks_tuple,\
					krb5_keyblock *keyblocks,\
					int n_keys)
version		SUNWprivate_1.1
end

function	xdr_cprinc3_arg
declaration	bool_t xdr_cprinc3_arg(\
			XDR *xdrs,\
			cprinc3_arg *objp)
version		SUNWprivate_1.1
end

function	xdr_setkey_arg
declaration	bool_t xdr_setkey_arg(\
			XDR *xdrs,\
			setkey_arg *objp)
version		SUNWprivate_1.1
end

function	xdr_setkey3_arg
declaration	bool_t xdr_setkey3_arg(\
			XDR *xdrs,\
			setkey3_arg *objp)
version		SUNWprivate_1.1
end

function	xdr_chrand3_arg
declaration	bool_t xdr_chrand3_arg(\
			XDR *xdrs,\
			chrand3_arg *objp)
version		SUNWprivate_1.1
end

function	xdr_chpass3_arg
declaration	bool_t xdr_chpass3_arg(\
			XDR *xdrs,\
			chpass3_arg *objp)
version		SUNWprivate_1.1
end

function	kadm5_init_iprop
declaration	krb5_error_code kadm5_init_iprop(void *handle)
version		SUNWprivate_1.1
end
