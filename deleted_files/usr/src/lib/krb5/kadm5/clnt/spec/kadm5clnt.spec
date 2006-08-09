#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/krb5/kadm5/clnt/spec/kadm5clnt.spec

function	chpass_principal_1
include		<kadm_rpc.h>
declaration	generic_ret *chpass_principal_1 (chpass_arg *argp, CLIENT *clnt)
version		SUNWprivate_1.1
end

function	chrand_principal_1
declaration	chrand_ret *chrand_principal_1 (chrand_arg *argp, CLIENT *clnt)

version		SUNWprivate_1.1
end

function	create_policy_1
include		<kadm_rpc.h>
declaration	generic_ret *create_policy_1 (cpol_arg *argp, CLIENT *clnt)
version		SUNWprivate_1.1
end

function	create_principal_1
include		<kadm_rpc.h>
declaration	generic_ret *create_principal_1(cprinc_arg *argp, CLIENT *clnt)
version		SUNWprivate_1.1
end

function	delete_policy_1
include		<kadm_rpc.h>
declaration	generic_ret *delete_policy_1 (dpol_arg *argp, CLIENT *clnt)
version		SUNWprivate_1.1
end

function	delete_principal_1
include		<kadm_rpc.h>
declaration	generic_ret *delete_principal_1(dprinc_arg *argp, CLIENT *clnt)
version		SUNWprivate_1.1
end

function	display_status
declaration	void display_status(char *msg, OM_uint32 maj_stat, \
			OM_uint32 min_stat, char *mech)
version		SUNWprivate_1.1
end

function	get_policy_1
declaration	gpol_ret *get_policy_1(gpol_arg *argp, CLIENT *clnt)
version		SUNWprivate_1.1
end

function	get_pols_1
declaration	gpols_ret *get_pols_1(gprinc_arg *argp, CLIENT *clnt)
version		SUNWprivate_1.1
end

function	get_principal_1
declaration	gprinc_ret *get_principal_1(gprinc_arg *argp, CLIENT *clnt)
version		SUNWprivate_1.1
end

function	get_princs_1
declaration	gprincs_ret *get_princs_1(gprinc_arg *argp, CLIENT *clnt)
version		SUNWprivate_1.1
end

function	get_privs_1
declaration	getprivs_ret *get_privs_1(void *argp, CLIENT *clnt)
version		SUNWprivate_1.1
end

function	init_1
include		<kadm_rpc.h>
declaration	generic_ret *init_1(void *argp, CLIENT *clnt, \
					enum clnt_stat *rpc_err_code)
version		SUNWprivate_1.1
end

function	kadm5_get_master
declaration	kadm5_ret_t kadm5_get_master(krb5_context context, \
			const char *realm, char **master)
version		SUNWprivate_1.1
end

function	kadm5_get_adm_host_srv_name
declaration	kadm5_ret_t kadm5_get_adm_host_srv_name(krb5_context context, \
			const char *realm, char **host_service_name)
version		SUNWprivate_1.1
end

function	kadm5_get_cpw_host_srv_name
declaration	kadm5_ret_t kadm5_get_cpw_host_srv_name(krb5_context context, \
			const char *realm, char **host_service_name)
version		SUNWprivate_1.1
end

function	kadm5_get_kiprop_host_srv_name
declaration	kadm5_ret_t kadm5_get_kiprop_host_srv_name(krb5_context \
			context, const char *realm, char **host_service_name)
version		SUNWprivate_1.1
end

function	kadm5_chpass_principal
declaration	kadm5_ret_t kadm5_chpass_principal(void *server_handle, \
			krb5_principal princ, char *password)
version		SUNWprivate_1.1
end

function	kadm5_chpass_principal_util
declaration	kadm5_ret_t kadm5_chpass_principal_util(void *server_handle, \
			krb5_principal princ, char *new_pw, char **ret_pw, \
			char *msg_ret, int msg_len)
version		SUNWprivate_1.1
end

function	kadm5_create_policy
declaration	kadm5_ret_t kadm5_create_policy(void *server_handle, \
			kadm5_policy_ent_t policy, long mask)
version		SUNWprivate_1.1
end

function	kadm5_create_principal
declaration	kadm5_ret_t kadm5_create_principal(void *server_handle, \
			kadm5_principal_ent_t princ, long mask, char *pw)
version		SUNWprivate_1.1
end

function	kadm5_decrypt_key
declaration	kadm5_ret_t kadm5_decrypt_key(void *server_handle, \
			kadm5_principal_ent_t entry, krb5_int32 ktype, \
			krb5_int32 stype, krb5_int32 kvno, \
			krb5_keyblock *keyblock, krb5_keysalt *keysalt, \
			int *kvnop)
version		SUNWprivate_1.1
end

function	kadm5_delete_policy
declaration	kadm5_ret_t kadm5_delete_policy(void *server_handle, char *name)
version		SUNWprivate_1.1
end

function	kadm5_delete_principal
declaration	kadm5_ret_t kadm5_delete_principal(void *server_handle, \
			krb5_principal principal)
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
declaration	krb5_error_code kadm5_free_config_params ( \
			krb5_context context, kadm5_config_params *params)
version		SUNWprivate_1.1
end

function	kadm5_free_name_list
declaration	kadm5_ret_t kadm5_free_name_list(void *server_handle, \
			char **names, int count)
version		SUNWprivate_1.1
end

function	kadm5_free_policy_ent
declaration	kadm5_ret_t kadm5_free_policy_ent(void *server_handle, \
			kadm5_policy_ent_t val)
version		SUNWprivate_1.1
end

function	kadm5_free_principal_ent
declaration	kadm5_ret_t kadm5_free_principal_ent(void *server_handle, \
			kadm5_principal_ent_t val)
version		SUNWprivate_1.1
end

function	kadm5_get_config_params
declaration	krb5_error_code kadm5_get_config_params (krb5_context context, \
			char *kdcprofile, char *kdcenv, \
			kadm5_config_params *params_in, \
			kadm5_config_params *params_out)
version		SUNWprivate_1.1
end

function	kadm5_get_policies
declaration	kadm5_ret_t kadm5_get_policies(void *server_handle, \
			char *exp, char ***pols, int *count)
version		SUNWprivate_1.1
end

function	kadm5_get_policy
declaration	kadm5_ret_t kadm5_get_policy(void *server_handle, char *name, \
			kadm5_policy_ent_t ent)
version		SUNWprivate_1.1
end

function	kadm5_get_principal
declaration	kadm5_ret_t kadm5_get_principal(void *server_handle, \
			krb5_principal princ, kadm5_principal_ent_t ent, \
			long mask)
version		SUNWprivate_1.1
end

function	kadm5_get_principals
declaration	kadm5_ret_t kadm5_get_principals(void *server_handle, \
			char *exp, char ***princs, int *count)
version		SUNWprivate_1.1
end

function	kadm5_get_privs
declaration	kadm5_ret_t kadm5_get_privs(void *server_handle, long *privs)
version		SUNWprivate_1.1
end

function	kadm5_init
declaration	kadm5_ret_t kadm5_init(char *client_name, char *pass, \
			char *service_name, kadm5_config_params *params, \
			krb5_ui_4 struct_version, krb5_ui_4 api_version, \
			void **server_handle)
version		SUNWprivate_1.1
end

function	kadm5_init_with_creds
declaration	kadm5_ret_t kadm5_init_with_creds(char *client_name, \
			krb5_ccache ccache, char *service_name, \
			kadm5_config_params *params, krb5_ui_4 struct_version, \
			krb5_ui_4 api_version, void **server_handle)
version		SUNWprivate_1.1
end

function	kadm5_init_with_password
declaration	kadm5_ret_t kadm5_init_with_password(char *client_name, \
			char *pass, char *service_name, \
			kadm5_config_params *params, krb5_ui_4 struct_version, \
			krb5_ui_4 api_version, void **server_handle)
version		SUNWprivate_1.1
end

function	kadm5_init_with_skey
declaration	kadm5_ret_t kadm5_init_with_skey(char *client_name, \
			char *keytab, char *service_name, \
			kadm5_config_params *params, krb5_ui_4 struct_version, \
			krb5_ui_4 api_version, void **server_handle)
version		SUNWprivate_1.1
end

function	kadm5_modify_policy
declaration	kadm5_ret_t kadm5_modify_policy(void *server_handle, \
			kadm5_policy_ent_t policy, long mask)
version		SUNWprivate_1.1
end

function	kadm5_modify_principal
declaration	kadm5_ret_t kadm5_modify_principal(void *server_handle, \
			kadm5_principal_ent_t princ, long mask)
version		SUNWprivate_1.1
end

function	kadm5_randkey_principal_old
declaration	kadm5_ret_t kadm5_randkey_principal_old(void *server_handle, \
			krb5_principal princ, krb5_keyblock **key, int *n_keys)
version		SUNWprivate_1.1
end

function	kadm5_randkey_principal
declaration	kadm5_ret_t kadm5_randkey_principal(void *server_handle, \
			krb5_principal princ, krb5_keyblock **key, int *n_keys)
version		SUNWprivate_1.1
end

function	kadm5_rename_principal
declaration	kadm5_ret_t kadm5_rename_principal(void *server_handle, \
			krb5_principal source, krb5_principal dest)
version		SUNWprivate_1.1
end

function	krb5_aprof_finish
declaration	krb5_error_code krb5_aprof_finish(krb5_pointer acontext)
version		SUNWprivate_1.1
end

function	krb5_aprof_get_deltat
declaration	krb5_error_code krb5_aprof_get_deltat (krb5_pointer acontext, \
			const char **hierarchy, krb5_boolean uselast, \
			krb5_deltat *deltatp)
version		SUNWprivate_1.1
end

function	krb5_aprof_get_int32
declaration	krb5_error_code krb5_aprof_get_int32 (krb5_pointer acontext, \
			const char **hierarchy, krb5_boolean uselast, \
			krb5_int32 *intp)
version		SUNWprivate_1.1
end

function	krb5_aprof_get_string
declaration	krb5_error_code krb5_aprof_get_string (krb5_pointer acontext, \
			const char **hierarchy, krb5_boolean uselast, \
			char **stringp)
version		SUNWprivate_1.1
end

function	krb5_aprof_getvals
declaration	krb5_error_code krb5_aprof_getvals (krb5_pointer acontext, \
			const char **hierarchy, char ***retdata)
version		SUNWprivate_1.1
end

function	krb5_aprof_init
declaration	krb5_error_code krb5_aprof_init (char *fname, \
			char *envname, krb5_pointer *acontextp)
version		SUNWprivate_1.1
end

function	krb5_flags_to_string
declaration	krb5_error_code krb5_flags_to_string (krb5_flags flags, \
			const char *sep, char *buffer, size_t buflen)
version		SUNWprivate_1.1
end

function	krb5_free_key_data_contents
declaration	kadm5_ret_t krb5_free_key_data_contents (krb5_context context, \
			krb5_key_data *key)
version		SUNWprivate_1.1
end

function	krb5_free_realm_params
declaration	krb5_error_code krb5_free_realm_params (krb5_context kcontext, \
			krb5_realm_params *rparams)
version		SUNWprivate_1.1
end

function	krb5_input_flag_to_string
declaration	krb5_error_code krb5_input_flag_to_string (int flag, \
			char *buffer, size_t buflen)
version		SUNWprivate_1.1
end

function	krb5_keysalt_is_present
declaration	krb5_boolean krb5_keysalt_is_present ( \
			krb5_key_salt_tuple *ksaltlist, krb5_int32 nksalts, \
			krb5_enctype enctype, krb5_int32 salttype)
version		SUNWprivate_1.1
end

function	krb5_klog_close
declaration	void krb5_klog_close(krb5_context kcontext)
version		SUNWprivate_1.1
end

function	krb5_klog_init
declaration	krb5_error_code krb5_klog_init(krb5_context kcontext, \
			char *ename, char *whoami, krb5_boolean do_com_err)
version		SUNWprivate_1.1
end

function	krb5_klog_syslog
declaration	int krb5_klog_syslog(int priority, const char *format, ...)
version		SUNWprivate_1.1
end

function	krb5_log_error_table
declaration	const char *krb5_log_error_table(long errorno)
version		SUNWprivate_1.1
end

function	krb5_read_realm_params
declaration	krb5_error_code krb5_read_realm_params (krb5_context kcontext, \
			char *realm, char *kdcprofile, char *kdcenv, \
			krb5_realm_params **rparamp)
version		SUNWprivate_1.1
end

function	krb5_string_to_flags
declaration	krb5_error_code krb5_string_to_flags (char *string, \
			const char *positive, const char *negative, \
			krb5_flags *flagsp);
version		SUNWprivate_1.1
end

function	krb5_keysalt_iterate
declaration	krb5_error_code krb5_keysalt_iterate ( \
			krb5_key_salt_tuple *ksaltlist, krb5_int32 nksalt, \
			krb5_boolean ignoresalt, \
			krb5_error_code (*iterator) (krb5_key_salt_tuple *, krb5_pointer), \
			krb5_pointer arg)
version		SUNWprivate_1.1
end

function	krb5_string_to_keysalts
declaration	krb5_error_code krb5_string_to_keysalts (char *string, \
			const char *tupleseps, const char *ksaltseps, \
			krb5_boolean dups, krb5_key_salt_tuple **ksaltp, \
			krb5_int32 *nksaltp);
version		SUNWprivate_1.1
end

function	modify_policy_1
include		<kadm_rpc.h>
declaration	generic_ret *modify_policy_1 (mpol_arg *argp, CLIENT *clnt)
version		SUNWprivate_1.1
end

function	modify_principal_1
include		<kadm_rpc.h>
declaration	generic_ret *modify_principal_1 (mprinc_arg *argp, CLIENT *clnt)
version		SUNWprivate_1.1
end

function	rename_principal_1
include		<kadm_rpc.h>
declaration	generic_ret *rename_principal_1 (rprinc_arg *argp, CLIENT *clnt)
version		SUNWprivate_1.1
end

function	xdr_chpass_arg
declaration	bool_t xdr_chpass_arg(XDR *xdrs, chpass_arg *objp)
version		SUNWprivate_1.1
end

function	xdr_chrand_arg
declaration	bool_t xdr_chrand_arg(XDR *xdrs, chrand_arg *objp)
version		SUNWprivate_1.1
end

function	xdr_chrand_ret
declaration	bool_t xdr_chrand_ret(XDR *xdrs, chrand_ret *objp)
version		SUNWprivate_1.1
end

function	xdr_cpol_arg
declaration	bool_t xdr_cpol_arg(XDR *xdrs, cpol_arg *objp)
version		SUNWprivate_1.1
end

function	xdr_cprinc_arg
declaration	bool_t xdr_cprinc_arg(XDR *xdrs, cprinc_arg *objp)
version		SUNWprivate_1.1
end

function	xdr_dpol_arg
declaration	bool_t xdr_dpol_arg(XDR *xdrs, dpol_arg *objp)
version		SUNWprivate_1.1
end

function	xdr_dprinc_arg
declaration	bool_t xdr_dprinc_arg(XDR *xdrs, dprinc_arg *objp)
version		SUNWprivate_1.1
end

function	xdr_generic_ret
include		<kadm_rpc.h>
declaration	bool_t xdr_generic_ret(XDR *xdrs, generic_ret *objp)
version		SUNWprivate_1.1
end

function	xdr_getprivs_ret
declaration	bool_t xdr_getprivs_ret(XDR *xdrs, getprivs_ret *objp)
version		SUNWprivate_1.1
end

function	xdr_gpol_arg
declaration	bool_t xdr_gpol_arg(XDR *xdrs, gpol_arg *objp)
version		SUNWprivate_1.1
end

function	xdr_gpol_ret
declaration	bool_t xdr_gpol_ret(XDR *xdrs, gpol_ret *objp)
version		SUNWprivate_1.1
end

function	xdr_gpols_arg
declaration	bool_t xdr_gpols_arg(XDR *xdrs, gpols_arg *objp)
version		SUNWprivate_1.1
end

function	xdr_gpols_ret
declaration	bool_t xdr_gpols_ret(XDR *xdrs, gpols_ret *objp)
version		SUNWprivate_1.1
end

function	xdr_gprinc_arg
declaration	bool_t xdr_gprinc_arg(XDR *xdrs, gprinc_arg *objp)
version		SUNWprivate_1.1
end

function	xdr_gprinc_ret
declaration	bool_t xdr_gprinc_ret(XDR *xdrs, gprinc_ret *objp)
version		SUNWprivate_1.1
end

function	xdr_gprincs_arg
declaration	bool_t xdr_gprincs_arg(XDR *xdrs, gprincs_arg *objp)
version		SUNWprivate_1.1
end

function	xdr_gprincs_ret
declaration	bool_t xdr_gprincs_ret(XDR *xdrs, gprincs_ret *objp)
version		SUNWprivate_1.1
end

function	xdr_kadm5_policy_ent_rec
declaration	bool_t xdr_kadm5_policy_ent_rec(XDR *xdrs, \
			kadm5_policy_ent_rec *objp)
version		SUNWprivate_1.1
end

function	xdr_kadm5_principal_ent_rec
declaration	bool_t xdr_kadm5_principal_ent_rec(XDR *xdrs, \
			kadm5_principal_ent_rec *objp)
version		SUNWprivate_1.1
end

function	xdr_kadm5_principal_ent_rec_v1
declaration	bool_t xdr_kadm5_principal_ent_rec_v1(XDR *xdrs, \
			kadm5_principal_ent_rec *objp)
version		SUNWprivate_1.1
end

function	xdr_kadm5_ret_t
declaration	bool_t xdr_kadm5_ret_t(XDR *xdrs, kadm5_ret_t *objp)
version		SUNWprivate_1.1
end

function	xdr_krb5_deltat
declaration	bool_t xdr_krb5_deltat(XDR *xdrs, krb5_deltat *objp)
version		SUNWprivate_1.1
end

function	xdr_krb5_enctype
declaration	bool_t xdr_krb5_enctype(XDR *xdrs, krb5_enctype *objp)
version		SUNWprivate_1.1
end

function	xdr_krb5_flags
declaration	bool_t xdr_krb5_flags(XDR *xdrs, krb5_flags *objp)
version		SUNWprivate_1.1
end

function	xdr_krb5_int16
declaration	bool_t xdr_krb5_int16(XDR *xdrs, krb5_int16 *objp)
version		SUNWprivate_1.1
end

function	xdr_krb5_key_data_nocontents
declaration	bool_t xdr_krb5_key_data_nocontents(XDR *xdrs, \
			krb5_key_data *objp)
version		SUNWprivate_1.1
end

function	xdr_krb5_keyblock
declaration	bool_t xdr_krb5_keyblock(XDR *xdrs, krb5_keyblock *objp)
version		SUNWprivate_1.1
end

function	xdr_krb5_kvno
declaration	bool_t xdr_krb5_kvno(XDR *xdrs, krb5_kvno *objp)
version		SUNWprivate_1.1
end

function	xdr_krb5_octet
declaration	bool_t xdr_krb5_octet(XDR *xdrs, krb5_octet *objp)
version		SUNWprivate_1.1
end

function	xdr_krb5_principal
declaration	bool_t xdr_krb5_principal(XDR *xdrs, krb5_principal *objp)
version		SUNWprivate_1.1
end

function	xdr_krb5_timestamp
declaration	bool_t xdr_krb5_timestamp(XDR *xdrs, krb5_timestamp *objp)
version		SUNWprivate_1.1
end

function	xdr_krb5_tl_data
declaration	bool_t xdr_krb5_tl_data(XDR *xdrs, krb5_tl_data **tl_data_head)
version		SUNWprivate_1.1
end

function	xdr_krb5_ui_4
declaration	bool_t xdr_krb5_ui_4(XDR *xdrs, krb5_ui_4 *objp)
version		SUNWprivate_1.1
end

function	xdr_mpol_arg
declaration	bool_t xdr_mpol_arg(XDR *xdrs, mpol_arg *objp)
version		SUNWprivate_1.1
end

function	xdr_mprinc_arg
declaration	bool_t xdr_mprinc_arg(XDR *xdrs, mprinc_arg *objp)
version		SUNWprivate_1.1
end

function	xdr_nullstring
declaration	bool_t xdr_nullstring(XDR *xdrs, char **objp)
version		SUNWprivate_1.1
end

function	xdr_nulltype
declaration	bool_t xdr_nulltype(XDR *xdrs, void **objp, xdrproc_t proc)
version		SUNWprivate_1.1
end

function	xdr_rprinc_arg
declaration	bool_t xdr_rprinc_arg(XDR *xdrs, rprinc_arg *objp)
version		SUNWprivate_1.1
end

function	xdr_ui_4
declaration	bool_t xdr_ui_4(XDR *xdrs, krb5_ui_4 *objp)
version		SUNWprivate_1.1
end

function	krb5_mk_chpw_req
declaration	krb5_error_code krb5_mk_chpw_req( krb5_context context,\
			krb5_auth_context auth_context,\
			krb5_data	*ap_req,\
			char		*passwd,\
			krb5_data	*packet)
version		SUNWprivate_1.1
end

function	krb5_rd_chpw_rep
declaration	krb5_error_code krb5_rd_chpw_rep( krb5_context context,\
				krb5_auth_context auth_context,\
				krb5_data	*packet,\
				int		*result_code,\
				krb5_data	*result_data)
version		SUNWprivate_1.1
end

function	chpw_error_message
declaration	const char * chpw_error_message(kadm5_ret_t result_code)
version		SUNWprivate_1.1
end

function	_kadm5_get_kpasswd_protocol
declaration	krb5_chgpwd_prot _kadm5_get_kpasswd_protocol(void *handle)
version		SUNWprivate_1.1
end

function	kadm5_chpass_principal_v2
declaration	kadm5_ret_t kadm5_chpass_principal_v2(void *server_handle, \
			krb5_principal princ, \
			char *password, \
			kadm5_ret_t *srvr_rsp_code,\
			krb5_data *srvr_msg)
version		SUNWprivate_1.1
end

function	kadm5_create_principal_3

declaration	kadm5_ret_t kadm5_create_principal_3(void *server_handle, \
			 kadm5_principal_ent_t princ, long mask, \
			 int n_ks_tuple, \
			 krb5_key_salt_tuple *ks_tuple, \
			 char *pw)
version		SUNWprivate_1.1
end

function	kadm5_chpass_principal_3
declaration	kadm5_ret_t kadm5_chpass_principal_3(void *server_handle, \
			 krb5_principal princ, krb5_boolean keepold, \
			 int n_ks_tuple, krb5_key_salt_tuple *ks_tuple, \
			 char *password)
version		SUNWprivate_1.1
end

function	kadm5_setkey_principal_3
declaration	kadm5_ret_t kadm5_setkey_principal_3(void *server_handle, \
			 krb5_principal princ, \
			 krb5_boolean keepold, int n_ks_tuple, \
			 krb5_key_salt_tuple *ks_tuple, \
			 krb5_keyblock *keyblocks, \
			 int n_keys)
version		SUNWprivate_1.1
end

function	kadm5_randkey_principal_3
declaration	kadm5_ret_t kadm5_randkey_principal_3(void *server_handle, \
			  krb5_principal princ, \
			  krb5_boolean keepold, int n_ks_tuple, \
			  krb5_key_salt_tuple *ks_tuple, \
			  krb5_keyblock **key, int *n_keys)
version		SUNWprivate_1.1
end

function	kadm5_init_iprop
declaration	krb5_error_code kadm5_init_iprop(void *handle)
version		SUNWprivate_1.1
end
