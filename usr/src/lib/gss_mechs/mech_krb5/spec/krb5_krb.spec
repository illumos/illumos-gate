#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/gss_mechs/mech_krb5/spec/krb5_krb.spec
#

function	krb5_appdefault_boolean
include		<krb5.h>, <k5-int.h>
declaration	void krb5_appdefault_boolean (krb5_context context, \
			const char *appname, const krb5_data *realm, \
			const char *option, int default_value, \
			int *ret_value)
version		SUNWprivate_1.1
end

function	krb5_appdefault_string
include		<krb5.h>, <k5-int.h>
declaration	void krb5_appdefault_string (krb5_context context, \
			const char *appname, const krb5_data *realm, \
			const char *option, const char *default_value, \
			char **ret_value)
version		SUNWprivate_1.1
end

function	krb5_auth_con_getpermetypes
include		<krb5.h>
declaration	krb5_error_code krb5_auth_con_getpermetypes \
			(krb5_context context, \
			krb5_auth_context auth_context, \
			krb5_enctype ** permetypes)
version		SUNWprivate_1.1
end

function	krb5_auth_con_setpermetypes
include		<krb5.h>
declaration	krb5_error_code krb5_auth_con_setpermetypes \
			(krb5_context context, \
			krb5_auth_context auth_context, \
			const krb5_enctype * permetypes)
version		SUNWprivate_1.1
end

function	krb5_crypto_us_timeofday
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_crypto_us_timeofday ( \
			register krb5_int32 *seconds, \
			register krb5_int32 *microseconds)
version		SUNWprivate_1.1
end

function	krb5_do_preauth
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_do_preauth ( \
			krb5_context context, krb5_kdc_req *request, \
			krb5_pa_data **in_padata, krb5_pa_data ***out_padata, \
			krb5_data *salt, krb5_data *s2kparams, \
			krb5_enctype *etype, \
			krb5_keyblock *as_key, \
			krb5_prompter_fct prompter, void *prompter_data, \
			krb5_gic_get_as_key_fct gak_fct, void *gak_data)
version		SUNWprivate_1.1
end

function	krb5_encrypt_helper
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_encrypt_helper ( \
			krb5_context context, \
			const krb5_keyblock *key, krb5_keyusage usage, \
			const krb5_data *plain, krb5_enc_data *cipher)
version		SUNWprivate_1.1
end

function	krb5_free_config_files
include		<krb5.h>, <k5-int.h>
declaration	void krb5_free_config_files (char **pfilenames)
version		SUNWprivate_1.1
end

function	krb5_free_default_realm
include		<krb5.h>, <k5-int.h>
declaration	void krb5_free_default_realm \
			(krb5_context context, char *lrealm)
version		SUNWprivate_1.1
end

function	krb5_free_ktypes
include		<krb5.h>, <k5-int.h>
declaration	void krb5_free_ktypes \
			(krb5_context context, \
			krb5_enctype *val)
version		SUNWprivate_1.1
end

function	krb5_free_realm_string
include		<krb5.h>, <k5-int.h>
declaration	void krb5_free_realm_string ( \
			krb5_context context, char *str)
version		SUNWprivate_1.1
end

function	krb5_get_default_config_files
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_get_default_config_files \
			(char ***pfilenames)
version		SUNWprivate_1.1
end

function	krb5_get_init_creds
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_get_init_creds ( \
			krb5_context context, krb5_creds *creds, \
			krb5_principal client, krb5_prompter_fct prompter, \
			void *prompter_data, krb5_deltat start_time, \
			char *in_tkt_service, \
			krb5_get_init_creds_opt *options, \
			krb5_gic_get_as_key_fct gak_fct, void *gak_data, \
			int	use_master, krb5_kdc_rep **as_reply)
version		SUNWprivate_1.1
end

function	krb5_get_init_creds_keytab
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_get_init_creds_keytab ( \
			krb5_context context, \
			krb5_creds *creds, krb5_principal client, \
			krb5_keytab arg_keytab, krb5_deltat start_time, \
			char *in_tkt_service, \
			krb5_get_init_creds_opt *options)
version		SUNWprivate_1.1
end

function	krb5_get_init_creds_opt_init
include		<krb5.h>, <k5-int.h>
declaration	void krb5_get_init_creds_opt_init ( \
			krb5_get_init_creds_opt *opt)
version		SUNWprivate_1.1
end

function	krb5_get_init_creds_opt_set_address_list
include		<krb5.h>, <k5-int.h>
declaration	void krb5_get_init_creds_opt_set_address_list ( \
			krb5_get_init_creds_opt *opt, \
			krb5_address **addresses)
version		SUNWprivate_1.1
end

function	krb5_get_init_creds_opt_set_etype_list
include		<krb5.h>, <k5-int.h>
declaration	void krb5_get_init_creds_opt_set_etype_list ( \
			krb5_get_init_creds_opt *opt, \
			krb5_enctype *etype_list, int etype_list_length)
version		SUNWprivate_1.1
end

function	krb5_get_init_creds_opt_set_forwardable
include		<krb5.h>, <k5-int.h>
declaration	void krb5_get_init_creds_opt_set_forwardable ( \
			krb5_get_init_creds_opt *opt, int forwardable)
version		SUNWprivate_1.1
end

function	krb5_get_init_creds_opt_set_preauth_list
include		<krb5.h>, <k5-int.h>
declaration	void krb5_get_init_creds_opt_set_preauth_list ( \
			krb5_get_init_creds_opt *opt, \
			krb5_preauthtype *preauth_list, int preauth_list_length)
version		SUNWprivate_1.1
end

function	krb5_get_init_creds_opt_set_proxiable
include		<krb5.h>, <k5-int.h>
declaration	void krb5_get_init_creds_opt_set_proxiable ( \
			krb5_get_init_creds_opt *opt, int proxiable)
version		SUNWprivate_1.1
end

function	krb5_get_init_creds_opt_set_renew_life
include		<krb5.h>, <k5-int.h>
declaration	void krb5_get_init_creds_opt_set_renew_life ( \
			krb5_get_init_creds_opt *opt, krb5_deltat renew_life)
version		SUNWprivate_1.1
end

function	krb5_get_init_creds_opt_set_salt
include		<krb5.h>, <k5-int.h>
declaration	void krb5_get_init_creds_opt_set_salt ( \
			krb5_get_init_creds_opt *opt, krb5_data *salt)
version		SUNWprivate_1.1
end

function	krb5_get_init_creds_opt_set_tkt_life
include		<krb5.h>, <k5-int.h>
declaration	void krb5_get_init_creds_opt_set_tkt_life ( \
			krb5_get_init_creds_opt *opt, krb5_deltat tkt_life)
version		SUNWprivate_1.1
end

function	krb5_get_init_creds_password
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_get_init_creds_password ( \
			krb5_context context, \
			krb5_creds *creds, \
			krb5_principal client, \
			char *password, \
			krb5_prompter_fct prompter, \
			void *data, \
			krb5_deltat start_time, \
			char *in_tkt_service, \
			krb5_get_init_creds_opt *options)
version		SUNWprivate_1.1
end

function	krb5_get_permitted_enctypes
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_get_permitted_enctypes \
			(krb5_context context, \
			krb5_enctype **ktypes)
version		SUNWprivate_1.1
end

function	krb5_get_profile
include		<k5-int.h>
declaration	krb5_error_code krb5_get_profile \
			(krb5_context ctx, profile_t* profile)
version		SUNWprivate_1.1
end

function	krb5_get_renewed_creds
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_get_renewed_creds ( \
			krb5_context context, \
			krb5_creds *creds, \
			krb5_principal client, \
			krb5_ccache ccache, \
			char *in_tkt_service)
version		SUNWprivate_1.1
end

function	krb5_get_server_rcache
include		<k5-int.h>
declaration	krb5_error_code krb5_get_server_rcache ( \
			krb5_context context, \
			const krb5_data *piece, \
			krb5_rcache *rcptr)
version		SUNWprivate_1.1
end

function	krb5_get_validated_creds
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_get_validated_creds ( \
			krb5_context context, \
			krb5_creds *creds, \
			krb5_principal client, \
			krb5_ccache ccache, \
			char *in_tkt_service)
version		SUNWprivate_1.1
end

function	krb5_init_secure_context
include		<krb5.h>
declaration	krb5_error_code krb5_init_secure_context ( \
			krb5_context *context)
version		SUNWprivate_1.1
end

function	krb5_is_permitted_enctype
include		<krb5.h>, <k5-int.h>
declaration	krb5_boolean krb5_is_permitted_enctype \
			(krb5_context context, \
			krb5_enctype etype)
version		SUNWprivate_1.1
end

function	krb5_libdefault_boolean
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_libdefault_boolean ( \
			krb5_context context, const char *option, \
			const krb5_data *realm, int *ret_valu)
version		SUNWprivate_1.1
end

function	krb5_prompter_posix
include		<k5-int.h>
declaration	krb5_error_code krb5_prompter_posix ( \
			krb5_context context, \
			void *data, \
			const char *name, \
			const char *banner, \
			int num_prompts, \
			krb5_prompt prompts[])
version		SUNWprivate_1.1
end

function	krb5_get_prompt_types
include		<k5-int.h>
declaration	krb5_prompt_type* krb5_get_prompt_types (\
			krb5_context context)
version		SUNWprivate_1.1
end

function	krb5_realm_iterator
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_realm_iterator ( \
			krb5_context context, void **iter_p, char **ret_realm)
version		SUNWprivate_1.1
end

function	krb5_realm_iterator_create
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_realm_iterator_create ( \
			krb5_context context, void **iter_p)
version		SUNWprivate_1.1
end

function	krb5_realm_iterator_free
include		<krb5.h>, <k5-int.h>
declaration	void krb5_realm_iterator_free ( \
			krb5_context context, void **iter_p)
version		SUNWprivate_1.1
end

function	krb5_recvauth_version
include		<krb5.h>
declaration	krb5_error_code krb5_recvauth_version \
			(krb5_context context, \
			krb5_auth_context *auth_context, \
			krb5_pointer fd, krb5_principal server, \
			krb5_int32 flags, krb5_keytab keytab, \
			krb5_ticket **ticket, krb5_data *version)
version		SUNWprivate_1.1
end

function	krb5_verify_init_creds
include		<krb5.h>, <k5-int.h>
declaration	krb5_error_code krb5_verify_init_creds ( \
			krb5_context context, \
			krb5_creds *creds, \
			krb5_principal server_arg, \
			krb5_keytab keytab_arg, \
			krb5_ccache *ccache_arg, \
			krb5_verify_init_creds_opt *options)
version		SUNWprivate_1.1
end

function	krb5_verify_init_creds_opt_init
include		<krb5.h>, <k5-int.h>
declaration	void krb5_verify_init_creds_opt_init ( \
			krb5_verify_init_creds_opt *opt)
version		SUNWprivate_1.1
end

function	krb5_verify_init_creds_opt_set_ap_req_nofail
include		<krb5.h>, <k5-int.h>
declaration	void krb5_verify_init_creds_opt_set_ap_req_nofail ( \
			krb5_verify_init_creds_opt *opt, int ap_req_nofail)
version		SUNWprivate_1.1
end

function	krb5_decode_ticket
include		<krb5.h>
declaration	krb5_error_code krb5_decode_ticket \
			(const krb5_data *code, krb5_ticket **rep)
version		SUNWprivate_1.1
end

function	krb5_init_keyblock
include		<k5-int.h>
declaration	krb5_error_code krb5_init_keyblock \
			(krb5_context, krb5_enctype enctype, \
			size_t length, krb5_keyblock **out)
version		SUNWprivate_1.1
end

function	krb5_init_allocated_keyblock
include		<k5-int.h>
declaration	krb5_error_code krb5_init_allocated_keyblock \
			(krb5_context, krb5_enctype enctype, \
			unsigned int length)
version		SUNWprivate_1.1
end

function	krb5_get_key_enctype
include		<k5-int.h>
declaration	krb5_enctype krb5_get_key_enctype(krb5_keyblock *)
version		SUNWprivate_1.1
end

function	krb5_get_key_length
include		<k5-int.h>
declaration	unsigned int krb5_get_key_length(krb5_keyblock *)
version		SUNWprivate_1.1
end

function	krb5_get_key_data
include		<k5-int.h>
declaration	krb5_octet *krb5_get_key_data(krb5_keyblock *)
version		SUNWprivate_1.1
end

function	krb5_set_key_enctype
include		<k5-int.h>
declaration	void krb5_set_key_enctype(krb5_keyblock *, krb5_enctype)
version		SUNWprivate_1.1
end

function	krb5_set_key_data
include		<k5-int.h>
declaration	void krb5_set_key_data(krb5_keyblock *,\
                		krb5_octet *)
version		SUNWprivate_1.1
end

function	krb5_set_key_length
include		<k5-int.h>
declaration	void krb5_set_key_length(krb5_keyblock *,\
	                 unsigned int)
version		SUNWprivate_1.1
end

