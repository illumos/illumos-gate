#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/gss_mechs/mech_krb5/spec/krb5_gss.spec
#

function	g_delete_cred_id
include		<gssapi_krb5.h>
declaration	int g_delete_cred_id (void **vdb, gss_cred_id_t cred)
version		SUNWprivate_1.1
end

function	g_delete_ctx_id
include		<gssapi_krb5.h>
declaration	int g_delete_ctx_id (void **vdb, gss_ctx_id_t ctx)
version		SUNWprivate_1.1
end

function	g_delete_name
include		<gssapi_krb5.h>
declaration	int g_delete_name (void **vdb, gss_name_t name)
version		SUNWprivate_1.1
end

function	g_display_com_err_status
include		<gssapi_krb5.h>
declaration	OM_uint32 g_display_com_err_status (OM_uint32 *minor_status, \
			OM_uint32 status_value, gss_buffer_t status_string)
version		SUNWprivate_1.1
end

function	g_display_major_status
include		<gssapi_krb5.h>
declaration	OM_uint32 g_display_major_status (OM_uint32 *minor_status, \
			OM_uint32 status_value, OM_uint32 *message_context, \
			gss_buffer_t status_string)
version		SUNWprivate_1.1
end

function	g_local_host_name
include		<gssapi_krb5.h>
declaration	char *g_local_host_name (void);
version		SUNWprivate_1.1
end

function	g_make_string_buffer
include		<gssapi_krb5.h>
declaration	int g_make_string_buffer (const char *str, \
			gss_buffer_t buffer)
version		SUNWprivate_1.1
end

function	g_make_token_header
include		<gssapi_krb5.h>
declaration	void g_make_token_header (gss_OID mech, int body_size, \
			unsigned char **buf, int tok_type)
version		SUNWprivate_1.1
end

function	g_order_check
include		<gssapi_krb5.h>
declaration	gss_int32 g_order_check (void **vqueue, gssint_uint64 seqnum)
version		SUNWprivate_1.1
end

function	g_order_free
include		<gssapi_krb5.h>
declaration	void g_order_free (void **vqueue)
version		SUNWprivate_1.1
end

function	g_order_init
include		<gssapi_krb5.h>
declaration	gss_int32 g_order_init (void **queue, gssint_uint64 seqnum, \
			int do_replay, int do_sequence, int wide)
version		SUNWprivate_1.1
end

function	g_queue_externalize
include		<gssapi_krb5.h>
declaration	gss_uint32 g_queue_externalize (void *vqueue, \
			unsigned char **buf, size_t *lenremain)
version		SUNWprivate_1.1
end

function	g_queue_internalize
include		<gssapi_krb5.h>
declaration	gss_uint32 g_queue_internalize (void **vqueue, \
			unsigned char **buf, size_t *lenremain)
version		SUNWprivate_1.1
end

function	g_queue_size
include		<gssapi_krb5.h>
declaration	gss_uint32 g_queue_size (void *vqueue, size_t *sizep)
version		SUNWprivate_1.1
end

function	g_save_cred_id
include		<gssapi_krb5.h>
declaration	int g_save_cred_id (void **vdb, gss_cred_id_t cred)
version		SUNWprivate_1.1
end

function	g_save_ctx_id
include		<gssapi_krb5.h>
declaration	int g_save_ctx_id (void **vdb, gss_ctx_id_t ctx)
version		SUNWprivate_1.1
end

function	g_save_name
include		<gssapi_krb5.h>
declaration	int g_save_name (void **vdb, gss_name_t name)
version		SUNWprivate_1.1
end

function	g_set_destroy
include		<gssapi_krb5.h>
declaration	int g_set_destroy (g_set *s)
version		SUNWprivate_1.1
end

function	g_set_entry_add
include		<gssapi_krb5.h>
declaration	int g_set_entry_add (g_set *s, void *key, void *value)
version		SUNWprivate_1.1
end

function	g_set_entry_delete
include		<gssapi_krb5.h>
declaration	int g_set_entry_delete (g_set *s, void *key)
version		SUNWprivate_1.1
end

function	g_set_entry_get
include		<gssapi_krb5.h>
declaration	int g_set_entry_get (g_set *s, void *key, void **value)
version		SUNWprivate_1.1
end

function	g_set_init
include		<gssapi_krb5.h>
declaration	int g_set_init (g_set *s)
version		SUNWprivate_1.1
end

function	g_strdup
include		<gssapi_krb5.h>
declaration	char *g_strdup (char *str)
version		SUNWprivate_1.1
end

function	g_token_size
include		<gssapi_krb5.h>
declaration	int g_token_size (gss_OID mech, unsigned int body_size)
version		SUNWprivate_1.1
end

function	g_validate_cred_id
include		<gssapi_krb5.h>
declaration	int g_validate_cred_id (void **vdb, gss_cred_id_t cred)
version		SUNWprivate_1.1
end

function	g_validate_ctx_id
include		<gssapi_krb5.h>
declaration	int g_validate_ctx_id (void **vdb, gss_ctx_id_t ctx)
version		SUNWprivate_1.1
end

function	g_validate_name
include		<gssapi_krb5.h>
declaration	int g_validate_name (void **vdb, gss_name_t name)
version		SUNWprivate_1.1
end

function	g_verify_token_header
include		<gssapi_krb5.h>
declaration	gss_int32 g_verify_token_header \
			(gss_OID mech, unsigned int *body_size, \
			unsigned char **buf, int tok_type, \
			unsigned int toksize, int wrapper_required)
version		SUNWprivate_1.1
end

function	gmt_mktime
declaration	time_t gmt_mktime (struct tm *t)
version		SUNWprivate_1.1
end

function	gss_krb5_ccache_name
include		<gssapi_krb5.h>
declaration	OM_uint32 gss_krb5_ccache_name ( \
			OM_uint32 *minor_status, \
			const char *name, \
			const char **out_name)
version		SUNWprivate_1.1
end

function	gss_krb5_copy_ccache
include		<gssapi_krb5.h>
declaration	OM_uint32 gss_krb5_copy_ccache ( \
			void *ctx, \
			OM_uint32 *minor_status, \
			gss_cred_id_t cred_handle, \
			krb5_ccache out_ccache)
version		SUNWprivate_1.1
end

function	gss_krb5_get_tkt_flags
include		<gssapi_krb5.h>
declaration	OM_uint32 gss_krb5_get_tkt_flags (OM_uint32 *minor_status, \
			gss_ctx_id_t context_handle, krb5_flags *ticket_flags)
version		SUNWprivate_1.1
end

data		gss_mech_krb5
declaration	const gss_OID_desc * const gss_mech_krb5
version		SUNWprivate_1.1
end

data		gss_mech_krb5_old
declaration	const gss_OID_desc * const gss_mech_krb5_old
version		SUNWprivate_1.1
end

data		gss_mech_krb5_v2
declaration	const gss_OID_desc * const gss_mech_krb5_v2
version		SUNWprivate_1.1
end

data		gss_mech_set_krb5
declaration	const gss_OID_set_desc * const gss_mech_set_krb5
version		SUNWprivate_1.1
end

data		gss_mech_set_krb5_both
declaration	const gss_OID_set_desc * const gss_mech_set_krb5_both
version		SUNWprivate_1.1
end

data		gss_mech_set_krb5_old
declaration	const gss_OID_set_desc * const gss_mech_set_krb5_old
version		SUNWprivate_1.1
end

data		gss_mech_set_krb5_v2
declaration	const gss_OID_set_desc * const gss_mech_set_krb5_old
version		SUNWprivate_1.1
end

data		gss_mech_set_krb5_v1v2
declaration	const gss_OID_set_desc * const gss_mech_set_krb5_old
version		SUNWprivate_1.1
end

data		gss_nt_krb5_name
declaration	const gss_OID_desc * const gss_nt_krb5_name
version		SUNWprivate_1.1
end

data		gss_nt_krb5_principal
declaration	const gss_OID_desc * const gss_nt_krb5_principal
version		SUNWprivate_1.1
end

function	kg_checksum_channel_bindings
include		<gssapiP_krb5.h>
declaration	krb5_error_code kg_checksum_channel_bindings (krb5_context context, \
				gss_channel_bindings_t cb, krb5_checksum *cksum, \
				int bigend)
version		SUNWprivate_1.1
end

function	kg_confounder_size
include		<gssapiP_krb5.h>
declaration	int kg_confounder_size (krb5_context context, krb5_keyblock *key)
version		SUNWprivate_1.1
end

data		kg_context
declaration	krb5_context kg_context
version		SUNWprivate_1.1
end

function	kg_ctx_externalize
include		<gssapiP_krb5.h>
declaration	krb5_error_code kg_ctx_externalize (krb5_context kcontext, \
			krb5_pointer arg, krb5_octet **buffer, size_t *lenremain)
version		SUNWprivate_1.1
end

function	kg_ctx_internalize
include		<gssapiP_krb5.h>
declaration	krb5_error_code kg_ctx_internalize (krb5_context kcontext, \
			krb5_pointer *argp, krb5_octet **buffer, size_t *lenremain)
version		SUNWprivate_1.1
end

function	kg_ctx_size
include		<gssapiP_krb5.h>
declaration	krb5_error_code kg_ctx_size (krb5_context kcontext, \
			krb5_pointer arg, size_t *sizep)
version		SUNWprivate_1.1
end

function	kg_decrypt
include		<gssapiP_krb5.h>
declaration	krb5_error_code kg_decrypt (krb5_context context, \
			krb5_keyblock *key, \
			int usage, \
			krb5_pointer iv, \
			krb5_pointer in, krb5_pointer out, int length)
version		SUNWprivate_1.1
end

function	kg_encrypt
include		<gssapiP_krb5.h>
declaration	krb5_error_code kg_encrypt (krb5_context context, \
			krb5_keyblock *key, \
			int usage, \
			krb5_pointer iv, \
			krb5_pointer in, \
			krb5_pointer out, \
			int length)
version		SUNWprivate_1.1
end

function	kg_encrypt_size
include		<gssapiP_krb5.h>
declaration	int kg_encrypt_size (krb5_context context, \
                               krb5_keyblock *key, int n)
version		SUNWprivate_1.1
end

function	kg_get_context
include		<gssapiP_krb5.h>
declaration	OM_uint32 kg_get_context (OM_uint32 *minor_status, \
			krb5_context *context)
version		SUNWprivate_1.1
end

function	kg_get_defcred
include		<gssapiP_krb5.h>
declaration	OM_uint32 kg_get_defcred (OM_uint32 *minor_status, \
			gss_cred_id_t *cred)
version		SUNWprivate_1.1
end

function	kg_get_seq_num
include		<gssapiP_krb5.h>
declaration	krb5_error_code kg_get_seq_num (krb5_context context, \
			krb5_keyblock *key, unsigned char *cksum, \
			unsigned char *buf, int *direction, \
			krb5_ui_4 *seqnum)
version		SUNWprivate_1.1
end

function	kg_make_confounder
include		<gssapiP_krb5.h>
declaration	krb5_error_code kg_make_confounder ( \
			krb5_context context, \
			krb5_keyblock *key, unsigned char *buf)
version		SUNWprivate_1.1
end

function	kg_make_seed
include		<gssapiP_krb5.h>
declaration	krb5_error_code kg_make_seed (krb5_context context, \
				krb5_keyblock *key, unsigned char *seed)
version		SUNWprivate_1.1
end

function	kg_make_seq_num
include		<gssapiP_krb5.h>
declaration	krb5_error_code kg_make_seq_num (krb5_context context, \
			krb5_keyblock *key, int direction, \
			krb5_ui_4 seqnum, unsigned char *cksum, \
			unsigned char *buf)
version		SUNWprivate_1.1
end

function	kg_oid_size
declaration	krb5_error_code kg_oid_size \
			(krb5_context kcontext, \
			krb5_pointer arg, size_t *sizep)
version		SUNWprivate_1.1
end

function	kg_queue_size
declaration	krb5_error_code kg_queue_size \
			(krb5_context kcontext, \
			krb5_pointer arg, size_t *sizep)
version		SUNWprivate_1.1
end

function	kg_release_defcred
include		<gssapiP_krb5.h>
declaration	OM_uint32 kg_release_defcred (OM_uint32 *minor_status)
version		SUNWprivate_1.1
end

function	kg_seal
include		<gssapiP_krb5.h>
declaration	OM_uint32 kg_seal (krb5_context context, \
			OM_uint32 *minor_status, gss_ctx_id_t context_handle, \
			int conf_req_flag, int qop_req, \
			gss_buffer_t input_msg_buffer, int *conf_state, \
			gss_buffer_t output_msg_buffer, int toktype)
version		SUNWprivate_1.1
end

function	kg_unseal
include		<gssapiP_krb5.h>
declaration	OM_uint32 kg_unseal (krb5_context context, \
			OM_uint32 *minor_status, gss_ctx_id_t context_handle, \
			gss_buffer_t input_token_buffer, \
			gss_buffer_t message_buffer, int *conf_state, \
			int *qop_state, int toktype)
version		SUNWprivate_1.1
end

data		kg_vdb
declaration	void *kg_vdb
version		SUNWprivate_1.1
end

function	kg2_parse_token
include		<gssapiP_krb5.h>
declaration	OM_uint32 kg2_parse_token (OM_uint32 *minor_status, \
			unsigned char *ptr, \
			int length, \
			krb5_ui_4 *flags, \
			int *nctypes,  \
			krb5_cksumtype **ctypes, \
			int noptions, \
			struct kg2_option *options,  \
			krb5_data *kmsg, \
			krb5_data *mic)
version		SUNWprivate_1.1
end

function	krb5_gss_import_name
include		<gssapiP_krb5.h>
declaration	OM_uint32 krb5_gss_import_name \
			(void *ctx, OM_uint32 *minor_status, \
			gss_buffer_t input_buffer_type, \
			gss_OID input_name_type, gss_name_t *output_name)
version		SUNWprivate_1.1
end

function	krb5_gss_init_sec_context
include		<gssapiP_krb5.h>
declaration	OM_uint32 krb5_gss_init_sec_context \
			(void *ct, OM_uint32 *context, \
			gss_cred_id_t cred_handle, \
			gss_ctx_id_t *context_handle, \
			gss_name_t target_name, gss_OID mech_type, \
			OM_uint32 req_flags, OM_uint32 time_req, \
			gss_channel_bindings_t input_chan_bindings, \
			gss_buffer_t input_token, gss_OID *actual_mech_type, \
			gss_buffer_t output_token, \
			OM_uint32 *ret_flags, OM_uint32 *time_rec)
version		SUNWprivate_1.1
end

function	gssspi_acquire_cred_with_password
include		<gssapiP_krb5.h>
declaration	OM_uint32 gssspi_acquire_cred_with_password \
			(void *ct ,\
                        OM_uint32 *minor_status ,\
                        const gss_name_t  desired_name ,\
                        const gss_buffer_t  password ,\
                        OM_uint32 time_req ,\
                        const gss_OID_set  desired_mechs ,\
                        gss_cred_usage_t cred_usage ,\
                        gss_cred_id_t *output_cred_handle ,\
                        gss_OID_set *actual_mechs ,\
                        OM_uint32 *time_rec)

version		SUNWprivate_1.1
end

data		krb5_gss_oid_array
declaration	const gss_OID_desc krb5_gss_oid_array[];
version		SUNWprivate_1.1
end
