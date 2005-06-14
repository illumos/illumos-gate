#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libgss/spec/gss.spec

data		GSS_C_NT_USER_NAME
version		SUNW_1.2
end		

data		GSS_C_NT_MACHINE_UID_NAME
version		SUNW_1.2
end		

data		GSS_C_NT_STRING_UID_NAME
version		SUNW_1.2
end		

data		GSS_C_NT_HOSTBASED_SERVICE
version		SUNW_1.2
end		

data		GSS_C_NT_ANONYMOUS
version		SUNW_1.2
end		

data		GSS_C_NT_EXPORT_NAME
version		SUNW_1.2
end		

function	gss_release_oid_set
include		<gssapi/gssapi.h>
declaration	OM_uint32 gss_release_oid_set( \
			OM_uint32 *minor_status ,\
			gss_OID_set *set)
version		SUNW_1.2
exception	$return != 0
end

function	gss_acquire_cred
include		<gssapi/gssapi.h>
declaration 	OM_uint32 gss_acquire_cred(  \
			OM_uint32 *minor_status ,\
			const gss_name_t  desired_name ,\
			OM_uint32 time_req ,\
			const gss_OID_set  desired_mechs ,\
			gss_cred_usage_t cred_usage ,\
			gss_cred_id_t *output_cred_handle ,\
			gss_OID_set *actual_mechs ,\
			OM_uint32 *time_rec)
version		SUNW_1.2
exception	$return != 0
end		

function	gss_acquire_cred_with_password
include		<gssapi/gssapi_ext.h>
declaration 	OM_uint32 gss_acquire_cred_with_password(  \
			OM_uint32 *minor_status ,\
			const gss_name_t  desired_name ,\
			const gss_buffer_t  password ,\
			OM_uint32 time_req ,\
			const gss_OID_set  desired_mechs ,\
			gss_cred_usage_t cred_usage ,\
			gss_cred_id_t *output_cred_handle ,\
			gss_OID_set *actual_mechs ,\
			OM_uint32 *time_rec)
version		SUNW_1.2
exception	$return != 0
end		

function	gss_release_cred
include		<gssapi/gssapi.h>
declaration	OM_uint32 gss_release_cred( \
			OM_uint32 * minor_status,\
		 	gss_cred_id_t *	cred_handle \
		)
version		SUNW_1.2
exception	$return != 0
end		

function	gss_init_sec_context
include		<gssapi/gssapi.h>
declaration 	OM_uint32 gss_init_sec_context( \
			OM_uint32 * minor_status ,\
			const gss_cred_id_t initiator_cred_hdle,\
			gss_ctx_id_t * context_handle  ,\
			const gss_name_t target_name  ,\
			const gss_OID mech_type  ,\
			OM_uint32 req_flags  ,\
			OM_uint32 time_req  ,\
			gss_channel_bindings_t input_chan_bindings  ,\
			const gss_buffer_t input_token  ,\
			gss_OID * actual_mech_type ,\
			gss_buffer_t output_token  ,\
			OM_uint32 * ret_flags  ,\
			OM_uint32 * time_rec \
			)
version		SUNW_1.2
exception	$return != 0
end		

function	gss_accept_sec_context
include		<gssapi/gssapi.h>
declaration	OM_uint32 gss_accept_sec_context(  \
			OM_uint32 * minor_status   ,\
			gss_ctx_id_t * context_handle   ,\
			const gss_cred_id_t acceptor_cred_hdle   ,\
			const gss_buffer_t input_token_buffer   ,\
			const gss_channel_bindings_t input_chan_bindings   ,\
			gss_name_t * src_name   ,\
			gss_OID * mech_type   ,\
			gss_buffer_t output_token   ,\
			OM_uint32 * ret_flags   ,\
			OM_uint32 * time_rec   ,\
			gss_cred_id_t *	delegated_cred_hdle \
			)
version		SUNW_1.2
exception	$return != 0
end		

function	gss_process_context_token
include		<gssapi/gssapi.h>
declaration 	OM_uint32 gss_process_context_token(  \
		OM_uint32 * minor_status   ,\
		const gss_ctx_id_t context_handle   ,\
		const gss_buffer_t	 token_buffer   \
		)
version		SUNW_1.2
exception	$return != 0
end		

function	gss_delete_sec_context
include		<gssapi/gssapi.h>
declaration OM_uint32 gss_delete_sec_context(  \
		OM_uint32 * minor_status   ,\
		gss_ctx_id_t * context_handle   ,\
		gss_buffer_t	output_token   \
		)
version		SUNW_1.2
exception	$return != 0
end		

function	gss_context_time
include		<gssapi/gssapi.h>
declaration	OM_uint32 gss_context_time(  \
		OM_uint32 * minor_status   ,\
		const gss_ctx_id_t context_handle   ,\
		OM_uint32 * time_rec   \
		)
version		SUNW_1.2
exception	$return != 0
end		

function	gss_display_status
include		<gssapi/gssapi.h>
declaration	OM_uint32 gss_display_status(  \
			OM_uint32 * minor_status   ,\
			OM_uint32 status_value   ,\
			int status_type   ,\
			const gss_OID mech_type   ,\
			OM_uint32 * message_context   ,\
			gss_buffer_t	status_string   \
			)
version		SUNW_1.2
exception	$return != 0
end

function	gss_indicate_mechs
include		<gssapi/gssapi.h>
declaration 	OM_uint32 gss_indicate_mechs(  \
			OM_uint32 * minor_status   ,\
			gss_OID_set * mech_set   \
		)
version		SUNW_1.2
exception	$return != 0
end		

function	gss_compare_name
include		<gssapi/gssapi.h>
declaration 	OM_uint32 gss_compare_name(  \
		OM_uint32 * minor_status   ,\
		const gss_name_t name1   ,\
		const gss_name_t name2   ,\
		int * name_equal   \
		)
version		SUNW_1.2
exception	$return != 0
end		

function	gss_display_name
include		<gssapi/gssapi.h>
declaration 	OM_uint32 gss_display_name(  \
			OM_uint32 * minor_status   ,\
			const gss_name_t input_name   ,\
			gss_buffer_t output_name_buffer   ,\
			gss_OID * output_name_type   \
		)
version		SUNW_1.2
exception	$return != 0
end		

function	gss_import_name
include		<gssapi/gssapi.h>
declaration 	OM_uint32 gss_import_name(  \
			OM_uint32 * minor_status   ,\
			const gss_buffer_t input_name_buffer   ,\
			const gss_OID input_name_type   ,\
			gss_name_t * output_name   \
			)
version		SUNW_1.2
exception	$return != 0
end		

function	gss_release_name
include		<gssapi/gssapi.h>
declaration 	OM_uint32 gss_release_name(  \
			OM_uint32 * minor_status   ,\
			gss_name_t * input_name \
		)
version		SUNW_1.2
exception	$return != 0
end		

function	gss_release_buffer
include		<gssapi/gssapi.h>
declaration 	OM_uint32 gss_release_buffer(  \
			OM_uint32 * minor_status   ,\
			gss_buffer_t	buffer   \
				)
version		SUNW_1.2
exception	$return != 0
end		


function	gss_inquire_cred
include		<gssapi/gssapi.h>
declaration	OM_uint32 gss_inquire_cred(  \
			OM_uint32 * minor_status   ,\
			const gss_cred_id_t cred_handle   ,\
			gss_name_t * name   ,\
			OM_uint32 * lifetime   ,\
			gss_cred_usage_t * cred_usage   ,\
			gss_OID_set * mechanisms   \
		)
version		SUNW_1.2
exception	$return != 0
end		

function	gss_inquire_context
include		<gssapi/gssapi.h>
declaration 	OM_uint32 gss_inquire_context(  \
			OM_uint32 * minor_status   ,\
			const gss_ctx_id_t context_handle   ,\
			gss_name_t * src_name   ,\
			gss_name_t * targ_name   ,\
			OM_uint32 * lifetime_rec   ,\
			gss_OID * mech_type   ,\
			OM_uint32 * ctx_flags   ,\
			int *	locally_initiated   ,\
			int * open   \
		)
version		SUNW_1.2
exception	$return != 0
end		

function	gss_get_mic
include		<gssapi/gssapi.h>
declaration 	OM_uint32 gss_get_mic(  \
			OM_uint32 * minor_status   ,\
			const gss_ctx_id_t context_handle   ,\
			gss_qop_t qop_req   ,\
			const gss_buffer_t message_buffer   ,\
			gss_buffer_t message_token  \
			)
version		SUNW_1.2
exception	$return != 0
end		

function	gss_verify_mic
include		<gssapi/gssapi.h>
declaration 	OM_uint32 gss_verify_mic(  \
			OM_uint32 * minor_status   ,\
			const gss_ctx_id_t context_handle   ,\
			const gss_buffer_t message_buffer   ,\
			const gss_buffer_t token_buffer   ,\
			gss_qop_t * qop_state  \
			)
version		SUNW_1.2
exception	$return != 0
end		

function	gss_wrap
include		<gssapi/gssapi.h>
declaration 	OM_uint32 gss_wrap(  \
			OM_uint32 * minor_status   ,\
			const gss_ctx_id_t context_handle   ,\
			int conf_req_flag   ,\
			gss_qop_t qop_req   ,\
			const gss_buffer_t input_message_bfer   ,\
			int * conf_state   ,\
			gss_buffer_t output_message_bfer   \
		)
version		SUNW_1.2
exception	$return != 0
end		

function	gss_unwrap
include		<gssapi/gssapi.h>
declaration 	OM_uint32 gss_unwrap(  \
			OM_uint32 * minor_status   ,\
			const gss_ctx_id_t context_handle   ,\
			const gss_buffer_t input_message_bfer   ,\
			gss_buffer_t output_message_bfer   ,\
			int * 	 conf_state   ,\
			gss_qop_t *		 qop_state   \
		)		
version		SUNW_1.2
exception	$return != 0
end

function	gss_wrap_size_limit
include		<gssapi/gssapi.h>
declaration 	OM_uint32 gss_wrap_size_limit(  \
			OM_uint32 * minor_status   ,\
			const gss_ctx_id_t context_handle   ,\
			int 	 conf_req_flag   ,\
			gss_qop_t qop_req   ,\
			OM_uint32 req_output_size   ,\
			OM_uint32 *		 max_input_size   \
			)
version		SUNW_1.2
exception	$return != 0
end		

function	gss_export_name
include		<gssapi/gssapi.h>
declaration 	OM_uint32 gss_export_name( \
			OM_uint32 * minor_status   ,\
			const gss_name_t 	 input_name   ,\
			gss_buffer_t 		 exported_name   \
			)
version		SUNW_1.2
exception	$return != 0
end		

function	gss_add_cred
include		<gssapi/gssapi.h>
declaration 	OM_uint32 gss_add_cred(  \
			OM_uint32 * minor_status   ,\
			const gss_cred_id_t input_cred_handle   ,\
			const gss_name_t desired_name   ,\
			const gss_OID desired_mech   ,\
			gss_cred_usage_t cred_usage   ,\
			OM_uint32 initiator_time_req   ,\
			OM_uint32 acceptor_time_req   ,\
			gss_cred_id_t * output_cred_handle   ,\
			gss_OID_set * actual_mechs   ,\
			OM_uint32 * initiator_time_rec   ,\
			OM_uint32 * acceptor_time_rec   \
		)
version		SUNW_1.2
exception	$return != 0
end		

function	gss_add_cred_with_password
include		<gssapi/gssapi_ext.h>
declaration 	OM_uint32 gss_add_cred_with_password(  \
			OM_uint32 * minor_status   ,\
			const gss_cred_id_t input_cred_handle   ,\
			const gss_name_t desired_name   ,\
			const gss_OID desired_mech   ,\
			const gss_buffer_t password   ,\
			gss_cred_usage_t cred_usage   ,\
			OM_uint32 initiator_time_req   ,\
			OM_uint32 acceptor_time_req   ,\
			gss_cred_id_t * output_cred_handle   ,\
			gss_OID_set * actual_mechs   ,\
			OM_uint32 * initiator_time_rec   ,\
			OM_uint32 * acceptor_time_rec   \
		)
version		SUNW_1.2
exception	$return != 0
end		

function	gss_store_cred
include		<gssapi/gssapi.h>
declaration 	OM_uint32 gss_store_cred(  \
			OM_uint32 * minor_status   ,\
			const gss_cred_id_t input_cred_handle   ,\
			gss_cred_usage_t cred_usage   ,\
			const gss_OID desired_mech   ,\
			OM_uint32 overwrite_cred   ,\
			OM_uint32 default_cred   ,\
			gss_OID_set * elements_stored   ,\
			gss_cred_usage_t * cred_usage_stored   \
		)
version		SUNW_1.2
exception	$return != 0
end		

function	gss_inquire_cred_by_mech
include		<gssapi/gssapi.h>
declaration 	OM_uint32 gss_inquire_cred_by_mech(  \
			OM_uint32 * minor_status   ,\
			const gss_cred_id_t cred_handle   ,\
			const gss_OID mech_type   ,\
			gss_name_t * name   ,\
			OM_uint32 * initiator_lifetime   ,\
			OM_uint32 * acceptor_lifetime   ,\
			gss_cred_usage_t * cred_usage  \
		)
version		SUNW_1.2
exception	$return != 0
end		

function	gss_export_sec_context
include		<gssapi/gssapi.h>
declaration 	OM_uint32 gss_export_sec_context(  \
			OM_uint32 * minor_status   ,\
			gss_ctx_id_t * context_handle   ,\
			gss_buffer_t interprocess_token   \
)
version		SUNW_1.2
exception	$return != 0
end		

function	gss_import_sec_context
include		<gssapi/gssapi.h>
declaration 	OM_uint32 gss_import_sec_context(  \
			OM_uint32 * minor_status   ,\
			const gss_buffer_t interprocess_token   ,\
			gss_ctx_id_t *	 context_handle   \
		)
version		SUNW_1.2
exception	$return != 0
end		

function	gss_release_oid
include		<gssapi/gssapi.h>
declaration 	OM_uint32 gss_release_oid(  \
			OM_uint32 * minor_status   ,\
			gss_OID * oid   \
		)
version		SUNW_1.2
exception	$return != 0
end		

function	gss_create_empty_oid_set
include		<gssapi/gssapi.h>
declaration 	OM_uint32 gss_create_empty_oid_set(  \
			OM_uint32 *  minor_status   ,\
			gss_OID_set * oid_set   \
			)
version		SUNW_1.2
exception	$return != 0
end		

function	gss_add_oid_set_member
include		<gssapi/gssapi.h>
declaration 	OM_uint32 gss_add_oid_set_member(  \
			OM_uint32 *  minor_status   ,\
			const gss_OID 	member_oid   ,\
			gss_OID_set *	oid_set   \
		)
version		SUNW_1.2
exception	$return != 0
end		

function	gss_test_oid_set_member
include		<gssapi/gssapi.h>
declaration 	OM_uint32 gss_test_oid_set_member(  \
			OM_uint32 *  minor_status   ,\
			const gss_OID  member   ,\
			const gss_OID_set set   ,\
			int *present)
version		SUNW_1.2
exception	$return != 0
end		

function	gss_str_to_oid
include		<gssapi/gssapi.h>
declaration	OM_uint32 gss_str_to_oid(  \
			OM_uint32 * minor_status   ,\
			const gss_buffer_t oid_str   ,\
			gss_OID * oid   \
		)
version		SUNWprivate_1.1
exception	$return != 0
end		


function	gss_inquire_names_for_mech
include		<gssapi/gssapi.h>
declaration	OM_uint32 gss_inquire_names_for_mech(  \
			OM_uint32 *  minor_status   ,\
			const gss_OID 	 mechanism   ,\
			gss_OID_set *		 name_types   \
		)
version		SUNW_1.2
exception	$return != 0
end		

function	gss_inquire_mechs_for_name
include		<gssapi/gssapi.h>
declaration	OM_uint32 gss_inquire_mechs_for_name(  \
			OM_uint32 * 	 minor_status   ,\
			const gss_name_t  input_name   ,\
			gss_OID_set *		 mech_types   \
			)
version		SUNW_1.2
exception	$return != 0
end		

function	gss_canonicalize_name
include		<gssapi/gssapi.h>
declaration	OM_uint32 gss_canonicalize_name(  \
			OM_uint32 * 		 minor_status   ,\
			const gss_name_t 	 input_name   ,\
			const gss_OID 	 mech_type   ,\
			gss_name_t * 		 output_name   \
		)
version		SUNW_1.2
exception	$return != 0
end		

function	gss_duplicate_name
include		<gssapi/gssapi.h>
declaration 	OM_uint32 gss_duplicate_name(  \
			OM_uint32 * 		 minor_status   ,\
			const gss_name_t 	 src_name   ,\
			gss_name_t * 		 dest_name \
		)
version		SUNW_1.2
exception	$return != 0
end		

function	gss_sign
declaration 	OM_uint32 gss_sign(OM_uint32 *minor_status  ,\
			gss_ctx_id_t context_handle ,\
			int  qop_req,\
			gss_buffer_t  message_buffer ,\
			gss_buffer_t  message_token \
		)
version		SUNW_1.2
exception	$return != 0
end		

function	gss_verify
declaration 	OM_uint32 gss_verify( \
			OM_uint32 *minor_status ,\
			gss_ctx_id_t context_handle ,\
			gss_buffer_t message_buffer ,\
			gss_buffer_t 		  token_buffer,\
			int 	*qop_state \
		)
version		SUNW_1.2
exception	$return != 0
end		

function	gss_seal
declaration 	OM_uint32 gss_seal( \
			OM_uint32 *minor_status ,\
			gss_ctx_id_t context_handle ,\
			int conf_req_flag ,\
			int qop_req ,\
			gss_buffer_t input_message_bfer ,\
			int *conf_state ,\
			gss_buffer_t	output_message_bfer \
		)
version		SUNW_1.2
exception	$return != 0
end		

function	gss_unseal
declaration 	OM_uint32 gss_unseal( \
			OM_uint32 *minor_status ,\
			gss_ctx_id_t  context_handle ,\
			gss_buffer_t  input_message_bfer ,\
			gss_buffer_t  output_message_bfer ,\
			int *conf_state ,\
			int *qop_state \
		)
version		SUNW_1.2
exception	$return != 0
end		

function	gss_oid_to_str
version		SUNWprivate_1.1
end		

function	gss_copy_oid_set
declaration	OM_uint32 gss_copy_oid_set( \
			OM_uint32 *,\
			const gss_OID_set_desc *, \
			gss_OID_set *)
version		SUNWprivate_1.1
end		

data		gss_nt_exported_name
declaration	const gss_OID_desc * const gss_nt_exported_name;
version		SUNWprivate_1.1
end		

data		gss_nt_service_name
declaration	const gss_OID_desc * const gss_nt_service_name;
version		SUNWprivate_1.1
end		

data		gss_nt_service_name_v2
declaration	const gss_OID_desc * const gss_nt_service_name_v2;
version		SUNWprivate_1.1
end		

function	__gss_qop_to_num
version		SUNWprivate_1.1
end		

function	__gss_num_to_qop
version		SUNWprivate_1.1
end		

function	__gss_get_mech_info
version		SUNWprivate_1.1
end		

function	__gss_mech_qops
version		SUNWprivate_1.1
end		

function	__gss_mech_to_oid
version		SUNWprivate_1.1
end		

function	__gss_oid_to_mech
version		SUNWprivate_1.1
end		

function	__gss_get_mechanisms
version		SUNWprivate_1.1
end		

function	__gss_userok
declaration	OM_uint32 __gss_userok(\
			OM_uint32        *minor,\
			const gss_name_t  name,\
			const char        *user,\
			int               *user_ok)
version		SUNWprivate_1.1
end		

function	gsscred_expname_to_unix_cred
version		SUNWprivate_1.1
end		

function	gsscred_expname_to_unix_cred_ext
declaration	OM_uint32 gsscred_expname_to_unix_cred_ext(\
			const gss_buffer_t expName,\
			uid_t *uidOut,\
			gid_t *gidOut,\
			gid_t *gids[],\
			int *gidsLen,\
			int try_mech)
version		SUNWprivate_1.1
end		

function	gsscred_name_to_unix_cred
declaration	OM_uint32 gsscred_name_to_unix_cred( \
			const gss_name_t intName, \
			const gss_OID mechType, \
			uid_t *uidOut, \
			gid_t *gidOut, \
			gid_t *gids[], \
			int *gidsLen)
version		SUNWprivate_1.1
end		

function	gsscred_name_to_unix_cred_ext
declaration 	OM_uint32 gsscred_name_to_unix_cred_ext(\
			const gss_name_t intName,\
			const gss_OID mechType,\
			uid_t *uidOut,\
			gid_t *gidOut,\
			gid_t *gids[],\
			int *gidsLen,\
			int try_mech)
version		SUNWprivate_1.1
end		

function	gsscred_set_options
declaration	void gsscred_set_options(void)
version		SUNWprivate_1.1
end

function	gss_get_group_info
version		SUNWprivate_1.1
end		

function	__gss_get_modOptions
declaration	char * __gss_get_modOptions(const gss_OID)
version		SUNWprivate_1.1
end

function	__gss_get_kmodName
version		SUNWprivate_1.1
end

# Needed by mech_dummy.so to run rpcgss_sample with -m 2
function	generic_gss_copy_oid
version		SUNWprivate_1.1
end

# Needed by mech_dummy.so to run rpcgss_sample with -m 2
function	generic_gss_release_oid
version		SUNWprivate_1.1
end

function	__gss_get_mech_type
version		SUNWprivate_1.1
end

function	der_length_size
version		SUNWprivate_1.1
end		

function	get_der_length
version		SUNWprivate_1.1
end		

function	put_der_length
version		SUNWprivate_1.1
end		
