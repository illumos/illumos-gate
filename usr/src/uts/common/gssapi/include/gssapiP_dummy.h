/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_GSSAPIP_DUMMY_H
#define	_GSSAPIP_DUMMY_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <gssapi/gssapi.h>

#define	SEC_CONTEXT_TOKEN 1
#define	DUMMY_SIZE_OF_INT 4

typedef void * dummy_token_t;

/* dummy name structure for internal representation. */
typedef struct {
	gss_OID type;
	gss_buffer_t buffer;
} dummy_name_desc, *dummy_name_t;

/* Structure for context handle */
typedef struct {
	OM_uint32 last_stat;
	int token_number;
	int established;
} dummy_gss_ctx_id_rec, *dummy_gss_ctx_id_t;

/* Dummy oid structure */
static const gss_OID_desc dummy_oids[] = {
	{10, "\053\006\001\004\001\052\002\032\001\002"},
};
const gss_OID_desc * const gss_mech_dummy = dummy_oids+0;
static const gss_OID_set_desc dummy_oidsets[] = {
	{1, (gss_OID) dummy_oids+0},
};
const gss_OID_set_desc * const gss_mech_set_dummy = dummy_oidsets+0;

#define	TWRITE_STR(ptr, str, len) \
	(void) memcpy((ptr), (char *) (str), (len)); \
	(ptr) += (len);
#ifndef	_KERNEL

#ifdef DEBUG_ON

#define	dprintf(a) printf(a)
#define	dprintf1(a, b) printf(a, b)

#else

#define	dprintf(a)
#define	dprintf1(a, b)
#define	DUMMY_STATIC

#endif	/* DEBUG_ON */

#else	/* _KERNEL */

#if defined(DEBUG) && !defined(DUMMY_MECH_DEBUG)
#define	DUMMY_MECH_DEBUG
#endif

#ifdef DUMMY_MECH_DEBUG
#define	DUMMY_MECH_LOG(A, B, C) \
	((void)((dummy_mech_log & (A)) && (printf((B), (C)), TRUE)))
#define	DUMMY_MECH_LOG0(A, B)   \
	((void)((dummy_mech_log & (A)) && (printf(B), TRUE)))
#else
#define	DUMMY_MECH_LOG(A, B, C)
#define	DUMMY_MECH_LOG0(A, B)

#endif

#define	dprintf(a)	DUMMY_MECH_LOG0(8, a)
#define	dprintf1(a, b)	DUMMY_MECH_LOG(8, a, b)
#define	DUMMY_STATIC	static

#endif	/* _KERNEL */

/*
 * declarations of internal name mechanism functions
 */

OM_uint32 dummy_gss_acquire_cred
	(
		void *,			/* dummy context */
		OM_uint32 *,		/* minor_status */
		gss_name_t,		/* desired_name */
		OM_uint32,		/* time_req */
		gss_OID_set,		/* desired_mechs */
		gss_cred_usage_t,	/* cred_usage */
		gss_cred_id_t *,	/* output_cred_handle */
		gss_OID_set *,		/* actual_mechs */
		OM_uint32 *		/* time_rec */
	/* */);

OM_uint32 dummy_gss_release_cred
	(
		void *,			/* dummy context */
		OM_uint32 *,		/* minor_status */
		gss_cred_id_t *		/* cred_handle */
	/* */);

OM_uint32 dummy_gss_init_sec_context
	(
		void *,			/* dummy context */
		OM_uint32 *,		/* minor_status */
		gss_cred_id_t,		/* claimant_cred_handle */
		gss_ctx_id_t *,		/* context_handle */
		gss_name_t,		/* target_name */
		gss_OID,		/* mech_type */
		OM_uint32,		/* req_flags */
		OM_uint32,		/* time_req */
		gss_channel_bindings_t, /* input_chan_bindings */
		gss_buffer_t,		/* input_token */
		gss_OID *,		/* actual_mech_type */
		gss_buffer_t,		/* output_token */
		OM_uint32 *,		/* ret_flags */
		OM_uint32 *		/* time_rec */
	/* */);

OM_uint32 dummy_gss_accept_sec_context
	(
		void *,			/* dummy context */
		OM_uint32 *,		/* minor_status */
		gss_ctx_id_t *,		/* context_handle */
		gss_cred_id_t,		/* verifier_cred_handle */
		gss_buffer_t,		/* input_token_buffer */
		gss_channel_bindings_t, /* input_chan_bindings */
		gss_name_t *,		/* src_name */
		gss_OID *,		/* mech_type */
		gss_buffer_t,		/* output_token */
		OM_uint32 *,		/* ret_flags */
		OM_uint32 *,		/* time_rec */
		gss_cred_id_t *		/* delegated_cred_handle */
	/* */);

OM_uint32 dummy_gss_process_context_token
	(
		void *,			/* dummy context */
		OM_uint32 *,		/* minor_status */
		gss_ctx_id_t,		/* context_handle */
		gss_buffer_t		/* token_buffer */
	/* */);

DUMMY_STATIC OM_uint32 dummy_gss_delete_sec_context
	(
		void *,			/* dummy context */
		OM_uint32 *,		/* minor_status */
		gss_ctx_id_t *,		/* context_handle */
		gss_buffer_t		/* output_token */
#ifdef	_KERNEL
	/* */, OM_uint32
#endif
	/* */);

OM_uint32 dummy_gss_context_time
	(
		void *,			/* dummy context */
		OM_uint32 *,		/* minor_status */
		gss_ctx_id_t,		/* context_handle */
		OM_uint32 *		/* time_rec */
	/* */);

DUMMY_STATIC OM_uint32 dummy_gss_sign
	(
		void *,			/* dummy context */
		OM_uint32 *,		/* minor_status */
		gss_ctx_id_t,		/* context_handle */
		int,			/* qop_req */
		gss_buffer_t,		/* message_buffer */
		gss_buffer_t		/* message_token */
#ifdef	_KERNEL
	/* */, OM_uint32
#endif
	/* */);

DUMMY_STATIC OM_uint32 dummy_gss_verify
	(
		void *,			/* dummy context */
		OM_uint32 *,		/* minor_status */
		gss_ctx_id_t,		/* context_handle */
		gss_buffer_t,		/* message_buffer */
		gss_buffer_t,		/* token_buffer */
		int *			/* qop_state */
#ifdef	_KERNEL
	/* */, OM_uint32

#endif
	/* */);

DUMMY_STATIC OM_uint32 dummy_gss_seal
	(
		void *,			/* dummy context */
		OM_uint32 *,		/* minor_status */
		gss_ctx_id_t,		/* context_handle */
		int,			/* conf_req_flag */
		int,			/* qop_req */
		gss_buffer_t,		/* input_message_buffer */
		int *,			/* conf_state */
		gss_buffer_t		/* output_message_buffer */
#ifdef	_KERNEL
	/* */, OM_uint32
#endif
	/* */);

DUMMY_STATIC OM_uint32 dummy_gss_unseal
	(
		void *,			/* dummy context */
		OM_uint32 *,		/* minor_status */
		gss_ctx_id_t,		/* context_handle */
		gss_buffer_t,		/* input_message_buffer */
		gss_buffer_t,		/* output_message_buffer */
		int *,			/* conf_state */
		int *			/* qop_state */
#ifdef	_KERNEL
	/* */, OM_uint32
#endif
	/* */);

OM_uint32 dummy_gss_display_status
	(
		void *,			/* dummy context */
		OM_uint32 *,		/* minor_status */
		OM_uint32,		/* status_value */
		int,			/* status_type */
		gss_OID,		/* mech_type */
		OM_uint32 *,		/* message_context */
		gss_buffer_t		/* status_string */
	/* */);

OM_uint32 dummy_gss_indicate_mechs
	(
		void *,			/* dummy context */
		OM_uint32 *,		/* minor_status */
		gss_OID_set *		/* mech_set */
	/* */);

OM_uint32 dummy_gss_compare_name
	(
		void *,			/* dummy context */
		OM_uint32 *,		/* minor_status */
		gss_name_t,		/* name1 */
		gss_name_t,		/* name2 */
		int *			/* name_equal */
	/* */);

OM_uint32 dummy_gss_display_name
	(
		void *,			/* dummy context */
		OM_uint32 *,		/* minor_status */
		gss_name_t,		/* input_name */
		gss_buffer_t,		/* output_name_buffer */
		gss_OID *		/* output_name_type */
	/* */);

OM_uint32 dummy_gss_import_name
	(
		void *,			/* dummy context */
		OM_uint32 *,		/* minor_status */
		gss_buffer_t,		/* input_name_buffer */
		gss_OID,		/* input_name_type */
		gss_name_t *		/* output_name */
	/* */);

OM_uint32 dummy_gss_release_name
	(
		void *,			/* dummy context */
		OM_uint32 *,		/* minor_status */
		gss_name_t *		/* input_name */
	/* */);

OM_uint32 dummy_gss_inquire_cred
	(
		void *,			/* dummy context */
		OM_uint32 *,		/* minor_status */
		gss_cred_id_t,		/* cred_handle */
		gss_name_t *,		/* name */
		OM_uint32 *,		/* lifetime */
		gss_cred_usage_t *,	/* cred_usage */
		gss_OID_set *		/* mechanisms */
	/* */);

OM_uint32 dummy_gss_inquire_context
	(
		void *,			/* dummy context */
		OM_uint32 *,		/* minor_status */
		gss_ctx_id_t,		/* context_handle */
		gss_name_t *,		/* initiator_name */
		gss_name_t *,		/* acceptor_name */
		OM_uint32 *,		/* lifetime_rec */
		gss_OID *,		/* mech_type */
		OM_uint32 *,		/* ret_flags */
		int *,			/* locally_initiated */
		int *			/* open */
	/* */);

/* New V2 entry points */
OM_uint32 dummy_gss_get_mic
	(
		void *,			/* dummy context */
		OM_uint32 *,		/* minor_status */
		gss_ctx_id_t,		/* context_handle */
		gss_qop_t,		/* qop_req */
		gss_buffer_t,		/* message_buffer */
		gss_buffer_t		/* message_token */
	/* */);

OM_uint32 dummy_gss_verify_mic
	(
		void *,			/* dummy context */
		OM_uint32 *,		/* minor_status */
		gss_ctx_id_t,		/* context_handle */
		gss_buffer_t,		/* message_buffer */
		gss_buffer_t,		/* message_token */
		gss_qop_t *		/* qop_state */
	/* */);

OM_uint32 dummy_gss_wrap
	(
		void *,			/* dummy context */
		OM_uint32 *,		/* minor_status */
		gss_ctx_id_t,		/* context_handle */
		int,			/* conf_req_flag */
		gss_qop_t,		/* qop_req */
		gss_buffer_t,		/* input_message_buffer */
		int *,			/* conf_state */
		gss_buffer_t		/* output_message_buffer */
	/* */);

OM_uint32 dummy_gss_unwrap
	(
		void *,			/* dummy context */
		OM_uint32 *,		/* minor_status */
		gss_ctx_id_t,		/* context_handle */
		gss_buffer_t,		/* input_message_buffer */
		gss_buffer_t,		/* output_message_buffer */
		int *,			/* conf_state */
		gss_qop_t *		/* qop_state */
	/* */);

OM_uint32 dummy_gss_wrap_size_limit
	(
		void *,			/* dummy context */
		OM_uint32 *,		/* minor_status */
		gss_ctx_id_t,		/* context_handle */
		int,			/* conf_req_flag */
		gss_qop_t,		/* qop_req */
		OM_uint32,		/* req_output_size */
		OM_uint32 *		/* max_input_size */
	/* */);

OM_uint32 dummy_gss_add_cred
	(
		void *,			/* dummy context */
		OM_uint32 *,		/* minor_status */
		gss_cred_id_t,		/* input_cred_handle */
		gss_name_t,		/* desired_name */
		gss_OID,		/* desired_mech */
		gss_cred_usage_t,	/* cred_usage */
		OM_uint32,		/* initiator_time_req */
		OM_uint32,		/* acceptor_time_req */
		gss_cred_id_t *,	/* output_cred_handle */
		gss_OID_set *,		/* actual_mechs */
		OM_uint32 *,		/* initiator_time_rec */
		OM_uint32 *		/* acceptor_time_rec */
	/* */);

OM_uint32 dummy_gss_inquire_cred_by_mech
	(
		void *,			/* dummy context */
		OM_uint32  *,		/* minor_status */
		gss_cred_id_t,		/* cred_handle */
		gss_OID,		/* mech_type */
		gss_name_t *,		/* name */
		OM_uint32 *,		/* initiator_lifetime */
		OM_uint32 *,		/* acceptor_lifetime */
		gss_cred_usage_t *	/* cred_usage */
	/* */);

OM_uint32 dummy_gss_export_sec_context
	(
		void *,			/* dummy context */
		OM_uint32 *,		/* minor_status */
		gss_ctx_id_t *,		/* context_handle */
		gss_buffer_t		/* interprocess_token */
	/* */);

OM_uint32 dummy_gss_import_sec_context
	(
		void *,			/* dummy context */
		OM_uint32 *,		/* minor_status */
		gss_buffer_t,		/* interprocess_token */
		gss_ctx_id_t *		/* context_handle */
	/* */);

#if 0
OM_uint32 dummy_gss_release_oid
	(
		OM_uint32 *,		/* minor_status */
		gss_OID *		/* oid */
	/* */);
#endif

OM_uint32 dummy_gss_internal_release_oid
	(
		void *,			/* dummy context  */
		OM_uint32 *,		/* minor_status */
		gss_OID *		/* oid */
	/* */);

OM_uint32 dummy_gss_inquire_names_for_mech
	(
		void *,		/* dummy context */
		OM_uint32 *,		/* minor_status */
		gss_OID,		/* mechanism */
		gss_OID_set *		/* name_types */
	/* */);

OM_uint32 dummy_pname_to_uid
	(
		void *,			/* dummy context */
		OM_uint32 *,		/* minor status */
		const gss_name_t,	/* pname */
		uid_t *			/* uidOut */
	/* */);


#ifdef	__cplusplus
}
#endif

#endif /* _GSSAPIP_DUMMY_H */
