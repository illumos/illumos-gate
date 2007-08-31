/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_GSSAPIP_SPNEGO_H_
#define	_GSSAPIP_SPNEGO_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <gssapi/gssapi.h>
#include <synch.h>
#include <syslog.h>

#define	SEC_CONTEXT_TOKEN 1
#define	SPNEGO_SIZE_OF_INT 4

#define	ACCEPT_COMPLETE 0
#define	ACCEPT_INCOMPLETE 1
#define	REJECT 2
#define	ACCEPT_DEFECTIVE_TOKEN 3

/*
 * constants for der encoding/decoding routines.
 */

#define	MECH_OID		0x06
#define	OCTET_STRING		0x04
#define	CONTEXT			0xa0
#define	SEQUENCE		0x30
#define	SEQUENCE_OF		0x30
#define	ENUMERATED		0x0a
#define	ENUMERATION_LENGTH	1
#define	HEADER_ID		0x60

/*
 * SPNEGO specific error codes (minor status codes)
 */
#define	ERR_SPNEGO_NO_MECHS_AVAILABLE		0x20000001
#define	ERR_SPNEGO_NO_CREDS_ACQUIRED		0x20000002
#define	ERR_SPNEGO_NO_MECH_FROM_ACCEPTOR	0x20000003
#define	ERR_SPNEGO_NEGOTIATION_FAILED		0x20000004
#define	ERR_SPNEGO_NO_TOKEN_FROM_ACCEPTOR	0x20000005
#define	ERR_SPNEGO_BAD_INPUT_PARAMETER		0x20000006

/*
 * send_token_flag is used to indicate in later steps what type
 * of token, if any should be sent or processed.
 * NO_TOKEN_SEND = no token should be sent
 * INIT_TOKEN_SEND = initial token will be sent
 * CONT_TOKEN_SEND = continuing tokens to be sent
 * CHECK_MIC = no token to be sent, but have a MIC to check.
 * ERROR_TOKEN_SEND = error token from peer needs to be sent.
 */

typedef	enum {NO_TOKEN_SEND, INIT_TOKEN_SEND, CONT_TOKEN_SEND,
		CHECK_MIC, ERROR_TOKEN_SEND} send_token_flag;

/*
 * The Mech OID:
 * { iso(1) org(3) dod(6) internet(1) security(5)
 *  mechanism(5) spnego(2) }
 */

#define	SPNEGO_OID_LENGTH 6
#define	SPNEGO_OID "\053\006\001\005\005\002"

typedef void *spnego_token_t;

/* Structure for context handle */
typedef struct {
	gss_buffer_desc DER_mechTypes;
	gss_OID internal_mech;
	gss_ctx_id_t ctx_handle;
	char  *optionStr;
	int MS_Interop;
	int optimistic;
	OM_uint32 last_status;
} spnego_gss_ctx_id_rec, *spnego_gss_ctx_id_t;

/* SPNEGO oid structure */
static const gss_OID_desc spnego_oids[] = {
	{SPNEGO_OID_LENGTH, SPNEGO_OID},
};

const gss_OID_desc * const gss_mech_spnego = spnego_oids+0;
static const gss_OID_set_desc spnego_oidsets[] = {
	{1, (gss_OID) spnego_oids+0},
};
const gss_OID_set_desc * const gss_mech_set_spnego = spnego_oidsets+0;

#define	TWRITE_STR(ptr, str, len) \
	memcpy((ptr), (char *)(str), (len)); \
	(ptr) += (len);

#ifdef DEBUG
#define	dsyslog(a) syslog(LOG_DEBUG, a)
#else
#define	dsyslog(a)
#define	SPNEGO_STATIC
#endif	/* DEBUG */

/*
 * declarations of internal name mechanism functions
 */

OM_uint32 spnego_gss_acquire_cred
(
	void *,			/* spnego context */
	OM_uint32 *,		/* minor_status */
	gss_name_t,		/* desired_name */
	OM_uint32,		/* time_req */
	gss_OID_set,		/* desired_mechs */
	gss_cred_usage_t,	/* cred_usage */
	gss_cred_id_t *,	/* output_cred_handle */
	gss_OID_set *,		/* actual_mechs */
	OM_uint32 *		/* time_rec */
);

OM_uint32 spnego_gss_release_cred
(
	void *,			/* spnego context */
	OM_uint32 *,		/* minor_status */
	/* CSTYLED */
	gss_cred_id_t	*	/* cred_handle */
);

OM_uint32 spnego_gss_init_sec_context
(
	void *,			/* spnego context */
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
);

OM_uint32 spnego_gss_accept_sec_context
(
	void *,			/* spnego context */
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
	/* CSTYLED */
	gss_cred_id_t *		/* delegated_cred_handle */
);

OM_uint32 spnego_gss_display_name
(
	void *,
	OM_uint32 *,		/* minor_status */
	gss_name_t,		/*  input_name */
	gss_buffer_t,		/*  output_name_buffer */
	gss_OID *		/* output_name_type */
);

OM_uint32 spnego_gss_display_status
(
	void *,			/* spnego context */
	OM_uint32 *,		/* minor_status */
	OM_uint32,		/* status_value */
	int,			/* status_type */
	gss_OID,		/* mech_type */
	OM_uint32 *,		/* message_context */
	gss_buffer_t		/* status_string */
);

OM_uint32 spnego_gss_import_name
(
	void *,			/* spnego context */
	OM_uint32 *,		/* minor_status */
	gss_buffer_t,		/* input_name_buffer */
	gss_OID,		/* input_name_type */
	/* CSTYLED */
	gss_name_t *		/* output_name */
);

OM_uint32 spnego_gss_release_name
(
	void *,			/* spnego context */
	OM_uint32 *,		/* minor_status */
	/* CSTYLED */
	gss_name_t *		/* input_name */
);

OM_uint32 spnego_gss_inquire_names_for_mech
(
	void *,			/* spnego context */
	OM_uint32 *,		/* minor_status */
	gss_OID,		/* mechanism */
	gss_OID_set *		/* name_types */
);

OM_uint32 spnego_gss_unseal
(
	void *context,
	OM_uint32 *minor_status,
	gss_ctx_id_t context_handle,
	gss_buffer_t input_message_buffer,
	gss_buffer_t output_message_buffer,
	int *conf_state,
	int *qop_state
);

OM_uint32 spnego_gss_seal
(
	void *context,
	OM_uint32 *minor_status,
	gss_ctx_id_t context_handle,
	int conf_req_flag,
	int qop_req,
	gss_buffer_t input_message_buffer,
	int *conf_state,
	gss_buffer_t output_message_buffer
);

OM_uint32 spnego_gss_process_context_token
(
	void *context,
	OM_uint32	*minor_status,
	const gss_ctx_id_t context_handle,
	const gss_buffer_t token_buffer
);

OM_uint32 spnego_gss_delete_sec_context
(
	void *context,
	OM_uint32 *minor_status,
	gss_ctx_id_t *context_handle,
	gss_buffer_t output_token
);

OM_uint32 spnego_gss_context_time
(
	void *context,
	OM_uint32	*minor_status,
	const gss_ctx_id_t context_handle,
	OM_uint32	*time_rec
);

OM_uint32 spnego_gss_export_sec_context
(
	void *context,
	OM_uint32	*minor_status,
	gss_ctx_id_t	*context_handle,
	gss_buffer_t	interprocess_token
);

OM_uint32 spnego_gss_import_sec_context
(
	void			*context,
	OM_uint32		*minor_status,
	const gss_buffer_t	interprocess_token,
	gss_ctx_id_t		*context_handle
);

OM_uint32 spnego_gss_inquire_context
(
	void		*context,
	OM_uint32	*minor_status,
	const gss_ctx_id_t context_handle,
	gss_name_t	*src_name,
	gss_name_t	*targ_name,
	OM_uint32	*lifetime_rec,
	gss_OID		*mech_type,
	OM_uint32	*ctx_flags,
	int		*locally_initiated,
	int		*open
);

OM_uint32 spnego_gss_wrap_size_limit
(
	void		*context,
	OM_uint32	*minor_status,
	const gss_ctx_id_t context_handle,
	int		conf_req_flag,
	gss_qop_t	qop_req,
	OM_uint32	req_output_size,
	OM_uint32	*max_input_size
);

OM_uint32 spnego_gss_sign
(
	void *context,
	OM_uint32 *minor_status,
	const gss_ctx_id_t context_handle,
	int  qop_req,
	const gss_buffer_t message_buffer,
	gss_buffer_t message_token
);

OM_uint32 spnego_gss_verify
(
	void *context,
	OM_uint32 *minor_status,
	const gss_ctx_id_t context_handle,
	const gss_buffer_t msg_buffer,
	const gss_buffer_t token_buffer,
	int *qop_state
);

OM_uint32 spnego_gss_inquire_cred
(
	void *context,
	OM_uint32 *minor_status,
	const gss_cred_id_t cred_handle,
	gss_name_t  *name,
	OM_uint32 *lifetime,
	gss_cred_usage_t *cred_usage,
	gss_OID_set *mechanisms
);


#ifdef	__cplusplus
}
#endif

#endif /* _GSSAPIP_SPNEGO_H_ */
