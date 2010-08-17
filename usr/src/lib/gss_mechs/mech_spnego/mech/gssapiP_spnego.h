/*
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */
#ifndef	_GSSAPIP_SPNEGO_H_
#define	_GSSAPIP_SPNEGO_H_

#ifdef	__cplusplus
extern "C" {
#endif

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include <syslog.h>

#define	SEC_CONTEXT_TOKEN 1
#define	SPNEGO_SIZE_OF_INT 4

#define	ACCEPT_COMPLETE 0
#define	ACCEPT_INCOMPLETE 1
#define	REJECT 2
#define REQUEST_MIC 3
#define	ACCEPT_DEFECTIVE_TOKEN 0xffffffffUL

/*
 * constants for der encoding/decoding routines.
 */

#define	MECH_OID		0x06
#define	OCTET_STRING		0x04
#define	CONTEXT			0xa0
#define	SEQUENCE		0x30
#define	SEQUENCE_OF		0x30
#define	BIT_STRING		0x03
#define	BIT_STRING_LENGTH	0x02
#define	BIT_STRING_PADDING	0x01
#define	ENUMERATED		0x0a
#define	ENUMERATION_LENGTH	1
#define	HEADER_ID		0x60
#define GENERAL_STRING		0x1b

/*
 * SPNEGO specific error codes (minor status codes)
 */
#define	ERR_SPNEGO_NO_MECHS_AVAILABLE		0x20000001
#define	ERR_SPNEGO_NO_CREDS_ACQUIRED		0x20000002
#define	ERR_SPNEGO_NO_MECH_FROM_ACCEPTOR	0x20000003
#define	ERR_SPNEGO_NEGOTIATION_FAILED		0x20000004
#define	ERR_SPNEGO_NO_TOKEN_FROM_ACCEPTOR	0x20000005

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

/* spnego name structure for internal representation. */
typedef struct {
	gss_OID type;
	gss_buffer_t buffer;
	gss_OID	mech_type;
	gss_name_t	mech_name;
} spnego_name_desc, *spnego_name_t;

/* Structure for context handle */
typedef struct {
	OM_uint32	magic_num;
	gss_buffer_desc DER_mechTypes;
	gss_OID internal_mech;
	gss_ctx_id_t ctx_handle;
	char  *optionStr;
	gss_cred_id_t default_cred;
	int mic_reqd;
	int mic_sent;
	int mic_rcvd;
	int firstpass;
	int mech_complete;
	int nego_done;
	OM_uint32 ctx_flags;
	gss_name_t internal_name;
	gss_OID actual_mech;
        struct errinfo err;
} spnego_gss_ctx_id_rec, *spnego_gss_ctx_id_t;

/*
 * The magic number must be less than a standard pagesize
 * to avoid a possible collision with a real address.
 */
#define	SPNEGO_MAGIC_ID  0x00000fed

/* SPNEGO oid declarations */
extern const gss_OID_desc * const gss_mech_spnego;
extern const gss_OID_set_desc * const gss_mech_set_spnego;


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
	OM_uint32 *,		/* minor_status */
	gss_name_t,		/* desired_name */
	OM_uint32,		/* time_req */
	gss_OID_set,		/* desired_mechs */
	gss_cred_usage_t,	/* cred_usage */
	gss_cred_id_t *,	/* output_cred_handle */
	gss_OID_set *,		/* actual_mechs */
	OM_uint32 *		/* time_rec */
);

OM_uint32 glue_spnego_gss_acquire_cred
(
	void *,
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
	OM_uint32 *,		/* minor_status */
	/* CSTYLED */
	gss_cred_id_t	*	/* cred_handle */
);

OM_uint32 glue_spnego_gss_release_cred
(
	void *,
	OM_uint32 *,		/* minor_status */
	/* CSTYLED */
	gss_cred_id_t	*	/* cred_handle */
);

OM_uint32 spnego_gss_init_sec_context
(
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

OM_uint32 glue_spnego_gss_init_sec_context
(
	void *,
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

#ifndef LEAN_CLIENT
OM_uint32 spnego_gss_accept_sec_context
(
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
OM_uint32 glue_spnego_gss_accept_sec_context
(
	void *,
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

#endif /* LEAN_CLIENT */

OM_uint32 spnego_gss_compare_name
(
	OM_uint32 *,		/* minor_status */
	const gss_name_t,	/* name1 */
	const gss_name_t,	/* name2 */
	int *			/* name_equal */
);

OM_uint32 glue_spnego_gss_compare_name
(
	void *,
	OM_uint32 *,		/* minor_status */
	const gss_name_t,	/* name1 */
	const gss_name_t,	/* name2 */
	int *			/* name_equal */
);

OM_uint32 spnego_gss_display_name
(
	OM_uint32 *,		/* minor_status */
	gss_name_t,		/*  input_name */
	gss_buffer_t,		/*  output_name_buffer */
	gss_OID *		/* output_name_type */
);

OM_uint32 glue_spnego_gss_display_name
(
	void *,
	OM_uint32 *,		/* minor_status */
	gss_name_t,		/*  input_name */
	gss_buffer_t,		/*  output_name_buffer */
	gss_OID *		/* output_name_type */
);

OM_uint32 spnego_gss_display_status
(
	OM_uint32 *,		/* minor_status */
	OM_uint32,		/* status_value */
	int,			/* status_type */
	gss_OID,		/* mech_type */
	OM_uint32 *,		/* message_context */
	gss_buffer_t		/* status_string */
);

OM_uint32 spnego_gss_display_status2
(
	OM_uint32 *,		/* minor_status */
	OM_uint32,		/* status_value */
	int,			/* status_type */
	gss_OID,		/* mech_type */
	OM_uint32 *,		/* message_context */
	gss_buffer_t		/* status_string */
);

OM_uint32 glue_spnego_gss_display_status
(
	void *,
	OM_uint32 *,		/* minor_status */
	OM_uint32,		/* status_value */
	int,			/* status_type */
	gss_OID,		/* mech_type */
	OM_uint32 *,		/* message_context */
	gss_buffer_t		/* status_string */
);

OM_uint32 spnego_gss_import_name
(
	OM_uint32 *,		/* minor_status */
	gss_buffer_t,		/* input_name_buffer */
	gss_OID,		/* input_name_type */
	/* CSTYLED */
	gss_name_t *		/* output_name */
);

OM_uint32 glue_spnego_gss_import_name
(
	void *,
	OM_uint32 *,		/* minor_status */
	gss_buffer_t,		/* input_name_buffer */
	gss_OID,		/* input_name_type */
	/* CSTYLED */
	gss_name_t *		/* output_name */
);
OM_uint32 spnego_gss_release_name
(
	OM_uint32 *,		/* minor_status */
	/* CSTYLED */
	gss_name_t *		/* input_name */
);

OM_uint32 glue_spnego_gss_release_name
(
	void *,

	OM_uint32 *,		/* minor_status */
	/* CSTYLED */
	gss_name_t *		/* input_name */
);

OM_uint32 spnego_gss_inquire_names_for_mech
(
	OM_uint32 *,		/* minor_status */
	gss_OID,		/* mechanism */
	gss_OID_set *		/* name_types */
);

OM_uint32 glue_spnego_gss_inquire_names_for_mech
(
	void *,
	OM_uint32 *,		/* minor_status */
	gss_OID,		/* mechanism */
	gss_OID_set *		/* name_types */
);

OM_uint32 spnego_gss_unwrap
(
	OM_uint32 *minor_status,
	gss_ctx_id_t context_handle,
	gss_buffer_t input_message_buffer,
	gss_buffer_t output_message_buffer,
	int *conf_state,
	gss_qop_t *qop_state
);

OM_uint32 spnego_gss_wrap
(
	OM_uint32 *minor_status,
	gss_ctx_id_t context_handle,
	int conf_req_flag,
	gss_qop_t qop_req,
	gss_buffer_t input_message_buffer,
	int *conf_state,
	gss_buffer_t output_message_buffer
);

OM_uint32 spnego_gss_process_context_token
(
	OM_uint32	*minor_status,
	const gss_ctx_id_t context_handle,
	const gss_buffer_t token_buffer
);

OM_uint32 spnego_gss_delete_sec_context
(
	OM_uint32 *minor_status,
	gss_ctx_id_t *context_handle,
	gss_buffer_t output_token
);

OM_uint32 glue_spnego_gss_delete_sec_context
(
	void *,

	OM_uint32 *minor_status,
	gss_ctx_id_t *context_handle,
	gss_buffer_t output_token
);

OM_uint32 spnego_gss_context_time
(
	OM_uint32	*minor_status,
	const gss_ctx_id_t context_handle,
	OM_uint32	*time_rec
);
OM_uint32 glue_spnego_gss_context_time
(
	void *,
	OM_uint32	*minor_status,
	const gss_ctx_id_t context_handle,
	OM_uint32	*time_rec
);

#ifndef LEAN_CLIENT
OM_uint32 spnego_gss_export_sec_context
(
	OM_uint32	*minor_status,
	gss_ctx_id_t	*context_handle,
	gss_buffer_t	interprocess_token
);

OM_uint32 glue_spnego_gss_export_sec_context
(
	void *,
	OM_uint32	*minor_status,
	gss_ctx_id_t	*context_handle,
	gss_buffer_t	interprocess_token
);

OM_uint32 spnego_gss_import_sec_context
(
	OM_uint32		*minor_status,
	const gss_buffer_t	interprocess_token,
	gss_ctx_id_t		*context_handle
);
OM_uint32 glue_spnego_gss_import_sec_context
(
	void *,
	OM_uint32		*minor_status,
	const gss_buffer_t	interprocess_token,
	gss_ctx_id_t		*context_handle
);
#endif /* LEAN_CLIENT */

OM_uint32 glue_spnego_gss_inquire_context
(
	void *,
	OM_uint32	*minor_status,
	const gss_ctx_id_t context_handle,
	gss_name_t	*src_name,
	gss_name_t	*targ_name,
	OM_uint32	*lifetime_rec,
	gss_OID		*mech_type,
	OM_uint32	*ctx_flags,
	int		*locally_initiated,
	int		*opened
);

OM_uint32 spnego_gss_inquire_context
(
	OM_uint32	*minor_status,
	const gss_ctx_id_t context_handle,
	gss_name_t	*src_name,
	gss_name_t	*targ_name,
	OM_uint32	*lifetime_rec,
	gss_OID		*mech_type,
	OM_uint32	*ctx_flags,
	int		*locally_initiated,
	int		*opened
);

OM_uint32 spnego_gss_wrap_size_limit
(
	OM_uint32	*minor_status,
	const gss_ctx_id_t context_handle,
	int		conf_req_flag,
	gss_qop_t	qop_req,
	OM_uint32	req_output_size,
	OM_uint32	*max_input_size
);

OM_uint32 glue_spnego_gss_wrap_size_limit
(
	void *,
	OM_uint32	*minor_status,
	const gss_ctx_id_t context_handle,
	int		conf_req_flag,
	gss_qop_t	qop_req,
	OM_uint32	req_output_size,
	OM_uint32	*max_input_size
);

OM_uint32 spnego_gss_get_mic
(
	OM_uint32 *minor_status,
	const gss_ctx_id_t context_handle,
	gss_qop_t qop_req,
	const gss_buffer_t message_buffer,
	gss_buffer_t message_token
);

OM_uint32 spnego_gss_verify_mic
(
	OM_uint32 *minor_status,
	const gss_ctx_id_t context_handle,
	const gss_buffer_t msg_buffer,
	const gss_buffer_t token_buffer,
	gss_qop_t *qop_state
);

OM_uint32
spnego_gss_inquire_sec_context_by_oid
(
	OM_uint32 *minor_status,
	const gss_ctx_id_t context_handle,
	const gss_OID desired_object,
	gss_buffer_set_t *data_set
);


#if 0 /* SUNW17PACresync - will be needed for full MIT 1.7 resync */
OM_uint32 spnego_gss_wrap_aead
(
	OM_uint32 *minor_status,
	gss_ctx_id_t context_handle,
	int conf_req_flag,
	gss_qop_t qop_req,
	gss_buffer_t input_assoc_buffer,
	gss_buffer_t input_payload_buffer,
	int *conf_state,
	gss_buffer_t output_message_buffer
);

OM_uint32 spnego_gss_unwrap_aead
(
	OM_uint32 *minor_status,
	gss_ctx_id_t context_handle,
	gss_buffer_t input_message_buffer,
	gss_buffer_t input_assoc_buffer,
	gss_buffer_t output_payload_buffer,
	int *conf_state,
	gss_qop_t *qop_state
);

OM_uint32 spnego_gss_wrap_iov
(
	OM_uint32 *minor_status,
	gss_ctx_id_t context_handle,
	int conf_req_flag,
	gss_qop_t qop_req,
	int *conf_state,
	gss_iov_buffer_desc *iov,
	int iov_count
);

OM_uint32 spnego_gss_unwrap_iov
(
	OM_uint32 *minor_status,
	gss_ctx_id_t context_handle,
	int *conf_state,
	gss_qop_t *qop_state,
	gss_iov_buffer_desc *iov,
	int iov_count
);

OM_uint32 spnego_gss_wrap_iov_length
(
	OM_uint32 *minor_status,
	gss_ctx_id_t context_handle,
	int conf_req_flag,
	gss_qop_t qop_req,
	int *conf_state,
	gss_iov_buffer_desc *iov,
	int iov_count
);

OM_uint32
spnego_gss_complete_auth_token
(
	OM_uint32 *minor_status,
	const gss_ctx_id_t context_handle,
	gss_buffer_t input_message_buffer
);
#endif /* 0 */

/*
 * Solaris SPNEGO
 * Cloned the krb5_*_error_message and krb5_gss_*_error_info APIs
 * to give similar functionality to SPNEGO mech.
 * See new files in this dir:
 *     spnego_disp_status.c
 *     spnego_kerrs.c
 *     error_map.h
 */
typedef int spnego_error_code;
void spnego_set_error_message (spnego_gss_ctx_id_t, spnego_error_code, const char *, ...);
const char * spnego_get_error_message (spnego_gss_ctx_id_t, spnego_error_code);
void spnego_free_error_message (spnego_gss_ctx_id_t, const char *);
void spnego_clear_error_message (spnego_gss_ctx_id_t);

void spnego_gss_save_error_info(OM_uint32 minor_code, spnego_gss_ctx_id_t ctx);
char *spnego_gss_get_error_message(OM_uint32 minor_code);
void spnego_gss_delete_error_info(void *p);

OM_uint32 krb5_gss_display_status2();
#ifdef	__cplusplus
}
#endif

#endif /* _GSSAPIP_SPNEGO_H_ */
