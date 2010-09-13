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

#ifndef	_SIP_MSG_H
#define	_SIP_MSG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <pthread.h>
#include <sip.h>
#include <sys/types.h>

#ifdef	__solaris__
extern int mutex_held();
#endif

extern sip_header_function_t *sip_header_function_table_external;

/* Compare Cseq numbers */
#define	SIP_CSEQ_LT(a, b)	((int32_t)((a)-(b)) < 0)
#define	SIP_CSEQ_GT(a, b)	((int32_t)((a)-(b)) > 0)
#define	SIP_CSEQ_GEQ(a, b)	((int32_t)((a)-(b)) >= 0)

#define	SIP_HEADER_ACTIVE	0x0
#define	SIP_HEADER_DELETED	0x1
#define	SIP_HEADER_DELETED_VAL	0x2

/* List of registered sent-by values */
typedef struct sent_by_list_s {
	struct sent_by_list_s	*sb_next;
	struct sent_by_list_s	*sb_prev;
	char			*sb_val;
} sent_by_list_t;

extern sent_by_list_t	*sip_sent_by;
extern int		sip_sent_by_count;
extern pthread_mutex_t	sip_sent_by_lock;

typedef struct sip_header {
	sip_hdr_general_t	sip_hdr_general;
	/* active/deleted or has deleted val */
	int			sip_header_state;
	struct sip_header	*sip_hdr_next;
	struct sip_header	*sip_hdr_prev;
	struct sip_message	*sip_hdr_sipmsg;
	/* True if header was allocated */
	boolean_t		sip_hdr_allocated;
	sip_header_function_t	*sip_header_functions;
}_sip_header_t;

/* Structure for the SIP message body */
typedef struct sip_content {
	char			*sip_content_start;
	char			*sip_content_end;
	char			*sip_content_current;
	struct sip_content	*sip_content_next;
	boolean_t		sip_content_allocated;
}sip_content_t;


/* General definitions */

/* Two string values */
typedef struct sip_2strs {
	sip_str_t	s1;
	sip_str_t	s2;
}sip_2strs_t;

/* An integer and a string value */
typedef struct sip_intstr {
	int		i;
	sip_str_t	s;
} sip_intstr_t;

/* Warn value */
typedef struct sip_warn {
	int		code;
	sip_str_t	agt;
	sip_str_t	text;
} sip_warn_t;

/* Date value */
typedef struct sip_date {
	sip_str_t	t;
	int		d;
	sip_str_t	m;
	int		y;
	sip_str_t	tz;
	sip_str_t	wd;
} sip_date_t;

/* Authorization and authentication value */
typedef struct sip_auth {
	sip_str_t	scheme;
	sip_param_t	*param;
} sip_auth_t;

/* RACK value */
typedef struct sip_rack {
	int		rack_resp_num;
	int		rack_cseq_num;
	sip_method_t	rack_method;
}sip_rack_t;

/* Cseq value */
typedef struct sip_cseq {
	int		num;
	sip_method_t	method;
} sip_cseq_value_t;

/* Value for Contact, From and To header */
typedef struct cftr_value {
	sip_str_t	*display_name;
	sip_str_t	uri;
} sip_cftr_value_t;

/* SIP name/version/transport value in Via */
typedef struct sip_proto_version_s {
	sip_str_t	name;
	sip_str_t	version;
	sip_str_t	transport;
}sip_proto_version_t;

/* Via value */
typedef struct via_value {
	sip_proto_version_t 	sent_protocol;
	sip_str_t		sent_by_host;
	int			sent_by_port;
}sip_via_value_t;

typedef struct sip_hdr_value {
	sip_value_t	sip_value;
	union {
		int			i;
		sip_str_t		str;
		sip_2strs_t		strs;
		sip_intstr_t		intstr;
		sip_warn_t		warn;
		sip_date_t		date;
		sip_auth_t		auth;
		sip_rack_t		rack;
		sip_cseq_value_t	cseq;
		sip_cftr_value_t	cftr;
		sip_via_value_t		via;
	} hdr_value;
} sip_hdr_value_t;

/*
 * NOTE: ALL value structs MUST have sip_value_t as the first field.
 */
#define	sip_value_version	sip_value.sip_value_version
#define	sip_next_value		sip_value.next
#define	sip_param_list		sip_value.param_list
#define	sip_value_state 	sip_value.value_state
#define	sip_value_header 	sip_value.parsed_header
#define	sip_value_start		sip_value.value_start
#define	sip_value_end		sip_value.value_end
#define	sip_value_parsed_uri 	sip_value.sip_value_parse_uri

#define	auth_val		hdr_value.auth
#define	auth_scheme_ptr		hdr_value.auth.scheme.sip_str_ptr
#define	auth_scheme_len		hdr_value.auth.scheme.sip_str_len
#define	auth_param		hdr_value.auth.param
#define	int_val			hdr_value.i
#define	str_val			hdr_value.str
#define	str_val_ptr		hdr_value.str.sip_str_ptr
#define	str_val_len		hdr_value.str.sip_str_len
#define	strs_val		hdr_value.strs
#define	strs_s1			hdr_value.strs.s1
#define	strs_s2			hdr_value.strs.s2
#define	strs1_val_ptr		hdr_value.strs.s1.sip_str_ptr
#define	strs1_val_len		hdr_value.strs.s1.sip_str_len
#define	strs2_val_ptr		hdr_value.strs.s2.sip_str_ptr
#define	strs2_val_len		hdr_value.strs.s2.sip_str_len
#define	intstr_val		hdr_value.intstr
#define	intstr_int		hdr_value.intstr.i
#define	intstr_str		hdr_value.intstr.s
#define	intstr_str_ptr		hdr_value.intstr.s.sip_str_ptr
#define	intstr_str_len		hdr_value.intstr.s.sip_str_len
#define	warn_code		hdr_value.warn.code
#define	warn_agt		hdr_value.warn.agt
#define	warn_text		hdr_value.warn.text
#define	warn_agt_ptr		warn_agt.sip_str_ptr
#define	warn_agt_len		warn_agt.sip_str_len
#define	warn_text_ptr		warn_text.sip_str_ptr
#define	warn_text_len		warn_text.sip_str_len
#define	date_t			hdr_value.date.t
#define	date_d			hdr_value.date.d
#define	date_m			hdr_value.date.m
#define	date_y			hdr_value.date.y
#define	date_tz			hdr_value.date.tz
#define	date_wd			hdr_value.date.wd
#define	date_t_ptr		date_t.sip_str_ptr
#define	date_t_len		date_t.sip_str_len
#define	date_m_ptr		date_m.sip_str_ptr
#define	date_m_len		date_m.sip_str_len
#define	date_tz_ptr		date_tz.sip_str_ptr
#define	date_tz_len		date_tz.sip_str_len
#define	date_wd_ptr		date_wd.sip_str_ptr
#define	date_wd_len		date_wd.sip_str_len
#define	rack_resp		hdr_value.rack.rack_resp_num
#define	rack_cseq		hdr_value.rack.rack_cseq_num
#define	rack_method		hdr_value.rack.rack_method
#define	cftr_name		hdr_value.cftr.display_name
#define	cftr_uri		hdr_value.cftr.uri
#define	cseq_num		hdr_value.cseq.num
#define	cseq_method		hdr_value.cseq.method
#define	via_protocol		hdr_value.via.sent_protocol
#define	via_protocol_name	hdr_value.via.sent_protocol.name
#define	via_protocol_vers	hdr_value.via.sent_protocol.version
#define	via_protocol_transport	hdr_value.via.sent_protocol.transport
#define	via_sent_by_host	hdr_value.via.sent_by_host
#define	via_sent_by_port	hdr_value.via.sent_by_port

#define	SIP_INT_VAL		0x01
#define	SIP_STR_VAL		0x02
#define	SIP_STRS_VAL		0x03
#define	SIP_INTSTR_VAL		0x04
#define	SIP_AUTH_VAL		0x05

/* hdr value contains two string */
typedef sip_hdr_value_t sip_acpt_value_t;
typedef sip_hdr_value_t sip_content_type_value_t;

/* hdr value contains one string only */
typedef sip_hdr_value_t sip_acpt_lang_value_t;
typedef sip_hdr_value_t sip_acpt_encode_value_t;
typedef sip_hdr_value_t sip_alert_value_t;
typedef sip_hdr_value_t sip_cl_info_value_t;
typedef sip_hdr_value_t sip_ct_disp_value_t;
typedef sip_hdr_value_t sip_ct_encode_value_t;
typedef sip_hdr_value_t sip_ct_lang_value_t;
typedef sip_hdr_value_t sip_irt_value_t;
typedef sip_hdr_value_t sip_mime_ver_value_t;
typedef sip_hdr_value_t sip_org_value_t;
typedef sip_hdr_value_t sip_prio_value_t;
typedef sip_hdr_value_t sip_reply_value_t;
typedef sip_hdr_value_t sip_privacy_value_t;
typedef sip_hdr_value_t sip_ppassertedid_value_t;
typedef sip_hdr_value_t sip_ppreferredid_value_t;
typedef sip_hdr_value_t sip_pxy_req_value_t;
typedef sip_hdr_value_t sip_req_value_t;
typedef sip_hdr_value_t sip_subject_value_t;
typedef sip_hdr_value_t sip_svr_value_t;
typedef sip_hdr_value_t sip_support_value_t;
typedef sip_hdr_value_t sip_unsupport_value_t;
typedef sip_hdr_value_t sip_usr_agt_value_t;
typedef sip_hdr_value_t sip_err_info_value_t;
typedef sip_hdr_value_t sip_date_value_t;
typedef sip_hdr_value_t sip_allert_value_t;
typedef sip_hdr_value_t	sip_callid_value_t;

/* hdr value contain one int only */
typedef sip_hdr_value_t sip_expr_value_t;
typedef sip_hdr_value_t sip_min_expr_value_t;
typedef sip_hdr_value_t sip_retry_value_t;
typedef sip_hdr_value_t sip_timestamp_value_t;
typedef sip_hdr_value_t sip_rseq_value_t;
typedef sip_hdr_value_t sip_content_len_value_t;
typedef sip_hdr_value_t sip_max_forwards_value_t;
typedef sip_hdr_value_t sip_allow_value_t;

/* hdr value contain one int, two strings */
typedef sip_hdr_value_t sip_warn_value_t;

/* hdr field value is a list of param=param_val */
typedef sip_hdr_value_t	sip_authen_value_t;
typedef sip_hdr_value_t	sip_authen_info_value_t;
typedef sip_hdr_value_t	sip_pxy_authen_value_t;
typedef sip_hdr_value_t	sip_pxy_author_value_t;
typedef sip_hdr_value_t	sip_3w_authen_value_t;

/* SIP request line structure */
typedef struct sip_request {
	sip_method_t	sip_request_method;
	sip_str_t	sip_request_uri;
	sip_uri_t	sip_parse_uri;
} sip_request_t;

/* SIP response line structure */
typedef struct sip_response {
	int		sip_response_code;
	sip_str_t	sip_response_phrase;
} sip_response_t;

/* SIP message type - request or response */
typedef struct sip_message_type {
	boolean_t		is_request;
	sip_proto_version_t	sip_proto_version;
	union {
	sip_request_t		sip_request;
	sip_response_t		sip_response;
	} U;
	/* This is to save old value when we use a recvd message. */
	struct sip_message_type	*sip_next;
} sip_message_type_t;

/* Increment reference count on SIP message */
#define	SIP_MSG_REFCNT_INCR(sip_msg) {				\
	(void) pthread_mutex_lock(&(sip_msg)->sip_msg_mutex);	\
	(sip_msg)->sip_msg_ref_cnt++;				\
	(void) pthread_mutex_unlock(&(sip_msg)->sip_msg_mutex);	\
}

/* Decrement reference count on SIP message */
#define	SIP_MSG_REFCNT_DECR(sip_msg) {					\
	(void) pthread_mutex_lock(&(sip_msg)->sip_msg_mutex);		\
	assert((sip_msg)->sip_msg_ref_cnt > 0);				\
	if (--(sip_msg)->sip_msg_ref_cnt == 0) {			\
		sip_destroy_msg(sip_msg);				\
	} else {							\
		(void) pthread_mutex_unlock(&(sip_msg)->sip_msg_mutex);	\
	}								\
}

/* SIP message structure */
typedef struct sip_message {
	char			*sip_msg_buf;	/* Message */
	char			*sip_msg_old_buf;
	boolean_t		sip_msg_modified;
	boolean_t		sip_msg_cannot_be_modified;
	int			sip_msg_len;
	size_t			sip_msg_content_len;	/* content length */
	sip_content_t		*sip_msg_content;
	/* All fields synchronizes on this */
	pthread_mutex_t		sip_msg_mutex;
	/* doubly linked list of headers */
	_sip_header_t		*sip_msg_headers_start;
	_sip_header_t		*sip_msg_headers_end;
	_sip_header_t		*sip_msg_start_line;
	sip_message_type_t	*sip_msg_req_res;
	int			sip_msg_ref_cnt;
}_sip_msg_t;

extern char		*sip_get_tcp_msg(sip_conn_object_t, char *, size_t *);
extern char		*sip_msg_to_msgbuf(_sip_msg_t *msg, int *error);
extern char		*_sip_startline_to_str(_sip_msg_t *sip_msg, int *error);
extern int		sip_adjust_msgbuf(_sip_msg_t *msg);
extern void		sip_delete_all_headers(_sip_msg_t *sip_msg);
extern _sip_header_t	*sip_dup_header(_sip_header_t *from);
extern int		_sip_copy_header(_sip_msg_t *, _sip_header_t *, char *,
			    boolean_t);
extern int		_sip_find_and_copy_header(_sip_msg_t *, _sip_msg_t *,
			    char *, char *, boolean_t);
extern int		_sip_find_and_copy_all_header(_sip_msg_t *,
			    _sip_msg_t *, char *header_name);
extern _sip_header_t	*sip_search_for_header(_sip_msg_t *, char *,
			    _sip_header_t *);
extern void		_sip_add_header(_sip_msg_t *, _sip_header_t *,
			    boolean_t, boolean_t, char *);
extern _sip_header_t	*sip_new_header(int);
extern int		sip_create_nonOKack(sip_msg_t, sip_msg_t, sip_msg_t);
extern void		sip_destroy_msg(_sip_msg_t *);
extern void		sip_free_header(_sip_header_t *sip_header);
extern void		sip_free_phdr(sip_parsed_header_t *);
extern void		sip_free_cftr_header(sip_parsed_header_t *);

extern int		sip_parse_allow_events_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_event_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_substate_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_acpt_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_acpt_encode_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_acpt_lang_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_alert_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_allow_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_useragt_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_usupport_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_timestamp_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_support_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_subject_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_server_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_retryaft_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_require_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_replyto_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_passertedid_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_ppreferredid_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_priority_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_org_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_mimeversion_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_minexpire_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_rseq_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_inreplyto_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_privacy_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_expire_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_errorinfo_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_contentlang_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_contentencode_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_contentdis_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_callinfo_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_date_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_warn_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_cftr_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_cseq_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_cid_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_via_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_clen_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_maxf_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_ctype_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_unknown_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_ainfo_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_preq_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_author_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_pauthor_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_pauthen_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_wauthen_header(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_rseq(_sip_header_t *, sip_parsed_header_t **);
extern int		sip_parse_rack(_sip_header_t *, sip_parsed_header_t **);
extern int		sip_parse_passertedid(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_ppreferredid(_sip_header_t *,
			    sip_parsed_header_t **);
extern int		sip_parse_privacy_header(_sip_header_t *,
			    sip_parsed_header_t **);

extern sip_param_t	*sip_get_param_from_list(sip_param_t *, char *);
extern int		sip_copy_values(char *, _sip_header_t *);
extern int		sip_add_content_length(_sip_msg_t *, int);
extern int		sip_delete_start_line_locked(_sip_msg_t *);

/* Useful access macros */
#define	sip_resp_phrase_len	U.sip_response.sip_response_phrase.sip_str_len
#define	sip_resp_phrase_ptr	U.sip_response.sip_response_phrase.sip_str_ptr

#define	sip_resp_code		U.sip_response.sip_response_code
#define	sip_resp_phrase		U.sip_response.sip_response_phrase

#define	sip_req_method		U.sip_request.sip_request_method
#define	sip_req_uri		U.sip_request.sip_request_uri
#define	sip_req_uri_ptr		U.sip_request.sip_request_uri.sip_str_ptr
#define	sip_req_uri_len		U.sip_request.sip_request_uri.sip_str_ptr
#define	sip_req_parse_uri	U.sip_request.sip_parse_uri

#define	sip_header_parse	sip_header_functions->header_parse_func
#define	sip_header_name		sip_header_functions->header_name

#define	sip_hdr_start		sip_hdr_general.sip_hdr_start
#define	sip_hdr_end		sip_hdr_general.sip_hdr_end
#define	sip_hdr_current		sip_hdr_general.sip_hdr_current
#define	sip_hdr_parsed		sip_hdr_general.sip_hdr_parsed

#ifdef	__cplusplus
}
#endif

#endif	/* _SIP_MSG_H */
