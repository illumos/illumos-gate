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

#ifndef	_SIP_H
#define	_SIP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <netinet/in.h>

/* Send a SIP message statefully */
#define	SIP_SEND_STATEFUL	0x0001

/* Enable multiple dialogs if a request is forked */
#define	SIP_DIALOG_ON_FORK	0x0010

#define	SIP_CRLF 		"\r\n"
#define	SKIP_CRLF(msg_ptr)	(msg_ptr = msg_ptr + 2)
#define	SIP_VERSION		"SIP/2.0"
#define	SIP			"SIP"

/* SIP headers */
#define	SIP_TO				"TO"
#define	SIP_FROM			"FROM"
#define	SIP_TAG				"TAG="
#define	SIP_CONTENT_LENGTH		"CONTENT-LENGTH"
#define	SIP_CONTENT_TYPE		"CONTENT-TYPE"
#define	SIP_CALL_ID			"CALL-ID"
#define	SIP_CSEQ			"CSEQ"
#define	SIP_MAX_FORWARDS		"MAX-FORWARDS"
#define	SIP_CONTACT			"CONTACT"
#define	SIP_VIA				"Via"
#define	SIP_RECORD_ROUTE		"RECORD-ROUTE"
#define	SIP_ROUTE			"ROUTE"
#define	SIP_ACCEPT			"ACCEPT"
#define	SIP_ACCEPT_ENCODE		"ACCEPT-ENCODING"
#define	SIP_ACCEPT_LANG			"ACCEPT-LANGUAGE"
#define	SIP_ALERT_INFO			"ALERT-INFO"
#define	SIP_ALLOW			"ALLOW"
#define	SIP_CALL_INFO			"CALL-INFO"
#define	SIP_CONTENT_DIS			"CONTENT-DISPOSITION"
#define	SIP_CONTENT_ENCODE		"CONTENT-ENCODING"
#define	SIP_CONTENT_LANG		"CONTENT-LANGUAGE"
#define	SIP_DATE			"DATE"
#define	SIP_ERROR_INFO			"ERROR-INFO"
#define	SIP_EXPIRE			"EXPIRES"
#define	SIP_IN_REPLY_TO			"IN-REPLY-TO"
#define	SIP_MIN_EXPIRE			"MIN-EXPIRES"
#define	SIP_MIME_VERSION		"MIME-VERSION"
#define	SIP_ORGANIZATION		"ORGANIZATION"
#define	SIP_PRIORITY			"PRIORITY"
#define	SIP_REQUIRE			"REQUIRE"
#define	SIP_REPLYTO			"REPLY-TO"
#define	SIP_RETRY_AFTER			"RETRY-AFTER"
#define	SIP_SERVER			"SERVER"
#define	SIP_SUBJECT			"SUBJECT"
#define	SIP_SUPPORT			"SUPPORTED"
#define	SIP_TIMESTAMP			"TIMESTAMP"
#define	SIP_UNSUPPORT			"UNSUPPORTED"
#define	SIP_USER_AGENT			"USER-AGENT"
#define	SIP_WARNING			"WARNING"
#define	SIP_ALLOW_EVENTS		"ALLOW-EVENTS"
#define	SIP_EVENT			"EVENT"
#define	SIP_SUBSCRIPTION_STATE		"SUBSCRIPTION-STATE"
#define	SIP_WWW_AUTHEN			"WWW-AUTHENTICATE"
#define	SIP_AUTHOR			"AUTHORIZATION"
#define	SIP_AUTHEN_INFO			"AUTHENTICATION-INFO"
#define	SIP_PROXY_AUTHOR		"PROXY-AUTHORIZATION"
#define	SIP_PROXY_AUTHEN		"PROXY-AUTHENTICATE"
#define	SIP_PROXY_REQ			"PROXY-REQUIRE"
#define	SIP_PASSERTEDID			"P-ASSERTED-IDENTITY"
#define	SIP_PPREFERREDID		"P-PREFERRED-IDENTITY"
#define	SIP_PRIVACY			"PRIVACY"
#define	SIP_RACK			"RACK"
#define	SIP_RSEQ			"RSEQ"

/* SIP Response Codes */

/* 1XX - Provisional */
#define	SIP_TRYING			100
#define	SIP_RINGING			180
#define	SIP_CALL_IS_BEING_FORWARDED 	181
#define	SIP_QUEUED			182
#define	SIP_SESSION_PROGRESS		183

/* 2XX - Success */
#define	SIP_OK				200
#define	SIP_ACCEPTED			202

/* 3XX - Redirection */
#define	SIP_MULTIPLE_CHOICES		300
#define	SIP_MOVED_PERMANENTLY		301
#define	SIP_MOVED_TEMPORARILY		302
#define	SIP_USE_PROXY			303
#define	SIP_ALTERNATIVE_SERVICE		304

/* 4XX - Request Failed */
#define	SIP_BAD_REQUEST			400
#define	SIP_UNAUTHORIZED		401
#define	SIP_PAYMENT_REQUIRED		402
#define	SIP_FORBIDDEN			403
#define	SIP_NOT_FOUND			404
#define	SIP_METHOD_NOT_ALLOWED		405
#define	SIP_NOT_ACCEPTABLE		406
#define	SIP_PROXY_AUTH_REQUIRED		407
#define	SIP_REQUEST_TIMEOUT		408
#define	SIP_GONE			410
#define	SIP_REQUEST_ENTITY_2_LARGE	413
#define	SIP_REQUEST_URI_2_LONG		414
#define	SIP_UNSUPPORTED_MEDIA_TYPE	415
#define	SIP_UNSUPPORTED_URI_SCHEME	416
#define	SIP_BAD_EXTENSION		420
#define	SIP_EXTENSION_REQUIRED		421
#define	SIP_INTERVAL_2_BRIEF		423
#define	SIP_TEMPORARILY_UNAVAIL		480
#define	SIP_CALL_NON_EXISTANT		481
#define	SIP_LOOP_DETECTED		482
#define	SIP_TOO_MANY_HOOPS		483
#define	SIP_ADDRESS_INCOMPLETE		484
#define	SIP_AMBIGUOUS			485
#define	SIP_BUSY_HERE			486
#define	SIP_REQUEST_TERMINATED		487
#define	SIP_NOT_ACCEPTABLE_HERE		488
#define	SIP_BAD_EVENT			489
#define	SIP_REQUEST_PENDING		491
#define	SIP_UNDECIPHERABLE		493

/* 5XX - Server Failure */
#define	SIP_SERVER_INTERNAL_ERROR	500
#define	SIP_NOT_IMPLEMENTED		501
#define	SIP_BAD_GATEWAY			502
#define	SIP_SERVICE_UNAVAILABLE		503
#define	SIP_SERVER_TIMEOUT		504
#define	SIP_VERSION_NOT_SUPPORTED	505
#define	SIP_MESSAGE_2_LARGE		513

/* 6XX - Global Failures */
#define	SIP_BUSY_EVERYWHERE		600
#define	SIP_DECLINE			601
#define	SIP_DOES_NOT_EXIST_ANYWHERE 	604
#define	SIP_NOT_ACCEPTABLE_ANYWHERE	606

/* Response error types */
#define	SIP_PROVISIONAL_RESP(resp)	((resp) >= 100 && (resp) < 200)
#define	SIP_FINAL_RESP(resp)		((resp) >= 200 && (resp) < 700)
#define	SIP_OK_RESP(resp)		((resp) >= 200 && (resp) < 300)
#define	SIP_NONOK_FINAL_RESP(resp)	((resp) >= 300 && (resp) < 700)
#define	SIP_REDIRECT_RESP(resp)		((resp) >= 300 && (resp) < 400)
#define	SIP_REQFAIL_RESP(resp)		((resp) >= 400 && (resp) < 500)
#define	SIP_SRVFAIL_RESP(resp)		((resp) >= 500 && (resp) < 600)
#define	SIP_GLOBFAIL_RESP(resp)		((resp) >= 600 && (resp) < 700)

/* Types of transactions */
#define	SIP_CLIENT_TRANSACTION		1
#define	SIP_SERVER_TRANSACTION		2

/* Transaction states */
#define	SIP_NEW_TRANSACTION		0

/* Client Transaction States */
#define	SIP_CLNT_CALLING		1
#define	SIP_CLNT_INV_PROCEEDING 	2
#define	SIP_CLNT_INV_TERMINATED 	3
#define	SIP_CLNT_INV_COMPLETED		4
#define	SIP_CLNT_TRYING		5
#define	SIP_CLNT_NONINV_PROCEEDING 	6
#define	SIP_CLNT_NONINV_TERMINATED 	7
#define	SIP_CLNT_NONINV_COMPLETED	8

/* Server Transaction States */
#define	SIP_SRV_INV_PROCEEDING		9
#define	SIP_SRV_INV_COMPLETED		10
#define	SIP_SRV_CONFIRMED		11
#define	SIP_SRV_INV_TERMINATED		12
#define	SIP_SRV_TRYING			13
#define	SIP_SRV_NONINV_PROCEEDING	14
#define	SIP_SRV_NONINV_COMPLETED	15
#define	SIP_SRV_NONINV_TERMINATED	16

/* Dialog types */
#define	SIP_UAC_DIALOG			1
#define	SIP_UAS_DIALOG			2

/* Dialog state */
typedef enum dialog_state {
	SIP_DLG_NEW = 0,	/* New dialog, no reply received yet */
	SIP_DLG_EARLY,		/* Early dialog, provisional reply received */
	SIP_DLG_CONFIRMED,	/* Confirmed dialog, 2xx reply received */
	SIP_DLG_DESTROYED	/* Destroyed dialog */
} dialog_state_t;

/* SIP URI parse errors */
#define	SIP_URIERR_SCHEME	0x00000001 /* invalid URL SCHEME name */
#define	SIP_URIERR_USER		0x00000002 /* invalid user name */
#define	SIP_URIERR_PASS		0x00000004 /* invalid password  */
#define	SIP_URIERR_HOST		0x00000008 /* invalid domain name */
#define	SIP_URIERR_PORT		0x00000010 /* invalid port number */
#define	SIP_URIERR_PARAM	0x00000020 /* parameter specific error */
#define	SIP_URIERR_HEADER	0x00000040 /* headers specific error */
#define	SIP_URIERR_OPAQUE	0x00000080 /* opaque specific error */
#define	SIP_URIERR_QUERY	0x00000100 /* query specific error */
#define	SIP_URIERR_PATH		0x00000200 /* path specific error */
#define	SIP_URIERR_REGNAME	0x00000400 /* reg-name specific error */
#define	SIP_URIERR_NOURI	0x00000800 /* No URI */
#define	SIP_URIERR_MEMORY	0x00001000 /* out of memory */

#ifdef		__linux__
#define		B_FALSE		0
#define		B_TRUE		1

typedef int		boolean_t;
typedef unsigned char	uchar_t;
typedef unsigned int	uint_t;
typedef unsigned int	uint32_t;
#endif

typedef struct sip_message	*sip_msg_t;
typedef struct sip_header	*sip_header_t;
typedef struct sip_value	*sip_header_value_t;
typedef struct sip_dialog	*sip_dialog_t;
typedef struct sip_uri		*sip_uri_t;
typedef struct sip_conn_object	*sip_conn_object_t;
typedef	struct sip_xaction	*sip_transaction_t;

typedef struct sip_str {
	char	*sip_str_ptr;
	int	sip_str_len;
}sip_str_t;


/* SIP parameter */
typedef struct sip_param {
	sip_str_t	param_name;
	sip_str_t	param_value;
	struct sip_param *param_next;
}sip_param_t;


/* Parsed header structure */
typedef struct sip_parsed_header {
	int		 sip_parsed_header_version;
	struct sip_value *value;
	sip_header_t	sip_header;
}sip_parsed_header_t;

#define	SIP_PARSED_HEADER_VERSION_1	1

/* Value states */
typedef enum {
	SIP_VALUE_ACTIVE = 0,
	SIP_VALUE_BAD,
	SIP_VALUE_DELETED
}sip_value_state_t;

/* SIP header value */
typedef struct sip_value {
	int			sip_value_version;
	void			*next;
	sip_param_t		*param_list;
	sip_value_state_t	value_state; /* Active/Deleted */
	sip_parsed_header_t	*parsed_header;
	char			*value_start;
	char			*value_end;
	sip_str_t		*sip_value_uri_str;
	sip_uri_t		sip_value_parse_uri;
}sip_value_t;

#define	SIP_VALUE_VERSION_1	1

typedef struct sip_header_general {
	char			*sip_hdr_start;
	char			*sip_hdr_end;
	char			*sip_hdr_current;
	sip_parsed_header_t	*sip_hdr_parsed;
}sip_hdr_general_t;

/* SIP methods */
typedef enum {
	UNKNOWN = 0,
	INVITE,
	ACK,
	OPTIONS,
	BYE,
	CANCEL,
	REGISTER,
	REFER,
	INFO,
	SUBSCRIBE,
	NOTIFY,
	PRACK
}sip_method_t;

#define	MAX_SIP_METHODS	12

typedef struct sip_methods {
	char *name;	/* Name of the method */
	int  len;	/* Length for comparison */
}sip_methods_t;

extern sip_methods_t sip_methods[];

/* SIP header function table */
typedef struct header_function_table {
	char		*header_name;
	char		*header_short_name;
	int		(*header_parse_func)(struct sip_header *,
			    struct sip_parsed_header **);
	boolean_t	(*header_check_compliance)(struct sip_parsed_header *);
	boolean_t	(*header_is_equal)(struct sip_parsed_header *,
			    struct sip_parsed_header *);
	void		(*header_free)(struct sip_parsed_header *);
}sip_header_function_t;

/* Connection Manager interface */
typedef struct sip_io_pointers_s {
	int	(*sip_conn_send)(const sip_conn_object_t, char *, int);
	void	(*sip_hold_conn_object)(sip_conn_object_t);
	void	(*sip_rel_conn_object)(sip_conn_object_t);
	boolean_t	(*sip_conn_is_stream)(sip_conn_object_t);
	boolean_t	(*sip_conn_is_reliable)(sip_conn_object_t);
	int 	(*sip_conn_remote_address)(sip_conn_object_t, struct sockaddr *,
		    socklen_t *);
	int 	(*sip_conn_local_address)(sip_conn_object_t, struct sockaddr *,
		    socklen_t *);
	int	(*sip_conn_transport)(sip_conn_object_t);
	int	(*sip_conn_timer1)(sip_conn_object_t);
	int	(*sip_conn_timer2)(sip_conn_object_t);
	int	(*sip_conn_timer4)(sip_conn_object_t);
	int	(*sip_conn_timerd)(sip_conn_object_t);
}sip_io_pointers_t;

/* Upper layer registerations */
typedef struct sip_ulp_pointers_s {
	void		(*sip_ulp_recv)(const sip_conn_object_t,
			    sip_msg_t, const sip_dialog_t);
	uint_t		(*sip_ulp_timeout)(void *, void (*func)(void *),
			    struct timeval *);
	boolean_t	(*sip_ulp_untimeout)(uint_t);
	int		(*sip_ulp_trans_error)(sip_transaction_t, int, void *);
	void		(*sip_ulp_dlg_del)(sip_dialog_t, sip_msg_t, void *);
	void		(*sip_ulp_trans_state_cb)(sip_transaction_t,
			    sip_msg_t, int, int);
	void		(*sip_ulp_dlg_state_cb)(sip_dialog_t, sip_msg_t, int,
			    int);
}sip_ulp_pointers_t;

/* SIP stack initialization structure */
typedef struct sip_stack_init_s {
	int			sip_version;
	int			sip_stack_flags;
	sip_io_pointers_t	*sip_io_pointers;
	sip_ulp_pointers_t	*sip_ulp_pointers;
	sip_header_function_t	*sip_function_table;
}sip_stack_init_t;

/* SIP stack version */
#define	SIP_STACK_VERSION		1

/* Flags for sip_stack_flags */
#define	SIP_STACK_DIALOGS		0x0001

extern int		sip_init_conn_object(sip_conn_object_t);
extern void		sip_clear_stale_data(sip_conn_object_t);
extern void		sip_conn_destroyed(sip_conn_object_t);

extern int		(*sip_stack_send)(const sip_conn_object_t, char *, int);
extern void		(*sip_refhold_conn)(sip_conn_object_t);
extern void		(*sip_refrele_conn)(sip_conn_object_t);
extern boolean_t	(*sip_is_conn_stream)(sip_conn_object_t);
extern boolean_t	(*sip_is_conn_reliable)(sip_conn_object_t);
extern int 		(*sip_conn_rem_addr)(sip_conn_object_t,
			    struct sockaddr *, socklen_t *);
extern int		(*sip_conn_local_addr)(sip_conn_object_t,
			    struct sockaddr *, socklen_t *);
extern int		(*sip_conn_transport)(sip_conn_object_t);
extern int		(*sip_conn_timer1)(sip_conn_object_t);
extern int		(*sip_conn_timer2)(sip_conn_object_t);
extern int		(*sip_conn_timer4)(sip_conn_object_t);
extern int		(*sip_conn_timerd)(sip_conn_object_t);

extern uint_t		(*sip_stack_timeout)(void *, void (*func)(void *),
			    struct timeval *);
extern boolean_t	(*sip_stack_untimeout)(uint_t);

extern sip_msg_t	sip_new_msg();
extern void		sip_free_msg(sip_msg_t);
extern void		sip_hold_msg(sip_msg_t);
extern int		sip_stack_init(sip_stack_init_t *);
extern int		sip_sendmsg(sip_conn_object_t, sip_msg_t, sip_dialog_t,
			    uint32_t);
extern void		sip_process_new_packet(sip_conn_object_t, void *,
			    size_t);
extern char 		*sip_guid();
extern char		*sip_sent_by_to_str(int *);
extern int		sip_register_sent_by(char *);
extern void		sip_unregister_sent_by(char *);
extern void		sip_unregister_all_sent_by();
extern char 		*sip_branchid(sip_msg_t);
extern uint32_t		sip_get_cseq();
extern uint32_t		sip_get_rseq();
extern int		sip_get_num_via(sip_msg_t, int *);

extern int 		sip_add_from(sip_msg_t, char *, char *, char *,
			    boolean_t, char *);
extern int 		sip_add_to(sip_msg_t, char *, char *, char *,
			    boolean_t, char *);
extern int 		sip_add_response_line(sip_msg_t, int, char *);
extern int 		sip_add_request_line(sip_msg_t, sip_method_t, char *);
extern int 		sip_add_via(sip_msg_t, char *, char *, int, char *);
extern int 		sip_add_maxforward(sip_msg_t, uint_t);
extern int 		sip_add_callid(sip_msg_t, char *);
extern int 		sip_add_cseq(sip_msg_t, sip_method_t, uint32_t);
extern int 		sip_add_content_type(sip_msg_t, char *, char *);
extern int 		sip_add_content(sip_msg_t, char *);
extern int 		sip_add_contact(sip_msg_t, char *, char *, boolean_t,
			    char *);
extern int 		sip_add_route(sip_msg_t, char *, char *, char *);
extern int 		sip_add_record_route(sip_msg_t, char *, char *, char *);
extern int 		sip_add_branchid_to_via(sip_msg_t, char *);
extern int 		sip_add_accept(sip_msg_t, char *, char *, char *,
			    char *);
extern int		sip_add_author(sip_msg_t, char *,  char *);
extern int		sip_add_authen_info(sip_msg_t, char *);
extern int		sip_add_proxy_authen(sip_msg_t, char *,  char *);
extern int		sip_add_proxy_author(sip_msg_t, char *, char *);
extern int		sip_add_proxy_require(sip_msg_t, char *);
extern int		sip_add_www_authen(sip_msg_t, char *, char *);
extern int		sip_add_accept_enc(sip_msg_t, char *, char *);
extern int		sip_add_accept_lang(sip_msg_t, char *, char *);
extern int		sip_add_alert_info(sip_msg_t, char *, char *);
extern int		sip_add_allow(sip_msg_t, sip_method_t);
extern int		sip_add_call_info(sip_msg_t, char *, char *);
extern int		sip_add_content_disp(sip_msg_t, char *, char *);
extern int		sip_add_content_enc(sip_msg_t, char *);
extern int		sip_add_content_lang(sip_msg_t, char *);
extern int		sip_add_date(sip_msg_t, char *);
extern int		sip_add_error_info(sip_msg_t, char *, char *);
extern int		sip_add_expires(sip_msg_t, int);
extern int		sip_add_in_reply_to(sip_msg_t, char *);
extern int		sip_add_mime_version(sip_msg_t, char *);
extern int		sip_add_min_expires(sip_msg_t, int);
extern int		sip_add_org(sip_msg_t, char *);
extern int		sip_add_priority(sip_msg_t, char *);
extern int		sip_add_reply_to(sip_msg_t, char *, char *, char *,
			    boolean_t);
extern int		sip_add_require(sip_msg_t, char *);
extern int		sip_add_retry_after(sip_msg_t, int, char *, char *);
extern int		sip_add_server(sip_msg_t, char *);
extern int		sip_add_subject(sip_msg_t, char *);
extern int		sip_add_supported(sip_msg_t, char *);
extern int		sip_add_tstamp(sip_msg_t, char *, char *);
extern int		sip_add_unsupported(sip_msg_t, char *);
extern int		sip_add_user_agent(sip_msg_t, char *);
extern int		sip_add_warning(sip_msg_t, int, char *, char *);
extern int		sip_add_allow_events(sip_msg_t, char *);
extern int		sip_add_event(sip_msg_t, char *, char *);
extern int		sip_add_substate(sip_msg_t, char *, char *);
extern int		sip_add_privacy(sip_msg_t, char *);
extern int		sip_add_passertedid(sip_msg_t, char *, char *,
			    boolean_t);
extern int		sip_add_ppreferredid(sip_msg_t, char *, char *,
			    boolean_t);
extern int		sip_add_rack(sip_msg_t, int, int, sip_method_t);
extern int		sip_add_rseq(sip_msg_t, int);
extern const sip_str_t *sip_get_author_scheme(sip_msg_t, int *);
extern const sip_str_t *sip_get_author_param(sip_msg_t, char *, int *);
extern const sip_str_t *sip_get_authen_info(sip_header_value_t, int *);
extern const sip_str_t *sip_get_proxy_authen_scheme(sip_msg_t, int *);
extern const sip_str_t *sip_get_proxy_authen_param(sip_msg_t, char *, int *);
extern const sip_str_t *sip_get_proxy_author_scheme(sip_msg_t, int *);
extern const sip_str_t *sip_get_proxy_author_param(sip_msg_t, char *, int *);
extern const sip_str_t *sip_get_proxy_require(sip_header_value_t, int *);
extern const sip_str_t *sip_get_www_authen_scheme(sip_msg_t, int *);
extern const sip_str_t *sip_get_www_authen_param(sip_msg_t, char *, int *);
extern const sip_str_t	*sip_get_allow_events(sip_header_value_t, int *);
extern const sip_str_t	*sip_get_event(sip_msg_t, int *);
extern const sip_str_t	*sip_get_substate(sip_msg_t, int *);
extern const sip_str_t	*sip_get_accept_type(sip_header_value_t, int *);
extern const sip_str_t	*sip_get_accept_sub_type(sip_header_value_t, int *);
extern const sip_str_t	*sip_get_accept_enc(sip_header_value_t, int *);
extern const sip_str_t	*sip_get_accept_lang(sip_header_value_t, int *);
extern const sip_str_t	*sip_get_alert_info_uri(sip_header_value_t, int *);
extern sip_method_t	sip_get_allow_method(sip_header_value_t, int *);
extern int		sip_get_min_expires(sip_msg_t, int *);
extern const sip_str_t	*sip_get_mime_version(sip_msg_t, int *);
extern const sip_str_t	*sip_get_org(sip_msg_t, int *);
extern const sip_str_t	*sip_get_priority(sip_msg_t, int *);
extern const sip_str_t	*sip_get_replyto_display_name(sip_msg_t, int *);
extern const sip_str_t	*sip_get_replyto_uri_str(sip_msg_t, int *);
extern const sip_str_t	*sip_get_date_time(sip_msg_t, int *);
extern int		sip_get_date_day(sip_msg_t, int *);
extern const sip_str_t	*sip_get_date_month(sip_msg_t, int *);
extern const sip_str_t	*sip_get_date_wkday(sip_msg_t, int *);
extern int		sip_get_date_year(sip_msg_t, int *);
extern const sip_str_t	*sip_get_date_timezone(sip_msg_t, int *);
extern const sip_str_t	*sip_get_content_disp(sip_msg_t, int *);
extern const sip_str_t	*sip_get_content_lang(sip_header_value_t, int *);
extern const sip_str_t	*sip_get_content_enc(sip_header_value_t, int *);
extern const sip_str_t	*sip_get_error_info_uri(sip_header_value_t, int *);
extern int		sip_get_expires(sip_msg_t, int *);
extern const sip_str_t	*sip_get_require(sip_header_value_t, int *);
extern const sip_str_t	*sip_get_subject(sip_msg_t, int *);
extern const sip_str_t	*sip_get_supported(sip_header_value_t, int *);
extern const sip_str_t	*sip_get_tstamp_delay(sip_msg_t, int *);
extern const sip_str_t	*sip_get_tstamp_value(sip_msg_t, int *);
extern const sip_str_t	*sip_get_unsupported(sip_header_value_t, int *);
extern const sip_str_t	*sip_get_server(sip_msg_t, int *);
extern const sip_str_t	*sip_get_user_agent(sip_msg_t, int *);
extern int		sip_get_warning_code(sip_header_value_t, int *);
extern const sip_str_t	*sip_get_warning_agent(sip_header_value_t, int *);
extern const sip_str_t	*sip_get_warning_text(sip_header_value_t, int *);
extern const sip_str_t	*sip_get_call_info_uri(sip_header_value_t, int *);
extern const sip_str_t	*sip_get_in_reply_to(sip_header_value_t, int *);
extern int		sip_get_retry_after_time(sip_msg_t, int *);
extern const sip_str_t	*sip_get_retry_after_cmts(sip_msg_t, int *);
extern const sip_str_t	*sip_get_passertedid_display_name(sip_header_value_t,
			    int *);
extern const sip_str_t	*sip_get_passertedid_uri_str(sip_header_value_t,
			    int *);
extern const sip_str_t	*sip_get_ppreferredid_display_name(sip_header_value_t,
			    int *);
extern const sip_str_t	*sip_get_ppreferredid_uri_str(sip_header_value_t,
			    int *);
extern const sip_str_t	*sip_get_priv_value(sip_header_value_t, int *);
extern int		sip_get_rack_resp_num(sip_msg_t, int *);
extern int		sip_get_rack_cseq_num(sip_msg_t, int *);
extern sip_method_t	sip_get_rack_method(sip_msg_t, int *);
extern int		sip_get_rseq_resp_num(sip_msg_t, int *);

extern int		sip_copy_start_line(sip_msg_t, sip_msg_t);
extern int		sip_delete_start_line(sip_msg_t sip_msg);
extern int		sip_copy_header(sip_msg_t, sip_header_t, char *);
extern int		sip_copy_header_by_name(sip_msg_t, sip_msg_t, char *,
			    char *);
extern int		sip_copy_all_headers(sip_msg_t, sip_msg_t);
extern int		sip_delete_header_by_name(sip_msg_t, char *);
extern int		sip_add_header(sip_msg_t, char *);
extern sip_header_t	sip_add_param(sip_header_t, char *, int *);
extern int		sip_delete_header(sip_header_t);
extern int		sip_delete_value(sip_header_t, sip_header_value_t);
extern sip_msg_t	sip_clone_msg(const sip_msg_t);
extern sip_msg_t	sip_create_response(const sip_msg_t, int, char *,
			    char *, char *);
extern int		sip_create_OKack(const sip_msg_t, sip_msg_t, char *,
			    char *, int, char *);
extern char 		*sip_get_resp_desc(int);
extern char		*sip_get_branchid(const sip_msg_t, int *);

extern const struct sip_header	*sip_get_header(sip_msg_t, char *, sip_header_t,
				    int *);
extern const struct sip_value	*sip_get_header_value(
				    const struct sip_header *, int *);
extern const struct sip_value	*sip_get_next_value(sip_header_value_t, int *);
extern const sip_str_t		*sip_get_param_value(sip_header_value_t,
				    char *, int *);
extern const sip_param_t	*sip_get_params(sip_header_value_t, int *);
extern boolean_t		sip_is_param_present(const sip_param_t *,
				    char *, int);

extern char		*sip_msg_to_str(sip_msg_t, int *);
extern char		*sip_hdr_to_str(sip_header_t, int *);
extern char		*sip_reqline_to_str(sip_msg_t, int *);
extern char		*sip_respline_to_str(sip_msg_t, int *);
extern boolean_t	sip_msg_is_request(const sip_msg_t, int *);
extern boolean_t	sip_msg_is_response(const sip_msg_t, int *);
extern sip_method_t	sip_get_request_method(const sip_msg_t, int *);
extern const sip_str_t	*sip_get_request_uri_str(sip_msg_t, int *);
extern int		sip_get_response_code(sip_msg_t, int *);
extern const sip_str_t	*sip_get_response_phrase(sip_msg_t, int *);
extern const sip_str_t	*sip_get_sip_version(sip_msg_t, int *);
extern int		sip_get_msg_len(sip_msg_t, int *);
extern const sip_str_t	*sip_get_route_uri_str(sip_header_value_t, int *);
extern const sip_str_t	*sip_get_route_display_name(sip_header_value_t, int *);
extern const sip_str_t	*sip_get_contact_uri_str(sip_header_value_t, int *);
extern const sip_str_t	*sip_get_contact_display_name(sip_header_value_t,
			    int *);
extern const sip_str_t	*sip_get_from_uri_str(sip_msg_t, int *);
extern const sip_str_t	*sip_get_from_display_name(sip_msg_t, int *);
extern const sip_str_t	*sip_get_from_tag(sip_msg_t, int *);
extern const sip_str_t	*sip_get_to_uri_str(sip_msg_t, int *);
extern const sip_str_t	*sip_get_to_display_name(sip_msg_t, int *);
extern const sip_str_t	*sip_get_to_tag(sip_msg_t, int *);
extern const sip_str_t	*sip_get_callid(sip_msg_t, int *);
extern int		sip_get_callseq_num(sip_msg_t, int *);
extern sip_method_t	sip_get_callseq_method(sip_msg_t, int *);
extern const sip_str_t	*sip_get_via_sent_by_host(sip_header_value_t, int *);
extern int		sip_get_via_sent_by_port(sip_header_value_t, int *);
extern const sip_str_t	*sip_get_via_sent_protocol_version(sip_header_value_t,
			    int *);
extern const sip_str_t	*sip_get_via_sent_protocol_name(sip_header_value_t,
			    int *);
extern const sip_str_t	*sip_get_via_sent_transport(sip_header_value_t,
			    int *);
extern int 		sip_get_maxforward(sip_msg_t, int *);
extern int 		sip_get_content_length(sip_msg_t, int *);
extern const sip_str_t	*sip_get_content_type(sip_msg_t, int *);
extern const sip_str_t	*sip_get_content_sub_type(sip_msg_t, int *);
extern char		*sip_get_content(sip_msg_t, int *);
extern sip_msg_t	sip_create_dialog_req(sip_method_t, sip_dialog_t,
			    char *, char *, int, char *, uint32_t, int);
extern sip_msg_t	sip_create_dialog_req_nocontact(sip_method_t,
			    sip_dialog_t, char *, char *, int, char *,
			    uint32_t, int);

extern int			sip_get_dialog_state(sip_dialog_t, int *);
extern int			sip_get_dialog_method(sip_dialog_t, int *);
extern const sip_str_t		*sip_get_dialog_callid(sip_dialog_t, int *);
extern const sip_str_t		*sip_get_dialog_local_tag(sip_dialog_t, int *);
extern const sip_str_t		*sip_get_dialog_remote_tag(sip_dialog_t, int *);
extern const struct sip_uri	*sip_get_dialog_local_uri(sip_dialog_t, int *);
extern const struct sip_uri	*sip_get_dialog_remote_uri(sip_dialog_t, int *);
extern const struct sip_uri	*sip_get_dialog_remote_target_uri(sip_dialog_t,
				    int *);
extern const struct sip_uri	*sip_get_dialog_local_contact_uri(sip_dialog_t,
				    int *);
extern const sip_str_t		*sip_get_dialog_route_set(sip_dialog_t, int *);
extern boolean_t		sip_is_dialog_secure(sip_dialog_t, int *);
extern uint32_t			sip_get_dialog_local_cseq(sip_dialog_t, int *);
extern uint32_t			sip_get_dialog_remote_cseq(sip_dialog_t, int *);
extern int			sip_get_dialog_type(sip_dialog_t dialog, int *);

extern void			sip_hold_dialog(sip_dialog_t);
extern void			sip_release_dialog(sip_dialog_t);
extern void			sip_delete_dialog(sip_dialog_t);

extern sip_uri_t		sip_parse_uri(sip_str_t *, int *);
extern void			sip_free_parsed_uri(sip_uri_t);
extern boolean_t		sip_is_sipuri(const struct sip_uri *);
extern const sip_str_t		*sip_get_uri_scheme(const struct sip_uri *,
				    int *);
extern const sip_str_t		*sip_get_uri_user(const struct sip_uri *,
				    int *);
extern const sip_str_t		*sip_get_uri_password(const struct sip_uri *,
				    int *);
extern const sip_str_t		*sip_get_uri_host(const struct sip_uri *,
				    int *);
extern int			sip_get_uri_port(const struct sip_uri *,
				    int *error);
extern const sip_param_t	*sip_get_uri_params(const struct sip_uri *,
				    int *);
extern const sip_str_t		*sip_get_uri_headers(const struct sip_uri *,
				    int *);
extern const sip_str_t		*sip_get_uri_opaque(const struct sip_uri *,
				    int *);
extern const sip_str_t		*sip_get_uri_query(const struct sip_uri *,
				    int *);
extern const sip_str_t		*sip_get_uri_path(const struct sip_uri *,
				    int *);
extern const sip_str_t		*sip_get_uri_regname(const struct sip_uri *,
				    int *);
extern boolean_t		sip_is_uri_teluser(const struct sip_uri *);
extern int			sip_get_uri_errflags(const struct sip_uri *,
				    int *);
extern char			*sip_uri_errflags_to_str(int);

extern const struct sip_uri	*sip_get_request_uri(sip_msg_t, int *);
extern const struct sip_uri	*sip_get_uri_parsed(sip_header_value_t, int *);

/* Transaction functions */
extern const struct sip_xaction	*sip_get_trans(sip_msg_t, int, int *);
extern char 			*sip_get_trans_branchid(sip_transaction_t,
				    int *);
extern sip_method_t		sip_get_trans_method(sip_transaction_t,
				    int *);
extern int			sip_get_trans_state(sip_transaction_t, int *);
extern const struct sip_message	*sip_get_trans_resp_msg(sip_transaction_t,
				    int *);
extern const struct sip_message	*sip_get_trans_orig_msg(sip_transaction_t,
				    int *);
extern void			sip_hold_trans(sip_transaction_t);
extern void			sip_release_trans(sip_transaction_t);
extern const struct sip_conn_object	*sip_get_trans_conn_obj(
					    sip_transaction_t, int *);
#ifdef	__cplusplus
}
#endif

#endif	/* _SIP_H */
