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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SLP_INTERNAL_H
#define	_SLP_INTERNAL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <thread.h>
#include <synch.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <slp.h>

/* SLPv2 function numbers */
#define	SRVRQST		1
#define	SRVRPLY		2
#define	SRVREG		3
#define	SRVDEREG	4
#define	SRVACK		5
#define	ATTRRQST	6
#define	ATTRRPLY	7
#define	DAADVERT	8
#define	SRVTYPERQST	9
#define	SRVTYPERPLY	10
#define	SAADVERT	11

/* SLPv2 protocol error functions, hidden under the API */
typedef enum {
	SLP_MSG_PARSE_ERROR		= 256,	/* used internally */
	SLP_VER_NOT_SUPPORTED		= 9,
	SLP_SICK_DA			= 10,
	SLP_DA_BUSY_NOW			= 11,
	SLP_OPTION_NOT_UNDERSTOOD	= 12,
	SLP_RQST_NOT_SUPPORTED		= 13
} slp_proto_err;

/* Defaults and properties */
#define	SLP_VERSION	2
#define	SLP_DEFAULT_SENDMTU		1400
#define	SLP_PORT	427
#define	SLP_DEFAULT_MAXWAIT	15000
#define	SLP_DEFAULT_MAXRESULTS	-1
#define	SLP_MULTICAST_ADDRESS	inet_addr("239.255.255.253")
#define	SLP_MAX_STRINGLEN	USHRT_MAX
#define	SLP_MAX_MSGLEN		16777216	/* max message length 2^24 */
#define	SLP_SUN_SCOPES_TAG	"424242SUN-TABLE-SCOPES424242"
#define	SLP_SUN_VERSION_TAG	"424242SUN-TABLE-VERSION424242"

/* Property names */
#define	SLP_CONFIG_USESCOPES		"net.slp.useScopes"
#define	SLP_CONFIG_ISBROADCASTONLY	"net.slp.isBroadcastOnly"
#define	SLP_CONFIG_MULTICASTTTL		"net.slp.multicastTTL"
#define	SLP_CONFIG_MULTICASTMAXWAIT	"net.slp.multicastMaximumWait"
#define	SLP_CONFIG_DATAGRAMTIMEOUTS	"net.slp.datagramTimeouts"
#define	SLP_CONFIG_MULTICASTTIMEOUTS	"net.slp.multicastTimeouts"
#define	SLP_CONFIG_MTU			"net.slp.mtu"
#define	SLP_CONFIG_INTERFACES		"net.slp.interfaces"
#define	SLP_CONFIG_LOCALE		"net.slp.locale"
#define	SLP_CONFIG_MAXRESULTS		"net.slp.maxResults"
#define	SLP_CONFIG_USEGETXXXBYYYY	"sun.net.slp.usegetxxxbyyyy"
#define	SLP_CONFIG_TYPEHINT		"net.slp.typeHint"
#define	SLP_CONFIG_SECURITY_ON		"net.slp.securityEnabled"
#define	SLP_CONFIG_SPI			"sun.net.slp.SPIs"
#define	SLP_CONFIG_SIGN_AS		"sun.net.slp.signAs"
#define	SLP_CONFIG_BYPASS_AUTH		"sun.net.slp.bypassAuth"
#define	SLP_CONFIG_AUTH_BACKEND		"sun.net.slp.authBackend"
#define	SLP_SUN_DA_TYPE			"service:directory-agent.sun"

#define	SLP_DEFAULT_CONFIG_FILE		"/etc/inet/slp.conf"

extern void slp_readConfig(void);

/* Synchronized queue structures and functions */

typedef void slp_queue_t;

extern slp_queue_t *slp_new_queue(SLPError *);
extern SLPError slp_enqueue(slp_queue_t *, void *);
extern SLPError slp_enqueue_at_head(slp_queue_t *, void *);
extern void *slp_dequeue_timed(slp_queue_t *, timestruc_t *, SLPBoolean *);
extern void *slp_dequeue(slp_queue_t *);
extern void slp_flush_queue(slp_queue_t *, void (*)(void *));
extern void slp_destroy_queue(slp_queue_t *);

typedef struct {
	struct iovec	*iov;
	int		iovlen;
	char	*msg;
	struct iovec	prlistlen;
	struct iovec	*prlist;
	struct iovec	scopeslen;
	struct iovec	*scopes;
} slp_msg_t;

/* Implementation of SLPHandle */
typedef struct handle_impl {
	const char	*locale;	/* language tag */
	int		fid;		/* SLP function ID */
	slp_msg_t	msg;		/* The SLP message */
	mutex_t		*tcp_lock;	/* TCP thread wait lock */
	int		tcp_ref_cnt;	/* TCP thread reference count */
	cond_t		*tcp_wait;	/* TCP thread wait condition var */
	SLPBoolean	async;		/* asynchronous flag */
	slp_queue_t	*q;		/* message queue for this handle */
	thread_t	producer_tid;	/* thr ID of message producer */
	thread_t	consumer_tid;	/* thr ID of message consumer */
	int		cancel;		/* cancellation flag */
	void		*ifinfo;	/* interface info */
	SLPBoolean	force_multicast; /* for SAAdvert solicitations */
	SLPBoolean	internal_call;	/* current call is an internal op */
	SLPBoolean	pending_outcall; /* is handle in use? */
	mutex_t		outcall_lock;	/* protects pending_outcall */
	cond_t		outcall_cv;	/* outcall cond var */
	SLPBoolean	close_on_end;	/* cleanup on slp_end_call */
} slp_handle_impl_t;

extern SLPError slp_start_call(slp_handle_impl_t *);
extern void slp_end_call(slp_handle_impl_t *);
extern void slp_cleanup_handle(slp_handle_impl_t *);

/* UA common functionality */
typedef void SLPGenericAppCB();
typedef SLPBoolean SLPMsgReplyCB(slp_handle_impl_t *, char *, void (*)(),
					void *, void **, int *);

extern SLPError slp_ua_common(SLPHandle, const char *, SLPGenericAppCB, void *,
				SLPMsgReplyCB);

extern SLPError slp_packSrvRqst(const char *, const char *,
				slp_handle_impl_t *);
extern SLPError slp_packSrvRqst_single(const char *, const char *,
					const char *, char **,
					const char *);
extern SLPBoolean slp_unpackSrvReply(slp_handle_impl_t *, char *,
					SLPSrvURLCallback, void *,
					void **, int *);
extern SLPError slp_packAttrRqst_single(const char *,
					const char *,
					const char *,
					char **,
					const char *);
extern SLPBoolean slp_UnpackAttrReply(slp_handle_impl_t *, char *,
					SLPAttrCallback, void *,
					void **, int *);
extern SLPError slp_getDAbyScope(const char *, slp_queue_t *);
extern SLPError slp_SAAdvert(slp_handle_impl_t *, void *);
extern SLPError slp_unpackDAAdvert(char *, char **, char **, char **,
					char **, SLPError *);
extern SLPError slp_unpackSAAdvert(char *, char **, char **, char **);

/* target selection routines */
typedef void slp_target_list_t;
typedef void slp_target_t;
extern SLPError slp_new_target_list(slp_handle_impl_t *hp, const char *,
					slp_target_list_t **);
extern const char *slp_get_uc_scopes(slp_target_list_t *);
extern const char *slp_get_mc_scopes(slp_target_list_t *);
extern slp_target_t *slp_next_uc_target(slp_target_list_t *);
extern slp_target_t *slp_next_failover(slp_target_t *);
extern void *slp_get_target_sin(slp_target_t *);
extern void slp_mark_target_used(slp_target_t *);
extern void slp_mark_target_failed(slp_target_t *);
extern slp_target_t *slp_fabricate_target(void *);
extern void slp_free_target(slp_target_t *);
extern void slp_destroy_target_list(slp_target_list_t *);

/* short-lived DA cache */
extern char *slp_find_das_cached(const char *);
extern void slp_put_das_cached(const char *, const char *, unsigned int);

/* networking */
extern void slp_uc_tcp_send(slp_handle_impl_t *, slp_target_t *,
				const char *, SLPBoolean, unsigned short);
extern void slp_uc_udp_send(slp_handle_impl_t *, slp_target_t *,
				const char *);
extern void slp_mc_send(slp_handle_impl_t *, const char *);
extern void slp_tcp_wait(slp_handle_impl_t *);
extern SLPError slp_tcp_read(int, char **);
extern char *slp_ntop(char *, int, const void *);
extern int slp_pton(const char *, void *);

/* IPC */
extern SLPError slp_send2slpd(const char *, char **);
extern SLPError slp_send2slpd_iov(struct iovec *, int, char **);

/* SLP-style list management */
extern int slp_onlist(const char *, const char *);
extern void slp_add2list(const char *, char **, SLPBoolean);
extern void slp_list_subtract(const char *, char **);

/* searching and storing */
typedef enum { preorder, postorder, endorder, leaf } VISIT;
extern void slp_twalk(void *, void (*)(void *, VISIT, int, void *),
			int, void *);
extern void *slp_tsearch(const void *, void **, int (*)());
extern void *slp_tfind(const void *, void *const *,
		int (*)(const void *, const void *));

/* DA and scope discovery routines */
extern SLPError slp_find_das(const char *, char **);
extern SLPError slp_administrative_scopes(char **, SLPBoolean);

/* UTF8 routines */
extern char *slp_utf_strchr(const char *, char);
extern int slp_strcasecmp(const char *, const char *);

/* Error reporting */
extern void slp_err(int, int, char *, char *, ...);

/* Mapping from protocol to API error codes */
extern SLPError slp_map_err(unsigned short);

/* Security: signing and verifying */
extern SLPError slp_sign(struct iovec *, int, time_t, struct iovec *, int);
extern SLPError slp_verify(struct iovec *, int, const char *,
			    size_t, int, size_t *);

/* Config convenience wrappers */
extern size_t slp_get_mtu();
extern int slp_get_next_onlist(char **);
extern int slp_get_maxResults();
#define	slp_get_mcmaxwait() atoi(SLPGetProperty(SLP_CONFIG_MULTICASTMAXWAIT))
#define	slp_get_maxresults() atoi(SLPGetProperty(SLP_CONFIG_MAXRESULTS))
#define	slp_get_multicastTTL() atoi(SLPGetProperty(SLP_CONFIG_MULTICASTTTL))
#define	slp_get_usebroadcast() \
	(!strcasecmp(SLPGetProperty(SLP_CONFIG_ISBROADCASTONLY), "true"))
#define	slp_get_security_on() \
	(!strcasecmp(SLPGetProperty(SLP_CONFIG_SECURITY_ON), "true"))
#define	slp_get_bypass_auth() \
	(!strcasecmp(SLPGetProperty(SLP_CONFIG_BYPASS_AUTH), "true"))

/* Primitive encoding routines */
extern SLPError slp_add_byte(char *, size_t, int, size_t *);
extern SLPError slp_add_sht(char *, size_t, unsigned short, size_t *);
extern SLPError slp_add_int32(char *, size_t, unsigned int, size_t *);
extern SLPError slp_add_string(char *, size_t, const char *, size_t *);
extern SLPError slp_get_byte(const char *, size_t, size_t *, int *);
extern SLPError slp_get_sht(const char *, size_t, size_t *, unsigned short *);
extern SLPError slp_get_int32(const char *, size_t, size_t *, unsigned int *);
extern SLPError slp_get_string(const char *, size_t, size_t *, char **);

/* Header generation and handling */

/* OFFSETS to fields in the header */
#define	SLP_VER		0
#define	SLP_FUN		1
#define	SLP_LEN		2
#define	SLP_FLAGS	5
#define	SLP_NEXTOP	7
#define	SLP_XID		10
#define	SLP_LANGLEN	12
#define	SLP_HDRLEN	14

/* Flags */
#define	SLP_OVERFLOW	(char)0x80
#define	SLP_FRESH	(char)0x40
#define	SLP_MCAST	(char)0x20

/* One byte macros (not needing byte order conversion) */
#define	slp_get_version(h)	(h)[SLP_VER]
#define	slp_set_version(h, v)	(h)[SLP_VER] = (v);
#define	slp_get_function(h)	(h)[SLP_FUN]
#define	slp_set_function(h, f)	(h)[SLP_FUN] = (f)
#define	slp_get_overflow(h)	((h)[SLP_FLAGS] & SLP_OVERFLOW)
#define	slp_set_overflow(h)	(h)[SLP_FLAGS] |= SLP_OVERFLOW
#define	slp_set_fresh(h)	(h)[SLP_FLAGS] |= SLP_FRESH
#define	slp_set_mcast(h)	(h)[SLP_FLAGS] |= SLP_MCAST

/* Routines requiring byte order conversions */
extern unsigned short slp_header_get_sht(const char *, size_t);
extern void slp_header_set_sht(char *, unsigned short, size_t);
extern unsigned int slp_header_get_int24(const char *, size_t);
extern void slp_header_set_int24(char *, unsigned int, size_t);
extern slp_proto_err slp_get_errcode(char *);
#define	slp_get_length(h)	slp_header_get_int24((h), SLP_LEN)
#define	slp_set_length(h, x)	slp_header_set_int24((h), (int)(x), SLP_LEN)
#define	slp_get_langlen(h)	slp_header_get_sht((h), SLP_LANGLEN)
#define	slp_set_langlen(h, x)	slp_header_set_sht((h), (x), SLP_LANGLEN)
#define	slp_get_option(h)	slp_header_get_int24((h), SLP_NEXTOP)
#define	slp_set_option(h, x)	slp_header_set_int24((h), (x), SLP_NEXTOP)
#define	slp_get_xid(h)		slp_header_get_sht((h), SLP_XID)
#define	slp_set_xid(h, x)	slp_header_set_sht((h), (x), SLP_XID)

extern SLPError slp_add_header(const char *, char *, size_t, int,
				size_t, size_t *);
#define	slp_hdrlang_length(h)	\
		(SLP_HDRLEN + strlen(((slp_handle_impl_t *)(h))->locale))

#ifdef __cplusplus
}
#endif

#endif	/* _SLP_INTERNAL_H */
