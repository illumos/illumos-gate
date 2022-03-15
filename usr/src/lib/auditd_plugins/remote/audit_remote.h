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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

#ifndef	_AUDIT_REMOTE_H
#define	_AUDIT_REMOTE_H


#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <security/auditd.h>

/* gettext() obfuscation routine for lint */
#ifdef __lint
#define	gettext(x)	x
#endif


/* send_record() return code */
enum send_record_rc {
	SEND_RECORD_SUCCESS,
	SEND_RECORD_NEXT,
	SEND_RECORD_RETRY,
	SEND_RECORD_FAIL
};
typedef enum send_record_rc send_record_rc_t;

/* closing helpers - the reason of connection closure */
enum close_rsn_e {
		RSN_UNDEFINED,		/* reason not defined */
		RSN_INIT_POLL,		/* poll() initialization failed */
		RSN_TOK_RECV_FAILED,	/* token receiving failed */
		RSN_TOK_TOO_BIG,	/* unacceptable token size */
		RSN_TOK_UNVERIFIABLE,	/* received unverifiable token */
		RSN_SOCKET_CLOSE,	/* socket closure */
		RSN_SOCKET_CREATE,	/* socket creation */
		RSN_CONNECTION_CREATE,	/* connection creation */
		RSN_PROTOCOL_NEGOTIATE,	/* protocol version negotiation */
		RSN_GSS_CTX_ESTABLISH,	/* establish GSS-API context */
		RSN_GSS_CTX_EXP,	/* expiration of the GSS-API context */
		RSN_UNKNOWN_AF,		/* unknown address family */
		RSN_MEMORY_ALLOCATE,	/* memory allocation failure */
		RSN_OTHER_ERR		/* other, not classified error */
};
typedef enum close_rsn_e close_rsn_t;

/* linked list of remote audit hosts (servers) */
typedef struct hostlist_s hostlist_t;
struct hostlist_s {
	hostlist_t	*next_host;
	struct hostent	*host;
	in_port_t	port;		/* TCP port number */
	gss_OID		mech;		/* GSS mechanism - see mech(5) */
};

/* transq_t - single, already sent token in the transmit queue. */
struct transq_node_s {
	struct transq_node_s	*next;
	struct transq_node_s	*prev;
	gss_buffer_desc		seq_token;	/* seq num || plain token */
	uint64_t		seq_num;	/* seq number */
};
typedef struct transq_node_s transq_node_t;

/* transq_hdr_t - the transmit queue header structure */
struct transq_hdr_s {
	struct transq_node_s	*head;
	struct transq_node_s	*end;
	long			count;	/* amount of nodes in the queue */
};
typedef struct transq_hdr_s transq_hdr_t;

/* pipe_msg_s - the notification pipe message */
struct pipe_msg_s {
	int		sock_num;	/* socket fd to be poll()ed and more */
	boolean_t	sync;		/* call the sync routines */
};
typedef struct pipe_msg_s pipe_msg_t;


/*
 * Cross audit_remote plugin source code shared functions and bool parameters.
 *
 * reset_transport() helpers:
 *     arg1) DO_SYNC, DO_NOT_SYNC
 *     arg2) DO_EXIT, DO_CLOSE, DO_NOT_EXIT, DO_NOT_CLOSE
 */
#define	DO_SYNC		B_TRUE
#define	DO_NOT_SYNC	B_FALSE
#define	DO_EXIT		B_FALSE
#define	DO_CLOSE	B_TRUE
#define	DO_NOT_EXIT	B_CLOSE
#define	DO_NOT_CLOSE	B_EXIT
extern void		reset_transport(boolean_t, boolean_t);
extern send_record_rc_t send_record(struct hostlist_s *, const char *, size_t,
    uint64_t, close_rsn_t *);

#if DEBUG
#define	DPRINT(x) { (void) fprintf x; (void) fflush(dfile); }
#else
#define	DPRINT(x)
#endif

#if DEBUG
extern FILE	*dfile;
#endif


#ifdef __cplusplus
}
#endif

#endif	/* _AUDIT_REMOTE_H */
