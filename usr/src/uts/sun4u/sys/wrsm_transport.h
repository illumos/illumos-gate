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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_WRSM_TRANSPORT_H
#define	_WRSM_TRANSPORT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/wrsm_common.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * WRSM_TL_VERSION - If any message formats change, this constant must
 * change in the next release, to ensure that imcompatible drivers
 * recognize the version skew.
 */
#define	WRSM_TL_VERSION	0x1

/*
 * Messagetypes
 * When you add a message here, remember to add it to fuction
 * messagetypes2string in wrsm_tl.c.
 */
enum {
	/* Common message types */
	WRSM_MSG_ACK,
	WRSM_MSG_NACK,
	WRSM_MSG_PING,
	WRSM_MSG_PING_RESPONSE,
	/* Config message types */
	WRSM_MSG_CONFIG_COOKIE,
	WRSM_MSG_CONFIG_PASSTHROUGH_LIST,
	WRSM_MSG_CONFIG_PASSTHROUGH_LIST_RESPONSE,
	WRSM_MSG_CONFIG_CNODE_ACCESS,
	/* Multihop message types */
	/* Session message types */
	WRSM_MSG_SESSION_START,
	WRSM_MSG_SESSION_START_RESPONSE,
	WRSM_MSG_SESSION_END,
	/* RSMPI Segment message types */
	WRSM_MSG_SEGMENT_CONNECT,
	WRSM_MSG_SEGMENT_CONNECT_RESPONSE,
	WRSM_MSG_SEGMENT_SMALLPUTMAP,
	WRSM_MSG_SEGMENT_SMALLPUTMAP_RESPONSE,
	WRSM_MSG_SEGMENT_BARRIERMAP,
	WRSM_MSG_SEGMENT_BARRIERMAP_RESPONSE,
	WRSM_MSG_SEGMENT_SEGMAP,
	WRSM_MSG_SEGMENT_SEGMAP_RESPONSE,
	WRSM_MSG_SEGMENT_DISCONNECT,
	WRSM_MSG_SEGMENT_UNPUBLISH,
	WRSM_MSG_SEGMENT_UNPUBLISH_RESPONSE,
	WRSM_MSG_SEGMENT_ACCESS,
	WRSM_MSG_SEGMENT_ACCESS_RESPONSE,
	/* RSMPI Interrupt message types */
	WRSM_MSG_INTR_RECVQ_CREATE,
	WRSM_MSG_INTR_RECVQ_CREATE_RESPONSE,
	WRSM_MSG_INTR_RECVQ_CONFIG,
	WRSM_MSG_INTR_RECVQ_CONFIG_RESPONSE,
	WRSM_MSG_INTR_RECVQ_DESTROY,
	/* RSMPI Barrier message types */
	/* RSMAPI Segment message types */
	/* RSMAPI Interrupt message types */
	/* RSMAPI Barrier message types */
	WRSM_MSG_TYPES_MAX
};
typedef uint8_t  wrsm_message_type_t;

/*
 * Format of messages
 */
#define	WRSM_TL_MSG_SIZE	(WRSM_CACHELINE_SIZE)

typedef uint32_t wrsm_messageid_t;
typedef uint8_t  wrsm_version_t;
typedef uint8_t  wrsm_sessionid_t;
#define	SESS_ID_INVALID	0

typedef struct wrsm_message_header {
	uint32_t		reserved1;
	wrsm_version_t		version;
	wrsm_sessionid_t	session_id;
	cnodeid_t		source_cnode;
	wrsm_message_type_t	message_type;
	wrsm_messageid_t	message_id;
	uint32_t		reserved2;
} wrsm_message_header_t;

#define	WRSM_MESSAGE_BODY_SIZE (WRSM_TL_MSG_SIZE - \
				sizeof (wrsm_message_header_t))

/*
 * An object of type wrsm_message_t must be 64-byte aligned. The user can
 * cast the body to message-specific structures.
 */
typedef struct wrsm_message {
	wrsm_message_header_t  header;
	uint8_t		 body[WRSM_MESSAGE_BODY_SIZE];
} wrsm_message_t;

/*
 * The following type may be allocated on the stack, it has the
 * right size for the wrsm message, optimal aignment for wrsm_blkread/blkwrite
 * and can be casted into either wrsm_message_t type or wrsm_smallput_msg.
 * The wrsm_message_t requires 32 bit allignment, the wrsm_raw_message
 * is declared as an array of uint64_t - giving it 8 byte alignment
 */
typedef uint64_t wrsm_raw_message_t[WRSM_TL_MSG_SIZE / sizeof (uint64_t)];

/*
 * Definition of the user's message handler function. rxhandler is called
 * when a given message type is received. Returns boolean to indicate
 * if the message was successfully processed. For datagrams, the return
 * value is ignored. For RPC messages, this function is called before the
 * thread calling rpc() is awakened, so returning FALSE will result in the
 * message being ignored, and the pending thread will eventually timeout.
 * The message buffer will be allcoated and freed by the transport, and
 * should not be freed by the user.
 */
typedef boolean_t (*wrsm_message_rxhandler_t)(wrsm_network_t *network,
					wrsm_message_t *message);

/*
 * Definition of the user's message handler function. txhandler is used for
 * formatting any transmit messages. Returns boolean to indicate if the
 * message was successfully processed. Returning FALSE will cause the
 * message to be discarded without being sent to the remote node (used,
 * for example, if a session cannot be established with the remote cnode).
 * The message buffer will be allcoated and freed by the
 * transport, and should not be freed by the user.
 */
typedef boolean_t (*wrsm_message_txhandler_t)(wrsm_network_t *network,
					cnodeid_t destination,
					wrsm_message_t *message);

/*
 * Transport functions
 *
 * The following functions return 0 for success.
 */

/* Initializes the transport for a specific RSM network */
int wrsm_tl_init(wrsm_network_t *rsm_network);

/* Cleans-up the transport for a specific RSM network */
void wrsm_tl_fini(wrsm_network_t *rsm_network);

/* Informs the transport that a new cnode is part of the config */
int wrsm_tl_newcnode(wrsm_network_t *rsm_network, cnodeid_t cnodeid);

/* Informs the transport that a cnode is no longer part of config */
int wrsm_tl_removecnode(wrsm_network_t *rsm_network, cnodeid_t cnodeid);

/* Informs the transport that a cnode is reachable */
void wrsm_tl_reachable(wrsm_network_t *rsm_network, cnodeid_t cnodeid);

/* Informs the transport that a cnode is no longer reachable */
void wrsm_tl_unreachable(wrsm_network_t *rsm_network, cnodeid_t cnodeid);

/* Adds user-defined handlers for a specific message type */
int wrsm_tl_add_handler(wrsm_network_t *rsm_network, wrsm_message_type_t,
    wrsm_message_txhandler_t send_func, wrsm_message_rxhandler_t receive_func);

/* Sends a datagram. Caller must allocate and free msg buffer. */
int wrsm_tl_dg(wrsm_network_t *rsm_network, cnodeid_t destination,
    wrsm_message_t *msg);

/*
 * Sends a message, waits for a response. If successful (return code is 0),
 * the response structure will contain the message from the remote node.
 * The caller must allocate and free both the msg and response buffer.
 * The caller may use the same message buffer for both the msg and response,
 * and the response will overwrite the original message.
 */
int wrsm_tl_rpc(wrsm_network_t *rsm_network, cnodeid_t destination,
    wrsm_message_t *msg, wrsm_message_t *response);

/*
 * Response to an rpc message, called by a receive message handler. The
 * orig_msg must be an unmodified version of the message buffer provided
 * to the receive message handler. The caller must allocate and free the
 * response buffer.
 */
int wrsm_tl_rsp(wrsm_network_t *rsm_network, wrsm_message_t *orig_msg,
    wrsm_message_t *response);

/*
 * The macro WRSM_TL_DUMP_MESSAGE dumps the contents of a message to the
 * console for debugging. If DEBUG is not defined, the macro results in
 * no code being generated.
 */
#ifdef DEBUG
#define	WRSM_TL_DUMP_MESSAGE(txt, msg) wrsm_tl_dump_message(txt, msg)
void wrsm_tl_dump_message(char *txt, wrsm_message_t *msg);
#else
#define	WRSM_TL_DUMP_MESSAGE(txt, msg)
#endif /* DEBUG */
/*
 * Standard handler functions
 */

/* Use WRSM_TL_NO_HANDLER if you don't need a send/receive handler. */
#define	WRSM_TL_NO_HANDLER	NULL

/*
 * Adds the session id to the message header. If there is currently no
 * session with the destination node, it will attempt to establish a new
 * session.
 */
boolean_t wrsm_tl_txhandler_sessionid(wrsm_network_t *, cnodeid_t,
    wrsm_message_t *);

/* Validates the session id for an incoming rpc response. */
boolean_t wrsm_tl_rxhandler_sessionid(wrsm_network_t *, wrsm_message_t *);

#ifdef __cplusplus
}
#endif

#endif /* _WRSM_TRANSPORT_H */
