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
 */
/*
 * Copyright (c) 2013, 2015 by Delphix. All rights reserved.
 */

#ifndef	_DHCPAGENT_IPC_H
#define	_DHCPAGENT_IPC_H

#include <sys/socket.h>
#include <net/if.h>		/* LIFNAMSIZ */
#include <stddef.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/dhcp.h>
#include <dhcp_impl.h>

/*
 * dhcpagent_ipc.[ch] comprise the interface used to perform
 * interprocess communication with the agent.  see dhcpagent_ipc.c for
 * documentation on how to use the exported functions.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#define	DHCP_AGENT_PATH		"/sbin/dhcpagent"
#define	DHCP_IPC_LISTEN_BACKLOG	30
#define	IPPORT_DHCPAGENT	4999
#define	DHCP_IPC_MAX_WAIT	15	/* max seconds to wait to start agent */

/*
 * return values which should be used by programs which talk to the
 * agent (for uniformity).
 */

#define	DHCP_EXIT_SUCCESS	0
#define	DHCP_EXIT_FAILURE	2
#define	DHCP_EXIT_BADARGS	3
#define	DHCP_EXIT_TIMEOUT	4
#define	DHCP_EXIT_SYSTEM	6

/*
 * opaque types for requests and replies.  users of this api do not
 * need to understand their contents.
 */

typedef struct dhcp_ipc_request dhcp_ipc_request_t;
typedef struct dhcp_ipc_reply   dhcp_ipc_reply_t;

/* payloads that can be passed in a request or reply */

typedef enum {
	DHCP_TYPE_OPTION,
	DHCP_TYPE_STATUS,
	DHCP_TYPE_OPTNUM,
	DHCP_TYPE_NONE
} dhcp_data_type_t;

/*
 * requests that can be sent to the agent
 *
 * code in dhcpagent relies on the numeric values of these
 * requests -- but there's no sane reason to change them anyway.
 *
 * If any commands are changed, added, or removed, see the ipc_typestr[]
 * array in dhcpagent_ipc.c.
 */

typedef enum {
	DHCP_DROP,	DHCP_EXTEND,  DHCP_PING,    DHCP_RELEASE,
	DHCP_START,  	DHCP_STATUS,  DHCP_INFORM,  DHCP_GET_TAG,
	DHCP_NIPC,	/* number of supported requests */
	DHCP_PRIMARY = 0x100,
	DHCP_V6 = 0x200
} dhcp_ipc_type_t;

/* structure passed with the DHCP_GET_TAG request */

typedef struct {
	uint_t		category;
	uint_t		code;
	uint_t		size;
} dhcp_optnum_t;

#define	DHCP_IPC_CMD(type)	((type) & 0x00ff)
#define	DHCP_IPC_FLAGS(type)	((type) & 0xff00)

/* special timeout values for dhcp_ipc_make_request() */

#define	DHCP_IPC_WAIT_FOREVER	(-1)
#define	DHCP_IPC_WAIT_DEFAULT	(-2)

/*
 * errors that can be returned from the provided functions.
 * note: keep in sync with dhcp_ipc_strerror()
 */

enum {
	/* System call errors must be kept contiguous */
	DHCP_IPC_SUCCESS,	DHCP_IPC_E_SOCKET,	DHCP_IPC_E_FCNTL,
	DHCP_IPC_E_READ,	DHCP_IPC_E_ACCEPT,	DHCP_IPC_E_CLOSE,
	DHCP_IPC_E_BIND,	DHCP_IPC_E_LISTEN,	DHCP_IPC_E_MEMORY,
	DHCP_IPC_E_CONNECT,	DHCP_IPC_E_WRITEV,	DHCP_IPC_E_POLL,

	/* All others follow */
	DHCP_IPC_E_TIMEOUT,	DHCP_IPC_E_SRVFAILED,	DHCP_IPC_E_EOF,
	DHCP_IPC_E_INVIF,	DHCP_IPC_E_INT,		DHCP_IPC_E_PERM,
	DHCP_IPC_E_OUTSTATE,	DHCP_IPC_E_PEND,	DHCP_IPC_E_BOOTP,
	DHCP_IPC_E_CMD_UNKNOWN, DHCP_IPC_E_UNKIF,	DHCP_IPC_E_PROTO,
	DHCP_IPC_E_FAILEDIF,	DHCP_IPC_E_NOPRIMARY,	DHCP_IPC_E_DOWNIF,
	DHCP_IPC_E_NOIPIF,	DHCP_IPC_E_NOVALUE,	DHCP_IPC_E_RUNNING
};

/*
 * low-level public dhcpagent ipc functions -- these are for use by
 * programs that need to communicate with the dhcpagent.  these will
 * remain relatively stable.
 */

extern const char	*dhcp_ipc_strerror(int);
extern dhcp_ipc_request_t *dhcp_ipc_alloc_request(dhcp_ipc_type_t, const char *,
			    const void *, uint32_t, dhcp_data_type_t);
extern void		*dhcp_ipc_get_data(dhcp_ipc_reply_t *, size_t *,
			    dhcp_data_type_t *);
extern int		dhcp_ipc_make_request(dhcp_ipc_request_t *,
			    dhcp_ipc_reply_t **, int32_t);
extern const char	*dhcp_ipc_type_to_string(dhcp_ipc_type_t);

/*
 * high-level public dhcpagent ipc functions
 */

extern int		dhcp_ipc_getinfo(dhcp_optnum_t *, DHCP_OPT **, int32_t);

/*
 * private dhcpagent ipc "server side" functions -- these are only for
 * use by dhcpagent(1M) and are subject to change.
 */

extern int		dhcp_ipc_init(int *);
extern int		dhcp_ipc_accept(int, int *, int *);
extern int		dhcp_ipc_recv_request(int, dhcp_ipc_request_t **, int);
extern dhcp_ipc_reply_t	*dhcp_ipc_alloc_reply(dhcp_ipc_request_t *, int,
			    const void *, uint32_t, dhcp_data_type_t);
extern int		dhcp_ipc_send_reply(int, dhcp_ipc_reply_t *);
extern int		dhcp_ipc_close(int);

/*
 * values for if_state in the dhcp_status_t
 *
 * code in this library and dhcpagent rely on the numeric values of these
 * requests -- but there's no sane reason to change them anyway.
 */

typedef enum {
	INIT,				/* nothing done yet */
	SELECTING,			/* sent DISCOVER, waiting for OFFERs */
	REQUESTING,			/* sent REQUEST, waiting for ACK/NAK */
	PRE_BOUND,			/* have ACK, setting up interface */
	BOUND,				/* have a valid lease */
	RENEWING,			/* have lease, but trying to renew */
	REBINDING,			/* have lease, but trying to rebind */
	INFORMATION,			/* sent INFORM, received ACK */
	INIT_REBOOT,			/* attempt to use cached ACK/Reply */
	ADOPTING,			/* attempting to adopt */
	INFORM_SENT,			/* sent INFORM, awaiting ACK */
	DECLINING,			/* sent v6 Decline, awaiting Reply */
	RELEASING,			/* sent v6 Release, awaiting Reply */
	DHCP_NSTATES			/* total number of states */
} DHCPSTATE;

/* values for if_dflags in the dhcp_status_t */

#define	DHCP_IF_PRIMARY		0x0100	/* interface is primary interface */
#define	DHCP_IF_BUSY		0x0200	/* asynchronous command pending */
#define	DHCP_IF_BOOTP		0x0400	/* interface is using bootp */
#define	DHCP_IF_REMOVED		0x0800	/* interface is going away */
#define	DHCP_IF_FAILED		0x1000	/* interface configuration problem */
#define	DHCP_IF_V6		0x2000	/* DHCPv6 interface */

/*
 * structure passed with the DHCP_STATUS replies
 *
 * when parsing a dhcp_status_t, `version' should always be checked
 * if there is a need to access any fields which were not defined in
 * version 1 of this structure.
 *
 * as new fields are added to the dhcp_status_t, they should be
 * appended to the structure and the version number incremented.
 */

typedef struct dhcp_status {
	uint8_t		version;	/* version of this structure */

	char		if_name[LIFNAMSIZ];
	DHCPSTATE	if_state;	/* state of interface; see above */

	time_t		if_began;	/* time lease began (absolute) */
	time_t		if_t1;		/* renewing time (absolute) */
	time_t		if_t2;		/* rebinding time (absolute) */
	time_t		if_lease;	/* lease expiration time (absolute) */

	uint16_t	if_dflags;	/* DHCP flags on this if; see above */

	/*
	 * these three fields are initially zero, and get incremented
	 * as if_state goes from INIT -> BOUND (or INIT ->
	 * INFORMATION).  if and when the interface moves to the
	 * RENEWING state, these fields are reset, so they always
	 * either indicate the number of packets sent, received, and
	 * declined while obtaining the current lease (if BOUND), or
	 * the number of packets sent, received, and declined while
	 * attempting to obtain a future lease (if any other state).
	 */

	uint32_t	if_sent;
	uint32_t	if_recv;
	uint32_t	if_bad_offers;
} dhcp_status_t;

#define	DHCP_STATUS_VER		1	/* current version of dhcp_status_t */
#define	DHCP_STATUS_VER1_SIZE	(offsetof(dhcp_status_t, if_bad_offers) + \
				    sizeof (uint32_t))

/*
 * the remainder of this file contains implementation-specific
 * artifacts which may change. note that a `dhcp_ipc_request_t' and a
 * `dhcp_ipc_reply_t' are incomplete types as far as consumers of this
 * api are concerned.  use these details at your own risk.
 */

typedef hrtime_t dhcp_ipc_id_t;

/*
 * note: the first 4 fields of the dhcp_ipc_request_t and dhcp_ipc_reply_t
 *	 are intentionally identical; code in dhcpagent_ipc.c counts on it!
 *
 * we pack these structs to ensure that their lengths will be identical between
 * 32-bit and 64-bit executables.
 */

#pragma pack(4)

struct	dhcp_ipc_request {
	dhcp_ipc_type_t  message_type;	/* type of request */
	dhcp_ipc_id_t	 ipc_id;	/* per-socket unique request id */
	dhcp_data_type_t data_type;	/* type of payload */
	uint32_t	 data_length;	/* size of actual data in the buffer */
	char		 ifname[LIFNAMSIZ];
	int32_t		 timeout;	/* timeout in seconds */
	uchar_t		 buffer[1];	/* dynamically extended */
};

struct	dhcp_ipc_reply {
	dhcp_ipc_type_t	 message_type;	/* same message type as request */
	dhcp_ipc_id_t	 ipc_id;	/* same id as request */
	dhcp_data_type_t data_type;	/* type of payload */
	uint32_t	 data_length;	/* size of actual data in the buffer */
	uint32_t	 return_code;	/* did the request succeed? */
	uchar_t		 buffer[1];	/* dynamically extended */
};

#pragma pack()

#define	DHCP_IPC_REPLY_SIZE	offsetof(dhcp_ipc_reply_t, buffer)
#define	DHCP_IPC_REQUEST_SIZE	offsetof(dhcp_ipc_request_t, buffer)

#define	DHCP_IPC_DEFAULT_WAIT	120	/* seconds */

#ifdef	__cplusplus
}
#endif

#endif	/* _DHCPAGENT_IPC_H */
