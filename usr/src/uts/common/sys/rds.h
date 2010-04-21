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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copyright (c) 2008 Oracle.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

/*
 * Include this file if the application uses rdsv3 sockets.
 */

/*
 * This file contains definitions from the ofed rds.h and rds_rdma.h
 * header file.
 */
#ifndef _RDSV3_RDS_H
#define	_RDSV3_RDS_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	RDS_IB_ABI_VERSION		0x301

#define	AF_RDS				AF_INET_OFFLOAD
#define	PF_RDS				AF_INET_OFFLOAD

#define	SOL_RDS				272

/*
 * setsockopt/getsockopt for SOL_RDS
 */
#define	RDSV3_CANCEL_SENT_TO		1
#define	RDSV3_GET_MR			2
#define	RDSV3_FREE_MR			3
/* deprecated: RDS_BARRIER 4 */
#define	RDSV3_RECVERR			5
#define	RDSV3_CONG_MONITOR		6

/*
 * Control message types for SOL_RDS.
 *
 * RDS_CMSG_RDMA_ARGS (sendmsg)
 *	Request a RDMA transfer to/from the specified
 *	memory ranges.
 *	The cmsg_data is a struct rdsv3_rdma_args.
 * RDS_CMSG_RDMA_DEST (recvmsg, sendmsg)
 *	Kernel informs application about intended
 *	source/destination of a RDMA transfer
 * RDS_CMSG_RDMA_MAP (sendmsg)
 *	Application asks kernel to map the given
 *	memory range into a IB MR, and send the
 *	R_Key along in an RDS extension header.
 *	The cmsg_data is a struct rdsv3_get_mr_args,
 *	the same as for the GET_MR setsockopt.
 * RDS_CMSG_RDMA_STATUS (recvmsg)
 *	Returns the status of a completed RDMA operation.
 */
#define	RDSV3_CMSG_RDMA_ARGS		1
#define	RDSV3_CMSG_RDMA_DEST		2
#define	RDSV3_CMSG_RDMA_MAP		3
#define	RDSV3_CMSG_RDMA_STATUS		4
#define	RDSV3_CMSG_CONG_UPDATE		5

/*
 * RDMA related types
 */

/*
 * This encapsulates a remote memory location.
 * In the current implementation, it contains the R_Key
 * of the remote memory region, and the offset into it
 * (so that the application does not have to worry about
 * alignment).
 */
typedef uint64_t	rdsv3_rdma_cookie_t;

struct rdsv3_iovec {
	uint64_t	addr;
	uint64_t	bytes;
};

struct rdsv3_get_mr_args {
	struct rdsv3_iovec vec;
	uint64_t	cookie_addr;
	uint64_t	flags;
};

struct rdsv3_free_mr_args {
	rdsv3_rdma_cookie_t cookie;
	uint64_t	flags;
};

struct rdsv3_rdma_args {
	rdsv3_rdma_cookie_t cookie;
	struct rdsv3_iovec remote_vec;
	uint64_t	local_vec_addr;
	uint64_t	nr_local;
	uint64_t	flags;
	uint64_t	user_token;
};

struct rdsv3_rdma_notify {
	uint64_t	user_token;
	int32_t		status;
};

#define	RDSV3_RDMA_SUCCESS	0
#define	RDSV3_RDMA_REMOTE_ERROR	1
#define	RDSV3_RDMA_CANCELED	2
#define	RDSV3_RDMA_DROPPED	3
#define	RDSV3_RDMA_OTHER_ERROR	4

/*
 * Common set of flags for all RDMA related structs
 */
#define	RDSV3_RDMA_READWRITE	0x0001
#define	RDSV3_RDMA_FENCE	0x0002	/* use FENCE for immediate send */
#define	RDSV3_RDMA_INVALIDATE	0x0004	/* invalidate R_Key after freeing MR */
#define	RDSV3_RDMA_USE_ONCE	0x0008	/* free MR after use */
#define	RDSV3_RDMA_DONTWAIT	0x0010	/* Don't wait in SET_BARRIER */
#define	RDSV3_RDMA_NOTIFY_ME	0x0020	/* Notify when operation completes */

/*
 * Congestion monitoring.
 * Congestion control in RDS happens at the host connection
 * level by exchanging a bitmap marking congested ports.
 * By default, a process sleeping in poll() is always woken
 * up when the congestion map is updated.
 * With explicit monitoring, an application can have more
 * fine-grained control.
 * The application installs a 64bit mask value in the socket,
 * where each bit corresponds to a group of ports.
 * When a congestion update arrives, RDS checks the set of
 * ports that are now uncongested against the list bit mask
 * installed in the socket, and if they overlap, we queue a
 * cong_notification on the socket.
 *
 * To install the congestion monitor bitmask, use RDS_CONG_MONITOR
 * with the 64bit mask.
 * Congestion updates are received via RDS_CMSG_CONG_UPDATE
 * control messages.
 *
 * The correspondence between bits and ports is
 *	1 << (portnum % 64)
 */
#define	RDSV3_CONG_MONITOR_SIZE	64
#define	RDSV3_CONG_MONITOR_BIT(port)	\
	(((unsigned int) port) % RDSV3_CONG_MONITOR_SIZE)
#define	RDSV3_CONG_MONITOR_MASK(port) (1ULL << RDSV3_CONG_MONITOR_BIT(port))

/* rds-info related */

#define	RDSV3_INFO_FIRST		10000
#define	RDSV3_INFO_COUNTERS		10000
#define	RDSV3_INFO_CONNECTIONS		10001
/* 10002 aka RDS_INFO_FLOWS is deprecated */
#define	RDSV3_INFO_SEND_MESSAGES	10003
#define	RDSV3_INFO_RETRANS_MESSAGES	10004
#define	RDSV3_INFO_RECV_MESSAGES	10005
#define	RDSV3_INFO_SOCKETS		10006
#define	RDSV3_INFO_TCP_SOCKETS		10007
#define	RDSV3_INFO_IB_CONNECTIONS	10008
#define	RDSV3_INFO_CONNECTION_STATS	10009
#define	RDSV3_INFO_IWARP_CONNECTIONS	10010
#define	RDSV3_INFO_LAST			10010

#ifndef __lock_lint
#pragma pack(1)
struct rdsv3_info_counter {
	uint8_t	name[32];
	uint64_t	value;
} __attribute__((packed));
#pragma pack()
#else
struct rdsv3_info_counter {
	uint8_t	name[32];
	uint64_t	value;
};
#endif

#define	RDSV3_INFO_CONNECTION_FLAG_SENDING	0x01
#define	RDSV3_INFO_CONNECTION_FLAG_CONNECTING	0x02
#define	RDSV3_INFO_CONNECTION_FLAG_CONNECTED	0x04

#ifndef __lock_lint
#pragma pack(1)
struct rdsv3_info_connection {
	uint64_t	next_tx_seq;
	uint64_t	next_rx_seq;
	uint32_t	laddr;			/* network order */
	uint32_t	faddr;			/* network order */
	uint8_t		transport[15];		/* null term ascii */
	uint8_t		flags;
} __attribute__((packed));
#pragma pack()
#else
struct rdsv3_info_connection {
	uint64_t	next_tx_seq;
	uint64_t	next_rx_seq;
	uint32_t	laddr;			/* network order */
	uint32_t	faddr;			/* network order */
	uint8_t		transport[15];		/* null term ascii */
	uint8_t		flags;
};
#endif

#ifndef __lock_lint
#pragma pack(1)
struct rdsv3_info_flow {
	uint32_t	laddr;			/* network order */
	uint32_t	faddr;			/* network order */
	uint32_t	bytes;
	uint16_t	lport;			/* network order */
	uint16_t	fport;			/* network order */
} __attribute__((packed));
#pragma pack()
#else
struct rdsv3_info_flow {
	uint32_t	laddr;			/* network order */
	uint32_t	faddr;			/* network order */
	uint32_t	bytes;
	uint16_t	lport;			/* network order */
	uint16_t	fport;			/* network order */
};
#endif

#define	RDSV3_INFO_MESSAGE_FLAG_ACK		0x01
#define	RDSV3_INFO_MESSAGE_FLAG_FAST_ACK		0x02

#ifndef __lock_lint
#pragma pack(1)
struct rdsv3_info_message {
	uint64_t	seq;
	uint32_t	len;
	uint32_t	laddr;			/* network order */
	uint32_t	faddr;			/* network order */
	uint16_t	lport;			/* network order */
	uint16_t	fport;			/* network order */
	uint8_t		flags;
} __attribute__((packed));
#pragma pack()
#else
struct rdsv3_info_message {
	uint64_t	seq;
	uint32_t	len;
	uint32_t	laddr;			/* network order */
	uint32_t	faddr;			/* network order */
	uint16_t	lport;			/* network order */
	uint16_t	fport;			/* network order */
	uint8_t		flags;
};
#endif

#ifndef __lock_lint
#pragma pack(1)
struct rdsv3_info_socket {
	uint32_t	sndbuf;
	uint32_t	bound_addr;		/* network order */
	uint32_t	connected_addr;		/* network order */
	uint16_t	bound_port;		/* network order */
	uint16_t	connected_port;		/* network order */
	uint32_t	rcvbuf;
	uint64_t	inum;
} __attribute__((packed));
#pragma pack()
#else
struct rdsv3_info_socket {
	uint32_t	sndbuf;
	uint32_t	bound_addr;		/* network order */
	uint32_t	connected_addr;		/* network order */
	uint16_t	bound_port;		/* network order */
	uint16_t	connected_port;		/* network order */
	uint32_t	rcvbuf;
	uint64_t	inum;
};
#endif

#ifndef __lock_lint
#pragma pack(1)
struct rdsv3_info_socket_v1 {
	uint32_t	sndbuf;
	uint32_t	bound_addr;		/* network order */
	uint32_t	connected_addr;		/* network order */
	uint16_t	bound_port;		/* network order */
	uint16_t	connected_port;		/* network order */
	uint32_t	rcvbuf;
} __attribute__((packed));
#pragma pack()
#else
struct rdsv3_info_socket_v1 {
	uint32_t	sndbuf;
	uint32_t	bound_addr;		/* network order */
	uint32_t	connected_addr;		/* network order */
	uint16_t	bound_port;		/* network order */
	uint16_t	connected_port;		/* network order */
	uint32_t	rcvbuf;
};
#endif

#define	RDS_IB_GID_LEN	16
struct rdsv3_info_rdma_connection {
	uint32_t	src_addr;		/* network order */
	uint32_t	dst_addr;		/* network order */
	uint8_t		src_gid[RDS_IB_GID_LEN];
	uint8_t		dst_gid[RDS_IB_GID_LEN];

	uint32_t	max_send_wr;
	uint32_t	max_recv_wr;
	uint32_t	max_send_sge;
	uint32_t	rdma_mr_max;
	uint32_t	rdma_mr_size;
};

#define	rdsv3_info_ib_connection rdsv3_info_rdma_connection
#define	rdma_fmr_max rdma_mr_max
#define	rdma_fmr_size rdma_mr_size

#ifdef	__cplusplus
}
#endif

#endif /* _RDSV3_RDS_H */
