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

#ifndef	_SYS_IB_MGT_IBMF_IBMF_MSG_H
#define	_SYS_IB_MGT_IBMF_IBMF_MSG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#define	IBMF_MAD_SIZE			0x100

/*
 * ibmf_addr definition
 *	This is local address information.
 *
 *	When used in ibmf_msg_transport, local_lid refers to the (local) sender
 *	and remote_lid/remote_qno refer to the destination (ie., receiver).
 *	When used in async message callback, local_lid is the (local) receiver
 *	and remote_lid/remote_qno refer to the (remote) source; ibmf fills
 *	all fields of the addr_info_t when generating the receive callback.
 *
 *	Note that the sender and receiver may be on the same node/port.
 */
typedef struct _ibmf_addr_info {
	ib_lid_t		ia_local_lid;
	ib_lid_t		ia_remote_lid;
	ib_qpn_t		ia_remote_qno;
	ib_pkey_t		ia_p_key;
	ib_qkey_t		ia_q_key;
	uint8_t			ia_service_level:4;
} ibmf_addr_info_t;

/*
 * ibmf_global_addr_info_t
 *	This has the global address information. This is filled in by the
 *	client when sending the message and will be filled in by IBMF when
 *	a message is received. ip_global_addr_valid is B_TRUE if global
 *	address component of the message is valid (ip_global_addr_valid is
 *	set by the client when sending packets and set by IBMF when packets
 *	are received).
 */
typedef struct _ibmf_global_addr_info {
	ib_gid_t		ig_sender_gid;	/* gid of the sender */
	ib_gid_t		ig_recver_gid;	/* gid of the receiver */
	uint32_t		ig_flow_label;	/* pkt grouping */
	uint8_t			ig_tclass;	/* end-to-end service level */
	uint8_t			ig_hop_limit;	/* inter subnet hops */
} ibmf_global_addr_info_t;

/*
 * ibmf_msg_bufs_t
 *	From the client's perspective, the message will consist of three
 *	sections, the MAD header, the Management Class header, and the
 *	data payload. IBMF will either assemble these sections into
 *	a message or disassemble the incoming message into these sections.
 *
 *	The MAD header buffer is always 24 bytes in length.
 *	It may be set to NULL only when the QP is configured for raw
 *	UD traffic through the flags specified in ibmf_alloc_qp().
 *
 *	The class header buffer pointer may point to a buffer containing
 *	the class specific header as defined by the IB Architecture
 *	Specification, rev1.1. Note that the RMPP header should not be
 *	included in the class header for classes that support RMPP.
 *	For example, for the Subnet Administration (SA) class, the class
 *	header starts at byte offset 36 in the MAD and is of length 20 bytes.
 *
 *	The data is provided in a buffer pointed to by im_bufs_cl_data,
 *	with the data length provided in im_bufs_cl_data_len.
 *
 *	When sending a MAD message, the client may choose to not provide
 *	a class header buffer in im_msgbufs_send.im_bufs_cl_hdr.
 *	In this case, the im_msgbufs_send.im_bufs_cl_hdr must be NULL,
 *	and IBMF will interpret this to imply that the class header
 *	and data buffer are grouped together in the
 *	im_msgbufs_send.im_bufs_cl_data buffer.
 *
 *	When sending a RAW UD packet over a non-special QP (i.e. not
 *	IBMF_QP_HANDLE_DEFAULT), the entire packet must be provided
 *	in a buffer pointed to by im_msgbufs_send.im_bufs_cl_data.
 *	The im_msgbufs_send.im_bufs_mad_hdr and
 *	im_msgbufs_send.im_bufs_cl_hdr pointers should be NULL.
 *
 *	The data contained in these buffers, MAD header, Management Class
 *	header, and data payload buffers, must be in wire format which
 *	is the big-endian format.
 */
typedef struct _ibmf_msg_bufs {
	ib_mad_hdr_t	*im_bufs_mad_hdr;	/* mad hdr (24 bytes) */
	void		*im_bufs_cl_hdr;	/* class hdr buffer ptr */
	size_t		im_bufs_cl_hdr_len;	/* class hdr buffer len ptr */
	void		*im_bufs_cl_data;	/* mad class data buf ptr */
	size_t		im_bufs_cl_data_len; 	/* mad class data len ptr */
} ibmf_msg_bufs_t;

/*
 * ibmf_msg definition
 *	The IBMF client initializes various members of the msg while sending
 *	the message. IBMF fills in the various members of the msg when a message
 *	is received.
 *	The im_msgbufs_send buffers must always be allocated and freed
 *	by the client of ibmf. Message content passed from client to ibmf
 *	must be through the im_msgbufs_send buffers.
 *	The im_msgbufs_recv buffers must always be allocated and freed
 *	by ibmf. Message content passed from ibmf to client
 *	will always be through the im_msgbufs_recv buffers.
 *
 *	im_msg_status: contains the IBMF status (defined in ibmf.h) of
 *	the transaction. This is the same as the return value of the
 *	ibmf_msg_transport() call for a blocking transaction.
 *
 *	im_msg_flags:  must be set to IBMF_MSG_FLAGS_GLOBAL_ADDRESS by
 *	the IBMF client if the send buffer contains a valid GRH, and by
 *	IBMF if the receive buffer contains a valid GRH
 *
 *	Note on Host versus IB Wire format:
 *	Any MAD data passed in the buffers pointed to by im_bufs_mad_hdr,
 *	im_bufs_cl_hdr, and im_bufs_cl_data in im_msgbufs_send and
 *	im_msgbufs_recv should be in IB wire format.
 *	All other data in the ibmf_msg_t structure should be in host format,
 *	including the data in im_local_addr and im_global_addr.
 */
typedef struct _ibmf_msg {
	ibmf_addr_info_t	im_local_addr;	/* local addressing info */
	ibmf_global_addr_info_t	im_global_addr;	/* global addressing info */
	int32_t			im_msg_status;	/* completion status */
	uint32_t		im_msg_flags;	/* flags */
	size_t			im_msg_sz_limit; /* max. message size */
	ibmf_msg_bufs_t		im_msgbufs_send; /* input data to ibmf */
	ibmf_msg_bufs_t		im_msgbufs_recv; /* output data from ibmf */
} ibmf_msg_t;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_IB_MGT_IBMF_IBMF_MSG_H */
