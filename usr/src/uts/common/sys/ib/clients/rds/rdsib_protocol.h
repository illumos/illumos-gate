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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2005 SilverStorm Technologies, Inc. All rights reserved.
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
 *	- Redistributions of source code must retain the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer.
 *
 *	- Redistributions in binary form must reproduce the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer in the documentation and/or other materials
 *	  provided with the distribution.
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
 * Sun elects to include this software in Sun product
 * under the OpenIB BSD license.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _RDSIB_PROTOCOL_H
#define	_RDSIB_PROTOCOL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <netinet/in.h>

#define	RDS_VERSION	4

/*
 * RDS Well known service id
 * Format: 0x1h00144Fhhhhhhhh
 *         "00144F" is the Sun OUI
 * 'h' can be any hex-decimal digit.
 */
#define	RDS_SERVICE_ID		0x1000144F00000001ULL

/* Max number of nodes supported with the default configuration */
#define	RDS_MAX_NODES	8

/* packet size */
#define	RDS_USER_DATA_BUFFER_SIZE	4096 /* 4K */

/* per session */
#define	RDS_MAX_DATA_RECV_BUFFERS	3000
#define	RDS_MAX_DATA_SEND_BUFFERS	2000
#define	RDS_MAX_CTRL_RECV_BUFFERS	100
#define	RDS_MAX_CTRL_SEND_BUFFERS	50

/* RQ low water mark in percentage. More RWR have to be posted */
#define	RDS_DATA_RECV_BUFFER_LWM	90
#define	RDS_CTRL_RECV_BUFFER_LWM	50

/*
 * High water mark in percentage of pkts pending on sockets.
 * Incoming traffic should be controlled or stopped for all sockets
 * or some sockets that are above their quota
 */
#define	RDS_PENDING_RX_PKTS_HWM	75

/*
 * Only interoperate with homogeneous Solaris (x32, x64, sparcv9).
 */
#if defined(__sparcv9)
#define	RDS_THIS_ARCH	1
#elif defined(__amd64)
#define	RDS_THIS_ARCH	2
#elif defined(__i386)
#define	RDS_THIS_ARCH	3
#else
#error "ISA not supported"
#endif

/*
 * CM Private Data
 *
 * This data is sent with the CM REQ message by the initiater of the
 * RC channel.
 *
 * cm_ip_pvt - ibt_ip_cm_info_t
 * version - RDS version
 * arch - only interoperate with homogeneous Solaris (x32, x64, sparcv9).
 * eptype - RDS_EP_TYPE_CTRL or RDS_EP_TYPE_DATA
 * failover - flag to indicate failover.
 * last_bufid - used during failover, indicates the last buffer the remote
 *     received.
 * user_buffer_size - Packet size on the sending node. This is also the size
 *     of the SGL buffer used in the send and receive WRs. This should be
 *     same size on the both active and passive nodes.
 * ack_rkey - RKEY for the RDMA acknowledgement buffer.
 * ack_addr - Registered MR address to receive RDMA acknowledgement.
 */
typedef struct rds_cm_private_data_s {
	uint8_t		cmp_ip_pvt[IBT_IP_HDR_PRIV_DATA_SZ];
	uint8_t		cmp_version;
	uint8_t		cmp_arch;
	uint8_t		cmp_eptype;
	uint8_t		cmp_failover;
	uintptr_t	cmp_last_bufid;
	uint32_t	cmp_user_buffer_size;
	ibt_rkey_t	cmp_ack_rkey;
	uintptr_t	cmp_ack_addr;
} rds_cm_private_data_t;

/*
 * Data Header
 * This header is transmitted with every WR.
 *
 * bufid - Ponter to the send buffer that is used to send this packet.
 * datalen - Number of bytes of data (not including the header)
 * npkts - number of remaining pkts(including this one) for the message.
 *         It is set to 1 for single packet messages.
 * psn - Packet sequence number(starts at 0). Zero for single packet messages.
 * sendport - Port number of the sending socket
 * recvport - Port number of the receiving socket
 */
typedef struct rds_data_hdr_s {
	uintptr_t		dh_bufid;
	uint32_t		dh_datalen;
	uint32_t		dh_npkts;
	uint32_t		dh_psn;
	in_port_t		dh_sendport;
	in_port_t		dh_recvport;
} rds_data_hdr_t;

#define	RDS_DATA_HDR_SZ		sizeof (rds_data_hdr_t)

/*
 * List of control commands sent on a session:
 *
 * STALL: This command is sent to inform remote RDS that a port is stalled.
 *	  Always sent on all existing sessions.
 * UNSTALL: This command is sent to inform remote RDS that a port is unstalled.
 *	  Always sent on all existing sessions.
 * STALL_PORTS: Inform remote RDS that all local ports are stalled.
 * UNSTALL_PORTS: Inform remote RDS that all local ports are unstalled.
 * HEARTBEAT: Sent to check if the connection is still alive
 */
#define	RDS_CTRL_CODE_STALL		1
#define	RDS_CTRL_CODE_UNSTALL		2
#define	RDS_CTRL_CODE_STALL_PORTS	3
#define	RDS_CTRL_CODE_UNSTALL_PORTS	4
#define	RDS_CTRL_CODE_HEARTBEAT		5
#define	RDS_CTRL_CODE_CLOSE_SESSION	6

/*
 * RDS ctrl packet
 *
 * port - Socket to be stalled/unstalled
 * code - STALL/UNSTALL (other codes are currently not used)
 */

typedef struct rds_ctrl_pkt_s {
	uint16_t	rcp_port;
	uint8_t		rcp_code;
} rds_ctrl_pkt_t;

#define	RDS_CTRLPKT_SIZE	sizeof (rds_ctrl_pkt_t)

#ifdef __cplusplus
}
#endif

#endif	/* _RDSIB_PROTOCOL_H */
