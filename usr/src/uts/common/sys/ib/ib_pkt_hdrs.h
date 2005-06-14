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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_IB_IB_PKT_HDRS_H
#define	_SYS_IB_IB_PKT_HDRS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _ib_lrh_hdr_t {
	uint8_t		VL_LVer; 	/* virtual lane pkt is using & */
					/* link level protocol of pkt  */
	uint8_t		SL_LNH;		/* requested service level */
					/* & headers following LRH */
	ib_lid_t	DLID; 		/* dest port and path on subnet */
	uint16_t	PktLen;		/* size of packet in four-byte words */
	ib_lid_t	SLID;		/* source port on subnet */
} ib_lrh_hdr_t;

/* defines and masks that go with local routing header */
#define	IB_LRH_VL_MASK				0xF0
#define	IB_LRH_VERSION_MASK			0x0F
#define	IB_LRH_SL_MASK				0xF0
#define	IB_LRH_NEXT_HDR_MASK			0x03
#define	IB_LRH_NEXT_HDR_RWH			0x00
#define	IB_LRH_NEXT_HDR_IPV6			0x01
#define	IB_LRH_NEXT_HDR_BTH			0x02
#define	IB_LRH_NEXT_HDR_GRH			0x03
#define	IB_LRH_PACKET_LENGTH_MASK		0x07FF

typedef struct _ib_grh_t {
	uint32_t	IPVer_TC_Flow; 	/* version, traffic class & */
					/* flow label of the packet */
	uint16_t	PayLen;		/* len of the pkt following the GRH */
	uint8_t		NxtHdr;		/* Header following the GRH */
	uint8_t		HopLmt;		/* max hops the pkt can take */
	ib_gid_t	SGID;		/* GID of the source port */
	ib_gid_t	DGID;		/* GID of the consuming port */
} ib_grh_t;

/* defines and masks that go with global route header */
#define	IB_GRH_IPVER_MASK			0xF0000000
#define	IB_GRH_TCLASS_MASK			0x0FF00000
#define	IB_GRH_FLOW_LABEL_MASK			0x000FFFFF
#define	IB_GRH_NEXT_HDR_BTH			0x1B

typedef struct _ib_bth_hdr_t {
	uint8_t 	OpCode;				/* iba packet type */
	uint8_t 	SE_M_PadCnt_TVer; /* responder should generate event */
				/* & migration state & payload pad count */
				/* & version of ibta transport headers */
	uint16_t 	P_Key; 		/* logical partition assoc with pkt */
	uint32_t	Reserved_DestQP; /* queue pair of dest */
	uint32_t	A_PSN; 		/* responder should generate ack & */
				/* packet sequence number */
} ib_bth_hdr_t;

/* defines and masks that go with base transport header */
#define	IB_BTH_SOLICITED_EVENT_MASK		0x80
#define	IB_BTH_MIG_REQ_MASK			0x40
#define	IB_BTH_PAD_CNT_MASK			0x30
#define	IB_BTH_TVER_MASK			0x0F
#define	IB_BTH_DEST_QP_MASK			0x00FFFFFF
#define	IB_BTH_ACK_REQ_MASK			0x80000000
#define	IB_BTH_PSN_MASK				0x00FFFFFF

typedef struct _ib_deth_hdr_t {
	uint32_t	Q_Key;		/* queue key */
	uint32_t	Reserved_SrcQP;	/* queue pair of the source */
} ib_deth_hdr_t;

#define	IB_DETH_SRC_QP_MASK			0x00FFFFFF

/* defines and masks that go with datagram extended transport header */
#define	IB_DETH_SRC_QP_MASK			0x00FFFFFF

#ifdef __cplusplus
}
#endif

#endif /* _SYS_IB_IB_PKT_HDRS_H */
