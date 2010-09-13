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

#ifndef	_SYS_HXGE_HXGE_TXDMA_HW_H
#define	_SYS_HXGE_HXGE_TXDMA_HW_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <hxge_defs.h>
#include <hxge_tdc_hw.h>

/*
 * Transmit Packet Descriptor Structure
 * 	See Hydra PRM (Chapter 8, Section 8.1.1)
 */
typedef union _tx_desc_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	sop:1;
		uint32_t	mark:1;
		uint32_t	num_ptr:4;
		uint32_t	rsvd:1;
		uint32_t	tr_len:13;
		uint32_t	sad:12;
		uint32_t	sad_l:32;
#else
		uint32_t	sad_l:32;
		uint32_t	sad:12;
		uint32_t	tr_len:13;
		uint32_t	rsvd:1;
		uint32_t	num_ptr:4;
		uint32_t	mark:1;
		uint32_t	sop:1;
#endif
	} bits;
} tx_desc_t, *p_tx_desc_t;

/*
 * TDC Ring Configuration
 */
#define	TDC_TDR_CFG_STADDR_SHIFT	6	/* bits 18:6 */
#define	TDC_TDR_CFG_STADDR_MASK		0x000000000007FFC0ULL
#define	TDC_TDR_CFG_ADDR_MASK		0x00000FFFFFFFFFC0ULL
#define	TDC_TDR_CFG_STADDR_BASE_SHIFT	19	/* bits 43:19 */
#define	TDC_TDR_CFG_STADDR_BASE_MASK	0x00000FFFFFF80000ULL
#define	TDC_TDR_CFG_LEN_SHIFT		53	/* bits 63:53 */
#define	TDC_TDR_CFG_LEN_MASK		0xFFE0000000000000ULL
#define	TDC_TDR_RST_SHIFT		46
#define	TDC_TDR_RST_MASK		0x0000400000000000ULL

/*
 * Transmit Event Mask
 */
#define	TDC_INT_MASK_MK_MASK		0x0000000000008000ULL

/*
 * Trasnmit Mailbox High
 */
#define	TDC_MBH_SHIFT			0	/* bit 11:0 */
#define	TDC_MBH_ADDR_SHIFT		32	/* bit 43:32 */
#define	TDC_MBH_MASK			0x0000000000000FFFULL

/*
 * Trasnmit Mailbox Low
 */
#define	TDC_MBL_SHIFT			6	/* bit 31:6 */
#define	TDC_MBL_MASK			0x00000000FFFFFFC0ULL

#define	TXDMA_MAILBOX_BYTE_LENGTH	64
#define	TXDMA_MAILBOX_UNUSED		24

typedef struct _txdma_mailbox_t {
	tdc_stat_t		tx_cs;			/* 8 bytes */
	tdc_tdr_pre_head_t	tx_dma_pre_st;		/* 8 bytes */
	tdc_tdr_head_t		tx_ring_hdl;		/* 8 bytes */
	tdc_tdr_kick_t		tx_ring_kick;		/* 8 bytes */
	uint32_t		tx_rng_err_logh;	/* 4 bytes */
	uint32_t		tx_rng_err_logl;	/* 4 bytes */
	uint8_t			resv[TXDMA_MAILBOX_UNUSED];
} txdma_mailbox_t, *p_txdma_mailbox_t;

/*
 * Internal Transmit Packet Format (16 bytes)
 */
#define	TX_PKT_HEADER_SIZE			16
#define	TX_MAX_GATHER_POINTERS			15
#define	TX_GATHER_POINTERS_THRESHOLD		8
/*
 * There is bugs in the hardware
 * and max sfter len is changed from 4096 to 4076.
 *
 * Jumbo from 9500 to 9216
 */
#define	TX_MAX_TRANSFER_LENGTH			4076
#define	TX_JUMBO_MTU				9216

#define	TX_PKT_HEADER_PAD_SHIFT			0	/* bit 2:0 */
#define	TX_PKT_HEADER_PAD_MASK			0x0000000000000007ULL
#define	TX_PKT_HEADER_TOT_XFER_LEN_SHIFT	16	/* bit 16:29 */
#define	TX_PKT_HEADER_TOT_XFER_LEN_MASK		0x000000000000FFF8ULL
#define	TX_PKT_HEADER_L4STUFF_SHIFT		32	/* bit 37:32 */
#define	TX_PKT_HEADER_L4STUFF_MASK		0x0000003F00000000ULL
#define	TX_PKT_HEADER_L4START_SHIFT		40	/* bit 45:40 */
#define	TX_PKT_HEADER_L4START_MASK		0x00003F0000000000ULL
#define	TX_PKT_HEADER_L3START_SHIFT		48	/* bit 45:40 */
#define	TX_PKT_HEADER_IHL_SHIFT			52	/* bit 52 */
#define	TX_PKT_HEADER_VLAN__SHIFT		56	/* bit 56 */
#define	TX_PKT_HEADER_TCP_UDP_CRC32C_SHIFT	57	/* bit 57 */
#define	TX_PKT_HEADER_LLC_SHIFT			57	/* bit 57 */
#define	TX_PKT_HEADER_TCP_UDP_CRC32C_SET	0x0200000000000000ULL
#define	TX_PKT_HEADER_TCP_UDP_CRC32C_MASK	0x0200000000000000ULL
#define	TX_PKT_HEADER_L4_PROTO_OP_SHIFT		2	/* bit 59:58 */
#define	TX_PKT_HEADER_L4_PROTO_OP_MASK		0x0C00000000000000ULL
#define	TX_PKT_HEADER_V4_HDR_CS_SHIFT		60	/* bit 60 */
#define	TX_PKT_HEADER_V4_HDR_CS_SET		0x1000000000000000ULL
#define	TX_PKT_HEADER_V4_HDR_CS_MASK		0x1000000000000000ULL
#define	TX_PKT_HEADER_IP_VER_SHIFT		61	/* bit 61 */
#define	TX_PKT_HEADER_IP_VER_MASK		0x2000000000000000ULL
#define	TX_PKT_HEADER_PKT_TYPE_SHIFT		62	/* bit 62 */
#define	TX_PKT_HEADER_PKT_TYPE_MASK		0x4000000000000000ULL

/* L4 Prototol Operations */
#define	TX_PKT_L4_PROTO_OP_NOP			0x00
#define	TX_PKT_L4_PROTO_OP_FULL_L4_CSUM		0x01
#define	TX_PKT_L4_PROTO_OP_L4_PAYLOAD_CSUM	0x02
#define	TX_PKT_L4_PROTO_OP_SCTP_CRC32		0x04

/* Transmit Packet Types */
#define	TX_PKT_PKT_TYPE_NOP			0x00
#define	TX_PKT_PKT_TYPE_TCP			0x01
#define	TX_PKT_PKT_TYPE_UDP			0x02
#define	TX_PKT_PKT_TYPE_SCTP			0x03

typedef union _tx_pkt_header_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	cksum_en_pkt_type:2;
		uint32_t	ip_ver:1;
		uint32_t	rsrvd:4;
		uint32_t	vlan:1;
		uint32_t	ihl:4;
		uint32_t	l3start:4;
		uint32_t	rsvrvd1:2;
		uint32_t	l4start:6;
		uint32_t	rsvrvd2:2;
		uint32_t	l4stuff:6;
		uint32_t	rsvrvd3:2;
		uint32_t	tot_xfer_len:14;
		uint32_t	rsrrvd4:13;
		uint32_t	pad:3;
#else
		uint32_t	pad:3;
		uint32_t	rsrrvd4:13;
		uint32_t	tot_xfer_len:14;
		uint32_t	rsvrvd3:2;
		uint32_t	l4stuff:6;
		uint32_t	rsvrvd2:2;
		uint32_t	l4start:6;
		uint32_t	rsvrvd1:2;
		uint32_t	l3start:4;
		uint32_t	ihl:4;
		uint32_t	vlan:1;
		uint32_t	rsrvd:4;
		uint32_t	ip_ver:1;
		uint32_t	cksum_en_pkt_type:2;
#endif
	} bits;
} tx_pkt_header_t, *p_tx_pkt_header_t;

typedef struct _tx_pkt_hdr_all_t {
	tx_pkt_header_t		pkthdr;
	uint64_t		reserved;
} tx_pkt_hdr_all_t, *p_tx_pkt_hdr_all_t;


#ifdef	__cplusplus
}
#endif

#endif /* _SYS_HXGE_HXGE_TXDMA_HW_H */
