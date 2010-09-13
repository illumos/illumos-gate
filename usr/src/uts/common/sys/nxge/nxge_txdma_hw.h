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

#ifndef	_SYS_NXGE_NXGE_TXDMA_HW_H
#define	_SYS_NXGE_NXGE_TXDMA_HW_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <nxge_defs.h>
#include <nxge_hw.h>

#if !defined(_BIG_ENDIAN)
#define	SWAP(X)	(X)
#else
#define	SWAP(X)   \
	(((X >> 32) & 0x00000000ffffffff) | \
	((X << 32) & 0xffffffff00000000))
#endif

/*
 * Partitioning Suport: same as those defined for the RX
 */

/*
 * TDC: Partitioning Support
 *	(Each of the following registers is for each TDC)
 */
#define	TX_LOG_REG_SIZE			512
#define	TX_LOG_DMA_OFFSET(channel)	(channel * TX_LOG_REG_SIZE)

#define	TX_LOG_PAGE_VLD_REG		(FZC_DMC + 0x40000)
#define	TX_LOG_PAGE_MASK1_REG		(FZC_DMC + 0x40008)
#define	TX_LOG_PAGE_VAL1_REG		(FZC_DMC + 0x40010)
#define	TX_LOG_PAGE_MASK2_REG		(FZC_DMC + 0x40018)
#define	TX_LOG_PAGE_VAL2_REG		(FZC_DMC + 0x40020)
#define	TX_LOG_PAGE_RELO1_REG		(FZC_DMC + 0x40028)
#define	TX_LOG_PAGE_RELO2_REG		(FZC_DMC + 0x40030)
#define	TX_LOG_PAGE_HDL_REG		(FZC_DMC + 0x40038)

/* Transmit Addressing Mode: Set to 1 to select 32-bit addressing mode */
#define	TX_ADDR_MD_REG			(FZC_DMC + 0x45000)

#define	TX_ADDR_MD_SHIFT	0			/* bits 0:0 */
#define	TX_ADDR_MD_SET_32	0x0000000000000001ULL	/* 1 to select 32 bit */
#define	TX_ADDR_MD_MASK		0x0000000000000001ULL

typedef union _tx_addr_md_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res1_1:31;
			uint32_t mode32:1;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t mode32:1;
			uint32_t res1_1:31;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} tx_addr_md_t, *p_tx_addr_md_t;

/* Transmit Packet Descriptor Structure */
#define	TX_PKT_DESC_SAD_SHIFT		0		/* bits 43:0 */
#define	TX_PKT_DESC_SAD_MASK		0x00000FFFFFFFFFFFULL
#define	TX_PKT_DESC_TR_LEN_SHIFT	44		/* bits 56:44 */
#define	TX_PKT_DESC_TR_LEN_MASK		0x01FFF00000000000ULL
#define	TX_PKT_DESC_NUM_PTR_SHIFT	58		/* bits 61:58 */
#define	TX_PKT_DESC_NUM_PTR_MASK	0x3C00000000000000ULL
#define	TX_PKT_DESC_MARK_SHIFT		62		/* bit 62 */
#define	TX_PKT_DESC_MARK		0x4000000000000000ULL
#define	TX_PKT_DESC_MARK_MASK		0x4000000000000000ULL
#define	TX_PKT_DESC_SOP_SHIFT		63		/* bit 63 */
#define	TX_PKT_DESC_SOP			0x8000000000000000ULL
#define	TX_PKT_DESC_SOP_MASK		0x8000000000000000ULL

typedef union _tx_desc_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t sop:1;
			uint32_t mark:1;
			uint32_t num_ptr:4;
			uint32_t res1:1;
			uint32_t tr_len:13;
			uint32_t sad:12;

#elif defined(_BIT_FIELDS_LTOH)
			uint32_t sad:12;
			uint32_t tr_len:13;
			uint32_t res1:1;
			uint32_t num_ptr:4;
			uint32_t mark:1;
			uint32_t sop:1;

#endif
		} hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t sad:32;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t sad:32;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		struct {

#if defined(_BIT_FIELDS_HTOL)
			uint32_t sop:1;
			uint32_t mark:1;
			uint32_t num_ptr:4;
			uint32_t res1:1;
			uint32_t tr_len:13;
			uint32_t sad:12;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t sad:12;
			uint32_t tr_len:13;
			uint32_t res1:1;
			uint32_t num_ptr:4;
			uint32_t mark:1;
			uint32_t sop:1;
#endif
		} hdw;
#endif
	} bits;
} tx_desc_t, *p_tx_desc_t;


/* Transmit Ring Configuration (24 Channels) */
#define	TX_RNG_CFIG_REG			(DMC + 0x40000)
#if OLD
#define	TX_RING_HDH_REG			(DMC + 0x40008)
#endif
#define	TX_RING_HDL_REG			(DMC + 0x40010)
#define	TX_RING_KICK_REG		(DMC + 0x40018)
#define	TX_ENT_MSK_REG			(DMC + 0x40020)
#define	TX_CS_REG			(DMC + 0x40028)
#define	TXDMA_MBH_REG			(DMC + 0x40030)
#define	TXDMA_MBL_REG			(DMC + 0x40038)
#define	TX_DMA_PRE_ST_REG		(DMC + 0x40040)
#define	TX_RNG_ERR_LOGH_REG		(DMC + 0x40048)
#define	TX_RNG_ERR_LOGL_REG		(DMC + 0x40050)
#define	TDMC_INTR_DBG_REG		(DMC + 0x40060)
#define	TX_CS_DBG_REG			(DMC + 0x40068)

/* Transmit Ring Configuration */
#define	TX_RNG_CFIG_STADDR_SHIFT	6			/* bits 18:6 */
#define	TX_RNG_CFIG_STADDR_MASK		0x000000000007FFC0ULL
#define	TX_RNG_CFIG_ADDR_MASK		0x00000FFFFFFFFFC0ULL
#define	TX_RNG_CFIG_STADDR_BASE_SHIFT	19			/* bits 43:19 */
#define	TX_RNG_CFIG_STADDR_BASE_MASK	0x00000FFFFFF80000ULL
#define	TX_RNG_CFIG_LEN_SHIFT		48			/* bits 60:48 */
#define	TX_RNG_CFIG_LEN_MASK		0xFFF8000000000000ULL

#define	TX_RNG_HEAD_TAIL_SHIFT		3
#define	TX_RNG_HEAD_TAIL_WRAP_SHIFT	19

typedef union _tx_rng_cfig_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res2:3;
			uint32_t len:13;
			uint32_t res1:4;
			uint32_t staddr_base:12;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t staddr_base:12;
			uint32_t res1:4;
			uint32_t len:13;
			uint32_t res2:3;
#endif
		} hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t staddr_base:13;
			uint32_t staddr:13;
			uint32_t res2:6;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t res2:6;
			uint32_t staddr:13;
			uint32_t staddr_base:13;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res2:3;
			uint32_t len:13;
			uint32_t res1:4;
			uint32_t staddr_base:12;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t staddr_base:12;
			uint32_t res1:4;
			uint32_t len:13;
			uint32_t res2:3;
#endif
		} hdw;
#endif
	} bits;
} tx_rng_cfig_t, *p_tx_rng_cfig_t;

/* Transmit Ring Head Low */
#define	TX_RING_HDL_SHIFT		3			/* bit 31:3 */
#define	TX_RING_HDL_MASK		0x00000000FFFFFFF8ULL

typedef union _tx_ring_hdl_t {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res0:12;
			uint32_t wrap:1;
			uint32_t head:16;
			uint32_t res2:3;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t res2:3;
			uint32_t head:16;
			uint32_t wrap:1;
			uint32_t res0:12;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} tx_ring_hdl_t, *p_tx_ring_hdl_t;

/* Transmit Ring Kick */
#define	TX_RING_KICK_TAIL_SHIFT		3			/* bit 43:3 */
#define	TX_RING_KICK_TAIL_MASK		0x000000FFFFFFFFFF8ULL

typedef union _tx_ring_kick_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res0:12;
			uint32_t wrap:1;
			uint32_t tail:16;
			uint32_t res2:3;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t res2:3;
			uint32_t tail:16;
			uint32_t wrap:1;
			uint32_t res0:12;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} tx_ring_kick_t, *p_tx_ring_kick_t;

/* Transmit Event Mask (DMC + 0x40020) */
#define	TX_ENT_MSK_PKT_PRT_ERR_SHIFT		0	/* bit 0: 0 to flag */
#define	TX_ENT_MSK_PKT_PRT_ERR_MASK		0x0000000000000001ULL
#define	TX_ENT_MSK_CONF_PART_ERR_SHIFT		1	/* bit 1: 0 to flag */
#define	TX_ENT_MSK_CONF_PART_ERR_MASK		0x0000000000000002ULL
#define	TX_ENT_MSK_NACK_PKT_RD_SHIFT		2	/* bit 2: 0 to flag */
#define	TX_ENT_MSK_NACK_PKT_RD_MASK		0x0000000000000004ULL
#define	TX_ENT_MSK_NACK_PREF_SHIFT		3	/* bit 3: 0 to flag */
#define	TX_ENT_MSK_NACK_PREF_MASK		0x0000000000000008ULL
#define	TX_ENT_MSK_PREF_BUF_ECC_ERR_SHIFT	4	/* bit 4: 0 to flag */
#define	TX_ENT_MSK_PREF_BUF_ECC_ERR_MASK	0x0000000000000010ULL
#define	TX_ENT_MSK_TX_RING_OFLOW_SHIFT		5	/* bit 5: 0 to flag */
#define	TX_ENT_MSK_TX_RING_OFLOW_MASK		0x0000000000000020ULL
#define	TX_ENT_MSK_PKT_SIZE_ERR_SHIFT		6	/* bit 6: 0 to flag */
#define	TX_ENT_MSK_PKT_SIZE_ERR_MASK		0x0000000000000040ULL
#define	TX_ENT_MSK_MBOX_ERR_SHIFT		7	/* bit 7: 0 to flag */
#define	TX_ENT_MSK_MBOX_ERR_MASK		0x0000000000000080ULL
#define	TX_ENT_MSK_MK_SHIFT			15	/* bit 15: 0 to flag */
#define	TX_ENT_MSK_MK_MASK			0x0000000000008000ULL
#define	TX_ENT_MSK_MK_ALL		(TX_ENT_MSK_PKT_PRT_ERR_MASK | \
					TX_ENT_MSK_CONF_PART_ERR_MASK |	\
					TX_ENT_MSK_NACK_PKT_RD_MASK |	\
					TX_ENT_MSK_NACK_PREF_MASK |	\
					TX_ENT_MSK_PREF_BUF_ECC_ERR_MASK | \
					TX_ENT_MSK_TX_RING_OFLOW_MASK |	\
					TX_ENT_MSK_PKT_SIZE_ERR_MASK | \
					TX_ENT_MSK_MBOX_ERR_MASK | \
					TX_ENT_MSK_MK_MASK)


typedef union _tx_dma_ent_msk_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res1_1:16;
			uint32_t mk:1;
			uint32_t res2:7;
			uint32_t mbox_err:1;
			uint32_t pkt_size_err:1;
			uint32_t tx_ring_oflow:1;
			uint32_t pref_buf_ecc_err:1;
			uint32_t nack_pref:1;
			uint32_t nack_pkt_rd:1;
			uint32_t conf_part_err:1;
			uint32_t pkt_prt_err:1;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t pkt_prt_err:1;
			uint32_t conf_part_err:1;
			uint32_t nack_pkt_rd:1;
			uint32_t nack_pref:1;
			uint32_t pref_buf_ecc_err:1;
			uint32_t tx_ring_oflow:1;
			uint32_t pkt_size_err:1;
			uint32_t mbox_err:1;
			uint32_t res2:7;
			uint32_t mk:1;
			uint32_t res1_1:16;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} tx_dma_ent_msk_t, *p_tx_dma_ent_msk_t;


/* Transmit Control and Status  (DMC + 0x40028) */
#define	TX_CS_PKT_PRT_ERR_SHIFT			0	/* RO, bit 0 */
#define	TX_CS_PKT_PRT_ERR_MASK			0x0000000000000001ULL
#define	TX_CS_CONF_PART_ERR_SHIF		1	/* RO, bit 1 */
#define	TX_CS_CONF_PART_ERR_MASK		0x0000000000000002ULL
#define	TX_CS_NACK_PKT_RD_SHIFT			2	/* RO, bit 2 */
#define	TX_CS_NACK_PKT_RD_MASK			0x0000000000000004ULL
#define	TX_CS_PREF_SHIFT			3	/* RO, bit 3 */
#define	TX_CS_PREF_MASK				0x0000000000000008ULL
#define	TX_CS_PREF_BUF_PAR_ERR_SHIFT		4	/* RO, bit 4 */
#define	TX_CS_PREF_BUF_PAR_ERR_MASK		0x0000000000000010ULL
#define	TX_CS_RING_OFLOW_SHIFT			5	/* RO, bit 5 */
#define	TX_CS_RING_OFLOW_MASK			0x0000000000000020ULL
#define	TX_CS_PKT_SIZE_ERR_SHIFT		6	/* RW, bit 6 */
#define	TX_CS_PKT_SIZE_ERR_MASK			0x0000000000000040ULL
#define	TX_CS_MMK_SHIFT				14	/* RC, bit 14 */
#define	TX_CS_MMK_MASK				0x0000000000004000ULL
#define	TX_CS_MK_SHIFT				15	/* RCW1C, bit 15 */
#define	TX_CS_MK_MASK				0x0000000000008000ULL
#define	TX_CS_SNG_SHIFT				27	/* RO, bit 27 */
#define	TX_CS_SNG_MASK				0x0000000008000000ULL
#define	TX_CS_STOP_N_GO_SHIFT			28	/* RW, bit 28 */
#define	TX_CS_STOP_N_GO_MASK			0x0000000010000000ULL
#define	TX_CS_MB_SHIFT				29	/* RO, bit 29 */
#define	TX_CS_MB_MASK				0x0000000020000000ULL
#define	TX_CS_RST_STATE_SHIFT			30	/* Rw, bit 30 */
#define	TX_CS_RST_STATE_MASK			0x0000000040000000ULL
#define	TX_CS_RST_SHIFT				31	/* Rw, bit 31 */
#define	TX_CS_RST_MASK				0x0000000080000000ULL
#define	TX_CS_LASTMASK_SHIFT			32	/* RW, bit 43:32 */
#define	TX_CS_LASTMARK_MASK			0x00000FFF00000000ULL
#define	TX_CS_PKT_CNT_SHIFT			48	/* RW, bit 59:48 */
#define	TX_CS_PKT_CNT_MASK			0x0FFF000000000000ULL

/* Trasnmit Control and Status */
typedef union _tx_cs_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res1:4;
			uint32_t pkt_cnt:12;
			uint32_t res2:4;
			uint32_t lastmark:12;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t lastmark:12;
			uint32_t res2:4;
			uint32_t pkt_cnt:12;
			uint32_t res1:4;
#endif
		} hdw;

#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t rst:1;
			uint32_t rst_state:1;
			uint32_t mb:1;
			uint32_t stop_n_go:1;
			uint32_t sng_state:1;
			uint32_t res1:11;
			uint32_t mk:1;
			uint32_t mmk:1;
			uint32_t res2:6;
			uint32_t mbox_err:1;
			uint32_t pkt_size_err:1;
			uint32_t tx_ring_oflow:1;
			uint32_t pref_buf_par_err:1;
			uint32_t nack_pref:1;
			uint32_t nack_pkt_rd:1;
			uint32_t conf_part_err:1;
			uint32_t pkt_prt_err:1;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t pkt_prt_err:1;
			uint32_t conf_part_err:1;
			uint32_t nack_pkt_rd:1;
			uint32_t nack_pref:1;
			uint32_t pref_buf_par_err:1;
			uint32_t tx_ring_oflow:1;
			uint32_t pkt_size_err:1;
			uint32_t mbox_err:1;
			uint32_t res2:6;
			uint32_t mmk:1;
			uint32_t mk:1;
			uint32_t res1:11;
			uint32_t sng_state:1;
			uint32_t stop_n_go:1;
			uint32_t mb:1;
			uint32_t rst_state:1;
			uint32_t rst:1;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res1:4;
			uint32_t pkt_cnt:12;
			uint32_t res2:4;
			uint32_t lastmark:12;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t lastmark:12;
			uint32_t res2:4;
			uint32_t pkt_cnt:12;
			uint32_t res1:4;
#endif
	} hdw;

#endif
	} bits;
} tx_cs_t, *p_tx_cs_t;

/* Trasnmit Mailbox High (DMC + 0x40030) */
#define	TXDMA_MBH_SHIFT			0	/* bit 11:0 */
#define	TXDMA_MBH_ADDR_SHIFT		32	/* bit 43:32 */
#define	TXDMA_MBH_MASK			0x0000000000000FFFULL

typedef union _txdma_mbh_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res1_1:20;
			uint32_t mbaddr:12;

#elif defined(_BIT_FIELDS_LTOH)
			uint32_t mbaddr:12;
			uint32_t res1_1:20;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txdma_mbh_t, *p_txdma_mbh_t;


/* Trasnmit Mailbox Low (DMC + 0x40038) */
#define	TXDMA_MBL_SHIFT			6	/* bit 31:6 */
#define	TXDMA_MBL_MASK			0x00000000FFFFFFC0ULL

typedef union _txdma_mbl_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t mbaddr:26;
			uint32_t res2:6;

#elif defined(_BIT_FIELDS_LTOH)
			uint32_t res2:6;
			uint32_t mbaddr:26;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txdma_mbl_t, *p_txdma_mbl_t;

/* Trasnmit Prefetch State High (DMC + 0x40040) */
#define	TX_DMA_PREF_ST_SHIFT		0	/* bit 5:0 */
#define	TX_DMA_PREF_ST_MASK		0x000000000000003FULL

typedef union _tx_dma_pre_st_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res1_1:13;
			uint32_t shadow_hd:19;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t shadow_hd:19;
			uint32_t res1_1:13;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} tx_dma_pre_st_t, *p_tx_dma_pre_st_t;

/* Trasnmit Ring Error Log High (DMC + 0x40048) */
#define	TX_RNG_ERR_LOGH_ERR_ADDR_SHIFT		0	/* RO bit 11:0 */
#define	TX_RNG_ERR_LOGH_ERR_ADDR_MASK		0x0000000000000FFFULL
#define	TX_RNG_ERR_LOGH_ADDR_SHIFT		32
#define	TX_RNG_ERR_LOGH_ERRCODE_SHIFT		26	/* RO bit 29:26 */
#define	TX_RNG_ERR_LOGH_ERRCODE_MASK		0x000000003C000000ULL
#define	TX_RNG_ERR_LOGH_MERR_SHIFT		30	/* RO bit 30 */
#define	TX_RNG_ERR_LOGH_MERR_MASK		0x0000000040000000ULL
#define	TX_RNG_ERR_LOGH_ERR_SHIFT		31	/* RO bit 31 */
#define	TX_RNG_ERR_LOGH_ERR_MASK		0x0000000080000000ULL

/* Transmit Ring Error codes */
#define	TXDMA_RING_PKT_PRT_ERR			0
#define	TXDMA_RING_CONF_PART_ERR		0x01
#define	TXDMA_RING_NACK_PKT_ERR			0x02
#define	TXDMA_RING_NACK_PREF_ERR		0x03
#define	TXDMA_RING_PREF_BUF_PAR_ERR		0x04
#define	TXDMA_RING_TX_RING_OFLOW_ERR		0x05
#define	TXDMA_RING_PKT_SIZE_ERR			0x06

typedef union _tx_rng_err_logh_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t err:1;
			uint32_t merr:1;
			uint32_t errcode:4;
			uint32_t res2:14;
			uint32_t err_addr:12;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t err_addr:12;
			uint32_t res2:14;
			uint32_t errcode:4;
			uint32_t merr:1;
			uint32_t err:1;

#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} tx_rng_err_logh_t, *p_tx_rng_err_logh_t;


/* Trasnmit Ring Error Log Log (DMC + 0x40050) */
#define	TX_RNG_ERR_LOGL_ERR_ADDR_SHIFT		0	/* RO bit 31:0 */
#define	TX_RNG_ERR_LOGL_ERR_ADDR_MASK		0x00000000FFFFFFFFULL

typedef union _tx_rng_err_logl_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t err_addr:32;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t err_addr:32;

#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} tx_rng_err_logl_t, *p_tx_rng_err_logl_t;

/*
 * TDMC_INTR_RBG_REG (DMC + 0x40060)
 */
typedef union _tdmc_intr_dbg_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res:16;
			uint32_t mk:1;
			uint32_t rsvd:7;
			uint32_t mbox_err:1;
			uint32_t pkt_size_err:1;
			uint32_t tx_ring_oflow:1;
			uint32_t pref_buf_par_err:1;
			uint32_t nack_pref:1;
			uint32_t nack_pkt_rd:1;
			uint32_t conf_part_err:1;
			uint32_t pkt_part_err:1;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t pkt_part_err:1;
			uint32_t conf_part_err:1;
			uint32_t nack_pkt_rd:1;
			uint32_t nack_pref:1;
			uint32_t pref_buf_par_err:1;
			uint32_t tx_ring_oflow:1;
			uint32_t pkt_size_err:1;
			uint32_t mbox_err:1;
			uint32_t rsvd:7;
			uint32_t mk:1;
			uint32_t res:16;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} tdmc_intr_dbg_t, *p_tdmc_intr_dbg_t;


/*
 * TX_CS_DBG (DMC + 0x40068)
 */
typedef union _tx_cs_dbg_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res1:4;
			uint32_t pkt_cnt:12;
			uint32_t res2:16;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t res2:16;
			uint32_t pkt_cnt:12;
			uint32_t res1:4;
#endif
		} hdw;

#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t rsvd:32;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t rsvd:32;

#endif
		} ldw;

#ifndef _BIG_ENDIAN
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res1:4;
			uint32_t pkt_cnt:12;
			uint32_t res2:16;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t res2:16;
			uint32_t pkt_cnt:12;
			uint32_t res1:4;
#endif
	} hdw;

#endif
	} bits;
} tx_cs_dbg_t, *p_tx_cs_dbg_t;

#define	TXDMA_MAILBOX_BYTE_LENGTH		64
#define	TXDMA_MAILBOX_UNUSED			24

typedef struct _txdma_mailbox_t {
	tx_cs_t			tx_cs;				/* 8 bytes */
	tx_dma_pre_st_t		tx_dma_pre_st;			/* 8 bytes */
	tx_ring_hdl_t		tx_ring_hdl;			/* 8 bytes */
	tx_ring_kick_t		tx_ring_kick;			/* 8 bytes */
	uint32_t		tx_rng_err_logh;		/* 4 bytes */
	uint32_t		tx_rng_err_logl;		/* 4 bytes */
	uint32_t		resv[TXDMA_MAILBOX_UNUSED];
} txdma_mailbox_t, *p_txdma_mailbox_t;

#if OLD
/* Transmit Ring Scheduler (per port) */
#define	TX_DMA_MAP_OFFSET(port)		(port * 8 + TX_DMA_MAP_REG)
#define	TX_DMA_MAP_PORT_OFFSET(port)	(port * 8)
#define	TX_DMA_MAP_REG			(FZC_DMC + 0x50000)
#define	TX_DMA_MAP0_REG			(FZC_DMC + 0x50000)
#define	TX_DMA_MAP1_REG			(FZC_DMC + 0x50008)
#define	TX_DMA_MAP2_REG			(FZC_DMC + 0x50010)
#define	TX_DMA_MAP3_REG			(FZC_DMC + 0x50018)

#define	TX_DMA_MAP_SHIFT		0	/* RO bit 31:0 */
#define	TX_DMA_MAPMASK			0x00000000FFFFFFFFULL

typedef union _tx_dma_map_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t bind:32;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t bind:32;

#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} tx_dma_map_t, *p_tx_dma_map_t;
#endif

#if OLD
/* Transmit Ring Scheduler: DRR Weight (32 Channels) */
#define	DRR_WT_REG			(FZC_DMC + 0x51000)
#define	DRR_WT_SHIFT			0	/* RO bit 19:0 */
#define	DRR_WT_MASK			0x00000000000FFFFFULL

#define	TXDMA_DRR_RNG_USE_OFFSET(channel)	(channel * 16)

typedef union _drr_wt_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res1_1:12;
			uint32_t wt:20;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t wt:20;
			uint32_t res1_1:12;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} drr_wt_t, *p_drr_wt_t;
#endif

#if OLD

/* Performance Monitoring (32 Channels) */
#define	TXRNG_USE_REG			(FZC_DMC + 0x51008)
#define	TXRNG_USE_CNT_SHIFT		0	/* RO bit 26:0 */
#define	TXRNG_USE_CNT_MASK		0x0000000007FFFFFFULL
#define	TXRNG_USE_OFLOW_SHIFT		0	/* RO bit 27 */
#define	TXRNG_USE_OFLOW_MASK		0x0000000008000000ULL

typedef union _txrng_use_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t res1_1:4;
			uint32_t oflow:1;
			uint32_t cnt:27;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t cnt:27;
			uint32_t oflow:1;
			uint32_t res1_1:4;

#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} txrng_use_t, *p_txrng_use_t;

#endif

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

#define	TX_CKSUM_EN_PKT_TYPE_TCP	(1ull << TX_PKT_HEADER_PKT_TYPE_SHIFT)
#define	TX_CKSUM_EN_PKT_TYPE_UDP	(2ull << TX_PKT_HEADER_PKT_TYPE_SHIFT)
#define	TX_CKSUM_EN_PKT_TYPE_NOOP	(0ull << TX_PKT_HEADER_PKT_TYPE_SHIFT)

typedef union _tx_pkt_header_t {
	uint64_t value;
	struct {
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t pad:3;
			uint32_t resv2:13;
			uint32_t tot_xfer_len:14;
			uint32_t resv1:2;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t pad:3;
			uint32_t resv2:13;
			uint32_t tot_xfer_len:14;
			uint32_t resv1:2;
#endif
		} ldw;
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t l4stuff:6;
			uint32_t resv3:2;
			uint32_t l4start:6;
			uint32_t resv2:2;
			uint32_t l3start:4;
			uint32_t ihl:4;
			uint32_t vlan:1;
			uint32_t llc:1;
			uint32_t res1:3;
			uint32_t ip_ver:1;
			uint32_t cksum_en_pkt_type:2;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t l4stuff:6;
			uint32_t resv3:2;
			uint32_t l4start:6;
			uint32_t resv2:2;
			uint32_t l3start:4;
			uint32_t ihl:4;
			uint32_t vlan:1;
			uint32_t llc:1;
			uint32_t res1:3;
			uint32_t ip_ver:1;
			uint32_t cksum_en_pkt_type:2;
#endif
		} hdw;
	} bits;
} tx_pkt_header_t, *p_tx_pkt_header_t;

typedef struct _tx_pkt_hdr_all_t {
	tx_pkt_header_t		pkthdr;
	uint64_t		reserved;
} tx_pkt_hdr_all_t, *p_tx_pkt_hdr_all_t;

/* Debug only registers */
#define	TDMC_INJ_PAR_ERR_REG		(FZC_DMC + 0x45040)
#define	TDMC_INJ_PAR_ERR_MASK		0x0000000000FFFFFFULL
#define	TDMC_INJ_PAR_ERR_MASK_N2	0x000000000000FFFFULL

typedef union _tdmc_inj_par_err_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t rsvc:8;
			uint32_t inject_parity_error:24;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t inject_parity_error:24;
			uint32_t rsvc:8;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} tdmc_inj_par_err_t, *p_tdmc_inj_par_err_t;

typedef union _tdmc_inj_par_err_n2_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t rsvc:16;
			uint32_t inject_parity_error:16;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t inject_parity_error:16;
			uint32_t rsvc:16;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} tdmc_inj_par_err_n2_t, *p_tdmc_inj_par_err_n2_t;

#define	TDMC_DBG_SEL_REG		(FZC_DMC + 0x45080)
#define	TDMC_DBG_SEL_MASK		0x000000000000003FULL

typedef union _tdmc_dbg_sel_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t rsvc:26;
			uint32_t dbg_sel:6;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t dbg_sel:6;
			uint32_t rsvc:26;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} tdmc_dbg_sel_t, *p_tdmc_dbg_sel_t;

#define	TDMC_TRAINING_REG		(FZC_DMC + 0x45088)
#define	TDMC_TRAINING_MASK		0x00000000FFFFFFFFULL

typedef union _tdmc_training_t {
	uint64_t value;
	struct {
#ifdef	_BIG_ENDIAN
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t vec:32;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t vec:6;
#endif
		} ldw;
#ifndef _BIG_ENDIAN
		uint32_t hdw;
#endif
	} bits;
} tdmc_training_t, *p_tdmc_training_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NXGE_NXGE_TXDMA_HW_H */
