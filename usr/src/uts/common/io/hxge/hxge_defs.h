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

#ifndef	_SYS_HXGE_HXGE_DEFS_H
#define	_SYS_HXGE_HXGE_DEFS_H

#ifdef	__cplusplus
extern "C" {
#endif

#if	!defined(_BIG_ENDIAN) && !defined(_LITTLE_ENDIAN) && \
		!defined(__BIG_ENDIAN) && !defined(__LITTLE_ENDIAN)
#error	Host endianness not defined
#endif

#if	!defined(_BIT_FIELDS_HTOL) && !defined(_BIT_FIELDS_LTOH) && \
		!defined(__BIT_FIELDS_HTOL) && !defined(__BIT_FIELDS_LTOH)
#error	Bit ordering not defined
#endif

/* RDC/TDC CSR size */
#define	DMA_CSR_SIZE		2048

/*
 * Define the Default RBR, RCR
 */
#define	RBR_DEFAULT_MAX_BLKS	4096	/* each entry (16 blockaddr/64B) */
#define	RBR_NBLK_PER_LINE	16	/* 16 block addresses per 64 B line */
#define	RBR_DEFAULT_MAX_LEN	65472	/* 2^16 - 64 */
#define	RBR_DEFAULT_MIN_LEN	64	/* multiple of 64 */

#define	SW_OFFSET_NO_OFFSET	0
#define	SW_OFFSET_64		1	/* 64 bytes */
#define	SW_OFFSET_128		2	/* 128 bytes */
#define	SW_OFFSET_INVALID	3

/*
 * RBR block descriptor is 32 bits (bits [43:12]
 */
#define	RBR_BKADDR_SHIFT	12
#define	RCR_DEFAULT_MAX_BLKS	4096	/* each entry (8 blockaddr/64B) */
#define	RCR_NBLK_PER_LINE	8	/* 8 block addresses per 64 B line */
#define	RCR_DEFAULT_MAX_LEN	(RCR_DEFAULT_MAX_BLKS)
#define	RCR_DEFAULT_MIN_LEN	32

/*  DMA Channels.  */
#define	HXGE_MAX_DMCS		(HXGE_MAX_RDCS + HXGE_MAX_TDCS)
#define	HXGE_MAX_RDCS		4
#define	HXGE_MAX_TDCS		4

#define	VLAN_ETHERTYPE			(0x8100)

/* 256 total, each blade gets 42 */
#define	TCAM_HXGE_TCAM_MAX_ENTRY	42

/*
 * Locate the DMA channel start offset (PIO_VADDR)
 * (DMA virtual address space of the PIO block)
 */
/* TX_RNG_CFIG is not used since we are not using VADDR. */
#define	TX_RNG_CFIG			0x1000000
#define	TDMC_PIOVADDR_OFFSET(channel)	(2 * DMA_CSR_SIZE * channel)
#define	RDMC_PIOVADDR_OFFSET(channel)	(TDMC_OFFSET(channel) + DMA_CSR_SIZE)

/*
 * PIO access using the DMC block directly (DMC)
 */
#define	DMC_OFFSET(channel)		(DMA_CSR_SIZE * channel)
#define	TDMC_OFFSET(channel)		(TX_RNG_CFIG + DMA_CSR_SIZE * channel)

#ifdef	SOLARIS
#ifndef	i386
#define	_BIT_FIELDS_BIG_ENDIAN		_BIT_FIELDS_HTOL
#else
#define	_BIT_FIELDS_LITTLE_ENDIAN	_BIT_FIELDS_LTOH
#endif
#else
#define	_BIT_FIELDS_LITTLE_ENDIAN	_LITTLE_ENDIAN_BITFIELD
#endif

/*
 * The following macros expect unsigned input values.
 */
#define	TXDMA_CHANNEL_VALID(cn)		(cn < HXGE_MAX_TDCS)

/*
 * Logical device definitions.
 */
#define	HXGE_INT_MAX_LD		32
#define	HXGE_INT_MAX_LDG	32

#define	HXGE_RDMA_LD_START	0	/* 0 - 3 with 4 - 7 reserved */
#define	HXGE_TDMA_LD_START	8	/* 8 - 11 with 12 - 15 reserved */
#define	HXGE_VMAC_LD		16
#define	HXGE_PFC_LD		17
#define	HXGE_NMAC_LD		18
#define	HXGE_MBOX_LD_START	20	/* 20 - 23  for SW Mbox */
#define	HXGE_SYS_ERROR_LD	31

#define	LDG_VALID(n)		(n < HXGE_INT_MAX_LDG)
#define	LD_VALID(n)		(n < HXGE_INT_MAX_LD)
#define	LD_RXDMA_LD_VALID(n)	(n < HXGE_MAX_RDCS)
#define	LD_TXDMA_LD_VALID(n)	(n >= HXGE_MAX_RDCS && \
					((n - HXGE_MAX_RDCS) < HXGE_MAX_TDCS)))

#define	LD_TIMER_MAX		0x3f
#define	LD_INTTIMER_VALID(n)	(n <= LD_TIMER_MAX)

/* System Interrupt Data */
#define	SID_VECTOR_MAX		0x1f
#define	SID_VECTOR_VALID(n)	(n <= SID_VECTOR_MAX)

#define	LD_IM_MASK		0x00000003ULL
#define	LDGTITMRES_RES_MASK	0x000FFFFFULL

#define	MIN_FRAME_SIZE		106	/* 68 byte min MTU + 38 byte header */
#define	MAX_FRAME_SIZE		9216
#define	STD_FRAME_SIZE		1522	/* 1518 + 4 = 5EE + 4 */
#define	HXGE_DEFAULT_MTU	1500
/*
 * sizeof (struct ether_header) + ETHERFCSL + 4 + TX_PKT_HEADER_SIZE
 * 12 + 6 + 4 + 16
 */
#define	MTU_TO_FRAME_SIZE	38

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_HXGE_HXGE_DEFS_H */
