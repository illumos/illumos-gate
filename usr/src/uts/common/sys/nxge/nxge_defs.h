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

#ifndef	_SYS_NXGE_NXGE_DEFS_H
#define	_SYS_NXGE_NXGE_DEFS_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Block Address Assignment (24-bit base address)
 * (bits [23:20]: block	 [19]: set to 1 for FZC	)
 */
#define	PIO			0x000000
#define	FZC_PIO			0x080000
#define	RESERVED_1		0x100000
#define	FZC_MAC			0x180000
#define	RESERVED_2		0x200000
#define	FZC_IPP			0x280000
#define	FFLP			0x300000
#define	FZC_FFLP		0x380000
#define	PIO_VADDR		0x400000
#define	RESERVED_3		0x480000
#define	ZCP			0x500000
#define	FZC_ZCP			0x580000
#define	DMC			0x600000
#define	FZC_DMC			0x680000
#define	TXC			0x700000
#define	FZC_TXC			0x780000
#define	PIO_LDSV		0x800000
#define	RESERVED_4		0x880000
#define	PIO_LDGIM		0x900000
#define	RESERVED_5		0x980000
#define	PIO_IMASK0		0xa00000
#define	RESERVED_6		0xa80000
#define	PIO_IMASK1		0xb00000
#define	RESERVED_7_START	0xb80000
#define	RESERVED_7_END		0xc00000
#define	FZC_PROM		0xc80000
#define	RESERVED_8		0xd00000
#define	FZC_PIM			0xd80000
#define	RESERVED_9_START 	0xe00000
#define	RESERVED_9_END 		0xf80000

/* PIO		(0x000000) */


/* FZC_PIO	(0x080000) */
#define	LDGITMRES		(FZC_PIO + 0x00008)	/* timer resolution */
#define	SID			(FZC_PIO + 0x10200)	/* 64 LDG, INT data */
#define	LDG_NUM			(FZC_PIO + 0x20000)	/* 69 LDs */



/* FZC_IPP 	(0x280000) */


/* FFLP		(0x300000), Header Parser */

/* PIO_VADDR	(0x400000), PIO Virtaul DMA Address */
/* ?? how to access DMA via PIO_VADDR? */
#define	VADDR			(PIO_VADDR + 0x00000) /* ?? not for driver */


/* ZCP		(0x500000), Neptune Only */


/* FZC_ZCP	(0x580000), Neptune Only */


/* DMC 		(0x600000), register offset (32 DMA channels) */

/* Transmit Ring Register Offset (32 Channels) */
#define	TX_RNG_CFIG		(DMC + 0x40000)
#define	TX_RING_HDH		(DMC + 0x40008)
#define	TX_RING_HDL		(DMC + 0x40010)
#define	TX_RING_KICK		(DMC + 0x40018)
/* Transmit Operations (32 Channels) */
#define	TX_ENT_MSK		(DMC + 0x40020)
#define	TX_CS			(DMC + 0x40028)
#define	TXDMA_MBH		(DMC + 0x40030)
#define	TXDMA_MBL		(DMC + 0x40038)
#define	TX_DMA_PRE_ST		(DMC + 0x40040)
#define	TX_RNG_ERR_LOGH		(DMC + 0x40048)
#define	TX_RNG_ERR_LOGL		(DMC + 0x40050)
#if OLD
#define	SH_TX_RNG_ERR_LOGH	(DMC + 0x40058)
#define	SH_TX_RNG_ERR_LOGL	(DMC + 0x40060)
#endif

/* FZC_DMC RED Initial Random Value register offset (global) */
#define	RED_RAN_INIT		(FZC_DMC + 0x00068)

#define	RX_ADDR_MD		(FZC_DMC + 0x00070)

/* FZC_DMC Ethernet Timeout Countue register offset (global) */
#define	EING_TIMEOUT		(FZC_DMC + 0x00078)

/* RDC Table */
#define	RDC_TBL			(FZC_DMC + 0x10000)	/* 256 * 8 */

/* FZC_DMC partitioning support register offset (32 channels) */

#define	TX_LOG_PAGE_VLD		(FZC_DMC + 0x40000)
#define	TX_LOG_MASK1		(FZC_DMC + 0x40008)
#define	TX_LOG_VAL1		(FZC_DMC + 0x40010)
#define	TX_LOG_MASK2		(FZC_DMC + 0x40018)
#define	TX_LOG_VAL2		(FZC_DMC + 0x40020)
#define	TX_LOG_PAGE_RELO1	(FZC_DMC + 0x40028)
#define	TX_LOG_PAGE_RELO2	(FZC_DMC + 0x40030)
#define	TX_LOG_PAGE_HDL		(FZC_DMC + 0x40038)

#define	TX_ADDR_MOD		(FZC_DMC + 0x41000) /* only one? */


/* FZC_DMC RED Parameters register offset (32 channels) */
#define	RDC_RED_PARA1		(FZC_DMC + 0x30000)
#define	RDC_RED_PARA2		(FZC_DMC + 0x30008)
/* FZC_DMC RED Discard Cound Register offset (32 channels) */
#define	RED_DIS_CNT		(FZC_DMC + 0x30010)

#if OLD /* This has been moved to TXC */
/* Transmit Ring Scheduler (per port) */
#define	TX_DMA_MAP0		(FZC_DMC + 0x50000)
#define	TX_DMA_MAP1		(FZC_DMC + 0x50008)
#define	TX_DMA_MAP2		(FZC_DMC + 0x50010)
#define	TX_DMA_MAP3		(FZC_DMC + 0x50018)
#endif

/* Transmit Ring Scheduler: DRR Weight (32 Channels) */
#define	DRR_WT			(FZC_DMC + 0x51000)
#if OLD
#define	TXRNG_USE		(FZC_DMC + 0x51008)
#endif

/* TXC		(0x700000)??	*/


/* FZC_TXC	(0x780000)??	*/


/*
 * PIO_LDSV	(0x800000)
 * Logical Device State Vector 0, 1, 2.
 * (69 logical devices, 8192 apart, partitioning control)
 */
#define	LDSV0			(PIO_LDSV + 0x00000)	/* RO (64 - 69) */
#define	LDSV1			(PIO_LDSV + 0x00008)	/* RO (32 - 63) */
#define	LDSV2			(PIO_LDSV + 0x00010)	/* RO ( 0 - 31) */

/*
 * PIO_LDGIM	(0x900000)
 * Logical Device Group Interrupt Management (64 groups).
 * (count 64, step 8192)
 */
#define	LDGIMGN			(PIO_LDGIMGN + 0x00000)	/* RW */

/*
 * PIO_IMASK0	(0xA000000)
 *
 * Logical Device Masks 0, 1.
 * (64 logical devices, 8192 apart, partitioning control)
 */
#define	LD_IM0			(PIO_IMASK0 + 0x00000)	/* RW ( 0 - 63) */

/*
 * PIO_IMASK0	(0xB000000)
 *
 * Logical Device Masks 0, 1.
 * (5 logical devices, 8192 apart, partitioning control)
 */
#define	LD_IM1			(PIO_IMASK1 + 0x00000)	/* RW (64 - 69) */


/* DMC/TMC CSR size */
#define	DMA_CSR_SLL		9	/* Used to calculate VR addresses */
#define	DMA_CSR_SIZE		(1 << DMA_CSR_SLL) /* 512 */
#define	DMA_CSR_MASK		0xff	/* Used to calculate VR addresses */
	/*
	 * That is, each DMA CSR set must fit into a 512 byte space.
	 * If you subtract DMC (0x60000) from each DMA register definition,
	 * what you have left over is currently less than 255 (0xff)
	 */
#define	DMA_CSR_MIN_PAGE_SIZE	(2 * DMA_CSR_SIZE) /* 1024 */
	/*
	 * There are 2 subpages per page in a VR.
	 */
#define	VDMA_CSR_SIZE		(8 * DMA_CSR_MIN_PAGE_SIZE) /* 0x2000 */
	/*
	 * There are 8 pages in a VR.
	 */

/*
 * Define the Default RBR, RCR
 */
#define	RBR_DEFAULT_MAX_BLKS	8192	/* each entry (16 blockaddr/64B) */
#define	RBR_NBLK_PER_LINE	16	/* 16 block addresses per 64 B line */
#define	RBR_DEFAULT_MAX_LEN	(RBR_DEFAULT_MAX_BLKS)
#define	RBR_DEFAULT_MIN_LEN	1
#define	RCR_DEFAULT_MAX		8192

#define	SW_OFFSET_NO_OFFSET		0
#define	SW_OFFSET_64			1	/* 64 bytes */
#define	SW_OFFSET_128			2	/* 128 bytes */
/* The following additional offsets are defined for Neptune-L and RF-NIU */
#define	SW_OFFSET_192			3
#define	SW_OFFSET_256			4
#define	SW_OFFSET_320			5
#define	SW_OFFSET_384			6
#define	SW_OFFSET_448			7

#define	TDC_DEFAULT_MAX		8192
/*
 * RBR block descriptor is 32 bits (bits [43:12]
 */
#define	RBR_BKADDR_SHIFT	12


#define	RCR_DEFAULT_MAX_BLKS	4096	/* each entry (8 blockaddr/64B) */
#define	RCR_NBLK_PER_LINE	8	/* 8 block addresses per 64 B line */
#define	RCR_DEFAULT_MAX_LEN	(RCR_DEFAULT_MAX_BLKS)
#define	RCR_DEFAULT_MIN_LEN	1

/*  DMA Channels.  */
#define	NXGE_MAX_DMCS		(NXGE_MAX_RDCS + NXGE_MAX_TDCS)
#define	NXGE_MAX_RDCS		16
#define	NXGE_MAX_TDCS		24
#define	NXGE_MAX_TDCS_NIU	16
/*
 * original mapping from Hypervisor
 */
#ifdef	ORIGINAL
#define	NXGE_N2_RXDMA_START_LDG	0
#define	NXGE_N2_TXDMA_START_LDG	16
#define	NXGE_N2_MIF_LDG		32
#define	NXGE_N2_MAC_0_LDG	33
#define	NXGE_N2_MAC_1_LDG	34
#define	NXGE_N2_SYS_ERROR_LDG	35
#endif

#define	NXGE_N2_RXDMA_START_LDG	19
#define	NXGE_N2_TXDMA_START_LDG	27
#define	NXGE_N2_MIF_LDG		17
#define	NXGE_N2_MAC_0_LDG	16
#define	NXGE_N2_MAC_1_LDG	35
#define	NXGE_N2_SYS_ERROR_LDG	18
#define	NXGE_N2_LDG_GAP		17

#define	NXGE_MAX_RDC_GRPS	8

/*
 * Max. ports per Neptune and NIU
 */
#define	NXGE_MAX_PORTS			4
#define	NXGE_PORTS_NEPTUNE		4
#define	NXGE_PORTS_NIU			2

/*
 * Virtualization Regions.
 */
#define	NXGE_MAX_VRS			8

/*
 * TDC groups are used exclusively for the purpose of Hybrid I/O
 * TX needs one group for each VR
 */
#define	NXGE_MAX_TDC_GROUPS		(NXGE_MAX_VRS)

/* Max. RDC table groups */
#define	NXGE_MAX_RDC_GROUPS		8
#define	NXGE_MAX_RDCS			16
#define	NXGE_MAX_DMAS			32

#define	NXGE_MAX_MACS_XMACS		16
#define	NXGE_MAX_MACS_BMACS		8
#define	NXGE_MAX_MACS			(NXGE_MAX_PORTS * NXGE_MAX_MACS_XMACS)

#define	NXGE_MAX_VLANS			4096
#define	VLAN_ETHERTYPE			(0x8100)


/* Scaling factor for RBR (receive block ring) */
#define	RBR_SCALE_1		0
#define	RBR_SCALE_2		1
#define	RBR_SCALE_3		2
#define	RBR_SCALE_4		3
#define	RBR_SCALE_5		4
#define	RBR_SCALE_6		5
#define	RBR_SCALE_7		6
#define	RBR_SCALE_8		7


#define	MAX_PORTS_PER_NXGE	4
#define	MAX_MACS		32

#define	TX_GATHER_POINTER_SZ	8
#define	TX_GP_PER_BLOCK		8
#define	TX_DEFAULT_MAX_GPS	1024	/* Max. # of gather pointers */
#define	TX_DEFAULT_JUMBO_MAX_GPS 4096	/* Max. # of gather pointers */
#define	TX_DEFAULT_MAX_LEN	(TX_DEFAULT_MAX_GPS/TX_GP_PER_BLOCK)
#define	TX_DEFAULT_JUMBO_MAX_LEN (TX_DEFAULT_JUMBO_MAX_GPS/TX_GP_PER_BLOCK)

#define	TX_RING_THRESHOLD		(TX_DEFAULT_MAX_GPS/4)
#define	TX_RING_JUMBO_THRESHOLD		(TX_DEFAULT_JUMBO_MAX_GPS/4)

#define	TRANSMIT_HEADER_SIZE		16	/* 16 B frame header */

#define	TX_DESC_SAD_SHIFT	0
#define	TX_DESC_SAD_MASK	0x00000FFFFFFFFFFFULL	/* start address */
#define	TX_DESC_TR_LEN_SHIFT	44
#define	TX_DESC_TR_LEN_MASK	0x00FFF00000000000ULL	/* Transfer Length */
#define	TX_DESC_NUM_PTR_SHIFT	58
#define	TX_DESC_NUM_PTR_MASK	0x2C00000000000000ULL	/* gather pointers */
#define	TX_DESC_MASK_SHIFT	62
#define	TX_DESC_MASK_MASK	0x4000000000000000ULL	/* Mark bit */
#define	TX_DESC_SOP_SHIF	63
#define	TX_DESC_NUM_MASK	0x8000000000000000ULL	/* Start of packet */

#define	TCAM_FLOW_KEY_MAX_CLASS		12
#define	TCAM_L3_MAX_USER_CLASS		4
#define	TCAM_MAX_ENTRY			256
#define	TCAM_NIU_TCAM_MAX_ENTRY		128
#define	TCAM_NXGE_TCAM_MAX_ENTRY	256
#define	NXGE_L2_PROG_CLS		2
#define	NXGE_L3_PROG_CLS		4



/* TCAM entry formats */
#define	TCAM_IPV4_5TUPLE_FORMAT	0x00
#define	TCAM_IPV6_5TUPLE_FORMAT	0x01
#define	TCAM_ETHERTYPE_FORMAT	0x02


/* TCAM */
#define	TCAM_SELECT_IPV6	0x01
#define	TCAM_LOOKUP		0x04
#define	TCAM_DISCARD		0x08

/* FLOW Key */
#define	FLOW_L4_1_34_BYTES	0x10
#define	FLOW_L4_1_78_BYTES	0x11
#define	FLOW_L4_0_12_BYTES	(0x10 << 2)
#define	FLOW_L4_0_56_BYTES	(0x11 << 2)
#define	FLOW_PROTO_NEXT		0x10
#define	FLOW_IPDA		0x20
#define	FLOW_IPSA		0x40
#define	FLOW_VLAN		0x80
#define	FLOW_L2DA		0x100
#define	FLOW_PORT		0x200

/* TCAM */
#define	MAX_EFRAME	11

#define	TCAM_USE_L2RDC_FLOW_LOOKUP	0x00
#define	TCAM_USE_OFFSET_DONE		0x01
#define	TCAM_OVERRIDE_L2_FLOW_LOOKUP	0x02
#define	TCAM_OVERRIDE_L2_USE_OFFSET	0x03

/*
 * FCRAM (Hashing):
 *	1. IPv4 exact match
 *	2. IPv6 exact match
 *	3. IPv4 Optimistic match
 *	4. IPv6 Optimistic match
 *
 */
#define	FCRAM_IPV4_EXT_MATCH	0x00
#define	FCRAM_IPV6_EXT_MATCH	0x01
#define	FCRAM_IPV4_OPTI_MATCH	0x02
#define	FCRAM_IPV6_OPTI_MATCH	0x03


#define	NXGE_HASH_MAX_ENTRY	256


#define	MAC_ADDR_LENGTH		6

/* convert values */
#define	NXGE_BASE(x, y)		(((y) << (x ## _SHIFT)) & (x ## _MASK))
#define	NXGE_VAL(x, y)		(((y) & (x ## _MASK)) >> (x ## _SHIFT))

/*
 * Locate the DMA channel start offset (PIO_VADDR)
 * (DMA virtual address space of the PIO block)
 */
#define	TDMC_PIOVADDR_OFFSET(channel)	(2 * DMA_CSR_SIZE * channel)
#define	RDMC_PIOVADDR_OFFSET(channel)	(TDMC_OFFSET(channel) + DMA_CSR_SIZE)

/*
 * PIO access using the DMC block directly (DMC)
 */
#define	DMC_OFFSET(channel)	(DMA_CSR_SIZE * channel)
#define	TDMC_OFFSET(channel)	(TX_RNG_CFIG + DMA_CSR_SIZE * channel)

/*
 * Number of logical pages.
 */
#define	NXGE_MAX_LOGICAL_PAGES		2

#ifdef	SOLARIS
#ifndef	i386
#define	_BIT_FIELDS_BIG_ENDIAN		_BIT_FIELDS_HTOL
#else
#define	_BIT_FIELDS_LITTLE_ENDIAN	_BIT_FIELDS_LTOH
#endif
#else
#define	_BIT_FIELDS_LITTLE_ENDIAN	_LITTLE_ENDIAN_BITFIELD
#endif

#define	MAX_PIO_RETRIES		32

#define	IS_PORT_NUM_VALID(portn)\
	(portn < 4)

/*
 * The following macros expect unsigned input values.
 */
#define	TXDMA_CHANNEL_VALID(cn)		(cn < NXGE_MAX_TDCS)
#define	TXDMA_PAGE_VALID(pn)		(pn < NXGE_MAX_LOGICAL_PAGES)
#define	TXDMA_FUNC_VALID(fn)		(fn < MAX_PORTS_PER_NXGE)
#define	FUNC_VALID(n)			(n < MAX_PORTS_PER_NXGE)

/*
 * DMA channel binding definitions.
 */
#define	VIR_PAGE_INDEX_MAX		8
#define	VIR_SUB_REGIONS			2
#define	VIR_DMA_BIND			1

#define	SUBREGION_VALID(n)		(n < VIR_SUB_REGIONS)
#define	VIR_PAGE_INDEX_VALID(n)		(n < VIR_PAGE_INDEX_MAX)
#define	VRXDMA_CHANNEL_VALID(n)		(n < NXGE_MAX_RDCS)

/*
 * Logical device definitions.
 */
#define	NXGE_INT_MAX_LD		69
#define	NXGE_INT_MAX_LDG	64

#define	NXGE_RDMA_LD_START	 0
#define	NXGE_TDMA_LD_START	32
#define	NXGE_MIF_LD		63
#define	NXGE_MAC_LD_PORT0	64
#define	NXGE_MAC_LD_PORT1	65
#define	NXGE_MAC_LD_PORT2	66
#define	NXGE_MAC_LD_PORT3	67
#define	NXGE_SYS_ERROR_LD	68

#define	LDG_VALID(n)			(n < NXGE_INT_MAX_LDG)
#define	LD_VALID(n)			(n < NXGE_INT_MAX_LD)
#define	LD_RXDMA_LD_VALID(n)		(n < NXGE_MAX_RDCS)
#define	LD_TXDMA_LD_VALID(n)		(n >= NXGE_MAX_RDCS && \
					((n - NXGE_MAX_RDCS) < NXGE_MAX_TDCS)))
#define	LD_MAC_VALID(n)			(IS_PORT_NUM_VALID(n))

#define	LD_TIMER_MAX			0x3f
#define	LD_INTTIMER_VALID(n)		(n <= LD_TIMER_MAX)

/* System Interrupt Data */
#define	SID_VECTOR_MAX			0x1f
#define	SID_VECTOR_VALID(n)		(n <= SID_VECTOR_MAX)

#define	NXGE_COMPILE_32

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NXGE_NXGE_DEFS_H */
