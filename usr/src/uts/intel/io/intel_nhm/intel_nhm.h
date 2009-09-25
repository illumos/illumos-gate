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

#ifndef _INTEL_NHM_H
#define	_INTEL_NHM_H

#ifdef __cplusplus
extern "C" {
#endif

#define	NHM_EP_CPU	0x2c408086
#define	NHM_WS_CPU	0x2c418086
#define	NHM_CPU_RAS	0x2c1a8086
#define	NHM_JF_CPU	0x2c588086
#define	NHM_JF_CPU_RAS	0x2cda8086
#define	NHM_WM_CPU	0x2c708086
#define	NHM_WM_CPU_RAS	0x2d9a8086

#define	NHM_INTERCONNECT	"Intel QuickPath"

#define	MAX_CPU_NODES	2
#define	CPU_PCI_DEVS	6
#define	CPU_PCI_FUNCS	6

#define	MAX_BUS_NUMBER	max_bus_number

#define	SOCKET_BUS(cpu) (MAX_BUS_NUMBER - (cpu))
#define	CPU_ID_RD(cpu)  nhm_pci_getl(SOCKET_BUS(cpu), 0, 0, 0, 0)
#define	MC_CONTROL_RD(cpu) \
    nhm_pci_getl(SOCKET_BUS(cpu), 3, 0, 0x48, 0)
#define	MC_STATUS_RD(cpu) \
    nhm_pci_getl(SOCKET_BUS(cpu), 3, 0, 0x4c, 0)
#define	MC_SMI_SPARE_DIMM_ERROR_STATUS_RD(cpu) \
    nhm_pci_getl(SOCKET_BUS(cpu), 3, 0, 0x50, 0)
#define	MC_CPU_RAS_RD(cpu) \
    nhm_pci_getl(SOCKET_BUS(cpu), 3, 2, 0, 0)
#define	MC_SCRUB_CONTROL_RD(cpu) \
    nhm_pci_getl(SOCKET_BUS(cpu), 3, 2, 0x4c, 0)
#define	MC_SCRUB_CONTROL_WR(cpu, reg) nhm_pci_putl(SOCKET_BUS(cpu), 3, 2, \
    0x4c, reg);
#define	MC_SSR_CONTROL_RD(cpu)	nhm_pci_getl(SOCKET_BUS(cpu), 3, 2, 0x48, 0)
#define	MC_SSR_CONTROL_WR(cpu, reg) nhm_pci_putl(SOCKET_BUS(cpu), 3, 2, 0x48, \
    reg);
#define	MC_SSR_SCRUB_CONTROL_RD(cpu)	nhm_pci_getl(SOCKET_BUS(cpu), 3, 2, \
    0x4c, 0)
#define	MC_RAS_ENABLES_RD(cpu)	nhm_pci_getl(SOCKET_BUS(cpu), 3, 2, 0x50, 0)
#define	MC_RAS_STATUS_RD(cpu)	nhm_pci_getl(SOCKET_BUS(cpu), 3, 2, 0x54, 0)
#define	MC_SSR_STATUS_RD(cpu)	nhm_pci_getl(SOCKET_BUS(cpu), 3, 2, 0x60, 0)
#define	MC_CHANNEL_MAPPER_RD(cpu)	nhm_pci_getl(SOCKET_BUS(cpu), 3, 0, \
    0x60, 0)
#define	MC_COR_ECC_CNT_RD(cpu, select) \
    nhm_pci_getl(SOCKET_BUS(cpu), 3, 2, 0x80 + ((select) * 4), 0)
#define	MC_CHANNEL_RANK_PRESENT_RD(cpu, channel) \
    nhm_pci_getl(SOCKET_BUS(cpu), (channel) + 4, 0, 0x7c, 0)
#define	MC_DOD_RD(cpu, channel, select) \
    nhm_pci_getl(SOCKET_BUS(cpu), (channel) + 4, 1, 0x48 + ((select) * 4), 0)
#define	MC_SAG_RD(cpu, channel, select) \
    nhm_pci_getl(SOCKET_BUS(cpu), (channel) + 4, 1, 0x80 + ((select) * 4), 0)
#define	MC_RIR_LIMIT_RD(cpu, channel, select) \
    nhm_pci_getl(SOCKET_BUS(cpu), (channel) + 4, 2, 0x40 + ((select) * 4), 0)
#define	MC_RIR_WAY_RD(cpu, channel, select) \
    nhm_pci_getl(SOCKET_BUS(cpu), (channel) + 4, 2, 0x80 + ((select) * 4), 0)
#define	MC_CHANNEL_DIMM_INIT_PARAMS_RD(cpu, channel) \
    nhm_pci_getl(SOCKET_BUS(cpu), (channel) + 4, 0, 0x58, 0)
#define	SAD_DRAM_RULE_RD(cpu, rule) \
    nhm_pci_getl(SOCKET_BUS(cpu), 0, 1, 0x80 + (4 * (rule)), 0)
#define	SAD_INTERLEAVE_LIST_RD(cpu, rule) \
    nhm_pci_getl(SOCKET_BUS(cpu), 0, 1, 0xc0 + (4 * (rule)), 0)
#define	TAD_DRAM_RULE_RD(cpu, rule) \
    nhm_pci_getl(SOCKET_BUS(cpu), 3, 1, 0x80 + (4 * (rule)), 0)
#define	TAD_INTERLEAVE_LIST_RD(cpu, rule) \
    nhm_pci_getl(SOCKET_BUS(cpu), 3, 1, 0xc0 + (4 * (rule)), 0)
#define	MC_DIMM_CLK_RATIO_STATUS(cpu) \
    nhm_pci_getl(SOCKET_BUS(cpu), 3, 4, 0x50, 0)

/*
 * MC_CONTROL
 */
#define	MC_CONTROL_CHANNEL_ACTIVE(reg, channel) \
	((reg) & (1 << (8 + (channel))) != 0)
#define	MC_CONTROL_ECCEN(reg) (((reg) >> 1) & 1)
#define	MC_CONTROL_CLOSED_PAGE(reg) ((reg) & 1)
#define	MC_CONTROL_DIVBY3(reg) ((reg >> 6) &1)

#define	NUM_CACHELINE_BITS	6	/* Cachelines are 64B */

/*
 * MC_STATUS
 */
#define	CHANNEL_DISABLED(reg, channel) ((reg) & (1 << (channel)))
#define	WS_ECC_ENABLED	0x10
/*
 * MC_CHANNEL_DIMM_INIT_PARAMS
 */
#define	THREE_DIMMS_PRESENT		(1 << 24) /* not quad rank */
#define	SINGLE_QUAD_RANK_PRESENT	(1 << 23)
#define	QUAD_RANK_PRESENT		(1 << 22) /* 1 or 2 quad rank dimms */
#define	REGISTERED_DIMM			(1 << 15)

/*
 * MC_DOD_CH
 */
#define	RANKOFFSET(reg)	(((reg) >> 10) & 7)
#define	DIMMPRESENT(reg) (((reg) & (1 << 9)) != 0)
#define	NUMBANK(reg) (((reg) & (3 << 7)) == 0 ? 4 : (((reg) >> 7) & 3) * 8)
#define	NUMRANK(reg) (((reg) & (3 << 5)) == 0 ? 1 : (((reg) >> 5) & 3) * 2)
#define	NUMROW(reg) ((((reg) >> 2) & 7) + 12)
#define	NUMCOL(reg) (((reg) & 3) + 10)
#define	DIMMWIDTH	8
#define	DIMMSIZE(reg) ((1ULL << (NUMCOL(reg) + NUMROW(reg))) * NUMRANK(reg) \
	* NUMBANK(reg) * DIMMWIDTH)

/*
 * MC_SAG_CH
 */
#define	DIVBY3(reg)	(((reg) >> 27) & 1)	/* 3 or 6 way interleave */
#define	REMOVE_6(reg)	(((reg) >> 24) & 1)
#define	REMOVE_7(reg)	(((reg) >> 25) & 1)
#define	REMOVE_8(reg)	(((reg) >> 26) & 1)
#define	CH_ADDRESS_OFFSET(reg) \
	(int64_t)((uint64_t)(reg) & 0x00ffffff)
#define	CH_ADDRESS_SOFFSET(reg) \
	((int64_t)(((uint64_t)(reg) & 0x00ffffff) << 40) >>40)
/* SAG offset covers SA[39:16] so granularity is 2^16 = 64KB */
#define	SAG_OFFSET_GRANULARITY	16
/* 24-bit mask for TTMAD_CR_SAG_CH*.OFFSET */
#define	SAG_OFFSET_SIZE_MASK	0xffffffULL
/* 16-bit mask for lower bits not covered by CREG value (SA[15:0]) */
#define	SAG_OFFSET_ADDR_MASK	0xffffULL
#define	CACHELINE_ADDR_MASK	0x3fULL	/* 6-bit mask */

/*
 * MC_RIR_LIMIT_CH
 */
#define	RIR_LIMIT(reg)	((((uint64_t)(reg) & 0x000003ff) + 1) << 28)
/*
 * MC_RIR_WAY_CH
 */
#define	RIR_OFFSET(reg)	(int64_t)((uint64_t)(reg >> 4)& 0x3ff)
#define	RIR_SOFFSET(reg)	((int64_t)(((uint64_t)(reg) & 0x3ff0) << 50) \
				    >> 54)
#define	RIR_DIMM_RANK(reg)	((reg) & 0xf)
#define	RIR_RANK(reg)	((reg) & 0x3)
#define	RIR_DIMM(reg)	((reg)>>2 & 0x03)
#define	RIR_OFFSET_SIZE_MASK	0x3ff

#define	MAX_RIR_WAY 4

#define	RIR_LIMIT_GRANULARITY	28
#define	RIR_OFFSET_ADDR_MASK	0xfffffffULL	/* 28-bit mask */
#define	RIR_INTLV_PGOPEN_BIT	12	/* Rank interleaving */
#define	RIR_INTLV_PGOPEN_MASK	0xfffULL	/* 12-bit mask */
#define	RIR_INTLV_PGCLS_BIT	6	/* Rank interleaving */
#define	RIR_INTLV_PGCLS_MASK	0x3fULL	/* 6-bit mask */
#define	RIR_INTLV_SIZE_MASK	0x3ULL
/*
 * MC_RAS_ENABLES
 */
#define	RAS_LOCKSTEP_ENABLE(reg) (((reg) & 2) != 0)
#define	RAS_MIRROR_MEM_ENABLE(reg) (((reg) & 1) != 0)
/*
 * MC_RAS_STATUS
 */
#define	REDUNDANCY_LOSS(reg) (((reg) & 1) != 0)
/*
 * MC_SSRSTATUS
 */
#define	SPAREING_IN_PROGRESS(reg) (((reg) & 2) != 0)
#define	SPAREING_COMPLETE(reg) (((reg) & 1) != 0)

/*
 * MC_SSR_CONTROL
 */
#define	SSR_MODE(reg) ((reg) & 3)
#define	SSR_IDLE	0
#define	SSR_SCRUB	1
#define	SSR_SPARE	2
#define	DEMAND_SCRUB_ENABLE	(1 << 6)
/*
 * MC_SCRUB_CONTROL
 */
#define	STARTSCRUB	(1 << 24)
/*
 * MC_DIMM_CLK_RATIO_STATUS
 */
#define	MAX_DIMM_CLK_RATIO(reg) (((reg) >> 24) & 0x1f)
/*
 * MC_SMI_SPARE_DIMM_ERROR_STATUS_RD
 */
#define	REDUNDANCY_LOSS_FAILING_DIMM(status) (((status) >> 12) & 3)
#define	DIMM_ERROR_OVERFLOW_STATUS(status) ((status) & 0xfff)

#define	MAX_MEMORY_CONTROLLERS	MAX_CPU_NODES
#define	CHANNELS_PER_MEMORY_CONTROLLER	3
#define	MAX_DIMMS_PER_CHANNEL	3

/*
 * SAD_DRAM_RULE
 */
#define	SAD_DRAM_LIMIT(sad) ((((uint64_t)(sad) & 0x000fffc0ULL) + 0x40) << 20)
#define	SAD_DRAM_MODE(sad) (((sad) >> 1) & 3)
#define	SAD_DRAM_RULE_ENABLE(sad) ((sad) & 1)

/*
 * from SAD_DRAM_RULE*.MODE
 */
#define	DIRECT	0
#define	XOR	1
#define	MOD3	2
#define	SAD_INTERLEAVE(list, num)	(((list) >> ((num) * 4)) & 0x3)
#define	INTERLEAVE_NWAY	8
#define	MAX_SAD_DRAM_RULE	8

#define	SAD_LIMIT_GRANULARITY	26
#define	SAD_LIMIT_ADDR_MASK	0x3ffffffULL
#define	SAD_INTLV_DIRECT_BIT	6
#define	SAD_INTLV_XOR_BIT	16
#define	SAD_INTLV_SIZE_MASK	0x7ULL
#define	SAD_INTLV_ADDR_MASK	0x3fULL

/*
 * TAD_DRAM_RULE
 */
#define	TAD_DRAM_LIMIT(tad) ((((uint64_t)(tad) & 0x000fffc0ULL) + 0x40) << 20)
#define	TAD_DRAM_MODE(tad) (((tad) >> 1) & 3)
#define	TAD_DRAM_RULE_ENABLE(tad) ((tad) & 1)

#define	TAD_INTERLEAVE(list, channel) (((list) >> ((channel) * 4)) & 3)

#define	MAX_TAD_DRAM_RULE 8

#define	VRANK_SZ 0x40000000

typedef struct sad {
	uint64_t limit;
	uint32_t node_list;
	uint32_t node_tgt[INTERLEAVE_NWAY];
	char mode;
	char enable;
	char interleave;
} sad_t;

typedef struct tad {
	uint64_t limit;
	uint32_t pkg_list;
	uint32_t pkg_tgt[INTERLEAVE_NWAY];
	char mode;
	char enable;
	char interleave;
} tad_t;

typedef struct sag_ch {
	uint32_t offset;
	int32_t soffset;
	char divby3;
	char remove6;
	char remove7;
	char remove8;
} sag_ch_t;

typedef struct rir_way {
	uint16_t offset;
	int16_t soffset;
	uint8_t	rank;
	uint8_t dimm;
	uint8_t dimm_rank;
	uint64_t rlimit;
} way_t;

typedef struct rir {
	uint64_t limit;
	way_t way[MAX_RIR_WAY];
	char interleave;
} rir_t;

typedef struct dod_type {
	int NUMCol;
	int NUMRow;
	int NUMRank;
	int NUMBank;
	int DIMMPresent;
	int RankOffset;
} dod_t;

/*
 * MC_CHANNEL_MAPPER
 */
#define	CHANNEL_MAP(reg, channel, write) (((reg) >> ((channel) * 6 + \
	((write) ? 0 : 3))) & 7)

extern int max_bus_number;

#ifdef __cplusplus
}
#endif

#endif /* _INTEL_NHM_H */
