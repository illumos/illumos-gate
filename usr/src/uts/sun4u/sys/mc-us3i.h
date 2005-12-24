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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_MC_US3I_H
#define	_SYS_MC_US3I_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(_KERNEL)

#define	NDGRPS_PER_MC		2		/* max dimm groups per mctrl */
#define	NDIMMS_PER_DGRP		2		/* max dimms in a group/pair */
#define	NLOGBANKS_PER_DGRP	2		/* max logical banks per grp */
#define	NLOGBANKS_PER_MC	16		/* max logical banks per mc */
#define	NLOGBANKS_PER_SEG	16		/* max logical banks per seg */
#define	MAX_DEVLEN		8
#define	TRANSFER_SIZE		64

#define	MC_SELECT_MASK		0x3000000000LL	/* upto 4 MCs at 64GB boundry */
#define	MC_SELECT_SHIFT		36
#define	DIMM_PAIR_SELECT_MASK	0x200000000LL	/* at 8GB boundry */
#define	DIMM_PAIR_SELECT_SHIFT	33
#define	LOG_BANK_SELECT_MASK	0x100000000LL	/* at 4GB boundry */
#define	LOG_BANK_SELECT_SHIFT	32
#define	XOR_DEVICE_SELECT_MASK	0x200000LL	/* at 2MB boundry */
#define	XOR_DEVICE_SELECT_SHIFT	21
#define	XOR_BANK_SELECT_MASK	0x100000LL	/* at 1MB boundry */
#define	XOR_BANK_SELECT_SHIFT	20

#define	MC_SIZE_MAX		0x1000000000LL	/* 64GB */
#define	DGRP_SIZE_MAX		0x200000000LL	/*  8GB */
#define	BANK_SIZE_MAX		0x100000000LL	/*  4GB */

#define	MC_BASE(id)		(id * MC_SIZE_MAX)
#define	DGRP_BASE(id)		((id & (NDGRPS_PER_MC - 1)) * DGRP_SIZE_MAX)
#define	LOGBANK_BASE(id)	((id & (NLOGBANKS_PER_SEG - 1)) * BANK_SIZE_MAX)

#define	ADDR_GEN_128Mb_X8_ROW_0	14
#define	ADDR_GEN_512Mb_X8_ROW_0	15

#ifndef	_ASM

struct mc_soft_state {
	dev_info_t	*dip;	/* dev info of myself */
	int		portid;
	int		mcr_read_ok;
	uint64_t	mcreg1;
	int		reglen;
	void		*reg;
	int		memlayoutlen;
	void		*memlayoutp;
};

struct memory_reg_info {
	uint64_t base;
	uint64_t size;
};

struct dimm_info {
	char	label[NDGRPS_PER_MC * NDIMMS_PER_DGRP][MAX_DEVLEN];
	char	table_width;	/* 1: symmetric 0: asymmetric */
	char	data[1];
};

struct pin_info {
	uchar_t	dimmtable[18];
	uchar_t	pintable[144];
};

/* This struct is included at the following structs to set up list */
typedef struct mc_dlist {
	struct mc_dlist *next;
	struct mc_dlist *prev;
	int id;
} mc_dlist_t;

/* unique segment id */
struct seg_info {
	mc_dlist_t seg_node;
	int nbanks;		/* The number of banks at this segment */
	uint32_t ifactor;	/* Max interleave factor at this segment */
	uint64_t base;
	uint64_t size;		/* memory size per segment */
	struct bank_info *head;	/* first bank at this segment */
	struct bank_info *tail;	/* last bank at this segment */
};

/* id = mc_id * nbanks + bank_no */
struct bank_info {
	mc_dlist_t bank_node;
	int local_id;		/* unique local bank id per segment */
	int seg_id;		/* unique segment id */
	int devgrp_id;		/* unique device group id */
	uint64_t mask;		/* If (Physical Address & MASK) == MATCH */
	uint64_t match;		/* Physic Address is located at this bank. */
	uint64_t base;		/* base address of the logical bank */
	uint64_t size;		/* memory size per logical bank */
	struct bank_info *next; /* next bank at the same segment */
};

/* id = id of dgrp_info * ndevices + device_no */
struct device_info {
	mc_dlist_t dev_node;
	char label[MAX_DEVLEN];
	uint64_t size;		/* memory size per physical dimm */
};

/* id = mc_id * ndevgrps + devgrp_no */
struct dgrp_info {
	mc_dlist_t dgrp_node;
	int ndevices;		/* number of physical dimms - always a pair */
	int nlogbanks;		/* number of logical banks - single or dual */
	int base_device;	/* base density - 128Mb, 256Mb, 512Mb or 1Gb */
	int part_type;		/* part type - x4, x8 */
	uint64_t base;		/* physical memory base of the dev group */
	uint64_t size;		/* total memory size of the dev group */
	int deviceids[NDIMMS_PER_DGRP];	/* 2 dimms per group on Jalapeno */
};

/* id = portid */
struct mctrl_info {
	mc_dlist_t mctrl_node;
	int ndevgrps;		/* The number of dimm groups */
	int devgrpids[NDGRPS_PER_MC];
	struct dimm_info *dimminfop;
};

extern int (*p2get_mem_unum)(int, uint64_t, char *, int, int *);
extern int (*p2get_mem_info)(int, uint64_t, uint64_t *, uint64_t *,
    uint64_t *, int *, int *, int *);
extern void plat_add_mem_unum_label(char *, int, int, int);

uint64_t get_mcr(int);

/* #ifdef	DEBUG */

#include <sys/promif.h>

/* useful debugging level of DPRINTF */
#define	MC_ATTACH_DEBUG	0x00000001
#define	MC_DETACH_DEBUG	0x00000002
#define	MC_CMD_DEBUG	0x00000004
#define	MC_REG_DEBUG	0x00000008
#define	MC_GUNUM_DEBUG	0x00000010
#define	MC_CNSTRC_DEBUG	0x00000020
#define	MC_DESTRC_DEBUG	0x00000040
#define	MC_LIST_DEBUG	0x00000080


#define	_PRINTF printf
#define	DPRINTF(flag, args)	if (mc_debug & flag) _PRINTF args;
#else
#define	DPRINTF(flag, args)

/* #endif  DEBUG */

#endif	/* !_ASM */

/* Memory Control Registers */
#define	ASI_MCU_CTRL		0x72
#define	MCREG1OFFSET		0x00

/* Mask and shift constants for Memory Control Register I */
#define	MCREG1_DIMM2_BANK3	0x8000000000000000ULL	/* bit 63 */
#define	MCREG1_DIMM1_BANK1	0x4000000000000000ULL	/* bit 62 */
#define	MCREG1_DIMM2_BANK2	0x2000000000000000ULL	/* bit 61 */
#define	MCREG1_DIMM1_BANK0	0x1000000000000000ULL	/* bit 60 */

#define	MCREG1_XOR_ENABLE	0x10000000000LL		/* bit 40 */
#define	MCREG1_ADDRGEN2_MASK	0xE000000000LL		/* bits 39:37 */
#define	MCREG1_ADDRGEN2_SHIFT	37
#define	MCREG1_ADDRGEN1_MASK	0x1C00000000LL		/* bits 36:34 */
#define	MCREG1_ADDRGEN1_SHIFT	34
#define	BASE_DEVICE_128Mb	0
#define	BASE_DEVICE_256Mb	1
#define	BASE_DEVICE_512Mb	2
#define	BASE_DEVICE_1Gb		3

#define	MCREG1_INTERLEAVE_MASK			0x1800000LL	/* bits 24:23 */
#define	MCREG1_INTERLEAVE_SHIFT			23
#define	INTERLEAVE_DISABLE			0
#define	INTERLEAVE_INTEXT_SAME_DIMM_PAIR	1
#define	INTERLEAVE_INTERNAL			2
#define	INTERLEAVE_INTEXT_BOTH_DIMM_PAIR	3

#define	MCREG1_X4DIMM2_MASK	0x200000LL		/* bit 21 */
#define	MCREG1_X4DIMM2_SHIFT	21
#define	MCREG1_X4DIMM1_MASK	0x100000LL		/* bit 20 */
#define	MCREG1_X4DIMM1_SHIFT	20
#define	PART_TYPE_X4		1
#define	PART_TYPE_X8		0

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MC_US3I_H */
