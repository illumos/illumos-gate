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

#ifndef	_SYS_MC_US3_H
#define	_SYS_MC_US3_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(_KERNEL)

#define	NBANKS	4
#define	NDGRPS	2
#define	NDIMMS	4
#define	MAX_DEVLEN	8
#define	TRANSFER_SIZE	64

#ifndef	_ASM

struct mc_soft_state {
	dev_info_t *dip;	/* dev info of myself */
	int portid;
	int size;
	void *memlayoutp;
	volatile uchar_t *mc_base; /* Mapped base address of MC registers */
};

struct dimm_info {
	char	label[NDGRPS * NDIMMS][MAX_DEVLEN];	/* dimm label */
	char	sym_flag;	/* 1: symmetric 0: asymmetric */
	char	data[1];
};

typedef char dimm_sid_t[DIMM_SERIAL_ID_LEN];

struct pin_info {
	uchar_t	dimmtable[144];
	uchar_t	pintable[576];
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
	struct bank_info *hb_inseg;	/* first bank at this segment */
	struct bank_info *tb_inseg;	/* last bank at this segment */
};

/* id = mc_id * nbanks + bank_no */
struct bank_info {
	mc_dlist_t bank_node;
	int local_id;		/* unique local bank id per segment */
	int seg_id;		/* unique segment id */
	int devgrp_id;		/* unique device group id */
	ushort_t valid;		/* valid flag per logic bank */
	ushort_t uk;		/* Upper Mask field to mask match 4 PA[37:26] */
	uint_t um;		/* Upper Match field to match PA[42:26] */
	uchar_t lk;		/* Lower Mask field to mask match 4 PA[9:6] */
	uchar_t lm;		/* Lower Match field to match PA[9:6] */
	uchar_t pos;		/* front=0, back=1 */
	uint64_t size;		/* memory size per logical bank */
	struct bank_info *n_inseg; /* next bank at the same segment */
	struct bank_info *p_inseg; /* previous bank at the same segment */
	struct dimm_info *dimminfop;
	dimm_sid_t *dimmsidp[NDIMMS];
};

/* id = mc_id * ndevgrps + devgrp_no */
struct dgrp_info {
	mc_dlist_t dgrp_node;
	int ndevices;	/* The number of available devices on this dev group */
	uint64_t size;	/* memory size per physical dimm group */
	int deviceids[NDIMMS];	/* 4 dimms per group on excalibur */
};

/* id = id of dgrp_info * ndevices + device_no */
struct device_info {
	mc_dlist_t dev_node;
	char label[MAX_DEVLEN];
	uint64_t size;		/* memory size per physical dimm */
};

/* id = portid */
struct mctrl_info {
	mc_dlist_t mctrl_node;
	int ndevgrps;		/* The number of dimm groups */
	int devgrpids[NDGRPS];
};

typedef struct dimm_sid_cache {
	int	mcid;	/* mc portid */
	int	seg_id;	/* segment these DIMMs are in */
	int	state;	/* state of cache for this mc */
	dimm_sid_t	*sids;  /* ptr to array of serial ids */
} dimm_sid_cache_t;

/* values for the state field of a dimm_sid_cache_t */
#define	MC_DIMM_SIDS_INVALID	0
#define	MC_DIMM_SIDS_REQUESTED	1
#define	MC_DIMM_SIDS_AVAILABLE	2

extern int (*p2get_mem_unum)(int, uint64_t, char *, int, int *);
extern int (*p2get_mem_info)(int, uint64_t, uint64_t *, uint64_t *,
    uint64_t *, int *, int *, int *);
extern int (*p2get_mem_offset)(uint64_t, uint64_t *);
extern int (*p2get_mem_addr)(int, char *, uint64_t, uint64_t *);
extern int (*p2get_mem_sid)(int, int, char *, int, int *);
extern int (*p2init_sid_cache)(void);
extern void plat_add_mem_unum_label(char *, int, int, int);
extern dimm_sid_cache_t *plat_alloc_sid_cache(int *);
extern int plat_populate_sid_cache(dimm_sid_cache_t *, int);

uint64_t get_mcr(int);

#ifdef	DEBUG

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

static uint_t mc_debug = 0;

#define	_PRINTF prom_printf
#define	DPRINTF(flag, args)	if (mc_debug & flag) _PRINTF args;
#else
#define	DPRINTF(flag, args)

#endif /* DEBUG */

#endif	/* !_ASM */

/* Memory Address Decoding Registers */
#define	ASI_MCU_CTRL	0x72
#define	REGOFFSET	8
#define	MADR0OFFSET	0x10

/* Mask and shift constants for Memory Address Decoding */
#define	MADR_UPA_MASK	0x7fffc000000LL		/* 17 bits */
#define	MADR_LPA_MASK	0x000000003c0LL		/* 4 bits */
#define	MADR_LK_MASK	0x0000003c000LL		/* 4 bits */

#define	MADR_UPA_SHIFT	26
#define	MADR_LPA_SHIFT	6
#define	MADR_LK_SHIFT	14

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MC_US3_H */
