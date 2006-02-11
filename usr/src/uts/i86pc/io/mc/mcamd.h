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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _MCAMD_H
#define	_MCAMD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/chip.h>
#include <sys/ksynch.h>
#include <sys/mc_amd.h>
#include <mcamd_api.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * PCI configuration space functions for the memory controller.  Note that
 * the function numbers here also serve as the mc_func indices in the mc_t.
 */
#define	MC_FUNC_HTCONFIG	0		/* unused */
#define	MC_FUNC_HTCONFIG_BINDNM	"pci1022,1100"	/* unused */
#define	MC_FUNC_ADDRMAP		1
#define	MC_FUNC_ADDRMAP_BINDNM	"pci1022,1101"
#define	MC_FUNC_DRAMCTL		2
#define	MC_FUNC_DRAMCTL_BINDNM	"pci1022,1102"

/*
 * The memory controller driver attaches to several device nodes, but publishes
 * a single minor node.  We need to ensure that the minor node can be
 * consistently mapped back to a single (and the same) device node, so we need
 * to pick one to be used.  We'll use the DRAM Controller device node, as it'll
 * be the last to be attached.
 */
#define	MC_FUNC_DEVIMAP		MC_FUNC_DRAMCTL

#define	MC_FUNC_NUM		3

/*
 * The following define the offsets at which various MC registers are
 * accessed in PCI config space.  For defines describing the register
 * structure see mc_amd.h.
 */

/*
 * BKDG 3.29 section 3.4 - MC DRAM base and limit addresses, hole offset.
 */
#define	MC_AM_REG_NODE_NUM	8	/* Number of DRAM nodes */
#define	MC_AM_REG_DRAMBASE_0	0x40	/* Offset for DRAM Base 0 */
#define	MC_AM_REG_DRAMLIM_0	0x44	/* Offset for DRAM Limit 0 */
#define	MC_AM_REG_DRAM_INCR	8	/* incr between base/limit pairs */
#define	MC_AM_REG_HOLEADDR	0xf0	/* DRAM Hole Address Register */

/*
 * BKDG 3.29 section 3.5 - DRAM contoller chip-select base, mask,
 * DRAM bank address mapping, DRAM configuration.
 */
#define	MC_DC_REG_CS_INCR	4	/* incr for CS base and mask */
#define	MC_DC_REG_CSBASE_0	0x40	/* 0x40 - 0x5c */
#define	MC_DC_REG_CSMASK_0	0x60	/* 0x60 - 0x7c */
#define	MC_DC_REG_BANKADDRMAP	0x80
#define	MC_DC_REG_DRAMCFGLO	0x90
#define	MC_DC_REG_DRAMCFGHI	0x94

typedef struct mc_func {
	uint_t mcf_instance;
	dev_info_t *mcf_devi;
} mc_func_t;

typedef struct mc_dimm mc_dimm_t;
typedef struct mc_cs mc_cs_t;
typedef struct mc mc_t;

typedef uint64_t mc_prop_t;			/* see mcamd_get_numprop */

/*
 * Node types for mch_type below.  These are used in array indexing.
 */
#define	MC_NT_MC		0
#define	MC_NT_CS		1
#define	MC_NT_DIMM		2
#define	MC_NT_NTYPES		3

typedef struct mc_hdr {
	uint_t mch_type;
	union {
		mc_t *_mch_mc;
		mc_cs_t *_mch_cs;
	} _mch_ptr;
} mc_hdr_t;

#define	mch_mc		_mch_ptr._mch_mc

struct mc_dimm {
	mc_hdr_t mcd_hdr;			/* id, pointer to parent */
	mc_dimm_t *mcd_next;			/* next dimm for this MC */
	mc_cs_t *mcd_cs[MC_CHIP_DIMMRANKMAX];	/* associated chip-selects */
	mc_prop_t mcd_num;			/* dimm number */
};

#define	mcd_mc mcd_hdr.mch_mc

struct mc_cs {
	mc_hdr_t mccs_hdr;			/* id, pointer to parent */
	mc_cs_t *mccs_next;			/* Next chip-select of MC */
	mc_dimm_t *mccs_dimm[MC_CHIP_DIMMPERCS]; /* dimms for this cs */
	mc_prop_t mccs_num;			/* Chip-select number */
	mc_prop_t mccs_base;			/* DRAM CS Base */
	mc_prop_t mccs_mask;			/* DRAM CS Mask */
	mc_prop_t mccs_size;			/* Chip-select bank size */
	mc_prop_t mccs_dimmnums[MC_CHIP_DIMMPERCS];
};

#define	mccs_mc	mccs_hdr.mch_mc

typedef struct mc_props {
	mc_dimm_t *mcp_dimmlist;	/* List of all logical DIMMs, */
	mc_dimm_t *mcp_dimmlast;	/* linked via mcd_mcnext */
	mc_prop_t mcp_num;		/* Associated *chip* number */
	mc_prop_t mcp_rev;		/* Chip revision (MC_REV_*) */
	mc_prop_t mcp_base;		/* base address for mc's drams */
	mc_prop_t mcp_lim;		/* limit address for mc's drams */
	mc_prop_t mcp_dramcfg;		/* DRAM config hi, DRAM config lo */
	mc_prop_t mcp_dramhole;		/* DRAM Hole Address Register */
	mc_prop_t mcp_ilen;		/* interleave enable */
	mc_prop_t mcp_ilsel;		/* interleave select */
	mc_prop_t mcp_csbankmap;	/* chip-select bank mapping reg */
	mc_prop_t mcp_accwidth;		/* dram access width (64 or 128) */
	mc_prop_t mcp_csbank_intlv;	/* cs bank interleave factor */
	mc_prop_t mcp_disabled_cs;	/* # banks with CSBE clear */
} mc_props_t;

struct mc {
	mc_hdr_t mc_hdr;			/* id */
	struct mc *mc_next;			/* linear, doubly-linked list */
	const char *mc_revname;			/* revision name string */
	uint_t mc_ref;				/* reference (attach) count */
	mc_func_t mc_funcs[MC_FUNC_NUM];	/* Instance, devinfo, ... */
	chip_t *mc_chip;			/* Associated chip */
	mc_cs_t *mc_cslist;			/* All active chip-selects */
	mc_cs_t *mc_cslast;			/* End of chip-select list */
	mc_props_t mc_props;			/* Properties */
	nvlist_t *mc_nvl;			/* nvlist for export */
	char *mc_snapshot;			/* packed nvlist for libmc */
	size_t mc_snapshotsz;			/* packed nvlist buffer size */
	uint_t mc_snapshotgen;			/* snapshot generation number */
};

typedef struct mcamd_hdl {
	int mcamd_errno;
	int mcamd_debug;
} mcamd_hdl_t;

extern mc_t *mc_list;
extern krwlock_t mc_lock;

extern void mcamd_mkhdl(mcamd_hdl_t *);
extern void mcamd_mc_register(struct cpu *);

#ifdef __cplusplus
}
#endif

#endif /* _MCAMD_H */
