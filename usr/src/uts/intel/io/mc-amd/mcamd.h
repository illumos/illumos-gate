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

#ifndef _MCAMD_H
#define	_MCAMD_H

/*
 * Header file for the mc-amd AMD memory-controller driver.  This should be
 * included from that driver source alone - any more-widely useful definitions
 * belong in mc_amd.h.
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ksynch.h>
#include <sys/mc_amd.h>
#include <sys/cpu_module.h>
#include <mcamd_api.h>
#include <mcamd_err.h>
#include <mcamd_dimmcfg.h>

#ifdef __cplusplus
extern "C" {
#endif

#if	MC_CHIP_DIMMPERCS > MC_UNUM_NDIMM
#error	"MC_CHIP_DIMMPERCS exceeds MC_UNUM_NDIMM"
#endif

/*
 * The memory controller configuration registers are accessed via PCI bus 0,
 * device 0x18 + nodeid, functions 0 to 3.  The function numbers are
 * MC_FUNC_*, defined in mc_amd.h.
 *
 * We do not attach to function 3 "Miscellaneous Control" pci1022,1103
 * since the agpgart driver already attaches to that function; instead we
 * retrieve what function 3 parameters we require via direct PCI Mechanism 1
 * accesses
 *
 * The memory controller driver attaches to these device nodes, but publishes
 * a single minor node.  We need to ensure that the minor node can be
 * consistently mapped back to a single (and the same) device node, so we
 * need to pick one to be used.  We'll use the dram address map device node,
 * as it'll be the last to be attached.
 */
#define	MC_FUNC_DEVIMAP		MC_FUNC_DRAMCTL
#define	MC_FUNC_NUM		(MC_FUNC_MISCCTL + 1)

#define	MC_FUNC_HTCONFIG_BINDNM	"pci1022,1100"
#define	MC_FUNC_ADDRMAP_BINDNM	"pci1022,1101"
#define	MC_FUNC_DRAMCTL_BINDNM	"pci1022,1102"

typedef struct mc_func {
	uint_t mcf_instance;
	dev_info_t *mcf_devi;
} mc_func_t;

typedef struct mc_dimm mc_dimm_t;
typedef struct mc_cs mc_cs_t;
typedef struct mc mc_t;

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
	const mcdcfg_csl_t *mcd_csl[MC_CHIP_DIMMRANKMAX]; /* cs lines */
	mcamd_prop_t mcd_num;			/* dimm number */
	mcamd_prop_t mcd_size;			/* dimm size in bytes */
};

#define	mcd_mc mcd_hdr.mch_mc

/*
 * Chip-select properties.  If a chip-select is associated with just one
 * dimm (whether it be on the A or B dram channel) that number will be
 * in csp_dimmnums[0];  if the chip-select is associated with two dimms
 * then csp_dimmnums[0] has the dimm from channel A and csp_dimmnums[1] has
 * the partner dimm from channel B.
 */
typedef struct mccs_props {
	mcamd_prop_t csp_num;			/* Chip-select number */
	mcamd_prop_t csp_base;			/* DRAM CS Base */
	mcamd_prop_t csp_mask;			/* DRAM CS Mask */
	mcamd_prop_t csp_size;			/* Chip-select bank size */
	mcamd_prop_t csp_csbe;			/* Chip-select bank enable */
	mcamd_prop_t csp_spare;			/* Spare */
	mcamd_prop_t csp_testfail;		/* TestFail */
	mcamd_prop_t csp_dimmnums[MC_CHIP_DIMMPERCS]; /* dimm(s) in cs */
	mcamd_prop_t csp_dimmrank;		/* rank # on dimms */
} mccs_props_t;

/*
 * Chip-select config register values
 */
typedef struct mccs_cfgrefs {
	mcamd_cfgreg_t csr_csbase;		/* Raw CS base reg */
	mcamd_cfgreg_t csr_csmask;		/* Raw CS mask reg */
} mccs_cfgregs_t;

struct mc_cs {
	mc_hdr_t mccs_hdr;			/* id, pointer to parent */
	mc_cs_t *mccs_next;			/* Next chip-select of MC */
	mc_dimm_t *mccs_dimm[MC_CHIP_DIMMPERCS]; /* dimms for this cs */
	const mcdcfg_csl_t *mccs_csl[MC_CHIP_DIMMPERCS]; /* cs lines */
	mccs_props_t mccs_props;		/* Properties */
	mccs_cfgregs_t mccs_cfgregs;		/* Raw config values */
};

#define	mccs_mc	mccs_hdr.mch_mc

/*
 * Memory controller properties.
 */
typedef struct mc_props {
	mcamd_prop_t mcp_num;		/* Associated *chip* number */
	mcamd_prop_t mcp_rev;		/* Chip revision (MC_REV_*) */
	mcamd_prop_t mcp_base;		/* base address for mc's drams */
	mcamd_prop_t mcp_lim;		/* limit address for mc's drams */
	mcamd_prop_t mcp_ilen;		/* interleave enable */
	mcamd_prop_t mcp_ilsel;		/* interleave select */
	mcamd_prop_t mcp_csintlvfctr;	/* cs bank interleave factor */
	mcamd_prop_t mcp_dramhole_size;	/* DRAM Hole Size */
	mcamd_prop_t mcp_accwidth;	/* dram access width (64 or 128) */
	mcamd_prop_t mcp_csbankmapreg;	/* chip-select bank mapping reg */
	mcamd_prop_t mcp_bnkswzl;	/* BankSwizzle enabled */
	mcamd_prop_t mcp_mod64mux;	/* Mismtached DIMMs support enabled */
	mcamd_prop_t mcp_sparecs;	/* cs# replaced by online spare */
	mcamd_prop_t mcp_badcs;		/* cs# replaced by online spare */
} mc_props_t;

/*
 * Memory controller config register values
 */
typedef struct mc_cfgregs {
	mcamd_cfgreg_t mcr_htroute[MC_CHIP_MAXNODES];
	mcamd_cfgreg_t mcr_htnodeid;
	mcamd_cfgreg_t mcr_htunitid;
	mcamd_cfgreg_t mcr_drambase;
	mcamd_cfgreg_t mcr_dramlimit;
	mcamd_cfgreg_t mcr_dramhole;
	mcamd_cfgreg_t mcr_dramcfglo;
	mcamd_cfgreg_t mcr_dramcfghi;
	mcamd_cfgreg_t mcr_drammisc;
	mcamd_cfgreg_t mcr_nbcfg;
	mcamd_cfgreg_t mcr_sparectl;
	mcamd_cfgreg_t mcr_scrubctl;
	mcamd_cfgreg_t mcr_scrubaddrlo;
	mcamd_cfgreg_t mcr_scrubaddrhi;
} mc_cfgregs_t;

struct mc {
	mc_hdr_t mc_hdr;			/* id */
	struct mc *mc_next;			/* next MC instance */
	const char *mc_revname;			/* revision name string */
	uint32_t mc_socket;			/* Package type */
	uint_t mc_ref;				/* reference (attach) count */
	mc_func_t mc_funcs[MC_FUNC_NUM];	/* Instance, devinfo, ... */
	mc_cs_t *mc_cslist;			/* All active chip-selects */
	mc_cs_t *mc_cslast;			/* End of chip-select list */
	mc_dimm_t *mc_dimmlist;			/* List of all logical DIMMs, */
	mc_dimm_t *mc_dimmlast;			/* linked via mcd_mcnext */
	mc_props_t mc_props;			/* Properties */
	mc_cfgregs_t mc_cfgregs;		/* Raw config values */
	hrtime_t mc_spareswaptime;		/* If initiated by us */
	nvlist_t *mc_nvl;			/* nvlist for export */
	char *mc_snapshot;			/* packed nvlist for libmc */
	size_t mc_snapshotsz;			/* packed nvlist buffer size */
	uint_t mc_snapshotgen;			/* snapshot generation number */
	int mc_csdiscontig;			/* chip-selects discontiguous */
};

typedef struct mcamd_hdl {
	int mcamd_errno;
	int mcamd_debug;
} mcamd_hdl_t;

extern mc_t *mc_list;
extern krwlock_t mc_lock;

extern void mcamd_mkhdl(mcamd_hdl_t *);
extern void mcamd_mc_register(cmi_hdl_t, mc_t *);
extern void mcamd_ereport_post(mc_t *, const char *, mc_unum_t *, uint64_t);

/*
 * mcamd_mc_ops prototypes
 */
extern cmi_errno_t mcamd_patounum_wrap(void *, uint64_t, uint8_t, uint8_t,
    uint32_t, int, mc_unum_t *);
extern cmi_errno_t mcamd_unumtopa_wrap(void *, mc_unum_t *, nvlist_t *,
    uint64_t *);

/*
 * Internal functions
 */
cmi_errno_t mcamd_cmierr(int, mcamd_hdl_t *);

#ifdef __cplusplus
}
#endif

#endif /* _MCAMD_H */
