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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _AO_H
#define	_AO_H

#include <sys/types.h>
#include <sys/mc.h>
#include <sys/mca_amd.h>
#include <sys/mc_amd.h>
#include <sys/cpu_module_ms_impl.h>
#include <sys/nvpair.h>
#include <sys/cyclic.h>
#include <sys/errorq.h>
#include <sys/kobj.h>
#include <sys/fm/util.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	AO_MAX_CHIPS		8

#define	AO_MCA_MAX_ERRORS	10

typedef struct ao_ms_data ao_ms_data_t;

/*
 * Rather than using torturous conditionals, we match errors using a table of
 * ao_error_disp_t's.  The members in the ao_error_disp_t are matched against
 * the value of MCi_STATUS, with a successful match indicating that the given
 * error occurred.
 *
 * While aed_stat_code will match most of the status code bits, a few of the
 * status code fields are either/or, and are treated separately so as to
 * minimize the number of ao_error_disp_t structures that must be created.
 * For example, the dc.tag_par error can have r4 values drd or dwr.  Rather
 * than creating two ao_error_disp_t's, we use the separate aed_stat_r4_bits
 * field to indicate both AO_MCA_R4_BIT_DRD and AO_MCA_R4_BIT_DWD.  As the
 * matching r4 values are drawn from aed_stat_r4_bits, we don't use the r4
 * bits in aed_stat_code for matching.  Similar reasoning lies behind the
 * creation of the pp and ii fields.
 */
#define	AO_AED_PANIC_NEVER	0x00
#define	AO_AED_PANIC_IFMCE	0x01
#define	AO_AED_PANIC_ALWAYS	0x80

/*
 * The AO_AED_F_* flags tell us how to interpret aspects of the error
 * telemetry, such as which bits of the captured address are valid for
 * this error.
 */
					/* MCi_ADDR ... */
#define	AO_AED_F_LINEAR		0x01	/* is a linear address */
#define	AO_AED_F_PHYSICAL	0x02	/* is a physical address */
#define	AO_AED_F_PAGEALIGNED	0x04	/* aligns to page size */
#define	AO_AED_F_L2SETWAY	0x08	/* 3:0 = way, 15/14/13/12:6 = set */

#define	AO_AED_FLAGS_ADDRTYPE	(AO_AED_F_LINEAR | AO_AED_F_PHYSICAL | \
    AO_AED_F_PAGEALIGNED | AO_AED_F_L2SETWAY)

/*
 * The AO_AED_ET_* flags group individual error dispositions into
 * error types.  This is used to nominate additional telemetry beyond the
 * architectural bank registers to capture for this error type.
 */
#define	AO_AED_ET_MEMECC		0x0001	/* Main memory ECC error */

typedef struct ao_error_disp {
	const char *aed_class;		/* ereport class for use if match */
	uint64_t aed_ereport_members;	/* ereport contents flags if match */
	uint64_t aed_stat_mask;		/* status msr bits for match */
	uint64_t aed_stat_mask_res;	/* status mask result for match */
	uint16_t aed_stat_code;		/* status code for match */
	uint8_t aed_stat_extcode;	/* extended status code for match */
	uint8_t aed_stat_pp_bits:4;	/* AO_MCA_PP_BIT_* for pp matching */
	uint8_t aed_stat_ii_bits:4;	/* AO_MCA_II_BIT_* for ii matching */
	uint16_t aed_stat_r4_bits;	/* AO_MCA_R4_BIT_* for r4 matching */
	uint8_t aed_addrvalid_hi;	/* most significant valid addr bit */
	uint8_t aed_addrvalid_lo;	/* least significant valid addr bit */
	uint8_t aed_panic_when;		/* extra conditions for panic */
	uint16_t aed_flags;		/* AO_AED_F_* */
	uint16_t aed_errtype;		/* AO_AED_ET_* */
} ao_error_disp_t;

/*
 * We store non-architectutal config as inherited from the BIOS to assist
 * in troubleshooting.
 */
struct ao_bios_cfg {
	uint64_t *bcfg_bank_mask;
};

/*
 * The master data structure used to hold MCA-related state.
 */
typedef struct ao_ms_mca {
	struct ao_bios_cfg ao_mca_bios_cfg;
	kmutex_t ao_mca_poll_lock;	/* keep pollers from colliding */
	uint_t ao_mca_flags;		/* AO_MCA_F_* */
} ao_ms_mca_t;

/*
 * Per-chip shared state
 */
struct ao_chipshared {
	uint32_t aos_chiprev;
	volatile ulong_t aos_cfgonce;	/* Config performed once per chip */
	hrtime_t aos_nb_poll_timestamp;
	cmi_hdl_t aos_nb_poll_owner;
	uint64_t aos_bcfg_nb_misc;	/* BIOS value of MC4_MISC MSR */
	uint32_t aos_bcfg_nb_cfg;	/* BIOS value of NB MCA Config */
	uint32_t aos_bcfg_nb_sparectl;	/* BIOS value of Online Spare Control */
	uint32_t aos_bcfg_dcfg_lo;	/* BIOS value of DRAM Config Low */
	uint32_t aos_bcfg_dcfg_hi;	/* BIOS value of DRAM Config High */
	uint32_t aos_bcfg_scrubctl;	/* BIOS value of scrub control */
};

/* Bit numbers for once-per-chip operations policed by cms_once */
enum ao_cfgonce_bitnum {
	AO_CFGONCE_NBMCA,
	AO_CFGONCE_NBCFG,
	AO_CFGONCE_DRAMCFG
};

/*
 * Per-CPU model-specific state
 */
struct ao_ms_data {
	cmi_hdl_t ao_ms_hdl;
	ao_ms_mca_t ao_ms_mca;
	struct ao_chipshared *ao_ms_shared;
	uint64_t ao_ms_hwcr_val;
};

#ifdef _KERNEL

struct regs;

/*
 * Our cms_ops operations and function prototypes for all non-NULL members.
 */
extern const cms_ops_t _cms_ops;

extern int ao_ms_init(cmi_hdl_t, void **);
extern void ao_ms_post_startup(cmi_hdl_t);
extern void ao_ms_post_mpstartup(cmi_hdl_t);
extern uint64_t ao_ms_mcgctl_val(cmi_hdl_t, int, uint64_t);
extern boolean_t ao_ms_bankctl_skipinit(cmi_hdl_t, int);
extern uint64_t ao_ms_bankctl_val(cmi_hdl_t, int, uint64_t);
extern void ao_ms_mca_init(cmi_hdl_t, int);
extern uint64_t ao_ms_poll_ownermask(cmi_hdl_t, hrtime_t);
extern uint32_t ao_ms_error_action(cmi_hdl_t, int, int, uint64_t,
    uint64_t, uint64_t, void *);
extern cms_cookie_t ao_ms_disp_match(cmi_hdl_t, int, int, uint64_t, uint64_t,
    uint64_t, void *);
extern void ao_ms_ereport_class(cmi_hdl_t, cms_cookie_t, const char **,
    const char **);
extern boolean_t ao_ms_ereport_includestack(cmi_hdl_t, cms_cookie_t);
extern void ao_ms_ereport_add_logout(cmi_hdl_t, nvlist_t *,
    nv_alloc_t *, int, uint64_t, uint64_t, uint64_t, void *, void *);
extern cms_errno_t ao_ms_msrinject(cmi_hdl_t, uint_t, uint64_t);

/*
 * Local functions
 */
extern void ao_procnode_scrubber_enable(cmi_hdl_t, ao_ms_data_t *);
extern void ao_pcicfg_write(uint_t, uint_t, uint_t, uint32_t);
extern uint32_t ao_pcicfg_read(uint_t, uint_t, uint_t);
extern void ao_bankstatus_prewrite(cmi_hdl_t, ao_ms_data_t *);
extern void ao_bankstatus_postwrite(cmi_hdl_t, ao_ms_data_t *);

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _AO_H */
