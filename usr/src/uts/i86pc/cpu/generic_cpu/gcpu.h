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
 * Copyright (c) 2018, Joyent, Inc.
 */

#ifndef _GCPU_H
#define	_GCPU_H

#include <sys/types.h>
#include <sys/cpu_module_impl.h>
#include <sys/cpu_module_ms.h>
#include <sys/ksynch.h>
#include <sys/systm.h>
#include <sys/fm/util.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	GCPU_MCA_ERRS_PERCPU	10	/* errorq slots per cpu */
#define	GCPU_MCA_MIN_ERRORS	30	/* minimum total errorq slots */
#define	GCPU_MCA_MAX_ERRORS	100	/* maximum total errorq slots */

typedef struct gcpu_data gcpu_data_t;

#define	GCPU_ERRCODE_MASK_ALL		0xffff

typedef struct gcpu_error_disp {
	const char *ged_class_fmt;	/* ereport class formatter (last bit) */
	const char *ged_compound_fmt;	/* compound error formatter */
	uint64_t ged_ereport_members;	/* ereport payload members */
	uint16_t ged_errcode_mask_on;	/* errcode bits that must be set ... */
	uint16_t ged_errcode_mask_off;	/* ... and must be clear for a match */
} gcpu_error_disp_t;

/*
 * For errorq_dispatch we need to have a single contiguous structure
 * capturing all our logout data.  We do not know in advance how many
 * error detector banks there are in this cpu model, so we'll manually
 * allocate additional space for the gcl_banks array below.
 */
typedef struct gcpu_bank_logout {
	uint64_t gbl_status;		/* MCi_STATUS value */
	uint64_t gbl_addr;		/* MCi_ADDR value */
	uint64_t gbl_misc;		/* MCi_MISC value */
	uint64_t gbl_disp;		/* Error disposition for this bank */
	uint32_t gbl_clrdefcnt;		/* Count of deferred status clears */
} gcpu_bank_logout_t;

/*
 * The data structure we "logout" all error telemetry from all banks of
 * a cpu to.  The gcl_data array declared with 1 member below will actually
 * have gcl_nbanks members - variable with the actual cpu model present.
 * After the gcl_data array there is a further model-specific array that
 * may be allocated, and gcl_ms_logout will point to that if present.
 * This cpu logout data must form one contiguous chunk of memory for
 * dispatch with errorq_dispatch.
 */
typedef struct gcpu_logout {
	gcpu_data_t *gcl_gcpu;		/* pointer to per-cpu gcpu_data_t */
	uintptr_t gcl_ip;		/* instruction pointer from #mc trap */
	uint64_t gcl_timestamp;		/* gethrtime() at logout */
	uint64_t gcl_mcg_status;	/* MCG_STATUS register value */
	uint64_t gcl_flags;		/* Flags */
	pc_t gcl_stack[FM_STK_DEPTH];	/* saved stack trace, if any */
	int gcl_stackdepth;		/* saved stack trace depth */
	int ismc;			/* is a machine check flag */
	int gcl_nbanks;			/* number of banks in array below */
	void *gcl_ms_logout;		/* Model-specific area after gcl_data */
	gcpu_bank_logout_t gcl_data[1];	/* Bank logout areas - must be last */
} gcpu_logout_t;

/*
 * gcl_flag values
 */
#define	GCPU_GCL_F_PRIV		0x1	/* #MC during privileged code */
#define	GCPU_GCL_F_TES_P	0x2	/* MCG_CAP indicates TES_P */

struct gcpu_bios_bankcfg {
	uint64_t bios_bank_ctl;
	uint64_t bios_bank_status;
	uint64_t bios_bank_addr;
	uint64_t bios_bank_misc;
};

struct gcpu_bios_cfg {
	uint64_t bios_mcg_cap;
	uint64_t bios_mcg_ctl;
	struct gcpu_bios_bankcfg *bios_bankcfg;
};

/*
 * Events types in poll trace records.  Keep these in sync with
 * the generic cpu mdb module names for each (see gcpu_mpt_dump in mdb).
 */
#define	GCPU_MPT_WHAT_CYC_ERR		0	/* cyclic-induced poll */
#define	GCPU_MPT_WHAT_POKE_ERR		1	/* manually-induced poll */
#define	GCPU_MPT_WHAT_UNFAULTING	2	/* discarded error state */
#define	GCPU_MPT_WHAT_MC_ERR		3	/* MC# */
#define	GCPU_MPT_WHAT_CMCI_ERR		4	/* CMCI interrupt */
#define	GCPU_MPT_WHAT_XPV_VIRQ		5	/* MCA_VIRQ in dom0 */
#define	GCPU_MPT_WHAT_XPV_VIRQ_LOGOUT	6	/* MCA_VIRQ logout complete */

typedef struct gcpu_poll_trace {
	hrtime_t mpt_when;		/* timestamp of event */
	uint8_t mpt_what;		/* GCPU_MPT_WHAT_* (which event?) */
	uint8_t mpt_nerr;		/* number of errors discovered */
	uint16_t mpt_pad1;
	uint32_t mpt_pad2;
} gcpu_poll_trace_t;

typedef struct gcpu_poll_trace_ctl {
	gcpu_poll_trace_t *mptc_tbufs;	/* trace buffers */
	uint_t mptc_curtrace;			/* last buffer filled */
} gcpu_poll_trace_ctl_t;


/*
 * For counting some of the important number or time for runtime
 * cmci enable/disable
 */
typedef struct gcpu_mca_cmci {
	uint32_t cmci_cap;	/* cmci capability for this bank */
	uint32_t ncmci;		/* number of correctable errors between polls */
	uint32_t drtcmci;	/* duration of no cmci when cmci is disabled */
	uint32_t cmci_enabled;	/* cmci enable/disable status for this bank */
} gcpu_mca_cmci_t;

/* Index for gcpu_mca_logout array below */
#define	GCPU_MCA_LOGOUT_EXCEPTION	0	/* area for #MC */
#define	GCPU_MCA_LOGOUT_POLLER_1	1	/* next/prev poll area */
#define	GCPU_MCA_LOGOUT_POLLER_2	2	/* prev/next poll area */
#define	GCPU_MCA_LOGOUT_NUM		3

typedef struct gcpu_mca {
	gcpu_logout_t *gcpu_mca_logout[GCPU_MCA_LOGOUT_NUM];
	uint32_t gcpu_mca_nextpoll_idx;	/* logout area for next poll */
	struct gcpu_bios_cfg gcpu_mca_bioscfg;
	uint_t gcpu_mca_nbanks;
	size_t gcpu_mca_lgsz;		/* size of gcpu_mca_logout structs */
	uint_t gcpu_mca_flags;		/* GCPU_MCA_F_* */
	hrtime_t gcpu_mca_lastpoll;
	gcpu_poll_trace_ctl_t gcpu_polltrace;
	uint32_t gcpu_mca_first_poll_cmci_enabled; /* cmci on in first poll */
	gcpu_mca_cmci_t *gcpu_bank_cmci;
} gcpu_mca_t;

typedef struct gcpu_mce_status {
	uint_t mce_nerr;	/* total errors found in logout of all banks */
	uint64_t mce_disp;	/* Disposition information */
	uint_t mce_npcc;	/* number of errors with PCC */
	uint_t mce_npcc_ok;	/* PCC with CMS_ERRSCOPE_CURCONTEXT_OK */
	uint_t mce_nuc;		/* number of errors with UC */
	uint_t mce_nuc_ok;	/* UC with CMS_ERRSCOPE_CLEARED_UC */
	uint_t mce_nuc_poisoned; /* UC with CMS_ERRSCOPE_POISONED */
	uint_t mce_forcefatal;	/* CMS_ERRSCOPE_FORCE_FATAL */
	uint_t mce_ignored;	/* CMS_ERRSCOPE_IGNORE_ERR */
} gcpu_mce_status_t;

/*
 * Flags for gcpu_mca_flags
 */
#define	GCPU_MCA_F_UNFAULTING		0x1	/* CPU exiting faulted state */
#define	GCPU_MCA_F_CMCI_CAPABLE		0x2	/* CPU supports CMCI */
#define	GCPU_MCA_F_CMCI_ENABLE		0x4	/* CPU CMCI enabled */

/*
 * State shared by all cpus on a chip
 */
struct gcpu_chipshared {
	kmutex_t gcpus_cfglock;		/* serial MCA config from chip cores */
	kmutex_t gcpus_poll_lock;	/* serialize pollers on the same chip */
	uint32_t gcpus_actv_banks;	/* MCA bank numbers active on chip */
	volatile uint32_t gcpus_actv_cnt; /* active cpu count in this chip */
	char *gcpus_ident;		/* ident string, if available */
};

struct gcpu_data {
	gcpu_mca_t gcpu_mca;			/* MCA state for this CPU */
	cmi_hdl_t gcpu_hdl;			/* associated handle */
	struct gcpu_chipshared *gcpu_shared;	/* Shared state for the chip */
};

#ifdef _KERNEL

struct regs;

/*
 * CMI implementation
 */
extern int gcpu_init(cmi_hdl_t, void **);
extern void gcpu_fini(cmi_hdl_t);
extern void gcpu_post_startup(cmi_hdl_t);
extern void gcpu_post_mpstartup(cmi_hdl_t);
extern void gcpu_faulted_enter(cmi_hdl_t);
extern void gcpu_faulted_exit(cmi_hdl_t);
extern void gcpu_mca_init(cmi_hdl_t);
extern void gcpu_mca_fini(cmi_hdl_t);
extern void gcpu_mca_cmci_enable(cmi_hdl_t);
extern cmi_errno_t gcpu_msrinject(cmi_hdl_t, cmi_mca_regs_t *, uint_t, int);
#ifndef __xpv
extern uint64_t gcpu_mca_trap(cmi_hdl_t, struct regs *);
extern void gcpu_cmci_trap(cmi_hdl_t);
extern void gcpu_hdl_poke(cmi_hdl_t);
#else
extern void gcpu_xpv_panic_callback(void);
#endif

/*
 * Local functions
 */
extern void gcpu_mca_poll_init(cmi_hdl_t);
extern void gcpu_mca_poll_fini(cmi_hdl_t);
extern void gcpu_mca_poll_start(cmi_hdl_t);
extern void gcpu_poll_trace_init(gcpu_poll_trace_ctl_t *);
extern void gcpu_poll_trace(gcpu_poll_trace_ctl_t *, uint8_t, uint8_t);
extern void gcpu_mca_logout(cmi_hdl_t, struct regs *, uint64_t,
    gcpu_mce_status_t *, boolean_t, int);
#ifdef __xpv
extern void gcpu_xpv_mca_init(int);
#endif /* __xpv */

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _GCPU_H */
