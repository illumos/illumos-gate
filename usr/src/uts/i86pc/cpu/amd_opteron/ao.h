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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _AO_H
#define	_AO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/mc.h>
#include <sys/mca_amd.h>
#include <sys/cpu_module_impl.h>
#include <sys/nvpair.h>
#include <sys/cyclic.h>
#include <sys/errorq.h>
#include <sys/kobj.h>
#include <sys/fm/util.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	AO_MCA_MAX_ERRORS	10

typedef struct ao_data ao_data_t;

typedef struct ao_bank_regs {
	uint32_t abr_status;
	uint32_t abr_addr;
} ao_bank_regs_t;

extern ao_bank_regs_t ao_bank_regs[AMD_MCA_BANK_COUNT];

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

#define	AO_AED_F_CORRECTABLE	0x01
#define	AO_AED_F_LOFAULT_OK	0x02

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
	uint8_t aed_panic_when;		/* extra conditions for panic */
	uint8_t aed_flags;		/* AO_AED_F_* */
} ao_error_disp_t;

/*
 * The poller has two parts.  First is the omni cyclic, which runs on all
 * CPUs, and which polls the error MSRs at some fixed (long) interval.  This
 * cyclic will run on all machines, all the time, and thus must have minimal
 * runtime impact.  The second portion of the poller is manually-initiated, and
 * is used by the error injector/synthesizer to request an immediate poll of the
 * error state registers.
 *
 * With this number of moving parts, it is essential that we have some sort of
 * audit log for post-mortem analysis.  A circular array of trace buffers
 * (ao_mca_poll_trace_t structures) is kept to record this activity.  Whenever
 * an event occurs that is of interest to the poller, an entry is made in
 * the trace array describing that event.
 */
#define	AO_MPT_WHAT_CYC_ERR		0	/* cyclic-induced poll */
#define	AO_MPT_WHAT_POKE_ERR		1	/* manually-induced poll */
#define	AO_MPT_WHAT_UNFAULTING		2	/* discarded error state */

typedef struct ao_mca_poll_trace {
	hrtime_t mpt_when;		/* timestamp of event */
	uint8_t mpt_what;		/* AO_MPT_WHAT_* (which event?) */
	uint8_t mpt_nerr;		/* number of errors discovered */
	uint16_t mpt_pad1;
	uint32_t mpt_pad2;
} ao_mca_poll_trace_t;

/*
 * Processor error state is saved in logout areas.  There are three separate
 * logout areas, each used for a different purpose.  The logout areas are stored
 * in an array (ao_mca_logout), indexed by the AO_MCA_LOGOUT_* macros.
 *
 * The save areas are:
 *
 * 1. Exception handler MSR save - Written to by the initial portion of the #mc
 *    handler.  Read from by the main body of the exception handler.
 *
 * 3. Poller MSR save - Used by the poller to store error state MSR values.
 *    While this logout area doesn't necessarily have to live in the ao_mca_t,
 *    it does so to enhance observability.
 *
 * The logout areas contain both global error state (acl_ip, acl_timestamp,
 * etc.), as well as a bank array.  The bank array contains one ao_bank_logout_t
 * per error reporting bank.
 */

typedef struct ao_bank_logout {
	uint64_t abl_status;		/* Saved MCi_STATUS register */
	uint64_t abl_addr;		/* Saved MCi_ADDR register */
} ao_bank_logout_t;

#define	AO_ACL_F_PRIV		0x1	/* #mc in kernel mode (else user) */
#define	AO_ACL_F_FATAL		0x2	/* logout detected fatal error(s) */

typedef struct ao_cpu_logout {
	ao_data_t *acl_ao;		/* pointer to per-cpu ao_data_t */
	uintptr_t acl_ip;		/* instruction pointer if #mc trap */
	uint64_t acl_timestamp;		/* gethrtime() at time of logout */
	uint64_t acl_mcg_status;	/* MCG_STATUS register value */
	ao_bank_logout_t acl_banks[AMD_MCA_BANK_COUNT]; /* bank state saves */
	pc_t acl_stack[FM_STK_DEPTH];	/* saved stack trace (if any) */
	int acl_stackdepth;		/* saved stack trace depth */
	uint_t acl_flags;		/* flags (see AO_ACL_F_* above) */
} ao_cpu_logout_t;

/* Index for ao_mca_logout, below */
#define	AO_MCA_LOGOUT_EXCEPTION		0
#define	AO_MCA_LOGOUT_POLLER		1
#define	AO_MCA_LOGOUT_NUM		2

#define	AO_MCA_F_UNFAULTING		0x1	/* CPU exiting faulted state */

/*
 * We store config as inherited from the BIOS to assist in troubleshooting.
 */
typedef struct ao_bios_cfg {
	uint64_t bcfg_bank_ctl[AMD_MCA_BANK_COUNT];
	uint64_t bcfg_bank_mask[AMD_MCA_BANK_COUNT];
	uint32_t bcfg_nb_cfg;
} ao_bios_cfg_t;

/*
 * The master data structure used to hold MCA-related state.
 */
typedef struct ao_mca {
	ao_bios_cfg_t ao_mca_bios_cfg;	/* Bank and NB config before our init */
	ao_cpu_logout_t ao_mca_logout[AO_MCA_LOGOUT_NUM]; /* save areas */
	kmutex_t ao_mca_poll_lock;	/* keep pollers from colliding */
	ao_mca_poll_trace_t *ao_mca_poll_trace; /* trace buffers for this cpu */
	uint_t ao_mca_poll_curtrace;	/* most recently-filled trace buffer */
	uint_t ao_mca_flags;		/* AO_MCA_F_* */
} ao_mca_t;

/*
 * Per-CPU state
 */
struct ao_data {
	ao_mca_t ao_mca;		/* MCA state for this CPU */
	cpu_t *ao_cpu;			/* link to CPU's cpu_t */
	const cmi_mc_ops_t *ao_mc_ops;	/* memory controller ops */
	void *ao_mc_data;		/* argument for memory controller ops */
};

#ifdef _KERNEL

struct regs;

extern errorq_t *ao_mca_queue;
extern const cmi_ops_t _cmi_ops;

extern void ao_faulted_enter(void *);
extern void ao_faulted_exit(void *);
extern int ao_scrubber_enable(void *, uint64_t, uint64_t);

extern void ao_mca_post_init(void *);
extern void ao_mca_init(void *);
extern int ao_mca_trap(void *, struct regs *);
extern int ao_mca_inject(void *, cmi_mca_regs_t *, uint_t);
extern void ao_mca_poke(void *);
extern void ao_mca_poll_init(ao_mca_t *);
extern void ao_mca_poll_start(void);

extern int ao_mca_logout(ao_cpu_logout_t *, struct regs *, int *);
extern void ao_mca_drain(void *, const void *, const errorq_elem_t *);
extern nvlist_t *ao_fmri_create(ao_data_t *, nv_alloc_t *);

extern void ao_mc_register(void *, const cmi_mc_ops_t *, void *);
extern const struct cmi_mc_ops *ao_mc_getops(void *);
extern int ao_mc_patounum(ao_data_t *, uint64_t, uint32_t, int, mc_unum_t *);
extern int ao_mc_unumtopa(ao_data_t *, mc_unum_t *, nvlist_t *, uint64_t *);

extern void ao_pcicfg_write(uint_t, uint_t, uint_t, uint32_t);
extern uint32_t ao_pcicfg_read(uint_t, uint_t, uint_t);

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _AO_H */
