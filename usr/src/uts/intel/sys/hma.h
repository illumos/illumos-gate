/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2019 Joyent, Inc.
 * Copyright 2024 Oxide Computer Company
 */

#ifndef _SYS_HMA_H
#define	_SYS_HMA_H

/*
 * Hypervisor Multiplexor API
 *
 * This provides a set of APIs that are usable by hypervisor implementations
 * that allows them to coexist and to make sure that they are all in a
 * consistent state.
 */

#include <sys/fp.h>

#ifdef __cplusplus
extern "C" {
#endif


/*
 * Register a hypervisor with HMA.  On success, a pointer to the opaque
 * registration token will be returned, indicating that proper host setup has
 * occurred for further hypervisor actions.
 */
typedef struct hma_reg hma_reg_t;
extern hma_reg_t *hma_register(const char *);
extern hma_reg_t *hma_register_exclusive(const char *);
extern void hma_unregister(hma_reg_t *);

/*
 * Allocate or free a VPID for use with VMX.
 *
 * This must not be performed by a hypervisor until it has successfully
 * registered via hma_register().
 */
extern uint16_t hma_vmx_vpid_alloc(void);
extern void hma_vmx_vpid_free(uint16_t);

/*
 * On all active CPUs, perform a single-context INVEPT on the given EPTP.
 */
extern void hma_vmx_invept_allcpus(uintptr_t);

struct hma_svm_asid {
	uint64_t hsa_gen;
	uint32_t hsa_asid;
};
typedef struct hma_svm_asid hma_svm_asid_t;

extern void hma_svm_asid_init(hma_svm_asid_t *);
extern uint8_t hma_svm_asid_update(hma_svm_asid_t *, boolean_t, boolean_t);

/*
 * Disable, enable, or query the GIF on CPUs supporting SVM.
 */
extern void hma_svm_gif_disable(void);
extern void hma_svm_gif_enable(void);
extern boolean_t hma_svm_gif_is_disabled(void);

typedef enum hma_cpc_flags {
	/* Guest not using CPCs */
	HCF_DISABLED = 0,

	/* Base (0-3) CPCs usable by guest */
	HCF_EN_BASE = (1 << 0),
	/* Extended (4-5) CPCs usable by guest */
	HCF_EN_EXTD = (1 << 1),
} hma_cpc_flags_t;

#define	HMA_CPC_REGS_MAX	6

typedef struct hma_cpc {
	uint64_t hc_evtsel;
	uint64_t hc_ctr;
} hma_cpc_t;

struct hma_svm_cpc_state {
	hma_cpc_t	hscs_regs[HMA_CPC_REGS_MAX];
	hma_cpc_flags_t	hscs_flags;
};

typedef enum hma_svm_cpc_res {
	/* Base (empty) case */
	HSCR_EMPTY = 0,

	/* Direct guest access to RDPMC instruction allowed */
	HSCR_ACCESS_RDPMC = (1 << 0),
	/* Direct guest access to CPC CTR MSRs allowed */
	HSCR_ACCESS_CTR_MSR = (1 << 1),
} hma_svm_cpc_res_t;

extern hma_svm_cpc_res_t hma_svm_cpc_enter(struct hma_svm_cpc_state *);
extern void hma_svm_cpc_exit(struct hma_svm_cpc_state *);

/*
 * FPU related management. These functions provide a set of APIs to manage the
 * FPU state and switch between host and guest management of this state.
 */

typedef struct hma_fpu hma_fpu_t;

/*
 * Allocate and free FPU state management structures.
 */
extern hma_fpu_t *hma_fpu_alloc(int);
extern void hma_fpu_free(hma_fpu_t *);

/*
 * Resets the FPU to the standard x86 default state. This should be called after
 * allocation and whenever the guest needs to logically reset the state (when
 * the CPU is reset, etc.). If the system supports xsave, then the xbv state
 * will be set to have the x87 and SSE portions as valid and the rest will be
 * set to their initial states (regardless of whether or not they will be
 * advertised in the host).
 */
extern int hma_fpu_init(hma_fpu_t *);

/*
 * Save the current host's FPU state and restore the guest's state in the FPU.
 * At this point, CR0.TS will not be set. The caller must not use the FPU in any
 * way before entering the guest.
 *
 * This should be used in normal operation before entering the guest. It should
 * also be used in a thread context operation when the thread is being scheduled
 * again. This interface has an implicit assumption that a given guest state
 * will be mapped to only one specific OS thread at any given time.
 *
 * This must be called with preemption disabled.
 */
extern void hma_fpu_start_guest(hma_fpu_t *);

/*
 * Save the current guest's FPU state and restore the host's state in the FPU.
 * By the time the thread returns to userland, the FPU will be in a usable
 * state; however, the FPU will not be usable while inside the kernel (CR0.TS
 * will be set).
 *
 * This should be used in normal operation after leaving the guest and returning
 * to user land. It should also be used in a thread context operation when the
 * thread is being descheduled. Like the hma_fpu_start_guest() interface, this
 * interface has an implicit assumption that a given guest state will be mapped
 * to only a single OS thread at any given time.
 *
 * This must be called with preemption disabled.
 */
extern void hma_fpu_stop_guest(hma_fpu_t *);

typedef enum {
	HFXR_OK = 0,
	HFXR_NO_SPACE,		/* buffer is not large enough */
	HFXR_BAD_ALIGN,		/* buffer is not properly (64-byte) aligned */
	HFXR_UNSUP_FMT,		/* data using unsupported (compressed) format */
	HFXR_UNSUP_FEAT,	/* data has unsupported features set */
	HFXR_INVALID_DATA,	/* CPU determined xsave data is invalid */
} hma_fpu_xsave_result_t;

/*
 * Get and set the contents of the FPU save area, formatted as XSAVE-style
 * information.  If XSAVE is not supported by the host, the input and output
 * values will be translated to and from the FXSAVE format.  Attempts to set
 * XSAVE values not supported by the host will result in an error.
 *
 * These functions cannot be called while the FPU is in use by the guest. It is
 * up to callers to guarantee this invariant.
 */
extern hma_fpu_xsave_result_t hma_fpu_get_xsave_state(const hma_fpu_t *, void *,
    size_t);
extern hma_fpu_xsave_result_t hma_fpu_set_xsave_state(hma_fpu_t *, void *,
    size_t);

typedef struct hma_xsave_state_desc {
	uint64_t	hxsd_bit;
	uint32_t	hxsd_size;
	uint32_t	hxsd_off;
} hma_xsave_state_desc_t;

/*
 * Get a description of the data fields supported by the host via the XSAVE APIs
 * for getting/setting guest FPU data.  See the function definition for more
 * detailed parameter usage.
 */
extern uint_t hma_fpu_describe_xsave_state(hma_xsave_state_desc_t *, uint_t,
    size_t *);

/*
 * Get and set the contents of the FPU save area. This sets the fxsave style
 * information. In all cases when this is in use, if an XSAVE state is actually
 * used by the host, then this will end up zeroing all of the non-fxsave state
 * and it will reset the xbv to indicate that the legacy x87 and SSE portions
 * are valid.
 *
 * These functions cannot be called while the FPU is in use by the guest. It is
 * up to callers to guarantee this fact.
 */
extern void hma_fpu_get_fxsave_state(const hma_fpu_t *, struct fxsave_state *);
extern int hma_fpu_set_fxsave_state(hma_fpu_t *, const struct fxsave_state *);

/* Perform HMA initialization steps during boot-up. */
extern void hma_init(void);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_HMA_H */
