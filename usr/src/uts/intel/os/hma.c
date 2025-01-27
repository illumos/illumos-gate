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
 * Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
 * Copyright 2024 Oxide Computer Company
 */

#include <sys/cpuvar.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/machsystm.h>
#include <sys/archsystm.h>
#include <sys/controlregs.h>
#include <sys/x86_archext.h>
#include <sys/id_space.h>
#include <sys/hma.h>
#include <sys/cmn_err.h>
#include <vm/hat.h>
#include <vm/as.h>

struct hma_reg {
	const char	*hr_name;
	list_node_t	hr_node;
};

static kmutex_t hma_lock;
static list_t hma_registrations;
static boolean_t hma_exclusive = B_FALSE;
int hma_disable = 0;

typedef enum hma_cpu_status {
	HCS_UNINITIALIZED = 0,
	HCS_READY,
	HCS_ERROR
} hma_cpu_status_t;

/*
 * When both host and guest want simultaneous use of the CPU performance
 * counters, which should take priority?
 *
 * Defer to the guest by default, making its activity invisible to
 * host-configured CPC measurements.  This is necessary since the Capacity &
 * Utilization system keeps the CPCs active at all times when not in use by
 * libcpc or dtrace users.
 */
typedef enum hma_cpc_priority {
	HCP_HOST_WINS = 0,
	HCP_GUEST_WINS = 1,
} hma_cpc_priority_t;
static hma_cpc_priority_t hma_cpc_priority = HCP_GUEST_WINS;

/*
 * VMX-specific per-CPU data
 */
typedef struct hma_vmx_cpu {
	void		*hvc_vmxon_page;
	uintptr_t	hvc_vmxon_pa;

} hma_vmx_cpu_t;

/*
 * SVM-specific per-CPU data
 */
typedef struct hma_svm_cpu {
	void		*hsc_hsave_page;
	uintptr_t	hsc_hsave_pa;
	hma_svm_asid_t	hsc_asid;
	uint_t		hsc_gif_disabled;
	/*
	 * hsc_cpc_saved_flags stores the state of guest performance counters
	 * while inside the hma_svm_cpc_enter/hma_svm_cpc_exit critical section.
	 *
	 * If, due to the state of host counters, requested guest counters, and
	 * hma_cpc_priority, the guest counters are _not_ loaded during
	 * hma_svm_cpc_enter(), then this field will hold HCF_DISABLED,
	 * indicating that no state restoration is required during
	 * hma_svm_cpc_exit().
	 *
	 * When hsc_cpc_saved_flags is not HCF_DISABLED, then hsc_cpc_host_regs
	 * will hold the saved host CPC state while the guest state occupies
	 * those registers in the CPU.
	 */
	hma_cpc_flags_t	hsc_cpc_saved_flags;
	hma_cpc_t	hsc_cpc_host_regs[6];
} hma_svm_cpu_t;

/*
 * Combined per-CPU state data
 *
 * The bulk of HMA state (VMX & SVM) is protected by cpu_lock, rather than a
 * mutex specific to the module.  It (cpu_lock) is already required for the
 * state needed to perform setup on all CPUs, so it was a natural fit to
 * protect this data too.
 */
struct hma_cpu {
	union {
		struct hma_vmx_cpu vmx;
		struct hma_svm_cpu svm;
	} hc_u;
	hma_cpu_status_t	hc_status;
	uintptr_t		_hc_padding[6];
} hma_cpu[NCPU];

/* Keep per-CPU state aligned to cache line size to avoid false sharing */
CTASSERT(sizeof (struct hma_cpu) % _CACHE_LINE_SIZE == 0);


static boolean_t hma_vmx_ready = B_FALSE;
static const char *hma_vmx_error = NULL;
static id_space_t *hma_vmx_vpid;

/* HMA-internal tracking of optional VMX capabilities */
typedef enum {
	HVC_EPT		= (1 << 0),
	HVC_VPID	= (1 << 1),
	HVC_INVEPT_ONE	= (1 << 2),
	HVC_INVEPT_ALL	= (1 << 3),
} hma_vmx_capab_t;

static uint32_t hma_vmx_revision;
static hma_vmx_capab_t hma_vmx_capabs = 0;

static boolean_t hma_svm_ready = B_FALSE;
static const char *hma_svm_error = NULL;
static uint32_t hma_svm_features;
static uint32_t hma_svm_max_asid;
static hma_cpc_flags_t hma_svm_cpc_allowed = HCF_DISABLED;

static int hma_vmx_init(void);
static int hma_svm_init(void);

/* Helpers from ml/hma_asm.s */
int hma_vmx_do_invept(int, uintptr_t);
int hma_vmx_vmxon(uintptr_t);

void
hma_init(void)
{
	mutex_init(&hma_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&hma_registrations, sizeof (struct hma_reg),
	    offsetof(struct hma_reg, hr_node));

	if (hma_disable != 0) {
		cmn_err(CE_CONT, "?hma_init: disabled");
		return;
	}

	switch (cpuid_getvendor(CPU)) {
	case X86_VENDOR_Intel:
		(void) hma_vmx_init();
		break;
	case X86_VENDOR_AMD:
	case X86_VENDOR_HYGON:
		(void) hma_svm_init();
		break;
	default:
		break;
	}
}

static hma_reg_t *
hma_register_backend(const char *name)
{
	struct hma_reg *reg;
	boolean_t is_ready;

	ASSERT(MUTEX_HELD(&hma_lock));

	switch (cpuid_getvendor(CPU)) {
	case X86_VENDOR_Intel:
		is_ready = hma_vmx_ready;
		break;
	case X86_VENDOR_AMD:
	case X86_VENDOR_HYGON:
		is_ready = hma_svm_ready;
		break;
	default:
		is_ready = B_FALSE;
		break;
	}

	if (!is_ready)
		return (NULL);

	reg = kmem_zalloc(sizeof (*reg), KM_SLEEP);
	reg->hr_name = name;
	list_insert_tail(&hma_registrations, reg);

	return (reg);
}

hma_reg_t *
hma_register(const char *name)
{
	struct hma_reg *reg = NULL;

	VERIFY(name != NULL);

	mutex_enter(&hma_lock);

	if (!hma_exclusive)
		reg = hma_register_backend(name);

	mutex_exit(&hma_lock);

	return (reg);
}

hma_reg_t *
hma_register_exclusive(const char *name)
{
	struct hma_reg *reg = NULL;

	VERIFY(name != NULL);

	mutex_enter(&hma_lock);

	if (list_is_empty(&hma_registrations)) {
		reg = hma_register_backend(name);
		if (reg != NULL)
			hma_exclusive = B_TRUE;
	}

	mutex_exit(&hma_lock);

	return (reg);
}

void
hma_unregister(hma_reg_t *reg)
{
	VERIFY(reg != NULL);
	VERIFY(!list_is_empty(&hma_registrations));

	mutex_enter(&hma_lock);
	list_remove(&hma_registrations, reg);
	if (hma_exclusive && list_is_empty(&hma_registrations))
		hma_exclusive = B_FALSE;
	mutex_exit(&hma_lock);
	kmem_free(reg, sizeof (*reg));
}

static __inline hma_vmx_cpu_t *
hma_vmx_cpu(processorid_t id)
{
	return (&hma_cpu[id].hc_u.vmx);
}

static __inline hma_svm_cpu_t *
hma_svm_cpu(processorid_t id)
{
	return (&hma_cpu[id].hc_u.svm);
}

/*
 * VPID 0 is reserved for instances where VPID is disabled.  Some hypervisors
 * (read: bhyve) reserve lower-order VPIDs for use in fallback behavior if
 * unique VPIDs could not be allocated for all the vCPUs belonging to a VM.
 */
#define	HMA_VPID_RESERVED	NCPU

uint16_t
hma_vmx_vpid_alloc(void)
{
	id_t res;

	/* Do not bother if the CPU lacks support */
	if ((hma_vmx_capabs & HVC_VPID) == 0) {
		return (0);
	}

	res = id_alloc_nosleep(hma_vmx_vpid);
	if (res == -1) {
		return (0);
	} else {
		ASSERT(res > HMA_VPID_RESERVED && res <= UINT16_MAX);
		return (res);
	}
}

void
hma_vmx_vpid_free(uint16_t vpid)
{
	VERIFY(vpid > HMA_VPID_RESERVED);
	id_free(hma_vmx_vpid, (id_t)vpid);
}

#define	INVEPT_SINGLE_CONTEXT	1
#define	INVEPT_ALL_CONTEXTS	2

static int
hma_vmx_invept_xcall(xc_arg_t arg1, xc_arg_t arg2, xc_arg_t arg3 __unused)
{
	int flag = (int)arg1;
	uintptr_t eptp = (uintptr_t)arg2;

	ASSERT(flag == INVEPT_SINGLE_CONTEXT || flag == INVEPT_ALL_CONTEXTS);

	VERIFY0(hma_vmx_do_invept(flag, eptp));
	return (0);
}

void
hma_vmx_invept_allcpus(uintptr_t eptp)
{
	int flag = -1;
	cpuset_t set;

	if ((hma_vmx_capabs & HVC_INVEPT_ONE) != 0) {
		flag = INVEPT_SINGLE_CONTEXT;
	} else if ((hma_vmx_capabs & HVC_INVEPT_ALL) != 0) {
		flag = INVEPT_ALL_CONTEXTS;
		eptp = 0;
	} else {
		return;
	}

	cpuset_zero(&set);
	mutex_enter(&cpu_lock);

	cpuset_or(&set, &cpu_active_set);
	xc_call((xc_arg_t)flag, (xc_arg_t)eptp, 0, CPUSET2BV(set),
	    hma_vmx_invept_xcall);

	mutex_exit(&cpu_lock);
}

static int
hma_vmx_cpu_vmxon(xc_arg_t arg1 __unused, xc_arg_t arg2 __unused,
    xc_arg_t arg3 __unused)
{
	uint64_t fctrl;
	const processorid_t id = CPU->cpu_seqid;
	hma_vmx_cpu_t *vmx_cpu = hma_vmx_cpu(id);

	VERIFY(vmx_cpu->hvc_vmxon_page != NULL);
	VERIFY(vmx_cpu->hvc_vmxon_pa != 0);

	/*
	 * Ensure that the VMX support and lock bits are enabled in the
	 * feature-control MSR.
	 */
	fctrl = rdmsr(MSR_IA32_FEAT_CTRL);
	if ((fctrl & IA32_FEAT_CTRL_LOCK) == 0 ||
	    (fctrl & IA32_FEAT_CTRL_VMX_EN) == 0) {
		fctrl = fctrl | IA32_FEAT_CTRL_VMX_EN | IA32_FEAT_CTRL_LOCK;
		wrmsr(MSR_IA32_FEAT_CTRL, fctrl);
	}

	setcr4(getcr4() | CR4_VMXE);

	if (hma_vmx_vmxon(vmx_cpu->hvc_vmxon_pa) == 0) {
		hma_cpu[id].hc_status = HCS_READY;
	} else {
		hma_cpu[id].hc_status = HCS_ERROR;

		/*
		 * If VMX has already been marked active and available for the
		 * system, then failure to perform VMXON on a newly-onlined CPU
		 * represents a fatal problem.  Continuing on would mean
		 * failure for any hypervisor thread which landed here.
		 */
		if (hma_vmx_ready) {
			panic("VMXON failure after VMX marked ready");
		}
	}
	return (0);
}

static int
hma_vmx_cpu_setup(cpu_setup_t what, int id, void *arg __unused)
{
	hma_vmx_cpu_t *vmx_cpu = hma_vmx_cpu(id);

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(id >= 0 && id < NCPU);

	if (what != CPU_ON) {
		/*
		 * For the purposes of VMX setup, only the CPU_ON event is of
		 * interest.  Letting VMX state linger on an offline CPU should
		 * not cause any harm.
		 *
		 * This logic assumes that any offlining activity is strictly
		 * administrative in nature and will not alter any existing
		 * configuration (such as %cr4 bits previously set).
		 */
		return (0);
	}

	const hma_cpu_status_t status = hma_cpu[id].hc_status;
	if (status == HCS_ERROR) {
		return (-1);
	}

	/* Allocate the VMXON page for this CPU, if not already done */
	if (vmx_cpu->hvc_vmxon_page == NULL) {
		caddr_t va;
		pfn_t pfn;

		va = kmem_alloc(PAGESIZE, KM_SLEEP);
		VERIFY0((uintptr_t)va & PAGEOFFSET);
		vmx_cpu->hvc_vmxon_page = va;

		/* Initialize the VMX revision field as expected */
		bcopy(&hma_vmx_revision, va, sizeof (hma_vmx_revision));

		/*
		 * Cache the physical address of the VMXON page rather than
		 * looking it up later when the potential blocking of
		 * hat_getpfnum would be less acceptable.
		 */
		pfn = hat_getpfnum(kas.a_hat, va);
		vmx_cpu->hvc_vmxon_pa = (pfn << PAGESHIFT);
	} else {
		VERIFY(vmx_cpu->hvc_vmxon_pa != 0);
	}

	if (status == HCS_UNINITIALIZED) {
		cpuset_t set;

		/* Activate VMX on this CPU */
		cpuset_zero(&set);
		cpuset_add(&set, id);
		xc_call(0, 0, 0, CPUSET2BV(set), hma_vmx_cpu_vmxon);
	} else {
		VERIFY3U(status, ==, HCS_READY);

		/*
		 * If an already-initialized CPU is going back online, perform
		 * an all-contexts invept to eliminate the possibility of
		 * cached EPT state causing issues.
		 */
		if ((hma_vmx_capabs & HVC_INVEPT_ALL) != 0) {
			cpuset_t set;

			cpuset_zero(&set);
			cpuset_add(&set, id);
			xc_call((xc_arg_t)INVEPT_ALL_CONTEXTS, 0, 0,
			    CPUSET2BV(set), hma_vmx_invept_xcall);
		}
	}

	return (hma_cpu[id].hc_status != HCS_READY);
}

/*
 * Determining the availability of VM execution controls is somewhat different
 * from conventional means, where one simply checks for asserted bits in the
 * MSR value.  Instead, these execution control MSRs are split into two halves:
 * the lower 32-bits indicating capabilities which can be zeroed in the VMCS
 * field and the upper 32-bits indicating capabilities which can be set to one.
 *
 * It is described in detail in Appendix A.3 of SDM volume 3.
 */
#define	VMX_CTL_ONE_SETTING(val, flag)	\
	(((val) & ((uint64_t)(flag) << 32)) != 0)

static const char *
hma_vmx_query_details(void)
{
	boolean_t query_true_ctl = B_FALSE;
	uint64_t msr;

	/* The basic INS/OUTS functionality is cited as a necessary prereq */
	msr = rdmsr(MSR_IA32_VMX_BASIC);
	if ((msr & IA32_VMX_BASIC_INS_OUTS) == 0) {
		return ("VMX does not support INS/OUTS");
	}

	/* Record the VMX revision for later VMXON usage */
	hma_vmx_revision = (uint32_t)msr;

	/*
	 * Bit 55 in the VMX_BASIC MSR determines how VMX control information
	 * can be queried.
	 */
	query_true_ctl = (msr & IA32_VMX_BASIC_TRUE_CTRLS) != 0;

	/* Check for EPT and VPID support */
	msr = rdmsr(query_true_ctl ?
	    MSR_IA32_VMX_TRUE_PROCBASED_CTLS : MSR_IA32_VMX_PROCBASED_CTLS);
	if (VMX_CTL_ONE_SETTING(msr, IA32_VMX_PROCBASED_2ND_CTLS)) {
		msr = rdmsr(MSR_IA32_VMX_PROCBASED2_CTLS);
		if (VMX_CTL_ONE_SETTING(msr, IA32_VMX_PROCBASED2_EPT)) {
			hma_vmx_capabs |= HVC_EPT;
		}
		if (VMX_CTL_ONE_SETTING(msr, IA32_VMX_PROCBASED2_VPID)) {
			hma_vmx_capabs |= HVC_VPID;
		}
	}

	/* Check for INVEPT support */
	if ((hma_vmx_capabs & HVC_EPT) != 0) {
		msr = rdmsr(MSR_IA32_VMX_EPT_VPID_CAP);
		if ((msr & IA32_VMX_EPT_VPID_INVEPT) != 0) {
			if ((msr & IA32_VMX_EPT_VPID_INVEPT_SINGLE) != 0) {
				hma_vmx_capabs |= HVC_INVEPT_ONE;
			}
			if ((msr & IA32_VMX_EPT_VPID_INVEPT_ALL) != 0) {
				hma_vmx_capabs |= HVC_INVEPT_ALL;
			}
		}
	}

	return (NULL);
}

static int
hma_vmx_init(void)
{
	cpu_t *cp;
	uint64_t msr;
	int err = 0;
	const char *msg = NULL;

	if (!is_x86_feature(x86_featureset, X86FSET_VMX)) {
		msg = "CPU does not support VMX";
		goto bail;
	}

	/* Has the BIOS set the feature-control lock bit without VMX enabled? */
	msr = rdmsr(MSR_IA32_FEAT_CTRL);
	if ((msr & IA32_FEAT_CTRL_LOCK) != 0 &&
	    (msr & IA32_FEAT_CTRL_VMX_EN) == 0) {
		msg = "VMX support disabled by BIOS";
		goto bail;
	}

	msg = hma_vmx_query_details();
	if (msg != NULL) {
		goto bail;
	}

	mutex_enter(&cpu_lock);
	/* Perform VMX configuration for already-online CPUs. */
	cp = cpu_active;
	do {
		err = hma_vmx_cpu_setup(CPU_ON, cp->cpu_seqid, NULL);
		if (err != 0) {
			msg = "failure during VMXON setup";
			mutex_exit(&cpu_lock);
			goto bail;
		}
	} while ((cp = cp->cpu_next_onln) != cpu_active);

	/*
	 * Register callback for later-onlined CPUs and perform other remaining
	 * resource allocation.
	 */
	register_cpu_setup_func(hma_vmx_cpu_setup, NULL);
	mutex_exit(&cpu_lock);

	hma_vmx_vpid = id_space_create("hma_vmx_vpid", HMA_VPID_RESERVED + 1,
	    UINT16_MAX);
	hma_vmx_ready = B_TRUE;

	return (0);

bail:
	hma_vmx_error = msg;
	cmn_err(CE_NOTE, "!hma_vmx_init: %s", msg);
	return (-1);
}

#define	VMCB_FLUSH_NOTHING	0x0
#define	VMCB_FLUSH_ALL		0x1
#define	VMCB_FLUSH_ASID		0x3

void
hma_svm_asid_init(hma_svm_asid_t *vcp)
{
	/*
	 * Initialize the generation to 0, forcing an ASID allocation on first
	 * entry.  Leave the ASID at 0, so if the host forgoes the call to
	 * hma_svm_asid_update(), SVM will bail on the invalid vcpu state.
	 */
	vcp->hsa_gen = 0;
	vcp->hsa_asid = 0;
}

uint8_t
hma_svm_asid_update(hma_svm_asid_t *vcp, boolean_t flush_by_asid,
    boolean_t npt_flush)
{
	/*
	 * Most ASID resource updates are expected to be performed as part of
	 * VMM entry into guest context, where interrupts would be disabled for
	 * the sake of state consistency.
	 *
	 * We demand this be the case, even though other situations which might
	 * incur an ASID update, such as userspace manipulation of guest vCPU
	 * state, may not require such consistency.
	 */
	ASSERT(!interrupts_enabled());

	/*
	 * If NPT changes dictate a TLB flush and by-ASID flushing is not
	 * supported/used, force a fresh ASID allocation.
	 */
	if (npt_flush && !flush_by_asid) {
		vcp->hsa_gen = 0;
	}

	hma_svm_asid_t *hcp = &(hma_svm_cpu(CPU->cpu_seqid)->hsc_asid);
	if (vcp->hsa_gen != hcp->hsa_gen) {
		hcp->hsa_asid++;

		if (hcp->hsa_asid >= hma_svm_max_asid) {
			/* Keep the ASID properly constrained */
			hcp->hsa_asid = 1;
			hcp->hsa_gen++;
			if (hcp->hsa_gen == 0) {
				/*
				 * Stay clear of the '0' sentinel value for
				 * generation, if wrapping around.
				 */
				hcp->hsa_gen = 1;
			}
		}
		vcp->hsa_gen = hcp->hsa_gen;
		vcp->hsa_asid = hcp->hsa_asid;

		ASSERT(vcp->hsa_asid != 0);
		ASSERT3U(vcp->hsa_asid, <, hma_svm_max_asid);

		if (flush_by_asid) {
			return (VMCB_FLUSH_ASID);
		} else {
			return (VMCB_FLUSH_ALL);
		}
	} else if (npt_flush) {
		ASSERT(flush_by_asid);
		return (VMCB_FLUSH_ASID);
	}

	return (VMCB_FLUSH_NOTHING);
}

void
hma_svm_gif_disable(void)
{
	/*
	 * Clear the GIF (masking interrupts) first, so the subsequent
	 * housekeeping can be done under its protection.
	 */
	__asm__ __volatile__("clgi");

	hma_svm_cpu_t *svm_cpu = hma_svm_cpu(CPU->cpu_seqid);
	const uint_t old_gif = atomic_swap_uint(&svm_cpu->hsc_gif_disabled, 1);

	if (old_gif != 0) {
		panic("GIF disable is set when expected to be clear");
	}
}

void
hma_svm_gif_enable(void)
{
	hma_svm_cpu_t *svm_cpu = hma_svm_cpu(CPU->cpu_seqid);
	const uint_t old_gif = atomic_swap_uint(&svm_cpu->hsc_gif_disabled, 0);

	if (old_gif == 0) {
		panic("GIF disable is clear when expected to be set");
	}

	/*
	 * Set the GIF last (un-masking interrupts) last, so the housekeeping
	 * will have been completed under its protection.
	 */
	__asm__ __volatile__("stgi");
}

boolean_t
hma_svm_gif_is_disabled(void)
{
	hma_svm_cpu_t *svm_cpu = hma_svm_cpu(CPU->cpu_seqid);

	/*
	 * At the time of this writing, there exists no mechanism by which the
	 * state of the GIF on a CPU can be directly queried.  Rather than
	 * attempting an indirect means of checking its state, we track it
	 * manually through the HMA disable/enable functions.
	 */
	return (svm_cpu->hsc_gif_disabled != 0);
}

#define	EVTSEL_EN(evt) (((evt) & AMD_PERF_EVTSEL_CTR_EN) != 0)
#define	CPC_BASE_REGS	4
#define	CPC_EXTD_REGS	6
#define	MSR_CPC_EXTD_EVTSEL(idx)	(MSR_AMD_F15H_PERF_EVTSEL0 + (idx * 2))
#define	MSR_CPC_EXTD_CTR(idx)		(MSR_AMD_F15H_PERF_CTR0 + (idx * 2))

/*
 * AMD CPU Performance Counter Support
 *
 * This provides a means of safely saving/loading host CPC state, along with
 * loading/saving guest CPC state upon guest entry/exit (respectively).
 * Currently, this only supports the 6 "extended" performance counters
 * (in MSRs C0010200h - C001020bh).  It pays no head to any other CPC state such
 * as the Northbridge counters or PerfMonV2 registers.
 */

hma_svm_cpc_res_t
hma_svm_cpc_enter(struct hma_svm_cpc_state *cpc_state)
{
	hma_svm_cpu_t *svm_cpu = hma_svm_cpu(CPU->cpu_seqid);

	ASSERT(!interrupts_enabled());

	svm_cpu->hsc_cpc_saved_flags = HCF_DISABLED;

	const hma_cpc_flags_t req_flags =
	    cpc_state->hscs_flags & hma_svm_cpc_allowed;
	if (req_flags == HCF_DISABLED) {
		return (HSCR_EMPTY);
	}

	/* Extended regs should not be enabled without base */
	IMPLY((req_flags & HCF_EN_EXTD) != 0, (req_flags & HCF_EN_BASE) != 0);

	const uint_t max_guest_reg =
	    (req_flags & HCF_EN_EXTD) != 0 ? CPC_EXTD_REGS : CPC_BASE_REGS;
	uint_t guest_active = 0;
	for (uint_t i = 0; i < max_guest_reg; i++) {
		if (EVTSEL_EN(cpc_state->hscs_regs[i].hc_evtsel)) {
			guest_active++;
		}
	}

	/*
	 * Guest is not currently measuring with any of the CPCs, so leave any
	 * host counters in place.
	 */
	if (guest_active == 0) {
		return (HSCR_EMPTY);
	}

	/*
	 * Read (and save) the host evtsel values, counting the number of
	 * registers in active use
	 */
	uint_t host_active = 0;
	for (uint_t i = 0; i < CPC_EXTD_REGS; i++) {
		const uint64_t evtsel = rdmsr(MSR_CPC_EXTD_EVTSEL(i));

		svm_cpu->hsc_cpc_host_regs[i].hc_evtsel = evtsel;
		if (EVTSEL_EN(evtsel)) {
			host_active++;
		}
	}

	if (host_active != 0) {
		if (hma_cpc_priority == HCP_HOST_WINS) {
			/*
			 * Host has priority access to the perf counters over
			 * the guest, so just leave everything in place.
			 */
			DTRACE_PROBE2(hma_svm__guest_deferred,
			    processorid_t, CPU->cpu_seqid,
			    uint_t, guest_active);
			return (HSCR_EMPTY);
		}

		DTRACE_PROBE2(hma_svm__host_deferred,
		    processorid_t, CPU->cpu_seqid, uint_t, host_active);

		/*
		 * Disable any active host counters, trying to do so in as
		 * consistent a manner as possible.
		 */
		for (uint_t i = 0; i < CPC_EXTD_REGS; i++) {
			const uint64_t evtsel =
			    svm_cpu->hsc_cpc_host_regs[i].hc_evtsel;
			wrmsr(MSR_CPC_EXTD_EVTSEL(i),
			    evtsel & ~AMD_PERF_EVTSEL_CTR_EN);
		}
	}

	/*
	 * With any active host counters stopped from collecting new events,
	 * save the counter values themselves before loading guest state.
	 */
	for (uint_t i = 0; i < CPC_EXTD_REGS; i++) {
		svm_cpu->hsc_cpc_host_regs[i].hc_ctr =
		    rdmsr(MSR_CPC_EXTD_CTR(i));
	}

	/*
	 * Now load the guest state, fixing it up with the flag necessary to
	 * collect events only while in guest context.
	 */
	for (uint_t i = 0; i < max_guest_reg; i++) {
		uint64_t evtsel = cpc_state->hscs_regs[i].hc_evtsel;

		/*
		 * Clear any existing HG flags, as well as any request for
		 * interrupt enable. (Trapping the interrupt from guest counters
		 * is not presently supported.)
		 */
		evtsel &= ~(AMD_PERF_EVTSEL_HG_MASK | AMD_PERF_EVTSEL_INT_EN);
		/* And indicate guest-only event tracking */
		evtsel |= AMD_PERF_EVTSEL_HG_GUEST;

		wrmsr(MSR_CPC_EXTD_EVTSEL(i), evtsel);
		wrmsr(MSR_CPC_EXTD_CTR(i), cpc_state->hscs_regs[i].hc_ctr);
	}

	svm_cpu->hsc_cpc_saved_flags = req_flags;
	return (HSCR_ACCESS_RDPMC | HSCR_ACCESS_CTR_MSR);
}

void
hma_svm_cpc_exit(struct hma_svm_cpc_state *cpc_state)
{
	ASSERT(!interrupts_enabled());

	hma_svm_cpu_t *svm_cpu = hma_svm_cpu(CPU->cpu_seqid);

	const hma_cpc_flags_t saved_flags = svm_cpu->hsc_cpc_saved_flags;
	if (saved_flags == HCF_DISABLED) {
		return;
	}

	/* Save the guest counter values. */
	const uint_t max_guest_reg =
	    (saved_flags & HCF_EN_EXTD) != 0 ? CPC_EXTD_REGS : CPC_BASE_REGS;
	for (uint_t i = 0; i < max_guest_reg; i++) {
		cpc_state->hscs_regs[i].hc_ctr = rdmsr(MSR_CPC_EXTD_CTR(i));
	}

	/*
	 * Load the host values back, once again taking care to toggle the
	 * counter enable state as a separate step in an attempt to keep
	 * readings as consistent as possible
	 */
	uint_t host_active = 0;
	for (uint_t i = 0; i < CPC_EXTD_REGS; i++) {
		const uint64_t evtsel = svm_cpu->hsc_cpc_host_regs[i].hc_evtsel;

		if (EVTSEL_EN(evtsel)) {
			host_active++;
		}
		wrmsr(MSR_CPC_EXTD_EVTSEL(i), evtsel & ~AMD_PERF_EVTSEL_CTR_EN);
		wrmsr(MSR_CPC_EXTD_CTR(i),
		    svm_cpu->hsc_cpc_host_regs[i].hc_ctr);
	}

	/*
	 * Allow any enabled host counters to collect events, now that all of
	 * the other state is loaded.
	 */
	if (host_active != 0) {
		for (uint_t i = 0; i < CPC_EXTD_REGS; i++) {
			wrmsr(MSR_CPC_EXTD_EVTSEL(i),
			    svm_cpu->hsc_cpc_host_regs[i].hc_evtsel);
		}
	}
}

static int
hma_svm_cpu_activate(xc_arg_t arg1 __unused, xc_arg_t arg2 __unused,
    xc_arg_t arg3 __unused)
{
	const processorid_t id = CPU->cpu_seqid;
	const uintptr_t hsave_pa = hma_svm_cpu(id)->hsc_hsave_pa;
	uint64_t efer;

	VERIFY(hsave_pa != 0);

	/* Enable SVM via EFER */
	efer = rdmsr(MSR_AMD_EFER);
	efer |= AMD_EFER_SVME;
	wrmsr(MSR_AMD_EFER, efer);

	/* Setup hsave area */
	wrmsr(MSR_AMD_VM_HSAVE_PA, hsave_pa);

	hma_cpu[id].hc_status = HCS_READY;
	return (0);
}

static int
hma_svm_cpu_setup(cpu_setup_t what, int id, void *arg __unused)
{
	hma_svm_cpu_t *svm_cpu = hma_svm_cpu(id);

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(id >= 0 && id < NCPU);

	switch (what) {
	case CPU_CONFIG:
	case CPU_ON:
	case CPU_INIT:
		break;
	default:
		/*
		 * Other events, such as CPU offlining, are of no interest.
		 * Letting the SVM state linger should not cause any harm.
		 *
		 * This logic assumes that any offlining activity is strictly
		 * administrative in nature and will not alter any existing
		 * configuration (such as EFER bits previously set).
		 */
		return (0);
	}

	/* Perform initialization if it has not been previously attempted. */
	if (hma_cpu[id].hc_status != HCS_UNINITIALIZED) {
		return ((hma_cpu[id].hc_status == HCS_READY) ? 0 : -1);
	}

	/* Allocate the hsave page for this CPU */
	if (svm_cpu->hsc_hsave_page == NULL) {
		caddr_t va;
		pfn_t pfn;

		va = kmem_alloc(PAGESIZE, KM_SLEEP);
		VERIFY0((uintptr_t)va & PAGEOFFSET);
		svm_cpu->hsc_hsave_page = va;

		/*
		 * Cache the physical address of the hsave page rather than
		 * looking it up later when the potential blocking of
		 * hat_getpfnum would be less acceptable.
		 */
		pfn = hat_getpfnum(kas.a_hat, va);
		svm_cpu->hsc_hsave_pa = (pfn << PAGESHIFT);
	} else {
		VERIFY(svm_cpu->hsc_hsave_pa != 0);
	}

	kpreempt_disable();
	if (CPU->cpu_seqid == id) {
		/* Perform svm setup directly if this CPU is the target */
		(void) hma_svm_cpu_activate(0, 0, 0);
		kpreempt_enable();
	} else {
		cpuset_t set;

		/* Use a cross-call if a remote CPU is the target */
		kpreempt_enable();
		cpuset_zero(&set);
		cpuset_add(&set, id);
		xc_call(0, 0, 0, CPUSET2BV(set), hma_svm_cpu_activate);
	}

	return (hma_cpu[id].hc_status != HCS_READY);
}

static int
hma_svm_init(void)
{
	uint64_t msr;
	const char *msg = NULL;
	struct cpuid_regs regs;
	cpu_t *cp;

	if (!is_x86_feature(x86_featureset, X86FSET_SVM)) {
		msg = "CPU does not support SVM";
		goto bail;
	}

	msr = rdmsr(MSR_AMD_VM_CR);
	if ((msr & AMD_VM_CR_SVMDIS) != 0) {
		msg = "SVM disabled by BIOS";
		goto bail;
	}

	regs.cp_eax = 0x8000000a;
	(void) cpuid_insn(NULL, &regs);
	const uint32_t nasid = regs.cp_ebx;
	const uint32_t feat = regs.cp_edx;

	if (nasid == 0) {
		msg = "Not enough ASIDs for guests";
		goto bail;
	}
	if ((feat & CPUID_AMD_EDX_NESTED_PAGING) == 0) {
		msg = "CPU does not support nested paging";
		goto bail;
	}
	if ((feat & CPUID_AMD_EDX_NRIPS) == 0) {
		msg = "CPU does not support NRIP save";
		goto bail;
	}

	hma_svm_features = feat;
	hma_svm_max_asid = nasid;

	mutex_enter(&cpu_lock);
	/* Perform SVM configuration for already-online CPUs. */
	cp = cpu_active;
	do {
		int err = hma_svm_cpu_setup(CPU_ON, cp->cpu_seqid, NULL);
		if (err != 0) {
			msg = "failure during SVM setup";
			mutex_exit(&cpu_lock);
			goto bail;
		}
	} while ((cp = cp->cpu_next_onln) != cpu_active);

	/*
	 * Register callback for later-onlined CPUs and perform other remaining
	 * resource allocation.
	 */
	register_cpu_setup_func(hma_svm_cpu_setup, NULL);
	mutex_exit(&cpu_lock);

	/* Initialize per-CPU ASID state. */
	for (uint_t i = 0; i < NCPU; i++) {
		/*
		 * Skip past sentinel 0 value for generation.  Doing so for
		 * ASID is unneeded, since it will be incremented during the
		 * first allocation.
		 */
		hma_svm_asid_t *cpu_asid = &hma_svm_cpu(i)->hsc_asid;
		cpu_asid->hsa_gen = 1;
		cpu_asid->hsa_asid = 0;
	}

	/*
	 * For now, only expose performance counter support if the host supports
	 * "extended" counters.  This makes MSR access more consistent for logic
	 * handling that state.
	 */
	if (is_x86_feature(x86_featureset, X86FSET_AMD_PCEC)) {
		hma_svm_cpc_allowed = HCF_EN_BASE | HCF_EN_EXTD;
	}

	hma_svm_ready = B_TRUE;
	return (0);

bail:
	hma_svm_error = msg;
	cmn_err(CE_NOTE, "!hma_svm_init: %s", msg);
	return (-1);
}
