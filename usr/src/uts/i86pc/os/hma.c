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
 */

#include <sys/cpuvar.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/machsystm.h>
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

static boolean_t hma_vmx_ready = B_FALSE;
static const char *hma_vmx_error = NULL;
static id_space_t *hma_vmx_vpid;

/*
 * The bulk of HMA state (VMX & SVM) is protected by cpu_lock, rather than a
 * mutex specific to the module.  It (cpu_lock) is already required for the
 * state needed to perform setup on all CPUs, so it was a natural fit to
 * protect this data too.
 */
typedef enum hma_cpu_state {
	HCS_UNINITIALIZED = 0,
	HCS_READY,
	HCS_ERROR
} hma_cpu_state_t;
static hma_cpu_state_t hma_cpu_status[NCPU];

/* HMA-internal tracking of optional VMX capabilities */
typedef enum {
	HVC_EPT		= (1 << 0),
	HVC_VPID	= (1 << 1),
	HVC_INVEPT_ONE	= (1 << 2),
	HVC_INVEPT_ALL	= (1 << 3),
} hma_vmx_capab_t;

static void *hma_vmx_vmxon_page[NCPU];
static uintptr_t hma_vmx_vmxon_pa[NCPU];
static uint32_t hma_vmx_revision;
static hma_vmx_capab_t hma_vmx_capabs = 0;

static boolean_t hma_svm_ready = B_FALSE;
static const char *hma_svm_error = NULL;
static uint32_t hma_svm_features;
static uint32_t hma_svm_max_asid;

static void *hma_svm_hsave_page[NCPU];
static uintptr_t hma_svm_hsave_pa[NCPU];

static hma_svm_asid_t hma_svm_cpu_asid[NCPU];


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

	switch (cpuid_getvendor(CPU)) {
	case X86_VENDOR_Intel:
		(void) hma_vmx_init();
		break;
	case X86_VENDOR_AMD:
		(void) hma_svm_init();
		break;
	default:
		break;
	}
}

hma_reg_t *
hma_register(const char *name)
{
	struct hma_reg *reg;
	boolean_t is_ready;

	VERIFY(name != NULL);

	reg = kmem_zalloc(sizeof (*reg), KM_SLEEP);
	reg->hr_name = name;

	mutex_enter(&hma_lock);
	switch (cpuid_getvendor(CPU)) {
	case X86_VENDOR_Intel:
		is_ready = hma_vmx_ready;
		break;
	case X86_VENDOR_AMD:
		is_ready = hma_svm_ready;
		break;
	default:
		is_ready = B_FALSE;
		break;
	}

	if (!is_ready) {
		kmem_free(reg, sizeof (*reg));
		reg = NULL;
	} else {
		list_insert_tail(&hma_registrations, reg);
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
	mutex_exit(&hma_lock);
	kmem_free(reg, sizeof (*reg));
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
	processorid_t id = CPU->cpu_seqid;
	void *vmxon_region = hma_vmx_vmxon_page[id];
	uintptr_t vmxon_pa = hma_vmx_vmxon_pa[id];

	VERIFY(vmxon_region != NULL && vmxon_pa != 0);

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

	if (hma_vmx_vmxon(vmxon_pa) == 0) {
		hma_cpu_status[id] = HCS_READY;
	} else {
		hma_cpu_status[id] = HCS_ERROR;

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
	hma_cpu_state_t state;

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

	state = hma_cpu_status[id];
	if (state == HCS_ERROR) {
		return (-1);
	}

	/* Allocate the VMXON page for this CPU, if not already done */
	if (hma_vmx_vmxon_page[id] == NULL) {
		caddr_t va;
		pfn_t pfn;

		va = kmem_alloc(PAGESIZE, KM_SLEEP);
		VERIFY0((uintptr_t)va & PAGEOFFSET);
		hma_vmx_vmxon_page[id] = va;

		/* Initialize the VMX revision field as expected */
		bcopy(&hma_vmx_revision, va, sizeof (hma_vmx_revision));

		/*
		 * Cache the physical address of the VMXON page rather than
		 * looking it up later when the potential blocking of
		 * hat_getpfnum would be less acceptable.
		 */
		pfn = hat_getpfnum(kas.a_hat, va);
		hma_vmx_vmxon_pa[id] = (pfn << PAGESHIFT);
	} else {
		VERIFY(hma_vmx_vmxon_pa[id] != 0);
	}

	if (state == HCS_UNINITIALIZED) {
		cpuset_t set;

		/* Activate VMX on this CPU */
		cpuset_zero(&set);
		cpuset_add(&set, id);
		xc_call(0, 0, 0, CPUSET2BV(set), hma_vmx_cpu_vmxon);
	} else {
		VERIFY3U(state, ==, HCS_READY);

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

	return (hma_cpu_status[id] != HCS_READY);
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
	cmn_err(CE_NOTE, "hma_vmx_init: %s", msg);
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
	hma_svm_asid_t *hcp = &hma_svm_cpu_asid[CPU->cpu_seqid];

	ASSERT(curthread->t_preempt != 0);

	/*
	 * If NPT changes dictate a TLB flush and by-ASID flushing is not
	 * supported/used, force a fresh ASID allocation.
	 */
	if (npt_flush && !flush_by_asid) {
		vcp->hsa_gen = 0;
	}

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
		}
		return (VMCB_FLUSH_ALL);
	} else if (npt_flush) {
		ASSERT(flush_by_asid);
		return (VMCB_FLUSH_ASID);
	}
	return (VMCB_FLUSH_NOTHING);
}

static int
hma_svm_cpu_activate(xc_arg_t arg1 __unused, xc_arg_t arg2 __unused,
    xc_arg_t arg3 __unused)
{
	const processorid_t id = CPU->cpu_seqid;
	const uintptr_t hsave_pa = hma_svm_hsave_pa[id];
	uint64_t efer;

	VERIFY(hsave_pa != 0);

	/* Enable SVM via EFER */
	efer = rdmsr(MSR_AMD_EFER);
	efer |= AMD_EFER_SVME;
	wrmsr(MSR_AMD_EFER, efer);

	/* Setup hsave area */
	wrmsr(MSR_AMD_VM_HSAVE_PA, hsave_pa);

	hma_cpu_status[id] = HCS_READY;
	return (0);
}

static int
hma_svm_cpu_setup(cpu_setup_t what, int id, void *arg __unused)
{
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
	if (hma_cpu_status[id] != HCS_UNINITIALIZED) {
		return ((hma_cpu_status[id] == HCS_READY) ? 0 : -1);
	}

	/* Allocate the hsave page for this CPU */
	if (hma_svm_hsave_page[id] == NULL) {
		caddr_t va;
		pfn_t pfn;

		va = kmem_alloc(PAGESIZE, KM_SLEEP);
		VERIFY0((uintptr_t)va & PAGEOFFSET);
		hma_svm_hsave_page[id] = va;

		/*
		 * Cache the physical address of the hsave page rather than
		 * looking it up later when the potential blocking of
		 * hat_getpfnum would be less acceptable.
		 */
		pfn = hat_getpfnum(kas.a_hat, va);
		hma_svm_hsave_pa[id] = (pfn << PAGESHIFT);
	} else {
		VERIFY(hma_svm_hsave_pa[id] != 0);
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

	return (hma_cpu_status[id] != HCS_READY);
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
		hma_svm_cpu_asid[i].hsa_gen = 1;
		hma_svm_cpu_asid[i].hsa_asid = 0;
	}

	hma_svm_ready = B_TRUE;
	return (0);

bail:
	hma_svm_error = msg;
	cmn_err(CE_NOTE, "hma_svm_init: %s", msg);
	return (-1);
}
