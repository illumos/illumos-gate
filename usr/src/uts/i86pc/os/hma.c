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
 * Copyright 2018 Joyent, Inc.
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

typedef enum vmx_cpu_state {
	VCS_UNINITIALIZED = 0,
	VCS_READY,
	VCS_ERROR
} vmx_cpu_state_t;

/*
 * The bulk of VMX-related HMA state is protected by cpu_lock, rather than a
 * mutex specific to the module.  It (cpu_lock) is already required for the
 * state needed to perform setup on all CPUs, so it was a natural fit to
 * protect this data too.
 */
static void *hma_vmx_vmxon_page[NCPU];
static uintptr_t hma_vmx_vmxon_pa[NCPU];
static vmx_cpu_state_t hma_vmx_status[NCPU];
static uint32_t hma_vmx_revision;


static int hma_vmx_init(void);
static int hma_svm_init(void);

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
		/* Punt on SVM support for now */
		is_ready = B_FALSE;
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


extern int hma_vmx_vmxon(uintptr_t);

/* ARGSUSED */
static int
hma_vmx_cpu_vmxon(xc_arg_t arg1, xc_arg_t arg2, xc_arg_t arg3)
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
		hma_vmx_status[id] = VCS_READY;
	} else {
		hma_vmx_status[id] = VCS_ERROR;

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

/* ARGSUSED2 */
static int
hma_vmx_cpu_setup(cpu_setup_t what, int id, void *arg)
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
		 * Letting the VMX state linger should not cause any harm.
		 *
		 * This logic assumes that any offlining activity is strictly
		 * administrative in nature and will not alter any existing
		 * configuration (such as %cr4 bits previously set).
		 */
		return (0);
	}

	/* Perform initialization if it has not been previously attempted. */
	if (hma_vmx_status[id] != VCS_UNINITIALIZED) {
		return ((hma_vmx_status[id] == VCS_READY) ? 0 : -1);
	}

	/* Allocate the VMXON page for this CPU */
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

	kpreempt_disable();
	if (CPU->cpu_seqid == id) {
		/* Perform vmxon setup directly if this CPU is the target */
		(void) hma_vmx_cpu_vmxon(0, 0, 0);
		kpreempt_enable();
	} else {
		cpuset_t set;

		/* Use a cross-call if a remote CPU is the target */
		kpreempt_enable();
		cpuset_zero(&set);
		cpuset_add(&set, id);
		xc_sync(0, 0, 0, CPUSET2BV(set), hma_vmx_cpu_vmxon);
	}

	return (hma_vmx_status[id] != VCS_READY);
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

	/* Does VMX support basic INS/OUTS functionality */
	msr = rdmsr(MSR_IA32_VMX_BASIC);
	if ((msr & IA32_VMX_BASIC_INS_OUTS) == 0) {
		msg = "VMX does not support INS/OUTS";
		goto bail;
	}
	/* Record the VMX revision for later VMXON usage */
	hma_vmx_revision = (uint32_t)msr;

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


static int
hma_svm_init(void)
{
	/* punt on AMD for now */
	return (ENOTSUP);
}
