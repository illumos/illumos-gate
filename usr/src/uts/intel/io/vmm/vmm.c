/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */
/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * Copyright 2015 Pluribus Networks Inc.
 * Copyright 2018 Joyent, Inc.
 * Copyright 2022 Oxide Computer Company
 * Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/sysctl.h>
#include <sys/kmem.h>
#include <sys/pcpu.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/rwlock.h>
#include <sys/sched.h>
#include <sys/systm.h>
#include <sys/sunddi.h>
#include <sys/hma.h>

#include <machine/md_var.h>
#include <x86/psl.h>
#include <x86/apicreg.h>

#include <machine/specialreg.h>
#include <machine/vmm.h>
#include <machine/vmm_dev.h>
#include <machine/vmparam.h>
#include <sys/vmm_instruction_emul.h>
#include <sys/vmm_vm.h>
#include <sys/vmm_gpt.h>
#include <sys/vmm_data.h>

#include "vmm_ioport.h"
#include "vmm_host.h"
#include "vmm_util.h"
#include "vatpic.h"
#include "vatpit.h"
#include "vhpet.h"
#include "vioapic.h"
#include "vlapic.h"
#include "vpmtmr.h"
#include "vrtc.h"
#include "vmm_stat.h"
#include "vmm_lapic.h"

#include "io/ppt.h"
#include "io/iommu.h"

struct vlapic;

/* Flags for vtc_status */
#define	VTCS_FPU_RESTORED	1 /* guest FPU restored, host FPU saved */
#define	VTCS_FPU_CTX_CRITICAL	2 /* in ctx where FPU restore cannot be lazy */

typedef struct vm_thread_ctx {
	struct vm	*vtc_vm;
	int		vtc_vcpuid;
	uint_t		vtc_status;
	enum vcpu_ustate vtc_ustate;
} vm_thread_ctx_t;

#define	VMM_MTRR_VAR_MAX 10
#define	VMM_MTRR_DEF_MASK \
	(MTRR_DEF_ENABLE | MTRR_DEF_FIXED_ENABLE | MTRR_DEF_TYPE)
#define	VMM_MTRR_PHYSBASE_MASK (MTRR_PHYSBASE_PHYSBASE | MTRR_PHYSBASE_TYPE)
#define	VMM_MTRR_PHYSMASK_MASK (MTRR_PHYSMASK_PHYSMASK | MTRR_PHYSMASK_VALID)
struct vm_mtrr {
	uint64_t def_type;
	uint64_t fixed4k[8];
	uint64_t fixed16k[2];
	uint64_t fixed64k;
	struct {
		uint64_t base;
		uint64_t mask;
	} var[VMM_MTRR_VAR_MAX];
};

/*
 * Initialization:
 * (a) allocated when vcpu is created
 * (i) initialized when vcpu is created and when it is reinitialized
 * (o) initialized the first time the vcpu is created
 * (x) initialized before use
 */
struct vcpu {
	/* (o) protects state, run_state, hostcpu, sipi_vector */
	kmutex_t	lock;

	enum vcpu_state	state;		/* (o) vcpu state */
	enum vcpu_run_state run_state;	/* (i) vcpu init/sipi/run state */
	kcondvar_t	vcpu_cv;	/* (o) cpu waiter cv */
	kcondvar_t	state_cv;	/* (o) IDLE-transition cv */
	int		hostcpu;	/* (o) vcpu's current host cpu */
	int		lastloccpu;	/* (o) last host cpu localized to */
	int		reqidle;	/* (i) request vcpu to idle */
	struct vlapic	*vlapic;	/* (i) APIC device model */
	enum x2apic_state x2apic_state;	/* (i) APIC mode */
	uint64_t	exit_intinfo;	/* (i) events pending at VM exit */
	uint64_t	exc_pending;	/* (i) exception pending */
	bool		nmi_pending;	/* (i) NMI pending */
	bool		extint_pending;	/* (i) INTR pending */

	uint8_t		sipi_vector;	/* (i) SIPI vector */
	hma_fpu_t	*guestfpu;	/* (a,i) guest fpu state */
	uint64_t	guest_xcr0;	/* (i) guest %xcr0 register */
	void		*stats;		/* (a,i) statistics */
	struct vm_exit	exitinfo;	/* (x) exit reason and collateral */
	uint64_t	nextrip;	/* (x) next instruction to execute */
	struct vie	*vie_ctx;	/* (x) instruction emulation context */
	vm_client_t	*vmclient;	/* (a) VM-system client */
	uint64_t	tsc_offset;	/* (x) offset from host TSC */
	struct vm_mtrr	mtrr;		/* (i) vcpu's MTRR */
	vcpu_cpuid_config_t cpuid_cfg;	/* (x) cpuid configuration */

	enum vcpu_ustate ustate;	/* (i) microstate for the vcpu */
	hrtime_t	ustate_when;	/* (i) time of last ustate change */
	uint64_t ustate_total[VU_MAX];	/* (o) total time spent in ustates */
	vm_thread_ctx_t	vtc;		/* (o) thread state for ctxops */
	struct ctxop	*ctxop;		/* (o) ctxop storage for vcpu */
};

#define	vcpu_lock(v)		mutex_enter(&((v)->lock))
#define	vcpu_unlock(v)		mutex_exit(&((v)->lock))
#define	vcpu_assert_locked(v)	ASSERT(MUTEX_HELD(&((v)->lock)))

struct mem_seg {
	size_t	len;
	bool	sysmem;
	vm_object_t *object;
};
#define	VM_MAX_MEMSEGS	5

struct mem_map {
	vm_paddr_t	gpa;
	size_t		len;
	vm_ooffset_t	segoff;
	int		segid;
	int		prot;
	int		flags;
};
#define	VM_MAX_MEMMAPS	8

/*
 * Initialization:
 * (o) initialized the first time the VM is created
 * (i) initialized when VM is created and when it is reinitialized
 * (x) initialized before use
 */
struct vm {
	void		*cookie;		/* (i) cpu-specific data */
	void		*iommu;			/* (x) iommu-specific data */
	struct vhpet	*vhpet;			/* (i) virtual HPET */
	struct vioapic	*vioapic;		/* (i) virtual ioapic */
	struct vatpic	*vatpic;		/* (i) virtual atpic */
	struct vatpit	*vatpit;		/* (i) virtual atpit */
	struct vpmtmr	*vpmtmr;		/* (i) virtual ACPI PM timer */
	struct vrtc	*vrtc;			/* (o) virtual RTC */
	volatile cpuset_t active_cpus;		/* (i) active vcpus */
	volatile cpuset_t debug_cpus;		/* (i) vcpus stopped for dbg */
	int		suspend;		/* (i) stop VM execution */
	volatile cpuset_t suspended_cpus;	/* (i) suspended vcpus */
	volatile cpuset_t halted_cpus;		/* (x) cpus in a hard halt */
	struct mem_map	mem_maps[VM_MAX_MEMMAPS]; /* (i) guest address space */
	struct mem_seg	mem_segs[VM_MAX_MEMSEGS]; /* (o) guest memory regions */
	struct vmspace	*vmspace;		/* (o) guest's address space */
	struct vcpu	vcpu[VM_MAXCPU];	/* (i) guest vcpus */
	/* The following describe the vm cpu topology */
	uint16_t	sockets;		/* (o) num of sockets */
	uint16_t	cores;			/* (o) num of cores/socket */
	uint16_t	threads;		/* (o) num of threads/core */
	uint16_t	maxcpus;		/* (o) max pluggable cpus */

	uint64_t	boot_tsc_offset;	/* (i) TSC offset at VM boot */
	hrtime_t	boot_hrtime;		/* (i) hrtime at VM boot */

	struct ioport_config ioports;		/* (o) ioport handling */

	bool		mem_transient;		/* (o) alloc transient memory */
	bool		is_paused;		/* (i) instance is paused */
};

static int vmm_initialized;


static void
nullop_panic(void)
{
	panic("null vmm operation call");
}

/* Do not allow use of an un-set `ops` to do anything but panic */
static struct vmm_ops vmm_ops_null = {
	.init		= (vmm_init_func_t)nullop_panic,
	.cleanup	= (vmm_cleanup_func_t)nullop_panic,
	.resume		= (vmm_resume_func_t)nullop_panic,
	.vminit		= (vmi_init_func_t)nullop_panic,
	.vmrun		= (vmi_run_func_t)nullop_panic,
	.vmcleanup	= (vmi_cleanup_func_t)nullop_panic,
	.vmgetreg	= (vmi_get_register_t)nullop_panic,
	.vmsetreg	= (vmi_set_register_t)nullop_panic,
	.vmgetdesc	= (vmi_get_desc_t)nullop_panic,
	.vmsetdesc	= (vmi_set_desc_t)nullop_panic,
	.vmgetcap	= (vmi_get_cap_t)nullop_panic,
	.vmsetcap	= (vmi_set_cap_t)nullop_panic,
	.vlapic_init	= (vmi_vlapic_init)nullop_panic,
	.vlapic_cleanup	= (vmi_vlapic_cleanup)nullop_panic,
	.vmpause	= (vmi_pause_t)nullop_panic,
	.vmsavectx	= (vmi_savectx)nullop_panic,
	.vmrestorectx	= (vmi_restorectx)nullop_panic,
	.vmgetmsr	= (vmi_get_msr_t)nullop_panic,
	.vmsetmsr	= (vmi_set_msr_t)nullop_panic,
};

static struct vmm_ops *ops = &vmm_ops_null;
static vmm_pte_ops_t *pte_ops = NULL;

#define	VMM_INIT()			((*ops->init)())
#define	VMM_CLEANUP()			((*ops->cleanup)())
#define	VMM_RESUME()			((*ops->resume)())

#define	VMINIT(vm)		((*ops->vminit)(vm))
#define	VMRUN(vmi, vcpu, rip)	((*ops->vmrun)(vmi, vcpu, rip))
#define	VMCLEANUP(vmi)			((*ops->vmcleanup)(vmi))

#define	VMGETREG(vmi, vcpu, num, rv)	((*ops->vmgetreg)(vmi, vcpu, num, rv))
#define	VMSETREG(vmi, vcpu, num, val)	((*ops->vmsetreg)(vmi, vcpu, num, val))
#define	VMGETDESC(vmi, vcpu, num, dsc)	((*ops->vmgetdesc)(vmi, vcpu, num, dsc))
#define	VMSETDESC(vmi, vcpu, num, dsc)	((*ops->vmsetdesc)(vmi, vcpu, num, dsc))
#define	VMGETCAP(vmi, vcpu, num, rv)	((*ops->vmgetcap)(vmi, vcpu, num, rv))
#define	VMSETCAP(vmi, vcpu, num, val)	((*ops->vmsetcap)(vmi, vcpu, num, val))
#define	VLAPIC_INIT(vmi, vcpu)		((*ops->vlapic_init)(vmi, vcpu))
#define	VLAPIC_CLEANUP(vmi, vlapic)	((*ops->vlapic_cleanup)(vmi, vlapic))

#define	fpu_start_emulating()	load_cr0(rcr0() | CR0_TS)
#define	fpu_stop_emulating()	clts()

SDT_PROVIDER_DEFINE(vmm);

SYSCTL_NODE(_hw, OID_AUTO, vmm, CTLFLAG_RW | CTLFLAG_MPSAFE, NULL,
    NULL);

/*
 * Halt the guest if all vcpus are executing a HLT instruction with
 * interrupts disabled.
 */
int halt_detection_enabled = 1;

/* Trap into hypervisor on all guest exceptions and reflect them back */
int trace_guest_exceptions;

/* Trap WBINVD and ignore it */
int trap_wbinvd = 1;

static void vm_free_memmap(struct vm *vm, int ident);
static bool sysmem_mapping(struct vm *vm, struct mem_map *mm);
static void vcpu_notify_event_locked(struct vcpu *vcpu, vcpu_notify_t);
static bool vcpu_sleep_bailout_checks(struct vm *vm, int vcpuid);
static int vcpu_vector_sipi(struct vm *vm, int vcpuid, uint8_t vector);

static void vmm_savectx(void *);
static void vmm_restorectx(void *);
static const struct ctxop_template vmm_ctxop_tpl = {
	.ct_rev		= CTXOP_TPL_REV,
	.ct_save	= vmm_savectx,
	.ct_restore	= vmm_restorectx,
};

#ifdef KTR
static const char *
vcpu_state2str(enum vcpu_state state)
{

	switch (state) {
	case VCPU_IDLE:
		return ("idle");
	case VCPU_FROZEN:
		return ("frozen");
	case VCPU_RUNNING:
		return ("running");
	case VCPU_SLEEPING:
		return ("sleeping");
	default:
		return ("unknown");
	}
}
#endif

static void
vcpu_cleanup(struct vm *vm, int i, bool destroy)
{
	struct vcpu *vcpu = &vm->vcpu[i];

	VLAPIC_CLEANUP(vm->cookie, vcpu->vlapic);
	if (destroy) {
		vmm_stat_free(vcpu->stats);

		vcpu_cpuid_cleanup(&vcpu->cpuid_cfg);

		hma_fpu_free(vcpu->guestfpu);
		vcpu->guestfpu = NULL;

		vie_free(vcpu->vie_ctx);
		vcpu->vie_ctx = NULL;

		vmc_destroy(vcpu->vmclient);
		vcpu->vmclient = NULL;

		ctxop_free(vcpu->ctxop);
		mutex_destroy(&vcpu->lock);
	}
}

static void
vcpu_init(struct vm *vm, int vcpu_id, bool create)
{
	struct vcpu *vcpu;

	KASSERT(vcpu_id >= 0 && vcpu_id < vm->maxcpus,
	    ("vcpu_init: invalid vcpu %d", vcpu_id));

	vcpu = &vm->vcpu[vcpu_id];

	if (create) {
		mutex_init(&vcpu->lock, NULL, MUTEX_ADAPTIVE, NULL);

		vcpu->state = VCPU_IDLE;
		vcpu->hostcpu = NOCPU;
		vcpu->lastloccpu = NOCPU;
		vcpu->guestfpu = hma_fpu_alloc(KM_SLEEP);
		vcpu->stats = vmm_stat_alloc();
		vcpu->vie_ctx = vie_alloc();
		vcpu_cpuid_init(&vcpu->cpuid_cfg);

		vcpu->ustate = VU_INIT;
		vcpu->ustate_when = gethrtime();

		vcpu->vtc.vtc_vm = vm;
		vcpu->vtc.vtc_vcpuid = vcpu_id;
		vcpu->ctxop = ctxop_allocate(&vmm_ctxop_tpl, &vcpu->vtc);
	} else {
		vie_reset(vcpu->vie_ctx);
		bzero(&vcpu->exitinfo, sizeof (vcpu->exitinfo));
		if (vcpu->ustate != VU_INIT) {
			vcpu_ustate_change(vm, vcpu_id, VU_INIT);
		}
		bzero(&vcpu->mtrr, sizeof (vcpu->mtrr));
	}

	vcpu->run_state = VRS_HALT;
	vcpu->vlapic = VLAPIC_INIT(vm->cookie, vcpu_id);
	(void) vm_set_x2apic_state(vm, vcpu_id, X2APIC_DISABLED);
	vcpu->reqidle = 0;
	vcpu->exit_intinfo = 0;
	vcpu->nmi_pending = false;
	vcpu->extint_pending = false;
	vcpu->exc_pending = 0;
	vcpu->guest_xcr0 = XFEATURE_ENABLED_X87;
	(void) hma_fpu_init(vcpu->guestfpu);
	vmm_stat_init(vcpu->stats);
	vcpu->tsc_offset = 0;
}

int
vcpu_trace_exceptions(struct vm *vm, int vcpuid)
{
	return (trace_guest_exceptions);
}

int
vcpu_trap_wbinvd(struct vm *vm, int vcpuid)
{
	return (trap_wbinvd);
}

struct vm_exit *
vm_exitinfo(struct vm *vm, int cpuid)
{
	struct vcpu *vcpu;

	if (cpuid < 0 || cpuid >= vm->maxcpus)
		panic("vm_exitinfo: invalid cpuid %d", cpuid);

	vcpu = &vm->vcpu[cpuid];

	return (&vcpu->exitinfo);
}

struct vie *
vm_vie_ctx(struct vm *vm, int cpuid)
{
	if (cpuid < 0 || cpuid >= vm->maxcpus)
		panic("vm_vie_ctx: invalid cpuid %d", cpuid);

	return (vm->vcpu[cpuid].vie_ctx);
}

static int
vmm_init(void)
{
	vmm_host_state_init();

	if (vmm_is_intel()) {
		ops = &vmm_ops_intel;
		pte_ops = &ept_pte_ops;
	} else if (vmm_is_svm()) {
		ops = &vmm_ops_amd;
		pte_ops = &rvi_pte_ops;
	} else {
		return (ENXIO);
	}

	return (VMM_INIT());
}

int
vmm_mod_load()
{
	int	error;

	VERIFY(vmm_initialized == 0);

	error = vmm_init();
	if (error == 0)
		vmm_initialized = 1;

	return (error);
}

int
vmm_mod_unload()
{
	int	error;

	VERIFY(vmm_initialized == 1);

	error = VMM_CLEANUP();
	if (error)
		return (error);
	vmm_initialized = 0;

	return (0);
}

/*
 * Create a test IOMMU domain to see if the host system has necessary hardware
 * and drivers to do so.
 */
bool
vmm_check_iommu(void)
{
	void *domain;
	const size_t arb_test_sz = (1UL << 32);

	domain = iommu_create_domain(arb_test_sz);
	if (domain == NULL) {
		return (false);
	}
	iommu_destroy_domain(domain);
	return (true);
}

static void
vm_init(struct vm *vm, bool create)
{
	int i;

	vm->cookie = VMINIT(vm);
	vm->iommu = NULL;
	vm->vioapic = vioapic_init(vm);
	vm->vhpet = vhpet_init(vm);
	vm->vatpic = vatpic_init(vm);
	vm->vatpit = vatpit_init(vm);
	vm->vpmtmr = vpmtmr_init(vm);
	if (create)
		vm->vrtc = vrtc_init(vm);

	vm_inout_init(vm, &vm->ioports);

	CPU_ZERO(&vm->active_cpus);
	CPU_ZERO(&vm->debug_cpus);

	vm->suspend = 0;
	CPU_ZERO(&vm->suspended_cpus);

	for (i = 0; i < vm->maxcpus; i++)
		vcpu_init(vm, i, create);

	/*
	 * Configure the VM-wide TSC offset so that the call to vm_init()
	 * represents the boot time (when the TSC(s) read 0).  Each vCPU will
	 * have its own offset from this, which is altered if/when the guest
	 * writes to MSR_TSC.
	 *
	 * The TSC offsetting math is all unsigned, using overflow for negative
	 * offets.  A reading of the TSC is negated to form the boot offset.
	 */
	const uint64_t boot_tsc = rdtsc_offset();
	vm->boot_tsc_offset = (uint64_t)(-(int64_t)boot_tsc);

	/* Convert the boot TSC reading to hrtime */
	vm->boot_hrtime = (hrtime_t)boot_tsc;
	scalehrtime(&vm->boot_hrtime);
}

/*
 * The default CPU topology is a single thread per package.
 */
uint_t cores_per_package = 1;
uint_t threads_per_core = 1;

int
vm_create(uint64_t flags, struct vm **retvm)
{
	struct vm *vm;
	struct vmspace *vmspace;

	/*
	 * If vmm.ko could not be successfully initialized then don't attempt
	 * to create the virtual machine.
	 */
	if (!vmm_initialized)
		return (ENXIO);

	bool track_dirty = (flags & VCF_TRACK_DIRTY) != 0;
	if (track_dirty && !pte_ops->vpeo_hw_ad_supported())
		return (ENOTSUP);

	vmspace = vmspace_alloc(VM_MAXUSER_ADDRESS, pte_ops, track_dirty);
	if (vmspace == NULL)
		return (ENOMEM);

	vm = kmem_zalloc(sizeof (struct vm), KM_SLEEP);

	vm->vmspace = vmspace;
	vm->mem_transient = (flags & VCF_RESERVOIR_MEM) == 0;
	for (uint_t i = 0; i < VM_MAXCPU; i++) {
		vm->vcpu[i].vmclient = vmspace_client_alloc(vmspace);
	}

	vm->sockets = 1;
	vm->cores = cores_per_package;	/* XXX backwards compatibility */
	vm->threads = threads_per_core;	/* XXX backwards compatibility */
	vm->maxcpus = VM_MAXCPU;	/* XXX temp to keep code working */

	vm_init(vm, true);

	*retvm = vm;
	return (0);
}

void
vm_get_topology(struct vm *vm, uint16_t *sockets, uint16_t *cores,
    uint16_t *threads, uint16_t *maxcpus)
{
	*sockets = vm->sockets;
	*cores = vm->cores;
	*threads = vm->threads;
	*maxcpus = vm->maxcpus;
}

uint16_t
vm_get_maxcpus(struct vm *vm)
{
	return (vm->maxcpus);
}

int
vm_set_topology(struct vm *vm, uint16_t sockets, uint16_t cores,
    uint16_t threads, uint16_t maxcpus)
{
	if (maxcpus != 0)
		return (EINVAL);	/* XXX remove when supported */
	if ((sockets * cores * threads) > vm->maxcpus)
		return (EINVAL);
	/* XXX need to check sockets * cores * threads == vCPU, how? */
	vm->sockets = sockets;
	vm->cores = cores;
	vm->threads = threads;
	vm->maxcpus = VM_MAXCPU;	/* XXX temp to keep code working */
	return (0);
}

static void
vm_cleanup(struct vm *vm, bool destroy)
{
	struct mem_map *mm;
	int i;

	ppt_unassign_all(vm);

	if (vm->iommu != NULL)
		iommu_destroy_domain(vm->iommu);

	/*
	 * Devices which attach their own ioport hooks should be cleaned up
	 * first so they can tear down those registrations.
	 */
	vpmtmr_cleanup(vm->vpmtmr);

	vm_inout_cleanup(vm, &vm->ioports);

	if (destroy)
		vrtc_cleanup(vm->vrtc);
	else
		vrtc_reset(vm->vrtc);

	vatpit_cleanup(vm->vatpit);
	vhpet_cleanup(vm->vhpet);
	vatpic_cleanup(vm->vatpic);
	vioapic_cleanup(vm->vioapic);

	for (i = 0; i < vm->maxcpus; i++)
		vcpu_cleanup(vm, i, destroy);

	VMCLEANUP(vm->cookie);

	/*
	 * System memory is removed from the guest address space only when
	 * the VM is destroyed. This is because the mapping remains the same
	 * across VM reset.
	 *
	 * Device memory can be relocated by the guest (e.g. using PCI BARs)
	 * so those mappings are removed on a VM reset.
	 */
	for (i = 0; i < VM_MAX_MEMMAPS; i++) {
		mm = &vm->mem_maps[i];
		if (destroy || !sysmem_mapping(vm, mm)) {
			vm_free_memmap(vm, i);
		} else {
			/*
			 * We need to reset the IOMMU flag so this mapping can
			 * be reused when a VM is rebooted. Since the IOMMU
			 * domain has already been destroyed we can just reset
			 * the flag here.
			 */
			mm->flags &= ~VM_MEMMAP_F_IOMMU;
		}
	}

	if (destroy) {
		for (i = 0; i < VM_MAX_MEMSEGS; i++)
			vm_free_memseg(vm, i);

		vmspace_destroy(vm->vmspace);
		vm->vmspace = NULL;
	}
}

void
vm_destroy(struct vm *vm)
{
	vm_cleanup(vm, true);
	kmem_free(vm, sizeof (*vm));
}

int
vm_reinit(struct vm *vm, uint64_t flags)
{
	/* A virtual machine can be reset only if all vcpus are suspended. */
	if (CPU_CMP(&vm->suspended_cpus, &vm->active_cpus) != 0) {
		if ((flags & VM_REINIT_F_FORCE_SUSPEND) == 0) {
			return (EBUSY);
		}

		/*
		 * Force the VM (and all its vCPUs) into a suspended state.
		 * This should be quick and easy, since the vm_reinit() call is
		 * made while holding the VM write lock, which requires holding
		 * all of the vCPUs in the VCPU_FROZEN state.
		 */
		(void) atomic_cmpset_int((uint_t *)&vm->suspend, 0,
		    VM_SUSPEND_RESET);
		for (uint_t i = 0; i < vm->maxcpus; i++) {
			struct vcpu *vcpu = &vm->vcpu[i];

			if (CPU_ISSET(i, &vm->suspended_cpus) ||
			    !CPU_ISSET(i, &vm->active_cpus)) {
				continue;
			}

			vcpu_lock(vcpu);
			VERIFY3U(vcpu->state, ==, VCPU_FROZEN);
			CPU_SET_ATOMIC(i, &vm->suspended_cpus);
			vcpu_unlock(vcpu);
		}

		VERIFY0(CPU_CMP(&vm->suspended_cpus, &vm->active_cpus));
	}

	vm_cleanup(vm, false);
	vm_init(vm, false);
	return (0);
}

bool
vm_is_paused(struct vm *vm)
{
	return (vm->is_paused);
}

int
vm_pause_instance(struct vm *vm)
{
	if (vm->is_paused) {
		return (EALREADY);
	}
	vm->is_paused = true;

	for (uint_t i = 0; i < vm->maxcpus; i++) {
		struct vcpu *vcpu = &vm->vcpu[i];

		if (!CPU_ISSET(i, &vm->active_cpus)) {
			continue;
		}
		vlapic_pause(vcpu->vlapic);

		/*
		 * vCPU-specific pause logic includes stashing any
		 * to-be-injected events in exit_intinfo where it can be
		 * accessed in a manner generic to the backend.
		 */
		ops->vmpause(vm->cookie, i);
	}
	vhpet_pause(vm->vhpet);
	vatpit_pause(vm->vatpit);
	vrtc_pause(vm->vrtc);

	return (0);
}

int
vm_resume_instance(struct vm *vm)
{
	if (!vm->is_paused) {
		return (EALREADY);
	}
	vm->is_paused = false;

	vrtc_resume(vm->vrtc);
	vatpit_resume(vm->vatpit);
	vhpet_resume(vm->vhpet);
	for (uint_t i = 0; i < vm->maxcpus; i++) {
		struct vcpu *vcpu = &vm->vcpu[i];

		if (!CPU_ISSET(i, &vm->active_cpus)) {
			continue;
		}
		vlapic_resume(vcpu->vlapic);
	}

	return (0);
}

int
vm_map_mmio(struct vm *vm, vm_paddr_t gpa, size_t len, vm_paddr_t hpa)
{
	vm_object_t *obj;

	if ((obj = vmm_mmio_alloc(vm->vmspace, gpa, len, hpa)) == NULL)
		return (ENOMEM);
	else
		return (0);
}

int
vm_unmap_mmio(struct vm *vm, vm_paddr_t gpa, size_t len)
{
	return (vmspace_unmap(vm->vmspace, gpa, gpa + len));
}

/*
 * Return 'true' if 'gpa' is allocated in the guest address space.
 *
 * This function is called in the context of a running vcpu which acts as
 * an implicit lock on 'vm->mem_maps[]'.
 */
bool
vm_mem_allocated(struct vm *vm, int vcpuid, vm_paddr_t gpa)
{
	struct mem_map *mm;
	int i;

#ifdef INVARIANTS
	int hostcpu, state;
	state = vcpu_get_state(vm, vcpuid, &hostcpu);
	KASSERT(state == VCPU_RUNNING && hostcpu == curcpu,
	    ("%s: invalid vcpu state %d/%d", __func__, state, hostcpu));
#endif

	for (i = 0; i < VM_MAX_MEMMAPS; i++) {
		mm = &vm->mem_maps[i];
		if (mm->len != 0 && gpa >= mm->gpa && gpa < mm->gpa + mm->len)
			return (true);		/* 'gpa' is sysmem or devmem */
	}

	if (ppt_is_mmio(vm, gpa))
		return (true);			/* 'gpa' is pci passthru mmio */

	return (false);
}

int
vm_alloc_memseg(struct vm *vm, int ident, size_t len, bool sysmem)
{
	struct mem_seg *seg;
	vm_object_t *obj;

	if (ident < 0 || ident >= VM_MAX_MEMSEGS)
		return (EINVAL);

	if (len == 0 || (len & PAGE_MASK))
		return (EINVAL);

	seg = &vm->mem_segs[ident];
	if (seg->object != NULL) {
		if (seg->len == len && seg->sysmem == sysmem)
			return (EEXIST);
		else
			return (EINVAL);
	}

	obj = vm_object_mem_allocate(len, vm->mem_transient);
	if (obj == NULL)
		return (ENOMEM);

	seg->len = len;
	seg->object = obj;
	seg->sysmem = sysmem;
	return (0);
}

int
vm_get_memseg(struct vm *vm, int ident, size_t *len, bool *sysmem,
    vm_object_t **objptr)
{
	struct mem_seg *seg;

	if (ident < 0 || ident >= VM_MAX_MEMSEGS)
		return (EINVAL);

	seg = &vm->mem_segs[ident];
	if (len)
		*len = seg->len;
	if (sysmem)
		*sysmem = seg->sysmem;
	if (objptr)
		*objptr = seg->object;
	return (0);
}

void
vm_free_memseg(struct vm *vm, int ident)
{
	struct mem_seg *seg;

	KASSERT(ident >= 0 && ident < VM_MAX_MEMSEGS,
	    ("%s: invalid memseg ident %d", __func__, ident));

	seg = &vm->mem_segs[ident];
	if (seg->object != NULL) {
		vm_object_release(seg->object);
		bzero(seg, sizeof (struct mem_seg));
	}
}

int
vm_mmap_memseg(struct vm *vm, vm_paddr_t gpa, int segid, vm_ooffset_t first,
    size_t len, int prot, int flags)
{
	struct mem_seg *seg;
	struct mem_map *m, *map;
	vm_ooffset_t last;
	int i, error;

	if (prot == 0 || (prot & ~(PROT_ALL)) != 0)
		return (EINVAL);

	if (flags & ~VM_MEMMAP_F_WIRED)
		return (EINVAL);

	if (segid < 0 || segid >= VM_MAX_MEMSEGS)
		return (EINVAL);

	seg = &vm->mem_segs[segid];
	if (seg->object == NULL)
		return (EINVAL);

	last = first + len;
	if (first < 0 || first >= last || last > seg->len)
		return (EINVAL);

	if ((gpa | first | last) & PAGE_MASK)
		return (EINVAL);

	map = NULL;
	for (i = 0; i < VM_MAX_MEMMAPS; i++) {
		m = &vm->mem_maps[i];
		if (m->len == 0) {
			map = m;
			break;
		}
	}

	if (map == NULL)
		return (ENOSPC);

	error = vmspace_map(vm->vmspace, seg->object, first, gpa, len, prot);
	if (error != 0)
		return (EFAULT);

	vm_object_reference(seg->object);

	if ((flags & VM_MEMMAP_F_WIRED) != 0) {
		error = vmspace_populate(vm->vmspace, gpa, gpa + len);
		if (error != 0) {
			VERIFY0(vmspace_unmap(vm->vmspace, gpa, gpa + len));
			return (EFAULT);
		}
	}

	map->gpa = gpa;
	map->len = len;
	map->segoff = first;
	map->segid = segid;
	map->prot = prot;
	map->flags = flags;
	return (0);
}

int
vm_munmap_memseg(struct vm *vm, vm_paddr_t gpa, size_t len)
{
	struct mem_map *m;
	int i;

	for (i = 0; i < VM_MAX_MEMMAPS; i++) {
		m = &vm->mem_maps[i];
		if (m->gpa == gpa && m->len == len &&
		    (m->flags & VM_MEMMAP_F_IOMMU) == 0) {
			vm_free_memmap(vm, i);
			return (0);
		}
	}

	return (EINVAL);
}

int
vm_mmap_getnext(struct vm *vm, vm_paddr_t *gpa, int *segid,
    vm_ooffset_t *segoff, size_t *len, int *prot, int *flags)
{
	struct mem_map *mm, *mmnext;
	int i;

	mmnext = NULL;
	for (i = 0; i < VM_MAX_MEMMAPS; i++) {
		mm = &vm->mem_maps[i];
		if (mm->len == 0 || mm->gpa < *gpa)
			continue;
		if (mmnext == NULL || mm->gpa < mmnext->gpa)
			mmnext = mm;
	}

	if (mmnext != NULL) {
		*gpa = mmnext->gpa;
		if (segid)
			*segid = mmnext->segid;
		if (segoff)
			*segoff = mmnext->segoff;
		if (len)
			*len = mmnext->len;
		if (prot)
			*prot = mmnext->prot;
		if (flags)
			*flags = mmnext->flags;
		return (0);
	} else {
		return (ENOENT);
	}
}

static void
vm_free_memmap(struct vm *vm, int ident)
{
	struct mem_map *mm;
	int error;

	mm = &vm->mem_maps[ident];
	if (mm->len) {
		error = vmspace_unmap(vm->vmspace, mm->gpa,
		    mm->gpa + mm->len);
		KASSERT(error == 0, ("%s: vmspace_unmap error %d",
		    __func__, error));
		bzero(mm, sizeof (struct mem_map));
	}
}

static __inline bool
sysmem_mapping(struct vm *vm, struct mem_map *mm)
{

	if (mm->len != 0 && vm->mem_segs[mm->segid].sysmem)
		return (true);
	else
		return (false);
}

vm_paddr_t
vmm_sysmem_maxaddr(struct vm *vm)
{
	struct mem_map *mm;
	vm_paddr_t maxaddr;
	int i;

	maxaddr = 0;
	for (i = 0; i < VM_MAX_MEMMAPS; i++) {
		mm = &vm->mem_maps[i];
		if (sysmem_mapping(vm, mm)) {
			if (maxaddr < mm->gpa + mm->len)
				maxaddr = mm->gpa + mm->len;
		}
	}
	return (maxaddr);
}

static void
vm_iommu_modify(struct vm *vm, bool map)
{
	int i, sz;
	vm_paddr_t gpa, hpa;
	struct mem_map *mm;
	vm_client_t *vmc;

	sz = PAGE_SIZE;
	vmc = vmspace_client_alloc(vm->vmspace);

	for (i = 0; i < VM_MAX_MEMMAPS; i++) {
		mm = &vm->mem_maps[i];
		if (!sysmem_mapping(vm, mm))
			continue;

		if (map) {
			KASSERT((mm->flags & VM_MEMMAP_F_IOMMU) == 0,
			    ("iommu map found invalid memmap %lx/%lx/%x",
			    mm->gpa, mm->len, mm->flags));
			if ((mm->flags & VM_MEMMAP_F_WIRED) == 0)
				continue;
			mm->flags |= VM_MEMMAP_F_IOMMU;
		} else {
			if ((mm->flags & VM_MEMMAP_F_IOMMU) == 0)
				continue;
			mm->flags &= ~VM_MEMMAP_F_IOMMU;
			KASSERT((mm->flags & VM_MEMMAP_F_WIRED) != 0,
			    ("iommu unmap found invalid memmap %lx/%lx/%x",
			    mm->gpa, mm->len, mm->flags));
		}

		gpa = mm->gpa;
		while (gpa < mm->gpa + mm->len) {
			vm_page_t *vmp;

			vmp = vmc_hold(vmc, gpa, PROT_WRITE);
			ASSERT(vmp != NULL);
			hpa = ((uintptr_t)vmp_get_pfn(vmp) << PAGESHIFT);
			(void) vmp_release(vmp);

			/*
			 * When originally ported from FreeBSD, the logic for
			 * adding memory to the guest domain would
			 * simultaneously remove it from the host domain.  The
			 * justification for that is not clear, and FreeBSD has
			 * subsequently changed the behavior to not remove the
			 * memory from the host domain.
			 *
			 * Leaving the guest memory in the host domain for the
			 * life of the VM is necessary to make it available for
			 * DMA, such as through viona in the TX path.
			 */
			if (map) {
				iommu_create_mapping(vm->iommu, gpa, hpa, sz);
			} else {
				iommu_remove_mapping(vm->iommu, gpa, sz);
			}

			gpa += PAGE_SIZE;
		}
	}
	vmc_destroy(vmc);

	/*
	 * Invalidate the cached translations associated with the domain
	 * from which pages were removed.
	 */
	iommu_invalidate_tlb(vm->iommu);
}

int
vm_unassign_pptdev(struct vm *vm, int pptfd)
{
	int error;

	error = ppt_unassign_device(vm, pptfd);
	if (error)
		return (error);

	if (ppt_assigned_devices(vm) == 0)
		vm_iommu_modify(vm, false);

	return (0);
}

int
vm_assign_pptdev(struct vm *vm, int pptfd)
{
	int error;
	vm_paddr_t maxaddr;

	/* Set up the IOMMU to do the 'gpa' to 'hpa' translation */
	if (ppt_assigned_devices(vm) == 0) {
		KASSERT(vm->iommu == NULL,
		    ("vm_assign_pptdev: iommu must be NULL"));
		maxaddr = vmm_sysmem_maxaddr(vm);
		vm->iommu = iommu_create_domain(maxaddr);
		if (vm->iommu == NULL)
			return (ENXIO);
		vm_iommu_modify(vm, true);
	}

	error = ppt_assign_device(vm, pptfd);
	return (error);
}

int
vm_get_register(struct vm *vm, int vcpuid, int reg, uint64_t *retval)
{
	if (vcpuid < 0 || vcpuid >= vm->maxcpus)
		return (EINVAL);

	if (reg >= VM_REG_LAST)
		return (EINVAL);

	struct vcpu *vcpu = &vm->vcpu[vcpuid];
	switch (reg) {
	case VM_REG_GUEST_XCR0:
		*retval = vcpu->guest_xcr0;
		return (0);
	default:
		return (VMGETREG(vm->cookie, vcpuid, reg, retval));
	}
}

int
vm_set_register(struct vm *vm, int vcpuid, int reg, uint64_t val)
{
	if (vcpuid < 0 || vcpuid >= vm->maxcpus)
		return (EINVAL);

	if (reg >= VM_REG_LAST)
		return (EINVAL);

	int error;
	struct vcpu *vcpu = &vm->vcpu[vcpuid];
	switch (reg) {
	case VM_REG_GUEST_RIP:
		error = VMSETREG(vm->cookie, vcpuid, reg, val);
		if (error == 0) {
			vcpu->nextrip = val;
		}
		return (error);
	case VM_REG_GUEST_XCR0:
		if (!validate_guest_xcr0(val, vmm_get_host_xcr0())) {
			return (EINVAL);
		}
		vcpu->guest_xcr0 = val;
		return (0);
	default:
		return (VMSETREG(vm->cookie, vcpuid, reg, val));
	}
}

static bool
is_descriptor_table(int reg)
{
	switch (reg) {
	case VM_REG_GUEST_IDTR:
	case VM_REG_GUEST_GDTR:
		return (true);
	default:
		return (false);
	}
}

static bool
is_segment_register(int reg)
{
	switch (reg) {
	case VM_REG_GUEST_ES:
	case VM_REG_GUEST_CS:
	case VM_REG_GUEST_SS:
	case VM_REG_GUEST_DS:
	case VM_REG_GUEST_FS:
	case VM_REG_GUEST_GS:
	case VM_REG_GUEST_TR:
	case VM_REG_GUEST_LDTR:
		return (true);
	default:
		return (false);
	}
}

int
vm_get_seg_desc(struct vm *vm, int vcpu, int reg, struct seg_desc *desc)
{

	if (vcpu < 0 || vcpu >= vm->maxcpus)
		return (EINVAL);

	if (!is_segment_register(reg) && !is_descriptor_table(reg))
		return (EINVAL);

	return (VMGETDESC(vm->cookie, vcpu, reg, desc));
}

int
vm_set_seg_desc(struct vm *vm, int vcpu, int reg, const struct seg_desc *desc)
{
	if (vcpu < 0 || vcpu >= vm->maxcpus)
		return (EINVAL);

	if (!is_segment_register(reg) && !is_descriptor_table(reg))
		return (EINVAL);

	return (VMSETDESC(vm->cookie, vcpu, reg, desc));
}

static int
translate_hma_xsave_result(hma_fpu_xsave_result_t res)
{
	switch (res) {
	case HFXR_OK:
		return (0);
	case HFXR_NO_SPACE:
		return (ENOSPC);
	case HFXR_BAD_ALIGN:
	case HFXR_UNSUP_FMT:
	case HFXR_UNSUP_FEAT:
	case HFXR_INVALID_DATA:
		return (EINVAL);
	default:
		panic("unexpected xsave result");
	}
}

int
vm_get_fpu(struct vm *vm, int vcpuid, void *buf, size_t len)
{
	if (vcpuid < 0 || vcpuid >= vm->maxcpus)
		return (EINVAL);

	struct vcpu *vcpu = &vm->vcpu[vcpuid];
	hma_fpu_xsave_result_t res;

	res = hma_fpu_get_xsave_state(vcpu->guestfpu, buf, len);
	return (translate_hma_xsave_result(res));
}

int
vm_set_fpu(struct vm *vm, int vcpuid, void *buf, size_t len)
{
	if (vcpuid < 0 || vcpuid >= vm->maxcpus)
		return (EINVAL);

	struct vcpu *vcpu = &vm->vcpu[vcpuid];
	hma_fpu_xsave_result_t res;

	res = hma_fpu_set_xsave_state(vcpu->guestfpu, buf, len);
	return (translate_hma_xsave_result(res));
}

int
vm_get_run_state(struct vm *vm, int vcpuid, uint32_t *state, uint8_t *sipi_vec)
{
	struct vcpu *vcpu;

	if (vcpuid < 0 || vcpuid >= vm->maxcpus) {
		return (EINVAL);
	}

	vcpu = &vm->vcpu[vcpuid];

	vcpu_lock(vcpu);
	*state = vcpu->run_state;
	*sipi_vec = vcpu->sipi_vector;
	vcpu_unlock(vcpu);

	return (0);
}

int
vm_set_run_state(struct vm *vm, int vcpuid, uint32_t state, uint8_t sipi_vec)
{
	struct vcpu *vcpu;

	if (vcpuid < 0 || vcpuid >= vm->maxcpus) {
		return (EINVAL);
	}
	if (!VRS_IS_VALID(state)) {
		return (EINVAL);
	}

	vcpu = &vm->vcpu[vcpuid];

	vcpu_lock(vcpu);
	vcpu->run_state = state;
	vcpu->sipi_vector = sipi_vec;
	vcpu_notify_event_locked(vcpu, VCPU_NOTIFY_EXIT);
	vcpu_unlock(vcpu);

	return (0);
}

int
vm_track_dirty_pages(struct vm *vm, uint64_t gpa, size_t len, uint8_t *bitmap)
{
	vmspace_t *vms = vm_get_vmspace(vm);
	return (vmspace_track_dirty(vms, gpa, len, bitmap));
}

static void
restore_guest_fpustate(struct vcpu *vcpu)
{
	/* Save host FPU and restore guest FPU */
	fpu_stop_emulating();
	hma_fpu_start_guest(vcpu->guestfpu);

	/* restore guest XCR0 if XSAVE is enabled in the host */
	if (rcr4() & CR4_XSAVE)
		load_xcr(0, vcpu->guest_xcr0);

	/*
	 * The FPU is now "dirty" with the guest's state so turn on emulation
	 * to trap any access to the FPU by the host.
	 */
	fpu_start_emulating();
}

static void
save_guest_fpustate(struct vcpu *vcpu)
{

	if ((rcr0() & CR0_TS) == 0)
		panic("fpu emulation not enabled in host!");

	/* save guest XCR0 and restore host XCR0 */
	if (rcr4() & CR4_XSAVE) {
		vcpu->guest_xcr0 = rxcr(0);
		load_xcr(0, vmm_get_host_xcr0());
	}

	/* save guest FPU and restore host FPU */
	fpu_stop_emulating();
	hma_fpu_stop_guest(vcpu->guestfpu);
	/*
	 * When the host state has been restored, we should not re-enable
	 * CR0.TS on illumos for eager FPU.
	 */
}

static int
vcpu_set_state_locked(struct vm *vm, int vcpuid, enum vcpu_state newstate,
    bool from_idle)
{
	struct vcpu *vcpu;
	int error;

	vcpu = &vm->vcpu[vcpuid];
	vcpu_assert_locked(vcpu);

	/*
	 * State transitions from the vmmdev_ioctl() must always begin from
	 * the VCPU_IDLE state. This guarantees that there is only a single
	 * ioctl() operating on a vcpu at any point.
	 */
	if (from_idle) {
		while (vcpu->state != VCPU_IDLE) {
			vcpu->reqidle = 1;
			vcpu_notify_event_locked(vcpu, VCPU_NOTIFY_EXIT);
			cv_wait(&vcpu->state_cv, &vcpu->lock);
		}
	} else {
		KASSERT(vcpu->state != VCPU_IDLE, ("invalid transition from "
		    "vcpu idle state"));
	}

	if (vcpu->state == VCPU_RUNNING) {
		KASSERT(vcpu->hostcpu == curcpu, ("curcpu %d and hostcpu %d "
		    "mismatch for running vcpu", curcpu, vcpu->hostcpu));
	} else {
		KASSERT(vcpu->hostcpu == NOCPU, ("Invalid hostcpu %d for a "
		    "vcpu that is not running", vcpu->hostcpu));
	}

	/*
	 * The following state transitions are allowed:
	 * IDLE -> FROZEN -> IDLE
	 * FROZEN -> RUNNING -> FROZEN
	 * FROZEN -> SLEEPING -> FROZEN
	 */
	switch (vcpu->state) {
	case VCPU_IDLE:
	case VCPU_RUNNING:
	case VCPU_SLEEPING:
		error = (newstate != VCPU_FROZEN);
		break;
	case VCPU_FROZEN:
		error = (newstate == VCPU_FROZEN);
		break;
	default:
		error = 1;
		break;
	}

	if (error)
		return (EBUSY);

	vcpu->state = newstate;
	if (newstate == VCPU_RUNNING)
		vcpu->hostcpu = curcpu;
	else
		vcpu->hostcpu = NOCPU;

	if (newstate == VCPU_IDLE) {
		cv_broadcast(&vcpu->state_cv);
	}

	return (0);
}

static void
vcpu_require_state(struct vm *vm, int vcpuid, enum vcpu_state newstate)
{
	int error;

	if ((error = vcpu_set_state(vm, vcpuid, newstate, false)) != 0)
		panic("Error %d setting state to %d\n", error, newstate);
}

static void
vcpu_require_state_locked(struct vm *vm, int vcpuid, enum vcpu_state newstate)
{
	int error;

	if ((error = vcpu_set_state_locked(vm, vcpuid, newstate, false)) != 0)
		panic("Error %d setting state to %d", error, newstate);
}

/*
 * Emulate a guest 'hlt' by sleeping until the vcpu is ready to run.
 */
static int
vm_handle_hlt(struct vm *vm, int vcpuid, bool intr_disabled)
{
	struct vcpu *vcpu;
	int vcpu_halted, vm_halted;
	bool userspace_exit = false;

	KASSERT(!CPU_ISSET(vcpuid, &vm->halted_cpus), ("vcpu already halted"));

	vcpu = &vm->vcpu[vcpuid];
	vcpu_halted = 0;
	vm_halted = 0;

	vcpu_lock(vcpu);
	while (1) {
		/*
		 * Do a final check for pending interrupts (including NMI and
		 * INIT) before putting this thread to sleep.
		 */
		if (vm_nmi_pending(vm, vcpuid))
			break;
		if (vcpu_run_state_pending(vm, vcpuid))
			break;
		if (!intr_disabled) {
			if (vm_extint_pending(vm, vcpuid) ||
			    vlapic_pending_intr(vcpu->vlapic, NULL)) {
				break;
			}
		}

		/*
		 * Also check for software events which would cause a wake-up.
		 * This will set the appropriate exitcode directly, rather than
		 * requiring a trip through VM_RUN().
		 */
		if (vcpu_sleep_bailout_checks(vm, vcpuid)) {
			userspace_exit = true;
			break;
		}

		/*
		 * Some Linux guests implement "halt" by having all vcpus
		 * execute HLT with interrupts disabled. 'halted_cpus' keeps
		 * track of the vcpus that have entered this state. When all
		 * vcpus enter the halted state the virtual machine is halted.
		 */
		if (intr_disabled) {
			if (!vcpu_halted && halt_detection_enabled) {
				vcpu_halted = 1;
				CPU_SET_ATOMIC(vcpuid, &vm->halted_cpus);
			}
			if (CPU_CMP(&vm->halted_cpus, &vm->active_cpus) == 0) {
				vm_halted = 1;
				break;
			}
		}

		vcpu_ustate_change(vm, vcpuid, VU_IDLE);
		vcpu_require_state_locked(vm, vcpuid, VCPU_SLEEPING);
		(void) cv_wait_sig(&vcpu->vcpu_cv, &vcpu->lock);
		vcpu_require_state_locked(vm, vcpuid, VCPU_FROZEN);
		vcpu_ustate_change(vm, vcpuid, VU_EMU_KERN);
	}

	if (vcpu_halted)
		CPU_CLR_ATOMIC(vcpuid, &vm->halted_cpus);

	vcpu_unlock(vcpu);

	if (vm_halted) {
		(void) vm_suspend(vm, VM_SUSPEND_HALT);
	}

	return (userspace_exit ? -1 : 0);
}

static int
vm_handle_paging(struct vm *vm, int vcpuid)
{
	struct vcpu *vcpu = &vm->vcpu[vcpuid];
	vm_client_t *vmc = vcpu->vmclient;
	struct vm_exit *vme = &vcpu->exitinfo;
	const int ftype = vme->u.paging.fault_type;

	ASSERT0(vme->inst_length);
	ASSERT(ftype == PROT_READ || ftype == PROT_WRITE || ftype == PROT_EXEC);

	if (vmc_fault(vmc, vme->u.paging.gpa, ftype) != 0) {
		/*
		 * If the fault cannot be serviced, kick it out to userspace for
		 * handling (or more likely, halting the instance).
		 */
		return (-1);
	}

	return (0);
}

int
vm_service_mmio_read(struct vm *vm, int cpuid, uint64_t gpa, uint64_t *rval,
    int rsize)
{
	int err = ESRCH;

	if (gpa >= DEFAULT_APIC_BASE && gpa < DEFAULT_APIC_BASE + PAGE_SIZE) {
		struct vlapic *vlapic = vm_lapic(vm, cpuid);

		err = vlapic_mmio_read(vlapic, gpa, rval, rsize);
	} else if (gpa >= VIOAPIC_BASE && gpa < VIOAPIC_BASE + VIOAPIC_SIZE) {
		err = vioapic_mmio_read(vm, cpuid, gpa, rval, rsize);
	} else if (gpa >= VHPET_BASE && gpa < VHPET_BASE + VHPET_SIZE) {
		err = vhpet_mmio_read(vm, cpuid, gpa, rval, rsize);
	}

	return (err);
}

int
vm_service_mmio_write(struct vm *vm, int cpuid, uint64_t gpa, uint64_t wval,
    int wsize)
{
	int err = ESRCH;

	if (gpa >= DEFAULT_APIC_BASE && gpa < DEFAULT_APIC_BASE + PAGE_SIZE) {
		struct vlapic *vlapic = vm_lapic(vm, cpuid);

		err = vlapic_mmio_write(vlapic, gpa, wval, wsize);
	} else if (gpa >= VIOAPIC_BASE && gpa < VIOAPIC_BASE + VIOAPIC_SIZE) {
		err = vioapic_mmio_write(vm, cpuid, gpa, wval, wsize);
	} else if (gpa >= VHPET_BASE && gpa < VHPET_BASE + VHPET_SIZE) {
		err = vhpet_mmio_write(vm, cpuid, gpa, wval, wsize);
	}

	return (err);
}

static int
vm_handle_mmio_emul(struct vm *vm, int vcpuid)
{
	struct vie *vie;
	struct vcpu *vcpu;
	struct vm_exit *vme;
	uint64_t inst_addr;
	int error, fault, cs_d;

	vcpu = &vm->vcpu[vcpuid];
	vme = &vcpu->exitinfo;
	vie = vcpu->vie_ctx;

	KASSERT(vme->inst_length == 0, ("%s: invalid inst_length %d",
	    __func__, vme->inst_length));

	inst_addr = vme->rip + vme->u.mmio_emul.cs_base;
	cs_d = vme->u.mmio_emul.cs_d;

	/* Fetch the faulting instruction */
	if (vie_needs_fetch(vie)) {
		error = vie_fetch_instruction(vie, vm, vcpuid, inst_addr,
		    &fault);
		if (error != 0) {
			return (error);
		} else if (fault) {
			/*
			 * If a fault during instruction fetch was encountered,
			 * it will have asserted that the appropriate exception
			 * be injected at next entry.
			 * No further work is required.
			 */
			return (0);
		}
	}

	if (vie_decode_instruction(vie, vm, vcpuid, cs_d) != 0) {
		/* Dump (unrecognized) instruction bytes in userspace */
		vie_fallback_exitinfo(vie, vme);
		return (-1);
	}
	if (vme->u.mmio_emul.gla != VIE_INVALID_GLA &&
	    vie_verify_gla(vie, vm, vcpuid, vme->u.mmio_emul.gla) != 0) {
		/* Decoded GLA does not match GLA from VM exit state */
		vie_fallback_exitinfo(vie, vme);
		return (-1);
	}

repeat:
	error = vie_emulate_mmio(vie, vm, vcpuid);
	if (error < 0) {
		/*
		 * MMIO not handled by any of the in-kernel-emulated devices, so
		 * make a trip out to userspace for it.
		 */
		vie_exitinfo(vie, vme);
	} else if (error == EAGAIN) {
		/*
		 * Continue emulating the rep-prefixed instruction, which has
		 * not completed its iterations.
		 *
		 * In case this can be emulated in-kernel and has a high
		 * repetition count (causing a tight spin), it should be
		 * deferential to yield conditions.
		 */
		if (!vcpu_should_yield(vm, vcpuid)) {
			goto repeat;
		} else {
			/*
			 * Defer to the contending load by making a trip to
			 * userspace with a no-op (BOGUS) exit reason.
			 */
			vie_reset(vie);
			vme->exitcode = VM_EXITCODE_BOGUS;
			return (-1);
		}
	} else if (error == 0) {
		/* Update %rip now that instruction has been emulated */
		vie_advance_pc(vie, &vcpu->nextrip);
	}
	return (error);
}

static int
vm_handle_inout(struct vm *vm, int vcpuid, struct vm_exit *vme)
{
	struct vcpu *vcpu;
	struct vie *vie;
	int err;

	vcpu = &vm->vcpu[vcpuid];
	vie = vcpu->vie_ctx;

repeat:
	err = vie_emulate_inout(vie, vm, vcpuid);

	if (err < 0) {
		/*
		 * In/out not handled by any of the in-kernel-emulated devices,
		 * so make a trip out to userspace for it.
		 */
		vie_exitinfo(vie, vme);
		return (err);
	} else if (err == EAGAIN) {
		/*
		 * Continue emulating the rep-prefixed ins/outs, which has not
		 * completed its iterations.
		 *
		 * In case this can be emulated in-kernel and has a high
		 * repetition count (causing a tight spin), it should be
		 * deferential to yield conditions.
		 */
		if (!vcpu_should_yield(vm, vcpuid)) {
			goto repeat;
		} else {
			/*
			 * Defer to the contending load by making a trip to
			 * userspace with a no-op (BOGUS) exit reason.
			 */
			vie_reset(vie);
			vme->exitcode = VM_EXITCODE_BOGUS;
			return (-1);
		}
	} else if (err != 0) {
		/* Emulation failure.  Bail all the way out to userspace. */
		vme->exitcode = VM_EXITCODE_INST_EMUL;
		bzero(&vme->u.inst_emul, sizeof (vme->u.inst_emul));
		return (-1);
	}

	vie_advance_pc(vie, &vcpu->nextrip);
	return (0);
}

static int
vm_handle_inst_emul(struct vm *vm, int vcpuid)
{
	struct vie *vie;
	struct vcpu *vcpu;
	struct vm_exit *vme;
	uint64_t cs_base;
	int error, fault, cs_d;

	vcpu = &vm->vcpu[vcpuid];
	vme = &vcpu->exitinfo;
	vie = vcpu->vie_ctx;

	vie_cs_info(vie, vm, vcpuid, &cs_base, &cs_d);

	/* Fetch the faulting instruction */
	ASSERT(vie_needs_fetch(vie));
	error = vie_fetch_instruction(vie, vm, vcpuid, vme->rip + cs_base,
	    &fault);
	if (error != 0) {
		return (error);
	} else if (fault) {
		/*
		 * If a fault during instruction fetch was encounted, it will
		 * have asserted that the appropriate exception be injected at
		 * next entry.  No further work is required.
		 */
		return (0);
	}

	if (vie_decode_instruction(vie, vm, vcpuid, cs_d) != 0) {
		/* Dump (unrecognized) instruction bytes in userspace */
		vie_fallback_exitinfo(vie, vme);
		return (-1);
	}

	error = vie_emulate_other(vie, vm, vcpuid);
	if (error != 0) {
		/*
		 * Instruction emulation was unable to complete successfully, so
		 * kick it out to userspace for handling.
		 */
		vie_fallback_exitinfo(vie, vme);
	} else {
		/* Update %rip now that instruction has been emulated */
		vie_advance_pc(vie, &vcpu->nextrip);
	}
	return (error);
}

static int
vm_handle_suspend(struct vm *vm, int vcpuid)
{
	int i;
	struct vcpu *vcpu;

	vcpu = &vm->vcpu[vcpuid];

	CPU_SET_ATOMIC(vcpuid, &vm->suspended_cpus);

	/*
	 * Wait until all 'active_cpus' have suspended themselves.
	 */
	vcpu_lock(vcpu);
	vcpu_ustate_change(vm, vcpuid, VU_INIT);
	while (1) {
		int rc;

		if (CPU_CMP(&vm->suspended_cpus, &vm->active_cpus) == 0) {
			break;
		}

		vcpu_require_state_locked(vm, vcpuid, VCPU_SLEEPING);
		rc = cv_reltimedwait_sig(&vcpu->vcpu_cv, &vcpu->lock, hz,
		    TR_CLOCK_TICK);
		vcpu_require_state_locked(vm, vcpuid, VCPU_FROZEN);

		/*
		 * If the userspace process driving the instance is killed, any
		 * vCPUs yet to be marked suspended (because they are not
		 * VM_RUN-ing in the kernel presently) will never reach that
		 * state.
		 *
		 * To avoid vm_handle_suspend() getting stuck in the kernel
		 * waiting for those vCPUs, offer a bail-out even though it
		 * means returning without all vCPUs in a suspended state.
		 */
		if (rc <= 0) {
			if ((curproc->p_flag & SEXITING) != 0) {
				break;
			}
		}
	}
	vcpu_unlock(vcpu);

	/*
	 * Wakeup the other sleeping vcpus and return to userspace.
	 */
	for (i = 0; i < vm->maxcpus; i++) {
		if (CPU_ISSET(i, &vm->suspended_cpus)) {
			vcpu_notify_event(vm, i);
		}
	}

	return (-1);
}

static int
vm_handle_reqidle(struct vm *vm, int vcpuid)
{
	struct vcpu *vcpu = &vm->vcpu[vcpuid];

	vcpu_lock(vcpu);
	KASSERT(vcpu->reqidle, ("invalid vcpu reqidle %d", vcpu->reqidle));
	vcpu->reqidle = 0;
	vcpu_unlock(vcpu);
	return (-1);
}

static int
vm_handle_run_state(struct vm *vm, int vcpuid)
{
	struct vcpu *vcpu = &vm->vcpu[vcpuid];
	bool handled = false;

	vcpu_lock(vcpu);
	while (1) {
		if ((vcpu->run_state & VRS_PEND_INIT) != 0) {
			vcpu_unlock(vcpu);
			VERIFY0(vcpu_arch_reset(vm, vcpuid, true));
			vcpu_lock(vcpu);

			vcpu->run_state &= ~(VRS_RUN | VRS_PEND_INIT);
			vcpu->run_state |= VRS_INIT;
		}

		if ((vcpu->run_state & (VRS_INIT | VRS_RUN | VRS_PEND_SIPI)) ==
		    (VRS_INIT | VRS_PEND_SIPI)) {
			const uint8_t vector = vcpu->sipi_vector;

			vcpu_unlock(vcpu);
			VERIFY0(vcpu_vector_sipi(vm, vcpuid, vector));
			vcpu_lock(vcpu);

			vcpu->run_state &= ~VRS_PEND_SIPI;
			vcpu->run_state |= VRS_RUN;
		}

		/*
		 * If the vCPU is now in the running state, there is no need to
		 * wait for anything prior to re-entry.
		 */
		if ((vcpu->run_state & VRS_RUN) != 0) {
			handled = true;
			break;
		}

		/*
		 * Also check for software events which would cause a wake-up.
		 * This will set the appropriate exitcode directly, rather than
		 * requiring a trip through VM_RUN().
		 */
		if (vcpu_sleep_bailout_checks(vm, vcpuid)) {
			break;
		}

		vcpu_ustate_change(vm, vcpuid, VU_IDLE);
		vcpu_require_state_locked(vm, vcpuid, VCPU_SLEEPING);
		(void) cv_wait_sig(&vcpu->vcpu_cv, &vcpu->lock);
		vcpu_require_state_locked(vm, vcpuid, VCPU_FROZEN);
		vcpu_ustate_change(vm, vcpuid, VU_EMU_KERN);
	}
	vcpu_unlock(vcpu);

	return (handled ? 0 : -1);
}

static int
vm_rdmtrr(const struct vm_mtrr *mtrr, uint32_t num, uint64_t *val)
{
	switch (num) {
	case MSR_MTRRcap:
		*val = MTRR_CAP_WC | MTRR_CAP_FIXED | VMM_MTRR_VAR_MAX;
		break;
	case MSR_MTRRdefType:
		*val = mtrr->def_type;
		break;
	case MSR_MTRR4kBase ... MSR_MTRR4kBase + 7:
		*val = mtrr->fixed4k[num - MSR_MTRR4kBase];
		break;
	case MSR_MTRR16kBase ... MSR_MTRR16kBase + 1:
		*val = mtrr->fixed16k[num - MSR_MTRR16kBase];
		break;
	case MSR_MTRR64kBase:
		*val = mtrr->fixed64k;
		break;
	case MSR_MTRRVarBase ... MSR_MTRRVarBase + (VMM_MTRR_VAR_MAX * 2) - 1: {
		uint_t offset = num - MSR_MTRRVarBase;
		if (offset % 2 == 0) {
			*val = mtrr->var[offset / 2].base;
		} else {
			*val = mtrr->var[offset / 2].mask;
		}
		break;
	}
	default:
		return (-1);
	}

	return (0);
}

static int
vm_wrmtrr(struct vm_mtrr *mtrr, uint32_t num, uint64_t val)
{
	switch (num) {
	case MSR_MTRRcap:
		/* MTRRCAP is read only */
		return (-1);
	case MSR_MTRRdefType:
		if (val & ~VMM_MTRR_DEF_MASK) {
			/* generate #GP on writes to reserved fields */
			return (-1);
		}
		mtrr->def_type = val;
		break;
	case MSR_MTRR4kBase ... MSR_MTRR4kBase + 7:
		mtrr->fixed4k[num - MSR_MTRR4kBase] = val;
		break;
	case MSR_MTRR16kBase ... MSR_MTRR16kBase + 1:
		mtrr->fixed16k[num - MSR_MTRR16kBase] = val;
		break;
	case MSR_MTRR64kBase:
		mtrr->fixed64k = val;
		break;
	case MSR_MTRRVarBase ... MSR_MTRRVarBase + (VMM_MTRR_VAR_MAX * 2) - 1: {
		uint_t offset = num - MSR_MTRRVarBase;
		if (offset % 2 == 0) {
			if (val & ~VMM_MTRR_PHYSBASE_MASK) {
				/* generate #GP on writes to reserved fields */
				return (-1);
			}
			mtrr->var[offset / 2].base = val;
		} else {
			if (val & ~VMM_MTRR_PHYSMASK_MASK) {
				/* generate #GP on writes to reserved fields */
				return (-1);
			}
			mtrr->var[offset / 2].mask = val;
		}
		break;
	}
	default:
		return (-1);
	}

	return (0);
}

static bool
is_mtrr_msr(uint32_t msr)
{
	switch (msr) {
	case MSR_MTRRcap:
	case MSR_MTRRdefType:
	case MSR_MTRR4kBase ... MSR_MTRR4kBase + 7:
	case MSR_MTRR16kBase ... MSR_MTRR16kBase + 1:
	case MSR_MTRR64kBase:
	case MSR_MTRRVarBase ... MSR_MTRRVarBase + (VMM_MTRR_VAR_MAX * 2) - 1:
		return (true);
	default:
		return (false);
	}
}

static int
vm_handle_rdmsr(struct vm *vm, int vcpuid, struct vm_exit *vme)
{
	struct vcpu *vcpu = &vm->vcpu[vcpuid];
	const uint32_t code = vme->u.msr.code;
	uint64_t val = 0;

	switch (code) {
	case MSR_MCG_CAP:
	case MSR_MCG_STATUS:
		val = 0;
		break;

	case MSR_MTRRcap:
	case MSR_MTRRdefType:
	case MSR_MTRR4kBase ... MSR_MTRR4kBase + 7:
	case MSR_MTRR16kBase ... MSR_MTRR16kBase + 1:
	case MSR_MTRR64kBase:
	case MSR_MTRRVarBase ... MSR_MTRRVarBase + (VMM_MTRR_VAR_MAX * 2) - 1:
		if (vm_rdmtrr(&vcpu->mtrr, code, &val) != 0)
			vm_inject_gp(vm, vcpuid);
		break;

	case MSR_TSC:
		/*
		 * In all likelihood, this should always be handled in guest
		 * context by VMX/SVM rather than taking an exit.  (Both VMX and
		 * SVM pass through read-only access to MSR_TSC to the guest.)
		 *
		 * No physical offset is requested of vcpu_tsc_offset() since
		 * rdtsc_offset() takes care of that instead.
		 */
		val = vcpu_tsc_offset(vm, vcpuid, false) + rdtsc_offset();
		break;

	default:
		/*
		 * Anything not handled at this point will be kicked out to
		 * userspace for attempted processing there.
		 */
		return (-1);
	}

	VERIFY0(vm_set_register(vm, vcpuid, VM_REG_GUEST_RAX,
	    val & 0xffffffff));
	VERIFY0(vm_set_register(vm, vcpuid, VM_REG_GUEST_RDX,
	    val >> 32));
	return (0);
}

static int
vm_handle_wrmsr(struct vm *vm, int vcpuid, struct vm_exit *vme)
{
	struct vcpu *vcpu = &vm->vcpu[vcpuid];
	const uint32_t code = vme->u.msr.code;
	const uint64_t val = vme->u.msr.wval;

	switch (code) {
	case MSR_MCG_CAP:
	case MSR_MCG_STATUS:
		/* Ignore writes */
		break;

	case MSR_MTRRcap:
	case MSR_MTRRdefType:
	case MSR_MTRR4kBase ... MSR_MTRR4kBase + 7:
	case MSR_MTRR16kBase ... MSR_MTRR16kBase + 1:
	case MSR_MTRR64kBase:
	case MSR_MTRRVarBase ... MSR_MTRRVarBase + (VMM_MTRR_VAR_MAX * 2) - 1:
		if (vm_wrmtrr(&vcpu->mtrr, code, val) != 0)
			vm_inject_gp(vm, vcpuid);
		break;

	case MSR_TSC:
		/*
		 * The effect of writing the TSC MSR is that a subsequent read
		 * of the TSC would report that value written (plus any time
		 * elapsed between the write and the read).  The guest TSC value
		 * is calculated from a global offset for the guest (which
		 * effectively makes its TSC read 0 at guest boot) and a
		 * per-vCPU offset to handle these writes to the MSR.
		 *
		 * To calculate that per-vCPU offset, we can work backwards from
		 * the guest value at the time of write:
		 *
		 * value = host TSC + VM boot offset + vCPU offset
		 *
		 * so therefore:
		 *
		 * value - host TSC - VM boot offset = vCPU offset
		 */
		vcpu->tsc_offset = val - vm->boot_tsc_offset - rdtsc_offset();
		break;

	default:
		/*
		 * Anything not handled at this point will be kicked out to
		 * userspace for attempted processing there.
		 */
		return (-1);
	}

	return (0);
}

int
vm_suspend(struct vm *vm, enum vm_suspend_how how)
{
	if (how <= VM_SUSPEND_NONE || how >= VM_SUSPEND_LAST)
		return (EINVAL);

	if (atomic_cmpset_int((uint_t *)&vm->suspend, 0, how) == 0) {
		return (EALREADY);
	}

	/*
	 * Notify all active vcpus that they are now suspended.
	 */
	for (uint_t i = 0; i < vm->maxcpus; i++) {
		struct vcpu *vcpu = &vm->vcpu[i];

		vcpu_lock(vcpu);
		if (vcpu->state == VCPU_IDLE || vcpu->state == VCPU_FROZEN) {
			/*
			 * Any vCPUs not actively running or in HLT can be
			 * marked as suspended immediately.
			 */
			if (CPU_ISSET(i, &vm->active_cpus)) {
				CPU_SET_ATOMIC(i, &vm->suspended_cpus);
			}
		} else {
			/*
			 * Those which are running or in HLT will pick up the
			 * suspended state after notification.
			 */
			vcpu_notify_event_locked(vcpu, VCPU_NOTIFY_EXIT);
		}
		vcpu_unlock(vcpu);
	}
	return (0);
}

void
vm_exit_run_state(struct vm *vm, int vcpuid, uint64_t rip)
{
	struct vm_exit *vmexit;

	vmexit = vm_exitinfo(vm, vcpuid);
	vmexit->rip = rip;
	vmexit->inst_length = 0;
	vmexit->exitcode = VM_EXITCODE_RUN_STATE;
	vmm_stat_incr(vm, vcpuid, VMEXIT_RUN_STATE, 1);
}

/*
 * Some vmm resources, such as the lapic, may have CPU-specific resources
 * allocated to them which would benefit from migration onto the host CPU which
 * is processing the vcpu state.
 */
static void
vm_localize_resources(struct vm *vm, struct vcpu *vcpu)
{
	/*
	 * Localizing cyclic resources requires acquisition of cpu_lock, and
	 * doing so with kpreempt disabled is a recipe for deadlock disaster.
	 */
	VERIFY(curthread->t_preempt == 0);

	/*
	 * Do not bother with localization if this vCPU is about to return to
	 * the host CPU it was last localized to.
	 */
	if (vcpu->lastloccpu == curcpu)
		return;

	/*
	 * Localize system-wide resources to the primary boot vCPU.  While any
	 * of the other vCPUs may access them, it keeps the potential interrupt
	 * footprint constrained to CPUs involved with this instance.
	 */
	if (vcpu == &vm->vcpu[0]) {
		vhpet_localize_resources(vm->vhpet);
		vrtc_localize_resources(vm->vrtc);
		vatpit_localize_resources(vm->vatpit);
	}

	vlapic_localize_resources(vcpu->vlapic);

	vcpu->lastloccpu = curcpu;
}

static void
vmm_savectx(void *arg)
{
	vm_thread_ctx_t *vtc = arg;
	struct vm *vm = vtc->vtc_vm;
	const int vcpuid = vtc->vtc_vcpuid;

	if (ops->vmsavectx != NULL) {
		ops->vmsavectx(vm->cookie, vcpuid);
	}

	/*
	 * Account for going off-cpu, unless the vCPU is idled, where being
	 * off-cpu is the explicit point.
	 */
	if (vm->vcpu[vcpuid].ustate != VU_IDLE) {
		vtc->vtc_ustate = vm->vcpu[vcpuid].ustate;
		vcpu_ustate_change(vm, vcpuid, VU_SCHED);
	}

	/*
	 * If the CPU holds the restored guest FPU state, save it and restore
	 * the host FPU state before this thread goes off-cpu.
	 */
	if ((vtc->vtc_status & VTCS_FPU_RESTORED) != 0) {
		struct vcpu *vcpu = &vm->vcpu[vcpuid];

		save_guest_fpustate(vcpu);
		vtc->vtc_status &= ~VTCS_FPU_RESTORED;
	}
}

static void
vmm_restorectx(void *arg)
{
	vm_thread_ctx_t *vtc = arg;
	struct vm *vm = vtc->vtc_vm;
	const int vcpuid = vtc->vtc_vcpuid;

	/* Complete microstate accounting for vCPU being off-cpu */
	if (vm->vcpu[vcpuid].ustate != VU_IDLE) {
		vcpu_ustate_change(vm, vcpuid, vtc->vtc_ustate);
	}

	/*
	 * When coming back on-cpu, only restore the guest FPU status if the
	 * thread is in a context marked as requiring it.  This should be rare,
	 * occurring only when a future logic error results in a voluntary
	 * sleep during the VMRUN critical section.
	 *
	 * The common case will result in elision of the guest FPU state
	 * restoration, deferring that action until it is clearly necessary
	 * during vm_run.
	 */
	VERIFY((vtc->vtc_status & VTCS_FPU_RESTORED) == 0);
	if ((vtc->vtc_status & VTCS_FPU_CTX_CRITICAL) != 0) {
		struct vcpu *vcpu = &vm->vcpu[vcpuid];

		restore_guest_fpustate(vcpu);
		vtc->vtc_status |= VTCS_FPU_RESTORED;
	}

	if (ops->vmrestorectx != NULL) {
		ops->vmrestorectx(vm->cookie, vcpuid);
	}

}

static int
vm_entry_actions(struct vm *vm, int vcpuid, const struct vm_entry *entry,
    struct vm_exit *vme)
{
	struct vcpu *vcpu;
	struct vie *vie;
	int err;

	vcpu = &vm->vcpu[vcpuid];
	vie = vcpu->vie_ctx;
	err = 0;

	switch (entry->cmd) {
	case VEC_DEFAULT:
		return (0);
	case VEC_DISCARD_INSTR:
		vie_reset(vie);
		return (0);
	case VEC_FULFILL_MMIO:
		err = vie_fulfill_mmio(vie, &entry->u.mmio);
		if (err == 0) {
			err = vie_emulate_mmio(vie, vm, vcpuid);
			if (err == 0) {
				vie_advance_pc(vie, &vcpu->nextrip);
			} else if (err < 0) {
				vie_exitinfo(vie, vme);
			} else if (err == EAGAIN) {
				/*
				 * Clear the instruction emulation state in
				 * order to re-enter VM context and continue
				 * this 'rep <instruction>'
				 */
				vie_reset(vie);
				err = 0;
			}
		}
		break;
	case VEC_FULFILL_INOUT:
		err = vie_fulfill_inout(vie, &entry->u.inout);
		if (err == 0) {
			err = vie_emulate_inout(vie, vm, vcpuid);
			if (err == 0) {
				vie_advance_pc(vie, &vcpu->nextrip);
			} else if (err < 0) {
				vie_exitinfo(vie, vme);
			} else if (err == EAGAIN) {
				/*
				 * Clear the instruction emulation state in
				 * order to re-enter VM context and continue
				 * this 'rep ins/outs'
				 */
				vie_reset(vie);
				err = 0;
			}
		}
		break;
	default:
		return (EINVAL);
	}
	return (err);
}

static int
vm_loop_checks(struct vm *vm, int vcpuid, struct vm_exit *vme)
{
	struct vie *vie;

	vie = vm->vcpu[vcpuid].vie_ctx;

	if (vie_pending(vie)) {
		/*
		 * Userspace has not fulfilled the pending needs of the
		 * instruction emulation, so bail back out.
		 */
		vie_exitinfo(vie, vme);
		return (-1);
	}

	return (0);
}

int
vm_run(struct vm *vm, int vcpuid, const struct vm_entry *entry)
{
	int error;
	struct vcpu *vcpu;
	struct vm_exit *vme;
	bool intr_disabled;
	int affinity_type = CPU_CURRENT;

	if (vcpuid < 0 || vcpuid >= vm->maxcpus)
		return (EINVAL);
	if (!CPU_ISSET(vcpuid, &vm->active_cpus))
		return (EINVAL);
	if (vm->is_paused) {
		return (EBUSY);
	}

	vcpu = &vm->vcpu[vcpuid];
	vme = &vcpu->exitinfo;

	vcpu_ustate_change(vm, vcpuid, VU_EMU_KERN);

	vcpu->vtc.vtc_status = 0;
	ctxop_attach(curthread, vcpu->ctxop);

	error = vm_entry_actions(vm, vcpuid, entry, vme);
	if (error != 0) {
		goto exit;
	}

restart:
	error = vm_loop_checks(vm, vcpuid, vme);
	if (error != 0) {
		goto exit;
	}

	thread_affinity_set(curthread, affinity_type);
	/*
	 * Resource localization should happen after the CPU affinity for the
	 * thread has been set to ensure that access from restricted contexts,
	 * such as VMX-accelerated APIC operations, can occur without inducing
	 * cyclic cross-calls.
	 *
	 * This must be done prior to disabling kpreempt via critical_enter().
	 */
	vm_localize_resources(vm, vcpu);
	affinity_type = CPU_CURRENT;
	critical_enter();

	/* Force a trip through update_sregs to reload %fs/%gs and friends */
	PCB_SET_UPDATE_SEGS(&ttolwp(curthread)->lwp_pcb);

	if ((vcpu->vtc.vtc_status & VTCS_FPU_RESTORED) == 0) {
		restore_guest_fpustate(vcpu);
		vcpu->vtc.vtc_status |= VTCS_FPU_RESTORED;
	}
	vcpu->vtc.vtc_status |= VTCS_FPU_CTX_CRITICAL;

	vcpu_require_state(vm, vcpuid, VCPU_RUNNING);
	error = VMRUN(vm->cookie, vcpuid, vcpu->nextrip);
	vcpu_require_state(vm, vcpuid, VCPU_FROZEN);

	/*
	 * Once clear of the delicate contexts comprising the VM_RUN handler,
	 * thread CPU affinity can be loosened while other processing occurs.
	 */
	vcpu->vtc.vtc_status &= ~VTCS_FPU_CTX_CRITICAL;
	thread_affinity_clear(curthread);
	critical_exit();

	if (error != 0) {
		/* Communicate out any error from VMRUN() above */
		goto exit;
	}

	vcpu->nextrip = vme->rip + vme->inst_length;
	switch (vme->exitcode) {
	case VM_EXITCODE_REQIDLE:
		error = vm_handle_reqidle(vm, vcpuid);
		break;
	case VM_EXITCODE_RUN_STATE:
		error = vm_handle_run_state(vm, vcpuid);
		break;
	case VM_EXITCODE_SUSPENDED:
		error = vm_handle_suspend(vm, vcpuid);
		break;
	case VM_EXITCODE_IOAPIC_EOI:
		vioapic_process_eoi(vm, vcpuid,
		    vme->u.ioapic_eoi.vector);
		break;
	case VM_EXITCODE_HLT:
		intr_disabled = ((vme->u.hlt.rflags & PSL_I) == 0);
		error = vm_handle_hlt(vm, vcpuid, intr_disabled);
		break;
	case VM_EXITCODE_PAGING:
		error = vm_handle_paging(vm, vcpuid);
		break;
	case VM_EXITCODE_MMIO_EMUL:
		error = vm_handle_mmio_emul(vm, vcpuid);
		break;
	case VM_EXITCODE_INOUT:
		error = vm_handle_inout(vm, vcpuid, vme);
		break;
	case VM_EXITCODE_INST_EMUL:
		error = vm_handle_inst_emul(vm, vcpuid);
		break;
	case VM_EXITCODE_MONITOR:
	case VM_EXITCODE_MWAIT:
	case VM_EXITCODE_VMINSN:
		vm_inject_ud(vm, vcpuid);
		break;
	case VM_EXITCODE_RDMSR:
		error = vm_handle_rdmsr(vm, vcpuid, vme);
		break;
	case VM_EXITCODE_WRMSR:
		error = vm_handle_wrmsr(vm, vcpuid, vme);
		break;
	case VM_EXITCODE_HT:
		affinity_type = CPU_BEST;
		break;
	case VM_EXITCODE_MTRAP:
		VERIFY0(vm_suspend_cpu(vm, vcpuid));
		error = -1;
		break;
	default:
		/* handled in userland */
		error = -1;
		break;
	}

	if (error == 0) {
		/* VM exit conditions handled in-kernel, continue running */
		goto restart;
	}

exit:
	kpreempt_disable();
	ctxop_detach(curthread, vcpu->ctxop);
	/* Make sure all of the needed vCPU context state is saved */
	vmm_savectx(&vcpu->vtc);
	kpreempt_enable();

	vcpu_ustate_change(vm, vcpuid, VU_EMU_USER);
	return (error);
}

int
vm_restart_instruction(void *arg, int vcpuid)
{
	struct vm *vm;
	struct vcpu *vcpu;
	enum vcpu_state state;
	uint64_t rip;
	int error;

	vm = arg;
	if (vcpuid < 0 || vcpuid >= vm->maxcpus)
		return (EINVAL);

	vcpu = &vm->vcpu[vcpuid];
	state = vcpu_get_state(vm, vcpuid, NULL);
	if (state == VCPU_RUNNING) {
		/*
		 * When a vcpu is "running" the next instruction is determined
		 * by adding 'rip' and 'inst_length' in the vcpu's 'exitinfo'.
		 * Thus setting 'inst_length' to zero will cause the current
		 * instruction to be restarted.
		 */
		vcpu->exitinfo.inst_length = 0;
	} else if (state == VCPU_FROZEN) {
		/*
		 * When a vcpu is "frozen" it is outside the critical section
		 * around VMRUN() and 'nextrip' points to the next instruction.
		 * Thus instruction restart is achieved by setting 'nextrip'
		 * to the vcpu's %rip.
		 */
		error = vm_get_register(vm, vcpuid, VM_REG_GUEST_RIP, &rip);
		KASSERT(!error, ("%s: error %d getting rip", __func__, error));
		vcpu->nextrip = rip;
	} else {
		panic("%s: invalid state %d", __func__, state);
	}
	return (0);
}

int
vm_exit_intinfo(struct vm *vm, int vcpuid, uint64_t info)
{
	struct vcpu *vcpu;

	if (vcpuid < 0 || vcpuid >= vm->maxcpus)
		return (EINVAL);

	vcpu = &vm->vcpu[vcpuid];

	if (VM_INTINFO_PENDING(info)) {
		const uint32_t type = VM_INTINFO_TYPE(info);
		const uint8_t vector = VM_INTINFO_VECTOR(info);

		if (type == VM_INTINFO_NMI && vector != IDT_NMI)
			return (EINVAL);
		if (type == VM_INTINFO_HWEXCP && vector >= 32)
			return (EINVAL);
		if (info & VM_INTINFO_MASK_RSVD)
			return (EINVAL);
	} else {
		info = 0;
	}
	vcpu->exit_intinfo = info;
	return (0);
}

enum exc_class {
	EXC_BENIGN,
	EXC_CONTRIBUTORY,
	EXC_PAGEFAULT
};

#define	IDT_VE	20	/* Virtualization Exception (Intel specific) */

static enum exc_class
exception_class(uint64_t info)
{
	ASSERT(VM_INTINFO_PENDING(info));

	/* Table 6-4, "Interrupt and Exception Classes", Intel SDM, Vol 3 */
	switch (VM_INTINFO_TYPE(info)) {
	case VM_INTINFO_HWINTR:
	case VM_INTINFO_SWINTR:
	case VM_INTINFO_NMI:
		return (EXC_BENIGN);
	default:
		/*
		 * Hardware exception.
		 *
		 * SVM and VT-x use identical type values to represent NMI,
		 * hardware interrupt and software interrupt.
		 *
		 * SVM uses type '3' for all exceptions. VT-x uses type '3'
		 * for exceptions except #BP and #OF. #BP and #OF use a type
		 * value of '5' or '6'. Therefore we don't check for explicit
		 * values of 'type' to classify 'intinfo' into a hardware
		 * exception.
		 */
		break;
	}

	switch (VM_INTINFO_VECTOR(info)) {
	case IDT_PF:
	case IDT_VE:
		return (EXC_PAGEFAULT);
	case IDT_DE:
	case IDT_TS:
	case IDT_NP:
	case IDT_SS:
	case IDT_GP:
		return (EXC_CONTRIBUTORY);
	default:
		return (EXC_BENIGN);
	}
}

/*
 * Fetch event pending injection into the guest, if one exists.
 *
 * Returns true if an event is to be injected (which is placed in `retinfo`).
 */
bool
vm_entry_intinfo(struct vm *vm, int vcpuid, uint64_t *retinfo)
{
	struct vcpu *vcpu = &vm->vcpu[vcpuid];
	const uint64_t info1 = vcpu->exit_intinfo;
	vcpu->exit_intinfo = 0;
	const uint64_t info2 = vcpu->exc_pending;
	vcpu->exc_pending = 0;

	if (VM_INTINFO_PENDING(info1) && VM_INTINFO_PENDING(info2)) {
		/*
		 * If an exception occurs while attempting to call the
		 * double-fault handler the processor enters shutdown mode
		 * (aka triple fault).
		 */
		if (VM_INTINFO_TYPE(info1) == VM_INTINFO_HWEXCP &&
		    VM_INTINFO_VECTOR(info1) == IDT_DF) {
			(void) vm_suspend(vm, VM_SUSPEND_TRIPLEFAULT);
			*retinfo = 0;
			return (false);
		}
		/*
		 * "Conditions for Generating a Double Fault"
		 *  Intel SDM, Vol3, Table 6-5
		 */
		const enum exc_class exc1 = exception_class(info1);
		const enum exc_class exc2 = exception_class(info2);
		if ((exc1 == EXC_CONTRIBUTORY && exc2 == EXC_CONTRIBUTORY) ||
		    (exc1 == EXC_PAGEFAULT && exc2 != EXC_BENIGN)) {
			/* Convert nested fault into a double fault. */
			*retinfo =
			    VM_INTINFO_VALID |
			    VM_INTINFO_DEL_ERRCODE |
			    VM_INTINFO_HWEXCP |
			    IDT_DF;
		} else {
			/* Handle exceptions serially */
			vcpu->exit_intinfo = info1;
			*retinfo = info2;
		}
		return (true);
	} else if (VM_INTINFO_PENDING(info1)) {
		*retinfo = info1;
		return (true);
	} else if (VM_INTINFO_PENDING(info2)) {
		*retinfo = info2;
		return (true);
	}

	return (false);
}

int
vm_get_intinfo(struct vm *vm, int vcpuid, uint64_t *info1, uint64_t *info2)
{
	struct vcpu *vcpu;

	if (vcpuid < 0 || vcpuid >= vm->maxcpus)
		return (EINVAL);

	vcpu = &vm->vcpu[vcpuid];
	*info1 = vcpu->exit_intinfo;
	*info2 = vcpu->exc_pending;
	return (0);
}

int
vm_inject_exception(struct vm *vm, int vcpuid, uint8_t vector,
    bool errcode_valid, uint32_t errcode, bool restart_instruction)
{
	struct vcpu *vcpu;
	uint64_t regval;
	int error;

	if (vcpuid < 0 || vcpuid >= vm->maxcpus)
		return (EINVAL);

	if (vector >= 32)
		return (EINVAL);

	/*
	 * NMIs are to be injected via their own specialized path using
	 * vm_inject_nmi().
	 */
	if (vector == IDT_NMI) {
		return (EINVAL);
	}

	/*
	 * A double fault exception should never be injected directly into
	 * the guest. It is a derived exception that results from specific
	 * combinations of nested faults.
	 */
	if (vector == IDT_DF) {
		return (EINVAL);
	}

	vcpu = &vm->vcpu[vcpuid];

	if (VM_INTINFO_PENDING(vcpu->exc_pending)) {
		/* Unable to inject exception due to one already pending */
		return (EBUSY);
	}

	if (errcode_valid) {
		/*
		 * Exceptions don't deliver an error code in real mode.
		 */
		error = vm_get_register(vm, vcpuid, VM_REG_GUEST_CR0, &regval);
		VERIFY0(error);
		if ((regval & CR0_PE) == 0) {
			errcode_valid = false;
		}
	}

	/*
	 * From section 26.6.1 "Interruptibility State" in Intel SDM:
	 *
	 * Event blocking by "STI" or "MOV SS" is cleared after guest executes
	 * one instruction or incurs an exception.
	 */
	error = vm_set_register(vm, vcpuid, VM_REG_GUEST_INTR_SHADOW, 0);
	VERIFY0(error);

	if (restart_instruction) {
		VERIFY0(vm_restart_instruction(vm, vcpuid));
	}

	uint64_t val = VM_INTINFO_VALID | VM_INTINFO_HWEXCP | vector;
	if (errcode_valid) {
		val |= VM_INTINFO_DEL_ERRCODE;
		val |= (uint64_t)errcode << VM_INTINFO_SHIFT_ERRCODE;
	}
	vcpu->exc_pending = val;
	return (0);
}

void
vm_inject_ud(struct vm *vm, int vcpuid)
{
	VERIFY0(vm_inject_exception(vm, vcpuid, IDT_UD, false, 0, true));
}

void
vm_inject_gp(struct vm *vm, int vcpuid)
{
	VERIFY0(vm_inject_exception(vm, vcpuid, IDT_GP, true, 0, true));
}

void
vm_inject_ac(struct vm *vm, int vcpuid, uint32_t errcode)
{
	VERIFY0(vm_inject_exception(vm, vcpuid, IDT_AC, true, errcode, true));
}

void
vm_inject_ss(struct vm *vm, int vcpuid, uint32_t errcode)
{
	VERIFY0(vm_inject_exception(vm, vcpuid, IDT_SS, true, errcode, true));
}

void
vm_inject_pf(struct vm *vm, int vcpuid, uint32_t errcode, uint64_t cr2)
{
	VERIFY0(vm_set_register(vm, vcpuid, VM_REG_GUEST_CR2, cr2));
	VERIFY0(vm_inject_exception(vm, vcpuid, IDT_PF, true, errcode, true));
}

static VMM_STAT(VCPU_NMI_COUNT, "number of NMIs delivered to vcpu");

int
vm_inject_nmi(struct vm *vm, int vcpuid)
{
	struct vcpu *vcpu;

	if (vcpuid < 0 || vcpuid >= vm->maxcpus)
		return (EINVAL);

	vcpu = &vm->vcpu[vcpuid];

	vcpu->nmi_pending = true;
	vcpu_notify_event(vm, vcpuid);
	return (0);
}

bool
vm_nmi_pending(struct vm *vm, int vcpuid)
{
	struct vcpu *vcpu = &vm->vcpu[vcpuid];

	return (vcpu->nmi_pending);
}

void
vm_nmi_clear(struct vm *vm, int vcpuid)
{
	struct vcpu *vcpu = &vm->vcpu[vcpuid];

	ASSERT(vcpu->nmi_pending);

	vcpu->nmi_pending = false;
	vmm_stat_incr(vm, vcpuid, VCPU_NMI_COUNT, 1);
}

static VMM_STAT(VCPU_EXTINT_COUNT, "number of ExtINTs delivered to vcpu");

int
vm_inject_extint(struct vm *vm, int vcpuid)
{
	struct vcpu *vcpu;

	if (vcpuid < 0 || vcpuid >= vm->maxcpus)
		return (EINVAL);

	vcpu = &vm->vcpu[vcpuid];

	vcpu->extint_pending = true;
	vcpu_notify_event(vm, vcpuid);
	return (0);
}

bool
vm_extint_pending(struct vm *vm, int vcpuid)
{
	struct vcpu *vcpu = &vm->vcpu[vcpuid];

	return (vcpu->extint_pending);
}

void
vm_extint_clear(struct vm *vm, int vcpuid)
{
	struct vcpu *vcpu = &vm->vcpu[vcpuid];

	ASSERT(vcpu->extint_pending);

	vcpu->extint_pending = false;
	vmm_stat_incr(vm, vcpuid, VCPU_EXTINT_COUNT, 1);
}

int
vm_inject_init(struct vm *vm, int vcpuid)
{
	struct vcpu *vcpu;

	if (vcpuid < 0 || vcpuid >= vm->maxcpus)
		return (EINVAL);

	vcpu = &vm->vcpu[vcpuid];
	vcpu_lock(vcpu);
	vcpu->run_state |= VRS_PEND_INIT;
	/*
	 * As part of queuing the INIT request, clear any pending SIPI.  It
	 * would not otherwise survive across the reset of the vCPU when it
	 * undergoes the requested INIT.  We would not want it to linger when it
	 * could be mistaken as a subsequent (after the INIT) SIPI request.
	 */
	vcpu->run_state &= ~VRS_PEND_SIPI;
	vcpu_notify_event_locked(vcpu, VCPU_NOTIFY_EXIT);

	vcpu_unlock(vcpu);
	return (0);
}

int
vm_inject_sipi(struct vm *vm, int vcpuid, uint8_t vector)
{
	struct vcpu *vcpu;

	if (vcpuid < 0 || vcpuid >= vm->maxcpus)
		return (EINVAL);

	vcpu = &vm->vcpu[vcpuid];
	vcpu_lock(vcpu);
	vcpu->run_state |= VRS_PEND_SIPI;
	vcpu->sipi_vector = vector;
	/* SIPI is only actionable if the CPU is waiting in INIT state */
	if ((vcpu->run_state & (VRS_INIT | VRS_RUN)) == VRS_INIT) {
		vcpu_notify_event_locked(vcpu, VCPU_NOTIFY_EXIT);
	}
	vcpu_unlock(vcpu);
	return (0);
}

bool
vcpu_run_state_pending(struct vm *vm, int vcpuid)
{
	struct vcpu *vcpu;

	ASSERT(vcpuid >= 0 && vcpuid < vm->maxcpus);
	vcpu = &vm->vcpu[vcpuid];

	/* Of interest: vCPU not in running state or with pending INIT */
	return ((vcpu->run_state & (VRS_RUN | VRS_PEND_INIT)) != VRS_RUN);
}

int
vcpu_arch_reset(struct vm *vm, int vcpuid, bool init_only)
{
	struct seg_desc desc;
	const enum vm_reg_name clear_regs[] = {
		VM_REG_GUEST_CR2,
		VM_REG_GUEST_CR3,
		VM_REG_GUEST_CR4,
		VM_REG_GUEST_RAX,
		VM_REG_GUEST_RBX,
		VM_REG_GUEST_RCX,
		VM_REG_GUEST_RSI,
		VM_REG_GUEST_RDI,
		VM_REG_GUEST_RBP,
		VM_REG_GUEST_RSP,
		VM_REG_GUEST_R8,
		VM_REG_GUEST_R9,
		VM_REG_GUEST_R10,
		VM_REG_GUEST_R11,
		VM_REG_GUEST_R12,
		VM_REG_GUEST_R13,
		VM_REG_GUEST_R14,
		VM_REG_GUEST_R15,
		VM_REG_GUEST_DR0,
		VM_REG_GUEST_DR1,
		VM_REG_GUEST_DR2,
		VM_REG_GUEST_DR3,
		VM_REG_GUEST_EFER,
	};
	const enum vm_reg_name data_segs[] = {
		VM_REG_GUEST_SS,
		VM_REG_GUEST_DS,
		VM_REG_GUEST_ES,
		VM_REG_GUEST_FS,
		VM_REG_GUEST_GS,
	};
	struct vcpu *vcpu = &vm->vcpu[vcpuid];

	if (vcpuid < 0 || vcpuid >= vm->maxcpus)
		return (EINVAL);

	for (uint_t i = 0; i < nitems(clear_regs); i++) {
		VERIFY0(vm_set_register(vm, vcpuid, clear_regs[i], 0));
	}

	VERIFY0(vm_set_register(vm, vcpuid, VM_REG_GUEST_RFLAGS, 2));
	VERIFY0(vm_set_register(vm, vcpuid, VM_REG_GUEST_RIP, 0xfff0));
	VERIFY0(vm_set_register(vm, vcpuid, VM_REG_GUEST_CR0, 0x60000010));

	/*
	 * The prescribed contents of %rdx differ slightly between the Intel and
	 * AMD architectural definitions.  The former expects the Extended Model
	 * in bits 16-19 where the latter expects all the Family, Model, and
	 * Stepping be there.  Common boot ROMs appear to disregard this
	 * anyways, so we stick with a compromise value similar to what is
	 * spelled out in the Intel SDM.
	 */
	VERIFY0(vm_set_register(vm, vcpuid, VM_REG_GUEST_RDX, 0x600));

	VERIFY0(vm_set_register(vm, vcpuid, VM_REG_GUEST_DR6, 0xffff0ff0));
	VERIFY0(vm_set_register(vm, vcpuid, VM_REG_GUEST_DR7, 0x400));

	/* CS: Present, R/W, Accessed */
	desc.access = 0x0093;
	desc.base = 0xffff0000;
	desc.limit = 0xffff;
	VERIFY0(vm_set_seg_desc(vm, vcpuid, VM_REG_GUEST_CS, &desc));
	VERIFY0(vm_set_register(vm, vcpuid, VM_REG_GUEST_CS, 0xf000));

	/* SS, DS, ES, FS, GS: Present, R/W, Accessed */
	desc.access = 0x0093;
	desc.base = 0;
	desc.limit = 0xffff;
	for (uint_t i = 0; i < nitems(data_segs); i++) {
		VERIFY0(vm_set_seg_desc(vm, vcpuid, data_segs[i], &desc));
		VERIFY0(vm_set_register(vm, vcpuid, data_segs[i], 0));
	}

	/* GDTR, IDTR */
	desc.base = 0;
	desc.limit = 0xffff;
	VERIFY0(vm_set_seg_desc(vm, vcpuid, VM_REG_GUEST_GDTR, &desc));
	VERIFY0(vm_set_seg_desc(vm, vcpuid, VM_REG_GUEST_IDTR, &desc));

	/* LDTR: Present, LDT */
	desc.access = 0x0082;
	desc.base = 0;
	desc.limit = 0xffff;
	VERIFY0(vm_set_seg_desc(vm, vcpuid, VM_REG_GUEST_LDTR, &desc));
	VERIFY0(vm_set_register(vm, vcpuid, VM_REG_GUEST_LDTR, 0));

	/* TR: Present, 32-bit TSS */
	desc.access = 0x008b;
	desc.base = 0;
	desc.limit = 0xffff;
	VERIFY0(vm_set_seg_desc(vm, vcpuid, VM_REG_GUEST_TR, &desc));
	VERIFY0(vm_set_register(vm, vcpuid, VM_REG_GUEST_TR, 0));

	vlapic_reset(vm_lapic(vm, vcpuid));

	VERIFY0(vm_set_register(vm, vcpuid, VM_REG_GUEST_INTR_SHADOW, 0));

	vcpu->exit_intinfo = 0;
	vcpu->exc_pending = 0;
	vcpu->nmi_pending = false;
	vcpu->extint_pending = 0;

	/*
	 * A CPU reset caused by power-on or system reset clears more state than
	 * one which is trigged from an INIT IPI.
	 */
	if (!init_only) {
		vcpu->guest_xcr0 = XFEATURE_ENABLED_X87;
		(void) hma_fpu_init(vcpu->guestfpu);

		/* XXX: clear MSRs and other pieces */
		bzero(&vcpu->mtrr, sizeof (vcpu->mtrr));
	}

	return (0);
}

static int
vcpu_vector_sipi(struct vm *vm, int vcpuid, uint8_t vector)
{
	struct seg_desc desc;

	if (vcpuid < 0 || vcpuid >= vm->maxcpus)
		return (EINVAL);

	/* CS: Present, R/W, Accessed */
	desc.access = 0x0093;
	desc.base = (uint64_t)vector << 12;
	desc.limit = 0xffff;
	VERIFY0(vm_set_seg_desc(vm, vcpuid, VM_REG_GUEST_CS, &desc));
	VERIFY0(vm_set_register(vm, vcpuid, VM_REG_GUEST_CS,
	    (uint64_t)vector << 8));

	VERIFY0(vm_set_register(vm, vcpuid, VM_REG_GUEST_RIP, 0));

	return (0);
}

int
vm_get_capability(struct vm *vm, int vcpu, int type, int *retval)
{
	if (vcpu < 0 || vcpu >= vm->maxcpus)
		return (EINVAL);

	if (type < 0 || type >= VM_CAP_MAX)
		return (EINVAL);

	return (VMGETCAP(vm->cookie, vcpu, type, retval));
}

int
vm_set_capability(struct vm *vm, int vcpu, int type, int val)
{
	if (vcpu < 0 || vcpu >= vm->maxcpus)
		return (EINVAL);

	if (type < 0 || type >= VM_CAP_MAX)
		return (EINVAL);

	return (VMSETCAP(vm->cookie, vcpu, type, val));
}

vcpu_cpuid_config_t *
vm_cpuid_config(struct vm *vm, int vcpuid)
{
	ASSERT3S(vcpuid, >=, 0);
	ASSERT3S(vcpuid, <, VM_MAXCPU);

	return (&vm->vcpu[vcpuid].cpuid_cfg);
}

struct vlapic *
vm_lapic(struct vm *vm, int cpu)
{
	ASSERT3S(cpu, >=, 0);
	ASSERT3S(cpu, <, VM_MAXCPU);

	return (vm->vcpu[cpu].vlapic);
}

struct vioapic *
vm_ioapic(struct vm *vm)
{

	return (vm->vioapic);
}

struct vhpet *
vm_hpet(struct vm *vm)
{

	return (vm->vhpet);
}

void *
vm_iommu_domain(struct vm *vm)
{

	return (vm->iommu);
}

int
vcpu_set_state(struct vm *vm, int vcpuid, enum vcpu_state newstate,
    bool from_idle)
{
	int error;
	struct vcpu *vcpu;

	if (vcpuid < 0 || vcpuid >= vm->maxcpus)
		panic("vcpu_set_state: invalid vcpuid %d", vcpuid);

	vcpu = &vm->vcpu[vcpuid];

	vcpu_lock(vcpu);
	error = vcpu_set_state_locked(vm, vcpuid, newstate, from_idle);
	vcpu_unlock(vcpu);

	return (error);
}

enum vcpu_state
vcpu_get_state(struct vm *vm, int vcpuid, int *hostcpu)
{
	struct vcpu *vcpu;
	enum vcpu_state state;

	if (vcpuid < 0 || vcpuid >= vm->maxcpus)
		panic("vcpu_get_state: invalid vcpuid %d", vcpuid);

	vcpu = &vm->vcpu[vcpuid];

	vcpu_lock(vcpu);
	state = vcpu->state;
	if (hostcpu != NULL)
		*hostcpu = vcpu->hostcpu;
	vcpu_unlock(vcpu);

	return (state);
}

uint64_t
vcpu_tsc_offset(struct vm *vm, int vcpuid, bool phys_adj)
{
	ASSERT(vcpuid >= 0 && vcpuid < vm->maxcpus);

	uint64_t vcpu_off = vm->boot_tsc_offset + vm->vcpu[vcpuid].tsc_offset;

	if (phys_adj) {
		/* Include any offset for the current physical CPU too */
		extern hrtime_t tsc_gethrtime_tick_delta(void);
		vcpu_off += (uint64_t)tsc_gethrtime_tick_delta();
	}

	return (vcpu_off);
}

/* Normalize hrtime against the boot time for a VM */
hrtime_t
vm_normalize_hrtime(struct vm *vm, hrtime_t hrt)
{
	/* To avoid underflow/overflow UB, perform math as unsigned */
	return ((hrtime_t)((uint64_t)hrt - (uint64_t)vm->boot_hrtime));
}

/* Denormalize hrtime against the boot time for a VM */
hrtime_t
vm_denormalize_hrtime(struct vm *vm, hrtime_t hrt)
{
	/* To avoid underflow/overflow UB, perform math as unsigned */
	return ((hrtime_t)((uint64_t)hrt + (uint64_t)vm->boot_hrtime));
}

int
vm_activate_cpu(struct vm *vm, int vcpuid)
{

	if (vcpuid < 0 || vcpuid >= vm->maxcpus)
		return (EINVAL);

	if (CPU_ISSET(vcpuid, &vm->active_cpus))
		return (EBUSY);

	if (vm->suspend != 0) {
		return (EBUSY);
	}

	CPU_SET_ATOMIC(vcpuid, &vm->active_cpus);

	/*
	 * It is possible that this vCPU was undergoing activation at the same
	 * time that the VM was being suspended.  If that happens to be the
	 * case, it should reflect the suspended state immediately.
	 */
	if (atomic_load_acq_int((uint_t *)&vm->suspend) != 0) {
		CPU_SET_ATOMIC(vcpuid, &vm->suspended_cpus);
	}

	return (0);
}

int
vm_suspend_cpu(struct vm *vm, int vcpuid)
{
	int i;

	if (vcpuid < -1 || vcpuid >= vm->maxcpus)
		return (EINVAL);

	if (vcpuid == -1) {
		vm->debug_cpus = vm->active_cpus;
		for (i = 0; i < vm->maxcpus; i++) {
			if (CPU_ISSET(i, &vm->active_cpus))
				vcpu_notify_event(vm, i);
		}
	} else {
		if (!CPU_ISSET(vcpuid, &vm->active_cpus))
			return (EINVAL);

		CPU_SET_ATOMIC(vcpuid, &vm->debug_cpus);
		vcpu_notify_event(vm, vcpuid);
	}
	return (0);
}

int
vm_resume_cpu(struct vm *vm, int vcpuid)
{

	if (vcpuid < -1 || vcpuid >= vm->maxcpus)
		return (EINVAL);

	if (vcpuid == -1) {
		CPU_ZERO(&vm->debug_cpus);
	} else {
		if (!CPU_ISSET(vcpuid, &vm->debug_cpus))
			return (EINVAL);

		CPU_CLR_ATOMIC(vcpuid, &vm->debug_cpus);
	}
	return (0);
}

static bool
vcpu_bailout_checks(struct vm *vm, int vcpuid, bool on_entry,
    uint64_t entry_rip)
{
	struct vcpu *vcpu = &vm->vcpu[vcpuid];
	struct vm_exit *vme = &vcpu->exitinfo;
	bool bail = false;

	ASSERT(vcpuid >= 0 && vcpuid < vm->maxcpus);

	if (vm->suspend) {
		if (on_entry) {
			VERIFY(vm->suspend > VM_SUSPEND_NONE &&
			    vm->suspend < VM_SUSPEND_LAST);

			vme->exitcode = VM_EXITCODE_SUSPENDED;
			vme->u.suspended.how = vm->suspend;
		} else {
			/*
			 * Handling VM suspend is complicated, so if that
			 * condition is detected outside of VM-entry itself,
			 * just emit a BOGUS exitcode so we take a lap to pick
			 * up the event during an entry and are directed into
			 * the vm_handle_suspend() logic.
			 */
			vme->exitcode = VM_EXITCODE_BOGUS;
		}
		bail = true;
	}
	if (vcpu->reqidle) {
		vme->exitcode = VM_EXITCODE_REQIDLE;
		vmm_stat_incr(vm, vcpuid, VMEXIT_REQIDLE, 1);

		if (!on_entry) {
			/*
			 * A reqidle request detected outside of VM-entry can be
			 * handled directly by clearing the request (and taking
			 * a lap to userspace).
			 */
			vcpu_assert_locked(vcpu);
			vcpu->reqidle = 0;
		}
		bail = true;
	}
	if (vcpu_should_yield(vm, vcpuid)) {
		vme->exitcode = VM_EXITCODE_BOGUS;
		vmm_stat_incr(vm, vcpuid, VMEXIT_ASTPENDING, 1);
		bail = true;
	}
	if (CPU_ISSET(vcpuid, &vm->debug_cpus)) {
		vme->exitcode = VM_EXITCODE_DEBUG;
		bail = true;
	}

	if (bail) {
		if (on_entry) {
			/*
			 * If bailing out during VM-entry, the current %rip must
			 * be recorded in the exitinfo.
			 */
			vme->rip = entry_rip;
		}
		vme->inst_length = 0;
	}
	return (bail);
}

static bool
vcpu_sleep_bailout_checks(struct vm *vm, int vcpuid)
{
	/*
	 * Bail-out check done prior to sleeping (in vCPU contexts like HLT or
	 * wait-for-SIPI) expect that %rip is already populated in the vm_exit
	 * structure, and we would only modify the exitcode.
	 */
	return (vcpu_bailout_checks(vm, vcpuid, false, 0));
}

bool
vcpu_entry_bailout_checks(struct vm *vm, int vcpuid, uint64_t rip)
{
	/*
	 * Bail-out checks done as part of VM entry require an updated %rip to
	 * populate the vm_exit struct if any of the conditions of interest are
	 * matched in the check.
	 */
	return (vcpu_bailout_checks(vm, vcpuid, true, rip));
}

cpuset_t
vm_active_cpus(struct vm *vm)
{

	return (vm->active_cpus);
}

cpuset_t
vm_debug_cpus(struct vm *vm)
{

	return (vm->debug_cpus);
}

cpuset_t
vm_suspended_cpus(struct vm *vm)
{

	return (vm->suspended_cpus);
}

void *
vcpu_stats(struct vm *vm, int vcpuid)
{

	return (vm->vcpu[vcpuid].stats);
}

int
vm_get_x2apic_state(struct vm *vm, int vcpuid, enum x2apic_state *state)
{
	if (vcpuid < 0 || vcpuid >= vm->maxcpus)
		return (EINVAL);

	*state = vm->vcpu[vcpuid].x2apic_state;

	return (0);
}

int
vm_set_x2apic_state(struct vm *vm, int vcpuid, enum x2apic_state state)
{
	if (vcpuid < 0 || vcpuid >= vm->maxcpus)
		return (EINVAL);

	if (state >= X2APIC_STATE_LAST)
		return (EINVAL);

	vm->vcpu[vcpuid].x2apic_state = state;

	vlapic_set_x2apic_state(vm, vcpuid, state);

	return (0);
}

/*
 * This function is called to ensure that a vcpu "sees" a pending event
 * as soon as possible:
 * - If the vcpu thread is sleeping then it is woken up.
 * - If the vcpu is running on a different host_cpu then an IPI will be directed
 *   to the host_cpu to cause the vcpu to trap into the hypervisor.
 */
static void
vcpu_notify_event_locked(struct vcpu *vcpu, vcpu_notify_t ntype)
{
	int hostcpu;

	ASSERT(ntype == VCPU_NOTIFY_APIC || VCPU_NOTIFY_EXIT);

	hostcpu = vcpu->hostcpu;
	if (vcpu->state == VCPU_RUNNING) {
		KASSERT(hostcpu != NOCPU, ("vcpu running on invalid hostcpu"));
		if (hostcpu != curcpu) {
			if (ntype == VCPU_NOTIFY_APIC) {
				vlapic_post_intr(vcpu->vlapic, hostcpu);
			} else {
				poke_cpu(hostcpu);
			}
		} else {
			/*
			 * If the 'vcpu' is running on 'curcpu' then it must
			 * be sending a notification to itself (e.g. SELF_IPI).
			 * The pending event will be picked up when the vcpu
			 * transitions back to guest context.
			 */
		}
	} else {
		KASSERT(hostcpu == NOCPU, ("vcpu state %d not consistent "
		    "with hostcpu %d", vcpu->state, hostcpu));
		if (vcpu->state == VCPU_SLEEPING) {
			cv_signal(&vcpu->vcpu_cv);
		}
	}
}

void
vcpu_notify_event(struct vm *vm, int vcpuid)
{
	struct vcpu *vcpu = &vm->vcpu[vcpuid];

	vcpu_lock(vcpu);
	vcpu_notify_event_locked(vcpu, VCPU_NOTIFY_EXIT);
	vcpu_unlock(vcpu);
}

void
vcpu_notify_event_type(struct vm *vm, int vcpuid, vcpu_notify_t ntype)
{
	struct vcpu *vcpu = &vm->vcpu[vcpuid];

	if (ntype == VCPU_NOTIFY_NONE) {
		return;
	}

	vcpu_lock(vcpu);
	vcpu_notify_event_locked(vcpu, ntype);
	vcpu_unlock(vcpu);
}

void
vcpu_ustate_change(struct vm *vm, int vcpuid, enum vcpu_ustate ustate)
{
	struct vcpu *vcpu = &vm->vcpu[vcpuid];
	hrtime_t now = gethrtime();

	ASSERT3U(ustate, !=, vcpu->ustate);
	ASSERT3S(ustate, <, VU_MAX);
	ASSERT3S(ustate, >=, VU_INIT);

	hrtime_t delta = now - vcpu->ustate_when;
	vcpu->ustate_total[vcpu->ustate] += delta;

	membar_producer();

	vcpu->ustate_when = now;
	vcpu->ustate = ustate;
}

struct vmspace *
vm_get_vmspace(struct vm *vm)
{

	return (vm->vmspace);
}

struct vm_client *
vm_get_vmclient(struct vm *vm, int vcpuid)
{
	return (vm->vcpu[vcpuid].vmclient);
}

int
vm_apicid2vcpuid(struct vm *vm, int apicid)
{
	/*
	 * XXX apic id is assumed to be numerically identical to vcpu id
	 */
	return (apicid);
}

struct vatpic *
vm_atpic(struct vm *vm)
{
	return (vm->vatpic);
}

struct vatpit *
vm_atpit(struct vm *vm)
{
	return (vm->vatpit);
}

struct vpmtmr *
vm_pmtmr(struct vm *vm)
{

	return (vm->vpmtmr);
}

struct vrtc *
vm_rtc(struct vm *vm)
{

	return (vm->vrtc);
}

enum vm_reg_name
vm_segment_name(int seg)
{
	static enum vm_reg_name seg_names[] = {
		VM_REG_GUEST_ES,
		VM_REG_GUEST_CS,
		VM_REG_GUEST_SS,
		VM_REG_GUEST_DS,
		VM_REG_GUEST_FS,
		VM_REG_GUEST_GS
	};

	KASSERT(seg >= 0 && seg < nitems(seg_names),
	    ("%s: invalid segment encoding %d", __func__, seg));
	return (seg_names[seg]);
}

void
vm_copy_teardown(struct vm *vm, int vcpuid, struct vm_copyinfo *copyinfo,
    uint_t num_copyinfo)
{
	for (uint_t idx = 0; idx < num_copyinfo; idx++) {
		if (copyinfo[idx].cookie != NULL) {
			(void) vmp_release((vm_page_t *)copyinfo[idx].cookie);
		}
	}
	bzero(copyinfo, num_copyinfo * sizeof (struct vm_copyinfo));
}

int
vm_copy_setup(struct vm *vm, int vcpuid, struct vm_guest_paging *paging,
    uint64_t gla, size_t len, int prot, struct vm_copyinfo *copyinfo,
    uint_t num_copyinfo, int *fault)
{
	uint_t idx, nused;
	size_t n, off, remaining;
	vm_client_t *vmc = vm_get_vmclient(vm, vcpuid);

	bzero(copyinfo, sizeof (struct vm_copyinfo) * num_copyinfo);

	nused = 0;
	remaining = len;
	while (remaining > 0) {
		uint64_t gpa;
		int error;

		KASSERT(nused < num_copyinfo, ("insufficient vm_copyinfo"));
		error = vm_gla2gpa(vm, vcpuid, paging, gla, prot, &gpa, fault);
		if (error || *fault)
			return (error);
		off = gpa & PAGEOFFSET;
		n = min(remaining, PAGESIZE - off);
		copyinfo[nused].gpa = gpa;
		copyinfo[nused].len = n;
		remaining -= n;
		gla += n;
		nused++;
	}

	for (idx = 0; idx < nused; idx++) {
		vm_page_t *vmp;
		caddr_t hva;

		vmp = vmc_hold(vmc, copyinfo[idx].gpa & PAGEMASK, prot);
		if (vmp == NULL) {
			break;
		}
		if ((prot & PROT_WRITE) != 0) {
			hva = (caddr_t)vmp_get_writable(vmp);
		} else {
			hva = (caddr_t)vmp_get_readable(vmp);
		}
		copyinfo[idx].hva = hva + (copyinfo[idx].gpa & PAGEOFFSET);
		copyinfo[idx].cookie = vmp;
		copyinfo[idx].prot = prot;
	}

	if (idx != nused) {
		vm_copy_teardown(vm, vcpuid, copyinfo, num_copyinfo);
		return (EFAULT);
	} else {
		*fault = 0;
		return (0);
	}
}

void
vm_copyin(struct vm *vm, int vcpuid, struct vm_copyinfo *copyinfo, void *kaddr,
    size_t len)
{
	char *dst;
	int idx;

	dst = kaddr;
	idx = 0;
	while (len > 0) {
		ASSERT(copyinfo[idx].prot & PROT_READ);

		bcopy(copyinfo[idx].hva, dst, copyinfo[idx].len);
		len -= copyinfo[idx].len;
		dst += copyinfo[idx].len;
		idx++;
	}
}

void
vm_copyout(struct vm *vm, int vcpuid, const void *kaddr,
    struct vm_copyinfo *copyinfo, size_t len)
{
	const char *src;
	int idx;

	src = kaddr;
	idx = 0;
	while (len > 0) {
		ASSERT(copyinfo[idx].prot & PROT_WRITE);

		bcopy(src, copyinfo[idx].hva, copyinfo[idx].len);
		len -= copyinfo[idx].len;
		src += copyinfo[idx].len;
		idx++;
	}
}

/*
 * Return the amount of in-use and wired memory for the VM. Since
 * these are global stats, only return the values with for vCPU 0
 */
VMM_STAT_DECLARE(VMM_MEM_RESIDENT);

static void
vm_get_rescnt(struct vm *vm, int vcpu, struct vmm_stat_type *stat)
{
	if (vcpu == 0) {
		vmm_stat_set(vm, vcpu, VMM_MEM_RESIDENT,
		    PAGE_SIZE * vmspace_resident_count(vm->vmspace));
	}
}

VMM_STAT_FUNC(VMM_MEM_RESIDENT, "Resident memory", vm_get_rescnt);

int
vm_ioport_access(struct vm *vm, int vcpuid, bool in, uint16_t port,
    uint8_t bytes, uint32_t *val)
{
	return (vm_inout_access(&vm->ioports, in, port, bytes, val));
}

/*
 * bhyve-internal interfaces to attach or detach IO port handlers.
 * Must be called with VM write lock held for safety.
 */
int
vm_ioport_attach(struct vm *vm, uint16_t port, ioport_handler_t func, void *arg,
    void **cookie)
{
	int err;
	err = vm_inout_attach(&vm->ioports, port, IOPF_DEFAULT, func, arg);
	if (err == 0) {
		*cookie = (void *)IOP_GEN_COOKIE(func, arg, port);
	}
	return (err);
}
int
vm_ioport_detach(struct vm *vm, void **cookie, ioport_handler_t *old_func,
    void **old_arg)
{
	uint16_t port = IOP_PORT_FROM_COOKIE((uintptr_t)*cookie);
	int err;

	err = vm_inout_detach(&vm->ioports, port, false, old_func, old_arg);
	if (err == 0) {
		*cookie = NULL;
	}
	return (err);
}

/*
 * External driver interfaces to attach or detach IO port handlers.
 * Must be called with VM write lock held for safety.
 */
int
vm_ioport_hook(struct vm *vm, uint16_t port, ioport_handler_t func,
    void *arg, void **cookie)
{
	int err;

	if (port == 0) {
		return (EINVAL);
	}

	err = vm_inout_attach(&vm->ioports, port, IOPF_DRV_HOOK, func, arg);
	if (err == 0) {
		*cookie = (void *)IOP_GEN_COOKIE(func, arg, port);
	}
	return (err);
}
void
vm_ioport_unhook(struct vm *vm, void **cookie)
{
	uint16_t port = IOP_PORT_FROM_COOKIE((uintptr_t)*cookie);
	ioport_handler_t old_func;
	void *old_arg;
	int err;

	err = vm_inout_detach(&vm->ioports, port, true, &old_func, &old_arg);

	/* ioport-hook-using drivers are expected to be well-behaved */
	VERIFY0(err);
	VERIFY(IOP_GEN_COOKIE(old_func, old_arg, port) == (uintptr_t)*cookie);

	*cookie = NULL;
}

int
vmm_kstat_update_vcpu(struct kstat *ksp, int rw)
{
	struct vm *vm = ksp->ks_private;
	vmm_vcpu_kstats_t *vvk = ksp->ks_data;
	const int vcpuid = vvk->vvk_vcpu.value.ui32;
	struct vcpu *vcpu = &vm->vcpu[vcpuid];

	ASSERT3U(vcpuid, <, VM_MAXCPU);

	vvk->vvk_time_init.value.ui64 = vcpu->ustate_total[VU_INIT];
	vvk->vvk_time_run.value.ui64 = vcpu->ustate_total[VU_RUN];
	vvk->vvk_time_idle.value.ui64 = vcpu->ustate_total[VU_IDLE];
	vvk->vvk_time_emu_kern.value.ui64 = vcpu->ustate_total[VU_EMU_KERN];
	vvk->vvk_time_emu_user.value.ui64 = vcpu->ustate_total[VU_EMU_USER];
	vvk->vvk_time_sched.value.ui64 = vcpu->ustate_total[VU_SCHED];

	return (0);
}

SET_DECLARE(vmm_data_version_entries, const vmm_data_version_entry_t);

static inline bool
vmm_data_is_cpu_specific(uint16_t data_class)
{
	switch (data_class) {
	case VDC_REGISTER:
	case VDC_MSR:
	case VDC_FPU:
	case VDC_LAPIC:
		return (true);
	default:
		break;
	}

	return (false);
}

static int
vmm_data_find(const vmm_data_req_t *req, const vmm_data_version_entry_t **resp)
{
	const vmm_data_version_entry_t **vdpp, *vdp;

	ASSERT(resp != NULL);
	ASSERT(req->vdr_result_len != NULL);

	SET_FOREACH(vdpp, vmm_data_version_entries) {
		vdp = *vdpp;
		if (vdp->vdve_class == req->vdr_class &&
		    vdp->vdve_version == req->vdr_version) {
			/*
			 * Enforce any data length expectation expressed by the
			 * provider for this data.
			 */
			if (vdp->vdve_len_expect != 0 &&
			    vdp->vdve_len_expect > req->vdr_len) {
				*req->vdr_result_len = vdp->vdve_len_expect;
				return (ENOSPC);
			}
			*resp = vdp;
			return (0);
		}
	}
	return (EINVAL);
}

static void *
vmm_data_from_class(const vmm_data_req_t *req, struct vm *vm, int vcpuid)
{
	switch (req->vdr_class) {
		/* per-cpu data/devices */
	case VDC_LAPIC:
		return (vm_lapic(vm, vcpuid));
	case VDC_VMM_ARCH:
		return (vm);

	case VDC_FPU:
	case VDC_REGISTER:
	case VDC_MSR:
		/*
		 * These have per-CPU handling which is dispatched outside
		 * vmm_data_version_entries listing.
		 */
		return (NULL);

		/* system-wide data/devices */
	case VDC_IOAPIC:
		return (vm->vioapic);
	case VDC_ATPIT:
		return (vm->vatpit);
	case VDC_ATPIC:
		return (vm->vatpic);
	case VDC_HPET:
		return (vm->vhpet);
	case VDC_PM_TIMER:
		return (vm->vpmtmr);
	case VDC_RTC:
		return (vm->vrtc);

	default:
		/* The data class will have been validated by now */
		panic("Unexpected class %u", req->vdr_class);
	}
}

const uint32_t arch_msr_iter[] = {
	MSR_EFER,

	/*
	 * While gsbase and fsbase are accessible via the MSR accessors, they
	 * are not included in MSR iteration since they are covered by the
	 * segment descriptor interface too.
	 */
	MSR_KGSBASE,

	MSR_STAR,
	MSR_LSTAR,
	MSR_CSTAR,
	MSR_SF_MASK,

	MSR_SYSENTER_CS_MSR,
	MSR_SYSENTER_ESP_MSR,
	MSR_SYSENTER_EIP_MSR,
	MSR_PAT,
};
const uint32_t generic_msr_iter[] = {
	MSR_TSC,
	MSR_MTRRcap,
	MSR_MTRRdefType,

	MSR_MTRR4kBase, MSR_MTRR4kBase + 1, MSR_MTRR4kBase + 2,
	MSR_MTRR4kBase + 3, MSR_MTRR4kBase + 4, MSR_MTRR4kBase + 5,
	MSR_MTRR4kBase + 6, MSR_MTRR4kBase + 7,

	MSR_MTRR16kBase, MSR_MTRR16kBase + 1,

	MSR_MTRR64kBase,
};

static int
vmm_data_read_msrs(struct vm *vm, int vcpuid, const vmm_data_req_t *req)
{
	VERIFY3U(req->vdr_class, ==, VDC_MSR);
	VERIFY3U(req->vdr_version, ==, 1);

	const uint_t num_msrs = nitems(arch_msr_iter) + nitems(generic_msr_iter)
	    + (VMM_MTRR_VAR_MAX * 2);
	const uint32_t output_len =
	    num_msrs * sizeof (struct vdi_field_entry_v1);
	*req->vdr_result_len = output_len;

	if (req->vdr_len < output_len) {
		return (ENOSPC);
	}

	struct vdi_field_entry_v1 *entryp = req->vdr_data;
	for (uint_t i = 0; i < nitems(arch_msr_iter); i++, entryp++) {
		const uint32_t msr = arch_msr_iter[i];
		uint64_t val = 0;

		int err = ops->vmgetmsr(vm->cookie, vcpuid, msr, &val);
		/* All of these MSRs are expected to work */
		VERIFY0(err);
		entryp->vfe_ident = msr;
		entryp->vfe_value = val;
	}

	struct vm_mtrr *mtrr = &vm->vcpu[vcpuid].mtrr;
	for (uint_t i = 0; i < nitems(generic_msr_iter); i++, entryp++) {
		const uint32_t msr = generic_msr_iter[i];

		entryp->vfe_ident = msr;
		switch (msr) {
		case MSR_TSC:
			/*
			 * Communicate this as the difference from the VM-wide
			 * offset of the boot time.
			 */
			entryp->vfe_value = vm->vcpu[vcpuid].tsc_offset;
			break;
		case MSR_MTRRcap:
		case MSR_MTRRdefType:
		case MSR_MTRR4kBase ... MSR_MTRR4kBase + 7:
		case MSR_MTRR16kBase ... MSR_MTRR16kBase + 1:
		case MSR_MTRR64kBase: {
			int err = vm_rdmtrr(mtrr, msr, &entryp->vfe_value);
			VERIFY0(err);
			break;
		}
		default:
			panic("unexpected msr export %x", msr);
		}
	}
	/* Copy the variable MTRRs */
	for (uint_t i = 0; i < (VMM_MTRR_VAR_MAX * 2); i++, entryp++) {
		const uint32_t msr = MSR_MTRRVarBase + i;

		entryp->vfe_ident = msr;
		int err = vm_rdmtrr(mtrr, msr, &entryp->vfe_value);
		VERIFY0(err);
	}
	return (0);
}

static int
vmm_data_write_msrs(struct vm *vm, int vcpuid, const vmm_data_req_t *req)
{
	VERIFY3U(req->vdr_class, ==, VDC_MSR);
	VERIFY3U(req->vdr_version, ==, 1);

	const struct vdi_field_entry_v1 *entryp = req->vdr_data;
	const uint_t entry_count =
	    req->vdr_len / sizeof (struct vdi_field_entry_v1);
	struct vm_mtrr *mtrr = &vm->vcpu[vcpuid].mtrr;

	/*
	 * First make sure that all of the MSRs can be manipulated.
	 * For now, this check is done by going though the getmsr handler
	 */
	for (uint_t i = 0; i < entry_count; i++, entryp++) {
		const uint32_t msr = entryp->vfe_ident;
		uint64_t val;
		int err = 0;

		switch (msr) {
		case MSR_TSC:
			break;
		default:
			if (is_mtrr_msr(msr)) {
				err = vm_rdmtrr(mtrr, msr, &val);
			} else {
				err = ops->vmgetmsr(vm->cookie, vcpuid, msr,
				    &val);
			}
			break;
		}
		if (err != 0) {
			return (err);
		}
	}

	/*
	 * Fairly confident that all of the 'set' operations are at least
	 * targeting valid MSRs, continue on.
	 */
	entryp = req->vdr_data;
	for (uint_t i = 0; i < entry_count; i++, entryp++) {
		const uint32_t msr = entryp->vfe_ident;
		const uint64_t val = entryp->vfe_value;
		int err = 0;

		switch (msr) {
		case MSR_TSC:
			vm->vcpu[vcpuid].tsc_offset = entryp->vfe_value;
			break;
		default:
			if (is_mtrr_msr(msr)) {
				if (msr == MSR_MTRRcap) {
					/*
					 * MTRRcap is read-only.  If the current
					 * value matches the incoming one,
					 * consider it a success
					 */
					uint64_t comp;
					err = vm_rdmtrr(mtrr, msr, &comp);
					if (err != 0 || comp != val) {
						err = EINVAL;
					}
				} else {
					err = vm_wrmtrr(mtrr, msr, val);
				}
			} else {
				err = ops->vmsetmsr(vm->cookie, vcpuid, msr,
				    val);
			}
			break;
		}
		if (err != 0) {
			return (err);
		}
	}
	*req->vdr_result_len = entry_count * sizeof (struct vdi_field_entry_v1);

	return (0);
}

static const vmm_data_version_entry_t msr_v1 = {
	.vdve_class = VDC_MSR,
	.vdve_version = 1,
	.vdve_len_per_item = sizeof (struct vdi_field_entry_v1),
	.vdve_vcpu_readf = vmm_data_read_msrs,
	.vdve_vcpu_writef = vmm_data_write_msrs,
};
VMM_DATA_VERSION(msr_v1);

static const uint32_t vmm_arch_v1_fields[] = {
	VAI_TSC_BOOT_OFFSET,
	VAI_BOOT_HRTIME,
	VAI_TSC_FREQ,
	VAI_VM_IS_PAUSED,
};

static const uint32_t vmm_arch_v1_vcpu_fields[] = {
	VAI_PEND_NMI,
	VAI_PEND_EXTINT,
	VAI_PEND_EXCP,
	VAI_PEND_INTINFO,
};

static bool
vmm_read_arch_field(struct vm *vm, int vcpuid, uint32_t ident, uint64_t *valp)
{
	ASSERT(valp != NULL);

	if (vcpuid == -1) {
		switch (ident) {
		case VAI_TSC_BOOT_OFFSET:
			*valp = vm->boot_tsc_offset;
			return (true);
		case VAI_BOOT_HRTIME:
			*valp = vm->boot_hrtime;
			return (true);
		case VAI_TSC_FREQ:
			/*
			 * Since the system TSC calibration is not public, just
			 * derive it from the scaling functions available.
			 */
			*valp = unscalehrtime(NANOSEC);
			return (true);
		case VAI_VM_IS_PAUSED:
			*valp = vm->is_paused ? 1 : 0;
			return (true);
		default:
			break;
		}
	} else {
		VERIFY(vcpuid >= 0 && vcpuid <= VM_MAXCPU);

		struct vcpu *vcpu = &vm->vcpu[vcpuid];
		switch (ident) {
		case VAI_PEND_NMI:
			*valp = vcpu->nmi_pending != 0 ? 1 : 0;
			return (true);
		case VAI_PEND_EXTINT:
			*valp = vcpu->extint_pending != 0 ? 1 : 0;
			return (true);
		case VAI_PEND_EXCP:
			*valp = vcpu->exc_pending;
			return (true);
		case VAI_PEND_INTINFO:
			*valp = vcpu->exit_intinfo;
			return (true);
		default:
			break;
		}
	}
	return (false);
}

static int
vmm_data_read_varch(struct vm *vm, int vcpuid, const vmm_data_req_t *req)
{
	VERIFY3U(req->vdr_class, ==, VDC_VMM_ARCH);
	VERIFY3U(req->vdr_version, ==, 1);

	/* per-vCPU fields are handled separately from VM-wide ones */
	if (vcpuid != -1 && (vcpuid < 0 || vcpuid >= VM_MAXCPU)) {
		return (EINVAL);
	}

	struct vdi_field_entry_v1 *entryp = req->vdr_data;

	/* Specific fields requested */
	if ((req->vdr_flags & VDX_FLAG_READ_COPYIN) != 0) {
		const uint_t count =
		    req->vdr_len / sizeof (struct vdi_field_entry_v1);

		for (uint_t i = 0; i < count; i++, entryp++) {
			if (!vmm_read_arch_field(vm, vcpuid, entryp->vfe_ident,
			    &entryp->vfe_value)) {
				return (EINVAL);
			}
		}
		*req->vdr_result_len =
		    count * sizeof (struct vdi_field_entry_v1);
		return (0);
	}

	/* Emit all of the possible values */
	const uint32_t *idents;
	uint_t ident_count;

	if (vcpuid == -1) {
		idents = vmm_arch_v1_fields;
		ident_count = nitems(vmm_arch_v1_fields);
	} else {
		idents = vmm_arch_v1_vcpu_fields;
		ident_count = nitems(vmm_arch_v1_vcpu_fields);

	}

	const uint32_t total_size =
	    ident_count * sizeof (struct vdi_field_entry_v1);

	*req->vdr_result_len = total_size;
	if (req->vdr_len < total_size) {
		return (ENOSPC);
	}
	for (uint_t i = 0; i < ident_count; i++, entryp++) {
		entryp->vfe_ident = idents[i];
		VERIFY(vmm_read_arch_field(vm, vcpuid, entryp->vfe_ident,
		    &entryp->vfe_value));
	}
	return (0);
}

static int
vmm_data_write_varch_vcpu(struct vm *vm, int vcpuid, const vmm_data_req_t *req)
{
	VERIFY3U(req->vdr_class, ==, VDC_VMM_ARCH);
	VERIFY3U(req->vdr_version, ==, 1);

	if (vcpuid < 0 || vcpuid >= VM_MAXCPU) {
		return (EINVAL);
	}

	const struct vdi_field_entry_v1 *entryp = req->vdr_data;
	const uint_t entry_count =
	    req->vdr_len / sizeof (struct vdi_field_entry_v1);
	struct vcpu *vcpu = &vm->vcpu[vcpuid];

	for (uint_t i = 0; i < entry_count; i++, entryp++) {
		const uint64_t val = entryp->vfe_value;

		switch (entryp->vfe_ident) {
		case VAI_PEND_NMI:
			vcpu->nmi_pending = (val != 0);
			break;
		case VAI_PEND_EXTINT:
			vcpu->extint_pending = (val != 0);
			break;
		case VAI_PEND_EXCP:
			if (!VM_INTINFO_PENDING(val)) {
				vcpu->exc_pending = 0;
			} else if (VM_INTINFO_TYPE(val) != VM_INTINFO_HWEXCP ||
			    (val & VM_INTINFO_MASK_RSVD) != 0) {
				/* reject improperly-formed hw exception */
				return (EINVAL);
			} else {
				vcpu->exc_pending = val;
			}
			break;
		case VAI_PEND_INTINFO:
			if (vm_exit_intinfo(vm, vcpuid, val) != 0) {
				return (EINVAL);
			}
			break;
		default:
			return (EINVAL);
		}
	}

	*req->vdr_result_len = entry_count * sizeof (struct vdi_field_entry_v1);
	return (0);
}

static int
vmm_data_write_varch(struct vm *vm, int vcpuid, const vmm_data_req_t *req)
{
	VERIFY3U(req->vdr_class, ==, VDC_VMM_ARCH);
	VERIFY3U(req->vdr_version, ==, 1);

	/* per-vCPU fields are handled separately from VM-wide ones */
	if (vcpuid != -1) {
		return (vmm_data_write_varch_vcpu(vm, vcpuid, req));
	}

	const struct vdi_field_entry_v1 *entryp = req->vdr_data;
	const uint_t entry_count =
	    req->vdr_len / sizeof (struct vdi_field_entry_v1);

	for (uint_t i = 0; i < entry_count; i++, entryp++) {
		const uint64_t val = entryp->vfe_value;

		switch (entryp->vfe_ident) {
		case VAI_TSC_BOOT_OFFSET:
			vm->boot_tsc_offset = val;
			break;
		case VAI_BOOT_HRTIME:
			vm->boot_hrtime = val;
			break;
		case VAI_TSC_FREQ:
			/* Guest TSC frequency not (currently) adjustable */
			return (EPERM);
		case VAI_VM_IS_PAUSED:
			/*
			 * The VM_PAUSE and VM_RESUME ioctls are the officially
			 * sanctioned mechanisms for setting the is-paused state
			 * of the VM.
			 */
			return (EPERM);
		default:
			return (EINVAL);
		}
	}
	*req->vdr_result_len = entry_count * sizeof (struct vdi_field_entry_v1);
	return (0);
}

static const vmm_data_version_entry_t vmm_arch_v1 = {
	.vdve_class = VDC_VMM_ARCH,
	.vdve_version = 1,
	.vdve_len_per_item = sizeof (struct vdi_field_entry_v1),
	.vdve_vcpu_readf = vmm_data_read_varch,
	.vdve_vcpu_writef = vmm_data_write_varch,
};
VMM_DATA_VERSION(vmm_arch_v1);

static int
vmm_data_read_versions(void *arg, const vmm_data_req_t *req)
{
	VERIFY3U(req->vdr_class, ==, VDC_VERSION);
	VERIFY3U(req->vdr_version, ==, 1);

	const uint32_t total_size = SET_COUNT(vmm_data_version_entries) *
	    sizeof (struct vdi_version_entry_v1);

	/* Make sure there is room for all of the entries */
	*req->vdr_result_len = total_size;
	if (req->vdr_len < *req->vdr_result_len) {
		return (ENOSPC);
	}

	struct vdi_version_entry_v1 *entryp = req->vdr_data;
	const vmm_data_version_entry_t **vdpp;
	SET_FOREACH(vdpp, vmm_data_version_entries) {
		const vmm_data_version_entry_t *vdp = *vdpp;

		entryp->vve_class = vdp->vdve_class;
		entryp->vve_version = vdp->vdve_version;
		entryp->vve_len_expect = vdp->vdve_len_expect;
		entryp->vve_len_per_item = vdp->vdve_len_per_item;
		entryp++;
	}
	return (0);
}

static int
vmm_data_write_versions(void *arg, const vmm_data_req_t *req)
{
	/* Writing to the version information makes no sense */
	return (EPERM);
}

static const vmm_data_version_entry_t versions_v1 = {
	.vdve_class = VDC_VERSION,
	.vdve_version = 1,
	.vdve_len_per_item = sizeof (struct vdi_version_entry_v1),
	.vdve_readf = vmm_data_read_versions,
	.vdve_writef = vmm_data_write_versions,
};
VMM_DATA_VERSION(versions_v1);

int
vmm_data_read(struct vm *vm, int vcpuid, const vmm_data_req_t *req)
{
	int err = 0;

	if (vmm_data_is_cpu_specific(req->vdr_class)) {
		if (vcpuid >= VM_MAXCPU) {
			return (EINVAL);
		}
	}

	const vmm_data_version_entry_t *entry = NULL;
	err = vmm_data_find(req, &entry);
	if (err != 0) {
		return (err);
	}
	ASSERT(entry != NULL);

	if (entry->vdve_readf != NULL) {
		void *datap = vmm_data_from_class(req, vm, vcpuid);

		err = entry->vdve_readf(datap, req);
	} else if (entry->vdve_vcpu_readf != NULL) {
		err = entry->vdve_vcpu_readf(vm, vcpuid, req);
	} else {
		err = EINVAL;
	}

	/*
	 * Successful reads of fixed-length data should populate the length of
	 * that result.
	 */
	if (err == 0 && entry->vdve_len_expect != 0) {
		*req->vdr_result_len = entry->vdve_len_expect;
	}

	return (err);
}

int
vmm_data_write(struct vm *vm, int vcpuid, const vmm_data_req_t *req)
{
	int err = 0;

	if (vmm_data_is_cpu_specific(req->vdr_class)) {
		if (vcpuid >= VM_MAXCPU) {
			return (EINVAL);
		}
	}

	const vmm_data_version_entry_t *entry = NULL;
	err = vmm_data_find(req, &entry);
	if (err != 0) {
		return (err);
	}
	ASSERT(entry != NULL);

	if (entry->vdve_writef != NULL) {
		void *datap = vmm_data_from_class(req, vm, vcpuid);

		err = entry->vdve_writef(datap, req);
	} else if (entry->vdve_vcpu_writef != NULL) {
		err = entry->vdve_vcpu_writef(vm, vcpuid, req);
	} else {
		err = EINVAL;
	}

	/*
	 * Successful writes of fixed-length data should populate the length of
	 * that result.
	 */
	if (err == 0 && entry->vdve_len_expect != 0) {
		*req->vdr_result_len = entry->vdve_len_expect;
	}

	return (err);
}
