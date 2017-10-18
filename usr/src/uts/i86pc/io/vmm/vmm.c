/*-
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
 * $FreeBSD: head/sys/amd64/vmm/vmm.c 280929 2015-04-01 00:15:31Z tychon $
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
 * Copyright 2017 Joyent, Inc.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: head/sys/amd64/vmm/vmm.c 280929 2015-04-01 00:15:31Z tychon $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/sysctl.h>
#include <sys/malloc.h>
#include <sys/pcpu.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/sched.h>
#include <sys/smp.h>
#include <x86/psl.h>
#include <sys/systm.h>

#include <vm/vm.h>

#include <machine/vm.h>
#include <machine/pcb.h>
#include <machine/smp.h>
#include <x86/apicreg.h>

#include <machine/vmm.h>
#include <machine/vmm_dev.h>
#include <machine/vmm_instruction_emul.h>

#include "vmm_ioport.h"
#include "vmm_ktr.h"
#include "vmm_host.h"
#include "vmm_mem.h"
#include "vmm_util.h"
#include "vatpic.h"
#include "vatpit.h"
#include "vhpet.h"
#include "vioapic.h"
#include "vlapic.h"
#include "vmm_ipi.h"
#include "vmm_stat.h"
#include "vmm_lapic.h"

#ifdef	__FreeBSD__
#include "io/ppt.h"
#include "io/iommu.h"
#endif

struct vhpet;
struct vioapic;
struct vlapic;

struct vcpu {
	int		flags;
	enum vcpu_state	state;
	struct mtx	mtx;
	int		hostcpu;	/* host cpuid this vcpu last ran on */
	struct vlapic	*vlapic;
	int		 vcpuid;
	struct savefpu	*guestfpu;	/* guest fpu state */
	void		*stats;
	struct vm_exit	exitinfo;
	uint64_t	nextrip;	/* (x) next instruction to execute */
	enum x2apic_state x2apic_state;
	uint64_t	exitintinfo;
	int		nmi_pending;
	int		extint_pending;
	struct vm_exception exception;
	int		exception_pending;
};

#define	vcpu_lock_init(v)	mtx_init(&((v)->mtx), "vcpu lock", 0, MTX_SPIN)
#define	vcpu_lock(v)		mtx_lock_spin(&((v)->mtx))
#define	vcpu_unlock(v)		mtx_unlock_spin(&((v)->mtx))
#define	vcpu_assert_locked(v)	mtx_assert(&((v)->mtx), MA_OWNED)

#define	VM_MAX_MEMORY_SEGMENTS	8

struct vm {
	void		*cookie;	/* processor-specific data */
	void		*iommu;		/* iommu-specific data */
	struct vcpu	vcpu[VM_MAXCPU];
	struct vhpet	*vhpet;
	struct vioapic	*vioapic;	/* virtual ioapic */
	struct vatpic	*vatpic;	/* virtual atpic */
	struct vatpit	*vatpit;	/* virtual atpit */
	int		num_mem_segs;
	struct vm_memory_segment mem_segs[VM_MAX_MEMORY_SEGMENTS];
	char		name[VM_MAX_NAMELEN];

	/*
	 * Set of active vcpus.
	 * An active vcpu is one that has been started implicitly (BSP) or
	 * explicitly (AP) by sending it a startup ipi.
	 */
	cpuset_t	active_cpus;

	vm_rendezvous_func_t rendezvous_func;
};

static int vmm_initialized;

static struct vmm_ops *ops;
#define	VMM_INIT()	(ops != NULL ? (*ops->init)() : 0)
#define	VMM_CLEANUP()	(ops != NULL ? (*ops->cleanup)() : 0)

#define	VMINIT(vm)	(ops != NULL ? (*ops->vminit)(vm): NULL)
#define	VMRUN(vmi, vcpu, rip) \
	(ops != NULL ? (*ops->vmrun)(vmi, vcpu, rip) : ENXIO)
#define	VMCLEANUP(vmi)	(ops != NULL ? (*ops->vmcleanup)(vmi) : NULL)
#define	VMMMAP_SET(vmi, gpa, hpa, len, attr, prot, spm)			\
    	(ops != NULL ? 							\
    	(*ops->vmmmap_set)(vmi, gpa, hpa, len, attr, prot, spm) :	\
	ENXIO)
#define	VMMMAP_GET(vmi, gpa) \
	(ops != NULL ? (*ops->vmmmap_get)(vmi, gpa) : ENXIO)
#define	VMGETREG(vmi, vcpu, num, retval)		\
	(ops != NULL ? (*ops->vmgetreg)(vmi, vcpu, num, retval) : ENXIO)
#define	VMSETREG(vmi, vcpu, num, val)		\
	(ops != NULL ? (*ops->vmsetreg)(vmi, vcpu, num, val) : ENXIO)
#define	VMGETDESC(vmi, vcpu, num, desc)		\
	(ops != NULL ? (*ops->vmgetdesc)(vmi, vcpu, num, desc) : ENXIO)
#define	VMSETDESC(vmi, vcpu, num, desc)		\
	(ops != NULL ? (*ops->vmsetdesc)(vmi, vcpu, num, desc) : ENXIO)
#define	VMGETCAP(vmi, vcpu, num, retval)	\
	(ops != NULL ? (*ops->vmgetcap)(vmi, vcpu, num, retval) : ENXIO)
#define	VMSETCAP(vmi, vcpu, num, val)		\
	(ops != NULL ? (*ops->vmsetcap)(vmi, vcpu, num, val) : ENXIO)
#define	VLAPIC_INIT(vmi, vcpu)			\
	(ops != NULL ? (*ops->vlapic_init)(vmi, vcpu) : NULL)
#define	VLAPIC_CLEANUP(vmi, vlapic)		\
	(ops != NULL ? (*ops->vlapic_cleanup)(vmi, vlapic) : NULL)

#define	fpu_start_emulating()	load_cr0(rcr0() | CR0_TS)
#define	fpu_stop_emulating()	clts()

static MALLOC_DEFINE(M_VM, "vm", "vm");

/* statistics */
static VMM_STAT(VCPU_TOTAL_RUNTIME, "vcpu total runtime");

static int vmm_ipinum;
SYSCTL_INT(_hw_vmm, OID_AUTO, ipinum, CTLFLAG_RD, &vmm_ipinum, 0,
    "IPI vector used for vcpu notifications");

static void
vcpu_cleanup(struct vm *vm, int i)
{
	struct vcpu *vcpu = &vm->vcpu[i];

	VLAPIC_CLEANUP(vm->cookie, vcpu->vlapic);
#ifdef	__FreeBSD__
	vmm_stat_free(vcpu->stats);	
#endif
	fpu_save_area_free(vcpu->guestfpu);
}

static void
vcpu_init(struct vm *vm, uint32_t vcpu_id)
{
	struct vcpu *vcpu;
	
	vcpu = &vm->vcpu[vcpu_id];

	vcpu_lock_init(vcpu);
	vcpu->hostcpu = NOCPU;
	vcpu->vcpuid = vcpu_id;
	vcpu->vlapic = VLAPIC_INIT(vm->cookie, vcpu_id);
	vm_set_x2apic_state(vm, vcpu_id, X2APIC_DISABLED);
	vcpu->exitintinfo = 0;
	vcpu->guestfpu = fpu_save_area_alloc();
	fpu_save_area_reset(vcpu->guestfpu);
#ifdef	__FreeBSD__
	vcpu->stats = vmm_stat_alloc();
#endif
}

struct vm_exit *
vm_exitinfo(struct vm *vm, int cpuid)
{
	struct vcpu *vcpu;

	if (cpuid < 0 || cpuid >= VM_MAXCPU)
		panic("vm_exitinfo: invalid cpuid %d", cpuid);

	vcpu = &vm->vcpu[cpuid];

	return (&vcpu->exitinfo);
}

static int
vmm_init(void)
{
	int error;

	vmm_host_state_init();
#ifdef	__FreeBSD__
	vmm_ipi_init();
#endif

	error = vmm_mem_init();
	if (error)
		return (error);

	if (vmm_is_intel())
		ops = &vmm_ops_intel;
	else if (vmm_is_amd())
		ops = &vmm_ops_amd;
	else
		return (ENXIO);

	return (VMM_INIT());
}

#ifdef	__FreeBSD__
static int
vmm_handler(module_t mod, int what, void *arg)
{
	int error;

	switch (what) {
	case MOD_LOAD:
		vmmdev_init();
		if (ppt_num_devices() > 0)
			iommu_init();
		error = vmm_init();
		if (error == 0)
			vmm_initialized = 1;
		break;
	case MOD_UNLOAD:
		error = vmmdev_cleanup();
		if (error == 0) {
			iommu_cleanup();
			vmm_ipi_cleanup();
			error = VMM_CLEANUP();
			/*
			 * Something bad happened - prevent new
			 * VMs from being created
			 */
			if (error)
				vmm_initialized = 0;
		}
		break;
	default:
		error = 0;
		break;
	}
	return (error);
}

static moduledata_t vmm_kmod = {
	"vmm",
	vmm_handler,
	NULL
};

/*
 * vmm initialization has the following dependencies:
 *
 * - iommu initialization must happen after the pci passthru driver has had
 *   a chance to attach to any passthru devices (after SI_SUB_CONFIGURE).
 *
 * - VT-x initialization requires smp_rendezvous() and therefore must happen
 *   after SMP is fully functional (after SI_SUB_SMP).
 */
DECLARE_MODULE(vmm, vmm_kmod, SI_SUB_SMP + 1, SI_ORDER_ANY);
MODULE_VERSION(vmm, 1);

SYSCTL_NODE(_hw, OID_AUTO, vmm, CTLFLAG_RW, NULL, NULL);
#else
int
vmm_mod_load()
{
	int	error;

	vmmdev_init();
	error = vmm_init();
	if (error == 0)
		vmm_initialized = 1;

	return (error);
}

int
vmm_mod_unload()
{
	int	error;

	vmmdev_cleanup();
	error = VMM_CLEANUP();
	if (error)
		return (error);
	vmm_initialized = 0;

	return (0);
}
#endif

int
vm_create(const char *name, struct vm **retvm)
{
	int i;
	struct vm *vm;
#ifdef	__FreeBSD__
	vm_paddr_t maxaddr;
#endif

#if notyet
	const int BSP = 0;
#endif

	/*
	 * If vmm.ko could not be successfully initialized then don't attempt
	 * to create the virtual machine.
	 */
	if (!vmm_initialized)
		return (ENXIO);

	if (name == NULL || strlen(name) >= VM_MAX_NAMELEN)
		return (EINVAL);

	vm = malloc(sizeof(struct vm), M_VM, M_WAITOK | M_ZERO);
	strcpy(vm->name, name);
	vm->cookie = VMINIT(vm);

	vm->vioapic = vioapic_init(vm);
	vm->vhpet = vhpet_init(vm);
	vm->vatpic = vatpic_init(vm);
	vm->vatpit = vatpit_init(vm);

	for (i = 0; i < VM_MAXCPU; i++) {
		vcpu_init(vm, i);
	}

#ifdef	__FreeBSD__
	maxaddr = vmm_mem_maxaddr();
	vm->iommu = iommu_create_domain(maxaddr);
#endif

	*retvm = vm;
	return (0);
}

static void
vm_free_mem_seg(struct vm *vm, struct vm_memory_segment *seg)
{
	size_t len;
	vm_paddr_t hpa;
#ifdef	__FreeBSD__
	void *host_domain;

	host_domain = iommu_host_domain();
#endif

	len = 0;
	while (len < seg->len) {
		hpa = vm_gpa2hpa(vm, seg->gpa + len, PAGE_SIZE);
		if (hpa == (vm_paddr_t)-1) {
			panic("vm_free_mem_segs: cannot free hpa "
			      "associated with gpa 0x%016lx", seg->gpa + len);
		}

#ifdef	__FreeBSD__
		/*
		 * Remove the 'gpa' to 'hpa' mapping in VMs domain.
		 * And resurrect the 1:1 mapping for 'hpa' in 'host_domain'.
		 */
		iommu_remove_mapping(vm->iommu, seg->gpa + len, PAGE_SIZE);
		iommu_create_mapping(host_domain, hpa, hpa, PAGE_SIZE);
#endif

		vmm_mem_free(hpa, PAGE_SIZE);

		len += PAGE_SIZE;
	}

#ifdef	__FreeBSD__
	/*
	 * Invalidate cached translations associated with 'vm->iommu' since
	 * we have now moved some pages from it.
	 */
	iommu_invalidate_tlb(vm->iommu);
#endif

	bzero(seg, sizeof(struct vm_memory_segment));
}

void
vm_destroy(struct vm *vm)
{
	int i;

#ifdef	__FreeBSD__
	ppt_unassign_all(vm);
#endif

	for (i = 0; i < vm->num_mem_segs; i++)
		vm_free_mem_seg(vm, &vm->mem_segs[i]);

	vm->num_mem_segs = 0;

	for (i = 0; i < VM_MAXCPU; i++)
		vcpu_cleanup(vm, i);

	vatpit_cleanup(vm->vatpit);
	vhpet_cleanup(vm->vhpet);
	vatpic_cleanup(vm->vatpic);
	vioapic_cleanup(vm->vioapic);

#ifdef	__FreeBSD__
	iommu_destroy_domain(vm->iommu);
#endif

	VMCLEANUP(vm->cookie);

	free(vm, M_VM);
}

const char *
vm_name(struct vm *vm)
{
	return (vm->name);
}

#ifdef	__FreeBSD__
int
vm_map_mmio(struct vm *vm, vm_paddr_t gpa, size_t len, vm_paddr_t hpa)
{
	const boolean_t spok = TRUE;	/* superpage mappings are ok */

	return (VMMMAP_SET(vm->cookie, gpa, hpa, len, VM_MEMATTR_UNCACHEABLE,
			   VM_PROT_RW, spok));
}

int
vm_unmap_mmio(struct vm *vm, vm_paddr_t gpa, size_t len)
{
	const boolean_t spok = TRUE;	/* superpage mappings are ok */

	return (VMMMAP_SET(vm->cookie, gpa, 0, len, 0,
			   VM_PROT_NONE, spok));
}
#endif

/*
 * Returns TRUE if 'gpa' is available for allocation and FALSE otherwise
 */
static boolean_t
vm_gpa_available(struct vm *vm, vm_paddr_t gpa)
{
	int i;
	vm_paddr_t gpabase, gpalimit;

	if (gpa & PAGE_MASK)
		panic("vm_gpa_available: gpa (0x%016lx) not page aligned", gpa);

	for (i = 0; i < vm->num_mem_segs; i++) {
		gpabase = vm->mem_segs[i].gpa;
		gpalimit = gpabase + vm->mem_segs[i].len;
		if (gpa >= gpabase && gpa < gpalimit)
			return (FALSE);
	}

	return (TRUE);
}

int
vm_malloc(struct vm *vm, vm_paddr_t gpa, size_t len)
{
	int error, available, allocated;
	struct vm_memory_segment *seg;
	vm_paddr_t g, hpa;
#ifdef	__FreeBSD__
	void *host_domain;
#endif

	const boolean_t spok = TRUE;	/* superpage mappings are ok */

	if ((gpa & PAGE_MASK) || (len & PAGE_MASK) || len == 0)
		return (EINVAL);
	
	available = allocated = 0;
	g = gpa;
	while (g < gpa + len) {
		if (vm_gpa_available(vm, g))
			available++;
		else
			allocated++;

		g += PAGE_SIZE;
	}

	/*
	 * If there are some allocated and some available pages in the address
	 * range then it is an error.
	 */
	if (allocated && available)
		return (EINVAL);

	/*
	 * If the entire address range being requested has already been
	 * allocated then there isn't anything more to do.
	 */
	if (allocated && available == 0)
		return (0);

	if (vm->num_mem_segs >= VM_MAX_MEMORY_SEGMENTS)
		return (E2BIG);

#ifdef	__FreeBSD__
	host_domain = iommu_host_domain();
#endif

	seg = &vm->mem_segs[vm->num_mem_segs];

	error = 0;
	seg->gpa = gpa;
	seg->len = 0;
	while (seg->len < len) {
		hpa = vmm_mem_alloc(PAGE_SIZE);
		if (hpa == 0) {
			error = ENOMEM;
			break;
		}

		error = VMMMAP_SET(vm->cookie, gpa + seg->len, hpa, PAGE_SIZE,
				   VM_MEMATTR_WRITE_BACK, VM_PROT_ALL, spok);
		if (error)
			break;

#ifdef	__FreeBSD__
		/*
		 * Remove the 1:1 mapping for 'hpa' from the 'host_domain'.
		 * Add mapping for 'gpa + seg->len' to 'hpa' in the VMs domain.
		 */
		iommu_remove_mapping(host_domain, hpa, PAGE_SIZE);
		iommu_create_mapping(vm->iommu, gpa + seg->len, hpa, PAGE_SIZE);
#endif

		seg->len += PAGE_SIZE;
	}

	if (error) {
		vm_free_mem_seg(vm, seg);
		return (error);
	}

#ifdef	__FreeBSD__
	/*
	 * Invalidate cached translations associated with 'host_domain' since
	 * we have now moved some pages from it.
	 */
	iommu_invalidate_tlb(host_domain);
#endif

	vm->num_mem_segs++;

	return (0);
}

vm_paddr_t
vm_gpa2hpa(struct vm *vm, vm_paddr_t gpa, size_t len)
{
	vm_paddr_t nextpage;

	nextpage = rounddown(gpa + PAGE_SIZE, PAGE_SIZE);
	if (len > nextpage - gpa)
		panic("vm_gpa2hpa: invalid gpa/len: 0x%016lx/%lu", gpa, len);

	return (VMMMAP_GET(vm->cookie, gpa));
}

void *
vm_gpa_hold(struct vm *vm, vm_paddr_t gpa, size_t len, int reqprot,
	    void **cookie)
{
#ifdef	__FreeBSD__
	int count, pageoff;
	vm_page_t m;

	pageoff = gpa & PAGE_MASK;
	if (len > PAGE_SIZE - pageoff)
		panic("vm_gpa_hold: invalid gpa/len: 0x%016lx/%lu", gpa, len);

	count = vm_fault_quick_hold_pages(&vm->vmspace->vm_map,
	    trunc_page(gpa), PAGE_SIZE, reqprot, &m, 1);

	if (count == 1) {
		*cookie = m;
		return ((void *)(PHYS_TO_DMAP(VM_PAGE_TO_PHYS(m)) + pageoff));
	} else {
		*cookie = NULL;
		return (NULL);
	}
#else
	int pageoff;
	vm_paddr_t hpa;

	pageoff = gpa & PAGE_MASK;
	if (len > PAGE_SIZE - pageoff)
		panic("vm_gpa_hold: invalid gpa/len: 0x%016lx/%lu", gpa, len);

	hpa = vm_gpa2hpa(vm, gpa, len);
	if (hpa == (vm_paddr_t)-1)
		return (NULL);

	return (hat_kpm_pfn2va(btop(hpa)) + pageoff);
#endif
}

void
vm_gpa_release(void *cookie)
{
#ifdef	__FreeBSD__
	vm_page_t m = cookie;

	vm_page_lock(m);
	vm_page_unhold(m);
	vm_page_unlock(m);
#endif
}

int
vm_gpabase2memseg(struct vm *vm, vm_paddr_t gpabase,
		  struct vm_memory_segment *seg)
{
	int i;

	for (i = 0; i < vm->num_mem_segs; i++) {
		if (gpabase == vm->mem_segs[i].gpa) {
			*seg = vm->mem_segs[i];
			return (0);
		}
	}
	return (-1);
}

int
vm_get_register(struct vm *vm, int vcpu, int reg, uint64_t *retval)
{

	if (vcpu < 0 || vcpu >= VM_MAXCPU)
		return (EINVAL);

	if (reg >= VM_REG_LAST)
		return (EINVAL);

	return (VMGETREG(vm->cookie, vcpu, reg, retval));
}

int
vm_set_register(struct vm *vm, int vcpuid, int reg, uint64_t val)
{
	struct vcpu *vcpu;
	int error;

	if (vcpuid < 0 || vcpuid >= VM_MAXCPU)
		return (EINVAL);

	if (reg >= VM_REG_LAST)
		return (EINVAL);

	error = VMSETREG(vm->cookie, vcpuid, reg, val);
	if (error || reg != VM_REG_GUEST_RIP)
		return (error);

	/* Set 'nextrip' to match the value of %rip */
	VCPU_CTR1(vm, vcpuid, "Setting nextrip to %#lx", val);
	vcpu = &vm->vcpu[vcpuid];
	vcpu->nextrip = val;
	return (0);
}

static boolean_t
is_descriptor_table(int reg)
{

	switch (reg) {
	case VM_REG_GUEST_IDTR:
	case VM_REG_GUEST_GDTR:
		return (TRUE);
	default:
		return (FALSE);
	}
}

static boolean_t
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
		return (TRUE);
	default:
		return (FALSE);
	}
}

int
vm_get_seg_desc(struct vm *vm, int vcpu, int reg,
		struct seg_desc *desc)
{

	if (vcpu < 0 || vcpu >= VM_MAXCPU)
		return (EINVAL);

	if (!is_segment_register(reg) && !is_descriptor_table(reg))
		return (EINVAL);

	return (VMGETDESC(vm->cookie, vcpu, reg, desc));
}

int
vm_set_seg_desc(struct vm *vm, int vcpu, int reg,
		struct seg_desc *desc)
{
	if (vcpu < 0 || vcpu >= VM_MAXCPU)
		return (EINVAL);

	if (!is_segment_register(reg) && !is_descriptor_table(reg))
		return (EINVAL);

	return (VMSETDESC(vm->cookie, vcpu, reg, desc));
}

static void
restore_guest_fpustate(struct vcpu *vcpu)
{

	/* flush host state to the pcb */
	fpuexit(curthread);

	/* restore guest FPU state */
	fpu_stop_emulating();
	fpurestore(vcpu->guestfpu);

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

	/* save guest FPU state */
	fpu_stop_emulating();
	fpusave(vcpu->guestfpu);
	fpu_start_emulating();
}

static VMM_STAT(VCPU_IDLE_TICKS, "number of ticks vcpu was idle");

static int
vcpu_set_state_locked(struct vcpu *vcpu, enum vcpu_state newstate,
    bool from_idle)
{
	int error;

	vcpu_assert_locked(vcpu);

	/*
	 * State transitions from the vmmdev_ioctl() must always begin from
	 * the VCPU_IDLE state. This guarantees that there is only a single
	 * ioctl() operating on a vcpu at any point.
	 */
	if (from_idle) {
		while (vcpu->state != VCPU_IDLE)
			msleep_spin(&vcpu->state, &vcpu->mtx, "vmstat", hz);
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

	if (newstate == VCPU_IDLE)
		wakeup(&vcpu->state);

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
vcpu_require_state_locked(struct vcpu *vcpu, enum vcpu_state newstate)
{
	int error;

	if ((error = vcpu_set_state_locked(vcpu, newstate, false)) != 0)
		panic("Error %d setting state to %d", error, newstate);
}

/*
 * Emulate a guest 'hlt' by sleeping until the vcpu is ready to run.
 */
static int
vm_handle_hlt(struct vm *vm, int vcpuid, bool intr_disabled, bool *retu)
{
#ifdef	__FreeBSD__
	struct vm_exit *vmexit;
#endif
	struct vcpu *vcpu;
	int t, timo, spindown;

	vcpu = &vm->vcpu[vcpuid];
	spindown = 0;

	vcpu_lock(vcpu);

	/*
	 * Do a final check for pending NMI or interrupts before
	 * really putting this thread to sleep.
	 *
	 * These interrupts could have happened any time after we
	 * returned from VMRUN() and before we grabbed the vcpu lock.
	 */
	if (vm->rendezvous_func == NULL &&
	    !vm_nmi_pending(vm, vcpuid) &&
	    (intr_disabled || !vlapic_pending_intr(vcpu->vlapic, NULL))) {
		t = ticks;
		vcpu_require_state_locked(vcpu, VCPU_SLEEPING);
		if (vlapic_enabled(vcpu->vlapic)) {
			/*
			 * XXX msleep_spin() is not interruptible so use the
			 * 'timo' to put an upper bound on the sleep time.
			 */
			timo = hz;
			msleep_spin(vcpu, &vcpu->mtx, "vmidle", timo);
		} else {
			/*
			 * Spindown the vcpu if the apic is disabled and it
			 * had entered the halted state.
			 */
			spindown = 1;
		}
		vcpu_require_state_locked(vcpu, VCPU_FROZEN);
		vmm_stat_incr(vm, vcpuid, VCPU_IDLE_TICKS, ticks - t);
	}
	vcpu_unlock(vcpu);

#ifdef	__FreeBSD__
	/*
	 * Since 'vm_deactivate_cpu()' grabs a sleep mutex we must call it
	 * outside the confines of the vcpu spinlock.
	 */
	if (spindown) {
		*retu = true;
		vmexit = vm_exitinfo(vm, vcpuid);
		vmexit->exitcode = VM_EXITCODE_SPINDOWN_CPU;
		vm_deactivate_cpu(vm, vcpuid);
		VCPU_CTR0(vm, vcpuid, "spinning down cpu");
	}
#endif

	return (0);
}

static int
vm_handle_inst_emul(struct vm *vm, int vcpuid, bool *retu)
{
	struct vie *vie;
	struct vcpu *vcpu;
	struct vm_exit *vme;
	uint64_t gla, gpa, cs_base;
	struct vm_guest_paging *paging;
	mem_region_read_t mread;
	mem_region_write_t mwrite;
	enum vm_cpu_mode cpu_mode;
	int cs_d, error, length;

	vcpu = &vm->vcpu[vcpuid];
	vme = &vcpu->exitinfo;

	gla = vme->u.inst_emul.gla;
	gpa = vme->u.inst_emul.gpa;
	cs_base = vme->u.inst_emul.cs_base;
	cs_d = vme->u.inst_emul.cs_d;
	vie = &vme->u.inst_emul.vie;
	paging = &vme->u.inst_emul.paging;
	cpu_mode = paging->cpu_mode;

	VCPU_CTR1(vm, vcpuid, "inst_emul fault accessing gpa %#lx", gpa);

	/* Fetch, decode and emulate the faulting instruction */
	if (vie->num_valid == 0) {
		/*
		 * If the instruction length is not known then assume a
		 * maximum size instruction.
		 */
		length = vme->inst_length ? vme->inst_length : VIE_INST_SIZE;
		error = vmm_fetch_instruction(vm, vcpuid, paging, vme->rip +
		    cs_base, length, vie);
	} else {
		/*
		 * The instruction bytes have already been copied into 'vie'
		 */
		error = 0;
	}
	if (error == 1)
		return (0);		/* Resume guest to handle page fault */
	else if (error == -1)
		return (EFAULT);
	else if (error != 0)
		panic("%s: vmm_fetch_instruction error %d", __func__, error);

	if (vmm_decode_instruction(vm, vcpuid, gla, cpu_mode, cs_d, vie) != 0)
		return (EFAULT);

	/*
	 * If the instruction length was not specified then update it now
	 * along with 'nextrip'.
	 */
	if (vme->inst_length == 0) {
		vme->inst_length = vie->num_processed;
		vcpu->nextrip += vie->num_processed;
	}
 
	/* return to userland unless this is an in-kernel emulated device */
	if (gpa >= DEFAULT_APIC_BASE && gpa < DEFAULT_APIC_BASE + PAGE_SIZE) {
		mread = lapic_mmio_read;
		mwrite = lapic_mmio_write;
	} else if (gpa >= VIOAPIC_BASE && gpa < VIOAPIC_BASE + VIOAPIC_SIZE) {
		mread = vioapic_mmio_read;
		mwrite = vioapic_mmio_write;
	} else if (gpa >= VHPET_BASE && gpa < VHPET_BASE + VHPET_SIZE) {
		mread = vhpet_mmio_read;
		mwrite = vhpet_mmio_write;
	} else {
		*retu = true;
		return (0);
	}

	error = vmm_emulate_instruction(vm, vcpuid, gpa, vie, paging,
	    mread, mwrite, retu);

	return (error);
}

int
vm_run(struct vm *vm, struct vm_run *vmrun)
{
	int error, vcpuid;
	struct vcpu *vcpu;
#ifdef	__FreeBSD__
	struct pcb *pcb;
#endif
	uint64_t tscval;
	struct vm_exit *vme;
	bool retu, intr_disabled;

	vcpuid = vmrun->cpuid;

	if (vcpuid < 0 || vcpuid >= VM_MAXCPU)
		return (EINVAL);

	vcpu = &vm->vcpu[vcpuid];
	vme = &vcpu->exitinfo;
restart:
	critical_enter();

	tscval = rdtsc();

#ifdef	__FreeBSD__
	pcb = PCPU_GET(curpcb);
	set_pcb_flags(pcb, PCB_FULL_IRET);
#endif

#ifndef	__FreeBSD__
	installctx(curthread, vcpu, save_guest_fpustate,
	    restore_guest_fpustate, NULL, NULL, NULL, NULL);
#endif
	restore_guest_fpustate(vcpu);

	vcpu_require_state(vm, vcpuid, VCPU_RUNNING);
	error = VMRUN(vm->cookie, vcpuid, vcpu->nextrip);
	vcpu_require_state(vm, vcpuid, VCPU_FROZEN);

	save_guest_fpustate(vcpu);
#ifndef	__FreeBSD__
	removectx(curthread, vcpu, save_guest_fpustate,
	    restore_guest_fpustate, NULL, NULL, NULL, NULL);
#endif

	vmm_stat_incr(vm, vcpuid, VCPU_TOTAL_RUNTIME, rdtsc() - tscval);

	critical_exit();

	if (error == 0) {
		retu = false;
		vcpu->nextrip = vme->rip + vme->inst_length;
		switch (vme->exitcode) {
		case VM_EXITCODE_HLT:
			intr_disabled = ((vme->u.hlt.rflags & PSL_I) == 0);
			error = vm_handle_hlt(vm, vcpuid, intr_disabled, &retu);
			break;
		case VM_EXITCODE_INST_EMUL:
			error = vm_handle_inst_emul(vm, vcpuid, &retu);
			break;
		case VM_EXITCODE_INOUT:
		case VM_EXITCODE_INOUT_STR:
			error = vm_handle_inout(vm, vcpuid, vme, &retu);
			break;
		default:
			retu = true;	/* handled in userland */
			break;
		}
	}

	if (error == 0 && retu == false) {
		goto restart;
	}

	/* copy the exit information */
	bcopy(vme, &vmrun->vm_exit, sizeof(struct vm_exit));
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
	if (vcpuid < 0 || vcpuid >= VM_MAXCPU)
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
		VCPU_CTR1(vm, vcpuid, "restarting instruction at %#lx by "
		    "setting inst_length to zero", vcpu->exitinfo.rip);
	} else if (state == VCPU_FROZEN) {
		/*
		 * When a vcpu is "frozen" it is outside the critical section
		 * around VMRUN() and 'nextrip' points to the next instruction.
		 * Thus instruction restart is achieved by setting 'nextrip'
		 * to the vcpu's %rip.
		 */
		error = vm_get_register(vm, vcpuid, VM_REG_GUEST_RIP, &rip);
		KASSERT(!error, ("%s: error %d getting rip", __func__, error));
		VCPU_CTR2(vm, vcpuid, "restarting instruction by updating "
		    "nextrip from %#lx to %#lx", vcpu->nextrip, rip);
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
	int type, vector;

	if (vcpuid < 0 || vcpuid >= VM_MAXCPU)
		return (EINVAL);

	vcpu = &vm->vcpu[vcpuid];

	if (info & VM_INTINFO_VALID) {
		type = info & VM_INTINFO_TYPE;
		vector = info & 0xff;
		if (type == VM_INTINFO_NMI && vector != IDT_NMI)
			return (EINVAL);
		if (type == VM_INTINFO_HWEXCEPTION && vector >= 32)
			return (EINVAL);
		if (info & VM_INTINFO_RSVD)
			return (EINVAL);
	} else {
		info = 0;
	}
	VCPU_CTR2(vm, vcpuid, "%s: info1(%#lx)", __func__, info);
	vcpu->exitintinfo = info;
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
	int type, vector;

#ifdef	__FreeBSD__
	KASSERT(info & VM_INTINFO_VALID, ("intinfo must be valid: %#lx", info));
#else
	KASSERT(info & VM_INTINFO_VALID, ("intinfo must be valid: %lx", info));
#endif
	type = info & VM_INTINFO_TYPE;
	vector = info & 0xff;

	/* Table 6-4, "Interrupt and Exception Classes", Intel SDM, Vol 3 */
	switch (type) {
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

	switch (vector) {
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

static int
nested_fault(struct vm *vm, int vcpuid, uint64_t info1, uint64_t info2,
    uint64_t *retinfo)
{
	enum exc_class exc1, exc2;
	int type1, vector1;

#ifdef	__FreeBSD__
	KASSERT(info1 & VM_INTINFO_VALID, ("info1 %#lx is not valid", info1));
	KASSERT(info2 & VM_INTINFO_VALID, ("info2 %#lx is not valid", info2));
#else
	KASSERT(info1 & VM_INTINFO_VALID, ("info1 %lx is not valid", info1));
	KASSERT(info2 & VM_INTINFO_VALID, ("info2 %lx is not valid", info2));
#endif

	/*
	 * If an exception occurs while attempting to call the double-fault
	 * handler the processor enters shutdown mode (aka triple fault).
	 */
	type1 = info1 & VM_INTINFO_TYPE;
	vector1 = info1 & 0xff;
	if (type1 == VM_INTINFO_HWEXCEPTION && vector1 == IDT_DF) {
		VCPU_CTR2(vm, vcpuid, "triple fault: info1(%#lx), info2(%#lx)",
		    info1, info2);
#ifdef	__FreeBSD__
		vm_suspend(vm, VM_SUSPEND_TRIPLEFAULT);
#endif
		*retinfo = 0;
		return (0);
	}

	/*
	 * Table 6-5 "Conditions for Generating a Double Fault", Intel SDM, Vol3
	 */
	exc1 = exception_class(info1);
	exc2 = exception_class(info2);
	if ((exc1 == EXC_CONTRIBUTORY && exc2 == EXC_CONTRIBUTORY) ||
	    (exc1 == EXC_PAGEFAULT && exc2 != EXC_BENIGN)) {
		/* Convert nested fault into a double fault. */
		*retinfo = IDT_DF;
		*retinfo |= VM_INTINFO_VALID | VM_INTINFO_HWEXCEPTION;
		*retinfo |= VM_INTINFO_DEL_ERRCODE;
	} else {
		/* Handle exceptions serially */
		*retinfo = info2;
	}
	return (1);
}

static uint64_t
vcpu_exception_intinfo(struct vcpu *vcpu)
{
	uint64_t info = 0;

	if (vcpu->exception_pending) {
		info = vcpu->exception.vector & 0xff;
		info |= VM_INTINFO_VALID | VM_INTINFO_HWEXCEPTION;
		if (vcpu->exception.error_code_valid) {
			info |= VM_INTINFO_DEL_ERRCODE;
			info |= (uint64_t)vcpu->exception.error_code << 32;
		}
	}
	return (info);
}

int
vm_entry_intinfo(struct vm *vm, int vcpuid, uint64_t *retinfo)
{
	struct vcpu *vcpu;
	uint64_t info1, info2;
	int valid;

	KASSERT(vcpuid >= 0 && vcpuid < VM_MAXCPU, ("invalid vcpu %d", vcpuid));

	vcpu = &vm->vcpu[vcpuid];

	info1 = vcpu->exitintinfo;
	vcpu->exitintinfo = 0;

	info2 = 0;
	if (vcpu->exception_pending) {
		info2 = vcpu_exception_intinfo(vcpu);
		vcpu->exception_pending = 0;
		VCPU_CTR2(vm, vcpuid, "Exception %d delivered: %#lx",
		    vcpu->exception.vector, info2);
	}

	if ((info1 & VM_INTINFO_VALID) && (info2 & VM_INTINFO_VALID)) {
		valid = nested_fault(vm, vcpuid, info1, info2, retinfo);
	} else if (info1 & VM_INTINFO_VALID) {
		*retinfo = info1;
		valid = 1;
	} else if (info2 & VM_INTINFO_VALID) {
		*retinfo = info2;
		valid = 1;
	} else {
		valid = 0;
	}

	if (valid) {
		VCPU_CTR4(vm, vcpuid, "%s: info1(%#lx), info2(%#lx), "
		    "retinfo(%#lx)", __func__, info1, info2, *retinfo);
	}

	return (valid);
}

int
vm_inject_exception(struct vm *vm, int vcpuid, struct vm_exception *exception)
{
	struct vcpu *vcpu;

	if (vcpuid < 0 || vcpuid >= VM_MAXCPU)
		return (EINVAL);

	if (exception->vector < 0 || exception->vector >= 32)
		return (EINVAL);

	vcpu = &vm->vcpu[vcpuid];

	if (vcpu->exception_pending) {
		VCPU_CTR2(vm, vcpuid, "Unable to inject exception %d due to "
		    "pending exception %d", exception->vector,
		    vcpu->exception.vector);
		return (EBUSY);
	}

	vcpu->exception_pending = 1;
	vcpu->exception = *exception;
	VCPU_CTR1(vm, vcpuid, "Exception %d pending", exception->vector);
	return (0);
}

int
vm_exception_pending(struct vm *vm, int vcpuid, struct vm_exception *exception)
{
	struct vcpu *vcpu;
	int pending;

	KASSERT(vcpuid >= 0 && vcpuid < VM_MAXCPU, ("invalid vcpu %d", vcpuid));

	vcpu = &vm->vcpu[vcpuid];
	pending = vcpu->exception_pending;
	if (pending) {
		vcpu->exception_pending = 0;
		*exception = vcpu->exception;
		VCPU_CTR1(vm, vcpuid, "Exception %d delivered",
		    exception->vector);
	}
	return (pending);
}

void
vm_inject_fault(void *vmarg, int vcpuid, int vector, int errcode_valid,
    int errcode)
{
	struct vm_exception exception;
	struct vm_exit *vmexit;
	struct vm *vm;
	int error;

	vm = vmarg;

	exception.vector = vector;
	exception.error_code = errcode;
	exception.error_code_valid = errcode_valid;
	error = vm_inject_exception(vm, vcpuid, &exception);
	KASSERT(error == 0, ("vm_inject_exception error %d", error));

	/*
	 * A fault-like exception allows the instruction to be restarted
	 * after the exception handler returns.
	 *
	 * By setting the inst_length to 0 we ensure that the instruction
	 * pointer remains at the faulting instruction.
	 */
	vmexit = vm_exitinfo(vm, vcpuid);
	vmexit->inst_length = 0;
}

void
vm_inject_pf(void *vmarg, int vcpuid, int error_code, uint64_t cr2)
{
	struct vm *vm;
	int error;

	vm = vmarg;
	VCPU_CTR2(vm, vcpuid, "Injecting page fault: error_code %#x, cr2 %#lx",
	    error_code, cr2);

	error = vm_set_register(vm, vcpuid, VM_REG_GUEST_CR2, cr2);
	KASSERT(error == 0, ("vm_set_register(cr2) error %d", error));

	vm_inject_fault(vm, vcpuid, IDT_PF, 1, error_code);
}

static VMM_STAT(VCPU_NMI_COUNT, "number of NMIs delivered to vcpu");

int
vm_inject_nmi(struct vm *vm, int vcpuid)
{
	struct vcpu *vcpu;

	if (vcpuid < 0 || vcpuid >= VM_MAXCPU)
		return (EINVAL);

	vcpu = &vm->vcpu[vcpuid];

	vcpu->nmi_pending = 1;
	vcpu_notify_event(vm, vcpuid, false);

	return (0);
}

int
vm_nmi_pending(struct vm *vm, int vcpuid)
{
	struct vcpu *vcpu;

	if (vcpuid < 0 || vcpuid >= VM_MAXCPU)
		panic("vm_nmi_pending: invalid vcpuid %d", vcpuid);

	vcpu = &vm->vcpu[vcpuid];

	return (vcpu->nmi_pending);
}

void
vm_nmi_clear(struct vm *vm, int vcpuid)
{
	struct vcpu *vcpu;

	if (vcpuid < 0 || vcpuid >= VM_MAXCPU)
		panic("vm_nmi_pending: invalid vcpuid %d", vcpuid);

	vcpu = &vm->vcpu[vcpuid];

	if (vcpu->nmi_pending == 0)
		panic("vm_nmi_clear: inconsistent nmi_pending state");

	vcpu->nmi_pending = 0;
	vmm_stat_incr(vm, vcpuid, VCPU_NMI_COUNT, 1);
}

static VMM_STAT(VCPU_EXTINT_COUNT, "number of ExtINTs delivered to vcpu");

int
vm_inject_extint(struct vm *vm, int vcpuid)
{
	struct vcpu *vcpu;

	if (vcpuid < 0 || vcpuid >= VM_MAXCPU)
		return (EINVAL);

	vcpu = &vm->vcpu[vcpuid];

	vcpu->extint_pending = 1;
	vcpu_notify_event(vm, vcpuid, false);

	return (0);
}

int
vm_extint_pending(struct vm *vm, int vcpuid)
{
	struct vcpu *vcpu;

	if (vcpuid < 0 || vcpuid >= VM_MAXCPU)
		panic("vm_extint_pending: invalid vcpuid %d", vcpuid);

	vcpu = &vm->vcpu[vcpuid];

	return (vcpu->extint_pending);
}

void
vm_extint_clear(struct vm *vm, int vcpuid)
{
	struct vcpu *vcpu;

	if (vcpuid < 0 || vcpuid >= VM_MAXCPU)
		panic("vm_extint_pending: invalid vcpuid %d", vcpuid);

	vcpu = &vm->vcpu[vcpuid];

	if (vcpu->extint_pending == 0)
		panic("vm_extint_clear: inconsistent extint_pending state");

	vcpu->extint_pending = 0;
	vmm_stat_incr(vm, vcpuid, VCPU_EXTINT_COUNT, 1);
}

int
vm_get_capability(struct vm *vm, int vcpu, int type, int *retval)
{
	if (vcpu < 0 || vcpu >= VM_MAXCPU)
		return (EINVAL);

	if (type < 0 || type >= VM_CAP_MAX)
		return (EINVAL);

	return (VMGETCAP(vm->cookie, vcpu, type, retval));
}

int
vm_set_capability(struct vm *vm, int vcpu, int type, int val)
{
	if (vcpu < 0 || vcpu >= VM_MAXCPU)
		return (EINVAL);

	if (type < 0 || type >= VM_CAP_MAX)
		return (EINVAL);

	return (VMSETCAP(vm->cookie, vcpu, type, val));
}

struct vhpet *
vm_hpet(struct vm *vm)
{
	return (vm->vhpet);
}

struct vioapic *
vm_ioapic(struct vm *vm)
{
	return (vm->vioapic);
}

struct vlapic *
vm_lapic(struct vm *vm, int cpu)
{
	return (vm->vcpu[cpu].vlapic);
}

#ifdef	__FreeBSD__
boolean_t
vmm_is_pptdev(int bus, int slot, int func)
{
	int found, i, n;
	int b, s, f;
	char *val, *cp, *cp2;

	/*
	 * XXX
	 * The length of an environment variable is limited to 128 bytes which
	 * puts an upper limit on the number of passthru devices that may be
	 * specified using a single environment variable.
	 *
	 * Work around this by scanning multiple environment variable
	 * names instead of a single one - yuck!
	 */
	const char *names[] = { "pptdevs", "pptdevs2", "pptdevs3", NULL };

	/* set pptdevs="1/2/3 4/5/6 7/8/9 10/11/12" */
	found = 0;
	for (i = 0; names[i] != NULL && !found; i++) {
		cp = val = getenv(names[i]);
		while (cp != NULL && *cp != '\0') {
			if ((cp2 = strchr(cp, ' ')) != NULL)
				*cp2 = '\0';

			n = sscanf(cp, "%d/%d/%d", &b, &s, &f);
			if (n == 3 && bus == b && slot == s && func == f) {
				found = 1;
				break;
			}
		
			if (cp2 != NULL)
				*cp2++ = ' ';

			cp = cp2;
		}
		freeenv(val);
	}
	return (found);
}
#endif

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

	if (vcpuid < 0 || vcpuid >= VM_MAXCPU)
		panic("vm_set_run_state: invalid vcpuid %d", vcpuid);

	vcpu = &vm->vcpu[vcpuid];

	vcpu_lock(vcpu);
	error = vcpu_set_state_locked(vcpu, newstate, from_idle);
	vcpu_unlock(vcpu);

	return (error);
}

enum vcpu_state
vcpu_get_state(struct vm *vm, int vcpuid, int *hostcpu)
{
	struct vcpu *vcpu;
	enum vcpu_state state;

	if (vcpuid < 0 || vcpuid >= VM_MAXCPU)
		panic("vm_get_run_state: invalid vcpuid %d", vcpuid);

	vcpu = &vm->vcpu[vcpuid];

	vcpu_lock(vcpu);
	state = vcpu->state;
	if (hostcpu != NULL)
		*hostcpu = vcpu->hostcpu;
	vcpu_unlock(vcpu);

	return (state);
}

int
vm_activate_cpu(struct vm *vm, int vcpuid)
{

	if (vcpuid < 0 || vcpuid >= VM_MAXCPU)
		return (EINVAL);

	if (CPU_ISSET(vcpuid, &vm->active_cpus))
		return (EBUSY);

	VCPU_CTR0(vm, vcpuid, "activated");
	CPU_SET_ATOMIC(vcpuid, &vm->active_cpus);
	return (0);
}

cpuset_t
vm_active_cpus(struct vm *vm)
{

	return (vm->active_cpus);
}

void *
vcpu_stats(struct vm *vm, int vcpuid)
{

	return (vm->vcpu[vcpuid].stats);
}

int
vm_get_x2apic_state(struct vm *vm, int vcpuid, enum x2apic_state *state)
{
	if (vcpuid < 0 || vcpuid >= VM_MAXCPU)
		return (EINVAL);

	*state = vm->vcpu[vcpuid].x2apic_state;

	return (0);
}

int
vm_set_x2apic_state(struct vm *vm, int vcpuid, enum x2apic_state state)
{
	if (vcpuid < 0 || vcpuid >= VM_MAXCPU)
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
void
vcpu_notify_event(struct vm *vm, int vcpuid, bool lapic_intr)
{
	int hostcpu;
	struct vcpu *vcpu;

	vcpu = &vm->vcpu[vcpuid];

	vcpu_lock(vcpu);
	hostcpu = vcpu->hostcpu;
	if (vcpu->state == VCPU_RUNNING) {
		KASSERT(hostcpu != NOCPU, ("vcpu running on invalid hostcpu"));
		if (hostcpu != curcpu) {
			if (lapic_intr) {
				vlapic_post_intr(vcpu->vlapic, hostcpu,
				    vmm_ipinum);
			} else {
				ipi_cpu(hostcpu, vmm_ipinum);
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
		if (vcpu->state == VCPU_SLEEPING)
			wakeup_one(vcpu);
	}
	vcpu_unlock(vcpu);
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
    int num_copyinfo)
{
#ifdef	__FreeBSD__
	int idx;

	for (idx = 0; idx < num_copyinfo; idx++) {
		if (copyinfo[idx].cookie != NULL)
			vm_gpa_release(copyinfo[idx].cookie);
	}
#endif
	bzero(copyinfo, num_copyinfo * sizeof(struct vm_copyinfo));
}

int
vm_copy_setup(struct vm *vm, int vcpuid, struct vm_guest_paging *paging,
    uint64_t gla, size_t len, int prot, struct vm_copyinfo *copyinfo,
    int num_copyinfo)
{
	int error, idx, nused;
	size_t n, off, remaining;
	void *hva, *cookie;
	uint64_t gpa;

	bzero(copyinfo, sizeof(struct vm_copyinfo) * num_copyinfo);

	nused = 0;
	remaining = len;
	while (remaining > 0) {
		KASSERT(nused < num_copyinfo, ("insufficient vm_copyinfo"));
		error = vm_gla2gpa(vm, vcpuid, paging, gla, prot, &gpa);
		if (error)
			return (error);
		off = gpa & PAGE_MASK;
		n = min(remaining, PAGE_SIZE - off);
		copyinfo[nused].gpa = gpa;
		copyinfo[nused].len = n;
		remaining -= n;
		gla += n;
		nused++;
	}

	for (idx = 0; idx < nused; idx++) {
		hva = vm_gpa_hold(vm, copyinfo[idx].gpa, copyinfo[idx].len,
		    prot, &cookie);
		if (hva == NULL)
			break;
		copyinfo[idx].hva = hva;
		copyinfo[idx].cookie = cookie;
	}

	if (idx != nused) {
		vm_copy_teardown(vm, vcpuid, copyinfo, num_copyinfo);
		return (-1);
	} else {
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
		bcopy(src, copyinfo[idx].hva, copyinfo[idx].len);
		len -= copyinfo[idx].len;
		src += copyinfo[idx].len;
		idx++;
	}
}
