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
 * Copyright 2019 Joyent, Inc.
 * Copyright 2020 Oxide Computer Company
 */

#ifndef _VMM_KERNEL_H_
#define	_VMM_KERNEL_H_

#include <sys/sdt.h>
#include <x86/segments.h>

SDT_PROVIDER_DECLARE(vmm);

struct vm;
struct vm_exception;
struct seg_desc;
struct vm_exit;
struct vm_run;
struct vhpet;
struct vioapic;
struct vlapic;
struct vmspace;
struct vm_object;
struct vm_guest_paging;
struct pmap;

struct vm_eventinfo {
	u_int	*rptr;		/* runblock cookie */
	int	*sptr;		/* suspend cookie */
	int	*iptr;		/* reqidle cookie */
};

typedef int	(*vmm_init_func_t)(int ipinum);
typedef int	(*vmm_cleanup_func_t)(void);
typedef void	(*vmm_resume_func_t)(void);
typedef void *	(*vmi_init_func_t)(struct vm *vm, struct pmap *pmap);
typedef int	(*vmi_run_func_t)(void *vmi, int vcpu, register_t rip,
		    struct pmap *pmap, struct vm_eventinfo *info);
typedef void	(*vmi_cleanup_func_t)(void *vmi);
typedef int	(*vmi_get_register_t)(void *vmi, int vcpu, int num,
				      uint64_t *retval);
typedef int	(*vmi_set_register_t)(void *vmi, int vcpu, int num,
				      uint64_t val);
typedef int	(*vmi_get_desc_t)(void *vmi, int vcpu, int num,
				  struct seg_desc *desc);
typedef int	(*vmi_set_desc_t)(void *vmi, int vcpu, int num,
				  struct seg_desc *desc);
typedef int	(*vmi_get_cap_t)(void *vmi, int vcpu, int num, int *retval);
typedef int	(*vmi_set_cap_t)(void *vmi, int vcpu, int num, int val);
typedef struct vmspace * (*vmi_vmspace_alloc)(vm_offset_t min, vm_offset_t max);
typedef void	(*vmi_vmspace_free)(struct vmspace *vmspace);
typedef struct vlapic * (*vmi_vlapic_init)(void *vmi, int vcpu);
typedef void	(*vmi_vlapic_cleanup)(void *vmi, struct vlapic *vlapic);
#ifndef __FreeBSD__
typedef void	(*vmi_savectx)(void *vmi, int vcpu);
typedef void	(*vmi_restorectx)(void *vmi, int vcpu);
#endif

struct vmm_ops {
	vmm_init_func_t		init;		/* module wide initialization */
	vmm_cleanup_func_t	cleanup;
	vmm_resume_func_t	resume;

	vmi_init_func_t		vminit;		/* vm-specific initialization */
	vmi_run_func_t		vmrun;
	vmi_cleanup_func_t	vmcleanup;
	vmi_get_register_t	vmgetreg;
	vmi_set_register_t	vmsetreg;
	vmi_get_desc_t		vmgetdesc;
	vmi_set_desc_t		vmsetdesc;
	vmi_get_cap_t		vmgetcap;
	vmi_set_cap_t		vmsetcap;
	vmi_vmspace_alloc	vmspace_alloc;
	vmi_vmspace_free	vmspace_free;
	vmi_vlapic_init		vlapic_init;
	vmi_vlapic_cleanup	vlapic_cleanup;

#ifndef __FreeBSD__
	vmi_savectx		vmsavectx;
	vmi_restorectx		vmrestorectx;
#endif
};

extern struct vmm_ops vmm_ops_intel;
extern struct vmm_ops vmm_ops_amd;

int vm_create(const char *name, struct vm **retvm);
void vm_destroy(struct vm *vm);
int vm_reinit(struct vm *vm);
const char *vm_name(struct vm *vm);
uint16_t vm_get_maxcpus(struct vm *vm);
void vm_get_topology(struct vm *vm, uint16_t *sockets, uint16_t *cores,
    uint16_t *threads, uint16_t *maxcpus);
int vm_set_topology(struct vm *vm, uint16_t sockets, uint16_t cores,
    uint16_t threads, uint16_t maxcpus);

/*
 * APIs that modify the guest memory map require all vcpus to be frozen.
 */
int vm_mmap_memseg(struct vm *vm, vm_paddr_t gpa, int segid, vm_ooffset_t off,
    size_t len, int prot, int flags);
int vm_alloc_memseg(struct vm *vm, int ident, size_t len, bool sysmem);
void vm_free_memseg(struct vm *vm, int ident);
int vm_map_mmio(struct vm *vm, vm_paddr_t gpa, size_t len, vm_paddr_t hpa);
int vm_unmap_mmio(struct vm *vm, vm_paddr_t gpa, size_t len);
#ifdef __FreeBSD__
int vm_assign_pptdev(struct vm *vm, int bus, int slot, int func);
int vm_unassign_pptdev(struct vm *vm, int bus, int slot, int func);
#else
int vm_assign_pptdev(struct vm *vm, int pptfd);
int vm_unassign_pptdev(struct vm *vm, int pptfd);
#endif /* __FreeBSD__ */

/*
 * APIs that inspect the guest memory map require only a *single* vcpu to
 * be frozen. This acts like a read lock on the guest memory map since any
 * modification requires *all* vcpus to be frozen.
 */
int vm_mmap_getnext(struct vm *vm, vm_paddr_t *gpa, int *segid,
    vm_ooffset_t *segoff, size_t *len, int *prot, int *flags);
int vm_get_memseg(struct vm *vm, int ident, size_t *len, bool *sysmem,
    struct vm_object **objptr);
vm_paddr_t vmm_sysmem_maxaddr(struct vm *vm);
void *vm_gpa_hold(struct vm *, int vcpuid, vm_paddr_t gpa, size_t len,
    int prot, void **cookie);
void vm_gpa_release(void *cookie);
bool vm_mem_allocated(struct vm *vm, int vcpuid, vm_paddr_t gpa);

int vm_get_register(struct vm *vm, int vcpu, int reg, uint64_t *retval);
int vm_set_register(struct vm *vm, int vcpu, int reg, uint64_t val);
int vm_get_seg_desc(struct vm *vm, int vcpu, int reg,
		    struct seg_desc *ret_desc);
int vm_set_seg_desc(struct vm *vm, int vcpu, int reg,
		    struct seg_desc *desc);
int vm_run(struct vm *vm, struct vm_run *vmrun);
int vm_suspend(struct vm *vm, enum vm_suspend_how how);
int vm_inject_nmi(struct vm *vm, int vcpu);
int vm_nmi_pending(struct vm *vm, int vcpuid);
void vm_nmi_clear(struct vm *vm, int vcpuid);
int vm_inject_extint(struct vm *vm, int vcpu);
int vm_extint_pending(struct vm *vm, int vcpuid);
void vm_extint_clear(struct vm *vm, int vcpuid);
struct vlapic *vm_lapic(struct vm *vm, int cpu);
struct vioapic *vm_ioapic(struct vm *vm);
struct vhpet *vm_hpet(struct vm *vm);
int vm_get_capability(struct vm *vm, int vcpu, int type, int *val);
int vm_set_capability(struct vm *vm, int vcpu, int type, int val);
int vm_get_x2apic_state(struct vm *vm, int vcpu, enum x2apic_state *state);
int vm_set_x2apic_state(struct vm *vm, int vcpu, enum x2apic_state state);
int vm_apicid2vcpuid(struct vm *vm, int apicid);
int vm_activate_cpu(struct vm *vm, int vcpu);
int vm_suspend_cpu(struct vm *vm, int vcpu);
int vm_resume_cpu(struct vm *vm, int vcpu);
struct vm_exit *vm_exitinfo(struct vm *vm, int vcpuid);
void vm_exit_suspended(struct vm *vm, int vcpuid, uint64_t rip);
void vm_exit_debug(struct vm *vm, int vcpuid, uint64_t rip);
void vm_exit_runblock(struct vm *vm, int vcpuid, uint64_t rip);
void vm_exit_astpending(struct vm *vm, int vcpuid, uint64_t rip);
void vm_exit_reqidle(struct vm *vm, int vcpuid, uint64_t rip);

#ifdef _SYS__CPUSET_H_
cpuset_t vm_active_cpus(struct vm *vm);
cpuset_t vm_debug_cpus(struct vm *vm);
cpuset_t vm_suspended_cpus(struct vm *vm);
#endif	/* _SYS__CPUSET_H_ */

static __inline int
vcpu_runblocked(struct vm_eventinfo *info)
{

	return (*info->rptr != 0);
}

static __inline int
vcpu_suspended(struct vm_eventinfo *info)
{

	return (*info->sptr);
}

static __inline int
vcpu_reqidle(struct vm_eventinfo *info)
{

	return (*info->iptr);
}

int vcpu_debugged(struct vm *vm, int vcpuid);

/*
 * Return true if device indicated by bus/slot/func is supposed to be a
 * pci passthrough device.
 *
 * Return false otherwise.
 */
bool vmm_is_pptdev(int bus, int slot, int func);

void *vm_iommu_domain(struct vm *vm);

enum vcpu_state {
	VCPU_IDLE,
	VCPU_FROZEN,
	VCPU_RUNNING,
	VCPU_SLEEPING,
};

int vcpu_set_state(struct vm *vm, int vcpu, enum vcpu_state state,
    bool from_idle);
enum vcpu_state vcpu_get_state(struct vm *vm, int vcpu, int *hostcpu);
void vcpu_block_run(struct vm *, int);
void vcpu_unblock_run(struct vm *, int);

#ifndef __FreeBSD__
uint64_t vcpu_tsc_offset(struct vm *vm, int vcpuid);
#endif

static __inline int
vcpu_is_running(struct vm *vm, int vcpu, int *hostcpu)
{
	return (vcpu_get_state(vm, vcpu, hostcpu) == VCPU_RUNNING);
}

#ifdef _SYS_THREAD_H
static __inline int
vcpu_should_yield(struct vm *vm, int vcpu)
{

	if (curthread->t_astflag)
		return (1);
	else if (CPU->cpu_runrun)
		return (1);
	else
		return (0);
}
#endif /* _SYS_THREAD_H */

void *vcpu_stats(struct vm *vm, int vcpu);
void vcpu_notify_event(struct vm *vm, int vcpuid, bool lapic_intr);
struct vmspace *vm_get_vmspace(struct vm *vm);
struct vatpic *vm_atpic(struct vm *vm);
struct vatpit *vm_atpit(struct vm *vm);
struct vpmtmr *vm_pmtmr(struct vm *vm);
struct vrtc *vm_rtc(struct vm *vm);

/*
 * Inject exception 'vector' into the guest vcpu. This function returns 0 on
 * success and non-zero on failure.
 *
 * Wrapper functions like 'vm_inject_gp()' should be preferred to calling
 * this function directly because they enforce the trap-like or fault-like
 * behavior of an exception.
 *
 * This function should only be called in the context of the thread that is
 * executing this vcpu.
 */
int vm_inject_exception(struct vm *vm, int vcpuid, int vector, int err_valid,
    uint32_t errcode, int restart_instruction);

/*
 * This function is called after a VM-exit that occurred during exception or
 * interrupt delivery through the IDT. The format of 'intinfo' is described
 * in Figure 15-1, "EXITINTINFO for All Intercepts", APM, Vol 2.
 *
 * If a VM-exit handler completes the event delivery successfully then it
 * should call vm_exit_intinfo() to extinguish the pending event. For e.g.,
 * if the task switch emulation is triggered via a task gate then it should
 * call this function with 'intinfo=0' to indicate that the external event
 * is not pending anymore.
 *
 * Return value is 0 on success and non-zero on failure.
 */
int vm_exit_intinfo(struct vm *vm, int vcpuid, uint64_t intinfo);

/*
 * This function is called before every VM-entry to retrieve a pending
 * event that should be injected into the guest. This function combines
 * nested events into a double or triple fault.
 *
 * Returns 0 if there are no events that need to be injected into the guest
 * and non-zero otherwise.
 */
int vm_entry_intinfo(struct vm *vm, int vcpuid, uint64_t *info);

int vm_get_intinfo(struct vm *vm, int vcpuid, uint64_t *info1, uint64_t *info2);

enum vm_reg_name vm_segment_name(int seg_encoding);

struct vm_copyinfo {
	uint64_t	gpa;
	size_t		len;
	void		*hva;
	void		*cookie;
};

/*
 * Set up 'copyinfo[]' to copy to/from guest linear address space starting
 * at 'gla' and 'len' bytes long. The 'prot' should be set to PROT_READ for
 * a copyin or PROT_WRITE for a copyout.
 *
 * retval	is_fault	Interpretation
 *   0		   0		Success
 *   0		   1		An exception was injected into the guest
 * EFAULT	  N/A		Unrecoverable error
 *
 * The 'copyinfo[]' can be passed to 'vm_copyin()' or 'vm_copyout()' only if
 * the return value is 0. The 'copyinfo[]' resources should be freed by calling
 * 'vm_copy_teardown()' after the copy is done.
 */
int vm_copy_setup(struct vm *vm, int vcpuid, struct vm_guest_paging *paging,
    uint64_t gla, size_t len, int prot, struct vm_copyinfo *copyinfo,
    int num_copyinfo, int *is_fault);
void vm_copy_teardown(struct vm *vm, int vcpuid, struct vm_copyinfo *copyinfo,
    int num_copyinfo);
void vm_copyin(struct vm *vm, int vcpuid, struct vm_copyinfo *copyinfo,
    void *kaddr, size_t len);
void vm_copyout(struct vm *vm, int vcpuid, const void *kaddr,
    struct vm_copyinfo *copyinfo, size_t len);

int vcpu_trace_exceptions(struct vm *vm, int vcpuid);

/* APIs to inject faults into the guest */
void vm_inject_fault(struct vm *vm, int vcpuid, int vector, int errcode_valid,
    int errcode);

void vm_inject_ud(struct vm *vm, int vcpuid);
void vm_inject_gp(struct vm *vm, int vcpuid);
void vm_inject_ac(struct vm *vm, int vcpuid, int errcode);
void vm_inject_ss(struct vm *vm, int vcpuid, int errcode);


#ifndef	__FreeBSD__

void vmm_sol_glue_init(void);
void vmm_sol_glue_cleanup(void);

int vmm_mod_load(void);
int vmm_mod_unload(void);

void vmm_call_trap(uint64_t);

/*
 * Because of tangled headers, these are mirrored by vmm_drv.h to present the
 * interface to driver consumers.
 */
typedef int (*vmm_rmem_cb_t)(void *, uintptr_t, uint_t, uint64_t *);
typedef int (*vmm_wmem_cb_t)(void *, uintptr_t, uint_t, uint64_t);

int vm_ioport_hook(struct vm *, uint_t, vmm_rmem_cb_t, vmm_wmem_cb_t, void *,
    void **);
void vm_ioport_unhook(struct vm *, void **);
int vm_ioport_handle_hook(struct vm *, int, bool, int, int, uint32_t *);

#endif /* __FreeBSD */

#endif /* _VMM_KERNEL_H_ */

