/*-
 * SPDX-License-Identifier: BSD-2-Clause
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
 * Copyright 2024 Oxide Computer Company
 * Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
 */

#ifndef _VMM_KERNEL_H_
#define	_VMM_KERNEL_H_

#include <sys/sdt.h>
#include <x86/segments.h>
#include <sys/vmm.h>
#include <sys/vmm_data.h>
#include <sys/linker_set.h>

SDT_PROVIDER_DECLARE(vmm);

struct vm;
struct vm_exception;
struct seg_desc;
struct vm_exit;
struct vie;
struct vm_run;
struct vhpet;
struct vioapic;
struct vlapic;
struct vmspace;
struct vm_client;
struct vm_object;
struct vm_guest_paging;
struct vmm_data_req;

/* Return values for architecture-specific calculation of the TSC multiplier */
typedef enum {
	FR_VALID,			/* valid multiplier, scaling needed */
	FR_SCALING_NOT_NEEDED,		/* scaling not required */
	FR_SCALING_NOT_SUPPORTED,	/* scaling not supported by platform */
	FR_OUT_OF_RANGE,		/* freq ratio out of supported range */
} freqratio_res_t;

typedef int	(*vmm_init_func_t)(void);
typedef int	(*vmm_cleanup_func_t)(void);
typedef void	(*vmm_resume_func_t)(void);
typedef void *	(*vmi_init_func_t)(struct vm *vm);
typedef int	(*vmi_run_func_t)(void *vmi, int vcpu, uint64_t rip);
typedef void	(*vmi_cleanup_func_t)(void *vmi);
typedef int	(*vmi_get_register_t)(void *vmi, int vcpu, int num,
    uint64_t *retval);
typedef int	(*vmi_set_register_t)(void *vmi, int vcpu, int num,
    uint64_t val);
typedef int	(*vmi_get_desc_t)(void *vmi, int vcpu, int num,
    struct seg_desc *desc);
typedef int	(*vmi_set_desc_t)(void *vmi, int vcpu, int num,
    const struct seg_desc *desc);
typedef int	(*vmi_get_cap_t)(void *vmi, int vcpu, int num, int *retval);
typedef int	(*vmi_set_cap_t)(void *vmi, int vcpu, int num, int val);
typedef struct vlapic *(*vmi_vlapic_init)(void *vmi, int vcpu);
typedef void	(*vmi_vlapic_cleanup)(void *vmi, struct vlapic *vlapic);
typedef void	(*vmi_savectx)(void *vmi, int vcpu);
typedef void	(*vmi_restorectx)(void *vmi, int vcpu);
typedef void	(*vmi_pause_t)(void *vmi, int vcpu);

typedef int	(*vmi_get_msr_t)(void *vmi, int vcpu, uint32_t msr,
    uint64_t *valp);
typedef int	(*vmi_set_msr_t)(void *vmi, int vcpu, uint32_t msr,
    uint64_t val);
typedef freqratio_res_t	(*vmi_freqratio_t)(uint64_t guest_hz,
    uint64_t host_hz, uint64_t *mult);

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
	vmi_vlapic_init		vlapic_init;
	vmi_vlapic_cleanup	vlapic_cleanup;
	vmi_pause_t		vmpause;

	vmi_savectx		vmsavectx;
	vmi_restorectx		vmrestorectx;

	vmi_get_msr_t		vmgetmsr;
	vmi_set_msr_t		vmsetmsr;

	vmi_freqratio_t		vmfreqratio;
	uint32_t		fr_intsize;
	uint32_t		fr_fracsize;
};

extern struct vmm_ops vmm_ops_intel;
extern struct vmm_ops vmm_ops_amd;

int vm_create(uint64_t flags, struct vm **retvm);
void vm_destroy(struct vm *vm);
int vm_reinit(struct vm *vm, uint64_t);
uint16_t vm_get_maxcpus(struct vm *vm);
void vm_get_topology(struct vm *vm, uint16_t *sockets, uint16_t *cores,
    uint16_t *threads, uint16_t *maxcpus);
int vm_set_topology(struct vm *vm, uint16_t sockets, uint16_t cores,
    uint16_t threads, uint16_t maxcpus);

int vm_pause_instance(struct vm *);
int vm_resume_instance(struct vm *);
bool vm_is_paused(struct vm *);

/*
 * APIs that race against hardware.
 */
int vm_track_dirty_pages(struct vm *, uint64_t, size_t, uint8_t *);
int vm_npt_do_operation(struct vm *, uint64_t, size_t, uint32_t, uint8_t *,
    int *);

/*
 * APIs that modify the guest memory map require all vcpus to be frozen.
 */
int vm_mmap_memseg(struct vm *vm, vm_paddr_t gpa, int segid, vm_ooffset_t off,
    size_t len, int prot, int flags);
int vm_munmap_memseg(struct vm *vm, vm_paddr_t gpa, size_t len);
int vm_alloc_memseg(struct vm *vm, int ident, size_t len, bool sysmem);
void vm_free_memseg(struct vm *vm, int ident);
int vm_map_mmio(struct vm *vm, vm_paddr_t gpa, size_t len, vm_paddr_t hpa);
int vm_unmap_mmio(struct vm *vm, vm_paddr_t gpa, size_t len);
int vm_assign_pptdev(struct vm *vm, int pptfd);
int vm_unassign_pptdev(struct vm *vm, int pptfd);

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
bool vm_mem_allocated(struct vm *vm, int vcpuid, vm_paddr_t gpa);

int vm_get_register(struct vm *vm, int vcpu, int reg, uint64_t *retval);
int vm_set_register(struct vm *vm, int vcpu, int reg, uint64_t val);
int vm_get_seg_desc(struct vm *vm, int vcpu, int reg,
    struct seg_desc *ret_desc);
int vm_set_seg_desc(struct vm *vm, int vcpu, int reg,
    const struct seg_desc *desc);
int vm_get_run_state(struct vm *vm, int vcpuid, uint32_t *state,
    uint8_t *sipi_vec);
int vm_set_run_state(struct vm *vm, int vcpuid, uint32_t state,
    uint8_t sipi_vec);
int vm_get_fpu(struct vm *vm, int vcpuid, void *buf, size_t len);
int vm_set_fpu(struct vm *vm, int vcpuid, void *buf, size_t len);
int vm_run(struct vm *vm, int vcpuid, const struct vm_entry *);
int vm_suspend(struct vm *, enum vm_suspend_how, int);
int vm_inject_nmi(struct vm *vm, int vcpu);
bool vm_nmi_pending(struct vm *vm, int vcpuid);
void vm_nmi_clear(struct vm *vm, int vcpuid);
int vm_inject_extint(struct vm *vm, int vcpu);
bool vm_extint_pending(struct vm *vm, int vcpuid);
void vm_extint_clear(struct vm *vm, int vcpuid);
int vm_inject_init(struct vm *vm, int vcpuid);
int vm_inject_sipi(struct vm *vm, int vcpuid, uint8_t vec);
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
struct vie *vm_vie_ctx(struct vm *vm, int vcpuid);
void vm_exit_suspended(struct vm *vm, int vcpuid, uint64_t rip);
void vm_exit_debug(struct vm *vm, int vcpuid, uint64_t rip);
void vm_exit_astpending(struct vm *vm, int vcpuid, uint64_t rip);
void vm_exit_reqidle(struct vm *vm, int vcpuid, uint64_t rip);
void vm_exit_run_state(struct vm *vm, int vcpuid, uint64_t rip);
int vm_service_mmio_read(struct vm *vm, int cpuid, uint64_t gpa, uint64_t *rval,
    int rsize);
int vm_service_mmio_write(struct vm *vm, int cpuid, uint64_t gpa, uint64_t wval,
    int wsize);

#ifdef _SYS__CPUSET_H_
cpuset_t vm_active_cpus(struct vm *vm);
cpuset_t vm_debug_cpus(struct vm *vm);
#endif	/* _SYS__CPUSET_H_ */

bool vcpu_entry_bailout_checks(struct vm *vm, int vcpuid, uint64_t rip);
bool vcpu_run_state_pending(struct vm *vm, int vcpuid);
int vcpu_arch_reset(struct vm *vm, int vcpuid, bool init_only);
int vm_vcpu_barrier(struct vm *, int);

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

uint64_t vcpu_tsc_offset(struct vm *vm, int vcpuid, bool phys_adj);
hrtime_t vm_normalize_hrtime(struct vm *, hrtime_t);
hrtime_t vm_denormalize_hrtime(struct vm *, hrtime_t);
uint64_t vm_get_freq_multiplier(struct vm *);

static __inline bool
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

typedef enum vcpu_notify {
	VCPU_NOTIFY_NONE,
	VCPU_NOTIFY_APIC,	/* Posted intr notification (if possible) */
	VCPU_NOTIFY_EXIT,	/* IPI to cause VM exit */
} vcpu_notify_t;

void *vcpu_stats(struct vm *vm, int vcpu);
void vcpu_notify_event(struct vm *vm, int vcpuid);
void vcpu_notify_event_type(struct vm *vm, int vcpuid, vcpu_notify_t);
struct vmspace *vm_get_vmspace(struct vm *vm);
struct vm_client *vm_get_vmclient(struct vm *vm, int vcpuid);
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
int vm_inject_exception(struct vm *vm, int vcpuid, uint8_t vector,
    bool err_valid, uint32_t errcode, bool restart_instruction);

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
 * Returns false if there are no events that need to be injected into the guest.
 */
bool vm_entry_intinfo(struct vm *vm, int vcpuid, uint64_t *info);

int vm_get_intinfo(struct vm *vm, int vcpuid, uint64_t *info1, uint64_t *info2);

enum vm_reg_name vm_segment_name(int seg_encoding);

struct vm_copyinfo {
	uint64_t	gpa;
	size_t		len;
	int		prot;
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
    uint_t num_copyinfo, int *is_fault);
void vm_copy_teardown(struct vm *vm, int vcpuid, struct vm_copyinfo *copyinfo,
    uint_t num_copyinfo);
void vm_copyin(struct vm *vm, int vcpuid, struct vm_copyinfo *copyinfo,
    void *kaddr, size_t len);
void vm_copyout(struct vm *vm, int vcpuid, const void *kaddr,
    struct vm_copyinfo *copyinfo, size_t len);

int vcpu_trace_exceptions(struct vm *vm, int vcpuid);
int vcpu_trap_wbinvd(struct vm *vm, int vcpuid);

void vm_inject_ud(struct vm *vm, int vcpuid);
void vm_inject_gp(struct vm *vm, int vcpuid);
void vm_inject_ac(struct vm *vm, int vcpuid, uint32_t errcode);
void vm_inject_ss(struct vm *vm, int vcpuid, uint32_t errcode);
void vm_inject_pf(struct vm *vm, int vcpuid, uint32_t errcode, uint64_t cr2);

/*
 * Both SVM and VMX have complex logic for injecting events such as exceptions
 * or interrupts into the guest.  Within those two backends, the progress of
 * event injection is tracked by event_inject_state, hopefully making it easier
 * to reason about.
 */
enum event_inject_state {
	EIS_CAN_INJECT	= 0, /* exception/interrupt can be injected */
	EIS_EV_EXISTING	= 1, /* blocked by existing event */
	EIS_EV_INJECTED	= 2, /* blocked by injected event */
	EIS_GI_BLOCK	= 3, /* blocked by guest interruptability */

	/*
	 * Flag to request an immediate exit from VM context after event
	 * injection in order to perform more processing
	 */
	EIS_REQ_EXIT	= (1 << 15),
};

/* Possible result codes for MSR access emulation */
typedef enum vm_msr_result {
	VMR_OK		= 0, /* succesfully emulated */
	VMR_GP		= 1, /* #GP should be injected */
	VMR_UNHANLDED	= 2, /* handle in userspace, kernel cannot emulate */
} vm_msr_result_t;

enum vm_cpuid_capability {
	VCC_NONE,
	VCC_NO_EXECUTE,
	VCC_FFXSR,
	VCC_TCE,
	VCC_LAST
};

/* Possible flags and entry count limit definited in sys/vmm.h */
typedef struct vcpu_cpuid_config {
	uint32_t		vcc_flags;
	uint32_t		vcc_nent;
	struct vcpu_cpuid_entry	*vcc_entries;
} vcpu_cpuid_config_t;

vcpu_cpuid_config_t *vm_cpuid_config(struct vm *, int);
int vm_get_cpuid(struct vm *, int, vcpu_cpuid_config_t *);
int vm_set_cpuid(struct vm *, int, const vcpu_cpuid_config_t *);
void vcpu_emulate_cpuid(struct vm *, int, uint64_t *, uint64_t *, uint64_t *,
    uint64_t *);
void legacy_emulate_cpuid(struct vm *, int, uint32_t *, uint32_t *, uint32_t *,
    uint32_t *);
void vcpu_cpuid_init(vcpu_cpuid_config_t *);
void vcpu_cpuid_cleanup(vcpu_cpuid_config_t *);

bool vm_cpuid_capability(struct vm *, int, enum vm_cpuid_capability);
bool validate_guest_xcr0(uint64_t, uint64_t);

void vmm_sol_glue_init(void);
void vmm_sol_glue_cleanup(void);

void *vmm_contig_alloc(size_t);
void vmm_contig_free(void *, size_t);

int vmm_mod_load(void);
int vmm_mod_unload(void);

bool vmm_check_iommu(void);

void vmm_call_trap(uint64_t);

uint64_t vmm_host_tsc_delta(void);

/*
 * Because of tangled headers, this is not exposed directly via the vmm_drv
 * interface, but rather mirrored as vmm_drv_iop_cb_t in vmm_drv.h.
 */
typedef int (*ioport_handler_t)(void *, bool, uint16_t, uint8_t, uint32_t *);

int vm_ioport_access(struct vm *vm, int vcpuid, bool in, uint16_t port,
    uint8_t bytes, uint32_t *val);

int vm_ioport_attach(struct vm *vm, uint16_t port, ioport_handler_t func,
    void *arg, void **cookie);
int vm_ioport_detach(struct vm *vm, void **cookie, ioport_handler_t *old_func,
    void **old_arg);

int vm_ioport_hook(struct vm *, uint16_t, ioport_handler_t, void *, void **);
void vm_ioport_unhook(struct vm *, void **);

enum vcpu_ustate {
	VU_INIT = 0,	/* initialized but has not yet attempted to run */
	VU_RUN,		/* running in guest context */
	VU_IDLE,	/* idle (HLTed, wait-for-SIPI, etc) */
	VU_EMU_KERN,	/* emulation performed in-kernel */
	VU_EMU_USER,	/* emulation performed in userspace */
	VU_SCHED,	/* off-cpu for interrupt, preempt, lock contention */
	VU_MAX
};

void vcpu_ustate_change(struct vm *, int, enum vcpu_ustate);

typedef struct vmm_kstats {
	kstat_named_t	vk_name;
} vmm_kstats_t;

typedef struct vmm_vcpu_kstats {
	kstat_named_t	vvk_vcpu;
	kstat_named_t	vvk_time_init;
	kstat_named_t	vvk_time_run;
	kstat_named_t	vvk_time_idle;
	kstat_named_t	vvk_time_emu_kern;
	kstat_named_t	vvk_time_emu_user;
	kstat_named_t	vvk_time_sched;
} vmm_vcpu_kstats_t;

#define	VMM_KSTAT_CLASS	"misc"

int vmm_kstat_update_vcpu(struct kstat *, int);

typedef struct vmm_data_req {
	uint16_t	vdr_class;
	uint16_t	vdr_version;
	uint32_t	vdr_flags;
	uint32_t	vdr_len;
	void		*vdr_data;
	uint32_t	*vdr_result_len;
	int		vdr_vcpuid;
} vmm_data_req_t;

typedef int (*vmm_data_writef_t)(void *, const vmm_data_req_t *);
typedef int (*vmm_data_readf_t)(void *, const vmm_data_req_t *);
typedef int (*vmm_data_vcpu_writef_t)(struct vm *, int, const vmm_data_req_t *);
typedef int (*vmm_data_vcpu_readf_t)(struct vm *, int, const vmm_data_req_t *);

typedef struct vmm_data_version_entry {
	uint16_t		vdve_class;
	uint16_t		vdve_version;

	/*
	 * If these handlers accept/emit a single item of a fixed length, it
	 * should be specified in vdve_len_expect.  The vmm-data logic will then
	 * ensure that requests possess at least that specified length before
	 * calling into the defined handlers.
	 */
	uint16_t		vdve_len_expect;

	/*
	 * For handlers which deal with (potentially) multiple items of a fixed
	 * length, vdve_len_per_item is used to hint (via the VDC_VERSION class)
	 * to userspace what that item size is.  Although not strictly mutually
	 * exclusive with vdve_len_expect, it is nonsensical to set them both.
	 */
	uint16_t		vdve_len_per_item;

	/*
	 * A vmm-data handler is expected to provide read/write functions which
	 * are either VM-wide (via vdve_readf and vdve_writef) or per-vCPU
	 * (via vdve_vcpu_readf and vdve_vcpu_writef).  Providing both is not
	 * allowed (but is not currently checked at compile time).
	 */

	/* VM-wide handlers */
	vmm_data_readf_t	vdve_readf;
	vmm_data_writef_t	vdve_writef;

	/* Per-vCPU handlers */
	vmm_data_vcpu_readf_t	vdve_vcpu_readf;
	vmm_data_vcpu_writef_t	vdve_vcpu_writef;

	/*
	 * The vdve_vcpu_readf/writef handlers can rely on vcpuid to be within
	 * the [0, VM_MAXCPU) bounds.  If they also can handle vcpuid == -1 (for
	 * VM-wide data), then they can opt into such cases by setting
	 * vdve_vcpu_wildcard to true.
	 *
	 * At a later time, it would make sense to improve the logic so a
	 * vmm-data class could define both the VM-wide and per-vCPU handlers,
	 * letting the incoming vcpuid determine which would be called.  Until
	 * then, vdve_vcpu_wildcard is the stopgap.
	 */
	bool			vdve_vcpu_wildcard;
} vmm_data_version_entry_t;

#define	VMM_DATA_VERSION(sym)	SET_ENTRY(vmm_data_version_entries, sym)

int vmm_data_read(struct vm *, const vmm_data_req_t *);
int vmm_data_write(struct vm *, const vmm_data_req_t *);

/*
 * TSC Scaling
 */
uint64_t vmm_calc_freq_multiplier(uint64_t guest_hz, uint64_t host_hz,
    uint32_t frac);

/* represents a multiplier for a guest in which no scaling is required */
#define	VM_TSCM_NOSCALE	0

#endif /* _VMM_KERNEL_H_ */
