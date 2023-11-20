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
 * Copyright 2023 Oxide Computer Company
 */

#ifndef	_VMM_DEV_H_
#define	_VMM_DEV_H_

#include <machine/vmm.h>

#include <sys/param.h>
#include <sys/cpuset.h>
#include <sys/vmm_data.h>

struct vm_create_req {
	char		name[VM_MAX_NAMELEN];
	uint64_t	flags;
};


struct vm_destroy_req {
	char		name[VM_MAX_NAMELEN];
};

struct vm_memmap {
	vm_paddr_t	gpa;
	int		segid;		/* memory segment */
	vm_ooffset_t	segoff;		/* offset into memory segment */
	size_t		len;		/* mmap length */
	int		prot;		/* RWX */
	int		flags;
};
#define	VM_MEMMAP_F_WIRED	0x01
#define	VM_MEMMAP_F_IOMMU	0x02

struct vm_munmap {
	vm_paddr_t	gpa;
	size_t		len;
};

#define	VM_MEMSEG_NAME(m)	((m)->name[0] != '\0' ? (m)->name : NULL)
struct vm_memseg {
	int		segid;
	size_t		len;
	char		name[VM_MAX_SEG_NAMELEN];
};

struct vm_register {
	int		cpuid;
	int		regnum;		/* enum vm_reg_name */
	uint64_t	regval;
};

struct vm_seg_desc {			/* data or code segment */
	int		cpuid;
	int		regnum;		/* enum vm_reg_name */
	struct seg_desc desc;
};

struct vm_register_set {
	int		cpuid;
	unsigned int	count;
	const int	*regnums;	/* enum vm_reg_name */
	uint64_t	*regvals;
};

struct vm_exception {
	int		cpuid;
	int		vector;
	uint32_t	error_code;
	int		error_code_valid;
	int		restart_instruction;
};

struct vm_lapic_msi {
	uint64_t	msg;
	uint64_t	addr;
};

struct vm_lapic_irq {
	int		cpuid;
	int		vector;
};

struct vm_ioapic_irq {
	int		irq;
};

struct vm_isa_irq {
	int		atpic_irq;
	int		ioapic_irq;
};

struct vm_isa_irq_trigger {
	int		atpic_irq;
	enum vm_intr_trigger trigger;
};

struct vm_capability {
	int		cpuid;
	enum vm_cap_type captype;
	int		capval;
	int		allcpus;
};

struct vm_pptdev {
	int		pptfd;
};

struct vm_pptdev_mmio {
	int		pptfd;
	vm_paddr_t	gpa;
	vm_paddr_t	hpa;
	size_t		len;
};

struct vm_pptdev_msi {
	int		vcpu;
	int		pptfd;
	int		numvec;		/* 0 means disabled */
	uint64_t	msg;
	uint64_t	addr;
};

struct vm_pptdev_msix {
	int		vcpu;
	int		pptfd;
	int		idx;
	uint64_t	msg;
	uint32_t	vector_control;
	uint64_t	addr;
};

struct vm_pptdev_limits {
	int		pptfd;
	int		msi_limit;
	int		msix_limit;
};

struct vm_nmi {
	int		cpuid;
};

#define	MAX_VM_STATS	64

struct vm_stats {
	int		cpuid;				/* in */
	int		index;				/* in */
	int		num_entries;			/* out */
	struct timeval	tv;
	uint64_t	statbuf[MAX_VM_STATS];
};

struct vm_stat_desc {
	int		index;				/* in */
	char		desc[128];			/* out */
};

struct vm_x2apic {
	int			cpuid;
	enum x2apic_state	state;
};

struct vm_gpa_pte {
	uint64_t	gpa;				/* in */
	uint64_t	pte[4];				/* out */
	int		ptenum;
};

struct vm_hpet_cap {
	uint32_t	capabilities;	/* lower 32 bits of HPET capabilities */
};

struct vm_suspend {
	enum vm_suspend_how how;
	int source;
};

/*
 * Deprecated flags for vm_reinit`flags:
 *
 * Suspend (by force) VM as part of reinit.  Effectively a no-op since
 * suspension requirements during reinit have been lifted.
 *
 * #define VM_REINIT_F_FORCE_SUSPEND	(1 << 0)
 */

struct vm_reinit {
	uint64_t	flags;
};

struct vm_gla2gpa {
	int		vcpuid;		/* inputs */
	int		prot;		/* PROT_READ or PROT_WRITE */
	uint64_t	gla;
	struct vm_guest_paging paging;
	int		fault;		/* outputs */
	uint64_t	gpa;
};

struct vm_activate_cpu {
	int		vcpuid;
};

struct vm_cpuset {
	int		which;
	int		cpusetsize;
#ifndef _KERNEL
	cpuset_t	*cpus;
#else
	void		*cpus;
#endif
};
#define	VM_ACTIVE_CPUS		0
/*
 * Deprecated:
 * #define VM_SUSPENDED_CPUS	1
 */
#define	VM_DEBUG_CPUS		2

struct vm_intinfo {
	int		vcpuid;
	uint64_t	info1;
	uint64_t	info2;
};

struct vm_rtc_data {
	int		offset;
	uint8_t		value;
};

struct vm_devmem_offset {
	int		segid;
	off_t		offset;
};

struct vm_cpu_topology {
	uint16_t	sockets;
	uint16_t	cores;
	uint16_t	threads;
	uint16_t	maxcpus;
};

struct vm_readwrite_kernemu_device {
	int		vcpuid;
	unsigned	access_width : 3;
	unsigned	_unused : 29;
	uint64_t	gpa;
	uint64_t	value;
};
_Static_assert(sizeof(struct vm_readwrite_kernemu_device) == 24, "ABI");

enum vcpu_reset_kind {
	VRK_RESET = 0,
	/*
	 * The reset performed by an INIT IPI clears much of the CPU state, but
	 * some portions are left untouched, unlike VRK_RESET, which represents
	 * a "full" reset as if the system was freshly powered on.
	 */
	VRK_INIT = 1,
};

struct vm_vcpu_reset {
	int		vcpuid;
	uint32_t	kind;	/* contains: enum vcpu_reset_kind */
};

struct vm_run_state {
	int		vcpuid;
	uint32_t	state;	/* of enum cpu_init_status type */
	uint8_t		sipi_vector;	/* vector of SIPI, if any */
	uint8_t		_pad[3];
};

/* Transfer data for VM_GET_FPU and VM_SET_FPU */
struct vm_fpu_state {
	int		vcpuid;
	void		*buf;
	size_t		len;
};

struct vm_fpu_desc_entry {
	uint64_t	vfde_feature;
	uint32_t	vfde_size;
	uint32_t	vfde_off;
};

struct vm_fpu_desc {
	struct vm_fpu_desc_entry	*vfd_entry_data;
	size_t				vfd_req_size;
	uint32_t			vfd_num_entries;
};

struct vmm_resv_query {
	size_t	vrq_free_sz;
	size_t	vrq_alloc_sz;
	size_t	vrq_alloc_transient_sz;
	size_t	vrq_limit;
};

struct vmm_resv_target {
	/* Target size for VMM reservoir */
	size_t	vrt_target_sz;

	/*
	 * Change of reservoir size to meet target will be done in multiple
	 * steps of chunk size (or smaller)
	 */
	size_t	vrt_chunk_sz;

	/*
	 * Resultant size of reservoir after operation.  Should match target
	 * size, except when interrupted.
	 */
	size_t	vrt_result_sz;
};

/*
 * struct vmm_dirty_tracker is used for tracking dirty guest pages during
 * e.g. live migration.
 *
 * - The `vdt_start_gpa` field specifies the offset from the beginning of
 *   guest physical memory to track;
 * - `vdt_pfns` points to a bit vector indexed by guest PFN relative to the
 *   given start address.  Each bit indicates whether the given guest page
 *   is dirty or not.
 * - `vdt_pfns_len` specifies the length of the of the guest physical memory
 *   region in bytes.  It also de facto bounds the range of guest addresses
 *   we will examine on any one `VM_TRACK_DIRTY_PAGES` ioctl().  If the
 *   range of the bit vector spans an unallocated region (or extends beyond
 *   the end of the guest physical address space) the corresponding bits in
 *   `vdt_pfns` will be zeroed.
 */
struct vmm_dirty_tracker {
	uint64_t	vdt_start_gpa;
	size_t		vdt_len;	/* length of region */
	void		*vdt_pfns;	/* bit vector of dirty bits */
};

/* Current (arbitrary) max length for vm_data_xfer */
#define VM_DATA_XFER_LIMIT	8192

#define	VDX_FLAG_READ_COPYIN	(1 << 0)
#define	VDX_FLAG_WRITE_COPYOUT	(1 << 1)

#define	VDX_FLAGS_VALID		(VDX_FLAG_READ_COPYIN | VDX_FLAG_WRITE_COPYOUT)

struct vm_data_xfer {
	int		vdx_vcpuid;
	uint16_t	vdx_class;
	uint16_t	vdx_version;
	uint32_t	vdx_flags;
	uint32_t	vdx_len;
	uint32_t	vdx_result_len;
	void		*vdx_data;
};

struct vm_vcpu_cpuid_config {
	int		vvcc_vcpuid;
	uint32_t	vvcc_flags;
	uint32_t	vvcc_nent;
	uint32_t	_pad;
	void		*vvcc_entries;
};

/* Query the computed legacy cpuid value for a vcpuid with VM_LEGACY_CPUID */
struct vm_legacy_cpuid {
	int		vlc_vcpuid;
	uint32_t	vlc_eax;
	uint32_t	vlc_ebx;
	uint32_t	vlc_ecx;
	uint32_t	vlc_edx;
};

/*
 * VMM Interface Version
 *
 * Despite the fact that the kernel interface to bhyve is explicitly considered
 * Private, there are out-of-gate consumers which utilize it.  While they assume
 * the risk of any breakage incurred by changes to bhyve, we can at least try to
 * make it easier to detect changes by exposing a "version" of the interface.
 * It can also be used by the in-gate userland to detect if packaging updates
 * somehow result in the userland and kernel falling out of sync.
 *
 * There are no established criteria for the magnitude of change which requires
 * this version to be incremented, and maintenance of it is considered a
 * best-effort activity.  Nothing is to be inferred about the magnitude of a
 * change when the version is modified.  It follows no rules like semver.
 */
#define	VMM_CURRENT_INTERFACE_VERSION	16


#define	VMMCTL_IOC_BASE		(('V' << 16) | ('M' << 8))
#define	VMM_IOC_BASE		(('v' << 16) | ('m' << 8))
#define	VMM_LOCK_IOC_BASE	(('v' << 16) | ('l' << 8))
#define	VMM_CPU_IOC_BASE	(('v' << 16) | ('p' << 8))

/* Operations performed on the vmmctl device */
#define	VMM_CREATE_VM		(VMMCTL_IOC_BASE | 0x01)
#define	VMM_DESTROY_VM		(VMMCTL_IOC_BASE | 0x02)
#define	VMM_VM_SUPPORTED	(VMMCTL_IOC_BASE | 0x03)
#define	VMM_INTERFACE_VERSION	(VMMCTL_IOC_BASE | 0x04)
#define	VMM_CHECK_IOMMU		(VMMCTL_IOC_BASE | 0x05)

#define	VMM_RESV_QUERY		(VMMCTL_IOC_BASE | 0x10)
#define	VMM_RESV_SET_TARGET	(VMMCTL_IOC_BASE | 0x11)

/* Operations performed in the context of a given vCPU */
#define	VM_RUN				(VMM_CPU_IOC_BASE | 0x01)
#define	VM_SET_REGISTER			(VMM_CPU_IOC_BASE | 0x02)
#define	VM_GET_REGISTER			(VMM_CPU_IOC_BASE | 0x03)
#define	VM_SET_SEGMENT_DESCRIPTOR	(VMM_CPU_IOC_BASE | 0x04)
#define	VM_GET_SEGMENT_DESCRIPTOR	(VMM_CPU_IOC_BASE | 0x05)
#define	VM_SET_REGISTER_SET		(VMM_CPU_IOC_BASE | 0x06)
#define	VM_GET_REGISTER_SET		(VMM_CPU_IOC_BASE | 0x07)
#define	VM_INJECT_EXCEPTION		(VMM_CPU_IOC_BASE | 0x08)
#define	VM_SET_CAPABILITY		(VMM_CPU_IOC_BASE | 0x09)
#define	VM_GET_CAPABILITY		(VMM_CPU_IOC_BASE | 0x0a)
#define	VM_PPTDEV_MSI			(VMM_CPU_IOC_BASE | 0x0b)
#define	VM_PPTDEV_MSIX			(VMM_CPU_IOC_BASE | 0x0c)
#define	VM_SET_X2APIC_STATE		(VMM_CPU_IOC_BASE | 0x0d)
#define	VM_GLA2GPA			(VMM_CPU_IOC_BASE | 0x0e)
#define	VM_GLA2GPA_NOFAULT		(VMM_CPU_IOC_BASE | 0x0f)
#define	VM_ACTIVATE_CPU			(VMM_CPU_IOC_BASE | 0x10)
#define	VM_SET_INTINFO			(VMM_CPU_IOC_BASE | 0x11)
#define	VM_GET_INTINFO			(VMM_CPU_IOC_BASE | 0x12)
#define	VM_RESTART_INSTRUCTION		(VMM_CPU_IOC_BASE | 0x13)
#define	VM_SET_KERNEMU_DEV		(VMM_CPU_IOC_BASE | 0x14)
#define	VM_GET_KERNEMU_DEV		(VMM_CPU_IOC_BASE | 0x15)
#define	VM_RESET_CPU			(VMM_CPU_IOC_BASE | 0x16)
#define	VM_GET_RUN_STATE		(VMM_CPU_IOC_BASE | 0x17)
#define	VM_SET_RUN_STATE		(VMM_CPU_IOC_BASE | 0x18)
#define	VM_GET_FPU			(VMM_CPU_IOC_BASE | 0x19)
#define	VM_SET_FPU			(VMM_CPU_IOC_BASE | 0x1a)
#define	VM_GET_CPUID			(VMM_CPU_IOC_BASE | 0x1b)
#define	VM_SET_CPUID			(VMM_CPU_IOC_BASE | 0x1c)
#define	VM_LEGACY_CPUID			(VMM_CPU_IOC_BASE | 0x1d)

/* Operations requiring write-locking the VM */
#define	VM_REINIT		(VMM_LOCK_IOC_BASE | 0x01)
#define	VM_BIND_PPTDEV		(VMM_LOCK_IOC_BASE | 0x02)
#define	VM_UNBIND_PPTDEV	(VMM_LOCK_IOC_BASE | 0x03)
#define	VM_MAP_PPTDEV_MMIO	(VMM_LOCK_IOC_BASE | 0x04)
#define	VM_ALLOC_MEMSEG		(VMM_LOCK_IOC_BASE | 0x05)
#define	VM_MMAP_MEMSEG		(VMM_LOCK_IOC_BASE | 0x06)
#define	VM_PMTMR_LOCATE		(VMM_LOCK_IOC_BASE | 0x07)
#define	VM_MUNMAP_MEMSEG	(VMM_LOCK_IOC_BASE | 0x08)
#define	VM_UNMAP_PPTDEV_MMIO	(VMM_LOCK_IOC_BASE | 0x09)
#define	VM_PAUSE		(VMM_LOCK_IOC_BASE | 0x0a)
#define	VM_RESUME		(VMM_LOCK_IOC_BASE | 0x0b)

#define	VM_WRLOCK_CYCLE		(VMM_LOCK_IOC_BASE | 0xff)

/* All other ioctls */
#define	VM_GET_GPA_PMAP			(VMM_IOC_BASE | 0x01)
#define	VM_GET_MEMSEG			(VMM_IOC_BASE | 0x02)
#define	VM_MMAP_GETNEXT			(VMM_IOC_BASE | 0x03)

#define	VM_LAPIC_IRQ			(VMM_IOC_BASE | 0x04)
#define	VM_LAPIC_LOCAL_IRQ		(VMM_IOC_BASE | 0x05)
#define	VM_LAPIC_MSI			(VMM_IOC_BASE | 0x06)

#define	VM_IOAPIC_ASSERT_IRQ		(VMM_IOC_BASE | 0x07)
#define	VM_IOAPIC_DEASSERT_IRQ		(VMM_IOC_BASE | 0x08)
#define	VM_IOAPIC_PULSE_IRQ		(VMM_IOC_BASE | 0x09)

#define	VM_ISA_ASSERT_IRQ		(VMM_IOC_BASE | 0x0a)
#define	VM_ISA_DEASSERT_IRQ		(VMM_IOC_BASE | 0x0b)
#define	VM_ISA_PULSE_IRQ		(VMM_IOC_BASE | 0x0c)
#define	VM_ISA_SET_IRQ_TRIGGER		(VMM_IOC_BASE | 0x0d)

#define	VM_RTC_WRITE			(VMM_IOC_BASE | 0x0e)
#define	VM_RTC_READ			(VMM_IOC_BASE | 0x0f)
#define	VM_RTC_SETTIME			(VMM_IOC_BASE | 0x10)
#define	VM_RTC_GETTIME			(VMM_IOC_BASE | 0x11)

#define	VM_SUSPEND			(VMM_IOC_BASE | 0x12)

#define	VM_IOAPIC_PINCOUNT		(VMM_IOC_BASE | 0x13)
#define	VM_GET_PPTDEV_LIMITS		(VMM_IOC_BASE | 0x14)
#define	VM_GET_HPET_CAPABILITIES	(VMM_IOC_BASE | 0x15)

#define	VM_STATS_IOC			(VMM_IOC_BASE | 0x16)
#define	VM_STAT_DESC			(VMM_IOC_BASE | 0x17)

#define	VM_INJECT_NMI			(VMM_IOC_BASE | 0x18)
#define	VM_GET_X2APIC_STATE		(VMM_IOC_BASE | 0x19)
#define	VM_SET_TOPOLOGY			(VMM_IOC_BASE | 0x1a)
#define	VM_GET_TOPOLOGY			(VMM_IOC_BASE | 0x1b)
#define	VM_GET_CPUS			(VMM_IOC_BASE | 0x1c)
#define	VM_SUSPEND_CPU			(VMM_IOC_BASE | 0x1d)
#define	VM_RESUME_CPU			(VMM_IOC_BASE | 0x1e)

#define	VM_PPTDEV_DISABLE_MSIX		(VMM_IOC_BASE | 0x1f)

/* Note: forces a barrier on a flush operation before returning. */
#define	VM_TRACK_DIRTY_PAGES		(VMM_IOC_BASE | 0x20)
#define	VM_DESC_FPU_AREA		(VMM_IOC_BASE | 0x21)

#define	VM_DATA_READ			(VMM_IOC_BASE | 0x22)
#define	VM_DATA_WRITE			(VMM_IOC_BASE | 0x23)

#define	VM_SET_AUTODESTRUCT		(VMM_IOC_BASE | 0x24)
#define	VM_DESTROY_SELF			(VMM_IOC_BASE | 0x25)
#define	VM_DESTROY_PENDING		(VMM_IOC_BASE | 0x26)

#define	VM_VCPU_BARRIER			(VMM_IOC_BASE | 0x27)

#define	VM_DEVMEM_GETOFFSET		(VMM_IOC_BASE | 0xff)

#define	VMM_CTL_DEV		"/dev/vmmctl"

#endif
