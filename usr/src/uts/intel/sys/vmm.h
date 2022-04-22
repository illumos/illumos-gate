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
 * Copyright 2021 Oxide Computer Company
 */

#ifndef _VMM_H_
#define	_VMM_H_

enum vm_suspend_how {
	VM_SUSPEND_NONE,
	VM_SUSPEND_RESET,
	VM_SUSPEND_POWEROFF,
	VM_SUSPEND_HALT,
	VM_SUSPEND_TRIPLEFAULT,
	VM_SUSPEND_LAST
};

/*
 * Identifiers for architecturally defined registers.
 */
enum vm_reg_name {
	VM_REG_GUEST_RAX,
	VM_REG_GUEST_RBX,
	VM_REG_GUEST_RCX,
	VM_REG_GUEST_RDX,
	VM_REG_GUEST_RSI,
	VM_REG_GUEST_RDI,
	VM_REG_GUEST_RBP,
	VM_REG_GUEST_R8,
	VM_REG_GUEST_R9,
	VM_REG_GUEST_R10,
	VM_REG_GUEST_R11,
	VM_REG_GUEST_R12,
	VM_REG_GUEST_R13,
	VM_REG_GUEST_R14,
	VM_REG_GUEST_R15,
	VM_REG_GUEST_CR0,
	VM_REG_GUEST_CR3,
	VM_REG_GUEST_CR4,
	VM_REG_GUEST_DR7,
	VM_REG_GUEST_RSP,
	VM_REG_GUEST_RIP,
	VM_REG_GUEST_RFLAGS,
	VM_REG_GUEST_ES,
	VM_REG_GUEST_CS,
	VM_REG_GUEST_SS,
	VM_REG_GUEST_DS,
	VM_REG_GUEST_FS,
	VM_REG_GUEST_GS,
	VM_REG_GUEST_LDTR,
	VM_REG_GUEST_TR,
	VM_REG_GUEST_IDTR,
	VM_REG_GUEST_GDTR,
	VM_REG_GUEST_EFER,
	VM_REG_GUEST_CR2,
	VM_REG_GUEST_PDPTE0,
	VM_REG_GUEST_PDPTE1,
	VM_REG_GUEST_PDPTE2,
	VM_REG_GUEST_PDPTE3,
	VM_REG_GUEST_INTR_SHADOW,
	VM_REG_GUEST_DR0,
	VM_REG_GUEST_DR1,
	VM_REG_GUEST_DR2,
	VM_REG_GUEST_DR3,
	VM_REG_GUEST_DR6,
	VM_REG_GUEST_ENTRY_INST_LENGTH,
	VM_REG_LAST
};

enum x2apic_state {
	X2APIC_DISABLED,
	X2APIC_ENABLED,
	X2APIC_STATE_LAST
};

#define	VM_INTINFO_VECTOR(info)	((info) & 0xff)
#define	VM_INTINFO_DEL_ERRCODE	0x800
#define	VM_INTINFO_RSVD		0x7ffff000
#define	VM_INTINFO_VALID	0x80000000
#define	VM_INTINFO_TYPE		0x700
#define	VM_INTINFO_HWINTR	(0 << 8)
#define	VM_INTINFO_NMI		(2 << 8)
#define	VM_INTINFO_HWEXCEPTION	(3 << 8)
#define	VM_INTINFO_SWINTR	(4 << 8)

/*
 * illumos doesn't have a limitation based on SPECNAMELEN like FreeBSD does.
 * To simplify structure definitions, an arbitrary limit has been chosen.
 * This same limit is used for memory segment names
 */

#define	VM_MAX_NAMELEN		128
#define	VM_MAX_SEG_NAMELEN	128

#define	VM_MAXCPU	32			/* maximum virtual cpus */

/*
 * Identifiers for optional vmm capabilities
 */
enum vm_cap_type {
	VM_CAP_HALT_EXIT,
	VM_CAP_MTRAP_EXIT,
	VM_CAP_PAUSE_EXIT,
	VM_CAP_ENABLE_INVPCID,
	VM_CAP_BPT_EXIT,
	VM_CAP_MAX
};

enum vmx_caps {
	VMX_CAP_NONE		= 0,
	VMX_CAP_TPR_SHADOW	= (1UL << 0),
	VMX_CAP_APICV		= (1UL << 1),
	VMX_CAP_APICV_X2APIC	= (1UL << 2),
	VMX_CAP_APICV_PIR	= (1UL << 3),
};

enum vm_intr_trigger {
	EDGE_TRIGGER,
	LEVEL_TRIGGER
};

/*
 * The 'access' field has the format specified in Table 21-2 of the Intel
 * Architecture Manual vol 3b.
 *
 * XXX The contents of the 'access' field are architecturally defined except
 * bit 16 - Segment Unusable.
 */
struct seg_desc {
	uint64_t	base;
	uint32_t	limit;
	uint32_t	access;
};
#define	SEG_DESC_TYPE(access)		((access) & 0x001f)
#define	SEG_DESC_DPL(access)		(((access) >> 5) & 0x3)
#define	SEG_DESC_PRESENT(access)	(((access) & 0x0080) ? 1 : 0)
#define	SEG_DESC_DEF32(access)		(((access) & 0x4000) ? 1 : 0)
#define	SEG_DESC_GRANULARITY(access)	(((access) & 0x8000) ? 1 : 0)
#define	SEG_DESC_UNUSABLE(access)	(((access) & 0x10000) ? 1 : 0)

enum vm_cpu_mode {
	CPU_MODE_REAL,
	CPU_MODE_PROTECTED,
	CPU_MODE_COMPATIBILITY,		/* IA-32E mode (CS.L = 0) */
	CPU_MODE_64BIT,			/* IA-32E mode (CS.L = 1) */
};

enum vm_paging_mode {
	PAGING_MODE_FLAT,
	PAGING_MODE_32,
	PAGING_MODE_PAE,
	PAGING_MODE_64,
};

struct vm_guest_paging {
	uint64_t	cr3;
	int		cpl;
	enum vm_cpu_mode cpu_mode;
	enum vm_paging_mode paging_mode;
};

enum vm_exitcode {
	VM_EXITCODE_INOUT,
	VM_EXITCODE_VMX,
	VM_EXITCODE_BOGUS,
	VM_EXITCODE_RDMSR,
	VM_EXITCODE_WRMSR,
	VM_EXITCODE_HLT,
	VM_EXITCODE_MTRAP,
	VM_EXITCODE_PAUSE,
	VM_EXITCODE_PAGING,
	VM_EXITCODE_INST_EMUL,
	VM_EXITCODE_RUN_STATE,
	VM_EXITCODE_MMIO_EMUL,
	VM_EXITCODE_DEPRECATED,	/* formerly RUNBLOCK */
	VM_EXITCODE_IOAPIC_EOI,
	VM_EXITCODE_SUSPENDED,
	VM_EXITCODE_MMIO,
	VM_EXITCODE_TASK_SWITCH,
	VM_EXITCODE_MONITOR,
	VM_EXITCODE_MWAIT,
	VM_EXITCODE_SVM,
	VM_EXITCODE_REQIDLE,
	VM_EXITCODE_DEBUG,
	VM_EXITCODE_VMINSN,
	VM_EXITCODE_BPT,
	VM_EXITCODE_HT,
	VM_EXITCODE_MAX
};

enum inout_flags {
	INOUT_IN	= (1U << 0), /* direction: 'in' when set, else 'out' */

	/*
	 * The following flags are used only for in-kernel emulation logic and
	 * are not exposed to userspace.
	 */
	INOUT_STR	= (1U << 1), /* ins/outs operation */
	INOUT_REP	= (1U << 2), /* 'rep' prefix present on instruction */
};

struct vm_inout {
	uint32_t	eax;
	uint16_t	port;
	uint8_t		bytes;		/* 1 or 2 or 4 */
	uint8_t		flags;		/* see: inout_flags */

	/*
	 * The address size and segment are relevant to INS/OUTS operations.
	 * Userspace is not concerned with them since the in-kernel emulation
	 * handles those specific aspects.
	 */
	uint8_t		addrsize;
	uint8_t		segment;
};

struct vm_mmio {
	uint8_t		bytes;		/* 1/2/4/8 bytes */
	uint8_t		read;		/* read: 1, write: 0 */
	uint16_t	_pad[3];
	uint64_t	gpa;
	uint64_t	data;
};

enum task_switch_reason {
	TSR_CALL,
	TSR_IRET,
	TSR_JMP,
	TSR_IDT_GATE,	/* task gate in IDT */
};

struct vm_task_switch {
	uint16_t	tsssel;		/* new TSS selector */
	int		ext;		/* task switch due to external event */
	uint32_t	errcode;
	int		errcode_valid;	/* push 'errcode' on the new stack */
	enum task_switch_reason reason;
	struct vm_guest_paging paging;
};

enum vcpu_run_state {
	VRS_HALT		= 0,
	VRS_INIT		= (1 << 0),
	VRS_RUN			= (1 << 1),

	VRS_PEND_INIT		= (1 << 14),
	VRS_PEND_SIPI		= (1 << 15),
};
#define VRS_MASK_VALID(v)	\
	((v) & (VRS_INIT | VRS_RUN | VRS_PEND_SIPI | VRS_PEND_SIPI))
#define VRS_IS_VALID(v)		((v) == VRS_MASK_VALID(v))

struct vm_exit {
	enum vm_exitcode	exitcode;
	int			inst_length;	/* 0 means unknown */
	uint64_t		rip;
	union {
		struct vm_inout	inout;
		struct vm_mmio	mmio;
		struct {
			uint64_t	gpa;
			int		fault_type;
		} paging;
		/*
		 * Kernel-internal MMIO decoding and emulation.
		 * Userspace should not expect to see this, but rather a
		 * VM_EXITCODE_MMIO with the above 'mmio' context.
		 */
		struct {
			uint64_t	gpa;
			uint64_t	gla;
			uint64_t	cs_base;
			int		cs_d;		/* CS.D */
		} mmio_emul;
		struct {
			uint8_t		inst[15];
			uint8_t		num_valid;
		} inst_emul;
		/*
		 * VMX specific payload. Used when there is no "better"
		 * exitcode to represent the VM-exit.
		 */
		struct {
			int		status;		/* vmx inst status */
			/*
			 * 'exit_reason' and 'exit_qualification' are valid
			 * only if 'status' is zero.
			 */
			uint32_t	exit_reason;
			uint64_t	exit_qualification;
			/*
			 * 'inst_error' and 'inst_type' are valid
			 * only if 'status' is non-zero.
			 */
			int		inst_type;
			int		inst_error;
		} vmx;
		/*
		 * SVM specific payload.
		 */
		struct {
			uint64_t	exitcode;
			uint64_t	exitinfo1;
			uint64_t	exitinfo2;
		} svm;
		struct {
			int		inst_length;
		} bpt;
		struct {
			uint32_t	code;		/* ecx value */
			uint64_t	wval;
		} msr;
		struct {
			uint64_t	rflags;
		} hlt;
		struct {
			int		vector;
		} ioapic_eoi;
		struct {
			enum vm_suspend_how how;
		} suspended;
		struct vm_task_switch task_switch;
	} u;
};

enum vm_entry_cmds {
	VEC_DEFAULT = 0,
	VEC_DISCARD_INSTR,	/* discard inst emul state */
	VEC_FULFILL_MMIO,	/* entry includes result for mmio emul */
	VEC_FULFILL_INOUT,	/* entry includes result for inout emul */
};

struct vm_entry {
	int cpuid;
	uint_t cmd;		/* see: vm_entry_cmds */
	void *exit_data;
	union {
		struct vm_inout inout;
		struct vm_mmio mmio;
	} u;
};

int vm_restart_instruction(void *vm, int vcpuid);

enum vm_create_flags {
	/*
	 * Allocate guest memory segments from existing reservoir capacity,
	 * rather than attempting to create transient allocations.
	 */
	VCF_RESERVOIR_MEM = (1 << 0),
};

#endif	/* _VMM_H_ */
