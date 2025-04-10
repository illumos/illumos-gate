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
 */
/* This file is dual-licensed; see usr/src/contrib/bhyve/LICENSE */

/*
 * Copyright 2018 Joyent, Inc.
 * Copyright 2021 Oxide Computer Company
 */

#ifndef _VMX_H_
#define	_VMX_H_

#include "vmcs.h"

struct vmxctx {
	uint64_t	guest_rdi;		/* Guest state */
	uint64_t	guest_rsi;
	uint64_t	guest_rdx;
	uint64_t	guest_rcx;
	uint64_t	guest_r8;
	uint64_t	guest_r9;
	uint64_t	guest_rax;
	uint64_t	guest_rbx;
	uint64_t	guest_rbp;
	uint64_t	guest_r10;
	uint64_t	guest_r11;
	uint64_t	guest_r12;
	uint64_t	guest_r13;
	uint64_t	guest_r14;
	uint64_t	guest_r15;
	uint64_t	guest_cr2;
	uint64_t	guest_dr0;
	uint64_t	guest_dr1;
	uint64_t	guest_dr2;
	uint64_t	guest_dr3;
	uint64_t	guest_dr6;

	uint64_t	host_dr0;
	uint64_t	host_dr1;
	uint64_t	host_dr2;
	uint64_t	host_dr3;
	uint64_t	host_dr6;
	uint64_t	host_dr7;
	uint64_t	host_debugctl;
	int		host_tf;

	int		inst_fail_status;
};

struct vmxcap {
	int	set;
	uint32_t proc_ctls;
	uint32_t proc_ctls2;
	uint32_t exc_bitmap;
};

struct vmxstate {
	uint64_t nextrip;	/* next instruction to be executed by guest */
	int	lastcpu;	/* host cpu that this 'vcpu' last ran on */
	uint16_t vpid;
};

struct apic_page {
	uint32_t reg[PAGE_SIZE / 4];
};
CTASSERT(sizeof (struct apic_page) == PAGE_SIZE);

/* Posted Interrupt Descriptor (described in section 29.6 of the Intel SDM) */
struct pir_desc {
	uint32_t	pir[8];
	uint64_t	pending;
	uint64_t	unused[3];
} __aligned(64);
CTASSERT(sizeof (struct pir_desc) == 64);

/* Index into the 'guest_msrs[]' array */
enum {
	IDX_MSR_LSTAR,
	IDX_MSR_CSTAR,
	IDX_MSR_STAR,
	IDX_MSR_SF_MASK,
	IDX_MSR_KGSBASE,
	IDX_MSR_PAT,
	GUEST_MSR_NUM		/* must be the last enumeration */
};

typedef enum {
	VS_NONE		= 0x0,
	VS_LAUNCHED	= 0x1,
	VS_LOADED	= 0x2
} vmcs_state_t;

/* virtual machine softc */
struct vmx {
	struct vmcs	vmcs[VM_MAXCPU];	/* one vmcs per virtual cpu */
	struct apic_page apic_page[VM_MAXCPU];	/* one apic page per vcpu */
	uint8_t		*msr_bitmap[VM_MAXCPU];	/* one MSR bitmap per vCPU */
	struct pir_desc	pir_desc[VM_MAXCPU];
	uint64_t	guest_msrs[VM_MAXCPU][GUEST_MSR_NUM];
	uint64_t	host_msrs[VM_MAXCPU][GUEST_MSR_NUM];
	uint64_t	tsc_offset_active[VM_MAXCPU];
	vmcs_state_t	vmcs_state[VM_MAXCPU];
	uintptr_t	vmcs_pa[VM_MAXCPU];
	void		*apic_access_page;
	struct vmxctx	ctx[VM_MAXCPU];
	struct vmxcap	cap[VM_MAXCPU];
	struct vmxstate	state[VM_MAXCPU];
	uint64_t	eptp;
	enum vmx_caps	vmx_caps;
	struct vm	*vm;
	/*
	 * Track the latest vmspace generation as it is run on a given host CPU.
	 * This allows us to react to modifications to the vmspace (such as
	 * unmap or changed protection) which necessitate flushing any
	 * guest-physical TLB entries tagged for this guest via 'invept'.
	 */
	uint64_t	eptgen[MAXCPU];
};
CTASSERT((offsetof(struct vmx, vmcs) & PAGE_MASK) == 0);
CTASSERT((offsetof(struct vmx, msr_bitmap) & PAGE_MASK) == 0);
CTASSERT((offsetof(struct vmx, pir_desc[0]) & 63) == 0);

static __inline bool
vmx_cap_en(const struct vmx *vmx, enum vmx_caps cap)
{
	return ((vmx->vmx_caps & cap) == cap);
}


/*
 * Section 5.2 "Conventions" from Intel Architecture Manual 2B.
 *
 *			error
 * VMsucceed		  0
 * VMFailInvalid	  1
 * VMFailValid		  2	see also VMCS VM-Instruction Error Field
 */
#define	VM_SUCCESS		0
#define	VM_FAIL_INVALID		1
#define	VM_FAIL_VALID		2
#define	VMX_SET_ERROR_CODE_ASM \
	"	jnc 1f;"						\
	"	mov $1, %[error];"	/* CF: error = 1 */		\
	"	jmp 3f;"						\
	"1:	jnz 2f;"						\
	"	mov $2, %[error];"	/* ZF: error = 2 */		\
	"	jmp 3f;"						\
	"2:	mov $0, %[error];"					\
	"3:"


#define	VMX_GUEST_VMEXIT	0
#define	VMX_VMRESUME_ERROR	1
#define	VMX_VMLAUNCH_ERROR	2
#define	VMX_INVEPT_ERROR	3
#define	VMX_VMWRITE_ERROR	4

int	vmx_enter_guest(struct vmxctx *ctx, struct vmx *vmx, int launched);
void	vmx_call_isr(uintptr_t entry);

int	vmx_set_tsc_offset(struct vmx *vmx, int vcpu, uint64_t offset);

extern char	vmx_exit_guest[];
extern char	vmx_exit_guest_flush_rsb[];

#endif
