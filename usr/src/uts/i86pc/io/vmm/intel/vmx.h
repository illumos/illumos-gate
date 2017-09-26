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
 * $FreeBSD: head/sys/amd64/vmm/intel/vmx.h 284174 2015-06-09 00:14:47Z tychon $
 */

#ifndef _VMX_H_
#define	_VMX_H_

#include "vmcs.h"

#ifndef	__FreeBSD__
#define	GUEST_MSR_MAX_ENTRIES	64		/* arbitrary */
#define	HOST_MSR_MAX_ENTRIES	64		/* arbitrary */
#endif

struct vmxctx {
	register_t	tmpstk[32];		/* vmx_return() stack */
	register_t	tmpstktop;

	register_t	guest_rdi;		/* Guest state */
	register_t	guest_rsi;
	register_t	guest_rdx;
	register_t	guest_rcx;
	register_t	guest_r8;
	register_t	guest_r9;
	register_t	guest_rax;
	register_t	guest_rbx;
	register_t	guest_rbp;
	register_t	guest_r10;
	register_t	guest_r11;
	register_t	guest_r12;
	register_t	guest_r13;
	register_t	guest_r14;
	register_t	guest_r15;
	register_t	guest_cr2;

	register_t	host_r15;		/* Host state */
	register_t	host_r14;
	register_t	host_r13;
	register_t	host_r12;
	register_t	host_rbp;
	register_t	host_rsp;
	register_t	host_rbx;
	register_t	host_rip;
	/*
	 * XXX todo debug registers and fpu state
	 */
	
	int		launched;		/* vmcs launch state */
	int		launch_error;
};

struct vmxcap {
	int	set;
	uint32_t proc_ctls;
	uint32_t proc_ctls2;
};

struct vmxstate {
	uint64_t nextrip;	/* next instruction to be executed by guest */
	int	lastcpu;	/* host cpu that this 'vcpu' last ran on */
	uint16_t vpid;
};

struct apic_page {
	uint32_t reg[PAGE_SIZE / 4];
};
CTASSERT(sizeof(struct apic_page) == PAGE_SIZE);

/* Posted Interrupt Descriptor (described in section 29.6 of the Intel SDM) */
struct pir_desc {
	uint64_t	pir[4];
	uint64_t	pending;
	uint64_t	unused[3];
} __aligned(64);
CTASSERT(sizeof(struct pir_desc) == 64);

/* Index into the 'guest_msrs[]' array */
enum {
	IDX_MSR_LSTAR,
	IDX_MSR_CSTAR,
	IDX_MSR_STAR,
	IDX_MSR_SF_MASK,
	IDX_MSR_KGSBASE,
	GUEST_MSR_NUM		/* must be the last enumeration */
};

/* virtual machine softc */
struct vmx {
	pml4_entry_t	pml4ept[NPML4EPG];
	struct vmcs	vmcs[VM_MAXCPU];	/* one vmcs per virtual cpu */
	struct apic_page apic_page[VM_MAXCPU];	/* one apic page per vcpu */
	char		msr_bitmap[PAGE_SIZE];
	struct pir_desc	pir_desc[VM_MAXCPU];
#ifdef	__FreeBSD__
	uint64_t	guest_msrs[VM_MAXCPU][GUEST_MSR_NUM];
#else
	struct msr_entry guest_msrs[VM_MAXCPU][GUEST_MSR_MAX_ENTRIES];
	struct msr_entry host_msrs[VM_MAXCPU][HOST_MSR_MAX_ENTRIES];
#endif
	struct vmxctx	ctx[VM_MAXCPU];
	struct vmxcap	cap[VM_MAXCPU];
	struct vmxstate	state[VM_MAXCPU];
	struct vm	*vm;
};
CTASSERT((offsetof(struct vmx, pml4ept) & PAGE_MASK) == 0);
CTASSERT((offsetof(struct vmx, vmcs) & PAGE_MASK) == 0);
CTASSERT((offsetof(struct vmx, msr_bitmap) & PAGE_MASK) == 0);

#define	VMX_RETURN_DIRECT	0
#define	VMX_RETURN_LONGJMP	1
#define	VMX_RETURN_VMRESUME	2
#define	VMX_RETURN_VMLAUNCH	3
#define	VMX_RETURN_AST		4
/*
 * vmx_setjmp() returns:
 * - 0 when it returns directly
 * - 1 when it returns from vmx_longjmp
 * - 2 when it returns from vmx_resume (which would only be in the error case)
 * - 3 when it returns from vmx_launch (which would only be in the error case)
 * - 4 when it returns from vmx_resume or vmx_launch because of AST pending
 */
int	vmx_setjmp(struct vmxctx *ctx);
void	vmx_longjmp(void);			/* returns via vmx_setjmp */
void	vmx_launch(struct vmxctx *ctx) __dead2;	/* may return via vmx_setjmp */
void	vmx_resume(struct vmxctx *ctx) __dead2;	/* may return via vmx_setjmp */

u_long	vmx_fix_cr0(u_long cr0);
u_long	vmx_fix_cr4(u_long cr4);

int	vmx_set_tsc_offset(struct vmx *vmx, int vcpu, uint64_t offset);

#endif
