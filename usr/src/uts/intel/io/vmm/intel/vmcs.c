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
 * Copyright 2014 Pluribus Networks Inc.
 * Copyright 2017 Joyent, Inc.
 * Copyright 2020 Oxide Computer Company
 */

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/systm.h>

#include <machine/specialreg.h>
#include <machine/vmm.h>
#include "vmx.h"

/* Bits 0-30 of VMX_BASIC MSR contain VMCS revision identifier */
#define	VMX_BASIC_REVISION(v)	((v) & 0x7fffffff)

uint32_t
vmcs_field_encoding(int ident)
{
	switch (ident) {
	case VM_REG_GUEST_CR0:
		return (VMCS_GUEST_CR0);
	case VM_REG_GUEST_CR3:
		return (VMCS_GUEST_CR3);
	case VM_REG_GUEST_CR4:
		return (VMCS_GUEST_CR4);
	case VM_REG_GUEST_DR7:
		return (VMCS_GUEST_DR7);
	case VM_REG_GUEST_RSP:
		return (VMCS_GUEST_RSP);
	case VM_REG_GUEST_RIP:
		return (VMCS_GUEST_RIP);
	case VM_REG_GUEST_RFLAGS:
		return (VMCS_GUEST_RFLAGS);
	case VM_REG_GUEST_ES:
		return (VMCS_GUEST_ES_SELECTOR);
	case VM_REG_GUEST_CS:
		return (VMCS_GUEST_CS_SELECTOR);
	case VM_REG_GUEST_SS:
		return (VMCS_GUEST_SS_SELECTOR);
	case VM_REG_GUEST_DS:
		return (VMCS_GUEST_DS_SELECTOR);
	case VM_REG_GUEST_FS:
		return (VMCS_GUEST_FS_SELECTOR);
	case VM_REG_GUEST_GS:
		return (VMCS_GUEST_GS_SELECTOR);
	case VM_REG_GUEST_TR:
		return (VMCS_GUEST_TR_SELECTOR);
	case VM_REG_GUEST_LDTR:
		return (VMCS_GUEST_LDTR_SELECTOR);
	case VM_REG_GUEST_EFER:
		return (VMCS_GUEST_IA32_EFER);
	case VM_REG_GUEST_PDPTE0:
		return (VMCS_GUEST_PDPTE0);
	case VM_REG_GUEST_PDPTE1:
		return (VMCS_GUEST_PDPTE1);
	case VM_REG_GUEST_PDPTE2:
		return (VMCS_GUEST_PDPTE2);
	case VM_REG_GUEST_PDPTE3:
		return (VMCS_GUEST_PDPTE3);
	case VM_REG_GUEST_ENTRY_INST_LENGTH:
		return (VMCS_ENTRY_INST_LENGTH);
	default:
		return (VMCS_INVALID_ENCODING);
	}
}

void
vmcs_seg_desc_encoding(int seg, uint32_t *base, uint32_t *lim, uint32_t *acc)
{
	switch (seg) {
	case VM_REG_GUEST_ES:
		*base = VMCS_GUEST_ES_BASE;
		*lim = VMCS_GUEST_ES_LIMIT;
		*acc = VMCS_GUEST_ES_ACCESS_RIGHTS;
		break;
	case VM_REG_GUEST_CS:
		*base = VMCS_GUEST_CS_BASE;
		*lim = VMCS_GUEST_CS_LIMIT;
		*acc = VMCS_GUEST_CS_ACCESS_RIGHTS;
		break;
	case VM_REG_GUEST_SS:
		*base = VMCS_GUEST_SS_BASE;
		*lim = VMCS_GUEST_SS_LIMIT;
		*acc = VMCS_GUEST_SS_ACCESS_RIGHTS;
		break;
	case VM_REG_GUEST_DS:
		*base = VMCS_GUEST_DS_BASE;
		*lim = VMCS_GUEST_DS_LIMIT;
		*acc = VMCS_GUEST_DS_ACCESS_RIGHTS;
		break;
	case VM_REG_GUEST_FS:
		*base = VMCS_GUEST_FS_BASE;
		*lim = VMCS_GUEST_FS_LIMIT;
		*acc = VMCS_GUEST_FS_ACCESS_RIGHTS;
		break;
	case VM_REG_GUEST_GS:
		*base = VMCS_GUEST_GS_BASE;
		*lim = VMCS_GUEST_GS_LIMIT;
		*acc = VMCS_GUEST_GS_ACCESS_RIGHTS;
		break;
	case VM_REG_GUEST_TR:
		*base = VMCS_GUEST_TR_BASE;
		*lim = VMCS_GUEST_TR_LIMIT;
		*acc = VMCS_GUEST_TR_ACCESS_RIGHTS;
		break;
	case VM_REG_GUEST_LDTR:
		*base = VMCS_GUEST_LDTR_BASE;
		*lim = VMCS_GUEST_LDTR_LIMIT;
		*acc = VMCS_GUEST_LDTR_ACCESS_RIGHTS;
		break;
	case VM_REG_GUEST_IDTR:
		*base = VMCS_GUEST_IDTR_BASE;
		*lim = VMCS_GUEST_IDTR_LIMIT;
		*acc = VMCS_INVALID_ENCODING;
		break;
	case VM_REG_GUEST_GDTR:
		*base = VMCS_GUEST_GDTR_BASE;
		*lim = VMCS_GUEST_GDTR_LIMIT;
		*acc = VMCS_INVALID_ENCODING;
		break;
	default:
		panic("invalid segment register %d", seg);
	}
}

uint32_t
vmcs_msr_encoding(uint32_t msr)
{
	switch (msr) {
	case MSR_PAT:
		return (VMCS_GUEST_IA32_PAT);
	case MSR_EFER:
		return (VMCS_GUEST_IA32_EFER);
	case MSR_SYSENTER_CS_MSR:
		return (VMCS_GUEST_IA32_SYSENTER_CS);
	case MSR_SYSENTER_ESP_MSR:
		return (VMCS_GUEST_IA32_SYSENTER_ESP);
	case MSR_SYSENTER_EIP_MSR:
		return (VMCS_GUEST_IA32_SYSENTER_EIP);
	/*
	 * While fsbase and gsbase are expected to be accessed (by the VMM) via
	 * the segment descriptor interfaces, we still make it available as MSR
	 * contents as well.
	 */
	case MSR_FSBASE:
		return (VMCS_GUEST_FS_BASE);
	case MSR_GSBASE:
		return (VMCS_GUEST_GS_BASE);
	default:
		return (VMCS_INVALID_ENCODING);
	}
}

void
vmcs_clear(uintptr_t vmcs_pa)
{
	int err;

	__asm __volatile("vmclear %[addr];"
	    VMX_SET_ERROR_CODE_ASM
	    : [error] "=r" (err)
	    : [addr] "m" (vmcs_pa)
	    : "memory");

	if (err != 0) {
		panic("vmclear(%p) error %d", (void *)vmcs_pa, err);
	}

	/*
	 * A call to critical_enter() was made in vmcs_load() to prevent
	 * preemption.  Now that the VMCS is unloaded, it is safe to relax that
	 * restriction.
	 */
	critical_exit();
}

void
vmcs_initialize(struct vmcs *vmcs, uintptr_t vmcs_pa)
{
	int err;

	/* set to VMCS revision */
	vmcs->identifier = VMX_BASIC_REVISION(rdmsr(MSR_VMX_BASIC));

	/*
	 * Perform a vmclear on the VMCS, but without the critical section
	 * manipulation as done by vmcs_clear() above.
	 */
	__asm __volatile("vmclear %[addr];"
	    VMX_SET_ERROR_CODE_ASM
	    : [error] "=r" (err)
	    : [addr] "m" (vmcs_pa)
	    : "memory");

	if (err != 0) {
		panic("vmclear(%p) error %d", (void *)vmcs_pa, err);
	}
}

void
vmcs_load(uintptr_t vmcs_pa)
{
	int err;

	/*
	 * While the VMCS is loaded on the CPU for subsequent operations, it is
	 * important that the thread not be preempted.  That is ensured with
	 * critical_enter() here, with a matching critical_exit() call in
	 * vmcs_clear() once the VMCS is unloaded.
	 */
	critical_enter();

	__asm __volatile("vmptrld %[addr];"
	    VMX_SET_ERROR_CODE_ASM
	    : [error] "=r" (err)
	    : [addr] "m" (vmcs_pa)
	    : "memory");

	if (err != 0) {
		panic("vmptrld(%p) error %d", (void *)vmcs_pa, err);
	}
}

uint64_t
vmcs_read(uint32_t encoding)
{
	int error;
	uint64_t val;

	__asm __volatile("vmread %[enc], %[val];"
	    VMX_SET_ERROR_CODE_ASM
	    : [error] "=r" (error), [val] "=r" (val)
	    : [enc] "r" ((uint64_t)encoding)
	    : "memory");

	if (error != 0) {
		panic("vmread(%x) error %d", encoding, error);
	}

	return (val);
}

void
vmcs_write(uint32_t encoding, uint64_t val)
{
	int error;

	__asm __volatile("vmwrite %[val], %[enc];"
	    VMX_SET_ERROR_CODE_ASM
	    : [error] "=r" (error)
	    : [val] "r" (val), [enc] "r" ((uint64_t)encoding)
	    : "memory");

	if (error != 0) {
		panic("vmwrite(%x, %lx) error %d", encoding, val, error);
	}
}
