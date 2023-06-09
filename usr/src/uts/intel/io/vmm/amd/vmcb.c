/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2013 Anish Gupta (akgupt3@gmail.com)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
 * Copyright 2020 Oxide Computer Company
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/x86_archext.h>

#include <machine/specialreg.h>
#include <machine/vmm.h>

#include "vmcb.h"
#include "svm.h"

struct vmcb_segment *
vmcb_segptr(struct vmcb *vmcb, int type)
{
	struct vmcb_state *state = &vmcb->state;

	switch (type) {
	case VM_REG_GUEST_CS:
		return (&state->cs);
	case VM_REG_GUEST_DS:
		return (&state->ds);
	case VM_REG_GUEST_ES:
		return (&state->es);
	case VM_REG_GUEST_FS:
		return (&state->fs);
	case VM_REG_GUEST_GS:
		return (&state->gs);
	case VM_REG_GUEST_SS:
		return (&state->ss);
	case VM_REG_GUEST_GDTR:
		return (&state->gdt);
	case VM_REG_GUEST_IDTR:
		return (&state->idt);
	case VM_REG_GUEST_LDTR:
		return (&state->ldt);
	case VM_REG_GUEST_TR:
		return (&state->tr);
	default:
		panic("unexpected seg %d", type);
	}
}

uint64_t *
vmcb_regptr(struct vmcb *vmcb, int ident, uint32_t *dirtyp)
{
	struct vmcb_state *state;
	uint64_t *res = NULL;
	uint32_t dirty = VMCB_CACHE_NONE;

	state = &vmcb->state;

	switch (ident) {
	case VM_REG_GUEST_CR2:
		res = &state->cr2;
		dirty = VMCB_CACHE_CR2;
		break;

	case VM_REG_GUEST_CR3:
		res = &state->cr3;
		dirty = VMCB_CACHE_CR;
		break;

	case VM_REG_GUEST_CR4:
		res = &state->cr4;
		dirty = VMCB_CACHE_CR;
		break;

	case VM_REG_GUEST_DR6:
		res = &state->dr6;
		dirty = VMCB_CACHE_DR;
		break;

	case VM_REG_GUEST_DR7:
		res = &state->dr7;
		dirty = VMCB_CACHE_DR;
		break;

	case VM_REG_GUEST_EFER:
		res = &state->efer;
		dirty = VMCB_CACHE_CR;
		break;

	case VM_REG_GUEST_RAX:
		res = &state->rax;
		break;

	case VM_REG_GUEST_RFLAGS:
		res = &state->rflags;
		break;

	case VM_REG_GUEST_RIP:
		res = &state->rip;
		break;

	case VM_REG_GUEST_RSP:
		res = &state->rsp;
		break;

	default:
		panic("unexpected register %d", ident);
		break;
	}

	ASSERT(res != NULL);
	if (dirtyp != NULL) {
		*dirtyp |= dirty;
	}
	return (res);
}

uint64_t *
vmcb_msr_ptr(struct vmcb *vmcb, uint32_t msr, uint32_t *dirtyp)
{
	uint64_t *res = NULL;
	uint32_t dirty = 0;
	struct vmcb_state *state = &vmcb->state;

	switch (msr) {
	case MSR_EFER:
		res = &state->efer;
		dirty = VMCB_CACHE_CR;
		break;

	case MSR_GSBASE:
		res = &state->gs.base;
		dirty = VMCB_CACHE_SEG;
		break;
	case MSR_FSBASE:
		res = &state->fs.base;
		dirty = VMCB_CACHE_SEG;
		break;
	case MSR_KGSBASE:
		res = &state->kernelgsbase;
		break;

	case MSR_STAR:
		res = &state->star;
		break;
	case MSR_LSTAR:
		res = &state->lstar;
		break;
	case MSR_CSTAR:
		res = &state->cstar;
		break;
	case MSR_SF_MASK:
		res = &state->sfmask;
		break;

	case MSR_SYSENTER_CS_MSR:
		res = &state->sysenter_cs;
		break;
	case MSR_SYSENTER_ESP_MSR:
		res = &state->sysenter_esp;
		break;
	case MSR_SYSENTER_EIP_MSR:
		res = &state->sysenter_eip;
		break;

	case MSR_PAT:
		res = &state->g_pat;
		dirty = VMCB_CACHE_NP;
		break;

	case MSR_DEBUGCTL:
		res = &state->dbgctl;
		dirty = VMCB_CACHE_LBR;
		break;
	case MSR_LBR_FROM:
		res = &state->br_from;
		dirty = VMCB_CACHE_LBR;
		break;
	case MSR_LBR_TO:
		res = &state->br_to;
		dirty = VMCB_CACHE_LBR;
		break;
	case MSR_LEX_FROM:
		res = &state->int_from;
		dirty = VMCB_CACHE_LBR;
		break;
	case MSR_LEX_TO:
		res = &state->int_to;
		dirty = VMCB_CACHE_LBR;
		break;
	}

	if (res != NULL && dirtyp != NULL) {
		*dirtyp = dirty;
	}
	return (res);
}
