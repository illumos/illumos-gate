/*-
 * Copyright (c) 2012 NetApp, Inc.
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
 * $FreeBSD: head/sys/amd64/vmm/vmm_host.c 242275 2012-10-29 01:51:24Z neel $
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
 * Copyright 2013 Pluribus Networks Inc.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: head/sys/amd64/vmm/vmm_host.c 242275 2012-10-29 01:51:24Z neel $");

#include <sys/param.h>
#include <sys/pcpu.h>

#include <machine/cpufunc.h>
#include <machine/segments.h>
#include <machine/specialreg.h>

#include "vmm_host.h"

static uint64_t vmm_host_efer, vmm_host_pat, vmm_host_cr0, vmm_host_cr4;

void
vmm_host_state_init(void)
{

	vmm_host_efer = rdmsr(MSR_EFER);
	vmm_host_pat = rdmsr(MSR_PAT);

	/*
	 * We always want CR0.TS to be set when the processor does a VM exit.
	 *
	 * With emulation turned on unconditionally after a VM exit, we are
	 * able to trap inadvertent use of the FPU until the guest FPU state
	 * has been safely squirreled away.
	 */
	vmm_host_cr0 = rcr0() | CR0_TS;

	vmm_host_cr4 = rcr4();
}

uint64_t
vmm_get_host_pat(void)
{

	return (vmm_host_pat);
}

uint64_t
vmm_get_host_efer(void)
{

	return (vmm_host_efer);
}

uint64_t
vmm_get_host_cr0(void)
{

	return (vmm_host_cr0);
}

uint64_t
vmm_get_host_cr4(void)
{

	return (vmm_host_cr4);
}

uint64_t
vmm_get_host_datasel(void)
{

#ifdef	__FreeBSD__
	return (GSEL(GDATA_SEL, SEL_KPL));
#else
	return (SEL_GDT(GDT_KDATA, SEL_KPL));
#endif

}

uint64_t
vmm_get_host_codesel(void)
{

#ifdef	__FreeBSD__
	return (GSEL(GCODE_SEL, SEL_KPL));
#else
	return (SEL_GDT(GDT_KCODE, SEL_KPL));
#endif
}


uint64_t
vmm_get_host_tsssel(void)
{

#ifdef	__FreeBSD__
	return (GSEL(GPROC0_SEL, SEL_KPL));
#else
	return (SEL_GDT(GDT_KTSS, SEL_KPL));
#endif
}

uint64_t
vmm_get_host_fsbase(void)
{

#ifdef	__FreeBSD__
	return (0);
#else
	return (rdmsr(MSR_FSBASE));
#endif
}

uint64_t
vmm_get_host_idtrbase(void)
{

#ifdef	__FreeBSD__
	return (r_idt.rd_base);
#else
	desctbr_t idtr;

	rd_idtr(&idtr);
	return (idtr.dtr_base);
#endif
}
