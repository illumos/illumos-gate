/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2014, Neel Natu (neel@freebsd.org)
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

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/x86_archext.h>
#include <sys/privregs.h>

#include <machine/cpufunc.h>
#include <machine/specialreg.h>
#include <machine/vmm.h>
#include <sys/vmm_kernel.h>

#include "svm.h"
#include "vmcb.h"
#include "svm_softc.h"
#include "svm_msr.h"

#ifndef MSR_AMDK8_IPM
#define	MSR_AMDK8_IPM	0xc0010055
#endif

enum {
	IDX_MSR_LSTAR,
	IDX_MSR_CSTAR,
	IDX_MSR_STAR,
	IDX_MSR_SF_MASK,
	HOST_MSR_NUM		/* must be the last enumeration */
};
CTASSERT(HOST_MSR_NUM == SVM_HOST_MSR_NUM);

void
svm_msr_guest_init(struct svm_softc *sc, int vcpu)
{
	/*
	 * All the MSRs accessible to the guest are either saved/restored by
	 * hardware on every #VMEXIT/VMRUN (e.g., G_PAT) or are saved/restored
	 * by VMSAVE/VMLOAD (e.g., MSR_GSBASE).
	 *
	 * There are no guest MSRs that are saved/restored "by hand" so nothing
	 * more to do here.
	 */
}

void
svm_msr_guest_enter(struct svm_softc *sc, int vcpu)
{
	uint64_t *host_msrs = sc->host_msrs[vcpu];

	/*
	 * Save host MSRs (if any) and restore guest MSRs (if any).
	 */
	host_msrs[IDX_MSR_LSTAR] = rdmsr(MSR_LSTAR);
	host_msrs[IDX_MSR_CSTAR] = rdmsr(MSR_CSTAR);
	host_msrs[IDX_MSR_STAR] = rdmsr(MSR_STAR);
	host_msrs[IDX_MSR_SF_MASK] = rdmsr(MSR_SF_MASK);

	/*
	 * Set the frequency multiplier MSR to enable guest TSC scaling if
	 * needed.
	 */
	uint64_t mult = vm_get_freq_multiplier(sc->vm);
	if (mult != VM_TSCM_NOSCALE) {
		wrmsr(MSR_AMD_TSC_RATIO, mult);
	}
}

void
svm_msr_guest_exit(struct svm_softc *sc, int vcpu)
{
	uint64_t *host_msrs = sc->host_msrs[vcpu];

	/*
	 * Save guest MSRs (if any) and restore host MSRs.
	 */
	wrmsr(MSR_LSTAR, host_msrs[IDX_MSR_LSTAR]);
	wrmsr(MSR_CSTAR, host_msrs[IDX_MSR_CSTAR]);
	wrmsr(MSR_STAR, host_msrs[IDX_MSR_STAR]);
	wrmsr(MSR_SF_MASK, host_msrs[IDX_MSR_SF_MASK]);

	/* Reset frequency multiplier MSR if any scaling is configured */
	if (vm_get_freq_multiplier(sc->vm) != VM_TSCM_NOSCALE) {
		wrmsr(MSR_AMD_TSC_RATIO, AMD_TSCM_RESET_VAL);
	}

	/* MSR_KGSBASE will be restored on the way back to userspace */
}

vm_msr_result_t
svm_rdmsr(struct svm_softc *sc, int vcpu, uint32_t num, uint64_t *result)
{
	switch (num) {
	case MSR_SYSCFG:
	case MSR_AMDK8_IPM:
	case MSR_EXTFEATURES:
		*result = 0;
		break;
	case MSR_AMD_DE_CFG:
		*result = 0;
		/*
		 * Bit 1 of DE_CFG is defined by AMD to control whether the
		 * lfence instruction is serializing.  Practically all CPUs
		 * supported by bhyve also contain this MSR, making it safe to
		 * expose unconditionally.
		 */
		if (is_x86_feature(x86_featureset, X86FSET_LFENCE_SER)) {
			*result |= AMD_DE_CFG_LFENCE_DISPATCH;
		}
		break;
	default:
		return (VMR_UNHANLDED);
	}
	return (VMR_OK);
}

vm_msr_result_t
svm_wrmsr(struct svm_softc *sc, int vcpu, uint32_t num, uint64_t val)
{
	switch (num) {
	case MSR_SYSCFG:
		/* Ignore writes */
		break;
	case MSR_AMD_DE_CFG:
		/* Ignore writes */
		break;
	case MSR_AMDK8_IPM:
		/*
		 * Ignore writes to the "Interrupt Pending Message" MSR.
		 */
		break;
	case MSR_K8_UCODE_UPDATE:
		/*
		 * Ignore writes to microcode update register.
		 */
		break;
	case MSR_EXTFEATURES:
		break;
	default:
		return (VMR_UNHANLDED);
	}

	return (VMR_OK);
}
