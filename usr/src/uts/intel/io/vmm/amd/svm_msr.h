/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2014 Neel Natu (neel@freebsd.org)
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
 *
 * $FreeBSD$
 */

#ifndef _SVM_MSR_H_
#define	_SVM_MSR_H_

struct svm_softc;

void svm_msr_guest_init(struct svm_softc *sc, int vcpu);
void svm_msr_guest_enter(struct svm_softc *sc, int vcpu);
void svm_msr_guest_exit(struct svm_softc *sc, int vcpu);

vm_msr_result_t svm_wrmsr(struct svm_softc *, int, uint32_t, uint64_t);
vm_msr_result_t svm_rdmsr(struct svm_softc *, int, uint32_t, uint64_t *);

/*
 * TSC Frequency Multiplier MSR related values
 */

/* N integer bits of frequency multiplier */
#define	AMD_TSCM_INT_SIZE	8

/* N fractional bits of frequency multiplier */
#define	AMD_TSCM_FRAC_SIZE	32

/*
 * The reset value of the frequency multiplier is 1.0 (section 15.30.5 of AMD
 * Architecture Programmer's Manual Volume 2), indicating the host and guest
 * have the same TSC frequency.
 */
#define	AMD_TSCM_RESET_VAL	(1ULL << AMD_TSCM_FRAC_SIZE)

#endif	/* _SVM_MSR_H_ */
