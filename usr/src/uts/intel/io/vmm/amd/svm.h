/*-
 * SPDX-License-Identifier: BSD-2-Clause
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

#ifndef	_SVM_H_
#define	_SVM_H_

/*
 * Guest register state that is saved outside the VMCB.
 */
struct svm_regctx {
	uint64_t	sctx_rbp;
	uint64_t	sctx_rbx;
	uint64_t	sctx_rcx;
	uint64_t	sctx_rdx;
	uint64_t	sctx_rdi;
	uint64_t	sctx_rsi;
	uint64_t	sctx_r8;
	uint64_t	sctx_r9;
	uint64_t	sctx_r10;
	uint64_t	sctx_r11;
	uint64_t	sctx_r12;
	uint64_t	sctx_r13;
	uint64_t	sctx_r14;
	uint64_t	sctx_r15;
	uint64_t	sctx_dr0;
	uint64_t	sctx_dr1;
	uint64_t	sctx_dr2;
	uint64_t	sctx_dr3;
	uint64_t	sctx_cr0_shadow;

	uint64_t	host_dr0;
	uint64_t	host_dr1;
	uint64_t	host_dr2;
	uint64_t	host_dr3;
	uint64_t	host_dr6;
	uint64_t	host_dr7;
	uint64_t	host_debugctl;
};

struct cpu;
void svm_launch(uint64_t pa, struct svm_regctx *gctx, struct cpu *pcpu);

#endif /* _SVM_H_ */
