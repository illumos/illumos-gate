/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
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
 * Copyright 2020 Oxide Computer Company
 */

#ifndef	_VMM_INSTRUCTION_EMUL_H_
#define	_VMM_INSTRUCTION_EMUL_H_

#include <sys/mman.h>
#include <machine/vmm.h>

struct vie;

struct vie *vie_alloc();
void vie_free(struct vie *);

enum vm_reg_name vie_regnum_map(uint8_t);

void vie_init_mmio(struct vie *vie, const char *inst_bytes, uint8_t inst_length,
    const struct vm_guest_paging *paging, uint64_t gpa);
void vie_init_inout(struct vie *vie, const struct vm_inout *inout,
    uint8_t inst_len, const struct vm_guest_paging *paging);
void vie_init_other(struct vie *vie, const struct vm_guest_paging *paging);

int vie_fulfill_mmio(struct vie *vie, const struct vm_mmio *res);
int vie_fulfill_inout(struct vie *vie, const struct vm_inout *res);

bool vie_needs_fetch(const struct vie *vie);
bool vie_pending(const struct vie *vie);
uint64_t vie_mmio_gpa(const struct vie *vie);
void vie_exitinfo(const struct vie *vie, struct vm_exit *vme);
void vie_fallback_exitinfo(const struct vie *vie, struct vm_exit *vme);
void vie_cs_info(const struct vie *vie, struct vm *vm, int vcpuid,
    uint64_t *cs_base, int *cs_d);

void vie_reset(struct vie *vie);
void vie_advance_pc(struct vie *vie, uint64_t *nextrip);

int vie_emulate_mmio(struct vie *vie, struct vm *vm, int vcpuid);
int vie_emulate_inout(struct vie *vie, struct vm *vm, int vcpuid);
int vie_emulate_other(struct vie *vie, struct vm *vm, int vcpuid);

/*
 * APIs to fetch and decode the instruction from nested page fault handler.
 *
 * 'vie' must be initialized before calling 'vie_fetch_instruction()'
 */
int vie_fetch_instruction(struct vie *vie, struct vm *vm, int cpuid,
    uint64_t rip, int *is_fault);

/*
 * Translate the guest linear address 'gla' to a guest physical address.
 *
 * retval	is_fault	Interpretation
 *   0		   0		'gpa' contains result of the translation
 *   0		   1		An exception was injected into the guest
 * EFAULT	  N/A		An unrecoverable hypervisor error occurred
 */
int vm_gla2gpa(struct vm *vm, int vcpuid, struct vm_guest_paging *paging,
    uint64_t gla, int prot, uint64_t *gpa, int *is_fault);

/*
 * Like vm_gla2gpa, but no exceptions are injected into the guest and
 * PTEs are not changed.
 */
int vm_gla2gpa_nofault(struct vm *vm, int vcpuid,
    struct vm_guest_paging *paging, uint64_t gla, int prot, uint64_t *gpa,
    int *is_fault);

int vie_verify_gla(struct vie *vie, struct vm *vm, int cpuid, uint64_t gla);
/*
 * Decode the instruction fetched into 'vie' so it can be emulated.
 *
 * 'gla' is the guest linear address provided by the hardware assist
 * that caused the nested page table fault. It is used to verify that
 * the software instruction decoding is in agreement with the hardware.
 *
 * Some hardware assists do not provide the 'gla' to the hypervisor.
 * To skip the 'gla' verification for this or any other reason pass
 * in VIE_INVALID_GLA instead.
 */
#define	VIE_INVALID_GLA		(1UL << 63)	/* a non-canonical address */
int vie_decode_instruction(struct vie *vie, struct vm *vm, int cpuid, int csd);

#endif	/* _VMM_INSTRUCTION_EMUL_H_ */
