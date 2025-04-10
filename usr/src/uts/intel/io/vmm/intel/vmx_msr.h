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
 * Copyright 2021 Oxide Computer Company
 */

#ifndef _VMX_MSR_H_
#define	_VMX_MSR_H_

void vmx_msr_init(void);
void vmx_msr_guest_init(struct vmx *vmx, int vcpuid);
void vmx_msr_guest_enter(struct vmx *vmx, int vcpuid);
void vmx_msr_guest_exit(struct vmx *vmx, int vcpuid);
vm_msr_result_t vmx_rdmsr(struct vmx *, int, uint32_t, uint64_t *);
vm_msr_result_t vmx_wrmsr(struct vmx *, int, uint32_t, uint64_t);

int vmx_set_ctlreg(int ctl_reg, int true_ctl_reg, uint32_t ones_mask,
    uint32_t zeros_mask, uint32_t *retval);

/*
 * According to Section 21.10.4 "Software Access to Related Structures",
 * changes to data structures pointed to by the VMCS must be made only when
 * there is no logical processor with a current VMCS that points to the
 * data structure.
 *
 * This pretty much limits us to configuring the MSR bitmap before VMCS
 * initialization for SMP VMs. Unless of course we do it the hard way - which
 * would involve some form of synchronization between the vcpus to vmclear
 * all VMCSs' that point to the bitmap.
 */
#define	MSR_BITMAP_ACCESS_NONE	0x0
#define	MSR_BITMAP_ACCESS_READ	0x1
#define	MSR_BITMAP_ACCESS_WRITE	0x2
#define	MSR_BITMAP_ACCESS_RW	(MSR_BITMAP_ACCESS_READ|MSR_BITMAP_ACCESS_WRITE)
void vmx_msr_bitmap_initialize(struct vmx *);
void vmx_msr_bitmap_destroy(struct vmx *);
void vmx_msr_bitmap_change_access(struct vmx *, int, uint_t, int);

#define	guest_msr_rw(vmx, vcpuid, msr) \
    vmx_msr_bitmap_change_access((vmx), (vcpuid), (msr), MSR_BITMAP_ACCESS_RW)

#define	guest_msr_ro(vmx, vcpuid, msr) \
    vmx_msr_bitmap_change_access((vmx), (vcpuid), (msr), MSR_BITMAP_ACCESS_READ)

#endif
