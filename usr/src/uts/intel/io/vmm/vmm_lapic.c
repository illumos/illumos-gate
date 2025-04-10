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
 * Copyright 2020 Oxide Computer Company
 */

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/cpuset.h>

#include <x86/specialreg.h>
#include <x86/apicreg.h>

#include <machine/vmm.h>
#include "vmm_lapic.h"
#include "vlapic.h"

/*
 * Some MSI message definitions
 */
#define	MSI_X86_ADDR_MASK	0xfff00000
#define	MSI_X86_ADDR_BASE	0xfee00000
#define	MSI_X86_ADDR_RH		0x00000008	/* Redirection Hint */
#define	MSI_X86_ADDR_LOG	0x00000004	/* Destination Mode */

int
lapic_set_intr(struct vm *vm, int cpu, int vector, bool level)
{
	struct vlapic *vlapic;
	vcpu_notify_t notify;

	if (cpu < 0 || cpu >= vm_get_maxcpus(vm))
		return (EINVAL);

	/*
	 * According to section "Maskable Hardware Interrupts" in Intel SDM
	 * vectors 16 through 255 can be delivered through the local APIC.
	 */
	if (vector < 16 || vector > 255)
		return (EINVAL);

	vlapic = vm_lapic(vm, cpu);
	notify = vlapic_set_intr_ready(vlapic, vector, level);
	vcpu_notify_event_type(vm, cpu, notify);
	return (0);
}

int
lapic_set_local_intr(struct vm *vm, int cpu, int vector)
{
	struct vlapic *vlapic;
	cpuset_t dmask;
	int error;

	if (cpu < -1 || cpu >= vm_get_maxcpus(vm))
		return (EINVAL);

	if (cpu == -1)
		dmask = vm_active_cpus(vm);
	else
		CPU_SETOF(cpu, &dmask);
	error = 0;
	while ((cpu = CPU_FFS(&dmask)) != 0) {
		cpu--;
		CPU_CLR(cpu, &dmask);
		vlapic = vm_lapic(vm, cpu);
		error = vlapic_trigger_lvt(vlapic, vector);
		if (error)
			break;
	}

	return (error);
}

int
lapic_intr_msi(struct vm *vm, uint64_t addr, uint64_t msg)
{
	int delmode, vec;
	uint32_t dest;
	bool phys;

	if ((addr & MSI_X86_ADDR_MASK) != MSI_X86_ADDR_BASE) {
		/* Invalid MSI address */
		return (-1);
	}

	/*
	 * Extract the x86-specific fields from the MSI addr/msg params
	 * according to the Intel Arch spec, Vol3 Ch 10.
	 *
	 * The PCI specification does not support level triggered MSI/MSI-X so
	 * ignore trigger level in 'msg'.
	 *
	 * Certain kinds of interrupt broadcasts (physical or logical-clustered
	 * for destination 0xff) are prohibited when the redirection hint bit is
	 * set for a given message.  Those edge cases are ignored for now.
	 */
	dest = (addr >> 12) & 0xff;
	phys = (addr & MSI_X86_ADDR_LOG) == 0;
	delmode = msg & APIC_DELMODE_MASK;
	vec = msg & 0xff;

	vlapic_deliver_intr(vm, LAPIC_TRIG_EDGE, dest, phys, delmode, vec);
	return (0);
}
