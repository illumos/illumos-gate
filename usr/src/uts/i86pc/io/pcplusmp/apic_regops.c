/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2014 Josef 'Jeff' Sipek <jeffpc@josefsipek.net>
 * Copyright (c) 2014 by Delphix. All rights reserved.
 * Copyright 2017 Joyent, Inc.
 */

#include <sys/cpuvar.h>
#include <sys/psm.h>
#include <sys/archsystm.h>
#include <sys/apic.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/mach_intr.h>
#include <sys/sysmacros.h>
#include <sys/trap.h>
#include <sys/x86_archext.h>
#include <sys/privregs.h>
#include <sys/psm_common.h>

/* Function prototypes of local apic */
static uint64_t local_apic_read(uint32_t reg);
static void local_apic_write(uint32_t reg, uint64_t value);
static int get_local_apic_pri(void);
static void local_apic_write_task_reg(uint64_t value);
static void local_apic_write_int_cmd(uint32_t cpu_id, uint32_t cmd1);

/*
 * According to the X2APIC specification:
 *
 *   xAPIC global enable    X2APIC enable         Description
 *   (IA32_APIC_BASE[11])   (IA32_APIC_BASE[10])
 * -----------------------------------------------------------
 *      0 			0 	APIC is disabled
 * 	0			1	Invalid
 *	1			0	APIC is enabled in xAPIC mode
 *	1			1	APIC is enabled in X2APIC mode
 * -----------------------------------------------------------
 */
apic_mode_t apic_mode = LOCAL_APIC;	/* Default mode is Local APIC */

/* See apic_directed_EOI_supported().  Currently 3-state variable. */
volatile int apic_directed_eoi_state = 2;

/* Uses MMIO (Memory Mapped IO) */
apic_reg_ops_t local_apic_regs_ops = {
	local_apic_read,
	local_apic_write,
	get_local_apic_pri,
	local_apic_write_task_reg,
	local_apic_write_int_cmd,
	apic_send_EOI,
};

int apic_have_32bit_cr8 = 0;

/* The default ops is local APIC (Memory Mapped IO) */
apic_reg_ops_t *apic_reg_ops = &local_apic_regs_ops;

/*
 * APIC register ops related data sturctures and functions.
 */
void apic_send_EOI();
void apic_send_directed_EOI(uint32_t irq);

/*
 * Local APIC Implementation
 */
static uint64_t
local_apic_read(uint32_t reg)
{
	return ((uint32_t)apicadr[reg]);
}

static void
local_apic_write(uint32_t reg, uint64_t value)
{
	apicadr[reg] = (uint32_t)value;
}

static int
get_local_apic_pri(void)
{
#if defined(__amd64)
	return ((int)getcr8());
#else
	if (apic_have_32bit_cr8)
		return ((int)getcr8());
	return (apicadr[APIC_TASK_REG]);
#endif
}

static void
local_apic_write_task_reg(uint64_t value)
{
#if defined(__amd64)
	setcr8((ulong_t)(value >> APIC_IPL_SHIFT));
#else
	if (apic_have_32bit_cr8)
		setcr8((ulong_t)(value >> APIC_IPL_SHIFT));
	else
		apicadr[APIC_TASK_REG] = (uint32_t)value;
#endif
}

static void
local_apic_write_int_cmd(uint32_t cpu_id, uint32_t cmd1)
{
	apicadr[APIC_INT_CMD2] = cpu_id << APIC_ICR_ID_BIT_OFFSET;
	apicadr[APIC_INT_CMD1] = cmd1;
}


/*ARGSUSED*/
void
apic_send_EOI(uint32_t irq)
{
	apic_reg_ops->apic_write(APIC_EOI_REG, 0);
}

/*
 * Support for Directed EOI capability is available in both the xAPIC
 * and x2APIC mode.
 */
void
apic_send_directed_EOI(uint32_t irq)
{
	uchar_t ioapicindex;
	uchar_t vector;
	apic_irq_t *apic_irq;
	short intr_index;

	/*
	 * Following the EOI to the local APIC unit, perform a directed
	 * EOI to the IOxAPIC generating the interrupt by writing to its
	 * EOI register.
	 *
	 * A broadcast EOI is not generated.
	 */
	apic_reg_ops->apic_write(APIC_EOI_REG, 0);

	apic_irq = apic_irq_table[irq];
	while (apic_irq) {
		intr_index = apic_irq->airq_mps_intr_index;
		if (intr_index == ACPI_INDEX || intr_index >= 0) {
			ioapicindex = apic_irq->airq_ioapicindex;
			vector = apic_irq->airq_vector;
			ioapic_write_eoi(ioapicindex, vector);
		}
		apic_irq = apic_irq->airq_next;
	}
}

/*
 * Determine which mode the current CPU is in. See the table above.
 * (IA32_APIC_BASE[11])   (IA32_APIC_BASE[10])
 */
int
apic_local_mode(void)
{
	uint64_t apic_base_msr;
	int bit = ((0x1 << (X2APIC_ENABLE_BIT + 1)) |
	    (0x1 << X2APIC_ENABLE_BIT));

	apic_base_msr = rdmsr(REG_APIC_BASE_MSR);

	if ((apic_base_msr & bit) == bit)
		return (LOCAL_X2APIC);
	else
		return (LOCAL_APIC);
}

void
apic_set_directed_EOI_handler()
{
	apic_reg_ops->apic_send_eoi = apic_send_directed_EOI;
}

int
apic_directed_EOI_supported()
{
	uint32_t ver;

	/*
	 * There are some known issues with some versions of Linux KVM and QEMU
	 * where by directed EOIs do not properly function and instead get
	 * coalesced at the hypervisor, causing the host not to see interrupts.
	 * Thus, when the platform is KVM, we would like to disable it by
	 * default, but keep it available otherwise.
	 *
	 * We use a three-state variable (apic_directed_eoi_state) to determine
	 * how we handle directed EOI.
	 *
	 * 0 --> Don't do directed EOI at all.
	 * 1 --> Do directed EOI if available, no matter the HW environment.
	 * 2 --> Don't do directed EOI on KVM, but do it otherwise if available.
	 *
	 * If some grinning weirdo put something else in there, treat it as '2'
	 * (i.e. the current default).
	 *
	 * Note, at this time illumos KVM does not identify as KVM. If it does,
	 * we'll need to do some work to determine if it should be caught by
	 * this or if it should show up as its own value of platform_type.
	 */
	switch (apic_directed_eoi_state) {
	case 0:
		/* Don't do it at all. */
		return (0);
	case 1:
		break;
	case 2:
	default:
		/* Only do it if we aren't on KVM. */
		if (get_hwenv() == HW_KVM)
			return (0);
		/* FALLTHRU */
	}

	ver = apic_reg_ops->apic_read(APIC_VERS_REG);
	if (ver & APIC_DIRECTED_EOI_BIT)
		return (1);

	return (0);
}
