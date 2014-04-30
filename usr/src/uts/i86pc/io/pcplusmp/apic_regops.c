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

/* Function prototypes of local apic and X2APIC */
static uint64_t local_apic_read(uint32_t reg);
static void local_apic_write(uint32_t reg, uint64_t value);
static int get_local_apic_pri(void);
static void local_apic_write_task_reg(uint64_t value);
static void local_apic_write_int_cmd(uint32_t cpu_id, uint32_t cmd1);
static uint64_t local_x2apic_read(uint32_t msr);
static void local_x2apic_write(uint32_t msr, uint64_t value);
static int get_local_x2apic_pri(void);
static void local_x2apic_write_task_reg(uint64_t value);
static void local_x2apic_write_int_cmd(uint32_t cpu_id, uint32_t cmd1);

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
int	x2apic_enable = 1;
apic_mode_t apic_mode = LOCAL_APIC;	/* Default mode is Local APIC */

/* Uses MMIO (Memory Mapped IO) */
static apic_reg_ops_t local_apic_regs_ops = {
	local_apic_read,
	local_apic_write,
	get_local_apic_pri,
	local_apic_write_task_reg,
	local_apic_write_int_cmd,
	apic_send_EOI,
};

/* X2APIC : Uses RDMSR/WRMSR instructions to access APIC registers */
static apic_reg_ops_t x2apic_regs_ops = {
	local_x2apic_read,
	local_x2apic_write,
	get_local_x2apic_pri,
	local_x2apic_write_task_reg,
	local_x2apic_write_int_cmd,
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

#define	X2APIC_ENABLE_BIT	10

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

/*
 * X2APIC Implementation.
 */
static uint64_t
local_x2apic_read(uint32_t msr)
{
	uint64_t i;

	i = (uint64_t)(rdmsr(REG_X2APIC_BASE_MSR + (msr >> 2)) & 0xffffffff);
	return (i);
}

static void
local_x2apic_write(uint32_t msr, uint64_t value)
{
	uint64_t tmp;

	if (msr != APIC_EOI_REG) {
		tmp = rdmsr(REG_X2APIC_BASE_MSR + (msr >> 2));
		tmp = (tmp & 0xffffffff00000000) | value;
	} else {
		tmp = 0;
	}

	wrmsr((REG_X2APIC_BASE_MSR + (msr >> 2)), tmp);
}

static int
get_local_x2apic_pri(void)
{
	return (rdmsr(REG_X2APIC_BASE_MSR + (APIC_TASK_REG >> 2)));
}

static void
local_x2apic_write_task_reg(uint64_t value)
{
	X2APIC_WRITE(APIC_TASK_REG, value);
}

static void
local_x2apic_write_int_cmd(uint32_t cpu_id, uint32_t cmd1)
{
	wrmsr((REG_X2APIC_BASE_MSR + (APIC_INT_CMD1 >> 2)),
	    (((uint64_t)cpu_id << 32) | cmd1));
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

int
apic_detect_x2apic(void)
{
	if (x2apic_enable == 0)
		return (0);

	return (is_x86_feature(x86_featureset, X86FSET_X2APIC));
}

void
apic_enable_x2apic(void)
{
	uint64_t apic_base_msr;

	if (apic_local_mode() == LOCAL_X2APIC) {
		/* BIOS apparently has enabled X2APIC */
		if (apic_mode != LOCAL_X2APIC)
			x2apic_update_psm();
		return;
	}

	/*
	 * This is the first time we are enabling X2APIC on this CPU
	 */
	apic_base_msr = rdmsr(REG_APIC_BASE_MSR);
	apic_base_msr = apic_base_msr | (0x1 << X2APIC_ENABLE_BIT);
	wrmsr(REG_APIC_BASE_MSR, apic_base_msr);

	if (apic_mode != LOCAL_X2APIC)
		x2apic_update_psm();
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

	ver = apic_reg_ops->apic_read(APIC_VERS_REG);
	if (ver & APIC_DIRECTED_EOI_BIT)
		return (1);

	return (0);
}

/*
 * Change apic_reg_ops depending upon the apic_mode.
 */
void
apic_change_ops()
{
	if (apic_mode == LOCAL_APIC)
		apic_reg_ops = &local_apic_regs_ops;
	else if (apic_mode == LOCAL_X2APIC)
		apic_reg_ops = &x2apic_regs_ops;
}

/*
 * Generates an interprocessor interrupt to another CPU when X2APIC mode is
 * enabled.
 */
void
x2apic_send_ipi(int cpun, int ipl)
{
	int vector;
	ulong_t flag;

	ASSERT(apic_mode == LOCAL_X2APIC);

	/*
	 * With X2APIC, Intel relaxed the semantics of the
	 * WRMSR instruction such that references to the X2APIC
	 * MSR registers are no longer serializing instructions.
	 * The code that initiates IPIs assumes that some sort
	 * of memory serialization occurs. The old APIC code
	 * did a write to uncachable memory mapped registers.
	 * Any reference to uncached memory is a serializing
	 * operation. To mimic those semantics here, we do an
	 * atomic operation, which translates to a LOCK OR instruction,
	 * which is serializing.
	 */
	atomic_or_ulong(&flag, 1);

	vector = apic_resv_vector[ipl];

	flag = intr_clear();

	/*
	 * According to X2APIC specification in section '2.3.5.1' of
	 * Interrupt Command Register Semantics, the semantics of
	 * programming Interrupt Command Register to dispatch an interrupt
	 * is simplified. A single MSR write to the 64-bit ICR is required
	 * for dispatching an interrupt. Specifically with the 64-bit MSR
	 * interface to ICR, system software is not required to check the
	 * status of the delivery status bit prior to writing to the ICR
	 * to send an IPI. With the removal of the Delivery Status bit,
	 * system software no longer has a reason to read the ICR. It remains
	 * readable only to aid in debugging.
	 */
#ifdef	DEBUG
	APIC_AV_PENDING_SET();
#endif	/* DEBUG */

	if ((cpun == psm_get_cpu_id())) {
		X2APIC_WRITE(X2APIC_SELF_IPI, vector);
	} else {
		apic_reg_ops->apic_write_int_cmd(
		    apic_cpus[cpun].aci_local_id, vector);
	}

	intr_restore(flag);
}

/*
 * Generates IPI to another CPU depending on the local APIC mode.
 * apic_send_ipi() and x2apic_send_ipi() depends on the configured
 * mode of the local APIC, but that may not match the actual mode
 * early in CPU startup.
 *
 * Any changes made to this routine must be accompanied by similar
 * changes to apic_send_ipi().
 */
void
apic_common_send_ipi(int cpun, int ipl)
{
	int vector;
	ulong_t flag;
	int mode = apic_local_mode();

	if (mode == LOCAL_X2APIC) {
		x2apic_send_ipi(cpun, ipl);
		return;
	}

	ASSERT(mode == LOCAL_APIC);

	vector = apic_resv_vector[ipl];
	ASSERT((vector >= APIC_BASE_VECT) && (vector <= APIC_SPUR_INTR));
	flag = intr_clear();
	while (local_apic_regs_ops.apic_read(APIC_INT_CMD1) & AV_PENDING)
		apic_ret();
	local_apic_regs_ops.apic_write_int_cmd(apic_cpus[cpun].aci_local_id,
	    vector);
	intr_restore(flag);
}
