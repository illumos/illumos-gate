/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2013 Tycho Nightingale <tycho.nightingale@pluribusnetworks.com>
 * Copyright (c) 2013 Neel Natu <neel@freebsd.org>
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
 * $FreeBSD$
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
 * Copyright 2014 Pluribus Networks Inc.
 * Copyright 2017 Joyent, Inc.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/cpuset.h>

#include <x86/apicreg.h>
#include <machine/vmm.h>

#include "vmm_ktr.h"
#include "vmm_lapic.h"
#include "vlapic.h"
#include "vioapic.h"

#define	IOREGSEL	0x00
#define	IOWIN		0x10

#define	REDIR_ENTRIES	32
#define	RTBL_RO_BITS	((uint64_t)(IOART_REM_IRR | IOART_DELIVS))

struct vioapic {
	struct vm	*vm;
	struct mtx	mtx;
	uint32_t	id;
	uint32_t	ioregsel;
	struct {
		uint64_t reg;
		int	 acnt;	/* sum of pin asserts (+1) and deasserts (-1) */
	} rtbl[REDIR_ENTRIES];
};

#define	VIOAPIC_LOCK(vioapic)		mtx_lock_spin(&((vioapic)->mtx))
#define	VIOAPIC_UNLOCK(vioapic)		mtx_unlock_spin(&((vioapic)->mtx))
#define	VIOAPIC_LOCKED(vioapic)		mtx_owned(&((vioapic)->mtx))

static MALLOC_DEFINE(M_VIOAPIC, "vioapic", "bhyve virtual ioapic");

#define	VIOAPIC_CTR1(vioapic, fmt, a1)					\
	VM_CTR1((vioapic)->vm, fmt, a1)

#define	VIOAPIC_CTR2(vioapic, fmt, a1, a2)				\
	VM_CTR2((vioapic)->vm, fmt, a1, a2)

#define	VIOAPIC_CTR3(vioapic, fmt, a1, a2, a3)				\
	VM_CTR3((vioapic)->vm, fmt, a1, a2, a3)

#define	VIOAPIC_CTR4(vioapic, fmt, a1, a2, a3, a4)			\
	VM_CTR4((vioapic)->vm, fmt, a1, a2, a3, a4)

#ifdef KTR
static const char *
pinstate_str(bool asserted)
{

	if (asserted)
		return ("asserted");
	else
		return ("deasserted");
}
#endif

static void
vioapic_send_intr(struct vioapic *vioapic, int pin)
{
	int vector, delmode;
	uint32_t low, high, dest;
	bool level, phys;

	KASSERT(pin >= 0 && pin < REDIR_ENTRIES,
	    ("vioapic_set_pinstate: invalid pin number %d", pin));

	KASSERT(VIOAPIC_LOCKED(vioapic),
	    ("vioapic_set_pinstate: vioapic is not locked"));

	low = vioapic->rtbl[pin].reg;
	high = vioapic->rtbl[pin].reg >> 32;

	if ((low & IOART_INTMASK) == IOART_INTMSET) {
		VIOAPIC_CTR1(vioapic, "ioapic pin%d: masked", pin);
		return;
	}

	phys = ((low & IOART_DESTMOD) == IOART_DESTPHY);
	delmode = low & IOART_DELMOD;
	level = low & IOART_TRGRLVL ? true : false;
	if (level)
		vioapic->rtbl[pin].reg |= IOART_REM_IRR;

	vector = low & IOART_INTVEC;
	dest = high >> APIC_ID_SHIFT;
	vlapic_deliver_intr(vioapic->vm, level, dest, phys, delmode, vector);
}

static void
vioapic_set_pinstate(struct vioapic *vioapic, int pin, bool newstate)
{
	int oldcnt, newcnt;
	bool needintr;

	KASSERT(pin >= 0 && pin < REDIR_ENTRIES,
	    ("vioapic_set_pinstate: invalid pin number %d", pin));

	KASSERT(VIOAPIC_LOCKED(vioapic),
	    ("vioapic_set_pinstate: vioapic is not locked"));

	oldcnt = vioapic->rtbl[pin].acnt;
	if (newstate)
		vioapic->rtbl[pin].acnt++;
	else
		vioapic->rtbl[pin].acnt--;
	newcnt = vioapic->rtbl[pin].acnt;

	if (newcnt < 0) {
		VIOAPIC_CTR2(vioapic, "ioapic pin%d: bad acnt %d",
		    pin, newcnt);
	}

	needintr = false;
	if (oldcnt == 0 && newcnt == 1) {
		needintr = true;
		VIOAPIC_CTR1(vioapic, "ioapic pin%d: asserted", pin);
	} else if (oldcnt == 1 && newcnt == 0) {
		VIOAPIC_CTR1(vioapic, "ioapic pin%d: deasserted", pin);
	} else {
		VIOAPIC_CTR3(vioapic, "ioapic pin%d: %s, ignored, acnt %d",
		    pin, pinstate_str(newstate), newcnt);
	}

	if (needintr)
		vioapic_send_intr(vioapic, pin);
}

enum irqstate {
	IRQSTATE_ASSERT,
	IRQSTATE_DEASSERT,
	IRQSTATE_PULSE
};

static int
vioapic_set_irqstate(struct vm *vm, int irq, enum irqstate irqstate)
{
	struct vioapic *vioapic;

	if (irq < 0 || irq >= REDIR_ENTRIES)
		return (EINVAL);

	vioapic = vm_ioapic(vm);

	VIOAPIC_LOCK(vioapic);
	switch (irqstate) {
	case IRQSTATE_ASSERT:
		vioapic_set_pinstate(vioapic, irq, true);
		break;
	case IRQSTATE_DEASSERT:
		vioapic_set_pinstate(vioapic, irq, false);
		break;
	case IRQSTATE_PULSE:
		vioapic_set_pinstate(vioapic, irq, true);
		vioapic_set_pinstate(vioapic, irq, false);
		break;
	default:
		panic("vioapic_set_irqstate: invalid irqstate %d", irqstate);
	}
	VIOAPIC_UNLOCK(vioapic);

	return (0);
}

int
vioapic_assert_irq(struct vm *vm, int irq)
{

	return (vioapic_set_irqstate(vm, irq, IRQSTATE_ASSERT));
}

int
vioapic_deassert_irq(struct vm *vm, int irq)
{

	return (vioapic_set_irqstate(vm, irq, IRQSTATE_DEASSERT));
}

int
vioapic_pulse_irq(struct vm *vm, int irq)
{

	return (vioapic_set_irqstate(vm, irq, IRQSTATE_PULSE));
}

#define	REDIR_IS_PHYS(reg)	(((reg) & IOART_DESTMOD) == IOART_DESTPHY)
#define	REDIR_IS_LOWPRIO(reg)	(((reg) & IOART_DELMOD) == IOART_DELLOPRI)
/* Level-triggered interrupts only valid in fixed and low-priority modes */
#define	REDIR_IS_LVLTRIG(reg)						\
    (((reg) & IOART_TRGRLVL) != 0 &&					\
    (((reg) & IOART_DELMOD) == IOART_DELFIXED || REDIR_IS_LOWPRIO(reg)))
#define	REDIR_DEST(reg)		((reg) >> (32 + APIC_ID_SHIFT))
#define	REDIR_VECTOR(reg)	((reg) & IOART_INTVEC)

/*
 * Given a redirection entry, determine which vCPUs would be targeted.
 */
static void
vioapic_calcdest(struct vioapic *vioapic, uint64_t redir_ent, cpuset_t *dmask)
{

	/*
	 * When calculating interrupt destinations with vlapic_calcdest(), the
	 * legacy xAPIC format is assumed, since the system lacks interrupt
	 * redirection hardware.
	 * See vlapic_deliver_intr() for more details.
	 */
	vlapic_calcdest(vioapic->vm, dmask, REDIR_DEST(redir_ent),
	    REDIR_IS_PHYS(redir_ent), REDIR_IS_LOWPRIO(redir_ent), false);
}

/*
 * Across all redirection entries utilizing a specified vector, determine the
 * set of vCPUs which would be targeted by a level-triggered interrupt.
 */
static void
vioapic_tmr_active(struct vioapic *vioapic, uint8_t vec, cpuset_t *result)
{
	u_int i;

	CPU_ZERO(result);
	if (vec == 0) {
		return;
	}

	for (i = 0; i < REDIR_ENTRIES; i++) {
		cpuset_t dest;
		const uint64_t val = vioapic->rtbl[i].reg;

		if (!REDIR_IS_LVLTRIG(val) || REDIR_VECTOR(val) != vec) {
			continue;
		}

		CPU_ZERO(&dest);
		vioapic_calcdest(vioapic, val, &dest);
		CPU_OR(result, &dest);
	}
}

/*
 * Update TMR state in vLAPICs after changes to vIOAPIC pin configuration
 */
static void
vioapic_update_tmrs(struct vioapic *vioapic, int vcpuid, uint64_t oldval,
    uint64_t newval)
{
	cpuset_t active, allset, newset, oldset;
	struct vm *vm;
	uint8_t newvec, oldvec;

	vm = vioapic->vm;
	CPU_ZERO(&allset);
	CPU_ZERO(&newset);
	CPU_ZERO(&oldset);
	newvec = oldvec = 0;

	if (REDIR_IS_LVLTRIG(oldval)) {
		vioapic_calcdest(vioapic, oldval, &oldset);
		CPU_OR(&allset, &oldset);
		oldvec = REDIR_VECTOR(oldval);
	}

	if (REDIR_IS_LVLTRIG(newval)) {
		vioapic_calcdest(vioapic, newval, &newset);
		CPU_OR(&allset, &newset);
		newvec = REDIR_VECTOR(newval);
	}

	if (CPU_EMPTY(&allset) ||
	    (CPU_CMP(&oldset, &newset) == 0 && oldvec == newvec)) {
		return;
	}

	/*
	 * Since the write to the redirection table has already occurred, a
	 * scan of level-triggered entries referencing the old vector will find
	 * only entries which are now currently valid.
	 */
	vioapic_tmr_active(vioapic, oldvec, &active);

	while (!CPU_EMPTY(&allset)) {
		struct vlapic *vlapic;
		u_int i;

		i = CPU_FFS(&allset) - 1;
		CPU_CLR(i, &allset);

		if (oldvec == newvec &&
		    CPU_ISSET(i, &oldset) && CPU_ISSET(i, &newset)) {
			continue;
		}

		if (i != vcpuid) {
			vcpu_block_run(vm, i);
		}

		vlapic = vm_lapic(vm, i);
		if (CPU_ISSET(i, &oldset)) {
			/*
			 * Perform the deassertion if no other level-triggered
			 * IOAPIC entries target this vCPU with the old vector
			 *
			 * Note: Sharing of vectors like that should be
			 * extremely rare in modern operating systems and was
			 * previously unsupported by the bhyve vIOAPIC.
			 */
			if (!CPU_ISSET(i, &active)) {
				vlapic_tmr_set(vlapic, oldvec, false);
			}
		}
		if (CPU_ISSET(i, &newset)) {
			vlapic_tmr_set(vlapic, newvec, true);
		}

		if (i != vcpuid) {
			vcpu_unblock_run(vm, i);
		}
	}
}

static uint32_t
vioapic_read(struct vioapic *vioapic, int vcpuid, uint32_t addr)
{
	int regnum, pin, rshift;

	regnum = addr & 0xff;
	switch (regnum) {
	case IOAPIC_ID:
		return (vioapic->id);
		break;
	case IOAPIC_VER:
		return (((REDIR_ENTRIES - 1) << MAXREDIRSHIFT) | 0x11);
		break;
	case IOAPIC_ARB:
		return (vioapic->id);
		break;
	default:
		break;
	}

	/* redirection table entries */
	if (regnum >= IOAPIC_REDTBL &&
	    regnum < IOAPIC_REDTBL + REDIR_ENTRIES * 2) {
		pin = (regnum - IOAPIC_REDTBL) / 2;
		if ((regnum - IOAPIC_REDTBL) % 2)
			rshift = 32;
		else
			rshift = 0;

		return (vioapic->rtbl[pin].reg >> rshift);
	}

	return (0);
}

static void
vioapic_write(struct vioapic *vioapic, int vcpuid, uint32_t addr, uint32_t data)
{
	uint64_t data64, mask64;
	uint64_t last, changed;
	int regnum, pin, lshift;

	regnum = addr & 0xff;
	switch (regnum) {
	case IOAPIC_ID:
		vioapic->id = data & APIC_ID_MASK;
		break;
	case IOAPIC_VER:
	case IOAPIC_ARB:
		/* readonly */
		break;
	default:
		break;
	}

	/* redirection table entries */
	if (regnum >= IOAPIC_REDTBL &&
	    regnum < IOAPIC_REDTBL + REDIR_ENTRIES * 2) {
		pin = (regnum - IOAPIC_REDTBL) / 2;
		if ((regnum - IOAPIC_REDTBL) % 2)
			lshift = 32;
		else
			lshift = 0;

		last = vioapic->rtbl[pin].reg;

		data64 = (uint64_t)data << lshift;
		mask64 = (uint64_t)0xffffffff << lshift;
		vioapic->rtbl[pin].reg &= ~mask64 | RTBL_RO_BITS;
		vioapic->rtbl[pin].reg |= data64 & ~RTBL_RO_BITS;

		VIOAPIC_CTR2(vioapic, "ioapic pin%d: redir table entry %#lx",
		    pin, vioapic->rtbl[pin].reg);

		/*
		 * If any fields in the redirection table entry (except mask
		 * or polarity) have changed then update the trigger-mode
		 * registers on all the vlapics.
		 */
		changed = last ^ vioapic->rtbl[pin].reg;
		if (changed & ~(IOART_INTMASK | IOART_INTPOL)) {
			VIOAPIC_CTR1(vioapic, "ioapic pin%d: recalculate "
			    "vlapic trigger-mode register", pin);
			vioapic_update_tmrs(vioapic, vcpuid, last,
			    vioapic->rtbl[pin].reg);
		}

		/*
		 * Generate an interrupt if the following conditions are met:
		 * - pin is not masked
		 * - previous interrupt has been EOIed
		 * - pin level is asserted
		 */
		if ((vioapic->rtbl[pin].reg & IOART_INTMASK) == IOART_INTMCLR &&
		    (vioapic->rtbl[pin].reg & IOART_REM_IRR) == 0 &&
		    (vioapic->rtbl[pin].acnt > 0)) {
			VIOAPIC_CTR2(vioapic, "ioapic pin%d: asserted at rtbl "
			    "write, acnt %d", pin, vioapic->rtbl[pin].acnt);
			vioapic_send_intr(vioapic, pin);
		}
	}
}

static int
vioapic_mmio_rw(struct vioapic *vioapic, int vcpuid, uint64_t gpa,
    uint64_t *data, int size, bool doread)
{
	uint64_t offset;

	offset = gpa - VIOAPIC_BASE;

	/*
	 * The IOAPIC specification allows 32-bit wide accesses to the
	 * IOREGSEL (offset 0) and IOWIN (offset 16) registers.
	 */
	if (size != 4 || (offset != IOREGSEL && offset != IOWIN)) {
		if (doread)
			*data = 0;
		return (0);
	}

	VIOAPIC_LOCK(vioapic);
	if (offset == IOREGSEL) {
		if (doread)
			*data = vioapic->ioregsel;
		else
			vioapic->ioregsel = *data;
	} else {
		if (doread) {
			*data = vioapic_read(vioapic, vcpuid,
			    vioapic->ioregsel);
		} else {
			vioapic_write(vioapic, vcpuid, vioapic->ioregsel,
			    *data);
		}
	}
	VIOAPIC_UNLOCK(vioapic);

	return (0);
}

int
vioapic_mmio_read(void *vm, int vcpuid, uint64_t gpa, uint64_t *rval,
    int size, void *arg)
{
	int error;
	struct vioapic *vioapic;

	vioapic = vm_ioapic(vm);
	error = vioapic_mmio_rw(vioapic, vcpuid, gpa, rval, size, true);
	return (error);
}

int
vioapic_mmio_write(void *vm, int vcpuid, uint64_t gpa, uint64_t wval,
    int size, void *arg)
{
	int error;
	struct vioapic *vioapic;

	vioapic = vm_ioapic(vm);
	error = vioapic_mmio_rw(vioapic, vcpuid, gpa, &wval, size, false);
	return (error);
}

void
vioapic_process_eoi(struct vm *vm, int vcpuid, int vector)
{
	struct vioapic *vioapic;
	int pin;

	KASSERT(vector >= 0 && vector < 256,
	    ("vioapic_process_eoi: invalid vector %d", vector));

	vioapic = vm_ioapic(vm);
	VIOAPIC_CTR1(vioapic, "ioapic processing eoi for vector %d", vector);

	/*
	 * XXX keep track of the pins associated with this vector instead
	 * of iterating on every single pin each time.
	 */
	VIOAPIC_LOCK(vioapic);
	for (pin = 0; pin < REDIR_ENTRIES; pin++) {
		if ((vioapic->rtbl[pin].reg & IOART_REM_IRR) == 0)
			continue;
		if ((vioapic->rtbl[pin].reg & IOART_INTVEC) != vector)
			continue;
		vioapic->rtbl[pin].reg &= ~IOART_REM_IRR;
		if (vioapic->rtbl[pin].acnt > 0) {
			VIOAPIC_CTR2(vioapic, "ioapic pin%d: asserted at eoi, "
			    "acnt %d", pin, vioapic->rtbl[pin].acnt);
			vioapic_send_intr(vioapic, pin);
		}
	}
	VIOAPIC_UNLOCK(vioapic);
}

struct vioapic *
vioapic_init(struct vm *vm)
{
	int i;
	struct vioapic *vioapic;

	vioapic = malloc(sizeof(struct vioapic), M_VIOAPIC, M_WAITOK | M_ZERO);

	vioapic->vm = vm;
	mtx_init(&vioapic->mtx, "vioapic lock", NULL, MTX_SPIN);

	/* Initialize all redirection entries to mask all interrupts */
	for (i = 0; i < REDIR_ENTRIES; i++)
		vioapic->rtbl[i].reg = 0x0001000000010000UL;

	return (vioapic);
}

void
vioapic_cleanup(struct vioapic *vioapic)
{

	free(vioapic, M_VIOAPIC);
}

int
vioapic_pincount(struct vm *vm)
{

	return (REDIR_ENTRIES);
}
