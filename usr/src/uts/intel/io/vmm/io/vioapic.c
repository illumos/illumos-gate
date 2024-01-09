/*-
 * SPDX-License-Identifier: BSD-2-Clause
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
 * Copyright 2021 Oxide Computer Company
 */

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/mutex.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/kmem.h>
#include <sys/cpuset.h>

#include <x86/apicreg.h>
#include <machine/vmm.h>
#include <sys/vmm_data.h>

#include "vmm_lapic.h"
#include "vlapic.h"
#include "vioapic.h"

#define	IOREGSEL	0x00
#define	IOWIN		0x10

#define	REDIR_ENTRIES	32
#define	RTBL_RO_BITS	((uint64_t)(IOART_REM_IRR | IOART_DELIVS))

struct ioapic_stats {
	uint64_t	is_interrupts;
	uint64_t	is_saturate_low;
	uint64_t	is_saturate_high;
};

struct vioapic {
	struct vm	*vm;
	kmutex_t	lock;
	uint32_t	id;
	uint32_t	ioregsel;
	struct {
		uint64_t reg;
		/*
		 * The sum of pin asserts (+1) and deasserts (-1) are tracked in
		 * 'acnt'.  It is clamped to prevent overflow or underflow
		 * should emulation consumers feed it an invalid set of
		 * transitions.
		 */
		uint_t acnt;
	} rtbl[REDIR_ENTRIES];
	struct ioapic_stats stats;
};

#define	VIOAPIC_LOCK(vioapic)		mutex_enter(&((vioapic)->lock))
#define	VIOAPIC_UNLOCK(vioapic)		mutex_exit(&((vioapic)->lock))
#define	VIOAPIC_LOCKED(vioapic)		MUTEX_HELD(&((vioapic)->lock))


static void
vioapic_send_intr(struct vioapic *vioapic, int pin)
{
	int vector, delmode;
	uint32_t low, high, dest;
	bool level, phys;

	VERIFY(pin >= 0 && pin < REDIR_ENTRIES);
	ASSERT(VIOAPIC_LOCKED(vioapic));

	low = vioapic->rtbl[pin].reg;
	high = vioapic->rtbl[pin].reg >> 32;

	if ((low & IOART_INTMASK) == IOART_INTMSET) {
		/* Pin is masked */
		return;
	}

	phys = ((low & IOART_DESTMOD) == IOART_DESTPHY);
	delmode = low & IOART_DELMOD;
	level = low & IOART_TRGRLVL ? true : false;
	if (level) {
		if ((low & IOART_REM_IRR) != 0) {
			/* IRR already pending */
			return;
		}
		vioapic->rtbl[pin].reg |= IOART_REM_IRR;
	}

	vector = low & IOART_INTVEC;
	dest = high >> APIC_ID_SHIFT;
	vlapic_deliver_intr(vioapic->vm, level, dest, phys, delmode, vector);
	vioapic->stats.is_interrupts++;
}

static int
vioapic_set_pinstate(struct vioapic *vioapic, int pin, bool newstate)
{
	uint_t oldcnt, newcnt;
	bool needintr = false;
	int err = 0;

	VERIFY(pin >= 0 && pin < REDIR_ENTRIES);
	ASSERT(VIOAPIC_LOCKED(vioapic));

	oldcnt = newcnt = vioapic->rtbl[pin].acnt;
	if (newstate) {
		if (newcnt != UINT_MAX) {
			newcnt++;
		} else {
			err = E2BIG;
			DTRACE_PROBE2(vioapic__sat_high,
			    struct vioapic *, vioapic, int, pin);
			vioapic->stats.is_saturate_high++;
		}
	} else {
		if (newcnt != 0) {
			newcnt--;
		} else {
			err = ERANGE;
			DTRACE_PROBE2(vioapic__sat_low,
			    struct vioapic *, vioapic, int, pin);
			vioapic->stats.is_saturate_low++;
		}
	}
	vioapic->rtbl[pin].acnt = newcnt;

	if (oldcnt == 0 && newcnt == 1) {
		needintr = true;
		DTRACE_PROBE2(vioapic__assert, struct vioapic *, vioapic,
		    int, pin);
	} else if (oldcnt == 1 && newcnt == 0) {
		DTRACE_PROBE2(vioapic__deassert, struct vioapic *, vioapic,
		    int, pin);
	}

	if (needintr) {
		vioapic_send_intr(vioapic, pin);
	}
	return (err);
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
	int err = 0;

	if (irq < 0 || irq >= REDIR_ENTRIES)
		return (EINVAL);

	vioapic = vm_ioapic(vm);

	VIOAPIC_LOCK(vioapic);
	switch (irqstate) {
	case IRQSTATE_ASSERT:
		err = vioapic_set_pinstate(vioapic, irq, true);
		break;
	case IRQSTATE_DEASSERT:
		err = vioapic_set_pinstate(vioapic, irq, false);
		break;
	case IRQSTATE_PULSE:
		err = vioapic_set_pinstate(vioapic, irq, true);
		if (err == 0) {
			err = vioapic_set_pinstate(vioapic, irq, false);
		}
		break;
	default:
		panic("vioapic_set_irqstate: invalid irqstate %d", irqstate);
	}
	VIOAPIC_UNLOCK(vioapic);

	return (err);
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

		data64 = (uint64_t)data << lshift;
		mask64 = (uint64_t)0xffffffff << lshift;
		vioapic->rtbl[pin].reg &= ~mask64 | RTBL_RO_BITS;
		vioapic->rtbl[pin].reg |= data64 & ~RTBL_RO_BITS;

		/*
		 * Switching from level to edge triggering will clear the IRR
		 * bit. This is what FreeBSD will do in order to EOI an
		 * interrupt when the IO-APIC doesn't support targeted EOI (see
		 * _ioapic_eoi_source).
		 */
		if ((vioapic->rtbl[pin].reg & IOART_TRGRMOD) == IOART_TRGREDG &&
		    (vioapic->rtbl[pin].reg & IOART_REM_IRR) != 0)
			vioapic->rtbl[pin].reg &= ~IOART_REM_IRR;

		/*
		 * Generate an interrupt if the following conditions are met:
		 * - pin trigger mode is level
		 * - pin level is asserted
		 */
		if ((vioapic->rtbl[pin].reg & IOART_TRGRMOD) == IOART_TRGRLVL &&
		    (vioapic->rtbl[pin].acnt > 0)) {
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
vioapic_mmio_read(struct vm *vm, int vcpuid, uint64_t gpa, uint64_t *rval,
    int size)
{
	int error;
	struct vioapic *vioapic;

	vioapic = vm_ioapic(vm);
	error = vioapic_mmio_rw(vioapic, vcpuid, gpa, rval, size, true);
	return (error);
}

int
vioapic_mmio_write(struct vm *vm, int vcpuid, uint64_t gpa, uint64_t wval,
    int size)
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
			/* Pin asserted at EOI */
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

	vioapic = kmem_zalloc(sizeof (struct vioapic), KM_SLEEP);

	vioapic->vm = vm;
	mutex_init(&vioapic->lock, NULL, MUTEX_ADAPTIVE, NULL);

	/* Initialize all redirection entries to mask all interrupts */
	for (i = 0; i < REDIR_ENTRIES; i++)
		vioapic->rtbl[i].reg = 0x0001000000010000UL;

	return (vioapic);
}

void
vioapic_cleanup(struct vioapic *vioapic)
{
	mutex_destroy(&vioapic->lock);
	kmem_free(vioapic, sizeof (*vioapic));
}

int
vioapic_pincount(struct vm *vm)
{

	return (REDIR_ENTRIES);
}

static int
vioapic_data_read(void *datap, const vmm_data_req_t *req)
{
	VERIFY3U(req->vdr_class, ==, VDC_IOAPIC);
	VERIFY3U(req->vdr_version, ==, 1);
	VERIFY3U(req->vdr_len, >=, sizeof (struct vdi_ioapic_v1));

	struct vioapic *vioapic = datap;
	struct vdi_ioapic_v1 *out = req->vdr_data;

	VIOAPIC_LOCK(vioapic);
	out->vi_id = vioapic->id;
	out->vi_reg_sel = vioapic->ioregsel;
	for (uint_t i = 0; i < REDIR_ENTRIES; i++) {
		out->vi_pin_reg[i] = vioapic->rtbl[i].reg;
		out->vi_pin_level[i] = vioapic->rtbl[i].acnt;
	}
	VIOAPIC_UNLOCK(vioapic);

	return (0);
}

static int
vioapic_data_write(void *datap, const vmm_data_req_t *req)
{
	VERIFY3U(req->vdr_class, ==, VDC_IOAPIC);
	VERIFY3U(req->vdr_version, ==, 1);
	VERIFY3U(req->vdr_len, >=, sizeof (struct vdi_ioapic_v1));

	struct vioapic *vioapic = datap;
	const struct vdi_ioapic_v1 *src = req->vdr_data;

	VIOAPIC_LOCK(vioapic);
	vioapic->id = src->vi_id;
	vioapic->ioregsel = src->vi_reg_sel;
	for (uint_t i = 0; i < REDIR_ENTRIES; i++) {
		vioapic->rtbl[i].reg = src->vi_pin_reg[i] & ~RTBL_RO_BITS;
		vioapic->rtbl[i].acnt = src->vi_pin_level[i];
	}
	VIOAPIC_UNLOCK(vioapic);

	return (0);
}

static const vmm_data_version_entry_t ioapic_v1 = {
	.vdve_class = VDC_IOAPIC,
	.vdve_version = 1,
	.vdve_len_expect = sizeof (struct vdi_ioapic_v1),
	.vdve_readf = vioapic_data_read,
	.vdve_writef = vioapic_data_write,
};
VMM_DATA_VERSION(ioapic_v1);
