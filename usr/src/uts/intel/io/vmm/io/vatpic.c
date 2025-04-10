/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2014 Tycho Nightingale <tycho.nightingale@pluribusnetworks.com>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
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

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/kernel.h>
#include <sys/kmem.h>
#include <sys/mutex.h>
#include <sys/systm.h>

#include <x86/apicreg.h>
#include <dev/ic/i8259.h>

#include <machine/vmm.h>

#include "vmm_lapic.h"
#include "vioapic.h"
#include "vatpic.h"

#define	VATPIC_LOCK(vatpic)		mutex_enter(&((vatpic)->lock))
#define	VATPIC_UNLOCK(vatpic)		mutex_exit(&((vatpic)->lock))
#define	VATPIC_LOCKED(vatpic)		MUTEX_HELD(&((vatpic)->lock))

#define	IRQ_BASE_MASK	0xf8

enum irqstate {
	IRQSTATE_ASSERT,
	IRQSTATE_DEASSERT,
	IRQSTATE_PULSE
};

enum icw_state {
	IS_ICW1 = 0,
	IS_ICW2,
	IS_ICW3,
	IS_ICW4,
};

struct atpic {
	enum icw_state	icw_state;

	bool		ready;
	bool		auto_eoi;
	bool		poll;
	bool		rotate;
	bool		special_full_nested;
	bool		read_isr_next;
	bool		intr_raised;
	bool		special_mask_mode;

	uint8_t		reg_irr;	/* Interrupt Request Register (IIR) */
	uint8_t		reg_isr;	/* Interrupt Service (ISR) */
	uint8_t		reg_imr;	/* Interrupt Mask Register (IMR) */
	uint8_t		irq_base;	/* base interrupt vector */
	uint8_t		lowprio;	/* lowest priority irq */
	uint8_t		elc;		/* level-triggered mode bits */

	uint_t		acnt[8];	/* sum of pin asserts and deasserts */
};

struct atpic_stats {
	uint64_t	as_interrupts;
	uint64_t	as_saturate_low;
	uint64_t	as_saturate_high;
};

struct vatpic {
	struct vm	*vm;
	kmutex_t	lock;
	struct atpic	atpic[2];
	struct atpic_stats stats;
};

/*
 * Loop over all the pins in priority order from highest to lowest.
 */
#define	ATPIC_PIN_FOREACH(pinvar, atpic, tmpvar)			\
	for (tmpvar = 0, pinvar = (atpic->lowprio + 1) & 0x7;		\
	    tmpvar < 8;							\
	    tmpvar++, pinvar = (pinvar + 1) & 0x7)

static int vatpic_set_pinstate(struct vatpic *vatpic, int pin, bool newstate);

static __inline bool
master_atpic(struct vatpic *vatpic, struct atpic *atpic)
{

	if (atpic == &vatpic->atpic[0])
		return (true);
	else
		return (false);
}

static __inline int
vatpic_get_highest_isrpin(struct atpic *atpic)
{
	int bit, pin;
	int i;

	ATPIC_PIN_FOREACH(pin, atpic, i) {
		bit = (1 << pin);

		if (atpic->reg_isr & bit) {
			/*
			 * An IS bit that is masked by an IMR bit will not be
			 * cleared by a non-specific EOI in Special Mask Mode.
			 */
			if (atpic->special_mask_mode &&
			    (atpic->reg_imr & bit) != 0) {
				continue;
			} else {
				return (pin);
			}
		}
	}

	return (-1);
}

static __inline int
vatpic_get_highest_irrpin(struct atpic *atpic)
{
	int serviced;
	int bit, pin, tmp;

	/*
	 * In 'Special Fully-Nested Mode' when an interrupt request from
	 * a slave is in service, the slave is not locked out from the
	 * master's priority logic.
	 */
	serviced = atpic->reg_isr;
	if (atpic->special_full_nested)
		serviced &= ~(1 << 2);

	/*
	 * In 'Special Mask Mode', when a mask bit is set in OCW1 it inhibits
	 * further interrupts at that level and enables interrupts from all
	 * other levels that are not masked. In other words the ISR has no
	 * bearing on the levels that can generate interrupts.
	 */
	if (atpic->special_mask_mode)
		serviced = 0;

	ATPIC_PIN_FOREACH(pin, atpic, tmp) {
		bit = 1 << pin;

		/*
		 * If there is already an interrupt in service at the same
		 * or higher priority then bail.
		 */
		if ((serviced & bit) != 0)
			break;

		/*
		 * If an interrupt is asserted and not masked then return
		 * the corresponding 'pin' to the caller.
		 */
		if ((atpic->reg_irr & bit) != 0 && (atpic->reg_imr & bit) == 0)
			return (pin);
	}

	return (-1);
}

static void
vatpic_notify_intr(struct vatpic *vatpic)
{
	struct atpic *atpic;
	int pin;

	ASSERT(VATPIC_LOCKED(vatpic));

	/*
	 * First check the slave.
	 */
	atpic = &vatpic->atpic[1];
	if (!atpic->intr_raised &&
	    (pin = vatpic_get_highest_irrpin(atpic)) != -1) {
		/*
		 * Cascade the request from the slave to the master.
		 */
		atpic->intr_raised = true;
		if (vatpic_set_pinstate(vatpic, 2, true) == 0) {
			(void) vatpic_set_pinstate(vatpic, 2, false);
		}
	} else {
		/* No eligible interrupts on slave chip */
	}

	/*
	 * Then check the master.
	 */
	atpic = &vatpic->atpic[0];
	if (!atpic->intr_raised &&
	    (pin = vatpic_get_highest_irrpin(atpic)) != -1) {
		/*
		 * From Section 3.6.2, "Interrupt Modes", in the
		 * MPtable Specification, Version 1.4
		 *
		 * PIC interrupts are routed to both the Local APIC
		 * and the I/O APIC to support operation in 1 of 3
		 * modes.
		 *
		 * 1. Legacy PIC Mode: the PIC effectively bypasses
		 * all APIC components.  In this mode the local APIC is
		 * disabled and LINT0 is reconfigured as INTR to
		 * deliver the PIC interrupt directly to the CPU.
		 *
		 * 2. Virtual Wire Mode: the APIC is treated as a
		 * virtual wire which delivers interrupts from the PIC
		 * to the CPU.  In this mode LINT0 is programmed as
		 * ExtINT to indicate that the PIC is the source of
		 * the interrupt.
		 *
		 * 3. Virtual Wire Mode via I/O APIC: PIC interrupts are
		 * fielded by the I/O APIC and delivered to the appropriate
		 * CPU.  In this mode the I/O APIC input 0 is programmed
		 * as ExtINT to indicate that the PIC is the source of the
		 * interrupt.
		 */
		atpic->intr_raised = true;
		(void) lapic_set_local_intr(vatpic->vm, -1, APIC_LVT_LINT0);
		(void) vioapic_pulse_irq(vatpic->vm, 0);
		vatpic->stats.as_interrupts++;
	} else {
		/* No eligible interrupts on master chip */
	}
}

static int
vatpic_icw1(struct vatpic *vatpic, struct atpic *atpic, uint8_t val)
{
	atpic->ready = false;

	atpic->icw_state = IS_ICW1;
	atpic->reg_irr = 0;
	atpic->reg_imr = 0;
	atpic->lowprio = 7;
	atpic->read_isr_next = false;
	atpic->poll = false;
	atpic->special_mask_mode = false;

	if ((val & ICW1_SNGL) != 0) {
		/* Cascade mode reqired */
		return (-1);
	}

	if ((val & ICW1_IC4) == 0) {
		/* ICW4 reqired */
		return (-1);
	}

	atpic->icw_state = IS_ICW2;

	return (0);
}

static int
vatpic_icw2(struct vatpic *vatpic, struct atpic *atpic, uint8_t val)
{
	atpic->irq_base = val & IRQ_BASE_MASK;
	atpic->icw_state = IS_ICW3;

	return (0);
}

static int
vatpic_icw3(struct vatpic *vatpic, struct atpic *atpic, uint8_t val)
{
	atpic->icw_state = IS_ICW4;

	return (0);
}

static int
vatpic_icw4(struct vatpic *vatpic, struct atpic *atpic, uint8_t val)
{
	if ((val & ICW4_8086) == 0) {
		/* Microprocessor mode required */
		return (-1);
	}

	atpic->auto_eoi = (val & ICW4_AEOI) != 0;
	if (master_atpic(vatpic, atpic)) {
		atpic->special_full_nested = (val & ICW4_SFNM) != 0;
	}

	atpic->icw_state = IS_ICW1;
	atpic->ready = true;

	return (0);
}

static int
vatpic_ocw1(struct vatpic *vatpic, struct atpic *atpic, uint8_t val)
{
	atpic->reg_imr = val;

	return (0);
}

static int
vatpic_ocw2(struct vatpic *vatpic, struct atpic *atpic, uint8_t val)
{
	atpic->rotate = (val & OCW2_R) != 0;

	if ((val & OCW2_EOI) != 0) {
		int isr_bit;

		if ((val & OCW2_SL) != 0) {
			/* specific EOI */
			isr_bit = val & 0x7;
		} else {
			/* non-specific EOI */
			isr_bit = vatpic_get_highest_isrpin(atpic);
		}

		if (isr_bit != -1) {
			atpic->reg_isr &= ~(1 << isr_bit);

			if (atpic->rotate)
				atpic->lowprio = isr_bit;
		}
	} else if ((val & OCW2_SL) != 0 && atpic->rotate) {
		/* specific priority */
		atpic->lowprio = val & 0x7;
	}

	return (0);
}

static int
vatpic_ocw3(struct vatpic *vatpic, struct atpic *atpic, uint8_t val)
{
	if ((val & OCW3_ESMM) != 0) {
		atpic->special_mask_mode = (val & OCW3_SMM) != 0;
	}
	if ((val & OCW3_RR) != 0) {
		atpic->read_isr_next = (val & OCW3_RIS) != 0;
	}
	if ((val & OCW3_P) != 0) {
		atpic->poll = true;
	}

	return (0);
}

static int
vatpic_set_pinstate(struct vatpic *vatpic, int pin, bool newstate)
{
	struct atpic *atpic;
	uint_t oldcnt, newcnt;
	int err = 0;

	VERIFY(pin >= 0 && pin < 16);
	ASSERT(VATPIC_LOCKED(vatpic));

	const int lpin = pin & 0x7;
	atpic = &vatpic->atpic[pin >> 3];

	oldcnt = newcnt = atpic->acnt[lpin];
	if (newstate) {
		if (newcnt != UINT_MAX) {
			newcnt++;
		} else {
			err = E2BIG;
			DTRACE_PROBE2(vatpic__sat_high, struct vatpic *, vatpic,
			    int, pin);
			vatpic->stats.as_saturate_high++;
		}
	} else {
		if (newcnt != 0) {
			newcnt--;
		} else {
			err = ERANGE;
			DTRACE_PROBE2(vatpic__sat_low, struct vatpic *, vatpic,
			    int, pin);
			vatpic->stats.as_saturate_low++;
		}
	}
	atpic->acnt[lpin] = newcnt;

	const bool level = ((atpic->elc & (1 << (lpin))) != 0);
	if ((oldcnt == 0 && newcnt == 1) || (newcnt > 0 && level == true)) {
		/* rising edge or level */
		DTRACE_PROBE2(vatpic__assert, struct vatpic *, vatpic,
		    int, pin);
		atpic->reg_irr |= (1 << lpin);
	} else if (oldcnt == 1 && newcnt == 0) {
		/* falling edge */
		DTRACE_PROBE2(vatpic__deassert, struct vatpic *, vatpic,
		    int, pin);
		if (level) {
			atpic->reg_irr &= ~(1 << lpin);
		}
	}

	vatpic_notify_intr(vatpic);
	return (err);
}

static int
vatpic_set_irqstate(struct vm *vm, int irq, enum irqstate irqstate)
{
	struct vatpic *vatpic;
	struct atpic *atpic;
	int err = 0;

	if (irq < 0 || irq > 15)
		return (EINVAL);

	vatpic = vm_atpic(vm);
	atpic = &vatpic->atpic[irq >> 3];

	if (!atpic->ready)
		return (0);

	VATPIC_LOCK(vatpic);
	switch (irqstate) {
	case IRQSTATE_ASSERT:
		err = vatpic_set_pinstate(vatpic, irq, true);
		break;
	case IRQSTATE_DEASSERT:
		err = vatpic_set_pinstate(vatpic, irq, false);
		break;
	case IRQSTATE_PULSE:
		err = vatpic_set_pinstate(vatpic, irq, true);
		if (err == 0) {
			err = vatpic_set_pinstate(vatpic, irq, false);
		}
		break;
	default:
		panic("vatpic_set_irqstate: invalid irqstate %d", irqstate);
	}
	VATPIC_UNLOCK(vatpic);

	return (err);
}

int
vatpic_assert_irq(struct vm *vm, int irq)
{
	return (vatpic_set_irqstate(vm, irq, IRQSTATE_ASSERT));
}

int
vatpic_deassert_irq(struct vm *vm, int irq)
{
	return (vatpic_set_irqstate(vm, irq, IRQSTATE_DEASSERT));
}

int
vatpic_pulse_irq(struct vm *vm, int irq)
{
	return (vatpic_set_irqstate(vm, irq, IRQSTATE_PULSE));
}

int
vatpic_set_irq_trigger(struct vm *vm, int irq, enum vm_intr_trigger trigger)
{
	if (irq < 0 || irq > 15)
		return (EINVAL);

	/*
	 * See comments in vatpic_elc_handler.
	 * These IRQs must be edge triggered.
	 */
	if (trigger == LEVEL_TRIGGER) {
		switch (irq) {
		case 0:
		case 1:
		case 2:
		case 8:
		case 13:
			return (EINVAL);
		}
	}

	struct vatpic *vatpic = vm_atpic(vm);
	struct atpic *atpic = &vatpic->atpic[irq >> 3];
	const int pin = irq & 0x7;

	VATPIC_LOCK(vatpic);
	if (trigger == LEVEL_TRIGGER) {
		atpic->elc |= (1 << pin);
	} else {
		atpic->elc &= ~(1 << pin);
	}
	VATPIC_UNLOCK(vatpic);

	return (0);
}

void
vatpic_pending_intr(struct vm *vm, int *vecptr)
{
	struct vatpic *vatpic;
	struct atpic *atpic;
	int pin;

	vatpic = vm_atpic(vm);

	atpic = &vatpic->atpic[0];

	VATPIC_LOCK(vatpic);

	pin = vatpic_get_highest_irrpin(atpic);
	if (pin == 2) {
		atpic = &vatpic->atpic[1];
		pin = vatpic_get_highest_irrpin(atpic);
	}

	/*
	 * If there are no pins active at this moment then return the spurious
	 * interrupt vector instead.
	 */
	if (pin == -1)
		pin = 7;

	KASSERT(pin >= 0 && pin <= 7, ("%s: invalid pin %d", __func__, pin));
	*vecptr = atpic->irq_base + pin;

	VATPIC_UNLOCK(vatpic);
}

static void
vatpic_pin_accepted(struct atpic *atpic, int pin)
{
	ASSERT(pin >= 0 && pin < 8);

	atpic->intr_raised = false;

	if (atpic->acnt[pin] == 0)
		atpic->reg_irr &= ~(1 << pin);

	if (atpic->auto_eoi) {
		if (atpic->rotate)
			atpic->lowprio = pin;
	} else {
		atpic->reg_isr |= (1 << pin);
	}
}

void
vatpic_intr_accepted(struct vm *vm, int vector)
{
	struct vatpic *vatpic;
	int pin;

	vatpic = vm_atpic(vm);

	VATPIC_LOCK(vatpic);

	pin = vector & 0x7;

	if ((vector & IRQ_BASE_MASK) == vatpic->atpic[1].irq_base) {
		vatpic_pin_accepted(&vatpic->atpic[1], pin);
		/*
		 * If this vector originated from the slave,
		 * accept the cascaded interrupt too.
		 */
		vatpic_pin_accepted(&vatpic->atpic[0], 2);
	} else {
		vatpic_pin_accepted(&vatpic->atpic[0], pin);
	}

	vatpic_notify_intr(vatpic);

	VATPIC_UNLOCK(vatpic);
}

static int
vatpic_read(struct vatpic *vatpic, struct atpic *atpic, bool in, int port,
    int bytes, uint32_t *eax)
{
	int pin;

	VATPIC_LOCK(vatpic);

	if (atpic->poll) {
		atpic->poll = false;
		pin = vatpic_get_highest_irrpin(atpic);
		if (pin >= 0) {
			vatpic_pin_accepted(atpic, pin);
			*eax = 0x80 | pin;
		} else {
			*eax = 0;
		}
	} else {
		if (port & ICU_IMR_OFFSET) {
			/* read interrrupt mask register */
			*eax = atpic->reg_imr;
		} else {
			if (atpic->read_isr_next) {
				/* read interrupt service register */
				*eax = atpic->reg_isr;
			} else {
				/* read interrupt request register */
				*eax = atpic->reg_irr;
			}
		}
	}

	VATPIC_UNLOCK(vatpic);

	return (0);

}

static int
vatpic_write(struct vatpic *vatpic, struct atpic *atpic, bool in, int port,
    int bytes, uint32_t *eax)
{
	int error;
	uint8_t val;

	error = 0;
	val = *eax;

	VATPIC_LOCK(vatpic);

	if (port & ICU_IMR_OFFSET) {
		switch (atpic->icw_state) {
		case IS_ICW2:
			error = vatpic_icw2(vatpic, atpic, val);
			break;
		case IS_ICW3:
			error = vatpic_icw3(vatpic, atpic, val);
			break;
		case IS_ICW4:
			error = vatpic_icw4(vatpic, atpic, val);
			break;
		default:
			error = vatpic_ocw1(vatpic, atpic, val);
			break;
		}
	} else {
		if (val & (1 << 4))
			error = vatpic_icw1(vatpic, atpic, val);

		if (atpic->ready) {
			if (val & (1 << 3))
				error = vatpic_ocw3(vatpic, atpic, val);
			else
				error = vatpic_ocw2(vatpic, atpic, val);
		}
	}

	if (atpic->ready)
		vatpic_notify_intr(vatpic);

	VATPIC_UNLOCK(vatpic);

	return (error);
}

int
vatpic_master_handler(void *arg, bool in, uint16_t port, uint8_t bytes,
    uint32_t *eax)
{
	struct vatpic *vatpic = arg;
	struct atpic *atpic = &vatpic->atpic[0];

	if (bytes != 1)
		return (-1);

	if (in) {
		return (vatpic_read(vatpic, atpic, in, port, bytes, eax));
	}

	return (vatpic_write(vatpic, atpic, in, port, bytes, eax));
}

int
vatpic_slave_handler(void *arg, bool in, uint16_t port, uint8_t bytes,
    uint32_t *eax)
{
	struct vatpic *vatpic = arg;
	struct atpic *atpic = &vatpic->atpic[1];

	if (bytes != 1)
		return (-1);

	if (in) {
		return (vatpic_read(vatpic, atpic, in, port, bytes, eax));
	}

	return (vatpic_write(vatpic, atpic, in, port, bytes, eax));
}

static const uint8_t vatpic_elc_mask[2] = {
	/*
	 * For the master PIC the cascade channel (IRQ2), the heart beat timer
	 * (IRQ0), and the keyboard controller (IRQ1) cannot be programmed for
	 * level mode.
	 */
	0xf8,
	/*
	 * For the slave PIC the real time clock (IRQ8) and the floating point
	 * error interrupt (IRQ13) cannot be programmed for level mode.
	 */
	0xde
};

int
vatpic_elc_handler(void *arg, bool in, uint16_t port, uint8_t bytes,
    uint32_t *eax)
{
	struct vatpic *vatpic = arg;
	struct atpic *atpic = NULL;
	uint8_t elc_mask = 0;

	switch (port) {
	case IO_ELCR1:
		atpic = &vatpic->atpic[0];
		elc_mask = vatpic_elc_mask[0];
		break;
	case IO_ELCR2:
		atpic = &vatpic->atpic[1];
		elc_mask = vatpic_elc_mask[1];
		break;
	default:
		return (-1);
	}

	if (bytes != 1)
		return (-1);

	VATPIC_LOCK(vatpic);
	if (in) {
		*eax = atpic->elc;
	} else {
		atpic->elc = *eax & elc_mask;
	}
	VATPIC_UNLOCK(vatpic);

	return (0);
}

struct vatpic *
vatpic_init(struct vm *vm)
{
	struct vatpic *vatpic;

	vatpic = kmem_zalloc(sizeof (struct vatpic), KM_SLEEP);
	vatpic->vm = vm;

	mutex_init(&vatpic->lock, NULL, MUTEX_ADAPTIVE, NULL);

	return (vatpic);
}

void
vatpic_cleanup(struct vatpic *vatpic)
{
	mutex_destroy(&vatpic->lock);
	kmem_free(vatpic, sizeof (*vatpic));
}

static int
vatpic_data_read(void *datap, const vmm_data_req_t *req)
{
	VERIFY3U(req->vdr_class, ==, VDC_ATPIC);
	VERIFY3U(req->vdr_version, ==, 1);
	VERIFY3U(req->vdr_len, >=, sizeof (struct vdi_atpic_v1));

	struct vatpic *vatpic = datap;
	struct vdi_atpic_v1 *out = req->vdr_data;

	VATPIC_LOCK(vatpic);
	for (uint_t i = 0; i < 2; i++) {
		const struct atpic *src = &vatpic->atpic[i];
		struct vdi_atpic_chip_v1 *chip = &out->va_chip[i];

		chip->vac_icw_state = src->icw_state;
		chip->vac_status =
		    (src->ready ? (1 << 0) : 0) |
		    (src->auto_eoi ? (1 << 1) : 0) |
		    (src->poll ? (1 << 2) : 0) |
		    (src->rotate ? (1 << 3) : 0) |
		    (src->special_full_nested ? (1 << 4) : 0) |
		    (src->read_isr_next ? (1 << 5) : 0) |
		    (src->intr_raised ? (1 << 6) : 0) |
		    (src->special_mask_mode ? (1 << 7) : 0);
		chip->vac_reg_irr = src->reg_irr;
		chip->vac_reg_isr = src->reg_isr;
		chip->vac_reg_imr = src->reg_imr;
		chip->vac_irq_base = src->irq_base;
		chip->vac_lowprio = src->lowprio;
		chip->vac_elc = src->elc;
		for (uint_t j = 0; j < 8; j++) {
			chip->vac_level[j] = src->acnt[j];
		}
	}
	VATPIC_UNLOCK(vatpic);

	return (0);
}

static bool
vatpic_data_validate(const struct vdi_atpic_v1 *src)
{
	for (uint_t i = 0; i < 2; i++) {
		const struct vdi_atpic_chip_v1 *chip = &src->va_chip[i];

		if (chip->vac_icw_state > IS_ICW4) {
			return (false);
		}
		if ((chip->vac_elc & ~vatpic_elc_mask[i]) != 0) {
			return (false);
		}
		/*
		 * TODO: The state of `intr_raised` could be checked what
		 * resides in the ISR/IRR registers.
		 */
	}

	return (true);
}

static int
vatpic_data_write(void *datap, const vmm_data_req_t *req)
{
	VERIFY3U(req->vdr_class, ==, VDC_ATPIC);
	VERIFY3U(req->vdr_version, ==, 1);
	VERIFY3U(req->vdr_len, >=, sizeof (struct vdi_atpic_v1));

	struct vatpic *vatpic = datap;
	const struct vdi_atpic_v1 *src = req->vdr_data;
	if (!vatpic_data_validate(src)) {
		return (EINVAL);
	}

	VATPIC_LOCK(vatpic);
	for (uint_t i = 0; i < 2; i++) {
		const struct vdi_atpic_chip_v1 *chip = &src->va_chip[i];
		struct atpic *out = &vatpic->atpic[i];

		out->icw_state = chip->vac_icw_state;

		out->ready = (chip->vac_status & (1 << 0)) != 0;
		out->auto_eoi = (chip->vac_status & (1 << 1)) != 0;
		out->poll = (chip->vac_status & (1 << 2)) != 0;
		out->rotate = (chip->vac_status & (1 << 3)) != 0;
		out->special_full_nested = (chip->vac_status & (1 << 4)) != 0;
		out->read_isr_next = (chip->vac_status & (1 << 5)) != 0;
		out->intr_raised = (chip->vac_status & (1 << 6)) != 0;
		out->special_mask_mode = (chip->vac_status & (1 << 7)) != 0;

		out->reg_irr = chip->vac_reg_irr;
		out->reg_isr = chip->vac_reg_isr;
		out->reg_imr = chip->vac_reg_imr;
		out->irq_base = chip->vac_irq_base;
		out->lowprio = chip->vac_lowprio;
		out->elc = chip->vac_elc;
		for (uint_t j = 0; j < 8; j++) {
			out->acnt[j] = chip->vac_level[j];
		}
	}
	VATPIC_UNLOCK(vatpic);

	return (0);
}

static const vmm_data_version_entry_t atpic_v1 = {
	.vdve_class = VDC_ATPIC,
	.vdve_version = 1,
	.vdve_len_expect = sizeof (struct vdi_atpic_v1),
	.vdve_readf = vatpic_data_read,
	.vdve_writef = vatpic_data_write,
};
VMM_DATA_VERSION(atpic_v1);
