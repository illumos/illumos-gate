/*-
 * Copyright (c) 2018 Joyent, Inc.
 * Copyright (c) 2014 Tycho Nightingale <tycho.nightingale@pluribusnetworks.com>
 * Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
 * Copyright (c) 2018 Joyent, Inc.
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/systm.h>

#include <machine/vmm.h>

#include "vmm_ktr.h"
#include "vatpic.h"
#include "vioapic.h"
#include "vatpit.h"

static MALLOC_DEFINE(M_VATPIT, "atpit", "bhyve virtual atpit (8254)");

#define	VATPIT_LOCK(vatpit)		mtx_lock_spin(&((vatpit)->mtx))
#define	VATPIT_UNLOCK(vatpit)		mtx_unlock_spin(&((vatpit)->mtx))
#define	VATPIT_LOCKED(vatpit)		mtx_owned(&((vatpit)->mtx))

#define	TIMER_SEL_MASK		0xc0
#define	TIMER_RW_MASK		0x30
#define	TIMER_MODE_MASK		0x0f
#define	TIMER_SEL_READBACK	0xc0

#define	TIMER_STS_OUT		0x80
#define	TIMER_STS_NULLCNT	0x40

#define	TIMER_RB_LCTR		0x20
#define	TIMER_RB_LSTATUS	0x10
#define	TIMER_RB_CTR_2		0x08
#define	TIMER_RB_CTR_1		0x04
#define	TIMER_RB_CTR_0		0x02

#define	TMR2_OUT_STS		0x20

#define	PIT_8254_FREQ		1193182
#define	TIMER_DIV(freq, hz)	(((freq) + (hz) / 2) / (hz))

struct vatpit_callout_arg {
	struct vatpit	*vatpit;
	int		channel_num;
};

struct channel {
	uint8_t		mode;
	uint16_t	initial;	/* initial counter value */

	uint8_t		reg_cr[2];
	uint8_t		reg_ol[2];
	uint8_t		reg_status;

	bool		slatched;	/* status latched */
	bool		olatched;	/* output latched */
	bool		cr_sel;		/* read MSB from control register */
	bool		ol_sel;		/* read MSB from output latch */
	bool		fr_sel;		/* read MSB from free-running timer */

	struct bintime	load_bt;	/* time when counter was loaded */
	struct bintime	callout_bt;	/* target time */

	struct callout	callout;
	struct vatpit_callout_arg callout_arg;
};

struct vatpit {
	struct vm	*vm;
	struct mtx	mtx;

	struct bintime	freq_bt;

	struct channel	channel[3];
};

static void pit_timer_start_cntr0(struct vatpit *vatpit);

static uint64_t
vatpit_delta_ticks(struct vatpit *vatpit, struct channel *c)
{
	struct bintime delta;
	uint64_t result;

	binuptime(&delta);
	bintime_sub(&delta, &c->load_bt);

	result = delta.sec * PIT_8254_FREQ;
	result += delta.frac / vatpit->freq_bt.frac;

	return (result);
}

static int
vatpit_get_out(struct vatpit *vatpit, int channel)
{
	struct channel *c;
	uint64_t delta_ticks;
	int out;

	c = &vatpit->channel[channel];

	switch (c->mode) {
	case TIMER_INTTC:
		delta_ticks = vatpit_delta_ticks(vatpit, c);
		out = (delta_ticks >= c->initial);
		break;
	default:
		out = 0;
		break;
	}

	return (out);
}

static void
vatpit_callout_handler(void *a)
{
	struct vatpit_callout_arg *arg = a;
	struct vatpit *vatpit;
	struct callout *callout;
	struct channel *c;

	vatpit = arg->vatpit;
	c = &vatpit->channel[arg->channel_num];
	callout = &c->callout;

	VM_CTR1(vatpit->vm, "atpit t%d fired", arg->channel_num);

	VATPIT_LOCK(vatpit);

	if (callout_pending(callout))		/* callout was reset */
		goto done;

	if (!callout_active(callout))		/* callout was stopped */
		goto done;

	callout_deactivate(callout);

	if (c->mode == TIMER_RATEGEN || c->mode == TIMER_SQWAVE) {
		pit_timer_start_cntr0(vatpit);
	}

	vatpic_pulse_irq(vatpit->vm, 0);
	vioapic_pulse_irq(vatpit->vm, 2);

done:
	VATPIT_UNLOCK(vatpit);
}

static void
pit_timer_start_cntr0(struct vatpit *vatpit)
{
	struct channel *c;
	struct bintime now, delta;
	sbintime_t precision;

	c = &vatpit->channel[0];
	if (c->initial != 0) {
		delta.sec = 0;
		delta.frac = vatpit->freq_bt.frac * c->initial;
		bintime_add(&c->callout_bt, &delta);
		precision = bttosbt(delta) >> tc_precexp;

		/*
		 * Reset 'callout_bt' if the time that the callout
		 * was supposed to fire is more than 'c->initial'
		 * ticks in the past.
		 */
		binuptime(&now);
		if (BINTIME_CMP(&c->callout_bt, <, &now)) {
			c->callout_bt = now;
			bintime_add(&c->callout_bt, &delta);
		}

		callout_reset_sbt(&c->callout, bttosbt(c->callout_bt),
		    precision, vatpit_callout_handler, &c->callout_arg,
		    C_ABSOLUTE);
	}
}

static uint16_t
pit_update_counter(struct vatpit *vatpit, struct channel *c, bool latch)
{
	uint16_t lval;
	uint64_t delta_ticks;

	/* cannot latch a new value until the old one has been consumed */
	if (latch && c->olatched)
		return (0);

	if (c->initial == 0) {
		/*
		 * This is possibly an o/s bug - reading the value of
		 * the timer without having set up the initial value.
		 *
		 * The original user-space version of this code set
		 * the timer to 100hz in this condition; do the same
		 * here.
		 */
		c->initial = TIMER_DIV(PIT_8254_FREQ, 100);
		binuptime(&c->load_bt);
		c->reg_status &= ~TIMER_STS_NULLCNT;
	}

	delta_ticks = vatpit_delta_ticks(vatpit, c);
	lval = c->initial - delta_ticks % c->initial;

	if (latch) {
		c->olatched = true;
		c->ol_sel = true;
		c->reg_ol[1] = lval;		/* LSB */
		c->reg_ol[0] = lval >> 8;	/* MSB */
	}

	return (lval);
}

static int
pit_readback1(struct vatpit *vatpit, int channel, uint8_t cmd)
{
	struct channel *c;

	c = &vatpit->channel[channel];

	/*
	 * Latch the count/status of the timer if not already latched.
	 * N.B. that the count/status latch-select bits are active-low.
	 */
	if ((cmd & TIMER_RB_LCTR) == 0 && !c->olatched) {
		(void) pit_update_counter(vatpit, c, true);
	}

	if ((cmd & TIMER_RB_LSTATUS) == 0 && !c->slatched) {
		c->slatched = true;
		/*
		 * For mode 0, see if the elapsed time is greater
		 * than the initial value - this results in the
		 * output pin being set to 1 in the status byte.
		 */
		if (c->mode == TIMER_INTTC && vatpit_get_out(vatpit, channel))
			c->reg_status |= TIMER_STS_OUT;
		else
			c->reg_status &= ~TIMER_STS_OUT;
	}

	return (0);
}

static int
pit_readback(struct vatpit *vatpit, uint8_t cmd)
{
	int error;

	/*
	 * The readback command can apply to all timers.
	 */
	error = 0;
	if (cmd & TIMER_RB_CTR_0)
		error = pit_readback1(vatpit, 0, cmd);
	if (!error && cmd & TIMER_RB_CTR_1)
		error = pit_readback1(vatpit, 1, cmd);
	if (!error && cmd & TIMER_RB_CTR_2)
		error = pit_readback1(vatpit, 2, cmd);

	return (error);
}

static int
vatpit_update_mode(struct vatpit *vatpit, uint8_t val)
{
	struct channel *c;
	int sel, rw;
	uint8_t mode;

	sel = val & TIMER_SEL_MASK;
	rw = val & TIMER_RW_MASK;
	mode = val & TIMER_MODE_MASK;

	/* Clear don't-care bit (M2) when M1 is set */
	if ((mode & TIMER_RATEGEN) != 0) {
		mode &= ~TIMER_SWSTROBE;
	}

	if (sel == TIMER_SEL_READBACK)
		return (pit_readback(vatpit, val));

	if (rw != TIMER_LATCH && rw != TIMER_16BIT)
		return (-1);

	if (rw != TIMER_LATCH) {
		/*
		 * Counter mode is not affected when issuing a
		 * latch command.
		 */
		if (mode != TIMER_INTTC &&
		    mode != TIMER_RATEGEN &&
		    mode != TIMER_SQWAVE &&
		    mode != TIMER_SWSTROBE)
			return (-1);
	}

	c = &vatpit->channel[sel >> 6];
	if (rw == TIMER_LATCH) {
		pit_update_counter(vatpit, c, true);
	} else {
		c->mode = mode;
		c->olatched = false;	/* reset latch after reprogramming */
		c->reg_status |= TIMER_STS_NULLCNT;
	}

	return (0);
}

int
vatpit_handler(void *arg, bool in, uint16_t port, uint8_t bytes, uint32_t *eax)
{
	struct vatpit *vatpit = arg;
	struct channel *c;
	uint8_t val;
	int error;

	if (bytes != 1)
		return (-1);

	val = *eax;

	if (port == TIMER_MODE) {
		if (in) {
			VM_CTR0(vatpit->vm, "vatpit attempt to read mode");
			return (-1);
		}

		VATPIT_LOCK(vatpit);
		error = vatpit_update_mode(vatpit, val);
		VATPIT_UNLOCK(vatpit);

		return (error);
	}

	/* counter ports */
	KASSERT(port >= TIMER_CNTR0 && port <= TIMER_CNTR2,
	    ("invalid port 0x%x", port));
	c = &vatpit->channel[port - TIMER_CNTR0];

	VATPIT_LOCK(vatpit);
	if (in && c->slatched) {
		/* Return the status byte if latched */
		*eax = c->reg_status;
		c->slatched = false;
		c->reg_status = 0;
	} else if (in) {
		/*
		 * The spec says that once the output latch is completely
		 * read it should revert to "following" the counter. Use
		 * the free running counter for this case (i.e. Linux
		 * TSC calibration). Assuming the access mode is 16-bit,
		 * toggle the MSB/LSB bit on each read.
		 */
		if (!c->olatched) {
			uint16_t tmp;

			tmp = pit_update_counter(vatpit, c, false);
			if (c->fr_sel) {
				tmp >>= 8;
			}
			tmp &= 0xff;
			*eax = tmp;
			c->fr_sel = !c->fr_sel;
		} else {
			if (c->ol_sel) {
				*eax = c->reg_ol[1];
				c->ol_sel = false;
			} else {
				*eax = c->reg_ol[0];
				c->olatched = false;
			}
		}
	} else {
		if (!c->cr_sel) {
			c->reg_cr[0] = *eax;
			c->cr_sel = true;
		} else {
			c->reg_cr[1] = *eax;
			c->cr_sel = false;

			c->reg_status &= ~TIMER_STS_NULLCNT;
			c->fr_sel = false;
			c->initial = c->reg_cr[0] | (uint16_t)c->reg_cr[1] << 8;
			binuptime(&c->load_bt);
			/* Start an interval timer for channel 0 */
			if (port == TIMER_CNTR0) {
				c->callout_bt = c->load_bt;
				pit_timer_start_cntr0(vatpit);
			}
			if (c->initial == 0)
				c->initial = 0xffff;
		}
	}
	VATPIT_UNLOCK(vatpit);

	return (0);
}

int
vatpit_nmisc_handler(void *arg, bool in, uint16_t port, uint8_t bytes,
    uint32_t *eax)
{
	struct vatpit *vatpit = arg;

	if (in) {
			VATPIT_LOCK(vatpit);
			if (vatpit_get_out(vatpit, 2))
				*eax = TMR2_OUT_STS;
			else
				*eax = 0;

			VATPIT_UNLOCK(vatpit);
	}

	return (0);
}

struct vatpit *
vatpit_init(struct vm *vm)
{
	struct vatpit *vatpit;
	struct vatpit_callout_arg *arg;
	int i;

	vatpit = malloc(sizeof (struct vatpit), M_VATPIT, M_WAITOK | M_ZERO);
	vatpit->vm = vm;

	mtx_init(&vatpit->mtx, "vatpit lock", NULL, MTX_SPIN);

	FREQ2BT(PIT_8254_FREQ, &vatpit->freq_bt);

	for (i = 0; i < 3; i++) {
		callout_init(&vatpit->channel[i].callout, 1);
		arg = &vatpit->channel[i].callout_arg;
		arg->vatpit = vatpit;
		arg->channel_num = i;
	}

	return (vatpit);
}

void
vatpit_cleanup(struct vatpit *vatpit)
{
	int i;

	for (i = 0; i < 3; i++)
		callout_drain(&vatpit->channel[i].callout);

	free(vatpit, M_VATPIT);
}

void
vatpit_localize_resources(struct vatpit *vatpit)
{
	for (uint_t i = 0; i < 3; i++) {
		/* Only localize channels which might be running */
		if (vatpit->channel[i].mode != 0) {
			vmm_glue_callout_localize(&vatpit->channel[i].callout);
		}
	}
}
