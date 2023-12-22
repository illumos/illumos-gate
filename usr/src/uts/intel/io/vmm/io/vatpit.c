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
 * Copyright 2022 Oxide Computer Company
 */

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/kernel.h>
#include <sys/kmem.h>
#include <sys/mutex.h>
#include <sys/systm.h>

#include <machine/vmm.h>

#include "vatpic.h"
#include "vioapic.h"
#include "vatpit.h"

#define	VATPIT_LOCK(vatpit)		mutex_enter(&((vatpit)->lock))
#define	VATPIT_UNLOCK(vatpit)		mutex_exit(&((vatpit)->lock))
#define	VATPIT_LOCKED(vatpit)		MUTEX_HELD(&((vatpit)->lock))

#define	TIMER_SEL_MASK		0xc0
#define	TIMER_RW_MASK		0x30
#define	TIMER_MODE_MASK		0x0f
#define	TIMER_SEL_READBACK	0xc0

#define	TIMER_STS_OUT		0x80
#define	TIMER_STS_NULLCNT	0x40

#define	VALID_STATUS_BITS	(TIMER_STS_OUT | TIMER_STS_NULLCNT)

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

	hrtime_t	time_loaded;	/* time when counter was loaded */
	hrtime_t	time_target;	/* target time */
	uint64_t	total_target;

	struct callout	callout;
	struct vatpit_callout_arg callout_arg;
};

struct vatpit {
	struct vm	*vm;
	kmutex_t	lock;

	struct channel	channel[3];
};

static void pit_timer_start_cntr0(struct vatpit *vatpit);

static uint64_t
vatpit_delta_ticks(struct vatpit *vatpit, struct channel *c)
{
	const hrtime_t delta = gethrtime() - c->time_loaded;

	return (hrt_freq_count(delta, PIT_8254_FREQ));
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

	VATPIT_LOCK(vatpit);

	if (callout_pending(callout))		/* callout was reset */
		goto done;

	if (!callout_active(callout))		/* callout was stopped */
		goto done;

	callout_deactivate(callout);

	if (c->mode == TIMER_RATEGEN || c->mode == TIMER_SQWAVE) {
		pit_timer_start_cntr0(vatpit);
	} else {
		/*
		 * For non-periodic timers, clear the time target to distinguish
		 * between a fired timer (thus a zero value) and a pending one
		 * awaiting VM resumption (holding a non-zero value).
		 */
		c->time_target = 0;
	}

	(void) vatpic_pulse_irq(vatpit->vm, 0);
	(void) vioapic_pulse_irq(vatpit->vm, 2);

done:
	VATPIT_UNLOCK(vatpit);
}

static void
vatpit_callout_reset(struct vatpit *vatpit)
{
	struct channel *c = &vatpit->channel[0];

	ASSERT(VATPIT_LOCKED(vatpit));
	callout_reset_hrtime(&c->callout, c->time_target,
	    vatpit_callout_handler, &c->callout_arg, C_ABSOLUTE);
}

static void
pit_timer_start_cntr0(struct vatpit *vatpit)
{
	struct channel *c = &vatpit->channel[0];

	if (c->initial == 0) {
		return;
	}

	c->total_target += c->initial;
	c->time_target = c->time_loaded +
	    hrt_freq_interval(PIT_8254_FREQ, c->total_target);

	/*
	 * If we are more than 'c->initial' ticks behind, reset the timer base
	 * to fire at the next 'c->initial' interval boundary.
	 */
	hrtime_t now = gethrtime();
	if (c->time_target < now) {
		const uint64_t ticks_behind =
		    hrt_freq_count(now - c->time_target, PIT_8254_FREQ);

		c->total_target += roundup(ticks_behind, c->initial);
		c->time_target = c->time_loaded +
		    hrt_freq_interval(PIT_8254_FREQ, c->total_target);
	}

	vatpit_callout_reset(vatpit);
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
		 * This is possibly an OS bug - reading the value of the timer
		 * without having set up the initial value.
		 *
		 * The original user-space version of this code set the timer to
		 * 100hz in this condition; do the same here.
		 */
		c->initial = TIMER_DIV(PIT_8254_FREQ, 100);
		c->time_loaded = gethrtime();
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
		(void) pit_update_counter(vatpit, c, true);
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
			/* Mode is write-only */
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
			c->time_loaded = gethrtime();
			/* Start an interval timer for channel 0 */
			if (port == TIMER_CNTR0) {
				c->time_target = c->time_loaded;
				c->total_target = 0;
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

	vatpit = kmem_zalloc(sizeof (struct vatpit), KM_SLEEP);
	vatpit->vm = vm;

	mutex_init(&vatpit->lock, NULL, MUTEX_ADAPTIVE, NULL);

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

	mutex_destroy(&vatpit->lock);
	kmem_free(vatpit, sizeof (*vatpit));
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

void
vatpit_pause(struct vatpit *vatpit)
{
	struct channel *c = &vatpit->channel[0];

	VATPIT_LOCK(vatpit);
	callout_stop(&c->callout);
	VATPIT_UNLOCK(vatpit);
}

void
vatpit_resume(struct vatpit *vatpit)
{
	struct channel *c = &vatpit->channel[0];

	VATPIT_LOCK(vatpit);
	ASSERT(!callout_active(&c->callout));
	if (c->time_target != 0) {
		vatpit_callout_reset(vatpit);
	}
	VATPIT_UNLOCK(vatpit);
}

static int
vatpit_data_read(void *datap, const vmm_data_req_t *req)
{
	VERIFY3U(req->vdr_class, ==, VDC_ATPIT);
	VERIFY3U(req->vdr_version, ==, 1);
	VERIFY3U(req->vdr_len, >=, sizeof (struct vdi_atpit_v1));

	struct vatpit *vatpit = datap;
	struct vdi_atpit_v1 *out = req->vdr_data;

	VATPIT_LOCK(vatpit);
	for (uint_t i = 0; i < 3; i++) {
		const struct channel *src = &vatpit->channel[i];
		struct vdi_atpit_channel_v1 *chan = &out->va_channel[i];

		chan->vac_initial = src->initial;
		chan->vac_reg_cr =
		    (src->reg_cr[0] | (uint16_t)src->reg_cr[1] << 8);
		chan->vac_reg_ol =
		    (src->reg_ol[0] | (uint16_t)src->reg_ol[1] << 8);
		chan->vac_reg_status = src->reg_status;
		chan->vac_mode = src->mode;
		chan->vac_status =
		    (src->slatched ? (1 << 0) : 0) |
		    (src->olatched ? (1 << 1) : 0) |
		    (src->cr_sel ? (1 << 2) : 0) |
		    (src->ol_sel ? (1 << 3) : 0) |
		    (src->fr_sel ? (1 << 4) : 0);
		/* Only channel 0 has the timer configured */
		if (i == 0 && src->time_target != 0) {
			chan->vac_time_target =
			    vm_normalize_hrtime(vatpit->vm, src->time_target);
		} else {
			chan->vac_time_target = 0;
		}
	}
	VATPIT_UNLOCK(vatpit);

	return (0);
}

static bool
vatpit_data_validate(const struct vdi_atpit_v1 *src)
{
	for (uint_t i = 0; i < 3; i++) {
		const struct vdi_atpit_channel_v1 *chan = &src->va_channel[i];

		if ((chan->vac_status & ~VALID_STATUS_BITS) != 0) {
			return (false);
		}
	}
	return (true);
}

static int
vatpit_data_write(void *datap, const vmm_data_req_t *req)
{
	VERIFY3U(req->vdr_class, ==, VDC_ATPIT);
	VERIFY3U(req->vdr_version, ==, 1);
	VERIFY3U(req->vdr_len, >=, sizeof (struct vdi_atpit_v1));

	struct vatpit *vatpit = datap;
	const struct vdi_atpit_v1 *src = req->vdr_data;
	if (!vatpit_data_validate(src)) {
		return (EINVAL);
	}

	VATPIT_LOCK(vatpit);
	for (uint_t i = 0; i < 3; i++) {
		const struct vdi_atpit_channel_v1 *chan = &src->va_channel[i];
		struct channel *out = &vatpit->channel[i];

		out->initial = chan->vac_initial;
		out->reg_cr[0] = chan->vac_reg_cr;
		out->reg_cr[1] = chan->vac_reg_cr >> 8;
		out->reg_ol[0] = chan->vac_reg_ol;
		out->reg_ol[1] = chan->vac_reg_ol >> 8;
		out->reg_status = chan->vac_reg_status;
		out->mode = chan->vac_mode;
		out->slatched = (chan->vac_status & (1 << 0)) != 0;
		out->olatched = (chan->vac_status & (1 << 1)) != 0;
		out->cr_sel = (chan->vac_status & (1 << 2)) != 0;
		out->ol_sel = (chan->vac_status & (1 << 3)) != 0;
		out->fr_sel = (chan->vac_status & (1 << 4)) != 0;

		/* Only channel 0 has the timer configured */
		if (i != 0) {
			continue;
		}

		struct callout *callout = &out->callout;
		if (callout_active(callout)) {
			callout_deactivate(callout);
		}

		if (chan->vac_time_target == 0) {
			out->time_loaded = 0;
			out->time_target = 0;
			continue;
		}

		/* back-calculate time_loaded for the appropriate interval */
		const uint64_t time_target =
		    vm_denormalize_hrtime(vatpit->vm, chan->vac_time_target);
		out->total_target = out->initial;
		out->time_target = time_target;
		out->time_loaded = time_target -
		    hrt_freq_interval(PIT_8254_FREQ, out->initial);

		if (!vm_is_paused(vatpit->vm)) {
			vatpit_callout_reset(vatpit);
		}
	}
	VATPIT_UNLOCK(vatpit);

	return (0);
}

static const vmm_data_version_entry_t atpit_v1 = {
	.vdve_class = VDC_ATPIT,
	.vdve_version = 1,
	.vdve_len_expect = sizeof (struct vdi_atpit_v1),
	.vdve_readf = vatpit_data_read,
	.vdve_writef = vatpit_data_write,
};
VMM_DATA_VERSION(atpit_v1);
