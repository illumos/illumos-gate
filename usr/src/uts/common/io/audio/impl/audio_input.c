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
 * Copyright (C) 4Front Technologies 1996-2008.
 *
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Purpose: Virtual mixing audio input routines
 *
 * This file contains the actual mixing and resampling engine for input.
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>
#include <sys/sdt.h>
#include "audio_impl.h"

#define	DECL_AUDIO_IMPORT(NAME, TYPE, SWAP, SHIFT)			\
void									\
auimpl_import_##NAME(audio_engine_t *e, uint_t nfr, audio_stream_t *sp)	\
{									\
	int		nch = e->e_nchan;				\
	int32_t		*out = (void *)sp->s_cnv_src;			\
	TYPE		*in = (void *)e->e_data;			\
	int		ch = 0;						\
	int		vol = sp->s_gain_eff;				\
									\
	do {	/* for each channel */					\
		TYPE 	*ip;						\
		int32_t *op;						\
		int 	i;						\
		int 	incr = e->e_chincr[ch];				\
		uint_t	tidx = e->e_tidx;				\
									\
		/* get value and adjust next channel offset */		\
		op = out++;						\
		ip = in + e->e_choffs[ch] + (tidx * incr);		\
									\
		i = nfr;						\
									\
		do {	/* for each frame */				\
			int32_t	sample = (TYPE)SWAP(*ip);		\
			int32_t	scaled = sample SHIFT;			\
									\
			scaled *= vol;					\
			scaled /= AUDIO_VOL_SCALE;			\
									\
			*op = scaled;					\
			op += nch;					\
									\
			ip += incr;					\
			if (++tidx == e->e_nframes) {			\
				tidx = 0;				\
				ip = in + e->e_choffs[ch];		\
			}						\
		} while (--i);						\
		ch++;							\
	} while (ch < nch);						\
}

DECL_AUDIO_IMPORT(16ne, int16_t, /* nop */, << 8)
DECL_AUDIO_IMPORT(16oe, int16_t, ddi_swap16, << 8)
DECL_AUDIO_IMPORT(32ne, int32_t, /* nop */, >> 8)
DECL_AUDIO_IMPORT(32oe, int32_t, ddi_swap32, >> 8)
DECL_AUDIO_IMPORT(24ne, int32_t, /* nop */, /* nop */)
DECL_AUDIO_IMPORT(24oe, int32_t, ddi_swap32, /* nop */)

/*
 * Produce capture data.  This takes data from the conversion buffer
 * and copies it into the stream data buffer.
 */
static void
auimpl_produce_data(audio_stream_t *sp, uint_t count)
{
	uint_t	nframes;
	uint_t	framesz;
	caddr_t	cnvsrc;
	caddr_t	data;

	nframes = sp->s_nframes;
	framesz = sp->s_framesz;

	ASSERT(sp->s_head >= sp->s_tail);
	ASSERT(sp->s_hidx < nframes);
	ASSERT(sp->s_tidx < nframes);

	/*
	 * Copy data.  We deal properly with wraps.  Done as a
	 * do...while to minimize the number of tests.
	 */
	cnvsrc = sp->s_cnv_src;
	data = sp->s_data + (sp->s_hidx * framesz);
	do {
		unsigned nf;
		unsigned nb;

		nf = min(nframes - sp->s_hidx, count);
		nb = nf * framesz;

		bcopy(cnvsrc, data, nb);
		data += nb;
		cnvsrc += nb;
		sp->s_hidx += nf;
		sp->s_head += nf;
		count -= nf;
		sp->s_samples += nf;
		if (sp->s_hidx == nframes) {
			sp->s_hidx = 0;
			data = sp->s_data;
		}
	} while (count);

	ASSERT(sp->s_tail <= sp->s_head);
	ASSERT(sp->s_hidx < nframes);
}

void
auimpl_input_callback(void *arg)
{
	audio_engine_t	*e = arg;
	uint_t		fragfr = e->e_fragfr;
	audio_stream_t	*sp;
	audio_client_t	*c;
	audio_client_t	*clist = NULL;
	list_t		*l = &e->e_streams;
	uint64_t	h;

	mutex_enter(&e->e_lock);

	if (e->e_suspended || e->e_failed) {
		mutex_exit(&e->e_lock);
		return;
	}

	if (e->e_need_start) {
		int rv;
		if ((rv = ENG_START(e)) != 0) {
			e->e_failed = B_TRUE;
			mutex_exit(&e->e_lock);
			audio_dev_warn(e->e_dev,
			    "failed starting input, rv = %d", rv);
			return;
		}
		e->e_need_start = B_FALSE;
	}

	h = ENG_COUNT(e);
	ASSERT(h >= e->e_head);
	if (h < e->e_head) {
		/*
		 * This is a sign of a serious bug.  We should
		 * probably offline the device via FMA, if we ever
		 * support FMA for audio devices.
		 */
		e->e_failed = B_TRUE;
		ENG_STOP(e);
		mutex_exit(&e->e_lock);
		audio_dev_warn(e->e_dev,
		    "device malfunction: broken capture sample counter");
		return;
	}
	e->e_head = h;
	ASSERT(e->e_head >= e->e_tail);

	if ((e->e_head - e->e_tail) > e->e_nframes) {
		/* no room for data, not much we can do */
		e->e_errors++;
		e->e_overruns++;
	}

	/* consume all fragments in the buffer */
	while ((e->e_head - e->e_tail) > fragfr) {

		/*
		 * Consider doing the SYNC outside of the lock.
		 */
		ENG_SYNC(e, fragfr);

		for (sp = list_head(l); sp != NULL; sp = list_next(l, sp)) {
			int space;
			int count;

			mutex_enter(&sp->s_lock);
			/* skip over streams paused or not running */
			if (sp->s_paused || !sp->s_running) {
				mutex_exit(&sp->s_lock);
				continue;
			}
			sp->s_cnv_src = sp->s_cnv_buf0;
			sp->s_cnv_dst = sp->s_cnv_buf1;

			e->e_import(e, fragfr, sp);

			/*
			 * Optionally convert fragment to requested sample
			 * format and rate.
			 */
			if (sp->s_converter != NULL) {
				count = sp->s_converter(sp, fragfr);
			} else {
				count = fragfr;
			}

			ASSERT(sp->s_head >= sp->s_tail);
			space = sp->s_nframes - (sp->s_head - sp->s_tail);
			if (count > space) {
				e->e_stream_overruns++;
				e->e_errors++;
				sp->s_errors += count - space;
				count = space;
			}

			auimpl_produce_data(sp, count);

			/* wake blocked threads (blocking reads, etc.) */
			cv_broadcast(&sp->s_cv);

			mutex_exit(&sp->s_lock);

			/*
			 * Add client to notification list.  We'll
			 * process it after dropping the lock.
			 */
			c = sp->s_client;

			if ((c->c_input != NULL) &&
			    (c->c_next_input == NULL)) {
				auclnt_hold(c);
				c->c_next_input = clist;
				clist = c;
			}
		}

		/*
		 * Update the tail pointer, and the data pointer.
		 */
		e->e_tail += fragfr;
		e->e_tidx += fragfr;
		if (e->e_tidx >= e->e_nframes) {
			e->e_tidx -= e->e_nframes;
		}
	}

	mutex_exit(&e->e_lock);

	/*
	 * Notify client personalities.
	 */

	while ((c = clist) != NULL) {
		clist = c->c_next_input;
		c->c_next_input = NULL;
		c->c_input(c);
		auclnt_release(c);
	}
}
