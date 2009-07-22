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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Purpose: Virtual mixing audio output routines
 *
 * This file contains the actual mixing and resampling engine for output.
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>
#include "audio_impl.h"

#define	DECL_AUDIO_EXPORT(NAME, TYPE, SAMPLE)				\
void									\
auimpl_export_##NAME(audio_engine_t *eng)				\
{									\
	int		fragfr = eng->e_fragfr;				\
	int		nch = eng->e_nchan;				\
	unsigned	hidx = eng->e_hidx;				\
	TYPE		*out = (void *)eng->e_data;			\
	int		ch = 0;						\
									\
	do {	/* for each channel */					\
		int32_t *ip;						\
		TYPE	*op;						\
		int	i;						\
		int	incr = eng->e_chincr[ch];			\
									\
		/* get value and adjust next channel offset */		\
		op = out + eng->e_choffs[ch] + (hidx * incr);		\
		ip = eng->e_chbufs[ch];					\
									\
		i = fragfr;						\
									\
		do {	/* for each frame */				\
			int32_t sample = *ip;				\
									\
			*op = SAMPLE;					\
			op += incr;					\
			ip++;						\
									\
		} while (--i);						\
									\
		ch++;							\
	} while (ch < nch);						\
}

DECL_AUDIO_EXPORT(16ne, int16_t, sample >> 8)
DECL_AUDIO_EXPORT(16oe, int16_t, ddi_swap16(sample >> 8))
DECL_AUDIO_EXPORT(32ne, int32_t, sample << 8)
DECL_AUDIO_EXPORT(32oe, int32_t, ddi_swap32(sample << 8))
DECL_AUDIO_EXPORT(24ne, int32_t, sample)
DECL_AUDIO_EXPORT(24oe, int32_t, ddi_swap32(sample))

/*
 * Simple limiter to prevent overflows when using fixed point computations
 */
static void
auimpl_output_limiter(audio_engine_t *eng)
{
	int k, t;
	unsigned int q, amp, amp2;
	int nchan = eng->e_nchan;
	int fragfr = eng->e_fragfr;
	int32_t **chbufs = eng->e_chbufs;
	unsigned int statevar = eng->e_limiter_state;

	for (t = 0; t < fragfr; t++) {

		amp = (unsigned)ABS(chbufs[0][t]);

		for (k = 1; k < nchan; k++)	{
			amp2 = (unsigned)ABS(chbufs[k][t]);
			if (amp2 > amp)
				amp = amp2;
		}

		amp >>= 8;
		q = 0x10000;

		if (amp > 0x7FFF)
			q = 0x7FFF0000 / amp;

		if (statevar > q) {
			statevar = q;
		} else {
			q = statevar;

			/*
			 * Simplier (linear) tracking algo
			 * (gives less distortion, but more pumping)
			 */
			statevar += 2;
			if (statevar > 0x10000)
				statevar = 0x10000;

			/*
			 * Classic tracking algo
			 * gives more distortion with no-lookahead
			 * statevar=0x10000-((0x10000-statevar)*0xFFF4>>16);
			 */
		}

		for (k = 0; k < nchan; k++) {
			int32_t in = chbufs[k][t];
			int32_t out = 0;
			unsigned int p;

			if (in >= 0) {
				p = in;
				p = ((p & 0xFFFF) * (q >> 4) >> 12) +
				    (p >> 16) * q;
				out = p;
			} else {
				p = -in;
				p = ((p & 0xFFFF) * (q >> 4) >> 12) +
				    (p >> 16) * q;
				out = -p;
			}
			/* safety code */
			/*
			 * if output after limiter is clamped, then it
			 * can be dropped
			 */
			if (out > 0x7FFFFF)
				out = 0x7FFFFF;
			else if (out < -0x7FFFFF)
				out = -0x7FFFFF;

			chbufs[k][t] = out;
		}
	}

	eng->e_limiter_state = statevar;
}

/*
 * Output mixing function.  Assumption: all work is done in 24-bit native PCM.
 */
static void
auimpl_output_mix(audio_stream_t *sp, int offset, int nfr)
{
	audio_engine_t *eng = sp->s_engine;
	const int32_t *src;
	int choffs;
	int nch;
	int vol;

	/*
	 * Initial setup.
	 */

	src = sp->s_cnv_ptr;
	choffs = sp->s_choffs;
	nch = sp->s_cnv_dst_nchan;
	vol = sp->s_gain_eff;

	/*
	 * Do the mixing.  We de-interleave the source stream at the
	 * same time.
	 */
	for (int ch = 0; ch < nch; ch++) {
		int32_t *op;
		const int32_t *ip;


		ip = src + ch;
		op = eng->e_chbufs[ch + choffs];
		op += offset;

		for (int i = nfr; i; i--) {

			int64_t	samp;

			samp = *ip;
			samp *= vol;
			samp /= AUDIO_VOL_SCALE;

			ip += nch;
			*op += (int32_t)samp;
			op++;
		}
	}

	sp->s_cnv_cnt -= nfr;
	sp->s_cnv_ptr += (nch * nfr);
}

/*
 * Consume a fragment's worth of data.  This is called when the data in
 * the conversion buffer is exhausted, and we need to refill it from the
 * source buffer.  We always consume data from the client in quantities of
 * a fragment at a time (assuming that a fragment is available.)
 */
static void
auimpl_consume_fragment(audio_stream_t *sp)
{
	unsigned	count;
	unsigned	avail;
	unsigned	nframes;
	unsigned	fragfr;
	unsigned	framesz;
	caddr_t		cnvbuf;

	sp->s_cnv_src = sp->s_cnv_buf0;
	sp->s_cnv_dst = sp->s_cnv_buf1;

	fragfr = sp->s_fragfr;
	nframes = sp->s_nframes;
	framesz = sp->s_framesz;

	ASSERT(sp->s_head >= sp->s_tail);

	avail = sp->s_head - sp->s_tail;
	cnvbuf = sp->s_cnv_src;

	count = min(avail, fragfr);

	/*
	 * Copy data.  We deal properly with wraps.  Done as a
	 * do...while to minimize the number of tests.
	 */
	do {
		unsigned n;
		unsigned nbytes;

		n = min(nframes - sp->s_tidx, count);
		nbytes = framesz * n;
		bcopy(sp->s_data + (sp->s_tidx * framesz), cnvbuf, nbytes);
		cnvbuf += nbytes;
		count -= n;
		sp->s_samples += n;
		sp->s_tail += n;
		sp->s_tidx += n;
		if (sp->s_tidx >= nframes)
			sp->s_tidx -= nframes;
	} while (count);

	/* Note: data conversion is optional! */
	count = min(avail, fragfr);
	if (sp->s_converter != NULL) {
		sp->s_cnv_cnt = sp->s_converter(sp, count);
	} else {
		sp->s_cnv_cnt = count;
	}
}

static void
auimpl_output_callback_impl(audio_engine_t *eng)
{
	int		fragfr = eng->e_fragfr;

	/* clear any preexisting mix results */
	for (int i = 0; i < eng->e_nchan; i++)
		bzero(eng->e_chbufs[i], AUDIO_CHBUFS * sizeof (int32_t));

	for (audio_stream_t *sp = list_head(&eng->e_streams);
	    sp != NULL;
	    sp = list_next(&eng->e_streams, sp)) {

		int		need;
		int		avail;
		int		used;
		int		offset;
		boolean_t	underrun = B_FALSE;
		boolean_t	drained = B_FALSE;
		audio_client_t	*c = sp->s_client;

		/*
		 * We need/want a full fragment.  If the client has
		 * less than that available, it will cause a client
		 * underrun in auimpl_consume_fragment, but in such a
		 * case we should get silence bytes.  Assignments done
		 * ahead of the lock to minimize lock contention.
		 */
		need = fragfr;
		offset = 0;

		mutex_enter(&sp->s_lock);
		/* skip over streams not running or paused */
		if ((!sp->s_running) || (sp->s_paused) || eng->e_suspended) {
			mutex_exit(&sp->s_lock);
			continue;
		}

		do {
			/* make sure we have data to chew on */
			if ((avail = sp->s_cnv_cnt) == 0) {
				auimpl_consume_fragment(sp);
				sp->s_cnv_ptr = sp->s_cnv_src;
				avail = sp->s_cnv_cnt;
			}

			/*
			 * We might have got more data than we need
			 * right now.  (E.g. 8kHz expanding to 48kHz.)
			 * Take only what we need.
			 */
			used = min(avail, need);

			/*
			 * Mix the results, as much data as we can use
			 * this round.
			 */
			auimpl_output_mix(sp, offset, used);

			/*
			 * Save the offset for the next round, so we don't
			 * remix into the same location.
			 */
			offset += used;

			/*
			 * Okay, we mixed some data, but it might not
			 * have been all we need.  This can happen
			 * either because we just mixed up some
			 * partial/residual data, or because the
			 * client has a fragment size which expands to
			 * less than a full fragment for us. (Such as
			 * a client wanting to operate at a higher
			 * data rate than the engine.)
			 */
			need -= used;

		} while (need && avail);

		if (avail == 0) {
			/* underrun or end of data */
			if (sp->s_draining) {
				if (sp->s_drain_idx == 0) {
					sp->s_drain_idx = eng->e_head;
				}
				if (eng->e_tail >= sp->s_drain_idx) {
					sp->s_drain_idx = 0;
					sp->s_draining = B_FALSE;
					/*
					 * After draining, stop the
					 * stream cleanly.  This
					 * prevents underrun errors.
					 *
					 * (Stream will auto-start if
					 * client submits more data to
					 * it.)
					 *
					 * AC3: When an AC3 stream
					 * drains we should probably
					 * stop the actual hardware
					 * engine.
					 */
					ASSERT(mutex_owned(&eng->e_lock));
					sp->s_running = B_FALSE;
					drained = B_TRUE;
				}
			} else {
				underrun = B_TRUE;
				sp->s_errors += need;
				eng->e_stream_underruns++;
			}
		}

		/* wake threads waiting for stream (blocking writes, etc.) */
		cv_broadcast(&sp->s_cv);

		mutex_exit(&sp->s_lock);


		/*
		 * Asynchronously notify clients.  We do as much as
		 * possible of this outside of the lock, it avoids
		 * s_lock and c_lock contention and eliminates any
		 * chance of deadlock.
		 */

		mutex_enter(&c->c_lock);
		c->c_do_output = B_TRUE;

		if (underrun)
			c->c_do_notify = B_TRUE;

		if (drained)
			c->c_do_drain = B_TRUE;

		cv_broadcast(&c->c_cv);
		mutex_exit(&c->c_lock);
	}

	/*
	 * Deal with 24-bit overflows (from mixing) gracefully.
	 */
	auimpl_output_limiter(eng);

	/*
	 * Export the data (a whole fragment) to the device.
	 */
	eng->e_export(eng);

	/*
	 * Update the head and offset.  The head counts without
	 * wrapping, whereas the offset wraps.  Note that the test +
	 * subtraction is faster for dealing with wrap than modulo.
	 */
	eng->e_head += fragfr;
	eng->e_hidx += fragfr;
	if (eng->e_hidx >= eng->e_nframes)
		eng->e_hidx -= eng->e_nframes;

	/*
	 * Consider doing the SYNC outside of the lock.
	 */
	ENG_SYNC(eng, fragfr);
}

/*
 * Outer loop attempts to keep playing until we hit maximum playahead.
 */

void
auimpl_output_callback(audio_engine_t *eng)
{
	unsigned fragfr;
	int64_t cnt;

	fragfr = eng->e_fragfr;
	cnt = eng->e_head - eng->e_tail;

	/* stay a bit ahead */
	while (cnt < (fragfr * 4)) {
		auimpl_output_callback_impl(eng);
		cnt = eng->e_head - eng->e_tail;
	}
}
