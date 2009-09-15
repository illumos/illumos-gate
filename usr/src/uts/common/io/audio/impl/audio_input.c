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
 * Purpose: Virtual mixing audio input routines
 *
 * This file contains the actual mixing and resampling engine for input.
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>
#include "audio_impl.h"

#define	DECL_AUDIO_IMPORT(NAME, TYPE, SWAP, SHIFT)			\
void									\
auimpl_import_##NAME(audio_engine_t *eng, audio_stream_t *sp)		\
{									\
	int		fragfr = eng->e_fragfr;				\
	int		nch = eng->e_nchan;				\
	unsigned	tidx = eng->e_tidx;				\
	int32_t 	*out = (void *)sp->s_cnv_src;			\
	TYPE		*in = (void *)eng->e_data;			\
	int		ch = 0;						\
	int		vol = sp->s_gain_eff;				\
									\
	do {	/* for each channel */					\
		TYPE 	*ip;						\
		int32_t *op;						\
		int 	i;						\
		int 	incr = eng->e_chincr[ch];			\
									\
		/* get value and adjust next channel offset */		\
		op = out++;						\
		ip = in + eng->e_choffs[ch] + (tidx * incr);		\
									\
		i = fragfr;						\
									\
		do {	/* for each frame */				\
			int32_t	sample = (TYPE)SWAP(*ip);		\
			int32_t	scaled = sample SHIFT;			\
									\
			scaled *= vol;					\
			scaled /= AUDIO_VOL_SCALE;			\
									\
			*op = scaled;					\
			ip += incr;					\
			op += nch;					\
									\
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
 * Produce a fragment's worth of data.  This is called when the data in
 * the conversion buffer is exhausted, and we need to refill it from the
 * source buffer.  We always consume data from the client in quantities of
 * a fragment at a time (assuming that a fragment is available.)
 */
static void
auimpl_produce_fragment(audio_stream_t *sp, unsigned count)
{
	unsigned	nframes;
	unsigned	framesz;
	caddr_t		cnvsrc;
	caddr_t		data;

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

		ASSERT(sp->s_hidx < nframes);
		nf = min(nframes - sp->s_hidx, count);
		nb = nf * framesz;

		bcopy(cnvsrc, data, nb);
		data += nb;
		cnvsrc += nb;
		sp->s_hidx += nf;
		sp->s_head += nf;
		count -= nf;
		sp->s_samples += nf;
		if (sp->s_hidx >= nframes) {
			sp->s_hidx -= nframes;
			data -= sp->s_nbytes;
		}
	} while (count);

	ASSERT(sp->s_tail <= sp->s_head);
	ASSERT(sp->s_hidx < nframes);
	ASSERT(sp->s_tail <= sp->s_head);
	ASSERT(sp->s_hidx < nframes);
}

void
auimpl_input_callback(audio_engine_t *eng)
{
	int		fragfr = eng->e_fragfr;
	boolean_t	overrun;
	audio_client_t	*c;

	/* consume all fragments in the buffer */
	while ((eng->e_head - eng->e_tail) > fragfr) {

		/*
		 * Consider doing the SYNC outside of the lock.
		 */
		ENG_SYNC(eng, fragfr);

		for (audio_stream_t *sp = list_head(&eng->e_streams);
		    sp != NULL;
		    sp = list_next(&eng->e_streams, sp)) {
			int space;
			int count;

			c = sp->s_client;

			mutex_enter(&sp->s_lock);
			/* skip over streams paused or not running */
			if (sp->s_paused || (!sp->s_running) ||
			    eng->e_suspended) {
				mutex_exit(&sp->s_lock);
				continue;
			}
			sp->s_cnv_src = sp->s_cnv_buf0;
			sp->s_cnv_dst = sp->s_cnv_buf1;
			eng->e_import(eng, sp);

			/*
			 * Optionally convert fragment to requested sample
			 * format and rate.
			 */
			if (sp->s_converter != NULL) {
				count = sp->s_converter(sp, fragfr);
			} else {
				count = fragfr;
			}

			space = sp->s_nframes - (sp->s_head - sp->s_tail);
			if (count > space) {
				eng->e_stream_overruns++;
				eng->e_errors++;
				sp->s_errors += count - space;
				count = space;
				overrun = B_TRUE;
			} else {
				overrun = B_FALSE;
			}

			auimpl_produce_fragment(sp, count);

			/* wake blocked threads (blocking reads, etc.) */
			cv_broadcast(&sp->s_cv);

			mutex_exit(&sp->s_lock);

			mutex_enter(&c->c_lock);
			if (overrun) {
				c->c_do_notify = B_TRUE;
			}
			c->c_do_input = B_TRUE;
			cv_broadcast(&c->c_cv);
			mutex_exit(&c->c_lock);
		}

		/*
		 * Update the tail pointer, and the data pointer.
		 */
		eng->e_tail += fragfr;
		eng->e_tidx += fragfr;
		if (eng->e_tidx >= eng->e_nframes) {
			eng->e_tidx -= eng->e_nframes;
		}
	}
}
