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

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/list.h>
#include <sys/file.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/atomic.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include "audio_impl.h"

/*
 * Audio Client implementation.
 */

/*
 * Attenuation table for dB->linear conversion. Indexed in steps of
 * 0.5 dB.  Table size is 25 dB (first entry is handled as mute).
 *
 * Notably, the last item in table is taken as 0 dB (i.e. maximum volume).
 *
 * Table contents can be calculated as follows (requires sunmath library):
 *
 * scale = AUDIO_VOL_SCALE;
 * for (i = -50; i <= 0; i++) {
 *     x = exp10(0.05 * i);
 *     printf("%d: %f %.0f\n", i,  x, trunc(x * scale));
 * }
 *
 */

static const uint16_t auimpl_db_table[AUDIO_DB_SIZE + 1] = {
	0,   0,   1,   1,   1,   1,   1,   1,   2,   2,
	2,   2,   3,   3,   4,   4,   5,   5,   6,   7,
	8,   9,   10,  11,  12,  14,  16,  18,  20,  22,
	25,  28,  32,  36,  40,  45,  51,  57,  64,  72,
	80,  90,  101, 114, 128, 143, 161, 181, 203, 228,
	256
};

static list_t			auimpl_clients;
static krwlock_t		auimpl_client_lock;
static audio_client_ops_t	*audio_client_ops[AUDIO_MN_TYPE_MASK + 1];

void *
auclnt_get_private(audio_client_t *c)
{
	return (c->c_private);
}

void
auclnt_set_private(audio_client_t *c, void *private)
{
	c->c_private = private;
}

int
auclnt_set_rate(audio_stream_t *sp, int rate)
{
	audio_parms_t	parms;
	int		rv = 0;

	/* basic sanity checks! */
	if ((rate < 5000) || (rate > 192000)) {
		return (EINVAL);
	}
	mutex_enter(&sp->s_lock);
	parms = *sp->s_user_parms;
	if (rate != parms.p_rate) {
		parms.p_rate = rate;
		rv = auimpl_format_setup(sp, &parms);
	}
	mutex_exit(&sp->s_lock);
	return (rv);
}

int
auclnt_get_rate(audio_stream_t *sp)
{
	return (sp->s_user_parms->p_rate);
}

unsigned
auclnt_get_fragsz(audio_stream_t *sp)
{
	return (sp->s_fragbytes);
}

unsigned
auclnt_get_framesz(audio_stream_t *sp)
{
	return (sp->s_framesz);
}

unsigned
auclnt_get_nfrags(audio_stream_t *sp)
{
	return (sp->s_nfrags);
}

unsigned
auclnt_get_nframes(audio_stream_t *sp)
{
	return (sp->s_nframes);
}

void
auclnt_set_latency(audio_stream_t *sp, unsigned frags, unsigned bytes)
{
	mutex_enter(&sp->s_lock);
	sp->s_hintfrags = (uint16_t)frags;
	sp->s_hintsz = bytes;
	mutex_exit(&sp->s_lock);
}

uint64_t
auclnt_get_head(audio_stream_t *sp)
{
	return (sp->s_head);
}

uint64_t
auclnt_get_tail(audio_stream_t *sp)
{
	return (sp->s_tail);
}

unsigned
auclnt_get_hidx(audio_stream_t *sp)
{
	return (sp->s_hidx);
}

unsigned
auclnt_get_tidx(audio_stream_t *sp)
{
	return (sp->s_tidx);
}

audio_stream_t *
auclnt_input_stream(audio_client_t *c)
{
	return (&c->c_istream);
}

audio_stream_t *
auclnt_output_stream(audio_client_t *c)
{
	return (&c->c_ostream);
}

unsigned
auclnt_get_count(audio_stream_t *sp)
{
	unsigned	count;

	mutex_enter(&sp->s_lock);
	ASSERT((sp->s_head - sp->s_tail) <= sp->s_nframes);
	count = (unsigned)(sp->s_head - sp->s_tail);
	mutex_exit(&sp->s_lock);

	return (count);
}

unsigned
auclnt_consume(audio_stream_t *sp, unsigned n)
{
	mutex_enter(&sp->s_lock);

	ASSERT(sp == &sp->s_client->c_istream);
	n = max(n, sp->s_head - sp->s_tail);
	sp->s_tail += n;
	sp->s_tidx += n;
	if (sp->s_tidx >= sp->s_nframes) {
		sp->s_tidx -= sp->s_nframes;
	}

	ASSERT(sp->s_tail <= sp->s_head);
	ASSERT(sp->s_hidx < sp->s_nframes);

	mutex_exit(&sp->s_lock);

	return (n);
}

unsigned
auclnt_consume_data(audio_stream_t *sp, caddr_t dst, unsigned n)
{
	unsigned nframes;
	unsigned framesz;
	unsigned cnt;
	caddr_t	data;

	mutex_enter(&sp->s_lock);

	nframes = sp->s_nframes;
	framesz = sp->s_framesz;

	ASSERT(sp == &sp->s_client->c_istream);
	ASSERT(sp->s_head >= sp->s_tail);
	ASSERT(sp->s_tidx < nframes);
	ASSERT(sp->s_hidx < nframes);

	cnt = n = min(n, sp->s_head - sp->s_tail);
	data = sp->s_data + (sp->s_tidx * framesz);
	do {
		unsigned nf, nb;

		nf = min(nframes - sp->s_tidx, n);
		nb = nf * framesz;

		bcopy(data, dst, nb);
		dst += nb;
		data += nb;

		n -= nf;
		sp->s_tail += nf;
		sp->s_tidx += nf;
		if (sp->s_tidx == nframes) {
			sp->s_tidx = 0;
			data = sp->s_data;
		}
	} while (n);

	ASSERT(sp->s_tail <= sp->s_head);
	ASSERT(sp->s_tidx < nframes);

	mutex_exit(&sp->s_lock);

	return (cnt);
}

unsigned
auclnt_produce(audio_stream_t *sp, unsigned n)
{
	mutex_enter(&sp->s_lock);

	ASSERT(sp == &sp->s_client->c_ostream);
	n = max(n, sp->s_nframes - (sp->s_head - sp->s_tail));
	sp->s_head += n;
	sp->s_hidx += n;
	if (sp->s_hidx >= sp->s_nframes) {
		sp->s_hidx -= sp->s_nframes;
	}

	ASSERT(sp->s_tail <= sp->s_head);
	ASSERT(sp->s_hidx < sp->s_nframes);

	mutex_exit(&sp->s_lock);

	return (n);
}

unsigned
auclnt_produce_data(audio_stream_t *sp, caddr_t src, unsigned n)
{
	unsigned nframes;
	unsigned framesz;
	unsigned cnt;
	caddr_t data;

	mutex_enter(&sp->s_lock);

	nframes = sp->s_nframes;
	framesz = sp->s_framesz;

	ASSERT(sp == &sp->s_client->c_ostream);
	ASSERT(sp->s_head >= sp->s_tail);
	ASSERT(sp->s_tidx < nframes);
	ASSERT(sp->s_hidx < nframes);

	cnt = n = min(n, nframes - (sp->s_head - sp->s_tail));
	data = sp->s_data + (sp->s_hidx * framesz);
	do {
		unsigned nf, nb;

		nf = min(nframes - sp->s_hidx, n);
		nb = nf * framesz;

		bcopy(src, data, nb);

		src += nb;
		data += nb;

		n -= nf;
		sp->s_head += nf;
		sp->s_hidx += nf;
		if (sp->s_hidx == nframes) {
			sp->s_hidx = 0;
			data = sp->s_data;
		}
	} while (n);

	ASSERT(sp->s_tail <= sp->s_head);
	ASSERT(sp->s_hidx < nframes);

	mutex_exit(&sp->s_lock);

	return (cnt);
}

int
auclnt_read(audio_client_t *c, struct uio *uio)
{
	audio_stream_t	*sp = &c->c_istream;
	unsigned	cnt;
	int		rv = 0;
	offset_t	loff;
	int		eagain;

	loff = uio->uio_loffset;
	eagain = EAGAIN;

	mutex_enter(&sp->s_lock);

	if ((!sp->s_paused) && (!sp->s_running)) {
		mutex_exit(&sp->s_lock);
		auclnt_start(sp);
		mutex_enter(&sp->s_lock);
	}

	ASSERT(sp->s_head >= sp->s_tail);
	ASSERT(sp->s_tidx < sp->s_nframes);
	ASSERT(sp->s_hidx < sp->s_nframes);

	while (uio->uio_resid >= sp->s_framesz) {

		while ((cnt = (sp->s_head - sp->s_tail)) == 0) {
			if (uio->uio_fmode & (FNONBLOCK|FNDELAY)) {
				mutex_exit(&sp->s_lock);
				return (eagain);
			}
			if (cv_wait_sig(&sp->s_cv, &sp->s_lock) == 0) {
				mutex_exit(&sp->s_lock);
				return (EINTR);
			}
		}

		cnt = min(cnt, sp->s_nframes - sp->s_tidx);
		cnt = min(cnt, (uio->uio_resid / sp->s_framesz));

		rv = uiomove(sp->s_data + (sp->s_tidx * sp->s_framesz),
		    cnt * sp->s_framesz, UIO_READ, uio);
		uio->uio_loffset = loff;
		eagain = 0;

		if (rv != 0) {
			mutex_exit(&sp->s_lock);
			return (rv);
		}

		sp->s_tail += cnt;
		sp->s_tidx += cnt;
		if (sp->s_tidx == sp->s_nframes) {
			sp->s_tidx = 0;
		}
	}

	ASSERT(sp->s_tail <= sp->s_head);
	ASSERT(sp->s_tidx < sp->s_nframes);

	/* round off any remaining partial bits */
	uio->uio_resid = 0;

	mutex_exit(&sp->s_lock);

	return (rv);
}

int
auclnt_write(audio_client_t *c, struct uio *uio)
{
	audio_stream_t *sp = &c->c_ostream;
	unsigned	cnt;
	int		rv = 0;
	offset_t	loff;
	int		eagain;

	loff = uio->uio_loffset;
	eagain = EAGAIN;

	mutex_enter(&sp->s_lock);

	ASSERT(sp->s_head >= sp->s_tail);
	ASSERT(sp->s_tidx < sp->s_nframes);
	ASSERT(sp->s_hidx < sp->s_nframes);

	while (uio->uio_resid >= sp->s_framesz) {

		while ((cnt = sp->s_nframes - (sp->s_head - sp->s_tail)) == 0) {
			if (uio->uio_fmode & (FNONBLOCK|FNDELAY)) {
				mutex_exit(&sp->s_lock);
				return (eagain);
			}
			if (cv_wait_sig(&sp->s_cv, &sp->s_lock) == 0) {
				mutex_exit(&sp->s_lock);
				return (EINTR);
			}
		}

		cnt = min(cnt, sp->s_nframes - sp->s_hidx);
		cnt = min(cnt, (uio->uio_resid / sp->s_framesz));

		rv = uiomove(sp->s_data + (sp->s_hidx * sp->s_framesz),
		    cnt * sp->s_framesz, UIO_WRITE, uio);
		uio->uio_loffset = loff;
		eagain = 0;

		if (rv != 0) {
			mutex_exit(&sp->s_lock);
			return (rv);
		}

		sp->s_head += cnt;
		sp->s_hidx += cnt;
		if (sp->s_hidx == sp->s_nframes) {
			sp->s_hidx = 0;
		}

		if ((!sp->s_paused) && (!sp->s_running) &&
		    ((sp->s_head - sp->s_tail) > sp->s_fragfr)) {
			mutex_exit(&sp->s_lock);
			auclnt_start(sp);
			mutex_enter(&sp->s_lock);
		}
	}

	ASSERT(sp->s_tail <= sp->s_head);
	ASSERT(sp->s_hidx < sp->s_nframes);

	/* round off any remaining partial bits */
	uio->uio_resid = 0;

	mutex_exit(&sp->s_lock);

	return (rv);
}

int
auclnt_chpoll(audio_client_t *c, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	audio_stream_t	*sp;
	short nev = 0;

	if (events & (POLLIN | POLLRDNORM)) {
		sp = &c->c_istream;
		mutex_enter(&sp->s_lock);
		if ((sp->s_head - sp->s_tail) > sp->s_fragfr) {
			nev = POLLIN | POLLRDNORM;
		}
		mutex_exit(&sp->s_lock);
	}

	if (events & POLLOUT) {
		sp = &c->c_ostream;
		mutex_enter(&sp->s_lock);
		if ((sp->s_nframes - (sp->s_head - sp->s_tail)) >
		    sp->s_fragfr) {
			nev = POLLOUT;
		}
		mutex_exit(&sp->s_lock);
	}

	if (nev) {
		*reventsp = nev & events;
	} else {
		*reventsp = 0;
		if (!anyyet) {
			*phpp = &c->c_pollhead;
		}
	}
	return (0);
}

void
auclnt_pollwakeup(audio_client_t *c, short events)
{
	pollwakeup(&c->c_pollhead, events);
}

void
auclnt_get_output_qlen(audio_client_t *c, unsigned *slen, unsigned *flen)
{
	audio_stream_t	*sp = &c->c_ostream;
	audio_engine_t	*e = sp->s_engine;
	uint64_t	el, sl;
	unsigned	cnt, er, sr;

	if (e == NULL) {
		/* if no output engine, can't do it! */
		*slen = 0;
		*flen = 0;
		return;
	}

	mutex_enter(&e->e_lock);
	mutex_enter(&sp->s_lock);
	if (e->e_ops.audio_engine_qlen != NULL) {
		el = ENG_QLEN(e) + (e->e_head - e->e_tail);
	} else {
		el = (e->e_head - e->e_tail);
	}
	er = e->e_rate;
	sl = sp->s_cnv_cnt;
	sr = sp->s_user_parms->p_rate;
	cnt = (unsigned)(sp->s_head - sp->s_tail);
	mutex_exit(&sp->s_lock);
	mutex_exit(&e->e_lock);

	/* engine frames converted to stream rate, plus stream frames */
	*slen = cnt;
	*flen = ((unsigned)(((el * sr) / er) + sl));
}

int
auclnt_set_format(audio_stream_t *sp, int fmt)
{
	audio_parms_t	parms;
	int		rv = 0;

	/*
	 * AC3: If we select an AC3 format, then we have to allocate
	 * another engine.  Normally this will be an output only
	 * engine.  However, for now we aren't supporting AC3
	 * passthru.
	 */

	switch (fmt) {
	case AUDIO_FORMAT_U8:
	case AUDIO_FORMAT_ULAW:
	case AUDIO_FORMAT_ALAW:
	case AUDIO_FORMAT_S8:
	case AUDIO_FORMAT_S16_LE:
	case AUDIO_FORMAT_S16_BE:
	case AUDIO_FORMAT_U16_LE:
	case AUDIO_FORMAT_U16_BE:
	case AUDIO_FORMAT_S24_LE:
	case AUDIO_FORMAT_S24_BE:
	case AUDIO_FORMAT_S32_LE:
	case AUDIO_FORMAT_S32_BE:
	case AUDIO_FORMAT_S24_PACKED:
		break;

	case AUDIO_FORMAT_AC3:		/* AC3: PASSTHRU */
	default:
		return (ENOTSUP);
	}


	mutex_enter(&sp->s_lock);
	parms = *sp->s_user_parms;

	/*
	 * Optimization.  Some personalities send us the same format
	 * over and over again.  (Sun personality does this
	 * repeatedly.)  setup_src is potentially expensive, so we
	 * avoid doing it unless we really need to.
	 */
	if (fmt != parms.p_format) {
		/*
		 * Note that setting the format doesn't check that the
		 * audio streams have been paused.  As a result, any
		 * data still playing or recording will probably get
		 * misinterpreted.  It would be smart if the client
		 * application paused/stopped playback before changing
		 * formats.
		 */
		parms.p_format = fmt;
		rv = auimpl_format_setup(sp, &parms);
	}
	mutex_exit(&sp->s_lock);

	return (rv);
}

int
auclnt_get_format(audio_stream_t *sp)
{
	return (sp->s_user_parms->p_format);
}

int
auclnt_get_output_format(audio_client_t *c)
{
	return (c->c_ostream.s_user_parms->p_format);
}

int
auclnt_get_input_format(audio_client_t *c)
{
	return (c->c_istream.s_user_parms->p_format);
}

int
auclnt_set_channels(audio_stream_t *sp, int nchan)
{
	audio_parms_t	parms;
	int		rv = 0;

	/* Validate setting */
	if ((nchan > AUDIO_MAX_CHANNELS) || (nchan < 1)) {
		return (EINVAL);
	}

	mutex_enter(&sp->s_lock);
	parms = *sp->s_user_parms;
	if (nchan != parms.p_nchan) {
		parms.p_nchan = nchan;
		rv = auimpl_format_setup(sp, &parms);
	}
	mutex_exit(&sp->s_lock);

	return (rv);
}

int
auclnt_get_channels(audio_stream_t *sp)
{
	return (sp->s_user_parms->p_nchan);
}


static void
auimpl_set_gain_master(audio_stream_t *sp, uint8_t gain)
{
	uint32_t	scaled;

	if (gain > 100) {
		gain = 0;
	}

	mutex_enter(&sp->s_lock);
	if (sp->s_gain_master == gain) {
		mutex_exit(&sp->s_lock);
		return;
	}

	/*
	 * calculate the scaled values.  Done now to avoid calculations
	 * later.
	 */
	scaled = (gain * sp->s_gain_pct * AUDIO_DB_SIZE) / (100 * 100);

	sp->s_gain_master = gain;
	sp->s_gain_scaled = auimpl_db_table[scaled];

	if (!sp->s_muted) {
		sp->s_gain_eff = sp->s_gain_scaled;
	}
	mutex_exit(&sp->s_lock);
}

int
auimpl_set_pcmvol(void *arg, uint64_t val)
{
	audio_dev_t	*d = arg;
	list_t		*l = &d->d_clients;
	audio_client_t	*c;

	if (val > 100) {
		return (EINVAL);
	}
	rw_enter(&auimpl_client_lock, RW_WRITER);
	d->d_pcmvol = val & 0xff;
	rw_downgrade(&auimpl_client_lock);

	for (c = list_head(l); c; c = list_next(l, c)) {
		/* don't need to check is_active here, its safe */
		auimpl_set_gain_master(&c->c_ostream, (uint8_t)val);
	}
	rw_exit(&auimpl_client_lock);

	return (0);
}

int
auimpl_get_pcmvol(void *arg, uint64_t *val)
{
	audio_dev_t	*d = arg;

	*val = d->d_pcmvol;
	return (0);
}

void
auclnt_set_gain(audio_stream_t *sp, uint8_t gain)
{
	uint32_t	scaled;

	if (gain > 100) {
		gain = 0;
	}

	mutex_enter(&sp->s_lock);

	/* if no change, don't bother doing updates */
	if (sp->s_gain_pct == gain) {
		mutex_exit(&sp->s_lock);
		return;
	}

	/*
	 * calculate the scaled values.  Done now to avoid calculations
	 * later.
	 */
	scaled = (gain * sp->s_gain_master * AUDIO_DB_SIZE) / (100 * 100);

	sp->s_gain_pct = gain;
	sp->s_gain_scaled = auimpl_db_table[scaled];

	if (!sp->s_muted) {
		sp->s_gain_eff = sp->s_gain_scaled;
	}
	mutex_exit(&sp->s_lock);

	atomic_inc_uint(&sp->s_client->c_dev->d_serial);
}

uint8_t
auclnt_get_gain(audio_stream_t *sp)
{
	return (sp->s_gain_pct);
}

void
auclnt_set_muted(audio_stream_t *sp, boolean_t muted)
{
	mutex_enter(&sp->s_lock);

	/* if no work change, don't bother doing updates */
	if (sp->s_muted == muted) {
		mutex_exit(&sp->s_lock);
		return;
	}

	sp->s_muted = muted;
	if (muted) {
		sp->s_gain_eff = 0;
	} else {
		sp->s_gain_eff = sp->s_gain_scaled;
	}
	mutex_exit(&sp->s_lock);

	atomic_inc_uint(&sp->s_client->c_dev->d_serial);
}

boolean_t
auclnt_get_muted(audio_stream_t *sp)
{
	return (sp->s_muted);
}

boolean_t
auclnt_is_running(audio_stream_t *sp)
{
	return (sp->s_running);
}

void
auclnt_start(audio_stream_t *sp)
{
	mutex_enter(&sp->s_lock);
	sp->s_running = B_TRUE;
	mutex_exit(&sp->s_lock);
}

void
auclnt_stop(audio_stream_t *sp)
{
	mutex_enter(&sp->s_lock);
	/* if running, then stop it */
	if (sp->s_running) {
		sp->s_running = B_FALSE;
		/*
		 * if we stopped the engine, we might need to wake up
		 * a thread that is waiting for drain to complete.
		 */
		cv_broadcast(&sp->s_cv);
	}
	mutex_exit(&sp->s_lock);
}

/*
 * When pausing, no new data will be played after the most recently
 * mixed samples have played.  However, the audio engine will continue
 * to play (possibly just silence).
 *
 * Note that we don't reference count the device, or release/close the
 * engine here.  Once fired up, the engine continues running unil it
 * is closed.
 */
void
auclnt_set_paused(audio_stream_t *sp)
{
	mutex_enter(&sp->s_lock);
	if (sp->s_paused) {
		mutex_exit(&sp->s_lock);
		return;
	}
	sp->s_paused = B_TRUE;
	mutex_exit(&sp->s_lock);

	auclnt_stop(sp);

	atomic_inc_uint(&sp->s_client->c_dev->d_serial);
}

void
auclnt_clear_paused(audio_stream_t *sp)
{
	mutex_enter(&sp->s_lock);
	if (!sp->s_paused) {
		mutex_exit(&sp->s_lock);
		return;
	}
	sp->s_paused = B_FALSE;
	mutex_exit(&sp->s_lock);
}

boolean_t
auclnt_is_paused(audio_stream_t *sp)
{
	return (sp->s_paused);
}

void
auclnt_flush(audio_stream_t *sp)
{
	mutex_enter(&sp->s_lock);
	if (sp == &sp->s_client->c_ostream) {
		sp->s_tail = sp->s_head;
		sp->s_tidx = sp->s_hidx;
	} else {
		sp->s_head = sp->s_tail;
		sp->s_hidx = sp->s_tidx;
	}
	sp->s_cnv_cnt = 0;
	mutex_exit(&sp->s_lock);
}

int
auclnt_get_oflag(audio_client_t *c)
{
	return (c->c_omode);
}

/*
 * These routines should not be accessed by client "personality"
 * implementations, but are for private framework use only.
 */

void
auimpl_client_init(void)
{
	rw_init(&auimpl_client_lock, NULL, RW_DRIVER, NULL);
	list_create(&auimpl_clients, sizeof (struct audio_client),
	    offsetof(struct audio_client, c_global_linkage));
}

void
auimpl_client_fini(void)
{
	rw_destroy(&auimpl_client_lock);
	list_destroy(&auimpl_clients);
}

static int
auimpl_stream_init(audio_stream_t *sp, audio_client_t *c)
{
	mutex_init(&sp->s_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&sp->s_cv, NULL, CV_DRIVER, NULL);
	sp->s_client = c;

	if (sp == &c->c_ostream) {
		sp->s_user_parms = &sp->s_cnv_src_parms;
		sp->s_phys_parms = &sp->s_cnv_dst_parms;
		sp->s_engcap = ENGINE_OUTPUT_CAP;
	} else {
		ASSERT(sp == &c->c_istream);
		sp->s_user_parms = &sp->s_cnv_dst_parms;
		sp->s_phys_parms = &sp->s_cnv_src_parms;
		sp->s_engcap = ENGINE_INPUT_CAP;
	}

	/* for now initialize conversion parameters */
	sp->s_src_quality = 3;	/* reasonable compromise for now */
	sp->s_cnv_dst_nchan = 2;
	sp->s_cnv_dst_format = AUDIO_FORMAT_S24_NE;
	sp->s_cnv_dst_rate = 48000;
	sp->s_cnv_src_nchan = 2;
	sp->s_cnv_src_format = AUDIO_FORMAT_S24_NE;
	sp->s_cnv_src_rate = 48000;

	/* set volume/gain all the way up */
	sp->s_muted = B_FALSE;
	sp->s_gain_pct = 0;
	sp->s_gain_scaled = AUDIO_VOL_SCALE;
	sp->s_gain_eff = AUDIO_VOL_SCALE;

	/*
	 * We have to start off with a reasonable buffer and
	 * interrupt configuration.
	 */
	sp->s_allocsz = 65536;
	sp->s_data = ddi_umem_alloc(sp->s_allocsz, DDI_UMEM_NOSLEEP,
	    &sp->s_cookie);
	if (sp->s_data == NULL) {
		sp->s_allocsz = 0;
		audio_dev_warn(c->c_dev, "ddi_umem_alloc failed");
		return (ENOMEM);
	}
	/* make sure no stale data left in stream */
	bzero(sp->s_data, sp->s_allocsz);

	/*
	 * Allocate SRC and data conversion state.
	 */
	mutex_enter(&sp->s_lock);
	if (auimpl_format_alloc(sp) != 0) {
		mutex_exit(&sp->s_lock);
		return (ENOMEM);
	}

	mutex_exit(&sp->s_lock);

	return (0);
}


static void
audio_stream_fini(audio_stream_t *sp)
{
	auimpl_format_free(sp);
	if (sp->s_cnv_buf0)
		kmem_free(sp->s_cnv_buf0, sp->s_cnv_max);
	if (sp->s_cnv_buf1)
		kmem_free(sp->s_cnv_buf1, sp->s_cnv_max);
	mutex_destroy(&sp->s_lock);
	cv_destroy(&sp->s_cv);
	if (sp->s_data != NULL) {
		ddi_umem_free(sp->s_cookie);
		sp->s_data = NULL;
	}
}

int
auclnt_start_drain(audio_client_t *c)
{
	audio_stream_t	*sp;
	int		rv;

	sp = &c->c_ostream;

	/* start an asynchronous drain operation. */
	mutex_enter(&sp->s_lock);
	if (sp->s_paused || !sp->s_running) {
		rv = EALREADY;
	} else {
		sp->s_draining = B_TRUE;
		rv = 0;
	}
	mutex_exit(&sp->s_lock);
	return (rv);
}

int
auclnt_drain(audio_client_t *c)
{
	audio_stream_t	*sp;

	sp = &c->c_ostream;

	/*
	 * Note: Drain logic will automatically "stop" the stream when
	 * the drain threshold has been reached.  So all we have to do
	 * is wait for the stream to stop.
	 */
	mutex_enter(&sp->s_lock);
	sp->s_draining = B_TRUE;
	while (sp->s_draining && sp->s_running && !sp->s_paused) {
		if (cv_wait_sig(&sp->s_cv, &sp->s_lock) == 0) {
			mutex_exit(&sp->s_lock);
			return (EINTR);
		}
	}
	mutex_exit(&sp->s_lock);
	return (0);
}

audio_client_t *
auimpl_client_create(dev_t dev)
{
	audio_client_ops_t	*ops;
	audio_client_t		*c;
	audio_client_t		*next;
	list_t			*list = &auimpl_clients;
	minor_t			minor;
	audio_dev_t		*d;

	/* validate minor number */
	minor = getminor(dev) & AUDIO_MN_TYPE_MASK;
	if ((ops = audio_client_ops[minor]) == NULL) {
		return (NULL);
	}

	/* lookup device instance */
	if ((d = auimpl_dev_hold_by_devt(dev)) == NULL) {
		audio_dev_warn(NULL, "no audio_dev for dev_t %d,%d",
		    getmajor(dev), getminor(dev));
		return (NULL);
	}

	if ((c = kmem_zalloc(sizeof (*c), KM_NOSLEEP)) == NULL) {
		audio_dev_warn(d, "unable to allocate client structure");
		auimpl_dev_release(d);
		return (NULL);
	}
	c->c_dev = d;

	mutex_init(&c->c_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&c->c_cv, NULL, CV_DRIVER, NULL);

	if ((auimpl_stream_init(&c->c_ostream, c) != 0) ||
	    (auimpl_stream_init(&c->c_istream, c) != 0)) {
		goto failed;
	}

	c->c_major =		getmajor(dev);
	c->c_origminor =	getminor(dev);
	c->c_ops =		*ops;

	/*
	 * We hold the client lock here.
	 */
	rw_enter(&auimpl_client_lock, RW_WRITER);

	minor = AUDIO_MN_CLONE_MASK;
	for (next = list_head(list); next; next = list_next(list, next)) {
		if (next->c_minor > minor) {
			break;
		}
		minor++;
	}
	if (minor >= MAXMIN32) {
		rw_exit(&auimpl_client_lock);
		goto failed;
	}
	c->c_minor = minor;
	list_insert_before(list, next, c);

	rw_exit(&auimpl_client_lock);


	return (c);

failed:
	auimpl_dev_release(d);
	audio_stream_fini(&c->c_ostream);
	audio_stream_fini(&c->c_istream);
	mutex_destroy(&c->c_lock);
	cv_destroy(&c->c_cv);
	kmem_free(c, sizeof (*c));
	return (NULL);
}

void
auimpl_client_destroy(audio_client_t *c)
{
	/* remove us from the global list */
	rw_enter(&auimpl_client_lock, RW_WRITER);
	list_remove(&auimpl_clients, c);
	rw_exit(&auimpl_client_lock);

	ASSERT(!c->c_istream.s_running);
	ASSERT(!c->c_istream.s_running);

	/* release the device reference count */
	auimpl_dev_release(c->c_dev);
	c->c_dev = NULL;

	mutex_destroy(&c->c_lock);
	cv_destroy(&c->c_cv);

	audio_stream_fini(&c->c_istream);
	audio_stream_fini(&c->c_ostream);
	kmem_free(c, sizeof (*c));
}

void
auimpl_client_activate(audio_client_t *c)
{
	rw_enter(&auimpl_client_lock, RW_WRITER);
	c->c_is_active = B_TRUE;
	rw_exit(&auimpl_client_lock);
}

void
auimpl_client_deactivate(audio_client_t *c)
{
	rw_enter(&auimpl_client_lock, RW_WRITER);
	c->c_is_active = B_FALSE;
	rw_exit(&auimpl_client_lock);
}

void
auclnt_close(audio_client_t *c)
{
	audio_dev_t	*d = c->c_dev;

	/* stop the engines if they are running */
	auclnt_stop(&c->c_istream);
	auclnt_stop(&c->c_ostream);

	rw_enter(&auimpl_client_lock, RW_WRITER);
	list_remove(&d->d_clients, c);
	rw_exit(&auimpl_client_lock);

	mutex_enter(&c->c_lock);
	/* if in transition need to wait for other thread to release */
	while (c->c_refcnt) {
		cv_wait(&c->c_cv, &c->c_lock);
	}
	mutex_exit(&c->c_lock);

	/* release any engines that we were holding */
	auimpl_engine_close(&c->c_ostream);
	auimpl_engine_close(&c->c_istream);
}

audio_dev_t *
auclnt_hold_dev_by_index(int index)
{
	return (auimpl_dev_hold_by_index(index));
}

void
auclnt_release_dev(audio_dev_t *dev)
{
	auimpl_dev_release(dev);
}

audio_client_t *
auclnt_hold_by_devt(dev_t dev)
{
	minor_t	mn = getminor(dev);
	major_t mj = getmajor(dev);
	list_t *list;
	audio_client_t *c;

	list = &auimpl_clients;
	/* linked list search is kind of inefficient, but it works */
	rw_enter(&auimpl_client_lock, RW_READER);
	for (c = list_head(list); c != NULL; c = list_next(list, c)) {
		if ((c->c_major == mj) && (c->c_minor == mn)) {
			mutex_enter(&c->c_lock);
			if (c->c_is_active) {
				c->c_refcnt++;
				mutex_exit(&c->c_lock);
			} else {
				mutex_exit(&c->c_lock);
				c = NULL;
			}
			break;
		}
	}
	rw_exit(&auimpl_client_lock);
	return (c);
}

void
auclnt_release(audio_client_t *c)
{
	mutex_enter(&c->c_lock);
	ASSERT(c->c_refcnt > 0);
	c->c_refcnt--;
	if (c->c_refcnt == 0)
		cv_broadcast(&c->c_cv);
	mutex_exit(&c->c_lock);
}

unsigned
auclnt_dev_get_serial(audio_dev_t *d)
{
	return (d->d_serial);
}

void
auclnt_dev_walk_clients(audio_dev_t *d,
    int (*walker)(audio_client_t *, void *),
    void *arg)
{
	list_t		*l = &d->d_clients;
	audio_client_t	*c;
	int		rv;

	rw_enter(&auimpl_client_lock, RW_READER);
restart:
	for (c = list_head(l); c != NULL; c = list_next(l, c)) {
		if (!c->c_is_active)
			continue;
		rv = (walker(c, arg));
		if (rv == AUDIO_WALK_STOP) {
			break;
		} else if (rv == AUDIO_WALK_RESTART) {
			goto restart;
		}
	}
	rw_exit(&auimpl_client_lock);
}


int
auclnt_open(audio_client_t *c, unsigned fmts, int oflag)
{
	audio_stream_t	*sp;
	audio_dev_t	*d = c->c_dev;
	int		rv = 0;
	int		flags;
	audio_parms_t	parms;

	flags = 0;
	if (oflag & FNDELAY)
		flags |= ENGINE_NDELAY;

	if (oflag & FWRITE) {
		sp = &c->c_ostream;
		rv = auimpl_engine_open(d, fmts, flags | ENGINE_OUTPUT, sp);

		if (rv != 0) {
			goto done;
		}
		mutex_enter(&sp->s_lock);
		parms = *sp->s_user_parms;
		rv = auimpl_format_setup(sp, &parms);
		mutex_exit(&sp->s_lock);
		if (rv != 0) {
			goto done;
		}
	}

	if (oflag & FREAD) {
		sp = &c->c_istream;
		rv = auimpl_engine_open(d, fmts, flags | ENGINE_INPUT, sp);

		if (rv != 0) {
			goto done;
		}
		mutex_enter(&sp->s_lock);
		parms = *sp->s_user_parms;
		rv = auimpl_format_setup(sp, &parms);
		mutex_exit(&sp->s_lock);
		if (rv != 0) {
			goto done;
		}
	}

done:
	if (rv != 0) {
		/* close any engines that we opened */
		auimpl_engine_close(&c->c_ostream);
		auimpl_engine_close(&c->c_istream);
	} else {
		rw_enter(&auimpl_client_lock, RW_WRITER);
		list_insert_tail(&d->d_clients, c);
		c->c_ostream.s_gain_master = d->d_pcmvol;
		c->c_istream.s_gain_master = 100;
		rw_exit(&auimpl_client_lock);
		auclnt_set_gain(&c->c_ostream, 100);
		auclnt_set_gain(&c->c_istream, 100);
	}

	return (rv);
}

minor_t
auclnt_get_minor(audio_client_t *c)
{
	return (c->c_minor);
}

minor_t
auclnt_get_original_minor(audio_client_t *c)
{
	return (c->c_origminor);
}

minor_t
auclnt_get_minor_type(audio_client_t *c)
{
	return (c->c_origminor & AUDIO_MN_TYPE_MASK);
}

queue_t *
auclnt_get_rq(audio_client_t *c)
{
	return (c->c_rq);
}

queue_t *
auclnt_get_wq(audio_client_t *c)
{
	return (c->c_wq);
}

pid_t
auclnt_get_pid(audio_client_t *c)
{
	return (c->c_pid);
}

cred_t *
auclnt_get_cred(audio_client_t *c)
{
	return (c->c_cred);
}

audio_dev_t *
auclnt_get_dev(audio_client_t *c)
{
	return (c->c_dev);
}

int
auclnt_get_dev_number(audio_dev_t *dev)
{
	return (dev->d_number);
}

int
auclnt_get_dev_index(audio_dev_t *dev)
{
	return (dev->d_index);
}

const char *
auclnt_get_dev_name(audio_dev_t *dev)
{
	return (dev->d_name);
}

const char *
auclnt_get_dev_driver(audio_dev_t *dev)
{
	return (ddi_driver_name(dev->d_dip));
}

dev_info_t *
auclnt_get_dev_devinfo(audio_dev_t *dev)
{
	return (dev->d_dip);
}

const char *
auclnt_get_dev_hw_info(audio_dev_t *dev, void **iter)
{
	struct audio_infostr *isp = *iter;
	if (isp == NULL) {
		isp = list_head(&dev->d_hwinfo);
	} else {
		isp = list_next(&dev->d_hwinfo, isp);
	}

	*iter = isp;
	return (isp ? isp->i_line : NULL);
}

int
auclnt_get_dev_instance(audio_dev_t *dev)
{
	return (dev->d_instance);
}

const char *
auclnt_get_dev_description(audio_dev_t *dev)
{
	return (dev->d_desc);
}

const char *
auclnt_get_dev_version(audio_dev_t *dev)
{
	return (dev->d_vers);
}

unsigned
auclnt_get_dev_capab(audio_dev_t *dev)
{
	uint32_t	flags;
	unsigned	caps = 0;

	flags = dev->d_flags;

	if (flags & DEV_OUTPUT_CAP)
		caps |= AUDIO_CLIENT_CAP_PLAY;
	if (flags & DEV_INPUT_CAP)
		caps |= AUDIO_CLIENT_CAP_RECORD;
	if (flags & DEV_DUPLEX_CAP)
		caps |= AUDIO_CLIENT_CAP_DUPLEX;

	/* AC3: deal with formats that don't support mixing */

	return (caps);
}

uint64_t
auclnt_get_samples(audio_stream_t *sp)
{
	uint64_t	n;

	mutex_enter(&sp->s_lock);
	n = sp->s_samples;
	mutex_exit(&sp->s_lock);
	return (n);
}

void
auclnt_set_samples(audio_stream_t *sp, uint64_t n)
{
	mutex_enter(&sp->s_lock);
	sp->s_samples = n;
	mutex_exit(&sp->s_lock);
}

uint64_t
auclnt_get_errors(audio_stream_t *sp)
{
	uint64_t	n;
	mutex_enter(&sp->s_lock);
	n = sp->s_errors;
	mutex_exit(&sp->s_lock);
	return (n);
}

void
auclnt_set_errors(audio_stream_t *sp, uint64_t n)
{
	mutex_enter(&sp->s_lock);
	sp->s_errors = n;
	mutex_exit(&sp->s_lock);
}

void
auclnt_register_ops(minor_t minor, audio_client_ops_t *ops)
{
	/* we control minor number allocations, no need for runtime checks */
	ASSERT(minor <= AUDIO_MN_TYPE_MASK);

	audio_client_ops[minor] = ops;
}

int
auimpl_create_minors(audio_dev_t *d)
{
	char			path[MAXPATHLEN];
	int			rv = 0;
	minor_t			minor;
	audio_client_ops_t	*ops;
	char			*nt;

	for (int i = 0; i <= AUDIO_MN_TYPE_MASK; i++) {

		if ((ops = audio_client_ops[i]) == NULL)
			continue;

		if (ops->aco_dev_init != NULL)
			d->d_minor_data[i] = ops->aco_dev_init(d);

		switch (i) {
		case AUDIO_MINOR_SNDSTAT:
			if (!(d->d_flags & DEV_SNDSTAT_CAP)) {
				continue;
			}
			nt = DDI_PSEUDO;
			break;

		default:
			if (!(d->d_flags & (DEV_INPUT_CAP| DEV_OUTPUT_CAP))) {
				continue;
			}
			nt = DDI_NT_AUDIO;
			break;
		}

		if (ops->aco_minor_prefix != NULL) {

			minor = AUDIO_MKMN(d->d_instance, i);
			(void) snprintf(path, sizeof (path),
			    "%s%d", ops->aco_minor_prefix, d->d_instance);

			rv = ddi_create_minor_node(d->d_dip, path, S_IFCHR,
			    minor, nt, 0);

			if (rv != 0)
				break;
		}
	}
	return (rv);
}

void
auimpl_remove_minors(audio_dev_t *d)
{
	char			path[MAXPATHLEN];
	audio_client_ops_t	*ops;

	for (int i = 0; i <= AUDIO_MN_TYPE_MASK; i++) {
		if ((ops = audio_client_ops[i]) == NULL)
			continue;
		if (ops->aco_minor_prefix != NULL) {
			(void) snprintf(path, sizeof (path), "%s%d",
			    ops->aco_minor_prefix, d->d_instance);
			(void) ddi_remove_minor_node(d->d_dip, path);
		}

		if (ops->aco_dev_fini != NULL)
			ops->aco_dev_fini(d->d_minor_data[i]);
	}
}

void *
auclnt_get_dev_minor_data(audio_dev_t *d, minor_t mn)
{
	ASSERT(mn < (1U << AUDIO_MN_TYPE_NBITS));
	return (d->d_minor_data[mn]);
}

void *
auclnt_get_minor_data(audio_client_t *c, minor_t mn)
{
	ASSERT(mn < (1U << AUDIO_MN_TYPE_NBITS));
	return (c->c_dev->d_minor_data[mn]);
}

/*
 * This will walk all controls registered to a clients device and callback
 * to walker for each one with its audio_ctrl. Note this data
 * must be considered read only by walker.
 *
 * Note that walk_func may return values to continue (AUDIO_WALK_CONTINUE)
 * or stop walk (AUDIO_WALK_STOP).
 *
 */
void
auclnt_walk_controls(audio_dev_t *d,
    int (*walker)(audio_ctrl_t *, void *),
    void *arg)
{
	audio_ctrl_t *ctrl;

	rw_enter(&d->d_ctrl_lock, RW_READER);
	for (ctrl = list_head(&d->d_controls); ctrl;
	    ctrl = list_next(&d->d_controls, ctrl)) {
		if (walker(ctrl, arg) == AUDIO_WALK_STOP)
			break;
	}
	rw_exit(&d->d_ctrl_lock);
}

/*
 * This will search all controls attached to an
 * audio device for a control with the desired name.
 *
 * d    - the audio device to look on
 * name - name of the control being looked for.
 *
 * On successful return a ctrl handle will be returned. On
 * failure NULL is returned.
 */
audio_ctrl_t *
auclnt_find_control(audio_dev_t *d, const char *name)
{
	audio_ctrl_t *ctrl;

	/* Verify argument */
	ASSERT(d);

	rw_enter(&d->d_ctrl_lock, RW_READER);
	for (ctrl = list_head(&d->d_controls); ctrl;
	    ctrl = list_next(&d->d_controls, ctrl)) {
		if (strcmp(ctrl->ctrl_name, name) == 0) {
			rw_exit(&d->d_ctrl_lock);
			return (ctrl);
		}
	}
	rw_exit(&d->d_ctrl_lock);
	return (NULL);
}

/*
 * Given a known control, get its attributes.
 *
 * The caller must supply a audio_ctrl_desc_t structure.  Also the
 * values in the structure are ignored when making the call and filled
 * in by this function. All data pointed to by elements of desc should
 * be assumed read only.
 *
 * If an error occurs then a non-zero is returned.
 *
 */
int
auclnt_control_describe(audio_ctrl_t *ctrl, audio_ctrl_desc_t *desc)
{
	ASSERT(ctrl);
	ASSERT(desc);

	bcopy(&ctrl->ctrl_des, desc, sizeof (*desc));
	return (0);
}

int
auclnt_control_read(audio_ctrl_t *ctrl, uint64_t *value)
{
	return (audio_control_read(ctrl, value));
}

int
auclnt_control_write(audio_ctrl_t *ctrl, uint64_t value)
{
	return (audio_control_write(ctrl, value));
}

void
auclnt_warn(audio_client_t *c, const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	auimpl_dev_vwarn(c ? c->c_dev : NULL, fmt, va);
	va_end(va);
}
