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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/list.h>
#include <sys/sysmacros.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/callb.h>
#include <sys/kstat.h>
#include <sys/note.h>

#include "audio_impl.h"

/*
 * Audio Engine functions.
 */

/*
 * Globals
 */
uint_t		audio_intrhz = AUDIO_INTRHZ;
/*
 * We need to operate at fairly high interrupt priority to avoid
 * underruns due to other less time sensitive processing.
 */
int		audio_priority = DDI_IPL_8;

audio_dev_t *
audio_dev_alloc(dev_info_t *dip, int instance)
{
	audio_dev_t *d;

	/*
	 * For a card with multiple independent audio ports on it, we
	 * allow the driver to provide a different instance numbering
	 * scheme than the standard DDI instance number.  (This is
	 * sort of like the PPA numbering scheme used by NIC drivers
	 * -- by default PPA == instance, but sometimes we need more
	 * flexibility.)
	 */
	if (instance == 0) {
		instance = ddi_get_instance(dip);
	}
	/* generally this shouldn't occur */
	if (instance > AUDIO_MN_INST_MASK) {
		audio_dev_warn(NULL, "bad instance number for %s (%d)",
		    ddi_driver_name(dip), instance);
		return (NULL);
	}

	if ((d = kmem_zalloc(sizeof (*d), KM_NOSLEEP)) == NULL) {
		audio_dev_warn(NULL, "unable to allocate audio device struct");
		return (NULL);
	}
	d->d_dip = dip;
	d->d_number = -1;
	d->d_major = ddi_driver_major(dip);
	d->d_instance = instance;
	d->d_pcmvol = 100;
	mutex_init(&d->d_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&d->d_cv, NULL, CV_DRIVER, NULL);
	mutex_init(&d->d_ctrl_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&d->d_ctrl_cv, NULL, CV_DRIVER, NULL);
	list_create(&d->d_clients, sizeof (struct audio_client),
	    offsetof(struct audio_client, c_dev_linkage));
	list_create(&d->d_engines, sizeof (struct audio_engine),
	    offsetof(struct audio_engine, e_dev_linkage));
	list_create(&d->d_controls, sizeof (struct audio_ctrl),
	    offsetof(struct audio_ctrl, ctrl_linkage));
	list_create(&d->d_hwinfo, sizeof (struct audio_infostr),
	    offsetof(struct audio_infostr, i_linkage));
	(void) snprintf(d->d_name, sizeof (d->d_name), "%s#%d",
	    ddi_driver_name(dip), instance);

	return (d);
}

void
audio_dev_free(audio_dev_t *d)
{
	struct audio_infostr *isp;

	while ((isp = list_remove_head(&d->d_hwinfo)) != NULL) {
		kmem_free(isp, sizeof (*isp));
	}
	if (d->d_pcmvol_ctrl != NULL) {
		audio_dev_del_control(d->d_pcmvol_ctrl);
	}
	list_destroy(&d->d_hwinfo);
	list_destroy(&d->d_engines);
	list_destroy(&d->d_controls);
	list_destroy(&d->d_clients);
	mutex_destroy(&d->d_ctrl_lock);
	mutex_destroy(&d->d_lock);
	cv_destroy(&d->d_cv);
	cv_destroy(&d->d_ctrl_cv);
	kmem_free(d, sizeof (*d));
}

void
audio_dev_set_description(audio_dev_t *d, const char *desc)
{
	(void) strlcpy(d->d_desc, desc, sizeof (d->d_desc));
}

void
audio_dev_set_version(audio_dev_t *d, const char *vers)
{
	(void) strlcpy(d->d_vers, vers, sizeof (d->d_vers));
}

void
audio_dev_add_info(audio_dev_t *d, const char *info)
{
	struct audio_infostr *isp;

	/* failure to add information structure is not critical */
	isp = kmem_zalloc(sizeof (*isp), KM_NOSLEEP);
	if (isp == NULL) {
		audio_dev_warn(d, "unable to allocate information structure");
	} else {
		(void) snprintf(isp->i_line, sizeof (isp->i_line), info);
		list_insert_tail(&d->d_hwinfo, isp);
	}
}

static void
auimpl_engine_reset(audio_engine_t *e)
{
	char	*buf;
	char	*ptr;
	int	nfr, resid, cnt;
	int	tidx;

	tidx = e->e_tidx;
	nfr = min(e->e_head - e->e_tail, e->e_nframes);
	buf = kmem_alloc(nfr * e->e_framesz, KM_SLEEP);
	ptr = buf;
	cnt = 0;

	ASSERT(e->e_nframes);

	for (resid = nfr; resid; resid -= cnt) {
		int	nbytes;

		cnt = min((e->e_nframes - tidx), resid);
		nbytes = cnt * e->e_framesz;

		bcopy(e->e_data + (tidx * e->e_framesz), ptr, nbytes);
		ptr += nbytes;
		tidx += cnt;
		if (tidx == e->e_nframes) {
			tidx = 0;
		}
	}

	if (e->e_flags & ENGINE_INPUT) {
		/* record */
		e->e_hidx = 0;
		e->e_tidx = (e->e_nframes - nfr) % e->e_nframes;
	} else {
		/* play */
		e->e_hidx = nfr % e->e_nframes;
		e->e_tidx = 0;
	}

	/* relocate from scratch area to destination */
	bcopy(buf, e->e_data + (e->e_tidx * e->e_framesz), nfr * e->e_framesz);
	kmem_free(buf, nfr * e->e_framesz);
}

static volatile uint_t auimpl_engno = 0;

audio_engine_t *
audio_engine_alloc(audio_engine_ops_t *ops, uint_t flags)
{
	int i;
	audio_engine_t *e;
	char tname[32];
	int num;

	if (ops->audio_engine_version != AUDIO_ENGINE_VERSION) {
		audio_dev_warn(NULL, "audio engine version mismatch: %d != %d",
		    ops->audio_engine_version, AUDIO_ENGINE_VERSION);
		return (NULL);
	}

	/* NB: The ops vector must be held in persistent storage! */
	e = kmem_zalloc(sizeof (audio_engine_t), KM_NOSLEEP);
	if (e == NULL) {
		audio_dev_warn(NULL, "unable to allocate engine struct");
		return (NULL);
	}
	e->e_ops = *ops;
	mutex_init(&e->e_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(audio_priority));
	cv_init(&e->e_cv, NULL, CV_DRIVER, NULL);
	list_create(&e->e_streams, sizeof (struct audio_stream),
	    offsetof(struct audio_stream, s_eng_linkage));

	for (i = 0; i < AUDIO_MAX_CHANNELS; i++) {
		e->e_chbufs[i] = kmem_zalloc(sizeof (int32_t) * AUDIO_CHBUFS,
		    KM_NOSLEEP);
		if (e->e_chbufs[i] == NULL) {
			audio_dev_warn(NULL, "unable to allocate channel buf");
			audio_engine_free(e);
			return (NULL);
		}
	}

	num = atomic_inc_uint_nv(&auimpl_engno);

	(void) snprintf(tname, sizeof (tname), "audio_engine_%d", num);

	e->e_flags = flags & ENGINE_DRIVER_FLAGS;
	return (e);
}

void
audio_engine_free(audio_engine_t *e)
{
	int i;

	for (i = 0; i < AUDIO_MAX_CHANNELS; i++) {
		if (e->e_chbufs[i] != NULL) {
			kmem_free(e->e_chbufs[i],
			    sizeof (int32_t) * AUDIO_CHBUFS);
		}
	}

	list_destroy(&e->e_streams);
	mutex_destroy(&e->e_lock);
	cv_destroy(&e->e_cv);
	kmem_free(e, sizeof (*e));
}

static list_t auimpl_devs_by_index;
static list_t auimpl_devs_by_number;
static krwlock_t auimpl_dev_lock;

/*
 * Not for public consumption: Private interfaces.
 */
void
auimpl_dev_hold(audio_dev_t *d)
{
	/* bump the reference count */
	mutex_enter(&d->d_lock);
	d->d_refcnt++;
	mutex_exit(&d->d_lock);
}

audio_dev_t *
auimpl_dev_hold_by_devt(dev_t dev)
{
	audio_dev_t *d;
	major_t major;
	int instance;
	list_t *l = &auimpl_devs_by_index;

	major = getmajor(dev);
	instance = (getminor(dev) >> AUDIO_MN_INST_SHIFT) & AUDIO_MN_INST_MASK;

	rw_enter(&auimpl_dev_lock, RW_READER);

	for (d = list_head(l); d; d = list_next(l, d)) {
		if ((d->d_major == major) && (d->d_instance == instance)) {
			auimpl_dev_hold(d);
			break;
		}
	}

	rw_exit(&auimpl_dev_lock);
	return (d);
}

audio_dev_t *
auimpl_dev_hold_by_index(int index)
{
	audio_dev_t *d;
	list_t *l = &auimpl_devs_by_index;

	rw_enter(&auimpl_dev_lock, RW_READER);

	for (d = list_head(l); d; d = list_next(l, d)) {
		if (d->d_index == index) {
			auimpl_dev_hold(d);
			break;
		}
	}

	rw_exit(&auimpl_dev_lock);
	return (d);
}

void
auimpl_dev_release(audio_dev_t *d)
{
	mutex_enter(&d->d_lock);
	d->d_refcnt--;
	mutex_exit(&d->d_lock);
}

int
auimpl_choose_format(int fmts)
{
	/*
	 * Choose the very best format we can.  We choose 24 bit in
	 * preference to 32 bit because we mix in 24 bit.  We do that
	 * to allow overflows to fit within 32-bits.  (Very few humans
	 * can tell a difference between 24 and 32 bit audio anyway.)
	 */
	if (fmts & AUDIO_FORMAT_S24_NE)
		return (AUDIO_FORMAT_S24_NE);

	if (fmts & AUDIO_FORMAT_S32_NE)
		return (AUDIO_FORMAT_S32_NE);

	if (fmts & AUDIO_FORMAT_S24_OE)
		return (AUDIO_FORMAT_S24_OE);

	if (fmts & AUDIO_FORMAT_S32_OE)
		return (AUDIO_FORMAT_S32_OE);

	if (fmts & AUDIO_FORMAT_S16_NE)
		return (AUDIO_FORMAT_S16_NE);

	if (fmts & AUDIO_FORMAT_S16_OE)
		return (AUDIO_FORMAT_S16_OE);

	if (fmts & AUDIO_FORMAT_AC3)
		return (AUDIO_FORMAT_AC3);

	return (AUDIO_FORMAT_NONE);
}

int
auimpl_engine_open(audio_stream_t *sp, int flags)
{
	return (auimpl_engine_setup(sp, flags, NULL, FORMAT_MSK_NONE));
}


int
auimpl_engine_setup(audio_stream_t *sp, int flags, audio_parms_t *parms,
    uint_t mask)
{
	audio_dev_t	*d = sp->s_client->c_dev;
	audio_engine_t	*e = NULL;
	audio_parms_t	uparms;
	list_t		*list;
	uint_t		cap;
	int		priority = 0;
	int		rv = ENODEV;
	int		sampsz;
	int		i;
	int		fragfr;
	int		fmts;


	mutex_enter(&d->d_lock);

	uparms = *sp->s_user_parms;
	if (mask & FORMAT_MSK_FMT)
		uparms.p_format = parms->p_format;
	if (mask & FORMAT_MSK_RATE)
		uparms.p_rate = parms->p_rate;
	if (mask & FORMAT_MSK_CHAN)
		uparms.p_nchan = parms->p_nchan;

	/*
	 * Which direction are we opening?  (We must open exactly
	 * one direction, otherwise the open is meaningless.)
	 */

	if (sp == &sp->s_client->c_ostream) {
		cap = ENGINE_OUTPUT_CAP;
		flags |= ENGINE_OUTPUT;
	} else {
		cap = ENGINE_INPUT_CAP;
		flags |= ENGINE_INPUT;
	}

	if (uparms.p_format == AUDIO_FORMAT_AC3) {
		fmts = AUDIO_FORMAT_AC3;
		flags |= ENGINE_EXCLUSIVE;
	} else {
		fmts = AUDIO_FORMAT_PCM;
	}

	list = &d->d_engines;


	/* If the device is suspended, wait for it to resume. */
	while (d->d_suspended) {
		cv_wait(&d->d_ctrl_cv, &d->d_lock);
	}

again:

	for (audio_engine_t *t = list_head(list); t; t = list_next(list, t)) {
		int		mypri;
		int		r;

		/* Make sure the engine can do what we want it to. */
		mutex_enter(&t->e_lock);

		if ((t->e_flags & cap) == 0) {
			mutex_exit(&t->e_lock);
			continue;
		}

		/*
		 * Open the engine early, as the inquiries to rate and format
		 * may not be accurate until this is done.
		 */
		if (list_is_empty(&t->e_streams)) {
			if (ENG_OPEN(t, flags, &t->e_nframes, &t->e_data)) {
				mutex_exit(&t->e_lock);
				rv = EIO;
				continue;
			}
		}

		if ((ENG_FORMAT(t) & fmts) == 0) {
			if (list_is_empty(&t->e_streams))
				ENG_CLOSE(t);
			mutex_exit(&t->e_lock);
			continue;
		}


		/* If it is in failed state, don't use this engine. */
		if (t->e_failed) {
			if (list_is_empty(&t->e_streams))
				ENG_CLOSE(t);
			mutex_exit(&t->e_lock);
			rv = rv ? EIO : 0;
			continue;
		}

		/*
		 * If the engine is in exclusive use, we can't use it.
		 * This is intended for use with AC3 or digital
		 * streams that cannot tolerate mixing.
		 */
		if ((t->e_flags & ENGINE_EXCLUSIVE) && (t != sp->s_engine)) {
			if (list_is_empty(&t->e_streams))
				ENG_CLOSE(t);
			mutex_exit(&t->e_lock);
			rv = rv ? EBUSY : 0;
			continue;
		}

		/*
		 * If the engine is in use incompatibly, we can't use
		 * it.  This should only happen for half-duplex audio
		 * devices.  I've not seen any of these that are
		 * recent enough to be supported by Solaris.
		 */
		if (((flags & ENGINE_INPUT) && (t->e_flags & ENGINE_OUTPUT)) ||
		    ((flags & ENGINE_OUTPUT) && (t->e_flags & ENGINE_INPUT))) {
			if (list_is_empty(&t->e_streams))
				ENG_CLOSE(t);
			mutex_exit(&t->e_lock);
			/* Only override the ENODEV or EIO. */
			rv = rv ? EBUSY : 0;
			continue;
		}

		/*
		 * In order to support as many different possible
		 * output streams (e.g. AC3 passthru or AC3 decode),
		 * or multiple exclusive outputs, we treat audio
		 * engines as *precious*.
		 *
		 * This means that we will try hard to reuse an
		 * existing allocated engine.  This may not be the
		 * optimal performance configuration (especially if we
		 * wanted to avoid rate conversion, for example), but
		 * it should have fewer cases where the configuration
		 * results in denying service to any client.
		 */

		/*
		 * This engine *can* support us, so we should no longer
		 * have a failure mode.
		 */
		rv = 0;
		mypri = (1U << 0);


		/*
		 * Mixing is cheap, so try not to pick on idle
		 * engines.  This avoids burning bus bandwidth (which
		 * may be precious for certain classes of traffic).
		 * Note that idleness is given a low priority compared
		 * to the other considerations.
		 *
		 * We also use this opportunity open the engine, if
		 * not already done so, so that our parameter
		 * inquiries will be valid.
		 */
		if (!list_is_empty(&t->e_streams))
			mypri |= (1U << 1);

		/*
		 * Slight preference is given to reuse an engine that
		 * we might already be using.
		 */
		if (t == sp->s_engine)
			mypri |= (1U << 2);


		/*
		 * Sample rate conversion avoidance.  Upsampling
		 * requires multiplications and is moderately
		 * expensive.  Downsampling requires division and is
		 * quite expensive, and hence to be avoided if at all
		 * possible.
		 */
		r = ENG_RATE(t);
		if (uparms.p_rate == r) {
			/*
			 * No conversion needed at all.  This is ideal.
			 */
			mypri |= (1U << 4) | (1U << 3);
		} else {
			int src, dst;

			if (flags & ENGINE_INPUT) {
				src = r;
				dst = uparms.p_rate;
			} else {
				src = uparms.p_rate;
				dst = r;
			}
			if ((src < dst) && ((dst % src) == 0)) {
				/*
				 * Pure upsampling only. This
				 * penalizes any engine which requires
				 * downsampling.
				 */
				mypri |= (1U << 3);
			}
		}

		/*
		 * Try not to pick on duplex engines.  This way we
		 * leave engines that can be used for recording or
		 * playback available as such.  All modern drivers
		 * use separate unidirectional engines for playback
		 * and record.
		 */
		if ((t->e_flags & ENGINE_CAPS) == cap) {
			mypri |= (1U << 5);
		}

		/*
		 * Try not to pick on engines that can do other
		 * formats.  This will generally be false, but if it
		 * happens we pretty strongly avoid using a limited
		 * resource.
		 */
		if ((t->e_format & ~fmts) == 0) {
			mypri |= (1U << 6);
		}

		if (mypri > priority) {
			if (e != NULL) {
				/*
				 * If we opened this for our own use
				 * and we are no longer using it, then
				 * close it back down.
				 */
				if (list_is_empty(&e->e_streams))
					ENG_CLOSE(e);
				mutex_exit(&e->e_lock);
			}
			e = t;
			priority = mypri;
		} else {
			mutex_exit(&t->e_lock);
		}

		/*
		 * Locking: at this point, if we have an engine, "e", it is
		 * locked.  No other engines should have a lock held.
		 */
	}

	if ((rv == EBUSY) && ((flags & ENGINE_NDELAY) == 0)) {
		ASSERT(e == NULL);
		if (cv_wait_sig(&d->d_cv, &d->d_lock) == 0) {
			mutex_exit(&d->d_lock);
			return (EINTR);
		}
		goto again;
	}

	if (rv != 0) {
		ASSERT(e == NULL);
		mutex_exit(&d->d_lock);
		return (rv);
	}

	ASSERT(e != NULL);
	ASSERT(mutex_owned(&e->e_lock));

	if (sp->s_engine && (sp->s_engine != e)) {
		/*
		 * If this represents a potential engine change, then
		 * we close off everything, and start anew. This turns
		 * out to be vastly simpler than trying to close all
		 * the races associated with a true hand off.  This
		 * ought to be relatively uncommon (changing engines).
		 */

		/* Drop the new reference. */
		if (list_is_empty(&e->e_streams))
			ENG_CLOSE(e);
		mutex_exit(&e->e_lock);
		mutex_exit(&d->d_lock);

		auimpl_engine_close(sp);

		/* Try again. */
		return (auimpl_engine_setup(sp, flags, parms, mask));
	}

	if (sp->s_engine == NULL) {
		/*
		 * Add a reference to this engine if we don't already
		 * have one.
		 */
		sp->s_engine = e;

		if (!list_is_empty(&e->e_streams)) {
			/*
			 * If the engine is already open, there is no
			 * need for further work.  The first open will
			 * be relatively expensive, but subsequent
			 * opens should be as cheap as possible.
			 */
			list_insert_tail(&e->e_streams, sp);
			goto ok;
		}
		list_insert_tail(&e->e_streams, sp);

	} else {
		ASSERT(sp->s_engine == e);
		/*
		 * No change in engine... hence don't reprogram the
		 * engine, and don't change references.
		 */
		goto ok;
	}

	e->e_format = ENG_FORMAT(e);
	e->e_nchan = ENG_CHANNELS(e);
	e->e_rate = ENG_RATE(e);

	/* Select format converters for the engine. */
	switch (e->e_format) {
	case AUDIO_FORMAT_S24_NE:
		e->e_export = auimpl_export_24ne;
		e->e_import = auimpl_import_24ne;
		sampsz = 4;
		break;
	case AUDIO_FORMAT_S32_NE:
		e->e_export = auimpl_export_32ne;
		e->e_import = auimpl_import_32ne;
		sampsz = 4;
		break;
	case AUDIO_FORMAT_S24_OE:
		e->e_export = auimpl_export_24oe;
		e->e_import = auimpl_import_24oe;
		sampsz = 4;
		break;
	case AUDIO_FORMAT_S32_OE:
		e->e_export = auimpl_export_32oe;
		e->e_import = auimpl_import_32oe;
		sampsz = 4;
		break;
	case AUDIO_FORMAT_S16_NE:
		e->e_export = auimpl_export_16ne;
		e->e_import = auimpl_import_16ne;
		sampsz = 2;
		break;
	case AUDIO_FORMAT_S16_OE:
		e->e_export = auimpl_export_16oe;
		e->e_import = auimpl_import_16oe;
		sampsz = 2;
		break;
	case AUDIO_FORMAT_AC3:
		e->e_export = auimpl_export_24ne;
		e->e_import = auimpl_import_24ne;
		flags |= ENGINE_EXCLUSIVE;
		sampsz = 2;
		break;
	default:
		audio_dev_warn(d, "bad format");
		rv = ENOTSUP;
		goto done;
	}

	fragfr = e->e_rate / audio_intrhz;
	if ((fragfr > AUDIO_CHBUFS) || (fragfr < 1)) {
		audio_dev_warn(d, "invalid fragment configration");
		rv = EINVAL;
		goto done;
	}

	/* Sanity test a few values. */
	if ((e->e_nchan < 0) || (e->e_nchan > AUDIO_MAX_CHANNELS) ||
	    (e->e_rate < 5000) || (e->e_rate > 192000)) {
		audio_dev_warn(d, "bad engine channels or rate");
		rv = EINVAL;
		goto done;
	}

	if ((e->e_nframes <= (fragfr * 2)) || (e->e_data == NULL)) {
		audio_dev_warn(d, "improper engine configuration");
		rv = EINVAL;
		goto done;
	}

	e->e_framesz = e->e_nchan * sampsz;
	e->e_fragfr = fragfr;
	e->e_head = 0;
	e->e_tail = 0;
	e->e_hidx = 0;
	e->e_tidx = 0;
	e->e_limiter_state = 0x10000;
	bzero(e->e_data, e->e_nframes * e->e_framesz);

	if (e->e_ops.audio_engine_playahead == NULL) {
		e->e_playahead = (fragfr * 3) / 2;
	} else {
		e->e_playahead = ENG_PLAYAHEAD(e);
		/*
		 * Need to have at least a fragment plus some extra to
		 * avoid underruns.
		 */
		if (e->e_playahead < ((fragfr * 3) / 2)) {
			e->e_playahead = (fragfr * 3) / 2;
		}

		/*
		 * Impossible to queue more frames than FIFO can hold.
		 */
		if (e->e_playahead > e->e_nframes) {
			e->e_playahead = (fragfr * 3) / 2;
		}
	}

	for (i = 0; i < e->e_nchan; i++) {
		if (e->e_ops.audio_engine_chinfo == NULL) {
			e->e_choffs[i] = i;
			e->e_chincr[i] = e->e_nchan;
		} else {
			ENG_CHINFO(e, i, &e->e_choffs[i], &e->e_chincr[i]);
		}
	}

	e->e_flags |= flags;

	/*
	 * Arrange for the engine to be started.  We defer this to the
	 * periodic callback, to ensure that the start happens near
	 * the edge of the periodic callback.  This is necessary to
	 * ensure that the first fragment processed is about the same
	 * size as the usual fragment size.  (Basically, the problem
	 * is that we have only 10 msec resolution with the periodic
	 * interface, whch is rather unfortunate.)
	 */
	e->e_need_start = B_TRUE;

	if (flags & ENGINE_OUTPUT) {
		/*
		 * Start the output callback to populate the engine on
		 * startup.  This avoids a false underrun when we're
		 * first starting up.
		 */
		auimpl_output_preload(e);

		e->e_periodic = ddi_periodic_add(auimpl_output_callback, e,
		    NANOSEC / audio_intrhz, audio_priority);
	} else {
		e->e_periodic = ddi_periodic_add(auimpl_input_callback, e,
		    NANOSEC / audio_intrhz, audio_priority);
	}

ok:
	sp->s_phys_parms->p_rate = e->e_rate;
	sp->s_phys_parms->p_nchan = e->e_nchan;

	/* Configure the engine. */
	mutex_enter(&sp->s_lock);
	rv = auimpl_format_setup(sp, parms, mask);
	mutex_exit(&sp->s_lock);

done:
	mutex_exit(&e->e_lock);
	mutex_exit(&d->d_lock);

	return (rv);
}

void
auimpl_engine_close(audio_stream_t *sp)
{
	audio_engine_t	*e = sp->s_engine;
	audio_dev_t	*d;
	ddi_periodic_t	ep;

	if (e == NULL)
		return;

	d = e->e_dev;
	ep = 0;

	mutex_enter(&d->d_lock);
	while (d->d_suspended) {
		cv_wait(&d->d_ctrl_cv, &d->d_lock);
	}

	mutex_enter(&e->e_lock);
	sp->s_engine = NULL;
	list_remove(&e->e_streams, sp);
	if (list_is_empty(&e->e_streams)) {
		ENG_STOP(e);
		ep = e->e_periodic;
		e->e_periodic = 0;
		e->e_flags &= ENGINE_DRIVER_FLAGS;
		ENG_CLOSE(e);
	}
	mutex_exit(&e->e_lock);

	if (ep != 0)
		ddi_periodic_delete(ep);

	cv_broadcast(&d->d_cv);
	mutex_exit(&d->d_lock);
}

int
audio_dev_register(audio_dev_t *d)
{
	list_t *l;
	audio_dev_t *srch;
	int start;

	/*
	 * Make sure we don't automatically unload.  This prevents
	 * loss of hardware settings when no audio clients are
	 * running.
	 */
	(void) ddi_prop_update_int(DDI_DEV_T_NONE, d->d_dip,
	    DDI_NO_AUTODETACH, 1);

	/*
	 * This does an in-order insertion, finding the first available
	 * free index.  "Special" devices (ones without any actual engines)
	 * are all numbered 0.  There should only be one of them anyway.
	 * All others start at one.
	 */
	if (d->d_flags & DEV_SNDSTAT_CAP) {
		start = 0;
	} else {
		start = 1;
	}
	d->d_index = start;

	rw_enter(&auimpl_dev_lock, RW_WRITER);
	l = &auimpl_devs_by_index;
	for (srch = list_head(l); srch; srch = list_next(l, srch)) {
		/* skip over special nodes */
		if (srch->d_index < start)
			continue;
		if (srch->d_index > d->d_index) {
			/* found a free spot! */
			break;
		}
		d->d_index++;
	}
	/*
	 * NB: If srch is NULL, then list_insert_before puts
	 * it on the tail of the list.  So if we didn't find a
	 * hole, then that's where we want it.
	 */
	list_insert_before(l, srch, d);

	/* insert in order by number */
	l = &auimpl_devs_by_number;
	for (srch = list_head(l); srch; srch = list_next(l, srch)) {
		if (srch->d_number >= d->d_number) {
			break;
		}
	}
	list_insert_before(l, srch, d);

	rw_exit(&auimpl_dev_lock);

	if (auimpl_create_minors(d) != 0) {
		rw_enter(&auimpl_dev_lock, RW_WRITER);
		auimpl_remove_minors(d);
		list_remove(&auimpl_devs_by_index, d);
		list_remove(&auimpl_devs_by_number, d);
		rw_exit(&auimpl_dev_lock);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

int
audio_dev_unregister(audio_dev_t *d)
{
	rw_enter(&auimpl_dev_lock, RW_WRITER);

	mutex_enter(&d->d_lock);
	/* if we are still in use, we can't unregister */
	if (d->d_refcnt) {
		mutex_exit(&d->d_lock);
		rw_exit(&auimpl_dev_lock);
		return (DDI_FAILURE);
	}
	auimpl_remove_minors(d);
	list_remove(&auimpl_devs_by_index, d);
	list_remove(&auimpl_devs_by_number, d);
	mutex_exit(&d->d_lock);

	rw_exit(&auimpl_dev_lock);

	return (DDI_SUCCESS);
}

static int
auimpl_engine_ksupdate(kstat_t *ksp, int rw)
{
	audio_engine_t *e = ksp->ks_private;
	struct audio_stats *st = &e->e_stats;

	if (rw == KSTAT_WRITE) {
		return (EACCES);
	}

	mutex_enter(&e->e_lock);
	st->st_head.value.ui64 = e->e_head;
	st->st_tail.value.ui64 = e->e_tail;
	st->st_flags.value.ui32 = e->e_flags;
	st->st_nbytes.value.ui32 = e->e_framesz * e->e_nframes;
	st->st_framesz.value.ui32 = e->e_framesz;
	st->st_hidx.value.ui32 = e->e_hidx;
	st->st_tidx.value.ui32 = e->e_tidx;
	st->st_format.value.ui32 = e->e_format;
	st->st_nchan.value.ui32 = e->e_nchan;
	st->st_rate.value.ui32 = e->e_rate;
	st->st_errors.value.ui32 = e->e_errors;
	st->st_engine_underruns.value.ui32 = e->e_underruns;
	st->st_engine_overruns.value.ui32 = e->e_overruns;
	st->st_stream_underruns.value.ui32 = e->e_stream_underruns;
	st->st_stream_overruns.value.ui32 = e->e_stream_overruns;
	st->st_suspended.value.ui32 = e->e_suspended;
	st->st_failed.value.ui32 = e->e_failed;
	st->st_playahead.value.ui32 = e->e_playahead;
	mutex_exit(&e->e_lock);

	return (0);
}

static void
auimpl_engine_ksinit(audio_dev_t *d, audio_engine_t *e)
{
	char			name[32];
	struct audio_stats	*st;

	(void) snprintf(name, sizeof (name), "engine_%d", e->e_num);

	e->e_ksp = kstat_create(ddi_driver_name(d->d_dip), d->d_instance,
	    name, "misc", KSTAT_TYPE_NAMED,
	    sizeof (struct audio_stats) / sizeof (kstat_named_t), 0);

	if (e->e_ksp == NULL) {
		audio_dev_warn(d, "unable to initialize kstats");
		return;
	}

	st = &e->e_stats;
	e->e_ksp->ks_data = st;
	e->e_ksp->ks_private = e;
	e->e_ksp->ks_lock = NULL;
	e->e_ksp->ks_update = auimpl_engine_ksupdate;
	kstat_named_init(&st->st_head, "head", KSTAT_DATA_UINT64);
	kstat_named_init(&st->st_tail, "tail", KSTAT_DATA_UINT64);
	kstat_named_init(&st->st_flags, "flags", KSTAT_DATA_UINT32);
	kstat_named_init(&st->st_nbytes, "nbytes", KSTAT_DATA_UINT32);
	kstat_named_init(&st->st_framesz, "framesz", KSTAT_DATA_UINT32);
	kstat_named_init(&st->st_hidx, "hidx", KSTAT_DATA_UINT32);
	kstat_named_init(&st->st_tidx, "tidx", KSTAT_DATA_UINT32);
	kstat_named_init(&st->st_format, "format", KSTAT_DATA_UINT32);
	kstat_named_init(&st->st_nchan, "channels", KSTAT_DATA_UINT32);
	kstat_named_init(&st->st_rate, "rate", KSTAT_DATA_UINT32);
	kstat_named_init(&st->st_errors, "errors", KSTAT_DATA_UINT32);
	kstat_named_init(&st->st_engine_overruns, "engine_overruns",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&st->st_engine_underruns, "engine_underruns",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&st->st_stream_overruns, "stream_overruns",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&st->st_stream_underruns, "stream_underruns",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&st->st_playahead, "playahead", KSTAT_DATA_UINT32);
	kstat_named_init(&st->st_suspended, "suspended", KSTAT_DATA_UINT32);
	kstat_named_init(&st->st_failed, "failed", KSTAT_DATA_UINT32);
	kstat_install(e->e_ksp);
}

void
audio_dev_add_engine(audio_dev_t *d, audio_engine_t *e)
{
	mutex_enter(&d->d_lock);

	e->e_num = d->d_engno++;

	auimpl_engine_ksinit(d, e);

	/* check for duplex */
	if ((e->e_flags & ENGINE_OUTPUT_CAP) && (d->d_flags & DEV_INPUT_CAP)) {
		d->d_flags |= DEV_DUPLEX_CAP;
	}
	if ((e->e_flags & ENGINE_INPUT_CAP) && (d->d_flags & DEV_OUTPUT_CAP)) {
		d->d_flags |= DEV_DUPLEX_CAP;
	}
	/* add in the direction caps -- must be done after duplex above */
	if (e->e_flags & ENGINE_OUTPUT_CAP) {
		d->d_flags |= DEV_OUTPUT_CAP;
	}
	if (e->e_flags & ENGINE_INPUT_CAP) {
		d->d_flags |= DEV_INPUT_CAP;
	}

	list_insert_tail(&d->d_engines, e);
	e->e_dev = d;
	mutex_exit(&d->d_lock);
}

void
audio_dev_remove_engine(audio_dev_t *d, audio_engine_t *e)
{
	mutex_enter(&d->d_lock);
	list_remove(&d->d_engines, e);
	e->e_dev = NULL;
	if (e->e_ksp)
		kstat_delete(e->e_ksp);
	e->e_ksp = NULL;
	mutex_exit(&d->d_lock);
}

/*
 * Change the number.
 */
void
auclnt_set_dev_number(audio_dev_t *d, int num)
{
	list_t		*l = &auimpl_devs_by_number;
	audio_dev_t	*srch;

	/* reorder our list */
	rw_enter(&auimpl_dev_lock, RW_WRITER);
	d->d_number = num;
	list_remove(l, d);
	for (srch = list_head(l); srch; srch = list_next(l, srch)) {
		if (srch->d_number >= d->d_number) {
			break;
		}
	}
	list_insert_before(l, srch, d);

	rw_exit(&auimpl_dev_lock);
}

void
auclnt_walk_devs(int (*walker)(audio_dev_t *, void *), void *arg)
{
	audio_dev_t	*d;
	boolean_t	cont;
	list_t		*l;

	l = &auimpl_devs_by_index;
	rw_enter(&auimpl_dev_lock, RW_READER);
	for (d = list_head(l); d; d = list_next(l, d)) {
		cont = walker(d, arg);
		if (cont == AUDIO_WALK_STOP)
			break;
	}
	rw_exit(&auimpl_dev_lock);
}

void
auclnt_walk_devs_by_number(int (*walker)(audio_dev_t *, void *), void *arg)
{
	audio_dev_t	*d;
	boolean_t	cont;
	list_t		*l;

	l = &auimpl_devs_by_number;
	rw_enter(&auimpl_dev_lock, RW_READER);
	for (d = list_head(l); d; d = list_next(l, d)) {
		cont = walker(d, arg);
		if (cont == AUDIO_WALK_STOP)
			break;
	}
	rw_exit(&auimpl_dev_lock);
}

void
auclnt_dev_walk_engines(audio_dev_t *d,
    int (*walker)(audio_engine_t *, void *),
    void *arg)
{
	audio_engine_t *e;
	list_t *l = &d->d_engines;

	mutex_enter(&d->d_lock);
	for (e = list_head(l); e != NULL; e = list_next(l, e)) {
		if (walker(e, arg) == AUDIO_WALK_STOP) {
			break;
		}
	}
	mutex_exit(&d->d_lock);
}

int
auclnt_engine_get_format(audio_engine_t *e)
{
	return (ENG_FORMAT(e));
}

int
auclnt_engine_get_channels(audio_engine_t *e)
{
	return (ENG_CHANNELS(e));
}

int
auclnt_engine_get_rate(audio_engine_t *e)
{
	return (ENG_RATE(e));
}

uint_t
auclnt_engine_get_capab(audio_engine_t *e)
{
	uint_t capab = 0;

	if (e->e_flags & ENGINE_INPUT_CAP) {
		capab |= AUDIO_CLIENT_CAP_RECORD;
	}
	if (e->e_flags & ENGINE_OUTPUT_CAP) {
		capab |= AUDIO_CLIENT_CAP_PLAY;
	}
	return (capab);
}

/*
 * This function suspends an engine.  The intent is to pause the
 * engine temporarily so that it does not underrun while user threads
 * are suspended.  The driver is still responsible for actually doing
 * the driver suspend work -- all this does is put the engine in a
 * paused state.  It does not prevent, for example, threads from
 * accessing the hardware.
 *
 * A properly implemented driver won't even be aware of the existence
 * of this routine -- the driver will just handle the suspend &
 * resume.  At the point of suspend & resume, the driver will see that
 * the engines are not running (as if all threads had "paused" it).
 *
 * Failure to execute either of the routines below is not critical,
 * but will probably lead to underruns and overflows as the kernel
 * driver gets resumed well in advance of the time when user threads
 * are ready to start operation.
 */
static void
auimpl_engine_suspend(audio_engine_t *e)
{
	ASSERT(mutex_owned(&e->e_lock));

	if (e->e_failed || e->e_suspended) {
		e->e_suspended = B_TRUE;
		return;
	}
	e->e_suspended = B_TRUE;
	if (e->e_flags & ENGINE_INPUT) {
		e->e_head = ENG_COUNT(e);
		ENG_STOP(e);
	}
	if (e->e_flags & ENGINE_OUTPUT) {
		e->e_tail = ENG_COUNT(e);
		ENG_STOP(e);
	}
}

static void
auimpl_engine_resume(audio_engine_t *e)
{
	ASSERT(mutex_owned(&e->e_lock));
	ASSERT(e->e_suspended);

	if (e->e_failed) {
		/* No longer suspended, but still failed! */
		e->e_suspended = B_FALSE;
		return;
	}

	if (e->e_flags & (ENGINE_INPUT | ENGINE_OUTPUT)) {

		auimpl_engine_reset(e);

		if (e->e_flags & ENGINE_OUTPUT) {
			auimpl_output_preload(e);
		}

		e->e_need_start = B_TRUE;
	}
	e->e_suspended = B_FALSE;
	cv_broadcast(&e->e_cv);
}

static int
auimpl_dev_suspend(audio_dev_t *d, void *dontcare)
{
	list_t		*l;
	audio_engine_t	*e;

	_NOTE(ARGUNUSED(dontcare));

	mutex_enter(&d->d_lock);
	mutex_enter(&d->d_ctrl_lock);
	if (d->d_suspended) {
		d->d_suspended++;
		mutex_exit(&d->d_ctrl_lock);
		mutex_exit(&d->d_lock);
		return (AUDIO_WALK_CONTINUE);
	}

	d->d_suspended++;

	(void) auimpl_save_controls(d);
	mutex_exit(&d->d_ctrl_lock);

	l = &d->d_engines;
	for (e = list_head(l); e != NULL; e = list_next(l, e)) {
		mutex_enter(&e->e_lock);
		auimpl_engine_suspend(e);
		mutex_exit(&e->e_lock);
	}
	mutex_exit(&d->d_lock);

	return (AUDIO_WALK_CONTINUE);
}

static int
auimpl_dev_resume(audio_dev_t *d, void *dontcare)
{
	list_t		*l;
	audio_engine_t	*e;

	_NOTE(ARGUNUSED(dontcare));

	mutex_enter(&d->d_lock);
	mutex_enter(&d->d_ctrl_lock);

	ASSERT(d->d_suspended);
	d->d_suspended--;
	if (d->d_suspended) {
		mutex_exit(&d->d_ctrl_lock);
		mutex_exit(&d->d_lock);
		return (AUDIO_WALK_CONTINUE);
	}

	(void) auimpl_restore_controls(d);
	cv_broadcast(&d->d_ctrl_cv);
	mutex_exit(&d->d_ctrl_lock);

	l = &d->d_engines;
	for (e = list_head(l); e != NULL; e = list_next(l, e)) {
		mutex_enter(&e->e_lock);
		auimpl_engine_resume(e);
		mutex_exit(&e->e_lock);
	}
	mutex_exit(&d->d_lock);

	return (AUDIO_WALK_CONTINUE);
}

boolean_t
auimpl_cpr(void *arg, int code)
{
	_NOTE(ARGUNUSED(arg));

	switch (code) {
	case CB_CODE_CPR_CHKPT:
		auclnt_walk_devs(auimpl_dev_suspend, NULL);
		return (B_TRUE);

	case CB_CODE_CPR_RESUME:
		auclnt_walk_devs(auimpl_dev_resume, NULL);
		return (B_TRUE);

	default:
		return (B_FALSE);
	}
}

void
audio_dev_suspend(audio_dev_t *d)
{
	(void) auimpl_dev_suspend(d, NULL);
}

void
audio_dev_resume(audio_dev_t *d)
{
	(void) auimpl_dev_resume(d, NULL);
}

static callb_id_t	auimpl_cpr_id = 0;

void
auimpl_dev_init(void)
{
	rw_init(&auimpl_dev_lock, NULL, RW_DRIVER, NULL);
	list_create(&auimpl_devs_by_index, sizeof (struct audio_dev),
	    offsetof(struct audio_dev, d_by_index));
	list_create(&auimpl_devs_by_number, sizeof (struct audio_dev),
	    offsetof(struct audio_dev, d_by_number));

	/*
	 * We "borrow" the CB_CL_CPR_PM class, which gets executed at
	 * about the right time for us.  It would be nice to have a
	 * new CB_CL_CPR_AUDIO class, but it isn't critical at this
	 * point.
	 *
	 * Note that we don't care about our thread id.
	 */
	auimpl_cpr_id = callb_add(auimpl_cpr, NULL, CB_CL_CPR_PM, "audio_cpr");
}

void
auimpl_dev_fini(void)
{
	(void) callb_delete(auimpl_cpr_id);
	list_destroy(&auimpl_devs_by_index);
	list_destroy(&auimpl_devs_by_number);
	rw_destroy(&auimpl_dev_lock);
}

void
audio_engine_set_private(audio_engine_t *eng, void *prv)
{
	eng->e_private = prv;
}

void *
audio_engine_get_private(audio_engine_t *eng)
{
	return (eng->e_private);
}

void
audio_dump_bytes(const uint8_t *w, int dcount)
{
	char		line[64];
	char		*s;
	int		i;
	const int	wrap = 16;

	s = line;
	line[0] = 0;

	cmn_err(CE_NOTE, "starting @ %p", (void *)w);
	for (i = 0; i < dcount; i++) {

		(void) sprintf(s, " %02x", *w);
		s += strlen(s);
		w++;

		if ((i % wrap) == (wrap - 1)) {
			cmn_err(CE_NOTE, "%08x:%s", i - (wrap - 1), line);
			line[0] = 0;
			s = line;
		}
	}

	if ((i % wrap) != 0) {
		cmn_err(CE_NOTE, "%08x:%s", i - (i % wrap), line);
	}
}

void
audio_dump_words(const uint16_t *w, int dcount)
{
	char		line[64];
	char		*s;
	int		i;
	const int	wrap = 8;

	s = line;
	line[0] = 0;

	cmn_err(CE_NOTE, "starting @ %p", (void *)w);
	for (i = 0; i < dcount; i++) {

		(void) sprintf(s, " %04x", *w);
		s += strlen(s);
		w++;

		if ((i % wrap) == (wrap - 1)) {
			cmn_err(CE_NOTE, "%08x:%s", i - (wrap - 1), line);
			line[0] = 0;
			s = line;
		}
	}

	if ((i % wrap) != 0) {
		cmn_err(CE_NOTE, "%08x:%s", i - (i % wrap), line);
	}
}

void
audio_dump_dwords(const uint32_t *w, int dcount)
{
	char		line[128];
	char		*s;
	int		i;
	const int	wrap = 4;

	s = line;
	line[0] = 0;

	cmn_err(CE_NOTE, "starting @ %p", (void *)w);
	for (i = 0; i < dcount; i++) {

		(void) sprintf(s, " %08x", *w);
		s += strlen(s);
		w++;

		if ((i % wrap) == (wrap - 1)) {
			cmn_err(CE_NOTE, "%08x:%s", i - (wrap - 1), line);
			line[0] = 0;
			s = line;
		}
	}

	if ((i % wrap) != 0) {
		cmn_err(CE_NOTE, "%08x:%s", i - (i % wrap), line);
	}
}
