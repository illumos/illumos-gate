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
	rw_init(&d->d_ctrl_lock, NULL, RW_DRIVER, NULL);
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
	rw_destroy(&d->d_ctrl_lock);
	mutex_destroy(&d->d_lock);
	cv_destroy(&d->d_cv);
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

void
audio_engine_consume(audio_engine_t *e)
{
	mutex_enter(&e->e_lock);
	e->e_tail = ENG_COUNT(e);
	if (e->e_tail > e->e_head) {
		/* want more data than we have, not much we can do */
		e->e_errors++;
		e->e_underruns++;
	}
	auimpl_output_callback(e);
	mutex_exit(&e->e_lock);
}

void
audio_engine_produce(audio_engine_t *e)
{
	mutex_enter(&e->e_lock);
	e->e_head = ENG_COUNT(e);
	if ((e->e_head - e->e_tail) > e->e_nframes) {
		/* no room for engine data, not much we can do */
		e->e_errors++;
		e->e_overruns++;
	}
	auimpl_input_callback(e);
	mutex_exit(&e->e_lock);
}

void
audio_engine_reset(audio_engine_t *e)
{
	char	*buf;
	char	*ptr;
	int	nfr;
	int	tail;


	if ((e->e_flags & (ENGINE_INPUT | ENGINE_OUTPUT)) == 0) {
		/* engine not open, nothing to do */
		return;
	}

	buf = kmem_alloc(e->e_nbytes, KM_SLEEP);
	ptr = buf;

	mutex_enter(&e->e_lock);

	tail = e->e_tidx;
	nfr = min(e->e_head - e->e_tail, e->e_nframes);
	while (nfr) {
		int	cnt;
		int	nbytes;

		cnt = min((e->e_nframes - tail), nfr);
		nbytes = cnt * e->e_framesz;

		bcopy(e->e_data + (tail * e->e_framesz), ptr, nbytes);
		ptr += nbytes;
		tail += cnt;
		if (tail >= e->e_framesz) {
			tail -= e->e_framesz;
		}
		nfr -= cnt;
	}

	nfr = min(e->e_head - e->e_tail, e->e_nframes);
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
	mutex_exit(&e->e_lock);

	kmem_free(buf, e->e_nbytes);
}

audio_engine_t *
audio_engine_alloc(audio_engine_ops_t *ops, unsigned flags)
{
	int i;
	audio_engine_t *e;

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
	mutex_init(&e->e_lock, NULL, MUTEX_DRIVER, NULL);
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
auimpl_engine_open(audio_dev_t *d, int fmts, int flags, audio_stream_t *sp)
{
	audio_engine_t	*e = NULL;
	list_t		*list;
	unsigned	caps;
	int		priority = 0;
	int		rv = ENODEV;
	int		sampsz;
	int		i;

	/*
	 * Engine selection:
	 *
	 * We try hard to avoid consuming an engine that can be used
	 * for another purpose.
	 *
	 */

	/*
	 * Which direction are we opening.  (We must open exactly
	 * one direction, otherwise the open is meaningless.)
	 */
	if (flags & ENGINE_OUTPUT)
		caps = ENGINE_OUTPUT_CAP;
	else if (flags & ENGINE_INPUT)
		caps = ENGINE_INPUT_CAP;
	else
		return (EINVAL);

	list = &d->d_engines;

	mutex_enter(&d->d_lock);

	/*
	 * First we want to know if we already have "default" input
	 * and output engines.
	 */

again:

	for (audio_engine_t *t = list_head(list); t; t = list_next(list, t)) {
		int	mypri;

		/* make sure the engine can do what we want it to */
		mutex_enter(&t->e_lock);
		if ((((t->e_flags & caps) & caps) == 0) ||
		    ((ENG_FORMAT(t) & fmts) == 0)) {
			mutex_exit(&t->e_lock);
			continue;
		}

		/* if engine is in exclusive use, can't do it */
		if (t->e_flags & ENGINE_EXCLUSIVE) {
			mutex_exit(&t->e_lock);
			rv = EBUSY;
			continue;
		}

		/* if engine is in incompatible use, can't do it */
		if (((flags & ENGINE_INPUT) && (t->e_flags & ENGINE_OUTPUT)) ||
		    ((flags & ENGINE_OUTPUT) && (t->e_flags & ENGINE_INPUT))) {
			mutex_exit(&t->e_lock);
			rv = EBUSY;
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

		rv = 0;
		mypri = 2000;

		/* try not to pick on idle engines */
		if (list_is_empty(&t->e_streams)) {
			mypri -= 1000;
		}

		/* try not to pick on duplex engines first */
		if ((t->e_flags & ENGINE_CAPS) != caps) {
			mypri -= 100;
		}

		/* try not to pick on engines that can do other formats */
		if (t->e_format & ~fmts) {
			mypri -= 10;
		}

		if (mypri > priority) {
			if (e != NULL) {
				mutex_exit(&e->e_lock);
			}
			e = t;
			priority = mypri;
		} else {
			mutex_exit(&t->e_lock);
		}
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

	/*
	 * If the engine is already open, there is no need for further
	 * work.  The first open will be relatively expensive, but
	 * subsequent opens should be as cheap as possible.
	 */
	if (!list_is_empty(&e->e_streams)) {
		rv = 0;
		goto ok;
	}

	e->e_format = ENG_FORMAT(e);
	e->e_nchan = ENG_CHANNELS(e);
	e->e_rate = ENG_RATE(e);

	/* Find out the "best" sample format supported by the device */
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

	/* sanity test a few values */
	if ((e->e_nchan < 0) || (e->e_nchan > AUDIO_MAX_CHANNELS) ||
	    (e->e_rate < 5000) || (e->e_rate > 192000)) {
		audio_dev_warn(d, "bad engine channels or rate");
		rv = EINVAL;
		goto done;
	}

	rv = ENG_OPEN(e, &e->e_fragfr, &e->e_nfrags, &e->e_data);
	if (rv != 0) {
		audio_dev_warn(d, "unable to open engine");
		goto done;
	}
	if ((e->e_fragfr < 1) || (e->e_data == NULL)) {
		audio_dev_warn(d, "improper engine configuration");
		rv = EINVAL;
		goto done;
	}

	if ((e->e_fragfr > AUDIO_CHBUFS) || (e->e_nfrags < 2)) {
		rv = EINVAL;
		audio_dev_warn(d, "invalid fragment configuration");
		goto done;
	}

	e->e_framesz = e->e_nchan * sampsz;
	e->e_fragbytes = e->e_fragfr * e->e_framesz;
	e->e_nframes = e->e_nfrags * e->e_fragfr;
	e->e_intrs = e->e_rate / e->e_fragfr;
	e->e_nbytes = e->e_nframes * e->e_framesz;
	e->e_head = 0;
	e->e_tail = 0;
	e->e_hidx = 0;
	e->e_tidx = 0;
	e->e_limiter_state = 0x10000;
	bzero(e->e_data, e->e_nbytes);

	if (e->e_ops.audio_engine_playahead == NULL) {
		e->e_playahead = (e->e_fragfr * 3) / 2;
	} else {
		e->e_playahead = ENG_PLAYAHEAD(e);
		/*
		 * Need to have at least a fragment plus some extra to
		 * avoid underruns.
		 */
		if (e->e_playahead < ((e->e_fragfr * 3) / 2)) {
			e->e_playahead = (e->e_fragfr * 3) / 2;
		}

		/*
		 * Impossible to queue more frames than FIFO can hold.
		 */
		if (e->e_playahead > e->e_nframes) {
			e->e_playahead = (e->e_fragfr * 3) / 2;
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

	e->e_flags |= (ENGINE_OPEN | (flags & (ENGINE_OUTPUT | ENGINE_INPUT)));

	/*
	 * Start the output callback to populate the engine on
	 * startup.  This avoids a false underrun when we're first
	 * starting up.
	 */
	if (flags & ENGINE_OUTPUT) {
		auimpl_output_callback(e);
	}

	/*
	 * Start the engine up now.
	 *
	 * AC3: Note that this will need to be modified for AC3, since
	 * for AC3 we can't start the device until we actually have
	 * some data for it from the application.  Probably the best
	 * way to do this would be to add a flag, ENGINE_DEFERRED or
	 * somesuch.
	 */
	if (e->e_ops.audio_engine_start != NULL) {
		rv = ENG_START(e);
		if (rv != 0) {
			ENG_CLOSE(e);
			goto done;
		}
	}

ok:
	sp->s_phys_parms->p_rate = e->e_rate;
	sp->s_phys_parms->p_nchan = e->e_nchan;

	list_insert_tail(&e->e_streams, sp);
	sp->s_engine = e;

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

	if (e == NULL)
		return;

	d = e->e_dev;

	mutex_enter(&d->d_lock);
	mutex_enter(&e->e_lock);
	sp->s_engine = NULL;
	list_remove(&e->e_streams, sp);
	if (list_is_empty(&e->e_streams)) {
		/* if last client holding engine open, close it all down */
		if (e->e_ops.audio_engine_stop != NULL)
			ENG_STOP(e);
		e->e_flags &= ENGINE_DRIVER_FLAGS;
		ENG_CLOSE(e);
	}
	mutex_exit(&e->e_lock);

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
	st->st_fragfr.value.ui32 = e->e_fragfr;
	st->st_nfrags.value.ui32 = e->e_nfrags;
	st->st_framesz.value.ui32 = e->e_framesz;
	st->st_nbytes.value.ui32 = e->e_nbytes;
	st->st_hidx.value.ui32 = e->e_hidx;
	st->st_tidx.value.ui32 = e->e_tidx;
	st->st_format.value.ui32 = e->e_format;
	st->st_nchan.value.ui32 = e->e_nchan;
	st->st_rate.value.ui32 = e->e_rate;
	st->st_intrs.value.ui32 = e->e_intrs;
	st->st_errors.value.ui32 = e->e_errors;
	st->st_engine_underruns.value.ui32 = e->e_underruns;
	st->st_engine_overruns.value.ui32 = e->e_overruns;
	st->st_stream_underruns.value.ui32 = e->e_stream_underruns;
	st->st_stream_overruns.value.ui32 = e->e_stream_overruns;
	st->st_suspended.value.ui32 = e->e_suspended;
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
	kstat_named_init(&st->st_fragfr, "fragfr", KSTAT_DATA_UINT32);
	kstat_named_init(&st->st_nfrags, "nfrags", KSTAT_DATA_UINT32);
	kstat_named_init(&st->st_framesz, "framesz", KSTAT_DATA_UINT32);
	kstat_named_init(&st->st_nbytes, "nbytes", KSTAT_DATA_UINT32);
	kstat_named_init(&st->st_hidx, "hidx", KSTAT_DATA_UINT32);
	kstat_named_init(&st->st_tidx, "tidx", KSTAT_DATA_UINT32);
	kstat_named_init(&st->st_format, "format", KSTAT_DATA_UINT32);
	kstat_named_init(&st->st_nchan, "channels", KSTAT_DATA_UINT32);
	kstat_named_init(&st->st_rate, "rate", KSTAT_DATA_UINT32);
	kstat_named_init(&st->st_intrs, "intrhz", KSTAT_DATA_UINT32);
	kstat_named_init(&st->st_errors, "errors", KSTAT_DATA_UINT32);
	kstat_named_init(&st->st_engine_overruns, "engine_overruns",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&st->st_engine_underruns, "engine_underruns",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&st->st_stream_overruns, "stream_overruns",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&st->st_stream_underruns, "stream_underruns",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&st->st_suspended, "suspended", KSTAT_DATA_UINT32);
	kstat_install(e->e_ksp);
}

void
audio_dev_add_engine(audio_dev_t *d, audio_engine_t *e)
{
	e->e_num = d->d_engno++;

	mutex_enter(&d->d_lock);

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
		mutex_enter(&d->d_lock);
		cont = walker(d, arg);
		mutex_exit(&d->d_lock);
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
		mutex_enter(&d->d_lock);
		cont = walker(d, arg);
		mutex_exit(&d->d_lock);
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

unsigned
auclnt_engine_get_capab(audio_engine_t *e)
{
	unsigned capab = 0;

	if (e->e_flags & ENGINE_INPUT_CAP) {
		capab |= AUDIO_CLIENT_CAP_RECORD;
	}
	if (e->e_flags & ENGINE_OUTPUT_CAP) {
		capab |= AUDIO_CLIENT_CAP_PLAY;
	}
	return (capab);
}

static void
auimpl_walk_engines(int (*walker)(audio_engine_t *, void *), void *arg)
{
	audio_dev_t	*d;
	audio_engine_t	*e;
	list_t		*l1;
	list_t		*l2;
	boolean_t	done = B_FALSE;

	rw_enter(&auimpl_dev_lock, RW_READER);
	l1 = &auimpl_devs_by_index;
	for (d = list_head(l1); d; d = list_next(l1, d)) {
		mutex_enter(&d->d_lock);
		l2 = &d->d_engines;
		for (e = list_head(l2); e; e = list_next(l2, e)) {
			if (walker(e, arg) == AUDIO_WALK_STOP) {
				done = B_TRUE;
				break;
			}
		}
		mutex_exit(&d->d_lock);
		if (done)
			break;
	}
	rw_exit(&auimpl_dev_lock);
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
static int
auimpl_engine_suspend(audio_engine_t *e, void *dontcare)
{
	_NOTE(ARGUNUSED(dontcare));

	mutex_enter(&e->e_lock);
	e->e_suspended = B_TRUE;
	mutex_exit(&e->e_lock);

	return (AUDIO_WALK_CONTINUE);
}

static int
auimpl_engine_resume(audio_engine_t *e, void *dontcare)
{
	_NOTE(ARGUNUSED(dontcare));
	mutex_enter(&e->e_lock);
	e->e_suspended = B_FALSE;
	mutex_exit(&e->e_lock);
	return (AUDIO_WALK_CONTINUE);
}

boolean_t
auimpl_cpr(void *arg, int code)
{
	_NOTE(ARGUNUSED(arg));

	switch (code) {
	case CB_CODE_CPR_CHKPT:
		auimpl_walk_engines(auimpl_engine_suspend, NULL);
		return (B_TRUE);

	case CB_CODE_CPR_RESUME:
		auimpl_walk_engines(auimpl_engine_resume, NULL);
		return (B_TRUE);

	default:
		return (B_FALSE);
	}
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
