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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <sys/types.h>
#include <sys/ksynch.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/cred.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/nsc_thread.h>
#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_errors.h>

#include <sys/unistat/spcs_s_k.h>
#ifdef DS_DDICT
#include "../contract.h"
#endif

#include <sys/nsctl/nsctl.h>

#include <sys/sdt.h>		/* dtrace is S10 or later */

#include "rdc.h"
#include "rdc_io.h"
#include "rdc_bitmap.h"

/*
 * Remote Dual Copy
 *
 * This file contains the nsctl io provider functionality for RDC.
 *
 * RDC is implemented as a simple filter module that pushes itself between
 * user (SIMCKD, STE, etc.) and SDBC.
 */


static int _rdc_open_count;
int	rdc_eio_nobmp = 0;

nsc_io_t *_rdc_io_hc;
static nsc_io_t *_rdc_io_hr;
static nsc_def_t _rdc_fd_def[], _rdc_io_def[], _rdc_ior_def[];

void _rdc_deinit_dev();
int rdc_diskq_enqueue(rdc_k_info_t *, rdc_aio_t *);
extern void rdc_unintercept_diskq(rdc_group_t *);
rdc_aio_t *rdc_aio_tbuf_get(void *, void *, int, int, int, int, int);

static nsc_buf_t *_rdc_alloc_handle(void (*)(), void (*)(),
    void (*)(), rdc_fd_t *);
static int _rdc_free_handle(rdc_buf_t *, rdc_fd_t *);

#ifdef DEBUG
int	rdc_overlap_cnt;
int	rdc_overlap_hnd_cnt;
#endif

static rdc_info_dev_t *rdc_devices;

extern int _rdc_rsrv_diskq(rdc_group_t *group);
extern void _rdc_rlse_diskq(rdc_group_t *group);

/*
 * _rdc_init_dev
 *	Initialise the io provider.
 */

int
_rdc_init_dev()
{
	_rdc_io_hc = nsc_register_io("rdc-high-cache",
		NSC_RDCH_ID|NSC_REFCNT|NSC_FILTER, _rdc_io_def);
	if (_rdc_io_hc == NULL)
		cmn_err(CE_WARN, "rdc: nsc_register_io (high, cache) failed.");

	_rdc_io_hr = nsc_register_io("rdc-high-raw",
		NSC_RDCHR_ID|NSC_REFCNT|NSC_FILTER, _rdc_ior_def);
	if (_rdc_io_hr == NULL)
		cmn_err(CE_WARN, "rdc: nsc_register_io (high, raw) failed.");

	if (!_rdc_io_hc || !_rdc_io_hr) {
		_rdc_deinit_dev();
		return (ENOMEM);
	}

	return (0);
}


/*
 * _rdc_deinit_dev
 *	De-initialise the io provider.
 *
 */

void
_rdc_deinit_dev()
{
	int rc;

	if (_rdc_io_hc) {
		if ((rc = nsc_unregister_io(_rdc_io_hc, 0)) != 0)
			cmn_err(CE_WARN,
			    "rdc: nsc_unregister_io (high, cache) failed: %d",
			    rc);
	}

	if (_rdc_io_hr) {
		if ((rc = nsc_unregister_io(_rdc_io_hr, 0)) != 0)
			cmn_err(CE_WARN,
			    "rdc: nsc_unregister_io (high, raw) failed: %d",
			    rc);
	}
}


/*
 * rdc_idev_open
 * - Open the nsctl file descriptors for the data devices.
 *
 * Must be called with rdc_conf_lock held.
 * id_sets is protected by rdc_conf_lock.
 */
static rdc_info_dev_t *
rdc_idev_open(rdc_k_info_t *krdc, char *pathname, int *rc)
{
	rdc_info_dev_t *dp;

	ASSERT(MUTEX_HELD(&rdc_conf_lock));

	for (dp = rdc_devices; dp; dp = dp->id_next) {
		if (dp->id_cache_dev.bi_fd &&
		    strcmp(pathname, nsc_pathname(dp->id_cache_dev.bi_fd)) == 0)
			break;
	}

	if (!dp) {
		dp = kmem_zalloc(sizeof (*dp), KM_SLEEP);
		if (!dp)
			return (NULL);

		dp->id_cache_dev.bi_krdc = krdc;
		dp->id_cache_dev.bi_fd = nsc_open(pathname,
			NSC_RDCHR_ID|NSC_RDWR|NSC_DEVICE,
			_rdc_fd_def, (blind_t)&dp->id_cache_dev, rc);
		if (!dp->id_cache_dev.bi_fd) {
			kmem_free(dp, sizeof (*dp));
			return (NULL);
		}

		dp->id_raw_dev.bi_krdc = krdc;
		dp->id_raw_dev.bi_fd = nsc_open(pathname,
			NSC_RDCHR_ID|NSC_RDWR|NSC_DEVICE,
			_rdc_fd_def, (blind_t)&dp->id_raw_dev, rc);
		if (!dp->id_raw_dev.bi_fd) {
			(void) nsc_close(dp->id_cache_dev.bi_fd);
			kmem_free(dp, sizeof (*dp));
			return (NULL);
		}

		mutex_init(&dp->id_rlock, NULL, MUTEX_DRIVER, NULL);
		cv_init(&dp->id_rcv, NULL, CV_DRIVER, NULL);

		dp->id_next = rdc_devices;
		rdc_devices = dp;
	}

	dp->id_sets++;
	return (dp);
}


/*
 * rdc_idev_close
 * - Close the nsctl file descriptors for the data devices.
 *
 * Must be called with rdc_conf_lock and dp->id_rlock held.
 * Will release dp->id_rlock before returning.
 *
 * id_sets is protected by rdc_conf_lock.
 */
static void
rdc_idev_close(rdc_k_info_t *krdc, rdc_info_dev_t *dp)
{
	rdc_info_dev_t **dpp;
#ifdef DEBUG
	int count = 0;
#endif

	ASSERT(MUTEX_HELD(&rdc_conf_lock));
	ASSERT(MUTEX_HELD(&dp->id_rlock));

	dp->id_sets--;
	if (dp->id_sets > 0) {
		mutex_exit(&dp->id_rlock);
		return;
	}

	/* external references must have gone */
	ASSERT((krdc->c_ref + krdc->r_ref + krdc->b_ref) == 0);

	/* unlink from chain */

	for (dpp = &rdc_devices; *dpp; dpp = &((*dpp)->id_next)) {
		if (*dpp == dp) {
			/* unlink */
			*dpp = dp->id_next;
			break;
		}
	}

	/*
	 * Wait for all reserves to go away - the rpc server is
	 * running asynchronously with this close, and so we
	 * have to wait for it to spot that the krdc is !IS_ENABLED()
	 * and throw away the nsc_buf_t's that it has allocated
	 * and release the device.
	 */

	while (IS_CRSRV(krdc) || IS_RRSRV(krdc)) {
#ifdef DEBUG
		if (!(++count % 16)) {
			cmn_err(CE_NOTE,
				"_rdc_idev_close(%s): waiting for nsc_release",
				rdc_u_info[krdc->index].primary.file);
		}
		if (count > (16*20)) {
			/* waited for 20 seconds - too long - panic */
			cmn_err(CE_PANIC,
				"_rdc_idev_close(%s, %p): lost nsc_release",
				rdc_u_info[krdc->index].primary.file,
				(void *)krdc);
		}
#endif
		mutex_exit(&dp->id_rlock);
		delay(HZ>>4);
		mutex_enter(&dp->id_rlock);
	}

	if (dp->id_cache_dev.bi_fd) {
		(void) nsc_close(dp->id_cache_dev.bi_fd);
		dp->id_cache_dev.bi_fd = NULL;
	}

	if (dp->id_raw_dev.bi_fd) {
		(void) nsc_close(dp->id_raw_dev.bi_fd);
		dp->id_raw_dev.bi_fd = NULL;
	}

	mutex_exit(&dp->id_rlock);
	mutex_destroy(&dp->id_rlock);
	cv_destroy(&dp->id_rcv);

	kmem_free(dp, sizeof (*dp));
}


/*
 * This function provokes an nsc_reserve() for the device which
 * if successful will populate krdc->maxfbas and urdc->volume_size
 * via the _rdc_attach_fd() callback.
 */
void
rdc_get_details(rdc_k_info_t *krdc)
{
	int rc;
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];
	nsc_size_t vol_size, maxfbas;

	if (_rdc_rsrv_devs(krdc, RDC_RAW, RDC_INTERNAL) == 0) {
		/*
		 * if the vol is already reserved,
		 * volume_size won't be populated on enable because
		 * it is a *fake* reserve and does not make it to
		 * _rdc_attach_fd(). So do it here.
		 */
		rc = nsc_partsize(RDC_U_FD(krdc), &vol_size);
		if (rc != 0) {
#ifdef DEBUG
			cmn_err(CE_WARN,
			    "rdc_get_details: partsize failed (%d)", rc);
#endif /* DEBUG */
			urdc->volume_size = vol_size = 0;
		}

		urdc->volume_size = vol_size;
		rc = nsc_maxfbas(RDC_U_FD(krdc), 0, &maxfbas);
		if (rc != 0) {
#ifdef DEBUG
			cmn_err(CE_WARN,
			    "rdc_get_details: maxfbas failed (%d)", rc);
#endif /* DEBUG */
			maxfbas = 0;
		}
		krdc->maxfbas = min(RDC_MAX_MAXFBAS, maxfbas);

		_rdc_rlse_devs(krdc, RDC_RAW);
	}
}


/*
 * Should only be used by the config code.
 */

int
rdc_dev_open(rdc_set_t *rdc_set, int options)
{
	rdc_k_info_t *krdc;
	int index;
	int rc;
	char *pathname;

	ASSERT(MUTEX_HELD(&rdc_conf_lock));

	if (options & RDC_OPT_PRIMARY)
		pathname = rdc_set->primary.file;
	else
		pathname = rdc_set->secondary.file;

	for (index = 0; index < rdc_max_sets; index++) {
		krdc = &rdc_k_info[index];

		if (!IS_CONFIGURED(krdc))
			break;
	}

	if (index == rdc_max_sets) {
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_dev_open: out of cd\'s");
#endif
		index = -EINVAL;
		goto out;
	}

	if (krdc->devices && (krdc->c_fd || krdc->r_fd)) {
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_dev_open: %s already open", pathname);
#endif
		index = -EINVAL;
		goto out;
	}

	_rdc_open_count++;

	krdc->devices = rdc_idev_open(krdc, pathname, &rc);
	if (!krdc->devices) {
		index = -rc;
		goto open_fail;
	}

	/*
	 * Grab the device size and maxfbas now.
	 */

	rdc_get_details(krdc);

out:
	return (index);

open_fail:
	_rdc_open_count--;

	return (index);
}


void
rdc_dev_close(rdc_k_info_t *krdc)
{
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];

	mutex_enter(&rdc_conf_lock);

	if (krdc->devices)
		mutex_enter(&krdc->devices->id_rlock);

#ifdef DEBUG
	if (!krdc->devices || !krdc->c_fd || !krdc->r_fd) {
		cmn_err(CE_WARN,
			"rdc_dev_close(%p): c_fd %p r_fd %p", (void *)krdc,
			(void *) (krdc->devices ? krdc->c_fd : 0),
			(void *) (krdc->devices ? krdc->r_fd : 0));
	}
#endif

	if (krdc->devices) {
		/* rdc_idev_close will release id_rlock */
		rdc_idev_close(krdc, krdc->devices);
		krdc->devices = NULL;
	}

	urdc->primary.file[0] = '\0';

	if (_rdc_open_count <= 0) {
		cmn_err(CE_WARN,
			"rdc: _rdc_open_count corrupt: %d",
			_rdc_open_count);
	}

	_rdc_open_count--;

	mutex_exit(&rdc_conf_lock);
}


/*
 * rdc_intercept
 *
 * Register for IO on this device with nsctl.
 *
 * For a 1-to-many primary we register for each krdc and let nsctl sort
 * out which it wants to be using. This means that we cannot tell which
 * krdc will receive the incoming io from nsctl, though we do know that
 * at any one time only one krdc will be 'attached' and so get io from
 * nsctl.
 *
 * So the krdc->many_next pointer is maintained as a circular list. The
 * result of these multiple nsc_register_paths is that we will see a
 * few more attach and detach io provider calls during enable/resume
 * and disable/suspend of the 1-to-many whilst nsctl settles down to
 * using a single krdc.
 *
 * The major advantage of this scheme is that nsctl sorts out all the
 * rdc_fd_t's so that they can only point to krdc's that are currently
 * active.
 */
int
rdc_intercept(rdc_k_info_t *krdc)
{
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];
	char *pathname;
	char *bitmap;

	if (rdc_get_vflags(urdc) & RDC_PRIMARY) {
		pathname = urdc->primary.file;
		bitmap = urdc->primary.bitmap;
	} else {
		pathname = urdc->secondary.file;
		bitmap = urdc->secondary.bitmap;
	}

	if (!krdc->b_tok)
		krdc->b_tok = nsc_register_path(bitmap, NSC_CACHE | NSC_DEVICE,
		    _rdc_io_hc);

	if (!krdc->c_tok)
		krdc->c_tok = nsc_register_path(pathname, NSC_CACHE,
		    _rdc_io_hc);

	if (!krdc->r_tok)
		krdc->r_tok = nsc_register_path(pathname, NSC_DEVICE,
		    _rdc_io_hr);

	if (!krdc->c_tok || !krdc->r_tok) {
		(void) rdc_unintercept(krdc);
		return (ENXIO);
	}

	return (0);
}


static void
wait_unregistering(rdc_k_info_t *krdc)
{
	while (krdc->group->unregistering > 0)
		(void) cv_wait_sig(&krdc->group->unregistercv, &rdc_conf_lock);
}

static void
set_unregistering(rdc_k_info_t *krdc)
{
	wait_unregistering(krdc);

	krdc->group->unregistering++;
}

static void
wakeup_unregistering(rdc_k_info_t *krdc)
{
	if (krdc->group->unregistering <= 0)
		return;

	krdc->group->unregistering--;
	cv_broadcast(&krdc->group->unregistercv);
}


/*
 * rdc_unintercept
 *
 * Unregister for IO on this device.
 *
 * See comments above rdc_intercept.
 */
int
rdc_unintercept(rdc_k_info_t *krdc)
{
	int err = 0;
	int rc;
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];

	mutex_enter(&rdc_conf_lock);
	set_unregistering(krdc);
	krdc->type_flag |= RDC_UNREGISTER;
	mutex_exit(&rdc_conf_lock);

	if (krdc->r_tok) {
		rc = nsc_unregister_path(krdc->r_tok, 0);
		if (rc) {
			cmn_err(CE_WARN, "rdc: unregister rawfd %d", rc);
			err = rc;
		}
		krdc->r_tok = NULL;
	}

	if (krdc->c_tok) {
		rc = nsc_unregister_path(krdc->c_tok, 0);
		if (rc) {
			cmn_err(CE_WARN, "rdc: unregister cachefd %d", rc);
			if (!err)
				err = rc;
		}
		krdc->c_tok = NULL;
	}

	if (krdc->b_tok) {
		rc = nsc_unregister_path(krdc->b_tok, 0);
		if (rc) {
			cmn_err(CE_WARN, "rdc: unregister bitmap %d", rc);
			err = rc;
		}
		krdc->b_tok = NULL;
	}

	rdc_group_enter(krdc);

	/* Wait for all necessary _rdc_close() calls to complete */
	while ((krdc->c_ref + krdc->r_ref + krdc->b_ref) != 0) {
		krdc->closing++;
		cv_wait(&krdc->closingcv, &krdc->group->lock);
		krdc->closing--;
	}

	rdc_clr_flags(urdc, RDC_ENABLED);
	rdc_group_exit(krdc);


	/*
	 * Check there are no outstanding writes in progress.
	 * This can happen when a set is being disabled which
	 * is one of the 'one_to_many' chain, that did not
	 * intercept the original write call.
	 */

	for (;;) {
		rdc_group_enter(krdc);
		if (krdc->aux_state & RDC_AUXWRITE) {
			rdc_group_exit(krdc);
			/*
			 * This doesn't happen very often,
			 * just delay a bit and re-look.
			 */
			delay(50);
		} else {
			rdc_group_exit(krdc);
			break;
		}
	}

	mutex_enter(&rdc_conf_lock);
	krdc->type_flag &= ~RDC_UNREGISTER;
	wakeup_unregistering(krdc);
	mutex_exit(&rdc_conf_lock);

	return (err);
}


/*
 * _rdc_rlse_d
 *	Internal version of _rdc_rlse_devs(), only concerned with the
 *	data device, not the bitmap.
 */

static void
_rdc_rlse_d(rdc_k_info_t *krdc, int devs)
{
	_rdc_info_dev_t *cip;
	_rdc_info_dev_t *rip;
	int raw = (devs & RDC_RAW);

	if (!krdc) {
		cmn_err(CE_WARN, "rdc: _rdc_rlse_devs null krdc");
		return;
	}

	ASSERT((devs & (~RDC_BMP)) != 0);

	cip = &krdc->devices->id_cache_dev;
	rip = &krdc->devices->id_raw_dev;

	if (IS_RSRV(cip)) {
		/* decrement count */

		if (raw) {
			if (cip->bi_ofailed > 0) {
				cip->bi_ofailed--;
			} else if (cip->bi_orsrv > 0) {
				cip->bi_orsrv--;
			}
		} else {
			if (cip->bi_failed > 0) {
				cip->bi_failed--;
			} else if (cip->bi_rsrv > 0) {
				cip->bi_rsrv--;
			}
		}

		/*
		 * reset nsc_fd ownership back link, it is only set if
		 * we have really done an underlying reserve, not for
		 * failed (faked) reserves.
		 */

		if (cip->bi_rsrv > 0 || cip->bi_orsrv > 0) {
			nsc_set_owner(cip->bi_fd, krdc->iodev);
		} else {
			nsc_set_owner(cip->bi_fd, NULL);
		}

		/* release nsc_fd */

		if (!IS_RSRV(cip)) {
			nsc_release(cip->bi_fd);
		}
	} else if (IS_RSRV(rip)) {
		/* decrement count */

		if (raw) {
			if (rip->bi_failed > 0) {
				rip->bi_failed--;
			} else if (rip->bi_rsrv > 0) {
				rip->bi_rsrv--;
			}
		} else {
			if (rip->bi_ofailed > 0) {
				rip->bi_ofailed--;
			} else if (rip->bi_orsrv > 0) {
				rip->bi_orsrv--;
			}
		}

		/*
		 * reset nsc_fd ownership back link, it is only set if
		 * we have really done an underlying reserve, not for
		 * failed (faked) reserves.
		 */

		if (rip->bi_rsrv > 0 || rip->bi_orsrv > 0) {
			nsc_set_owner(rip->bi_fd, krdc->iodev);
		} else {
			nsc_set_owner(rip->bi_fd, NULL);
		}

		/* release nsc_fd and any waiters */

		if (!IS_RSRV(rip)) {
			rip->bi_flag = 0;
			nsc_release(rip->bi_fd);
			cv_broadcast(&krdc->devices->id_rcv);
		}
	} else {
		cmn_err(CE_WARN, "rdc: _rdc_rlse_devs no reserve? krdc %p",
			(void *) krdc);
	}
}

/*
 * _rdc_rlse_devs
 *	Release named underlying devices and take care of setting the
 *	back link on the nsc_fd to the correct parent iodev.
 *
 *	NOTE: the 'devs' argument must be the same as that passed to
 *	the preceding _rdc_rsrv_devs call.
 */

void
_rdc_rlse_devs(rdc_k_info_t *krdc, int devs)
{

	DTRACE_PROBE(_rdc_rlse_devs_start);
	mutex_enter(&krdc->devices->id_rlock);

	ASSERT(!(devs & RDC_CACHE));

	if ((devs & (~RDC_BMP)) != 0) {
		_rdc_rlse_d(krdc, devs);
	}

	if ((devs & RDC_BMP) != 0) {
		if (krdc->bmaprsrv > 0 && --krdc->bmaprsrv == 0) {
			nsc_release(krdc->bitmapfd);
		}
	}

	mutex_exit(&krdc->devices->id_rlock);

}

/*
 * _rdc_rsrv_d
 *	Reserve device flagged, unless its companion is already reserved,
 *	in that case increase the reserve on the companion.  Take care
 *	of setting the nsc_fd ownership back link to the correct parent
 *	iodev pointer.
 */

static int
_rdc_rsrv_d(int raw, _rdc_info_dev_t *rid, _rdc_info_dev_t *cid, int flag,
    rdc_k_info_t *krdc)
{
	_rdc_info_dev_t *p = NULL;
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];
	int other = 0;
	int rc;


#ifdef DEBUG
	if ((rid->bi_rsrv < 0) ||
	    (cid->bi_rsrv < 0) ||
	    (rid->bi_orsrv < 0) ||
	    (cid->bi_orsrv < 0) ||
	    (rid->bi_failed < 0) ||
	    (cid->bi_failed < 0) ||
	    (rid->bi_ofailed < 0) ||
	    (cid->bi_ofailed < 0)) {
		cmn_err(CE_WARN,
		    "_rdc_rsrv_d: negative counts (rsrv %d %d orsrv %d %d)",
		    rid->bi_rsrv, cid->bi_rsrv,
		    rid->bi_orsrv, cid->bi_orsrv);
		cmn_err(CE_WARN,
		    "_rdc_rsrv_d: negative counts (fail %d %d ofail %d %d)",
		    rid->bi_failed, cid->bi_failed,
		    rid->bi_ofailed, cid->bi_ofailed);
		cmn_err(CE_PANIC, "_rdc_rsrv_d: negative counts (krdc %p)",
		    (void *) krdc);
	}
#endif

	/*
	 * If user wants to do a cache reserve and it's already
	 * raw reserved internally, we need to do a real nsc_reserve, so wait
	 * until the release has been done.
	 */
	if (IS_RSRV(rid) && (flag == RDC_EXTERNAL) &&
	    (raw == 0) && (rid->bi_flag != RDC_EXTERNAL)) {
		krdc->devices->id_release++;
		while (IS_RSRV(rid))
			cv_wait(&krdc->devices->id_rcv,
				&krdc->devices->id_rlock);
		krdc->devices->id_release--;
	}

	/* select underlying device to use */

	if (IS_RSRV(rid)) {
		p = rid;
		if (!raw) {
			other = 1;
		}
	} else if (IS_RSRV(cid)) {
		p = cid;
		if (raw) {
			other = 1;
		}
	}

	/* just increment count and return if already reserved */

	if (p && !RFAILED(p)) {
		if (other) {
			p->bi_orsrv++;
		} else {
			p->bi_rsrv++;
		}

		/* set nsc_fd ownership back link */
		nsc_set_owner(p->bi_fd, krdc->iodev);
		return (0);
	}

	/* attempt reserve */

	if (!p) {
		p = raw ? rid : cid;
	}

	if (!p->bi_fd) {
		/* rpc server raced with rdc_dev_close() */
		return (EIO);
	}
	if ((rc = nsc_reserve(p->bi_fd, 0)) == 0) {
		/*
		 * convert failed counts into reserved counts, and add
		 * in this reserve.
		 */

		p->bi_orsrv = p->bi_ofailed;
		p->bi_rsrv = p->bi_failed;

		if (other) {
			p->bi_orsrv++;
		} else {
			p->bi_rsrv++;
		}

		p->bi_ofailed = 0;
		p->bi_failed = 0;

		/* set nsc_fd ownership back link */

		nsc_set_owner(p->bi_fd, krdc->iodev);
	} else if (rc != EINTR) {
		/*
		 * If this is the master, and the secondary is not
		 * failed, then just fake this external reserve so that
		 * we can do remote io to the secondary and continue to
		 * provide service to the client.
		 *
		 * Subsequent calls to _rdc_rsrv_d() will re-try the
		 * nsc_reserve() until it succeeds.
		 */

		if ((rdc_get_vflags(urdc) & RDC_PRIMARY) &&
		    !(rdc_get_vflags(urdc) & RDC_LOGGING) &&
		    !((rdc_get_vflags(urdc) & RDC_SLAVE) &&
		    (rdc_get_vflags(urdc) & RDC_SYNCING))) {
			if (!(rdc_get_vflags(urdc) & RDC_VOL_FAILED)) {
				rdc_many_enter(krdc);
				/* Primary, so reverse sync needed */
				rdc_set_mflags(urdc, RDC_RSYNC_NEEDED);
				rdc_set_flags_log(urdc, RDC_VOL_FAILED,
				    "nsc_reserve failed");
				rdc_many_exit(krdc);
				rc = -1;
#ifdef DEBUG
				cmn_err(CE_NOTE, "nsc_reserve failed "
				    "with rc == %d\n", rc);
#endif
			} else {
				rc = 0;
			}

			if (other) {
				p->bi_ofailed++;
			} else {
				p->bi_failed++;
			}

			if (krdc->maxfbas == 0) {
				/*
				 * fake a maxfbas value for remote i/o,
				 * this will get reset when the next
				 * successful reserve happens as part
				 * of the rdc_attach_fd() callback.
				 */
				krdc->maxfbas = 128;
			}
		}
	}

	if (rc == 0 && raw) {
		p->bi_flag = flag;
	}


	return (rc);
}

/*
 * _rdc_rsrv_devs
 *	Reserve named underlying devices.
 *
 */

int
_rdc_rsrv_devs(rdc_k_info_t *krdc, int devs, int flag)
{
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];
	int write = 0;
	int rc = 0;
	int got = 0;

	if (!krdc) {
		cmn_err(CE_WARN, "rdc: _rdc_rsrv_devs null krdc");
		return (EINVAL);
	}

	ASSERT(!(devs & RDC_CACHE));

	mutex_enter(&krdc->devices->id_rlock);

	if ((devs & (~RDC_BMP)) != 0) {
		if ((rc = _rdc_rsrv_d((devs & RDC_CACHE) == 0,
		    &krdc->devices->id_raw_dev, &krdc->devices->id_cache_dev,
		    flag, krdc)) != 0) {
			if (rc == -1) {
				/*
				 * we need to call rdc_write_state()
				 * after we drop the mutex
				 */
				write = 1;
				rc = 0;
			} else {
				cmn_err(CE_WARN,
				    "rdc: nsc_reserve(%s) failed %d\n",
				    nsc_pathname(krdc->c_fd), rc);
			}
		} else {
			got |= (devs & (~RDC_BMP));
		}
	}

	if (rc == 0 && (devs & RDC_BMP) != 0) {
		if (krdc->bitmapfd == NULL)
			rc = EIO;
		else if ((krdc->bmaprsrv == 0) &&
		    (rc = nsc_reserve(krdc->bitmapfd, 0)) != 0) {
			cmn_err(CE_WARN,
				"rdc: nsc_reserve(%s) failed %d\n",
				nsc_pathname(krdc->bitmapfd), rc);
		} else {
			krdc->bmaprsrv++;
			got |= RDC_BMP;
		}
		if (!RDC_SUCCESS(rc)) {
			/* Undo any previous reserve */
			if (got != 0)
				_rdc_rlse_d(krdc, got);
		}
	}

	mutex_exit(&krdc->devices->id_rlock);

	if (write) {
		rdc_write_state(urdc);
	}

	return (rc);
}


/*
 * Read from the remote end, ensuring that if this is a many group in
 * slave mode that we only remote read from the secondary with the
 * valid data.
 */
int
_rdc_remote_read(rdc_k_info_t *krdc, nsc_buf_t *h, nsc_off_t pos,
    nsc_size_t len, int flag)
{
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];
	rdc_k_info_t *this = krdc;	/* krdc that was requested */
	int rc;

	if (flag & NSC_RDAHEAD) {
		/*
		 * no point in doing readahead remotely,
		 * just say we did it ok - the client is about to
		 * throw this buffer away as soon as we return.
		 */
		return (NSC_DONE);
	}

	/*
	 * If this is a many group with a reverse sync in progress and
	 * this is not the slave krdc/urdc, then search for the slave
	 * so that we can do the remote io from the correct secondary.
	 */
	if ((rdc_get_mflags(urdc) & RDC_SLAVE) &&
	    !(rdc_get_vflags(urdc) & RDC_SLAVE)) {
		rdc_many_enter(krdc);
		for (krdc = krdc->many_next; krdc != this;
		    krdc = krdc->many_next) {
			urdc = &rdc_u_info[krdc->index];
			if (!IS_ENABLED(urdc))
				continue;
			if (rdc_get_vflags(urdc) & RDC_SLAVE)
				break;
		}
		rdc_many_exit(krdc);

		this = krdc;
	}

read1:
	if (rdc_get_vflags(urdc) & RDC_LOGGING) {
		/* cannot do remote io without the remote node! */
		rc = ENETDOWN;
		goto read2;
	}


	/* wait for the remote end to have the latest data */

	if (IS_ASYNC(urdc)) {
		while (krdc->group->ra_queue.blocks != 0) {
			if (!krdc->group->rdc_writer)
				(void) rdc_writer(krdc->index);

			(void) rdc_drain_queue(krdc->index);
		}
	}

	if (krdc->io_kstats) {
		mutex_enter(krdc->io_kstats->ks_lock);
		kstat_runq_enter(KSTAT_IO_PTR(krdc->io_kstats));
		mutex_exit(krdc->io_kstats->ks_lock);
	}

	rc = rdc_net_read(krdc->index, krdc->remote_index, h, pos, len);

	if (krdc->io_kstats) {
		mutex_enter(krdc->io_kstats->ks_lock);
		kstat_runq_exit(KSTAT_IO_PTR(krdc->io_kstats));
		mutex_exit(krdc->io_kstats->ks_lock);
	}

	/* If read error keep trying every secondary until no more */
read2:
	if (!RDC_SUCCESS(rc) && IS_MANY(krdc) &&
	    !(rdc_get_mflags(urdc) & RDC_SLAVE)) {
		rdc_many_enter(krdc);
		for (krdc = krdc->many_next; krdc != this;
		    krdc = krdc->many_next) {
			urdc = &rdc_u_info[krdc->index];
			if (!IS_ENABLED(urdc))
				continue;
			rdc_many_exit(krdc);
			goto read1;
		}
		rdc_many_exit(krdc);
	}

	return (rc);
}


/*
 * _rdc_alloc_buf
 *	Allocate a buffer of data
 *
 * Calling/Exit State:
 *	Returns NSC_DONE or NSC_HIT for success, NSC_PENDING for async
 *	I/O, > 0 is an error code.
 *
 * Description:
 */
int rdcbufs = 0;

static int
_rdc_alloc_buf(rdc_fd_t *rfd, nsc_off_t pos, nsc_size_t len, int flag,
    rdc_buf_t **ptr)
{
	rdc_k_info_t *krdc = rfd->rdc_info;
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];
	nsc_vec_t *vec = NULL;
	rdc_buf_t *h;
	size_t size;
	int ioflag;
	int rc = 0;

	if (RDC_IS_BMP(rfd) || RDC_IS_QUE(rfd))
		return (EIO);

	if (len == 0)
		return (EINVAL);

	if (flag & NSC_WRBUF) {

		if (!(rdc_get_vflags(urdc) & RDC_PRIMARY) &&
		    !(rdc_get_vflags(urdc) & RDC_LOGGING)) {
			/*
			 * Forbid writes to secondary unless logging.
			 */
			return (EIO);
		}
	}

	if (!(rdc_get_vflags(urdc) & RDC_PRIMARY) &&
	    (rdc_get_vflags(urdc) & RDC_SYNC_NEEDED)) {
		/*
		 * Forbid any io to secondary if it needs a sync.
		 */
		return (EIO);
	}

	if ((rdc_get_vflags(urdc) & RDC_PRIMARY) &&
	    (rdc_get_vflags(urdc) & RDC_RSYNC_NEEDED) &&
	    !(rdc_get_vflags(urdc) & RDC_VOL_FAILED) &&
	    !(rdc_get_vflags(urdc) & RDC_SLAVE)) {
		/*
		 * Forbid any io to primary if it needs a reverse sync
		 * and is not actively syncing.
		 */
		return (EIO);
	}

	/* Bounds checking */
	ASSERT(urdc->volume_size != 0);
	if (pos + len > urdc->volume_size) {
#ifdef DEBUG
		cmn_err(CE_NOTE,
			    "rdc: Attempt to access beyond end of rdc volume");
#endif
		return (EIO);
	}

	h = *ptr;
	if (h == NULL) {
		/* should never happen (nsctl does this for us) */
#ifdef DEBUG
		cmn_err(CE_WARN, "_rdc_alloc_buf entered without buffer!");
#endif
		h = (rdc_buf_t *)_rdc_alloc_handle(NULL, NULL, NULL, rfd);
		if (h == NULL)
			return (ENOMEM);

		h->rdc_bufh.sb_flag &= ~NSC_HALLOCATED;
		*ptr = h;
	}

	if (flag & NSC_NOBLOCK) {
		cmn_err(CE_WARN,
		    "_rdc_alloc_buf: removing unsupported NSC_NOBLOCK flag");
		flag &= ~(NSC_NOBLOCK);
	}

	h->rdc_bufh.sb_error = 0;
	h->rdc_bufh.sb_flag |= flag;
	h->rdc_bufh.sb_pos = pos;
	h->rdc_bufh.sb_len = len;
	ioflag = flag;

	bzero(&h->rdc_sync, sizeof (h->rdc_sync));
	mutex_init(&h->rdc_sync.lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&h->rdc_sync.cv, NULL, CV_DRIVER, NULL);

	if (flag & NSC_WRBUF)
		_rdc_async_throttle(krdc, len);	/* throttle incoming io */

	/*
	 * Use remote io when:
	 * - local volume is failed
	 * - reserve status is failed
	 */
	if ((rdc_get_vflags(urdc) & RDC_VOL_FAILED) || IS_RFAILED(krdc)) {
		rc = EIO;
	} else {
		rc = nsc_alloc_buf(RDC_U_FD(krdc), pos, len,
			ioflag, &h->rdc_bufp);
		if (!RDC_SUCCESS(rc)) {
			rdc_many_enter(krdc);
			if (rdc_get_vflags(urdc) & RDC_PRIMARY) {
				/* Primary, so reverse sync needed */
				rdc_set_mflags(urdc, RDC_RSYNC_NEEDED);
			} else {
				/* Secondary, so forward sync needed */
				rdc_set_flags(urdc, RDC_SYNC_NEEDED);
			}
			rdc_set_flags_log(urdc, RDC_VOL_FAILED,
				"nsc_alloc_buf failed");
			rdc_many_exit(krdc);
			rdc_write_state(urdc);
		}
	}

	if (RDC_SUCCESS(rc)) {
		h->rdc_bufh.sb_vec = h->rdc_bufp->sb_vec;
		h->rdc_flags |= RDC_ALLOC;

		/*
		 * If in slave and reading data, remote read on top of
		 * the buffer to ensure that we have the latest data.
		 */
		if ((flag & NSC_READ) &&
		    (rdc_get_vflags(urdc) & RDC_PRIMARY) &&
		    (rdc_get_mflags(urdc) & RDC_SLAVE)) {
			rc = _rdc_remote_read(krdc, &h->rdc_bufh,
			    pos, len, flag);
			/*
			 * Set NSC_MIXED so that the
			 * cache will throw away this buffer when we free
			 * it since we have combined data from multiple
			 * sources into a single buffer.
			 */
			h->rdc_bufp->sb_flag |= NSC_MIXED;
		}
	}

	/*
	 * If nsc_alloc_buf above fails, or local volume is failed or
	 * bitmap is failed or reserve, then we fill the buf from remote
	 */

	if ((!RDC_SUCCESS(rc)) && (rdc_get_vflags(urdc) & RDC_PRIMARY) &&
	    !(rdc_get_vflags(urdc) & RDC_LOGGING)) {
		if (flag & NSC_NODATA) {
			ASSERT(!(flag & NSC_READ));
			h->rdc_flags |= RDC_REMOTE_BUF;
			h->rdc_bufh.sb_vec = NULL;
		} else {
			size = sizeof (nsc_vec_t) * 2;
			h->rdc_vsize = size + FBA_SIZE(len);
			vec = kmem_zalloc(h->rdc_vsize, KM_SLEEP);

			if (!vec) {
				rc = ENOMEM;
				goto error;
			}

			/* single flat buffer */

			vec[0].sv_addr = (uchar_t *)vec + size;
			vec[0].sv_len  = FBA_SIZE(len);
			vec[0].sv_vme  = 0;

			/* null terminator */

			vec[1].sv_addr = NULL;
			vec[1].sv_len  = 0;
			vec[1].sv_vme  = 0;

			h->rdc_bufh.sb_vec = vec;
			h->rdc_flags |= RDC_REMOTE_BUF;
			h->rdc_flags |= RDC_VEC_ALLOC;
		}

		if (flag & NSC_READ) {
			rc = _rdc_remote_read(krdc, &h->rdc_bufh,
			    pos, len, flag);
		} else {
			rc = NSC_DONE;
		}
	}
error:
	if (!RDC_SUCCESS(rc)) {
		h->rdc_bufh.sb_error = rc;
	}

	return (rc);
}


/*
 * _rdc_free_buf
 */

static int
_rdc_free_buf(rdc_buf_t *h)
{
	int rc = 0;

	if (h->rdc_flags & RDC_ALLOC) {
		if (h->rdc_bufp) {
			rc = nsc_free_buf(h->rdc_bufp);
		}
		h->rdc_flags &= ~(RDC_ALLOC);

		if (!RDC_SUCCESS(rc)) {
#ifdef DEBUG
			cmn_err(CE_WARN,
			    "_rdc_free_buf(%p): nsc_free_buf(%p) returned %d",
				(void *) h, (void *) h->rdc_bufp, rc);
#endif
			return (rc);
		}
	}

	if (h->rdc_flags & (RDC_REMOTE_BUF|RDC_VEC_ALLOC)) {
		if (h->rdc_flags & RDC_VEC_ALLOC) {
			kmem_free(h->rdc_bufh.sb_vec, h->rdc_vsize);
		}
		h->rdc_flags &= ~(RDC_REMOTE_BUF|RDC_VEC_ALLOC);
	}

	if (h->rdc_anon) {
		/* anon buffers still pending */
		DTRACE_PROBE1(rdc_free_buf_err, aio_buf_t, h->rdc_anon);
	}

	if ((h->rdc_bufh.sb_flag & NSC_HALLOCATED) == 0) {
		rc = _rdc_free_handle(h, h->rdc_fd);
		if (!RDC_SUCCESS(rc)) {
#ifdef DEBUG
			cmn_err(CE_WARN,
			    "_rdc_free_buf(%p): _rdc_free_handle returned %d",
				(void *) h, rc);
#endif
			return (rc);
		}
	} else {
		h->rdc_bufh.sb_flag = NSC_HALLOCATED;
		h->rdc_bufh.sb_vec = NULL;
		h->rdc_bufh.sb_error = 0;
		h->rdc_bufh.sb_pos = 0;
		h->rdc_bufh.sb_len = 0;
		h->rdc_anon = NULL;
		h->rdc_vsize = 0;

		cv_destroy(&h->rdc_sync.cv);
		mutex_destroy(&h->rdc_sync.lock);

	}

	return (0);
}


/*
 * _rdc_open
 *	Open a device
 *
 * Calling/Exit State:
 *	Returns a token to identify the device.
 *
 * Description:
 *	Performs the housekeeping operations associated with an upper layer
 *	of the nsctl stack opening a device.
 */

/* ARGSUSED */

static int
_rdc_open(char *path, int flag, blind_t *cdp, nsc_iodev_t *iodev)
{
	rdc_k_info_t *krdc;
#ifdef DEBUG
	rdc_u_info_t *urdc;
#endif
	rdc_fd_t *rfd;
	int raw = ((flag & NSC_CACHE) == 0);
	int index;
	int bmp = 0;
	int queue = 0;

	rfd = kmem_zalloc(sizeof (*rfd), KM_SLEEP);
	if (!rfd)
		return (ENOMEM);

	/*
	 * Take config lock to prevent a race with the
	 * (de)configuration code.
	 */

	mutex_enter(&rdc_conf_lock);

	index = rdc_lookup_enabled(path, 0);
	if (index < 0) {
		index = rdc_lookup_bitmap(path);
		if (index >= 0)
			bmp = 1;
	}
	if (index < 0) {
		index = rdc_lookup_diskq(path);
		if (index >= 0)
			queue = 1;
	}
	if (index < 0) {
		/* not found in config */
		mutex_exit(&rdc_conf_lock);
		kmem_free(rfd, sizeof (*rfd));
		return (ENXIO);
	}
#ifdef DEBUG
	urdc = &rdc_u_info[index];
#endif
	krdc = &rdc_k_info[index];

	mutex_exit(&rdc_conf_lock);

	rdc_group_enter(krdc);

	ASSERT(IS_ENABLED(urdc));

	if (bmp) {
		krdc->b_ref++;
	} else if (raw) {
		krdc->r_ref++;
	} else if (!queue) {
		krdc->c_ref++;
	}

	rfd->rdc_info = krdc;
	if (bmp)
		rfd->rdc_type = RDC_BMP;
	else if (queue)
		rfd->rdc_type = RDC_QUE;
	else
		rfd->rdc_oflags = flag;

	rdc_group_exit(krdc);

	*cdp = (blind_t)rfd;

	return (0);
}

static int
_rdc_openc(char *path, int flag, blind_t *cdp, nsc_iodev_t *iodev)
{
	return (_rdc_open(path, NSC_CACHE|flag, cdp, iodev));
}

static int
_rdc_openr(char *path, int flag, blind_t *cdp, nsc_iodev_t *iodev)
{
	return (_rdc_open(path, NSC_DEVICE|flag, cdp, iodev));
}


/*
 * _rdc_close
 *	Close a device
 *
 * Calling/Exit State:
 *	Always succeeds - returns 0
 *
 * Description:
 *	Performs the housekeeping operations associated with an upper layer
 *	of the sd stack closing a shadowed device.
 */

static int
_rdc_close(rfd)
rdc_fd_t *rfd;
{
	rdc_k_info_t *krdc = rfd->rdc_info;
	int bmp = RDC_IS_BMP(rfd);
	int raw = RDC_IS_RAW(rfd);
	int queue = RDC_IS_QUE(rfd);

	/*
	 * we don't keep ref counts for the queue, so skip this stuff.
	 * we may not even have a valid krdc at this point
	 */
	if (queue)
		goto queue;
	rdc_group_enter(krdc);

	if (bmp) {
		krdc->b_ref--;
	} else if (raw && !queue) {
		krdc->r_ref--;
	} else if (!queue) {
		krdc->c_ref--;
	}

	if (krdc->closing) {
		cv_broadcast(&krdc->closingcv);
	}

	rdc_group_exit(krdc);
queue:
	kmem_free(rfd, sizeof (*rfd));
	return (0);
}

/*
 * _rdc_alloc_handle
 *	Allocate a handle
 *
 */

static nsc_buf_t *
_rdc_alloc_handle(void (*d_cb)(), void (*r_cb)(), void (*w_cb)(), rdc_fd_t *rfd)
{
	rdc_buf_t *h;

	h = kmem_zalloc(sizeof (*h), KM_SLEEP);
	if (!h)
		return (NULL);

	h->rdc_bufp = nsc_alloc_handle(RDC_FD(rfd), d_cb, r_cb, w_cb);
	if (!h->rdc_bufp) {
		if (!IS_RFAILED(rfd->rdc_info)) {
			/*
			 * This is a real failure from the io provider below.
			 */
			kmem_free(h, sizeof (*h));
			return (NULL);
		} else {
			/* EMPTY */
			/*
			 * This is just a failed primary device where
			 * we can do remote io to the secondary.
			 */
		}
	}

	h->rdc_bufh.sb_flag = NSC_HALLOCATED;
	h->rdc_fd = rfd;
	mutex_init(&h->aio_lock, NULL, MUTEX_DRIVER, NULL);

	return (&h->rdc_bufh);
}


/*
 * _rdc_free_handle
 *	Free a handle
 *
 */

/* ARGSUSED */
static int
_rdc_free_handle(rdc_buf_t *h, rdc_fd_t *rfd)
{
	int rc;

	mutex_destroy(&h->aio_lock);
	if (h->rdc_bufp) {
		rc = nsc_free_handle(h->rdc_bufp);
		if (!RDC_SUCCESS(rc))
			return (rc);
	}
	kmem_free(h, sizeof (rdc_buf_t));
	return (0);
}


/*
 * _rdc_attach
 *	Attach
 *
 * Calling/Exit State:
 *	Returns 0 for success, errno on failure.
 *
 * Description:
 */

static int
_rdc_attach(rdc_fd_t *rfd, nsc_iodev_t *iodev)
{
	rdc_k_info_t *krdc;
	int raw = RDC_IS_RAW(rfd);
	int rc;

	if ((RDC_IS_BMP(rfd)) || RDC_IS_QUE(rfd))
		return (EINVAL);

	krdc = rfd->rdc_info;
	if (krdc == NULL)
		return (EINVAL);

	mutex_enter(&krdc->devices->id_rlock);
	krdc->iodev = iodev;
	mutex_exit(&krdc->devices->id_rlock);

	rc = _rdc_rsrv_devs(krdc, (raw ? RDC_RAW : RDC_CACHE), RDC_EXTERNAL);
	return (rc);
}


/*
 * _rdc_detach
 *	Detach
 *
 * Calling/Exit State:
 *	Returns 0 for success, always succeeds
 *
 * Description:
 */

static int
_rdc_detach(rdc_fd_t *rfd, nsc_iodev_t *iodev)
{
	rdc_k_info_t *krdc = rfd->rdc_info;
	int raw = RDC_IS_RAW(rfd);

	/*
	 * Flush the async queue if necessary.
	 */

	if (IS_ASYNC(&rdc_u_info[krdc->index]) && !RDC_IS_DISKQ(krdc->group)) {
		int tries = 1;

		while (krdc->group->ra_queue.blocks != 0 && tries--) {
			if (!krdc->group->rdc_writer)
				(void) rdc_writer(krdc->index);

			(void) rdc_drain_queue(krdc->index);
		}

		/* force disgard of possibly blocked flusher threads */
		if (rdc_drain_queue(krdc->index) != 0) {
#ifdef DEBUG
			net_queue *qp = &krdc->group->ra_queue;
#endif
			do {
				mutex_enter(&krdc->group->ra_queue.net_qlock);
				krdc->group->asyncdis = 1;
				cv_broadcast(&krdc->group->asyncqcv);
				mutex_exit(&krdc->group->ra_queue.net_qlock);
				cmn_err(CE_WARN,
	"RDC: async I/O pending and not drained for %s during detach",
				rdc_u_info[krdc->index].primary.file);
#ifdef DEBUG
				cmn_err(CE_WARN,
		"nitems: %" NSC_SZFMT " nblocks: %" NSC_SZFMT
		" head: 0x%p tail: 0x%p",
		    qp->nitems, qp->blocks, (void *)qp->net_qhead,
		    (void *)qp->net_qtail);
#endif
			} while (krdc->group->rdc_thrnum > 0);
		}
	}

	mutex_enter(&krdc->devices->id_rlock);
	if (krdc->iodev != iodev)
		cmn_err(CE_WARN, "_rdc_detach: iodev mismatch %p : %p",
		    (void *) krdc->iodev, (void *) iodev);

	krdc->iodev = NULL;
	mutex_exit(&krdc->devices->id_rlock);

	_rdc_rlse_devs(krdc, (raw ? RDC_RAW : RDC_CACHE));

	return (0);
}

/*
 * _rdc_get_pinned
 *
 * only affects local node.
 */

static int
_rdc_get_pinned(rdc_fd_t *rfd)
{
	return (nsc_get_pinned(RDC_FD(rfd)));
}

/*
 * _rdc_discard_pinned
 *
 * only affects local node.
 */

static int
_rdc_discard_pinned(rdc_fd_t *rfd, nsc_off_t pos, nsc_size_t len)
{
	return (nsc_discard_pinned(RDC_FD(rfd), pos, len));
}

/*
 * _rdc_partsize
 *
 * only affects the local node.
 */

static int
_rdc_partsize(rdc_fd_t *rfd, nsc_size_t *ptr)
{
	rdc_u_info_t *urdc;

	urdc = &rdc_u_info[rfd->rdc_info->index];
	/* Always return saved size */
	ASSERT(urdc->volume_size != 0);
	*ptr = urdc->volume_size;
	return (0);
}

/*
 * _rdc_maxfbas
 *
 * only affects local node
 */

/* ARGSUSED */
static int
_rdc_maxfbas(rdc_fd_t *rfd, int flag, nsc_size_t *ptr)
{
	rdc_k_info_t *krdc = rfd->rdc_info;
	int raw = RDC_IS_RAW(rfd);
	int rtype = raw ? RDC_RAW : RDC_CACHE;
	int rc = 0;

	if (krdc == NULL)
		return (EINVAL);
	if (flag == NSC_RDAHEAD || flag == NSC_CACHEBLK) {
		rc = _rdc_rsrv_devs(krdc, rtype, RDC_INTERNAL);
		if (rc == 0) {
			rc = nsc_maxfbas(RDC_U_FD(krdc), flag, ptr);
			_rdc_rlse_devs(krdc, rtype);
		}
	} else {
		/* Always return saved size */
		ASSERT(krdc->maxfbas != 0);
		*ptr = krdc->maxfbas - 1;
	}

	return (rc);
}

/* ARGSUSED */
static int
_rdc_control(rdc_fd_t *rfd, int cmd, void *ptr, int len)
{
	return (nsc_control(RDC_FD(rfd),  cmd, ptr, len));
}

/*
 * _rdc_attach_fd
 *
 * called by nsctl as part of nsc_reserve() processing when one of
 * SNDR's underlying file descriptors becomes available and metadata
 * should be re-acquired.
 */
static int
_rdc_attach_fd(blind_t arg)
{
	_rdc_info_dev_t *dip = (_rdc_info_dev_t *)arg;
	rdc_k_info_t *krdc;
	rdc_u_info_t *urdc;
	nsc_size_t maxfbas, partsize;
	int rc;

	krdc = dip->bi_krdc;
	urdc = &rdc_u_info[krdc->index];

	if ((rc = nsc_partsize(dip->bi_fd, &partsize)) != 0) {
		cmn_err(CE_WARN,
		    "SNDR: cannot get volume size of %s, error %d",
		    nsc_pathname(dip->bi_fd), rc);
	} else if (urdc->volume_size == 0 && partsize > 0) {
		/* set volume size for the first time */
		urdc->volume_size = partsize;
	} else if (urdc->volume_size != partsize) {
		/*
		 * SNDR cannot yet cope with a volume being resized,
		 * so fail it.
		 */
		if (!(rdc_get_vflags(urdc) & RDC_VOL_FAILED)) {
			rdc_many_enter(krdc);
			if (rdc_get_vflags(urdc) & RDC_PRIMARY)
				rdc_set_mflags(urdc, RDC_RSYNC_NEEDED);
			else
				rdc_set_mflags(urdc, RDC_SYNC_NEEDED);
			rdc_set_flags_log(urdc, RDC_VOL_FAILED,
			    "volume resized");
			rdc_many_exit(krdc);
			rdc_write_state(urdc);
		}

		cmn_err(CE_WARN,
		    "SNDR: %s changed size from %" NSC_SZFMT " to %" NSC_SZFMT,
		    nsc_pathname(dip->bi_fd), urdc->volume_size, partsize);
	}

	if ((rc = nsc_maxfbas(dip->bi_fd, 0, &maxfbas)) != 0) {
		cmn_err(CE_WARN,
		    "SNDR: cannot get max transfer size for %s, error %d",
		    nsc_pathname(dip->bi_fd), rc);
	} else if (maxfbas > 0) {
		krdc->maxfbas = min(RDC_MAX_MAXFBAS, maxfbas);
	}

	return (0);
}


/*
 * _rdc_pinned
 *
 * only affects local node
 */

static void
_rdc_pinned(_rdc_info_dev_t *dip, nsc_off_t pos, nsc_size_t len)
{
	nsc_pinned_data(dip->bi_krdc->iodev, pos, len);
}


/*
 * _rdc_unpinned
 *
 * only affects local node.
 */

static void
_rdc_unpinned(_rdc_info_dev_t *dip, nsc_off_t pos, nsc_size_t len)
{
	nsc_unpinned_data(dip->bi_krdc->iodev, pos, len);
}


/*
 * _rdc_read
 *
 * read the specified data into the buffer - go remote if local down,
 * or the remote end has more recent data because an reverse sync is
 * in progress.
 */

static int
_rdc_read(rdc_buf_t *h, nsc_off_t pos, nsc_size_t len, int flag)
{
	rdc_k_info_t *krdc = h->rdc_fd->rdc_info;
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];
	int remote = (RDC_REMOTE(h) || (rdc_get_mflags(urdc) & RDC_SLAVE));
	int rc1, rc2;

	rc1 = rc2 = 0;

	if (!RDC_HANDLE_LIMITS(&h->rdc_bufh, pos, len)) {
		cmn_err(CE_WARN,
		    "_rdc_read: bounds check: io(handle) pos %" NSC_XSZFMT
		    "(%" NSC_XSZFMT ") len %" NSC_XSZFMT "(%" NSC_XSZFMT ")",
			pos, h->rdc_bufh.sb_pos, len, h->rdc_bufh.sb_len);
		h->rdc_bufh.sb_error = EINVAL;
		return (h->rdc_bufh.sb_error);
	}

	if (flag & NSC_NOBLOCK) {
		cmn_err(CE_WARN,
		    "_rdc_read: removing unsupported NSC_NOBLOCK flag");
		flag &= ~(NSC_NOBLOCK);
	}


	if (!remote) {
		rc1 = nsc_read(h->rdc_bufp, pos, len, flag);
	}

	if (remote || !RDC_SUCCESS(rc1)) {
		rc2 = _rdc_remote_read(krdc, &h->rdc_bufh, pos, len, flag);
	}

	if (remote && !RDC_SUCCESS(rc2))
		h->rdc_bufh.sb_error = rc2;
	else if (!RDC_SUCCESS(rc1) && !RDC_SUCCESS(rc2))
		h->rdc_bufh.sb_error = rc1;

	return (h->rdc_bufh.sb_error);
}


static int
_rdc_remote_write(rdc_k_info_t *krdc, rdc_buf_t *h, nsc_buf_t *nsc_h,
    nsc_off_t pos, nsc_size_t len, int flag, uint_t bitmask)
{
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];
	int rc = 0;
	nsc_size_t plen, syncblockpos;
	aio_buf_t *anon = NULL;

	if (!(rdc_get_vflags(urdc) & RDC_PRIMARY))
		return (EINVAL);

	if ((rdc_get_vflags(urdc) & RDC_LOGGING) &&
	    (!IS_STATE(urdc, RDC_QUEUING))) {
		goto done;
	}

	/*
	 * this check for RDC_SYNCING may seem redundant, but there is a window
	 * in rdc_sync, where an async set has not yet been transformed into a
	 * sync set.
	 */
	if ((!IS_ASYNC(urdc) || IS_STATE(urdc, RDC_SYNCING)) ||
	    RDC_REMOTE(h) ||
	    krdc->group->synccount > 0 ||
	    (rdc_get_vflags(urdc) & RDC_SLAVE) ||
	    (rdc_get_vflags(urdc) & RDC_VOL_FAILED) ||
	    (rdc_get_vflags(urdc) & RDC_BMP_FAILED)) {

		/* sync mode, or remote io mode, or local device is dead */
		rc = rdc_net_write(krdc->index, krdc->remote_index,
		    nsc_h, pos, len, RDC_NOSEQ, RDC_NOQUE, NULL);

		if ((rc == 0) &&
		    !(rdc_get_vflags(urdc) & RDC_BMP_FAILED) &&
		    !(rdc_get_vflags(urdc) & RDC_VOL_FAILED)) {
			if (IS_STATE(urdc, RDC_SYNCING) &&
			    !IS_STATE(urdc, RDC_FULL) ||
			    !IS_STATE(urdc, RDC_SLAVE)) {
				mutex_enter(&krdc->syncbitmutex);

				syncblockpos = LOG_TO_FBA_NUM(krdc->syncbitpos);

				DTRACE_PROBE4(rdc_remote_write,
					nsc_off_t, krdc->syncbitpos,
					nsc_off_t, syncblockpos,
					nsc_off_t, pos,
					nsc_size_t, len);

				/*
				 * If the current I/O's position plus length is
				 * greater then the sync block position, only
				 * clear those blocks upto sync block position
				 */
				if (pos < syncblockpos) {
					if ((pos + len) > syncblockpos)
						plen = syncblockpos - pos;
					else
						plen = len;
					RDC_CLR_BITMAP(krdc, pos, plen, bitmask,
					    RDC_BIT_BUMP);
				}
				mutex_exit(&krdc->syncbitmutex);
			} else {
				RDC_CLR_BITMAP(krdc, pos, len, bitmask,
				    RDC_BIT_BUMP);
			}
		} else if (rc != 0) {
			rdc_group_enter(krdc);
			rdc_set_flags_log(urdc, RDC_LOGGING,
			    "net write failed");
			rdc_write_state(urdc);
			if (rdc_get_vflags(urdc) & RDC_SYNCING)
				krdc->disk_status = 1;
			rdc_group_exit(krdc);
		}
	} else if (!IS_STATE(urdc, RDC_SYNCING)) {
		DTRACE_PROBE1(async_enque_start, rdc_buf_t *, h);

		ASSERT(krdc->group->synccount == 0);
		/* async mode */
		if ((h == NULL) || ((h->rdc_flags & RDC_ASYNC_VEC) == 0)) {

			rc = _rdc_enqueue_write(krdc, pos, len, flag, NULL);

		} else {
			anon = rdc_aio_buf_get(h, krdc->index);
			if (anon == NULL) {
#ifdef DEBUG
				cmn_err(CE_WARN,
				    "enqueue write failed for handle %p",
					(void *) h);
#endif
				return (EINVAL);
			}
			rc = _rdc_enqueue_write(krdc, pos, len, flag,
			    anon->rdc_abufp);

			/*
			 * get rid of the aio_buf_t now, as this
			 * may not be the set that this rdc_buf
			 * was allocated on, we are done with it anyways
			 * enqueuing code frees the nsc_abuf
			 */
			rdc_aio_buf_del(h, krdc);
		}

	} else {
		ASSERT(IS_STATE(urdc, RDC_SYNCING));
		ASSERT(0);
	}

done:
	if ((anon == NULL) && h && (h->rdc_flags & RDC_ASYNC_VEC)) {
		/*
		 * Toss the anonymous buffer if we have one allocated.
		 */
		anon = rdc_aio_buf_get(h, krdc->index);
		if (anon) {
			(void) nsc_free_buf(anon->rdc_abufp);
			rdc_aio_buf_del(h, krdc);
		}
	}

	return (rc);
}

/*
 * _rdc_multi_write
 *
 * Send to multihop remote. Obeys 1 to many if present and we are crazy
 * enough to support it.
 *
 */
int
_rdc_multi_write(nsc_buf_t *h, nsc_off_t pos, nsc_size_t len, int flag,
    rdc_k_info_t *krdc)
{
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];
	rdc_k_info_t *this = krdc;	/* krdc that was requested */
	int rc, retval;
	uint_t bitmask;

	retval = rc = 0;
	if (!RDC_HANDLE_LIMITS(h, pos, len)) {
		cmn_err(CE_WARN,
	    "_rdc_multi_write: bounds check: io(handle) pos %" NSC_XSZFMT
	    "(%" NSC_XSZFMT ") len %" NSC_XSZFMT "(%" NSC_XSZFMT ")",
			pos, h->sb_pos, len, h->sb_len);
		return (EINVAL);
	}

	/* if this is a 1 to many, set all the bits for all the sets */
	do {
		if (RDC_SET_BITMAP(krdc, pos, len, &bitmask) < 0) {
			(void) nsc_uncommit(h, pos, len, flag);
			/* set the error, but try other sets */
			retval = EIO;
		}
		if (IS_MANY(krdc) && IS_STATE(urdc, RDC_PRIMARY)) {
			rdc_many_enter(krdc);
			for (krdc = krdc->many_next; krdc != this;
			    krdc = krdc->many_next) {
				urdc = &rdc_u_info[krdc->index];
				if (!IS_ENABLED(urdc))
					continue;
				break;
			}
			rdc_many_exit(krdc);
		}
	} while (krdc != this);

	urdc = &rdc_u_info[krdc->index];

	if (flag & NSC_NOBLOCK) {
		cmn_err(CE_WARN,
		    "_rdc_multi_write: removing unsupported NSC_NOBLOCK flag");
		flag &= ~(NSC_NOBLOCK);
	}

multiwrite1:
	if ((rdc_get_vflags(urdc) & RDC_PRIMARY) &&
	    (!IS_STATE(urdc, RDC_LOGGING) ||
	    (IS_STATE(urdc, RDC_LOGGING) &&
	    IS_STATE(urdc, RDC_QUEUING)))) {
		rc = _rdc_remote_write(krdc, NULL, h, pos, len, flag, bitmask);
	}

	if (!RDC_SUCCESS(rc) && retval == 0) {
		retval = rc;
	}

multiwrite2:
	if (IS_MANY(krdc) && (rdc_get_vflags(urdc) && RDC_PRIMARY)) {
		rdc_many_enter(krdc);
		for (krdc = krdc->many_next; krdc != this;
		    krdc = krdc->many_next) {
			urdc = &rdc_u_info[krdc->index];
			if (!IS_ENABLED(urdc))
				continue;
			rc = 0;
			rdc_many_exit(krdc);

			goto multiwrite1;
		}
		rdc_many_exit(krdc);
	}

	return (retval);
}

void
_rdc_diskq_enqueue_thr(rdc_aio_t *p)
{
	rdc_thrsync_t *sync = (rdc_thrsync_t *)p->next;
	rdc_k_info_t *krdc = &rdc_k_info[p->index];
	int rc2;


	rc2 = rdc_diskq_enqueue(krdc, p);

	/*
	 * overload flag with error return if any
	 */
	if (!RDC_SUCCESS(rc2)) {
		p->flag = rc2;
	} else {
		p->flag = 0;
	}
	mutex_enter(&sync->lock);
	sync->complete++;
	cv_broadcast(&sync->cv);
	mutex_exit(&sync->lock);
}

/*
 * _rdc_sync_write_thr
 * syncronous write thread which writes to network while
 * local write is occuring
 */
void
_rdc_sync_write_thr(rdc_aio_t *p)
{
	rdc_thrsync_t *sync = (rdc_thrsync_t *)p->next;
	rdc_buf_t *h = (rdc_buf_t *)p->handle;
	rdc_k_info_t *krdc = &rdc_k_info[p->index];
#ifdef	DEBUG
	rdc_u_info_t *urdc;
#endif
	int rc2;
	int bitmask;

	rdc_group_enter(krdc);
	krdc->aux_state |= RDC_AUXWRITE;
#ifdef	DEBUG
	urdc = &rdc_u_info[krdc->index];
	if (!IS_ENABLED(urdc)) {
		cmn_err(CE_WARN, "rdc_sync_write_thr: set not enabled %s:%s",
		    urdc->secondary.file,
		    urdc->secondary.bitmap);
	}
#endif
	rdc_group_exit(krdc);
	bitmask = p->iostatus;	/* overload */
	rc2 = _rdc_remote_write(krdc, h, &h->rdc_bufh, p->pos, p->len,
		p->flag, bitmask);


	/*
	 * overload flag with error return if any
	 */
	if (!RDC_SUCCESS(rc2)) {
		p->flag = rc2;
	} else {
		p->flag = 0;
	}

	rdc_group_enter(krdc);
	krdc->aux_state &= ~RDC_AUXWRITE;
	rdc_group_exit(krdc);

	mutex_enter(&sync->lock);
	sync->complete++;
	cv_broadcast(&sync->cv);
	mutex_exit(&sync->lock);
}

/*
 * _rdc_write
 *
 * Commit changes to the buffer locally and send remote.
 *
 * If this write is whilst the local primary volume is being synced,
 * then we write the remote end first to ensure that the new data
 * cannot be overwritten by a concurrent sync operation.
 */

static int
_rdc_write(rdc_buf_t *h, nsc_off_t pos, nsc_size_t len, int flag)
{
	rdc_k_info_t *krdc = h->rdc_fd->rdc_info;
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];
	rdc_k_info_t *this;
	rdc_k_info_t *multi = NULL;
	int remote = RDC_REMOTE(h);
	int rc1, rc2;
	uint_t bitmask;
	int first;
	int rsync;
	int nthr;
	int winddown;
	int thrrc = 0;
	rdc_aio_t *bp[SNDR_MAXTHREADS];
	aio_buf_t *anon;
	nsthread_t  *tp;
	rdc_thrsync_t *sync = &h->rdc_sync;

	/* If this is the multi-hop secondary, move along to the primary */
	if (IS_MULTI(krdc) && !IS_PRIMARY(urdc)) {
		multi = krdc;
		krdc = krdc->multi_next;
		urdc = &rdc_u_info[krdc->index];

		if (!IS_ENABLED(urdc)) {
			krdc = h->rdc_fd->rdc_info;
			urdc = &rdc_u_info[krdc->index];
			multi = NULL;
		}
	}
	this = krdc;

	rsync = (IS_PRIMARY(urdc)) && (IS_SLAVE(urdc));

	/*
	 * If this is a many group with a reverse sync in progress and
	 * this is not the slave krdc/urdc, then search for the slave
	 * so that we can do the remote io to the correct secondary
	 * before the local io.
	 */
	if (rsync && !(IS_SLAVE(urdc))) {
		rdc_many_enter(krdc);
		for (krdc = krdc->many_next; krdc != this;
		    krdc = krdc->many_next) {
			urdc = &rdc_u_info[krdc->index];
			if (!IS_ENABLED(urdc))
				continue;
			if (rdc_get_vflags(urdc) & RDC_SLAVE)
				break;
		}
		rdc_many_exit(krdc);

		this = krdc;
	}

	urdc = &rdc_u_info[krdc->index];

	rc1 = rc2 = 0;
	first = 1;
	nthr = 0;
	if (!RDC_HANDLE_LIMITS(&h->rdc_bufh, pos, len)) {
		cmn_err(CE_WARN,
		"_rdc_write: bounds check: io(handle) pos %" NSC_XSZFMT
		"(%" NSC_XSZFMT ") len %" NSC_XSZFMT "(%" NSC_XSZFMT ")",
			pos, h->rdc_bufh.sb_pos, len, h->rdc_bufh.sb_len);
		h->rdc_bufh.sb_error = EINVAL;
		return (h->rdc_bufh.sb_error);
	}

	DTRACE_PROBE(rdc_write_bitmap_start);

	/* if this is a 1 to many, set all the bits for all the sets */
	do {
		if (RDC_SET_BITMAP(krdc, pos, len, &bitmask) < 0) {
			if (rdc_eio_nobmp) {
			    (void) nsc_uncommit(h->rdc_bufp, pos, len, flag);
			    /* set the error, but try the other sets */
			    h->rdc_bufh.sb_error = EIO;
			}
		}

		if (IS_MANY(krdc) && IS_STATE(urdc, RDC_PRIMARY)) {
			rdc_many_enter(krdc);
			for (krdc = krdc->many_next; krdc != this;
			    krdc = krdc->many_next) {
				urdc = &rdc_u_info[krdc->index];
				if (!IS_ENABLED(urdc))
					continue;
				break;
			}
			rdc_many_exit(krdc);
		}

	} while (krdc != this);

	urdc = &rdc_u_info[krdc->index];

	DTRACE_PROBE(rdc_write_bitmap_end);

write1:
	/* just in case we switch mode during write */
	if (IS_ASYNC(urdc) && (!IS_STATE(urdc, RDC_SYNCING)) &&
	    (!IS_STATE(urdc, RDC_LOGGING) ||
	    IS_STATE(urdc, RDC_QUEUING))) {
		h->rdc_flags |= RDC_ASYNC_BUF;
	}
	if (BUF_IS_ASYNC(h)) {
		/*
		 * We are async mode
		 */
		aio_buf_t *p;
		DTRACE_PROBE(rdc_write_async_start);

		if ((krdc->type_flag & RDC_DISABLEPEND) ||
		    ((IS_STATE(urdc, RDC_LOGGING) &&
		    !IS_STATE(urdc, RDC_QUEUING)))) {
			goto localwrite;
		}
		if (IS_STATE(urdc, RDC_VOL_FAILED)) {
			/*
			 * overload remote as we don't want to do local
			 * IO later. forge ahead with async
			 */
			remote++;
		}
		if ((IS_STATE(urdc, RDC_SYNCING)) ||
		    (IS_STATE(urdc, RDC_LOGGING) &&
		    !IS_STATE(urdc, RDC_QUEUING))) {
			goto localwrite;
		}

		p = rdc_aio_buf_add(krdc->index, h);
		if (p == NULL) {
#ifdef DEBUG
			cmn_err(CE_WARN,
			    "rdc_alloc_buf  aio_buf allocation failed");
#endif
			goto localwrite;
		}

		mutex_enter(&h->aio_lock);

		DTRACE_PROBE(rdc_write_async__allocabuf_start);
		rc1 = nsc_alloc_abuf(pos, len, 0, &p->rdc_abufp);
		DTRACE_PROBE(rdc_write_async__allocabuf_end);
		if (!RDC_SUCCESS(rc1)) {
#ifdef DEBUG
			cmn_err(CE_WARN,
			    "rdc_alloc_buf NSC_ANON allocation failed"
			    " rc %d",
			    rc1);
#endif
			mutex_exit(&h->aio_lock);
			goto localwrite;
		}
		h->rdc_flags |= RDC_ASYNC_VEC;
		mutex_exit(&h->aio_lock);

		/*
		 * Copy buffer into anonymous buffer
		 */

		DTRACE_PROBE(rdc_write_async_nsccopy_start);
		rc1 =
		    nsc_copy(&h->rdc_bufh, p->rdc_abufp, pos, pos, len);
		DTRACE_PROBE(rdc_write_async_nsccopy_end);
		if (!RDC_SUCCESS(rc1)) {
#ifdef DEBUG
			cmn_err(CE_WARN,
			    "_rdc_write: nsc_copy failed rc=%d state %x",
			    rc1, rdc_get_vflags(urdc));
#endif
			rc1 = nsc_free_buf(p->rdc_abufp);
			rdc_aio_buf_del(h, krdc);
			rdc_group_enter(krdc);
			rdc_group_log(krdc, RDC_FLUSH|RDC_OTHERREMOTE,
				"nsc_copy failure");
			rdc_group_exit(krdc);
		}
		DTRACE_PROBE(rdc_write_async_end);

		/*
		 * using a diskq, launch a thread to queue it
		 * and free the aio->h and aio
		 * if the thread fails, do it the old way (see localwrite)
		 */

		if (RDC_IS_DISKQ(krdc->group)) {

			if (nthr >= SNDR_MAXTHREADS) {
#ifdef DEBUG
				cmn_err(CE_NOTE, "nthr overrun in _rdc_write");
#endif
				thrrc = ENOEXEC;
				goto localwrite;
			}

			anon = rdc_aio_buf_get(h, krdc->index);
			if (anon == NULL) {
#ifdef DEBUG
				cmn_err(CE_WARN, "rdc_aio_buf_get failed for "
				    "%p", (void *)h);
#endif
				thrrc = ENOEXEC;
				goto localwrite;
			}

			/* get a populated rdc_aio_t */
			bp[nthr] =
			    rdc_aio_tbuf_get(sync, anon->rdc_abufp, pos, len,
			    flag, krdc->index, bitmask);

			if (bp[nthr] == NULL) {
#ifdef DEBUG
				cmn_err(CE_NOTE, "_rdcwrite: "
				    "kmem_alloc failed bp aio (1)");
#endif
				thrrc = ENOEXEC;
				goto localwrite;
			}
			/* start the queue io */
			tp = nst_create(_rdc_ioset, _rdc_diskq_enqueue_thr,
				(void *)bp[nthr], NST_SLEEP);

			if (tp == NULL) {
#ifdef DEBUG
				cmn_err(CE_NOTE,
					"_rdcwrite: nst_create failure");
#endif
				thrrc = ENOEXEC;
			} else {
				mutex_enter(&(sync->lock));
				sync->threads++;
				mutex_exit(&(sync->lock));
				nthr++;

			}
			/*
			 * the handle that is to be enqueued is now in
			 * the rdc_aio_t, and will be freed there.
			 * dump the aio_t now. If this is 1 to many
			 * we may not do this in _rdc_free_buf()
			 * if this was not the index that the rdc_buf_t
			 * was allocated on.
			 */
			rdc_aio_buf_del(h, krdc);

		}
	}	/* end of async */

	/*
	 * We try to overlap local and network IO for the sync case
	 * (we already do it for async)
	 * If one to many, we need to track the resulting nst_thread
	 * so we don't trash the nsc_buf on a free
	 * Start network IO first then do local (sync only)
	 */

	if (IS_PRIMARY(urdc) && !IS_STATE(urdc, RDC_LOGGING) &&
		!BUF_IS_ASYNC(h)) {


		/*
		 * if forward syncing, we must do local IO first
		 * then remote io. Don't spawn thread
		 */
		if (!rsync && (IS_STATE(urdc, RDC_SYNCING))) {
			thrrc = ENOEXEC;
			goto localwrite;
		}
		if (IS_MULTI(krdc)) {
			rdc_k_info_t *ktmp;
			rdc_u_info_t *utmp;

			ktmp = krdc->multi_next;
			utmp = &rdc_u_info[ktmp->index];
			if (IS_ENABLED(utmp))
				multi = ktmp;
		}
		if (nthr >= SNDR_MAXTHREADS) {
#ifdef DEBUG
			cmn_err(CE_NOTE, "nthr overrun in _rdc_write");
#endif
			thrrc = ENOEXEC;
			goto localwrite;
		}

		bp[nthr] = rdc_aio_tbuf_get(sync, h, pos, len,
		    flag, krdc->index, bitmask);

		if (bp[nthr] == NULL) {
#ifdef DEBUG
			cmn_err(CE_NOTE, "_rdcwrite: kmem_alloc failed bp aio");
#endif
			thrrc = ENOEXEC;
			goto localwrite;
		}
		tp = nst_create(_rdc_ioset, _rdc_sync_write_thr,
			(void *)bp[nthr], NST_SLEEP);
		if (tp == NULL) {
#ifdef DEBUG
			cmn_err(CE_NOTE,
				"_rdcwrite: nst_create failure");
#endif
			thrrc = ENOEXEC;
		} else {
			mutex_enter(&(sync->lock));
			sync->threads++;
			mutex_exit(&(sync->lock));
			nthr++;
		}
	}
localwrite:
	if (!remote && !rsync && first) {
		DTRACE_PROBE(rdc_write_nscwrite_start);
		rc1 = nsc_write(h->rdc_bufp, pos, len, flag);
		DTRACE_PROBE(rdc_write_nscwrite_end);
		if (!RDC_SUCCESS(rc1)) {
			rdc_many_enter(krdc);
			if (IS_PRIMARY(urdc))
				/* Primary, so reverse sync needed */
				rdc_set_mflags(urdc, RDC_RSYNC_NEEDED);
			else
				/* Secondary, so sync needed */
				rdc_set_flags(urdc, RDC_SYNC_NEEDED);
			rdc_set_flags_log(urdc, RDC_VOL_FAILED,
			    "local write failed");
			rdc_many_exit(krdc);
			rdc_write_state(urdc);
		}
	}

	/*
	 * This is where we either enqueue async IO for the flusher
	 * or do sync IO in the case of an error in thread creation
	 * or we are doing a forward sync
	 * NOTE: if we are async, and using a diskq, we have
	 * already enqueued this write.
	 * _rdc_remote_write will end up enqueuueing to memory,
	 * or in case of a thread creation error above, try again
	 * enqueue the diskq write if thrrc == ENOEXEC
	 */
	if ((IS_PRIMARY(urdc)) && (thrrc == ENOEXEC) ||
	    (BUF_IS_ASYNC(h) && !RDC_IS_DISKQ(krdc->group))) {
		thrrc = 0;
		if (IS_MULTI(krdc)) {
			rdc_k_info_t *ktmp;
			rdc_u_info_t *utmp;

			ktmp = krdc->multi_next;
			utmp = &rdc_u_info[ktmp->index];
			if (IS_ENABLED(utmp))
				multi = ktmp;
		}

		DTRACE_PROBE(rdc_write_remote_start);

		rc2 = _rdc_remote_write(krdc, h, &h->rdc_bufh,
		    pos, len, flag, bitmask);

		DTRACE_PROBE(rdc_rdcwrite_remote_end);
	}

	if (!RDC_SUCCESS(rc1)) {
		if ((IS_PRIMARY(urdc)) && !RDC_SUCCESS(rc2)) {
			h->rdc_bufh.sb_error = rc1;
		}
	} else if ((remote || rsync) && !RDC_SUCCESS(rc2)) {
		h->rdc_bufh.sb_error = rc2;
	}
write2:
	/*
	 * If one to many, jump back into the loop to continue IO
	 */
	if (IS_MANY(krdc) && (IS_PRIMARY(urdc))) {
		rdc_many_enter(krdc);
		for (krdc = krdc->many_next; krdc != this;
		    krdc = krdc->many_next) {
			urdc = &rdc_u_info[krdc->index];
			if (!IS_ENABLED(urdc))
				continue;
			rc2 = first = 0;
			h->rdc_flags &= ~RDC_ASYNC_BUF;
			rdc_many_exit(krdc);
			goto write1;
		}
		rdc_many_exit(krdc);
	}
	urdc = &rdc_u_info[krdc->index];

	/*
	 * collect all of our threads if any
	 */
	if (nthr) {

		mutex_enter(&(sync->lock));
		/* wait for the threads */
		while (sync->complete != sync->threads) {
			cv_wait(&(sync->cv), &(sync->lock));
		}
		mutex_exit(&(sync->lock));

		/* collect status */

		winddown = 0;
		while (winddown < nthr) {
			/*
			 * Get any error return from thread
			 */
			if ((remote || rsync) && bp[winddown]->flag) {
				h->rdc_bufh.sb_error =
					bp[winddown]->flag;
			}
			if (bp[winddown])
				kmem_free(bp[winddown], sizeof (rdc_aio_t));
			winddown++;
		}
	}

	if (rsync && !(IS_STATE(urdc, RDC_VOL_FAILED))) {
		rc1 = nsc_write(h->rdc_bufp, pos, len, flag);
		if (!RDC_SUCCESS(rc1)) {
			/* rsync, so reverse sync needed already set */
			rdc_many_enter(krdc);
			rdc_set_flags_log(urdc, RDC_VOL_FAILED,
			    "rsync local write failed");
			rdc_many_exit(krdc);
			rdc_write_state(urdc);

			/*
			 * only report the error if a remote error
			 * occurred as well.
			 */
			if (h->rdc_bufh.sb_error)
				h->rdc_bufh.sb_error = rc1;
		}
	}

	if (multi) {
		/* Multi-hop secondary, just set bits in the bitmap */
		(void) RDC_SET_BITMAP(multi, pos, len, &bitmask);
	}

	return (h->rdc_bufh.sb_error);
}


static void
_rdc_bzero(nsc_buf_t *h, nsc_off_t pos, nsc_size_t len)
{
	nsc_vec_t *v;
	uchar_t *a;
	size_t sz;
	int l;

	if (!RDC_HANDLE_LIMITS(h, pos, len)) {
		cmn_err(CE_WARN,
		"_rdc_bzero: bounds check: io(handle) pos %" NSC_XSZFMT
		"(%" NSC_XSZFMT ") len %" NSC_XSZFMT "(%" NSC_XSZFMT ")",
			pos, h->sb_pos, len, h->sb_len);
		return;
	}

	if (!len)
		return;

	/* find starting point */

	v = h->sb_vec;
	pos -= h->sb_pos;

	for (; pos >= FBA_NUM(v->sv_len); v++)
		pos -= FBA_NUM(v->sv_len);

	a = v->sv_addr + FBA_SIZE(pos);
	l = v->sv_len - FBA_SIZE(pos);

	/* zero */

	len = FBA_SIZE(len);	/* convert to bytes */

	while (len) {
		if (!a)		/* end of vec */
			break;

		sz = (size_t)min((nsc_size_t)l, len);

		bzero(a, sz);

		len -= sz;
		l -= sz;
		a += sz;

		if (!l) {
			v++;
			a = v->sv_addr;
			l = v->sv_len;
		}
	}
}


/*
 * _rdc_zero
 *
 * Zero and commit the specified area of the buffer.
 *
 * If this write is whilst the local primary volume is being synced,
 * then we write the remote end first to ensure that the new data
 * cannot be overwritten by a concurrent sync operation.
 */

static int
_rdc_zero(rdc_buf_t *h, nsc_off_t pos, nsc_size_t len, int flag)
{
	rdc_k_info_t *krdc = h->rdc_fd->rdc_info;
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];
	rdc_k_info_t *this;
	rdc_k_info_t *multi = NULL;
	int remote = RDC_REMOTE(h);
	int rc1, rc2;
	uint_t bitmask;
	int first;
	int rsync;

	/* If this is the multi-hop secondary, move along to the primary */
	if (IS_MULTI(krdc) && !(rdc_get_vflags(urdc) & RDC_PRIMARY)) {
		multi = krdc;
		krdc = krdc->multi_next;
		urdc = &rdc_u_info[krdc->index];

		if (!IS_ENABLED(urdc)) {
			krdc = h->rdc_fd->rdc_info;
			urdc = &rdc_u_info[krdc->index];
			multi = NULL;
		}
	}
	this = krdc;

	rsync = ((rdc_get_vflags(urdc) & RDC_PRIMARY) &&
	    (rdc_get_mflags(urdc) & RDC_SLAVE));

	/*
	 * If this is a many group with a reverse sync in progress and
	 * this is not the slave krdc/urdc, then search for the slave
	 * so that we can do the remote io to the correct secondary
	 * before the local io.
	 */
	if (rsync && !(rdc_get_vflags(urdc) & RDC_SLAVE)) {
		rdc_many_enter(krdc);
		for (krdc = krdc->many_next; krdc != this;
		    krdc = krdc->many_next) {
			urdc = &rdc_u_info[krdc->index];
			if (!IS_ENABLED(urdc))
				continue;
			if (rdc_get_vflags(urdc) & RDC_SLAVE)
				break;
		}
		rdc_many_exit(krdc);

		this = krdc;
	}

	rc1 = rc2 = 0;
	first = 1;

	if (!RDC_HANDLE_LIMITS(&h->rdc_bufh, pos, len)) {
		cmn_err(CE_WARN,
		    "_rdc_zero: bounds check: io(handle) pos %" NSC_XSZFMT
		    "(%" NSC_XSZFMT ") len %" NSC_XSZFMT "(%" NSC_XSZFMT ")",
			pos, h->rdc_bufh.sb_pos, len, h->rdc_bufh.sb_len);
		h->rdc_bufh.sb_error = EINVAL;
		return (h->rdc_bufh.sb_error);
	}

zero1:
	if (RDC_SET_BITMAP(krdc, pos, len, &bitmask) < 0) {
		(void) nsc_uncommit(h->rdc_bufp, pos, len, flag);
		h->rdc_bufh.sb_error = EIO;
		goto zero2;
	}

	if (IS_ASYNC(urdc)) {
		/*
		 * We are async mode
		 */
		aio_buf_t *p;

		if ((krdc->type_flag & RDC_DISABLEPEND) ||
		    (rdc_get_vflags(urdc) & RDC_LOGGING)) {
			mutex_exit(&krdc->group->ra_queue.net_qlock);
			goto localzero;
		}

		if ((rdc_get_vflags(urdc) & RDC_VOL_FAILED) ||
		    (rdc_get_vflags(urdc) & RDC_BMP_FAILED)) {
			mutex_exit(&krdc->group->ra_queue.net_qlock);
			goto zero2;
		}
		if (rdc_get_vflags(urdc) & RDC_LOGGING) {
			mutex_exit(&krdc->group->ra_queue.net_qlock);
			goto localzero;
		}
		p = rdc_aio_buf_add(krdc->index, h);
		if (p == NULL) {
#ifdef DEBUG
			cmn_err(CE_WARN,
			    "rdc_alloc_buf  aio_buf allocation failed");
#endif
			goto localzero;
		}
		mutex_enter(&h->aio_lock);
		rc1 = nsc_alloc_abuf(pos, len, 0, &p->rdc_abufp);
		if (!RDC_SUCCESS(rc1)) {
#ifdef DEBUG
			cmn_err(CE_WARN,
			    "rdc_alloc_buf NSC_ANON allocation failed rc %d",
			    rc1);
#endif
			mutex_exit(&h->aio_lock);
			goto localzero;
		}
		h->rdc_flags |= RDC_ASYNC_VEC;
		mutex_exit(&h->aio_lock);

		/*
		 * Copy buffer into anonymous buffer
		 */

		rc1 = nsc_zero(p->rdc_abufp, pos, len, flag);
		if (!RDC_SUCCESS(rc1)) {
#ifdef DEBUG
			cmn_err(CE_WARN,
			    "_rdc_zero: nsc_zero failed rc=%d state %x",
			    rc1, rdc_get_vflags(urdc));
#endif
			rc1 = nsc_free_buf(p->rdc_abufp);
			rdc_aio_buf_del(h, krdc);
			rdc_group_enter(krdc);
			rdc_group_log(krdc, RDC_FLUSH | RDC_OTHERREMOTE,
				"nsc_zero failed");
			rdc_group_exit(krdc);
		}
	}	/* end of async */

localzero:

	if (flag & NSC_NOBLOCK) {
		cmn_err(CE_WARN,
		    "_rdc_zero: removing unsupported NSC_NOBLOCK flag");
		flag &= ~(NSC_NOBLOCK);
	}

	if (!remote && !rsync && first) {
		rc1 = nsc_zero(h->rdc_bufp, pos, len, flag);
		if (!RDC_SUCCESS(rc1)) {
			ASSERT(rdc_get_vflags(urdc) & RDC_PRIMARY);
			rdc_many_enter(krdc);
			/* Primary, so reverse sync needed */
			rdc_set_mflags(urdc, RDC_RSYNC_NEEDED);
			rdc_set_flags_log(urdc, RDC_VOL_FAILED,
			    "nsc_zero failed");
			rdc_many_exit(krdc);
			rdc_write_state(urdc);
		}
	}

	/*
	 * send new data to remote end - nsc_zero has zero'd
	 * the data in the buffer, or _rdc_bzero will be used below.
	 */

	if (rdc_get_vflags(urdc) & RDC_PRIMARY) {
		if (first && (remote || rsync || !RDC_SUCCESS(rc1))) {
			/* bzero so that we can send new data to remote node */
			_rdc_bzero(&h->rdc_bufh, pos, len);
		}

		if (IS_MULTI(krdc)) {
			rdc_k_info_t *ktmp;
			rdc_u_info_t *utmp;

			ktmp = krdc->multi_next;
			utmp = &rdc_u_info[ktmp->index];
			if (IS_ENABLED(utmp))
				multi = ktmp;
		}

		rc2 = _rdc_remote_write(krdc, h, &h->rdc_bufh,
		    pos, len, flag, bitmask);
	}

	if (!RDC_SUCCESS(rc1)) {
		if ((rdc_get_vflags(urdc) & RDC_PRIMARY) && !RDC_SUCCESS(rc2)) {
			h->rdc_bufh.sb_error = rc1;
		}
	} else if ((remote || rsync) && !RDC_SUCCESS(rc2)) {
		h->rdc_bufh.sb_error = rc2;
	}

zero2:
	if (IS_MANY(krdc) && (rdc_get_vflags(urdc) && RDC_PRIMARY)) {
		rdc_many_enter(krdc);
		for (krdc = krdc->many_next; krdc != this;
		    krdc = krdc->many_next) {
			urdc = &rdc_u_info[krdc->index];
			if (!IS_ENABLED(urdc))
				continue;
			rc2 = first = 0;
			rdc_many_exit(krdc);
			goto zero1;
		}
		rdc_many_exit(krdc);
	}

	if (rsync && !(rdc_get_vflags(urdc) & RDC_VOL_FAILED)) {
		rc1 = nsc_write(h->rdc_bufp, pos, len, flag);
		if (!RDC_SUCCESS(rc1)) {
			/* rsync, so reverse sync needed already set */
			rdc_many_enter(krdc);
			rdc_set_flags_log(urdc, RDC_VOL_FAILED,
			    "nsc_write failed");
			rdc_many_exit(krdc);
			rdc_write_state(urdc);

			/*
			 * only report the error if a remote error
			 * occurred as well.
			 */
			if (h->rdc_bufh.sb_error)
				h->rdc_bufh.sb_error = rc1;
		}
	}

	if (multi) {
		/* Multi-hop secondary, just set bits in the bitmap */
		(void) RDC_SET_BITMAP(multi, pos, len, &bitmask);
	}

	return (h->rdc_bufh.sb_error);
}


/*
 * _rdc_uncommit
 * - refresh specified data region in the buffer to prevent the cache
 *   serving the scribbled on data back to another client.
 *
 * Only needs to happen on the local node.  If in remote io mode, then
 * just return 0 - we do not cache the data on the local node and the
 * changed data will not have made it to the cache on the other node,
 * so it has no need to uncommit.
 */

static int
_rdc_uncommit(rdc_buf_t *h, nsc_off_t pos, nsc_size_t len, int flag)
{
	int remote = RDC_REMOTE(h);
	int rc = 0;

	if (!RDC_HANDLE_LIMITS(&h->rdc_bufh, pos, len)) {
		cmn_err(CE_WARN,
		"_rdc_uncommit: bounds check: io(handle) pos %" NSC_XSZFMT
		"(%" NSC_XSZFMT ") len %" NSC_XSZFMT "(%" NSC_XSZFMT ")",
			pos, h->rdc_bufh.sb_pos, len, h->rdc_bufh.sb_len);
		h->rdc_bufh.sb_error = EINVAL;
		return (h->rdc_bufh.sb_error);
	}

	if (flag & NSC_NOBLOCK) {
		cmn_err(CE_WARN,
		    "_rdc_uncommit: removing unsupported NSC_NOBLOCK flag");
		flag &= ~(NSC_NOBLOCK);
	}

	if (!remote) {
		rc = nsc_uncommit(h->rdc_bufp, pos, len, flag);
	}

	if (!RDC_SUCCESS(rc))
		h->rdc_bufh.sb_error = rc;

	return (rc);
}


/*
 * _rdc_trksize
 *
 * only needs to happen on local node.
 */

static int
_rdc_trksize(rdc_fd_t *rfd, nsc_size_t trksize)
{
	return (nsc_set_trksize(RDC_FD(rfd), trksize));
}


static nsc_def_t _rdc_fd_def[] = {
	"Attach",	(uintptr_t)_rdc_attach_fd,	0,
	"Pinned",	(uintptr_t)_rdc_pinned,		0,
	"Unpinned",	(uintptr_t)_rdc_unpinned,	0,
	0,		0,				0
};


static nsc_def_t _rdc_io_def[] = {
	"Open",		(uintptr_t)_rdc_openc,		0,
	"Close",	(uintptr_t)_rdc_close,		0,
	"Attach",	(uintptr_t)_rdc_attach,		0,
	"Detach",	(uintptr_t)_rdc_detach,		0,
	"AllocHandle",	(uintptr_t)_rdc_alloc_handle,	0,
	"FreeHandle",	(uintptr_t)_rdc_free_handle,	0,
	"AllocBuf",	(uintptr_t)_rdc_alloc_buf,	0,
	"FreeBuf",	(uintptr_t)_rdc_free_buf,	0,
	"GetPinned",	(uintptr_t)_rdc_get_pinned,	0,
	"Discard",	(uintptr_t)_rdc_discard_pinned,	0,
	"PartSize",	(uintptr_t)_rdc_partsize,	0,
	"MaxFbas",	(uintptr_t)_rdc_maxfbas,	0,
	"Control",	(uintptr_t)_rdc_control,	0,
	"Read",		(uintptr_t)_rdc_read,		0,
	"Write",	(uintptr_t)_rdc_write,		0,
	"Zero",		(uintptr_t)_rdc_zero,		0,
	"Uncommit",	(uintptr_t)_rdc_uncommit,	0,
	"TrackSize",	(uintptr_t)_rdc_trksize,	0,
	"Provide",	0,				0,
	0,		0,				0
};

static nsc_def_t _rdc_ior_def[] = {
	"Open",		(uintptr_t)_rdc_openr,		0,
	"Close",	(uintptr_t)_rdc_close,		0,
	"Attach",	(uintptr_t)_rdc_attach,		0,
	"Detach",	(uintptr_t)_rdc_detach,		0,
	"AllocHandle",	(uintptr_t)_rdc_alloc_handle,	0,
	"FreeHandle",	(uintptr_t)_rdc_free_handle,	0,
	"AllocBuf",	(uintptr_t)_rdc_alloc_buf,	0,
	"FreeBuf",	(uintptr_t)_rdc_free_buf,	0,
	"GetPinned",	(uintptr_t)_rdc_get_pinned,	0,
	"Discard",	(uintptr_t)_rdc_discard_pinned,	0,
	"PartSize",	(uintptr_t)_rdc_partsize,	0,
	"MaxFbas",	(uintptr_t)_rdc_maxfbas,	0,
	"Control",	(uintptr_t)_rdc_control,	0,
	"Read",		(uintptr_t)_rdc_read,		0,
	"Write",	(uintptr_t)_rdc_write,		0,
	"Zero",		(uintptr_t)_rdc_zero,		0,
	"Uncommit",	(uintptr_t)_rdc_uncommit,	0,
	"TrackSize",	(uintptr_t)_rdc_trksize,	0,
	"Provide",	0,				0,
	0,		0,				0
};
