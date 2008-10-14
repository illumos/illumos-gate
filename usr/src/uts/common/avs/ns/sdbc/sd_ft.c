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
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/cred.h>
#include <sys/ddi.h>

#include <sys/nsc_thread.h>
#include <sys/nsctl/nsctl.h>

#include <sys/sdt.h>		/* dtrace is S10 or later */

#include "sd_bcache.h"
#include "sd_ft.h"
#include "sd_trace.h"
#include "sd_io.h"
#include "sd_misc.h"
#include <sys/ncall/ncall.h>

_sd_ft_info_t  _sd_ft_data;

static volatile int _sd_ft_exit = 0;
static kcondvar_t _sd_ft_cv;
int _sd_node_recovery;		/* node recovery in progress */
/*
 *  _sd_async_recovery:
 *	0 = flush and wait
 *	1 = clone and async-write
 *	2 = quicksort, clone, and async-write
 * quicksort allows contiguous blocks to be joined,
 * which may greatly improve recovery time for raid devices.
 * if kmem_alloc fails, acts as _sd_async_recovery == 1
 */
static int _sd_async_recovery = 2;
static int xmem_inval_hit, xmem_inval_miss, xmem_inval_inuse;


/*
 * flag to inhibit reset of remote SCSI buses and sending of
 * nodedown callback if mirror was deconfigured properly.
 * - prevents trashing any I/O that may be happening on the mirror
 *   node during a normal shutdown and prevents undesired simckd failover.
 */
static int mirror_clean_shutdown = 0;

/*
 * Forward declare all statics that are used before defined to enforce
 * parameter checking
 * Some (if not all) of these could be removed if the code were reordered
 */

static void _sd_health_thread(void);
static void _sd_cache_recover(void);
static int _sd_ft_clone(ss_centry_info_t *, int);
static void _sd_remote_enable(void);
static void sdbc_setmodeandftdata();
static void _sd_cd_discard_mirror(int cd);
static int _sd_failover_file_open(void);
static void _sd_failover_done(void);
static void _sd_wait_for_dirty(void);
static void _sdbc_clear_warm_start(void);
static int sdbc_recover_vol(ss_vol_t *, int);
void _ncall_poke(int);

int _sdbc_ft_hold_io;
kcondvar_t _sdbc_ft_hold_io_cv;
kmutex_t _sdbc_ft_hold_io_lk;
extern int sdbc_use_dmchain;
extern void sdbc_requeue_head_dm_try(_sd_cctl_t *cc_ent);

/*
 * _sdbc_ft_unload - cache is being unloaded (or failed to load).
 * Deallocate any global lock/sv that we created.
 */
void
_sdbc_ft_unload(void)
{
	cv_destroy(&_sd_ft_cv);
	mutex_destroy(&_sd_ft_data.fi_lock);
	cv_destroy(&_sd_ft_data.fi_rem_sv);
	mutex_destroy(&_sd_ft_data.fi_sleep);
	bzero(&_sd_ft_data, sizeof (_sd_ft_info_t));
}

/*
 * _sdbc_ft_load - cache is being loaded. Allocate all global lock/sv
 * that we need. Return 0 if we succeed. If we fail return -1 (don't
 * need to do the unload step as we expect our caller to do that).
 */
int
_sdbc_ft_load(void)
{
	/* _sd_ft_data is sure to be zeroes, don't need to bzero it */

	mutex_init(&_sd_ft_data.fi_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&_sd_ft_data.fi_rem_sv, NULL, CV_DRIVER, NULL);
	cv_init(&_sd_ft_cv, NULL, CV_DRIVER, NULL);
	mutex_init(&_sd_ft_data.fi_sleep, NULL, MUTEX_DRIVER, NULL);
	return (0);
}
int
_sdbc_ft_configure(void)
{
	_sd_ft_exit = 1;
	return (nsc_create_process(
		(void (*)(void *))_sd_health_thread, 0, TRUE));
}




void
_sdbc_ft_deconfigure(void)
{
	_sd_ft_exit = 0;
	_sd_unblock(&_sd_ft_cv);
	mutex_enter(&_sd_ft_data.fi_lock);
	_sd_node_recovery = 0;
	cv_broadcast(&_sd_ft_data.fi_rem_sv);
	mutex_exit(&_sd_ft_data.fi_lock);
}


/*
 * _sd_health_thread -- daemon thread on each node watches if mirror
 * node to has crashed, and it needs to flush the mirrors cache entries.
 * Note we do *not* detect that the node has come up again, but wait
 * for the node to inform us that it is up via _sd_cache_reenable().
 */
static void
_sd_health_thread(void)
{
	int warm_started = 0;

	mutex_enter(&_sd_cache_lock);
	_sd_cache_dem_cnt++;
	mutex_exit(&_sd_cache_lock);

	/* clear _sd_ft_data in case this is a cache re-enable w/o unload */

	bzero(&_sd_ft_data, sizeof (_sd_ft_info_t));

	sdbc_setmodeandftdata();

#ifdef DEBUG
	cmn_err(CE_NOTE, "sdbc(_sd_health_thread) safestore "
	    "is %s. Fast writes %s",
	    (_SD_MIRROR_CONFIGD) ? "up" : "down",
	    (_SD_NODE_HINTS & _SD_WRTHRU_MASK) ?
	    "disabled" : "enabled");
#endif

	/* CONSTCOND */
	while (1) {
		_sd_timed_block(HZ/8, &_sd_ft_cv);
		if (_sd_ft_exit == 0) {
			mutex_enter(&_sd_cache_lock);
			_sd_cache_dem_cnt--;
			mutex_exit(&_sd_cache_lock);
			return;
		}

		/* NB evaluation order is important here for nvmem systems */
		if (_sd_is_mirror_crashed() ||
		    (warm_started = _sdbc_warm_start())) {

			/*
			 * Hash invalidate here. We do not want data from
			 * previous failover incarnation to be cache hits, if
			 * the 2 failover happens within a short time
			 */
			_sd_hash_invalidate_cd(-1);

			/*
			 * don't change mirror state when warm starting
			 * nvmem systems.  _sd_mirror_down() is called in
			 * in _sd_remote_enable() on nvmem systems if the
			 * media is down.
			 */
			if (!warm_started)
				if (!mirror_clean_shutdown)
					_sd_mirror_down();
				else
					_sd_mirror_cache_down();

			(void) _sd_set_node_hint(NSC_FORCED_WRTHRU);
			if (!warm_started) {
				/* was FAST */
				mutex_enter(&_sd_ft_data.fi_lock);
				_sd_node_recovery = 0;
				/* was FAST */
				mutex_exit(&_sd_ft_data.fi_lock);
				/* Assume other side is still up */
				cmn_err(CE_WARN,
				    "sdbc(_sd_health_thread)"
				    "Safestore is down. Fast writes %s",
				    (_SD_NODE_HINTS & _SD_WRTHRU_MASK) ?
				    "disabled" : "enabled");
				_sd_unblock(&_sd_flush_cv);

				if (SAFESTORE_LOCAL(sdbc_safestore))
					continue;

				/* Wait for cache to drain and panic */
				_sd_wait_for_dirty();
				cmn_err(CE_WARN,
				    "sdbc(_sd_health_thread)"
				    " dirty blocks flushed");
				continue;
			}
			/* was FAST */
			mutex_enter(&_sd_ft_data.fi_lock);
			_sd_node_recovery = 1;
			/* was FAST */
			mutex_exit(&_sd_ft_data.fi_lock);
			if (!SAFESTORE_LOCAL(sdbc_safestore))
				cmn_err(CE_WARN,
				    "sdbc(_sd_health_thread)"
				    " Cache on node %d is down. "
				    "Fast writes %s",
				    _SD_MIRROR_HOST,
				    (_SD_NODE_HINTS & _SD_WRTHRU_MASK) ?
				    "disabled" : "enabled");
			cmn_err(CE_NOTE,
			    "sdbc(_sd_health_thread)"
			    " Cache recovery in progress");
			_sd_cache_recover();

			mutex_enter(&_sd_ft_data.fi_lock);
			_sd_node_recovery = 0;
			_sdbc_clear_warm_start(); /* nvmem systems */
			cv_broadcast(&_sd_ft_data.fi_rem_sv);
			mutex_exit(&_sd_ft_data.fi_lock);
			cmn_err(CE_NOTE,
			    "sdbc(_sd_health_thread) %s Cache recovery done",
			    _sd_async_recovery ?
			    "asynchronous" : "synchronous");
			/* restore previous state */
			if (warm_started && !_sd_is_mirror_down()) {
				(void) _sd_clear_node_hint(NSC_FORCED_WRTHRU);
				cmn_err(CE_NOTE,
				    "sdbc(_sd_health_thread) Fast writes %s",
				    (_SD_NODE_HINTS & _SD_WRTHRU_MASK) ?
				    "disabled" : "enabled");
			}
			warm_started = 0;

		} else if (_sd_is_mirror_node_down()) {
			_sd_mirror_down();
		}
	}
}

/*
 * _sdbc_recovery_io_wait - wait for i/o being done directly
 * out of safe storage to complete. If the i/o does not make any
 * progress within about 25 seconds we return EIO otherwise return 0.
 *
 */
static
int
_sdbc_recovery_io_wait(void)
{
	int tries = 0;
	int last_numio = 0;

	/*
	 * Wait for numio to reach 0.
	 * If numio has not changed for 85+ seconds,
	 * break & pin blocks
	 */
	while (_sd_ft_data.fi_numio > 0) {
		if (last_numio == _sd_ft_data.fi_numio) {
			if (++tries > 512) break;
		} else {
			last_numio = _sd_ft_data.fi_numio;
			tries = 0;
		}
		delay(HZ/8);
	}
	if (_sd_ft_data.fi_numio != 0) {
		cmn_err(CE_WARN, "sdbc(_sdbc_recovery_io_wait) %d "
		    "recovery i/o's not done", _sd_ft_data.fi_numio);
		return (EIO);
	}
	return (0);
}


#if defined(_SD_FAULT_RES)
/*
 * _sd_recovery_wait()
 *   while _sd_node_recovery is set, accesses to mirrored devices will block
 *   (_sd_node_recovery-1) is count of blocked threads.
 */
int
_sd_recovery_wait(void)
{
	int blk;

	mutex_enter(&_sd_ft_data.fi_lock);
	blk = _sd_node_recovery ? _sd_node_recovery++ : 0;

	if (blk)
		cv_wait(&_sd_ft_data.fi_rem_sv, &_sd_ft_data.fi_lock);
	mutex_exit(&_sd_ft_data.fi_lock);

	if (!_sd_cache_initialized)
		return (EINVAL);
	return (0);
}

/*
 * _sd_recovery_wblk_wait - wait for recovery i/o to a device
 * to cease. If the file is closed or the cache is disabled
 * first return an error otherwise return 0.
 *
 * A device is being recovered from our point of view either
 * during failover or by putting a disk back online after
 * a disk failure.
 *
 * This code is used to delay access to a device while recovery
 * writes are in progress from either a failover or while flushing
 * i/o after a failed disk has been repaired.
 */
int
_sd_recovery_wblk_wait(int cd)
{
	_sd_cd_info_t *cdi = &_sd_cache_files[cd];

	while (_sd_cache_initialized &&
		FILE_OPENED(cd) && cdi->cd_recovering) {
		/* spawn writer if none */
		if (!cdi->cd_writer) (void) cd_writer(cd);
		delay(HZ/8);
	}
	if (!_sd_cache_initialized || !FILE_OPENED(cd))
		return (EINVAL);
	return (0);
}

/*
 * Recover from a crash of another node:
 *
 * 1) Open all remote files
 * 2) Allocate other node's buffers and new buffer headers
 * 3) Flush all dirty buffers to disk
 * 4) Deallocate resources
 */
static void
_sd_cache_recover(void)
{
	int cblocks_processed;

	SDTRACE(ST_ENTER|SDF_RECOVER, SDT_INV_CD, 0, SDT_INV_BL, 0, 0);

	/* was FAST */
	mutex_enter(&_sd_ft_data.fi_lock);
	_sd_ft_data.fi_numio = 0;
	/* was FAST */
	mutex_exit(&_sd_ft_data.fi_lock);

#ifdef _SD_DRIVE_RESP
	if (!mirror_clean_shutdown)
		_raw_reset_other();
#endif
	mirror_clean_shutdown = 0;

	cblocks_processed = _sd_failover_file_open();

	/* allow cache config to proceed */
	mutex_enter(&_sdbc_ft_hold_io_lk);
	_sdbc_ft_hold_io = 0;
	cv_signal(&_sdbc_ft_hold_io_cv);
	mutex_exit(&_sdbc_ft_hold_io_lk);

	/* wait for sequential recovery to complete */
	if (!_sd_async_recovery && cblocks_processed)
		(void) _sdbc_recovery_io_wait();

	_sd_failover_done();

	if (cblocks_processed)
		cmn_err(CE_NOTE,
		    "sdbc %ssynchronous recovery complete "
		    "%d cache blocks processed",
		    _sd_async_recovery ? "a" : "",
		    cblocks_processed);

	SDTRACE(ST_EXIT|SDF_RECOVER, SDT_INV_CD, 0, SDT_INV_BL, 0, 0);
}

void
_sd_mirror_iodone(void)
{
	/* was FAST */
	mutex_enter(&_sd_ft_data.fi_lock);
	_sd_ft_data.fi_numio--;
	/* was FAST */
	mutex_exit(&_sd_ft_data.fi_lock);
}



/*
 * _sd_ft_clone -- clone cache block from ft area, retry write or pin.
 */
static int
_sd_ft_clone(ss_centry_info_t *ft_cent, int async)
{
	_sd_cctl_t *ent;
	int cd = ft_cent->sc_cd;
	nsc_off_t cblk = ft_cent->sc_fpos;
	int dirty = ft_cent->sc_dirty;
	ss_resource_t *res = ft_cent->sc_res;
	_sd_cd_info_t *cdi;

	SDTRACE(ST_ENTER|SDF_FT_CLONE, cd, BLK_FBAS, cblk, dirty, _SD_NO_NET);
	cdi = &(_sd_cache_files[cd]);
	if ((cdi->cd_info->sh_failed != 2) && !FILE_OPENED(cd)) {
		cmn_err(CE_WARN, "sdbc(_sd_ft_clone) recovery "
		    "write failed: cd %x; cblk %" NSC_SZFMT "; dirty %x",
		    cd, cblk, dirty);
		SDTRACE(ST_EXIT|SDF_FT_CLONE,
		    cd, BLK_FBAS, cblk, dirty, EINTR);
		return (-1);
	}

	/*
	 * allocate new cache entry and read data
	 */
	ent = sdbc_centry_alloc_blks(cd, cblk, 1, 0);

	if (SSOP_READ_CBLOCK(sdbc_safestore, res, (void *)ent->cc_data,
	    CACHE_BLOCK_SIZE, 0) == SS_ERR) {
		cmn_err(CE_WARN, "sdbc(_sd_ft_clone) read of "
		    "pinned data block failed. cannot recover "
		    "0x%p size 0x%x", (void *)res, CACHE_BLOCK_SIZE);

		/* _sd_process_failure ?? */
		_sd_centry_release(ent);
		return (-1);
	}

	ent->cc_write = ft_cent;
	ent->cc_dirty = ent->cc_valid = (ushort_t)dirty;
	ent->cc_flag |= (ft_cent->sc_flag & CC_PINNABLE);

	ent->cc_chain = NULL;

	/*
	 * _sd_process_failure() adds to failed list & does pinned callback
	 * otherwise async flush
	 */
	if (cdi->cd_info->sh_failed) { /* raw device open/reserve failed */
		mutex_enter(&cdi->cd_lock);
		(cdi->cd_info->sh_numio)++;
		mutex_exit(&cdi->cd_lock);
		(void) _sd_process_failure(ent);
	} else {

		if (cdi->cd_global->sv_pinned != _SD_NO_HOST) {
			cdi->cd_global->sv_pinned = _SD_NO_HOST;
			SSOP_SETVOL(sdbc_safestore, cdi->cd_global);
		}

		if (async) {
			_sd_enqueue_dirty(cd, ent, ent, 1);
		} else {
			/*
			 * this is sync write with asynchronous callback
			 * (queue to disk and return).
			 */

			mutex_enter(&(cdi->cd_lock));
			(cdi->cd_info->sh_numio)++;
			mutex_exit(&cdi->cd_lock);
			_sd_async_flcent(ent, cdi->cd_crdev);
		}
	}
	_sd_centry_release(ent);
	SDTRACE(ST_EXIT|SDF_FT_CLONE, cd, BLK_FBAS, cblk, dirty, _SD_NO_NET);
	return (0);
}


/*
 * _sd_repin_cd - scan for dirty blocks held by mirror node.
 *
 * sdbc on this node is being attached to cd. If sdbc on other
 * node had failed writes (pinnable or not) we need to take
 * responsbility for them now here.
 */
int
_sd_repin_cd(int cd)
{
	ss_voldata_t *cd_gl;
	_sd_cd_info_t *cdi;

	if (!FILE_OPENED(cd))
		return (EINVAL);

	cdi = &_sd_cache_files[cd];
	if (cdi->cd_global->sv_pinned == _SD_NO_HOST)
		return (0);

	cd_gl = _sdbc_gl_file_info + cd;

	if (sdbc_recover_vol(cd_gl->sv_vol, cd))
		_sd_cd_discard_mirror(cd);

	return (0);
}


static int
_sd_cache_mirror_enable(int host)
{
	if (_sd_cache_initialized) {
		if (host != _SD_MIRROR_HOST) {
			cmn_err(CE_WARN, "sdbc(_sd_cache_mirror_enable) "
			    "Configured mirror %x. Got message from %x",
			    _SD_MIRROR_HOST, host);
			return (-EINVAL);
		}
		if (_sd_node_recovery) (void) _sd_recovery_wait();
		if (_sd_cache_initialized && _sd_is_mirror_down()) {
			int i;

			/* make sure any pinned data we have is now refreshed */
			for (i = 0; i < sdbc_max_devs; i++)
				if (FILE_OPENED(i))
					(void) _sdbc_remote_store_pinned(i);

			cmn_err(CE_NOTE,
			    "sdbc(_sd_cache_mirror_enable) Cache on "
			    "mirror node %d is up. Fast writes enabled",
			    host);
			_sd_mirror_up();
			(void) _sd_clear_node_hint(NSC_FORCED_WRTHRU);
		}
	}
	_sd_ft_data.fi_host_state = _SD_HOST_CONFIGURED;
	return (_sd_cache_initialized);
}


/*
 * two stage mirror disable:
 *	stage 0: set FORCED_WRTHRU hint (cache shutdown started)
 *	stage 1: mirror shutdown completed
 */
static int
_sd_cache_mirror_disable(int host, int stage)
{
	if (_sd_cache_initialized) {

		if (host != _SD_MIRROR_HOST)
			return (0);
		if (stage == 0) {
			(void) _sd_set_node_hint(NSC_FORCED_WRTHRU);
			return (0);
		}
		_sd_ft_data.fi_host_state = _SD_HOST_DECONFIGURED;
		mirror_clean_shutdown = 1;
		_sd_unblock(&_sd_ft_cv);
	} else {
		_sd_ft_data.fi_host_state = _SD_HOST_NONE;
	}
	return (0);
}

/*
 * set the fault tolerant data to indicate the state
 * of the safestore host.  set mode to writethru if appropriate
 */
static void
sdbc_setmodeandftdata()
{
	/*
	 * if single node local safestore or ram safestore
	 * then mark host state as carashed/_SD_HOST_NONE and set writethru
	 */
	if (SAFESTORE_LOCAL(sdbc_safestore)) {
		if (!SAFESTORE_SAFE(sdbc_safestore)) {
			_sd_mirror_down();	/* mirror node down */
			(void) _sd_set_node_hint(NSC_FORCED_WRTHRU);
		} else {
			_sd_ft_data.fi_host_state = _SD_HOST_CONFIGURED;
			if (_sdbc_warm_start())
				(void) _sd_set_node_hint(NSC_FORCED_WRTHRU);
		}
	} else
		_sd_remote_enable();
}

static void
_sd_remote_enable(void)
{
	ncall_t *ncall;
	long r;

	if (ncall_alloc(_SD_MIRROR_HOST, 0, _SD_NO_NET, &ncall)) {
		_sd_mirror_down();	/* mirror node down */
		(void) _sd_set_node_hint(NSC_FORCED_WRTHRU);
		return;
	}

	r = ncall_send(ncall, 0, SD_ENABLE, _SD_SELF_HOST);
	if (!r) (void) ncall_read_reply(ncall, 1, &r);
	ncall_free(ncall);

	if (r == 1) {		/* _sd_cache_initialized */
		if (!_sd_is_mirror_crashed() &&
		    _sd_ft_data.fi_host_state == _SD_HOST_NONE)
			_sd_ft_data.fi_host_state = _SD_HOST_CONFIGURED;
		return;
	}
	if (r == ENOLINK)
		_sd_mirror_down();		/* mirror node down */
	else
		_sd_mirror_cache_down();	/* mirror up, but no cache */
	(void) _sd_set_node_hint(NSC_FORCED_WRTHRU);
}


void
_sd_remote_disable(int stage)
{
	ncall_t *ncall;

	if (ncall_alloc(_SD_MIRROR_HOST, 0, 0, &ncall) == 0)
		(void) ncall_send(ncall, NCALL_ASYNC, SD_DISABLE,
		    _SD_SELF_HOST, stage);
}

void
r_sd_ifs_cache_enable(ncall_t *ncall, int *ap)
{
	ncall_reply(ncall, _sd_cache_mirror_enable(*ap));
}



void
r_sd_ifs_cache_disable(ncall_t *ncall, int *ap)
{
	(void) _sd_cache_mirror_disable(ap[0], ap[1]);
	ncall_done(ncall);
}

#else /* (_SD_FAULT_RES) */

void r_sd_ifs_cache_enable()  {; }
void r_sd_ifs_cache_disable() {; }

#endif /* (_SD_FAULT_RES) */

/*
 * invalidate cache hash table entries for given device
 * or (-1) all devices belonging to mirrored node
 */
void
_sd_hash_invalidate_cd(int CD)
{
	int i;
	_sd_cd_info_t *cdi;
	_sd_hash_hd_t *hptr;
	_sd_cctl_t *cc_ent, *ent;
	_sd_hash_bucket_t *bucket;
	int cd;
	nsc_off_t blk;

	for (i = 0; i < (_sd_htable->ht_size); i++) {
		bucket = (_sd_htable->ht_buckets + i);
		mutex_enter(bucket->hb_lock);
		hptr = bucket->hb_head;
		while (hptr) {
			cc_ent = (_sd_cctl_t *)hptr;
			cd = CENTRY_CD(cc_ent);
			blk = CENTRY_BLK(cc_ent);
			cdi = &_sd_cache_files[cd];

			/*
			 * Skip if device doesn't match or pinned.
			 * (-1) skip attached cd's
			 */
			if ((CD != -1 &&
				(cd != CD || CENTRY_PINNED(cc_ent))) ||
				(CD == -1 && nsc_held(cdi->cd_rawfd))) {
					hptr = hptr->hh_next;
					continue;
			}
			mutex_exit(bucket->hb_lock);

			ent = cc_ent;
		fl1:
			if (CC_CD_BLK_MATCH(cd, blk, ent) ||
			    (ent = (_sd_cctl_t *)_sd_hash_search(cd, blk,
			    _sd_htable))) {
				if (SET_CENTRY_INUSE(ent)) {
					xmem_inval_inuse++;
					_sd_cc_wait(cd, blk, ent, CC_INUSE);
					goto fl1; /* try again */
				}

				/* cc_inuse is set, delete on block match */
				if (CC_CD_BLK_MATCH(cd, blk, ent)) {
					xmem_inval_hit++;
					(void)
					_sd_hash_delete((struct _sd_hash_hd *)
							ent, _sd_htable);

					if (sdbc_use_dmchain) {

						/* attempt to que head */
						if (ent->cc_alloc_size_dm) {
							sdbc_requeue_head_dm_try
									(ent);
						}
					} else
						_sd_requeue_head(ent);

				} else
					xmem_inval_miss++;

				CLEAR_CENTRY_INUSE(ent);
			}
			mutex_enter(bucket->hb_lock);
			hptr = bucket->hb_head;
		}
		mutex_exit(bucket->hb_lock);
	}
}


/*
 * _sd_cd_online(cd,discard)
 *	clear local error state.
 *	if (discard && _attached != _SD_SELF_HOST) then release buffers.
 *	if (!discard && _attached != _SD_MIRROR_HOST) then re-issue I/Os
 *		(add to dirty pending queue).
 * returns:
 *	0	success
 *	EINVAL	invalid device or not failed
 *	EBUSY	attached by this node, or by active mirror
 */
static int
_sd_cd_online(int cd, int discard)
{
	_sd_cd_info_t *cdi = &_sd_cache_files[cd];
	int failed, num;
	_sd_cctl_t *cc_ent, *cc_next, *cc_last, *cc_first, *cc_next_chain;

	/*
	 * in the case where a failed device has been closed and
	 * then re-opened, sh_failed will be zero because it is
	 * cleared in _sd_open_cd().  hence the test for
	 * _pinned != _SD_SELF_HOST which allows the restore to
	 * proceed in this scenario.
	 */
	if (cd < 0 || cd >= sdbc_max_devs)
		return (EINVAL);

	if (!cdi->cd_info || !cdi->cd_global)
		return (EINVAL);

	if ((cdi->cd_info->sh_failed == 0) &&
	    (cdi->cd_global->sv_pinned != _SD_SELF_HOST))
		return (0);

	if (_sd_nodes_configured > 1) {

		/* can't discard while attached on multinode systems */
		if (discard && (cdi->cd_global->sv_attached == _SD_SELF_HOST))
			return (EBUSY);

		if (!discard &&		/* attached by active mirror! */
		    (cdi->cd_global->sv_attached == _SD_MIRROR_HOST) &&
		    !_sd_is_mirror_down())
			return (EBUSY);
	}

	mutex_enter(&cdi->cd_lock);

	cc_ent = cdi->cd_fail_head;
	failed = cdi->cd_info->sh_numfail;
	cdi->cd_fail_head = NULL;
	cdi->cd_info->sh_numfail = 0;
	cdi->cd_info->sh_failed = 0;
	cdi->cd_global->sv_pinned = _SD_NO_HOST;
	SSOP_SETVOL(sdbc_safestore, cdi->cd_global);

	if (cc_ent == NULL) {
		mutex_exit(&cdi->cd_lock);
		return (0);
	}
	/* prevent any new i/o from arriving for this cd */
	if (!discard)
		cdi->cd_recovering = 1;

	mutex_exit(&cdi->cd_lock);

	num = 0;
	cc_first = cc_ent;
	for (; cc_ent; cc_ent = cc_next_chain) {
		cc_next_chain = cc_ent->cc_dirty_link;

		for (; cc_ent; cc_ent = cc_next) {
			cc_next = cc_ent->cc_dirty_next;
			cc_last = cc_ent;
			num++;

			if (discard) {
				ss_centry_info_t *wctl;
				/* was FAST */
				mutex_enter(&cc_ent->cc_lock);
				cc_ent->cc_valid = cc_ent->cc_dirty = 0;
				cc_ent->cc_flag &= ~(CC_PEND_DIRTY|CC_PINNED);
				cc_ent->cc_dirty_next = NULL;
				cc_ent->cc_dirty_link = NULL;
				wctl = cc_ent->cc_write;
				cc_ent->cc_write = NULL;
				/* was FAST */
				mutex_exit(&cc_ent->cc_lock);
				if (wctl) {
					wctl->sc_flag = 0;
					wctl->sc_dirty = 0;

					SSOP_SETCENTRY(sdbc_safestore, wctl);
					SSOP_DEALLOCRESOURCE(sdbc_safestore,
					    wctl->sc_res);
				}

				continue;
			}

			/* Clear PEND_DIRTY, iocount & iostatus */
			if (SET_CENTRY_INUSE(cc_ent) == 0) {
				cc_ent->cc_flag &= ~CC_PEND_DIRTY;
				cc_ent->cc_iocount = 0;
				cc_ent->cc_iostatus = 0; /* _SD_IO_NONE */
				CLEAR_CENTRY_INUSE(cc_ent);
			} else {
				/* was FAST */
				mutex_enter(&cc_ent->cc_lock);
				cc_ent->cc_flag &= ~CC_PEND_DIRTY;
				cc_ent->cc_iocount = 0;
				cc_ent->cc_iostatus = 0; /* _SD_IO_NONE */
				/* was FAST */
				mutex_exit(&cc_ent->cc_lock);
			}
		}
	}
	if (num != failed)
		cmn_err(CE_WARN, "sdbc(_sd_cd_online) count %d vs numfail %d",
		    num, failed);
	if (discard) {
		_sd_hash_invalidate_cd(cd);
		return (0);
	}

	_sd_enqueue_dirty_chain(cd, cc_first, cc_last, num);
	/* make sure data gets flushed in case there is no new I/O */
	(void) nsc_reserve(cdi->cd_rawfd, NSC_MULTI);
	(void) _sd_wait_for_flush(cd);
	cdi->cd_recovering = 0;
	nsc_release(cdi->cd_rawfd);

	return (0);
}

#if defined(_SD_FAULT_RES)

/*
 * This node has disk attached, discard pins held by mirror
 */
static void
_sd_cd_discard_mirror(int cd)
{
	ncall_t *ncall;
	if (ncall_alloc(_SD_MIRROR_HOST, 0, 0, &ncall))
		return;
	(void) ncall_send(ncall, NCALL_ASYNC, SD_CD_DISCARD, cd);
}

void
r_cd_discard(ncall_t *ncall, int *ap)
{
	int r, cd = *ap;
	if (_sd_cache_initialized) {
		SDTRACE(ST_ENTER|SDF_ONLINE, cd, 1, SDT_INV_BL, 1, 0);
		r = _sd_cd_online(cd, 1);
		SDTRACE(ST_EXIT|SDF_ONLINE, cd, 1, SDT_INV_BL, 1, r);
	}
	ncall_done(ncall);
}

/*
 * _sd_failover_file_open -
 *	on failover, open devices which are not attached by this node.
 */
static int
_sd_failover_file_open(void)
{
	int rc, cd, flag = 0;
	ss_voldata_t *cd_gl;
	_sd_cd_info_t *cdi;
	int cblocks_processed = 0;
	extern ss_voldata_t *_sdbc_gl_file_info;

	for (cd = 0; cd < sdbc_max_devs; cd++) {
		cd_gl = _sdbc_gl_file_info + cd;
		cdi = &(_sd_cache_files[cd]);

		/*
		 * If the cd is open and reserved we certainly don't
		 * need to do it again. However the recovery code
		 * must be racing some other cache usage which could
		 * be bad.  We really need to be able to lock out
		 * all cache activity for this cd that is not tied
		 * to the recovery process. This doesn't seem to be
		 * feasible in sdbc since a competing thread could
		 * already be finished doing an alloc_buf. If this
		 * hole is to be closed sd-ctl must be more in
		 * control of the failover process.
		 */
		if (FILE_OPENED(cd) && nsc_held(cdi->cd_rawfd))
			continue;

		/*
		 * this constuct says that, on non-nvmem systems,
		 * if we are attempting to open a "local" device and
		 * nothing is pinned, then continue.  i.e. open only
		 * remote devices or devices that have pinned data.
		 * for recovery on nvmem systems we open all devices.
		 */
		if ((!_sdbc_warm_start()) &&
			((cd_gl->sv_attached != _SD_MIRROR_HOST) &&
			(cd_gl->sv_pinned != _SD_MIRROR_HOST) &&
			(cd_gl->sv_pinned != _SD_SELF_HOST)))
			continue;
		if (!cd_gl->sv_volname ||
			!cd_gl->sv_volname[0])
			continue;

		if (_sd_open_cd(cd_gl->sv_volname, cd, flag) < 0) {
			cmn_err(CE_WARN, " sdbc(_sd_failover_file_open) "
			    "Unable to open disk partition %s",
			    cd_gl->sv_volname);
			continue;
		}

		SDTRACE(ST_INFO|SDF_RECOVER, cd, 0, 0, 0, 0);
		rc = nsc_reserve(cdi->cd_rawfd, NSC_MULTI);
		if (rc == 0) {
			cdi->cd_failover = 1;
		}

		if (rc != 0) cdi->cd_info->sh_failed = 1;

		cblocks_processed += sdbc_recover_vol(cd_gl->sv_vol, cd);
	}

	return (cblocks_processed);
}


static int
sdbc_recover_vol(ss_vol_t *vol, int cd)
{
	ss_cdirkey_t key;
	ss_cdir_t cdir;
	ss_voldata_t *cd_gl = _sdbc_gl_file_info + cd;
	ss_centry_info_t *cinfo;
	ss_centry_info_t centry;
	int cblocks_processed = 0;
	int err;
	ss_centry_info_t *sdbc_get_cinfo_byres(ss_resource_t *);

	/* setup the key to get a volume directory stream of centrys */
	key.ck_type  = CDIR_VOL;
	key.cdk_u.ck_vol = vol;

	if (SSOP_GETCDIR(sdbc_safestore, &key, &cdir)) {
		cmn_err(CE_WARN, "sdbc(sdbc_recover_vol): "
		    "cannot recover volume %s",
		    cd_gl->sv_volname);
		return (0);
	}

	/* cycle through the cdir getting resource tokens and reading centrys */
	/*CONSTANTCONDITION*/
	while (1) {

		if ((err = SSOP_GETCDIRENT(sdbc_safestore, &cdir, &centry))
								== SS_ERR) {
			cmn_err(CE_WARN, "sdbc(sdbc_recover_vol): "
				"cache entry read failure %s %p",
				cd_gl->sv_volname, (void *)centry.sc_res);

			continue;
		}


		if (err == SS_EOF)
			break; /* done */


		/*
		 * this get into double caching consistency
		 * need to resolve this jgk
		 */
		if ((cinfo = sdbc_get_cinfo_byres(centry.sc_res)) == NULL) {
			/* should not happen */
			cmn_err(CE_WARN, "sdbc(sdbc_recover_vol): "
			    "invalid ss resource %p", (void *)centry.sc_res);
			continue;
		}
		bcopy(&centry, cinfo, sizeof (ss_centry_info_t));

		/*
		 * note
		 * ss should return a stream of dirty blocks ordered
		 * by block number.  if it turns out that ss will not support
		 * this then sorting for async recovery will have to be
		 * done here  jgk
		 */
		ASSERT(cinfo->sc_dirty);

		if (!cinfo->sc_dirty) /* should not happen */
			continue;

		/*
		 * clone mirror cache entry and do
		 * 	async I/O or sync I/O or pin if sh_failed
		 */
		(void) _sd_ft_clone(cinfo, _sd_async_recovery);
		++cblocks_processed;
	}


	if (cblocks_processed)
		cmn_err(CE_NOTE,
	"sdbc(sdbc_recover_vol) %d cache blocks processed for volume %s",
			cblocks_processed, cd_gl->sv_volname);

	return (cblocks_processed);
}

/*
 * _sd_failover_done -
 *	mark failover open'd devices as requiring nsc_release()
 *	when all queued I/O's have drained.
 */
static void
_sd_failover_done(void)
{
	_sd_cd_info_t *cdi;
	int cd;

	for (cd = 0; cd < sdbc_max_devs; cd++) {
		cdi = &(_sd_cache_files[cd]);

		if (FILE_OPENED(cd) && cdi->cd_failover)
			cdi->cd_failover = 2;
	}
}

#endif /* (_SD_FAULT_RES) */

/*
 * _sd_uncommit - discard local buffer modifications
 *	clear the valid bits.
 */
int
_sd_uncommit(_sd_buf_handle_t *handle, nsc_off_t fba_pos, nsc_size_t fba_len,
    int flag)
{
	int cd;
	sdbc_cblk_fba_t st_cblk_len;	/* FBA len of starting cache block */
	sdbc_cblk_fba_t end_cblk_len;	/* FBA len of ending cache block */
	sdbc_cblk_fba_t st_cblk_off;	/* FBA offset into starting cblock */
	nsc_size_t cc_len;
	int bits;
	_sd_cctl_t *cc_ent;

	cd = HANDLE_CD(handle);

	ASSERT_HANDLE_LIMITS(handle, fba_pos, fba_len);

	if ((handle->bh_flag & NSC_WRBUF) == 0) {
		DTRACE_PROBE(_sd_uncommit_end_handle_write);

		return (EINVAL);
	}

	if (fba_len == 0) {
		DTRACE_PROBE(_sd_uncommit_end_zero_len);
		return (NSC_DONE);
	}

	SDTRACE(ST_ENTER|SDF_UNCOMMIT, cd, fba_len, fba_pos, flag, 0);

	cc_ent = handle->bh_centry;
	while (CENTRY_BLK(cc_ent) != FBA_TO_BLK_NUM(fba_pos))
		cc_ent = cc_ent->cc_chain;

	cc_len = fba_len;	/* current length */
	st_cblk_off = BLK_FBA_OFF(fba_pos);
	st_cblk_len = (BLK_FBAS - st_cblk_off);
	if ((nsc_size_t)st_cblk_len >= fba_len) {
		end_cblk_len = 0;
		st_cblk_len = (sdbc_cblk_fba_t)fba_len;
	}
	else
		end_cblk_len = BLK_FBA_OFF(fba_pos + fba_len);

	/*
	 * Check if remote write-cache spool is dirty,
	 * if not, we can just discard local valid bits.
	 */
	bits = SDBC_GET_BITS(st_cblk_off, st_cblk_len);
	cc_ent->cc_valid &= ~bits;

	cc_len -= st_cblk_len;
	cc_ent = cc_ent->cc_chain;
	bits = SDBC_GET_BITS(0, BLK_FBAS);

	while (cc_len > (nsc_size_t)end_cblk_len) {
		cc_ent->cc_valid = 0;
		cc_ent = cc_ent->cc_chain;
		cc_len -= BLK_FBAS;
	}

#if defined(_SD_DEBUG)
	if (cc_len != end_cblk_len)
		cmn_err(CE_WARN, "fba_len %" NSC_SZFMT " end_cblk_len %d in "
		    "_sd_write", fba_len, end_cblk_len);
#endif

	if (cc_len) {
		bits = SDBC_GET_BITS(0, end_cblk_len);
		cc_ent->cc_valid &= ~bits;
	}
	SDTRACE(ST_EXIT|SDF_UNCOMMIT, cd, fba_len, fba_pos, flag, 0);

	return (NSC_DONE);
}

static void
_sd_wait_for_dirty(void)
{
	int cd;

	for (cd = 0; cd < sdbc_max_devs; cd++) {
		while (_SD_CD_WBLK_USED(cd))
			delay(HZ);
	}
}

/*
 * _sd_wait_for_flush - wait for all i/o for this cd to cease.
 * This function assumes that no further i/o are being issued
 * against this device. This assumption is enforced by sd-ctl
 * when called from _sd_flush_cd. Recovery also uses this
 * wait and it enforces this assumption (somewhat imperfectly)
 * by using cd_recovering.
 * We must see progress in getting i/o complete within 25 seconds
 * or we will return an error. If we complete normally (all i/o done)
 * we return 0.
 */
int
_sd_wait_for_flush(int cd)
{
	_sd_cd_info_t *cdi = &(_sd_cache_files[cd]);
	int tries = 0, used, last_used = 0, inprogress = 0;

	if (!(_SD_CD_WBLK_USED(cd)))
		return (0);
	/*
	 * Wait for WBLK_USED to reach 0.
	 * If unchanged for 32+ seconds returns EAGAIN
	 */
	if (!cdi->cd_writer)
		(void) cd_writer(cd); /* spawn writer if not already running */

	while (((used = _SD_CD_WBLK_USED(cd)) != 0) || cdi->cd_writer) {
		if (last_used == used &&
		    inprogress == cdi->cd_write_inprogress) {
			if (cdi->cd_info->sh_failed)
				break;
			if (++tries > 128) {
				cmn_err(CE_WARN, "sdbc(_sd_wait_for_flush) "
				    "%s still has %d blocks pending %d"
				    " in progress (@ %lx)",
				    cdi->cd_info->sh_filename, last_used,
				    inprogress, nsc_lbolt());
				return (EAGAIN);
			}
		} else {
			last_used = used;
			inprogress = cdi->cd_write_inprogress;
			tries = 0;
		}
		_sd_unblock(&_sd_flush_cv);
		delay(HZ/4);
	}
	if (cdi->cd_info->sh_failed)
		return (EIO);
	else
		return (0);
}


static
int _sd_ft_warm_start;

int
_sdbc_warm_start(void)
{
	return (_sd_ft_warm_start);
}

void
_sdbc_clear_warm_start(void)
{
	_sd_ft_warm_start = 0;
}

void
_sdbc_set_warm_start(void)
{
	_sd_ft_warm_start = 1;
}

/*ARGSUSED*/
void
_ncall_poke(int host)
{
	cmn_err(CE_PANIC, " NYI - _ncall_poke");
}
