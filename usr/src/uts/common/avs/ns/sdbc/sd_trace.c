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
#include <sys/ddi.h>
#include <sys/nsc_thread.h>

#include "sd_bcache.h"
#include "sd_trace.h"
#include "sd_misc.h"

#ifndef _SD_NOTRACE

#ifndef SM_SDTRSEMA
#define	SM_SDTRSEMA 1
#define	SM_SDTRLCK  1
#endif

int _sd_trace_mask = 0;

/*
 * _sdbd_trace_t _sd_trace_table[-1, 0 .. sdbc_max_devs - 1]
 *	allocate memory, shift pointer up by one.
 */
static _sdbc_trace_t	*_sd_trace_table;

static kcondvar_t	_sd_adump_cv;
static int _sd_trace_configed;
static kmutex_t  _sd_adump_lk;

static int		_alert_cd = SDT_ANY_CD;
static int		_last_cd = SDT_ANY_CD;
#define	XMEM(x, y)	(void)(x = y, y = (SDT_ANY_CD), x)

/*
 * Forward declare all statics that are used before defined to enforce
 * parameter checking.
 * Some (if not all) of these could be removed if the code were reordered
 */

static int _sd_set_adump(int cd, int flag, _sdtr_table_t *table);

/*
 * _sdbc_tr_unload - cache is being unloaded. Release any memory/lock/sv's
 * created by _sdbc_tr_unload and null the stale pointers.
 *
 */
void
_sdbc_tr_unload(void)
{
	if (_sd_trace_table)
		nsc_kmem_free((_sd_trace_table - 1),
		    sizeof (_sdbc_trace_t) * (sdbc_max_devs + 1));
	cv_destroy(&_sd_adump_cv);
	mutex_destroy(&_sd_adump_lk);

	_sd_trace_table = NULL;
}

/*
 * _sdbc_tr_load - cache is being loaded. Allocate the memory/lock/sv's
 * which need to be present regardless of state of cache configuration.
 *
 */
int
_sdbc_tr_load(void)
{
	_sdbc_trace_t *m;

	cv_init(&_sd_adump_cv, NULL, CV_DRIVER, NULL);
	mutex_init(&_sd_adump_lk, NULL, MUTEX_DRIVER, NULL);

	/*
	 * this maybe ought to wait to see if traces are configured, but it
	 * is only 4k
	 */

	m = (_sdbc_trace_t *)nsc_kmem_zalloc(
	    sizeof (_sdbc_trace_t) * (sdbc_max_devs + 1),
	    KM_NOSLEEP, sdbc_stats_mem);

	if (m == NULL) {
		cmn_err(CE_WARN,
		    "sdbc(_sdbc_tr_load) cannot allocate trace table");
		return (-1);
	}
	_sd_trace_table = m + 1;

	return (0);

}

/*
 * _sdbc_tr_configure - configure a trace area for the descriptor "cd".
 * Unlike other ..._configure routines this routine is called multiple
 * times since there will be an unknown number of open descriptors. At
 * cache config time if tracing is enabled only the slot for SDT_INV_CD
 * is created.
 *
 * Allocate the SD cache trace area (per device)
 */

int
_sdbc_tr_configure(int cd)
{
	int size;
	_sdtr_table_t *t;
	kmutex_t *lk;

	if (!_sd_cache_config.trace_size)
		return (0);

	if (cd == SDT_INV_CD)
		_sd_trace_configed = 1;

	if (_sd_trace_table[cd].tbl)
		return (0);

	size = sizeof (_sdtr_table_t) +
	    _sd_cache_config.trace_size * sizeof (_sdtr_t);

	if ((t = (_sdtr_table_t *)nsc_kmem_zalloc(size,
	    KM_NOSLEEP, sdbc_stats_mem)) == NULL) {
		cmn_err(CE_WARN, "sdbc(_sdbc_tr_configure) failed to "
		    "allocate %d bytes for trace, cd=%d", size, cd);
		return (-1);
	}

	lk = nsc_kmem_zalloc(sizeof (kmutex_t), KM_NOSLEEP, sdbc_local_mem);
	if (!lk) {
		nsc_kmem_free(t, size);
		cmn_err(CE_WARN, "sdbc(_sdbc_tr_configure) cannot "
		    "alloc trace lock for cd %d", cd);
		return (-1);
	}
	mutex_init(lk, NULL, MUTEX_DRIVER, NULL);

	_sd_trace_table[cd].t_lock = lk;
	t->tt_cd   = cd;
	t->tt_max  = _sd_cache_config.trace_size;
	t->tt_mask = _sd_cache_config.trace_mask;
	t->tt_lbolt = (char)_sd_cache_config.trace_lbolt;
	t->tt_good = (char)_sd_cache_config.trace_good;
	_sd_trace_mask |= t->tt_mask;
	_sd_trace_table[cd].tbl = t;
	return (0);
}


/*
 * _sdbc_tr_deconfigure
 *	free all trace memory (regions) when deconfiguring cache
 */
void
_sdbc_tr_deconfigure(void)
{
	int i, size;
	_sdbc_trace_t *tt;

	if (!_sd_cache_config.trace_size || !_sd_trace_configed)
		return;

	mutex_enter(&_sd_adump_lk);
	_sd_trace_configed = 0;
	cv_broadcast(&_sd_adump_cv);
	mutex_exit(&_sd_adump_lk);

	for (i = -1, tt = &_sd_trace_table[-1]; i < sdbc_max_devs; i++, tt++) {
		if (tt->tbl == NULL) continue;
		size = tt->tbl->tt_max * sizeof (_sdtr_t) +
		    sizeof (_sdtr_table_t);
		if (tt->t_lock) {
			mutex_destroy(tt->t_lock);
			nsc_kmem_free(tt->t_lock, sizeof (kmutex_t));
		}
		nsc_kmem_free(tt->tbl, size);
		tt->t_lock = NULL;
		tt->tbl = NULL;
	}
	_alert_cd = SDT_ANY_CD;
	_last_cd = SDT_ANY_CD;
}

static int first_alert = 0;
/*
 * SDALERT(f,cd,len,fba,flg,ret) \
 *	_sd_alert(f,cd,len,fba,flg,ret)
 *  Build a ALERT trace entry and place it into the trace table.
 */
void
_sd_alert(int f, int cd, int len, nsc_off_t fba, int flg, int ret)
{
	int tin;
	_sdtr_t *tp;
	_sdtr_table_t *t;
	kmutex_t *lk;

	if (!first_alert) {
		first_alert++;
		cmn_err(CE_WARN,
		    "sdbc(_sd_alert) cd=%x f=%x len=%x fba=%" NSC_SZFMT
		    " flg=%x ret=%x", cd, f, len, fba, flg, ret);

	}

	/* Watch out for negative error codes or simply bogus cd's */

	if (cd < -1 || cd >= sdbc_max_devs) {
		/*
		 * no device trace buffer -- use SDT_INV_CD table?
		 */
		if ((t = _sd_trace_table[-1].tbl) == NULL)
			return;
		lk = _sd_trace_table[-1].t_lock;
	} else {
		lk = _sd_trace_table[cd].t_lock;
		if ((t = _sd_trace_table[cd].tbl) == NULL) {
			/*
			 * no device trace buffer -- use SDT_INV_CD table?
			 */
			if ((t = _sd_trace_table[-1].tbl) == NULL)
				return;
			lk = _sd_trace_table[-1].t_lock;
		}
	}

	if (!(t->tt_mask & ST_ALERT))
		return;	/* check per-device mask */

	if (t->tt_good) mutex_enter(lk);
	t->tt_alert++;	/* alert on this device */
	t->tt_cnt++;	/* overwritten entries if (tt_cnt >= tt_max) */

	tin = t->tt_in++;
	if (tin >= t->tt_max) tin = t->tt_in = 0;
	tp = &t->tt_buf[tin];
	tp->t_time = 0;		/* not filled in yet */
	if (t->tt_good) mutex_exit(lk);

	tp->t_func = (ushort_t)f | ST_ALERT;
	tp->t_len = (ushort_t)len;
	tp->t_fba = fba;
	tp->t_flg = flg;
	tp->t_ret = ret;
	/*
	 * On LP64 systems we will only capture the low 32 bits of the
	 * time this really should be good enough for our purposes.
	 *
	 */
	if (t->tt_lbolt)
		tp->t_time = (int)nsc_lbolt();
	else
		tp->t_time = (int)nsc_usec();

	/* wakeup trace daemon, with hint */
	_alert_cd = cd;

	if (_sd_trace_configed)
		cv_signal(&_sd_adump_cv);
}


/*
 * SDTRACE(f,cd,len,fba,flg,ret) \
 *	if (_sd_trace_mask & (f)) _sd_trace(f,cd,len,fba,flg,ret)
 *  Build a trace entry and place it into the trace table.
 */
void
_sd_trace(int f, int cd, int len, nsc_off_t fba, int flg, int ret)
{
	int tin;
	_sdtr_t *tp;
	_sdtr_table_t *t;
	kmutex_t *lk;

	/* Watch out for negative error codes or simply bogus cd's */

	if (cd < -1 || cd >= sdbc_max_devs) {
		/*
		 * no device trace buffer -- use SDT_INV_CD table?
		 */
		if ((t = _sd_trace_table[-1].tbl) == NULL)
			return;
		lk = _sd_trace_table[-1].t_lock;
	} else {
		lk = _sd_trace_table[cd].t_lock;
		if ((t = _sd_trace_table[cd].tbl) == NULL)
			return;
	}

	if (!(t->tt_mask & f))
		return;	/* check per-device mask */

	/*
	 * Don't overwrite if alert signaled (count lost instead)
	 * Locking only if 'trace_good' parameter set.
	 */
	if (t->tt_good) mutex_enter(lk);
	if (t->tt_alert && (t->tt_cnt >= t->tt_max)) {
		t->tt_lost++; /* lost during alert */
		if (t->tt_good) mutex_exit(lk);
		return;
	}
	t->tt_cnt++;	/* overwritten entries if (tt_cnt >= tt_max) */

	tin = t->tt_in++;
	if (tin >= t->tt_max) tin = t->tt_in = 0;
	tp = &t->tt_buf[tin];
	tp->t_time = 0;		/* not filled in yet */
	if (t->tt_good) mutex_exit(lk);

	tp->t_func = (ushort_t)f;
	tp->t_len = (ushort_t)len;
	tp->t_fba = fba;
	tp->t_flg = flg;
	tp->t_ret = ret;
	/*
	 * On LP64 systems we will only capture the low 32 bits of the
	 * time this really should be good enough for our purposes.
	 *
	 */
	if (t->tt_lbolt)
		tp->t_time = (int)nsc_lbolt();
	else
		tp->t_time = (int)nsc_usec();
}

/*
 * _sd_scan_alert -- search for device with trace alert
 */
static int
_sd_scan_alert(void)
{
	int cd;

	XMEM(cd, _alert_cd);
	if ((cd != SDT_ANY_CD) && _sd_trace_table[cd].tbl->tt_alert)
		return (cd);
	for (cd = _last_cd + 1; cd < sdbc_max_devs; cd++)
		if (_sd_trace_table[cd].tbl &&
		    _sd_trace_table[cd].tbl->tt_alert)
			return (_last_cd = cd);
	for (cd = SDT_INV_CD; cd <= _last_cd; cd++)
		if (_sd_trace_table[cd].tbl &&
		    _sd_trace_table[cd].tbl->tt_alert)
			return (_last_cd = cd);
	return (SDT_ANY_CD);
}

/*
 * _sd_scan_entries -- search for next device with trace entries
 */
static int
_sd_scan_entries(void)
{
	int cd;

	for (cd = _last_cd + 1; cd < sdbc_max_devs; cd++)
		if (_sd_trace_table[cd].tbl && _sd_trace_table[cd].tbl->tt_cnt)
			return (_last_cd = cd);
	for (cd = SDT_INV_CD; cd <= _last_cd; cd++)
		if (_sd_trace_table[cd].tbl && _sd_trace_table[cd].tbl->tt_cnt)
			return (_last_cd = cd);
	return (SDT_ANY_CD);
}


/*
 * _sd_adump
 *	copy information about new trace records to trace daemon,
 *	or modify trace parameters.
 *
 * Some tracing parameters can be modified
 * [Either per-device if cd specified, or the defaults if cd = SDT_ANY_CD]
 *  SD_LOGSIZE:   table.tt_max (size for future opens)
 *  SD_SET_LBOLT: table.tt_lbolt
 *  SD_SET_MASK:  table.tt_mask
 *  SD_SET_GOOD:  table.tt_good
 *
 * if (cd >= 0) dump specific device records;
 * if (cd == SDT_INV_CD) dump records which don't apply to any one device.
 * if (cd == SDT_ANY_CD), then choose a device:
 *	1) most recent alert, block if (flag & SD_ALERT_WAIT)
 *	2) "next" device with unprocessed records.
 */
int
_sd_adump(void *args, int *rvp)
{
	struct a {
		long cd;
		_sdtr_table_t *table;
		_sdtr_t *buf;
		long size;
		long flag;
	} *uap = (struct a *)args;
	_sdtr_t *ubuf;
	_sdtr_table_t tt, *t;
	kmutex_t *lk;
	int cd, count, lost, new_cnt;

	if (uap->flag & (SD_SET_SIZE|SD_SET_MASK|SD_SET_LBOLT|SD_SET_GOOD)) {
		return (_sd_set_adump(uap->cd, uap->flag, uap->table));
	}
	if (! _sd_trace_configed) {
		return (EINVAL); /* not initialized yet */
	}
	if (uap->cd >= SDT_INV_CD) {
		/* specific device: check if configured. dump current state. */
		if ((uap->cd > (long)sdbc_max_devs) ||
		    !(t = _sd_trace_table[uap->cd].tbl)) {
			return (ENOSPC); /* no space configured */
		}
		lk = _sd_trace_table[uap->cd].t_lock;
		cd = uap->cd;
	} else {
		/*
		 * SDT_ANY_CD:
		 * SD_ALERT_WAIT - wait for alert
		 */
	scan:
		if ((cd = _sd_scan_alert()) != SDT_ANY_CD)
			goto dump;
		if ((uap->flag & SD_ALERT_WAIT)) {
			mutex_enter(&_sd_adump_lk);
			if (!_sd_trace_configed) {
				mutex_exit(&_sd_adump_lk);
				return (EINVAL);
			}

			if (!cv_wait_sig(&_sd_adump_cv, &_sd_adump_lk)) {
				mutex_exit(&_sd_adump_lk);
				return (EINTR);
			}
			mutex_exit(&_sd_adump_lk);

			if (!_sd_trace_configed || !_sd_cache_initialized) {
				return (EIDRM);
			}
			goto scan;
		}
		/* any device with entries */
		if ((cd = _sd_scan_entries()) == SDT_INV_CD)
			return (0);		/* no new entries */

	dump:
		lk = _sd_trace_table[cd].t_lock;
		if ((t = _sd_trace_table[cd].tbl) == NULL) {
			if (uap->flag & SD_ALERT_WAIT) {
				t = _sd_trace_table[-1].tbl;
				lk = _sd_trace_table[-1].t_lock;
			} else {
				return (ENOSPC); /* no space configured */
			}
		}
	}

	/*
	 * take a snapshot of the table state
	 */
	if (t->tt_good)
		mutex_enter(lk);
	tt = *t;
	if (t->tt_good)
		mutex_exit(lk);

	/*
	 * copy trace log entries to daemon
	 *
	 * size:   entries in user-level 'buf'
	 * count:  how many entries to copy [force count <= size]
	 * tt_max: size of kernel buffer
	 * tt_cnt: written entries [lossage if tt_cnt > tt_max]
	 * cnt:    for wrap-around calculations
	 */
	if ((count = tt.tt_cnt) > tt.tt_max) { /* lost from beginning */
		tt.tt_out = tt.tt_in;
		count = tt.tt_max;
		lost = tt.tt_cnt - tt.tt_max;
	} else
		lost = 0;
	if (count <= 0)
		return (0);
	if ((long)count > uap->size)
		count = uap->size;
	ubuf = uap->buf;
	if ((tt.tt_out + count) > tt.tt_max) {
		int cnt = tt.tt_max - tt.tt_out;
		if (cnt > count)
			cnt = count;
		if (copyout(&(t->tt_buf[tt.tt_out]), ubuf,
		    cnt * sizeof (_sdtr_t))) {
			return (EFAULT);
		}
		ubuf += cnt;
		cnt = count - cnt;
		if (copyout(&(t->tt_buf[0]), ubuf, cnt * sizeof (_sdtr_t))) {
			return (EFAULT);
		}
		tt.tt_out = cnt;
	} else {
		if (copyout(&(t->tt_buf[tt.tt_out]), ubuf,
		    count * sizeof (_sdtr_t))) {
			return (EFAULT);
		}
		tt.tt_out += count;
		if (tt.tt_out == tt.tt_max)
			tt.tt_out = 0;
	}

	/*
	 * tt_alert uses fuzzy counting.
	 * if multiple alerts signaled, leave it at 1.
	 */
	if (t->tt_alert)
		t->tt_alert = (t->tt_alert > 1) ? 1 : 0;

	/*
	 * tt_cntout is tt_cnt after dump
	 * update tt_cnt for copied entries
	 */
	if (t->tt_good)
		mutex_enter(lk);
	tt.tt_cntout = t->tt_cnt;
	t->tt_out = tt.tt_out;
	new_cnt = t->tt_cnt;
	if ((new_cnt -= count+lost) < 0)
		new_cnt = 0;
	t->tt_cnt = new_cnt;	/* race with new traces if not "tt_good" */
	if (t->tt_good)
		mutex_exit(lk);

	if (copyout(&tt, uap->table, sizeof (tt) - sizeof (_sdtr_t))) {
		return (EFAULT);
	}
	*rvp = count;

	first_alert = 0;
	return (0);
}


/* set size, mask, lbolt, or good(locks) */
static int
_sd_set_adump(int cd, int flag, _sdtr_table_t *table)
{
	_sdtr_table_t tt, *t;

	if (copyin(table, &tt, sizeof (tt) - sizeof (_sdtr_t))) {
		return (EFAULT);
	}
	if (cd == SDT_ANY_CD) {		/* modify config parameter */
		if (flag & SD_SET_SIZE)
			_sd_cache_config.trace_size = tt.tt_max;
		if (flag & SD_SET_MASK) {
			_sd_cache_config.trace_mask = tt.tt_mask;
			/* explicitly set global mask, not bitwise or */
			_sd_trace_mask = tt.tt_mask;
		}
		if (flag & SD_SET_LBOLT)
			_sd_cache_config.trace_lbolt = tt.tt_lbolt;
		if (flag & SD_SET_GOOD)
			_sd_cache_config.trace_good = tt.tt_good;
		return (0);
	}
	if (flag & SD_SET_SIZE)
		_sd_cache_config.trace_size = tt.tt_max;
	/* modify particular device parameters */
	if (!_sd_trace_table[cd].tbl)
		(void) _sdbc_tr_configure(cd);
	if ((t = _sd_trace_table[cd].tbl) == NULL)
		return (0);
	if (flag & SD_SET_MASK) {
		t->tt_mask = tt.tt_mask;
		_sd_trace_mask |= tt.tt_mask; /* or-ed with global mask */
	}
	if (flag & SD_SET_LBOLT)
		t->tt_lbolt = tt.tt_lbolt;
	if (flag & SD_SET_GOOD)
		t->tt_good = tt.tt_good;
	if (copyout(t, table, sizeof (*t) - sizeof (_sdtr_t))) {
		return (EFAULT);
	}
	return (0);
}

#else /* ! _SD_NOTRACE */

int _sd_adump() 	{ return (ENOSYS); }
int _sdbc_tr_load(void) 	{ return (0); }
int _sdbc_tr_configure(void) 	{ return (0); }
void _sdbc_tr_deconfigure(void)	{ return; }
void _sdbc_tr_unload(void) { return; }

#endif /* ! _SD_NOTRACE */
