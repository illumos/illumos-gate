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
#include <sys/sdt.h>

#include <sys/varargs.h>
#include <sys/unistat/spcs_s.h>

#include "safestore.h"
#include "safestore_impl.h"
#include "sd_trace.h"

typedef struct safestore_modules_s {
	struct safestore_modules_s *ssm_next;
	safestore_ops_t *ssm_module;
} safestore_modules_t;

safestore_modules_t *ss_modules;
kmutex_t safestore_mutex;
int ss_initialized;

/* the safestore module init/deinit functions */

void ss_ram_init();
void ss_ram_deinit();

/* CSTYLED */
/**#
 * initialize the safestore subsystem and all safestore
 * modules by calling all safestore modules' initialization functions
 *
 * NOTE: This function must be called with the _sdbc_config_lock held
 *
 * @param none
 * @return void
 *
 */
void
sst_init()
{
	/*
	 * initialize the ss modules we know about
	 * this results in calls to sst_register_mod()
	 */
	if (ss_initialized != SS_INITTED) {
		mutex_init(&safestore_mutex, NULL, MUTEX_DRIVER, NULL);
		ss_ram_init();
		ss_initialized = SS_INITTED;
	}

}

/* CSTYLED */
/**#
 * deinitialize the safestore subsystem and all safestore modules
 * by calling all safestore modules' deinitialization functions
 *
 * NOTE: This function must be called with the _sdbc_config_lock held
 *
 * @param none
 * @return void
 *
 */
void
sst_deinit()
{
	if (ss_initialized == SS_INITTED) {
		ss_ram_deinit();
		mutex_destroy(&safestore_mutex);
		ss_initialized = 0;
	}
}

/* BEGIN CSTYLED */
/**#
 * called by a safestore module to register its ops table
 * for use by clients
 *
 * @param ss_ops structure of safestore functions
 * @return void
 *
 * @see safestore_ops_t{}
 */
void
sst_register_mod(safestore_ops_t *ss_ops) /* END CSTYLED */
{
	safestore_modules_t *new;

	new = kmem_alloc(sizeof (*new), KM_SLEEP);

	mutex_enter(&safestore_mutex);
	new->ssm_module = ss_ops;
	new->ssm_next = ss_modules;

	ss_modules = new;
	mutex_exit(&safestore_mutex);
}

/* BEGIN CSTYLED */
/**#
 * called by a safestore module to unregister its ops table
 * @param ss_ops structure of safestore functions
 *
 * @return void
 *
 * @see safestore_ops_t{}
 */
void
sst_unregister_mod(safestore_ops_t *ss_ops) /* END CSTYLED */
{
	safestore_modules_t *ssm, *prev;
	int found = 0;

	mutex_enter(&safestore_mutex);
	prev = NULL;
	for (ssm = ss_modules; ssm; prev = ssm, ssm = ssm->ssm_next) {
		if (ssm->ssm_module == ss_ops) {
			if (!prev)
				ss_modules = ssm->ssm_next;
			else
				prev->ssm_next = ssm->ssm_next;

			kmem_free(ssm, sizeof (safestore_modules_t));
			++found;
			break;
		}
	}
	mutex_exit(&safestore_mutex);

	if (!found)
		cmn_err(CE_WARN, "ss(sst_unregister_mod) "
				"ss module %p not found", (void *)ss_ops);
}

/* BEGIN CSTYLED */
/**#
 * open a safestore module for use by a client
 * @param ss_type  specifies a valid media type and transport type.
 *                 the first module found that supports these reqested type
 *                 is used. may contain more than one media type or transport
 *                 type if client has no preference among several types.
 *                 more than one ss_type may be specified in the call if
 *                 client has an ordered preference.
 *
 * @return safestore_ops_t *  pointer to a valid safestore ops structure
 *			      if the request is satisfied.
 *         NULL otherwise
 *
 * @see safestore_ops_t{}
 * @see SS_M_RAM
 * @see SS_M_NV_SINGLENODE
 * @see SS_M_NV_DUALNODE_NOMIRROR
 * @see SS_M_NV_DUALNODE_MIRROR
 * @see SS_T_STE
 * @see SS_T_RPC
 * @see SS_T_NONE
 */
safestore_ops_t *
sst_open(uint_t ss_type, ...) /* END CSTYLED */
{
	va_list ap;
	uint_t ssop_type;
	safestore_modules_t *ssm;

	if ((ss_modules == NULL) || !ss_type)
		return (NULL);

	va_start(ap, ss_type);
	mutex_enter(&safestore_mutex);
	do {
		for (ssm = ss_modules; ssm; ssm = ssm->ssm_next) {
			ssop_type = ssm->ssm_module->ssop_type;
			if ((ssop_type &  SS_MEDIA_MASK) & ss_type)
			    if ((ssop_type &  SS_TRANSPORT_MASK) & ss_type) {
					va_end(ap);
					mutex_exit(&safestore_mutex);
					return (ssm->ssm_module);
			    }
		}
	} while ((ss_type = va_arg(ap, uint_t)) != 0);
	mutex_exit(&safestore_mutex);

	va_end(ap);
	return (NULL);
}

/* BEGIN CSTYLED */
/**#
 * close a safestore module. called when client no longer wishes to use
 * a safestore module
 *
 * @param ssp  points to a safestore_ops_t obtained from a previous call
 *             to sst_open()
 *
 * @return SS_OK if successful
 *         SS_ERR otherwise
 */
/*ARGSUSED*/
int
sst_close(safestore_ops_t *ssp) /* END CSTYLED */
{
	return (SS_OK);
}


/*
 * _sdbc_writeq_configure - configure the given writeq
 * Allocate the lock and sv we need to maintain waiters
 *
 */
int
_sdbc_writeq_configure(_sd_writeq_t *wrq)
{
	int i;

	wrq->wq_inq = 0;
	mutex_init(&wrq->wq_qlock, NULL, MUTEX_DRIVER, NULL);
	wrq->wq_qtop = NULL;
	wrq->wq_slp_top = 0;
	wrq->wq_slp_index = 0;
	wrq->wq_slp_inq = 0;

	for (i = 0; i < SD_WR_SLP_Q_MAX; i++) {
		wrq->wq_slp[i].slp_wqneed = 0;
		cv_init(&wrq->wq_slp[i].slp_wqcv, NULL, CV_DRIVER, NULL);
	}

	return (0);
}

/*
 * _sdbc_writeq_deconfigure - deconfigure the given writeq
 * Deallocate the lock and sv if present.
 *
 */
void
_sdbc_writeq_deconfigure(_sd_writeq_t *wrq)
{
	int i;

	if (wrq) {
		mutex_destroy(&wrq->wq_qlock);
		for (i = 0; i < SD_WR_SLP_Q_MAX; i++) {
			cv_destroy(&wrq->wq_slp[i].slp_wqcv);
		}
		wrq->wq_inq = 0;
		wrq->wq_qtop = NULL;
	}

}


int _sd_wblk_sync = 1;

ss_wr_cctl_t *
ss_alloc_write(int need, int *stall, _sd_writeq_t *q)
{
	ss_wr_cctl_t *wctl;
	ss_wr_cctl_t *ret;
	int i;
	int aged = 0;

	if (_sd_wblk_sync && (q->wq_inq == 0))
		return (NULL); /* do sync write if queue empty */

	SDTRACE(ST_ENTER|SDF_WR_ALLOC, SDT_INV_CD, need,
	    SDT_INV_BL, q->wq_inq, _SD_NO_NET);

	if (need <= 0) {
		cmn_err(CE_WARN, "ss_alloc_write: bogus need value! %d", need);
		return (NULL);
	}

	mutex_enter(&(q->wq_qlock));
retry_wr_get:
	if (q->wq_inq < need) {
		if (!_sd_wblk_sync) {
			unsigned stime;
			stime = nsc_usec();

			/*
			 * Try to keep requests ordered so large requests
			 * are not starved.  We can queue 255 write requests,
			 * After That go into write-through.
			 */
			if (q->wq_slp_inq < SD_WR_SLP_Q_MAX) {
				q->wq_slp_inq++;
				/* give preference to aged requests */
				if (aged) {
					WQ_SVWAIT_TOP(q, need);
				} else {
					WQ_SVWAIT_BOTTOM(q, need);
				}
				aged++;
			} else {
				mutex_exit(&(q->wq_qlock));
				return (NULL);
			}

			SDTRACE(ST_INFO|SDF_WR_ALLOC,
				SDT_INV_CD, need, SDT_INV_BL, q->wq_inq,
				(nsc_usec()-stime));
			(void) (*stall)++;
			goto retry_wr_get;
		}
		ret = NULL;
	} else {
get_wctl:
		wctl = q->wq_qtop;
		ret = wctl;
		DTRACE_PROBE1(alloc_write,
		    ss_wr_cctl_t *, wctl);
		for (i = 1; i < need; ++i) {
			wctl = wctl->wc_next;
			DTRACE_PROBE1(alloc_write_cont,
			    ss_wr_cctl_t *, wctl);
		}

		q->wq_qtop = wctl->wc_next;
		wctl->wc_next = NULL;
		q->wq_inq -= need;
	}
	mutex_exit(&(q->wq_qlock));

	SDTRACE(ST_EXIT|SDF_WR_ALLOC, SDT_INV_CD, need,
	    SDT_INV_BL, q->wq_inq, _SD_NO_NET);
	return (ret);
}

/*
 * ss_release_write - put a write block back in the writeq.
 *
 * ARGUMENTS:
 *	wctl 	- Write control block to be release.
 *      q       - write q to put the wctl
 *
 * RETURNS:     NONE
 */

void
ss_release_write(ss_wr_cctl_t *wctl, _sd_writeq_t *q)
{

	SDTRACE(ST_ENTER|SDF_WR_FREE, SDT_INV_CD, 0, SDT_INV_BL, q->wq_inq,
		_SD_NO_NET);

	DTRACE_PROBE1(release_write,
			    ss_wr_cctl_t *, wctl);

#if defined(_SD_DEBUG)
	if (wctl->wc_gl_info->sci_dirty) {
		SDALERT(SDF_WR_FREE, wctl->wc_gl_info->sci_cd,
			0, wctl->wc_gl_info->sci_fpos,
			wctl->wc_gl_info->sci_dirty, 0);
	}
#endif
	mutex_enter(&q->wq_qlock);

	wctl->wc_next = q->wq_qtop;
	q->wq_qtop = wctl;
	q->wq_inq++;
	if (WQ_NEED_SIG(q)) {
		q->wq_slp_inq--;
		WQ_SVSIG(q);
	}
	mutex_exit(&q->wq_qlock);
	SDTRACE(ST_EXIT|SDF_WR_FREE, SDT_INV_CD, 0, SDT_INV_BL, q->wq_inq,
	    _SD_NO_NET);
}
