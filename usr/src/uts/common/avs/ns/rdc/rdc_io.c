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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/ksynch.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/errno.h>
#include <sys/sysmacros.h>

#ifdef _SunOS_5_6
/*
 * on 2.6 both dki_lock.h and rpc/types.h define bool_t so we
 * define enum_t here as it is all we need from rpc/types.h
 * anyway and make it look like we included it. Yuck.
 */
#define	_RPC_TYPES_H
typedef int enum_t;
#else
#ifndef DS_DDICT
#include <rpc/types.h>
#endif
#endif /* _SunOS_5_6 */

#include <sys/ddi.h>

#include <sys/nsc_thread.h>
#include <sys/nsctl/nsctl.h>

#include <sys/sdt.h>		/* dtrace is S10 or later */

#include "rdc_io.h"
#include "rdc_bitmap.h"
#include "rdc_update.h"
#include "rdc_ioctl.h"
#include "rdcsrv.h"
#include "rdc_diskq.h"

#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_k.h>
#include <sys/unistat/spcs_errors.h>

volatile int net_exit;
nsc_size_t MAX_RDC_FBAS;

#ifdef DEBUG
int RDC_MAX_SYNC_THREADS = 8;
int rdc_maxthreads_last = 8;
#endif

kmutex_t rdc_ping_lock;		/* Ping lock */
static kmutex_t net_blk_lock;

/*
 * rdc_conf_lock is used as a global device configuration lock.
 * It is also used by enable/resume and disable/suspend code to ensure that
 * the transition of an rdc set between configured and unconfigured is
 * atomic.
 *
 * krdc->group->lock is used to protect state changes of a configured rdc
 * set (e.g. changes to urdc->flags), such as enabled to disabled and vice
 * versa.
 *
 * rdc_many_lock is also used to protect changes in group membership. A group
 * linked list cannot change while this lock is held. The many list and the
 * multi-hop list are both protected by rdc_many_lock.
 */
kmutex_t rdc_conf_lock;
kmutex_t rdc_many_lock;			/* Many/multi-list lock */

static kmutex_t rdc_net_hnd_id_lock;	/* Network handle id lock */
int rdc_debug = 0;
int rdc_debug_sleep = 0;

static int rdc_net_hnd_id = 1;

extern kmutex_t rdc_clnt_lock;

static void rdc_ditemsfree(rdc_net_dataset_t *);
void rdc_clnt_destroy(void);

rdc_k_info_t *rdc_k_info;
rdc_u_info_t *rdc_u_info;

unsigned long rdc_async_timeout;

nsc_size_t rdc_maxthres_queue = RDC_MAXTHRES_QUEUE;
int rdc_max_qitems = RDC_MAX_QITEMS;
int rdc_asyncthr = RDC_ASYNCTHR;
static nsc_svc_t *rdc_volume_update;
static int rdc_prealloc_handle = 1;

extern int _rdc_rsrv_diskq(rdc_group_t *group);
extern void _rdc_rlse_diskq(rdc_group_t *group);

/*
 * Forward declare all statics that are used before defined
 * to enforce parameter checking
 *
 * Some (if not all) of these could be removed if the code were reordered
 */

static void rdc_volume_update_svc(intptr_t);
static void halt_sync(rdc_k_info_t *krdc);
void rdc_kstat_create(int index);
void rdc_kstat_delete(int index);
static int rdc_checkforbitmap(int, nsc_off_t);
static int rdc_installbitmap(int, void *, int, nsc_off_t, int, int *, int);
static rdc_group_t *rdc_newgroup();

int rdc_enable_diskq(rdc_k_info_t *krdc);
void rdc_close_diskq(rdc_group_t *group);
int rdc_suspend_diskq(rdc_k_info_t *krdc);
int rdc_resume_diskq(rdc_k_info_t *krdc);
void rdc_init_diskq_header(rdc_group_t *grp, dqheader *header);
void rdc_fail_diskq(rdc_k_info_t *krdc, int wait, int dolog);
void rdc_unfail_diskq(rdc_k_info_t *krdc);
void rdc_unintercept_diskq(rdc_group_t *grp);
int rdc_stamp_diskq(rdc_k_info_t *krdc, int rsrvd, int flags);
void rdc_qfiller_thr(rdc_k_info_t *krdc);

nstset_t *_rdc_ioset;
nstset_t *_rdc_flset;

/*
 * RDC threadset tunables
 */
int rdc_threads = 64;		/* default number of threads */
int rdc_threads_inc = 8;	/* increment for changing the size of the set */

/*
 * Private threadset manipulation variables
 */
static int rdc_threads_hysteresis = 2;
				/* hysteresis for threadset resizing */
static int rdc_sets_active;	/* number of sets currently enabled */

#ifdef DEBUG
kmutex_t rdc_cntlock;
#endif

/*
 * rdc_thread_deconfigure - rdc is being deconfigured, stop any
 * thread activity.
 *
 * Inherently single-threaded by the Solaris module unloading code.
 */
static void
rdc_thread_deconfigure(void)
{
	nst_destroy(_rdc_ioset);
	_rdc_ioset = NULL;

	nst_destroy(_rdc_flset);
	_rdc_flset = NULL;

	nst_destroy(sync_info.rdc_syncset);
	sync_info.rdc_syncset = NULL;
}

/*
 * rdc_thread_configure - rdc is being configured, initialize the
 * threads we need for flushing aync volumes.
 *
 * Must be called with rdc_conf_lock held.
 */
static int
rdc_thread_configure(void)
{
	ASSERT(MUTEX_HELD(&rdc_conf_lock));

	if ((_rdc_ioset = nst_init("rdc_thr", rdc_threads)) == NULL)
		return (EINVAL);

	if ((_rdc_flset = nst_init("rdc_flushthr", 2)) == NULL)
		return (EINVAL);

	if ((sync_info.rdc_syncset =
	    nst_init("rdc_syncthr", RDC_MAX_SYNC_THREADS)) == NULL)
		return (EINVAL);

	return (0);
}


/*
 * rdc_thread_tune - called to tune the size of the rdc threadset.
 *
 * Called from the config code when an rdc_set has been enabled or disabled.
 * 'sets' is the increment to the number of active rdc_sets.
 *
 * Must be called with rdc_conf_lock held.
 */
static void
rdc_thread_tune(int sets)
{
	int incr = (sets > 0) ? 1 : -1;
	int change = 0;
	int nthreads;

	ASSERT(MUTEX_HELD(&rdc_conf_lock));

	if (sets < 0)
		sets = -sets;

	while (sets--) {
		nthreads = nst_nthread(_rdc_ioset);
		rdc_sets_active += incr;

		if (rdc_sets_active >= nthreads)
			change += nst_add_thread(_rdc_ioset, rdc_threads_inc);
		else if ((rdc_sets_active <
		    (nthreads - (rdc_threads_inc + rdc_threads_hysteresis))) &&
		    ((nthreads - rdc_threads_inc) >= rdc_threads))
			change -= nst_del_thread(_rdc_ioset, rdc_threads_inc);
	}

#ifdef DEBUG
	if (change) {
		cmn_err(CE_NOTE, "!rdc_thread_tune: "
		    "nsets %d, nthreads %d, nthreads change %d",
		    rdc_sets_active, nst_nthread(_rdc_ioset), change);
	}
#endif
}


/*
 * _rdc_unload() - cache is being unloaded,
 * deallocate any dual copy structures allocated during cache
 * loading.
 */
void
_rdc_unload(void)
{
	int i;
	rdc_k_info_t *krdc;

	if (rdc_volume_update) {
		(void) nsc_unregister_svc(rdc_volume_update);
		rdc_volume_update = NULL;
	}

	rdc_thread_deconfigure();

	if (rdc_k_info != NULL) {
		for (i = 0; i < rdc_max_sets; i++) {
			krdc = &rdc_k_info[i];
			mutex_destroy(&krdc->dc_sleep);
			mutex_destroy(&krdc->bmapmutex);
			mutex_destroy(&krdc->kstat_mutex);
			mutex_destroy(&krdc->bmp_kstat_mutex);
			mutex_destroy(&krdc->syncbitmutex);
			cv_destroy(&krdc->busycv);
			cv_destroy(&krdc->closingcv);
			cv_destroy(&krdc->haltcv);
			cv_destroy(&krdc->synccv);
		}
	}

	mutex_destroy(&sync_info.lock);
	mutex_destroy(&rdc_ping_lock);
	mutex_destroy(&net_blk_lock);
	mutex_destroy(&rdc_conf_lock);
	mutex_destroy(&rdc_many_lock);
	mutex_destroy(&rdc_net_hnd_id_lock);
	mutex_destroy(&rdc_clnt_lock);
#ifdef DEBUG
	mutex_destroy(&rdc_cntlock);
#endif
	net_exit = ATM_EXIT;

	if (rdc_k_info != NULL)
		kmem_free(rdc_k_info, sizeof (*rdc_k_info) * rdc_max_sets);
	if (rdc_u_info != NULL)
		kmem_free(rdc_u_info, sizeof (*rdc_u_info) * rdc_max_sets);
	rdc_k_info = NULL;
	rdc_u_info = NULL;
	rdc_max_sets = 0;
}


/*
 * _rdc_load() - rdc is being loaded, Allocate anything
 * that will be needed while the cache is loaded but doesn't really
 * depend on configuration parameters.
 *
 */
int
_rdc_load(void)
{
	int i;
	rdc_k_info_t *krdc;

	mutex_init(&rdc_ping_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&net_blk_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&rdc_conf_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&rdc_many_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&rdc_net_hnd_id_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&rdc_clnt_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&sync_info.lock, NULL, MUTEX_DRIVER, NULL);

#ifdef DEBUG
	mutex_init(&rdc_cntlock, NULL, MUTEX_DRIVER, NULL);
#endif

	if ((i = nsc_max_devices()) < rdc_max_sets)
		rdc_max_sets = i;
	/* following case for partial installs that may fail */
	if (!rdc_max_sets)
		rdc_max_sets = 1024;

	rdc_k_info = kmem_zalloc(sizeof (*rdc_k_info) * rdc_max_sets, KM_SLEEP);
	if (!rdc_k_info)
		return (ENOMEM);

	rdc_u_info = kmem_zalloc(sizeof (*rdc_u_info) * rdc_max_sets, KM_SLEEP);
	if (!rdc_u_info) {
		kmem_free(rdc_k_info, sizeof (*rdc_k_info) * rdc_max_sets);
		return (ENOMEM);
	}

	net_exit = ATM_NONE;
	for (i = 0; i < rdc_max_sets; i++) {
		krdc = &rdc_k_info[i];
		bzero(krdc, sizeof (*krdc));
		krdc->index = i;
		mutex_init(&krdc->dc_sleep, NULL, MUTEX_DRIVER, NULL);
		mutex_init(&krdc->bmapmutex, NULL, MUTEX_DRIVER, NULL);
		mutex_init(&krdc->kstat_mutex, NULL, MUTEX_DRIVER, NULL);
		mutex_init(&krdc->bmp_kstat_mutex, NULL, MUTEX_DRIVER, NULL);
		mutex_init(&krdc->syncbitmutex, NULL, MUTEX_DRIVER, NULL);
		cv_init(&krdc->busycv, NULL, CV_DRIVER, NULL);
		cv_init(&krdc->closingcv, NULL, CV_DRIVER, NULL);
		cv_init(&krdc->haltcv, NULL, CV_DRIVER, NULL);
		cv_init(&krdc->synccv, NULL, CV_DRIVER, NULL);
	}

	rdc_volume_update = nsc_register_svc("RDCVolumeUpdated",
	    rdc_volume_update_svc);

	return (0);
}

static void
rdc_u_init(rdc_u_info_t *urdc)
{
	const int index = (int)(urdc - &rdc_u_info[0]);

	if (urdc->secondary.addr.maxlen)
		free_rdc_netbuf(&urdc->secondary.addr);
	if (urdc->primary.addr.maxlen)
		free_rdc_netbuf(&urdc->primary.addr);

	bzero(urdc, sizeof (rdc_u_info_t));

	urdc->index = index;
	urdc->maxqfbas = rdc_maxthres_queue;
	urdc->maxqitems = rdc_max_qitems;
	urdc->asyncthr = rdc_asyncthr;
}

/*
 * _rdc_configure() - cache is being configured.
 *
 * Initialize dual copy structures
 */
int
_rdc_configure(void)
{
	int index;
	rdc_k_info_t *krdc;

	for (index = 0; index < rdc_max_sets; index++) {
		krdc = &rdc_k_info[index];

		krdc->remote_index = -1;
		krdc->dcio_bitmap = NULL;
		krdc->bitmap_ref = NULL;
		krdc->bitmap_size = 0;
		krdc->bitmap_write = 0;
		krdc->disk_status = 0;
		krdc->many_next = krdc;

		rdc_u_init(&rdc_u_info[index]);
	}

	rdc_async_timeout = 120 * HZ;   /* Seconds * HZ */
	MAX_RDC_FBAS = FBA_LEN(RDC_MAXDATA);
	if (net_exit != ATM_INIT) {
		net_exit = ATM_INIT;
		return (0);
	}
	return (0);
}

/*
 * _rdc_deconfigure - rdc is being deconfigured, shut down any
 * dual copy operations and return to an unconfigured state.
 */
void
_rdc_deconfigure(void)
{
	rdc_k_info_t *krdc;
	rdc_u_info_t *urdc;
	int index;

	for (index = 0; index < rdc_max_sets; index++) {
		krdc = &rdc_k_info[index];
		urdc = &rdc_u_info[index];

		krdc->remote_index = -1;
		krdc->dcio_bitmap = NULL;
		krdc->bitmap_ref = NULL;
		krdc->bitmap_size = 0;
		krdc->bitmap_write = 0;
		krdc->disk_status = 0;
		krdc->many_next = krdc;

		if (urdc->primary.addr.maxlen)
			free_rdc_netbuf(&(urdc->primary.addr));

		if (urdc->secondary.addr.maxlen)
			free_rdc_netbuf(&(urdc->secondary.addr));

		bzero(urdc, sizeof (rdc_u_info_t));
		urdc->index = index;
	}
	net_exit = ATM_EXIT;
	rdc_clnt_destroy();

}


/*
 * Lock primitives, containing checks that lock ordering isn't broken
 */
/*ARGSUSED*/
void
rdc_many_enter(rdc_k_info_t *krdc)
{
	ASSERT(!MUTEX_HELD(&krdc->bmapmutex));

	mutex_enter(&rdc_many_lock);
}

/* ARGSUSED */
void
rdc_many_exit(rdc_k_info_t *krdc)
{
	mutex_exit(&rdc_many_lock);
}

void
rdc_group_enter(rdc_k_info_t *krdc)
{
	ASSERT(!MUTEX_HELD(&rdc_many_lock));
	ASSERT(!MUTEX_HELD(&rdc_conf_lock));
	ASSERT(!MUTEX_HELD(&krdc->bmapmutex));

	mutex_enter(&krdc->group->lock);
}

void
rdc_group_exit(rdc_k_info_t *krdc)
{
	mutex_exit(&krdc->group->lock);
}

/*
 * Suspend and disable operations use this function to wait until it is safe
 * to do continue, without trashing data structures used by other ioctls.
 */
static void
wait_busy(rdc_k_info_t *krdc)
{
	ASSERT(MUTEX_HELD(&rdc_conf_lock));

	while (krdc->busy_count > 0)
		cv_wait(&krdc->busycv, &rdc_conf_lock);
}


/*
 * Other ioctls use this function to hold off disable and suspend.
 */
void
set_busy(rdc_k_info_t *krdc)
{
	ASSERT(MUTEX_HELD(&rdc_conf_lock));

	wait_busy(krdc);

	krdc->busy_count++;
}


/*
 * Other ioctls use this function to allow disable and suspend to continue.
 */
void
wakeup_busy(rdc_k_info_t *krdc)
{
	ASSERT(MUTEX_HELD(&rdc_conf_lock));

	if (krdc->busy_count <= 0)
		return;

	krdc->busy_count--;
	cv_broadcast(&krdc->busycv);
}


/*
 * Remove the rdc set from its group, and destroy the group if no longer in
 * use.
 */
static void
remove_from_group(rdc_k_info_t *krdc)
{
	rdc_k_info_t *p;
	rdc_group_t *group;

	ASSERT(MUTEX_HELD(&rdc_conf_lock));

	rdc_many_enter(krdc);
	group = krdc->group;

	group->count--;

	/*
	 * lock queue while looking at thrnum
	 */
	mutex_enter(&group->ra_queue.net_qlock);
	if ((group->rdc_thrnum == 0) && (group->count == 0)) {

		/*
		 * Assure the we've stopped and the flusher thread has not
		 * fallen back to sleep
		 */
		if (krdc->group->ra_queue.qfill_sleeping != RDC_QFILL_DEAD) {
			group->ra_queue.qfflags |= RDC_QFILLSTOP;
			while (krdc->group->ra_queue.qfflags & RDC_QFILLSTOP) {
				if (krdc->group->ra_queue.qfill_sleeping ==
				    RDC_QFILL_ASLEEP)
					cv_broadcast(&group->ra_queue.qfcv);
				mutex_exit(&group->ra_queue.net_qlock);
				delay(2);
				mutex_enter(&group->ra_queue.net_qlock);
			}
		}
		mutex_exit(&group->ra_queue.net_qlock);

		mutex_enter(&group->diskqmutex);
		rdc_close_diskq(group);
		mutex_exit(&group->diskqmutex);
		rdc_delgroup(group);
		rdc_many_exit(krdc);
		krdc->group = NULL;
		return;
	}
	mutex_exit(&group->ra_queue.net_qlock);
	/*
	 * Always clear the group field.
	 * no, you need it set in rdc_flush_memq().
	 * to call rdc_group_log()
	 * krdc->group = NULL;
	 */

	/* Take this rdc structure off the group list */

	for (p = krdc->group_next; p->group_next != krdc; p = p->group_next)
	;
	p->group_next = krdc->group_next;

	rdc_many_exit(krdc);
}


/*
 * Add the rdc set to its group, setting up a new group if it's the first one.
 */
static int
add_to_group(rdc_k_info_t *krdc, int options, int cmd)
{
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];
	rdc_u_info_t *utmp;
	rdc_k_info_t *ktmp;
	int index;
	rdc_group_t *group;
	int rc = 0;
	nsthread_t *trc;

	ASSERT(MUTEX_HELD(&rdc_conf_lock));

	/*
	 * Look for matching group name, primary host name and secondary
	 * host name.
	 */

	rdc_many_enter(krdc);
	for (index = 0; index < rdc_max_sets; index++) {
		utmp = &rdc_u_info[index];
		ktmp = &rdc_k_info[index];

		if (urdc->group_name[0] == 0)
			break;

		if (!IS_CONFIGURED(ktmp))
			continue;

		if (strncmp(utmp->group_name, urdc->group_name,
		    NSC_MAXPATH) != 0)
			continue;
		if (strncmp(utmp->primary.intf, urdc->primary.intf,
		    MAX_RDC_HOST_SIZE) != 0) {
			/* Same group name, different primary interface */
			rdc_many_exit(krdc);
			return (-1);
		}
		if (strncmp(utmp->secondary.intf, urdc->secondary.intf,
		    MAX_RDC_HOST_SIZE) != 0) {
			/* Same group name, different secondary interface */
			rdc_many_exit(krdc);
			return (-1);
		}

		/* Group already exists, so add this set to the group */

		if (((options & RDC_OPT_ASYNC) == 0) &&
		    ((ktmp->type_flag & RDC_ASYNCMODE) != 0)) {
			/* Must be same mode as existing group members */
			rdc_many_exit(krdc);
			return (-1);
		}
		if (((options & RDC_OPT_ASYNC) != 0) &&
		    ((ktmp->type_flag & RDC_ASYNCMODE) == 0)) {
			/* Must be same mode as existing group members */
			rdc_many_exit(krdc);
			return (-1);
		}

		/* cannont reconfigure existing group into new queue this way */
		if ((cmd != RDC_CMD_RESUME) &&
		    !RDC_IS_DISKQ(ktmp->group) && urdc->disk_queue[0] != '\0') {
			rdc_many_exit(krdc);
			return (RDC_EQNOADD);
		}

		ktmp->group->count++;
		krdc->group = ktmp->group;
		krdc->group_next = ktmp->group_next;
		ktmp->group_next = krdc;

		urdc->autosync = utmp->autosync;	/* Same as rest */

		(void) strncpy(urdc->disk_queue, utmp->disk_queue, NSC_MAXPATH);

		rdc_many_exit(krdc);
		return (0);
	}

	/* This must be a new group */
	group = rdc_newgroup();
	krdc->group = group;
	krdc->group_next = krdc;
	urdc->autosync = -1;	/* Unknown */

	/*
	 * Tune the thread set by one for each thread created
	 */
	rdc_thread_tune(1);

	trc = nst_create(_rdc_ioset, rdc_qfiller_thr, (void *)krdc, NST_SLEEP);
	if (trc == NULL) {
		rc = -1;
		cmn_err(CE_NOTE, "!unable to create queue filler daemon");
		goto fail;
	}

	if (urdc->disk_queue[0] == '\0') {
		krdc->group->flags |= RDC_MEMQUE;
	} else {
		krdc->group->flags |= RDC_DISKQUE;

		/* XXX check here for resume or enable and act accordingly */

		if (cmd == RDC_CMD_RESUME) {
			rc = rdc_resume_diskq(krdc);

		} else if (cmd == RDC_CMD_ENABLE) {
			rc = rdc_enable_diskq(krdc);
			if ((rc == RDC_EQNOADD) && (cmd != RDC_CMD_ENABLE)) {
				cmn_err(CE_WARN, "!disk queue %s enable failed,"
				    " enabling memory queue",
				    urdc->disk_queue);
				krdc->group->flags &= ~RDC_DISKQUE;
				krdc->group->flags |= RDC_MEMQUE;
				bzero(urdc->disk_queue, NSC_MAXPATH);
			}
		}
	}
fail:
	rdc_many_exit(krdc);
	return (rc);
}


/*
 * Move the set to a new group if possible
 */
static int
change_group(rdc_k_info_t *krdc, int options)
{
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];
	rdc_u_info_t *utmp;
	rdc_k_info_t *ktmp;
	rdc_k_info_t *next;
	char tmpq[NSC_MAXPATH];
	int index;
	int rc = -1;
	rdc_group_t *group, *old_group;
	nsthread_t *trc;

	ASSERT(MUTEX_HELD(&rdc_conf_lock));

	/*
	 * Look for matching group name, primary host name and secondary
	 * host name.
	 */

	bzero(&tmpq, sizeof (tmpq));
	rdc_many_enter(krdc);

	old_group = krdc->group;
	next = krdc->group_next;

	if (RDC_IS_DISKQ(old_group)) { /* can't keep your own queue */
		(void) strncpy(tmpq, urdc->disk_queue, NSC_MAXPATH);
		bzero(urdc->disk_queue, sizeof (urdc->disk_queue));
	}
	for (index = 0; index < rdc_max_sets; index++) {
		utmp = &rdc_u_info[index];
		ktmp = &rdc_k_info[index];

		if (ktmp == krdc)
			continue;

		if (urdc->group_name[0] == 0)
			break;

		if (!IS_CONFIGURED(ktmp))
			continue;

		if (strncmp(utmp->group_name, urdc->group_name,
		    NSC_MAXPATH) != 0)
			continue;
		if (strncmp(utmp->primary.intf, urdc->primary.intf,
		    MAX_RDC_HOST_SIZE) != 0)
			goto bad;
		if (strncmp(utmp->secondary.intf, urdc->secondary.intf,
		    MAX_RDC_HOST_SIZE) != 0)
			goto bad;

		/* Group already exists, so add this set to the group */

		if (((options & RDC_OPT_ASYNC) == 0) &&
		    ((ktmp->type_flag & RDC_ASYNCMODE) != 0)) {
			/* Must be same mode as existing group members */
			goto bad;
		}
		if (((options & RDC_OPT_ASYNC) != 0) &&
		    ((ktmp->type_flag & RDC_ASYNCMODE) == 0)) {
			/* Must be same mode as existing group members */
			goto bad;
		}

		ktmp->group->count++;
		krdc->group = ktmp->group;
		krdc->group_next = ktmp->group_next;
		ktmp->group_next = krdc;
		bzero(urdc->disk_queue, sizeof (urdc->disk_queue));
		(void) strncpy(urdc->disk_queue, utmp->disk_queue, NSC_MAXPATH);

		goto good;
	}

	/* This must be a new group */
	group = rdc_newgroup();
	krdc->group = group;
	krdc->group_next = krdc;

	trc = nst_create(_rdc_ioset, rdc_qfiller_thr, (void *)krdc, NST_SLEEP);
	if (trc == NULL) {
		rc = -1;
		cmn_err(CE_NOTE, "!unable to create queue filler daemon");
		goto bad;
	}

	if (urdc->disk_queue[0] == 0) {
		krdc->group->flags |= RDC_MEMQUE;
	} else {
		krdc->group->flags |= RDC_DISKQUE;
		if ((rc = rdc_enable_diskq(krdc)) < 0)
			goto bad;
	}
good:
	if (options & RDC_OPT_ASYNC) {
		krdc->type_flag |= RDC_ASYNCMODE;
		rdc_set_flags(urdc, RDC_ASYNC);
	} else {
		krdc->type_flag &= ~RDC_ASYNCMODE;
		rdc_clr_flags(urdc, RDC_ASYNC);
	}

	old_group->count--;
	if (!old_group->rdc_writer && old_group->count == 0) {
		/* Group now empty, so destroy */
		if (RDC_IS_DISKQ(old_group)) {
			rdc_unintercept_diskq(old_group);
			mutex_enter(&old_group->diskqmutex);
			rdc_close_diskq(old_group);
			mutex_exit(&old_group->diskqmutex);
		}

		mutex_enter(&old_group->ra_queue.net_qlock);

		/*
		 * Assure the we've stopped and the flusher thread has not
		 * fallen back to sleep
		 */
		if (old_group->ra_queue.qfill_sleeping != RDC_QFILL_DEAD) {
			old_group->ra_queue.qfflags |= RDC_QFILLSTOP;
			while (old_group->ra_queue.qfflags & RDC_QFILLSTOP) {
				if (old_group->ra_queue.qfill_sleeping ==
				    RDC_QFILL_ASLEEP)
					cv_broadcast(&old_group->ra_queue.qfcv);
				mutex_exit(&old_group->ra_queue.net_qlock);
				delay(2);
				mutex_enter(&old_group->ra_queue.net_qlock);
			}
		}
		mutex_exit(&old_group->ra_queue.net_qlock);

		rdc_delgroup(old_group);
		rdc_many_exit(krdc);
		return (0);
	}

	/* Take this rdc structure off the old group list */

	for (ktmp = next; ktmp->group_next != krdc; ktmp = ktmp->group_next)
	;
	ktmp->group_next = next;

	rdc_many_exit(krdc);
	return (0);

bad:
	/* Leave existing group status alone */
	(void) strncpy(urdc->disk_queue, tmpq, NSC_MAXPATH);
	rdc_many_exit(krdc);
	return (rc);
}


/*
 * Set flags for an rdc set, setting the group flags as necessary.
 */
void
rdc_set_flags(rdc_u_info_t *urdc, int flags)
{
	rdc_k_info_t *krdc = &rdc_k_info[urdc->index];
	int vflags, sflags, bflags, ssflags;

	DTRACE_PROBE2(rdc_set_flags, int, krdc->index, int, flags);
	vflags = flags & RDC_VFLAGS;
	sflags = flags & RDC_SFLAGS;
	bflags = flags & RDC_BFLAGS;
	ssflags = flags & RDC_SYNC_STATE_FLAGS;

	if (vflags) {
		/* normal volume flags */
		ASSERT(MUTEX_HELD(&rdc_conf_lock) ||
		    MUTEX_HELD(&krdc->group->lock));
		if (ssflags)
			mutex_enter(&krdc->bmapmutex);

		urdc->flags |= vflags;

		if (ssflags)
			mutex_exit(&krdc->bmapmutex);
	}

	if (sflags) {
		/* Sync state flags that are protected by a different lock */
		ASSERT(MUTEX_HELD(&rdc_many_lock));
		urdc->sync_flags |= sflags;
	}

	if (bflags) {
		/* Bmap state flags that are protected by a different lock */
		ASSERT(MUTEX_HELD(&krdc->bmapmutex));
		urdc->bmap_flags |= bflags;
	}

}


/*
 * Clear flags for an rdc set, clearing the group flags as necessary.
 */
void
rdc_clr_flags(rdc_u_info_t *urdc, int flags)
{
	rdc_k_info_t *krdc = &rdc_k_info[urdc->index];
	int vflags, sflags, bflags;

	DTRACE_PROBE2(rdc_clr_flags, int, krdc->index, int, flags);
	vflags = flags & RDC_VFLAGS;
	sflags = flags & RDC_SFLAGS;
	bflags = flags & RDC_BFLAGS;

	if (vflags) {
		/* normal volume flags */
		ASSERT(MUTEX_HELD(&rdc_conf_lock) ||
		    MUTEX_HELD(&krdc->group->lock));
		urdc->flags &= ~vflags;

	}

	if (sflags) {
		/* Sync state flags that are protected by a different lock */
		ASSERT(MUTEX_HELD(&rdc_many_lock));
		urdc->sync_flags &= ~sflags;
	}

	if (bflags) {
		/* Bmap state flags that are protected by a different lock */
		ASSERT(MUTEX_HELD(&krdc->bmapmutex));
		urdc->bmap_flags &= ~bflags;
	}
}


/*
 * Get the flags for an rdc set.
 */
int
rdc_get_vflags(rdc_u_info_t *urdc)
{
	return (urdc->flags | urdc->sync_flags | urdc->bmap_flags);
}


/*
 * Initialise flags for an rdc set.
 */
static void
rdc_init_flags(rdc_u_info_t *urdc)
{
	urdc->flags = 0;
	urdc->mflags = 0;
	urdc->sync_flags = 0;
	urdc->bmap_flags = 0;
}


/*
 * Set flags for a many group.
 */
void
rdc_set_mflags(rdc_u_info_t *urdc, int flags)
{
	rdc_k_info_t *krdc = &rdc_k_info[urdc->index];
	rdc_k_info_t *this = krdc;

	ASSERT(!(flags & ~RDC_MFLAGS));

	if (flags == 0)
		return;

	ASSERT(MUTEX_HELD(&rdc_many_lock));

	rdc_set_flags(urdc, flags);	/* set flags on local urdc */

	urdc->mflags |= flags;
	for (krdc = krdc->many_next; krdc != this; krdc = krdc->many_next) {
		urdc = &rdc_u_info[krdc->index];
		if (!IS_ENABLED(urdc))
			continue;
		urdc->mflags |= flags;
	}
}


/*
 * Clear flags for a many group.
 */
void
rdc_clr_mflags(rdc_u_info_t *urdc, int flags)
{
	rdc_k_info_t *krdc = &rdc_k_info[urdc->index];
	rdc_k_info_t *this = krdc;
	rdc_u_info_t *utmp;

	ASSERT(!(flags & ~RDC_MFLAGS));

	if (flags == 0)
		return;

	ASSERT(MUTEX_HELD(&rdc_many_lock));

	rdc_clr_flags(urdc, flags);	/* clear flags on local urdc */

	/*
	 * We must maintain the mflags based on the set of flags for
	 * all the urdc's that are chained up.
	 */

	/*
	 * First look through all the urdc's and remove bits from
	 * the 'flags' variable that are in use elsewhere.
	 */

	for (krdc = krdc->many_next; krdc != this; krdc = krdc->many_next) {
		utmp = &rdc_u_info[krdc->index];
		if (!IS_ENABLED(utmp))
			continue;
		flags &= ~(rdc_get_vflags(utmp) & RDC_MFLAGS);
		if (flags == 0)
			break;
	}

	/*
	 * Now clear flags as necessary.
	 */

	if (flags != 0) {
		urdc->mflags &= ~flags;
		for (krdc = krdc->many_next; krdc != this;
		    krdc = krdc->many_next) {
			utmp = &rdc_u_info[krdc->index];
			if (!IS_ENABLED(utmp))
				continue;
			utmp->mflags &= ~flags;
		}
	}
}


int
rdc_get_mflags(rdc_u_info_t *urdc)
{
	return (urdc->mflags);
}


void
rdc_set_flags_log(rdc_u_info_t *urdc, int flags, char *why)
{
	DTRACE_PROBE2(rdc_set_flags_log, int, urdc->index, int, flags);

	rdc_set_flags(urdc, flags);

	if (why == NULL)
		return;

	if (flags & RDC_LOGGING)
		cmn_err(CE_NOTE, "!sndr: %s:%s entered logging mode: %s",
		    urdc->secondary.intf, urdc->secondary.file, why);
	if (flags & RDC_VOL_FAILED)
		cmn_err(CE_NOTE, "!sndr: %s:%s volume failed: %s",
		    urdc->secondary.intf, urdc->secondary.file, why);
	if (flags & RDC_BMP_FAILED)
		cmn_err(CE_NOTE, "!sndr: %s:%s bitmap failed: %s",
		    urdc->secondary.intf, urdc->secondary.file, why);
}
/*
 * rdc_lor(source, dest, len)
 * logically OR memory pointed to by source and dest, copying result into dest.
 */
void
rdc_lor(const uchar_t *source, uchar_t *dest, int len)
{
	int i;

	if (source == NULL)
		return;

	for (i = 0; i < len; i++)
		*dest++ |= *source++;
}


static int
check_filesize(int index, spcs_s_info_t kstatus)
{
	uint64_t remote_size;
	char tmp1[16], tmp2[16];
	rdc_u_info_t *urdc = &rdc_u_info[index];
	int status;

	status = rdc_net_getsize(index, &remote_size);
	if (status) {
		(void) spcs_s_inttostring(status, tmp1, sizeof (tmp1), 0);
		spcs_s_add(kstatus, RDC_EGETSIZE, urdc->secondary.intf,
		    urdc->secondary.file, tmp1);
		(void) rdc_net_state(index, CCIO_ENABLELOG);
		return (RDC_EGETSIZE);
	}
	if (remote_size < (unsigned long long)urdc->volume_size) {
		(void) spcs_s_inttostring(
		    urdc->volume_size, tmp1, sizeof (tmp1), 0);
		/*
		 * Cheat, and covert to int, until we have
		 * spcs_s_unsignedlonginttostring().
		 */
		status = (int)remote_size;
		(void) spcs_s_inttostring(status, tmp2, sizeof (tmp2), 0);
		spcs_s_add(kstatus, RDC_ESIZE, urdc->primary.intf,
		    urdc->primary.file, tmp1, urdc->secondary.intf,
		    urdc->secondary.file, tmp2);
		(void) rdc_net_state(index, CCIO_ENABLELOG);
		return (RDC_ESIZE);
	}
	return (0);
}


static void
rdc_volume_update_svc(intptr_t arg)
{
	rdc_update_t *update = (rdc_update_t *)arg;
	rdc_k_info_t *krdc;
	rdc_k_info_t *this;
	rdc_u_info_t *urdc;
	struct net_bdata6 bd;
	int index;
	int rc;

#ifdef DEBUG_IIUPDATE
	cmn_err(CE_NOTE, "!SNDR received update request for %s",
	    update->volume);
#endif

	if ((update->protocol != RDC_SVC_ONRETURN) &&
	    (update->protocol != RDC_SVC_VOL_ENABLED)) {
		/* don't understand what the client intends to do */
		update->denied = 1;
		spcs_s_add(update->status, RDC_EVERSION);
		return;
	}

	index = rdc_lookup_enabled(update->volume, 0);
	if (index < 0)
		return;

	/*
	 * warn II that this volume is in use by sndr so
	 * II can validate the sizes of the master vs shadow
	 * and avoid trouble later down the line with
	 * size mis-matches between urdc->volume_size and
	 * what is returned from nsc_partsize() which may
	 * be the size of the master when replicating the shadow
	 */
	if (update->protocol == RDC_SVC_VOL_ENABLED) {
		if (index >= 0)
			update->denied = 1;
		return;
	}

	krdc = &rdc_k_info[index];
	urdc = &rdc_u_info[index];
	this = krdc;

	do {
		if (!(rdc_get_vflags(urdc) & RDC_LOGGING)) {
#ifdef DEBUG_IIUPDATE
		cmn_err(CE_NOTE, "!SNDR refused update request for %s",
		    update->volume);
#endif
		update->denied = 1;
		spcs_s_add(update->status, RDC_EMIRRORUP);
		return;
		}
		/* 1->many - all must be logging */
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

#ifdef DEBUG_IIUPDATE
	cmn_err(CE_NOTE, "!SNDR allowed update request for %s", update->volume);
#endif
	urdc = &rdc_u_info[krdc->index];
	do {

		bd.size = min(krdc->bitmap_size, (nsc_size_t)update->size);
		bd.data.data_val = (char *)update->bitmap;
		bd.offset = 0;
		bd.cd = index;

		if ((rc = RDC_OR_BITMAP(&bd)) != 0) {
			update->denied = 1;
			spcs_s_add(update->status, rc);
			return;
		}
		urdc = &rdc_u_info[index];
		urdc->bits_set = RDC_COUNT_BITMAP(krdc);
		if (IS_MANY(krdc) && IS_STATE(urdc, RDC_PRIMARY)) {
			rdc_many_enter(krdc);
			for (krdc = krdc->many_next; krdc != this;
			    krdc = krdc->many_next) {
				index = krdc->index;
				if (!IS_ENABLED(urdc))
					continue;
				break;
			}
			rdc_many_exit(krdc);
		}
	} while (krdc != this);


	/* II (or something else) has updated us, so no need for a sync */
	if (rdc_get_vflags(urdc) & (RDC_SYNC_NEEDED | RDC_RSYNC_NEEDED)) {
		rdc_many_enter(krdc);
		rdc_clr_flags(urdc, RDC_SYNC_NEEDED | RDC_RSYNC_NEEDED);
		rdc_many_exit(krdc);
	}

	if (krdc->bitmap_write > 0)
		(void) rdc_write_bitmap(krdc);
}


/*
 * rdc_check()
 *
 * Return 0 if the set is configured, enabled and the supplied
 * addressing information matches the in-kernel config, otherwise
 * return 1.
 */
static int
rdc_check(rdc_k_info_t *krdc, rdc_set_t *rdc_set)
{
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];

	ASSERT(MUTEX_HELD(&krdc->group->lock));

	if (!IS_ENABLED(urdc))
		return (1);

	if (strncmp(urdc->primary.file, rdc_set->primary.file,
	    NSC_MAXPATH) != 0) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!rdc_check: primary file mismatch %s vs %s",
		    urdc->primary.file, rdc_set->primary.file);
#endif
		return (1);
	}

	if (rdc_set->primary.addr.len != 0 &&
	    bcmp(urdc->primary.addr.buf, rdc_set->primary.addr.buf,
	    urdc->primary.addr.len) != 0) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!rdc_check: primary address mismatch for %s",
		    urdc->primary.file);
#endif
		return (1);
	}

	if (strncmp(urdc->secondary.file, rdc_set->secondary.file,
	    NSC_MAXPATH) != 0) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!rdc_check: secondary file mismatch %s vs %s",
		    urdc->secondary.file, rdc_set->secondary.file);
#endif
		return (1);
	}

	if (rdc_set->secondary.addr.len != 0 &&
	    bcmp(urdc->secondary.addr.buf, rdc_set->secondary.addr.buf,
	    urdc->secondary.addr.len) != 0) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!rdc_check: secondary addr mismatch for %s",
		    urdc->secondary.file);
#endif
		return (1);
	}

	return (0);
}


/*
 * Lookup enabled sets for a bitmap match
 */

int
rdc_lookup_bitmap(char *pathname)
{
	rdc_u_info_t *urdc;
#ifdef DEBUG
	rdc_k_info_t *krdc;
#endif
	int index;

	for (index = 0; index < rdc_max_sets; index++) {
		urdc = &rdc_u_info[index];
#ifdef DEBUG
		krdc = &rdc_k_info[index];
#endif
		ASSERT(krdc->index == index);
		ASSERT(urdc->index == index);

		if (!IS_ENABLED(urdc))
			continue;

		if (rdc_get_vflags(urdc) & RDC_PRIMARY) {
			if (strncmp(pathname, urdc->primary.bitmap,
			    NSC_MAXPATH) == 0)
				return (index);
		} else {
			if (strncmp(pathname, urdc->secondary.bitmap,
			    NSC_MAXPATH) == 0)
				return (index);
		}
	}

	return (-1);
}


/*
 * Translate a pathname to index into rdc_k_info[].
 * Returns first match that is enabled.
 */

int
rdc_lookup_enabled(char *pathname, int allow_disabling)
{
	rdc_u_info_t *urdc;
	rdc_k_info_t *krdc;
	int index;

restart:
	for (index = 0; index < rdc_max_sets; index++) {
		urdc = &rdc_u_info[index];
		krdc = &rdc_k_info[index];

		ASSERT(krdc->index == index);
		ASSERT(urdc->index == index);

		if (!IS_ENABLED(urdc))
			continue;

		if (allow_disabling == 0 && krdc->type_flag & RDC_UNREGISTER)
			continue;

		if (rdc_get_vflags(urdc) & RDC_PRIMARY) {
			if (strncmp(pathname, urdc->primary.file,
			    NSC_MAXPATH) == 0)
				return (index);
		} else {
			if (strncmp(pathname, urdc->secondary.file,
			    NSC_MAXPATH) == 0)
				return (index);
		}
	}

	if (allow_disabling == 0) {
		/* None found, or only a disabling one found, so try again */
		allow_disabling = 1;
		goto restart;
	}

	return (-1);
}


/*
 * Translate a pathname to index into rdc_k_info[].
 * Returns first match that is configured.
 *
 * Used by enable & resume code.
 * Must be called with rdc_conf_lock held.
 */

int
rdc_lookup_configured(char *pathname)
{
	rdc_u_info_t *urdc;
	rdc_k_info_t *krdc;
	int index;

	ASSERT(MUTEX_HELD(&rdc_conf_lock));

	for (index = 0; index < rdc_max_sets; index++) {
		urdc = &rdc_u_info[index];
		krdc = &rdc_k_info[index];

		ASSERT(krdc->index == index);
		ASSERT(urdc->index == index);

		if (!IS_CONFIGURED(krdc))
			continue;

		if (rdc_get_vflags(urdc) & RDC_PRIMARY) {
			if (strncmp(pathname, urdc->primary.file,
			    NSC_MAXPATH) == 0)
				return (index);
		} else {
			if (strncmp(pathname, urdc->secondary.file,
			    NSC_MAXPATH) == 0)
				return (index);
		}
	}

	return (-1);
}


/*
 * Looks up a configured set with matching secondary interface:volume
 * to check for illegal many-to-one volume configs.  To be used during
 * enable and resume processing.
 *
 * Must be called with rdc_conf_lock held.
 */

static int
rdc_lookup_many2one(rdc_set_t *rdc_set)
{
	rdc_u_info_t *urdc;
	rdc_k_info_t *krdc;
	int index;

	ASSERT(MUTEX_HELD(&rdc_conf_lock));

	for (index = 0; index < rdc_max_sets; index++) {
		urdc = &rdc_u_info[index];
		krdc = &rdc_k_info[index];

		if (!IS_CONFIGURED(krdc))
			continue;

		if (strncmp(urdc->secondary.file,
		    rdc_set->secondary.file, NSC_MAXPATH) != 0)
			continue;
		if (strncmp(urdc->secondary.intf,
		    rdc_set->secondary.intf, MAX_RDC_HOST_SIZE) != 0)
			continue;

		break;
	}

	if (index < rdc_max_sets)
		return (index);
	else
		return (-1);
}


/*
 * Looks up an rdc set to check if it is already configured, to be used from
 * functions called from the config ioctl where the interface names can be
 * used for comparison.
 *
 * Must be called with rdc_conf_lock held.
 */

int
rdc_lookup_byname(rdc_set_t *rdc_set)
{
	rdc_u_info_t *urdc;
	rdc_k_info_t *krdc;
	int index;

	ASSERT(MUTEX_HELD(&rdc_conf_lock));

	for (index = 0; index < rdc_max_sets; index++) {
		urdc = &rdc_u_info[index];
		krdc = &rdc_k_info[index];

		ASSERT(krdc->index == index);
		ASSERT(urdc->index == index);

		if (!IS_CONFIGURED(krdc))
			continue;

		if (strncmp(urdc->primary.file, rdc_set->primary.file,
		    NSC_MAXPATH) != 0)
			continue;
		if (strncmp(urdc->primary.intf, rdc_set->primary.intf,
		    MAX_RDC_HOST_SIZE) != 0)
			continue;
		if (strncmp(urdc->secondary.file, rdc_set->secondary.file,
		    NSC_MAXPATH) != 0)
			continue;
		if (strncmp(urdc->secondary.intf, rdc_set->secondary.intf,
		    MAX_RDC_HOST_SIZE) != 0)
			continue;

		break;
	}

	if (index < rdc_max_sets)
		return (index);
	else
		return (-1);
}

/*
 * Looks up a secondary hostname and device, to be used from
 * functions called from the config ioctl where the interface names can be
 * used for comparison.
 *
 * Must be called with rdc_conf_lock held.
 */

int
rdc_lookup_byhostdev(char *intf, char *file)
{
	rdc_u_info_t *urdc;
	rdc_k_info_t *krdc;
	int index;

	ASSERT(MUTEX_HELD(&rdc_conf_lock));

	for (index = 0; index < rdc_max_sets; index++) {
		urdc = &rdc_u_info[index];
		krdc = &rdc_k_info[index];

		ASSERT(krdc->index == index);
		ASSERT(urdc->index == index);

		if (!IS_CONFIGURED(krdc))
			continue;

		if (strncmp(urdc->secondary.file, file,
		    NSC_MAXPATH) != 0)
			continue;
		if (strncmp(urdc->secondary.intf, intf,
		    MAX_RDC_HOST_SIZE) != 0)
			continue;
		break;
	}

	if (index < rdc_max_sets)
		return (index);
	else
		return (-1);
}


/*
 * Looks up an rdc set to see if it is currently enabled, to be used on the
 * server so that the interface addresses must be used for comparison, as
 * the interface names may differ from those used on the client.
 *
 */

int
rdc_lookup_byaddr(rdc_set_t *rdc_set)
{
	rdc_u_info_t *urdc;
#ifdef DEBUG
	rdc_k_info_t *krdc;
#endif
	int index;

	for (index = 0; index < rdc_max_sets; index++) {
		urdc = &rdc_u_info[index];
#ifdef DEBUG
		krdc = &rdc_k_info[index];
#endif
		ASSERT(krdc->index == index);
		ASSERT(urdc->index == index);

		if (!IS_ENABLED(urdc))
			continue;

		if (strcmp(urdc->primary.file, rdc_set->primary.file) != 0)
			continue;

		if (strcmp(urdc->secondary.file, rdc_set->secondary.file) != 0)
			continue;

		if (bcmp(urdc->primary.addr.buf, rdc_set->primary.addr.buf,
		    urdc->primary.addr.len) != 0) {
			continue;
		}

		if (bcmp(urdc->secondary.addr.buf, rdc_set->secondary.addr.buf,
		    urdc->secondary.addr.len) != 0) {
			continue;
		}

		break;
	}

	if (index < rdc_max_sets)
		return (index);
	else
		return (-1);
}


/*
 * Return index of first multihop or 1-to-many
 * Behavior controlled by setting ismany.
 * ismany TRUE (one-to-many)
 * ismany FALSE (multihops)
 *
 */
static int
rdc_lookup_multimany(rdc_k_info_t *krdc, const int ismany)
{
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];
	rdc_u_info_t *utmp;
	rdc_k_info_t *ktmp;
	char *pathname;
	int index;
	int role;

	ASSERT(MUTEX_HELD(&rdc_conf_lock));
	ASSERT(MUTEX_HELD(&rdc_many_lock));

	if (rdc_get_vflags(urdc) & RDC_PRIMARY) {
		/* this host is the primary of the krdc set */
		pathname = urdc->primary.file;
		if (ismany) {
			/*
			 * 1-many sets are linked by primary :
			 * look for matching primary on this host
			 */
			role = RDC_PRIMARY;
		} else {
			/*
			 * multihop sets link primary to secondary :
			 * look for matching secondary on this host
			 */
			role = 0;
		}
	} else {
		/* this host is the secondary of the krdc set */
		pathname = urdc->secondary.file;
		if (ismany) {
			/*
			 * 1-many sets are linked by primary, so if
			 * this host is the secondary of the set this
			 * cannot require 1-many linkage.
			 */
			return (-1);
		} else {
			/*
			 * multihop sets link primary to secondary :
			 * look for matching primary on this host
			 */
			role = RDC_PRIMARY;
		}
	}

	for (index = 0; index < rdc_max_sets; index++) {
		utmp = &rdc_u_info[index];
		ktmp = &rdc_k_info[index];

		if (!IS_CONFIGURED(ktmp)) {
			continue;
		}

		if (role == RDC_PRIMARY) {
			/*
			 * Find a primary that is this host and is not
			 * krdc but shares the same data volume as krdc.
			 */
			if ((rdc_get_vflags(utmp) & RDC_PRIMARY) &&
			    strncmp(utmp->primary.file, pathname,
			    NSC_MAXPATH) == 0 && (krdc != ktmp)) {
				break;
			}
		} else {
			/*
			 * Find a secondary that is this host and is not
			 * krdc but shares the same data volume as krdc.
			 */
			if (!(rdc_get_vflags(utmp) & RDC_PRIMARY) &&
			    strncmp(utmp->secondary.file, pathname,
			    NSC_MAXPATH) == 0 && (krdc != ktmp)) {
				break;
			}
		}
	}

	if (index < rdc_max_sets)
		return (index);
	else
		return (-1);
}

/*
 * Returns secondary match that is configured.
 *
 * Used by enable & resume code.
 * Must be called with rdc_conf_lock held.
 */

static int
rdc_lookup_secondary(char *pathname)
{
	rdc_u_info_t *urdc;
	rdc_k_info_t *krdc;
	int index;

	ASSERT(MUTEX_HELD(&rdc_conf_lock));

	for (index = 0; index < rdc_max_sets; index++) {
		urdc = &rdc_u_info[index];
		krdc = &rdc_k_info[index];

		ASSERT(krdc->index == index);
		ASSERT(urdc->index == index);

		if (!IS_CONFIGURED(krdc))
			continue;

		if (!IS_STATE(urdc, RDC_PRIMARY)) {
			if (strncmp(pathname, urdc->secondary.file,
			    NSC_MAXPATH) == 0)
			return (index);
		}
	}

	return (-1);
}


static nsc_fd_t *
rdc_open_direct(rdc_k_info_t *krdc)
{
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];
	int rc;

	if (krdc->remote_fd == NULL)
		krdc->remote_fd = nsc_open(urdc->direct_file,
		    NSC_RDCHR_ID|NSC_DEVICE|NSC_RDWR, 0, 0, &rc);
	return (krdc->remote_fd);
}

static void
rdc_close_direct(rdc_k_info_t *krdc)
{
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];

	urdc->direct_file[0] = 0;
	if (krdc->remote_fd) {
		if (nsc_close(krdc->remote_fd) == 0) {
			krdc->remote_fd = NULL;
		}
	}
}


#ifdef DEBUG_MANY
static void
print_many(rdc_k_info_t *start)
{
	rdc_k_info_t *p = start;
	rdc_u_info_t *q = &rdc_u_info[p->index];

	do {
		cmn_err(CE_CONT, "!krdc %p, %s %s (many_nxt %p multi_nxt %p)\n",
		    p, q->primary.file, q->secondary.file, p->many_next,
		    p->multi_next);
		delay(10);
		p = p->many_next;
		q = &rdc_u_info[p->index];
	} while (p && p != start);
}
#endif /* DEBUG_MANY */


static int
add_to_multi(rdc_k_info_t *krdc)
{
	rdc_u_info_t *urdc;
	rdc_k_info_t *ktmp;
	rdc_u_info_t *utmp;
	int mindex;
	int domulti;

	urdc = &rdc_u_info[krdc->index];

	ASSERT(MUTEX_HELD(&rdc_conf_lock));
	ASSERT(MUTEX_HELD(&rdc_many_lock));

	/* Now find companion krdc */
	mindex = rdc_lookup_multimany(krdc, FALSE);

#ifdef DEBUG_MANY
	cmn_err(CE_NOTE,
	    "!add_to_multi: lookup_multimany: mindex %d prim %s sec %s",
	    mindex, urdc->primary.file, urdc->secondary.file);
#endif

	if (mindex >= 0) {
		ktmp = &rdc_k_info[mindex];
		utmp = &rdc_u_info[mindex];

		domulti = 1;

		if ((rdc_get_vflags(urdc) & RDC_PRIMARY) &&
		    ktmp->multi_next != NULL) {
			/*
			 * We are adding a new primary to a many
			 * group that is the target of a multihop, just
			 * ignore it since we are linked in elsewhere.
			 */
			domulti = 0;
		}

		if (domulti) {
			if (rdc_get_vflags(urdc) & RDC_PRIMARY) {
				/* Is previous leg using direct file I/O? */
				if (utmp->direct_file[0] != 0) {
					/* It is, so cannot proceed */
					return (-1);
				}
			} else {
				/* Is this leg using direct file I/O? */
				if (urdc->direct_file[0] != 0) {
					/* It is, so cannot proceed */
					return (-1);
				}
			}
			krdc->multi_next = ktmp;
			ktmp->multi_next = krdc;
		}
	} else {
		krdc->multi_next = NULL;
#ifdef DEBUG_MANY
		cmn_err(CE_NOTE, "!add_to_multi: NULL multi_next index %d",
		    krdc->index);
#endif
	}

	return (0);
}


/*
 * Add a new set to the circular list of 1-to-many primaries and chain
 * up any multihop as well.
 */
static int
add_to_many(rdc_k_info_t *krdc)
{
	rdc_k_info_t *okrdc;
	int oindex;

	ASSERT(MUTEX_HELD(&rdc_conf_lock));

	rdc_many_enter(krdc);

	if (add_to_multi(krdc) < 0) {
		rdc_many_exit(krdc);
		return (-1);
	}

	oindex = rdc_lookup_multimany(krdc, TRUE);
	if (oindex < 0) {
#ifdef DEBUG_MANY
		print_many(krdc);
#endif
		rdc_many_exit(krdc);
		return (0);
	}

	okrdc = &rdc_k_info[oindex];

#ifdef DEBUG_MANY
	print_many(okrdc);
#endif
	krdc->many_next = okrdc->many_next;
	okrdc->many_next = krdc;

#ifdef DEBUG_MANY
	print_many(okrdc);
#endif
	rdc_many_exit(krdc);
	return (0);
}


/*
 * Remove a set from the circular list of 1-to-many primaries.
 */
static void
remove_from_many(rdc_k_info_t *old)
{
	rdc_u_info_t *uold = &rdc_u_info[old->index];
	rdc_k_info_t *p, *q;

	ASSERT(MUTEX_HELD(&rdc_conf_lock));

	rdc_many_enter(old);

#ifdef DEBUG_MANY
	cmn_err(CE_NOTE, "!rdc: before remove_from_many");
	print_many(old);
#endif

	if (old->many_next == old) {
		/* remove from multihop */
		if ((q = old->multi_next) != NULL) {
			ASSERT(q->multi_next == old);
			q->multi_next = NULL;
			old->multi_next = NULL;
		}

		rdc_many_exit(old);
		return;
	}

	/* search */
	for (p = old->many_next; p->many_next != old; p = p->many_next)
	;

	p->many_next = old->many_next;
	old->many_next = old;

	if ((q = old->multi_next) != NULL) {
		/*
		 * old was part of a multihop, so switch multi pointers
		 * to someone remaining on the many chain
		 */
		ASSERT(p->multi_next == NULL);

		q->multi_next = p;
		p->multi_next = q;
		old->multi_next = NULL;
	}

#ifdef DEBUG_MANY
	if (p == old) {
		cmn_err(CE_NOTE, "!rdc: after remove_from_many empty");
	} else {
		cmn_err(CE_NOTE, "!rdc: after remove_from_many");
		print_many(p);
	}
#endif

	rdc_clr_mflags(&rdc_u_info[p->index],
	    (rdc_get_vflags(uold) & RDC_MFLAGS));

	rdc_many_exit(old);
}


static int
_rdc_enable(rdc_set_t *rdc_set, int options, spcs_s_info_t kstatus)
{
	int index;
	char *rhost;
	struct netbuf *addrp;
	rdc_k_info_t *krdc;
	rdc_u_info_t *urdc;
	rdc_srv_t *svp = NULL;
	char *local_file;
	char *local_bitmap;
	char *diskq;
	int rc;
	nsc_size_t maxfbas;
	rdc_group_t *grp;

	if ((rdc_set->primary.intf[0] == 0) ||
	    (rdc_set->primary.addr.len == 0) ||
	    (rdc_set->primary.file[0] == 0) ||
	    (rdc_set->primary.bitmap[0] == 0) ||
	    (rdc_set->secondary.intf[0] == 0) ||
	    (rdc_set->secondary.addr.len == 0) ||
	    (rdc_set->secondary.file[0] == 0) ||
	    (rdc_set->secondary.bitmap[0] == 0)) {
		spcs_s_add(kstatus, RDC_EEMPTY);
		return (RDC_EEMPTY);
	}

	/* Next check there aren't any enabled rdc sets which match. */

	mutex_enter(&rdc_conf_lock);

	if (rdc_lookup_byname(rdc_set) >= 0) {
		mutex_exit(&rdc_conf_lock);
		spcs_s_add(kstatus, RDC_EENABLED, rdc_set->primary.intf,
		    rdc_set->primary.file, rdc_set->secondary.intf,
		    rdc_set->secondary.file);
		return (RDC_EENABLED);
	}

	if (rdc_lookup_many2one(rdc_set) >= 0) {
		mutex_exit(&rdc_conf_lock);
		spcs_s_add(kstatus, RDC_EMANY2ONE, rdc_set->primary.intf,
		    rdc_set->primary.file, rdc_set->secondary.intf,
		    rdc_set->secondary.file);
		return (RDC_EMANY2ONE);
	}

	if (rdc_set->netconfig->knc_proto == NULL) {
		mutex_exit(&rdc_conf_lock);
		spcs_s_add(kstatus, RDC_ENETCONFIG);
		return (RDC_ENETCONFIG);
	}

	if (rdc_set->primary.addr.len == 0) {
		mutex_exit(&rdc_conf_lock);
		spcs_s_add(kstatus, RDC_ENETBUF, rdc_set->primary.file);
		return (RDC_ENETBUF);
	}

	if (rdc_set->secondary.addr.len == 0) {
		mutex_exit(&rdc_conf_lock);
		spcs_s_add(kstatus, RDC_ENETBUF, rdc_set->secondary.file);
		return (RDC_ENETBUF);
	}

	/* Check that the local data volume isn't in use as a bitmap */
	if (options & RDC_OPT_PRIMARY)
		local_file = rdc_set->primary.file;
	else
		local_file = rdc_set->secondary.file;
	if (rdc_lookup_bitmap(local_file) >= 0) {
		mutex_exit(&rdc_conf_lock);
		spcs_s_add(kstatus, RDC_EVOLINUSE, local_file);
		return (RDC_EVOLINUSE);
	}

	/* check that the secondary data volume isn't in use */
	if (!(options & RDC_OPT_PRIMARY)) {
		local_file = rdc_set->secondary.file;
		if (rdc_lookup_secondary(local_file) >= 0) {
			mutex_exit(&rdc_conf_lock);
			spcs_s_add(kstatus, RDC_EVOLINUSE, local_file);
			return (RDC_EVOLINUSE);
		}
	}

	/* check that the local data vol is not in use as a diskqueue */
	if (options & RDC_OPT_PRIMARY) {
		if (rdc_lookup_diskq(rdc_set->primary.file) >= 0) {
			mutex_exit(&rdc_conf_lock);
			spcs_s_add(kstatus,
			    RDC_EVOLINUSE, rdc_set->primary.file);
			return (RDC_EVOLINUSE);
		}
	}

	/* Check that the bitmap isn't in use as a data volume */
	if (options & RDC_OPT_PRIMARY)
		local_bitmap = rdc_set->primary.bitmap;
	else
		local_bitmap = rdc_set->secondary.bitmap;
	if (rdc_lookup_configured(local_bitmap) >= 0) {
		mutex_exit(&rdc_conf_lock);
		spcs_s_add(kstatus, RDC_EBMPINUSE, local_bitmap);
		return (RDC_EBMPINUSE);
	}

	/* Check that the bitmap isn't already in use as a bitmap */
	if (rdc_lookup_bitmap(local_bitmap) >= 0) {
		mutex_exit(&rdc_conf_lock);
		spcs_s_add(kstatus, RDC_EBMPINUSE, local_bitmap);
		return (RDC_EBMPINUSE);
	}

	/* check that the diskq (if here) is not in use */
	diskq = rdc_set->disk_queue;
	if (diskq[0] && rdc_diskq_inuse(rdc_set, diskq)) {
		mutex_exit(&rdc_conf_lock);
		spcs_s_add(kstatus, RDC_EDISKQINUSE, diskq);
		return (RDC_EDISKQINUSE);
	}


	/* Set urdc->volume_size */
	index = rdc_dev_open(rdc_set, options);
	if (index < 0) {
		mutex_exit(&rdc_conf_lock);
		if (options & RDC_OPT_PRIMARY)
			spcs_s_add(kstatus, RDC_EOPEN, rdc_set->primary.intf,
			    rdc_set->primary.file);
		else
			spcs_s_add(kstatus, RDC_EOPEN, rdc_set->secondary.intf,
			    rdc_set->secondary.file);
		return (RDC_EOPEN);
	}

	urdc = &rdc_u_info[index];
	krdc = &rdc_k_info[index];

	/* copy relevant parts of rdc_set to urdc field by field */

	(void) strncpy(urdc->primary.intf, rdc_set->primary.intf,
	    MAX_RDC_HOST_SIZE);
	(void) strncpy(urdc->secondary.intf, rdc_set->secondary.intf,
	    MAX_RDC_HOST_SIZE);

	(void) strncpy(urdc->group_name, rdc_set->group_name, NSC_MAXPATH);
	(void) strncpy(urdc->disk_queue, rdc_set->disk_queue, NSC_MAXPATH);

	dup_rdc_netbuf(&rdc_set->primary.addr, &urdc->primary.addr);
	(void) strncpy(urdc->primary.file, rdc_set->primary.file, NSC_MAXPATH);
	(void) strncpy(urdc->primary.bitmap, rdc_set->primary.bitmap,
	    NSC_MAXPATH);

	dup_rdc_netbuf(&rdc_set->secondary.addr, &urdc->secondary.addr);
	(void) strncpy(urdc->secondary.file, rdc_set->secondary.file,
	    NSC_MAXPATH);
	(void) strncpy(urdc->secondary.bitmap, rdc_set->secondary.bitmap,
	    NSC_MAXPATH);

	urdc->setid = rdc_set->setid;

	/*
	 * before we try to add to group, or create one, check out
	 * if we are doing the wrong thing with the diskq
	 */

	if (urdc->disk_queue[0] && (options & RDC_OPT_SYNC)) {
		mutex_exit(&rdc_conf_lock);
		rdc_dev_close(krdc);
		spcs_s_add(kstatus, RDC_EQWRONGMODE);
		return (RDC_EQWRONGMODE);
	}

	if ((rc = add_to_group(krdc, options, RDC_CMD_ENABLE)) != 0) {
		mutex_exit(&rdc_conf_lock);
		rdc_dev_close(krdc);
		if (rc == RDC_EQNOADD) {
			spcs_s_add(kstatus, RDC_EQNOADD, rdc_set->disk_queue);
			return (RDC_EQNOADD);
		} else {
			spcs_s_add(kstatus, RDC_EGROUP,
			    rdc_set->primary.intf, rdc_set->primary.file,
			    rdc_set->secondary.intf, rdc_set->secondary.file,
			    rdc_set->group_name);
			return (RDC_EGROUP);
		}
	}

	/*
	 * maxfbas was set in rdc_dev_open as primary's maxfbas.
	 * If diskq's maxfbas is smaller, then use diskq's.
	 */
	grp = krdc->group;
	if (grp && RDC_IS_DISKQ(grp) && (grp->diskqfd != 0)) {
		rc = _rdc_rsrv_diskq(grp);
		if (RDC_SUCCESS(rc)) {
			rc = nsc_maxfbas(grp->diskqfd, 0, &maxfbas);
			if (rc == 0) {
#ifdef DEBUG
				if (krdc->maxfbas != maxfbas)
					cmn_err(CE_NOTE,
					    "!_rdc_enable: diskq maxfbas = %"
					    NSC_SZFMT ", primary maxfbas = %"
					    NSC_SZFMT, maxfbas, krdc->maxfbas);
#endif
				krdc->maxfbas = min(krdc->maxfbas, maxfbas);
			} else {
				cmn_err(CE_WARN,
				    "!_rdc_enable: diskq maxfbas failed (%d)",
				    rc);
			}
			_rdc_rlse_diskq(grp);
		} else {
			cmn_err(CE_WARN,
			    "!_rdc_enable: diskq reserve failed (%d)", rc);
		}
	}

	rdc_init_flags(urdc);
	(void) strncpy(urdc->direct_file, rdc_set->direct_file, NSC_MAXPATH);
	if ((options & RDC_OPT_PRIMARY) && rdc_set->direct_file[0]) {
		if (rdc_open_direct(krdc) == NULL)
			rdc_set_flags(urdc, RDC_FCAL_FAILED);
	}

	krdc->many_next = krdc;

	ASSERT(krdc->type_flag == 0);
	krdc->type_flag = RDC_CONFIGURED;

	if (options & RDC_OPT_PRIMARY)
		rdc_set_flags(urdc, RDC_PRIMARY);

	if (options & RDC_OPT_ASYNC)
		krdc->type_flag |= RDC_ASYNCMODE;

	set_busy(krdc);
	urdc->syshostid = rdc_set->syshostid;

	if (add_to_many(krdc) < 0) {
		mutex_exit(&rdc_conf_lock);

		rdc_group_enter(krdc);

		spcs_s_add(kstatus, RDC_EMULTI);
		rc = RDC_EMULTI;
		goto fail;
	}

	/* Configured but not enabled */
	ASSERT(IS_CONFIGURED(krdc) && !IS_ENABLED(urdc));

	mutex_exit(&rdc_conf_lock);

	rdc_group_enter(krdc);

	/* Configured but not enabled */
	ASSERT(IS_CONFIGURED(krdc) && !IS_ENABLED(urdc));

	/*
	 * The rdc set is configured but not yet enabled. Other operations must
	 * ignore this set until it is enabled.
	 */

	urdc->sync_pos = 0;

	if (rdc_set->maxqfbas > 0)
		urdc->maxqfbas = rdc_set->maxqfbas;
	else
		urdc->maxqfbas = rdc_maxthres_queue;

	if (rdc_set->maxqitems > 0)
		urdc->maxqitems = rdc_set->maxqitems;
	else
		urdc->maxqitems = rdc_max_qitems;

	if (rdc_set->asyncthr > 0)
		urdc->asyncthr = rdc_set->asyncthr;
	else
		urdc->asyncthr = rdc_asyncthr;

	if (urdc->autosync == -1) {
		/* Still unknown */
		if (rdc_set->autosync > 0)
			urdc->autosync = 1;
		else
			urdc->autosync = 0;
	}

	urdc->netconfig = rdc_set->netconfig;

	if (options & RDC_OPT_PRIMARY) {
		rhost = rdc_set->secondary.intf;
		addrp = &rdc_set->secondary.addr;
	} else {
		rhost = rdc_set->primary.intf;
		addrp = &rdc_set->primary.addr;
	}

	if (options & RDC_OPT_ASYNC)
		rdc_set_flags(urdc, RDC_ASYNC);

	svp = rdc_create_svinfo(rhost, addrp, urdc->netconfig);
	if (svp == NULL) {
		spcs_s_add(kstatus, ENOMEM);
		rc = ENOMEM;
		goto fail;
	}
	urdc->netconfig = NULL;		/* This will be no good soon */

	rdc_kstat_create(index);

	/* Don't set krdc->intf here */

	if (rdc_enable_bitmap(krdc, options & RDC_OPT_SETBMP) < 0)
		goto bmpfail;

	RDC_ZERO_BITREF(krdc);
	if (krdc->lsrv == NULL)
		krdc->lsrv = svp;
	else {
#ifdef DEBUG
		cmn_err(CE_WARN, "!_rdc_enable: krdc->lsrv already set: %p",
		    (void *) krdc->lsrv);
#endif
		rdc_destroy_svinfo(svp);
	}
	svp = NULL;

	/* Configured but not enabled */
	ASSERT(IS_CONFIGURED(krdc) && !IS_ENABLED(urdc));

	/* And finally */

	krdc->remote_index = -1;
	/* Should we set the whole group logging? */
	rdc_set_flags(urdc, RDC_ENABLED | RDC_LOGGING);

	rdc_group_exit(krdc);

	if (rdc_intercept(krdc) != 0) {
		rdc_group_enter(krdc);
		rdc_clr_flags(urdc, RDC_ENABLED);
		if (options & RDC_OPT_PRIMARY)
			spcs_s_add(kstatus, RDC_EREGISTER, urdc->primary.file);
		else
			spcs_s_add(kstatus, RDC_EREGISTER,
			    urdc->secondary.file);
#ifdef DEBUG
		cmn_err(CE_NOTE, "!nsc_register_path failed %s",
		    urdc->primary.file);
#endif
		rc = RDC_EREGISTER;
		goto bmpfail;
	}
#ifdef DEBUG
	cmn_err(CE_NOTE, "!SNDR: enabled %s %s", urdc->primary.file,
	    urdc->secondary.file);
#endif

	rdc_write_state(urdc);

	mutex_enter(&rdc_conf_lock);
	wakeup_busy(krdc);
	mutex_exit(&rdc_conf_lock);

	return (0);

bmpfail:
	if (options & RDC_OPT_PRIMARY)
		spcs_s_add(kstatus, RDC_EBITMAP, rdc_set->primary.bitmap);
	else
		spcs_s_add(kstatus, RDC_EBITMAP, rdc_set->secondary.bitmap);
	rc = RDC_EBITMAP;
	if (rdc_get_vflags(urdc) & RDC_ENABLED) {
		rdc_group_exit(krdc);
		(void) rdc_unintercept(krdc);
		rdc_group_enter(krdc);
	}

fail:
	rdc_kstat_delete(index);
	rdc_group_exit(krdc);
	if (krdc->intf) {
		rdc_if_t *ip = krdc->intf;
		mutex_enter(&rdc_conf_lock);
		krdc->intf = NULL;
		rdc_remove_from_if(ip);
		mutex_exit(&rdc_conf_lock);
	}
	rdc_group_enter(krdc);
	/* Configured but not enabled */
	ASSERT(IS_CONFIGURED(krdc) && !IS_ENABLED(urdc));

	rdc_dev_close(krdc);
	rdc_close_direct(krdc);
	rdc_destroy_svinfo(svp);

	/* Configured but not enabled */
	ASSERT(IS_CONFIGURED(krdc) && !IS_ENABLED(urdc));

	rdc_group_exit(krdc);

	mutex_enter(&rdc_conf_lock);

	/* Configured but not enabled */
	ASSERT(IS_CONFIGURED(krdc) && !IS_ENABLED(urdc));

	remove_from_group(krdc);

	if (IS_MANY(krdc) || IS_MULTI(krdc))
		remove_from_many(krdc);

	rdc_u_init(urdc);

	ASSERT(krdc->type_flag & RDC_CONFIGURED);
	krdc->type_flag = 0;
	wakeup_busy(krdc);

	mutex_exit(&rdc_conf_lock);

	return (rc);
}

static int
rdc_enable(rdc_config_t *uparms, spcs_s_info_t kstatus)
{
	int rc;
	char itmp[10];

	if (!(uparms->options & RDC_OPT_SYNC) &&
	    !(uparms->options & RDC_OPT_ASYNC)) {
		rc = RDC_EEINVAL;
		(void) spcs_s_inttostring(
		    uparms->options, itmp, sizeof (itmp), 1);
		spcs_s_add(kstatus, RDC_EEINVAL, itmp);
		goto done;
	}

	if (!(uparms->options & RDC_OPT_PRIMARY) &&
	    !(uparms->options & RDC_OPT_SECONDARY)) {
		rc = RDC_EEINVAL;
		(void) spcs_s_inttostring(
		    uparms->options, itmp, sizeof (itmp), 1);
		spcs_s_add(kstatus, RDC_EEINVAL, itmp);
		goto done;
	}

	if (!(uparms->options & RDC_OPT_SETBMP) &&
	    !(uparms->options & RDC_OPT_CLRBMP)) {
		rc = RDC_EEINVAL;
		(void) spcs_s_inttostring(
		    uparms->options, itmp, sizeof (itmp), 1);
		spcs_s_add(kstatus, RDC_EEINVAL, itmp);
		goto done;
	}

	rc = _rdc_enable(uparms->rdc_set, uparms->options, kstatus);
done:
	return (rc);
}

/* ARGSUSED */
static int
_rdc_disable(rdc_k_info_t *krdc, rdc_config_t *uap, spcs_s_info_t kstatus)
{
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];
	rdc_if_t *ip;
	int index = krdc->index;
	disk_queue *q;
	rdc_set_t *rdc_set = uap->rdc_set;

	ASSERT(krdc->group != NULL);
	rdc_group_enter(krdc);
#ifdef DEBUG
	ASSERT(rdc_check(krdc, rdc_set) == 0);
#else
	if (((uap->options & RDC_OPT_FORCE_DISABLE) == 0) &&
	    rdc_check(krdc, rdc_set)) {
		rdc_group_exit(krdc);
		spcs_s_add(kstatus, RDC_EALREADY, rdc_set->primary.file,
		    rdc_set->secondary.file);
		return (RDC_EALREADY);
	}
#endif

	if (rdc_get_vflags(urdc) & RDC_PRIMARY) {
		halt_sync(krdc);
		ASSERT(IS_ENABLED(urdc));
	}
	q = &krdc->group->diskq;

	if (IS_ASYNC(urdc) && RDC_IS_DISKQ(krdc->group) &&
	    ((!IS_STATE(urdc, RDC_LOGGING)) && (!QEMPTY(q)))) {
		krdc->type_flag &= ~RDC_DISABLEPEND;
		rdc_group_exit(krdc);
		spcs_s_add(kstatus, RDC_EQNOTEMPTY, urdc->disk_queue);
		return (RDC_EQNOTEMPTY);
	}
	rdc_group_exit(krdc);
	(void) rdc_unintercept(krdc);

#ifdef DEBUG
	cmn_err(CE_NOTE, "!SNDR: disabled %s %s", urdc->primary.file,
	    urdc->secondary.file);
#endif

	/* Configured but not enabled */
	ASSERT(IS_CONFIGURED(krdc) && !IS_ENABLED(urdc));

	/*
	 * No new io can come in through the io provider.
	 * Wait for the async flusher to finish.
	 */

	if (IS_ASYNC(urdc) && !RDC_IS_DISKQ(krdc->group)) {
		int tries = 2; /* in case of hopelessly stuck flusher threads */
#ifdef DEBUG
		net_queue *qp = &krdc->group->ra_queue;
#endif
		do {
			if (!krdc->group->rdc_writer)
				(void) rdc_writer(krdc->index);

			(void) rdc_drain_queue(krdc->index);

		} while (krdc->group->rdc_writer && tries--);

		/* ok, force it to happen... */
		if (rdc_drain_queue(krdc->index) != 0) {
			do {
				mutex_enter(&krdc->group->ra_queue.net_qlock);
				krdc->group->asyncdis = 1;
				cv_broadcast(&krdc->group->asyncqcv);
				mutex_exit(&krdc->group->ra_queue.net_qlock);
				cmn_err(CE_WARN,
				    "!SNDR: async I/O pending and not flushed "
				    "for %s during disable",
				    urdc->primary.file);
#ifdef DEBUG
				cmn_err(CE_WARN,
				    "!nitems: %" NSC_SZFMT " nblocks: %"
				    NSC_SZFMT " head: 0x%p tail: 0x%p",
				    qp->nitems, qp->blocks,
				    (void *)qp->net_qhead,
				    (void *)qp->net_qtail);
#endif
			} while (krdc->group->rdc_thrnum > 0);
		}
	}

	mutex_enter(&rdc_conf_lock);
	ip = krdc->intf;
	krdc->intf = 0;

	if (ip) {
		rdc_remove_from_if(ip);
	}

	mutex_exit(&rdc_conf_lock);

	rdc_group_enter(krdc);

	/* Configured but not enabled */
	ASSERT(IS_CONFIGURED(krdc) && !IS_ENABLED(urdc));

	/* Must not hold group lock during this function */
	rdc_group_exit(krdc);
	while (rdc_dump_alloc_bufs_cd(krdc->index) == EAGAIN)
		delay(2);
	rdc_group_enter(krdc);

	(void) rdc_clear_state(krdc);

	rdc_free_bitmap(krdc, RDC_CMD_DISABLE);
	rdc_close_bitmap(krdc);

	rdc_dev_close(krdc);
	rdc_close_direct(krdc);

	/* Configured but not enabled */
	ASSERT(IS_CONFIGURED(krdc) && !IS_ENABLED(urdc));

	rdc_group_exit(krdc);

	/*
	 * we should now unregister the queue, with no conflicting
	 * locks held. This is the last(only) member of the group
	 */
	if (krdc->group && RDC_IS_DISKQ(krdc->group) &&
	    krdc->group->count == 1) { /* stop protecting queue */
		rdc_unintercept_diskq(krdc->group);
	}

	mutex_enter(&rdc_conf_lock);

	/* Configured but not enabled */
	ASSERT(IS_CONFIGURED(krdc) && !IS_ENABLED(urdc));

	wait_busy(krdc);

	if (IS_MANY(krdc) || IS_MULTI(krdc))
		remove_from_many(krdc);

	remove_from_group(krdc);

	krdc->remote_index = -1;
	ASSERT(krdc->type_flag & RDC_CONFIGURED);
	ASSERT(krdc->type_flag & RDC_DISABLEPEND);
	krdc->type_flag = 0;
#ifdef	DEBUG
	if (krdc->dcio_bitmap)
		cmn_err(CE_WARN, "!_rdc_disable: possible mem leak, "
		    "dcio_bitmap");
#endif
	krdc->dcio_bitmap = NULL;
	krdc->bitmap_ref = NULL;
	krdc->bitmap_size = 0;
	krdc->maxfbas = 0;
	krdc->bitmap_write = 0;
	krdc->disk_status = 0;
	rdc_destroy_svinfo(krdc->lsrv);
	krdc->lsrv = NULL;
	krdc->multi_next = NULL;

	rdc_u_init(urdc);

	mutex_exit(&rdc_conf_lock);
	rdc_kstat_delete(index);

	return (0);
}

static int
rdc_disable(rdc_config_t *uparms, spcs_s_info_t kstatus)
{
	rdc_k_info_t *krdc;
	int index;
	int rc;

	mutex_enter(&rdc_conf_lock);

	index = rdc_lookup_byname(uparms->rdc_set);
	if (index >= 0)
		krdc = &rdc_k_info[index];
	if (index < 0 || (krdc->type_flag & RDC_DISABLEPEND)) {
		mutex_exit(&rdc_conf_lock);
		spcs_s_add(kstatus, RDC_EALREADY, uparms->rdc_set->primary.file,
		    uparms->rdc_set->secondary.file);
		return (RDC_EALREADY);
	}

	krdc->type_flag |= RDC_DISABLEPEND;
	wait_busy(krdc);
	if (krdc->type_flag == 0) {
		/* A resume or enable failed */
		mutex_exit(&rdc_conf_lock);
		spcs_s_add(kstatus, RDC_EALREADY, uparms->rdc_set->primary.file,
		    uparms->rdc_set->secondary.file);
		return (RDC_EALREADY);
	}
	mutex_exit(&rdc_conf_lock);

	rc = _rdc_disable(krdc, uparms, kstatus);
	return (rc);
}


/*
 * Checks whether the state of one of the other sets in the 1-many or
 * multi-hop config should prevent a sync from starting on this one.
 * Return NULL if no just cause or impediment is found, otherwise return
 * a pointer to the offending set.
 */
static rdc_u_info_t *
rdc_allow_pri_sync(rdc_u_info_t *urdc, int options)
{
	rdc_k_info_t *krdc = &rdc_k_info[urdc->index];
	rdc_k_info_t *ktmp;
	rdc_u_info_t *utmp;
	rdc_k_info_t *kmulti = NULL;

	ASSERT(rdc_get_vflags(urdc) & RDC_PRIMARY);

	rdc_many_enter(krdc);

	/*
	 * In the reverse sync case we need to check the previous leg of
	 * the multi-hop config. The link to that set can be from any of
	 * the 1-many list, so as we go through we keep an eye open for it.
	 */
	if ((options & RDC_OPT_REVERSE) && (IS_MULTI(krdc))) {
		/* This set links to the first leg */
		ktmp = krdc->multi_next;
		utmp = &rdc_u_info[ktmp->index];
		if (IS_ENABLED(utmp))
			kmulti = ktmp;
	}

	if (IS_MANY(krdc)) {
		for (ktmp = krdc->many_next; ktmp != krdc;
		    ktmp = ktmp->many_next) {
			utmp = &rdc_u_info[ktmp->index];

			if (!IS_ENABLED(utmp))
				continue;

			if (options & RDC_OPT_FORWARD) {
				/*
				 * Reverse sync needed is bad, as it means a
				 * reverse sync in progress or started and
				 * didn't complete, so this primary volume
				 * is not consistent. So we shouldn't copy
				 * it to its secondary.
				 */
				if (rdc_get_mflags(utmp) & RDC_RSYNC_NEEDED) {
					rdc_many_exit(krdc);
					return (utmp);
				}
			} else {
				/* Reverse, so see if we need to spot kmulti */
				if ((kmulti == NULL) && (IS_MULTI(ktmp))) {
					/* This set links to the first leg */
					kmulti = ktmp->multi_next;
					if (!IS_ENABLED(
					    &rdc_u_info[kmulti->index]))
						kmulti = NULL;
				}

				/*
				 * Non-logging is bad, as the bitmap will
				 * be updated with the bits for this sync.
				 */
				if (!(rdc_get_vflags(utmp) & RDC_LOGGING)) {
					rdc_many_exit(krdc);
					return (utmp);
				}
			}
		}
	}

	if (kmulti) {
		utmp = &rdc_u_info[kmulti->index];
		ktmp = kmulti;	/* In case we decide we do need to use ktmp */

		ASSERT(options & RDC_OPT_REVERSE);

		if (IS_REPLICATING(utmp)) {
			/*
			 * Replicating is bad as data is already flowing to
			 * the target of the requested sync operation.
			 */
			rdc_many_exit(krdc);
			return (utmp);
		}

		if (rdc_get_vflags(utmp) & RDC_SYNCING) {
			/*
			 * Forward sync in progress is bad, as data is
			 * already flowing to the target of the requested
			 * sync operation.
			 * Reverse sync in progress is bad, as the primary
			 * has already decided which data to copy.
			 */
			rdc_many_exit(krdc);
			return (utmp);
		}

		/*
		 * Clear the "sync needed" flags, as the multi-hop secondary
		 * will be updated via this requested sync operation, so does
		 * not need to complete its aborted forward sync.
		 */
		if (rdc_get_vflags(utmp) & RDC_SYNC_NEEDED)
			rdc_clr_flags(utmp, RDC_SYNC_NEEDED);
	}

	if (IS_MANY(krdc) && (options & RDC_OPT_REVERSE)) {
		for (ktmp = krdc->many_next; ktmp != krdc;
		    ktmp = ktmp->many_next) {
			utmp = &rdc_u_info[ktmp->index];
			if (!IS_ENABLED(utmp))
				continue;

			/*
			 * Clear any "reverse sync needed" flags, as the
			 * volume will be updated via this requested
			 * sync operation, so does not need to complete
			 * its aborted reverse sync.
			 */
			if (rdc_get_mflags(utmp) & RDC_RSYNC_NEEDED)
				rdc_clr_mflags(utmp, RDC_RSYNC_NEEDED);
		}
	}

	rdc_many_exit(krdc);

	return (NULL);
}

static void
_rdc_sync_wrthr(void *thrinfo)
{
	rdc_syncthr_t *syncinfo = (rdc_syncthr_t *)thrinfo;
	nsc_buf_t *handle = NULL;
	rdc_k_info_t *krdc = syncinfo->krdc;
	int rc;
	int tries = 0;

	DTRACE_PROBE2(rdc_sync_loop_netwrite_start, int, krdc->index,
	    nsc_buf_t *, handle);

retry:
	rc = nsc_alloc_buf(RDC_U_FD(krdc), syncinfo->offset, syncinfo->len,
	    NSC_READ | NSC_NOCACHE, &handle);

	if (!RDC_SUCCESS(rc) || krdc->remote_index < 0) {
		DTRACE_PROBE(rdc_sync_wrthr_alloc_buf_err);
		goto failed;
	}

	rdc_group_enter(krdc);
	if ((krdc->disk_status == 1) || (krdc->dcio_bitmap == NULL)) {
		rdc_group_exit(krdc);
		goto failed;
	}
	rdc_group_exit(krdc);

	if ((rc = rdc_net_write(krdc->index, krdc->remote_index, handle,
	    handle->sb_pos, handle->sb_len, RDC_NOSEQ, RDC_NOQUE, NULL)) > 0) {
		rdc_u_info_t *urdc = &rdc_u_info[krdc->index];

		/*
		 * The following is to handle
		 * the case where the secondary side
		 * has thrown our buffer handle token away in a
		 * attempt to preserve its health on restart
		 */
		if ((rc == EPROTO) && (tries < 3)) {
			(void) nsc_free_buf(handle);
			handle = NULL;
			tries++;
			delay(HZ >> 2);
			goto retry;
		}

		DTRACE_PROBE(rdc_sync_wrthr_remote_write_err);
		cmn_err(CE_WARN, "!rdc_sync_wrthr: remote write failed (%d) "
		    "0x%x", rc, rdc_get_vflags(urdc));

		goto failed;
	}
	(void) nsc_free_buf(handle);
	handle = NULL;

	return;
failed:
	(void) nsc_free_buf(handle);
	syncinfo->status->offset = syncinfo->offset;
}

/*
 * see above comments on _rdc_sync_wrthr
 */
static void
_rdc_sync_rdthr(void *thrinfo)
{
	rdc_syncthr_t *syncinfo = (rdc_syncthr_t *)thrinfo;
	nsc_buf_t *handle = NULL;
	rdc_k_info_t *krdc = syncinfo->krdc;
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];
	int rc;

	rc = nsc_alloc_buf(RDC_U_FD(krdc), syncinfo->offset, syncinfo->len,
	    NSC_WRITE | NSC_WRTHRU | NSC_NOCACHE, &handle);

	if (!RDC_SUCCESS(rc) || krdc->remote_index < 0) {
		goto failed;
	}
	rdc_group_enter(krdc);
	if ((krdc->disk_status == 1) || (krdc->dcio_bitmap == NULL)) {
		rdc_group_exit(krdc);
		goto failed;
	}
	rdc_group_exit(krdc);

	rc = rdc_net_read(krdc->index, krdc->remote_index, handle,
	    handle->sb_pos, handle->sb_len);

	if (!RDC_SUCCESS(rc)) {
		cmn_err(CE_WARN, "!rdc_sync_rdthr: remote read failed(%d)", rc);
		goto failed;
	}
	if (!IS_STATE(urdc, RDC_FULL))
		rdc_set_bitmap_many(krdc, handle->sb_pos, handle->sb_len);

	rc = nsc_write(handle, handle->sb_pos, handle->sb_len, 0);

	if (!RDC_SUCCESS(rc)) {
		rdc_many_enter(krdc);
		rdc_set_flags_log(urdc, RDC_VOL_FAILED, "nsc_write failed");
		rdc_many_exit(krdc);
		rdc_write_state(urdc);
		goto failed;
	}

	(void) nsc_free_buf(handle);
	handle = NULL;

	return;
failed:
	(void) nsc_free_buf(handle);
	syncinfo->status->offset = syncinfo->offset;
}

/*
 * _rdc_sync_wrthr
 * sync loop write thread
 * if there are avail threads, we have not
 * used up the pipe, so the sync loop will, if
 * possible use these to multithread the write/read
 */
void
_rdc_sync_thread(void *thrinfo)
{
	rdc_syncthr_t *syncinfo = (rdc_syncthr_t *)thrinfo;
	rdc_k_info_t *krdc = syncinfo->krdc;
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];
	rdc_thrsync_t *sync = &krdc->syncs;
	uint_t bitmask;
	int rc;

	rc = _rdc_rsrv_devs(krdc, RDC_RAW, RDC_INTERNAL);
	if (!RDC_SUCCESS(rc))
		goto failed;

	if (IS_STATE(urdc, RDC_SLAVE))
		_rdc_sync_rdthr(thrinfo);
	else
		_rdc_sync_wrthr(thrinfo);

	_rdc_rlse_devs(krdc, RDC_RAW);

	if (krdc->dcio_bitmap == NULL) {
#ifdef DEBUG
		cmn_err(CE_NOTE, "!_rdc_sync_wrthr: NULL bitmap");
#else
	/*EMPTY*/
#endif
	} else if (syncinfo->status->offset < 0) {

		RDC_SET_BITMASK(syncinfo->offset, syncinfo->len, &bitmask);
		RDC_CLR_BITMAP(krdc, syncinfo->offset, syncinfo->len, \
		    bitmask, RDC_BIT_FORCE);
	}

failed:
	/*
	 * done with this, get rid of it.
	 * the status is not freed, it should still be a status chain
	 * that _rdc_sync() has the head of
	 */
	kmem_free(syncinfo, sizeof (*syncinfo));

	/*
	 * decrement the global sync thread num
	 */
	mutex_enter(&sync_info.lock);
	sync_info.active_thr--;
	/* LINTED */
	RDC_AVAIL_THR_TUNE(sync_info);
	mutex_exit(&sync_info.lock);

	/*
	 * krdc specific stuff
	 */
	mutex_enter(&sync->lock);
	sync->complete++;
	cv_broadcast(&sync->cv);
	mutex_exit(&sync->lock);
}

int
_rdc_setup_syncthr(rdc_syncthr_t **synthr, nsc_off_t offset,
    nsc_size_t len, rdc_k_info_t *krdc, sync_status_t *stats)
{
	rdc_syncthr_t *tmp;
	/* alloc here, free in the sync thread */
	tmp =
	    (rdc_syncthr_t *)kmem_zalloc(sizeof (rdc_syncthr_t), KM_NOSLEEP);

	if (tmp == NULL)
		return (-1);
	tmp->offset = offset;
	tmp->len = len;
	tmp->status = stats;
	tmp->krdc = krdc;

	*synthr = tmp;
	return (0);
}

sync_status_t *
_rdc_new_sync_status()
{
	sync_status_t *s;

	s = (sync_status_t *)kmem_zalloc(sizeof (*s), KM_NOSLEEP);
	s->offset = -1;
	return (s);
}

void
_rdc_free_sync_status(sync_status_t *status)
{
	sync_status_t *s;

	while (status) {
		s = status->next;
		kmem_free(status, sizeof (*status));
		status = s;
	}
}
int
_rdc_sync_status_ok(sync_status_t *status, int *offset)
{
#ifdef DEBUG_SYNCSTATUS
	int i = 0;
#endif
	while (status) {
		if (status->offset >= 0) {
			*offset = status->offset;
			return (-1);
		}
		status = status->next;
#ifdef DEBUG_SYNCSTATUS
		i++;
#endif
	}
#ifdef DEBUGSYNCSTATUS
	cmn_err(CE_NOTE, "!rdc_sync_status_ok: checked %d statuses", i);
#endif
	return (0);
}

int mtsync = 1;
/*
 * _rdc_sync() : rdc sync loop
 *
 */
static void
_rdc_sync(rdc_k_info_t *krdc)
{
	nsc_size_t size = 0;
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];
	int rtype;
	int sts;
	int reserved = 0;
	nsc_buf_t *alloc_h = NULL;
	nsc_buf_t *handle = NULL;
	nsc_off_t mask;
	nsc_size_t maxbit;
	nsc_size_t len;
	nsc_off_t offset = 0;
	int sync_completed = 0;
	int tries = 0;
	int rc;
	int queuing = 0;
	uint_t bitmask;
	sync_status_t *ss, *sync_status = NULL;
	rdc_thrsync_t *sync = &krdc->syncs;
	rdc_syncthr_t *syncinfo;
	nsthread_t *trc = NULL;

	if (IS_STATE(urdc, RDC_QUEUING) && !IS_STATE(urdc, RDC_FULL)) {
		/* flusher is handling the sync in the update case */
		queuing = 1;
		goto sync_done;
	}

	/*
	 * Main sync/resync loop
	 */
	DTRACE_PROBE(rdc_sync_loop_start);

	rtype = RDC_RAW;
	sts = _rdc_rsrv_devs(krdc, rtype, RDC_INTERNAL);

	DTRACE_PROBE(rdc_sync_loop_rsrv);

	if (sts != 0)
		goto failed_noincr;

	reserved = 1;

	/*
	 * pre-allocate a handle if we can - speeds up the sync.
	 */

	if (rdc_prealloc_handle) {
		alloc_h = nsc_alloc_handle(RDC_U_FD(krdc), NULL, NULL, NULL);
#ifdef DEBUG
		if (!alloc_h) {
			cmn_err(CE_WARN,
			    "!rdc sync: failed to pre-alloc handle");
		}
#endif
	} else {
		alloc_h = NULL;
	}

	ASSERT(urdc->volume_size != 0);
	size = urdc->volume_size;
	mask = ~(LOG_TO_FBA_NUM(1) - 1);
	maxbit = FBA_TO_LOG_NUM(size - 1);

	/*
	 * as this while loop can also move data, it is counted as a
	 * sync loop thread
	 */
	rdc_group_enter(krdc);
	rdc_clr_flags(urdc, RDC_LOGGING);
	rdc_set_flags(urdc, RDC_SYNCING);
	krdc->group->synccount++;
	rdc_group_exit(krdc);
	mutex_enter(&sync_info.lock);
	sync_info.active_thr++;
	/* LINTED */
	RDC_AVAIL_THR_TUNE(sync_info);
	mutex_exit(&sync_info.lock);

	while (offset < size) {
		rdc_group_enter(krdc);
		ASSERT(krdc->aux_state & RDC_AUXSYNCIP);
		if (krdc->disk_status == 1 || krdc->dcio_bitmap == NULL) {
			rdc_group_exit(krdc);
			if (krdc->disk_status == 1) {
				DTRACE_PROBE(rdc_sync_loop_disk_status_err);
			} else {
				DTRACE_PROBE(rdc_sync_loop_dcio_bitmap_err);
			}
			goto failed;		/* halt sync */
		}
		rdc_group_exit(krdc);

		if (!(rdc_get_vflags(urdc) & RDC_FULL)) {
			mutex_enter(&krdc->syncbitmutex);
			krdc->syncbitpos = FBA_TO_LOG_NUM(offset);
			len = 0;

			/* skip unnecessary chunks */

			while (krdc->syncbitpos <= maxbit &&
			    !RDC_BIT_ISSET(krdc, krdc->syncbitpos)) {
				offset += LOG_TO_FBA_NUM(1);
				krdc->syncbitpos++;
			}

			/* check for boundary */

			if (offset >= size) {
				mutex_exit(&krdc->syncbitmutex);
				goto sync_done;
			}

			/* find maximal length we can transfer */

			while (krdc->syncbitpos <= maxbit &&
			    RDC_BIT_ISSET(krdc, krdc->syncbitpos)) {
				len += LOG_TO_FBA_NUM(1);
				krdc->syncbitpos++;
				/* we can only read maxfbas anyways */
				if (len >= krdc->maxfbas)
					break;
			}

			len = min(len, (size - offset));

		} else {
			len = size - offset;
		}

		/* truncate to the io provider limit */
		ASSERT(krdc->maxfbas != 0);
		len = min(len, krdc->maxfbas);

		if (len > LOG_TO_FBA_NUM(1)) {
			/*
			 * If the update is larger than a bitmap chunk,
			 * then truncate to a whole number of bitmap
			 * chunks.
			 *
			 * If the update is smaller than a bitmap
			 * chunk, this must be the last write.
			 */
			len &= mask;
		}

		if (!(rdc_get_vflags(urdc) & RDC_FULL)) {
			krdc->syncbitpos = FBA_TO_LOG_NUM(offset + len);
			mutex_exit(&krdc->syncbitmutex);
		}

		/*
		 * Find out if we can reserve a thread here ...
		 * note: skip the mutex for the first check, if the number
		 * is up there, why bother even grabbing the mutex to
		 * only realize that we can't have a thread anyways
		 */

		if (mtsync && sync_info.active_thr < RDC_MAX_SYNC_THREADS) {

			mutex_enter(&sync_info.lock);
			if (sync_info.avail_thr >= 1) {
				if (sync_status == NULL) {
					ss = sync_status =
					    _rdc_new_sync_status();
				} else {
					ss = ss->next = _rdc_new_sync_status();
				}
				if (ss == NULL) {
					mutex_exit(&sync_info.lock);
#ifdef DEBUG
					cmn_err(CE_WARN, "!rdc_sync: can't "
					    "allocate status for mt sync");
#endif
					goto retry;
				}
				/*
				 * syncinfo protected by sync_info lock but
				 * not part of the sync_info structure
				 * be careful if moving
				 */
				if (_rdc_setup_syncthr(&syncinfo,
				    offset, len, krdc, ss) < 0) {
					_rdc_free_sync_status(ss);
				}

				trc = nst_create(sync_info.rdc_syncset,
				    _rdc_sync_thread, syncinfo, NST_SLEEP);

				if (trc == NULL) {
					mutex_exit(&sync_info.lock);
#ifdef DEBUG
					cmn_err(CE_NOTE, "!rdc_sync: unable to "
					    "mt sync");
#endif
					_rdc_free_sync_status(ss);
					kmem_free(syncinfo, sizeof (*syncinfo));
					syncinfo = NULL;
					goto retry;
				} else {
					mutex_enter(&sync->lock);
					sync->threads++;
					mutex_exit(&sync->lock);
				}

				sync_info.active_thr++;
				/* LINTED */
				RDC_AVAIL_THR_TUNE(sync_info);

				mutex_exit(&sync_info.lock);
				goto threaded;
			}
			mutex_exit(&sync_info.lock);
		}
retry:
		handle = alloc_h;
		DTRACE_PROBE(rdc_sync_loop_allocbuf_start);
		if (rdc_get_vflags(urdc) & RDC_SLAVE)
			sts = nsc_alloc_buf(RDC_U_FD(krdc), offset, len,
			    NSC_WRITE | NSC_WRTHRU | NSC_NOCACHE, &handle);
		else
			sts = nsc_alloc_buf(RDC_U_FD(krdc), offset, len,
			    NSC_READ | NSC_NOCACHE, &handle);

		DTRACE_PROBE(rdc_sync_loop_allocbuf_end);
		if (sts > 0) {
			if (handle && handle != alloc_h) {
				(void) nsc_free_buf(handle);
			}

			handle = NULL;
			DTRACE_PROBE(rdc_sync_loop_allocbuf_err);
			goto failed;
		}

		if (rdc_get_vflags(urdc) & RDC_SLAVE) {
			/* overwrite buffer with remote data */
			sts = rdc_net_read(krdc->index, krdc->remote_index,
			    handle, handle->sb_pos, handle->sb_len);

			if (!RDC_SUCCESS(sts)) {
#ifdef DEBUG
				cmn_err(CE_WARN,
				    "!rdc sync: remote read failed (%d)", sts);
#endif
				DTRACE_PROBE(rdc_sync_loop_remote_read_err);
				goto failed;
			}
			if (!(rdc_get_vflags(urdc) & RDC_FULL))
				rdc_set_bitmap_many(krdc, handle->sb_pos,
				    handle->sb_len);

			/* commit locally */

			sts = nsc_write(handle, handle->sb_pos,
			    handle->sb_len, 0);

			if (!RDC_SUCCESS(sts)) {
				/* reverse sync needed already set */
				rdc_many_enter(krdc);
				rdc_set_flags_log(urdc, RDC_VOL_FAILED,
				    "write failed during sync");
				rdc_many_exit(krdc);
				rdc_write_state(urdc);
				DTRACE_PROBE(rdc_sync_loop_nsc_write_err);
				goto failed;
			}
		} else {
			/* send local data to remote */
			DTRACE_PROBE2(rdc_sync_loop_netwrite_start,
			    int, krdc->index, nsc_buf_t *, handle);

			if ((sts = rdc_net_write(krdc->index,
			    krdc->remote_index, handle, handle->sb_pos,
			    handle->sb_len, RDC_NOSEQ, RDC_NOQUE, NULL)) > 0) {

				/*
				 * The following is to handle
				 * the case where the secondary side
				 * has thrown our buffer handle token away in a
				 * attempt to preserve its health on restart
				 */
				if ((sts == EPROTO) && (tries < 3)) {
					(void) nsc_free_buf(handle);
					handle = NULL;
					tries++;
					delay(HZ >> 2);
					goto retry;
				}
#ifdef DEBUG
				cmn_err(CE_WARN,
				    "!rdc sync: remote write failed (%d) 0x%x",
				    sts, rdc_get_vflags(urdc));
#endif
				DTRACE_PROBE(rdc_sync_loop_netwrite_err);
				goto failed;
			}
			DTRACE_PROBE(rdc_sync_loop_netwrite_end);
		}

		(void) nsc_free_buf(handle);
		handle = NULL;

		if (krdc->dcio_bitmap == NULL) {
#ifdef DEBUG
			cmn_err(CE_NOTE, "!_rdc_sync: NULL bitmap");
#else
		;
		/*EMPTY*/
#endif
		} else {

			RDC_SET_BITMASK(offset, len, &bitmask);
			RDC_CLR_BITMAP(krdc, offset, len, bitmask, \
			    RDC_BIT_FORCE);
			ASSERT(!IS_ASYNC(urdc));
		}

		/*
		 * Only release/reserve if someone is waiting
		 */
		if (krdc->devices->id_release || nsc_waiting(RDC_U_FD(krdc))) {
			DTRACE_PROBE(rdc_sync_loop_rlse_start);
			if (alloc_h) {
				(void) nsc_free_handle(alloc_h);
				alloc_h = NULL;
			}

			_rdc_rlse_devs(krdc, rtype);
			reserved = 0;
			delay(2);

			rtype = RDC_RAW;
			sts = _rdc_rsrv_devs(krdc, rtype, RDC_INTERNAL);
			if (sts != 0) {
				handle = NULL;
				DTRACE_PROBE(rdc_sync_loop_rdc_rsrv_err);
				goto failed;
			}

			reserved = 1;

			if (rdc_prealloc_handle) {
				alloc_h = nsc_alloc_handle(RDC_U_FD(krdc),
				    NULL, NULL, NULL);
#ifdef DEBUG
				if (!alloc_h) {
					cmn_err(CE_WARN, "!rdc_sync: "
					    "failed to pre-alloc handle");
				}
#endif
			}
			DTRACE_PROBE(rdc_sync_loop_rlse_end);
		}
threaded:
		offset += len;
		urdc->sync_pos = offset;
	}

sync_done:
	sync_completed = 1;

failed:
	krdc->group->synccount--;
failed_noincr:
	mutex_enter(&sync->lock);
	while (sync->complete != sync->threads) {
		cv_wait(&sync->cv, &sync->lock);
	}
	sync->complete = 0;
	sync->threads = 0;
	mutex_exit(&sync->lock);

	/*
	 * if sync_completed is 0 here,
	 * we know that the main sync thread failed anyway
	 * so just free the statuses and fail
	 */
	if (sync_completed && (_rdc_sync_status_ok(sync_status, &rc) < 0)) {
		urdc->sync_pos = rc;
		sync_completed = 0; /* at least 1 thread failed */
	}

	_rdc_free_sync_status(sync_status);

	/*
	 * we didn't increment, we didn't even sync,
	 * so don't dec sync_info.active_thr
	 */
	if (!queuing) {
		mutex_enter(&sync_info.lock);
		sync_info.active_thr--;
		/* LINTED */
		RDC_AVAIL_THR_TUNE(sync_info);
		mutex_exit(&sync_info.lock);
	}

	if (handle) {
		(void) nsc_free_buf(handle);
	}

	if (alloc_h) {
		(void) nsc_free_handle(alloc_h);
	}

	if (reserved) {
		_rdc_rlse_devs(krdc, rtype);
	}

notstarted:
	rdc_group_enter(krdc);
	ASSERT(krdc->aux_state & RDC_AUXSYNCIP);
	if (IS_STATE(urdc, RDC_QUEUING))
		rdc_clr_flags(urdc, RDC_QUEUING);

	if (sync_completed) {
		(void) rdc_net_state(krdc->index, CCIO_DONE);
	} else {
		(void) rdc_net_state(krdc->index, CCIO_ENABLELOG);
	}

	rdc_clr_flags(urdc, RDC_SYNCING);
	if (rdc_get_vflags(urdc) & RDC_SLAVE) {
		rdc_many_enter(krdc);
		rdc_clr_mflags(urdc, RDC_SLAVE);
		rdc_many_exit(krdc);
	}
	if (krdc->type_flag & RDC_ASYNCMODE)
		rdc_set_flags(urdc, RDC_ASYNC);
	if (sync_completed) {
		rdc_many_enter(krdc);
		rdc_clr_mflags(urdc, RDC_RSYNC_NEEDED);
		rdc_many_exit(krdc);
	} else {
		krdc->remote_index = -1;
		rdc_set_flags_log(urdc, RDC_LOGGING, "sync failed to complete");
	}
	rdc_group_exit(krdc);
	rdc_write_state(urdc);

	mutex_enter(&net_blk_lock);
	if (sync_completed)
		krdc->sync_done = RDC_COMPLETED;
	else
		krdc->sync_done = RDC_FAILED;
	cv_broadcast(&krdc->synccv);
	mutex_exit(&net_blk_lock);

}


static int
rdc_sync(rdc_config_t *uparms, spcs_s_info_t kstatus)
{
	rdc_set_t *rdc_set = uparms->rdc_set;
	int options = uparms->options;
	int rc = 0;
	int busy = 0;
	int index;
	rdc_k_info_t *krdc;
	rdc_u_info_t *urdc;
	rdc_k_info_t *kmulti;
	rdc_u_info_t *umulti;
	rdc_group_t *group;
	rdc_srv_t *svp;
	int sm, um, md;
	int sync_completed = 0;
	int thrcount;

	mutex_enter(&rdc_conf_lock);
	index = rdc_lookup_byname(rdc_set);
	if (index >= 0)
		krdc = &rdc_k_info[index];
	if (index < 0 || (krdc->type_flag & RDC_DISABLEPEND)) {
		mutex_exit(&rdc_conf_lock);
		spcs_s_add(kstatus, RDC_EALREADY, rdc_set->primary.file,
		    rdc_set->secondary.file);
		rc = RDC_EALREADY;
		goto notstarted;
	}

	urdc = &rdc_u_info[index];
	group = krdc->group;
	set_busy(krdc);
	busy = 1;
	if ((krdc->type_flag == 0) || (krdc->type_flag & RDC_DISABLEPEND)) {
		/* A resume or enable failed  or we raced with a teardown */
		mutex_exit(&rdc_conf_lock);
		spcs_s_add(kstatus, RDC_EALREADY, rdc_set->primary.file,
		    rdc_set->secondary.file);
		rc = RDC_EALREADY;
		goto notstarted;
	}
	mutex_exit(&rdc_conf_lock);
	rdc_group_enter(krdc);

	if (!IS_STATE(urdc, RDC_LOGGING)) {
		spcs_s_add(kstatus, RDC_ESETNOTLOGGING, urdc->secondary.intf,
		    urdc->secondary.file);
		rc = RDC_ENOTLOGGING;
		goto notstarted_unlock;
	}

	if (rdc_check(krdc, rdc_set)) {
		spcs_s_add(kstatus, RDC_EALREADY, rdc_set->primary.file,
		    rdc_set->secondary.file);
		rc = RDC_EALREADY;
		goto notstarted_unlock;
	}

	if (!(rdc_get_vflags(urdc) & RDC_PRIMARY)) {
		spcs_s_add(kstatus, RDC_ENOTPRIMARY, rdc_set->primary.intf,
		    rdc_set->primary.file, rdc_set->secondary.intf,
		    rdc_set->secondary.file);
		rc = RDC_ENOTPRIMARY;
		goto notstarted_unlock;
	}

	if ((options & RDC_OPT_REVERSE) && (IS_STATE(urdc, RDC_QUEUING))) {
		/*
		 * cannot reverse sync when queuing, need to go logging first
		 */
		spcs_s_add(kstatus, RDC_EQNORSYNC, rdc_set->primary.intf,
		    rdc_set->primary.file, rdc_set->secondary.intf,
		    rdc_set->secondary.file);
		rc = RDC_EQNORSYNC;
		goto notstarted_unlock;
	}

	svp = krdc->lsrv;
	krdc->intf = rdc_add_to_if(svp, &(urdc->primary.addr),
	    &(urdc->secondary.addr), 1);

	if (!krdc->intf) {
		spcs_s_add(kstatus, RDC_EADDTOIF, urdc->primary.intf,
		    urdc->secondary.intf);
		rc = RDC_EADDTOIF;
		goto notstarted_unlock;
	}

	if (urdc->volume_size == 0) {
		/* Implies reserve failed when previous resume was done */
		rdc_get_details(krdc);
	}
	if (urdc->volume_size == 0) {
		spcs_s_add(kstatus, RDC_ENOBMAP);
		rc = RDC_ENOBMAP;
		goto notstarted_unlock;
	}

	if (krdc->dcio_bitmap == NULL) {
		if (rdc_resume_bitmap(krdc) < 0) {
			spcs_s_add(kstatus, RDC_ENOBMAP);
			rc = RDC_ENOBMAP;
			goto notstarted_unlock;
		}
	}

	if ((rdc_get_vflags(urdc) & RDC_BMP_FAILED) && (krdc->bitmapfd)) {
		if (rdc_reset_bitmap(krdc)) {
			spcs_s_add(kstatus, RDC_EBITMAP);
			rc = RDC_EBITMAP;
			goto notstarted_unlock;
		}
	}

	if (IS_MANY(krdc) || IS_MULTI(krdc)) {
		rdc_u_info_t *ubad;

		if ((ubad = rdc_allow_pri_sync(urdc, options)) != NULL) {
			spcs_s_add(kstatus, RDC_ESTATE,
			    ubad->primary.intf, ubad->primary.file,
			    ubad->secondary.intf, ubad->secondary.file);
			rc = RDC_ESTATE;
			goto notstarted_unlock;
		}
	}

	/*
	 * there is a small window where _rdc_sync is still
	 * running, but has cleared the RDC_SYNCING flag.
	 * Use aux_state which is only cleared
	 * after _rdc_sync had done its 'death' broadcast.
	 */
	if (krdc->aux_state & RDC_AUXSYNCIP) {
#ifdef DEBUG
		if (!rdc_get_vflags(urdc) & RDC_SYNCING) {
			cmn_err(CE_WARN, "!rdc_sync: "
			    "RDC_AUXSYNCIP set, SYNCING off");
		}
#endif
		spcs_s_add(kstatus, RDC_ESYNCING, rdc_set->primary.file);
		rc = RDC_ESYNCING;
		goto notstarted_unlock;
	}
	if (krdc->disk_status == 1) {
		spcs_s_add(kstatus, RDC_ESYNCING, rdc_set->primary.file);
		rc = RDC_ESYNCING;
		goto notstarted_unlock;
	}

	if ((options & RDC_OPT_FORWARD) &&
	    (rdc_get_mflags(urdc) & RDC_RSYNC_NEEDED)) {
		/* cannot forward sync if a reverse sync is needed */
		spcs_s_add(kstatus, RDC_ERSYNCNEEDED, rdc_set->primary.intf,
		    rdc_set->primary.file, rdc_set->secondary.intf,
		    rdc_set->secondary.file);
		rc = RDC_ERSYNCNEEDED;
		goto notstarted_unlock;
	}

	urdc->sync_pos = 0;

	/* Check if the rdc set is accessible on the remote node */
	if (rdc_net_getstate(krdc, &sm, &um, &md, FALSE) < 0) {
		/*
		 * Remote end may be inaccessible, or the rdc set is not
		 * enabled at the remote end.
		 */
		spcs_s_add(kstatus, RDC_ECONNOPEN, urdc->secondary.intf,
		    urdc->secondary.file);
		rc = RDC_ECONNOPEN;
		goto notstarted_unlock;
	}
	if (options & RDC_OPT_REVERSE)
		krdc->remote_index = rdc_net_state(index, CCIO_RSYNC);
	else
		krdc->remote_index = rdc_net_state(index, CCIO_SLAVE);
	if (krdc->remote_index < 0) {
		/*
		 * Remote note probably not in a valid state to be synced,
		 * as the state was fetched OK above.
		 */
		spcs_s_add(kstatus, RDC_ERSTATE, urdc->secondary.intf,
		    urdc->secondary.file, urdc->primary.intf,
		    urdc->primary.file);
		rc = RDC_ERSTATE;
		goto notstarted_unlock;
	}

	rc = check_filesize(index, kstatus);
	if (rc != 0) {
		(void) rdc_net_state(krdc->index, CCIO_ENABLELOG);
		goto notstarted_unlock;
	}

	krdc->sync_done = 0;

	mutex_enter(&krdc->bmapmutex);
	krdc->aux_state |= RDC_AUXSYNCIP;
	mutex_exit(&krdc->bmapmutex);

	if (options & RDC_OPT_REVERSE) {
		rdc_many_enter(krdc);
		rdc_set_mflags(urdc, RDC_SLAVE | RDC_RSYNC_NEEDED);
		mutex_enter(&krdc->bmapmutex);
		rdc_clr_flags(urdc, RDC_VOL_FAILED);
		mutex_exit(&krdc->bmapmutex);
		rdc_write_state(urdc);
		/* LINTED */
		if (kmulti = krdc->multi_next) {
			umulti = &rdc_u_info[kmulti->index];
			if (IS_ENABLED(umulti) && (rdc_get_vflags(umulti) &
			    (RDC_VOL_FAILED | RDC_SYNC_NEEDED))) {
				rdc_clr_flags(umulti, RDC_SYNC_NEEDED);
				rdc_clr_flags(umulti, RDC_VOL_FAILED);
				rdc_write_state(umulti);
			}
		}
		rdc_many_exit(krdc);
	} else {
		rdc_clr_flags(urdc, RDC_FCAL_FAILED);
		rdc_write_state(urdc);
	}

	if (options & RDC_OPT_UPDATE) {
		ASSERT(urdc->volume_size != 0);
		if (rdc_net_getbmap(index,
		    BMAP_LOG_BYTES(urdc->volume_size)) > 0) {
			spcs_s_add(kstatus, RDC_ENOBMAP);
			rc = RDC_ENOBMAP;

			(void) rdc_net_state(index, CCIO_ENABLELOG);

			rdc_clr_flags(urdc, RDC_SYNCING);
			if (options & RDC_OPT_REVERSE) {
				rdc_many_enter(krdc);
				rdc_clr_mflags(urdc, RDC_SLAVE);
				rdc_many_exit(krdc);
			}
			if (krdc->type_flag & RDC_ASYNCMODE)
				rdc_set_flags(urdc, RDC_ASYNC);
			krdc->remote_index = -1;
			rdc_set_flags_log(urdc, RDC_LOGGING,
			    "failed to read remote bitmap");
			rdc_write_state(urdc);
			goto failed;
		}
		rdc_clr_flags(urdc, RDC_FULL);
	} else {
		/*
		 * This is a full sync (not an update sync), mark the
		 * entire bitmap dirty
		 */
		(void) RDC_FILL_BITMAP(krdc, FALSE);

		rdc_set_flags(urdc, RDC_FULL);
	}

	rdc_group_exit(krdc);

	/*
	 * allow diskq->memq flusher to wake up
	 */
	mutex_enter(&krdc->group->ra_queue.net_qlock);
	krdc->group->ra_queue.qfflags &= ~RDC_QFILLSLEEP;
	mutex_exit(&krdc->group->ra_queue.net_qlock);

	/*
	 * if this is a full sync on a non-diskq set or
	 * a diskq set that has failed, clear the async flag
	 */
	if (krdc->type_flag & RDC_ASYNCMODE) {
		if ((!(options & RDC_OPT_UPDATE)) ||
		    (!RDC_IS_DISKQ(krdc->group)) ||
		    (!(IS_STATE(urdc, RDC_QUEUING)))) {
			/* full syncs, or core queue are synchronous */
			rdc_group_enter(krdc);
			rdc_clr_flags(urdc, RDC_ASYNC);
			rdc_group_exit(krdc);
		}

		/*
		 * if the queue failed because it was full, lets see
		 * if we can restart it. After _rdc_sync() is done
		 * the modes will switch and we will begin disk
		 * queuing again. NOTE: this should only be called
		 * once per group, as it clears state for all group
		 * members, also clears the async flag for all members
		 */
		if (IS_STATE(urdc, RDC_DISKQ_FAILED)) {
			rdc_unfail_diskq(krdc);
		} else {
		/* don't add insult to injury by flushing a dead queue */

			/*
			 * if we are updating, and a diskq and
			 * the async thread isn't active, start
			 * it up.
			 */
			if ((options & RDC_OPT_UPDATE) &&
			    (IS_STATE(urdc, RDC_QUEUING))) {
				rdc_group_enter(krdc);
				rdc_clr_flags(urdc, RDC_SYNCING);
				rdc_group_exit(krdc);
				mutex_enter(&krdc->group->ra_queue.net_qlock);
				if (krdc->group->ra_queue.qfill_sleeping ==
				    RDC_QFILL_ASLEEP)
					cv_broadcast(&group->ra_queue.qfcv);
				mutex_exit(&krdc->group->ra_queue.net_qlock);
				thrcount = urdc->asyncthr;
				while ((thrcount-- > 0) &&
				    !krdc->group->rdc_writer) {
					(void) rdc_writer(krdc->index);
				}
			}
		}
	}

	/*
	 * For a reverse sync, merge the current bitmap with all other sets
	 * that share this volume.
	 */
	if (options & RDC_OPT_REVERSE) {
retry_many:
		rdc_many_enter(krdc);
		if (IS_MANY(krdc)) {
			rdc_k_info_t *kmany;
			rdc_u_info_t *umany;

			for (kmany = krdc->many_next; kmany != krdc;
			    kmany = kmany->many_next) {
				umany = &rdc_u_info[kmany->index];
				if (!IS_ENABLED(umany))
					continue;
				ASSERT(umany->flags & RDC_PRIMARY);

				if (!mutex_tryenter(&kmany->group->lock)) {
					rdc_many_exit(krdc);
					/* May merge more than once */
					goto retry_many;
				}
				rdc_merge_bitmaps(krdc, kmany);
				mutex_exit(&kmany->group->lock);
			}
		}
		rdc_many_exit(krdc);

retry_multi:
		rdc_many_enter(krdc);
		if (IS_MULTI(krdc)) {
			rdc_k_info_t *kmulti = krdc->multi_next;
			rdc_u_info_t *umulti = &rdc_u_info[kmulti->index];

			if (IS_ENABLED(umulti)) {
				ASSERT(!(umulti->flags & RDC_PRIMARY));

				if (!mutex_tryenter(&kmulti->group->lock)) {
					rdc_many_exit(krdc);
					goto retry_multi;
				}
				rdc_merge_bitmaps(krdc, kmulti);
				mutex_exit(&kmulti->group->lock);
			}
		}
		rdc_many_exit(krdc);
	}

	rdc_group_enter(krdc);

	if (krdc->bitmap_write == 0) {
		if (rdc_write_bitmap_fill(krdc) >= 0)
			krdc->bitmap_write = -1;
	}

	if (krdc->bitmap_write > 0)
		(void) rdc_write_bitmap(krdc);

	urdc->bits_set = RDC_COUNT_BITMAP(krdc);

	rdc_group_exit(krdc);

	if (options & RDC_OPT_REVERSE) {
		(void) _rdc_sync_event_notify(RDC_SYNC_START,
		    urdc->primary.file, urdc->group_name);
	}

	/* Now set off the sync itself */

	mutex_enter(&net_blk_lock);
	if (nsc_create_process(
	    (void (*)(void *))_rdc_sync, (void *)krdc, FALSE)) {
		mutex_exit(&net_blk_lock);
		spcs_s_add(kstatus, RDC_ENOPROC);
		/*
		 * We used to just return here,
		 * but we need to clear the AUXSYNCIP bit
		 * and there is a very small chance that
		 * someone may be waiting on the disk_status flag.
		 */
		rc = RDC_ENOPROC;
		/*
		 * need the group lock held at failed.
		 */
		rdc_group_enter(krdc);
		goto failed;
	}

	mutex_enter(&rdc_conf_lock);
	wakeup_busy(krdc);
	busy = 0;
	mutex_exit(&rdc_conf_lock);

	while (krdc->sync_done == 0)
		cv_wait(&krdc->synccv, &net_blk_lock);
	mutex_exit(&net_blk_lock);

	rdc_group_enter(krdc);

	if (krdc->sync_done == RDC_FAILED) {
		char siztmp1[16];
		(void) spcs_s_inttostring(
		    urdc->sync_pos, siztmp1, sizeof (siztmp1),
		    0);
		spcs_s_add(kstatus, RDC_EFAIL, siztmp1);
		rc = RDC_EFAIL;
	} else
		sync_completed = 1;

failed:
	/*
	 * We use this flag now to make halt_sync() wait for
	 * us to terminate and let us take the group lock.
	 */
	krdc->aux_state &= ~RDC_AUXSYNCIP;
	if (krdc->disk_status == 1) {
		krdc->disk_status = 0;
		cv_broadcast(&krdc->haltcv);
	}

notstarted_unlock:
	rdc_group_exit(krdc);

	if (sync_completed && (options & RDC_OPT_REVERSE)) {
		(void) _rdc_sync_event_notify(RDC_SYNC_DONE,
		    urdc->primary.file, urdc->group_name);
	}

notstarted:
	if (busy) {
		mutex_enter(&rdc_conf_lock);
		wakeup_busy(krdc);
		mutex_exit(&rdc_conf_lock);
	}

	return (rc);
}

/* ARGSUSED */
static int
_rdc_suspend(rdc_k_info_t *krdc, rdc_set_t *rdc_set, spcs_s_info_t kstatus)
{
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];
	rdc_if_t *ip;
	int index = krdc->index;

	ASSERT(krdc->group != NULL);
	rdc_group_enter(krdc);
#ifdef DEBUG
	ASSERT(rdc_check(krdc, rdc_set) == 0);
#else
	if (rdc_check(krdc, rdc_set)) {
		rdc_group_exit(krdc);
		spcs_s_add(kstatus, RDC_EALREADY, rdc_set->primary.file,
		    rdc_set->secondary.file);
		return (RDC_EALREADY);
	}
#endif

	if (rdc_get_vflags(urdc) & RDC_PRIMARY) {
		halt_sync(krdc);
		ASSERT(IS_ENABLED(urdc));
	}

	rdc_group_exit(krdc);
	(void) rdc_unintercept(krdc);

#ifdef DEBUG
	cmn_err(CE_NOTE, "!SNDR: suspended %s %s", urdc->primary.file,
	    urdc->secondary.file);
#endif

	/* Configured but not enabled */
	ASSERT(IS_CONFIGURED(krdc) && !IS_ENABLED(urdc));


	if (IS_ASYNC(urdc) && !RDC_IS_DISKQ(krdc->group)) {
		int tries = 2; /* in case of possibly stuck flusher threads */
#ifdef DEBUG
		net_queue *qp = &krdc->group->ra_queue;
#endif
		do {
			if (!krdc->group->rdc_writer)
				(void) rdc_writer(krdc->index);

			(void) rdc_drain_queue(krdc->index);

		} while (krdc->group->rdc_writer && tries--);

		/* ok, force it to happen... */
		if (rdc_drain_queue(krdc->index) != 0) {
			do {
				mutex_enter(&krdc->group->ra_queue.net_qlock);
				krdc->group->asyncdis = 1;
				cv_broadcast(&krdc->group->asyncqcv);
				mutex_exit(&krdc->group->ra_queue.net_qlock);
				cmn_err(CE_WARN,
				    "!SNDR: async I/O pending and not flushed "
				    "for %s during suspend",
				    urdc->primary.file);
#ifdef DEBUG
				cmn_err(CE_WARN,
				    "!nitems: %" NSC_SZFMT " nblocks: %"
				    NSC_SZFMT " head: 0x%p tail: 0x%p",
				    qp->nitems, qp->blocks,
				    (void *)qp->net_qhead,
				    (void *)qp->net_qtail);
#endif
			} while (krdc->group->rdc_thrnum > 0);
		}
	}

	mutex_enter(&rdc_conf_lock);
	ip = krdc->intf;
	krdc->intf = 0;

	if (ip) {
		rdc_remove_from_if(ip);
	}

	mutex_exit(&rdc_conf_lock);

	rdc_group_enter(krdc);

	/* Configured but not enabled */
	ASSERT(IS_CONFIGURED(krdc) && !IS_ENABLED(urdc));

	rdc_group_exit(krdc);
	/* Must not hold group lock during this function */
	while (rdc_dump_alloc_bufs_cd(krdc->index) == EAGAIN)
		delay(2);
	rdc_group_enter(krdc);

	/* Don't rdc_clear_state, unlike _rdc_disable */

	rdc_free_bitmap(krdc, RDC_CMD_SUSPEND);
	rdc_close_bitmap(krdc);

	rdc_dev_close(krdc);
	rdc_close_direct(krdc);

	/* Configured but not enabled */
	ASSERT(IS_CONFIGURED(krdc) && !IS_ENABLED(urdc));

	rdc_group_exit(krdc);

	/*
	 * we should now unregister the queue, with no conflicting
	 * locks held. This is the last(only) member of the group
	 */
	if (krdc->group && RDC_IS_DISKQ(krdc->group) &&
	    krdc->group->count == 1) { /* stop protecting queue */
		rdc_unintercept_diskq(krdc->group);
	}

	mutex_enter(&rdc_conf_lock);

	/* Configured but not enabled */
	ASSERT(IS_CONFIGURED(krdc) && !IS_ENABLED(urdc));

	wait_busy(krdc);

	if (IS_MANY(krdc) || IS_MULTI(krdc))
		remove_from_many(krdc);

	remove_from_group(krdc);

	krdc->remote_index = -1;
	ASSERT(krdc->type_flag & RDC_CONFIGURED);
	ASSERT(krdc->type_flag & RDC_DISABLEPEND);
	krdc->type_flag = 0;
#ifdef	DEBUG
	if (krdc->dcio_bitmap)
		cmn_err(CE_WARN, "!_rdc_suspend: possible mem leak, "
		    "dcio_bitmap");
#endif
	krdc->dcio_bitmap = NULL;
	krdc->bitmap_ref = NULL;
	krdc->bitmap_size = 0;
	krdc->maxfbas = 0;
	krdc->bitmap_write = 0;
	krdc->disk_status = 0;
	rdc_destroy_svinfo(krdc->lsrv);
	krdc->lsrv = NULL;
	krdc->multi_next = NULL;

	rdc_u_init(urdc);

	mutex_exit(&rdc_conf_lock);
	rdc_kstat_delete(index);
	return (0);
}

static int
rdc_suspend(rdc_config_t *uparms, spcs_s_info_t kstatus)
{
	rdc_k_info_t *krdc;
	int index;
	int rc;

	mutex_enter(&rdc_conf_lock);

	index = rdc_lookup_byname(uparms->rdc_set);
	if (index >= 0)
		krdc = &rdc_k_info[index];
	if (index < 0 || (krdc->type_flag & RDC_DISABLEPEND)) {
		mutex_exit(&rdc_conf_lock);
		spcs_s_add(kstatus, RDC_EALREADY, uparms->rdc_set->primary.file,
		    uparms->rdc_set->secondary.file);
		return (RDC_EALREADY);
	}

	krdc->type_flag |= RDC_DISABLEPEND;
	wait_busy(krdc);
	if (krdc->type_flag == 0) {
		/* A resume or enable failed */
		mutex_exit(&rdc_conf_lock);
		spcs_s_add(kstatus, RDC_EALREADY, uparms->rdc_set->primary.file,
		    uparms->rdc_set->secondary.file);
		return (RDC_EALREADY);
	}
	mutex_exit(&rdc_conf_lock);

	rc = _rdc_suspend(krdc, uparms->rdc_set, kstatus);
	return (rc);
}

static int
_rdc_resume(rdc_set_t *rdc_set, int options, spcs_s_info_t kstatus)
{
	int index;
	char *rhost;
	struct netbuf *addrp;
	rdc_k_info_t *krdc;
	rdc_u_info_t *urdc;
	rdc_srv_t *svp = NULL;
	char *local_file;
	char *local_bitmap;
	int rc, rc1;
	nsc_size_t maxfbas;
	rdc_group_t *grp;

	if ((rdc_set->primary.intf[0] == 0) ||
	    (rdc_set->primary.addr.len == 0) ||
	    (rdc_set->primary.file[0] == 0) ||
	    (rdc_set->primary.bitmap[0] == 0) ||
	    (rdc_set->secondary.intf[0] == 0) ||
	    (rdc_set->secondary.addr.len == 0) ||
	    (rdc_set->secondary.file[0] == 0) ||
	    (rdc_set->secondary.bitmap[0] == 0)) {
		spcs_s_add(kstatus, RDC_EEMPTY);
		return (RDC_EEMPTY);
	}

	/* Next check there aren't any enabled rdc sets which match. */

	mutex_enter(&rdc_conf_lock);

	if (rdc_lookup_byname(rdc_set) >= 0) {
		mutex_exit(&rdc_conf_lock);
		spcs_s_add(kstatus, RDC_EENABLED, rdc_set->primary.intf,
		    rdc_set->primary.file, rdc_set->secondary.intf,
		    rdc_set->secondary.file);
		return (RDC_EENABLED);
	}

	if (rdc_lookup_many2one(rdc_set) >= 0) {
		mutex_exit(&rdc_conf_lock);
		spcs_s_add(kstatus, RDC_EMANY2ONE, rdc_set->primary.intf,
		    rdc_set->primary.file, rdc_set->secondary.intf,
		    rdc_set->secondary.file);
		return (RDC_EMANY2ONE);
	}

	if (rdc_set->netconfig->knc_proto == NULL) {
		mutex_exit(&rdc_conf_lock);
		spcs_s_add(kstatus, RDC_ENETCONFIG);
		return (RDC_ENETCONFIG);
	}

	if (rdc_set->primary.addr.len == 0) {
		mutex_exit(&rdc_conf_lock);
		spcs_s_add(kstatus, RDC_ENETBUF, rdc_set->primary.file);
		return (RDC_ENETBUF);
	}

	if (rdc_set->secondary.addr.len == 0) {
		mutex_exit(&rdc_conf_lock);
		spcs_s_add(kstatus, RDC_ENETBUF, rdc_set->secondary.file);
		return (RDC_ENETBUF);
	}

	/* Check that the local data volume isn't in use as a bitmap */
	if (options & RDC_OPT_PRIMARY)
		local_file = rdc_set->primary.file;
	else
		local_file = rdc_set->secondary.file;
	if (rdc_lookup_bitmap(local_file) >= 0) {
		mutex_exit(&rdc_conf_lock);
		spcs_s_add(kstatus, RDC_EVOLINUSE, local_file);
		return (RDC_EVOLINUSE);
	}

	/* check that the secondary data volume isn't in use */
	if (!(options & RDC_OPT_PRIMARY)) {
		local_file = rdc_set->secondary.file;
		if (rdc_lookup_secondary(local_file) >= 0) {
			mutex_exit(&rdc_conf_lock);
			spcs_s_add(kstatus, RDC_EVOLINUSE, local_file);
			return (RDC_EVOLINUSE);
		}
	}

	/* Check that the bitmap isn't in use as a data volume */
	if (options & RDC_OPT_PRIMARY)
		local_bitmap = rdc_set->primary.bitmap;
	else
		local_bitmap = rdc_set->secondary.bitmap;
	if (rdc_lookup_configured(local_bitmap) >= 0) {
		mutex_exit(&rdc_conf_lock);
		spcs_s_add(kstatus, RDC_EBMPINUSE, local_bitmap);
		return (RDC_EBMPINUSE);
	}

	/* Check that the bitmap isn't already in use as a bitmap */
	if (rdc_lookup_bitmap(local_bitmap) >= 0) {
		mutex_exit(&rdc_conf_lock);
		spcs_s_add(kstatus, RDC_EBMPINUSE, local_bitmap);
		return (RDC_EBMPINUSE);
	}

	/* Set urdc->volume_size */
	index = rdc_dev_open(rdc_set, options);
	if (index < 0) {
		mutex_exit(&rdc_conf_lock);
		if (options & RDC_OPT_PRIMARY)
			spcs_s_add(kstatus, RDC_EOPEN, rdc_set->primary.intf,
			    rdc_set->primary.file);
		else
			spcs_s_add(kstatus, RDC_EOPEN, rdc_set->secondary.intf,
			    rdc_set->secondary.file);
		return (RDC_EOPEN);
	}

	urdc = &rdc_u_info[index];
	krdc = &rdc_k_info[index];

	/* copy relevant parts of rdc_set to urdc field by field */

	(void) strncpy(urdc->primary.intf, rdc_set->primary.intf,
	    MAX_RDC_HOST_SIZE);
	(void) strncpy(urdc->secondary.intf, rdc_set->secondary.intf,
	    MAX_RDC_HOST_SIZE);

	(void) strncpy(urdc->group_name, rdc_set->group_name, NSC_MAXPATH);

	dup_rdc_netbuf(&rdc_set->primary.addr, &urdc->primary.addr);
	(void) strncpy(urdc->primary.file, rdc_set->primary.file, NSC_MAXPATH);
	(void) strncpy(urdc->primary.bitmap, rdc_set->primary.bitmap,
	    NSC_MAXPATH);

	dup_rdc_netbuf(&rdc_set->secondary.addr, &urdc->secondary.addr);
	(void) strncpy(urdc->secondary.file, rdc_set->secondary.file,
	    NSC_MAXPATH);
	(void) strncpy(urdc->secondary.bitmap, rdc_set->secondary.bitmap,
	    NSC_MAXPATH);
	(void) strncpy(urdc->disk_queue, rdc_set->disk_queue, NSC_MAXPATH);
	urdc->setid = rdc_set->setid;

	if ((options & RDC_OPT_SYNC) && urdc->disk_queue[0]) {
		mutex_exit(&rdc_conf_lock);
		rdc_dev_close(krdc);
		spcs_s_add(kstatus, RDC_EQWRONGMODE);
		return (RDC_EQWRONGMODE);
	}

	/*
	 * init flags now so that state left by failures in add_to_group()
	 * are preserved.
	 */
	rdc_init_flags(urdc);

	if ((rc1 = add_to_group(krdc, options, RDC_CMD_RESUME)) != 0) {
		if (rc1 == RDC_EQNOADD) { /* something went wrong with queue */
			rdc_fail_diskq(krdc, RDC_WAIT, RDC_NOLOG);
			/* don't return a failure here, continue with resume */

		} else { /* some other group add failure */
			mutex_exit(&rdc_conf_lock);
			rdc_dev_close(krdc);
			spcs_s_add(kstatus, RDC_EGROUP,
			    rdc_set->primary.intf, rdc_set->primary.file,
			    rdc_set->secondary.intf, rdc_set->secondary.file,
			    rdc_set->group_name);
			return (RDC_EGROUP);
		}
	}

	/*
	 * maxfbas was set in rdc_dev_open as primary's maxfbas.
	 * If diskq's maxfbas is smaller, then use diskq's.
	 */
	grp = krdc->group;
	if (grp && RDC_IS_DISKQ(grp) && (grp->diskqfd != 0)) {
		rc = _rdc_rsrv_diskq(grp);
		if (RDC_SUCCESS(rc)) {
			rc = nsc_maxfbas(grp->diskqfd, 0, &maxfbas);
			if (rc == 0) {
#ifdef DEBUG
				if (krdc->maxfbas != maxfbas)
					cmn_err(CE_NOTE,
					    "!_rdc_resume: diskq maxfbas = %"
					    NSC_SZFMT ", primary maxfbas = %"
					    NSC_SZFMT, maxfbas, krdc->maxfbas);
#endif
					krdc->maxfbas = min(krdc->maxfbas,
					    maxfbas);
			} else {
				cmn_err(CE_WARN,
				    "!_rdc_resume: diskq maxfbas failed (%d)",
				    rc);
			}
			_rdc_rlse_diskq(grp);
		} else {
			cmn_err(CE_WARN,
			    "!_rdc_resume: diskq reserve failed (%d)", rc);
		}
	}

	(void) strncpy(urdc->direct_file, rdc_set->direct_file, NSC_MAXPATH);
	if ((options & RDC_OPT_PRIMARY) && rdc_set->direct_file[0]) {
		if (rdc_open_direct(krdc) == NULL)
			rdc_set_flags(urdc, RDC_FCAL_FAILED);
	}

	krdc->many_next = krdc;

	ASSERT(krdc->type_flag == 0);
	krdc->type_flag = RDC_CONFIGURED;

	if (options & RDC_OPT_PRIMARY)
		rdc_set_flags(urdc, RDC_PRIMARY);

	if (options & RDC_OPT_ASYNC)
		krdc->type_flag |= RDC_ASYNCMODE;

	set_busy(krdc);

	urdc->syshostid = rdc_set->syshostid;

	if (add_to_many(krdc) < 0) {
		mutex_exit(&rdc_conf_lock);

		rdc_group_enter(krdc);

		spcs_s_add(kstatus, RDC_EMULTI);
		rc = RDC_EMULTI;
		goto fail;
	}

	/* Configured but not enabled */
	ASSERT(IS_CONFIGURED(krdc) && !IS_ENABLED(urdc));

	mutex_exit(&rdc_conf_lock);

	if (urdc->volume_size == 0) {
		rdc_many_enter(krdc);
		if (options & RDC_OPT_PRIMARY)
			rdc_set_mflags(urdc, RDC_RSYNC_NEEDED);
		else
			rdc_set_flags(urdc, RDC_SYNC_NEEDED);
		rdc_set_flags(urdc, RDC_VOL_FAILED);
		rdc_many_exit(krdc);
	}

	rdc_group_enter(krdc);

	/* Configured but not enabled */
	ASSERT(IS_CONFIGURED(krdc) && !IS_ENABLED(urdc));

	/*
	 * The rdc set is configured but not yet enabled. Other operations must
	 * ignore this set until it is enabled.
	 */

	urdc->sync_pos = 0;

	/* Set tunable defaults, we'll pick up tunables from the header later */

	urdc->maxqfbas = rdc_maxthres_queue;
	urdc->maxqitems = rdc_max_qitems;
	urdc->autosync = 0;
	urdc->asyncthr = rdc_asyncthr;

	urdc->netconfig = rdc_set->netconfig;

	if (options & RDC_OPT_PRIMARY) {
		rhost = rdc_set->secondary.intf;
		addrp = &rdc_set->secondary.addr;
	} else {
		rhost = rdc_set->primary.intf;
		addrp = &rdc_set->primary.addr;
	}

	if (options & RDC_OPT_ASYNC)
		rdc_set_flags(urdc, RDC_ASYNC);

	svp = rdc_create_svinfo(rhost, addrp, urdc->netconfig);
	if (svp == NULL) {
		spcs_s_add(kstatus, ENOMEM);
		rc = ENOMEM;
		goto fail;
	}

	urdc->netconfig = NULL;		/* This will be no good soon */

	/* Don't set krdc->intf here */
	rdc_kstat_create(index);

	/* if the bitmap resume isn't clean, it will clear queuing flag */

	(void) rdc_resume_bitmap(krdc);

	if (RDC_IS_DISKQ(krdc->group)) {
		disk_queue *q = &krdc->group->diskq;
		if ((rc1 == RDC_EQNOADD) ||
		    IS_QSTATE(q, RDC_QBADRESUME)) {
			rdc_clr_flags(urdc, RDC_QUEUING);
			RDC_ZERO_BITREF(krdc);
		}
	}

	if (krdc->lsrv == NULL)
		krdc->lsrv = svp;
	else {
#ifdef DEBUG
		cmn_err(CE_WARN, "!_rdc_resume: krdc->lsrv already set: %p",
		    (void *) krdc->lsrv);
#endif
		rdc_destroy_svinfo(svp);
	}
	svp = NULL;

	/* Configured but not enabled */
	ASSERT(IS_CONFIGURED(krdc) && !IS_ENABLED(urdc));

	/* And finally */

	krdc->remote_index = -1;

	/* Should we set the whole group logging? */
	rdc_set_flags(urdc, RDC_ENABLED | RDC_LOGGING);

	rdc_group_exit(krdc);

	if (rdc_intercept(krdc) != 0) {
		rdc_group_enter(krdc);
		rdc_clr_flags(urdc, RDC_ENABLED);
		if (options & RDC_OPT_PRIMARY)
			spcs_s_add(kstatus, RDC_EREGISTER, urdc->primary.file);
		else
			spcs_s_add(kstatus, RDC_EREGISTER,
			    urdc->secondary.file);
#ifdef DEBUG
		cmn_err(CE_NOTE, "!nsc_register_path failed %s",
		    urdc->primary.file);
#endif
		rc = RDC_EREGISTER;
		goto bmpfail;
	}
#ifdef DEBUG
	cmn_err(CE_NOTE, "!SNDR: resumed %s %s", urdc->primary.file,
	    urdc->secondary.file);
#endif

	rdc_write_state(urdc);

	mutex_enter(&rdc_conf_lock);
	wakeup_busy(krdc);
	mutex_exit(&rdc_conf_lock);

	return (0);

bmpfail:
	if (options & RDC_OPT_PRIMARY)
		spcs_s_add(kstatus, RDC_EBITMAP, urdc->primary.bitmap);
	else
		spcs_s_add(kstatus, RDC_EBITMAP, urdc->secondary.bitmap);
	rc = RDC_EBITMAP;
	if (rdc_get_vflags(urdc) & RDC_ENABLED) {
		rdc_group_exit(krdc);
		(void) rdc_unintercept(krdc);
		rdc_group_enter(krdc);
	}

fail:
	rdc_kstat_delete(index);
	/* Don't unset krdc->intf here, unlike _rdc_enable */

	/* Configured but not enabled */
	ASSERT(IS_CONFIGURED(krdc) && !IS_ENABLED(urdc));

	rdc_dev_close(krdc);
	rdc_close_direct(krdc);
	rdc_destroy_svinfo(svp);

	/* Configured but not enabled */
	ASSERT(IS_CONFIGURED(krdc) && !IS_ENABLED(urdc));

	rdc_group_exit(krdc);

	mutex_enter(&rdc_conf_lock);

	/* Configured but not enabled */
	ASSERT(IS_CONFIGURED(krdc) && !IS_ENABLED(urdc));

	remove_from_group(krdc);

	if (IS_MANY(krdc) || IS_MULTI(krdc))
		remove_from_many(krdc);

	rdc_u_init(urdc);

	ASSERT(krdc->type_flag & RDC_CONFIGURED);
	krdc->type_flag = 0;
	wakeup_busy(krdc);

	mutex_exit(&rdc_conf_lock);

	return (rc);
}

static int
rdc_resume(rdc_config_t *uparms, spcs_s_info_t kstatus)
{
	char itmp[10];
	int rc;

	if (!(uparms->options & RDC_OPT_SYNC) &&
	    !(uparms->options & RDC_OPT_ASYNC)) {
		(void) spcs_s_inttostring(
		    uparms->options, itmp, sizeof (itmp), 1);
		spcs_s_add(kstatus, RDC_EEINVAL, itmp);
		rc = RDC_EEINVAL;
		goto done;
	}

	if (!(uparms->options & RDC_OPT_PRIMARY) &&
	    !(uparms->options & RDC_OPT_SECONDARY)) {
		(void) spcs_s_inttostring(
		    uparms->options, itmp, sizeof (itmp), 1);
		spcs_s_add(kstatus, RDC_EEINVAL, itmp);
		rc = RDC_EEINVAL;
		goto done;
	}

	rc = _rdc_resume(uparms->rdc_set, uparms->options, kstatus);
done:
	return (rc);
}

/*
 * if rdc_group_log is called because a volume has failed,
 * we must disgard the queue to preserve write ordering.
 * later perhaps, we can keep queuing, but we would have to
 * rewrite the i/o path to acommodate that. currently, if there
 * is a volume failure, the buffers are satisfied remotely and
 * there is no way to satisfy them from the current diskq config
 * phew, if we do that.. it will be difficult
 */
int
rdc_can_queue(rdc_k_info_t *krdc)
{
	rdc_k_info_t *p;
	rdc_u_info_t *q;

	for (p = krdc->group_next; ; p = p->group_next) {
		q = &rdc_u_info[p->index];
		if (IS_STATE(q, RDC_VOL_FAILED))
			return (0);
		if (p == krdc)
			break;
	}
	return (1);
}

/*
 * wait here, until all in flight async i/o's have either
 * finished or failed. Avoid the race with r_net_state()
 * which tells remote end to log.
 */
void
rdc_inflwait(rdc_group_t *grp)
{
	int bail = RDC_CLNT_TMOUT * 2; /* to include retries */
	volatile int *inflitems;

	if (RDC_IS_DISKQ(grp))
		inflitems = (&(grp->diskq.inflitems));
	else
		inflitems = (&(grp->ra_queue.inflitems));

	while (*inflitems && (--bail > 0))
		delay(HZ);
}

void
rdc_group_log(rdc_k_info_t *krdc, int flag, char *why)
{
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];
	rdc_k_info_t *p;
	rdc_u_info_t *q;
	int do_group;
	int sm, um, md;
	disk_queue *dq;

	void (*flag_op)(rdc_u_info_t *urdc, int flag);

	ASSERT(MUTEX_HELD(&krdc->group->lock));

	if (!IS_ENABLED(urdc))
		return;

	rdc_many_enter(krdc);

	if ((flag & RDC_QUEUING) && (!IS_STATE(urdc, RDC_SYNCING)) &&
	    (rdc_can_queue(krdc))) {
		flag_op = rdc_set_flags; /* keep queuing, link error */
		flag &= ~RDC_FLUSH;
	} else {
		flag_op = rdc_clr_flags; /* stop queuing, user request */
	}

	do_group = 1;
	if (!(rdc_get_vflags(urdc) & RDC_PRIMARY))
		do_group = 0;
	else if ((urdc->group_name[0] == 0) ||
	    (rdc_get_vflags(urdc) & RDC_LOGGING) ||
	    (rdc_get_vflags(urdc) & RDC_SYNCING))
		do_group = 0;
	if (do_group) {
		for (p = krdc->group_next; p != krdc; p = p->group_next) {
			q = &rdc_u_info[p->index];
			if (!IS_ENABLED(q))
				continue;
			if ((rdc_get_vflags(q) & RDC_LOGGING) ||
			    (rdc_get_vflags(q) & RDC_SYNCING)) {
				do_group = 0;
				break;
			}
		}
	}
	if (!do_group && (flag & RDC_FORCE_GROUP))
		do_group = 1;

	rdc_many_exit(krdc);
	dq = &krdc->group->diskq;
	if (do_group) {
#ifdef DEBUG
		cmn_err(CE_NOTE, "!SNDR:Group point-in-time for grp: %s %s:%s",
		    urdc->group_name, urdc->primary.intf, urdc->secondary.intf);
#endif
		DTRACE_PROBE(rdc_diskq_group_PIT);

		/* Set group logging at the same PIT under rdc_many_lock */
		rdc_many_enter(krdc);
		rdc_set_flags_log(urdc, RDC_LOGGING, why);
		if (RDC_IS_DISKQ(krdc->group))
			flag_op(urdc, RDC_QUEUING);
		for (p = krdc->group_next; p != krdc; p = p->group_next) {
			q = &rdc_u_info[p->index];
			if (!IS_ENABLED(q))
				continue;
			rdc_set_flags_log(q, RDC_LOGGING,
			    "consistency group member following leader");
			if (RDC_IS_DISKQ(p->group))
				flag_op(q, RDC_QUEUING);
		}

		rdc_many_exit(krdc);

		/*
		 * This can cause the async threads to fail,
		 * which in turn will call rdc_group_log()
		 * again. Release the lock and re-aquire.
		 */
		rdc_group_exit(krdc);

		while (rdc_dump_alloc_bufs_cd(krdc->index) == EAGAIN)
			delay(2);
		if (!RDC_IS_DISKQ(krdc->group))
			RDC_ZERO_BITREF(krdc);

		rdc_inflwait(krdc->group);

		/*
		 * a little lazy, but neat. recall dump_alloc_bufs to
		 * ensure that the queue pointers & seq are reset properly
		 * after we have waited for inflight stuff
		 */
		while (rdc_dump_alloc_bufs_cd(krdc->index) == EAGAIN)
			delay(2);

		rdc_group_enter(krdc);
		if (RDC_IS_DISKQ(krdc->group) && (!(flag & RDC_QUEUING))) {
			/* fail or user request */
			RDC_ZERO_BITREF(krdc);
			mutex_enter(&krdc->group->diskq.disk_qlock);
			rdc_init_diskq_header(krdc->group,
			    &krdc->group->diskq.disk_hdr);
			SET_QNXTIO(dq, QHEAD(dq));
			mutex_exit(&krdc->group->diskq.disk_qlock);
		}

		if (flag & RDC_ALLREMOTE) {
			/* Tell other node to start logging */
			if (krdc->lsrv && krdc->intf && !krdc->intf->if_down)
				(void) rdc_net_state(krdc->index,
				    CCIO_ENABLELOG);
		}

		if (flag & (RDC_ALLREMOTE | RDC_OTHERREMOTE)) {
			rdc_many_enter(krdc);
			for (p = krdc->group_next; p != krdc;
			    p = p->group_next) {
				if (p->lsrv && krdc->intf &&
				    !krdc->intf->if_down) {
					(void) rdc_net_state(p->index,
					    CCIO_ENABLELOG);
				}
			}
			rdc_many_exit(krdc);
		}

		rdc_write_state(urdc);
		for (p = krdc->group_next; p != krdc; p = p->group_next) {
			q = &rdc_u_info[p->index];
			if (!IS_ENABLED(q))
				continue;
			rdc_write_state(q);
		}
	} else {
		/* No point in time is possible, just deal with single set */

		if (rdc_get_vflags(urdc) & RDC_PRIMARY) {
			halt_sync(krdc);
		} else {
			if (rdc_net_getstate(krdc, &sm, &um, &md, TRUE) < 0) {
				rdc_clr_flags(urdc, RDC_SYNCING);
				rdc_set_flags_log(urdc, RDC_LOGGING,
				    "failed to read remote state");

				rdc_write_state(urdc);
				while (rdc_dump_alloc_bufs_cd(krdc->index)
				    == EAGAIN)
					delay(2);
				if ((RDC_IS_DISKQ(krdc->group)) &&
				    (!(flag & RDC_QUEUING))) { /* fail! */
					mutex_enter(QLOCK(dq));
					rdc_init_diskq_header(krdc->group,
					    &krdc->group->diskq.disk_hdr);
					SET_QNXTIO(dq, QHEAD(dq));
					mutex_exit(QLOCK(dq));
				}

				return;
			}
		}

		if (rdc_get_vflags(urdc) & RDC_SYNCING)
			return;

		if (RDC_IS_DISKQ(krdc->group))
			flag_op(urdc, RDC_QUEUING);

		if ((RDC_IS_DISKQ(krdc->group)) &&
		    (!(flag & RDC_QUEUING))) { /* fail! */
			RDC_ZERO_BITREF(krdc);
			mutex_enter(QLOCK(dq));
			rdc_init_diskq_header(krdc->group,
			    &krdc->group->diskq.disk_hdr);
			SET_QNXTIO(dq, QHEAD(dq));
			mutex_exit(QLOCK(dq));
		}

		if (!(rdc_get_vflags(urdc) & RDC_LOGGING)) {
			rdc_set_flags_log(urdc, RDC_LOGGING, why);

			rdc_write_state(urdc);

			while (rdc_dump_alloc_bufs_cd(krdc->index) == EAGAIN)
				delay(2);
			if (!RDC_IS_DISKQ(krdc->group))
				RDC_ZERO_BITREF(krdc);

			rdc_inflwait(krdc->group);
			/*
			 * a little lazy, but neat. recall dump_alloc_bufs to
			 * ensure that the queue pointers & seq are reset
			 * properly after we have waited for inflight stuff
			 */
			while (rdc_dump_alloc_bufs_cd(krdc->index) == EAGAIN)
				delay(2);

			if (flag & RDC_ALLREMOTE) {
				/* Tell other node to start logging */
				if (krdc->lsrv && krdc->intf &&
				    !krdc->intf->if_down) {
					(void) rdc_net_state(krdc->index,
					    CCIO_ENABLELOG);
				}
			}
		}
	}
	/*
	 * just in case any threads were in flight during log cleanup
	 */
	if (RDC_IS_DISKQ(krdc->group)) {
		mutex_enter(QLOCK(dq));
		cv_broadcast(&dq->qfullcv);
		mutex_exit(QLOCK(dq));
	}
}

static int
_rdc_log(rdc_k_info_t *krdc, rdc_set_t *rdc_set, spcs_s_info_t kstatus)
{
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];
	rdc_srv_t *svp;

	rdc_group_enter(krdc);
	if (rdc_check(krdc, rdc_set)) {
		rdc_group_exit(krdc);
		spcs_s_add(kstatus, RDC_EALREADY, rdc_set->primary.file,
		    rdc_set->secondary.file);
		return (RDC_EALREADY);
	}

	svp = krdc->lsrv;
	if (rdc_get_vflags(urdc) & RDC_PRIMARY)
		krdc->intf = rdc_add_to_if(svp, &(urdc->primary.addr),
		    &(urdc->secondary.addr), 1);
	else
		krdc->intf = rdc_add_to_if(svp, &(urdc->secondary.addr),
		    &(urdc->primary.addr), 0);

	if (!krdc->intf) {
		rdc_group_exit(krdc);
		spcs_s_add(kstatus, RDC_EADDTOIF, urdc->primary.intf,
		    urdc->secondary.intf);
		return (RDC_EADDTOIF);
	}

	rdc_group_log(krdc, RDC_FLUSH | RDC_ALLREMOTE, NULL);

	if (rdc_get_vflags(urdc) & RDC_SYNCING) {
		rdc_group_exit(krdc);
		spcs_s_add(kstatus, RDC_ESYNCING, urdc->primary.file);
		return (RDC_ESYNCING);
	}

	rdc_group_exit(krdc);

	return (0);
}

static int
rdc_log(rdc_config_t *uparms, spcs_s_info_t kstatus)
{
	rdc_k_info_t *krdc;
	int rc = 0;
	int index;

	mutex_enter(&rdc_conf_lock);
	index = rdc_lookup_byname(uparms->rdc_set);
	if (index >= 0)
		krdc = &rdc_k_info[index];
	if (index < 0 || (krdc->type_flag & RDC_DISABLEPEND)) {
		mutex_exit(&rdc_conf_lock);
		spcs_s_add(kstatus, RDC_EALREADY, uparms->rdc_set->primary.file,
		    uparms->rdc_set->secondary.file);
		return (RDC_EALREADY);
	}

	set_busy(krdc);
	if (krdc->type_flag == 0) {
		/* A resume or enable failed */
		wakeup_busy(krdc);
		mutex_exit(&rdc_conf_lock);
		spcs_s_add(kstatus, RDC_EALREADY, uparms->rdc_set->primary.file,
		    uparms->rdc_set->secondary.file);
		return (RDC_EALREADY);
	}
	mutex_exit(&rdc_conf_lock);

	rc = _rdc_log(krdc, uparms->rdc_set, kstatus);

	mutex_enter(&rdc_conf_lock);
	wakeup_busy(krdc);
	mutex_exit(&rdc_conf_lock);

	return (rc);
}


static int
rdc_wait(rdc_config_t *uparms, spcs_s_info_t kstatus)
{
	rdc_k_info_t *krdc;
	rdc_u_info_t *urdc;
	int index;
	int need_check = 0;

	mutex_enter(&rdc_conf_lock);
	index = rdc_lookup_byname(uparms->rdc_set);
	if (index >= 0)
		krdc = &rdc_k_info[index];
	if (index < 0 || (krdc->type_flag & RDC_DISABLEPEND)) {
		mutex_exit(&rdc_conf_lock);
		spcs_s_add(kstatus, RDC_EALREADY, uparms->rdc_set->primary.file,
		    uparms->rdc_set->secondary.file);
		return (RDC_EALREADY);
	}

	urdc = &rdc_u_info[index];
	if (!(rdc_get_vflags(urdc) & RDC_PRIMARY)) {
		mutex_exit(&rdc_conf_lock);
		return (0);
	}

	set_busy(krdc);
	if (krdc->type_flag == 0) {
		/* A resume or enable failed */
		wakeup_busy(krdc);
		mutex_exit(&rdc_conf_lock);
		spcs_s_add(kstatus, RDC_EALREADY, uparms->rdc_set->primary.file,
		    uparms->rdc_set->secondary.file);
		return (RDC_EALREADY);
	}
	mutex_exit(&rdc_conf_lock);

	rdc_group_enter(krdc);
	if (rdc_check(krdc, uparms->rdc_set)) {
		rdc_group_exit(krdc);
		mutex_enter(&rdc_conf_lock);
		wakeup_busy(krdc);
		mutex_exit(&rdc_conf_lock);
		spcs_s_add(kstatus, RDC_EALREADY, uparms->rdc_set->primary.file,
		    uparms->rdc_set->secondary.file);
		return (RDC_EALREADY);
	}

	if ((rdc_get_vflags(urdc) & (RDC_SYNCING | RDC_PRIMARY)) !=
	    (RDC_SYNCING | RDC_PRIMARY)) {
		rdc_group_exit(krdc);
		mutex_enter(&rdc_conf_lock);
		wakeup_busy(krdc);
		mutex_exit(&rdc_conf_lock);
		return (0);
	}
	if (rdc_get_vflags(urdc) & RDC_SYNCING) {
		need_check = 1;
	}
	rdc_group_exit(krdc);

	mutex_enter(&net_blk_lock);

	mutex_enter(&rdc_conf_lock);
	wakeup_busy(krdc);
	mutex_exit(&rdc_conf_lock);

	(void) cv_wait_sig(&krdc->synccv, &net_blk_lock);

	mutex_exit(&net_blk_lock);
	if (need_check) {
		if (krdc->sync_done == RDC_COMPLETED) {
			return (0);
		} else if (krdc->sync_done == RDC_FAILED) {
			return (EIO);
		}
	}
	return (0);
}


static int
rdc_health(rdc_config_t *uparms, spcs_s_info_t kstatus, int *rvp)
{
	rdc_k_info_t *krdc;
	rdc_u_info_t *urdc;
	int rc = 0;
	int index;

	mutex_enter(&rdc_conf_lock);
	index = rdc_lookup_byname(uparms->rdc_set);
	if (index >= 0)
		krdc = &rdc_k_info[index];
	if (index < 0 || (krdc->type_flag & RDC_DISABLEPEND)) {
		mutex_exit(&rdc_conf_lock);
		spcs_s_add(kstatus, RDC_EALREADY, uparms->rdc_set->primary.file,
		    uparms->rdc_set->secondary.file);
		return (RDC_EALREADY);
	}

	set_busy(krdc);
	if (krdc->type_flag == 0) {
		/* A resume or enable failed */
		wakeup_busy(krdc);
		mutex_exit(&rdc_conf_lock);
		spcs_s_add(kstatus, RDC_EALREADY, uparms->rdc_set->primary.file,
		    uparms->rdc_set->secondary.file);
		return (RDC_EALREADY);
	}

	mutex_exit(&rdc_conf_lock);

	rdc_group_enter(krdc);
	if (rdc_check(krdc, uparms->rdc_set)) {
		rdc_group_exit(krdc);
		spcs_s_add(kstatus, RDC_EALREADY, uparms->rdc_set->primary.file,
		    uparms->rdc_set->secondary.file);
		rc = RDC_EALREADY;
		goto done;
	}

	urdc = &rdc_u_info[index];
	if (rdc_isactive_if(&(urdc->primary.addr), &(urdc->secondary.addr)))
		*rvp = RDC_ACTIVE;
	else
		*rvp = RDC_INACTIVE;

	rdc_group_exit(krdc);

done:
	mutex_enter(&rdc_conf_lock);
	wakeup_busy(krdc);
	mutex_exit(&rdc_conf_lock);

	return (rc);
}


static int
rdc_reconfig(rdc_config_t *uparms, spcs_s_info_t kstatus)
{
	rdc_k_info_t *krdc;
	rdc_u_info_t *urdc;
	int rc = -2;
	int index;

	mutex_enter(&rdc_conf_lock);
	index = rdc_lookup_byname(uparms->rdc_set);
	if (index >= 0)
		krdc = &rdc_k_info[index];
	if (index < 0 || (krdc->type_flag & RDC_DISABLEPEND)) {
		mutex_exit(&rdc_conf_lock);
		spcs_s_add(kstatus, RDC_EALREADY, uparms->rdc_set->primary.file,
		    uparms->rdc_set->secondary.file);
		return (RDC_EALREADY);
	}

	urdc = &rdc_u_info[index];
	set_busy(krdc);
	if (krdc->type_flag == 0) {
		/* A resume or enable failed */
		wakeup_busy(krdc);
		mutex_exit(&rdc_conf_lock);
		spcs_s_add(kstatus, RDC_EALREADY, uparms->rdc_set->primary.file,
		    uparms->rdc_set->secondary.file);
		return (RDC_EALREADY);
	}

	mutex_exit(&rdc_conf_lock);

	rdc_group_enter(krdc);
	if (rdc_check(krdc, uparms->rdc_set)) {
		rdc_group_exit(krdc);
		spcs_s_add(kstatus, RDC_EALREADY, uparms->rdc_set->primary.file,
		    uparms->rdc_set->secondary.file);
		rc = RDC_EALREADY;
		goto done;
	}
	if ((rdc_get_vflags(urdc) & RDC_BMP_FAILED) && (krdc->bitmapfd))
		(void) rdc_reset_bitmap(krdc);

	/* Move to a new bitmap if necessary */
	if (strncmp(urdc->primary.bitmap, uparms->rdc_set->primary.bitmap,
	    NSC_MAXPATH) != 0) {
		if (rdc_get_vflags(urdc) & RDC_PRIMARY) {
			rc = rdc_move_bitmap(krdc,
			    uparms->rdc_set->primary.bitmap);
		} else {
			(void) strncpy(urdc->primary.bitmap,
			    uparms->rdc_set->primary.bitmap, NSC_MAXPATH);
			/* simulate a succesful rdc_move_bitmap */
			rc = 0;
		}
	}
	if (strncmp(urdc->secondary.bitmap, uparms->rdc_set->secondary.bitmap,
	    NSC_MAXPATH) != 0) {
		if (rdc_get_vflags(urdc) & RDC_PRIMARY) {
			(void) strncpy(urdc->secondary.bitmap,
			    uparms->rdc_set->secondary.bitmap, NSC_MAXPATH);
			/* simulate a succesful rdc_move_bitmap */
			rc = 0;
		} else {
			rc = rdc_move_bitmap(krdc,
			    uparms->rdc_set->secondary.bitmap);
		}
	}
	if (rc == -1) {
		rdc_group_exit(krdc);
		spcs_s_add(kstatus, RDC_EBMPRECONFIG,
		    uparms->rdc_set->secondary.intf,
		    uparms->rdc_set->secondary.file);
		rc = RDC_EBMPRECONFIG;
		goto done;
	}

	/*
	 * At this point we fail any other type of reconfig
	 * if not in logging mode and we did not do a bitmap reconfig
	 */

	if (!(rdc_get_vflags(urdc) & RDC_LOGGING) && rc == -2) {
		/* no other changes possible unless logging */
		rdc_group_exit(krdc);
		spcs_s_add(kstatus, RDC_ENOTLOGGING,
		    uparms->rdc_set->primary.intf,
		    uparms->rdc_set->primary.file,
		    uparms->rdc_set->secondary.intf,
		    uparms->rdc_set->secondary.file);
		rc = RDC_ENOTLOGGING;
		goto done;
	}
	rc = 0;
	/* Change direct file if necessary */
	if ((rdc_get_vflags(urdc) & RDC_PRIMARY) &&
	    strncmp(urdc->direct_file, uparms->rdc_set->direct_file,
	    NSC_MAXPATH)) {
		if (!(rdc_get_vflags(urdc) & RDC_LOGGING)) {
			rdc_group_exit(krdc);
			goto notlogging;
		}
		rdc_close_direct(krdc);
		(void) strncpy(urdc->direct_file, uparms->rdc_set->direct_file,
		    NSC_MAXPATH);

		if (urdc->direct_file[0]) {
			if (rdc_open_direct(krdc) == NULL)
				rdc_set_flags(urdc, RDC_FCAL_FAILED);
			else
				rdc_clr_flags(urdc, RDC_FCAL_FAILED);
		}
	}

	rdc_group_exit(krdc);

	/* Change group if necessary */
	if (strncmp(urdc->group_name, uparms->rdc_set->group_name,
	    NSC_MAXPATH) != 0) {
		char orig_group[NSC_MAXPATH];
		if (!(rdc_get_vflags(urdc) & RDC_LOGGING))
			goto notlogging;
		mutex_enter(&rdc_conf_lock);

		(void) strncpy(orig_group, urdc->group_name, NSC_MAXPATH);
		(void) strncpy(urdc->group_name, uparms->rdc_set->group_name,
		    NSC_MAXPATH);

		rc = change_group(krdc, uparms->options);
		if (rc == RDC_EQNOADD) {
			mutex_exit(&rdc_conf_lock);
			spcs_s_add(kstatus, RDC_EQNOADD,
			    uparms->rdc_set->disk_queue);
			goto done;
		} else if (rc < 0) {
			(void) strncpy(urdc->group_name, orig_group,
			    NSC_MAXPATH);
			mutex_exit(&rdc_conf_lock);
			spcs_s_add(kstatus, RDC_EGROUP,
			    urdc->primary.intf, urdc->primary.file,
			    urdc->secondary.intf, urdc->secondary.file,
			    uparms->rdc_set->group_name);
			rc = RDC_EGROUP;
			goto done;
		}

		mutex_exit(&rdc_conf_lock);

		if (rc >= 0) {
			if (!(rdc_get_vflags(urdc) & RDC_LOGGING))
				goto notlogging;
			if (uparms->options & RDC_OPT_ASYNC) {
				mutex_enter(&rdc_conf_lock);
				krdc->type_flag |= RDC_ASYNCMODE;
				mutex_exit(&rdc_conf_lock);
				if (uparms->options & RDC_OPT_PRIMARY)
					krdc->bitmap_ref =
					    (uchar_t *)kmem_zalloc(
					    (krdc->bitmap_size * BITS_IN_BYTE *
					    BMAP_REF_PREF_SIZE), KM_SLEEP);
				rdc_group_enter(krdc);
				rdc_set_flags(urdc, RDC_ASYNC);
				rdc_group_exit(krdc);
			} else {
				mutex_enter(&rdc_conf_lock);
				krdc->type_flag &= ~RDC_ASYNCMODE;
				mutex_exit(&rdc_conf_lock);
				rdc_group_enter(krdc);
				rdc_clr_flags(urdc, RDC_ASYNC);
				rdc_group_exit(krdc);
				if (krdc->bitmap_ref) {
					kmem_free(krdc->bitmap_ref,
					    (krdc->bitmap_size * BITS_IN_BYTE *
					    BMAP_REF_PREF_SIZE));
					krdc->bitmap_ref = NULL;
				}
			}
		}
	} else {
		if ((((uparms->options & RDC_OPT_ASYNC) == 0) &&
		    ((krdc->type_flag & RDC_ASYNCMODE) != 0)) ||
		    (((uparms->options & RDC_OPT_ASYNC) != 0) &&
		    ((krdc->type_flag & RDC_ASYNCMODE) == 0))) {
			if (!(rdc_get_vflags(urdc) & RDC_LOGGING))
				goto notlogging;

			if (krdc->group->count > 1) {
				spcs_s_add(kstatus, RDC_EGROUPMODE);
				rc = RDC_EGROUPMODE;
				goto done;
			}
		}

		/* Switch sync/async if necessary */
		if (krdc->group->count == 1) {
			/* Only member of group. Can change sync/async */
			if (((uparms->options & RDC_OPT_ASYNC) == 0) &&
			    ((krdc->type_flag & RDC_ASYNCMODE) != 0)) {
				if (!(rdc_get_vflags(urdc) & RDC_LOGGING))
					goto notlogging;
				/* switch to sync */
				mutex_enter(&rdc_conf_lock);
				krdc->type_flag &= ~RDC_ASYNCMODE;
				if (RDC_IS_DISKQ(krdc->group)) {
					krdc->group->flags &= ~RDC_DISKQUE;
					krdc->group->flags |= RDC_MEMQUE;
					rdc_unintercept_diskq(krdc->group);
					mutex_enter(&krdc->group->diskqmutex);
					rdc_close_diskq(krdc->group);
					mutex_exit(&krdc->group->diskqmutex);
					bzero(&urdc->disk_queue,
					    sizeof (urdc->disk_queue));
				}
				mutex_exit(&rdc_conf_lock);
				rdc_group_enter(krdc);
				rdc_clr_flags(urdc, RDC_ASYNC);
				rdc_group_exit(krdc);
				if (krdc->bitmap_ref) {
					kmem_free(krdc->bitmap_ref,
					    (krdc->bitmap_size * BITS_IN_BYTE *
					    BMAP_REF_PREF_SIZE));
					krdc->bitmap_ref = NULL;
				}
			} else if (((uparms->options & RDC_OPT_ASYNC) != 0) &&
			    ((krdc->type_flag & RDC_ASYNCMODE) == 0)) {
				if (!(rdc_get_vflags(urdc) & RDC_LOGGING))
					goto notlogging;
				/* switch to async */
				mutex_enter(&rdc_conf_lock);
				krdc->type_flag |= RDC_ASYNCMODE;
				mutex_exit(&rdc_conf_lock);
				if (uparms->options & RDC_OPT_PRIMARY)
					krdc->bitmap_ref =
					    (uchar_t *)kmem_zalloc(
					    (krdc->bitmap_size * BITS_IN_BYTE *
					    BMAP_REF_PREF_SIZE), KM_SLEEP);
				rdc_group_enter(krdc);
				rdc_set_flags(urdc, RDC_ASYNC);
				rdc_group_exit(krdc);
			}
		}
	}
	/* Reverse concept of primary and secondary */
	if ((uparms->options & RDC_OPT_REVERSE_ROLE) != 0) {
		rdc_set_t rdc_set;
		struct netbuf paddr, saddr;

		mutex_enter(&rdc_conf_lock);

		/*
		 * Disallow role reversal for advanced configurations
		 */

		if (IS_MANY(krdc) || IS_MULTI(krdc)) {
			mutex_exit(&rdc_conf_lock);
			spcs_s_add(kstatus, RDC_EMASTER, urdc->primary.intf,
			    urdc->primary.file, urdc->secondary.intf,
			    urdc->secondary.file);
			return (RDC_EMASTER);
		}
		bzero((void *) &rdc_set, sizeof (rdc_set_t));
		dup_rdc_netbuf(&urdc->primary.addr, &saddr);
		dup_rdc_netbuf(&urdc->secondary.addr, &paddr);
		free_rdc_netbuf(&urdc->primary.addr);
		free_rdc_netbuf(&urdc->secondary.addr);
		dup_rdc_netbuf(&saddr, &urdc->secondary.addr);
		dup_rdc_netbuf(&paddr, &urdc->primary.addr);
		free_rdc_netbuf(&paddr);
		free_rdc_netbuf(&saddr);
		/* copy primary parts of urdc to rdc_set field by field */
		(void) strncpy(rdc_set.primary.intf, urdc->primary.intf,
		    MAX_RDC_HOST_SIZE);
		(void) strncpy(rdc_set.primary.file, urdc->primary.file,
		    NSC_MAXPATH);
		(void) strncpy(rdc_set.primary.bitmap, urdc->primary.bitmap,
		    NSC_MAXPATH);

		/* Now overwrite urdc primary */
		(void) strncpy(urdc->primary.intf, urdc->secondary.intf,
		    MAX_RDC_HOST_SIZE);
		(void) strncpy(urdc->primary.file, urdc->secondary.file,
		    NSC_MAXPATH);
		(void) strncpy(urdc->primary.bitmap, urdc->secondary.bitmap,
		    NSC_MAXPATH);

		/* Now ovwewrite urdc secondary */
		(void) strncpy(urdc->secondary.intf, rdc_set.primary.intf,
		    MAX_RDC_HOST_SIZE);
		(void) strncpy(urdc->secondary.file, rdc_set.primary.file,
		    NSC_MAXPATH);
		(void) strncpy(urdc->secondary.bitmap, rdc_set.primary.bitmap,
		    NSC_MAXPATH);

		if (rdc_get_vflags(urdc) & RDC_PRIMARY) {
			rdc_clr_flags(urdc, RDC_PRIMARY);
			if (krdc->intf) {
				krdc->intf->issecondary = 1;
				krdc->intf->isprimary = 0;
				krdc->intf->if_down = 1;
			}
		} else {
			rdc_set_flags(urdc, RDC_PRIMARY);
			if (krdc->intf) {
				krdc->intf->issecondary = 0;
				krdc->intf->isprimary = 1;
				krdc->intf->if_down = 1;
			}
		}

		if ((rdc_get_vflags(urdc) & RDC_PRIMARY) &&
		    ((krdc->type_flag & RDC_ASYNCMODE) != 0)) {
			if (!krdc->bitmap_ref)
				krdc->bitmap_ref =
				    (uchar_t *)kmem_zalloc((krdc->bitmap_size *
				    BITS_IN_BYTE * BMAP_REF_PREF_SIZE),
				    KM_SLEEP);
			if (krdc->bitmap_ref == NULL) {
				cmn_err(CE_WARN,
				    "!rdc_reconfig: bitmap_ref alloc %"
				    NSC_SZFMT " failed",
				    krdc->bitmap_size * BITS_IN_BYTE *
				    BMAP_REF_PREF_SIZE);
				mutex_exit(&rdc_conf_lock);
				return (-1);
			}
		}

		if ((rdc_get_vflags(urdc) & RDC_PRIMARY) &&
		    (rdc_get_vflags(urdc) & RDC_SYNC_NEEDED)) {
			/* Primary, so reverse sync needed */
			rdc_many_enter(krdc);
			rdc_clr_flags(urdc, RDC_SYNC_NEEDED);
			rdc_set_mflags(urdc, RDC_RSYNC_NEEDED);
			rdc_many_exit(krdc);
		} else if (rdc_get_vflags(urdc) & RDC_RSYNC_NEEDED) {
			/* Secondary, so forward sync needed */
			rdc_many_enter(krdc);
			rdc_clr_flags(urdc, RDC_RSYNC_NEEDED);
			rdc_set_flags(urdc, RDC_SYNC_NEEDED);
			rdc_many_exit(krdc);
		}

		/*
		 * rewrite bitmap header
		 */
		rdc_write_state(urdc);
		mutex_exit(&rdc_conf_lock);
	}

done:
	mutex_enter(&rdc_conf_lock);
	wakeup_busy(krdc);
	mutex_exit(&rdc_conf_lock);

	return (rc);

notlogging:
	/* no other changes possible unless logging */
	mutex_enter(&rdc_conf_lock);
	wakeup_busy(krdc);
	mutex_exit(&rdc_conf_lock);
	spcs_s_add(kstatus, RDC_ENOTLOGGING, urdc->primary.intf,
	    urdc->primary.file, urdc->secondary.intf,
	    urdc->secondary.file);
	return (RDC_ENOTLOGGING);
}

static int
rdc_reset(rdc_config_t *uparms, spcs_s_info_t kstatus)
{
	rdc_k_info_t *krdc;
	rdc_u_info_t *urdc;
	int rc = 0;
	int index;
	int cleared_error = 0;

	mutex_enter(&rdc_conf_lock);
	index = rdc_lookup_byname(uparms->rdc_set);
	if (index >= 0)
		krdc = &rdc_k_info[index];
	if (index < 0 || (krdc->type_flag & RDC_DISABLEPEND)) {
		mutex_exit(&rdc_conf_lock);
		spcs_s_add(kstatus, RDC_EALREADY, uparms->rdc_set->primary.file,
		    uparms->rdc_set->secondary.file);
		return (RDC_EALREADY);
	}

	urdc = &rdc_u_info[index];
	set_busy(krdc);
	if (krdc->type_flag == 0) {
		/* A resume or enable failed */
		wakeup_busy(krdc);
		mutex_exit(&rdc_conf_lock);
		spcs_s_add(kstatus, RDC_EALREADY, uparms->rdc_set->primary.file,
		    uparms->rdc_set->secondary.file);
		return (RDC_EALREADY);
	}

	mutex_exit(&rdc_conf_lock);

	rdc_group_enter(krdc);
	if (rdc_check(krdc, uparms->rdc_set)) {
		spcs_s_add(kstatus, RDC_EALREADY, uparms->rdc_set->primary.file,
		    uparms->rdc_set->secondary.file);
		rc = RDC_EALREADY;
		goto done;
	}

	if ((rdc_get_vflags(urdc) & RDC_BMP_FAILED) && (krdc->bitmapfd)) {
		if (rdc_reset_bitmap(krdc) == 0)
			cleared_error++;
	}

	/* Fix direct file if necessary */
	if ((rdc_get_vflags(urdc) & RDC_PRIMARY) && urdc->direct_file[0]) {
		if (rdc_open_direct(krdc) == NULL)
			rdc_set_flags(urdc, RDC_FCAL_FAILED);
		else {
			rdc_clr_flags(urdc, RDC_FCAL_FAILED);
			cleared_error++;
		}
	}

	if ((rdc_get_vflags(urdc) & RDC_VOL_FAILED)) {
		rdc_many_enter(krdc);
		rdc_clr_flags(urdc, RDC_VOL_FAILED);
		cleared_error++;
		rdc_many_exit(krdc);
	}

	if (cleared_error) {
		/* cleared an error so we should be in logging mode */
		rdc_set_flags_log(urdc, RDC_LOGGING, "set reset");
	}
	rdc_group_exit(krdc);

	if ((rdc_get_vflags(urdc) & RDC_DISKQ_FAILED))
		rdc_unfail_diskq(krdc);

done:
	mutex_enter(&rdc_conf_lock);
	wakeup_busy(krdc);
	mutex_exit(&rdc_conf_lock);

	return (rc);
}


static int
rdc_tunable(rdc_config_t *uparms, spcs_s_info_t kstatus)
{
	rdc_k_info_t *krdc;
	rdc_u_info_t *urdc;
	rdc_k_info_t *p;
	rdc_u_info_t *q;
	int rc = 0;
	int index;

	mutex_enter(&rdc_conf_lock);
	index = rdc_lookup_byname(uparms->rdc_set);
	if (index >= 0)
		krdc = &rdc_k_info[index];
	if (index < 0 || (krdc->type_flag & RDC_DISABLEPEND)) {
		mutex_exit(&rdc_conf_lock);
		spcs_s_add(kstatus, RDC_EALREADY, uparms->rdc_set->primary.file,
		    uparms->rdc_set->secondary.file);
		return (RDC_EALREADY);
	}

	urdc = &rdc_u_info[index];
	set_busy(krdc);
	if (krdc->type_flag == 0) {
		/* A resume or enable failed */
		wakeup_busy(krdc);
		mutex_exit(&rdc_conf_lock);
		spcs_s_add(kstatus, RDC_EALREADY, uparms->rdc_set->primary.file,
		    uparms->rdc_set->secondary.file);
		return (RDC_EALREADY);
	}

	mutex_exit(&rdc_conf_lock);

	rdc_group_enter(krdc);
	if (rdc_check(krdc, uparms->rdc_set)) {
		spcs_s_add(kstatus, RDC_EALREADY, uparms->rdc_set->primary.file,
		    uparms->rdc_set->secondary.file);
		rc = RDC_EALREADY;
		goto done;
	}

	if (uparms->rdc_set->maxqfbas > 0) {
		urdc->maxqfbas = uparms->rdc_set->maxqfbas;
		rdc_write_state(urdc);
		for (p = krdc->group_next; p != krdc; p = p->group_next) {
			q = &rdc_u_info[p->index];
			q->maxqfbas = urdc->maxqfbas;
			rdc_write_state(q);
		}
	}

	if (uparms->rdc_set->maxqitems > 0) {
		urdc->maxqitems = uparms->rdc_set->maxqitems;
		rdc_write_state(urdc);
		for (p = krdc->group_next; p != krdc; p = p->group_next) {
			q = &rdc_u_info[p->index];
			q->maxqitems = urdc->maxqitems;
			rdc_write_state(q);
		}
	}

	if (uparms->options & RDC_OPT_SET_QNOBLOCK) {
		disk_queue *que;

		if (!RDC_IS_DISKQ(krdc->group)) {
			spcs_s_add(kstatus, RDC_EQNOQUEUE, urdc->primary.intf,
			    urdc->primary.file, urdc->secondary.intf,
			    urdc->secondary.file);
			rc = RDC_EQNOQUEUE;
			goto done;
		}

		que = &krdc->group->diskq;
		mutex_enter(QLOCK(que));
		SET_QSTATE(que, RDC_QNOBLOCK);
		/* queue will fail if this fails */
		(void) rdc_stamp_diskq(krdc, 0, RDC_GROUP_LOCKED);
		mutex_exit(QLOCK(que));

	}

	if (uparms->options & RDC_OPT_CLR_QNOBLOCK) {
		disk_queue *que;

		if (!RDC_IS_DISKQ(krdc->group)) {
			spcs_s_add(kstatus, RDC_EQNOQUEUE, urdc->primary.intf,
			    urdc->primary.file, urdc->secondary.intf,
			    urdc->secondary.file);
			rc = RDC_EQNOQUEUE;
			goto done;
		}
		que = &krdc->group->diskq;
		mutex_enter(QLOCK(que));
		CLR_QSTATE(que, RDC_QNOBLOCK);
		/* queue will fail if this fails */
		(void) rdc_stamp_diskq(krdc, 0, RDC_GROUP_LOCKED);
		mutex_exit(QLOCK(que));

	}
	if (uparms->rdc_set->asyncthr > 0) {
		urdc->asyncthr = uparms->rdc_set->asyncthr;
		rdc_write_state(urdc);
		for (p = krdc->group_next; p != krdc; p = p->group_next) {
			q = &rdc_u_info[p->index];
			q->asyncthr = urdc->asyncthr;
			rdc_write_state(q);
		}
	}

	if (uparms->rdc_set->autosync >= 0) {
		if (uparms->rdc_set->autosync == 0)
			urdc->autosync = 0;
		else
			urdc->autosync = 1;

		rdc_write_state(urdc);

		/* Changed autosync, so update rest of the group */

		for (p = krdc->group_next; p != krdc; p = p->group_next) {
			q = &rdc_u_info[p->index];
			q->autosync = urdc->autosync;
			rdc_write_state(q);
		}
	}

done:
	rdc_group_exit(krdc);

	mutex_enter(&rdc_conf_lock);
	wakeup_busy(krdc);
	mutex_exit(&rdc_conf_lock);

	return (rc);
}

static int
rdc_status(void *arg, int mode, rdc_config_t *uparms, spcs_s_info_t kstatus)
{
	rdc_k_info_t *krdc;
	rdc_u_info_t *urdc;
	disk_queue *dqp;
	int rc = 0;
	int index;
	char *ptr;
	extern int rdc_status_copy32(const void *, void *, size_t, int);

	mutex_enter(&rdc_conf_lock);
	index = rdc_lookup_byname(uparms->rdc_set);
	if (index >= 0)
		krdc = &rdc_k_info[index];
	if (index < 0 || (krdc->type_flag & RDC_DISABLEPEND)) {
		mutex_exit(&rdc_conf_lock);
		spcs_s_add(kstatus, RDC_EALREADY, uparms->rdc_set->primary.file,
		    uparms->rdc_set->secondary.file);
		return (RDC_EALREADY);
	}

	set_busy(krdc);
	if (krdc->type_flag == 0) {
		/* A resume or enable failed */
		wakeup_busy(krdc);
		mutex_exit(&rdc_conf_lock);
		spcs_s_add(kstatus, RDC_EALREADY, uparms->rdc_set->primary.file,
		    uparms->rdc_set->secondary.file);
		return (RDC_EALREADY);
	}

	mutex_exit(&rdc_conf_lock);

	rdc_group_enter(krdc);
	if (rdc_check(krdc, uparms->rdc_set)) {
		rdc_group_exit(krdc);
		spcs_s_add(kstatus, RDC_EALREADY, uparms->rdc_set->primary.file,
		    uparms->rdc_set->secondary.file);
		rc = RDC_EALREADY;
		goto done;
	}

	urdc = &rdc_u_info[index];

	/*
	 * sneak out qstate in urdc->flags
	 * this is harmless because it's value is not used
	 * in urdc->flags. the real qstate is kept in
	 * group->diskq->disk_hdr.h.state
	 */
	if (RDC_IS_DISKQ(krdc->group)) {
		dqp = &krdc->group->diskq;
		if (IS_QSTATE(dqp, RDC_QNOBLOCK))
		urdc->flags |= RDC_QNOBLOCK;
	}

	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		ptr = (char *)arg + offsetof(struct rdc_config32, rdc_set);
		rc = rdc_status_copy32(urdc, ptr, sizeof (struct rdc_set32),
		    mode);
	} else {
		ptr = (char *)arg + offsetof(struct rdc_config, rdc_set);
		rc = ddi_copyout(urdc, ptr, sizeof (struct rdc_set), mode);
	}
	/* clear out qstate from flags */
	urdc->flags &= ~RDC_QNOBLOCK;

	if (rc)
		rc = EFAULT;

	rdc_group_exit(krdc);
done:
	mutex_enter(&rdc_conf_lock);
	wakeup_busy(krdc);
	mutex_exit(&rdc_conf_lock);

	return (rc);
}

/*
 * Overwrite the bitmap with one supplied by the
 * user.
 * Copy into all bitmaps that are tracking this volume.
 */

int
rdc_bitmapset(int op, char *sechost, char *secdev, void *bmapaddr, int bmapsz,
    nsc_off_t off, int mode)
{
	int rc;
	rdc_k_info_t *krdc;
	int *indexvec;
	int index;
	int indexit;
	kmutex_t **grouplocks;
	int i;
	int groupind;

	if (off % FBA_SIZE(1)) {
		/* Must be modulo FBA */
		cmn_err(CE_WARN, "!bitmapset: Offset is not on an FBA "
		    "boundary %llu", (unsigned long long)off);
		return (EINVAL);
	}
	if (bmapsz % FBA_SIZE(1)) {
		/* Must be modulo FBA */
		cmn_err(CE_WARN, "!bitmapset: Size is not on an FBA "
		    "boundary %d", bmapsz);
		return (EINVAL);
	}

	mutex_enter(&rdc_conf_lock);
	index = rdc_lookup_byhostdev(sechost, secdev);
	if (index >= 0) {
		krdc = &rdc_k_info[index];
	}
	if (index < 0 || (krdc->type_flag & RDC_DISABLEPEND)) {
		rc = ENODEV;
		mutex_exit(&rdc_conf_lock);
		return (rc);
	}
	indexvec = kmem_alloc(rdc_max_sets * sizeof (int), KM_SLEEP);
	grouplocks = kmem_alloc(rdc_max_sets * sizeof (kmutex_t *), KM_SLEEP);

	/*
	 * I now have this set, and I want to take the group
	 * lock on it, and all the group locks of all the
	 * sets on the many and multi-hop links.
	 * I have to take the many lock while traversing the
	 * many/multi links.
	 * I think I also need to set the busy count on this
	 * set, otherwise when I drop the conf_lock, what
	 * will stop some other process from coming in and
	 * issuing a disable?
	 */
	set_busy(krdc);
	mutex_exit(&rdc_conf_lock);

retrylock:
	groupind = 0;
	indexit = 0;
	rdc_many_enter(krdc);
	/*
	 * Take this initial sets group lock first.
	 */
	if (!mutex_tryenter(&krdc->group->lock)) {
		rdc_many_exit(krdc);
		goto retrylock;
	}

	grouplocks[groupind] = &krdc->group->lock;
	groupind++;

	rc = rdc_checkforbitmap(index, off + bmapsz);
	if (rc) {
		goto done;
	}
	indexvec[indexit] = index;
	indexit++;
	if (IS_MANY(krdc)) {
		rdc_k_info_t *ktmp;

		for (ktmp = krdc->many_next; ktmp != krdc;
		    ktmp =  ktmp->many_next) {
			/*
			 * attempt to take the group lock,
			 * if we don't already have it.
			 */
			if (ktmp->group == NULL) {
				rc = ENODEV;
				goto done;
			}
			for (i = 0; i < groupind; i++) {
				if (grouplocks[i] == &ktmp->group->lock)
					/* already have the group lock */
					break;
			}
			/*
			 * didn't find our lock in our collection,
			 * attempt to take group lock.
			 */
			if (i >= groupind) {
				if (!mutex_tryenter(&ktmp->group->lock)) {
					for (i = 0; i < groupind; i++) {
						mutex_exit(grouplocks[i]);
					}
					rdc_many_exit(krdc);
					goto retrylock;
				}
				grouplocks[groupind] = &ktmp->group->lock;
				groupind++;
			}
			rc = rdc_checkforbitmap(ktmp->index, off + bmapsz);
			if (rc == 0) {
				indexvec[indexit] = ktmp->index;
				indexit++;
			} else {
				goto done;
			}
		}
	}
	if (IS_MULTI(krdc)) {
		rdc_k_info_t *kmulti = krdc->multi_next;

		if (kmulti->group == NULL) {
			rc = ENODEV;
			goto done;
		}
		/*
		 * This can't be in our group already.
		 */
		if (!mutex_tryenter(&kmulti->group->lock)) {
			for (i = 0; i < groupind; i++) {
				mutex_exit(grouplocks[i]);
			}
			rdc_many_exit(krdc);
			goto retrylock;
		}
		grouplocks[groupind] = &kmulti->group->lock;
		groupind++;

		rc = rdc_checkforbitmap(kmulti->index, off + bmapsz);
		if (rc == 0) {
			indexvec[indexit] = kmulti->index;
			indexit++;
		} else {
			goto done;
		}
	}
	rc = rdc_installbitmap(op, bmapaddr, bmapsz, off, mode, indexvec,
	    indexit);
done:
	for (i = 0; i < groupind; i++) {
		mutex_exit(grouplocks[i]);
	}
	rdc_many_exit(krdc);
	mutex_enter(&rdc_conf_lock);
	wakeup_busy(krdc);
	mutex_exit(&rdc_conf_lock);
	kmem_free(indexvec, rdc_max_sets * sizeof (int));
	kmem_free(grouplocks, rdc_max_sets * sizeof (kmutex_t *));
	return (rc);
}

static int
rdc_checkforbitmap(int index, nsc_off_t limit)
{
	rdc_k_info_t *krdc;
	rdc_u_info_t *urdc;

	krdc = &rdc_k_info[index];
	urdc = &rdc_u_info[index];

	if (!IS_ENABLED(urdc)) {
		return (EIO);
	}
	if (!(rdc_get_vflags(urdc) & RDC_LOGGING)) {
		return (ENXIO);
	}
	if (krdc->dcio_bitmap == NULL) {
		cmn_err(CE_WARN, "!checkforbitmap: No bitmap for set (%s:%s)",
		    urdc->secondary.intf, urdc->secondary.file);
		return (ENOENT);
	}
	if (limit > krdc->bitmap_size) {
		cmn_err(CE_WARN, "!checkbitmap: Bitmap exceeded, "
		    "incore %" NSC_SZFMT " user supplied %" NSC_SZFMT
		    " for set (%s:%s)", krdc->bitmap_size,
		    limit, urdc->secondary.intf, urdc->secondary.file);
		return (ENOSPC);
	}
	return (0);
}



/*
 * Copy the user supplied bitmap to this set.
 */
static int
rdc_installbitmap(int op, void *bmapaddr, int bmapsz,
    nsc_off_t off, int mode, int *vec, int veccnt)
{
	int rc;
	nsc_off_t sfba;
	nsc_off_t efba;
	nsc_off_t fba;
	void *ormem = NULL;
	int len;
	int left;
	int copied;
	int index;
	rdc_k_info_t *krdc;
	rdc_u_info_t *urdc;

	rc = 0;
	ormem = kmem_alloc(RDC_MAXDATA, KM_SLEEP);
	left = bmapsz;
	copied = 0;
	while (left > 0) {
		if (left > RDC_MAXDATA) {
			len = RDC_MAXDATA;
		} else {
			len = left;
		}
		if (ddi_copyin((char *)bmapaddr + copied, ormem,
		    len, mode)) {
			cmn_err(CE_WARN, "!installbitmap: Copyin failed");
			rc = EFAULT;
			goto out;
		}
		sfba = FBA_NUM(off + copied);
		efba = FBA_NUM(off + copied + len);
		for (index = 0; index < veccnt; index++) {
			krdc = &rdc_k_info[vec[index]];
			urdc = &rdc_u_info[vec[index]];

			mutex_enter(&krdc->bmapmutex);
			if (op == RDC_BITMAPSET) {
				bcopy(ormem, krdc->dcio_bitmap + off + copied,
				    len);
			} else {
				rdc_lor(ormem,
				    krdc->dcio_bitmap + off + copied, len);
			}
			/*
			 * Maybe this should be just done once outside of
			 * the the loop? (Less work, but leaves a window
			 * where the bits_set doesn't match the bitmap).
			 */
			urdc->bits_set = RDC_COUNT_BITMAP(krdc);
			mutex_exit(&krdc->bmapmutex);
			if (krdc->bitmap_write > 0) {
				for (fba = sfba; fba < efba; fba++) {
					if (rc = rdc_write_bitmap_fba(krdc,
					    fba)) {

						cmn_err(CE_WARN,
						    "!installbitmap: "
						    "write_bitmap_fba failed "
						    "on fba number %" NSC_SZFMT
						    " set %s:%s", fba,
						    urdc->secondary.intf,
						    urdc->secondary.file);
						goto out;
					}
				}
			}
		}
		copied += len;
		left -= len;
	}
out:
	kmem_free(ormem, RDC_MAXDATA);
	return (rc);
}

/*
 * _rdc_config
 */
int
_rdc_config(void *arg, int mode, spcs_s_info_t kstatus, int *rvp)
{
	int rc = 0;
	struct netbuf fsvaddr, tsvaddr;
	struct knetconfig *knconf;
	char *p = NULL, *pf = NULL;
	struct rdc_config *uap;
	STRUCT_DECL(knetconfig, knconf_tmp);
	STRUCT_DECL(rdc_config, uparms);
	int enable, disable;
	int cmd;


	STRUCT_HANDLE(rdc_set, rs);
	STRUCT_HANDLE(rdc_addr, pa);
	STRUCT_HANDLE(rdc_addr, sa);

	STRUCT_INIT(uparms, mode);

	bzero(STRUCT_BUF(uparms), STRUCT_SIZE(uparms));
	bzero(&fsvaddr, sizeof (fsvaddr));
	bzero(&tsvaddr, sizeof (tsvaddr));

	knconf = NULL;

	if (ddi_copyin(arg, STRUCT_BUF(uparms), STRUCT_SIZE(uparms), mode)) {
		return (EFAULT);
	}

	STRUCT_SET_HANDLE(rs, mode, STRUCT_FGETP(uparms, rdc_set));
	STRUCT_SET_HANDLE(pa, mode, STRUCT_FADDR(rs, primary));
	STRUCT_SET_HANDLE(sa, mode, STRUCT_FADDR(rs, secondary));
	cmd = STRUCT_FGET(uparms, command);
	if (cmd == RDC_CMD_ENABLE || cmd == RDC_CMD_RESUME) {
		fsvaddr.len = STRUCT_FGET(pa, addr.len);
		fsvaddr.maxlen = STRUCT_FGET(pa, addr.maxlen);
		fsvaddr.buf =  kmem_zalloc(fsvaddr.len, KM_SLEEP);

		if (ddi_copyin(STRUCT_FGETP(pa, addr.buf),
		    fsvaddr.buf, fsvaddr.len, mode)) {
			kmem_free(fsvaddr.buf, fsvaddr.len);
#ifdef DEBUG
			cmn_err(CE_WARN, "!copyin failed primary.addr 2");
#endif
			return (EFAULT);
		}


		tsvaddr.len = STRUCT_FGET(sa, addr.len);
		tsvaddr.maxlen = STRUCT_FGET(sa, addr.maxlen);
		tsvaddr.buf =  kmem_zalloc(tsvaddr.len, KM_SLEEP);

		if (ddi_copyin(STRUCT_FGETP(sa, addr.buf),
		    tsvaddr.buf, tsvaddr.len, mode)) {
#ifdef DEBUG
			cmn_err(CE_WARN, "!copyin failed secondary addr");
#endif
			kmem_free(fsvaddr.buf, fsvaddr.len);
			kmem_free(tsvaddr.buf, tsvaddr.len);
			return (EFAULT);
		}
	} else {
		fsvaddr.len = 0;
		fsvaddr.maxlen = 0;
		fsvaddr.buf =  kmem_zalloc(fsvaddr.len, KM_SLEEP);
		tsvaddr.len = 0;
		tsvaddr.maxlen = 0;
		tsvaddr.buf =  kmem_zalloc(tsvaddr.len, KM_SLEEP);
	}

	if (STRUCT_FGETP(uparms, rdc_set->netconfig) != NULL) {
		STRUCT_INIT(knconf_tmp, mode);
		knconf = kmem_zalloc(sizeof (*knconf), KM_SLEEP);
		if (ddi_copyin(STRUCT_FGETP(uparms, rdc_set->netconfig),
		    STRUCT_BUF(knconf_tmp), STRUCT_SIZE(knconf_tmp), mode)) {
#ifdef DEBUG
			cmn_err(CE_WARN, "!copyin failed netconfig");
#endif
			kmem_free(fsvaddr.buf, fsvaddr.len);
			kmem_free(tsvaddr.buf, tsvaddr.len);
			kmem_free(knconf, sizeof (*knconf));
			return (EFAULT);
		}

		knconf->knc_semantics = STRUCT_FGET(knconf_tmp, knc_semantics);
		knconf->knc_protofmly = STRUCT_FGETP(knconf_tmp, knc_protofmly);
		knconf->knc_proto = STRUCT_FGETP(knconf_tmp, knc_proto);

#ifndef _SunOS_5_6
		if ((mode & DATAMODEL_LP64) == 0) {
			knconf->knc_rdev =
			    expldev(STRUCT_FGET(knconf_tmp, knc_rdev));
		} else {
#endif
			knconf->knc_rdev = STRUCT_FGET(knconf_tmp, knc_rdev);
#ifndef _SunOS_5_6
		}
#endif

		pf = kmem_alloc(KNC_STRSIZE, KM_SLEEP);
		p = kmem_alloc(KNC_STRSIZE, KM_SLEEP);
		rc = ddi_copyin(knconf->knc_protofmly, pf, KNC_STRSIZE, mode);
		if (rc) {
#ifdef DEBUG
			cmn_err(CE_WARN, "!copyin failed parms protofmly");
#endif
			rc = EFAULT;
			goto out;
		}
		rc = ddi_copyin(knconf->knc_proto, p, KNC_STRSIZE, mode);
		if (rc) {
#ifdef DEBUG
			cmn_err(CE_WARN, "!copyin failed parms proto");
#endif
			rc = EFAULT;
			goto out;
		}
		knconf->knc_protofmly = pf;
		knconf->knc_proto = p;
	} /* !NULL netconfig */

	uap = kmem_alloc(sizeof (*uap), KM_SLEEP);

	/* copy relevant parts of rdc_config to uap field by field */

	(void) strncpy(uap->rdc_set[0].primary.intf, STRUCT_FGETP(pa, intf),
	    MAX_RDC_HOST_SIZE);
	(void) strncpy(uap->rdc_set[0].primary.file, STRUCT_FGETP(pa, file),
	    NSC_MAXPATH);
	(void) strncpy(uap->rdc_set[0].primary.bitmap, STRUCT_FGETP(pa, bitmap),
	    NSC_MAXPATH);
	uap->rdc_set[0].netconfig = knconf;
	uap->rdc_set[0].flags = STRUCT_FGET(uparms, rdc_set->flags);
	uap->rdc_set[0].index = STRUCT_FGET(uparms, rdc_set->index);
	uap->rdc_set[0].setid = STRUCT_FGET(uparms, rdc_set->setid);
	uap->rdc_set[0].sync_pos = STRUCT_FGET(uparms, rdc_set->sync_pos);
	uap->rdc_set[0].volume_size = STRUCT_FGET(uparms, rdc_set->volume_size);
	uap->rdc_set[0].bits_set = STRUCT_FGET(uparms, rdc_set->bits_set);
	uap->rdc_set[0].autosync = STRUCT_FGET(uparms, rdc_set->autosync);
	uap->rdc_set[0].maxqfbas = STRUCT_FGET(uparms, rdc_set->maxqfbas);
	uap->rdc_set[0].maxqitems = STRUCT_FGET(uparms, rdc_set->maxqitems);
	uap->rdc_set[0].asyncthr = STRUCT_FGET(uparms, rdc_set->asyncthr);
	uap->rdc_set[0].syshostid = STRUCT_FGET(uparms, rdc_set->syshostid);
	uap->rdc_set[0].primary.addr = fsvaddr;		/* struct copy */
	uap->rdc_set[0].secondary.addr = tsvaddr;	/* struct copy */

	(void) strncpy(uap->rdc_set[0].secondary.intf, STRUCT_FGETP(sa, intf),
	    MAX_RDC_HOST_SIZE);
	(void) strncpy(uap->rdc_set[0].secondary.file, STRUCT_FGETP(sa, file),
	    NSC_MAXPATH);
	(void) strncpy(uap->rdc_set[0].secondary.bitmap,
	    STRUCT_FGETP(sa, bitmap), NSC_MAXPATH);

	(void) strncpy(uap->rdc_set[0].direct_file,
	    STRUCT_FGETP(rs, direct_file), NSC_MAXPATH);

	(void) strncpy(uap->rdc_set[0].group_name, STRUCT_FGETP(rs, group_name),
	    NSC_MAXPATH);

	(void) strncpy(uap->rdc_set[0].disk_queue, STRUCT_FGETP(rs, disk_queue),
	    NSC_MAXPATH);

	uap->command = STRUCT_FGET(uparms, command);
	uap->options = STRUCT_FGET(uparms, options);

	enable = (uap->command == RDC_CMD_ENABLE ||
	    uap->command == RDC_CMD_RESUME);
	disable = (uap->command == RDC_CMD_DISABLE ||
	    uap->command == RDC_CMD_SUSPEND);

	/*
	 * Initialise the threadset if it has not already been done.
	 *
	 * This has to be done now, not in rdcattach(), because
	 * rdcattach() can be called before nskernd is running (eg.
	 * boot -r) in which case the nst_init() would fail and hence
	 * the attach would fail.
	 *
	 * Threadset creation is locked by the rdc_conf_lock,
	 * destruction is inherently single threaded as it is done in
	 * _rdc_unload() which must be the last thing performed by
	 * rdcdetach().
	 */

	if (enable && _rdc_ioset == NULL) {
		mutex_enter(&rdc_conf_lock);

		if (_rdc_ioset == NULL) {
			rc = rdc_thread_configure();
		}

		mutex_exit(&rdc_conf_lock);

		if (rc || _rdc_ioset == NULL) {
			spcs_s_add(kstatus, RDC_ENOTHREADS);
			rc = RDC_ENOTHREADS;
			goto outuap;
		}
	}
	switch (uap->command) {
	case RDC_CMD_ENABLE:
		rc = rdc_enable(uap, kstatus);
		break;
	case RDC_CMD_DISABLE:
		rc = rdc_disable(uap, kstatus);
		break;
	case RDC_CMD_COPY:
		rc = rdc_sync(uap, kstatus);
		break;
	case RDC_CMD_LOG:
		rc = rdc_log(uap, kstatus);
		break;
	case RDC_CMD_RECONFIG:
		rc = rdc_reconfig(uap, kstatus);
		break;
	case RDC_CMD_RESUME:
		rc = rdc_resume(uap, kstatus);
		break;
	case RDC_CMD_SUSPEND:
		rc = rdc_suspend(uap, kstatus);
		break;
	case RDC_CMD_TUNABLE:
		rc = rdc_tunable(uap, kstatus);
		break;
	case RDC_CMD_WAIT:
		rc = rdc_wait(uap, kstatus);
		break;
	case RDC_CMD_HEALTH:
		rc = rdc_health(uap, kstatus, rvp);
		break;
	case RDC_CMD_STATUS:
		rc = rdc_status(arg, mode, uap, kstatus);
		break;
	case RDC_CMD_RESET:
		rc = rdc_reset(uap, kstatus);
		break;
	case RDC_CMD_ADDQ:
		rc = rdc_add_diskq(uap, kstatus);
		break;
	case RDC_CMD_REMQ:
		if ((rc = rdc_rem_diskq(uap, kstatus)) != 0)
			break;
		/* FALLTHRU */
	case RDC_CMD_KILLQ:
		rc = rdc_kill_diskq(uap, kstatus);
		break;
	case RDC_CMD_INITQ:
		rc = rdc_init_diskq(uap, kstatus);
		break;

	default:
		rc = EINVAL;
		break;
	}

	/*
	 * Tune the threadset size after a successful rdc_set addition
	 * or removal.
	 */
	if ((enable || disable) && rc == 0) {
		mutex_enter(&rdc_conf_lock);
		rdc_thread_tune(enable ? 2 : -2);
		mutex_exit(&rdc_conf_lock);
	}
outuap:
	kmem_free(uap, sizeof (*uap));
out:
	kmem_free(fsvaddr.buf, fsvaddr.len);
	kmem_free(tsvaddr.buf, tsvaddr.len);
	if (pf)
		kmem_free(pf, KNC_STRSIZE);
	if (p)
		kmem_free(p, KNC_STRSIZE);
	if (knconf)
		kmem_free(knconf, sizeof (*knconf));
	return (rc);
}


/*
 * krdc->group->lock held on entry to halt_sync()
 */
static void
halt_sync(rdc_k_info_t *krdc)
{
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];

	ASSERT(MUTEX_HELD(&krdc->group->lock));
	ASSERT(IS_ENABLED(urdc));

	/*
	 * If a sync is in progress, halt it
	 */
	if ((rdc_get_vflags(urdc) & RDC_PRIMARY) &&
	    (krdc->aux_state & RDC_AUXSYNCIP)) {
		krdc->disk_status = 1;

		while (krdc->disk_status == 1) {
			if (cv_wait_sig(&krdc->haltcv, &krdc->group->lock) == 0)
				break;
		}
	}
}

/*
 * return size in blocks
 */
uint64_t
mirror_getsize(int index)
{
	rdc_k_info_t *krdc;
	rdc_u_info_t *urdc;
	int rc, rs;
	nsc_size_t size;

	krdc = &rdc_k_info[index];
	urdc = &rdc_u_info[index];

	rc = _rdc_rsrv_devs(krdc, RDC_RAW, RDC_INTERNAL);
	rs = nsc_partsize(RDC_U_FD(krdc), &size);
	urdc->volume_size = size;
	if (rc == 0)
		_rdc_rlse_devs(krdc, RDC_RAW);

	return (rs == 0 ? urdc->volume_size : 0);
}


/*
 * Create a new dataset for this transfer, and add it to the list
 * of datasets via the net_dataset pointer in the krdc.
 */
rdc_net_dataset_t *
rdc_net_add_set(int index)
{
	rdc_k_info_t *krdc;
	rdc_u_info_t *urdc;
	rdc_net_dataset_t *dset;

	if (index >= rdc_max_sets) {
		cmn_err(CE_NOTE, "!rdc_net_add_set: bad index %d", index);
		return (NULL);
	}
	krdc = &rdc_k_info[index];
	urdc = &rdc_u_info[index];

	dset = kmem_alloc(sizeof (*dset), KM_NOSLEEP);
	if (dset == NULL) {
		cmn_err(CE_NOTE, "!rdc_net_add_set: kmem_alloc failed");
		return (NULL);
	}
	RDC_DSMEMUSE(sizeof (*dset));
	dset->inuse = 1;
	dset->nitems = 0;
	dset->delpend = 0;
	dset->head = NULL;
	dset->tail = NULL;
	mutex_enter(&krdc->dc_sleep);

	if (!IS_ENABLED(urdc)) {
		/* raced with a disable command */
		kmem_free(dset, sizeof (*dset));
		RDC_DSMEMUSE(-sizeof (*dset));
		mutex_exit(&krdc->dc_sleep);
		return (NULL);
	}
	/*
	 * Shared the id generator, (and the locks).
	 */
	mutex_enter(&rdc_net_hnd_id_lock);
	if (++rdc_net_hnd_id == 0)
		rdc_net_hnd_id = 1;
	dset->id = rdc_net_hnd_id;
	mutex_exit(&rdc_net_hnd_id_lock);

#ifdef DEBUG
	if (krdc->net_dataset != NULL) {
		rdc_net_dataset_t *dset2;
		for (dset2 = krdc->net_dataset; dset2; dset2 = dset2->next) {
			if (dset2->id == dset->id) {
				cmn_err(CE_PANIC,
				    "rdc_net_add_set duplicate id %p:%d %p:%d",
				    (void *)dset, dset->id,
				    (void *)dset2, dset2->id);
			}
		}
	}
#endif
	dset->next = krdc->net_dataset;
	krdc->net_dataset = dset;
	mutex_exit(&krdc->dc_sleep);

	return (dset);
}

/*
 * fetch the previously added dataset.
 */
rdc_net_dataset_t *
rdc_net_get_set(int index, int id)
{
	rdc_k_info_t *krdc;
	rdc_net_dataset_t *dset;

	if (index >= rdc_max_sets) {
		cmn_err(CE_NOTE, "!rdc_net_get_set: bad index %d", index);
		return (NULL);
	}
	krdc = &rdc_k_info[index];

	mutex_enter(&krdc->dc_sleep);

	dset = krdc->net_dataset;
	while (dset && (dset->id != id))
		dset = dset->next;

	if (dset) {
		dset->inuse++;
	}

	mutex_exit(&krdc->dc_sleep);
	return (dset);
}

/*
 * Decrement the inuse counter. Data may be freed.
 */
void
rdc_net_put_set(int index, rdc_net_dataset_t *dset)
{
	rdc_k_info_t *krdc;

	if (index >= rdc_max_sets) {
		cmn_err(CE_NOTE, "!rdc_net_put_set: bad index %d", index);
		return;
	}
	krdc = &rdc_k_info[index];

	mutex_enter(&krdc->dc_sleep);
	dset->inuse--;
	ASSERT(dset->inuse >= 0);
	if ((dset->inuse == 0) && (dset->delpend)) {
		rdc_net_free_set(krdc, dset);
	}
	mutex_exit(&krdc->dc_sleep);
}

/*
 * Mark that we are finished with this set. Decrement inuse
 * counter, mark as needing deletion, and
 * remove from linked list.
 */
void
rdc_net_del_set(int index, rdc_net_dataset_t *dset)
{
	rdc_k_info_t *krdc;

	if (index >= rdc_max_sets) {
		cmn_err(CE_NOTE, "!rdc_net_del_set: bad index %d", index);
		return;
	}
	krdc = &rdc_k_info[index];

	mutex_enter(&krdc->dc_sleep);
	dset->inuse--;
	ASSERT(dset->inuse >= 0);
	dset->delpend = 1;
	if (dset->inuse == 0) {
		rdc_net_free_set(krdc, dset);
	}
	mutex_exit(&krdc->dc_sleep);
}

/*
 * free all the memory associated with this set, and remove from
 * list.
 * Enters and exits with dc_sleep lock held.
 */

void
rdc_net_free_set(rdc_k_info_t *krdc, rdc_net_dataset_t *dset)
{
	rdc_net_dataset_t **dsetp;
#ifdef DEBUG
	int found = 0;
#endif

	ASSERT(MUTEX_HELD(&krdc->dc_sleep));
	ASSERT(dset);
	for (dsetp = &krdc->net_dataset; *dsetp; dsetp = &((*dsetp)->next)) {
		if (*dsetp == dset) {
			*dsetp = dset->next;
#ifdef DEBUG
			found = 1;
#endif
			break;
		}
	}

#ifdef DEBUG
	if (found == 0) {
		cmn_err(CE_WARN, "!rdc_net_free_set: Unable to find "
		    "dataset 0x%p in krdc list", (void *)dset);
	}
#endif
	/*
	 * unlinked from list. Free all the data
	 */
	rdc_ditemsfree(dset);
	/*
	 * free my core.
	 */
	kmem_free(dset, sizeof (*dset));
	RDC_DSMEMUSE(-sizeof (*dset));
}


/*
 * Free all the dataitems and the data it points to.
 */
static void
rdc_ditemsfree(rdc_net_dataset_t *dset)
{
	rdc_net_dataitem_t *ditem;
	rdc_net_dataitem_t *nitem;

	ditem = dset->head;

	while (ditem) {
		nitem = ditem->next;
		kmem_free(ditem->dptr, ditem->mlen);
		RDC_DSMEMUSE(-ditem->mlen);
		dset->nitems--;
		kmem_free(ditem, sizeof (*ditem));
		RDC_DSMEMUSE(-sizeof (*ditem));
		ditem = nitem;
	}
	ASSERT(dset->nitems == 0);
}

/*
 * allocate and initialize a rdc_aio_t
 */
rdc_aio_t *
rdc_aio_tbuf_get(void *n, void *h, int pos, int len, int flag, int index, int s)
{
	rdc_aio_t *p;

	p = kmem_zalloc(sizeof (rdc_aio_t), KM_NOSLEEP);
	if (p == NULL) {
#ifdef DEBUG
		cmn_err(CE_NOTE, "!_rdcaiotbufget: kmem_alloc failed bp aio");
#endif
		return (NULL);
	} else {
		p->next = n; /* overload */
		p->handle = h;
		p->pos = pos;
		p->qpos = -1;
		p->len = len;
		p->flag = flag;
		p->index = index;
		p->iostatus = s; /* overload */
		/* set up seq later, in case thr create fails */
	}
	return (p);
}

/*
 * rdc_aio_buf_get
 * get an aio_buf
 */
aio_buf_t *
rdc_aio_buf_get(rdc_buf_t *h, int index)
{
	aio_buf_t *p;

	if (index >= rdc_max_sets) {
		cmn_err(CE_NOTE, "!rdc: rdc_aio_buf_get bad index %x", index);
		return (NULL);
	}

	mutex_enter(&h->aio_lock);

	p = h->rdc_anon;
	while (p && (p->kindex != index))
		p = p->next;

	mutex_exit(&h->aio_lock);
	return (p);
}

/*
 * rdc_aio_buf_del
 * delete a aio_buf
 */
void
rdc_aio_buf_del(rdc_buf_t *h, rdc_k_info_t *krdc)
{
	aio_buf_t *p, **pp;

	mutex_enter(&h->aio_lock);

	p = NULL;
	for (pp = &h->rdc_anon; *pp; pp = &((*pp)->next)) {
		if ((*pp)->kindex == krdc->index) {
			p = *pp;
			break;
		}
	}

	if (p) {
		*pp = p->next;
		kmem_free(p, sizeof (*p));
	}
	mutex_exit(&h->aio_lock);
}

/*
 * rdc_aio_buf_add
 * Add a aio_buf.
 */
aio_buf_t *
rdc_aio_buf_add(int index, rdc_buf_t *h)
{
	aio_buf_t *p;

	p = kmem_zalloc(sizeof (*p), KM_NOSLEEP);
	if (p == NULL) {
		cmn_err(CE_NOTE, "!rdc_aio_buf_add: kmem_alloc failed");
		return (NULL);
	}

	p->rdc_abufp = NULL;
	p->kindex = index;

	mutex_enter(&h->aio_lock);
	p->next = h->rdc_anon;
	h->rdc_anon = p;
	mutex_exit(&h->aio_lock);
	return (p);
}

/*
 * kmemalloc a new group structure and setup the common
 * fields.
 */
static rdc_group_t *
rdc_newgroup()
{
	rdc_group_t *group;

	group = kmem_zalloc(sizeof (rdc_group_t), KM_SLEEP);
	group->diskq.lastio = kmem_zalloc(sizeof (rdc_aio_t), KM_SLEEP);
	group->count = 1;
	group->seq = RDC_NEWSEQ;
	group->seqack = RDC_NEWSEQ;
	mutex_init(&group->lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&group->ra_queue.net_qlock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&group->diskqmutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&group->diskq.disk_qlock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&group->diskq.head_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&group->addthrnumlk, NULL, MUTEX_DRIVER, NULL);
	cv_init(&group->unregistercv, NULL, CV_DRIVER, NULL);
	cv_init(&group->asyncqcv, NULL, CV_DRIVER, NULL);
	cv_init(&group->diskq.busycv, NULL, CV_DRIVER, NULL);
	cv_init(&group->diskq.qfullcv, NULL, CV_DRIVER, NULL);
	cv_init(&group->ra_queue.qfcv, NULL, CV_DRIVER, NULL);
	group->ra_queue.qfill_sleeping = RDC_QFILL_DEAD;
	group->diskq.busycnt = 0;
	ASSERT(group->synccount == 0);		/* group was kmem_zalloc'ed */

	/*
	 * add default number of threads to the flusher thread set, plus
	 * one extra thread for the disk queue flusher
	 */
	if (nst_add_thread(_rdc_flset, 3) != 3)
		cmn_err(CE_NOTE, "!rdc_newgroup: nst_add_thread failed");

	return (group);
}

void
rdc_delgroup(rdc_group_t *group)
{

	ASSERT(group->asyncstall == 0);
	ASSERT(group->rdc_thrnum == 0);
	ASSERT(group->count == 0);
	ASSERT(MUTEX_HELD(&rdc_many_lock));

	mutex_enter(&group->ra_queue.net_qlock);
	rdc_sleepqdiscard(group);
	mutex_exit(&group->ra_queue.net_qlock);

	/* try to remove flusher threads that this group added to _rdc_flset */
	if (nst_del_thread(_rdc_flset, group->rdc_addthrnum + 3) !=
	    group->rdc_addthrnum + 3)
		cmn_err(CE_NOTE, "!rdc_delgroup: nst_del_thread failed");

	mutex_destroy(&group->lock);
	mutex_destroy(&group->ra_queue.net_qlock);
	mutex_destroy(&group->diskqmutex);
	mutex_destroy(&group->diskq.disk_qlock);
	mutex_destroy(&group->diskq.head_lock);
	mutex_destroy(&group->addthrnumlk);
	cv_destroy(&group->unregistercv);
	cv_destroy(&group->asyncqcv);
	cv_destroy(&group->diskq.busycv);
	cv_destroy(&group->diskq.qfullcv);
	cv_destroy(&group->ra_queue.qfcv);
	kmem_free(group->diskq.lastio, sizeof (rdc_aio_t));
	kmem_free(group, sizeof (rdc_group_t));
}
