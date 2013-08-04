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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/note.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/sunndi.h>
#include <sys/kstat.h>
#include <sys/conf.h>
#include <sys/ddi_periodic.h>
#include <sys/devctl.h>
#include <sys/callb.h>
#include <sys/sysevent.h>
#include <sys/taskq.h>
#include <sys/ddi.h>
#include <sys/bitset.h>
#include <sys/damap.h>
#include <sys/damap_impl.h>

#ifdef DEBUG
static int damap_debug = 0;
#endif /* DEBUG */

extern taskq_t *system_taskq;

static void dam_addrset_activate(dam_t *, bitset_t *);
static void dam_addrset_deactivate(dam_t *, bitset_t *);
static void dam_stabilize_map(void *);
static void dam_addr_stable_cb(void *);
static void dam_addrset_stable_cb(void *);
static void dam_sched_timeout(void (*timeout_cb)(), dam_t *, clock_t);
static void dam_addr_report(dam_t *, dam_da_t *, id_t, int);
static void dam_addr_release(dam_t *, id_t);
static void dam_addr_report_release(dam_t *, id_t);
static void dam_addr_deactivate(dam_t *, id_t);
static void dam_deact_cleanup(dam_t *, id_t, char *, damap_deact_rsn_t);
static id_t dam_get_addrid(dam_t *, char *);
static int dam_kstat_create(dam_t *);
static int dam_map_alloc(dam_t *);

#define	DAM_INCR_STAT(mapp, stat)				\
	if ((mapp)->dam_kstatsp) {				\
		struct dam_kstats *stp = (mapp)->dam_kstatsp->ks_data;	\
		stp->stat.value.ui32++;				\
	}

#define	DAM_SET_STAT(mapp, stat, val)				\
	if ((mapp)->dam_kstatsp) {				\
		struct dam_kstats *stp = (mapp)->dam_kstatsp->ks_data;	\
		stp->stat.value.ui32 = (val);			\
	}


/*
 * increase damap size by 64 entries at a time
 */
#define	DAM_SIZE_BUMP	64

int	damap_taskq_dispatch_retry_usec = 1000;

/*
 * config/unconfig taskq data
 */
typedef struct {
	dam_t *tqd_mapp;
	id_t tqd_id;
} cfg_tqd_t;

extern pri_t maxclsyspri;

/*
 * Create new device address map
 *
 * name:		map name (kstat unique)
 * size:		max # of map entries
 * mode:		style of address reports: per-address or fullset
 * stable_usec:		# of quiescent microseconds before report/map is stable
 *
 * activate_arg:	address provider activation-callout private
 * activate_cb:		address provider activation callback handler
 * deactivate_cb:	address provider deactivation callback handler
 *
 * config_arg:		configuration-callout private
 * config_cb:		class configuration callout
 * unconfig_cb:		class unconfiguration callout
 *
 * damapp:		pointer to map handle (return)
 *
 * Returns:	DAM_SUCCESS
 *		DAM_EINVAL	Invalid argument(s)
 *		DAM_FAILURE	General failure
 */
int
damap_create(char *name, damap_rptmode_t mode, int map_opts,
    int stable_usec, void *activate_arg, damap_activate_cb_t activate_cb,
    damap_deactivate_cb_t deactivate_cb,
    void *config_arg, damap_configure_cb_t configure_cb,
    damap_unconfig_cb_t unconfig_cb,
    damap_t **damapp)
{
	dam_t *mapp;

	if (configure_cb == NULL || unconfig_cb == NULL || name == NULL)
		return (DAM_EINVAL);

	mapp = kmem_zalloc(sizeof (*mapp), KM_SLEEP);
	mapp->dam_options = map_opts;
	mapp->dam_stable_ticks = drv_usectohz(stable_usec);
	mapp->dam_size = 0;
	mapp->dam_rptmode = mode;
	mapp->dam_activate_arg = activate_arg;
	mapp->dam_activate_cb = (activate_cb_t)activate_cb;
	mapp->dam_deactivate_cb = (deactivate_cb_t)deactivate_cb;
	mapp->dam_config_arg = config_arg;
	mapp->dam_configure_cb = (configure_cb_t)configure_cb;
	mapp->dam_unconfig_cb = (unconfig_cb_t)unconfig_cb;
	mapp->dam_name = i_ddi_strdup(name, KM_SLEEP);
	mutex_init(&mapp->dam_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&mapp->dam_sync_cv, NULL, CV_DRIVER, NULL);
	bitset_init(&mapp->dam_active_set);
	bitset_init(&mapp->dam_stable_set);
	bitset_init(&mapp->dam_report_set);
	*damapp = (damap_t *)mapp;

	DTRACE_PROBE5(damap__create,
	    char *, mapp->dam_name, damap_t *, mapp,
	    damap_rptmode_t, mode, int, map_opts, int, stable_usec);

	return (DAM_SUCCESS);
}

/*
 * Allocate backing resources
 *
 * DAMs are lightly backed on create - major allocations occur
 * at the time a report is made to the map, and are extended on
 * a demand basis.
 */
static int
dam_map_alloc(dam_t *mapp)
{
	void *softstate_p;

	ASSERT(mutex_owned(&mapp->dam_lock));
	if (mapp->dam_flags & DAM_DESTROYPEND)
		return (DAM_FAILURE);

	/*
	 * dam_high > 0 signals map allocation complete
	 */
	if (mapp->dam_high)
		return (DAM_SUCCESS);

	mapp->dam_size = DAM_SIZE_BUMP;
	if (ddi_soft_state_init(&softstate_p, sizeof (dam_da_t),
	    mapp->dam_size) != DDI_SUCCESS)
		return (DAM_FAILURE);

	if (ddi_strid_init(&mapp->dam_addr_hash, mapp->dam_size) !=
	    DDI_SUCCESS) {
		ddi_soft_state_fini(softstate_p);
		return (DAM_FAILURE);
	}
	if (dam_kstat_create(mapp) != DDI_SUCCESS) {
		ddi_soft_state_fini(softstate_p);
		ddi_strid_fini(&mapp->dam_addr_hash);
		return (DAM_FAILURE);
	}
	mapp->dam_da = softstate_p;
	mapp->dam_high = 1;
	bitset_resize(&mapp->dam_active_set, mapp->dam_size);
	bitset_resize(&mapp->dam_stable_set, mapp->dam_size);
	bitset_resize(&mapp->dam_report_set, mapp->dam_size);
	return (DAM_SUCCESS);
}

/*
 * Destroy address map
 *
 * damapp:	address map
 *
 * Returns:	DAM_SUCCESS
 *		DAM_EINVAL	Invalid argument(s)
 *		DAM_FAILURE	General failure
 */
void
damap_destroy(damap_t *damapp)
{
	int i;
	dam_t *mapp = (dam_t *)damapp;

	ASSERT(mapp);

	DTRACE_PROBE2(damap__destroy,
	    char *, mapp->dam_name, damap_t *, mapp);

	mutex_enter(&mapp->dam_lock);

	/*
	 * prevent new reports from being added to the map
	 */
	mapp->dam_flags |= DAM_DESTROYPEND;

	if (mapp->dam_high) {
		mutex_exit(&mapp->dam_lock);
		/*
		 * wait for outstanding reports to stabilize and cancel
		 * the timer for this map
		 */
		(void) damap_sync(damapp, 0);
		mutex_enter(&mapp->dam_lock);
		dam_sched_timeout(NULL, mapp, 0);

		/*
		 * map is at full stop
		 * release the contents of the map, invoking the
		 * detactivation protocol as addresses are released
		 */
		mutex_exit(&mapp->dam_lock);
		for (i = 1; i < mapp->dam_high; i++) {
			if (ddi_get_soft_state(mapp->dam_da, i) == NULL)
				continue;

			ASSERT(DAM_IN_REPORT(mapp, i) == 0);

			if (DAM_IS_STABLE(mapp, i)) {
				dam_addr_deactivate(mapp, i);
			} else {
				ddi_strid_free(mapp->dam_addr_hash, i);
				ddi_soft_state_free(mapp->dam_da, i);
			}
		}
		ddi_strid_fini(&mapp->dam_addr_hash);
		ddi_soft_state_fini(&mapp->dam_da);
		kstat_delete(mapp->dam_kstatsp);
	} else
		mutex_exit(&mapp->dam_lock);

	bitset_fini(&mapp->dam_active_set);
	bitset_fini(&mapp->dam_stable_set);
	bitset_fini(&mapp->dam_report_set);
	mutex_destroy(&mapp->dam_lock);
	cv_destroy(&mapp->dam_sync_cv);
	if (mapp->dam_name)
		kmem_free(mapp->dam_name, strlen(mapp->dam_name) + 1);
	kmem_free(mapp, sizeof (*mapp));
}

/*
 * Wait for map stability.  If sync was successfull then return 1.
 * If called with a non-zero sync_usec, then a return value of 0 means a
 * timeout occurred prior to sync completion. NOTE: if sync_usec is
 * non-zero, it should be much longer than dam_stable_ticks.
 *
 * damapp:	address map
 * sync_usec:	micorseconds until we give up on sync completion.
 */
#define	WAITFOR_FLAGS (DAM_SETADD | DAM_SPEND)
int
damap_sync(damap_t *damapp, int sync_usec)
{
	dam_t	*mapp = (dam_t *)damapp;
	int	rv;

	ASSERT(mapp);
	DTRACE_PROBE3(damap__map__sync__start,
	    char *, mapp->dam_name, dam_t *, mapp,
	    int, sync_usec);

	/*
	 * Block when waiting for
	 *	a) stabilization pending or a fullset update pending
	 *	b) the report set to finalize (bitset is null)
	 *	c) any scheduled timeouts to fire
	 */
	rv = 1;					/* return synced */
	mutex_enter(&mapp->dam_lock);
again:	while ((mapp->dam_flags & WAITFOR_FLAGS) ||
	    (!bitset_is_null(&mapp->dam_report_set)) ||
	    (mapp->dam_tid != 0)) {
		DTRACE_PROBE2(damap__map__sync__waiting,
		    char *, mapp->dam_name, dam_t *, mapp);

		/* Wait for condition relayed via timeout */
		if (sync_usec) {
			if (cv_reltimedwait(&mapp->dam_sync_cv, &mapp->dam_lock,
			    drv_usectohz(sync_usec), TR_MICROSEC) == -1) {
				mapp->dam_sync_to_cnt++;
				rv = 0;		/* return timeout */
				break;
			}
		} else
			cv_wait(&mapp->dam_sync_cv, &mapp->dam_lock);
	}

	if (rv) {
		/*
		 * Delay one stabilization time after the apparent sync above
		 * and verify accuracy - resync if not accurate.
		 */
		(void) cv_reltimedwait(&mapp->dam_sync_cv, &mapp->dam_lock,
		    mapp->dam_stable_ticks, TR_MICROSEC);
		if (rv && ((mapp->dam_flags & WAITFOR_FLAGS) ||
		    (!bitset_is_null(&mapp->dam_report_set)) ||
		    (mapp->dam_tid != 0)))
			goto again;
	}
	mutex_exit(&mapp->dam_lock);

	DTRACE_PROBE3(damap__map__sync__end,
	    char *, mapp->dam_name, dam_t *, mapp,
	    int, rv);
	return (rv);
}

/*
 * Return 1 if active set is empty
 */
int
damap_is_empty(damap_t *damapp)
{
	dam_t	*mapp = (dam_t *)damapp;
	int	rv;

	mutex_enter(&mapp->dam_lock);
	rv = bitset_is_null(&mapp->dam_active_set);
	mutex_exit(&mapp->dam_lock);
	return (rv);
}

/*
 * Get the name of a device address map
 *
 * damapp:	address map
 *
 * Returns:	name
 */
char *
damap_name(damap_t *damapp)
{
	dam_t *mapp = (dam_t *)damapp;

	return (mapp ? mapp->dam_name : "UNKNOWN_damap");
}

/*
 * Get the current size of the device address map
 *
 * damapp:	address map
 *
 * Returns:	size
 */
int
damap_size(damap_t *damapp)
{
	dam_t *mapp = (dam_t *)damapp;

	return (mapp->dam_size);
}

/*
 * Report an address to per-address report
 *
 * damapp:	address map handle
 * address:	address in ascii string representation
 * addridp:	address ID
 * nvl:		optional nvlist of configuration-private data
 * addr_priv:	optional provider-private (passed to activate/deactivate cb)
 *
 * Returns:	DAM_SUCCESS
 *		DAM_EINVAL	Invalid argument(s)
 *		DAM_MAPFULL	address map exhausted
 */
int
damap_addr_add(damap_t *damapp, char *address, damap_id_t *addridp,
    nvlist_t *nvl, void *addr_priv)
{
	dam_t *mapp = (dam_t *)damapp;
	id_t addrid;
	dam_da_t *passp;

	if (!mapp || !address || (mapp->dam_rptmode != DAMAP_REPORT_PERADDR))
		return (DAM_EINVAL);

	DTRACE_PROBE3(damap__addr__add,
	    char *, mapp->dam_name, dam_t *, mapp,
	    char *, address);

	mutex_enter(&mapp->dam_lock);
	if ((dam_map_alloc(mapp) != DAM_SUCCESS) ||
	    ((addrid = dam_get_addrid(mapp, address)) == 0)) {
		mutex_exit(&mapp->dam_lock);
		return (DAM_MAPFULL);
	}

	passp = ddi_get_soft_state(mapp->dam_da, addrid);
	ASSERT(passp != NULL);

	/*
	 * If re-reporting the same address (add or remove) clear
	 * the existing report
	 */
	if (DAM_IN_REPORT(mapp, addrid)) {
		DTRACE_PROBE3(damap__addr__add__jitter,
		    char *, mapp->dam_name, dam_t *, mapp,
		    char *, address);
		DAM_INCR_STAT(mapp, dam_jitter);
		dam_addr_report_release(mapp, addrid);
		passp->da_jitter++;
	}
	passp->da_ppriv_rpt = addr_priv;
	if (nvl)
		(void) nvlist_dup(nvl, &passp->da_nvl_rpt, KM_SLEEP);

	dam_addr_report(mapp, passp, addrid, RPT_ADDR_ADD);
	if (addridp != NULL)
		*addridp = (damap_id_t)addrid;
	mutex_exit(&mapp->dam_lock);
	return (DAM_SUCCESS);
}

/*
 * Report removal of address from per-address report
 *
 * damapp:	address map
 * address:	address in ascii string representation
 *
 * Returns:	DAM_SUCCESS
 *		DAM_EINVAL	Invalid argument(s)
 *		DAM_FAILURE	General failure
 */
int
damap_addr_del(damap_t *damapp, char *address)
{
	dam_t *mapp = (dam_t *)damapp;
	id_t addrid;
	dam_da_t *passp;

	if (!mapp || !address || (mapp->dam_rptmode != DAMAP_REPORT_PERADDR))
		return (DAM_EINVAL);

	DTRACE_PROBE3(damap__addr__del,
	    char *, mapp->dam_name, dam_t *, mapp,
	    char *, address);
	mutex_enter(&mapp->dam_lock);
	if (dam_map_alloc(mapp) != DAM_SUCCESS) {
		mutex_exit(&mapp->dam_lock);
		return (DAM_MAPFULL);
	}

	/*
	 * if reporting the removal of an address which is not in the map
	 * return success
	 */
	if (!(addrid = ddi_strid_str2id(mapp->dam_addr_hash, address))) {
		mutex_exit(&mapp->dam_lock);
		return (DAM_SUCCESS);
	}
	passp = ddi_get_soft_state(mapp->dam_da, addrid);
	ASSERT(passp);
	if (DAM_IN_REPORT(mapp, addrid)) {
		DTRACE_PROBE3(damap__addr__del__jitter,
		    char *, mapp->dam_name, dam_t *, mapp,
		    char *, address);
		DAM_INCR_STAT(mapp, dam_jitter);
		dam_addr_report_release(mapp, addrid);
		passp->da_jitter++;
	}
	dam_addr_report(mapp, passp, addrid, RPT_ADDR_DEL);
	mutex_exit(&mapp->dam_lock);
	return (DAM_SUCCESS);
}

static int
damap_addrset_flush_locked(damap_t *damapp)
{
	dam_t	*mapp = (dam_t *)damapp;
	int	idx;

	ASSERT(mapp);
	ASSERT(mutex_owned(&mapp->dam_lock));
	if (mapp->dam_rptmode != DAMAP_REPORT_FULLSET) {
		return (DAM_EINVAL);
	}

	DTRACE_PROBE2(damap__addrset__flush__locked__enter,
	    char *, mapp->dam_name, dam_t *, mapp);
	if (mapp->dam_flags & DAM_SETADD) {
		DTRACE_PROBE2(damap__addrset__flush__locked__reset,
		    char *, mapp->dam_name, dam_t *, mapp);

		/*
		 * cancel stabilization timeout
		 */
		dam_sched_timeout(NULL, mapp, 0);
		DAM_INCR_STAT(mapp, dam_jitter);

		/*
		 * clear pending reports
		 */
		for (idx = 1; idx < mapp->dam_high; idx++) {
			if (DAM_IN_REPORT(mapp, idx)) {
				dam_addr_report_release(mapp, idx);
			}
		}

		bitset_zero(&mapp->dam_report_set);
		mapp->dam_flags &= ~DAM_SETADD;
		cv_signal(&mapp->dam_sync_cv);
	}

	return (DAM_SUCCESS);
}

/*
 * Initiate full-set report
 *
 * damapp:	address map
 *
 * Returns:	DAM_SUCCESS
 *		DAM_EINVAL	Invalid argument(s)
 */
int
damap_addrset_begin(damap_t *damapp)
{
	dam_t	*mapp = (dam_t *)damapp;
	int	rv;

	if (mapp == NULL) {
		return (DAM_EINVAL);
	}

	DTRACE_PROBE2(damap__addrset__begin,
	    char *, mapp->dam_name, dam_t *, mapp);

	mutex_enter(&mapp->dam_lock);
	if (dam_map_alloc(mapp) != DAM_SUCCESS) {
		mutex_exit(&mapp->dam_lock);

		return (DAM_MAPFULL);
	}

	rv = damap_addrset_flush_locked(damapp);
	if (rv == DAM_SUCCESS) {
		mapp->dam_flags |= DAM_SETADD;
	}
	mutex_exit(&mapp->dam_lock);

	return (rv);
}

/*
 * Cancel full-set report
 *
 * damapp:	address map
 *
 * Returns:	DAM_SUCCESS
 *		DAM_EINVAL	Invalid argument(s)
 */
int
damap_addrset_flush(damap_t *damapp)
{
	int	rv;
	dam_t	*mapp = (dam_t *)damapp;

	if (mapp == NULL) {
		return (DAM_EINVAL);
	}

	DTRACE_PROBE2(damap__addrset__flush,
	    char *, mapp->dam_name, dam_t *, mapp);

	mutex_enter(&mapp->dam_lock);
	rv = damap_addrset_flush_locked(damapp);
	mutex_exit(&mapp->dam_lock);

	return (rv);
}

/*
 * Report address to full-set report
 *
 * damapp:	address map handle
 * address:	address in ascii string representation
 * rindx:	index if address stabilizes
 * nvl:		optional nvlist of configuration-private data
 * addr_priv:	optional provider-private data (passed to activate/release cb)
 *
 * Returns:	DAM_SUCCESS
 *		DAM_EINVAL	Invalid argument(s)
 *		DAM_MAPFULL	address map exhausted
 *		DAM_FAILURE	General failure
 */
int
damap_addrset_add(damap_t *damapp, char *address, damap_id_t *ridx,
    nvlist_t *nvl, void *addr_priv)
{
	dam_t *mapp = (dam_t *)damapp;
	id_t addrid;
	dam_da_t *passp;

	if (!mapp || !address || (mapp->dam_rptmode != DAMAP_REPORT_FULLSET))
		return (DAM_EINVAL);

	DTRACE_PROBE3(damap__addrset__add,
	    char *, mapp->dam_name, dam_t *, mapp, char *, address);

	mutex_enter(&mapp->dam_lock);
	if (!(mapp->dam_flags & DAM_SETADD)) {
		mutex_exit(&mapp->dam_lock);
		return (DAM_FAILURE);
	}

	if ((addrid = dam_get_addrid(mapp, address)) == 0) {
		mutex_exit(&mapp->dam_lock);
		return (DAM_MAPFULL);
	}

	passp = ddi_get_soft_state(mapp->dam_da, addrid);
	ASSERT(passp);
	if (DAM_IN_REPORT(mapp, addrid)) {
		DTRACE_PROBE3(damap__addrset__add__jitter,
		    char *, mapp->dam_name, dam_t *, mapp,
		    char *, address);
		dam_addr_report_release(mapp, addrid);
		passp->da_jitter++;
	}
	passp->da_ppriv_rpt = addr_priv;
	if (nvl)
		(void) nvlist_dup(nvl, &passp->da_nvl_rpt, KM_SLEEP);
	bitset_add(&mapp->dam_report_set, addrid);
	if (ridx)
		*ridx = (damap_id_t)addrid;
	mutex_exit(&mapp->dam_lock);
	return (DAM_SUCCESS);
}

/*
 * Commit full-set report for stabilization
 *
 * damapp:	address map handle
 * flags:	(currently 0)
 *
 * Returns:	DAM_SUCCESS
 *		DAM_EINVAL	Invalid argument(s)
 *		DAM_FAILURE	General failure
 */
int
damap_addrset_end(damap_t *damapp, int flags)
{
	dam_t *mapp = (dam_t *)damapp;
	int i;

	if (!mapp || (mapp->dam_rptmode != DAMAP_REPORT_FULLSET))
		return (DAM_EINVAL);

	DTRACE_PROBE2(damap__addrset__end,
	    char *, mapp->dam_name, dam_t *, mapp);

	mutex_enter(&mapp->dam_lock);
	if (!(mapp->dam_flags & DAM_SETADD)) {
		mutex_exit(&mapp->dam_lock);
		return (DAM_FAILURE);
	}

	if (flags & DAMAP_END_RESET) {
		DTRACE_PROBE2(damap__addrset__end__reset,
		    char *, mapp->dam_name, dam_t *, mapp);
		dam_sched_timeout(NULL, mapp, 0);
		for (i = 1; i < mapp->dam_high; i++)
			if (DAM_IN_REPORT(mapp, i))
				dam_addr_report_release(mapp, i);
	} else {
		mapp->dam_last_update = gethrtime();
		dam_sched_timeout(dam_addrset_stable_cb, mapp,
		    mapp->dam_stable_ticks);
	}
	mutex_exit(&mapp->dam_lock);
	return (DAM_SUCCESS);
}

/*
 * Return nvlist registered with reported address
 *
 * damapp:	address map handle
 * addrid:	address ID
 *
 * Returns:	nvlist_t *	provider supplied via damap_addr{set}_add())
 *		NULL
 */
nvlist_t *
damap_id2nvlist(damap_t *damapp, damap_id_t addrid)
{
	dam_t *mapp = (dam_t *)damapp;
	dam_da_t *pass;

	if (mapp->dam_high && ddi_strid_id2str(mapp->dam_addr_hash, addrid)) {
		if (pass = ddi_get_soft_state(mapp->dam_da, addrid))
			return (pass->da_nvl);
	}
	return (NULL);
}

/*
 * Return address string
 *
 * damapp:	address map handle
 * addrid:	address ID
 *
 * Returns:	char *		Address string
 *		NULL
 */
char *
damap_id2addr(damap_t *damapp, damap_id_t addrid)
{
	dam_t *mapp = (dam_t *)damapp;

	if (mapp->dam_high)
		return (ddi_strid_id2str(mapp->dam_addr_hash, addrid));
	else
		return (NULL);
}

/*
 * Release address reference in map
 *
 * damapp:	address map handle
 * addrid:	address ID
 */
void
damap_id_rele(damap_t *damapp, damap_id_t addrid)
{
	dam_t *mapp = (dam_t *)damapp;
	dam_da_t *passp;
	char *addr;

	passp = ddi_get_soft_state(mapp->dam_da, (id_t)addrid);
	ASSERT(passp);

	addr = damap_id2addr(damapp, addrid);
	DTRACE_PROBE4(damap__id__rele,
	    char *, mapp->dam_name, dam_t *, mapp,
	    char *, addr, int, passp->da_ref);

	mutex_enter(&mapp->dam_lock);

	/*
	 * teardown address if last outstanding reference
	 */
	if (--passp->da_ref == 0)
		dam_addr_release(mapp, (id_t)addrid);

	mutex_exit(&mapp->dam_lock);
}

/*
 * Return current reference count on address reference in map
 *
 * damapp:	address map handle
 * addrid:	address ID
 *
 * Returns:	DAM_SUCCESS
 *		DAM_FAILURE
 */
int
damap_id_ref(damap_t *damapp, damap_id_t addrid)
{
	dam_t *mapp = (dam_t *)damapp;
	dam_da_t *passp;
	int ref = -1;

	passp = ddi_get_soft_state(mapp->dam_da, (id_t)addrid);
	if (passp)
		ref = passp->da_ref;

	return (ref);
}

/*
 * Return next address ID in list
 *
 * damapp:	address map handle
 * damap_list:	address ID list passed to config|unconfig
 *		returned by look by lookup_all
 * last:	last ID returned, 0 is start of list
 *
 * Returns:	addrid		Next ID from the list
 *		0		End of the list
 */
damap_id_t
damap_id_next(damap_t *damapp, damap_id_list_t damap_list, damap_id_t last)
{
	int i, start;
	dam_t *mapp = (dam_t *)damapp;
	bitset_t *dam_list = (bitset_t *)damap_list;

	if (!mapp || !dam_list)
		return ((damap_id_t)0);

	start = (int)last + 1;
	for (i = start; i < mapp->dam_high; i++) {
		if (bitset_in_set(dam_list, i)) {
			return ((damap_id_t)i);
		}
	}
	return ((damap_id_t)0);
}

/*
 * Set config private data
 *
 * damapp:	address map handle
 * addrid:	address ID
 * cfg_priv:	configuration private data
 *
 */
void
damap_id_priv_set(damap_t *damapp, damap_id_t addrid, void *cfg_priv)
{
	dam_t *mapp = (dam_t *)damapp;
	dam_da_t *passp;

	mutex_enter(&mapp->dam_lock);
	passp = ddi_get_soft_state(mapp->dam_da, (id_t)addrid);
	if (!passp) {
		mutex_exit(&mapp->dam_lock);
		return;
	}
	passp->da_cfg_priv = cfg_priv;
	mutex_exit(&mapp->dam_lock);
}

/*
 * Get config private data
 *
 * damapp:	address map handle
 * addrid:	address ID
 *
 * Returns:	configuration private data
 */
void *
damap_id_priv_get(damap_t *damapp, damap_id_t addrid)
{
	dam_t *mapp = (dam_t *)damapp;
	dam_da_t *passp;
	void *rv;

	mutex_enter(&mapp->dam_lock);
	passp = ddi_get_soft_state(mapp->dam_da, (id_t)addrid);
	if (!passp) {
		mutex_exit(&mapp->dam_lock);
		return (NULL);
	}
	rv = passp->da_cfg_priv;
	mutex_exit(&mapp->dam_lock);
	return (rv);
}

/*
 * Lookup a single address in the active address map
 *
 * damapp:	address map handle
 * address:	address string
 *
 * Returns:	ID of active/stable address
 *		0	Address not in stable set
 *
 * Future: Allow the caller to wait for stabilize before returning not found.
 */
damap_id_t
damap_lookup(damap_t *damapp, char *address)
{
	dam_t *mapp = (dam_t *)damapp;
	id_t addrid = 0;
	dam_da_t *passp = NULL;

	DTRACE_PROBE3(damap__lookup,
	    char *, mapp->dam_name, dam_t *, mapp,
	    char *, address);
	mutex_enter(&mapp->dam_lock);
	if (!mapp->dam_high)
		addrid = 0;
	else
		addrid = ddi_strid_str2id(mapp->dam_addr_hash, address);
	if (addrid) {
		if (DAM_IS_STABLE(mapp, addrid)) {
			passp = ddi_get_soft_state(mapp->dam_da, addrid);
			ASSERT(passp);
			if (passp) {
				passp->da_ref++;
			} else {
				addrid = 0;
			}
		} else {
			addrid = 0;
		}
	}
	mutex_exit(&mapp->dam_lock);
	DTRACE_PROBE4(damap__lookup__return,
	    char *, mapp->dam_name, dam_t *, mapp,
	    char *, address, int, addrid);
	return ((damap_id_t)addrid);
}


/*
 * Return the list of stable addresses in the map
 *
 * damapp:	address map handle
 * id_listp:	pointer to list of address IDs in stable map (returned)
 *
 * Returns:	# of entries returned in alist
 */
int
damap_lookup_all(damap_t *damapp, damap_id_list_t *id_listp)
{
	dam_t *mapp = (dam_t *)damapp;
	int mapsz = mapp->dam_size;
	int n_ids, i;
	bitset_t *bsp;
	char	 *addrp;
	dam_da_t *passp;

	DTRACE_PROBE2(damap__lookup__all,
	    char *, mapp->dam_name, dam_t *, mapp);
	mutex_enter(&mapp->dam_lock);
	if (!mapp->dam_high) {
		*id_listp = (damap_id_list_t)NULL;
		mutex_exit(&mapp->dam_lock);
		DTRACE_PROBE2(damap__lookup__all__nomap,
		    char *, mapp->dam_name, dam_t *, mapp);
		return (0);
	}
	bsp = kmem_alloc(sizeof (*bsp), KM_SLEEP);
	bitset_init(bsp);
	bitset_resize(bsp, mapsz);
	bitset_copy(&mapp->dam_active_set, bsp);
	for (n_ids = 0, i = 1; i < mapsz; i++) {
		if (bitset_in_set(bsp, i)) {
			passp = ddi_get_soft_state(mapp->dam_da, i);
			ASSERT(passp);
			if (passp) {
				addrp = damap_id2addr(damapp, i);
				DTRACE_PROBE3(damap__lookup__all__item,
				    char *, mapp->dam_name, dam_t *, mapp,
				    char *, addrp);
				passp->da_ref++;
				n_ids++;
			}
		}
	}
	if (n_ids) {
		*id_listp = (damap_id_list_t)bsp;
		mutex_exit(&mapp->dam_lock);
		return (n_ids);
	} else {
		*id_listp = (damap_id_list_t)NULL;
		bitset_fini(bsp);
		kmem_free(bsp, sizeof (*bsp));
		mutex_exit(&mapp->dam_lock);
		return (0);
	}
}

/*
 * Release the address list returned by damap_lookup_all()
 *
 * mapp:	address map handle
 * id_list:	list of address IDs returned in damap_lookup_all()
 */
void
damap_id_list_rele(damap_t *damapp, damap_id_list_t id_list)
{
	dam_t *mapp = (dam_t *)damapp;
	int i;

	if (id_list == NULL)
		return;

	mutex_enter(&mapp->dam_lock);
	for (i = 1; i < mapp->dam_high; i++) {
		if (bitset_in_set((bitset_t *)id_list, i))
			(void) dam_addr_release(mapp, i);
	}
	mutex_exit(&mapp->dam_lock);
	bitset_fini((bitset_t *)id_list);
	kmem_free((void *)id_list, sizeof (bitset_t));
}

/*
 * activate an address that has passed the stabilization interval
 */
static void
dam_addr_activate(dam_t *mapp, id_t addrid)
{
	dam_da_t *passp;
	int config_rv;
	char *addrstr;

	mutex_enter(&mapp->dam_lock);
	bitset_add(&mapp->dam_active_set, addrid);
	passp = ddi_get_soft_state(mapp->dam_da, addrid);
	ASSERT(passp);

	/*
	 * copy the reported nvlist and provider private data
	 */
	addrstr = ddi_strid_id2str(mapp->dam_addr_hash, addrid);
	DTRACE_PROBE3(damap__addr__activate__start,
	    char *, mapp->dam_name, dam_t *, mapp,
	    char *, addrstr);
	passp->da_nvl = passp->da_nvl_rpt;
	passp->da_ppriv = passp->da_ppriv_rpt;
	passp->da_ppriv_rpt = NULL;
	passp->da_nvl_rpt = NULL;
	passp->da_last_stable = gethrtime();
	passp->da_stable_cnt++;
	mutex_exit(&mapp->dam_lock);
	if (mapp->dam_activate_cb) {
		(*mapp->dam_activate_cb)(mapp->dam_activate_arg, addrstr,
		    addrid, &passp->da_ppriv_rpt);
	}

	/*
	 * call the address-specific configuration action as part of
	 * activation.
	 */
	config_rv = (*mapp->dam_configure_cb)(mapp->dam_config_arg, mapp,
	    addrid);
	if (config_rv != DAM_SUCCESS) {
		mutex_enter(&mapp->dam_lock);
		passp->da_flags |= DA_FAILED_CONFIG;
		mutex_exit(&mapp->dam_lock);
		DTRACE_PROBE3(damap__addr__activate__config__failure,
		    char *, mapp->dam_name, dam_t *, mapp,
		    char *, addrstr);
		dam_deact_cleanup(mapp, addrid, addrstr,
		    DAMAP_DEACT_RSN_CFG_FAIL);
	} else {
		DTRACE_PROBE3(damap__addr__activate__end,
		    char *, mapp->dam_name, dam_t *, mapp,
		    char *, addrstr);
	}
}

/*
 * deactivate a previously stable address
 */
static void
dam_addr_deactivate(dam_t *mapp, id_t addrid)
{
	char *addrstr;

	addrstr = ddi_strid_id2str(mapp->dam_addr_hash, addrid);
	DTRACE_PROBE3(damap__addr__deactivate__start,
	    char *, mapp->dam_name, dam_t *, mapp,
	    char *, addrstr);

	/*
	 * call the unconfiguration callback
	 */
	(*mapp->dam_unconfig_cb)(mapp->dam_config_arg, mapp, addrid);
	dam_deact_cleanup(mapp, addrid, addrstr, DAMAP_DEACT_RSN_GONE);
}

static void
dam_deact_cleanup(dam_t *mapp, id_t addrid, char *addrstr,
    damap_deact_rsn_t deact_rsn)
{
	dam_da_t *passp;

	passp = ddi_get_soft_state(mapp->dam_da, addrid);
	ASSERT(passp);
	if (mapp->dam_deactivate_cb)
		(*mapp->dam_deactivate_cb)(mapp->dam_activate_arg,
		    ddi_strid_id2str(mapp->dam_addr_hash, addrid),
		    addrid, passp->da_ppriv, deact_rsn);

	/*
	 * clear the active bit and free the backing info for
	 * this address
	 */
	mutex_enter(&mapp->dam_lock);
	bitset_del(&mapp->dam_active_set, addrid);
	passp->da_ppriv = NULL;
	if (passp->da_nvl)
		nvlist_free(passp->da_nvl);
	passp->da_nvl = NULL;
	passp->da_ppriv_rpt = NULL;
	if (passp->da_nvl_rpt)
		nvlist_free(passp->da_nvl_rpt);
	passp->da_nvl_rpt = NULL;

	DTRACE_PROBE3(damap__addr__deactivate__end,
	    char *, mapp->dam_name, dam_t *, mapp,
	    char *, addrstr);

	(void) dam_addr_release(mapp, addrid);
	mutex_exit(&mapp->dam_lock);
}

/*
 * taskq callback for multi-thread activation
 */
static void
dam_tq_config(void *arg)
{
	cfg_tqd_t *tqd = (cfg_tqd_t *)arg;

	dam_addr_activate(tqd->tqd_mapp, tqd->tqd_id);
	kmem_free(tqd, sizeof (*tqd));
}

/*
 * taskq callback for multi-thread deactivation
 */
static void
dam_tq_unconfig(void *arg)
{
	cfg_tqd_t *tqd = (cfg_tqd_t *)arg;

	dam_addr_deactivate(tqd->tqd_mapp, tqd->tqd_id);
	kmem_free(tqd, sizeof (*tqd));
}

/*
 * Activate a set of stabilized addresses
 */
static void
dam_addrset_activate(dam_t *mapp, bitset_t *activate)
{

	int i, nset;
	taskq_t *tqp = NULL;
	cfg_tqd_t *tqd = NULL;
	char tqn[TASKQ_NAMELEN];
	extern pri_t maxclsyspri;

	if (mapp->dam_options & DAMAP_MTCONFIG) {
		/*
		 * calculate the # of taskq threads to create
		 */
		for (i = 1, nset = 0; i < mapp->dam_high; i++)
			if (bitset_in_set(activate, i))
				nset++;
		ASSERT(nset);
		(void) snprintf(tqn, sizeof (tqn), "actv-%s", mapp->dam_name);
		tqp = taskq_create(tqn, nset, maxclsyspri, 1,
		    INT_MAX, TASKQ_PREPOPULATE);
	}
	for (i = 1; i < mapp->dam_high; i++) {
		if (bitset_in_set(activate, i)) {
			if (!tqp)
				dam_addr_activate(mapp, i);
			else {
				/*
				 * multi-threaded activation
				 */
				tqd = kmem_alloc(sizeof (*tqd), KM_SLEEP);
				tqd->tqd_mapp = mapp;
				tqd->tqd_id = i;
				(void) taskq_dispatch(tqp, dam_tq_config,
				    tqd, TQ_SLEEP);
			}
		}
	}
	if (tqp) {
		taskq_wait(tqp);
		taskq_destroy(tqp);
	}
}

/*
 * Deactivate a set of stabilized addresses
 */
static void
dam_addrset_deactivate(dam_t *mapp, bitset_t *deactivate)
{
	int i, nset;
	taskq_t *tqp = NULL;
	cfg_tqd_t *tqd = NULL;
	char tqn[TASKQ_NAMELEN];

	DTRACE_PROBE2(damap__addrset__deactivate,
	    char *, mapp->dam_name, dam_t *, mapp);

	if (mapp->dam_options & DAMAP_MTCONFIG) {
		/*
		 * compute the # of taskq threads to dispatch
		 */
		for (i = 1, nset = 0; i < mapp->dam_high; i++)
			if (bitset_in_set(deactivate, i))
				nset++;
		(void) snprintf(tqn, sizeof (tqn), "deactv-%s",
		    mapp->dam_name);
		tqp = taskq_create(tqn, nset, maxclsyspri, 1,
		    INT_MAX, TASKQ_PREPOPULATE);
	}
	for (i = 1; i < mapp->dam_high; i++) {
		if (bitset_in_set(deactivate, i)) {
			if (!tqp) {
				dam_addr_deactivate(mapp, i);
			} else {
				tqd = kmem_alloc(sizeof (*tqd), KM_SLEEP);
				tqd->tqd_mapp = mapp;
				tqd->tqd_id = i;
				(void) taskq_dispatch(tqp,
				    dam_tq_unconfig, tqd, TQ_SLEEP);
			}
		}
	}

	if (tqp) {
		taskq_wait(tqp);
		taskq_destroy(tqp);
	}
}

/*
 * Release a previously activated address
 */
static void
dam_addr_release(dam_t *mapp, id_t addrid)
{
	dam_da_t *passp;
	char	 *addrstr;


	ASSERT(mutex_owned(&mapp->dam_lock));
	passp = ddi_get_soft_state(mapp->dam_da, addrid);
	ASSERT(passp);

	addrstr = ddi_strid_id2str(mapp->dam_addr_hash, addrid);
	DTRACE_PROBE3(damap__addr__release,
	    char *, mapp->dam_name, dam_t *, mapp,
	    char *, addrstr);

	/*
	 * defer releasing the address until outstanding references
	 * are released
	 */
	if (passp->da_ref > 1) {
		DTRACE_PROBE4(damap__addr__release__outstanding__refs,
		    char *, mapp->dam_name, dam_t *, mapp,
		    char *, addrstr, int, passp->da_ref);
		return;
	}

	/*
	 * allow pending reports to stabilize
	 */
	if (DAM_IN_REPORT(mapp, addrid)) {
		DTRACE_PROBE3(damap__addr__release__report__pending,
		    char *, mapp->dam_name, dam_t *, mapp,
		    char *, addrstr);
		return;
	}

	ddi_strid_free(mapp->dam_addr_hash, addrid);
	ddi_soft_state_free(mapp->dam_da, addrid);
}

/*
 * process stabilized address reports
 */
static void
dam_stabilize_map(void *arg)
{
	dam_t *mapp = (dam_t *)arg;
	bitset_t delta;
	bitset_t cfg;
	bitset_t uncfg;
	int has_cfg, has_uncfg;
	uint32_t i, n_active;

	DTRACE_PROBE2(damap__stabilize__map,
	    char *, mapp->dam_name, dam_t *, mapp);

	bitset_init(&delta);
	bitset_resize(&delta, mapp->dam_size);
	bitset_init(&cfg);
	bitset_resize(&cfg, mapp->dam_size);
	bitset_init(&uncfg);
	bitset_resize(&uncfg, mapp->dam_size);

	/*
	 * determine which addresses have changed during
	 * this stabilization cycle
	 */
	mutex_enter(&mapp->dam_lock);
	ASSERT(mapp->dam_flags & DAM_SPEND);
	if (!bitset_xor(&mapp->dam_active_set, &mapp->dam_stable_set,
	    &delta)) {
		/*
		 * no difference
		 */
		bitset_zero(&mapp->dam_stable_set);
		mapp->dam_flags &= ~DAM_SPEND;
		cv_signal(&mapp->dam_sync_cv);
		mutex_exit(&mapp->dam_lock);

		bitset_fini(&uncfg);
		bitset_fini(&cfg);
		bitset_fini(&delta);
		DTRACE_PROBE2(damap__stabilize__map__nochange,
		    char *, mapp->dam_name, dam_t *, mapp);
		return;
	}

	/*
	 * compute the sets of addresses to be activated and deactivated
	 */
	has_cfg = bitset_and(&delta, &mapp->dam_stable_set, &cfg);
	has_uncfg = bitset_and(&delta, &mapp->dam_active_set, &uncfg);

	/*
	 * drop map lock while invoking callouts
	 */
	mutex_exit(&mapp->dam_lock);

	/*
	 * activate all newly stable addresss
	 */
	if (has_cfg)
		dam_addrset_activate(mapp, &cfg);

	/*
	 * deactivate addresss which are no longer in the map
	 */
	if (has_uncfg)
		dam_addrset_deactivate(mapp, &uncfg);


	/*
	 * timestamp the last stable time and increment the kstat keeping
	 * the # of of stable cycles for the map
	 */
	mutex_enter(&mapp->dam_lock);
	bitset_zero(&mapp->dam_stable_set);
	mapp->dam_last_stable = gethrtime();
	mapp->dam_stable_cnt++;
	DAM_INCR_STAT(mapp, dam_cycles);

	/*
	 * determine the number of stable addresses
	 * and update the n_active kstat for this map
	 */
	for (i = 1, n_active = 0; i < mapp->dam_high; i++)
		if (bitset_in_set(&mapp->dam_active_set, i))
			n_active++;
	DAM_SET_STAT(mapp, dam_active, n_active);

	DTRACE_PROBE3(damap__map__stable__end,
	    char *, mapp->dam_name, dam_t *, mapp,
	    int, n_active);

	mapp->dam_flags &= ~DAM_SPEND;
	cv_signal(&mapp->dam_sync_cv);
	mutex_exit(&mapp->dam_lock);

	bitset_fini(&uncfg);
	bitset_fini(&cfg);
	bitset_fini(&delta);
}

/*
 * per-address stabilization timeout
 */
static void
dam_addr_stable_cb(void *arg)
{
	dam_t *mapp = (dam_t *)arg;
	int i;
	dam_da_t *passp;
	int spend = 0;
	int tpend = 0;
	int64_t ts, next_ticks, delta_ticks;

	mutex_enter(&mapp->dam_lock);
	if (mapp->dam_tid == 0) {
		DTRACE_PROBE2(damap__map__addr__stable__cancelled,
		    char *, mapp->dam_name, dam_t *, mapp);
		mutex_exit(&mapp->dam_lock);
		return;
	}
	mapp->dam_tid = 0;

	/*
	 * If still under stabilization, reschedule timeout,
	 * otherwise dispatch the task to activate and deactivate the
	 * new stable address
	 */
	if (mapp->dam_flags & DAM_SPEND) {
		DAM_INCR_STAT(mapp, dam_overrun);
		mapp->dam_stable_overrun++;
		DTRACE_PROBE2(damap__map__addr__stable__overrun,
		    char *, mapp->dam_name, dam_t *, mapp);
		dam_sched_timeout(dam_addr_stable_cb, mapp,
		    mapp->dam_stable_ticks);
		mutex_exit(&mapp->dam_lock);
		return;
	}

	DAM_SET_STAT(mapp, dam_overrun, 0);
	mapp->dam_stable_overrun = 0;

	/* See if any reports stabalized and compute next timeout. */
	ts = ddi_get_lbolt64();
	next_ticks = mapp->dam_stable_ticks;
	for (i = 1; i < mapp->dam_high; i++) {
		if (bitset_in_set(&mapp->dam_report_set, i)) {
			passp = ddi_get_soft_state(mapp->dam_da, i);
			ASSERT(passp);

			if (passp->da_deadline <= ts)
				spend++;	/* report has stabilized */
			else {
				/* not stabilized, determine next map timeout */
				tpend++;
				delta_ticks = passp->da_deadline - ts;
				if (delta_ticks < next_ticks)
					next_ticks = delta_ticks;
			}
		}
	}

	/*
	 * schedule system_taskq activation of stabilized reports
	 */
	if (spend) {
		if (taskq_dispatch(system_taskq, dam_stabilize_map,
		    mapp, TQ_NOSLEEP | TQ_NOQUEUE)) {
			DTRACE_PROBE2(damap__map__addr__stable__start,
			    char *, mapp->dam_name, dam_t *, mapp);

			/*
			 * The stable_set we compute below stays pending until
			 * processed by dam_stabilize_map. We can't set
			 * DAM_SPEND (or bitset_del things from the
			 * report_set) until we *know* that we can handoff the
			 * result to dam_stabilize_map. If dam_stabilize_map
			 * starts executing before we are complete, it will
			 * block on the dam_lock mutex until we are ready.
			 */
			mapp->dam_flags |= DAM_SPEND;

			/*
			 * Copy the current active_set to the stable_set, then
			 * add or remove stabilized report_set address from
			 * the stable set (and delete them from the report_set).
			 */
			bitset_copy(&mapp->dam_active_set,
			    &mapp->dam_stable_set);
			for (i = 1; i < mapp->dam_high; i++) {
				if (!bitset_in_set(&mapp->dam_report_set, i))
					continue;

				passp = ddi_get_soft_state(mapp->dam_da, i);
				if (passp->da_deadline > ts)
					continue; /* report not stabilized */

				/* report has stabilized */
				if (passp->da_flags & DA_RELE)
					bitset_del(&mapp->dam_stable_set, i);
				else
					bitset_add(&mapp->dam_stable_set, i);

				bitset_del(&mapp->dam_report_set, i);
			}
		} else {
			DTRACE_PROBE2(damap__map__addr__stable__spendfail,
			    char *, mapp->dam_name, dam_t *, mapp);

			/*
			 * Avoid waiting the entire stabalization
			 * time again if taskq_diskpatch fails.
			 */
			tpend++;
			delta_ticks = drv_usectohz(
			    damap_taskq_dispatch_retry_usec);
			if (delta_ticks < next_ticks)
				next_ticks = delta_ticks;
		}
	}

	/*
	 * reschedule the stabilization timer if there are reports
	 * still pending
	 */
	if (tpend) {
		DTRACE_PROBE2(damap__map__addr__stable__tpend, char *,
		    mapp->dam_name, dam_t *, mapp);
		dam_sched_timeout(dam_addr_stable_cb, mapp,
		    (clock_t)next_ticks);
	}

	mutex_exit(&mapp->dam_lock);
}

/*
 * fullset stabilization timeout callback
 */
static void
dam_addrset_stable_cb(void *arg)
{
	dam_t *mapp = (dam_t *)arg;

	mutex_enter(&mapp->dam_lock);
	if (mapp->dam_tid == 0) {
		mutex_exit(&mapp->dam_lock);
		DTRACE_PROBE2(damap__map__addrset__stable__cancelled,
		    char *, mapp->dam_name, dam_t *, mapp);
		return;
	}
	mapp->dam_tid = 0;

	/*
	 * If map still underoing stabilization reschedule timeout,
	 * else dispatch the task to configure the new stable set of
	 * addresses.
	 */
	if ((mapp->dam_flags & DAM_SPEND) ||
	    (taskq_dispatch(system_taskq, dam_stabilize_map, mapp,
	    TQ_NOSLEEP | TQ_NOQUEUE) == NULL)) {
		DAM_INCR_STAT(mapp, dam_overrun);
		mapp->dam_stable_overrun++;
		dam_sched_timeout(dam_addrset_stable_cb, mapp,
		    drv_usectohz(damap_taskq_dispatch_retry_usec));

		DTRACE_PROBE2(damap__map__addrset__stable__overrun,
		    char *, mapp->dam_name, dam_t *, mapp);
		mutex_exit(&mapp->dam_lock);
		return;
	}

	DAM_SET_STAT(mapp, dam_overrun, 0);
	mapp->dam_stable_overrun = 0;
	bitset_copy(&mapp->dam_report_set, &mapp->dam_stable_set);
	bitset_zero(&mapp->dam_report_set);
	mapp->dam_flags |= DAM_SPEND;
	mapp->dam_flags &= ~DAM_SETADD;
	/* NOTE: don't need cv_signal since DAM_SPEND is still set */

	DTRACE_PROBE2(damap__map__addrset__stable__start,
	    char *, mapp->dam_name, dam_t *, mapp);
	mutex_exit(&mapp->dam_lock);
}

/*
 * schedule map timeout in 'ticks' ticks
 * if map timer is currently running, cancel if ticks == 0
 */
static void
dam_sched_timeout(void (*timeout_cb)(), dam_t *mapp, clock_t ticks)
{
	timeout_id_t tid;

	DTRACE_PROBE4(damap__sched__timeout,
	    char *, mapp->dam_name, dam_t *, mapp,
	    int, ticks, timeout_id_t, mapp->dam_tid);

	ASSERT(mutex_owned(&mapp->dam_lock));
	if ((tid = mapp->dam_tid) != 0) {
		if (ticks == 0) {
			mapp->dam_tid = 0;
			mutex_exit(&mapp->dam_lock);
			(void) untimeout(tid);
			mutex_enter(&mapp->dam_lock);
		}
	} else {
		if (timeout_cb && (ticks != 0))
			mapp->dam_tid = timeout(timeout_cb, mapp, ticks);
	}
}

/*
 * report addition or removal of an address
 */
static void
dam_addr_report(dam_t *mapp, dam_da_t *passp, id_t addrid, int rpt_type)
{
	char *addrstr = damap_id2addr((damap_t *)mapp, addrid);

	DTRACE_PROBE4(damap__addr__report,
	    char *, mapp->dam_name, dam_t *, mapp,
	    char *, addrstr, int, rpt_type);

	ASSERT(mutex_owned(&mapp->dam_lock));
	ASSERT(!DAM_IN_REPORT(mapp, addrid));
	passp->da_last_report = gethrtime();
	mapp->dam_last_update = gethrtime();
	passp->da_report_cnt++;
	passp->da_deadline = ddi_get_lbolt64() + mapp->dam_stable_ticks;
	if (rpt_type == RPT_ADDR_DEL)
		passp->da_flags |= DA_RELE;
	else if (rpt_type == RPT_ADDR_ADD)
		passp->da_flags &= ~DA_RELE;
	bitset_add(&mapp->dam_report_set, addrid);
	dam_sched_timeout(dam_addr_stable_cb, mapp, mapp->dam_stable_ticks);
}

/*
 * release an address report
 */
static void
dam_addr_report_release(dam_t *mapp, id_t addrid)
{
	dam_da_t *passp;
	char *addrstr = damap_id2addr((damap_t *)mapp, addrid);

	DTRACE_PROBE3(damap__addr__report__release,
	    char *, mapp->dam_name, dam_t *, mapp,
	    char *, addrstr);

	ASSERT(mutex_owned(&mapp->dam_lock));
	passp = ddi_get_soft_state(mapp->dam_da, addrid);
	ASSERT(passp);
	/*
	 * clear the report bit
	 * if the address has a registered deactivation handler and
	 * we are holding a private data pointer and the address has not
	 * stabilized, deactivate the address (private data).
	 */
	bitset_del(&mapp->dam_report_set, addrid);
	if (!DAM_IS_STABLE(mapp, addrid) && mapp->dam_deactivate_cb &&
	    passp->da_ppriv_rpt) {
		mutex_exit(&mapp->dam_lock);
		(*mapp->dam_deactivate_cb)(mapp->dam_activate_arg,
		    ddi_strid_id2str(mapp->dam_addr_hash, addrid),
		    addrid, passp->da_ppriv_rpt, DAMAP_DEACT_RSN_UNSTBL);
		mutex_enter(&mapp->dam_lock);
	}
	passp->da_ppriv_rpt = NULL;
	if (passp->da_nvl_rpt)
		nvlist_free(passp->da_nvl_rpt);
}

/*
 * return the map ID of an address
 */
static id_t
dam_get_addrid(dam_t *mapp, char *address)
{
	damap_id_t addrid;
	dam_da_t *passp;

	ASSERT(mutex_owned(&mapp->dam_lock));
	if ((addrid = ddi_strid_str2id(mapp->dam_addr_hash, address)) == 0) {
		if ((addrid = ddi_strid_alloc(mapp->dam_addr_hash,
		    address)) == (damap_id_t)0) {
			return (0);
		}
		if (ddi_soft_state_zalloc(mapp->dam_da, addrid) !=
		    DDI_SUCCESS) {
			ddi_strid_free(mapp->dam_addr_hash, addrid);
			return (0);
		}

		if (addrid >= mapp->dam_high)
			mapp->dam_high = addrid + 1;

		/*
		 * expand bitmaps if ID has outgrown old map size
		 */
		if (mapp->dam_high > mapp->dam_size) {
			mapp->dam_size = mapp->dam_size + DAM_SIZE_BUMP;
			bitset_resize(&mapp->dam_active_set, mapp->dam_size);
			bitset_resize(&mapp->dam_stable_set, mapp->dam_size);
			bitset_resize(&mapp->dam_report_set, mapp->dam_size);
		}

		passp = ddi_get_soft_state(mapp->dam_da, addrid);
		passp->da_ref = 1;
		passp->da_addr = ddi_strid_id2str(mapp->dam_addr_hash,
		    addrid); /* for mdb */
	}
	return (addrid);
}

/*
 * create and install map statistics
 */
static int
dam_kstat_create(dam_t *mapp)
{
	kstat_t			*mapsp;
	struct dam_kstats	*statsp;

	mapsp = kstat_create("dam", 0, mapp->dam_name, "damap",
	    KSTAT_TYPE_NAMED,
	    sizeof (struct dam_kstats) / sizeof (kstat_named_t), 0);

	if (mapsp == NULL)
		return (DDI_FAILURE);

	statsp = (struct dam_kstats *)mapsp->ks_data;
	kstat_named_init(&statsp->dam_cycles, "cycles", KSTAT_DATA_UINT32);
	kstat_named_init(&statsp->dam_overrun, "overrun", KSTAT_DATA_UINT32);
	kstat_named_init(&statsp->dam_jitter, "jitter", KSTAT_DATA_UINT32);
	kstat_named_init(&statsp->dam_active, "active", KSTAT_DATA_UINT32);
	kstat_install(mapsp);
	mapp->dam_kstatsp = mapsp;
	return (DDI_SUCCESS);
}
