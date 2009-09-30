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
#include <sys/ddi_timer.h>
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

static void dam_addrset_activate(dam_t *, bitset_t *);
static void dam_addrset_release(dam_t *, bitset_t *);
static void dam_activate_taskq(void *);
static void dam_addr_stable_cb(void *);
static void dam_set_stable_cb(void *);
static void dam_sched_tmo(dam_t *, clock_t, void (*tmo_cb)());
static void dam_add_report(dam_t *, dam_da_t *, id_t, int);
static void dam_release(dam_t *, id_t);
static void dam_release_report(dam_t *, id_t);
static void dam_deactivate_addr(dam_t *, id_t);
static id_t dam_get_addrid(dam_t *, char *);
static int dam_kstat_create(dam_t *);
static void dam_kstat_destroy(dam_t *);

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
 * Create new device address map
 *
 * ident:		map name (kstat)
 * size:		max # of map entries
 * rptmode:		type or mode of reporting
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
damap_create(char *ident, size_t size, damap_rptmode_t rptmode,
    clock_t stable_usec,
    void *activate_arg, damap_activate_cb_t activate_cb,
    damap_deactivate_cb_t deactivate_cb,
    void *config_arg, damap_configure_cb_t configure_cb,
    damap_unconfig_cb_t unconfig_cb,
    damap_t **damapp)
{
	dam_t *mapp;
	void *softstate_p;

	DTRACE_PROBE1(damap__create__entry, char *, ident);
	if ((configure_cb == NULL) || (unconfig_cb == NULL))
		return (DAM_EINVAL);

	if (ddi_soft_state_init(&softstate_p, sizeof (dam_da_t), size) !=
	    DDI_SUCCESS)
		return (DAM_FAILURE);

	mapp = kmem_zalloc(sizeof (*mapp), KM_SLEEP);
	if (ddi_strid_init(&mapp->dam_addr_hash, size) != DDI_SUCCESS) {
		ddi_soft_state_fini(&softstate_p);
		kmem_free(mapp, sizeof (*mapp));
		return (DAM_FAILURE);
	}

	mapp->dam_da = softstate_p;
	mapp->dam_stabletmo = drv_usectohz(stable_usec);
	mapp->dam_size = size;
	mapp->dam_high = 1;
	mapp->dam_rptmode = rptmode;

	mapp->dam_activate_arg = activate_arg;
	mapp->dam_activate_cb = (activate_cb_t)activate_cb;
	mapp->dam_deactivate_cb = (deactivate_cb_t)deactivate_cb;

	mapp->dam_config_arg = config_arg;
	mapp->dam_configure_cb = (configure_cb_t)configure_cb;
	mapp->dam_unconfig_cb = (unconfig_cb_t)unconfig_cb;

	if (ident)
		mapp->dam_name = i_ddi_strdup(ident, KM_SLEEP);

	bitset_init(&mapp->dam_active_set);
	bitset_resize(&mapp->dam_active_set, size);
	bitset_init(&mapp->dam_stable_set);
	bitset_resize(&mapp->dam_stable_set, size);
	bitset_init(&mapp->dam_report_set);
	bitset_resize(&mapp->dam_report_set, size);
	mutex_init(&mapp->dam_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&mapp->dam_cv, NULL, CV_DRIVER, NULL);
	mapp->dam_taskqp = ddi_taskq_create(NULL, ident, 1, TASKQ_DEFAULTPRI,
	    0);
	*damapp = (damap_t *)mapp;
	if (dam_kstat_create(mapp) != DDI_SUCCESS) {
		damap_destroy((damap_t *)mapp);
		return (DAM_FAILURE);
	}

	DTRACE_PROBE1(damap__create__exit, dam_t *, mapp);
	return (DAM_SUCCESS);
}

/*
 * Destroy device address map
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

	DTRACE_PROBE2(damap__destroy__entry, dam_t *, mapp, char *,
	    mapp->dam_name);

	DAM_FLAG_SET(mapp, DAM_DESTROYPEND);
	(void) damap_sync(damapp);

	/*
	 * cancel pending timeouts and kill off the taskq
	 */
	dam_sched_tmo(mapp, 0, NULL);
	ddi_taskq_wait(mapp->dam_taskqp);
	ddi_taskq_destroy(mapp->dam_taskqp);

	for (i = 1; i < mapp->dam_high; i++) {
		if (ddi_get_soft_state(mapp->dam_da, i) == NULL)
			continue;
		if (DAM_IN_REPORT(mapp, i))
			dam_release_report(mapp, i);
		if (DAM_IS_STABLE(mapp, i))
			dam_deactivate_addr(mapp, i);
		ddi_strid_free(mapp->dam_addr_hash, i);
		ddi_soft_state_free(mapp->dam_da, i);
	}
	ddi_strid_fini(&mapp->dam_addr_hash);
	ddi_soft_state_fini(&mapp->dam_da);
	bitset_fini(&mapp->dam_active_set);
	bitset_fini(&mapp->dam_stable_set);
	bitset_fini(&mapp->dam_report_set);
	dam_kstat_destroy(mapp);
	mutex_destroy(&mapp->dam_lock);
	cv_destroy(&mapp->dam_cv);
	if (mapp->dam_name)
		kmem_free(mapp->dam_name, strlen(mapp->dam_name) + 1);
	kmem_free(mapp, sizeof (*mapp));
	DTRACE_PROBE(damap__destroy__exit);
}

/*
 * Wait for map stability.
 *
 * damapp:	address map
 */
int
damap_sync(damap_t *damapp)
{

#define	WAITFOR_FLAGS (DAM_SETADD | DAM_SPEND | MAP_LOCK)

	dam_t *mapp = (dam_t *)damapp;
	int   none_active;

	ASSERT(mapp);

	DTRACE_PROBE1(damap__sync__entry, dam_t *, mapp);

	mutex_enter(&mapp->dam_lock);
	while ((mapp->dam_flags & WAITFOR_FLAGS) ||
	    (!bitset_is_null(&mapp->dam_report_set)) || (mapp->dam_tid != 0)) {
		cv_wait(&mapp->dam_cv, &mapp->dam_lock);
	}

	none_active = bitset_is_null(&mapp->dam_active_set);

	mutex_exit(&mapp->dam_lock);
	DTRACE_PROBE2(damap__sync__exit, dam_t *, mapp, int, none_active);

	return (none_active);
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
 * Report an address to per-address report
 *
 * damapp:	address map handle
 * address:	address in ascii string representation
 * rindx:	index if address stabilizes
 * nvl:		optional nvlist of configuration-private data
 * addr_priv:	optional provider-private (passed to activate/deactivate cb)
 *
 * Returns:	DAM_SUCCESS
 *		DAM_EINVAL	Invalid argument(s)
 *		DAM_MAPFULL	address map exhausted
 */
int
damap_addr_add(damap_t *damapp, char *address, damap_id_t *ridx, nvlist_t *nvl,
    void *addr_priv)
{
	dam_t *mapp = (dam_t *)damapp;
	id_t addrid;
	dam_da_t *passp;

	DTRACE_PROBE2(damap__addr__add__entry, dam_t *, mapp,
	    char *, address);
	if (!mapp || !address || (mapp->dam_rptmode != DAMAP_REPORT_PERADDR) ||
	    (mapp->dam_flags & DAM_DESTROYPEND))
		return (DAM_EINVAL);

	DAM_LOCK(mapp, ADDR_LOCK);
	if ((addrid = dam_get_addrid(mapp, address)) == 0) {
		DAM_UNLOCK(mapp, ADDR_LOCK);
		return (DAM_MAPFULL);
	}

	passp = ddi_get_soft_state(mapp->dam_da, addrid);
	ASSERT(passp != NULL);

	/*
	 * If re-reporting the same address (add or remove) clear
	 * the existing report
	 */
	if (DAM_IN_REPORT(mapp, addrid)) {
		DAM_INCR_STAT(mapp, dam_rereport);
		dam_release_report(mapp, addrid);
		passp->da_jitter++;
	}
	passp->da_ppriv_rpt = addr_priv;
	if (nvl)
		(void) nvlist_dup(nvl, &passp->da_nvl_rpt, KM_SLEEP);

	dam_add_report(mapp, passp, addrid, RPT_ADDR_ADD);
	if (ridx != NULL)
		*ridx = (damap_id_t)addrid;
	DAM_UNLOCK(mapp, ADDR_LOCK);
	DTRACE_PROBE3(damap__addr__add__exit, dam_t *, mapp, char *,
	    address, int, addrid);
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

	DTRACE_PROBE2(damap__addr__del__entry, dam_t *, mapp,
	    char *, address);
	if (!mapp || !address || (mapp->dam_rptmode != DAMAP_REPORT_PERADDR) ||
	    (mapp->dam_flags & DAM_DESTROYPEND))
		return (DAM_EINVAL);

	DAM_LOCK(mapp, ADDR_LOCK);
	if (!(addrid = ddi_strid_str2id(mapp->dam_addr_hash, address))) {
		DAM_UNLOCK(mapp, ADDR_LOCK);
		return (DAM_SUCCESS);
	}
	passp = ddi_get_soft_state(mapp->dam_da, addrid);
	ASSERT(passp);
	if (DAM_IN_REPORT(mapp, addrid)) {
		DAM_INCR_STAT(mapp, dam_rereport);
		dam_release_report(mapp, addrid);
		passp->da_jitter++;
	}
	dam_add_report(mapp, passp, addrid, RPT_ADDR_DEL);
	DAM_UNLOCK(mapp, ADDR_LOCK);
	DTRACE_PROBE3(damap__addr__del__exit, dam_t *, mapp,
	    char *, address, int, addrid);
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
	dam_t *mapp = (dam_t *)damapp;
	int i;

	DTRACE_PROBE1(damap__addrset__begin__entry, dam_t *, mapp);

	if ((mapp->dam_rptmode != DAMAP_REPORT_FULLSET) ||
	    (mapp->dam_flags & DAM_DESTROYPEND))
		return (DAM_EINVAL);

	DAM_LOCK(mapp, MAP_LOCK);
	/*
	 * reset any pending reports
	 */
	if (mapp->dam_flags & DAM_SETADD) {
		/*
		 * cancel stabilization timeout
		 */
		dam_sched_tmo(mapp, 0, NULL);
		DAM_INCR_STAT(mapp, dam_rereport);
		DAM_UNLOCK(mapp, MAP_LOCK);
		DAM_LOCK(mapp, ADDR_LOCK);
		for (i = 1; i < mapp->dam_high; i++) {
			if (DAM_IN_REPORT(mapp, i))
				dam_release_report(mapp, i);
		}
		DAM_UNLOCK(mapp, ADDR_LOCK);
		DAM_LOCK(mapp, MAP_LOCK);
	}
	DAM_FLAG_SET(mapp, DAM_SETADD);
	bitset_zero(&mapp->dam_report_set);
	DAM_UNLOCK(mapp, MAP_LOCK);
	DTRACE_PROBE(damap__addrset__begin__exit);
	return (DAM_SUCCESS);
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

	DTRACE_PROBE2(damap__addrset__add__entry, dam_t *, mapp,
	    char *, address);

	if (!mapp || !address || (mapp->dam_rptmode != DAMAP_REPORT_FULLSET) ||
	    (mapp->dam_flags & DAM_DESTROYPEND))
		return (DAM_EINVAL);

	if (!(mapp->dam_flags & DAM_SETADD))
		return (DAM_FAILURE);

	DAM_LOCK(mapp, ADDR_LOCK);
	if ((addrid = dam_get_addrid(mapp, address)) == 0) {
		DAM_UNLOCK(mapp, ADDR_LOCK);
		return (DAM_MAPFULL);
	}

	passp = ddi_get_soft_state(mapp->dam_da, addrid);
	ASSERT(passp);
	if (DAM_IN_REPORT(mapp, addrid)) {
		dam_release_report(mapp, addrid);
		passp->da_jitter++;
	}
	passp->da_ppriv_rpt = addr_priv;
	if (nvl)
		(void) nvlist_dup(nvl, &passp->da_nvl_rpt, KM_SLEEP);
	DAM_LOCK(mapp, MAP_LOCK);
	bitset_add(&mapp->dam_report_set, addrid);
	DAM_UNLOCK(mapp, MAP_LOCK);
	if (ridx)
		*ridx = (damap_id_t)addrid;
	DAM_UNLOCK(mapp, ADDR_LOCK);
	DTRACE_PROBE3(damap__addr__addset__exit, dam_t *, mapp, char *,
	    address, int, addrid);
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

	DTRACE_PROBE1(damap__addrset__end__entry, dam_t *, mapp);

	if (!mapp || (mapp->dam_rptmode != DAMAP_REPORT_FULLSET) ||
	    (mapp->dam_flags & DAM_DESTROYPEND))
		return (DAM_EINVAL);

	if (!(mapp->dam_flags & DAM_SETADD))
		return (DAM_FAILURE);

	if (flags & DAMAP_RESET) {
		DAM_LOCK(mapp, MAP_LOCK);
		dam_sched_tmo(mapp, 0, NULL);
		DAM_UNLOCK(mapp, MAP_LOCK);
		DAM_LOCK(mapp, ADDR_LOCK);
		for (i = 1; i < mapp->dam_high; i++)
			if (DAM_IN_REPORT(mapp, i))
				dam_release_report(mapp, i);
		DAM_UNLOCK(mapp, ADDR_LOCK);
	} else {
		mapp->dam_last_update = gethrtime();
		DAM_LOCK(mapp, MAP_LOCK);
		dam_sched_tmo(mapp, mapp->dam_stabletmo, dam_set_stable_cb);
		DAM_UNLOCK(mapp, MAP_LOCK);
	}
	DTRACE_PROBE(damap__addrset__end__exit);
	return (DAM_SUCCESS);
}

/*
 * Return nvlist registered with reported address
 *
 * damapp:	address map handle
 * aid:		address ID
 *
 * Returns:	nvlist_t *	provider supplied via damap_addr{set}_add())
 *		NULL
 */
nvlist_t *
damap_id2nvlist(damap_t *damapp, damap_id_t addrid)
{
	dam_t *mapp = (dam_t *)damapp;
	id_t aid = (id_t)addrid;
	dam_da_t *pass;

	if (ddi_strid_id2str(mapp->dam_addr_hash, aid)) {
		if (pass = ddi_get_soft_state(mapp->dam_da, aid))
			return (pass->da_nvl);
	}
	return (NULL);
}

/*
 * Return address string
 *
 * damapp:	address map handle
 * aid:		address ID
 *
 * Returns:	char *		Address string
 *		NULL
 */
char *
damap_id2addr(damap_t *damapp, damap_id_t aid)
{
	dam_t *mapp = (dam_t *)damapp;

	return (ddi_strid_id2str(mapp->dam_addr_hash, (id_t)aid));
}

/*
 * Hold address reference in map
 *
 * damapp:	address map handle
 * aid:		address ID
 *
 * Returns:	DAM_SUCCESS
 *		DAM_FAILURE
 */
int
damap_id_hold(damap_t *damapp, damap_id_t aid)
{
	dam_t *mapp = (dam_t *)damapp;
	dam_da_t *passp;


	DAM_LOCK(mapp, ADDR_LOCK);
	passp = ddi_get_soft_state(mapp->dam_da, (id_t)aid);
	if (!passp) {
		DAM_UNLOCK(mapp, ADDR_LOCK);
		return (DAM_FAILURE);
	}
	passp->da_ref++;
	DAM_UNLOCK(mapp, ADDR_LOCK);
	return (DAM_SUCCESS);
}

/*
 * Release address reference in map
 *
 * damapp:	address map handle
 * aid:		address ID
 */
void
damap_id_rele(damap_t *damapp, damap_id_t addrid)
{
	dam_t *mapp = (dam_t *)damapp;

	DAM_LOCK(mapp, ADDR_LOCK);
	dam_release(mapp, (id_t)addrid);
	DAM_UNLOCK(mapp, ADDR_LOCK);
}

/*
 * Return current reference count on address reference in map
 *
 * damapp:	address map handle
 * aid:		address ID
 *
 * Returns:	DAM_SUCCESS
 *		DAM_FAILURE
 */
int
damap_id_ref(damap_t *damapp, damap_id_t aid)
{
	dam_t *mapp = (dam_t *)damapp;
	dam_da_t *passp;
	int ref = -1;

	DAM_LOCK(mapp, ADDR_LOCK);
	passp = ddi_get_soft_state(mapp->dam_da, (id_t)aid);
	if (passp)
		ref = passp->da_ref;
	DAM_UNLOCK(mapp, ADDR_LOCK);
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
	for (i = start; i < mapp->dam_high; i++)
		if (bitset_in_set(dam_list, i))
			return ((damap_id_t)i);
	return ((damap_id_t)0);
}

/*
 * Set config private data
 *
 * damapp:	address map handle
 * aid:		address ID
 * cfg_priv:	configuration private data
 *
 */
void
damap_id_priv_set(damap_t *damapp, damap_id_t aid, void *cfg_priv)
{
	dam_t *mapp = (dam_t *)damapp;
	dam_da_t *passp;


	DAM_LOCK(mapp, ADDR_LOCK);
	passp = ddi_get_soft_state(mapp->dam_da, (id_t)aid);
	if (!passp) {
		DAM_UNLOCK(mapp, ADDR_LOCK);
		return;
	}
	passp->da_cfg_priv = cfg_priv;
	DAM_UNLOCK(mapp, ADDR_LOCK);
}

/*
 * Get config private data
 *
 * damapp:	address map handle
 * aid:		address ID
 *
 * Returns:	configuration private data
 */
void *
damap_id_priv_get(damap_t *damapp, damap_id_t aid)
{
	dam_t *mapp = (dam_t *)damapp;
	dam_da_t *passp;
	void *rv;


	DAM_LOCK(mapp, ADDR_LOCK);
	passp = ddi_get_soft_state(mapp->dam_da, (id_t)aid);
	if (!passp) {
		DAM_UNLOCK(mapp, ADDR_LOCK);
		return (NULL);
	}
	rv = passp->da_cfg_priv;
	DAM_UNLOCK(mapp, ADDR_LOCK);
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

	DAM_LOCK(mapp, ADDR_LOCK);
	addrid = ddi_strid_str2id(mapp->dam_addr_hash, address);
	if (addrid) {
		DAM_LOCK(mapp, MAP_LOCK);
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
		DAM_UNLOCK(mapp, MAP_LOCK);
	}
	DAM_UNLOCK(mapp, ADDR_LOCK);
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
	dam_da_t *passp;

	bsp = kmem_alloc(sizeof (*bsp), KM_SLEEP);
	bitset_init(bsp);
	bitset_resize(bsp, mapsz);
	DAM_LOCK(mapp, MAP_LOCK);
	bitset_copy(&mapp->dam_active_set, bsp);
	DAM_UNLOCK(mapp, MAP_LOCK);
	DAM_LOCK(mapp, ADDR_LOCK);
	for (n_ids = 0, i = 1; i < mapsz; i++) {
		if (bitset_in_set(bsp, i)) {
			passp = ddi_get_soft_state(mapp->dam_da, i);
			ASSERT(passp);
			if (passp) {
				passp->da_ref++;
				n_ids++;
			}
		}
	}
	DAM_UNLOCK(mapp, ADDR_LOCK);
	if (n_ids) {
		*id_listp = (damap_id_list_t)bsp;
		return (n_ids);
	} else {
		*id_listp = (damap_id_list_t)NULL;
		bitset_fini(bsp);
		kmem_free(bsp, sizeof (*bsp));
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

	DAM_LOCK(mapp, ADDR_LOCK);
	for (i = 1; i < mapp->dam_high; i++) {
		if (bitset_in_set((bitset_t *)id_list, i))
			(void) dam_release(mapp, i);
	}
	DAM_UNLOCK(mapp, ADDR_LOCK);
	bitset_fini((bitset_t *)id_list);
	kmem_free((void *)id_list, sizeof (bitset_t));
}

/*
 * Activate a set of stabilized addresses
 */
static void
dam_addrset_activate(dam_t *mapp, bitset_t *active_set)
{
	dam_da_t *passp;
	char *addrstr;
	int i;
	uint32_t n_active = 0;

	for (i = 1; i < mapp->dam_high; i++) {
		if (bitset_in_set(&mapp->dam_active_set, i))
			n_active++;
		if (!bitset_in_set(active_set, i))
			continue;
		n_active++;
		passp = ddi_get_soft_state(mapp->dam_da, i);
		ASSERT(passp);
		if (mapp->dam_activate_cb) {
			addrstr = ddi_strid_id2str(mapp->dam_addr_hash, i);
			(*mapp->dam_activate_cb)(
			    mapp->dam_activate_arg, addrstr, i,
			    &passp->da_ppriv_rpt);
		}
		DTRACE_PROBE2(damap__addrset__activate, dam_t *, mapp, int, i);
		DAM_LOCK(mapp, MAP_LOCK);
		bitset_add(&mapp->dam_active_set, i);
		/*
		 * copy the reported nvlist and provider private data
		 */
		passp->da_nvl = passp->da_nvl_rpt;
		passp->da_ppriv = passp->da_ppriv_rpt;
		passp->da_ppriv_rpt = NULL;
		passp->da_nvl_rpt = NULL;
		passp->da_last_stable = gethrtime();
		passp->da_stable_cnt++;
		DAM_UNLOCK(mapp, MAP_LOCK);
		DAM_SET_STAT(mapp, dam_numstable, n_active);
	}
}

/*
 * Release a set of stabilized addresses
 */
static void
dam_addrset_release(dam_t *mapp, bitset_t *release_set)
{
	int i;

	DAM_LOCK(mapp, ADDR_LOCK);
	for (i = 1; i < mapp->dam_high; i++) {
		if (bitset_in_set(release_set, i)) {
			DTRACE_PROBE2(damap__addrset__release, dam_t *, mapp,
			    int, i);
			DAM_LOCK(mapp, MAP_LOCK);
			bitset_del(&mapp->dam_active_set, i);
			DAM_UNLOCK(mapp, MAP_LOCK);
			(void) dam_release(mapp, i);
		}
	}
	DAM_UNLOCK(mapp, ADDR_LOCK);
}

/*
 * release a previously activated address
 */
static void
dam_release(dam_t *mapp, id_t addrid)
{
	dam_da_t *passp;

	DAM_ASSERT_LOCKED(mapp, ADDR_LOCK);
	passp = ddi_get_soft_state(mapp->dam_da, addrid);
	ASSERT(passp);

	/*
	 * invoke the deactivation callback to notify
	 * this address is no longer active
	 */
	dam_deactivate_addr(mapp, addrid);

	/*
	 * allow pending reports for this address to stabilize
	 */
	if (DAM_IN_REPORT(mapp, addrid))
		return;

	/*
	 * defer teardown until outstanding references are released
	 */
	if (--passp->da_ref) {
		passp->da_flags |= DA_RELE;
		return;
	}
	ddi_strid_free(mapp->dam_addr_hash, addrid);
	ddi_soft_state_free(mapp->dam_da, addrid);
}

/*
 * process stabilized address reports
 */
static void
dam_activate_taskq(void *arg)
{
	dam_t *mapp = (dam_t *)arg;
	bitset_t delta;
	bitset_t cfg;
	bitset_t uncfg;
	int has_cfg, has_uncfg;

	bitset_init(&delta);
	bitset_resize(&delta, mapp->dam_size);
	bitset_init(&cfg);
	bitset_resize(&cfg, mapp->dam_size);
	bitset_init(&uncfg);
	bitset_resize(&uncfg, mapp->dam_size);

	DTRACE_PROBE1(damap__activate__taskq__entry, dam_t, mapp);
	DAM_LOCK(mapp, MAP_LOCK);
	if (!bitset_xor(&mapp->dam_active_set, &mapp->dam_stable_set,
	    &delta)) {
		bitset_zero(&mapp->dam_stable_set);
		DAM_FLAG_CLR(mapp, DAM_SPEND);
		DAM_UNLOCK(mapp, MAP_LOCK);
		bitset_fini(&uncfg);
		bitset_fini(&cfg);
		bitset_fini(&delta);
		return;
	}
	has_cfg = bitset_and(&delta, &mapp->dam_stable_set, &cfg);
	has_uncfg = bitset_and(&delta, &mapp->dam_active_set, &uncfg);
	DAM_UNLOCK(mapp, MAP_LOCK);
	if (has_cfg) {
		dam_addrset_activate(mapp, &cfg);
		(*mapp->dam_configure_cb)(mapp->dam_config_arg, mapp, &cfg);
	}
	if (has_uncfg) {
		(*mapp->dam_unconfig_cb)(mapp->dam_config_arg, mapp, &uncfg);
		dam_addrset_release(mapp, &uncfg);
	}
	DAM_LOCK(mapp, MAP_LOCK);
	bitset_zero(&mapp->dam_stable_set);
	DAM_FLAG_CLR(mapp, DAM_SPEND);
	mapp->dam_last_stable = gethrtime();
	mapp->dam_stable_cnt++;
	DAM_INCR_STAT(mapp, dam_stable);
	DAM_UNLOCK(mapp, MAP_LOCK);
	bitset_fini(&uncfg);
	bitset_fini(&cfg);
	bitset_fini(&delta);
	DTRACE_PROBE1(damap__activate__taskq__exit, dam_t, mapp);
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
	int64_t	next_tmov = mapp->dam_stabletmo;
	int64_t tmo_delta;
	int64_t ts = lbolt64;

	DTRACE_PROBE1(damap__addr__stable__cb__entry, dam_t *, mapp);
	DAM_LOCK(mapp, MAP_LOCK);
	if (mapp->dam_tid == 0) {
		DAM_UNLOCK(mapp, MAP_LOCK);
		return;
	}
	mapp->dam_tid = 0;
	/*
	 * If still under stabilization, reschedule timeout,
	 * else dispatch the task to activate & deactivate the stable
	 * set.
	 */
	if (mapp->dam_flags & DAM_SPEND) {
		DAM_INCR_STAT(mapp, dam_stable_blocked);
		mapp->dam_stable_overrun++;
		dam_sched_tmo(mapp, mapp->dam_stabletmo, dam_addr_stable_cb);
		DAM_UNLOCK(mapp, MAP_LOCK);
		DTRACE_PROBE1(damap__addr__stable__cb__overrun,
		    dam_t *, mapp);
		return;
	}

	bitset_copy(&mapp->dam_active_set, &mapp->dam_stable_set);
	for (i = 1; i < mapp->dam_high; i++) {
		if (!bitset_in_set(&mapp->dam_report_set, i))
			continue;
		/*
		 * Stabilize each address
		 */
		passp = ddi_get_soft_state(mapp->dam_da, i);
		ASSERT(passp);
		if (!passp) {
			cmn_err(CE_WARN, "Clearing report no softstate %d", i);
			bitset_del(&mapp->dam_report_set, i);
			continue;
		}

		/* report has stabilized */
		if (passp->da_deadline <= ts) {
			bitset_del(&mapp->dam_report_set, i);
			if (passp->da_flags & DA_RELE) {
				DTRACE_PROBE2(damap__addr__stable__del,
				    dam_t *, mapp, int, i);
				bitset_del(&mapp->dam_stable_set, i);
			} else {
				DTRACE_PROBE2(damap__addr__stable__add,
				    dam_t *, mapp, int, i);
				bitset_add(&mapp->dam_stable_set, i);
			}
			spend++;
			continue;
		}

		/*
		 * not stabilized, determine next (future) map timeout
		 */
		tpend++;
		tmo_delta = passp->da_deadline - ts;
		if (tmo_delta < next_tmov)
			next_tmov = tmo_delta;
	}

	/*
	 * schedule taskq activation of stabilized reports
	 */
	if (spend) {
		if (ddi_taskq_dispatch(mapp->dam_taskqp, dam_activate_taskq,
		    mapp, DDI_NOSLEEP) == DDI_SUCCESS) {
			DAM_FLAG_SET(mapp, DAM_SPEND);
		} else
			tpend++;
	}

	/*
	 * schedule timeout to handle future stabalization of active reports
	 */
	if (tpend)
		dam_sched_tmo(mapp, (clock_t)next_tmov, dam_addr_stable_cb);
	DAM_UNLOCK(mapp, MAP_LOCK);
	DTRACE_PROBE1(damap__addr__stable__cb__exit, dam_t *, mapp);
}

/*
 * fullset stabilization timeout
 */
static void
dam_set_stable_cb(void *arg)
{
	dam_t *mapp = (dam_t *)arg;

	DTRACE_PROBE1(damap__set__stable__cb__enter, dam_t *, mapp);

	DAM_LOCK(mapp, MAP_LOCK);
	if (mapp->dam_tid == 0) {
		DAM_UNLOCK(mapp, MAP_LOCK);
		return;
	}
	mapp->dam_tid = 0;

	/*
	 * If still under stabilization, reschedule timeout,
	 * else dispatch the task to activate & deactivate the stable
	 * set.
	 */
	if (mapp->dam_flags & DAM_SPEND) {
		DAM_INCR_STAT(mapp, dam_stable_blocked);
		mapp->dam_stable_overrun++;
		dam_sched_tmo(mapp, mapp->dam_stabletmo, dam_set_stable_cb);
		DTRACE_PROBE1(damap__set__stable__cb__overrun,
		    dam_t *, mapp);
	} else if (ddi_taskq_dispatch(mapp->dam_taskqp, dam_activate_taskq,
	    mapp, DDI_NOSLEEP) == DDI_FAILURE) {
		dam_sched_tmo(mapp, mapp->dam_stabletmo, dam_set_stable_cb);
	} else {
		bitset_copy(&mapp->dam_report_set, &mapp->dam_stable_set);
		bitset_zero(&mapp->dam_report_set);
		DAM_FLAG_CLR(mapp, DAM_SETADD);
		DAM_FLAG_SET(mapp, DAM_SPEND);
	}
	DAM_UNLOCK(mapp, MAP_LOCK);
	DTRACE_PROBE1(damap__set__stable__cb__exit, dam_t *, mapp);
}

/*
 * reschedule map timeout 'tmo_ms' ticks
 */
static void
dam_sched_tmo(dam_t *mapp, clock_t tmo_ms, void (*tmo_cb)())
{
	timeout_id_t tid;

	if ((tid = mapp->dam_tid) != 0) {
		mapp->dam_tid = 0;
		DAM_UNLOCK(mapp, MAP_LOCK);
		(void) untimeout(tid);
		DAM_LOCK(mapp, MAP_LOCK);
	}

	if (tmo_cb && (tmo_ms != 0))
		mapp->dam_tid = timeout(tmo_cb, mapp, tmo_ms);
}

/*
 * record report addition or removal of an address
 */
static void
dam_add_report(dam_t *mapp, dam_da_t *passp, id_t addrid, int report)
{
	ASSERT(!DAM_IN_REPORT(mapp, addrid));
	passp->da_last_report = gethrtime();
	mapp->dam_last_update = gethrtime();
	passp->da_report_cnt++;
	passp->da_deadline = lbolt64 + mapp->dam_stabletmo;
	if (report == RPT_ADDR_DEL)
		passp->da_flags |= DA_RELE;
	else if (report == RPT_ADDR_ADD)
		passp->da_flags &= ~DA_RELE;
	DAM_LOCK(mapp, MAP_LOCK);
	bitset_add(&mapp->dam_report_set, addrid);
	dam_sched_tmo(mapp, mapp->dam_stabletmo, dam_addr_stable_cb);
	DAM_UNLOCK(mapp, MAP_LOCK);

}

/*
 * release an address report
 */
static void
dam_release_report(dam_t *mapp, id_t addrid)
{
	dam_da_t *passp;

	passp = ddi_get_soft_state(mapp->dam_da, addrid);
	ASSERT(passp);
	passp->da_ppriv_rpt = NULL;
	if (passp->da_nvl_rpt)
		nvlist_free(passp->da_nvl_rpt);
	passp->da_nvl_rpt = NULL;
	DAM_LOCK(mapp, MAP_LOCK);
	bitset_del(&mapp->dam_report_set, addrid);
	DAM_UNLOCK(mapp, MAP_LOCK);
}

/*
 * deactivate a previously stable address
 */
static void
dam_deactivate_addr(dam_t *mapp, id_t addrid)
{
	dam_da_t *passp;

	passp = ddi_get_soft_state(mapp->dam_da, addrid);
	ASSERT(passp);
	if (passp == NULL)
		return;
	DAM_UNLOCK(mapp, ADDR_LOCK);
	if (mapp->dam_deactivate_cb)
		(*mapp->dam_deactivate_cb)(
		    mapp->dam_activate_arg,
		    ddi_strid_id2str(mapp->dam_addr_hash,
		    addrid), addrid, passp->da_ppriv);
	DAM_LOCK(mapp, ADDR_LOCK);
	passp->da_ppriv = NULL;
	if (passp->da_nvl)
		nvlist_free(passp->da_nvl);
	passp->da_nvl = NULL;
}

/*
 * return the map ID of an address
 */
static id_t
dam_get_addrid(dam_t *mapp, char *address)
{
	damap_id_t addrid;
	dam_da_t *passp;

	if ((addrid = ddi_strid_str2id(mapp->dam_addr_hash, address)) == 0) {
		if ((addrid = ddi_strid_fixed_alloc(mapp->dam_addr_hash,
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
	}
	passp = ddi_get_soft_state(mapp->dam_da, addrid);
	if (passp == NULL)
		return (0);
	passp->da_ref++;
	if (passp->da_addr == NULL)
		passp->da_addr = ddi_strid_id2str(
		    mapp->dam_addr_hash, addrid); /* for mdb */
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
	if (mapsp == NULL) {
		return (DDI_FAILURE);
	}

	statsp = (struct dam_kstats *)mapsp->ks_data;
	kstat_named_init(&statsp->dam_stable, "stable cycles",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&statsp->dam_stable_blocked,
	    "stable cycle overrun", KSTAT_DATA_UINT32);
	kstat_named_init(&statsp->dam_rereport,
	    "restarted reports", KSTAT_DATA_UINT32);
	kstat_named_init(&statsp->dam_numstable,
	    "# of stable map entries", KSTAT_DATA_UINT32);
	kstat_install(mapsp);
	mapp->dam_kstatsp = mapsp;
	return (DDI_SUCCESS);
}

/*
 * destroy map stats
 */
static void
dam_kstat_destroy(dam_t *mapp)
{

	kstat_delete(mapp->dam_kstatsp);
}
