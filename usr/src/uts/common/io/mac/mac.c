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


/*
 * MAC Services Module
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/id_space.h>
#include <sys/esunddi.h>
#include <sys/stat.h>
#include <sys/mkdev.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/dlpi.h>
#include <sys/dls.h>
#include <sys/modhash.h>
#include <sys/vlan.h>
#include <sys/mac.h>
#include <sys/mac_impl.h>
#include <sys/dld.h>
#include <sys/modctl.h>
#include <sys/fs/dv_node.h>
#include <sys/thread.h>
#include <sys/proc.h>
#include <sys/callb.h>
#include <sys/cpuvar.h>
#include <sys/atomic.h>
#include <sys/sdt.h>
#include <inet/nd.h>
#include <sys/ethernet.h>

#define	IMPL_HASHSZ	67	/* prime */

static kmem_cache_t	*i_mac_impl_cachep;
static mod_hash_t	*i_mac_impl_hash;
krwlock_t		i_mac_impl_lock;
uint_t			i_mac_impl_count;
static kmem_cache_t	*mac_vnic_tx_cache;
static id_space_t	*minor_ids;
static uint32_t		minor_count;

#define	MACTYPE_KMODDIR	"mac"
#define	MACTYPE_HASHSZ	67
static mod_hash_t	*i_mactype_hash;
/*
 * i_mactype_lock synchronizes threads that obtain references to mactype_t
 * structures through i_mactype_getplugin().
 */
static kmutex_t		i_mactype_lock;

static void i_mac_notify_thread(void *);
static mblk_t *mac_vnic_tx(void *, mblk_t *);
static mblk_t *mac_vnic_txloop(void *, mblk_t *);
static void   mac_register_priv_prop(mac_impl_t *, mac_priv_prop_t *, uint_t);
static void   mac_unregister_priv_prop(mac_impl_t *);

/*
 * Private functions.
 */

/*ARGSUSED*/
static int
i_mac_constructor(void *buf, void *arg, int kmflag)
{
	mac_impl_t	*mip = buf;

	bzero(buf, sizeof (mac_impl_t));

	mip->mi_linkstate = LINK_STATE_UNKNOWN;

	rw_init(&mip->mi_state_lock, NULL, RW_DRIVER, NULL);
	rw_init(&mip->mi_gen_lock, NULL, RW_DRIVER, NULL);
	rw_init(&mip->mi_data_lock, NULL, RW_DRIVER, NULL);
	rw_init(&mip->mi_notify_lock, NULL, RW_DRIVER, NULL);
	rw_init(&mip->mi_rx_lock, NULL, RW_DRIVER, NULL);
	rw_init(&mip->mi_tx_lock, NULL, RW_DRIVER, NULL);
	rw_init(&mip->mi_resource_lock, NULL, RW_DRIVER, NULL);
	mutex_init(&mip->mi_activelink_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&mip->mi_notify_bits_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&mip->mi_notify_cv, NULL, CV_DRIVER, NULL);
	mutex_init(&mip->mi_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&mip->mi_rx_cv, NULL, CV_DRIVER, NULL);
	return (0);
}

/*ARGSUSED*/
static void
i_mac_destructor(void *buf, void *arg)
{
	mac_impl_t	*mip = buf;

	ASSERT(mip->mi_ref == 0);
	ASSERT(!mip->mi_exclusive);
	ASSERT(mip->mi_active == 0);
	ASSERT(mip->mi_linkstate == LINK_STATE_UNKNOWN);
	ASSERT(mip->mi_devpromisc == 0);
	ASSERT(mip->mi_promisc == 0);
	ASSERT(mip->mi_mmap == NULL);
	ASSERT(mip->mi_mmrp == NULL);
	ASSERT(mip->mi_mnfp == NULL);
	ASSERT(mip->mi_resource_add == NULL);
	ASSERT(mip->mi_ksp == NULL);
	ASSERT(mip->mi_kstat_count == 0);
	ASSERT(mip->mi_notify_bits == 0);
	ASSERT(mip->mi_notify_thread == NULL);

	rw_destroy(&mip->mi_gen_lock);
	rw_destroy(&mip->mi_state_lock);
	rw_destroy(&mip->mi_data_lock);
	rw_destroy(&mip->mi_notify_lock);
	rw_destroy(&mip->mi_rx_lock);
	rw_destroy(&mip->mi_tx_lock);
	rw_destroy(&mip->mi_resource_lock);
	mutex_destroy(&mip->mi_activelink_lock);
	mutex_destroy(&mip->mi_notify_bits_lock);
	cv_destroy(&mip->mi_notify_cv);
	mutex_destroy(&mip->mi_lock);
	cv_destroy(&mip->mi_rx_cv);
}

/*
 * mac_vnic_tx_t kmem cache support functions.
 */

/* ARGSUSED */
static int
i_mac_vnic_tx_ctor(void *buf, void *arg, int mkflag)
{
	mac_vnic_tx_t *vnic_tx = buf;

	bzero(buf, sizeof (mac_vnic_tx_t));
	mutex_init(&vnic_tx->mv_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&vnic_tx->mv_cv, NULL, CV_DRIVER, NULL);
	return (0);
}

/* ARGSUSED */
static void
i_mac_vnic_tx_dtor(void *buf, void *arg)
{
	mac_vnic_tx_t *vnic_tx = buf;

	ASSERT(vnic_tx->mv_refs == 0);
	mutex_destroy(&vnic_tx->mv_lock);
	cv_destroy(&vnic_tx->mv_cv);
}

static void
i_mac_notify(mac_impl_t *mip, mac_notify_type_t type)
{
	rw_enter(&i_mac_impl_lock, RW_READER);
	if (mip->mi_disabled)
		goto exit;

	/*
	 * Guard against incorrect notifications.  (Running a newer
	 * mac client against an older implementation?)
	 */
	if (type >= MAC_NNOTE)
		goto exit;

	mutex_enter(&mip->mi_notify_bits_lock);
	mip->mi_notify_bits |= (1 << type);
	cv_broadcast(&mip->mi_notify_cv);
	mutex_exit(&mip->mi_notify_bits_lock);

exit:
	rw_exit(&i_mac_impl_lock);
}

static void
i_mac_log_link_state(mac_impl_t *mip)
{
	/*
	 * If no change, then it is not interesting.
	 */
	if (mip->mi_lastlinkstate == mip->mi_linkstate)
		return;

	switch (mip->mi_linkstate) {
	case LINK_STATE_UP:
		if (mip->mi_type->mt_ops.mtops_ops & MTOPS_LINK_DETAILS) {
			char det[200];

			mip->mi_type->mt_ops.mtops_link_details(det,
			    sizeof (det), (mac_handle_t)mip, mip->mi_pdata);

			cmn_err(CE_NOTE, "!%s link up, %s", mip->mi_name, det);
		} else {
			cmn_err(CE_NOTE, "!%s link up", mip->mi_name);
		}
		break;

	case LINK_STATE_DOWN:
		/*
		 * Only transitions from UP to DOWN are interesting
		 */
		if (mip->mi_lastlinkstate != LINK_STATE_UNKNOWN)
			cmn_err(CE_NOTE, "!%s link down", mip->mi_name);
		break;

	case LINK_STATE_UNKNOWN:
		/*
		 * This case is normally not interesting.
		 */
		break;
	}
	mip->mi_lastlinkstate = mip->mi_linkstate;
}

static void
i_mac_notify_thread(void *arg)
{
	mac_impl_t	*mip = arg;
	callb_cpr_t	cprinfo;

	CALLB_CPR_INIT(&cprinfo, &mip->mi_notify_bits_lock, callb_generic_cpr,
	    "i_mac_notify_thread");

	mutex_enter(&mip->mi_notify_bits_lock);
	for (;;) {
		uint32_t	bits;
		uint32_t	type;

		bits = mip->mi_notify_bits;
		if (bits == 0) {
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			cv_wait(&mip->mi_notify_cv, &mip->mi_notify_bits_lock);
			CALLB_CPR_SAFE_END(&cprinfo, &mip->mi_notify_bits_lock);
			continue;
		}
		mip->mi_notify_bits = 0;

		if ((bits & (1 << MAC_NNOTE)) != 0) {
			/* request to quit */
			ASSERT(mip->mi_disabled);
			break;
		}

		mutex_exit(&mip->mi_notify_bits_lock);

		/*
		 * Log link changes.
		 */
		if ((bits & (1 << MAC_NOTE_LINK)) != 0)
			i_mac_log_link_state(mip);

		/*
		 * Do notification callbacks for each notification type.
		 */
		for (type = 0; type < MAC_NNOTE; type++) {
			mac_notify_fn_t	*mnfp;

			if ((bits & (1 << type)) == 0) {
				continue;
			}

			/*
			 * Walk the list of notifications.
			 */
			rw_enter(&mip->mi_notify_lock, RW_READER);
			for (mnfp = mip->mi_mnfp; mnfp != NULL;
			    mnfp = mnfp->mnf_nextp) {

				mnfp->mnf_fn(mnfp->mnf_arg, type);
			}
			rw_exit(&mip->mi_notify_lock);
		}

		mutex_enter(&mip->mi_notify_bits_lock);
	}

	mip->mi_notify_thread = NULL;
	cv_broadcast(&mip->mi_notify_cv);

	CALLB_CPR_EXIT(&cprinfo);

	thread_exit();
}

static mactype_t *
i_mactype_getplugin(const char *pname)
{
	mactype_t	*mtype = NULL;
	boolean_t	tried_modload = B_FALSE;

	mutex_enter(&i_mactype_lock);

find_registered_mactype:
	if (mod_hash_find(i_mactype_hash, (mod_hash_key_t)pname,
	    (mod_hash_val_t *)&mtype) != 0) {
		if (!tried_modload) {
			/*
			 * If the plugin has not yet been loaded, then
			 * attempt to load it now.  If modload() succeeds,
			 * the plugin should have registered using
			 * mactype_register(), in which case we can go back
			 * and attempt to find it again.
			 */
			if (modload(MACTYPE_KMODDIR, (char *)pname) != -1) {
				tried_modload = B_TRUE;
				goto find_registered_mactype;
			}
		}
	} else {
		/*
		 * Note that there's no danger that the plugin we've loaded
		 * could be unloaded between the modload() step and the
		 * reference count bump here, as we're holding
		 * i_mactype_lock, which mactype_unregister() also holds.
		 */
		atomic_inc_32(&mtype->mt_ref);
	}

	mutex_exit(&i_mactype_lock);
	return (mtype);
}

/*
 * Module initialization functions.
 */

void
mac_init(void)
{
	i_mac_impl_cachep = kmem_cache_create("mac_impl_cache",
	    sizeof (mac_impl_t), 0, i_mac_constructor, i_mac_destructor,
	    NULL, NULL, NULL, 0);
	ASSERT(i_mac_impl_cachep != NULL);

	mac_vnic_tx_cache = kmem_cache_create("mac_vnic_tx_cache",
	    sizeof (mac_vnic_tx_t), 0, i_mac_vnic_tx_ctor, i_mac_vnic_tx_dtor,
	    NULL, NULL, NULL, 0);
	ASSERT(mac_vnic_tx_cache != NULL);

	i_mac_impl_hash = mod_hash_create_extended("mac_impl_hash",
	    IMPL_HASHSZ, mod_hash_null_keydtor, mod_hash_null_valdtor,
	    mod_hash_bystr, NULL, mod_hash_strkey_cmp, KM_SLEEP);
	rw_init(&i_mac_impl_lock, NULL, RW_DEFAULT, NULL);
	i_mac_impl_count = 0;

	i_mactype_hash = mod_hash_create_extended("mactype_hash",
	    MACTYPE_HASHSZ,
	    mod_hash_null_keydtor, mod_hash_null_valdtor,
	    mod_hash_bystr, NULL, mod_hash_strkey_cmp, KM_SLEEP);

	/*
	 * Allocate an id space to manage minor numbers. The range of the
	 * space will be from MAC_MAX_MINOR+1 to MAXMIN32 (maximum legal
	 * minor number is MAXMIN, but id_t is type of integer and does not
	 * allow MAXMIN).
	 */
	minor_ids = id_space_create("mac_minor_ids", MAC_MAX_MINOR+1, MAXMIN32);
	ASSERT(minor_ids != NULL);
	minor_count = 0;
}

int
mac_fini(void)
{
	if (i_mac_impl_count > 0 || minor_count > 0)
		return (EBUSY);

	id_space_destroy(minor_ids);

	mod_hash_destroy_hash(i_mac_impl_hash);
	rw_destroy(&i_mac_impl_lock);

	kmem_cache_destroy(i_mac_impl_cachep);
	kmem_cache_destroy(mac_vnic_tx_cache);

	mod_hash_destroy_hash(i_mactype_hash);
	return (0);
}

/*
 * Client functions.
 */

static int
mac_hold(const char *macname, mac_impl_t **pmip)
{
	mac_impl_t	*mip;
	int		err;

	/*
	 * Check the device name length to make sure it won't overflow our
	 * buffer.
	 */
	if (strlen(macname) >= MAXNAMELEN)
		return (EINVAL);

	/*
	 * Look up its entry in the global hash table.
	 */
	rw_enter(&i_mac_impl_lock, RW_WRITER);
	err = mod_hash_find(i_mac_impl_hash, (mod_hash_key_t)macname,
	    (mod_hash_val_t *)&mip);

	if (err != 0) {
		rw_exit(&i_mac_impl_lock);
		return (ENOENT);
	}

	if (mip->mi_disabled) {
		rw_exit(&i_mac_impl_lock);
		return (ENOENT);
	}

	if (mip->mi_exclusive) {
		rw_exit(&i_mac_impl_lock);
		return (EBUSY);
	}

	mip->mi_ref++;
	rw_exit(&i_mac_impl_lock);

	*pmip = mip;
	return (0);
}

static void
mac_rele(mac_impl_t *mip)
{
	rw_enter(&i_mac_impl_lock, RW_WRITER);
	ASSERT(mip->mi_ref != 0);
	if (--mip->mi_ref == 0)
		ASSERT(!mip->mi_activelink);
	rw_exit(&i_mac_impl_lock);
}

int
mac_hold_exclusive(mac_handle_t mh)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	/*
	 * Look up its entry in the global hash table.
	 */
	rw_enter(&i_mac_impl_lock, RW_WRITER);
	if (mip->mi_disabled) {
		rw_exit(&i_mac_impl_lock);
		return (ENOENT);
	}

	if (mip->mi_ref != 0) {
		rw_exit(&i_mac_impl_lock);
		return (EBUSY);
	}

	ASSERT(!mip->mi_exclusive);

	mip->mi_ref++;
	mip->mi_exclusive = B_TRUE;
	rw_exit(&i_mac_impl_lock);
	return (0);
}

void
mac_rele_exclusive(mac_handle_t mh)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	/*
	 * Look up its entry in the global hash table.
	 */
	rw_enter(&i_mac_impl_lock, RW_WRITER);
	ASSERT(mip->mi_ref == 1 && mip->mi_exclusive);
	mip->mi_ref--;
	mip->mi_exclusive = B_FALSE;
	rw_exit(&i_mac_impl_lock);
}

int
mac_open(const char *macname, mac_handle_t *mhp)
{
	mac_impl_t	*mip;
	int		err;

	/*
	 * Look up its entry in the global hash table.
	 */
	if ((err = mac_hold(macname, &mip)) != 0)
		return (err);

	/*
	 * Hold the dip associated to the MAC to prevent it from being
	 * detached. For a softmac, its underlying dip is held by the
	 * mi_open() callback.
	 *
	 * This is done to be more tolerant with some defective drivers,
	 * which incorrectly handle mac_unregister() failure in their
	 * xxx_detach() routine. For example, some drivers ignore the
	 * failure of mac_unregister() and free all resources that
	 * that are needed for data transmition.
	 */
	e_ddi_hold_devi(mip->mi_dip);

	rw_enter(&mip->mi_gen_lock, RW_WRITER);

	if ((mip->mi_oref != 0) ||
	    !(mip->mi_callbacks->mc_callbacks & MC_OPEN)) {
		goto done;
	}

	/*
	 * Note that we do not hold i_mac_impl_lock when calling the
	 * mc_open() callback function to avoid deadlock with the
	 * i_mac_notify() function.
	 */
	if ((err = mip->mi_open(mip->mi_driver)) != 0) {
		rw_exit(&mip->mi_gen_lock);
		ddi_release_devi(mip->mi_dip);
		mac_rele(mip);
		return (err);
	}

done:
	mip->mi_oref++;
	rw_exit(&mip->mi_gen_lock);
	*mhp = (mac_handle_t)mip;
	return (0);
}

int
mac_open_by_linkid(datalink_id_t linkid, mac_handle_t *mhp)
{
	dls_dl_handle_t	dlh;
	int		err;

	if ((err = dls_devnet_hold_tmp(linkid, &dlh)) != 0)
		return (err);

	if (dls_devnet_vid(dlh) != VLAN_ID_NONE) {
		err = EINVAL;
		goto done;
	}

	dls_devnet_prop_task_wait(dlh);

	err = mac_open(dls_devnet_mac(dlh), mhp);

done:
	dls_devnet_rele_tmp(dlh);
	return (err);
}

int
mac_open_by_linkname(const char *link, mac_handle_t *mhp)
{
	datalink_id_t	linkid;
	int		err;

	if ((err = dls_mgmt_get_linkid(link, &linkid)) != 0)
		return (err);
	return (mac_open_by_linkid(linkid, mhp));
}

void
mac_close(mac_handle_t mh)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	rw_enter(&mip->mi_gen_lock, RW_WRITER);

	ASSERT(mip->mi_oref != 0);
	if (--mip->mi_oref == 0) {
		if ((mip->mi_callbacks->mc_callbacks & MC_CLOSE))
			mip->mi_close(mip->mi_driver);
	}
	rw_exit(&mip->mi_gen_lock);

	ddi_release_devi(mip->mi_dip);
	mac_rele(mip);
}

const mac_info_t *
mac_info(mac_handle_t mh)
{
	return (&((mac_impl_t *)mh)->mi_info);
}

dev_info_t *
mac_devinfo_get(mac_handle_t mh)
{
	return (((mac_impl_t *)mh)->mi_dip);
}

const char *
mac_name(mac_handle_t mh)
{
	return (((mac_impl_t *)mh)->mi_name);
}

minor_t
mac_minor(mac_handle_t mh)
{
	return (((mac_impl_t *)mh)->mi_minor);
}

uint64_t
mac_stat_get(mac_handle_t mh, uint_t stat)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	uint64_t	val;
	int		ret;

	/*
	 * The range of stat determines where it is maintained.  Stat
	 * values from 0 up to (but not including) MAC_STAT_MIN are
	 * mainteined by the mac module itself.  Everything else is
	 * maintained by the driver.
	 */
	if (stat < MAC_STAT_MIN) {
		/* These stats are maintained by the mac module itself. */
		switch (stat) {
		case MAC_STAT_LINK_STATE:
			return (mip->mi_linkstate);
		case MAC_STAT_LINK_UP:
			return (mip->mi_linkstate == LINK_STATE_UP);
		case MAC_STAT_PROMISC:
			return (mip->mi_devpromisc != 0);
		default:
			ASSERT(B_FALSE);
		}
	}

	/*
	 * Call the driver to get the given statistic.
	 */
	ret = mip->mi_getstat(mip->mi_driver, stat, &val);
	if (ret != 0) {
		/*
		 * The driver doesn't support this statistic.  Get the
		 * statistic's default value.
		 */
		val = mac_stat_default(mip, stat);
	}
	return (val);
}

int
mac_start(mac_handle_t mh)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	int		err;

	ASSERT(mip->mi_start != NULL);

	rw_enter(&(mip->mi_state_lock), RW_WRITER);

	/*
	 * Check whether the device is already started.
	 */
	if (mip->mi_active++ != 0) {
		/*
		 * It's already started so there's nothing more to do.
		 */
		err = 0;
		goto done;
	}

	/*
	 * Start the device.
	 */
	if ((err = mip->mi_start(mip->mi_driver)) != 0)
		--mip->mi_active;

done:
	rw_exit(&(mip->mi_state_lock));
	return (err);
}

void
mac_stop(mac_handle_t mh)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	ASSERT(mip->mi_stop != NULL);

	rw_enter(&(mip->mi_state_lock), RW_WRITER);

	/*
	 * Check whether the device is still needed.
	 */
	ASSERT(mip->mi_active != 0);
	if (--mip->mi_active != 0) {
		/*
		 * It's still needed so there's nothing more to do.
		 */
		goto done;
	}

	/*
	 * Stop the device.
	 */
	mip->mi_stop(mip->mi_driver);

done:
	rw_exit(&(mip->mi_state_lock));
}

int
mac_multicst_add(mac_handle_t mh, const uint8_t *addr)
{
	mac_impl_t		*mip = (mac_impl_t *)mh;
	mac_multicst_addr_t	**pp;
	mac_multicst_addr_t	*p;
	int			err;

	ASSERT(mip->mi_multicst != NULL);

	/*
	 * Verify the address.
	 */
	if ((err = mip->mi_type->mt_ops.mtops_multicst_verify(addr,
	    mip->mi_pdata)) != 0) {
		return (err);
	}

	/*
	 * Check whether the given address is already enabled.
	 */
	rw_enter(&(mip->mi_data_lock), RW_WRITER);
	for (pp = &(mip->mi_mmap); (p = *pp) != NULL; pp = &(p->mma_nextp)) {
		if (bcmp(p->mma_addr, addr, mip->mi_type->mt_addr_length) ==
		    0) {
			/*
			 * The address is already enabled so just bump the
			 * reference count.
			 */
			p->mma_ref++;
			err = 0;
			goto done;
		}
	}

	/*
	 * Allocate a new list entry.
	 */
	if ((p = kmem_zalloc(sizeof (mac_multicst_addr_t),
	    KM_NOSLEEP)) == NULL) {
		err = ENOMEM;
		goto done;
	}

	/*
	 * Enable a new multicast address.
	 */
	if ((err = mip->mi_multicst(mip->mi_driver, B_TRUE, addr)) != 0) {
		kmem_free(p, sizeof (mac_multicst_addr_t));
		goto done;
	}

	/*
	 * Add the address to the list of enabled addresses.
	 */
	bcopy(addr, p->mma_addr, mip->mi_type->mt_addr_length);
	p->mma_ref++;
	*pp = p;

done:
	rw_exit(&(mip->mi_data_lock));
	return (err);
}

int
mac_multicst_remove(mac_handle_t mh, const uint8_t *addr)
{
	mac_impl_t		*mip = (mac_impl_t *)mh;
	mac_multicst_addr_t	**pp;
	mac_multicst_addr_t	*p;
	int			err;

	ASSERT(mip->mi_multicst != NULL);

	/*
	 * Find the entry in the list for the given address.
	 */
	rw_enter(&(mip->mi_data_lock), RW_WRITER);
	for (pp = &(mip->mi_mmap); (p = *pp) != NULL; pp = &(p->mma_nextp)) {
		if (bcmp(p->mma_addr, addr, mip->mi_type->mt_addr_length) ==
		    0) {
			if (--p->mma_ref == 0)
				break;

			/*
			 * There is still a reference to this address so
			 * there's nothing more to do.
			 */
			err = 0;
			goto done;
		}
	}

	/*
	 * We did not find an entry for the given address so it is not
	 * currently enabled.
	 */
	if (p == NULL) {
		err = ENOENT;
		goto done;
	}
	ASSERT(p->mma_ref == 0);

	/*
	 * Disable the multicast address.
	 */
	if ((err = mip->mi_multicst(mip->mi_driver, B_FALSE, addr)) != 0) {
		p->mma_ref++;
		goto done;
	}

	/*
	 * Remove it from the list.
	 */
	*pp = p->mma_nextp;
	kmem_free(p, sizeof (mac_multicst_addr_t));

done:
	rw_exit(&(mip->mi_data_lock));
	return (err);
}

/*
 * mac_unicst_verify: Verifies the passed address. It fails
 * if the passed address is a group address or has incorrect length.
 */
boolean_t
mac_unicst_verify(mac_handle_t mh, const uint8_t *addr, uint_t len)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	/*
	 * Verify the address.
	 */
	if ((len != mip->mi_type->mt_addr_length) ||
	    (mip->mi_type->mt_ops.mtops_unicst_verify(addr,
	    mip->mi_pdata)) != 0) {
		return (B_FALSE);
	} else {
		return (B_TRUE);
	}
}

int
mac_unicst_set(mac_handle_t mh, const uint8_t *addr)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	int		err;
	boolean_t	notify = B_FALSE;

	ASSERT(mip->mi_unicst != NULL);

	/*
	 * Verify the address.
	 */
	if ((err = mip->mi_type->mt_ops.mtops_unicst_verify(addr,
	    mip->mi_pdata)) != 0) {
		return (err);
	}

	/*
	 * Program the new unicast address.
	 */
	rw_enter(&(mip->mi_data_lock), RW_WRITER);

	/*
	 * If address doesn't change, do nothing.
	 * This check is necessary otherwise it may call into mac_unicst_set
	 * recursively.
	 */
	if (bcmp(addr, mip->mi_addr, mip->mi_type->mt_addr_length) == 0)
		goto done;

	if ((err = mip->mi_unicst(mip->mi_driver, addr)) != 0)
		goto done;

	/*
	 * Save the address and flag that we need to send a notification.
	 */
	bcopy(addr, mip->mi_addr, mip->mi_type->mt_addr_length);
	notify = B_TRUE;

done:
	rw_exit(&(mip->mi_data_lock));

	if (notify)
		i_mac_notify(mip, MAC_NOTE_UNICST);

	return (err);
}

void
mac_unicst_get(mac_handle_t mh, uint8_t *addr)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	/*
	 * Copy out the current unicast source address.
	 */
	rw_enter(&(mip->mi_data_lock), RW_READER);
	bcopy(mip->mi_addr, addr, mip->mi_type->mt_addr_length);
	rw_exit(&(mip->mi_data_lock));
}

void
mac_dest_get(mac_handle_t mh, uint8_t *addr)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	/*
	 * Copy out the current destination address.
	 */
	rw_enter(&(mip->mi_data_lock), RW_READER);
	bcopy(mip->mi_dstaddr, addr, mip->mi_type->mt_addr_length);
	rw_exit(&(mip->mi_data_lock));
}

int
mac_promisc_set(mac_handle_t mh, boolean_t on, mac_promisc_type_t ptype)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	int		err = 0;

	ASSERT(mip->mi_setpromisc != NULL);
	ASSERT(ptype == MAC_DEVPROMISC || ptype == MAC_PROMISC);

	/*
	 * Determine whether we should enable or disable promiscuous mode.
	 * For details on the distinction between "device promiscuous mode"
	 * and "MAC promiscuous mode", see PSARC/2005/289.
	 */
	rw_enter(&(mip->mi_data_lock), RW_WRITER);
	if (on) {
		/*
		 * Enable promiscuous mode on the device if not yet enabled.
		 */
		if (mip->mi_devpromisc++ == 0) {
			err = mip->mi_setpromisc(mip->mi_driver, B_TRUE);
			if (err != 0) {
				mip->mi_devpromisc--;
				goto done;
			}
			i_mac_notify(mip, MAC_NOTE_DEVPROMISC);
		}

		/*
		 * Enable promiscuous mode on the MAC if not yet enabled.
		 */
		if (ptype == MAC_PROMISC && mip->mi_promisc++ == 0)
			i_mac_notify(mip, MAC_NOTE_PROMISC);
	} else {
		if (mip->mi_devpromisc == 0) {
			err = EPROTO;
			goto done;
		}
		/*
		 * Disable promiscuous mode on the device if this is the last
		 * enabling.
		 */
		if (--mip->mi_devpromisc == 0) {
			err = mip->mi_setpromisc(mip->mi_driver, B_FALSE);
			if (err != 0) {
				mip->mi_devpromisc++;
				goto done;
			}
			i_mac_notify(mip, MAC_NOTE_DEVPROMISC);
		}

		/*
		 * Disable promiscuous mode on the MAC if this is the last
		 * enabling.
		 */
		if (ptype == MAC_PROMISC && --mip->mi_promisc == 0)
			i_mac_notify(mip, MAC_NOTE_PROMISC);
	}

done:
	rw_exit(&(mip->mi_data_lock));
	return (err);
}

boolean_t
mac_promisc_get(mac_handle_t mh, mac_promisc_type_t ptype)
{
	mac_impl_t		*mip = (mac_impl_t *)mh;

	ASSERT(ptype == MAC_DEVPROMISC || ptype == MAC_PROMISC);

	/*
	 * Return the current promiscuity.
	 */
	if (ptype == MAC_DEVPROMISC)
		return (mip->mi_devpromisc != 0);
	else
		return (mip->mi_promisc != 0);
}

void
mac_sdu_get(mac_handle_t mh, uint_t *min_sdu, uint_t *max_sdu)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	if (min_sdu != NULL)
		*min_sdu = mip->mi_sdu_min;
	if (max_sdu != NULL)
		*max_sdu = mip->mi_sdu_max;
}

void
mac_resources(mac_handle_t mh)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	/*
	 * If the driver supports resource registration, call the driver to
	 * ask it to register its resources.
	 */
	if (mip->mi_callbacks->mc_callbacks & MC_RESOURCES)
		mip->mi_resources(mip->mi_driver);
}

void
mac_ioctl(mac_handle_t mh, queue_t *wq, mblk_t *bp)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	int cmd = ((struct iocblk *)bp->b_rptr)->ioc_cmd;

	if ((cmd == ND_GET && (mip->mi_callbacks->mc_callbacks & MC_GETPROP)) ||
	    (cmd == ND_SET && (mip->mi_callbacks->mc_callbacks & MC_SETPROP))) {
		/*
		 * If ndd props were registered, call them.
		 * Note that ndd ioctls are Obsolete
		 */
		mac_ndd_ioctl(mip, wq, bp);
		return;
	}

	/*
	 * Call the driver to handle the ioctl.  The driver may not support
	 * any ioctls, in which case we reply with a NAK on its behalf.
	 */
	if (mip->mi_callbacks->mc_callbacks & MC_IOCTL)
		mip->mi_ioctl(mip->mi_driver, wq, bp);
	else
		miocnak(wq, bp, 0, EINVAL);
}

const mac_txinfo_t *
mac_do_tx_get(mac_handle_t mh, boolean_t is_vnic)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	mac_txinfo_t	*mtp;

	/*
	 * Grab the lock to prevent us from racing with MAC_PROMISC being
	 * changed.  This is sufficient since MAC clients are careful to always
	 * call mac_txloop_add() prior to enabling MAC_PROMISC, and to disable
	 * MAC_PROMISC prior to calling mac_txloop_remove().
	 */
	rw_enter(&mip->mi_tx_lock, RW_READER);

	if (mac_promisc_get(mh, MAC_PROMISC)) {
		ASSERT(mip->mi_mtfp != NULL);
		if (mip->mi_vnic_present && !is_vnic) {
			mtp = &mip->mi_vnic_txloopinfo;
		} else {
			mtp = &mip->mi_txloopinfo;
		}
	} else {
		if (mip->mi_vnic_present && !is_vnic) {
			mtp = &mip->mi_vnic_txinfo;
		} else {
			/*
			 * Note that we cannot ASSERT() that mip->mi_mtfp is
			 * NULL, because to satisfy the above ASSERT(), we
			 * have to disable MAC_PROMISC prior to calling
			 * mac_txloop_remove().
			 */
			mtp = &mip->mi_txinfo;
		}
	}

	rw_exit(&mip->mi_tx_lock);
	return (mtp);
}

/*
 * Invoked by VNIC to obtain the transmit entry point.
 */
const mac_txinfo_t *
mac_vnic_tx_get(mac_handle_t mh)
{
	return (mac_do_tx_get(mh, B_TRUE));
}

/*
 * Invoked by any non-VNIC client to obtain the transmit entry point.
 * If a VNIC is present, the VNIC transmit function provided by the VNIC
 * will be returned to the MAC client.
 */
const mac_txinfo_t *
mac_tx_get(mac_handle_t mh)
{
	return (mac_do_tx_get(mh, B_FALSE));
}

link_state_t
mac_link_get(mac_handle_t mh)
{
	return (((mac_impl_t *)mh)->mi_linkstate);
}

mac_notify_handle_t
mac_notify_add(mac_handle_t mh, mac_notify_t notify, void *arg)
{
	mac_impl_t		*mip = (mac_impl_t *)mh;
	mac_notify_fn_t		*mnfp;

	mnfp = kmem_zalloc(sizeof (mac_notify_fn_t), KM_SLEEP);
	mnfp->mnf_fn = notify;
	mnfp->mnf_arg = arg;

	/*
	 * Add it to the head of the 'notify' callback list.
	 */
	rw_enter(&mip->mi_notify_lock, RW_WRITER);
	mnfp->mnf_nextp = mip->mi_mnfp;
	mip->mi_mnfp = mnfp;
	rw_exit(&mip->mi_notify_lock);

	return ((mac_notify_handle_t)mnfp);
}

void
mac_notify_remove(mac_handle_t mh, mac_notify_handle_t mnh)
{
	mac_impl_t		*mip = (mac_impl_t *)mh;
	mac_notify_fn_t		*mnfp = (mac_notify_fn_t *)mnh;
	mac_notify_fn_t		**pp;
	mac_notify_fn_t		*p;

	/*
	 * Search the 'notify' callback list for the function closure.
	 */
	rw_enter(&mip->mi_notify_lock, RW_WRITER);
	for (pp = &(mip->mi_mnfp); (p = *pp) != NULL;
	    pp = &(p->mnf_nextp)) {
		if (p == mnfp)
			break;
	}
	ASSERT(p != NULL);

	/*
	 * Remove it from the list.
	 */
	*pp = p->mnf_nextp;
	rw_exit(&mip->mi_notify_lock);

	/*
	 * Free it.
	 */
	kmem_free(mnfp, sizeof (mac_notify_fn_t));
}

void
mac_notify(mac_handle_t mh)
{
	mac_impl_t		*mip = (mac_impl_t *)mh;
	mac_notify_type_t	type;

	for (type = 0; type < MAC_NNOTE; type++)
		i_mac_notify(mip, type);
}

/*
 * Register a receive function for this mac.
 * More information on this function's interaction with mac_rx()
 * can be found atop mac_rx().
 */
mac_rx_handle_t
mac_do_rx_add(mac_handle_t mh, mac_rx_t rx, void *arg, boolean_t is_active)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	mac_rx_fn_t	*mrfp;

	mrfp = kmem_zalloc(sizeof (mac_rx_fn_t), KM_SLEEP);
	mrfp->mrf_fn = rx;
	mrfp->mrf_arg = arg;
	mrfp->mrf_active = is_active;

	/*
	 * Add it to the head of the 'rx' callback list.
	 */
	rw_enter(&(mip->mi_rx_lock), RW_WRITER);

	/*
	 * mac_rx() will only call callbacks that are marked inuse.
	 */
	mrfp->mrf_inuse = B_TRUE;
	mrfp->mrf_nextp = mip->mi_mrfp;

	/*
	 * mac_rx() could be traversing the remainder of the list
	 * and miss the new callback we're adding here. This is not a problem
	 * because we do not guarantee the callback to take effect immediately
	 * after mac_rx_add() returns.
	 */
	mip->mi_mrfp = mrfp;
	rw_exit(&(mip->mi_rx_lock));

	return ((mac_rx_handle_t)mrfp);
}

mac_rx_handle_t
mac_rx_add(mac_handle_t mh, mac_rx_t rx, void *arg)
{
	return (mac_do_rx_add(mh, rx, arg, B_FALSE));
}

mac_rx_handle_t
mac_active_rx_add(mac_handle_t mh, mac_rx_t rx, void *arg)
{
	return (mac_do_rx_add(mh, rx, arg, B_TRUE));
}

/*
 * Unregister a receive function for this mac.
 * This function does not block if wait is B_FALSE. This is useful
 * for clients who call mac_rx_remove() from a non-blockable context.
 * More information on this function's interaction with mac_rx()
 * can be found atop mac_rx().
 */
void
mac_rx_remove(mac_handle_t mh, mac_rx_handle_t mrh, boolean_t wait)
{
	mac_impl_t		*mip = (mac_impl_t *)mh;
	mac_rx_fn_t		*mrfp = (mac_rx_fn_t *)mrh;
	mac_rx_fn_t		**pp;
	mac_rx_fn_t		*p;

	/*
	 * Search the 'rx' callback list for the function closure.
	 */
	rw_enter(&mip->mi_rx_lock, RW_WRITER);
	for (pp = &(mip->mi_mrfp); (p = *pp) != NULL; pp = &(p->mrf_nextp)) {
		if (p == mrfp)
			break;
	}
	ASSERT(p != NULL);

	/*
	 * If mac_rx() is running, mark callback for deletion
	 * and return (if wait is false), or wait until mac_rx()
	 * exits (if wait is true).
	 */
	if (mip->mi_rx_ref > 0) {
		DTRACE_PROBE1(defer_delete, mac_impl_t *, mip);
		p->mrf_inuse = B_FALSE;
		mutex_enter(&mip->mi_lock);
		mip->mi_rx_removed++;
		mutex_exit(&mip->mi_lock);

		rw_exit(&mip->mi_rx_lock);
		if (wait)
			mac_rx_remove_wait(mh);
		return;
	}

	/* Remove it from the list. */
	*pp = p->mrf_nextp;
	kmem_free(mrfp, sizeof (mac_rx_fn_t));
	rw_exit(&mip->mi_rx_lock);
}

/*
 * Wait for all pending callback removals to be completed by mac_rx().
 * Note that if we call mac_rx_remove() immediately before this, there is no
 * guarantee we would wait *only* on the callback that we specified.
 * mac_rx_remove() could have been called by other threads and we would have
 * to wait for other marked callbacks to be removed as well.
 */
void
mac_rx_remove_wait(mac_handle_t mh)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	mutex_enter(&mip->mi_lock);
	while (mip->mi_rx_removed > 0) {
		DTRACE_PROBE1(need_wait, mac_impl_t *, mip);
		cv_wait(&mip->mi_rx_cv, &mip->mi_lock);
	}
	mutex_exit(&mip->mi_lock);
}

mac_txloop_handle_t
mac_txloop_add(mac_handle_t mh, mac_txloop_t tx, void *arg)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	mac_txloop_fn_t	*mtfp;

	mtfp = kmem_zalloc(sizeof (mac_txloop_fn_t), KM_SLEEP);
	mtfp->mtf_fn = tx;
	mtfp->mtf_arg = arg;

	/*
	 * Add it to the head of the 'tx' callback list.
	 */
	rw_enter(&(mip->mi_tx_lock), RW_WRITER);
	mtfp->mtf_nextp = mip->mi_mtfp;
	mip->mi_mtfp = mtfp;
	rw_exit(&(mip->mi_tx_lock));

	return ((mac_txloop_handle_t)mtfp);
}

/*
 * Unregister a transmit function for this mac.  This removes the function
 * from the list of transmit functions for this mac.
 */
void
mac_txloop_remove(mac_handle_t mh, mac_txloop_handle_t mth)
{
	mac_impl_t		*mip = (mac_impl_t *)mh;
	mac_txloop_fn_t		*mtfp = (mac_txloop_fn_t *)mth;
	mac_txloop_fn_t		**pp;
	mac_txloop_fn_t		*p;

	/*
	 * Search the 'tx' callback list for the function.
	 */
	rw_enter(&(mip->mi_tx_lock), RW_WRITER);
	for (pp = &(mip->mi_mtfp); (p = *pp) != NULL; pp = &(p->mtf_nextp)) {
		if (p == mtfp)
			break;
	}
	ASSERT(p != NULL);

	/* Remove it from the list. */
	*pp = p->mtf_nextp;
	kmem_free(mtfp, sizeof (mac_txloop_fn_t));
	rw_exit(&(mip->mi_tx_lock));
}

void
mac_resource_set(mac_handle_t mh, mac_resource_add_t add, void *arg)
{
	mac_impl_t		*mip = (mac_impl_t *)mh;

	/*
	 * Update the 'resource_add' callbacks.
	 */
	rw_enter(&(mip->mi_resource_lock), RW_WRITER);
	mip->mi_resource_add = add;
	mip->mi_resource_add_arg = arg;
	rw_exit(&(mip->mi_resource_lock));
}

/*
 * Driver support functions.
 */

mac_register_t *
mac_alloc(uint_t mac_version)
{
	mac_register_t *mregp;

	/*
	 * Make sure there isn't a version mismatch between the driver and
	 * the framework.  In the future, if multiple versions are
	 * supported, this check could become more sophisticated.
	 */
	if (mac_version != MAC_VERSION)
		return (NULL);

	mregp = kmem_zalloc(sizeof (mac_register_t), KM_SLEEP);
	mregp->m_version = mac_version;
	return (mregp);
}

void
mac_free(mac_register_t *mregp)
{
	kmem_free(mregp, sizeof (mac_register_t));
}

/*
 * Allocate a minor number.
 */
minor_t
mac_minor_hold(boolean_t sleep)
{
	minor_t	minor;

	/*
	 * Grab a value from the arena.
	 */
	atomic_add_32(&minor_count, 1);

	if (sleep)
		minor = (uint_t)id_alloc(minor_ids);
	else
		minor = (uint_t)id_alloc_nosleep(minor_ids);

	if (minor == 0) {
		atomic_add_32(&minor_count, -1);
		return (0);
	}

	return (minor);
}

/*
 * Release a previously allocated minor number.
 */
void
mac_minor_rele(minor_t minor)
{
	/*
	 * Return the value to the arena.
	 */
	id_free(minor_ids, minor);
	atomic_add_32(&minor_count, -1);
}

uint32_t
mac_no_notification(mac_handle_t mh)
{
	mac_impl_t *mip = (mac_impl_t *)mh;
	return (mip->mi_unsup_note);
}

boolean_t
mac_is_legacy(mac_handle_t mh)
{
	mac_impl_t *mip = (mac_impl_t *)mh;
	return (mip->mi_legacy);
}

/*
 * mac_register() is how drivers register new MACs with the GLDv3
 * framework.  The mregp argument is allocated by drivers using the
 * mac_alloc() function, and can be freed using mac_free() immediately upon
 * return from mac_register().  Upon success (0 return value), the mhp
 * opaque pointer becomes the driver's handle to its MAC interface, and is
 * the argument to all other mac module entry points.
 */
int
mac_register(mac_register_t *mregp, mac_handle_t *mhp)
{
	mac_impl_t		*mip;
	mactype_t		*mtype;
	int			err = EINVAL;
	struct devnames		*dnp = NULL;
	uint_t			instance;
	boolean_t		style1_created = B_FALSE;
	boolean_t		style2_created = B_FALSE;
	mac_capab_legacy_t	legacy;
	char			*driver;
	minor_t			minor = 0;

	/* Find the required MAC-Type plugin. */
	if ((mtype = i_mactype_getplugin(mregp->m_type_ident)) == NULL)
		return (EINVAL);

	/* Create a mac_impl_t to represent this MAC. */
	mip = kmem_cache_alloc(i_mac_impl_cachep, KM_SLEEP);

	/*
	 * The mac is not ready for open yet.
	 */
	mip->mi_disabled = B_TRUE;

	/*
	 * When a mac is registered, the m_instance field can be set to:
	 *
	 *  0:	Get the mac's instance number from m_dip.
	 *	This is usually used for physical device dips.
	 *
	 *  [1 .. MAC_MAX_MINOR-1]: Use the value as the mac's instance number.
	 *	For example, when an aggregation is created with the key option,
	 *	"key" will be used as the instance number.
	 *
	 *  -1: Assign an instance number from [MAC_MAX_MINOR .. MAXMIN-1].
	 *	This is often used when a MAC of a virtual link is registered
	 *	(e.g., aggregation when "key" is not specified, or vnic).
	 *
	 * Note that the instance number is used to derive the mi_minor field
	 * of mac_impl_t, which will then be used to derive the name of kstats
	 * and the devfs nodes.  The first 2 cases are needed to preserve
	 * backward compatibility.
	 */
	switch (mregp->m_instance) {
	case 0:
		instance = ddi_get_instance(mregp->m_dip);
		break;
	case ((uint_t)-1):
		minor = mac_minor_hold(B_TRUE);
		if (minor == 0) {
			err = ENOSPC;
			goto fail;
		}
		instance = minor - 1;
		break;
	default:
		instance = mregp->m_instance;
		if (instance >= MAC_MAX_MINOR) {
			err = EINVAL;
			goto fail;
		}
		break;
	}

	mip->mi_minor = (minor_t)(instance + 1);
	mip->mi_dip = mregp->m_dip;

	driver = (char *)ddi_driver_name(mip->mi_dip);

	/* Construct the MAC name as <drvname><instance> */
	(void) snprintf(mip->mi_name, sizeof (mip->mi_name), "%s%d",
	    driver, instance);

	mip->mi_driver = mregp->m_driver;

	mip->mi_type = mtype;
	mip->mi_margin = mregp->m_margin;
	mip->mi_info.mi_media = mtype->mt_type;
	mip->mi_info.mi_nativemedia = mtype->mt_nativetype;
	if (mregp->m_max_sdu <= mregp->m_min_sdu)
		goto fail;
	mip->mi_sdu_min = mregp->m_min_sdu;
	mip->mi_sdu_max = mregp->m_max_sdu;
	mip->mi_info.mi_addr_length = mip->mi_type->mt_addr_length;
	/*
	 * If the media supports a broadcast address, cache a pointer to it
	 * in the mac_info_t so that upper layers can use it.
	 */
	mip->mi_info.mi_brdcst_addr = mip->mi_type->mt_brdcst_addr;

	/*
	 * Copy the unicast source address into the mac_info_t, but only if
	 * the MAC-Type defines a non-zero address length.  We need to
	 * handle MAC-Types that have an address length of 0
	 * (point-to-point protocol MACs for example).
	 */
	if (mip->mi_type->mt_addr_length > 0) {
		if (mregp->m_src_addr == NULL)
			goto fail;
		mip->mi_info.mi_unicst_addr =
		    kmem_alloc(mip->mi_type->mt_addr_length, KM_SLEEP);
		bcopy(mregp->m_src_addr, mip->mi_info.mi_unicst_addr,
		    mip->mi_type->mt_addr_length);

		/*
		 * Copy the fixed 'factory' MAC address from the immutable
		 * info.  This is taken to be the MAC address currently in
		 * use.
		 */
		bcopy(mip->mi_info.mi_unicst_addr, mip->mi_addr,
		    mip->mi_type->mt_addr_length);
		/* Copy the destination address if one is provided. */
		if (mregp->m_dst_addr != NULL) {
			bcopy(mregp->m_dst_addr, mip->mi_dstaddr,
			    mip->mi_type->mt_addr_length);
		}
	} else if (mregp->m_src_addr != NULL) {
		goto fail;
	}

	/*
	 * The format of the m_pdata is specific to the plugin.  It is
	 * passed in as an argument to all of the plugin callbacks.  The
	 * driver can update this information by calling
	 * mac_pdata_update().
	 */
	if (mregp->m_pdata != NULL) {
		/*
		 * Verify that the plugin supports MAC plugin data and that
		 * the supplied data is valid.
		 */
		if (!(mip->mi_type->mt_ops.mtops_ops & MTOPS_PDATA_VERIFY))
			goto fail;
		if (!mip->mi_type->mt_ops.mtops_pdata_verify(mregp->m_pdata,
		    mregp->m_pdata_size)) {
			goto fail;
		}
		mip->mi_pdata = kmem_alloc(mregp->m_pdata_size, KM_SLEEP);
		bcopy(mregp->m_pdata, mip->mi_pdata, mregp->m_pdata_size);
		mip->mi_pdata_size = mregp->m_pdata_size;
	}

	/*
	 * Register the private properties.
	 */
	mac_register_priv_prop(mip, mregp->m_priv_props,
	    mregp->m_priv_prop_count);

	/*
	 * Stash the driver callbacks into the mac_impl_t, but first sanity
	 * check to make sure all mandatory callbacks are set.
	 */
	if (mregp->m_callbacks->mc_getstat == NULL ||
	    mregp->m_callbacks->mc_start == NULL ||
	    mregp->m_callbacks->mc_stop == NULL ||
	    mregp->m_callbacks->mc_setpromisc == NULL ||
	    mregp->m_callbacks->mc_multicst == NULL ||
	    mregp->m_callbacks->mc_unicst == NULL ||
	    mregp->m_callbacks->mc_tx == NULL) {
		goto fail;
	}
	mip->mi_callbacks = mregp->m_callbacks;

	/*
	 * Set up the possible transmit routines.
	 */
	mip->mi_txinfo.mt_fn = mip->mi_tx;
	mip->mi_txinfo.mt_arg = mip->mi_driver;

	mip->mi_legacy = mac_capab_get((mac_handle_t)mip,
	    MAC_CAPAB_LEGACY, &legacy);

	if (mip->mi_legacy) {
		/*
		 * Legacy device. Messages being sent will be looped back
		 * by the underlying driver. Therefore the txloop function
		 * pointer is the same as the tx function pointer.
		 */
		mip->mi_txloopinfo.mt_fn = mip->mi_txinfo.mt_fn;
		mip->mi_txloopinfo.mt_arg = mip->mi_txinfo.mt_arg;
		mip->mi_unsup_note = legacy.ml_unsup_note;
		mip->mi_phy_dev = legacy.ml_dev;
	} else {
		/*
		 * Normal device. The framework needs to do the loopback.
		 */
		mip->mi_txloopinfo.mt_fn = mac_txloop;
		mip->mi_txloopinfo.mt_arg = mip;
		mip->mi_unsup_note = 0;
		mip->mi_phy_dev = makedevice(ddi_driver_major(mip->mi_dip),
		    ddi_get_instance(mip->mi_dip) + 1);
	}

	mip->mi_vnic_txinfo.mt_fn = mac_vnic_tx;
	mip->mi_vnic_txinfo.mt_arg = mip;

	mip->mi_vnic_txloopinfo.mt_fn = mac_vnic_txloop;
	mip->mi_vnic_txloopinfo.mt_arg = mip;

	/*
	 * Allocate a notification thread.
	 */
	mip->mi_notify_thread = thread_create(NULL, 0, i_mac_notify_thread,
	    mip, 0, &p0, TS_RUN, minclsyspri);
	if (mip->mi_notify_thread == NULL)
		goto fail;

	/*
	 * Initialize the kstats for this device.
	 */
	mac_stat_create(mip);


	/* set the gldv3 flag in dn_flags */
	dnp = &devnamesp[ddi_driver_major(mip->mi_dip)];
	LOCK_DEV_OPS(&dnp->dn_lock);
	dnp->dn_flags |= (DN_GLDV3_DRIVER | DN_NETWORK_DRIVER);
	UNLOCK_DEV_OPS(&dnp->dn_lock);

	if (mip->mi_minor < MAC_MAX_MINOR + 1) {
		/* Create a style-2 DLPI device */
		if (ddi_create_minor_node(mip->mi_dip, driver, S_IFCHR, 0,
		    DDI_NT_NET, CLONE_DEV) != DDI_SUCCESS)
			goto fail;
		style2_created = B_TRUE;

		/* Create a style-1 DLPI device */
		if (ddi_create_minor_node(mip->mi_dip, mip->mi_name, S_IFCHR,
		    mip->mi_minor, DDI_NT_NET, 0) != DDI_SUCCESS)
			goto fail;
		style1_created = B_TRUE;
	}

	rw_enter(&i_mac_impl_lock, RW_WRITER);
	if (mod_hash_insert(i_mac_impl_hash,
	    (mod_hash_key_t)mip->mi_name, (mod_hash_val_t)mip) != 0) {

		rw_exit(&i_mac_impl_lock);
		err = EEXIST;
		goto fail;
	}

	DTRACE_PROBE2(mac__register, struct devnames *, dnp,
	    (mac_impl_t *), mip);

	/*
	 * Mark the MAC to be ready for open.
	 */
	mip->mi_disabled = B_FALSE;

	rw_exit(&i_mac_impl_lock);

	atomic_inc_32(&i_mac_impl_count);

	cmn_err(CE_NOTE, "!%s registered", mip->mi_name);
	*mhp = (mac_handle_t)mip;
	return (0);

fail:
	if (style1_created)
		ddi_remove_minor_node(mip->mi_dip, mip->mi_name);

	if (style2_created)
		ddi_remove_minor_node(mip->mi_dip, driver);

	/* clean up notification thread */
	if (mip->mi_notify_thread != NULL) {
		mutex_enter(&mip->mi_notify_bits_lock);
		mip->mi_notify_bits = (1 << MAC_NNOTE);
		cv_broadcast(&mip->mi_notify_cv);
		while (mip->mi_notify_bits != 0)
			cv_wait(&mip->mi_notify_cv, &mip->mi_notify_bits_lock);
		mutex_exit(&mip->mi_notify_bits_lock);
	}

	if (mip->mi_info.mi_unicst_addr != NULL) {
		kmem_free(mip->mi_info.mi_unicst_addr,
		    mip->mi_type->mt_addr_length);
		mip->mi_info.mi_unicst_addr = NULL;
	}

	mac_stat_destroy(mip);

	if (mip->mi_type != NULL) {
		atomic_dec_32(&mip->mi_type->mt_ref);
		mip->mi_type = NULL;
	}

	if (mip->mi_pdata != NULL) {
		kmem_free(mip->mi_pdata, mip->mi_pdata_size);
		mip->mi_pdata = NULL;
		mip->mi_pdata_size = 0;
	}

	if (minor != 0) {
		ASSERT(minor > MAC_MAX_MINOR);
		mac_minor_rele(minor);
	}

	mac_unregister_priv_prop(mip);

	kmem_cache_free(i_mac_impl_cachep, mip);
	return (err);
}

int
mac_disable(mac_handle_t mh)
{
	mac_impl_t		*mip = (mac_impl_t *)mh;

	/*
	 * See if there are any other references to this mac_t (e.g., VLAN's).
	 * If not, set mi_disabled to prevent any new VLAN's from being
	 * created while we're destroying this mac.
	 */
	rw_enter(&i_mac_impl_lock, RW_WRITER);
	if (mip->mi_ref > 0) {
		rw_exit(&i_mac_impl_lock);
		return (EBUSY);
	}
	mip->mi_disabled = B_TRUE;
	rw_exit(&i_mac_impl_lock);
	return (0);
}

int
mac_unregister(mac_handle_t mh)
{
	int			err;
	mac_impl_t		*mip = (mac_impl_t *)mh;
	mod_hash_val_t		val;
	mac_multicst_addr_t	*p, *nextp;
	mac_margin_req_t	*mmr, *nextmmr;

	/*
	 * See if there are any other references to this mac_t (e.g., VLAN's).
	 * If not, set mi_disabled to prevent any new VLAN's from being
	 * created while we're destroying this mac. Once mac_disable() returns
	 * 0, the rest of mac_unregister() stuff should continue without
	 * returning an error.
	 */
	if (!mip->mi_disabled) {
		if ((err = mac_disable(mh)) != 0)
			return (err);
	}

	/*
	 * Clean up notification thread (wait for it to exit).
	 */
	mutex_enter(&mip->mi_notify_bits_lock);
	mip->mi_notify_bits = (1 << MAC_NNOTE);
	cv_broadcast(&mip->mi_notify_cv);
	while (mip->mi_notify_bits != 0)
		cv_wait(&mip->mi_notify_cv, &mip->mi_notify_bits_lock);
	mutex_exit(&mip->mi_notify_bits_lock);

	if (mip->mi_minor < MAC_MAX_MINOR + 1) {
		ddi_remove_minor_node(mip->mi_dip, mip->mi_name);
		ddi_remove_minor_node(mip->mi_dip,
		    (char *)ddi_driver_name(mip->mi_dip));
	}

	ASSERT(!mip->mi_activelink);

	mac_stat_destroy(mip);

	rw_enter(&i_mac_impl_lock, RW_WRITER);
	(void) mod_hash_remove(i_mac_impl_hash,
	    (mod_hash_key_t)mip->mi_name, &val);
	ASSERT(mip == (mac_impl_t *)val);

	ASSERT(i_mac_impl_count > 0);
	atomic_dec_32(&i_mac_impl_count);
	rw_exit(&i_mac_impl_lock);

	if (mip->mi_pdata != NULL)
		kmem_free(mip->mi_pdata, mip->mi_pdata_size);
	mip->mi_pdata = NULL;
	mip->mi_pdata_size = 0;

	/*
	 * Free the list of multicast addresses.
	 */
	for (p = mip->mi_mmap; p != NULL; p = nextp) {
		nextp = p->mma_nextp;
		kmem_free(p, sizeof (mac_multicst_addr_t));
	}
	mip->mi_mmap = NULL;

	/*
	 * Free the list of margin request.
	 */
	for (mmr = mip->mi_mmrp; mmr != NULL; mmr = nextmmr) {
		nextmmr = mmr->mmr_nextp;
		kmem_free(mmr, sizeof (mac_margin_req_t));
	}
	mip->mi_mmrp = NULL;

	mip->mi_linkstate = LINK_STATE_UNKNOWN;
	kmem_free(mip->mi_info.mi_unicst_addr, mip->mi_type->mt_addr_length);
	mip->mi_info.mi_unicst_addr = NULL;

	atomic_dec_32(&mip->mi_type->mt_ref);
	mip->mi_type = NULL;

	if (mip->mi_minor > MAC_MAX_MINOR)
		mac_minor_rele(mip->mi_minor);

	mac_unregister_priv_prop(mip);

	cmn_err(CE_NOTE, "!%s unregistered", mip->mi_name);

	kmem_cache_free(i_mac_impl_cachep, mip);

	return (0);
}

/*
 * To avoid potential deadlocks, mac_rx() releases mi_rx_lock
 * before invoking its list of upcalls. This introduces races with
 * mac_rx_remove() and mac_rx_add(), who can potentially modify the
 * upcall list while mi_rx_lock is not being held. The race with
 * mac_rx_remove() is handled by incrementing mi_rx_ref upon entering
 * mac_rx(); a non-zero mi_rx_ref would tell mac_rx_remove()
 * to not modify the list but instead mark an upcall for deletion.
 * before mac_rx() exits, mi_rx_ref is decremented and if it
 * is 0, the marked upcalls will be removed from the list and freed.
 * The race with mac_rx_add() is harmless because mac_rx_add() only
 * prepends to the list and since mac_rx() saves the list head
 * before releasing mi_rx_lock, any prepended upcall won't be seen
 * until the next packet chain arrives.
 *
 * To minimize lock contention between multiple parallel invocations
 * of mac_rx(), mi_rx_lock is acquired as a READER lock. The
 * use of atomic operations ensures the sanity of mi_rx_ref. mi_rx_lock
 * will be upgraded to WRITER mode when there are marked upcalls to be
 * cleaned.
 */
static void
mac_do_rx(mac_handle_t mh, mac_resource_handle_t mrh, mblk_t *mp_chain,
    boolean_t active_only)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	mblk_t		*bp = mp_chain;
	mac_rx_fn_t	*mrfp;

	/*
	 * Call all registered receive functions.
	 */
	rw_enter(&mip->mi_rx_lock, RW_READER);
	if ((mrfp = mip->mi_mrfp) == NULL) {
		/* There are no registered receive functions. */
		freemsgchain(bp);
		rw_exit(&mip->mi_rx_lock);
		return;
	}
	atomic_inc_32(&mip->mi_rx_ref);
	rw_exit(&mip->mi_rx_lock);

	/*
	 * Call registered receive functions.
	 */
	do {
		mblk_t *recv_bp;

		if (active_only && !mrfp->mrf_active) {
			mrfp = mrfp->mrf_nextp;
			if (mrfp == NULL) {
				/*
				 * We hit the last receiver, but it's not
				 * active.
				 */
				freemsgchain(bp);
			}
			continue;
		}

		recv_bp = (mrfp->mrf_nextp != NULL) ? copymsgchain(bp) : bp;
		if (recv_bp != NULL) {
			if (mrfp->mrf_inuse) {
				/*
				 * Send bp itself and keep the copy.
				 * If there's only one active receiver,
				 * it should get the original message,
				 * tagged with the hardware checksum flags.
				 */
				mrfp->mrf_fn(mrfp->mrf_arg, mrh, bp);
				bp = recv_bp;
			} else {
				freemsgchain(recv_bp);
			}
		}

		mrfp = mrfp->mrf_nextp;
	} while (mrfp != NULL);

	rw_enter(&mip->mi_rx_lock, RW_READER);
	if (atomic_dec_32_nv(&mip->mi_rx_ref) == 0 && mip->mi_rx_removed > 0) {
		mac_rx_fn_t	**pp, *p;
		uint32_t	cnt = 0;

		DTRACE_PROBE1(delete_callbacks, mac_impl_t *, mip);

		/*
		 * Need to become exclusive before doing cleanup
		 */
		if (rw_tryupgrade(&mip->mi_rx_lock) == 0) {
			rw_exit(&mip->mi_rx_lock);
			rw_enter(&mip->mi_rx_lock, RW_WRITER);
		}

		/*
		 * We return if another thread has already entered and cleaned
		 * up the list.
		 */
		if (mip->mi_rx_ref > 0 || mip->mi_rx_removed == 0) {
			rw_exit(&mip->mi_rx_lock);
			return;
		}

		/*
		 * Free removed callbacks.
		 */
		pp = &mip->mi_mrfp;
		while (*pp != NULL) {
			if (!(*pp)->mrf_inuse) {
				p = *pp;
				*pp = (*pp)->mrf_nextp;
				kmem_free(p, sizeof (*p));
				cnt++;
				continue;
			}
			pp = &(*pp)->mrf_nextp;
		}

		/*
		 * Wake up mac_rx_remove_wait()
		 */
		mutex_enter(&mip->mi_lock);
		ASSERT(mip->mi_rx_removed == cnt);
		mip->mi_rx_removed = 0;
		cv_broadcast(&mip->mi_rx_cv);
		mutex_exit(&mip->mi_lock);
	}
	rw_exit(&mip->mi_rx_lock);
}

void
mac_rx(mac_handle_t mh, mac_resource_handle_t mrh, mblk_t *mp_chain)
{
	mac_do_rx(mh, mrh, mp_chain, B_FALSE);
}

/*
 * Send a packet chain up to the receive callbacks which declared
 * themselves as being active.
 */
void
mac_active_rx(void *arg, mac_resource_handle_t mrh, mblk_t *mp_chain)
{
	mac_do_rx(arg, mrh, mp_chain, B_TRUE);
}

/*
 * Function passed to the active client sharing a VNIC. This function
 * is returned by mac_tx_get() when a VNIC is present. It invokes
 * the VNIC transmit entry point which was specified by the VNIC when
 * it called mac_vnic_set(). The VNIC transmit entry point will
 * pass the packets to the local VNICs and/or to the underlying VNICs
 * if needed.
 */
static mblk_t *
mac_vnic_tx(void *arg, mblk_t *mp)
{
	mac_impl_t	*mip = arg;
	mac_txinfo_t	*mtfp;
	mac_vnic_tx_t	*mvt;

	/*
	 * There is a race between the notification of the VNIC
	 * addition and removal, and the processing of the VNIC notification
	 * by the MAC client. During this window, it is possible for
	 * an active MAC client to contine invoking mac_vnic_tx() while
	 * the VNIC has already been removed. So we cannot assume
	 * that mi_vnic_present will always be true when mac_vnic_tx()
	 * is invoked.
	 */
	rw_enter(&mip->mi_tx_lock, RW_READER);
	if (!mip->mi_vnic_present) {
		rw_exit(&mip->mi_tx_lock);
		freemsgchain(mp);
		return (NULL);
	}

	ASSERT(mip->mi_vnic_tx != NULL);
	mvt = mip->mi_vnic_tx;
	MAC_VNIC_TXINFO_REFHOLD(mvt);
	rw_exit(&mip->mi_tx_lock);

	mtfp = &mvt->mv_txinfo;
	mtfp->mt_fn(mtfp->mt_arg, mp);

	MAC_VNIC_TXINFO_REFRELE(mvt);
	return (NULL);
}

/*
 * Transmit function -- ONLY used when there are registered loopback listeners.
 */
mblk_t *
mac_do_txloop(void *arg, mblk_t *bp, boolean_t call_vnic)
{
	mac_impl_t	*mip = arg;
	mac_txloop_fn_t	*mtfp;
	mblk_t		*loop_bp, *resid_bp, *next_bp;

	if (call_vnic) {
		/*
		 * In promiscous mode, a copy of the sent packet will
		 * be sent to the client's promiscous receive entry
		 * points via mac_vnic_tx()->
		 * mac_active_rx_promisc()->mac_rx_default().
		 */
		return (mac_vnic_tx(arg, bp));
	}

	while (bp != NULL) {
		next_bp = bp->b_next;
		bp->b_next = NULL;

		if ((loop_bp = copymsg(bp)) == NULL)
			goto noresources;

		if ((resid_bp = mip->mi_tx(mip->mi_driver, bp)) != NULL) {
			ASSERT(resid_bp == bp);
			freemsg(loop_bp);
			goto noresources;
		}

		rw_enter(&mip->mi_tx_lock, RW_READER);
		mtfp = mip->mi_mtfp;
		while (mtfp != NULL && loop_bp != NULL) {
			bp = loop_bp;

			/* XXX counter bump if copymsg() fails? */
			if (mtfp->mtf_nextp != NULL)
				loop_bp = copymsg(bp);
			else
				loop_bp = NULL;

			mtfp->mtf_fn(mtfp->mtf_arg, bp);
			mtfp = mtfp->mtf_nextp;
		}
		rw_exit(&mip->mi_tx_lock);

		/*
		 * It's possible we've raced with the disabling of promiscuous
		 * mode, in which case we can discard our copy.
		 */
		if (loop_bp != NULL)
			freemsg(loop_bp);

		bp = next_bp;
	}

	return (NULL);

noresources:
	bp->b_next = next_bp;
	return (bp);
}

mblk_t *
mac_txloop(void *arg, mblk_t *bp)
{
	return (mac_do_txloop(arg, bp, B_FALSE));
}

static mblk_t *
mac_vnic_txloop(void *arg, mblk_t *bp)
{
	return (mac_do_txloop(arg, bp, B_TRUE));
}

void
mac_link_update(mac_handle_t mh, link_state_t link)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	/*
	 * Save the link state.
	 */
	mip->mi_linkstate = link;

	/*
	 * Send a MAC_NOTE_LINK notification.
	 */
	i_mac_notify(mip, MAC_NOTE_LINK);
}

void
mac_unicst_update(mac_handle_t mh, const uint8_t *addr)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	if (mip->mi_type->mt_addr_length == 0)
		return;

	/*
	 * If the address has not changed, do nothing.
	 */
	if (bcmp(addr, mip->mi_addr, mip->mi_type->mt_addr_length) == 0)
		return;

	/*
	 * Save the address.
	 */
	bcopy(addr, mip->mi_addr, mip->mi_type->mt_addr_length);

	/*
	 * Send a MAC_NOTE_UNICST notification.
	 */
	i_mac_notify(mip, MAC_NOTE_UNICST);
}

void
mac_tx_update(mac_handle_t mh)
{
	/*
	 * Send a MAC_NOTE_TX notification.
	 */
	i_mac_notify((mac_impl_t *)mh, MAC_NOTE_TX);
}

void
mac_resource_update(mac_handle_t mh)
{
	/*
	 * Send a MAC_NOTE_RESOURCE notification.
	 */
	i_mac_notify((mac_impl_t *)mh, MAC_NOTE_RESOURCE);
}

mac_resource_handle_t
mac_resource_add(mac_handle_t mh, mac_resource_t *mrp)
{
	mac_impl_t		*mip = (mac_impl_t *)mh;
	mac_resource_handle_t	mrh;
	mac_resource_add_t	add;
	void			*arg;

	rw_enter(&mip->mi_resource_lock, RW_READER);
	add = mip->mi_resource_add;
	arg = mip->mi_resource_add_arg;

	if (add != NULL)
		mrh = add(arg, mrp);
	else
		mrh = NULL;
	rw_exit(&mip->mi_resource_lock);

	return (mrh);
}

int
mac_pdata_update(mac_handle_t mh, void *mac_pdata, size_t dsize)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	/*
	 * Verify that the plugin supports MAC plugin data and that the
	 * supplied data is valid.
	 */
	if (!(mip->mi_type->mt_ops.mtops_ops & MTOPS_PDATA_VERIFY))
		return (EINVAL);
	if (!mip->mi_type->mt_ops.mtops_pdata_verify(mac_pdata, dsize))
		return (EINVAL);

	if (mip->mi_pdata != NULL)
		kmem_free(mip->mi_pdata, mip->mi_pdata_size);

	mip->mi_pdata = kmem_alloc(dsize, KM_SLEEP);
	bcopy(mac_pdata, mip->mi_pdata, dsize);
	mip->mi_pdata_size = dsize;

	/*
	 * Since the MAC plugin data is used to construct MAC headers that
	 * were cached in fast-path headers, we need to flush fast-path
	 * information for links associated with this mac.
	 */
	i_mac_notify(mip, MAC_NOTE_FASTPATH_FLUSH);
	return (0);
}

void
mac_multicst_refresh(mac_handle_t mh, mac_multicst_t refresh, void *arg,
    boolean_t add)
{
	mac_impl_t		*mip = (mac_impl_t *)mh;
	mac_multicst_addr_t	*p;

	/*
	 * If no specific refresh function was given then default to the
	 * driver's m_multicst entry point.
	 */
	if (refresh == NULL) {
		refresh = mip->mi_multicst;
		arg = mip->mi_driver;
	}
	ASSERT(refresh != NULL);

	/*
	 * Walk the multicast address list and call the refresh function for
	 * each address.
	 */
	rw_enter(&(mip->mi_data_lock), RW_READER);
	for (p = mip->mi_mmap; p != NULL; p = p->mma_nextp)
		refresh(arg, add, p->mma_addr);
	rw_exit(&(mip->mi_data_lock));
}

void
mac_unicst_refresh(mac_handle_t mh, mac_unicst_t refresh, void *arg)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	/*
	 * If no specific refresh function was given then default to the
	 * driver's mi_unicst entry point.
	 */
	if (refresh == NULL) {
		refresh = mip->mi_unicst;
		arg = mip->mi_driver;
	}
	ASSERT(refresh != NULL);

	/*
	 * Call the refresh function with the current unicast address.
	 */
	refresh(arg, mip->mi_addr);
}

void
mac_promisc_refresh(mac_handle_t mh, mac_setpromisc_t refresh, void *arg)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	/*
	 * If no specific refresh function was given then default to the
	 * driver's m_promisc entry point.
	 */
	if (refresh == NULL) {
		refresh = mip->mi_setpromisc;
		arg = mip->mi_driver;
	}
	ASSERT(refresh != NULL);

	/*
	 * Call the refresh function with the current promiscuity.
	 */
	refresh(arg, (mip->mi_devpromisc != 0));
}

/*
 * The mac client requests that the mac not to change its margin size to
 * be less than the specified value.  If "current" is B_TRUE, then the client
 * requests the mac not to change its margin size to be smaller than the
 * current size. Further, return the current margin size value in this case.
 *
 * We keep every requested size in an ordered list from largest to smallest.
 */
int
mac_margin_add(mac_handle_t mh, uint32_t *marginp, boolean_t current)
{
	mac_impl_t		*mip = (mac_impl_t *)mh;
	mac_margin_req_t	**pp, *p;
	int			err = 0;

	rw_enter(&(mip->mi_data_lock), RW_WRITER);
	if (current)
		*marginp = mip->mi_margin;

	/*
	 * If the current margin value cannot satisfy the margin requested,
	 * return ENOTSUP directly.
	 */
	if (*marginp > mip->mi_margin) {
		err = ENOTSUP;
		goto done;
	}

	/*
	 * Check whether the given margin is already in the list. If so,
	 * bump the reference count.
	 */
	for (pp = &(mip->mi_mmrp); (p = *pp) != NULL; pp = &(p->mmr_nextp)) {
		if (p->mmr_margin == *marginp) {
			/*
			 * The margin requested is already in the list,
			 * so just bump the reference count.
			 */
			p->mmr_ref++;
			goto done;
		}
		if (p->mmr_margin < *marginp)
			break;
	}


	if ((p = kmem_zalloc(sizeof (mac_margin_req_t), KM_NOSLEEP)) == NULL) {
		err = ENOMEM;
		goto done;
	}

	p->mmr_margin = *marginp;
	p->mmr_ref++;
	p->mmr_nextp = *pp;
	*pp = p;

done:
	rw_exit(&(mip->mi_data_lock));
	return (err);
}

/*
 * The mac client requests to cancel its previous mac_margin_add() request.
 * We remove the requested margin size from the list.
 */
int
mac_margin_remove(mac_handle_t mh, uint32_t margin)
{
	mac_impl_t		*mip = (mac_impl_t *)mh;
	mac_margin_req_t	**pp, *p;
	int			err = 0;

	rw_enter(&(mip->mi_data_lock), RW_WRITER);
	/*
	 * Find the entry in the list for the given margin.
	 */
	for (pp = &(mip->mi_mmrp); (p = *pp) != NULL; pp = &(p->mmr_nextp)) {
		if (p->mmr_margin == margin) {
			if (--p->mmr_ref == 0)
				break;

			/*
			 * There is still a reference to this address so
			 * there's nothing more to do.
			 */
			goto done;
		}
	}

	/*
	 * We did not find an entry for the given margin.
	 */
	if (p == NULL) {
		err = ENOENT;
		goto done;
	}

	ASSERT(p->mmr_ref == 0);

	/*
	 * Remove it from the list.
	 */
	*pp = p->mmr_nextp;
	kmem_free(p, sizeof (mac_margin_req_t));
done:
	rw_exit(&(mip->mi_data_lock));
	return (err);
}

/*
 * The mac client requests to get the mac's current margin value.
 */
void
mac_margin_get(mac_handle_t mh, uint32_t *marginp)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	rw_enter(&(mip->mi_data_lock), RW_READER);
	*marginp = mip->mi_margin;
	rw_exit(&(mip->mi_data_lock));
}

boolean_t
mac_margin_update(mac_handle_t mh, uint32_t margin)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	uint32_t	margin_needed = 0;

	rw_enter(&(mip->mi_data_lock), RW_WRITER);

	if (mip->mi_mmrp != NULL)
		margin_needed = mip->mi_mmrp->mmr_margin;

	if (margin_needed <= margin)
		mip->mi_margin = margin;

	rw_exit(&(mip->mi_data_lock));

	if (margin_needed <= margin)
		i_mac_notify(mip, MAC_NOTE_MARGIN);

	return (margin_needed <= margin);
}

boolean_t
mac_do_active_set(mac_handle_t mh, boolean_t shareable)
{
	mac_impl_t *mip = (mac_impl_t *)mh;

	mutex_enter(&mip->mi_activelink_lock);
	if (mip->mi_activelink) {
		mutex_exit(&mip->mi_activelink_lock);
		return (B_FALSE);
	}
	mip->mi_activelink = B_TRUE;
	mip->mi_shareable = shareable;
	mutex_exit(&mip->mi_activelink_lock);
	return (B_TRUE);
}

/*
 * Called by MAC clients. By default, active MAC clients cannot
 * share the NIC with VNICs.
 */
boolean_t
mac_active_set(mac_handle_t mh)
{
	return (mac_do_active_set(mh, B_FALSE));
}

/*
 * Called by MAC clients which can share the NIC with VNICS, e.g. DLS.
 */
boolean_t
mac_active_shareable_set(mac_handle_t mh)
{
	return (mac_do_active_set(mh, B_TRUE));
}

void
mac_active_clear(mac_handle_t mh)
{
	mac_impl_t *mip = (mac_impl_t *)mh;

	mutex_enter(&mip->mi_activelink_lock);
	ASSERT(mip->mi_activelink);
	mip->mi_activelink = B_FALSE;
	mutex_exit(&mip->mi_activelink_lock);
}

boolean_t
mac_vnic_set(mac_handle_t mh, mac_txinfo_t *tx_info, mac_getcapab_t getcapab_fn,
    void *getcapab_arg)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	mac_vnic_tx_t	*vnic_tx;

	mutex_enter(&mip->mi_activelink_lock);
	rw_enter(&mip->mi_tx_lock, RW_WRITER);
	ASSERT(!mip->mi_vnic_present);

	if (mip->mi_activelink && !mip->mi_shareable) {
		/*
		 * The NIC is already used by an active client which cannot
		 * share it with VNICs.
		 */
		rw_exit(&mip->mi_tx_lock);
		mutex_exit(&mip->mi_activelink_lock);
		return (B_FALSE);
	}

	vnic_tx = kmem_cache_alloc(mac_vnic_tx_cache, KM_SLEEP);
	vnic_tx->mv_refs = 0;
	vnic_tx->mv_txinfo = *tx_info;
	vnic_tx->mv_clearing = B_FALSE;

	mip->mi_vnic_present = B_TRUE;
	mip->mi_vnic_tx = vnic_tx;
	mip->mi_vnic_getcapab_fn = getcapab_fn;
	mip->mi_vnic_getcapab_arg = getcapab_arg;
	rw_exit(&mip->mi_tx_lock);
	mutex_exit(&mip->mi_activelink_lock);

	i_mac_notify(mip, MAC_NOTE_VNIC);
	return (B_TRUE);
}

void
mac_vnic_clear(mac_handle_t mh)
{
	mac_impl_t *mip = (mac_impl_t *)mh;
	mac_vnic_tx_t	*vnic_tx;

	rw_enter(&mip->mi_tx_lock, RW_WRITER);
	ASSERT(mip->mi_vnic_present);
	mip->mi_vnic_present = B_FALSE;
	/*
	 * Setting mi_vnic_tx to NULL here under the lock guarantees
	 * that no new references to the current VNIC transmit structure
	 * will be taken by mac_vnic_tx(). This is a necessary condition
	 * for safely waiting for the reference count to drop to
	 * zero below.
	 */
	vnic_tx = mip->mi_vnic_tx;
	mip->mi_vnic_tx = NULL;
	mip->mi_vnic_getcapab_fn = NULL;
	mip->mi_vnic_getcapab_arg = NULL;
	rw_exit(&mip->mi_tx_lock);

	i_mac_notify(mip, MAC_NOTE_VNIC);

	/*
	 * Wait for all TX calls referencing the VNIC transmit
	 * entry point that was removed to complete.
	 */
	mutex_enter(&vnic_tx->mv_lock);
	vnic_tx->mv_clearing = B_TRUE;
	while (vnic_tx->mv_refs > 0)
		cv_wait(&vnic_tx->mv_cv, &vnic_tx->mv_lock);
	mutex_exit(&vnic_tx->mv_lock);
	kmem_cache_free(mac_vnic_tx_cache, vnic_tx);
}

/*
 * mac_info_get() is used for retrieving the mac_info when a DL_INFO_REQ is
 * issued before a DL_ATTACH_REQ. we walk the i_mac_impl_hash table and find
 * the first mac_impl_t with a matching driver name; then we copy its mac_info_t
 * to the caller. we do all this with i_mac_impl_lock held so the mac_impl_t
 * cannot disappear while we are accessing it.
 */
typedef struct i_mac_info_state_s {
	const char	*mi_name;
	mac_info_t	*mi_infop;
} i_mac_info_state_t;

/*ARGSUSED*/
static uint_t
i_mac_info_walker(mod_hash_key_t key, mod_hash_val_t *val, void *arg)
{
	i_mac_info_state_t	*statep = arg;
	mac_impl_t		*mip = (mac_impl_t *)val;

	if (mip->mi_disabled)
		return (MH_WALK_CONTINUE);

	if (strcmp(statep->mi_name,
	    ddi_driver_name(mip->mi_dip)) != 0)
		return (MH_WALK_CONTINUE);

	statep->mi_infop = &mip->mi_info;
	return (MH_WALK_TERMINATE);
}

boolean_t
mac_info_get(const char *name, mac_info_t *minfop)
{
	i_mac_info_state_t	state;

	rw_enter(&i_mac_impl_lock, RW_READER);
	state.mi_name = name;
	state.mi_infop = NULL;
	mod_hash_walk(i_mac_impl_hash, i_mac_info_walker, &state);
	if (state.mi_infop == NULL) {
		rw_exit(&i_mac_impl_lock);
		return (B_FALSE);
	}
	*minfop = *state.mi_infop;
	rw_exit(&i_mac_impl_lock);
	return (B_TRUE);
}

boolean_t
mac_do_capab_get(mac_handle_t mh, mac_capab_t cap, void *cap_data,
    boolean_t is_vnic)
{
	mac_impl_t *mip = (mac_impl_t *)mh;

	if (!is_vnic) {
		rw_enter(&mip->mi_tx_lock, RW_READER);
		if (mip->mi_vnic_present) {
			boolean_t rv;

			rv = mip->mi_vnic_getcapab_fn(mip->mi_vnic_getcapab_arg,
			    cap, cap_data);
			rw_exit(&mip->mi_tx_lock);
			return (rv);
		}
		rw_exit(&mip->mi_tx_lock);
	}

	if (mip->mi_callbacks->mc_callbacks & MC_GETCAPAB)
		return (mip->mi_getcapab(mip->mi_driver, cap, cap_data));
	else
		return (B_FALSE);
}

boolean_t
mac_capab_get(mac_handle_t mh, mac_capab_t cap, void *cap_data)
{
	return (mac_do_capab_get(mh, cap, cap_data, B_FALSE));
}

boolean_t
mac_vnic_capab_get(mac_handle_t mh, mac_capab_t cap, void *cap_data)
{
	return (mac_do_capab_get(mh, cap, cap_data, B_TRUE));
}

boolean_t
mac_sap_verify(mac_handle_t mh, uint32_t sap, uint32_t *bind_sap)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	return (mip->mi_type->mt_ops.mtops_sap_verify(sap, bind_sap,
	    mip->mi_pdata));
}

mblk_t *
mac_header(mac_handle_t mh, const uint8_t *daddr, uint32_t sap, mblk_t *payload,
    size_t extra_len)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	return (mip->mi_type->mt_ops.mtops_header(mip->mi_addr, daddr, sap,
	    mip->mi_pdata, payload, extra_len));
}

int
mac_header_info(mac_handle_t mh, mblk_t *mp, mac_header_info_t *mhip)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	return (mip->mi_type->mt_ops.mtops_header_info(mp, mip->mi_pdata,
	    mhip));
}

mblk_t *
mac_header_cook(mac_handle_t mh, mblk_t *mp)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	if (mip->mi_type->mt_ops.mtops_ops & MTOPS_HEADER_COOK) {
		if (DB_REF(mp) > 1) {
			mblk_t *newmp = copymsg(mp);
			if (newmp == NULL)
				return (NULL);
			freemsg(mp);
			mp = newmp;
		}
		return (mip->mi_type->mt_ops.mtops_header_cook(mp,
		    mip->mi_pdata));
	}
	return (mp);
}

mblk_t *
mac_header_uncook(mac_handle_t mh, mblk_t *mp)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	if (mip->mi_type->mt_ops.mtops_ops & MTOPS_HEADER_UNCOOK) {
		if (DB_REF(mp) > 1) {
			mblk_t *newmp = copymsg(mp);
			if (newmp == NULL)
				return (NULL);
			freemsg(mp);
			mp = newmp;
		}
		return (mip->mi_type->mt_ops.mtops_header_uncook(mp,
		    mip->mi_pdata));
	}
	return (mp);
}

void
mac_init_ops(struct dev_ops *ops, const char *name)
{
	dld_init_ops(ops, name);
}

void
mac_fini_ops(struct dev_ops *ops)
{
	dld_fini_ops(ops);
}

/*
 * MAC Type Plugin functions.
 */

mactype_register_t *
mactype_alloc(uint_t mactype_version)
{
	mactype_register_t *mtrp;

	/*
	 * Make sure there isn't a version mismatch between the plugin and
	 * the framework.  In the future, if multiple versions are
	 * supported, this check could become more sophisticated.
	 */
	if (mactype_version != MACTYPE_VERSION)
		return (NULL);

	mtrp = kmem_zalloc(sizeof (mactype_register_t), KM_SLEEP);
	mtrp->mtr_version = mactype_version;
	return (mtrp);
}

void
mactype_free(mactype_register_t *mtrp)
{
	kmem_free(mtrp, sizeof (mactype_register_t));
}

int
mactype_register(mactype_register_t *mtrp)
{
	mactype_t	*mtp;
	mactype_ops_t	*ops = mtrp->mtr_ops;

	/* Do some sanity checking before we register this MAC type. */
	if (mtrp->mtr_ident == NULL || ops == NULL)
		return (EINVAL);

	/*
	 * Verify that all mandatory callbacks are set in the ops
	 * vector.
	 */
	if (ops->mtops_unicst_verify == NULL ||
	    ops->mtops_multicst_verify == NULL ||
	    ops->mtops_sap_verify == NULL ||
	    ops->mtops_header == NULL ||
	    ops->mtops_header_info == NULL) {
		return (EINVAL);
	}

	mtp = kmem_zalloc(sizeof (*mtp), KM_SLEEP);
	mtp->mt_ident = mtrp->mtr_ident;
	mtp->mt_ops = *ops;
	mtp->mt_type = mtrp->mtr_mactype;
	mtp->mt_nativetype = mtrp->mtr_nativetype;
	mtp->mt_addr_length = mtrp->mtr_addrlen;
	if (mtrp->mtr_brdcst_addr != NULL) {
		mtp->mt_brdcst_addr = kmem_alloc(mtrp->mtr_addrlen, KM_SLEEP);
		bcopy(mtrp->mtr_brdcst_addr, mtp->mt_brdcst_addr,
		    mtrp->mtr_addrlen);
	}

	mtp->mt_stats = mtrp->mtr_stats;
	mtp->mt_statcount = mtrp->mtr_statcount;

	mtp->mt_mapping = mtrp->mtr_mapping;
	mtp->mt_mappingcount = mtrp->mtr_mappingcount;

	if (mod_hash_insert(i_mactype_hash,
	    (mod_hash_key_t)mtp->mt_ident, (mod_hash_val_t)mtp) != 0) {
		kmem_free(mtp->mt_brdcst_addr, mtp->mt_addr_length);
		kmem_free(mtp, sizeof (*mtp));
		return (EEXIST);
	}
	return (0);
}

int
mactype_unregister(const char *ident)
{
	mactype_t	*mtp;
	mod_hash_val_t	val;
	int 		err;

	/*
	 * Let's not allow MAC drivers to use this plugin while we're
	 * trying to unregister it.  Holding i_mactype_lock also prevents a
	 * plugin from unregistering while a MAC driver is attempting to
	 * hold a reference to it in i_mactype_getplugin().
	 */
	mutex_enter(&i_mactype_lock);

	if ((err = mod_hash_find(i_mactype_hash, (mod_hash_key_t)ident,
	    (mod_hash_val_t *)&mtp)) != 0) {
		/* A plugin is trying to unregister, but it never registered. */
		err = ENXIO;
		goto done;
	}

	if (mtp->mt_ref != 0) {
		err = EBUSY;
		goto done;
	}

	err = mod_hash_remove(i_mactype_hash, (mod_hash_key_t)ident, &val);
	ASSERT(err == 0);
	if (err != 0) {
		/* This should never happen, thus the ASSERT() above. */
		err = EINVAL;
		goto done;
	}
	ASSERT(mtp == (mactype_t *)val);

	kmem_free(mtp->mt_brdcst_addr, mtp->mt_addr_length);
	kmem_free(mtp, sizeof (mactype_t));
done:
	mutex_exit(&i_mactype_lock);
	return (err);
}

int
mac_set_prop(mac_handle_t mh, mac_prop_t *macprop, void *val, uint_t valsize)
{
	int err = ENOTSUP;
	mac_impl_t *mip = (mac_impl_t *)mh;

	if (mip->mi_callbacks->mc_callbacks & MC_SETPROP) {
		err = mip->mi_callbacks->mc_setprop(mip->mi_driver,
		    macprop->mp_name, macprop->mp_id, valsize, val);
	}
	return (err);
}

int
mac_get_prop(mac_handle_t mh, mac_prop_t *macprop, void *val, uint_t valsize)
{
	int err = ENOTSUP;
	mac_impl_t *mip = (mac_impl_t *)mh;
	uint32_t sdu;
	link_state_t link_state;

	switch (macprop->mp_id) {
	case MAC_PROP_MTU:
		if (valsize < sizeof (sdu))
			return (EINVAL);
		if ((macprop->mp_flags & MAC_PROP_DEFAULT) == 0) {
			mac_sdu_get(mh, NULL, &sdu);
			bcopy(&sdu, val, sizeof (sdu));
			return (0);
		} else {
			if (mip->mi_info.mi_media == DL_ETHER) {
				sdu = ETHERMTU;
				bcopy(&sdu, val, sizeof (sdu));
				return (0);
			}
			/*
			 * ask driver for its default.
			 */
			break;
		}
	case MAC_PROP_STATUS:
		if (valsize < sizeof (link_state))
			return (EINVAL);
		link_state = mac_link_get(mh);
		bcopy(&link_state, val, sizeof (link_state));
		return (0);
	default:
		break;
	}
	if (mip->mi_callbacks->mc_callbacks & MC_GETPROP) {
		err = mip->mi_callbacks->mc_getprop(mip->mi_driver,
		    macprop->mp_name, macprop->mp_id, macprop->mp_flags,
		    valsize, val);
	}
	return (err);
}

int
mac_maxsdu_update(mac_handle_t mh, uint_t sdu_max)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	if (sdu_max <= mip->mi_sdu_min)
		return (EINVAL);
	mip->mi_sdu_max = sdu_max;

	/* Send a MAC_NOTE_SDU_SIZE notification. */
	i_mac_notify(mip, MAC_NOTE_SDU_SIZE);
	return (0);
}

static void
mac_register_priv_prop(mac_impl_t *mip, mac_priv_prop_t *mpp, uint_t nprop)
{
	mac_priv_prop_t *mpriv;

	if (mpp == NULL)
		return;

	mpriv = kmem_zalloc(nprop * sizeof (*mpriv), KM_SLEEP);
	(void) memcpy(mpriv, mpp, nprop * sizeof (*mpriv));
	mip->mi_priv_prop = mpriv;
	mip->mi_priv_prop_count = nprop;
}

static void
mac_unregister_priv_prop(mac_impl_t *mip)
{
	mac_priv_prop_t	*mpriv;

	mpriv = mip->mi_priv_prop;
	if (mpriv != NULL) {
		kmem_free(mpriv, mip->mi_priv_prop_count * sizeof (*mpriv));
		mip->mi_priv_prop = NULL;
	}
	mip->mi_priv_prop_count = 0;
}
