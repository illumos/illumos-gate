/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * MAC Services Module
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/dlpi.h>
#include <sys/mac.h>
#include <sys/mac_impl.h>
#include <sys/dld_impl.h>

#define	IMPL_HASHSZ	67	/* prime */

static kmem_cache_t	*i_mac_impl_cachep;
static ght_t		i_mac_impl_hash;

/*
 * Private functions.
 */

/*ARGSUSED*/
static boolean_t
i_mac_ether_unicst_verify(mac_impl_t *mip, const uint8_t *addr)
{
	/*
	 * Check the address is not a group address.
	 */
	if (addr[0] & 0x01)
		return (B_FALSE);

	return (B_TRUE);
}

static boolean_t
i_mac_ether_multicst_verify(mac_impl_t *mip, const uint8_t *addr)
{
	mac_t		*mp = mip->mi_mp;

	/*
	 * Check the address is a group address.
	 */
	if (!(addr[0] & 0x01))
		return (B_FALSE);

	/*
	 * Check the address is not the media broadcast address.
	 */
	if (bcmp(addr, mp->m_info.mi_brdcst_addr, mip->mi_addr_length) == 0)
		return (B_FALSE);

	return (B_TRUE);
}

/*ARGSUSED*/
static int
i_mac_constructor(void *buf, void *arg, int kmflag)
{
	mac_impl_t	*mip = buf;

	bzero(buf, sizeof (mac_impl_t));

	mip->mi_link = LINK_STATE_UNKNOWN;

	rw_init(&mip->mi_state_lock, NULL, RW_DRIVER, NULL);
	rw_init(&mip->mi_data_lock, NULL, RW_DRIVER, NULL);
	rw_init(&mip->mi_notify_lock, NULL, RW_DRIVER, NULL);
	rw_init(&mip->mi_rx_lock, NULL, RW_DRIVER, NULL);
	rw_init(&mip->mi_txloop_lock, NULL, RW_DRIVER, NULL);
	rw_init(&mip->mi_resource_lock, NULL, RW_DRIVER, NULL);
	mutex_init(&mip->mi_activelink_lock, NULL, MUTEX_DEFAULT, NULL);
	return (0);
}

/*ARGSUSED*/
static void
i_mac_destructor(void *buf, void *arg)
{
	mac_impl_t	*mip = buf;

	ASSERT(mip->mi_mp == NULL);
	ASSERT(mip->mi_hte == NULL);
	ASSERT(mip->mi_ref == 0);
	ASSERT(mip->mi_active == 0);
	ASSERT(mip->mi_link == LINK_STATE_UNKNOWN);
	ASSERT(mip->mi_devpromisc == 0);
	ASSERT(mip->mi_promisc == 0);
	ASSERT(mip->mi_mmap == NULL);
	ASSERT(mip->mi_mnfp == NULL);
	ASSERT(mip->mi_resource_add == NULL);
	ASSERT(mip->mi_ksp == NULL);

	rw_destroy(&mip->mi_state_lock);
	rw_destroy(&mip->mi_data_lock);
	rw_destroy(&mip->mi_notify_lock);
	rw_destroy(&mip->mi_rx_lock);
	rw_destroy(&mip->mi_txloop_lock);
	rw_destroy(&mip->mi_resource_lock);
	mutex_destroy(&mip->mi_activelink_lock);
}

int
i_mac_create(mac_t *mp)
{
	dev_info_t	*dip;
	mac_impl_t	*mip;
	int		err;
	ghte_t		hte;

	dip = mp->m_dip;
	ASSERT(dip != NULL);
	ASSERT(ddi_get_instance(dip) >= 0);

	/*
	 * Allocate a new mac_impl_t.
	 */
	mip = kmem_cache_alloc(i_mac_impl_cachep, KM_SLEEP);

	/*
	 * Construct a name.
	 */
	(void) snprintf(mip->mi_dev, MAXNAMELEN - 1, "%s%d",
	    ddi_driver_name(dip), ddi_get_instance(dip));
	mip->mi_port = mp->m_port;

	MAC_NAME(mip->mi_name, mip->mi_dev, mip->mi_port);

	/*
	 * Set the mac_t/mac_impl_t cross-references.
	 */
	mip->mi_mp = mp;
	mp->m_impl = (void *)mip;

	/*
	 * Allocate a hash table entry.
	 */
	hte = ght_alloc(i_mac_impl_hash, KM_SLEEP);

	GHT_KEY(hte) = GHT_PTR_TO_KEY(mip->mi_name);
	GHT_VAL(hte) = GHT_PTR_TO_VAL(mip);

	/*
	 * Insert the hash table entry.
	 */
	ght_lock(i_mac_impl_hash, GHT_WRITE);
	if ((err = ght_insert(hte)) != 0) {
		ght_free(hte);
		kmem_cache_free(i_mac_impl_cachep, mip);
		goto done;
	}

	mip->mi_hte = hte;

	/*
	 * Copy the fixed 'factory' MAC address from the immutable info.
	 * This is taken to be the MAC address currently in use.
	 */
	mip->mi_addr_length = mp->m_info.mi_addr_length;
	bcopy(mp->m_info.mi_unicst_addr, mip->mi_addr, mip->mi_addr_length);

	/*
	 * Set up the address verification functions.
	 */
	ASSERT(mp->m_info.mi_media == DL_ETHER);
	mip->mi_unicst_verify = i_mac_ether_unicst_verify;
	mip->mi_multicst_verify = i_mac_ether_multicst_verify;

	/*
	 * Set up the two possible transmit routines.
	 */
	mip->mi_txinfo.mt_fn = mp->m_tx;
	mip->mi_txinfo.mt_arg = mp->m_driver;
	mip->mi_txloopinfo.mt_fn = mac_txloop;
	mip->mi_txloopinfo.mt_arg = mip;

	/*
	 * Initialize the kstats for this device.
	 */
	mac_stat_create(mip);

done:
	ght_unlock(i_mac_impl_hash);
	return (err);
}

static void
i_mac_destroy(mac_t *mp)
{
	mac_impl_t		*mip = mp->m_impl;
	ghte_t			hte;
	mac_multicst_addr_t	*p, *nextp;

	ght_lock(i_mac_impl_hash, GHT_WRITE);

	ASSERT(mip->mi_ref == 0);
	ASSERT(!mip->mi_activelink);

	/*
	 * Destroy the kstats.
	 */
	mac_stat_destroy(mip);

	/*
	 * Remove and destroy the hash table entry.
	 */
	hte = mip->mi_hte;
	ght_remove(hte);
	ght_free(hte);
	mip->mi_hte = NULL;

	/*
	 * Free the list of multicast addresses.
	 */
	for (p = mip->mi_mmap; p != NULL; p = nextp) {
		nextp = p->mma_nextp;
		kmem_free(p, sizeof (mac_multicst_addr_t));
	}
	mip->mi_mmap = NULL;

	/*
	 * Clean up the mac_impl_t ready to go back into the cache.
	 */
	mp->m_impl = NULL;
	mip->mi_mp = NULL;
	mip->mi_link = LINK_STATE_UNKNOWN;
	mip->mi_destroying = B_FALSE;

	/*
	 * Free the structure back to the cache.
	 */
	kmem_cache_free(i_mac_impl_cachep, mip);

	ght_unlock(i_mac_impl_hash);
}

static void
i_mac_notify(mac_impl_t *mip, mac_notify_type_t type)
{
	mac_notify_fn_t		*mnfp;
	mac_notify_t		notify;
	void			*arg;

	/*
	 * Walk the list of notifications.
	 */
	rw_enter(&(mip->mi_notify_lock), RW_READER);
	for (mnfp = mip->mi_mnfp; mnfp != NULL; mnfp = mnfp->mnf_nextp) {
		notify = mnfp->mnf_fn;
		arg = mnfp->mnf_arg;

		ASSERT(notify != NULL);
		notify(arg, type);
	}
	rw_exit(&(mip->mi_notify_lock));
}

/*
 * Module initialization functions.
 */

void
mac_init(void)
{
	int	err;

	i_mac_impl_cachep = kmem_cache_create("mac_impl_cache",
	    sizeof (mac_impl_t), 0, i_mac_constructor, i_mac_destructor, NULL,
	    NULL, NULL, 0);
	ASSERT(i_mac_impl_cachep != NULL);

	err = ght_str_create("mac_impl_hash", IMPL_HASHSZ, &i_mac_impl_hash);
	ASSERT(err == 0);
}

int
mac_fini(void)
{
	int	err;

	if ((err = ght_destroy(i_mac_impl_hash)) != 0)
		return (err);

	kmem_cache_destroy(i_mac_impl_cachep);
	return (0);
}

/*
 * Client functions.
 */

int
mac_open(const char *dev, uint_t port, mac_handle_t *mhp)
{
	char		name[MAXNAMELEN];
	char		driver[MAXNAMELEN];
	uint_t		instance;
	major_t		major;
	dev_info_t	*dip;
	mac_impl_t	*mip;
	ghte_t		hte;
	int		err;

	/*
	 * Check the device name length to make sure it won't overflow our
	 * buffer.
	 */
	if (strlen(dev) >= MAXNAMELEN)
		return (EINVAL);

	/*
	 * Split the device name into driver and instance components.
	 */
	if (ddi_parse(dev, driver, &instance) != DDI_SUCCESS)
		return (EINVAL);

	/*
	 * Get the major number of the driver.
	 */
	if ((major = ddi_name_to_major(driver)) == (major_t)-1)
		return (EINVAL);

	/*
	 * Hold the given instance to prevent it from being detached.
	 * (This will also attach it if it is not currently attached).
	 */
	if ((dip = ddi_hold_devi_by_instance(major, instance, 0)) == NULL)
		return (EINVAL);

	/*
	 * Construct the name of the MAC interface.
	 */
	MAC_NAME(name, dev, port);

	/*
	 * Look up its entry in the global hash table.
	 */
again:
	ght_lock(i_mac_impl_hash, GHT_WRITE);
	if ((err = ght_find(i_mac_impl_hash, GHT_PTR_TO_KEY(name), &hte)) != 0)
		goto failed;

	mip = (mac_impl_t *)GHT_VAL(hte);
	ASSERT(mip->mi_mp->m_dip == dip);

	if (mip->mi_destroying) {
		ght_unlock(i_mac_impl_hash);
		goto again;
	}

	mip->mi_ref++;
	ght_unlock(i_mac_impl_hash);

	*mhp = (mac_handle_t)mip;
	return (0);

failed:
	ght_unlock(i_mac_impl_hash);
	ddi_release_devi(dip);
	return (err);
}

void
mac_close(mac_handle_t mh)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	dev_info_t	*dip = mip->mi_mp->m_dip;

	ght_lock(i_mac_impl_hash, GHT_WRITE);

	ASSERT(mip->mi_ref != 0);
	if (--mip->mi_ref == 0) {
		ASSERT(!mip->mi_activelink);
	}
	ddi_release_devi(dip);
	ght_unlock(i_mac_impl_hash);
}

const mac_info_t *
mac_info(mac_handle_t mh)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	mac_t		*mp = mip->mi_mp;

	/*
	 * Return a pointer to the mac_info_t embedded in the mac_t.
	 */
	return (&(mp->m_info));
}

uint64_t
mac_stat_get(mac_handle_t mh, enum mac_stat stat)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	mac_t		*mp = mip->mi_mp;

	ASSERT(mp->m_info.mi_stat[stat]);
	ASSERT(mp->m_stat != NULL);

	/*
	 * Call the driver to get the given statistic.
	 */
	return (mp->m_stat(mp->m_driver, stat));
}

int
mac_start(mac_handle_t mh)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	mac_t		*mp = mip->mi_mp;
	int		err;

	ASSERT(mp->m_start != NULL);

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
	if ((err = mp->m_start(mp->m_driver)) != 0)
		--mip->mi_active;

done:
	rw_exit(&(mip->mi_state_lock));
	return (err);
}

void
mac_stop(mac_handle_t mh)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	mac_t		*mp = mip->mi_mp;

	ASSERT(mp->m_stop != NULL);

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
	mp->m_stop(mp->m_driver);

done:
	rw_exit(&(mip->mi_state_lock));
}

int
mac_multicst_add(mac_handle_t mh, const uint8_t *addr)
{
	mac_impl_t		*mip = (mac_impl_t *)mh;
	mac_t			*mp = mip->mi_mp;
	mac_multicst_addr_t	**pp;
	mac_multicst_addr_t	*p;
	int			err;

	ASSERT(mp->m_multicst != NULL);

	/*
	 * Verify the address.
	 */
	if (!(mip->mi_multicst_verify(mip, addr)))
		return (EINVAL);

	/*
	 * Check whether the given address is already enabled.
	 */
	rw_enter(&(mip->mi_data_lock), RW_WRITER);
	for (pp = &(mip->mi_mmap); (p = *pp) != NULL; pp = &(p->mma_nextp)) {
		if (bcmp(p->mma_addr, addr, mip->mi_addr_length) == 0) {
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
	if ((err = mp->m_multicst(mp->m_driver, B_TRUE, addr)) != 0) {
		kmem_free(p, sizeof (mac_multicst_addr_t));
		goto done;
	}

	/*
	 * Add the address to the list of enabled addresses.
	 */
	bcopy(addr, p->mma_addr, mip->mi_addr_length);
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
	mac_t			*mp = mip->mi_mp;
	mac_multicst_addr_t	**pp;
	mac_multicst_addr_t	*p;
	int			err;

	ASSERT(mp->m_multicst != NULL);

	/*
	 * Find the entry in the list for the given address.
	 */
	rw_enter(&(mip->mi_data_lock), RW_WRITER);
	for (pp = &(mip->mi_mmap); (p = *pp) != NULL; pp = &(p->mma_nextp)) {
		if (bcmp(p->mma_addr, addr, mip->mi_addr_length) == 0) {
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
	if ((err = mp->m_multicst(mp->m_driver, B_FALSE, addr)) != 0) {
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

int
mac_unicst_set(mac_handle_t mh, const uint8_t *addr)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	mac_t		*mp = mip->mi_mp;
	int		err;
	boolean_t	notify = B_FALSE;

	ASSERT(mp->m_unicst != NULL);

	/*
	 * Verify the address.
	 */
	if (!(mip->mi_unicst_verify(mip, addr)))
		return (EINVAL);

	/*
	 * Program the new unicast address.
	 */
	rw_enter(&(mip->mi_data_lock), RW_WRITER);

	/*
	 * If address doesn't change, do nothing.
	 * This check is necessary otherwise it may call into mac_unicst_set
	 * recursively.
	 */
	if (bcmp(addr, mip->mi_addr, mip->mi_addr_length) == 0) {
		err = 0;
		goto done;
	}

	if ((err = mp->m_unicst(mp->m_driver, addr)) != 0)
		goto done;

	/*
	 * Save the address and flag that we need to send a notification.
	 */
	bcopy(addr, mip->mi_addr, mip->mi_addr_length);
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
	 * Copy out the current unicast address.
	 */
	rw_enter(&(mip->mi_data_lock), RW_READER);
	bcopy(mip->mi_addr, addr, mip->mi_addr_length);
	rw_exit(&(mip->mi_data_lock));
}

int
mac_promisc_set(mac_handle_t mh, boolean_t on, mac_promisc_type_t ptype)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	mac_t		*mp = mip->mi_mp;
	int		err = 0;

	ASSERT(mp->m_promisc != NULL);
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
			if ((err = mp->m_promisc(mp->m_driver, B_TRUE)) != 0) {
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
			if ((err = mp->m_promisc(mp->m_driver, B_FALSE)) != 0) {
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
mac_resources(mac_handle_t mh)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	mac_t		*mp = mip->mi_mp;

	ASSERT(mp->m_resources != NULL);

	/*
	 * Call the driver to register its resources.
	 */
	mp->m_resources(mp->m_driver);
}

void
mac_ioctl(mac_handle_t mh, queue_t *wq, mblk_t *bp)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	mac_t		*mp = mip->mi_mp;

	ASSERT(mp->m_ioctl != NULL);

	/*
	 * Call the driver to handle the ioctl.
	 */
	mp->m_ioctl(mp->m_driver, wq, bp);
}

const mac_txinfo_t *
mac_tx_get(mac_handle_t mh)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	mac_txinfo_t	*mtp;

	/*
	 * Grab the lock to prevent us from racing with MAC_PROMISC being
	 * changed.  This is sufficient since MAC clients are careful to always
	 * call mac_txloop_add() prior to enabling MAC_PROMISC, and to disable
	 * MAC_PROMISC prior to calling mac_txloop_remove().
	 */
	rw_enter(&mip->mi_txloop_lock, RW_READER);

	if (mac_promisc_get(mh, MAC_PROMISC)) {
		ASSERT(mip->mi_mtfp != NULL);
		mtp = &mip->mi_txloopinfo;
	} else {
		/*
		 * Note that we cannot ASSERT() that mip->mi_mtfp is NULL,
		 * because to satisfy the above ASSERT(), we have to disable
		 * MAC_PROMISC prior to calling mac_txloop_remove().
		 */
		mtp = &mip->mi_txinfo;

	}

	rw_exit(&mip->mi_txloop_lock);
	return (mtp);
}

link_state_t
mac_link_get(mac_handle_t mh)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	/*
	 * Return the current link state.
	 */
	return (mip->mi_link);
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
	rw_enter(&(mip->mi_notify_lock), RW_WRITER);
	mnfp->mnf_nextp = mip->mi_mnfp;
	mip->mi_mnfp = mnfp;
	rw_exit(&(mip->mi_notify_lock));

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
	rw_enter(&(mip->mi_notify_lock), RW_WRITER);
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
	rw_exit(&(mip->mi_notify_lock));

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

mac_rx_handle_t
mac_rx_add(mac_handle_t mh, mac_rx_t rx, void *arg)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	mac_rx_fn_t	*mrfp;

	mrfp = kmem_zalloc(sizeof (mac_rx_fn_t), KM_SLEEP);
	mrfp->mrf_fn = rx;
	mrfp->mrf_arg = arg;

	/*
	 * Add it to the head of the 'rx' callback list.
	 */
	rw_enter(&(mip->mi_rx_lock), RW_WRITER);
	mrfp->mrf_nextp = mip->mi_mrfp;
	mip->mi_mrfp = mrfp;
	rw_exit(&(mip->mi_rx_lock));

	return ((mac_rx_handle_t)mrfp);
}

/*
 * Unregister a receive function for this mac.  This removes the function
 * from the list of receive functions for this mac.
 */
void
mac_rx_remove(mac_handle_t mh, mac_rx_handle_t mrh)
{
	mac_impl_t		*mip = (mac_impl_t *)mh;
	mac_rx_fn_t		*mrfp = (mac_rx_fn_t *)mrh;
	mac_rx_fn_t		**pp;
	mac_rx_fn_t		*p;

	/*
	 * Search the 'rx' callback list for the function closure.
	 */
	rw_enter(&(mip->mi_rx_lock), RW_WRITER);
	for (pp = &(mip->mi_mrfp); (p = *pp) != NULL; pp = &(p->mrf_nextp)) {
		if (p == mrfp)
			break;
	}
	ASSERT(p != NULL);

	/* Remove it from the list. */
	*pp = p->mrf_nextp;
	kmem_free(mrfp, sizeof (mac_rx_fn_t));
	rw_exit(&(mip->mi_rx_lock));
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
	rw_enter(&(mip->mi_txloop_lock), RW_WRITER);
	mtfp->mtf_nextp = mip->mi_mtfp;
	mip->mi_mtfp = mtfp;
	rw_exit(&(mip->mi_txloop_lock));

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
	rw_enter(&(mip->mi_txloop_lock), RW_WRITER);
	for (pp = &(mip->mi_mtfp); (p = *pp) != NULL; pp = &(p->mtf_nextp)) {
		if (p == mtfp)
			break;
	}
	ASSERT(p != NULL);

	/* Remove it from the list. */
	*pp = p->mtf_nextp;
	kmem_free(mtfp, sizeof (mac_txloop_fn_t));
	rw_exit(&(mip->mi_txloop_lock));
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

int
mac_register(mac_t *mp)
{
	int	err;
	char	name[MAXNAMELEN], aggr_name[MAXNAMELEN];
	struct devnames *dnp;

#ifdef	DEBUG
	if (strcmp(mp->m_ident, MAC_IDENT) != 0)
		cmn_err(CE_WARN, "%s%d/%d: possible mac interface mismatch",
		    ddi_driver_name(mp->m_dip),
		    ddi_get_instance(mp->m_dip),
		    mp->m_port);
#endif	/* DEBUG */

	ASSERT(!(mp->m_info.mi_addr_length & 1));

	/*
	 * Create a new mac_impl_t to pair with the mac_t.
	 */
	if ((err = i_mac_create(mp)) != 0)
		return (err);

	/*
	 * Create a DDI_NT_MAC minor node such that libdevinfo(3lib) can be
	 * used to search for mac interfaces.
	 */
	(void) sprintf(name, "%d", mp->m_port);
	if (ddi_create_minor_node(mp->m_dip, name, S_IFCHR, mp->m_port,
	    DDI_NT_MAC, 0) != DDI_SUCCESS) {
		i_mac_destroy(mp);
		return (EEXIST);
	}

	/*
	 * Right now only the "aggr" driver creates nodes at mac_register
	 * time, but it is expected that in the future with some
	 * enhancement of devfs, all the drivers can create nodes here.
	 */
	if (strcmp(ddi_driver_name(mp->m_dip), "aggr") == 0) {
		(void) snprintf(aggr_name, MAXNAMELEN, "aggr%u", mp->m_port);
		err = dld_ppa_create(aggr_name, AGGR_DEV, mp->m_port, 0);
		if (err != 0) {
			ASSERT(err != EEXIST);
			ddi_remove_minor_node(mp->m_dip, name);
			i_mac_destroy(mp);
			return (err);
		}
	}

	/* set the gldv3 flag in dn_flags */
	dnp = &devnamesp[ddi_driver_major(mp->m_dip)];
	LOCK_DEV_OPS(&dnp->dn_lock);
	dnp->dn_flags |= DN_GLDV3_DRIVER;
	UNLOCK_DEV_OPS(&dnp->dn_lock);

	cmn_err(CE_NOTE, "!%s%d/%d registered",
	    ddi_driver_name(mp->m_dip),
	    ddi_get_instance(mp->m_dip),
	    mp->m_port);

	return (0);
}

int
mac_unregister(mac_t *mp)
{
	int		err;
	char		name[MAXNAMELEN];
	mac_impl_t	*mip = mp->m_impl;

	/*
	 * See if there are any other references to this mac_t (e.g., VLAN's).
	 * If not, set mi_destroying to prevent any new VLAN's from being
	 * created before we can perform the i_mac_destroy() below.
	 */
	ght_lock(i_mac_impl_hash, GHT_WRITE);
	if (mip->mi_ref > 0) {
		ght_unlock(i_mac_impl_hash);
		return (EBUSY);
	}
	mip->mi_destroying = B_TRUE;
	ght_unlock(i_mac_impl_hash);

	if (strcmp(ddi_driver_name(mp->m_dip), "aggr") == 0) {
		(void) snprintf(name, MAXNAMELEN, "aggr%u", mp->m_port);
		if ((err = dld_ppa_destroy(name)) != 0)
			return (err);
	}

	/*
	 * Destroy the mac_impl_t.
	 */
	i_mac_destroy(mp);

	/*
	 * Remove the minor node.
	 */
	(void) sprintf(name, "%d", mp->m_port);
	ddi_remove_minor_node(mp->m_dip, name);

	cmn_err(CE_NOTE, "!%s%d/%d unregistered",
	    ddi_driver_name(mp->m_dip),
	    ddi_get_instance(mp->m_dip),
	    mp->m_port);

	return (0);
}

void
mac_rx(mac_t *mp, mac_resource_handle_t mrh, mblk_t *bp)
{
	mac_impl_t	*mip = mp->m_impl;
	mac_rx_fn_t	*mrfp;

	/*
	 * Call all registered receive functions.
	 */
	rw_enter(&mip->mi_rx_lock, RW_READER);
	mrfp = mip->mi_mrfp;
	if (mrfp == NULL) {
		/* There are no registered receive functions. */
		freemsgchain(bp);
		rw_exit(&mip->mi_rx_lock);
		return;
	}
	do {
		mblk_t *recv_bp;

		if (mrfp->mrf_nextp != NULL) {
			/* XXX Do we bump a counter if copymsgchain() fails? */
			recv_bp = copymsgchain(bp);
		} else {
			recv_bp = bp;
		}
		if (recv_bp != NULL)
			mrfp->mrf_fn(mrfp->mrf_arg, mrh, recv_bp);
		mrfp = mrfp->mrf_nextp;
	} while (mrfp != NULL);
	rw_exit(&mip->mi_rx_lock);
}

/*
 * Transmit function -- ONLY used when there are registered loopback listeners.
 */
mblk_t *
mac_txloop(void *arg, mblk_t *bp)
{
	mac_impl_t	*mip = arg;
	mac_t		*mp = mip->mi_mp;
	mac_txloop_fn_t	*mtfp;
	mblk_t		*loop_bp, *resid_bp, *next_bp;

	while (bp != NULL) {
		next_bp = bp->b_next;
		bp->b_next = NULL;

		if ((loop_bp = copymsg(bp)) == NULL)
			goto noresources;

		if ((resid_bp = mp->m_tx(mp->m_driver, bp)) != NULL) {
			ASSERT(resid_bp == bp);
			freemsg(loop_bp);
			goto noresources;
		}

		rw_enter(&mip->mi_txloop_lock, RW_READER);
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
		rw_exit(&mip->mi_txloop_lock);

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

void
mac_link_update(mac_t *mp, link_state_t link)
{
	mac_impl_t	*mip = mp->m_impl;

	ASSERT(mip->mi_mp == mp);

	/*
	 * Save the link state.
	 */
	mip->mi_link = link;

	/*
	 * Send a MAC_NOTE_LINK notification.
	 */
	i_mac_notify(mip, MAC_NOTE_LINK);
}

void
mac_unicst_update(mac_t *mp, const uint8_t *addr)
{
	mac_impl_t	*mip = mp->m_impl;

	ASSERT(mip->mi_mp == mp);

	/*
	 * Save the address.
	 */
	bcopy(addr, mip->mi_addr, mip->mi_addr_length);

	/*
	 * Send a MAC_NOTE_UNICST notification.
	 */
	i_mac_notify(mip, MAC_NOTE_UNICST);
}

void
mac_tx_update(mac_t *mp)
{
	mac_impl_t	*mip = mp->m_impl;

	ASSERT(mip->mi_mp == mp);

	/*
	 * Send a MAC_NOTE_TX notification.
	 */
	i_mac_notify(mip, MAC_NOTE_TX);
}

void
mac_resource_update(mac_t *mp)
{
	mac_impl_t	*mip = mp->m_impl;

	ASSERT(mip->mi_mp == mp);

	/*
	 * Send a MAC_NOTE_RESOURCE notification.
	 */
	i_mac_notify(mip, MAC_NOTE_RESOURCE);
}

mac_resource_handle_t
mac_resource_add(mac_t *mp, mac_resource_t *mrp)
{
	mac_impl_t		*mip = mp->m_impl;
	mac_resource_handle_t	mrh;
	mac_resource_add_t	add;
	void			*arg;

	rw_enter(&mip->mi_resource_lock, RW_READER);
	add = mip->mi_resource_add;
	arg = mip->mi_resource_add_arg;

	mrh = add(arg, mrp);
	rw_exit(&mip->mi_resource_lock);

	return (mrh);
}

void
mac_multicst_refresh(mac_t *mp, mac_multicst_t refresh, void *arg,
    boolean_t add)
{
	mac_impl_t		*mip = mp->m_impl;
	mac_multicst_addr_t	*p;

	/*
	 * If no specific refresh function was given then default to the
	 * driver's m_multicst entry point.
	 */
	if (refresh == NULL) {
		refresh = mp->m_multicst;
		arg = mp->m_driver;
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
mac_unicst_refresh(mac_t *mp, mac_unicst_t refresh, void *arg)
{
	mac_impl_t	*mip = mp->m_impl;
	/*
	 * If no specific refresh function was given then default to the
	 * driver's m_unicst entry point.
	 */
	if (refresh == NULL) {
		refresh = mp->m_unicst;
		arg = mp->m_driver;
	}
	ASSERT(refresh != NULL);

	/*
	 * Call the refresh function with the current unicast address.
	 */
	refresh(arg, mip->mi_addr);
}

void
mac_promisc_refresh(mac_t *mp, mac_promisc_t refresh, void *arg)
{
	mac_impl_t	*mip = mp->m_impl;

	/*
	 * If no specific refresh function was given then default to the
	 * driver's m_promisc entry point.
	 */
	if (refresh == NULL) {
		refresh = mp->m_promisc;
		arg = mp->m_driver;
	}
	ASSERT(refresh != NULL);

	/*
	 * Call the refresh function with the current promiscuity.
	 */
	refresh(arg, (mip->mi_devpromisc != 0));
}

boolean_t
mac_active_set(mac_handle_t mh)
{
	mac_impl_t *mip = (mac_impl_t *)mh;

	mutex_enter(&mip->mi_activelink_lock);
	if (mip->mi_activelink) {
		mutex_exit(&mip->mi_activelink_lock);
		return (B_FALSE);
	}
	mip->mi_activelink = B_TRUE;
	mutex_exit(&mip->mi_activelink_lock);
	return (B_TRUE);
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
