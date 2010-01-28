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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/id_space.h>
#include <sys/esunddi.h>
#include <sys/stat.h>
#include <sys/mkdev.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/dlpi.h>
#include <sys/modhash.h>
#include <sys/mac.h>
#include <sys/mac_provider.h>
#include <sys/mac_impl.h>
#include <sys/mac_client_impl.h>
#include <sys/mac_client_priv.h>
#include <sys/mac_soft_ring.h>
#include <sys/dld.h>
#include <sys/modctl.h>
#include <sys/fs/dv_node.h>
#include <sys/thread.h>
#include <sys/proc.h>
#include <sys/callb.h>
#include <sys/cpuvar.h>
#include <sys/atomic.h>
#include <sys/sdt.h>
#include <sys/mac_flow.h>
#include <sys/ddi_intr_impl.h>
#include <sys/disp.h>
#include <sys/sdt.h>

/*
 * MAC Provider Interface.
 *
 * Interface for GLDv3 compatible NIC drivers.
 */

static void i_mac_notify_thread(void *);

typedef void (*mac_notify_default_cb_fn_t)(mac_impl_t *);

static const mac_notify_default_cb_fn_t mac_notify_cb_list[MAC_NNOTE] = {
	mac_fanout_recompute,	/* MAC_NOTE_LINK */
	NULL,		/* MAC_NOTE_UNICST */
	NULL,		/* MAC_NOTE_TX */
	NULL,		/* MAC_NOTE_DEVPROMISC */
	NULL,		/* MAC_NOTE_FASTPATH_FLUSH */
	NULL,		/* MAC_NOTE_SDU_SIZE */
	NULL,		/* MAC_NOTE_MARGIN */
	NULL,		/* MAC_NOTE_CAPAB_CHG */
	NULL		/* MAC_NOTE_LOWLINK */
};

/*
 * Driver support functions.
 */

/* REGISTRATION */

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
 * mac_register() is how drivers register new MACs with the GLDv3
 * framework.  The mregp argument is allocated by drivers using the
 * mac_alloc() function, and can be freed using mac_free() immediately upon
 * return from mac_register().  Upon success (0 return value), the mhp
 * opaque pointer becomes the driver's handle to its MAC interface, and is
 * the argument to all other mac module entry points.
 */
/* ARGSUSED */
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
	char			*driver;
	minor_t			minor = 0;

	/* A successful call to mac_init_ops() sets the DN_GLDV3_DRIVER flag. */
	if (!GLDV3_DRV(ddi_driver_major(mregp->m_dip)))
		return (EINVAL);

	/* Find the required MAC-Type plugin. */
	if ((mtype = mactype_getplugin(mregp->m_type_ident)) == NULL)
		return (EINVAL);

	/* Create a mac_impl_t to represent this MAC. */
	mip = kmem_cache_alloc(i_mac_impl_cachep, KM_SLEEP);

	/*
	 * The mac is not ready for open yet.
	 */
	mip->mi_state_flags |= MIS_DISABLED;

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
	mip->mi_clients_list = NULL;
	mip->mi_nclients = 0;

	/* Set the default IEEE Port VLAN Identifier */
	mip->mi_pvid = 1;

	/* Default bridge link learning protection values */
	mip->mi_llimit = 1000;
	mip->mi_ldecay = 200;

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

	mip->mi_v12n_level = mregp->m_v12n;

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

		/*
		 * At this point, we should set up the classification
		 * rules etc but we delay it till mac_open() so that
		 * the resource discovery has taken place and we
		 * know someone wants to use the device. Otherwise
		 * memory gets allocated for Rx ring structures even
		 * during probe.
		 */

		/* Copy the destination address if one is provided. */
		if (mregp->m_dst_addr != NULL) {
			bcopy(mregp->m_dst_addr, mip->mi_dstaddr,
			    mip->mi_type->mt_addr_length);
			mip->mi_dstaddr_set = B_TRUE;
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
	if (mip->mi_type->mt_ops.mtops_ops & MTOPS_PDATA_VERIFY) {
		/*
		 * Verify if the supplied plugin data is valid.  Note that
		 * even if the caller passed in a NULL pointer as plugin data,
		 * we still need to verify if that's valid as the plugin may
		 * require plugin data to function.
		 */
		if (!mip->mi_type->mt_ops.mtops_pdata_verify(mregp->m_pdata,
		    mregp->m_pdata_size)) {
			goto fail;
		}
		if (mregp->m_pdata != NULL) {
			mip->mi_pdata =
			    kmem_alloc(mregp->m_pdata_size, KM_SLEEP);
			bcopy(mregp->m_pdata, mip->mi_pdata,
			    mregp->m_pdata_size);
			mip->mi_pdata_size = mregp->m_pdata_size;
		}
	} else if (mregp->m_pdata != NULL) {
		/*
		 * The caller supplied non-NULL plugin data, but the plugin
		 * does not recognize plugin data.
		 */
		err = EINVAL;
		goto fail;
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
	    mregp->m_callbacks->mc_multicst == NULL) {
		goto fail;
	}
	mip->mi_callbacks = mregp->m_callbacks;

	if (mac_capab_get((mac_handle_t)mip, MAC_CAPAB_LEGACY,
	    &mip->mi_capab_legacy)) {
		mip->mi_state_flags |= MIS_LEGACY;
		mip->mi_phy_dev = mip->mi_capab_legacy.ml_dev;
	} else {
		mip->mi_phy_dev = makedevice(ddi_driver_major(mip->mi_dip),
		    mip->mi_minor);
	}

	/*
	 * Allocate a notification thread. thread_create blocks for memory
	 * if needed, it never fails.
	 */
	mip->mi_notify_thread = thread_create(NULL, 0, i_mac_notify_thread,
	    mip, 0, &p0, TS_RUN, minclsyspri);

	/*
	 * Initialize the capabilities
	 */

	if (i_mac_capab_get((mac_handle_t)mip, MAC_CAPAB_VNIC, NULL))
		mip->mi_state_flags |= MIS_IS_VNIC;

	if (i_mac_capab_get((mac_handle_t)mip, MAC_CAPAB_AGGR, NULL))
		mip->mi_state_flags |= MIS_IS_AGGR;

	mac_addr_factory_init(mip);

	/*
	 * Enforce the virtrualization level registered.
	 */
	if (mip->mi_v12n_level & MAC_VIRT_LEVEL1) {
		if (mac_init_rings(mip, MAC_RING_TYPE_RX) != 0 ||
		    mac_init_rings(mip, MAC_RING_TYPE_TX) != 0)
			goto fail;

		/*
		 * The driver needs to register at least rx rings for this
		 * virtualization level.
		 */
		if (mip->mi_rx_groups == NULL)
			goto fail;
	}

	/*
	 * The driver must set mc_unicst entry point to NULL when it advertises
	 * CAP_RINGS for rx groups.
	 */
	if (mip->mi_rx_groups != NULL) {
		if (mregp->m_callbacks->mc_unicst != NULL)
			goto fail;
	} else {
		if (mregp->m_callbacks->mc_unicst == NULL)
			goto fail;
	}

	/*
	 * The driver must set mc_tx entry point to NULL when it advertises
	 * CAP_RINGS for tx rings.
	 */
	if (mip->mi_tx_groups != NULL) {
		if (mregp->m_callbacks->mc_tx != NULL)
			goto fail;
	} else {
		if (mregp->m_callbacks->mc_tx == NULL)
			goto fail;
	}

	/*
	 * Initialize MAC addresses. Must be called after mac_init_rings().
	 */
	mac_init_macaddr(mip);

	mip->mi_share_capab.ms_snum = 0;
	if (mip->mi_v12n_level & MAC_VIRT_HIO) {
		(void) mac_capab_get((mac_handle_t)mip, MAC_CAPAB_SHARES,
		    &mip->mi_share_capab);
	}

	/*
	 * Initialize the kstats for this device.
	 */
	mac_stat_create(mip);

	/* Zero out any properties. */
	bzero(&mip->mi_resource_props, sizeof (mac_resource_props_t));

	if (mip->mi_minor <= MAC_MAX_MINOR) {
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

	mac_flow_l2tab_create(mip, &mip->mi_flow_tab);

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
	mip->mi_state_flags &= ~MIS_DISABLED;
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

	mac_addr_factory_fini(mip);

	/* Clean up registered MAC addresses */
	mac_fini_macaddr(mip);

	/* Clean up registered rings */
	mac_free_rings(mip, MAC_RING_TYPE_RX);
	mac_free_rings(mip, MAC_RING_TYPE_TX);

	/* Clean up notification thread */
	if (mip->mi_notify_thread != NULL)
		i_mac_notify_exit(mip);

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

	/*
	 * Clear the state before destroying the mac_impl_t
	 */
	mip->mi_state_flags = 0;

	kmem_cache_free(i_mac_impl_cachep, mip);
	return (err);
}

/*
 * Unregister from the GLDv3 framework
 */
int
mac_unregister(mac_handle_t mh)
{
	int			err;
	mac_impl_t		*mip = (mac_impl_t *)mh;
	mod_hash_val_t		val;
	mac_margin_req_t	*mmr, *nextmmr;

	/* Fail the unregister if there are any open references to this mac. */
	if ((err = mac_disable_nowait(mh)) != 0)
		return (err);

	/*
	 * Clean up notification thread and wait for it to exit.
	 */
	i_mac_notify_exit(mip);

	i_mac_perim_enter(mip);

	/*
	 * There is still resource properties configured over this mac.
	 */
	if (mip->mi_resource_props.mrp_mask != 0)
		mac_fastpath_enable((mac_handle_t)mip);

	if (mip->mi_minor < MAC_MAX_MINOR + 1) {
		ddi_remove_minor_node(mip->mi_dip, mip->mi_name);
		ddi_remove_minor_node(mip->mi_dip,
		    (char *)ddi_driver_name(mip->mi_dip));
	}

	ASSERT(mip->mi_nactiveclients == 0 && !(mip->mi_state_flags &
	    MIS_EXCLUSIVE));

	mac_stat_destroy(mip);

	(void) mod_hash_remove(i_mac_impl_hash,
	    (mod_hash_key_t)mip->mi_name, &val);
	ASSERT(mip == (mac_impl_t *)val);

	ASSERT(i_mac_impl_count > 0);
	atomic_dec_32(&i_mac_impl_count);

	if (mip->mi_pdata != NULL)
		kmem_free(mip->mi_pdata, mip->mi_pdata_size);
	mip->mi_pdata = NULL;
	mip->mi_pdata_size = 0;

	/*
	 * Free the list of margin request.
	 */
	for (mmr = mip->mi_mmrp; mmr != NULL; mmr = nextmmr) {
		nextmmr = mmr->mmr_nextp;
		kmem_free(mmr, sizeof (mac_margin_req_t));
	}
	mip->mi_mmrp = NULL;

	mip->mi_linkstate = mip->mi_lowlinkstate = LINK_STATE_UNKNOWN;
	kmem_free(mip->mi_info.mi_unicst_addr, mip->mi_type->mt_addr_length);
	mip->mi_info.mi_unicst_addr = NULL;

	atomic_dec_32(&mip->mi_type->mt_ref);
	mip->mi_type = NULL;

	/*
	 * Free the primary MAC address.
	 */
	mac_fini_macaddr(mip);

	/*
	 * free all rings
	 */
	mac_free_rings(mip, MAC_RING_TYPE_RX);
	mac_free_rings(mip, MAC_RING_TYPE_TX);

	mac_addr_factory_fini(mip);

	bzero(mip->mi_addr, MAXMACADDRLEN);
	bzero(mip->mi_dstaddr, MAXMACADDRLEN);

	/* and the flows */
	mac_flow_tab_destroy(mip->mi_flow_tab);
	mip->mi_flow_tab = NULL;

	if (mip->mi_minor > MAC_MAX_MINOR)
		mac_minor_rele(mip->mi_minor);

	cmn_err(CE_NOTE, "!%s unregistered", mip->mi_name);

	/*
	 * Reset the perim related fields to default values before
	 * kmem_cache_free
	 */
	i_mac_perim_exit(mip);
	mip->mi_state_flags = 0;

	mac_unregister_priv_prop(mip);

	ASSERT(mip->mi_bridge_link == NULL);
	kmem_cache_free(i_mac_impl_cachep, mip);

	return (0);
}

/* DATA RECEPTION */

/*
 * This function is invoked for packets received by the MAC driver in
 * interrupt context. The ring generation number provided by the driver
 * is matched with the ring generation number held in MAC. If they do not
 * match, received packets are considered stale packets coming from an older
 * assignment of the ring. Drop them.
 */
void
mac_rx_ring(mac_handle_t mh, mac_ring_handle_t mrh, mblk_t *mp_chain,
    uint64_t mr_gen_num)
{
	mac_ring_t		*mr = (mac_ring_t *)mrh;

	if ((mr != NULL) && (mr->mr_gen_num != mr_gen_num)) {
		DTRACE_PROBE2(mac__rx__rings__stale__packet, uint64_t,
		    mr->mr_gen_num, uint64_t, mr_gen_num);
		freemsgchain(mp_chain);
		return;
	}
	mac_rx(mh, (mac_resource_handle_t)mrh, mp_chain);
}

/*
 * This function is invoked for each packet received by the underlying driver.
 */
void
mac_rx(mac_handle_t mh, mac_resource_handle_t mrh, mblk_t *mp_chain)
{
	mac_impl_t *mip = (mac_impl_t *)mh;

	/*
	 * Check if the link is part of a bridge.  If not, then we don't need
	 * to take the lock to remain consistent.  Make this common case
	 * lock-free and tail-call optimized.
	 */
	if (mip->mi_bridge_link == NULL) {
		mac_rx_common(mh, mrh, mp_chain);
	} else {
		/*
		 * Once we take a reference on the bridge link, the bridge
		 * module itself can't unload, so the callback pointers are
		 * stable.
		 */
		mutex_enter(&mip->mi_bridge_lock);
		if ((mh = mip->mi_bridge_link) != NULL)
			mac_bridge_ref_cb(mh, B_TRUE);
		mutex_exit(&mip->mi_bridge_lock);
		if (mh == NULL) {
			mac_rx_common((mac_handle_t)mip, mrh, mp_chain);
		} else {
			mac_bridge_rx_cb(mh, mrh, mp_chain);
			mac_bridge_ref_cb(mh, B_FALSE);
		}
	}
}

/*
 * Special case function: this allows snooping of packets transmitted and
 * received by TRILL. By design, they go directly into the TRILL module.
 */
void
mac_trill_snoop(mac_handle_t mh, mblk_t *mp)
{
	mac_impl_t *mip = (mac_impl_t *)mh;

	if (mip->mi_promisc_list != NULL)
		mac_promisc_dispatch(mip, mp, NULL);
}

/*
 * This is the upward reentry point for packets arriving from the bridging
 * module and from mac_rx for links not part of a bridge.
 */
void
mac_rx_common(mac_handle_t mh, mac_resource_handle_t mrh, mblk_t *mp_chain)
{
	mac_impl_t		*mip = (mac_impl_t *)mh;
	mac_ring_t		*mr = (mac_ring_t *)mrh;
	mac_soft_ring_set_t 	*mac_srs;
	mblk_t			*bp = mp_chain;
	boolean_t		hw_classified = B_FALSE;

	/*
	 * If there are any promiscuous mode callbacks defined for
	 * this MAC, pass them a copy if appropriate.
	 */
	if (mip->mi_promisc_list != NULL)
		mac_promisc_dispatch(mip, mp_chain, NULL);

	if (mr != NULL) {
		/*
		 * If the SRS teardown has started, just return. The 'mr'
		 * continues to be valid until the driver unregisters the mac.
		 * Hardware classified packets will not make their way up
		 * beyond this point once the teardown has started. The driver
		 * is never passed a pointer to a flow entry or SRS or any
		 * structure that can be freed much before mac_unregister.
		 */
		mutex_enter(&mr->mr_lock);
		if ((mr->mr_state != MR_INUSE) || (mr->mr_flag &
		    (MR_INCIPIENT | MR_CONDEMNED | MR_QUIESCE))) {
			mutex_exit(&mr->mr_lock);
			freemsgchain(mp_chain);
			return;
		}
		if (mr->mr_classify_type == MAC_HW_CLASSIFIER) {
			hw_classified = B_TRUE;
			MR_REFHOLD_LOCKED(mr);
		}
		mutex_exit(&mr->mr_lock);

		/*
		 * We check if an SRS is controlling this ring.
		 * If so, we can directly call the srs_lower_proc
		 * routine otherwise we need to go through mac_rx_classify
		 * to reach the right place.
		 */
		if (hw_classified) {
			mac_srs = mr->mr_srs;
			/*
			 * This is supposed to be the fast path.
			 * All packets received though here were steered by
			 * the hardware classifier, and share the same
			 * MAC header info.
			 */
			mac_srs->srs_rx.sr_lower_proc(mh,
			    (mac_resource_handle_t)mac_srs, mp_chain, B_FALSE);
			MR_REFRELE(mr);
			return;
		}
		/* We'll fall through to software classification */
	} else {
		flow_entry_t *flent;
		int err;

		rw_enter(&mip->mi_rw_lock, RW_READER);
		if (mip->mi_single_active_client != NULL) {
			flent = mip->mi_single_active_client->mci_flent_list;
			FLOW_TRY_REFHOLD(flent, err);
			rw_exit(&mip->mi_rw_lock);
			if (err == 0) {
				(flent->fe_cb_fn)(flent->fe_cb_arg1,
				    flent->fe_cb_arg2, mp_chain, B_FALSE);
				FLOW_REFRELE(flent);
				return;
			}
		} else {
			rw_exit(&mip->mi_rw_lock);
		}
	}

	if (!FLOW_TAB_EMPTY(mip->mi_flow_tab)) {
		if ((bp = mac_rx_flow(mh, mrh, bp)) == NULL)
			return;
	}

	freemsgchain(bp);
}

/* DATA TRANSMISSION */

/*
 * A driver's notification to resume transmission, in case of a provider
 * without TX rings.
 */
void
mac_tx_update(mac_handle_t mh)
{
	/*
	 * Walk the list of MAC clients (mac_client_handle)
	 * and update
	 */
	i_mac_tx_srs_notify((mac_impl_t *)mh, NULL);
}

/*
 * A driver's notification to resume transmission on the specified TX ring.
 */
void
mac_tx_ring_update(mac_handle_t mh, mac_ring_handle_t rh)
{
	i_mac_tx_srs_notify((mac_impl_t *)mh, rh);
}

/* LINK STATE */
/*
 * Notify the MAC layer about a link state change
 */
void
mac_link_update(mac_handle_t mh, link_state_t link)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	/*
	 * Save the link state.
	 */
	mip->mi_lowlinkstate = link;

	/*
	 * Send a MAC_NOTE_LOWLINK notification.  This tells the notification
	 * thread to deliver both lower and upper notifications.
	 */
	i_mac_notify(mip, MAC_NOTE_LOWLINK);
}

/*
 * Notify the MAC layer about a link state change due to bridging.
 */
void
mac_link_redo(mac_handle_t mh, link_state_t link)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	/*
	 * Save the link state.
	 */
	mip->mi_linkstate = link;

	/*
	 * Send a MAC_NOTE_LINK notification.  Only upper notifications are
	 * made.
	 */
	i_mac_notify(mip, MAC_NOTE_LINK);
}

/* MINOR NODE HANDLING */

/*
 * Given a dev_t, return the instance number (PPA) associated with it.
 * Drivers can use this in their getinfo(9e) implementation to lookup
 * the instance number (i.e. PPA) of the device, to use as an index to
 * their own array of soft state structures.
 *
 * Returns -1 on error.
 */
int
mac_devt_to_instance(dev_t devt)
{
	return (dld_devt_to_instance(devt));
}

/*
 * This function returns the first minor number that is available for
 * driver private use.  All minor numbers smaller than this are
 * reserved for GLDv3 use.
 */
minor_t
mac_private_minor(void)
{
	return (MAC_PRIVATE_MINOR);
}

/* OTHER CONTROL INFORMATION */

/*
 * A driver notified us that its primary MAC address has changed.
 */
void
mac_unicst_update(mac_handle_t mh, const uint8_t *addr)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	if (mip->mi_type->mt_addr_length == 0)
		return;

	i_mac_perim_enter(mip);

	/*
	 * If address changes, freshen the MAC address value and update
	 * all MAC clients that share this MAC address.
	 */
	if (bcmp(addr, mip->mi_addr, mip->mi_type->mt_addr_length) != 0) {
		mac_freshen_macaddr(mac_find_macaddr(mip, mip->mi_addr),
		    (uint8_t *)addr);
	}

	i_mac_perim_exit(mip);

	/*
	 * Send a MAC_NOTE_UNICST notification.
	 */
	i_mac_notify(mip, MAC_NOTE_UNICST);
}

void
mac_dst_update(mac_handle_t mh, const uint8_t *addr)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	if (mip->mi_type->mt_addr_length == 0)
		return;

	i_mac_perim_enter(mip);
	bcopy(addr, mip->mi_dstaddr, mip->mi_type->mt_addr_length);
	i_mac_perim_exit(mip);
	i_mac_notify(mip, MAC_NOTE_DEST);
}

/*
 * MAC plugin information changed.
 */
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

/*
 * Invoked by driver as well as the framework to notify its capability change.
 */
void
mac_capab_update(mac_handle_t mh)
{
	/* Send MAC_NOTE_CAPAB_CHG notification */
	i_mac_notify((mac_impl_t *)mh, MAC_NOTE_CAPAB_CHG);
}

int
mac_maxsdu_update(mac_handle_t mh, uint_t sdu_max)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	if (sdu_max == 0 || sdu_max < mip->mi_sdu_min)
		return (EINVAL);
	mip->mi_sdu_max = sdu_max;

	/* Send a MAC_NOTE_SDU_SIZE notification. */
	i_mac_notify(mip, MAC_NOTE_SDU_SIZE);
	return (0);
}

/* PRIVATE FUNCTIONS, FOR INTERNAL USE ONLY */

/*
 * Updates the mac_impl structure with the current state of the link
 */
static void
i_mac_log_link_state(mac_impl_t *mip)
{
	/*
	 * If no change, then it is not interesting.
	 */
	if (mip->mi_lastlowlinkstate == mip->mi_lowlinkstate)
		return;

	switch (mip->mi_lowlinkstate) {
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
		if (mip->mi_lastlowlinkstate != LINK_STATE_UNKNOWN)
			cmn_err(CE_NOTE, "!%s link down", mip->mi_name);
		break;

	case LINK_STATE_UNKNOWN:
		/*
		 * This case is normally not interesting.
		 */
		break;
	}
	mip->mi_lastlowlinkstate = mip->mi_lowlinkstate;
}

/*
 * Main routine for the callbacks notifications thread
 */
static void
i_mac_notify_thread(void *arg)
{
	mac_impl_t	*mip = arg;
	callb_cpr_t	cprinfo;
	mac_cb_t	*mcb;
	mac_cb_info_t	*mcbi;
	mac_notify_cb_t	*mncb;

	mcbi = &mip->mi_notify_cb_info;
	CALLB_CPR_INIT(&cprinfo, mcbi->mcbi_lockp, callb_generic_cpr,
	    "i_mac_notify_thread");

	mutex_enter(mcbi->mcbi_lockp);

	for (;;) {
		uint32_t	bits;
		uint32_t	type;

		bits = mip->mi_notify_bits;
		if (bits == 0) {
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			cv_wait(&mcbi->mcbi_cv, mcbi->mcbi_lockp);
			CALLB_CPR_SAFE_END(&cprinfo, mcbi->mcbi_lockp);
			continue;
		}
		mip->mi_notify_bits = 0;
		if ((bits & (1 << MAC_NNOTE)) != 0) {
			/* request to quit */
			ASSERT(mip->mi_state_flags & MIS_DISABLED);
			break;
		}

		mutex_exit(mcbi->mcbi_lockp);

		/*
		 * Log link changes on the actual link, but then do reports on
		 * synthetic state (if part of a bridge).
		 */
		if ((bits & (1 << MAC_NOTE_LOWLINK)) != 0) {
			link_state_t newstate;
			mac_handle_t mh;

			i_mac_log_link_state(mip);
			newstate = mip->mi_lowlinkstate;
			if (mip->mi_bridge_link != NULL) {
				mutex_enter(&mip->mi_bridge_lock);
				if ((mh = mip->mi_bridge_link) != NULL) {
					newstate = mac_bridge_ls_cb(mh,
					    newstate);
				}
				mutex_exit(&mip->mi_bridge_lock);
			}
			if (newstate != mip->mi_linkstate) {
				mip->mi_linkstate = newstate;
				bits |= 1 << MAC_NOTE_LINK;
			}
		}

		/*
		 * Do notification callbacks for each notification type.
		 */
		for (type = 0; type < MAC_NNOTE; type++) {
			if ((bits & (1 << type)) == 0) {
				continue;
			}

			if (mac_notify_cb_list[type] != NULL)
				(*mac_notify_cb_list[type])(mip);

			/*
			 * Walk the list of notifications.
			 */
			MAC_CALLBACK_WALKER_INC(&mip->mi_notify_cb_info);
			for (mcb = mip->mi_notify_cb_list; mcb != NULL;
			    mcb = mcb->mcb_nextp) {
				mncb = (mac_notify_cb_t *)mcb->mcb_objp;
				mncb->mncb_fn(mncb->mncb_arg, type);
			}
			MAC_CALLBACK_WALKER_DCR(&mip->mi_notify_cb_info,
			    &mip->mi_notify_cb_list);
		}

		mutex_enter(mcbi->mcbi_lockp);
	}

	mip->mi_state_flags |= MIS_NOTIFY_DONE;
	cv_broadcast(&mcbi->mcbi_cv);

	/* CALLB_CPR_EXIT drops the lock */
	CALLB_CPR_EXIT(&cprinfo);
	thread_exit();
}

/*
 * Signal the i_mac_notify_thread asking it to quit.
 * Then wait till it is done.
 */
void
i_mac_notify_exit(mac_impl_t *mip)
{
	mac_cb_info_t	*mcbi;

	mcbi = &mip->mi_notify_cb_info;

	mutex_enter(mcbi->mcbi_lockp);
	mip->mi_notify_bits = (1 << MAC_NNOTE);
	cv_broadcast(&mcbi->mcbi_cv);


	while ((mip->mi_notify_thread != NULL) &&
	    !(mip->mi_state_flags & MIS_NOTIFY_DONE)) {
		cv_wait(&mcbi->mcbi_cv, mcbi->mcbi_lockp);
	}

	/* Necessary clean up before doing kmem_cache_free */
	mip->mi_state_flags &= ~MIS_NOTIFY_DONE;
	mip->mi_notify_bits = 0;
	mip->mi_notify_thread = NULL;
	mutex_exit(mcbi->mcbi_lockp);
}

/*
 * Entry point invoked by drivers to dynamically add a ring to an
 * existing group.
 */
int
mac_group_add_ring(mac_group_handle_t gh, int index)
{
	mac_group_t *group = (mac_group_t *)gh;
	mac_impl_t *mip = (mac_impl_t *)group->mrg_mh;
	int ret;

	i_mac_perim_enter(mip);

	/*
	 * Only RX rings can be added or removed by drivers currently.
	 */
	ASSERT(group->mrg_type == MAC_RING_TYPE_RX);

	ret = i_mac_group_add_ring(group, NULL, index);

	i_mac_perim_exit(mip);

	return (ret);
}

/*
 * Entry point invoked by drivers to dynamically remove a ring
 * from an existing group. The specified ring handle must no longer
 * be used by the driver after a call to this function.
 */
void
mac_group_rem_ring(mac_group_handle_t gh, mac_ring_handle_t rh)
{
	mac_group_t *group = (mac_group_t *)gh;
	mac_impl_t *mip = (mac_impl_t *)group->mrg_mh;

	i_mac_perim_enter(mip);

	/*
	 * Only RX rings can be added or removed by drivers currently.
	 */
	ASSERT(group->mrg_type == MAC_RING_TYPE_RX);

	i_mac_group_rem_ring(group, (mac_ring_t *)rh, B_TRUE);

	i_mac_perim_exit(mip);
}
