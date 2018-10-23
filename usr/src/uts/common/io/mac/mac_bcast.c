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
#include <sys/sysmacros.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/list.h>
#include <sys/kmem.h>
#include <sys/stream.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/atomic.h>
#include <sys/stat.h>
#include <sys/modhash.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/sdt.h>
#include <sys/mac.h>
#include <sys/mac_impl.h>
#include <sys/mac_client_impl.h>
#include <sys/mac_client_priv.h>
#include <sys/mac_flow_impl.h>

/*
 * Broadcast and multicast traffic must be distributed to the MAC clients
 * that are defined on top of the same MAC. The set of
 * destinations to which a multicast packet must be sent is a subset
 * of all MAC clients defined on top of the MAC. A MAC client can be member
 * of more than one such subset.
 *
 * To accomodate these requirements, we introduce broadcast groups.
 * A broadcast group is associated with a broadcast or multicast
 * address. The members of a broadcast group consist of the MAC clients
 * that should received copies of packets sent to the address
 * associated with the group, and are defined on top of the
 * same MAC.
 *
 * The broadcast groups defined on top of a MAC are chained,
 * hanging off the mac_impl_t. The broadcast group id's are
 * unique globally (tracked by mac_bcast_id).
 */

/*
 * The same MAC client may be added for different <addr,vid> tuple,
 * we maintain a ref count for the number of times it has been added
 * to account for deleting the MAC client from the group.
 */
typedef struct mac_bcast_grp_mcip_s {
	mac_client_impl_t	*mgb_client;
	int			mgb_client_ref;
} mac_bcast_grp_mcip_t;

typedef struct mac_bcast_grp_s {			/* Protected by */
	struct mac_bcast_grp_s	*mbg_next;		/* SL */
	void			*mbg_addr;		/* SL */
	uint16_t		mbg_vid;		/* SL */
	mac_impl_t		*mbg_mac_impl;		/* WO */
	mac_addrtype_t		mbg_addrtype;		/* WO */
	flow_entry_t		*mbg_flow_ent;		/* WO */
	mac_bcast_grp_mcip_t	*mbg_clients;		/* mi_rw_lock */
	uint_t			mbg_nclients;		/* mi_rw_lock */
	uint_t			mbg_nclients_alloc;	/* SL */
	uint64_t		mbg_clients_gen;	/* mi_rw_lock */
	uint32_t		mbg_id;			/* atomic */
} mac_bcast_grp_t;

static kmem_cache_t *mac_bcast_grp_cache;
static uint32_t mac_bcast_id = 0;

void
mac_bcast_init(void)
{
	mac_bcast_grp_cache = kmem_cache_create("mac_bcast_grp_cache",
	    sizeof (mac_bcast_grp_t), 0, NULL, NULL, NULL, NULL, NULL, 0);
}

void
mac_bcast_fini(void)
{
	kmem_cache_destroy(mac_bcast_grp_cache);
}

mac_impl_t *
mac_bcast_grp_mip(void *grp)
{
	mac_bcast_grp_t *bcast_grp = grp;

	return (bcast_grp->mbg_mac_impl);
}

/*
 * Free the specific broadcast group. Invoked when the last reference
 * to the group is released.
 */
void
mac_bcast_grp_free(void *bcast_grp)
{
	mac_bcast_grp_t	*grp = bcast_grp;
	mac_impl_t *mip = grp->mbg_mac_impl;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));

	ASSERT(grp->mbg_addr != NULL);
	kmem_free(grp->mbg_addr, mip->mi_type->mt_addr_length);
	kmem_free(grp->mbg_clients,
	    grp->mbg_nclients_alloc * sizeof (mac_bcast_grp_mcip_t));
	mip->mi_bcast_ngrps--;
	kmem_cache_free(mac_bcast_grp_cache, grp);
}

/*
 * arg1: broadcast group
 * arg2: sender MAC client if it is being sent by a MAC client,
 * NULL if it was received from the wire.
 */
void
mac_bcast_send(void *arg1, void *arg2, mblk_t *mp_chain, boolean_t is_loopback)
{
	mac_bcast_grp_t *grp = arg1;
	mac_client_impl_t *src_mcip = arg2, *dst_mcip;
	mac_impl_t *mip = grp->mbg_mac_impl;
	uint64_t gen;
	uint_t i;
	mblk_t *mp_chain1;
	flow_entry_t	*flent;
	int err;

	rw_enter(&mip->mi_rw_lock, RW_READER);

	/*
	 * Pass a copy of the mp chain to every MAC client except the sender
	 * MAC client, if the packet was not received from the underlying NIC.
	 *
	 * The broadcast group lock should not be held across calls to
	 * the flow's callback function, since the same group could
	 * potentially be accessed from the same context. When the lock
	 * is reacquired, changes to the broadcast group while the lock
	 * was released are caught using a generation counter incremented
	 * each time the list of MAC clients associated with the broadcast
	 * group is changed.
	 */
	for (i = 0; i < grp->mbg_nclients_alloc; i++) {
		dst_mcip = grp->mbg_clients[i].mgb_client;
		if (dst_mcip == NULL)
			continue;
		flent = dst_mcip->mci_flent;
		if (flent == NULL || dst_mcip == src_mcip) {
			/*
			 * Don't send a copy of the packet back to
			 * its sender.
			 */
			continue;
		}

		/*
		 * It is important to hold a reference on the
		 * flow_ent here.
		 */
		if ((mp_chain1 = mac_copymsgchain_cksum(mp_chain)) == NULL)
			break;
		/*
		 * Fix the checksum for packets originating
		 * from the local machine.
		 */
		if ((src_mcip != NULL) &&
		    (mp_chain1 = mac_fix_cksum(mp_chain1)) == NULL)
			break;

		FLOW_TRY_REFHOLD(flent, err);
		if (err != 0) {
			freemsgchain(mp_chain1);
			continue;
		}

		gen = grp->mbg_clients_gen;

		rw_exit(&mip->mi_rw_lock);

		DTRACE_PROBE4(mac__bcast__send__to, mac_client_impl_t *,
		    src_mcip, flow_fn_t, dst_mcip->mci_flent->fe_cb_fn,
		    void *, dst_mcip->mci_flent->fe_cb_arg1,
		    void *, dst_mcip->mci_flent->fe_cb_arg2);

		(dst_mcip->mci_flent->fe_cb_fn)(dst_mcip->mci_flent->fe_cb_arg1,
		    dst_mcip->mci_flent->fe_cb_arg2, mp_chain1, is_loopback);
		FLOW_REFRELE(flent);

		rw_enter(&mip->mi_rw_lock, RW_READER);

		/* update stats */
		if (grp->mbg_addrtype == MAC_ADDRTYPE_MULTICAST) {
			MCIP_STAT_UPDATE(dst_mcip, multircv, 1);
			MCIP_STAT_UPDATE(dst_mcip, multircvbytes,
			    msgdsize(mp_chain));
		} else {
			MCIP_STAT_UPDATE(dst_mcip, brdcstrcv, 1);
			MCIP_STAT_UPDATE(dst_mcip, brdcstrcvbytes,
			    msgdsize(mp_chain));
		}

		if (grp->mbg_clients_gen != gen) {
			/*
			 * The list of MAC clients associated with the group
			 * was changed while the lock was released.
			 * Give up on the current packet.
			 */
			rw_exit(&mip->mi_rw_lock);
			freemsgchain(mp_chain);
			return;
		}
	}
	rw_exit(&mip->mi_rw_lock);

	if (src_mcip != NULL) {
		/*
		 * The packet was sent from one of the MAC clients,
		 * so we need to send a copy of the packet to the
		 * underlying NIC so that it can be sent on the wire.
		 */
		MCIP_STAT_UPDATE(src_mcip, multixmt, 1);
		MCIP_STAT_UPDATE(src_mcip, multixmtbytes, msgdsize(mp_chain));
		MCIP_STAT_UPDATE(src_mcip, brdcstxmt, 1);
		MCIP_STAT_UPDATE(src_mcip, brdcstxmtbytes, msgdsize(mp_chain));

		MAC_TX(mip, mip->mi_default_tx_ring, mp_chain, src_mcip);
		if (mp_chain != NULL)
			freemsgchain(mp_chain);
	} else {
		freemsgchain(mp_chain);
	}
}

/*
 * Add the specified MAC client to the group corresponding to the specified
 * broadcast or multicast address.
 * Return 0 on success, or an errno value on failure.
 */
int
mac_bcast_add(mac_client_impl_t *mcip, const uint8_t *addr, uint16_t vid,
    mac_addrtype_t addrtype)
{
	mac_impl_t 		*mip = mcip->mci_mip;
	mac_bcast_grp_t		*grp = NULL, **last_grp;
	size_t			addr_len = mip->mi_type->mt_addr_length;
	int			rc = 0;
	int			i, index = -1;
	mac_mcast_addrs_t	**prev_mi_addr = NULL;
	mac_mcast_addrs_t	**prev_mci_addr = NULL;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));

	ASSERT(addrtype == MAC_ADDRTYPE_MULTICAST ||
	    addrtype == MAC_ADDRTYPE_BROADCAST);

	/*
	 * Add the MAC client to the list of MAC clients associated
	 * with the group.
	 */
	if (addrtype == MAC_ADDRTYPE_MULTICAST) {
		mac_mcast_addrs_t	*maddr;

		/*
		 * In case of a driver (say aggr), we need this information
		 * on a per MAC instance basis.
		 */
		prev_mi_addr = &mip->mi_mcast_addrs;
		for (maddr = *prev_mi_addr; maddr != NULL;
		    prev_mi_addr = &maddr->mma_next, maddr = maddr->mma_next) {
			if (bcmp(maddr->mma_addr, addr, addr_len) == 0)
				break;
		}
		if (maddr == NULL) {
			/*
			 * For multicast addresses, have the underlying MAC
			 * join the corresponding multicast group.
			 */
			rc = mip->mi_multicst(mip->mi_driver, B_TRUE, addr);
			if (rc != 0)
				return (rc);
			maddr = kmem_zalloc(sizeof (mac_mcast_addrs_t),
			    KM_SLEEP);
			bcopy(addr, maddr->mma_addr, addr_len);
			*prev_mi_addr = maddr;
		} else {
			prev_mi_addr = NULL;
		}
		maddr->mma_ref++;

		/*
		 * We maintain a separate list for each MAC client. Get
		 * the entry or add, if it is not present.
		 */
		prev_mci_addr = &mcip->mci_mcast_addrs;
		for (maddr = *prev_mci_addr; maddr != NULL;
		    prev_mci_addr = &maddr->mma_next, maddr = maddr->mma_next) {
			if (bcmp(maddr->mma_addr, addr, addr_len) == 0)
				break;
		}
		if (maddr == NULL) {
			maddr = kmem_zalloc(sizeof (mac_mcast_addrs_t),
			    KM_SLEEP);
			bcopy(addr, maddr->mma_addr, addr_len);
			*prev_mci_addr = maddr;
		} else {
			prev_mci_addr = NULL;
		}
		maddr->mma_ref++;
	}

	/* The list is protected by the perimeter */
	last_grp = &mip->mi_bcast_grp;
	for (grp = *last_grp; grp != NULL;
	    last_grp = &grp->mbg_next, grp = grp->mbg_next) {
		if (bcmp(grp->mbg_addr, addr, addr_len) == 0 &&
		    grp->mbg_vid == vid)
			break;
	}

	if (grp == NULL) {
		/*
		 * The group does not yet exist, create it.
		 */
		flow_desc_t flow_desc;
		char flow_name[MAXFLOWNAMELEN];

		grp = kmem_cache_alloc(mac_bcast_grp_cache, KM_SLEEP);
		bzero(grp, sizeof (mac_bcast_grp_t));
		grp->mbg_next = NULL;
		grp->mbg_mac_impl = mip;

		DTRACE_PROBE1(mac__bcast__add__new__group, mac_bcast_grp_t *,
		    grp);

		grp->mbg_addr = kmem_zalloc(addr_len, KM_SLEEP);
		bcopy(addr, grp->mbg_addr, addr_len);
		grp->mbg_addrtype = addrtype;
		grp->mbg_vid = vid;

		/*
		 * Add a new flow to the underlying MAC.
		 */
		bzero(&flow_desc, sizeof (flow_desc));
		bcopy(addr, &flow_desc.fd_dst_mac, addr_len);
		flow_desc.fd_mac_len = (uint32_t)addr_len;

		flow_desc.fd_mask = FLOW_LINK_DST;
		if (vid != 0) {
			flow_desc.fd_vid = vid;
			flow_desc.fd_mask |= FLOW_LINK_VID;
		}

		grp->mbg_id = atomic_inc_32_nv(&mac_bcast_id);
		(void) sprintf(flow_name,
		    "mac/%s/mcast%d", mip->mi_name, grp->mbg_id);

		rc = mac_flow_create(&flow_desc, NULL, flow_name,
		    grp, FLOW_MCAST, &grp->mbg_flow_ent);
		if (rc != 0) {
			kmem_free(grp->mbg_addr, addr_len);
			kmem_cache_free(mac_bcast_grp_cache, grp);
			goto fail;
		}
		grp->mbg_flow_ent->fe_mbg = grp;
		mip->mi_bcast_ngrps++;

		/*
		 * Initial creation reference on the flow. This is released
		 * in the corresponding delete action i_mac_bcast_delete()
		 */
		FLOW_REFHOLD(grp->mbg_flow_ent);

		/*
		 * When the multicast and broadcast packet is received
		 * by the underlying NIC, mac_rx_classify() will invoke
		 * mac_bcast_send() with arg2=NULL, which will cause
		 * mac_bcast_send() to send a copy of the packet(s)
		 * to every MAC client opened on top of the underlying MAC.
		 *
		 * When the mac_bcast_send() function is invoked from
		 * the transmit path of a MAC client, it will specify the
		 * transmitting MAC client as the arg2 value, which will
		 * allow mac_bcast_send() to skip that MAC client and not
		 * send it a copy of the packet.
		 *
		 * We program the classifier to dispatch matching broadcast
		 * packets to mac_bcast_send().
		 */

		grp->mbg_flow_ent->fe_cb_fn = mac_bcast_send;
		grp->mbg_flow_ent->fe_cb_arg1 = grp;
		grp->mbg_flow_ent->fe_cb_arg2 = NULL;

		rc = mac_flow_add(mip->mi_flow_tab, grp->mbg_flow_ent);
		if (rc != 0) {
			FLOW_FINAL_REFRELE(grp->mbg_flow_ent);
			goto fail;
		}

		*last_grp = grp;
	}

	ASSERT(grp->mbg_addrtype == addrtype);

	/*
	 * Add the MAC client to the list of MAC clients associated
	 * with the group.
	 */
	rw_enter(&mip->mi_rw_lock, RW_WRITER);
	for (i = 0; i < grp->mbg_nclients_alloc; i++) {
		/*
		 * The MAC client was already added, say when we have
		 * different unicast addresses with the same vid.
		 * Just increment the ref and we are done.
		 */
		if (grp->mbg_clients[i].mgb_client == mcip) {
			grp->mbg_clients[i].mgb_client_ref++;
			rw_exit(&mip->mi_rw_lock);
			return (0);
		} else if (grp->mbg_clients[i].mgb_client == NULL &&
		    index == -1) {
			index = i;
		}
	}
	if (grp->mbg_nclients_alloc == grp->mbg_nclients) {
		mac_bcast_grp_mcip_t	*new_clients;
		uint_t			new_size = grp->mbg_nclients+1;

		new_clients = kmem_zalloc(new_size *
		    sizeof (mac_bcast_grp_mcip_t), KM_SLEEP);

		if (grp->mbg_nclients > 0) {
			ASSERT(grp->mbg_clients != NULL);
			bcopy(grp->mbg_clients, new_clients, grp->mbg_nclients *
			    sizeof (mac_bcast_grp_mcip_t));
			kmem_free(grp->mbg_clients, grp->mbg_nclients *
			    sizeof (mac_bcast_grp_mcip_t));
		}

		grp->mbg_clients = new_clients;
		grp->mbg_nclients_alloc = new_size;
		index = new_size - 1;
	}

	ASSERT(index != -1);
	grp->mbg_clients[index].mgb_client = mcip;
	grp->mbg_clients[index].mgb_client_ref = 1;
	grp->mbg_nclients++;
	/*
	 * Since we're adding to the list of MAC clients using that group,
	 * kick the generation count, which will allow mac_bcast_send()
	 * to detect that condition after re-acquiring the lock.
	 */
	grp->mbg_clients_gen++;
	rw_exit(&mip->mi_rw_lock);
	return (0);

fail:
	if (prev_mi_addr != NULL) {
		kmem_free(*prev_mi_addr, sizeof (mac_mcast_addrs_t));
		*prev_mi_addr = NULL;
		(void) mip->mi_multicst(mip->mi_driver, B_FALSE, addr);
	}
	if (prev_mci_addr != NULL) {
		kmem_free(*prev_mci_addr, sizeof (mac_mcast_addrs_t));
		*prev_mci_addr = NULL;
	}
	return (rc);
}

/*
 * Remove the specified MAC client from the group corresponding to
 * the specific broadcast or multicast address.
 *
 * Note: mac_bcast_delete() calls  mac_remove_flow() which
 * will call cv_wait for fe_refcnt to drop to 0. So this function
 * should not be called from interrupt or STREAMS context.
 */
void
mac_bcast_delete(mac_client_impl_t *mcip, const uint8_t *addr, uint16_t vid)
{
	mac_impl_t *mip = mcip->mci_mip;
	mac_bcast_grp_t *grp = NULL, **prev;
	size_t addr_len = mip->mi_type->mt_addr_length;
	flow_entry_t *flent;
	uint_t i;
	mac_mcast_addrs_t	*maddr = NULL;
	mac_mcast_addrs_t	**mprev;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));

	/* find the broadcast group. The list is protected by the perimeter */
	prev = &mip->mi_bcast_grp;
	for (grp = mip->mi_bcast_grp; grp != NULL; prev = &grp->mbg_next,
	    grp = grp->mbg_next) {
		if (bcmp(grp->mbg_addr, addr, addr_len) == 0 &&
		    grp->mbg_vid == vid)
			break;
	}
	ASSERT(grp != NULL);

	/*
	 * Remove the MAC client from the list of MAC clients associated
	 * with that broadcast group.
	 *
	 * We mark the mbg_clients[] location corresponding to the removed MAC
	 * client NULL and reuse that location when we add a new MAC client.
	 */

	rw_enter(&mip->mi_rw_lock, RW_WRITER);

	for (i = 0; i < grp->mbg_nclients_alloc; i++) {
		if (grp->mbg_clients[i].mgb_client == mcip)
			break;
	}

	ASSERT(i < grp->mbg_nclients_alloc);
	/*
	 * If there are more references to this MAC client, then we let
	 * it remain till it goes to 0.
	 */
	if (--grp->mbg_clients[i].mgb_client_ref > 0)
		goto update_maddr;

	grp->mbg_clients[i].mgb_client = NULL;
	grp->mbg_clients[i].mgb_client_ref = 0;

	/*
	 * Since we're removing from the list of MAC clients using that group,
	 * kick the generation count, which will allow mac_bcast_send()
	 * to detect that condition.
	 */
	grp->mbg_clients_gen++;

	if (--grp->mbg_nclients == 0) {
		/*
		 * The last MAC client of the group was just removed.
		 * Unlink the current group from the list of groups
		 * defined on top of the underlying NIC. The group
		 * structure will stay around until the last reference
		 * is dropped.
		 */
		*prev = grp->mbg_next;
	}
update_maddr:
	rw_exit(&mip->mi_rw_lock);

	if (grp->mbg_addrtype == MAC_ADDRTYPE_MULTICAST) {
		mprev = &mcip->mci_mcast_addrs;
		for (maddr = mcip->mci_mcast_addrs; maddr != NULL;
		    mprev = &maddr->mma_next, maddr = maddr->mma_next) {
			if (bcmp(grp->mbg_addr, maddr->mma_addr,
			    mip->mi_type->mt_addr_length) == 0)
				break;
		}
		ASSERT(maddr != NULL);
		if (--maddr->mma_ref == 0) {
			*mprev = maddr->mma_next;
			maddr->mma_next = NULL;
			kmem_free(maddr, sizeof (mac_mcast_addrs_t));
		}

		mprev = &mip->mi_mcast_addrs;
		for (maddr = mip->mi_mcast_addrs; maddr != NULL;
		    mprev = &maddr->mma_next, maddr = maddr->mma_next) {
			if (bcmp(grp->mbg_addr, maddr->mma_addr,
			    mip->mi_type->mt_addr_length) == 0)
				break;
		}
		ASSERT(maddr != NULL);
		if (--maddr->mma_ref == 0) {
			(void) mip->mi_multicst(mip->mi_driver, B_FALSE, addr);
			*mprev = maddr->mma_next;
			maddr->mma_next = NULL;
			kmem_free(maddr, sizeof (mac_mcast_addrs_t));
		}
	}

	/*
	 * If the group itself is being removed, remove the
	 * corresponding flow from the underlying NIC.
	 */
	flent = grp->mbg_flow_ent;
	if (grp->mbg_nclients == 0) {
		mac_flow_remove(mip->mi_flow_tab, flent, B_FALSE);
		mac_flow_wait(flent, FLOW_DRIVER_UPCALL);
		FLOW_FINAL_REFRELE(flent);
	}
}

/*
 * This will be called by a driver, such as aggr, when a port is added/removed
 * to add/remove the port to/from all the multcast addresses for that aggr.
 */
void
mac_bcast_refresh(mac_impl_t *mip, mac_multicst_t refresh_fn, void *arg,
    boolean_t add)
{
	mac_mcast_addrs_t *grp, *next;

	ASSERT(refresh_fn != NULL);

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));

	/*
	 * Walk the multicast address list and call the refresh function for
	 * each address.
	 */

	for (grp = mip->mi_mcast_addrs; grp != NULL; grp = next) {
		/*
		 * Save the next pointer just in case the refresh
		 * function's action causes the group entry to be
		 * freed.
		 * We won't be adding to this list as part of the
		 * refresh.
		 */
		next = grp->mma_next;
		refresh_fn(arg, add, grp->mma_addr);
	}
}

/*
 * Walk the MAC client's multicast address list and add/remove the addr/vid
 * ('arg' is 'flent') to all the addresses.
 */
void
mac_client_bcast_refresh(mac_client_impl_t *mcip, mac_multicst_t refresh_fn,
    void *arg, boolean_t add)
{
	mac_mcast_addrs_t *grp, *next;
	mac_impl_t		*mip = mcip->mci_mip;

	ASSERT(refresh_fn != NULL);

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));
	/*
	 * Walk the multicast address list and call the refresh function for
	 * each address.
	 * Broadcast addresses are not added or removed through the multicast
	 * entry points, so don't include them as part of the refresh.
	 */
	for (grp = mcip->mci_mcast_addrs; grp != NULL; grp = next) {
		/*
		 * Save the next pointer just in case the refresh
		 * function's action causes the group entry to be
		 * freed.
		 * We won't be adding to this list as part of the
		 * refresh.
		 */
		next = grp->mma_next;
		refresh_fn(arg, add, grp->mma_addr);
	}
}
