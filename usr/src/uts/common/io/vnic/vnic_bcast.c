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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include <sys/mac.h>
#include <sys/vnic.h>
#include <sys/vnic_impl.h>

/*
 * Broadcast and multicast traffic must be distributed to the VNICs
 * that are defined on top of the same underlying NIC. The set of
 * destinations to which a multicast packet must be sent is a subset
 * of all VNICs defined on top of the same NIC. A VNIC can be member
 * of more than one such subset.
 *
 * To accomodate these requirements, we introduce broadcast groups.
 * A broadcast group is associated with a broadcast or multicast
 * address. The members of a broadcast group consist of the VNICs
 * that should received copies of packets sent to the address
 * associated with the group, and are defined on top of the
 * same underlying NIC. The underlying NIC is always implicetely
 * part of the group.
 *
 * The broadcast groups defined on top of a underlying NIC are chained,
 * hanging off vnic_mac_t structures.
 */

typedef struct vnic_bcast_grp_s {
	struct vnic_bcast_grp_s	*vbg_next;
	uint_t		vbg_refs;
	void		*vbg_addr;
	vnic_mac_t	*vbg_vnic_mac;
	mac_addrtype_t	vbg_addrtype;
	vnic_flow_t	*vbg_flow_ent;
	vnic_t		**vbg_vnics;
	uint_t		vbg_nvnics;
	uint_t		vbg_nvnics_alloc;
	uint64_t	vbg_vnics_gen;
} vnic_bcast_grp_t;

#define	VNIC_BCAST_GRP_REFHOLD(grp) {		\
	atomic_add_32(&(grp)->vbg_refs, 1);	\
	ASSERT((grp)->vbg_refs != 0);		\
}

#define	VNIC_BCAST_GRP_REFRELE(grp) {		\
	ASSERT((grp)->vbg_refs != 0);		\
	membar_exit();				\
	if (atomic_add_32_nv(&(grp)->vbg_refs, -1) == 0)	\
		vnic_bcast_grp_free(grp);	\
}

static kmem_cache_t *vnic_bcast_grp_cache;

void
vnic_bcast_init(void)
{
	vnic_bcast_grp_cache = kmem_cache_create("vnic_bcast_grp_cache",
	    sizeof (vnic_bcast_grp_t), 0, NULL, NULL, NULL, NULL, NULL, 0);
}

void
vnic_bcast_fini(void)
{
	kmem_cache_destroy(vnic_bcast_grp_cache);
}

/*
 * Free the specific broadcast group. Invoked when the last reference
 * to the group is released.
 */
static void
vnic_bcast_grp_free(vnic_bcast_grp_t *grp)
{
	vnic_mac_t *vnic_mac = grp->vbg_vnic_mac;

	if (grp->vbg_addrtype == MAC_ADDRTYPE_MULTICAST) {
		/*
		 * The address is a multicast address, have the
		 * underlying NIC leave the multicast group.
		 */
		(void) mac_multicst_remove(vnic_mac->va_mh, grp->vbg_addr);
	}

	ASSERT(grp->vbg_addr != NULL);
	kmem_free(grp->vbg_addr, grp->vbg_vnic_mac->va_addr_len);

	ASSERT(grp->vbg_vnics != NULL);
	kmem_free(grp->vbg_vnics, grp->vbg_nvnics_alloc * sizeof (vnic_t *));

	kmem_cache_free(vnic_bcast_grp_cache, grp);
}

void
vnic_bcast_send(void *arg1, void *arg2, mblk_t *mp_chain)
{
	vnic_bcast_grp_t *grp = arg1;
	vnic_t *sender_vnic = arg2, *vnic;
	const vnic_flow_fn_info_t *fn_info;
	krwlock_t *grp_lock = &grp->vbg_vnic_mac->va_bcast_grp_lock;
	uint64_t gen;
	uint_t i;
	mblk_t *mp_chain1;
	vnic_mac_t *vnic_mac = grp->vbg_vnics[0]->vn_vnic_mac;

	VNIC_BCAST_GRP_REFHOLD(grp);
	rw_enter(grp_lock, RW_READER);

	/*
	 * Pass a copy of the mp chain to every VNIC except the sender
	 * VNIC, if the packet was not received from the underlying NIC.
	 *
	 * The broadcast group lock across calls to the flow's callback
	 * function, since the same group could potentially be accessed
	 * from the same context. When the lock is reacquired, changes
	 * to the broadcast group while the lock was released
	 * are caught using a generation counter incremented each time
	 * the list of VNICs associated with the broadcast group
	 * is changed.
	 */
	for (i = 0; i < grp->vbg_nvnics; i++) {
		vnic = grp->vbg_vnics[i];
		if (vnic == sender_vnic)
			continue;

		/*
		 * If this consumer is in promiscuous mode then it
		 * will have already seen a copy of the packet.
		 */
		if (vnic->vn_promisc)
			continue;
		/*
		 * It is important to hold a reference on the
		 * flow_ent here. vnic_dev_delete() may be waiting
		 * to delete the vnic after removing it from grp.
		 */
		if ((mp_chain1 = vnic_copymsgchain_cksum(mp_chain)) == NULL)
			break;
		/*
		 * Fix the checksum for packets originating
		 * from the local machine.
		 */
		if ((sender_vnic != NULL) &&
		    ((mp_chain1 = vnic_fix_cksum(mp_chain1)) == NULL))
			break;
		VNIC_FLOW_REFHOLD(vnic->vn_flow_ent);
		fn_info = vnic_classifier_get_fn_info(vnic->vn_flow_ent);
		gen = grp->vbg_vnics_gen;
		rw_exit(grp_lock);
		(fn_info->ff_fn)(fn_info->ff_arg1, fn_info->ff_arg2, mp_chain1);
		VNIC_FLOW_REFRELE(vnic->vn_flow_ent);
		rw_enter(grp_lock, RW_READER);

		/* update stats */
		if (grp->vbg_addrtype == MAC_ADDRTYPE_MULTICAST)
			vnic->vn_stat_multircv++;
		else
			vnic->vn_stat_brdcstrcv++;

		if (grp->vbg_vnics_gen != gen) {
			/*
			 * The list of VNICs associated with the group
			 * was changed while the lock was released.
			 * Give up on the current packet.
			 */
			freemsgchain(mp_chain);
			goto bail;
		}
	}

	if (sender_vnic != NULL) {
		/*
		 * The packet was sent from one of the VNICs
		 * (vnic_active_tx()), or from the active MAC
		 * (vnic_active_tx()). In both cases, we need to send
		 * a copy of the packet to the underlying NIC so that
		 * it can be sent on the wire.
		 */
		const mac_txinfo_t *mtp = vnic_mac->va_txinfo;
		mblk_t *rest;

		if ((mp_chain1 = vnic_copymsgchain_cksum(mp_chain)) != NULL) {
			rw_exit(grp_lock);
			rest = mtp->mt_fn(mtp->mt_arg, mp_chain1);
			rw_enter(grp_lock, RW_READER);
			if (rest != NULL)
				freemsgchain(rest);
		}
	}

	if ((sender_vnic != (vnic_t *)-1) && (sender_vnic != NULL)) {
		/*
		 * Called while sending a packet from one of the VNICs.
		 * Make sure the active interface gets its copy.
		 */
		mp_chain1 = (sender_vnic != NULL) ? vnic_fix_cksum(mp_chain) :
		    mp_chain;
		if (mp_chain1 != NULL) {
			rw_exit(grp_lock);
			mac_active_rx(vnic_mac->va_mh, NULL, mp_chain1);
			rw_enter(grp_lock, RW_READER);
		}
	} else {
		freemsgchain(mp_chain);
	}
bail:
	rw_exit(grp_lock);
	VNIC_BCAST_GRP_REFRELE(grp);
}

/*
 * Add the specified VNIC to the group corresponding to the specified
 * broadcast or multicast address.
 * Return 0 on success, or an errno value on failure.
 */
int
vnic_bcast_add(vnic_t *vnic, const uint8_t *addr, mac_addrtype_t addrtype)
{
	vnic_mac_t *vnic_mac = vnic->vn_vnic_mac;
	vnic_bcast_grp_t *grp = NULL, **last_grp;
	int rc = 0;

	ASSERT(addrtype == MAC_ADDRTYPE_MULTICAST ||
	    addrtype == MAC_ADDRTYPE_BROADCAST);

	rw_enter(&vnic_mac->va_bcast_grp_lock, RW_WRITER);

	/*
	 * Does a group with the specified broadcast address already
	 * exist for the underlying NIC?
	 */
	last_grp = &vnic_mac->va_bcast_grp;
	for (grp = *last_grp; grp != NULL;
	    last_grp = &grp->vbg_next, grp = grp->vbg_next) {
		if (bcmp(grp->vbg_addr, addr, vnic_mac->va_addr_len) == 0)
			break;
	}

	if (grp == NULL) {
		/*
		 * The group does not yet exist, create it.
		 */
		grp = kmem_cache_alloc(vnic_bcast_grp_cache, KM_SLEEP);
		bzero(grp, sizeof (vnic_bcast_grp_t));
		grp->vbg_next = NULL;
		ASSERT(grp->vbg_refs == 0);
		grp->vbg_vnic_mac = vnic_mac;

		grp->vbg_addr = kmem_zalloc(vnic_mac->va_addr_len, KM_SLEEP);
		bcopy(addr, grp->vbg_addr, vnic_mac->va_addr_len);
		grp->vbg_addrtype = addrtype;

		/*
		 * Add a new flow for the broadcast address.
		 */
		grp->vbg_flow_ent = vnic_classifier_flow_create(
		    vnic_mac->va_addr_len, (uchar_t *)addr, grp, B_FALSE,
		    KM_NOSLEEP);
		if (grp->vbg_flow_ent == NULL) {
			rc = ENOMEM;
			goto bail;
		}

		/*
		 * When the multicast and broadcast packet is received
		 * by the underlying NIC, mac_rx_classify() will invoke
		 * vnic_bcast_send() with arg2=NULL, which will cause
		 * vnic_bcast_send() to send a copy of the packet(s)
		 * to every VNIC defined on top of the underlying MAC.
		 *
		 * When the vnic_bcast_send() function is invoked from
		 * the VNIC transmit path, it will specify the transmitting
		 * VNIC as the arg2 value, which will allow vnic_bcast_send()
		 * to skip that VNIC and not send it a copy of the packet.
		 *
		 * We program the classifier to dispatch matching broadcast
		 * packets to vnic_bcast_send().
		 * We need a ring allocated for this bcast flow, so that
		 * later snooping of the underlying MAC uses the same scheme
		 * of intercepting the ring's receiver to mac_rx_promisc().
		 * For the economy of hardware resources, we command the MAC
		 * classifier to use a soft ring for these broadcast and
		 * multicast flows.
		 */
		vnic_classifier_flow_add(vnic_mac, grp->vbg_flow_ent,
		    vnic_bcast_send, grp, NULL);

		/*
		 * For multicast addresses, have the underlying MAC
		 * join the corresponsing multicast group.
		 */
		if ((addrtype == MAC_ADDRTYPE_MULTICAST) &&
		    ((rc = mac_multicst_add(vnic_mac->va_mh, addr)) != 0)) {
			vnic_classifier_flow_remove(vnic->vn_vnic_mac,
			    grp->vbg_flow_ent);
			vnic_classifier_flow_destroy(grp->vbg_flow_ent);
			goto bail;
		}

		*last_grp = grp;
	}

	/*
	 * Add the VNIC to the list of VNICs associated with the group.
	 */
	if (grp->vbg_nvnics_alloc == grp->vbg_nvnics) {
		vnic_t **new_vnics;
		uint_t new_size = grp->vbg_nvnics+1;

		new_vnics = kmem_zalloc(new_size * sizeof (vnic_t *),
		    KM_SLEEP);

		if (grp->vbg_nvnics) {
			ASSERT(grp->vbg_vnics != NULL);
			bcopy(grp->vbg_vnics, new_vnics, grp->vbg_nvnics *
			    sizeof (vnic_t *));
			kmem_free(grp->vbg_vnics, grp->vbg_nvnics *
			    sizeof (vnic_t *));
		}

		grp->vbg_vnics = new_vnics;
		grp->vbg_nvnics_alloc = new_size;
	}

	grp->vbg_vnics[grp->vbg_nvnics++] = vnic;

	/*
	 * Since we're adding to the list of VNICs using that group,
	 * kick the generation count, which will allow vnic_bcast_send()
	 * to detect that condition.
	 */
	grp->vbg_vnics_gen++;

	VNIC_BCAST_GRP_REFHOLD(grp);

bail:
	if (rc != 0 && grp != NULL) {
		kmem_free(grp->vbg_addr, vnic_mac->va_addr_len);
		kmem_cache_free(vnic_bcast_grp_cache, grp);
	}

	rw_exit(&vnic->vn_vnic_mac->va_bcast_grp_lock);
	return (rc);
}

/*
 * Remove the specified VNIC from the group corresponding to
 * the specific broadcast or multicast address.
 *
 * Note: vnic_bcast_delete() calls  net_remove_flow() which
 * will call cv_wait for fe_refcnt to drop to 0. So this function
 * should not be called from interrupt or STREAMS context. The only
 * callers are vnic_dev_delete() and vnic_m_multicst() (both of
 * which are called from taskq thread context).
 */
void
vnic_bcast_delete(vnic_t *vnic, const uint8_t *addr)
{
	vnic_mac_t *vnic_mac = vnic->vn_vnic_mac;
	vnic_bcast_grp_t *grp, **prev;
	uint_t i;
	boolean_t removing_grp = B_FALSE;

	rw_enter(&vnic_mac->va_bcast_grp_lock, RW_WRITER);

	/* find the broadcast group */
	prev = &vnic_mac->va_bcast_grp;
	for (grp = vnic_mac->va_bcast_grp; grp != NULL; prev = &grp->vbg_next,
	    grp = grp->vbg_next) {
		if (bcmp(grp->vbg_addr, addr, vnic_mac->va_addr_len) == 0)
			break;
	}
	ASSERT(grp != NULL);

	/*
	 * Remove the VNIC from the list of VNICs associated with that
	 * broadcast group.
	 *
	 * We keep the vbg_vnics[] always compact by repacing
	 * the removed vnic with the last non NULL element in that array.
	 */

	for (i = 0; i < grp->vbg_nvnics; i++) {
		if (grp->vbg_vnics[i] == vnic)
			break;
	}

	ASSERT(i < grp->vbg_nvnics);

	if (i == (grp->vbg_nvnics-1)) {
		grp->vbg_vnics[i] = NULL;
	} else {
		grp->vbg_vnics[i] = grp->vbg_vnics[grp->vbg_nvnics-1];
		grp->vbg_vnics[grp->vbg_nvnics-1] = NULL;
	}

	/*
	 * Since we're removing from the list of VNICs using that group,
	 * kick the generation count, which will allow vnic_bcast_send()
	 * to detect that condition.
	 */
	grp->vbg_vnics_gen++;

	if (--grp->vbg_nvnics == 0) {
		/*
		 * Unlink the current group from the list of groups
		 * defined on top of the underlying NIC. The group
		 * structure will stay around until the last reference
		 * is dropped.
		 */
		*prev = grp->vbg_next;
		removing_grp = B_TRUE;
	}

	rw_exit(&vnic->vn_vnic_mac->va_bcast_grp_lock);

	/*
	 * If the group itself is being removed, remove the
	 * corresponding flow from the underlying NIC.
	 */
	if (removing_grp) {
		vnic_classifier_flow_remove(vnic->vn_vnic_mac,
		    grp->vbg_flow_ent);
		vnic_classifier_flow_destroy(grp->vbg_flow_ent);
	}

	VNIC_BCAST_GRP_REFRELE(grp);
}
