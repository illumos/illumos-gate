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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/list.h>
#include <sys/ksynch.h>
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
#include <sys/dlpi.h>
#include <sys/mac.h>
#include <sys/mac_ether.h>
#include <sys/dls.h>
#include <sys/pattr.h>
#include <sys/vnic.h>
#include <sys/vnic_impl.h>
#include <sys/gld.h>
#include <inet/ip.h>
#include <inet/ip_impl.h>

static int vnic_m_start(void *);
static void vnic_m_stop(void *);
static int vnic_m_promisc(void *, boolean_t);
static int vnic_m_multicst(void *, boolean_t, const uint8_t *);
static int vnic_m_unicst(void *, const uint8_t *);
static int vnic_m_stat(void *, uint_t, uint64_t *);
static void vnic_m_resources(void *);
static mblk_t *vnic_m_tx(void *, mblk_t *);
static boolean_t vnic_m_capab_get(void *, mac_capab_t, void *);
static void vnic_mac_free(vnic_mac_t *);
static uint_t vnic_info_walker(mod_hash_key_t, mod_hash_val_t *, void *);
static void vnic_notify_cb(void *, mac_notify_type_t);
static int vnic_modify_mac_addr(vnic_t *, uint_t, uchar_t *);
static mblk_t *vnic_active_tx(void *, mblk_t *);
static int vnic_promisc_set(vnic_t *, boolean_t);

static kmem_cache_t	*vnic_cache;
static kmem_cache_t	*vnic_mac_cache;
static krwlock_t	vnic_lock;
static kmutex_t		vnic_mac_lock;
static uint_t		vnic_count;

/* hash of VNICs (vnic_t's), keyed by VNIC id */
static mod_hash_t	*vnic_hash;
#define	VNIC_HASHSZ	64
#define	VNIC_HASH_KEY(vnic_id)	((mod_hash_key_t)(uintptr_t)vnic_id)

/*
 * Hash of underlying open MACs (vnic_mac_t's), keyed by the string
 * "<device name><instance number>/<port number>".
 */
static mod_hash_t	*vnic_mac_hash;
#define	VNIC_MAC_HASHSZ	64

#define	VNIC_MAC_REFHOLD(va) {			\
	ASSERT(MUTEX_HELD(&vnic_mac_lock));	\
	(va)->va_refs++;			\
	ASSERT((va)->va_refs != 0);		\
}

#define	VNIC_MAC_REFRELE(va) {			\
	ASSERT(MUTEX_HELD(&vnic_mac_lock));	\
	ASSERT((va)->va_refs != 0);		\
	if (--((va)->va_refs) == 0)		\
		vnic_mac_free(va);		\
}

static uchar_t vnic_brdcst_mac[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

/* used by vnic_walker */
typedef struct vnic_info_state {
	datalink_id_t	vs_vnic_id;
	datalink_id_t	vs_linkid;
	boolean_t	vs_vnic_found;
	vnic_info_new_vnic_fn_t	vs_new_vnic_fn;
	void		*vs_fn_arg;
	int		vs_rc;
} vnic_info_state_t;

#define	VNIC_M_CALLBACK_FLAGS	(MC_RESOURCES | MC_GETCAPAB)

static mac_callbacks_t vnic_m_callbacks = {
	VNIC_M_CALLBACK_FLAGS,
	vnic_m_stat,
	vnic_m_start,
	vnic_m_stop,
	vnic_m_promisc,
	vnic_m_multicst,
	vnic_m_unicst,
	vnic_m_tx,
	vnic_m_resources,
	NULL,			/* m_ioctl */
	vnic_m_capab_get
};

/* ARGSUSED */
static int
vnic_mac_ctor(void *buf, void *arg, int kmflag)
{
	vnic_mac_t *vnic_mac = buf;

	bzero(vnic_mac, sizeof (vnic_mac_t));
	rw_init(&vnic_mac->va_bcast_grp_lock, NULL, RW_DRIVER, NULL);
	rw_init(&vnic_mac->va_promisc_lock, NULL, RW_DRIVER, NULL);

	return (0);
}

/* ARGSUSED */
static void
vnic_mac_dtor(void *buf, void *arg)
{
	vnic_mac_t *vnic_mac = buf;

	rw_destroy(&vnic_mac->va_promisc_lock);
	rw_destroy(&vnic_mac->va_bcast_grp_lock);
}

void
vnic_dev_init(void)
{
	vnic_cache = kmem_cache_create("vnic_cache",
	    sizeof (vnic_t), 0, NULL, NULL, NULL, NULL, NULL, 0);

	vnic_mac_cache = kmem_cache_create("vnic_mac_cache",
	    sizeof (vnic_mac_t), 0, vnic_mac_ctor, vnic_mac_dtor,
	    NULL, NULL, NULL, 0);

	vnic_hash = mod_hash_create_idhash("vnic_hash",
	    VNIC_HASHSZ, mod_hash_null_valdtor);

	vnic_mac_hash = mod_hash_create_idhash("vnic_mac_hash",
	    VNIC_MAC_HASHSZ, mod_hash_null_valdtor);

	rw_init(&vnic_lock, NULL, RW_DEFAULT, NULL);

	mutex_init(&vnic_mac_lock, NULL, MUTEX_DEFAULT, NULL);

	vnic_count = 0;
}

void
vnic_dev_fini(void)
{
	ASSERT(vnic_count == 0);

	mutex_destroy(&vnic_mac_lock);
	rw_destroy(&vnic_lock);
	mod_hash_destroy_idhash(vnic_mac_hash);
	mod_hash_destroy_idhash(vnic_hash);
	kmem_cache_destroy(vnic_mac_cache);
	kmem_cache_destroy(vnic_cache);
}

uint_t
vnic_dev_count(void)
{
	return (vnic_count);
}

static int
vnic_mac_open(datalink_id_t linkid, vnic_mac_t **vmp)
{
	int err;
	vnic_mac_t *vnic_mac = NULL;
	const mac_info_t *mip;

	*vmp = NULL;

	mutex_enter(&vnic_mac_lock);

	err = mod_hash_find(vnic_mac_hash, (mod_hash_key_t)(uintptr_t)linkid,
	    (mod_hash_val_t *)&vnic_mac);
	if (err == 0) {
		/* this MAC is already opened, increment reference count */
		VNIC_MAC_REFHOLD(vnic_mac);
		mutex_exit(&vnic_mac_lock);
		*vmp = vnic_mac;
		return (0);
	}

	vnic_mac = kmem_cache_alloc(vnic_mac_cache, KM_SLEEP);
	if ((err = mac_open_by_linkid(linkid, &vnic_mac->va_mh)) != 0) {
		vnic_mac->va_mh = NULL;
		goto bail;
	}

	/*
	 * For now, we do not support VNICs over legacy drivers.  This will
	 * soon be changed.
	 */
	if (mac_is_legacy(vnic_mac->va_mh)) {
		err = ENOTSUP;
		goto bail;
	}

	/* only ethernet support, for now */
	mip = mac_info(vnic_mac->va_mh);
	if (mip->mi_media != DL_ETHER) {
		err = ENOTSUP;
		goto bail;
	}
	if (mip->mi_media != mip->mi_nativemedia) {
		err = ENOTSUP;
		goto bail;
	}

	vnic_mac->va_linkid = linkid;

	/* add entry to hash table */
	err = mod_hash_insert(vnic_mac_hash, (mod_hash_key_t)(uintptr_t)linkid,
	    (mod_hash_val_t)vnic_mac);
	ASSERT(err == 0);

	/* initialize the flow table associated with lower MAC */
	vnic_mac->va_addr_len = ETHERADDRL;
	(void) vnic_classifier_flow_tab_init(vnic_mac, vnic_mac->va_addr_len,
	    KM_SLEEP);

	vnic_mac->va_txinfo = mac_vnic_tx_get(vnic_mac->va_mh);
	vnic_mac->va_notify_hdl = mac_notify_add(vnic_mac->va_mh,
	    vnic_notify_cb, vnic_mac);

	VNIC_MAC_REFHOLD(vnic_mac);
	*vmp = vnic_mac;
	mutex_exit(&vnic_mac_lock);
	return (0);

bail:
	if (vnic_mac != NULL) {
		if (vnic_mac->va_mh != NULL)
			mac_close(vnic_mac->va_mh);
		kmem_cache_free(vnic_mac_cache, vnic_mac);
	}
	mutex_exit(&vnic_mac_lock);
	return (err);
}

/*
 * Create a new flow for the active MAC client sharing the NIC
 * with the VNICs. This allows the unicast packets for that NIC
 * to be classified and passed up to the active MAC client. It
 * also allows packets sent from a VNIC to the active link to
 * be classified by the VNIC transmit function and delivered via
 * the MAC module locally. Returns B_TRUE on success, B_FALSE on
 * failure.
 */
static int
vnic_init_active_rx(vnic_mac_t *vnic_mac)
{
	uchar_t nic_mac_addr[MAXMACADDRLEN];

	if (vnic_mac->va_active_flow != NULL)
		return (B_TRUE);

	mac_unicst_get(vnic_mac->va_mh, nic_mac_addr);

	vnic_mac->va_active_flow = vnic_classifier_flow_create(
	    vnic_mac->va_addr_len, nic_mac_addr, NULL, B_TRUE, KM_SLEEP);

	vnic_classifier_flow_add(vnic_mac, vnic_mac->va_active_flow,
	    (vnic_rx_fn_t)mac_active_rx, vnic_mac->va_mh, NULL);
	return (B_TRUE);
}

static void
vnic_fini_active_rx(vnic_mac_t *vnic_mac)
{
	if (vnic_mac->va_active_flow == NULL)
		return;

	vnic_classifier_flow_remove(vnic_mac, vnic_mac->va_active_flow);
	vnic_classifier_flow_destroy(vnic_mac->va_active_flow);
	vnic_mac->va_active_flow = NULL;
}

static void
vnic_update_active_rx(vnic_mac_t *vnic_mac)
{
	if (vnic_mac->va_active_flow == NULL)
		return;

	vnic_fini_active_rx(vnic_mac);
	(void) vnic_init_active_rx(vnic_mac);
}

/*
 * Copy an mblk, preserving its hardware checksum flags.
 */
mblk_t *
vnic_copymsg_cksum(mblk_t *mp)
{
	mblk_t *mp1;
	uint32_t start, stuff, end, value, flags;

	mp1 = copymsg(mp);
	if (mp1 == NULL)
		return (NULL);

	hcksum_retrieve(mp, NULL, NULL, &start, &stuff, &end, &value, &flags);
	(void) hcksum_assoc(mp1, NULL, NULL, start, stuff, end, value,
	    flags, KM_NOSLEEP);

	return (mp1);
}

/*
 * Copy an mblk chain, presenting the hardware checksum flags of the
 * individual mblks.
 */
mblk_t *
vnic_copymsgchain_cksum(mblk_t *mp)
{
	mblk_t *nmp = NULL;
	mblk_t **nmpp = &nmp;

	for (; mp != NULL; mp = mp->b_next) {
		if ((*nmpp = vnic_copymsg_cksum(mp)) == NULL) {
			freemsgchain(nmp);
			return (NULL);
		}

		nmpp = &((*nmpp)->b_next);
	}

	return (nmp);
}


/*
 * Process the specified mblk chain for proper handling of hardware
 * checksum offload. This routine is invoked for loopback VNIC traffic.
 * The function handles a NULL mblk chain passed as argument.
 */
mblk_t *
vnic_fix_cksum(mblk_t *mp_chain)
{
	mblk_t *mp, *prev = NULL, *new_chain = mp_chain, *mp1;
	uint32_t flags, start, stuff, end, value;

	for (mp = mp_chain; mp != NULL; prev = mp, mp = mp->b_next) {
		uint16_t len;
		uint32_t offset;
		struct ether_header *ehp;
		uint16_t sap;

		hcksum_retrieve(mp, NULL, NULL, &start, &stuff, &end, &value,
		    &flags);
		if (flags == 0)
			continue;

		/*
		 * Since the processing of checksum offload for loopback
		 * traffic requires modification of the packet contents,
		 * ensure sure that we are always modifying our own copy.
		 */
		if (DB_REF(mp) > 1) {
			mp1 = copymsg(mp);
			if (mp1 == NULL)
				continue;
			mp1->b_next = mp->b_next;
			mp->b_next = NULL;
			freemsg(mp);
			if (prev != NULL)
				prev->b_next = mp1;
			else
				new_chain = mp1;
			mp = mp1;
		}

		/*
		 * Ethernet, and optionally VLAN header.
		 */
		/*LINTED*/
		ehp = (struct ether_header *)mp->b_rptr;
		if (ntohs(ehp->ether_type) == VLAN_TPID) {
			struct ether_vlan_header *evhp;

			ASSERT(MBLKL(mp) >=
			    sizeof (struct ether_vlan_header));
			/*LINTED*/
			evhp = (struct ether_vlan_header *)mp->b_rptr;
			sap = ntohs(evhp->ether_type);
			offset = sizeof (struct ether_vlan_header);
		} else {
			sap = ntohs(ehp->ether_type);
			offset = sizeof (struct ether_header);
		}

		if (MBLKL(mp) <= offset) {
			offset -= MBLKL(mp);
			if (mp->b_cont == NULL) {
				/* corrupted packet, skip it */
				if (prev != NULL)
					prev->b_next = mp->b_next;
				else
					new_chain = mp->b_next;
				mp1 = mp->b_next;
				mp->b_next = NULL;
				freemsg(mp);
				mp = mp1;
				continue;
			}
			mp = mp->b_cont;
		}

		if (flags & (HCK_FULLCKSUM | HCK_IPV4_HDRCKSUM)) {
			ipha_t *ipha = NULL;

			/*
			 * In order to compute the full and header
			 * checksums, we need to find and parse
			 * the IP and/or ULP headers.
			 */

			sap = (sap < ETHERTYPE_802_MIN) ? 0 : sap;

			/*
			 * IP header.
			 */
			if (sap != ETHERTYPE_IP)
				continue;

			ASSERT(MBLKL(mp) >= offset + sizeof (ipha_t));
			/*LINTED*/
			ipha = (ipha_t *)(mp->b_rptr + offset);

			if (flags & HCK_FULLCKSUM) {
				ipaddr_t src, dst;
				uint32_t cksum;
				uint16_t *up;
				uint8_t proto;

				/*
				 * Pointer to checksum field in ULP header.
				 */
				proto = ipha->ipha_protocol;
				ASSERT(ipha->ipha_version_and_hdr_length ==
				    IP_SIMPLE_HDR_VERSION);
				if (proto == IPPROTO_TCP) {
					/*LINTED*/
					up = IPH_TCPH_CHECKSUMP(ipha,
					    IP_SIMPLE_HDR_LENGTH);
				} else {
					ASSERT(proto == IPPROTO_UDP);
					/*LINTED*/
					up = IPH_UDPH_CHECKSUMP(ipha,
					    IP_SIMPLE_HDR_LENGTH);
				}

				/*
				 * Pseudo-header checksum.
				 */
				src = ipha->ipha_src;
				dst = ipha->ipha_dst;
				len = ntohs(ipha->ipha_length) -
				    IP_SIMPLE_HDR_LENGTH;

				cksum = (dst >> 16) + (dst & 0xFFFF) +
				    (src >> 16) + (src & 0xFFFF);
				cksum += htons(len);

				/*
				 * The checksum value stored in the packet needs
				 * to be correct. Compute it here.
				 */
				*up = 0;
				cksum += (((proto) == IPPROTO_UDP) ?
				    IP_UDP_CSUM_COMP : IP_TCP_CSUM_COMP);
				cksum = IP_CSUM(mp, IP_SIMPLE_HDR_LENGTH +
				    offset, cksum);
				*(up) = (uint16_t)(cksum ? cksum : ~cksum);

				flags |= HCK_FULLCKSUM_OK;
				value = 0xffff;
			}

			if (flags & HCK_IPV4_HDRCKSUM) {
				ASSERT(ipha != NULL);
				ipha->ipha_hdr_checksum =
				    (uint16_t)ip_csum_hdr(ipha);
			}
		}

		if (flags & HCK_PARTIALCKSUM) {
			uint16_t *up, partial, cksum;
			uchar_t *ipp; /* ptr to beginning of IP header */

			if (mp->b_cont != NULL) {
				mblk_t *mp1;

				mp1 = msgpullup(mp, offset + end);
				if (mp1 == NULL)
					continue;
				mp1->b_next = mp->b_next;
				mp->b_next = NULL;
				freemsg(mp);
				if (prev != NULL)
					prev->b_next = mp1;
				else
					new_chain = mp1;
				mp = mp1;
			}

			ipp = mp->b_rptr + offset;
			/*LINTED*/
			up = (uint16_t *)((uchar_t *)ipp + stuff);
			partial = *up;
			*up = 0;

			cksum = IP_BCSUM_PARTIAL(mp->b_rptr + offset + start,
			    end - start, partial);
			cksum = ~cksum;
			*up = cksum ? cksum : ~cksum;

			/*
			 * Since we already computed the whole checksum,
			 * indicate to the stack that it has already
			 * been verified by the hardware.
			 */
			flags &= ~HCK_PARTIALCKSUM;
			flags |= (HCK_FULLCKSUM | HCK_FULLCKSUM_OK);
			value = 0xffff;
		}

		(void) hcksum_assoc(mp, NULL, NULL, start, stuff, end,
		    value, flags, KM_NOSLEEP);
	}

	return (new_chain);
}

static void
vnic_mac_close(vnic_mac_t *vnic_mac)
{
	mutex_enter(&vnic_mac_lock);
	VNIC_MAC_REFRELE(vnic_mac);
	mutex_exit(&vnic_mac_lock);
}

static void
vnic_mac_free(vnic_mac_t *vnic_mac)
{
	mod_hash_val_t val;

	ASSERT(MUTEX_HELD(&vnic_mac_lock));
	vnic_fini_active_rx(vnic_mac);
	mac_notify_remove(vnic_mac->va_mh, vnic_mac->va_notify_hdl);
	if (vnic_mac->va_mac_set) {
		vnic_mac->va_mac_set = B_FALSE;
		mac_vnic_clear(vnic_mac->va_mh);
	}
	vnic_classifier_flow_tab_fini(vnic_mac);
	mac_close(vnic_mac->va_mh);

	(void) mod_hash_remove(vnic_mac_hash,
	    (mod_hash_key_t)(uintptr_t)vnic_mac->va_linkid, &val);
	ASSERT(vnic_mac == (vnic_mac_t *)val);

	kmem_cache_free(vnic_mac_cache, vnic_mac);
}

/*
 * Initial VNIC receive routine. Invoked for packets that are steered
 * to a VNIC but the VNIC has not been started yet.
 */
/* ARGSUSED */
static void
vnic_rx_initial(void *arg1, void *arg2, mblk_t *mp_chain)
{
	vnic_t *vnic = arg1;
	mblk_t *mp;

	/* update stats */
	for (mp = mp_chain; mp != NULL; mp = mp->b_next)
		vnic->vn_stat_ierrors++;
	freemsgchain(mp_chain);
}

/*
 * VNIC receive routine invoked after the classifier for the VNIC
 * has been initialized and the VNIC has been started.
 */
/* ARGSUSED */
void
vnic_rx(void *arg1, void *arg2, mblk_t *mp_chain)
{
	vnic_t *vnic = arg1;
	mblk_t *mp;

	/* update stats */
	for (mp = mp_chain; mp != NULL; mp = mp->b_next) {
		vnic->vn_stat_ipackets++;
		vnic->vn_stat_rbytes += msgdsize(mp);
	}

	/* pass packet up */
	mac_rx(vnic->vn_mh, NULL, mp_chain);
}

/*
 * Routine to create a MAC-based VNIC. Adds the passed MAC address
 * to an unused slot in the NIC if one is available. Otherwise it
 * sets the NIC in promiscuous mode and assigns the MAC address to
 * a Rx ring if available or a soft ring.
 */
static int
vnic_add_unicstaddr(vnic_t *vnic, mac_multi_addr_t *maddr)
{
	vnic_mac_t *vnic_mac = vnic->vn_vnic_mac;
	int err;

	if (mac_unicst_verify(vnic_mac->va_mh, maddr->mma_addr,
	    maddr->mma_addrlen) == B_FALSE)
		return (EINVAL);

	if (mac_vnic_capab_get(vnic_mac->va_mh, MAC_CAPAB_MULTIADDRESS,
	    &(vnic->vn_mma_capab))) {
		if (vnic->vn_maddr_naddrfree == 0) {
			/*
			 * No free address slots available.
			 * Enable promiscuous mode.
			 */
			goto set_promisc;
		}

		err = vnic->vn_maddr_add(vnic->vn_maddr_handle, maddr);
		if (err != 0) {
			if (err == ENOSPC) {
				/*
				 * There was a race to add addresses
				 * with other multiple address consumers,
				 * and we lost out. Use promisc mode.
				 */
				goto set_promisc;
			}

			return (err);
		}

		vnic->vn_slot_id = maddr->mma_slot;
		vnic->vn_multi_mac = B_TRUE;
	} else {
		/*
		 * Either multiple MAC address support is not
		 * available or all available addresses have
		 * been used up.
		 */
	set_promisc:
		if ((err = mac_promisc_set(vnic_mac->va_mh, B_TRUE,
		    MAC_DEVPROMISC)) != 0) {
			return (err);
		}

		vnic->vn_promisc_mac = B_TRUE;
	}
	return (err);
}

/*
 * VNIC is getting deleted. Remove the MAC address from the slot.
 * If promiscuous mode was being used, then unset the promiscuous mode.
 */
static int
vnic_remove_unicstaddr(vnic_t *vnic)
{
	vnic_mac_t *vnic_mac = vnic->vn_vnic_mac;
	int err;

	if (vnic->vn_multi_mac) {
		ASSERT(vnic->vn_promisc_mac == B_FALSE);
		err = vnic->vn_maddr_remove(vnic->vn_maddr_handle,
		    vnic->vn_slot_id);
		vnic->vn_multi_mac = B_FALSE;
	}

	if (vnic->vn_promisc_mac) {
		ASSERT(vnic->vn_multi_mac == B_FALSE);
		err = mac_promisc_set(vnic_mac->va_mh, B_FALSE, MAC_DEVPROMISC);
		vnic->vn_promisc_mac = B_FALSE;
	}

	return (err);
}

/*
 * Create a new VNIC upon request from administrator.
 * Returns 0 on success, an errno on failure.
 */
int
vnic_dev_create(datalink_id_t vnic_id, datalink_id_t linkid, int mac_len,
    uchar_t *mac_addr)
{
	vnic_t *vnic = NULL;
	mac_register_t *mac;
	int err;
	vnic_mac_t *vnic_mac;
	mac_multi_addr_t maddr;
	mac_txinfo_t tx_info;

	if (mac_len != ETHERADDRL) {
		/* currently only ethernet NICs are supported */
		return (EINVAL);
	}

	rw_enter(&vnic_lock, RW_WRITER);

	/* does a VNIC with the same id already exist? */
	err = mod_hash_find(vnic_hash, VNIC_HASH_KEY(vnic_id),
	    (mod_hash_val_t *)&vnic);
	if (err == 0) {
		rw_exit(&vnic_lock);
		return (EEXIST);
	}

	vnic = kmem_cache_alloc(vnic_cache, KM_NOSLEEP);
	if (vnic == NULL) {
		rw_exit(&vnic_lock);
		return (ENOMEM);
	}

	/* open underlying MAC */
	err = vnic_mac_open(linkid, &vnic_mac);
	if (err != 0) {
		kmem_cache_free(vnic_cache, vnic);
		rw_exit(&vnic_lock);
		return (err);
	}

	bzero(vnic, sizeof (*vnic));
	vnic->vn_id = vnic_id;
	vnic->vn_vnic_mac = vnic_mac;

	vnic->vn_started = B_FALSE;
	vnic->vn_promisc = B_FALSE;
	vnic->vn_multi_mac = B_FALSE;
	vnic->vn_bcast_grp = B_FALSE;

	/* set the VNIC MAC address */
	maddr.mma_addrlen = mac_len;
	maddr.mma_slot = 0;
	maddr.mma_flags = 0;
	bcopy(mac_addr, maddr.mma_addr, mac_len);
	if ((err = vnic_add_unicstaddr(vnic, &maddr)) != 0)
		goto bail;
	bcopy(mac_addr, vnic->vn_addr, mac_len);

	/* set the initial VNIC capabilities */
	if (!mac_vnic_capab_get(vnic_mac->va_mh, MAC_CAPAB_HCKSUM,
	    &vnic->vn_hcksum_txflags))
		vnic->vn_hcksum_txflags = 0;

	/* register with the MAC module */
	if ((mac = mac_alloc(MAC_VERSION)) == NULL)
		goto bail;

	mac->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	mac->m_driver = vnic;
	mac->m_dip = vnic_get_dip();
	mac->m_instance = (uint_t)-1;
	mac->m_src_addr = vnic->vn_addr;
	mac->m_callbacks = &vnic_m_callbacks;

	mac_sdu_get(vnic_mac->va_mh, &mac->m_min_sdu, &mac->m_max_sdu);

	/*
	 * As the current margin size of the underlying mac is used to
	 * determine the margin size of the VNIC itself, request the
	 * underlying mac not to change to a smaller margin size.
	 */
	err = mac_margin_add(vnic_mac->va_mh, &(vnic->vn_margin), B_TRUE);
	if (err != 0)
		goto bail;
	mac->m_margin = vnic->vn_margin;
	err = mac_register(mac, &vnic->vn_mh);
	mac_free(mac);
	if (err != 0) {
		VERIFY(mac_margin_remove(vnic_mac->va_mh,
		    vnic->vn_margin) == 0);
		goto bail;
	}

	if ((err = dls_devnet_create(vnic->vn_mh, vnic->vn_id)) != 0) {
		VERIFY(mac_margin_remove(vnic_mac->va_mh,
		    vnic->vn_margin) == 0);
		(void) mac_unregister(vnic->vn_mh);
		goto bail;
	}

	/* add new VNIC to hash table */
	err = mod_hash_insert(vnic_hash, VNIC_HASH_KEY(vnic_id),
	    (mod_hash_val_t)vnic);
	ASSERT(err == 0);
	vnic_count++;

	rw_exit(&vnic_lock);

	/* Create a flow, initialized with the MAC address of the VNIC */
	if ((vnic->vn_flow_ent = vnic_classifier_flow_create(mac_len, mac_addr,
	    NULL, B_FALSE, KM_SLEEP)) == NULL) {
		(void) vnic_dev_delete(vnic_id);
		vnic = NULL;
		err = ENOMEM;
		goto bail_unlocked;
	}

	vnic_classifier_flow_add(vnic_mac, vnic->vn_flow_ent, vnic_rx_initial,
	    vnic, vnic);

	/* setup VNIC to receive broadcast packets */
	err = vnic_bcast_add(vnic, vnic_brdcst_mac, MAC_ADDRTYPE_BROADCAST);
	if (err != 0) {
		(void) vnic_dev_delete(vnic_id);
		vnic = NULL;
		goto bail_unlocked;
	}
	vnic->vn_bcast_grp = B_TRUE;

	mutex_enter(&vnic_mac_lock);
	if (!vnic_mac->va_mac_set) {
		/*
		 * We want to MAC layer to call the VNIC tx outbound
		 * routine, so that local broadcast packets sent by
		 * the active interface sharing the underlying NIC (if
		 * any), can be broadcast to every VNIC.
		 */
		tx_info.mt_fn = vnic_active_tx;
		tx_info.mt_arg = vnic_mac;
		if (!mac_vnic_set(vnic_mac->va_mh, &tx_info,
		    vnic_m_capab_get, vnic)) {
			mutex_exit(&vnic_mac_lock);
			(void) vnic_dev_delete(vnic_id);
			vnic = NULL;
			err = EBUSY;
			goto bail_unlocked;
		}
		vnic_mac->va_mac_set = B_TRUE;
	}
	mutex_exit(&vnic_mac_lock);

	/* allow passing packets to NIC's active MAC client */
	if (!vnic_init_active_rx(vnic_mac)) {
		(void) vnic_dev_delete(vnic_id);
		vnic = NULL;
		err = ENOMEM;
		goto bail_unlocked;
	}

	return (0);

bail:
	(void) vnic_remove_unicstaddr(vnic);
	vnic_mac_close(vnic_mac);
	rw_exit(&vnic_lock);

bail_unlocked:
	if (vnic != NULL) {
		kmem_cache_free(vnic_cache, vnic);
	}

	return (err);
}

/*
 * Modify the properties of an existing VNIC.
 */
/* ARGSUSED */
int
vnic_dev_modify(datalink_id_t vnic_id, uint_t modify_mask,
    vnic_mac_addr_type_t mac_addr_type, uint_t mac_len, uchar_t *mac_addr)
{
	vnic_t *vnic = NULL;
	int rv = 0;
	boolean_t notify_mac_addr = B_FALSE;

	rw_enter(&vnic_lock, RW_WRITER);

	if (mod_hash_find(vnic_hash, VNIC_HASH_KEY(vnic_id),
	    (mod_hash_val_t *)&vnic) != 0) {
		rw_exit(&vnic_lock);
		return (ENOENT);
	}

	if (modify_mask & VNIC_IOC_MODIFY_ADDR) {
		rv = vnic_modify_mac_addr(vnic, mac_len, mac_addr);
		if (rv == 0)
			notify_mac_addr = B_TRUE;
	}

	rw_exit(&vnic_lock);

	if (notify_mac_addr)
		mac_unicst_update(vnic->vn_mh, mac_addr);

	return (rv);
}

int
vnic_dev_delete(datalink_id_t vnic_id)
{
	vnic_t *vnic = NULL;
	mod_hash_val_t val;
	vnic_flow_t *flent;
	datalink_id_t tmpid;
	int rc;
	vnic_mac_t *vnic_mac;

	rw_enter(&vnic_lock, RW_WRITER);

	if (mod_hash_find(vnic_hash, VNIC_HASH_KEY(vnic_id),
	    (mod_hash_val_t *)&vnic) != 0) {
		rw_exit(&vnic_lock);
		return (ENOENT);
	}

	if ((rc = dls_devnet_destroy(vnic->vn_mh, &tmpid)) != 0) {
		rw_exit(&vnic_lock);
		return (rc);
	}

	ASSERT(vnic_id == tmpid);

	/*
	 * We cannot unregister the MAC yet. Unregistering would
	 * free up mac_impl_t which should not happen at this time.
	 * Packets could be entering vnic_rx() through the
	 * flow entry and so mac_impl_t cannot be NULL. So disable
	 * mac_impl_t by calling mac_disable(). This will prevent any
	 * new claims on mac_impl_t.
	 */
	if (mac_disable(vnic->vn_mh) != 0) {
		(void) dls_devnet_create(vnic->vn_mh, vnic_id);
		rw_exit(&vnic_lock);
		return (EBUSY);
	}

	(void) mod_hash_remove(vnic_hash, VNIC_HASH_KEY(vnic_id), &val);
	ASSERT(vnic == (vnic_t *)val);

	if (vnic->vn_bcast_grp)
		(void) vnic_bcast_delete(vnic, vnic_brdcst_mac);

	flent = vnic->vn_flow_ent;
	if (flent != NULL) {
		/*
		 * vnic_classifier_flow_destroy() ensures that the
		 * flow is no longer used.
		 */
		vnic_classifier_flow_remove(vnic->vn_vnic_mac, flent);
		vnic_classifier_flow_destroy(flent);
	}

	rc = mac_margin_remove(vnic->vn_vnic_mac->va_mh, vnic->vn_margin);
	ASSERT(rc == 0);
	rc = mac_unregister(vnic->vn_mh);
	ASSERT(rc == 0);
	(void) vnic_remove_unicstaddr(vnic);
	vnic_mac = vnic->vn_vnic_mac;
	kmem_cache_free(vnic_cache, vnic);
	vnic_count--;
	rw_exit(&vnic_lock);
	vnic_mac_close(vnic_mac);
	return (0);
}

/*
 * For the specified packet chain, return a sub-chain to be sent
 * and the transmit function to be used to send the packet. Also
 * return a pointer to the sub-chain of packets that should
 * be re-classified. If the function returns NULL, the packet
 * should be sent using the underlying NIC.
 */
static vnic_flow_t *
vnic_classify(vnic_mac_t *vnic_mac, mblk_t *mp, mblk_t **mp_chain_rest)
{
	vnic_flow_t *flow_ent;

	/* one packet at a time */
	*mp_chain_rest = mp->b_next;
	mp->b_next = NULL;

	/* do classification on the packet */
	flow_ent = vnic_classifier_get_flow(vnic_mac, mp);

	return (flow_ent);
}

/*
 * Send a packet chain to a local VNIC or an active MAC client.
 */
static void
vnic_local_tx(vnic_mac_t *vnic_mac, vnic_flow_t *flow_ent, mblk_t *mp_chain)
{
	mblk_t *mp1;
	const vnic_flow_fn_info_t *fn_info;
	vnic_t *vnic;

	if (!vnic_classifier_is_active(flow_ent) &&
	    mac_promisc_get(vnic_mac->va_mh, MAC_PROMISC)) {
		/*
		 * If the MAC is in promiscous mode,
		 * send a copy of the active client.
		 */
		if ((mp1 = vnic_copymsgchain_cksum(mp_chain)) == NULL)
			goto sendit;
		if ((mp1 = vnic_fix_cksum(mp1)) == NULL)
			goto sendit;
		mac_active_rx(vnic_mac->va_mh, NULL, mp1);
	}
sendit:
	fn_info = vnic_classifier_get_fn_info(flow_ent);
	/*
	 * If the vnic to which we would deliver this packet is in
	 * promiscuous mode then it already received the packet via
	 * vnic_promisc_rx().
	 *
	 * XXX assumes that ff_arg2 is a vnic_t pointer if it is
	 * non-NULL (currently always true).
	 */
	vnic = (vnic_t *)fn_info->ff_arg2;
	if ((vnic != NULL) && vnic->vn_promisc)
		freemsg(mp_chain);
	else if ((mp1 = vnic_fix_cksum(mp_chain)) != NULL)
		(fn_info->ff_fn)(fn_info->ff_arg1, fn_info->ff_arg2, mp1);
}

/*
 * This function is invoked when a MAC client needs to send a packet
 * to a NIC which is shared by VNICs. It is passed to the MAC layer
 * by a call to mac_vnic_set() when the NIC is opened, and is returned
 * to MAC clients by mac_tx_get() when VNICs are present.
 */
mblk_t *
vnic_active_tx(void *arg, mblk_t *mp_chain)
{
	vnic_mac_t *vnic_mac = arg;
	mblk_t *mp, *extra_mp = NULL;
	vnic_flow_t *flow_ent;
	void *flow_cookie;
	const mac_txinfo_t *mtp = vnic_mac->va_txinfo;

	for (mp = mp_chain; mp != NULL; mp = extra_mp) {
		mblk_t *next;

		next = mp->b_next;
		mp->b_next = NULL;

		vnic_promisc_rx(vnic_mac, (vnic_t *)-1, mp);

		flow_ent = vnic_classify(vnic_mac, mp, &extra_mp);
		ASSERT(extra_mp == NULL);
		extra_mp = next;

		if (flow_ent != NULL) {
			flow_cookie = vnic_classifier_get_client_cookie(
			    flow_ent);
			if (flow_cookie != NULL) {
				/*
				 * Send a copy to every VNIC defined on the
				 * interface, as well as the underlying MAC.
				 */
				vnic_bcast_send(flow_cookie, (vnic_t *)-1, mp);
			} else {
				/*
				 * loopback the packet to a local VNIC or
				 * an active MAC client.
				 */
				vnic_local_tx(vnic_mac, flow_ent, mp);
			}
			VNIC_FLOW_REFRELE(flow_ent);
			mp_chain = NULL;
		} else {
			/*
			 * Non-VNIC destination, send via the underlying
			 * NIC. In order to avoid a recursive call
			 * to this function, we ensured that mtp points
			 * to the unerlying NIC transmit function
			 * by inilizating through mac_vnic_tx_get().
			 */
			mp_chain = mtp->mt_fn(mtp->mt_arg, mp);
			if (mp_chain != NULL)
				break;
		}
	}

	if ((mp_chain != NULL) && (extra_mp != NULL)) {
		ASSERT(mp_chain->b_next == NULL);
		mp_chain->b_next = extra_mp;
	}
	return (mp_chain);
}

/*
 * VNIC transmit function.
 */
mblk_t *
vnic_m_tx(void *arg, mblk_t *mp_chain)
{
	vnic_t *vnic = arg;
	vnic_mac_t *vnic_mac = vnic->vn_vnic_mac;
	mblk_t *mp, *extra_mp = NULL;
	vnic_flow_t *flow_ent;
	void *flow_cookie;

	/*
	 * Update stats.
	 */
	for (mp = mp_chain; mp != NULL; mp = mp->b_next) {
		vnic->vn_stat_opackets++;
		vnic->vn_stat_obytes += msgdsize(mp);
	}

	for (mp = mp_chain; mp != NULL; mp = extra_mp) {
		mblk_t *next;

		next = mp->b_next;
		mp->b_next = NULL;

		vnic_promisc_rx(vnic->vn_vnic_mac, vnic, mp);

		flow_ent = vnic_classify(vnic->vn_vnic_mac, mp, &extra_mp);
		ASSERT(extra_mp == NULL);
		extra_mp = next;

		if (flow_ent != NULL) {
			flow_cookie = vnic_classifier_get_client_cookie(
			    flow_ent);
			if (flow_cookie != NULL) {
				/*
				 * The vnic_bcast_send function expects
				 * to receive the sender VNIC as value
				 * for arg2.
				 */
				vnic_bcast_send(flow_cookie, vnic, mp);
			} else {
				/*
				 * loopback the packet to a local VNIC or
				 * an active MAC client.
				 */
				vnic_local_tx(vnic_mac, flow_ent, mp);
			}
			VNIC_FLOW_REFRELE(flow_ent);
			mp_chain = NULL;
		} else {
			/*
			 * Non-local destination, send via the underlying
			 * NIC.
			 */
			const mac_txinfo_t *mtp = vnic->vn_txinfo;
			mp_chain = mtp->mt_fn(mtp->mt_arg, mp);
			if (mp_chain != NULL)
				break;
		}
	}

	/* update stats to account for unsent packets */
	for (mp = mp_chain; mp != NULL; mp = mp->b_next) {
		vnic->vn_stat_opackets--;
		vnic->vn_stat_obytes -= msgdsize(mp);
		vnic->vn_stat_oerrors++;
		/*
		 * link back in the last portion not counted due to bandwidth
		 * control.
		 */
		if (mp->b_next == NULL) {
			mp->b_next = extra_mp;
			break;
		}
	}

	return (mp_chain);
}

/* ARGSUSED */
static void
vnic_m_resources(void *arg)
{
	/* no resources to advertise */
}

static int
vnic_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	vnic_t *vnic = arg;
	int rval = 0;

	rw_enter(&vnic_lock, RW_READER);

	switch (stat) {
	case ETHER_STAT_LINK_DUPLEX:
		*val = mac_stat_get(vnic->vn_vnic_mac->va_mh,
		    ETHER_STAT_LINK_DUPLEX);
		break;
	case MAC_STAT_IFSPEED:
		*val = mac_stat_get(vnic->vn_vnic_mac->va_mh,
		    MAC_STAT_IFSPEED);
		break;
	case MAC_STAT_MULTIRCV:
		*val = vnic->vn_stat_multircv;
		break;
	case MAC_STAT_BRDCSTRCV:
		*val = vnic->vn_stat_brdcstrcv;
		break;
	case MAC_STAT_MULTIXMT:
		*val = vnic->vn_stat_multixmt;
		break;
	case MAC_STAT_BRDCSTXMT:
		*val = vnic->vn_stat_brdcstxmt;
		break;
	case MAC_STAT_IERRORS:
		*val = vnic->vn_stat_ierrors;
		break;
	case MAC_STAT_OERRORS:
		*val = vnic->vn_stat_oerrors;
		break;
	case MAC_STAT_RBYTES:
		*val = vnic->vn_stat_rbytes;
		break;
	case MAC_STAT_IPACKETS:
		*val = vnic->vn_stat_ipackets;
		break;
	case MAC_STAT_OBYTES:
		*val = vnic->vn_stat_obytes;
		break;
	case MAC_STAT_OPACKETS:
		*val = vnic->vn_stat_opackets;
		break;
	default:
		rval = ENOTSUP;
	}

	rw_exit(&vnic_lock);
	return (rval);
}

/*
 * Return information about the specified capability.
 */
/* ARGSUSED */
static boolean_t
vnic_m_capab_get(void *arg, mac_capab_t cap, void *cap_data)
{
	vnic_t *vnic = arg;

	switch (cap) {
	case MAC_CAPAB_POLL:
		return (B_TRUE);
	case MAC_CAPAB_HCKSUM: {
		uint32_t *hcksum_txflags = cap_data;

		*hcksum_txflags = vnic->vn_hcksum_txflags &
		    (HCKSUM_INET_FULL_V4 | HCKSUM_IPHDRCKSUM |
		    HCKSUM_INET_PARTIAL);
		break;
	}
	default:
		return (B_FALSE);
	}
	return (B_TRUE);
}

static int
vnic_m_start(void *arg)
{
	vnic_t *vnic = arg;
	mac_handle_t lower_mh = vnic->vn_vnic_mac->va_mh;
	int rc;

	rc = mac_start(lower_mh);
	if (rc != 0)
		return (rc);

	vnic_classifier_flow_update_fn(vnic->vn_flow_ent, vnic_rx, vnic, vnic);
	return (0);
}

static void
vnic_m_stop(void *arg)
{
	vnic_t *vnic = arg;
	mac_handle_t lower_mh = vnic->vn_vnic_mac->va_mh;

	vnic_classifier_flow_update_fn(vnic->vn_flow_ent, vnic_rx_initial,
	    vnic, vnic);
	mac_stop(lower_mh);
}

/* ARGSUSED */
static int
vnic_m_promisc(void *arg, boolean_t on)
{
	vnic_t *vnic = arg;

	return (vnic_promisc_set(vnic, on));
}

static int
vnic_m_multicst(void *arg, boolean_t add, const uint8_t *addrp)
{
	vnic_t *vnic = arg;
	int rc = 0;

	if (add)
		rc = vnic_bcast_add(vnic, addrp, MAC_ADDRTYPE_MULTICAST);
	else
		vnic_bcast_delete(vnic, addrp);

	return (rc);
}

static int
vnic_m_unicst(void *arg, const uint8_t *mac_addr)
{
	vnic_t *vnic = arg;
	vnic_mac_t *vnic_mac = vnic->vn_vnic_mac;
	int rv;

	rw_enter(&vnic_lock, RW_WRITER);
	rv = vnic_modify_mac_addr(vnic, vnic_mac->va_addr_len,
	    (uchar_t *)mac_addr);
	rw_exit(&vnic_lock);

	if (rv == 0)
		mac_unicst_update(vnic->vn_mh, mac_addr);
	return (0);
}

int
vnic_info(uint_t *nvnics, datalink_id_t vnic_id, datalink_id_t linkid,
    void *fn_arg, vnic_info_new_vnic_fn_t new_vnic_fn)
{
	vnic_info_state_t state;
	int rc = 0;

	rw_enter(&vnic_lock, RW_READER);

	*nvnics = vnic_count;

	bzero(&state, sizeof (state));
	state.vs_vnic_id = vnic_id;
	state.vs_linkid = linkid;
	state.vs_new_vnic_fn = new_vnic_fn;
	state.vs_fn_arg = fn_arg;

	mod_hash_walk(vnic_hash, vnic_info_walker, &state);

	if ((rc = state.vs_rc) == 0 && vnic_id != DATALINK_ALL_LINKID &&
	    !state.vs_vnic_found)
		rc = ENOENT;

	rw_exit(&vnic_lock);
	return (rc);
}

/*
 * Walker invoked when building a list of vnics that must be passed
 * up to user space.
 */
/*ARGSUSED*/
static uint_t
vnic_info_walker(mod_hash_key_t key, mod_hash_val_t *val, void *arg)
{
	vnic_t *vnic;
	vnic_info_state_t *state = arg;

	if (state->vs_rc != 0)
		return (MH_WALK_TERMINATE);	/* terminate walk */

	vnic = (vnic_t *)val;

	if (state->vs_vnic_id != DATALINK_ALL_LINKID &&
	    vnic->vn_id != state->vs_vnic_id) {
		goto bail;
	}

	state->vs_vnic_found = B_TRUE;

	state->vs_rc = state->vs_new_vnic_fn(state->vs_fn_arg,
	    vnic->vn_id, vnic->vn_addr_type, vnic->vn_vnic_mac->va_addr_len,
	    vnic->vn_addr, vnic->vn_vnic_mac->va_linkid);
bail:
	return ((state->vs_rc == 0) ? MH_WALK_CONTINUE : MH_WALK_TERMINATE);
}

/*
 * vnic_notify_cb() and vnic_notify_walker() below are used to
 * process events received from an underlying NIC and, if needed,
 * forward these events to the VNICs defined on top of that NIC.
 */

typedef struct vnic_notify_state {
	mac_notify_type_t	vo_type;
	vnic_mac_t		*vo_vnic_mac;
} vnic_notify_state_t;

/* ARGSUSED */
static uint_t
vnic_notify_walker(mod_hash_key_t key, mod_hash_val_t *val, void *arg)
{
	vnic_t *vnic = (vnic_t *)val;
	vnic_notify_state_t *state = arg;

	/* ignore VNICs that don't use the specified underlying MAC */
	if (vnic->vn_vnic_mac != state->vo_vnic_mac)
		return (MH_WALK_CONTINUE);

	switch (state->vo_type) {
	case MAC_NOTE_TX:
		mac_tx_update(vnic->vn_mh);
		break;
	case MAC_NOTE_LINK:
		/*
		 * The VNIC link state must be up regardless of
		 * the link state of the underlying NIC to maintain
		 * connectivity between VNICs on the same host.
		 */
		mac_link_update(vnic->vn_mh, LINK_STATE_UP);
		break;
	case MAC_NOTE_UNICST:
		vnic_update_active_rx(vnic->vn_vnic_mac);
		break;
	case MAC_NOTE_VNIC:
		/* only for clients which share a NIC with a VNIC */
		break;
	case MAC_NOTE_PROMISC:
		mutex_enter(&vnic_mac_lock);
		vnic->vn_vnic_mac->va_txinfo = mac_vnic_tx_get(
		    vnic->vn_vnic_mac->va_mh);
		mutex_exit(&vnic_mac_lock);
		break;
	}

	return (MH_WALK_CONTINUE);
}

static void
vnic_notify_cb(void *arg, mac_notify_type_t type)
{
	vnic_mac_t *vnic = arg;
	vnic_notify_state_t state;

	state.vo_type = type;
	state.vo_vnic_mac = vnic;

	rw_enter(&vnic_lock, RW_READER);
	mod_hash_walk(vnic_hash, vnic_notify_walker, &state);
	rw_exit(&vnic_lock);
}

static int
vnic_modify_mac_addr(vnic_t *vnic, uint_t mac_len, uchar_t *mac_addr)
{
	vnic_mac_t *vnic_mac = vnic->vn_vnic_mac;
	vnic_flow_t *vnic_flow = vnic->vn_flow_ent;

	ASSERT(RW_WRITE_HELD(&vnic_lock));

	if (mac_len != vnic_mac->va_addr_len)
		return (EINVAL);

	vnic_classifier_flow_update_addr(vnic_flow, mac_addr);
	return (0);
}

static int
vnic_promisc_set(vnic_t *vnic, boolean_t on)
{
	vnic_mac_t *vnic_mac = vnic->vn_vnic_mac;
	int r = -1;

	if (vnic->vn_promisc == on)
		return (0);

	if (on) {
		if ((r = mac_promisc_set(vnic_mac->va_mh, B_TRUE,
		    MAC_DEVPROMISC)) != 0) {
			return (r);
		}

		rw_enter(&vnic_mac->va_promisc_lock, RW_WRITER);
		vnic->vn_promisc_next = vnic_mac->va_promisc;
		vnic_mac->va_promisc = vnic;
		vnic_mac->va_promisc_gen++;

		vnic->vn_promisc = B_TRUE;
		rw_exit(&vnic_mac->va_promisc_lock);

		return (0);
	} else {
		vnic_t *loop, *prev = NULL;

		rw_enter(&vnic_mac->va_promisc_lock, RW_WRITER);
		loop = vnic_mac->va_promisc;

		while ((loop != NULL) && (loop != vnic)) {
			prev = loop;
			loop = loop->vn_promisc_next;
		}

		if ((loop != NULL) &&
		    ((r = mac_promisc_set(vnic_mac->va_mh, B_FALSE,
		    MAC_DEVPROMISC)) == 0)) {
			if (prev != NULL)
				prev->vn_promisc_next = loop->vn_promisc_next;
			else
				vnic_mac->va_promisc = loop->vn_promisc_next;
			vnic_mac->va_promisc_gen++;

			vnic->vn_promisc = B_FALSE;
		}
		rw_exit(&vnic_mac->va_promisc_lock);

		return (r);
	}
}

void
vnic_promisc_rx(vnic_mac_t *vnic_mac, vnic_t *sender, mblk_t *mp)
{
	vnic_t *loop;
	vnic_flow_t *flow;
	const vnic_flow_fn_info_t *fn_info;
	mac_header_info_t hdr_info;
	boolean_t dst_must_match = B_TRUE;

	ASSERT(mp->b_next == NULL);

	rw_enter(&vnic_mac->va_promisc_lock, RW_READER);
	if (vnic_mac->va_promisc == NULL)
		goto done;

	if (mac_header_info(vnic_mac->va_mh, mp, &hdr_info) != 0)
		goto done;

	/*
	 * If this is broadcast or multicast then the destination
	 * address need not match for us to deliver it.
	 */
	if ((hdr_info.mhi_dsttype == MAC_ADDRTYPE_BROADCAST) ||
	    (hdr_info.mhi_dsttype == MAC_ADDRTYPE_MULTICAST))
		dst_must_match = B_FALSE;

	for (loop = vnic_mac->va_promisc;
	    loop != NULL;
	    loop = loop->vn_promisc_next) {
		if (loop == sender)
			continue;

		if (dst_must_match &&
		    (bcmp(hdr_info.mhi_daddr, loop->vn_addr,
		    sizeof (loop->vn_addr)) != 0))
			continue;

		flow = loop->vn_flow_ent;
		ASSERT(flow != NULL);

		if (!flow->vf_is_active) {
			mblk_t *copy;
			uint64_t gen;

			if ((copy = vnic_copymsg_cksum(mp)) == NULL)
				break;
			if ((sender != NULL) &&
			    ((copy = vnic_fix_cksum(copy)) == NULL))
				break;

			VNIC_FLOW_REFHOLD(flow);
			gen = vnic_mac->va_promisc_gen;
			rw_exit(&vnic_mac->va_promisc_lock);

			fn_info = vnic_classifier_get_fn_info(flow);
			(fn_info->ff_fn)(fn_info->ff_arg1,
			    fn_info->ff_arg2, copy);

			VNIC_FLOW_REFRELE(flow);
			rw_enter(&vnic_mac->va_promisc_lock, RW_READER);
			if (vnic_mac->va_promisc_gen != gen)
				break;
		}
	}
done:
	rw_exit(&vnic_mac->va_promisc_lock);
}
