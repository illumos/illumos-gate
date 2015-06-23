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

/*
 * Data-Link Services Module
 */

#include	<sys/sysmacros.h>
#include	<sys/strsubr.h>
#include	<sys/strsun.h>
#include	<sys/vlan.h>
#include	<sys/dld_impl.h>
#include	<sys/sdt.h>
#include	<sys/atomic.h>

static kmem_cache_t	*i_dls_link_cachep;
mod_hash_t		*i_dls_link_hash;
static uint_t		i_dls_link_count;

#define		LINK_HASHSZ	67	/* prime */
#define		IMPL_HASHSZ	67	/* prime */

/*
 * Construct a hash key encompassing both DLSAP value and VLAN idenitifier.
 */
#define	MAKE_KEY(_sap)						\
	((mod_hash_key_t)(uintptr_t)((_sap) << VLAN_ID_SIZE))

#define	DLS_STRIP_PADDING(pktsize, p) {			\
	if (pktsize != 0) {				\
		ssize_t delta = pktsize - msgdsize(p);	\
							\
		if (delta < 0)				\
			(void) adjmsg(p, delta);	\
	}						\
}

/*
 * Private functions.
 */

/*ARGSUSED*/
static int
i_dls_link_constructor(void *buf, void *arg, int kmflag)
{
	dls_link_t	*dlp = buf;
	char		name[MAXNAMELEN];

	bzero(buf, sizeof (dls_link_t));

	(void) snprintf(name, MAXNAMELEN, "dls_link_t_%p_hash", buf);
	dlp->dl_str_hash = mod_hash_create_idhash(name, IMPL_HASHSZ,
	    mod_hash_null_valdtor);

	return (0);
}

/*ARGSUSED*/
static void
i_dls_link_destructor(void *buf, void *arg)
{
	dls_link_t	*dlp = buf;

	ASSERT(dlp->dl_ref == 0);
	ASSERT(dlp->dl_mh == NULL);
	ASSERT(dlp->dl_mah == NULL);
	ASSERT(dlp->dl_unknowns == 0);

	mod_hash_destroy_idhash(dlp->dl_str_hash);
	dlp->dl_str_hash = NULL;

}

/*
 * - Parse the mac header information of the given packet.
 * - Strip the padding and skip over the header. Note that because some
 *   DLS consumers only check the db_ref count of the first mblk, we
 *   pullup the message into a single mblk. Because the original message
 *   is freed as the result of message pulling up, mac_vlan_header_info()
 *   is called again to update the mhi_saddr and mhi_daddr pointers in the
 *   mhip. Further, the mac_vlan_header_info() function ensures that the
 *   size of the pulled message is greater than the MAC header size,
 *   therefore we can directly advance b_rptr to point at the payload.
 *
 * We choose to use a macro for performance reasons.
 */
#define	DLS_PREPARE_PKT(mh, mp, mhip, err) {				\
	mblk_t *nextp = (mp)->b_next;					\
	if (((err) = mac_vlan_header_info((mh), (mp), (mhip))) == 0) {	\
		DLS_STRIP_PADDING((mhip)->mhi_pktsize, (mp));		\
		if (MBLKL((mp)) < (mhip)->mhi_hdrsize) {		\
			mblk_t *newmp;					\
			if ((newmp = msgpullup((mp), -1)) == NULL) {	\
				(err) = EINVAL;				\
			} else {					\
				(mp)->b_next = NULL;			\
				freemsg((mp));				\
				(mp) = newmp;				\
				VERIFY(mac_vlan_header_info((mh),	\
				    (mp), (mhip)) == 0);		\
				(mp)->b_next = nextp;			\
				(mp)->b_rptr += (mhip)->mhi_hdrsize;	\
			}						\
		} else {						\
			(mp)->b_rptr += (mhip)->mhi_hdrsize;		\
		}							\
	}								\
}

/*
 * Truncate the chain starting at mp such that all packets in the chain
 * have identical source and destination addresses, saps, and tag types
 * (see below).  It returns a pointer to the mblk following the chain,
 * NULL if there is no further packet following the processed chain.
 * The countp argument is set to the number of valid packets in the chain.
 * Note that the whole MAC header (including the VLAN tag if any) in each
 * packet will be stripped.
 */
static mblk_t *
i_dls_link_subchain(dls_link_t *dlp, mblk_t *mp, const mac_header_info_t *mhip,
    uint_t *countp)
{
	mblk_t		*prevp;
	uint_t		npacket = 1;
	size_t		addr_size = dlp->dl_mip->mi_addr_length;
	uint16_t	vid = VLAN_ID(mhip->mhi_tci);
	uint16_t	pri = VLAN_PRI(mhip->mhi_tci);

	/*
	 * Compare with subsequent headers until we find one that has
	 * differing header information. After checking each packet
	 * strip padding and skip over the header.
	 */
	for (prevp = mp; (mp = mp->b_next) != NULL; prevp = mp) {
		mac_header_info_t cmhi;
		uint16_t cvid, cpri;
		int err;

		DLS_PREPARE_PKT(dlp->dl_mh, mp, &cmhi, err);
		if (err != 0)
			break;

		prevp->b_next = mp;

		/*
		 * The source, destination, sap, vlan tag must all match in
		 * a given subchain.
		 */
		if (mhip->mhi_saddr == NULL || cmhi.mhi_saddr == NULL ||
		    memcmp(mhip->mhi_daddr, cmhi.mhi_daddr, addr_size) != 0 ||
		    memcmp(mhip->mhi_saddr, cmhi.mhi_saddr, addr_size) != 0 ||
		    mhip->mhi_bindsap != cmhi.mhi_bindsap) {
			/*
			 * Note that we don't need to restore the padding.
			 */
			mp->b_rptr -= cmhi.mhi_hdrsize;
			break;
		}

		cvid = VLAN_ID(cmhi.mhi_tci);
		cpri = VLAN_PRI(cmhi.mhi_tci);

		/*
		 * There are several types of packets. Packets don't match
		 * if they are classified to different type or if they are
		 * VLAN packets but belong to different VLANs:
		 *
		 * packet type		tagged		vid		pri
		 * ---------------------------------------------------------
		 * untagged		No		zero		zero
		 * VLAN packets		Yes		non-zero	-
		 * priority tagged	Yes		zero		non-zero
		 * 0 tagged		Yes		zero		zero
		 */
		if ((mhip->mhi_istagged != cmhi.mhi_istagged) ||
		    (vid != cvid) || ((vid == VLAN_ID_NONE) &&
		    (((pri == 0) && (cpri != 0)) ||
		    ((pri != 0) && (cpri == 0))))) {
			mp->b_rptr -= cmhi.mhi_hdrsize;
			break;
		}

		npacket++;
	}

	/*
	 * Break the chain at this point and return a pointer to the next
	 * sub-chain.
	 */
	prevp->b_next = NULL;
	*countp = npacket;
	return (mp);
}

/* ARGSUSED */
static int
i_dls_head_hold(mod_hash_key_t key, mod_hash_val_t val)
{
	dls_head_t *dhp = (dls_head_t *)val;

	/*
	 * The lock order is  mod_hash's internal lock -> dh_lock as in the
	 * call to i_dls_link_rx -> mod_hash_find_cb_rval -> i_dls_head_hold
	 */
	mutex_enter(&dhp->dh_lock);
	if (dhp->dh_removing) {
		mutex_exit(&dhp->dh_lock);
		return (-1);
	}
	dhp->dh_ref++;
	mutex_exit(&dhp->dh_lock);
	return (0);
}

void
i_dls_head_rele(dls_head_t *dhp)
{
	mutex_enter(&dhp->dh_lock);
	dhp->dh_ref--;
	if (dhp->dh_ref == 0 && dhp->dh_removing != 0)
		cv_broadcast(&dhp->dh_cv);
	mutex_exit(&dhp->dh_lock);
}

static dls_head_t *
i_dls_head_alloc(mod_hash_key_t key)
{
	dls_head_t	*dhp;

	dhp = kmem_zalloc(sizeof (dls_head_t), KM_SLEEP);
	dhp->dh_key = key;
	return (dhp);
}

static void
i_dls_head_free(dls_head_t *dhp)
{
	ASSERT(dhp->dh_ref == 0);
	kmem_free(dhp, sizeof (dls_head_t));
}

/*
 * Try to send mp up to the streams of the given sap and vid. Return B_TRUE
 * if this message is sent to any streams.
 * Note that this function will copy the message chain and the original
 * mp will remain valid after this function
 */
static uint_t
i_dls_link_rx_func(dls_link_t *dlp, mac_resource_handle_t mrh,
    mac_header_info_t *mhip, mblk_t *mp, uint32_t sap,
    boolean_t (*acceptfunc)())
{
	mod_hash_t	*hash = dlp->dl_str_hash;
	mod_hash_key_t	key;
	dls_head_t	*dhp;
	dld_str_t	*dsp;
	mblk_t		*nmp;
	dls_rx_t	ds_rx;
	void		*ds_rx_arg;
	uint_t		naccepted = 0;
	int		rval;

	/*
	 * Construct a hash key from the VLAN identifier and the
	 * DLSAP that represents dld_str_t in promiscuous mode.
	 */
	key = MAKE_KEY(sap);

	/*
	 * Search the hash table for dld_str_t eligible to receive
	 * a packet chain for this DLSAP/VLAN combination. The mod hash's
	 * internal lock serializes find/insert/remove from the mod hash list.
	 * Incrementing the dh_ref (while holding the mod hash lock) ensures
	 * dls_link_remove will wait for the upcall to finish.
	 */
	if (mod_hash_find_cb_rval(hash, key, (mod_hash_val_t *)&dhp,
	    i_dls_head_hold, &rval) != 0 || (rval != 0)) {
		return (B_FALSE);
	}

	/*
	 * Find dld_str_t that will accept the sub-chain.
	 */
	for (dsp = dhp->dh_list; dsp != NULL; dsp = dsp->ds_next) {
		if (!acceptfunc(dsp, mhip, &ds_rx, &ds_rx_arg))
			continue;

		/*
		 * We have at least one acceptor.
		 */
		naccepted++;

		/*
		 * There will normally be at least more dld_str_t
		 * (since we've yet to check for non-promiscuous
		 * dld_str_t) so dup the sub-chain.
		 */
		if ((nmp = copymsgchain(mp)) != NULL)
			ds_rx(ds_rx_arg, mrh, nmp, mhip);
	}

	/*
	 * Release the hold on the dld_str_t chain now that we have
	 * finished walking it.
	 */
	i_dls_head_rele(dhp);
	return (naccepted);
}

/* ARGSUSED */
void
i_dls_link_rx(void *arg, mac_resource_handle_t mrh, mblk_t *mp,
    boolean_t loopback)
{
	dls_link_t			*dlp = arg;
	mod_hash_t			*hash = dlp->dl_str_hash;
	mblk_t				*nextp;
	mac_header_info_t		mhi;
	dls_head_t			*dhp;
	dld_str_t			*dsp;
	dld_str_t			*ndsp;
	mblk_t				*nmp;
	mod_hash_key_t			key;
	uint_t				npacket;
	boolean_t			accepted;
	dls_rx_t			ds_rx, nds_rx;
	void				*ds_rx_arg, *nds_rx_arg;
	uint16_t			vid;
	int				err, rval;

	/*
	 * Walk the packet chain.
	 */
	for (; mp != NULL; mp = nextp) {
		/*
		 * Wipe the accepted state.
		 */
		accepted = B_FALSE;

		DLS_PREPARE_PKT(dlp->dl_mh, mp, &mhi, err);
		if (err != 0) {
			atomic_inc_32(&(dlp->dl_unknowns));
			nextp = mp->b_next;
			mp->b_next = NULL;
			freemsg(mp);
			continue;
		}

		/*
		 * Grab the longest sub-chain we can process as a single
		 * unit.
		 */
		nextp = i_dls_link_subchain(dlp, mp, &mhi, &npacket);
		ASSERT(npacket != 0);

		vid = VLAN_ID(mhi.mhi_tci);

		if (mhi.mhi_istagged) {
			/*
			 * If it is tagged traffic, send it upstream to
			 * all dld_str_t which are attached to the physical
			 * link and bound to SAP 0x8100.
			 */
			if (i_dls_link_rx_func(dlp, mrh, &mhi, mp,
			    ETHERTYPE_VLAN, dls_accept) > 0) {
				accepted = B_TRUE;
			}

			/*
			 * Don't pass the packets up if they are tagged
			 * packets and:
			 *  - their VID and priority are both zero and the
			 *    original packet isn't using the PVID (invalid
			 *    packets).
			 *  - their sap is ETHERTYPE_VLAN and their VID is
			 *    zero as they have already been sent upstreams.
			 */
			if ((vid == VLAN_ID_NONE && !mhi.mhi_ispvid &&
			    VLAN_PRI(mhi.mhi_tci) == 0) ||
			    (mhi.mhi_bindsap == ETHERTYPE_VLAN &&
			    vid == VLAN_ID_NONE)) {
				freemsgchain(mp);
				goto loop;
			}
		}

		/*
		 * Construct a hash key from the VLAN identifier and the
		 * DLSAP.
		 */
		key = MAKE_KEY(mhi.mhi_bindsap);

		/*
		 * Search the has table for dld_str_t eligible to receive
		 * a packet chain for this DLSAP/VLAN combination.
		 */
		if (mod_hash_find_cb_rval(hash, key, (mod_hash_val_t *)&dhp,
		    i_dls_head_hold, &rval) != 0 || (rval != 0)) {
			freemsgchain(mp);
			goto loop;
		}

		/*
		 * Find the first dld_str_t that will accept the sub-chain.
		 */
		for (dsp = dhp->dh_list; dsp != NULL; dsp = dsp->ds_next)
			if (dls_accept(dsp, &mhi, &ds_rx, &ds_rx_arg))
				break;

		/*
		 * If we did not find any dld_str_t willing to accept the
		 * sub-chain then throw it away.
		 */
		if (dsp == NULL) {
			i_dls_head_rele(dhp);
			freemsgchain(mp);
			goto loop;
		}

		/*
		 * We have at least one acceptor.
		 */
		accepted = B_TRUE;
		for (;;) {
			/*
			 * Find the next dld_str_t that will accept the
			 * sub-chain.
			 */
			for (ndsp = dsp->ds_next; ndsp != NULL;
			    ndsp = ndsp->ds_next)
				if (dls_accept(ndsp, &mhi, &nds_rx,
				    &nds_rx_arg))
					break;

			/*
			 * If there are no more dld_str_t that are willing
			 * to accept the sub-chain then we don't need to dup
			 * it before handing it to the current one.
			 */
			if (ndsp == NULL) {
				ds_rx(ds_rx_arg, mrh, mp, &mhi);

				/*
				 * Since there are no more dld_str_t, we're
				 * done.
				 */
				break;
			}

			/*
			 * There are more dld_str_t so dup the sub-chain.
			 */
			if ((nmp = copymsgchain(mp)) != NULL)
				ds_rx(ds_rx_arg, mrh, nmp, &mhi);

			dsp = ndsp;
			ds_rx = nds_rx;
			ds_rx_arg = nds_rx_arg;
		}

		/*
		 * Release the hold on the dld_str_t chain now that we have
		 * finished walking it.
		 */
		i_dls_head_rele(dhp);

loop:
		/*
		 * If there were no acceptors then add the packet count to the
		 * 'unknown' count.
		 */
		if (!accepted)
			atomic_add_32(&(dlp->dl_unknowns), npacket);
	}
}

/* ARGSUSED */
void
dls_rx_vlan_promisc(void *arg, mac_resource_handle_t mrh, mblk_t *mp,
    boolean_t loopback)
{
	dld_str_t			*dsp = arg;
	dls_link_t			*dlp = dsp->ds_dlp;
	mac_header_info_t		mhi;
	dls_rx_t			ds_rx;
	void				*ds_rx_arg;
	int				err;

	DLS_PREPARE_PKT(dlp->dl_mh, mp, &mhi, err);
	if (err != 0)
		goto drop;

	/*
	 * If there is promiscuous handle for vlan, we filter out the untagged
	 * pkts and pkts that are not for the primary unicast address.
	 */
	if (dsp->ds_vlan_mph != NULL) {
		uint8_t prim_addr[MAXMACADDRLEN];
		size_t	addr_length = dsp->ds_mip->mi_addr_length;

		if (!(mhi.mhi_istagged))
			goto drop;
		ASSERT(dsp->ds_mh != NULL);
		mac_unicast_primary_get(dsp->ds_mh, (uint8_t *)prim_addr);
		if (memcmp(mhi.mhi_daddr, prim_addr, addr_length) != 0)
			goto drop;

		if (!dls_accept(dsp, &mhi, &ds_rx, &ds_rx_arg))
			goto drop;

		ds_rx(ds_rx_arg, NULL, mp, &mhi);
		return;
	}

drop:
	atomic_inc_32(&dlp->dl_unknowns);
	freemsg(mp);
}

/* ARGSUSED */
void
dls_rx_promisc(void *arg, mac_resource_handle_t mrh, mblk_t *mp,
    boolean_t loopback)
{
	dld_str_t			*dsp = arg;
	dls_link_t			*dlp = dsp->ds_dlp;
	mac_header_info_t		mhi;
	dls_rx_t			ds_rx;
	void				*ds_rx_arg;
	int				err;
	dls_head_t			*dhp;
	mod_hash_key_t			key;

	DLS_PREPARE_PKT(dlp->dl_mh, mp, &mhi, err);
	if (err != 0)
		goto drop;

	/*
	 * In order to filter out sap pkt that no dls channel listens, search
	 * the hash table trying to find a dld_str_t eligible to receive the pkt
	 */
	if ((dsp->ds_promisc & DLS_PROMISC_SAP) == 0) {
		key = MAKE_KEY(mhi.mhi_bindsap);
		if (mod_hash_find(dsp->ds_dlp->dl_str_hash, key,
		    (mod_hash_val_t *)&dhp) != 0)
			goto drop;
	}

	if (!dls_accept_promisc(dsp, &mhi, &ds_rx, &ds_rx_arg, loopback))
		goto drop;

	ds_rx(ds_rx_arg, NULL, mp, &mhi);
	return;

drop:
	atomic_inc_32(&dlp->dl_unknowns);
	freemsg(mp);
}

static void
i_dls_link_destroy(dls_link_t *dlp)
{
	ASSERT(dlp->dl_nactive == 0);
	ASSERT(dlp->dl_impl_count == 0);
	ASSERT(dlp->dl_zone_ref == 0);

	/*
	 * Free the structure back to the cache.
	 */
	if (dlp->dl_mch != NULL)
		mac_client_close(dlp->dl_mch, 0);

	if (dlp->dl_mh != NULL) {
		ASSERT(MAC_PERIM_HELD(dlp->dl_mh));
		mac_close(dlp->dl_mh);
	}

	dlp->dl_mh = NULL;
	dlp->dl_mch = NULL;
	dlp->dl_mip = NULL;
	dlp->dl_unknowns = 0;
	dlp->dl_nonip_cnt = 0;
	kmem_cache_free(i_dls_link_cachep, dlp);
}

static int
i_dls_link_create(const char *name, dls_link_t **dlpp)
{
	dls_link_t		*dlp;
	int			err;

	/*
	 * Allocate a new dls_link_t structure.
	 */
	dlp = kmem_cache_alloc(i_dls_link_cachep, KM_SLEEP);

	/*
	 * Name the dls_link_t after the MAC interface it represents.
	 */
	(void) strlcpy(dlp->dl_name, name, sizeof (dlp->dl_name));

	/*
	 * First reference; hold open the MAC interface.
	 */
	ASSERT(dlp->dl_mh == NULL);
	err = mac_open(dlp->dl_name, &dlp->dl_mh);
	if (err != 0)
		goto bail;

	ASSERT(MAC_PERIM_HELD(dlp->dl_mh));
	dlp->dl_mip = mac_info(dlp->dl_mh);

	/* DLS is the "primary" MAC client */
	ASSERT(dlp->dl_mch == NULL);

	err = mac_client_open(dlp->dl_mh, &dlp->dl_mch, NULL,
	    MAC_OPEN_FLAGS_USE_DATALINK_NAME);
	if (err != 0)
		goto bail;

	DTRACE_PROBE2(dls__primary__client, char *, dlp->dl_name, void *,
	    dlp->dl_mch);

	*dlpp = dlp;
	return (0);

bail:
	i_dls_link_destroy(dlp);
	return (err);
}

/*
 * Module initialization functions.
 */

void
dls_link_init(void)
{
	/*
	 * Create a kmem_cache of dls_link_t structures.
	 */
	i_dls_link_cachep = kmem_cache_create("dls_link_cache",
	    sizeof (dls_link_t), 0, i_dls_link_constructor,
	    i_dls_link_destructor, NULL, NULL, NULL, 0);
	ASSERT(i_dls_link_cachep != NULL);

	/*
	 * Create a dls_link_t hash table and associated lock.
	 */
	i_dls_link_hash = mod_hash_create_extended("dls_link_hash",
	    IMPL_HASHSZ, mod_hash_null_keydtor, mod_hash_null_valdtor,
	    mod_hash_bystr, NULL, mod_hash_strkey_cmp, KM_SLEEP);
	i_dls_link_count = 0;
}

int
dls_link_fini(void)
{
	if (i_dls_link_count > 0)
		return (EBUSY);

	/*
	 * Destroy the kmem_cache.
	 */
	kmem_cache_destroy(i_dls_link_cachep);

	/*
	 * Destroy the hash table and associated lock.
	 */
	mod_hash_destroy_hash(i_dls_link_hash);
	return (0);
}

/*
 * Exported functions.
 */

static int
dls_link_hold_common(const char *name, dls_link_t **dlpp, boolean_t create)
{
	dls_link_t		*dlp;
	int			err;

	/*
	 * Look up a dls_link_t corresponding to the given macname in the
	 * global hash table. The i_dls_link_hash itself is protected by the
	 * mod_hash package's internal lock which synchronizes
	 * find/insert/remove into the global mod_hash list. Assumes that
	 * inserts and removes are single threaded on a per mac end point
	 * by the mac perimeter.
	 */
	if ((err = mod_hash_find(i_dls_link_hash, (mod_hash_key_t)name,
	    (mod_hash_val_t *)&dlp)) == 0)
		goto done;

	ASSERT(err == MH_ERR_NOTFOUND);
	if (!create)
		return (ENOENT);

	/*
	 * We didn't find anything so we need to create one.
	 */
	if ((err = i_dls_link_create(name, &dlp)) != 0)
		return (err);

	/*
	 * Insert the dls_link_t.
	 */
	err = mod_hash_insert(i_dls_link_hash, (mod_hash_key_t)dlp->dl_name,
	    (mod_hash_val_t)dlp);
	ASSERT(err == 0);

	atomic_inc_32(&i_dls_link_count);
	ASSERT(i_dls_link_count != 0);

done:
	ASSERT(MAC_PERIM_HELD(dlp->dl_mh));
	/*
	 * Bump the reference count and hand back the reference.
	 */
	dlp->dl_ref++;
	*dlpp = dlp;
	return (0);
}

int
dls_link_hold_create(const char *name, dls_link_t **dlpp)
{
	return (dls_link_hold_common(name, dlpp, B_TRUE));
}

int
dls_link_hold(const char *name, dls_link_t **dlpp)
{
	return (dls_link_hold_common(name, dlpp, B_FALSE));
}

dev_info_t *
dls_link_devinfo(dev_t dev)
{
	dls_link_t	*dlp;
	dev_info_t	*dip;
	char	macname[MAXNAMELEN];
	char	*drv;
	mac_perim_handle_t	mph;

	if ((drv = ddi_major_to_name(getmajor(dev))) == NULL)
		return (NULL);
	(void) snprintf(macname, MAXNAMELEN, "%s%d", drv,
	    DLS_MINOR2INST(getminor(dev)));

	/*
	 * The code below assumes that the name constructed above is the
	 * macname. This is not the case for legacy devices. Currently this
	 * is ok because this function is only called in the getinfo(9e) path,
	 * which for a legacy device would directly end up in the driver's
	 * getinfo, rather than here
	 */
	if (mac_perim_enter_by_macname(macname, &mph) != 0)
		return (NULL);

	if (dls_link_hold(macname, &dlp) != 0) {
		mac_perim_exit(mph);
		return (NULL);
	}

	dip = mac_devinfo_get(dlp->dl_mh);
	dls_link_rele(dlp);
	mac_perim_exit(mph);

	return (dip);
}

dev_t
dls_link_dev(dls_link_t *dlp)
{
	return (makedevice(ddi_driver_major(mac_devinfo_get(dlp->dl_mh)),
	    mac_minor(dlp->dl_mh)));
}

void
dls_link_rele(dls_link_t *dlp)
{
	mod_hash_val_t	val;

	ASSERT(MAC_PERIM_HELD(dlp->dl_mh));
	/*
	 * Check if there are any more references.
	 */
	if (--dlp->dl_ref == 0) {
		(void) mod_hash_remove(i_dls_link_hash,
		    (mod_hash_key_t)dlp->dl_name, &val);
		ASSERT(dlp == (dls_link_t *)val);

		/*
		 * Destroy the dls_link_t.
		 */
		i_dls_link_destroy(dlp);
		ASSERT(i_dls_link_count > 0);
		atomic_dec_32(&i_dls_link_count);
	}
}

int
dls_link_rele_by_name(const char *name)
{
	dls_link_t		*dlp;

	if (mod_hash_find(i_dls_link_hash, (mod_hash_key_t)name,
	    (mod_hash_val_t *)&dlp) != 0)
		return (ENOENT);

	ASSERT(MAC_PERIM_HELD(dlp->dl_mh));

	/*
	 * Must fail detach if mac client is busy.
	 */
	ASSERT(dlp->dl_ref > 0 && dlp->dl_mch != NULL);
	if (mac_link_has_flows(dlp->dl_mch))
		return (ENOTEMPTY);

	dls_link_rele(dlp);
	return (0);
}

int
dls_link_setzid(const char *name, zoneid_t zid)
{
	dls_link_t	*dlp;
	int		err = 0;
	zoneid_t	old_zid;

	if ((err = dls_link_hold_create(name, &dlp)) != 0)
		return (err);

	ASSERT(MAC_PERIM_HELD(dlp->dl_mh));

	if ((old_zid = dlp->dl_zid) == zid)
		goto done;

	/*
	 * Check whether this dlp is used by its own zone.  If yes, we cannot
	 * change its zoneid.
	 */
	if (dlp->dl_zone_ref != 0) {
		err = EBUSY;
		goto done;
	}

	dlp->dl_zid = zid;

	if (zid == GLOBAL_ZONEID) {
		/*
		 * The link is moving from a non-global zone to the global
		 * zone, so we need to release the reference that was held
		 * when the link was originally assigned to the non-global
		 * zone.
		 */
		dls_link_rele(dlp);
	}

done:
	/*
	 * We only keep the reference to this link open if the link has
	 * successfully moved from the global zone to a non-global zone.
	 */
	if (err != 0 || old_zid != GLOBAL_ZONEID)
		dls_link_rele(dlp);
	return (err);
}

int
dls_link_getzid(const char *name, zoneid_t *zidp)
{
	dls_link_t	*dlp;
	int		err = 0;

	if ((err = dls_link_hold(name, &dlp)) != 0)
		return (err);

	ASSERT(MAC_PERIM_HELD(dlp->dl_mh));

	*zidp = dlp->dl_zid;

	dls_link_rele(dlp);
	return (0);
}

void
dls_link_add(dls_link_t *dlp, uint32_t sap, dld_str_t *dsp)
{
	mod_hash_t	*hash = dlp->dl_str_hash;
	mod_hash_key_t	key;
	dls_head_t	*dhp;
	dld_str_t	*p;
	int		err;

	ASSERT(MAC_PERIM_HELD(dlp->dl_mh));

	/*
	 * Generate a hash key based on the sap.
	 */
	key = MAKE_KEY(sap);

	/*
	 * Search the table for a list head with this key.
	 */
	if ((err = mod_hash_find(hash, key, (mod_hash_val_t *)&dhp)) != 0) {
		ASSERT(err == MH_ERR_NOTFOUND);

		dhp = i_dls_head_alloc(key);
		err = mod_hash_insert(hash, key, (mod_hash_val_t)dhp);
		ASSERT(err == 0);
	}

	/*
	 * Add the dld_str_t to the head of the list. List walkers in
	 * i_dls_link_rx_* bump up dh_ref to ensure the list does not change
	 * while they walk the list. The membar below ensures that list walkers
	 * see exactly the old list or the new list.
	 */
	ASSERT(dsp->ds_next == NULL);
	p = dhp->dh_list;
	dsp->ds_next = p;

	membar_producer();

	dhp->dh_list = dsp;

	/*
	 * Save a pointer to the list head.
	 */
	dsp->ds_head = dhp;
	dlp->dl_impl_count++;
}

void
dls_link_remove(dls_link_t *dlp, dld_str_t *dsp)
{
	mod_hash_t	*hash = dlp->dl_str_hash;
	dld_str_t	**pp;
	dld_str_t	*p;
	dls_head_t	*dhp;

	ASSERT(MAC_PERIM_HELD(dlp->dl_mh));

	/*
	 * We set dh_removing here to tell the receive callbacks not to pass
	 * up packets anymore. Then wait till the current callbacks are done.
	 * This happens either in the close path or in processing the
	 * DL_UNBIND_REQ via a taskq thread, and it is ok to cv_wait in either.
	 * The dh_ref ensures there aren't and there won't be any upcalls
	 * walking or using the dh_list. The mod hash internal lock ensures
	 * that the insert/remove of the dls_head_t itself synchronizes with
	 * any i_dls_link_rx trying to locate it. The perimeter ensures that
	 * there isn't another simultaneous dls_link_add/remove.
	 */
	dhp = dsp->ds_head;

	mutex_enter(&dhp->dh_lock);
	dhp->dh_removing = B_TRUE;
	while (dhp->dh_ref != 0)
		cv_wait(&dhp->dh_cv, &dhp->dh_lock);
	mutex_exit(&dhp->dh_lock);

	/*
	 * Walk the list and remove the dld_str_t.
	 */
	for (pp = &dhp->dh_list; (p = *pp) != NULL; pp = &(p->ds_next)) {
		if (p == dsp)
			break;
	}
	ASSERT(p != NULL);
	*pp = p->ds_next;
	p->ds_next = NULL;
	p->ds_head = NULL;

	ASSERT(dlp->dl_impl_count != 0);
	dlp->dl_impl_count--;

	if (dhp->dh_list == NULL) {
		mod_hash_val_t	val = NULL;

		/*
		 * The list is empty so remove the hash table entry.
		 */
		(void) mod_hash_remove(hash, dhp->dh_key, &val);
		ASSERT(dhp == (dls_head_t *)val);
		i_dls_head_free(dhp);
	} else {
		mutex_enter(&dhp->dh_lock);
		dhp->dh_removing = B_FALSE;
		mutex_exit(&dhp->dh_lock);
	}
}
