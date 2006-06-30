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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Data-Link Services Module
 */

#include	<sys/types.h>
#include	<sys/stream.h>
#include	<sys/strsun.h>
#include	<sys/strsubr.h>
#include	<sys/sysmacros.h>
#include	<sys/atomic.h>
#include	<sys/modhash.h>
#include	<sys/dlpi.h>
#include	<sys/ethernet.h>
#include	<sys/byteorder.h>
#include	<sys/vlan.h>
#include	<sys/mac.h>
#include	<sys/sdt.h>

#include	<sys/dls.h>
#include	<sys/dld_impl.h>
#include	<sys/dls_impl.h>

static kmem_cache_t	*i_dls_link_cachep;
static mod_hash_t	*i_dls_link_hash;
static uint_t		i_dls_link_count;
static krwlock_t	i_dls_link_lock;

#define		LINK_HASHSZ	67	/* prime */
#define		IMPL_HASHSZ	67	/* prime */

/*
 * Construct a hash key encompassing both DLSAP value and VLAN idenitifier.
 */
#define	MAKE_KEY(_sap, _vid)						\
	((mod_hash_key_t)(uintptr_t)					\
	(((_sap) << VLAN_ID_SIZE) | (_vid) & VLAN_ID_MASK))

/*
 * Extract the DLSAP value from the hash key.
 */
#define	KEY_SAP(_key)							\
	(((uint32_t)(uintptr_t)(_key)) >> VLAN_ID_SIZE)

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

	(void) sprintf(name, "dls_link_t_%p_hash", buf);
	dlp->dl_impl_hash = mod_hash_create_idhash(name, IMPL_HASHSZ,
	    mod_hash_null_valdtor);

	mutex_init(&dlp->dl_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&dlp->dl_promisc_lock, NULL, MUTEX_DEFAULT, NULL);
	rw_init(&dlp->dl_impl_lock, NULL, RW_DEFAULT, NULL);
	return (0);
}

/*ARGSUSED*/
static void
i_dls_link_destructor(void *buf, void *arg)
{
	dls_link_t	*dlp = buf;

	ASSERT(dlp->dl_ref == 0);
	ASSERT(dlp->dl_mh == NULL);
	ASSERT(dlp->dl_unknowns == 0);

	mod_hash_destroy_idhash(dlp->dl_impl_hash);
	dlp->dl_impl_hash = NULL;

	mutex_destroy(&dlp->dl_lock);
	mutex_destroy(&dlp->dl_promisc_lock);
	rw_destroy(&dlp->dl_impl_lock);
}

/*
 * Truncate the chain starting at mp such that all packets in the chain
 * have identical source and destination addresses, saps, and VLAN tags (if
 * any).  It returns a pointer to the mblk following the chain, NULL if
 * there is no further packet following the processed chain.  The countp
 * argument is set to the number of valid packets in the chain.  It is set
 * to 0 if the function encountered a problem with the first packet.
 */
static mblk_t *
i_dls_link_subchain(dls_link_t *dlp, mblk_t *mp, mac_header_info_t *mhip,
    uint16_t *vidp, uint_t *countp)
{
	mblk_t		**pp;
	mblk_t		*p;
	uint_t		npacket;
	size_t		addr_size = dlp->dl_mip->mi_addr_length;

	/*
	 * Packets should always be at least 16 bit aligned.
	 */
	ASSERT(IS_P2ALIGNED(mp->b_rptr, sizeof (uint16_t)));

	if (dls_link_header_info(dlp, mp, mhip, vidp) != 0) {
		/*
		 * Something is wrong with the initial header.  No chain is
		 * possible.
		 */
		p = mp->b_next;
		mp->b_next = NULL;
		*countp = 0;
		return (p);
	}

	/*
	 * Compare with subsequent headers until we find one that has
	 * differing header information. After checking each packet
	 * strip padding and skip over the header.
	 */
	npacket = 1;
	for (pp = &(mp->b_next); (p = *pp) != NULL; pp = &(p->b_next)) {
		mac_header_info_t cmhi;
		uint16_t cvid;

		if (dls_link_header_info(dlp, p, &cmhi, &cvid) != 0)
			break;

		/*
		 * The source, destination, sap, and vlan id must all match
		 * in a given subchain.
		 */
		if (memcmp(mhip->mhi_daddr, cmhi.mhi_daddr, addr_size) != 0 ||
		    memcmp(mhip->mhi_saddr, cmhi.mhi_saddr, addr_size) != 0 ||
		    mhip->mhi_bindsap != cmhi.mhi_bindsap) {
			break;
		}

		if (cvid != *vidp)
			break;

		DLS_STRIP_PADDING(cmhi.mhi_pktsize, p);
		p->b_rptr += cmhi.mhi_hdrsize;
		npacket++;
	}

	/*
	 * Strip padding and skip over the initial packet's header.
	 */
	DLS_STRIP_PADDING(mhip->mhi_pktsize, mp);
	mp->b_rptr += mhip->mhi_hdrsize;

	/*
	 * Break the chain at this point and return a pointer to the next
	 * sub-chain.
	 */
	*pp = NULL;
	*countp = npacket;
	return (p);
}

static void
i_dls_head_hold(dls_head_t *dhp)
{
	atomic_inc_32(&dhp->dh_ref);
}

static void
i_dls_head_rele(dls_head_t *dhp)
{
	atomic_dec_32(&dhp->dh_ref);
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

static void
i_dls_link_rx(void *arg, mac_resource_handle_t mrh, mblk_t *mp)
{
	dls_link_t			*dlp = arg;
	mod_hash_t			*hash = dlp->dl_impl_hash;
	mblk_t				*nextp;
	mac_header_info_t		mhi;
	uint16_t			vid;
	dls_head_t			*dhp;
	dls_impl_t			*dip;
	dls_impl_t			*ndip;
	mblk_t				*nmp;
	mod_hash_key_t			key;
	uint_t				npacket;
	boolean_t			accepted;
	dls_rx_t			di_rx, ndi_rx;
	void				*di_rx_arg, *ndi_rx_arg;

	/*
	 * Walk the packet chain.
	 */
	while (mp != NULL) {
		/*
		 * Wipe the accepted state.
		 */
		accepted = B_FALSE;

		/*
		 * Grab the longest sub-chain we can process as a single
		 * unit.
		 */
		nextp = i_dls_link_subchain(dlp, mp, &mhi, &vid, &npacket);

		if (npacket == 0) {
			/*
			 * The first packet had an unrecognized header.
			 * Modify npacket so that this stray can be
			 * accounted for.
			 */
			npacket = 1;
			freemsg(mp);
			goto loop;
		}

		/*
		 * Construct a hash key from the VLAN identifier and the
		 * DLSAP.
		 */
		key = MAKE_KEY(mhi.mhi_bindsap, vid);

		/*
		 * Search the has table for dls_impl_t eligible to receive
		 * a packet chain for this DLSAP/VLAN combination.
		 */
		rw_enter(&dlp->dl_impl_lock, RW_READER);
		if (mod_hash_find(hash, key, (mod_hash_val_t *)&dhp) != 0) {
			rw_exit(&dlp->dl_impl_lock);
			freemsgchain(mp);
			goto loop;
		}
		i_dls_head_hold(dhp);
		rw_exit(&dlp->dl_impl_lock);

		/*
		 * Find the first dls_impl_t that will accept the sub-chain.
		 */
		for (dip = dhp->dh_list; dip != NULL; dip = dip->di_nextp)
			if (dls_accept(dip, &mhi, &di_rx, &di_rx_arg))
				break;

		/*
		 * If we did not find any dls_impl_t willing to accept the
		 * sub-chain then throw it away.
		 */
		if (dip == NULL) {
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
			 * Find the next dls_impl_t that will accept the
			 * sub-chain.
			 */
			for (ndip = dip->di_nextp; ndip != NULL;
			    ndip = ndip->di_nextp)
				if (dls_accept(ndip, &mhi, &ndi_rx,
				    &ndi_rx_arg))
					break;

			/*
			 * If there are no more dls_impl_t that are willing
			 * to accept the sub-chain then we don't need to dup
			 * it before handing it to the current one.
			 */
			if (ndip == NULL) {
				di_rx(di_rx_arg, mrh, mp, mhi.mhi_hdrsize);

				/*
				 * Since there are no more dls_impl_t, we're
				 * done.
				 */
				break;
			}

			/*
			 * There are more dls_impl_t so dup the sub-chain.
			 */
			if ((nmp = copymsgchain(mp)) != NULL)
				di_rx(di_rx_arg, mrh, nmp, mhi.mhi_hdrsize);

			dip = ndip;
			di_rx = ndi_rx;
			di_rx_arg = ndi_rx_arg;
		}

		/*
		 * Release the hold on the dls_impl_t chain now that we have
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

		/*
		 * Move onto the next sub-chain.
		 */
		mp = nextp;
	}
}

static void
i_dls_link_rx_promisc(void *arg, mac_resource_handle_t mrh, mblk_t *mp)
{
	dls_link_t			*dlp = arg;
	mod_hash_t			*hash = dlp->dl_impl_hash;
	mblk_t				*nextp;
	mac_header_info_t		mhi;
	uint16_t			vid;
	dls_head_t			*dhp;
	dls_impl_t			*dip;
	dls_impl_t			*ndip;
	mblk_t				*nmp;
	mod_hash_key_t			key;
	uint_t				npacket;
	boolean_t			accepted;
	dls_rx_t			di_rx, ndi_rx;
	void				*di_rx_arg, *ndi_rx_arg;

	/*
	 * Walk the packet chain.
	 */
	while (mp != NULL) {
		/*
		 * Wipe the accepted state.
		 */
		accepted = B_FALSE;

		/*
		 * Grab the longest sub-chain we can process as a single
		 * unit.
		 */
		nextp = i_dls_link_subchain(dlp, mp, &mhi, &vid, &npacket);

		if (npacket == 0) {
			/*
			 * The first packet had an unrecognized header.
			 * Modify npacket so that this stray can be
			 * accounted for.
			 */
			npacket = 1;
			freemsg(mp);
			goto loop;
		}

		/*
		 * Construct a hash key from the VLAN identifier and the
		 * DLSAP that represents dls_impl_t in promiscuous mode.
		 */
		key = MAKE_KEY(DLS_SAP_PROMISC, vid);

		/*
		 * Search the has table for dls_impl_t eligible to receive
		 * a packet chain for this DLSAP/VLAN combination.
		 */
		rw_enter(&dlp->dl_impl_lock, RW_READER);
		if (mod_hash_find(hash, key, (mod_hash_val_t *)&dhp) != 0) {
			rw_exit(&dlp->dl_impl_lock);
			goto non_promisc;
		}
		i_dls_head_hold(dhp);
		rw_exit(&dlp->dl_impl_lock);

		/*
		 * Find dls_impl_t that will accept the sub-chain.
		 */
		for (dip = dhp->dh_list; dip != NULL; dip = dip->di_nextp) {
			if (!dls_accept(dip, &mhi, &di_rx, &di_rx_arg))
				continue;

			/*
			 * We have at least one acceptor.
			 */
			accepted = B_TRUE;

			/*
			 * There will normally be at least more dls_impl_t
			 * (since we've yet to check for non-promiscuous
			 * dls_impl_t) so dup the sub-chain.
			 */
			if ((nmp = copymsgchain(mp)) != NULL)
				di_rx(di_rx_arg, mrh, nmp, mhi.mhi_hdrsize);
		}

		/*
		 * Release the hold on the dls_impl_t chain now that we have
		 * finished walking it.
		 */
		i_dls_head_rele(dhp);

non_promisc:
		/*
		 * Construct a hash key from the VLAN identifier and the
		 * DLSAP.
		 */
		key = MAKE_KEY(mhi.mhi_bindsap, vid);

		/*
		 * Search the has table for dls_impl_t eligible to receive
		 * a packet chain for this DLSAP/VLAN combination.
		 */
		rw_enter(&dlp->dl_impl_lock, RW_READER);
		if (mod_hash_find(hash, key, (mod_hash_val_t *)&dhp) != 0) {
			rw_exit(&dlp->dl_impl_lock);
			freemsgchain(mp);
			goto loop;
		}
		i_dls_head_hold(dhp);
		rw_exit(&dlp->dl_impl_lock);

		/*
		 * Find the first dls_impl_t that will accept the sub-chain.
		 */
		for (dip = dhp->dh_list; dip != NULL; dip = dip->di_nextp)
			if (dls_accept(dip, &mhi, &di_rx, &di_rx_arg))
				break;

		/*
		 * If we did not find any dls_impl_t willing to accept the
		 * sub-chain then throw it away.
		 */
		if (dip == NULL) {
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
			 * Find the next dls_impl_t that will accept the
			 * sub-chain.
			 */
			for (ndip = dip->di_nextp; ndip != NULL;
			    ndip = ndip->di_nextp)
				if (dls_accept(ndip, &mhi, &ndi_rx,
				    &ndi_rx_arg))
					break;

			/*
			 * If there are no more dls_impl_t that are willing
			 * to accept the sub-chain then we don't need to dup
			 * it before handing it to the current one.
			 */
			if (ndip == NULL) {
				di_rx(di_rx_arg, mrh, mp, mhi.mhi_hdrsize);

				/*
				 * Since there are no more dls_impl_t, we're
				 * done.
				 */
				break;
			}

			/*
			 * There are more dls_impl_t so dup the sub-chain.
			 */
			if ((nmp = copymsgchain(mp)) != NULL)
				di_rx(di_rx_arg, mrh, nmp, mhi.mhi_hdrsize);

			dip = ndip;
			di_rx = ndi_rx;
			di_rx_arg = ndi_rx_arg;
		}

		/*
		 * Release the hold on the dls_impl_t chain now that we have
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

		/*
		 * Move onto the next sub-chain.
		 */
		mp = nextp;
	}
}

static void
i_dls_link_txloop(void *arg, mblk_t *mp)
{
	dls_link_t			*dlp = arg;
	mod_hash_t			*hash = dlp->dl_impl_hash;
	mblk_t				*nextp;
	mac_header_info_t		mhi;
	uint16_t			vid;
	dls_head_t			*dhp;
	dls_impl_t			*dip;
	dls_impl_t			*ndip;
	mblk_t				*nmp;
	mod_hash_key_t			key;
	uint_t				npacket;
	dls_rx_t			di_rx, ndi_rx;
	void				*di_rx_arg, *ndi_rx_arg;

	/*
	 * Walk the packet chain.
	 */
	while (mp != NULL) {
		/*
		 * Grab the longest sub-chain we can process as a single
		 * unit.
		 */
		nextp = i_dls_link_subchain(dlp, mp, &mhi, &vid, &npacket);

		if (npacket == 0) {
			freemsg(mp);
			goto loop;
		}

		/*
		 * Construct a hash key from the VLAN identifier and the
		 * DLSAP.
		 */
		key = MAKE_KEY(mhi.mhi_bindsap, vid);

		/*
		 * Search the has table for dls_impl_t eligible to receive
		 * a packet chain for this DLSAP/VLAN combination.
		 */
		rw_enter(&dlp->dl_impl_lock, RW_READER);
		if (mod_hash_find(hash, key, (mod_hash_val_t *)&dhp) != 0) {
			rw_exit(&dlp->dl_impl_lock);
			goto promisc;
		}
		i_dls_head_hold(dhp);
		rw_exit(&dlp->dl_impl_lock);

		/*
		 * Find dls_impl_t that will accept the sub-chain.
		 */
		for (dip = dhp->dh_list; dip != NULL; dip = dip->di_nextp) {
			if (!dls_accept_loopback(dip, &di_rx, &di_rx_arg))
				continue;

			/*
			 * There should be at least more dls_impl_t (since
			 * we've yet to check for dls_impl_t in promiscuous
			 * mode) so dup the sub-chain.
			 */
			if ((nmp = copymsgchain(mp)) != NULL)
				di_rx(di_rx_arg, NULL, nmp, mhi.mhi_hdrsize);
		}

		/*
		 * Release the hold on the dls_impl_t chain now that we have
		 * finished walking it.
		 */
		i_dls_head_rele(dhp);

promisc:
		/*
		 * Construct a hash key from the VLAN identifier and the
		 * DLSAP that represents dls_impl_t in promiscuous mode.
		 */
		key = MAKE_KEY(DLS_SAP_PROMISC, vid);

		/*
		 * Search the has table for dls_impl_t eligible to receive
		 * a packet chain for this DLSAP/VLAN combination.
		 */
		rw_enter(&dlp->dl_impl_lock, RW_READER);
		if (mod_hash_find(hash, key, (mod_hash_val_t *)&dhp) != 0) {
			rw_exit(&dlp->dl_impl_lock);
			freemsgchain(mp);
			goto loop;
		}
		i_dls_head_hold(dhp);
		rw_exit(&dlp->dl_impl_lock);

		/*
		 * Find the first dls_impl_t that will accept the sub-chain.
		 */
		for (dip = dhp->dh_list; dip != NULL; dip = dip->di_nextp)
			if (dls_accept_loopback(dip, &di_rx, &di_rx_arg))
				break;

		/*
		 * If we did not find any dls_impl_t willing to accept the
		 * sub-chain then throw it away.
		 */
		if (dip == NULL) {
			i_dls_head_rele(dhp);
			freemsgchain(mp);
			goto loop;
		}

		for (;;) {
			/*
			 * Find the next dls_impl_t that will accept the
			 * sub-chain.
			 */
			for (ndip = dip->di_nextp; ndip != NULL;
			    ndip = ndip->di_nextp)
				if (dls_accept_loopback(ndip, &ndi_rx,
				    &ndi_rx_arg)) {
					break;
				}

			/*
			 * If there are no more dls_impl_t that are willing
			 * to accept the sub-chain then we don't need to dup
			 * it before handing it to the current one.
			 */
			if (ndip == NULL) {
				di_rx(di_rx_arg, NULL, mp, mhi.mhi_hdrsize);

				/*
				 * Since there are no more dls_impl_t, we're
				 * done.
				 */
				break;
			}

			/*
			 * There are more dls_impl_t so dup the sub-chain.
			 */
			if ((nmp = copymsgchain(mp)) != NULL)
				di_rx(di_rx_arg, NULL, nmp, mhi.mhi_hdrsize);

			dip = ndip;
			di_rx = ndi_rx;
			di_rx_arg = ndi_rx_arg;
		}

		/*
		 * Release the hold on the dls_impl_t chain now that we have
		 * finished walking it.
		 */
		i_dls_head_rele(dhp);

loop:
		/*
		 * Move onto the next sub-chain.
		 */
		mp = nextp;
	}
}

/*ARGSUSED*/
static uint_t
i_dls_link_walk(mod_hash_key_t key, mod_hash_val_t *val, void *arg)
{
	boolean_t	*promiscp = arg;
	uint32_t	sap = KEY_SAP(key);

	if (sap == DLS_SAP_PROMISC) {
		*promiscp = B_TRUE;
		return (MH_WALK_TERMINATE);
	}

	return (MH_WALK_CONTINUE);
}

static int
i_dls_link_create(const char *name, uint_t ddi_instance, dls_link_t **dlpp)
{
	dls_link_t		*dlp;

	/*
	 * Allocate a new dls_link_t structure.
	 */
	dlp = kmem_cache_alloc(i_dls_link_cachep, KM_SLEEP);

	/*
	 * Name the dls_link_t after the MAC interface it represents.
	 */
	(void) strlcpy(dlp->dl_name, name, sizeof (dlp->dl_name));
	dlp->dl_ddi_instance = ddi_instance;

	/*
	 * Set the packet loopback function for use when the MAC is in
	 * promiscuous mode, and initialize promiscuous bookeeping fields.
	 */
	dlp->dl_txloop = i_dls_link_txloop;
	dlp->dl_npromisc = 0;
	dlp->dl_mth = NULL;

	*dlpp = dlp;
	return (0);
}

static void
i_dls_link_destroy(dls_link_t *dlp)
{
	ASSERT(dlp->dl_npromisc == 0);
	ASSERT(dlp->dl_nactive == 0);
	ASSERT(dlp->dl_mth == NULL);
	ASSERT(dlp->dl_macref == 0);
	ASSERT(dlp->dl_mh == NULL);
	ASSERT(dlp->dl_mip == NULL);
	ASSERT(dlp->dl_impl_count == 0);
	ASSERT(dlp->dl_mrh == NULL);

	/*
	 * Free the structure back to the cache.
	 */
	dlp->dl_unknowns = 0;
	kmem_cache_free(i_dls_link_cachep, dlp);
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
	rw_init(&i_dls_link_lock, NULL, RW_DEFAULT, NULL);
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
	rw_destroy(&i_dls_link_lock);
	return (0);
}

/*
 * Exported functions.
 */

int
dls_link_hold(const char *name, uint_t ddi_instance, dls_link_t **dlpp)
{
	dls_link_t		*dlp;
	int			err;

	/*
	 * Look up a dls_link_t corresponding to the given mac_handle_t
	 * in the global hash table. We need to hold i_dls_link_lock in
	 * order to atomically find and insert a dls_link_t into the
	 * hash table.
	 */
	rw_enter(&i_dls_link_lock, RW_WRITER);
	if ((err = mod_hash_find(i_dls_link_hash, (mod_hash_key_t)name,
	    (mod_hash_val_t *)&dlp)) == 0)
		goto done;

	ASSERT(err == MH_ERR_NOTFOUND);

	/*
	 * We didn't find anything so we need to create one.
	 */
	if ((err = i_dls_link_create(name, ddi_instance, &dlp)) != 0) {
		rw_exit(&i_dls_link_lock);
		return (err);
	}

	/*
	 * Insert the dls_link_t.
	 */
	err = mod_hash_insert(i_dls_link_hash, (mod_hash_key_t)name,
	    (mod_hash_val_t)dlp);
	ASSERT(err == 0);

	i_dls_link_count++;
	ASSERT(i_dls_link_count != 0);

done:
	/*
	 * Bump the reference count and hand back the reference.
	 */
	dlp->dl_ref++;
	*dlpp = dlp;
	rw_exit(&i_dls_link_lock);
	return (0);
}

void
dls_link_rele(dls_link_t *dlp)
{
	mod_hash_val_t	val;

	rw_enter(&i_dls_link_lock, RW_WRITER);

	/*
	 * Check if there are any more references.
	 */
	if (--dlp->dl_ref != 0) {
		/*
		 * There are more references so there's nothing more to do.
		 */
		goto done;
	}

	(void) mod_hash_remove(i_dls_link_hash,
	    (mod_hash_key_t)dlp->dl_name, &val);
	ASSERT(dlp == (dls_link_t *)val);

	/*
	 * Destroy the dls_link_t.
	 */
	i_dls_link_destroy(dlp);
	ASSERT(i_dls_link_count > 0);
	i_dls_link_count--;
done:
	rw_exit(&i_dls_link_lock);
}

int
dls_mac_hold(dls_link_t *dlp)
{
	int err = 0;

	mutex_enter(&dlp->dl_lock);

	ASSERT(IMPLY(dlp->dl_macref != 0, dlp->dl_mh != NULL));
	ASSERT(IMPLY(dlp->dl_macref == 0, dlp->dl_mh == NULL));

	if (dlp->dl_macref == 0) {
		/*
		 * First reference; hold open the MAC interface.
		 */
		err = mac_open(dlp->dl_name, dlp->dl_ddi_instance, &dlp->dl_mh);
		if (err != 0)
			goto done;

		dlp->dl_mip = mac_info(dlp->dl_mh);
	}

	dlp->dl_macref++;
done:
	mutex_exit(&dlp->dl_lock);
	return (err);
}

void
dls_mac_rele(dls_link_t *dlp)
{
	mutex_enter(&dlp->dl_lock);
	ASSERT(dlp->dl_mh != NULL);

	if (--dlp->dl_macref == 0) {
		mac_close(dlp->dl_mh);
		dlp->dl_mh = NULL;
		dlp->dl_mip = NULL;
	}
	mutex_exit(&dlp->dl_lock);
}

void
dls_link_add(dls_link_t *dlp, uint32_t sap, dls_impl_t *dip)
{
	dls_vlan_t	*dvp = dip->di_dvp;
	mod_hash_t	*hash = dlp->dl_impl_hash;
	mod_hash_key_t	key;
	dls_head_t	*dhp;
	dls_impl_t	*p;
	mac_rx_t	rx;
	int		err;
	boolean_t	promisc = B_FALSE;

	/*
	 * Generate a hash key based on the sap and the VLAN id.
	 */
	key = MAKE_KEY(sap, dvp->dv_id);

	/*
	 * We need dl_lock here because we want to be able to walk
	 * the hash table *and* set the mac rx func atomically. if
	 * these two operations are separate, someone else could
	 * insert/remove dls_impl_t from the hash table after we
	 * drop the hash lock and this could cause our chosen rx
	 * func to be incorrect. note that we cannot call mac_rx_add
	 * when holding the hash lock because this can cause deadlock.
	 */
	mutex_enter(&dlp->dl_lock);

	/*
	 * Search the table for a list head with this key.
	 */
	rw_enter(&dlp->dl_impl_lock, RW_WRITER);

	if ((err = mod_hash_find(hash, key, (mod_hash_val_t *)&dhp)) != 0) {
		ASSERT(err == MH_ERR_NOTFOUND);

		dhp = i_dls_head_alloc(key);
		err = mod_hash_insert(hash, key, (mod_hash_val_t)dhp);
		ASSERT(err == 0);
	}

	/*
	 * Add the dls_impl_t to the head of the list.
	 */
	ASSERT(dip->di_nextp == NULL);
	p = dhp->dh_list;
	dip->di_nextp = p;
	dhp->dh_list = dip;

	/*
	 * Save a pointer to the list head.
	 */
	dip->di_headp = dhp;
	dlp->dl_impl_count++;

	/*
	 * Walk the bound dls_impl_t to see if there are any
	 * in promiscuous 'all sap' mode.
	 */
	mod_hash_walk(hash, i_dls_link_walk, (void *)&promisc);
	rw_exit(&dlp->dl_impl_lock);

	/*
	 * If there are then we need to use a receive routine
	 * which will route packets to those dls_impl_t as well
	 * as ones bound to the  DLSAP of the packet.
	 */
	if (promisc)
		rx = i_dls_link_rx_promisc;
	else
		rx = i_dls_link_rx;

	/* Replace the existing receive function if there is one. */
	if (dlp->dl_mrh != NULL)
		mac_rx_remove(dlp->dl_mh, dlp->dl_mrh);
	dlp->dl_mrh = mac_rx_add(dlp->dl_mh, rx, (void *)dlp);
	mutex_exit(&dlp->dl_lock);
}

void
dls_link_remove(dls_link_t *dlp, dls_impl_t *dip)
{
	mod_hash_t	*hash = dlp->dl_impl_hash;
	dls_impl_t	**pp;
	dls_impl_t	*p;
	dls_head_t	*dhp;
	mac_rx_t	rx;

	/*
	 * We need dl_lock here because we want to be able to walk
	 * the hash table *and* set the mac rx func atomically. if
	 * these two operations are separate, someone else could
	 * insert/remove dls_impl_t from the hash table after we
	 * drop the hash lock and this could cause our chosen rx
	 * func to be incorrect. note that we cannot call mac_rx_add
	 * when holding the hash lock because this can cause deadlock.
	 */
	mutex_enter(&dlp->dl_lock);
	rw_enter(&dlp->dl_impl_lock, RW_WRITER);

	/*
	 * Poll the hash table entry until all references have been dropped.
	 * We need to drop all locks before sleeping because we don't want
	 * the interrupt handler to block. We set di_removing here to
	 * tell the receive callbacks not to pass up packets anymore.
	 * This is only a hint to quicken the decrease of the refcnt so
	 * the assignment need not be protected by any lock.
	 */
	dhp = dip->di_headp;
	dip->di_removing = B_TRUE;
	while (dhp->dh_ref != 0) {
		rw_exit(&dlp->dl_impl_lock);
		mutex_exit(&dlp->dl_lock);
		delay(drv_usectohz(1000));	/* 1ms delay */
		mutex_enter(&dlp->dl_lock);
		rw_enter(&dlp->dl_impl_lock, RW_WRITER);
	}

	/*
	 * Walk the list and remove the dls_impl_t.
	 */
	for (pp = &dhp->dh_list; (p = *pp) != NULL; pp = &(p->di_nextp)) {
		if (p == dip)
			break;
	}
	ASSERT(p != NULL);
	*pp = p->di_nextp;
	p->di_nextp = NULL;

	ASSERT(dlp->dl_impl_count > 0);
	dlp->dl_impl_count--;

	if (dhp->dh_list == NULL) {
		mod_hash_val_t	val = NULL;

		/*
		 * The list is empty so remove the hash table entry.
		 */
		(void) mod_hash_remove(hash, dhp->dh_key, &val);
		ASSERT(dhp == (dls_head_t *)val);
		i_dls_head_free(dhp);
	}
	dip->di_removing = B_FALSE;

	/*
	 * If there are no dls_impl_t then there's no need to register a
	 * receive function with the mac.
	 */
	if (dlp->dl_impl_count == 0) {
		rw_exit(&dlp->dl_impl_lock);
		mac_rx_remove(dlp->dl_mh, dlp->dl_mrh);
		dlp->dl_mrh = NULL;
	} else {
		boolean_t promisc = B_FALSE;

		/*
		 * Walk the bound dls_impl_t to see if there are any
		 * in promiscuous 'all sap' mode.
		 */
		mod_hash_walk(hash, i_dls_link_walk, (void *)&promisc);
		rw_exit(&dlp->dl_impl_lock);

		/*
		 * If there are then we need to use a receive routine
		 * which will route packets to those dls_impl_t as well
		 * as ones bound to the  DLSAP of the packet.
		 */
		if (promisc)
			rx = i_dls_link_rx_promisc;
		else
			rx = i_dls_link_rx;

		mac_rx_remove(dlp->dl_mh, dlp->dl_mrh);
		dlp->dl_mrh = mac_rx_add(dlp->dl_mh, rx, (void *)dlp);
	}
	mutex_exit(&dlp->dl_lock);
}

int
dls_link_header_info(dls_link_t *dlp, mblk_t *mp, mac_header_info_t *mhip,
    uint16_t *vidp)
{
	boolean_t	is_ethernet = (dlp->dl_mip->mi_media == DL_ETHER);
	int		err = 0;

	if ((err = mac_header_info(dlp->dl_mh, mp, mhip)) != 0)
		return (err);

	/*
	 * If this is a VLAN-tagged Ethernet packet, then the SAP in the
	 * mac_header_info_t as returned by mac_header_info() is VLAN_TPID.
	 * We need to grab the ethertype from the VLAN header.
	 */
	if (is_ethernet && (mhip->mhi_bindsap == VLAN_TPID)) {
		struct ether_vlan_header *evhp;
		uint16_t sap;

		evhp = (struct ether_vlan_header *)mp->b_rptr;
		sap = ntohs(evhp->ether_type);
		(void) mac_sap_verify(dlp->dl_mh, sap, &mhip->mhi_bindsap);
		mhip->mhi_hdrsize = sizeof (struct ether_vlan_header);
		if (vidp != NULL)
			*vidp = VLAN_ID(ntohs(evhp->ether_tci));
	} else if (vidp != NULL) {
		*vidp = VLAN_ID_NONE;
	}
	return (0);
}
