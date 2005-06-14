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
 * Data-Link Services Module
 */

#include	<sys/types.h>
#include	<sys/stream.h>
#include	<sys/strsun.h>
#include	<sys/strsubr.h>
#include	<sys/sysmacros.h>
#include	<sys/atomic.h>
#include	<sys/ght.h>
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
static ght_t		i_dls_link_hash;

#define		LINK_HASHSZ	67	/* prime */
#define		IMPL_HASHSZ	67	/* prime */

/*
 * Construct a hash key encompassing both DLSAP value and VLAN idenitifier.
 */
#define	MAKE_KEY(_sap, _vid)						\
	GHT_SCALAR_TO_KEY(((_sap) << VLAN_ID_SIZE) | (_vid) & VLAN_ID_MASK)

/*
 * Extract the DLSAP value from the hash key.
 */
#define	KEY_SAP(_key)							\
	(((uint32_t)(uintptr_t)(_key)) >> VLAN_ID_SIZE)

/*
 * Private functions.
 */

/*ARGSUSED*/
static int
i_dls_link_constructor(void *buf, void *arg, int kmflag)
{
	dls_link_t	*dlp = buf;
	char		name[MAXNAMELEN];
	int		err;

	bzero(buf, sizeof (dls_link_t));

	(void) sprintf(name, "dls_link_t_%p_impl_hash", buf);
	err = ght_scalar_create(name, IMPL_HASHSZ, &(dlp->dl_impl_hash));
	ASSERT(err == 0);

	mutex_init(&dlp->dl_lock, NULL, MUTEX_DEFAULT, NULL);
	return (0);
}

/*ARGSUSED*/
static void
i_dls_link_destructor(void *buf, void *arg)
{
	dls_link_t	*dlp = buf;
	int		err;

	ASSERT(dlp->dl_ref == 0);
	ASSERT(dlp->dl_hte == NULL);
	ASSERT(dlp->dl_mh == NULL);
	ASSERT(dlp->dl_unknowns == 0);

	err = ght_destroy(dlp->dl_impl_hash);
	ASSERT(err == 0);

	mutex_destroy(&dlp->dl_lock);
}

#define	ETHER_MATCH(_pkt_a, _pkt_b)					\
	((((uint16_t *)(_pkt_a))[0] == ((uint16_t *)(_pkt_b))[0]) &&	\
	(((uint16_t *)(_pkt_a))[1] == ((uint16_t *)(_pkt_b))[1]) &&	\
	(((uint16_t *)(_pkt_a))[2] == ((uint16_t *)(_pkt_b))[2]) &&	\
	(((uint16_t *)(_pkt_a))[6] == ((uint16_t *)(_pkt_b))[6]))

#define	ETHER_VLAN_MATCH(_pkt_a, _pkt_b)				\
	((((uint16_t *)(_pkt_a))[0] == ((uint16_t *)(_pkt_b))[0]) &&	\
	(((uint16_t *)(_pkt_a))[1] == ((uint16_t *)(_pkt_b))[1]) &&	\
	(((uint16_t *)(_pkt_a))[2] == ((uint16_t *)(_pkt_b))[2]) &&	\
	(((uint16_t *)(_pkt_a))[6] == ((uint16_t *)(_pkt_b))[6]) &&	\
	(((uint16_t *)(_pkt_a))[7] == ((uint16_t *)(_pkt_b))[7]) &&	\
	(((uint16_t *)(_pkt_a))[8] == ((uint16_t *)(_pkt_b))[8]))

static mblk_t *
i_dls_link_ether_subchain(mblk_t *mp, uint_t *header_lengthp,
    uint8_t **daddrp, uint16_t *type_lengthp, uint16_t *vidp,
    uint_t *countp)
{
	struct ether_header		*ehp;
	struct ether_vlan_header	*evhp;
	mblk_t				**pp;
	mblk_t				*p;
	uint_t				npacket;

	/*
	 * Packets should always be at least 16 bit aligned.
	 */
	ASSERT(IS_P2ALIGNED(mp->b_rptr, sizeof (uint16_t)));

	/*
	 * Determine whether this is a VLAN or non-VLAN packet.
	 */
	ASSERT(MBLKL(mp) >= sizeof (struct ether_header));
	ehp = (struct ether_header *)mp->b_rptr;
	if ((*type_lengthp = ntohs(ehp->ether_type)) == VLAN_TPID)
		goto vlan;

	/*
	 * It is a non-VLAN header.
	 */
	*header_lengthp = sizeof (struct ether_header);

	/*
	 * Parse the rest of the header information that we need.
	 */
	*daddrp = (uint8_t *)&(ehp->ether_dhost);
	*vidp = VLAN_ID_NONE;

	/*
	 * Compare with subsequent headers until we find one that has
	 * differing header information. After checking each packet skip over
	 * the header.
	 */
	npacket = 1;
	for (pp = &(mp->b_next); (p = *pp) != NULL; pp = &(p->b_next)) {
		if (!ETHER_MATCH(p->b_rptr, mp->b_rptr) != 0)
			break;
		p->b_rptr += sizeof (struct ether_header);
		npacket++;
	}

	/*
	 * Skip over the initial packet's header.
	 */
	mp->b_rptr += sizeof (struct ether_header);
	goto done;

vlan:
	/*
	 * It is a VLAN header.
	 */
	evhp = (struct ether_vlan_header *)mp->b_rptr;
	*header_lengthp = sizeof (struct ether_vlan_header);

	/*
	 * Parse the header information.
	 */
	*daddrp = (uint8_t *)&(evhp->ether_dhost);
	*vidp = VLAN_ID(ntohs(evhp->ether_tci));
	*type_lengthp = ntohs(evhp->ether_type);

	/*
	 * Compare with subsequent headers until we find one that has
	 * differing header information. After checking each packet skip over
	 * the header.
	 */
	npacket = 1;
	for (pp = &(mp->b_next); (p = *pp) != NULL; pp = &(p->b_next)) {
		if (!ETHER_VLAN_MATCH(p->b_rptr, mp->b_rptr) != 0)
			break;
		p->b_rptr += sizeof (struct ether_vlan_header);
		npacket++;
	}

	/*
	 * Skip over the initial packet's header.
	 */
	mp->b_rptr += sizeof (struct ether_vlan_header);

done:
	/*
	 * Break the chain at this point and return a pointer to the next
	 * sub-chain.
	 */
	*pp = NULL;
	*countp = npacket;
	return (p);
}

static void
i_dls_link_ether_rx(void *arg, mac_resource_handle_t mrh, mblk_t *mp)
{
	dls_link_t			*dlp = arg;
	ght_t				hash = dlp->dl_impl_hash;
	mblk_t				*nextp;
	uint_t				header_length;
	uint8_t				*daddr;
	uint16_t			type_length;
	uint16_t			vid;
	uint16_t			sap;
	ghte_t				hte;
	dls_impl_t			*dip;
	dls_impl_t			*ndip;
	mblk_t				*nmp;
	ght_key_t			key;
	uint_t				npacket;
	boolean_t			accepted;

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
		nextp = i_dls_link_ether_subchain(mp, &header_length, &daddr,
		    &type_length, &vid, &npacket);

		/*
		 * Calculate the DLSAP: LLC (0) if the type/length field is
		 * interpreted as a length, otherwise it is the value of the
		 * type/length field.
		 */
		sap = (type_length <= ETHERMTU) ? DLS_SAP_LLC : type_length;

		/*
		 * Construct a hash key from the VLAN identifier and the
		 * DLSAP.
		 */
		key = MAKE_KEY(sap, vid);

		/*
		 * Search the has table for dls_impl_t eligible to receive
		 * a packet chain for this DLSAP/VLAN combination.
		 */
		ght_lock(hash, GHT_READ);
		if (ght_find(hash, key, &hte) != 0) {
			ght_unlock(hash);
			freemsgchain(mp);
			goto loop;
		}

		/*
		 * Place a hold the chain of dls_impl_t to make sure none are
		 * removed from under our feet.
		 */
		ght_hold(hte);
		ght_unlock(hash);

		/*
		 * Find the first dls_impl_t that will accept the sub-chain.
		 */
		for (dip = (dls_impl_t *)GHT_VAL(hte); dip != NULL;
		    dip = dip->di_nextp)
			if (dls_accept(dip, daddr))
				break;

		/*
		 * If we did not find any dls_impl_t willing to accept the
		 * sub-chain then throw it away.
		 */
		if (dip == NULL) {
			ght_rele(hte);
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
				if (dls_accept(ndip, daddr))
					break;

			/*
			 * If there are no more dls_impl_t that are willing
			 * to accept the sub-chain then we don't need to dup
			 * it before handing it to the current one.
			 */
			if (ndip == NULL) {
				dip->di_rx(dip->di_rx_arg, mrh, mp,
				    header_length);

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
				dip->di_rx(dip->di_rx_arg, mrh, nmp,
				    header_length);

			dip = ndip;
		}

		/*
		 * Release the hold on the dls_impl_t chain now that we have
		 * finished walking it.
		 */
		ght_rele(hte);

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
i_dls_link_ether_rx_promisc(void *arg, mac_resource_handle_t mrh,
    mblk_t *mp)
{
	dls_link_t			*dlp = arg;
	ght_t				hash = dlp->dl_impl_hash;
	mblk_t				*nextp;
	uint_t				header_length;
	uint8_t				*daddr;
	uint16_t			type_length;
	uint16_t			vid;
	uint16_t			sap;
	ghte_t				hte;
	dls_impl_t			*dip;
	dls_impl_t			*ndip;
	mblk_t				*nmp;
	ght_key_t			key;
	uint_t				npacket;
	boolean_t			accepted;

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
		nextp = i_dls_link_ether_subchain(mp, &header_length, &daddr,
		    &type_length, &vid, &npacket);

		/*
		 * Construct a hash key from the VLAN identifier and the
		 * DLSAP that represents dls_impl_t in promiscuous mode.
		 */
		key = MAKE_KEY(DLS_SAP_PROMISC, vid);

		/*
		 * Search the has table for dls_impl_t eligible to receive
		 * a packet chain for this DLSAP/VLAN combination.
		 */
		ght_lock(hash, GHT_READ);
		if (ght_find(hash, key, &hte) != 0) {
			ght_unlock(hash);
			goto non_promisc;
		}

		/*
		 * Place a hold the chain of dls_impl_t to make sure none are
		 * removed from under our feet.
		 */
		ght_hold(hte);
		ght_unlock(hash);

		/*
		 * Find dls_impl_t that will accept the sub-chain.
		 */
		for (dip = (dls_impl_t *)GHT_VAL(hte); dip != NULL;
		    dip = dip->di_nextp) {
			if (!dls_accept(dip, daddr))
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
				dip->di_rx(dip->di_rx_arg, mrh, nmp,
				    header_length);
		}

		/*
		 * Release the hold on the dls_impl_t chain now that we have
		 * finished walking it.
		 */
		ght_rele(hte);

non_promisc:
		/*
		 * Calculate the DLSAP: LLC (0) if the type/length field is
		 * interpreted as a length, otherwise it is the value of the
		 * type/length field.
		 */
		sap = (type_length <= ETHERMTU) ? DLS_SAP_LLC : type_length;

		/*
		 * Construct a hash key from the VLAN identifier and the
		 * DLSAP.
		 */
		key = MAKE_KEY(sap, vid);

		/*
		 * Search the has table for dls_impl_t eligible to receive
		 * a packet chain for this DLSAP/VLAN combination.
		 */
		ght_lock(hash, GHT_READ);
		if (ght_find(hash, key, &hte) != 0) {
			ght_unlock(hash);
			freemsgchain(mp);
			goto loop;
		}

		/*
		 * Place a hold the chain of dls_impl_t to make sure none are
		 * removed from under our feet.
		 */
		ght_hold(hte);
		ght_unlock(hash);

		/*
		 * Find the first dls_impl_t that will accept the sub-chain.
		 */
		for (dip = (dls_impl_t *)GHT_VAL(hte); dip != NULL;
		    dip = dip->di_nextp)
			if (dls_accept(dip, daddr))
				break;

		/*
		 * If we did not find any dls_impl_t willing to accept the
		 * sub-chain then throw it away.
		 */
		if (dip == NULL) {
			ght_rele(hte);
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
				if (dls_accept(ndip, daddr))
					break;

			/*
			 * If there are no more dls_impl_t that are willing
			 * to accept the sub-chain then we don't need to dup
			 * it before handing it to the current one.
			 */
			if (ndip == NULL) {
				dip->di_rx(dip->di_rx_arg, mrh, mp,
				    header_length);

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
				dip->di_rx(dip->di_rx_arg, mrh, nmp,
				    header_length);

			dip = ndip;
		}

		/*
		 * Release the hold on the dls_impl_t chain now that we have
		 * finished walking it.
		 */
		ght_rele(hte);

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
i_dls_link_ether_loopback(void *arg, mblk_t *mp)
{
	dls_link_t			*dlp = arg;
	ght_t				hash = dlp->dl_impl_hash;
	mblk_t				*nextp;
	uint_t				header_length;
	uint8_t				*daddr;
	uint16_t			type_length;
	uint16_t			vid;
	uint16_t			sap;
	ghte_t				hte;
	dls_impl_t			*dip;
	dls_impl_t			*ndip;
	mblk_t				*nmp;
	ght_key_t			key;
	uint_t				npacket;

	/*
	 * Walk the packet chain.
	 */
	while (mp != NULL) {
		/*
		 * Grab the longest sub-chain we can process as a single
		 * unit.
		 */
		nextp = i_dls_link_ether_subchain(mp, &header_length, &daddr,
		    &type_length, &vid, &npacket);

		/*
		 * Calculate the DLSAP: LLC (0) if the type/length field is
		 * interpreted as a length, otherwise it is the value of the
		 * type/length field.
		 */
		sap = (type_length <= ETHERMTU) ? DLS_SAP_LLC : type_length;

		/*
		 * Construct a hash key from the VLAN identifier and the
		 * DLSAP.
		 */
		key = MAKE_KEY(sap, vid);

		/*
		 * Search the has table for dls_impl_t eligible to receive
		 * a packet chain for this DLSAP/VLAN combination.
		 */
		ght_lock(hash, GHT_READ);
		if (ght_find(hash, key, &hte) != 0) {
			ght_unlock(hash);
			goto promisc;
		}

		/*
		 * Place a hold the chain of dls_impl_t to make sure none are
		 * removed from under our feet.
		 */
		ght_hold(hte);
		ght_unlock(hash);

		/*
		 * Find dls_impl_t that will accept the sub-chain.
		 */
		for (dip = (dls_impl_t *)GHT_VAL(hte); dip != NULL;
		    dip = dip->di_nextp) {
			if (!dls_accept_loopback(dip, daddr))
				continue;

			/*
			 * There should be at least more dls_impl_t (since
			 * we've yet to check for dls_impl_t in promiscuous
			 * mode) so dup the sub-chain.
			 */
			if ((nmp = copymsgchain(mp)) != NULL)
				dip->di_rx(dip->di_rx_arg, NULL, nmp,
				    header_length);
		}

		/*
		 * Release the hold on the dls_impl_t chain now that we have
		 * finished walking it.
		 */
		ght_rele(hte);

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
		ght_lock(hash, GHT_READ);
		if (ght_find(hash, key, &hte) != 0) {
			ght_unlock(hash);
			freemsgchain(mp);
			goto loop;
		}

		/*
		 * Place a hold the chain of dls_impl_t to make sure none are
		 * removed from under our feet.
		 */
		ght_hold(hte);
		ght_unlock(hash);

		/*
		 * Find the first dls_impl_t that will accept the sub-chain.
		 */
		for (dip = (dls_impl_t *)GHT_VAL(hte); dip != NULL;
		    dip = dip->di_nextp)
			if (dls_accept_loopback(dip, daddr))
				break;

		/*
		 * If we did not find any dls_impl_t willing to accept the
		 * sub-chain then throw it away.
		 */
		if (dip == NULL) {
			ght_rele(hte);
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
				if (dls_accept_loopback(ndip, daddr))
					break;

			/*
			 * If there are no more dls_impl_t that are willing
			 * to accept the sub-chain then we don't need to dup
			 * it before handing it to the current one.
			 */
			if (ndip == NULL) {
				dip->di_rx(dip->di_rx_arg, NULL, mp,
				    header_length);

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
				dip->di_rx(dip->di_rx_arg, NULL, nmp,
				    header_length);

			dip = ndip;
		}

		/*
		 * Release the hold on the dls_impl_t chain now that we have
		 * finished walking it.
		 */
		ght_rele(hte);

loop:
		/*
		 * Move onto the next sub-chain.
		 */
		mp = nextp;
	}
}

static boolean_t
i_dls_link_walk(void *arg, ghte_t hte)
{
	boolean_t	*promiscp = arg;
	ght_key_t	key = GHT_KEY(hte);
	uint32_t	sap = KEY_SAP(key);

	if (sap == DLS_SAP_PROMISC) {
		*promiscp = B_TRUE;
		return (B_FALSE);	/* terminate walk */
	}

	return (B_TRUE);
}

static int
i_dls_link_create(const char *dev, uint_t port, dls_link_t **dlpp)
{
	dls_link_t		*dlp;
	int			err;
	mac_handle_t		mh;

	/*
	 * Check that the MAC exists, and (for now) that it's
	 * of type DL_ETHER.
	 */
	if ((err = mac_open(dev, port, &mh)) != 0)
		return (err);

	ASSERT(mac_info(mh)->mi_media == DL_ETHER);
	mac_close(mh);

	/*
	 * Allocate a new dls_link_t structure.
	 */
	dlp = kmem_cache_alloc(i_dls_link_cachep, KM_SLEEP);

	/*
	 * Name the dls_link_t after the MAC interface it represents.
	 */
	MAC_NAME(dlp->dl_name, dev, port);
	(void) strlcpy(dlp->dl_dev, dev, MAXNAMELEN);
	dlp->dl_port = port;

	/*
	 * Set the initial packet receive function.
	 */
	ASSERT(ght_count(dlp->dl_impl_hash) == 0);

	/*
	 * Set the packet loopback function for use when the MAC is in
	 * promiscuous mode, and initialize promiscuous bookeeping fields.
	 */
	dlp->dl_loopback = i_dls_link_ether_loopback;
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

	/*
	 * Free the structure back to the cache.
	 */
	dlp->dl_mrh = NULL;
	dlp->dl_unknowns = 0;
	kmem_cache_free(i_dls_link_cachep, dlp);

}

/*
 * Module initialization functions.
 */

void
dls_link_init(void)
{
	int	err;

	/*
	 * Create a kmem_cache of dls_link_t structures.
	 */
	i_dls_link_cachep = kmem_cache_create("dls_link_cache",
	    sizeof (dls_link_t), 0, i_dls_link_constructor,
	    i_dls_link_destructor, NULL, NULL, NULL, 0);
	ASSERT(i_dls_link_cachep != NULL);

	/*
	 * Create a global hash tables to be keyed by a name.
	 */
	err = ght_str_create("dls_link_hash", LINK_HASHSZ, &i_dls_link_hash);
	ASSERT(err == 0);
}

int
dls_link_fini(void)
{
	int	err;

	/*
	 * Destroy the hash table. This will return EBUSY if there are
	 * still entries present.
	 */
	if ((err = ght_destroy(i_dls_link_hash)) != 0)
		return (err);

	/*
	 * Destroy the kmem_cache.
	 */
	kmem_cache_destroy(i_dls_link_cachep);
	return (0);
}

/*
 * Exported functions.
 */

int
dls_link_hold(const char *dev, uint_t port, dls_link_t **dlpp)
{
	char			name[MAXNAMELEN];
	dls_link_t		*dlp;
	int			err;
	ghte_t			hte;
	ghte_t			nhte;

	/*
	 * Allocate a new hash table entry.
	 */
	nhte = ght_alloc(i_dls_link_hash, KM_SLEEP);

	/*
	 * Construct a copy of the name used to identify any existing
	 * dls_link_t.
	 */
	MAC_NAME(name, dev, port);

	/*
	 * Look up a dls_link_t corresponding to the given mac_handle_t
	 * in the global hash table.
	 */
	ght_lock(i_dls_link_hash, GHT_WRITE);
	if ((err = ght_find(i_dls_link_hash, GHT_PTR_TO_KEY(name),
	    &hte)) == 0) {
		dlp = (dls_link_t *)GHT_VAL(hte);
		ght_free(nhte);
		goto done;
	}
	ASSERT(err == ENOENT);

	/*
	 * We didn't find anything so we need to create one.
	 */
	if ((err = i_dls_link_create(dev, port, &dlp)) != 0) {
		ght_free(nhte);
		ght_unlock(i_dls_link_hash);
		return (err);
	}

	GHT_KEY(nhte) = GHT_PTR_TO_KEY(dlp->dl_name);
	GHT_VAL(nhte) = GHT_PTR_TO_VAL(dlp);
	dlp->dl_hte = nhte;
	/*
	 * Insert the entry.
	 */
	err = ght_insert(nhte);
	ASSERT(err == 0);

done:
	/*
	 * Bump the reference count and hand back the reference.
	 */
	dlp->dl_ref++;
	*dlpp = dlp;
	ght_unlock(i_dls_link_hash);
	return (err);
}

void
dls_link_rele(dls_link_t *dlp)
{
	ghte_t		hte;

	ght_lock(i_dls_link_hash, GHT_WRITE);

	/*
	 * Check if there are any more references.
	 */
	if (--dlp->dl_ref != 0) {
		/*
		 * There are more references so there's nothing more to do.
		 */
		goto done;
	}

	hte = dlp->dl_hte;
	dlp->dl_hte = NULL;

	/*
	 * Remove the hash table entry.
	 */
	ght_remove(hte);
	ght_free(hte);

	/*
	 * Destroy the dls_link_t.
	 */
	i_dls_link_destroy(dlp);

done:
	ght_unlock(i_dls_link_hash);
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
		err = mac_open(dlp->dl_dev, dlp->dl_port, &dlp->dl_mh);
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
	ght_t		hash = dlp->dl_impl_hash;
	ghte_t		hte;
	ghte_t		nhte;
	ght_key_t	key;
	dls_impl_t	**pp;
	dls_impl_t	*p;
	mac_rx_t	rx;
	int		err;
	uint_t		impl_count;

	ASSERT(dip->di_nextp == NULL);

	/*
	 * For ethernet media, sap values less than or equal to
	 * ETHERMTU (1500) represent LLC channels. (See PSARC 2003/150).
	 * We strictly use 0 to represent LLC channels.
	 */
	sap = (sap <= ETHERMTU) ? 0 : sap;

	/*
	 * Make the appropriate key value depending on whether the
	 * dls_impl_t is in promiscuous mode or not.
	 */
	key = MAKE_KEY(sap, dvp->dv_id);

	/*
	 * We need dl_lock here because we want to be able to walk
	 * the hash table *and* set the mac rx func atomically. if
	 * these two operations are separate, someone else could
	 * insert/remove dls_impl_t from the ght after we drop the
	 * ght lock and this could cause our chosen rx func to be
	 * incorrect. note that we cannot call mac_rx_set when
	 * holding the ght lock because this can cause deadlock.
	 */
	mutex_enter(&dlp->dl_lock);
	/*
	 * Allocate a new entry.
	 */
	nhte = ght_alloc(hash, KM_SLEEP);

	/*
	 * Search the table for any existing entry with this key.
	 */
	ght_lock(hash, GHT_WRITE);
	if ((err = ght_find(hash, key, &hte)) != 0) {
		ASSERT(err == ENOENT);

		GHT_KEY(nhte) = key;
		GHT_VAL(nhte) = GHT_PTR_TO_VAL(dip);

		/*
		 * Insert it in the table to be the head of a new list.
		 */
		err = ght_insert(nhte);
		ASSERT(err == 0);

		/*
		 * Cache a reference to the hash table entry.
		 */
		ASSERT(dip->di_hte == NULL);
		dip->di_hte = nhte;

		goto done;
	}

	/*
	 * Free the unused hash table entry.
	 */
	ght_free(nhte);

	/*
	 * Add the dls_impl_t to the end of the list. We can't add to the head
	 * because the hash table internals already have a reference to the
	 * head of the list.
	 */
	for (pp = (dls_impl_t **)&(GHT_VAL(hte)); (p = *pp) != NULL;
	    pp = &(p->di_nextp))
		ASSERT(p != dip);

	*pp = dip;

	/*
	 * Cache a reference to the hash table entry.
	 */
	ASSERT(dip->di_hte == NULL);
	dip->di_hte = hte;

done:
	/*
	 * If there are no dls_impl_t then we can just drop all received
	 * packets on the floor.
	 */
	impl_count = ght_count(hash);
	if (impl_count == 0) {
		ght_unlock(hash);
	} else {
		boolean_t promisc = B_FALSE;

		/*
		 * Walk the bound dls_impl_t to see if there are any
		 * in promiscuous 'all sap' mode.
		 */
		ght_walk(hash, i_dls_link_walk, (void *)&promisc);

		/*
		 * If there are then we need to use a receive routine
		 * which will route packets to those dls_impl_t as well
		 * as ones bound to the  DLSAP of the packet.
		 */
		if (promisc)
			rx = i_dls_link_ether_rx_promisc;
		else
			rx = i_dls_link_ether_rx;

		ght_unlock(hash);

		/* Replace the existing receive function if there is one. */
		if (dlp->dl_mrh != NULL)
			mac_rx_remove(dlp->dl_mh, dlp->dl_mrh);
		dlp->dl_mrh = mac_rx_add(dlp->dl_mh, rx, (void *)dlp);
	}
	mutex_exit(&dlp->dl_lock);
}

void
dls_link_remove(dls_link_t *dlp, dls_impl_t *dip)
{
	ght_t		hash = dlp->dl_impl_hash;
	ghte_t		hte;
	dls_impl_t	**pp;
	dls_impl_t	*p;
	mac_rx_t	rx;

	/*
	 * We need dl_lock here because we want to be able to walk
	 * the hash table *and* set the mac rx func atomically. if
	 * these two operations are separate, someone else could
	 * insert/remove dls_impl_t from the ght after we drop the
	 * ght lock and this could cause our chosen rx func to be
	 * incorrect. note that we cannot call mac_rx_add when
	 * holding the ght lock because this can cause deadlock.
	 */
	mutex_enter(&dlp->dl_lock);

	ght_lock(hash, GHT_WRITE);

	/*
	 * Get the cached hash table entry reference.
	 */
	hte = dip->di_hte;
	ASSERT(hte != NULL);

	/*
	 * Poll the hash table entry until all references have been dropped.
	 * We need to drop all locks before sleeping because we don't want
	 * the interrupt handler to block. We set di_removing here to
	 * tell the receive callbacks not to pass up packets anymore.
	 * This is only a hint to quicken the decrease of the refcnt so
	 * the assignment need not be protected by any lock.
	 */
	dip->di_removing = B_TRUE;
	while (ght_ref(hte) != 0) {
		ght_unlock(hash);
		mutex_exit(&dlp->dl_lock);
		delay(drv_usectohz(1000));	/* 1ms delay */
		mutex_enter(&dlp->dl_lock);
		ght_lock(hash, GHT_WRITE);
	}

	/*
	 * Walk the list and remove the dls_impl_t.
	 */
	for (pp = (dls_impl_t **)&(GHT_VAL(hte)); (p = *pp) != NULL;
	    pp = &(p->di_nextp)) {
		if (p == dip)
			break;
	}
	ASSERT(p != NULL);

	*pp = p->di_nextp;
	p->di_nextp = NULL;
	dip->di_hte = NULL;

	if (GHT_VAL(hte) == NULL) {
		/*
		 * The list is empty so remove the hash table entry.
		 */
		ght_remove(hte);
		ght_free(hte);
	}
	dip->di_removing = B_FALSE;

	/*
	 * If there are no dls_impl_t then there's no need to register a
	 * receive function with the mac.
	 */
	if (ght_count(hash) == 0) {
		ght_unlock(hash);
		mac_rx_remove(dlp->dl_mh, dlp->dl_mrh);
		dlp->dl_mrh = NULL;
	} else {
		boolean_t promisc = B_FALSE;

		/*
		 * Walk the bound dls_impl_t to see if there are any
		 * in promiscuous 'all sap' mode.
		 */
		ght_walk(hash, i_dls_link_walk, (void *)&promisc);

		/*
		 * If there are then we need to use a receive routine
		 * which will route packets to those dls_impl_t as well
		 * as ones bound to the  DLSAP of the packet.
		 */
		if (promisc)
			rx = i_dls_link_ether_rx_promisc;
		else
			rx = i_dls_link_ether_rx;

		ght_unlock(hash);

		mac_rx_remove(dlp->dl_mh, dlp->dl_mrh);
		dlp->dl_mrh = mac_rx_add(dlp->dl_mh, rx, (void *)dlp);
	}
	mutex_exit(&dlp->dl_lock);
}
