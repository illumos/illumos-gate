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
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * gld - Generic LAN Driver
 * media dependent routines
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/kmem.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/kstat.h>
#include <sys/debug.h>

#include <sys/byteorder.h>
#include <sys/strsun.h>
#include <sys/dlpi.h>
#include <sys/ethernet.h>
#include <sys/multidata.h>
#include <sys/gld.h>
#include <sys/gldpriv.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>
#include <sys/ib/clients/ibd/ibd.h>
#include <sys/pattr.h>

#define	DLSAPLENGTH(macinfo) \
	((macinfo)->gldm_addrlen + ABS((macinfo)->gldm_saplen))

#ifdef GLD_DEBUG
extern int gld_debug;
#endif

extern void gld_bitrevcopy(caddr_t src, caddr_t target, size_t n);
extern char *gld_macaddr_sprintf(char *, unsigned char *, int);
extern gld_vlan_t *gld_find_vlan(gld_mac_info_t *, uint32_t);
extern uint32_t gld_global_options;

static struct	llc_snap_hdr llc_snap_def = {
	LSAP_SNAP,		/* DLSAP 0xaa */
	LSAP_SNAP,		/* SLSAP 0xaa */
	CNTL_LLC_UI,		/* Control 0x03 */
	0x00, 0x00, 0x00,	/* Org[3] */
	0x00			/* Type */
};

#define	ISETHERTYPE(snaphdr) \
	(snaphdr->d_lsap == LSAP_SNAP && \
	snaphdr->s_lsap == LSAP_SNAP && \
	snaphdr->control == CNTL_LLC_UI && \
	snaphdr->org[0] == 0 && \
	snaphdr->org[1] == 0 && \
	snaphdr->org[2] == 0)

/* ======== */
/* Ethernet */
/* ======== */

static mac_addr_t ether_broadcast = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

void
gld_init_ether(gld_mac_info_t *macinfo)
{
	struct gldkstats *sp =
	    ((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)->kstatp->ks_data;

	/* Assumptions we make for this medium */
	ASSERT(macinfo->gldm_type == DL_ETHER);
	ASSERT(macinfo->gldm_addrlen == 6);
	ASSERT(macinfo->gldm_saplen == -2);
#ifndef	lint
	ASSERT(sizeof (struct ether_header) == 14);
	ASSERT(sizeof (mac_addr_t) == 6);
#endif

	kstat_named_init(&sp->glds_frame, "align_errors", KSTAT_DATA_ULONG);
	kstat_named_init(&sp->glds_crc, "fcs_errors", KSTAT_DATA_ULONG);
	kstat_named_init(&sp->glds_collisions, "collisions", KSTAT_DATA_ULONG);
	kstat_named_init(&sp->glds_nocarrier, "carrier_errors",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&sp->glds_defer, "defer_xmts", KSTAT_DATA_ULONG);
	kstat_named_init(&sp->glds_xmtlatecoll, "tx_late_collisions",
					KSTAT_DATA_ULONG);
	kstat_named_init(&sp->glds_short, "runt_errors", KSTAT_DATA_ULONG);
	kstat_named_init(&sp->glds_excoll, "ex_collisions", KSTAT_DATA_ULONG);

	/*
	 * only initialize the new statistics if the driver
	 * knows about them.
	 */
	if (macinfo->gldm_driver_version != GLD_VERSION_200)
		return;

	kstat_named_init(&sp->glds_dot3_first_coll,
	    "first_collisions", KSTAT_DATA_UINT32);
	kstat_named_init(&sp->glds_dot3_multi_coll,
	    "multi_collisions", KSTAT_DATA_UINT32);
	kstat_named_init(&sp->glds_dot3_sqe_error,
	    "sqe_errors", KSTAT_DATA_UINT32);
	kstat_named_init(&sp->glds_dot3_mac_xmt_error,
	    "macxmt_errors", KSTAT_DATA_UINT32);
	kstat_named_init(&sp->glds_dot3_mac_rcv_error,
	    "macrcv_errors", KSTAT_DATA_UINT32);
	kstat_named_init(&sp->glds_dot3_frame_too_long,
	    "toolong_errors", KSTAT_DATA_UINT32);
	kstat_named_init(&sp->glds_duplex, "duplex", KSTAT_DATA_CHAR);
}

/*ARGSUSED*/
void
gld_uninit_ether(gld_mac_info_t *macinfo)
{
}

int
gld_interpret_ether(gld_mac_info_t *macinfo, mblk_t *mp, pktinfo_t *pktinfo,
    packet_flag_t flags)
{
	struct ether_header *mh;
	gld_mac_pvt_t *mac_pvt = (gld_mac_pvt_t *)macinfo->gldm_mac_pvt;
	struct llc_snap_hdr *snaphdr;
	mblk_t *pmp = NULL, *savemp = mp;
	unsigned short typelen;
	int ret = 0;

	/*
	 * Quickly handle receive fastpath for IPQ hack.
	 */
	if (flags == GLD_RXQUICK) {
		pktinfo->pktLen = msgdsize(mp);
		/*
		 * Check whether the header is contiguous, which
		 * also implicitly makes sure the packet is big enough.
		 */
		if (MBLKL(mp) < sizeof (struct ether_header))
			return (-1);
		mh = (struct ether_header *)mp->b_rptr;
		pktinfo->ethertype = REF_NET_USHORT(mh->ether_type);
		pktinfo->isForMe = mac_eq(&mh->ether_dhost,
		    mac_pvt->curr_macaddr, macinfo->gldm_addrlen);
		pktinfo->macLen = sizeof (struct ether_header);

		return (0);
	}

	bzero((void *)pktinfo, sizeof (*pktinfo));

	pktinfo->pktLen = msgdsize(mp);

	/* make sure packet has at least a whole mac header */
	if (pktinfo->pktLen < sizeof (struct ether_header))
		return (-1);

	/* make sure the mac header falls into contiguous memory */
	if (MBLKL(mp) < sizeof (struct ether_header)) {
		if ((pmp = msgpullup(mp, -1)) == NULL) {
#ifdef GLD_DEBUG
			if (gld_debug & GLDERRS)
				cmn_err(CE_WARN,
				    "GLD: interpret_ether cannot msgpullup");
#endif
			return (-1);
		}
		mp = pmp;	/* this mblk contains the whole mac header */
	}

	mh = (struct ether_header *)mp->b_rptr;

	/* Check to see if the mac is a broadcast or multicast address. */
	if (mac_eq(&mh->ether_dhost, ether_broadcast, macinfo->gldm_addrlen))
		pktinfo->isBroadcast = 1;
	else if (mh->ether_dhost.ether_addr_octet[0] & 1)
		pktinfo->isMulticast = 1;

	typelen = REF_NET_USHORT(mh->ether_type);
	/*
	 * If the hardware is capable of VLAN tag insertion
	 * strip out the VLAN tag info. Knowing hardware is
	 * capable of VLAN can be established by the presance
	 * of non null 'macinfo->gldm_send_tagged'.
	 */
	if (flags == GLD_TX) {
		if ((typelen == ETHERTYPE_VLAN) &&
		    (macinfo->gldm_send_tagged != NULL)) {
			struct ether_vlan_header *evhp;
			uint16_t tci;

			if ((MBLKL(mp) < sizeof (struct ether_vlan_header)) &&
			    (pullupmsg(mp, sizeof (struct ether_vlan_header))
			    == 0)) {
				ret = -1;
				goto out;
			}
			evhp = (struct ether_vlan_header *)mp->b_rptr;
			tci = REF_NET_USHORT(evhp->ether_tci);

			/*
			 * We don't allow the VID and priority are both zero.
			 */
			if ((GLD_VTAG_PRI((int32_t)tci) == 0 &&
			    GLD_VTAG_VID((int32_t)tci) == VLAN_VID_NONE) ||
			    (GLD_VTAG_CFI((uint32_t)tci)) != VLAN_CFI_ETHER) {
				ret = -1;
				goto out;
			}

			/*
			 * Remember the VTAG info in order to reinsert it,
			 * Then strip the tag. This is required because some
			 * drivers do not allow the size of message (passed
			 * by the gldm_send_tagged() function) to be greater
			 * than ETHERMAX.
			 */
			GLD_SAVE_MBLK_VTAG(savemp, GLD_TCI2VTAG(tci));
			ovbcopy(mp->b_rptr, mp->b_rptr + VTAG_SIZE,
			    2 * ETHERADDRL);
			mp->b_rptr += VTAG_SIZE;
		}
		goto out;	/* Got all info we need for xmit case */
	}

	ASSERT(GLDM_LOCK_HELD(macinfo));

	/*
	 * Deal with the mac header
	 */

	mac_copy(&mh->ether_dhost, pktinfo->dhost, macinfo->gldm_addrlen);
	mac_copy(&mh->ether_shost, pktinfo->shost, macinfo->gldm_addrlen);

	pktinfo->isLooped = mac_eq(pktinfo->shost,
	    mac_pvt->curr_macaddr, macinfo->gldm_addrlen);
	pktinfo->isForMe = mac_eq(pktinfo->dhost,
	    mac_pvt->curr_macaddr, macinfo->gldm_addrlen);

	pktinfo->macLen = sizeof (struct ether_header);

	if (typelen > ETHERMTU) {
		pktinfo->ethertype = typelen; /* use type interpretation */
		goto out;
	}

	/*
	 * Packet is 802.3 so the ether type/length field
	 * specifies the number of bytes that should be present
	 * in the data field.  Additional bytes are padding, and
	 * should be removed
	 */
	{
	int delta = pktinfo->pktLen -
	    (sizeof (struct ether_header) + typelen);

	if (delta > 0 && adjmsg(mp, -delta))
		pktinfo->pktLen -= delta;
	}

	/*
	 * Before trying to look beyond the MAC header, make sure the LLC
	 * header exists, and that both it and any SNAP header are contiguous.
	 */
	if (pktinfo->pktLen < pktinfo->macLen + LLC_HDR1_LEN)
		goto out;	/* LLC hdr should have been there! */

	pktinfo->isLLC = 1;

	if (gld_global_options & GLD_OPT_NO_ETHRXSNAP ||
	    pktinfo->pktLen <  pktinfo->macLen + LLC_SNAP_HDR_LEN)
		goto out;

	if (MBLKL(mp) < sizeof (struct ether_header) + LLC_SNAP_HDR_LEN &&
	    MBLKL(mp) < pktinfo->pktLen) {
		/*
		 * we don't have the entire packet within the first mblk (and
		 * therefore we didn't do the msgpullup above), AND the first
		 * mblk may not contain all the data we need to look at.
		 */
		ASSERT(pmp == NULL);	/* couldn't have done msgpullup above */
		if ((pmp = msgpullup(mp, -1)) == NULL) {
#ifdef GLD_DEBUG
			if (gld_debug & GLDERRS)
				cmn_err(CE_WARN,
				    "GLD: interpret_ether cannot msgpullup2");
#endif
			goto out;	/* can't interpret this pkt further */
		}
		mp = pmp;	/* this mblk should contain everything needed */
	}

	/*
	 * Check SAP/SNAP information for EtherType.
	 */

	snaphdr = (struct llc_snap_hdr *)(mp->b_rptr + pktinfo->macLen);
	if (ISETHERTYPE(snaphdr)) {
		pktinfo->ethertype = REF_NET_USHORT(snaphdr->type);
		pktinfo->hdrLen = LLC_SNAP_HDR_LEN;
	}
out:
	if (pmp != NULL)
		freemsg(pmp);

	return (ret);
}

mblk_t *
gld_unitdata_ether(gld_t *gld, mblk_t *mp)
{
	gld_mac_info_t *macinfo = gld->gld_mac_info;
	dl_unitdata_req_t *dlp = (dl_unitdata_req_t *)mp->b_rptr;
	struct gld_dlsap *gldp = DLSAP(dlp, dlp->dl_dest_addr_offset);
	mac_addr_t dhost;
	unsigned short typelen;
	mblk_t *nmp;
	struct ether_header *mh;
	int hdrlen;
	uint32_t vptag;
	gld_vlan_t *gld_vlan;

	ASSERT(macinfo);

	/* extract needed info from the mblk before we maybe reuse it */
	mac_copy(gldp->glda_addr, dhost, macinfo->gldm_addrlen);

	/* look in the unitdata request for a sap, else use bound one */
	if (dlp->dl_dest_addr_length >= DLSAPLENGTH(macinfo) &&
	    REF_HOST_USHORT(gldp->glda_sap) != 0)
		typelen = REF_HOST_USHORT(gldp->glda_sap);
	else
		typelen = gld->gld_sap;

	/*
	 * We take values less than or equal to ETHERMTU to mean that the
	 * packet should not have an encoded EtherType and so we use the
	 * IEEE 802.3 length interpretation of the type/length field.
	 */
	if (typelen <= ETHERMTU)
		typelen = msgdsize(mp);

	hdrlen = sizeof (struct ether_header);

	/*
	 * Check to see if VLAN is enabled on this stream
	 * if so then make the header bigger to hold a clone
	 * vlan tag.
	 */
	gld_vlan = (gld_vlan_t *)gld->gld_vlan;
	if (gld_vlan && (gld_vlan->gldv_id != VLAN_VID_NONE)) {
		hdrlen += VTAG_SIZE;
		vptag = gld_vlan->gldv_ptag;
	}

	/* need a buffer big enough for the headers */
	nmp = mp->b_cont;	/* where the packet payload M_DATA is */
	if (DB_REF(nmp) == 1 && MBLKHEAD(nmp) >= hdrlen) {
		/* it fits at the beginning of the first M_DATA block */
		freeb(mp);	/* don't need the M_PROTO anymore */
	} else if (DB_REF(mp) == 1 && MBLKSIZE(mp) >= hdrlen) {
		/* we can reuse the dl_unitdata_req M_PROTO mblk */
		nmp = mp;
		DB_TYPE(nmp) = M_DATA;
		nmp->b_rptr = nmp->b_wptr = DB_LIM(nmp);
	} else {
		/* we need to allocate one */
		if ((nmp = allocb(hdrlen, BPRI_MED)) == NULL)
			return (NULL);
		nmp->b_rptr = nmp->b_wptr = DB_LIM(nmp);
		linkb(nmp, mp->b_cont);
		freeb(mp);
	}

	/* Got the space, now copy in the header components */

	nmp->b_rptr -= sizeof (typelen);
	SET_NET_USHORT(*(uint16_t *)nmp->b_rptr, typelen);
	if (hdrlen > sizeof (struct ether_header)) {
		nmp->b_rptr -= sizeof (uint16_t);
		SET_NET_USHORT(*(uint16_t *)nmp->b_rptr, vptag);
		vptag >>= 16;
		nmp->b_rptr -= sizeof (uint16_t);
		SET_NET_USHORT(*(uint16_t *)nmp->b_rptr, vptag);
	}
	nmp->b_rptr -= (ETHERADDRL * 2);
	mh = (struct ether_header *)nmp->b_rptr;
	mac_copy(dhost, &mh->ether_dhost, macinfo->gldm_addrlen);

	/*
	 * We access the mac address without the mutex to prevent
	 * mutex contention (BUG 4211361)
	 */
	mac_copy(((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)->curr_macaddr,
	    &mh->ether_shost, macinfo->gldm_addrlen);

	return (nmp);
}

/*
 * Insert the VLAN tag into the packet. The packet now is an Ethernet header
 * without VLAN tag information.
 */
mblk_t *
gld_insert_vtag_ether(mblk_t *mp, uint32_t vtag)
{
	struct ether_vlan_header *evhp;
	struct ether_header *ehp;
	mblk_t *nmp;

	if (vtag == VLAN_VID_NONE)
		return (mp);

	if (DB_REF(mp) == 1 && MBLKHEAD(mp) >= VTAG_SIZE) {
		/* it fits at the beginning of the message block */
		nmp = mp;
		ovbcopy(nmp->b_rptr, nmp->b_rptr - VTAG_SIZE, 2 * ETHERADDRL);
		nmp->b_rptr -= VTAG_SIZE;
		evhp = (struct ether_vlan_header *)nmp->b_rptr;
	} else {
		/* we need to allocate one */
		if ((nmp = allocb(sizeof (struct ether_vlan_header),
		    BPRI_MED)) == NULL) {
			return (NULL);
		}
		nmp->b_wptr += sizeof (struct ether_vlan_header);

		/* transfer the ether_header fields */
		evhp = (struct ether_vlan_header *)nmp->b_rptr;
		ehp = (struct ether_header *)mp->b_rptr;
		mac_copy(&ehp->ether_dhost, &evhp->ether_dhost, ETHERADDRL);
		mac_copy(&ehp->ether_shost, &evhp->ether_shost, ETHERADDRL);
		bcopy(&ehp->ether_type, &evhp->ether_type, sizeof (uint16_t));

		/* offset the mp of the MAC header length. */
		mp->b_rptr += sizeof (struct ether_header);
		if (MBLKL(mp) == 0) {
			nmp->b_cont = mp->b_cont;
			freeb(mp);
		} else {
			nmp->b_cont = mp;
		}
	}

	SET_NET_USHORT(evhp->ether_tci, vtag);
	vtag >>= 16;
	SET_NET_USHORT(evhp->ether_tpid, vtag);
	return (nmp);
}

mblk_t *
gld_fastpath_ether(gld_t *gld, mblk_t *mp)
{
	gld_mac_info_t *macinfo = gld->gld_mac_info;
	dl_unitdata_req_t *dlp = (dl_unitdata_req_t *)mp->b_cont->b_rptr;
	struct gld_dlsap *gldp = DLSAP(dlp, dlp->dl_dest_addr_offset);
	unsigned short typelen;
	mblk_t *nmp;
	struct ether_header *mh;
	int hdrlen;
	uint32_t vptag;
	gld_vlan_t *gld_vlan;

	ASSERT(macinfo);

	/* look in the unitdata request for a sap, else use bound one */
	if (dlp->dl_dest_addr_length >= DLSAPLENGTH(macinfo) &&
	    REF_HOST_USHORT(gldp->glda_sap) != 0)
		typelen = REF_HOST_USHORT(gldp->glda_sap);
	else
		typelen = gld->gld_sap;

	/*
	 * We only do fast-path for EtherType encoding because this is the only
	 * case where the media header will be consistent from packet to packet.
	 */
	if (typelen <= ETHERMTU)
		return (NULL);

	/*
	 * Initialize the fast path header to include the
	 * basic source address information and type field.
	 */
	hdrlen = sizeof (struct ether_header);

	/*
	 * Check to see if VLAN is enabled on this stream
	 * if so then make the header bigger to hold a clone
	 * vlan tag.
	 */
	gld_vlan = (gld_vlan_t *)gld->gld_vlan;
	if (gld_vlan && (gld_vlan->gldv_id != VLAN_VID_NONE)) {
		hdrlen += VTAG_SIZE;
		vptag = gld_vlan->gldv_ptag;
	}

	if ((nmp = allocb(hdrlen, BPRI_MED)) == NULL)
		return (NULL);

	nmp->b_rptr = nmp->b_wptr = DB_LIM(nmp);

	/* Got the space, now copy in the header components */

	nmp->b_rptr -= sizeof (typelen);
	SET_NET_USHORT(*(uint16_t *)nmp->b_rptr, typelen);

	/*
	 * If the header is for a VLAN stream, then add
	 * in the VLAN tag to the clone header.
	 */
	if (hdrlen > sizeof (struct ether_header)) {
		nmp->b_rptr -= sizeof (uint16_t);
		SET_NET_USHORT(*(uint16_t *)nmp->b_rptr, vptag);
		vptag >>= 16;
		nmp->b_rptr -= sizeof (uint16_t);
		SET_NET_USHORT(*(uint16_t *)nmp->b_rptr, vptag);
	}
	nmp->b_rptr -= (ETHERADDRL * 2);
	mh = (struct ether_header *)nmp->b_rptr;
	mac_copy(gldp->glda_addr, &mh->ether_dhost, macinfo->gldm_addrlen);

	GLDM_LOCK(macinfo, RW_WRITER);
	mac_copy(((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)->curr_macaddr,
	    &mh->ether_shost, macinfo->gldm_addrlen);
	GLDM_UNLOCK(macinfo);

	return (nmp);
}

/* == */
/* IB */
/* == */

void
gld_init_ib(gld_mac_info_t *macinfo)
{
	/*
	 * Currently, the generic stats maintained by GLD is
	 * sufficient for IPoIB.
	 */

	/* Assumptions we make for this medium */
	ASSERT(macinfo->gldm_type == DL_IB);
	ASSERT(macinfo->gldm_addrlen == IPOIB_ADDRL);
	ASSERT(macinfo->gldm_saplen == -2);
}

/* ARGSUSED */
void
gld_uninit_ib(gld_mac_info_t *macinfo)
{
}

/*
 * The packet format sent to the driver is:
 * IPOIB_ADDRL bytes dest addr :: 2b sap :: 2b 0s :: data
 * The packet format received from the driver is:
 * IPOIB_GRH_SIZE bytes pseudo GRH :: 2b sap :: 2b 0s :: data.
 */
int
gld_interpret_ib(gld_mac_info_t *macinfo, mblk_t *mp, pktinfo_t *pktinfo,
    packet_flag_t flags)
{
	ipoib_pgrh_t *grh;
	ipoib_ptxhdr_t *gldp;
	mblk_t *pmp = NULL;
	gld_mac_pvt_t *mac_pvt = (gld_mac_pvt_t *)macinfo->gldm_mac_pvt;

	/*
	 * Quickly handle receive fastpath for IPQ hack.
	 */
	if (flags == GLD_RXQUICK) {
		pktinfo->pktLen = msgdsize(mp) - IPOIB_GRH_SIZE;

		/*
		 * Check whether the header is contiguous, which
		 * also implicitly makes sure the packet is big enough.
		 */
		if (MBLKL(mp) < (IPOIB_GRH_SIZE + IPOIB_HDRSIZE))
			return (-1);

		/*
		 * Almost all times, unicast will not have
		 * a valid pgrh; quickly identify and ask for
		 * IPQ hack optimization only in that case.
		 */
		grh = (ipoib_pgrh_t *)mp->b_rptr;
		if (grh->ipoib_vertcflow == 0) {
			struct ipoib_header *ihp = (struct ipoib_header *)
			    (mp->b_rptr + IPOIB_GRH_SIZE);

			pktinfo->isForMe = 1;
			pktinfo->ethertype = REF_NET_USHORT(ihp->ipoib_type);
			pktinfo->macLen = IPOIB_GRH_SIZE + IPOIB_HDRSIZE;
			return (0);
		} else {
			return (-1);
		}
	}

	/*
	 * Handle the GLD_TX, GLD_RX, GLD_RXLOOP cases now.
	 */
	ASSERT(flags != GLD_RXQUICK);
	bzero((void *)pktinfo, sizeof (*pktinfo));

	if (flags != GLD_RX) {
		/*
		 * GLD_TX and GLD_RXLOOP cases.
		 */
		gldp = (ipoib_ptxhdr_t *)mp->b_rptr;
		pktinfo->pktLen = msgdsize(mp);

		/* make sure packet has at least a pseudo header */
		if (pktinfo->pktLen < sizeof (ipoib_ptxhdr_t))
			return (-1);

		/* make sure the mac header falls into contiguous memory */
		if (MBLKL(mp) < sizeof (ipoib_ptxhdr_t)) {
			if ((pmp = msgpullup(mp, -1)) == NULL) {
#ifdef GLD_DEBUG
				if (gld_debug & GLDERRS)
					cmn_err(CE_WARN,
					    "GLD: interpret_ib "
					    "cannot msgpullup");
#endif
				return (-1);
			}
			/* this mblk contains the whole mac header */
			mp = pmp;
		}

		/*
		 * Check if mac is broadcast or multicast address; all these
		 * types of address have the top 4 bytes as 0x00FFFFFF.
		 */
		if (mac_eq(&gldp->ipoib_dest, macinfo->gldm_broadcast_addr,
		    sizeof (uint32_t))) {
			if (mac_eq(&gldp->ipoib_dest,
			    macinfo->gldm_broadcast_addr, IPOIB_ADDRL))
				pktinfo->isBroadcast = 1;
			else
				pktinfo->isMulticast = 1;
		}

		/*
		 * Only count bytes we will be sending over the wire
		 * or looping back.
		 */
		pktinfo->pktLen -= IPOIB_ADDRL;
		if (flags == GLD_TX)
			goto out;	/* Got all info we need for xmit case */

		/*
		 * Loopback case: this is a dup'ed message.
		 */
		mp->b_rptr += IPOIB_ADDRL;
		mac_copy(&gldp->ipoib_dest, pktinfo->dhost, IPOIB_ADDRL);
		mac_copy(mac_pvt->curr_macaddr, pktinfo->shost, IPOIB_ADDRL);
	} else {
		/*
		 * GLD_RX case; process packet sent from driver.
		 */
		ipoib_mac_t *mact, *tact;
		ib_qpn_t dqpn;

		pktinfo->pktLen = msgdsize(mp);
		/* make sure packet has at least pgrh and mac header */
		if (pktinfo->pktLen < (IPOIB_GRH_SIZE + IPOIB_HDRSIZE))
			return (-1);

		/* make sure the header falls into contiguous memory */
		if (MBLKL(mp) < (IPOIB_GRH_SIZE + IPOIB_HDRSIZE)) {
			if ((pmp = msgpullup(mp, -1)) == NULL) {
#ifdef GLD_DEBUG
				if (gld_debug & GLDERRS)
					cmn_err(CE_WARN,
					    "GLD: interpret_ib "
					    "cannot msgpullup2");
#endif
				return (-1);
			}
			/* this mblk contains the whole mac header */
			mp = pmp;
		}

		grh = (ipoib_pgrh_t *)mp->b_rptr;
		mp->b_rptr += IPOIB_GRH_SIZE;
		pktinfo->pktLen -= IPOIB_GRH_SIZE;
		if (grh->ipoib_vertcflow) {
			/*
			 * First, copy source address from grh.
			 */
			mact = (ipoib_mac_t *)pktinfo->shost;
			mac_copy(&grh->ipoib_sqpn, &mact->ipoib_qpn,
			    IPOIB_ADDRL);

			/*
			 * Then copy destination address from grh;
			 * first, the 16 bytes of GID.
			 */
			mact = (ipoib_mac_t *)pktinfo->dhost;
			mac_copy(&grh->ipoib_dgid_pref,
			    &mact->ipoib_gidpref, IPOIB_ADDRL -
			    sizeof (mact->ipoib_qpn));
			tact = (ipoib_mac_t *)mac_pvt->curr_macaddr;

			/* Is this a multicast address */
			if (*(uchar_t *)(grh->ipoib_dgid_pref) == 0xFF) {
				/*
				 * Only check for hardware looping in
				 * multicast case. It is assumed higher
				 * layer code (IP) will stop unicast loops;
				 * ie will prevent a transmit to self.
				 */
				if (bcmp(&grh->ipoib_sqpn, tact,
				    IPOIB_ADDRL) == 0)
					pktinfo->isLooped = 1;

				tact = (ipoib_mac_t *)macinfo->
				    gldm_broadcast_addr;
				if (mac_eq(tact->ipoib_gidpref,
				    grh->ipoib_dgid_pref,
				    IPOIB_ADDRL - sizeof (tact->ipoib_qpn)))
					pktinfo->isBroadcast = 1;
				else
					pktinfo->isMulticast = 1;
				/*
				 * Now copy the 4 bytes QPN part of the
				 * destination address.
				 */
				dqpn = htonl(IB_MC_QPN);
				mac_copy(&dqpn, &mact->ipoib_qpn,
				    sizeof (mact->ipoib_qpn));
			} else {
				/*
				 * Now copy the 4 bytes QPN part of the
				 * destination address.
				 */
				mac_copy(&tact->ipoib_qpn, &mact->ipoib_qpn,
				    sizeof (mact->ipoib_qpn));
				/*
				 * Any unicast packets received on IBA are
				 * for the node.
				 */
				pktinfo->isForMe = 1;
			}
		} else {
			/*
			 * It can not be a IBA multicast packet.
			 * Must have been unicast to us. We do not
			 * have shost information, which is used in
			 * gld_addudind(); IP/ARP does not care.
			 */
			pktinfo->nosource = 1;
			mac_copy(mac_pvt->curr_macaddr, pktinfo->dhost,
			    IPOIB_ADDRL);
			/*
			 * Any unicast packets received on IBA are
			 * for the node.
			 */
			pktinfo->isForMe = 1;
		}
	}

	ASSERT((flags == GLD_RX) || (flags == GLD_RXLOOP));
	ASSERT(GLDM_LOCK_HELD(macinfo));
	pktinfo->ethertype = REF_NET_USHORT(((ipoib_hdr_t *)
	    (mp->b_rptr))->ipoib_type);
	pktinfo->macLen = IPOIB_HDRSIZE;

out:
	if (pmp != NULL)
		freemsg(pmp);

	return (0);
}

/*
 * The packet format sent to the driver is: 2b sap :: 2b 0s :: data
 */
void
gld_interpret_mdt_ib(gld_mac_info_t *macinfo, mblk_t *mp, pdescinfo_t *pinfo,
    pktinfo_t *pktinfo, mdt_packet_flag_t flags)
{
	gld_mac_pvt_t *mac_pvt;
	multidata_t *dlmdp;
	pattrinfo_t attr_info = { PATTR_DSTADDRSAP, };
	pattr_t *patr;
	ipoib_ptxhdr_t *dlap = NULL;

	/*
	 * Per packet formatting.
	 */
	if (flags == GLD_MDT_TXPKT) {
		ipoib_hdr_t *hptr;
		uint_t seg;

		if (PDESC_HDRL(pinfo) == 0)
			return;

		/*
		 * Update packet's link header.
		 */
		pinfo->hdr_rptr -= IPOIB_HDRSIZE;
		hptr = (ipoib_hdr_t *)pinfo->hdr_rptr;
		hptr->ipoib_mbz = htons(0);
		hptr->ipoib_type = pktinfo->ethertype;

		/*
		 * Total #bytes that will be put on wire.
		 */
		pktinfo->pktLen = PDESC_HDRL(pinfo);
		for (seg = 0; seg < pinfo->pld_cnt; seg++)
			pktinfo->pktLen += PDESC_PLDL(pinfo, seg);

		return;
	}

	/*
	 * The following two cases of GLD_MDT_TX and GLD_MDT_RXLOOP are per
	 * MDT message processing.
	 */
	dlmdp = mmd_getmultidata(mp);
	patr = mmd_getpattr(dlmdp, NULL, &attr_info);
	ASSERT(patr != NULL);
	ASSERT(macinfo->gldm_saplen == -2);
	if (patr != NULL)
		dlap = (ipoib_ptxhdr_t *)((pattr_addr_t *)attr_info.buf)->addr;

	if (flags == GLD_MDT_TX) {
		bzero((void *)pktinfo, sizeof (*pktinfo));
		if (dlap == NULL)
			return;

		/*
		 * Check if mac is broadcast or multicast address; all these
		 * types of address have the top 4 bytes as 0x00FFFFFF.
		 */
		if (mac_eq(dlap, macinfo->gldm_broadcast_addr,
		    sizeof (uint32_t))) {
			if (mac_eq(dlap, macinfo->gldm_broadcast_addr,
			    IPOIB_ADDRL))
				pktinfo->isBroadcast = 1;
			else
				pktinfo->isMulticast = 1;
		}
		pktinfo->ethertype = REF_NET_USHORT(dlap->
		    ipoib_rhdr.ipoib_type);
	} else {
		ASSERT(flags == GLD_MDT_RXLOOP);
		pktinfo->macLen = IPOIB_HDRSIZE;
		mac_pvt = (gld_mac_pvt_t *)macinfo->gldm_mac_pvt;
		mac_copy(mac_pvt->curr_macaddr, pktinfo->shost, IPOIB_ADDRL);
		if (dlap == NULL)
			return;
		mac_copy(&dlap->ipoib_dest, pktinfo->dhost, IPOIB_ADDRL);
	}
}

mblk_t *
gld_unitdata_ib(gld_t *gld, mblk_t *mp)
{
	gld_mac_info_t *macinfo = gld->gld_mac_info;
	dl_unitdata_req_t *dlp = (dl_unitdata_req_t *)mp->b_rptr;
	ipoib_ptxhdr_t *gldp = IPOIBDLSAP(dlp, dlp->dl_dest_addr_offset);
	ipoib_mac_t dhost;
	unsigned short type;
	mblk_t *nmp;
	int hdrlen;

	ASSERT(macinfo != NULL);

	/* extract needed info from the mblk before we maybe reuse it */
	mac_copy(&gldp->ipoib_dest, &dhost, IPOIB_ADDRL);

	/* look in the unitdata request for a sap, else use bound one */
	if (dlp->dl_dest_addr_length >= DLSAPLENGTH(macinfo) &&
	    REF_HOST_USHORT(gldp->ipoib_rhdr.ipoib_type) != 0)
		type = REF_HOST_USHORT(gldp->ipoib_rhdr.ipoib_type);
	else
		type = gld->gld_sap;

	hdrlen = sizeof (ipoib_ptxhdr_t);

	/* need a buffer big enough for the headers */
	nmp = mp->b_cont;	/* where the packet payload M_DATA is */
	if (DB_REF(nmp) == 1 && MBLKHEAD(nmp) >= hdrlen) {
		/* it fits at the beginning of the first M_DATA block */
		freeb(mp);	/* don't need the M_PROTO anymore */
	} else if (DB_REF(mp) == 1 && MBLKSIZE(mp) >= hdrlen) {
		/* we can reuse the dl_unitdata_req M_PROTO mblk */
		nmp = mp;
		DB_TYPE(nmp) = M_DATA;
		nmp->b_rptr = nmp->b_wptr = DB_LIM(nmp);
	} else {
		/* we need to allocate one */
		if ((nmp = allocb(hdrlen, BPRI_MED)) == NULL)
			return (NULL);
		nmp->b_rptr = nmp->b_wptr = DB_LIM(nmp);
		linkb(nmp, mp->b_cont);
		freeb(mp);
	}

	/* Got the space, now copy in the header components */

	nmp->b_rptr -= sizeof (ipoib_ptxhdr_t);
	gldp = (ipoib_ptxhdr_t *)nmp->b_rptr;
	SET_NET_USHORT(gldp->ipoib_rhdr.ipoib_type, type);
	gldp->ipoib_rhdr.ipoib_mbz = 0;
	mac_copy(&dhost, &gldp->ipoib_dest, IPOIB_ADDRL);

	return (nmp);
}

mblk_t *
gld_fastpath_ib(gld_t *gld, mblk_t *mp)
{
	gld_mac_info_t *macinfo = gld->gld_mac_info;
	dl_unitdata_req_t *dlp = (dl_unitdata_req_t *)mp->b_cont->b_rptr;
	ipoib_ptxhdr_t *gldp = IPOIBDLSAP(dlp, dlp->dl_dest_addr_offset);
	unsigned short type;
	mblk_t *nmp;
	ipoib_ptxhdr_t *tgldp;
	int hdrlen;

	ASSERT(macinfo != NULL);

	/* look in the unitdata request for a sap, else use bound one */
	if (dlp->dl_dest_addr_length >= DLSAPLENGTH(macinfo) &&
	    REF_HOST_USHORT(gldp->ipoib_rhdr.ipoib_type) != 0)
		type = REF_HOST_USHORT(gldp->ipoib_rhdr.ipoib_type);
	else
		type = gld->gld_sap;

	hdrlen = sizeof (ipoib_ptxhdr_t);

	if ((nmp = allocb(hdrlen, BPRI_MED)) == NULL)
		return (NULL);

	nmp->b_rptr = nmp->b_wptr = DB_LIM(nmp);

	/* Got the space, now copy in the header components */

	nmp->b_rptr -= sizeof (ipoib_ptxhdr_t);
	tgldp = (ipoib_ptxhdr_t *)nmp->b_rptr;
	tgldp->ipoib_rhdr.ipoib_type = htons(type);
	tgldp->ipoib_rhdr.ipoib_mbz = 0;
	mac_copy(&gldp->ipoib_dest, &tgldp->ipoib_dest, IPOIB_ADDRL);

	return (nmp);
}

/* ==== */
/* FDDI */
/* ==== */

void
gld_init_fddi(gld_mac_info_t *macinfo)
{
	struct gldkstats *sp =
	    ((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)->kstatp->ks_data;

	/* Assumptions we make for this medium */
	ASSERT(macinfo->gldm_type == DL_FDDI);
	ASSERT(macinfo->gldm_addrlen == 6);
	ASSERT(macinfo->gldm_saplen == -2);
#ifndef	lint
	ASSERT(sizeof (struct fddi_mac_frm) == 13);
	ASSERT(sizeof (mac_addr_t) == 6);
#endif

	/* Wire address format is bit reversed from canonical format */
	macinfo->gldm_options |= GLDOPT_CANONICAL_ADDR;

	kstat_named_init(&sp->glds_fddi_mac_error,
	    "mac_errors", KSTAT_DATA_UINT32);
	kstat_named_init(&sp->glds_fddi_mac_lost,
	    "mac_lost_errors", KSTAT_DATA_UINT32);
	kstat_named_init(&sp->glds_fddi_mac_token,
	    "mac_tokens", KSTAT_DATA_UINT32);
	kstat_named_init(&sp->glds_fddi_mac_tvx_expired,
	    "mac_tvx_expired", KSTAT_DATA_UINT32);
	kstat_named_init(&sp->glds_fddi_mac_late,
	    "mac_late", KSTAT_DATA_UINT32);
	kstat_named_init(&sp->glds_fddi_mac_ring_op,
	    "mac_ring_ops", KSTAT_DATA_UINT32);
}

/*ARGSUSED*/
void
gld_uninit_fddi(gld_mac_info_t *macinfo)
{
}

int
gld_interpret_fddi(gld_mac_info_t *macinfo, mblk_t *mp, pktinfo_t *pktinfo,
    packet_flag_t flags)
{
	struct fddi_mac_frm *mh;
	gld_mac_pvt_t *mac_pvt;
	struct llc_snap_hdr *snaphdr;
	mblk_t *pmp = NULL;

	/*
	 * Quickly handle receive fastpath; FDDI does not support IPQ hack.
	 */
	if (flags == GLD_RXQUICK) {
		pktinfo->pktLen = msgdsize(mp);
		return (-1);
	}

	bzero((void *)pktinfo, sizeof (*pktinfo));

	pktinfo->pktLen = msgdsize(mp);

	/* make sure packet has at least a whole mac header */
	if (pktinfo->pktLen < sizeof (struct fddi_mac_frm))
		return (-1);

	/* make sure the mac header falls into contiguous memory */
	if (MBLKL(mp) < sizeof (struct fddi_mac_frm)) {
		if ((pmp = msgpullup(mp, -1)) == NULL) {
#ifdef GLD_DEBUG
			if (gld_debug & GLDERRS)
				cmn_err(CE_WARN,
				    "GLD: interpret_fddi cannot msgpullup");
#endif
			return (-1);
		}
		mp = pmp;	/* this mblk contains the whole mac header */
	}

	mh = (struct fddi_mac_frm *)mp->b_rptr;

	/* Check to see if the mac is a broadcast or multicast address. */
	/* NB we are still in wire format (non canonical) */
	/* mac_eq works because ether_broadcast is the same either way */
	if (mac_eq(mh->fddi_dhost, ether_broadcast, macinfo->gldm_addrlen))
		pktinfo->isBroadcast = 1;
	else if (mh->fddi_dhost[0] & 0x80)
		pktinfo->isMulticast = 1;

	if (flags == GLD_TX)
		goto out;	/* Got all info we need for xmit case */

	ASSERT(GLDM_LOCK_HELD(macinfo));

	/*
	 * Deal with the mac header
	 */

	cmac_copy(mh->fddi_dhost, pktinfo->dhost,
	    macinfo->gldm_addrlen, macinfo);
	cmac_copy(mh->fddi_shost, pktinfo->shost,
	    macinfo->gldm_addrlen, macinfo);

	mac_pvt = (gld_mac_pvt_t *)macinfo->gldm_mac_pvt;
	pktinfo->isLooped = mac_eq(pktinfo->shost,
	    mac_pvt->curr_macaddr, macinfo->gldm_addrlen);
	pktinfo->isForMe = mac_eq(pktinfo->dhost,
	    mac_pvt->curr_macaddr, macinfo->gldm_addrlen);

	pktinfo->macLen = sizeof (struct fddi_mac_frm);

	/*
	 * Before trying to look beyond the MAC header, make sure the LLC
	 * header exists, and that both it and any SNAP header are contiguous.
	 */
	if (MBLKL(mp) < sizeof (struct fddi_mac_frm) + LLC_SNAP_HDR_LEN &&
	    MBLKL(mp) < pktinfo->pktLen) {
		/*
		 * we don't have the entire packet within the first mblk (and
		 * therefore we didn't do the msgpullup above), AND the first
		 * mblk may not contain all the data we need to look at.
		 */
		ASSERT(pmp == NULL);	/* couldn't have done msgpullup above */
		if ((pmp = msgpullup(mp, -1)) == NULL) {
#ifdef GLD_DEBUG
			if (gld_debug & GLDERRS)
				cmn_err(CE_WARN,
				    "GLD: interpret_fddi cannot msgpullup2");
#endif
			goto out;	/* can't interpret this pkt further */
		}
		mp = pmp;	/* this mblk should contain everything needed */
	}

	/*
	 * Check SAP/SNAP information.
	 */
	if ((mh->fddi_fc & 0x70) == 0x50) {
		if (pktinfo->pktLen < pktinfo->macLen + LLC_HDR1_LEN)
			goto out;

		pktinfo->isLLC = 1;

		if (pktinfo->pktLen < pktinfo->macLen + LLC_SNAP_HDR_LEN)
			goto out;

		snaphdr = (struct llc_snap_hdr *)(mp->b_rptr + pktinfo->macLen);
		if (ISETHERTYPE(snaphdr)) {
			pktinfo->ethertype = REF_NET_USHORT(snaphdr->type);
			pktinfo->hdrLen = LLC_SNAP_HDR_LEN;
		}
	}
out:
	if (pmp != NULL)
		freemsg(pmp);

	return (0);
}

mblk_t *
gld_unitdata_fddi(gld_t *gld, mblk_t *mp)
{
	gld_mac_info_t *macinfo = gld->gld_mac_info;
	dl_unitdata_req_t *dlp = (dl_unitdata_req_t *)mp->b_rptr;
	struct gld_dlsap *gldp = DLSAP(dlp, dlp->dl_dest_addr_offset);
	mac_addr_t dhost;
	unsigned short type;
	mblk_t *nmp;
	struct fddi_mac_frm *mh;
	int hdrlen;

	ASSERT(macinfo);

	/* extract needed info from the mblk before we maybe reuse it */
	mac_copy(gldp->glda_addr, dhost, macinfo->gldm_addrlen);

	/* look in the unitdata request for a sap, else use bound one */
	if (dlp->dl_dest_addr_length >= DLSAPLENGTH(macinfo) &&
	    REF_HOST_USHORT(gldp->glda_sap) != 0)
		type = REF_HOST_USHORT(gldp->glda_sap);
	else
		type = gld->gld_sap;


	hdrlen = sizeof (struct fddi_mac_frm);

	/*
	 * Check whether we need to do EtherType encoding or whether the packet
	 * is LLC.
	 */
	if (type > GLD_MAX_802_SAP)
		hdrlen += sizeof (struct llc_snap_hdr);

	/* need a buffer big enough for the headers */
	nmp = mp->b_cont;	/* where the packet payload M_DATA is */
	if (DB_REF(nmp) == 1 && MBLKHEAD(nmp) >= hdrlen) {
		/* it fits at the beginning of the first M_DATA block */
		freeb(mp);	/* don't need the M_PROTO anymore */
	} else if (DB_REF(mp) == 1 && MBLKSIZE(mp) >= hdrlen) {
		/* we can reuse the dl_unitdata_req M_PROTO mblk */
		nmp = mp;
		DB_TYPE(nmp) = M_DATA;
		nmp->b_rptr = nmp->b_wptr = DB_LIM(nmp);
	} else {
		/* we need to allocate one */
		if ((nmp = allocb(hdrlen, BPRI_MED)) == NULL)
			return (NULL);
		nmp->b_rptr = nmp->b_wptr = DB_LIM(nmp);
		linkb(nmp, mp->b_cont);
		freeb(mp);
	}


	/* Got the space, now copy in the header components */
	if (type > GLD_MAX_802_SAP) {
		/* create the snap header */
		struct llc_snap_hdr *snap;
		nmp->b_rptr -= sizeof (struct llc_snap_hdr);
		snap  = (struct llc_snap_hdr *)(nmp->b_rptr);
		*snap = llc_snap_def;
		SET_NET_USHORT(snap->type, type);
	}

	nmp->b_rptr -= sizeof (struct fddi_mac_frm);

	mh = (struct fddi_mac_frm *)nmp->b_rptr;

	mh->fddi_fc = 0x50;
	cmac_copy(dhost, mh->fddi_dhost, macinfo->gldm_addrlen, macinfo);

	/*
	 * We access the mac address without the mutex to prevent
	 * mutex contention (BUG 4211361)
	 */
	cmac_copy(((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)->curr_macaddr,
	    mh->fddi_shost, macinfo->gldm_addrlen, macinfo);
	return (nmp);
}

mblk_t *
gld_fastpath_fddi(gld_t *gld, mblk_t *mp)
{
	gld_mac_info_t *macinfo = gld->gld_mac_info;
	dl_unitdata_req_t *dlp = (dl_unitdata_req_t *)mp->b_cont->b_rptr;
	struct gld_dlsap *gldp = DLSAP(dlp, dlp->dl_dest_addr_offset);
	unsigned short type;
	mblk_t *nmp;
	struct fddi_mac_frm *mh;
	int hdrlen;

	ASSERT(macinfo);

	/* look in the unitdata request for a sap, else use bound one */
	if (dlp->dl_dest_addr_length >= DLSAPLENGTH(macinfo) &&
	    REF_HOST_USHORT(gldp->glda_sap) != 0)
		type = REF_HOST_USHORT(gldp->glda_sap);
	else
		type = gld->gld_sap;

	hdrlen = sizeof (struct fddi_mac_frm);

	/*
	 * Check whether we need to do EtherType encoding or whether the packet
	 * will be LLC.
	 */
	if (type > GLD_MAX_802_SAP)
		hdrlen += sizeof (struct llc_snap_hdr);

	if ((nmp = allocb(hdrlen, BPRI_MED)) == NULL)
		return (NULL);

	nmp->b_rptr = nmp->b_wptr = DB_LIM(nmp);

	/* Got the space, now copy in the header components */

	if (type > GLD_MAX_802_SAP) {
		/* create the snap header */
		struct llc_snap_hdr *snap;
		nmp->b_rptr -= sizeof (struct llc_snap_hdr);
		snap  = (struct llc_snap_hdr *)(nmp->b_rptr);
		*snap = llc_snap_def;
		snap->type = htons(type);	/* we know it's aligned */
	}

	nmp->b_rptr -= sizeof (struct fddi_mac_frm);

	mh = (struct fddi_mac_frm *)nmp->b_rptr;
	mh->fddi_fc = 0x50;
	cmac_copy(gldp->glda_addr, mh->fddi_dhost,
	    macinfo->gldm_addrlen, macinfo);

	GLDM_LOCK(macinfo, RW_WRITER);
	cmac_copy(((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)->curr_macaddr,
	    mh->fddi_shost, macinfo->gldm_addrlen, macinfo);
	GLDM_UNLOCK(macinfo);

	return (nmp);
}

/* ========== */
/* Token Ring */
/* ========== */

#define	GLD_SR_VAR(macinfo)	\
	(((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)->data)

#define	GLD_SR_HASH(macinfo)	((struct srtab **)GLD_SR_VAR(macinfo))

#define	GLD_SR_MUTEX(macinfo)	\
	(&((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)->datalock)

static void gld_sr_clear(gld_mac_info_t *);
static void gld_rcc_receive(gld_mac_info_t *, pktinfo_t *, struct gld_ri *,
    uchar_t *, int);
static void gld_rcc_send(gld_mac_info_t *, queue_t *, uchar_t *,
    struct gld_ri **, uchar_t *);

static mac_addr_t tokenbroadcastaddr2 = { 0xc0, 0x00, 0xff, 0xff, 0xff, 0xff };
static struct gld_ri ri_ste_def;

void
gld_init_tr(gld_mac_info_t *macinfo)
{
	struct gldkstats *sp =
	    ((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)->kstatp->ks_data;

	/* avoid endian-dependent code by initializing here instead of static */
	ri_ste_def.len = 2;
	ri_ste_def.rt = RT_STE;
	ri_ste_def.mtu = RT_MTU_MAX;
	ri_ste_def.dir = 0;
	ri_ste_def.res = 0;

	/* Assumptions we make for this medium */
	ASSERT(macinfo->gldm_type == DL_TPR);
	ASSERT(macinfo->gldm_addrlen == 6);
	ASSERT(macinfo->gldm_saplen == -2);
#ifndef	lint
	ASSERT(sizeof (struct tr_mac_frm_nori) == 14);
	ASSERT(sizeof (mac_addr_t) == 6);
#endif

	mutex_init(GLD_SR_MUTEX(macinfo), NULL, MUTEX_DRIVER, NULL);

	GLD_SR_VAR(macinfo) = kmem_zalloc(sizeof (struct srtab *)*SR_HASH_SIZE,
				KM_SLEEP);

	/* Default is RDE enabled for this medium */
	((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)->rde_enabled =
	    ddi_getprop(DDI_DEV_T_NONE, macinfo->gldm_devinfo, 0,
	    "gld_rde_enable", 1);

	/*
	 * Default is to use STE for unknown paths if RDE is enabled.
	 * If RDE is disabled, default is to use NULL RIF fields.
	 *
	 * It's possible to force use of STE for ALL packets:
	 * disable RDE but enable STE.  This may be useful for
	 * non-transparent bridges, when it is not desired to run
	 * the RDE algorithms.
	 */
	((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)->rde_str_indicator_ste =
	    ddi_getprop(DDI_DEV_T_NONE, macinfo->gldm_devinfo, 0,
	    "gld_rde_str_indicator_ste",
	    ((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)->rde_enabled);

	/* Default 10 second route timeout on lack of activity */
	{
	int t = ddi_getprop(DDI_DEV_T_NONE, macinfo->gldm_devinfo, 0,
	    "gld_rde_timeout", 10);
	if (t < 1)
		t = 1;		/* Let's be reasonable */
	if (t > 600)
		t = 600;	/* Let's be reasonable */
	/* We're using ticks (lbolts) for our timeout -- convert from seconds */
	t = drv_usectohz(1000000 * t);
	((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)->rde_timeout = t;
	}

	kstat_named_init(&sp->glds_dot5_line_error,
	    "line_errors", KSTAT_DATA_UINT32);
	kstat_named_init(&sp->glds_dot5_burst_error,
	    "burst_errors", KSTAT_DATA_UINT32);
	kstat_named_init(&sp->glds_dot5_signal_loss,
	    "signal_losses", KSTAT_DATA_UINT32);

	/*
	 * only initialize the new statistics if the driver
	 * knows about them.
	 */
	if (macinfo->gldm_driver_version != GLD_VERSION_200)
		return;

	kstat_named_init(&sp->glds_dot5_ace_error,
	    "ace_errors", KSTAT_DATA_UINT32);
	kstat_named_init(&sp->glds_dot5_internal_error,
	    "internal_errors", KSTAT_DATA_UINT32);
	kstat_named_init(&sp->glds_dot5_lost_frame_error,
	    "lost_frame_errors", KSTAT_DATA_UINT32);
	kstat_named_init(&sp->glds_dot5_frame_copied_error,
	    "frame_copied_errors", KSTAT_DATA_UINT32);
	kstat_named_init(&sp->glds_dot5_token_error,
	    "token_errors", KSTAT_DATA_UINT32);
	kstat_named_init(&sp->glds_dot5_freq_error,
	    "freq_errors", KSTAT_DATA_UINT32);
}

void
gld_uninit_tr(gld_mac_info_t *macinfo)
{
	mutex_destroy(GLD_SR_MUTEX(macinfo));
	gld_sr_clear(macinfo);
	kmem_free(GLD_SR_VAR(macinfo), sizeof (struct srtab *) * SR_HASH_SIZE);
}

int
gld_interpret_tr(gld_mac_info_t *macinfo, mblk_t *mp, pktinfo_t *pktinfo,
    packet_flag_t flags)
{
	struct tr_mac_frm *mh;
	gld_mac_pvt_t *mac_pvt;
	struct llc_snap_hdr *snaphdr;
	mblk_t *pmp = NULL;
	struct gld_ri *rh;

	/*
	 * Quickly handle receive fastpath; TR does not support IPQ hack.
	 */
	if (flags == GLD_RXQUICK) {
		pktinfo->pktLen = msgdsize(mp);
		return (-1);
	}

	bzero((void *)pktinfo, sizeof (*pktinfo));

	pktinfo->pktLen = msgdsize(mp);

	/* make sure packet has at least a whole mac header */
	if (pktinfo->pktLen < sizeof (struct tr_mac_frm_nori))
		return (-1);

	/* make sure the mac header falls into contiguous memory */
	if (MBLKL(mp) < sizeof (struct tr_mac_frm_nori)) {
		if ((pmp = msgpullup(mp, -1)) == NULL) {
#ifdef GLD_DEBUG
			if (gld_debug & GLDERRS)
				cmn_err(CE_WARN,
				    "GLD: interpret_tr cannot msgpullup");
#endif
			return (-1);
		}
		mp = pmp;	/* this mblk contains the whole mac header */
	}

	mh = (struct tr_mac_frm *)mp->b_rptr;

	/* Check to see if the mac is a broadcast or multicast address. */
	if (mac_eq(mh->tr_dhost, ether_broadcast, macinfo->gldm_addrlen) ||
	    mac_eq(mh->tr_dhost, tokenbroadcastaddr2, macinfo->gldm_addrlen))
		pktinfo->isBroadcast = 1;
	else if (mh->tr_dhost[0] & 0x80)
		pktinfo->isMulticast = 1;

	if (flags == GLD_TX)
		goto out;	/* Got all info we need for xmit case */

	ASSERT(GLDM_LOCK_HELD(macinfo));

	/*
	 * Deal with the mac header
	 */

	mac_copy(mh->tr_dhost, pktinfo->dhost, macinfo->gldm_addrlen);
	mac_copy(mh->tr_shost, pktinfo->shost, macinfo->gldm_addrlen);
	pktinfo->shost[0] &= ~0x80;	/* turn off RIF indicator */

	mac_pvt = (gld_mac_pvt_t *)macinfo->gldm_mac_pvt;
	pktinfo->isLooped = mac_eq(pktinfo->shost,
	    mac_pvt->curr_macaddr, macinfo->gldm_addrlen);
	pktinfo->isForMe = mac_eq(pktinfo->dhost,
	    mac_pvt->curr_macaddr, macinfo->gldm_addrlen);

	rh = (struct gld_ri *)NULL;
	pktinfo->macLen = sizeof (struct tr_mac_frm_nori);

	/*
	 * Before trying to look beyond the MAC header, make sure the data
	 * structures are all contiguously where we can conveniently look at
	 * them.  We'll use a worst-case estimate of how many bytes into the
	 * packet data we'll be needing to look.  Things will be more efficient
	 * if the driver puts at least this much into the first mblk.
	 *
	 * Even after this, we still will have to do checks against the total
	 * length of the packet.  A bad incoming packet may not hold all the
	 * data structures it says it does.
	 */
	if (MBLKL(mp) < sizeof (struct tr_mac_frm) +
	    LLC_HDR1_LEN + sizeof (struct rde_pdu) &&
	    MBLKL(mp) < pktinfo->pktLen) {
		/*
		 * we don't have the entire packet within the first mblk (and
		 * therefore we didn't do the msgpullup above), AND the first
		 * mblk may not contain all the data we need to look at.
		 */
		ASSERT(pmp == NULL);	/* couldn't have done msgpullup above */
		if ((pmp = msgpullup(mp, -1)) == NULL) {
#ifdef GLD_DEBUG
			if (gld_debug & GLDERRS)
				cmn_err(CE_WARN,
				    "GLD: interpret_tr cannot msgpullup2");
#endif
			goto out;	/* can't interpret this pkt further */
		}
		mp = pmp;	/* this mblk should contain everything needed */
		mh = (struct tr_mac_frm *)mp->b_rptr;	/* to look at RIF */
	}

	if (mh->tr_shost[0] & 0x80) {
		/* Routing Information Field (RIF) is present */
		if (pktinfo->pktLen < sizeof (struct tr_mac_frm_nori) + 2)
			goto out;	/* RIF should have been there! */
		rh = (struct gld_ri *)&mh->tr_ri;
		if ((rh->len & 1) || rh->len < 2) {
			/* Bogus RIF, don't handle this packet */
#ifdef GLD_DEBUG
			if (gld_debug & GLDERRS)
				cmn_err(CE_WARN,
				    "GLD: received TR packet with "
				    "bogus RIF length %d",
				    rh->len);
#endif
			goto out;
		}
		if (pktinfo->pktLen < sizeof (struct tr_mac_frm_nori) + rh->len)
			goto out;	/* RIF should have been there! */
		pktinfo->macLen += rh->len;
	}

	if ((mh->tr_fc & 0xc0) == 0x40) {
		if (pktinfo->pktLen < pktinfo->macLen + LLC_HDR1_LEN)
			goto out;

		pktinfo->isLLC = 1;

		if (pktinfo->pktLen < pktinfo->macLen + LLC_SNAP_HDR_LEN)
			goto out;

		snaphdr = (struct llc_snap_hdr *)(mp->b_rptr + pktinfo->macLen);
		if (ISETHERTYPE(snaphdr)) {
			pktinfo->ethertype = REF_NET_USHORT(snaphdr->type);
			pktinfo->hdrLen = LLC_SNAP_HDR_LEN;
		}

		/* Inform the Route Control Component of received LLC frame */
		gld_rcc_receive(macinfo, pktinfo, rh,
		    mp->b_rptr + pktinfo->macLen,
		    pktinfo->pktLen - pktinfo->macLen);
	}
out:
	if (pmp != NULL)
		freemsg(pmp);

	return (0);
}

mblk_t *
gld_unitdata_tr(gld_t *gld, mblk_t *mp)
{
	gld_mac_info_t *macinfo = gld->gld_mac_info;
	dl_unitdata_req_t *dlp = (dl_unitdata_req_t *)mp->b_rptr;
	struct gld_dlsap *gldp = DLSAP(dlp, dlp->dl_dest_addr_offset);
	mac_addr_t dhost;
	unsigned short type;
	mblk_t *nmp, *llcmp, *pmp = NULL;
	struct tr_mac_frm_nori *mh;
	int hdrlen;
	struct gld_ri *rh;

	ASSERT(macinfo);

	/* extract needed info from the mblk before we maybe reuse it */
	mac_copy(gldp->glda_addr, dhost, macinfo->gldm_addrlen);

	/* look in the unitdata request for a sap, else use bound one */
	if (dlp->dl_dest_addr_length >= DLSAPLENGTH(macinfo) &&
	    REF_HOST_USHORT(gldp->glda_sap) != 0)
		type = REF_HOST_USHORT(gldp->glda_sap);
	else
		type = gld->gld_sap;

	/* includes maximum possible Routing Information Field (RIF) size */
	hdrlen = sizeof (struct tr_mac_frm);

	/*
	 * Check whether we need to do EtherType encoding or whether the packet
	 * is LLC.
	 */
	if (type > GLD_MAX_802_SAP)
		hdrlen += sizeof (struct llc_snap_hdr);

	/* need a buffer big enough for the headers */
	llcmp = nmp = mp->b_cont; /* where the packet payload M_DATA is */

	/*
	 * We are going to need to look at the LLC header, so make sure it
	 * is contiguously in a single mblk.  If we're the ones who create
	 * the LLC header (below, in the case where sap > 0xff) then we don't
	 * have to worry about it here.
	 */
	ASSERT(nmp != NULL);	/* gld_unitdata guarantees msgdsize > 0 */
	if (type <= GLD_MAX_802_SAP) {
		if (MBLKL(llcmp) < LLC_HDR1_LEN) {
			llcmp = pmp = msgpullup(nmp, LLC_HDR1_LEN);
			if (pmp == NULL) {
#ifdef GLD_DEBUG
				if (gld_debug & GLDERRS)
					cmn_err(CE_WARN,
					    "GLD: unitdata_tr "
					    "cannot msgpullup");
#endif
				return (NULL);
			}
		}
	}

	if (DB_REF(nmp) == 1 && MBLKHEAD(nmp) >= hdrlen) {
		/* it fits at the beginning of the first M_DATA block */
		freeb(mp);	/* don't need the M_PROTO anymore */
	} else if (DB_REF(mp) == 1 && MBLKSIZE(mp) >= hdrlen) {
		/* we can reuse the dl_unitdata_req M_PROTO mblk */
		nmp = mp;
		DB_TYPE(nmp) = M_DATA;
		nmp->b_rptr = nmp->b_wptr = DB_LIM(nmp);
	} else {
		/* we need to allocate one */
		if ((nmp = allocb(hdrlen, BPRI_MED)) == NULL) {
			if (pmp != NULL)
				freemsg(pmp);
			return (NULL);
		}
		nmp->b_rptr = nmp->b_wptr = DB_LIM(nmp);
		linkb(nmp, mp->b_cont);
		freeb(mp);
	}

	/* Got the space, now copy in the header components */
	if (type > GLD_MAX_802_SAP) {
		/* create the snap header */
		struct llc_snap_hdr *snap;
		llcmp = nmp;	/* LLC header is going to be in this mblk */
		nmp->b_rptr -= sizeof (struct llc_snap_hdr);
		snap  = (struct llc_snap_hdr *)(nmp->b_rptr);
		*snap = llc_snap_def;
		SET_NET_USHORT(snap->type, type);
	}

	/* Hold SR tables still while we maybe point at an entry */
	mutex_enter(GLD_SR_MUTEX(macinfo));

	gld_rcc_send(macinfo, WR(gld->gld_qptr), dhost, &rh, llcmp->b_rptr);

	if (rh != NULL) {
		/* copy in the RIF */
		ASSERT(rh->len <= sizeof (struct gld_ri));
		nmp->b_rptr -= rh->len;
		bcopy((caddr_t)rh, (caddr_t)nmp->b_rptr, rh->len);
	}

	mutex_exit(GLD_SR_MUTEX(macinfo));

	/* no longer need the pulled-up mblk */
	if (pmp != NULL)
		freemsg(pmp);

	/*
	 * fill in token ring header
	 */
	nmp->b_rptr -= sizeof (struct tr_mac_frm_nori);
	mh = (struct tr_mac_frm_nori *)nmp->b_rptr;
	mh->tr_ac = 0x10;
	mh->tr_fc = 0x40;
	mac_copy(dhost, mh->tr_dhost, macinfo->gldm_addrlen);

	/*
	 * We access the mac address without the mutex to prevent
	 * mutex contention (BUG 4211361)
	 */
	mac_copy(((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)->curr_macaddr,
	    mh->tr_shost, macinfo->gldm_addrlen);

	if (rh != NULL)
		mh->tr_shost[0] |= 0x80;
	else
		mh->tr_shost[0] &= ~0x80;

	return (nmp);
}

/*
 * We cannot have our client sending us "fastpath" M_DATA messages,
 * because to do that we must provide a fixed MAC header to
 * be prepended to each outgoing packet.  But with Source Routing
 * media, the length and content of the MAC header changes as the
 * routes change, so there is no fixed header we can provide.  So
 * we decline to accept M_DATA messages if Source Routing is enabled.
 */
mblk_t *
gld_fastpath_tr(gld_t *gld, mblk_t *mp)
{
	gld_mac_info_t *macinfo = gld->gld_mac_info;
	dl_unitdata_req_t *dlp = (dl_unitdata_req_t *)mp->b_cont->b_rptr;
	struct gld_dlsap *gldp = DLSAP(dlp, dlp->dl_dest_addr_offset);
	unsigned short type;
	mblk_t *nmp;
	struct tr_mac_frm_nori *mh;
	int hdrlen;

	ASSERT(macinfo);

	/*
	 * If we are doing Source Routing, then we cannot provide a fixed
	 * MAC header, so fail.
	 */
	if (((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)->rde_enabled)
		return (NULL);

	/* look in the unitdata request for a sap, else use bound one */
	if (dlp->dl_dest_addr_length >= DLSAPLENGTH(macinfo) &&
	    REF_HOST_USHORT(gldp->glda_sap) != 0)
		type = REF_HOST_USHORT(gldp->glda_sap);
	else
		type = gld->gld_sap;

	hdrlen = sizeof (struct tr_mac_frm_nori);

	if (((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)->rde_str_indicator_ste)
		hdrlen += ri_ste_def.len;

	/*
	 * Check whether we need to do EtherType encoding or whether the packet
	 * will be LLC.
	 */
	if (type > GLD_MAX_802_SAP)
		hdrlen += sizeof (struct llc_snap_hdr);

	if ((nmp = allocb(hdrlen, BPRI_MED)) == NULL)
		return (NULL);

	nmp->b_rptr = nmp->b_wptr = DB_LIM(nmp);

	/* Got the space, now copy in the header components */

	if (type > GLD_MAX_802_SAP) {
		/* create the snap header */
		struct llc_snap_hdr *snap;
		nmp->b_rptr -= sizeof (struct llc_snap_hdr);
		snap  = (struct llc_snap_hdr *)(nmp->b_rptr);
		*snap = llc_snap_def;
		snap->type = htons(type);	/* we know it's aligned */
	}

	/* RDE is disabled, use NULL RIF, or STE RIF */
	if (((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)->rde_str_indicator_ste) {
		nmp->b_rptr -= ri_ste_def.len;
		bcopy((caddr_t)&ri_ste_def, (caddr_t)nmp->b_rptr,
		    ri_ste_def.len);
	}

	/*
	 * fill in token ring header
	 */
	nmp->b_rptr -= sizeof (struct tr_mac_frm_nori);
	mh = (struct tr_mac_frm_nori *)nmp->b_rptr;
	mh->tr_ac = 0x10;
	mh->tr_fc = 0x40;
	mac_copy(gldp->glda_addr, mh->tr_dhost, macinfo->gldm_addrlen);

	GLDM_LOCK(macinfo, RW_WRITER);
	mac_copy(((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)->curr_macaddr,
	    mh->tr_shost, macinfo->gldm_addrlen);
	GLDM_UNLOCK(macinfo);

	if (((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)->rde_str_indicator_ste)
		mh->tr_shost[0] |= 0x80;
	else
		mh->tr_shost[0] &= ~0x80;

	return (nmp);
}

/*
 * Route Determination Entity (ISO 8802-2 / IEEE 802.2 : 1994, Section 9)
 *
 * RDE is an LLC layer entity.  GLD is a MAC layer entity.  The proper
 * solution to this architectural anomaly is to move RDE support out of GLD
 * and into LLC where it belongs.  In particular, only LLC has the knowledge
 * necessary to reply to XID and TEST packets.  If and when it comes time to
 * move RDE out of GLD to LLC, the LLC-to-GLD interface should be modified
 * to use MA_UNITDATA structures rather than DL_UNITDATA structures.  Of
 * course, GLD will still have to continue to also support the DL_ structures
 * as long as IP is not layered over LLC.  Another, perhaps better, idea
 * would be to make RDE an autopush module on top of the token ring drivers:
 * RDE would sit between LLC and GLD.  It would then also sit between IP and
 * GLD, providing services to all clients of GLD/tokenring.  In that case,
 * GLD would still have to continue to support the DL_ interface for non-
 * Token Ring interfaces, using the MA_ interface only for media supporting
 * Source Routing media.
 *
 * At present, Token Ring is the only source routing medium we support.
 * Since Token Ring is not at this time a strategic network medium for Sun,
 * rather than devote a large amount of resources to creating a proper
 * architecture and implementation of RDE, we do the minimum necessary to
 * get it to work.  The interface between the above token ring code and the
 * below RDE code is designed to make it relatively easy to change to an
 * MA_UNITDATA model later should this ever become a priority.
 */

static void gld_send_rqr(gld_mac_info_t *, uchar_t *, struct gld_ri *,
    struct rde_pdu *, int);
static void gld_rde_pdu_req(gld_mac_info_t *, queue_t *, uchar_t *,
    struct gld_ri *, uchar_t, uchar_t, uchar_t);
static void gld_get_route(gld_mac_info_t *, queue_t *, uchar_t *,
    struct gld_ri **, uchar_t, uchar_t);
static void gld_reset_route(gld_mac_info_t *, queue_t *,
    uchar_t *, uchar_t, uchar_t);
static void gld_rde_pdu_ind(gld_mac_info_t *, struct gld_ri *, struct rde_pdu *,
    int);
static void gld_rif_ind(gld_mac_info_t *, struct gld_ri *, uchar_t *,
    uchar_t, uchar_t);
static struct srtab **gld_sr_hash(struct srtab **, uchar_t *, int);
static struct srtab *gld_sr_lookup_entry(gld_mac_info_t *, uchar_t *);
static struct srtab *gld_sr_create_entry(gld_mac_info_t *, uchar_t *);

/*
 * This routine implements a modified subset of the 802.2 RDE RCC receive
 * actions:
 *   we implement RCC receive events 3 to 12 (ISO 8802-2:1994 9.6.3.4);
 *   we omit special handling for the NULL SAP;
 *   we omit XID/TEST handling;
 *   we pass all packets (including RDE) upstream to LLC.
 */
static void
gld_rcc_receive(gld_mac_info_t *macinfo, pktinfo_t *pktinfo, struct gld_ri *rh,
    uchar_t *llcpkt, int llcpktlen)
{
	struct llc_snap_hdr *snaphdr = (struct llc_snap_hdr *)(llcpkt);

	if (!((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)->rde_enabled)
		return;

	/*
	 * First, ensure this packet wasn't something we received just
	 * because we were in promiscuous mode.  Since none of the below
	 * code wants to see group addressed packets anyway, we can do
	 * this check up front.  Since we're doing that, we can omit the
	 * checks for group addressed packets below.
	 */
	if (!pktinfo->isForMe)
		return;		/* Event 6 */

	/* Process a subset of Route Determination Entity (RDE) packets */
	if (snaphdr->d_lsap == LSAP_RDE) {
		struct rde_pdu *pdu = (struct rde_pdu *)(llcpkt + LLC_HDR1_LEN);
		int pdulen = llcpktlen - LLC_HDR1_LEN;

		/* sanity check the PDU */
		if ((pdulen < sizeof (struct rde_pdu)) ||
		    (snaphdr->s_lsap != LSAP_RDE))
			return;

		/* we only handle route discovery PDUs, not XID/TEST/other */
		if (snaphdr->control != CNTL_LLC_UI)
			return;

		switch (pdu->rde_ptype) {
		case RDE_RQC:	/* Route Query Command; Events 8 - 11 */
			gld_send_rqr(macinfo, pktinfo->shost, rh, pdu, pdulen);
			/* FALLTHROUGH */
		case RDE_RQR:	/* Route Query Response; Event 12 */
		case RDE_RS:	/* Route Selected; Event 7 */
			gld_rde_pdu_ind(macinfo, rh, pdu, pdulen);
			break;
		default:	/* ignore if unrecognized ptype */
			return;
		}

		return;
	}

	/* Consider routes seen in other IA SRF packets */

	if (rh == NULL)
		return;		/* no RIF; Event 3 */

	if ((rh->rt & 0x04) != 0)
		return;		/* not SRF; Event 5 */

	gld_rif_ind(macinfo, rh, pktinfo->shost, snaphdr->s_lsap,
	    snaphdr->d_lsap);	/* Event 4 */
}

/*
 * Send RQR: 802.2 9.6.3.4.2(9) RCC Receive Events 8-11
 *
 * The routing processing really doesn't belong here; it should be handled in
 * the LLC layer above.  If that were the case then RDE could just send down
 * an extra MA_UNITDATA_REQ with the info needed to construct the packet.  But
 * at the time we get control here, it's not a particularly good time to be
 * constructing packets and trying to send them.  Specifically, at this layer
 * we need to construct the full media packet, which means the below routine
 * knows that it is dealing with Token Ring media.  If this were instead done
 * via a proper MA_UNITDATA interface, the RDE stuff could all be completely
 * media independent.  But since TR is the only source routing medium we
 * support, this works even though it is not clean.
 *
 * We "know" that the only time we can get here is from the "interpret"
 * routine, and only when it was called at receive time.
 */
static void
gld_send_rqr(gld_mac_info_t *macinfo, uchar_t *shost, struct gld_ri *rh,
    struct rde_pdu *pdu, int pdulen)
{
	mblk_t *nmp;
	int nlen;
	struct tr_mac_frm_nori *nmh;
	struct gld_ri *nrh;
	struct llc_snap_hdr *nsnaphdr;
	struct rde_pdu *npdu;

	/* We know and assume we're on the receive path */
	ASSERT(GLDM_LOCK_HELD(macinfo));

	if (pdulen < sizeof (struct rde_pdu))
		return;		/* Bad incoming PDU */

	nlen = sizeof (struct tr_mac_frm) + LLC_HDR1_LEN +
	    sizeof (struct rde_pdu);

	if ((nmp = allocb(nlen, BPRI_MED)) == NULL)
		return;

	nmp->b_rptr = nmp->b_wptr = DB_LIM(nmp);

	nmp->b_rptr -= sizeof (struct rde_pdu);
	npdu = (struct rde_pdu *)(nmp->b_rptr);
	*npdu = *pdu;	/* copy orig/target macaddr/saps */
	npdu->rde_ver = 1;
	npdu->rde_ptype = RDE_RQR;
	mac_copy(((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)->curr_macaddr,
	    npdu->rde_target_mac, macinfo->gldm_addrlen);

	nmp->b_rptr -= LLC_HDR1_LEN;
	nsnaphdr = (struct llc_snap_hdr *)(nmp->b_rptr);
	nsnaphdr->s_lsap = nsnaphdr->d_lsap = LSAP_RDE;
	nsnaphdr->control = CNTL_LLC_UI;

	if (rh == NULL || (rh->rt & 0x06) == 0x06 ||
	    rh->len > sizeof (struct gld_ri)) {
		/* no RIF (Event 8), or RIF type STE (Event 9): send ARE RQR */
		nmp->b_rptr -= 2;
		nrh = (struct gld_ri *)(nmp->b_rptr);
		nrh->len = 2;
		nrh->rt = RT_ARE;
		nrh->dir = 0;
		nrh->res = 0;
		nrh->mtu = RT_MTU_MAX;
	} else {
		/*
		 * RIF must be ARE (Event 10) or SRF (Event 11):
		 * send SRF (reverse) RQR
		 */
		ASSERT(rh->len <= sizeof (struct gld_ri));
		nmp->b_rptr -= rh->len;
		nrh = (struct gld_ri *)(nmp->b_rptr);
		bcopy(rh, nrh, rh->len);	/* copy incoming RIF */
		nrh->rt = RT_SRF;		/* make it SRF */
		nrh->dir ^= 1;			/* reverse direction */
	}

	nmp->b_rptr -= sizeof (struct tr_mac_frm_nori);
	nmh = (struct tr_mac_frm_nori *)(nmp->b_rptr);
	nmh->tr_ac = 0x10;
	nmh->tr_fc = 0x40;
	mac_copy(shost, nmh->tr_dhost, macinfo->gldm_addrlen);
	mac_copy(((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)->curr_macaddr,
	    nmh->tr_shost, macinfo->gldm_addrlen);
	nmh->tr_shost[0] |= 0x80;		/* indicate RIF present */

	/*
	 * Packet assembled; send it.
	 *
	 * As noted before, this is not really a good time to be trying to
	 * send out packets.  We have no obvious queue to use if the packet
	 * can't be sent right away.  We pick one arbitrarily.
	 */
	{
	gld_vlan_t *vlan;
	queue_t *q;

	if ((vlan = gld_find_vlan(macinfo, VLAN_VID_NONE)) == NULL) {
		/* oops, no vlan on the list for this macinfo! */
		/* this should not happen */
		freeb(nmp);
		return;
	}
	q = vlan->gldv_str_next->gld_qptr;

	/*
	 * Queue the packet and let gld_wsrv
	 * handle it, thus preventing a panic
	 * caused by v2 TR in promiscuous mode
	 * where it attempts to get the mutex
	 * in this thread while already holding
	 * it.
	 */
	(void) putbq(WR(q), nmp);
	qenable(WR(q));
	}
}

/*
 * This routine implements a modified subset of the 802.2 RDE RCC send actions:
 *   we implement RCC send events 5 to 10 (ISO 8802-2:1994 9.6.3.5);
 *   we omit special handling for the NULL SAP;
 *   events 11 to 12 are handled by gld_rde_pdu_req below;
 *   we require an immediate response to our GET_ROUTE_REQUEST.
 */
static void
gld_rcc_send(gld_mac_info_t *macinfo, queue_t *q, uchar_t *dhost,
    struct gld_ri **rhp, uchar_t *llcpkt)
{
	struct llc_snap_hdr *snaphdr = (struct llc_snap_hdr *)(llcpkt);

	/*
	 * Our caller has to take the mutex because: to avoid an extra bcopy
	 * of the RIF on every transmit, we pass back a pointer to our sr
	 * table entry via rhp.  The caller has to keep the mutex until it has a
	 * chance to copy the RIF out into the outgoing packet, so that we
	 * don't modify the entry while it's being copied.  This is a
	 * little ugly, but saves the extra bcopy.
	 */
	ASSERT(mutex_owned(GLD_SR_MUTEX(macinfo)));

	*rhp = (struct gld_ri *)NULL;	/* start off clean (no RIF) */

	if (!((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)->rde_enabled) {
		/* RDE is disabled -- use NULL or STE always */
		if (((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)->
		    rde_str_indicator_ste)
			*rhp = &ri_ste_def;	/* STE option */
		return;
	}

	if (!(dhost[0] & 0x80)) {
		/* individual address; Events 7 - 10 */
		if ((snaphdr->control & 0xef) == 0xe3) {
			/* TEST command, reset the route */
			gld_reset_route(macinfo, q,
			    dhost, snaphdr->d_lsap, snaphdr->s_lsap);
		}
		gld_get_route(macinfo, q,
		    dhost, rhp, snaphdr->d_lsap, snaphdr->s_lsap);
	}

	if (*rhp == NULL) {
		/*
		 * group address (Events 5 - 6),
		 * or no route available (Events 8 - 9):
		 * Need to send NSR or STE, as configured.
		 */
		if (((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)->
		    rde_str_indicator_ste)
			*rhp = &ri_ste_def;	/* STE option */
	}
}

/*
 * RCC send events 11 - 12
 *
 * At present we only handle the RQC ptype.
 *
 * We "know" that the only time we can get here is from the "unitdata"
 * routine, called at wsrv time.
 *
 * If we ever implement the RS ptype (Event 13), this may no longer be true!
 */
static void
gld_rde_pdu_req(gld_mac_info_t *macinfo, queue_t *q, uchar_t *dhost,
    struct gld_ri *rh, uchar_t dsap, uchar_t ssap, uchar_t ptype)
{
	mblk_t *nmp;
	int nlen;
	struct tr_mac_frm_nori *nmh;
	struct gld_ri *nrh;
	struct llc_snap_hdr *nsnaphdr;
	struct rde_pdu *npdu;
	int srpresent = 0;

	/* if you change this to process other types, review all code below */
	ASSERT(ptype == RDE_RQC);
	ASSERT(rh == NULL);	/* RQC never uses SRF */

	nlen = sizeof (struct tr_mac_frm) + LLC_HDR1_LEN +
	    sizeof (struct rde_pdu);

	if ((nmp = allocb(nlen, BPRI_MED)) == NULL)
		return;

	nmp->b_rptr = nmp->b_wptr = DB_LIM(nmp);

	nmp->b_rptr -= sizeof (struct rde_pdu);
	npdu = (struct rde_pdu *)(nmp->b_rptr);
	npdu->rde_ver = 1;
	npdu->rde_ptype = ptype;
	mac_copy(dhost, &npdu->rde_target_mac, 6);

	/*
	 * access the mac address without a mutex - take a risk -
	 * to prevent mutex contention (BUG 4211361)
	 */
	mac_copy(((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)->curr_macaddr,
	    &npdu->rde_orig_mac, 6);
	npdu->rde_target_sap = dsap;
	npdu->rde_orig_sap = ssap;

	nmp->b_rptr -= LLC_HDR1_LEN;
	nsnaphdr = (struct llc_snap_hdr *)(nmp->b_rptr);
	nsnaphdr->s_lsap = nsnaphdr->d_lsap = LSAP_RDE;
	nsnaphdr->control = CNTL_LLC_UI;

#if 0	/* we don't need this for now */
	if (rh != NULL) {
		/* send an SRF frame with specified RIF */
		ASSERT(rh->len <= sizeof (struct gld_ri));
		nmp->b_rptr -= rh->len;
		nrh = (struct gld_ri *)(nmp->b_rptr);
		bcopy(rh, nrh, rh->len);
		ASSERT(nrh->rt == RT_SRF);
		srpresent = 1;
	} else
#endif

	/* Need to send NSR or STE, as configured.  */
	if (((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)->rde_str_indicator_ste) {
		/* send an STE frame */
		nmp->b_rptr -= 2;
		nrh = (struct gld_ri *)(nmp->b_rptr);
		nrh->len = 2;
		nrh->rt = RT_STE;
		nrh->dir = 0;
		nrh->res = 0;
		nrh->mtu = RT_MTU_MAX;
		srpresent = 1;
	} /* else send an NSR frame */

	nmp->b_rptr -= sizeof (struct tr_mac_frm_nori);
	nmh = (struct tr_mac_frm_nori *)(nmp->b_rptr);
	nmh->tr_ac = 0x10;
	nmh->tr_fc = 0x40;
	mac_copy(dhost, nmh->tr_dhost, macinfo->gldm_addrlen);
	/*
	 * access the mac address without a mutex - take a risk -
	 * to prevent mutex contention  - BUG 4211361
	 */
	mac_copy(((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)->curr_macaddr,
	    nmh->tr_shost, macinfo->gldm_addrlen);

	if (srpresent)
		nmh->tr_shost[0] |= 0x80;
	else
		nmh->tr_shost[0] &= ~0x80;

	/*
	 * Packet assembled; send it.
	 *
	 * Since we own the SR_MUTEX, we don't want to take the maclock
	 * mutex (since they are acquired in the opposite order on the
	 * receive path, so deadlock could occur).  We could rearrange
	 * the code in gld_get_route() and drop the SR_MUTEX around the
	 * call to gld_rde_pdu_req(), but that's kind of ugly.  Rather,
	 * we just refrain from calling gld_start() from here, and
	 * instead just queue the packet for wsrv to send next.  Besides,
	 * it's more important to get the packet we're working on out
	 * quickly than this RQC.
	 */
	(void) putbq(WR(q), nmp);
	qenable(WR(q));
}

/*
 * Route Determination Component (RDC)
 *
 * We do not implement separate routes for each SAP, as specified by
 * ISO 8802-2; instead we implement only one route per remote mac address.
 */
static void
gld_get_route(gld_mac_info_t *macinfo, queue_t *q, uchar_t *dhost,
    struct gld_ri **rhp, uchar_t dsap, uchar_t ssap)
{
	struct srtab *sr;
	clock_t t = ddi_get_lbolt();

	ASSERT(mutex_owned(GLD_SR_MUTEX(macinfo)));

	sr = gld_sr_lookup_entry(macinfo, dhost);

	if (sr == NULL) {
		/*
		 * we have no entry -- never heard of this address:
		 * create an empty entry and initiate RQC
		 */
		sr = gld_sr_create_entry(macinfo, dhost);
		gld_rde_pdu_req(macinfo, q, dhost, (struct gld_ri *)NULL,
		    dsap, ssap, RDE_RQC);
		if (sr)
			sr->sr_timer = t;
		*rhp = NULL;		/* we have no route yet */
		return;
	}

	/* we have an entry; see if we know a route yet */

	if (sr->sr_ri.len == 0) {
		/* Have asked RQC, but no reply (yet) */
		if (t - sr->sr_timer >
		    ((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)->rde_timeout) {
			/* RQR overdue, resend RQC */
			gld_rde_pdu_req(macinfo, q, dhost,
			    (struct gld_ri *)NULL, dsap, ssap, RDE_RQC);
			sr->sr_timer = t;
		}
		*rhp = NULL;		/* we have no route yet */
		return;
	}

	/* we know a route, or it's local */

	/* if it might be stale, reset and get a new one */
	if (t - sr->sr_timer >
	    ((gld_mac_pvt_t *)macinfo->gldm_mac_pvt)->rde_timeout) {
		gld_rde_pdu_req(macinfo, q, dhost,
		    (struct gld_ri *)NULL, dsap, ssap, RDE_RQC);
		sr->sr_ri.len = 0;
		sr->sr_timer = t;
		*rhp = NULL;		/* we have no route */
		return;
	}

	if (sr->sr_ri.len == 2) {
		/* the remote site is on our local ring -- no route needed */
		*rhp = NULL;
		return;
	}

	*rhp = &sr->sr_ri;	/* we have a route, return it */
}

/*
 * zap the specified entry and reinitiate RQC
 */
static void
gld_reset_route(gld_mac_info_t *macinfo, queue_t *q,
    uchar_t *dhost, uchar_t dsap, uchar_t ssap)
{
	struct srtab *sr;

	ASSERT(mutex_owned(GLD_SR_MUTEX(macinfo)));

	sr = gld_sr_create_entry(macinfo, dhost);
	gld_rde_pdu_req(macinfo, q, dhost, (struct gld_ri *)NULL,
	    dsap, ssap, RDE_RQC);
	if (sr == NULL)
		return;

	sr->sr_ri.len = 0;
	sr->sr_timer = ddi_get_lbolt();
}

/*
 * This routine is called when an RDE PDU is received from our peer.
 * If it is an RS (Route Selected) PDU, we adopt the specified route.
 * If it is an RQR (reply to our previous RQC), we evaluate the
 * specified route in comparison with our current known route, if any,
 * and we keep the "better" of the two routes.
 */
static void
gld_rde_pdu_ind(gld_mac_info_t *macinfo, struct gld_ri *rh, struct rde_pdu *pdu,
    int pdulen)
{
	struct srtab *sr;
	uchar_t *otherhost;

	if (pdulen < sizeof (struct rde_pdu))
		return;		/* Bad incoming PDU */

	if (pdu->rde_ptype == RDE_RQC)
		return;			/* ignore RQC */

	if (pdu->rde_ptype != RDE_RQR && pdu->rde_ptype != RDE_RS) {
#ifdef GLD_DEBUG
		if (gld_debug & GLDERRS)
			cmn_err(CE_WARN, "gld: bogus RDE ptype 0x%x received",
			    pdu->rde_ptype);
#endif
		return;
	}

	if (rh == NULL) {
#ifdef GLD_DEBUG
		if (gld_debug & GLDERRS)
			cmn_err(CE_WARN,
			    "gld: bogus NULL RIF, ptype 0x%x received",
			    pdu->rde_ptype);
#endif
		return;
	}

	ASSERT(rh->len >= 2);
	ASSERT(rh->len <= sizeof (struct gld_ri));
	ASSERT((rh->len & 1) == 0);

	if (pdu->rde_ptype == RDE_RQR) {
		/* A reply to our RQC has its address as target mac */
		otherhost = pdu->rde_target_mac;
	} else {
		ASSERT(pdu->rde_ptype == RDE_RS);
		/* An RS has its address as orig mac */
		otherhost = pdu->rde_orig_mac;
	}

	mutex_enter(GLD_SR_MUTEX(macinfo));

	if ((sr = gld_sr_create_entry(macinfo, otherhost)) == NULL) {
		mutex_exit(GLD_SR_MUTEX(macinfo));
		return;		/* oh well, out of memory */
	}

	if (pdu->rde_ptype == RDE_RQR) {
		/* see if new route is better than what we may already have */
		if (sr->sr_ri.len != 0 &&
		    sr->sr_ri.len <= rh->len) {
			mutex_exit(GLD_SR_MUTEX(macinfo));
			return;	/* we have one, and new one is no shorter */
		}
	}

	/* adopt the new route */
	bcopy((caddr_t)rh, (caddr_t)&sr->sr_ri, rh->len); /* copy incom RIF */
	sr->sr_ri.rt = RT_SRF;	/* make it a clean SRF */
	sr->sr_ri.dir ^= 1;	/* reverse direction */
	sr->sr_timer = ddi_get_lbolt();

	mutex_exit(GLD_SR_MUTEX(macinfo));
}

/*
 * This routine is called when a packet with a RIF is received.  Our
 * policy is to adopt the route.
 */
/* ARGSUSED3 */
static void
gld_rif_ind(gld_mac_info_t *macinfo, struct gld_ri *rh, uchar_t *shost,
    uchar_t ssap, uchar_t dsap)
{
	struct srtab *sr;

	ASSERT(rh != NULL);		/* ensure RIF */
	ASSERT((rh->rt & 0x04) == 0);	/* ensure SRF */
	ASSERT(rh->len >= 2);
	ASSERT(rh->len <= sizeof (struct gld_ri));
	ASSERT((rh->len & 1) == 0);

	mutex_enter(GLD_SR_MUTEX(macinfo));

	if ((sr = gld_sr_create_entry(macinfo, shost)) == NULL) {
		mutex_exit(GLD_SR_MUTEX(macinfo));
		return;		/* oh well, out of memory */
	}

	/* we have an entry; fill it in */
	bcopy((caddr_t)rh, (caddr_t)&sr->sr_ri, rh->len); /* copy incom RIF */
	sr->sr_ri.rt = RT_SRF;	/* make it a clean SRF */
	sr->sr_ri.dir ^= 1;	/* reverse direction */
	sr->sr_timer = ddi_get_lbolt();

	mutex_exit(GLD_SR_MUTEX(macinfo));
}

static struct srtab **
gld_sr_hash(struct srtab **sr_hash_tbl, uchar_t *addr, int addr_length)
{
	uint_t hashval = 0;

	while (--addr_length >= 0)
		hashval ^= *addr++;

	return (&sr_hash_tbl[hashval % SR_HASH_SIZE]);
}

static struct srtab *
gld_sr_lookup_entry(gld_mac_info_t *macinfo, uchar_t *macaddr)
{
	struct srtab *sr;

	ASSERT(mutex_owned(GLD_SR_MUTEX(macinfo)));

	for (sr = *gld_sr_hash(GLD_SR_HASH(macinfo), macaddr,
	    macinfo->gldm_addrlen); sr; sr = sr->sr_next)
		if (mac_eq(macaddr, sr->sr_mac, macinfo->gldm_addrlen))
			return (sr);

	return ((struct srtab *)0);
}

static struct srtab *
gld_sr_create_entry(gld_mac_info_t *macinfo, uchar_t *macaddr)
{
	struct srtab *sr;
	struct srtab **srp;

	ASSERT(!(macaddr[0] & 0x80));	/* no group addresses here */
	ASSERT(mutex_owned(GLD_SR_MUTEX(macinfo)));

	srp = gld_sr_hash(GLD_SR_HASH(macinfo), macaddr, macinfo->gldm_addrlen);

	for (sr = *srp; sr; sr = sr->sr_next)
		if (mac_eq(macaddr, sr->sr_mac, macinfo->gldm_addrlen))
			return (sr);

	if (!(sr = kmem_zalloc(sizeof (struct srtab), KM_NOSLEEP))) {
#ifdef GLD_DEBUG
		if (gld_debug & GLDERRS)
			cmn_err(CE_WARN,
			    "gld: gld_sr_create_entry kmem_alloc failed");
#endif
		return ((struct srtab *)0);
	}

	bcopy((caddr_t)macaddr, (caddr_t)sr->sr_mac, macinfo->gldm_addrlen);

	sr->sr_next = *srp;
	*srp = sr;
	return (sr);
}

static void
gld_sr_clear(gld_mac_info_t *macinfo)
{
	int i;
	struct srtab **sr_hash_tbl = GLD_SR_HASH(macinfo);
	struct srtab **srp, *sr;

	/*
	 * Walk through the table, deleting all entries.
	 *
	 * Only called from uninit, so don't need the mutex.
	 */
	for (i = 0; i < SR_HASH_SIZE; i++) {
		for (srp = &sr_hash_tbl[i]; (sr = *srp) != NULL; ) {
			*srp = sr->sr_next;
			kmem_free((char *)sr, sizeof (struct srtab));
		}
	}
}

#ifdef	DEBUG
void
gld_sr_dump(gld_mac_info_t *macinfo)
{
	int i, j;
	struct srtab **sr_hash_tbl;
	struct srtab *sr;

	sr_hash_tbl = GLD_SR_HASH(macinfo);
	if (sr_hash_tbl == NULL)
		return;

	mutex_enter(GLD_SR_MUTEX(macinfo));

	/*
	 * Walk through the table, printing all entries
	 */
	cmn_err(CE_NOTE, "GLD Source Routing Table (0x%p):", (void *)macinfo);
	cmn_err(CE_CONT, "Addr len,rt,dir,mtu,res rng,brg0 rng,brg1...\n");
	for (i = 0; i < SR_HASH_SIZE; i++) {
		for (sr = sr_hash_tbl[i]; sr; sr = sr->sr_next) {
			cmn_err(CE_CONT,
			    "%x:%x:%x:%x:%x:%x %d,%x,%x,%x,%x ",
			    sr->sr_mac[0], sr->sr_mac[1], sr->sr_mac[2],
			    sr->sr_mac[3], sr->sr_mac[4], sr->sr_mac[5],
			    sr->sr_ri.len, sr->sr_ri.rt, sr->sr_ri.dir,
			    sr->sr_ri.mtu, sr->sr_ri.res);
			if (sr->sr_ri.len)
				for (j = 0; j < (sr->sr_ri.len - 2) / 2; j++)
					cmn_err(CE_CONT, "%x ",
					    REF_NET_USHORT(*(unsigned short *)
					    &sr->sr_ri.rd[j]));
			cmn_err(CE_CONT, "\n");
		}
	}

	mutex_exit(GLD_SR_MUTEX(macinfo));
}
#endif
