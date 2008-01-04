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

/*
 * DL_IB MAC Type plugin for the Nemo mac module
 */

#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/dlpi.h>
#include <sys/ib/clients/ibd/ibd.h>
#include <sys/mac.h>
#include <sys/mac_ib.h>
#include <sys/dls.h>
#include <sys/byteorder.h>
#include <sys/strsun.h>
#include <inet/common.h>
#include <sys/note.h>

static uint8_t ib_brdcst[] = { 0x00, 0xff, 0xff, 0xff,
    0xff, 0x10, 0x40, 0x1b, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff };

static struct modlmisc mac_ib_modlmisc = {
	&mod_miscops,
	"Infiniband MAC Type plugin 1.0"
};

static struct modlinkage mac_ib_modlinkage = {
	MODREV_1,
	&mac_ib_modlmisc,
	NULL
};

static mactype_ops_t mac_ib_type_ops;

int
_init(void)
{
	mactype_register_t *mtrp;
	int	err;

	if ((mtrp = mactype_alloc(MACTYPE_VERSION)) == NULL)
		return (ENOTSUP);
	mtrp->mtr_ident = MAC_PLUGIN_IDENT_IB;
	mtrp->mtr_ops = &mac_ib_type_ops;
	mtrp->mtr_mactype = DL_IB;
	mtrp->mtr_addrlen = IPOIB_ADDRL;
	mtrp->mtr_brdcst_addr = ib_brdcst;

	/*
	 * So far, generic stats maintained by GLDv3 are sufficient for IB.
	 */
	mtrp->mtr_stats = NULL;
	mtrp->mtr_statcount = 0;
	if ((err = mactype_register(mtrp)) == 0) {
		if ((err = mod_install(&mac_ib_modlinkage)) != 0)
			(void) mactype_unregister(MAC_PLUGIN_IDENT_IB);
	}
	mactype_free(mtrp);
	return (err);
}

int
_fini(void)
{
	int	err;

	if ((err = mactype_unregister(MAC_PLUGIN_IDENT_IB)) != 0)
		return (err);
	return (mod_remove(&mac_ib_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&mac_ib_modlinkage, modinfop));
}

/*
 * MAC Type plugin operations
 */

/* ARGSUSED */
int
mac_ib_unicst_verify(const void *addr, void *mac_pdata)
{
	ipoib_mac_t *ibaddr = (ipoib_mac_t *)addr;

	/*
	 * The address must not be a multicast address.
	 */
	return (ntohl(ibaddr->ipoib_qpn) == IB_MC_QPN ? EINVAL : 0);
}

int
mac_ib_multicst_verify(const void *addr, void *mac_pdata)
{
	ipoib_mac_t *ibaddr = (ipoib_mac_t *)addr;
	uint8_t *p_gid = (uint8_t *)addr + sizeof (ipoib_mac_t)
	    - MAC_IB_GID_SIZE;
	uint32_t bcst_gid[3] = { 0x0, 0x0, MAC_IB_BROADCAST_GID };

	_NOTE(ARGUNUSED(mac_pdata));

	/*
	 * The address must be a multicast address.
	 */
	if ((ntohl(ibaddr->ipoib_qpn) & IB_QPN_MASK) != IB_MC_QPN)
		return (EINVAL);

	/*
	 * The address must not be the broadcast address.
	 */
	if (bcmp(p_gid, (uint8_t *)bcst_gid + sizeof (bcst_gid) -
	    MAC_IB_GID_SIZE, MAC_IB_GID_SIZE) == 0)
		return (EINVAL);

	return (0);
}

/*
 * Check the legality of a SAP value. The following values are
 * allowed, as specified by PSARC 2003/150:
 *
 * min-ethertype-sap (256).. EtherType max(65535)	ethertype semantics
 *        (0)             .. max-802-sap(255)		IEEE 802 semantics
 */
boolean_t
mac_ib_sap_verify(uint32_t sap, uint32_t *bind_sap, void *mac_pdata)
{
	_NOTE(ARGUNUSED(mac_pdata));

	if (sap > MAC_IB_MAX_802_SAP && sap <= MAC_IB_ETHERTYPE_MAX) {
		if (bind_sap != NULL)
			*bind_sap = sap;
		return (B_TRUE);
	}

	if (sap <= MAC_IB_MAX_802_SAP) {
		if (bind_sap != NULL)
			*bind_sap = DLS_SAP_LLC;
		return (B_TRUE);
	}

	return (B_FALSE);
}

/* ARGSUSED */
mblk_t *
mac_ib_header(const void *saddr, const void *daddr, uint32_t sap,
    void *mac_pdata, mblk_t *payload, size_t extra_len)
{
	ib_header_info_t	*ibhp;
	mblk_t			*mp;

	if (!mac_ib_sap_verify(sap, NULL, NULL))
		return (NULL);

	mp = allocb(sizeof (ib_header_info_t) + extra_len, BPRI_HI);
	if (mp == NULL)
		return (NULL);

	ibhp = (ib_header_info_t *)mp->b_rptr;
	ibhp->ipib_rhdr.ipoib_type = htons(sap);
	ibhp->ipib_rhdr.ipoib_mbz = 0;
	bcopy(daddr, &ibhp->ib_dst, IPOIB_ADDRL);
	mp->b_wptr += sizeof (ib_header_info_t);
	return (mp);
}

int
mac_ib_header_info(mblk_t *mp, void *mac_pdata, mac_header_info_t *hdr_info)
{
	ib_header_info_t	*ibhp;
	uint16_t	sap;

	if (MBLKL(mp) < sizeof (ib_header_info_t))
		return (EINVAL);

	ibhp = (ib_header_info_t *)mp->b_rptr;

	hdr_info->mhi_hdrsize = sizeof (ib_header_info_t);
	hdr_info->mhi_daddr = (const uint8_t *)&(ibhp->ib_dst);
	if (ibhp->ib_grh.ipoib_vertcflow != 0)
		hdr_info->mhi_saddr = (const uint8_t *)&(ibhp->ib_src);
	else
		hdr_info->mhi_saddr = NULL;

	if (mac_ib_unicst_verify(hdr_info->mhi_daddr, mac_pdata) == 0) {
		hdr_info->mhi_dsttype = MAC_ADDRTYPE_UNICAST;
	} else if (mac_ib_multicst_verify(hdr_info->mhi_daddr,
	    mac_pdata) == 0) {
		hdr_info->mhi_dsttype = MAC_ADDRTYPE_MULTICAST;
	} else {
		hdr_info->mhi_dsttype = MAC_ADDRTYPE_BROADCAST;
	}

	sap = ntohs(ibhp->ipib_rhdr.ipoib_type);
	hdr_info->mhi_origsap = hdr_info->mhi_bindsap = sap;
	hdr_info->mhi_pktsize = 0;

	return (0);
}

/*
 * Take the provided `mp' (which is expected to have a header "dst + type"),
 * and return a pointer to an mblk_t with a header "GRH + type".
 * If the conversion cannot be performed, return NULL.
 */
static mblk_t *
mac_ib_header_cook(mblk_t *mp, void *pdata)
{
	ipoib_ptxhdr_t	*orig_hp;
	mblk_t			*llmp;

	if (MBLKL(mp) < sizeof (ipoib_ptxhdr_t))
		return (NULL);

	orig_hp = (ipoib_ptxhdr_t *)mp->b_rptr;
	llmp = mac_ib_header(NULL, &orig_hp->ipoib_dest,
	    ntohs(orig_hp->ipoib_rhdr.ipoib_type), pdata, NULL, 0);
	if (llmp == NULL)
		return (NULL);

	/*
	 * The plugin framework guarantees that we have the only reference
	 * to the mblk_t, so we can safely modify it.
	 */
	ASSERT(DB_REF(mp) == 1);
	mp->b_rptr += sizeof (ipoib_ptxhdr_t);
	llmp->b_cont = mp;
	return (llmp);
}

/*
 * Take the provided `mp' (which is expected to have a header "GRH + type"),
 * and return a pointer to an mblk_t with a header "type". If the conversion
 * cannot be performed, return NULL.
 */
static mblk_t *
mac_ib_header_uncook(mblk_t *mp, void *pdata)
{
	_NOTE(ARGUNUSED(pdata));

	/*
	 * The plugin framework guarantees that we have the only reference to
	 * the mblk_t and the underlying dblk_t, so we can safely modify it.
	 */
	ASSERT(DB_REF(mp) == 1);

	mp->b_rptr += sizeof (ib_addrs_t);
	return (mp);
}

void
mac_ib_link_details(char *buf, size_t sz, mac_handle_t mh, void *mac_pdata)
{
	uint64_t	speed;

	_NOTE(ARGUNUSED(mac_pdata));

	speed = mac_stat_get(mh, MAC_STAT_IFSPEED);

	/* convert to Mbps */
	speed /= 1000000;

	buf[0] = 0;
	(void) snprintf(buf, sz, "%u Mbps", (uint32_t)speed);
}

static mactype_ops_t mac_ib_type_ops = {
	MTOPS_HEADER_COOK | MTOPS_HEADER_UNCOOK | MTOPS_LINK_DETAILS,
	mac_ib_unicst_verify,
	mac_ib_multicst_verify,
	mac_ib_sap_verify,
	mac_ib_header,
	mac_ib_header_info,
	NULL,
	mac_ib_header_cook,
	mac_ib_header_uncook,
	mac_ib_link_details
};
