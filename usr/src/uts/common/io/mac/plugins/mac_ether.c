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

/*
 * Ethernet MAC plugin for the Nemo mac module
 */

#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/dlpi.h>
#include <sys/mac.h>
#include <sys/mac_ether.h>
#include <sys/dls.h>
#include <sys/ethernet.h>
#include <sys/byteorder.h>
#include <sys/strsun.h>
#include <inet/common.h>

static uint8_t	ether_brdcst[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

static mac_stat_info_t ether_stats[] = {
	/* RFC1643 stats */
	{ ETHER_STAT_ALIGN_ERRORS, "align_errors", KSTAT_DATA_UINT32,	0 },
	{ ETHER_STAT_FCS_ERRORS, "fcs_errors", KSTAT_DATA_UINT32,	0 },
	{ ETHER_STAT_FIRST_COLLISIONS, "first_collisions", KSTAT_DATA_UINT32,
	    0 },
	{ ETHER_STAT_MULTI_COLLISIONS, "multi_collisions", KSTAT_DATA_UINT32,
	    0 },
	{ ETHER_STAT_SQE_ERRORS, "sqe_errors", KSTAT_DATA_UINT32,	0},
	{ ETHER_STAT_DEFER_XMTS, "defer_xmts", KSTAT_DATA_UINT32,	0},
	{ ETHER_STAT_TX_LATE_COLLISIONS, "tx_late_collisions",
	    KSTAT_DATA_UINT32, 0 },
	{ ETHER_STAT_EX_COLLISIONS, "ex_collisions", KSTAT_DATA_UINT32,	0 },
	{ ETHER_STAT_MACXMT_ERRORS, "macxmt_errors", KSTAT_DATA_UINT32,	0 },
	{ ETHER_STAT_CARRIER_ERRORS, "carrier_errors", KSTAT_DATA_UINT32, 0 },
	{ ETHER_STAT_TOOLONG_ERRORS, "toolong_errors", KSTAT_DATA_UINT32, 0 },
	{ ETHER_STAT_MACRCV_ERRORS, "macrcv_errors", KSTAT_DATA_UINT32, 0 },

	/* Statistics described in the ieee802.3(5) man page */
	{ ETHER_STAT_XCVR_ADDR, "xcvr_addr", KSTAT_DATA_UINT32,		0 },
	{ ETHER_STAT_XCVR_ID, "xcvr_id", KSTAT_DATA_UINT32, 		0 },
	{ ETHER_STAT_XCVR_INUSE, "xcvr_inuse", KSTAT_DATA_UINT32,	0 },
	{ ETHER_STAT_CAP_1000FDX, "cap_1000fdx", KSTAT_DATA_UINT32,	0 },
	{ ETHER_STAT_CAP_1000HDX, "cap_1000hdx", KSTAT_DATA_UINT32,	0 },
	{ ETHER_STAT_CAP_100FDX, "cap_100fdx", KSTAT_DATA_UINT32,	0 },
	{ ETHER_STAT_CAP_100HDX, "cap_100hdx", KSTAT_DATA_UINT32,	0 },
	{ ETHER_STAT_CAP_10FDX, "cap_10fdx", KSTAT_DATA_UINT32,		0 },
	{ ETHER_STAT_CAP_10HDX, "cap_10hdx", KSTAT_DATA_UINT32,		0 },
	{ ETHER_STAT_CAP_ASMPAUSE, "cap_asmpause", KSTAT_DATA_UINT32,	0 },
	{ ETHER_STAT_CAP_PAUSE, "cap_pause", KSTAT_DATA_UINT32,		0 },
	{ ETHER_STAT_CAP_AUTONEG, "cap_autoneg", KSTAT_DATA_UINT32,	0 },
	{ ETHER_STAT_ADV_CAP_1000FDX, "adv_cap_1000fdx", KSTAT_DATA_UINT32, 0 },
	{ ETHER_STAT_ADV_CAP_1000HDX, "adv_cap_1000hdx", KSTAT_DATA_UINT32, 0 },
	{ ETHER_STAT_ADV_CAP_100FDX, "adv_cap_100fdx", KSTAT_DATA_UINT32, 0},
	{ ETHER_STAT_ADV_CAP_100HDX, "adv_cap_100hdx", KSTAT_DATA_UINT32, 0},
	{ ETHER_STAT_ADV_CAP_10FDX, "adv_cap_10fdx", KSTAT_DATA_UINT32,	0 },
	{ ETHER_STAT_ADV_CAP_10HDX, "adv_cap_10hdx", KSTAT_DATA_UINT32,	0 },
	{ ETHER_STAT_ADV_CAP_ASMPAUSE, "adv_cap_asmpause", KSTAT_DATA_UINT32,
	    0 },
	{ ETHER_STAT_ADV_CAP_PAUSE, "adv_cap_pause", KSTAT_DATA_UINT32,	0 },
	{ ETHER_STAT_ADV_CAP_AUTONEG, "adv_cap_autoneg", KSTAT_DATA_UINT32, 0 },
	{ ETHER_STAT_LP_CAP_1000FDX, "lp_cap_1000fdx", KSTAT_DATA_UINT32, 0 },
	{ ETHER_STAT_LP_CAP_1000HDX, "lp_cap_1000hdx", KSTAT_DATA_UINT32, 0 },
	{ ETHER_STAT_LP_CAP_100FDX, "lp_cap_100fdx", KSTAT_DATA_UINT32,	0 },
	{ ETHER_STAT_LP_CAP_100HDX, "lp_cap_100hdx", KSTAT_DATA_UINT32,	0 },
	{ ETHER_STAT_LP_CAP_10FDX, "lp_cap_10fdx", KSTAT_DATA_UINT32,	0 },
	{ ETHER_STAT_LP_CAP_10HDX, "lp_cap_10hdx", KSTAT_DATA_UINT32,	0 },
	{ ETHER_STAT_LP_CAP_ASMPAUSE, "lp_cap_asmpause", KSTAT_DATA_UINT32, 0 },
	{ ETHER_STAT_LP_CAP_PAUSE, "lp_cap_pause", KSTAT_DATA_UINT32,	0 },
	{ ETHER_STAT_LP_CAP_AUTONEG, "lp_cap_autoneg", KSTAT_DATA_UINT32, 0 },
	{ ETHER_STAT_LINK_ASMPAUSE, "link_asmpause", KSTAT_DATA_UINT32,	0 },
	{ ETHER_STAT_LINK_PAUSE, "link_pause", KSTAT_DATA_UINT32,	0 },
	{ ETHER_STAT_LINK_AUTONEG, "link_autoneg", KSTAT_DATA_UINT32,	0 },
	{ ETHER_STAT_LINK_DUPLEX, "link_duplex", KSTAT_DATA_UINT32,	0 }
};

static struct modlmisc mac_ether_modlmisc = {
	&mod_miscops,
	"Ethernet MAC plugin %I%"
};

static struct modlinkage mac_ether_modlinkage = {
	MODREV_1,
	&mac_ether_modlmisc,
	NULL
};

static mactype_ops_t mac_ether_type_ops;

int
_init(void)
{
	mactype_register_t *mtrp;
	int	err;

	if ((mtrp = mactype_alloc(MACTYPE_VERSION)) == NULL)
		return (ENOTSUP);
	mtrp->mtr_ident = MAC_PLUGIN_IDENT_ETHER;
	mtrp->mtr_ops = &mac_ether_type_ops;
	mtrp->mtr_mactype = DL_ETHER;
	mtrp->mtr_nativetype = DL_ETHER;
	mtrp->mtr_addrlen = ETHERADDRL;
	mtrp->mtr_brdcst_addr = ether_brdcst;
	mtrp->mtr_stats = ether_stats;
	mtrp->mtr_statcount = A_CNT(ether_stats);
	if ((err = mactype_register(mtrp)) == 0) {
		if ((err = mod_install(&mac_ether_modlinkage)) != 0)
			(void) mactype_unregister(MAC_PLUGIN_IDENT_ETHER);
	}
	mactype_free(mtrp);
	return (err);
}

int
_fini(void)
{
	int	err;

	if ((err = mactype_unregister(MAC_PLUGIN_IDENT_ETHER)) != 0)
		return (err);
	return (mod_remove(&mac_ether_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&mac_ether_modlinkage, modinfop));
}

/*
 * MAC Type plugin operations
 */

/* ARGSUSED */
int
mac_ether_unicst_verify(const void *addr, void *mac_pdata)
{
	/* If it's not a group address, then it's a valid unicast address. */
	return (((((uint8_t *)addr)[0] & 0x01) != 0) ? EINVAL : 0);
}

/* ARGSUSED */
int
mac_ether_multicst_verify(const void *addr, void *mac_pdata)
{
	/* The address must be a group address. */
	if ((((uint8_t *)addr)[0] & 0x01) == 0)
		return (EINVAL);
	/* The address must not be the media broadcast address. */
	if (bcmp(addr, ether_brdcst, ETHERADDRL) == 0)
		return (EINVAL);
	return (0);
}

/*
 * Check the legality of an Ethernet SAP value. The following values are
 * allowed, as specified by PSARC 2003/150:
 *
 * 0..ETHERMTU (1500)					802 semantics
 * ETHERTYPE_802_MIN (1536)..ETHERTYPE_MAX (65535)	ethertype semantics
 *
 * Note that SAP values less than or equal to ETHERMTU (1500) represent LLC
 * channels. (See PSARC 2003/150).  We strictly use SAP 0 to represent LLC
 * channels.
 */
/* ARGSUSED */
boolean_t
mac_ether_sap_verify(uint32_t sap, uint32_t *bind_sap, void *mac_pdata)
{
	if (sap >= ETHERTYPE_802_MIN && sap <= ETHERTYPE_MAX) {
		if (bind_sap != NULL)
			*bind_sap = sap;
		return (B_TRUE);
	}

	if (sap <= ETHERMTU) {
		if (bind_sap != NULL)
			*bind_sap = DLS_SAP_LLC;
		return (B_TRUE);
	}
	return (B_FALSE);
}

/* ARGSUSED */
mblk_t *
mac_ether_header(const void *saddr, const void *daddr, uint32_t sap,
    void *mac_pdata, mblk_t *payload, size_t extra_len)
{
	struct ether_header	*ehp;
	mblk_t			*mp;
	uint32_t		bind_sap;

	if (!mac_ether_sap_verify(sap, &bind_sap, NULL))
		return (NULL);

	mp = allocb(sizeof (struct ether_header) + extra_len, BPRI_HI);
	if (mp == NULL)
		return (NULL);

	ehp = (struct ether_header *)mp->b_rptr;
	bcopy(daddr, &(ehp->ether_dhost), ETHERADDRL);
	bcopy(saddr, &(ehp->ether_shost), ETHERADDRL);

	/*
	 * sap <= ETHERMTU indicates that LLC is being used.  If that's the
	 * case, then the ether_type needs to be set to the payload length.
	 */
	if ((bind_sap == DLS_SAP_LLC) && (payload != NULL))
		sap = msgdsize(payload);
	ehp->ether_type = htons(sap);

	mp->b_wptr += sizeof (struct ether_header);
	return (mp);
}

/* ARGSUSED */
int
mac_ether_header_info(mblk_t *mp, void *mac_pdata, mac_header_info_t *hdr_info)
{
	struct ether_header	*ehp;
	uint16_t		ether_type;

	if (MBLKL(mp) < sizeof (struct ether_header))
		return (EINVAL);

	ehp = (struct ether_header *)mp->b_rptr;
	ether_type = ntohs(ehp->ether_type);

	hdr_info->mhi_hdrsize = sizeof (struct ether_header);
	hdr_info->mhi_daddr = (const uint8_t *)&(ehp->ether_dhost);
	hdr_info->mhi_saddr = (const uint8_t *)&(ehp->ether_shost);
	hdr_info->mhi_origsap = ether_type;
	hdr_info->mhi_bindsap = (ether_type > ETHERMTU) ?
	    ether_type : DLS_SAP_LLC;
	hdr_info->mhi_pktsize = (hdr_info->mhi_bindsap == DLS_SAP_LLC) ?
	    hdr_info->mhi_hdrsize + ether_type : 0;

	if (mac_ether_unicst_verify(hdr_info->mhi_daddr, NULL) == 0)
		hdr_info->mhi_dsttype = MAC_ADDRTYPE_UNICAST;
	else if (mac_ether_multicst_verify(hdr_info->mhi_daddr, NULL) == 0)
		hdr_info->mhi_dsttype = MAC_ADDRTYPE_MULTICAST;
	else
		hdr_info->mhi_dsttype = MAC_ADDRTYPE_BROADCAST;

	return (0);
}

static mactype_ops_t mac_ether_type_ops = {
	0,
	mac_ether_unicst_verify,
	mac_ether_multicst_verify,
	mac_ether_sap_verify,
	mac_ether_header,
	mac_ether_header_info
};
