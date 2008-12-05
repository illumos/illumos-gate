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

/*
 * WiFi MAC Type plugin for the Nemo mac module
 *
 * This is a bit of mutant since we pretend to be mostly DL_ETHER.
 */

#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/dlpi.h>
#include <sys/dld_impl.h>
#include <sys/mac_wifi.h>
#include <sys/ethernet.h>
#include <sys/byteorder.h>
#include <sys/strsun.h>
#include <inet/common.h>

uint8_t wifi_bcastaddr[]	= { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static uint8_t wifi_ietfmagic[]	= { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00 };
static uint8_t wifi_ieeemagic[]	= { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0xf8 };

static mac_stat_info_t wifi_stats[] = {
	/* statistics described in ieee802.11(5) */
{ WIFI_STAT_TX_FRAGS, 		"tx_frags",		KSTAT_DATA_UINT32, 0 },
{ WIFI_STAT_MCAST_TX,		"mcast_tx",		KSTAT_DATA_UINT32, 0 },
{ WIFI_STAT_TX_FAILED,		"tx_failed",		KSTAT_DATA_UINT32, 0 },
{ WIFI_STAT_TX_RETRANS,		"tx_retrans",		KSTAT_DATA_UINT32, 0 },
{ WIFI_STAT_TX_RERETRANS,	"tx_reretrans",		KSTAT_DATA_UINT32, 0 },
{ WIFI_STAT_RTS_SUCCESS,	"rts_success",		KSTAT_DATA_UINT32, 0 },
{ WIFI_STAT_RTS_FAILURE,	"rts_failure",		KSTAT_DATA_UINT32, 0 },
{ WIFI_STAT_ACK_FAILURE,	"ack_failure",		KSTAT_DATA_UINT32, 0 },
{ WIFI_STAT_RX_FRAGS, 		"rx_frags",		KSTAT_DATA_UINT32, 0 },
{ WIFI_STAT_MCAST_RX,		"mcast_rx", 		KSTAT_DATA_UINT32, 0 },
{ WIFI_STAT_FCS_ERRORS,		"fcs_errors", 		KSTAT_DATA_UINT32, 0 },
{ WIFI_STAT_WEP_ERRORS,		"wep_errors",		KSTAT_DATA_UINT32, 0 },
{ WIFI_STAT_RX_DUPS,		"rx_dups",		KSTAT_DATA_UINT32, 0 }
};

static struct modlmisc mac_wifi_modlmisc = {
	&mod_miscops,
	"WiFi MAC plugin"
};

static struct modlinkage mac_wifi_modlinkage = {
	MODREV_1,
	&mac_wifi_modlmisc,
	NULL
};

static mactype_ops_t mac_wifi_type_ops;

int
_init(void)
{
	mactype_register_t *mtrp = mactype_alloc(MACTYPE_VERSION);
	int err;

	/*
	 * If `mtrp' is NULL, then this plugin is not compatible with
	 * the system's MAC Type plugin framework.
	 */
	if (mtrp == NULL)
		return (ENOTSUP);

	mtrp->mtr_ops		= &mac_wifi_type_ops;
	mtrp->mtr_ident		= MAC_PLUGIN_IDENT_WIFI;
	mtrp->mtr_mactype	= DL_ETHER;
	mtrp->mtr_nativetype	= DL_WIFI;
	mtrp->mtr_stats		= wifi_stats;
	mtrp->mtr_statcount	= A_CNT(wifi_stats);
	mtrp->mtr_addrlen	= IEEE80211_ADDR_LEN;
	mtrp->mtr_brdcst_addr	= wifi_bcastaddr;

	if ((err = mactype_register(mtrp)) == 0) {
		if ((err = mod_install(&mac_wifi_modlinkage)) != 0)
			(void) mactype_unregister(MAC_PLUGIN_IDENT_WIFI);
	}
	mactype_free(mtrp);
	return (err);
}

int
_fini(void)
{
	int	err;

	if ((err = mactype_unregister(MAC_PLUGIN_IDENT_WIFI)) != 0)
		return (err);
	return (mod_remove(&mac_wifi_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&mac_wifi_modlinkage, modinfop));
}

/*
 * MAC Type plugin operations
 */

static boolean_t
mac_wifi_pdata_verify(void *pdata, size_t pdata_size)
{
	wifi_data_t *wdp = pdata;

	return (pdata_size == sizeof (wifi_data_t) && wdp->wd_opts == 0);
}

/* ARGSUSED */
static int
mac_wifi_unicst_verify(const void *addr, void *pdata)
{
	/* If it's not a group address, then it's a valid unicast address. */
	return (IEEE80211_IS_MULTICAST(addr) ? EINVAL : 0);
}

/* ARGSUSED */
static int
mac_wifi_multicst_verify(const void *addr, void *pdata)
{
	/* The address must be a group address. */
	if (!IEEE80211_IS_MULTICAST(addr))
		return (EINVAL);
	/* The address must not be the media broadcast address. */
	if (bcmp(addr, wifi_bcastaddr, sizeof (wifi_bcastaddr)) == 0)
		return (EINVAL);
	return (0);
}

/*
 * Verify that `sap' is valid, and return the actual SAP to bind to in
 * `*bind_sap'.  The WiFI SAP space is identical to Ethernet.
 */
/* ARGSUSED */
static boolean_t
mac_wifi_sap_verify(uint32_t sap, uint32_t *bind_sap, void *pdata)
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

/*
 * Create a template WiFi datalink header for `sap' packets between `saddr'
 * and `daddr'.  Any enabled modes and features relevant to building the
 * header are passed via `pdata'.  Return NULL on failure.
 */
/* ARGSUSED */
static mblk_t *
mac_wifi_header(const void *saddr, const void *daddr, uint32_t sap,
    void *pdata, mblk_t *payload, size_t extra_len)
{
	struct ieee80211_frame	*wh;
	struct ieee80211_llc	*llc;
	mblk_t			*mp;
	wifi_data_t		*wdp = pdata;

	if (!mac_wifi_sap_verify(sap, NULL, NULL))
		return (NULL);

	if ((mp = allocb(WIFI_HDRSIZE + extra_len, BPRI_HI)) == NULL)
		return (NULL);
	bzero(mp->b_rptr, WIFI_HDRSIZE + extra_len);

	/*
	 * Fill in the fixed parts of the ieee80211_frame.
	 */
	wh = (struct ieee80211_frame *)mp->b_rptr;
	mp->b_wptr += sizeof (struct ieee80211_frame);
	wh->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_DATA;

	switch (wdp->wd_opmode) {
	case IEEE80211_M_STA:
		wh->i_fc[1] = IEEE80211_FC1_DIR_TODS;
		IEEE80211_ADDR_COPY(wh->i_addr1, wdp->wd_bssid);
		IEEE80211_ADDR_COPY(wh->i_addr2, saddr);
		IEEE80211_ADDR_COPY(wh->i_addr3, daddr);
		break;

	case IEEE80211_M_IBSS:
	case IEEE80211_M_AHDEMO:
		wh->i_fc[1] = IEEE80211_FC1_DIR_NODS;
		IEEE80211_ADDR_COPY(wh->i_addr1, daddr);
		IEEE80211_ADDR_COPY(wh->i_addr2, saddr);
		IEEE80211_ADDR_COPY(wh->i_addr3, wdp->wd_bssid);
		break;

	case IEEE80211_M_HOSTAP:
		wh->i_fc[1] = IEEE80211_FC1_DIR_FROMDS;
		IEEE80211_ADDR_COPY(wh->i_addr1, daddr);
		IEEE80211_ADDR_COPY(wh->i_addr2, wdp->wd_bssid);
		IEEE80211_ADDR_COPY(wh->i_addr3, saddr);
		break;
	}

	switch (wdp->wd_secalloc) {
	case WIFI_SEC_WEP:
		/*
		 * Fill in the fixed parts of the WEP-portion of the frame.
		 */
		wh->i_fc[1] |= IEEE80211_FC1_WEP;
		/*
		 * The actual contents of the WEP-portion of the packet
		 * are computed when the packet is sent -- for now, we
		 * just need to account for the size.
		 */
		mp->b_wptr += IEEE80211_WEP_IVLEN + IEEE80211_WEP_KIDLEN;
		break;

	case WIFI_SEC_WPA:
		wh->i_fc[1] |= IEEE80211_FC1_WEP;
		mp->b_wptr += IEEE80211_WEP_IVLEN +
		    IEEE80211_WEP_KIDLEN + IEEE80211_WEP_EXTIVLEN;
		break;

	default:
		break;
	}

	/*
	 * Fill in the fixed parts of the ieee80211_llc header.
	 */
	llc = (struct ieee80211_llc *)mp->b_wptr;
	mp->b_wptr += sizeof (struct ieee80211_llc);
	bcopy(wifi_ietfmagic, llc, sizeof (wifi_ietfmagic));
	llc->illc_ether_type = htons(sap);

	return (mp);
}

/*
 * Use the provided `mp' (which is expected to point to a WiFi header), and
 * fill in the provided `mhp'.  Return an errno on failure.
 */
/* ARGSUSED */
static int
mac_wifi_header_info(mblk_t *mp, void *pdata, mac_header_info_t *mhp)
{
	struct ieee80211_frame	*wh;
	struct ieee80211_llc	*llc;
	uchar_t			*llcp;
	wifi_data_t		*wdp = pdata;

	if (MBLKL(mp) < sizeof (struct ieee80211_frame))
		return (EINVAL);

	wh = (struct ieee80211_frame *)mp->b_rptr;
	llcp = mp->b_rptr + sizeof (struct ieee80211_frame);

	/*
	 * When we receive frames from other hosts, the hardware will have
	 * already performed WEP decryption, and thus there will not be a WEP
	 * portion.  However, when we receive a loopback copy of our own
	 * packets, it will still have a WEP portion.  Skip past it to get to
	 * the LLC header.
	 */
	if (wh->i_fc[1] & IEEE80211_FC1_WEP) {
		llcp += IEEE80211_WEP_IVLEN + IEEE80211_WEP_KIDLEN;
		if (wdp->wd_secalloc == WIFI_SEC_WPA)
			llcp += IEEE80211_WEP_EXTIVLEN;
	}

	if ((uintptr_t)mp->b_wptr - (uintptr_t)llcp <
	    sizeof (struct ieee80211_llc))
		return (EINVAL);

	llc = (struct ieee80211_llc *)llcp;
	mhp->mhi_origsap = ntohs(llc->illc_ether_type);
	mhp->mhi_bindsap = mhp->mhi_origsap;
	mhp->mhi_pktsize = 0;
	mhp->mhi_hdrsize = (uintptr_t)llcp + sizeof (*llc) -
	    (uintptr_t)mp->b_rptr;

	/*
	 * Verify the LLC header is one of the known formats.  As per MSFT's
	 * convention, if the header is using IEEE 802.1H encapsulation, then
	 * treat the LLC header as data.  As per DL_ETHER custom when treating
	 * the LLC header as data, set the mhi_bindsap to be DLS_SAP_LLC, and
	 * assume mhi_origsap contains the data length.
	 */
	if (bcmp(llc, wifi_ieeemagic, sizeof (wifi_ieeemagic)) == 0) {
		mhp->mhi_bindsap = DLS_SAP_LLC;
		mhp->mhi_hdrsize -= sizeof (*llc);
		mhp->mhi_pktsize = mhp->mhi_hdrsize + mhp->mhi_origsap;
	} else if (bcmp(llc, wifi_ietfmagic, sizeof (wifi_ietfmagic)) != 0) {
		return (EINVAL);
	}

	switch (wh->i_fc[1] & IEEE80211_FC1_DIR_MASK) {
	case IEEE80211_FC1_DIR_NODS:
		mhp->mhi_daddr = wh->i_addr1;
		mhp->mhi_saddr = wh->i_addr2;
		break;

	case IEEE80211_FC1_DIR_TODS:
		mhp->mhi_daddr = wh->i_addr3;
		mhp->mhi_saddr = wh->i_addr2;
		break;

	case IEEE80211_FC1_DIR_FROMDS:
		mhp->mhi_daddr = wh->i_addr1;
		mhp->mhi_saddr = wh->i_addr3;
		break;

	case IEEE80211_FC1_DIR_DSTODS:
		/* We don't support AP-to-AP mode yet */
		return (ENOTSUP);
	}

	if (mac_wifi_unicst_verify(mhp->mhi_daddr, NULL) == 0)
		mhp->mhi_dsttype = MAC_ADDRTYPE_UNICAST;
	else if (mac_wifi_multicst_verify(mhp->mhi_daddr, NULL) == 0)
		mhp->mhi_dsttype = MAC_ADDRTYPE_MULTICAST;
	else
		mhp->mhi_dsttype = MAC_ADDRTYPE_BROADCAST;

	return (0);
}

/*
 * Take the provided `mp' (which is expected to have an Ethernet header), and
 * return a pointer to an mblk_t with a WiFi header.  Note that the returned
 * header will not be complete until the driver finishes filling it in prior
 * to transmit.  If the conversion cannot be performed, return NULL.
 */
static mblk_t *
mac_wifi_header_cook(mblk_t *mp, void *pdata)
{
	struct ether_header	*ehp;
	mblk_t			*llmp;

	if (MBLKL(mp) < sizeof (struct ether_header))
		return (NULL);

	ehp = (void *)mp->b_rptr;
	llmp = mac_wifi_header(&ehp->ether_shost, &ehp->ether_dhost,
	    ntohs(ehp->ether_type), pdata, NULL, 0);
	if (llmp == NULL)
		return (NULL);

	/*
	 * The plugin framework guarantees that we have the only reference
	 * to the mblk_t, so we can safely modify it.
	 */
	ASSERT(DB_REF(mp) == 1);
	mp->b_rptr += sizeof (struct ether_header);
	llmp->b_cont = mp;
	return (llmp);
}

/*
 * Take the provided `mp' (which is expected to have a WiFi header), and
 * return a pointer to an mblk_t with an Ethernet header.  If the conversion
 * cannot be performed, return NULL.
 */
static mblk_t *
mac_wifi_header_uncook(mblk_t *mp, void *pdata)
{
	mac_header_info_t	mhi;
	struct ether_header	eh;

	if (mac_wifi_header_info(mp, pdata, &mhi) != 0) {
		/*
		 * The plugin framework guarantees the header is properly
		 * formed, so this should never happen.
		 */
		return (NULL);
	}

	/*
	 * The plugin framework guarantees that we have the only reference to
	 * the mblk_t and the underlying dblk_t, so we can safely modify it.
	 */
	ASSERT(DB_REF(mp) == 1);

	IEEE80211_ADDR_COPY(&eh.ether_dhost, mhi.mhi_daddr);
	IEEE80211_ADDR_COPY(&eh.ether_shost, mhi.mhi_saddr);
	eh.ether_type = htons(mhi.mhi_origsap);

	ASSERT(mhi.mhi_hdrsize >= sizeof (struct ether_header));
	mp->b_rptr += mhi.mhi_hdrsize - sizeof (struct ether_header);
	bcopy(&eh, mp->b_rptr, sizeof (struct ether_header));
	return (mp);
}

static mactype_ops_t mac_wifi_type_ops = {
	MTOPS_PDATA_VERIFY | MTOPS_HEADER_COOK | MTOPS_HEADER_UNCOOK,
	mac_wifi_unicst_verify,
	mac_wifi_multicst_verify,
	mac_wifi_sap_verify,
	mac_wifi_header,
	mac_wifi_header_info,
	mac_wifi_pdata_verify,
	mac_wifi_header_cook,
	mac_wifi_header_uncook
};
