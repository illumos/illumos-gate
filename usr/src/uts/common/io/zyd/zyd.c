/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2007 by  Lukas Turek <turek@ksvi.mff.cuni.cz>
 * Copyright (c) 2007 by  Jiri Svoboda <jirik.svoboda@seznam.cz>
 * Copyright (c) 2007 by  Martin Krulis <martin.krulis@matfyz.cz>
 * Copyright (c) 2006 by Damien Bergamini <damien.bergamini@free.fr>
 * Copyright (c) 2006 by Florian Stoehr <ich@florian-stoehr.de>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

/*
 * ZD1211 wLAN driver
 * Driver major routines
 */

#include <sys/byteorder.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/mac_provider.h>
#include <sys/mac_wifi.h>
#include <sys/strsun.h>
#include <sys/ksynch.h>

#include "zyd.h"
#include "zyd_reg.h"

static int zyd_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int zyd_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

static int zyd_m_stat(void *arg, uint_t stat, uint64_t *val);
static int zyd_m_start(void *arg);
static void zyd_m_stop(void *arg);
static int zyd_m_unicst(void *arg, const uint8_t *macaddr);
static int zyd_m_multicst(void *arg, boolean_t add, const uint8_t *m);
static int zyd_m_promisc(void *arg, boolean_t on);
static void zyd_m_ioctl(void *arg, queue_t *wq, mblk_t *mp);
static mblk_t *zyd_m_tx(void *arg, mblk_t *mp);
static int zyd_m_getprop(void *arg, const char *pr_name,
    mac_prop_id_t wldp_pr_num, uint_t wldp_length, void *wldp_buf);
static void zyd_m_propinfo(void *arg, const char *pr_name,
    mac_prop_id_t wldp_pr_num, mac_prop_info_handle_t mph);
static int zyd_m_setprop(void *arg, const char *pr_name,
    mac_prop_id_t wldp_pr_num, uint_t wldp_length, const void *wldp_buf);

static int zyd_newstate(struct ieee80211com *ic,
    enum ieee80211_state state, int arg);

/* Driver identification */
static char zyd_ident[] = ZYD_DRV_DESC " " ZYD_DRV_REV;

/* Global state pointer for managing per-device soft states */
void *zyd_ssp;

/*
 * Mac Call Back entries
 */
static mac_callbacks_t zyd_m_callbacks = {
	MC_IOCTL | MC_SETPROP | MC_GETPROP | MC_PROPINFO,
	zyd_m_stat,		/* Get the value of a statistic */
	zyd_m_start,		/* Start the device */
	zyd_m_stop,		/* Stop the device */
	zyd_m_promisc,		/* Enable or disable promiscuous mode */
	zyd_m_multicst,		/* Enable or disable a multicast addr */
	zyd_m_unicst,		/* Set the unicast MAC address */
	zyd_m_tx,		/* Transmit a packet */
	NULL,
	zyd_m_ioctl,		/* Process an unknown ioctl */
	NULL,			/* mc_getcapab */
	NULL,
	NULL,
	zyd_m_setprop,
	zyd_m_getprop,
	zyd_m_propinfo
};

/*
 *  Module Loading Data & Entry Points
 */
DDI_DEFINE_STREAM_OPS(zyd_devops,	/* name */
    nulldev,			/* identify */
    nulldev,			/* probe */
    zyd_attach,			/* attach */
    zyd_detach,			/* detach */
    nodev,			/* reset */
    NULL,			/* getinfo */
    D_MP,			/* flag */
    NULL,			/* stream_tab */
    ddi_quiesce_not_needed	/* quiesce */
);

static struct modldrv zyd_modldrv = {
	&mod_driverops,		/* drv_modops */
	zyd_ident,		/* drv_linkinfo */
	&zyd_devops		/* drv_dev_ops */
};

static struct modlinkage zyd_ml = {
	MODREV_1,		/* ml_rev */
	{&zyd_modldrv, NULL}	/* ml_linkage */
};

/*
 * Wireless-specific structures
 */
static const struct ieee80211_rateset zyd_rateset_11b = {
	4, {2, 4, 11, 22}	/* units are 0.5Mbit! */
};

static const struct ieee80211_rateset zyd_rateset_11g = {
	12, {2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108}
};


#ifdef DEBUG
uint32_t zyd_dbg_flags;

void
zyd_dbg(uint32_t dbg_mask, const int8_t *fmt, ...)
{
	va_list args;

	if (dbg_mask & zyd_dbg_flags) {
		va_start(args, fmt);
		vcmn_err(CE_CONT, fmt, args);
		va_end(args);
	}
}
#endif

void
zyd_warn(const int8_t *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vcmn_err(CE_WARN, fmt, args);
	va_end(args);
}

/*
 * Internal functions
 */
static uint8_t
zyd_plcp_signal(uint16_t rate)
{
	switch (rate) {
		/* CCK rates (returned values are device-dependent) */
	case 2:
		return (0x0);
	case 4:
		return (0x1);
	case 11:
		return (0x2);
	case 22:
		return (0x3);

		/* OFDM rates (cf IEEE Std 802.11a-1999, pp. 14 Table 80) */
	case 12:
		return (0xb);
	case 18:
		return (0xf);
	case 24:
		return (0xa);
	case 36:
		return (0xe);
	case 48:
		return (0x9);
	case 72:
		return (0xd);
	case 96:
		return (0x8);
	case 108:
		return (0xc);

		/* unsupported rates (should not get there) */
	default:
		return (0xff);
	}
}

/*
 * Timeout function for scanning.
 *
 * Called at the end of each scanning round.
 */
static void
zyd_next_scan(void *arg)
{
	struct zyd_softc *sc = arg;
	struct ieee80211com *ic = &sc->ic;

	ZYD_DEBUG((ZYD_DBG_SCAN, "scan timer: fired\n"));

	if (ic->ic_state == IEEE80211_S_SCAN) {
		ieee80211_next_scan(ic);
	} else {
		ZYD_DEBUG((ZYD_DBG_SCAN, "scan timer: no work\n"));
	}
}

/*
 * Extract a 802.11 frame from the received packet and forward it to net80211.
 */
void
zyd_receive(struct zyd_softc *sc, const uint8_t *buf, uint16_t len)
{
	const struct zyd_rx_stat *stat;
	struct ieee80211com *ic = &sc->ic;
	struct ieee80211_frame *wh;
	struct ieee80211_node *in;
	int rlen;		/* Actual frame length */
	uint8_t rssi;
	mblk_t *m;

	if (len < ZYD_MIN_FRAGSZ) {
		/* Packet is too short, silently drop it */
		sc->rx_err++;
		return;
	}

	stat = (const struct zyd_rx_stat *)
	    (buf + len - sizeof (struct zyd_rx_stat));
	if (stat->flags & ZYD_RX_ERROR) {
		/* Frame is corrupted, silently drop it */
		sc->rx_err++;
		return;
	}

	/* compute actual frame length */
	rlen = len - sizeof (struct zyd_plcphdr) -
	    sizeof (struct zyd_rx_stat) - IEEE80211_CRC_LEN;

	m = allocb(rlen, BPRI_MED);
	if (m == NULL) {
		sc->rx_nobuf++;
		return;
	}

	/* Copy frame to new buffer */
	bcopy(buf + sizeof (struct zyd_plcphdr), m->b_wptr, rlen);
	m->b_wptr += rlen;

	/* Send frame to net80211 stack */
	wh = (struct ieee80211_frame *)m->b_rptr;
	in = ieee80211_find_rxnode(ic, wh);
	rssi = (stat->rssi < 25) ? 230 : (255 - stat->rssi) / 2;

	(void) ieee80211_input(ic, m, in, (int32_t)rssi, 0);

	ieee80211_free_node(in);
}

/*
 * xxx_send callback for net80211.
 *
 * Transmit a 802.11 frame.
 *
 * Constructs a packet from zyd_tx_header and 802.11 frame data
 * and sends it to the chip.
 */
/*ARGSUSED*/
static int
zyd_send(ieee80211com_t *ic, mblk_t *mp, uint8_t type)
{
	struct zyd_softc *sc = ZYD_IC_TO_SOFTC(ic);
	struct zyd_tx_header *buf_hdr;
	struct ieee80211_frame *wh;
	struct ieee80211_node *in;
	struct ieee80211_key *k;
	mblk_t *m, *m0;
	int len, off, mblen;
	uint16_t frame_size, additional_size, rate;
	uint8_t service;
	int res;

	ASSERT(mp->b_next == NULL);

	/* device not ready, drop all frames */
	if (!sc->usb.connected || sc->suspended || !sc->running) {
		freemsg(mp);
		if (type == IEEE80211_FC0_TYPE_DATA)
			return (DDI_SUCCESS);
		else
			return (DDI_FAILURE);
	}

	/* device queue overrun */
	if (sc->tx_queued >= ZYD_TX_LIST_COUNT) {
		/* drop management frames */
		if (type != IEEE80211_FC0_TYPE_DATA) {
			freemsg(mp);
		} else {
			(void) zyd_serial_enter(sc, ZYD_NO_SIG);
			sc->resched = B_TRUE;
			zyd_serial_exit(sc);
		}
		return (DDI_FAILURE);
	}

	m = allocb(msgdsize(mp) + sizeof (struct zyd_tx_header) + 32,
	    BPRI_MED);
	if (m == NULL) {
		sc->tx_nobuf++;
		(void) zyd_serial_enter(sc, ZYD_NO_SIG);
		sc->resched = B_TRUE;
		zyd_serial_exit(sc);
		return (DDI_FAILURE);
	}
	m->b_rptr += sizeof (struct zyd_tx_header);
	m->b_wptr = m->b_rptr;

	for (off = 0, m0 = mp; m0 != NULL; m0 = m0->b_cont) {
		mblen = MBLKL(m0);
		(void) memcpy(m->b_rptr + off, m0->b_rptr, mblen);
		off += mblen;
	}
	m->b_wptr += off;

	wh = (struct ieee80211_frame *)m->b_rptr;
	in = ieee80211_find_txnode(ic, wh->i_addr1);

	if (in == NULL) {
		freemsg(m);
		sc->tx_err++;
		freemsg(mp);
		return (DDI_SUCCESS);
	}
	in->in_inact = 0;

	if (type == IEEE80211_FC0_TYPE_DATA)
		(void) ieee80211_encap(ic, m, in);

	if (wh->i_fc[1] & IEEE80211_FC1_WEP) {
		k = ieee80211_crypto_encap(ic, m);
		if (k == NULL) {
			sc->tx_err++;
			ieee80211_free_node(in);
			freemsg(m);
			freemsg(mp);
			return (DDI_SUCCESS);
		}
		/* packet header may have moved, reset our local pointer */
		wh = (struct ieee80211_frame *)m->b_rptr;
	}

	/*
	 * pickup a rate. May need work to make adaptive - at present,
	 * picks best rate for mode.
	 */
	if (type == IEEE80211_FC0_TYPE_MGT) {
		/* mgmt frames are sent at 1M */
		rate = (uint16_t)in->in_rates.ir_rates[0];
	} else if (ic->ic_fixed_rate != IEEE80211_FIXED_RATE_NONE) {
		rate = (uint16_t)ic->ic_sup_rates[ic->ic_curmode].
		    ir_rates[ic->ic_fixed_rate];
	} else {
		rate = (uint16_t)ic->ic_sup_rates[ic->ic_curmode].
		    ir_rates[in->in_txrate];
	}
	rate &= IEEE80211_RATE_VAL;
	if (rate == 0)		/* should not happen */
		rate = 2;

	/* Get total length of frame */
	len = msgsize(m);

	m->b_rptr -= sizeof (struct zyd_tx_header);
	buf_hdr = (struct zyd_tx_header *)m->b_rptr;

	frame_size = (uint16_t)len + 4;	/* include CRC32 */
	buf_hdr->frame_size = LE_16(frame_size);

	/*
	 * Compute "packet size". What the 10 stands for,
	 * nobody knows.
	 */
	additional_size = sizeof (struct zyd_tx_header) + 10;
	if (sc->mac_rev == ZYD_ZD1211)
		buf_hdr->packet_size = LE_16(frame_size + additional_size);
	else
		buf_hdr->packet_size = LE_16(additional_size);

	buf_hdr->rate_mod_flags = LE_8(zyd_plcp_signal(rate));
	buf_hdr->type_flags = LE_8(ZYD_TX_FLAG_BACKOFF);
	if (!IEEE80211_IS_MULTICAST(wh->i_addr1)) {
		/* multicast frames are not sent at OFDM rates in 802.11b/g */
		if (frame_size > ic->ic_rtsthreshold) {
			buf_hdr->type_flags |= ZYD_TX_FLAG_RTS;
		} else if (ZYD_RATE_IS_OFDM(rate) &&
		    (ic->ic_flags & IEEE80211_F_USEPROT)) {
			if (ic->ic_protmode == IEEE80211_PROT_CTSONLY)
				buf_hdr->type_flags |=
				    ZYD_TX_FLAG_CTS_TO_SELF;
			else if (ic->ic_protmode == IEEE80211_PROT_RTSCTS)
				buf_hdr->type_flags |= ZYD_TX_FLAG_RTS;
		}
	} else
		buf_hdr->type_flags |= ZYD_TX_FLAG_MULTICAST;

	if ((type == IEEE80211_FC0_TYPE_CTL) &&
	    (wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK)
	    == IEEE80211_FC0_SUBTYPE_PS_POLL)
		buf_hdr->type_flags |= ZYD_TX_FLAG_TYPE(ZYD_TX_TYPE_PS_POLL);

	if (ZYD_RATE_IS_OFDM(rate)) {
		buf_hdr->rate_mod_flags |= ZYD_TX_RMF_OFDM;
		if (ic->ic_curmode == IEEE80211_MODE_11A)
			buf_hdr->rate_mod_flags |= ZYD_TX_RMF_5GHZ;
	} else if (rate != 2 && (ic->ic_flags & IEEE80211_F_SHPREAMBLE))
		buf_hdr->rate_mod_flags |= ZYD_TX_RMF_SH_PREAMBLE;

	/*
	 * Compute frame duration and length-extension service flag.
	 */
	service = 0x00;

	buf_hdr->frame_duration = LE_16((16 * frame_size + rate - 1) / rate);
	buf_hdr->service = service;
	buf_hdr->next_frame_duration = LE_16(0);

	if (rate == 22) {
		const int remainder = (16 * frame_size) % 22;
		if (remainder != 0 && remainder < 7)
			buf_hdr->service |= ZYD_TX_SERVICE_LENGTH_EXTENSION;
	}

	res = zyd_usb_send_packet(&sc->usb, m);
	if (res != ZYD_SUCCESS) {
		sc->tx_err++;
	} else {
		(void) zyd_serial_enter(sc, ZYD_NO_SIG);
		sc->tx_queued++;
		zyd_serial_exit(sc);
		freemsg(mp);
		ic->ic_stats.is_tx_frags++;
		ic->ic_stats.is_tx_bytes += len;
	}

	ieee80211_free_node(in);

	return (DDI_SUCCESS);
}

/*
 * Register with the MAC layer.
 */
static zyd_res
zyd_mac_init(struct zyd_softc *sc)
{
	struct ieee80211com *ic = &sc->ic;
	mac_register_t *macp;
	wifi_data_t wd = { 0 };
	int err;

	/*
	 * Initialize mac structure
	 */
	macp = mac_alloc(MAC_VERSION);
	if (macp == NULL) {
		ZYD_WARN("failed to allocate MAC structure\n");
		return (ZYD_FAILURE);
	}

	/*
	 * Initialize pointer to device specific functions
	 */
	wd.wd_secalloc = WIFI_SEC_NONE;
	wd.wd_opmode = sc->ic.ic_opmode;
	IEEE80211_ADDR_COPY(wd.wd_bssid, ic->ic_macaddr);

	macp->m_type_ident = MAC_PLUGIN_IDENT_WIFI;
	macp->m_driver = sc;
	macp->m_dip = sc->dip;
	macp->m_src_addr = ic->ic_macaddr;
	macp->m_callbacks = &zyd_m_callbacks;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = IEEE80211_MTU;
	macp->m_pdata = &wd;
	macp->m_pdata_size = sizeof (wd);

	/*
	 * Register the macp to mac
	 */
	err = mac_register(macp, &sc->ic.ic_mach);
	mac_free(macp);

	if (err != DDI_SUCCESS) {
		ZYD_WARN("failed to register MAC structure\n");
		return (ZYD_FAILURE);
	}

	return (ZYD_SUCCESS);
}

/*
 * Register with net80211.
 */
static void
zyd_wifi_init(struct zyd_softc *sc)
{
	struct ieee80211com *ic = &sc->ic;
	int i;

	/*
	 * Initialize the WiFi part, which will be used by generic layer
	 */
	ic->ic_phytype = IEEE80211_T_OFDM;
	ic->ic_opmode = IEEE80211_M_STA;
	ic->ic_state = IEEE80211_S_INIT;
	ic->ic_maxrssi = 255;
	ic->ic_xmit = zyd_send;

	/* set device capabilities */
	ic->ic_caps = IEEE80211_C_TXPMGT |	/* tx power management */
	    IEEE80211_C_SHPREAMBLE |		/* short preamble supported */
	    IEEE80211_C_SHSLOT | IEEE80211_C_WPA;	/* Support WPA/WPA2 */

	/* Copy MAC address */
	IEEE80211_ADDR_COPY(ic->ic_macaddr, sc->macaddr);

	/*
	 * set supported .11b and .11g rates
	 */
	ic->ic_sup_rates[IEEE80211_MODE_11B] = zyd_rateset_11b;
	ic->ic_sup_rates[IEEE80211_MODE_11G] = zyd_rateset_11g;

	/*
	 * set supported .11b and .11g channels(1 through 14)
	 */
	for (i = 1; i <= 14; i++) {
		ic->ic_sup_channels[i].ich_freq =
		    ieee80211_ieee2mhz(i, IEEE80211_CHAN_2GHZ);
		ic->ic_sup_channels[i].ich_flags =
		    IEEE80211_CHAN_CCK | IEEE80211_CHAN_OFDM |
		    IEEE80211_CHAN_DYN | IEEE80211_CHAN_2GHZ;
	}

	/*
	 * Init generic layer (it cannot fail)
	 */
	ieee80211_attach(ic);

	/* register WPA door */
	ieee80211_register_door(ic, ddi_driver_name(sc->dip),
	    ddi_get_instance(sc->dip));

	/* Must be after attach! */
	sc->newstate = ic->ic_newstate;
	ic->ic_newstate = zyd_newstate;

	ieee80211_media_init(ic);
	ic->ic_def_txkey = 0;
}

/*
 * Device operations
 */
/*
 * Binding the driver to a device.
 *
 * Concurrency: Until zyd_attach() returns with success,
 * the only other entry point that can be executed is getinfo().
 * Thus no locking here yet.
 */
static int
zyd_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	struct zyd_softc *sc;
	char strbuf[32];
	int instance;
	int err;

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		sc = ddi_get_soft_state(zyd_ssp, ddi_get_instance(dip));
		ASSERT(sc != NULL);

		(void) zyd_resume(sc);
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);
	err = ddi_soft_state_zalloc(zyd_ssp, instance);

	if (err != DDI_SUCCESS) {
		ZYD_WARN("failed to allocate soft state\n");
		return (DDI_FAILURE);
	}

	sc = ddi_get_soft_state(zyd_ssp, instance);
	sc->dip = dip;
	sc->timeout_id = 0;

	if (zyd_usb_init(sc) != ZYD_SUCCESS) {
		ddi_soft_state_free(zyd_ssp, instance);
		return (DDI_FAILURE);
	}

	if (zyd_hw_init(sc) != ZYD_SUCCESS) {
		zyd_usb_deinit(sc);
		ddi_soft_state_free(zyd_ssp, instance);
		return (DDI_FAILURE);
	}

	zyd_wifi_init(sc);

	if (zyd_mac_init(sc) != DDI_SUCCESS) {
		ieee80211_detach(&sc->ic);
		zyd_usb_deinit(sc);
		ddi_soft_state_free(zyd_ssp, instance);
		return (DDI_FAILURE);
	}

	/*
	 * Create minor node of type DDI_NT_NET_WIFI
	 */
	(void) snprintf(strbuf, sizeof (strbuf), ZYD_DRV_NAME"%d", instance);
	err = ddi_create_minor_node(dip, strbuf, S_IFCHR,
	    instance + 1, DDI_NT_NET_WIFI, 0);
	if (err != DDI_SUCCESS)
		ZYD_WARN("failed to create minor node\n");

	/* initialize locking */
	zyd_serial_init(sc);

	return (DDI_SUCCESS);
}

/*
 * Detach the driver from a device.
 *
 * Concurrency: Will be called only after a successful attach
 * (and not concurrently).
 */
static int
zyd_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	struct zyd_softc *sc = NULL;

	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_SUSPEND:
		sc = ddi_get_soft_state(zyd_ssp, ddi_get_instance(dip));
		ASSERT(sc != NULL);

		return (zyd_suspend(sc));

	default:
		return (DDI_FAILURE);
	}

	sc = ddi_get_soft_state(zyd_ssp, ddi_get_instance(dip));
	ASSERT(sc != NULL);

	if (mac_disable(sc->ic.ic_mach) != 0)
		return (DDI_FAILURE);
	/*
	 * Unregister from the MAC layer subsystem
	 */
	(void) mac_unregister(sc->ic.ic_mach);

	/*
	 * Detach ieee80211
	 */
	ieee80211_detach(&sc->ic);

	zyd_hw_deinit(sc);
	zyd_usb_deinit(sc);

	/* At this point it should be safe to release & destroy the locks */
	zyd_serial_deinit(sc);

	ddi_remove_minor_node(dip, NULL);
	ddi_soft_state_free(zyd_ssp, ddi_get_instance(dip));
	return (DDI_SUCCESS);
}

/*
 * Mac Call Back functions
 */

/*
 * Read device statistic information.
 */
static int
zyd_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	struct zyd_softc *sc = (struct zyd_softc *)arg;
	ieee80211com_t *ic = &sc->ic;
	ieee80211_node_t *in;

	switch (stat) {
	case MAC_STAT_IFSPEED:
		if (!sc->usb.connected || sc->suspended || !sc->running)
			return (ENOTSUP);
		in = ieee80211_ref_node(ic->ic_bss);
		*val = ((ic->ic_fixed_rate == IEEE80211_FIXED_RATE_NONE) ?
		    IEEE80211_RATE(in->in_txrate) :
		    ic->ic_fixed_rate) / 2 * 1000000;
		ieee80211_free_node(in);
		break;
	case MAC_STAT_NOXMTBUF:
		*val = sc->tx_nobuf;
		break;
	case MAC_STAT_NORCVBUF:
		*val = sc->rx_nobuf;
		break;
	case MAC_STAT_IERRORS:
		*val = sc->rx_err;
		break;
	case MAC_STAT_RBYTES:
		*val = ic->ic_stats.is_rx_bytes;
		break;
	case MAC_STAT_IPACKETS:
		*val = ic->ic_stats.is_rx_frags;
		break;
	case MAC_STAT_OBYTES:
		*val = ic->ic_stats.is_tx_bytes;
		break;
	case MAC_STAT_OPACKETS:
		*val = ic->ic_stats.is_tx_frags;
		break;
	case MAC_STAT_OERRORS:
	case WIFI_STAT_TX_FAILED:
		*val = sc->tx_err;
		break;
	case WIFI_STAT_TX_RETRANS:
	case WIFI_STAT_FCS_ERRORS:
	case WIFI_STAT_WEP_ERRORS:
	case WIFI_STAT_TX_FRAGS:
	case WIFI_STAT_MCAST_TX:
	case WIFI_STAT_RTS_SUCCESS:
	case WIFI_STAT_RTS_FAILURE:
	case WIFI_STAT_ACK_FAILURE:
	case WIFI_STAT_RX_FRAGS:
	case WIFI_STAT_MCAST_RX:
	case WIFI_STAT_RX_DUPS:
		return (ieee80211_stat(ic, stat, val));
	default:
		return (ENOTSUP);
	}
	return (0);
}

/*
 * Start the device.
 *
 * Concurrency: Presumably fully concurrent, must lock.
 */
static int
zyd_m_start(void *arg)
{
	struct zyd_softc *sc = (struct zyd_softc *)arg;

	(void) zyd_serial_enter(sc, ZYD_NO_SIG);
	if ((!sc->usb.connected) || (zyd_hw_start(sc) != ZYD_SUCCESS)) {
		zyd_serial_exit(sc);
		return (DDI_FAILURE);
	}
	zyd_serial_exit(sc);

	ieee80211_new_state(&sc->ic, IEEE80211_S_INIT, -1);
	sc->running = B_TRUE;

	return (DDI_SUCCESS);
}

/*
 * Stop the device.
 */
static void
zyd_m_stop(void *arg)
{
	struct zyd_softc *sc = (struct zyd_softc *)arg;

	sc->running = B_FALSE;
	ieee80211_new_state(&sc->ic, IEEE80211_S_INIT, -1);

	(void) zyd_serial_enter(sc, ZYD_NO_SIG);
	sc->resched = B_FALSE;
	zyd_hw_stop(sc);
	zyd_serial_exit(sc);
}

/*
 * Change the MAC address of the device.
 */
/*ARGSUSED*/
static int
zyd_m_unicst(void *arg, const uint8_t *macaddr)
{
	return (DDI_FAILURE);
}

/*
 * Enable/disable multicast.
 */
/*ARGSUSED*/
static int
zyd_m_multicst(void *arg, boolean_t add, const uint8_t *m)
{
	ZYD_DEBUG((ZYD_DBG_GLD, "multicast not implemented\n"));
	return (DDI_SUCCESS);
}

/*
 * Enable/disable promiscuous mode.
 */
/*ARGSUSED*/
static int
zyd_m_promisc(void *arg, boolean_t on)
{
	ZYD_DEBUG((ZYD_DBG_GLD, "promiscuous not implemented\n"));
	return (DDI_SUCCESS);
}

/*
 * IOCTL request.
 */
static void
zyd_m_ioctl(void *arg, queue_t *wq, mblk_t *mp)
{
	struct zyd_softc *sc = (struct zyd_softc *)arg;
	struct ieee80211com *ic = &sc->ic;

	if (!sc->usb.connected || sc->suspended || !sc->running) {
		miocnak(wq, mp, 0, ENXIO);
		return;
	}

	if (ieee80211_ioctl(ic, wq, mp) == ENETRESET) {
		if (sc->running && ic->ic_des_esslen) {
			zyd_m_stop(sc);
			if (zyd_m_start(sc) != DDI_SUCCESS)
				return;
			ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
		}
	}
}

/*
 * callback functions for /get/set properties
 */
static int
zyd_m_setprop(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    uint_t wldp_length, const void *wldp_buf)
{
	struct zyd_softc *sc = (struct zyd_softc *)arg;
	struct ieee80211com *ic = &sc->ic;
	int err;

	if (!sc->usb.connected || sc->suspended || !sc->running) {
		return (ENXIO);
	}

	err = ieee80211_setprop(ic, pr_name, wldp_pr_num, wldp_length,
	    wldp_buf);
	if (err == ENETRESET) {
		if (sc->running && ic->ic_des_esslen) {
			zyd_m_stop(sc);
			if (zyd_m_start(sc) != DDI_SUCCESS)
				return (DDI_FAILURE);
			ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
		}
		err = 0;
	}

	return (err);
}

static int
zyd_m_getprop(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    uint_t wldp_length, void *wldp_buf)
{
	struct zyd_softc *sc = (struct zyd_softc *)arg;
	int err;

	if (!sc->usb.connected || sc->suspended || !sc->running) {
		return (DDI_FAILURE);
	}

	err = ieee80211_getprop(&sc->ic, pr_name, wldp_pr_num,
	    wldp_length, wldp_buf);

	return (err);
}

static void
zyd_m_propinfo(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    mac_prop_info_handle_t mph)
{
	struct zyd_softc *sc = (struct zyd_softc *)arg;

	ieee80211_propinfo(&sc->ic, pr_name, wldp_pr_num, mph);
}

/*
 * Transmit a data frame.
 */
static mblk_t *
zyd_m_tx(void *arg, mblk_t *mp)
{
	struct zyd_softc *sc = (struct zyd_softc *)arg;
	struct ieee80211com *ic = &sc->ic;
	mblk_t *next;

	ASSERT(mp != NULL);

	/* not associated, drop data frames */
	if (ic->ic_state != IEEE80211_S_RUN) {
		freemsg(mp);
		return (DDI_SUCCESS);
	}

	while (mp != NULL) {
		next = mp->b_next;
		mp->b_next = NULL;

		if (zyd_send(ic, mp, IEEE80211_FC0_TYPE_DATA) != DDI_SUCCESS) {
			mp->b_next = next;
			break;
		}
		mp = next;
	}

	return (mp);
}

/*
 * xxx_newstate callback for net80211.
 *
 * Called by net80211 whenever the ieee80211 state changes.
 */
static int
zyd_newstate(struct ieee80211com *ic, enum ieee80211_state nstate, int arg)
{
	struct zyd_softc *sc = ZYD_IC_TO_SOFTC(ic);
	struct ieee80211_node *in;
	uint_t chan;

	if (sc->timeout_id != 0) {
		(void) untimeout(sc->timeout_id);
		sc->timeout_id = 0;
	}

	if (!sc->usb.connected || sc->suspended || !sc->running) {
		return (sc->newstate(ic, nstate, arg));
	}

	switch (nstate) {
	case IEEE80211_S_SCAN:
		ZYD_DEBUG((ZYD_DBG_SCAN, "scan timer: starting next\n"));
		sc->timeout_id = timeout(zyd_next_scan, sc,
		    drv_usectohz(ZYD_DWELL_TIME));
		/*FALLTHRU*/
	case IEEE80211_S_AUTH:
	case IEEE80211_S_ASSOC:
	case IEEE80211_S_RUN:
		chan = ieee80211_chan2ieee(ic, ic->ic_curchan);
		if (chan == 0 || chan == IEEE80211_CHAN_ANY) {
			ZYD_WARN("invalid channel number\n");
			return (0);
		}
		(void) zyd_serial_enter(sc, ZYD_SER_SIG);
		zyd_hw_set_channel(sc, chan);
		zyd_serial_exit(sc);

		in = ic->ic_bss;
		in->in_txrate = in->in_rates.ir_nrates - 1;
	default:
		break;
	}

	return (sc->newstate(ic, nstate, arg));
}

/*
 * USB-safe synchronization.
 * Debugging routines.
 *
 * Kmutexes should never be held when making calls to USBA
 * or when sleeping. Thus, we implement our own "mutex" on top
 * of kmutexes and kcondvars.
 *
 * Usage: Any (possibly concurrent) access to the soft state or device must
 * be serialized with a pair of zyd_serial_enter()/zyd_serial_exit().
 */
/*
 * Initialize the serialization object.
 */
void
zyd_serial_init(struct zyd_softc *sc)
{
	mutex_init(&sc->serial.lock, NULL, MUTEX_DRIVER,
	    sc->usb.cdata->dev_iblock_cookie);
	cv_init(&sc->serial.wait, NULL, CV_DRIVER, NULL);

	sc->serial.held = B_FALSE;
	sc->serial.initialized = B_TRUE;
}

/*
 * Wait for the serialization object.
 *
 * If wait_sig is ZYD_SER_SIG, the function may return
 * a signal is received. In this case, the serialization object
 * is not acquired (but the mutex is) and the return value is ZYD_FAILURE.
 *
 * In any other case the function returns ZYD_SUCCESS and the
 * serialization object is acquired.
 */
zyd_res
zyd_serial_enter(struct zyd_softc *sc, boolean_t wait_sig)
{
	zyd_res res;

	mutex_enter(&sc->serial.lock);

	res = ZYD_SUCCESS;

	while (sc->serial.held != B_FALSE) {
		if (wait_sig == ZYD_SER_SIG) {
			res = cv_wait_sig(&sc->serial.wait, &sc->serial.lock);
		} else {
			cv_wait(&sc->serial.wait, &sc->serial.lock);
		}
	}
	sc->serial.held = B_TRUE;

	mutex_exit(&sc->serial.lock);

	return (res);
}

/*
 * Release the serialization object.
 */
void
zyd_serial_exit(struct zyd_softc *sc)
{
	mutex_enter(&sc->serial.lock);
	sc->serial.held = B_FALSE;
	cv_broadcast(&sc->serial.wait);
	mutex_exit(&sc->serial.lock);
}

/*
 * Destroy the serialization object.
 */
void
zyd_serial_deinit(struct zyd_softc *sc)
{
	cv_destroy(&sc->serial.wait);
	mutex_destroy(&sc->serial.lock);

	sc->serial.initialized = B_FALSE;
}


/*
 * zyd_cb_lock: a special signal structure that is used for notification
 * that a callback function has been called.
 */

/* Initializes the zyd_cb_lock structure. */
void
zyd_cb_lock_init(struct zyd_cb_lock *lock)
{
	ASSERT(lock != NULL);
	mutex_init(&lock->mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&lock->cv, NULL, CV_DRIVER, NULL);
	lock->done = B_FALSE;
}

/* Deinitalizes the zyd_cb_lock structure. */
void
zyd_cb_lock_destroy(struct zyd_cb_lock *lock)
{
	ASSERT(lock != NULL);
	mutex_destroy(&lock->mutex);
	cv_destroy(&lock->cv);
}

/*
 * Wait on lock until someone calls the "signal" function or the timeout
 * expires. Note: timeout is in microseconds.
 */
zyd_res
zyd_cb_lock_wait(struct zyd_cb_lock *lock, clock_t timeout)
{
	zyd_res res;
	clock_t etime;
	int cv_res;

	ASSERT(lock != NULL);

	mutex_enter(&lock->mutex);

	if (timeout < 0) {
		/* no timeout - wait as long as needed */
		while (lock->done == B_FALSE)
			(void) cv_wait(&lock->cv, &lock->mutex);
	} else {
		/* wait with timeout (given in usec) */
		etime = ddi_get_lbolt() + drv_usectohz(timeout);
		while (lock->done == B_FALSE) {
			cv_res =
			    cv_timedwait_sig(&lock->cv, &lock->mutex, etime);
			if (cv_res <= 0)
				break;
		}
	}

	res = (lock->done == B_TRUE) ? ZYD_SUCCESS : ZYD_FAILURE;

	mutex_exit(&lock->mutex);

	return (res);
}

/* Signal that the job (eg. callback) is done and unblock anyone who waits. */
void
zyd_cb_lock_signal(struct zyd_cb_lock *lock)
{
	ASSERT(lock != NULL);

	mutex_enter(&lock->mutex);

	lock->done = B_TRUE;
	cv_broadcast(&lock->cv);

	mutex_exit(&lock->mutex);
}

/*
 * Loadable module configuration entry points
 */

/*
 * _init module entry point.
 *
 * Called when the module is being loaded into memory.
 */
int
_init(void)
{
	int err;

	err = ddi_soft_state_init(&zyd_ssp, sizeof (struct zyd_softc), 1);

	if (err != DDI_SUCCESS)
		return (err);

	mac_init_ops(&zyd_devops, ZYD_DRV_NAME);
	err = mod_install(&zyd_ml);

	if (err != DDI_SUCCESS) {
		mac_fini_ops(&zyd_devops);
		ddi_soft_state_fini(&zyd_ssp);
	}

	return (err);
}

/*
 * _info module entry point.
 *
 * Called to obtain information about the module.
 */
int
_info(struct modinfo *modinfop)
{
	return (mod_info(&zyd_ml, modinfop));
}

/*
 * _fini module entry point.
 *
 * Called when the module is being unloaded.
 */
int
_fini(void)
{
	int err;

	err = mod_remove(&zyd_ml);
	if (err == DDI_SUCCESS) {
		mac_fini_ops(&zyd_devops);
		ddi_soft_state_fini(&zyd_ssp);
	}

	return (err);
}
