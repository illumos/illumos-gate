/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2005, 2006
 *	Damien Bergamini <damien.bergamini@free.fr>
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
 */

/*
 * Ralink Technology RT2500USB chipset driver
 * http://www.ralinktech.com/
 */
#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/strsubr.h>
#include <sys/modctl.h>
#include <sys/devops.h>
#include <sys/byteorder.h>
#include <sys/mac_provider.h>
#include <sys/mac_wifi.h>
#include <sys/net80211.h>

#define	USBDRV_MAJOR_VER	2
#define	USBDRV_MINOR_VER	0
#include <sys/usb/usba.h>
#include <sys/usb/usba/usba_types.h>

#include "ural_reg.h"
#include "ural_var.h"

static void *ural_soft_state_p = NULL;

#define	RAL_TXBUF_SIZE  	(IEEE80211_MAX_LEN)
#define	RAL_RXBUF_SIZE  	(IEEE80211_MAX_LEN)

/* quickly determine if a given rate is CCK or OFDM */
#define	RAL_RATE_IS_OFDM(rate)	((rate) >= 12 && (rate) != 22)
#define	RAL_ACK_SIZE		14	/* 10 + 4(FCS) */
#define	RAL_CTS_SIZE		14	/* 10 + 4(FCS) */
#define	RAL_SIFS		10	/* us */
#define	RAL_RXTX_TURNAROUND	5	/* us */

#define	URAL_N(a)		(sizeof (a) / sizeof ((a)[0]))

/*
 * Supported rates for 802.11a/b/g modes (in 500Kbps unit).
 */
static const struct ieee80211_rateset ural_rateset_11a =
	{ 8, { 12, 18, 24, 36, 48, 72, 96, 108 } };

static const struct ieee80211_rateset ural_rateset_11b =
	{ 4, { 2, 4, 11, 22 } };

static const struct ieee80211_rateset ural_rateset_11g =
	{ 12, { 2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108 } };

/*
 * Default values for MAC registers; values taken from the reference driver.
 */
static const struct {
	uint16_t	reg;
	uint16_t	val;
} ural_def_mac[] = {
	{ RAL_TXRX_CSR5,  0x8c8d },
	{ RAL_TXRX_CSR6,  0x8b8a },
	{ RAL_TXRX_CSR7,  0x8687 },
	{ RAL_TXRX_CSR8,  0x0085 },
	{ RAL_MAC_CSR13,  0x1111 },
	{ RAL_MAC_CSR14,  0x1e11 },
	{ RAL_TXRX_CSR21, 0xe78f },
	{ RAL_MAC_CSR9,   0xff1d },
	{ RAL_MAC_CSR11,  0x0002 },
	{ RAL_MAC_CSR22,  0x0053 },
	{ RAL_MAC_CSR15,  0x0000 },
	{ RAL_MAC_CSR8,   0x0780 },
	{ RAL_TXRX_CSR19, 0x0000 },
	{ RAL_TXRX_CSR18, 0x005a },
	{ RAL_PHY_CSR2,   0x0000 },
	{ RAL_TXRX_CSR0,  0x1ec0 },
	{ RAL_PHY_CSR4,   0x000f }
};

/*
 * Default values for BBP registers; values taken from the reference driver.
 */
static const struct {
	uint8_t	reg;
	uint8_t	val;
} ural_def_bbp[] = {
	{  3, 0x02 },
	{  4, 0x19 },
	{ 14, 0x1c },
	{ 15, 0x30 },
	{ 16, 0xac },
	{ 17, 0x48 },
	{ 18, 0x18 },
	{ 19, 0xff },
	{ 20, 0x1e },
	{ 21, 0x08 },
	{ 22, 0x08 },
	{ 23, 0x08 },
	{ 24, 0x80 },
	{ 25, 0x50 },
	{ 26, 0x08 },
	{ 27, 0x23 },
	{ 30, 0x10 },
	{ 31, 0x2b },
	{ 32, 0xb9 },
	{ 34, 0x12 },
	{ 35, 0x50 },
	{ 39, 0xc4 },
	{ 40, 0x02 },
	{ 41, 0x60 },
	{ 53, 0x10 },
	{ 54, 0x18 },
	{ 56, 0x08 },
	{ 57, 0x10 },
	{ 58, 0x08 },
	{ 61, 0x60 },
	{ 62, 0x10 },
	{ 75, 0xff }
};

/*
 * Default values for RF register R2 indexed by channel numbers.
 */
static const uint32_t ural_rf2522_r2[] = {
	0x307f6, 0x307fb, 0x30800, 0x30805, 0x3080a, 0x3080f, 0x30814,
	0x30819, 0x3081e, 0x30823, 0x30828, 0x3082d, 0x30832, 0x3083e
};

static const uint32_t ural_rf2523_r2[] = {
	0x00327, 0x00328, 0x00329, 0x0032a, 0x0032b, 0x0032c, 0x0032d,
	0x0032e, 0x0032f, 0x00340, 0x00341, 0x00342, 0x00343, 0x00346
};

static const uint32_t ural_rf2524_r2[] = {
	0x00327, 0x00328, 0x00329, 0x0032a, 0x0032b, 0x0032c, 0x0032d,
	0x0032e, 0x0032f, 0x00340, 0x00341, 0x00342, 0x00343, 0x00346
};

static const uint32_t ural_rf2525_r2[] = {
	0x20327, 0x20328, 0x20329, 0x2032a, 0x2032b, 0x2032c, 0x2032d,
	0x2032e, 0x2032f, 0x20340, 0x20341, 0x20342, 0x20343, 0x20346
};

static const uint32_t ural_rf2525_hi_r2[] = {
	0x2032f, 0x20340, 0x20341, 0x20342, 0x20343, 0x20344, 0x20345,
	0x20346, 0x20347, 0x20348, 0x20349, 0x2034a, 0x2034b, 0x2034e
};

static const uint32_t ural_rf2525e_r2[] = {
	0x2044d, 0x2044e, 0x2044f, 0x20460, 0x20461, 0x20462, 0x20463,
	0x20464, 0x20465, 0x20466, 0x20467, 0x20468, 0x20469, 0x2046b
};

static const uint32_t ural_rf2526_hi_r2[] = {
	0x0022a, 0x0022b, 0x0022b, 0x0022c, 0x0022c, 0x0022d, 0x0022d,
	0x0022e, 0x0022e, 0x0022f, 0x0022d, 0x00240, 0x00240, 0x00241
};

static const uint32_t ural_rf2526_r2[] = {
	0x00226, 0x00227, 0x00227, 0x00228, 0x00228, 0x00229, 0x00229,
	0x0022a, 0x0022a, 0x0022b, 0x0022b, 0x0022c, 0x0022c, 0x0022d
};

/*
 * For dual-band RF, RF registers R1 and R4 also depend on channel number;
 * values taken from the reference driver.
 */
static const struct {
	uint8_t		chan;
	uint32_t	r1;
	uint32_t	r2;
	uint32_t	r4;
} ural_rf5222[] = {
	{   1, 0x08808, 0x0044d, 0x00282 },
	{   2, 0x08808, 0x0044e, 0x00282 },
	{   3, 0x08808, 0x0044f, 0x00282 },
	{   4, 0x08808, 0x00460, 0x00282 },
	{   5, 0x08808, 0x00461, 0x00282 },
	{   6, 0x08808, 0x00462, 0x00282 },
	{   7, 0x08808, 0x00463, 0x00282 },
	{   8, 0x08808, 0x00464, 0x00282 },
	{   9, 0x08808, 0x00465, 0x00282 },
	{  10, 0x08808, 0x00466, 0x00282 },
	{  11, 0x08808, 0x00467, 0x00282 },
	{  12, 0x08808, 0x00468, 0x00282 },
	{  13, 0x08808, 0x00469, 0x00282 },
	{  14, 0x08808, 0x0046b, 0x00286 },

	{  36, 0x08804, 0x06225, 0x00287 },
	{  40, 0x08804, 0x06226, 0x00287 },
	{  44, 0x08804, 0x06227, 0x00287 },
	{  48, 0x08804, 0x06228, 0x00287 },
	{  52, 0x08804, 0x06229, 0x00287 },
	{  56, 0x08804, 0x0622a, 0x00287 },
	{  60, 0x08804, 0x0622b, 0x00287 },
	{  64, 0x08804, 0x0622c, 0x00287 },

	{ 100, 0x08804, 0x02200, 0x00283 },
	{ 104, 0x08804, 0x02201, 0x00283 },
	{ 108, 0x08804, 0x02202, 0x00283 },
	{ 112, 0x08804, 0x02203, 0x00283 },
	{ 116, 0x08804, 0x02204, 0x00283 },
	{ 120, 0x08804, 0x02205, 0x00283 },
	{ 124, 0x08804, 0x02206, 0x00283 },
	{ 128, 0x08804, 0x02207, 0x00283 },
	{ 132, 0x08804, 0x02208, 0x00283 },
	{ 136, 0x08804, 0x02209, 0x00283 },
	{ 140, 0x08804, 0x0220a, 0x00283 },

	{ 149, 0x08808, 0x02429, 0x00281 },
	{ 153, 0x08808, 0x0242b, 0x00281 },
	{ 157, 0x08808, 0x0242d, 0x00281 },
	{ 161, 0x08808, 0x0242f, 0x00281 }
};

/*
 * device operations
 */
static int ural_attach(dev_info_t *, ddi_attach_cmd_t);
static int ural_detach(dev_info_t *, ddi_detach_cmd_t);

/*
 * Module Loading Data & Entry Points
 */
DDI_DEFINE_STREAM_OPS(ural_dev_ops, nulldev, nulldev, ural_attach,
    ural_detach, nodev, NULL, D_MP, NULL, ddi_quiesce_not_needed);

static struct modldrv ural_modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	"ural driver v1.4",	/* short description */
	&ural_dev_ops		/* driver specific ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&ural_modldrv,
	NULL
};

static int	ural_m_stat(void *,  uint_t, uint64_t *);
static int	ural_m_start(void *);
static void	ural_m_stop(void *);
static int	ural_m_promisc(void *, boolean_t);
static int	ural_m_multicst(void *, boolean_t, const uint8_t *);
static int	ural_m_unicst(void *, const uint8_t *);
static mblk_t	*ural_m_tx(void *, mblk_t *);
static void	ural_m_ioctl(void *, queue_t *, mblk_t *);
static int	ural_m_setprop(void *, const char *, mac_prop_id_t,
    uint_t, const void *);
static int	ural_m_getprop(void *, const char *, mac_prop_id_t,
    uint_t, void *);
static void	ural_m_propinfo(void *, const char *, mac_prop_id_t,
    mac_prop_info_handle_t);

static mac_callbacks_t ural_m_callbacks = {
	MC_IOCTL | MC_SETPROP | MC_GETPROP | MC_PROPINFO,
	ural_m_stat,
	ural_m_start,
	ural_m_stop,
	ural_m_promisc,
	ural_m_multicst,
	ural_m_unicst,
	ural_m_tx,
	NULL,
	ural_m_ioctl,
	NULL,		/* mc_getcapab */
	NULL,
	NULL,
	ural_m_setprop,
	ural_m_getprop,
	ural_m_propinfo
};

static void ural_amrr_start(struct ural_softc *, struct ieee80211_node *);
static int  ural_tx_trigger(struct ural_softc *, mblk_t *);
static int  ural_rx_trigger(struct ural_softc *);

uint32_t ural_dbg_flags = 0;

void
ral_debug(uint32_t dbg_flags, const int8_t *fmt, ...)
{
	va_list args;

	if (dbg_flags & ural_dbg_flags) {
		va_start(args, fmt);
		vcmn_err(CE_CONT, fmt, args);
		va_end(args);
	}
}

static uint16_t
ural_read(struct ural_softc *sc, uint16_t reg)
{
	usb_ctrl_setup_t req;
	usb_cr_t cr;
	usb_cb_flags_t cf;
	mblk_t *mp;
	int err;
	uint16_t val;

	bzero(&req, sizeof (req));
	req.bmRequestType = USB_DEV_REQ_TYPE_VENDOR | USB_DEV_REQ_DEV_TO_HOST;
	req.bRequest = RAL_READ_MAC;
	req.wValue = 0;
	req.wIndex = reg;
	req.wLength = sizeof (uint16_t);

	mp = NULL;
	err = usb_pipe_ctrl_xfer_wait(sc->sc_udev->dev_default_ph, &req, &mp,
	    &cr, &cf, 0);

	if (err != USB_SUCCESS) {
		ral_debug(RAL_DBG_ERR,
		    "ural_read(): could not read MAC register:"
		    " cr:%s(%d), cf:(%x)\n",
		    usb_str_cr(cr), cr, cf);
		return (0);
	}

	bcopy(mp->b_rptr, &val, sizeof (uint16_t));

	if (mp)
		freemsg(mp);

	return (LE_16(val));
}

static void
ural_read_multi(struct ural_softc *sc, uint16_t reg, void *buf, int len)
{
	usb_ctrl_setup_t req;
	usb_cr_t cr;
	usb_cb_flags_t cf;
	mblk_t *mp;
	int err;

	bzero(&req, sizeof (req));
	req.bmRequestType = USB_DEV_REQ_TYPE_VENDOR | USB_DEV_REQ_DEV_TO_HOST;
	req.bRequest = RAL_READ_MULTI_MAC;
	req.wValue = 0;
	req.wIndex = reg;
	req.wLength = (uint16_t)len;
	req.attrs = USB_ATTRS_AUTOCLEARING;

	mp = NULL;
	err = usb_pipe_ctrl_xfer_wait(sc->sc_udev->dev_default_ph, &req, &mp,
	    &cr, &cf, 0);

	if (err != USB_SUCCESS) {
		ral_debug(RAL_DBG_ERR,
		    "ural_read_multi(): could not read MAC register:"
		    "cr:%s(%d), cf:(%x)\n",
		    usb_str_cr(cr), cr, cf);
		return;
	}

	bcopy(mp->b_rptr, buf, len);

	if (mp)
		freemsg(mp);
}

static void
ural_write(struct ural_softc *sc, uint16_t reg, uint16_t val)
{
	usb_ctrl_setup_t req;
	usb_cr_t cr;
	usb_cb_flags_t cf;
	int err;

	bzero(&req, sizeof (req));
	req.bmRequestType = USB_DEV_REQ_TYPE_VENDOR | USB_DEV_REQ_HOST_TO_DEV;
	req.bRequest = RAL_WRITE_MAC;
	req.wValue = val;
	req.wIndex = reg;
	req.wLength = 0;
	req.attrs = USB_ATTRS_NONE;

	err = usb_pipe_ctrl_xfer_wait(sc->sc_udev->dev_default_ph, &req, NULL,
	    &cr, &cf, 0);

	if (err != USB_SUCCESS) {
		ral_debug(RAL_DBG_ERR,
		    "ural_write(): could not write MAC register:"
		    "cr:%s(%d), cf:(%x)\n",
		    usb_str_cr(cr), cr, cf);
	}
}

/* ARGSUSED */
static void
ural_txeof(usb_pipe_handle_t pipe, usb_bulk_req_t *req)
{
	struct ural_softc *sc = (struct ural_softc *)req->bulk_client_private;
	struct ieee80211com *ic = &sc->sc_ic;

	ral_debug(RAL_DBG_TX,
	    "ural_txeof(): cr:%s(%d), flags:0x%x, tx_queued:%d",
	    usb_str_cr(req->bulk_completion_reason),
	    req->bulk_completion_reason,
	    req->bulk_cb_flags,
	    sc->tx_queued);

	if (req->bulk_completion_reason != USB_CR_OK)
		sc->sc_tx_err++;

	mutex_enter(&sc->tx_lock);

	sc->tx_queued--;
	sc->sc_tx_timer = 0;

	if (sc->sc_need_sched) {
		sc->sc_need_sched = 0;
		mac_tx_update(ic->ic_mach);
	}

	mutex_exit(&sc->tx_lock);
	usb_free_bulk_req(req);
}

/* ARGSUSED */
static void
ural_rxeof(usb_pipe_handle_t pipe, usb_bulk_req_t *req)
{
	struct ural_softc *sc = (struct ural_softc *)req->bulk_client_private;
	struct ieee80211com *ic = &sc->sc_ic;

	struct ural_rx_desc *desc;
	struct ieee80211_frame *wh;
	struct ieee80211_node *ni;

	mblk_t *m, *mp;
	int len, pktlen;
	char *rxbuf;

	mp = req->bulk_data;
	req->bulk_data = NULL;

	ral_debug(RAL_DBG_RX,
	    "ural_rxeof(): cr:%s(%d), flags:0x%x, rx_queued:%d",
	    usb_str_cr(req->bulk_completion_reason),
	    req->bulk_completion_reason,
	    req->bulk_cb_flags,
	    sc->rx_queued);

	if (req->bulk_completion_reason != USB_CR_OK) {
		sc->sc_rx_err++;
		goto fail;
	}

	len = (uintptr_t)mp->b_wptr - (uintptr_t)mp->b_rptr;
	rxbuf = (char *)mp->b_rptr;

	if (len < RAL_RX_DESC_SIZE + IEEE80211_MIN_LEN) {
		ral_debug(RAL_DBG_ERR,
		    "ural_rxeof(): xfer too short %d\n", len);
		sc->sc_rx_err++;
		goto fail;
	}

	/* rx descriptor is located at the end */
	desc = (struct ural_rx_desc *)(rxbuf + len - RAL_RX_DESC_SIZE);

	if ((LE_32(desc->flags) & RAL_RX_PHY_ERROR) ||
	    (LE_32(desc->flags) & RAL_RX_CRC_ERROR)) {
		/*
		 * This should not happen since we did not request to receive
		 * those frames when we filled RAL_TXRX_CSR2.
		 */
		ral_debug(RAL_DBG_ERR, "PHY or CRC error\n");
		sc->sc_rx_err++;
		goto fail;
	}

	pktlen = (LE_32(desc->flags) >> 16) & 0xfff;

	if (pktlen > (len - RAL_RX_DESC_SIZE)) {
		ral_debug(RAL_DBG_ERR,
		    "ural_rxeof(): pktlen mismatch <%d, %d>.\n", pktlen, len);
		goto fail;
	}

	/* Strip trailing 802.11 MAC FCS. */
	pktlen -= IEEE80211_CRC_LEN;

	if ((m = allocb(pktlen, BPRI_MED)) == NULL) {
		ral_debug(RAL_DBG_ERR,
		    "ural_rxeof(): allocate mblk failed.\n");
		sc->sc_rx_nobuf++;
		goto fail;
	}

	bcopy(rxbuf, m->b_rptr, pktlen);
	m->b_wptr += pktlen;

	wh = (struct ieee80211_frame *)m->b_rptr;
	ni = ieee80211_find_rxnode(ic, wh);

	/* send the frame to the 802.11 layer */
	(void) ieee80211_input(ic, m, ni, desc->rssi, 0);

	/* node is no longer needed */
	ieee80211_free_node(ni);
fail:
	mutex_enter(&sc->rx_lock);
	sc->rx_queued--;
	mutex_exit(&sc->rx_lock);

	freemsg(mp);
	usb_free_bulk_req(req);

	if (RAL_IS_RUNNING(sc))
		(void) ural_rx_trigger(sc);
}

/*
 * Return the expected ack rate for a frame transmitted at rate `rate'.
 * this should depend on the destination node basic rate set.
 */
static int
ural_ack_rate(struct ieee80211com *ic, int rate)
{
	switch (rate) {
	/* CCK rates */
	case 2:
		return (2);
	case 4:
	case 11:
	case 22:
		return ((ic->ic_curmode == IEEE80211_MODE_11B) ? 4 : rate);

	/* OFDM rates */
	case 12:
	case 18:
		return (12);
	case 24:
	case 36:
		return (24);
	case 48:
	case 72:
	case 96:
	case 108:
		return (48);
	}

	/* default to 1Mbps */
	return (2);
}

/*
 * Compute the duration (in us) needed to transmit `len' bytes at rate `rate'.
 * The function automatically determines the operating mode depending on the
 * given rate. `flags' indicates whether short preamble is in use or not.
 */
static uint16_t
ural_txtime(int len, int rate, uint32_t flags)
{
	uint16_t txtime;

	if (RAL_RATE_IS_OFDM(rate)) {
		/* IEEE Std 802.11a-1999, pp. 37 */
		txtime = (8 + 4 * len + 3 + rate - 1) / rate;
		txtime = 16 + 4 + 4 * txtime + 6;
	} else {
		/* IEEE Std 802.11b-1999, pp. 28 */
		txtime = (16 * len + rate - 1) / rate;
		if (rate != 2 && (flags & IEEE80211_F_SHPREAMBLE))
			txtime +=  72 + 24;
		else
			txtime += 144 + 48;
	}
	return (txtime);
}

static uint8_t
ural_plcp_signal(int rate)
{
	switch (rate) {
	/* CCK rates (returned values are device-dependent) */
	case 2:		return (0x0);
	case 4:		return (0x1);
	case 11:	return (0x2);
	case 22:	return (0x3);

	/* OFDM rates (cf IEEE Std 802.11a-1999, pp. 14 Table 80) */
	case 12:	return (0xb);
	case 18:	return (0xf);
	case 24:	return (0xa);
	case 36:	return (0xe);
	case 48:	return (0x9);
	case 72:	return (0xd);
	case 96:	return (0x8);
	case 108:	return (0xc);

	/* unsupported rates (should not get there) */
	default:	return (0xff);
	}
}

static void
ural_setup_tx_desc(struct ural_softc *sc, struct ural_tx_desc *desc,
    uint32_t flags, int len, int rate)
{
	struct ieee80211com *ic = &sc->sc_ic;
	uint16_t plcp_length;
	int remainder;

	desc->flags = LE_32(flags);
	desc->flags |= LE_32(RAL_TX_NEWSEQ);
	desc->flags |= LE_32(len << 16);

	desc->wme = LE_16(RAL_AIFSN(2) | RAL_LOGCWMIN(3) | RAL_LOGCWMAX(5));
	desc->wme |= LE_16(RAL_IVOFFSET(sizeof (struct ieee80211_frame)));

	/* setup PLCP fields */
	desc->plcp_signal  = ural_plcp_signal(rate);
	desc->plcp_service = 4;

	len += IEEE80211_CRC_LEN;
	if (RAL_RATE_IS_OFDM(rate)) {
		desc->flags |= LE_32(RAL_TX_OFDM);

		plcp_length = len & 0xfff;
		desc->plcp_length_hi = plcp_length >> 6;
		desc->plcp_length_lo = plcp_length & 0x3f;
	} else {
		plcp_length = (16 * len + rate - 1) / rate;
		if (rate == 22) {
			remainder = (16 * len) % 22;
			if (remainder != 0 && remainder < 7)
				desc->plcp_service |= RAL_PLCP_LENGEXT;
		}
		desc->plcp_length_hi = plcp_length >> 8;
		desc->plcp_length_lo = plcp_length & 0xff;

		if (rate != 2 && (ic->ic_flags & IEEE80211_F_SHPREAMBLE))
			desc->plcp_signal |= 0x08;
	}

	desc->iv = 0;
	desc->eiv = 0;
}

#define	RAL_TX_TIMEOUT		5

static int
ural_send(ieee80211com_t *ic, mblk_t *mp, uint8_t type)
{
	struct ural_softc *sc = (struct ural_softc *)ic;
	struct ural_tx_desc *desc;

	struct ieee80211_frame *wh;
	struct ieee80211_key *k;

	uint16_t dur;
	uint32_t flags = 0;
	int rate, err = DDI_SUCCESS;

	struct ieee80211_node *ni = NULL;
	mblk_t *m, *m0;
	int off, mblen, pktlen, xferlen;

	/* discard packets while suspending or not inited */
	if (!RAL_IS_RUNNING(sc)) {
		freemsg(mp);
		return (ENXIO);
	}

	mutex_enter(&sc->tx_lock);

	if (sc->tx_queued > RAL_TX_LIST_COUNT) {
		ral_debug(RAL_DBG_TX, "ural_send(): "
		    "no TX buffer available!\n");
		if ((type & IEEE80211_FC0_TYPE_MASK) ==
		    IEEE80211_FC0_TYPE_DATA) {
			sc->sc_need_sched = 1;
		}
		sc->sc_tx_nobuf++;
		err = ENOMEM;
		goto fail;
	}

	m = allocb(RAL_TXBUF_SIZE + RAL_TX_DESC_SIZE, BPRI_MED);
	if (m == NULL) {
		ral_debug(RAL_DBG_ERR, "ural_send(): can't alloc mblk.\n");
		err = DDI_FAILURE;
		goto fail;
	}

	m->b_rptr += RAL_TX_DESC_SIZE;	/* skip TX descriptor */
	m->b_wptr += RAL_TX_DESC_SIZE;

	for (off = 0, m0 = mp; m0 != NULL; m0 = m0->b_cont) {
		mblen = (uintptr_t)m0->b_wptr - (uintptr_t)m0->b_rptr;
		(void) memcpy(m->b_rptr + off, m0->b_rptr, mblen);
		off += mblen;
	}
	m->b_wptr += off;

	wh = (struct ieee80211_frame *)m->b_rptr;

	ni = ieee80211_find_txnode(ic, wh->i_addr1);
	if (ni == NULL) {
		err = DDI_FAILURE;
		sc->sc_tx_err++;
		freemsg(m);
		goto fail;
	}

	if ((type & IEEE80211_FC0_TYPE_MASK) ==
	    IEEE80211_FC0_TYPE_DATA) {
		(void) ieee80211_encap(ic, m, ni);
	}

	if (wh->i_fc[1] & IEEE80211_FC1_WEP) {
		k = ieee80211_crypto_encap(ic, m);
		if (k == NULL) {
			sc->sc_tx_err++;
			freemsg(m);
			err = DDI_FAILURE;
			goto fail;
		}
		/* packet header may have moved, reset our local pointer */
		wh = (struct ieee80211_frame *)m->b_rptr;
	}

	m->b_rptr -= RAL_TX_DESC_SIZE;	/* restore */
	desc = (struct ural_tx_desc *)m->b_rptr;

	if ((type & IEEE80211_FC0_TYPE_MASK) ==
	    IEEE80211_FC0_TYPE_DATA) {	/* DATA */
		if (ic->ic_fixed_rate != IEEE80211_FIXED_RATE_NONE)
			rate = ic->ic_bss->in_rates.ir_rates[ic->ic_fixed_rate];
		else
			rate = ni->in_rates.ir_rates[ni->in_txrate];

		rate &= IEEE80211_RATE_VAL;
		if (rate <= 0) {
			rate = 2;	/* basic rate */
		}

		if (!IEEE80211_IS_MULTICAST(wh->i_addr1)) {
			flags |= RAL_TX_ACK;
			flags |= RAL_TX_RETRY(7);

			dur = ural_txtime(RAL_ACK_SIZE, ural_ack_rate(ic, rate),
			    ic->ic_flags) + RAL_SIFS;
			*(uint16_t *)(uintptr_t)wh->i_dur = LE_16(dur);
		}
	} else {	/* MGMT */
		rate = IEEE80211_IS_CHAN_5GHZ(ic->ic_curchan) ? 12 : 2;

		if (!IEEE80211_IS_MULTICAST(wh->i_addr1)) {
			flags |= RAL_TX_ACK;

			dur = ural_txtime(RAL_ACK_SIZE, rate, ic->ic_flags)
			    + RAL_SIFS;
			*(uint16_t *)(uintptr_t)wh->i_dur = LE_16(dur);

			/* tell hardware to add timestamp for probe responses */
			if ((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) ==
			    IEEE80211_FC0_TYPE_MGT &&
			    (wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) ==
			    IEEE80211_FC0_SUBTYPE_PROBE_RESP)
				flags |= RAL_TX_TIMESTAMP;
		}
	}

	pktlen = (uintptr_t)m->b_wptr - (uintptr_t)m->b_rptr - RAL_TX_DESC_SIZE;
	ural_setup_tx_desc(sc, desc, flags, pktlen, rate);

	/* align end on a 2-bytes boundary */
	xferlen = (RAL_TX_DESC_SIZE + pktlen + 1) & ~1;

	/*
	 * No space left in the last URB to store the extra 2 bytes, force
	 * sending of another URB.
	 */
	if ((xferlen % 64) == 0)
		xferlen += 2;

	m->b_wptr = m->b_rptr + xferlen;

	ral_debug(RAL_DBG_TX, "sending data frame len=%u rate=%u xfer len=%u\n",
	    pktlen, rate, xferlen);

	(void) ural_tx_trigger(sc, m);

	ic->ic_stats.is_tx_frags++;
	ic->ic_stats.is_tx_bytes += pktlen;

fail:
	if (ni != NULL)
		ieee80211_free_node(ni);

	if ((type & IEEE80211_FC0_TYPE_MASK) != IEEE80211_FC0_TYPE_DATA ||
	    err == 0) {
		freemsg(mp);
	}

	mutex_exit(&sc->tx_lock);

	return (err);
}

static mblk_t *
ural_m_tx(void *arg, mblk_t *mp)
{
	struct ural_softc *sc = (struct ural_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;
	mblk_t *next;

	/*
	 * No data frames go out unless we're associated; this
	 * should not happen as the 802.11 layer does not enable
	 * the xmit queue until we enter the RUN state.
	 */
	if (ic->ic_state != IEEE80211_S_RUN) {
		ral_debug(RAL_DBG_ERR, "ural_m_tx(): "
		    "discard, state %u\n", ic->ic_state);
		freemsgchain(mp);
		return (NULL);
	}

	while (mp != NULL) {
		next = mp->b_next;
		mp->b_next = NULL;
		if (ural_send(ic, mp, IEEE80211_FC0_TYPE_DATA) != DDI_SUCCESS) {
			mp->b_next = next;
			freemsgchain(mp);
			return (NULL);
		}
		mp = next;
	}
	return (mp);
}

static void
ural_set_testmode(struct ural_softc *sc)
{
	usb_ctrl_setup_t req;
	usb_cr_t cr;
	usb_cb_flags_t cf;
	int err;

	bzero(&req, sizeof (req));
	req.bmRequestType = USB_DEV_REQ_TYPE_VENDOR | USB_DEV_REQ_HOST_TO_DEV;
	req.bRequest = RAL_VENDOR_REQUEST;
	req.wValue = 4;
	req.wIndex = 1;
	req.wLength = 0;
	req.attrs = USB_ATTRS_NONE;

	err = usb_pipe_ctrl_xfer_wait(sc->sc_udev->dev_default_ph, &req, NULL,
	    &cr, &cf, 0);

	if (err != USB_SUCCESS) {
		ral_debug(RAL_DBG_USB,
		    "ural_set_testmode(): could not set test mode:"
		    "cr:%s(%d), cf:%(x)\n",
		    usb_str_cr(cr), cr, cf);
	}
}

static void
ural_eeprom_read(struct ural_softc *sc, uint16_t addr, void *buf, int len)
{
	usb_ctrl_setup_t req;
	usb_cr_t cr;
	usb_cb_flags_t cf;
	mblk_t *mp;
	int err;

	bzero(&req, sizeof (req));
	req.bmRequestType = USB_DEV_REQ_TYPE_VENDOR | USB_DEV_REQ_DEV_TO_HOST;
	req.bRequest = RAL_READ_EEPROM;
	req.wValue = 0;
	req.wIndex = addr;
	req.wLength = (uint16_t)len;

	mp = NULL;
	err = usb_pipe_ctrl_xfer_wait(sc->sc_udev->dev_default_ph, &req, &mp,
	    &cr, &cf, 0);

	if (err != USB_SUCCESS) {
		ral_debug(RAL_DBG_USB,
		    "ural_eeprom_read(): could not read EEPROM:"
		    "cr:%s(%d), cf:(%x)\n",
		    usb_str_cr(cr), cr, cf);
		return;
	}

	bcopy(mp->b_rptr, buf, len);

	if (mp)
		freemsg(mp);
}

static void
ural_bbp_write(struct ural_softc *sc, uint8_t reg, uint8_t val)
{
	uint16_t tmp;
	int ntries;

	for (ntries = 0; ntries < 5; ntries++) {
		if (!(ural_read(sc, RAL_PHY_CSR8) & RAL_BBP_BUSY))
			break;
	}
	if (ntries == 5) {
		ral_debug(RAL_DBG_ERR,
		    "ural_bbp_write(): could not write to BBP\n");
		return;
	}

	tmp = reg << 8 | val;
	ural_write(sc, RAL_PHY_CSR7, tmp);
}

static uint8_t
ural_bbp_read(struct ural_softc *sc, uint8_t reg)
{
	uint16_t val;
	int ntries;

	val = RAL_BBP_WRITE | reg << 8;
	ural_write(sc, RAL_PHY_CSR7, val);

	for (ntries = 0; ntries < 5; ntries++) {
		if (!(ural_read(sc, RAL_PHY_CSR8) & RAL_BBP_BUSY))
			break;
	}
	if (ntries == 5) {
		ral_debug(RAL_DBG_ERR, "ural_bbp_read(): could not read BBP\n");
		return (0);
	}

	return (ural_read(sc, RAL_PHY_CSR7) & 0xff);
}

static void
ural_rf_write(struct ural_softc *sc, uint8_t reg, uint32_t val)
{
	uint32_t tmp;
	int ntries;

	for (ntries = 0; ntries < 5; ntries++) {
		if (!(ural_read(sc, RAL_PHY_CSR10) & RAL_RF_LOBUSY))
			break;
	}
	if (ntries == 5) {
		ral_debug(RAL_DBG_ERR,
		    "ural_rf_write(): could not write to RF\n");
		return;
	}

	tmp = RAL_RF_BUSY | RAL_RF_20BIT | (val & 0xffff) << 2 | (reg & 0x3);
	ural_write(sc, RAL_PHY_CSR9,  tmp & 0xffff);
	ural_write(sc, RAL_PHY_CSR10, tmp >> 16);

	/* remember last written value in sc */
	sc->rf_regs[reg] = val;

	ral_debug(RAL_DBG_HW, "RF R[%u] <- 0x%05x\n", reg & 0x3, val & 0xfffff);
}

/*
 * Disable RF auto-tuning.
 */
static void
ural_disable_rf_tune(struct ural_softc *sc)
{
	uint32_t tmp;

	if (sc->rf_rev != RAL_RF_2523) {
		tmp = sc->rf_regs[RAL_RF1] & ~RAL_RF1_AUTOTUNE;
		ural_rf_write(sc, RAL_RF1, tmp);
	}

	tmp = sc->rf_regs[RAL_RF3] & ~RAL_RF3_AUTOTUNE;
	ural_rf_write(sc, RAL_RF3, tmp);

	ral_debug(RAL_DBG_HW, "disabling RF autotune\n");
}


static void
ural_set_chan(struct ural_softc *sc, struct ieee80211_channel *c)
{
	struct ieee80211com *ic = &sc->sc_ic;
	uint8_t power, tmp;
	uint_t i, chan;

	chan = ieee80211_chan2ieee(ic, c);
	if (chan == 0 || chan == IEEE80211_CHAN_ANY)
		return;

	if (IEEE80211_IS_CHAN_2GHZ(c))
		power = min(sc->txpow[chan - 1], 31);
	else
		power = 31;

	/* adjust txpower using ifconfig settings */
	power -= (100 - ic->ic_txpowlimit) / 8;

	ral_debug(RAL_DBG_HW, "setting channel to %u, txpower to %u\n",
	    chan, power);

	switch (sc->rf_rev) {
	case RAL_RF_2522:
		ural_rf_write(sc, RAL_RF1, 0x00814);
		ural_rf_write(sc, RAL_RF2, ural_rf2522_r2[chan - 1]);
		ural_rf_write(sc, RAL_RF3, power << 7 | 0x00040);
		break;

	case RAL_RF_2523:
		ural_rf_write(sc, RAL_RF1, 0x08804);
		ural_rf_write(sc, RAL_RF2, ural_rf2523_r2[chan - 1]);
		ural_rf_write(sc, RAL_RF3, power << 7 | 0x38044);
		ural_rf_write(sc, RAL_RF4, (chan == 14) ? 0x00280 : 0x00286);
		break;

	case RAL_RF_2524:
		ural_rf_write(sc, RAL_RF1, 0x0c808);
		ural_rf_write(sc, RAL_RF2, ural_rf2524_r2[chan - 1]);
		ural_rf_write(sc, RAL_RF3, power << 7 | 0x00040);
		ural_rf_write(sc, RAL_RF4, (chan == 14) ? 0x00280 : 0x00286);
		break;

	case RAL_RF_2525:
		ural_rf_write(sc, RAL_RF1, 0x08808);
		ural_rf_write(sc, RAL_RF2, ural_rf2525_hi_r2[chan - 1]);
		ural_rf_write(sc, RAL_RF3, power << 7 | 0x18044);
		ural_rf_write(sc, RAL_RF4, (chan == 14) ? 0x00280 : 0x00286);

		ural_rf_write(sc, RAL_RF1, 0x08808);
		ural_rf_write(sc, RAL_RF2, ural_rf2525_r2[chan - 1]);
		ural_rf_write(sc, RAL_RF3, power << 7 | 0x18044);
		ural_rf_write(sc, RAL_RF4, (chan == 14) ? 0x00280 : 0x00286);
		break;

	case RAL_RF_2525E:
		ural_rf_write(sc, RAL_RF1, 0x08808);
		ural_rf_write(sc, RAL_RF2, ural_rf2525e_r2[chan - 1]);
		ural_rf_write(sc, RAL_RF3, power << 7 | 0x18044);
		ural_rf_write(sc, RAL_RF4, (chan == 14) ? 0x00286 : 0x00282);
		break;

	case RAL_RF_2526:
		ural_rf_write(sc, RAL_RF2, ural_rf2526_hi_r2[chan - 1]);
		ural_rf_write(sc, RAL_RF4, (chan & 1) ? 0x00386 : 0x00381);
		ural_rf_write(sc, RAL_RF1, 0x08804);

		ural_rf_write(sc, RAL_RF2, ural_rf2526_r2[chan - 1]);
		ural_rf_write(sc, RAL_RF3, power << 7 | 0x18044);
		ural_rf_write(sc, RAL_RF4, (chan & 1) ? 0x00386 : 0x00381);
		break;

	/* dual-band RF */
	case RAL_RF_5222:
		for (i = 0; ural_rf5222[i].chan != chan; i++) {
			if (i > URAL_N(ural_rf5222)) break;
		}

		ural_rf_write(sc, RAL_RF1, ural_rf5222[i].r1);
		ural_rf_write(sc, RAL_RF2, ural_rf5222[i].r2);
		ural_rf_write(sc, RAL_RF3, power << 7 | 0x00040);
		ural_rf_write(sc, RAL_RF4, ural_rf5222[i].r4);
		break;
	}

	if (ic->ic_opmode != IEEE80211_M_MONITOR &&
	    ic->ic_state != IEEE80211_S_SCAN) {
		/* set Japan filter bit for channel 14 */
		tmp = ural_bbp_read(sc, 70);

		tmp &= ~RAL_JAPAN_FILTER;
		if (chan == 14)
			tmp |= RAL_JAPAN_FILTER;

		ural_bbp_write(sc, 70, tmp);

		/* clear CRC errs */
		(void) ural_read(sc, RAL_STA_CSR0);

		drv_usecwait(10000);
		ural_disable_rf_tune(sc);
	}
}

/*
 * Refer to IEEE Std 802.11-1999 pp. 123 for more information on TSF
 * synchronization.
 */
static void
ural_enable_tsf_sync(struct ural_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	uint16_t logcwmin, preload, tmp;

	/* first, disable TSF synchronization */
	ural_write(sc, RAL_TXRX_CSR19, 0);

	tmp = (16 * ic->ic_bss->in_intval) << 4;
	ural_write(sc, RAL_TXRX_CSR18, tmp);

	logcwmin = (ic->ic_opmode == IEEE80211_M_IBSS) ? 2 : 0;
	preload = (ic->ic_opmode == IEEE80211_M_IBSS) ? 320 : 6;
	tmp = logcwmin << 12 | preload;
	ural_write(sc, RAL_TXRX_CSR20, tmp);

	/* finally, enable TSF synchronization */
	tmp = RAL_ENABLE_TSF | RAL_ENABLE_TBCN;
	if (ic->ic_opmode == IEEE80211_M_STA)
		tmp |= RAL_ENABLE_TSF_SYNC(1);
	else
		tmp |= RAL_ENABLE_TSF_SYNC(2) | RAL_ENABLE_BEACON_GENERATOR;
	ural_write(sc, RAL_TXRX_CSR19, tmp);

	ral_debug(RAL_DBG_HW, "enabling TSF synchronization\n");
}

/*
 * This function can be called by ieee80211_set_shortslottime(). Refer to
 * IEEE Std 802.11-1999 pp. 85 to know how these values are computed.
 */
/* ARGSUSED */
static void
ural_update_slot(struct ieee80211com *ic, int onoff)
{
	struct ural_softc *sc = (struct ural_softc *)ic;
	uint16_t slottime, sifs, eifs;

	slottime = (ic->ic_flags & IEEE80211_F_SHSLOT) ? 9 : 20;
	/* slottime = (onoff ? 9 : 20); */

	/*
	 * These settings may sound a bit inconsistent but this is what the
	 * reference driver does.
	 */
	if (ic->ic_curmode == IEEE80211_MODE_11B) {
		sifs = 16 - RAL_RXTX_TURNAROUND;
		eifs = 364;
	} else {
		sifs = 10 - RAL_RXTX_TURNAROUND;
		eifs = 64;
	}

	ural_write(sc, RAL_MAC_CSR10, slottime);
	ural_write(sc, RAL_MAC_CSR11, sifs);
	ural_write(sc, RAL_MAC_CSR12, eifs);
}

static void
ural_set_txpreamble(struct ural_softc *sc)
{
	uint16_t tmp;

	tmp = ural_read(sc, RAL_TXRX_CSR10);

	tmp &= ~RAL_SHORT_PREAMBLE;
	if (sc->sc_ic.ic_flags & IEEE80211_F_SHPREAMBLE)
		tmp |= RAL_SHORT_PREAMBLE;

	ural_write(sc, RAL_TXRX_CSR10, tmp);
}

static void
ural_set_basicrates(struct ural_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;

	/* update basic rate set */
	if (ic->ic_curmode == IEEE80211_MODE_11B) {
		/* 11b basic rates: 1, 2Mbps */
		ural_write(sc, RAL_TXRX_CSR11, 0x3);
	} else if (IEEE80211_IS_CHAN_5GHZ(ic->ic_bss->in_chan)) {
		/* 11a basic rates: 6, 12, 24Mbps */
		ural_write(sc, RAL_TXRX_CSR11, 0x150);
	} else {
		/* 11g basic rates: 1, 2, 5.5, 11, 6, 12, 24Mbps */
		ural_write(sc, RAL_TXRX_CSR11, 0x15f);
	}
}

static void
ural_set_bssid(struct ural_softc *sc, uint8_t *bssid)
{
	uint16_t tmp;

	tmp = bssid[0] | bssid[1] << 8;
	ural_write(sc, RAL_MAC_CSR5, tmp);

	tmp = bssid[2] | bssid[3] << 8;
	ural_write(sc, RAL_MAC_CSR6, tmp);

	tmp = bssid[4] | bssid[5] << 8;
	ural_write(sc, RAL_MAC_CSR7, tmp);

	ral_debug(RAL_DBG_HW, "setting BSSID to " MACSTR "\n", MAC2STR(bssid));
}

static void
ural_set_macaddr(struct ural_softc *sc, uint8_t *addr)
{
	uint16_t tmp;

	tmp = addr[0] | addr[1] << 8;
	ural_write(sc, RAL_MAC_CSR2, tmp);

	tmp = addr[2] | addr[3] << 8;
	ural_write(sc, RAL_MAC_CSR3, tmp);

	tmp = addr[4] | addr[5] << 8;
	ural_write(sc, RAL_MAC_CSR4, tmp);

	ral_debug(RAL_DBG_HW,
	    "setting MAC address to " MACSTR "\n", MAC2STR(addr));
}

static void
ural_update_promisc(struct ural_softc *sc)
{
	uint32_t tmp;

	tmp = ural_read(sc, RAL_TXRX_CSR2);

	tmp &= ~RAL_DROP_NOT_TO_ME;
	if (!(sc->sc_rcr & RAL_RCR_PROMISC))
		tmp |= RAL_DROP_NOT_TO_ME;

	ural_write(sc, RAL_TXRX_CSR2, tmp);

	ral_debug(RAL_DBG_HW, "%s promiscuous mode\n",
	    (sc->sc_rcr & RAL_RCR_PROMISC) ?  "entering" : "leaving");
}

static const char *
ural_get_rf(int rev)
{
	switch (rev) {
	case RAL_RF_2522:	return ("RT2522");
	case RAL_RF_2523:	return ("RT2523");
	case RAL_RF_2524:	return ("RT2524");
	case RAL_RF_2525:	return ("RT2525");
	case RAL_RF_2525E:	return ("RT2525e");
	case RAL_RF_2526:	return ("RT2526");
	case RAL_RF_5222:	return ("RT5222");
	default:		return ("unknown");
	}
}

static void
ural_read_eeprom(struct ural_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	uint16_t val;

	ural_eeprom_read(sc, RAL_EEPROM_CONFIG0, &val, 2);
	val = LE_16(val);
	sc->rf_rev =   (val >> 11) & 0x7;
	sc->hw_radio = (val >> 10) & 0x1;
	sc->led_mode = (val >> 6)  & 0x7;
	sc->rx_ant =   (val >> 4)  & 0x3;
	sc->tx_ant =   (val >> 2)  & 0x3;
	sc->nb_ant =   val & 0x3;

	/* read MAC address */
	ural_eeprom_read(sc, RAL_EEPROM_ADDRESS, ic->ic_macaddr, 6);

	/* read default values for BBP registers */
	ural_eeprom_read(sc, RAL_EEPROM_BBP_BASE, sc->bbp_prom, 2 * 16);

	/* read Tx power for all b/g channels */
	ural_eeprom_read(sc, RAL_EEPROM_TXPOWER, sc->txpow, 14);
}

static int
ural_bbp_init(struct ural_softc *sc)
{
	int i, ntries;

	/* wait for BBP to be ready */
	for (ntries = 0; ntries < 100; ntries++) {
		if (ural_bbp_read(sc, RAL_BBP_VERSION) != 0)
			break;
		drv_usecwait(1000);
	}
	if (ntries == 100) {
		ral_debug(RAL_DBG_ERR, "timeout waiting for BBP\n");
		return (EIO);
	}

	/* initialize BBP registers to default values */
	for (i = 0; i < URAL_N(ural_def_bbp); i++)
		ural_bbp_write(sc, ural_def_bbp[i].reg, ural_def_bbp[i].val);

	return (0);
}

static void
ural_set_txantenna(struct ural_softc *sc, int antenna)
{
	uint16_t tmp;
	uint8_t tx;

	tx = ural_bbp_read(sc, RAL_BBP_TX) & ~RAL_BBP_ANTMASK;
	if (antenna == 1)
		tx |= RAL_BBP_ANTA;
	else if (antenna == 2)
		tx |= RAL_BBP_ANTB;
	else
		tx |= RAL_BBP_DIVERSITY;

	/* need to force I/Q flip for RF 2525e, 2526 and 5222 */
	if (sc->rf_rev == RAL_RF_2525E || sc->rf_rev == RAL_RF_2526 ||
	    sc->rf_rev == RAL_RF_5222)
		tx |= RAL_BBP_FLIPIQ;

	ural_bbp_write(sc, RAL_BBP_TX, tx);

	/* update values in PHY_CSR5 and PHY_CSR6 */
	tmp = ural_read(sc, RAL_PHY_CSR5) & ~0x7;
	ural_write(sc, RAL_PHY_CSR5, tmp | (tx & 0x7));

	tmp = ural_read(sc, RAL_PHY_CSR6) & ~0x7;
	ural_write(sc, RAL_PHY_CSR6, tmp | (tx & 0x7));
}

static void
ural_set_rxantenna(struct ural_softc *sc, int antenna)
{
	uint8_t rx;

	rx = ural_bbp_read(sc, RAL_BBP_RX) & ~RAL_BBP_ANTMASK;
	if (antenna == 1)
		rx |= RAL_BBP_ANTA;
	else if (antenna == 2)
		rx |= RAL_BBP_ANTB;
	else
		rx |= RAL_BBP_DIVERSITY;

	/* need to force no I/Q flip for RF 2525e and 2526 */
	if (sc->rf_rev == RAL_RF_2525E || sc->rf_rev == RAL_RF_2526)
		rx &= ~RAL_BBP_FLIPIQ;

	ural_bbp_write(sc, RAL_BBP_RX, rx);
}

/*
 * This function is called periodically (every 200ms) during scanning to
 * switch from one channel to another.
 */
static void
ural_next_scan(void *arg)
{
	struct ural_softc *sc = arg;
	struct ieee80211com *ic = &sc->sc_ic;

	if (ic->ic_state == IEEE80211_S_SCAN)
		ieee80211_next_scan(ic);
}

static int
ural_newstate(struct ieee80211com *ic, enum ieee80211_state nstate, int arg)
{
	struct ural_softc *sc = (struct ural_softc *)ic;
	enum ieee80211_state ostate;
	struct ieee80211_node *ni;
	int err;

	RAL_LOCK(sc);

	ostate = ic->ic_state;

	if (sc->sc_scan_id != 0) {
		(void) untimeout(sc->sc_scan_id);
		sc->sc_scan_id = 0;
	}

	if (sc->sc_amrr_id != 0) {
		(void) untimeout(sc->sc_amrr_id);
		sc->sc_amrr_id = 0;
	}

	switch (nstate) {
	case IEEE80211_S_INIT:
		if (ostate == IEEE80211_S_RUN) {
			/* abort TSF synchronization */
			ural_write(sc, RAL_TXRX_CSR19, 0);
			/* force tx led to stop blinking */
			ural_write(sc, RAL_MAC_CSR20, 0);
		}
		break;

	case IEEE80211_S_SCAN:
		ural_set_chan(sc, ic->ic_curchan);
		sc->sc_scan_id = timeout(ural_next_scan, (void *)sc,
		    drv_usectohz(sc->dwelltime * 1000));
		break;

	case IEEE80211_S_AUTH:
		ural_set_chan(sc, ic->ic_curchan);
		break;

	case IEEE80211_S_ASSOC:
		ural_set_chan(sc, ic->ic_curchan);
		break;

	case IEEE80211_S_RUN:
		ural_set_chan(sc, ic->ic_curchan);

		ni = ic->ic_bss;

		if (ic->ic_opmode != IEEE80211_M_MONITOR) {
			ural_update_slot(ic, 1);
			ural_set_txpreamble(sc);
			ural_set_basicrates(sc);
			ural_set_bssid(sc, ni->in_bssid);
		}


		/* make tx led blink on tx (controlled by ASIC) */
		ural_write(sc, RAL_MAC_CSR20, 1);

		if (ic->ic_opmode != IEEE80211_M_MONITOR)
			ural_enable_tsf_sync(sc);

		/* enable automatic rate adaptation in STA mode */
		if (ic->ic_opmode == IEEE80211_M_STA &&
		    ic->ic_fixed_rate == IEEE80211_FIXED_RATE_NONE)
			ural_amrr_start(sc, ni);

		break;
	}

	RAL_UNLOCK(sc);

	err = sc->sc_newstate(ic, nstate, arg);
	/*
	 * Finally, start any timers.
	 */
	if (nstate == IEEE80211_S_RUN)
		ieee80211_start_watchdog(ic, 1);

	return (err);
}



static void
ural_close_pipes(struct ural_softc *sc)
{
	usb_flags_t flags = USB_FLAGS_SLEEP;

	if (sc->sc_rx_pipeh != NULL) {
		usb_pipe_reset(sc->sc_dev, sc->sc_rx_pipeh, flags, NULL, 0);
		usb_pipe_close(sc->sc_dev, sc->sc_rx_pipeh, flags, NULL, 0);
		sc->sc_rx_pipeh = NULL;
	}

	if (sc->sc_tx_pipeh != NULL) {
		usb_pipe_reset(sc->sc_dev, sc->sc_tx_pipeh, flags, NULL, 0);
		usb_pipe_close(sc->sc_dev, sc->sc_tx_pipeh, flags, NULL, 0);
		sc->sc_tx_pipeh = NULL;
	}
}

static int
ural_open_pipes(struct ural_softc *sc)
{
	usb_ep_data_t *ep_node;
	usb_pipe_policy_t policy;
	int err;

	ep_node = usb_lookup_ep_data(sc->sc_dev, sc->sc_udev, 0, 0, 0,
	    USB_EP_ATTR_BULK, USB_EP_DIR_OUT);

	bzero(&policy, sizeof (usb_pipe_policy_t));
	policy.pp_max_async_reqs = RAL_TX_LIST_COUNT;

	if ((err = usb_pipe_open(sc->sc_dev,
	    &ep_node->ep_descr, &policy, USB_FLAGS_SLEEP,
	    &sc->sc_tx_pipeh)) != USB_SUCCESS) {
		ral_debug(RAL_DBG_ERR,
		    "ural_open_pipes(): %x failed to open tx pipe\n", err);
		goto fail;
	}

	ep_node = usb_lookup_ep_data(sc->sc_dev, sc->sc_udev, 0, 0, 0,
	    USB_EP_ATTR_BULK, USB_EP_DIR_IN);

	bzero(&policy, sizeof (usb_pipe_policy_t));
	policy.pp_max_async_reqs = RAL_RX_LIST_COUNT + 32;

	if ((err = usb_pipe_open(sc->sc_dev,
	    &ep_node->ep_descr, &policy, USB_FLAGS_SLEEP,
	    &sc->sc_rx_pipeh)) != USB_SUCCESS) {
		ral_debug(RAL_DBG_ERR,
		    "ural_open_pipes(): %x failed to open rx pipe\n", err);
		goto fail;
	}

	return (USB_SUCCESS);

fail:
	if (sc->sc_rx_pipeh != NULL) {
		usb_pipe_close(sc->sc_dev, sc->sc_rx_pipeh,
		    USB_FLAGS_SLEEP, NULL, 0);
		sc->sc_rx_pipeh = NULL;
	}

	if (sc->sc_tx_pipeh != NULL) {
		usb_pipe_close(sc->sc_dev, sc->sc_tx_pipeh,
		    USB_FLAGS_SLEEP, NULL, 0);
		sc->sc_tx_pipeh = NULL;
	}

	return (USB_FAILURE);
}

static int
ural_tx_trigger(struct ural_softc *sc, mblk_t *mp)
{
	usb_bulk_req_t *req;
	int err;

	sc->sc_tx_timer = RAL_TX_TIMEOUT;

	req = usb_alloc_bulk_req(sc->sc_dev, 0, USB_FLAGS_SLEEP);
	if (req == NULL) {
		ral_debug(RAL_DBG_ERR,
		    "ural_tx_trigger(): failed to allocate req");
		freemsg(mp);
		return (-1);
	}

	req->bulk_len		= (uintptr_t)mp->b_wptr - (uintptr_t)mp->b_rptr;
	req->bulk_data		= mp;
	req->bulk_client_private = (usb_opaque_t)sc;
	req->bulk_timeout	= RAL_TX_TIMEOUT;
	req->bulk_attributes	= USB_ATTRS_AUTOCLEARING;
	req->bulk_cb		= ural_txeof;
	req->bulk_exc_cb	= ural_txeof;
	req->bulk_completion_reason = 0;
	req->bulk_cb_flags	= 0;

	if ((err = usb_pipe_bulk_xfer(sc->sc_tx_pipeh, req, 0))
	    != USB_SUCCESS) {

		ral_debug(RAL_DBG_ERR, "ural_tx_trigger(): "
		    "failed to do tx xfer, %d", err);
		usb_free_bulk_req(req);
		return (-1);
	}

	sc->tx_queued++;

	return (0);
}

static int
ural_rx_trigger(struct ural_softc *sc)
{
	usb_bulk_req_t *req;
	int err;

	req = usb_alloc_bulk_req(sc->sc_dev, RAL_RXBUF_SIZE, USB_FLAGS_SLEEP);
	if (req == NULL) {
		ral_debug(RAL_DBG_ERR,
		    "ural_rx_trigger(): failed to allocate req");
		return (-1);
	}

	req->bulk_len		= RAL_RXBUF_SIZE;
	req->bulk_client_private = (usb_opaque_t)sc;
	req->bulk_timeout	= 0;
	req->bulk_attributes	= USB_ATTRS_SHORT_XFER_OK
	    | USB_ATTRS_AUTOCLEARING;
	req->bulk_cb		= ural_rxeof;
	req->bulk_exc_cb	= ural_rxeof;
	req->bulk_completion_reason = 0;
	req->bulk_cb_flags	= 0;

	err = usb_pipe_bulk_xfer(sc->sc_rx_pipeh, req, 0);

	if (err != USB_SUCCESS) {
		ral_debug(RAL_DBG_ERR, "ural_rx_trigger(): "
		    "failed to do rx xfer, %d", err);
		usb_free_bulk_req(req);

		return (-1);
	}

	mutex_enter(&sc->rx_lock);
	sc->rx_queued++;
	mutex_exit(&sc->rx_lock);

	return (0);
}

static void
ural_init_tx_queue(struct ural_softc *sc)
{
	sc->tx_queued = 0;
}

static int
ural_init_rx_queue(struct ural_softc *sc)
{
	int	i;

	sc->rx_queued = 0;

	for (i = 0; i < RAL_RX_LIST_COUNT; i++) {
		if (ural_rx_trigger(sc) != 0) {
			return (USB_FAILURE);
		}
	}

	return (USB_SUCCESS);
}

static void
ural_stop(struct ural_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;

	ieee80211_new_state(ic, IEEE80211_S_INIT, -1);
	ieee80211_stop_watchdog(ic);	/* stop the watchdog */

	RAL_LOCK(sc);

	sc->sc_tx_timer = 0;
	sc->sc_flags &= ~RAL_FLAG_RUNNING;	/* STOP */

	/* disable Rx */
	ural_write(sc, RAL_TXRX_CSR2, RAL_DISABLE_RX);

	/* reset ASIC and BBP (but won't reset MAC registers!) */
	ural_write(sc, RAL_MAC_CSR1, RAL_RESET_ASIC | RAL_RESET_BBP);
	ural_write(sc, RAL_MAC_CSR1, 0);

	ural_close_pipes(sc);

	RAL_UNLOCK(sc);
}

static int
ural_init(struct ural_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	uint16_t tmp;
	int i, ntries;

	ural_set_testmode(sc);
	ural_write(sc, 0x308, 0x00f0);	/* magic */

	ural_stop(sc);

	/* initialize MAC registers to default values */
	for (i = 0; i < URAL_N(ural_def_mac); i++)
		ural_write(sc, ural_def_mac[i].reg, ural_def_mac[i].val);

	/* wait for BBP and RF to wake up (this can take a long time!) */
	for (ntries = 0; ntries < 100; ntries++) {
		tmp = ural_read(sc, RAL_MAC_CSR17);
		if ((tmp & (RAL_BBP_AWAKE | RAL_RF_AWAKE)) ==
		    (RAL_BBP_AWAKE | RAL_RF_AWAKE))
			break;
		drv_usecwait(1000);
	}
	if (ntries == 100) {
		ral_debug(RAL_DBG_ERR,
		    "ural_init(): timeout waiting for BBP/RF to wakeup\n");
		goto fail;
	}

	/* we're ready! */
	ural_write(sc, RAL_MAC_CSR1, RAL_HOST_READY);

	/* set basic rate set (will be updated later) */
	ural_write(sc, RAL_TXRX_CSR11, 0x15f);

	if (ural_bbp_init(sc) != 0)
		goto fail;

	/* set default BSS channel */
	ural_set_chan(sc, ic->ic_curchan);

	/* clear statistic registers (STA_CSR0 to STA_CSR10) */
	ural_read_multi(sc, RAL_STA_CSR0, sc->sta, sizeof (sc->sta));

	ural_set_txantenna(sc, sc->tx_ant);
	ural_set_rxantenna(sc, sc->rx_ant);

	ural_set_macaddr(sc, ic->ic_macaddr);

	if (ural_open_pipes(sc) != USB_SUCCESS) {
		ral_debug(RAL_DBG_ERR, "ural_init(): "
		    "could not open pipes.\n");
		goto fail;
	}

	ural_init_tx_queue(sc);

	if (ural_init_rx_queue(sc) != USB_SUCCESS)
		goto fail;

	/* kick Rx */
	tmp = RAL_DROP_PHY | RAL_DROP_CRC;
	if (ic->ic_opmode != IEEE80211_M_MONITOR) {
		tmp |= RAL_DROP_CTL | RAL_DROP_BAD_VERSION;
		if (ic->ic_opmode != IEEE80211_M_HOSTAP)
			tmp |= RAL_DROP_TODS;
		if (!(sc->sc_rcr & RAL_RCR_PROMISC))
			tmp |= RAL_DROP_NOT_TO_ME;
	}
	ural_write(sc, RAL_TXRX_CSR2, tmp);
	sc->sc_flags |= RAL_FLAG_RUNNING;	/* RUNNING */

	return (DDI_SUCCESS);
fail:
	ural_stop(sc);
	return (EIO);
}

static int
ural_disconnect(dev_info_t *devinfo)
{
	struct ural_softc *sc;
	struct ieee80211com *ic;

	/*
	 * We can't call ural_stop() here, since the hardware is removed,
	 * we can't access the register anymore.
	 */
	sc = ddi_get_soft_state(ural_soft_state_p, ddi_get_instance(devinfo));
	ASSERT(sc != NULL);

	if (!RAL_IS_RUNNING(sc))	/* different device or not inited */
		return (DDI_SUCCESS);

	ic = &sc->sc_ic;
	ieee80211_new_state(ic, IEEE80211_S_INIT, -1);
	ieee80211_stop_watchdog(ic);	/* stop the watchdog */

	RAL_LOCK(sc);

	sc->sc_tx_timer = 0;
	sc->sc_flags &= ~RAL_FLAG_RUNNING;	/* STOP */

	ural_close_pipes(sc);

	RAL_UNLOCK(sc);

	return (DDI_SUCCESS);
}

static int
ural_reconnect(dev_info_t *devinfo)
{
	struct ural_softc *sc;
	int err;

	sc = ddi_get_soft_state(ural_soft_state_p, ddi_get_instance(devinfo));
	ASSERT(sc != NULL);

	/* check device changes after disconnect */
	if (usb_check_same_device(sc->sc_dev, NULL, USB_LOG_L2, -1,
	    USB_CHK_BASIC | USB_CHK_CFG, NULL) != USB_SUCCESS) {
		ral_debug(RAL_DBG_ERR, "different device connected\n");
		return (DDI_FAILURE);
	}

	err = ural_init(sc);

	return (err);
}

static void
ural_resume(struct ural_softc *sc)
{
	/* check device changes after suspend */
	if (usb_check_same_device(sc->sc_dev, NULL, USB_LOG_L2, -1,
	    USB_CHK_BASIC | USB_CHK_CFG, NULL) != USB_SUCCESS) {
		ral_debug(RAL_DBG_ERR, "no or different device connected\n");
		return;
	}

	(void) ural_init(sc);
}

#define	URAL_AMRR_MIN_SUCCESS_THRESHOLD	1
#define	URAL_AMRR_MAX_SUCCESS_THRESHOLD	10

/*
 * Naive implementation of the Adaptive Multi Rate Retry algorithm:
 * "IEEE 802.11 Rate Adaptation: A Practical Approach"
 * Mathieu Lacage, Hossein Manshaei, Thierry Turletti
 * INRIA Sophia - Projet Planete
 * http://www-sop.inria.fr/rapports/sophia/RR-5208.html
 *
 * This algorithm is particularly well suited for ural since it does not
 * require per-frame retry statistics.  Note however that since h/w does
 * not provide per-frame stats, we can't do per-node rate adaptation and
 * thus automatic rate adaptation is only enabled in STA operating mode.
 */
#define	is_success(amrr)	\
	((amrr)->retrycnt < (amrr)->txcnt / 10)
#define	is_failure(amrr)	\
	((amrr)->retrycnt > (amrr)->txcnt / 3)
#define	is_enough(amrr)		\
	((amrr)->txcnt > 10)
#define	is_min_rate(ni)		\
	((ni)->in_txrate == 0)
#define	is_max_rate(ni)		\
	((ni)->in_txrate == (ni)->in_rates.ir_nrates - 1)
#define	increase_rate(ni)	\
	((ni)->in_txrate++)
#define	decrease_rate(ni)	\
	((ni)->in_txrate--)
#define	reset_cnt(amrr)	do {	\
	(amrr)->txcnt = (amrr)->retrycnt = 0;	\
	_NOTE(CONSTCOND)	\
} while (/* CONSTCOND */0)

static void
ural_ratectl(struct ural_amrr *amrr, struct ieee80211_node *ni)
{
	int need_change = 0;

	if (is_success(amrr) && is_enough(amrr)) {
		amrr->success++;
		if (amrr->success >= amrr->success_threshold &&
		    !is_max_rate(ni)) {
			amrr->recovery = 1;
			amrr->success = 0;
			increase_rate(ni);
			need_change = 1;
		} else {
			amrr->recovery = 0;
		}
	} else if (is_failure(amrr)) {
		amrr->success = 0;
		if (!is_min_rate(ni)) {
			if (amrr->recovery) {
				amrr->success_threshold *= 2;
				if (amrr->success_threshold >
				    URAL_AMRR_MAX_SUCCESS_THRESHOLD)
					amrr->success_threshold =
					    URAL_AMRR_MAX_SUCCESS_THRESHOLD;
			} else {
				amrr->success_threshold =
				    URAL_AMRR_MIN_SUCCESS_THRESHOLD;
			}
			decrease_rate(ni);
			need_change = 1;
		}
		amrr->recovery = 0;	/* original paper was incorrect */
	}

	if (is_enough(amrr) || need_change)
		reset_cnt(amrr);
}

static void
ural_amrr_timeout(void *arg)
{
	struct ural_softc *sc = (struct ural_softc *)arg;
	struct ural_amrr *amrr = &sc->amrr;

	ural_read_multi(sc, RAL_STA_CSR0, sc->sta, sizeof (sc->sta));

	/* count TX retry-fail as Tx errors */
	sc->sc_tx_err += sc->sta[9];
	sc->sc_tx_retries += (sc->sta[7] + sc->sta[8]);

	amrr->retrycnt =
	    sc->sta[7] +	/* TX one-retry ok count */
	    sc->sta[8] +	/* TX more-retry ok count */
	    sc->sta[9];		/* TX retry-fail count */

	amrr->txcnt =
	    amrr->retrycnt +
	    sc->sta[6];		/* TX no-retry ok count */

	ural_ratectl(amrr, sc->sc_ic.ic_bss);

	sc->sc_amrr_id = timeout(ural_amrr_timeout, (void *)sc,
	    drv_usectohz(1000 * 1000)); /* 1 second */
}


static void
ural_amrr_start(struct ural_softc *sc, struct ieee80211_node *ni)
{
	struct ural_amrr *amrr = &sc->amrr;
	int i;

	/* clear statistic registers (STA_CSR0 to STA_CSR10) */
	ural_read_multi(sc, RAL_STA_CSR0, sc->sta, sizeof (sc->sta));

	amrr->success = 0;
	amrr->recovery = 0;
	amrr->txcnt = amrr->retrycnt = 0;
	amrr->success_threshold = URAL_AMRR_MIN_SUCCESS_THRESHOLD;

	/* set rate to some reasonable initial value */
	for (i = ni->in_rates.ir_nrates - 1;
	    i > 0 && (ni->in_rates.ir_rates[i] & IEEE80211_RATE_VAL) > 72;
	    i--) {
	}

	ni->in_txrate = i;

	sc->sc_amrr_id = timeout(ural_amrr_timeout, (void *)sc,
	    drv_usectohz(1000 * 1000)); /* 1 second */
}

void
ural_watchdog(void *arg)
{
	struct ural_softc *sc = arg;
	struct ieee80211com *ic = &sc->sc_ic;
	int ntimer = 0;

	RAL_LOCK(sc);
	ic->ic_watchdog_timer = 0;

	if (!RAL_IS_RUNNING(sc)) {
		RAL_UNLOCK(sc);
		return;
	}

	if (sc->sc_tx_timer > 0) {
		if (--sc->sc_tx_timer == 0) {
			ral_debug(RAL_DBG_ERR, "tx timer timeout\n");
			RAL_UNLOCK(sc);
			(void) ural_init(sc);
			(void) ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
			return;
		}
	}

	if (ic->ic_state == IEEE80211_S_RUN)
		ntimer = 1;

	RAL_UNLOCK(sc);

	ieee80211_watchdog(ic);

	if (ntimer)
		ieee80211_start_watchdog(ic, ntimer);
}

static int
ural_m_start(void *arg)
{
	struct ural_softc *sc = (struct ural_softc *)arg;
	int err;

	/*
	 * initialize RT2500USB hardware
	 */
	err = ural_init(sc);
	if (err != DDI_SUCCESS) {
		ral_debug(RAL_DBG_ERR, "device configuration failed\n");
		goto fail;
	}
	sc->sc_flags |= RAL_FLAG_RUNNING;	/* RUNNING */
	return (err);

fail:
	ural_stop(sc);
	return (err);
}

static void
ural_m_stop(void *arg)
{
	struct ural_softc *sc = (struct ural_softc *)arg;

	(void) ural_stop(sc);
	sc->sc_flags &= ~RAL_FLAG_RUNNING;	/* STOP */
}

static int
ural_m_unicst(void *arg, const uint8_t *macaddr)
{
	struct ural_softc *sc = (struct ural_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;

	ral_debug(RAL_DBG_MSG, "ural_m_unicst(): " MACSTR "\n",
	    MAC2STR(macaddr));

	IEEE80211_ADDR_COPY(ic->ic_macaddr, macaddr);
	(void) ural_set_macaddr(sc, (uint8_t *)macaddr);
	(void) ural_init(sc);

	return (0);
}

/*ARGSUSED*/
static int
ural_m_multicst(void *arg, boolean_t add, const uint8_t *mca)
{
	return (0);
}

static int
ural_m_promisc(void *arg, boolean_t on)
{
	struct ural_softc *sc = (struct ural_softc *)arg;

	if (on) {
		sc->sc_rcr |= RAL_RCR_PROMISC;
		sc->sc_rcr |= RAL_RCR_MULTI;
	} else {
		sc->sc_rcr &= ~RAL_RCR_PROMISC;
		sc->sc_rcr &= ~RAL_RCR_PROMISC;
	}

	ural_update_promisc(sc);
	return (0);
}

/*
 * callback functions for /get/set properties
 */
static int
ural_m_setprop(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    uint_t wldp_length, const void *wldp_buf)
{
	struct ural_softc *sc = (struct ural_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;
	int err;

	err = ieee80211_setprop(ic, pr_name, wldp_pr_num,
	    wldp_length, wldp_buf);
	RAL_LOCK(sc);
	if (err == ENETRESET) {
		if (RAL_IS_RUNNING(sc)) {
			RAL_UNLOCK(sc);
			(void) ural_init(sc);
			(void) ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
			RAL_LOCK(sc);
		}
		err = 0;
	}
	RAL_UNLOCK(sc);

	return (err);
}

static int
ural_m_getprop(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    uint_t wldp_length, void *wldp_buf)
{
	struct ural_softc *sc = (struct ural_softc *)arg;
	int err;

	err = ieee80211_getprop(&sc->sc_ic, pr_name, wldp_pr_num,
	    wldp_length, wldp_buf);

	return (err);
}

static void
ural_m_propinfo(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    mac_prop_info_handle_t mph)
{
	struct ural_softc *sc = (struct ural_softc *)arg;

	ieee80211_propinfo(&sc->sc_ic, pr_name, wldp_pr_num, mph);
}

static void
ural_m_ioctl(void* arg, queue_t *wq, mblk_t *mp)
{
	struct ural_softc *sc = (struct ural_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;
	int err;

	err = ieee80211_ioctl(ic, wq, mp);
	RAL_LOCK(sc);
	if (err == ENETRESET) {
		if (RAL_IS_RUNNING(sc)) {
			RAL_UNLOCK(sc);
			(void) ural_init(sc);
			(void) ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
			RAL_LOCK(sc);
		}
	}
	RAL_UNLOCK(sc);
}

static int
ural_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	struct ural_softc *sc  = (struct ural_softc *)arg;
	ieee80211com_t	*ic = &sc->sc_ic;
	ieee80211_node_t *ni = ic->ic_bss;
	struct ieee80211_rateset *rs = &ni->in_rates;

	RAL_LOCK(sc);
	switch (stat) {
	case MAC_STAT_IFSPEED:
		*val = ((ic->ic_fixed_rate == IEEE80211_FIXED_RATE_NONE) ?
		    (rs->ir_rates[ni->in_txrate] & IEEE80211_RATE_VAL)
		    : ic->ic_fixed_rate) / 2 * 1000000;
		break;
	case MAC_STAT_NOXMTBUF:
		*val = sc->sc_tx_nobuf;
		break;
	case MAC_STAT_NORCVBUF:
		*val = sc->sc_rx_nobuf;
		break;
	case MAC_STAT_IERRORS:
		*val = sc->sc_rx_err;
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
		*val = sc->sc_tx_err;
		break;
	case WIFI_STAT_TX_RETRANS:
		*val = sc->sc_tx_retries;
		break;
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
		RAL_UNLOCK(sc);
		return (ieee80211_stat(ic, stat, val));
	default:
		RAL_UNLOCK(sc);
		return (ENOTSUP);
	}
	RAL_UNLOCK(sc);

	return (0);
}


static int
ural_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	struct ural_softc *sc;
	struct ieee80211com *ic;
	int err, i;
	int instance;

	char strbuf[32];

	wifi_data_t wd = { 0 };
	mac_register_t *macp;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		sc = ddi_get_soft_state(ural_soft_state_p,
		    ddi_get_instance(devinfo));
		ASSERT(sc != NULL);
		ural_resume(sc);
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(devinfo);

	if (ddi_soft_state_zalloc(ural_soft_state_p, instance) != DDI_SUCCESS) {
		ral_debug(RAL_DBG_MSG, "ural_attach(): "
		    "unable to alloc soft_state_p\n");
		return (DDI_FAILURE);
	}

	sc = ddi_get_soft_state(ural_soft_state_p, instance);
	ic = (ieee80211com_t *)&sc->sc_ic;
	sc->sc_dev = devinfo;

	if (usb_client_attach(devinfo, USBDRV_VERSION, 0) != USB_SUCCESS) {
		ral_debug(RAL_DBG_ERR,
		    "ural_attach(): usb_client_attach failed\n");
		goto fail1;
	}

	if (usb_get_dev_data(devinfo, &sc->sc_udev,
	    USB_PARSE_LVL_ALL, 0) != USB_SUCCESS) {
		sc->sc_udev = NULL;
		goto fail2;
	}

	mutex_init(&sc->sc_genlock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&sc->tx_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&sc->rx_lock, NULL, MUTEX_DRIVER, NULL);

	/* retrieve RT2570 rev. no */
	sc->asic_rev = ural_read(sc, RAL_MAC_CSR0);

	/* retrieve MAC address and various other things from EEPROM */
	ural_read_eeprom(sc);

	ral_debug(RAL_DBG_MSG, "ural: MAC/BBP RT2570 (rev 0x%02x), RF %s\n",
	    sc->asic_rev, ural_get_rf(sc->rf_rev));

	ic->ic_phytype = IEEE80211_T_OFDM;	/* not only, but not used */
	ic->ic_opmode = IEEE80211_M_STA;	/* default to BSS mode */
	ic->ic_state = IEEE80211_S_INIT;

	ic->ic_maxrssi = 63;
	ic->ic_set_shortslot = ural_update_slot;
	ic->ic_xmit = ural_send;

	/* set device capabilities */
	ic->ic_caps =
	    IEEE80211_C_TXPMGT |	/* tx power management */
	    IEEE80211_C_SHPREAMBLE |	/* short preamble supported */
	    IEEE80211_C_SHSLOT;		/* short slot time supported */

	ic->ic_caps |= IEEE80211_C_WPA; /* Support WPA/WPA2 */

#define	IEEE80211_CHAN_A	\
	(IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_OFDM)

	if (sc->rf_rev == RAL_RF_5222) {
		/* set supported .11a rates */
		ic->ic_sup_rates[IEEE80211_MODE_11A] = ural_rateset_11a;

		/* set supported .11a channels */
		for (i = 36; i <= 64; i += 4) {
			ic->ic_sup_channels[i].ich_freq =
			    ieee80211_ieee2mhz(i, IEEE80211_CHAN_5GHZ);
			ic->ic_sup_channels[i].ich_flags = IEEE80211_CHAN_A;
		}
		for (i = 100; i <= 140; i += 4) {
			ic->ic_sup_channels[i].ich_freq =
			    ieee80211_ieee2mhz(i, IEEE80211_CHAN_5GHZ);
			ic->ic_sup_channels[i].ich_flags = IEEE80211_CHAN_A;
		}
		for (i = 149; i <= 161; i += 4) {
			ic->ic_sup_channels[i].ich_freq =
			    ieee80211_ieee2mhz(i, IEEE80211_CHAN_5GHZ);
			ic->ic_sup_channels[i].ich_flags = IEEE80211_CHAN_A;
		}
	}

	/* set supported .11b and .11g rates */
	ic->ic_sup_rates[IEEE80211_MODE_11B] = ural_rateset_11b;
	ic->ic_sup_rates[IEEE80211_MODE_11G] = ural_rateset_11g;

	/* set supported .11b and .11g channels (1 through 14) */
	for (i = 1; i <= 14; i++) {
		ic->ic_sup_channels[i].ich_freq =
		    ieee80211_ieee2mhz(i, IEEE80211_CHAN_2GHZ);
		ic->ic_sup_channels[i].ich_flags =
		    IEEE80211_CHAN_CCK | IEEE80211_CHAN_OFDM |
		    IEEE80211_CHAN_DYN | IEEE80211_CHAN_2GHZ;
	}

	ieee80211_attach(ic);

	/* register WPA door */
	ieee80211_register_door(ic, ddi_driver_name(devinfo),
	    ddi_get_instance(devinfo));

	/* override state transition machine */
	sc->sc_newstate = ic->ic_newstate;
	ic->ic_newstate = ural_newstate;
	ic->ic_watchdog = ural_watchdog;
	ieee80211_media_init(ic);
	ic->ic_def_txkey = 0;

	sc->sc_rcr = 0;
	sc->dwelltime = 300;
	sc->sc_flags &= 0;

	/*
	 * Provide initial settings for the WiFi plugin; whenever this
	 * information changes, we need to call mac_plugindata_update()
	 */
	wd.wd_opmode = ic->ic_opmode;
	wd.wd_secalloc = WIFI_SEC_NONE;
	IEEE80211_ADDR_COPY(wd.wd_bssid, ic->ic_bss->in_bssid);

	if ((macp = mac_alloc(MAC_VERSION)) == NULL) {
		ral_debug(RAL_DBG_ERR, "ural_attach(): "
		    "MAC version mismatch\n");
		goto fail3;
	}

	macp->m_type_ident	= MAC_PLUGIN_IDENT_WIFI;
	macp->m_driver		= sc;
	macp->m_dip		= devinfo;
	macp->m_src_addr	= ic->ic_macaddr;
	macp->m_callbacks	= &ural_m_callbacks;
	macp->m_min_sdu		= 0;
	macp->m_max_sdu		= IEEE80211_MTU;
	macp->m_pdata		= &wd;
	macp->m_pdata_size	= sizeof (wd);

	err = mac_register(macp, &ic->ic_mach);
	mac_free(macp);
	if (err != 0) {
		ral_debug(RAL_DBG_ERR, "ural_attach(): "
		    "mac_register() err %x\n", err);
		goto fail3;
	}

	if (usb_register_hotplug_cbs(devinfo, ural_disconnect,
	    ural_reconnect) != USB_SUCCESS) {
		ral_debug(RAL_DBG_ERR,
		    "ural: ural_attach() failed to register events");
		goto fail4;
	}

	/*
	 * Create minor node of type DDI_NT_NET_WIFI
	 */
	(void) snprintf(strbuf, sizeof (strbuf), "%s%d",
	    "ural", instance);
	err = ddi_create_minor_node(devinfo, strbuf, S_IFCHR,
	    instance + 1, DDI_NT_NET_WIFI, 0);

	if (err != DDI_SUCCESS)
		ral_debug(RAL_DBG_ERR, "ddi_create_minor_node() failed\n");

	/*
	 * Notify link is down now
	 */
	mac_link_update(ic->ic_mach, LINK_STATE_DOWN);

	return (DDI_SUCCESS);
fail4:
	(void) mac_unregister(ic->ic_mach);
fail3:
	mutex_destroy(&sc->sc_genlock);
	mutex_destroy(&sc->tx_lock);
	mutex_destroy(&sc->rx_lock);
fail2:
	usb_client_detach(sc->sc_dev, sc->sc_udev);
fail1:
	ddi_soft_state_free(ural_soft_state_p, ddi_get_instance(devinfo));

	return (DDI_FAILURE);
}

static int
ural_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd)
{
	struct ural_softc *sc;

	sc = ddi_get_soft_state(ural_soft_state_p, ddi_get_instance(devinfo));
	ASSERT(sc != NULL);

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		if (RAL_IS_RUNNING(sc))
			(void) ural_stop(sc);
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	if (mac_disable(sc->sc_ic.ic_mach) != 0)
		return (DDI_FAILURE);

	ural_stop(sc);
	usb_unregister_hotplug_cbs(devinfo);

	/*
	 * Unregister from the MAC layer subsystem
	 */
	(void) mac_unregister(sc->sc_ic.ic_mach);

	/*
	 * detach ieee80211 layer
	 */
	ieee80211_detach(&sc->sc_ic);

	mutex_destroy(&sc->sc_genlock);
	mutex_destroy(&sc->tx_lock);
	mutex_destroy(&sc->rx_lock);

	/* pipes will be close in ural_stop() */
	usb_client_detach(devinfo, sc->sc_udev);
	sc->sc_udev = NULL;

	ddi_remove_minor_node(devinfo, NULL);
	ddi_soft_state_free(ural_soft_state_p, ddi_get_instance(devinfo));

	return (DDI_SUCCESS);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_init(void)
{
	int status;

	status = ddi_soft_state_init(&ural_soft_state_p,
	    sizeof (struct ural_softc), 1);
	if (status != 0)
		return (status);

	mac_init_ops(&ural_dev_ops, "ural");
	status = mod_install(&modlinkage);
	if (status != 0) {
		mac_fini_ops(&ural_dev_ops);
		ddi_soft_state_fini(&ural_soft_state_p);
	}
	return (status);
}

int
_fini(void)
{
	int status;

	status = mod_remove(&modlinkage);
	if (status == 0) {
		mac_fini_ops(&ural_dev_ops);
		ddi_soft_state_fini(&ural_soft_state_p);
	}
	return (status);
}
