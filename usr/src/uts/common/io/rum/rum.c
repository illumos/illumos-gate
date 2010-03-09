/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2005-2007 Damien Bergamini <damien.bergamini@free.fr>
 * Copyright (c) 2006 Niall O'Higgins <niallo@openbsd.org>
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
 * Ralink Technology RT2501USB/RT2601USB chipset driver
 * http://www.ralinktech.com.tw/
 */
#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/strsubr.h>
#include <sys/modctl.h>
#include <sys/devops.h>
#include <sys/mac_provider.h>
#include <sys/mac_wifi.h>
#include <sys/net80211.h>
#include <sys/byteorder.h>

#define	USBDRV_MAJOR_VER	2
#define	USBDRV_MINOR_VER	0
#include <sys/usb/usba.h>
#include <sys/usb/usba/usba_types.h>

#include "rum_reg.h"
#include "rum_var.h"
#include "rt2573_ucode.h"

static void *rum_soft_state_p = NULL;

#define	RAL_TXBUF_SIZE  	(IEEE80211_MAX_LEN)
#define	RAL_RXBUF_SIZE  	(IEEE80211_MAX_LEN)

/* quickly determine if a given rate is CCK or OFDM */
#define	RUM_RATE_IS_OFDM(rate)	((rate) >= 12 && (rate) != 22)
#define	RUM_ACK_SIZE	14	/* 10 + 4(FCS) */
#define	RUM_CTS_SIZE	14	/* 10 + 4(FCS) */

#define	RUM_N(a)		(sizeof (a) / sizeof ((a)[0]))

/*
 * Supported rates for 802.11a/b/g modes (in 500Kbps unit).
 */
static const struct ieee80211_rateset rum_rateset_11a =
	{ 8, { 12, 18, 24, 36, 48, 72, 96, 108 } };

static const struct ieee80211_rateset rum_rateset_11b =
	{ 4, { 2, 4, 11, 22 } };

static const struct ieee80211_rateset rum_rateset_11g =
	{ 12, { 2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108 } };

static const struct {
	uint32_t	reg;
	uint32_t	val;
} rum_def_mac[] = {
	{ RT2573_TXRX_CSR0,  0x025fb032 },
	{ RT2573_TXRX_CSR1,  0x9eaa9eaf },
	{ RT2573_TXRX_CSR2,  0x8a8b8c8d },
	{ RT2573_TXRX_CSR3,  0x00858687 },
	{ RT2573_TXRX_CSR7,  0x2e31353b },
	{ RT2573_TXRX_CSR8,  0x2a2a2a2c },
	{ RT2573_TXRX_CSR15, 0x0000000f },
	{ RT2573_MAC_CSR6,   0x00000fff },
	{ RT2573_MAC_CSR8,   0x016c030a },
	{ RT2573_MAC_CSR10,  0x00000718 },
	{ RT2573_MAC_CSR12,  0x00000004 },
	{ RT2573_MAC_CSR13,  0x00007f00 },
	{ RT2573_SEC_CSR0,   0x00000000 },
	{ RT2573_SEC_CSR1,   0x00000000 },
	{ RT2573_SEC_CSR5,   0x00000000 },
	{ RT2573_PHY_CSR1,   0x000023b0 },
	{ RT2573_PHY_CSR5,   0x00040a06 },
	{ RT2573_PHY_CSR6,   0x00080606 },
	{ RT2573_PHY_CSR7,   0x00000408 },
	{ RT2573_AIFSN_CSR,  0x00002273 },
	{ RT2573_CWMIN_CSR,  0x00002344 },
	{ RT2573_CWMAX_CSR,  0x000034aa }
};

static const struct {
	uint8_t	reg;
	uint8_t	val;
} rum_def_bbp[] = {
	{   3, 0x80 },
	{  15, 0x30 },
	{  17, 0x20 },
	{  21, 0xc8 },
	{  22, 0x38 },
	{  23, 0x06 },
	{  24, 0xfe },
	{  25, 0x0a },
	{  26, 0x0d },
	{  32, 0x0b },
	{  34, 0x12 },
	{  37, 0x07 },
	{  39, 0xf8 },
	{  41, 0x60 },
	{  53, 0x10 },
	{  54, 0x18 },
	{  60, 0x10 },
	{  61, 0x04 },
	{  62, 0x04 },
	{  75, 0xfe },
	{  86, 0xfe },
	{  88, 0xfe },
	{  90, 0x0f },
	{  99, 0x00 },
	{ 102, 0x16 },
	{ 107, 0x04 }
};

static const struct rfprog {
	uint8_t		chan;
	uint32_t	r1, r2, r3, r4;
}  rum_rf5226[] = {
	{   1, 0x00b03, 0x001e1, 0x1a014, 0x30282 },
	{   2, 0x00b03, 0x001e1, 0x1a014, 0x30287 },
	{   3, 0x00b03, 0x001e2, 0x1a014, 0x30282 },
	{   4, 0x00b03, 0x001e2, 0x1a014, 0x30287 },
	{   5, 0x00b03, 0x001e3, 0x1a014, 0x30282 },
	{   6, 0x00b03, 0x001e3, 0x1a014, 0x30287 },
	{   7, 0x00b03, 0x001e4, 0x1a014, 0x30282 },
	{   8, 0x00b03, 0x001e4, 0x1a014, 0x30287 },
	{   9, 0x00b03, 0x001e5, 0x1a014, 0x30282 },
	{  10, 0x00b03, 0x001e5, 0x1a014, 0x30287 },
	{  11, 0x00b03, 0x001e6, 0x1a014, 0x30282 },
	{  12, 0x00b03, 0x001e6, 0x1a014, 0x30287 },
	{  13, 0x00b03, 0x001e7, 0x1a014, 0x30282 },
	{  14, 0x00b03, 0x001e8, 0x1a014, 0x30284 },

	{  34, 0x00b03, 0x20266, 0x36014, 0x30282 },
	{  38, 0x00b03, 0x20267, 0x36014, 0x30284 },
	{  42, 0x00b03, 0x20268, 0x36014, 0x30286 },
	{  46, 0x00b03, 0x20269, 0x36014, 0x30288 },

	{  36, 0x00b03, 0x00266, 0x26014, 0x30288 },
	{  40, 0x00b03, 0x00268, 0x26014, 0x30280 },
	{  44, 0x00b03, 0x00269, 0x26014, 0x30282 },
	{  48, 0x00b03, 0x0026a, 0x26014, 0x30284 },
	{  52, 0x00b03, 0x0026b, 0x26014, 0x30286 },
	{  56, 0x00b03, 0x0026c, 0x26014, 0x30288 },
	{  60, 0x00b03, 0x0026e, 0x26014, 0x30280 },
	{  64, 0x00b03, 0x0026f, 0x26014, 0x30282 },

	{ 100, 0x00b03, 0x0028a, 0x2e014, 0x30280 },
	{ 104, 0x00b03, 0x0028b, 0x2e014, 0x30282 },
	{ 108, 0x00b03, 0x0028c, 0x2e014, 0x30284 },
	{ 112, 0x00b03, 0x0028d, 0x2e014, 0x30286 },
	{ 116, 0x00b03, 0x0028e, 0x2e014, 0x30288 },
	{ 120, 0x00b03, 0x002a0, 0x2e014, 0x30280 },
	{ 124, 0x00b03, 0x002a1, 0x2e014, 0x30282 },
	{ 128, 0x00b03, 0x002a2, 0x2e014, 0x30284 },
	{ 132, 0x00b03, 0x002a3, 0x2e014, 0x30286 },
	{ 136, 0x00b03, 0x002a4, 0x2e014, 0x30288 },
	{ 140, 0x00b03, 0x002a6, 0x2e014, 0x30280 },

	{ 149, 0x00b03, 0x002a8, 0x2e014, 0x30287 },
	{ 153, 0x00b03, 0x002a9, 0x2e014, 0x30289 },
	{ 157, 0x00b03, 0x002ab, 0x2e014, 0x30281 },
	{ 161, 0x00b03, 0x002ac, 0x2e014, 0x30283 },
	{ 165, 0x00b03, 0x002ad, 0x2e014, 0x30285 }
}, rum_rf5225[] = {
	{   1, 0x00b33, 0x011e1, 0x1a014, 0x30282 },
	{   2, 0x00b33, 0x011e1, 0x1a014, 0x30287 },
	{   3, 0x00b33, 0x011e2, 0x1a014, 0x30282 },
	{   4, 0x00b33, 0x011e2, 0x1a014, 0x30287 },
	{   5, 0x00b33, 0x011e3, 0x1a014, 0x30282 },
	{   6, 0x00b33, 0x011e3, 0x1a014, 0x30287 },
	{   7, 0x00b33, 0x011e4, 0x1a014, 0x30282 },
	{   8, 0x00b33, 0x011e4, 0x1a014, 0x30287 },
	{   9, 0x00b33, 0x011e5, 0x1a014, 0x30282 },
	{  10, 0x00b33, 0x011e5, 0x1a014, 0x30287 },
	{  11, 0x00b33, 0x011e6, 0x1a014, 0x30282 },
	{  12, 0x00b33, 0x011e6, 0x1a014, 0x30287 },
	{  13, 0x00b33, 0x011e7, 0x1a014, 0x30282 },
	{  14, 0x00b33, 0x011e8, 0x1a014, 0x30284 },

	{  34, 0x00b33, 0x01266, 0x26014, 0x30282 },
	{  38, 0x00b33, 0x01267, 0x26014, 0x30284 },
	{  42, 0x00b33, 0x01268, 0x26014, 0x30286 },
	{  46, 0x00b33, 0x01269, 0x26014, 0x30288 },

	{  36, 0x00b33, 0x01266, 0x26014, 0x30288 },
	{  40, 0x00b33, 0x01268, 0x26014, 0x30280 },
	{  44, 0x00b33, 0x01269, 0x26014, 0x30282 },
	{  48, 0x00b33, 0x0126a, 0x26014, 0x30284 },
	{  52, 0x00b33, 0x0126b, 0x26014, 0x30286 },
	{  56, 0x00b33, 0x0126c, 0x26014, 0x30288 },
	{  60, 0x00b33, 0x0126e, 0x26014, 0x30280 },
	{  64, 0x00b33, 0x0126f, 0x26014, 0x30282 },

	{ 100, 0x00b33, 0x0128a, 0x2e014, 0x30280 },
	{ 104, 0x00b33, 0x0128b, 0x2e014, 0x30282 },
	{ 108, 0x00b33, 0x0128c, 0x2e014, 0x30284 },
	{ 112, 0x00b33, 0x0128d, 0x2e014, 0x30286 },
	{ 116, 0x00b33, 0x0128e, 0x2e014, 0x30288 },
	{ 120, 0x00b33, 0x012a0, 0x2e014, 0x30280 },
	{ 124, 0x00b33, 0x012a1, 0x2e014, 0x30282 },
	{ 128, 0x00b33, 0x012a2, 0x2e014, 0x30284 },
	{ 132, 0x00b33, 0x012a3, 0x2e014, 0x30286 },
	{ 136, 0x00b33, 0x012a4, 0x2e014, 0x30288 },
	{ 140, 0x00b33, 0x012a6, 0x2e014, 0x30280 },

	{ 149, 0x00b33, 0x012a8, 0x2e014, 0x30287 },
	{ 153, 0x00b33, 0x012a9, 0x2e014, 0x30289 },
	{ 157, 0x00b33, 0x012ab, 0x2e014, 0x30281 },
	{ 161, 0x00b33, 0x012ac, 0x2e014, 0x30283 },
	{ 165, 0x00b33, 0x012ad, 0x2e014, 0x30285 }
};

/*
 * device operations
 */
static int rum_attach(dev_info_t *, ddi_attach_cmd_t);
static int rum_detach(dev_info_t *, ddi_detach_cmd_t);

/*
 * Module Loading Data & Entry Points
 */
DDI_DEFINE_STREAM_OPS(rum_dev_ops, nulldev, nulldev, rum_attach,
    rum_detach, nodev, NULL, D_MP, NULL, ddi_quiesce_not_needed);

static struct modldrv rum_modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	"rum driver v1.2",	/* short description */
	&rum_dev_ops		/* driver specific ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&rum_modldrv,
	NULL
};

static int	rum_m_stat(void *,  uint_t, uint64_t *);
static int	rum_m_start(void *);
static void	rum_m_stop(void *);
static int	rum_m_promisc(void *, boolean_t);
static int	rum_m_multicst(void *, boolean_t, const uint8_t *);
static int	rum_m_unicst(void *, const uint8_t *);
static mblk_t	*rum_m_tx(void *, mblk_t *);
static void	rum_m_ioctl(void *, queue_t *, mblk_t *);
static int	rum_m_setprop(void *, const char *, mac_prop_id_t,
    uint_t, const void *);
static int	rum_m_getprop(void *, const char *, mac_prop_id_t,
    uint_t, void *);
static void	rum_m_propinfo(void *, const char *, mac_prop_id_t,
    mac_prop_info_handle_t);

static mac_callbacks_t rum_m_callbacks = {
	MC_IOCTL | MC_SETPROP | MC_GETPROP | MC_PROPINFO,
	rum_m_stat,
	rum_m_start,
	rum_m_stop,
	rum_m_promisc,
	rum_m_multicst,
	rum_m_unicst,
	rum_m_tx,
	NULL,
	rum_m_ioctl,
	NULL,		/* mc_getcapab */
	NULL,
	NULL,
	rum_m_setprop,
	rum_m_getprop,
	rum_m_propinfo
};

static void rum_amrr_start(struct rum_softc *, struct ieee80211_node *);
static int  rum_tx_trigger(struct rum_softc *, mblk_t *);
static int  rum_rx_trigger(struct rum_softc *);

uint32_t rum_dbg_flags = 0;

void
ral_debug(uint32_t dbg_flags, const int8_t *fmt, ...)
{
	va_list args;

	if (dbg_flags & rum_dbg_flags) {
		va_start(args, fmt);
		vcmn_err(CE_CONT, fmt, args);
		va_end(args);
	}
}

static void
rum_read_multi(struct rum_softc *sc, uint16_t reg, void *buf, int len)
{
	usb_ctrl_setup_t req;
	usb_cr_t cr;
	usb_cb_flags_t cf;
	mblk_t *mp;
	int err;

	bzero(&req, sizeof (req));
	req.bmRequestType = USB_DEV_REQ_TYPE_VENDOR | USB_DEV_REQ_DEV_TO_HOST;
	req.bRequest = RT2573_READ_MULTI_MAC;
	req.wValue = 0;
	req.wIndex = reg;
	req.wLength = (uint16_t)len;
	req.attrs = USB_ATTRS_AUTOCLEARING;

	mp = NULL;
	err = usb_pipe_ctrl_xfer_wait(sc->sc_udev->dev_default_ph, &req, &mp,
	    &cr, &cf, 0);

	if (err != USB_SUCCESS) {
		ral_debug(RAL_DBG_ERR,
		    "rum_read_multi(): could not read MAC register:"
		    "cr:%s(%d), cf:(%x)\n",
		    usb_str_cr(cr), cr, cf);
		return;
	}

	bcopy(mp->b_rptr, buf, len);
	freemsg(mp);
}

static uint32_t
rum_read(struct rum_softc *sc, uint16_t reg)
{
	uint32_t val;

	rum_read_multi(sc, reg, &val, sizeof (val));

	return (LE_32(val));
}

static void
rum_write_multi(struct rum_softc *sc, uint16_t reg, void *buf, size_t len)
{
	usb_ctrl_setup_t req;
	usb_cr_t cr;
	usb_cb_flags_t cf;
	mblk_t *mp;
	int err;

	bzero(&req, sizeof (req));
	req.bmRequestType = USB_DEV_REQ_TYPE_VENDOR | USB_DEV_REQ_HOST_TO_DEV;
	req.bRequest = RT2573_WRITE_MULTI_MAC;
	req.wValue = 0;
	req.wIndex = reg;
	req.wLength = (uint16_t)len;
	req.attrs = USB_ATTRS_NONE;

	if ((mp = allocb(len, BPRI_HI)) == NULL) {
		ral_debug(RAL_DBG_ERR, "rum_write_multi(): failed alloc mblk.");
		return;
	}

	bcopy(buf, mp->b_wptr, len);
	mp->b_wptr += len;

	err = usb_pipe_ctrl_xfer_wait(sc->sc_udev->dev_default_ph, &req, &mp,
	    &cr, &cf, 0);

	if (err != USB_SUCCESS) {
		ral_debug(RAL_DBG_USB,
		    "rum_write_multi(): could not write MAC register:"
		    "cr:%s(%d), cf:(%x)\n",
		    usb_str_cr(cr), cr, cf);
	}

	freemsg(mp);
}

static void
rum_write(struct rum_softc *sc, uint16_t reg, uint32_t val)
{
	uint32_t tmp = LE_32(val);

	rum_write_multi(sc, reg, &tmp, sizeof (tmp));
}

#define	UGETDW(w) ((w)[0] | ((w)[1] << 8) | ((w)[2] << 16) | ((w)[3] << 24))

static int
rum_load_microcode(struct rum_softc *sc)
{
	usb_ctrl_setup_t req;
	usb_cr_t cr;
	usb_cb_flags_t cf;
	int err;

	const uint8_t *ucode;
	int size;
	uint16_t reg = RT2573_MCU_CODE_BASE;

	ucode = rt2573_ucode;
	size  = sizeof (rt2573_ucode);

	/* copy firmware image into NIC */
	for (; size >= 4; reg += 4, ucode += 4, size -= 4) {
		rum_write(sc, reg, UGETDW(ucode));
		/* rum_write(sc, reg, *(uint32_t *)(ucode)); */
	}

	bzero(&req, sizeof (req));
	req.bmRequestType = USB_DEV_REQ_TYPE_VENDOR | USB_DEV_REQ_HOST_TO_DEV;
	req.bRequest = RT2573_MCU_CNTL;
	req.wValue = RT2573_MCU_RUN;
	req.wIndex = 0;
	req.wLength = 0;
	req.attrs = USB_ATTRS_NONE;

	err = usb_pipe_ctrl_xfer_wait(sc->sc_udev->dev_default_ph, &req, NULL,
	    &cr, &cf, 0);

	if (err != USB_SUCCESS) {
		ral_debug(RAL_DBG_ERR,
		    "rum_load_microcode(): could not run firmware: "
		    "cr:%s(%d), cf:(%x)\n",
		    usb_str_cr(cr), cr, cf);
	}

	ral_debug(RAL_DBG_MSG,
	    "rum_load_microcode(%d): done\n", sizeof (rt2573_ucode));

	return (err);
}

static void
rum_eeprom_read(struct rum_softc *sc, uint16_t addr, void *buf, int len)
{
	usb_ctrl_setup_t req;
	usb_cr_t cr;
	usb_cb_flags_t cf;
	mblk_t *mp;
	int err;

	bzero(&req, sizeof (req));
	req.bmRequestType = USB_DEV_REQ_TYPE_VENDOR | USB_DEV_REQ_DEV_TO_HOST;
	req.bRequest = RT2573_READ_EEPROM;
	req.wValue = 0;
	req.wIndex = addr;
	req.wLength = (uint16_t)len;

	mp = NULL;
	err = usb_pipe_ctrl_xfer_wait(sc->sc_udev->dev_default_ph, &req, &mp,
	    &cr, &cf, 0);

	if (err != USB_SUCCESS) {
		ral_debug(RAL_DBG_USB,
		    "rum_eeprom_read(): could not read EEPROM:"
		    "cr:%s(%d), cf:(%x)\n",
		    usb_str_cr(cr), cr, cf);
		return;
	}

	bcopy(mp->b_rptr, buf, len);
	freemsg(mp);
}

/* ARGSUSED */
static void
rum_txeof(usb_pipe_handle_t pipe, usb_bulk_req_t *req)
{
	struct rum_softc *sc = (struct rum_softc *)req->bulk_client_private;
	struct ieee80211com *ic = &sc->sc_ic;

	ral_debug(RAL_DBG_TX,
	    "rum_txeof(): cr:%s(%d), flags:0x%x, tx_queued:%d",
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
rum_rxeof(usb_pipe_handle_t pipe, usb_bulk_req_t *req)
{
	struct rum_softc *sc = (struct rum_softc *)req->bulk_client_private;
	struct ieee80211com *ic = &sc->sc_ic;

	struct rum_rx_desc *desc;
	struct ieee80211_frame *wh;
	struct ieee80211_node *ni;

	mblk_t *m, *mp;
	int len, pktlen;
	char *rxbuf;

	mp = req->bulk_data;
	req->bulk_data = NULL;

	ral_debug(RAL_DBG_RX,
	    "rum_rxeof(): cr:%s(%d), flags:0x%x, rx_queued:%d",
	    usb_str_cr(req->bulk_completion_reason),
	    req->bulk_completion_reason,
	    req->bulk_cb_flags,
	    sc->rx_queued);

	if (req->bulk_completion_reason != USB_CR_OK) {
		sc->sc_rx_err++;
		goto fail;
	}

	len = msgdsize(mp);
	rxbuf = (char *)mp->b_rptr;


	if (len < RT2573_RX_DESC_SIZE + sizeof (struct ieee80211_frame_min)) {
		ral_debug(RAL_DBG_ERR,
		    "rum_rxeof(): xfer too short %d\n", len);
		sc->sc_rx_err++;
		goto fail;
	}

	/* rx descriptor is located at the head, different from RT2500USB */
	desc = (struct rum_rx_desc *)rxbuf;

	if (LE_32(desc->flags) & RT2573_RX_CRC_ERROR) {
		/*
		 * This should not happen since we did not request to receive
		 * those frames when we filled RT2573_TXRX_CSR0.
		 */
		ral_debug(RAL_DBG_ERR, "CRC error\n");
		sc->sc_rx_err++;
		goto fail;
	}

	pktlen = (LE_32(desc->flags) >> 16) & 0xfff;

	if (pktlen > (len - RT2573_RX_DESC_SIZE)) {
		ral_debug(RAL_DBG_ERR,
		    "rum_rxeof(): pktlen mismatch <%d, %d>.\n", pktlen, len);
		goto fail;
	}

	if ((m = allocb(pktlen, BPRI_MED)) == NULL) {
		ral_debug(RAL_DBG_ERR,
		    "rum_rxeof(): allocate mblk failed.\n");
		sc->sc_rx_nobuf++;
		goto fail;
	}

	bcopy(rxbuf + RT2573_RX_DESC_SIZE, m->b_rptr, pktlen);
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
		(void) rum_rx_trigger(sc);
}

/*
 * Return the expected ack rate for a frame transmitted at rate `rate'.
 */
static int
rum_ack_rate(struct ieee80211com *ic, int rate)
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
rum_txtime(int len, int rate, uint32_t flags)
{
	uint16_t txtime;

	if (RUM_RATE_IS_OFDM(rate)) {
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
rum_plcp_signal(int rate)
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
rum_setup_tx_desc(struct rum_softc *sc, struct rum_tx_desc *desc,
    uint32_t flags, uint16_t xflags, int len, int rate)
{
	struct ieee80211com *ic = &sc->sc_ic;
	uint16_t plcp_length;
	int remainder;

	desc->flags = LE_32(flags);
	desc->flags |= LE_32(RT2573_TX_VALID);
	desc->flags |= LE_32(len << 16);

	desc->xflags = LE_16(xflags);

	desc->wme = LE_16(RT2573_QID(0) | RT2573_AIFSN(2) |
	    RT2573_LOGCWMIN(4) | RT2573_LOGCWMAX(10));

	/* setup PLCP fields */
	desc->plcp_signal  = rum_plcp_signal(rate);
	desc->plcp_service = 4;

	len += IEEE80211_CRC_LEN;
	if (RUM_RATE_IS_OFDM(rate)) {
		desc->flags |= LE_32(RT2573_TX_OFDM);

		plcp_length = len & 0xfff;
		desc->plcp_length_hi = plcp_length >> 6;
		desc->plcp_length_lo = plcp_length & 0x3f;
	} else {
		plcp_length = (16 * len + rate - 1) / rate;
		if (rate == 22) {
			remainder = (16 * len) % 22;
			if (remainder != 0 && remainder < 7)
				desc->plcp_service |= RT2573_PLCP_LENGEXT;
		}
		desc->plcp_length_hi = plcp_length >> 8;
		desc->plcp_length_lo = plcp_length & 0xff;

		if (rate != 2 && (ic->ic_flags & IEEE80211_F_SHPREAMBLE))
			desc->plcp_signal |= 0x08;
	}
}

#define	RUM_TX_TIMEOUT	5

static int
rum_send(ieee80211com_t *ic, mblk_t *mp, uint8_t type)
{
	struct rum_softc *sc = (struct rum_softc *)ic;
	struct rum_tx_desc *desc;

	struct ieee80211_frame *wh;
	struct ieee80211_key *k;

	uint16_t dur;
	uint32_t flags = 0;
	int rate, err = DDI_SUCCESS, rv;

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
		ral_debug(RAL_DBG_TX, "rum_send(): "
		    "no TX buffer available!\n");
		if ((type & IEEE80211_FC0_TYPE_MASK) ==
		    IEEE80211_FC0_TYPE_DATA) {
			sc->sc_need_sched = 1;
		}
		sc->sc_tx_nobuf++;
		err = ENOMEM;
		goto fail;
	}

	m = allocb(RAL_TXBUF_SIZE + RT2573_TX_DESC_SIZE, BPRI_MED);
	if (m == NULL) {
		ral_debug(RAL_DBG_ERR, "rum_send(): can't alloc mblk.\n");
		err = DDI_FAILURE;
		goto fail;
	}

	m->b_rptr += RT2573_TX_DESC_SIZE;	/* skip TX descriptor */
	m->b_wptr += RT2573_TX_DESC_SIZE;

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
			err = DDI_FAILURE;
			freemsg(m);
			goto fail;
		}
		/* packet header may have moved, reset our local pointer */
		wh = (struct ieee80211_frame *)m->b_rptr;
	}

	m->b_rptr -= RT2573_TX_DESC_SIZE;	/* restore */
	desc = (struct rum_tx_desc *)m->b_rptr;

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
			flags |= RT2573_TX_NEED_ACK;
			flags |= RT2573_TX_MORE_FRAG;

			dur = rum_txtime(RUM_ACK_SIZE, rum_ack_rate(ic, rate),
			    ic->ic_flags) + sc->sifs;
			*(uint16_t *)(uintptr_t)wh->i_dur = LE_16(dur);
		}
	} else {	/* MGMT */
		rate = IEEE80211_IS_CHAN_5GHZ(ic->ic_curchan) ? 12 : 2;

		if (!IEEE80211_IS_MULTICAST(wh->i_addr1)) {
			flags |= RT2573_TX_NEED_ACK;

			dur = rum_txtime(RUM_ACK_SIZE, rum_ack_rate(ic, rate),
			    ic->ic_flags) + sc->sifs;
			*(uint16_t *)(uintptr_t)wh->i_dur = LE_16(dur);

			/* tell hardware to add timestamp for probe responses */
			if ((wh->i_fc[0] &
			    (IEEE80211_FC0_TYPE_MASK |
			    IEEE80211_FC0_SUBTYPE_MASK)) ==
			    (IEEE80211_FC0_TYPE_MGT |
			    IEEE80211_FC0_SUBTYPE_PROBE_RESP))
				flags |= RT2573_TX_TIMESTAMP;
		}
	}

	pktlen = msgdsize(m) - RT2573_TX_DESC_SIZE;
	rum_setup_tx_desc(sc, desc, flags, 0, pktlen, rate);

	/* align end on a 4-bytes boundary */
	xferlen = (RT2573_TX_DESC_SIZE + pktlen + 3) & ~3;

	/*
	 * No space left in the last URB to store the extra 4 bytes, force
	 * sending of another URB.
	 */
	if ((xferlen % 64) == 0)
		xferlen += 4;

	m->b_wptr = m->b_rptr + xferlen;

	ral_debug(RAL_DBG_TX, "sending data frame len=%u rate=%u xfer len=%u\n",
	    pktlen, rate, xferlen);

	rv = rum_tx_trigger(sc, m);

	if (rv == 0) {
		ic->ic_stats.is_tx_frags++;
		ic->ic_stats.is_tx_bytes += pktlen;
	}

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
rum_m_tx(void *arg, mblk_t *mp)
{
	struct rum_softc *sc = (struct rum_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;
	mblk_t *next;

	/*
	 * No data frames go out unless we're associated; this
	 * should not happen as the 802.11 layer does not enable
	 * the xmit queue until we enter the RUN state.
	 */
	if (ic->ic_state != IEEE80211_S_RUN) {
		ral_debug(RAL_DBG_ERR, "rum_m_tx(): "
		    "discard, state %u\n", ic->ic_state);
		freemsgchain(mp);
		return (NULL);
	}

	while (mp != NULL) {
		next = mp->b_next;
		mp->b_next = NULL;
		if (rum_send(ic, mp, IEEE80211_FC0_TYPE_DATA) != DDI_SUCCESS) {
			mp->b_next = next;
			freemsgchain(mp);
			return (NULL);
		}
		mp = next;
	}
	return (mp);
}

static void
rum_bbp_write(struct rum_softc *sc, uint8_t reg, uint8_t val)
{
	uint32_t tmp;
	int ntries;

	for (ntries = 0; ntries < 5; ntries++) {
		if (!(rum_read(sc, RT2573_PHY_CSR3) & RT2573_BBP_BUSY))
			break;
	}
	if (ntries == 5) {
		ral_debug(RAL_DBG_ERR,
		    "rum_bbp_write(): could not write to BBP\n");
		return;
	}

	tmp = RT2573_BBP_BUSY | (reg & 0x7f) << 8 | val;
	rum_write(sc, RT2573_PHY_CSR3, tmp);
}

static uint8_t
rum_bbp_read(struct rum_softc *sc, uint8_t reg)
{
	uint32_t val;
	int ntries;

	for (ntries = 0; ntries < 5; ntries++) {
		if (!(rum_read(sc, RT2573_PHY_CSR3) & RT2573_BBP_BUSY))
			break;
	}
	if (ntries == 5) {
		ral_debug(RAL_DBG_ERR, "rum_bbp_read(): could not read BBP\n");
		return (0);
	}

	val = RT2573_BBP_BUSY | RT2573_BBP_READ | reg << 8;
	rum_write(sc, RT2573_PHY_CSR3, val);

	for (ntries = 0; ntries < 100; ntries++) {
		val = rum_read(sc, RT2573_PHY_CSR3);
		if (!(val & RT2573_BBP_BUSY))
			return (val & 0xff);
		drv_usecwait(1);
	}

	ral_debug(RAL_DBG_ERR, "rum_bbp_read(): could not read BBP\n");
	return (0);
}

static void
rum_rf_write(struct rum_softc *sc, uint8_t reg, uint32_t val)
{
	uint32_t tmp;
	int ntries;

	for (ntries = 0; ntries < 5; ntries++) {
		if (!(rum_read(sc, RT2573_PHY_CSR4) & RT2573_RF_BUSY))
			break;
	}
	if (ntries == 5) {
		ral_debug(RAL_DBG_ERR,
		    "rum_rf_write(): could not write to RF\n");
		return;
	}

	tmp = RT2573_RF_BUSY | RT2573_RF_20BIT | (val & 0xfffff) << 2 |
	    (reg & 3);
	rum_write(sc, RT2573_PHY_CSR4, tmp);

	/* remember last written value in sc */
	sc->rf_regs[reg] = val;

	ral_debug(RAL_DBG_HW, "RF R[%u] <- 0x%05x\n", reg & 3, val & 0xfffff);
}

static void
rum_select_antenna(struct rum_softc *sc)
{
	uint8_t bbp4, bbp77;
	uint32_t tmp;

	bbp4  = rum_bbp_read(sc, 4);
	bbp77 = rum_bbp_read(sc, 77);

	/* make sure Rx is disabled before switching antenna */
	tmp = rum_read(sc, RT2573_TXRX_CSR0);
	rum_write(sc, RT2573_TXRX_CSR0, tmp | RT2573_DISABLE_RX);

	rum_bbp_write(sc,  4, bbp4);
	rum_bbp_write(sc, 77, bbp77);

	rum_write(sc, RT2573_TXRX_CSR0, tmp);
}

/*
 * Enable multi-rate retries for frames sent at OFDM rates.
 * In 802.11b/g mode, allow fallback to CCK rates.
 */
static void
rum_enable_mrr(struct rum_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	uint32_t tmp;

	tmp = rum_read(sc, RT2573_TXRX_CSR4);

	tmp &= ~RT2573_MRR_CCK_FALLBACK;
	if (!IEEE80211_IS_CHAN_5GHZ(ic->ic_curchan))
		tmp |= RT2573_MRR_CCK_FALLBACK;
	tmp |= RT2573_MRR_ENABLED;

	rum_write(sc, RT2573_TXRX_CSR4, tmp);
}

static void
rum_set_txpreamble(struct rum_softc *sc)
{
	uint32_t tmp;

	tmp = rum_read(sc, RT2573_TXRX_CSR4);

	tmp &= ~RT2573_SHORT_PREAMBLE;
	if (sc->sc_ic.ic_flags & IEEE80211_F_SHPREAMBLE)
		tmp |= RT2573_SHORT_PREAMBLE;

	rum_write(sc, RT2573_TXRX_CSR4, tmp);
}

static void
rum_set_basicrates(struct rum_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;

	/* update basic rate set */
	if (ic->ic_curmode == IEEE80211_MODE_11B) {
		/* 11b basic rates: 1, 2Mbps */
		rum_write(sc, RT2573_TXRX_CSR5, 0x3);
	} else if (IEEE80211_IS_CHAN_5GHZ(ic->ic_bss->in_chan)) {
		/* 11a basic rates: 6, 12, 24Mbps */
		rum_write(sc, RT2573_TXRX_CSR5, 0x150);
	} else {
		/* 11b/g basic rates: 1, 2, 5.5, 11Mbps */
		rum_write(sc, RT2573_TXRX_CSR5, 0xf);
	}
}

/*
 * Reprogram MAC/BBP to switch to a new band.  Values taken from the reference
 * driver.
 */
static void
rum_select_band(struct rum_softc *sc, struct ieee80211_channel *c)
{
	uint8_t bbp17, bbp35, bbp96, bbp97, bbp98, bbp104;
	uint32_t tmp;

	/* update all BBP registers that depend on the band */
	bbp17 = 0x20; bbp96 = 0x48; bbp104 = 0x2c;
	bbp35 = 0x50; bbp97 = 0x48; bbp98  = 0x48;
	if (IEEE80211_IS_CHAN_5GHZ(c)) {
		bbp17 += 0x08; bbp96 += 0x10; bbp104 += 0x0c;
		bbp35 += 0x10; bbp97 += 0x10; bbp98  += 0x10;
	}
	if ((IEEE80211_IS_CHAN_2GHZ(c) && sc->ext_2ghz_lna) ||
	    (IEEE80211_IS_CHAN_5GHZ(c) && sc->ext_5ghz_lna)) {
		bbp17 += 0x10; bbp96 += 0x10; bbp104 += 0x10;
	}

	sc->bbp17 = bbp17;
	rum_bbp_write(sc,  17, bbp17);
	rum_bbp_write(sc,  96, bbp96);
	rum_bbp_write(sc, 104, bbp104);

	if ((IEEE80211_IS_CHAN_2GHZ(c) && sc->ext_2ghz_lna) ||
	    (IEEE80211_IS_CHAN_5GHZ(c) && sc->ext_5ghz_lna)) {
		rum_bbp_write(sc, 75, 0x80);
		rum_bbp_write(sc, 86, 0x80);
		rum_bbp_write(sc, 88, 0x80);
	}

	rum_bbp_write(sc, 35, bbp35);
	rum_bbp_write(sc, 97, bbp97);
	rum_bbp_write(sc, 98, bbp98);

	tmp = rum_read(sc, RT2573_PHY_CSR0);
	tmp &= ~(RT2573_PA_PE_2GHZ | RT2573_PA_PE_5GHZ);
	if (IEEE80211_IS_CHAN_2GHZ(c))
		tmp |= RT2573_PA_PE_2GHZ;
	else
		tmp |= RT2573_PA_PE_5GHZ;
	rum_write(sc, RT2573_PHY_CSR0, tmp);

	/* 802.11a uses a 16 microseconds short interframe space */
	sc->sifs = IEEE80211_IS_CHAN_5GHZ(c) ? 16 : 10;
}

static void
rum_set_chan(struct rum_softc *sc, struct ieee80211_channel *c)
{
	struct ieee80211com *ic = &sc->sc_ic;
	const struct rfprog *rfprog;
	uint8_t bbp3, bbp94 = RT2573_BBPR94_DEFAULT;
	int8_t power;
	uint_t i, chan;

	chan = ieee80211_chan2ieee(ic, c);
	if (chan == 0 || chan == IEEE80211_CHAN_ANY)
		return;

	/* select the appropriate RF settings based on what EEPROM says */
	rfprog = (sc->rf_rev == RT2573_RF_5225 ||
	    sc->rf_rev == RT2573_RF_2527) ? rum_rf5225 : rum_rf5226;

	/* find the settings for this channel (we know it exists) */
	for (i = 0; rfprog[i].chan != chan; i++) {
	}

	power = sc->txpow[i];
	if (power < 0) {
		bbp94 += power;
		power = 0;
	} else if (power > 31) {
		bbp94 += power - 31;
		power = 31;
	}

	/*
	 * If we are switching from the 2GHz band to the 5GHz band or
	 * vice-versa, BBP registers need to be reprogrammed.
	 */
	if (c->ich_flags != ic->ic_curchan->ich_flags) {
		rum_select_band(sc, c);
		rum_select_antenna(sc);
	}
	ic->ic_curchan = c;

	rum_rf_write(sc, RT2573_RF1, rfprog[i].r1);
	rum_rf_write(sc, RT2573_RF2, rfprog[i].r2);
	rum_rf_write(sc, RT2573_RF3, rfprog[i].r3 | power << 7);
	rum_rf_write(sc, RT2573_RF4, rfprog[i].r4 | sc->rffreq << 10);

	rum_rf_write(sc, RT2573_RF1, rfprog[i].r1);
	rum_rf_write(sc, RT2573_RF2, rfprog[i].r2);
	rum_rf_write(sc, RT2573_RF3, rfprog[i].r3 | power << 7 | 1);
	rum_rf_write(sc, RT2573_RF4, rfprog[i].r4 | sc->rffreq << 10);

	rum_rf_write(sc, RT2573_RF1, rfprog[i].r1);
	rum_rf_write(sc, RT2573_RF2, rfprog[i].r2);
	rum_rf_write(sc, RT2573_RF3, rfprog[i].r3 | power << 7);
	rum_rf_write(sc, RT2573_RF4, rfprog[i].r4 | sc->rffreq << 10);

	drv_usecwait(10);

	/* enable smart mode for MIMO-capable RFs */
	bbp3 = rum_bbp_read(sc, 3);

	bbp3 &= ~RT2573_SMART_MODE;
	if (sc->rf_rev == RT2573_RF_5225 || sc->rf_rev == RT2573_RF_2527)
		bbp3 |= RT2573_SMART_MODE;

	rum_bbp_write(sc, 3, bbp3);

	if (bbp94 != RT2573_BBPR94_DEFAULT)
		rum_bbp_write(sc, 94, bbp94);
}

/*
 * Enable TSF synchronization and tell h/w to start sending beacons for IBSS
 * and HostAP operating modes.
 */
static void
rum_enable_tsf_sync(struct rum_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	uint32_t tmp;

	if (ic->ic_opmode != IEEE80211_M_STA) {
		/*
		 * Change default 16ms TBTT adjustment to 8ms.
		 * Must be done before enabling beacon generation.
		 */
		rum_write(sc, RT2573_TXRX_CSR10, 1 << 12 | 8);
	}

	tmp = rum_read(sc, RT2573_TXRX_CSR9) & 0xff000000;

	/* set beacon interval (in 1/16ms unit) */
	tmp |= ic->ic_bss->in_intval * 16;

	tmp |= RT2573_TSF_TICKING | RT2573_ENABLE_TBTT;
	if (ic->ic_opmode == IEEE80211_M_STA)
		tmp |= RT2573_TSF_MODE(1);
	else
		tmp |= RT2573_TSF_MODE(2) | RT2573_GENERATE_BEACON;

	rum_write(sc, RT2573_TXRX_CSR9, tmp);
}

/* ARGSUSED */
static void
rum_update_slot(struct ieee80211com *ic, int onoff)
{
	struct rum_softc *sc = (struct rum_softc *)ic;
	uint8_t slottime;
	uint32_t tmp;

	slottime = (ic->ic_flags & IEEE80211_F_SHSLOT) ? 9 : 20;

	tmp = rum_read(sc, RT2573_MAC_CSR9);
	tmp = (tmp & ~0xff) | slottime;
	rum_write(sc, RT2573_MAC_CSR9, tmp);

	ral_debug(RAL_DBG_HW, "setting slot time to %uus\n", slottime);
}

static void
rum_set_bssid(struct rum_softc *sc, const uint8_t *bssid)
{
	uint32_t tmp;

	tmp = bssid[0] | bssid[1] << 8 | bssid[2] << 16 | bssid[3] << 24;
	rum_write(sc, RT2573_MAC_CSR4, tmp);

	tmp = bssid[4] | bssid[5] << 8 | RT2573_ONE_BSSID << 16;
	rum_write(sc, RT2573_MAC_CSR5, tmp);
}

static void
rum_set_macaddr(struct rum_softc *sc, const uint8_t *addr)
{
	uint32_t tmp;

	tmp = addr[0] | addr[1] << 8 | addr[2] << 16 | addr[3] << 24;
	rum_write(sc, RT2573_MAC_CSR2, tmp);

	tmp = addr[4] | addr[5] << 8 | 0xff << 16;
	rum_write(sc, RT2573_MAC_CSR3, tmp);

	ral_debug(RAL_DBG_HW,
	    "setting MAC address to " MACSTR "\n", MAC2STR(addr));
}

static void
rum_update_promisc(struct rum_softc *sc)
{
	uint32_t tmp;

	tmp = rum_read(sc, RT2573_TXRX_CSR0);

	tmp &= ~RT2573_DROP_NOT_TO_ME;
	if (!(sc->sc_rcr & RAL_RCR_PROMISC))
		tmp |= RT2573_DROP_NOT_TO_ME;

	rum_write(sc, RT2573_TXRX_CSR0, tmp);

	ral_debug(RAL_DBG_HW, "%s promiscuous mode\n",
	    (sc->sc_rcr & RAL_RCR_PROMISC) ?  "entering" : "leaving");
}

static const char *
rum_get_rf(int rev)
{
	switch (rev) {
	case RT2573_RF_2527:	return ("RT2527 (MIMO XR)");
	case RT2573_RF_2528:	return ("RT2528");
	case RT2573_RF_5225:	return ("RT5225 (MIMO XR)");
	case RT2573_RF_5226:	return ("RT5226");
	default:		return ("unknown");
	}
}

static void
rum_read_eeprom(struct rum_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	uint16_t val;

	/* read MAC address */
	rum_eeprom_read(sc, RT2573_EEPROM_ADDRESS, ic->ic_macaddr, 6);

	rum_eeprom_read(sc, RT2573_EEPROM_ANTENNA, &val, 2);
	val = LE_16(val);
	sc->rf_rev =   (val >> 11) & 0x1f;
	sc->hw_radio = (val >> 10) & 0x1;
	sc->rx_ant =   (val >> 4)  & 0x3;
	sc->tx_ant =   (val >> 2)  & 0x3;
	sc->nb_ant =   val & 0x3;

	ral_debug(RAL_DBG_HW, "RF revision=%d\n", sc->rf_rev);

	rum_eeprom_read(sc, RT2573_EEPROM_CONFIG2, &val, 2);
	val = LE_16(val);
	sc->ext_5ghz_lna = (val >> 6) & 0x1;
	sc->ext_2ghz_lna = (val >> 4) & 0x1;

	ral_debug(RAL_DBG_HW, "External 2GHz LNA=%d\nExternal 5GHz LNA=%d\n",
	    sc->ext_2ghz_lna, sc->ext_5ghz_lna);

	rum_eeprom_read(sc, RT2573_EEPROM_RSSI_2GHZ_OFFSET, &val, 2);
	val = LE_16(val);
	if ((val & 0xff) != 0xff)
		sc->rssi_2ghz_corr = (int8_t)(val & 0xff);	/* signed */

	rum_eeprom_read(sc, RT2573_EEPROM_RSSI_5GHZ_OFFSET, &val, 2);
	val = LE_16(val);
	if ((val & 0xff) != 0xff)
		sc->rssi_5ghz_corr = (int8_t)(val & 0xff);	/* signed */

	ral_debug(RAL_DBG_HW, "RSSI 2GHz corr=%d\nRSSI 5GHz corr=%d\n",
	    sc->rssi_2ghz_corr, sc->rssi_5ghz_corr);

	rum_eeprom_read(sc, RT2573_EEPROM_FREQ_OFFSET, &val, 2);
	val = LE_16(val);
	if ((val & 0xff) != 0xff)
		sc->rffreq = val & 0xff;

	ral_debug(RAL_DBG_HW, "RF freq=%d\n", sc->rffreq);

	/* read Tx power for all a/b/g channels */
	rum_eeprom_read(sc, RT2573_EEPROM_TXPOWER, sc->txpow, 14);
	/* default Tx power for 802.11a channels */
	(void) memset(sc->txpow + 14, 24, sizeof (sc->txpow) - 14);

	/* read default values for BBP registers */
	rum_eeprom_read(sc, RT2573_EEPROM_BBP_BASE, sc->bbp_prom, 2 * 16);
}

static int
rum_bbp_init(struct rum_softc *sc)
{
	int i, ntries;

	/* wait for BBP to be ready */
	for (ntries = 0; ntries < 100; ntries++) {
		const uint8_t val = rum_bbp_read(sc, 0);
		if (val != 0 && val != 0xff)
			break;
		drv_usecwait(1000);
	}
	if (ntries == 100) {
		ral_debug(RAL_DBG_ERR, "timeout waiting for BBP\n");
		return (EIO);
	}

	/* initialize BBP registers to default values */
	for (i = 0; i < RUM_N(rum_def_bbp); i++)
		rum_bbp_write(sc, rum_def_bbp[i].reg, rum_def_bbp[i].val);

	/* write vendor-specific BBP values (from EEPROM) */
	for (i = 0; i < 16; i++) {
		if (sc->bbp_prom[i].reg == 0 || sc->bbp_prom[i].reg == 0xff)
			continue;
		rum_bbp_write(sc, sc->bbp_prom[i].reg, sc->bbp_prom[i].val);
	}

	return (0);
}

/*
 * This function is called periodically (every 200ms) during scanning to
 * switch from one channel to another.
 */
static void
rum_next_scan(void *arg)
{
	struct rum_softc *sc = arg;
	struct ieee80211com *ic = &sc->sc_ic;

	if (ic->ic_state == IEEE80211_S_SCAN)
		ieee80211_next_scan(ic);
}

static int
rum_newstate(struct ieee80211com *ic, enum ieee80211_state nstate, int arg)
{
	struct rum_softc *sc = (struct rum_softc *)ic;
	enum ieee80211_state ostate;
	struct ieee80211_node *ni;
	int err;
	uint32_t tmp;

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
			tmp = rum_read(sc, RT2573_TXRX_CSR9);
			rum_write(sc, RT2573_TXRX_CSR9, tmp & ~0x00ffffff);
		}
		break;

	case IEEE80211_S_SCAN:
		rum_set_chan(sc, ic->ic_curchan);
		sc->sc_scan_id = timeout(rum_next_scan, (void *)sc,
		    drv_usectohz(sc->dwelltime * 1000));
		break;

	case IEEE80211_S_AUTH:
		rum_set_chan(sc, ic->ic_curchan);
		break;

	case IEEE80211_S_ASSOC:
		rum_set_chan(sc, ic->ic_curchan);
		break;

	case IEEE80211_S_RUN:
		rum_set_chan(sc, ic->ic_curchan);

		ni = ic->ic_bss;

		if (ic->ic_opmode != IEEE80211_M_MONITOR) {
			rum_update_slot(ic, 1);
			rum_enable_mrr(sc);
			rum_set_txpreamble(sc);
			rum_set_basicrates(sc);
			rum_set_bssid(sc, ni->in_bssid);
		}

		if (ic->ic_opmode != IEEE80211_M_MONITOR)
			rum_enable_tsf_sync(sc);

		/* enable automatic rate adaptation in STA mode */
		if (ic->ic_opmode == IEEE80211_M_STA &&
		    ic->ic_fixed_rate == IEEE80211_FIXED_RATE_NONE)
			rum_amrr_start(sc, ni);
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
rum_close_pipes(struct rum_softc *sc)
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
rum_open_pipes(struct rum_softc *sc)
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
		    "rum_open_pipes(): %x failed to open tx pipe\n", err);
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
		    "rum_open_pipes(): %x failed to open rx pipe\n", err);
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
rum_tx_trigger(struct rum_softc *sc, mblk_t *mp)
{
	usb_bulk_req_t *req;
	int err;

	sc->sc_tx_timer = RUM_TX_TIMEOUT;

	req = usb_alloc_bulk_req(sc->sc_dev, 0, USB_FLAGS_SLEEP);
	if (req == NULL) {
		ral_debug(RAL_DBG_ERR,
		    "rum_tx_trigger(): failed to allocate req");
		freemsg(mp);
		return (-1);
	}

	req->bulk_len		= msgdsize(mp);
	req->bulk_data		= mp;
	req->bulk_client_private = (usb_opaque_t)sc;
	req->bulk_timeout	= RUM_TX_TIMEOUT;
	req->bulk_attributes	= USB_ATTRS_AUTOCLEARING;
	req->bulk_cb		= rum_txeof;
	req->bulk_exc_cb	= rum_txeof;
	req->bulk_completion_reason = 0;
	req->bulk_cb_flags	= 0;

	if ((err = usb_pipe_bulk_xfer(sc->sc_tx_pipeh, req, 0))
	    != USB_SUCCESS) {

		ral_debug(RAL_DBG_ERR, "rum_tx_trigger(): "
		    "failed to do tx xfer, %d", err);
		usb_free_bulk_req(req);
		return (-1);
	}

	sc->tx_queued++;

	return (0);
}

static int
rum_rx_trigger(struct rum_softc *sc)
{
	usb_bulk_req_t *req;
	int err;

	req = usb_alloc_bulk_req(sc->sc_dev, RAL_RXBUF_SIZE, USB_FLAGS_SLEEP);
	if (req == NULL) {
		ral_debug(RAL_DBG_ERR,
		    "rum_rx_trigger(): failed to allocate req");
		return (-1);
	}

	req->bulk_len		= RAL_RXBUF_SIZE;
	req->bulk_client_private = (usb_opaque_t)sc;
	req->bulk_timeout	= 0;
	req->bulk_attributes	= USB_ATTRS_SHORT_XFER_OK
	    | USB_ATTRS_AUTOCLEARING;
	req->bulk_cb		= rum_rxeof;
	req->bulk_exc_cb	= rum_rxeof;
	req->bulk_completion_reason = 0;
	req->bulk_cb_flags	= 0;

	err = usb_pipe_bulk_xfer(sc->sc_rx_pipeh, req, 0);

	if (err != USB_SUCCESS) {
		ral_debug(RAL_DBG_ERR, "rum_rx_trigger(): "
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
rum_init_tx_queue(struct rum_softc *sc)
{
	sc->tx_queued = 0;
}

static int
rum_init_rx_queue(struct rum_softc *sc)
{
	int	i;

	sc->rx_queued = 0;

	for (i = 0; i < RAL_RX_LIST_COUNT; i++) {
		if (rum_rx_trigger(sc) != 0) {
			return (USB_FAILURE);
		}
	}

	return (USB_SUCCESS);
}

static void
rum_stop(struct rum_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	uint32_t tmp;

	ieee80211_new_state(ic, IEEE80211_S_INIT, -1);
	ieee80211_stop_watchdog(ic);	/* stop the watchdog */

	RAL_LOCK(sc);

	sc->sc_tx_timer = 0;
	sc->sc_flags &= ~RAL_FLAG_RUNNING;	/* STOP */

	/* disable Rx */
	tmp = rum_read(sc, RT2573_TXRX_CSR0);
	rum_write(sc, RT2573_TXRX_CSR0, tmp | RT2573_DISABLE_RX);

	/* reset ASIC */
	rum_write(sc, RT2573_MAC_CSR1, 3);
	rum_write(sc, RT2573_MAC_CSR1, 0);

	rum_close_pipes(sc);

	RAL_UNLOCK(sc);
}

static int
rum_init(struct rum_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	uint32_t tmp;
	int i, ntries;

	rum_stop(sc);

	/* initialize MAC registers to default values */
	for (i = 0; i < RUM_N(rum_def_mac); i++)
		rum_write(sc, rum_def_mac[i].reg, rum_def_mac[i].val);

	/* set host ready */
	rum_write(sc, RT2573_MAC_CSR1, 3);
	rum_write(sc, RT2573_MAC_CSR1, 0);

	/* wait for BBP/RF to wakeup */
	for (ntries = 0; ntries < 1000; ntries++) {
		if (rum_read(sc, RT2573_MAC_CSR12) & 8)
			break;
		rum_write(sc, RT2573_MAC_CSR12, 4);	/* force wakeup */
		drv_usecwait(1000);
	}
	if (ntries == 1000) {
		ral_debug(RAL_DBG_ERR,
		    "rum_init(): timeout waiting for BBP/RF to wakeup\n");
		goto fail;
	}

	if (rum_bbp_init(sc) != 0)
		goto fail;

	/* select default channel */
	rum_select_band(sc, ic->ic_curchan);
	rum_select_antenna(sc);
	rum_set_chan(sc, ic->ic_curchan);

	/* clear STA registers */
	rum_read_multi(sc, RT2573_STA_CSR0, sc->sta, sizeof (sc->sta));

	rum_set_macaddr(sc, ic->ic_macaddr);

	/* initialize ASIC */
	rum_write(sc, RT2573_MAC_CSR1, 4);

	if (rum_open_pipes(sc) != USB_SUCCESS) {
		ral_debug(RAL_DBG_ERR, "rum_init(): "
		    "could not open pipes.\n");
		goto fail;
	}

	rum_init_tx_queue(sc);

	if (rum_init_rx_queue(sc) != USB_SUCCESS)
		goto fail;

	/* update Rx filter */
	tmp = rum_read(sc, RT2573_TXRX_CSR0) & 0xffff;
	tmp |= RT2573_DROP_PHY_ERROR | RT2573_DROP_CRC_ERROR;
	if (ic->ic_opmode != IEEE80211_M_MONITOR) {
		tmp |= RT2573_DROP_CTL | RT2573_DROP_VER_ERROR |
		    RT2573_DROP_ACKCTS;
		if (ic->ic_opmode != IEEE80211_M_HOSTAP)
			tmp |= RT2573_DROP_TODS;
		if (!(sc->sc_rcr & RAL_RCR_PROMISC))
			tmp |= RT2573_DROP_NOT_TO_ME;
	}

	rum_write(sc, RT2573_TXRX_CSR0, tmp);
	sc->sc_flags |= RAL_FLAG_RUNNING;	/* RUNNING */

	return (DDI_SUCCESS);
fail:
	rum_stop(sc);
	return (DDI_FAILURE);
}

static int
rum_disconnect(dev_info_t *devinfo)
{
	struct rum_softc *sc;
	struct ieee80211com *ic;

	/*
	 * We can't call rum_stop() here, since the hardware is removed,
	 * we can't access the register anymore.
	 */
	sc = ddi_get_soft_state(rum_soft_state_p, ddi_get_instance(devinfo));
	ASSERT(sc != NULL);

	if (!RAL_IS_RUNNING(sc))	/* different device or not inited */
		return (DDI_SUCCESS);

	ic = &sc->sc_ic;
	ieee80211_new_state(ic, IEEE80211_S_INIT, -1);
	ieee80211_stop_watchdog(ic);	/* stop the watchdog */

	RAL_LOCK(sc);

	sc->sc_tx_timer = 0;
	sc->sc_flags &= ~RAL_FLAG_RUNNING;	/* STOP */

	rum_close_pipes(sc);

	RAL_UNLOCK(sc);

	return (DDI_SUCCESS);
}

static int
rum_reconnect(dev_info_t *devinfo)
{
	struct rum_softc *sc;
	int err;

	sc = ddi_get_soft_state(rum_soft_state_p, ddi_get_instance(devinfo));
	ASSERT(sc != NULL);

	/* check device changes after disconnect */
	if (usb_check_same_device(sc->sc_dev, NULL, USB_LOG_L2, -1,
	    USB_CHK_BASIC | USB_CHK_CFG, NULL) != USB_SUCCESS) {
		ral_debug(RAL_DBG_ERR, "different device connected\n");
		return (DDI_FAILURE);
	}

	err = rum_load_microcode(sc);
	if (err != USB_SUCCESS) {
		ral_debug(RAL_DBG_ERR, "could not load 8051 microcode\n");
		goto fail;
	}

	err = rum_init(sc);
fail:
	return (err);
}

static void
rum_resume(struct rum_softc *sc)
{
	int err;

	/* check device changes after suspend */
	if (usb_check_same_device(sc->sc_dev, NULL, USB_LOG_L2, -1,
	    USB_CHK_BASIC | USB_CHK_CFG, NULL) != USB_SUCCESS) {
		ral_debug(RAL_DBG_ERR, "no or different device connected\n");
		return;
	}

	err = rum_load_microcode(sc);
	if (err != USB_SUCCESS) {
		ral_debug(RAL_DBG_ERR, "could not load 8051 microcode\n");
		return;
	}

	(void) rum_init(sc);
}

#define	RUM_AMRR_MIN_SUCCESS_THRESHOLD	1
#define	RUM_AMRR_MAX_SUCCESS_THRESHOLD	10

/*
 * Naive implementation of the Adaptive Multi Rate Retry algorithm:
 * "IEEE 802.11 Rate Adaptation: A Practical Approach"
 * Mathieu Lacage, Hossein Manshaei, Thierry Turletti
 * INRIA Sophia - Projet Planete
 * http://www-sop.inria.fr/rapports/sophia/RR-5208.html
 *
 * This algorithm is particularly well suited for rum since it does not
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
rum_ratectl(struct rum_amrr *amrr, struct ieee80211_node *ni)
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
				    RUM_AMRR_MAX_SUCCESS_THRESHOLD)
					amrr->success_threshold =
					    RUM_AMRR_MAX_SUCCESS_THRESHOLD;
			} else {
				amrr->success_threshold =
				    RUM_AMRR_MIN_SUCCESS_THRESHOLD;
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
rum_amrr_timeout(void *arg)
{
	struct rum_softc *sc = (struct rum_softc *)arg;
	struct rum_amrr *amrr = &sc->amrr;

	rum_read_multi(sc, RT2573_STA_CSR0, sc->sta, sizeof (sc->sta));

	/* count TX retry-fail as Tx errors */
	sc->sc_tx_err += LE_32(sc->sta[5]) >> 16;
	sc->sc_tx_retries += ((LE_32(sc->sta[4]) >> 16) +
	    (LE_32(sc->sta[5]) & 0xffff));

	amrr->retrycnt =
	    (LE_32(sc->sta[4]) >> 16) +		/* TX one-retry ok count */
	    (LE_32(sc->sta[5]) & 0xffff) +	/* TX more-retry ok count */
	    (LE_32(sc->sta[5]) >> 16);		/* TX retry-fail count */

	amrr->txcnt =
	    amrr->retrycnt +
	    (LE_32(sc->sta[4]) & 0xffff);	/* TX no-retry ok count */

	rum_ratectl(amrr, sc->sc_ic.ic_bss);

	sc->sc_amrr_id = timeout(rum_amrr_timeout, (void *)sc,
	    drv_usectohz(1000 * 1000)); /* 1 second */
}

static void
rum_amrr_start(struct rum_softc *sc, struct ieee80211_node *ni)
{
	struct rum_amrr *amrr = &sc->amrr;
	int i;

	/* clear statistic registers (STA_CSR0 to STA_CSR5) */
	rum_read_multi(sc, RT2573_STA_CSR0, sc->sta, sizeof (sc->sta));

	amrr->success = 0;
	amrr->recovery = 0;
	amrr->txcnt = amrr->retrycnt = 0;
	amrr->success_threshold = RUM_AMRR_MIN_SUCCESS_THRESHOLD;

	/* set rate to some reasonable initial value */
	for (i = ni->in_rates.ir_nrates - 1;
	    i > 0 && (ni->in_rates.ir_rates[i] & IEEE80211_RATE_VAL) > 72;
	    i--) {
	}

	ni->in_txrate = i;

	sc->sc_amrr_id = timeout(rum_amrr_timeout, (void *)sc,
	    drv_usectohz(1000 * 1000)); /* 1 second */
}

void
rum_watchdog(void *arg)
{
	struct rum_softc *sc = arg;
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
			(void) rum_init(sc);
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
rum_m_start(void *arg)
{
	struct rum_softc *sc = (struct rum_softc *)arg;
	int err;

	/*
	 * initialize RT2501USB hardware
	 */
	err = rum_init(sc);
	if (err != DDI_SUCCESS) {
		ral_debug(RAL_DBG_ERR, "device configuration failed\n");
		goto fail;
	}
	sc->sc_flags |= RAL_FLAG_RUNNING;	/* RUNNING */
	return (err);

fail:
	rum_stop(sc);
	return (err);
}

static void
rum_m_stop(void *arg)
{
	struct rum_softc *sc = (struct rum_softc *)arg;

	(void) rum_stop(sc);
	sc->sc_flags &= ~RAL_FLAG_RUNNING;	/* STOP */
}

static int
rum_m_unicst(void *arg, const uint8_t *macaddr)
{
	struct rum_softc *sc = (struct rum_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;

	ral_debug(RAL_DBG_MSG, "rum_m_unicst(): " MACSTR "\n",
	    MAC2STR(macaddr));

	IEEE80211_ADDR_COPY(ic->ic_macaddr, macaddr);
	(void) rum_set_macaddr(sc, (uint8_t *)macaddr);
	(void) rum_init(sc);

	return (0);
}

/*ARGSUSED*/
static int
rum_m_multicst(void *arg, boolean_t add, const uint8_t *mca)
{
	return (0);
}

static int
rum_m_promisc(void *arg, boolean_t on)
{
	struct rum_softc *sc = (struct rum_softc *)arg;

	if (on) {
		sc->sc_rcr |= RAL_RCR_PROMISC;
		sc->sc_rcr |= RAL_RCR_MULTI;
	} else {
		sc->sc_rcr &= ~RAL_RCR_PROMISC;
		sc->sc_rcr &= ~RAL_RCR_MULTI;
	}

	rum_update_promisc(sc);
	return (0);
}

/*
 * callback functions for /get/set properties
 */
static int
rum_m_setprop(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    uint_t wldp_length, const void *wldp_buf)
{
	struct rum_softc *sc = (struct rum_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;
	int err;

	err = ieee80211_setprop(ic, pr_name, wldp_pr_num,
	    wldp_length, wldp_buf);
	RAL_LOCK(sc);
	if (err == ENETRESET) {
		if (RAL_IS_RUNNING(sc)) {
			RAL_UNLOCK(sc);
			(void) rum_init(sc);
			(void) ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
			RAL_LOCK(sc);
		}
		err = 0;
	}
	RAL_UNLOCK(sc);

	return (err);
}

static int
rum_m_getprop(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    uint_t wldp_length, void *wldp_buf)
{
	struct rum_softc *sc = (struct rum_softc *)arg;
	int err;

	err = ieee80211_getprop(&sc->sc_ic, pr_name, wldp_pr_num,
	    wldp_length, wldp_buf);

	return (err);
}

static void
rum_m_propinfo(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    mac_prop_info_handle_t prh)
{
	struct rum_softc *sc = (struct rum_softc *)arg;

	ieee80211_propinfo(&sc->sc_ic, pr_name, wldp_pr_num, prh);
}

static void
rum_m_ioctl(void* arg, queue_t *wq, mblk_t *mp)
{
	struct rum_softc *sc = (struct rum_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;
	int err;

	err = ieee80211_ioctl(ic, wq, mp);
	RAL_LOCK(sc);
	if (err == ENETRESET) {
		if (RAL_IS_RUNNING(sc)) {
			RAL_UNLOCK(sc);
			(void) rum_init(sc);
			(void) ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
			RAL_LOCK(sc);
		}
	}
	RAL_UNLOCK(sc);
}

static int
rum_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	struct rum_softc *sc  = (struct rum_softc *)arg;
	ieee80211com_t	*ic = &sc->sc_ic;
	ieee80211_node_t *ni;
	struct ieee80211_rateset *rs;

	RAL_LOCK(sc);

	ni = ic->ic_bss;
	rs = &ni->in_rates;

	switch (stat) {
	case MAC_STAT_IFSPEED:
		*val = ((ic->ic_fixed_rate == IEEE80211_FIXED_RATE_NONE) ?
		    (rs->ir_rates[ni->in_txrate] & IEEE80211_RATE_VAL)
		    : ic->ic_fixed_rate) * 500000ull;
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
rum_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	struct rum_softc *sc;
	struct ieee80211com *ic;
	int err, i, ntries;
	uint32_t tmp;
	int instance;

	char strbuf[32];

	wifi_data_t wd = { 0 };
	mac_register_t *macp;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		sc = ddi_get_soft_state(rum_soft_state_p,
		    ddi_get_instance(devinfo));
		ASSERT(sc != NULL);
		rum_resume(sc);
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(devinfo);

	if (ddi_soft_state_zalloc(rum_soft_state_p, instance) != DDI_SUCCESS) {
		ral_debug(RAL_DBG_MSG, "rum_attach(): "
		    "unable to alloc soft_state_p\n");
		return (DDI_FAILURE);
	}

	sc = ddi_get_soft_state(rum_soft_state_p, instance);
	ic = (ieee80211com_t *)&sc->sc_ic;
	sc->sc_dev = devinfo;

	if (usb_client_attach(devinfo, USBDRV_VERSION, 0) != USB_SUCCESS) {
		ral_debug(RAL_DBG_ERR,
		    "rum_attach(): usb_client_attach failed\n");
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

	/* retrieve RT2573 rev. no */
	for (ntries = 0; ntries < 1000; ntries++) {
		if ((tmp = rum_read(sc, RT2573_MAC_CSR0)) != 0)
			break;
		drv_usecwait(1000);
	}
	if (ntries == 1000) {
		ral_debug(RAL_DBG_ERR,
		    "rum_attach(): timeout waiting for chip to settle\n");
		goto fail3;
	}

	/* retrieve MAC address and various other things from EEPROM */
	rum_read_eeprom(sc);

	ral_debug(RAL_DBG_MSG, "rum: MAC/BBP RT2573 (rev 0x%05x), RF %s\n",
	    tmp, rum_get_rf(sc->rf_rev));

	err = rum_load_microcode(sc);
	if (err != USB_SUCCESS) {
		ral_debug(RAL_DBG_ERR, "could not load 8051 microcode\n");
		goto fail3;
	}

	ic->ic_phytype = IEEE80211_T_OFDM;	/* not only, but not used */
	ic->ic_opmode = IEEE80211_M_STA;	/* default to BSS mode */
	ic->ic_state = IEEE80211_S_INIT;

	ic->ic_maxrssi = 63;
	ic->ic_set_shortslot = rum_update_slot;
	ic->ic_xmit = rum_send;

	/* set device capabilities */
	ic->ic_caps =
	    IEEE80211_C_TXPMGT |	/* tx power management */
	    IEEE80211_C_SHPREAMBLE |	/* short preamble supported */
	    IEEE80211_C_SHSLOT;		/* short slot time supported */

	ic->ic_caps |= IEEE80211_C_WPA; /* Support WPA/WPA2 */

#define	IEEE80211_CHAN_A	\
	(IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_OFDM)

	if (sc->rf_rev == RT2573_RF_5225 || sc->rf_rev == RT2573_RF_5226) {
		/* set supported .11a rates */
		ic->ic_sup_rates[IEEE80211_MODE_11A] = rum_rateset_11a;

		/* set supported .11a channels */
		for (i = 34; i <= 46; i += 4) {
			ic->ic_sup_channels[i].ich_freq =
			    ieee80211_ieee2mhz(i, IEEE80211_CHAN_5GHZ);
			ic->ic_sup_channels[i].ich_flags = IEEE80211_CHAN_A;
		}
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
		for (i = 149; i <= 165; i += 4) {
			ic->ic_sup_channels[i].ich_freq =
			    ieee80211_ieee2mhz(i, IEEE80211_CHAN_5GHZ);
			ic->ic_sup_channels[i].ich_flags = IEEE80211_CHAN_A;
		}
	}

	/* set supported .11b and .11g rates */
	ic->ic_sup_rates[IEEE80211_MODE_11B] = rum_rateset_11b;
	ic->ic_sup_rates[IEEE80211_MODE_11G] = rum_rateset_11g;

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
	ic->ic_newstate = rum_newstate;
	ic->ic_watchdog = rum_watchdog;
	ieee80211_media_init(ic);
	ic->ic_def_txkey = 0;

	sc->sc_rcr = 0;
	sc->dwelltime = 300;
	sc->sc_flags = 0;

	/*
	 * Provide initial settings for the WiFi plugin; whenever this
	 * information changes, we need to call mac_plugindata_update()
	 */
	wd.wd_opmode = ic->ic_opmode;
	wd.wd_secalloc = WIFI_SEC_NONE;
	IEEE80211_ADDR_COPY(wd.wd_bssid, ic->ic_bss->in_bssid);

	if ((macp = mac_alloc(MAC_VERSION)) == NULL) {
		ral_debug(RAL_DBG_ERR, "rum_attach(): "
		    "MAC version mismatch\n");
		goto fail3;
	}

	macp->m_type_ident	= MAC_PLUGIN_IDENT_WIFI;
	macp->m_driver		= sc;
	macp->m_dip		= devinfo;
	macp->m_src_addr	= ic->ic_macaddr;
	macp->m_callbacks	= &rum_m_callbacks;
	macp->m_min_sdu		= 0;
	macp->m_max_sdu		= IEEE80211_MTU;
	macp->m_pdata		= &wd;
	macp->m_pdata_size	= sizeof (wd);

	err = mac_register(macp, &ic->ic_mach);
	mac_free(macp);
	if (err != 0) {
		ral_debug(RAL_DBG_ERR, "rum_attach(): "
		    "mac_register() err %x\n", err);
		goto fail3;
	}

	if (usb_register_hotplug_cbs(devinfo, rum_disconnect,
	    rum_reconnect) != USB_SUCCESS) {
		ral_debug(RAL_DBG_ERR,
		    "rum_attach() failed to register events");
		goto fail4;
	}

	/*
	 * Create minor node of type DDI_NT_NET_WIFI
	 */
	(void) snprintf(strbuf, sizeof (strbuf), "%s%d",
	    "rum", instance);
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
	ddi_soft_state_free(rum_soft_state_p, ddi_get_instance(devinfo));

	return (DDI_FAILURE);
}

static int
rum_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd)
{
	struct rum_softc *sc;

	sc = ddi_get_soft_state(rum_soft_state_p, ddi_get_instance(devinfo));
	ASSERT(sc != NULL);

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		if (RAL_IS_RUNNING(sc))
			(void) rum_stop(sc);
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	rum_stop(sc);
	usb_unregister_hotplug_cbs(devinfo);

	/*
	 * Unregister from the MAC layer subsystem
	 */
	if (mac_unregister(sc->sc_ic.ic_mach) != 0)
		return (DDI_FAILURE);

	/*
	 * detach ieee80211 layer
	 */
	ieee80211_detach(&sc->sc_ic);

	mutex_destroy(&sc->sc_genlock);
	mutex_destroy(&sc->tx_lock);
	mutex_destroy(&sc->rx_lock);

	/* pipes will be closed in rum_stop() */
	usb_client_detach(devinfo, sc->sc_udev);
	sc->sc_udev = NULL;

	ddi_remove_minor_node(devinfo, NULL);
	ddi_soft_state_free(rum_soft_state_p, ddi_get_instance(devinfo));

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

	status = ddi_soft_state_init(&rum_soft_state_p,
	    sizeof (struct rum_softc), 1);
	if (status != 0)
		return (status);

	mac_init_ops(&rum_dev_ops, "rum");
	status = mod_install(&modlinkage);
	if (status != 0) {
		mac_fini_ops(&rum_dev_ops);
		ddi_soft_state_fini(&rum_soft_state_p);
	}
	return (status);
}

int
_fini(void)
{
	int status;

	status = mod_remove(&modlinkage);
	if (status == 0) {
		mac_fini_ops(&rum_dev_ops);
		ddi_soft_state_fini(&rum_soft_state_p);
	}
	return (status);
}
