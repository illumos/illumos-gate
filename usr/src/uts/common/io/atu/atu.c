/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2003, 2004
 *	Daan Vreeken <Danovitsch@Vitsch.net>.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by Daan Vreeken.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY Daan Vreeken AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL Daan Vreeken OR THE VOICES IN HIS HEAD
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Atmel AT76c503 / AT76c503a / AT76c505 / AT76c505a  USB WLAN driver
 *
 * Originally written by Daan Vreeken <Danovitsch @ Vitsch . net>
 *  http://vitsch.net/bsd/atuwi
 *
 * Contributed to by :
 *  Chris Whitehouse, Alistair Phillips, Peter Pilka, Martijn van Buul,
 *  Suihong Liang, Arjan van Leeuwen, Stuart Walsh
 *
 * Ported to OpenBSD by Theo de Raadt and David Gwynne.
 */

#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/mac_provider.h>
#include <sys/mac_wifi.h>
#include <sys/net80211.h>
#define	USBDRV_MAJOR_VER	2
#define	USBDRV_MINOR_VER	0
#include <sys/usb/usba.h>
#include <sys/usb/usba/usba_types.h>

#include "fw/atmel_rfmd.hex"
#include "fw/atmel_rfmd2958.hex"
#include "fw/atmel_rfmd2958-smc.hex"
#include "fw/atmel_intersil.hex"
#include "fw/atmel_at76c505_rfmd.hex"
#include "fw/atmel_at76c503_rfmd_acc.hex"
#include "fw/atmel_at76c503_i3863.hex"
#include "atu.h"

static void *atu_soft_state_p;
static mac_callbacks_t	atu_m_callbacks;
static const struct ieee80211_rateset atu_rateset = {4, {2, 4, 11, 22}};

static int
atu_usb_request(struct atu_softc *sc, uint8_t type,
    uint8_t request, uint16_t value, uint16_t index, uint16_t length,
    uint8_t *data)
{
	usb_ctrl_setup_t	req;
	usb_cb_flags_t		cf;
	usb_cr_t		cr;
	mblk_t			*mp = NULL;
	int			uret = USB_SUCCESS;

	bzero(&req, sizeof (req));
	req.bmRequestType = type;
	req.bRequest = request;
	req.wValue = value;
	req.wIndex = index;
	req.wLength = length;
	req.attrs = USB_ATTRS_NONE;

	if (type & USB_DEV_REQ_DEV_TO_HOST) {
		req.attrs = USB_ATTRS_AUTOCLEARING;
		uret = usb_pipe_ctrl_xfer_wait(sc->sc_udev->dev_default_ph,
		    &req, &mp, &cr, &cf, 0);
		if (mp == NULL)
			return (EIO);

		if (uret == USB_SUCCESS)
			bcopy(mp->b_rptr, data, length);
	} else {
		if ((mp = allocb(length, BPRI_HI)) == NULL)
			return (ENOMEM);

		bcopy(data, mp->b_wptr, length);
		mp->b_wptr += length;
		uret = usb_pipe_ctrl_xfer_wait(sc->sc_udev->dev_default_ph,
		    &req, &mp, &cr, &cf, 0);
	}

	if (mp)
		freemsg(mp);

	return (uret == USB_SUCCESS ? 0 : EIO);
}

static int
atu_get_mib(struct atu_softc *sc, uint8_t type, uint8_t size,
    uint8_t index, uint8_t *buf)
{
	return atu_usb_request(sc, ATU_VENDOR_IF_IN, 0x033,
	    type << 8, index, size, buf);
}

static int
atu_get_cmd_status(struct atu_softc *sc, uint8_t cmd, uint8_t *status)
{
	/*
	 * all other drivers (including Windoze) request 40 bytes of status
	 * and get a short-xfer of just 6 bytes. we can save 34 bytes of
	 * buffer if we just request those 6 bytes in the first place :)
	 */
	return atu_usb_request(sc, ATU_VENDOR_IF_IN, 0x22, cmd,
	    0x0000, 6, status);
}

static uint8_t
atu_get_dfu_state(struct atu_softc *sc)
{
	uint8_t	state;

	if (atu_usb_request(sc, DFU_GETSTATE, 0, 0, 1, &state))
		return (DFUState_DFUError);
	return (state);
}

static int
atu_get_opmode(struct atu_softc *sc, uint8_t *mode)
{
	return atu_usb_request(sc, ATU_VENDOR_IF_IN, 0x33, 0x0001,
	    0x0000, 1, mode);
}

static int
atu_get_config(struct atu_softc *sc)
{
	struct ieee80211com	*ic = &sc->sc_ic;
	struct atu_rfmd_conf	rfmd_conf;
	struct atu_intersil_conf intersil_conf;
	int			err;

	switch (sc->sc_radio) {
	case RadioRFMD:
	case RadioRFMD2958:
	case RadioRFMD2958_SMC:
	case AT76C503_RFMD_ACC:
	case AT76C505_RFMD:
		err = atu_usb_request(sc, ATU_VENDOR_IF_IN, 0x33, 0x0a02,
		    0x0000, sizeof (rfmd_conf), (uint8_t *)&rfmd_conf);
		if (err) {
			cmn_err(CE_WARN, "%s: get RFMD config failed\n",
			    sc->sc_name);
			return (err);
		}
		bcopy(rfmd_conf.MACAddr, ic->ic_macaddr, IEEE80211_ADDR_LEN);
		break;

	case RadioIntersil:
	case AT76C503_i3863:
		err = atu_usb_request(sc, ATU_VENDOR_IF_IN, 0x33, 0x0902,
		    0x0000, sizeof (intersil_conf), (uint8_t *)&intersil_conf);
		if (err) {
			cmn_err(CE_WARN, "%s: get Intersil config failed\n",
			    sc->sc_name);
			return (err);
		}
		bcopy(intersil_conf.MACAddr, ic->ic_macaddr,
		    IEEE80211_ADDR_LEN);
		break;
	}

	return (0);
}

static int
atu_wait_completion(struct atu_softc *sc, uint8_t cmd, uint8_t *status)
{
	uint8_t	statusreq[6];
	int	idle_count = 0, err;

	while ((err = atu_get_cmd_status(sc, cmd, statusreq)) == 0) {

		if ((statusreq[5] != STATUS_IN_PROGRESS) &&
		    (statusreq[5] != STATUS_IDLE)) {
			if (status != NULL)
				*status = statusreq[5];
			return (0);
		} else if (idle_count++ > 60) {
			cmn_err(CE_WARN, "%s: command (0x%02x) timeout\n",
			    sc->sc_name, cmd);
			return (ETIME);
		}

		drv_usecwait(10 * 1000);
	}

	return (err);
}

static int
atu_send_command(struct atu_softc *sc, uint8_t *command, int size)
{
	return atu_usb_request(sc, ATU_VENDOR_DEV_OUT, 0x0e, 0x0000,
	    0x0000, size, command);
}

static int
atu_send_mib(struct atu_softc *sc, uint8_t type, uint8_t size,
    uint8_t index, void *data)
{
	struct atu_cmd_set_mib	request;
	int err;

	bzero(&request, sizeof (request));
	request.AtCmd = CMD_SET_MIB;
	request.AtSize = size + 4;
	request.MIBType = type;
	request.MIBSize = size;
	request.MIBIndex = index;
	request.MIBReserved = 0;

	/*
	 * For 1 and 2 byte requests we assume a direct value,
	 * everything bigger than 2 bytes we assume a pointer to the data
	 */
	switch (size) {
	case 0:
		break;
	case 1:
		request.data[0] = (long)data & 0x000000ff;
		break;
	case 2:
		request.data[0] = (long)data & 0x000000ff;
		request.data[1] = (long)data >> 8;
		break;
	default:
		bcopy(data, request.data, size);
		break;
	}

	err = atu_usb_request(sc, ATU_VENDOR_DEV_OUT, 0x0e, 0x0000,
	    0x0000, size+8, (uint8_t *)&request);
	if (err)
		return (err);

	return (atu_wait_completion(sc, CMD_SET_MIB, NULL));
}

static int
atu_switch_radio(struct atu_softc *sc, boolean_t on)
{
	struct atu_cmd	radio;
	boolean_t	ostate;
	int		err;

	/* Intersil doesn't seem to support radio switch */
	if (sc->sc_radio == RadioIntersil)
		return (0);

	ostate = ATU_RADIO_ON(sc) ? B_TRUE : B_FALSE;
	if (on != ostate) {
		bzero(&radio, sizeof (radio));
		radio.Cmd = on ? CMD_RADIO_ON : CMD_RADIO_OFF;

		err = atu_send_command(sc, (uint8_t *)&radio,
		    sizeof (radio));
		if (err)
			return (err);

		err = atu_wait_completion(sc, radio.Cmd, NULL);
		if (err)
			return (err);

		if (on)
			sc->sc_flags |= ATU_FLAG_RADIO_ON;
		else
			sc->sc_flags &= ~ATU_FLAG_RADIO_ON;
	}

	return (0);
}

static int
atu_config(struct atu_softc *sc)
{
	struct ieee80211com		*ic = &sc->sc_ic;
	struct ieee80211_key		*k;
	struct atu_cmd_card_config	cmd;
	uint8_t				rates[4] = {0x82, 0x84, 0x8B, 0x96};
	int				err, i;

	err = atu_send_mib(sc, MIB_MAC_ADDR_STA, ic->ic_macaddr);
	if (err) {
		cmn_err(CE_WARN, "%s: setting MAC address failed\n",
		    sc->sc_name);
		return (err);
	}

	bzero(&cmd, sizeof (cmd));
	cmd.Cmd = CMD_STARTUP;
	cmd.Reserved = 0;
	cmd.Size = sizeof (cmd) - 4;
	cmd.Channel = ATU_DEF_CHAN;
	cmd.ShortRetryLimit = 7;
	cmd.RTS_Threshold = 2347;
	cmd.FragThreshold = 2346;
	cmd.PromiscuousMode = 1;
	cmd.AutoRateFallback = 1;
	bcopy(rates, cmd.BasicRateSet, 4);

	if (ic->ic_flags & IEEE80211_F_PRIVACY) {
		k = ic->ic_nw_keys + ic->ic_def_txkey;
		switch (k->wk_keylen) {
		case 5:
			cmd.EncryptionType = ATU_ENC_WEP40;
			break;
		case 13:
			cmd.EncryptionType = ATU_ENC_WEP104;
			break;
		default:
			cmn_err(CE_WARN, "%s: key invalid (%d bytes)\n",
			    sc->sc_name, k->wk_keylen);
			goto nowep;
		}
		cmd.PrivacyInvoked = 1;
		cmd.ExcludeUnencrypted = 1;
		cmd.WEP_DefaultKeyID = ic->ic_def_txkey;
		for (i = 0; i < IEEE80211_WEP_NKID; i++) {
			k = ic->ic_nw_keys + i;
			if (k->wk_keylen == 0)
				continue;
			bcopy(k->wk_key, cmd.WEP_DefaultKey + i, k->wk_keylen);
		}
	} else {
nowep:
		cmd.EncryptionType = ATU_ENC_NONE;
	}

	bcopy(ic->ic_des_essid, cmd.SSID, ic->ic_des_esslen);
	cmd.SSID_Len = ic->ic_des_esslen;
	cmd.BeaconPeriod = 100;

	err = atu_send_command(sc, (uint8_t *)&cmd, sizeof (cmd));
	if (err)
		return (err);
	err = atu_wait_completion(sc, CMD_STARTUP, NULL);
	if (err)
		return (err);

	err = atu_switch_radio(sc, B_TRUE);
	if (err)
		return (err);

	err = atu_send_mib(sc, MIB_MAC_MGMT_POWER_MODE,
	    (void *)ATU_POWER_ACTIVE);
	if (err)
		return (err);

	return (0);
}

static int
atu_start_scan(struct atu_softc *sc)
{
	struct ieee80211com	*ic = &sc->sc_ic;
	struct atu_cmd_do_scan	scan;
	int			err;

	if (!ATU_RUNNING(sc))
		return (EIO);

	bzero(&scan, sizeof (scan));
	scan.Cmd = CMD_START_SCAN;
	scan.Reserved = 0;
	scan.Size = sizeof (scan) - 4;
	(void) memset(scan.BSSID, 0xff, sizeof (scan.BSSID));
	bcopy(ic->ic_des_essid, scan.SSID, ic->ic_des_esslen);
	scan.SSID_Len = ic->ic_des_esslen;
	scan.ScanType = ATU_SCAN_ACTIVE;
	scan.Channel = ieee80211_chan2ieee(ic, ic->ic_curchan);
	scan.ProbeDelay = 0;
	scan.MinChannelTime = 20;
	scan.MaxChannelTime = 40;
	scan.InternationalScan = 0;

	err = atu_send_command(sc, (uint8_t *)&scan, sizeof (scan));
	if (err) {
		cmn_err(CE_WARN, "%s: SCAN command failed\n",
		    sc->sc_name);
		return (err);
	}

	err = atu_wait_completion(sc, CMD_START_SCAN, NULL);
	if (err) {
		cmn_err(CE_WARN, "%s: SCAN completion failed\n",
		    sc->sc_name);
		return (err);
	}

	return (0);
}

static int
atu_join(struct atu_softc *sc, struct ieee80211_node *node)
{
	struct atu_cmd_join	join;
	uint8_t			status;
	int			err;

	bzero(&join, sizeof (join));
	join.Cmd = CMD_JOIN;
	join.Reserved = 0x00;
	join.Size = sizeof (join) - 4;
	bcopy(node->in_bssid, join.bssid, IEEE80211_ADDR_LEN);
	bcopy(node->in_essid, join.essid, node->in_esslen);
	join.essid_size = node->in_esslen;

	if (node->in_capinfo & IEEE80211_CAPINFO_IBSS)
		join.bss_type = ATU_MODE_IBSS;
	else
		join.bss_type = ATU_MODE_STA;

	join.channel = ieee80211_chan2ieee(&sc->sc_ic, node->in_chan);
	join.timeout = ATU_JOIN_TIMEOUT;
	join.reserved = 0x00;

	err = atu_send_command(sc, (uint8_t *)&join, sizeof (join));
	if (err) {
		cmn_err(CE_WARN, "%s: JOIN command failed\n",
		    sc->sc_name);
		return (err);
	}
	err = atu_wait_completion(sc, CMD_JOIN, &status);
	if (err)
		return (err);

	if (status != STATUS_COMPLETE) {
		cmn_err(CE_WARN, "%s: incorrect JOIN state (0x%02x)\n",
		    sc->sc_name, status);
		return (EIO);
	}

	return (0);
}

static int
atu_newstate(struct ieee80211com *ic, enum ieee80211_state nstate, int arg)
{
	struct atu_softc	*sc = (struct atu_softc *)ic;
	enum ieee80211_state	ostate = ic->ic_state;
	int			err = 0;

	ATU_LOCK(sc);

	if (sc->sc_scan_timer != 0) {
		ATU_UNLOCK(sc);
		(void) untimeout(sc->sc_scan_timer);
		ATU_LOCK(sc);
		sc->sc_scan_timer = 0;
	}
	ostate = ic->ic_state;

	switch (nstate) {
	case IEEE80211_S_SCAN:
		switch (ostate) {
			case IEEE80211_S_SCAN:
			case IEEE80211_S_AUTH:
			case IEEE80211_S_ASSOC:
			case IEEE80211_S_RUN:
				ATU_UNLOCK(sc);
				sc->sc_newstate(ic, nstate, arg);
				ATU_LOCK(sc);
				if ((err = atu_start_scan(sc)) != 0) {
					ATU_UNLOCK(sc);
					ieee80211_cancel_scan(ic);
					return (err);
				}
				sc->sc_scan_timer = timeout(
				    (void (*) (void*))ieee80211_next_scan,
				    (void *)&sc->sc_ic, 0);

				ATU_UNLOCK(sc);
				return (err);
			default:
				break;
		}
		break;

	case IEEE80211_S_AUTH:
		switch (ostate) {
		case IEEE80211_S_INIT:
		case IEEE80211_S_SCAN:
			err = atu_join(sc, ic->ic_bss);
			if (err) {
				ATU_UNLOCK(sc);
				return (err);
			}
			break;
		default:
			break;
		}
	default:
		break;
	}

	ATU_UNLOCK(sc);
	err = sc->sc_newstate(ic, nstate, arg);

	return (err);
}

static int
atu_open_pipes(struct atu_softc *sc)
{
	usb_ep_data_t		*ep;
	usb_pipe_policy_t	policy = {0};
	int			uret;

	ep = usb_lookup_ep_data(sc->sc_dip, sc->sc_udev, 0, 0, 0,
	    USB_EP_ATTR_BULK, USB_EP_DIR_OUT);
	policy.pp_max_async_reqs = ATU_TX_LIST_CNT;

	uret = usb_pipe_open(sc->sc_dip, &ep->ep_descr, &policy,
	    USB_FLAGS_SLEEP, &sc->sc_tx_pipe);
	if (uret != USB_SUCCESS)
		goto fail;

	ep = usb_lookup_ep_data(sc->sc_dip, sc->sc_udev, 0, 0, 0,
	    USB_EP_ATTR_BULK, USB_EP_DIR_IN);
	policy.pp_max_async_reqs = ATU_RX_LIST_CNT + 32;

	uret = usb_pipe_open(sc->sc_dip, &ep->ep_descr, &policy,
	    USB_FLAGS_SLEEP, &sc->sc_rx_pipe);
	if (uret != USB_SUCCESS)
		goto fail;

	return (0);
fail:
	if (sc->sc_rx_pipe != NULL) {
		usb_pipe_close(sc->sc_dip, sc->sc_rx_pipe,
		    USB_FLAGS_SLEEP, NULL, 0);
		sc->sc_rx_pipe = NULL;
	}

	if (sc->sc_tx_pipe != NULL) {
		usb_pipe_close(sc->sc_dip, sc->sc_tx_pipe,
		    USB_FLAGS_SLEEP, NULL, 0);
		sc->sc_tx_pipe = NULL;
	}

	return (EIO);
}

static void
atu_close_pipes(struct atu_softc *sc)
{
	usb_flags_t flags = USB_FLAGS_SLEEP;

	if (sc->sc_rx_pipe != NULL) {
		usb_pipe_reset(sc->sc_dip, sc->sc_rx_pipe, flags, NULL, 0);
		usb_pipe_close(sc->sc_dip, sc->sc_rx_pipe, flags, NULL, 0);
		sc->sc_rx_pipe = NULL;
	}

	if (sc->sc_tx_pipe != NULL) {
		usb_pipe_reset(sc->sc_dip, sc->sc_tx_pipe, flags, NULL, 0);
		usb_pipe_close(sc->sc_dip, sc->sc_tx_pipe, flags, NULL, 0);
		sc->sc_tx_pipe = NULL;
	}
}

static int atu_rx_trigger(struct atu_softc *sc);

/*ARGSUSED*/
static void
atu_rxeof(usb_pipe_handle_t pipe, usb_bulk_req_t *req)
{
	struct atu_softc *sc = (struct atu_softc *)req->bulk_client_private;
	struct ieee80211com	*ic = &sc->sc_ic;
	struct ieee80211_node	*ni;
	struct atu_rx_hdr	*h;
	struct ieee80211_frame	*wh;
	mblk_t			*mp = req->bulk_data;
	int			len, pktlen;

	req->bulk_data = NULL;
	if (req->bulk_completion_reason != USB_CR_OK) {
		sc->sc_rx_err++;
		goto fail;
	}

	len = msgdsize(mp);
	if (len < ATU_RX_HDRLEN + ATU_MIN_FRAMELEN) {
		cmn_err(CE_CONT, "%s: fragment (%d bytes)\n",
		    sc->sc_name, len);
		sc->sc_rx_err++;
		goto fail;
	}

	h = (struct atu_rx_hdr *)mp->b_rptr;
	pktlen = h->length - 4;
	if (pktlen + ATU_RX_HDRLEN + 4 != len) {
		cmn_err(CE_CONT, "%s: jumbo (%d bytes -> %d bytes)\n",
		    sc->sc_name, len, pktlen);
		sc->sc_rx_err++;
		goto fail;
	}

	mp->b_rptr += ATU_RX_HDRLEN;
	mp->b_wptr = mp->b_rptr + pktlen;
	wh = (struct ieee80211_frame *)mp->b_rptr;

	if (wh->i_fc[1] & IEEE80211_FC1_WEP)
		wh->i_fc[1] &= ~IEEE80211_FC1_WEP;

	ni = ieee80211_find_rxnode(ic, wh);
	(void) ieee80211_input(ic, mp, ni, h->rssi, h->rx_time);
	ieee80211_free_node(ni);
done:
	usb_free_bulk_req(req);

	mutex_enter(&sc->sc_rxlock);
	sc->rx_queued--;
	mutex_exit(&sc->sc_rxlock);

	if (ATU_RUNNING(sc))
		(void) atu_rx_trigger(sc);
	return;
fail:
	freemsg(mp);
	goto done;
}

/*ARGSUSED*/
static void
atu_txeof(usb_pipe_handle_t pipe, usb_bulk_req_t *req)
{
	struct atu_softc *sc = (struct atu_softc *)req->bulk_client_private;
	struct ieee80211com	*ic = &sc->sc_ic;

	if (req->bulk_completion_reason != USB_CR_OK)
		ic->ic_stats.is_tx_failed++;
	usb_free_bulk_req(req);

	mutex_enter(&sc->sc_txlock);
	sc->tx_queued--;

	if (sc->sc_need_sched) {
		sc->sc_need_sched = 0;
		mac_tx_update(ic->ic_mach);
	}

	mutex_exit(&sc->sc_txlock);
}

static int
atu_rx_trigger(struct atu_softc *sc)
{
	usb_bulk_req_t *req;
	int uret;

	req = usb_alloc_bulk_req(sc->sc_dip, ATU_RX_BUFSZ, USB_FLAGS_SLEEP);
	if (req == NULL)
		return (ENOMEM);

	req->bulk_len		= ATU_RX_BUFSZ;
	req->bulk_client_private = (usb_opaque_t)sc;
	req->bulk_timeout	= 0;
	req->bulk_attributes = USB_ATTRS_SHORT_XFER_OK | USB_ATTRS_AUTOCLEARING;
	req->bulk_cb		= atu_rxeof;
	req->bulk_exc_cb	= atu_rxeof;
	req->bulk_completion_reason = 0;
	req->bulk_cb_flags	= 0;

	uret = usb_pipe_bulk_xfer(sc->sc_rx_pipe, req, 0);
	if (uret != USB_SUCCESS) {
		usb_free_bulk_req(req);
		return (EIO);
	}

	mutex_enter(&sc->sc_rxlock);
	sc->rx_queued++;
	mutex_exit(&sc->sc_rxlock);

	return (0);
}

static int
atu_tx_trigger(struct atu_softc *sc, mblk_t *mp)
{
	usb_bulk_req_t *req;
	int uret;

	req = usb_alloc_bulk_req(sc->sc_dip, 0, USB_FLAGS_SLEEP);
	if (req == NULL)
		return (EIO);

	req->bulk_len		= msgdsize(mp);
	req->bulk_data		= mp;
	req->bulk_client_private = (usb_opaque_t)sc;
	req->bulk_timeout	= 10;
	req->bulk_attributes	= USB_ATTRS_AUTOCLEARING;
	req->bulk_cb		= atu_txeof;
	req->bulk_exc_cb	= atu_txeof;
	req->bulk_completion_reason = 0;
	req->bulk_cb_flags	= 0;

	uret = usb_pipe_bulk_xfer(sc->sc_tx_pipe, req, 0);
	if (uret != USB_SUCCESS) {
		req->bulk_data = NULL;
		usb_free_bulk_req(req);
		return (EIO);
	}

	mutex_enter(&sc->sc_txlock);
	sc->tx_queued++;
	mutex_exit(&sc->sc_txlock);

	return (0);
}

static int
atu_init_rx_queue(struct atu_softc *sc)
{
	int err, i;

	mutex_enter(&sc->sc_rxlock);
	sc->rx_queued = 0;
	mutex_exit(&sc->sc_rxlock);

	for (i = 0; i < ATU_RX_LIST_CNT; i++) {
		err = atu_rx_trigger(sc);
		if (err)
			return (err);
	}

	return (0);
}

static void
atu_init_tx_queue(struct atu_softc *sc)
{
	mutex_enter(&sc->sc_txlock);
	sc->tx_queued = 0;
	mutex_exit(&sc->sc_txlock);
}

static int
atu_send(ieee80211com_t *ic, mblk_t *mp, uint8_t type)
{
	struct atu_softc	*sc = (struct atu_softc *)ic;
	struct ieee80211_node	*ni = NULL;
	struct atu_tx_hdr	*desc;
	struct ieee80211_frame	*wh;
	mblk_t			*m;
	int pktlen = msgdsize(mp), err = 0;

	mutex_enter(&sc->sc_txlock);
	if (sc->tx_queued > ATU_TX_LIST_CNT) {
		sc->sc_tx_nobuf++;
		mutex_exit(&sc->sc_txlock);
		err = ENOMEM;
		goto fail;
	}
	mutex_exit(&sc->sc_txlock);

	m = allocb(ATU_TX_BUFSZ, BPRI_MED);
	if (m == NULL) {
		sc->sc_tx_nobuf++;
		err = ENOMEM;
		goto fail;
	}
	/* reserve tx header space */
	m->b_rptr += ATU_TX_HDRLEN;
	m->b_wptr += ATU_TX_HDRLEN;

	/* copy and (implicitly) free old data */
	mcopymsg(mp, m->b_wptr);
	m->b_wptr += pktlen;
	wh = (struct ieee80211_frame *)m->b_rptr;

	ni = ieee80211_find_txnode(ic, wh->i_addr1);
	if (ni == NULL) {
		ic->ic_stats.is_tx_failed++;
		freemsg(m);
		err = ENXIO;
		goto fail;
	}

	if (type == IEEE80211_FC0_TYPE_DATA)
		(void) ieee80211_encap(ic, m, ni);

	/* full WEP in device, prune WEP fields (IV, KID) */
	if (wh->i_fc[1] & IEEE80211_FC1_WEP) {
		(void) memmove(m->b_rptr + IEEE80211_WEP_IVLEN
		    + IEEE80211_WEP_KIDLEN, m->b_rptr,
		    sizeof (struct ieee80211_frame));
		m->b_rptr += IEEE80211_WEP_IVLEN + IEEE80211_WEP_KIDLEN;
	}
	pktlen = msgdsize(m);
	m->b_rptr -= ATU_TX_HDRLEN;

	/* setup tx header */
	desc = (struct atu_tx_hdr *)m->b_rptr;
	bzero(desc, ATU_TX_HDRLEN);
	desc->length = (uint16_t)pktlen;
	desc->tx_rate = ATU_DEF_TX_RATE;

	err = atu_tx_trigger(sc, m);
	if (!err) {
		ic->ic_stats.is_tx_frags++;
		ic->ic_stats.is_tx_bytes += pktlen;
	} else {
		ic->ic_stats.is_tx_failed++;
		freemsg(m);
	}
fail:
	if (ni != NULL)
		ieee80211_free_node(ni);

	return (err);
}

static int
atu_stop(struct atu_softc *sc)
{
	sc->sc_flags &= ~ATU_FLAG_RUNNING;
	atu_close_pipes(sc);

	return (atu_switch_radio(sc, B_FALSE));
}

static int
atu_init(struct atu_softc *sc)
{
	int err;

	err = atu_stop(sc);
	if (err)
		return (err);

	err = atu_open_pipes(sc);
	if (err)
		goto fail;

	err = atu_config(sc);
	if (err) {
		cmn_err(CE_WARN, "%s: startup config failed\n",
		    sc->sc_name);
		goto fail;
	}

	atu_init_tx_queue(sc);

	err = atu_init_rx_queue(sc);
	if (err) {
		cmn_err(CE_WARN, "%s: rx queue init failed\n", sc->sc_name);
		goto fail;
	}

	sc->sc_flags |= ATU_FLAG_RUNNING;

	return (0);
fail:
	(void) atu_stop(sc);
	return (err);
}

static void
atu_watchdog(void *arg)
{
	struct atu_softc *sc = arg;
	struct ieee80211com *ic = &sc->sc_ic;

	ieee80211_stop_watchdog(ic);

	ATU_LOCK(sc);
	if (!ATU_RUNNING(sc)) {
		ATU_UNLOCK(sc);
		return;
	}

	ATU_UNLOCK(sc);
	switch (ic->ic_state) {
		case IEEE80211_S_AUTH:
		case IEEE80211_S_ASSOC:
			if (ic->ic_bss->in_fails > 0)
				ieee80211_new_state(ic, IEEE80211_S_INIT, -1);
			else
				ieee80211_watchdog(ic);
			break;
	}
}

static int
atu_dfu_stage1(void *arg)
{
	struct atu_softc *sc = arg;
	uint8_t	state, *ptr = NULL, status[6];
	int block_size, bytes_left = 0, block = 0, err, i, count = 0;

	/*
	 * Uploading firmware is done with the DFU (Device Firmware Upgrade)
	 * interface. See "Universal Serial Bus - Device Class Specification
	 * for Device Firmware Upgrade" pdf for details of the protocol.
	 * Maybe this could be moved to a separate 'firmware driver' once more
	 * device drivers need it... For now we'll just do it here.
	 *
	 * Just for your information, the Atmel's DFU descriptor looks like
	 * this:
	 *
	 * 07		size
	 * 21		type
	 * 01		capabilities : only firmware download, *need* reset
	 *		  after download
	 * 13 05	detach timeout : max 1299ms between DFU_DETACH and
	 *		  reset
	 * 00 04	max bytes of firmware per transaction : 1024
	 */
	for (i = 0; i < sizeof (atu_fw_table) / sizeof (atu_fw_table[0]); i++)
		if (sc->sc_radio == atu_fw_table[i].atur_type) {
			ptr = atu_fw_table[i].atur_int;
			bytes_left = atu_fw_table[i].atur_int_size;
		}

	state = atu_get_dfu_state(sc);
	while (block >= 0 && state > 0) {
		switch (state) {
		case DFUState_DnLoadSync:
			/* get DFU status */
			err = atu_usb_request(sc, DFU_GETSTATUS, 0, 0, 6,
			    status);
			if (err) {
				cmn_err(CE_WARN, "%s: DFU get status failed\n",
				    sc->sc_name);
				return (err);
			}
			/* success means state => DnLoadIdle */
			state = DFUState_DnLoadIdle;
			continue;

		case DFUState_DFUIdle:
		case DFUState_DnLoadIdle:
			if (bytes_left >= DFU_MaxBlockSize)
				block_size = DFU_MaxBlockSize;
			else
				block_size = bytes_left;

			err = atu_usb_request(sc, DFU_DNLOAD, block++, 0,
			    block_size, ptr);
			if (err) {
				cmn_err(CE_WARN, "%s: DFU download failed\n",
				    sc->sc_name);
				return (err);
			}

			ptr += block_size;
			bytes_left -= block_size;
			if (block_size == 0)
				block = -1;
			break;

		case DFUState_DFUError:
			cmn_err(CE_WARN, "%s: DFU state error\n", sc->sc_name);
			return (EIO);

		default:
			drv_usecwait(10*1000);
			if (++count > 100) {
				cmn_err(CE_WARN, "%s: DFU timeout\n",
				    sc->sc_name);
				return (ETIME);
			}
			break;
		}

		state = atu_get_dfu_state(sc);
	}
	if (state != DFUState_ManifestSync)
		cmn_err(CE_WARN, "%s: DFU state (%d) != ManifestSync\n",
		    sc->sc_name, state);

	err = atu_usb_request(sc, DFU_GETSTATUS, 0, 0, 6, status);
	if (err) {
		cmn_err(CE_WARN, "%s: DFU get status failed\n",
		    sc->sc_name);
		return (err);
	}

	err = atu_usb_request(sc, DFU_REMAP, 0, 0, 0, NULL);
	if (err && !(sc->sc_quirk & ATU_QUIRK_NO_REMAP)) {
		cmn_err(CE_WARN, "%s: DFU remap failed\n", sc->sc_name);
		return (err);
	}

	/*
	 * after a lot of trying and measuring I found out the device needs
	 * about 56 miliseconds after sending the remap command before
	 * it's ready to communicate again. So we'll wait just a little bit
	 * longer than that to be sure...
	 */
	drv_usecwait((56+100)*1000);

	return (0);
}

static int
atu_dfu_stage2(void *arg)
{
	struct atu_softc *sc = arg;
	uint8_t	*ptr = NULL;
	int block_size, bytes_left = 0, block = 0, err, i;

	for (i = 0; i < sizeof (atu_fw_table) / sizeof (atu_fw_table[0]); i++)
		if (sc->sc_radio == atu_fw_table[i].atur_type) {
			ptr = atu_fw_table[i].atur_ext;
			bytes_left = atu_fw_table[i].atur_ext_size;
		}

	while (bytes_left) {
		if (bytes_left > 1024)
			block_size = 1024;
		else
			block_size = bytes_left;

		err = atu_usb_request(sc, ATU_VENDOR_DEV_OUT, 0x0e,
		    0x0802, block, block_size, ptr);
		if (err) {
			cmn_err(CE_WARN, "%s: stage2 firmware load failed\n",
			    sc->sc_name);
			return (err);
		}

		ptr += block_size;
		block++;
		bytes_left -= block_size;
	}

	err = atu_usb_request(sc, ATU_VENDOR_DEV_OUT, 0x0e, 0x0802,
	    block, 0, NULL);
	if (err) {
		cmn_err(CE_WARN, "%s: zero-length block load failed\n",
		    sc->sc_name);
		return (err);
	}

	/*
	 * The SMC2662w V.4 seems to require some time to do its thing with
	 * the stage2 firmware... 20 ms isn't enough, but 21 ms works 100
	 * times out of 100 tries. We'll wait a bit longer just to be sure
	 */
	if (sc->sc_quirk & ATU_QUIRK_FW_DELAY)
		drv_usecwait((21 + 100) * 1000);

	return (0);
}

static int
atu_load_microcode(struct atu_softc *sc, boolean_t attach)
{
	usb_dev_reset_lvl_t	reset;
	uint8_t			mode, chan;
	int			err;

	reset = attach ? USB_RESET_LVL_REATTACH : USB_RESET_LVL_DEFAULT;

	err = atu_get_opmode(sc, &mode);
	if (!err) {
		if (mode == ATU_DEV_READY)
			return (0);
		/*
		 * Opmode of SMC2662 V.4 does not change after stage2
		 * firmware download. If succeeded reading the channel
		 * number, stage2 firmware is already running.
		 */
		if (sc->sc_radio != RadioIntersil &&
		    atu_get_mib(sc, MIB_PHY_CHANNEL, &chan) == 0)
			return (0);

		if (mode == ATU_DEV_STAGE2)
stage2:
			return (atu_dfu_stage2(sc));
	}

	err = atu_dfu_stage1(sc);
	if (err)
		return (err);

	if (usb_reset_device(sc->sc_dip, reset) != USB_SUCCESS)
		return (EIO);

	if (attach)
		return (EAGAIN);
	else
		goto stage2;
}

static int
atu_disconnect(dev_info_t *dip)
{
	struct atu_softc *sc;
	struct ieee80211com *ic;

	sc = ddi_get_soft_state(atu_soft_state_p, ddi_get_instance(dip));
	ic = &sc->sc_ic;

	ieee80211_new_state(ic, IEEE80211_S_INIT, -1);
	ieee80211_stop_watchdog(ic);

	ATU_LOCK(sc);
	if (sc->sc_scan_timer != 0) {
		ATU_UNLOCK(sc);
		(void) untimeout(sc->sc_scan_timer);
		ATU_LOCK(sc);
		sc->sc_scan_timer = 0;
	}

	sc->sc_flags &= ~(ATU_FLAG_RUNNING | ATU_FLAG_RADIO_ON);
	atu_close_pipes(sc);

	ATU_UNLOCK(sc);
	return (0);
}

static int
atu_reconnect(dev_info_t *dip)
{
	struct atu_softc *sc;
	int err;

	sc = ddi_get_soft_state(atu_soft_state_p, ddi_get_instance(dip));
	if (usb_check_same_device(sc->sc_dip, NULL, USB_LOG_L2, -1,
	    USB_CHK_BASIC, NULL) != USB_SUCCESS)
		return (DDI_FAILURE);

	ATU_LOCK(sc);
	err = atu_load_microcode(sc, B_FALSE);
	if (!err)
		err = atu_init(sc);

	ATU_UNLOCK(sc);
	return (err ? DDI_FAILURE : DDI_SUCCESS);
}

static int
atu_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	struct atu_softc	*sc;
	struct ieee80211com	*ic;
	mac_register_t		*macp;
	wifi_data_t		wd = {0};
	int			instance, i, err;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		sc = ddi_get_soft_state(atu_soft_state_p,
		    ddi_get_instance(dip));
		if (usb_check_same_device(sc->sc_dip, NULL, USB_LOG_L2, -1,
		    USB_CHK_BASIC, NULL) != USB_SUCCESS)
			return (DDI_SUCCESS);

		if (atu_load_microcode(sc, B_FALSE) == 0)
			(void) atu_init(sc);

		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);
	if (ddi_soft_state_zalloc(atu_soft_state_p, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);

	sc = ddi_get_soft_state(atu_soft_state_p, instance);
	ic = &sc->sc_ic;
	sc->sc_dip = dip;

	(void) snprintf(sc->sc_name, sizeof (sc->sc_name), "%s%d",
	    "atu", instance);

	err = usb_client_attach(dip, USBDRV_VERSION, 0);
	if (err != USB_SUCCESS)
		goto fail1;

	err = usb_get_dev_data(dip, &sc->sc_udev, USB_PARSE_LVL_ALL, 0);
	if (err != USB_SUCCESS) {
		sc->sc_udev = NULL;
		goto fail2;
	}

	for (i = 0; i < sizeof (atu_dev_table)/sizeof (atu_dev_table[0]); i++) {
		struct atu_dev_type *t = &atu_dev_table[i];
		if (sc->sc_udev->dev_descr->idVendor == t->atu_vid &&
		    sc->sc_udev->dev_descr->idProduct == t->atu_pid) {
			sc->sc_radio = t->atu_radio;
			sc->sc_quirk = t->atu_quirk;
		}
	}

	err = atu_load_microcode(sc, B_TRUE);
	if (err == EAGAIN) {
		sc->sc_flags |= ATU_FLAG_REATTACH;	/* reattaching */
		return (DDI_SUCCESS);
	} else if (err) {
		goto fail2;
	}
	sc->sc_flags &= ~ATU_FLAG_REATTACH;

	/* read device config & MAC address */
	err = atu_get_config(sc);
	if (err) {
		cmn_err(CE_WARN, "%s: read device config failed\n",
		    sc->sc_name);
		goto fail2;
	}

	mutex_init(&sc->sc_genlock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&sc->sc_txlock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&sc->sc_rxlock, NULL, MUTEX_DRIVER, NULL);

	ic->ic_phytype = IEEE80211_T_DS;
	ic->ic_opmode = IEEE80211_M_STA;
	ic->ic_caps = IEEE80211_C_SHPREAMBLE | IEEE80211_C_WEP;
	ic->ic_sup_rates[IEEE80211_MODE_11B] = atu_rateset;
	ic->ic_maxrssi = atu_fw_table[sc->sc_radio].max_rssi;
	ic->ic_state = IEEE80211_S_INIT;
	for (i = 1; i <= 14; i++) {
		ic->ic_sup_channels[i].ich_freq =
		    ieee80211_ieee2mhz(i, IEEE80211_CHAN_2GHZ);
		ic->ic_sup_channels[i].ich_flags =
		    IEEE80211_CHAN_CCK | IEEE80211_CHAN_2GHZ |
		    IEEE80211_CHAN_PASSIVE;
	}
	ic->ic_xmit = atu_send;
	ieee80211_attach(ic);

	sc->sc_newstate = ic->ic_newstate;
	ic->ic_newstate = atu_newstate;
	ic->ic_watchdog = atu_watchdog;
	ieee80211_media_init(ic);

	ic->ic_def_txkey = 0;
	wd.wd_opmode = ic->ic_opmode;
	wd.wd_secalloc = WIFI_SEC_NONE;
	IEEE80211_ADDR_COPY(wd.wd_bssid, ic->ic_bss->in_bssid);

	macp = mac_alloc(MAC_VERSION);
	if (macp == NULL)
		goto fail3;

	macp->m_type_ident	= MAC_PLUGIN_IDENT_WIFI;
	macp->m_driver		= sc;
	macp->m_dip		= dip;
	macp->m_src_addr	= ic->ic_macaddr;
	macp->m_callbacks	= &atu_m_callbacks;
	macp->m_min_sdu		= 0;
	macp->m_max_sdu		= IEEE80211_MTU;
	macp->m_pdata		= &wd;
	macp->m_pdata_size	= sizeof (wd);

	err = mac_register(macp, &ic->ic_mach);
	mac_free(macp);
	if (err)
		goto fail3;

	err = usb_register_hotplug_cbs(sc->sc_dip, atu_disconnect,
	    atu_reconnect);
	if (err != USB_SUCCESS)
		goto fail4;

	err = ddi_create_minor_node(dip, sc->sc_name, S_IFCHR,
	    instance + 1, DDI_NT_NET_WIFI, 0);
	if (err != DDI_SUCCESS)
		cmn_err(CE_WARN, "%s: minor node creation failed\n",
		    sc->sc_name);

	mac_link_update(ic->ic_mach, LINK_STATE_DOWN);
	return (DDI_SUCCESS);

fail4:
	(void) mac_unregister(ic->ic_mach);
fail3:
	mutex_destroy(&sc->sc_genlock);
	mutex_destroy(&sc->sc_rxlock);
	mutex_destroy(&sc->sc_txlock);
fail2:
	usb_client_detach(sc->sc_dip, sc->sc_udev);
fail1:
	ddi_soft_state_free(atu_soft_state_p, instance);

	return (DDI_FAILURE);
}

static int
atu_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	struct atu_softc *sc;
	int err;

	sc = ddi_get_soft_state(atu_soft_state_p, ddi_get_instance(dip));

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		ieee80211_new_state(&sc->sc_ic, IEEE80211_S_INIT, -1);
		ieee80211_stop_watchdog(&sc->sc_ic);

		ATU_LOCK(sc);
		if (sc->sc_scan_timer != 0) {
			ATU_UNLOCK(sc);
			(void) untimeout(sc->sc_scan_timer);
			ATU_LOCK(sc);
			sc->sc_scan_timer = 0;
		}
		(void) atu_stop(sc);

		ATU_UNLOCK(sc);
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	if (!ATU_REATTACH(sc)) {
		err = mac_disable(sc->sc_ic.ic_mach);
		if (err)
			return (DDI_FAILURE);

		(void) atu_stop(sc);

		usb_unregister_hotplug_cbs(dip);
		(void) mac_unregister(sc->sc_ic.ic_mach);
		ieee80211_detach(&sc->sc_ic);

		mutex_destroy(&sc->sc_genlock);
		mutex_destroy(&sc->sc_txlock);
		mutex_destroy(&sc->sc_rxlock);

		ddi_remove_minor_node(dip, NULL);
	}

	usb_client_detach(dip, sc->sc_udev);
	ddi_soft_state_free(atu_soft_state_p, ddi_get_instance(dip));

	return (DDI_SUCCESS);
}

DDI_DEFINE_STREAM_OPS(atu_dev_ops, nulldev, nulldev, atu_attach,
    atu_detach, nodev, NULL, D_MP, NULL, ddi_quiesce_not_needed);

static struct modldrv atu_modldrv = {
	&mod_driverops,
	"atu driver v1.1",
	&atu_dev_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&atu_modldrv,
	NULL
};

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_init(void)
{
	int status;

	status = ddi_soft_state_init(&atu_soft_state_p,
	    sizeof (struct atu_softc), 1);
	if (status != 0)
		return (status);

	mac_init_ops(&atu_dev_ops, "atu");
	status = mod_install(&modlinkage);
	if (status != 0) {
		mac_fini_ops(&atu_dev_ops);
		ddi_soft_state_fini(&atu_soft_state_p);
	}
	return (status);
}

int
_fini(void)
{
	int status;

	status = mod_remove(&modlinkage);
	if (status == 0) {
		mac_fini_ops(&atu_dev_ops);
		ddi_soft_state_fini(&atu_soft_state_p);
	}
	return (status);
}

static int
atu_m_start(void *arg)
{
	struct atu_softc *sc = (struct atu_softc *)arg;
	int err;

	ATU_LOCK(sc);
	err = atu_init(sc);

	ATU_UNLOCK(sc);
	return (err);
}

static void
atu_m_stop(void *arg)
{
	struct atu_softc *sc = (struct atu_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;

	ieee80211_new_state(ic, IEEE80211_S_INIT, -1);
	ieee80211_stop_watchdog(ic);

	ATU_LOCK(sc);
	if (sc->sc_scan_timer != 0) {
		ATU_UNLOCK(sc);
		(void) untimeout(sc->sc_scan_timer);
		ATU_LOCK(sc);
		sc->sc_scan_timer = 0;
	}
	(void) atu_stop(sc);

	ATU_UNLOCK(sc);
}

/*ARGSUSED*/
static int
atu_m_unicst(void *arg, const uint8_t *macaddr)
{
	return (ENOTSUP);
}

/*ARGSUSED*/
static int
atu_m_multicst(void *arg, boolean_t add, const uint8_t *mca)
{
	return (ENOTSUP);
}

/*ARGSUSED*/
static int
atu_m_promisc(void *arg, boolean_t on)
{
	return (0);
}

static int
atu_m_setprop(void *arg, const char *name, mac_prop_id_t id, uint_t len,
    const void *buf)
{
	struct atu_softc *sc = (struct atu_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;
	int err;

	err = ieee80211_setprop(ic, name, id, len, buf);
	if (err != ENETRESET)
		return (err);
	if (ic->ic_des_esslen == 0)
		return (0);

	ATU_LOCK(sc);
	if (ATU_RUNNING(sc)) {
		if (sc->sc_scan_timer != 0) {
			ATU_UNLOCK(sc);
			(void) untimeout(sc->sc_scan_timer);
			ATU_LOCK(sc);
			sc->sc_scan_timer = 0;
		}
		err = atu_init(sc);

		ATU_UNLOCK(sc);
		if (err)
			return (err);
		ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
		ATU_LOCK(sc);
	}

	ATU_UNLOCK(sc);
	return (0);
}

static int
atu_m_getprop(void *arg, const char *name, mac_prop_id_t id,
    uint_t length, void *buf)
{
	struct atu_softc *sc = (struct atu_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;

	return (ieee80211_getprop(ic, name, id, length, buf));
}

static void
atu_m_propinfo(void *arg, const char *name, mac_prop_id_t id,
    mac_prop_info_handle_t mph)
{
	struct atu_softc *sc = (struct atu_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;

	ieee80211_propinfo(ic, name, id, mph);
}

static void
atu_m_ioctl(void* arg, queue_t *wq, mblk_t *mp)
{
	struct atu_softc *sc = (struct atu_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;
	int err;

	err = ieee80211_ioctl(ic, wq, mp);
	if (err != ENETRESET || ic->ic_des_esslen == 0)
		return;

	ATU_LOCK(sc);
	if (ATU_RUNNING(sc)) {
		if (sc->sc_scan_timer != 0) {
			ATU_UNLOCK(sc);
			(void) untimeout(sc->sc_scan_timer);
			ATU_LOCK(sc);
			sc->sc_scan_timer = 0;
		}
		err = atu_init(sc);

		ATU_UNLOCK(sc);
		if (err)
			return;
		ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
		ATU_LOCK(sc);
	}

	ATU_UNLOCK(sc);
}

static mblk_t *
atu_m_tx(void *arg, mblk_t *mp)
{
	struct atu_softc *sc = (struct atu_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;
	mblk_t *next;

	if (ic->ic_state != IEEE80211_S_RUN) {
		freemsgchain(mp);
		return (NULL);
	}

	while (mp != NULL) {
		next = mp->b_next;
		mp->b_next = NULL;
		if (atu_send(ic, mp, IEEE80211_FC0_TYPE_DATA) == ENOMEM) {
			mutex_enter(&sc->sc_txlock);
			sc->sc_need_sched = 1;
			mutex_exit(&sc->sc_txlock);

			mp->b_next = next;
			return (mp);
		}
		mp = next;
	}

	return (mp);
}

static int
atu_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	struct atu_softc	*sc  = (struct atu_softc *)arg;
	ieee80211com_t		*ic = &sc->sc_ic;
	ieee80211_node_t	*in;

	ATU_LOCK(sc);
	switch (stat) {
	case MAC_STAT_IFSPEED:
		in = ic->ic_bss;
		*val = ((ic->ic_fixed_rate == IEEE80211_FIXED_RATE_NONE) ?
		    IEEE80211_RATE(in->in_txrate) :
		    ic->ic_fixed_rate) / 2 * 1000000;
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
		*val = ic->ic_stats.is_tx_failed;
		break;
	case WIFI_STAT_TX_FRAGS:
	case WIFI_STAT_MCAST_TX:
	case WIFI_STAT_TX_FAILED:
	case WIFI_STAT_TX_RETRANS:
	case WIFI_STAT_TX_RERETRANS:
	case WIFI_STAT_RTS_SUCCESS:
	case WIFI_STAT_RTS_FAILURE:
	case WIFI_STAT_ACK_FAILURE:
	case WIFI_STAT_RX_FRAGS:
	case WIFI_STAT_MCAST_RX:
	case WIFI_STAT_FCS_ERRORS:
	case WIFI_STAT_WEP_ERRORS:
	case WIFI_STAT_RX_DUPS:
		ATU_UNLOCK(sc);
		return (ieee80211_stat(ic, stat, val));
	default:
		ATU_UNLOCK(sc);
		return (ENOTSUP);
	}

	ATU_UNLOCK(sc);
	return (0);
}

static mac_callbacks_t atu_m_callbacks = {
	MC_IOCTL | MC_SETPROP | MC_GETPROP | MC_PROPINFO,
	atu_m_stat,
	atu_m_start,
	atu_m_stop,
	atu_m_promisc,
	atu_m_multicst,
	atu_m_unicst,
	atu_m_tx,
	NULL,
	atu_m_ioctl,
	NULL,
	NULL,
	NULL,
	atu_m_setprop,
	atu_m_getprop,
	atu_m_propinfo
};
