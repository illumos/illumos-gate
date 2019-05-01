/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

/*
 * Copyright (c) 2006 Sam Leffler, Errno Consulting
 * Copyright (c) 2008-2009 Weongyo Jeong <weongyo@freebsd.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    similar to the "NO WARRANTY" disclaimer below ("Disclaimer") and any
 *    redistribution must be conditioned upon including a substantially
 *    similar Disclaimer requirement for further binary redistribution.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF NONINFRINGEMENT, MERCHANTIBILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGES.
 */

/*
 * This driver is distantly derived from a driver of the same name
 * by Damien Bergamini.  The original copyright is included below:
 *
 * Copyright (c) 2006
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


#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
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

#include "uath_reg.h"
#include "uath_var.h"

static void *uath_soft_state_p = NULL;

/*
 * Bit flags in the ral_dbg_flags
 */
#define	UATH_DBG_MSG		0x000001
#define	UATH_DBG_ERR		0x000002
#define	UATH_DBG_USB		0x000004
#define	UATH_DBG_TX		0x000008
#define	UATH_DBG_RX		0x000010
#define	UATH_DBG_FW		0x000020
#define	UATH_DBG_TX_CMD		0x000040
#define	UATH_DBG_RX_CMD		0x000080
#define	UATH_DBG_ALL		0x000fff

uint32_t uath_dbg_flags = 0;

#ifdef DEBUG
#define	UATH_DEBUG \
	uath_debug
#else
#define	UATH_DEBUG(...) (void)(0)
#endif

/*
 * Various supported device vendors/products.
 * UB51: AR5005UG 802.11b/g, UB52: AR5005UX 802.11b/g
 */
#define	UATH_FLAG_PRE_FIRMWARE	(1 << 0)
#define	UATH_FLAG_ABG		(1 << 1)
#define	UATH_FLAG_ERR		(1 << 2)
#define	UATH_DEV(v, p, f)						\
	{ { USB_VENDOR_##v, USB_PRODUCT_##v##_##p }, (f) },		\
	{ { USB_VENDOR_##v, USB_PRODUCT_##v##_##p##_NF },		\
	    (f) | UATH_FLAG_PRE_FIRMWARE }
#define	UATH_DEV_UG(v, p)	UATH_DEV(v, p, 0)
#define	UATH_DEV_UX(v, p)	UATH_DEV(v, p, UATH_FLAG_ABG)

struct uath_devno {
	uint16_t vendor_id;
	uint16_t product_id;
};

static const struct uath_type {
	struct uath_devno	dev;
	uint8_t			flags;
} uath_devs[] = {
	UATH_DEV_UG(ACCTON,		SMCWUSBTG2),
	UATH_DEV_UG(ATHEROS,		AR5523),
	UATH_DEV_UG(ATHEROS2,		AR5523_1),
	UATH_DEV_UG(ATHEROS2,		AR5523_2),
	UATH_DEV_UX(ATHEROS2,		AR5523_3),
	UATH_DEV_UG(CONCEPTRONIC,	AR5523_1),
	UATH_DEV_UX(CONCEPTRONIC,	AR5523_2),
	UATH_DEV_UX(DLINK,		DWLAG122),
	UATH_DEV_UX(DLINK,		DWLAG132),
	UATH_DEV_UG(DLINK,		DWLG132),
	UATH_DEV_UG(GIGASET,		AR5523),
	UATH_DEV_UG(GIGASET,		SMCWUSBTG),
	UATH_DEV_UG(GLOBALSUN,		AR5523_1),
	UATH_DEV_UX(GLOBALSUN,		AR5523_2),
	UATH_DEV_UG(IODATA,		USBWNG54US),
	UATH_DEV_UG(MELCO,		WLIU2KAMG54),
	UATH_DEV_UX(NETGEAR,		WG111U),
	UATH_DEV_UG(NETGEAR3,		WG111T),
	UATH_DEV_UG(NETGEAR3,		WPN111),
	UATH_DEV_UG(PHILIPS,		SNU6500),
	UATH_DEV_UX(UMEDIA,		AR5523_2),
	UATH_DEV_UG(UMEDIA,		TEW444UBEU),
	UATH_DEV_UG(WISTRONNEWEB,	AR5523_1),
	UATH_DEV_UX(WISTRONNEWEB,	AR5523_2),
	UATH_DEV_UG(ZCOM,		AR5523)
};

static char uath_fwmod[] = "uathfw";
static char uath_binmod[] = "uathbin";

/*
 * Supported rates for 802.11b/g modes (in 500Kbps unit).
 */
static const struct ieee80211_rateset uath_rateset_11b =
	{ 4, { 2, 4, 11, 22 } };

static const struct ieee80211_rateset uath_rateset_11g =
	{ 12, { 2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108 } };

/*
 * device operations
 */
static int uath_attach(dev_info_t *, ddi_attach_cmd_t);
static int uath_detach(dev_info_t *, ddi_detach_cmd_t);

/*
 * Module Loading Data & Entry Points
 */
DDI_DEFINE_STREAM_OPS(uath_dev_ops, nulldev, nulldev, uath_attach,
    uath_detach, nodev, NULL, D_MP, NULL, ddi_quiesce_not_needed);

static struct modldrv uath_modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	"Atheros AR5523 USB Driver v1.1",	/* short description */
	&uath_dev_ops		/* driver specific ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&uath_modldrv,
	NULL
};

static int	uath_m_stat(void *,  uint_t, uint64_t *);
static int	uath_m_start(void *);
static void	uath_m_stop(void *);
static int	uath_m_promisc(void *, boolean_t);
static int	uath_m_multicst(void *, boolean_t, const uint8_t *);
static int	uath_m_unicst(void *, const uint8_t *);
static mblk_t	*uath_m_tx(void *, mblk_t *);
static void	uath_m_ioctl(void *, queue_t *, mblk_t *);
static int	uath_m_setprop(void *, const char *, mac_prop_id_t,
		    uint_t, const void *);
static int	uath_m_getprop(void *, const char *, mac_prop_id_t,
		    uint_t, void *);
static void	uath_m_propinfo(void *, const char *, mac_prop_id_t,
		    mac_prop_info_handle_t);

static mac_callbacks_t uath_m_callbacks = {
	MC_IOCTL | MC_SETPROP | MC_GETPROP | MC_PROPINFO,
	uath_m_stat,
	uath_m_start,
	uath_m_stop,
	uath_m_promisc,
	uath_m_multicst,
	uath_m_unicst,
	uath_m_tx,
	NULL,
	uath_m_ioctl,
	NULL,
	NULL,
	NULL,
	uath_m_setprop,
	uath_m_getprop,
	uath_m_propinfo
};

static usb_alt_if_data_t *
		uath_lookup_alt_if(usb_client_dev_data_t *,
		    uint_t, uint_t, uint_t);
static usb_ep_data_t *
		uath_lookup_ep_data(dev_info_t *,
		    usb_client_dev_data_t *, uint_t, uint_t, uint8_t, uint8_t);
static const char *
		uath_codename(int code);

static uint_t	uath_lookup(uint16_t, uint16_t);
static void	uath_list_all_eps(usb_alt_if_data_t *);
static int	uath_open_pipes(struct uath_softc *);
static void	uath_close_pipes(struct uath_softc *);
static int	uath_fw_send(struct uath_softc *,
		    usb_pipe_handle_t, const void *, size_t);
static int	uath_fw_ack(struct uath_softc *, int);
static int	uath_loadsym(ddi_modhandle_t, char *, char **, size_t *);
static int	uath_loadfirmware(struct uath_softc *);
static int	uath_alloc_cmd_list(struct uath_softc *,
		    struct uath_cmd *, int, int);
static int 	uath_init_cmd_list(struct uath_softc *);
static void	uath_free_cmd_list(struct uath_cmd *, int);
static int	uath_host_available(struct uath_softc *);
static void	uath_get_capability(struct uath_softc *, uint32_t, uint32_t *);
static int	uath_get_devcap(struct uath_softc *);
static int	uath_get_devstatus(struct uath_softc *, uint8_t *);
static int	uath_get_status(struct uath_softc *, uint32_t, void *, int);

static void	uath_cmd_lock_init(struct uath_cmd_lock *);
static void	uath_cmd_lock_destroy(struct uath_cmd_lock *);
static int	uath_cmd_lock_wait(struct uath_cmd_lock *, clock_t);
static void	uath_cmd_lock_signal(struct uath_cmd_lock *);

static int	uath_cmd_read(struct uath_softc *, uint32_t, const void *,
		    int, void *, int, int);
static int	uath_cmd_write(struct uath_softc *, uint32_t, const void *,
		    int, int);
static int	uath_cmdsend(struct uath_softc *, uint32_t,
		    const void *, int, void *, int, int);
static int	uath_rx_cmd_xfer(struct uath_softc *);
static int	uath_tx_cmd_xfer(struct uath_softc *,
		    usb_pipe_handle_t, const void *, uint_t);
static void	uath_cmd_txeof(usb_pipe_handle_t, struct usb_bulk_req *);
static void	uath_cmd_rxeof(usb_pipe_handle_t, usb_bulk_req_t *);
static void	uath_cmdeof(struct uath_softc *, struct uath_cmd *);

static void	uath_init_data_queue(struct uath_softc *);
static int	uath_rx_data_xfer(struct uath_softc *sc);
static int	uath_tx_data_xfer(struct uath_softc *, mblk_t *);
static void	uath_data_txeof(usb_pipe_handle_t, usb_bulk_req_t *);
static void	uath_data_rxeof(usb_pipe_handle_t, usb_bulk_req_t *);

static int	uath_create_connection(struct uath_softc *, uint32_t);
static int	uath_set_rates(struct uath_softc *,
		    const struct ieee80211_rateset *);
static int	uath_write_associd(struct uath_softc *);
static int	uath_set_ledsteady(struct uath_softc *, int, int);
static int	uath_set_ledblink(struct uath_softc *, int, int, int, int);
static void	uath_update_rxstat(struct uath_softc *, uint32_t);
static int	uath_send(ieee80211com_t *, mblk_t *, uint8_t);
static int	uath_reconnect(dev_info_t *);
static int	uath_disconnect(dev_info_t *);
static int	uath_newstate(struct ieee80211com *, enum ieee80211_state, int);

static int	uath_dataflush(struct uath_softc *);
static int	uath_cmdflush(struct uath_softc *);
static int	uath_flush(struct uath_softc *);
static int	uath_set_ledstate(struct uath_softc *, int);
static int	uath_set_chan(struct uath_softc *, struct ieee80211_channel *);
static int	uath_reset_tx_queues(struct uath_softc *);
static int	uath_wme_init(struct uath_softc *);
static int	uath_config_multi(struct uath_softc *,
		    uint32_t, const void *, int);
static void	uath_config(struct uath_softc *, uint32_t, uint32_t);
static int	uath_switch_channel(struct uath_softc *,
		    struct ieee80211_channel *);
static int	uath_set_rxfilter(struct uath_softc *, uint32_t, uint32_t);
static int	uath_init_locked(void *);
static void	uath_stop_locked(void *);
static int	uath_init(struct uath_softc *);
static void	uath_stop(struct uath_softc *);
static void	uath_resume(struct uath_softc *);

static void
uath_debug(uint32_t dbg_flags, const int8_t *fmt, ...)
{
	va_list args;

	if (dbg_flags & uath_dbg_flags) {
		va_start(args, fmt);
		vcmn_err(CE_CONT, fmt, args);
		va_end(args);
	}
}

static uint_t
uath_lookup(uint16_t vendor_id, uint16_t product_id)
{
	int i, size;

	size = sizeof (uath_devs) / sizeof (struct uath_type);

	for (i = 0; i < size; i++) {
		if ((vendor_id == uath_devs[i].dev.vendor_id) &&
		    (product_id == uath_devs[i].dev.product_id))
			return (uath_devs[i].flags);
	}
	return (UATH_FLAG_ERR);
}

/*
 * Return a specific alt_if from the device descriptor tree.
 */
static usb_alt_if_data_t *
uath_lookup_alt_if(usb_client_dev_data_t *dev_data, uint_t config,
    uint_t interface, uint_t alt)
{
	usb_cfg_data_t *cfg_data;
	usb_if_data_t *if_data;
	usb_alt_if_data_t *if_alt_data;

	/*
	 * Assume everything is in the tree for now,
	 * (USB_PARSE_LVL_ALL)
	 * so we can directly index the array.
	 */

	/* Descend to configuration, configs are 1-based */
	if (config < 1 || config > dev_data->dev_n_cfg)
		return (NULL);
	cfg_data = &dev_data->dev_cfg[config - 1];

	/* Descend to interface */
	if (interface > cfg_data->cfg_n_if - 1)
		return (NULL);
	if_data = &cfg_data->cfg_if[interface];

	/* Descend to alt */
	if (alt > if_data->if_n_alt - 1)
		return (NULL);
	if_alt_data = &if_data->if_alt[alt];

	return (if_alt_data);
}

/*
 * Print all endpoints of an alt_if.
 */
static void
uath_list_all_eps(usb_alt_if_data_t *ifalt)
{
	usb_ep_data_t *ep_data;
	usb_ep_descr_t *ep_descr;
	int i;

	for (i = 0; i < ifalt->altif_n_ep; i++) {
		ep_data = &ifalt->altif_ep[i];
		ep_descr = &ep_data->ep_descr;
		UATH_DEBUG(UATH_DBG_USB,
		    "uath: uath_list_all_endpoint: "
		    "ep addresa[%x] is %x",
		    i, ep_descr->bEndpointAddress);
	}
}

static usb_ep_data_t *
uath_lookup_ep_data(dev_info_t *dip,
    usb_client_dev_data_t *dev_datap,
    uint_t interface,
    uint_t alternate,
    uint8_t address,
    uint8_t type)
{
	usb_alt_if_data_t *altif_data;
	int i;

	if ((dip == NULL) || (dev_datap == NULL))
		return (NULL);

	altif_data = &dev_datap->dev_curr_cfg->
	    cfg_if[interface].if_alt[alternate];

	for (i = 0; i < altif_data->altif_n_ep; i++) {
		usb_ep_descr_t *ept = &altif_data->altif_ep[i].ep_descr;
		uint8_t ept_type = ept->bmAttributes & USB_EP_ATTR_MASK;
		uint8_t ept_address = ept->bEndpointAddress;

		if (ept->bLength == 0)
			continue;
		if ((ept_type == type) &&
		    ((type == USB_EP_ATTR_CONTROL) || (address == ept_address)))
			return (&altif_data->altif_ep[i]);
	}
	return (NULL);
}

/*
 * Open communication pipes.
 * The following pipes are used by the AR5523:
 * ep0: 0x81 IN  Rx cmd
 * ep1: 0x01 OUT Tx cmd
 * ep2: 0x82 IN  Rx data
 * ep3: 0x02 OUT Tx data
 */
static int
uath_open_pipes(struct uath_softc *sc)
{
	usb_ep_data_t *ep_node;
	usb_ep_descr_t *ep_descr;
	usb_pipe_policy_t policy;
	int err;

#ifdef DEBUG
	usb_alt_if_data_t *altif_data;

	altif_data = uath_lookup_alt_if(sc->sc_udev, UATH_CONFIG_NO,
	    UATH_IFACE_INDEX, UATH_ALT_IF_INDEX);
	if (altif_data == NULL) {
		UATH_DEBUG(UATH_DBG_ERR, "alt_if not found");
		return (USB_FAILURE);
	}

	uath_list_all_eps(altif_data);
#endif

	/*
	 * XXX pipes numbers are hardcoded because we don't have any way
	 * to distinguish the data pipes from the firmware command pipes
	 * (both are bulk pipes) using the endpoints descriptors.
	 */
	ep_node = uath_lookup_ep_data(sc->sc_dev, sc->sc_udev,
	    0, 0, 0x81, USB_EP_ATTR_BULK);
	ep_descr = &ep_node->ep_descr;
	UATH_DEBUG(UATH_DBG_MSG, "uath: uath_open_pipes(): "
	    "find pipe %x\n", ep_descr->bEndpointAddress);

	bzero(&policy, sizeof (usb_pipe_policy_t));
	policy.pp_max_async_reqs = UATH_CMD_LIST_COUNT;

	err = usb_pipe_open(sc->sc_dev, &ep_node->ep_descr,
	    &policy, USB_FLAGS_SLEEP, &sc->rx_cmd_pipe);
	if (err != USB_SUCCESS) {
		UATH_DEBUG(UATH_DBG_ERR, "uath: uath_open_pipes(): "
		    "failed to open rx data pipe, err = %x\n",
		    err);
		goto fail;
	}


	ep_node = uath_lookup_ep_data(sc->sc_dev, sc->sc_udev,
	    0, 0, 0x01, USB_EP_ATTR_BULK);
	ep_descr = &ep_node->ep_descr;
	UATH_DEBUG(UATH_DBG_ERR, "uath: uath_open_pipes(): "
	    "find pipe %x\n",
	    ep_descr->bEndpointAddress);

	bzero(&policy, sizeof (usb_pipe_policy_t));
	policy.pp_max_async_reqs = UATH_CMD_LIST_COUNT;

	err = usb_pipe_open(sc->sc_dev, &ep_node->ep_descr,
	    &policy, USB_FLAGS_SLEEP, &sc->tx_cmd_pipe);
	if (err != USB_SUCCESS) {
		UATH_DEBUG(UATH_DBG_ERR, "uath: uath_open_pipes(): "
		    "failed to open tx command pipe, err = %x\n",
		    err);
		goto fail;
	}

	ep_node = uath_lookup_ep_data(sc->sc_dev, sc->sc_udev,
	    0, 0, 0x82, USB_EP_ATTR_BULK);
	ep_descr = &ep_node->ep_descr;
	UATH_DEBUG(UATH_DBG_ERR, "uath: uath_open_pipes(): "
	    "find pipe %x\n",
	    ep_descr->bEndpointAddress);

	bzero(&policy, sizeof (usb_pipe_policy_t));
	policy.pp_max_async_reqs = UATH_RX_DATA_LIST_COUNT;

	err = usb_pipe_open(sc->sc_dev, &ep_node->ep_descr,
	    &policy, USB_FLAGS_SLEEP, &sc->rx_data_pipe);
	if (err != USB_SUCCESS) {
		UATH_DEBUG(UATH_DBG_ERR, "uath: uath_open_pipes(): "
		    "failed to open tx pipe, err = %x\n",
		    err);
		goto fail;
	}

	ep_node = uath_lookup_ep_data(sc->sc_dev, sc->sc_udev,
	    0, 0, 0x02, USB_EP_ATTR_BULK);
	ep_descr = &ep_node->ep_descr;
	UATH_DEBUG(UATH_DBG_ERR, "uath: uath_open_pipes(): "
	    "find pipe %x\n",
	    ep_descr->bEndpointAddress);

	bzero(&policy, sizeof (usb_pipe_policy_t));
	policy.pp_max_async_reqs = UATH_TX_DATA_LIST_COUNT;

	err = usb_pipe_open(sc->sc_dev, &ep_node->ep_descr,
	    &policy, USB_FLAGS_SLEEP, &sc->tx_data_pipe);
	if (err != USB_SUCCESS) {
		UATH_DEBUG(UATH_DBG_ERR, "uath: uath_open_pipes(): "
		    "failed to open rx command pipe, err = %x\n",
		    err);
		goto fail;
	}

	return (UATH_SUCCESS);
fail:
	uath_close_pipes(sc);
	return (err);
}

static void
uath_close_pipes(struct uath_softc *sc)
{
	usb_flags_t flags = USB_FLAGS_SLEEP;

	if (sc->rx_cmd_pipe != NULL) {
		usb_pipe_reset(sc->sc_dev, sc->rx_cmd_pipe, flags, NULL, 0);
		usb_pipe_close(sc->sc_dev, sc->rx_cmd_pipe, flags, NULL, 0);
		sc->rx_cmd_pipe = NULL;
	}

	if (sc->tx_cmd_pipe != NULL) {
		usb_pipe_reset(sc->sc_dev, sc->tx_cmd_pipe, flags, NULL, 0);
		usb_pipe_close(sc->sc_dev, sc->tx_cmd_pipe, flags, NULL, 0);
		sc->tx_cmd_pipe = NULL;
	}

	if (sc->rx_data_pipe != NULL) {
		usb_pipe_reset(sc->sc_dev, sc->rx_data_pipe, flags, NULL, 0);
		usb_pipe_close(sc->sc_dev, sc->rx_data_pipe, flags, NULL, 0);
		sc->rx_data_pipe = NULL;
	}

	if (sc->tx_data_pipe != NULL) {
		usb_pipe_reset(sc->sc_dev, sc->tx_data_pipe, flags, NULL, 0);
		usb_pipe_close(sc->sc_dev, sc->tx_data_pipe, flags, NULL, 0);
		sc->tx_data_pipe = NULL;
	}

}

static const char *
uath_codename(int code)
{
#define	N(a)	(sizeof (a)/sizeof (a[0]))
	static const char *names[] = {
	    "0x00",
	    "HOST_AVAILABLE",
	    "BIND",
	    "TARGET_RESET",
	    "TARGET_GET_CAPABILITY",
	    "TARGET_SET_CONFIG",
	    "TARGET_GET_STATUS",
	    "TARGET_GET_STATS",
	    "TARGET_START",
	    "TARGET_STOP",
	    "TARGET_ENABLE",
	    "TARGET_DISABLE",
	    "CREATE_CONNECTION",
	    "UPDATE_CONNECT_ATTR",
	    "DELETE_CONNECT",
	    "SEND",
	    "FLUSH",
	    "STATS_UPDATE",
	    "BMISS",
	    "DEVICE_AVAIL",
	    "SEND_COMPLETE",
	    "DATA_AVAIL",
	    "SET_PWR_MODE",
	    "BMISS_ACK",
	    "SET_LED_STEADY",
	    "SET_LED_BLINK",
	    "SETUP_BEACON_DESC",
	    "BEACON_INIT",
	    "RESET_KEY_CACHE",
	    "RESET_KEY_CACHE_ENTRY",
	    "SET_KEY_CACHE_ENTRY",
	    "SET_DECOMP_MASK",
	    "SET_REGULATORY_DOMAIN",
	    "SET_LED_STATE",
	    "WRITE_ASSOCID",
	    "SET_STA_BEACON_TIMERS",
	    "GET_TSF",
	    "RESET_TSF",
	    "SET_ADHOC_MODE",
	    "SET_BASIC_RATE",
	    "MIB_CONTROL",
	    "GET_CHANNEL_DATA",
	    "GET_CUR_RSSI",
	    "SET_ANTENNA_SWITCH",
	    "0x2c", "0x2d", "0x2e",
	    "USE_SHORT_SLOT_TIME",
	    "SET_POWER_MODE",
	    "SETUP_PSPOLL_DESC",
	    "SET_RX_MULTICAST_FILTER",
	    "RX_FILTER",
	    "PER_CALIBRATION",
	    "RESET",
	    "DISABLE",
	    "PHY_DISABLE",
	    "SET_TX_POWER_LIMIT",
	    "SET_TX_QUEUE_PARAMS",
	    "SETUP_TX_QUEUE",
	    "RELEASE_TX_QUEUE",
	};
	static char buf[8];

	if (code < N(names))
		return (names[code]);
	if (code == WDCMSG_SET_DEFAULT_KEY)
		return ("SET_DEFAULT_KEY");

	(void) snprintf(buf, sizeof (buf), "0x%02x", code);
	return (buf);
#undef N
}

static int
uath_fw_send(struct uath_softc *sc, usb_pipe_handle_t pipe,
    const void *data, size_t len)
{
	usb_bulk_req_t *send_req;
	mblk_t *mblk;
	int res;

	send_req = usb_alloc_bulk_req(sc->sc_dev, len, USB_FLAGS_SLEEP);

	send_req->bulk_len = (int)len;
	send_req->bulk_attributes = USB_ATTRS_AUTOCLEARING;
	send_req->bulk_timeout = UATH_CMD_TIMEOUT;

	mblk = send_req->bulk_data;
	bcopy(data, mblk->b_wptr, len);
	mblk->b_wptr += len;

	res = usb_pipe_bulk_xfer(pipe, send_req, USB_FLAGS_SLEEP);
	if (res != USB_SUCCESS) {
		UATH_DEBUG(UATH_DBG_FW, "uath: uath_fw_send(): "
		    "Error %x writing data to bulk/out pipe", res);
		return (UATH_FAILURE);
	}

	usb_free_bulk_req(send_req);
	return (UATH_SUCCESS);
}

static int
uath_fw_ack(struct uath_softc *sc, int len)
{
	struct uath_fwblock *rxblock;
	usb_bulk_req_t *req;
	mblk_t *mp;
	int err;

	req = usb_alloc_bulk_req(sc->sc_dev, len, USB_FLAGS_SLEEP);
	if (req == NULL) {
		UATH_DEBUG(UATH_DBG_FW,
		    "uath: uath_fw_ack(): "
		    "uath_rx_transfer(): failed to allocate req");
		return (UATH_FAILURE);
	}

	req->bulk_len			= len;
	req->bulk_client_private	= (usb_opaque_t)sc;
	req->bulk_timeout		= 0;
	req->bulk_attributes		= USB_ATTRS_SHORT_XFER_OK
	    | USB_ATTRS_AUTOCLEARING;

	err = usb_pipe_bulk_xfer(sc->rx_cmd_pipe, req, USB_FLAGS_SLEEP);
	if (err != USB_SUCCESS) {
		UATH_DEBUG(UATH_DBG_FW, "uath: uath_fw_ack(): "
		    "failed to do rx xfer, %d", err);
		usb_free_bulk_req(req);
		return (UATH_FAILURE);
	}

	mp = req->bulk_data;
	req->bulk_data = NULL;

	rxblock = (struct uath_fwblock *)mp->b_rptr;
	UATH_DEBUG(UATH_DBG_FW, "uath: uath_fw_ack() "
	    "rxblock flags=0x%x total=%d\n",
	    BE_32(rxblock->flags), BE_32(rxblock->rxtotal));

	freemsg(mp);
	usb_free_bulk_req(req);

	return (UATH_SUCCESS);
}

/*
 * find uath firmware module's "_start" "_end" symbols
 * and get its size.
 */
static int
uath_loadsym(ddi_modhandle_t modp, char *sym, char **start, size_t *len)
{
	char start_sym[64];
	char end_sym[64];
	char *p, *end;
	int rv;
	size_t n;

	(void) snprintf(start_sym, sizeof (start_sym), "%s_start", sym);
	(void) snprintf(end_sym, sizeof (end_sym), "%s_end", sym);

	p = (char *)ddi_modsym(modp, start_sym, &rv);
	if (p == NULL || rv != 0) {
		UATH_DEBUG(UATH_DBG_MSG, "uath: uath_loadsym(): "
		    "mod %s: symbol %s not found\n", uath_fwmod, start_sym);
		return (UATH_FAILURE);
	}

	end = (char *)ddi_modsym(modp, end_sym, &rv);
	if (end == NULL || rv != 0) {
		UATH_DEBUG(UATH_DBG_MSG, "uath: uath_loadsym(): "
		    "mod %s: symbol %s not found\n", uath_fwmod, end_sym);
		return (UATH_FAILURE);
	}

	n = _PTRDIFF(end, p);
	*start = p;
	*len = n;

	return (UATH_SUCCESS);
}

/*
 * Load the MIPS R4000 microcode into the device.  Once the image is loaded,
 * the device will detach itself from the bus and reattach later with a new
 * product Id (a la ezusb).  XXX this could also be implemented in userland
 * through /dev/ugen.
 */
static int
uath_loadfirmware(struct uath_softc *sc)
{
	struct uath_fwblock txblock;
	ddi_modhandle_t modp;
	char *fw_index, *fw_image = NULL;
	size_t fw_size, len;
	int err = DDI_SUCCESS, rv = 0;

	modp = ddi_modopen(uath_fwmod, KRTLD_MODE_FIRST, &rv);
	if (modp == NULL) {
		cmn_err(CE_WARN, "uath: uath_loadfirmware(): "
		    "module %s not found\n", uath_fwmod);
		goto label;
	}

	err = uath_loadsym(modp, uath_binmod, &fw_index, &fw_size);
	if (err != UATH_SUCCESS) {
		cmn_err(CE_WARN, "uath: uath_loadfirmware(): "
		    "could not get firmware\n");
		goto label;
	}

	fw_image = (char *)kmem_alloc(fw_size, KM_SLEEP);
	if (fw_image == NULL) {
		UATH_DEBUG(UATH_DBG_ERR, "uath: uath_loadfirmware(): "
		    "failed to alloc firmware memory\n");
		err = UATH_FAILURE;
		goto label;
	}

	(void) memcpy(fw_image, fw_index, fw_size);
	fw_index = fw_image;
	len = fw_size;
	UATH_DEBUG(UATH_DBG_MSG, "loading firmware size = %lu\n", fw_size);

	/* bzero(txblock, sizeof (struct uath_fwblock)); */
	txblock.flags = BE_32(UATH_WRITE_BLOCK);
	txblock.total = BE_32(fw_size);

	while (len > 0) {
		size_t mlen = min(len, UATH_MAX_FWBLOCK_SIZE);

		txblock.remain = BE_32(len - mlen);
		txblock.len = BE_32(mlen);

		UATH_DEBUG(UATH_DBG_FW, "uath: uath_loadfirmware(): "
		    "sending firmware block: %d bytes sending\n", mlen);
		UATH_DEBUG(UATH_DBG_FW, "uath: uath_loadfirmware(): "
		    "sending firmware block: %d bytes remaining\n",
		    len - mlen);

		/* send firmware block meta-data */
		err = uath_fw_send(sc, sc->tx_cmd_pipe, &txblock,
		    sizeof (struct uath_fwblock));
		if (err != UATH_SUCCESS) {
			UATH_DEBUG(UATH_DBG_FW, "uath: uath_loadfirmware(): "
			    "send block meta-data error");
			goto label;
		}

		/* send firmware block data */
		err = uath_fw_send(sc, sc->tx_data_pipe, fw_index, mlen);
		if (err != UATH_SUCCESS) {
			UATH_DEBUG(UATH_DBG_FW, "uath: uath_loadfirmware() "
			    "send block data err");
			goto label;
		}

		/* wait for ack from firmware */
		err = uath_fw_ack(sc, sizeof (struct uath_fwblock));
		if (err != UATH_SUCCESS) {
			UATH_DEBUG(UATH_DBG_FW, "uath: uath_loadfirmware() "
			    "rx block ack err");
			goto label;
		}

		fw_index += mlen;
		len -= mlen;
	}

label:
	if (fw_image != NULL)
		kmem_free(fw_image, fw_size);
	fw_image = fw_index = NULL;
	if (modp != NULL)
		(void) ddi_modclose(modp);
	return (err);
}

static int
uath_alloc_cmd_list(struct uath_softc *sc, struct uath_cmd cmds[],
    int ncmd, int maxsz)
{
	int i, err;

	for (i = 0; i < ncmd; i++) {
		struct uath_cmd *cmd = &cmds[i];

		cmd->sc = sc;	/* backpointer for callbacks */
		cmd->msgid = i;
		cmd->buf = kmem_zalloc(maxsz, KM_NOSLEEP);
		if (cmd->buf == NULL) {
			UATH_DEBUG(UATH_DBG_ERR, "uath: uath_alloc_cmd_list(): "
			    "could not allocate xfer buffer\n");
			err = DDI_ENOMEM;
			goto fail;
		}
	}
	return (UATH_SUCCESS);

fail:
	uath_free_cmd_list(cmds, ncmd);
	return (err);
}

static int
uath_init_cmd_list(struct uath_softc *sc)
{
	int i;

	sc->sc_cmdid = sc->rx_cmd_queued = sc->tx_cmd_queued = 0;
	for (i = 0; i < UATH_CMD_LIST_COUNT; i++) {
		if (uath_rx_cmd_xfer(sc) != UATH_SUCCESS) {
			UATH_DEBUG(UATH_DBG_ERR, "uath: uath_init_cmd_list(): "
			    "failed to init cmd list %x\n", i);
			return (UATH_FAILURE);
		}
	}
	return (UATH_SUCCESS);
}

static void
uath_free_cmd_list(struct uath_cmd cmds[], int ncmd)
{
	int i;

	for (i = 0; i < ncmd; i++)
		if (cmds[i].buf != NULL) {
			kmem_free(cmds[i].buf, UATH_MAX_CMDSZ);
			cmds[i].buf = NULL;
		}
}

static int
uath_host_available(struct uath_softc *sc)
{
	struct uath_cmd_host_available setup;

	/* inform target the host is available */
	setup.sw_ver_major = BE_32(ATH_SW_VER_MAJOR);
	setup.sw_ver_minor = BE_32(ATH_SW_VER_MINOR);
	setup.sw_ver_patch = BE_32(ATH_SW_VER_PATCH);
	setup.sw_ver_build = BE_32(ATH_SW_VER_BUILD);
	return (uath_cmd_read(sc, WDCMSG_HOST_AVAILABLE,
	    &setup, sizeof (setup), NULL, 0, 0));
}

static void
uath_get_capability(struct uath_softc *sc, uint32_t cap, uint32_t *val)
{
	int err;

	cap = BE_32(cap);
	err = uath_cmd_read(sc, WDCMSG_TARGET_GET_CAPABILITY, &cap,
	    sizeof (cap), val, sizeof (uint32_t), UATH_CMD_FLAG_MAGIC);
	if (err == UATH_SUCCESS)
		*val = BE_32(*val);
	else
		UATH_DEBUG(UATH_DBG_ERR, "uath: uath_get_capability(): "
		    "could not read capability %u\n", BE_32(cap));
}

static int
uath_get_devcap(struct uath_softc *sc)
{
	struct uath_devcap *cap = &sc->sc_devcap;

	/* collect device capabilities */
	uath_get_capability(sc, CAP_TARGET_VERSION,
	    &cap->targetVersion);
	uath_get_capability(sc, CAP_TARGET_REVISION,
	    &cap->targetRevision);
	uath_get_capability(sc, CAP_MAC_VERSION,
	    &cap->macVersion);
	uath_get_capability(sc, CAP_MAC_REVISION,
	    &cap->macRevision);
	uath_get_capability(sc, CAP_PHY_REVISION,
	    &cap->phyRevision);
	uath_get_capability(sc, CAP_ANALOG_5GHz_REVISION,
	    &cap->analog5GhzRevision);
	uath_get_capability(sc, CAP_ANALOG_2GHz_REVISION,
	    &cap->analog2GhzRevision);
	uath_get_capability(sc, CAP_REG_DOMAIN,
	    &cap->regDomain);
	uath_get_capability(sc, CAP_REG_CAP_BITS,
	    &cap->regCapBits);

	/* NB: not supported in rev 1.5 */
	/* uath_get_capability(sc, CAP_COUNTRY_CODE, cap->countryCode); */

	uath_get_capability(sc, CAP_WIRELESS_MODES,
	    &cap->wirelessModes);
	uath_get_capability(sc, CAP_CHAN_SPREAD_SUPPORT,
	    &cap->chanSpreadSupport);
	uath_get_capability(sc, CAP_COMPRESS_SUPPORT,
	    &cap->compressSupport);
	uath_get_capability(sc, CAP_BURST_SUPPORT,
	    &cap->burstSupport);
	uath_get_capability(sc, CAP_FAST_FRAMES_SUPPORT,
	    &cap->fastFramesSupport);
	uath_get_capability(sc, CAP_CHAP_TUNING_SUPPORT,
	    &cap->chapTuningSupport);
	uath_get_capability(sc, CAP_TURBOG_SUPPORT,
	    &cap->turboGSupport);
	uath_get_capability(sc, CAP_TURBO_PRIME_SUPPORT,
	    &cap->turboPrimeSupport);
	uath_get_capability(sc, CAP_DEVICE_TYPE,
	    &cap->deviceType);
	uath_get_capability(sc, CAP_WME_SUPPORT,
	    &cap->wmeSupport);
	uath_get_capability(sc, CAP_TOTAL_QUEUES,
	    &cap->numTxQueues);
	uath_get_capability(sc, CAP_CONNECTION_ID_MAX,
	    &cap->connectionIdMax);

	uath_get_capability(sc, CAP_LOW_5GHZ_CHAN,
	    &cap->low5GhzChan);
	uath_get_capability(sc, CAP_HIGH_5GHZ_CHAN,
	    &cap->high5GhzChan);
	uath_get_capability(sc, CAP_LOW_2GHZ_CHAN,
	    &cap->low2GhzChan);
	uath_get_capability(sc, CAP_HIGH_2GHZ_CHAN,
	    &cap->high2GhzChan);
	uath_get_capability(sc, CAP_TWICE_ANTENNAGAIN_5G,
	    &cap->twiceAntennaGain5G);
	uath_get_capability(sc, CAP_TWICE_ANTENNAGAIN_2G,
	    &cap->twiceAntennaGain2G);

	uath_get_capability(sc, CAP_CIPHER_AES_CCM,
	    &cap->supportCipherAES_CCM);
	uath_get_capability(sc, CAP_CIPHER_TKIP,
	    &cap->supportCipherTKIP);
	uath_get_capability(sc, CAP_MIC_TKIP,
	    &cap->supportMicTKIP);

	cap->supportCipherWEP = 1;	/* NB: always available */
	return (UATH_SUCCESS);
}

static int
uath_get_status(struct uath_softc *sc, uint32_t which, void *odata, int olen)
{
	int err;

	which = BE_32(which);
	err = uath_cmd_read(sc, WDCMSG_TARGET_GET_STATUS,
	    &which, sizeof (which), odata, olen, UATH_CMD_FLAG_MAGIC);
	if (err != UATH_SUCCESS)
		UATH_DEBUG(UATH_DBG_ERR, "uath: uath_get_status(): "
		    "could not read EEPROM offset 0x%02x\n", BE_32(which));
	return (err);
}

static int
uath_get_devstatus(struct uath_softc *sc, uint8_t macaddr[IEEE80211_ADDR_LEN])
{
	int err;

	/* retrieve MAC address */
	err = uath_get_status(sc, ST_MAC_ADDR, macaddr, IEEE80211_ADDR_LEN);
	if (err != UATH_SUCCESS) {
		UATH_DEBUG(UATH_DBG_ERR, "uath: uath_get_devstatus(): "
		    "could not read MAC address\n");
		return (err);
	}

	err = uath_get_status(sc, ST_SERIAL_NUMBER,
	    &sc->sc_serial[0], sizeof (sc->sc_serial));
	if (err != UATH_SUCCESS) {
		UATH_DEBUG(UATH_DBG_ERR, "uath: uath_get_devstatus(): "
		    "could not read device serial number\n");
		return (err);
	}

	return (UATH_SUCCESS);
}

/*
 * uath_cmd_lock: a special signal structure that is used for notification
 * that a callback function has been called.
 */

/* Initializes the uath_cmd_lock structure. */
static void
uath_cmd_lock_init(struct uath_cmd_lock *lock)
{
	ASSERT(lock != NULL);
	mutex_init(&lock->mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&lock->cv, NULL, CV_DRIVER, NULL);
	lock->done = B_FALSE;
}

/* Deinitalizes the uath_cb_lock structure. */
void
uath_cmd_lock_destroy(struct uath_cmd_lock *lock)
{
	ASSERT(lock != NULL);
	mutex_destroy(&lock->mutex);
	cv_destroy(&lock->cv);
}

/*
 * Wait on lock until someone calls the "signal" function or the timeout
 * expires. Note: timeout is in microseconds.
 */
static int
uath_cmd_lock_wait(struct uath_cmd_lock *lock, clock_t timeout)
{
	int res, cv_res;
	clock_t etime;

	ASSERT(lock != NULL);
	mutex_enter(&lock->mutex);

	if (timeout < 0) {
		/* no timeout - wait as long as needed */
		while (lock->done == B_FALSE)
			cv_wait(&lock->cv, &lock->mutex);
	} else {
		/* wait with timeout (given in usec) */
		etime = ddi_get_lbolt() + drv_usectohz(timeout);
		while (lock->done == B_FALSE) {
			cv_res = cv_timedwait_sig(&lock->cv,
			    &lock->mutex, etime);
			if (cv_res <= 0) break;
		}
	}

	res = (lock->done == B_TRUE) ? UATH_SUCCESS : UATH_FAILURE;
	mutex_exit(&lock->mutex);

	return (res);
}

/* Signal that the job (eg. callback) is done and unblock anyone who waits. */
static void
uath_cmd_lock_signal(struct uath_cmd_lock *lock)
{
	ASSERT(lock != NULL);

	mutex_enter(&lock->mutex);
	lock->done = B_TRUE;
	cv_broadcast(&lock->cv);
	mutex_exit(&lock->mutex);
}

static int
uath_cmd_read(struct uath_softc *sc, uint32_t code, const void *idata,
    int ilen, void *odata, int olen, int flags)
{
	flags |= UATH_CMD_FLAG_READ;
	return (uath_cmdsend(sc, code, idata, ilen, odata, olen, flags));
}

static int
uath_cmd_write(struct uath_softc *sc, uint32_t code, const void *data,
    int len, int flags)
{
	flags &= ~UATH_CMD_FLAG_READ;
	return (uath_cmdsend(sc, code, data, len, NULL, 0, flags));
}

/*
 * Low-level function to send read or write commands to the firmware.
 */
static int
uath_cmdsend(struct uath_softc *sc, uint32_t code, const void *idata, int ilen,
    void *odata, int olen, int flags)
{
	struct uath_cmd_hdr *hdr;
	struct uath_cmd *cmd;
	int err;

	/* grab a xfer */
	cmd = &sc->sc_cmd[sc->sc_cmdid];

	cmd->flags = flags;
	/* always bulk-out a multiple of 4 bytes */
	cmd->buflen = (sizeof (struct uath_cmd_hdr) + ilen + 3) & ~3;

	hdr = (struct uath_cmd_hdr *)cmd->buf;
	bzero(hdr, sizeof (struct uath_cmd_hdr));
	hdr->len   = BE_32(cmd->buflen);
	hdr->code  = BE_32(code);
	hdr->msgid = cmd->msgid;	/* don't care about endianness */
	hdr->magic = BE_32((cmd->flags & UATH_CMD_FLAG_MAGIC) ? 1 << 24 : 0);
	bcopy(idata, (uint8_t *)(hdr + 1), ilen);

	UATH_DEBUG(UATH_DBG_TX_CMD, "uath: uath_cmdsend(): "
	    "queue %x send %s [flags 0x%x] olen %d\n",
	    cmd->msgid, uath_codename(code), cmd->flags, olen);

	cmd->odata = odata;
	if (odata == NULL)
		UATH_DEBUG(UATH_DBG_TX_CMD, "uath: uath_cmdsend(): "
		    "warning - odata is NULL\n");
	else if (olen < UATH_MAX_CMDSZ - sizeof (*hdr) + sizeof (uint32_t))
		UATH_DEBUG(UATH_DBG_TX_CMD, "uath: uath_cmdsend(): "
		    "warning - olen %x is short\n, olen");
	cmd->olen = olen;

	err = uath_tx_cmd_xfer(sc, sc->tx_cmd_pipe, cmd->buf, cmd->buflen);
	if (err != UATH_SUCCESS) {
		UATH_DEBUG(UATH_DBG_ERR, "uath: uath_cmdsend(): "
		    "Error writing command\n");
		return (UATH_FAILURE);
	}

	sc->sc_cmdid = (sc->sc_cmdid + 1) % UATH_CMD_LIST_COUNT;

	if (cmd->flags & UATH_CMD_FLAG_READ) {
		/* wait at most two seconds for command reply */
		uath_cmd_lock_init(&sc->rlock);
		err = uath_cmd_lock_wait(&sc->rlock, 2000000);
		cmd->odata = NULL;	/* in case reply comes too late */
		if (err != UATH_SUCCESS) {
			UATH_DEBUG(UATH_DBG_ERR, "uath: uath_cmdsend(): "
			    "timeout waiting for reply, "
			    "to cmd 0x%x (%u), queue %x\n",
			    code, code, cmd->msgid);
			err = UATH_FAILURE;
		} else if (cmd->olen != olen) {
			UATH_DEBUG(UATH_DBG_ERR, "uath: uath_cmdsend(): "
			    "unexpected reply data count "
			    "to cmd 0x%x (%x), got %u, expected %u\n",
			    code, cmd->msgid, cmd->olen, olen);
			err = UATH_FAILURE;
		}
		uath_cmd_lock_destroy(&sc->rlock);
		return (err);
	}

	return (UATH_SUCCESS);
}

/* ARGSUSED */
static void
uath_cmd_txeof(usb_pipe_handle_t pipe, struct usb_bulk_req *req)
{
	struct uath_softc *sc = (struct uath_softc *)req->bulk_client_private;

	UATH_DEBUG(UATH_DBG_TX_CMD, "uath: uath_cmd_txeof(): "
	    "cr:%s(%d), flags:0x%x, tx queued %d\n",
	    usb_str_cr(req->bulk_completion_reason),
	    req->bulk_completion_reason,
	    req->bulk_cb_flags,
	    sc->tx_cmd_queued);

	if (req->bulk_completion_reason != USB_CR_OK)
		sc->sc_tx_err++;

	mutex_enter(&sc->sc_txlock_cmd);
	sc->tx_cmd_queued--;
	mutex_exit(&sc->sc_txlock_cmd);
	usb_free_bulk_req(req);
}

static int
uath_tx_cmd_xfer(struct uath_softc *sc,
    usb_pipe_handle_t pipe, const void *data, uint_t len)
{
	usb_bulk_req_t *send_req;
	mblk_t *mblk;
	int res;

	send_req = usb_alloc_bulk_req(sc->sc_dev, len, USB_FLAGS_SLEEP);

	send_req->bulk_client_private		= (usb_opaque_t)sc;
	send_req->bulk_len			= (int)len;
	send_req->bulk_attributes		= USB_ATTRS_AUTOCLEARING;
	send_req->bulk_timeout			= UATH_CMD_TIMEOUT;
	send_req->bulk_cb			= uath_cmd_txeof;
	send_req->bulk_exc_cb			= uath_cmd_txeof;
	send_req->bulk_completion_reason	= 0;
	send_req->bulk_cb_flags			= 0;

	mblk = send_req->bulk_data;
	bcopy(data, mblk->b_rptr, len);
	mblk->b_wptr += len;

	res = usb_pipe_bulk_xfer(pipe, send_req, USB_FLAGS_NOSLEEP);
	if (res != UATH_SUCCESS) {
		UATH_DEBUG(UATH_DBG_ERR, "uath: uath_tx_cmd_xfer(): "
		    "Error %x writing cmd to bulk/out pipe", res);
		return (UATH_FAILURE);
	}

	mutex_enter(&sc->sc_txlock_cmd);
	sc->tx_cmd_queued++;
	mutex_exit(&sc->sc_txlock_cmd);
	return (UATH_SUCCESS);
}

static void
uath_cmdeof(struct uath_softc *sc, struct uath_cmd *cmd)
{
	struct uath_cmd_hdr *hdr;
	int dlen;

	hdr = (struct uath_cmd_hdr *)cmd->buf;

	hdr->code = BE_32(hdr->code);
	hdr->len = BE_32(hdr->len);
	hdr->magic = BE_32(hdr->magic);	/* target status on return */

	/* NB: msgid is passed thru w/o byte swapping */
	UATH_DEBUG(UATH_DBG_RX_CMD, "uath: uath_cmdeof(): "
	    "%s: [ix %x] len=%x status %x\n",
	    uath_codename(hdr->code),
	    hdr->msgid,
	    hdr->len,
	    hdr->magic);

	switch (hdr->code & 0xff) {
	/* reply to a read command */
	default:
		dlen = hdr->len - sizeof (*hdr);
		UATH_DEBUG(UATH_DBG_RX_CMD, "uath: uath_cmdeof(): "
		    "code %x data len %u\n",
		    hdr->code & 0xff, dlen);

		/*
		 * The first response from the target after the
		 * HOST_AVAILABLE has an invalid msgid so we must
		 * treat it specially.
		 */
		if ((hdr->msgid < UATH_CMD_LIST_COUNT) && (hdr->code != 0x13)) {
			uint32_t *rp = (uint32_t *)(hdr + 1);
			uint_t olen;

			if (!(sizeof (*hdr) <= hdr->len &&
			    hdr->len < UATH_MAX_CMDSZ)) {
				UATH_DEBUG(UATH_DBG_RX_CMD,
				    "uath: uath_cmdeof(): "
				    "invalid WDC msg length %u; "
				    "msg ignored\n",
				    hdr->len);
				return;
			}

			/*
			 * Calculate return/receive payload size; the
			 * first word, if present, always gives the
			 * number of bytes--unless it's 0 in which
			 * case a single 32-bit word should be present.
			 */
			if (dlen >= sizeof (uint32_t)) {
				olen = BE_32(rp[0]);
				dlen -= sizeof (uint32_t);
				if (olen == 0) {
					/* convention is 0 =>'s one word */
					olen = sizeof (uint32_t);
					/* XXX KASSERT(olen == dlen ) */
				}
			} else
				olen = 0;

			if (cmd->odata != NULL) {
				/* NB: cmd->olen validated in uath_cmd */
				if (olen > cmd->olen) {
					/* XXX complain? */
					UATH_DEBUG(UATH_DBG_RX_CMD,
					    "uath: uath_cmdeof(): "
					    "cmd 0x%x olen %u cmd olen %u\n",
					    hdr->code, olen, cmd->olen);
					olen = cmd->olen;
				}
				if (olen > dlen) {
					/* XXX complain, shouldn't happen */
					UATH_DEBUG(UATH_DBG_RX_CMD,
					    "uath: uath_cmdeof(): "
					    "cmd 0x%x olen %u dlen %u\n",
					    hdr->code, olen, dlen);
					olen = dlen;
				}
				/* XXX have submitter do this */
				/* copy answer into caller's supplied buffer */
				bcopy(&rp[1], cmd->odata, olen);
				cmd->olen = olen;
			}
		}

		/* Just signal that something happened */
		uath_cmd_lock_signal(&sc->rlock);
		break;

	case WDCMSG_TARGET_START:
		UATH_DEBUG(UATH_DBG_RX_CMD, "uath: uath_cmdeof(): "
		    "receive TARGET STAERT\n");

		if (hdr->msgid >= UATH_CMD_LIST_COUNT) {
			/* XXX */
			return;
		}
		dlen = hdr->len - sizeof (*hdr);
		if (dlen != sizeof (uint32_t)) {
			/* XXX something wrong */
			return;
		}
		/* XXX have submitter do this */
		/* copy answer into caller's supplied buffer */
		bcopy(hdr + 1, cmd->odata, sizeof (uint32_t));
		cmd->olen = sizeof (uint32_t);

		/* wake up caller */
		uath_cmd_lock_signal(&sc->rlock);
		break;

	case WDCMSG_SEND_COMPLETE:
		/* this notification is sent when UATH_TX_NOTIFY is set */
		UATH_DEBUG(UATH_DBG_RX_CMD, "uath: uath_cmdeof(): "
		    "receive Tx notification\n");
		break;

	case WDCMSG_TARGET_GET_STATS:
		UATH_DEBUG(UATH_DBG_RX_CMD, "uath: uath_cmdeof(): "
		    "received device statistics\n");
		break;
	}
}

/* ARGSUSED */
static void
uath_cmd_rxeof(usb_pipe_handle_t pipe, usb_bulk_req_t *req)
{
	struct uath_softc *sc = (struct uath_softc *)req->bulk_client_private;
	struct uath_cmd_hdr *hdr;
	struct uath_cmd *cmd;
	mblk_t *m, *mp;
	int len;

	UATH_DEBUG(UATH_DBG_RX_CMD, "uath: uath_cmd_rxeof(): "
	    "cr:%s(%d), flags:0x%x, rx queued %d\n",
	    usb_str_cr(req->bulk_completion_reason),
	    req->bulk_completion_reason,
	    req->bulk_cb_flags,
	    sc->rx_cmd_queued);

	m = req->bulk_data;
	req->bulk_data = NULL;

	if (req->bulk_completion_reason != USB_CR_OK) {
		UATH_DEBUG(UATH_DBG_RX_CMD, "uath: uath_cmd_rxeof(): "
		    "USB CR is not OK\n");
		goto fail;
	}

	if (m->b_cont != NULL) {
		/* Fragmented message, concatenate */
		mp = msgpullup(m, -1);
		freemsg(m);
		m = mp;
		mp = NULL;
	}

	len = msgdsize(m);
	if (len < sizeof (struct uath_cmd_hdr)) {
		UATH_DEBUG(UATH_DBG_RX_CMD, "uath: uath_rx_cmdeof(): "
		    "short xfer error\n");
		goto fail;
	}

	hdr = (struct uath_cmd_hdr *)m->b_rptr;
	if (BE_32(hdr->code) == 0x13)
		cmd = &sc->sc_cmd[0];
	else
		cmd = &sc->sc_cmd[hdr->msgid];

	bcopy(m->b_rptr, cmd->buf, len);
	uath_cmdeof(sc, cmd);
	(void) uath_rx_cmd_xfer(sc);
fail:
	mutex_enter(&sc->sc_rxlock_cmd);
	sc->rx_cmd_queued--;
	mutex_exit(&sc->sc_rxlock_cmd);
	if (m) freemsg(m);
	usb_free_bulk_req(req);
}

static int
uath_rx_cmd_xfer(struct uath_softc *sc)
{
	usb_bulk_req_t *req;
	int err;

	req = usb_alloc_bulk_req(sc->sc_dev, UATH_MAX_CMDSZ, USB_FLAGS_SLEEP);
	if (req == NULL) {
		UATH_DEBUG(UATH_DBG_MSG, "uath: uath_rx_cmd_xfer(): "
		    "failed to allocate req");
		return (UATH_FAILURE);
	}

	req->bulk_len			= UATH_MAX_CMDSZ;
	req->bulk_client_private	= (usb_opaque_t)sc;
	req->bulk_cb			= uath_cmd_rxeof;
	req->bulk_exc_cb		= uath_cmd_rxeof;
	req->bulk_timeout		= 0;
	req->bulk_completion_reason	= 0;
	req->bulk_cb_flags		= 0;
	req->bulk_attributes		= USB_ATTRS_SHORT_XFER_OK
	    | USB_ATTRS_AUTOCLEARING;

	err = usb_pipe_bulk_xfer(sc->rx_cmd_pipe, req, USB_FLAGS_NOSLEEP);
	if (err != USB_SUCCESS) {
		UATH_DEBUG(UATH_DBG_MSG, "uath: uath_rx_cmd_xfer(): "
		    "failed to do rx xfer, %d", err);
		usb_free_bulk_req(req);
		return (UATH_FAILURE);
	}

	mutex_enter(&sc->sc_rxlock_cmd);
	sc->rx_cmd_queued++;
	mutex_exit(&sc->sc_rxlock_cmd);
	return (UATH_SUCCESS);
}

static void
uath_init_data_queue(struct uath_softc *sc)
{
	sc->tx_data_queued = sc->rx_data_queued = 0;
}

/* ARGSUSED */
static void
uath_data_txeof(usb_pipe_handle_t pipe, usb_bulk_req_t *req)
{
	struct uath_softc *sc = (struct uath_softc *)req->bulk_client_private;
	struct ieee80211com *ic = &sc->sc_ic;

	UATH_DEBUG(UATH_DBG_TX, "uath: uath_data_txeof(): "
	    "uath_txeof(): cr:%s(%d), flags:0x%x, tx_data_queued %d\n",
	    usb_str_cr(req->bulk_completion_reason),
	    req->bulk_completion_reason,
	    req->bulk_cb_flags,
	    sc->tx_data_queued);

	if (req->bulk_completion_reason != USB_CR_OK)
		sc->sc_tx_err++;

	mutex_enter(&sc->sc_txlock_data);
	sc->tx_data_queued--;

	if (sc->sc_need_sched) {
		sc->sc_need_sched = 0;
		mac_tx_update(ic->ic_mach);
	}

	mutex_exit(&sc->sc_txlock_data);
	usb_free_bulk_req(req);
}

static int
uath_tx_data_xfer(struct uath_softc *sc, mblk_t *mp)
{
	usb_bulk_req_t *req;
	int err;

	req = usb_alloc_bulk_req(sc->sc_dev, 0, USB_FLAGS_SLEEP);
	if (req == NULL) {
		UATH_DEBUG(UATH_DBG_TX, "uath: uath_tx_data_xfer(): "
		    "uath_tx_data_xfer(): failed to allocate req");
		freemsg(mp);
		return (UATH_FAILURE);
	}

	req->bulk_len			= msgdsize(mp);
	req->bulk_data			= mp;
	req->bulk_client_private 	= (usb_opaque_t)sc;
	req->bulk_timeout		= UATH_DATA_TIMEOUT;
	req->bulk_attributes		= USB_ATTRS_AUTOCLEARING;
	req->bulk_cb			= uath_data_txeof;
	req->bulk_exc_cb		= uath_data_txeof;
	req->bulk_completion_reason 	= 0;
	req->bulk_cb_flags		= 0;

	if ((err = usb_pipe_bulk_xfer(sc->tx_data_pipe, req, 0)) !=
	    USB_SUCCESS) {

		UATH_DEBUG(UATH_DBG_TX, "uath: uath_tx_data_xfer(): "
		    "failed to do tx xfer, %d", err);
		usb_free_bulk_req(req);
		return (UATH_FAILURE);
	}

	sc->tx_data_queued++;
	return (UATH_SUCCESS);
}

/* ARGSUSED */
static void
uath_data_rxeof(usb_pipe_handle_t pipe, usb_bulk_req_t *req)
{
	struct uath_softc *sc = (struct uath_softc *)req->bulk_client_private;
	struct ieee80211com *ic = &sc->sc_ic;
	struct uath_chunk *chunk;
	struct uath_rx_desc *desc;
	struct ieee80211_frame *wh;
	struct ieee80211_node *ni;

	mblk_t *m, *mp;
	uint8_t *rxbuf;
	int actlen, pktlen;

	mutex_enter(&sc->sc_rxlock_data);

	UATH_DEBUG(UATH_DBG_RX, "uath: uath_data_rxeof(): "
	    "cr:%s(%d), flags:0x%x, rx_data_queued %d\n",
	    usb_str_cr(req->bulk_completion_reason),
	    req->bulk_completion_reason,
	    req->bulk_cb_flags,
	    sc->rx_data_queued);

	mp = req->bulk_data;
	req->bulk_data = NULL;

	if (req->bulk_completion_reason != USB_CR_OK) {
		UATH_DEBUG(UATH_DBG_RX, "uath: uath_data_rxeof(): "
		    "USB CR is not OK\n");
		sc->sc_rx_err++;
		goto fail;
	}

	rxbuf = (uint8_t *)mp->b_rptr;
	actlen = (uintptr_t)mp->b_wptr - (uintptr_t)mp->b_rptr;
	if (actlen < UATH_MIN_RXBUFSZ) {
		UATH_DEBUG(UATH_DBG_RX, "uath_data_rxeof(): "
		    "wrong recv size %d\n", actlen);
		sc->sc_rx_err++;
		goto fail;
	}

	chunk = (struct uath_chunk *)rxbuf;
	if (chunk->seqnum == 0 && chunk->flags == 0 && chunk->length == 0) {
		UATH_DEBUG(UATH_DBG_RX, "uath: uath_data_rxeof(): "
		    "strange response\n");
		UATH_RESET_INTRX(sc);
		sc->sc_rx_err++;
		goto fail;
	}

	if (chunk->seqnum != sc->sc_intrx_nextnum) {
		UATH_DEBUG(UATH_DBG_RX, "uath: uath_data_rxeof(): "
		    "invalid seqnum %d, expected %d\n",
		    chunk->seqnum, sc->sc_intrx_nextnum);
		UATH_STAT_INC(sc, st_badchunkseqnum);
		UATH_RESET_INTRX(sc);
		sc->sc_rx_err++;
		goto fail;
	}

	/* check multi-chunk frames  */
	if ((chunk->seqnum == 0 && !(chunk->flags & UATH_CFLAGS_FINAL)) ||
	    (chunk->seqnum != 0 && (chunk->flags & UATH_CFLAGS_FINAL)) ||
	    chunk->flags & UATH_CFLAGS_RXMSG) {
		UATH_DEBUG(UATH_DBG_RX, "uath: uath_data_rxeof(): "
		    "receive multi-chunk frames "
		    "chunk seqnum %x, flags %x, length %u\n",
		    chunk->seqnum, chunk->flags, BE_16(chunk->length));
		UATH_STAT_INC(sc, st_multichunk);
	}


	/* if the frame is not final continue the transfer  */
	if (!(chunk->flags & UATH_CFLAGS_FINAL))
		sc->sc_intrx_nextnum++;

	/*
	 * if the frame is not set UATH_CFLAGS_RXMSG, then rx descriptor is
	 * located at the end, 32-bit aligned
	 */
	desc = (chunk->flags & UATH_CFLAGS_RXMSG) ?
	    (struct uath_rx_desc *)(chunk + 1) :
	    (struct uath_rx_desc *)(((uint8_t *)chunk) +
	    sizeof (struct uath_chunk) + BE_16(chunk->length) -
	    sizeof (struct uath_rx_desc));

	UATH_DEBUG(UATH_DBG_RX, "uath: uath_data_rxeof(): "
	    "frame len %u code %u status %u rate %u antenna %u "
	    "rssi %d channel %u phyerror %u connix %u "
	    "decrypterror %u keycachemiss %u\n",
	    BE_32(desc->framelen), BE_32(desc->code), BE_32(desc->status),
	    BE_32(desc->rate), BE_32(desc->antenna), BE_32(desc->rssi),
	    BE_32(desc->channel), BE_32(desc->phyerror), BE_32(desc->connix),
	    BE_32(desc->decrypterror), BE_32(desc->keycachemiss));

	if (BE_32(desc->len) > IEEE80211_MAX_LEN) {
		UATH_DEBUG(UATH_DBG_RX, "uath: uath_data_rxeof(): "
		    "bad descriptor (len=%d)\n", BE_32(desc->len));
		UATH_STAT_INC(sc, st_toobigrxpkt);
		goto fail;
	}

	uath_update_rxstat(sc, BE_32(desc->status));

	pktlen = BE_32(desc->framelen) - UATH_RX_DUMMYSIZE;

	if ((m = allocb(pktlen, BPRI_MED)) == NULL) {
		UATH_DEBUG(UATH_DBG_RX, "uath: uath_data_rxeof(): "
		    "allocate mblk failed.\n");
		sc->sc_rx_nobuf++;
		goto fail;
	}
	bcopy((rxbuf + sizeof (struct uath_chunk)), m->b_rptr, pktlen);

	m->b_wptr = m->b_rptr + pktlen;
	wh = (struct ieee80211_frame *)m->b_rptr;
	ni = ieee80211_find_rxnode(ic, wh);

	/* send the frame to the 802.11 layer */
	(void) ieee80211_input(ic, m, ni, (int)BE_32(desc->rssi), 0);

	/* node is no longer needed */
	ieee80211_free_node(ni);
fail:
	sc->rx_data_queued--;
	if (mp) freemsg(mp);
	usb_free_bulk_req(req);
	mutex_exit(&sc->sc_rxlock_data);
	if (UATH_IS_RUNNING(sc) && !UATH_IS_SUSPEND(sc)) {
		(void) uath_rx_data_xfer(sc);
	}
}

static int
uath_rx_data_xfer(struct uath_softc *sc)
{
	usb_bulk_req_t *req;
	int err;

	req = usb_alloc_bulk_req(sc->sc_dev,
	    IEEE80211_MAX_LEN, USB_FLAGS_SLEEP);
	if (req == NULL) {
		UATH_DEBUG(UATH_DBG_ERR, "uath: uath_rx_data_xfer(): "
		    "failed to allocate req");
		return (UATH_SUCCESS);
	}

	req->bulk_len			= IEEE80211_MAX_LEN;
	req->bulk_cb			= uath_data_rxeof;
	req->bulk_exc_cb		= uath_data_rxeof;
	req->bulk_client_private	= (usb_opaque_t)sc;
	req->bulk_timeout		= 0;
	req->bulk_completion_reason	= 0;
	req->bulk_cb_flags		= 0;
	req->bulk_attributes		= USB_ATTRS_SHORT_XFER_OK
	    | USB_ATTRS_AUTOCLEARING;

	err = usb_pipe_bulk_xfer(sc->rx_data_pipe, req, 0);
	if (err != UATH_SUCCESS) {
		UATH_DEBUG(UATH_DBG_ERR, "uath: uath_rx_data_xfer(): "
		    "failed to do rx xfer, %d", err);
		usb_free_bulk_req(req);
		return (UATH_FAILURE);
	}

	mutex_enter(&sc->sc_rxlock_data);
	sc->rx_data_queued++;
	mutex_exit(&sc->sc_rxlock_data);
	return (UATH_SUCCESS);
}

static void
uath_update_rxstat(struct uath_softc *sc, uint32_t status)
{

	switch (status) {
	case UATH_STATUS_STOP_IN_PROGRESS:
		UATH_STAT_INC(sc, st_stopinprogress);
		break;
	case UATH_STATUS_CRC_ERR:
		UATH_STAT_INC(sc, st_crcerr);
		break;
	case UATH_STATUS_PHY_ERR:
		UATH_STAT_INC(sc, st_phyerr);
		break;
	case UATH_STATUS_DECRYPT_CRC_ERR:
		UATH_STAT_INC(sc, st_decrypt_crcerr);
		break;
	case UATH_STATUS_DECRYPT_MIC_ERR:
		UATH_STAT_INC(sc, st_decrypt_micerr);
		break;
	case UATH_STATUS_DECOMP_ERR:
		UATH_STAT_INC(sc, st_decomperr);
		break;
	case UATH_STATUS_KEY_ERR:
		UATH_STAT_INC(sc, st_keyerr);
		break;
	case UATH_STATUS_ERR:
		UATH_STAT_INC(sc, st_err);
		break;
	default:
		break;
	}
}

static void
uath_next_scan(void *arg)
{
	struct uath_softc	*sc = arg;
	struct ieee80211com	*ic = &sc->sc_ic;

	if (ic->ic_state == IEEE80211_S_SCAN)
		ieee80211_next_scan(ic);

	sc->sc_scan_id = 0;
}

static int
uath_create_connection(struct uath_softc *sc, uint32_t connid)
{
	const struct ieee80211_rateset *rs;
	struct ieee80211com *ic = &sc->sc_ic;
	struct ieee80211_node *ni = ic->ic_bss;
	struct uath_cmd_create_connection create;
	int err;

	bzero(&create, sizeof (create));
	create.connid = BE_32(connid);
	create.bssid = BE_32(0);
	/* XXX packed or not?  */
	create.size = BE_32(sizeof (struct uath_cmd_rateset));

	rs = &ni->in_rates;
	create.connattr.rateset.length = rs->ir_nrates;
	bcopy(rs->ir_rates, &create.connattr.rateset.set[0],
	    rs->ir_nrates);

	/* XXX turbo */
	if (UATH_IS_CHAN_A(ni->in_chan))
		create.connattr.wlanmode = BE_32(WLAN_MODE_11a);
	else if (UATH_IS_CHAN_ANYG(ni->in_chan))
		create.connattr.wlanmode = BE_32(WLAN_MODE_11g);
	else
		create.connattr.wlanmode = BE_32(WLAN_MODE_11b);

	err = uath_cmd_write(sc, WDCMSG_CREATE_CONNECTION, &create,
	    sizeof (create), 0);
	return (err);
}

static int
uath_set_rates(struct uath_softc *sc, const struct ieee80211_rateset *rs)
{
	struct uath_cmd_rates rates;
	int err;

	bzero(&rates, sizeof (rates));
	rates.connid = BE_32(UATH_ID_BSS);		/* XXX */
	rates.size   = BE_32(sizeof (struct uath_cmd_rateset));
	/* XXX bounds check rs->rs_nrates */
	rates.rateset.length = rs->ir_nrates;
	bcopy(rs->ir_rates, &rates.rateset.set[0], rs->ir_nrates);

	UATH_DEBUG(UATH_DBG_MSG, "uath: uath_set_rates(): "
	    "setting supported rates nrates=%d\n", rs->ir_nrates);
	err = uath_cmd_write(sc, WDCMSG_SET_BASIC_RATE,
	    &rates, sizeof (rates), 0);
	return (err);
}

static int
uath_write_associd(struct uath_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct ieee80211_node *ni = ic->ic_bss;
	struct uath_cmd_set_associd associd;
	int err;

	bzero(&associd, sizeof (associd));
	associd.defaultrateix = BE_32(1);	/* XXX */
	associd.associd = BE_32(ni->in_associd);
	associd.timoffset = BE_32(0x3b);	/* XXX */
	IEEE80211_ADDR_COPY(associd.bssid, ni->in_bssid);
	err = uath_cmd_write(sc, WDCMSG_WRITE_ASSOCID, &associd,
	    sizeof (associd), 0);
	return (err);
}

static int
uath_set_ledsteady(struct uath_softc *sc, int lednum, int ledmode)
{
	struct uath_cmd_ledsteady led;
	int err;

	led.lednum = BE_32(lednum);
	led.ledmode = BE_32(ledmode);

	UATH_DEBUG(UATH_DBG_MSG, "uath: uath_set_ledsteady(): "
	    "set %s led %s (steady)\n",
	    (lednum == UATH_LED_LINK) ? "link" : "activity",
	    ledmode ? "on" : "off");
	err = uath_cmd_write(sc, WDCMSG_SET_LED_STEADY, &led, sizeof (led), 0);
	return (err);
}

static int
uath_set_ledblink(struct uath_softc *sc, int lednum, int ledmode,
    int blinkrate, int slowmode)
{
	struct uath_cmd_ledblink led;
	int err;

	led.lednum = BE_32(lednum);
	led.ledmode = BE_32(ledmode);
	led.blinkrate = BE_32(blinkrate);
	led.slowmode = BE_32(slowmode);

	UATH_DEBUG(UATH_DBG_MSG, "uath: uath_set_ledblink(): "
	    "set %s led %s (blink)\n",
	    (lednum == UATH_LED_LINK) ? "link" : "activity",
	    ledmode ? "on" : "off");

	err = uath_cmd_write(sc, WDCMSG_SET_LED_BLINK,
	    &led, sizeof (led), 0);
	return (err);
}


static int
uath_newstate(struct ieee80211com *ic, enum ieee80211_state nstate, int arg)
{
	struct uath_softc *sc = (struct uath_softc *)ic;
	struct ieee80211_node *ni = ic->ic_bss;
	enum ieee80211_state ostate;
	int err;

	ostate = ic->ic_state;
	UATH_DEBUG(UATH_DBG_MSG, "uath: uath_newstate(): "
	    "%d -> %d\n", ostate, nstate);

	if (sc->sc_scan_id != 0) {
		(void) untimeout(sc->sc_scan_id);
		sc->sc_scan_id = 0;
	}

	UATH_LOCK(sc);

	if (UATH_IS_DISCONNECT(sc) && (nstate != IEEE80211_S_INIT)) {
		UATH_UNLOCK(sc);
		return (DDI_SUCCESS);
	}

	if (UATH_IS_SUSPEND(sc) && (nstate != IEEE80211_S_INIT)) {
		UATH_UNLOCK(sc);
		return (DDI_SUCCESS);
	}

	switch (nstate) {
	case IEEE80211_S_INIT:
		if (ostate == IEEE80211_S_RUN) {
			/* turn link and activity LEDs off */
			(void) uath_set_ledstate(sc, 0);
		}
		break;
	case IEEE80211_S_SCAN:
		if (uath_switch_channel(sc, ic->ic_curchan) != UATH_SUCCESS) {
			UATH_DEBUG(UATH_DBG_ERR, "uath: uath_newstate(): "
			    "could not switch channel\n");
			break;
		}
		sc->sc_scan_id = timeout(uath_next_scan, (void *)sc,
		    drv_usectohz(250000));
		break;
	case IEEE80211_S_AUTH:
		/* XXX good place?  set RTS threshold  */
		uath_config(sc, CFG_USER_RTS_THRESHOLD, ic->ic_rtsthreshold);

		if (uath_switch_channel(sc, ni->in_chan) != 0) {
			UATH_DEBUG(UATH_DBG_ERR, "uath: uath_newstate(): "
			    "could not switch channel\n");
			break;
		}
		if (uath_create_connection(sc, UATH_ID_BSS) != 0) {
			UATH_DEBUG(UATH_DBG_ERR, "uath: uath_newstate(): "
			    "could not create connection\n");
			break;
		}
		break;
	case IEEE80211_S_ASSOC:
		if (uath_set_rates(sc, &ni->in_rates) != 0) {
			UATH_DEBUG(UATH_DBG_ERR, "uath: uath_newstate(): "
			    "could not set negotiated rate set\n");
			break;
		}
		break;
	case IEEE80211_S_RUN:
		/* XXX monitor mode doesn't be supported  */
		if (ic->ic_opmode == IEEE80211_M_MONITOR) {
			(void) uath_set_ledstate(sc, 1);
			break;
		}

		/*
		 * Tx rate is controlled by firmware, report the maximum
		 * negotiated rate in ifconfig output.
		 */
		ni->in_txrate = ni->in_rates.ir_nrates - 1;

		if (uath_write_associd(sc) != 0) {
			UATH_DEBUG(UATH_DBG_ERR, "uath: uath_newstate(): "
			    "could not write association id\n");
			break;
		}
		/* turn link LED on */
		(void) uath_set_ledsteady(sc, UATH_LED_LINK, UATH_LED_ON);
		/* make activity LED blink */
		(void) uath_set_ledblink(sc, UATH_LED_ACTIVITY,
		    UATH_LED_ON, 1, 2);
		/* set state to associated */
		(void) uath_set_ledstate(sc, 1);
		break;
	}

	UATH_UNLOCK(sc);

	err = sc->sc_newstate(ic, nstate, arg);
	return (err);
}

static int
uath_send(ieee80211com_t *ic, mblk_t *mp, uint8_t type)
{
	struct uath_softc *sc = (struct uath_softc *)ic;
	struct uath_chunk *chunk;
	struct uath_tx_desc *desc;
	struct ieee80211_frame *wh;
	struct ieee80211_node *ni = NULL;
	struct ieee80211_key *k;

	mblk_t *m, *m0;
	int err, off, mblen;
	int pktlen, framelen, msglen;

	err = UATH_SUCCESS;

	mutex_enter(&sc->sc_txlock_data);

	if (UATH_IS_SUSPEND(sc)) {
		err = 0;
		goto fail;
	}

	if (sc->tx_data_queued > UATH_TX_DATA_LIST_COUNT) {
		UATH_DEBUG(UATH_DBG_TX, "uath: uath_send(): "
		    "no TX buffer available!\n");
		if ((type & IEEE80211_FC0_TYPE_MASK) ==
		    IEEE80211_FC0_TYPE_DATA) {
			sc->sc_need_sched = 1;
		}
		sc->sc_tx_nobuf++;
		err = ENOMEM;
		goto fail;
	}

	m = allocb(UATH_MAX_TXBUFSZ, BPRI_MED);
	if (m == NULL) {
		UATH_DEBUG(UATH_DBG_TX, "uath: uath_send(): "
		    "can't alloc mblk.\n");
		err = DDI_FAILURE;
		goto fail;
	}

	/* skip TX descriptor */
	m->b_rptr += sizeof (struct uath_chunk) + sizeof (struct uath_tx_desc);
	m->b_wptr += sizeof (struct uath_chunk) + sizeof (struct uath_tx_desc);

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
			freemsg(m);
			err = DDI_FAILURE;
			goto fail;
		}
		/* packet header may have moved, reset our local pointer */
		wh = (struct ieee80211_frame *)m->b_rptr;
	}

	pktlen = (uintptr_t)m->b_wptr - (uintptr_t)m->b_rptr;
	framelen = pktlen + IEEE80211_CRC_LEN;
	msglen = framelen + sizeof (struct uath_tx_desc);

	m->b_rptr -= sizeof (struct uath_chunk) + sizeof (struct uath_tx_desc);

	chunk = (struct uath_chunk *)m->b_rptr;
	desc = (struct uath_tx_desc *)(chunk + 1);

	/* one chunk only for now */
	chunk->seqnum = 0;
	chunk->flags = UATH_CFLAGS_FINAL;
	chunk->length = BE_16(msglen);

	/* fill Tx descriptor */
	desc->msglen = BE_32(msglen);
	/* NB: to get UATH_TX_NOTIFY reply, `msgid' must be larger than 0  */
	desc->msgid  = sc->sc_msgid; /* don't care about endianness */
	desc->type   = BE_32(WDCMSG_SEND);
	switch (wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) {
	case IEEE80211_FC0_TYPE_CTL:
	case IEEE80211_FC0_TYPE_MGT:
		/* NB: force all management frames to highest queue */
		if (ni->in_flags & UATH_NODE_QOS) {
			/* NB: force all management frames to highest queue */
			desc->txqid = BE_32(WME_AC_VO | UATH_TXQID_MINRATE);
		} else
			desc->txqid = BE_32(WME_AC_BE | UATH_TXQID_MINRATE);
		break;
	case IEEE80211_FC0_TYPE_DATA:
		/* XXX multicast frames should honor mcastrate */
		desc->txqid = BE_32(WME_AC_BE);
		break;
	default:
		UATH_DEBUG(UATH_DBG_TX, "uath: uath_send(): "
		    "bogus frame type 0x%x (%s)\n",
		    wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK);
		err = EIO;
		goto fail;
	}

	if (ic->ic_state == IEEE80211_S_AUTH ||
	    ic->ic_state == IEEE80211_S_ASSOC ||
	    ic->ic_state == IEEE80211_S_RUN)
		desc->connid = BE_32(UATH_ID_BSS);
	else
		desc->connid = BE_32(UATH_ID_INVALID);
	desc->flags  = BE_32(0 /* no UATH_TX_NOTIFY */);
	desc->buflen = BE_32(pktlen);

	(void) uath_tx_data_xfer(sc, m);

	sc->sc_msgid = (sc->sc_msgid + 1) % UATH_TX_DATA_LIST_COUNT;

	ic->ic_stats.is_tx_frags++;
	ic->ic_stats.is_tx_bytes += pktlen;

fail:
	if (ni != NULL)
		ieee80211_free_node(ni);
	if ((mp) &&
	    ((type & IEEE80211_FC0_TYPE_MASK) != IEEE80211_FC0_TYPE_DATA ||
	    err == 0)) {
		freemsg(mp);
	}
	mutex_exit(&sc->sc_txlock_data);
	return (err);
}

static int
uath_reconnect(dev_info_t *devinfo)
{
	struct uath_softc *sc;
	struct ieee80211com *ic;
	int err;
	uint16_t vendor_id, product_id;

	UATH_DEBUG(UATH_DBG_MSG, "uath: uath_reconnect(): "
	    "uath online\n");

	sc = ddi_get_soft_state(uath_soft_state_p, ddi_get_instance(devinfo));
	ASSERT(sc != NULL);
	ic = (struct ieee80211com *)&sc->sc_ic;

	if (!UATH_IS_RECONNECT(sc)) {
		err = uath_open_pipes(sc);
		if (err != UATH_SUCCESS) {
			UATH_DEBUG(UATH_DBG_ERR, "uath: uath_reconnect(): "
			    "could not open pipes\n");
			return (DDI_FAILURE);
		}

		err = uath_loadfirmware(sc);
		if (err != DDI_SUCCESS) {
			UATH_DEBUG(UATH_DBG_ERR, "uath: uath_reconnect(): "
			    "could not download firmware\n");
			return (DDI_FAILURE);
		}

		uath_close_pipes(sc);
		usb_client_detach(sc->sc_dev, sc->sc_udev);

		/* reset device */
		err = usb_reset_device(sc->sc_dev, USB_RESET_LVL_DEFAULT);
		if (err != USB_SUCCESS) {
			UATH_DEBUG(UATH_DBG_ERR, "uath: uath_reconnect(): "
			    "could not reset device %x\n", err);
		}

		err = usb_client_attach(devinfo, USBDRV_VERSION, 0);
		if (err != USB_SUCCESS) {
			UATH_DEBUG(UATH_DBG_ERR, "uath: uath_reconnect(): "
			    "usb_client_attach failed\n");
		}

		err = usb_get_dev_data(devinfo, &sc->sc_udev,
		    USB_PARSE_LVL_ALL, 0);
		if (err != USB_SUCCESS) {
			sc->sc_udev = NULL;
			UATH_DEBUG(UATH_DBG_ERR, "uath: uath_reconnect(): "
			    "usb_get_dev_data failed\n");
		}

		vendor_id = sc->sc_udev->dev_descr->idVendor;
		product_id = sc->sc_udev->dev_descr->idProduct;
		sc->dev_flags = uath_lookup(vendor_id, product_id);
		if (sc->dev_flags == UATH_FLAG_ERR) {
			UATH_DEBUG(UATH_DBG_ERR, "uath: uath_reconnect(): "
			    "HW does not match\n");
		}

		UATH_DEBUG(UATH_DBG_MSG, "uath: uath_reconnect(): "
		    "vendorId = %x,deviceID = %x, flags = %x\n",
		    vendor_id, product_id, sc->dev_flags);

		UATH_LOCK(sc);
		sc->sc_flags |= UATH_FLAG_RECONNECT;
		UATH_UNLOCK(sc);

	} else {
		err = uath_open_pipes(sc);
		if (err != UATH_SUCCESS) {
			UATH_DEBUG(UATH_DBG_ERR, "uath: uath_reconnect(): "
			    "could not open pipes\n");
			return (DDI_FAILURE);
		}

		/*
		 * Allocate xfers for firmware commands.
		 */
		err = uath_alloc_cmd_list(sc, sc->sc_cmd, UATH_CMD_LIST_COUNT,
		    UATH_MAX_CMDSZ);
		if (err != UATH_SUCCESS) {
			UATH_DEBUG(UATH_DBG_ERR, "uath: uath_reconnect(): "
			    "could not allocate Tx command list\n");
			return (DDI_FAILURE);
		}

		err = uath_init_cmd_list(sc);
		if (err != UATH_SUCCESS) {
			UATH_DEBUG(UATH_DBG_ERR, "uath: uath_reconnect(): "
			    "could not init RX command list\n");
			return (DDI_FAILURE);
		}

		/*
		 * We're now ready to send+receive firmware commands.
		 */
		err = uath_host_available(sc);
		if (err != UATH_SUCCESS) {
			UATH_DEBUG(UATH_DBG_ERR, "uath: uath_reconnect(): "
			    "could not initialize adapter\n");
			return (DDI_FAILURE);
		}

		err = uath_get_devcap(sc);
		if (err != UATH_SUCCESS) {
			UATH_DEBUG(UATH_DBG_ERR, "uath: uath_reconnect(): "
			    "could not get device capabilities\n");
			return (DDI_FAILURE);
		}

		err = uath_get_devstatus(sc, ic->ic_macaddr);
		if (err != UATH_SUCCESS) {
			UATH_DEBUG(UATH_DBG_ERR, "uath: uath_reconnect(): "
			    "could not get dev status\n");
			return (DDI_FAILURE);
		}

		err = usb_check_same_device(sc->sc_dev, NULL, USB_LOG_L2, -1,
		    USB_CHK_BASIC, NULL);
		if (err != USB_SUCCESS) {
			UATH_DEBUG(UATH_DBG_ERR, "uath: uath_reconnect(): "
			    "different device connected %x\n", err);
			return (DDI_FAILURE);
		}

		err = uath_init(sc);
		if (err != UATH_SUCCESS) {
			UATH_DEBUG(UATH_DBG_ERR, "uath: uath_reconnect(): "
			    "device re-connect failed\n");
			return (DDI_FAILURE);
		}

		UATH_LOCK(sc);
		sc->sc_flags &= ~UATH_FLAG_RECONNECT;
		sc->sc_flags &= ~UATH_FLAG_DISCONNECT;
		sc->sc_flags |= UATH_FLAG_RUNNING;
		UATH_UNLOCK(sc);
	}

	return (DDI_SUCCESS);
}

static int
uath_disconnect(dev_info_t *devinfo)
{
	struct uath_softc *sc;
	struct ieee80211com *ic;

	/*
	 * We can't call uath_stop() here, since the hardware is removed,
	 * we can't access the register anymore.
	 */
	sc = ddi_get_soft_state(uath_soft_state_p, ddi_get_instance(devinfo));
	ASSERT(sc != NULL);

	if (sc->sc_flags & UATH_FLAG_RECONNECT) {
		UATH_DEBUG(UATH_DBG_MSG, "uath: uath_disconnect(): "
		    "stage 0 in re-connect\n");
		uath_close_pipes(sc);
		return (DDI_SUCCESS);
	}

	UATH_LOCK(sc);
	sc->sc_flags |= UATH_FLAG_DISCONNECT;
	UATH_UNLOCK(sc);

	ic = (struct ieee80211com *)&sc->sc_ic;
	ieee80211_new_state(ic, IEEE80211_S_INIT, -1);

	UATH_LOCK(sc);
	sc->sc_flags &= ~UATH_FLAG_RUNNING;	/* STOP */
	UATH_UNLOCK(sc);

	/* abort and free xfers */
	uath_free_cmd_list(sc->sc_cmd, UATH_CMD_LIST_COUNT);

	/* close Tx/Rx pipes */
	uath_close_pipes(sc);

	UATH_DEBUG(UATH_DBG_MSG, "uath: uath_disconnect(): "
	    "offline success\n");

	return (DDI_SUCCESS);
}

static int
uath_dataflush(struct uath_softc *sc)
{
	struct uath_chunk *chunk;
	struct uath_tx_desc *desc;
	uint8_t *buf;
	int err;

	buf = kmem_alloc(UATH_MAX_TXBUFSZ, KM_NOSLEEP);
	if (buf == NULL) {
		UATH_DEBUG(UATH_DBG_ERR, "uath: uath_dataflush(): "
		    "no bufs\n");
		return (ENOBUFS);
	}

	chunk = (struct uath_chunk *)buf;
	desc = (struct uath_tx_desc *)(chunk + 1);

	/* one chunk only */
	chunk->seqnum = 0;
	chunk->flags = UATH_CFLAGS_FINAL;
	chunk->length = BE_16(sizeof (struct uath_tx_desc));

	bzero(desc, sizeof (struct uath_tx_desc));
	desc->msglen = BE_32(sizeof (struct uath_tx_desc));
	desc->msgid  = sc->sc_msgid; /* don't care about endianness */
	desc->type   = BE_32(WDCMSG_FLUSH);
	desc->txqid  = BE_32(0);
	desc->connid = BE_32(0);
	desc->flags  = BE_32(0);

	UATH_DEBUG(UATH_DBG_MSG, "uath: uath_dataflush(): "
	    "send flush ix %d\n", desc->msgid);

	err = uath_fw_send(sc, sc->tx_data_pipe, buf,
	    sizeof (struct uath_chunk) + sizeof (struct uath_tx_desc));
	if (err != UATH_SUCCESS) {
		UATH_DEBUG(UATH_DBG_ERR, "uath: uath_dataflush(): "
		    "data flush error");
		return (UATH_FAILURE);
	}

	kmem_free(buf, UATH_MAX_TXBUFSZ);
	sc->sc_msgid = (sc->sc_msgid + 1) % UATH_TX_DATA_LIST_COUNT;

	return (UATH_SUCCESS);
}

static int
uath_cmdflush(struct uath_softc *sc)
{
	return (uath_cmd_write(sc, WDCMSG_FLUSH, NULL, 0, 0));
}

static int
uath_flush(struct uath_softc *sc)
{
	int err;

	err = uath_dataflush(sc);
	if (err != UATH_SUCCESS)
		goto failed;

	err = uath_cmdflush(sc);
	if (err != UATH_SUCCESS)
		goto failed;

	return (UATH_SUCCESS);
failed:
	return (err);
}

static int
uath_set_ledstate(struct uath_softc *sc, int connected)
{
	int err;

	UATH_DEBUG(UATH_DBG_MSG, "uath: uath_set_ledstate(): "
	    "set led state %sconnected\n", connected ? "" : "!");

	connected = BE_32(connected);
	err = uath_cmd_write(sc, WDCMSG_SET_LED_STATE,
	    &connected, sizeof (connected), 0);
	return (err);
}

static int
uath_config_multi(struct uath_softc *sc, uint32_t reg, const void *data,
    int len)
{
	struct uath_write_mac write;
	int err;

	write.reg = BE_32(reg);
	write.len = BE_32(len);
	bcopy(data, write.data, len);

	/* properly handle the case where len is zero (reset) */
	err = uath_cmd_write(sc, WDCMSG_TARGET_SET_CONFIG, &write,
	    (len == 0) ? sizeof (uint32_t) : 2 * sizeof (uint32_t) + len, 0);
	if (err != UATH_SUCCESS) {
		UATH_DEBUG(UATH_DBG_MSG, "uath: uath_config_multi(): "
		    "could not write %d bytes to register 0x%02x\n", len, reg);
	}
	return (err);
}

static void
uath_config(struct uath_softc *sc, uint32_t reg, uint32_t val)
{
	struct uath_write_mac write;
	int err;

	write.reg = BE_32(reg);
	write.len = BE_32(0);	/* 0 = single write */
	*(uint32_t *)write.data = BE_32(val);

	err = uath_cmd_write(sc, WDCMSG_TARGET_SET_CONFIG, &write,
	    3 * sizeof (uint32_t), 0);
	if (err != UATH_SUCCESS) {
		UATH_DEBUG(UATH_DBG_MSG, "uath: uath_config(): "
		    "could not write register 0x%02x\n",
		    reg);
	}
}

static int
uath_switch_channel(struct uath_softc *sc, struct ieee80211_channel *c)
{
	int err;

	/* set radio frequency */
	err = uath_set_chan(sc, c);
	if (err) {
		UATH_DEBUG(UATH_DBG_ERR, "uath: uath_switch_channel(): "
		    "could not set channel\n");
		goto failed;
	}

	/* reset Tx rings */
	err = uath_reset_tx_queues(sc);
	if (err) {
		UATH_DEBUG(UATH_DBG_ERR, "uath: uath_switch_channel(): "
		    "could not reset Tx queues\n");
		goto failed;
	}

	/* set Tx rings WME properties */
	err = uath_wme_init(sc);
	if (err) {
		UATH_DEBUG(UATH_DBG_ERR, "uath: uath_switch_channel(): "
		    "could not init Tx queues\n");
		goto failed;
	}

	err = uath_set_ledstate(sc, 0);
	if (err) {
		UATH_DEBUG(UATH_DBG_ERR, "uath: uath_switch_channel(): "
		    "could not set led state\n");
		goto failed;
	}

	err = uath_flush(sc);
	if (err) {
		UATH_DEBUG(UATH_DBG_ERR, "uath: uath_switch_channel(): "
		    "could not flush pipes\n");
		goto failed;
	}

failed:
	return (err);
}

static int
uath_set_rxfilter(struct uath_softc *sc, uint32_t bits, uint32_t op)
{
	struct uath_cmd_rx_filter rxfilter;

	rxfilter.bits = BE_32(bits);
	rxfilter.op = BE_32(op);

	UATH_DEBUG(UATH_DBG_MSG, "uath: uath_set_rxfilter(): "
	    "setting Rx filter=0x%x flags=0x%x\n", bits, op);

	return ((uath_cmd_write(sc, WDCMSG_RX_FILTER, &rxfilter,
	    sizeof (rxfilter), 0)));
}

static int
uath_set_chan(struct uath_softc *sc, struct ieee80211_channel *c)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct uath_cmd_reset reset;

	bzero(&reset, sizeof (reset));
	if (IEEE80211_IS_CHAN_2GHZ(c))
		reset.flags |= BE_32(UATH_CHAN_2GHZ);
	if (IEEE80211_IS_CHAN_5GHZ(c))
		reset.flags |= BE_32(UATH_CHAN_5GHZ);
	/* NB: 11g =>'s 11b so don't specify both OFDM and CCK */
	if (UATH_IS_CHAN_OFDM(c))
		reset.flags |= BE_32(UATH_CHAN_OFDM);
	else if (UATH_IS_CHAN_CCK(c))
		reset.flags |= BE_32(UATH_CHAN_CCK);
	/* turbo can be used in either 2GHz or 5GHz */
	if (c->ich_flags & IEEE80211_CHAN_TURBO)
		reset.flags |= BE_32(UATH_CHAN_TURBO);

	reset.freq = BE_32(c->ich_freq);
	reset.maxrdpower = BE_32(50);	/* XXX */
	reset.channelchange = BE_32(1);
	reset.keeprccontent = BE_32(0);

	UATH_DEBUG(UATH_DBG_MSG, "uath: uath_set_chan(): "
	    "set channel %d, flags 0x%x freq %u\n",
	    ieee80211_chan2ieee(ic, c),
	    BE_32(reset.flags), BE_32(reset.freq));

	return (uath_cmd_write(sc, WDCMSG_RESET, &reset, sizeof (reset), 0));
}

static int
uath_reset_tx_queues(struct uath_softc *sc)
{
	int ac, err;

	for (ac = 0; ac < 4; ac++) {
		const uint32_t qid = BE_32(ac);
		err = uath_cmd_write(sc, WDCMSG_RELEASE_TX_QUEUE, &qid,
		    sizeof (qid), 0);
		if (err != UATH_SUCCESS)
			break;
	}
	return (err);
}

static int
uath_wme_init(struct uath_softc *sc)
{
	/* XXX get from net80211 */
	static const struct uath_wme_settings uath_wme_11g[4] = {
		{ 7, 4, 10,  0, 0 },	/* Background */
		{ 3, 4, 10,  0, 0 },	/* Best-Effort */
		{ 3, 3,  4, 26, 0 },	/* Video */
		{ 2, 2,  3, 47, 0 }	/* Voice */
	};

	struct uath_cmd_txq_setup qinfo;
	int ac, err;

	for (ac = 0; ac < 4; ac++) {
		qinfo.qid		= BE_32(ac);
		qinfo.len		= BE_32(sizeof (qinfo.attr));
		qinfo.attr.priority	= BE_32(ac);	/* XXX */
		qinfo.attr.aifs		= BE_32(uath_wme_11g[ac].aifsn);
		qinfo.attr.logcwmin	= BE_32(uath_wme_11g[ac].logcwmin);
		qinfo.attr.logcwmax	= BE_32(uath_wme_11g[ac].logcwmax);
		qinfo.attr.mode		= BE_32(uath_wme_11g[ac].acm);
		qinfo.attr.qflags	= BE_32(1);
		qinfo.attr.bursttime	=
		    BE_32(UATH_TXOP_TO_US(uath_wme_11g[ac].txop));

		err = uath_cmd_write(sc, WDCMSG_SETUP_TX_QUEUE, &qinfo,
		    sizeof (qinfo), 0);
		if (err != UATH_SUCCESS)
			break;
	}
	return (err);
}

static void
uath_stop_locked(void *arg)
{
	struct uath_softc *sc = (struct uath_softc *)arg;

	/* flush data & control requests into the target  */
	(void) uath_flush(sc);

	/* set a LED status to the disconnected.  */
	(void) uath_set_ledstate(sc, 0);

	/* stop the target  */
	(void) uath_cmd_write(sc, WDCMSG_TARGET_STOP, NULL, 0, 0);

	/* abort any pending transfers */
	usb_pipe_reset(sc->sc_dev, sc->rx_data_pipe, USB_FLAGS_SLEEP, NULL, 0);
	usb_pipe_reset(sc->sc_dev, sc->tx_data_pipe, USB_FLAGS_SLEEP, NULL, 0);
	usb_pipe_reset(sc->sc_dev, sc->tx_cmd_pipe, USB_FLAGS_SLEEP, NULL, 0);
}

static int
uath_init_locked(void *arg)
{
	struct uath_softc *sc = arg;
	struct ieee80211com *ic = &sc->sc_ic;
	uint32_t val;
	int i, err;

	if (UATH_IS_RUNNING(sc))
		uath_stop_locked(sc);

	uath_init_data_queue(sc);

	/* reset variables */
	sc->sc_intrx_nextnum = sc->sc_msgid = 0;

	val = BE_32(0);
	(void) uath_cmd_write(sc, WDCMSG_BIND, &val, sizeof (val), 0);

	/* set MAC address */
	(void) uath_config_multi(sc, CFG_MAC_ADDR,
	    ic->ic_macaddr, IEEE80211_ADDR_LEN);

	/* XXX honor net80211 state */
	uath_config(sc, CFG_RATE_CONTROL_ENABLE, 0x00000001);
	uath_config(sc, CFG_DIVERSITY_CTL, 0x00000001);
	uath_config(sc, CFG_ABOLT, 0x0000003f);
	uath_config(sc, CFG_WME_ENABLED, 0x00000001);

	uath_config(sc, CFG_SERVICE_TYPE, 1);
	uath_config(sc, CFG_TP_SCALE, 0x00000000);
	uath_config(sc, CFG_TPC_HALF_DBM5, 0x0000003c);
	uath_config(sc, CFG_TPC_HALF_DBM2, 0x0000003c);
	uath_config(sc, CFG_OVERRD_TX_POWER, 0x00000000);
	uath_config(sc, CFG_GMODE_PROTECTION, 0x00000000);
	uath_config(sc, CFG_GMODE_PROTECT_RATE_INDEX, 0x00000003);
	uath_config(sc, CFG_PROTECTION_TYPE, 0x00000000);
	uath_config(sc, CFG_MODE_CTS, 0x00000002);

	err = uath_cmd_read(sc, WDCMSG_TARGET_START, NULL, 0,
	    &val, sizeof (val), UATH_CMD_FLAG_MAGIC);
	if (err) {
		UATH_DEBUG(UATH_DBG_ERR, "uath: uath_init_locked(): "
		    "could not start target\n");
		goto fail;
	}

	UATH_DEBUG(UATH_DBG_MSG, "uath: uath_init_locked(): "
	    "%s returns handle: 0x%x\n",
	    uath_codename(WDCMSG_TARGET_START), BE_32(val));

	/* set default channel */
	err = uath_switch_channel(sc, ic->ic_curchan);
	if (err) {
		UATH_DEBUG(UATH_DBG_ERR, "uath: uath_init_locked(): "
		    "could not switch channel, error %d\n", err);
		goto fail;
	}

	val = BE_32(TARGET_DEVICE_AWAKE);
	(void) uath_cmd_write(sc, WDCMSG_SET_PWR_MODE, &val, sizeof (val), 0);
	/* XXX? check */
	(void) uath_cmd_write(sc, WDCMSG_RESET_KEY_CACHE, NULL, 0, 0);

	for (i = 0; i < UATH_RX_DATA_LIST_COUNT; i++) {
		err = uath_rx_data_xfer(sc);
		if (err != UATH_SUCCESS) {
			UATH_DEBUG(UATH_DBG_ERR, "uath: uath_init_locked(): "
			    "could not alloc rx xfer %x\n", i);
			goto fail;
		}
	}

	/* enable Rx */
	(void) uath_set_rxfilter(sc, 0x0, UATH_FILTER_OP_INIT);
	(void) uath_set_rxfilter(sc,
	    UATH_FILTER_RX_UCAST | UATH_FILTER_RX_MCAST |
	    UATH_FILTER_RX_BCAST | UATH_FILTER_RX_BEACON,
	    UATH_FILTER_OP_SET);

	return (UATH_SUCCESS);

fail:
	uath_stop_locked(sc);
	return (err);
}

static int
uath_init(struct uath_softc *sc)
{
	int err;

	UATH_LOCK(sc);
	err = uath_init_locked(sc);
	if (err != UATH_SUCCESS) {
		UATH_DEBUG(UATH_DBG_ERR, "uath: uath_init(): "
		    "failed to initialize uath hardware\n");
		UATH_UNLOCK(sc);
		return (DDI_FAILURE);
	}
	UATH_UNLOCK(sc);
	return (DDI_SUCCESS);
}

static void
uath_stop(struct uath_softc *sc)
{
	UATH_DEBUG(UATH_DBG_MSG, "uath: uath_stop(): "
	    "uath stop now\n");

	UATH_LOCK(sc);
	uath_stop_locked(sc);
	UATH_UNLOCK(sc);
}

static void
uath_resume(struct uath_softc *sc)
{
	int err;

	UATH_DEBUG(UATH_DBG_MSG, "uath: uath_resume(): "
	    "uath resume now\n");

	/* check device changes after suspend */
	if (usb_check_same_device(sc->sc_dev, NULL, USB_LOG_L2, -1,
	    USB_CHK_BASIC | USB_CHK_CFG, NULL) != USB_SUCCESS) {
		UATH_DEBUG(UATH_DBG_MSG, "uath: uath_resume: "
		    "no or different device connected\n");
		return;
	}

	/*
	 * initialize hardware
	 */
	err = uath_init_cmd_list(sc);
	if (err != UATH_SUCCESS) {
		UATH_DEBUG(UATH_DBG_MSG, "uath: uath_resume(): "
		    "could not init RX command list\n");
		return;
	}

	err = uath_init(sc);
	if (err != UATH_SUCCESS) {
		UATH_DEBUG(UATH_DBG_MSG, "uath: uath_resume(): "
		    "hardware init failed\n");
		uath_stop(sc);
		return;
	}

	ieee80211_new_state(&sc->sc_ic, IEEE80211_S_INIT, -1);
	UATH_LOCK(sc);
	sc->sc_flags &= ~UATH_FLAG_SUSPEND;
	sc->sc_flags |= UATH_FLAG_RUNNING;
	UATH_UNLOCK(sc);
}

static int
uath_m_start(void *arg)
{
	struct uath_softc *sc = (struct uath_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;
	int err;

	/*
	 * initialize hardware
	 */
	err = uath_init(sc);
	if (err != UATH_SUCCESS) {
		UATH_DEBUG(UATH_DBG_ERR, "uath: uath_m_start(): "
		    "device configuration failed\n");
		uath_stop(sc);
		return (err);
	}

	ieee80211_new_state(ic, IEEE80211_S_INIT, -1);

	UATH_LOCK(sc);
	sc->sc_flags |= UATH_FLAG_RUNNING;
	UATH_UNLOCK(sc);
	return (DDI_SUCCESS);
}

static void
uath_m_stop(void *arg)
{
	struct uath_softc *sc = (struct uath_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;

	ieee80211_new_state(ic, IEEE80211_S_INIT, -1);

	if (!UATH_IS_DISCONNECT(sc))
		uath_stop(sc);

	UATH_LOCK(sc);
	sc->sc_flags &= ~UATH_FLAG_RUNNING;
	UATH_UNLOCK(sc);
}

static void
uath_m_ioctl(void* arg, queue_t *wq, mblk_t *mp)
{
	struct uath_softc *sc = (struct uath_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;
	int err;

	err = ieee80211_ioctl(ic, wq, mp);
	UATH_LOCK(sc);
	if (err == ENETRESET) {
		if (ic->ic_des_esslen) {
			if (UATH_IS_RUNNING(sc)) {
				UATH_UNLOCK(sc);
				(void) uath_init(sc);
				(void) ieee80211_new_state(ic,
				    IEEE80211_S_SCAN, -1);
				UATH_LOCK(sc);
			}
		}
	}
	UATH_UNLOCK(sc);
}

/*ARGSUSED*/
static int
uath_m_unicst(void *arg, const uint8_t *macaddr)
{
	return (0);
}

/*ARGSUSED*/
static int
uath_m_multicst(void *arg, boolean_t add, const uint8_t *mca)
{
	return (0);
}

/*ARGSUSED*/
static int
uath_m_promisc(void *arg, boolean_t on)
{
	return (0);
}

/*
 * callback functions for /get/set properties
 */
static int
uath_m_setprop(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    uint_t wldp_length, const void *wldp_buf)
{
	struct uath_softc *sc = (struct uath_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;
	int err;

	err = ieee80211_setprop(ic, pr_name, wldp_pr_num,
	    wldp_length, wldp_buf);
	UATH_LOCK(sc);
	if (err == ENETRESET) {
		if (ic->ic_des_esslen && UATH_IS_RUNNING(sc)) {
			UATH_UNLOCK(sc);
			(void) uath_init(sc);
			(void) ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
			UATH_LOCK(sc);
		}
		err = 0;
	}
	UATH_UNLOCK(sc);
	return (err);
}

static int
uath_m_getprop(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    uint_t wldp_length, void *wldp_buf)
{
	struct uath_softc *sc = (struct uath_softc *)arg;
	int err;

	err = ieee80211_getprop(&sc->sc_ic, pr_name, wldp_pr_num,
	    wldp_length, wldp_buf);
	return (err);
}

static void
uath_m_propinfo(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    mac_prop_info_handle_t prh)
{
	struct uath_softc *sc = (struct uath_softc *)arg;

	ieee80211_propinfo(&sc->sc_ic, pr_name, wldp_pr_num, prh);
}

static int
uath_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	struct uath_softc *sc  = (struct uath_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;
	struct ieee80211_node *ni = NULL;
	struct ieee80211_rateset *rs = NULL;

	UATH_LOCK(sc);
	switch (stat) {
	case MAC_STAT_IFSPEED:
		ni = ic->ic_bss;
		rs = &ni->in_rates;
		*val = ((ic->ic_fixed_rate == IEEE80211_FIXED_RATE_NONE) ?
		    (rs->ir_rates[ni->in_txrate] & IEEE80211_RATE_VAL)
		    : ic->ic_fixed_rate) * 5000000ull;
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
		UATH_UNLOCK(sc);
		return (ieee80211_stat(ic, stat, val));
	default:
		UATH_UNLOCK(sc);
		return (ENOTSUP);
	}
	UATH_UNLOCK(sc);

	return (0);
}

static mblk_t *
uath_m_tx(void *arg, mblk_t *mp)
{
	struct uath_softc *sc = (struct uath_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;
	mblk_t *next;

	/*
	 * No data frames go out unless we're associated; this
	 * should not happen as the 802.11 layer does not enable
	 * the xmit queue until we enter the RUN state.
	 */
	if ((ic->ic_state != IEEE80211_S_RUN) ||
	    UATH_IS_SUSPEND(sc)) {
		UATH_DEBUG(UATH_DBG_MSG, "uath: uath_m_tx(): "
		    "discard, state %u\n", ic->ic_state);
		freemsgchain(mp);
		return (NULL);
	}

	while (mp != NULL) {
		next = mp->b_next;
		mp->b_next = NULL;
		if (uath_send(ic, mp, IEEE80211_FC0_TYPE_DATA) != DDI_SUCCESS) {
			mp->b_next = next;
			break;
		}
		mp = next;
	}
	return (mp);
}

static int
uath_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	struct uath_softc *sc;
	struct ieee80211com *ic;

	int i, err, instance;
	char strbuf[32];
	uint16_t vendor_id, product_id;

	wifi_data_t wd = { 0 };
	mac_register_t *macp;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		sc = ddi_get_soft_state(uath_soft_state_p,
		    ddi_get_instance(devinfo));
		ASSERT(sc != NULL);
		uath_resume(sc);
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(devinfo);
	err = ddi_soft_state_zalloc(uath_soft_state_p, instance);
	if (err != DDI_SUCCESS) {
		UATH_DEBUG(UATH_DBG_ERR, "uath: uath_attach(): "
		    "ddi_soft_state_zalloc failed\n");
		return (DDI_FAILURE);
	}

	sc = ddi_get_soft_state(uath_soft_state_p, instance);
	ic = (ieee80211com_t *)&sc->sc_ic;
	sc->sc_dev = devinfo;

	err = usb_client_attach(devinfo, USBDRV_VERSION, 0);
	if (err != USB_SUCCESS) {
		UATH_DEBUG(UATH_DBG_ERR, "uath: uath_attach(): "
		    "usb_client_attach failed\n");
		goto fail1;
	}

	err = usb_get_dev_data(devinfo, &sc->sc_udev, USB_PARSE_LVL_ALL, 0);
	if (err != USB_SUCCESS) {
		sc->sc_udev = NULL;
		UATH_DEBUG(UATH_DBG_ERR, "uath: uath_attach(): "
		    "usb_get_dev_data failed\n");
		goto fail2;
	}

	vendor_id = sc->sc_udev->dev_descr->idVendor;
	product_id = sc->sc_udev->dev_descr->idProduct;
	sc->dev_flags = uath_lookup(vendor_id, product_id);
	if (sc->dev_flags == UATH_FLAG_ERR) {
		UATH_DEBUG(UATH_DBG_ERR, "uath: uath_attach(): "
		    "HW does not match\n");
		goto fail2;
	}

	UATH_DEBUG(UATH_DBG_MSG, "uath: uath_attach(): "
	    "vendorId = %x,deviceID = %x, flags = %x\n",
	    vendor_id, product_id, sc->dev_flags);

	/*
	 * We must open the pipes early because they're used to upload the
	 * firmware (pre-firmware devices) or to send firmware commands.
	 */
	err = uath_open_pipes(sc);
	if (err != UATH_SUCCESS) {
		UATH_DEBUG(UATH_DBG_ERR, "uath: uath_attach(): "
		    "could not open pipes\n");
		goto fail3;
	}

	if (sc->dev_flags & UATH_FLAG_PRE_FIRMWARE) {
		err = uath_loadfirmware(sc);
		if (err != DDI_SUCCESS) {
			UATH_DEBUG(UATH_DBG_ERR, "uath: uath_attach(): "
			    "could not read firmware %s, err %d\n",
			    "uath-ar5523", err);
			goto fail3;
		}

		uath_close_pipes(sc);
		usb_client_detach(sc->sc_dev, sc->sc_udev);

		err = usb_reset_device(devinfo, USB_RESET_LVL_REATTACH);
		if (err != USB_SUCCESS) {
			UATH_DEBUG(UATH_DBG_ERR, "uath: uath_attach(): "
			    "could not re-attach, err %d\n", err);
			goto fail1;
		}
		return (DDI_SUCCESS);
	}

	UATH_DEBUG(UATH_DBG_MSG, "uath: uath_attach(): "
	    "firmware download and re-attach successfully\n");

	/*
	 * Only post-firmware devices here.
	 */
	mutex_init(&sc->sc_genlock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&sc->sc_rxlock_cmd, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&sc->sc_txlock_cmd, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&sc->sc_rxlock_data, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&sc->sc_txlock_data, NULL, MUTEX_DRIVER, NULL);

	/*
	 * Allocate xfers for firmware commands.
	 */
	err = uath_alloc_cmd_list(sc, sc->sc_cmd, UATH_CMD_LIST_COUNT,
	    UATH_MAX_CMDSZ);
	if (err != UATH_SUCCESS) {
		UATH_DEBUG(UATH_DBG_ERR, "uath: uath_attach(): "
		    "could not allocate Tx command list\n");
		goto fail4;
	}

	err = uath_init_cmd_list(sc);
	if (err != UATH_SUCCESS) {
		UATH_DEBUG(UATH_DBG_ERR, "uath: uath_attach(): "
		    "could not init RX command list\n");
		goto fail5;
	}

	/*
	 * We're now ready to send+receive firmware commands.
	 */
	err = uath_host_available(sc);
	if (err != UATH_SUCCESS) {
		UATH_DEBUG(UATH_DBG_ERR, "uath: uath_attach(): "
		    "could not initialize adapter\n");
		goto fail5;
	}

	err = uath_get_devcap(sc);
	if (err != UATH_SUCCESS) {
		UATH_DEBUG(UATH_DBG_ERR, "uath: uath_attach(): "
		    "could not get device capabilities\n");
		goto fail5;
	}

	err = uath_get_devstatus(sc, ic->ic_macaddr);
	if (err != UATH_SUCCESS) {
		UATH_DEBUG(UATH_DBG_ERR, "uath: uath_attach(): "
		    "could not get dev status\n");
		goto fail5;
	}

	UATH_DEBUG(UATH_DBG_MSG, "uath: uath_attach(): "
	    "MAC address is: %x:%x:%x:%x:%x:%x\n",
	    ic->ic_macaddr[0], ic->ic_macaddr[1], ic->ic_macaddr[2],
	    ic->ic_macaddr[3], ic->ic_macaddr[4], ic->ic_macaddr[5]);

	ic->ic_phytype = IEEE80211_T_OFDM;	/* not only, but not used */
	ic->ic_opmode = IEEE80211_M_STA;	/* default to BSS mode */
	ic->ic_state = IEEE80211_S_INIT;

	ic->ic_maxrssi = 40;

	ic->ic_xmit = uath_send;

	/* set device capabilities */
	ic->ic_caps =
	    IEEE80211_C_TXPMGT |	/* tx power management */
	    IEEE80211_C_SHPREAMBLE |	/* short preamble supported */
	    IEEE80211_C_SHSLOT;		/* short slot time supported */

	ic->ic_caps |= IEEE80211_C_WPA;  /* Support WPA/WPA2 */

	/* set supported .11b and .11g rates */
	ic->ic_sup_rates[IEEE80211_MODE_11B] = uath_rateset_11b;
	ic->ic_sup_rates[IEEE80211_MODE_11G] = uath_rateset_11g;

	/* set supported .11b and .11g channels (1 through 11) */
	for (i = 1; i <= 11; i++) {
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
	ic->ic_newstate = uath_newstate;
	ieee80211_media_init(ic);
	ic->ic_def_txkey = 0;

	sc->sc_flags = 0;

	/*
	 * Provide initial settings for the WiFi plugin; whenever this
	 * information changes, we need to call mac_plugindata_update()
	 */
	wd.wd_opmode = ic->ic_opmode;
	wd.wd_secalloc = WIFI_SEC_NONE;
	IEEE80211_ADDR_COPY(wd.wd_bssid, ic->ic_bss->in_bssid);

	if ((macp = mac_alloc(MAC_VERSION)) == NULL) {
		UATH_DEBUG(UATH_DBG_ERR, "uath_attach(): "
		    "MAC version mismatch\n");
		goto fail5;
	}

	macp->m_type_ident	= MAC_PLUGIN_IDENT_WIFI;
	macp->m_driver		= sc;
	macp->m_dip		= devinfo;
	macp->m_src_addr	= ic->ic_macaddr;
	macp->m_callbacks	= &uath_m_callbacks;
	macp->m_min_sdu		= 0;
	macp->m_max_sdu		= IEEE80211_MTU;
	macp->m_pdata		= &wd;
	macp->m_pdata_size	= sizeof (wd);

	err = mac_register(macp, &ic->ic_mach);
	mac_free(macp);
	if (err != 0) {
		UATH_DEBUG(UATH_DBG_ERR, "uath_attach(): "
		    "mac_register() error %x\n", err);
		goto fail5;
	};

	err = usb_register_hotplug_cbs(devinfo,
	    uath_disconnect, uath_reconnect);
	if (err != USB_SUCCESS) {
		UATH_DEBUG(UATH_DBG_ERR, "uath: uath_attach(): "
		    "failed to register events\n");
		goto fail6;
	}

	/*
	 * Create minor node of type DDI_NT_NET_WIFI
	 */
	(void) snprintf(strbuf, sizeof (strbuf), "%s%d",
	    "uath", instance);
	err = ddi_create_minor_node(devinfo, strbuf, S_IFCHR,
	    instance + 1, DDI_NT_NET_WIFI, 0);
	if (err != DDI_SUCCESS)
		UATH_DEBUG(UATH_DBG_ERR, "uath: uath_attach(): "
		    "ddi_create_minor_node() failed\n");

	/*
	 * Notify link is down now
	 */
	mac_link_update(ic->ic_mach, LINK_STATE_DOWN);

	UATH_DEBUG(UATH_DBG_MSG, "uath: uath_attach(): "
	    "attach success\n");
	return (DDI_SUCCESS);

fail6:
	(void) mac_unregister(ic->ic_mach);
fail5:
	uath_free_cmd_list(sc->sc_cmd, UATH_CMD_LIST_COUNT);
fail4:
	mutex_destroy(&sc->sc_genlock);
	mutex_destroy(&sc->sc_rxlock_cmd);
	mutex_destroy(&sc->sc_rxlock_data);
	mutex_destroy(&sc->sc_txlock_cmd);
	mutex_destroy(&sc->sc_txlock_data);
fail3:
	uath_close_pipes(sc);
fail2:
	usb_client_detach(sc->sc_dev, sc->sc_udev);
fail1:
	ddi_soft_state_free(uath_soft_state_p, ddi_get_instance(devinfo));
	return (DDI_FAILURE);
}

static int
uath_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd)
{
	struct uath_softc *sc;

	sc = ddi_get_soft_state(uath_soft_state_p, ddi_get_instance(devinfo));
	ASSERT(sc != NULL);

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		if (UATH_IS_RUNNING(sc)) {
			ieee80211_new_state(&sc->sc_ic, IEEE80211_S_INIT, -1);
			uath_stop(sc);
		}
		UATH_LOCK(sc);
		sc->sc_flags &= ~UATH_FLAG_RUNNING;
		sc->sc_flags |= UATH_FLAG_SUSPEND;
		UATH_UNLOCK(sc);
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	if (sc->dev_flags & UATH_FLAG_PRE_FIRMWARE) {
		ddi_soft_state_free(uath_soft_state_p,
		    ddi_get_instance(devinfo));
		return (DDI_SUCCESS);
	}

	if (!UATH_IS_DISCONNECT(sc) && UATH_IS_RUNNING(sc))
		uath_stop(sc);

	uath_free_cmd_list(sc->sc_cmd, UATH_CMD_LIST_COUNT);

	if (mac_disable(sc->sc_ic.ic_mach) != 0)
		return (DDI_FAILURE);

	/*
	 * Unregister from the MAC layer subsystem
	 */
	if (mac_unregister(sc->sc_ic.ic_mach) != 0)
		return (DDI_FAILURE);

	/*
	 * detach ieee80211 layer
	 */
	ieee80211_detach(&sc->sc_ic);

	/* close Tx/Rx pipes */
	uath_close_pipes(sc);
	usb_unregister_hotplug_cbs(devinfo);

	mutex_destroy(&sc->sc_genlock);
	mutex_destroy(&sc->sc_rxlock_cmd);
	mutex_destroy(&sc->sc_rxlock_data);
	mutex_destroy(&sc->sc_txlock_cmd);
	mutex_destroy(&sc->sc_txlock_data);

	/* pipes will be close in uath_stop() */
	usb_client_detach(devinfo, sc->sc_udev);
	sc->sc_udev = NULL;

	ddi_remove_minor_node(devinfo, NULL);
	ddi_soft_state_free(uath_soft_state_p, ddi_get_instance(devinfo));

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

	status = ddi_soft_state_init(&uath_soft_state_p,
	    sizeof (struct uath_softc), 1);
	if (status != 0)
		return (status);

	mac_init_ops(&uath_dev_ops, "uath");
	status = mod_install(&modlinkage);
	if (status != 0) {
		mac_fini_ops(&uath_dev_ops);
		ddi_soft_state_fini(&uath_soft_state_p);
	}
	return (status);
}

int
_fini(void)
{
	int status;

	status = mod_remove(&modlinkage);
	if (status == 0) {
		mac_fini_ops(&uath_dev_ops);
		ddi_soft_state_fini(&uath_soft_state_p);
	}
	return (status);
}
