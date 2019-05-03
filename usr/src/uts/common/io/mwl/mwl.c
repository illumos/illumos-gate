/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2007-2009 Sam Leffler, Errno Consulting
 * Copyright (c) 2007-2008 Marvell Semiconductor, Inc.
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
 * Copyright 2019 Joyent, Inc.
 */

/*
 * Driver for the Marvell 88W8363 Wireless LAN controller.
 */
#include <sys/stat.h>
#include <sys/dlpi.h>
#include <inet/common.h>
#include <inet/mi.h>
#include <sys/stream.h>
#include <sys/errno.h>
#include <sys/stropts.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/pci.h>
#include <sys/mac_provider.h>
#include <sys/mac_wifi.h>
#include <sys/net80211.h>
#include <inet/wifi_ioctl.h>

#include "mwl_var.h"

static int mwl_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd);
static int mwl_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd);
static int mwl_quiesce(dev_info_t *devinfo);

DDI_DEFINE_STREAM_OPS(mwl_dev_ops, nulldev, nulldev, mwl_attach, mwl_detach,
    nodev, NULL, D_MP, NULL, mwl_quiesce);

static struct modldrv mwl_modldrv = {
	&mod_driverops,	/* Type of module.  This one is a driver */
	"Marvell 88W8363 WiFi driver v1.1",	/* short description */
	&mwl_dev_ops	/* driver specific ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&mwl_modldrv, NULL
};

static void *mwl_soft_state_p = NULL;

static int	mwl_m_stat(void *,  uint_t, uint64_t *);
static int	mwl_m_start(void *);
static void	mwl_m_stop(void *);
static int	mwl_m_promisc(void *, boolean_t);
static int	mwl_m_multicst(void *, boolean_t, const uint8_t *);
static int	mwl_m_unicst(void *, const uint8_t *);
static mblk_t	*mwl_m_tx(void *, mblk_t *);
static void	mwl_m_ioctl(void *, queue_t *, mblk_t *);
static int	mwl_m_setprop(void *arg, const char *pr_name,
		    mac_prop_id_t wldp_pr_num,
		    uint_t wldp_length, const void *wldp_buf);
static int	mwl_m_getprop(void *arg, const char *pr_name,
		    mac_prop_id_t wldp_pr_num, uint_t wldp_length,
		    void *wldp_buf);
static void	mwl_m_propinfo(void *, const char *, mac_prop_id_t,
    mac_prop_info_handle_t);

static mac_callbacks_t mwl_m_callbacks = {
	MC_IOCTL | MC_SETPROP | MC_GETPROP | MC_PROPINFO,
	mwl_m_stat,
	mwl_m_start,
	mwl_m_stop,
	mwl_m_promisc,
	mwl_m_multicst,
	mwl_m_unicst,
	mwl_m_tx,
	NULL,
	mwl_m_ioctl,
	NULL,
	NULL,
	NULL,
	mwl_m_setprop,
	mwl_m_getprop,
	mwl_m_propinfo
};

#define	MWL_DBG_ATTACH		(1 << 0)
#define	MWL_DBG_DMA		(1 << 1)
#define	MWL_DBG_FW		(1 << 2)
#define	MWL_DBG_HW		(1 << 3)
#define	MWL_DBG_INTR		(1 << 4)
#define	MWL_DBG_RX		(1 << 5)
#define	MWL_DBG_TX		(1 << 6)
#define	MWL_DBG_CMD		(1 << 7)
#define	MWL_DBG_CRYPTO		(1 << 8)
#define	MWL_DBG_SR		(1 << 9)
#define	MWL_DBG_MSG		(1 << 10)

uint32_t mwl_dbg_flags = 0x0;

#ifdef DEBUG
#define	MWL_DBG	\
	mwl_debug
#else
#define	MWL_DBG(...) (void)(0)
#endif

/*
 * PIO access attributes for registers
 */
static ddi_device_acc_attr_t mwl_reg_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC
};

static ddi_device_acc_attr_t mwl_cmdbuf_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC
};

/*
 * DMA access attributes for descriptors and bufs: NOT to be byte swapped.
 */
static ddi_device_acc_attr_t mwl_desc_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC
};

static ddi_device_acc_attr_t mwl_buf_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC
};

/*
 * Describes the chip's DMA engine
 */
static ddi_dma_attr_t mwl_dma_attr = {
	DMA_ATTR_V0,			/* dma_attr version */
	0x0000000000000000ull,		/* dma_attr_addr_lo */
	0xFFFFFFFF,			/* dma_attr_addr_hi */
	0x00000000FFFFFFFFull,		/* dma_attr_count_max */
	0x0000000000000001ull,		/* dma_attr_align */
	0x00000FFF,			/* dma_attr_burstsizes */
	0x00000001,			/* dma_attr_minxfer */
	0x000000000000FFFFull,		/* dma_attr_maxxfer */
	0xFFFFFFFFFFFFFFFFull,		/* dma_attr_seg */
	1,				/* dma_attr_sgllen */
	0x00000001,			/* dma_attr_granular */
	0				/* dma_attr_flags */
};

/*
 * Supported rates for 802.11a/b/g modes (in 500Kbps unit).
 */
static const struct ieee80211_rateset mwl_rateset_11b =
	{ 4, { 2, 4, 11, 22 } };

static const struct ieee80211_rateset mwl_rateset_11g =
	{ 12, { 2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108 } };

static int	mwl_alloc_dma_mem(dev_info_t *, ddi_dma_attr_t *, size_t,
		    ddi_device_acc_attr_t *, uint_t, uint_t,
		    struct dma_area *);
static void	mwl_free_dma_mem(struct dma_area *);
static int	mwl_alloc_cmdbuf(struct mwl_softc *);
static void	mwl_free_cmdbuf(struct mwl_softc *);
static int	mwl_alloc_rx_ring(struct mwl_softc *, int);
static void	mwl_free_rx_ring(struct mwl_softc *);
static int	mwl_alloc_tx_ring(struct mwl_softc *, struct mwl_tx_ring *,
		    int);
static void	mwl_free_tx_ring(struct mwl_softc *, struct mwl_tx_ring *);
static int	mwl_setupdma(struct mwl_softc *);
static void	mwl_txq_init(struct mwl_softc *, struct mwl_tx_ring *, int);
static int	mwl_tx_setup(struct mwl_softc *, int, int);
static int	mwl_setup_txq(struct mwl_softc *);
static int	mwl_fwload(struct mwl_softc *, void *);
static int	mwl_loadsym(ddi_modhandle_t, char *, char **, size_t *);
static void	mwlFwReset(struct mwl_softc *);
static void	mwlPokeSdramController(struct mwl_softc *, int);
static void	mwlTriggerPciCmd(struct mwl_softc *);
static int	mwlWaitFor(struct mwl_softc *, uint32_t);
static int	mwlSendBlock(struct mwl_softc *, int, const void *, size_t);
static int	mwlSendBlock2(struct mwl_softc *, const void *, size_t);
static void	mwlSendCmd(struct mwl_softc *);
static int	mwlExecuteCmd(struct mwl_softc *, unsigned short);
static int	mwlWaitForCmdComplete(struct mwl_softc *, uint16_t);
static void	dumpresult(struct mwl_softc *, int);
static int	mwlResetHalState(struct mwl_softc *);
static int	mwlGetPwrCalTable(struct mwl_softc *);
static int	mwlGetCalTable(struct mwl_softc *, uint8_t, uint8_t);
static int	mwlGetPwrCalTable(struct mwl_softc *);
static void	dumpcaldata(const char *, const uint8_t *, int);
static void	get2Ghz(MWL_HAL_CHANNELINFO *, const uint8_t *, int);
static void	get5Ghz(MWL_HAL_CHANNELINFO *, const uint8_t *, int);
static void	setmaxtxpow(struct mwl_hal_channel *, int, int);
static uint16_t	ieee2mhz(int);
static const char *
		mwlcmdname(int);
static int	mwl_gethwspecs(struct mwl_softc *);
static int	mwl_getchannels(struct mwl_softc *);
static void	getchannels(struct mwl_softc *, int, int *,
		    struct mwl_channel *);
static void	addchannels(struct mwl_channel *, int, int *,
		    const MWL_HAL_CHANNELINFO *, int);
static void	addht40channels(struct mwl_channel *, int, int *,
		    const MWL_HAL_CHANNELINFO *, int);
static const struct mwl_channel *
		findchannel(const struct mwl_channel *, int,
		    int, int);
static void	addchan(struct mwl_channel *, int, int, int, int);

static int	mwl_chan_set(struct mwl_softc *, struct mwl_channel *);
static void	mwl_mapchan(MWL_HAL_CHANNEL *, const struct mwl_channel *);
static int	mwl_setcurchanrates(struct mwl_softc *);
const struct ieee80211_rateset *
		mwl_get_suprates(struct ieee80211com *,
		    const struct mwl_channel *);
static uint32_t	cvtChannelFlags(const MWL_HAL_CHANNEL *);
static const struct mwl_hal_channel *
		findhalchannel(const struct mwl_softc *,
		    const MWL_HAL_CHANNEL *);
enum ieee80211_phymode
		mwl_chan2mode(const struct mwl_channel *);
static int	mwl_map2regioncode(const struct mwl_regdomain *);
static int	mwl_startrecv(struct mwl_softc *);
static int	mwl_mode_init(struct mwl_softc *);
static void	mwl_hal_intrset(struct mwl_softc *, uint32_t);
static void	mwl_hal_getisr(struct mwl_softc *, uint32_t *);
static int	mwl_hal_sethwdma(struct mwl_softc *,
		    const struct mwl_hal_txrxdma *);
static int	mwl_hal_getchannelinfo(struct mwl_softc *, int, int,
		    const MWL_HAL_CHANNELINFO **);
static int	mwl_hal_setmac_locked(struct mwl_softc *, const uint8_t *);
static int	mwl_hal_keyreset(struct mwl_softc *, const MWL_HAL_KEYVAL *,
		    const uint8_t mac[IEEE80211_ADDR_LEN]);
static int	mwl_hal_keyset(struct mwl_softc *, const MWL_HAL_KEYVAL *,
		    const uint8_t mac[IEEE80211_ADDR_LEN]);
static int	mwl_hal_newstation(struct mwl_softc *, const uint8_t *,
		    uint16_t, uint16_t, const MWL_HAL_PEERINFO *, int, int);
static int	mwl_hal_setantenna(struct mwl_softc *, MWL_HAL_ANTENNA, int);
static int	mwl_hal_setradio(struct mwl_softc *, int, MWL_HAL_PREAMBLE);
static int	mwl_hal_setwmm(struct mwl_softc *, int);
static int	mwl_hal_setchannel(struct mwl_softc *, const MWL_HAL_CHANNEL *);
static int	mwl_hal_settxpower(struct mwl_softc *, const MWL_HAL_CHANNEL *,
		    uint8_t);
static int	mwl_hal_settxrate(struct mwl_softc *, MWL_HAL_TXRATE_HANDLING,
		    const MWL_HAL_TXRATE *);
static int	mwl_hal_settxrate_auto(struct mwl_softc *,
		    const MWL_HAL_TXRATE *);
static int	mwl_hal_setrateadaptmode(struct mwl_softc *, uint16_t);
static int	mwl_hal_setoptimizationlevel(struct mwl_softc *, int);
static int	mwl_hal_setregioncode(struct mwl_softc *, int);
static int	mwl_hal_setassocid(struct mwl_softc *, const uint8_t *,
		    uint16_t);
static int	mwl_setrates(struct ieee80211com *);
static int	mwl_hal_setrtsthreshold(struct mwl_softc *, int);
static int	mwl_hal_setcsmode(struct mwl_softc *, MWL_HAL_CSMODE);
static int	mwl_hal_setpromisc(struct mwl_softc *, int);
static int	mwl_hal_start(struct mwl_softc *);
static int	mwl_hal_setinframode(struct mwl_softc *);
static int	mwl_hal_stop(struct mwl_softc *);
static struct ieee80211_node *
		mwl_node_alloc(struct ieee80211com *);
static void	mwl_node_free(struct ieee80211_node *);
static int	mwl_key_alloc(struct ieee80211com *,
		    const struct ieee80211_key *,
		    ieee80211_keyix *, ieee80211_keyix *);
static int	mwl_key_delete(struct ieee80211com *,
		    const struct ieee80211_key *);
static int	mwl_key_set(struct ieee80211com *, const struct ieee80211_key *,
		    const uint8_t mac[IEEE80211_ADDR_LEN]);
static void	mwl_setanywepkey(struct ieee80211com *, const uint8_t *);
static void	mwl_setglobalkeys(struct ieee80211com *c);
static int	addgroupflags(MWL_HAL_KEYVAL *, const struct ieee80211_key *);
static void	mwl_hal_txstart(struct mwl_softc *, int);
static int	mwl_send(ieee80211com_t *, mblk_t *, uint8_t);
static void	mwl_next_scan(void *);
static MWL_HAL_PEERINFO *
		mkpeerinfo(MWL_HAL_PEERINFO *, const struct ieee80211_node *);
static uint32_t	get_rate_bitmap(const struct ieee80211_rateset *);
static int	mwl_newstate(struct ieee80211com *, enum ieee80211_state, int);
static int	cvtrssi(uint8_t);
static uint_t	mwl_intr(caddr_t, caddr_t);
static uint_t	mwl_softintr(caddr_t, caddr_t);
static void	mwl_tx_intr(struct mwl_softc *);
static void	mwl_rx_intr(struct mwl_softc *);
static int	mwl_init(struct mwl_softc *);
static void	mwl_stop(struct mwl_softc *);
static int	mwl_resume(struct mwl_softc *);


#ifdef DEBUG
static void
mwl_debug(uint32_t dbg_flags, const int8_t *fmt, ...)
{
	va_list args;

	if (dbg_flags & mwl_dbg_flags) {
		va_start(args, fmt);
		vcmn_err(CE_CONT, fmt, args);
		va_end(args);
	}
}
#endif

/*
 * Allocate an DMA memory and a DMA handle for accessing it
 */
static int
mwl_alloc_dma_mem(dev_info_t *devinfo, ddi_dma_attr_t *dma_attr,
	size_t memsize, ddi_device_acc_attr_t *attr_p, uint_t alloc_flags,
	uint_t bind_flags, struct dma_area *dma_p)
{
	int err;

	/*
	 * Allocate handle
	 */
	err = ddi_dma_alloc_handle(devinfo, dma_attr,
	    DDI_DMA_SLEEP, NULL, &dma_p->dma_hdl);
	if (err != DDI_SUCCESS) {
		MWL_DBG(MWL_DBG_DMA, "mwl: mwl_alloc_dma_mem(): "
		    "failed to alloc handle\n");
		goto fail1;
	}

	/*
	 * Allocate memory
	 */
	err = ddi_dma_mem_alloc(dma_p->dma_hdl, memsize, attr_p,
	    alloc_flags, DDI_DMA_SLEEP, NULL, &dma_p->mem_va,
	    &dma_p->alength, &dma_p->acc_hdl);
	if (err != DDI_SUCCESS) {
		MWL_DBG(MWL_DBG_DMA, "mwl: mwl_alloc_dma_mem(): "
		    "failed to alloc mem\n");
		goto fail2;
	}

	/*
	 * Bind the two together
	 */
	err = ddi_dma_addr_bind_handle(dma_p->dma_hdl, NULL,
	    dma_p->mem_va, dma_p->alength, bind_flags,
	    DDI_DMA_SLEEP, NULL, &dma_p->cookie, &dma_p->ncookies);
	if (err != DDI_DMA_MAPPED) {
		MWL_DBG(MWL_DBG_DMA, "mwl: mwl_alloc_dma_mem(): "
		    "failed to bind handle\n");
		goto fail3;
	}

	if (dma_p->ncookies != 1) {
		MWL_DBG(MWL_DBG_DMA, "mwl: mwl_alloc_dma_mem(): "
		    "failed to alloc cookies\n");
		goto fail4;
	}

	dma_p->nslots = ~0U;
	dma_p->size = ~0U;
	dma_p->token = ~0U;
	dma_p->offset = 0;

	return (DDI_SUCCESS);

fail4:
	(void) ddi_dma_unbind_handle(dma_p->dma_hdl);
fail3:
	ddi_dma_mem_free(&dma_p->acc_hdl);
fail2:
	ddi_dma_free_handle(&dma_p->dma_hdl);
fail1:
	return (err);
}

static void
mwl_free_dma_mem(struct dma_area *dma_p)
{
	if (dma_p->dma_hdl != NULL) {
		(void) ddi_dma_unbind_handle(dma_p->dma_hdl);
		if (dma_p->acc_hdl != NULL) {
			ddi_dma_mem_free(&dma_p->acc_hdl);
			dma_p->acc_hdl = NULL;
		}
		ddi_dma_free_handle(&dma_p->dma_hdl);
		dma_p->ncookies = 0;
		dma_p->dma_hdl = NULL;
	}
}

static int
mwl_alloc_cmdbuf(struct mwl_softc *sc)
{
	int err;
	size_t size;

	size = MWL_CMDBUF_SIZE;

	err = mwl_alloc_dma_mem(sc->sc_dev, &mwl_dma_attr, size,
	    &mwl_cmdbuf_accattr, DDI_DMA_CONSISTENT,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &sc->sc_cmd_dma);
	if (err != DDI_SUCCESS) {
		MWL_DBG(MWL_DBG_DMA, "mwl: mwl_alloc_cmdbuf(): "
		    "failed to alloc dma mem\n");
		return (DDI_FAILURE);
	}

	sc->sc_cmd_mem = (uint16_t *)sc->sc_cmd_dma.mem_va;
	sc->sc_cmd_dmaaddr = sc->sc_cmd_dma.cookie.dmac_address;

	return (DDI_SUCCESS);
}

static void
mwl_free_cmdbuf(struct mwl_softc *sc)
{
	if (sc->sc_cmd_mem != NULL)
		mwl_free_dma_mem(&sc->sc_cmd_dma);
}

static int
mwl_alloc_rx_ring(struct mwl_softc *sc, int count)
{
	struct mwl_rx_ring *ring;
	struct mwl_rxdesc *ds;
	struct mwl_rxbuf *bf;
	int i, err, datadlen;

	ring = &sc->sc_rxring;
	ring->count = count;
	ring->cur = ring->next = 0;
	err = mwl_alloc_dma_mem(sc->sc_dev, &mwl_dma_attr,
	    count * sizeof (struct mwl_rxdesc),
	    &mwl_desc_accattr,
	    DDI_DMA_CONSISTENT, DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &ring->rxdesc_dma);
	if (err) {
		MWL_DBG(MWL_DBG_DMA, "mwl: mwl_alloc_rxring(): "
		    "alloc tx ring failed, size %d\n",
		    (uint32_t)(count * sizeof (struct mwl_rxdesc)));
		return (DDI_FAILURE);
	}

	MWL_DBG(MWL_DBG_DMA, "mwl: mwl_alloc_rx_ring(): "
	    "dma len = %d\n", (uint32_t)(ring->rxdesc_dma.alength));
	ring->desc = (struct mwl_rxdesc *)ring->rxdesc_dma.mem_va;
	ring->physaddr = ring->rxdesc_dma.cookie.dmac_address;
	bzero(ring->desc, count * sizeof (struct mwl_rxdesc));

	datadlen = count * sizeof (struct mwl_rxbuf);
	ring->buf = (struct mwl_rxbuf *)kmem_zalloc(datadlen, KM_SLEEP);
	if (ring->buf == NULL) {
		MWL_DBG(MWL_DBG_DMA, "mwl: mwl_alloc_rxring(): "
		    "could not alloc rx ring data buffer\n");
		return (DDI_FAILURE);
	}
	bzero(ring->buf, count * sizeof (struct mwl_rxbuf));

	/*
	 * Pre-allocate Rx buffers and populate Rx ring.
	 */
	for (i = 0; i < count; i++) {
		ds = &ring->desc[i];
		bf = &ring->buf[i];
		/* alloc DMA memory */
		(void) mwl_alloc_dma_mem(sc->sc_dev, &mwl_dma_attr,
		    sc->sc_dmabuf_size,
		    &mwl_buf_accattr,
		    DDI_DMA_STREAMING,
		    DDI_DMA_READ | DDI_DMA_STREAMING,
		    &bf->rxbuf_dma);
		bf->bf_mem = (uint8_t *)(bf->rxbuf_dma.mem_va);
		bf->bf_baddr = bf->rxbuf_dma.cookie.dmac_address;
		bf->bf_desc = ds;
		bf->bf_daddr = ring->physaddr + _PTRDIFF(ds, ring->desc);
	}

	(void) ddi_dma_sync(ring->rxdesc_dma.dma_hdl,
	    0,
	    ring->rxdesc_dma.alength,
	    DDI_DMA_SYNC_FORDEV);

	return (0);
}

static void
mwl_free_rx_ring(struct mwl_softc *sc)
{
	struct mwl_rx_ring *ring;
	struct mwl_rxbuf *bf;
	int i;

	ring = &sc->sc_rxring;

	if (ring->desc != NULL) {
		mwl_free_dma_mem(&ring->rxdesc_dma);
	}

	if (ring->buf != NULL) {
		for (i = 0; i < ring->count; i++) {
			bf = &ring->buf[i];
			mwl_free_dma_mem(&bf->rxbuf_dma);
		}
		kmem_free(ring->buf,
		    (ring->count * sizeof (struct mwl_rxbuf)));
	}
}

static int
mwl_alloc_tx_ring(struct mwl_softc *sc, struct mwl_tx_ring *ring,
    int count)
{
	struct mwl_txdesc *ds;
	struct mwl_txbuf *bf;
	int i, err, datadlen;

	ring->count = count;
	ring->queued = 0;
	ring->cur = ring->next = ring->stat = 0;
	err = mwl_alloc_dma_mem(sc->sc_dev, &mwl_dma_attr,
	    count * sizeof (struct mwl_txdesc), &mwl_desc_accattr,
	    DDI_DMA_CONSISTENT, DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &ring->txdesc_dma);
	if (err) {
		MWL_DBG(MWL_DBG_DMA, "mwl: mwl_alloc_tx_ring(): "
		    "alloc tx ring failed, size %d\n",
		    (uint32_t)(count * sizeof (struct mwl_txdesc)));
		return (DDI_FAILURE);
	}

	MWL_DBG(MWL_DBG_DMA, "mwl: mwl_alloc_tx_ring(): "
	    "dma len = %d\n", (uint32_t)(ring->txdesc_dma.alength));
	ring->desc = (struct mwl_txdesc *)ring->txdesc_dma.mem_va;
	ring->physaddr = ring->txdesc_dma.cookie.dmac_address;
	bzero(ring->desc, count * sizeof (struct mwl_txdesc));

	datadlen = count * sizeof (struct mwl_txbuf);
	ring->buf = kmem_zalloc(datadlen, KM_SLEEP);
	if (ring->buf == NULL) {
		MWL_DBG(MWL_DBG_DMA, "mwl: mwl_alloc_tx_ring(): "
		    "could not alloc tx ring data buffer\n");
		return (DDI_FAILURE);
	}
	bzero(ring->buf, count * sizeof (struct mwl_txbuf));

	for (i = 0; i < count; i++) {
		ds = &ring->desc[i];
		bf = &ring->buf[i];
		/* alloc DMA memory */
		(void) mwl_alloc_dma_mem(sc->sc_dev, &mwl_dma_attr,
		    sc->sc_dmabuf_size,
		    &mwl_buf_accattr,
		    DDI_DMA_STREAMING,
		    DDI_DMA_WRITE | DDI_DMA_STREAMING,
		    &bf->txbuf_dma);
		bf->bf_baddr = bf->txbuf_dma.cookie.dmac_address;
		bf->bf_mem = (uint8_t *)(bf->txbuf_dma.mem_va);
		bf->bf_daddr = ring->physaddr + _PTRDIFF(ds, ring->desc);
		bf->bf_desc = ds;
	}

	(void) ddi_dma_sync(ring->txdesc_dma.dma_hdl,
	    0,
	    ring->txdesc_dma.alength,
	    DDI_DMA_SYNC_FORDEV);

	return (0);
}

/* ARGSUSED */
static void
mwl_free_tx_ring(struct mwl_softc *sc, struct mwl_tx_ring *ring)
{
	struct mwl_txbuf *bf;
	int i;

	if (ring->desc != NULL) {
		mwl_free_dma_mem(&ring->txdesc_dma);
	}

	if (ring->buf != NULL) {
		for (i = 0; i < ring->count; i++) {
			bf = &ring->buf[i];
			mwl_free_dma_mem(&bf->txbuf_dma);
		}
		kmem_free(ring->buf,
		    (ring->count * sizeof (struct mwl_txbuf)));
	}
}

/*
 * Inform the f/w about location of the tx/rx dma data structures
 * and related state.  This cmd must be done immediately after a
 * mwl_hal_gethwspecs call or the f/w will lockup.
 */
static int
mwl_hal_sethwdma(struct mwl_softc *sc, const struct mwl_hal_txrxdma *dma)
{
	HostCmd_DS_SET_HW_SPEC *pCmd;
	int retval;

	_CMD_SETUP(pCmd, HostCmd_DS_SET_HW_SPEC, HostCmd_CMD_SET_HW_SPEC);
	pCmd->WcbBase[0] = LE_32(dma->wcbBase[0]);
	pCmd->WcbBase[1] = LE_32(dma->wcbBase[1]);
	pCmd->WcbBase[2] = LE_32(dma->wcbBase[2]);
	pCmd->WcbBase[3] = LE_32(dma->wcbBase[3]);
	pCmd->TxWcbNumPerQueue = LE_32(dma->maxNumTxWcb);
	pCmd->NumTxQueues = LE_32(dma->maxNumWCB);
	pCmd->TotalRxWcb = LE_32(1);		/* XXX */
	pCmd->RxPdWrPtr = LE_32(dma->rxDescRead);
	/*
	 * pCmd->Flags = LE_32(SET_HW_SPEC_HOSTFORM_BEACON
	 * #ifdef MWL_HOST_PS_SUPPORT
	 * | SET_HW_SPEC_HOST_POWERSAVE
	 * #endif
	 * | SET_HW_SPEC_HOSTFORM_PROBERESP);
	 */
	pCmd->Flags = 0;
	/* disable multi-bss operation for A1-A4 parts */
	if (sc->sc_revs.mh_macRev < 5)
		pCmd->Flags |= LE_32(SET_HW_SPEC_DISABLEMBSS);

	retval = mwlExecuteCmd(sc, HostCmd_CMD_SET_HW_SPEC);
	if (retval == 0) {
		if (pCmd->Flags & LE_32(SET_HW_SPEC_DISABLEMBSS))
			sc->sc_hw_flags &= ~MHF_MBSS;
		else
			sc->sc_hw_flags |= MHF_MBSS;
	}

	return (retval);
}

/*
 * Inform firmware of our tx/rx dma setup.  The BAR 0
 * writes below are for compatibility with older firmware.
 * For current firmware we send this information with a
 * cmd block via mwl_hal_sethwdma.
 */
static int
mwl_setupdma(struct mwl_softc *sc)
{
	int i, err;

	sc->sc_hwdma.rxDescRead = sc->sc_rxring.physaddr;
	mwl_mem_write4(sc, sc->sc_hwspecs.rxDescRead, sc->sc_hwdma.rxDescRead);
	mwl_mem_write4(sc, sc->sc_hwspecs.rxDescWrite, sc->sc_hwdma.rxDescRead);

	for (i = 0; i < MWL_NUM_TX_QUEUES - MWL_NUM_ACK_QUEUES; i++) {
		struct mwl_tx_ring *txring = &sc->sc_txring[i];
		sc->sc_hwdma.wcbBase[i] = txring->physaddr;
		mwl_mem_write4(sc, sc->sc_hwspecs.wcbBase[i],
		    sc->sc_hwdma.wcbBase[i]);
	}
	sc->sc_hwdma.maxNumTxWcb = MWL_TX_RING_COUNT;
	sc->sc_hwdma.maxNumWCB = MWL_NUM_TX_QUEUES - MWL_NUM_ACK_QUEUES;

	err = mwl_hal_sethwdma(sc, &sc->sc_hwdma);
	if (err != 0) {
		MWL_DBG(MWL_DBG_DMA, "mwl: mwl_setupdma(): "
		    "unable to setup tx/rx dma; hal status %u\n", err);
		/* XXX */
	}

	return (err);
}

/* ARGSUSED */
static void
mwl_txq_init(struct mwl_softc *sc, struct mwl_tx_ring *txring, int qnum)
{
	struct mwl_txbuf *bf;
	struct mwl_txdesc *ds;
	int i;

	txring->qnum = qnum;
	txring->txpri = 0;	/* XXX */

	bf = txring->buf;
	ds = txring->desc;
	for (i = 0; i < MWL_TX_RING_COUNT - 1; i++) {
		bf++;
		ds->pPhysNext = bf->bf_daddr;
		ds++;
	}
	bf = txring->buf;
	ds->pPhysNext = LE_32(bf->bf_daddr);
}

/*
 * Setup a hardware data transmit queue for the specified
 * access control.  We record the mapping from ac's
 * to h/w queues for use by mwl_tx_start.
 */
static int
mwl_tx_setup(struct mwl_softc *sc, int ac, int mvtype)
{
#define	N(a)	(sizeof (a)/sizeof (a[0]))
	struct mwl_tx_ring *txring;

	if (ac >= N(sc->sc_ac2q)) {
		MWL_DBG(MWL_DBG_DMA, "mwl: mwl_tx_setup(): "
		    "AC %u out of range, max %u!\n",
		    ac, (uint_t)N(sc->sc_ac2q));
		return (0);
	}
	if (mvtype >= MWL_NUM_TX_QUEUES) {
		MWL_DBG(MWL_DBG_DMA, "mwl: mwl_tx_setup(): "
		    "mvtype %u out of range, max %u!\n",
		    mvtype, MWL_NUM_TX_QUEUES);
		return (0);
	}
	txring = &sc->sc_txring[mvtype];
	mwl_txq_init(sc, txring, mvtype);
	sc->sc_ac2q[ac] = txring;
	return (1);
#undef N
}

static int
mwl_setup_txq(struct mwl_softc *sc)
{
	int err = 0;

	/* NB: insure BK queue is the lowest priority h/w queue */
	if (!mwl_tx_setup(sc, WME_AC_BK, MWL_WME_AC_BK)) {
		MWL_DBG(MWL_DBG_DMA, "mwl: mwl_setup_txq(): "
		    "unable to setup xmit queue for %s traffic!\n",
		    mwl_wme_acnames[WME_AC_BK]);
		err = EIO;
		return (err);
	}
	if (!mwl_tx_setup(sc, WME_AC_BE, MWL_WME_AC_BE) ||
	    !mwl_tx_setup(sc, WME_AC_VI, MWL_WME_AC_VI) ||
	    !mwl_tx_setup(sc, WME_AC_VO, MWL_WME_AC_VO)) {
		/*
		 * Not enough hardware tx queues to properly do WME;
		 * just punt and assign them all to the same h/w queue.
		 * We could do a better job of this if, for example,
		 * we allocate queues when we switch from station to
		 * AP mode.
		 */
		sc->sc_ac2q[WME_AC_BE] = sc->sc_ac2q[WME_AC_BK];
		sc->sc_ac2q[WME_AC_VI] = sc->sc_ac2q[WME_AC_BK];
		sc->sc_ac2q[WME_AC_VO] = sc->sc_ac2q[WME_AC_BK];
	}

	return (err);
}

/*
 * find mwl firmware module's "_start" "_end" symbols
 * and get its size.
 */
static int
mwl_loadsym(ddi_modhandle_t modp, char *sym, char **start, size_t *len)
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
		MWL_DBG(MWL_DBG_FW, "mwl: mwl_loadsym(): "
		    "mod %s: symbol %s not found\n", sym, start_sym);
		return (-1);
	}

	end = (char *)ddi_modsym(modp, end_sym, &rv);
	if (end == NULL || rv != 0) {
		MWL_DBG(MWL_DBG_FW, "mwl: mwl_loadsym(): "
		    "mod %s: symbol %s not found\n", sym, end_sym);
		return (-1);
	}

	n = _PTRDIFF(end, p);
	*start = p;
	*len = n;

	return (0);
}

static void
mwlFwReset(struct mwl_softc *sc)
{
	if (mwl_ctl_read4(sc,  MACREG_REG_INT_CODE) == 0xffffffff) {
		MWL_DBG(MWL_DBG_FW, "mwl: mwlFWReset(): "
		    "device not present!\n");
		return;
	}

	mwl_ctl_write4(sc, MACREG_REG_H2A_INTERRUPT_EVENTS, ISR_RESET);
	sc->sc_hw_flags &= ~MHF_FWHANG;
}

static void
mwlPokeSdramController(struct mwl_softc *sc, int SDRAMSIZE_Addr)
{
	/* Set up sdram controller for superflyv2 */
	mwl_ctl_write4(sc, 0x00006014, 0x33);
	mwl_ctl_write4(sc, 0x00006018, 0xa3a2632);
	mwl_ctl_write4(sc, 0x00006010, SDRAMSIZE_Addr);
}

static void
mwlTriggerPciCmd(struct mwl_softc *sc)
{
	(void) ddi_dma_sync(sc->sc_cmd_dma.dma_hdl,
	    0,
	    sc->sc_cmd_dma.alength,
	    DDI_DMA_SYNC_FORDEV);

	mwl_ctl_write4(sc, MACREG_REG_GEN_PTR, sc->sc_cmd_dmaaddr);
	(void) mwl_ctl_read4(sc, MACREG_REG_INT_CODE);

	mwl_ctl_write4(sc, MACREG_REG_INT_CODE, 0x00);
	(void) mwl_ctl_read4(sc, MACREG_REG_INT_CODE);

	mwl_ctl_write4(sc, MACREG_REG_H2A_INTERRUPT_EVENTS,
	    MACREG_H2ARIC_BIT_DOOR_BELL);
	(void) mwl_ctl_read4(sc, MACREG_REG_INT_CODE);
}

static int
mwlWaitFor(struct mwl_softc *sc, uint32_t val)
{
	int i;

	for (i = 0; i < FW_MAX_NUM_CHECKS; i++) {
		DELAY(FW_CHECK_USECS);
		if (mwl_ctl_read4(sc, MACREG_REG_INT_CODE) == val)
			return (1);
	}
	return (0);
}

/*
 * Firmware block xmit when talking to the boot-rom.
 */
static int
mwlSendBlock(struct mwl_softc *sc, int bsize, const void *data, size_t dsize)
{
	sc->sc_cmd_mem[0] = LE_16(HostCmd_CMD_CODE_DNLD);
	sc->sc_cmd_mem[1] = LE_16(bsize);
	(void) memcpy(&sc->sc_cmd_mem[4], data, dsize);
	mwlTriggerPciCmd(sc);
	/* XXX 2000 vs 200 */
	if (mwlWaitFor(sc, MACREG_INT_CODE_CMD_FINISHED)) {
		mwl_ctl_write4(sc, MACREG_REG_INT_CODE, 0);
		return (1);
	}

	MWL_DBG(MWL_DBG_FW, "mwl: mwlSendBlock(): "
	    "timeout waiting for CMD_FINISHED, INT_CODE 0x%x\n",
	    mwl_ctl_read4(sc, MACREG_REG_INT_CODE));
	return (0);
}

/*
 * Firmware block xmit when talking to the 1st-stage loader.
 */
static int
mwlSendBlock2(struct mwl_softc *sc, const void *data, size_t dsize)
{
	(void) memcpy(&sc->sc_cmd_mem[0], data, dsize);
	mwlTriggerPciCmd(sc);
	if (mwlWaitFor(sc, MACREG_INT_CODE_CMD_FINISHED)) {
		mwl_ctl_write4(sc, MACREG_REG_INT_CODE, 0);
		return (1);
	}

	MWL_DBG(MWL_DBG_FW, "mwl: mwlSendBlock2(): "
	    "timeout waiting for CMD_FINISHED, INT_CODE 0x%x\n",
	    mwl_ctl_read4(sc, MACREG_REG_INT_CODE));
	return (0);
}

/* ARGSUSED */
static int
mwl_fwload(struct mwl_softc *sc, void *fwargs)
{
	char *fwname = "mwlfw";
	char *fwbootname = "mwlboot";
	char *fwbinname = "mw88W8363fw";
	char *fwboot_index, *fw_index;
	uint8_t *fw, *fwboot;
	ddi_modhandle_t modfw;
	/* XXX get from firmware header */
	uint32_t FwReadySignature = HostCmd_SOFTAP_FWRDY_SIGNATURE;
	uint32_t OpMode = HostCmd_SOFTAP_MODE;
	const uint8_t *fp, *ep;
	size_t fw_size, fwboot_size;
	uint32_t blocksize, nbytes;
	int i, rv, err, ntries;

	rv = err = 0;
	fw = fwboot = NULL;
	fw_index = fwboot_index = NULL;

	modfw = ddi_modopen(fwname, KRTLD_MODE_FIRST, &rv);
	if (modfw == NULL) {
		MWL_DBG(MWL_DBG_FW, "mwl: mwl_fwload(): "
		    "module %s not found\n", fwname);
		err = -1;
		goto bad2;
	}

	err = mwl_loadsym(modfw, fwbootname, &fwboot_index, &fwboot_size);
	if (err != 0) {
		MWL_DBG(MWL_DBG_FW, "mwl: mwl_fwload(): "
		    "could not get boot firmware\n");
		err = -1;
		goto bad2;
	}

	err = mwl_loadsym(modfw, fwbinname, &fw_index, &fw_size);
	if (err != 0) {
		MWL_DBG(MWL_DBG_FW, "mwl: mwl_fwload(): "
		    "could not get firmware\n");
		err = -1;
		goto bad2;
	}

	fwboot = (uint8_t *)kmem_alloc(fwboot_size, KM_SLEEP);
	if (fwboot == NULL) {
		MWL_DBG(MWL_DBG_FW, "mwl: mwl_loadfirmware(): "
		    "failed to alloc boot firmware memory\n");
		err = -1;
		goto bad2;
	}
	(void) memcpy(fwboot, fwboot_index, fwboot_size);

	fw = (uint8_t *)kmem_alloc(fw_size, KM_SLEEP);
	if (fw == NULL) {
		MWL_DBG(MWL_DBG_FW, "mwl: mwl_loadfirmware(): "
		    "failed to alloc firmware memory\n");
		err = -1;
		goto bad2;
	}
	(void) memcpy(fw, fw_index, fw_size);

	if (modfw != NULL)
		(void) ddi_modclose(modfw);

	if (fw_size < 4) {
		MWL_DBG(MWL_DBG_FW, "mwl: mwl_fwload(): "
		    "could not load firmware image %s\n",
		    fwname);
		err = ENXIO;
		goto bad2;
	}

	if (fw[0] == 0x01 && fw[1] == 0x00 &&
	    fw[2] == 0x00 && fw[3] == 0x00) {
		/*
		 * 2-stage load, get the boot firmware.
		 */
		if (fwboot == NULL) {
			MWL_DBG(MWL_DBG_FW, "mwl: mwl_fwload(): "
			    "could not load firmware image %s\n",
			    fwbootname);
			err = ENXIO;
			goto bad2;
		}
	} else
		fwboot = NULL;

	mwlFwReset(sc);

	mwl_ctl_write4(sc, MACREG_REG_A2H_INTERRUPT_CLEAR_SEL,
	    MACREG_A2HRIC_BIT_MASK);
	mwl_ctl_write4(sc, MACREG_REG_A2H_INTERRUPT_CAUSE, 0x00);
	mwl_ctl_write4(sc, MACREG_REG_A2H_INTERRUPT_MASK, 0x00);
	mwl_ctl_write4(sc, MACREG_REG_A2H_INTERRUPT_STATUS_MASK,
	    MACREG_A2HRIC_BIT_MASK);
	if (sc->sc_SDRAMSIZE_Addr != 0) {
		/* Set up sdram controller for superflyv2 */
		mwlPokeSdramController(sc, sc->sc_SDRAMSIZE_Addr);
	}

	MWL_DBG(MWL_DBG_FW, "mwl: mwl_fwload(): "
	    "load %s firmware image (%u bytes)\n",
	    fwname, (unsigned int)fw_size);

	if (fwboot != NULL) {
		/*
		 * Do 2-stage load.  The 1st stage loader is setup
		 * with the bootrom loader then we load the real
		 * image using a different handshake. With this
		 * mechanism the firmware is segmented into chunks
		 * that have a CRC.  If a chunk is incorrect we'll
		 * be told to retransmit.
		 */
		/* XXX assumes hlpimage fits in a block */
		/* NB: zero size block indicates download is finished */
		if (!mwlSendBlock(sc, fwboot_size, fwboot, fwboot_size) ||
		    !mwlSendBlock(sc, 0, NULL, 0)) {
			err = ETIMEDOUT;
			goto bad;
		}
		DELAY(200 * FW_CHECK_USECS);
		if (sc->sc_SDRAMSIZE_Addr != 0) {
			/* Set up sdram controller for superflyv2 */
			mwlPokeSdramController(sc, sc->sc_SDRAMSIZE_Addr);
		}
		nbytes = ntries = 0;		/* NB: silence compiler */
		for (fp = fw, ep = fp + fw_size; fp < ep; ) {
			mwl_ctl_write4(sc, MACREG_REG_INT_CODE, 0);
			blocksize = mwl_ctl_read4(sc, MACREG_REG_SCRATCH);
			if (blocksize == 0)	/* download complete */
				break;
			if (blocksize > 0x00000c00) {
				err = EINVAL;
				goto bad;
			}
			if ((blocksize & 0x1) == 0) {
				/* block successfully downloaded, advance */
				fp += nbytes;
				ntries = 0;
			} else {
				if (++ntries > 2) {
					/*
					 * Guard against f/w telling us to
					 * retry infinitely.
					 */
					err = ELOOP;
					goto bad;
				}
				/* clear NAK bit/flag */
				blocksize &= ~0x1;
			}
			if (blocksize > _PTRDIFF(ep, fp)) {
				/* XXX this should not happen, what to do? */
				blocksize = _PTRDIFF(ep, fp);
			}
			nbytes = blocksize;
			if (!mwlSendBlock2(sc, fp, nbytes)) {
				err = ETIMEDOUT;
				goto bad;
			}
		}
	} else {
		for (fp = fw, ep = fp + fw_size; fp < ep; ) {
			nbytes = _PTRDIFF(ep, fp);
			if (nbytes > FW_DOWNLOAD_BLOCK_SIZE)
				nbytes = FW_DOWNLOAD_BLOCK_SIZE;
			if (!mwlSendBlock(sc, FW_DOWNLOAD_BLOCK_SIZE, fp,
			    nbytes)) {
				err = EIO;
				goto bad;
			}
			fp += nbytes;
		}
	}

	/*
	 * Wait for firmware to startup; we monitor the
	 * INT_CODE register waiting for a signature to
	 * written back indicating it's ready to go.
	 */
	sc->sc_cmd_mem[1] = 0;
	/*
	 * XXX WAR for mfg fw download
	 */
	if (OpMode != HostCmd_STA_MODE)
		mwlTriggerPciCmd(sc);
	for (i = 0; i < FW_MAX_NUM_CHECKS; i++) {
		mwl_ctl_write4(sc, MACREG_REG_GEN_PTR, OpMode);
		DELAY(FW_CHECK_USECS);
		if (mwl_ctl_read4(sc, MACREG_REG_INT_CODE) ==
		    FwReadySignature) {
			mwl_ctl_write4(sc, MACREG_REG_INT_CODE, 0x00);
			return (mwlResetHalState(sc));
		}
	}
	MWL_DBG(MWL_DBG_FW, "mwl: mwl_fwload(): "
	    "firmware download timeout\n");
	return (ETIMEDOUT);
bad:
	mwlFwReset(sc);
bad2:
	if (fw != NULL)
		kmem_free(fw, fw_size);
	if (fwboot != NULL)
		kmem_free(fwboot, fwboot_size);
	fwboot = fw = NULL;
	fwboot_index = fw_index = NULL;
	if (modfw != NULL)
		(void) ddi_modclose(modfw);
	return (err);
}

/*
 * Low level firmware cmd block handshake support.
 */
static void
mwlSendCmd(struct mwl_softc *sc)
{
	(void) ddi_dma_sync(sc->sc_cmd_dma.dma_hdl,
	    0,
	    sc->sc_cmd_dma.alength,
	    DDI_DMA_SYNC_FORDEV);

	mwl_ctl_write4(sc, MACREG_REG_GEN_PTR, sc->sc_cmd_dmaaddr);
	(void) mwl_ctl_read4(sc, MACREG_REG_INT_CODE);

	mwl_ctl_write4(sc, MACREG_REG_H2A_INTERRUPT_EVENTS,
	    MACREG_H2ARIC_BIT_DOOR_BELL);
}

static int
mwlExecuteCmd(struct mwl_softc *sc, unsigned short cmd)
{
	if (mwl_ctl_read4(sc,  MACREG_REG_INT_CODE) == 0xffffffff) {
		MWL_DBG(MWL_DBG_CMD, "mwl: mwlExecuteCmd(): "
		    "device not present!\n");
		return (EIO);
	}
	mwlSendCmd(sc);
	if (!mwlWaitForCmdComplete(sc, 0x8000 | cmd)) {
		MWL_DBG(MWL_DBG_CMD, "mwl: mwlExecuteCmd(): "
		    "timeout waiting for f/w cmd %s\n", mwlcmdname(cmd));
		return (ETIMEDOUT);
	}
	(void) ddi_dma_sync(sc->sc_cmd_dma.dma_hdl,
	    0,
	    sc->sc_cmd_dma.alength,
	    DDI_DMA_SYNC_FORDEV);

	MWL_DBG(MWL_DBG_CMD, "mwl: mwlExecuteCmd(): "
	    "send cmd %s\n", mwlcmdname(cmd));

	if (mwl_dbg_flags & MWL_DBG_CMD)
		dumpresult(sc, 1);

	return (0);
}

static int
mwlWaitForCmdComplete(struct mwl_softc *sc, uint16_t cmdCode)
{
#define	MAX_WAIT_FW_COMPLETE_ITERATIONS	10000
	int i;

	for (i = 0; i < MAX_WAIT_FW_COMPLETE_ITERATIONS; i++) {
		if (sc->sc_cmd_mem[0] == LE_16(cmdCode))
			return (1);
		DELAY(1 * 1000);
	}
	return (0);
#undef MAX_WAIT_FW_COMPLETE_ITERATIONS
}

static const char *
mwlcmdname(int cmd)
{
	static char buf[12];
#define	CMD(x)	case HostCmd_CMD_##x: return #x
	switch (cmd) {
	CMD(CODE_DNLD);
	CMD(GET_HW_SPEC);
	CMD(SET_HW_SPEC);
	CMD(MAC_MULTICAST_ADR);
	CMD(802_11_GET_STAT);
	CMD(MAC_REG_ACCESS);
	CMD(BBP_REG_ACCESS);
	CMD(RF_REG_ACCESS);
	CMD(802_11_RADIO_CONTROL);
	CMD(802_11_RF_TX_POWER);
	CMD(802_11_RF_ANTENNA);
	CMD(SET_BEACON);
	CMD(SET_RF_CHANNEL);
	CMD(SET_AID);
	CMD(SET_INFRA_MODE);
	CMD(SET_G_PROTECT_FLAG);
	CMD(802_11_RTS_THSD);
	CMD(802_11_SET_SLOT);
	CMD(SET_EDCA_PARAMS);
	CMD(802_11H_DETECT_RADAR);
	CMD(SET_WMM_MODE);
	CMD(HT_GUARD_INTERVAL);
	CMD(SET_FIXED_RATE);
	CMD(SET_LINKADAPT_CS_MODE);
	CMD(SET_MAC_ADDR);
	CMD(SET_RATE_ADAPT_MODE);
	CMD(BSS_START);
	CMD(SET_NEW_STN);
	CMD(SET_KEEP_ALIVE);
	CMD(SET_APMODE);
	CMD(SET_SWITCH_CHANNEL);
	CMD(UPDATE_ENCRYPTION);
	CMD(BASTREAM);
	CMD(SET_RIFS);
	CMD(SET_N_PROTECT_FLAG);
	CMD(SET_N_PROTECT_OPMODE);
	CMD(SET_OPTIMIZATION_LEVEL);
	CMD(GET_CALTABLE);
	CMD(SET_MIMOPSHT);
	CMD(GET_BEACON);
	CMD(SET_REGION_CODE);
	CMD(SET_POWERSAVESTATION);
	CMD(SET_TIM);
	CMD(GET_TIM);
	CMD(GET_SEQNO);
	CMD(DWDS_ENABLE);
	CMD(AMPDU_RETRY_RATEDROP_MODE);
	CMD(CFEND_ENABLE);
	}
	(void) snprintf(buf, sizeof (buf), "0x%x", cmd);
	return (buf);
#undef CMD
}

static void
dumpresult(struct mwl_softc *sc, int showresult)
{
	const FWCmdHdr *h = (const FWCmdHdr *)sc->sc_cmd_mem;
	int len;

	len = LE_16(h->Length);
#ifdef MWL_MBSS_SUPPORT
	MWL_DBG(MWL_DBG_CMD, "mwl: mwl_dumpresult(): "
	    "Cmd %s Length %d SeqNum %d MacId %d",
	    mwlcmdname(LE_16(h->Cmd) & ~0x8000), len, h->SeqNum, h->MacId);
#else
	MWL_DBG(MWL_DBG_CMD, "mwl: mwl_dumpresult(): "
	    "Cmd %s Length %d SeqNum %d",
	    mwlcmdname(LE_16(h->Cmd) & ~0x8000), len, LE_16(h->SeqNum));
#endif
	if (showresult) {
		const char *results[] =
		    { "OK", "ERROR", "NOT_SUPPORT", "PENDING", "BUSY",
		    "PARTIAL_DATA" };
		int result = LE_16(h->Result);

		if (result <= HostCmd_RESULT_PARTIAL_DATA)
			MWL_DBG(MWL_DBG_CMD, "mwl: dumpresult(): "
			    "Result %s", results[result]);
		else
			MWL_DBG(MWL_DBG_CMD, "mwl: dumpresult(): "
			    "Result %d", result);
	}
}

static int
mwlGetCalTable(struct mwl_softc *sc, uint8_t annex, uint8_t index)
{
	HostCmd_FW_GET_CALTABLE *pCmd;
	int retval;

	_CMD_SETUP(pCmd, HostCmd_FW_GET_CALTABLE, HostCmd_CMD_GET_CALTABLE);
	pCmd->annex = annex;
	pCmd->index = index;
	(void) memset(pCmd->calTbl, 0, sizeof (pCmd->calTbl));

	retval = mwlExecuteCmd(sc, HostCmd_CMD_GET_CALTABLE);
	if (retval == 0 &&
	    pCmd->calTbl[0] != annex && annex != 0 && annex != 255)
		retval = EIO;
	return (retval);
}

/*
 * Construct channel info for 2.4GHz channels from cal data.
 */
static void
get2Ghz(MWL_HAL_CHANNELINFO *ci, const uint8_t table[], int len)
{
	int i, j;

	j = 0;
	for (i = 0; i < len; i += 4) {
		struct mwl_hal_channel *hc = &ci->channels[j];
		hc->ieee = 1+j;
		hc->freq = ieee2mhz(1+j);
		(void) memcpy(hc->targetPowers, &table[i], 4);
		setmaxtxpow(hc, 0, 4);
		j++;
	}
	ci->nchannels = j;
	ci->freqLow = ieee2mhz(1);
	ci->freqHigh = ieee2mhz(j);
}

/*
 * Construct channel info for 5GHz channels from cal data.
 */
static void
get5Ghz(MWL_HAL_CHANNELINFO *ci, const uint8_t table[], int len)
{
	int i, j, f, l, h;

	l = 32000;
	h = 0;
	j = 0;
	for (i = 0; i < len; i += 4) {
		struct mwl_hal_channel *hc;

		if (table[i] == 0)
			continue;
		f = 5000 + 5*table[i];
		if (f < l)
			l = f;
		if (f > h)
			h = f;
		hc = &ci->channels[j];
		hc->freq = (uint16_t)f;
		hc->ieee = table[i];
		(void) memcpy(hc->targetPowers, &table[i], 4);
		setmaxtxpow(hc, 1, 4);	/* NB: col 1 is the freq, skip */
		j++;
	}
	ci->nchannels = j;
	ci->freqLow = (uint16_t)((l == 32000) ? 0 : l);
	ci->freqHigh = (uint16_t)h;
}

/*
 * Calculate the max tx power from the channel's cal data.
 */
static void
setmaxtxpow(struct mwl_hal_channel *hc, int i, int maxix)
{
	hc->maxTxPow = hc->targetPowers[i];
	for (i++; i < maxix; i++)
		if (hc->targetPowers[i] > hc->maxTxPow)
			hc->maxTxPow = hc->targetPowers[i];
}

static uint16_t
ieee2mhz(int chan)
{
	if (chan == 14)
		return (2484);
	if (chan < 14)
		return (2407 + chan * 5);
	return (2512 + (chan - 15) * 20);
}

static void
dumpcaldata(const char *name, const uint8_t *table, int n)
{
	int i;
	MWL_DBG(MWL_DBG_HW, "\n%s:\n", name);
	for (i = 0; i < n; i += 4)
		MWL_DBG(MWL_DBG_HW, "[%2d] %3d %3d %3d %3d\n",
		    i/4, table[i+0], table[i+1], table[i+2], table[i+3]);
}

static int
mwlGetPwrCalTable(struct mwl_softc *sc)
{
	const uint8_t *data;
	MWL_HAL_CHANNELINFO *ci;
	int len;

	/* NB: we hold the lock so it's ok to use cmdbuf */
	data = ((const HostCmd_FW_GET_CALTABLE *) sc->sc_cmd_mem)->calTbl;
	if (mwlGetCalTable(sc, 33, 0) == 0) {
		len = (data[2] | (data[3] << 8)) - 12;
		if (len > PWTAGETRATETABLE20M)
			len = PWTAGETRATETABLE20M;
		dumpcaldata("2.4G 20M", &data[12], len);
		get2Ghz(&sc->sc_20M, &data[12], len);
	}
	if (mwlGetCalTable(sc, 34, 0) == 0) {
		len = (data[2] | (data[3] << 8)) - 12;
		if (len > PWTAGETRATETABLE40M)
			len = PWTAGETRATETABLE40M;
		dumpcaldata("2.4G 40M", &data[12], len);
		ci = &sc->sc_40M;
		get2Ghz(ci, &data[12], len);
	}
	if (mwlGetCalTable(sc, 35, 0) == 0) {
		len = (data[2] | (data[3] << 8)) - 20;
		if (len > PWTAGETRATETABLE20M_5G)
			len = PWTAGETRATETABLE20M_5G;
		dumpcaldata("5G 20M", &data[20], len);
		get5Ghz(&sc->sc_20M_5G, &data[20], len);
	}
	if (mwlGetCalTable(sc, 36, 0) == 0) {
		len = (data[2] | (data[3] << 8)) - 20;
		if (len > PWTAGETRATETABLE40M_5G)
			len = PWTAGETRATETABLE40M_5G;
		dumpcaldata("5G 40M", &data[20], len);
		ci = &sc->sc_40M_5G;
		get5Ghz(ci, &data[20], len);
	}
	sc->sc_hw_flags |= MHF_CALDATA;
	return (0);
}

/*
 * Reset internal state after a firmware download.
 */
static int
mwlResetHalState(struct mwl_softc *sc)
{
	int err = 0;

	/*
	 * Fetch cal data for later use.
	 * XXX may want to fetch other stuff too.
	 */
	/* XXX check return */
	if ((sc->sc_hw_flags & MHF_CALDATA) == 0)
		err = mwlGetPwrCalTable(sc);
	return (err);
}

#define	IEEE80211_CHAN_HTG	(IEEE80211_CHAN_HT|IEEE80211_CHAN_G)
#define	IEEE80211_CHAN_HTA	(IEEE80211_CHAN_HT|IEEE80211_CHAN_A)

static void
addchan(struct mwl_channel *c, int freq, int flags, int ieee, int txpow)
{
	c->ic_freq = (uint16_t)freq;
	c->ic_flags = flags;
	c->ic_ieee = (uint8_t)ieee;
	c->ic_minpower = 0;
	c->ic_maxpower = 2*txpow;
	c->ic_maxregpower = (uint8_t)txpow;
}

static const struct mwl_channel *
findchannel(const struct mwl_channel chans[], int nchans,
	int freq, int flags)
{
	const struct mwl_channel *c;
	int i;

	for (i = 0; i < nchans; i++) {
		c = &chans[i];
		if (c->ic_freq == freq && c->ic_flags == flags)
			return (c);
	}
	return (NULL);
}

static void
addht40channels(struct mwl_channel chans[], int maxchans, int *nchans,
	const MWL_HAL_CHANNELINFO *ci, int flags)
{
	struct mwl_channel *c;
	const struct mwl_channel *extc;
	const struct mwl_hal_channel *hc;
	int i;

	c = &chans[*nchans];

	flags &= ~IEEE80211_CHAN_HT;
	for (i = 0; i < ci->nchannels; i++) {
		/*
		 * Each entry defines an HT40 channel pair; find the
		 * extension channel above and the insert the pair.
		 */
		hc = &ci->channels[i];
		extc = findchannel(chans, *nchans, hc->freq+20,
		    flags | IEEE80211_CHAN_HT20);
		if (extc != NULL) {
			if (*nchans >= maxchans)
				break;
			addchan(c, hc->freq, flags | IEEE80211_CHAN_HT40U,
			    hc->ieee, hc->maxTxPow);
			c->ic_extieee = extc->ic_ieee;
			c++, (*nchans)++;
			if (*nchans >= maxchans)
				break;
			addchan(c, extc->ic_freq, flags | IEEE80211_CHAN_HT40D,
			    extc->ic_ieee, hc->maxTxPow);
			c->ic_extieee = hc->ieee;
			c++, (*nchans)++;
		}
	}
}

static void
addchannels(struct mwl_channel chans[], int maxchans, int *nchans,
	const MWL_HAL_CHANNELINFO *ci, int flags)
{
	struct mwl_channel *c;
	int i;

	c = &chans[*nchans];

	for (i = 0; i < ci->nchannels; i++) {
		const struct mwl_hal_channel *hc;

		hc = &ci->channels[i];
		if (*nchans >= maxchans)
			break;
		addchan(c, hc->freq, flags, hc->ieee, hc->maxTxPow);
		c++, (*nchans)++;

		if (flags == IEEE80211_CHAN_G || flags == IEEE80211_CHAN_HTG) {
			/* g channel have a separate b-only entry */
			if (*nchans >= maxchans)
				break;
			c[0] = c[-1];
			c[-1].ic_flags = IEEE80211_CHAN_B;
			c++, (*nchans)++;
		}
		if (flags == IEEE80211_CHAN_HTG) {
			/* HT g channel have a separate g-only entry */
			if (*nchans >= maxchans)
				break;
			c[-1].ic_flags = IEEE80211_CHAN_G;
			c[0] = c[-1];
			c[0].ic_flags &= ~IEEE80211_CHAN_HT;
			c[0].ic_flags |= IEEE80211_CHAN_HT20;	/* HT20 */
			c++, (*nchans)++;
		}
		if (flags == IEEE80211_CHAN_HTA) {
			/* HT a channel have a separate a-only entry */
			if (*nchans >= maxchans)
				break;
			c[-1].ic_flags = IEEE80211_CHAN_A;
			c[0] = c[-1];
			c[0].ic_flags &= ~IEEE80211_CHAN_HT;
			c[0].ic_flags |= IEEE80211_CHAN_HT20;	/* HT20 */
			c++, (*nchans)++;
		}
	}
}

static int
mwl_hal_getchannelinfo(struct mwl_softc *sc, int band, int chw,
	const MWL_HAL_CHANNELINFO **ci)
{
	switch (band) {
	case MWL_FREQ_BAND_2DOT4GHZ:
		*ci = (chw == MWL_CH_20_MHz_WIDTH) ? &sc->sc_20M : &sc->sc_40M;
		break;
	case MWL_FREQ_BAND_5GHZ:
		*ci = (chw == MWL_CH_20_MHz_WIDTH) ?
		    &sc->sc_20M_5G : &sc->sc_40M_5G;
		break;
	default:
		return (EINVAL);
	}
	return (((*ci)->freqLow == (*ci)->freqHigh) ? EINVAL : 0);
}

static void
getchannels(struct mwl_softc *sc, int maxchans, int *nchans,
	struct mwl_channel chans[])
{
	const MWL_HAL_CHANNELINFO *ci;

	/*
	 * Use the channel info from the hal to craft the
	 * channel list.  Note that we pass back an unsorted
	 * list; the caller is required to sort it for us
	 * (if desired).
	 */
	*nchans = 0;
	if (mwl_hal_getchannelinfo(sc,
	    MWL_FREQ_BAND_2DOT4GHZ, MWL_CH_20_MHz_WIDTH, &ci) == 0)
		addchannels(chans, maxchans, nchans, ci, IEEE80211_CHAN_HTG);
	if (mwl_hal_getchannelinfo(sc,
	    MWL_FREQ_BAND_5GHZ, MWL_CH_20_MHz_WIDTH, &ci) == 0)
		addchannels(chans, maxchans, nchans, ci, IEEE80211_CHAN_HTA);
	if (mwl_hal_getchannelinfo(sc,
	    MWL_FREQ_BAND_2DOT4GHZ, MWL_CH_40_MHz_WIDTH, &ci) == 0)
		addht40channels(chans, maxchans, nchans, ci,
		    IEEE80211_CHAN_HTG);
	if (mwl_hal_getchannelinfo(sc,
	    MWL_FREQ_BAND_5GHZ, MWL_CH_40_MHz_WIDTH, &ci) == 0)
		addht40channels(chans, maxchans, nchans, ci,
		    IEEE80211_CHAN_HTA);
}

static int
mwl_getchannels(struct mwl_softc *sc)
{
	/*
	 * Use the channel info from the hal to craft the
	 * channel list for net80211.  Note that we pass up
	 * an unsorted list; net80211 will sort it for us.
	 */
	(void) memset(sc->sc_channels, 0, sizeof (sc->sc_channels));
	sc->sc_nchans = 0;
	getchannels(sc, IEEE80211_CHAN_MAX, &sc->sc_nchans, sc->sc_channels);

	sc->sc_regdomain.regdomain = SKU_DEBUG;
	sc->sc_regdomain.country = CTRY_DEFAULT;
	sc->sc_regdomain.location = 'I';
	sc->sc_regdomain.isocc[0] = ' ';	/* XXX? */
	sc->sc_regdomain.isocc[1] = ' ';
	return (sc->sc_nchans == 0 ? EIO : 0);
}

#undef IEEE80211_CHAN_HTA
#undef IEEE80211_CHAN_HTG

/*
 * Return "hw specs".  Note this must be the first
 * cmd MUST be done after a firmware download or the
 * f/w will lockup.
 * XXX move into the hal so driver doesn't need to be responsible
 */
static int
mwl_gethwspecs(struct mwl_softc *sc)
{
	struct mwl_hal_hwspec *hw;
	HostCmd_DS_GET_HW_SPEC *pCmd;
	int retval;

	hw = &sc->sc_hwspecs;
	_CMD_SETUP(pCmd, HostCmd_DS_GET_HW_SPEC, HostCmd_CMD_GET_HW_SPEC);
	(void) memset(&pCmd->PermanentAddr[0], 0xff, IEEE80211_ADDR_LEN);
	pCmd->ulFwAwakeCookie = LE_32((unsigned int)sc->sc_cmd_dmaaddr + 2048);

	retval = mwlExecuteCmd(sc, HostCmd_CMD_GET_HW_SPEC);
	if (retval == 0) {
		IEEE80211_ADDR_COPY(hw->macAddr, pCmd->PermanentAddr);
		hw->wcbBase[0] = LE_32(pCmd->WcbBase0) & 0x0000ffff;
		hw->wcbBase[1] = LE_32(pCmd->WcbBase1[0]) & 0x0000ffff;
		hw->wcbBase[2] = LE_32(pCmd->WcbBase1[1]) & 0x0000ffff;
		hw->wcbBase[3] = LE_32(pCmd->WcbBase1[2]) & 0x0000ffff;
		hw->rxDescRead = LE_32(pCmd->RxPdRdPtr)& 0x0000ffff;
		hw->rxDescWrite = LE_32(pCmd->RxPdWrPtr)& 0x0000ffff;
		hw->regionCode = LE_16(pCmd->RegionCode) & 0x00ff;
		hw->fwReleaseNumber = LE_32(pCmd->FWReleaseNumber);
		hw->maxNumWCB = LE_16(pCmd->NumOfWCB);
		hw->maxNumMCAddr = LE_16(pCmd->NumOfMCastAddr);
		hw->numAntennas = LE_16(pCmd->NumberOfAntenna);
		hw->hwVersion = pCmd->Version;
		hw->hostInterface = pCmd->HostIf;

		sc->sc_revs.mh_macRev = hw->hwVersion;		/* XXX */
		sc->sc_revs.mh_phyRev = hw->hostInterface;	/* XXX */
	}

	return (retval);
}

static int
mwl_hal_setmac_locked(struct mwl_softc *sc,
	const uint8_t addr[IEEE80211_ADDR_LEN])
{
	HostCmd_DS_SET_MAC *pCmd;

	_VCMD_SETUP(pCmd, HostCmd_DS_SET_MAC, HostCmd_CMD_SET_MAC_ADDR);
	IEEE80211_ADDR_COPY(&pCmd->MacAddr[0], addr);
#ifdef MWL_MBSS_SUPPORT
	/* NB: already byte swapped */
	pCmd->MacType = WL_MAC_TYPE_PRIMARY_CLIENT;
#endif
	return (mwlExecuteCmd(sc, HostCmd_CMD_SET_MAC_ADDR));
}

static void
cvtPeerInfo(PeerInfo_t *to, const MWL_HAL_PEERINFO *from)
{
	to->LegacyRateBitMap = LE_32(from->LegacyRateBitMap);
	to->HTRateBitMap = LE_32(from->HTRateBitMap);
	to->CapInfo = LE_16(from->CapInfo);
	to->HTCapabilitiesInfo = LE_16(from->HTCapabilitiesInfo);
	to->MacHTParamInfo = from->MacHTParamInfo;
	to->AddHtInfo.ControlChan = from->AddHtInfo.ControlChan;
	to->AddHtInfo.AddChan = from->AddHtInfo.AddChan;
	to->AddHtInfo.OpMode = LE_16(from->AddHtInfo.OpMode);
	to->AddHtInfo.stbc = LE_16(from->AddHtInfo.stbc);
}

/* XXX station id must be in [0..63] */
static int
mwl_hal_newstation(struct mwl_softc *sc,
	const uint8_t addr[IEEE80211_ADDR_LEN], uint16_t aid, uint16_t sid,
	const MWL_HAL_PEERINFO *peer, int isQosSta, int wmeInfo)
{
	HostCmd_FW_SET_NEW_STN *pCmd;
	int retval;

	_VCMD_SETUP(pCmd, HostCmd_FW_SET_NEW_STN, HostCmd_CMD_SET_NEW_STN);
	pCmd->AID = LE_16(aid);
	pCmd->StnId = LE_16(sid);
	pCmd->Action = LE_16(0);	/* SET */
	if (peer != NULL) {
		/* NB: must fix up byte order */
		cvtPeerInfo(&pCmd->PeerInfo, peer);
	}
	IEEE80211_ADDR_COPY(&pCmd->MacAddr[0], addr);
	pCmd->Qosinfo = (uint8_t)wmeInfo;
	pCmd->isQosSta = (isQosSta != 0);

	MWL_DBG(MWL_DBG_HW, "mwl: mwl_hal_newstation(): "
	    "LegacyRateBitMap %x, CapInfo %x\n",
	    pCmd->PeerInfo.LegacyRateBitMap, pCmd->PeerInfo.CapInfo);

	retval = mwlExecuteCmd(sc, HostCmd_CMD_SET_NEW_STN);
	return (retval);
}

/*
 * Configure antenna use.
 * Takes effect immediately.
 * XXX tx antenna setting ignored
 * XXX rx antenna setting should always be 3 (for now)
 */
static int
mwl_hal_setantenna(struct mwl_softc *sc, MWL_HAL_ANTENNA dirSet, int ant)
{
	HostCmd_DS_802_11_RF_ANTENNA *pCmd;
	int retval;

	if (!(dirSet == WL_ANTENNATYPE_RX || dirSet == WL_ANTENNATYPE_TX))
		return (EINVAL);

	_CMD_SETUP(pCmd, HostCmd_DS_802_11_RF_ANTENNA,
	    HostCmd_CMD_802_11_RF_ANTENNA);
	pCmd->Action = LE_16(dirSet);
	if (ant == 0)			/* default to all/both antennae */
		ant = 3;
	pCmd->AntennaMode = LE_16(ant);

	retval = mwlExecuteCmd(sc, HostCmd_CMD_802_11_RF_ANTENNA);
	return (retval);
}

/*
 * Configure radio.
 * Takes effect immediately.
 * XXX preamble installed after set fixed rate cmd
 */
static int
mwl_hal_setradio(struct mwl_softc *sc, int onoff, MWL_HAL_PREAMBLE preamble)
{
	HostCmd_DS_802_11_RADIO_CONTROL *pCmd;
	int retval;

	_CMD_SETUP(pCmd, HostCmd_DS_802_11_RADIO_CONTROL,
	    HostCmd_CMD_802_11_RADIO_CONTROL);
	pCmd->Action = LE_16(HostCmd_ACT_GEN_SET);
	if (onoff == 0)
		pCmd->Control = 0;
	else
		pCmd->Control = LE_16(preamble);
	pCmd->RadioOn = LE_16(onoff);

	retval = mwlExecuteCmd(sc, HostCmd_CMD_802_11_RADIO_CONTROL);
	return (retval);
}

static int
mwl_hal_setwmm(struct mwl_softc *sc, int onoff)
{
	HostCmd_FW_SetWMMMode *pCmd;
	int retval;

	_CMD_SETUP(pCmd, HostCmd_FW_SetWMMMode,
	    HostCmd_CMD_SET_WMM_MODE);
	pCmd->Action = LE_16(onoff);

	retval = mwlExecuteCmd(sc, HostCmd_CMD_SET_WMM_MODE);
	return (retval);
}

/*
 * Convert public channel flags definition to a
 * value suitable for feeding to the firmware.
 * Note this includes byte swapping.
 */
static uint32_t
cvtChannelFlags(const MWL_HAL_CHANNEL *chan)
{
	uint32_t w;

	/*
	 * NB: f/w only understands FREQ_BAND_5GHZ, supplying the more
	 * precise band info causes it to lockup (sometimes).
	 */
	w = (chan->channelFlags.FreqBand == MWL_FREQ_BAND_2DOT4GHZ) ?
	    FREQ_BAND_2DOT4GHZ : FREQ_BAND_5GHZ;
	switch (chan->channelFlags.ChnlWidth) {
	case MWL_CH_10_MHz_WIDTH:
		w |= CH_10_MHz_WIDTH;
		break;
	case MWL_CH_20_MHz_WIDTH:
		w |= CH_20_MHz_WIDTH;
		break;
	case MWL_CH_40_MHz_WIDTH:
	default:
		w |= CH_40_MHz_WIDTH;
		break;
	}
	switch (chan->channelFlags.ExtChnlOffset) {
	case MWL_EXT_CH_NONE:
		w |= EXT_CH_NONE;
		break;
	case MWL_EXT_CH_ABOVE_CTRL_CH:
		w |= EXT_CH_ABOVE_CTRL_CH;
		break;
	case MWL_EXT_CH_BELOW_CTRL_CH:
		w |= EXT_CH_BELOW_CTRL_CH;
		break;
	}
	return (LE_32(w));
}

static int
mwl_hal_setchannel(struct mwl_softc *sc, const MWL_HAL_CHANNEL *chan)
{
	HostCmd_FW_SET_RF_CHANNEL *pCmd;
	int retval;

	_CMD_SETUP(pCmd, HostCmd_FW_SET_RF_CHANNEL, HostCmd_CMD_SET_RF_CHANNEL);
	pCmd->Action = LE_16(HostCmd_ACT_GEN_SET);
	pCmd->CurrentChannel = chan->channel;
	pCmd->ChannelFlags = cvtChannelFlags(chan);	/* NB: byte-swapped */

	retval = mwlExecuteCmd(sc, HostCmd_CMD_SET_RF_CHANNEL);
	return (retval);
}

static int
mwl_hal_settxpower(struct mwl_softc *sc,
    const MWL_HAL_CHANNEL *c, uint8_t maxtxpow)
{
	HostCmd_DS_802_11_RF_TX_POWER *pCmd;
	const struct mwl_hal_channel *hc;
	int i = 0, retval;

	hc = findhalchannel(sc, c);
	if (hc == NULL) {
		/* XXX temp while testing */
		MWL_DBG(MWL_DBG_HW, "mwl: mwl_hal_settxpower(): "
		    "no cal data for channel %u band %u width %u ext %u\n",
		    c->channel, c->channelFlags.FreqBand,
		    c->channelFlags.ChnlWidth, c->channelFlags.ExtChnlOffset);
		return (EINVAL);
	}

	_CMD_SETUP(pCmd, HostCmd_DS_802_11_RF_TX_POWER,
	    HostCmd_CMD_802_11_RF_TX_POWER);
	pCmd->Action = LE_16(HostCmd_ACT_GEN_SET_LIST);
	/* NB: 5Ghz cal data have the channel # in [0]; don't truncate */
	if (c->channelFlags.FreqBand == MWL_FREQ_BAND_5GHZ)
		pCmd->PowerLevelList[i++] = LE_16(hc->targetPowers[0]);
	for (; i < 4; i++) {
		uint16_t pow = hc->targetPowers[i];
		if (pow > maxtxpow)
			pow = maxtxpow;
		pCmd->PowerLevelList[i] = LE_16(pow);
	}
	retval = mwlExecuteCmd(sc, HostCmd_CMD_802_11_RF_TX_POWER);
	return (retval);
}

#define	RATEVAL(r)	((r) &~ RATE_MCS)
#define	RATETYPE(r)	(((r) & RATE_MCS) ? HT_RATE_TYPE : LEGACY_RATE_TYPE)

static int
mwl_hal_settxrate(struct mwl_softc *sc, MWL_HAL_TXRATE_HANDLING handling,
	const MWL_HAL_TXRATE *rate)
{
	HostCmd_FW_USE_FIXED_RATE *pCmd;
	FIXED_RATE_ENTRY *fp;
	int retval, i, n;

	_VCMD_SETUP(pCmd, HostCmd_FW_USE_FIXED_RATE,
	    HostCmd_CMD_SET_FIXED_RATE);

	pCmd->MulticastRate = RATEVAL(rate->McastRate);
	pCmd->MultiRateTxType = RATETYPE(rate->McastRate);
	/* NB: no rate type field */
	pCmd->ManagementRate = RATEVAL(rate->MgtRate);
	(void) memset(pCmd->FixedRateTable, 0, sizeof (pCmd->FixedRateTable));
	if (handling == RATE_FIXED) {
		pCmd->Action = LE_32(HostCmd_ACT_GEN_SET);
		pCmd->AllowRateDrop = LE_32(FIXED_RATE_WITHOUT_AUTORATE_DROP);
		fp = pCmd->FixedRateTable;
		fp->FixedRate =
		    LE_32(RATEVAL(rate->RateSeries[0].Rate));
		fp->FixRateTypeFlags.FixRateType =
		    LE_32(RATETYPE(rate->RateSeries[0].Rate));
		pCmd->EntryCount = LE_32(1);
	} else if (handling == RATE_FIXED_DROP) {
		pCmd->Action = LE_32(HostCmd_ACT_GEN_SET);
		pCmd->AllowRateDrop = LE_32(FIXED_RATE_WITH_AUTO_RATE_DROP);
		n = 0;
		fp = pCmd->FixedRateTable;
		for (i = 0; i < 4; i++) {
			if (rate->RateSeries[0].TryCount == 0)
				break;
			fp->FixRateTypeFlags.FixRateType =
			    LE_32(RATETYPE(rate->RateSeries[i].Rate));
			fp->FixedRate =
			    LE_32(RATEVAL(rate->RateSeries[i].Rate));
			fp->FixRateTypeFlags.RetryCountValid =
			    LE_32(RETRY_COUNT_VALID);
			fp->RetryCount =
			    LE_32(rate->RateSeries[i].TryCount-1);
			n++;
		}
		pCmd->EntryCount = LE_32(n);
	} else
		pCmd->Action = LE_32(HostCmd_ACT_NOT_USE_FIXED_RATE);

	retval = mwlExecuteCmd(sc, HostCmd_CMD_SET_FIXED_RATE);
	return (retval);
}

static int
mwl_hal_settxrate_auto(struct mwl_softc *sc, const MWL_HAL_TXRATE *rate)
{
	HostCmd_FW_USE_FIXED_RATE *pCmd;
	int retval;

	_CMD_SETUP(pCmd, HostCmd_FW_USE_FIXED_RATE,
	    HostCmd_CMD_SET_FIXED_RATE);

	pCmd->MulticastRate = RATEVAL(rate->McastRate);
	pCmd->MultiRateTxType = RATETYPE(rate->McastRate);
	/* NB: no rate type field */
	pCmd->ManagementRate = RATEVAL(rate->MgtRate);
	(void) memset(pCmd->FixedRateTable, 0, sizeof (pCmd->FixedRateTable));
	pCmd->Action = LE_32(HostCmd_ACT_NOT_USE_FIXED_RATE);

	retval = mwlExecuteCmd(sc, HostCmd_CMD_SET_FIXED_RATE);
	return (retval);
}

#undef RATEVAL
#undef RATETYPE

/* XXX 0 = indoor, 1 = outdoor */
static int
mwl_hal_setrateadaptmode(struct mwl_softc *sc, uint16_t mode)
{
	HostCmd_DS_SET_RATE_ADAPT_MODE *pCmd;
	int retval;

	_CMD_SETUP(pCmd, HostCmd_DS_SET_RATE_ADAPT_MODE,
	    HostCmd_CMD_SET_RATE_ADAPT_MODE);
	pCmd->Action = LE_16(HostCmd_ACT_GEN_SET);
	pCmd->RateAdaptMode = LE_16(mode);

	retval = mwlExecuteCmd(sc, HostCmd_CMD_SET_RATE_ADAPT_MODE);
	return (retval);
}

static int
mwl_hal_setoptimizationlevel(struct mwl_softc *sc, int level)
{
	HostCmd_FW_SET_OPTIMIZATION_LEVEL *pCmd;
	int retval;

	_CMD_SETUP(pCmd, HostCmd_FW_SET_OPTIMIZATION_LEVEL,
	    HostCmd_CMD_SET_OPTIMIZATION_LEVEL);
	pCmd->OptLevel = (uint8_t)level;

	retval = mwlExecuteCmd(sc, HostCmd_CMD_SET_OPTIMIZATION_LEVEL);
	return (retval);
}

/*
 * Set the region code that selects the radar bin'ing agorithm.
 */
static int
mwl_hal_setregioncode(struct mwl_softc *sc, int regionCode)
{
	HostCmd_SET_REGIONCODE_INFO *pCmd;
	int retval;

	_CMD_SETUP(pCmd, HostCmd_SET_REGIONCODE_INFO,
	    HostCmd_CMD_SET_REGION_CODE);
	/* XXX map pseudo-codes to fw codes */
	switch (regionCode) {
	case DOMAIN_CODE_ETSI_131:
		pCmd->regionCode = LE_16(DOMAIN_CODE_ETSI);
		break;
	default:
		pCmd->regionCode = LE_16(regionCode);
		break;
	}

	retval = mwlExecuteCmd(sc, HostCmd_CMD_SET_REGION_CODE);
	return (retval);
}

static int
mwl_hal_setassocid(struct mwl_softc *sc,
	const uint8_t bssId[IEEE80211_ADDR_LEN], uint16_t assocId)
{
	HostCmd_FW_SET_AID *pCmd = (HostCmd_FW_SET_AID *) &sc->sc_cmd_mem[0];
	int retval;

	_VCMD_SETUP(pCmd, HostCmd_FW_SET_AID, HostCmd_CMD_SET_AID);
	pCmd->AssocID = LE_16(assocId);
	IEEE80211_ADDR_COPY(&pCmd->MacAddr[0], bssId);

	retval = mwlExecuteCmd(sc, HostCmd_CMD_SET_AID);
	return (retval);
}

/*
 * Inform firmware of tx rate parameters.  Called whenever
 * user-settable params change and after a channel change.
 */
static int
mwl_setrates(struct ieee80211com *ic)
{
	struct mwl_softc *sc = (struct mwl_softc *)ic;
	MWL_HAL_TXRATE rates;

	const struct ieee80211_rateset *rs;
	rs = &ic->ic_bss->in_rates;

	/*
	 * Update the h/w rate map.
	 * NB: 0x80 for MCS is passed through unchanged
	 */
	(void) memset(&rates, 0, sizeof (rates));
	/* rate used to send management frames */
	rates.MgtRate = rs->ir_rates[0] & IEEE80211_RATE_VAL;
	/* rate used to send multicast frames */
	rates.McastRate = rates.MgtRate;

	return (mwl_hal_settxrate(sc, RATE_AUTO, &rates));
}

/*
 * Set packet size threshold for implicit use of RTS.
 * Takes effect immediately.
 * XXX packet length > threshold =>'s RTS
 */
static int
mwl_hal_setrtsthreshold(struct mwl_softc *sc, int threshold)
{
	HostCmd_DS_802_11_RTS_THSD *pCmd;
	int retval;

	_VCMD_SETUP(pCmd, HostCmd_DS_802_11_RTS_THSD,
	    HostCmd_CMD_802_11_RTS_THSD);
	pCmd->Action  = LE_16(HostCmd_ACT_GEN_SET);
	pCmd->Threshold = LE_16(threshold);

	retval = mwlExecuteCmd(sc, HostCmd_CMD_802_11_RTS_THSD);
	return (retval);
}

static int
mwl_hal_setcsmode(struct mwl_softc *sc, MWL_HAL_CSMODE csmode)
{
	HostCmd_DS_SET_LINKADAPT_CS_MODE *pCmd;
	int retval;

	_CMD_SETUP(pCmd, HostCmd_DS_SET_LINKADAPT_CS_MODE,
	    HostCmd_CMD_SET_LINKADAPT_CS_MODE);
	pCmd->Action = LE_16(HostCmd_ACT_GEN_SET);
	pCmd->CSMode = LE_16(csmode);

	retval = mwlExecuteCmd(sc, HostCmd_CMD_SET_LINKADAPT_CS_MODE);
	return (retval);
}

static int
mwl_hal_setpromisc(struct mwl_softc *sc, int ena)
{
	uint32_t v;

	v = mwl_ctl_read4(sc, MACREG_REG_PROMISCUOUS);
	mwl_ctl_write4(sc, MACREG_REG_PROMISCUOUS, ena ? v | 1 : v & ~1);

	return (0);
}

static int
mwl_hal_start(struct mwl_softc *sc)
{
	HostCmd_DS_BSS_START *pCmd;
	int retval;

	_VCMD_SETUP(pCmd, HostCmd_DS_BSS_START, HostCmd_CMD_BSS_START);
	pCmd->Enable = LE_32(HostCmd_ACT_GEN_ON);

	retval = mwlExecuteCmd(sc, HostCmd_CMD_BSS_START);
	return (retval);
}

/*
 * Enable sta-mode operation (disables beacon frame xmit).
 */
static int
mwl_hal_setinframode(struct mwl_softc *sc)
{
	HostCmd_FW_SET_INFRA_MODE *pCmd;
	int retval;

	_VCMD_SETUP(pCmd, HostCmd_FW_SET_INFRA_MODE,
	    HostCmd_CMD_SET_INFRA_MODE);

	retval = mwlExecuteCmd(sc, HostCmd_CMD_SET_INFRA_MODE);
	return (retval);
}

static int
mwl_hal_stop(struct mwl_softc *sc)
{
	HostCmd_DS_BSS_START *pCmd;
	int retval;

	_VCMD_SETUP(pCmd, HostCmd_DS_BSS_START,
	    HostCmd_CMD_BSS_START);
	pCmd->Enable = LE_32(HostCmd_ACT_GEN_OFF);
	retval = mwlExecuteCmd(sc, HostCmd_CMD_BSS_START);

	return (retval);
}

static int
mwl_hal_keyset(struct mwl_softc *sc, const MWL_HAL_KEYVAL *kv,
	const uint8_t mac[IEEE80211_ADDR_LEN])
{
	HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY *pCmd;
	int retval;

	_VCMD_SETUP(pCmd, HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY,
	    HostCmd_CMD_UPDATE_ENCRYPTION);
	if (kv->keyFlags & (KEY_FLAG_TXGROUPKEY|KEY_FLAG_RXGROUPKEY))
		pCmd->ActionType = LE_32(EncrActionTypeSetGroupKey);
	else
		pCmd->ActionType = LE_32(EncrActionTypeSetKey);
	pCmd->KeyParam.Length = LE_16(sizeof (pCmd->KeyParam));
	pCmd->KeyParam.KeyTypeId = LE_16(kv->keyTypeId);
	pCmd->KeyParam.KeyInfo = LE_32(kv->keyFlags);
	pCmd->KeyParam.KeyIndex = LE_32(kv->keyIndex);
	/* NB: includes TKIP MIC keys */
	(void) memcpy(&pCmd->KeyParam.Key, &kv->key, kv->keyLen);
	switch (kv->keyTypeId) {
	case KEY_TYPE_ID_WEP:
		pCmd->KeyParam.KeyLen = LE_16(kv->keyLen);
		break;
	case KEY_TYPE_ID_TKIP:
		pCmd->KeyParam.KeyLen = LE_16(sizeof (TKIP_TYPE_KEY));
		pCmd->KeyParam.Key.TkipKey.TkipRsc.low =
		    LE_16(kv->key.tkip.rsc.low);
		pCmd->KeyParam.Key.TkipKey.TkipRsc.high =
		    LE_32(kv->key.tkip.rsc.high);
		pCmd->KeyParam.Key.TkipKey.TkipTsc.low =
		    LE_16(kv->key.tkip.tsc.low);
		pCmd->KeyParam.Key.TkipKey.TkipTsc.high =
		    LE_32(kv->key.tkip.tsc.high);
		break;
	case KEY_TYPE_ID_AES:
		pCmd->KeyParam.KeyLen = LE_16(sizeof (AES_TYPE_KEY));
		break;
	}
#ifdef MWL_MBSS_SUPPORT
	IEEE80211_ADDR_COPY(pCmd->KeyParam.Macaddr, mac);
#else
	IEEE80211_ADDR_COPY(pCmd->Macaddr, mac);
#endif

	retval = mwlExecuteCmd(sc, HostCmd_CMD_UPDATE_ENCRYPTION);
	return (retval);
}

static int
mwl_hal_keyreset(struct mwl_softc *sc, const MWL_HAL_KEYVAL *kv,
    const uint8_t mac[IEEE80211_ADDR_LEN])
{
	HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY *pCmd;
	int retval;

	_VCMD_SETUP(pCmd, HostCmd_FW_UPDATE_ENCRYPTION_SET_KEY,
	    HostCmd_CMD_UPDATE_ENCRYPTION);
	pCmd->ActionType = LE_16(EncrActionTypeRemoveKey);
	pCmd->KeyParam.Length = LE_16(sizeof (pCmd->KeyParam));
	pCmd->KeyParam.KeyTypeId = LE_16(kv->keyTypeId);
	pCmd->KeyParam.KeyInfo = LE_32(kv->keyFlags);
	pCmd->KeyParam.KeyIndex = LE_32(kv->keyIndex);
#ifdef MWL_MBSS_SUPPORT
	IEEE80211_ADDR_COPY(pCmd->KeyParam.Macaddr, mac);
#else
	IEEE80211_ADDR_COPY(pCmd->Macaddr, mac);
#endif
	retval = mwlExecuteCmd(sc, HostCmd_CMD_UPDATE_ENCRYPTION);
	return (retval);
}

/* ARGSUSED */
static struct ieee80211_node *
mwl_node_alloc(struct ieee80211com *ic)
{
	struct mwl_node *mn;

	mn = kmem_zalloc(sizeof (struct mwl_node), KM_SLEEP);
	if (mn == NULL) {
		/* XXX stat+msg */
		MWL_DBG(MWL_DBG_MSG, "mwl: mwl_node_alloc(): "
		    "alloc node failed\n");
		return (NULL);
	}
	return (&mn->mn_node);
}

static void
mwl_node_free(struct ieee80211_node *ni)
{
	struct ieee80211com *ic = ni->in_ic;
	struct mwl_node *mn = MWL_NODE(ni);

	if (mn->mn_staid != 0) {
		// mwl_hal_delstation(mn->mn_hvap, vap->iv_myaddr);
		// delstaid(sc, mn->mn_staid);
		mn->mn_staid = 0;
	}
	ic->ic_node_cleanup(ni);
	kmem_free(ni, sizeof (struct mwl_node));
}

/*
 * Allocate a key cache slot for a unicast key.  The
 * firmware handles key allocation and every station is
 * guaranteed key space so we are always successful.
 */
static int
mwl_key_alloc(struct ieee80211com *ic, const struct ieee80211_key *k,
	ieee80211_keyix *keyix, ieee80211_keyix *rxkeyix)
{
	if (k->wk_keyix != IEEE80211_KEYIX_NONE ||
	    (k->wk_flags & IEEE80211_KEY_GROUP)) {
		if (!(&ic->ic_nw_keys[0] <= k &&
		    k < &ic->ic_nw_keys[IEEE80211_WEP_NKID])) {
			/* should not happen */
			MWL_DBG(MWL_DBG_CRYPTO, "mwl: mwl_key_alloc(): "
			    "bogus group key\n");
			return (0);
		}
		/* give the caller what they requested */
		*keyix = *rxkeyix = k - ic->ic_nw_keys;
		MWL_DBG(MWL_DBG_CRYPTO, "mwl: mwl_key_alloc(): "
		    "alloc GROUP key keyix %x, rxkeyix %x\n",
		    *keyix, *rxkeyix);
	} else {
		/*
		 * Firmware handles key allocation.
		 */
		*keyix = *rxkeyix = 0;
		MWL_DBG(MWL_DBG_CRYPTO, "mwl: mwl_key_alloc(): "
		    "reset key index in key allocation\n");
	}

	return (1);
}

/*
 * Delete a key entry allocated by mwl_key_alloc.
 */
static int
mwl_key_delete(struct ieee80211com *ic, const struct ieee80211_key *k)
{
	struct mwl_softc *sc = (struct mwl_softc *)ic;
	MWL_HAL_KEYVAL hk;
	const uint8_t bcastaddr[IEEE80211_ADDR_LEN] =
	    { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	(void) memset(&hk, 0, sizeof (hk));
	hk.keyIndex = k->wk_keyix;
	switch (k->wk_cipher->ic_cipher) {
	case IEEE80211_CIPHER_WEP:
		hk.keyTypeId = KEY_TYPE_ID_WEP;
		break;
	case IEEE80211_CIPHER_TKIP:
		hk.keyTypeId = KEY_TYPE_ID_TKIP;
		break;
	case IEEE80211_CIPHER_AES_CCM:
		hk.keyTypeId = KEY_TYPE_ID_AES;
		break;
	default:
		/* XXX should not happen */
		MWL_DBG(MWL_DBG_CRYPTO, "mwl: mwl_key_delete(): "
		    "unknown cipher %d\n", k->wk_cipher->ic_cipher);
		return (0);
	}
	return (mwl_hal_keyreset(sc, &hk, bcastaddr) == 0);
}

/*
 * Set the key cache contents for the specified key.  Key cache
 * slot(s) must already have been allocated by mwl_key_alloc.
 */
/* ARGSUSED */
static int
mwl_key_set(struct ieee80211com *ic, const struct ieee80211_key *k,
	const uint8_t mac[IEEE80211_ADDR_LEN])
{
#define	GRPXMIT	(IEEE80211_KEY_XMIT | IEEE80211_KEY_GROUP)
/* NB: static wep keys are marked GROUP+tx/rx; GTK will be tx or rx */
#define	IEEE80211_IS_STATICKEY(k) \
	(((k)->wk_flags & (GRPXMIT|IEEE80211_KEY_RECV)) == \
	(GRPXMIT|IEEE80211_KEY_RECV))
	struct mwl_softc *sc = (struct mwl_softc *)ic;
	const struct ieee80211_cipher *cip = k->wk_cipher;
	const uint8_t *macaddr;
	MWL_HAL_KEYVAL hk;

	(void) memset(&hk, 0, sizeof (hk));
	hk.keyIndex = k->wk_keyix;
	switch (cip->ic_cipher) {
	case IEEE80211_CIPHER_WEP:
		hk.keyTypeId = KEY_TYPE_ID_WEP;
		hk.keyLen = k->wk_keylen;
		if (k->wk_keyix == ic->ic_def_txkey)
			hk.keyFlags = KEY_FLAG_WEP_TXKEY;
		if (!IEEE80211_IS_STATICKEY(k)) {
			/* NB: WEP is never used for the PTK */
			(void) addgroupflags(&hk, k);
		}
		break;
	case IEEE80211_CIPHER_TKIP:
		hk.keyTypeId = KEY_TYPE_ID_TKIP;
		hk.key.tkip.tsc.high = (uint32_t)(k->wk_keytsc >> 16);
		hk.key.tkip.tsc.low = (uint16_t)k->wk_keytsc;
		hk.keyFlags = KEY_FLAG_TSC_VALID | KEY_FLAG_MICKEY_VALID;
		hk.keyLen = k->wk_keylen + IEEE80211_MICBUF_SIZE;
		if (!addgroupflags(&hk, k))
			hk.keyFlags |= KEY_FLAG_PAIRWISE;
		break;
	case IEEE80211_CIPHER_AES_CCM:
		hk.keyTypeId = KEY_TYPE_ID_AES;
		hk.keyLen = k->wk_keylen;
		if (!addgroupflags(&hk, k))
			hk.keyFlags |= KEY_FLAG_PAIRWISE;
		break;
	default:
		/* XXX should not happen */
		MWL_DBG(MWL_DBG_CRYPTO, "mwl: mwl_key_set(): "
		    "unknown cipher %d\n",
		    k->wk_cipher->ic_cipher);
		return (0);
	}
	/*
	 * NB: tkip mic keys get copied here too; the layout
	 * just happens to match that in ieee80211_key.
	 */
	(void) memcpy(hk.key.aes, k->wk_key, hk.keyLen);

	/*
	 * Locate address of sta db entry for writing key;
	 * the convention unfortunately is somewhat different
	 * than how net80211, hostapd, and wpa_supplicant think.
	 */

	/*
	 * NB: keys plumbed before the sta reaches AUTH state
	 * will be discarded or written to the wrong sta db
	 * entry because iv_bss is meaningless.  This is ok
	 * (right now) because we handle deferred plumbing of
	 * WEP keys when the sta reaches AUTH state.
	 */
	macaddr = ic->ic_bss->in_bssid;
	if (k->wk_flags & IEEE80211_KEY_XMIT) {
		/* XXX plumb to local sta db too for static key wep */
		(void) mwl_hal_keyset(sc, &hk, ic->ic_macaddr);
	}
	return (mwl_hal_keyset(sc, &hk, macaddr) == 0);
#undef IEEE80211_IS_STATICKEY
#undef GRPXMIT
}

/*
 * Plumb any static WEP key for the station.  This is
 * necessary as we must propagate the key from the
 * global key table of the vap to each sta db entry.
 */
static void
mwl_setanywepkey(struct ieee80211com *ic, const uint8_t mac[IEEE80211_ADDR_LEN])
{
	if ((ic->ic_flags & (IEEE80211_F_PRIVACY|IEEE80211_F_WPA)) ==
	    IEEE80211_F_PRIVACY &&
	    ic->ic_def_txkey != IEEE80211_KEYIX_NONE &&
	    ic->ic_nw_keys[ic->ic_def_txkey].wk_keyix != IEEE80211_KEYIX_NONE)
		(void) mwl_key_set(ic, &ic->ic_nw_keys[ic->ic_def_txkey], mac);
}

static void
mwl_setglobalkeys(struct ieee80211com *ic)
{
	struct ieee80211_key *wk;

	wk = &ic->ic_nw_keys[0];
	for (; wk < &ic->ic_nw_keys[IEEE80211_WEP_NKID]; wk++)
		if (wk->wk_keyix != IEEE80211_KEYIX_NONE)
			(void) mwl_key_set(ic, wk, ic->ic_macaddr);
}

static int
addgroupflags(MWL_HAL_KEYVAL *hk, const struct ieee80211_key *k)
{
	if (k->wk_flags & IEEE80211_KEY_GROUP) {
		if (k->wk_flags & IEEE80211_KEY_XMIT)
			hk->keyFlags |= KEY_FLAG_TXGROUPKEY;
		if (k->wk_flags & IEEE80211_KEY_RECV)
			hk->keyFlags |= KEY_FLAG_RXGROUPKEY;
		return (1);
	} else
		return (0);
}

/*
 * Set/change channels.
 */
static int
mwl_chan_set(struct mwl_softc *sc, struct mwl_channel *chan)
{
	MWL_HAL_CHANNEL hchan;
	int maxtxpow;

	MWL_DBG(MWL_DBG_HW, "mwl: mwl_chan_set(): "
	    "chan %u MHz/flags 0x%x\n",
	    chan->ic_freq, chan->ic_flags);

	/*
	 * Convert to a HAL channel description with
	 * the flags constrained to reflect the current
	 * operating mode.
	 */
	mwl_mapchan(&hchan, chan);
	mwl_hal_intrset(sc, 0);		/* disable interrupts */

	(void) mwl_hal_setchannel(sc, &hchan);
	/*
	 * Tx power is cap'd by the regulatory setting and
	 * possibly a user-set limit.  We pass the min of
	 * these to the hal to apply them to the cal data
	 * for this channel.
	 * XXX min bound?
	 */
	maxtxpow = 2 * chan->ic_maxregpower;
	if (maxtxpow > 100)
		maxtxpow = 100;
	(void) mwl_hal_settxpower(sc, &hchan, maxtxpow / 2);
	/* NB: potentially change mcast/mgt rates */
	(void) mwl_setcurchanrates(sc);

	sc->sc_curchan = hchan;
	mwl_hal_intrset(sc, sc->sc_imask);

	return (0);
}

/*
 * Convert net80211 channel to a HAL channel.
 */
static void
mwl_mapchan(MWL_HAL_CHANNEL *hc, const struct mwl_channel *chan)
{
	hc->channel = chan->ic_ieee;

	*(uint32_t *)&hc->channelFlags = 0;
	if (((chan)->ic_flags & IEEE80211_CHAN_2GHZ) != 0)
		hc->channelFlags.FreqBand = MWL_FREQ_BAND_2DOT4GHZ;
	else if (((chan)->ic_flags & IEEE80211_CHAN_5GHZ) != 0)
		hc->channelFlags.FreqBand = MWL_FREQ_BAND_5GHZ;
	if (((chan)->ic_flags & IEEE80211_CHAN_HT40) != 0) {
		hc->channelFlags.ChnlWidth = MWL_CH_40_MHz_WIDTH;
		if (((chan)->ic_flags & IEEE80211_CHAN_HT40U) != 0)
			hc->channelFlags.ExtChnlOffset =
			    MWL_EXT_CH_ABOVE_CTRL_CH;
		else
			hc->channelFlags.ExtChnlOffset =
			    MWL_EXT_CH_BELOW_CTRL_CH;
	} else
		hc->channelFlags.ChnlWidth = MWL_CH_20_MHz_WIDTH;
	/* XXX 10MHz channels */
}

/*
 * Return the phy mode for with the specified channel.
 */
enum ieee80211_phymode
mwl_chan2mode(const struct mwl_channel *chan)
{

	if (IEEE80211_IS_CHAN_HTA(chan))
		return (IEEE80211_MODE_11NA);
	else if (IEEE80211_IS_CHAN_HTG(chan))
		return (IEEE80211_MODE_11NG);
	else if (IEEE80211_IS_CHAN_108G(chan))
		return (IEEE80211_MODE_TURBO_G);
	else if (IEEE80211_IS_CHAN_ST(chan))
		return (IEEE80211_MODE_STURBO_A);
	else if (IEEE80211_IS_CHAN_TURBO(chan))
		return (IEEE80211_MODE_TURBO_A);
	else if (IEEE80211_IS_CHAN_HALF(chan))
		return (IEEE80211_MODE_HALF);
	else if (IEEE80211_IS_CHAN_QUARTER(chan))
		return (IEEE80211_MODE_QUARTER);
	else if (IEEE80211_IS_CHAN_A(chan))
		return (IEEE80211_MODE_11A);
	else if (IEEE80211_IS_CHAN_ANYG(chan))
		return (IEEE80211_MODE_11G);
	else if (IEEE80211_IS_CHAN_B(chan))
		return (IEEE80211_MODE_11B);
	else if (IEEE80211_IS_CHAN_FHSS(chan))
		return (IEEE80211_MODE_FH);

	/* NB: should not get here */
	MWL_DBG(MWL_DBG_HW, "mwl: mwl_chan2mode(): "
	    "cannot map channel to mode; freq %u flags 0x%x\n",
	    chan->ic_freq, chan->ic_flags);
	return (IEEE80211_MODE_11B);
}

/* XXX inline or eliminate? */
const struct ieee80211_rateset *
mwl_get_suprates(struct ieee80211com *ic, const struct mwl_channel *c)
{
	/* XXX does this work for 11ng basic rates? */
	return (&ic->ic_sup_rates[mwl_chan2mode(c)]);
}

/*
 * Inform firmware of tx rate parameters.
 * Called after a channel change.
 */
static int
mwl_setcurchanrates(struct mwl_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	const struct ieee80211_rateset *rs;
	MWL_HAL_TXRATE rates;

	(void) memset(&rates, 0, sizeof (rates));
	rs = mwl_get_suprates(ic, sc->sc_cur_chan);
	/* rate used to send management frames */
	rates.MgtRate = rs->ir_rates[0] & IEEE80211_RATE_VAL;
	/* rate used to send multicast frames */
	rates.McastRate = rates.MgtRate;

	return (mwl_hal_settxrate_auto(sc, &rates));
}

static const struct mwl_hal_channel *
findhalchannel(const struct mwl_softc *sc, const MWL_HAL_CHANNEL *c)
{
	const struct mwl_hal_channel *hc;
	const MWL_HAL_CHANNELINFO *ci;
	int chan = c->channel, i;

	if (c->channelFlags.FreqBand == MWL_FREQ_BAND_2DOT4GHZ) {
		i = chan - 1;
		if (c->channelFlags.ChnlWidth == MWL_CH_40_MHz_WIDTH) {
			ci = &sc->sc_40M;
			if (c->channelFlags.ExtChnlOffset ==
			    MWL_EXT_CH_BELOW_CTRL_CH)
				i -= 4;
		} else
			ci = &sc->sc_20M;
		/* 2.4G channel table is directly indexed */
		hc = ((unsigned)i < ci->nchannels) ? &ci->channels[i] : NULL;
	} else if (c->channelFlags.FreqBand == MWL_FREQ_BAND_5GHZ) {
		if (c->channelFlags.ChnlWidth == MWL_CH_40_MHz_WIDTH) {
			ci = &sc->sc_40M_5G;
			if (c->channelFlags.ExtChnlOffset ==
			    MWL_EXT_CH_BELOW_CTRL_CH)
				chan -= 4;
		} else
			ci = &sc->sc_20M_5G;
		/* 5GHz channel table is sparse and must be searched */
		for (i = 0; i < ci->nchannels; i++)
			if (ci->channels[i].ieee == chan)
				break;
		hc = (i < ci->nchannels) ? &ci->channels[i] : NULL;
	} else
		hc = NULL;
	return (hc);
}

/*
 * Map SKU+country code to region code for radar bin'ing.
 */
static int
mwl_map2regioncode(const struct mwl_regdomain *rd)
{
	switch (rd->regdomain) {
	case SKU_FCC:
	case SKU_FCC3:
		return (DOMAIN_CODE_FCC);
	case SKU_CA:
		return (DOMAIN_CODE_IC);
	case SKU_ETSI:
	case SKU_ETSI2:
	case SKU_ETSI3:
		if (rd->country == CTRY_SPAIN)
			return (DOMAIN_CODE_SPAIN);
		if (rd->country == CTRY_FRANCE || rd->country == CTRY_FRANCE2)
			return (DOMAIN_CODE_FRANCE);
		/* XXX force 1.3.1 radar type */
		return (DOMAIN_CODE_ETSI_131);
	case SKU_JAPAN:
		return (DOMAIN_CODE_MKK);
	case SKU_ROW:
		return (DOMAIN_CODE_DGT);	/* Taiwan */
	case SKU_APAC:
	case SKU_APAC2:
	case SKU_APAC3:
		return (DOMAIN_CODE_AUS);	/* Australia */
	}
	/* XXX KOREA? */
	return (DOMAIN_CODE_FCC);			/* XXX? */
}

/*
 * Setup the rx data structures.  This should only be
 * done once or we may get out of sync with the firmware.
 */
static int
mwl_startrecv(struct mwl_softc *sc)
{
	struct mwl_rx_ring *ring;
	struct mwl_rxdesc *ds;
	struct mwl_rxbuf *bf, *prev;

	int i;

	ring = &sc->sc_rxring;
	bf = ring->buf;

	prev = NULL;
	for (i = 0; i < MWL_RX_RING_COUNT; i++, bf++) {
		ds = bf->bf_desc;
		/*
		 * NB: DMA buffer contents is known to be unmodified
		 * so there's no need to flush the data cache.
		 */

		/*
		 * Setup descriptor.
		 */
		ds->QosCtrl = 0;
		ds->RSSI = 0;
		ds->Status = EAGLE_RXD_STATUS_IDLE;
		ds->Channel = 0;
		ds->PktLen = LE_16(MWL_AGGR_SIZE);
		ds->SQ2 = 0;
		ds->pPhysBuffData = LE_32(bf->bf_baddr);
		/* NB: don't touch pPhysNext, set once */
		ds->RxControl = EAGLE_RXD_CTRL_DRIVER_OWN;

		(void) ddi_dma_sync(ring->rxdesc_dma.dma_hdl,
		    i * sizeof (struct mwl_rxdesc),
		    sizeof (struct mwl_rxdesc),
		    DDI_DMA_SYNC_FORDEV);

		if (prev != NULL) {
			ds = prev->bf_desc;
			ds->pPhysNext = LE_32(bf->bf_daddr);
		}
		prev = bf;
	}

	if (prev != NULL) {
		ds = prev->bf_desc;
		ds->pPhysNext = ring->physaddr;
	}

	/* set filters, etc. */
	(void) mwl_mode_init(sc);

	return (0);
}

static int
mwl_mode_init(struct mwl_softc *sc)
{
	/*
	 * NB: Ignore promisc in hostap mode; it's set by the
	 * bridge.  This is wrong but we have no way to
	 * identify internal requests (from the bridge)
	 * versus external requests such as for tcpdump.
	 */
	/* mwl_setmcastfilter - not support now */
	(void) mwl_hal_setpromisc(sc, 0);

	return (0);
}

/*
 * Kick the firmware to tell it there are new tx descriptors
 * for processing.  The driver says what h/w q has work in
 * case the f/w ever gets smarter.
 */
/* ARGSUSED */
static void
mwl_hal_txstart(struct mwl_softc *sc, int qnum)
{

	mwl_ctl_write4(sc, MACREG_REG_H2A_INTERRUPT_EVENTS,
	    MACREG_H2ARIC_BIT_PPA_READY);
	(void) mwl_ctl_read4(sc, MACREG_REG_INT_CODE);
}

static int
mwl_send(ieee80211com_t *ic, mblk_t *mp, uint8_t type)
{
	struct mwl_softc *sc = (struct mwl_softc *)ic;
	struct mwl_tx_ring *ring;
	struct mwl_txdesc *ds;
	struct mwl_txbuf *bf;
	struct ieee80211_frame *wh, *wh1;
	struct ieee80211_node *ni = NULL;

	int err, off;
	int mblen, pktlen, hdrlen;
	mblk_t *m, *m0;
	uint8_t *addr_4, *txbuf;
	uint16_t *pfwlen;

	MWL_TXLOCK(sc);

	err = DDI_SUCCESS;
	if (!MWL_IS_RUNNING(sc) || MWL_IS_SUSPEND(sc)) {
		err = ENXIO;
		goto fail1;
	}

	ring = &sc->sc_txring[1];
	if (ring->queued > 15) {
		MWL_DBG(MWL_DBG_TX, "mwl: mwl_send(): "
		    "no txbuf, %d\n", ring->queued);
		sc->sc_need_sched = 1;
		sc->sc_tx_nobuf++;
		err = ENOMEM;
		goto fail1;
	}

	m = allocb(msgdsize(mp) + 32, BPRI_MED);
	if (m == NULL) {
		MWL_DBG(MWL_DBG_TX, "mwl: mwl_send():"
		    "can't alloc mblk.\n");
		err = DDI_FAILURE;
		goto fail1;
	}

	for (off = 0, m0 = mp; m0 != NULL; m0 = m0->b_cont) {
		mblen = MBLKL(m0);
		(void) bcopy(m0->b_rptr, m->b_rptr + off, mblen);
		off += mblen;
	}
	m->b_wptr += off;

	wh = (struct ieee80211_frame *)m->b_rptr;
	ni = ieee80211_find_txnode(ic, wh->i_addr1);
	if (ni == NULL) {
		err = DDI_FAILURE;
		sc->sc_tx_err++;
		goto fail2;
	}

	hdrlen = sizeof (*wh);
	pktlen = msgdsize(m);

	(void) ieee80211_encap(ic, m, ni);

	if (wh->i_fc[1] & IEEE80211_FC1_WEP) {
		const struct ieee80211_cipher *cip;
		struct ieee80211_key *k;
		k = ieee80211_crypto_encap(ic, m);
		if (k == NULL) {
			sc->sc_tx_err++;
			err = DDI_FAILURE;
			goto fail3;
		}

		/*
		 * Adjust the packet length for the crypto additions
		 * done during encap and any other bits that the f/w
		 * will add later on.
		 */
		cip = k->wk_cipher;
		pktlen += cip->ic_header + cip->ic_miclen + cip->ic_trailer;
		/* packet header may have moved, reset our local pointer */
		wh = (struct ieee80211_frame *)m->b_rptr;
	}

	ds = &ring->desc[ring->cur];
	bf = &ring->buf[ring->cur];

	bf->bf_node = ieee80211_ref_node(ni);
	txbuf = (uint8_t *)bf->bf_mem;

	/*
	 * inject FW specific fields into the 802.11 frame
	 *
	 *  2   bytes FW len (inject)
	 *  24 bytes 802.11 frame header
	 *  6   bytes addr4 (inject)
	 *  n   bytes 802.11 frame body
	 */
	pfwlen = (uint16_t *)txbuf;
	*pfwlen = pktlen - hdrlen;
	wh1 = (struct ieee80211_frame *)(txbuf + 2);
	bcopy(wh, wh1, sizeof (struct ieee80211_frame));
	addr_4 = txbuf + (sizeof (struct ieee80211_frame) + sizeof (uint16_t));
	(void) memset(addr_4, 0, 6);
	bcopy(m->b_rptr + sizeof (struct ieee80211_frame), txbuf + 32, *pfwlen);
	pktlen += 8;

	(void) ddi_dma_sync(bf->txbuf_dma.dma_hdl,
	    0,
	    pktlen,
	    DDI_DMA_SYNC_FORDEV);

	ds->QosCtrl = 0;
	ds->PktLen = (uint16_t)pktlen;
	ds->PktPtr = bf->bf_baddr;
	ds->Status = LE_32(EAGLE_TXD_STATUS_FW_OWNED);
	ds->Format = 0;
	ds->pad = 0;
	ds->ack_wcb_addr = 0;
	ds->TxPriority = 1;

	MWL_DBG(MWL_DBG_TX, "mwl: mwl_send(): "
	    "tx desc Status %x, DataRate %x, TxPriority %x, QosCtrl %x, "
	    "PktLen %x, SapPktInfo %x, Format %x, Pad %x, ack_wcb_addr %x\n",
	    ds->Status, ds->DataRate, ds->TxPriority, ds->QosCtrl, ds->PktLen,
	    ds->SapPktInfo, ds->Format, ds->pad, ds->ack_wcb_addr);

	(void) ddi_dma_sync(ring->txdesc_dma.dma_hdl,
	    ring->cur * sizeof (struct mwl_txdesc),
	    sizeof (struct mwl_txdesc),
	    DDI_DMA_SYNC_FORDEV);

	MWL_DBG(MWL_DBG_TX, "mwl: mwl_send(): "
	    "pktlen = %u, slot = %u, queued = %x\n",
	    mblen, ring->cur, ring->queued);

	ring->queued++;
	ring->cur = (ring->cur + 1) % MWL_TX_RING_COUNT;

	/*
	 * NB: We don't need to lock against tx done because
	 * this just prods the firmware to check the transmit
	 * descriptors.  The firmware will also start fetching
	 * descriptors by itself if it notices new ones are
	 * present when it goes to deliver a tx done interrupt
	 * to the host. So if we race with tx done processing
	 * it's ok.  Delivering the kick here rather than in
	 * mwl_tx_start is an optimization to avoid poking the
	 * firmware for each packet.
	 *
	 * NB: the queue id isn't used so 0 is ok.
	 */
	mwl_hal_txstart(sc, 0);

	ic->ic_stats.is_tx_frags++;
	ic->ic_stats.is_tx_bytes += pktlen;

fail3:
	ieee80211_free_node(ni);
fail2:
	freemsg(m);
fail1:
	if ((type & IEEE80211_FC0_TYPE_MASK) != IEEE80211_FC0_TYPE_DATA ||
	    err == DDI_SUCCESS)
		freemsg(mp);
	MWL_TXUNLOCK(sc);
	return (err);
}

/*
 * This function is called periodically (every 200ms) during scanning to
 * switch from one channel to another.
 */
static void
mwl_next_scan(void *arg)
{
	struct mwl_softc *sc = (struct mwl_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;

	if (ic->ic_state == IEEE80211_S_SCAN)
		(void) ieee80211_next_scan(ic);

	sc->sc_scan_id = 0;
}

/*
 * Convert a legacy rate set to a firmware bitmask.
 */
static uint32_t
get_rate_bitmap(const struct ieee80211_rateset *rs)
{
	uint32_t rates;
	int i;

	rates = 0;
	for (i = 0; i < rs->ir_nrates; i++)
		switch (rs->ir_rates[i] & IEEE80211_RATE_VAL) {
		case 2:	  rates |= 0x001; break;
		case 4:	  rates |= 0x002; break;
		case 11:  rates |= 0x004; break;
		case 22:  rates |= 0x008; break;
		case 44:  rates |= 0x010; break;
		case 12:  rates |= 0x020; break;
		case 18:  rates |= 0x040; break;
		case 24:  rates |= 0x080; break;
		case 36:  rates |= 0x100; break;
		case 48:  rates |= 0x200; break;
		case 72:  rates |= 0x400; break;
		case 96:  rates |= 0x800; break;
		case 108: rates |= 0x1000; break;
		}
	return (rates);
}

/*
 * Craft station database entry for station.
 * NB: use host byte order here, the hal handles byte swapping.
 */
static MWL_HAL_PEERINFO *
mkpeerinfo(MWL_HAL_PEERINFO *pi, const struct ieee80211_node *ni)
{
	(void) memset(pi, 0, sizeof (*pi));
	pi->LegacyRateBitMap = get_rate_bitmap(&ni->in_rates);
	pi->CapInfo = ni->in_capinfo;
	return (pi);
}

static int
mwl_newstate(struct ieee80211com *ic, enum ieee80211_state nstate, int arg)
{
	struct mwl_softc *sc = (struct mwl_softc *)ic;
	enum ieee80211_state ostate;
	struct ieee80211_channel *ic_chan;
	struct ieee80211_node *ni = NULL;
	MWL_HAL_PEERINFO pi;
	uint32_t chan;

	if (sc->sc_scan_id != 0) {
		(void) untimeout(sc->sc_scan_id);
		sc->sc_scan_id = 0;
	}

	MWL_GLOCK(sc);

	ostate = ic->ic_state;
	MWL_DBG(MWL_DBG_MSG, "mwl: mwl_newstate(): "
	    "ostate %x -> nstate %x\n",
	    ostate, nstate);

	switch (nstate) {
	case IEEE80211_S_INIT:
		break;
	case IEEE80211_S_SCAN:
		if (ostate != IEEE80211_S_INIT) {
			ic_chan = ic->ic_curchan;
			chan = ieee80211_chan2ieee(ic, ic_chan);
			if (chan != 0 && chan != IEEE80211_CHAN_ANY) {
				sc->sc_cur_chan =
				    &sc->sc_channels[3 * chan - 2];
				MWL_DBG(MWL_DBG_MSG, "mwl: mwl_newstate(): "
				    "chan num is %u, sc chan is %u\n",
				    chan, sc->sc_cur_chan->ic_ieee);
				(void) mwl_chan_set(sc, sc->sc_cur_chan);
			}
		}
		sc->sc_scan_id = timeout(mwl_next_scan, (void *)sc,
		    drv_usectohz(250000));
		break;
	case IEEE80211_S_AUTH:
		ic_chan = ic->ic_curchan;
		chan = ieee80211_chan2ieee(ic, ic_chan);
		sc->sc_cur_chan = &sc->sc_channels[3 * chan - 2];
		MWL_DBG(MWL_DBG_MSG, "mwl: mwl_newstate(): "
		    "chan num is %u, sc chan is %u\n",
		    chan, sc->sc_cur_chan->ic_ieee);
		(void) mwl_chan_set(sc, sc->sc_cur_chan);
		ni = ic->ic_bss;
		(void) mwl_hal_newstation(sc, ic->ic_macaddr, 0, 0, NULL, 0, 0);
		mwl_setanywepkey(ic, ni->in_macaddr);
		break;
	case IEEE80211_S_ASSOC:
		break;
	case IEEE80211_S_RUN:
		ni = ic->ic_bss;
		(void) mwl_hal_newstation(sc,
		    ic->ic_macaddr, 0, 0, mkpeerinfo(&pi, ni), 0, 0);
		mwl_setglobalkeys(ic);
		(void) mwl_hal_setassocid(sc,
		    ic->ic_bss->in_bssid, ic->ic_bss->in_associd);
		(void) mwl_setrates(ic);
		(void) mwl_hal_setrtsthreshold(sc, ic->ic_rtsthreshold);
		(void) mwl_hal_setcsmode(sc, CSMODE_AUTO_ENA);
		break;
	default:
		break;
	}

	MWL_GUNLOCK(sc);

	return (sc->sc_newstate(ic, nstate, arg));
}

/*
 * Set the interrupt mask.
 */
static void
mwl_hal_intrset(struct mwl_softc *sc, uint32_t mask)
{
	mwl_ctl_write4(sc, MACREG_REG_A2H_INTERRUPT_MASK, 0);
	(void) mwl_ctl_read4(sc, MACREG_REG_INT_CODE);

	sc->sc_hal_imask = mask;
	mwl_ctl_write4(sc, MACREG_REG_A2H_INTERRUPT_MASK, mask);
	(void) mwl_ctl_read4(sc, MACREG_REG_INT_CODE);
}

/*
 * Return the current ISR setting and clear the cause.
 */
static void
mwl_hal_getisr(struct mwl_softc *sc, uint32_t *status)
{
	uint32_t cause;

	cause = mwl_ctl_read4(sc, MACREG_REG_A2H_INTERRUPT_CAUSE);
	if (cause == 0xffffffff) {	/* card removed */
		cause = 0;
	} else if (cause != 0) {
		/* clear cause bits */
		mwl_ctl_write4(sc, MACREG_REG_A2H_INTERRUPT_CAUSE,
		    cause & ~sc->sc_hal_imask);
		(void) mwl_ctl_read4(sc, MACREG_REG_INT_CODE);
		cause &= sc->sc_hal_imask;
	}
	*status = cause;
}

static void
mwl_tx_intr(struct mwl_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct mwl_tx_ring *ring;
	struct mwl_txdesc *ds;

	uint32_t status;

	MWL_TXLOCK(sc);

	ring = &sc->sc_txring[1];

	if (!(ring->queued)) {
		MWL_TXUNLOCK(sc);
		return;
	}

	(void) ddi_dma_sync(ring->txdesc_dma.dma_hdl,
	    0,
	    ring->txdesc_dma.alength,
	    DDI_DMA_SYNC_FORCPU);

	for (;;) {
		ds = &ring->desc[ring->next];

		status = LE_32(ds->Status);

		if (status & LE_32(EAGLE_TXD_STATUS_FW_OWNED)) {
			break;
		}

		if (status == LE_32(EAGLE_TXD_STATUS_IDLE)) {
			break;
		}

		MWL_DBG(MWL_DBG_TX, "mwl: mwl_tx_intr(): "
		    "recv tx desc status %x, datarate %x, txpriority %x, "
		    "QosCtrl %x, pktLen %x, SapPktInfo %x, Format %x, "
		    "pad %x, ack_wcb_addr %x\n",
		    ds->Status, ds->DataRate, ds->TxPriority,
		    ds->QosCtrl, ds->PktLen, ds->SapPktInfo,
		    ds->Format, ds->pad, ds->ack_wcb_addr);

		/* descriptor is no longer valid */
		ds->Status = LE_32(EAGLE_TXD_STATUS_IDLE);

		(void) ddi_dma_sync(ring->txdesc_dma.dma_hdl,
		    ring->next * sizeof (struct mwl_txdesc),
		    sizeof (struct mwl_txdesc),
		    DDI_DMA_SYNC_FORDEV);

		ring->queued--;
		ring->next = (ring->next + 1) % MWL_TX_RING_COUNT;
		MWL_DBG(MWL_DBG_TX, "mwl: mwl_tx_intr(): "
		    " tx done idx=%u, queued= %d\n",
		    ring->next, ring->queued);

		if (sc->sc_need_sched &&
		    (ring->queued < MWL_TX_RING_COUNT)) {
			sc->sc_need_sched = 0;
			mac_tx_update(ic->ic_mach);
		}

	}

	MWL_TXUNLOCK(sc);
}

/*
 * Convert hardware signal strength to rssi.  The value
 * provided by the device has the noise floor added in;
 * we need to compensate for this but we don't have that
 * so we use a fixed value.
 *
 * The offset of 8 is good for both 2.4 and 5GHz.  The LNA
 * offset is already set as part of the initial gain.  This
 * will give at least +/- 3dB for 2.4GHz and +/- 5dB for 5GHz.
 */
static int
cvtrssi(uint8_t ssi)
{
	int rssi = (int)ssi + 8;
	/* XXX hack guess until we have a real noise floor */
	rssi = 2 * (87 - rssi);	/* NB: .5 dBm units */
	return (rssi < 0 ? 0 : rssi > 127 ? 127 : rssi);
}

static void
mwl_rx_intr(struct mwl_softc *sc)
{
	struct ieee80211com	*ic = &sc->sc_ic;
	struct mwl_rx_ring *ring;
	struct ieee80211_node	*ni;
	struct ieee80211_frame *wh;

	struct mwl_rxbuf *bf;
	struct mwl_rxdesc *ds;
	mblk_t	*mp0;

	int ntodo, len, rssi;
	uint8_t *data, status;

	MWL_RXLOCK(sc);

	ring = &sc->sc_rxring;
	for (ntodo = MWL_RX_RING_COUNT; ntodo > 0; ntodo--) {
		bf = &ring->buf[ring->cur];
		ds = bf->bf_desc;
		data = bf->bf_mem;

		(void) ddi_dma_sync(ring->rxdesc_dma.dma_hdl,
		    ring->cur * sizeof (struct mwl_rxdesc),
		    sizeof (struct mwl_rxdesc),
		    DDI_DMA_SYNC_FORCPU);

		if (ds->RxControl != EAGLE_RXD_CTRL_DMA_OWN)
			break;

		status = ds->Status;
		if (status & EAGLE_RXD_STATUS_DECRYPT_ERR_MASK) {
			MWL_DBG(MWL_DBG_CRYPTO, "mwl: mwl_rx_intr(): "
			    "rx decrypt error\n");
			sc->sc_rx_err++;
		}

		/*
		 * Sync the data buffer.
		 */
		len = LE_16(ds->PktLen);

		(void) ddi_dma_sync(bf->rxbuf_dma.dma_hdl,
		    0,
		    bf->rxbuf_dma.alength,
		    DDI_DMA_SYNC_FORCPU);

		if (len < 32 || len > sc->sc_dmabuf_size) {
			MWL_DBG(MWL_DBG_RX, "mwl: mwl_rx_intr(): "
			    "packet len error %d\n", len);
			sc->sc_rx_err++;
			goto rxnext;
		}

		mp0 = allocb(sc->sc_dmabuf_size, BPRI_MED);
		if (mp0 == NULL) {
			MWL_DBG(MWL_DBG_RX, "mwl: mwl_rx_intr(): "
			    "alloc mblk error\n");
			sc->sc_rx_nobuf++;
			goto rxnext;
		}
		bcopy(data+ 2, mp0->b_wptr, 24);
		mp0->b_wptr += 24;
		bcopy(data + 32, mp0->b_wptr, len - 32);
		mp0->b_wptr += (len - 32);

		wh = (struct ieee80211_frame *)mp0->b_rptr;
		if ((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) ==
		    IEEE80211_FC0_TYPE_CTL) {
			freemsg(mp0);
			goto rxnext;
		}

		/*
		 * The f/w strips WEP header but doesn't clear
		 * the WEP bit; mark the packet with M_WEP so
		 * net80211 will treat the data as decrypted.
		 * While here also clear the PWR_MGT bit since
		 * power save is handled by the firmware and
		 * passing this up will potentially cause the
		 * upper layer to put a station in power save
		 * (except when configured with MWL_HOST_PS_SUPPORT).
		 */
#ifdef MWL_HOST_PS_SUPPORT
		wh->i_fc[1] &= ~IEEE80211_FC1_WEP;
#else
		wh->i_fc[1] &= ~(IEEE80211_FC1_WEP | IEEE80211_FC1_PWR_MGT);
#endif

		/* calculate rssi early so we can re-use for each aggregate */
		rssi = cvtrssi(ds->RSSI);

		ni = ieee80211_find_rxnode(ic, wh);

		/* send the frame to the 802.11 layer */
		(void) ieee80211_input(ic, mp0, ni, rssi, 0);
		ieee80211_free_node(ni);
rxnext:
		/*
		 * Setup descriptor.
		 */
		ds->QosCtrl = 0;
		ds->RSSI = 0;
		ds->Status = EAGLE_RXD_STATUS_IDLE;
		ds->Channel = 0;
		ds->PktLen = LE_16(MWL_AGGR_SIZE);
		ds->SQ2 = 0;
		ds->pPhysBuffData = bf->bf_baddr;
		/* NB: don't touch pPhysNext, set once */
		ds->RxControl = EAGLE_RXD_CTRL_DRIVER_OWN;

		(void) ddi_dma_sync(ring->rxdesc_dma.dma_hdl,
		    ring->cur * sizeof (struct mwl_rxdesc),
		    sizeof (struct mwl_rxdesc),
		    DDI_DMA_SYNC_FORDEV);

		/* NB: ignore ENOMEM so we process more descriptors */
		ring->cur = (ring->cur + 1) % MWL_RX_RING_COUNT;
	}

	MWL_RXUNLOCK(sc);
}

/*ARGSUSED*/
static uint_t
mwl_softintr(caddr_t data, caddr_t unused)
{
	struct mwl_softc *sc = (struct mwl_softc *)data;

	/*
	 * Check if the soft interrupt is triggered by another
	 * driver at the same level.
	 */
	MWL_GLOCK(sc);
	if (sc->sc_rx_pend) {
		sc->sc_rx_pend = 0;
		MWL_GUNLOCK(sc);
		mwl_rx_intr(sc);
		return (DDI_INTR_CLAIMED);
	}
	MWL_GUNLOCK(sc);

	return (DDI_INTR_UNCLAIMED);
}

/*ARGSUSED*/
static uint_t
mwl_intr(caddr_t arg, caddr_t unused)
{
	struct mwl_softc *sc = (struct mwl_softc *)arg;
	uint32_t status;

	MWL_GLOCK(sc);

	if (!MWL_IS_RUNNING(sc) || MWL_IS_SUSPEND(sc)) {
		MWL_GUNLOCK(sc);
		return (DDI_INTR_UNCLAIMED);
	}

	/*
	 * Figure out the reason(s) for the interrupt.
	 */
	mwl_hal_getisr(sc, &status);		/* NB: clears ISR too */
	if (status == 0) {
		MWL_GUNLOCK(sc);
		return (DDI_INTR_UNCLAIMED);
	}

	if (status & MACREG_A2HRIC_BIT_RX_RDY) {
		sc->sc_rx_pend = 1;
		(void) ddi_intr_trigger_softint(sc->sc_softintr_hdl, NULL);
	}
	if (status & MACREG_A2HRIC_BIT_TX_DONE) {
		mwl_tx_intr(sc);
	}
	if (status & MACREG_A2HRIC_BIT_BA_WATCHDOG) {
		MWL_DBG(MWL_DBG_INTR, "mwl: mwl_intr(): "
		    "ba watchdog\n");
	}
	if (status & MACREG_A2HRIC_BIT_OPC_DONE) {
		MWL_DBG(MWL_DBG_INTR, "mwl: mwl_intr(): "
		    "opc done\n");
	}
	if (status & MACREG_A2HRIC_BIT_MAC_EVENT) {
		MWL_DBG(MWL_DBG_INTR, "mwl: mwl_intr(): "
		    "mac event\n");
	}
	if (status & MACREG_A2HRIC_BIT_ICV_ERROR) {
		MWL_DBG(MWL_DBG_INTR, "mwl: mwl_intr(): "
		    "ICV error\n");
	}
	if (status & MACREG_A2HRIC_BIT_QUEUE_EMPTY) {
		MWL_DBG(MWL_DBG_INTR, "mwl: mwl_intr(): "
		    "queue empty\n");
	}
	if (status & MACREG_A2HRIC_BIT_QUEUE_FULL) {
		MWL_DBG(MWL_DBG_INTR, "mwl: mwl_intr(): "
		    "queue full\n");
	}
	if (status & MACREG_A2HRIC_BIT_RADAR_DETECT) {
		MWL_DBG(MWL_DBG_INTR, "mwl: mwl_intr(): "
		    "radar detect\n");
	}
	if (status & MACREG_A2HRIC_BIT_CHAN_SWITCH) {
		MWL_DBG(MWL_DBG_INTR, "mwl: mwl_intr(): "
		    "chan switch\n");
	}

	MWL_GUNLOCK(sc);

	return (DDI_INTR_CLAIMED);
}

static int
mwl_init(struct mwl_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	int err = 0;

	mwl_hal_intrset(sc, 0);

	sc->sc_txantenna = 0;		/* h/w default */
	sc->sc_rxantenna = 0;		/* h/w default */

	err = mwl_hal_setantenna(sc, WL_ANTENNATYPE_RX, sc->sc_rxantenna);
	if (err != 0) {
		MWL_DBG(MWL_DBG_HW, "mwl: mwl_init(): "
		    "could not set rx antenna\n");
		goto fail;
	}

	err = mwl_hal_setantenna(sc, WL_ANTENNATYPE_TX, sc->sc_txantenna);
	if (err != 0) {
		MWL_DBG(MWL_DBG_HW, "mwl: init(): "
		    "could not set tx antenna\n");
		goto fail;
	}

	err = mwl_hal_setradio(sc, 1, WL_AUTO_PREAMBLE);
	if (err != 0) {
		MWL_DBG(MWL_DBG_HW, "mwl: init(): "
		    "could not set radio\n");
		goto fail;
	}

	err = mwl_hal_setwmm(sc, (ic->ic_flags & IEEE80211_F_WME) != 0);
	if (err != 0) {
		MWL_DBG(MWL_DBG_HW, "mwl: init(): "
		    "could not set wme\n");
		goto fail;
	}

	/* select default channel */
	ic->ic_ibss_chan = &ic->ic_sup_channels[0];
	ic->ic_curchan = ic->ic_ibss_chan;
	sc->sc_cur_chan = &sc->sc_channels[1];

	err = mwl_chan_set(sc, sc->sc_cur_chan);
	if (err != 0) {
		MWL_DBG(MWL_DBG_HW, "mwl: init(): "
		    "could not set wme\n");
		goto fail;
	}

	err = mwl_hal_setrateadaptmode(sc, 0);
	if (err != 0) {
		MWL_DBG(MWL_DBG_HW, "mwl: init(): "
		    "could not set rate adapt mode\n");
		goto fail;
	}

	err = mwl_hal_setoptimizationlevel(sc,
	    (ic->ic_flags & IEEE80211_F_BURST) != 0);
	if (err != 0) {
		MWL_DBG(MWL_DBG_HW, "mwl: init(): "
		    "could not set optimization level\n");
		goto fail;
	}

	err = mwl_hal_setregioncode(sc, mwl_map2regioncode(&sc->sc_regdomain));
	if (err != 0) {
		MWL_DBG(MWL_DBG_HW, "mwl: init(): "
		    "could not set regioncode\n");
		goto fail;
	}

	err = mwl_startrecv(sc);
	if (err != 0) {
		MWL_DBG(MWL_DBG_HW, "mwl: init(): "
		    "could not set start recv logic\n");
		goto fail;
	}

	/*
	 * Enable interrupts.
	 */
	sc->sc_imask = MACREG_A2HRIC_BIT_RX_RDY
	    | MACREG_A2HRIC_BIT_TX_DONE
	    | MACREG_A2HRIC_BIT_OPC_DONE
	    | MACREG_A2HRIC_BIT_ICV_ERROR
	    | MACREG_A2HRIC_BIT_RADAR_DETECT
	    | MACREG_A2HRIC_BIT_CHAN_SWITCH
	    | MACREG_A2HRIC_BIT_BA_WATCHDOG
	    | MACREQ_A2HRIC_BIT_TX_ACK;

	mwl_hal_intrset(sc, sc->sc_imask);

	err = mwl_hal_start(sc);
	if (err != 0) {
		MWL_DBG(MWL_DBG_HW, "mwl: init(): "
		    "could not get hal start\n");
		goto fail;
	}

	err = mwl_hal_setinframode(sc);
	if (err != 0) {
		MWL_DBG(MWL_DBG_HW, "mwl: init(): "
		    "could not set infra mode\n");
		goto fail;
	}

fail:
	return (err);
}

static int
mwl_resume(struct mwl_softc *sc)
{
	int qid, err = 0;

	err = mwl_fwload(sc, NULL);
	if (err != 0) {
		MWL_DBG(MWL_DBG_SR, "mwl: mwl_resume(): "
		    "failed to load fw\n");
		goto fail;
	}

	err = mwl_gethwspecs(sc);
	if (err != 0) {
		MWL_DBG(MWL_DBG_SR, "mwl: mwl_resume(): "
		    "failed to get hw spec\n");
		goto fail;
	}

	err = mwl_alloc_rx_ring(sc, MWL_RX_RING_COUNT);
	if (err != 0) {
		MWL_DBG(MWL_DBG_SR, "mwl: mwl_resume(): "
		    "could not alloc cmd dma buffer\n");
		goto fail;
	}

	for (qid = 0; qid < MWL_NUM_TX_QUEUES; qid++) {
		err = mwl_alloc_tx_ring(sc,
		    &sc->sc_txring[qid], MWL_TX_RING_COUNT);
		if (err != 0) {
			MWL_DBG(MWL_DBG_SR, "mwl: mwl_resume(): "
			    "could not alloc tx ring %d\n", qid);
			goto fail;
		}
	}

	err = mwl_setupdma(sc);
	if (err != 0) {
		MWL_DBG(MWL_DBG_SR, "mwl: mwl_resume(): "
		    "could not setup dma\n");
		goto fail;
	}

	err = mwl_setup_txq(sc);
	if (err != 0) {
		MWL_DBG(MWL_DBG_SR, "mwl: mwl_resume(): "
		    "could not setup txq\n");
		goto fail;
	}

fail:
	return (err);
}

static void
mwl_stop(struct mwl_softc *sc)
{
	int err;

	/* by pass if it's quiesced */
	if (!MWL_IS_QUIESCE(sc))
		MWL_GLOCK(sc);

	err = mwl_hal_stop(sc);
	if (err != 0) {
		MWL_DBG(MWL_DBG_HW, "mwl: mwl_stop(): "
		    "could not stop hw\n");
	}

	/* by pass if it's quiesced */
	if (!MWL_IS_QUIESCE(sc))
		MWL_GUNLOCK(sc);
}

static int
mwl_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	struct mwl_softc *sc  = (struct mwl_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;
	struct ieee80211_node *ni = NULL;
	struct ieee80211_rateset *rs = NULL;

	MWL_GLOCK(sc);
	switch (stat) {
	case MAC_STAT_IFSPEED:
		ni = ic->ic_bss;
		rs = &ni->in_rates;
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
		MWL_GUNLOCK(sc);
		return (ieee80211_stat(ic, stat, val));
	default:
		MWL_GUNLOCK(sc);
		return (ENOTSUP);
	}

	MWL_GUNLOCK(sc);
	return (0);
}

static int
mwl_m_start(void *arg)
{
	struct mwl_softc *sc = (struct mwl_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;
	int err;

	err = mwl_init(sc);
	if (err != DDI_SUCCESS) {
		MWL_DBG(MWL_DBG_HW, "mwl: mwl_m_start():"
		    "Hardware initialization failed\n");
		goto fail1;
	}

	ieee80211_new_state(ic, IEEE80211_S_INIT, -1);

	MWL_GLOCK(sc);
	sc->sc_flags |= MWL_F_RUNNING;
	MWL_GUNLOCK(sc);

	return (0);
fail1:
	mwl_stop(sc);
	return (err);
}

static void
mwl_m_stop(void *arg)
{
	struct mwl_softc *sc = (struct mwl_softc *)arg;

	mwl_stop(sc);

	ieee80211_new_state(&sc->sc_ic, IEEE80211_S_INIT, -1);

	MWL_GLOCK(sc);
	sc->sc_flags &= ~MWL_F_RUNNING;
	MWL_GUNLOCK(sc);
}

/*ARGSUSED*/
static int
mwl_m_promisc(void *arg, boolean_t on)
{
	struct mwl_softc *sc = (struct mwl_softc *)arg;
	int err;

	err = mwl_hal_setpromisc(sc, on);

	return (err);
}

/*ARGSUSED*/
static int
mwl_m_multicst(void *arg, boolean_t add, const uint8_t *mca)
{
	return (ENOTSUP);
}

/*ARGSUSED*/
static int
mwl_m_unicst(void *arg, const uint8_t *macaddr)
{
	return (ENOTSUP);
}

static mblk_t *
mwl_m_tx(void *arg, mblk_t *mp)
{
	struct mwl_softc *sc = (struct mwl_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;
	mblk_t *next;

	if (MWL_IS_SUSPEND(sc)) {
		freemsgchain(mp);
		return (NULL);
	}

	/*
	 * No data frames go out unless we're associated; this
	 * should not happen as the 802.11 layer does not enable
	 * the xmit queue until we enter the RUN state.
	 */
	if (ic->ic_state != IEEE80211_S_RUN) {
		MWL_DBG(MWL_DBG_TX, "mwl: mwl_m_tx(): "
		    "discard, state %u\n", ic->ic_state);
		freemsgchain(mp);
		return (NULL);
	}

	while (mp != NULL) {
		next = mp->b_next;
		mp->b_next = NULL;
		if (mwl_send(ic, mp, IEEE80211_FC0_TYPE_DATA) !=
		    DDI_SUCCESS) {
			mp->b_next = next;
			break;
		}
		mp = next;
	}
	return (mp);
}

static void
mwl_m_ioctl(void* arg, queue_t *wq, mblk_t *mp)
{
	struct mwl_softc *sc = (struct mwl_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;
	int err;

	err = ieee80211_ioctl(ic, wq, mp);
	if (err == ENETRESET) {
		if (ic->ic_des_esslen) {
			if (MWL_IS_RUNNING(sc)) {
				(void) mwl_init(sc);
				(void) ieee80211_new_state(ic,
				    IEEE80211_S_SCAN, -1);
			}
		}
	}
}

/*
 * Call back function for get/set proporty
 */
static int
mwl_m_getprop(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    uint_t wldp_length, void *wldp_buf)
{
	struct mwl_softc *sc = (struct mwl_softc *)arg;
	int err = 0;

	err = ieee80211_getprop(&sc->sc_ic, pr_name, wldp_pr_num,
	    wldp_length, wldp_buf);

	return (err);
}

static void
mwl_m_propinfo(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    mac_prop_info_handle_t prh)
{
	struct mwl_softc *sc = (struct mwl_softc *)arg;

	ieee80211_propinfo(&sc->sc_ic, pr_name, wldp_pr_num, prh);
}

static int
mwl_m_setprop(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    uint_t wldp_length, const void *wldp_buf)
{
	struct mwl_softc *sc = (struct mwl_softc *)arg;
	ieee80211com_t *ic = &sc->sc_ic;
	int err;

	err = ieee80211_setprop(ic, pr_name, wldp_pr_num, wldp_length,
	    wldp_buf);
	if (err == ENETRESET) {
		if (ic->ic_des_esslen) {
			if (MWL_IS_RUNNING(sc)) {
				(void) mwl_init(sc);
				(void) ieee80211_new_state(ic,
				    IEEE80211_S_SCAN, -1);
			}
		}
		err = 0;
	}
	return (err);
}

static int
mwl_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	struct mwl_softc *sc;
	struct ieee80211com *ic;
	int i, err, qid, instance;
	int intr_type, intr_count, intr_actual;
	char strbuf[32];
	uint8_t csz;
	uint16_t vendor_id, device_id, command;

	wifi_data_t wd = { 0 };
	mac_register_t *macp;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		sc = ddi_get_soft_state(mwl_soft_state_p,
		    ddi_get_instance(devinfo));
		ASSERT(sc != NULL);
		MWL_GLOCK(sc);
		sc->sc_flags &= ~MWL_F_SUSPEND;
		MWL_GUNLOCK(sc);
		if (mwl_resume(sc) != 0) {
			MWL_DBG(MWL_DBG_SR, "mwl: mwl_attach(): "
			    "failed to resume\n");
			return (DDI_FAILURE);
		}
		if (MWL_IS_RUNNING(sc)) {
			(void) mwl_init(sc);
			ieee80211_new_state(&sc->sc_ic, IEEE80211_S_INIT, -1);
		}
		MWL_DBG(MWL_DBG_SR, "mwl: mwl_attach(): "
		    "resume now\n");
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(devinfo);
	if (ddi_soft_state_zalloc(mwl_soft_state_p,
	    ddi_get_instance(devinfo)) != DDI_SUCCESS) {
		MWL_DBG(MWL_DBG_ATTACH, "mwl: mwl_attach(): "
		    "Unable to alloc soft state\n");
		return (DDI_FAILURE);
	}

	sc = ddi_get_soft_state(mwl_soft_state_p, ddi_get_instance(devinfo));
	ic = &sc->sc_ic;
	sc->sc_dev = devinfo;

	/* PCI configuration space */
	err = ddi_regs_map_setup(devinfo, 0, (caddr_t *)&sc->sc_cfg_base, 0, 0,
	    &mwl_reg_accattr, &sc->sc_cfg_handle);
	if (err != DDI_SUCCESS) {
		MWL_DBG(MWL_DBG_ATTACH, "mwl: mwl_attach(): "
		    "ddi_regs_map_setup() failed");
		goto attach_fail0;
	}
	csz = ddi_get8(sc->sc_cfg_handle,
	    (uint8_t *)(sc->sc_cfg_base + PCI_CONF_CACHE_LINESZ));
	if (!csz)
		csz = 16;
	sc->sc_cachelsz = csz << 2;
	sc->sc_dmabuf_size = roundup(IEEE80211_MAX_LEN, sc->sc_cachelsz);
	vendor_id = ddi_get16(sc->sc_cfg_handle,
	    (uint16_t *)(sc->sc_cfg_base + PCI_CONF_VENID));
	device_id = ddi_get16(sc->sc_cfg_handle,
	    (uint16_t *)(sc->sc_cfg_base + PCI_CONF_DEVID));
	MWL_DBG(MWL_DBG_ATTACH, "mwl: mwl_attach(): "
	    "vendor 0x%x, device id 0x%x, cache size %d\n",
	    vendor_id, device_id, csz);

	/*
	 * Enable response to memory space accesses,
	 * and enabe bus master.
	 */
	command = PCI_COMM_MAE | PCI_COMM_ME;
	ddi_put16(sc->sc_cfg_handle,
	    (uint16_t *)((uintptr_t)(sc->sc_cfg_base) + PCI_CONF_COMM),
	    command);
	ddi_put8(sc->sc_cfg_handle,
	    (uint8_t *)(sc->sc_cfg_base + PCI_CONF_LATENCY_TIMER), 0xa8);
	ddi_put8(sc->sc_cfg_handle,
	    (uint8_t *)(sc->sc_cfg_base + PCI_CONF_ILINE), 0x10);

	/* BAR0 */
	err = ddi_regs_map_setup(devinfo, 1,
	    &sc->sc_mem_base, 0, 0, &mwl_reg_accattr, &sc->sc_mem_handle);
	if (err != DDI_SUCCESS) {
		MWL_DBG(MWL_DBG_ATTACH, "mwl: mwl_attach(): "
		    "i/o space failed");
		goto attach_fail1;
	}

	/* BAR1 */
	err = ddi_regs_map_setup(devinfo, 2,
	    &sc->sc_io_base, 0, 0, &mwl_reg_accattr, &sc->sc_io_handle);
	if (err != DDI_SUCCESS) {
		MWL_DBG(MWL_DBG_ATTACH, "mwl: mwl_attach(): "
		    "memory space failed");
		goto attach_fail2;
	}

	MWL_DBG(MWL_DBG_ATTACH, "mwl: mwl_attach(): "
	    "PCI configuration is done successfully\n");

	/*
	 * Alloc cmd DMA buffer for firmware download
	 */
	err = mwl_alloc_cmdbuf(sc);
	if (err != 0) {
		MWL_DBG(MWL_DBG_ATTACH, "mwl: mwl_attach(): "
		    "could not alloc cmd dma buffer\n");
		goto attach_fail3;
	}

	sc->sc_imask = 0;
	sc->sc_hw_flags = 0;
	sc->sc_flags = 0;

	/*
	 * Some cards have SDRAM.  When loading firmware we need
	 * to reset the SDRAM controller prior to doing this.
	 * When the SDRAMSIZE is non-zero we do that work in
	 * mwl_hal_fwload.
	 */
	switch (device_id) {
	case 0x2a02:		/* CB82 */
	case 0x2a03:		/* CB85 */
	case 0x2a08:		/* MC85_B1 */
	case 0x2a0b:		/* CB85AP */
	case 0x2a24:
		sc->sc_SDRAMSIZE_Addr = 0x40fe70b7;	/* 8M SDRAM */
		break;
	case 0x2a04:		/* MC85 */
		sc->sc_SDRAMSIZE_Addr = 0x40fc70b7;	/* 16M SDRAM */
		break;
	default:
		break;
	}

	err = mwl_fwload(sc, NULL);
	if (err != 0) {
		MWL_DBG(MWL_DBG_ATTACH, "mwl: mwl_attach(): "
		    "firmware download failed\n");
		goto attach_fail4;
	}

	MWL_DBG(MWL_DBG_ATTACH, "mwl: mwl_attach(): "
	    "firmware download successfully\n");

	err = mwl_gethwspecs(sc);
	if (err != 0) {
		MWL_DBG(MWL_DBG_ATTACH, "mwl: mwl_attach(): "
		    "failed to get hw spec\n");
		goto attach_fail4;
	}

	err = mwl_getchannels(sc);
	if (err != 0) {
		MWL_DBG(MWL_DBG_ATTACH, "mwl: mwl_attach(): "
		    "failed to get channels\n");
		goto attach_fail4;
	}

	/*
	 * Alloc rx DMA buffer
	 */
	err = mwl_alloc_rx_ring(sc, MWL_RX_RING_COUNT);
	if (err != 0) {
		MWL_DBG(MWL_DBG_ATTACH, "mwl: mwl_attach(): "
		    "could not alloc cmd dma buffer\n");
		goto attach_fail5;
	}

	/*
	 * Alloc rx DMA buffer
	 */
	for (qid = 0; qid < MWL_NUM_TX_QUEUES; qid++) {
		err = mwl_alloc_tx_ring(sc,
		    &sc->sc_txring[qid], MWL_TX_RING_COUNT);
		if (err != 0) {
			MWL_DBG(MWL_DBG_ATTACH, "mwl: mwl_attach(): "
			    "could not alloc tx ring %d\n", qid);
			goto attach_fail6;
		}
	}

	err = mwl_setupdma(sc);
	if (err != 0) {
		MWL_DBG(MWL_DBG_ATTACH, "mwl: mwl_attach(): "
		    "could not setup dma\n");
		goto attach_fail6;
	}

	err = mwl_setup_txq(sc);
	if (err != 0) {
		MWL_DBG(MWL_DBG_ATTACH, "mwl: mwl_attach(): "
		    "could not setup txq\n");
		goto attach_fail6;
	}

	IEEE80211_ADDR_COPY(ic->ic_macaddr, sc->sc_hwspecs.macAddr);
	MWL_DBG(MWL_DBG_ATTACH, "mwl: mwl_attach(): "
	    "mwl MAC:%2x:%2x:%2x:%2x:%2x:%2x\n",
	    ic->ic_macaddr[0],
	    ic->ic_macaddr[1],
	    ic->ic_macaddr[2],
	    ic->ic_macaddr[3],
	    ic->ic_macaddr[4],
	    ic->ic_macaddr[5]);

	err = mwl_hal_setmac_locked(sc, ic->ic_macaddr);
	if (err != 0) {			/* NB: mwl_setupdma prints msg */
		MWL_DBG(MWL_DBG_ATTACH, "mwl: attach(): "
		    "could not set mac\n");
		goto attach_fail6;
	}

	mutex_init(&sc->sc_glock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&sc->sc_rxlock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&sc->sc_txlock, NULL, MUTEX_DRIVER, NULL);


	/* set supported rates */
	ic->ic_sup_rates[IEEE80211_MODE_11B] = mwl_rateset_11b;
	ic->ic_sup_rates[IEEE80211_MODE_11G] = mwl_rateset_11g;

	/* set supported .11b and .11g channels (1 through 14) */
	for (i = 1; i <= 14; i++) {
		ic->ic_sup_channels[i].ich_freq =
		    ieee80211_ieee2mhz(i, IEEE80211_CHAN_2GHZ);
		ic->ic_sup_channels[i].ich_flags =
		    IEEE80211_CHAN_DYN | IEEE80211_CHAN_2GHZ;
	}

	ic->ic_phytype = IEEE80211_T_OFDM; /* not only, but not used */
	ic->ic_opmode = IEEE80211_M_STA; /* default to BSS mode */
	ic->ic_state = IEEE80211_S_INIT;

	/* set device capabilities */
	ic->ic_caps =
	    IEEE80211_C_TXPMGT |	/* tx power management */
	    IEEE80211_C_SHPREAMBLE |	/* short preamble supported */
	    IEEE80211_C_SHSLOT;		/* short slot time supported */

	/* WPA/WPA2 support */
	ic->ic_caps |= IEEE80211_C_WPA; /* Support WPA/WPA2 */

	/* Enable hardware encryption */
	ic->ic_caps |= IEEE80211_C_WEP | IEEE80211_C_TKIP | IEEE80211_C_AES_CCM;

	ic->ic_xmit = mwl_send;

	ieee80211_attach(ic);

	/* register WPA door */
	ieee80211_register_door(ic, ddi_driver_name(devinfo),
	    ddi_get_instance(devinfo));

	/* override state transition machine */
	sc->sc_newstate = ic->ic_newstate;
	ic->ic_newstate = mwl_newstate;
	ic->ic_node_alloc = mwl_node_alloc;
	ic->ic_node_free = mwl_node_free;
	ic->ic_crypto.cs_max_keyix = 0;
	ic->ic_crypto.cs_key_alloc = mwl_key_alloc;
	ic->ic_crypto.cs_key_delete = mwl_key_delete;
	ic->ic_crypto.cs_key_set = mwl_key_set;

	ieee80211_media_init(ic);

	ic->ic_def_txkey = 0;

	err = mwl_hal_newstation(sc, ic->ic_macaddr, 0, 0, NULL, 0, 0);
	if (err != 0) {
		MWL_DBG(MWL_DBG_ATTACH, "mwl: attach(): "
		    "could not create new station\n");
		goto attach_fail7;
	}

	IEEE80211_ADDR_COPY(ic->ic_bss->in_bssid, ic->ic_macaddr);
	// mwl_setglobalkeys(ic);

	err = ddi_intr_get_supported_types(devinfo, &intr_type);
	if ((err != DDI_SUCCESS) || (!(intr_type & DDI_INTR_TYPE_FIXED))) {
		MWL_DBG(MWL_DBG_ATTACH, "mwl: mwl_attach(): "
		    "fixed type interrupt is not supported\n");
		goto attach_fail7;
	}

	err = ddi_intr_get_nintrs(devinfo, DDI_INTR_TYPE_FIXED, &intr_count);
	if ((err != DDI_SUCCESS) || (intr_count != 1)) {
		MWL_DBG(MWL_DBG_ATTACH, "mwl: mwl_attach(): "
		    "no fixed interrupts\n");
		goto attach_fail7;
	}

	sc->sc_intr_htable = kmem_zalloc(sizeof (ddi_intr_handle_t), KM_SLEEP);

	err = ddi_intr_alloc(devinfo, sc->sc_intr_htable,
	    DDI_INTR_TYPE_FIXED, 0, intr_count, &intr_actual, 0);
	if ((err != DDI_SUCCESS) || (intr_actual != 1)) {
		MWL_DBG(MWL_DBG_ATTACH, "mwl: mwl_attach(): "
		    "ddi_intr_alloc() failed 0x%x\n", err);
		goto attach_fail8;
	}

	err = ddi_intr_get_pri(sc->sc_intr_htable[0], &sc->sc_intr_pri);
	if (err != DDI_SUCCESS) {
		MWL_DBG(MWL_DBG_ATTACH, "mwl: mwl_attach(): "
		    "ddi_intr_get_pri() failed 0x%x\n", err);
		goto attach_fail9;
	}

	err = ddi_intr_add_softint(devinfo, &sc->sc_softintr_hdl,
	    DDI_INTR_SOFTPRI_MAX, mwl_softintr, (caddr_t)sc);
	if (err != DDI_SUCCESS) {
		MWL_DBG(MWL_DBG_ATTACH, "mwl: mwl_attach(): "
		    "ddi_add_softintr() failed");
		goto attach_fail9;
	}

	err = ddi_intr_add_handler(sc->sc_intr_htable[0], mwl_intr,
	    (caddr_t)sc, NULL);
	if (err != DDI_SUCCESS) {
		MWL_DBG(MWL_DBG_ATTACH, "mwl: mwl_attach(): "
		    "ddi_intr_addr_handle() failed\n");
		goto attach_fail10;
	}

	err = ddi_intr_enable(sc->sc_intr_htable[0]);
	if (err != DDI_SUCCESS) {
		MWL_DBG(MWL_DBG_ATTACH, "mwl: mwl_attach(): "
		    "ddi_intr_enable() failed\n");
		goto attach_fail11;
	}

	/*
	 * Provide initial settings for the WiFi plugin; whenever this
	 * information changes, we need to call mac_plugindata_update()
	 */
	wd.wd_opmode = ic->ic_opmode;
	wd.wd_secalloc = WIFI_SEC_NONE;
	IEEE80211_ADDR_COPY(wd.wd_bssid, ic->ic_bss->in_bssid);

	if ((macp = mac_alloc(MAC_VERSION)) == NULL) {
		MWL_DBG(MWL_DBG_ATTACH, "mwl: mwl_attach(): "
		    "MAC version mismatch\n");
		goto attach_fail12;
	}

	macp->m_type_ident	= MAC_PLUGIN_IDENT_WIFI;
	macp->m_driver		= sc;
	macp->m_dip		= devinfo;
	macp->m_src_addr	= ic->ic_macaddr;
	macp->m_callbacks	= &mwl_m_callbacks;
	macp->m_min_sdu		= 0;
	macp->m_max_sdu		= IEEE80211_MTU;
	macp->m_pdata		= &wd;
	macp->m_pdata_size	= sizeof (wd);

	err = mac_register(macp, &ic->ic_mach);
	mac_free(macp);
	if (err != 0) {
		MWL_DBG(MWL_DBG_ATTACH, "mwl: mwl_attach(): "
		    "mac_register err %x\n", err);
		goto attach_fail12;
	}

	/*
	 * Create minor node of type DDI_NT_NET_WIFI
	 */
	(void) snprintf(strbuf, sizeof (strbuf), "%s%d",
	    "mwl", instance);
	err = ddi_create_minor_node(devinfo, strbuf, S_IFCHR,
	    instance + 1, DDI_NT_NET_WIFI, 0);
	if (err != 0) {
		MWL_DBG(MWL_DBG_ATTACH, "mwl: mwl_attach(): "
		    "create minor node error\n");
		goto attach_fail13;
	}

	/*
	 * Notify link is down now
	 */
	mac_link_update(ic->ic_mach, LINK_STATE_DOWN);

	MWL_DBG(MWL_DBG_ATTACH, "mwl: mwl_attach(): "
	    "driver attach successfully\n");
	return (DDI_SUCCESS);

attach_fail13:
	(void) mac_disable(ic->ic_mach);
	(void) mac_unregister(ic->ic_mach);
attach_fail12:
	(void) ddi_intr_disable(sc->sc_intr_htable[0]);
attach_fail11:
	(void) ddi_intr_remove_handler(sc->sc_intr_htable[0]);
attach_fail10:
	(void) ddi_intr_remove_softint(sc->sc_softintr_hdl);
	sc->sc_softintr_hdl = NULL;
attach_fail9:
	(void) ddi_intr_free(sc->sc_intr_htable[0]);
attach_fail8:
	kmem_free(sc->sc_intr_htable, sizeof (ddi_intr_handle_t));
attach_fail7:
	mutex_destroy(&sc->sc_txlock);
	mutex_destroy(&sc->sc_rxlock);
	mutex_destroy(&sc->sc_glock);
attach_fail6:
	while (--qid >= 0)
		mwl_free_tx_ring(sc, &sc->sc_txring[qid]);
attach_fail5:
	mwl_free_rx_ring(sc);
attach_fail4:
	mwl_free_cmdbuf(sc);
attach_fail3:
	ddi_regs_map_free(&sc->sc_mem_handle);
attach_fail2:
	ddi_regs_map_free(&sc->sc_io_handle);
attach_fail1:
	ddi_regs_map_free(&sc->sc_cfg_handle);
attach_fail0:
	ddi_soft_state_free(mwl_soft_state_p, ddi_get_instance(devinfo));
	return (DDI_FAILURE);
}

static int32_t
mwl_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd)
{
	struct mwl_softc *sc;
	int qid;

	sc = ddi_get_soft_state(mwl_soft_state_p, ddi_get_instance(devinfo));
	ASSERT(sc != NULL);

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		if (MWL_IS_RUNNING(sc))
			mwl_stop(sc);
		for (qid = 0; qid < MWL_NUM_TX_QUEUES; qid++)
			mwl_free_tx_ring(sc, &sc->sc_txring[qid]);
		mwl_free_rx_ring(sc);
		MWL_GLOCK(sc);
		sc->sc_flags |= MWL_F_SUSPEND;
		MWL_GUNLOCK(sc);
		MWL_DBG(MWL_DBG_SR, "mwl: mwl_detach(): "
		    "suspend now\n");
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	if (mac_disable(sc->sc_ic.ic_mach) != 0)
		return (DDI_FAILURE);

	/*
	 * Unregister from the MAC layer subsystem
	 */
	(void) mac_unregister(sc->sc_ic.ic_mach);

	(void) ddi_intr_remove_softint(sc->sc_softintr_hdl);
	sc->sc_softintr_hdl = NULL;
	(void) ddi_intr_disable(sc->sc_intr_htable[0]);
	(void) ddi_intr_remove_handler(sc->sc_intr_htable[0]);
	(void) ddi_intr_free(sc->sc_intr_htable[0]);
	kmem_free(sc->sc_intr_htable, sizeof (ddi_intr_handle_t));

	/*
	 * detach ieee80211 layer
	 */
	ieee80211_detach(&sc->sc_ic);


	for (qid = 0; qid < MWL_NUM_TX_QUEUES; qid++)
		mwl_free_tx_ring(sc, &sc->sc_txring[qid]);
	mwl_free_rx_ring(sc);
	mwl_free_cmdbuf(sc);

	mutex_destroy(&sc->sc_txlock);
	mutex_destroy(&sc->sc_rxlock);
	mutex_destroy(&sc->sc_glock);

	ddi_regs_map_free(&sc->sc_mem_handle);
	ddi_regs_map_free(&sc->sc_io_handle);
	ddi_regs_map_free(&sc->sc_cfg_handle);

	ddi_remove_minor_node(devinfo, NULL);
	ddi_soft_state_free(mwl_soft_state_p, ddi_get_instance(devinfo));

	MWL_DBG(MWL_DBG_ATTACH, "mwl: mwl_detach(): "
	    "detach successfully\n");
	return (DDI_SUCCESS);
}

/*
 * quiesce(9E) entry point.
 *
 * This function is called when the system is single-threaded at high
 * PIL with preemption disabled. Therefore, this function must not be
 * blocked.
 *
 * This function returns DDI_SUCCESS on success, or DDI_FAILURE on failure.
 * DDI_FAILURE indicates an error condition and should almost never happen.
 */
int
mwl_quiesce(dev_info_t *dip)
{
	struct mwl_softc *sc;

	sc = ddi_get_soft_state(mwl_soft_state_p, ddi_get_instance(dip));
	if (sc == NULL)
		return (DDI_FAILURE);

#ifdef DEBUG
	mwl_dbg_flags = 0;
#endif

	/*
	 * No more blocking is allowed while we are in quiesce(9E) entry point
	 */
	sc->sc_flags |= MWL_F_QUIESCE;

	/*
	 * Disable all interrupts
	 */
	mwl_stop(sc);
	return (DDI_SUCCESS);
}

int
_init(void)
{
	int status;

	status = ddi_soft_state_init(&mwl_soft_state_p,
	    sizeof (struct mwl_softc), 1);
	if (status != 0)
		return (status);

	mac_init_ops(&mwl_dev_ops, "mwl");
	status = mod_install(&modlinkage);
	if (status != 0) {
		mac_fini_ops(&mwl_dev_ops);
		ddi_soft_state_fini(&mwl_soft_state_p);
	}
	return (status);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int status;

	status = mod_remove(&modlinkage);
	if (status == 0) {
		mac_fini_ops(&mwl_dev_ops);
		ddi_soft_state_fini(&mwl_soft_state_p);
	}
	return (status);
}
