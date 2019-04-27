/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2002-2004 Sam Leffler, Errno Consulting
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer,
 * without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 * similar to the "NO WARRANTY" disclaimer below ("Disclaimer") and any
 * redistribution must be conditioned upon including a substantially
 * similar Disclaimer requirement for further binary redistribution.
 * 3. Neither the names of the above-listed copyright holders nor the names
 * of any contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
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
 *
 */

/*
 * Driver for the Atheros Wireless LAN controller.
 *
 * The Atheros driver calls into net80211 module for IEEE80211 protocol
 * management functionalities. The driver includes a LLD(Low Level Driver)
 * part to implement H/W related operations.
 * The following is the high level structure of ath driver.
 * (The arrows between modules indicate function call direction.)
 *
 *
 *                                                  |
 *                                                  | GLD thread
 *                                                  V
 *         ==================  =========================================
 *         |                |  |[1]                                    |
 *         |                |  |  GLDv3 Callback functions registered  |
 *         |   Net80211     |  =========================       by      |
 *         |    module      |          |               |     driver    |
 *         |                |          V               |               |
 *         |                |========================  |               |
 *         |   Functions exported by net80211       |  |               |
 *         |                                        |  |               |
 *         ==========================================  =================
 *                         |                                  |
 *                         V                                  |
 *         +----------------------------------+               |
 *         |[2]                               |               |
 *         |    Net80211 Callback functions   |               |
 *         |      registered by LLD           |               |
 *         +----------------------------------+               |
 *                         |                                  |
 *                         V                                  v
 *         +-----------------------------------------------------------+
 *         |[3]                                                        |
 *         |                LLD Internal functions                     |
 *         |                                                           |
 *         +-----------------------------------------------------------+
 *                                    ^
 *                                    | Software interrupt thread
 *                                    |
 *
 * The short description of each module is as below:
 *      Module 1: GLD callback functions, which are intercepting the calls from
 *                GLD to LLD.
 *      Module 2: Net80211 callback functions registered by LLD, which
 *                calls into LLD for H/W related functions needed by net80211.
 *      Module 3: LLD Internal functions, which are responsible for allocing
 *                descriptor/buffer, handling interrupt and other H/W
 *                operations.
 *
 * All functions are running in 3 types of thread:
 * 1. GLD callbacks threads, such as ioctl, intr, etc.
 * 2. Clock interruptt thread which is responsible for scan, rate control and
 *    calibration.
 * 3. Software Interrupt thread originated in LLD.
 *
 * The lock strategy is as below:
 * There have 4 queues for tx, each queue has one asc_txqlock[i] to
 *      prevent conflicts access to queue resource from different thread.
 *
 * All the transmit buffers are contained in asc_txbuf which are
 *      protected by asc_txbuflock.
 *
 * Each receive buffers are contained in asc_rxbuf which are protected
 *      by asc_rxbuflock.
 *
 * In ath struct, asc_genlock is a general lock, protecting most other
 *      operational data in ath_softc struct and HAL accesses.
 *      It is acquired by the interupt handler and most "mode-ctrl" routines.
 *
 * Any of the locks can be acquired singly, but where multiple
 * locks are acquired, they *must* be in the order:
 *    asc_genlock >> asc_txqlock[i] >> asc_txbuflock >> asc_rxbuflock
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/signal.h>
#include <sys/stream.h>
#include <sys/termio.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/cmn_err.h>
#include <sys/stropts.h>
#include <sys/strsubr.h>
#include <sys/strtty.h>
#include <sys/kbio.h>
#include <sys/cred.h>
#include <sys/stat.h>
#include <sys/consdev.h>
#include <sys/kmem.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/pci.h>
#include <sys/errno.h>
#include <sys/mac_provider.h>
#include <sys/dlpi.h>
#include <sys/ethernet.h>
#include <sys/list.h>
#include <sys/byteorder.h>
#include <sys/strsun.h>
#include <sys/policy.h>
#include <inet/common.h>
#include <inet/nd.h>
#include <inet/mi.h>
#include <inet/wifi_ioctl.h>
#include <sys/mac_wifi.h>
#include "ath_hal.h"
#include "ath_impl.h"
#include "ath_aux.h"
#include "ath_rate.h"

#define	ATH_MAX_RSSI	63	/* max rssi */

extern void ath_halfix_init(void);
extern void ath_halfix_finit(void);
extern int32_t ath_getset(ath_t *asc, mblk_t *mp, uint32_t cmd);

/*
 * PIO access attributes for registers
 */
static ddi_device_acc_attr_t ath_reg_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

/*
 * DMA access attributes for descriptors: NOT to be byte swapped.
 */
static ddi_device_acc_attr_t ath_desc_accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

/*
 * DMA attributes for rx/tx buffers
 */
static ddi_dma_attr_t ath_dma_attr = {
	DMA_ATTR_V0,		/* version number */
	0,			/* low address */
	0xffffffffU,		/* high address */
	0x3ffffU,		/* counter register max */
	1,			/* alignment */
	0xFFF,			/* burst sizes */
	1,			/* minimum transfer size */
	0x3ffffU,		/* max transfer size */
	0xffffffffU,		/* address register max */
	1,			/* no scatter-gather */
	1,			/* granularity of device */
	0,			/* DMA flags */
};

static ddi_dma_attr_t ath_desc_dma_attr = {
	DMA_ATTR_V0,		/* version number */
	0,			/* low address */
	0xffffffffU,		/* high address */
	0xffffffffU,		/* counter register max */
	0x1000,			/* alignment */
	0xFFF,			/* burst sizes */
	1,			/* minimum transfer size */
	0xffffffffU,		/* max transfer size */
	0xffffffffU,		/* address register max */
	1,			/* no scatter-gather */
	1,			/* granularity of device */
	0,			/* DMA flags */
};

static kmutex_t ath_loglock;
static void *ath_soft_state_p = NULL;
static int ath_dwelltime = 150;		/* scan interval, ms */

static int	ath_m_stat(void *,  uint_t, uint64_t *);
static int	ath_m_start(void *);
static void	ath_m_stop(void *);
static int	ath_m_promisc(void *, boolean_t);
static int	ath_m_multicst(void *, boolean_t, const uint8_t *);
static int	ath_m_unicst(void *, const uint8_t *);
static mblk_t	*ath_m_tx(void *, mblk_t *);
static void	ath_m_ioctl(void *, queue_t *, mblk_t *);
static int	ath_m_setprop(void *, const char *, mac_prop_id_t,
    uint_t, const void *);
static int	ath_m_getprop(void *, const char *, mac_prop_id_t,
    uint_t, void *);
static void	ath_m_propinfo(void *, const char *, mac_prop_id_t,
    mac_prop_info_handle_t);

static mac_callbacks_t ath_m_callbacks = {
	MC_IOCTL | MC_SETPROP | MC_GETPROP | MC_PROPINFO,
	ath_m_stat,
	ath_m_start,
	ath_m_stop,
	ath_m_promisc,
	ath_m_multicst,
	ath_m_unicst,
	ath_m_tx,
	NULL,
	ath_m_ioctl,
	NULL,		/* mc_getcapab */
	NULL,
	NULL,
	ath_m_setprop,
	ath_m_getprop,
	ath_m_propinfo
};

/*
 * Available debug flags:
 * ATH_DBG_INIT, ATH_DBG_GLD, ATH_DBG_HAL, ATH_DBG_INT, ATH_DBG_ATTACH,
 * ATH_DBG_DETACH, ATH_DBG_AUX, ATH_DBG_WIFICFG, ATH_DBG_OSDEP
 */
uint32_t ath_dbg_flags = 0;

/*
 * Exception/warning cases not leading to panic.
 */
void
ath_problem(const int8_t *fmt, ...)
{
	va_list args;

	mutex_enter(&ath_loglock);

	va_start(args, fmt);
	vcmn_err(CE_WARN, fmt, args);
	va_end(args);

	mutex_exit(&ath_loglock);
}

/*
 * Normal log information independent of debug.
 */
void
ath_log(const int8_t *fmt, ...)
{
	va_list args;

	mutex_enter(&ath_loglock);

	va_start(args, fmt);
	vcmn_err(CE_CONT, fmt, args);
	va_end(args);

	mutex_exit(&ath_loglock);
}

void
ath_dbg(uint32_t dbg_flags, const int8_t *fmt, ...)
{
	va_list args;

	if (dbg_flags & ath_dbg_flags) {
		mutex_enter(&ath_loglock);
		va_start(args, fmt);
		vcmn_err(CE_CONT, fmt, args);
		va_end(args);
		mutex_exit(&ath_loglock);
	}
}

void
ath_setup_desc(ath_t *asc, struct ath_buf *bf)
{
	struct ath_desc *ds;

	ds = bf->bf_desc;
	ds->ds_link = bf->bf_daddr;
	ds->ds_data = bf->bf_dma.cookie.dmac_address;
	ATH_HAL_SETUPRXDESC(asc->asc_ah, ds,
	    bf->bf_dma.alength,		/* buffer size */
	    0);

	if (asc->asc_rxlink != NULL)
		*asc->asc_rxlink = bf->bf_daddr;
	asc->asc_rxlink = &ds->ds_link;
}


/*
 * Allocate an area of memory and a DMA handle for accessing it
 */
static int
ath_alloc_dma_mem(dev_info_t *devinfo, ddi_dma_attr_t *dma_attr, size_t memsize,
    ddi_device_acc_attr_t *attr_p, uint_t alloc_flags,
    uint_t bind_flags, dma_area_t *dma_p)
{
	int err;

	/*
	 * Allocate handle
	 */
	err = ddi_dma_alloc_handle(devinfo, dma_attr,
	    DDI_DMA_SLEEP, NULL, &dma_p->dma_hdl);
	if (err != DDI_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * Allocate memory
	 */
	err = ddi_dma_mem_alloc(dma_p->dma_hdl, memsize, attr_p,
	    alloc_flags, DDI_DMA_SLEEP, NULL, &dma_p->mem_va,
	    &dma_p->alength, &dma_p->acc_hdl);
	if (err != DDI_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * Bind the two together
	 */
	err = ddi_dma_addr_bind_handle(dma_p->dma_hdl, NULL,
	    dma_p->mem_va, dma_p->alength, bind_flags,
	    DDI_DMA_SLEEP, NULL, &dma_p->cookie, &dma_p->ncookies);
	if (err != DDI_DMA_MAPPED)
		return (DDI_FAILURE);

	dma_p->nslots = ~0U;
	dma_p->size = ~0U;
	dma_p->token = ~0U;
	dma_p->offset = 0;
	return (DDI_SUCCESS);
}

/*
 * Free one allocated area of DMAable memory
 */
static void
ath_free_dma_mem(dma_area_t *dma_p)
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


/*
 * Initialize tx/rx buffer list. Allocate DMA memory for
 * each buffer.
 */
static int
ath_buflist_setup(dev_info_t *devinfo, ath_t *asc, list_t *bflist,
    struct ath_buf **pbf, struct ath_desc **pds, int nbuf, uint_t dmabflags)
{
	int i, err;
	struct ath_buf *bf = *pbf;
	struct ath_desc *ds = *pds;

	list_create(bflist, sizeof (struct ath_buf),
	    offsetof(struct ath_buf, bf_node));
	for (i = 0; i < nbuf; i++, bf++, ds++) {
		bf->bf_desc = ds;
		bf->bf_daddr = asc->asc_desc_dma.cookie.dmac_address +
		    ((uintptr_t)ds - (uintptr_t)asc->asc_desc);
		list_insert_tail(bflist, bf);

		/* alloc DMA memory */
		err = ath_alloc_dma_mem(devinfo, &ath_dma_attr,
		    asc->asc_dmabuf_size, &ath_desc_accattr, DDI_DMA_STREAMING,
		    dmabflags, &bf->bf_dma);
		if (err != DDI_SUCCESS)
			return (err);
	}
	*pbf = bf;
	*pds = ds;

	return (DDI_SUCCESS);
}

/*
 * Destroy tx/rx buffer list. Free DMA memory.
 */
static void
ath_buflist_cleanup(list_t *buflist)
{
	struct ath_buf *bf;

	if (!buflist)
		return;

	bf = list_head(buflist);
	while (bf != NULL) {
		if (bf->bf_m != NULL) {
			freemsg(bf->bf_m);
			bf->bf_m = NULL;
		}
		/* Free DMA buffer */
		ath_free_dma_mem(&bf->bf_dma);
		if (bf->bf_in != NULL) {
			ieee80211_free_node(bf->bf_in);
			bf->bf_in = NULL;
		}
		list_remove(buflist, bf);
		bf = list_head(buflist);
	}
	list_destroy(buflist);
}


static void
ath_desc_free(ath_t *asc)
{
	ath_buflist_cleanup(&asc->asc_txbuf_list);
	ath_buflist_cleanup(&asc->asc_rxbuf_list);

	/* Free descriptor DMA buffer */
	ath_free_dma_mem(&asc->asc_desc_dma);

	kmem_free((void *)asc->asc_vbufptr, asc->asc_vbuflen);
	asc->asc_vbufptr = NULL;
}

static int
ath_desc_alloc(dev_info_t *devinfo, ath_t *asc)
{
	int err;
	size_t size;
	struct ath_desc *ds;
	struct ath_buf *bf;

	size = sizeof (struct ath_desc) * (ATH_TXBUF + ATH_RXBUF);

	err = ath_alloc_dma_mem(devinfo, &ath_desc_dma_attr, size,
	    &ath_desc_accattr, DDI_DMA_CONSISTENT,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT, &asc->asc_desc_dma);

	/* virtual address of the first descriptor */
	asc->asc_desc = (struct ath_desc *)asc->asc_desc_dma.mem_va;

	ds = asc->asc_desc;
	ATH_DEBUG((ATH_DBG_INIT, "ath: ath_desc_alloc(): DMA map: "
	    "%p (%d) -> %p\n",
	    asc->asc_desc, asc->asc_desc_dma.alength,
	    asc->asc_desc_dma.cookie.dmac_address));

	/* allocate data structures to describe TX/RX DMA buffers */
	asc->asc_vbuflen = sizeof (struct ath_buf) * (ATH_TXBUF + ATH_RXBUF);
	bf = (struct ath_buf *)kmem_zalloc(asc->asc_vbuflen, KM_SLEEP);
	asc->asc_vbufptr = bf;

	/* DMA buffer size for each TX/RX packet */
	asc->asc_dmabuf_size = roundup(1000 + sizeof (struct ieee80211_frame) +
	    IEEE80211_MTU + IEEE80211_CRC_LEN +
	    (IEEE80211_WEP_IVLEN + IEEE80211_WEP_KIDLEN +
	    IEEE80211_WEP_CRCLEN), asc->asc_cachelsz);

	/* create RX buffer list */
	err = ath_buflist_setup(devinfo, asc, &asc->asc_rxbuf_list, &bf, &ds,
	    ATH_RXBUF, DDI_DMA_READ | DDI_DMA_STREAMING);
	if (err != DDI_SUCCESS) {
		ath_desc_free(asc);
		return (err);
	}

	/* create TX buffer list */
	err = ath_buflist_setup(devinfo, asc, &asc->asc_txbuf_list, &bf, &ds,
	    ATH_TXBUF, DDI_DMA_STREAMING);
	if (err != DDI_SUCCESS) {
		ath_desc_free(asc);
		return (err);
	}


	return (DDI_SUCCESS);
}

static void
ath_printrxbuf(struct ath_buf *bf, int32_t done)
{
	struct ath_desc *ds = bf->bf_desc;
	const struct ath_rx_status *rs = &bf->bf_status.ds_rxstat;

	ATH_DEBUG((ATH_DBG_RECV, "ath: R (%p %p) %08x %08x %08x "
	    "%08x %08x %08x %c\n",
	    ds, bf->bf_daddr,
	    ds->ds_link, ds->ds_data,
	    ds->ds_ctl0, ds->ds_ctl1,
	    ds->ds_hw[0], ds->ds_hw[1],
	    !done ? ' ' : (rs->rs_status == 0) ? '*' : '!'));
}

static void
ath_rx_handler(ath_t *asc)
{
	ieee80211com_t *ic = (ieee80211com_t *)asc;
	struct ath_buf *bf;
	struct ath_hal *ah = asc->asc_ah;
	struct ath_desc *ds;
	struct ath_rx_status *rs;
	mblk_t *rx_mp;
	struct ieee80211_frame *wh;
	int32_t len, loop = 1;
	uint8_t phyerr;
	HAL_STATUS status;
	HAL_NODE_STATS hal_node_stats;
	struct ieee80211_node *in;

	do {
		mutex_enter(&asc->asc_rxbuflock);
		bf = list_head(&asc->asc_rxbuf_list);
		if (bf == NULL) {
			ATH_DEBUG((ATH_DBG_RECV, "ath: ath_rx_handler(): "
			    "no buffer\n"));
			mutex_exit(&asc->asc_rxbuflock);
			break;
		}
		ASSERT(bf->bf_dma.cookie.dmac_address != 0);
		ds = bf->bf_desc;
		if (ds->ds_link == bf->bf_daddr) {
			/*
			 * Never process the self-linked entry at the end,
			 * this may be met at heavy load.
			 */
			mutex_exit(&asc->asc_rxbuflock);
			break;
		}

		rs = &bf->bf_status.ds_rxstat;
		status = ATH_HAL_RXPROCDESC(ah, ds,
		    bf->bf_daddr,
		    ATH_PA2DESC(asc, ds->ds_link), rs);
		if (status == HAL_EINPROGRESS) {
			mutex_exit(&asc->asc_rxbuflock);
			break;
		}
		list_remove(&asc->asc_rxbuf_list, bf);
		mutex_exit(&asc->asc_rxbuflock);

		if (rs->rs_status != 0) {
			if (rs->rs_status & HAL_RXERR_CRC)
				asc->asc_stats.ast_rx_crcerr++;
			if (rs->rs_status & HAL_RXERR_FIFO)
				asc->asc_stats.ast_rx_fifoerr++;
			if (rs->rs_status & HAL_RXERR_DECRYPT)
				asc->asc_stats.ast_rx_badcrypt++;
			if (rs->rs_status & HAL_RXERR_PHY) {
				asc->asc_stats.ast_rx_phyerr++;
				phyerr = rs->rs_phyerr & 0x1f;
				asc->asc_stats.ast_rx_phy[phyerr]++;
			}
			goto rx_next;
		}
		len = rs->rs_datalen;

		/* less than sizeof(struct ieee80211_frame) */
		if (len < 20) {
			asc->asc_stats.ast_rx_tooshort++;
			goto rx_next;
		}

		if ((rx_mp = allocb(asc->asc_dmabuf_size, BPRI_MED)) == NULL) {
			ath_problem("ath: ath_rx_handler(): "
			    "allocing mblk buffer failed.\n");
			return;
		}

		ATH_DMA_SYNC(bf->bf_dma, DDI_DMA_SYNC_FORCPU);
		bcopy(bf->bf_dma.mem_va, rx_mp->b_rptr, len);

		rx_mp->b_wptr += len;
		wh = (struct ieee80211_frame *)rx_mp->b_rptr;
		if ((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) ==
		    IEEE80211_FC0_TYPE_CTL) {
			/*
			 * Ignore control frame received in promisc mode.
			 */
			freemsg(rx_mp);
			goto rx_next;
		}
		/* Remove the CRC at the end of IEEE80211 frame */
		rx_mp->b_wptr -= IEEE80211_CRC_LEN;
#ifdef DEBUG
		ath_printrxbuf(bf, status == HAL_OK);
#endif /* DEBUG */
		/*
		 * Locate the node for sender, track state, and then
		 * pass the (referenced) node up to the 802.11 layer
		 * for its use.
		 */
		in = ieee80211_find_rxnode(ic, wh);

		/*
		 * Send frame up for processing.
		 */
		(void) ieee80211_input(ic, rx_mp, in,
		    rs->rs_rssi, rs->rs_tstamp);

		ieee80211_free_node(in);

rx_next:
		mutex_enter(&asc->asc_rxbuflock);
		list_insert_tail(&asc->asc_rxbuf_list, bf);
		mutex_exit(&asc->asc_rxbuflock);
		ath_setup_desc(asc, bf);
	} while (loop);

	/* rx signal state monitoring */
	ATH_HAL_RXMONITOR(ah, &hal_node_stats, &asc->asc_curchan);
}

static void
ath_printtxbuf(struct ath_buf *bf, int done)
{
	struct ath_desc *ds = bf->bf_desc;
	const struct ath_tx_status *ts = &bf->bf_status.ds_txstat;

	ATH_DEBUG((ATH_DBG_SEND, "ath: T(%p %p) %08x %08x %08x %08x %08x"
	    " %08x %08x %08x %c\n",
	    ds, bf->bf_daddr,
	    ds->ds_link, ds->ds_data,
	    ds->ds_ctl0, ds->ds_ctl1,
	    ds->ds_hw[0], ds->ds_hw[1], ds->ds_hw[2], ds->ds_hw[3],
	    !done ? ' ' : (ts->ts_status == 0) ? '*' : '!'));
}

/*
 * The input parameter mp has following assumption:
 * For data packets, GLDv3 mac_wifi plugin allocates and fills the
 * ieee80211 header. For management packets, net80211 allocates and
 * fills the ieee80211 header. In both cases, enough spaces in the
 * header are left for encryption option.
 */
static int32_t
ath_tx_start(ath_t *asc, struct ieee80211_node *in, struct ath_buf *bf,
    mblk_t *mp)
{
	ieee80211com_t *ic = (ieee80211com_t *)asc;
	struct ieee80211_frame *wh;
	struct ath_hal *ah = asc->asc_ah;
	uint32_t subtype, flags, ctsduration;
	int32_t keyix, iswep, hdrlen, pktlen, mblen, mbslen, try0;
	uint8_t rix, cix, txrate, ctsrate;
	struct ath_desc *ds;
	struct ath_txq *txq;
	HAL_PKT_TYPE atype;
	const HAL_RATE_TABLE *rt;
	HAL_BOOL shortPreamble;
	struct ath_node *an;
	caddr_t dest;

	/*
	 * CRC are added by H/W, not encaped by driver,
	 * but we must count it in pkt length.
	 */
	pktlen = IEEE80211_CRC_LEN;

	wh = (struct ieee80211_frame *)mp->b_rptr;
	iswep = wh->i_fc[1] & IEEE80211_FC1_WEP;
	keyix = HAL_TXKEYIX_INVALID;
	hdrlen = sizeof (struct ieee80211_frame);
	if (iswep != 0) {
		const struct ieee80211_cipher *cip;
		struct ieee80211_key *k;

		/*
		 * Construct the 802.11 header+trailer for an encrypted
		 * frame. The only reason this can fail is because of an
		 * unknown or unsupported cipher/key type.
		 */
		k = ieee80211_crypto_encap(ic, mp);
		if (k == NULL) {
			ATH_DEBUG((ATH_DBG_AUX, "crypto_encap failed\n"));
			/*
			 * This can happen when the key is yanked after the
			 * frame was queued.  Just discard the frame; the
			 * 802.11 layer counts failures and provides
			 * debugging/diagnostics.
			 */
			return (EIO);
		}
		cip = k->wk_cipher;
		/*
		 * Adjust the packet + header lengths for the crypto
		 * additions and calculate the h/w key index.  When
		 * a s/w mic is done the frame will have had any mic
		 * added to it prior to entry so m0->m_pkthdr.len above will
		 * account for it. Otherwise we need to add it to the
		 * packet length.
		 */
		hdrlen += cip->ic_header;
		pktlen += cip->ic_trailer;
		if ((k->wk_flags & IEEE80211_KEY_SWMIC) == 0)
			pktlen += cip->ic_miclen;
		keyix = k->wk_keyix;

		/* packet header may have moved, reset our local pointer */
		wh = (struct ieee80211_frame *)mp->b_rptr;
	}

	dest = bf->bf_dma.mem_va;
	for (; mp != NULL; mp = mp->b_cont) {
		mblen = MBLKL(mp);
		bcopy(mp->b_rptr, dest, mblen);
		dest += mblen;
	}
	mbslen = (uintptr_t)dest - (uintptr_t)bf->bf_dma.mem_va;
	pktlen += mbslen;

	bf->bf_in = in;

	/* setup descriptors */
	ds = bf->bf_desc;
	rt = asc->asc_currates;
	ASSERT(rt != NULL);

	/*
	 * The 802.11 layer marks whether or not we should
	 * use short preamble based on the current mode and
	 * negotiated parameters.
	 */
	if ((ic->ic_flags & IEEE80211_F_SHPREAMBLE) &&
	    (in->in_capinfo & IEEE80211_CAPINFO_SHORT_PREAMBLE)) {
		shortPreamble = AH_TRUE;
		asc->asc_stats.ast_tx_shortpre++;
	} else {
		shortPreamble = AH_FALSE;
	}

	an = ATH_NODE(in);

	/*
	 * Calculate Atheros packet type from IEEE80211 packet header
	 * and setup for rate calculations.
	 */
	switch (wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) {
	case IEEE80211_FC0_TYPE_MGT:
		subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
		if (subtype == IEEE80211_FC0_SUBTYPE_BEACON)
			atype = HAL_PKT_TYPE_BEACON;
		else if (subtype == IEEE80211_FC0_SUBTYPE_PROBE_RESP)
			atype = HAL_PKT_TYPE_PROBE_RESP;
		else if (subtype == IEEE80211_FC0_SUBTYPE_ATIM)
			atype = HAL_PKT_TYPE_ATIM;
		else
			atype = HAL_PKT_TYPE_NORMAL;
		rix = 0;	/* lowest rate */
		try0 = ATH_TXMAXTRY;
		if (shortPreamble)
			txrate = an->an_tx_mgtratesp;
		else
			txrate = an->an_tx_mgtrate;
		/* force all ctl frames to highest queue */
		txq = asc->asc_ac2q[WME_AC_VO];
		break;
	case IEEE80211_FC0_TYPE_CTL:
		atype = HAL_PKT_TYPE_PSPOLL;
		subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
		rix = 0;	/* lowest rate */
		try0 = ATH_TXMAXTRY;
		if (shortPreamble)
			txrate = an->an_tx_mgtratesp;
		else
			txrate = an->an_tx_mgtrate;
		/* force all ctl frames to highest queue */
		txq = asc->asc_ac2q[WME_AC_VO];
		break;
	case IEEE80211_FC0_TYPE_DATA:
		atype = HAL_PKT_TYPE_NORMAL;
		rix = an->an_tx_rix0;
		try0 = an->an_tx_try0;
		if (shortPreamble)
			txrate = an->an_tx_rate0sp;
		else
			txrate = an->an_tx_rate0;
		/* Always use background queue */
		txq = asc->asc_ac2q[WME_AC_BK];
		break;
	default:
		/* Unknown 802.11 frame */
		asc->asc_stats.ast_tx_invalid++;
		return (1);
	}
	/*
	 * Calculate miscellaneous flags.
	 */
	flags = HAL_TXDESC_CLRDMASK;
	if (IEEE80211_IS_MULTICAST(wh->i_addr1)) {
		flags |= HAL_TXDESC_NOACK;	/* no ack on broad/multicast */
		asc->asc_stats.ast_tx_noack++;
	} else if (pktlen > ic->ic_rtsthreshold) {
		flags |= HAL_TXDESC_RTSENA;	/* RTS based on frame length */
		asc->asc_stats.ast_tx_rts++;
	}

	/*
	 * Calculate duration.  This logically belongs in the 802.11
	 * layer but it lacks sufficient information to calculate it.
	 */
	if ((flags & HAL_TXDESC_NOACK) == 0 &&
	    (wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) !=
	    IEEE80211_FC0_TYPE_CTL) {
		uint16_t dur;
		dur = ath_hal_computetxtime(ah, rt, IEEE80211_ACK_SIZE,
		    rix, shortPreamble);
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		*(uint16_t *)wh->i_dur = LE_16(dur);
	}

	/*
	 * Calculate RTS/CTS rate and duration if needed.
	 */
	ctsduration = 0;
	if (flags & (HAL_TXDESC_RTSENA|HAL_TXDESC_CTSENA)) {
		/*
		 * CTS transmit rate is derived from the transmit rate
		 * by looking in the h/w rate table.  We must also factor
		 * in whether or not a short preamble is to be used.
		 */
		cix = rt->info[rix].controlRate;
		ctsrate = rt->info[cix].rateCode;
		if (shortPreamble)
			ctsrate |= rt->info[cix].shortPreamble;
		/*
		 * Compute the transmit duration based on the size
		 * of an ACK frame.  We call into the HAL to do the
		 * computation since it depends on the characteristics
		 * of the actual PHY being used.
		 */
		if (flags & HAL_TXDESC_RTSENA) {	/* SIFS + CTS */
			ctsduration += ath_hal_computetxtime(ah,
			    rt, IEEE80211_ACK_SIZE, cix, shortPreamble);
		}
		/* SIFS + data */
		ctsduration += ath_hal_computetxtime(ah,
		    rt, pktlen, rix, shortPreamble);
		if ((flags & HAL_TXDESC_NOACK) == 0) {  /* SIFS + ACK */
			ctsduration += ath_hal_computetxtime(ah,
			    rt, IEEE80211_ACK_SIZE, cix, shortPreamble);
		}
	} else
		ctsrate = 0;

	if (++txq->axq_intrcnt >= ATH_TXINTR_PERIOD) {
		flags |= HAL_TXDESC_INTREQ;
		txq->axq_intrcnt = 0;
	}

	/*
	 * Formulate first tx descriptor with tx controls.
	 */
	ATH_HAL_SETUPTXDESC(ah, ds,
	    pktlen,			/* packet length */
	    hdrlen,			/* header length */
	    atype,			/* Atheros packet type */
	    MIN(in->in_txpower, 60),	/* txpower */
	    txrate, try0,		/* series 0 rate/tries */
	    keyix,			/* key cache index */
	    an->an_tx_antenna,		/* antenna mode */
	    flags,			/* flags */
	    ctsrate,			/* rts/cts rate */
	    ctsduration);		/* rts/cts duration */
	bf->bf_flags = flags;

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	ATH_DEBUG((ATH_DBG_SEND, "ath: ath_xmit(): to %s totlen=%d "
	    "an->an_tx_rate1sp=%d tx_rate2sp=%d tx_rate3sp=%d "
	    "qnum=%d rix=%d sht=%d dur = %d\n",
	    ieee80211_macaddr_sprintf(wh->i_addr1), mbslen, an->an_tx_rate1sp,
	    an->an_tx_rate2sp, an->an_tx_rate3sp,
	    txq->axq_qnum, rix, shortPreamble, *(uint16_t *)wh->i_dur));

	/*
	 * Setup the multi-rate retry state only when we're
	 * going to use it.  This assumes ath_hal_setuptxdesc
	 * initializes the descriptors (so we don't have to)
	 * when the hardware supports multi-rate retry and
	 * we don't use it.
	 */
	if (try0 != ATH_TXMAXTRY)
		ATH_HAL_SETUPXTXDESC(ah, ds,
		    an->an_tx_rate1sp, 2,	/* series 1 */
		    an->an_tx_rate2sp, 2,	/* series 2 */
		    an->an_tx_rate3sp, 2);	/* series 3 */

	ds->ds_link = 0;
	ds->ds_data = bf->bf_dma.cookie.dmac_address;
	ATH_HAL_FILLTXDESC(ah, ds,
	    mbslen,		/* segment length */
	    AH_TRUE,		/* first segment */
	    AH_TRUE,		/* last segment */
	    ds);		/* first descriptor */

	ATH_DMA_SYNC(bf->bf_dma, DDI_DMA_SYNC_FORDEV);

	mutex_enter(&txq->axq_lock);
	list_insert_tail(&txq->axq_list, bf);
	if (txq->axq_link == NULL) {
		ATH_HAL_PUTTXBUF(ah, txq->axq_qnum, bf->bf_daddr);
	} else {
		*txq->axq_link = bf->bf_daddr;
	}
	txq->axq_link = &ds->ds_link;
	mutex_exit(&txq->axq_lock);

	ATH_HAL_TXSTART(ah, txq->axq_qnum);

	ic->ic_stats.is_tx_frags++;
	ic->ic_stats.is_tx_bytes += pktlen;

	return (0);
}

/*
 * Transmit a management frame.  On failure we reclaim the skbuff.
 * Note that management frames come directly from the 802.11 layer
 * and do not honor the send queue flow control.  Need to investigate
 * using priority queueing so management frames can bypass data.
 */
static int
ath_xmit(ieee80211com_t *ic, mblk_t *mp, uint8_t type)
{
	ath_t *asc = (ath_t *)ic;
	struct ath_hal *ah = asc->asc_ah;
	struct ieee80211_node *in = NULL;
	struct ath_buf *bf = NULL;
	struct ieee80211_frame *wh;
	int error = 0;

	ASSERT(mp->b_next == NULL);

	if (!ATH_IS_RUNNING(asc)) {
		if ((type & IEEE80211_FC0_TYPE_MASK) !=
		    IEEE80211_FC0_TYPE_DATA) {
			freemsg(mp);
		}
		return (ENXIO);
	}

	/* Grab a TX buffer */
	mutex_enter(&asc->asc_txbuflock);
	bf = list_head(&asc->asc_txbuf_list);
	if (bf != NULL)
		list_remove(&asc->asc_txbuf_list, bf);
	if (list_empty(&asc->asc_txbuf_list)) {
		ATH_DEBUG((ATH_DBG_SEND, "ath: ath_mgmt_send(): "
		    "stop queue\n"));
		asc->asc_stats.ast_tx_qstop++;
	}
	mutex_exit(&asc->asc_txbuflock);
	if (bf == NULL) {
		ATH_DEBUG((ATH_DBG_SEND, "ath: ath_mgmt_send(): discard, "
		    "no xmit buf\n"));
		ic->ic_stats.is_tx_nobuf++;
		if ((type & IEEE80211_FC0_TYPE_MASK) ==
		    IEEE80211_FC0_TYPE_DATA) {
			asc->asc_stats.ast_tx_nobuf++;
			mutex_enter(&asc->asc_resched_lock);
			asc->asc_resched_needed = B_TRUE;
			mutex_exit(&asc->asc_resched_lock);
		} else {
			asc->asc_stats.ast_tx_nobufmgt++;
			freemsg(mp);
		}
		return (ENOMEM);
	}

	wh = (struct ieee80211_frame *)mp->b_rptr;

	/* Locate node */
	in = ieee80211_find_txnode(ic,  wh->i_addr1);
	if (in == NULL) {
		error = EIO;
		goto bad;
	}

	in->in_inact = 0;
	switch (type & IEEE80211_FC0_TYPE_MASK) {
	case IEEE80211_FC0_TYPE_DATA:
		(void) ieee80211_encap(ic, mp, in);
		break;
	default:
		if ((wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) ==
		    IEEE80211_FC0_SUBTYPE_PROBE_RESP) {
			/* fill time stamp */
			uint64_t tsf;
			uint32_t *tstamp;

			tsf = ATH_HAL_GETTSF64(ah);
			/* adjust 100us delay to xmit */
			tsf += 100;
			/* LINTED E_BAD_PTR_CAST_ALIGN */
			tstamp = (uint32_t *)&wh[1];
			tstamp[0] = LE_32(tsf & 0xffffffff);
			tstamp[1] = LE_32(tsf >> 32);
		}
		asc->asc_stats.ast_tx_mgmt++;
		break;
	}

	error = ath_tx_start(asc, in, bf, mp);
	if (error != 0) {
bad:
		ic->ic_stats.is_tx_failed++;
		if (bf != NULL) {
			mutex_enter(&asc->asc_txbuflock);
			list_insert_tail(&asc->asc_txbuf_list, bf);
			mutex_exit(&asc->asc_txbuflock);
		}
	}
	if (in != NULL)
		ieee80211_free_node(in);
	if ((type & IEEE80211_FC0_TYPE_MASK) != IEEE80211_FC0_TYPE_DATA ||
	    error == 0) {
		freemsg(mp);
	}

	return (error);
}

static mblk_t *
ath_m_tx(void *arg, mblk_t *mp)
{
	ath_t *asc = arg;
	ieee80211com_t *ic = (ieee80211com_t *)asc;
	mblk_t *next;
	int error = 0;

	/*
	 * No data frames go out unless we're associated; this
	 * should not happen as the 802.11 layer does not enable
	 * the xmit queue until we enter the RUN state.
	 */
	if (ic->ic_state != IEEE80211_S_RUN) {
		ATH_DEBUG((ATH_DBG_SEND, "ath: ath_m_tx(): "
		    "discard, state %u\n", ic->ic_state));
		asc->asc_stats.ast_tx_discard++;
		freemsgchain(mp);
		return (NULL);
	}

	while (mp != NULL) {
		next = mp->b_next;
		mp->b_next = NULL;
		error = ath_xmit(ic, mp, IEEE80211_FC0_TYPE_DATA);
		if (error != 0) {
			mp->b_next = next;
			if (error == ENOMEM) {
				break;
			} else {
				freemsgchain(mp);	/* CR6501759 issues */
				return (NULL);
			}
		}
		mp = next;
	}

	return (mp);
}

static int
ath_tx_processq(ath_t *asc, struct ath_txq *txq)
{
	ieee80211com_t *ic = (ieee80211com_t *)asc;
	struct ath_hal *ah = asc->asc_ah;
	struct ath_buf *bf;
	struct ath_desc *ds;
	struct ieee80211_node *in;
	int32_t sr, lr, nacked = 0;
	struct ath_tx_status *ts;
	HAL_STATUS status;
	struct ath_node *an;

	for (;;) {
		mutex_enter(&txq->axq_lock);
		bf = list_head(&txq->axq_list);
		if (bf == NULL) {
			txq->axq_link = NULL;
			mutex_exit(&txq->axq_lock);
			break;
		}
		ds = bf->bf_desc;	/* last decriptor */
		ts = &bf->bf_status.ds_txstat;
		status = ATH_HAL_TXPROCDESC(ah, ds, ts);
#ifdef DEBUG
		ath_printtxbuf(bf, status == HAL_OK);
#endif
		if (status == HAL_EINPROGRESS) {
			mutex_exit(&txq->axq_lock);
			break;
		}
		list_remove(&txq->axq_list, bf);
		mutex_exit(&txq->axq_lock);
		in = bf->bf_in;
		if (in != NULL) {
			an = ATH_NODE(in);
			/* Successful transmition */
			if (ts->ts_status == 0) {
				an->an_tx_ok++;
				an->an_tx_antenna = ts->ts_antenna;
				if (ts->ts_rate & HAL_TXSTAT_ALTRATE)
					asc->asc_stats.ast_tx_altrate++;
				asc->asc_stats.ast_tx_rssidelta =
				    ts->ts_rssi - asc->asc_stats.ast_tx_rssi;
				asc->asc_stats.ast_tx_rssi = ts->ts_rssi;
			} else {
				an->an_tx_err++;
				if (ts->ts_status & HAL_TXERR_XRETRY)
					asc->asc_stats.ast_tx_xretries++;
				if (ts->ts_status & HAL_TXERR_FIFO)
					asc->asc_stats.ast_tx_fifoerr++;
				if (ts->ts_status & HAL_TXERR_FILT)
					asc->asc_stats.ast_tx_filtered++;
				an->an_tx_antenna = 0;	/* invalidate */
			}
			sr = ts->ts_shortretry;
			lr = ts->ts_longretry;
			asc->asc_stats.ast_tx_shortretry += sr;
			asc->asc_stats.ast_tx_longretry += lr;
			/*
			 * Hand the descriptor to the rate control algorithm.
			 */
			if ((ts->ts_status & HAL_TXERR_FILT) == 0 &&
			    (bf->bf_flags & HAL_TXDESC_NOACK) == 0) {
				/*
				 * If frame was ack'd update the last rx time
				 * used to workaround phantom bmiss interrupts.
				 */
				if (ts->ts_status == 0) {
					nacked++;
					an->an_tx_ok++;
				} else {
					an->an_tx_err++;
				}
				an->an_tx_retr += sr + lr;
			}
		}
		bf->bf_in = NULL;
		mutex_enter(&asc->asc_txbuflock);
		list_insert_tail(&asc->asc_txbuf_list, bf);
		mutex_exit(&asc->asc_txbuflock);
		/*
		 * Reschedule stalled outbound packets
		 */
		mutex_enter(&asc->asc_resched_lock);
		if (asc->asc_resched_needed) {
			asc->asc_resched_needed = B_FALSE;
			mac_tx_update(ic->ic_mach);
		}
		mutex_exit(&asc->asc_resched_lock);
	}
	return (nacked);
}


static void
ath_tx_handler(ath_t *asc)
{
	int i;

	/*
	 * Process each active queue.
	 */
	for (i = 0; i < HAL_NUM_TX_QUEUES; i++) {
		if (ATH_TXQ_SETUP(asc, i)) {
			(void) ath_tx_processq(asc, &asc->asc_txq[i]);
		}
	}
}

static struct ieee80211_node *
ath_node_alloc(ieee80211com_t *ic)
{
	struct ath_node *an;
	ath_t *asc = (ath_t *)ic;

	an = kmem_zalloc(sizeof (struct ath_node), KM_SLEEP);
	ath_rate_update(asc, &an->an_node, 0);
	return (&an->an_node);
}

static void
ath_node_free(struct ieee80211_node *in)
{
	ieee80211com_t *ic = in->in_ic;
	ath_t *asc = (ath_t *)ic;
	struct ath_buf *bf;
	struct ath_txq *txq;
	int32_t i;

	for (i = 0; i < HAL_NUM_TX_QUEUES; i++) {
		if (ATH_TXQ_SETUP(asc, i)) {
			txq = &asc->asc_txq[i];
			mutex_enter(&txq->axq_lock);
			bf = list_head(&txq->axq_list);
			while (bf != NULL) {
				if (bf->bf_in == in) {
					bf->bf_in = NULL;
				}
				bf = list_next(&txq->axq_list, bf);
			}
			mutex_exit(&txq->axq_lock);
		}
	}
	ic->ic_node_cleanup(in);
	if (in->in_wpa_ie != NULL)
		ieee80211_free(in->in_wpa_ie);
	kmem_free(in, sizeof (struct ath_node));
}

static void
ath_next_scan(void *arg)
{
	ieee80211com_t *ic = arg;
	ath_t *asc = (ath_t *)ic;

	asc->asc_scan_timer = 0;
	if (ic->ic_state == IEEE80211_S_SCAN) {
		asc->asc_scan_timer = timeout(ath_next_scan, (void *)asc,
		    drv_usectohz(ath_dwelltime * 1000));
		ieee80211_next_scan(ic);
	}
}

static void
ath_stop_scantimer(ath_t *asc)
{
	timeout_id_t tmp_id = 0;

	while ((asc->asc_scan_timer != 0) && (tmp_id != asc->asc_scan_timer)) {
		tmp_id = asc->asc_scan_timer;
		(void) untimeout(tmp_id);
	}
	asc->asc_scan_timer = 0;
}

static int32_t
ath_newstate(ieee80211com_t *ic, enum ieee80211_state nstate, int arg)
{
	ath_t *asc = (ath_t *)ic;
	struct ath_hal *ah = asc->asc_ah;
	struct ieee80211_node *in;
	int32_t i, error;
	uint8_t *bssid;
	uint32_t rfilt;
	enum ieee80211_state ostate;

	static const HAL_LED_STATE leds[] = {
	    HAL_LED_INIT,	/* IEEE80211_S_INIT */
	    HAL_LED_SCAN,	/* IEEE80211_S_SCAN */
	    HAL_LED_AUTH,	/* IEEE80211_S_AUTH */
	    HAL_LED_ASSOC,	/* IEEE80211_S_ASSOC */
	    HAL_LED_RUN,	/* IEEE80211_S_RUN */
	};
	if (!ATH_IS_RUNNING(asc))
		return (0);

	ostate = ic->ic_state;
	if (nstate != IEEE80211_S_SCAN)
		ath_stop_scantimer(asc);

	ATH_LOCK(asc);
	ATH_HAL_SETLEDSTATE(ah, leds[nstate]);	/* set LED */

	if (nstate == IEEE80211_S_INIT) {
		asc->asc_imask &= ~(HAL_INT_SWBA | HAL_INT_BMISS);
		/*
		 * Disable interrupts.
		 */
		ATH_HAL_INTRSET(ah, asc->asc_imask &~ HAL_INT_GLOBAL);
		ATH_UNLOCK(asc);
		goto done;
	}
	in = ic->ic_bss;
	error = ath_chan_set(asc, ic->ic_curchan);
	if (error != 0) {
		if (nstate != IEEE80211_S_SCAN) {
			ATH_UNLOCK(asc);
			ieee80211_reset_chan(ic);
			goto bad;
		}
	}

	rfilt = ath_calcrxfilter(asc);

	if (nstate == IEEE80211_S_SCAN)
		bssid = ic->ic_macaddr;
	else
		bssid = in->in_bssid;
	ATH_HAL_SETRXFILTER(ah, rfilt);

	if (nstate == IEEE80211_S_RUN && ic->ic_opmode != IEEE80211_M_IBSS)
		ATH_HAL_SETASSOCID(ah, bssid, in->in_associd);
	else
		ATH_HAL_SETASSOCID(ah, bssid, 0);
	if (ic->ic_flags & IEEE80211_F_PRIVACY) {
		for (i = 0; i < IEEE80211_WEP_NKID; i++) {
			if (ATH_HAL_KEYISVALID(ah, i))
				ATH_HAL_KEYSETMAC(ah, i, bssid);
		}
	}

	if ((nstate == IEEE80211_S_RUN) &&
	    (ostate != IEEE80211_S_RUN)) {
		/* Configure the beacon and sleep timers. */
		ath_beacon_config(asc);
	} else {
		asc->asc_imask &= ~(HAL_INT_SWBA | HAL_INT_BMISS);
		ATH_HAL_INTRSET(ah, asc->asc_imask);
	}
	/*
	 * Reset the rate control state.
	 */
	ath_rate_ctl_reset(asc, nstate);

	ATH_UNLOCK(asc);
done:
	/*
	 * Invoke the parent method to complete the work.
	 */
	error = asc->asc_newstate(ic, nstate, arg);
	/*
	 * Finally, start any timers.
	 */
	if (nstate == IEEE80211_S_RUN) {
		ieee80211_start_watchdog(ic, 1);
	} else if ((nstate == IEEE80211_S_SCAN) && (ostate != nstate)) {
		/* start ap/neighbor scan timer */
		ASSERT(asc->asc_scan_timer == 0);
		asc->asc_scan_timer = timeout(ath_next_scan, (void *)asc,
		    drv_usectohz(ath_dwelltime * 1000));
	}
bad:
	return (error);
}

/*
 * Periodically recalibrate the PHY to account
 * for temperature/environment changes.
 */
static void
ath_calibrate(ath_t *asc)
{
	struct ath_hal *ah = asc->asc_ah;
	HAL_BOOL iqcaldone;

	asc->asc_stats.ast_per_cal++;

	if (ATH_HAL_GETRFGAIN(ah) == HAL_RFGAIN_NEED_CHANGE) {
		/*
		 * Rfgain is out of bounds, reset the chip
		 * to load new gain values.
		 */
		ATH_DEBUG((ATH_DBG_HAL, "ath: ath_calibrate(): "
		    "Need change RFgain\n"));
		asc->asc_stats.ast_per_rfgain++;
		(void) ath_reset(&asc->asc_isc);
	}
	if (!ATH_HAL_CALIBRATE(ah, &asc->asc_curchan, &iqcaldone)) {
		ATH_DEBUG((ATH_DBG_HAL, "ath: ath_calibrate(): "
		    "calibration of channel %u failed\n",
		    asc->asc_curchan.channel));
		asc->asc_stats.ast_per_calfail++;
	}
}

static void
ath_watchdog(void *arg)
{
	ath_t *asc = arg;
	ieee80211com_t *ic = &asc->asc_isc;
	int ntimer = 0;

	ATH_LOCK(asc);
	ic->ic_watchdog_timer = 0;
	if (!ATH_IS_RUNNING(asc)) {
		ATH_UNLOCK(asc);
		return;
	}

	if (ic->ic_state == IEEE80211_S_RUN) {
		/* periodic recalibration */
		ath_calibrate(asc);

		/*
		 * Start the background rate control thread if we
		 * are not configured to use a fixed xmit rate.
		 */
		if (ic->ic_fixed_rate == IEEE80211_FIXED_RATE_NONE) {
			asc->asc_stats.ast_rate_calls ++;
			if (ic->ic_opmode == IEEE80211_M_STA)
				ath_rate_ctl(ic, ic->ic_bss);
			else
				ieee80211_iterate_nodes(&ic->ic_sta,
				    ath_rate_ctl, asc);
		}

		ntimer = 1;
	}
	ATH_UNLOCK(asc);

	ieee80211_watchdog(ic);
	if (ntimer != 0)
		ieee80211_start_watchdog(ic, ntimer);
}

static void
ath_tx_proc(void *arg)
{
	ath_t *asc = arg;
	ath_tx_handler(asc);
}


static uint_t
ath_intr(caddr_t arg)
{
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	ath_t *asc = (ath_t *)arg;
	struct ath_hal *ah = asc->asc_ah;
	HAL_INT status;
	ieee80211com_t *ic = (ieee80211com_t *)asc;

	ATH_LOCK(asc);

	if (!ATH_IS_RUNNING(asc)) {
		/*
		 * The hardware is not ready/present, don't touch anything.
		 * Note this can happen early on if the IRQ is shared.
		 */
		ATH_UNLOCK(asc);
		return (DDI_INTR_UNCLAIMED);
	}

	if (!ATH_HAL_INTRPEND(ah)) {	/* shared irq, not for us */
		ATH_UNLOCK(asc);
		return (DDI_INTR_UNCLAIMED);
	}

	ATH_HAL_GETISR(ah, &status);
	status &= asc->asc_imask;
	if (status & HAL_INT_FATAL) {
		asc->asc_stats.ast_hardware++;
		goto reset;
	} else if (status & HAL_INT_RXORN) {
		asc->asc_stats.ast_rxorn++;
		goto reset;
	} else {
		if (status & HAL_INT_RXEOL) {
			asc->asc_stats.ast_rxeol++;
			asc->asc_rxlink = NULL;
		}
		if (status & HAL_INT_TXURN) {
			asc->asc_stats.ast_txurn++;
			ATH_HAL_UPDATETXTRIGLEVEL(ah, AH_TRUE);
		}

		if (status & HAL_INT_RX) {
			asc->asc_rx_pend = 1;
			ddi_trigger_softintr(asc->asc_softint_id);
		}
		if (status & HAL_INT_TX) {
			if (ddi_taskq_dispatch(asc->asc_tq, ath_tx_proc,
			    asc, DDI_NOSLEEP) != DDI_SUCCESS) {
				ath_problem("ath: ath_intr(): "
				    "No memory available for tx taskq\n");
			}
		}
		ATH_UNLOCK(asc);

		if (status & HAL_INT_SWBA) {
			/* This will occur only in Host-AP or Ad-Hoc mode */
			return (DDI_INTR_CLAIMED);
		}

		if (status & HAL_INT_BMISS) {
			if (ic->ic_state == IEEE80211_S_RUN) {
				(void) ieee80211_new_state(ic,
				    IEEE80211_S_ASSOC, -1);
			}
		}

	}

	return (DDI_INTR_CLAIMED);
reset:
	(void) ath_reset(ic);
	ATH_UNLOCK(asc);
	return (DDI_INTR_CLAIMED);
}

static uint_t
ath_softint_handler(caddr_t data)
{
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	ath_t *asc = (ath_t *)data;

	/*
	 * Check if the soft interrupt is triggered by another
	 * driver at the same level.
	 */
	ATH_LOCK(asc);
	if (asc->asc_rx_pend) { /* Soft interrupt for this driver */
		asc->asc_rx_pend = 0;
		ATH_UNLOCK(asc);
		ath_rx_handler(asc);
		return (DDI_INTR_CLAIMED);
	}
	ATH_UNLOCK(asc);
	return (DDI_INTR_UNCLAIMED);
}

/*
 * following are gld callback routine
 * ath_gld_send, ath_gld_ioctl, ath_gld_gstat
 * are listed in other corresponding sections.
 * reset the hardware w/o losing operational state.  this is
 * basically a more efficient way of doing ath_gld_stop, ath_gld_start,
 * followed by state transitions to the current 802.11
 * operational state.  used to recover from errors rx overrun
 * and to reset the hardware when rf gain settings must be reset.
 */

static void
ath_stop_locked(ath_t *asc)
{
	ieee80211com_t *ic = (ieee80211com_t *)asc;
	struct ath_hal *ah = asc->asc_ah;

	ATH_LOCK_ASSERT(asc);
	if (!asc->asc_isrunning)
		return;

	/*
	 * Shutdown the hardware and driver:
	 *    reset 802.11 state machine
	 *    turn off timers
	 *    disable interrupts
	 *    turn off the radio
	 *    clear transmit machinery
	 *    clear receive machinery
	 *    drain and release tx queues
	 *    reclaim beacon resources
	 *    power down hardware
	 *
	 * Note that some of this work is not possible if the
	 * hardware is gone (invalid).
	 */
	ATH_UNLOCK(asc);
	ieee80211_new_state(ic, IEEE80211_S_INIT, -1);
	ieee80211_stop_watchdog(ic);
	ATH_LOCK(asc);
	ATH_HAL_INTRSET(ah, 0);
	ath_draintxq(asc);
	if (!asc->asc_invalid) {
		ath_stoprecv(asc);
		ATH_HAL_PHYDISABLE(ah);
	} else {
		asc->asc_rxlink = NULL;
	}
	asc->asc_isrunning = 0;
}

static void
ath_m_stop(void *arg)
{
	ath_t *asc = arg;
	struct ath_hal *ah = asc->asc_ah;

	ATH_LOCK(asc);
	ath_stop_locked(asc);
	ATH_HAL_SETPOWER(ah, HAL_PM_AWAKE);
	asc->asc_invalid = 1;
	ATH_UNLOCK(asc);
}

static int
ath_start_locked(ath_t *asc)
{
	ieee80211com_t *ic = (ieee80211com_t *)asc;
	struct ath_hal *ah = asc->asc_ah;
	HAL_STATUS status;

	ATH_LOCK_ASSERT(asc);

	/*
	 * The basic interface to setting the hardware in a good
	 * state is ``reset''.  On return the hardware is known to
	 * be powered up and with interrupts disabled.  This must
	 * be followed by initialization of the appropriate bits
	 * and then setup of the interrupt mask.
	 */
	asc->asc_curchan.channel = ic->ic_curchan->ich_freq;
	asc->asc_curchan.channelFlags = ath_chan2flags(ic, ic->ic_curchan);
	if (!ATH_HAL_RESET(ah, (HAL_OPMODE)ic->ic_opmode,
	    &asc->asc_curchan, AH_FALSE, &status)) {
		ATH_DEBUG((ATH_DBG_HAL, "ath: ath_m_start(): "
		    "reset hardware failed: '%s' (HAL status %u)\n",
		    ath_get_hal_status_desc(status), status));
		return (ENOTACTIVE);
	}

	(void) ath_startrecv(asc);

	/*
	 * Enable interrupts.
	 */
	asc->asc_imask = HAL_INT_RX | HAL_INT_TX
	    | HAL_INT_RXEOL | HAL_INT_RXORN
	    | HAL_INT_FATAL | HAL_INT_GLOBAL;
	ATH_HAL_INTRSET(ah, asc->asc_imask);

	/*
	 * The hardware should be ready to go now so it's safe
	 * to kick the 802.11 state machine as it's likely to
	 * immediately call back to us to send mgmt frames.
	 */
	ath_chan_change(asc, ic->ic_curchan);

	asc->asc_isrunning = 1;

	return (0);
}

int
ath_m_start(void *arg)
{
	ath_t *asc = arg;
	int err;

	ATH_LOCK(asc);
	/*
	 * Stop anything previously setup.  This is safe
	 * whether this is the first time through or not.
	 */
	ath_stop_locked(asc);

	if ((err = ath_start_locked(asc)) != 0) {
		ATH_UNLOCK(asc);
		return (err);
	}

	asc->asc_invalid = 0;
	ATH_UNLOCK(asc);

	return (0);
}


static int
ath_m_unicst(void *arg, const uint8_t *macaddr)
{
	ath_t *asc = arg;
	struct ath_hal *ah = asc->asc_ah;

	ATH_DEBUG((ATH_DBG_GLD, "ath: ath_gld_saddr(): "
	    "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
	    macaddr[0], macaddr[1], macaddr[2],
	    macaddr[3], macaddr[4], macaddr[5]));

	ATH_LOCK(asc);
	IEEE80211_ADDR_COPY(asc->asc_isc.ic_macaddr, macaddr);
	ATH_HAL_SETMAC(ah, asc->asc_isc.ic_macaddr);

	(void) ath_reset(&asc->asc_isc);
	ATH_UNLOCK(asc);
	return (0);
}

static int
ath_m_promisc(void *arg, boolean_t on)
{
	ath_t *asc = arg;
	struct ath_hal *ah = asc->asc_ah;
	uint32_t rfilt;

	ATH_LOCK(asc);
	rfilt = ATH_HAL_GETRXFILTER(ah);
	if (on)
		rfilt |= HAL_RX_FILTER_PROM;
	else
		rfilt &= ~HAL_RX_FILTER_PROM;
	asc->asc_promisc = on;
	ATH_HAL_SETRXFILTER(ah, rfilt);
	ATH_UNLOCK(asc);

	return (0);
}

static int
ath_m_multicst(void *arg, boolean_t add, const uint8_t *mca)
{
	ath_t *asc = arg;
	struct ath_hal *ah = asc->asc_ah;
	uint32_t val, index, bit;
	uint8_t pos;
	uint32_t *mfilt = asc->asc_mcast_hash;

	ATH_LOCK(asc);

	/* calculate XOR of eight 6bit values */
	val = ATH_LE_READ_4(mca + 0);
	pos = (val >> 18) ^ (val >> 12) ^ (val >> 6) ^ val;
	val = ATH_LE_READ_4(mca + 3);
	pos ^= (val >> 18) ^ (val >> 12) ^ (val >> 6) ^ val;
	pos &= 0x3f;
	index = pos / 32;
	bit = 1 << (pos % 32);

	if (add) {	/* enable multicast */
		asc->asc_mcast_refs[pos]++;
		mfilt[index] |= bit;
	} else {	/* disable multicast */
		if (--asc->asc_mcast_refs[pos] == 0)
			mfilt[index] &= ~bit;
	}
	ATH_HAL_SETMCASTFILTER(ah, mfilt[0], mfilt[1]);

	ATH_UNLOCK(asc);
	return (0);
}
/*
 * callback functions for /get/set properties
 */
static int
ath_m_setprop(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    uint_t wldp_length, const void *wldp_buf)
{
	ath_t	*asc = arg;
	int	err;

	err = ieee80211_setprop(&asc->asc_isc, pr_name, wldp_pr_num,
	    wldp_length, wldp_buf);

	ATH_LOCK(asc);

	if (err == ENETRESET) {
		if (ATH_IS_RUNNING(asc)) {
			ATH_UNLOCK(asc);
			(void) ath_m_start(asc);
			(void) ieee80211_new_state(&asc->asc_isc,
			    IEEE80211_S_SCAN, -1);
			ATH_LOCK(asc);
		}
		err = 0;
	}

	ATH_UNLOCK(asc);

	return (err);
}

static int
ath_m_getprop(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    uint_t wldp_length, void *wldp_buf)
{
	ath_t	*asc = arg;
	int	err = 0;

	err = ieee80211_getprop(&asc->asc_isc, pr_name, wldp_pr_num,
	    wldp_length, wldp_buf);

	return (err);
}

static void
ath_m_propinfo(void *arg, const char *pr_name, mac_prop_id_t wldp_pr_num,
    mac_prop_info_handle_t mph)
{
	ath_t	*asc = arg;

	ieee80211_propinfo(&asc->asc_isc, pr_name, wldp_pr_num, mph);
}

static void
ath_m_ioctl(void *arg, queue_t *wq, mblk_t *mp)
{
	ath_t *asc = arg;
	int32_t err;

	err = ieee80211_ioctl(&asc->asc_isc, wq, mp);
	ATH_LOCK(asc);
	if (err == ENETRESET) {
		if (ATH_IS_RUNNING(asc)) {
			ATH_UNLOCK(asc);
			(void) ath_m_start(asc);
			(void) ieee80211_new_state(&asc->asc_isc,
			    IEEE80211_S_SCAN, -1);
			ATH_LOCK(asc);
		}
	}
	ATH_UNLOCK(asc);
}

static int
ath_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	ath_t *asc = arg;
	ieee80211com_t *ic = (ieee80211com_t *)asc;
	struct ieee80211_node *in = ic->ic_bss;
	struct ieee80211_rateset *rs = &in->in_rates;

	ATH_LOCK(asc);
	switch (stat) {
	case MAC_STAT_IFSPEED:
		*val = (rs->ir_rates[in->in_txrate] & IEEE80211_RATE_VAL) / 2 *
		    1000000ull;
		break;
	case MAC_STAT_NOXMTBUF:
		*val = asc->asc_stats.ast_tx_nobuf +
		    asc->asc_stats.ast_tx_nobufmgt;
		break;
	case MAC_STAT_IERRORS:
		*val = asc->asc_stats.ast_rx_tooshort;
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
		*val = asc->asc_stats.ast_tx_fifoerr +
		    asc->asc_stats.ast_tx_xretries +
		    asc->asc_stats.ast_tx_discard;
		break;
	case WIFI_STAT_TX_RETRANS:
		*val = asc->asc_stats.ast_tx_xretries;
		break;
	case WIFI_STAT_FCS_ERRORS:
		*val = asc->asc_stats.ast_rx_crcerr;
		break;
	case WIFI_STAT_WEP_ERRORS:
		*val = asc->asc_stats.ast_rx_badcrypt;
		break;
	case WIFI_STAT_TX_FRAGS:
	case WIFI_STAT_MCAST_TX:
	case WIFI_STAT_RTS_SUCCESS:
	case WIFI_STAT_RTS_FAILURE:
	case WIFI_STAT_ACK_FAILURE:
	case WIFI_STAT_RX_FRAGS:
	case WIFI_STAT_MCAST_RX:
	case WIFI_STAT_RX_DUPS:
		ATH_UNLOCK(asc);
		return (ieee80211_stat(ic, stat, val));
	default:
		ATH_UNLOCK(asc);
		return (ENOTSUP);
	}
	ATH_UNLOCK(asc);

	return (0);
}

static int
ath_pci_setup(ath_t *asc)
{
	uint16_t command;

	/*
	 * Enable memory mapping and bus mastering
	 */
	ASSERT(asc != NULL);
	command = pci_config_get16(asc->asc_cfg_handle, PCI_CONF_COMM);
	command |= PCI_COMM_MAE | PCI_COMM_ME;
	pci_config_put16(asc->asc_cfg_handle, PCI_CONF_COMM, command);
	command = pci_config_get16(asc->asc_cfg_handle, PCI_CONF_COMM);
	if ((command & PCI_COMM_MAE) == 0) {
		ath_problem("ath: ath_pci_setup(): "
		    "failed to enable memory mapping\n");
		return (EIO);
	}
	if ((command & PCI_COMM_ME) == 0) {
		ath_problem("ath: ath_pci_setup(): "
		    "failed to enable bus mastering\n");
		return (EIO);
	}
	ATH_DEBUG((ATH_DBG_INIT, "ath: ath_pci_setup(): "
	    "set command reg to 0x%x \n", command));

	return (0);
}

static int
ath_resume(dev_info_t *devinfo)
{
	ath_t *asc;
	int ret = DDI_SUCCESS;

	asc = ddi_get_soft_state(ath_soft_state_p, ddi_get_instance(devinfo));
	if (asc == NULL) {
		ATH_DEBUG((ATH_DBG_SUSPEND, "ath: ath_resume(): "
		    "failed to get soft state\n"));
		return (DDI_FAILURE);
	}

	ATH_LOCK(asc);
	/*
	 * Set up config space command register(s). Refuse
	 * to resume on failure.
	 */
	if (ath_pci_setup(asc) != 0) {
		ATH_DEBUG((ATH_DBG_SUSPEND, "ath: ath_resume(): "
		    "ath_pci_setup() failed\n"));
		ATH_UNLOCK(asc);
		return (DDI_FAILURE);
	}

	if (!asc->asc_invalid)
		ret = ath_start_locked(asc);
	ATH_UNLOCK(asc);

	return (ret);
}

static int
ath_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	ath_t *asc;
	ieee80211com_t *ic;
	struct ath_hal *ah;
	uint8_t csz;
	HAL_STATUS status;
	caddr_t regs;
	uint32_t i, val;
	uint16_t vendor_id, device_id;
	const char *athname;
	int32_t ath_countrycode = CTRY_DEFAULT;	/* country code */
	int32_t err, ath_regdomain = 0; /* regulatory domain */
	char strbuf[32];
	int instance;
	wifi_data_t wd = { 0 };
	mac_register_t *macp;

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		return (ath_resume(devinfo));

	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(devinfo);
	if (ddi_soft_state_zalloc(ath_soft_state_p, instance) != DDI_SUCCESS) {
		ATH_DEBUG((ATH_DBG_ATTACH, "ath: ath_attach(): "
		    "Unable to alloc softstate\n"));
		return (DDI_FAILURE);
	}

	asc = ddi_get_soft_state(ath_soft_state_p, ddi_get_instance(devinfo));
	ic = (ieee80211com_t *)asc;
	asc->asc_dev = devinfo;

	mutex_init(&asc->asc_genlock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&asc->asc_txbuflock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&asc->asc_rxbuflock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&asc->asc_resched_lock, NULL, MUTEX_DRIVER, NULL);

	err = pci_config_setup(devinfo, &asc->asc_cfg_handle);
	if (err != DDI_SUCCESS) {
		ATH_DEBUG((ATH_DBG_ATTACH, "ath: ath_attach(): "
		    "pci_config_setup() failed"));
		goto attach_fail0;
	}

	if (ath_pci_setup(asc) != 0)
		goto attach_fail1;

	/*
	 * Cache line size is used to size and align various
	 * structures used to communicate with the hardware.
	 */
	csz = pci_config_get8(asc->asc_cfg_handle, PCI_CONF_CACHE_LINESZ);
	if (csz == 0) {
		/*
		 * We must have this setup properly for rx buffer
		 * DMA to work so force a reasonable value here if it
		 * comes up zero.
		 */
		csz = ATH_DEF_CACHE_BYTES / sizeof (uint32_t);
		pci_config_put8(asc->asc_cfg_handle, PCI_CONF_CACHE_LINESZ,
		    csz);
	}
	asc->asc_cachelsz = csz << 2;
	vendor_id = pci_config_get16(asc->asc_cfg_handle, PCI_CONF_VENID);
	device_id = pci_config_get16(asc->asc_cfg_handle, PCI_CONF_DEVID);
	ATH_DEBUG((ATH_DBG_ATTACH, "ath: ath_attach(): vendor 0x%x, "
	    "device id 0x%x, cache size %d\n", vendor_id, device_id, csz));

	athname = ath_hal_probe(vendor_id, device_id);
	ATH_DEBUG((ATH_DBG_ATTACH, "ath: ath_attach(): athname: %s\n",
	    athname ? athname : "Atheros ???"));

	pci_config_put8(asc->asc_cfg_handle, PCI_CONF_LATENCY_TIMER, 0xa8);
	val = pci_config_get32(asc->asc_cfg_handle, 0x40);
	if ((val & 0x0000ff00) != 0)
		pci_config_put32(asc->asc_cfg_handle, 0x40, val & 0xffff00ff);

	err = ddi_regs_map_setup(devinfo, 1,
	    &regs, 0, 0, &ath_reg_accattr, &asc->asc_io_handle);
	ATH_DEBUG((ATH_DBG_ATTACH, "ath: ath_attach(): "
	    "regs map1 = %x err=%d\n", regs, err));
	if (err != DDI_SUCCESS) {
		ATH_DEBUG((ATH_DBG_ATTACH, "ath: ath_attach(): "
		    "ddi_regs_map_setup() failed"));
		goto attach_fail1;
	}

	ah = ath_hal_attach(device_id, asc, 0, regs, &status);
	if (ah == NULL) {
		ATH_DEBUG((ATH_DBG_ATTACH, "ath: ath_attach(): "
		    "unable to attach hw: '%s' (HAL status %u)\n",
		    ath_get_hal_status_desc(status), status));
		goto attach_fail2;
	}
	ATH_DEBUG((ATH_DBG_ATTACH, "mac %d.%d phy %d.%d",
	    ah->ah_macVersion, ah->ah_macRev,
	    ah->ah_phyRev >> 4, ah->ah_phyRev & 0xf));
	ATH_HAL_INTRSET(ah, 0);
	asc->asc_ah = ah;

	if (ah->ah_abi != HAL_ABI_VERSION) {
		ATH_DEBUG((ATH_DBG_ATTACH, "ath: ath_attach(): "
		    "HAL ABI mismatch detected (0x%x != 0x%x)\n",
		    ah->ah_abi, HAL_ABI_VERSION));
		goto attach_fail3;
	}

	ATH_DEBUG((ATH_DBG_ATTACH, "ath: ath_attach(): "
	    "HAL ABI version 0x%x\n", ah->ah_abi));
	ATH_DEBUG((ATH_DBG_ATTACH, "ath: ath_attach(): "
	    "HAL mac version %d.%d, phy version %d.%d\n",
	    ah->ah_macVersion, ah->ah_macRev,
	    ah->ah_phyRev >> 4, ah->ah_phyRev & 0xf));
	if (ah->ah_analog5GhzRev)
		ATH_DEBUG((ATH_DBG_ATTACH, "ath: ath_attach(): "
		    "HAL 5ghz radio version %d.%d\n",
		    ah->ah_analog5GhzRev >> 4,
		    ah->ah_analog5GhzRev & 0xf));
	if (ah->ah_analog2GhzRev)
		ATH_DEBUG((ATH_DBG_ATTACH, "ath: ath_attach(): "
		    "HAL 2ghz radio version %d.%d\n",
		    ah->ah_analog2GhzRev >> 4,
		    ah->ah_analog2GhzRev & 0xf));

	/*
	 * Check if the MAC has multi-rate retry support.
	 * We do this by trying to setup a fake extended
	 * descriptor.  MAC's that don't have support will
	 * return false w/o doing anything.  MAC's that do
	 * support it will return true w/o doing anything.
	 */
	asc->asc_mrretry = ATH_HAL_SETUPXTXDESC(ah, NULL, 0, 0, 0, 0, 0, 0);
	ATH_DEBUG((ATH_DBG_ATTACH, "ath: ath_attach(): "
	    "multi rate retry support=%x\n",
	    asc->asc_mrretry));

	/*
	 * Get the hardware key cache size.
	 */
	asc->asc_keymax = ATH_HAL_KEYCACHESIZE(ah);
	if (asc->asc_keymax > sizeof (asc->asc_keymap) * NBBY) {
		ATH_DEBUG((ATH_DBG_ATTACH, "ath_attach:"
		    " Warning, using only %u entries in %u key cache\n",
		    sizeof (asc->asc_keymap) * NBBY, asc->asc_keymax));
		asc->asc_keymax = sizeof (asc->asc_keymap) * NBBY;
	}
	/*
	 * Reset the key cache since some parts do not
	 * reset the contents on initial power up.
	 */
	for (i = 0; i < asc->asc_keymax; i++)
		ATH_HAL_KEYRESET(ah, i);

	ATH_HAL_GETREGDOMAIN(ah, (uint32_t *)&ath_regdomain);
	ATH_HAL_GETCOUNTRYCODE(ah, &ath_countrycode);
	/*
	 * Collect the channel list using the default country
	 * code and including outdoor channels.  The 802.11 layer
	 * is resposible for filtering this list to a set of
	 * channels that it considers ok to use.
	 */
	asc->asc_have11g = 0;

	/* enable outdoor use, enable extended channels */
	err = ath_getchannels(asc, ath_countrycode, AH_FALSE, AH_TRUE);
	if (err != 0)
		goto attach_fail3;

	/*
	 * Setup rate tables for all potential media types.
	 */
	ath_rate_setup(asc, IEEE80211_MODE_11A);
	ath_rate_setup(asc, IEEE80211_MODE_11B);
	ath_rate_setup(asc, IEEE80211_MODE_11G);
	ath_rate_setup(asc, IEEE80211_MODE_TURBO_A);

	/* Setup here so ath_rate_update is happy */
	ath_setcurmode(asc, IEEE80211_MODE_11A);

	err = ath_desc_alloc(devinfo, asc);
	if (err != DDI_SUCCESS) {
		ATH_DEBUG((ATH_DBG_ATTACH, "ath: ath_attach(): "
		    "failed to allocate descriptors: %d\n", err));
		goto attach_fail3;
	}

	if ((asc->asc_tq = ddi_taskq_create(devinfo, "ath_taskq", 1,
	    TASKQ_DEFAULTPRI, 0)) == NULL) {
		goto attach_fail4;
	}
	/* Setup transmit queues in the HAL */
	if (ath_txq_setup(asc))
		goto attach_fail4;

	ATH_HAL_GETMAC(ah, ic->ic_macaddr);

	/*
	 * Initialize pointers to device specific functions which
	 * will be used by the generic layer.
	 */
	/* 11g support is identified when we fetch the channel set */
	if (asc->asc_have11g)
		ic->ic_caps |= IEEE80211_C_SHPREAMBLE |
		    IEEE80211_C_SHSLOT;		/* short slot time */
	/*
	 * Query the hal to figure out h/w crypto support.
	 */
	if (ATH_HAL_CIPHERSUPPORTED(ah, HAL_CIPHER_WEP))
		ic->ic_caps |= IEEE80211_C_WEP;
	if (ATH_HAL_CIPHERSUPPORTED(ah, HAL_CIPHER_AES_OCB))
		ic->ic_caps |= IEEE80211_C_AES;
	if (ATH_HAL_CIPHERSUPPORTED(ah, HAL_CIPHER_AES_CCM)) {
		ATH_DEBUG((ATH_DBG_ATTACH, "Atheros support H/W CCMP\n"));
		ic->ic_caps |= IEEE80211_C_AES_CCM;
	}
	if (ATH_HAL_CIPHERSUPPORTED(ah, HAL_CIPHER_CKIP))
		ic->ic_caps |= IEEE80211_C_CKIP;
	if (ATH_HAL_CIPHERSUPPORTED(ah, HAL_CIPHER_TKIP)) {
		ATH_DEBUG((ATH_DBG_ATTACH, "Atheros support H/W TKIP\n"));
		ic->ic_caps |= IEEE80211_C_TKIP;
		/*
		 * Check if h/w does the MIC and/or whether the
		 * separate key cache entries are required to
		 * handle both tx+rx MIC keys.
		 */
		if (ATH_HAL_CIPHERSUPPORTED(ah, HAL_CIPHER_MIC)) {
			ATH_DEBUG((ATH_DBG_ATTACH, "Support H/W TKIP MIC\n"));
			ic->ic_caps |= IEEE80211_C_TKIPMIC;
		}

		/*
		 * If the h/w supports storing tx+rx MIC keys
		 * in one cache slot automatically enable use.
		 */
		if (ATH_HAL_HASTKIPSPLIT(ah) ||
		    !ATH_HAL_SETTKIPSPLIT(ah, AH_FALSE)) {
			asc->asc_splitmic = 1;
		}
	}
	ic->ic_caps |= IEEE80211_C_WPA;	/* Support WPA/WPA2 */

	asc->asc_hasclrkey = ATH_HAL_CIPHERSUPPORTED(ah, HAL_CIPHER_CLR);
	/*
	 * Mark key cache slots associated with global keys
	 * as in use.  If we knew TKIP was not to be used we
	 * could leave the +32, +64, and +32+64 slots free.
	 */
	for (i = 0; i < IEEE80211_WEP_NKID; i++) {
		setbit(asc->asc_keymap, i);
		setbit(asc->asc_keymap, i+64);
		if (asc->asc_splitmic) {
			setbit(asc->asc_keymap, i+32);
			setbit(asc->asc_keymap, i+32+64);
		}
	}

	ic->ic_phytype = IEEE80211_T_OFDM;
	ic->ic_opmode = IEEE80211_M_STA;
	ic->ic_state = IEEE80211_S_INIT;
	ic->ic_maxrssi = ATH_MAX_RSSI;
	ic->ic_set_shortslot = ath_set_shortslot;
	ic->ic_xmit = ath_xmit;
	ieee80211_attach(ic);

	/* different instance has different WPA door */
	(void) snprintf(ic->ic_wpadoor, MAX_IEEE80211STR, "%s_%s%d", WPA_DOOR,
	    ddi_driver_name(devinfo),
	    ddi_get_instance(devinfo));

	/* Override 80211 default routines */
	ic->ic_reset = ath_reset;
	asc->asc_newstate = ic->ic_newstate;
	ic->ic_newstate = ath_newstate;
	ic->ic_watchdog = ath_watchdog;
	ic->ic_node_alloc = ath_node_alloc;
	ic->ic_node_free = ath_node_free;
	ic->ic_crypto.cs_key_alloc = ath_key_alloc;
	ic->ic_crypto.cs_key_delete = ath_key_delete;
	ic->ic_crypto.cs_key_set = ath_key_set;
	ieee80211_media_init(ic);
	/*
	 * initialize default tx key
	 */
	ic->ic_def_txkey = 0;

	asc->asc_rx_pend = 0;
	ATH_HAL_INTRSET(ah, 0);
	err = ddi_add_softintr(devinfo, DDI_SOFTINT_LOW,
	    &asc->asc_softint_id, NULL, 0, ath_softint_handler, (caddr_t)asc);
	if (err != DDI_SUCCESS) {
		ATH_DEBUG((ATH_DBG_ATTACH, "ath: ath_attach(): "
		    "ddi_add_softintr() failed\n"));
		goto attach_fail5;
	}

	if (ddi_get_iblock_cookie(devinfo, 0, &asc->asc_iblock)
	    != DDI_SUCCESS) {
		ATH_DEBUG((ATH_DBG_ATTACH, "ath: ath_attach(): "
		    "Can not get iblock cookie for INT\n"));
		goto attach_fail6;
	}

	if (ddi_add_intr(devinfo, 0, NULL, NULL, ath_intr,
	    (caddr_t)asc) != DDI_SUCCESS) {
		ATH_DEBUG((ATH_DBG_ATTACH, "ath: ath_attach(): "
		    "Can not set intr for ATH driver\n"));
		goto attach_fail6;
	}

	/*
	 * Provide initial settings for the WiFi plugin; whenever this
	 * information changes, we need to call mac_plugindata_update()
	 */
	wd.wd_opmode = ic->ic_opmode;
	wd.wd_secalloc = WIFI_SEC_NONE;
	IEEE80211_ADDR_COPY(wd.wd_bssid, ic->ic_bss->in_bssid);

	if ((macp = mac_alloc(MAC_VERSION)) == NULL) {
		ATH_DEBUG((ATH_DBG_ATTACH, "ath: ath_attach(): "
		    "MAC version mismatch\n"));
		goto attach_fail7;
	}

	macp->m_type_ident	= MAC_PLUGIN_IDENT_WIFI;
	macp->m_driver		= asc;
	macp->m_dip		= devinfo;
	macp->m_src_addr	= ic->ic_macaddr;
	macp->m_callbacks	= &ath_m_callbacks;
	macp->m_min_sdu		= 0;
	macp->m_max_sdu		= IEEE80211_MTU;
	macp->m_pdata		= &wd;
	macp->m_pdata_size	= sizeof (wd);

	err = mac_register(macp, &ic->ic_mach);
	mac_free(macp);
	if (err != 0) {
		ATH_DEBUG((ATH_DBG_ATTACH, "ath: ath_attach(): "
		    "mac_register err %x\n", err));
		goto attach_fail7;
	}

	/* Create minor node of type DDI_NT_NET_WIFI */
	(void) snprintf(strbuf, sizeof (strbuf), "%s%d",
	    ATH_NODENAME, instance);
	err = ddi_create_minor_node(devinfo, strbuf, S_IFCHR,
	    instance + 1, DDI_NT_NET_WIFI, 0);
	if (err != DDI_SUCCESS)
		ATH_DEBUG((ATH_DBG_ATTACH, "WARN: ath: ath_attach(): "
		    "Create minor node failed - %d\n", err));

	mac_link_update(ic->ic_mach, LINK_STATE_DOWN);
	asc->asc_invalid = 1;
	asc->asc_isrunning = 0;
	asc->asc_promisc = B_FALSE;
	bzero(asc->asc_mcast_refs, sizeof (asc->asc_mcast_refs));
	bzero(asc->asc_mcast_hash, sizeof (asc->asc_mcast_hash));
	return (DDI_SUCCESS);
attach_fail7:
	ddi_remove_intr(devinfo, 0, asc->asc_iblock);
attach_fail6:
	ddi_remove_softintr(asc->asc_softint_id);
attach_fail5:
	(void) ieee80211_detach(ic);
attach_fail4:
	ath_desc_free(asc);
	if (asc->asc_tq)
		ddi_taskq_destroy(asc->asc_tq);
attach_fail3:
	ah->ah_detach(asc->asc_ah);
attach_fail2:
	ddi_regs_map_free(&asc->asc_io_handle);
attach_fail1:
	pci_config_teardown(&asc->asc_cfg_handle);
attach_fail0:
	asc->asc_invalid = 1;
	mutex_destroy(&asc->asc_txbuflock);
	for (i = 0; i < HAL_NUM_TX_QUEUES; i++) {
		if (ATH_TXQ_SETUP(asc, i)) {
			struct ath_txq *txq = &asc->asc_txq[i];
			mutex_destroy(&txq->axq_lock);
		}
	}
	mutex_destroy(&asc->asc_rxbuflock);
	mutex_destroy(&asc->asc_genlock);
	mutex_destroy(&asc->asc_resched_lock);
	ddi_soft_state_free(ath_soft_state_p, instance);

	return (DDI_FAILURE);
}

/*
 * Suspend transmit/receive for powerdown
 */
static int
ath_suspend(ath_t *asc)
{
	ATH_LOCK(asc);
	ath_stop_locked(asc);
	ATH_UNLOCK(asc);
	ATH_DEBUG((ATH_DBG_SUSPEND, "ath: suspended.\n"));

	return (DDI_SUCCESS);
}

static int32_t
ath_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd)
{
	ath_t *asc;

	asc = ddi_get_soft_state(ath_soft_state_p, ddi_get_instance(devinfo));
	ASSERT(asc != NULL);

	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_SUSPEND:
		return (ath_suspend(asc));

	default:
		return (DDI_FAILURE);
	}

	if (mac_disable(asc->asc_isc.ic_mach) != 0)
		return (DDI_FAILURE);

	ath_stop_scantimer(asc);

	/* disable interrupts */
	ATH_HAL_INTRSET(asc->asc_ah, 0);

	/*
	 * Unregister from the MAC layer subsystem
	 */
	(void) mac_unregister(asc->asc_isc.ic_mach);

	/* free intterrupt resources */
	ddi_remove_intr(devinfo, 0, asc->asc_iblock);
	ddi_remove_softintr(asc->asc_softint_id);

	/*
	 * NB: the order of these is important:
	 * o call the 802.11 layer before detaching the hal to
	 *   insure callbacks into the driver to delete global
	 *   key cache entries can be handled
	 * o reclaim the tx queue data structures after calling
	 *   the 802.11 layer as we'll get called back to reclaim
	 *   node state and potentially want to use them
	 * o to cleanup the tx queues the hal is called, so detach
	 *   it last
	 */
	ieee80211_detach(&asc->asc_isc);
	ath_desc_free(asc);
	ddi_taskq_destroy(asc->asc_tq);
	ath_txq_cleanup(asc);
	asc->asc_ah->ah_detach(asc->asc_ah);

	/* free io handle */
	ddi_regs_map_free(&asc->asc_io_handle);
	pci_config_teardown(&asc->asc_cfg_handle);

	/* destroy locks */
	mutex_destroy(&asc->asc_rxbuflock);
	mutex_destroy(&asc->asc_genlock);
	mutex_destroy(&asc->asc_resched_lock);

	ddi_remove_minor_node(devinfo, NULL);
	ddi_soft_state_free(ath_soft_state_p, ddi_get_instance(devinfo));

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
static int32_t
ath_quiesce(dev_info_t *devinfo)
{
	ath_t		*asc;
	struct ath_hal	*ah;
	int		i;

	asc = ddi_get_soft_state(ath_soft_state_p, ddi_get_instance(devinfo));

	if (asc == NULL || (ah = asc->asc_ah) == NULL)
		return (DDI_FAILURE);

	/*
	 * Disable interrupts
	 */
	ATH_HAL_INTRSET(ah, 0);

	/*
	 * Disable TX HW
	 */
	for (i = 0; i < HAL_NUM_TX_QUEUES; i++) {
		if (ATH_TXQ_SETUP(asc, i)) {
			ATH_HAL_STOPTXDMA(ah, asc->asc_txq[i].axq_qnum);
		}
	}

	/*
	 * Disable RX HW
	 */
	ATH_HAL_STOPPCURECV(ah);
	ATH_HAL_SETRXFILTER(ah, 0);
	ATH_HAL_STOPDMARECV(ah);
	drv_usecwait(3000);

	/*
	 * Power down HW
	 */
	ATH_HAL_PHYDISABLE(ah);

	return (DDI_SUCCESS);
}

DDI_DEFINE_STREAM_OPS(ath_dev_ops, nulldev, nulldev, ath_attach, ath_detach,
    nodev, NULL, D_MP, NULL, ath_quiesce);

static struct modldrv ath_modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	"ath driver 1.4/HAL 0.10.5.6",		/* short description */
	&ath_dev_ops		/* driver specific ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&ath_modldrv, NULL
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

	status = ddi_soft_state_init(&ath_soft_state_p, sizeof (ath_t), 1);
	if (status != 0)
		return (status);

	mutex_init(&ath_loglock, NULL, MUTEX_DRIVER, NULL);
	ath_halfix_init();
	mac_init_ops(&ath_dev_ops, "ath");
	status = mod_install(&modlinkage);
	if (status != 0) {
		mac_fini_ops(&ath_dev_ops);
		ath_halfix_finit();
		mutex_destroy(&ath_loglock);
		ddi_soft_state_fini(&ath_soft_state_p);
	}

	return (status);
}

int
_fini(void)
{
	int status;

	status = mod_remove(&modlinkage);
	if (status == 0) {
		mac_fini_ops(&ath_dev_ops);
		ath_halfix_finit();
		mutex_destroy(&ath_loglock);
		ddi_soft_state_fini(&ath_soft_state_p);
	}
	return (status);
}
