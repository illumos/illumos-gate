/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Driver for the Atheros Wireless LAN controller.
 *
 * The Atheros driver can be devided into 2 parts: H/W related(we called LLD:
 * Low Level Driver) and IEEE80211 protocol related(we called IEEE80211),
 * and each part has several sub modules.
 * The following is the high level structure of ath driver.
 * (The arrows between modules indicate function call direction.)
 *
 *
 *                     ^                                |
 *                     |                                | GLD thread
 *                     |                                V
 *             ==================  =========================================
 *             |[1]             |  |[2]                                    |
 *             |                |  |    GLD Callback functions registered  |
 *             |   IEEE80211    |  =========================       by      |
 *             |                |          |               |   IEEE80211   |
 *             |   Internal     |          V               |               |
 * =========   |                |========================  |               |
 * |[3]    |   |   Functions                            |  |               |
 * |       |   |                                        |  |               |
 * |Multi- |   ==========================================  =================
 * |       |       ^           |                |                  |
 * |Func   |       |           V                V                  V
 * |       |   ======================   ------------------------------------
 * |Thread |   |[4]                 |   |[5]                               |
 * |       |-->| Functions exported |   |   IEEE80211 Callback functions   |
 * |       |   |    by IEEE80211    |   |      registered by LLD           |
 * =========   ======================   ------------------------------------
 *                       ^                                |
 *                       |                                V
 *             -------------------------------------------------------------
 *             |[6]                                                        |
 *             |                LLD Internal functions                     |
 *             |                                                           |
 *             -------------------------------------------------------------
 *                                        ^
 *                                        | Software interrupt thread
 *                                        |
 *
 * Modules 1/2/3/4 constitute part IEEE80211, and modules 5/6 constitute LLD.
 * The short description of each module is as below:
 *      Module 1: IEEE80211 Internal functions, including ieee80211 state
 *                machine, convert functions between 802.3 frame and
 *                802.11 frame, and node maintain function, etc.
 *      Module 2: GLD callback functions, which are intercepting the calls from
 *                GLD to LLD, and adding IEEE80211's mutex protection.
 *      Module 3: Multi-func thread, which is responsible for scan timing,
 *                rate control timing and calibrate timing.
 *      Module 4: Functions exported by IEEE80211, which can be called from
 *                other modules.
 *      Module 5: IEEE80211 callback functions registered by LLD, which include
 *                GLD related callbacks and some other functions needed by
 *                IEEE80211.
 *      Module 6: LLD Internal functions, which are responsible for allocing
 *                descriptor/buffer, handling interrupt and other H/W
 *                operations.
 *
 * All functions are running in 3 types of thread:
 * 1. GLD callbacks threads, such as ioctl, intr, etc.
 * 2. Multi-Func thread in IEEE80211 which is responsible for scan,
 *    rate control and calibrate.
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
 * In ieee80211com struct, isc_genlock is a general lock to protect
 *      necessary data and functions in ieee80211_com struct. Some data in
 *      ieee802.11_com don't need protection. For example, isc_dev is writen
 *      only in ath_attach(), but read in many other functions, so protection
 *      is not necessary.
 *
 * Any of the locks can be acquired singly, but where multiple
 * locks are acquired, they *must* be in the order:
 *
 *    isc_genlock >> asc_genlock >> asc_txqlock[i] >>
 *        asc_txbuflock >> asc_rxbuflock
 *
 * Note:
 * 1. All the IEEE80211 callback functions(except isc_gld_intr)
 *    registered by LLD in module [5] are protected by isc_genlock before
 *    calling from IEEE80211.
 * 2. Module [4] have 3 important functions ieee80211_input(),
 *    ieee80211_new_state() and _ieee80211_new_state().
 *    The functions in module [6] should avoid holding mutex or other locks
 *    during the call to ieee80211_input().
 *    In particular, the soft interrupt thread that calls ieee80211_input()
 *    may in some cases carry out processing that includes sending an outgoing
 *    packet, resulting in a call to the driver's ath_mgmt_send() routine.
 *    If the ath_mgmt_send() routine were to try to acquire a mutex being held
 *    by soft interrupt thread at the time it calls ieee80211_input(),
 *    this could result in a panic due to recursive mutex entry.
 *    ieee80211_new_state() and _ieee80211_new_state() are almost the same
 *    except that the latter function asserts isc_genlock is owned in its entry.
 *    so ieee80211_new_state() is only called by ath_bmiss_handler()
 *    from soft interrupt handler thread.
 *    As the same reason to ieee80211_input, we can't hold any other mutex.
 * 3. *None* of these locks may be held across calls out to the
 *    GLD routines gld_recv() in ieee80211_input().
 *
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
#include <sys/gld.h>
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
#include "ath_hal.h"
#include "ath_impl.h"
#include "ath_aux.h"
#include "ath_rate.h"

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
 * Describes the chip's DMA engine
 */
static ddi_dma_attr_t dma_attr = {
	DMA_ATTR_V0,			/* dma_attr version */
	0x0000000000000000ull,		/* dma_attr_addr_lo */
	0xFFFFFFFFFFFFFFFFull,		/* dma_attr_addr_hi */
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

static uint8_t ath_broadcast_addr[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static kmutex_t ath_loglock;
static void *ath_soft_state_p = NULL;

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
ath_alloc_dma_mem(dev_info_t *devinfo, size_t memsize,
	ddi_device_acc_attr_t *attr_p, uint_t alloc_flags,
	uint_t bind_flags, dma_area_t *dma_p)
{
	int err;

	/*
	 * Allocate handle
	 */
	err = ddi_dma_alloc_handle(devinfo, &dma_attr,
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


static int
ath_desc_alloc(dev_info_t *devinfo, ath_t *asc)
{
	int i, err;
	size_t size;
	struct ath_desc *ds;
	struct ath_buf *bf;

	size = sizeof (struct ath_desc) * (ATH_TXBUF + ATH_RXBUF);

	err = ath_alloc_dma_mem(devinfo, size, &ath_desc_accattr,
	    DDI_DMA_CONSISTENT, DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    &asc->asc_desc_dma);

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

	/* create RX buffer list and allocate DMA memory */
	list_create(&asc->asc_rxbuf_list, sizeof (struct ath_buf),
	    offsetof(struct ath_buf, bf_node));
	for (i = 0; i < ATH_RXBUF; i++, bf++, ds++) {
		bf->bf_desc = ds;
		bf->bf_daddr = asc->asc_desc_dma.cookie.dmac_address +
		    ((caddr_t)ds - (caddr_t)asc->asc_desc);
		list_insert_tail(&asc->asc_rxbuf_list, bf);

		/* alloc DMA memory */
		err = ath_alloc_dma_mem(devinfo, asc->asc_dmabuf_size,
		    &ath_desc_accattr,
		    DDI_DMA_STREAMING, DDI_DMA_READ | DDI_DMA_STREAMING,
		    &bf->bf_dma);
		if (err != DDI_SUCCESS)
			return (err);
	}

	/* create TX buffer list and allocate DMA memory */
	list_create(&asc->asc_txbuf_list, sizeof (struct ath_buf),
	    offsetof(struct ath_buf, bf_node));
	for (i = 0; i < ATH_TXBUF; i++, bf++, ds++) {
		bf->bf_desc = ds;
		bf->bf_daddr = asc->asc_desc_dma.cookie.dmac_address +
		    ((caddr_t)ds - (caddr_t)asc->asc_desc);
		list_insert_tail(&asc->asc_txbuf_list, bf);

		/* alloc DMA memory */
		err = ath_alloc_dma_mem(devinfo, size, &ath_desc_accattr,
		    DDI_DMA_STREAMING, DDI_DMA_STREAMING, &bf->bf_dma);
		if (err != DDI_SUCCESS)
			return (err);
	}

	return (DDI_SUCCESS);
}

static void
ath_desc_free(ath_t *asc)
{
	struct ath_buf *bf;

	/* Free TX DMA buffer */
	bf = list_head(&asc->asc_txbuf_list);
	while (bf != NULL) {
		ath_free_dma_mem(&bf->bf_dma);
		list_remove(&asc->asc_txbuf_list, bf);
		bf = list_head(&asc->asc_txbuf_list);
	}
	list_destroy(&asc->asc_txbuf_list);

	/* Free RX DMA uffer */
	bf = list_head(&asc->asc_rxbuf_list);
	while (bf != NULL) {
		ath_free_dma_mem(&bf->bf_dma);
		list_remove(&asc->asc_rxbuf_list, bf);
		bf = list_head(&asc->asc_rxbuf_list);
	}
	list_destroy(&asc->asc_rxbuf_list);

	/* Free descriptor DMA buffer */
	ath_free_dma_mem(&asc->asc_desc_dma);

	kmem_free((void *)asc->asc_vbufptr, asc->asc_vbuflen);
	asc->asc_vbufptr = NULL;
}

static void
ath_printrxbuf(struct ath_buf *bf, int32_t done)
{
	struct ath_desc *ds = bf->bf_desc;

	ATH_DEBUG((ATH_DBG_RECV, "ath: R (%p %p) %08x %08x %08x "
	    "%08x %08x %08x %c\n",
	    ds, bf->bf_daddr,
	    ds->ds_link, ds->ds_data,
	    ds->ds_ctl0, ds->ds_ctl1,
	    ds->ds_hw[0], ds->ds_hw[1],
	    !done ? ' ' : (ds->ds_rxstat.rs_status == 0) ? '*' : '!'));
}

static void
ath_rx_handler(ath_t *asc)
{
	ieee80211com_t *isc = (ieee80211com_t *)asc;
	struct ath_buf *bf;
	struct ath_hal *ah = asc->asc_ah;
	struct ath_desc *ds;
	mblk_t *rx_mp;
	struct ieee80211_frame *wh, whbuf;
	int32_t len, loop = 1;
	uint8_t phyerr;
	HAL_STATUS status;
	HAL_NODE_STATS hal_node_stats;

	do {
		mutex_enter(&asc->asc_rxbuflock);
		bf = list_head(&asc->asc_rxbuf_list);
		if (bf == NULL) {
			ATH_DEBUG((ATH_DBG_RECV, "ath: ath_rx_handler(): "
			    "no buffer\n"));
			mutex_exit(&asc->asc_rxbuflock);
			break;
		}
		ASSERT(bf->bf_dma.cookie.dmac_address != NULL);
		ds = bf->bf_desc;
		if (ds->ds_link == bf->bf_daddr) {
			/*
			 * Never process the self-linked entry at the end,
			 * this may be met at heavy load.
			 */
			mutex_exit(&asc->asc_rxbuflock);
			break;
		}

		status = ATH_HAL_RXPROCDESC(ah, ds,
		    bf->bf_daddr,
		    ATH_PA2DESC(asc, ds->ds_link));
		if (status == HAL_EINPROGRESS) {
			mutex_exit(&asc->asc_rxbuflock);
			break;
		}
		list_remove(&asc->asc_rxbuf_list, bf);
		mutex_exit(&asc->asc_rxbuflock);

		if (ds->ds_rxstat.rs_status != 0) {
			if (ds->ds_rxstat.rs_status & HAL_RXERR_CRC)
				asc->asc_stats.ast_rx_crcerr++;
			if (ds->ds_rxstat.rs_status & HAL_RXERR_FIFO)
				asc->asc_stats.ast_rx_fifoerr++;
			if (ds->ds_rxstat.rs_status & HAL_RXERR_DECRYPT)
				asc->asc_stats.ast_rx_badcrypt++;
			if (ds->ds_rxstat.rs_status & HAL_RXERR_PHY) {
				asc->asc_stats.ast_rx_phyerr++;
				phyerr = ds->ds_rxstat.rs_phyerr & 0x1f;
				asc->asc_stats.ast_rx_phy[phyerr]++;
			}
			goto rx_next;
		}
		len = ds->ds_rxstat.rs_datalen;

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
		if ((wh->ifrm_fc[0] & IEEE80211_FC0_TYPE_MASK) ==
		    IEEE80211_FC0_TYPE_CTL) {
			/*
			 * Ignore control frame received in promisc mode.
			 */
			freemsg(rx_mp);
			goto rx_next;
		}
		/* Remove the CRC at the end of IEEE80211 frame */
		rx_mp->b_wptr -= IEEE80211_CRC_LEN;
		if (wh->ifrm_fc[1] & IEEE80211_FC1_WEP) {
			/*
			 * WEP is decrypted by hardware. Clear WEP bit
			 * and trim WEP header for ieee80211_input().
			 */
			wh->ifrm_fc[1] &= ~IEEE80211_FC1_WEP;
			bcopy(wh, &whbuf, sizeof (whbuf));
			/*
			 * Remove WEP related fields between
			 * header and payload.
			 */
			rx_mp->b_rptr += IEEE80211_WEP_IVLEN +
			    IEEE80211_WEP_KIDLEN;
			bcopy(&whbuf, rx_mp->b_rptr, sizeof (whbuf));
			/*
			 * Remove WEP CRC from the tail.
			 */
			rx_mp->b_wptr -= IEEE80211_WEP_CRCLEN;
		}
#ifdef DEBUG
		ath_printrxbuf(bf, status == HAL_OK);
#endif /* DEBUG */
		ieee80211_input(isc, rx_mp,
		    ds->ds_rxstat.rs_rssi,
		    ds->ds_rxstat.rs_tstamp,
		    ds->ds_rxstat.rs_antenna);
rx_next:
		mutex_enter(&asc->asc_rxbuflock);
		list_insert_tail(&asc->asc_rxbuf_list, bf);
		mutex_exit(&asc->asc_rxbuflock);
		ath_setup_desc(asc, bf);
	} while (loop);

	/* rx signal state monitoring */
	ATH_HAL_RXMONITOR(ah, &hal_node_stats);
	ATH_HAL_RXENA(ah);	/* in case of RXEOL */
}

static void
ath_printtxbuf(struct ath_buf *bf, int done)
{
	struct ath_desc *ds = bf->bf_desc;

	ATH_DEBUG((ATH_DBG_SEND, "ath: T(%p %p) %08x %08x %08x %08x %08x"
	    " %08x %08x %08x %c\n",
	    ds, bf->bf_daddr,
	    ds->ds_link, ds->ds_data,
	    ds->ds_ctl0, ds->ds_ctl1,
	    ds->ds_hw[0], ds->ds_hw[1], ds->ds_hw[2], ds->ds_hw[3],
	    !done ? ' ' : (ds->ds_txstat.ts_status == 0) ? '*' : '!'));
}

/*
 * The input parameter mp has following assumption:
 * the first mblk is for ieee80211 header, and there has enough space left
 * for WEP option at the end of this mblk.
 * The continue mblks are for payload.
 */
static int32_t
ath_xmit(ath_t *asc, struct ieee80211_node *in,
    struct ath_buf *bf, mblk_t *mp, mblk_t *mp_header)
{
	ieee80211com_t *isc = (ieee80211com_t *)asc;
	struct ieee80211_frame *wh;
	struct ath_hal *ah = asc->asc_ah;
	uint32_t subtype, flags, ctsduration, antenna;
	int32_t keyix, iswep, hdrlen, pktlen, mblen, mbslen, try0;
	uint8_t rix, cix, txrate, ctsrate, *tmp_ptr;
	struct ath_desc *ds;
	struct ath_txq *txq;
	HAL_PKT_TYPE atype;
	const HAL_RATE_TABLE *rt;
	HAL_BOOL shortPreamble;
	mblk_t *mp0;
	struct ath_node *an;

	/*
	 * CRC are added by H/W, not encaped by driver,
	 * but we must count it in pkt length.
	 */
	pktlen = IEEE80211_CRC_LEN;

	wh = (struct ieee80211_frame *)mp_header->b_rptr;
	iswep = wh->ifrm_fc[1] & IEEE80211_FC1_WEP;
	keyix = HAL_TXKEYIX_INVALID;
	hdrlen = sizeof (struct ieee80211_frame);
	if (iswep) {
		hdrlen += IEEE80211_WEP_IVLEN + IEEE80211_WEP_KIDLEN;
		pktlen += IEEE80211_WEP_CRCLEN;
		keyix = isc->isc_wep_txkey;
	}
	tmp_ptr = (uint8_t *)bf->bf_dma.mem_va;

	/* Copy 80211 header from mblk to DMA txbuf */
	mblen = mp_header->b_wptr - mp_header->b_rptr;
	bcopy(mp_header->b_rptr, tmp_ptr, mblen);
	tmp_ptr += mblen;
	pktlen += mblen;
	mbslen = mblen;

	/*
	 * If mp==NULL, then it's a management frame,
	 * else it's a data frame.
	 */
	if (mp != NULL) {
		/*
		 * Copy the first mblk to DMA txbuf
		 * (this mblk includes ether header).
		 */
		mblen = mp->b_wptr - mp->b_rptr - sizeof (struct ether_header);
		bcopy(mp->b_rptr + sizeof (struct ether_header),
			tmp_ptr, mblen);
		tmp_ptr += mblen;
		pktlen += mblen;
		mbslen += mblen;

		/* Copy subsequent mblks to DMA txbuf */
		for (mp0 = mp->b_cont; mp0 != NULL; mp0 = mp0->b_cont) {
			mblen = mp0->b_wptr - mp0->b_rptr;
			bcopy(mp0->b_rptr, tmp_ptr, mblen);
			tmp_ptr += mblen;
			pktlen += mblen;
			mbslen += mblen;
		}
	}

	bf->bf_in = in;

	/* setup descriptors */
	ds = bf->bf_desc;
	rt = asc->asc_currates;

	/*
	 * The 802.11 layer marks whether or not we should
	 * use short preamble based on the current mode and
	 * negotiated parameters.
	 */
	if ((isc->isc_flags & IEEE80211_F_SHPREAMBLE) &&
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
	switch (wh->ifrm_fc[0] & IEEE80211_FC0_TYPE_MASK) {
	case IEEE80211_FC0_TYPE_MGT:
		subtype = wh->ifrm_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
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
		subtype = wh->ifrm_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
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
	if (IEEE80211_IS_MULTICAST(wh->ifrm_addr1)) {
		flags |= HAL_TXDESC_NOACK;	/* no ack on broad/multicast */
		asc->asc_stats.ast_tx_noack++;
	} else if (pktlen > isc->isc_rtsthreshold) {
		flags |= HAL_TXDESC_RTSENA;	/* RTS based on frame length */
		asc->asc_stats.ast_tx_rts++;
	}

	/*
	 * Calculate duration.  This logically belongs in the 802.11
	 * layer but it lacks sufficient information to calculate it.
	 */
	if ((flags & HAL_TXDESC_NOACK) == 0 &&
	    (wh->ifrm_fc[0] & IEEE80211_FC0_TYPE_MASK) !=
	    IEEE80211_FC0_TYPE_CTL) {
		uint16_t dur;
		dur = ath_hal_computetxtime(ah, rt, IEEE80211_ACK_SIZE,
		    rix, shortPreamble);
		*(uint16_t *)wh->ifrm_dur = LE_16(dur);
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
		if ((flags & HAL_TXDESC_NOACK) == 0) {	/* SIFS + ACK */
			ctsduration += ath_hal_computetxtime(ah,
			    rt, IEEE80211_ACK_SIZE, cix, shortPreamble);
		}
	} else
		ctsrate = 0;

	/*
	 * For now use the antenna on which the last good
	 * frame was received on.  We assume this field is
	 * initialized to 0 which gives us ``auto'' or the
	 * ``default'' antenna.
	 */
	if (an->an_tx_antenna)
		antenna = an->an_tx_antenna;
	else
		antenna = in->in_recv_hist[in->in_hist_cur].irh_rantenna;

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
	    keyix,
	    antenna,			/* antenna mode */
	    flags,			/* flags */
	    ctsrate,			/* rts/cts rate */
	    ctsduration);		/* rts/cts duration */

	ATH_DEBUG((ATH_DBG_SEND, "ath: ath_xmit(): to %s totlen=%d "
	    "an->an_tx_rate1sp=%d tx_rate2sp=%d tx_rate3sp=%d "
	    "qnum=%d rix=%d sht=%d dur = %d\n",
	    ieee80211_ether_sprintf(wh->ifrm_addr1), mbslen, an->an_tx_rate1sp,
	    an->an_tx_rate2sp, an->an_tx_rate3sp,
	    txq->axq_qnum, rix, shortPreamble, *(uint16_t *)wh->ifrm_dur));

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

	return (0);
}


static int
ath_gld_send(gld_mac_info_t *gld_p, mblk_t *mp)
{
	int err;
	ath_t *asc = ATH_STATE(gld_p);
	ieee80211com_t *isc = (ieee80211com_t *)asc;
	struct ieee80211_node *in;
	mblk_t *mp_header;
	struct ath_buf *bf = NULL;

	/*
	 * No data frames go out unless we're associated; this
	 * should not happen as the 802.11 layer does not enable
	 * the xmit queue until we enter the RUN state.
	 */
	if (isc->isc_state != IEEE80211_S_RUN) {
		ATH_DEBUG((ATH_DBG_SEND, "ath: ath_gld_send(): "
		    "discard, state %u\n", isc->isc_state));
		asc->asc_stats.ast_tx_discard++;
		return (GLD_NOLINK);
	}

	/*
	 * Only supports STA mode
	 */
	if (isc->isc_opmode != IEEE80211_M_STA)
		return (GLD_NOLINK);

	/*
	 * Locate AP information, so we can fill MAC address.
	 */
	in = isc->isc_bss;
	in->in_inact = 0;

	/*
	 * Grab a TX buffer.
	 */
	mutex_enter(&asc->asc_txbuflock);
	bf = list_head(&asc->asc_txbuf_list);

	if (bf != NULL)
		list_remove(&asc->asc_txbuf_list, bf);
	mutex_exit(&asc->asc_txbuflock);

	if (bf == NULL) {
		ATH_DEBUG((ATH_DBG_SEND, "ath: ath_gld_send(): "
		    "no TX DMA buffer available: 100 times\n"));
		asc->asc_stats.ast_tx_nobuf++;

		mutex_enter(&asc->asc_gld_sched_lock);
		asc->asc_need_gld_sched = 1;
		mutex_exit(&asc->asc_gld_sched_lock);
		return (GLD_NORESOURCES);
	}

	mp_header = ieee80211_fill_header(isc, mp, isc->isc_wep_txkey, in);
	if (mp_header == NULL) {
		/* Push back the TX buf */
		mutex_enter(&asc->asc_txbuflock);
		list_insert_tail(&asc->asc_txbuf_list, bf);
		mutex_exit(&asc->asc_txbuflock);
		return (GLD_FAILURE);
	}

	err = ath_xmit(asc, in, bf, mp, mp_header);
	freemsg(mp_header);

	if (!err) {
		freemsg(mp);
		return (GLD_SUCCESS);
	} else {
		return (GLD_FAILURE);
	}
}

static void
ath_tx_processq(ath_t *asc, struct ath_txq *txq)
{
	ieee80211com_t *isc = (ieee80211com_t *)asc;
	struct ath_hal *ah = asc->asc_ah;
	struct ath_buf *bf;
	struct ath_desc *ds;
	struct ieee80211_node *in;
	int32_t sr, lr;
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
		status = ATH_HAL_TXPROCDESC(ah, ds);
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
			if (ds->ds_txstat.ts_status == 0) {
				an->an_tx_ok++;
				an->an_tx_antenna =
				    ds->ds_txstat.ts_antenna;
				if (ds->ds_txstat.ts_rate &
				    HAL_TXSTAT_ALTRATE)
					asc->asc_stats.ast_tx_altrate++;
				asc->asc_stats.ast_tx_rssidelta =
				    ds->ds_txstat.ts_rssi -
				    asc->asc_stats.ast_tx_rssi;
				asc->asc_stats.ast_tx_rssi =
				    ds->ds_txstat.ts_rssi;
			} else {
				an->an_tx_err++;
				if (ds->ds_txstat.ts_status &
				    HAL_TXERR_XRETRY)
					asc->asc_stats.
					    ast_tx_xretries++;
				if (ds->ds_txstat.ts_status &
				    HAL_TXERR_FIFO)
					asc->asc_stats.ast_tx_fifoerr++;
				if (ds->ds_txstat.ts_status &
				    HAL_TXERR_FILT)
					asc->asc_stats.
					    ast_tx_filtered++;
				an->an_tx_antenna = 0;	/* invalidate */
			}
			sr = ds->ds_txstat.ts_shortretry;
			lr = ds->ds_txstat.ts_longretry;
			asc->asc_stats.ast_tx_shortretry += sr;
			asc->asc_stats.ast_tx_longretry += lr;
			an->an_tx_retr += sr + lr;
		}
		bf->bf_in = NULL;
		mutex_enter(&asc->asc_txbuflock);
		list_insert_tail(&asc->asc_txbuf_list, bf);
		mutex_exit(&asc->asc_txbuflock);
		mutex_enter(&asc->asc_gld_sched_lock);
		/*
		 * Reschedule stalled outbound packets
		 */
		if (asc->asc_need_gld_sched) {
			asc->asc_need_gld_sched = 0;
			gld_sched(isc->isc_dev);
		}
		mutex_exit(&asc->asc_gld_sched_lock);
	}
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
			ath_tx_processq(asc, &asc->asc_txq[i]);
		}
	}
}

static struct ieee80211_node *
ath_node_alloc(ieee80211com_t *isc)
{
	struct ath_node *an;
	ath_t *asc = (ath_t *)isc;

	an = kmem_zalloc(sizeof (struct ath_node), KM_SLEEP);
	ath_rate_update(asc, &an->an_node, 0);
	return (&an->an_node);
}

static void
ath_node_free(ieee80211com_t *isc, struct ieee80211_node *in)
{
	ath_t *asc = (ath_t *)isc;
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
	kmem_free(in, sizeof (struct ath_node));
}

static void
ath_node_copy(struct ieee80211_node *dst, const struct ieee80211_node *src)
{
	bcopy(src, dst, sizeof (struct ieee80211_node));
}

/*
 * Transmit a management frame.  On failure we reclaim the skbuff.
 * Note that management frames come directly from the 802.11 layer
 * and do not honor the send queue flow control.  Need to investigate
 * using priority queueing so management frames can bypass data.
 */
static int32_t
ath_mgmt_send(ieee80211com_t *isc, mblk_t *mp)
{
	ath_t *asc = (ath_t *)isc;
	struct ath_hal *ah = asc->asc_ah;
	struct ieee80211_node *in;
	struct ath_buf *bf = NULL;
	struct ieee80211_frame *wh;
	int32_t error = 0;

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
		asc->asc_stats.ast_tx_nobufmgt++;
		goto bad;
	}
	wh = (struct ieee80211_frame *)mp->b_rptr;
	if ((wh->ifrm_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) ==
	    IEEE80211_FC0_SUBTYPE_PROBE_RESP) {
		/* fill time stamp */
		uint64_t tsf;
		uint32_t *tstamp;

		tsf = ATH_HAL_GETTSF64(ah);
		/* adjust 100us delay to xmit */
		tsf += 100;
		tstamp = (uint32_t *)&wh[1];
		tstamp[0] = LE_32(tsf & 0xffffffff);
		tstamp[1] = LE_32(tsf >> 32);
	}
	/*
	 * Locate node state.  When operating
	 * in station mode we always use ic_bss.
	 */
	if (isc->isc_opmode != IEEE80211_M_STA) {
		in = ieee80211_find_node(isc, wh->ifrm_addr1);
		if (in == NULL)
			in = isc->isc_bss;
	} else
		in = isc->isc_bss;

	error = ath_xmit(asc, in, bf, NULL, mp);
	if (error == 0) {
		asc->asc_stats.ast_tx_mgmt++;
		freemsg(mp);
		return (0);
	}
bad:
	if (bf != NULL) {
		mutex_enter(&asc->asc_txbuflock);
		list_insert_tail(&asc->asc_txbuf_list, bf);
		mutex_exit(&asc->asc_txbuflock);
	}
	freemsg(mp);
	return (error);
}

static int32_t
ath_new_state(ieee80211com_t *isc, enum ieee80211_state nstate)
{
	ath_t *asc = (ath_t *)isc;
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
	    HAL_LED_ASSOC, 	/* IEEE80211_S_ASSOC */
	    HAL_LED_RUN, 	/* IEEE80211_S_RUN */
	};
	if (asc->asc_invalid == 1)
		return (0);

	ostate = isc->isc_state;

	ATH_HAL_SETLEDSTATE(ah, leds[nstate]);	/* set LED */

	if (nstate == IEEE80211_S_INIT) {
		asc->asc_imask &= ~(HAL_INT_SWBA | HAL_INT_BMISS);
		ATH_HAL_INTRSET(ah, asc->asc_imask);
		error = 0;			/* cheat + use error return */
		goto bad;
	}
	in = isc->isc_bss;
	error = ath_chan_set(asc, in->in_chan);
	if (error != 0)
		goto bad;

	rfilt = ath_calcrxfilter(asc);
	if (nstate == IEEE80211_S_SCAN)
		bssid = isc->isc_macaddr;
	else
		bssid = in->in_bssid;
	ATH_HAL_SETRXFILTER(ah, rfilt);

	if (nstate == IEEE80211_S_RUN && isc->isc_opmode != IEEE80211_M_IBSS)
		ATH_HAL_SETASSOCID(ah, bssid, in->in_associd);
	else
		ATH_HAL_SETASSOCID(ah, bssid, 0);
	if (isc->isc_flags & IEEE80211_F_WEPON) {
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

	if (nstate == IEEE80211_S_RUN) {
		nvlist_t *attr_list = NULL;
		sysevent_id_t eid;
		int32_t err = 0;
		char *str_name = "ATH";
		char str_value[256] = {0};

		ATH_DEBUG((ATH_DBG_80211, "ath: ath new state(RUN): "
		    "ic_flags=0x%08x iv=%d"
		    " bssid=%s capinfo=0x%04x chan=%d\n",
		    isc->isc_flags,
		    in->in_intval,
		    ieee80211_ether_sprintf(in->in_bssid),
		    in->in_capinfo,
		    ieee80211_chan2ieee(isc, in->in_chan)));

		(void) sprintf(str_value, "%s%s%d", "-i ",
		    ddi_driver_name(asc->asc_dev),
		    ddi_get_instance(asc->asc_dev));
		if (nvlist_alloc(&attr_list,
		    NV_UNIQUE_NAME_TYPE, KM_SLEEP) == 0) {
			err = nvlist_add_string(attr_list,
			    str_name, str_value);
			if (err != DDI_SUCCESS)
				ATH_DEBUG((ATH_DBG_80211, "ath: "
				    "ath_new_state: error log event\n"));
			err = ddi_log_sysevent(asc->asc_dev,
			    DDI_VENDOR_SUNW, "class",
			    "subclass", attr_list,
			    &eid, DDI_NOSLEEP);
			if (err != DDI_SUCCESS)
				ATH_DEBUG((ATH_DBG_80211, "ath: "
				    "ath_new_state(): error log event\n"));
			nvlist_free(attr_list);
		}
	}

	return (0);
bad:
	return (error);
}

/*
 * Periodically recalibrate the PHY to account
 * for temperature/environment changes.
 */
static void
ath_calibrate(ieee80211com_t *isc)
{
	ath_t *asc = (ath_t *)isc;
	struct ath_hal *ah = asc->asc_ah;
	struct ieee80211channel *ch;
	HAL_CHANNEL hchan;

	asc->asc_stats.ast_per_cal++;

	/*
	 * Convert to a HAL channel description with the flags
	 * constrained to reflect the current operating mode.
	 */
	ch = isc->isc_ibss_chan;
	hchan.channel = ch->ich_freq;
	hchan.channelFlags = ath_chan2flags(isc, ch);

	if (ATH_HAL_GETRFGAIN(ah) == HAL_RFGAIN_NEED_CHANGE) {
		/*
		 * Rfgain is out of bounds, reset the chip
		 * to load new gain values.
		 */
		ATH_DEBUG((ATH_DBG_HAL, "ath: ath_calibrate(): "
		    "Need change RFgain\n"));
		asc->asc_stats.ast_per_rfgain++;
		ath_reset(asc);
	}
	if (!ATH_HAL_CALIBRATE(ah, &hchan)) {
		ATH_DEBUG((ATH_DBG_HAL, "ath: ath_calibrate(): "
		    "calibration of channel %u failed\n",
		    ch->ich_freq));
		asc->asc_stats.ast_per_calfail++;
	}
}

static uint_t
ath_gld_intr(gld_mac_info_t *gld_p)
{
	ath_t *asc = ATH_STATE(gld_p);
	struct ath_hal *ah = asc->asc_ah;
	HAL_INT status;
	enum ieee80211_state isc_state;
	ieee80211com_t *isc = (ieee80211com_t *)asc;

	mutex_enter(&asc->asc_genlock);

	if (!ATH_HAL_INTRPEND(ah)) {	/* shared irq, not for us */
		mutex_exit(&asc->asc_genlock);
		return (DDI_INTR_UNCLAIMED);
	}

	ATH_HAL_GETISR(ah, &status);
	status &= asc->asc_imask;
	if (status & HAL_INT_FATAL) {
		asc->asc_stats.ast_hardware++;
		mutex_exit(&asc->asc_genlock);
		goto reset;
	} else if (status & HAL_INT_RXORN) {
		asc->asc_stats.ast_rxorn++;
		mutex_exit(&asc->asc_genlock);
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
			ath_tx_handler(asc);
		}

		mutex_exit(&asc->asc_genlock);

		if (status & HAL_INT_SWBA) {
			/* This will occur only in Host-AP or Ad-Hoc mode */
			return (DDI_INTR_CLAIMED);
		}
		if (status & HAL_INT_BMISS) {
			mutex_enter(&isc->isc_genlock);
			isc_state = isc->isc_state;
			mutex_exit(&isc->isc_genlock);
			if (isc_state == IEEE80211_S_RUN) {
				(void) ieee80211_new_state(isc,
				    IEEE80211_S_ASSOC, -1);
			}
		}
	}

	return (DDI_INTR_CLAIMED);
reset:
	mutex_enter(&isc->isc_genlock);
	ath_reset(asc);
	mutex_exit(&isc->isc_genlock);
	return (DDI_INTR_CLAIMED);
}

static uint_t
ath_softint_handler(caddr_t data)
{
	ath_t *asc = (ath_t *)data;

	/*
	 * Check if the soft interrupt is triggered by another
	 * driver at the same level.
	 */
	mutex_enter(&asc->asc_genlock);
	if (asc->asc_rx_pend) { /* Soft interrupt for this driver */
		asc->asc_rx_pend = 0;
		mutex_exit(&asc->asc_genlock);
		ath_rx_handler((ath_t *)data);
		return (DDI_INTR_CLAIMED);
	}
	mutex_exit(&asc->asc_genlock);
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

static int
ath_gld_reset(gld_mac_info_t *gld_p)
{
	ath_t *asc = ATH_STATE(gld_p);

	ath_reset(asc);
	return (GLD_SUCCESS);
}


static int
ath_gld_stop(gld_mac_info_t *gld_p)
{
	ath_t *asc = ATH_STATE(gld_p);
	ieee80211com_t *isc = (ieee80211com_t *)asc;
	struct ath_hal *ah = asc->asc_ah;

	(void) _ieee80211_new_state(isc, IEEE80211_S_INIT, -1);
	ATH_HAL_INTRSET(ah, 0);
	ath_draintxq(asc);
	if (! asc->asc_invalid)
		ath_stoprecv(asc);
	else
		asc->asc_rxlink = NULL;
	ATH_HAL_SETPOWER(ah, HAL_PM_FULL_SLEEP, 0);

	asc->asc_invalid = 1;

	return (GLD_SUCCESS);
}

int
ath_gld_start(gld_mac_info_t *gld_p)
{
	int ret;
	ath_t *asc = ATH_STATE(gld_p);
	ieee80211com_t *isc = (ieee80211com_t *)asc;
	struct ieee80211_node *in;
	enum ieee80211_phymode mode;
	struct ath_hal *ah = asc->asc_ah;
	HAL_STATUS status;
	HAL_CHANNEL hchan;

	/*
	 * Stop anything previously setup.  This is safe
	 * whether this is the first time through or not.
	 */
	ret = ath_gld_stop(gld_p);
	if (ret != GLD_SUCCESS)
		return (ret);

	/*
	 * The basic interface to setting the hardware in a good
	 * state is ``reset''.  On return the hardware is known to
	 * be powered up and with interrupts disabled.  This must
	 * be followed by initialization of the appropriate bits
	 * and then setup of the interrupt mask.
	 */
	hchan.channel = isc->isc_ibss_chan->ich_freq;
	hchan.channelFlags = ath_chan2flags(isc, isc->isc_ibss_chan);
	if (!ATH_HAL_RESET(ah, (HAL_OPMODE)isc->isc_opmode,
	    &hchan, AH_FALSE, &status)) {
		ATH_DEBUG((ATH_DBG_HAL, "ath: ath_gld_start(): "
		    "unable to reset hardware, hal status %u\n", status));
		return (GLD_FAILURE);
	}
	/*
	 * Setup the hardware after reset: the key cache
	 * is filled as needed and the receive engine is
	 * set going.  Frame transmit is handled entirely
	 * in the frame output path; there's nothing to do
	 * here except setup the interrupt mask.
	 */
	ath_initkeytable(asc);

	if (ath_startrecv(asc))
		return (GLD_FAILURE);

	/*
	 * Enable interrupts.
	 */
	asc->asc_imask = HAL_INT_RX | HAL_INT_TX
	    | HAL_INT_RXEOL | HAL_INT_RXORN
	    | HAL_INT_FATAL | HAL_INT_GLOBAL;
	ATH_HAL_INTRSET(ah, asc->asc_imask);

	isc->isc_state = IEEE80211_S_INIT;

	/*
	 * The hardware should be ready to go now so it's safe
	 * to kick the 802.11 state machine as it's likely to
	 * immediately call back to us to send mgmt frames.
	 */
	in = isc->isc_bss;
	in->in_chan = isc->isc_ibss_chan;
	mode = ieee80211_chan2mode(isc, in->in_chan);
	if (mode != asc->asc_curmode)
		ath_setcurmode(asc, mode);
	asc->asc_invalid = 0;
	return (GLD_SUCCESS);
}


static int32_t
ath_gld_saddr(gld_mac_info_t *gld_p, unsigned char *macaddr)
{
	ath_t *asc = ATH_STATE(gld_p);
	struct ath_hal *ah = asc->asc_ah;

	ATH_DEBUG((ATH_DBG_GLD, "ath: ath_gld_saddr(): "
	    "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
	    macaddr[0], macaddr[1], macaddr[2],
	    macaddr[3], macaddr[4], macaddr[5]));

	IEEE80211_ADDR_COPY(asc->asc_isc.isc_macaddr, macaddr);
	ATH_HAL_SETMAC(ah, asc->asc_isc.isc_macaddr);

	ath_reset(asc);
	return (GLD_SUCCESS);
}

static int
ath_gld_set_promiscuous(gld_mac_info_t *macinfo, int mode)
{
	ath_t *asc = ATH_STATE(macinfo);
	struct ath_hal *ah = asc->asc_ah;
	uint32_t rfilt;

	rfilt = ATH_HAL_GETRXFILTER(ah);
	switch (mode) {
	case GLD_MAC_PROMISC_PHYS:
		ATH_HAL_SETRXFILTER(ah, rfilt | HAL_RX_FILTER_PROM);
		break;
	case GLD_MAC_PROMISC_MULTI:
		rfilt |= HAL_RX_FILTER_MCAST;
		rfilt &= ~HAL_RX_FILTER_PROM;
		ATH_HAL_SETRXFILTER(ah, rfilt);
		break;
	case GLD_MAC_PROMISC_NONE:
		ATH_HAL_SETRXFILTER(ah, rfilt & (~HAL_RX_FILTER_PROM));
		break;
	default:
		break;
	}

	return (GLD_SUCCESS);
}

static int
ath_gld_set_multicast(gld_mac_info_t *macinfo, uchar_t *mca, int flag)
{
	uint32_t mfilt[2], val, rfilt;
	uint8_t pos;
	ath_t *asc = ATH_STATE(macinfo);
	struct ath_hal *ah = asc->asc_ah;

	rfilt = ATH_HAL_GETRXFILTER(ah);

	/* disable multicast */
	if (flag == GLD_MULTI_DISABLE) {
		ATH_HAL_SETRXFILTER(ah, rfilt & (~HAL_RX_FILTER_MCAST));
		return (GLD_SUCCESS);
	}

	/* enable multicast */
	ATH_HAL_SETRXFILTER(ah, rfilt | HAL_RX_FILTER_MCAST);

	mfilt[0] = mfilt[1] = 0;

	/* calculate XOR of eight 6bit values */
	val = ATH_LE_READ_4(mca + 0);
	pos = (val >> 18) ^ (val >> 12) ^ (val >> 6) ^ val;
	val = ATH_LE_READ_4(mca + 3);
	pos ^= (val >> 18) ^ (val >> 12) ^ (val >> 6) ^ val;
	pos &= 0x3f;
	mfilt[pos / 32] |= (1 << (pos % 32));
	ATH_HAL_SETMCASTFILTER(ah, mfilt[0], mfilt[1]);

	return (GLD_SUCCESS);
}

static void
ath_wlan_ioctl(ath_t *asc, queue_t *wq, mblk_t *mp, uint32_t cmd)
{

	struct iocblk *iocp = (struct iocblk *)mp->b_rptr;
	uint32_t len, ret;
	mblk_t *mp1;

	/* sanity check */
	if (iocp->ioc_count == 0 || !(mp1 = mp->b_cont)) {
		miocnak(wq, mp, 0, EINVAL);
		return;
	}

	/* assuming single data block */
	if (mp1->b_cont) {
		freemsg(mp1->b_cont);
		mp1->b_cont = NULL;
	}

	/* we will overwrite everything */
	mp1->b_wptr = mp1->b_rptr;

	ret = ath_getset(asc, mp1, cmd);

	len = msgdsize(mp1);

	miocack(wq, mp, len, ret);
}

static int
ath_gld_ioctl(gld_mac_info_t *gld_p, queue_t *wq, mblk_t *mp)
{
	struct iocblk *iocp;
	int32_t cmd, err;
	ath_t *asc = ATH_STATE(gld_p);
	boolean_t need_privilege;

	/*
	 * Validate the command before bothering with the mutexen ...
	 */
	iocp = (struct iocblk *)mp->b_rptr;
	cmd = iocp->ioc_cmd;
	need_privilege = B_TRUE;
	switch (cmd) {
	case WLAN_SET_PARAM:
	case WLAN_COMMAND:
		break;
	case WLAN_GET_PARAM:
		need_privilege = B_FALSE;
		break;
	default:
		ATH_DEBUG((ATH_DBG_GLD, "ath: ath_gld_ioctl(): "
		    "unknown cmd 0x%x", cmd));
		miocnak(wq, mp, 0, EINVAL);
		return (GLD_SUCCESS);
	}

	if (need_privilege) {
		/*
		 * Check for specific net_config privilege on Solaris 10+.
		 * Otherwise just check for root access ...
		 */
		if (secpolicy_net_config != NULL)
			err = secpolicy_net_config(iocp->ioc_cr, B_FALSE);
		else
			err = drv_priv(iocp->ioc_cr);
		if (err != 0) {
			miocnak(wq, mp, 0, err);
			return (GLD_SUCCESS);
		}
	}

	ath_wlan_ioctl(asc, wq, mp, cmd);
	return (GLD_SUCCESS);
}

static int
ath_gld_gstat(gld_mac_info_t *gld_p, struct gld_stats *glds_p)
{
	ath_t *asc = ATH_STATE(gld_p);
	ieee80211com_t *isc = (ieee80211com_t *)asc;
	struct ieee80211_node *in = isc->isc_bss;
	struct ath_node *an = ATH_NODE(in);
	struct ieee80211_rateset *rs = &in->in_rates;

	glds_p->glds_crc	= asc->asc_stats.ast_rx_crcerr;
	glds_p->glds_multircv	= 0;
	glds_p->glds_multixmt	= 0;
	glds_p->glds_excoll	= 0;
	glds_p->glds_xmtretry	= an->an_tx_retr;
	glds_p->glds_defer	= 0;
	glds_p->glds_noxmtbuf	= asc->asc_stats.ast_tx_nobuf;
	glds_p->glds_norcvbuf	= asc->asc_stats.ast_rx_fifoerr;
	glds_p->glds_short	= asc->asc_stats.ast_rx_tooshort;
	glds_p->glds_missed	= asc->asc_stats.ast_rx_badcrypt;
	glds_p->glds_speed	= 1000000*(rs->ir_rates[in->in_txrate] &
	    IEEE80211_RATE_VAL) / 2;
	glds_p->glds_duplex	= GLD_DUPLEX_FULL;

	return (GLD_SUCCESS);
}

static int
ath_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	ath_t *asc;
	ieee80211com_t *isc;
	struct ath_hal *ah;
	uint8_t csz;
	HAL_STATUS status;
	caddr_t regs;
	uint32_t i, val;
	uint16_t vendor_id, device_id, command;
	const char *athname;
	int32_t ath_countrycode = CTRY_DEFAULT;	/* country code */
	int32_t err, ath_regdomain = 0; /* regulatory domain */
	char strbuf[32];

	switch (cmd) {
	case DDI_RESUME:
		return (DDI_FAILURE);
	case DDI_ATTACH:
		break;
	default:
		return (DDI_FAILURE);
	}

	if (ddi_soft_state_zalloc(ath_soft_state_p,
	    ddi_get_instance(devinfo)) != DDI_SUCCESS) {
		ATH_DEBUG((ATH_DBG_ATTACH, "ath: ath_attach(): "
		    "Unable to alloc softstate\n"));
		return (DDI_FAILURE);
	}

	asc = ddi_get_soft_state(ath_soft_state_p, ddi_get_instance(devinfo));
	isc = (ieee80211com_t *)asc;
	asc->asc_dev = devinfo;

	ath_halfix_init();

	mutex_init(&asc->asc_genlock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&asc->asc_txbuflock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&asc->asc_rxbuflock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&asc->asc_gld_sched_lock, NULL, MUTEX_DRIVER, NULL);

	err = pci_config_setup(devinfo, &asc->asc_cfg_handle);
	if (err != DDI_SUCCESS) {
		ATH_DEBUG((ATH_DBG_ATTACH, "ath: ath_attach(): "
		    "pci_config_setup() failed"));
		goto attach_fail0;
	}

	csz = pci_config_get8(asc->asc_cfg_handle, PCI_CONF_CACHE_LINESZ);
	asc->asc_cachelsz = csz << 2;
	vendor_id = pci_config_get16(asc->asc_cfg_handle, PCI_CONF_VENID);
	device_id = pci_config_get16(asc->asc_cfg_handle, PCI_CONF_DEVID);
	ATH_DEBUG((ATH_DBG_ATTACH, "ath: ath_attach(): vendor 0x%x, "
	    "device id 0x%x, cache size %d\n", vendor_id, device_id, csz));

	athname = ath_hal_probe(vendor_id, device_id);
	ATH_DEBUG((ATH_DBG_ATTACH, "ath: ath_attach(): athname: %s\n",
	    athname ? athname : "Atheros ???"));

	/*
	 * Enable response to memory space accesses,
	 * and enabe bus master.
	 */
	command = PCI_COMM_MAE | PCI_COMM_ME;
	pci_config_put16(asc->asc_cfg_handle, PCI_CONF_COMM, command);
	ATH_DEBUG((ATH_DBG_ATTACH, "ath: ath_attach(): "
	    "set command reg to 0x%x \n", command));

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
		    "unable to attach hw; HAL status %u\n", status));
		goto attach_fail2;
	}
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
	ath_rate_setup(asc, IEEE80211_MODE_TURBO);

	/* Setup here so ath_rate_update is happy */
	ath_setcurmode(asc, IEEE80211_MODE_11A);

	err = ath_desc_alloc(devinfo, asc);
	if (err != DDI_SUCCESS) {
		ATH_DEBUG((ATH_DBG_ATTACH, "ath: ath_attach(): "
		    "failed to allocate descriptors: %d\n", err));
		goto attach_fail3;
	}

	/* Setup transmit queues in the HAL */
	if (ath_txq_setup(asc))
		goto attach_fail4;

	ATH_HAL_GETMAC(ah, asc->asc_isc.isc_macaddr);

	/* setup gld */
	if ((isc->isc_dev = gld_mac_alloc(devinfo)) == NULL) {
		ATH_DEBUG((ATH_DBG_ATTACH, "ath: ath_attach(): "
		"gld_mac_alloc = %p\n", (void *)isc->isc_dev));
		goto attach_fail4;
	}

	/* pre initialize some variables for isc */
	isc->isc_dev->gldm_private	= (caddr_t)asc;

	isc->isc_gld_reset		= ath_gld_reset;
	isc->isc_gld_start		= ath_gld_start;
	isc->isc_gld_stop		= ath_gld_stop;
	isc->isc_gld_saddr		= ath_gld_saddr;
	isc->isc_gld_send		= ath_gld_send;
	isc->isc_gld_set_promiscuous	= ath_gld_set_promiscuous;
	isc->isc_gld_gstat		= ath_gld_gstat;
	isc->isc_gld_ioctl		= ath_gld_ioctl;
	isc->isc_gld_set_multicast	= ath_gld_set_multicast;
	isc->isc_gld_intr		= ath_gld_intr;

	isc->isc_mgmt_send = ath_mgmt_send;
	isc->isc_new_state = ath_new_state;
	isc->isc_phytype = IEEE80211_T_OFDM;
	isc->isc_opmode = IEEE80211_M_STA;
	isc->isc_caps = IEEE80211_C_WEP | IEEE80211_C_IBSS |
	    IEEE80211_C_HOSTAP;
	/* 11g support is identified when we fetch the channel set */
	if (asc->asc_have11g)
		isc->isc_caps |= IEEE80211_C_SHPREAMBLE;
	isc->isc_node_alloc = ath_node_alloc;
	isc->isc_node_free = ath_node_free;
	isc->isc_node_copy = ath_node_copy;
	isc->isc_rate_ctl = ath_rate_ctl;
	isc->isc_calibrate = ath_calibrate;
	(void) ieee80211_ifattach(isc->isc_dev);

	isc->isc_dev->gldm_devinfo		= devinfo;
	isc->isc_dev->gldm_vendor_addr		= asc->asc_isc.isc_macaddr;
	isc->isc_dev->gldm_broadcast_addr	= ath_broadcast_addr;
	isc->isc_dev->gldm_ident		= "Atheros driver";
	isc->isc_dev->gldm_type			= DL_ETHER;
	isc->isc_dev->gldm_minpkt		= 0;
	isc->isc_dev->gldm_maxpkt		= 1500;
	isc->isc_dev->gldm_addrlen		= ETHERADDRL;
	isc->isc_dev->gldm_saplen		= -2;
	isc->isc_dev->gldm_ppa			= ddi_get_instance(devinfo);

	asc->asc_rx_pend = 0;
	ATH_HAL_INTRSET(ah, 0);
	err = ddi_add_softintr(devinfo, DDI_SOFTINT_LOW,
	    &asc->asc_softint_id, NULL, 0, ath_softint_handler, (caddr_t)asc);
	if (err != DDI_SUCCESS) {
		ATH_DEBUG((ATH_DBG_ATTACH, "ath: ath_attach(): "
		    "ddi_add_softintr() failed"));
		goto attach_fail5;
	}

	if (ddi_get_iblock_cookie(devinfo, 0, &asc->asc_iblock)
	    != DDI_SUCCESS) {
		ATH_DEBUG((ATH_DBG_ATTACH, "ath: ath_attach(): "
		    "Can not get iblock cookie for INT\n"));
		goto attach_fail6;
	}

	if (ddi_add_intr(devinfo, 0, NULL, NULL, gld_intr,
	    (caddr_t)asc->asc_isc.isc_dev) != DDI_SUCCESS) {
		ATH_DEBUG((ATH_DBG_ATTACH, "ath: ath_attach(): "
		    "Can not set intr for ATH driver\n"));
		goto attach_fail6;
	}
	isc->isc_dev->gldm_cookie = asc->asc_iblock;

	if (err = gld_register(devinfo, "ath", isc->isc_dev)) {
		ATH_DEBUG((ATH_DBG_ATTACH, "ath: ath_attach(): "
		    "gld_register err %x\n", err));
		goto attach_fail7;
	}

	/* Create minor node of type DDI_NT_NET_WIFI */
	(void) snprintf(strbuf, sizeof (strbuf), "%s%d",
	    ATH_NODENAME, isc->isc_dev->gldm_ppa);
	err = ddi_create_minor_node(devinfo, strbuf, S_IFCHR,
	    isc->isc_dev->gldm_ppa + 1, DDI_NT_NET_WIFI, 0);
	if (err != DDI_SUCCESS)
		ATH_DEBUG((ATH_DBG_ATTACH, "WARN: ath: ath_attach(): "
		    "Create minor node failed - %d\n", err));

	asc->asc_invalid = 1;
	return (DDI_SUCCESS);
attach_fail7:
	ddi_remove_intr(devinfo, 0, asc->asc_iblock);
attach_fail6:
	ddi_remove_softintr(asc->asc_softint_id);
attach_fail5:
	gld_mac_free(isc->isc_dev);
attach_fail4:
	ath_desc_free(asc);
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
	mutex_destroy(&asc->asc_gld_sched_lock);
	ddi_soft_state_free(ath_soft_state_p, ddi_get_instance(devinfo));

	return (DDI_FAILURE);
}

static int32_t
ath_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd)
{
	ath_t *asc;
	int32_t i;

	asc = ddi_get_soft_state(ath_soft_state_p, ddi_get_instance(devinfo));
	ASSERT(asc != NULL);

	switch (cmd) {
	default:
		return (DDI_FAILURE);

	case DDI_SUSPEND:
		return (DDI_FAILURE);

	case DDI_DETACH:
		break;
	}

	ASSERT(asc->asc_isc.isc_mf_thread == NULL);

	/* disable interrupts */
	ATH_HAL_INTRSET(asc->asc_ah, 0);

	/* free intterrupt resources */
	ddi_remove_intr(devinfo, 0, asc->asc_iblock);
	ddi_remove_softintr(asc->asc_softint_id);

	/* detach 802.11 and Atheros HAL */
	ieee80211_ifdetach(asc->asc_isc.isc_dev);
	ath_desc_free(asc);
	asc->asc_ah->ah_detach(asc->asc_ah);
	ath_halfix_finit();

	/* detach gld */
	if (gld_unregister(asc->asc_isc.isc_dev) != 0)
		return (DDI_FAILURE);
	gld_mac_free(asc->asc_isc.isc_dev);

	/* free io handle */
	ddi_regs_map_free(&asc->asc_io_handle);
	pci_config_teardown(&asc->asc_cfg_handle);

	/* destroy locks */
	mutex_destroy(&asc->asc_txbuflock);
	for (i = 0; i < HAL_NUM_TX_QUEUES; i++) {
		if (ATH_TXQ_SETUP(asc, i)) {
			struct ath_txq *txq = &asc->asc_txq[i];
			mutex_destroy(&txq->axq_lock);
		}
	}
	mutex_destroy(&asc->asc_rxbuflock);
	mutex_destroy(&asc->asc_genlock);
	mutex_destroy(&asc->asc_gld_sched_lock);

	ddi_remove_minor_node(devinfo, NULL);
	ddi_soft_state_free(ath_soft_state_p, ddi_get_instance(devinfo));

	return (DDI_SUCCESS);
}

static struct module_info ath_module_info = {
	0,	/* ATH_IDNUM, */
	"ath",	/* ATH_DRIVER_NAME, */
	0,
	INFPSZ,
	4096,	/* ATH_HIWAT, */
	128,	/* ATH_LOWAT */
};

static struct qinit ath_r_qinit = {	/* read queues */
	NULL,
	gld_rsrv,
	gld_open,
	gld_close,
	NULL,
	&ath_module_info,
	NULL
};

static struct qinit ath_w_qinit = {	/* write queues */
	gld_wput,
	gld_wsrv,
	NULL,
	NULL,
	NULL,
	&ath_module_info,
	NULL
};

static struct streamtab ath_streamtab = {
	&ath_r_qinit,
	&ath_w_qinit,
	NULL,
	NULL
};

static struct cb_ops ath_cb_ops = {
	nulldev,		/* cb_open */
	nulldev,		/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	nodev,			/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	&ath_streamtab,		/* cb_stream */
	D_MP,			/* cb_flag */
	0,			/* cb_rev */
	nodev,			/* cb_aread */
	nodev			/* cb_awrite */
};

static struct dev_ops ath_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	gld_getinfo,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	ath_attach,		/* devo_attach */
	ath_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&ath_cb_ops,		/* devo_cb_ops */
	(struct bus_ops *)NULL,	/* devo_bus_ops */
	NULL			/* devo_power */
};

static struct modldrv ath_modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	"ath driver 1.1",	/* short description */
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
	status = mod_install(&modlinkage);
	if (status != 0) {
		ddi_soft_state_fini(&ath_soft_state_p);
		mutex_destroy(&ath_loglock);
	}

	return (status);
}

int
_fini(void)
{
	int status;

	status = mod_remove(&modlinkage);
	if (status == 0) {
		ddi_soft_state_fini(&ath_soft_state_p);
		mutex_destroy(&ath_loglock);
	}
	return (status);
}
