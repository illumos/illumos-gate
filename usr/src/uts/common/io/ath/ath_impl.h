/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
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
 *    notice, this list of conditions and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    similar to the "NO WARRANTY" disclaimer below ("Disclaimer") and any
 *    redistribution must be conditioned upon including a substantially
 *    similar Disclaimer requirement for further binary redistribution.
 * 3. Neither the names of the above-listed copyright holders nor the names
 *    of any contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
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
 * ath_impl.h is a bridge between the HAL and the driver. It
 * defines some data structures encapsulating the HAL interface
 * and communicating with the IEEE80211 MAC layer and other
 * driver components.
 */

#ifndef	_ATH_IMPL_H
#define	_ATH_IMPL_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Defintions for the Atheros Wireless LAN controller driver.
 */

#include <sys/note.h>
#include <sys/list.h>
#include <sys/net80211.h>
#include "ath_hal.h"

/* Bit map related macros. */
#define	setbit(a, i)		((a)[(i)/NBBY] |= (1 << ((i)%NBBY)))
#define	clrbit(a, i)		((a)[(i)/NBBY] &= ~(1 << ((i)%NBBY)))
#define	isset(a, i)		((a)[(i)/NBBY] & (1 << ((i)%NBBY)))
#define	isclr(a, i)		(!((a)[(i)/NBBY] & (1 << ((i)%NBBY))))

/*
 * Bit flags in the ath_dbg_flags
 */
#define	ATH_DBG_INIT		0x00000001	/* initialisation	*/
#define	ATH_DBG_GLD		0x00000002	/* GLD entry points	*/
#define	ATH_DBG_HAL		0x00000004	/* HAL related code	*/
#define	ATH_DBG_INT		0x00000008	/* interrupt handler	*/
#define	ATH_DBG_RECV		0x00000010	/* receive-side code	*/
#define	ATH_DBG_SEND		0x00000020	/* packet-send code	*/
#define	ATH_DBG_80211		0x00000040	/* 80211 state machine	*/
#define	ATH_DBG_IOCTL		0x00000080	/* ioctl code		*/
#define	ATH_DBG_STATS		0x00000100	/* statistics		*/
#define	ATH_DBG_RATE		0x00000200	/* rate control		*/
#define	ATH_DBG_AUX		0x00000400	/* for ath_aux.c	*/
#define	ATH_DBG_WIFICFG		0x00000800	/* wificonfig		*/
#define	ATH_DBG_OSDEP		0x00001000	/* osdep		*/
#define	ATH_DBG_ATTACH		0x00002000	/* attach		*/
#define	ATH_DBG_DETACH		0x00004000	/* detach		*/
#define	ATH_DBG_SUSPEND		0x00008000	/* suspend/resume	*/
#define	ATH_DBG_ALL		0x0000ffff	/* all			*/

#ifdef DEBUG
#define	ATH_DDB(command)	do {				\
					{ command; }		\
					_NOTE(CONSTANTCONDITION)\
				} while (0)
#else
#define	ATH_DDB(command)
#endif /* DEBUG */

/*
 * Node type of wifi device
 */
#ifndef DDI_NT_NET_WIFI
#define	DDI_NT_NET_WIFI	"ddi_network:wifi"
#endif
#define	ATH_NODENAME	"ath"

#define	ATH_DEBUG(args)		ATH_DDB(ath_dbg args)

#define	list_empty(a) ((a)->list_head.list_next == &(a)->list_head)
#define	ATH_LE_READ_4(p)						\
	((uint32_t)							\
	((((uint8_t *)(p))[0]) | (((uint8_t *)(p))[1] <<  8) |		\
	(((uint8_t *)(p))[2] << 16) | (((uint8_t *)(p))[3] << 24)))
#define	ATH_N(a)	(sizeof (a) / sizeof (a[0]))
#define	ATH_TXQ_SETUP(asc, i)	((asc)->asc_txqsetup & (1<<i))
#define	ATH_PA2DESC(_asc, _pa) \
	((struct ath_desc *)((caddr_t)(_asc)->asc_desc + \
	((_pa) - (_asc)->asc_desc_dma.cookie.dmac_address)))
/*
 * Sync a DMA area described by a dma_area_t
 */
#define	ATH_DMA_SYNC(area, flag)    ((void) ddi_dma_sync((area).dma_hdl,    \
				(area).offset, (area).alength, (flag)))

#define	ATH_TXINTR_PERIOD 5
#define	ATH_TIMEOUT	1000
#define	ATH_RXBUF	80		/* number of RX buffers */
#define	ATH_TXBUF	200		/* number of TX buffers */
#define	ATH_TXDESC	1		/* number of descriptors per buffer */
#define	ATH_TXMAXTRY	11		/* max number of transmit attempts */
#define	ATH_MCHASH	64		/* multicast hash table size */

#define	ATH_DEF_CACHE_BYTES	32	/* default cache line size */

/* driver-specific node state */
struct ath_node {
	struct ieee80211_node an_node;	/* base class */
	uint32_t	an_tx_times;	/* rate ctl times on one rate */
	uint32_t	an_tx_ok;	/* tx ok pkt */
	uint32_t	an_tx_err;	/* tx !ok pkt */
	uint32_t	an_tx_retr;	/* tx retry count */
	int32_t		an_tx_upper;	/* tx upper rate req cnt */
	uint32_t	an_tx_antenna;	/* antenna for last good frame */
	uint8_t		an_tx_rix0;	/* series 0 rate index */
	uint8_t		an_tx_try0;	/* series 0 try count */
	uint8_t		an_tx_mgtrate;	/* h/w rate for management/ctl frames */
	uint8_t		an_tx_mgtratesp; /* short preamble h/w rate for " " */
	uint8_t		an_tx_rate0;	/* series 0 h/w rate */
	uint8_t		an_tx_rate1;	/* series 1 h/w rate */
	uint8_t		an_tx_rate2;	/* series 2 h/w rate */
	uint8_t		an_tx_rate3;	/* series 3 h/w rate */
	uint8_t		an_tx_rate0sp;	/* series 0 short preamble h/w rate */
	uint8_t		an_tx_rate1sp;	/* series 1 short preamble h/w rate */
	uint8_t		an_tx_rate2sp;	/* series 2 short preamble h/w rate */
	uint8_t		an_tx_rate3sp;	/* series 3 short preamble h/w rate */
};
#define	ATH_NODE(_n)	((struct ath_node *)(_n))


struct ath_stats {
	uint32_t	ast_hardware;	/* fatal hardware error interrupts */
	uint32_t	ast_rxorn;	/* rx overrun interrupts */
	uint32_t	ast_rxeol;	/* rx eol interrupts */
	uint32_t	ast_txurn;	/* tx underrun interrupts */
	uint32_t	ast_tx_mgmt;	/* management frames transmitted */
	uint32_t	ast_tx_discard;	/* frames discarded prior to assoc */
	uint32_t	ast_tx_invalid; /* frames discarded 'cuz device gone */
	uint32_t	ast_tx_qstop;	/* tx queue stopped 'cuz full */
	uint32_t	ast_tx_nobuf;	/* tx failed 'cuz no tx buffer (data) */
	uint32_t	ast_tx_nobufmgt; /* tx failed 'cuz no tx buffer(mgmt) */
	uint32_t	ast_tx_xretries; /* tx failed 'cuz too many retries */
	uint32_t	ast_tx_fifoerr;	/* tx failed 'cuz FIFO underrun */
	uint32_t	ast_tx_filtered; /* tx failed 'cuz xmit filtered */
	uint32_t	ast_tx_shortretry; /* tx on-chip retries (short) */
	uint32_t	ast_tx_longretry; /* tx on-chip retries (long) */
	uint32_t	ast_tx_noack;	/* tx frames with no ack marked */
	uint32_t	ast_tx_rts;	/* tx frames with rts enabled */
	uint32_t	ast_tx_shortpre; /* tx frames with short preamble */
	uint32_t	ast_tx_altrate;	/* tx frames with alternate rate */
	uint32_t	ast_tx_protect;	/* tx frames with protection */
	int16_t		ast_tx_rssi;	/* tx rssi of last ack */
	int16_t		ast_tx_rssidelta; /* tx rssi delta */
	uint32_t	ast_rx_crcerr;	/* rx failed 'cuz of bad CRC */
	uint32_t	ast_rx_fifoerr;	/* rx failed 'cuz of FIFO overrun */
	uint32_t	ast_rx_badcrypt; /* rx failed 'cuz decryption */
	uint32_t	ast_rx_phyerr;	/* rx PHY error summary count */
	uint32_t	ast_rx_phy[32];	/* rx PHY error per-code counts */
	uint32_t	ast_rx_tooshort; /* rx discarded 'cuz frame too short */
	uint32_t	ast_per_cal;	/* periodic calibration calls */
	uint32_t	ast_per_calfail; /* periodic calibration failed */
	uint32_t	ast_per_rfgain;	/* periodic calibration rfgain reset */
	uint32_t	ast_rate_calls;	/* rate control checks */
	uint32_t	ast_rate_raise;	/* rate control raised xmit rate */
	uint32_t	ast_rate_drop;	/* rate control dropped xmit rate */
};


/*
 * Describes one chunk of allocated DMA-able memory
 *
 * In some cases, this is a single chunk as allocated from the system;
 * but we also use this structure to represent slices carved off such
 * a chunk.  Even when we don't really need all the information, we
 * use this structure as a convenient way of correlating the various
 * ways of looking at a piece of memory (kernel VA, IO space DVMA,
 * handle+offset, etc).
 */
struct dma_area {
	ddi_acc_handle_t	acc_hdl;	/* handle for memory */
	caddr_t			mem_va;		/* CPU VA of memory */
	uint32_t		nslots;		/* number of slots */
	uint32_t		size;		/* size per slot */
	size_t			alength;	/* allocated size */
						/* >= product of above */

	ddi_dma_handle_t	dma_hdl;	/* DMA handle */
	offset_t		offset;		/* relative to handle */
	ddi_dma_cookie_t	cookie;		/* associated cookie */
	uint32_t		ncookies;	/* must be 1 */
	uint32_t		token;		/* arbitrary identifier */
};						/* 0x50 (80) bytes */
typedef struct dma_area dma_area_t;

struct ath_buf {
	int			bf_flags;	/* tx descriptor flags */
	struct ath_desc		*bf_desc;	/* virtual addr of desc */
	struct ath_desc_status	bf_status;	/* tx/rx status */
	uint32_t		bf_daddr;	/* physical addr of desc */
	dma_area_t		bf_dma;		/* dma area for buf */
	mblk_t			*bf_m;		/* message for buf */
	struct ieee80211_node	*bf_in;		/* pointer to the node */

	/* we're in list of asc->asc_txbuf_list or asc->asc_rxbuf_list */
	list_node_t		bf_node;
};


/*
 * Data transmit queue state.  One of these exists for each
 * hardware transmit queue.  Packets sent to us from above
 * are assigned to queues based on their priority.  Not all
 * devices support a complete set of hardware transmit queues.
 * For those devices the array sc_ac2q will map multiple
 * priorities to fewer hardware queues (typically all to one
 * hardware queue).
 */
struct ath_txq {
	uint_t		axq_qnum;	/* hardware q number */
	uint_t		axq_depth;	/* queue depth (stat only) */
	uint_t		axq_intrcnt;	/* interrupt count */
	uint32_t	*axq_link;	/* link ptr in last TX desc */
	list_t		axq_list;	/* transmit queue */
	kmutex_t	axq_lock;	/* lock on q and link */
};


/*
 * asc_isc must be the first element, for convience of
 * casting between iee80211com and ath
 */
typedef struct ath {
	ieee80211com_t		asc_isc;	/* IEEE 802.11 common */
	dev_info_t		*asc_dev;	/* back pointer to dev_info_t */
	ddi_taskq_t		*asc_tq;	/* private task queue */
	struct ath_hal		*asc_ah;	/* Atheros HAL */
	uint32_t		asc_invalid : 1, /* being detached */
				asc_isrunning : 1, /* device is operational */
				asc_mrretry : 1, /* multi-rate retry support */
				asc_have11g : 1, /* have 11g support */
				asc_splitmic : 1, /* Split TKIP mic keys */
				asc_hasclrkey: 1; /* CLR key supported */
	const HAL_RATE_TABLE	*asc_rates[IEEE80211_MODE_MAX]; /* h/w rate */
	uint8_t			asc_protrix;	/* protect rate index */
	uint8_t			asc_mcastantenna; /* Multicast antenna number */

	ddi_acc_handle_t	asc_cfg_handle;	/* DDI I/O handle */
	ddi_acc_handle_t	asc_io_handle;	/* DDI I/O handle */
	uint16_t		asc_cachelsz;	/* cache line size */
	ddi_iblock_cookie_t	asc_iblock;
	ddi_softintr_t		asc_softint_id;

	struct ath_desc		*asc_desc;	/* TX/RX descriptors */
	dma_area_t		asc_desc_dma;	/* descriptor structure */
	/* pointer to the first "struct ath_buf" */
	struct ath_buf		*asc_vbufptr;
	/* length of all allocated "struct ath_buf" */
	uint32_t		asc_vbuflen;
	/* size of one DMA TX/RX buffer based on 802.11 MTU */
	int32_t			asc_dmabuf_size;

	list_t			asc_rxbuf_list;
	kmutex_t		asc_rxbuflock;	/* recv lock for above data */
	uint32_t		*asc_rxlink;	/* link ptr in last RX desc */
	uint32_t		asc_rx_pend;
	uint64_t		asc_lastrx;	/* tsf at last rx'd frame */

	list_t			asc_txbuf_list;
	kmutex_t		asc_txbuflock;	/* txbuf lock */

	uint_t			asc_txqsetup;	/* h/w queues setup */
	struct ath_txq		asc_txq[HAL_NUM_TX_QUEUES]; /* tx queues */
	struct ath_txq		*asc_ac2q[5];	/* WME AC -> h/w qnum */

	const HAL_RATE_TABLE	*asc_currates;	/* current rate table */
	enum ieee80211_phymode	asc_curmode;	/* current phy mode */
	HAL_CHANNEL		asc_curchan;	/* current h/w channel */
	uint8_t			asc_rixmap[256]; /* IEEE to h/w rate table ix */
	HAL_INT			asc_imask;	/* interrupt mask copy */
	struct ath_stats	asc_stats;	/* interface statistics */
	boolean_t		asc_promisc;	/* Promiscuous mode enabled */
	uint8_t			asc_mcast_refs[ATH_MCHASH]; /* refer count */
	uint32_t		asc_mcast_hash[2]; /* multicast hash table */
	kmutex_t		asc_genlock;

	boolean_t		asc_resched_needed;
	kmutex_t		asc_resched_lock;

	uint32_t		asc_keymax;	/* size of key cache */
	uint8_t			asc_keymap[16];	/* bit map of key cache use */

	timeout_id_t		asc_scan_timer;
	int			(*asc_newstate)(ieee80211com_t *,
					enum ieee80211_state, int);
} ath_t;

#define	ATH_STATE(macinfo)	((ath_t *)((macinfo)->gldm_private))

#define	ATH_LOCK(_asc)		mutex_enter(&(_asc)->asc_genlock)
#define	ATH_UNLOCK(_asc)	mutex_exit(&(_asc)->asc_genlock)
#define	ATH_LOCK_ASSERT(_asc)	ASSERT(mutex_owned(&(_asc)->asc_genlock))

#define	ATH_IS_RUNNING(_asc)	\
	(((_asc)->asc_invalid == 0) && ((_asc)->asc_isrunning == 1))

/* Debug and log functions */
void ath_dbg(uint32_t dbg_flags, const char *fmt, ...);	/* debug function */
void ath_log(const char *fmt, ...);	/* event log function */
void ath_problem(const char *fmt, ...);	/* run-time problem function */

#ifdef __cplusplus
}
#endif

#endif /* _ATH_IMPL_H */
