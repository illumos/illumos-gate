/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
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

#ifndef	_RT2661_VAR_H
#define	_RT2661_VAR_H

#ifdef __cplusplus
extern "C" {
#endif

struct dma_area {
	ddi_acc_handle_t	acc_hdl;	/* handle for memory */
	caddr_t			mem_va;		/* CPU VA of memory */
	uint32_t		nslots;		/* number of slots */
	uint32_t		size;		/* size per slot */
	size_t			alength;	/* allocated size */

	ddi_dma_handle_t	dma_hdl;	/* DMA handle */
	offset_t		offset;		/* relative to handle */
	ddi_dma_cookie_t	cookie;		/* associated cookie */
	uint32_t		ncookies;	/* must be 1 */
	uint32_t		token;		/* arbitrary identifier */
};

struct rt2661_tx_data {
	struct dma_area		txdata_dma;
	caddr_t			buf;
	uint32_t		paddr;
	struct ieee80211_node	*ni;
};

struct rt2661_tx_ring {
	struct dma_area		txdesc_dma;
	uint32_t		paddr;
	struct rt2661_tx_desc	*desc;
	struct rt2661_tx_data	*data;
	int			count;
	int			queued;
	int			cur;
	int			next;
	int			stat;
};

struct rt2661_rx_data {
	struct dma_area	rxdata_dma;
	caddr_t		buf;
	uint32_t	paddr;
};

struct rt2661_rx_ring {
	struct dma_area		rxdesc_dma;
	uint32_t		paddr;
	struct rt2661_rx_desc	*desc;
	struct rt2661_rx_data	*data;
	int			count;
	int			cur;
	int			next;
};

struct rt2661_amrr {
	uint_t	amrr_min_success_threshold;
	uint_t	amrr_max_success_threshold;
};

struct rt2661_amrr_node {
	int	amn_success;
	int	amn_recovery;
	int	amn_success_threshold;
	int	amn_txcnt;
	int	amn_retrycnt;
};

struct rt2661_node {
	struct ieee80211_node		ni;
	struct rt2661_amrr_node		amn;
};

struct rt2661_softc {
	struct ieee80211com	sc_ic;
	dev_info_t		*sc_dev;

	/* ddi reg handler */
	ddi_acc_handle_t	sc_cfg_handle;
	caddr_t			sc_cfg_base;

	/* ddi i/o handler */
	ddi_acc_handle_t	sc_io_handle;
	caddr_t			sc_io_base;

	uint16_t		sc_cachelsz;
	uint32_t		sc_dmabuf_size;

	struct rt2661_amrr	amrr;

	struct rt2661_tx_ring	txq[4];
	struct rt2661_tx_ring	mgtq;
	struct rt2661_rx_ring	rxq;

	/* interrupt */
	ddi_iblock_cookie_t	sc_iblock;
	ddi_softint_handle_t	sc_softintr_hdl;
	ddi_intr_handle_t	*sc_intr_htable;
	uint_t			sc_intr_pri;

	kmutex_t		sc_genlock;
	kmutex_t		sc_txlock;
	kmutex_t		sc_rxlock;

	int			sc_tx_timer;
	uint32_t		sc_rx_pend;
	timeout_id_t		sc_scan_id;
	timeout_id_t		sc_rssadapt_id;
	timeout_id_t		sc_stat_id;
	enum ieee80211_state	sc_ostate;

	struct ieee80211_channel *sc_curchan;

	uint8_t			rf_rev;
	uint8_t			rfprog;
	uint8_t			rffreq;

	uint32_t		rf_regs[4];
	int8_t			txpow[38];

	struct {
		uint8_t	reg;
		uint8_t	val;
	}			bbp_prom[16];


	int			hw_radio;
	int			rx_ant;
	int			tx_ant;
	int			nb_ant;
	int			ext_2ghz_lna;
	int			ext_5ghz_lna;
	int			rssi_2ghz_corr;
	int			rssi_5ghz_corr;

	int			ncalls;
	int			avg_rssi;
	int			sifs;
	uint8_t			bbp18;
	uint8_t			bbp21;
	uint8_t			bbp22;
	uint8_t			bbp16;
	uint8_t			bbp17;
	uint8_t			bbp64;

	/* kstats */
	uint32_t		sc_tx_nobuf;
	uint32_t		sc_rx_nobuf;
	uint32_t		sc_tx_err;
	uint32_t		sc_rx_err;
	uint32_t		sc_tx_retries;

	uint32_t		sc_need_sched;
	uint32_t		sc_flags;
	uint32_t		sc_rcr;
	int			(*sc_newstate)(struct ieee80211com *,
				    enum ieee80211_state, int);
};

#define	RT2661_GLOCK(_sc)		mutex_enter(&(_sc)->sc_genlock)
#define	RT2661_GUNLOCK(_sc)		mutex_exit(&(_sc)->sc_genlock)

#define	RT2661_INPUT_RUNNING	(1 << 0)
#define	RT2661_F_RUNNING	(1 << 1)
#define	RT2661_F_SUSPEND	(1 << 2)
#define	RT2661_F_FWLOADED	(1 << 3)
#define	RT2661_F_QUIESCE	(1 << 4)

#define	RT2661_RCR_PROMISC	(1 << 0)
#define	RT2661_RCR_MULTI	(1 << 1)

#define	RT2661_IS_RUNNING(_sc)		(((_sc)->sc_flags & RT2661_F_RUNNING))
#define	RT2661_IS_SUSPEND(_sc)		(((_sc)->sc_flags & RT2661_F_SUSPEND))
#define	RT2661_IS_FWLOADED(_sc)		(((_sc)->sc_flags & RT2661_F_FWLOADED))
#define	RT2661_IS_FASTREBOOT(_sc)	(((_sc)->sc_flags & RT2661_F_QUIESCE))

#define	RT2661_DMA_SYNC(area, flag) ((void) ddi_dma_sync((area).dma_hdl,\
	(area).offset, (area).alength, (flag)))

#define	RT2661_SUCCESS		0
#define	RT2661_FAILURE		-1

#ifdef __cplusplus
}
#endif

#endif /* _RT2661_VAR_H */
