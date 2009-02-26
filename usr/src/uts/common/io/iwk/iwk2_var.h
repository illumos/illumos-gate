/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2007, Intel Corporation
 * All rights reserved.
 */

/*
 * Copyright (c) 2006
 * Copyright (c) 2007
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

#ifndef _IWK_VAR_H
#define	_IWK_VAR_H

#ifdef __cplusplus
extern "C" {
#endif

#define	IWK_DMA_SYNC(area, flag) \
	(void) ddi_dma_sync((area).dma_hdl, (area).offset, \
	(area).alength, (flag))

#define	IWK_CHK_FAST_RECOVER(sc) \
	(sc->sc_ic.ic_state == IEEE80211_S_RUN && \
	sc->sc_ic.ic_opmode == IEEE80211_M_STA)

typedef struct iwk_dma_area {
	ddi_acc_handle_t	acc_hdl; /* handle for memory */
	caddr_t			mem_va; /* CPU VA of memory */
	uint32_t		nslots; /* number of slots */
	uint32_t		size;   /* size per slot */
	size_t			alength; /* allocated size */
					/* >= product of above */
	ddi_dma_handle_t	dma_hdl; /* DMA handle */
	offset_t		offset;  /* relative to handle */
	ddi_dma_cookie_t	cookie; /* associated cookie */
	uint32_t		ncookies;
	uint32_t		token; /* arbitrary identifier */
} iwk_dma_t;

typedef struct iwk_tx_data {
	iwk_dma_t		dma_data;
	iwk_tx_desc_t		*desc;
	uint32_t		paddr_desc;
	iwk_cmd_t		*cmd;
	uint32_t		paddr_cmd;
} iwk_tx_data_t;

typedef struct iwk_tx_ring {
	iwk_dma_t		dma_desc;
	iwk_dma_t		dma_cmd;
	iwk_tx_data_t	*data;
	int			qid;
	int			count;
	int			window;
	int			queued;
	int			cur;
} iwk_tx_ring_t;

typedef struct iwk_rx_data {
	iwk_dma_t		dma_data;
} iwk_rx_data_t;

typedef struct iwk_rx_ring {
	iwk_dma_t		dma_desc;
	uint32_t 		*desc;
	iwk_rx_data_t	data[RX_QUEUE_SIZE];
	int			cur;
} iwk_rx_ring_t;

typedef struct iwk_amrr {
	ieee80211_node_t in;	/* must be the first */
	int	txcnt;
	int	retrycnt;
	int	success;
	int	success_threshold;
	int	recovery;
} iwk_amrr_t;

typedef struct iwk_ibss_node {
	iwk_add_sta_t	node;
	int8_t		used;
} iwk_ibss_node_t;

typedef struct iwk_ibss_beacon {
	/* for update beacon frame dynamically */
	struct			ieee80211_beacon_offsets iwk_boff;
	uint32_t		beacon_cmd_len;
	iwk_tx_beacon_cmd_t	beacon_cmd;
	uint8_t			syncbeacon;
	/* beacon frame allocated from net80211 module */
	mblk_t			*mp;
} iwk_ibss_beacon_t;

typedef struct iwk_ibss {
	iwk_ibss_node_t		ibss_node_tb[IWK_STATION_COUNT];
	uint32_t		node_number;
	kmutex_t		node_tb_lock;
	iwk_ibss_beacon_t	ibss_beacon;
} iwk_ibss_t;

typedef struct iwk_softc {
	struct ieee80211com	sc_ic;
	dev_info_t		*sc_dip;
	int			(*sc_newstate)(struct ieee80211com *,
	    enum ieee80211_state, int);
	void			(*sc_recv_mgmt)(ieee80211com_t *, mblk_t *,
	    ieee80211_node_t *, int, int, uint32_t);
	enum ieee80211_state	sc_ostate;
	kmutex_t		sc_glock;
	kmutex_t		sc_mt_lock;
	kmutex_t		sc_tx_lock;
	kcondvar_t		sc_mt_cv;
	kcondvar_t		sc_tx_cv;
	kcondvar_t		sc_cmd_cv;
	kcondvar_t		sc_fw_cv;

	kthread_t		*sc_mf_thread;
	uint32_t		sc_mf_thread_switch;

	uint32_t		sc_flags;
	uint32_t		sc_dmabuf_sz;
	uint16_t		sc_clsz;
	uint8_t			sc_rev;
	uint8_t			sc_resv;
	uint16_t		sc_assoc_id;
	uint16_t		sc_reserved0;

	/* shared area */
	iwk_dma_t		sc_dma_sh;
	iwk_shared_t		*sc_shared;
	/* keep warm area */
	iwk_dma_t		sc_dma_kw;
	/* tx scheduler base address */
	uint32_t		sc_scd_base_addr;

	iwk_tx_ring_t		sc_txq[IWK_NUM_QUEUES];
	iwk_rx_ring_t		sc_rxq;

	/* firmware dma */
	iwk_firmware_hdr_t	*sc_hdr;
	char			*sc_boot;
	iwk_dma_t		sc_dma_fw_text;
	iwk_dma_t		sc_dma_fw_init_text;
	iwk_dma_t		sc_dma_fw_data;
	iwk_dma_t		sc_dma_fw_data_bak;
	iwk_dma_t		sc_dma_fw_init_data;

	ddi_acc_handle_t	sc_cfg_handle;
	caddr_t			sc_cfg_base;
	ddi_acc_handle_t	sc_handle;
	caddr_t			sc_base;
	ddi_intr_handle_t	*sc_intr_htable;
	uint_t			sc_intr_pri;

	iwk_rxon_cmd_t		sc_config;
	iwk_rxon_cmd_t		sc_config_save;
	struct iwk_eep		sc_eep_map; /* eeprom map */
	uint32_t		sc_scd_base;

	struct iwk_alive_resp	sc_card_alive_run;
	struct iwk_init_alive_resp	sc_card_alive_init;

	int32_t			sc_tempera;
	int32_t			sc_last_tempera;
	int32_t			sc_user_txpower;
	struct iwk_notif_statistics	sc_statistics;
	struct iwk_rx_gain_diff		sc_rxgain_diff;
	struct iwk_rx_sensitivity	sc_rx_sens;

	uint32_t		sc_tx_timer;
	uint32_t		sc_scan_pending;
	uint8_t			*sc_fw_bin;

	ddi_softint_handle_t    sc_soft_hdl;
	uint32_t		sc_rx_softint_pending;
	uint32_t		sc_need_reschedule;

	clock_t			sc_clk;

	/* kstats */
	uint32_t		sc_tx_nobuf;
	uint32_t		sc_rx_nobuf;
	uint32_t		sc_tx_err;
	uint32_t		sc_rx_err;
	uint32_t		sc_tx_retries;
	iwk_ibss_t		sc_ibss;
} iwk_sc_t;

#define	IWK_F_ATTACHED		(1 << 0)
#define	IWK_F_CMD_DONE		(1 << 1)
#define	IWK_F_FW_INIT		(1 << 2)
#define	IWK_F_HW_ERR_RECOVER	(1 << 3)
#define	IWK_F_RATE_AUTO_CTL	(1 << 4)
#define	IWK_F_RUNNING		(1 << 5)
#define	IWK_F_SCANNING		(1 << 6)
#define	IWK_F_SUSPEND		(1 << 7)
#define	IWK_F_RADIO_OFF		(1 << 8)
#define	IWK_F_STATISTICS	(1 << 9)
#define	IWK_F_QUIESCED		(1 << 10)
#define	IWK_F_LAZY_RESUME	(1 << 11)

#define	IWK_SUCCESS		0
#define	IWK_FAIL		EIO

#ifdef __cplusplus
}
#endif

#endif /* _IWK_VAR_H */
