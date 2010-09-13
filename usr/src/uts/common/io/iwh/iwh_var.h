/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2009, Intel Corporation
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

#ifndef _IWH_VAR_H
#define	_IWH_VAR_H

#ifdef __cplusplus
extern "C" {
#endif

#define	IWH_DMA_SYNC(area, flag) \
	(void) ddi_dma_sync((area).dma_hdl, (area).offset, \
	(area).alength, (flag))

#define	IWH_CHK_FAST_RECOVER(sc) \
	(sc->sc_ic.ic_state == IEEE80211_S_RUN && \
	sc->sc_ic.ic_opmode == IEEE80211_M_STA)

typedef struct iwh_dma_area {
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
} iwh_dma_t;

typedef struct iwh_tx_data {
	iwh_dma_t		dma_data;	/* for sending frames */
	iwh_tx_desc_t		*desc;
	uint32_t		paddr_desc;
	iwh_cmd_t		*cmd;
	uint32_t		paddr_cmd;
} iwh_tx_data_t;

typedef struct iwh_tx_ring {
	iwh_dma_t		dma_desc;	/* for descriptor itself */
	iwh_dma_t		dma_cmd;	/* for command to ucode */
	iwh_tx_data_t	*data;
	int			qid;		/* ID of queue */
	int			count;
	int			window;
	int			queued;
	int			cur;
	int			desc_cur;
} iwh_tx_ring_t;

typedef struct iwh_rx_data {
	iwh_dma_t		dma_data;
} iwh_rx_data_t;

typedef struct iwh_rx_ring {
	iwh_dma_t		dma_desc;
	uint32_t 		*desc;
	iwh_rx_data_t	data[RX_QUEUE_SIZE];
	int			cur;
} iwh_rx_ring_t;


typedef struct iwh_amrr {
	ieee80211_node_t in;
	uint32_t	txcnt;
	uint32_t	retrycnt;
	uint32_t	success;
	uint32_t	success_threshold;
	int		recovery;
	volatile uint32_t	ht_mcs_idx;
} iwh_amrr_t;

struct	iwh_phy_rx {
	uint8_t	flag;
	uint8_t	reserved[3];
	uint8_t	buf[128];
};

struct iwh_beacon_missed {
	uint32_t	consecutive;
	uint32_t	total;
	uint32_t	expected;
	uint32_t	received;
};

typedef struct iwh_softc {
	struct ieee80211com	sc_ic;
	dev_info_t		*sc_dip;
	int			(*sc_newstate)(struct ieee80211com *,
	    enum ieee80211_state, int);
	void			(*sc_recv_action)(ieee80211_node_t *,
				    const uint8_t *, const uint8_t *);
	int			(*sc_send_action)(ieee80211_node_t *,
				    int, int, uint16_t[4]);
	volatile uint32_t	sc_cmd_flag;
	volatile uint32_t	sc_cmd_accum;

	enum ieee80211_state	sc_ostate;
	kmutex_t		sc_glock;
	kmutex_t		sc_mt_lock;
	kmutex_t		sc_tx_lock;
	kmutex_t		sc_suspend_lock;
	kcondvar_t		sc_mt_cv;
	kcondvar_t		sc_tx_cv;
	kcondvar_t		sc_cmd_cv;
	kcondvar_t		sc_fw_cv;
	kcondvar_t		sc_put_seg_cv;
	kcondvar_t		sc_ucode_cv;

	kthread_t		*sc_mf_thread;
	volatile uint32_t	sc_mf_thread_switch;

	volatile uint32_t	sc_flags;
	uint32_t		sc_dmabuf_sz;
	uint16_t		sc_clsz;
	uint8_t			sc_rev;
	uint8_t			sc_resv;
	uint16_t		sc_assoc_id;
	uint16_t		sc_reserved0;

	/* shared area */
	iwh_dma_t		sc_dma_sh;
	iwh_shared_t		*sc_shared;
	/* keep warm area */
	iwh_dma_t		sc_dma_kw;
	/* tx scheduler base address */
	uint32_t		sc_scd_base_addr;

	uint32_t		sc_hw_rev;
	struct iwh_phy_rx	sc_rx_phy_res;

	iwh_tx_ring_t		sc_txq[IWH_NUM_QUEUES];
	iwh_rx_ring_t		sc_rxq;

	/* firmware dma */
	iwh_firmware_hdr_t	*sc_hdr;
	char			*sc_boot;
	iwh_dma_t		sc_dma_fw_text;
	iwh_dma_t		sc_dma_fw_init_text;
	iwh_dma_t		sc_dma_fw_data;
	iwh_dma_t		sc_dma_fw_data_bak;
	iwh_dma_t		sc_dma_fw_init_data;

	ddi_acc_handle_t	sc_cfg_handle;
	caddr_t			sc_cfg_base;
	ddi_acc_handle_t	sc_handle;
	caddr_t			sc_base;
	ddi_intr_handle_t	*sc_intr_htable;
	uint_t			sc_intr_pri;

	iwh_rxon_cmd_t		sc_config;
	iwh_rxon_cmd_t		sc_config_save;

	uint8_t			sc_eep_map[IWH_SP_EEPROM_SIZE];
	struct	iwh_eep_calibration *sc_eep_calib;
	struct	iwh_calib_results	sc_calib_results;
	uint32_t		sc_scd_base;

	struct iwh_alive_resp	sc_card_alive_run;
	struct iwh_init_alive_resp	sc_card_alive_init;
	iwh_ht_conf_t		sc_ht_conf;
	uint16_t		sc_dev_id;

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
} iwh_sc_t;

#define	SC_CMD_FLG_NONE		(0)
#define	SC_CMD_FLG_PENDING	(1)
#define	SC_CMD_FLG_DONE		(2)

#define	IWH_F_ATTACHED		(1 << 0)
#define	IWH_F_CMD_DONE		(1 << 1)
#define	IWH_F_FW_INIT		(1 << 2)
#define	IWH_F_HW_ERR_RECOVER	(1 << 3)
#define	IWH_F_RATE_AUTO_CTL	(1 << 4)
#define	IWH_F_RUNNING		(1 << 5)
#define	IWH_F_SCANNING		(1 << 6)
#define	IWH_F_SUSPEND		(1 << 7)
#define	IWH_F_RADIO_OFF		(1 << 8)
#define	IWH_F_STATISTICS	(1 << 9)
#define	IWH_F_READY		(1 << 10)
#define	IWH_F_PUT_SEG		(1 << 11)
#define	IWH_F_QUIESCED		(1 << 12)
#define	IWH_F_LAZY_RESUME	(1 << 13)

#define	IWH_SUCCESS		0
#define	IWH_FAIL		EIO

/*
 * Interaction steps for 802.11e/n between net80211 module
 * and iwh driver:
 * -- setup link with 802.11n AP: net80211 module is responsible
 *    for setup link with 802.11n AP. iwh driver monitors current
 *    state and make relevant configurations according work mode.
 * -- QoS parameter updating: net80211 module is responsible for
 *    extract EDCA parameters from the fram of AP, iwh driver get
 *    these parameters and make relevant configuration to HW.
 * -- TX queue management: iwh driver place a frame into suitable
 *    TX queue according to frame type and user priority extracted
 *    from frame head.
 * -- MIMO: iwh driver make relevant configurations in TX and RX
 *    direction according to AP mode from net80211 module.
 * -- Link aggregation: AMSDU is implemented by net80211 module and
 *    AMPDU is implemented by both iwh driver and net80211 module.
 *    iwh driver distinguish frames in one AMPDU frame and net80211
 *    module is responsible reordering every frame.
 * -- Block ACK: net80211 module is responsible for setup agreement
 *    with AP and iwh driver is responsible for realistic ACK.
 * -- Rate scaling: This function is implemented independently by
 *    iwh driver.
 * -- HT protection: This feature is also implemented by iwh driver
 *    no interaction with net80211 module.
 */

#ifdef __cplusplus
}
#endif

#endif /* _IWH_VAR_H */
