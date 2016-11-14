/*	$NetBSD: if_iwnvar.h,v 1.17 2015/09/22 23:23:06 nonaka Exp $	*/
/*	$OpenBSD: if_iwnvar.h,v 1.28 2014/09/09 18:55:08 sthen Exp $	*/

/*-
 * Copyright (c) 2007, 2008
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

/*
 * Copyright 2016 Hans Rosenfeld <rosenfeld@grumpf.hope-2000.org>
 */

#ifndef _IF_IWNVAR_H
#define	_IF_IWNVAR_H

#include <sys/net80211.h>
#include <sys/queue.h>

struct iwn_dma_info {
	ddi_dma_handle_t	dma_hdl;
	ddi_acc_handle_t	acc_hdl;
	ddi_dma_cookie_t	cookie;
	uint_t			ncookies;
	uintptr_t		paddr;
	caddr_t			vaddr;
	size_t			size;
	size_t			length;
};

struct iwn_tx_data {
	struct iwn_dma_info	dma_data;
	uintptr_t		cmd_paddr;
	uintptr_t		scratch_paddr;
	struct iwn_dma_info	cmd_dma;
	struct ieee80211_node	*ni;
};

struct iwn_tx_ring {
	struct iwn_dma_info	desc_dma;
	struct iwn_dma_info	cmd_dma;
	struct iwn_tx_desc	*desc;
	struct iwn_tx_cmd	*cmd;
	struct iwn_tx_data	data[IWN_TX_RING_COUNT];
	int			qid;
	int			queued;
	int			cur;
};

#define	IWN_RBUF_COUNT	(IWN_RX_RING_COUNT + 32)

struct iwn_softc;

struct iwn_rx_data {
	struct iwn_dma_info	dma_data;
};

struct iwn_rx_ring {
	struct iwn_dma_info	desc_dma;
	struct iwn_dma_info	stat_dma;
	uint32_t		*desc;
	struct iwn_rx_status	*stat;
	struct iwn_rx_data	data[IWN_RX_RING_COUNT];
	int			cur;
};

struct iwn_node {
	struct	ieee80211_node		ni;	/* must be the first */
	struct	ieee80211_amrr_node	amn;
	uint16_t			disable_tid;
	uint8_t				id;
	uint8_t				ridx[IEEE80211_RATE_MAXSIZE];
};

struct iwn_calib_state {
	uint8_t		state;
#define IWN_CALIB_STATE_INIT	0
#define IWN_CALIB_STATE_ASSOC	1
#define IWN_CALIB_STATE_RUN	2

	u_int		nbeacons;
	int32_t		noise[3];
	uint32_t	rssi[3];
	uint32_t	ofdm_x1;
	uint32_t	ofdm_mrc_x1;
	uint32_t	ofdm_x4;
	uint32_t	ofdm_mrc_x4;
	uint32_t	cck_x4;
	uint32_t	cck_mrc_x4;
	uint32_t	bad_plcp_ofdm;
	uint32_t	fa_ofdm;
	uint32_t	bad_plcp_cck;
	uint32_t	fa_cck;
	uint32_t	low_fa;
	uint8_t		cck_state;
#define IWN_CCK_STATE_INIT	0
#define IWN_CCK_STATE_LOFA	1
#define IWN_CCK_STATE_HIFA	2

	uint8_t		noise_samples[20];
	u_int		cur_noise_sample;
	uint8_t		noise_ref;
	uint32_t	energy_samples[10];
	u_int		cur_energy_sample;
	uint32_t	energy_cck;
};

struct iwn_calib_info {
	uint8_t		*buf;
	u_int		len;
};

struct iwn_fw_part {
	const uint8_t	*text;
	uint32_t	textsz;
	const uint8_t	*data;
	uint32_t	datasz;
};

struct iwn_fw_info {
	u_char			*data;
	size_t			size;
	struct iwn_fw_part	init;
	struct iwn_fw_part	main;
	struct iwn_fw_part	boot;
};

struct iwn_ops {
	int		(*load_firmware)(struct iwn_softc *);
	void		(*read_eeprom)(struct iwn_softc *);
	int		(*post_alive)(struct iwn_softc *);
	int		(*nic_config)(struct iwn_softc *);
	int		(*config_bt_coex)(struct iwn_softc *);
	void		(*update_sched)(struct iwn_softc *, int, int, uint8_t,
			    uint16_t);
	int		(*get_temperature)(struct iwn_softc *);
	int		(*get_rssi)(const struct iwn_rx_stat *);
	int		(*set_txpower)(struct iwn_softc *, int);
	int		(*init_gains)(struct iwn_softc *);
	int		(*set_gains)(struct iwn_softc *);
	int		(*add_node)(struct iwn_softc *, struct iwn_node_info *,
			    int);
	void		(*tx_done)(struct iwn_softc *, struct iwn_rx_desc *,
			    struct iwn_rx_data *);
#ifndef IEEE80211_NO_HT
	void		(*ampdu_tx_start)(struct iwn_softc *,
			    struct ieee80211_node *, uint8_t, uint16_t);
	void		(*ampdu_tx_stop)(struct iwn_softc *, uint8_t,
			    uint16_t);
#endif
};

struct iwn_softc {
	struct ieee80211com	sc_ic;
	dev_info_t		*sc_dip;

	int			(*sc_newstate)(struct ieee80211com *,
				    enum ieee80211_state, int);

	enum ieee80211_state	sc_ostate;

	clock_t			sc_clk;
	struct ieee80211_amrr	amrr;
	uint8_t			fixed_ridx;

	uint16_t		sc_devid;
	caddr_t			sc_base;

	u_int			sc_flags;
#define IWN_FLAG_HAS_5GHZ	(1 << 0)
#define IWN_FLAG_HAS_OTPROM	(1 << 1)
#define IWN_FLAG_CALIB_DONE	(1 << 2)
#define IWN_FLAG_USE_ICT	(1 << 3)
#define IWN_FLAG_INTERNAL_PA	(1 << 4)
#define	IWN_FLAG_FW_DMA		(1 << 5)
#define IWN_FLAG_HAS_11N	(1 << 6)
#define IWN_FLAG_ENH_SENS	(1 << 7)
/* Added for NetBSD */
#define IWN_FLAG_HW_INITED	(1 << 8)
#define IWN_FLAG_SCANNING_2GHZ	(1 << 9)
#define IWN_FLAG_SCANNING_5GHZ	(1 << 10)
#define IWN_FLAG_SCANNING	(IWN_FLAG_SCANNING_2GHZ|IWN_FLAG_SCANNING_5GHZ)
/* From iwp.c */
#define	IWN_FLAG_ATTACHED	(1 << 11)
#define	IWN_FLAG_CMD_DONE	(1 << 12)
#define	IWN_FLAG_FW_ALIVE	(1 << 13)
#define	IWN_FLAG_HW_ERR_RECOVER	(1 << 14)
#define	IWN_FLAG_RATE_AUTO_CTL	(1 << 15)
#define	IWN_FLAG_RUNNING	(1 << 16)
#define	IWN_FLAG_SUSPEND	(1 << 17)
#define	IWN_FLAG_RADIO_OFF	(1 << 18)
#define	IWN_FLAG_STATISTICS	(1 << 19)
#define	IWN_FLAG_READY		(1 << 20)
#define	IWN_FLAG_PUT_SEG	(1 << 21)
#define	IWN_FLAG_QUIESCED	(1 << 22)
#define	IWN_FLAG_LAZY_RESUME	(1 << 23)
#define	IWN_FLAG_STOP_CALIB_TO	(1 << 24)

	uint8_t 		hw_type;

	struct iwn_ops		ops;
	const char		*fwname;
	const struct iwn_sensitivity_limits
				*limits;
	int			ntxqs;
	int			ndmachnls;
	uint8_t			broadcast_id;
	int			rxonsz;
	int			schedsz;
	uint32_t		fw_text_maxsz;
	uint32_t		fw_data_maxsz;
	uint32_t		fwsz;
	uint32_t			sched_txfact_addr;

	/* TX scheduler rings. */
	struct iwn_dma_info	sched_dma;
	uint16_t		*sched;
	uint32_t		sched_base;

	/* "Keep Warm" page. */
	struct iwn_dma_info	kw_dma;

	/* Firmware DMA transfer. */
	struct iwn_dma_info	fw_dma;

	/* ICT table. */
	struct iwn_dma_info	ict_dma;
	uint32_t		*ict;
	int			ict_cur;

	/* TX/RX rings. */
	struct iwn_tx_ring	txq[IWN5000_NTXQUEUES];
	struct iwn_rx_ring	rxq;

	ddi_acc_handle_t	sc_regh;
	void 			*sc_ih;
	ddi_acc_handle_t	sc_pcih;
	uint_t			sc_intr_pri;
	int			sc_intr_cap;
	int			sc_intr_count;
	size_t			sc_intr_size;
	ddi_intr_handle_t	*sc_intr_htable;
	int			sc_cap_off;	/* PCIe Capabilities. */

	ddi_periodic_t		sc_periodic;
	timeout_id_t		scan_to;
	timeout_id_t		calib_to;
	int			calib_cnt;
	struct iwn_calib_state	calib;


	struct iwn_fw_info	fw;
	struct iwn_calib_info	calibcmd[5];
	uint32_t		errptr;

	struct iwn_rx_stat	last_rx_stat;
	int			last_rx_valid;
	struct iwn_ucode_info	ucode_info;
	struct iwn_rxon		rxon;
	struct iwn_rxon		rxon_save;
	uint32_t		rawtemp;
	int			temp;
	int			noise;
	uint32_t		qfullmsk;

	uint32_t		prom_base;
	struct iwn4965_eeprom_band
				bands[IWN_NBANDS];
	uint16_t		rfcfg;
	uint8_t			calib_ver;
	char			eeprom_domain[4];
	uint32_t		eeprom_crystal;
	int16_t			eeprom_temp;
	int16_t			eeprom_voltage;
	int16_t			eeprom_rawtemp;
	int8_t			maxpwr2GHz;
	int8_t			maxpwr5GHz;
	int8_t			maxpwr[IEEE80211_CHAN_MAX];
	int8_t			enh_maxpwr[35];

	uint8_t			reset_noise_gain;
	uint8_t			noise_gain;

	uint32_t		tlv_feature_flags;

	int32_t			temp_off;
	uint32_t		int_mask;
	uint8_t			ntxchains;
	uint8_t			nrxchains;
	uint8_t			txchainmask;
	uint8_t			rxchainmask;
	uint8_t			chainmask;

	int			sc_tx_timer;
	void			*powerhook;

	kmutex_t		sc_mtx;		/* mutex for init/stop */
	kmutex_t		sc_tx_mtx;
	kmutex_t		sc_mt_mtx;

	kcondvar_t		sc_cmd_cv;
	kcondvar_t		sc_scan_cv;
	kcondvar_t		sc_fhdma_cv;
	kcondvar_t		sc_alive_cv;
	kcondvar_t		sc_calib_cv;
	kcondvar_t		sc_mt_cv;

	volatile uint32_t	sc_cmd_flag;
	volatile uint32_t	sc_cmd_accum;
#define	SC_CMD_FLG_NONE		(0)
#define	SC_CMD_FLG_PENDING	(1)
#define	SC_CMD_FLG_DONE		(2)

	/* kstats */
	uint32_t		sc_tx_nobuf;
	uint32_t		sc_rx_nobuf;
	uint32_t		sc_tx_err;
	uint32_t		sc_rx_err;
	uint32_t		sc_tx_retries;

	kstat_t			*sc_ks_misc;
	struct iwn_ks_misc	*sc_misc;
	kstat_t			*sc_ks_ant;
	struct iwn_ks_ant	*sc_ant;
	kstat_t			*sc_ks_sens;
	struct iwn_ks_sens	*sc_sens;
	kstat_t			*sc_ks_timing;
	struct iwn_ks_timing	*sc_timing;
	kstat_t			*sc_ks_edca;
	struct iwn_ks_edca	*sc_edca;
	kstat_t			*sc_ks_txpower;
	struct iwn_ks_txpower	*sc_txpower;
	kstat_t			*sc_ks_toff;
	union {
		struct iwn_ks_toff_2000 *t2000;
		struct iwn_ks_toff_6000 *t6000;
	}			sc_toff;
};

struct iwn_ks_misc {
	kstat_named_t		temp;
	kstat_named_t		crit_temp;
	kstat_named_t		pslevel;
	kstat_named_t		noise;
};

struct iwn_ks_ant {
	kstat_named_t		tx_ant;
	kstat_named_t		rx_ant;
	kstat_named_t		conn_ant;
	kstat_named_t		gain[3];
};

struct iwn_ks_sens {
	kstat_named_t		ofdm_x1;
	kstat_named_t		ofdm_mrc_x1;
	kstat_named_t		ofdm_x4;
	kstat_named_t		ofdm_mrc_x4;
	kstat_named_t		cck_x4;
	kstat_named_t		cck_mrc_x4;
	kstat_named_t		energy_cck;
};

struct iwn_ks_timing {
	kstat_named_t		bintval;
	kstat_named_t		tstamp;
	kstat_named_t		init;
};

struct iwn_ks_edca {
	struct {
		kstat_named_t		cwmin;
		kstat_named_t		cwmax;
		kstat_named_t		aifsn;
		kstat_named_t		txop;
	} ac[4];
};

struct iwn_ks_txpower {
	kstat_named_t		vdiff;
	kstat_named_t		chan;
	kstat_named_t		group;
	kstat_named_t		subband;
	struct {
		kstat_named_t	power;
		kstat_named_t	gain;
		kstat_named_t	temp;
		kstat_named_t	tcomp;
		struct {
			kstat_named_t	rf_gain;
			kstat_named_t	dsp_gain;
		} rate[IWN_RIDX_MAX];
	} txchain[2];
};

struct iwn_ks_toff_2000 {
	kstat_named_t		toff_lo;
	kstat_named_t		toff_hi;
	kstat_named_t		volt;
};

struct iwn_ks_toff_6000 {
	kstat_named_t		toff;
};

#define	IWN_CHK_FAST_RECOVER(sc) \
	(sc->sc_ic.ic_state == IEEE80211_S_RUN && \
	sc->sc_ic.ic_opmode == IEEE80211_M_STA)

#endif	/* _IF_IWNVAR_H */
