/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2004 Sam Leffler, Errno Consulting
 * Copyright (c) 2004 Video54 Technologies, Inc.
 * Copyright (c) 2008 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
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

#ifndef	_ARN_RC_H
#define	_ARN_RC_H

#ifdef __cplusplus
extern "C" {
#endif

#include "arn_ath9k.h"

struct arn_softc;
struct ath_buf;

#define	ATH_RATE_MAX		30
#define	RATE_TABLE_SIZE		64
#define	MAX_TX_RATE_PHY		48

/*
 * VALID_ALL - valid for 20/40/Legacy,
 * VALID - Legacy only,
 * VALID_20 - HT 20 only,
 * VALID_40 - HT 40 only
 */

#define	INVALID		0x0
#define	VALID		0x1
#define	VALID_20	0x2
#define	VALID_40	0x4
#define	VALID_2040	(VALID_20|VALID_40)
#define	VALID_ALL	(VALID_2040|VALID)

enum {
	WLAN_RC_PHY_OFDM,
	WLAN_RC_PHY_CCK,
	WLAN_RC_PHY_HT_20_SS,
	WLAN_RC_PHY_HT_20_DS,
	WLAN_RC_PHY_HT_40_SS,
	WLAN_RC_PHY_HT_40_DS,
	WLAN_RC_PHY_HT_20_SS_HGI,
	WLAN_RC_PHY_HT_20_DS_HGI,
	WLAN_RC_PHY_HT_40_SS_HGI,
	WLAN_RC_PHY_HT_40_DS_HGI,
	WLAN_RC_PHY_MAX
};

#define	WLAN_RC_PHY_DS(_phy)	((_phy == WLAN_RC_PHY_HT_20_DS)		|| \
				(_phy == WLAN_RC_PHY_HT_40_DS)		|| \
				(_phy == WLAN_RC_PHY_HT_20_DS_HGI)	|| \
				(_phy == WLAN_RC_PHY_HT_40_DS_HGI))
#define	WLAN_RC_PHY_40(_phy)	((_phy == WLAN_RC_PHY_HT_40_SS) 	|| \
				(_phy == WLAN_RC_PHY_HT_40_DS)		|| \
				(_phy == WLAN_RC_PHY_HT_40_SS_HGI)	|| \
				(_phy == WLAN_RC_PHY_HT_40_DS_HGI))
#define	WLAN_RC_PHY_SGI(_phy)	((_phy == WLAN_RC_PHY_HT_20_SS_HGI)	|| \
				(_phy == WLAN_RC_PHY_HT_20_DS_HGI)	|| \
				(_phy == WLAN_RC_PHY_HT_40_SS_HGI)	|| \
				(_phy == WLAN_RC_PHY_HT_40_DS_HGI))

#define	WLAN_RC_PHY_HT(_phy)	(_phy >= WLAN_RC_PHY_HT_20_SS)

#define	WLAN_RC_CAP_MODE(capflag)	(((capflag & WLAN_RC_HT_FLAG) ?	\
	(capflag & WLAN_RC_40_FLAG) ? VALID_40 : VALID_20 : VALID))

/*
 * Return TRUE if flag supports HT20 && client supports HT20 or
 * return TRUE if flag supports HT40 && client supports HT40.
 * This is used becos some rates overlap between HT20/HT40.
 */
#define	WLAN_RC_PHY_HT_VALID(flag, capflag)			\
	(((flag & VALID_20) && !(capflag & WLAN_RC_40_FLAG)) || \
	((flag & VALID_40) && (capflag & WLAN_RC_40_FLAG)))

#define	WLAN_RC_DS_FLAG		(0x01)
#define	WLAN_RC_40_FLAG		(0x02)
#define	WLAN_RC_SGI_FLAG	(0x04)
#define	WLAN_RC_HT_FLAG		(0x08)

/*
 * struct ath_rate_table - Rate Control table
 * @valid: valid for use in rate control
 * @valid_single_stream: valid for use in rate control for
 * 	single stream operation
 * @phy: CCK/OFDM
 * @ratekbps: rate in Kbits per second
 * @user_ratekbps: user rate in Kbits per second
 * @ratecode: rate that goes into HW descriptors
 * @short_preamble: Mask for enabling short preamble in ratecode for CCK
 * @dot11rate: value that goes into supported
 * 	rates info element of MLME
 * @ctrl_rate: Index of next lower basic rate, used for duration computation
 * @max_4ms_framelen: maximum frame length(bytes) for tx duration
 * @probe_interval: interval for rate control to probe for other rates
 * @rssi_reduce_interval: interval for rate control to reduce rssi
 * @initial_ratemax: initial ratemax value
 */
struct ath_rate_table {
	int rate_cnt;
	uint8_t rateCodeToIndex[256];
	struct {
		int valid;
		int valid_single_stream;
		uint8_t phy;
		uint32_t ratekbps;
		uint32_t user_ratekbps;
		uint8_t ratecode;
		uint8_t short_preamble;
		uint8_t dot11rate;
		uint8_t ctrl_rate;
		int8_t rssi_ack_validmin;
		int8_t rssi_ack_deltamin;
		uint8_t base_index;
		uint8_t cw40index;
		uint8_t sgi_index;
		uint8_t ht_index;
		uint32_t max_4ms_framelen;
		uint16_t lpAckDuration;
		uint16_t spAckDuration;
	} info[RATE_TABLE_SIZE];
	uint32_t probe_interval;
	uint32_t rssi_reduce_interval;
	uint8_t initial_ratemax;
};

struct ath_tx_ratectrl_state {
	int8_t rssi_thres; /* required rssi for this rate (dB) */
	uint8_t per; /* recent estimate of packet error rate (%) */
};

struct ath_rateset {
	uint8_t rs_nrates;
	uint8_t rs_rates[ATH_RATE_MAX];
};

/*
 * struct ath_rate_priv - Rate Control priv data
 * @state: RC state
 * @rssi_last: last ACK rssi
 * @rssi_last_lookup: last ACK rssi used for lookup
 * @rssi_last_prev: previous last ACK rssi
 * @rssi_last_prev2: 2nd previous last ACK rssi
 * @rssi_sum_cnt: count of rssi_sum for averaging
 * @rssi_sum_rate: rate that we are averaging
 * @rssi_sum: running sum of rssi for averaging
 * @probe_rate: rate we are probing at
 * @rssi_time: msec timestamp for last ack rssi
 * @rssi_down_time: msec timestamp for last down step
 * @probe_time: msec timestamp for last probe
 * @hw_maxretry_pktcnt: num of packets since we got HW max retry error
 * @max_valid_rate: maximum number of valid rate
 * @per_down_time: msec timestamp for last PER down step
 * @valid_phy_ratecnt: valid rate count
 * @rate_max_phy: phy index for the max rate
 * @probe_interval: interval for ratectrl to probe for other rates
 * @prev_data_rix: rate idx of last data frame
 * @ht_cap: HT capabilities
 * @single_stream: When TRUE, only single TX stream possible
 * @neg_rates: Negotatied rates
 * @neg_ht_rates: Negotiated HT rates
 */
struct ath_rate_priv {
	int8_t rssi_last;
	int8_t rssi_last_lookup;
	int8_t rssi_last_prev;
	int8_t rssi_last_prev2;
	int32_t rssi_sum_cnt;
	int32_t rssi_sum_rate;
	int32_t rssi_sum;
	uint8_t rate_table_size;
	uint8_t probe_rate;
	uint8_t hw_maxretry_pktcnt;
	uint8_t max_valid_rate;
	uint8_t valid_rate_index[RATE_TABLE_SIZE];
	uint8_t ht_cap;
	uint8_t single_stream;
	uint8_t valid_phy_ratecnt[WLAN_RC_PHY_MAX];
	uint8_t valid_phy_rateidx[WLAN_RC_PHY_MAX][RATE_TABLE_SIZE];
	uint8_t rc_phy_mode;
	uint8_t rate_max_phy;
	uint32_t rssi_time;
	uint32_t rssi_down_time;
	uint32_t probe_time;
	uint32_t per_down_time;
	uint32_t probe_interval;
	uint32_t prev_data_rix;
	uint32_t tx_triglevel_max;
	struct ath_tx_ratectrl_state state[RATE_TABLE_SIZE];
	struct ath_rateset neg_rates;
	struct ath_rateset neg_ht_rates;
};

enum ath9k_internal_frame_type {
	ATH9K_NOT_INTERNAL,
	ATH9K_INT_PAUSE,
	ATH9K_INT_UNPAUSE
};

struct ath_tx_info_priv {
	struct ath_tx_status tx;
	int n_frames;
	int n_bad_frames;
	boolean_t update_rc;
	enum ath9k_internal_frame_type frame_type;
};

#define	ATH_TX_INFO_PRIV(tx_info)	\
	((struct ath_tx_info_priv *)((tx_info)->rate_driver_data[0]))

/* Temp private definitions for RC */
struct ath9k_tx_rate {
	int8_t idx;
	uint8_t count;
	uint8_t flags;
};

enum ath9k_rate_control_flags {
	ATH9K_TX_RC_USE_RTS_CTS		= BIT(0),
	ATH9K_TX_RC_USE_CTS_PROTECT		= BIT(1),
	ATH9K_TX_RC_USE_SHORT_PREAMBLE	= BIT(2),
	ATH9K_TX_RC_MCS			= BIT(3),
	ATH9K_TX_RC_GREEN_FIELD		= BIT(4),
	ATH9K_TX_RC_40_MHZ_WIDTH		= BIT(5),
	ATH9K_TX_RC_DUP_DATA		= BIT(6),
	ATH9K_TX_RC_SHORT_GI		= BIT(7),
};

/* RATE */
void arn_tx_status(struct arn_softc *sc, struct ath_buf *bf, boolean_t is_data);
void arn_get_rate(struct arn_softc *sc, struct ath_buf *bf,
    struct ieee80211_frame *wh);
void arn_rate_init(struct arn_softc *sc, struct ieee80211_node *in);


void arn_rate_attach(struct arn_softc *sc);
void arn_rate_update(struct arn_softc *sc,
    struct ieee80211_node *in, int32_t rate);
void arn_rate_ctl_start(struct arn_softc *sc, struct ieee80211_node *in);
void arn_rate_cb(void *arg, struct ieee80211_node *in);
void arn_rate_ctl_reset(struct arn_softc *sc, enum ieee80211_state state);
void arn_rate_ctl(void *arg, struct ieee80211_node *in);

#ifdef __cplusplus
}
#endif

#endif /* _ARN_RC_H */
