/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Macro and date structures defined for 802.11 wifi config tool.
 */

#ifndef	__WIFI_IOCTL_H
#define	__WIFI_IOCTL_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	MAX_KEY_LENGTH 26
#define	MAX_ESSID_LENGTH (32 + 1)	/* max essid length is 32 */
					/* one more for '\0' */
#define	MAX_CHANNEL_NUM	99
#define	MAX_RSSI 15
#define	MAX_NWEPKEYS 4
#define	NET_802_11 80211
#define	MAX_BUF_LEN 65536
#define	MAX_SCAN_SUPPORT_RATES 8

/*
 * ioctls
 */
#define	WLAN_IOCTL_BASE 0x1000
#define	WLAN_GET_VERSION (WLAN_IOCTL_BASE + 0x0)
#define	WLAN_SET_PARAM (WLAN_IOCTL_BASE + 0x2)
#define	WLAN_GET_PARAM (WLAN_IOCTL_BASE + 0x3)
#define	WLAN_COMMAND (WLAN_IOCTL_BASE + 0x4)

/*
 * parameters
 */
#define	WL_PARAMETERS_BASE 0x2000
#define	WL_BSSID (WL_PARAMETERS_BASE + 0x0)
#define	WL_ESSID (WL_PARAMETERS_BASE + 0x1)
#define	WL_NODE_NAME (WL_PARAMETERS_BASE + 0x2)
#define	WL_PHY_SUPPORT (WL_PARAMETERS_BASE + 0x3)
#define	WL_PHY_CONFIG (WL_PARAMETERS_BASE + 0x4)
#define	WL_DOMAIN (WL_PARAMETERS_BASE + 0x5)
#define	WL_POWER_MODE (WL_PARAMETERS_BASE + 0x6)
#define	WL_TX_POWER (WL_PARAMETERS_BASE + 0x7)
#define	WL_RSSI (WL_PARAMETERS_BASE + 0x8)
#define	WL_RSSI_THRESHOLD (WL_PARAMETERS_BASE + 0x9)
#define	WL_ESS_LIST (WL_PARAMETERS_BASE + 0xa)
#define	WL_BSS_TYPE (WL_PARAMETERS_BASE + 0xb)
#define	WL_CREATE_IBSS (WL_PARAMETERS_BASE + 0xc)
#define	WL_RTS_THRESHOLD (WL_PARAMETERS_BASE + 0xd)
#define	WL_SHORT_RETRY (WL_PARAMETERS_BASE + 0xe)
#define	WL_LONG_RETRY (WL_PARAMETERS_BASE + 0xf)
#define	WL_BEACON_PERIOD (WL_PARAMETERS_BASE + 0x10)
#define	WL_TX_LIFETIME (WL_PARAMETERS_BASE + 0x11)
#define	WL_RX_LIFETIME (WL_PARAMETERS_BASE + 0x12)
#define	WL_FRAG_THRESHOLD (WL_PARAMETERS_BASE + 0x13)
#define	WL_VENDOR_ID (WL_PARAMETERS_BASE + 0x14)
#define	WL_PRODUCT_ID (WL_PARAMETERS_BASE + 0x15)
#define	WL_NUM_ANTS (WL_PARAMETERS_BASE + 0x16)
#define	WL_RX_ANTENNA (WL_PARAMETERS_BASE + 0x17)
#define	WL_TX_ANTENNA (WL_PARAMETERS_BASE + 0x18)
#define	WL_SUPPORTED_RATES (WL_PARAMETERS_BASE + 0x19)
#define	WL_DESIRED_RATES (WL_PARAMETERS_BASE + 0x1a)
#define	WL_WEP_KEY_TAB (WL_PARAMETERS_BASE + 0x1b)
#define	WL_WEP_KEY_ID (WL_PARAMETERS_BASE + 0x1c)
#define	WL_WEP_MAPPING_TAB (WL_PARAMETERS_BASE + 0x1d)
#define	WL_WEP_MAPPING_LEN (WL_PARAMETERS_BASE + 0x1e)
#define	WL_ENCRYPTION (WL_PARAMETERS_BASE + 0x1f)
#define	WL_AUTH_MODE (WL_PARAMETERS_BASE + 0x20)
#define	WL_EXCL_UNENC (WL_PARAMETERS_BASE + 0x21)
#define	WL_RFMON (WL_PARAMETERS_BASE + 0x22)
#define	WL_RADIO (WL_PARAMETERS_BASE + 0x23)
#define	WL_LINKSTATUS (WL_PARAMETERS_BASE + 0x24)
#define	WL_DEV_DEPEND (WL_PARAMETERS_BASE + 0x25)
/*
 * commands
 */
#define	WL_COMMAND_BASE 0x3000
#define	WL_SCAN (WL_COMMAND_BASE + 0x0)
#define	WL_DISASSOCIATE (WL_COMMAND_BASE + 0x1)
#define	WL_REASSOCIATE (WL_COMMAND_BASE + 0x2)
#define	WL_LOAD_DEFAULTS (WL_COMMAND_BASE + 0x3)
#define	WL_ASSOCIAT (WL_COMMAND_BASE + 0x4)

/*
 * domains
 */
/* --USA */
#define	WL_DOMAIN_BASE 0x4000
#define	WL_DOMAIN_FCC (WL_DOMAIN_BASE + 0x0)
/* --Canada */
#define	WL_DOMAIN_DOC (WL_DOMAIN_BASE + 0x1)
/* --Most of Europe */
#define	WL_DOMAIN_ETSI (WL_DOMAIN_BASE + 0x2)
/* --Spain */
#define	WL_DOMAIN_SPAIN (WL_DOMAIN_BASE + 0x3)
/* --France */
#define	WL_DOMAIN_FRANCE (WL_DOMAIN_BASE + 0x4)
/* --Japan */
#define	WL_DOMAIN_MKK (WL_DOMAIN_BASE + 0x5)

/*
 * power mode
 */

#define	WL_PM_AM 0x0
#define	WL_PM_MPS 0x1
#define	WL_PM_FAST 0x2
#define	WL_PM_USER 0x3

/*
 * rates
 */
#define	WL_RATE_BASIC_SET 0x80
#define	WL_RATE_1M 2
#define	WL_RATE_2M 4
#define	WL_RATE_5_5M 11
#define	WL_RATE_6M 12
#define	WL_RATE_9M 18
#define	WL_RATE_11M 22
#define	WL_RATE_12M 24
#define	WL_RATE_18M 36
#define	WL_RATE_22M 44
#define	WL_RATE_24M 48
#define	WL_RATE_33M 66
#define	WL_RATE_36M 72
#define	WL_RATE_48M 96
#define	WL_RATE_54M 108
/*
 * wep operations
 */
#define	WL_WEP_OPERATION_BASE 0x6000
#define	WL_ADD (WL_WEP_OPERATION_BASE + 0x0)
#define	WL_DEL (WL_WEP_OPERATION_BASE + 0x1)
#define	WL_NUL (WL_WEP_OPERATION_BASE + 0x2)
#define	WL_IND (WL_WEP_OPERATION_BASE + 0x3)

#define	WL_NOENCRYPTION 0x0
#define	WL_ENC_WEP 0x1
#define	WL_ENC_WPA 0x2
#define	WL_OPENSYSTEM 0x1
#define	WL_SHAREDKEY 0x2

/*
 * linkstatus
 */
#define	WL_CONNECTED 0x0
#define	WL_NOTCONNECTED 0x1

/*
 * prives
 */
#define	WL_PRIV_BASE 0x7000
#define	WL_PRIV_RW (WL_PRIV_BASE + 0x0)
#define	WL_PRIV_R (WL_PRIV_BASE + 0x1)
#define	WL_PRIV_W (WL_PRIV_BASE + 0x2)
#define	WL_PRIV_INT (WL_PRIV_BASE + 0x3)
#define	WL_PRIV_INT_ARRAY (WL_PRIV_BASE + 0x4)
#define	WL_PRIV_BYTE (WL_PRIV_BASE + 0x5)
#define	WL_PRIV_BYTE_ARRAY (WL_PRIV_BASE + 0x6)
#define	WL_PRIV_STRING (WL_PRIV_BASE + 0x7)
#define	WL_PRIV_STRING_ARRAY (WL_PRIV_BASE + 0x8)
/*
 * return values
 */
#define	WL_SUCCESS 0x0
#define	WL_NOTSUPPORTED EINVAL
#define	WL_LACK_FEATURE ENOTSUP
#define	WL_HW_ERROR EIO
#define	WL_ACCESS_DENIED EACCES
#define	WL_RETURN_BASE	0x7000
#define	WL_READONLY (WL_RETURN_BASE + 0x1)
#define	WL_WRITEONLY (WL_RETURN_BASE + 0x2)
#define	WL_NOAP (WL_RETURN_BASE + 0x3)
/*
 * other values
 */
#define	WL_OTHER_BASE 0x8000
#define	WL_FHSS (WL_OTHER_BASE + 0x0)
#define	WL_DSSS (WL_OTHER_BASE + 0x1)
#define	WL_IRBASE (WL_OTHER_BASE + 0x2)
#define	WL_OFDM (WL_OTHER_BASE + 0x3)
#define	WL_HRDS (WL_OTHER_BASE + 0x4)
#define	WL_ERP (WL_OTHER_BASE + 0x5)

#define	WL_BSS_BSS 1
#define	WL_BSS_IBSS 3
#define	WL_BSS_ANY 2
/*
 * field_offset
 */
#define	WIFI_BUF_OFFSET		offsetof(wldp_t, wldp_buf)

/*
 * type definationes
 */
typedef boolean_t wl_create_ibss_t;
typedef char wl_bssid_t[6];

typedef struct wl_essid {
	uint32_t wl_essid_length;
	char wl_essid_essid[34];
}wl_essid_t;

typedef struct wl_nodename {
	uint32_t wl_nodename_length;
	char wl_nodename_name[34];
} wl_nodename_t;

typedef struct wl_phy_supported {
	uint32_t wl_phy_support_num;
	uint32_t wl_phy_support_phy_types[1];
} wl_phy_supported_t;

typedef struct wl_fhss {
	uint32_t wl_fhss_subtype;
	uint32_t wl_fhss_channel;
	uint32_t wl_fhss_hoptime;
	uint32_t wl_fhss_hoppattern;
	uint32_t wl_fhss_hopset;
	uint32_t wl_fhss_dwelltime;
} wl_fhss_t;

typedef struct wl_dsss {
	uint32_t wl_dsss_subtype;
	uint32_t wl_dsss_channel;
	boolean_t wl_dsss_have_short_preamble;
	uint32_t wl_dsss_preamble_mode;
	boolean_t wl_dsss_agility_enabled;
	boolean_t wl_dsss_have_pbcc;
	boolean_t wl_dsss_pbcc_enable;
} wl_dsss_t;

typedef struct wl_ofdm {
	uint32_t wl_ofdm_subtype;
	uint32_t wl_ofdm_frequency;
	uint32_t wl_ofdm_freq_supported;
	boolean_t wl_ofdm_ht_enabled;
} wl_ofdm_t;

typedef struct wl_erp {
	uint32_t wl_erp_subtype;
	uint32_t wl_erp_channel;
	boolean_t wl_erp_have_short_preamble;
	uint32_t wl_erp_preamble_mode;
	boolean_t wl_erp_have_agility;
	boolean_t wl_erp_agility_enabled;
	boolean_t wl_erp_have_pbcc;
	boolean_t wl_erp_pbcc_enabled;
	boolean_t wl_erp_have_dsss_ofdm;
	boolean_t wl_erp_dsss_ofdm_enabled;
	boolean_t wl_erp_have_sst;
	boolean_t wl_erp_sst_enabled;
	boolean_t wl_erp_ht_enabled;
} wl_erp_t;

typedef union wl_phy_conf {
	wl_fhss_t wl_phy_fhss_conf;
	wl_dsss_t wl_phy_dsss_conf;
	wl_ofdm_t wl_phy_ofdm_conf;
	wl_erp_t wl_phy_erp_conf;
} wl_phy_conf_t;

typedef uint32_t wl_domain_t;

typedef struct wl_ps_mode {
	uint32_t wl_ps_mode;
	uint32_t wl_ps_max_sleep;
	uint32_t wl_ps_min_sleep;
	uint32_t wl_ps_max_awake;
	uint32_t wl_ps_min_awake;
	boolean_t wl_ps_nobroadcast;
} wl_ps_mode_t;

typedef uint32_t wl_linkstatus_t;
typedef uint32_t wl_tx_pwer_t;
typedef uint32_t wl_rssi_t;
typedef uint32_t wl_rssi_threshold_t;
typedef uint32_t wl_bss_type_t;
typedef uint32_t wl_authmode_t;
typedef uint32_t wl_encryption_t;
typedef uint32_t wl_wep_key_id_t;
typedef boolean_t wl_radio_t;
typedef uint32_t wl_rts_threshold_t;
typedef uint32_t wl_short_retry_t;
typedef uint32_t wl_long_retry_t;
typedef uint32_t wl_beacon_period_t;
typedef uint32_t wl_tx_lifetime_t;
typedef uint32_t wl_rx_lifetime_t;
typedef uint32_t wl_frag_threshold_t;
typedef char wl_vendor_t[128];
typedef char wl_product_t[128];
typedef uint32_t wl_num_ants_t;
typedef uint32_t wl_rx_antenna_t;
typedef uint32_t wl_tx_antenna_t;

typedef struct wl_rates {
	uint32_t wl_rates_num;
	char wl_rates_rates[1];
} wl_rates_t;

typedef struct wl_ess_conf {
	uint32_t wl_ess_conf_length;
	wl_essid_t wl_ess_conf_essid;
	wl_bssid_t wl_ess_conf_bssid;
	char wl_ess_conf_reserved[2];
	wl_bss_type_t wl_ess_conf_bsstype;
	wl_authmode_t wl_ess_conf_authmode;
	boolean_t wl_ess_conf_wepenabled;
	wl_rssi_t wl_ess_conf_sl;
	union {
		wl_fhss_t wl_phy_fhss_conf;
		wl_dsss_t wl_phy_dsss_conf;
		wl_ofdm_t wl_phy_ofdm_conf;
		wl_erp_t wl_phy_erp_conf;
	} wl_phy_conf;
	char wl_supported_rates[MAX_SCAN_SUPPORT_RATES];
} wl_ess_conf_t;

typedef struct wl_ess_list {
	uint32_t wl_ess_list_num;
	wl_ess_conf_t wl_ess_list_ess[1];
} wl_ess_list_t;

typedef struct wl_wep_key {
	uint32_t wl_wep_length;
	char wl_wep_key[MAX_KEY_LENGTH];
	uint32_t wl_wep_operation;
} wl_wep_key_t;
typedef wl_wep_key_t wl_wep_key_tab_t[MAX_NWEPKEYS];

typedef struct wep_mapping {
	uint32_t wl_wep_map_index;
	boolean_t wl_wep_map_wepon;
	char wl_wep_map_mac_addr[6];
	char wl_wep_map_reserved[2];
	wl_wep_key_t wl_wep_map_wepkey;
} wep_mapping_t;
typedef wep_mapping_t wep_mapping_tab_t[1];

typedef struct wl_priv_param {
	char wl_priv_name[8];
	uint32_t wl_priv_type;
	uint32_t wl_priv_size;
	char wl_priv_value[1];
} wl_priv_param_t;

typedef struct wl_dev_depend {
	uint32_t wl_dev_depend_num;
	uint32_t wl_dev_depend_ret_idx;
	wl_priv_param_t wl_dev_depend_priv[1];
} wl_dev_depend_t;

typedef struct wlan_ver {
	uint32_t wl_ver_major;
	uint32_t wl_ver_minor;
} wlan_ver_t;

typedef struct wldp {
	uint32_t wldp_length;
	uint32_t wldp_type;
	uint32_t wldp_result;
	uint32_t wldp_id;
	uint32_t wldp_buf[1];
} wldp_t;

#ifdef __cplusplus
}
#endif

#endif /* __WIFI_IOCTL_H */
