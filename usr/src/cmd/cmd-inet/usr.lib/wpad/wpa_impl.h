/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2003-2004, Jouni Malinen <jkmaline@cc.hut.fi>
 * Sun elects to license this software under the BSD license.
 * See README for more details.
 */
#ifndef __WPA_IMPL_H
#define	__WPA_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <net/wpa.h>
#include <libdladm.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	BIT(n)			(1 << (n))

#define	WPA_CIPHER_NONE		BIT(0)
#define	WPA_CIPHER_WEP40	BIT(1)
#define	WPA_CIPHER_WEP104	BIT(2)
#define	WPA_CIPHER_TKIP		BIT(3)
#define	WPA_CIPHER_CCMP		BIT(4)

#define	WPA_KEY_MGMT_IEEE8021X	BIT(0)
#define	WPA_KEY_MGMT_PSK	BIT(1)
#define	WPA_KEY_MGMT_NONE	BIT(2)
#define	WPA_KEY_MGMT_IEEE8021X_NO_WPA	BIT(3)

#define	WPA_PROTO_WPA		BIT(0)
#define	WPA_PROTO_RSN		BIT(1)

#pragma pack(1)
struct ieee802_1x_hdr {
	uint8_t		version;
	uint8_t		type;
	uint16_t	length;
	/* followed by length octets of data */
};
#pragma pack()

#define	EAPOL_VERSION	2

enum {	IEEE802_1X_TYPE_EAP_PACKET	= 0,
	IEEE802_1X_TYPE_EAPOL_START	= 1,
	IEEE802_1X_TYPE_EAPOL_LOGOFF	= 2,
	IEEE802_1X_TYPE_EAPOL_KEY	= 3,
	IEEE802_1X_TYPE_EAPOL_ENCAPSULATED_ASF_ALERT	= 4
};

enum {	EAPOL_KEY_TYPE_RC4 = 1,
	EAPOL_KEY_TYPE_RSN = 2,
	EAPOL_KEY_TYPE_WPA = 254
};

#define	WPA_NONCE_LEN		32
#define	WPA_REPLAY_COUNTER_LEN	8
#define	MAX_PSK_LENGTH		64
#define	WPA_PMK_LEN		32

#pragma pack(1)
struct wpa_eapol_key {
	uint8_t		type;
	uint16_t	key_info;
	uint16_t	key_length;
	uint8_t		replay_counter[WPA_REPLAY_COUNTER_LEN];
	uint8_t		key_nonce[WPA_NONCE_LEN];
	uint8_t		key_iv[16];
	uint8_t		key_rsc[8];
	uint8_t		key_id[8]; /* Reserved in IEEE 802.11i/RSN */
	uint8_t		key_mic[16];
	uint16_t	key_data_length;
	/* followed by key_data_length bytes of key_data */
};
#pragma pack()

#define	WPA_KEY_INFO_TYPE_MASK		(BIT(0) | BIT(1) | BIT(2))
#define	WPA_KEY_INFO_TYPE_HMAC_MD5_RC4	BIT(0)
#define	WPA_KEY_INFO_TYPE_HMAC_SHA1_AES	BIT(1)
#define	WPA_KEY_INFO_KEY_TYPE		BIT(3) /* 1: Pairwise, 0: Group key */
/* bit4..5 is used in WPA, but is reserved in IEEE 802.11i/RSN */
#define	WPA_KEY_INFO_KEY_INDEX_MASK	(BIT(4) | BIT(5))
#define	WPA_KEY_INFO_KEY_INDEX_SHIFT	4
#define	WPA_KEY_INFO_INSTALL		BIT(6) /* pairwise */
#define	WPA_KEY_INFO_TXRX		BIT(6) /* group */
#define	WPA_KEY_INFO_ACK		BIT(7)
#define	WPA_KEY_INFO_MIC		BIT(8)
#define	WPA_KEY_INFO_SECURE		BIT(9)
#define	WPA_KEY_INFO_ERROR		BIT(10)
#define	WPA_KEY_INFO_REQUEST		BIT(11)
#define	WPA_KEY_INFO_ENCR_KEY_DATA	BIT(12) /* IEEE 802.11i/RSN only */

#define	WPA_CAPABILITY_PREAUTH		BIT(0)

#define	GENERIC_INFO_ELEM		0xdd
#define	RSN_INFO_ELEM			0x30

#define	MAX_LOGBUF			4096
#define	MAX_SCANRESULTS			64

enum {
	REASON_UNSPECIFIED			= 1,
	REASON_DEAUTH_LEAVING			= 3,
	REASON_INVALID_IE			= 13,
	REASON_MICHAEL_MIC_FAILURE		= 14,
	REASON_4WAY_HANDSHAKE_TIMEOUT		= 15,
	REASON_GROUP_KEY_UPDATE_TIMEOUT		= 16,
	REASON_IE_IN_4WAY_DIFFERS		= 17,
	REASON_GROUP_CIPHER_NOT_VALID		= 18,
	REASON_PAIRWISE_CIPHER_NOT_VALID	= 19,
	REASON_AKMP_NOT_VALID			= 20,
	REASON_UNSUPPORTED_RSN_IE_VERSION	= 21,
	REASON_INVALID_RSN_IE_CAPAB		= 22,
	REASON_IEEE_802_1X_AUTH_FAILED		= 23,
	REASON_CIPHER_SUITE_REJECTED		= 24
};

/*
 * wpa_supplicant
 */
#define	PMKID_LEN 			16
#define	PMK_LEN				32

#define	MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define	MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"

struct rsn_pmksa_cache {
	struct rsn_pmksa_cache	*next;
	uint8_t			pmkid[PMKID_LEN];
	uint8_t			pmk[PMK_LEN];
	time_t			expiration;
	int			akmp; /* WPA_KEY_MGMT_* */
	uint8_t			aa[IEEE80211_ADDR_LEN];
};

struct rsn_pmksa_candidate {
	struct rsn_pmksa_candidate *next;
	uint8_t			bssid[IEEE80211_ADDR_LEN];
};


#pragma pack(1)
struct wpa_ptk {
	uint8_t mic_key[16]; /* EAPOL-Key MIC Key (MK) */
	uint8_t encr_key[16]; /* EAPOL-Key Encryption Key (EK) */
	uint8_t tk1[16]; /* Temporal Key 1 (TK1) */
	union {
		uint8_t tk2[16]; /* Temporal Key 2 (TK2) */
		struct {
			uint8_t tx_mic_key[8];
			uint8_t rx_mic_key[8];
		} auth;
	} u;
};
#pragma pack()


struct wpa_supplicant {
	struct l2_packet_data	*l2;
	unsigned char		own_addr[IEEE80211_ADDR_LEN];

	datalink_id_t		linkid;
	char			kname[WPA_STRSIZE];

	uint8_t			pmk[PMK_LEN];

	uint8_t			snonce[WPA_NONCE_LEN];
	uint8_t			anonce[WPA_NONCE_LEN];
	/* ANonce from the last 1/4 msg */

	struct wpa_ptk		ptk, tptk;
	int			ptk_set, tptk_set;
	int			renew_snonce;

	struct wpa_config	*conf;

	uint8_t			request_counter[WPA_REPLAY_COUNTER_LEN];
	uint8_t			rx_replay_counter[WPA_REPLAY_COUNTER_LEN];
	int			rx_replay_counter_set;

	uint8_t			bssid[IEEE80211_ADDR_LEN];
	int			reassociate; /* reassociation requested */

	uint8_t			*ap_wpa_ie;
	size_t			ap_wpa_ie_len;

	/*
	 * Selected configuration
	 * based on Beacon/ProbeResp WPA IE
	 */
	int			proto;
	int 			pairwise_cipher;
	int 			group_cipher;
	int			key_mgmt;

	struct wpa_driver_ops	*driver;

	enum {
		WPA_DISCONNECTED,
		WPA_SCANNING,
		WPA_ASSOCIATING,
		WPA_ASSOCIATED,
		WPA_4WAY_HANDSHAKE,
		WPA_GROUP_HANDSHAKE,
		WPA_COMPLETED
	} wpa_state;

	struct rsn_pmksa_cache	*pmksa; /* PMKSA cache */
	int	pmksa_count; /* number of entries in PMKSA cache */
	struct rsn_pmksa_cache	*cur_pmksa; /* current PMKSA entry */
	struct rsn_pmksa_candidate	*pmksa_candidates;

	/*
	 * number of EAPOL packets received after the
	 * previous association event
	 */
	int			eapol_received;
};

struct wpa_ie_data {
	int	proto;
	int	pairwise_cipher;
	int	group_cipher;
	int	key_mgmt;
	int	capabilities;
};

/* WPA configuration */
struct wpa_ssid {
	uint8_t	*ssid;
	size_t	ssid_len;

	uint8_t	bssid[IEEE80211_ADDR_LEN];
	int	bssid_set;

	uint8_t	psk[PMK_LEN];
	int	psk_set;
	char	*passphrase;

	/* Bitfields of allowed Pairwise/Group Ciphers, WPA_CIPHER_* */
	int	pairwise_cipher;
	int	group_cipher;

	int	key_mgmt;
	int	proto; /* Bitfield of allowed protocols (WPA_PROTO_*) */
};

struct wpa_config {
	struct wpa_ssid *ssid; /* global network list */
	int eapol_version;
	/* int ap_scan; */
};

struct wpa_config *wpa_config_read(void *);
void wpa_config_free(struct wpa_config *);

/*
 * Debugging function - conditional printf and hex dump.
 * Driver wrappers can use these for debugging purposes.
 */
enum { MSG_MSGDUMP, MSG_DEBUG, MSG_INFO, MSG_WARNING, MSG_ERROR };

void wpa_printf(int, char *, ...);
void wpa_hexdump(int, const char *, const uint8_t *, size_t);

void wpa_event_handler(void *, wpa_event_type);
void wpa_supplicant_rx_eapol(void *, unsigned char *, unsigned char *, size_t);

void wpa_supplicant_scan(void *, void *);
void wpa_supplicant_req_scan(struct wpa_supplicant *, int, int);

void wpa_supplicant_req_auth_timeout(struct wpa_supplicant *, int, int);
void wpa_supplicant_cancel_auth_timeout(struct wpa_supplicant *);
void wpa_supplicant_disassociate(struct wpa_supplicant *, int);

void pmksa_cache_free(struct wpa_supplicant *);
void pmksa_candidate_free(struct wpa_supplicant *);
struct rsn_pmksa_cache *pmksa_cache_get(struct wpa_supplicant *,
    uint8_t *, uint8_t *);

int wpa_parse_wpa_ie(struct wpa_supplicant *, uint8_t *,
	size_t, struct wpa_ie_data *);
int wpa_gen_wpa_ie(struct wpa_supplicant *, uint8_t *);

#ifdef __cplusplus
}
#endif

#endif /* __WPA_IMPL_H */
