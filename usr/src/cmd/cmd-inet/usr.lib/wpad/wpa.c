/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2003-2004, Jouni Malinen <jkmaline@cc.hut.fi>
 * Sun elects to license this software under the BSD license.
 * See README for more details.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <sys/ethernet.h>
#include <fcntl.h>
#include <unistd.h>

#include "wpa_impl.h"
#include "wpa_enc.h"
#include "driver.h"
#include "eloop.h"
#include "l2_packet.h"

static void pmksa_cache_set_expiration(struct wpa_supplicant *);

/*
 * IEEE 802.11i/D3.0
 */
static const int WPA_SELECTOR_LEN = 4;
static const uint8_t WPA_OUI_TYPE[] = { 0x00, 0x50, 0xf2, 1 };
static const uint16_t WPA_VERSION = 1;
static const uint8_t
WPA_AUTH_KEY_MGMT_UNSPEC_802_1X[] 		= { 0x00, 0x50, 0xf2, 1 };
static const uint8_t
WPA_AUTH_KEY_MGMT_PSK_OVER_802_1X[] 		= { 0x00, 0x50, 0xf2, 2 };
static const uint8_t WPA_CIPHER_SUITE_NONE[]	= { 0x00, 0x50, 0xf2, 0 };
static const uint8_t WPA_CIPHER_SUITE_WEP40[]	= { 0x00, 0x50, 0xf2, 1 };
static const uint8_t WPA_CIPHER_SUITE_TKIP[]	= { 0x00, 0x50, 0xf2, 2 };
static const uint8_t WPA_CIPHER_SUITE_CCMP[]	= { 0x00, 0x50, 0xf2, 4 };
static const uint8_t WPA_CIPHER_SUITE_WEP104[]	= { 0x00, 0x50, 0xf2, 5 };

/*
 * WPA IE version 1
 * 00-50-f2:1 (OUI:OUI type)
 * 0x01 0x00 (version; little endian)
 * (all following fields are optional:)
 * Group Suite Selector (4 octets) (default: TKIP)
 * Pairwise Suite Count (2 octets, little endian) (default: 1)
 * Pairwise Suite List (4 * n octets) (default: TKIP)
 * Authenticated Key Management Suite Count (2 octets, little endian)
 * (default: 1)
 * Authenticated Key Management Suite List (4 * n octets)
 * (default: unspec 802.1x)
 * WPA Capabilities (2 octets, little endian) (default: 0)
 */
#pragma pack(1)
struct wpa_ie_hdr {
	uint8_t		elem_id;
	uint8_t		len;
	uint8_t		oui[3];
	uint8_t		oui_type;
	uint16_t	version;
};
#pragma pack()

/*
 * IEEE 802.11i/D9.0
 */
static const int RSN_SELECTOR_LEN = 4;
static const uint16_t RSN_VERSION = 1;
static const uint8_t
RSN_AUTH_KEY_MGMT_UNSPEC_802_1X[]		= { 0x00, 0x0f, 0xac, 1 };
static const uint8_t
RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X[]		= { 0x00, 0x0f, 0xac, 2 };
static const uint8_t RSN_CIPHER_SUITE_NONE[]	= { 0x00, 0x0f, 0xac, 0 };
static const uint8_t RSN_CIPHER_SUITE_WEP40[]	= { 0x00, 0x0f, 0xac, 1 };
static const uint8_t RSN_CIPHER_SUITE_TKIP[]	= { 0x00, 0x0f, 0xac, 2 };
static const uint8_t RSN_CIPHER_SUITE_CCMP[]	= { 0x00, 0x0f, 0xac, 4 };
static const uint8_t RSN_CIPHER_SUITE_WEP104[]	= { 0x00, 0x0f, 0xac, 5 };

/*
 * EAPOL-Key Key Data Encapsulation
 * GroupKey and STAKey require encryption, otherwise, encryption is optional.
 */
static const uint8_t RSN_KEY_DATA_GROUPKEY[]	= { 0x00, 0x0f, 0xac, 1 };
static const uint8_t RSN_KEY_DATA_PMKID[]	= { 0x00, 0x0f, 0xac, 4 };

/*
 * 1/4: PMKID
 * 2/4: RSN IE
 * 3/4: one or two RSN IEs + GTK IE (encrypted)
 * 4/4: empty
 * 1/2: GTK IE (encrypted)
 * 2/2: empty
 */

/*
 * RSN IE version 1
 * 0x01 0x00 (version; little endian)
 * (all following fields are optional:)
 * Group Suite Selector (4 octets) (default: CCMP)
 * Pairwise Suite Count (2 octets, little endian) (default: 1)
 * Pairwise Suite List (4 * n octets) (default: CCMP)
 * Authenticated Key Management Suite Count (2 octets, little endian)
 *    (default: 1)
 * Authenticated Key Management Suite List (4 * n octets)
 *    (default: unspec 802.1x)
 * RSN Capabilities (2 octets, little endian) (default: 0)
 * PMKID Count (2 octets) (default: 0)
 * PMKID List (16 * n octets)
 */
#pragma pack(1)
struct rsn_ie_hdr {
	uint8_t		elem_id; /* WLAN_EID_RSN */
	uint8_t		len;
	uint16_t	version;
};
#pragma pack()

static int
random_get_pseudo_bytes(uint8_t *ptr, size_t len)
{
	int fd;
	size_t resid = len;
	size_t bytes;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd == -1) {
		wpa_printf(MSG_ERROR, "Could not open /dev/urandom.\n");
		return (-1);
	}

	while (resid != 0) {
		bytes = read(fd, ptr, resid);
		ptr += bytes;
		resid -= bytes;
	}

	(void) close(fd);

	return (0);
}

static void
inc_byte_array(uint8_t *counter, size_t len)
{
	int pos = len - 1;
	while (pos >= 0) {
		counter[pos]++;
		if (counter[pos] != 0)
			break;
		pos--;
	}
}

static int
wpa_selector_to_bitfield(uint8_t *s)
{
	if (memcmp(s, WPA_CIPHER_SUITE_NONE, WPA_SELECTOR_LEN) == 0)
		return (WPA_CIPHER_NONE);
	if (memcmp(s, WPA_CIPHER_SUITE_WEP40, WPA_SELECTOR_LEN) == 0)
		return (WPA_CIPHER_WEP40);
	if (memcmp(s, WPA_CIPHER_SUITE_TKIP, WPA_SELECTOR_LEN) == 0)
		return (WPA_CIPHER_TKIP);
	if (memcmp(s, WPA_CIPHER_SUITE_CCMP, WPA_SELECTOR_LEN) == 0)
		return (WPA_CIPHER_CCMP);
	if (memcmp(s, WPA_CIPHER_SUITE_WEP104, WPA_SELECTOR_LEN) == 0)
		return (WPA_CIPHER_WEP104);
	return (0);
}

static int
wpa_key_mgmt_to_bitfield(uint8_t *s)
{
	if (memcmp(s, WPA_AUTH_KEY_MGMT_UNSPEC_802_1X, WPA_SELECTOR_LEN) == 0)
		return (WPA_KEY_MGMT_IEEE8021X);
	if (memcmp(s, WPA_AUTH_KEY_MGMT_PSK_OVER_802_1X, WPA_SELECTOR_LEN) ==
	    0)
		return (WPA_KEY_MGMT_PSK);
	return (0);
}

static int
rsn_selector_to_bitfield(uint8_t *s)
{
	if (memcmp(s, RSN_CIPHER_SUITE_NONE, RSN_SELECTOR_LEN) == 0)
		return (WPA_CIPHER_NONE);
	if (memcmp(s, RSN_CIPHER_SUITE_WEP40, RSN_SELECTOR_LEN) == 0)
		return (WPA_CIPHER_WEP40);
	if (memcmp(s, RSN_CIPHER_SUITE_TKIP, RSN_SELECTOR_LEN) == 0)
		return (WPA_CIPHER_TKIP);
	if (memcmp(s, RSN_CIPHER_SUITE_CCMP, RSN_SELECTOR_LEN) == 0)
		return (WPA_CIPHER_CCMP);
	if (memcmp(s, RSN_CIPHER_SUITE_WEP104, RSN_SELECTOR_LEN) == 0)
		return (WPA_CIPHER_WEP104);
	return (0);
}

static int
rsn_key_mgmt_to_bitfield(uint8_t *s)
{
	if (memcmp(s, RSN_AUTH_KEY_MGMT_UNSPEC_802_1X, RSN_SELECTOR_LEN) == 0)
		return (WPA_KEY_MGMT_IEEE8021X);
	if (memcmp(s, RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X, RSN_SELECTOR_LEN) ==
	    0)
		return (WPA_KEY_MGMT_PSK);
	return (0);
}

static void
pmksa_cache_free_entry(struct wpa_supplicant *wpa_s,
	struct rsn_pmksa_cache *entry)
{
	wpa_s->pmksa_count--;
	if (wpa_s->cur_pmksa == entry) {
		wpa_printf(MSG_DEBUG, "RSN: removed current PMKSA entry");
		wpa_s->cur_pmksa = NULL;
	}
	free(entry);
}

/* ARGSUSED */
static void
pmksa_cache_expire(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_supplicant *wpa_s = eloop_ctx;
	time_t now;

	(void) time(&now);
	while (wpa_s->pmksa && wpa_s->pmksa->expiration <= now) {
		struct rsn_pmksa_cache *entry = wpa_s->pmksa;
		wpa_s->pmksa = entry->next;
		wpa_printf(MSG_DEBUG, "RSN: expired PMKSA cache entry for "
		    MACSTR, MAC2STR(entry->aa));
		pmksa_cache_free_entry(wpa_s, entry);
	}

	pmksa_cache_set_expiration(wpa_s);
}

static void
pmksa_cache_set_expiration(struct wpa_supplicant *wpa_s)
{
	int sec;
	eloop_cancel_timeout(pmksa_cache_expire, wpa_s, NULL);
	if (wpa_s->pmksa == NULL)
		return;
	sec = wpa_s->pmksa->expiration - time(NULL);
	if (sec < 0)
		sec = 0;
	(void) eloop_register_timeout(sec + 1, 0, pmksa_cache_expire,
	    wpa_s, NULL);
}

void
pmksa_cache_free(struct wpa_supplicant *wpa_s)
{
	struct rsn_pmksa_cache *entry, *prev;

	entry = wpa_s->pmksa;
	wpa_s->pmksa = NULL;
	while (entry) {
		prev = entry;
		entry = entry->next;
		free(prev);
	}
	pmksa_cache_set_expiration(wpa_s);
	wpa_s->cur_pmksa = NULL;
}

struct rsn_pmksa_cache *
pmksa_cache_get(struct wpa_supplicant *wpa_s,
		uint8_t *aa, uint8_t *pmkid)
{
	struct rsn_pmksa_cache *entry = wpa_s->pmksa;
	while (entry) {
		if ((aa == NULL ||
		    memcmp(entry->aa, aa, IEEE80211_ADDR_LEN) == 0) &&
		    (pmkid == NULL ||
		    memcmp(entry->pmkid, pmkid, PMKID_LEN) == 0))
			return (entry);
		entry = entry->next;
	}
	return (NULL);
}

int
pmksa_cache_list(struct wpa_supplicant *wpa_s, char *buf, size_t len)
{
	int i, j;
	char *pos = buf;
	struct rsn_pmksa_cache *entry;
	time_t now;

	(void) time(&now);
	pos += snprintf(pos, buf + len - pos,
	    "Index / AA / PMKID / expiration (in seconds)\n");
	i = 0;
	entry = wpa_s->pmksa;
	while (entry) {
		i++;
		pos += snprintf(pos, buf + len - pos, "%d " MACSTR " ",
		    i, MAC2STR(entry->aa));
		for (j = 0; j < PMKID_LEN; j++)
			pos += snprintf(pos, buf + len - pos, "%02x",
			    entry->pmkid[j]);
		pos += snprintf(pos, buf + len - pos, " %d\n",
		    (int)(entry->expiration - now));
		entry = entry->next;
	}
	return (pos - buf);
}

void
pmksa_candidate_free(struct wpa_supplicant *wpa_s)
{
	struct rsn_pmksa_candidate *entry, *prev;

	entry = wpa_s->pmksa_candidates;
	wpa_s->pmksa_candidates = NULL;
	while (entry) {
		prev = entry;
		entry = entry->next;
		free(prev);
	}
}

/* ARGSUSED */
static int
wpa_parse_wpa_ie_wpa(struct wpa_supplicant *wpa_s, uint8_t *wpa_ie,
    size_t wpa_ie_len, struct wpa_ie_data *data)
{
	struct wpa_ie_hdr *hdr;
	uint8_t *pos;
	int left;
	int i, count;

	data->proto = WPA_PROTO_WPA;
	data->pairwise_cipher = WPA_CIPHER_TKIP;
	data->group_cipher = WPA_CIPHER_TKIP;
	data->key_mgmt = WPA_KEY_MGMT_IEEE8021X;
	data->capabilities = 0;

	if (wpa_ie_len == 0) {
		/* No WPA IE - fail silently */
		return (-1);
	}

	if (wpa_ie_len < sizeof (struct wpa_ie_hdr)) {
		wpa_printf(MSG_DEBUG, "%s: ie len too short %u",
		    "wpa_parse_wpa_ie_wpa", wpa_ie_len);
		return (-1);
	}

	hdr = (struct wpa_ie_hdr *)wpa_ie;

	if (hdr->elem_id != GENERIC_INFO_ELEM ||
	    hdr->len != wpa_ie_len - 2 ||
	    memcmp(&hdr->oui, WPA_OUI_TYPE, WPA_SELECTOR_LEN) != 0 ||
	    LE_16(hdr->version) != WPA_VERSION) {
		wpa_printf(MSG_DEBUG, "%s: malformed ie or unknown version",
		    "wpa_parse_wpa_ie_wpa");
		return (-1);
	}

	pos = (uint8_t *)(hdr + 1);
	left = wpa_ie_len - sizeof (*hdr);

	if (left >= WPA_SELECTOR_LEN) {
		data->group_cipher = wpa_selector_to_bitfield(pos);
		pos += WPA_SELECTOR_LEN;
		left -= WPA_SELECTOR_LEN;
	} else if (left > 0) {
		wpa_printf(MSG_DEBUG, "%s: ie length mismatch, %u too much",
		    "wpa_parse_wpa_ie_wpa", left);
		return (-1);
	}

	if (left >= 2) {
		data->pairwise_cipher = 0;
		count = pos[0] | (pos[1] << 8);
		pos += 2;
		left -= 2;
		if (count == 0 || left < count * WPA_SELECTOR_LEN) {
			wpa_printf(MSG_DEBUG, "%s: ie count botch (pairwise), "
			    "count %u left %u",
			    "wpa_parse_wpa_ie_wpa", count, left);
			return (-1);
		}
		for (i = 0; i < count; i++) {
			data->pairwise_cipher |= wpa_selector_to_bitfield(pos);
			pos += WPA_SELECTOR_LEN;
			left -= WPA_SELECTOR_LEN;
		}
	} else if (left == 1) {
		wpa_printf(MSG_DEBUG, "%s: ie too short (for key mgmt)",
		    "wpa_parse_wpa_ie_wpa");
		return (-1);
	}

	if (left >= 2) {
		data->key_mgmt = 0;
		count = pos[0] | (pos[1] << 8);
		pos += 2;
		left -= 2;
		if (count == 0 || left < count * WPA_SELECTOR_LEN) {
			wpa_printf(MSG_DEBUG, "%s: ie count botch (key mgmt), "
			    "count %u left %u",
			    "wpa_parse_wpa_ie_wpa", count, left);
			return (-1);
		}
		for (i = 0; i < count; i++) {
			data->key_mgmt |= wpa_key_mgmt_to_bitfield(pos);
			pos += WPA_SELECTOR_LEN;
			left -= WPA_SELECTOR_LEN;
		}
	} else if (left == 1) {
		wpa_printf(MSG_DEBUG, "%s: ie too short (for capabilities)",
		    "wpa_parse_wpa_ie_wpa");
		return (-1);
	}

	if (left >= 2) {
		data->capabilities = pos[0] | (pos[1] << 8);
		pos += 2;
		left -= 2;
	}

	if (left > 0) {
		wpa_printf(MSG_DEBUG, "%s: ie has %u trailing bytes",
		    "wpa_parse_wpa_ie_wpa", left);
		return (-1);
	}

	return (0);
}

/* ARGSUSED */
static int
wpa_parse_wpa_ie_rsn(struct wpa_supplicant *wpa_s, uint8_t *rsn_ie,
    size_t rsn_ie_len, struct wpa_ie_data *data)
{
	struct rsn_ie_hdr *hdr;
	uint8_t *pos;
	int left;
	int i, count;

	data->proto = WPA_PROTO_RSN;
	data->pairwise_cipher = WPA_CIPHER_CCMP;
	data->group_cipher = WPA_CIPHER_CCMP;
	data->key_mgmt = WPA_KEY_MGMT_IEEE8021X;
	data->capabilities = 0;

	if (rsn_ie_len == 0) {
		/* No RSN IE - fail silently */
		return (-1);
	}

	if (rsn_ie_len < sizeof (struct rsn_ie_hdr)) {
		wpa_printf(MSG_DEBUG, "%s: ie len too short %u",
		    "wpa_parse_wpa_ie_rsn", rsn_ie_len);
		return (-1);
	}

	hdr = (struct rsn_ie_hdr *)rsn_ie;

	if (hdr->elem_id != RSN_INFO_ELEM ||
	    hdr->len != rsn_ie_len - 2 ||
	    LE_16(hdr->version) != RSN_VERSION) {
		wpa_printf(MSG_DEBUG, "%s: malformed ie or unknown version",
		    "wpa_parse_wpa_ie_rsn");
		return (-1);
	}

	pos = (uint8_t *)(hdr + 1);
	left = rsn_ie_len - sizeof (*hdr);

	if (left >= RSN_SELECTOR_LEN) {
		data->group_cipher = rsn_selector_to_bitfield(pos);
		pos += RSN_SELECTOR_LEN;
		left -= RSN_SELECTOR_LEN;
	} else if (left > 0) {
		wpa_printf(MSG_DEBUG, "%s: ie length mismatch, %u too much",
		    "wpa_parse_wpa_ie_rsn", left);
		return (-1);
	}

	if (left >= 2) {
		data->pairwise_cipher = 0;
		count = pos[0] | (pos[1] << 8);
		pos += 2;
		left -= 2;
		if (count == 0 || left < count * RSN_SELECTOR_LEN) {
			wpa_printf(MSG_DEBUG, "%s: ie count botch (pairwise), "
			    "count %u left %u",
			    "wpa_parse_wpa_ie_rsn", count, left);
			return (-1);
		}
		for (i = 0; i < count; i++) {
			data->pairwise_cipher |= rsn_selector_to_bitfield(pos);
			pos += RSN_SELECTOR_LEN;
			left -= RSN_SELECTOR_LEN;
		}
	} else if (left == 1) {
		wpa_printf(MSG_DEBUG, "%s: ie too short (for key mgmt)",
		    "wpa_parse_wpa_ie_rsn");
		return (-1);
	}

	if (left >= 2) {
		data->key_mgmt = 0;
		count = pos[0] | (pos[1] << 8);
		pos += 2;
		left -= 2;
		if (count == 0 || left < count * RSN_SELECTOR_LEN) {
			wpa_printf(MSG_DEBUG, "%s: ie count botch (key mgmt), "
			    "count %u left %u",
			    "wpa_parse_wpa_ie_rsn", count, left);
			return (-1);
		}
		for (i = 0; i < count; i++) {
			data->key_mgmt |= rsn_key_mgmt_to_bitfield(pos);
			pos += RSN_SELECTOR_LEN;
			left -= RSN_SELECTOR_LEN;
		}
	} else if (left == 1) {
		wpa_printf(MSG_DEBUG, "%s: ie too short (for capabilities)",
		    "wpa_parse_wpa_ie_rsn");
		return (-1);
	}

	if (left >= 2) {
		data->capabilities = pos[0] | (pos[1] << 8);
		pos += 2;
		left -= 2;
	}

	if (left > 0) {
		/*
		 * RSN IE could include PMKID data, but Authenticator should
		 * never include it, so no need to parse it in the Supplicant.
		 */
		wpa_printf(MSG_DEBUG, "%s: ie has %u trailing bytes - ignored",
		    "wpa_parse_wpa_ie_rsn", left);
	}

	return (0);
}

int
wpa_parse_wpa_ie(struct wpa_supplicant *wpa_s, uint8_t *wpa_ie,
    size_t wpa_ie_len, struct wpa_ie_data *data)
{
	if (wpa_ie_len >= 1 && wpa_ie[0] == RSN_INFO_ELEM)
		return (wpa_parse_wpa_ie_rsn(wpa_s, wpa_ie, wpa_ie_len, data));
	else
		return (wpa_parse_wpa_ie_wpa(wpa_s, wpa_ie, wpa_ie_len, data));
}

static int
wpa_gen_wpa_ie_wpa(struct wpa_supplicant *wpa_s, uint8_t *wpa_ie)
{
	uint8_t *pos;
	struct wpa_ie_hdr *hdr;

	hdr = (struct wpa_ie_hdr *)wpa_ie;
	hdr->elem_id = GENERIC_INFO_ELEM;
	(void) memcpy(&hdr->oui, WPA_OUI_TYPE, WPA_SELECTOR_LEN);
	hdr->version = LE_16(WPA_VERSION);
	pos = (uint8_t *)(hdr + 1);

	if (wpa_s->group_cipher == WPA_CIPHER_CCMP) {
		(void) memcpy(pos, WPA_CIPHER_SUITE_CCMP, WPA_SELECTOR_LEN);
	} else if (wpa_s->group_cipher == WPA_CIPHER_TKIP) {
		(void) memcpy(pos, WPA_CIPHER_SUITE_TKIP, WPA_SELECTOR_LEN);
	} else if (wpa_s->group_cipher == WPA_CIPHER_WEP104) {
		(void) memcpy(pos, WPA_CIPHER_SUITE_WEP104, WPA_SELECTOR_LEN);
	} else if (wpa_s->group_cipher == WPA_CIPHER_WEP40) {
		(void) memcpy(pos, WPA_CIPHER_SUITE_WEP40, WPA_SELECTOR_LEN);
	} else {
		wpa_printf(MSG_WARNING, "Invalid group cipher (%d).",
		    wpa_s->group_cipher);
		return (-1);
	}
	pos += WPA_SELECTOR_LEN;

	*pos++ = 1;
	*pos++ = 0;
	if (wpa_s->pairwise_cipher == WPA_CIPHER_CCMP) {
		(void) memcpy(pos, WPA_CIPHER_SUITE_CCMP, WPA_SELECTOR_LEN);
	} else if (wpa_s->pairwise_cipher == WPA_CIPHER_TKIP) {
		(void) memcpy(pos, WPA_CIPHER_SUITE_TKIP, WPA_SELECTOR_LEN);
	} else if (wpa_s->pairwise_cipher == WPA_CIPHER_NONE) {
		(void) memcpy(pos, WPA_CIPHER_SUITE_NONE, WPA_SELECTOR_LEN);
	} else {
		wpa_printf(MSG_WARNING, "Invalid pairwise cipher (%d).",
		    wpa_s->pairwise_cipher);
		return (-1);
	}
	pos += WPA_SELECTOR_LEN;

	*pos++ = 1;
	*pos++ = 0;
	if (wpa_s->key_mgmt == WPA_KEY_MGMT_IEEE8021X) {
		(void) memcpy(pos, WPA_AUTH_KEY_MGMT_UNSPEC_802_1X,
		    WPA_SELECTOR_LEN);
	} else if (wpa_s->key_mgmt == WPA_KEY_MGMT_PSK) {
		(void) memcpy(pos, WPA_AUTH_KEY_MGMT_PSK_OVER_802_1X,
		    WPA_SELECTOR_LEN);
	} else {
		wpa_printf(MSG_WARNING, "Invalid key management type (%d).",
		    wpa_s->key_mgmt);
		return (-1);
	}
	pos += WPA_SELECTOR_LEN;

	/*
	 * WPA Capabilities; use defaults, so no need to include it
	 */
	hdr->len = (pos - wpa_ie) - 2;

	return (pos - wpa_ie);
}

static int
wpa_gen_wpa_ie_rsn(struct wpa_supplicant *wpa_s, uint8_t *rsn_ie)
{
	uint8_t *pos;
	struct rsn_ie_hdr *hdr;

	hdr = (struct rsn_ie_hdr *)rsn_ie;
	hdr->elem_id = RSN_INFO_ELEM;
	hdr->version = LE_16(RSN_VERSION);
	pos = (uint8_t *)(hdr + 1);

	if (wpa_s->group_cipher == WPA_CIPHER_CCMP) {
		(void) memcpy(pos, RSN_CIPHER_SUITE_CCMP, RSN_SELECTOR_LEN);
	} else if (wpa_s->group_cipher == WPA_CIPHER_TKIP) {
		(void) memcpy(pos, RSN_CIPHER_SUITE_TKIP, RSN_SELECTOR_LEN);
	} else if (wpa_s->group_cipher == WPA_CIPHER_WEP104) {
		(void) memcpy(pos, RSN_CIPHER_SUITE_WEP104, RSN_SELECTOR_LEN);
	} else if (wpa_s->group_cipher == WPA_CIPHER_WEP40) {
		(void) memcpy(pos, RSN_CIPHER_SUITE_WEP40, RSN_SELECTOR_LEN);
	} else {
		wpa_printf(MSG_WARNING, "Invalid group cipher (%d).",
		    wpa_s->group_cipher);
		return (-1);
	}
	pos += RSN_SELECTOR_LEN;

	*pos++ = 1;
	*pos++ = 0;
	if (wpa_s->pairwise_cipher == WPA_CIPHER_CCMP) {
		(void) memcpy(pos, RSN_CIPHER_SUITE_CCMP, RSN_SELECTOR_LEN);
	} else if (wpa_s->pairwise_cipher == WPA_CIPHER_TKIP) {
		(void) memcpy(pos, RSN_CIPHER_SUITE_TKIP, RSN_SELECTOR_LEN);
	} else if (wpa_s->pairwise_cipher == WPA_CIPHER_NONE) {
		(void) memcpy(pos, RSN_CIPHER_SUITE_NONE, RSN_SELECTOR_LEN);
	} else {
		wpa_printf(MSG_WARNING, "Invalid pairwise cipher (%d).",
		    wpa_s->pairwise_cipher);
		return (-1);
	}
	pos += RSN_SELECTOR_LEN;

	*pos++ = 1;
	*pos++ = 0;
	if (wpa_s->key_mgmt == WPA_KEY_MGMT_IEEE8021X) {
		(void) memcpy(pos, RSN_AUTH_KEY_MGMT_UNSPEC_802_1X,
		    RSN_SELECTOR_LEN);
	} else if (wpa_s->key_mgmt == WPA_KEY_MGMT_PSK) {
		(void) memcpy(pos, RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X,
		    RSN_SELECTOR_LEN);
	} else {
		wpa_printf(MSG_WARNING, "Invalid key management type (%d).",
		    wpa_s->key_mgmt);
		return (-1);
	}
	pos += RSN_SELECTOR_LEN;

	/* RSN Capabilities */
	*pos++ = 0;
	*pos++ = 0;

	if (wpa_s->cur_pmksa) {
		/* PMKID Count (2 octets, little endian) */
		*pos++ = 1;
		*pos++ = 0;
		/* PMKID */
		(void) memcpy(pos, wpa_s->cur_pmksa->pmkid, PMKID_LEN);
		pos += PMKID_LEN;
	}

	hdr->len = (pos - rsn_ie) - 2;

	return (pos - rsn_ie);
}

int
wpa_gen_wpa_ie(struct wpa_supplicant *wpa_s, uint8_t *wpa_ie)
{
	if (wpa_s->proto == WPA_PROTO_RSN)
		return (wpa_gen_wpa_ie_rsn(wpa_s, wpa_ie));
	else
		return (wpa_gen_wpa_ie_wpa(wpa_s, wpa_ie));
}

static void
wpa_pmk_to_ptk(uint8_t *pmk, uint8_t *addr1, uint8_t *addr2,
    uint8_t *nonce1, uint8_t *nonce2, uint8_t *ptk, size_t ptk_len)
{
	uint8_t data[2 * IEEE80211_ADDR_LEN + 2 * WPA_PMK_LEN];

	/*
	 * PTK = PRF-X(PMK, "Pairwise key expansion",
	 * 	Min(AA, SA) || Max(AA, SA) ||
	 * 	Min(ANonce, SNonce) || Max(ANonce, SNonce))
	 */

	if (memcmp(addr1, addr2, IEEE80211_ADDR_LEN) < 0) {
		(void) memcpy(data, addr1, IEEE80211_ADDR_LEN);
		(void) memcpy(data + IEEE80211_ADDR_LEN, addr2,
		    IEEE80211_ADDR_LEN);
	} else {
		(void) memcpy(data, addr2, IEEE80211_ADDR_LEN);
		(void) memcpy(data + IEEE80211_ADDR_LEN, addr1,
		    IEEE80211_ADDR_LEN);
	}

	if (memcmp(nonce1, nonce2, WPA_PMK_LEN) < 0) {
		(void) memcpy(data + 2 * IEEE80211_ADDR_LEN, nonce1,
		    WPA_PMK_LEN);
		(void) memcpy(data + 2 * IEEE80211_ADDR_LEN + WPA_PMK_LEN,
		    nonce2, WPA_PMK_LEN);
	} else {
		(void) memcpy(data + 2 * IEEE80211_ADDR_LEN, nonce2,
		    WPA_PMK_LEN);
		(void) memcpy(data + 2 * IEEE80211_ADDR_LEN + WPA_PMK_LEN,
		    nonce1, WPA_PMK_LEN);
	}

	sha1_prf(pmk, WPA_PMK_LEN, "Pairwise key expansion", data,
	    sizeof (data), ptk, ptk_len);

	wpa_hexdump(MSG_DEBUG, "WPA: PMK", pmk, WPA_PMK_LEN);
	wpa_hexdump(MSG_DEBUG, "WPA: PTK", ptk, ptk_len);
}

struct wpa_ssid *
wpa_supplicant_get_ssid(struct wpa_supplicant *wpa_s)
{
	struct wpa_ssid *entry;
	uint8_t ssid[MAX_ESSID_LENGTH];
	int ssid_len;
	uint8_t bssid[IEEE80211_ADDR_LEN];

	(void) memset(ssid, 0, MAX_ESSID_LENGTH);
	ssid_len = wpa_s->driver->get_ssid(wpa_s->linkid, (char *)ssid);
	if (ssid_len < 0) {
		wpa_printf(MSG_WARNING, "Could not read SSID from driver.");
		return (NULL);
	}

	if (wpa_s->driver->get_bssid(wpa_s->linkid, (char *)bssid) < 0) {
		wpa_printf(MSG_WARNING, "Could not read BSSID from driver.");
		return (NULL);
	}

	entry = wpa_s->conf->ssid;
	wpa_printf(MSG_DEBUG, "entry len=%d ssid=%s,"
	    " driver len=%d ssid=%s",
	    entry->ssid_len, entry->ssid, ssid_len, ssid);

	if (ssid_len == entry->ssid_len &&
	    memcmp(ssid, entry->ssid, ssid_len) == 0 &&
	    (!entry->bssid_set ||
	    memcmp(bssid, entry->bssid, IEEE80211_ADDR_LEN) == 0))
		return (entry);

	return (NULL);
}

static void
wpa_eapol_key_mic(uint8_t *key, int ver, uint8_t *buf, size_t len, uint8_t *mic)
{
	if (ver == WPA_KEY_INFO_TYPE_HMAC_MD5_RC4) {
		hmac_md5(key, 16, buf, len, mic);
	} else if (ver == WPA_KEY_INFO_TYPE_HMAC_SHA1_AES) {
		uint8_t hash[SHA1_MAC_LEN];
		hmac_sha1(key, 16, buf, len, hash);
		(void) memcpy(mic, hash, MD5_MAC_LEN);
	}
}

void
wpa_supplicant_key_request(struct wpa_supplicant *wpa_s,
	int error, int pairwise)
{
	int rlen;
	struct ieee802_1x_hdr *hdr;
	struct wpa_eapol_key *reply;
	unsigned char *rbuf;
	struct l2_ethhdr *ethhdr;
	int key_info, ver;
	uint8_t bssid[IEEE80211_ADDR_LEN];

	if (wpa_s->pairwise_cipher == WPA_CIPHER_CCMP)
		ver = WPA_KEY_INFO_TYPE_HMAC_SHA1_AES;
	else
		ver = WPA_KEY_INFO_TYPE_HMAC_MD5_RC4;

	if (wpa_s->driver->get_bssid(wpa_s->linkid, (char *)bssid) < 0) {
		wpa_printf(MSG_WARNING, "Failed to read BSSID for EAPOL-Key "
		    "request");
		return;
	}

	rlen = sizeof (*ethhdr) + sizeof (*hdr) + sizeof (*reply);
	rbuf = malloc(rlen);
	if (rbuf == NULL)
		return;

	(void) memset(rbuf, 0, rlen);
	ethhdr = (struct l2_ethhdr *)rbuf;
	(void) memcpy(ethhdr->h_dest, bssid, IEEE80211_ADDR_LEN);
	(void) memcpy(ethhdr->h_source, wpa_s->own_addr, IEEE80211_ADDR_LEN);
	ethhdr->h_proto = htons(ETHERTYPE_EAPOL);

	hdr = (struct ieee802_1x_hdr *)(ethhdr + 1);
	hdr->version = wpa_s->conf->eapol_version;
	hdr->type = IEEE802_1X_TYPE_EAPOL_KEY;
	hdr->length = htons(sizeof (*reply));

	reply = (struct wpa_eapol_key *)(hdr + 1);
	reply->type = wpa_s->proto == WPA_PROTO_RSN ?
	    EAPOL_KEY_TYPE_RSN : EAPOL_KEY_TYPE_WPA;
	key_info = WPA_KEY_INFO_REQUEST | ver;
	if (wpa_s->ptk_set)
		key_info |= WPA_KEY_INFO_MIC;
	if (error)
		key_info |= WPA_KEY_INFO_ERROR;
	if (pairwise)
		key_info |= WPA_KEY_INFO_KEY_TYPE;
	reply->key_info = BE_16(key_info);
	reply->key_length = 0;
	(void) memcpy(reply->replay_counter, wpa_s->request_counter,
	    WPA_REPLAY_COUNTER_LEN);
	inc_byte_array(wpa_s->request_counter, WPA_REPLAY_COUNTER_LEN);

	reply->key_data_length = BE_16(0);

	if (key_info & WPA_KEY_INFO_MIC) {
		wpa_eapol_key_mic(wpa_s->ptk.mic_key, ver, (uint8_t *)hdr,
		    rlen - sizeof (*ethhdr), reply->key_mic);
	}

	wpa_printf(MSG_INFO, "WPA: Sending EAPOL-Key Request (error=%d "
	    "pairwise=%d ptk_set=%d len=%d)",
	    error, pairwise, wpa_s->ptk_set, rlen);
	wpa_hexdump(MSG_MSGDUMP, "WPA: TX EAPOL-Key Request", rbuf, rlen);
	(void) l2_packet_send(wpa_s->l2, rbuf, rlen);
	free(rbuf);
}

static void
wpa_supplicant_process_1_of_4(struct wpa_supplicant *wpa_s,
    unsigned char *src_addr, struct wpa_eapol_key *key, int ver)
{
	int rlen;
	struct ieee802_1x_hdr *hdr;
	struct wpa_eapol_key *reply;
	unsigned char *rbuf;
	struct l2_ethhdr *ethhdr;
	struct wpa_ssid *ssid;
	struct wpa_ptk *ptk;
	uint8_t buf[8], wpa_ie_buf[80], *wpa_ie, *pmkid = NULL;
	int wpa_ie_len;

	wpa_s->wpa_state = WPA_4WAY_HANDSHAKE;
	wpa_printf(MSG_DEBUG, "WPA: RX message 1 of 4-Way Handshake from "
	    MACSTR " (ver=%d)", MAC2STR(src_addr), ver);

	ssid = wpa_supplicant_get_ssid(wpa_s);
	if (ssid == NULL) {
		wpa_printf(MSG_WARNING,
		    "WPA: No SSID info found (msg 1 of 4).");
		return;
	}

	if (wpa_s->proto == WPA_PROTO_RSN) {
		/* RSN: msg 1/4 should contain PMKID for the selected PMK */
		uint8_t *pos = (uint8_t *)(key + 1);
		uint8_t *end = pos + BE_16(key->key_data_length);

		wpa_hexdump(MSG_DEBUG, "RSN: msg 1/4 key data",
		    pos, BE_16(key->key_data_length));

		while (pos + 1 < end) {
			if (pos + 2 + pos[1] > end) {
				wpa_printf(MSG_DEBUG, "RSN: key data "
				    "underflow (ie=%d len=%d)",
				    pos[0], pos[1]);
				break;
			}
			if (pos[0] == GENERIC_INFO_ELEM &&
			    pos + 1 + RSN_SELECTOR_LEN < end &&
			    pos[1] >= RSN_SELECTOR_LEN + PMKID_LEN &&
			    memcmp(pos + 2, RSN_KEY_DATA_PMKID,
			    RSN_SELECTOR_LEN) == 0) {
				pmkid = pos + 2 + RSN_SELECTOR_LEN;
				wpa_hexdump(MSG_DEBUG, "RSN: PMKID from "
				    "Authenticator", pmkid, PMKID_LEN);
				break;
			} else if (pos[0] == GENERIC_INFO_ELEM && pos[1] == 0)
				break;
			pos += 2 + pos[1];
		}
	}

	wpa_ie = wpa_ie_buf;
	wpa_ie_len = wpa_gen_wpa_ie(wpa_s, wpa_ie);
	if (wpa_ie_len < 0) {
		wpa_printf(MSG_WARNING, "WPA: Failed to generate "
		    "WPA IE (for msg 2 of 4).");
		return;
	}
	wpa_hexdump(MSG_DEBUG, "WPA: WPA IE for msg 2/4", wpa_ie, wpa_ie_len);

	rlen = sizeof (*ethhdr) + sizeof (*hdr) + sizeof (*reply) + wpa_ie_len;
	rbuf = malloc(rlen);
	if (rbuf == NULL)
		return;

	(void) memset(rbuf, 0, rlen);
	ethhdr = (struct l2_ethhdr *)rbuf;
	(void) memcpy(ethhdr->h_dest, src_addr, IEEE80211_ADDR_LEN);
	(void) memcpy(ethhdr->h_source, wpa_s->own_addr, IEEE80211_ADDR_LEN);
	ethhdr->h_proto = htons(ETHERTYPE_EAPOL);

	hdr = (struct ieee802_1x_hdr *)(ethhdr + 1);
	hdr->version = wpa_s->conf->eapol_version;
	hdr->type = IEEE802_1X_TYPE_EAPOL_KEY;
	hdr->length = htons(sizeof (*reply) + wpa_ie_len);

	reply = (struct wpa_eapol_key *)(hdr + 1);
	reply->type = wpa_s->proto == WPA_PROTO_RSN ?
	    EAPOL_KEY_TYPE_RSN : EAPOL_KEY_TYPE_WPA;
	reply->key_info = BE_16(ver | WPA_KEY_INFO_KEY_TYPE | WPA_KEY_INFO_MIC);
	reply->key_length = key->key_length;
	(void) memcpy(reply->replay_counter, key->replay_counter,
	    WPA_REPLAY_COUNTER_LEN);

	reply->key_data_length = BE_16(wpa_ie_len);
	(void) memcpy(reply + 1, wpa_ie, wpa_ie_len);

	if (wpa_s->renew_snonce) {
		if (random_get_pseudo_bytes(wpa_s->snonce, WPA_NONCE_LEN)) {
			wpa_printf(MSG_WARNING, "WPA: Failed to get "
			    "random data for SNonce");
			free(rbuf);
			return;
		}

		wpa_s->renew_snonce = 0;
		wpa_hexdump(MSG_DEBUG, "WPA: Renewed SNonce",
		    wpa_s->snonce, WPA_NONCE_LEN);
	}
	(void) memcpy(reply->key_nonce, wpa_s->snonce, WPA_NONCE_LEN);
	ptk = &wpa_s->tptk;
	(void) memcpy(wpa_s->anonce, key->key_nonce, WPA_NONCE_LEN);

	wpa_pmk_to_ptk(wpa_s->pmk, wpa_s->own_addr, src_addr,
	    wpa_s->snonce, key->key_nonce, (uint8_t *)ptk, sizeof (*ptk));

	/*
	 * Supplicant: swap tx/rx Mic keys
	 */
	(void) memcpy(buf, ptk->u.auth.tx_mic_key, 8);
	(void) memcpy(ptk->u.auth.tx_mic_key, ptk->u.auth.rx_mic_key, 8);
	(void) memcpy(ptk->u.auth.rx_mic_key, buf, 8);
	wpa_s->tptk_set = 1;
	wpa_eapol_key_mic(wpa_s->tptk.mic_key, ver, (uint8_t *)hdr,
	    rlen - sizeof (*ethhdr), reply->key_mic);
	wpa_hexdump(MSG_DEBUG, "WPA: EAPOL-Key MIC", reply->key_mic, 16);

	wpa_printf(MSG_DEBUG, "WPA: Sending EAPOL-Key 2/4");
	wpa_hexdump(MSG_MSGDUMP, "WPA: TX EAPOL-Key 2/4", rbuf, rlen);
	(void) l2_packet_send(wpa_s->l2, rbuf, rlen);

	free(rbuf);
}

static void
wpa_supplicant_process_3_of_4_gtk(struct wpa_supplicant *wpa_s,
    unsigned char *src_addr, struct wpa_eapol_key *key,
    uint8_t *gtk, int gtk_len)
{
	int keyidx, tx, key_rsc_len = 0, alg;

	wpa_hexdump(MSG_DEBUG,
	    "WPA: received GTK in pairwise handshake", gtk, gtk_len);

	keyidx = gtk[0] & 0x3;
	tx = !!(gtk[0] & BIT(2));
	if (tx && wpa_s->pairwise_cipher != WPA_CIPHER_NONE) {
		/*
		 * Ignore Tx bit in GTK IE if a pairwise key is used.
		 * One AP seemed to set this bit (incorrectly, since Tx
		 * is only when doing Group Key only APs) and without
		 * this workaround, the data connection does not work
		 * because wpa_supplicant configured non-zero keyidx to
		 * be used for unicast.
		 */
		wpa_printf(MSG_INFO, "RSN: Tx bit set for GTK IE, but "
		    "pairwise keys are used - ignore Tx bit");
		tx = 0;
	}

	gtk += 2;
	gtk_len -= 2;
	wpa_hexdump(MSG_DEBUG, "WPA: Group Key", gtk, gtk_len);

	switch (wpa_s->group_cipher) {
	case WPA_CIPHER_CCMP:
		if (gtk_len != 16) {
			wpa_printf(MSG_WARNING, "WPA: Unsupported CCMP"
			    " Group Cipher key length %d.", gtk_len);
			return;
		}
		key_rsc_len = 6;
		alg = WPA_ALG_CCMP;
		break;
	case WPA_CIPHER_TKIP:
		if (gtk_len != 32) {
			wpa_printf(MSG_WARNING, "WPA: Unsupported TKIP"
			    " Group Cipher key length %d.", gtk_len);
			return;
		}
		key_rsc_len = 6;
		alg = WPA_ALG_TKIP;
		break;
	case WPA_CIPHER_WEP104:
		if (gtk_len != 13) {
			wpa_printf(MSG_WARNING, "WPA: Unsupported "
			    "WEP104 Group Cipher key length " "%d.", gtk_len);
			return;
		}
		alg = WPA_ALG_WEP;
		break;
	case WPA_CIPHER_WEP40:
		if (gtk_len != 5) {
			wpa_printf(MSG_WARNING, "WPA: Unsupported "
			    "WEP40 Group Cipher key length %d.", gtk_len);
			return;
		}
		alg = WPA_ALG_WEP;
		break;
	default:
		wpa_printf(MSG_WARNING, "WPA: Unsupport Group Cipher "
		    "%d", wpa_s->group_cipher);
		return;
	}

	wpa_printf(MSG_DEBUG, "WPA: Installing GTK to the driver "
	    "(keyidx=%d tx=%d).", keyidx, tx);
	wpa_hexdump(MSG_DEBUG, "WPA: RSC", key->key_rsc, key_rsc_len);
	if (wpa_s->group_cipher == WPA_CIPHER_TKIP) {
		uint8_t tmpbuf[8];
		/*
		 * Swap Tx/Rx keys for Michael MIC
		 */
		(void) memcpy(tmpbuf, gtk + 16, 8);
		(void) memcpy(gtk + 16, gtk + 24, 8);
		(void) memcpy(gtk + 24, tmpbuf, 8);
	}
	if (wpa_s->pairwise_cipher == WPA_CIPHER_NONE) {
		if (wpa_s->driver->set_key(wpa_s->linkid, alg,
		    (uint8_t *)"\xff\xff\xff\xff\xff\xff",
		    keyidx, 1, key->key_rsc,
		    key_rsc_len, gtk, gtk_len) < 0)
			wpa_printf(MSG_WARNING, "WPA: Failed to set "
			    "GTK to the driver (Group only).");
	} else if (wpa_s->driver->set_key(wpa_s->linkid, alg,
	    (uint8_t *)"\xff\xff\xff\xff\xff\xff", keyidx, tx,
	    key->key_rsc, key_rsc_len, gtk, gtk_len) < 0) {
		wpa_printf(MSG_WARNING, "WPA: Failed to set GTK to "
		    "the driver.");
	}

	wpa_printf(MSG_INFO, "WPA: Key negotiation completed with "
	    MACSTR, MAC2STR(src_addr));
	eloop_cancel_timeout(wpa_supplicant_scan, wpa_s, NULL);
	wpa_supplicant_cancel_auth_timeout(wpa_s);
	wpa_s->wpa_state = WPA_COMPLETED;
}

static void
wpa_supplicant_process_3_of_4(struct wpa_supplicant *wpa_s,
    unsigned char *src_addr, struct wpa_eapol_key *key,
    int extra_len, int ver)
{
	int rlen;
	struct ieee802_1x_hdr *hdr;
	struct wpa_eapol_key *reply;
	unsigned char *rbuf;
	struct l2_ethhdr *ethhdr;
	int key_info, ie_len = 0, keylen, gtk_len = 0;
	uint8_t *ie = NULL, *gtk = NULL, *key_rsc;
	uint8_t null_rsc[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };

	wpa_s->wpa_state = WPA_4WAY_HANDSHAKE;
	wpa_printf(MSG_DEBUG, "WPA: RX message 3 of 4-Way Handshake from "
	    MACSTR " (ver=%d)", MAC2STR(src_addr), ver);

	key_info = BE_16(key->key_info);

	if (wpa_s->proto == WPA_PROTO_RSN) {
		uint8_t *pos = (uint8_t *)(key + 1);
		uint8_t *end = pos + BE_16(key->key_data_length);
		while (pos + 1 < end) {
			if (pos + 2 + pos[1] > end) {
				wpa_printf(MSG_DEBUG, "RSN: key data "
				    "underflow (ie=%d len=%d)",
				    pos[0], pos[1]);
				break;
			}
			if (*pos == RSN_INFO_ELEM) {
				ie = pos;
				ie_len = pos[1] + 2;
			} else if (pos[0] == GENERIC_INFO_ELEM &&
			    pos + 1 + RSN_SELECTOR_LEN < end &&
			    pos[1] > RSN_SELECTOR_LEN + 2 &&
			    memcmp(pos + 2, RSN_KEY_DATA_GROUPKEY,
			    RSN_SELECTOR_LEN) == 0) {
				if (!(key_info & WPA_KEY_INFO_ENCR_KEY_DATA)) {
					wpa_printf(MSG_WARNING, "WPA: GTK IE "
					    "in unencrypted key data");
					return;
				}
				gtk = pos + 2 + RSN_SELECTOR_LEN;
				gtk_len = pos[1] - RSN_SELECTOR_LEN;
			} else if (pos[0] == GENERIC_INFO_ELEM && pos[1] == 0)
				break;

			pos += 2 + pos[1];
		}
	} else {
		ie = (uint8_t *)(key + 1);
		ie_len = BE_16(key->key_data_length);
		if (ie_len > extra_len) {
			wpa_printf(MSG_INFO, "WPA: Truncated EAPOL-Key packet:"
			    " ie_len=%d > extra_len=%d",
			    ie_len, extra_len);
			return;
		}
	}

	if (wpa_s->ap_wpa_ie &&
	    (wpa_s->ap_wpa_ie_len != ie_len ||
	    memcmp(wpa_s->ap_wpa_ie, ie, ie_len) != 0)) {
		wpa_printf(MSG_WARNING, "WPA: WPA IE in 3/4 msg does not match"
		    " with WPA IE in Beacon/ProbeResp (src=" MACSTR ")",
		    MAC2STR(src_addr));
		wpa_hexdump(MSG_INFO, "WPA: WPA IE in Beacon/ProbeResp",
		    wpa_s->ap_wpa_ie, wpa_s->ap_wpa_ie_len);
		wpa_hexdump(MSG_INFO, "WPA: WPA IE in 3/4 msg", ie, ie_len);
		wpa_supplicant_disassociate(wpa_s, REASON_IE_IN_4WAY_DIFFERS);
		wpa_supplicant_req_scan(wpa_s, 0, 0);
		return;
	}

	if (memcmp(wpa_s->anonce, key->key_nonce, WPA_NONCE_LEN) != 0) {
		wpa_printf(MSG_WARNING, "WPA: ANonce from message 1 of 4-Way "
		    "Handshake differs from 3 of 4-Way Handshake - drop"
		    " packet (src=" MACSTR ")", MAC2STR(src_addr));
		return;
	}

	keylen = BE_16(key->key_length);
	switch (wpa_s->pairwise_cipher) {
	case WPA_CIPHER_CCMP:
		if (keylen != 16) {
			wpa_printf(MSG_WARNING, "WPA: Invalid CCMP key length "
			    "%d (src=" MACSTR ")",
			    keylen, MAC2STR(src_addr));
			return;
		}
		break;
	case WPA_CIPHER_TKIP:
		if (keylen != 32) {
			wpa_printf(MSG_WARNING, "WPA: Invalid TKIP key length "
			    "%d (src=" MACSTR ")",
			    keylen, MAC2STR(src_addr));
			return;
		}
		break;
	}

	rlen = sizeof (*ethhdr) + sizeof (*hdr) + sizeof (*reply);
	rbuf = malloc(rlen);
	if (rbuf == NULL)
		return;

	(void) memset(rbuf, 0, rlen);
	ethhdr = (struct l2_ethhdr *)rbuf;
	(void) memcpy(ethhdr->h_dest, src_addr, IEEE80211_ADDR_LEN);
	(void) memcpy(ethhdr->h_source, wpa_s->own_addr, IEEE80211_ADDR_LEN);
	ethhdr->h_proto = htons(ETHERTYPE_EAPOL);

	hdr = (struct ieee802_1x_hdr *)(ethhdr + 1);
	hdr->version = wpa_s->conf->eapol_version;
	hdr->type = IEEE802_1X_TYPE_EAPOL_KEY;
	hdr->length = htons(sizeof (*reply));

	reply = (struct wpa_eapol_key *)(hdr + 1);
	reply->type = wpa_s->proto == WPA_PROTO_RSN ?
	    EAPOL_KEY_TYPE_RSN : EAPOL_KEY_TYPE_WPA;
	reply->key_info = BE_16(ver | WPA_KEY_INFO_KEY_TYPE |
	    WPA_KEY_INFO_MIC | (key_info & WPA_KEY_INFO_SECURE));
	reply->key_length = key->key_length;
	(void) memcpy(reply->replay_counter, key->replay_counter,
	    WPA_REPLAY_COUNTER_LEN);

	reply->key_data_length = BE_16(0);

	(void) memcpy(reply->key_nonce, wpa_s->snonce, WPA_NONCE_LEN);
	wpa_eapol_key_mic(wpa_s->ptk.mic_key, ver, (uint8_t *)hdr,
	    rlen - sizeof (*ethhdr), reply->key_mic);

	wpa_printf(MSG_DEBUG, "WPA: Sending EAPOL-Key 4/4");
	wpa_hexdump(MSG_MSGDUMP, "WPA: TX EAPOL-Key 4/4", rbuf, rlen);
	(void) l2_packet_send(wpa_s->l2, rbuf, rlen);

	free(rbuf);

	/*
	 * SNonce was successfully used in msg 3/4, so mark it to be renewed
	 * for the next 4-Way Handshake. If msg 3 is received again, the old
	 * SNonce will still be used to avoid changing PTK.
	 */
	wpa_s->renew_snonce = 1;

	if (key_info & WPA_KEY_INFO_INSTALL) {
		int alg, keylen, rsclen;
		wpa_printf(MSG_DEBUG, "WPA: Installing PTK to the driver.");
		switch (wpa_s->pairwise_cipher) {
		case WPA_CIPHER_CCMP:
			alg = WPA_ALG_CCMP;
			keylen = 16;
			rsclen = 6;
			break;
		case WPA_CIPHER_TKIP:
			alg = WPA_ALG_TKIP;
			keylen = 32;
			rsclen = 6;
			break;
		case WPA_CIPHER_NONE:
			wpa_printf(MSG_DEBUG, "WPA: Pairwise Cipher Suite: "
			    "NONE - do not use pairwise keys");
			return;
		default:
			wpa_printf(MSG_WARNING, "WPA: Unsupported pairwise "
			    "cipher %d", wpa_s->pairwise_cipher);
			return;
		}
		if (wpa_s->proto == WPA_PROTO_RSN) {
			key_rsc = null_rsc;
		} else {
			key_rsc = key->key_rsc;
			wpa_hexdump(MSG_DEBUG, "WPA: RSC", key_rsc, rsclen);
		}

		if (wpa_s->driver->set_key(wpa_s->linkid, alg, src_addr,
		    0, 1, key_rsc, rsclen,
		    (uint8_t *)&wpa_s->ptk.tk1, keylen) < 0) {
			wpa_printf(MSG_WARNING, "WPA: Failed to set PTK to the"
			    " driver.");
		}
	}

	wpa_printf(MSG_DEBUG, "%s: key_info=%x gtk=%p\n",
	    "wpa_supplicant_process_3_of_4", key_info, gtk);
	wpa_s->wpa_state = WPA_GROUP_HANDSHAKE;

	if (gtk)
		wpa_supplicant_process_3_of_4_gtk(wpa_s,
		    src_addr, key, gtk, gtk_len);
}

static void
wpa_supplicant_process_1_of_2(struct wpa_supplicant *wpa_s,
    unsigned char *src_addr, struct wpa_eapol_key *key,
    int extra_len, int ver)
{
	int rlen;
	struct ieee802_1x_hdr *hdr;
	struct wpa_eapol_key *reply;
	unsigned char *rbuf;
	struct l2_ethhdr *ethhdr;
	int key_info, keylen, keydatalen, maxkeylen, keyidx, key_rsc_len = 0;
	int alg, tx;
	uint8_t ek[32], tmpbuf[8], gtk[32];
	uint8_t *gtk_ie = NULL;
	size_t gtk_ie_len = 0;

	wpa_s->wpa_state = WPA_GROUP_HANDSHAKE;
	wpa_printf(MSG_DEBUG, "WPA: RX message 1 of Group Key Handshake from "
	    MACSTR " (ver=%d)", MAC2STR(src_addr), ver);

	key_info = BE_16(key->key_info);
	keydatalen = BE_16(key->key_data_length);

	if (wpa_s->proto == WPA_PROTO_RSN) {
		uint8_t *pos = (uint8_t *)(key + 1);
		uint8_t *end = pos + keydatalen;
		while (pos + 1 < end) {
			if (pos + 2 + pos[1] > end) {
				wpa_printf(MSG_DEBUG, "RSN: key data "
				    "underflow (ie=%d len=%d)",
				    pos[0], pos[1]);
				break;
			}
			if (pos[0] == GENERIC_INFO_ELEM &&
			    pos + 1 + RSN_SELECTOR_LEN < end &&
			    pos[1] > RSN_SELECTOR_LEN + 2 &&
			    memcmp(pos + 2, RSN_KEY_DATA_GROUPKEY,
			    RSN_SELECTOR_LEN) == 0) {
				if (!(key_info & WPA_KEY_INFO_ENCR_KEY_DATA)) {
					wpa_printf(MSG_WARNING, "WPA: GTK IE "
					    "in unencrypted key data");
					return;
				}
				gtk_ie = pos + 2 + RSN_SELECTOR_LEN;
				gtk_ie_len = pos[1] - RSN_SELECTOR_LEN;
				break;
			} else if (pos[0] == GENERIC_INFO_ELEM && pos[1] == 0) {
				break;
			}

			pos += 2 + pos[1];
		}

		if (gtk_ie == NULL) {
			wpa_printf(MSG_INFO, "WPA: No GTK IE in Group Key "
			    "message 1/2");
			return;
		}
		maxkeylen = keylen = gtk_ie_len - 2;
	} else {
		keylen = BE_16(key->key_length);
		maxkeylen = keydatalen;
		if (keydatalen > extra_len) {
			wpa_printf(MSG_INFO, "WPA: Truncated EAPOL-Key packet:"
			    " key_data_length=%d > extra_len=%d",
			    keydatalen, extra_len);
			return;
		}
		if (ver == WPA_KEY_INFO_TYPE_HMAC_SHA1_AES)
			maxkeylen -= 8;
	}

	switch (wpa_s->group_cipher) {
	case WPA_CIPHER_CCMP:
		if (keylen != 16 || maxkeylen < 16) {
			wpa_printf(MSG_WARNING, "WPA: Unsupported CCMP Group "
			    "Cipher key length %d (%d).", keylen, maxkeylen);
			return;
		}
		key_rsc_len = 6;
		alg = WPA_ALG_CCMP;
		break;
	case WPA_CIPHER_TKIP:
		if (keylen != 32 || maxkeylen < 32) {
			wpa_printf(MSG_WARNING, "WPA: Unsupported TKIP Group "
			    "Cipher key length %d (%d).", keylen, maxkeylen);
			return;
		}
		key_rsc_len = 6; /* key->key_data; */
		alg = WPA_ALG_TKIP;
		break;
	case WPA_CIPHER_WEP104:
		if (keylen != 13 || maxkeylen < 13) {
			wpa_printf(MSG_WARNING, "WPA: Unsupported WEP104 Group"
			    " Cipher key length %d (%d).", keylen, maxkeylen);
			return;
		}
		alg = WPA_ALG_WEP;
		break;
	case WPA_CIPHER_WEP40:
		if (keylen != 5 || maxkeylen < 5) {
			wpa_printf(MSG_WARNING, "WPA: Unsupported WEP40 Group "
			    "Cipher key length %d (%d).", keylen, maxkeylen);
			return;
		}
		alg = WPA_ALG_WEP;
		break;
	default:
		wpa_printf(MSG_WARNING, "WPA: Unsupport Group Cipher %d",
		    wpa_s->group_cipher);
		return;
	}

	if (wpa_s->proto == WPA_PROTO_RSN) {
		wpa_hexdump(MSG_DEBUG,
		    "WPA: received GTK in group key handshake",
		    gtk_ie, gtk_ie_len);
		keyidx = gtk_ie[0] & 0x3;
		tx = !!(gtk_ie[0] & BIT(2));
		if (gtk_ie_len - 2 > sizeof (gtk)) {
			wpa_printf(MSG_INFO, "WPA: Too long GTK in GTK IE "
			    "(len=%d)", gtk_ie_len - 2);
			return;
		}
		(void) memcpy(gtk, gtk_ie + 2, gtk_ie_len - 2);
	} else {
		keyidx = (key_info & WPA_KEY_INFO_KEY_INDEX_MASK) >>
		    WPA_KEY_INFO_KEY_INDEX_SHIFT;
		if (ver == WPA_KEY_INFO_TYPE_HMAC_MD5_RC4) {
			(void) memcpy(ek, key->key_iv, 16);
			(void) memcpy(ek + 16, wpa_s->ptk.encr_key, 16);
			rc4_skip(ek, 32, 256, (uint8_t *)(key + 1), keydatalen);
			(void) memcpy(gtk, key + 1, keylen);
		} else if (ver == WPA_KEY_INFO_TYPE_HMAC_SHA1_AES) {
			if (keydatalen % 8) {
				wpa_printf(MSG_WARNING, "WPA: Unsupported "
				    "AES-WRAP len %d", keydatalen);
				return;
			}
			if (aes_unwrap(wpa_s->ptk.encr_key, maxkeylen / 8,
			    (uint8_t *)(key + 1), gtk)) {
				wpa_printf(MSG_WARNING, "WPA: AES unwrap "
				    "failed - could not decrypt GTK");
				return;
			}
		}
		tx = !!(key_info & WPA_KEY_INFO_TXRX);
		if (tx && wpa_s->pairwise_cipher != WPA_CIPHER_NONE) {
			/*
			 * Ignore Tx bit in Group Key message if a pairwise key
			 * is used. Some APs seem to setting this bit
			 * (incorrectly, since Tx is only when doing Group Key
			 * only APs) and without this workaround, the data
			 * connection does not work because wpa_supplicant
			 * configured non-zero keyidx to be used for unicast.
			 */
			wpa_printf(MSG_INFO, "WPA: Tx bit set for GTK, but "
			    "pairwise keys are used - ignore Tx bit");
			tx = 0;
		}
	}
	wpa_hexdump(MSG_DEBUG, "WPA: Group Key", gtk, keylen);
	wpa_printf(MSG_DEBUG, "WPA: Installing GTK to the driver (keyidx=%d "
	    "tx=%d).", keyidx, tx);
	wpa_hexdump(MSG_DEBUG, "WPA: RSC", key->key_rsc, key_rsc_len);
	if (wpa_s->group_cipher == WPA_CIPHER_TKIP) {
		/*
		 * Swap Tx/Rx keys for Michael MIC
		 */
		(void) memcpy(tmpbuf, gtk + 16, 8);
		(void) memcpy(gtk + 16, gtk + 24, 8);
		(void) memcpy(gtk + 24, tmpbuf, 8);
	}
	if (wpa_s->pairwise_cipher == WPA_CIPHER_NONE) {
		if (wpa_s->driver->set_key(wpa_s->linkid, alg,
		    (uint8_t *)"\xff\xff\xff\xff\xff\xff",
		    keyidx, 1, key->key_rsc,
		    key_rsc_len, gtk, keylen) < 0)
			wpa_printf(MSG_WARNING, "WPA: Failed to set GTK to the"
			    " driver (Group only).");
	} else if (wpa_s->driver->set_key(wpa_s->linkid, alg,
	    (uint8_t *)"\xff\xff\xff\xff\xff\xff",
	    keyidx, tx,
	    key->key_rsc, key_rsc_len,
	    gtk, keylen) < 0) {
		wpa_printf(MSG_WARNING, "WPA: Failed to set GTK to the "
		    "driver.");
	}

	rlen = sizeof (*ethhdr) + sizeof (*hdr) + sizeof (*reply);
	rbuf = malloc(rlen);
	if (rbuf == NULL)
		return;

	(void) memset(rbuf, 0, rlen);
	ethhdr = (struct l2_ethhdr *)rbuf;
	(void) memcpy(ethhdr->h_dest, src_addr, IEEE80211_ADDR_LEN);
	(void) memcpy(ethhdr->h_source, wpa_s->own_addr, IEEE80211_ADDR_LEN);
	ethhdr->h_proto = htons(ETHERTYPE_EAPOL);

	hdr = (struct ieee802_1x_hdr *)(ethhdr + 1);
	hdr->version = wpa_s->conf->eapol_version;
	hdr->type = IEEE802_1X_TYPE_EAPOL_KEY;
	hdr->length = htons(sizeof (*reply));

	reply = (struct wpa_eapol_key *)(hdr + 1);
	reply->type = wpa_s->proto == WPA_PROTO_RSN ?
	    EAPOL_KEY_TYPE_RSN : EAPOL_KEY_TYPE_WPA;
	reply->key_info =
	    BE_16(ver | WPA_KEY_INFO_MIC | WPA_KEY_INFO_SECURE |
	    (key_info & WPA_KEY_INFO_KEY_INDEX_MASK));
	reply->key_length = key->key_length;
	(void) memcpy(reply->replay_counter, key->replay_counter,
	    WPA_REPLAY_COUNTER_LEN);

	reply->key_data_length = BE_16(0);

	wpa_eapol_key_mic(wpa_s->ptk.mic_key, ver, (uint8_t *)hdr,
	    rlen - sizeof (*ethhdr), reply->key_mic);

	wpa_printf(MSG_DEBUG, "WPA: Sending EAPOL-Key 2/2");
	wpa_hexdump(MSG_MSGDUMP, "WPA: TX EAPOL-Key 2/2", rbuf, rlen);
	(void) l2_packet_send(wpa_s->l2, rbuf, rlen);
	free(rbuf);

	wpa_printf(MSG_INFO, "WPA: Key negotiation completed with " MACSTR,
	    MAC2STR(src_addr));
	eloop_cancel_timeout(wpa_supplicant_scan, wpa_s, NULL);
	wpa_supplicant_cancel_auth_timeout(wpa_s);
	wpa_s->wpa_state = WPA_COMPLETED;
	wpa_printf(MSG_INFO, "-----------------------------------\n");
}

static int
wpa_supplicant_verify_eapol_key_mic(struct wpa_supplicant *wpa_s,
    struct wpa_eapol_key *key, int ver, uint8_t *buf, size_t len)
{
	uint8_t mic[16];
	int ok = 0;

	(void) memcpy(mic, key->key_mic, 16);
	if (wpa_s->tptk_set) {
		(void) memset(key->key_mic, 0, 16);
		wpa_eapol_key_mic(wpa_s->tptk.mic_key, ver, buf, len,
		    key->key_mic);
		if (memcmp(mic, key->key_mic, 16) != 0) {
			wpa_printf(MSG_WARNING, "WPA: Invalid EAPOL-Key MIC "
			    "when using TPTK - ignoring TPTK");
		} else {
			ok = 1;
			wpa_s->tptk_set = 0;
			wpa_s->ptk_set = 1;
			(void) memcpy(&wpa_s->ptk, &wpa_s->tptk,
			    sizeof (wpa_s->ptk));
		}
	}

	if (!ok && wpa_s->ptk_set) {
		(void) memset(key->key_mic, 0, 16);
		wpa_eapol_key_mic(wpa_s->ptk.mic_key, ver, buf, len,
		    key->key_mic);
		if (memcmp(mic, key->key_mic, 16) != 0) {
			wpa_printf(MSG_WARNING, "WPA: Invalid EAPOL-Key MIC "
			    "- dropping packet");
			return (-1);
		}
		ok = 1;
	}

	if (!ok) {
		wpa_printf(MSG_WARNING, "WPA: Could not verify EAPOL-Key MIC "
		    "- dropping packet");
		return (-1);
	}

	(void) memcpy(wpa_s->rx_replay_counter, key->replay_counter,
	    WPA_REPLAY_COUNTER_LEN);
	wpa_s->rx_replay_counter_set = 1;

	return (0);
}

/* Decrypt RSN EAPOL-Key key data (RC4 or AES-WRAP) */
static int
wpa_supplicant_decrypt_key_data(struct wpa_supplicant *wpa_s,
	struct wpa_eapol_key *key, int ver)
{
	int keydatalen = BE_16(key->key_data_length);

	wpa_hexdump(MSG_DEBUG, "RSN: encrypted key data",
	    (uint8_t *)(key + 1), keydatalen);
	if (!wpa_s->ptk_set) {
		wpa_printf(MSG_WARNING, "WPA: PTK not available, "
		    "cannot decrypt EAPOL-Key key data.");
		return (-1);
	}

	/*
	 * Decrypt key data here so that this operation does not need
	 * to be implemented separately for each message type.
	 */
	if (ver == WPA_KEY_INFO_TYPE_HMAC_MD5_RC4) {
		uint8_t ek[32];
		(void) memcpy(ek, key->key_iv, 16);
		(void) memcpy(ek + 16, wpa_s->ptk.encr_key, 16);
		rc4_skip(ek, 32, 256, (uint8_t *)(key + 1), keydatalen);
	} else if (ver == WPA_KEY_INFO_TYPE_HMAC_SHA1_AES) {
		uint8_t *buf;
		if (keydatalen % 8) {
			wpa_printf(MSG_WARNING, "WPA: Unsupported "
			    "AES-WRAP len %d", keydatalen);
			return (-1);
		}
		keydatalen -= 8; /* AES-WRAP adds 8 bytes */
		buf = malloc(keydatalen);
		if (buf == NULL) {
			wpa_printf(MSG_WARNING, "WPA: No memory for "
			    "AES-UNWRAP buffer");
			return (-1);
		}
		if (aes_unwrap(wpa_s->ptk.encr_key, keydatalen / 8,
		    (uint8_t *)(key + 1), buf)) {
			free(buf);
			wpa_printf(MSG_WARNING, "WPA: AES unwrap failed - "
			    "could not decrypt EAPOL-Key key data");
			return (-1);
		}
		(void) memcpy(key + 1, buf, keydatalen);
		free(buf);
		key->key_data_length = BE_16(keydatalen);
	}
	wpa_hexdump(MSG_DEBUG, "WPA: decrypted EAPOL-Key key data",
	    (uint8_t *)(key + 1), keydatalen);

	return (0);
}

static void
wpa_sm_rx_eapol(struct wpa_supplicant *wpa_s,
    unsigned char *src_addr, unsigned char *buf, size_t len)
{
	size_t plen, data_len, extra_len;
	struct ieee802_1x_hdr *hdr;
	struct wpa_eapol_key *key;
	int key_info, ver;

	wpa_printf(MSG_DEBUG, "WPA: EAPOL frame len %u\n ", len);

	hdr = (struct ieee802_1x_hdr *)buf;
	key = (struct wpa_eapol_key *)(hdr + 1);
	wpa_printf(MSG_DEBUG, "hdr_len=%u, key_len=%u",
	    sizeof (*hdr), sizeof (*key));
	if (len < sizeof (*hdr) + sizeof (*key)) {
		wpa_printf(MSG_DEBUG, "WPA: EAPOL frame too short, len %u, "
		    "expecting at least %u",
		    len, sizeof (*hdr) + sizeof (*key));
		return;
	}
	plen = ntohs(hdr->length);
	data_len = plen + sizeof (*hdr);
	wpa_printf(MSG_DEBUG, "IEEE 802.1X RX: version=%d type=%d length=%d",
	    hdr->version, hdr->type, plen);

	if (hdr->type != IEEE802_1X_TYPE_EAPOL_KEY) {
		wpa_printf(MSG_DEBUG, "WPA: EAPOL frame (type %u) discarded, "
		    "not a Key frame", hdr->type);
		return;
	}
	if (plen > len - sizeof (*hdr) || plen < sizeof (*key)) {
		wpa_printf(MSG_DEBUG, "WPA: EAPOL frame payload size %u "
		    "invalid (frame size %u)", plen, len);
		return;
	}

	wpa_printf(MSG_DEBUG, "  EAPOL-Key type=%d", key->type);
	if (key->type != EAPOL_KEY_TYPE_WPA && key->type !=
	    EAPOL_KEY_TYPE_RSN) {
		wpa_printf(MSG_DEBUG, "WPA: EAPOL-Key type (%d) unknown, "
		    "discarded", key->type);
		return;
	}

	wpa_hexdump(MSG_MSGDUMP, "WPA: RX EAPOL-Key", buf, len);
	if (data_len < len) {
		wpa_printf(MSG_DEBUG, "WPA: ignoring %d bytes after the IEEE "
		    "802.1X data", len - data_len);
	}
	key_info = BE_16(key->key_info);
	ver = key_info & WPA_KEY_INFO_TYPE_MASK;
	if (ver != WPA_KEY_INFO_TYPE_HMAC_MD5_RC4 &&
	    ver != WPA_KEY_INFO_TYPE_HMAC_SHA1_AES) {
		wpa_printf(MSG_INFO, "WPA: Unsupported EAPOL-Key descriptor "
		    "version %d.", ver);
		return;
	}

	if (wpa_s->pairwise_cipher == WPA_CIPHER_CCMP &&
	    ver != WPA_KEY_INFO_TYPE_HMAC_SHA1_AES) {
		wpa_printf(MSG_INFO, "WPA: CCMP is used, but EAPOL-Key "
		    "descriptor version (%d) is not 2.", ver);
		if (wpa_s->group_cipher != WPA_CIPHER_CCMP &&
		    !(key_info & WPA_KEY_INFO_KEY_TYPE)) {
			/*
			 * Earlier versions of IEEE 802.11i did not explicitly
			 * require version 2 descriptor for all EAPOL-Key
			 * packets, so allow group keys to use version 1 if
			 * CCMP is not used for them.
			 */
			wpa_printf(MSG_INFO, "WPA: Backwards compatibility: "
			    "allow invalid version for non-CCMP group keys");
		} else
			return;
	}

	if (wpa_s->rx_replay_counter_set &&
	    memcmp(key->replay_counter, wpa_s->rx_replay_counter,
	    WPA_REPLAY_COUNTER_LEN) <= 0) {
		wpa_printf(MSG_WARNING, "WPA: EAPOL-Key Replay Counter did not"
		    " increase - dropping packet");
		return;
	}

	if (!(key_info & WPA_KEY_INFO_ACK)) {
		wpa_printf(MSG_INFO, "WPA: No Ack bit in key_info");
		return;
	}

	if (key_info & WPA_KEY_INFO_REQUEST) {
		wpa_printf(MSG_INFO, "WPA: EAPOL-Key with Request bit - "
		    "dropped");
		return;
	}

	if ((key_info & WPA_KEY_INFO_MIC) &&
	    wpa_supplicant_verify_eapol_key_mic(wpa_s, key, ver, buf,
	    data_len)) {
		return;
	}

	extra_len = data_len - sizeof (*hdr) - sizeof (*key);

	if (wpa_s->proto == WPA_PROTO_RSN &&
	    (key_info & WPA_KEY_INFO_ENCR_KEY_DATA) &&
	    wpa_supplicant_decrypt_key_data(wpa_s, key, ver))
		return;

	if (key_info & WPA_KEY_INFO_KEY_TYPE) {
		if (key_info & WPA_KEY_INFO_KEY_INDEX_MASK) {
			wpa_printf(MSG_WARNING, "WPA: Ignored EAPOL-Key "
			    "(Pairwise) with non-zero key index");
			return;
		}
		if (key_info & WPA_KEY_INFO_MIC) {
			/* 3/4 4-Way Handshake */
			wpa_supplicant_process_3_of_4(wpa_s, src_addr, key,
			    extra_len, ver);
		} else {
			/* 1/4 4-Way Handshake */
			wpa_supplicant_process_1_of_4(wpa_s, src_addr, key,
			    ver);
		}
	} else {
		if (key_info & WPA_KEY_INFO_MIC) {
			/* 1/2 Group Key Handshake */
			wpa_supplicant_process_1_of_2(wpa_s, src_addr, key,
			    extra_len, ver);
		} else {
			wpa_printf(MSG_WARNING, "WPA: EAPOL-Key (Group) "
			    "without Mic bit - dropped");
		}
	}
}

void
wpa_supplicant_rx_eapol(void *ctx, unsigned char *src_addr,
    unsigned char *buf, size_t len)
{
	struct wpa_supplicant *wpa_s = ctx;

	wpa_printf(MSG_DEBUG, "RX EAPOL from " MACSTR, MAC2STR(src_addr));
	wpa_hexdump(MSG_MSGDUMP, "RX EAPOL", buf, len);

	if (wpa_s->eapol_received == 0) {
		/* Timeout for completing IEEE 802.1X and WPA authentication */
		wpa_supplicant_req_auth_timeout(
		    wpa_s, wpa_s->key_mgmt == WPA_KEY_MGMT_IEEE8021X ?
		    70 : 10, 0);
	}
	wpa_s->eapol_received++;

	/*
	 * Source address of the incoming EAPOL frame could be compared to the
	 * current BSSID. However, it is possible that a centralized
	 * Authenticator could be using another MAC address than the BSSID of
	 * an AP, so just allow any address to be used for now. The replies are
	 * still sent to the current BSSID (if available), though.
	 */
	wpa_sm_rx_eapol(wpa_s, src_addr, buf, len);
}
