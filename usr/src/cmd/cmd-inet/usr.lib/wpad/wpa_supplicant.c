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
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <door.h>
#include <libdladm.h>
#include <libdllink.h>
#include <sys/ethernet.h>

#include "wpa_impl.h"
#include "wpa_enc.h"
#include "driver.h"
#include "eloop.h"
#include "l2_packet.h"

static const char *wpa_supplicant_version =
"wpa_supplicant v1.0";

extern struct wpa_driver_ops wpa_driver_wifi_ops;
int wpa_debug_level = MSG_ERROR;

/*
 * wpa_printf - conditional printf
 * @level: priority level (MSG_*) of the message
 * @fmt: printf format string, followed by optional arguments
 *
 * This function is used to print conditional debugging and error messages. The
 * output may be directed to stdout, stderr, and/or syslog based on
 * configuration.
 */
void
wpa_printf(int level, char *fmt, ...)
{
	va_list ap;
	char buffer[MAX_LOGBUF];

	if (level < wpa_debug_level)
		return;

	va_start(ap, fmt);

	/* LINTED E_SEC_PRINTF_VAR_FMT */
	(void) vsnprintf(buffer, sizeof (buffer), fmt, ap);

	va_end(ap);

	syslog(LOG_NOTICE | LOG_DAEMON, "%s", buffer);
}

/*
 * wpa_hexdump - conditional hex dump
 * @level: priority level (MSG_*) of the message
 * @title: title of for the message
 * @buf: data buffer to be dumped
 * @len: length of the @buf
 *
 * This function is used to print conditional debugging and error messages. The
 * output may be directed to stdout, stderr, and/or syslog based on
 * configuration. The contents of @buf is printed out has hex dump.
 */
void
wpa_hexdump(int level, const char *title, const uint8_t *buf, size_t len)
{
	size_t i;
	char buffer[MAX_LOGBUF], tmp[4];
	int n;

	if (level < wpa_debug_level)
		return;

	(void) snprintf(buffer, sizeof (buffer), "%s - hexdump(len=%d):",
	    title, len);
	n = strlen(buffer);

	for (i = 0; i < len; i++) {
		(void) sprintf(tmp, " %02x", buf[i]);

		n += strlen(tmp);
		if (n >= MAX_LOGBUF) break;

		(void) strlcat(buffer, tmp, sizeof (buffer));
	}

	syslog(LOG_NOTICE | LOG_DAEMON, "%s", buffer);
}

static const char *
wpa_ssid_txt(char *ssid, size_t ssid_len)
{
	static char ssid_txt[MAX_ESSID_LENGTH + 1];
	char *pos;

	if (ssid_len > MAX_ESSID_LENGTH)
		ssid_len = MAX_ESSID_LENGTH;
	(void) memcpy(ssid_txt, ssid, ssid_len);
	ssid_txt[ssid_len] = '\0';
	for (pos = ssid_txt; *pos != '\0'; pos ++) {
		if ((uint8_t)*pos < 32 || (uint8_t)*pos >= 127)
			*pos = '_';
	}
	return (ssid_txt);
}

/* ARGSUSED */
void
wpa_supplicant_scan(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_supplicant *wpa_s = eloop_ctx;
	struct wpa_ssid *ssid;

	if (wpa_s->conf == NULL)
		return;

	if (wpa_s->wpa_state == WPA_DISCONNECTED)
		wpa_s->wpa_state = WPA_SCANNING;

	ssid = wpa_s->conf->ssid;
	wpa_printf(MSG_DEBUG, "Starting AP scan (%s SSID)",
	    ssid ? "specific": "broadcast");

	if (ssid) {
		wpa_printf(MSG_DEBUG, "Scan SSID: %s", ssid->ssid);
	}

	if (wpa_s->driver->scan(wpa_s->linkid)) {
		wpa_printf(MSG_WARNING, "Failed to initiate AP scan.");
	}
}

void
wpa_supplicant_req_scan(struct wpa_supplicant *wpa_s, int sec, int usec)
{
	wpa_printf(MSG_DEBUG, "Setting scan request: %d sec %d usec",
	    sec, usec);
	(void) eloop_cancel_timeout(wpa_supplicant_scan, wpa_s, NULL);
	(void) eloop_register_timeout(sec, usec, wpa_supplicant_scan,
	    wpa_s, NULL);
}

void
wpa_supplicant_cancel_scan(struct wpa_supplicant *wpa_s)
{
	wpa_printf(MSG_DEBUG, "Cancelling scan request");
	eloop_cancel_timeout(wpa_supplicant_scan, wpa_s, NULL);
}

/* ARGSUSED */
static void
wpa_supplicant_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_supplicant *wpa_s = eloop_ctx;

	wpa_printf(MSG_INFO, "Authentication with " MACSTR " timed out.",
	    MAC2STR(wpa_s->bssid));

	wpa_s->reassociate = 1;
	wpa_supplicant_req_scan(wpa_s, 0, 0);
}

void
wpa_supplicant_req_auth_timeout(struct wpa_supplicant *wpa_s,
				int sec, int usec)
{
	wpa_printf(MSG_DEBUG, "Setting authentication timeout: %d sec "
	    "%d usec", sec, usec);
	eloop_cancel_timeout(wpa_supplicant_timeout, wpa_s, NULL);
	(void) eloop_register_timeout(sec, usec, wpa_supplicant_timeout,
	    wpa_s, NULL);
}

void
wpa_supplicant_cancel_auth_timeout(struct wpa_supplicant *wpa_s)
{
	wpa_printf(MSG_DEBUG, "Cancelling authentication timeout");
	eloop_cancel_timeout(wpa_supplicant_timeout, wpa_s, NULL);
}

static void
wpa_supplicant_cleanup(struct wpa_supplicant *wpa_s)
{
	l2_packet_deinit(wpa_s->l2);
	wpa_s->l2 = NULL;

	if (wpa_s->conf != NULL) {
		wpa_config_free(wpa_s->conf);
		wpa_s->conf = NULL;
	}

	free(wpa_s->ap_wpa_ie);
	pmksa_candidate_free(wpa_s);
	pmksa_cache_free(wpa_s);
}

static void
wpa_clear_keys(struct wpa_supplicant *wpa_s, uint8_t *addr)
{
	wpa_s->driver->set_key(wpa_s->linkid, WPA_ALG_NONE,
	    (uint8_t *)"\xff\xff\xff\xff\xff\xff", 0, 0, NULL, 0, NULL, 0);
	wpa_s->driver->set_key(wpa_s->linkid, WPA_ALG_NONE,
	    (uint8_t *)"\xff\xff\xff\xff\xff\xff", 1, 0, NULL, 0, NULL, 0);
	wpa_s->driver->set_key(wpa_s->linkid, WPA_ALG_NONE,
	    (uint8_t *)"\xff\xff\xff\xff\xff\xff", 2, 0, NULL, 0, NULL, 0);
	wpa_s->driver->set_key(wpa_s->linkid, WPA_ALG_NONE,
	    (uint8_t *)"\xff\xff\xff\xff\xff\xff", 3, 0, NULL, 0, NULL, 0);
	if (addr) {
		wpa_s->driver->set_key(wpa_s->linkid, WPA_ALG_NONE, addr,
		    0, 0, NULL, 0, NULL, 0);
	}
}

static void
wpa_supplicant_mark_disassoc(struct wpa_supplicant *wpa_s)
{
	wpa_s->wpa_state = WPA_DISCONNECTED;
	(void) memset(wpa_s->bssid, 0, IEEE80211_ADDR_LEN);
}

static int
wpa_supplicant_set_suites(struct wpa_supplicant *wpa_s,
    dladm_wlan_ess_t *bss, struct wpa_ssid *ssid,
    uint8_t *wpa_ie, int *wpa_ie_len)
{
	struct wpa_ie_data ie;
	int sel, proto;
	uint8_t *ap_ie;
	size_t ap_ie_len;

	/* RSN or WPA */
	if (bss->we_wpa_ie_len && bss->we_wpa_ie[0] == RSN_INFO_ELEM &&
	    (ssid->proto & WPA_PROTO_RSN)) {
		wpa_printf(MSG_DEBUG, "RSN: using IEEE 802.11i/D9.0");
		proto = WPA_PROTO_RSN;
	} else {
		wpa_printf(MSG_DEBUG, "WPA: using IEEE 802.11i/D3.0");
		proto = WPA_PROTO_WPA;
	}

	ap_ie = bss->we_wpa_ie;
	ap_ie_len = bss->we_wpa_ie_len;

	if (wpa_parse_wpa_ie(wpa_s, ap_ie, ap_ie_len, &ie)) {
		wpa_printf(MSG_WARNING, "WPA: Failed to parse WPA IE for "
		    "the selected BSS.");
		return (-1);
	}

	wpa_s->proto = proto;
	free(wpa_s->ap_wpa_ie);
	wpa_s->ap_wpa_ie = malloc(ap_ie_len);
	(void) memcpy(wpa_s->ap_wpa_ie, ap_ie, ap_ie_len);
	wpa_s->ap_wpa_ie_len = ap_ie_len;

	sel = ie.group_cipher & ssid->group_cipher;
	if (sel & WPA_CIPHER_CCMP) {
		wpa_s->group_cipher = WPA_CIPHER_CCMP;
	} else if (sel & WPA_CIPHER_TKIP) {
		wpa_s->group_cipher = WPA_CIPHER_TKIP;
	} else if (sel & WPA_CIPHER_WEP104) {
		wpa_s->group_cipher = WPA_CIPHER_WEP104;
	} else if (sel & WPA_CIPHER_WEP40) {
		wpa_s->group_cipher = WPA_CIPHER_WEP40;
	} else {
		wpa_printf(MSG_WARNING, "WPA: Failed to select group cipher.");
		return (-1);
	}

	sel = ie.pairwise_cipher & ssid->pairwise_cipher;
	if (sel & WPA_CIPHER_CCMP) {
		wpa_s->pairwise_cipher = WPA_CIPHER_CCMP;
	} else if (sel & WPA_CIPHER_TKIP) {
		wpa_s->pairwise_cipher = WPA_CIPHER_TKIP;
	} else if (sel & WPA_CIPHER_NONE) {
		wpa_s->pairwise_cipher = WPA_CIPHER_NONE;
	} else {
		wpa_printf(MSG_WARNING, "WPA: Failed to select pairwise "
		    "cipher.");
		return (-1);
	}

	sel = ie.key_mgmt & ssid->key_mgmt;
	if (sel & WPA_KEY_MGMT_IEEE8021X) {
		wpa_s->key_mgmt = WPA_KEY_MGMT_IEEE8021X;
	} else if (sel & WPA_KEY_MGMT_PSK) {
		wpa_s->key_mgmt = WPA_KEY_MGMT_PSK;
	} else {
		wpa_printf(MSG_WARNING, "WPA: Failed to select authenticated "
		    "key management type.");
		return (-1);
	}

	*wpa_ie_len = wpa_gen_wpa_ie(wpa_s, wpa_ie);
	if (*wpa_ie_len < 0) {
		wpa_printf(MSG_WARNING, "WPA: Failed to generate WPA IE.");
		return (-1);
	}
	wpa_hexdump(MSG_DEBUG, "WPA: Own WPA IE", wpa_ie, *wpa_ie_len);

	if (ssid->key_mgmt & WPA_KEY_MGMT_PSK)
		(void) memcpy(wpa_s->pmk, ssid->psk, PMK_LEN);
	else if (wpa_s->cur_pmksa)
		(void) memcpy(wpa_s->pmk, wpa_s->cur_pmksa->pmk, PMK_LEN);
	else {
		(void) memset(wpa_s->pmk, 0, PMK_LEN);
	}

	return (0);
}

static void wpa_supplicant_associate(struct wpa_supplicant *wpa_s,
    dladm_wlan_ess_t *bss, struct wpa_ssid *ssid)
{
	uint8_t wpa_ie[IEEE80211_MAX_OPT_IE];
	int wpa_ie_len;

	wpa_s->reassociate = 0;
	wpa_printf(MSG_DEBUG, "Trying to associate with " MACSTR
	    " (SSID='%s' freq=%d MHz)", MAC2STR(bss->we_bssid.wb_bytes),
	    wpa_ssid_txt((char *)ssid->ssid, ssid->ssid_len), bss->we_freq);
	wpa_supplicant_cancel_scan(wpa_s);

	if (bss->we_wpa_ie_len &&
	    (ssid->key_mgmt & (WPA_KEY_MGMT_IEEE8021X | WPA_KEY_MGMT_PSK))) {
		wpa_s->cur_pmksa = pmksa_cache_get(wpa_s,
		    bss->we_bssid.wb_bytes, NULL);
		if (wpa_s->cur_pmksa) {
			wpa_hexdump(MSG_DEBUG, "RSN: PMKID",
			    wpa_s->cur_pmksa->pmkid, PMKID_LEN);
		}
		if (wpa_supplicant_set_suites(wpa_s, bss, ssid,
		    wpa_ie, &wpa_ie_len)) {
			wpa_printf(MSG_WARNING, "WPA: Failed to set WPA key "
			    "management and encryption suites");
			return;
		}
	} else {
		wpa_ie_len = 0;
	}

	wpa_clear_keys(wpa_s, bss->we_bssid.wb_bytes);
	wpa_s->wpa_state = WPA_ASSOCIATING;
	wpa_s->driver->associate(wpa_s->linkid,
	    (const char *)bss->we_bssid.wb_bytes, wpa_ie, wpa_ie_len);

	/* Timeout for IEEE 802.11 authentication and association */
	wpa_supplicant_req_auth_timeout(wpa_s, 15, 0);
}

void
wpa_supplicant_disassociate(struct wpa_supplicant *wpa_s, int reason_code)
{
	uint8_t *addr = NULL;
	wpa_s->wpa_state = WPA_DISCONNECTED;
	if (memcmp(wpa_s->bssid, "\x00\x00\x00\x00\x00\x00",
	    IEEE80211_ADDR_LEN) != 0) {
		wpa_s->driver->disassociate(wpa_s->linkid, reason_code);
		addr = wpa_s->bssid;
	}
	wpa_clear_keys(wpa_s, addr);
}

static dladm_wlan_ess_t *
wpa_supplicant_select_bss(struct wpa_supplicant *wpa_s, struct wpa_ssid *group,
    dladm_wlan_ess_t *results, int num, struct wpa_ssid **selected_ssid)
{
	struct wpa_ssid *ssid;
	dladm_wlan_ess_t *bss, *selected = NULL;
	int i;

	struct wpa_ie_data ie;

	wpa_printf(MSG_DEBUG, "Selecting BSS from scan results (%d)", num);

	bss = NULL;
	ssid = NULL;

	/* try to find matched AP */
	for (i = 0; i < num && !selected; i++) {
		bss = &results[i];
		wpa_printf(MSG_DEBUG, "%d: " MACSTR " ssid='%s' "
		    "wpa_ie_len=%d",
		    i, MAC2STR(bss->we_bssid.wb_bytes),
		    wpa_ssid_txt(bss->we_ssid.we_bytes, bss->we_ssid_len),
		    bss->we_wpa_ie_len);
		if (bss->we_wpa_ie_len == 0) {
			wpa_printf(MSG_DEBUG, "   skip - no WPA/RSN IE");
		}

		ssid = group;
		if (bss->we_ssid_len != ssid->ssid_len ||
		    memcmp(bss->we_ssid.we_bytes, ssid->ssid,
		    bss->we_ssid_len) != 0) {
			wpa_printf(MSG_DEBUG, "   skip - SSID mismatch");
			continue;
		}
		if (!((ssid->proto & (WPA_PROTO_RSN | WPA_PROTO_WPA)) &&
		    wpa_parse_wpa_ie(wpa_s, bss->we_wpa_ie,
		    bss->we_wpa_ie_len, &ie) == 0)) {
			wpa_printf(MSG_DEBUG, "   skip - "
			    "could not parse WPA/RSN IE");
			continue;
		}
		if (!(ie.proto & ssid->proto)) {
			wpa_printf(MSG_DEBUG, "   skip - proto mismatch");
			continue;
		}
		if (!(ie.pairwise_cipher & ssid->pairwise_cipher)) {
			wpa_printf(MSG_DEBUG, "   skip - PTK cipher mismatch");
			continue;
		}
		if (!(ie.group_cipher & ssid->group_cipher)) {
			wpa_printf(MSG_DEBUG, "   skip - GTK cipher mismatch");
			continue;
		}
		if (!(ie.key_mgmt & ssid->key_mgmt)) {
			wpa_printf(MSG_DEBUG, "   skip - key mgmt mismatch");
			continue;
		}

		selected = bss;
		*selected_ssid = ssid;
		wpa_printf(MSG_DEBUG, "   selected");
	}

	return (selected);
}


static void
wpa_supplicant_scan_results(struct wpa_supplicant *wpa_s)
{
	dladm_wlan_ess_t results[MAX_SCANRESULTS];
	int num;
	dladm_wlan_ess_t *selected = NULL;
	struct wpa_ssid *ssid;

	(void) memset(results, 0, sizeof (dladm_wlan_ess_t) * MAX_SCANRESULTS);
	num = wpa_s->driver->get_scan_results(wpa_s->linkid, results,
	    MAX_SCANRESULTS);
	wpa_printf(MSG_DEBUG, "Scan results: %d", num);
	if (num < 0)
		return;
	if (num > MAX_SCANRESULTS) {
		wpa_printf(MSG_INFO, "Not enough room for all APs (%d < %d)",
		    num, MAX_SCANRESULTS);
		num = MAX_SCANRESULTS;
	}

	selected = wpa_supplicant_select_bss(wpa_s,
	    wpa_s->conf->ssid, results, num, &ssid);

	if (selected) {
		if (wpa_s->reassociate ||
		    memcmp(selected->we_bssid.wb_bytes, wpa_s->bssid,
		    IEEE80211_ADDR_LEN) != 0) {
			wpa_supplicant_associate(wpa_s, selected, ssid);
		} else {
			wpa_printf(MSG_DEBUG, "Already associated with the "
			    "selected AP.");
		}
	} else {
		wpa_printf(MSG_DEBUG, "No suitable AP found.");
		wpa_supplicant_req_scan(wpa_s, 5, 0);	/* wait 5 seconds */
	}
}

/*
 * wpa_event_handler - report a driver event for wpa_supplicant
 * @wpa_s: pointer to wpa_supplicant data; this is the @ctx variable registered
 *	with wpa_driver_events_init()
 * @event: event type (defined above)
 *
 * Driver wrapper code should call this function whenever an event is received
 * from the driver.
 */
void
wpa_event_handler(void *cookie, wpa_event_type event)
{
	struct wpa_supplicant *wpa_s = cookie;
	uint8_t bssid[IEEE80211_ADDR_LEN];

	switch (event) {
	case EVENT_ASSOC:
		wpa_s->wpa_state = WPA_ASSOCIATED;
		wpa_printf(MSG_DEBUG, "\nAssociation event - clear replay "
		    "counter\n");
		(void) memset(wpa_s->rx_replay_counter, 0,
		    WPA_REPLAY_COUNTER_LEN);
		wpa_s->rx_replay_counter_set = 0;
		wpa_s->renew_snonce = 1;
		if (wpa_s->driver->get_bssid(wpa_s->linkid,
		    (char *)bssid) >= 0 &&
		    memcmp(bssid, wpa_s->bssid, IEEE80211_ADDR_LEN) != 0) {
			wpa_printf(MSG_DEBUG, "Associated to a new BSS: "
			    "BSSID=" MACSTR, MAC2STR(bssid));
			(void) memcpy(wpa_s->bssid, bssid, IEEE80211_ADDR_LEN);
			if (wpa_s->key_mgmt != WPA_KEY_MGMT_NONE)
				wpa_clear_keys(wpa_s, bssid);
		}

		wpa_s->eapol_received = 0;
		if (wpa_s->key_mgmt == WPA_KEY_MGMT_NONE) {
			wpa_supplicant_cancel_auth_timeout(wpa_s);
		} else {
			/* Timeout for receiving the first EAPOL packet */
			wpa_supplicant_req_auth_timeout(wpa_s, 10, 0);
		}
		break;
	case EVENT_DISASSOC:
		if (wpa_s->wpa_state >= WPA_ASSOCIATED)
			wpa_supplicant_req_scan(wpa_s, 0, 100000);
		wpa_supplicant_mark_disassoc(wpa_s);
		wpa_printf(MSG_DEBUG, "Disconnect event - remove keys");
		if (wpa_s->key_mgmt != WPA_KEY_MGMT_NONE)
			wpa_clear_keys(wpa_s, wpa_s->bssid);
		break;
	case EVENT_SCAN_RESULTS:
		wpa_supplicant_scan_results(wpa_s);
		break;
	default:
		wpa_printf(MSG_INFO, "Unknown event %d", event);
		break;
	}
}

/* ARGSUSED */
static void
wpa_supplicant_terminate(int sig, void *eloop_ctx, void *signal_ctx)
{
	wpa_printf(MSG_INFO, "Signal %d received - terminating", sig);
	eloop_terminate();
}

static int
wpa_supplicant_driver_init(const char *link, struct wpa_supplicant *wpa_s)
{
	wpa_s->l2 = l2_packet_init(link, ETHERTYPE_EAPOL,
	    wpa_supplicant_rx_eapol, wpa_s);
	if (wpa_s->l2 == NULL)
		return (-1);

	if (l2_packet_get_own_addr(wpa_s->l2, wpa_s->own_addr)) {
		(void) fprintf(stderr, "Failed to get own L2 address\n");
		return (-1);
	}

	if (wpa_s->driver->set_wpa(wpa_s->linkid, 1) < 0) {
		wpa_printf(MSG_ERROR, "Failed to enable WPA in the driver.");
		return (-1);
	}

	wpa_clear_keys(wpa_s, NULL);
	wpa_supplicant_req_scan(wpa_s, 0, 100000);

	return (0);
}

static int door_id = -1;

/* ARGSUSED */
static void
event_handler(void *cookie, char *argp, size_t asize,
    door_desc_t *dp, uint_t n_desc)
{
	wpa_event_type event;

	event = ((wl_events_t *)argp)->event;
	wpa_event_handler(cookie, event);

	(void) door_return(NULL, 0, NULL, 0);
}

/*
 * Create the driver to wpad door
 */
int
wpa_supplicant_door_setup(void *cookie, char *doorname)
{
	struct stat stbuf;
	int error = 0;

	wpa_printf(MSG_DEBUG, "wpa_supplicant_door_setup(%s)", doorname);
	/*
	 * Create the door
	 */
	door_id = door_create(event_handler, cookie,
	    DOOR_UNREF | DOOR_REFUSE_DESC | DOOR_NO_CANCEL);

	if (door_id < 0) {
		error = -1;
		goto out;
	}

	if (stat(doorname, &stbuf) < 0) {
		int newfd;
		if ((newfd = creat(doorname, 0666)) < 0) {
			(void) door_revoke(door_id);
			door_id = -1;
			error = -1;

			goto out;
		}
		(void) close(newfd);
	}

	if (fattach(door_id, doorname) < 0) {
		if ((errno != EBUSY) || (fdetach(doorname) < 0) ||
		    (fattach(door_id, doorname) < 0)) {
			(void) door_revoke(door_id);
			door_id = -1;
			error = -1;

			goto out;
		}
	}

out:
	return (error);
}

void
wpa_supplicant_door_destroy(char *doorname)
{
	wpa_printf(MSG_DEBUG, "wpa_supplicant_door_destroy(%s)\n", doorname);

	if (door_id == -1)
		return;

	if (door_revoke(door_id) == -1) {
		wpa_printf(MSG_ERROR, "failed to door_revoke(%d) %s, exiting.",
		    door_id, strerror(errno));
	}

	if (fdetach(doorname) == -1) {
		wpa_printf(MSG_ERROR, "failed to fdetach %s: %s, exiting.",
		    doorname, strerror(errno));
	}

	(void) close(door_id);
}

static int
wpa_config_parse_ssid(struct wpa_ssid *ssid, int line, const char *value)
{
	free(ssid->ssid);

	ssid->ssid = (uint8_t *)strdup(value);
	ssid->ssid_len = strlen(value);

	if (ssid->ssid == NULL) {
		wpa_printf(MSG_ERROR, "Invalid SSID '%s'.", line, value);
		return (-1);
	}
	if (ssid->ssid_len > MAX_ESSID_LENGTH) {
		free(ssid->ssid);
		wpa_printf(MSG_ERROR, "Too long SSID '%s'.", line, value);
		return (-1);
	}
	wpa_printf(MSG_MSGDUMP, "SSID: %s", ssid->ssid);
	return (0);
}

static struct wpa_ssid *
wpa_config_read_network(struct wpa_supplicant *wpa_s)
{
	struct wpa_ssid *ssid;
	char buf[MAX_ESSID_LENGTH + 1];
	dladm_secobj_class_t cl;
	uint8_t psk[MAX_PSK_LENGTH + 1];
	uint_t key_len;

	wpa_printf(MSG_MSGDUMP, "Start of a new network configration");

	ssid = (struct wpa_ssid *)malloc(sizeof (*ssid));
	if (ssid == NULL)
		return (NULL);
	(void) memset(ssid, 0, sizeof (*ssid));

	/*
	 * Set default supported values
	 */
	ssid->proto = WPA_PROTO_WPA | WPA_PROTO_RSN;
	ssid->pairwise_cipher = WPA_CIPHER_CCMP | WPA_CIPHER_TKIP;
	ssid->group_cipher = WPA_CIPHER_CCMP | WPA_CIPHER_TKIP |
	    WPA_CIPHER_WEP104 | WPA_CIPHER_WEP40;
	ssid->key_mgmt = WPA_KEY_MGMT_PSK; /* | WPA_KEY_MGMT_IEEE8021X; */

	(void) memset(buf, 0, MAX_ESSID_LENGTH + 1);
	wpa_s->driver->get_ssid(wpa_s->linkid, (char *)buf);

	(void) wpa_config_parse_ssid(ssid, 0, buf);

	key_len = sizeof (psk);
	(void) dladm_get_secobj((const char *)wpa_s->kname, &cl, psk, &key_len,
	    DLADM_OPT_ACTIVE);
	psk[key_len] = '\0';
	ssid->passphrase = strdup((const char *)psk);

	if (ssid->passphrase) {
		pbkdf2_sha1(ssid->passphrase, (char *)ssid->ssid,
		    ssid->ssid_len, 4096, ssid->psk, PMK_LEN);
		wpa_hexdump(MSG_MSGDUMP, "PSK (from passphrase)",
		    ssid->psk, PMK_LEN);
		ssid->psk_set = 1;
	}

	if ((ssid->key_mgmt & WPA_KEY_MGMT_PSK) && !ssid->psk_set) {
		wpa_printf(MSG_ERROR, "WPA-PSK accepted for key "
		    "management, but no PSK configured.");
		free(ssid);
		ssid = NULL;
	}

	return (ssid);
}

struct wpa_config *
wpa_config_read(void *arg)
{
	struct wpa_ssid *ssid;
	struct wpa_config *config;
	struct wpa_supplicant *wpa_s = arg;

	config = malloc(sizeof (*config));
	if (config == NULL)
		return (NULL);
	(void) memset(config, 0, sizeof (*config));
	config->eapol_version = 1;	/* fixed value */

	wpa_printf(MSG_DEBUG, "Reading configuration parameters from driver\n");

	ssid = wpa_config_read_network(wpa_s);
	if (ssid == NULL) {
		wpa_config_free(config);
		config = NULL;
	} else {
		config->ssid = ssid;
	}

	return (config);
}

void
wpa_config_free(struct wpa_config *config)
{
	struct wpa_ssid *ssid = config->ssid;

	if (ssid != NULL) {
		free(ssid->ssid);
		free(ssid->passphrase);
		free(ssid);
	}
	free(config);
}

static int
daemon(boolean_t nochdir, boolean_t noclose)
{
	int retv;

	if ((retv = fork()) == -1)
		return (-1);
	if (retv != 0)
		_exit(EXIT_SUCCESS);
	if (setsid() == -1)
		return (-1);

	if (!nochdir && chdir("/") == -1)
		return (-1);

	if (!noclose) {
		(void) close(0);
		(void) close(1);
		(void) close(2);
		if ((retv = open("/dev/null", O_RDWR)) != -1) {
			(void) dup2(retv, 1);
			(void) dup2(retv, 2);
		}
	}

	return (0);
}

static void
usage(void)
{
	(void) printf("%s\n\n"
	    "usage:\n"
	    "  wpa_supplicant [-hv] -i<ifname> -k<keyname>\n"
	    "options:\n"
	    "  -h = show this help text\n"
	    "  -v = show version\n",
	    wpa_supplicant_version);
}

int
main(int argc, char *argv[])
{
	struct wpa_supplicant wpa_s;
	char *link = NULL;
	char *key = NULL;
	dlpi_handle_t dh = NULL;
	datalink_id_t linkid;
	dladm_phys_attr_t dpa;
	int c;
	int exitcode;
	char door_file[WPA_STRSIZE];

	for (;;) {
		c = getopt(argc, argv, "Dk:hi:v");
		if (c < 0)
			break;
		switch (c) {
		case 'D':
			wpa_debug_level = MSG_DEBUG;
			break;
		case 'h':
			usage();
			return (-1);
		case 'i':
			link = optarg;
			break;
		case 'k':
			key = optarg;
			break;
		case 'v':
			(void) printf("%s\n", wpa_supplicant_version);
			return (-1);
		default:
			usage();
			return (-1);
		}
	}

	/*
	 * key name is required to retrieve PSK value through libwdladm APIs.
	 * key is saved by dladm command by keyname
	 * see dladm.
	 */
	if ((link == NULL) || (key == NULL)) {
		wpa_printf(MSG_ERROR, "\nLink & key is required.");
		return (-1);
	}

	if ((strlen(key) >= sizeof (wpa_s.kname)))  {
		wpa_printf(MSG_ERROR, "Too long key name '%s'.", key);
		return (-1);
	}

	if (daemon(0, 0))
		return (-1);

	/*
	 * Hold this link open to prevent a link renaming operation.
	 */
	if (dlpi_open(link, &dh, 0) != DLPI_SUCCESS) {
		wpa_printf(MSG_ERROR, "Failed to open link '%s'.", link);
		return (-1);
	}

	if (dladm_name2info(link, &linkid, NULL, NULL, NULL) !=
	    DLADM_STATUS_OK) {
		wpa_printf(MSG_ERROR, "Invalid link name '%s'.", link);
		dlpi_close(dh);
		return (-1);
	}

	/*
	 * Get the device name of the link, which will be used as the door
	 * file name used to communicate with the driver. Note that different
	 * links use different doors.
	 */
	if (dladm_phys_info(linkid, &dpa, DLADM_OPT_ACTIVE) !=
	    DLADM_STATUS_OK) {
		wpa_printf(MSG_ERROR,
		    "Failed to get device name of link '%s'.", link);
		dlpi_close(dh);
		return (-1);
	}
	(void) snprintf(door_file, WPA_STRSIZE, "%s_%s", WPA_DOOR, dpa.dp_dev);

	(void) memset(&wpa_s, 0, sizeof (wpa_s));
	wpa_s.driver = &wpa_driver_wifi_ops;
	wpa_s.linkid = linkid;
	(void) strlcpy(wpa_s.kname, key, sizeof (wpa_s.kname));
	eloop_init(&wpa_s);

	/*
	 * Setup default WPA/WPA2 configuration
	 * get ESSID and PSK value
	 */
	wpa_s.conf = wpa_config_read(&wpa_s);
	if (wpa_s.conf == NULL || wpa_s.conf->ssid == NULL) {
		wpa_printf(MSG_ERROR, "\nNo networks (SSID) configured.\n");
		exitcode = -1;
		goto cleanup;
	}

	exitcode = 0;

	/*
	 * Setup door file to communicate with driver
	 */
	if (wpa_supplicant_door_setup(&wpa_s, door_file) != 0) {
		wpa_printf(MSG_ERROR, "Failed to setup door(%s)", door_file);
		exitcode = -1;
		goto cleanup;
	}

	wpa_s.renew_snonce = 1;
	if (wpa_supplicant_driver_init(link, &wpa_s) < 0) {
		exitcode = -1;
		goto cleanup;
	}

	/*
	 * This link is hold again in wpa_supplicant_driver_init(), so that
	 * we release the first reference.
	 */
	dlpi_close(dh);
	dh = NULL;

	wpa_printf(MSG_DEBUG, "=> eloop_run");

	(void) eloop_register_signal(SIGINT, wpa_supplicant_terminate, NULL);
	(void) eloop_register_signal(SIGTERM, wpa_supplicant_terminate, NULL);
	(void) eloop_register_signal(SIGKILL, wpa_supplicant_terminate, NULL);

	eloop_run();

	wpa_printf(MSG_DEBUG, "<= eloop_run()");
	wpa_supplicant_disassociate(&wpa_s, REASON_DEAUTH_LEAVING);

	if (wpa_s.driver->set_wpa(wpa_s.linkid, 0) < 0) {
		wpa_printf(MSG_ERROR, "Failed to disable WPA in the driver.\n");
	}

cleanup:
	wpa_supplicant_door_destroy(door_file);
	wpa_supplicant_cleanup(&wpa_s);
	eloop_destroy();

	if (dh != NULL)
		dlpi_close(dh);

	return (exitcode);
}
