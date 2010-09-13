/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2004, Sam Leffler <sam@errno.com>
 * Sun elects to license this software under the BSD license.
 * See README for more details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <stropts.h>
#include <string.h>
#include <stddef.h>

#include "wpa_impl.h"
#include "driver.h"

#define	WPA_STATUS(status)	(status == DLADM_STATUS_OK? 0 : -1)

/*
 * get_bssid - get the current BSSID
 * @linkid: linkid of the given interface
 * @bssid: buffer for BSSID (IEEE80211_ADDR_LEN = 6 bytes)
 *
 * Returns: 0 on success, -1 on failure
 *
 * Query kernel driver for the current BSSID and copy it to @bssid.
 * Setting @bssid to 00:00:00:00:00:00 is recommended if the STA is not
 * associated.
 */
int
wpa_driver_wifi_get_bssid(dladm_handle_t handle, datalink_id_t linkid,
    char *bssid)
{
	dladm_status_t status;
	dladm_wlan_linkattr_t attr;
	dladm_wlan_attr_t *wl_attrp;

	status = dladm_wlan_get_linkattr(handle, linkid, &attr);
	if (status != DLADM_STATUS_OK)
		return (-1);

	wl_attrp = &attr.la_wlan_attr;
	if ((attr.la_valid & DLADM_WLAN_LINKATTR_WLAN) == 0 ||
	    (wl_attrp->wa_valid & DLADM_WLAN_ATTR_BSSID) == 0)
		return (-1);

	(void) memcpy(bssid, wl_attrp->wa_bssid.wb_bytes, DLADM_WLAN_BSSID_LEN);

	wpa_printf(MSG_DEBUG, "wpa_driver_wifi_get_bssid: " MACSTR,
	    MAC2STR((unsigned char *)bssid));

	return (WPA_STATUS(status));
}

/*
 * get_ssid - get the current SSID
 * @linkid: linkid of the given interface
 * @ssid: buffer for SSID (at least 32 bytes)
 *
 * Returns: length of the SSID on success, -1 on failure
 *
 * Query kernel driver for the current SSID and copy it to @ssid.
 * Returning zero is recommended if the STA is not associated.
 */
int
wpa_driver_wifi_get_ssid(dladm_handle_t handle, datalink_id_t linkid,
    char *ssid)
{
	int ret;
	dladm_status_t status;
	dladm_wlan_linkattr_t attr;
	dladm_wlan_attr_t *wl_attrp;

	status = dladm_wlan_get_linkattr(handle, linkid, &attr);
	if (status != DLADM_STATUS_OK)
		return (-1);

	wl_attrp = &attr.la_wlan_attr;
	if ((attr.la_valid & DLADM_WLAN_LINKATTR_WLAN) == 0 ||
	    (wl_attrp->wa_valid & DLADM_WLAN_ATTR_ESSID) == 0)
		return (-1);

	(void) memcpy(ssid, wl_attrp->wa_essid.we_bytes, MAX_ESSID_LENGTH);
	ret = strlen(ssid);

	wpa_printf(MSG_DEBUG, "wpa_driver_wifi_get_ssid: ssid=%s len=%d",
	    ssid, ret);

	return (ret);
}

static int
wpa_driver_wifi_set_wpa_ie(dladm_handle_t handle, datalink_id_t linkid,
    uint8_t *wpa_ie, uint32_t wpa_ie_len)
{
	dladm_status_t status;

	wpa_printf(MSG_DEBUG, "%s", "wpa_driver_wifi_set_wpa_ie");
	status = dladm_wlan_wpa_set_ie(handle, linkid, wpa_ie, wpa_ie_len);

	return (WPA_STATUS(status));
}

/*
 * set_wpa - enable/disable WPA support
 * @linkid: linkid of the given interface
 * @enabled: 1 = enable, 0 = disable
 *
 * Returns: 0 on success, -1 on failure
 *
 * Configure the kernel driver to enable/disable WPA support. This may
 * be empty function, if WPA support is always enabled. Common
 * configuration items are WPA IE (clearing it when WPA support is
 * disabled), Privacy flag for capability field, roaming mode (need to
 * allow wpa_supplicant to control roaming).
 */
static int
wpa_driver_wifi_set_wpa(dladm_handle_t handle, datalink_id_t linkid,
    boolean_t enabled)
{
	dladm_status_t status;

	wpa_printf(MSG_DEBUG, "wpa_driver_wifi_set_wpa: enable=%d", enabled);

	if (!enabled && wpa_driver_wifi_set_wpa_ie(handle, linkid, NULL, 0) < 0)
		return (-1);

	status = dladm_wlan_wpa_set_wpa(handle, linkid, enabled);

	return (WPA_STATUS(status));
}

static int
wpa_driver_wifi_del_key(dladm_handle_t handle, datalink_id_t linkid,
    int key_idx, unsigned char *addr)
{
	dladm_status_t status;
	dladm_wlan_bssid_t bss;

	wpa_printf(MSG_DEBUG, "%s: id=%d", "wpa_driver_wifi_del_key",
	    key_idx);

	(void) memcpy(bss.wb_bytes, addr, DLADM_WLAN_BSSID_LEN);
	status = dladm_wlan_wpa_del_key(handle, linkid, key_idx, &bss);

	return (WPA_STATUS(status));
}

/*
 * set_key - configure encryption key
 * @linkid: linkid of the given interface
 * @alg: encryption algorithm (%WPA_ALG_NONE, %WPA_ALG_WEP,
 *	%WPA_ALG_TKIP, %WPA_ALG_CCMP); %WPA_ALG_NONE clears the key.
 * @addr: address of the peer STA or ff:ff:ff:ff:ff:ff for
 *	broadcast/default keys
 * @key_idx: key index (0..3), always 0 for unicast keys
 * @set_tx: configure this key as the default Tx key (only used when
 *	driver does not support separate unicast/individual key
 * @seq: sequence number/packet number, @seq_len octets, the next
 *	packet number to be used for in replay protection; configured
 *	for Rx keys (in most cases, this is only used with broadcast
 *	keys and set to zero for unicast keys)
 * @seq_len: length of the @seq, depends on the algorithm:
 *	TKIP: 6 octets, CCMP: 6 octets
 * @key: key buffer; TKIP: 16-byte temporal key, 8-byte Tx Mic key,
 *	8-byte Rx Mic Key
 * @key_len: length of the key buffer in octets (WEP: 5 or 13,
 *	TKIP: 32, CCMP: 16)
 *
 * Returns: 0 on success, -1 on failure
 *
 * Configure the given key for the kernel driver. If the driver
 * supports separate individual keys (4 default keys + 1 individual),
 * @addr can be used to determine whether the key is default or
 * individual. If only 4 keys are supported, the default key with key
 * index 0 is used as the individual key. STA must be configured to use
 * it as the default Tx key (@set_tx is set) and accept Rx for all the
 * key indexes. In most cases, WPA uses only key indexes 1 and 2 for
 * broadcast keys, so key index 0 is available for this kind of
 * configuration.
 */
static int
wpa_driver_wifi_set_key(dladm_handle_t handle, datalink_id_t linkid,
    wpa_alg alg, unsigned char *addr, int key_idx, boolean_t set_tx,
    uint8_t *seq, uint32_t seq_len, uint8_t *key, uint32_t key_len)
{
	char *alg_name;
	dladm_wlan_cipher_t cipher;
	dladm_wlan_bssid_t bss;
	dladm_status_t status;

	wpa_printf(MSG_DEBUG, "%s", "wpa_driver_wifi_set_key");
	if (alg == WPA_ALG_NONE)
		return (wpa_driver_wifi_del_key(handle, linkid, key_idx, addr));

	switch (alg) {
	case WPA_ALG_WEP:
		alg_name = "WEP";
		cipher = DLADM_WLAN_CIPHER_WEP;
		break;
	case WPA_ALG_TKIP:
		alg_name = "TKIP";
		cipher = DLADM_WLAN_CIPHER_TKIP;
		break;
	case WPA_ALG_CCMP:
		alg_name = "CCMP";
		cipher = DLADM_WLAN_CIPHER_AES_CCM;
		break;
	default:
		wpa_printf(MSG_DEBUG, "wpa_driver_wifi_set_key:"
		    " unknown/unsupported algorithm %d", alg);
		return (-1);
	}

	wpa_printf(MSG_DEBUG, "wpa_driver_wifi_set_key: alg=%s key_idx=%d"
	    " set_tx=%d seq_len=%d seq=%d key_len=%d",
	    alg_name, key_idx, set_tx,
	    seq_len, *(uint64_t *)(uintptr_t)seq, key_len);

	if (seq_len > sizeof (uint64_t)) {
		wpa_printf(MSG_DEBUG, "wpa_driver_wifi_set_key:"
		    " seq_len %d too big", seq_len);
		return (-1);
	}
	(void) memcpy(bss.wb_bytes, addr, DLADM_WLAN_BSSID_LEN);

	status = dladm_wlan_wpa_set_key(handle, linkid, cipher, &bss, set_tx,
	    *(uint64_t *)(uintptr_t)seq, key_idx, key, key_len);

	return (WPA_STATUS(status));
}

/*
 * disassociate - request driver to disassociate
 * @linkid: linkid of the given interface
 * @reason_code: 16-bit reason code to be sent in the disassociation
 * frame
 *
 * Return: 0 on success, -1 on failure
 */
static int
wpa_driver_wifi_disassociate(dladm_handle_t handle, datalink_id_t linkid,
    int reason_code)
{
	dladm_status_t status;

	wpa_printf(MSG_DEBUG, "wpa_driver_wifi_disassociate");

	status = dladm_wlan_wpa_set_mlme(handle, linkid,
	    DLADM_WLAN_MLME_DISASSOC, reason_code, NULL);

	return (WPA_STATUS(status));
}

/*
 * associate - request driver to associate
 * @linkid: linkid of the given interface
 * @bssid: BSSID of the selected AP
 * @wpa_ie: WPA information element to be included in (Re)Association
 *	Request (including information element id and length). Use of
 *	this WPA IE is optional. If the driver generates the WPA IE, it
 *	can use @pairwise_suite, @group_suite, and @key_mgmt_suite
 *	to select proper algorithms. In this case, the driver has to
 *	notify wpa_supplicant about the used WPA IE by generating an
 *	event that the interface code will convert into EVENT_ASSOCINFO
 *	data (see wpa_supplicant.h). When using WPA2/IEEE 802.11i,
 *	@wpa_ie is used for RSN IE instead. The driver can determine
 *	which version is used by looking at the first byte of the IE
 *	(0xdd for WPA, 0x30 for WPA2/RSN).
 * @wpa_ie_len: length of the @wpa_ie
 *
 * Return: 0 on success, -1 on failure
 */
static int
wpa_driver_wifi_associate(dladm_handle_t handle, datalink_id_t linkid,
    const char *bssid, uint8_t *wpa_ie, uint32_t wpa_ie_len)
{
	dladm_status_t status;
	dladm_wlan_bssid_t bss;

	wpa_printf(MSG_DEBUG, "wpa_driver_wifi_associate : "
	    MACSTR, MAC2STR(bssid));

	/*
	 * NB: Don't need to set the freq or cipher-related state as
	 * this is implied by the bssid which is used to locate
	 * the scanned node state which holds it.
	 */
	if (wpa_driver_wifi_set_wpa_ie(handle, linkid, wpa_ie, wpa_ie_len) < 0)
		return (-1);

	(void) memcpy(bss.wb_bytes, bssid, DLADM_WLAN_BSSID_LEN);
	status = dladm_wlan_wpa_set_mlme(handle, linkid, DLADM_WLAN_MLME_ASSOC,
	    0, &bss);

	return (WPA_STATUS(status));
}

/*
 * scan - request the driver to initiate scan
 * @linkid: linkid of the given interface
 *
 * Return: 0 on success, -1 on failure
 *
 * Once the scan results are ready, the driver should report scan
 * results event for wpa_supplicant which will eventually request the
 * results with wpa_driver_get_scan_results().
 */
static int
wpa_driver_wifi_scan(dladm_handle_t handle, datalink_id_t linkid)
{
	dladm_status_t status;

	wpa_printf(MSG_DEBUG, "%s", "wpa_driver_wifi_scan");
	/*
	 * We force the state to INIT before calling ieee80211_new_state
	 * to get ieee80211_begin_scan called.  We really want to scan w/o
	 * altering the current state but that's not possible right now.
	 */
	(void) wpa_driver_wifi_disassociate(handle, linkid,
	    DLADM_WLAN_REASON_DISASSOC_LEAVING);

	status = dladm_wlan_scan(handle, linkid, NULL, NULL);

	wpa_printf(MSG_DEBUG, "%s: return", "wpa_driver_wifi_scan");
	return (WPA_STATUS(status));
}

/*
 * get_scan_results - fetch the latest scan results
 * @linkid: linkid of the given interface
 * @results: pointer to buffer for scan results
 * @max_size: maximum number of entries (buffer size)
 *
 * Return: number of scan result entries used on success, -1 on failure
 *
 * If scan results include more than @max_size BSSes, @max_size will be
 * returned and the remaining entries will not be included in the
 * buffer.
 */
int
wpa_driver_wifi_get_scan_results(dladm_handle_t handle, datalink_id_t linkid,
    dladm_wlan_ess_t *results, uint32_t max_size)
{
	uint_t ret;

	wpa_printf(MSG_DEBUG, "%s: max size=%d\n",
	    "wpa_driver_wifi_get_scan_results", max_size);

	if (dladm_wlan_wpa_get_sr(handle, linkid, results, max_size, &ret)
	    != DLADM_STATUS_OK) {
		return (-1);
	}

	return (ret);
}

struct wpa_driver_ops wpa_driver_wifi_ops = {
	wpa_driver_wifi_get_bssid,
	wpa_driver_wifi_get_ssid,
	wpa_driver_wifi_set_wpa,
	wpa_driver_wifi_set_key,
	wpa_driver_wifi_scan,
	wpa_driver_wifi_get_scan_results,
	wpa_driver_wifi_disassociate,
	wpa_driver_wifi_associate
};
