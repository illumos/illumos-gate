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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <execinfo.h>
#include <kstat.h>
#include <libdladm.h>
#include <libdllink.h>
#include <libdlstat.h>
#include <libdlwlan.h>
#include <libnwam.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <libdlpi.h>
#include <ucontext.h>

#include "events.h"
#include "llp.h"
#include "objects.h"
#include "ncp.h"
#include "ncu.h"
#include "known_wlans.h"
#include "util.h"

/*
 * ncu_phys.c - contains routines that are physical-link specific.
 * Mostly WiFi code.
 */

/*
 * Get link state from kstats. Used to determine initial link state for
 * cases where drivers do not support DL_NOTE_LINK_UP/DOWN.  If link
 * state is LINK_STATE_UNKNOWN, we assume the link is up and the IP NCU
 * timeout will cause us to move on to other links.
 */
link_state_t
nwamd_get_link_state(const char *name)
{
	kstat_ctl_t *kcp;
	kstat_t *ksp;
	char module[DLPI_LINKNAME_MAX];
	uint_t instance;
	link_state_t link_state = LINK_STATE_UNKNOWN;

	if ((kcp = kstat_open()) == NULL)
		return (link_state);

	if (dlpi_parselink(name, module, &instance) != DLPI_SUCCESS)
		goto out;

	if ((ksp = kstat_lookup(kcp, module, instance, "mac")) == NULL) {
		/*
		 * The kstat query could fail if the underlying MAC
		 * driver was already detached.
		 */
		goto out;
	}

	if (kstat_read(kcp, ksp, NULL) == -1)
		goto out;

	(void) dladm_kstat_value(ksp, "link_state", KSTAT_DATA_UINT32,
	    &link_state);

out:
	(void) kstat_close(kcp);

	return (link_state);
}

/*
 * Set/unset link propeties.  At present, these are MAC address, link MTU and
 * autopush modules.  We set MAC address last as setting it may cause a chip
 * reset which can prevent other device property setting succeeding.
 */
void
nwamd_set_unset_link_properties(nwamd_ncu_t *ncu, boolean_t set)
{
	dlpi_handle_t dh = ncu->ncu_link.nwamd_link_dhp;
	char *addr = set ? ncu->ncu_link.nwamd_link_mac_addr : NULL;
	uint64_t mtu = set ? ncu->ncu_link.nwamd_link_mtu : 0;
	char **autopush = set ? ncu->ncu_link.nwamd_link_autopush : NULL;
	uint_t num_autopush = set ? ncu->ncu_link.nwamd_link_num_autopush : 0;
	uchar_t *hwaddr = NULL, curraddr[DLPI_PHYSADDR_MAX];
	size_t hwaddrlen = DLPI_PHYSADDR_MAX;
	int retval;
	dladm_status_t status;
	char mtustr[DLADM_PROP_VAL_MAX];
	char *cp;
	char errmsg[DLADM_STRSIZE];
	uint_t cnt = 1;

	/*
	 * Set MTU here - either default value (if mtu == 0 indicating it has
	 * not been set) or specified value.
	 */
	if (mtu == 0) {
		cp = mtustr;
		status = dladm_get_linkprop(dld_handle,
		    ncu->ncu_link.nwamd_link_id, DLADM_PROP_VAL_DEFAULT, "mtu",
		    &cp, &cnt);
		if (status != DLADM_STATUS_OK) {
			nlog(LOG_ERR, "nwamd_set_unset_link_properties: "
			    "dladm_get_linkprop failed: %s",
			    dladm_status2str(status, errmsg));
			return;
		}
	} else {
		(void) snprintf(mtustr, DLADM_PROP_VAL_MAX, "%lld", mtu);
	}

	cp = mtustr;

	nlog(LOG_DEBUG, "nwamd_set_unset_link_properties: setting MTU of %s "
	    "for link %s", mtustr, ncu->ncu_name);
	status = dladm_set_linkprop(dld_handle, ncu->ncu_link.nwamd_link_id,
	    "mtu", &cp, 1, DLADM_OPT_ACTIVE);
	if (status != DLADM_STATUS_OK) {
		nlog(LOG_ERR, "nwamd_set_unset_link_properties: "
		    "dladm_set_linkprop failed: %s",
		    dladm_status2str(status, errmsg));
	}

	nlog(LOG_DEBUG, "nwamd_set_unset_link_properties: setting %d "
	    "autopush module for link %s", num_autopush, ncu->ncu_name);
	status = dladm_set_linkprop(dld_handle, ncu->ncu_link.nwamd_link_id,
	    "autopush", autopush, num_autopush, DLADM_OPT_ACTIVE);
	if (status != DLADM_STATUS_OK) {
		nlog(LOG_ERR, "nwamd_set_unset_link_properties: "
		    "dladm_set_linkprop failed for autopush property: %s",
		    dladm_status2str(status, errmsg));
	}

	/*
	 * Set physical address - either factory (if link_mac_addr is NULL
	 * or we are unsetting properties) or specified MAC address string.
	 */
	if (addr == NULL) {
		if ((hwaddr = calloc(1, DLPI_PHYSADDR_MAX)) == NULL) {
			nlog(LOG_ERR,
			    "nwamd_set_unset_link_properties: malloc() failed");
			return;
		}
		if ((retval = dlpi_get_physaddr(dh, DL_FACT_PHYS_ADDR,
		    hwaddr, &hwaddrlen)) != DLPI_SUCCESS) {
			nlog(LOG_ERR, "nwamd_set_unset_link_properties: "
			    "could not get physical address for %s: %s",
			    ncu->ncu_name, dlpi_strerror(retval));
			free(hwaddr);
			return;
		}
	} else {
		int addrlen = hwaddrlen;
		if ((hwaddr = _link_aton(addr, &addrlen)) == NULL) {
			if (addrlen == -1) {
				nlog(LOG_ERR,
				    "nwamd_set_unset_link_properties: "
				    "%s: bad address for %s",
				    addr, ncu->ncu_name);
				return;
			} else {
				nlog(LOG_ERR, "nwamd_set_unset_link_properties:"
				    " malloc() failed");
				return;
			}
		}
		hwaddrlen = addrlen;
	}

	/*
	 * Only set physical address if desired address differs from current -
	 * this avoids unnecessary chip resets for some drivers.
	 */
	retval = dlpi_get_physaddr(dh, DL_CURR_PHYS_ADDR, curraddr,
	    &hwaddrlen);
	if (retval != DLPI_SUCCESS || bcmp(curraddr, hwaddr, hwaddrlen) != 0) {
		retval = dlpi_set_physaddr(dh, DL_CURR_PHYS_ADDR, hwaddr,
		    hwaddrlen);
		if (retval != DLPI_SUCCESS) {
			nlog(LOG_ERR, "nwamd_set_unset_link_properties:"
			    "failed setting mac address on %s: %s",
			    ncu->ncu_name, dlpi_strerror(retval));
		}
	}
	free(hwaddr);
}

#define	WLAN_ENC(sec)						\
	((sec == DLADM_WLAN_SECMODE_WPA ? "WPA" : 		\
	(sec == DLADM_WLAN_SECMODE_WEP ? "WEP" : "none")))

#define	NEED_ENC(sec)						\
	(sec == DLADM_WLAN_SECMODE_WPA || sec == DLADM_WLAN_SECMODE_WEP)

#define	WIRELESS_LAN_INIT_COUNT	8

/*
 * The variable wireless_scan_level specifies the signal level
 * that we will initiate connections to previously-visited APs
 * at when we are in the connected state.
 */
dladm_wlan_strength_t wireless_scan_level = DLADM_WLAN_STRENGTH_WEAK;

/*
 * The variable wireless_scan_interval specifies how often the periodic
 * scan occurs.
 */
uint64_t wireless_scan_interval = WIRELESS_SCAN_INTERVAL_DEFAULT;

/*
 * The variable wireless_autoconf specifies if we use dladm_wlan_autoconf()
 * to connect.
 */
boolean_t wireless_autoconf = B_FALSE;

/*
 * The variable wireless_strict_bssid specifies if we only connect
 * to WLANs with BSSIDs that we previously connected to.
 */
boolean_t wireless_strict_bssid = B_FALSE;

/*
 * We need to ensure scan or connect threads do not run concurrently
 * on any links - otherwise we get radio interference.  Acquire this
 * lock on entering scan/connect threads to prevent this.
 */
pthread_mutex_t wireless_mutex = PTHREAD_MUTEX_INITIALIZER;

static void
scanconnect_entry(void)
{
	(void) pthread_mutex_lock(&wireless_mutex);
}

static void
scanconnect_exit(void)
{
	(void) pthread_mutex_unlock(&wireless_mutex);
}

/*
 * Below are functions used to handle storage/retrieval of keys
 * for a given WLAN. The keys are stored/retrieved using dladm_set_secobj()
 * and dladm_get_secobj().
 */

/*
 * Convert key hexascii string to raw secobj value. This
 * code is very similar to convert_secobj() in dladm.c, it would
 * be good to have a libdladm function to convert values.
 */
static int
key_string_to_secobj_value(char *buf, uint8_t *obj_val, uint_t *obj_lenp,
    dladm_secobj_class_t class)
{
	size_t buf_len = strlen(buf);

	nlog(LOG_DEBUG, "before: key_string_to_secobj_value: buf_len = %d",
	    buf_len);
	if (buf_len == 0) {
		/* length zero means "delete" */
		return (0);
	}

	if (buf[buf_len - 1] == '\n')
		buf[--buf_len] = '\0';

	nlog(LOG_DEBUG, "after: key_string_to_secobj_value: buf_len = %d",
	    buf_len);

	if (class == DLADM_SECOBJ_CLASS_WPA) {
		/*
		 * Per IEEE802.11i spec, the Pre-shared key (PSK) length should
		 * be between 8 and 63.
		 */
		if (buf_len < 8 || buf_len > 63) {
			nlog(LOG_ERR,
			    "key_string_to_secobj_value:"
			    " invalid WPA key length: buf_len = %d", buf_len);
			return (-1);
		}
		(void) memcpy(obj_val, buf, (uint_t)buf_len);
		*obj_lenp = buf_len;
		return (0);
	}

	switch (buf_len) {
	case 5:		/* ASCII key sizes */
	case 13:
		(void) memcpy(obj_val, buf, (uint_t)buf_len);
		*obj_lenp = (uint_t)buf_len;
		break;
	case 10:
	case 26:	/* Hex key sizes, not preceded by 0x */
		if (hexascii_to_octet(buf, (uint_t)buf_len, obj_val, obj_lenp)
		    != 0) {
			nlog(LOG_ERR,
			    "key_string_to_secobj_value: invalid WEP key");
			return (-1);
		}
		break;
	case 12:
	case 28:	/* Hex key sizes, preceded by 0x */
		if (strncmp(buf, "0x", 2) != 0 ||
		    hexascii_to_octet(buf + 2, (uint_t)buf_len - 2, obj_val,
		    obj_lenp) != 0) {
			nlog(LOG_ERR,
			    "key_string_to_secobj_value: invalid WEP key");
			return (-1);
		}
		break;
	default:
		syslog(LOG_ERR,
		    "key_string_to_secobj_value: invalid WEP key length");
		return (-1);
	}
	return (0);
}

/*
 * Callback used on each known WLAN:
 * return 1 if a secobj, linked with an existing kwown wlan, has the same name
 * of the secobj that is being created.
 */

static int
find_keyname_cb(nwam_known_wlan_handle_t kwh, void *new_keyname)
{
	nwam_error_t err;
	nwam_value_t old_key;

	char **old_keyname;
	uint_t num_old_keyname, i;

	if ((err = nwam_known_wlan_get_prop_value(kwh,
	    NWAM_KNOWN_WLAN_PROP_KEYNAME, &old_key)) != NWAM_SUCCESS) {
		nlog(LOG_ERR, "find_keyname_cb: nwam_known_wlan_get_prop: %s",
		    nwam_strerror(err));
		return (0);
	}
	if ((err = nwam_value_get_string_array(old_key, &old_keyname,
	    &num_old_keyname))
	    != NWAM_SUCCESS) {
		nlog(LOG_ERR, "find_keyname_cb: nwam_value_get_string: %s",
		    nwam_strerror(err));
		nwam_value_free(old_key);
		return (0);
	}
	nwam_value_free(old_key);
	for (i = 0; i < num_old_keyname; i++) {
		if (strcmp(old_keyname[i], (const char *)new_keyname) == 0)
			/* Found matching keyname so terminate walk */
			return (1);
	}
	return (0);
}

/*
 * Print the key name format into the appropriate field, then convert any ":"
 * characters to ".", as ":[1-4]" is the slot indicator, which otherwise
 * would trip us up.  Invalid characters for secobj names are ignored.
 * The fourth parameter is expected to be of size DLADM_SECOBJ_NAME_MAX.
 *
 * (Note that much of the system uses DLADM_WLAN_MAX_KEYNAME_LEN, which is 64
 * rather than 32, but that dladm_get_secobj will fail if a length greater than
 * DLD_SECOBJ_NAME_MAX is seen, and that's 32.  This is all horribly broken.)
 */
void
nwamd_set_key_name(const char *essid, const char *bssid, char *name, size_t nsz)
{
	int i, j;
	char secobj_name[DLADM_WLAN_MAX_KEYNAME_LEN];

	/* create a concatenated string with essid and bssid */
	if (bssid == NULL || bssid[0] == '\0') {
		(void) snprintf(secobj_name, sizeof (secobj_name), "nwam-%s",
		    essid);
	} else {
		(void) snprintf(secobj_name, sizeof (secobj_name), "nwam-%s-%s",
		    essid, bssid);
	}

	/* copy only valid chars to the return string, terminating with \0 */
	i = 0; /* index into secobj_name */
	j = 0; /* index into name */
	while (secobj_name[i] != '\0') {
		if (j == nsz - 1)
			break;

		if (secobj_name[i] == ':') {
			name[j] = '.';
			j++;
		} else if (isalnum(secobj_name[i]) ||
		    secobj_name[i] == '.' || secobj_name[i] == '-' ||
		    secobj_name[i] == '_') {
			name[j] = secobj_name[i];
			j++;
		}
		i++;
	}
	name[j] = '\0';
}

nwam_error_t
nwamd_wlan_set_key(const char *linkname, const char *essid, const char *bssid,
    uint32_t security_mode, uint_t keyslot, char *raw_key)
{
	nwamd_object_t ncu_obj;
	nwamd_ncu_t *ncu;
	nwamd_link_t *link;
	int ret = 0;
	uint8_t obj_val[DLADM_SECOBJ_VAL_MAX];
	uint_t obj_len = sizeof (obj_val);
	char obj_name[DLADM_SECOBJ_NAME_MAX];
	char obj_tempname[DLADM_SECOBJ_NAME_MAX];
	dladm_status_t status;
	char errmsg[DLADM_STRSIZE];
	dladm_secobj_class_t class;

	if ((ncu_obj = nwamd_ncu_object_find(NWAM_NCU_TYPE_LINK, linkname))
	    == NULL) {
		nlog(LOG_ERR, "nwamd_wlan_set_key: could not find object  "
		    "for link %s", linkname);
		return (NWAM_ENTITY_NOT_FOUND);
	}
	ncu = ncu_obj->nwamd_object_data;
	link = &ncu->ncu_link;

	class = (security_mode == DLADM_WLAN_SECMODE_WEP ?
	    DLADM_SECOBJ_CLASS_WEP : DLADM_SECOBJ_CLASS_WPA);
	if (key_string_to_secobj_value(raw_key, obj_val, &obj_len,
	    class) != 0) {
		/* above function logs internally on failure */
		nwamd_object_release(ncu_obj);
		return (NWAM_ERROR_INTERNAL);
	}

	nlog(LOG_DEBUG, "nwamd_wlan_set_key: running for link %s", linkname);
	/*
	 * Name key object for this WLAN so it can be later retrieved.
	 * (bssid is appended if an object, with the same keyname,
	 * already exists and is associated to a known wlan)
	 */
	nwamd_set_key_name(essid, NULL, obj_tempname, sizeof (obj_tempname));
	(void) nwam_walk_known_wlans(find_keyname_cb, obj_tempname, 0, &ret);
	/*
	 * We also check if the keyval is the same. The user might want
	 * to use the same key for more APs with the same ESSID.
	 * This can result in a known wlan with multiple BSSIDs
	 */
	if (ret == 1) {
		dladm_wlan_key_t *old_secobj = nwamd_wlan_get_key_named(
		    obj_tempname, security_mode);
		nlog(LOG_DEBUG, "found existing obj_name %s", obj_tempname);
		ret = memcmp((*old_secobj).wk_val, obj_val, obj_len);
		nwamd_set_key_name(essid, ret ? bssid : NULL, obj_name,
		    sizeof (obj_name));
		free(old_secobj);
	} else {
		nwamd_set_key_name(essid, NULL, obj_name,
		    sizeof (obj_name));
	}
	nlog(LOG_DEBUG, "store_key: obj_name is %s", obj_name);

	/*
	 * We have validated the new key, so remove the old one.
	 * This will actually delete the keyobj only if the user had set
	 * a wrong key and is replacing it with a new one for the same AP.
	 */
	status = dladm_unset_secobj(dld_handle, obj_name,
	    DLADM_OPT_ACTIVE | DLADM_OPT_PERSIST);
	if (status != DLADM_STATUS_OK && status != DLADM_STATUS_NOTFOUND) {
		nlog(LOG_ERR, "store_key: could not remove old secure object "
		    "'%s' for key: %s", obj_name,
		    dladm_status2str(status, errmsg));
		nwamd_object_release(ncu_obj);
		return (NWAM_ERROR_INTERNAL);
	}

	/* if we're just deleting the key, then we're done */
	if (raw_key[0] == '\0') {
		nwamd_object_release(ncu_obj);
		return (NWAM_SUCCESS);
	}

	status = dladm_set_secobj(dld_handle, obj_name, class,
	    obj_val, obj_len,
	    DLADM_OPT_CREATE | DLADM_OPT_PERSIST | DLADM_OPT_ACTIVE);
	if (status != DLADM_STATUS_OK) {
		nlog(LOG_ERR, "store_key: could not create secure object "
		    "'%s' for key: %s", obj_name,
		    dladm_status2str(status, errmsg));
		nwamd_object_release(ncu_obj);
		return (NWAM_ERROR_INTERNAL);
	}
	link->nwamd_link_wifi_key = nwamd_wlan_get_key_named(obj_name,
	    security_mode);
	(void) strlcpy(link->nwamd_link_wifi_keyname, obj_name,
	    sizeof (link->nwamd_link_wifi_keyname));
	link->nwamd_link_wifi_security_mode = security_mode;
	if (security_mode == DLADM_WLAN_SECMODE_WEP) {
		link->nwamd_link_wifi_key->wk_idx =
		    (keyslot >= 1 && keyslot <= 4) ? keyslot : 1;
	}

	/* If link NCU is offline* or online, (re)connect. */
	switch (ncu_obj->nwamd_object_state) {
	case NWAM_STATE_ONLINE:
		/* if changing the key of the connected WLAN, reconnect */
		if (strcmp(essid, link->nwamd_link_wifi_essid) == 0)
			nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
			    ncu_obj->nwamd_object_name, NWAM_STATE_ONLINE,
			    NWAM_AUX_STATE_LINK_WIFI_CONNECTING);
		break;
	case NWAM_STATE_OFFLINE_TO_ONLINE:
		/* if we are waiting for the key, connect */
		if (ncu_obj->nwamd_object_aux_state ==
		    NWAM_AUX_STATE_LINK_WIFI_NEED_KEY)
			nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
			    ncu_obj->nwamd_object_name,
			    NWAM_STATE_OFFLINE_TO_ONLINE,
			    NWAM_AUX_STATE_LINK_WIFI_CONNECTING);
		break;
	default:
		break;
	}
	nwamd_object_release(ncu_obj);

	return (NWAM_SUCCESS);
}

/*
 * returns NULL if no key was recovered from libdladm.  Passing in
 * security mode of 0 means we don't care what key type it is.
 */
dladm_wlan_key_t *
nwamd_wlan_get_key_named(const char *name, uint32_t security_mode)
{
	dladm_status_t status;
	char errmsg[DLADM_STRSIZE];
	dladm_wlan_key_t *cooked_key;
	dladm_secobj_class_t class;

	if (security_mode == DLADM_WLAN_SECMODE_NONE)
		return (NULL);

	/*
	 * Newly-allocated key must be freed by caller, or by
	 * subsequent call to nwamd_wlan_get_key_named().
	 */
	if ((cooked_key = malloc(sizeof (dladm_wlan_key_t))) == NULL) {
		nlog(LOG_ERR, "nwamd_wlan_get_key_named: malloc failed");
		return (NULL);
	}

	/*
	 * Set name appropriately to retrieve key for this WLAN.  Note that we
	 * cannot use the actual wk_name buffer size, as it's two times too
	 * large for dladm_get_secobj.
	 */
	(void) strlcpy(cooked_key->wk_name, name, DLADM_SECOBJ_NAME_MAX);
	nlog(LOG_DEBUG, "nwamd_wlan_get_key_named: len = %d, object = %s\n",
	    strlen(cooked_key->wk_name), cooked_key->wk_name);
	cooked_key->wk_len = sizeof (cooked_key->wk_val);
	cooked_key->wk_idx = 1;

	/* Try the kernel first, then fall back to persistent storage. */
	status = dladm_get_secobj(dld_handle, cooked_key->wk_name, &class,
	    cooked_key->wk_val, &cooked_key->wk_len,
	    DLADM_OPT_ACTIVE);
	if (status != DLADM_STATUS_OK) {
		nlog(LOG_DEBUG, "nwamd_wlan_get_key_named: "
		    "dladm_get_secobj(TEMP) failed: %s",
		    dladm_status2str(status, errmsg));
		status = dladm_get_secobj(dld_handle, cooked_key->wk_name,
		    &class, cooked_key->wk_val, &cooked_key->wk_len,
		    DLADM_OPT_PERSIST);
	}

	switch (status) {
	case DLADM_STATUS_OK:
		nlog(LOG_DEBUG, "nwamd_wlan_get_key_named: "
		    "dladm_get_secobj succeeded: len %d", cooked_key->wk_len);
		break;
	case DLADM_STATUS_NOTFOUND:
		/*
		 * We do not want an error in the case that the secobj
		 * is not found, since we then prompt for it.
		 */
		free(cooked_key);
		return (NULL);
	default:
		nlog(LOG_ERR, "nwamd_wlan_get_key_named: could not get key "
		    "from secure object '%s': %s", cooked_key->wk_name,
		    dladm_status2str(status, errmsg));
		free(cooked_key);
		return (NULL);
	}

	if (security_mode != 0) {
		switch (class) {
		case DLADM_SECOBJ_CLASS_WEP:
			if (security_mode == DLADM_WLAN_SECMODE_WEP)
				return (cooked_key);
			break;
		case DLADM_SECOBJ_CLASS_WPA:
			if (security_mode == DLADM_WLAN_SECMODE_WPA)
				return (cooked_key);
			break;
		default:
			/* shouldn't happen */
			nlog(LOG_ERR, "nwamd_wlan_get_key: invalid class %d",
			    class);
			break;
		}
		/* key type mismatch */
		nlog(LOG_ERR, "nwamd_wlan_get_key: key type mismatch"
		    " from secure object '%s'", cooked_key->wk_name);
		free(cooked_key);
		return (NULL);
	}

	return (cooked_key);
}

static dladm_wlan_key_t *
nwamd_wlan_get_key(const char *essid, const char *bssid, uint32_t security_mode)
{
	char keyname[DLADM_SECOBJ_NAME_MAX];

	nwamd_set_key_name(essid, bssid, keyname, DLADM_SECOBJ_NAME_MAX);

	return (nwamd_wlan_get_key_named(keyname, security_mode));
}

/*
 * Checks if a wireless network can be selected or not.  A wireless network
 * CANNOT be selected if the NCU is DISABLED, or the NCU is OFFLINE or
 * ONLINE* and has lower priority than the currently active priority-group.
 * Called with object lock held.
 */
static boolean_t
wireless_selection_possible(nwamd_object_t object)
{
	nwamd_ncu_t *ncu = object->nwamd_object_data;

	if (ncu->ncu_link.nwamd_link_media != DL_WIFI)
		return (B_FALSE);

	(void) pthread_mutex_lock(&active_ncp_mutex);
	if (object->nwamd_object_state == NWAM_STATE_DISABLED ||
	    ((object->nwamd_object_state == NWAM_STATE_OFFLINE ||
	    object->nwamd_object_state == NWAM_STATE_ONLINE_TO_OFFLINE) &&
	    ncu->ncu_link.nwamd_link_activation_mode ==
	    NWAM_ACTIVATION_MODE_PRIORITIZED &&
	    (current_ncu_priority_group == INVALID_PRIORITY_GROUP ||
	    ncu->ncu_link.nwamd_link_priority_group >
	    current_ncu_priority_group))) {
		(void) pthread_mutex_unlock(&active_ncp_mutex);
		return (B_FALSE);
	}
	(void) pthread_mutex_unlock(&active_ncp_mutex);

	return (B_TRUE);
}

/*
 * Update the selected and/or connected values for the
 * scan data.  If these change, we need to trigger a scan
 * event since the updated values need to be communicated
 * to the GUI.
 */
void
nwamd_set_selected_connected(nwamd_ncu_t *ncu, boolean_t selected,
    boolean_t connected)
{
	nwamd_link_t *link = &ncu->ncu_link;
	nwamd_wifi_scan_t *s = &link->nwamd_link_wifi_scan;
	int i;
	boolean_t trigger_scan_event = B_FALSE;

	for (i = 0; i < s->nwamd_wifi_scan_curr_num; i++) {
		if (strcmp(s->nwamd_wifi_scan_curr[i].nww_essid,
		    link->nwamd_link_wifi_essid) != 0 ||
		    (link->nwamd_link_wifi_bssid[0] != '\0' &&
		    strcmp(s->nwamd_wifi_scan_curr[i].nww_bssid,
		    link->nwamd_link_wifi_bssid) != 0))
			continue;
		if (selected) {
			if (!s->nwamd_wifi_scan_curr[i].nww_selected)
				trigger_scan_event = B_TRUE;
			s->nwamd_wifi_scan_curr[i].nww_selected = B_TRUE;
		} else {
			if (s->nwamd_wifi_scan_curr[i].nww_selected)
				trigger_scan_event = B_TRUE;
			s->nwamd_wifi_scan_curr[i].nww_selected = B_FALSE;
		}
		if (connected) {
			if (!s->nwamd_wifi_scan_curr[i].nww_connected)
				trigger_scan_event = B_TRUE;
			s->nwamd_wifi_scan_curr[i].nww_connected = B_TRUE;
		} else {
			if (s->nwamd_wifi_scan_curr[i].nww_connected)
				trigger_scan_event = B_TRUE;
			s->nwamd_wifi_scan_curr[i].nww_connected = B_FALSE;
		}
	}

	if (trigger_scan_event || s->nwamd_wifi_scan_changed) {
		nwamd_event_t scan_event = nwamd_event_init_wlan
		    (ncu->ncu_name, NWAM_EVENT_TYPE_WLAN_SCAN_REPORT, connected,
		    s->nwamd_wifi_scan_curr, s->nwamd_wifi_scan_curr_num);
		if (scan_event != NULL) {
			/* Avoid sending same scan data multiple times */
			s->nwamd_wifi_scan_changed = B_FALSE;
			nwamd_event_enqueue(scan_event);
		}
	}
}

/*
 * Callback used on each known WLAN - if the BSSID is matched, set
 * the ESSID of the hidden WLAN to the known WLAN name.
 */
static int
find_bssid_cb(nwam_known_wlan_handle_t kwh, void *data)
{
	nwamd_link_t *link = data;
	nwam_error_t err;
	nwam_value_t bssidval;
	char **bssids, *name;
	uint_t num_bssids, i;

	if ((err = nwam_known_wlan_get_prop_value(kwh,
	    NWAM_KNOWN_WLAN_PROP_BSSIDS, &bssidval)) != NWAM_SUCCESS) {
		nlog(LOG_ERR, "find_bssid_cb: nwam_known_wlan_get_prop: %s",
		    nwam_strerror(err));
		return (0);
	}
	if ((err = nwam_value_get_string_array(bssidval, &bssids, &num_bssids))
	    != NWAM_SUCCESS) {
		nlog(LOG_ERR, "find_bssid_cb: nwam_value_get_string_array: %s",
		    nwam_strerror(err));
		nwam_value_free(bssidval);
		return (0);
	}
	for (i = 0; i < num_bssids; i++) {
		if (strcmp(bssids[i], link->nwamd_link_wifi_bssid) == 0) {
			if ((err = nwam_known_wlan_get_name(kwh, &name))
			    != NWAM_SUCCESS) {
				nlog(LOG_ERR, "find_bssid_cb: "
				    "nwam_known_wlan_get_name: %s",
				    nwam_strerror(err));
				continue;
			}
			(void) strlcpy(link->nwamd_link_wifi_essid, name,
			    sizeof (link->nwamd_link_wifi_essid));
			free(name);
			nwam_value_free(bssidval);
			/* Found ESSID for BSSID so terminate walk */
			return (1);
		}
	}
	nwam_value_free(bssidval);

	return (0);
}

/*
 * We may have encountered a BSSID for a hidden WLAN before and as a result
 * may have a known WLAN entry with this BSSID.  Walk known WLANs, searching
 * for a BSSID match.  Called with object lock held.
 */
static void
check_if_hidden_wlan_was_visited(nwamd_link_t *link)
{
	(void) nwam_walk_known_wlans(find_bssid_cb, link,
	    NWAM_FLAG_KNOWN_WLAN_WALK_PRIORITY_ORDER, NULL);
}

nwam_error_t
nwamd_wlan_select(const char *linkname, const char *essid, const char *bssid,
    uint32_t security_mode, boolean_t add_to_known_wlans)
{
	nwamd_object_t ncu_obj;
	nwamd_ncu_t *ncu;
	nwamd_link_t *link;
	boolean_t found_key = B_FALSE;

	if ((ncu_obj = nwamd_ncu_object_find(NWAM_NCU_TYPE_LINK, linkname))
	    == NULL) {
		nlog(LOG_ERR, "nwamd_wlan_select: could not find object  "
		    "for link %s", linkname);
		return (NWAM_ENTITY_NOT_FOUND);
	}
	ncu = ncu_obj->nwamd_object_data;
	link = &ncu->ncu_link;

	/*
	 * If wireless selection is not possible because of the current
	 * state or priority-group, then stop.
	 */
	if (!wireless_selection_possible(ncu_obj)) {
		nwamd_object_release(ncu_obj);
		return (NWAM_ENTITY_INVALID_STATE);
	}

	/* unset selected, connected flag for previously connected wlan */
	nwamd_set_selected_connected(ncu, B_FALSE, B_FALSE);

	/* Disconnect to allow new selection to go ahead */
	(void) dladm_wlan_disconnect(dld_handle, link->nwamd_link_id);

	(void) strlcpy(link->nwamd_link_wifi_essid, essid,
	    sizeof (link->nwamd_link_wifi_essid));
	(void) strlcpy(link->nwamd_link_wifi_bssid, bssid,
	    sizeof (link->nwamd_link_wifi_bssid));
	link->nwamd_link_wifi_security_mode = security_mode;
	link->nwamd_link_wifi_add_to_known_wlans = add_to_known_wlans;

	/* If this is a hidden wlan, then essid is empty */
	if (link->nwamd_link_wifi_essid[0] == '\0')
		check_if_hidden_wlan_was_visited(link);

	/* set selected flag for newly-selected WLAN */
	nwamd_set_selected_connected(ncu, B_TRUE, B_FALSE);

	/* does this WLAN require a key? If so go to NEED_KEY */
	if (NEED_ENC(link->nwamd_link_wifi_security_mode)) {
		/*
		 * nwam secobjs can have two formats: nwam-ESSID-BSSID and
		 * nwam-ESSID. There is no reason for searching through known
		 * wlan keynames since this is only the selection process.
		 */
		if ((link->nwamd_link_wifi_key = nwamd_wlan_get_key
		    (link->nwamd_link_wifi_essid, link->nwamd_link_wifi_bssid,
		    link->nwamd_link_wifi_security_mode)) != NULL) {
			/*
			 * Found old key format,
			 * known wlans with similar names might exist
			 */
			nwamd_set_key_name(link->nwamd_link_wifi_essid,
			    link->nwamd_link_wifi_bssid,
			    link->nwamd_link_wifi_keyname,
			    DLADM_SECOBJ_NAME_MAX);
			nlog(LOG_DEBUG, "nwamd_wlan_select: got old format "
			    "WLAN key %s",
			    link->nwamd_link_wifi_keyname);
			found_key = B_TRUE;
		} else if ((link->nwamd_link_wifi_key = nwamd_wlan_get_key
		    (link->nwamd_link_wifi_essid, NULL,
		    link->nwamd_link_wifi_security_mode)) != NULL) {
			nwamd_set_key_name(link->nwamd_link_wifi_essid, NULL,
			    link->nwamd_link_wifi_keyname,
			    DLADM_SECOBJ_NAME_MAX);
			nlog(LOG_DEBUG, "nwamd_wlan_select: got WLAN key %s",
			    link->nwamd_link_wifi_keyname);
			found_key = B_TRUE;
		} else {
			nlog(LOG_ERR, "nwamd_wlan_select: could not "
			    "find key for WLAN '%s'",
			    link->nwamd_link_wifi_essid);
		}
	} else {
		free(link->nwamd_link_wifi_key);
		link->nwamd_link_wifi_key = NULL;
		link->nwamd_link_wifi_keyname[0] = '\0';
	}

	if (NEED_ENC(link->nwamd_link_wifi_security_mode) && !found_key) {
		nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
		    ncu_obj->nwamd_object_name,
		    NWAM_STATE_OFFLINE_TO_ONLINE,
		    NWAM_AUX_STATE_LINK_WIFI_NEED_KEY);
	} else {
		nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
		    ncu_obj->nwamd_object_name, NWAM_STATE_OFFLINE_TO_ONLINE,
		    NWAM_AUX_STATE_LINK_WIFI_CONNECTING);
	}
	nwamd_object_release(ncu_obj);

	return (NWAM_SUCCESS);
}

/*
 * See if BSSID is in visited list of BSSIDs for known WLAN. Used for
 * strict BSSID matching (depends on wireless_strict_bssid property value).
 */
static int
bssid_match(nwam_known_wlan_handle_t kwh, void *bssid)
{
	nwam_value_t bssidsval;
	nwam_error_t err;
	char **bssids;
	uint_t nelem, i;
	int found = 0;

	if ((err = nwam_known_wlan_get_prop_value(kwh,
	    NWAM_KNOWN_WLAN_PROP_BSSIDS, &bssidsval)) != NWAM_SUCCESS) {
		nlog(LOG_ERR, "bssid_match: %s", nwam_strerror(err));
		return (0);
	}
	if ((err = nwam_value_get_string_array(bssidsval, &bssids, &nelem))
	    != NWAM_SUCCESS) {
		nwam_value_free(bssidsval);
		return (0);
	}
	for (i = 0; i < nelem; i++) {
		if (strcmp((const char *)bssid, bssids[i]) == 0) {
			found = 1;
			break;
		}
	}
	nwam_value_free(bssidsval);

	return (found);
}

/* Find most prioritized AP with strongest signal in scan data. */
static int
find_best_wlan_cb(nwam_known_wlan_handle_t kwh, void *data)
{
	nwamd_ncu_t *ncu = data;
	nwamd_link_t *link = &ncu->ncu_link;
	nwamd_wifi_scan_t *s = &link->nwamd_link_wifi_scan;
	nwam_error_t err;
	char *name = NULL;
	int i;
	dladm_wlan_strength_t curr_strength = 0;
	dladm_wlan_strength_t max_strength = 0;
	boolean_t found = B_FALSE;

	if ((err = nwam_known_wlan_get_name(kwh, &name)) != NWAM_SUCCESS) {
		nlog(LOG_ERR, "find_best_wlan_cb: could not look up name: %s",
		    nwam_strerror(err));
		return (0);
	}

	if (link->nwamd_link_wifi_connected) {
		(void) dladm_wlan_str2strength
		    (link->nwamd_link_wifi_signal_strength, &curr_strength);
	}

	/*
	 * If we're >= scan level, don't pick another Known WLAN if still
	 * connected (even if a Known WLAN with higher priority is available).
	 * If the user wants to connect to a different Known WLAN, it can be
	 * done from the GUI or select-wifi subcommand of nwamadm(8).
	 */
	if (curr_strength >= wireless_scan_level &&
	    link->nwamd_link_wifi_connected) {
		free(name);
		return (1);
	}

	for (i = 0; i < s->nwamd_wifi_scan_curr_num; i++) {
		nwam_wlan_t *cur_wlan = &(s->nwamd_wifi_scan_curr[i]);
		int b_match = bssid_match(kwh, cur_wlan->nww_bssid);

		/*
		 * We need to either match the scanned essid, or in the case
		 * where the essid was not broadcast, match the scanned bssid.
		 */
		if (strcmp(cur_wlan->nww_essid, name) != 0 &&
		    !(cur_wlan->nww_essid[0] == '\0' && b_match))
			continue;
		/*
		 * If wireless_strict_bssid is specified, need to match
		 * BSSID too.
		 */
		if (wireless_strict_bssid && !b_match)
			continue;
		/*
		 * Found a match. Since we walk known WLANs in
		 * priority order, it's guaranteed to be the
		 * most prioritized. It may not be the strongest though -
		 * we continue the walk and record the strength along
		 * with the ESSID and BSSID, so that if we encounter
		 * another AP with the same ESSID but a higher signal strength,
		 * we will choose it - but only if the currently-connected
		 * WLAN is at or below wireless_scan_level.
		 */
		(void) dladm_wlan_str2strength
		    (cur_wlan->nww_signal_strength, &curr_strength);

		if (curr_strength > max_strength) {
			(void) strlcpy(link->nwamd_link_wifi_essid,
			    cur_wlan->nww_essid,
			    sizeof (link->nwamd_link_wifi_essid));
			/*
			 * Set BSSID if wireless_strict_bssid is specified or
			 * if this is a hidden WLAN.  Store the BSSID here and
			 * then later determine the hidden WLAN's name in the
			 * connect thread.
			 */
			if (wireless_strict_bssid ||
			    cur_wlan->nww_essid[0] == '\0') {
				(void) strlcpy(link->nwamd_link_wifi_bssid,
				    cur_wlan->nww_bssid,
				    sizeof (link->nwamd_link_wifi_bssid));
			}
			(void) strlcpy(link->nwamd_link_wifi_signal_strength,
			    cur_wlan->nww_signal_strength,
			    sizeof (link->nwamd_link_wifi_signal_strength));
			link->nwamd_link_wifi_security_mode =
			    cur_wlan->nww_security_mode;
			found = B_TRUE;
		}
		(void) dladm_wlan_str2strength
		    (link->nwamd_link_wifi_signal_strength, &max_strength);
	}
	free(name);
	return (found ? 1 : 0);
}

static boolean_t
nwamd_find_known_wlan(nwamd_object_t ncu_obj)
{
	nwamd_ncu_t *ncu = ncu_obj->nwamd_object_data;
	int ret;

	/*
	 * Walk known WLANs, finding lowest priority (preferred) WLAN
	 * in our scan results.
	 */
	(void) nwam_walk_known_wlans(find_best_wlan_cb, ncu,
	    NWAM_FLAG_KNOWN_WLAN_WALK_PRIORITY_ORDER, &ret);

	return (ret == 1);
}

/*
 * WLAN scan code for WIFI link NCUs.
 */

/* Create periodic scan event for object.  Called with object lock held. */
void
nwamd_ncu_create_periodic_scan_event(nwamd_object_t ncu_obj)
{
	nwamd_event_t scan_event;

	if (wireless_scan_interval == 0) {
		nlog(LOG_DEBUG, "nwamd_ncu_create_periodic_scan_event: "
		    "wireless_scan_interval set to 0 so no periodic scanning");
		return;
	}
	scan_event = nwamd_event_init(NWAM_EVENT_TYPE_PERIODIC_SCAN,
	    NWAM_OBJECT_TYPE_NCU, 0, ncu_obj->nwamd_object_name);
	if (scan_event != NULL) {
		nwamd_event_enqueue_timed(scan_event,
		    wireless_scan_interval > WIRELESS_SCAN_INTERVAL_MIN ?
		    wireless_scan_interval : WIRELESS_SCAN_INTERVAL_MIN);
	}
}

/* Handle periodic scan event (which puts link into WIFI_INIT state */
void
nwamd_ncu_handle_periodic_scan_event(nwamd_event_t event)
{
	nwamd_object_t ncu_obj;
	nwamd_ncu_t *ncu;

	ncu_obj = nwamd_object_find(NWAM_OBJECT_TYPE_NCU,
	    event->event_object);
	if (ncu_obj == NULL) {
		nlog(LOG_ERR, "nwamd_ncu_handle_periodic_scan_event: "
		    "no object %s", event->event_object);
		return;
	}
	ncu = ncu_obj->nwamd_object_data;

	/* Only rescan if state is offline* or online */
	nlog(LOG_DEBUG, "nwamd_ncu_handle_periodic_scan_event: doing rescan..");

	if (ncu_obj->nwamd_object_state == NWAM_STATE_OFFLINE_TO_ONLINE ||
	    ncu_obj->nwamd_object_state == NWAM_STATE_ONLINE) {
		/* rescan, then create periodic scan event */
		(void) nwamd_wlan_scan(ncu->ncu_name);
		nwamd_ncu_create_periodic_scan_event(ncu_obj);
	}
	nwamd_object_release(ncu_obj);
}

static boolean_t
get_scan_results(void *arg, dladm_wlan_attr_t *attrp)
{
	nwamd_wifi_scan_t *s = arg;
	const char *linkname = s->nwamd_wifi_scan_link;
	char essid_name[DLADM_STRSIZE];
	char bssid_name[DLADM_STRSIZE];
	char strength[DLADM_STRSIZE];
	uint_t i, index = 0;
	boolean_t found = B_FALSE;

	(void) dladm_wlan_essid2str(&attrp->wa_essid, essid_name);
	(void) dladm_wlan_bssid2str(&attrp->wa_bssid, bssid_name);
	(void) dladm_wlan_strength2str(&attrp->wa_strength, strength);

	index = s->nwamd_wifi_scan_curr_num;
	if (index == NWAMD_MAX_NUM_WLANS) {
		nlog(LOG_ERR, "get_scan_results: truncating WLAN scan results "
		    "for link %s: ommiting (%s, %s)", linkname, essid_name,
		    bssid_name);
		return (B_TRUE);
	}

	(void) strlcpy(s->nwamd_wifi_scan_curr[index].nww_essid, essid_name,
	    sizeof (s->nwamd_wifi_scan_curr[index].nww_essid));
	(void) strlcpy(s->nwamd_wifi_scan_curr[index].nww_bssid, bssid_name,
	    sizeof (s->nwamd_wifi_scan_curr[index].nww_bssid));
	(void) strlcpy(s->nwamd_wifi_scan_curr[index].nww_signal_strength,
	    strength,
	    sizeof (s->nwamd_wifi_scan_curr[index].nww_signal_strength));
	s->nwamd_wifi_scan_curr[index].nww_security_mode = attrp->wa_secmode;
	s->nwamd_wifi_scan_curr[index].nww_speed = attrp->wa_speed;
	s->nwamd_wifi_scan_curr[index].nww_channel = attrp->wa_channel;
	s->nwamd_wifi_scan_curr[index].nww_bsstype = attrp->wa_bsstype;

	/*
	 * We fill in actual values for selected/connected/key later when we
	 * reacquire the object lock.
	 */
	s->nwamd_wifi_scan_curr[index].nww_selected = B_FALSE;
	s->nwamd_wifi_scan_curr[index].nww_connected = B_FALSE;
	s->nwamd_wifi_scan_curr[index].nww_have_key = B_FALSE;
	s->nwamd_wifi_scan_curr[index].nww_keyindex = 1;
	s->nwamd_wifi_scan_curr_num++;

	/* Check if this AP was in previous scan results */
	for (i = 0; i < s->nwamd_wifi_scan_last_num; i++) {
		found = (strcmp(s->nwamd_wifi_scan_last[i].nww_essid,
		    essid_name) == 0 &&
		    strcmp(s->nwamd_wifi_scan_last[i].nww_bssid,
		    bssid_name) == 0);
		if (found)
			break;
	}
	if (!found)
		s->nwamd_wifi_scan_changed = B_TRUE;

	nlog(LOG_DEBUG, "get_scan_results(%s, %d): ESSID %s, BSSID %s",
	    linkname, index, essid_name, bssid_name);

	return (B_TRUE);
}

/*
 * Check if we're connected to the expected WLAN, or in the case of autoconf
 * record the WLAN we're connected to.
 */
boolean_t
nwamd_wlan_connected(nwamd_object_t ncu_obj)
{
	nwamd_ncu_t *ncu = ncu_obj->nwamd_object_data;
	nwamd_link_t *link = &ncu->ncu_link;
	dladm_wlan_linkattr_t attr;
	char essid[DLADM_STRSIZE];
	char bssid[DLADM_STRSIZE];
	boolean_t connected = B_FALSE;
	int retries = 0;

	/*
	 * This is awful, but some wireless drivers
	 * (particularly 'ath') will erroneously report
	 * "disconnected" if queried right after a scan.  If we
	 * see 'down' reported here, we retry a few times to
	 * make sure it's really down.
	 */
	while (retries++ < 4) {
		if (dladm_wlan_get_linkattr(dld_handle, link->nwamd_link_id,
		    &attr) != DLADM_STATUS_OK) {
			attr.la_status = DLADM_WLAN_LINK_DISCONNECTED;
		} else if (attr.la_status == DLADM_WLAN_LINK_CONNECTED) {
			break;
		}
	}

	if (attr.la_status == DLADM_WLAN_LINK_CONNECTED) {
		(void) dladm_wlan_essid2str(&attr.la_wlan_attr.wa_essid, essid);
		(void) dladm_wlan_bssid2str(&attr.la_wlan_attr.wa_bssid, bssid);
		connected = B_TRUE;
		nlog(LOG_DEBUG, "nwamd_wlan_connected: %s connected to %s %s",
		    ncu->ncu_name, essid, bssid);
	} else {
		return (B_FALSE);
	}
	/*
	 * If we're using autoconf,  we have no control over what we connect to,
	 * so rather than verifying ESSSID, simply record ESSID/BSSID.
	 */
	if (link->nwamd_link_wifi_autoconf) {
		(void) strlcpy(link->nwamd_link_wifi_essid, essid,
		    sizeof (link->nwamd_link_wifi_essid));
		(void) strlcpy(link->nwamd_link_wifi_bssid, bssid,
		    sizeof (link->nwamd_link_wifi_bssid));
	}
	/*
	 * Are we connected to expected WLAN? Note:
	 * we'd like to verify BSSID, but we cannot due to CR 6772510.
	 */
	if (strcmp(essid, link->nwamd_link_wifi_essid) == 0) {
		/* Update connected signal strength */
		(void) dladm_wlan_strength2str(&attr.la_wlan_attr.wa_strength,
		    link->nwamd_link_wifi_signal_strength);

		/* Store current BSSID */
		(void) strlcpy(link->nwamd_link_wifi_bssid, bssid,
		    sizeof (link->nwamd_link_wifi_bssid));

		if (attr.la_wlan_attr.wa_strength < wireless_scan_level) {
			/*
			 * We're connected, but we've dropped below
			 * scan threshold.  Initiate a scan.
			 */
			nlog(LOG_DEBUG, "nwamd_wlan_connected: "
			    "connected but signal under threshold...");
			(void) nwamd_wlan_scan(ncu->ncu_name);
		}
		return (connected);
	} else if (strlen(essid) == 0) {
		/*
		 * For hidden WLANs, no ESSID is specified, so we cannot verify
		 * WLAN name.
		 */
		nlog(LOG_DEBUG,
		    "nwamd_wlan_connected: connected to hidden WLAN, cannot "
		    "verify connection details");
		return (connected);
	} else {
		(void) nlog(LOG_ERR,
		    "nwamd_wlan_connected: wrong AP on %s; expected %s %s",
		    ncu->ncu_name, link->nwamd_link_wifi_essid,
		    link->nwamd_link_wifi_bssid);
		(void) dladm_wlan_disconnect(dld_handle, link->nwamd_link_id);
		link->nwamd_link_wifi_connected = B_FALSE;
		return (B_FALSE);
	}
}

/*
 * WLAN scan thread. Called with the per-link WiFi mutex held.
 */
static void *
wlan_scan_thread(void *arg)
{
	char *linkname = arg;
	nwamd_object_t ncu_obj;
	nwamd_ncu_t *ncu;
	nwamd_link_t *link;
	dladm_status_t status;
	char essid[DLADM_STRSIZE];
	char bssid[DLADM_STRSIZE];
	uint32_t now, link_id;
	nwamd_wifi_scan_t s;
	int i;

	if ((ncu_obj = nwamd_ncu_object_find(NWAM_NCU_TYPE_LINK, linkname))
	    == NULL) {
		nlog(LOG_ERR, "wlan_scan_thread: could not find object  "
		    "for link %s", linkname);
		free(linkname);
		return (NULL);
	}

	ncu = ncu_obj->nwamd_object_data;
	link = &ncu->ncu_link;

	/*
	 * It is possible multiple scan threads have queued up waiting for the
	 * object lock.  We try to prevent excessive scanning by limiting the
	 * interval between scans to WIRELESS_SCAN_REQUESTED_INTERVAL_MIN sec.
	 */
	now = NSEC_TO_SEC(gethrtime());
	if ((now - link->nwamd_link_wifi_scan.nwamd_wifi_scan_last_time) <
	    WIRELESS_SCAN_REQUESTED_INTERVAL_MIN) {
		nlog(LOG_DEBUG, "wlan_scan_thread: last scan for %s "
		    "was < %d sec ago, ignoring scan request",
		    linkname, WIRELESS_SCAN_REQUESTED_INTERVAL_MIN);
		nwamd_object_release(ncu_obj);
		free(linkname);
		return (NULL);
	}

	/*
	 * Prepare scan data - copy link name and copy previous "current"
	 * scan results from the nwamd_link_t to the last scan results for
	 * the next scan so that we can compare results to find if things
	 * have changed since last time.
	 */
	(void) bzero(&s, sizeof (nwamd_wifi_scan_t));
	(void) strlcpy(s.nwamd_wifi_scan_link, ncu->ncu_name,
	    sizeof (s.nwamd_wifi_scan_link));
	s.nwamd_wifi_scan_last_num =
	    link->nwamd_link_wifi_scan.nwamd_wifi_scan_curr_num;
	if (s.nwamd_wifi_scan_last_num > 0) {
		(void) memcpy(s.nwamd_wifi_scan_last,
		    link->nwamd_link_wifi_scan.nwamd_wifi_scan_curr,
		    s.nwamd_wifi_scan_last_num * sizeof (nwam_wlan_t));
	}
	link_id = link->nwamd_link_id;
	nwamd_object_release(ncu_obj);

	nlog(LOG_DEBUG, "wlan_scan_thread: initiating scan on %s",
	    s.nwamd_wifi_scan_link);

	scanconnect_entry();
	status = dladm_wlan_scan(dld_handle, link_id, &s, get_scan_results);
	s.nwamd_wifi_scan_last_time = NSEC_TO_SEC(gethrtime());
	if (!s.nwamd_wifi_scan_changed) {
		/* Scan may have lost WLANs, if so this qualifies as change */
		s.nwamd_wifi_scan_changed = (s.nwamd_wifi_scan_curr_num !=
		    s.nwamd_wifi_scan_last_num);
	}
	scanconnect_exit();

	if (status != DLADM_STATUS_OK) {
		nlog(LOG_ERR, "wlan_scan_thread: cannot scan link %s",
		    s.nwamd_wifi_scan_link);
		free(linkname);
		return (NULL);
	}

	if ((ncu_obj = nwamd_ncu_object_find(NWAM_NCU_TYPE_LINK, linkname))
	    == NULL) {
		nlog(LOG_ERR, "wlan_scan_thread: could not find object  "
		    "for link %s after doing scan", linkname);
		free(linkname);
		return (NULL);
	}
	ncu = ncu_obj->nwamd_object_data;
	link = &ncu->ncu_link;

	/* For new scan data, add key info from known WLANs */
	for (i = 0; i < s.nwamd_wifi_scan_curr_num; i++) {
		if (NEED_ENC(s.nwamd_wifi_scan_curr[i].nww_security_mode)) {
			char keyname[NWAM_MAX_VALUE_LEN];
			dladm_wlan_key_t *key = NULL;

			/*
			 * If strict_bssid is true, we start checking for
			 * known wlans with the same BSSID.
			 * This would prevent the selection of secobjs
			 * that actually are referenced by different kwl
			 * with the same ESSID.
			 */
			if (wireless_strict_bssid) {
				int b_match = 0;
				(void) nwam_walk_known_wlans(bssid_match,
				    s.nwamd_wifi_scan_curr[i].nww_bssid, 0,
				    &b_match);
				if (b_match == 0)
					continue;
			}

			if (known_wlan_get_keyname
			    (s.nwamd_wifi_scan_curr[i].nww_essid, keyname)
			    == NWAM_SUCCESS &&
			    (key = nwamd_wlan_get_key_named(keyname,
			    s.nwamd_wifi_scan_curr[i].nww_security_mode))
			    != NULL) {
				s.nwamd_wifi_scan_curr[i].nww_have_key =
				    B_TRUE;
				s.nwamd_wifi_scan_curr[i].nww_keyindex =
				    s.nwamd_wifi_scan_curr[i].
				    nww_security_mode ==
				    DLADM_WLAN_SECMODE_WEP ?
				    key->wk_idx : 1;
				nlog(LOG_DEBUG, "found matching keyname for \
				    %s", s.nwamd_wifi_scan_curr[i].nww_bssid);
				free(key);
			}
		}
	}
	/* Copy scan data into nwamd_link_t */
	link->nwamd_link_wifi_scan = s;
	/* Set selected, connected and send scan event if we've got new data */
	nwamd_set_selected_connected(ncu,
	    link->nwamd_link_wifi_essid[0] != '\0',
	    link->nwamd_link_wifi_connected);

	/*
	 * If wireless selection is not possible because of the current
	 * state or priority-group, then this was just a scan request.
	 * Nothing else to do.
	 */
	if (!wireless_selection_possible(ncu_obj)) {
		nwamd_object_release(ncu_obj);
		free(linkname);
		return (NULL);
	}

	/*
	 * Check if WLAN is on our known WLAN list. If no
	 * previously-visited WLANs are found in scan data, set
	 * new state to NEED_SELECTION (provided we're not currently
	 * connected, as can be the case during a periodic scan or
	 * monitor-triggered scan where the signal strength recovers.
	 */
	if (!nwamd_find_known_wlan(ncu_obj)) {
		if (!nwamd_wlan_connected(ncu_obj)) {
			if (link->nwamd_link_wifi_connected) {
				nlog(LOG_DEBUG, "wlan_scan_thread: "
				    "unexpected disconnect after scan");
				nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
				    ncu_obj->nwamd_object_name,
				    NWAM_STATE_ONLINE_TO_OFFLINE,
				    NWAM_AUX_STATE_DOWN);
			} else {
				nlog(LOG_DEBUG, "wlan_scan_thread: "
				    "no known WLANs - ask user");
				nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
				    ncu_obj->nwamd_object_name,
				    NWAM_STATE_OFFLINE_TO_ONLINE,
				    NWAM_AUX_STATE_LINK_WIFI_NEED_SELECTION);
			}
		} else {
			/* still connected. if not online, change to online */
			nlog(LOG_DEBUG, "wlan_scan_thread: still connected to "
			    "%s %s", link->nwamd_link_wifi_essid,
			    link->nwamd_link_wifi_bssid);
			if (ncu_obj->nwamd_object_state != NWAM_STATE_ONLINE) {
				nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
				    ncu_obj->nwamd_object_name,
				    NWAM_STATE_OFFLINE_TO_ONLINE,
				    NWAM_AUX_STATE_UP);
			}
		}
		nwamd_object_release(ncu_obj);

	} else {
		nlog(LOG_DEBUG, "wlan_scan_thread: found known WLAN %s %s",
		    link->nwamd_link_wifi_essid, link->nwamd_link_wifi_bssid);

		if (!nwamd_wlan_connected(ncu_obj)) {
			/* Copy selected ESSID/BSSID, unlock, call select */
			(void) strlcpy(essid, link->nwamd_link_wifi_essid,
			    sizeof (essid));
			(void) strlcpy(bssid, link->nwamd_link_wifi_bssid,
			    sizeof (bssid));
			nwamd_object_release(ncu_obj);
			(void) nwamd_wlan_select(linkname, essid, bssid,
			    link->nwamd_link_wifi_security_mode, B_TRUE);
		} else {
			/* still connected.  if not online, change to online */
			nlog(LOG_DEBUG, "wlan_scan_thread: still connected to "
			    "known WLAN %s %s", link->nwamd_link_wifi_essid,
			    link->nwamd_link_wifi_bssid);
			if (ncu_obj->nwamd_object_state != NWAM_STATE_ONLINE) {
				nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
				    ncu_obj->nwamd_object_name,
				    NWAM_STATE_OFFLINE_TO_ONLINE,
				    NWAM_AUX_STATE_UP);
			}
			nwamd_object_release(ncu_obj);
		}
	}
	free(linkname);
	return (NULL);
}

nwam_error_t
nwamd_wlan_scan(const char *linkname)
{
	pthread_t wifi_thread;
	char *link = strdup(linkname);

	if (link == NULL) {
		nlog(LOG_ERR, "nwamd_wlan_scan: out of memory");
		return (NWAM_NO_MEMORY);
	}

	nlog(LOG_DEBUG, "nwamd_wlan_scan: WLAN scan for %s",
	    link);

	if (pthread_create(&wifi_thread, NULL, wlan_scan_thread,
	    link) != 0) {
		nlog(LOG_ERR, "nwamd_wlan_scan: could not start scan");
		free(link);
		return (NWAM_ERROR_INTERNAL);
	}
	/* detach thread so that it doesn't become a zombie */
	(void) pthread_detach(wifi_thread);
	return (NWAM_SUCCESS);
}

/*
 * WLAN connection code.
 */

static dladm_status_t
do_connect(uint32_t link_id, dladm_wlan_attr_t *attrp, dladm_wlan_key_t *key,
    uint_t keycount, uint_t flags)
{
	dladm_status_t status;
	char errmsg[DLADM_STRSIZE];

	scanconnect_entry();
	status = dladm_wlan_connect(dld_handle, link_id, attrp,
	    DLADM_WLAN_CONNECT_TIMEOUT_DEFAULT, key, keycount, flags);
	scanconnect_exit();

	nlog(LOG_DEBUG, "nwamd_do_connect: dladm_wlan_connect returned %s",
	    dladm_status2str(status, errmsg));

	return (status);
}

static void *
wlan_connect_thread(void *arg)
{
	char *linkname = arg;
	nwamd_object_t ncu_obj;
	nwamd_ncu_t *ncu;
	nwamd_link_t *link;
	nwam_error_t err;
	uint_t	keycount;
	uint32_t link_id;
	dladm_wlan_key_t *key = NULL;
	dladm_wlan_attr_t attr;
	dladm_status_t status;
	boolean_t autoconf = B_FALSE;

	if ((ncu_obj = nwamd_ncu_object_find(NWAM_NCU_TYPE_LINK, linkname))
	    == NULL) {
		nlog(LOG_ERR, "wlan_connect_thread: could not find object  "
		    "for link %s", linkname);
		free(linkname);
		return (NULL);
	}

	ncu = ncu_obj->nwamd_object_data;
	link = &ncu->ncu_link;

	if (!wireless_selection_possible(ncu_obj)) {
		nlog(LOG_DEBUG, "wlan_connect_thread: %s in invalid state or "
		    "has lower priority", ncu->ncu_name);
		goto done;
	}

	/* If it is already connected to the required AP, just return. */
	if (nwamd_wlan_connected(ncu_obj)) {
		nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
		    ncu_obj->nwamd_object_name,
		    ncu_obj->nwamd_object_state, NWAM_AUX_STATE_UP);
		goto done;
	}

	(void) memset(&attr, 0, sizeof (attr));
	if (dladm_wlan_str2essid(link->nwamd_link_wifi_essid, &attr.wa_essid)
	    != DLADM_STATUS_OK) {
		nlog(LOG_ERR, "wlan_connect_thread: invalid ESSID '%s' "
		    "for '%s'", link->nwamd_link_wifi_essid, ncu->ncu_name);
		goto done;
	}
	attr.wa_valid = DLADM_WLAN_ATTR_ESSID;

	/* note: bssid logic here is non-functional */
	if (link->nwamd_link_wifi_bssid[0] != '\0') {
		if (dladm_wlan_str2bssid(link->nwamd_link_wifi_bssid,
		    &attr.wa_bssid) != DLADM_STATUS_OK) {
			nlog(LOG_ERR, "wlan_connect_thread: invalid BSSID '%s'",
			    "for '%s'", link->nwamd_link_wifi_bssid,
			    ncu->ncu_name);
		} else {
			attr.wa_valid |= DLADM_WLAN_ATTR_BSSID;
		}
	}

	/* First check for the key */
	if (NEED_ENC(link->nwamd_link_wifi_security_mode)) {
		if (link->nwamd_link_wifi_key == NULL) {
			nlog(LOG_ERR, "wlan_connect_thread: could not find "
			    "key for WLAN '%s'", link->nwamd_link_wifi_essid);
			nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
			    ncu_obj->nwamd_object_name,
			    NWAM_STATE_OFFLINE_TO_ONLINE,
			    NWAM_AUX_STATE_LINK_WIFI_NEED_KEY);
			goto done;
		}
		/* Make a copy of the key as we need to unlock the object */
		if ((key = calloc(1, sizeof (dladm_wlan_key_t))) == NULL) {
			nlog(LOG_ERR, "wlan_connect_thread: out of memory");
			goto done;
		}
		(void) memcpy(key, link->nwamd_link_wifi_key,
		    sizeof (dladm_wlan_key_t));

		attr.wa_valid |= DLADM_WLAN_ATTR_SECMODE;
		attr.wa_secmode = link->nwamd_link_wifi_security_mode;
		keycount = 1;
		nlog(LOG_DEBUG, "wlan_connect_thread: retrieved key");
	} else {
		key = NULL;
		keycount = 0;
	}

	/*
	 * Connect; only scan if a bssid was not specified.  If it times out,
	 * try a second time using autoconf.  Drop the object lock during the
	 * connect attempt since connecting may take some time, and access to
	 * the link object during that period would be impossible if we held the
	 * lock.
	 */

	link->nwamd_link_wifi_autoconf = B_FALSE;
	link_id = link->nwamd_link_id;

	nwamd_object_release(ncu_obj);

	status = do_connect(link_id, &attr, key, keycount,
	    DLADM_WLAN_CONNECT_NOSCAN);
	if (status != DLADM_STATUS_OK) {
		/* Connect failed, try autoconf */
		if (!wireless_autoconf || (status = do_connect(link_id, &attr,
		    NULL, 0, 0)) != DLADM_STATUS_OK) {
			nlog(LOG_ERR, "wlan_connect_thread: connect failed for "
			    "%s", linkname);
			goto done_unlocked;
		}
		if (status == DLADM_STATUS_OK)
			autoconf = B_TRUE;
	}

	/* Connect succeeded, reacquire object */
	if ((ncu_obj = nwamd_ncu_object_find(NWAM_NCU_TYPE_LINK, linkname))
	    == NULL) {
		nlog(LOG_ERR, "wlan_connect_thread: could not find object  "
		    "for link %s", linkname);
		goto done_unlocked;
	}

	ncu = ncu_obj->nwamd_object_data;
	link = &ncu->ncu_link;

	if (autoconf)
		link->nwamd_link_wifi_autoconf = B_TRUE;

	/*
	 * If WLAN is WEP/WPA, we would like to test the connection as the key
	 * may be wrong.  It is difficult to find a reliable test that works
	 * across APs however.  Do nothing for now.
	 */
	link->nwamd_link_wifi_connected = nwamd_wlan_connected(ncu_obj);

	if (link->nwamd_link_wifi_connected) {
		if (link->nwamd_link_wifi_add_to_known_wlans) {
			/* add to known WLANs */
			nlog(LOG_DEBUG, "wlan_connect_thread: "
			    "add '%s' to known WLANs",
			    link->nwamd_link_wifi_essid);
			if ((err = nwam_known_wlan_add_to_known_wlans
			    (link->nwamd_link_wifi_essid,
			    link->nwamd_link_wifi_bssid[0] != '\0' ?
			    link->nwamd_link_wifi_bssid : NULL,
			    link->nwamd_link_wifi_security_mode,
			    link->nwamd_link_wifi_security_mode ==
			    DLADM_WLAN_SECMODE_WEP ?
			    (uint_t)link->nwamd_link_wifi_key->wk_idx : 1,
			    NEED_ENC(link->nwamd_link_wifi_security_mode) ?
			    link->nwamd_link_wifi_keyname : NULL))
			    != NWAM_SUCCESS) {
				nlog(LOG_ERR, "wlan_connect_thread: "
				    "could not add to known WLANs: %s",
				    nwam_strerror(err));
			}
		}
		nwamd_set_selected_connected(ncu, B_TRUE, B_TRUE);
		nlog(LOG_DEBUG, "wlan_connect_thread: connect "
		    "succeeded, setting state online");
		nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
		    ncu_obj->nwamd_object_name, NWAM_STATE_ONLINE,
		    NWAM_AUX_STATE_UP);
	}

done:
	nwamd_object_release(ncu_obj);
done_unlocked:
	free(linkname);
	free(key);

	return (NULL);
}

void
nwamd_wlan_connect(const char *linkname)
{
	pthread_t wifi_thread;
	char *link = strdup(linkname);

	if (link == NULL) {
		nlog(LOG_ERR, "nwamd_wlan_connect: out of memory");
		return;
	}

	nlog(LOG_DEBUG, "nwamd_wlan_connect: WLAN connect for %s",
	    link);

	if (pthread_create(&wifi_thread, NULL, wlan_connect_thread, link) != 0)
		nlog(LOG_ERR, "nwamd_wlan_connect: could not start connect");

	/* detach thread so that it doesn't become a zombie */
	(void) pthread_detach(wifi_thread);
}

/*
 * Launch signal strength-monitoring thread which periodically
 * checks connection and signal strength.  If we become disconnected
 * or signal drops below threshold specified by wireless_scan_level,
 * initiate a scan.  The scan initiation is taken care of by
 * the call to nwamd_wlan_connected().
 */
static void *
wlan_monitor_signal_thread(void *arg)
{
	char *linkname = arg;
	nwamd_object_t ncu_obj;
	nwamd_ncu_t *ncu;
	nwamd_link_t *link;
	boolean_t first_time = B_TRUE;

	for (;;) {
		if ((ncu_obj = nwamd_ncu_object_find(NWAM_NCU_TYPE_LINK,
		    linkname)) == NULL) {
			nlog(LOG_ERR, "wlan_monitor_signal_thread: could "
			    "not find object for link %s", linkname);
			break;
		}
		ncu = ncu_obj->nwamd_object_data;
		link = &ncu->ncu_link;

		/* If the NCU is DISABLED/OFFLINE, exit the monitoring thread */
		if (ncu_obj->nwamd_object_state == NWAM_STATE_OFFLINE ||
		    ncu_obj->nwamd_object_state == NWAM_STATE_DISABLED) {
			nlog(LOG_INFO, "wlan_monitor_signal_thread: "
			    "%s is %s, stopping thread", linkname,
			    nwam_state_to_string(ncu_obj->nwamd_object_state));
			link->nwamd_link_wifi_monitor_thread = 0;
			nwamd_object_release(ncu_obj);
			break;
		}

		/*
		 * First time thru loop, we check if there is another
		 * link monitoring thread in operation - if so exit this
		 * thread.
		 */
		if (first_time) {
			first_time = B_FALSE;

			if (link->nwamd_link_wifi_monitor_thread != 0) {
				/* Already have a monitor thread for link? */
				nwamd_object_release(ncu_obj);
				break;
			} else {
				link->nwamd_link_wifi_monitor_thread =
				    pthread_self();
			}
		}
		if (!nwamd_wlan_connected(ncu_obj)) {
			nlog(LOG_ERR, "wlan_monitor_signal_thread: "
			    "disconnect occured for WLAN on link %s", linkname);
			nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
			    ncu_obj->nwamd_object_name,
			    NWAM_STATE_ONLINE_TO_OFFLINE,
			    NWAM_AUX_STATE_DOWN);
			link->nwamd_link_wifi_monitor_thread = 0;
			nwamd_object_release(ncu_obj);
			break;
		}
		nwamd_object_release(ncu_obj);
		(void) sleep(WIRELESS_MONITOR_SIGNAL_INTERVAL);
	}
	free(linkname);

	return (NULL);
}

void
nwamd_wlan_monitor_signal(const char *linkname)
{
	pthread_t wifi_thread;
	char *link = strdup(linkname);

	if (link == NULL) {
		nlog(LOG_ERR, "nwamd_wlan_monitor_signal: out of memory");
		return;
	}

	nlog(LOG_DEBUG, "nwamd_wlan_monitor_signal: WLAN monitor for %s",
	    link);

	if (pthread_create(&wifi_thread, NULL, wlan_monitor_signal_thread,
	    link) != 0) {
		nlog(LOG_ERR, "nwamd_wlan_monitor_signal: could not monitor "
		    "link %s", link);
		free(link);
		return;
	}

	/* detach thread so that it doesn't become a zombie */
	(void) pthread_detach(wifi_thread);
}

void
nwamd_ncu_handle_link_state_event(nwamd_event_t event)
{
	nwam_event_t evm;
	nwamd_object_t ncu_obj;
	nwamd_ncu_t *ncu;
	nwamd_link_t *link;

	ncu_obj = nwamd_object_find(NWAM_OBJECT_TYPE_NCU, event->event_object);
	if (ncu_obj == NULL) {
		nlog(LOG_INFO, "nwamd_ncu_handle_link_state_event: no object "
		    "%s", event->event_object);
		nwamd_event_do_not_send(event);
		return;
	}
	ncu = ncu_obj->nwamd_object_data;
	link = &ncu->ncu_link;
	evm = event->event_msg;

	/*
	 * We ignore link state events for WiFi because it is very flaky.
	 * Instead we use the monitor thread and drive WiFi state changes from
	 * there.
	 */
	if (link->nwamd_link_media == DL_WIFI) {
		nwamd_object_release(ncu_obj);
		return;
	}

	/*
	 * If it's a link up event and we're not disabled, go online.
	 */
	if (evm->nwe_data.nwe_link_state.nwe_link_up &&
	    ncu_obj->nwamd_object_state != NWAM_STATE_DISABLED) {

		if (link->nwamd_link_activation_mode ==
		    NWAM_ACTIVATION_MODE_PRIORITIZED) {
			int64_t priority_group;

			(void) pthread_mutex_lock(&active_ncp_mutex);
			priority_group = current_ncu_priority_group;
			(void) pthread_mutex_unlock(&active_ncp_mutex);

			/* compare priority groups */
			if (link->nwamd_link_priority_group > priority_group) {
				nlog(LOG_DEBUG,
				    "nwamd_ncu_handle_link_state_event: "
				    "got LINK UP event for priority group "
				    "%lld, less preferred than current %lld, "
				    "ignoring",
				    link->nwamd_link_priority_group,
				    priority_group);

			} else if (link->nwamd_link_priority_group ==
			    priority_group) {
				nlog(LOG_DEBUG,
				    "nwamd_ncu_handle_link_state_event: "
				    "got LINK UP event for priority group "
				    "%lld, same as current %lld",
				    link->nwamd_link_priority_group,
				    priority_group);
				/*
				 * Change link state to UP.  It will be
				 * propagated to IP state machine.  Only do
				 * the NCU check if and when the interface
				 * NCU is online.
				 */
				nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
				    event->event_object,
				    NWAM_STATE_OFFLINE_TO_ONLINE,
				    NWAM_AUX_STATE_UP);
			} else {
				nlog(LOG_DEBUG,
				    "nwamd_ncu_handle_link_state_event: "
				    "got LINK UP event for priority group "
				    "%lld, more preferred than current %lld",
				    link->nwamd_link_priority_group,
				    priority_group);

				/*
				 * We need to mark the link as up so that when
				 * it is activated we will bring the interface
				 * up.
				 */
				nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
				    event->event_object,
				    NWAM_STATE_OFFLINE_TO_ONLINE,
				    NWAM_AUX_STATE_UP);
				nwamd_object_release(ncu_obj);
				nwamd_ncp_deactivate_priority_group
				    (priority_group);
				nwamd_ncp_activate_priority_group
				    (link->nwamd_link_priority_group);
				return;
			}

		} else if (link->nwamd_link_activation_mode ==
		    NWAM_ACTIVATION_MODE_MANUAL) {
			nlog(LOG_DEBUG, "nwamd_ncu_handle_link_state_event: "
			    "got LINK UP event for manual NCU %s",
			    ncu_obj->nwamd_object_name);

			nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
			    event->event_object, NWAM_STATE_OFFLINE_TO_ONLINE,
			    NWAM_AUX_STATE_UP);
		}
	}

	/*
	 * If the link is down then start or continue transition down.
	 */
	if (!evm->nwe_data.nwe_link_state.nwe_link_up &&
	    (ncu_obj->nwamd_object_state == NWAM_STATE_ONLINE ||
	    ncu_obj->nwamd_object_state == NWAM_STATE_OFFLINE_TO_ONLINE)) {

		if (link->nwamd_link_activation_mode ==
		    NWAM_ACTIVATION_MODE_PRIORITIZED) {
			nlog(LOG_DEBUG,
			    "nwamd_ncu_handle_link_state_event: "
			    "got LINK DOWN for priority group %lld",
			    link->nwamd_link_priority_group);
			/* Moving to offline checks priority group */
		} else {
			nlog(LOG_DEBUG, "nwamd_ncu_handle_link_state_event: "
			    "got LINK DOWN event for manual NCU %s",
			    ncu_obj->nwamd_object_name);
		}
		nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
		    event->event_object, NWAM_STATE_ONLINE_TO_OFFLINE,
		    NWAM_AUX_STATE_DOWN);
	}

	nwamd_object_release(ncu_obj);
}
