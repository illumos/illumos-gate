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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file containes all the routines to handle wireless (more
 * accurately, 802.11 "WiFi" family only at this moment) operations.
 * This is only phase 0 work so the handling is pretty simple.
 *
 * When the daemon starts up, for each WiFi interface detected, it'll
 * spawn a thread doing an access point (AP) scanning.  After the scans
 * finish and if one of the WiFi interfaces is chosen to be active, the
 * code will pop up a window showing the scan results and wait for the
 * user's input on which AP to connect to and then complete the AP
 * connection and IP interface set up.  WEP is supported to connect to
 * those APs which require it.  The code also maintains a list of known
 * WiFi APs in the file KNOWN_WIFI_NETS.  Whenever the code successfully
 * connects to an AP, the AP's ESSID/BSSID will be added to that file.
 * This file is used in the following way.
 *
 * If the AP scan results contain one known AP, the code will automatically
 * connect to that AP without asking the user.  But if the detected signal
 * strength of that AP is weaker than some other AP's, the code will still
 * pop up a window asking for user input.
 *
 * If the AP scan results contain more than one known APs, the code will
 * pop up a window listing those known APs only.  If the user does not
 * make a choice, the full list of available APs will be shown.
 *
 * If the AP scan results contain no known AP, the full list of available
 * APs is shown and the user is asked which AP to connect to.
 *
 * Note that not all APs broadcast the Beacon.  And some events may
 * happen during the AP scan such that not all available APs are found.
 * So the code also allows a user to manually input an AP's data in the
 * pop up window.  This allows a user to connect to the aforementioned
 * "hidden" APs.
 *
 * The code also periodically (specified by wlan_scan_interval) checks
 * for the health of the AP connection.  If the signal strength of the
 * connected AP drops below a threshold (specified by wireless_scan_level),
 * the code will try to do another scan to find out other APs available.
 * If there is currently no connected AP, a scan will also be done
 * periodically to look for available APs.  In both cases, if there are
 * new APs, the above AP connection procedure will be performed.
 *
 * One limitation of the current code is that a user cannot initiate a
 * WiFi APs scan manually.  A manual scan can only be done when the code
 * shows a pop up window asking for user input.  Suppose there is no
 * connected AP and periodic scan is going on.  If a user wants to
 * connect to a hidden AP, this is only possible if there is another
 * non-hidden AP available such that after a periodic scan, the pop up
 * window is shown.  This will be fixed in a later phase.
 */

#include <unistd.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <syslog.h>
#include <assert.h>
#include <limits.h>
#include <errno.h>
#include <sys/stat.h>
#include <syslog.h>
#include <pthread.h>
#include <sys/wait.h>
#include <stropts.h>
#include <sys/types.h>
#include <fcntl.h>
#include <locale.h>
#include <libintl.h>
#include <libdladm.h>
#include <libdllink.h>
#include <libinetutil.h>

#include "defines.h"
#include "structures.h"
#include "functions.h"
#include "variables.h"

static pthread_mutex_t wifi_mutex;
static pthread_mutexattr_t wifi_mutex_attr;
static pthread_mutex_t wifi_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t wifi_init_cond = PTHREAD_COND_INITIALIZER;

typedef enum {
	SUCCESS = 0,
	FAILURE,
	TRY_AGAIN
} return_vals_t;

/*
 * Is a wireless interface doing a scan currently?  We only allow one
 * wireless interface to do a scan at any one time.  This is to
 * avoid unnecessary interference.  The following variable is used
 * to store the interface doing the scan.  It is protected by
 * wifi_init_mutex.
 */
static struct interface *wifi_scan_intf = NULL;

/* used entries have non NULL memebers */
static struct wireless_lan *wlans = NULL;
static uint_t wireless_lan_count = 0; /* allocated */
static uint_t wireless_lan_used = 0; /* used entries */

static int wepkey_string_to_secobj_value(char *, uint8_t *, uint_t *);
static int store_wepkey(char *, char *, char *);
static dladm_wlan_wepkey_t *retrieve_wepkey(const char *, const char *);

static boolean_t add_wlan_entry(struct interface *, char *, char *, char *,
    boolean_t);
static boolean_t already_in_visited_wlan_list(const struct wireless_lan *);
static boolean_t check_wlan(const char *, const char *);
static boolean_t connect_or_autoconf(struct wireless_lan *, const char *);
static return_vals_t connect_to_new_wlan(const struct wireless_lan *, int,
    const char *);
static boolean_t find_wlan_entry(struct interface *, char *, char *);
static void free_wireless_lan(struct wireless_lan *);
static struct wireless_lan *get_specific_lan(void);
static void get_user_wepkey(struct wireless_lan *);
static char *get_zenity_response(const char *);
static boolean_t wlan_autoconf(const char *ifname);
static int zenity_height(int);
static boolean_t get_scan_results(void *, dladm_wlan_attr_t *);

#define	WIRELESS_LAN_INIT_COUNT	8

struct visited_wlans_list *visited_wlan_list = NULL;

/*
 * The variable wlan_scan_interval controls the interval in seconds
 * between periodic scans.
 */
uint_t wlan_scan_interval = 120;

/*
 * The variable wireless_scan_level specifies the lowest signal level
 * when a periodic wireless scan needs to be done.
 */
dladm_wlan_strength_t wireless_scan_level = DLADM_WLAN_STRENGTH_VERY_WEAK;

void
init_mutexes(void)
{
	(void) pthread_mutexattr_init(&wifi_mutex_attr);
	(void) pthread_mutexattr_settype(&wifi_mutex_attr,
	    PTHREAD_MUTEX_RECURSIVE);
	(void) pthread_mutex_init(&wifi_mutex, &wifi_mutex_attr);
}

/*
 * wlan is expected to be non-NULL.
 */
static void
get_user_wepkey(struct wireless_lan *wlan)
{
	char zenity_cmd[1024];
	char buf[1024];
	FILE *zcptr;

	/*
	 * First, test if we have wepkey stored as secobj. If so,
	 * no need to prompt for it.
	 */
	wlan->cooked_wepkey = retrieve_wepkey(wlan->essid, wlan->bssid);
	if (wlan->cooked_wepkey != NULL) {
		dprintf("get_user_wepkey: retrieve_wepkey() returns non NULL");
		return;
	}

	(void) snprintf(zenity_cmd, sizeof (zenity_cmd),
	    "%s --entry --text=\"%s %s\""
	    " --title=\"%s\" --hide-text", ZENITY,
	    gettext("Enter WEP key for WiFi network"), wlan->essid,
	    gettext("Enter WEP key"));

	if (!valid_graphical_user(B_TRUE))
		return;

	zcptr = popen(zenity_cmd, "r");
	if (zcptr != NULL) {
		if (fgets(buf, sizeof (buf), zcptr) != NULL) {
			wlan->raw_wepkey = strdup(buf);
			if (wlan->raw_wepkey != NULL) {
				/* Store WEP key persistently */
				if (store_wepkey(wlan->essid, wlan->bssid,
				    wlan->raw_wepkey) != 0) {
					syslog(LOG_ERR,
					    "get_user_wepkey: failed to store"
					    " user specified WEP key");
				}
			} else {
				syslog(LOG_ERR,
				    "get_user_wepkey: strdup failed");
			}
		}
		(void) pclose(zcptr);
	} else {
		syslog(LOG_ERR, "Could not run %s: %m", ZENITY);
	}
}

static boolean_t
find_wlan_entry(struct interface *intf, char *essid, char *bssid)
{
	int i;

	(void) pthread_mutex_lock(&wifi_mutex);
	/* Check if the new entry is already there. */
	for (i = 0; i < wireless_lan_used; i++) {
		/*
		 * Assume that essid and bssid are already NULL terminated.
		 * Note that we also check for the interface name here.
		 * If there is only one wireless interface, it should not
		 * matter.  But if there are more than 1, then it is safer
		 * to use the interface which finds the AP to connect to
		 * it.
		 */
		if (strcmp(wlans[i].essid, essid) == 0 &&
		    strcmp(wlans[i].bssid, bssid) == 0 &&
		    strcmp(wlans[i].wl_if_name, intf->if_name) == 0) {
			(void) pthread_mutex_unlock(&wifi_mutex);
			return (B_TRUE);
		}
	}
	(void) pthread_mutex_unlock(&wifi_mutex);
	return (B_FALSE);
}

static void
free_wireless_lan(struct wireless_lan *wlp)
{
	free(wlp->essid);
	wlp->essid = NULL;
	free(wlp->bssid);
	wlp->bssid = NULL;
	free(wlp->signal_strength);
	wlp->signal_strength = NULL;
	free(wlp->raw_wepkey);
	wlp->raw_wepkey = NULL;
	free(wlp->cooked_wepkey);
	wlp->cooked_wepkey = NULL;
	free(wlp->wl_if_name);
	wlp->wl_if_name = NULL;
}

static boolean_t
add_wlan_entry(struct interface *intf, char *essid, char *bssid,
    char *signal_strength, boolean_t wep)
{
	int n;

	(void) pthread_mutex_lock(&wifi_mutex);

	if (wireless_lan_used == wireless_lan_count) {
		int newcnt;
		struct wireless_lan *r;

		newcnt = (wireless_lan_count == 0) ?
		    WIRELESS_LAN_INIT_COUNT : wireless_lan_count * 2;
		r = realloc(wlans, newcnt * sizeof (*wlans));
		if (r == NULL) {
			syslog(LOG_ERR, "add_wlan_entry: realloc failed");
			(void) pthread_mutex_unlock(&wifi_mutex);
			return (B_FALSE);
		}
		(void) memset((void *)(r + wireless_lan_count), 0,
		    (newcnt - wireless_lan_count) * sizeof (*r));
		wireless_lan_count = newcnt;
		wlans = r;
	}

	n = wireless_lan_used;
	wlans[n].essid = strdup(essid);
	wlans[n].bssid = strdup(bssid);
	wlans[n].signal_strength = strdup(signal_strength);
	wlans[n].wl_if_name = strdup(intf->if_name);
	wlans[n].need_wepkey = wep;
	wlans[n].raw_wepkey = NULL;
	wlans[n].cooked_wepkey = NULL;
	if (wlans[n].essid == NULL || wlans[n].bssid == NULL ||
	    wlans[n].signal_strength == NULL || wlans[n].wl_if_name == NULL) {
		syslog(LOG_ERR, "add_wlan_entry: strdup failed");
		free_wireless_lan(&(wlans[n]));
		(void) pthread_mutex_unlock(&wifi_mutex);
		return (B_FALSE);
	}
	wireless_lan_used++;
	(void) pthread_mutex_unlock(&wifi_mutex);
	return (B_TRUE);
}

static void
clear_lan_entries(void)
{
	int i;

	(void) pthread_mutex_lock(&wifi_mutex);
	for (i = 0; i < wireless_lan_used; i++)
		free_wireless_lan(&(wlans[i]));
	wireless_lan_used = 0;
	(void) pthread_mutex_unlock(&wifi_mutex);
}

/*
 * Verify if a WiFi NIC is associated with the given ESSID.  If the given
 * ESSID is NULL, and if the NIC is already connected,  return true.
 * Otherwise,
 *
 * 1. If the NIC is associated with the given ESSID, return true.
 * 2. If the NIC is not associated with any AP, return false.
 * 3. If the NIC is associated with a different AP, tell the driver
 *    to disassociate with it and then return false.
 */
static boolean_t
check_wlan(const char *intf, const char *exp_essid)
{
	dladm_wlan_linkattr_t attr;
	dladm_status_t status;
	char cur_essid[DLADM_STRSIZE];
	char errmsg[DLADM_STRSIZE];

	status = dladm_wlan_get_linkattr(intf, &attr);
	if (status != DLADM_STATUS_OK) {
		dprintf("check_wlan: dladm_wlan_get_linkattr() failed: %s",
		    dladm_status2str(status, errmsg));
		return (B_FALSE);
	}
	if (attr.la_status == DLADM_WLAN_LINKSTATUS_DISCONNECTED)
		return (B_FALSE);
	if (exp_essid == NULL)
		return (B_TRUE);
	(void) dladm_wlan_essid2str(&attr.la_wlan_attr.wa_essid, cur_essid);

	/* Is the NIC associated with the expected one? */
	if (strcmp(cur_essid, exp_essid) == 0)
		return (B_TRUE);

	/* Tell the driver to disassociate with the current AP. */
	if (dladm_wlan_disconnect(intf) != DLADM_STATUS_OK)
		dprintf("check_wlan: dladm_wlan_disconnect() fails");
	return (B_FALSE);
}

/*
 * Given a wireless interface, use it to scan for available networks.
 */
boolean_t
scan_wireless_nets(struct interface *intf)
{
	boolean_t	new_ap = B_FALSE;
	dladm_status_t	status;
	int		num_ap;

	assert(intf->if_type == IF_WIRELESS);
	/*
	 * If there is already a scan in progress, wait until the
	 * scan is done to avoid interference.  But if the interface
	 * doing the scan is the same as the one requesting the new
	 * scan, just return.
	 *
	 * Whenever a wireless scan is in progress, all the other
	 * threads checking the wireless AP list should wait.
	 */
	(void) pthread_mutex_lock(&wifi_init_mutex);
	while (wifi_scan_intf != NULL) {
		dprintf("scan_wireless_nets in progress: old %s new %s",
		    wifi_scan_intf->if_name, intf->if_name);
		if (strcmp(wifi_scan_intf->if_name, intf->if_name) == 0) {
			(void) pthread_mutex_unlock(&wifi_init_mutex);
			return (B_FALSE);
		}
		(void) pthread_cond_wait(&wifi_init_cond, &wifi_init_mutex);
	}
	wifi_scan_intf = intf;
	(void) pthread_mutex_unlock(&wifi_init_mutex);

	/*
	 * Since only one scan is allowed at any one time, no need to grab
	 * a lock in checking wireless_lan_used.
	 */
	num_ap = wireless_lan_used;
	status = dladm_wlan_scan(intf->if_name, intf, get_scan_results);
	if (status != DLADM_STATUS_OK)
		syslog(LOG_NOTICE, "cannot scan link '%s'", intf->if_name);
	else
		new_ap = (wireless_lan_used > num_ap);

	(void) pthread_mutex_lock(&wifi_init_mutex);
	wifi_scan_intf = NULL;
	(void) pthread_cond_signal(&wifi_init_cond);
	(void) pthread_mutex_unlock(&wifi_init_mutex);

	return (new_ap);
}

/* ARGSUSED */
static void
wireless_scan(struct interface *ifp, void *arg)
{
	if (ifp->if_type == IF_WIRELESS) {
		dprintf("periodic_wireless_scan: %s", ifp->if_name);
		if (scan_wireless_nets(ifp)) {
			dprintf("new AP added: %s", ifp->if_name);
			gen_newif_event(ifp);
		}
	}
}

static boolean_t
get_scan_results(void *arg, dladm_wlan_attr_t *attrp)
{

	boolean_t 	wep;
	char		essid_name[DLADM_STRSIZE];
	char		bssid_name[DLADM_STRSIZE];
	char		strength[DLADM_STRSIZE];

	(void) dladm_wlan_essid2str(&attrp->wa_essid, essid_name);
	(void) dladm_wlan_bssid2str(&attrp->wa_bssid, bssid_name);
	(void) dladm_wlan_strength2str(&attrp->wa_strength, strength);

	wep = (attrp->wa_secmode == DLADM_WLAN_SECMODE_WEP);

	if (!find_wlan_entry(arg, essid_name, bssid_name) &&
	    add_wlan_entry(arg, essid_name, bssid_name, strength, wep)) {
		return (B_TRUE);
	}
	return (B_FALSE);
}

/* ARGSUSED */
void *
periodic_wireless_scan(void *arg)
{
	/*
	 * No periodic scan if the "-i" option is used to change the
	 * interval to 0.
	 */
	if (wlan_scan_interval == 0)
		return (NULL);

	for (;;) {
		int ret;
		dladm_wlan_linkattr_t attr;
		llp_t *cur_llp;
		struct interface *ifp;

		ret = poll(NULL, 0, wlan_scan_interval * MILLISEC);

		/*
		 * We assume that once an llp is created, it will never be
		 * deleted in the lifetime of the process.  So it is OK
		 * to do this assignment without a lock.
		 */
		cur_llp = link_layer_profile;

		/*
		 * We do a scan if
		 *
		 * 1. There is no active profile.  Or
		 * 2. We are now disconnected from the AP.  Or
		 * 3. The signal strength falls below a certain specified level.
		 */
		if (ret == 0) {
			if (cur_llp != NULL) {
				if (cur_llp->llp_type != IF_WIRELESS ||
				    dladm_wlan_get_linkattr(cur_llp->llp_lname,
				    &attr) != DLADM_STATUS_OK) {
					continue;
				}
				if (attr.la_status ==
				    DLADM_WLAN_LINKSTATUS_CONNECTED &&
				    attr.la_wlan_attr.wa_strength >
				    wireless_scan_level) {
					continue;
				}
				/*
				 * Clear the IF_DHCPFAILED and IF_DHCPSTARTED
				 * flags on this interface; this is a "fresh
				 * start" for the interface, so we should
				 * retry dhcp.
				 */
				ifp = get_interface(cur_llp->llp_lname);
				if (ifp != NULL) {
					ifp->if_lflags &= ~IF_DHCPFAILED;
					ifp->if_lflags &= ~IF_DHCPSTARTED;
				}
				/*
				 * Deactivate the original llp.
				 * If we reached this point, we either were
				 * not connected, or were connected with
				 * "very weak" signal strength; so we're
				 * assuming that having this llp active was
				 * not very useful.  So we deactivate.
				 */
				llp_deactivate();
			}
			/* We should start from fresh. */
			clear_lan_entries();
			walk_interface(wireless_scan, NULL);
		} else if (ret == -1) {
			if (errno == EINTR)
				continue;
			syslog(LOG_INFO, "periodic_wireless_scan: poll failed");
			return (NULL);
		}
	}
	/* NOTREACHED */
	return (NULL);
}

/*
 * Below are functions used to handle storage/retrieval of WEP keys
 * for a given WLAN. The keys are stored/retrieved using dladm_set_secobj()
 * and dladm_get_secobj().
 */

/*
 * Convert wepkey hexascii string to raw secobj value. This
 * code is very similar to convert_secobj() in dladm.c, it would
 * be good to have a libdladm function to convert values.
 */
static int
wepkey_string_to_secobj_value(char *buf, uint8_t *obj_val, uint_t *obj_lenp)
{
	size_t buf_len = strlen(buf);

	dprintf("before: wepkey_string_to_secobj_value: buf_len = %d", buf_len);
	if (buf_len == 0) {
		syslog(LOG_ERR,
		    "wepkey_string_to_secobj_value: empty WEP key");
		return (-1);
	}

	if (buf[buf_len - 1] == '\n')
		buf[--buf_len] = '\0';

	dprintf("after: wepkey_string_to_secobj_value: buf_len = %d", buf_len);
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
			syslog(LOG_ERR,
			    "wepkey_string_to_secobj_value: invalid WEP key");
			return (-1);
		}
		break;
	case 12:
	case 28:	/* Hex key sizes, preceded by 0x */
		if (strncmp(buf, "0x", 2) != 0 ||
		    hexascii_to_octet(buf + 2, (uint_t)buf_len - 2, obj_val,
		    obj_lenp) != 0) {
			syslog(LOG_ERR,
			    "wepkey_string_to_secobj_value: invalid WEP key");
			return (-1);
		}
		break;
	default:
		syslog(LOG_ERR,
		    "wepkey_string_to_secobj_value: invalid WEP key length");
		return (-1);
	}
	return (0);
}

/*
 * Print the key format into the appropriate field, then convert any ":"
 * characters to ".", as ":[1-4]" is the slot indicator, which otherwise
 * would trip us up.  The third parameter is expected to be of size
 * DLADM_SECOBJ_NAME_MAX.
 */
static void
set_key_name(const char *essid, const char *bssid, char *name, size_t nsz)
{
	int i;

	if (bssid == NULL)
		(void) snprintf(name, nsz, "nwam-%s", essid);
	else
		(void) snprintf(name, nsz, "nwam-%s-%s", essid, bssid);
	for (i = 0; i < strlen(name); i++)
		if (name[i] == ':')
			name[i] = '.';
}

static int
store_wepkey(char *essid, char *bssid, char *raw_wepkey)
{
	uint8_t obj_val[DLADM_SECOBJ_VAL_MAX];
	uint_t obj_len;
	char obj_name[DLADM_SECOBJ_NAME_MAX];
	dladm_status_t status;
	char errmsg[DLADM_STRSIZE];

	/*
	 * Name wepkey object for this WLAN so it can be later retrieved
	 * (name is unique for each ESSID/BSSID combination).
	 */
	set_key_name(essid, bssid, obj_name, sizeof (obj_name));
	dprintf("store_wepkey: obj_name is %s", obj_name);

	if (wepkey_string_to_secobj_value(raw_wepkey, obj_val, &obj_len) != 0) {
		/* above function logs internally on failure */
		return (-1);
	}

	status = dladm_set_secobj(obj_name, DLADM_SECOBJ_CLASS_WEP,
	    obj_val, obj_len,
	    DLADM_OPT_CREATE | DLADM_OPT_PERSIST | DLADM_OPT_TEMP);
	if (status != DLADM_STATUS_OK) {
		syslog(LOG_ERR, "store_wepkey: could not create secure object "
		    "'%s' for wepkey: %s", obj_name,
		    dladm_status2str(status, errmsg));
		return (-1);
	}
	return (0);
}

/*
 * retrieve_wepkey returns NULL if no wepkey was recovered from dladm
 */
static dladm_wlan_wepkey_t *
retrieve_wepkey(const char *essid, const char *bssid)
{
	dladm_status_t status;
	char errmsg[DLADM_STRSIZE];
	dladm_wlan_wepkey_t *cooked_wepkey;
	dladm_secobj_class_t class;

	/*
	 * Newly-allocated wepkey must be freed by caller, or by
	 * subsequent call to retrieve_wepkey().
	 */
	if ((cooked_wepkey = malloc(sizeof (dladm_wlan_wepkey_t))) == NULL) {
		syslog(LOG_ERR, "retrieve_wepkey: malloc failed");
		return (NULL);
	}

	/* Set name appropriately to retrieve wepkey for this WLAN */
	set_key_name(essid, bssid, cooked_wepkey->wk_name,
	    DLADM_SECOBJ_NAME_MAX);
	dprintf("retrieve_wepkey: len = %d, object = %s\n",
	    strlen(cooked_wepkey->wk_name), cooked_wepkey->wk_name);
	cooked_wepkey->wk_len = DLADM_SECOBJ_NAME_MAX;
	cooked_wepkey->wk_idx = 1;

	/* Try the kernel first, then fall back to persistent storage. */
	status = dladm_get_secobj(cooked_wepkey->wk_name, &class,
	    cooked_wepkey->wk_val, &cooked_wepkey->wk_len,
	    DLADM_OPT_TEMP);
	if (status != DLADM_STATUS_OK) {
		dprintf("retrieve_wepkey: dladm_get_secobj(TEMP) failed: %s",
		    dladm_status2str(status, errmsg));
		status = dladm_get_secobj(cooked_wepkey->wk_name, &class,
		    cooked_wepkey->wk_val, &cooked_wepkey->wk_len,
		    DLADM_OPT_PERSIST);
	}

	switch (status) {
	case DLADM_STATUS_OK:
		dprintf("retrieve_wepkey: dladm_get_secobj succeeded: len %d",
		    cooked_wepkey->wk_len);
		break;
	case DLADM_STATUS_NOTFOUND:
		/*
		 * We do not want an error in the case that the secobj
		 * is not found, since we then prompt for it.
		 */
		free(cooked_wepkey);
		return (NULL);
	default:
		syslog(LOG_ERR, "retrieve_wepkey: could not get wepkey "
		    "from secure object '%s': %s", cooked_wepkey->wk_name,
		    dladm_status2str(status, errmsg));
		free(cooked_wepkey);
		return (NULL);
	}

	return (cooked_wepkey);
}

/* Create the KNOWN_WIFI_NETS using info from the interface list.  */
void
create_known_wifi_nets_file(void)
{
	FILE *fp;
	int dirmode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;

	/* Create the NWAM directory in case it does not exist. */
	if (mkdir(LLPDIR, dirmode) != 0) {
		if (errno != EEXIST) {
			syslog(LOG_ERR, "could not create %s: %m", LLPDIR);
			return;
		}
	}
	if ((fp = fopen(KNOWN_WIFI_NETS, "a+")) == NULL) {
		syslog(LOG_ERR, "could not open %s: %m", KNOWN_WIFI_NETS);
		return;
	}
	dprintf("Creating %s", KNOWN_WIFI_NETS);
	(void) fclose(fp);
}

/*
 * Add an entry to known_wifi_nets file given the parameters.
 */
void
update_known_wifi_nets_file(const char *essid, const char *bssid)
{
	FILE *fp;

	dprintf("update_known_wifi_nets_file(%s, %s)", essid, STRING(bssid));
	fp = fopen(KNOWN_WIFI_NETS, "a+");
	if (fp == NULL) {
		if (errno != ENOENT) {
			syslog(LOG_ERR, "fopen(%s) failed: %m",
			    KNOWN_WIFI_NETS);
			return;
		}

		/*
		 * If there is none, we should create one instead.
		 * For now, we will use the order of seeing each new net
		 * for the priority.  We should have a priority field
		 * in the known_wifi_nets file eventually...
		 */
		create_known_wifi_nets_file();
		fp = fopen(KNOWN_WIFI_NETS, "a");
		if (fp == NULL) {
			syslog(LOG_ERR, "second fopen(%s) failed: %m",
			    KNOWN_WIFI_NETS);
			return;
		}
	}
	/* now see if this info is already in the file */
	if (known_wifi_nets_lookup(essid, bssid) == B_FALSE) {
		/* now add this to the file */
		(void) fprintf(fp, "%s\t%s\n", essid,
		    bssid == NULL ? "" : bssid);
	}
	(void) fclose(fp);
}

/*
 * Check if the given AP (ESSID, BSSID pair) is on the known AP list.
 */
boolean_t
known_wifi_nets_lookup(const char *new_essid, const char *new_bssid)
{
	FILE *fp;
	char line[LINE_MAX];
	char *cp, *lasts, *essid, *bssid;
	int line_num;
	boolean_t found = B_FALSE;

	/*
	 * For now the file format is:
	 * essid\tbssid
	 * (essid followed by tab followed by bssid)
	 */
	fp = fopen(KNOWN_WIFI_NETS, "r+");
	if (fp == NULL) {
		if (errno != ENOENT) {
			syslog(LOG_ERR, "fopen(%s) failed: %m",
			    KNOWN_WIFI_NETS);
			return (B_FALSE);
		}
		create_known_wifi_nets_file();
		return (B_FALSE);
	}
	for (line_num = 1; fgets(line, sizeof (line), fp) != NULL; line_num++) {
		if (line[strlen(line) - 1] == '\n')
			line[strlen(line) - 1] = '\0';

		cp = line;
		while (isspace(*cp))
			cp++;

		if (*cp == '#' || *cp == '\0')
			continue;

		if ((essid = strtok_r(cp, "\t", &lasts)) == NULL) {
			syslog(LOG_ERR, "%s:%d: not enough tokens; "
			    "ignoring entry", KNOWN_WIFI_NETS, line_num);
			continue;
		}
		bssid = strtok_r(NULL, "\t", &lasts);
		if (strcmp(essid, new_essid) != 0)
			continue;
		if (new_bssid == NULL) {
			/*
			 * no BSSID specified => ESSID match
			 * is good enough.
			 */
			found = B_TRUE;
		} else if (bssid != NULL && strcmp(bssid, new_bssid) == 0) {
			/* Match on both is always good. */
			found = B_TRUE;
		}
		if (found)
			break;
	}
	(void) fclose(fp);
	return (found);
}

/*
 * reqlan->essid is required (i.e., cannot be NULL)
 * reqlan->bssid is optional (i.e., may be NULL)
 */
boolean_t
connect_chosen_lan(struct wireless_lan *reqlan, const char *ifname)
{
	uint_t	keycount;
	dladm_wlan_wepkey_t *key;
	dladm_wlan_attr_t attr;
	dladm_status_t status;
	uint_t flags = DLADM_WLAN_CONNECT_NOSCAN;
	int timeout = DLADM_WLAN_CONNECT_TIMEOUT_DEFAULT;
	char errmsg[DLADM_STRSIZE];

	(void) memset(&attr, 0, sizeof (attr));
	/* try to apply essid selected by the user */
	if (reqlan->essid == NULL)
		return (B_FALSE);
	dprintf("connect_chosen_lan(%s, %s, %s)", reqlan->essid,
	    STRING(reqlan->bssid), ifname);

	/* If it is already connected to the required AP, just return. */
	if (check_wlan(ifname, reqlan->essid))
		return (B_TRUE);

	if (dladm_wlan_str2essid(reqlan->essid, &attr.wa_essid) !=
	    DLADM_STATUS_OK) {
		syslog(LOG_ERR,
		    "connect_chosen_lan: invalid ESSID '%s' for '%s'",
		    reqlan->essid, ifname);
		return (B_FALSE);
	}
	attr.wa_valid = DLADM_WLAN_ATTR_ESSID;
	if (reqlan->bssid != NULL) {
		if (dladm_wlan_str2bssid(reqlan->bssid, &attr.wa_bssid) !=
		    DLADM_STATUS_OK) {
			syslog(LOG_ERR,
			    "connect_chosen_lan: invalid BSSID '%s' for '%s'",
			    reqlan->bssid, ifname);
			return (B_FALSE);
		}
		attr.wa_valid |= DLADM_WLAN_ATTR_BSSID;
	}

	/* First check for the wepkey */
	if (reqlan->need_wepkey) {
		get_user_wepkey(reqlan);
		if (reqlan->cooked_wepkey == NULL)
			return (B_FALSE);
		attr.wa_valid |= DLADM_WLAN_ATTR_SECMODE;
		attr.wa_secmode = DLADM_WLAN_SECMODE_WEP;
		key = reqlan->cooked_wepkey;
		keycount = 1;
		dprintf("connect_chosen_lan: retrieved key");
	} else {
		key = NULL;
		keycount = 0;
	}

	/*
	 * Connect; only scan if a bssid was not specified.
	 * If it times out and we were trying with a bssid,
	 * try a second time with just the ESSID.
	 */

	status = dladm_wlan_connect(ifname, &attr, timeout, key, keycount,
	    flags);
	dprintf("connect_chosen_lan: dladm_wlan_connect returned %s",
	    dladm_status2str(status, errmsg));
	if (status == DLADM_STATUS_TIMEDOUT && reqlan->bssid != NULL) {
		syslog(LOG_INFO, "connect_chosen_lan: failed for (%s, %s), "
		    "trying again with just (%s)",
		    reqlan->essid, reqlan->bssid, reqlan->essid);
		attr.wa_valid &= ~DLADM_WLAN_ATTR_BSSID;
		flags = 0;
		status = dladm_wlan_connect(ifname, &attr, timeout, key,
		    keycount, flags);
	}
	if (status != DLADM_STATUS_OK) {
		syslog(LOG_ERR,
		    "connect_chosen_lan: connect to '%s' failed on '%s': %s",
		    reqlan->essid, ifname, dladm_status2str(status, errmsg));
		return (B_FALSE);
	}
	return (B_TRUE);
}

/*
 * First attempt to connect to the network specified by essid.
 * If that fails, attempt to connect using autoconf.
 */
static boolean_t
connect_or_autoconf(struct wireless_lan *reqlan, const char *ifname)
{
	if (!connect_chosen_lan(reqlan, ifname)) {
		syslog(LOG_WARNING,
		    "Could not connect to chosen WLAN %s, going to auto-conf",
		    reqlan->essid);
		return (wlan_autoconf(ifname));
	}
	return (B_TRUE);
}

/*
 * The +1 is for the extra "compare" row, the 24 is for the font spacing
 * and the 125 if extra for the buttons et al.
 */
static int
zenity_height(int rows)
{
	return (((rows + 1) * 24) + 125);
}

static return_vals_t
connect_to_new_wlan(const struct wireless_lan *lanlist, int num,
    const char *ifname)
{
	int i, rtn, j = 0;
	struct interface *intf;
	struct wireless_lan *reqlan;
	char buf[2048];
	char *endbuf = buf;
	size_t buflen = 0;
	char zenity_cmd[2048];
	char *other_str = gettext("Other");
	char *rescan_str = gettext("Rescan");
	boolean_t autoconf = B_FALSE;

	dprintf("connect_to_new_wlan(..., %d, %s)", num, ifname);

	if (num == 0) {
		display(gettext("No Wifi networks found; continuing in case "
		    "you know of any which do not broadcast."));
	}

	if ((intf = get_interface(ifname)) == NULL) {
		dprintf("connect_to_new_wlan: cannot find wireless interface: "
		    "%s", ifname);
		return (FAILURE);
	}

	/* build list for display */
	buf[0] = '\0';
	for (i = 0; i < num; i++) {
		if ((lanlist[i].essid == NULL) || (lanlist[i].bssid == NULL)) {
			syslog(LOG_WARNING, "wifi list entry %d broken: "
			    "essid %s, bssid %s; ignoring", i,
			    STRING(lanlist[i].essid), STRING(lanlist[i].bssid));
			continue;
		}
		/*
		 * Only use the interface which finds the AP to connect to it.
		 */
		if (strcmp(lanlist[i].wl_if_name, ifname) != 0) {
			dprintf("connect_to_new_wlan: wrong interface (%s) for "
			    "%s (should be %s)", ifname, lanlist[i].essid,
			    lanlist[i].wl_if_name);
			continue;
		}

		j++;
		/*
		 * Zenity uses a space as its delimiter, so put the ESSID in
		 * quotes so it won't get confused if there is a space in the
		 * ESSID name.
		 */
		if (sizeof (buf) - 1 > buflen) {
			buflen += snprintf(endbuf, sizeof (buf) - buflen,
			    "%d '%s' %s %s '%s' ", j,
			    lanlist[i].essid, lanlist[i].bssid,
			    lanlist[i].need_wepkey ? "WEP" : "none",
			    lanlist[i].signal_strength);
			endbuf = buf + buflen;
		}
	}
	if (sizeof (buf) - 1 > buflen) {
		/*
		 * All columns except the first are empty for the "Other"
		 * and "Rescan" rows.
		 */
		(void) snprintf(endbuf, sizeof (buf) - buflen,
		    "\"%s\" \"\" \"\" \"\" \"\" \"%s\" \"\" \"\" \"\" \"\"",
		    other_str, rescan_str);
	}

	(void) snprintf(zenity_cmd, sizeof (zenity_cmd),
	    "%s --list --title=\"%s\""
	    " --height=%d --width=500 --column=\"#\" --column=\"%s\""
	    " --column=\"%s\" --column=\"%s\" --column=\"%s\""
	    " %s ", ZENITY, gettext("Choose WiFi network you wish to activate"),
	    zenity_height(j), "ESSID", "BSSID", gettext("Encryption"),
	    gettext("Signal"), buf);

	/* present list to user and get selection */
	rtn = get_user_preference(zenity_cmd, other_str, rescan_str, &reqlan,
	    lanlist);
	switch (rtn) {
	case 1:
		/* user chose "other"; pop-up for specific essid */
		reqlan = get_specific_lan();
		break;
	case 2:
		/* user chose "Rescan" */
		(void) scan_wireless_nets(intf);
		return (TRY_AGAIN);
	case -1:
		reqlan = NULL;
		break;
	default:
		/* common case: reqlan was set in get_user_preference() */
		break;
	}

	if ((reqlan == NULL) || (reqlan->essid == NULL)) {
		dprintf("did not get user preference; attempting autoconf");
		return (wlan_autoconf(ifname) ? SUCCESS : FAILURE);
	}
	dprintf("get_user_preference() returned essid %s, bssid %s, encr %s",
	    reqlan->essid, STRING(reqlan->bssid),
	    reqlan->need_wepkey ? "WEP" : "none");

	/* set wepkey before first time connection */
	if (reqlan->need_wepkey && reqlan->raw_wepkey == NULL &&
	    reqlan->cooked_wepkey == NULL)
		get_user_wepkey(reqlan);

	/*
	 * now attempt to connect to selection, backing
	 * off to autoconf if the connect fails
	 */
	if (connect_chosen_lan(reqlan, ifname)) {
		/* succeeded, so add entry to known_essid_list_file */
		update_known_wifi_nets_file(reqlan->essid, reqlan->bssid);
	} else {
		/* failed to connect; try auto-conf */
		syslog(LOG_WARNING, "Could not connect to chosen WLAN "
		    "%s; going to auto-conf", reqlan->essid);
		autoconf = B_TRUE;
	}
	free_wireless_lan(reqlan);

	if (!autoconf)
		return (SUCCESS);
	return (wlan_autoconf(ifname) ? SUCCESS : FAILURE);
}

struct wireless_lan *
prompt_for_visited(void)
{
	char buf[1024];
	size_t buflen = 0;
	char *endbuf = buf;
	char zenity_cmd[1024];
	char *select_str = gettext("Select from all available WiFi networks");
	char *rescan_str = gettext("Rescan");
	struct wireless_lan *req_conf = NULL, *list;
	int i = 0;

	/* Build zenity command string */
	buf[0] = '\0';
	if (visited_wlan_list->total > 0) {
		struct visited_wlans *vlp;
		struct wireless_lan *wlp;

		list = calloc(visited_wlan_list->total,
		    sizeof (struct wireless_lan));
		if (list == NULL) {
			syslog(LOG_ERR, "prompt_for_visited: calloc failed");
			return (NULL);
		}
		for (vlp = visited_wlan_list->head;
		    vlp != NULL; vlp = vlp->next) {

			wlp = vlp->wifi_net;
			if (wlp->essid == NULL || wlp->bssid == NULL) {
				dprintf("Invalid essid/bssid values");
				continue;
			}
			i++;
			if (sizeof (buf) - 1 > buflen) {
				buflen += snprintf(endbuf,
				    sizeof (buf) - buflen,
				    "%d '%s' %s %s '%s' ",
				    i, wlp->essid, wlp->bssid,
				    wlp->need_wepkey ? "WEP" : gettext("none"),
				    wlp->signal_strength);
				endbuf = buf + buflen;
			}
			list[i-1].essid = wlp->essid;
			list[i-1].bssid = wlp->bssid;
			list[i-1].need_wepkey = wlp->need_wepkey;
			list[i-1].raw_wepkey = wlp->raw_wepkey;
			list[i-1].cooked_wepkey = wlp->cooked_wepkey;
			list[i-1].signal_strength = wlp->signal_strength;
			list[i-1].wl_if_name = wlp->wl_if_name;
		}
	}
	if (sizeof (buf) - 1 > buflen) {
		(void) snprintf(endbuf, sizeof (buf) - buflen,
		    "\"%s\"", select_str);
	}

	(void) snprintf(zenity_cmd, sizeof (zenity_cmd),
	    "%s --list --title=\"%s\""
	    " --height=%d --width=670 --column=\"#\" --column=\"%s\""
	    " --column=\"%s\" --column=\"%s\" --column=\"%s\""
	    " %s", ZENITY, gettext("Choose from pre-visited WiFi network"),
	    zenity_height(i), "ESSID", "BSSID", gettext("Encryption"),
	    gettext("Signal"), buf);

	/*
	 * If the user doesn't make a choice or something goes wrong
	 * (get_user_preference() returned -1), or if the user chooses
	 * the "select from all available" string (get_user_preference()
	 * returned 1), we simply return NULL: there was no selection
	 * made from the visited list.  If the user *did* make a choice
	 * (get_user_preference() returned 0), return the alloc'd struct.
	 */
	if (get_user_preference(zenity_cmd, select_str,	rescan_str,
	    &req_conf, list) != 0)
		req_conf = NULL;

	free(list);
	return (req_conf);
}

static boolean_t
wlan_autoconf(const char *ifname)
{
	dladm_status_t status;
	boolean_t autoconf;

	if (lookup_boolean_property(OUR_PG, "autoconf", &autoconf) == 0) {
		if (!autoconf)
			return (B_FALSE);
	}

	/* If the NIC is already associated with something, just return. */
	if (check_wlan(ifname, NULL))
		return (B_TRUE);

	/*
	 * Do autoconf, relying on the heuristics used by dladm_wlan_connect()
	 * to cycle through WLANs detected in priority order, attempting
	 * to connect.
	 */
	status = dladm_wlan_connect(ifname, NULL,
	    DLADM_WLAN_CONNECT_TIMEOUT_DEFAULT, NULL, 0, 0);
	if (status != DLADM_STATUS_OK) {
		char errmsg[DLADM_STRSIZE];

		syslog(LOG_ERR,
		    "wlan_autoconf: dladm_wlan_connect failed for '%s': %s",
		    ifname, dladm_status2str(status, errmsg));
		return (B_FALSE);
	}
	return (B_TRUE);
}

/*
 * Returns:
 * B_TRUE if this info is already in visited_wlan_list
 * B_FALSE if not
 */
static boolean_t
already_in_visited_wlan_list(const struct wireless_lan *new_wlan)
{
	struct visited_wlans *vwlp;

	vwlp = visited_wlan_list->head;
	while (vwlp != NULL && vwlp->wifi_net != NULL) {
		if (strcmp(vwlp->wifi_net->essid, new_wlan->essid) == 0) {
			dprintf("%s already in visited_wlan_list",
			    vwlp->wifi_net->essid);
			return (B_TRUE);
		} else {
			vwlp = vwlp->next;
		}
	}
	return (B_FALSE);
}

static char *
get_zenity_response(const char *cmd)
{
	char buf[1024];
	size_t buf_len;
	char *rtnp;
	FILE *cptr;
	int ret;

	if (!valid_graphical_user(B_TRUE))
		return (NULL);

	cptr = popen(cmd, "r");
	if (cptr == NULL) {
		syslog(LOG_ERR, "Could not run %s: %m", ZENITY);
		return (NULL);
	}
	if (fgets(buf, sizeof (buf), cptr) != NULL) {
		buf_len = strlen(buf);
		if (buf_len > 0 && buf[buf_len - 1] == '\n')
			buf[buf_len - 1] = '\0';
		dprintf("get_zenity_resp: zenity returned '%s'", buf);
	} else {
		buf[0] = '\0';
		dprintf("get_zenity_resp: zenity returned nothing");
	}
	ret = pclose(cptr);
	/*
	 * We should probably make sure that those ZENITY_* exit
	 * environment variables are not set first...
	 */
	if (ret == -1 || !WIFEXITED(ret) || (WEXITSTATUS(ret) == 255)) {
		dprintf("get_zenity_resp: %s did not exit normally", ZENITY);
		return (NULL);
	}
	if (WEXITSTATUS(ret) == 1) {
		dprintf("get_zenity_resp: user cancelled");
		return (NULL);
	}
	if ((rtnp = strdup(buf)) == NULL)
		syslog(LOG_ERR, "get_zenity_response: strdup failed");

	return (rtnp);
}

/*
 * get_user_preference():  Present a list of essid/bssid pairs to the
 * user via zenity (passed in in a pre-formatted zenity string in the
 * param cmd).  If there's a final list item ("Other", "Select from
 * full list", etc.) that may be selected and should be differentiated,
 * that item should be passed in in compare param.
 *
 * Four possible return values:
 * -1: No response from user, or other error.  *req_lan is undefined.
 *  0: essid/bssid pair was selected.  *req_lan has these values in
 *     a malloc'd buffer, which the caller is responsible for freeing.
 *  1: a compare string ("Other") was given, and the user response matched
 *     that string.  *req_lan is undefined.
 *  2: a compare string ("Rescan") was given, and the user response matched
 *     that string.  *req_lan is undefined.
 */
int
get_user_preference(const char *cmd, const char *compare_other,
    const char *compare_rescan, struct wireless_lan **req_lan,
    const struct wireless_lan *list)
{
	char *response;
	struct wireless_lan *wlp;
	const struct wireless_lan *sel;
	int answer;

	assert(req_lan != NULL);
	wlp = calloc(1, sizeof (struct wireless_lan));
	if (wlp == NULL) {
		syslog(LOG_ERR, "malloc failed");
		return (-1);
	}

	response = get_zenity_response(cmd);
	if (response == NULL) {
		free(wlp);
		return (-1);
	}
	if (strcmp(response, compare_other) == 0) {
		free(response);
		free(wlp);
		return (1);
	}
	if (strcmp(response, compare_rescan) == 0) {
		free(response);
		free(wlp);
		return (2);
	}
	answer = atoi(response);
	if (answer <= 0) {
		dprintf("%s returned invalid string", ZENITY);
		free(response);
		free(wlp);
		return (-1);
	}
	sel = &list[answer - 1];

	if ((wlp->essid = strdup(sel->essid)) == NULL)
		goto dup_error;

	if ((sel->bssid != NULL) && ((wlp->bssid = strdup(sel->bssid)) == NULL))
		goto dup_error;

	wlp->need_wepkey = sel->need_wepkey;

	if ((sel->raw_wepkey != NULL) &&
	    ((wlp->raw_wepkey = strdup(sel->raw_wepkey)) == NULL))
		goto dup_error;

	if (sel->cooked_wepkey != NULL) {
		wlp->cooked_wepkey = malloc(sizeof (dladm_wlan_wepkey_t));
		if (wlp->cooked_wepkey == NULL)
			goto dup_error;
		*(wlp->cooked_wepkey) = *(sel->cooked_wepkey);
	}

	if ((sel->signal_strength != NULL) &&
	    ((wlp->signal_strength = strdup(sel->signal_strength)) == NULL))
		goto dup_error;

	if ((sel->wl_if_name != NULL) &&
	    ((wlp->wl_if_name = strdup(sel->wl_if_name)) == NULL))
		goto dup_error;

	dprintf("selected: %s, %s, %s, '%s', %s", wlp->essid,
	    STRING(wlp->bssid), wlp->need_wepkey ? "WEP" : "none",
	    STRING(wlp->signal_strength), STRING(wlp->wl_if_name));

	free(response);

	*req_lan = wlp;
	return (0);

dup_error:
	syslog(LOG_ERR, "get_user_preference: strdup failed");
	free_wireless_lan(wlp);
	free(wlp);
	free(response);
	return (-1);
}

/*
 * Returns a pointer to an alloc'd struct wireless lan if a response
 * is received from the user; only the essid will be valid in this
 * case.  If no response received, or other failure, returns NULL.
 */
static struct wireless_lan *
get_specific_lan(void)
{
	char specify_str[1024];
	char *response;
	struct wireless_lan *wlp;

	/*
	 * TRANSLATION_NOTE: the token "ESSID" should not be translated
	 * in the phrase below.
	 */
	(void) snprintf(specify_str, sizeof (specify_str), ZENITY
	    " --entry --title=\"%s\" --text=\"%s\"",
	    gettext("Specify WiFi network"), gettext("Enter ESSID"));

	response = get_zenity_response(specify_str);
	if (response == NULL)
		return (NULL);

	wlp = calloc(1, sizeof (struct wireless_lan));
	if (wlp == NULL) {
		syslog(LOG_ERR, "malloc failed: %m");
		free(response);
		return (NULL);
	}
	wlp->essid = response;

	(void) snprintf(specify_str, sizeof (specify_str), ZENITY
	    " --list --title=\"%s\" --text=\"%s\" --column=\"%s\" none wep",
	    gettext("Security"), gettext("Enter security"),
	    gettext("Type"));

	response = get_zenity_response(specify_str);
	if (response != NULL && strcmp(response, "wep") == 0)
		wlp->need_wepkey = B_TRUE;

	free(response);
	return (wlp);
}

/*
 * Returns:
 * B_TRUE if things go well
 * B_FALSE if we were unable to connect to anything
 */
boolean_t
handle_wireless_lan(const char *ifname)
{
	const struct wireless_lan *cur_wlans;
	int i, num_wlans;
	struct wireless_lan *req_conf = NULL;
	boolean_t result;
	dladm_wlan_strength_t strongest = DLADM_WLAN_STRENGTH_VERY_WEAK;
	dladm_wlan_strength_t strength;
	return_vals_t connect_result;

start_over:
	if (visited_wlan_list == NULL) {
		if ((visited_wlan_list = calloc(1,
		    sizeof (struct visited_wlans_list))) == NULL) {
			syslog(LOG_ERR, "handle_wireless_lan: calloc failed");
			return (B_FALSE);
		}
	}

	/*
	 * We wait while a scan is in progress.  Since we allow a user
	 * to initiate a re-scan, we can proceed even when no scan
	 * has been done to fill in the AP list.
	 */
	(void) pthread_mutex_lock(&wifi_init_mutex);
	while (wifi_scan_intf != NULL)
		(void) pthread_cond_wait(&wifi_init_cond, &wifi_init_mutex);
	(void) pthread_mutex_unlock(&wifi_init_mutex);

	(void) pthread_mutex_lock(&wifi_mutex);
	num_wlans = wireless_lan_used;
	cur_wlans = wlans;

	/*
	 * Try to see if any of the wifi nets currently available
	 * has been used previously. If more than one available
	 * nets has been used before, then prompt user with
	 * all the applicable previously wifi nets, and ask which
	 * one to connect to.
	 */
	for (i = 0; i < num_wlans; i++) {
		struct visited_wlans *new_wlan;

		/* Find the AP with the highest signal. */
		if (dladm_wlan_str2strength(cur_wlans[i].signal_strength,
		    &strength) != DLADM_STATUS_OK) {
			continue;
		}
		if (strength > strongest)
			strongest = strength;

		if (!known_wifi_nets_lookup(cur_wlans[i].essid,
		    cur_wlans[i].bssid))
			continue;

		if (already_in_visited_wlan_list(&cur_wlans[i])) {
			/* don't have to add it again */
			continue;
		}

		/* add this to the visited_wlan_list */
		dprintf("adding essid %s, bssid %s to visited list",
		    cur_wlans[i].essid, STRING(cur_wlans[i].bssid));

		new_wlan = calloc(1, sizeof (struct visited_wlans));
		if (new_wlan == NULL) {
			syslog(LOG_ERR, "handle_wireless_lan: calloc failed");
			result = B_FALSE;
			connect_result = FAILURE;
			goto all_done;
		}
		new_wlan->wifi_net = calloc(1, sizeof (struct wireless_lan));
		if (new_wlan->wifi_net == NULL) {
			free(new_wlan);
			syslog(LOG_ERR, "handle_wireless_lan: calloc failed");
			result = B_FALSE;
			connect_result = FAILURE;
			goto all_done;
		}
		new_wlan->wifi_net->essid = strdup(cur_wlans[i].essid);
		new_wlan->wifi_net->bssid = strdup(cur_wlans[i].bssid);
		new_wlan->wifi_net->raw_wepkey = NULL;
		new_wlan->wifi_net->cooked_wepkey = NULL;
		new_wlan->wifi_net->need_wepkey = cur_wlans[i].need_wepkey;
		new_wlan->wifi_net->signal_strength =
		    strdup(cur_wlans[i].signal_strength);
		new_wlan->wifi_net->wl_if_name =
		    strdup(cur_wlans[i].wl_if_name);
		if (new_wlan->wifi_net->essid == NULL ||
		    new_wlan->wifi_net->bssid == NULL ||
		    new_wlan->wifi_net->signal_strength == NULL ||
		    new_wlan->wifi_net->wl_if_name == NULL) {
			syslog(LOG_ERR, "handle_wireless_lan: strdup failed");
			free_wireless_lan(new_wlan->wifi_net);
			free(new_wlan->wifi_net);
			free(new_wlan);
			result = B_FALSE;
			connect_result = FAILURE;
			goto all_done;
		}

		new_wlan->next = visited_wlan_list->head;
		visited_wlan_list->head = new_wlan;
		visited_wlan_list->total++;
	}

	if (visited_wlan_list->total == 1) {
		struct wireless_lan *target = visited_wlan_list->head->wifi_net;

		/*
		 * only one previously visited wifi net, connect to it
		 * (falling back to autoconf if the connect fails) if there
		 * is no AP with a better signal strength.
		 */
		if (dladm_wlan_str2strength(target->signal_strength,
		    &strength) == DLADM_STATUS_OK) {
			if (strength < strongest)
				goto connect_any;
		}
		result = connect_or_autoconf(target, ifname);
		connect_result = result ? SUCCESS : FAILURE;

	} else if (visited_wlan_list->total > 1) {
		/*
		 * more than one previously visited wifi nets seen.
		 * prompt user for which one should we connect to
		 */
		if ((req_conf = prompt_for_visited()) != NULL) {
			result = connect_or_autoconf(req_conf, ifname);
			connect_result = result ? SUCCESS : FAILURE;
		} else {
			/*
			 * The user didn't make a choice; offer the full list.
			 */
			connect_result = connect_to_new_wlan(cur_wlans,
			    num_wlans, ifname);
			result = (connect_result == SUCCESS);
		}
	} else {
connect_any:
		/* last case, no previously visited wlan found */
		connect_result = connect_to_new_wlan(cur_wlans, num_wlans,
		    ifname);
		result = (connect_result == SUCCESS);
	}

all_done:
	/*
	 * We locked down the list above; free it now that we're done.
	 */
	(void) pthread_mutex_unlock(&wifi_mutex);
	if (visited_wlan_list != NULL) {
		struct visited_wlans *vwlp = visited_wlan_list->head, *next;

		for (; vwlp != NULL; vwlp = next) {
			if (vwlp->wifi_net != NULL) {
				free_wireless_lan(vwlp->wifi_net);
				free(vwlp->wifi_net);
				vwlp->wifi_net = NULL;
			}
			next = vwlp->next;
			free(vwlp);
		}
		free(visited_wlan_list);
		visited_wlan_list = NULL;
	}
	if (req_conf != NULL) {
		free_wireless_lan(req_conf);
		free(req_conf);
		req_conf = NULL;
	}
	if (connect_result == TRY_AGAIN) {
		dprintf("end of handle_wireless_lan() TRY_AGAIN");
		goto start_over;
	}
	return (result);
}
