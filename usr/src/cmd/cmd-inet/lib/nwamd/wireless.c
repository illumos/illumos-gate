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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file contains all the routines to handle wireless (more
 * accurately, 802.11 "WiFi" family only at this moment) operations.
 * This is only phase 0 work so the handling is pretty simple.
 *
 * When the daemon starts up, for each WiFi interface detected, it'll
 * spawn a thread doing an access point (AP) scanning.  After the scans
 * finish and if one of the WiFi interfaces is chosen to be active, the
 * code will send a message to the GUI, which then must gather the results.
 *
 * WEP/WPA is supported to connect to those APs which require it.  The code
 * also maintains a list of known WiFi APs in the file KNOWN_WIFI_NETS.
 * Whenever the code successfully connects to an AP, the AP's ESSID/BSSID will
 * be added to that file.  This file is used in the following way.
 *
 * If the AP scan results contain one known AP (plus any number of unknown
 * APs), the code will automatically connect to that AP without contacting the
 * GUI.  But if the detected signal strength of that one known AP is weaker
 * than any of the unknown APs, the code will block on the GUI.
 *
 * If the AP scan results contain more than one known APs or no known APs, the
 * GUI is notified.
 *
 * Note that not all APs broadcast the Beacon.  And some events may
 * happen during the AP scan such that not all available APs are found.
 * Thus, the GUI can specify an AP's data.
 *
 * The code also periodically (specified by wlan_scan_interval) checks
 * for the health of the AP connection.  If the signal strength of the
 * connected AP drops below a threshold (specified by wireless_scan_level),
 * the code will try to do another scan to find out other APs available.
 * If there is currently no connected AP, a scan will also be done
 * periodically to look for available APs.  In both cases, if there are
 * new APs, the above AP connection procedure will be performed.
 *
 * As a way to deal with the innumerable bugs that seem to plague wireless
 * interfaces with respect to concurrent operations, we completely exclude all
 * connect operations on all interfaces when another connect or scan is
 * running, and exclude all scans on all interfaces when another connect or
 * scan is running.  This is done using wifi_scan_intf.
 *
 * Much of the BSSID handling logic in this module is questionable due to
 * underlying bugs such as CR 6772510.  There's likely little that we can do
 * about this.
 *
 * Lock ordering note: wifi_mutex and wifi_init_mutex are not held at the same
 * time.
 */

#include <unistd.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <syslog.h>
#include <limits.h>
#include <errno.h>
#include <sys/stat.h>
#include <syslog.h>
#include <pthread.h>
#include <sys/wait.h>
#include <stropts.h>
#include <sys/types.h>
#include <fcntl.h>
#include <libdladm.h>
#include <libdllink.h>
#include <libinetutil.h>
#include <libgen.h>

#include "defines.h"
#include "structures.h"
#include "functions.h"
#include "variables.h"

#define	WLAN_ENC(sec)						\
	((sec == DLADM_WLAN_SECMODE_WPA ? "WPA" : 		\
	(sec == DLADM_WLAN_SECMODE_WEP ? "WEP" : "none")))

#define	NEED_ENC(sec)						\
	(sec == DLADM_WLAN_SECMODE_WPA || sec == DLADM_WLAN_SECMODE_WEP)

static pthread_mutex_t wifi_mutex;

typedef enum {
	ESSID = 0,
	BSSID,
	MAX_FIELDS
} known_wifi_nets_fields_t;

/*
 * List of wireless interfaces; protected by wifi_mutex.
 */
static struct qelem wi_list;
static uint_t wi_link_count;

/*
 * Is a wireless interface doing a scan currently?  We only allow one
 * wireless interface to do a scan at any one time.  This is to
 * avoid unnecessary interference.  The following variable is used
 * to store the interface doing the scan.  It is protected by
 * wifi_init_mutex.
 */
static const char *wifi_scan_intf;
static boolean_t connect_running;
static pthread_mutex_t wifi_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t wifi_init_cond = PTHREAD_COND_INITIALIZER;

/*
 * Array of wireless LAN entries; protected by wifi_mutex.
 */
static struct wireless_lan *wlans;
static uint_t wireless_lan_count; /* allocated */
static uint_t wireless_lan_used; /* used entries */
static boolean_t new_ap_found;

static int key_string_to_secobj_value(char *, uint8_t *, uint_t *,
    dladm_secobj_class_t);
static int store_key(struct wireless_lan *);
static dladm_wlan_key_t *retrieve_key(const char *, const char *,
    dladm_secobj_class_t);

static struct wireless_lan *add_wlan_entry(const char *, const char *,
    const char *, dladm_wlan_attr_t *);
static boolean_t check_wlan(const wireless_if_t *, const char *, const char *,
    boolean_t);
static struct wireless_lan *find_wlan_entry(const char *, const char *,
    const char *);
static void free_wireless_lan(struct wireless_lan *);
static return_vals_t get_user_key(struct wireless_lan *);
static boolean_t wlan_autoconf(const wireless_if_t *);
static boolean_t get_scan_results(void *, dladm_wlan_attr_t *);
static int add_known_wifi_nets_file(const char *, const char *);
static boolean_t known_wifi_nets_lookup(const char *, const char *, char *);
static return_vals_t connect_chosen_lan(struct wireless_lan *, wireless_if_t *);

#define	WIRELESS_LAN_INIT_COUNT	8

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

/*
 * This controls whether we are strict about matching BSSID in the known wifi
 * networks file.  By default, we're not strict.
 */
boolean_t strict_bssid;

void
initialize_wireless(void)
{
	pthread_mutexattr_t wifi_mutex_attr;

	(void) pthread_mutexattr_init(&wifi_mutex_attr);
	(void) pthread_mutexattr_settype(&wifi_mutex_attr,
	    PTHREAD_MUTEX_RECURSIVE);
	(void) pthread_mutex_init(&wifi_mutex, &wifi_mutex_attr);
	wi_list.q_forw = wi_list.q_back = &wi_list;
}

void
add_wireless_if(const char *ifname)
{
	wireless_if_t *wip;

	if ((wip = calloc(1, sizeof (*wip))) != NULL) {
		(void) strlcpy(wip->wi_name, ifname, sizeof (wip->wi_name));
		(void) dladm_name2info(dld_handle, ifname, &wip->wi_linkid,
		    NULL, NULL, NULL);
		if (pthread_mutex_lock(&wifi_mutex) == 0) {
			insque(&wip->wi_links, wi_list.q_back);
			wi_link_count++;
			(void) pthread_mutex_unlock(&wifi_mutex);
		} else {
			free(wip);
		}
	}
}

static wireless_if_t *
find_wireless_if(const char *ifname)
{
	wireless_if_t *wip;

	for (wip = (wireless_if_t *)wi_list.q_forw;
	    wip != (wireless_if_t *)&wi_list;
	    wip = (wireless_if_t *)wip->wi_links.q_forw) {
		if (strcmp(wip->wi_name, ifname) == 0)
			return (wip);
	}
	return (NULL);
}

void
remove_wireless_if(const char *ifname)
{
	wireless_if_t *wip;

	if (pthread_mutex_lock(&wifi_mutex) == 0) {
		if ((wip = find_wireless_if(ifname)) != NULL) {
			remque(&wip->wi_links);
			wi_link_count--;
		}
		(void) pthread_mutex_unlock(&wifi_mutex);
		free(wip);
	}
}

/*
 * wlan is expected to be non-NULL.
 */
static return_vals_t
get_user_key(struct wireless_lan *wlan)
{
	dladm_secobj_class_t class;

	/*
	 * First, test if we have key stored as secobj. If so,
	 * no need to prompt for it.
	 */
	class = (wlan->attrs.wa_secmode == DLADM_WLAN_SECMODE_WEP ?
	    DLADM_SECOBJ_CLASS_WEP : DLADM_SECOBJ_CLASS_WPA);
	wlan->cooked_key = retrieve_key(wlan->essid, wlan->bssid, class);
	if (wlan->cooked_key != NULL) {
		dprintf("get_user_key: retrieve_key() returns non NULL");
		return (SUCCESS);
	} else if (request_wlan_key(wlan)) {
		return (WAITING);
	} else {
		return (FAILURE);
	}
}

/*
 * This function assumes that wifi_mutex is held.  If bssid is specified, then
 * an exact match is returned.  If it's not specified, then the best match is
 * returned.
 */
static struct wireless_lan *
find_wlan_entry(const char *ifname, const char *essid, const char *bssid)
{
	struct wireless_lan *wlan, *best;

	best = NULL;
	for (wlan = wlans; wlan < wlans + wireless_lan_used; wlan++) {
		if (strcmp(wlan->essid, essid) != 0 ||
		    strcmp(wlan->wl_if_name, ifname) != 0)
			continue;
		if (bssid[0] == '\0') {
			if (best == NULL ||
			    wlan->attrs.wa_strength > best->attrs.wa_strength)
				best = wlan;
		} else {
			if (strcmp(wlan->bssid, bssid) == 0)
				return (wlan);
		}
	}
	return (best);
}

static void
free_wireless_lan(struct wireless_lan *wlp)
{
	free(wlp->essid);
	wlp->essid = NULL;
	/* empty string is not allocated */
	if (wlp->bssid != NULL && wlp->bssid[0] != '\0')
		free(wlp->bssid);
	wlp->bssid = NULL;
	free(wlp->signal_strength);
	wlp->signal_strength = NULL;
	free(wlp->raw_key);
	wlp->raw_key = NULL;
	free(wlp->cooked_key);
	wlp->cooked_key = NULL;
}

/*
 * This function assumes that wifi_mutex is held.
 */
static struct wireless_lan *
add_wlan_entry(const char *ifname, const char *essid, const char *bssid,
    dladm_wlan_attr_t *attrp)
{
	char strength[DLADM_STRSIZE];
	struct wireless_lan *wlan;

	if (wireless_lan_used == wireless_lan_count) {
		int newcnt;

		newcnt = (wireless_lan_count == 0) ?
		    WIRELESS_LAN_INIT_COUNT : wireless_lan_count * 2;
		wlan = realloc(wlans, newcnt * sizeof (*wlans));
		if (wlan == NULL) {
			syslog(LOG_ERR, "add_wlan_entry: realloc failed");
			return (NULL);
		}
		wireless_lan_count = newcnt;
		wlans = wlan;
	}

	(void) dladm_wlan_strength2str(&attrp->wa_strength, strength);

	wlan = wlans + wireless_lan_used;
	(void) memset(wlan, 0, sizeof (*wlan));
	wlan->attrs = *attrp;
	wlan->essid = strdup(essid);
	/* do not do allocation for zero-length */
	wlan->bssid = *bssid == '\0' ? "" : strdup(bssid);
	wlan->signal_strength = strdup(strength);
	(void) strlcpy(wlan->wl_if_name, ifname, sizeof (wlan->wl_if_name));
	wlan->scanned = B_TRUE;
	if (wlan->essid == NULL || wlan->bssid == NULL ||
	    wlan->signal_strength == NULL) {
		syslog(LOG_ERR, "add_wlan_entry: strdup failed");
		free_wireless_lan(wlan);
		return (NULL);
	}
	wireless_lan_used++;
	new_ap_found = B_TRUE;
	return (wlan);
}

/*
 * Remove entries that are no longer seen on the network.  The caller does not
 * hold wifi_mutex, but is the only thread that can modify the wlan list.
 * Retain connected entries, as lack of visibility in a scan may just be a
 * temporary condition (driver problem) and may not reflect an actual
 * disconnect.
 */
static boolean_t
clear_unscanned_entries(const char *ifname)
{
	struct wireless_lan *wlan, *wlput;
	boolean_t dropped;

	if (pthread_mutex_lock(&wifi_mutex) != 0)
		return (B_FALSE);
	wlput = wlans;
	dropped = B_FALSE;
	for (wlan = wlans; wlan < wlans + wireless_lan_used; wlan++) {
		if (strcmp(ifname, wlan->wl_if_name) != 0 || wlan->scanned ||
		    wlan->connected) {
			if (wlput != wlan)
				*wlput = *wlan;
			wlput++;
		} else {
			dprintf("dropping unseen AP %s %s", wlan->essid,
			    wlan->bssid);
			dropped = B_TRUE;
			free_wireless_lan(wlan);
		}
	}
	wireless_lan_used = wlput - wlans;
	(void) pthread_mutex_unlock(&wifi_mutex);
	return (dropped);
}

/*
 * Verify if a WiFi NIC is associated with the given ESSID and BSSID.  If the
 * given ESSID is NULL, and if the NIC is already connected, return true.
 * Otherwise,
 *
 * 1. If the NIC is associated with the given ESSID/BSSID, return true.
 * 2. If the NIC is not associated with any AP, return false.
 * 3. If the NIC is associated with a different AP, tear down IP interface,
 *    tell the driver to disassociate with AP, and then return false.
 */
static boolean_t
check_wlan(const wireless_if_t *wip, const char *exp_essid,
    const char *exp_bssid, boolean_t sendevent)
{
	dladm_wlan_linkattr_t attr;
	dladm_status_t status;
	char cur_essid[DLADM_STRSIZE];
	char cur_bssid[DLADM_STRSIZE];
	char errmsg[DLADM_STRSIZE];

	status = dladm_wlan_get_linkattr(dld_handle, wip->wi_linkid, &attr);
	if (status != DLADM_STATUS_OK) {
		dprintf("check_wlan: dladm_wlan_get_linkattr() for %s "
		    "failed: %s", wip->wi_name,
		    dladm_status2str(status, errmsg));
		return (B_FALSE);
	}
	if (attr.la_status == DLADM_WLAN_LINK_DISCONNECTED)
		return (B_FALSE);

	/* If we're expecting "any" connection, then we're done. */
	if (exp_essid == NULL)
		return (B_TRUE);

	/* Is the NIC associated with the expected access point? */
	(void) dladm_wlan_essid2str(&attr.la_wlan_attr.wa_essid, cur_essid);
	if (strcmp(cur_essid, exp_essid) != 0) {
		dprintf("wrong ESSID: have %s expect %s; taking down",
		    cur_essid, exp_essid);
		goto unexpected;
	}

	if (exp_bssid == NULL)
		return (B_TRUE);

	(void) dladm_wlan_bssid2str(&attr.la_wlan_attr.wa_bssid, cur_bssid);
	if (strcmp(cur_bssid, exp_bssid) == 0)
		return (B_TRUE);
	dprintf("wrong BSSID: have %s expect %s; taking down",
	    cur_bssid, exp_bssid);

unexpected:
	if (sendevent) {
		/* If not, then shut the interface down normally */
		(void) np_queue_add_event(EV_TAKEDOWN, wip->wi_name);
		(void) dladm_wlan_disconnect(dld_handle, wip->wi_linkid);
	}
	return (B_FALSE);
}

/*
 * Examine all WLANs associated with an interface, verify the expected WLAN,
 * and update the 'connected' attribute appropriately.  The caller holds
 * wifi_mutex and deals with the 'known' flag.  If the expected WLAN is NULL,
 * then we expect to be connected to just "any" (autoconf) network.
 */
static boolean_t
update_connected_wlan(wireless_if_t *wip, struct wireless_lan *exp_wlan)
{
	dladm_wlan_linkattr_t attr;
	struct wireless_lan *wlan, *lastconn, *newconn;
	char essid[DLADM_STRSIZE];
	char bssid[DLADM_STRSIZE];
	boolean_t connected, wasconn;

	if (dladm_wlan_get_linkattr(dld_handle, wip->wi_linkid, &attr) !=
	    DLADM_STATUS_OK)
		attr.la_status = DLADM_WLAN_LINK_DISCONNECTED;
	if (attr.la_status == DLADM_WLAN_LINK_CONNECTED) {
		(void) dladm_wlan_essid2str(&attr.la_wlan_attr.wa_essid, essid);
		(void) dladm_wlan_bssid2str(&attr.la_wlan_attr.wa_bssid, bssid);
		connected = B_TRUE;
		wip->wi_wireless_done = B_TRUE;
		dprintf("update: %s reports connection to %s %s", wip->wi_name,
		    essid, bssid);
	} else {
		connected = B_FALSE;
		dprintf("update: %s is currently unconnected", wip->wi_name);
	}

	/*
	 * First, verify that if we're connected, then we should be and that
	 * we're connected to the expected AP.
	 */
	if (exp_wlan != NULL) {
		/*
		 * If we're connected to the wrong one, then disconnect.  Note:
		 * we'd like to verify BSSID, but we cannot due to CR 6772510.
		 */
		if (connected && strcmp(exp_wlan->essid, essid) != 0) {
			dprintf("update: wrong AP on %s; expected %s %s",
			    exp_wlan->wl_if_name, exp_wlan->essid,
			    exp_wlan->bssid);
			(void) dladm_wlan_disconnect(dld_handle,
			    wip->wi_linkid);
			connected = B_FALSE;
		}
		/* If we're not in the expected state, then report disconnect */
		if (exp_wlan->connected != connected) {
			exp_wlan->connected = B_FALSE;
			if (connected) {
				dprintf("update: unexpected connection to %s "
				    "%s; clearing", essid, bssid);
				(void) dladm_wlan_disconnect(dld_handle,
				    wip->wi_linkid);
			} else {
				dprintf("update: not connected to %s %s as "
				    "expected", exp_wlan->essid,
				    exp_wlan->bssid);
				report_wlan_disconnect(exp_wlan);
			}
			connected = B_FALSE;
		}
	}

	/*
	 * State is now known to be good, so make the list entries match.
	 */
	wasconn = B_FALSE;
	lastconn = newconn = NULL;
	for (wlan = wlans; wlan < wlans + wireless_lan_used; wlan++) {
		if (strcmp(wlan->wl_if_name, wip->wi_name) != 0)
			continue;
		/* missing bssid check */
		if (connected && strcmp(wlan->essid, essid) == 0) {
			wasconn = wlan->connected;
			wlan->connected = connected;
			newconn = wlan;
		} else if (wlan->connected) {
			lastconn = wlan;
			wlan->connected = B_FALSE;
		}
	}
	if (newconn == NULL && connected) {
		newconn = add_wlan_entry(wip->wi_name, essid, bssid,
		    &attr.la_wlan_attr);
		if (newconn != NULL)
			newconn->connected = connected;
	}
	if (lastconn != NULL)
		report_wlan_disconnect(lastconn);
	if (newconn != NULL && !wasconn && connected)
		report_wlan_connected(newconn);
	return (connected);
}

/*
 * If there is already a scan or connect in progress, defer until the operation
 * is done to avoid radio interference *and* significant driver bugs.
 *
 * Returns B_TRUE when the lock is taken and the caller must call
 * scanconnect_exit.  Returns B_FALSE when lock not taken; caller must not call
 * scanconnect_exit.
 *
 * If we happen to be doing a scan, and the interface doing the scan is the
 * same as the one requesting a new scan, then wait for it to finish, and then
 * report that we're done by returning B_FALSE (no lock taken).
 */
static boolean_t
scanconnect_entry(const char *ifname, boolean_t is_connect)
{
	boolean_t already_done;

	if (pthread_mutex_lock(&wifi_init_mutex) != 0)
		return (B_FALSE);
	already_done = B_FALSE;
	while (wifi_scan_intf != NULL) {
		dprintf("%s in progress on %s; blocking %s of %s",
		    connect_running ? "connect" : "scan", wifi_scan_intf,
		    is_connect ? "connect" : "scan", ifname);
		if (!is_connect && !connect_running &&
		    strcmp(wifi_scan_intf, ifname) == 0)
			already_done = B_TRUE;
		(void) pthread_cond_wait(&wifi_init_cond, &wifi_init_mutex);
		if (already_done || shutting_down) {
			(void) pthread_mutex_unlock(&wifi_init_mutex);
			return (B_FALSE);
		}
	}
	dprintf("now exclusively %s on %s",
	    is_connect ? "connecting" : "scanning", ifname);
	wifi_scan_intf = ifname;
	connect_running = is_connect;
	(void) pthread_mutex_unlock(&wifi_init_mutex);
	return (B_TRUE);
}

static void
scanconnect_exit(void)
{
	(void) pthread_mutex_lock(&wifi_init_mutex);
	dprintf("done exclusively %s on %s",
	    connect_running ? "connecting" : "scanning", wifi_scan_intf);
	wifi_scan_intf = NULL;
	(void) pthread_cond_broadcast(&wifi_init_cond);
	(void) pthread_mutex_unlock(&wifi_init_mutex);
}

/*
 * Return B_TRUE if we're in the midst of connecting on a given wireless
 * interface.  We shouldn't try to take such an interface down.
 */
static boolean_t
connecting_on(const char *ifname)
{
	boolean_t in_progress;

	if (pthread_mutex_lock(&wifi_init_mutex) != 0)
		return (B_FALSE);
	in_progress = (wifi_scan_intf != NULL && connect_running &&
	    strcmp(ifname, wifi_scan_intf) == 0);
	(void) pthread_mutex_unlock(&wifi_init_mutex);
	return (in_progress);
}

/*
 * Terminate all waiting transient threads as soon as possible.  This assumes
 * that the shutting_down flag has already been set.
 */
void
terminate_wireless(void)
{
	(void) pthread_cond_broadcast(&wifi_init_cond);
}

/*
 * Given a wireless interface, use it to scan for available networks.  The
 * caller must not hold wifi_mutex.
 */
static void
scan_wireless_nets(const char *ifname)
{
	boolean_t	dropped;
	boolean_t	new_found;
	dladm_status_t	status;
	int		i;
	datalink_id_t	linkid;
	wireless_if_t	*wip;

	/*
	 * Wait for scan/connect to finish, and return if error or if this
	 * interface is already done.
	 */
	if (!scanconnect_entry(ifname, B_FALSE))
		return;

	/* Grab the linkid from the wireless interface */
	if (pthread_mutex_lock(&wifi_mutex) != 0)
		goto scan_end;
	if ((wip = find_wireless_if(ifname)) == NULL) {
		(void) pthread_mutex_unlock(&wifi_mutex);
		dprintf("aborted scan on %s; unable to locate interface",
		    ifname);
		goto scan_end;
	}
	linkid = wip->wi_linkid;
	(void) pthread_mutex_unlock(&wifi_mutex);

	/*
	 * Since only one scan is allowed at any one time, and only scans can
	 * modify the list, there's no need to grab a lock in checking
	 * wireless_lan_used or the wlans list itself, or for the new_ap_found
	 * global.
	 *
	 * All other threads must hold the mutex when reading this data, and
	 * this thread must hold the mutex only when writing portions that
	 * those other threads may read.
	 */
	for (i = 0; i < wireless_lan_used; i++)
		wlans[i].scanned = B_FALSE;
	new_ap_found = B_FALSE;
	dprintf("starting scan on %s", ifname);
	status = dladm_wlan_scan(dld_handle, linkid, (char *)ifname,
	    get_scan_results);
	if (status == DLADM_STATUS_OK) {
		dropped = clear_unscanned_entries(ifname);
	} else {
		dropped = B_FALSE;
		syslog(LOG_NOTICE, "cannot scan link '%s'", ifname);
	}

scan_end:
	/* Need to sample this global before clearing out scan lock */
	new_found = new_ap_found;

	/*
	 * Due to common driver bugs, it's necessary to check the state of the
	 * interface right after doing a scan.  If it's connected and we didn't
	 * expect it to be, or if we're accidentally connected to the wrong AP,
	 * then disconnect now and reconnect.
	 */
	if (pthread_mutex_lock(&wifi_mutex) == 0) {
		if ((wip = find_wireless_if(ifname)) != NULL) {
			dladm_wlan_linkattr_t attr;
			struct wireless_lan *wlan;
			char essid[DLADM_STRSIZE];
			char bssid[DLADM_STRSIZE];
			boolean_t connected;
			int retries = 0;

			wip->wi_scan_running = B_FALSE;

			/*
			 * This is awful, but some wireless drivers
			 * (particularly 'ath') will erroneously report
			 * "disconnected" if queried right after a scan.  If we
			 * see 'down' reported here, we retry a few times to
			 * make sure it's really down.
			 */
			while (retries++ < 4) {
				if (dladm_wlan_get_linkattr(dld_handle,
				    wip->wi_linkid, &attr) != DLADM_STATUS_OK)
					attr.la_status =
					    DLADM_WLAN_LINK_DISCONNECTED;
				else if (attr.la_status ==
				    DLADM_WLAN_LINK_CONNECTED)
					break;
			}
			if (attr.la_status == DLADM_WLAN_LINK_CONNECTED) {
				(void) dladm_wlan_essid2str(
				    &attr.la_wlan_attr.wa_essid, essid);
				(void) dladm_wlan_bssid2str(
				    &attr.la_wlan_attr.wa_bssid, bssid);
				connected = B_TRUE;
				dprintf("scan: %s reports connection to %s "
				    "%s", ifname, essid, bssid);
			} else {
				connected = B_FALSE;
				dprintf("scan: %s is currently unconnected",
				    ifname);
			}
			/* Disconnect from wrong AP first */
			for (wlan = wlans; wlan < wlans + wireless_lan_used;
			    wlan++) {
				if (strcmp(wlan->wl_if_name, ifname) != 0)
					continue;
				/* missing bssid check */
				if (strcmp(wlan->essid, essid) == 0) {
					/*
					 * This is the one we are currently
					 * connected to.  See if we should be
					 * here.
					 */
					if (!connected || !wlan->connected)
						(void) dladm_wlan_disconnect(
						    dld_handle, linkid);
					break;
				}
			}
			/* Connect to right AP by reporting disconnect */
			for (wlan = wlans; wlan < wlans + wireless_lan_used;
			    wlan++) {
				if (strcmp(wlan->wl_if_name, ifname) != 0)
					continue;
				if (wlan->connected) {
					/* missing bssid check */
					if (connected &&
					    strcmp(wlan->essid, essid) == 0)
						break;
					/*
					 * We weren't where we were supposed to
					 * be.  Try to reconnect now.
					 */
					(void) np_queue_add_event(EV_LINKDISC,
					    ifname);
				}
			}
		}
		(void) pthread_mutex_unlock(&wifi_mutex);
	}

	scanconnect_exit();

	if (status == DLADM_STATUS_OK)
		report_scan_complete(ifname, dropped || new_found, wlans,
		    wireless_lan_used);

	if (new_found) {
		dprintf("new AP added: %s", ifname);
		(void) np_queue_add_event(EV_NEWAP, ifname);
	}
}

/*
 * Rescan all wireless interfaces.  This routine intentionally does not hold
 * wifi_mutex during the scan, as scans can take a long time to accomplish, and
 * there may be more than one wireless interface.  The counter is used to make
 * sure that we don't run "forever" if the list is changing quickly.
 */
static void
rescan_wifi_no_lock(void)
{
	uint_t cnt = 0;
	wireless_if_t *wip;
	char ifname[LIFNAMSIZ];

	if (pthread_mutex_lock(&wifi_mutex) != 0)
		return;
	wip = (wireless_if_t *)wi_list.q_forw;
	while (cnt++ < wi_link_count && wip != (wireless_if_t *)&wi_list) {
		(void) strlcpy(ifname, wip->wi_name, sizeof (ifname));
		dprintf("periodic wireless scan: %s", ifname);
		/* Even less than "very weak" */
		wip->wi_strength = 0;
		wip->wi_scan_running = B_TRUE;
		(void) pthread_mutex_unlock(&wifi_mutex);

		scan_wireless_nets(ifname);

		if (pthread_mutex_lock(&wifi_mutex) != 0)
			return;
		if ((wip = find_wireless_if(ifname)) == NULL)
			wip = (wireless_if_t *)&wi_list;
		else
			wip = (wireless_if_t *)wip->wi_links.q_forw;
	}
	(void) pthread_mutex_unlock(&wifi_mutex);
}

/*
 * This thread is given the name of the interface to scan, and must free that
 * name when done.
 */
static void *
scan_thread(void *arg)
{
	char *ifname = arg;

	scan_wireless_nets(ifname);
	free(ifname);

	return (NULL);
}

/*
 * Launch a thread to scan the given wireless interface.  We copy the interface
 * name over to allocated storage because it's not possible to hand off a lock
 * on the interface list to the new thread, and the caller's storage (our input
 * argument) isn't guaranteed to be stable after we return to the caller.
 */
int
launch_wireless_scan(const char *ifname)
{
	int retv;
	wireless_if_t *wip;
	pthread_t if_thr;
	pthread_attr_t attr;
	char *winame;

	if ((winame = strdup(ifname)) == NULL)
		return (ENOMEM);

	if ((retv = pthread_mutex_lock(&wifi_mutex)) != 0) {
		free(winame);
		return (retv);
	}

	if ((wip = find_wireless_if(ifname)) == NULL) {
		retv = ENXIO;
	} else if (wip->wi_scan_running) {
		retv = EINPROGRESS;
	} else {
		(void) pthread_attr_init(&attr);
		(void) pthread_attr_setdetachstate(&attr,
		    PTHREAD_CREATE_DETACHED);
		retv = pthread_create(&if_thr, &attr, scan_thread, winame);
		if (retv == 0)
			wip->wi_scan_running = B_TRUE;
	}
	(void) pthread_mutex_unlock(&wifi_mutex);

	/* If thread not started, then discard the name. */
	if (retv != 0)
		free(winame);

	return (retv);
}

/*
 * Caller does not hold wifi_mutex.
 */
static boolean_t
get_scan_results(void *arg, dladm_wlan_attr_t *attrp)
{
	const char *ifname = arg;
	wireless_if_t *wip;
	struct wireless_lan *wlan;
	char		essid_name[DLADM_STRSIZE];
	char		bssid_name[DLADM_STRSIZE];
	boolean_t	retv;

	(void) dladm_wlan_essid2str(&attrp->wa_essid, essid_name);
	(void) dladm_wlan_bssid2str(&attrp->wa_bssid, bssid_name);

	/*
	 * Check whether ESSID is "hidden".
	 * If so try to substitute it with the ESSID from the
	 * known_wifi_nets with the same BSSID
	 */
	if (essid_name[0] == '\0') {
		if (known_wifi_nets_lookup(essid_name, bssid_name,
		    essid_name) &&
		    dladm_wlan_str2essid(essid_name, &attrp->wa_essid) ==
		    DLADM_STATUS_OK) {
			dprintf("Using ESSID %s with BSSID %s",
			    essid_name, bssid_name);
		}
	}

	if (pthread_mutex_lock(&wifi_mutex) != 0)
		return (B_FALSE);

	if ((wip = find_wireless_if(ifname)) == NULL) {
		(void) pthread_mutex_unlock(&wifi_mutex);
		return (B_FALSE);
	}

	/* Remember the strongest we encounter */
	if (attrp->wa_strength > wip->wi_strength)
		wip->wi_strength = attrp->wa_strength;

	wlan = find_wlan_entry(ifname, essid_name, bssid_name);
	if (wlan != NULL) {
		if (wlan->rescan)
			new_ap_found = B_TRUE;
		wlan->rescan = B_FALSE;
		wlan->scanned = B_TRUE;
		wlan->attrs = *attrp;
		retv = B_TRUE;
	} else if (add_wlan_entry(ifname, essid_name, bssid_name, attrp) !=
	    NULL) {
		retv = B_TRUE;
	} else {
		retv = B_FALSE;
	}
	(void) pthread_mutex_unlock(&wifi_mutex);
	return (retv);
}

/*
 * This is called when IP reports that the link layer is down.  It just
 * verifies that we're still connected as expected.  If not, then cover for the
 * known driver bugs (by disconnecting) and send an event so that we'll attempt
 * to recover.  No scan is done; if a scan is needed, we'll do one the next
 * time the timer pops.
 *
 * Note that we don't retry in case of error.  Since IP has reported the
 * interface as down, the best case here is that we detect a link failure and
 * start the connection process over again.
 */
void
wireless_verify(const char *ifname)
{
	datalink_id_t linkid;
	dladm_wlan_linkattr_t attr;
	wireless_if_t *wip;
	struct wireless_lan *wlan;
	boolean_t is_failure;

	/*
	 * If these calls fail, it means that the wireless link is down.
	 */
	if (dladm_name2info(dld_handle, ifname, &linkid, NULL, NULL, NULL) !=
	    DLADM_STATUS_OK ||
	    dladm_wlan_get_linkattr(dld_handle, linkid, &attr) !=
	    DLADM_STATUS_OK) {
		attr.la_status = DLADM_WLAN_LINK_DISCONNECTED;
	}

	/*
	 * If the link is down, then work around a known driver bug (by forcing
	 * disconnect), and then deliver an event so that the state machine can
	 * retry.
	 */
	if (attr.la_status != DLADM_WLAN_LINK_CONNECTED) {
		if (connecting_on(ifname))
			return;
		is_failure = B_TRUE;
		if (pthread_mutex_lock(&wifi_mutex) == 0) {
			if ((wip = find_wireless_if(ifname)) != NULL) {
				/*
				 * Link down while waiting for user to supply
				 * key is *not* a failure case.
				 */
				if (!wip->wi_wireless_done &&
				    wip->wi_need_key) {
					is_failure = B_FALSE;
				} else {
					wip->wi_wireless_done = B_FALSE;
					wip->wi_need_key = B_FALSE;
				}
			}
			if (is_failure) {
				for (wlan = wlans;
				    wlan < wlans + wireless_lan_used; wlan++) {
					if (strcmp(wlan->wl_if_name, ifname) ==
					    0) {
						if (wlan->connected)
							report_wlan_disconnect(
							    wlan);
						wlan->connected = B_FALSE;
					}
				}
			}
			(void) pthread_mutex_unlock(&wifi_mutex);
		}
		if (is_failure) {
			dprintf("wireless check indicates disconnect");
			(void) dladm_wlan_disconnect(dld_handle, linkid);
			(void) np_queue_add_event(EV_LINKDISC, ifname);
		}
	}
}

/* ARGSUSED */
void *
periodic_wireless_scan(void *arg)
{
	for (;;) {
		int ret, intv;
		dladm_wlan_linkattr_t attr;
		char ifname[LIFNAMSIZ];
		libnwam_interface_type_t ift;
		datalink_id_t linkid;
		char essid[DLADM_STRSIZE];
		struct wireless_lan *wlan;

		/*
		 * Stop the scanning process if the user changes the interval
		 * to zero dynamically.  Reset the thread ID to a known-invalid
		 * value.  (Copy to a local variable to avoid race condition in
		 * case SIGINT hits between this test and the call to poll().)
		 */
		if ((intv = wlan_scan_interval) == 0) {
			dprintf("periodic wireless scan halted");
			break;
		}

		ret = poll(NULL, 0, intv * MILLISEC);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			syslog(LOG_INFO, "periodic_wireless_scan: poll failed");
			break;
		}

		/*
		 * Just one more check before doing a scan that might now be
		 * unwanted
		 */
		if (wlan_scan_interval == 0) {
			dprintf("periodic wireless scan halted");
			break;
		}

		/* Get current profile name, if any */
		llp_get_name_and_type(ifname, sizeof (ifname), &ift);

		/*
		 * We do a scan if
		 *
		 * 1. There is no active profile.  Or
		 * 2. Profile is wireless and we're not connected to the AP.  Or
		 * 3. The signal strength falls below a certain specified level.
		 */
		if (ifname[0] != '\0') {
			if (ift != IF_WIRELESS)
				continue;

			/*
			 * If these things fail, it means that our wireless
			 * link isn't viable.  Proceed in that way.
			 */
			if (dladm_name2info(dld_handle, ifname, &linkid, NULL,
			    NULL, NULL) != DLADM_STATUS_OK ||
			    dladm_wlan_get_linkattr(dld_handle, linkid,
			    &attr) != DLADM_STATUS_OK) {
				attr.la_status = DLADM_WLAN_LINK_DISCONNECTED;
				attr.la_wlan_attr.wa_strength = 0;
			}

			if (attr.la_status == DLADM_WLAN_LINK_CONNECTED &&
			    attr.la_wlan_attr.wa_strength >
			    wireless_scan_level) {
				/*
				 * Double-check the ESSID.  Some drivers
				 * (notably 'iwh') have a habit of randomly
				 * reconnecting themselves to APs that you
				 * never requested.
				 */
				(void) dladm_wlan_essid2str(
				    &attr.la_wlan_attr.wa_essid, essid);
				if (pthread_mutex_lock(&wifi_mutex) != 0)
					continue;
				for (wlan = wlans;
				    wlan < wlans + wireless_lan_used; wlan++) {
					if (wlan->connected &&
					    strcmp(wlan->wl_if_name, ifname) ==
					    0)
						break;
				}
				if (wlan >= wlans + wireless_lan_used ||
				    strcmp(wlan->essid, essid) == 0) {
					(void) pthread_mutex_unlock(
					    &wifi_mutex);
					continue;
				}
				dprintf("%s is connected to %s instead of %s",
				    ifname, essid, wlan->essid);
				(void) pthread_mutex_unlock(&wifi_mutex);
			}
		}

		/* Rescan the wireless interfaces */
		rescan_wifi_no_lock();

		if (ifname[0] != '\0') {
			wireless_if_t *wip;

			/*
			 * If we're still connected and there's nothing better
			 * around, then there's no point in switching now.
			 */
			if (pthread_mutex_lock(&wifi_mutex) != 0)
				continue;
			if ((wip = find_wireless_if(ifname)) != NULL) {
				if (attr.la_status ==
				    DLADM_WLAN_LINK_CONNECTED &&
				    wip->wi_strength <=
				    attr.la_wlan_attr.wa_strength) {
					(void) pthread_mutex_unlock(&
					    wifi_mutex);
					continue;
				}
				wip->wi_wireless_done = B_FALSE;
				wip->wi_need_key = B_FALSE;
			}
			(void) pthread_mutex_unlock(&wifi_mutex);

			/*
			 * Try to work around known driver bugs: if the driver
			 * says we're disconnected, then tell it to disconnect
			 * for sure.
			 */
			(void) dladm_wlan_disconnect(dld_handle, linkid);

			/*
			 * Tell the state machine that we've lost this link so
			 * that it can do something about the problem.
			 */
			(void) np_queue_add_event(
			    (attr.la_status == DLADM_WLAN_LINK_CONNECTED ?
			    EV_LINKFADE : EV_LINKDISC), ifname);
		}
	}
	scan = 0;
	(void) pthread_detach(pthread_self());
	return (NULL);
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

	dprintf("before: key_string_to_secobj_value: buf_len = %d", buf_len);
	if (buf_len == 0) {
		/* length zero means "delete" */
		return (0);
	}

	if (buf[buf_len - 1] == '\n')
		buf[--buf_len] = '\0';

	dprintf("after: key_string_to_secobj_value: buf_len = %d", buf_len);

	if (class == DLADM_SECOBJ_CLASS_WPA) {
		/*
		 * Per IEEE802.11i spec, the Pre-shared key (PSK) length should
		 * be between 8 and 63.
		 */
		if (buf_len < 8 || buf_len > 63) {
			syslog(LOG_ERR,
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
			syslog(LOG_ERR,
			    "key_string_to_secobj_value: invalid WEP key");
			return (-1);
		}
		break;
	case 12:
	case 28:	/* Hex key sizes, preceded by 0x */
		if (strncmp(buf, "0x", 2) != 0 ||
		    hexascii_to_octet(buf + 2, (uint_t)buf_len - 2, obj_val,
		    obj_lenp) != 0) {
			syslog(LOG_ERR,
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
 * Print the key name format into the appropriate field, then convert any ":"
 * characters to ".", as ":[1-4]" is the slot indicator, which otherwise
 * would trip us up.  Invalid characters for secobj names are ignored.
 * The fourth parameter is expected to be of size DLADM_SECOBJ_NAME_MAX.
 *
 * (Note that much of the system uses DLADM_WLAN_MAX_KEYNAME_LEN, which is 64
 * rather than 32, but that dladm_get_secobj will fail if a length greater than
 * DLD_SECOBJ_NAME_MAX is seen, and that's 32.  This is all horribly broken.)
 */
static void
set_key_name(const char *essid, const char *bssid, char *name, size_t nsz)
{
	int i, j;
	char secobj_name[DLADM_WLAN_MAX_KEYNAME_LEN];

	/* create a concatenated string with essid and bssid */
	if (bssid[0] == '\0') {
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

static int
store_key(struct wireless_lan *wlan)
{
	uint8_t obj_val[DLADM_SECOBJ_VAL_MAX];
	uint_t obj_len = sizeof (obj_val);
	char obj_name[DLADM_SECOBJ_NAME_MAX];
	dladm_status_t status;
	char errmsg[DLADM_STRSIZE];
	dladm_secobj_class_t class;

	/*
	 * Name key object for this WLAN so it can be later retrieved
	 * (name is unique for each ESSID/BSSID combination).
	 */
	set_key_name(wlan->essid, wlan->bssid, obj_name, sizeof (obj_name));
	dprintf("store_key: obj_name is %s", obj_name);

	class = (wlan->attrs.wa_secmode == DLADM_WLAN_SECMODE_WEP ?
	    DLADM_SECOBJ_CLASS_WEP : DLADM_SECOBJ_CLASS_WPA);
	if (key_string_to_secobj_value(wlan->raw_key, obj_val, &obj_len,
	    class) != 0) {
		/* above function logs internally on failure */
		return (-1);
	}

	/* we've validated the new key, so remove the old one */
	status = dladm_unset_secobj(dld_handle, obj_name,
	    DLADM_OPT_ACTIVE | DLADM_OPT_PERSIST);
	if (status != DLADM_STATUS_OK && status != DLADM_STATUS_NOTFOUND) {
		syslog(LOG_ERR, "store_key: could not remove old secure object "
		    "'%s' for key: %s", obj_name,
		    dladm_status2str(status, errmsg));
		return (-1);
	}

	/* if we're just deleting the key, then we're done */
	if (wlan->raw_key[0] == '\0')
		return (0);

	status = dladm_set_secobj(dld_handle, obj_name, class,
	    obj_val, obj_len,
	    DLADM_OPT_CREATE | DLADM_OPT_PERSIST | DLADM_OPT_ACTIVE);
	if (status != DLADM_STATUS_OK) {
		syslog(LOG_ERR, "store_key: could not create secure object "
		    "'%s' for key: %s", obj_name,
		    dladm_status2str(status, errmsg));
		return (-1);
	}
	/*
	 * We don't really need to retrieve the key we just stored, but
	 * we do need to set the cooked key, and the function below takes
	 * care of allocating memory and setting the length and slot ID
	 * besides just copying the value, so it is simpler just to call
	 * the retrieve function instead of doing it all here.
	 *
	 * Since we just stored the key, retrieve_key() "shouldn't"
	 * fail.  If it does fail, it's not the end of the world; a NULL
	 * value for wlan->cooked_key simply means this particular
	 * attempt to connect will fail, and alternative connection
	 * options will be used.
	 */
	wlan->cooked_key = retrieve_key(wlan->essid, wlan->bssid, class);
	return (0);
}

/*
 * retrieve_key returns NULL if no key was recovered from libdladm
 */
static dladm_wlan_key_t *
retrieve_key(const char *essid, const char *bssid, dladm_secobj_class_t req)
{
	dladm_status_t status;
	char errmsg[DLADM_STRSIZE];
	dladm_wlan_key_t *cooked_key;
	dladm_secobj_class_t class;

	/*
	 * Newly-allocated key must be freed by caller, or by
	 * subsequent call to retrieve_key().
	 */
	if ((cooked_key = malloc(sizeof (dladm_wlan_key_t))) == NULL) {
		syslog(LOG_ERR, "retrieve_key: malloc failed");
		return (NULL);
	}

	/*
	 * Set name appropriately to retrieve key for this WLAN.  Note that we
	 * cannot use the actual wk_name buffer size, as it's two times too
	 * large for dladm_get_secobj.
	 */
	set_key_name(essid, bssid, cooked_key->wk_name, DLADM_SECOBJ_NAME_MAX);
	dprintf("retrieve_key: len = %d, object = %s\n",
	    strlen(cooked_key->wk_name), cooked_key->wk_name);
	cooked_key->wk_len = sizeof (cooked_key->wk_val);
	cooked_key->wk_idx = 1;

	/* Try the kernel first, then fall back to persistent storage. */
	status = dladm_get_secobj(dld_handle, cooked_key->wk_name, &class,
	    cooked_key->wk_val, &cooked_key->wk_len,
	    DLADM_OPT_ACTIVE);
	if (status != DLADM_STATUS_OK) {
		dprintf("retrieve_key: dladm_get_secobj(TEMP) failed: %s",
		    dladm_status2str(status, errmsg));
		status = dladm_get_secobj(dld_handle, cooked_key->wk_name,
		    &class, cooked_key->wk_val, &cooked_key->wk_len,
		    DLADM_OPT_PERSIST);
	}

	switch (status) {
	case DLADM_STATUS_OK:
		dprintf("retrieve_key: dladm_get_secobj succeeded: len %d",
		    cooked_key->wk_len);
		break;
	case DLADM_STATUS_NOTFOUND:
		/*
		 * We do not want an error in the case that the secobj
		 * is not found, since we then prompt for it.
		 */
		free(cooked_key);
		return (NULL);
	default:
		syslog(LOG_ERR, "retrieve_key: could not get key "
		    "from secure object '%s': %s", cooked_key->wk_name,
		    dladm_status2str(status, errmsg));
		free(cooked_key);
		return (NULL);
	}

	if (class != req) {	/* the key mismatch */
		syslog(LOG_ERR, "retrieve_key: key type mismatch"
		    " from secure object '%s'", cooked_key->wk_name);
		free(cooked_key);
		return (NULL);
	}

	return (cooked_key);
}

/*
 * Add an entry to known_wifi_nets file given the parameters.  The caller holds
 * wifi_mutex.
 */
static int
add_known_wifi_nets_file(const char *essid, const char *bssid)
{
	int retv;
	FILE *fp = NULL;

	dprintf("add_known_wifi_nets_file(%s, %s)", essid, bssid);

	/* Create the NWAM directory in case it does not exist. */
	if (mkdir(LLPDIRNAME, LLPDIRMODE) != 0 &&
	    errno != EEXIST) {
		retv = errno;
		syslog(LOG_ERR, "could not create %s: %m", LLPDIRNAME);
	} else if ((fp = fopen(KNOWN_WIFI_NETS, "a+")) == NULL) {
		retv = errno;
		syslog(LOG_ERR, "fopen(%s) failed: %m", KNOWN_WIFI_NETS);
	} else if (known_wifi_nets_lookup(essid, bssid, NULL)) {
		retv = EEXIST;
	} else {
		/* now add this to the file */
		(void) fprintf(fp, "%s\t%s\n", essid, bssid);
		retv = 0;
	}
	if (fp != NULL)
		(void) fclose(fp);
	return (retv);
}

static int
delete_known_wifi_nets_file(const char *essid, const char *bssid)
{
	FILE *fpin, *fpout;
	char line[LINE_MAX];
	char *cp;
	int retv;
	size_t essidlen, bssidlen;
	boolean_t found;

	if ((fpin = fopen(KNOWN_WIFI_NETS, "r")) == NULL)
		return (errno);

	if ((fpout = fopen(KNOWN_WIFI_TMP, "w")) == NULL) {
		retv = errno;
		(void) fclose(fpin);
		return (retv);
	}

	found = B_FALSE;
	essidlen = strlen(essid);
	bssidlen = strlen(bssid);
	while (fgets(line, sizeof (line), fpin) != NULL) {
		cp = line;
		while (isspace(*cp))
			cp++;

		if (*cp == '#' || *cp == '\0' ||
		    strncmp(essid, cp, essidlen) != 0 ||
		    (cp[essidlen] != '\0' && !isspace(cp[essidlen]))) {
			(void) fputs(line, fpout);
			continue;
		}

		/* skip over the essid to examine bssid */
		while (*cp != '\0' && !isspace(*cp))
			cp++;
		while (isspace(*cp))
			cp++;

		/*
		 * Deleting with bssid empty means "all entries under this
		 * essid."  As a result, deleting a wildcard entry for a bssid
		 * means deleting all entries for that bssid.
		 */

		if (bssidlen == 0 ||
		    (strncmp(bssid, cp, bssidlen) == 0 &&
		    (cp[bssidlen] == '\0' || isspace(cp[bssidlen])))) {
			/* delete this entry */
			found = B_TRUE;
			continue;
		}

		(void) fputs(line, fpout);
	}

	(void) fclose(fpin);
	(void) fclose(fpout);

	if (found) {
		if (rename(KNOWN_WIFI_TMP, KNOWN_WIFI_NETS) == 0) {
			retv = 0;
		} else {
			retv = errno;
			(void) unlink(KNOWN_WIFI_TMP);
		}
	} else {
		retv = ENXIO;
		(void) unlink(KNOWN_WIFI_TMP);
	}

	return (retv);
}

/*
 * Check if the given AP (ESSID, BSSID pair) is on the known AP list.
 * If found_essid is non-NULL and the match is found (B_TRUE is returned)
 * the matched ESSID is copied out into buffer pointed by found_essid.
 * The buffer is expected to be at least DLADM_STRSIZE bytes long.
 */
static boolean_t
known_wifi_nets_lookup(const char *new_essid, const char *new_bssid,
    char *found_essid)
{
	FILE *fp;
	char line[LINE_MAX];
	char *cp;
	char *tok[MAX_FIELDS];
	int line_num;
	boolean_t found = B_FALSE;

	/*
	 * For now the file format is:
	 * essid\tbssid
	 * (essid followed by tab followed by bssid)
	 */
	fp = fopen(KNOWN_WIFI_NETS, "r");
	if (fp == NULL)
		return (B_FALSE);
	for (line_num = 1; fgets(line, sizeof (line), fp) != NULL; line_num++) {

		cp = line;
		while (isspace(*cp))
			cp++;

		if (*cp == '#' || *cp == '\0')
			continue;

		if (bufsplit(cp, MAX_FIELDS, tok) != MAX_FIELDS) {
			syslog(LOG_ERR, "%s:%d: wrong number of tokens; "
			    "ignoring entry", KNOWN_WIFI_NETS, line_num);
			continue;
		}

		/*
		 * If we're searching on ESSID alone, then any match on a
		 * specific ESSID will do.
		 */
		if (*new_bssid == '\0') {
			if (*new_essid != '\0' &&
			    strcmp(tok[ESSID], new_essid) == 0) {
				found = B_TRUE;
				break;
			}
		}
		/*
		 * If BSSID match is found we check ESSID, which should
		 * either match as well, or be an empty string.
		 * In latter case we'll retrieve the ESSID from known_wifi_nets
		 * later.
		 */
		else if (strcmp(tok[BSSID], new_bssid) == 0) {
			/*
			 * Got BSSID match, either ESSID was not specified,
			 * or it should match
			 */
			if (*new_essid == '\0' ||
			    strcmp(tok[ESSID], new_essid) == 0) {
				found = B_TRUE;
				break;
			}
		}
	}

	if (found) {
		if (found_essid != NULL)
			(void) strlcpy(found_essid, tok[ESSID], DLADM_STRSIZE);
	}

	(void) fclose(fp);
	return (found);
}

static uint_t
extract_known_aps(FILE *fp, libnwam_known_ap_t *kap, char *sbuf, size_t *totstr)
{
	char line[LINE_MAX];
	char *cp;
	char *tok[MAX_FIELDS];
	size_t accstr = 0;
	uint_t count = 0;
	char key[DLADM_SECOBJ_NAME_MAX];
	uint8_t keyval[DLADM_SECOBJ_VAL_MAX];
	dladm_secobj_class_t class;
	uint_t keylen;

	while (fgets(line, sizeof (line), fp) != NULL) {
		cp = line;
		while (isspace(*cp))
			cp++;

		if (*cp == '#' || *cp == '\0')
			continue;

		if (bufsplit(cp, MAX_FIELDS, tok) != MAX_FIELDS)
			continue;

		if (totstr != NULL)
			accstr += strlen(tok[BSSID]) + strlen(tok[ESSID]) + 2;
		count++;

		if (kap != NULL) {
			kap->ka_essid = strcpy(sbuf, tok[ESSID]);
			sbuf += strlen(sbuf) + 1;
			kap->ka_bssid = strcpy(sbuf, tok[BSSID]);
			sbuf += strlen(sbuf) + 1;
			set_key_name(tok[ESSID], tok[BSSID], key, sizeof (key));
			keylen = sizeof (keyval);
			if (dladm_get_secobj(dld_handle, key, &class, keyval,
			    &keylen, DLADM_OPT_ACTIVE) == DLADM_STATUS_OK)
				kap->ka_haskey = B_TRUE;
			else
				kap->ka_haskey = B_FALSE;
			kap++;
		}
	}
	if (totstr != NULL)
		*totstr = accstr;
	return (count);
}

libnwam_known_ap_t *
get_known_ap_list(size_t *kasizep, uint_t *countp)
{
	FILE *fp;
	libnwam_known_ap_t *kap = NULL;
	size_t kasize;
	uint_t count;
	int retv;

	if ((retv = pthread_mutex_lock(&wifi_mutex)) != 0) {
		errno = retv;
		return (kap);
	}
	if ((fp = fopen(KNOWN_WIFI_NETS, "r")) != NULL) {
		count = extract_known_aps(fp, NULL, NULL, &kasize);
		rewind(fp);
		kasize += count * sizeof (*kap);
		if (count != 0 && (kap = malloc(kasize)) != NULL) {
			(void) extract_known_aps(fp, kap, (char *)(kap + count),
			    NULL);
			*kasizep = kasize;
			*countp = count;
		}
		(void) fclose(fp);
	}
	(void) pthread_mutex_unlock(&wifi_mutex);
	return (kap);
}

int
add_known_ap(const char *essid, const char *bssid)
{
	int retv;
	char ifname[LIFNAMSIZ];
	libnwam_interface_type_t ift;
	struct wireless_lan *wlan, *savedwlan;

	/*
	 * First check the current LLP.  If there is one, then its connection
	 * state determines what to do after adding the known AP to the list.
	 * If not, then we act if there are no connected APs.
	 */
	llp_get_name_and_type(ifname, sizeof (ifname), &ift);

	if ((retv = pthread_mutex_lock(&wifi_mutex)) != 0)
		return (retv);

	retv = add_known_wifi_nets_file(essid, bssid);
	if (retv == 0 && (ift == IF_UNKNOWN || ift == IF_WIRELESS)) {
		boolean_t any_connected, one_matches;

		/*
		 * If this is in our list of scanned APs and if no interface is
		 * connected, then we have a reevaluation event.
		 */
		any_connected = one_matches = B_FALSE;
		for (wlan = wlans; wlan < wlans + wireless_lan_used;
		    wlan++) {
			/*
			 * If LLP is selected, then ignore all others.  Only
			 * the state of this one interface is at issue.
			 */
			if (ifname[0] != '\0' &&
			    strcmp(ifname, wlan->wl_if_name) != 0)
				continue;
			if (wlan->connected)
				any_connected = B_TRUE;
			if (strcmp(essid, wlan->essid) == 0 &&
			    (bssid[0] == '\0' ||
			    strcmp(bssid, wlan->bssid) == 0)) {
				one_matches = B_TRUE;
				savedwlan = wlan;
			}
		}
		if (!any_connected && one_matches) {
			(void) np_queue_add_event(EV_RESELECT,
			    savedwlan->wl_if_name);
		}
	}
	(void) pthread_mutex_unlock(&wifi_mutex);
	return (retv);
}

int
delete_known_ap(const char *essid, const char *bssid)
{
	int retv;
	struct wireless_lan *wlan;
	wireless_if_t *wip;

	if ((retv = pthread_mutex_lock(&wifi_mutex)) != 0)
		return (retv);

	retv = delete_known_wifi_nets_file(essid, bssid);
	if (retv == 0) {
		for (wlan = wlans; wlan < wlans + wireless_lan_used;
		    wlan++) {
			if (wlan->connected &&
			    strcmp(essid, wlan->essid) == 0 &&
			    (bssid[0] == '\0' ||
			    strcmp(bssid, wlan->bssid) == 0)) {
				wlan->connected = B_FALSE;
				report_wlan_disconnect(wlan);
				wip = find_wireless_if(wlan->wl_if_name);
				if (wip != NULL) {
					wip->wi_wireless_done = B_FALSE;
					wip->wi_need_key = B_FALSE;
					(void) dladm_wlan_disconnect(dld_handle,
					    wip->wi_linkid);
				}
				(void) np_queue_add_event(EV_RESELECT,
				    wlan->wl_if_name);
			}
		}
	}
	(void) pthread_mutex_unlock(&wifi_mutex);
	return (retv);
}

/*
 * reqlan->essid is required (i.e., cannot be zero-length)
 * reqlan->bssid is optional (i.e., may be zero-length)
 */
static return_vals_t
connect_chosen_lan(struct wireless_lan *reqlan, wireless_if_t *wip)
{
	uint_t	keycount;
	dladm_wlan_key_t *key;
	dladm_wlan_attr_t attr;
	dladm_status_t status;
	uint_t flags = DLADM_WLAN_CONNECT_NOSCAN;
	int timeout = DLADM_WLAN_CONNECT_TIMEOUT_DEFAULT;
	char errmsg[DLADM_STRSIZE];
	return_vals_t rval;

	wip->wi_need_key = B_FALSE;

	(void) memset(&attr, 0, sizeof (attr));
	/* try to apply essid selected by the user */
	if (reqlan->essid == NULL)
		return (FAILURE);
	dprintf("connect_chosen_lan(%s, %s, %s)", reqlan->essid,
	    reqlan->bssid, wip->wi_name);

	/* If it is already connected to the required AP, just return. */
	if (check_wlan(wip, reqlan->essid, NULL, B_TRUE))
		return (SUCCESS);

	if (dladm_wlan_str2essid(reqlan->essid, &attr.wa_essid) !=
	    DLADM_STATUS_OK) {
		syslog(LOG_ERR,
		    "connect_chosen_lan: invalid ESSID '%s' for '%s'",
		    reqlan->essid, wip->wi_name);
		return (FAILURE);
	}
	attr.wa_valid = DLADM_WLAN_ATTR_ESSID;

	/* note: bssid logic here is non-functional */
	if (reqlan->bssid[0] != '\0') {
		if (dladm_wlan_str2bssid(reqlan->bssid, &attr.wa_bssid) !=
		    DLADM_STATUS_OK) {
			syslog(LOG_ERR,
			    "connect_chosen_lan: invalid BSSID '%s' for '%s'",
			    reqlan->bssid, wip->wi_name);
			return (FAILURE);
		}
		attr.wa_valid |= DLADM_WLAN_ATTR_BSSID;
	}

	/* First check for the key */
	if (NEED_ENC(reqlan->attrs.wa_secmode)) {
		/* Note that this happens only for known APs from the list */
		if ((rval = get_user_key(reqlan)) != SUCCESS) {
			if (rval == WAITING)
				wip->wi_need_key = B_TRUE;
			return (rval);
		}
		attr.wa_valid |= DLADM_WLAN_ATTR_SECMODE;
		attr.wa_secmode = reqlan->attrs.wa_secmode;
		key = reqlan->cooked_key;
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

	status = dladm_wlan_connect(dld_handle, wip->wi_linkid, &attr, timeout,
	    key, keycount, flags);
	dprintf("connect_chosen_lan: dladm_wlan_connect returned %s",
	    dladm_status2str(status, errmsg));
	/*
	 * This doesn't work due to CR 6772510.
	 */
#ifdef CR6772510_FIXED
	if (status == DLADM_STATUS_TIMEDOUT && reqlan->bssid[0] != '\0') {
		syslog(LOG_INFO, "connect_chosen_lan: failed for (%s, %s), "
		    "trying again with just (%s)",
		    reqlan->essid, reqlan->bssid, reqlan->essid);
		attr.wa_valid &= ~DLADM_WLAN_ATTR_BSSID;
		flags = 0;
		status = dladm_wlan_connect(dld_handle, wip->wi_linkid, &attr,
		    timeout, key, keycount, flags);
	}
#endif /* CR6772510_FIXED */
	if (status == DLADM_STATUS_OK) {
		return (SUCCESS);
	} else {
		syslog(LOG_ERR,
		    "connect_chosen_lan: connect to '%s' failed on '%s': %s",
		    reqlan->essid, wip->wi_name,
		    dladm_status2str(status, errmsg));
		return (FAILURE);
	}
}

/*
 * Check that the wireless LAN is connected to the desired ESSID/BSSID.  This
 * is used by the GUI to check for connectivity before doing anything
 * destructive.
 */
boolean_t
check_wlan_connected(const char *ifname, const char *essid, const char *bssid)
{
	wireless_if_t *wip;
	boolean_t retv;

	if (pthread_mutex_lock(&wifi_mutex) != 0)
		return (B_FALSE);

	if ((wip = find_wireless_if(ifname)) == NULL) {
		retv = B_FALSE;
	} else {
		if (essid[0] == '\0' && bssid[0] == '\0')
			essid = NULL;
		retv = check_wlan(wip, essid, bssid, B_FALSE);
	}
	(void) pthread_mutex_unlock(&wifi_mutex);
	return (retv);
}

/*
 * This thread performs the blocking actions related to a wireless connection
 * request.  The attempt to connect isn't started until all other connects and
 * scans have finished, and while the connect is in progress, no new connects
 * or scans can be started.
 */
static void *
connect_thread(void *arg)
{
	struct wireless_lan *req_wlan = arg;
	wireless_if_t *wip;
	struct wireless_lan *wlan = NULL;

	if (!scanconnect_entry(req_wlan->wl_if_name, B_TRUE))
		goto failure_noentry;

	if (pthread_mutex_lock(&wifi_mutex) != 0)
		goto failure_unlocked;

	if ((wip = find_wireless_if(req_wlan->wl_if_name)) == NULL)
		goto failure;

	/* This is an autoconf request. */
	if (req_wlan->essid[0] == '\0' && req_wlan->bssid[0] == '\0') {
		if (!wlan_autoconf(wip) && !update_connected_wlan(wip, NULL))
			goto failure;
		else
			goto done;
	}

	wlan = find_wlan_entry(req_wlan->wl_if_name, req_wlan->essid,
	    req_wlan->bssid);
	if (wlan == NULL)
		wlan = req_wlan;

	/*
	 * now attempt to connect to selection
	 */
	switch (connect_chosen_lan(wlan, wip)) {
	case WAITING:
		break;

	case SUCCESS: {
		dladm_status_t		status;
		dladm_wlan_linkattr_t	attr;
		char			lclssid[DLADM_STRSIZE];
		char			unnecessary_buf[DLADM_STRSIZE];

		/*
		 * Successful connection to user-chosen AP; add entry to
		 * known_essid_list_file.  First make sure the wlan->bssid
		 * isn't empty.  Note that empty bssid is never allocated.
		 *
		 * We would like to query the driver only in the case where the
		 * BSSID is not known, but it turns out that due to CR 6772510,
		 * the actual BSSID we connect to is arbitrary.  Nothing we can
		 * do about that; just get the new value and live with it.
		 */
		status = dladm_wlan_get_linkattr(dld_handle, wip->wi_linkid,
		    &attr);
		if (status != DLADM_STATUS_OK) {
			dprintf("failed to get linkattr on %s after connecting "
			    "to %s: %s", wlan->wl_if_name, wlan->essid,
			    dladm_status2str(status, unnecessary_buf));
			goto failure;
		}
		(void) dladm_wlan_essid2str(&attr.la_wlan_attr.wa_essid,
		    lclssid);
		if (strcmp(req_wlan->essid, lclssid) != 0) {
			dprintf("connected to strange network: expected %s got "
			    "%s", req_wlan->essid, lclssid);
			goto failure;
		}
		(void) dladm_wlan_bssid2str(&attr.la_wlan_attr.wa_bssid,
		    lclssid);
		if (wlan == req_wlan || strcmp(wlan->bssid, lclssid) != 0) {
			wlan = add_wlan_entry(req_wlan->wl_if_name,
			    req_wlan->essid, lclssid, &attr.la_wlan_attr);
			if (wlan == NULL)
				goto failure;
		}
		if (wlan->bssid[0] == '\0' && lclssid[0] != '\0')
			wlan->bssid = strdup(lclssid);
		if (wlan->bssid == NULL || wlan->bssid[0] == '\0') {
			/* Don't leave it as NULL (for simplicity) */
			wlan->bssid = "";
			goto failure;
		}
		wlan->connected = B_TRUE;
		if (!update_connected_wlan(wip, wlan))
			goto failure;
		wlan->known = B_TRUE;
		(void) add_known_wifi_nets_file(wlan->essid, wlan->bssid);
		/* We're done; trigger IP bring-up. */
		(void) np_queue_add_event(EV_RESELECT, wlan->wl_if_name);
		report_wlan_connected(wlan);
		break;
	}

	default:
		goto failure;
	}

done:
	(void) pthread_mutex_unlock(&wifi_mutex);
	scanconnect_exit();
	free_wireless_lan(req_wlan);
	return (NULL);

failure:
	/*
	 * Failed to connect.  Set 'rescan' flag so that we treat this AP as
	 * new if it's seen again, because the wireless radio may have just
	 * been off briefly while we were trying to connect.
	 */
	if (wip != NULL) {
		wip->wi_need_key = B_FALSE;
		wip->wi_wireless_done = B_FALSE;
		(void) dladm_wlan_disconnect(dld_handle, wip->wi_linkid);
	}
	if (wlan != NULL)
		wlan->rescan = B_TRUE;
	(void) pthread_mutex_unlock(&wifi_mutex);

failure_unlocked:
	scanconnect_exit();
failure_noentry:
	syslog(LOG_WARNING, "could not connect to chosen WLAN %s on %s",
	    req_wlan->essid, req_wlan->wl_if_name);
	report_wlan_connect_fail(req_wlan->wl_if_name);
	free_wireless_lan(req_wlan);
	return (NULL);
}

/*
 * This is the entry point for GUI "select access point" requests.  It verifies
 * the parameters and then launches a new thread to perform the connect
 * operation.  When it returns success (0), the user should expect future
 * events indicating progress.
 *
 * Returns:
 *	0	- ok (or more data requested with new event)
 *	ENXIO	- no such interface
 *	ENODEV	- interface is not wireless
 *	EINVAL	- failed to perform requested action
 */
int
set_specific_lan(const char *ifname, const char *essid, const char *bssid)
{
	libnwam_interface_type_t ift;
	pthread_t conn_thr;
	pthread_attr_t attr;
	struct wireless_lan *wlan;
	int retv;

	if ((ift = get_if_type(ifname)) == IF_UNKNOWN)
		return (ENXIO);
	if (ift != IF_WIRELESS)
		return (EINVAL);

	if ((wlan = calloc(1, sizeof (struct wireless_lan))) == NULL)
		return (ENOMEM);
	(void) strlcpy(wlan->wl_if_name, ifname, sizeof (wlan->wl_if_name));
	wlan->essid = strdup(essid);
	wlan->bssid = *bssid == '\0' ? "" : strdup(bssid);
	if (wlan->essid == NULL || wlan->bssid == NULL) {
		free_wireless_lan(wlan);
		return (ENOMEM);
	}
	(void) pthread_attr_init(&attr);
	(void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	retv = pthread_create(&conn_thr, &attr, connect_thread, wlan);
	if (retv == 0)
		dprintf("started connect thread %d for %s %s %s", conn_thr,
		    ifname, essid, bssid);
	else
		free_wireless_lan(wlan);
	return (retv);
}

int
set_wlan_key(const char *ifname, const char *essid, const char *bssid,
    const char *key, const char *secmode)
{
	libnwam_interface_type_t ift;
	struct wireless_lan *wlan, local_wlan;
	wireless_if_t *wip;
	int retv;
	boolean_t need_key;
	dladm_wlan_secmode_t smode = DLADM_WLAN_SECMODE_WEP;

	ift = get_if_type(ifname);
	if (ift == IF_UNKNOWN)
		return (ENXIO);
	if (ift != IF_WIRELESS)
		return (EINVAL);

	if (*secmode != '\0' &&
	    dladm_wlan_str2secmode(secmode, &smode) != DLADM_STATUS_OK)
		return (EINVAL);

	if ((retv = pthread_mutex_lock(&wifi_mutex)) != 0)
		return (retv);

	if ((wlan = find_wlan_entry(ifname, essid, bssid)) == NULL) {
		/* If not seen in scan, then secmode is required */
		if (*secmode == '\0') {
			retv = ENODEV;
			goto done;
		}
		/* Prohibit a completely blank entry */
		if (*essid == '\0' && *bssid == '\0') {
			retv = EINVAL;
			goto done;
		}
		(void) memset(&local_wlan, 0, sizeof (local_wlan));
		wlan = &local_wlan;
		(void) strlcpy(wlan->wl_if_name, ifname,
		    sizeof (wlan->wl_if_name));
		wlan->essid = (char *)essid;
		wlan->bssid = (char *)bssid;
		wlan->raw_key = (char *)key;
		wlan->attrs.wa_secmode = smode;
	} else {
		/* If seen in scan, then secmode given (if any) must match */
		if (*secmode != '\0' && smode != wlan->attrs.wa_secmode) {
			retv = EINVAL;
			goto done;
		}
		/* save a copy of the new key in the scan entry */
		if ((wlan->raw_key = strdup(key)) == NULL) {
			retv = ENOMEM;
			goto done;
		}
	}

	if (store_key(wlan) != 0)
		retv = EINVAL;
	else
		retv = 0;

done:
	wip = find_wireless_if(ifname);
	need_key = wip != NULL && wip->wi_need_key;
	(void) pthread_mutex_unlock(&wifi_mutex);

	if (retv == 0 && need_key)
		retv = set_specific_lan(ifname, essid, bssid);

	return (retv);
}

static boolean_t
wlan_autoconf(const wireless_if_t *wip)
{
	dladm_status_t status;
	boolean_t autoconf;

	if (lookup_boolean_property(OUR_PG, "autoconf", &autoconf) == 0) {
		if (!autoconf)
			return (B_FALSE);
	}

	/* If the NIC is already associated with something, just return. */
	if (check_wlan(wip, NULL, NULL, B_TRUE))
		return (B_TRUE);

	/*
	 * Do autoconf, relying on the heuristics used by dladm_wlan_connect()
	 * to cycle through WLANs detected in priority order, attempting
	 * to connect.
	 */
	status = dladm_wlan_connect(dld_handle, wip->wi_linkid, NULL,
	    DLADM_WLAN_CONNECT_TIMEOUT_DEFAULT, NULL, 0, 0);
	if (status != DLADM_STATUS_OK) {
		char errmsg[DLADM_STRSIZE];

		syslog(LOG_ERR,
		    "wlan_autoconf: dladm_wlan_connect failed for '%s': %s",
		    wip->wi_name, dladm_status2str(status, errmsg));
		return (B_FALSE);
	}
	return (B_TRUE);
}

/*
 * This function searches through the wlans[] array and determines which ones
 * have been visited before.
 *
 * If exactly one has been visited before, and it has the highest signal
 * strength, then we attempt to connect to it right away.
 *
 * In all other cases -- if none have been visited before, or more than one was
 * visited, or if the one that was visited doesn't have the highest signal
 * strength, or if the automatic connect attempt fails for any reason -- then
 * we hand over the data to the GUI for resolution.  The user will have to be
 * prompted for a choice.
 *
 * If no GUI exists, we'll get back FAILURE (instead of WAITING), which will
 * cause the autoconf mechanism to run instead.
 */
return_vals_t
handle_wireless_lan(const char *ifname)
{
	wireless_if_t *wip;
	struct wireless_lan *cur_wlan, *max_wlan;
	struct wireless_lan *most_recent;
	boolean_t many_present;
	dladm_wlan_strength_t strongest = DLADM_WLAN_STRENGTH_VERY_WEAK;
	return_vals_t connect_result = FAILURE;

	/*
	 * We wait while a scan or another connect is in progress, and then
	 * block other connects/scans.  Since we allow a user to initiate a
	 * re-scan, we can proceed even when no scan has yet been done to fill
	 * in the AP list.
	 */
	if (!scanconnect_entry(ifname, B_TRUE))
		return (FAILURE);

	if (pthread_mutex_lock(&wifi_mutex) != 0) {
		scanconnect_exit();
		return (FAILURE);
	}

	if ((wip = find_wireless_if(ifname)) == NULL)
		goto finished;

	if (wip->wi_wireless_done) {
		dprintf("handle_wireless_lan: skipping policy scan; done");
		/* special case; avoid interface update */
		(void) pthread_mutex_unlock(&wifi_mutex);
		scanconnect_exit();
		return (SUCCESS);
	}

	dprintf("handle_wireless_lan: starting policy scan");
	cur_wlan = wlans;
	max_wlan = wlans + wireless_lan_used;
	most_recent = NULL;
	many_present = B_FALSE;

	/*
	 * Try to see if any of the wifi nets currently available
	 * has been used previously. If more than one available
	 * nets has been used before, then prompt user with
	 * all the applicable previously wifi nets, and ask which
	 * one to connect to.
	 */
	for (; cur_wlan < max_wlan; cur_wlan++) {
		/* Find the AP with the highest signal. */
		if (cur_wlan->attrs.wa_strength > strongest)
			strongest = cur_wlan->attrs.wa_strength;

		if (known_wifi_nets_lookup(cur_wlan->essid, cur_wlan->bssid,
		    NULL))
			cur_wlan->known = B_TRUE;

		if (!cur_wlan->known && !strict_bssid &&
		    known_wifi_nets_lookup(cur_wlan->essid, "", NULL)) {
			dprintf("noticed new BSSID %s for ESSID %s on %s",
			    cur_wlan->bssid, cur_wlan->essid, ifname);
			if (add_known_wifi_nets_file(cur_wlan->essid,
			    cur_wlan->bssid) == 0)
				cur_wlan->known = B_TRUE;
		}

		if (cur_wlan->known || cur_wlan->connected) {
			/*
			 * The ESSID comparison here mimics what the "already
			 * in visited wlan list" function once did, but
			 * slightly better as we also pay attention to signal
			 * strength to pick the best of the duplicates.
			 */
			if (most_recent == NULL) {
				most_recent = cur_wlan;
			} else if (strcmp(cur_wlan->essid,
			    most_recent->essid) != 0) {
				many_present = B_TRUE;
			} else if (cur_wlan->attrs.wa_strength >
			    most_recent->attrs.wa_strength) {
				if (most_recent->connected) {
					(void) dladm_wlan_disconnect(dld_handle,
					    wip->wi_linkid);
					most_recent->connected = B_FALSE;
					report_wlan_disconnect(most_recent);
					wip->wi_wireless_done = B_FALSE;
				}
				most_recent = cur_wlan;
			}
		}

		/* Reset any security information we may have had. */
		free(cur_wlan->raw_key);
		cur_wlan->raw_key = NULL;
		free(cur_wlan->cooked_key);
		cur_wlan->cooked_key = NULL;
	}

	if (most_recent != NULL && !many_present &&
	    most_recent->attrs.wa_strength >= strongest) {
		if (most_recent->connected) {
			dprintf("%s already connected to %s", ifname,
			    most_recent->essid);
			connect_result = SUCCESS;
		} else {
			dprintf("%s connecting automatically to %s", ifname,
			    most_recent->essid);
			connect_result = connect_chosen_lan(most_recent, wip);
			switch (connect_result) {
			case FAILURE:
				report_wlan_connect_fail(wip->wi_name);
				most_recent->rescan = B_TRUE;
				syslog(LOG_WARNING, "could not connect to "
				    "chosen WLAN %s on %s, going to auto-conf",
				    most_recent->essid, ifname);
				connect_result = wlan_autoconf(wip) ? SUCCESS :
				    FAILURE;
				most_recent = NULL;
				break;
			case SUCCESS:
				most_recent->connected = B_TRUE;
				report_wlan_connected(most_recent);
				break;
			}
		}
	} else if (request_wlan_selection(ifname, wlans, wireless_lan_used)) {
		dprintf("%s is unknown and not connected; requested help",
		    ifname);
		connect_result = WAITING;
	} else {
		dprintf("%s has no connected AP or GUI; try auto", ifname);
		connect_result = wlan_autoconf(wip) ? SUCCESS : FAILURE;
		most_recent = NULL;
	}

finished:
	if (connect_result == SUCCESS &&
	    !update_connected_wlan(wip, most_recent))
		connect_result = FAILURE;
	(void) pthread_mutex_unlock(&wifi_mutex);
	scanconnect_exit();

	return (connect_result);
}

void
disconnect_wlan(const char *ifname)
{
	wireless_if_t *wip;
	struct wireless_lan *wlan;

	if (pthread_mutex_lock(&wifi_mutex) == 0) {
		if ((wip = find_wireless_if(ifname)) != NULL) {
			wip->wi_wireless_done = B_FALSE;
			wip->wi_need_key = B_FALSE;
			(void) dladm_wlan_disconnect(dld_handle,
			    wip->wi_linkid);
		}
		for (wlan = wlans; wlan < wlans + wireless_lan_used; wlan++) {
			if (strcmp(ifname, wlan->wl_if_name) == 0 &&
			    wlan->connected) {
				wlan->connected = B_FALSE;
				report_wlan_disconnect(wlan);
			}
		}
		(void) pthread_mutex_unlock(&wifi_mutex);
	}
}

void
get_wireless_state(const char *ifname, boolean_t *need_wlan,
    boolean_t *need_key)
{
	wireless_if_t *wip;

	*need_wlan = *need_key = B_FALSE;
	if (pthread_mutex_lock(&wifi_mutex) == 0) {
		if ((wip = find_wireless_if(ifname)) != NULL) {
			*need_key = wip->wi_need_key;
			if (!wip->wi_need_key && !wip->wi_wireless_done)
				*need_wlan = B_TRUE;
		}
		(void) pthread_mutex_unlock(&wifi_mutex);
	}
}

void
print_wireless_status(void)
{
	wireless_if_t *wip;
	struct wireless_lan *wlan;

	if (pthread_mutex_lock(&wifi_mutex) == 0) {
		for (wip = (wireless_if_t *)wi_list.q_forw;
		    wip != (wireless_if_t *)&wi_list;
		    wip = (wireless_if_t *)wip->wi_links.q_forw) {
			dprintf("WIF %s linkid %d scan %srunning "
			    "wireless %sdone %sneed key strength %d",
			    wip->wi_name, wip->wi_linkid,
			    wip->wi_scan_running ? "" : "not ",
			    wip->wi_wireless_done ? "" : "not ",
			    wip->wi_need_key ? "" : "don't ",
			    wip->wi_strength);
		}
		for (wlan = wlans; wlan < wlans + wireless_lan_used; wlan++) {
			dprintf("WLAN I/F %s ESS %s BSS %s signal %s key %sset "
			    "%sknown %sconnected %sscanned",
			    wlan->wl_if_name, wlan->essid, wlan->bssid,
			    wlan->signal_strength,
			    wlan->raw_key == NULL ? "un" : "",
			    wlan->known ? "" : "not ",
			    wlan->connected ? "" : "not ",
			    wlan->scanned ? "" : "not ");
		}
		(void) pthread_mutex_unlock(&wifi_mutex);
	}
}
