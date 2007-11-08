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
 * connection and IP interface set up.  WEP/WPA is supported to connect to
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
static pthread_mutexattr_t wifi_mutex_attr;
static pthread_mutex_t wifi_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t wifi_init_cond = PTHREAD_COND_INITIALIZER;

typedef enum {
	SUCCESS = 0,
	FAILURE,
	TRY_AGAIN
} return_vals_t;

typedef enum {
	ESSID = 0,
	BSSID,
	MAX_FIELDS
} known_wifi_nets_fields_t;

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

static int key_string_to_secobj_value(char *, uint8_t *, uint_t *,
    dladm_secobj_class_t);
static int store_key(struct wireless_lan *);
static dladm_wlan_key_t *retrieve_key(const char *, const char *,
    dladm_secobj_class_t);

static boolean_t add_wlan_entry(struct interface *, char *, char *, char *,
    dladm_wlan_secmode_t);
static boolean_t already_in_visited_wlan_list(const struct wireless_lan *);
static boolean_t check_wlan(const char *, const char *);
static boolean_t connect_or_autoconf(struct wireless_lan *, const char *);
static return_vals_t connect_to_new_wlan(const struct wireless_lan *, int,
    const char *);
static boolean_t find_wlan_entry(struct interface *, char *, char *);
static void free_wireless_lan(struct wireless_lan *);
static struct wireless_lan *get_specific_lan(void);
static void get_user_key(struct wireless_lan *);
static int get_user_preference(char *const *, const char *, const char *,
    struct wireless_lan **, const struct wireless_lan *);
static char **alloc_argv(int, size_t);
static void free_argv(char **);
static char **build_wlanlist_zargv(const struct wireless_lan *, int,
    const char *, int, const char **, int);
static char *get_zenity_response(char *const *);
static boolean_t wlan_autoconf(const char *ifname);
static int zenity_height(int);
static boolean_t get_scan_results(void *, dladm_wlan_attr_t *);
static boolean_t known_wifi_nets_lookup(const char *, const char *, char *);


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

/*
 * Some constants for zenity args
 */
/*
 * For a wlan table, command begins with 5 general args:
 * cmdname (argv[0]), window type (list), title, height, and width.
 */
#define	ZENITY_LIST_INIT_ARGS	5
/*
 * Columns: index, ESSID, BSSID, Encryption Type, Signal Strength
 */
#define	ZENITY_COLUMNS_PER_WLAN	5
/*
 * Cap the length of an individual arg at 64 bytes.
 * Longest args tend to be extra row strings.
 */
#define	ZENITY_ARG_LEN		64
/*
 * Typical zenity return buffers are index number strings
 * or extra row strings; 1024 should be sufficient.
 */
#define	ZENITY_RTN_BUF_SIZE	1024

/*
 * Alloc an array of (cnt + 1) pointers, where the first cnt pointers
 * point to an alloc'd buffer of specified len.  The last pointer in
 * the array is NULL.
 */
static char **
alloc_argv(int cnt, size_t buflen)
{
	int i;
	char **argv;

	if ((argv = calloc(cnt + 1, sizeof (char *))) == NULL) {
		syslog(LOG_ERR, "calloc failed: %m");
		return (NULL);
	}
	for (i = 0; i < cnt; i++) {
		if ((argv[i] = malloc(buflen)) == NULL) {
			syslog(LOG_ERR, "malloc failed: %m");
			free_argv(argv);
			return (NULL);
		}
	}
	argv[cnt] = NULL;

	return (argv);
}

/*
 * Free an argv.  Assumes that the first NULL pointer encountered
 * indicates the end of the array: that is, that the array is null-
 * terminated and that no other elements are NULL.
 */
static void
free_argv(char **argv)
{
	int i = 0;

	if (argv == NULL)
		return;

	while (argv[i] != NULL)
		free(argv[i++]);
	free(argv);
}

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
get_user_key(struct wireless_lan *wlan)
{
	dladm_secobj_class_t class;
	int zargc, cur;
	char **zargv;

	/*
	 * First, test if we have key stored as secobj. If so,
	 * no need to prompt for it.
	 */
	class = (wlan->sec_mode == DLADM_WLAN_SECMODE_WEP ?
	    DLADM_SECOBJ_CLASS_WEP : DLADM_SECOBJ_CLASS_WPA);
	wlan->cooked_key = retrieve_key(wlan->essid, wlan->bssid, class);
	if (wlan->cooked_key != NULL) {
		dprintf("get_user_key: retrieve_key() returns non NULL");
		return;
	}

	if (!valid_graphical_user(B_TRUE))
		return;

	/*
	 * build zenity 'entry' argv, with text hidden:
	 *	'zenity --entry --title=foo --text=bar --hide-text'
	 * Five args needed.
	 */
	zargc = 5;
	if ((zargv = alloc_argv(zargc, ZENITY_ARG_LEN)) == NULL)
		return;

	cur = 0;
	(void) snprintf(zargv[cur++], ZENITY_ARG_LEN, ZENITY);
	(void) snprintf(zargv[cur++], ZENITY_ARG_LEN, "--entry");
	(void) snprintf(zargv[cur++], ZENITY_ARG_LEN, "--title=%s",
	    gettext("Enter Key"));
	(void) snprintf(zargv[cur++], ZENITY_ARG_LEN, "--text=%s %s",
	    gettext("Enter key for WiFi network"), wlan->essid);
	(void) snprintf(zargv[cur++], ZENITY_ARG_LEN, "--hide-text");

	wlan->raw_key = get_zenity_response(zargv);
	if (wlan->raw_key == NULL) {
		dprintf("get_user_key: failed to obtain user-specified key");
		goto cleanup;
	}

	/* Store key persistently */
	if (store_key(wlan) != 0) {
		syslog(LOG_ERR, "get_user_key: failed to store user-specified "
		    "key");
	}

cleanup:
	free_argv(zargv);
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
	free(wlp->raw_key);
	wlp->raw_key = NULL;
	free(wlp->cooked_key);
	wlp->cooked_key = NULL;
	free(wlp->wl_if_name);
	wlp->wl_if_name = NULL;
}

static boolean_t
add_wlan_entry(struct interface *intf, char *essid, char *bssid,
    char *signal_strength, dladm_wlan_secmode_t sec)
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
	wlans[n].sec_mode = sec;
	wlans[n].raw_key = NULL;
	wlans[n].cooked_key = NULL;
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
	dladm_wlan_secmode_t	sec;
	char		essid_name[DLADM_STRSIZE];
	char		bssid_name[DLADM_STRSIZE];
	char		strength[DLADM_STRSIZE];

	(void) dladm_wlan_essid2str(&attrp->wa_essid, essid_name);
	(void) dladm_wlan_bssid2str(&attrp->wa_bssid, bssid_name);
	(void) dladm_wlan_strength2str(&attrp->wa_strength, strength);

	sec = attrp->wa_secmode;

	/*
	 * Check whether ESSID is "hidden".
	 * If so try to substitute it with the ESSID from the
	 * known_wifi_nets with the same BSSID
	 */
	if (essid_name[0] == '\0') {
		if (known_wifi_nets_lookup(essid_name, bssid_name,
		    essid_name)) {
			dprintf("Using ESSID %s with BSSID %s",
			    essid_name, bssid_name);
		}
	}

	if (!find_wlan_entry(arg, essid_name, bssid_name) &&
	    add_wlan_entry(arg, essid_name, bssid_name, strength, sec)) {
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
				 * Clear the DHCP flags on this interface;
				 * this is a "fresh start" for the interface,
				 * so we should retry dhcp.
				 */
				ifp = get_interface(cur_llp->llp_lname);
				if (ifp != NULL)
					ifp->if_lflags &= ~IF_DHCPFLAGS;

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
		syslog(LOG_ERR,
		    "key_string_to_secobj_value: empty key");
		return (-1);
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
 * Print the key format into the appropriate field, then convert any ":"
 * characters to ".", as ":[1-4]" is the slot indicator, which otherwise
 * would trip us up.  The third parameter is expected to be of size
 * DLADM_SECOBJ_NAME_MAX.
 */
static void
set_key_name(const char *essid, const char *bssid, char *name, size_t nsz)
{
	int i, rtn, len;

	if (bssid == NULL)
		rtn = snprintf(name, nsz, "nwam-%s", essid);
	else
		rtn = snprintf(name, nsz, "nwam-%s-%s", essid, bssid);
	len = (rtn < nsz) ? rtn : nsz - 1;
	for (i = 0; i < len; i++)
		if (name[i] == ':')
			name[i] = '.';
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

	class = (wlan->sec_mode == DLADM_WLAN_SECMODE_WEP ?
	    DLADM_SECOBJ_CLASS_WEP : DLADM_SECOBJ_CLASS_WPA);
	if (key_string_to_secobj_value(wlan->raw_key, obj_val, &obj_len,
	    class) != 0) {
		/* above function logs internally on failure */
		return (-1);
	}

	status = dladm_set_secobj(obj_name, class,
	    obj_val, obj_len,
	    DLADM_OPT_CREATE | DLADM_OPT_PERSIST | DLADM_OPT_TEMP);
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

	/* Set name appropriately to retrieve key for this WLAN */
	set_key_name(essid, bssid, cooked_key->wk_name,
	    DLADM_SECOBJ_NAME_MAX);
	dprintf("retrieve_key: len = %d, object = %s\n",
	    strlen(cooked_key->wk_name), cooked_key->wk_name);
	cooked_key->wk_len = DLADM_SECOBJ_NAME_MAX;
	cooked_key->wk_idx = 1;

	/* Try the kernel first, then fall back to persistent storage. */
	status = dladm_get_secobj(cooked_key->wk_name, &class,
	    cooked_key->wk_val, &cooked_key->wk_len,
	    DLADM_OPT_TEMP);
	if (status != DLADM_STATUS_OK) {
		dprintf("retrieve_key: dladm_get_secobj(TEMP) failed: %s",
		    dladm_status2str(status, errmsg));
		status = dladm_get_secobj(cooked_key->wk_name, &class,
		    cooked_key->wk_val, &cooked_key->wk_len,
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
	if (!known_wifi_nets_lookup(essid, bssid, NULL)) {
		/* now add this to the file */
		(void) fprintf(fp, "%s\t%s\n", essid,
		    bssid == NULL ? "" : bssid);
	}
	(void) fclose(fp);
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
		 * If BSSID match is found we check ESSID, which should
		 * either match as well, or be an empty string.
		 * In latter case we'll retrieve the ESSID from known_wifi_nets
		 * later.
		 */
		if (strcmp(tok[BSSID], new_bssid) == 0) {
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

/*
 * reqlan->essid is required (i.e., cannot be NULL)
 * reqlan->bssid is optional (i.e., may be NULL)
 */
boolean_t
connect_chosen_lan(struct wireless_lan *reqlan, const char *ifname)
{
	uint_t	keycount;
	dladm_wlan_key_t *key;
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

	/* First check for the key */
	if (NEED_ENC(reqlan->sec_mode)) {
		get_user_key(reqlan);
		if (reqlan->cooked_key == NULL)
			return (B_FALSE);
		attr.wa_valid |= DLADM_WLAN_ATTR_SECMODE;
		attr.wa_secmode = reqlan->sec_mode;
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

/*
 * Construct an arg vector for zenity which displays a list of wlans.
 * Additional options may be added at the end of the list of wlans with
 * the "extra_rows" arg.
 *
 * Parameters include:
 *	lanlist: a linked list of wlans; one row per list node.
 *	nlans: the number of nodes in lanlist.
 *	title: the string that should be the zenity window title.
 *	width: the width of the zenity window.
 *	extra_rows: pointer to an array of strings; each string will
 *	    appear on its own row in the table, in the first column
 *	    of that row.
 *	nrows: the number of extra row strings.
 *
 * A pointer to the arg vector is returned; the caller must free that
 * memory using free_argv().
 */
static char **
build_wlanlist_zargv(const struct wireless_lan *lanlist, int nlans,
    const char *title, int width, const char **extra_rows, int nrows)
{
	int cur, i, j;
	int zargc, hdrargc, wlanargc;
	char **zargv;

	/*
	 * There are three sections of arguments: the initial args, specifying
	 * general formatting info; the column titles (one arg per column);
	 * and the row data (one row per wlan, plus any extra rows; and one
	 * arg per column per row).
	 */
	hdrargc = ZENITY_LIST_INIT_ARGS + ZENITY_COLUMNS_PER_WLAN;
	wlanargc = (nlans + nrows) * ZENITY_COLUMNS_PER_WLAN;
	zargc = hdrargc + wlanargc;
	if ((zargv = alloc_argv(zargc, ZENITY_ARG_LEN)) == NULL)
		return (NULL);

	/* initial args */
	cur = 0;
	(void) snprintf(zargv[cur++], ZENITY_ARG_LEN, ZENITY);
	(void) snprintf(zargv[cur++], ZENITY_ARG_LEN, "--list");
	(void) snprintf(zargv[cur++], ZENITY_ARG_LEN, "--title=%s", title);
	(void) snprintf(zargv[cur++], ZENITY_ARG_LEN, "--height=%d",
	    zenity_height(nlans + nrows));
	(void) snprintf(zargv[cur++], ZENITY_ARG_LEN, "--width=%d", width);

	/* column titles */
	(void) snprintf(zargv[cur++], ZENITY_ARG_LEN, "--column=#");
	(void) snprintf(zargv[cur++], ZENITY_ARG_LEN, "--column=ESSID");
	(void) snprintf(zargv[cur++], ZENITY_ARG_LEN, "--column=BSSID");
	(void) snprintf(zargv[cur++], ZENITY_ARG_LEN, "--column=%s",
	    gettext("Encryption"));
	(void) snprintf(zargv[cur++], ZENITY_ARG_LEN, "--column=%s",
	    gettext("Signal"));

	/* wlan rows */
	for (i = 0; i < nlans; i++) {
		(void) snprintf(zargv[cur++], ZENITY_ARG_LEN, "%d", i + 1);
		(void) snprintf(zargv[cur++], ZENITY_ARG_LEN, "%s",
		    lanlist[i].essid);
		(void) snprintf(zargv[cur++], ZENITY_ARG_LEN, "%s",
		    lanlist[i].bssid);
		(void) snprintf(zargv[cur++], ZENITY_ARG_LEN, "%s",
		    WLAN_ENC(lanlist[i].sec_mode));
		(void) snprintf(zargv[cur++], ZENITY_ARG_LEN, "%s",
		    lanlist[i].signal_strength);
	}

	/* extra rows */
	for (i = 0; i < nrows; i++) {
		/* all columns are empty except the first */
		(void) snprintf(zargv[cur++], ZENITY_ARG_LEN, extra_rows[i]);
		for (j = 0; j < ZENITY_COLUMNS_PER_WLAN - 1; j++)
			*zargv[cur++] = '\0';
	}

	return (zargv);
}

static return_vals_t
connect_to_new_wlan(const struct wireless_lan *lanlist, int nlans,
    const char *ifname)
{
	struct interface *intf;
	int i, dlist_cnt;
	int rtn;
	char **zargv;
	const char *title = gettext("Choose WiFi network you wish to activate");
	const char *extra_rows[2];
	struct wireless_lan *dlist, *reqlan;
	boolean_t autoconf = B_FALSE;

	dprintf("connect_to_new_wlan(..., %d, %s)", nlans, ifname);

	if (nlans == 0) {
		display(gettext("No Wifi networks found; continuing in case "
		    "you know of any which do not broadcast."));
	}

	if ((intf = get_interface(ifname)) == NULL) {
		dprintf("connect_to_new_wlan: cannot find wireless interface: "
		    "%s", ifname);
		return (FAILURE);
	}

	/* build list of wlans to be displayed */
	if ((dlist = calloc(nlans, sizeof (struct wireless_lan))) == NULL)
		return (FAILURE);

	for (i = 0, dlist_cnt = 0; i < nlans; i++) {
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

		dlist[dlist_cnt++] = lanlist[i];
	}

	extra_rows[0] = gettext("Other");
	extra_rows[1] = gettext("Rescan");
	/* width = 500 is the result of trial-and-error testing */
	zargv = build_wlanlist_zargv(dlist, dlist_cnt, title, 500, extra_rows,
	    sizeof (extra_rows) / sizeof (extra_rows[0]));
	if (zargv == NULL) {
		free(dlist);
		return (FAILURE);
	}

	/* present list to user and get selection */
	rtn = get_user_preference(zargv, extra_rows[0], extra_rows[1],
	    &reqlan, dlist);
	switch (rtn) {
	case 1:
		/* user chose "other"; pop-up for specific essid */
		reqlan = get_specific_lan();
		break;
	case 2:
		/* user chose "Rescan" */
		(void) scan_wireless_nets(intf);
		rtn = TRY_AGAIN;
		goto cleanup;
	case -1:
		reqlan = NULL;
		break;
	default:
		/* common case: reqlan was set in get_user_preference() */
		break;
	}

	if ((reqlan == NULL) || (reqlan->essid == NULL)) {
		dprintf("did not get user preference; attempting autoconf");
		rtn = wlan_autoconf(ifname) ? SUCCESS : FAILURE;
		goto cleanup;
	}
	dprintf("get_user_preference() returned essid %s, bssid %s, encr %s",
	    reqlan->essid, STRING(reqlan->bssid),
	    WLAN_ENC(reqlan->sec_mode));

	/* set key before first time connection */
	if (NEED_ENC(reqlan->sec_mode) && reqlan->raw_key == NULL &&
	    reqlan->cooked_key == NULL)
		get_user_key(reqlan);

	/*
	 * now attempt to connect to selection, backing
	 * off to autoconf if the connect fails
	 */
	if (connect_chosen_lan(reqlan, ifname)) {
		/*
		 * Succeeded, so add entry to known_essid_list_file;
		 * but first make sure the reqlan->bssid isn't empty.
		 */
		if (reqlan->bssid == NULL) {
			dladm_status_t		status;
			dladm_wlan_linkattr_t	attr;
			char			bssid[DLADM_STRSIZE];

			status = dladm_wlan_get_linkattr(ifname, &attr);

			if (status == DLADM_STATUS_OK) {
				(void) dladm_wlan_bssid2str(
				    &attr.la_wlan_attr.wa_bssid, bssid);
				reqlan->bssid = strdup(bssid);
			} else {
				dprintf("failed to get linkattr after "
				    "connecting to %s", reqlan->essid);
			}
		}
		update_known_wifi_nets_file(reqlan->essid, reqlan->bssid);
	} else {
		/* failed to connect; try auto-conf */
		syslog(LOG_WARNING, "Could not connect to chosen WLAN "
		    "%s; going to auto-conf", reqlan->essid);
		autoconf = B_TRUE;
	}
	free_wireless_lan(reqlan);

	if (autoconf)
		rtn = wlan_autoconf(ifname) ? SUCCESS : FAILURE;
	else
		rtn = SUCCESS;

cleanup:
	free_argv(zargv);
	free(dlist);

	return (rtn);
}

struct wireless_lan *
prompt_for_visited(void)
{
	int dlist_cnt;
	char **zargv;
	const char *title = gettext("Choose from pre-visited WiFi network");
	const char *extra_rows[1];
	struct wireless_lan *req_conf, *dlist;
	struct visited_wlans *vlp;
	struct wireless_lan *wlp;

	/* build list of wlans to be displayed */
	dlist = calloc(visited_wlan_list->total, sizeof (struct wireless_lan));
	if (dlist == NULL) {
		syslog(LOG_ERR, "prompt_for_visited: calloc failed");
		return (NULL);
	}
	dlist_cnt = 0;
	for (vlp = visited_wlan_list->head; vlp != NULL; vlp = vlp->next) {
		wlp = vlp->wifi_net;
		if (wlp->essid == NULL || wlp->bssid == NULL) {
			dprintf("Invalid essid/bssid values");
			continue;
		}
		dlist[dlist_cnt++] = *wlp;
	}

	extra_rows[0] = gettext("Select from all available WiFi networks");
	/* width = 670 is the result of trial-and-error testing */
	zargv = build_wlanlist_zargv(dlist, dlist_cnt, title, 670, extra_rows,
	    sizeof (extra_rows) / sizeof (extra_rows[0]));
	if (zargv == NULL) {
		free(dlist);
		return (NULL);
	}

	/*
	 * If the user doesn't make a choice or something goes wrong
	 * (get_user_preference() returned -1), or if the user chooses
	 * the "select from all available" string (get_user_preference()
	 * returned 1), we simply return NULL: there was no selection
	 * made from the visited list.  If the user *did* make a choice
	 * (get_user_preference() returned 0), return the alloc'd struct.
	 */
	if (get_user_preference(zargv, extra_rows[0], NULL, &req_conf,
	    dlist) != 0)
		req_conf = NULL;

	free(dlist);
	free_argv(zargv);
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
get_zenity_response(char *const *zargv)
{
	int pfds[2];
	pid_t pid;
	int status, i;
	char inbuf[ZENITY_RTN_BUF_SIZE];
	ssize_t n, bytes_read;
	char *rtnp = NULL;

	if (!valid_graphical_user(B_TRUE))
		return (NULL);

	if (pipe(pfds) < 0) {
		syslog(LOG_ERR, "pipe() failed: %m");
		return (NULL);
	}
	if ((pid = fork()) < 0) {
		syslog(LOG_ERR, "fork() failed: %m");
		return (NULL);
	} else if (pid == 0) {
		/*
		 * child: close read side of pipe, point stdout at write side
		 */
		(void) close(pfds[0]);
		if (dup2(pfds[1], STDOUT_FILENO) < 0) {
			syslog(LOG_ERR, "dup2() failed: %m");
			_exit(EXIT_FAILURE);
		}
		(void) close(pfds[1]);
		(void) execv(ZENITY, zargv);
		syslog(LOG_ERR, "execv() failed: %m");
		_exit(EXIT_FAILURE);
	} else {
		/*
		 * parent: close write side of pipe, read from read side
		 * to get zenity output from child.
		 */
		(void) close(pfds[1]);
		(void) waitpid(pid, &status, 0);
		if (WIFSIGNALED(status) || WIFSTOPPED(status)) {
			i = WIFSIGNALED(status) ? WTERMSIG(status) :
			    WSTOPSIG(status);
			syslog(LOG_ERR, "%s %s with signal %d (%s)",
			    ZENITY, (WIFSIGNALED(status) ? "terminated" :
			    "stopped"), i, strsignal(i));
			return (NULL);
		}
		bytes_read = 0;
		do {
			n = read(pfds[0], inbuf + bytes_read,
			    sizeof (inbuf) - bytes_read);
			if (n < 0) {
				if (errno != EINTR) {
					syslog(LOG_ERR, "read() failed: %m");
					break;
				}
			} else {
				bytes_read += n;
			}
			if (bytes_read == sizeof (inbuf)) {
				bytes_read--;
				syslog(LOG_WARNING, "get_zenity_response: too "
				    "much data; input read will be limited to "
				    "%d bytes", bytes_read);
				break;
			}
		} while (n != 0);
		(void) close(pfds[0]);
		if (bytes_read == 0) {
			syslog(LOG_ERR, "failed to read zenity output");
			return (NULL);
		}
		if (inbuf[bytes_read - 1] == '\n')
			inbuf[bytes_read - 1] = '\0';
		else
			inbuf[bytes_read] = '\0';

		if ((rtnp = strdup(inbuf)) == NULL)
			syslog(LOG_ERR, "get_zenity_response: strdup failed");
	}

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
static int
get_user_preference(char *const *zargv, const char *compare_other,
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
		syslog(LOG_ERR, "calloc failed");
		return (-1);
	}

	response = get_zenity_response(zargv);
	if (response == NULL) {
		free(wlp);
		return (-1);
	}
	if (compare_other != NULL && strcmp(response, compare_other) == 0) {
		free(response);
		free(wlp);
		return (1);
	}
	if (compare_rescan != NULL && strcmp(response, compare_rescan) == 0) {
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

	wlp->sec_mode = sel->sec_mode;

	if ((sel->raw_key != NULL) &&
	    ((wlp->raw_key = strdup(sel->raw_key)) == NULL))
		goto dup_error;

	if (sel->cooked_key != NULL) {
		wlp->cooked_key = malloc(sizeof (dladm_wlan_key_t));
		if (wlp->cooked_key == NULL)
			goto dup_error;
		*(wlp->cooked_key) = *(sel->cooked_key);
	}

	if ((sel->signal_strength != NULL) &&
	    ((wlp->signal_strength = strdup(sel->signal_strength)) == NULL))
		goto dup_error;

	if ((sel->wl_if_name != NULL) &&
	    ((wlp->wl_if_name = strdup(sel->wl_if_name)) == NULL))
		goto dup_error;

	dprintf("selected: %s, %s, %s, '%s', %s", wlp->essid,
	    STRING(wlp->bssid), WLAN_ENC(wlp->sec_mode),
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
	int zargc, cur;
	char **zargv;
	char *response;
	struct wireless_lan *wlp = NULL;

	/*
	 * build zenity 'entry' argv to get an ESSID:
	 *	'zenity --entry --title=foo --text=bar'
	 * Four args needed.
	 */
	zargc = 4;
	if ((zargv = alloc_argv(zargc, ZENITY_ARG_LEN)) == NULL)
		return (NULL);

	cur = 0;
	(void) snprintf(zargv[cur++], ZENITY_ARG_LEN, ZENITY);
	(void) snprintf(zargv[cur++], ZENITY_ARG_LEN, "--entry");
	(void) snprintf(zargv[cur++], ZENITY_ARG_LEN, "--title=%s",
	    gettext("Specify WiFi Network"));
	(void) snprintf(zargv[cur++], ZENITY_ARG_LEN, "--text=%s %s",
	    gettext("Enter"), "ESSID");

	response = get_zenity_response(zargv);
	if (response == NULL)
		goto cleanup;
	free_argv(zargv);

	wlp = calloc(1, sizeof (struct wireless_lan));
	if (wlp == NULL) {
		syslog(LOG_ERR, "calloc failed: %m");
		goto cleanup;
	}
	wlp->essid = response;
	wlp->sec_mode = DLADM_WLAN_SECMODE_NONE;

	/*
	 * build zenity 'list' argv to get security mode:
	 *	'zenity --list --title=foo --text=bar --column=baz <3 modes>'
	 * Eight args needed.
	 */
	zargc = 8;
	if ((zargv = alloc_argv(zargc, ZENITY_ARG_LEN)) == NULL) {
		/* assume the default security mode, "none" */
		return (wlp);
	}

	cur = 0;
	(void) snprintf(zargv[cur++], ZENITY_ARG_LEN, ZENITY);
	(void) snprintf(zargv[cur++], ZENITY_ARG_LEN, "--list");
	(void) snprintf(zargv[cur++], ZENITY_ARG_LEN, "--title=%s",
	    gettext("Security"));
	(void) snprintf(zargv[cur++], ZENITY_ARG_LEN, "--text=%s",
	    gettext("Enter security mode"));
	(void) snprintf(zargv[cur++], ZENITY_ARG_LEN, "--column=%s",
	    gettext("Type"));
	(void) snprintf(zargv[cur++], ZENITY_ARG_LEN, "None");
	(void) snprintf(zargv[cur++], ZENITY_ARG_LEN, "WEP");
	(void) snprintf(zargv[cur++], ZENITY_ARG_LEN, "WPA");

	response = get_zenity_response(zargv);
	/* "none" was set as the default earlier */
	if (response != NULL) {
		if (strcmp(response, "WEP") == 0)
			wlp->sec_mode = DLADM_WLAN_SECMODE_WEP;
		else if (strcmp(response, "WPA") == 0)
			wlp->sec_mode = DLADM_WLAN_SECMODE_WPA;
	}
cleanup:
	free_argv(zargv);
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
		    cur_wlans[i].bssid, NULL))
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
		new_wlan->wifi_net->raw_key = NULL;
		new_wlan->wifi_net->cooked_key = NULL;
		new_wlan->wifi_net->sec_mode = cur_wlans[i].sec_mode;
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
