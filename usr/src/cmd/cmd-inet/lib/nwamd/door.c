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
 * This file contains the routines that service the libdoor(3LIB) interface.
 * This interface is intended for use by an external GUI utility to provide
 * status information to users and allow control over nwam behavior in certain
 * situations.
 *
 * The daemon has one active thread for each door call.  Typically, a client
 * will make a blocking call to await new events, and if an active client is
 * busy, we will enqueue a small number of events here.  If too many are
 * enqueued, then we begin dropping events, and a single special "lost" event
 * is placed in the queue.  Clients are expected to start over at that point.
 *
 * For client events that require a response from the client, the server must
 * assume a response if "lost" occurs or if there are no clients.
 *
 * When no clients are present, we just drop events.  No history is maintained.
 *
 * Thread cancellation notes: In general, we disable cancellation for all
 * calls, as allowing cancellation would require special handlers throughout
 * the nwamd code to deal with the release of locks taken in various contexts.
 * Instead, we allow it to run to completion on the assumption that all calls
 * are expected to run without significant blocking.
 *
 * The one exception to this is the event-wait function, which intentionally
 * blocks indefinitely.  This request must enable cancellation so that an idle
 * client can be terminated cleanly.
 */

#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <pthread.h>
#include <door.h>
#include <alloca.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <pwd.h>
#include <auth_attr.h>
#include <auth_list.h>
#include <secdb.h>
#include <bsm/adt.h>
#include <bsm/adt_event.h>

#include "defines.h"
#include "structures.h"
#include "functions.h"
#include "variables.h"

/* Idle time before declaring a client to be dead. */
uint_t door_idle_time = 10;

static int door_fd = -1;

static uid_t cur_user = (uid_t)-1;
static adt_session_data_t *cur_ah;

/*
 * event_queue is a simple circular queue of fixed size.  'evput' is the next
 * location to write, and 'evget' is the next waiting event.  The queue size is
 * chosen so that it's extremely unlikely that a functioning GUI could get this
 * far behind on events and still be at all usable.  (Too large, and we'd wait
 * too long backing off to automatic mode on a broken GUI.  Too small, and an
 * interface up/down transient would cause us to switch to automatic mode too
 * easily.)
 */
#define	MAX_DESCR_EVENTS	64
static nwam_descr_event_t event_queue[MAX_DESCR_EVENTS];
static nwam_descr_event_t *evput = event_queue, *evget = event_queue;
static struct wireless_lan *current_wlans;
static size_t current_wlansize;

/*
 * This lock protects the event queue and the current_wlans list.
 */
static pthread_mutex_t event_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * sleep_cv is used to block waiting for new events to appear in an empty
 * queue.  client_cv is used to wait for event client threads to wake up and
 * return before shutting down the daemon.
 */
static pthread_cond_t sleep_cv, client_cv;
static uint_t sleeping_clients;
static boolean_t active_clients;
static uint32_t client_expire;

/*
 * Register a "user logout" event with the auditing system.
 * A "logout" occurs when the GUI stops calling the event wait system (detected
 * either by idle timer or queue overflow), or when a different authorized user
 * calls the daemon (the previous one is logged out), or when the daemon itself
 * is shut down.
 */
static void
audit_detach(void)
{
	adt_event_data_t *event;

	event = adt_alloc_event(cur_ah, ADT_nwam_detach);
	if (event == NULL)
		syslog(LOG_ERR, "audit failure: detach allocation: %m");
	else if (adt_put_event(event, ADT_SUCCESS, ADT_SUCCESS) != 0)
		syslog(LOG_ERR, "audit failure: detach put: %m");
	adt_free_event(event);
	(void) adt_end_session(cur_ah);
	cur_ah = NULL;
	cur_user = (uid_t)-1;
}

/*
 * Register either a normal "user login" event (if 'attached' is set) or a
 * failed login (if 'attached' is not set) with auditing.
 */
static void
audit_attach(ucred_t *ucr, boolean_t attached)
{
	adt_session_data_t *ah;
	adt_event_data_t *event;
	int retv, status, retval;

	if (adt_start_session(&ah, NULL, 0) != 0) {
		syslog(LOG_ERR, "audit failure: session start: %m");
		return;
	}

	if (adt_set_from_ucred(ah, ucr, ADT_NEW) != 0) {
		syslog(LOG_ERR, "audit failure: session credentials: %m");
		goto failure;
	}
	if ((event = adt_alloc_event(ah, ADT_nwam_attach)) == NULL) {
		syslog(LOG_ERR, "audit failure: audit allocation: %m");
		goto failure;
	}
	event->adt_nwam_attach.auth_used = NET_AUTOCONF_AUTH;
	if (attached) {
		status = ADT_SUCCESS;
		retval = ADT_SUCCESS;
	} else {
		status = ADT_FAILURE;
		retval = ADT_FAIL_VALUE_AUTH;
	}
	retv = adt_put_event(event, status, retval);
	adt_free_event(event);
	if (retv != 0) {
		syslog(LOG_ERR, "audit failure: attach put: %m");
		goto failure;
	}

	/*
	 * Only successful attach records result in a detach.  All else have
	 * (at most) a single failure record, and nothing else.  Thus, we do
	 * not set cur_ah until we know we've written an attach record.
	 */
	if (attached) {
		cur_ah = ah;
		return;
	}

failure:
	(void) adt_end_session(ah);
}

/* Convert descriptive event to a text name for debug log */
static const char *
descr_event_name(libnwam_descr_evtype_t evt)
{
	/*
	 * Cast to int so that compiler and lint don't complain about extra
	 * 'default' case, and so that we can handle stray values.
	 */
	switch ((int)evt) {
	case deInitial:
		return ("Initial");
	case deInterfaceUp:
		return ("InterfaceUp");
	case deInterfaceDown:
		return ("InterfaceDown");
	case deInterfaceAdded:
		return ("InterfaceAdded");
	case deInterfaceRemoved:
		return ("InterfaceRemoved");
	case deWlanConnectFail:
		return ("WlanConnectFail");
	case deWlanDisconnect:
		return ("WlanDisconnect");
	case deWlanConnected:
		return ("WlanConnected");
	case deLLPSelected:
		return ("LLPSelected");
	case deLLPUnselected:
		return ("LLPUnselected");
	case deULPActivated:
		return ("ULPActivated");
	case deULPDeactivated:
		return ("ULPDeactivated");
	case deScanChange:
		return ("ScanChange");
	case deScanSame:
		return ("ScanSame");
	case deWlanKeyNeeded:
		return ("WlanKeyNeeded");
	case deWlanSelectionNeeded:
		return ("WlanSelectionNeeded");
	default:
		return ("unknown");
	}
}

/*
 * This is called only by ndcWaitEvent, which holds event_lock until it has
 * copied out the data from the entry.
 */
static const nwam_descr_event_t *
get_descr_event(void)
{
	nwam_descr_event_t *nde;
	static const nwam_descr_event_t init = { deInitial };

	if (!active_clients) {
		syslog(LOG_INFO, "new active door client detected");
		active_clients = B_TRUE;
		return (&init);
	}
	if ((nde = evget) == evput)
		return (NULL);
	if ((evget = nde + 1) >= event_queue + MAX_DESCR_EVENTS)
		evget = event_queue;
	/* If this event has a new WLAN snapshot, then update */
	if (nde->nde_wlans != NULL) {
		free(current_wlans);
		current_wlans = nde->nde_wlans;
		current_wlansize = nde->nde_wlansize;
		nde->nde_wlans = NULL;
	}
	return (nde);
}

/*
 * {start,put}_descr_event are called by the reporting functions.  This
 * function starts a new descriptive event and returns with the lock held (if
 * the return value is non-NULL).
 */
static nwam_descr_event_t *
start_descr_event(libnwam_descr_evtype_t evt)
{
	nwam_descr_event_t *nde, *ndenext;

	if (!active_clients || pthread_mutex_lock(&event_lock) != 0) {
		dprintf("dropping event %s; no active client",
		    descr_event_name(evt));
		return (NULL);
	}
	nde = evput;
	if ((ndenext = nde + 1) >= event_queue + MAX_DESCR_EVENTS)
		ndenext = event_queue;
	if (ndenext == evget) {
		syslog(LOG_INFO, "descr event queue overflow");
		active_clients = B_FALSE;
		(void) np_queue_add_event(EV_RESELECT, NULL);
		evput = evget = event_queue;
		audit_detach();
		(void) pthread_mutex_unlock(&event_lock);
		return (NULL);
	} else {
		nde->nde_type = evt;
		return (nde);
	}
}

/* Finish reporting the event; must not be called if nde is NULL */
static void
put_descr_event(nwam_descr_event_t *nde, const char *ifname)
{
	if (ifname != NULL) {
		dprintf("putting descr event %s %s",
		    descr_event_name(nde->nde_type), ifname);
		(void) strlcpy(nde->nde_interface, ifname,
		    sizeof (nde->nde_interface));
		if (++nde >= event_queue + MAX_DESCR_EVENTS)
			nde = event_queue;
		evput = nde;
		(void) pthread_cond_signal(&sleep_cv);
	}
	/* Cannot drop the lock unless we've acquired it. */
	assert(nde != NULL);
	(void) pthread_mutex_unlock(&event_lock);
}

/*
 * Finish reporting an event that sets the WLAN snapshot.  If there's no
 * client, then update the saved snapshot right now, as we won't be queuing the
 * event.
 */
static boolean_t
commit_wlans(nwam_descr_event_t *nde, const struct wireless_lan *wlans,
    int wlan_cnt, const char *ifname)
{
	size_t wlansize;
	struct wireless_lan *saved_wlans;

	wlansize = sizeof (*saved_wlans) * wlan_cnt;
	if ((saved_wlans = malloc(wlansize)) == NULL) {
		if (nde != NULL)
			put_descr_event(nde, NULL);
		return (B_FALSE);
	}
	(void) memcpy(saved_wlans, wlans, wlansize);

	if (nde != NULL) {
		nde->nde_wlansize = wlansize;
		nde->nde_wlans = saved_wlans;
		put_descr_event(nde, ifname);
		return (B_TRUE);
	} else {
		/* If the UI isn't running, then save the cached results */
		if (pthread_mutex_lock(&event_lock) == 0) {
			free(current_wlans);
			current_wlans = saved_wlans;
			current_wlansize = wlansize;
			(void) pthread_mutex_unlock(&event_lock);
		} else {
			free(saved_wlans);
		}
		return (B_FALSE);
	}
}

void
report_interface_up(const char *ifname, struct in_addr addr, int prefixlen)
{
	nwam_descr_event_t *nde;

	if ((nde = start_descr_event(deInterfaceUp)) != NULL) {
		nde->nde_v4address = addr;
		nde->nde_prefixlen = prefixlen;
		put_descr_event(nde, ifname);
	}
}

void
report_interface_down(const char *ifname, libnwam_diag_cause_t cause)
{
	nwam_descr_event_t *nde;

	if ((nde = start_descr_event(deInterfaceDown)) != NULL) {
		nde->nde_cause = cause;
		put_descr_event(nde, ifname);
	}
}

void
report_interface_added(const char *ifname)
{
	nwam_descr_event_t *nde;

	if ((nde = start_descr_event(deInterfaceAdded)) != NULL)
		put_descr_event(nde, ifname);
}

void
report_interface_removed(const char *ifname)
{
	nwam_descr_event_t *nde;

	if ((nde = start_descr_event(deInterfaceRemoved)) != NULL)
		put_descr_event(nde, ifname);
}

void
report_wlan_connect_fail(const char *ifname)
{
	nwam_descr_event_t *nde;

	if ((nde = start_descr_event(deWlanConnectFail)) != NULL)
		put_descr_event(nde, ifname);
}

void
report_wlan_disconnect(const struct wireless_lan *wlan)
{
	nwam_descr_event_t *nde;

	if ((nde = start_descr_event(deWlanDisconnect)) != NULL) {
		nde->nde_attrs = wlan->attrs;
		put_descr_event(nde, wlan->wl_if_name);
	}
}

void
report_wlan_connected(const struct wireless_lan *wlan)
{
	nwam_descr_event_t *nde;

	if ((nde = start_descr_event(deWlanConnected)) != NULL) {
		nde->nde_attrs = wlan->attrs;
		put_descr_event(nde, wlan->wl_if_name);
	}
}

void
report_llp_selected(const char *ifname)
{
	nwam_descr_event_t *nde;

	if ((nde = start_descr_event(deLLPSelected)) != NULL)
		put_descr_event(nde, ifname);
}

void
report_llp_unselected(const char *ifname, libnwam_diag_cause_t cause)
{
	nwam_descr_event_t *nde;

	if ((nde = start_descr_event(deLLPUnselected)) != NULL) {
		nde->nde_cause = cause;
		put_descr_event(nde, ifname);
	}
}

void
report_ulp_activated(const char *ulpname)
{
	nwam_descr_event_t *nde;

	if ((nde = start_descr_event(deULPActivated)) != NULL)
		put_descr_event(nde, ulpname);
}

void
report_ulp_deactivated(const char *ulpname)
{
	nwam_descr_event_t *nde;

	if ((nde = start_descr_event(deULPDeactivated)) != NULL)
		put_descr_event(nde, ulpname);
}

void
report_scan_complete(const char *ifname, boolean_t changed,
    const struct wireless_lan *wlans, int wlan_cnt)
{
	nwam_descr_event_t *nde;

	nde = start_descr_event(changed ? deScanChange : deScanSame);
	(void) commit_wlans(nde, wlans, wlan_cnt, ifname);
}

boolean_t
request_wlan_key(struct wireless_lan *wlan)
{
	nwam_descr_event_t *nde;

	if ((nde = start_descr_event(deWlanKeyNeeded)) != NULL) {
		nde->nde_attrs = wlan->attrs;
		put_descr_event(nde, wlan->wl_if_name);
		return (B_TRUE);
	} else {
		return (B_FALSE);
	}
}

boolean_t
request_wlan_selection(const char *ifname, const struct wireless_lan *wlans,
    int wlan_cnt)
{
	nwam_descr_event_t *nde;

	nde = start_descr_event(deWlanSelectionNeeded);
	return (commit_wlans(nde, wlans, wlan_cnt, ifname));
}

/* ARGSUSED */
static void
thread_cancel_handler(void *arg)
{
	if (--sleeping_clients == 0) {
		client_expire = NSEC_TO_SEC(gethrtime()) + door_idle_time;
		(void) pthread_cond_signal(&client_cv);
		/*
		 * On the wrong thread; must call start_timer from the main
		 * thread.
		 */
		if (client_expire < timer_expire)
			(void) np_queue_add_event(EV_DOOR_TIME, NULL);
	}
	(void) pthread_mutex_unlock(&event_lock);
}

/*
 * A timer is set when there are waiting event collectors.  If there haven't
 * been any collectors for "a long time," then we assume that the user
 * interface has been terminated or is jammed.
 */
void
check_door_life(uint32_t now)
{
	if (active_clients && sleeping_clients == 0) {
		if (client_expire > now) {
			start_timer(now, client_expire - now);
		} else {
			syslog(LOG_INFO,
			    "no active door clients left; flushing queue");
			if (pthread_mutex_lock(&event_lock) == 0) {
				active_clients = B_FALSE;
				if (evput != evget) {
					(void) np_queue_add_event(EV_RESELECT,
					    NULL);
				}
				evput = evget = event_queue;
				audit_detach();
				(void) pthread_mutex_unlock(&event_lock);
			}
		}
	}
}

/*
 * This is called for an unrecognized UID.  We check to see if the user is
 * authorized to issue commands to the NWAM daemon.
 */
static boolean_t
update_cur_user(ucred_t *ucr)
{
	struct passwd *pwd;
	uid_t uid = ucred_getruid(ucr);
	boolean_t attached = B_FALSE;

	if ((pwd = getpwuid(uid)) == NULL) {
		syslog(LOG_DEBUG, "unable to translate uid %d to a name", uid);
	} else if (chkauthattr(NET_AUTOCONF_AUTH, pwd->pw_name) == 0) {
		syslog(LOG_DEBUG, "user %s (%d) does not have %s", pwd->pw_name,
		    uid, NET_AUTOCONF_AUTH);
	} else {
		attached = B_TRUE;
	}
	if (pthread_mutex_lock(&event_lock) == 0) {
		if (attached) {
			audit_detach();
			cur_user = uid;
		}
		audit_attach(ucr, attached);
		(void) pthread_mutex_unlock(&event_lock);
	} else {
		attached = B_FALSE;
	}
	return (attached);
}

/* ARGSUSED */
static void
nwam_door_server(void *cookie, char *argp, size_t arg_size, door_desc_t *dp,
    uint_t ndesc)
{
	/* LINTED: alignment */
	nwam_door_cmd_t *ndc = (nwam_door_cmd_t *)argp;
	int retv = -1;
	ucred_t *ucr = NULL;
	libnwam_interface_type_t ift;

	if (arg_size < sizeof (*ndc) || door_ucred(&ucr) != 0) {
		retv = EINVAL;
		(void) door_return((char *)&retv, sizeof (retv), NULL, 0);
		return;
	}

	if (ucred_getruid(ucr) != cur_user && !update_cur_user(ucr)) {
		ucred_free(ucr);
		retv = EPERM;
		(void) door_return((char *)&retv, sizeof (retv), NULL, 0);
		return;
	}
	ucred_free(ucr);

	/*
	 * Only the blocking event wait can be canceled, and then only when
	 * headed for a block.
	 */
	(void) pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

	switch (ndc->ndc_type) {
	case ndcNull:
		dprintf("door: null event from client");
		retv = 0;
		break;

	case ndcWaitEvent: {
		const nwam_descr_event_t *nde;
		nwam_descr_event_t ndcopy;

		if ((retv = pthread_mutex_lock(&event_lock)) != 0)
			break;
		if ((nde = get_descr_event()) != NULL) {
			ndcopy = *nde;
			(void) pthread_mutex_unlock(&event_lock);
			dprintf("door: returning waiting event %s",
			    descr_event_name(ndcopy.nde_type));
			(void) door_return((char *)&ndcopy, sizeof (ndcopy),
			    NULL, 0);
			return;
		}

		(void) pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
		pthread_cleanup_push(thread_cancel_handler, NULL);
		sleeping_clients++;
		while ((nde = get_descr_event()) == NULL &&
		    door_fd != -1) {
			if (pthread_cond_wait(&sleep_cv, &event_lock) != 0)
				break;
		}
		if (nde != NULL)
			ndcopy = *nde;
		pthread_cleanup_pop(1);
		if (nde == NULL) {
			retv = EBADF;
			break;
		}
		dprintf("door: returning waited-for event %s",
		    descr_event_name(ndcopy.nde_type));
		(void) door_return((char *)&ndcopy, sizeof (ndcopy), NULL, 0);
		return;
	}

	case ndcGetLLPList: {
		nwam_llp_data_t *nld;
		llp_t *llplist, *llpstack, *llp;
		size_t llpsize;
		uint_t count;
		char selected[LIFNAMSIZ], locked[LIFNAMSIZ];

		/*
		 * Note that door_return never returns here, so we can't just
		 * use malloc'd memory.  Copy over to a stack-allocated buffer
		 * and do the string pointer fix-ups.
		 */
		if ((retv = pthread_mutex_lock(&machine_lock)) != 0)
			break;
		errno = 0;
		llplist = get_llp_list(&llpsize, &count, selected, locked);
		(void) pthread_mutex_unlock(&machine_lock);
		if (llplist != NULL) {
			nld = alloca(sizeof (*nld) + llpsize);
			nld->nld_count = count;
			(void) strlcpy(nld->nld_selected, selected,
			    sizeof (nld->nld_selected));
			(void) strlcpy(nld->nld_locked, locked,
			    sizeof (nld->nld_locked));
			llpstack = (llp_t *)(nld + 1);
			(void) memcpy(llpstack, llplist, llpsize);
			llp = llpstack;
			while (count-- > 0) {
				if (llp->llp_ipv4addrstr != NULL)
					llp->llp_ipv4addrstr -=
					    (uintptr_t)llplist;
				if (llp->llp_ipv6addrstr != NULL)
					llp->llp_ipv6addrstr -=
					    (uintptr_t)llplist;
				llp++;
			}
			free(llplist);
			llpsize += sizeof (*nld);
		} else {
			retv = errno;
			dprintf("door: no LLP list to get");
			break;
		}
		dprintf("door: get llp list returning %d entries",
		    nld->nld_count);
		(void) door_return((char *)nld, llpsize, NULL, 0);
		return;
	}

	case ndcSetLLPPriority:
		if ((retv = pthread_mutex_lock(&machine_lock)) != 0)
			break;
		dprintf("door: set priority on %s to %d",
		    ndc->ndc_interface, ndc->ndc_priority);
		retv = set_llp_priority(ndc->ndc_interface, ndc->ndc_priority);
		(void) pthread_mutex_unlock(&machine_lock);
		break;

	case ndcLockLLP:
		if ((retv = pthread_mutex_lock(&machine_lock)) != 0)
			break;
		if (ndc->ndc_interface[0] == '\0')
			dprintf("door: unlocking llp selection");
		else
			dprintf("door: locking to %s", ndc->ndc_interface);
		retv = set_locked_llp(ndc->ndc_interface);
		(void) pthread_mutex_unlock(&machine_lock);
		break;

	case ndcGetWlanList: {
		char *wlans;
		size_t wlansize;

		/*
		 * We protect ourselves here against a malicious or confused
		 * user.  The list is stable only while we're holding the lock,
		 * and the lock can't be held during the door return.
		 */
		if ((retv = pthread_mutex_lock(&event_lock)) != 0)
			break;
		if (current_wlans == NULL) {
			(void) pthread_mutex_unlock(&event_lock);
			dprintf("door: no WLAN list to get");
			retv = ENXIO;
			break;
		}
		wlans = alloca(wlansize = current_wlansize);
		(void) memcpy(wlans, current_wlans, wlansize);
		(void) pthread_mutex_unlock(&event_lock);
		dprintf("door: get wlan list returning %lu bytes",
		    (ulong_t)wlansize);
		(void) door_return(wlans, wlansize, NULL, 0);
		return;
	}

	case ndcGetKnownAPList: {
		nwam_known_ap_t *nka;
		libnwam_known_ap_t *kalist, *kastack, *kap;
		size_t kasize;
		uint_t count;

		/*
		 * Note that door_return never returns here, so we can't just
		 * use malloc'd memory.  Copy over to a stack-allocated buffer
		 * and do the string pointer fix-ups.
		 */
		errno = 0;
		kalist = get_known_ap_list(&kasize, &count);
		if (kalist != NULL) {
			nka = alloca(sizeof (*nka) + kasize);
			nka->nka_count = count;
			kastack = (libnwam_known_ap_t *)(nka + 1);
			(void) memcpy(kastack, kalist, kasize);
			kap = kastack;
			while (count-- > 0) {
				kap->ka_bssid -= (uintptr_t)kalist;
				kap->ka_essid -= (uintptr_t)kalist;
				kap++;
			}
			free(kalist);
			kasize += sizeof (*nka);
		} else {
			retv = errno;
			dprintf("door: no known AP list to get");
			break;
		}
		dprintf("door: get known AP list returning %u entries",
		    nka->nka_count);
		(void) door_return((char *)nka, kasize, NULL, 0);
		return;
	}

	case ndcAddKnownAP:
		dprintf("door: adding known AP %s %s",
		    ndc->ndc_essid, ndc->ndc_bssid);
		retv = add_known_ap(ndc->ndc_essid, ndc->ndc_bssid);
		break;

	case ndcDeleteKnownAP:
		dprintf("door: removing known AP %s %s",
		    ndc->ndc_essid, ndc->ndc_bssid);
		retv = delete_known_ap(ndc->ndc_essid, ndc->ndc_bssid);
		break;

	case ndcSelectWlan:
		if ((retv = pthread_mutex_lock(&machine_lock)) != 0)
			break;
		dprintf("door: selecting WLAN on %s as %s %s",
		    ndc->ndc_interface, ndc->ndc_essid, ndc->ndc_bssid);
		/*
		 * Check if we're already connected to the requested
		 * ESSID/BSSID.  If so, then this request succeeds without
		 * changing anything.  Otherwise, tear down the interface
		 * (disconnecting from the WLAN) and set up again.
		 */
		if (check_wlan_connected(ndc->ndc_interface, ndc->ndc_essid,
		    ndc->ndc_bssid)) {
			retv = 0;
		} else {
			takedowninterface(ndc->ndc_interface, dcSelect);
			if (link_layer_profile != NULL)
				link_layer_profile->llp_waiting = B_TRUE;
			retv = set_specific_lan(ndc->ndc_interface,
			    ndc->ndc_essid, ndc->ndc_bssid);
		}
		(void) pthread_mutex_unlock(&machine_lock);
		break;

	case ndcWlanKey:
		if ((retv = pthread_mutex_lock(&machine_lock)) != 0)
			break;
		dprintf("door: selecting WLAN key on %s for %s %s",
		    ndc->ndc_interface, ndc->ndc_essid, ndc->ndc_bssid);
		retv = set_wlan_key(ndc->ndc_interface, ndc->ndc_essid,
		    ndc->ndc_bssid, ndc->ndc_key);
		(void) pthread_mutex_unlock(&machine_lock);
		break;

	case ndcStartRescan:
		dprintf("door: rescan requested on %s",
		    ndc->ndc_interface);
		ift = get_if_type(ndc->ndc_interface);
		if (ift != IF_UNKNOWN && ift != IF_WIRELESS) {
			retv = EINVAL;
			break;
		}
		if ((retv = pthread_mutex_lock(&machine_lock)) != 0)
			break;
		retv = launch_wireless_scan(ndc->ndc_interface);
		(void) pthread_mutex_unlock(&machine_lock);
		break;

	default:
		dprintf("door: unknown request type %d", (int)ndc->ndc_type);
		break;
	}
	if (retv != 0)
		dprintf("door: returning to caller with error %d (%s)",
		    retv, strerror(retv));
	(void) door_return((char *)&retv, sizeof (retv), NULL, 0);
}

static void
door_cleanup(void)
{
	if (door_fd != -1) {
		syslog(LOG_DEBUG, "closing door");
		(void) door_revoke(door_fd);
		door_fd = -1;
	}
	(void) unlink(DOOR_FILENAME);
}

void
terminate_door(void)
{
	door_cleanup();
	if (pthread_mutex_lock(&event_lock) != 0)
		return;
	if (sleeping_clients != 0)
		syslog(LOG_DEBUG, "waiting on %d sleeping clients",
		    sleeping_clients);
	while (sleeping_clients != 0) {
		(void) pthread_cond_broadcast(&sleep_cv);
		if (pthread_cond_wait(&client_cv, &event_lock) != 0)
			break;
	}
	free(current_wlans);
	current_wlans = NULL;
	audit_detach();
	(void) pthread_mutex_unlock(&event_lock);
}

void
initialize_door(void)
{
	int did;

	/* Do a low-overhead "touch" on the file that will be the door node. */
	syslog(LOG_DEBUG, "opening door");
	did = open(DOOR_FILENAME,
	    O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK,
	    DOOR_FILEMODE);
	if (did != -1) {
		(void) close(did);
	} else if (errno != EEXIST) {
		syslog(LOG_ERR, "unable to create control door node: %m");
		exit(EXIT_FAILURE);
	}

	(void) atexit(door_cleanup);

	/* Create the door. */
	door_fd = door_create(nwam_door_server, NULL, DOOR_REFUSE_DESC);
	if (door_fd == -1) {
		syslog(LOG_ERR, "unable to create control door: %m");
		exit(EXIT_FAILURE);
	}

	/* Attach the door to the file. */
	(void) fdetach(DOOR_FILENAME);
	if (fattach(door_fd, DOOR_FILENAME) == -1) {
		syslog(LOG_ERR, "unable to attach control door: %m");
		exit(EXIT_FAILURE);
	}
}
