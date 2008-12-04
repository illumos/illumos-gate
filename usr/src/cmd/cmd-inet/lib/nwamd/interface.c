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
 * This file contains the routines that manipulate interfaces, the
 * list of interfaces present on the system, and upper layer profiles;
 * and various support functions.  It also contains a set of functions
 * to read property values stored in the SMF repository.  Finally, it
 * contains the functions required for the "gather info" threads.
 *
 * The daemon maintains a list of structures that represent each IPv4
 * interface found on the system (after doing 'ifconfig -a plumb').
 * This list represents the objects manipulated by the daemon; while
 * the list of llp_t structures represents the configuration details
 * requested by the user (either the automatic defaults or entries in
 * /etc/nwam/llp).  IPv6 interfaces are not tracked in the interfaces
 * list; rather, when the decision is made to make an interface active,
 * IPv6 is brought up in addition to IPv4 (assuming the LLP configuration
 * includes IPv6; this is the default for automatic configuration).
 *
 * When an interface is taken down, we unplumb the IPv6 link-local interface
 * completely, so that dhcpagent and in.ndpd will remove any addresses they've
 * added.  Events are watched on the IPv4 interface alone, which is always
 * present for this version of NWAM.
 *
 * Interfaces are brought up and torn down by a sequence of ifconfig
 * commands (currently posix_spawn'd() by nwamd; the longer-term direction
 * here is to use libinetcfg).
 *
 * Upper Layer Profile management is controlled by user-provided scripts,
 * which should be created in /etc/nwam/ulp.  One script,
 * /etc/nwam/ulp/check-conditions, checks the current network setup and
 * returns the name of the ULP which should be active under the current
 * conditions.  A ULP is specified by two scripts, found in
 * /etc/nwam/ulp/<ulp name>: bringup and teardown.  All scripts are
 * optional; if they do not exist or are not executable, nwamd will
 * simply move on.
 *
 * When an interface has been successfully brought up (signalled by the
 * assignment of an IP address to the interface), the daemon will first
 * teardown the existing ULP (if there is one) by running the teardown
 * script for that ULP.  It will then run the check-conditions script;
 * if the name of a ULP is returned, it runs the bringup script for that
 * ULP.
 *
 * A "gather info" thread is initiated for an interface when it becomes
 * available.  For a wired interface, "available" means the IFF_RUNNING
 * flag is set; wireless interfaces are considered to always be available,
 * so a wireless interface's gather info thread will run once, when it is
 * found at startup.  This thread will do a scan on a wireless interface,
 * and initiate DHCP on a wired interface.  It will then generate an event
 * for the state machine that indicates the availability of a new interface.
 *
 * The ifs_head and associated list pointers are protected by ifs_lock.  Only
 * the main thread may modify the list (single writer), and it does so with the
 * lock held.  As a consequence, the main thread alone may read the list (and
 * examine pointers) without holding any locks.  All other threads must hold
 * ifs_lock for the duration of any examination of the data structures, and
 * must not deal directly in interface pointers.  (A thread may also hold
 * machine_lock to block the main thread entirely in order to manipulate the
 * data; such use is isolated to the door interface.)
 *
 * Functions in this file have comments noting where the main thread alone is
 * the caller.  These functions do not need to acquire the lock.
 *
 * If you hold both ifs_lock and llp_lock, you must take ifs_lock first.
 */

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <syslog.h>
#include <unistd.h>
#include <libscf.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <inetcfg.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <libdllink.h>

#include "defines.h"
#include "structures.h"
#include "functions.h"
#include "variables.h"

static pthread_mutex_t ifs_lock = PTHREAD_MUTEX_INITIALIZER;

static struct interface *ifs_head;
static struct interface *ifs_wired, *ifs_wired_last;
static struct interface *ifs_wireless, *ifs_wireless_last;

static char upper_layer_profile[MAXHOSTNAMELEN];

#define	LOOPBACK_IF	"lo0"

void
show_if_status(const char *ifname)
{
	icfg_if_t intf;
	icfg_handle_t h;
	struct sockaddr_in sin;
	socklen_t addrlen = sizeof (struct sockaddr_in);
	int prefixlen = 0;

	(void) strlcpy(intf.if_name, ifname, sizeof (intf.if_name));
	/* We only display new addr info for v4 interfaces */
	intf.if_protocol = AF_INET;
	if (icfg_open(&h, &intf) != ICFG_SUCCESS) {
		syslog(LOG_ERR, "icfg_open failed on interface %s", ifname);
		return;
	}
	if (icfg_get_addr(h, (struct sockaddr *)&sin, &addrlen, &prefixlen,
	    B_TRUE) != ICFG_SUCCESS) {
		syslog(LOG_ERR, "icfg_get_addr failed on interface %s", ifname);
		icfg_close(h);
		return;
	}
	icfg_close(h);
	report_interface_up(ifname, sin.sin_addr, prefixlen);
}

/*
 * If this interface matches the currently active llp, return B_TRUE.
 * Otherwise, return B_FALSE.
 * Called only from main thread.
 */
boolean_t
interface_is_active(const struct interface *ifp)
{
	if (link_layer_profile == NULL || ifp == NULL)
		return (B_FALSE);

	return (strcmp(ifp->if_name, link_layer_profile->llp_lname) == 0);
}

/*
 * Execute 'ifconfig ifname dhcp wait 0'.
 */
static void
start_dhcp(struct interface *ifp)
{
	int res;
	uint32_t now_s;
	uint64_t timer_s;

	if (ifp->if_lflags & IF_DHCPSTARTED) {
		dprintf("start_dhcp: already started; returning");
		return;
	}
	ifp->if_lflags |= IF_DHCPSTARTED;

	/*
	 * If we need to use DHCP and DHCP is already controlling the
	 * interface, we don't need to do anything.  Otherwise, start it now.
	 */
	if (!(ifp->if_flags & IFF_DHCPRUNNING)) {
		dprintf("launching DHCP on %s", ifp->if_name);
		(void) start_child(IFCONFIG, ifp->if_name, "dhcp", "wait", "0",
		    NULL);
	} else {
		dprintf("DHCP already running on %s; resetting timer",
		    ifp->if_name);
	}
	ifp->if_lflags &= ~IF_DHCPFAILED;

	/* start dhcp timer */
	res = lookup_count_property(OUR_PG, "dhcp_wait_time", &timer_s);
	if (res == -1)
		timer_s = NWAM_DEFAULT_DHCP_WAIT_TIME;

	now_s = NSEC_TO_SEC(gethrtime());
	ifp->if_timer_expire = now_s + timer_s;

	start_timer(now_s, timer_s);
}

static boolean_t
check_svc_up(const char *fmri, int wait_time)
{
	int i;
	char *state;

	for (i = 1; i <= wait_time; i++) {
		state = smf_get_state(fmri);
		if (state == NULL) {
			syslog(LOG_ERR, "smf_get_state(%s) returned \"%s\"",
			    fmri, scf_strerror(scf_error()));
		} else {
			if (strcmp(SCF_STATE_STRING_ONLINE, state) == 0) {
				free(state);
				return (B_TRUE);
			}
			free(state);
		}
		(void) sleep(1);
	}
	return (B_FALSE);
}

boolean_t
ulp_is_active(void)
{
	return (upper_layer_profile[0] != '\0');
}

/*
 * Inputs:
 *   res is a pointer to the scf_resources_t to be released.
 */
static void
release_scf_resources(scf_resources_t *res)
{
	scf_value_destroy(res->sr_val);
	scf_property_destroy(res->sr_prop);
	scf_pg_destroy(res->sr_pg);
	scf_snapshot_destroy(res->sr_snap);
	scf_instance_destroy(res->sr_inst);
	(void) scf_handle_unbind(res->sr_handle);
	scf_handle_destroy(res->sr_handle);
}

/*
 * Inputs:
 *   lpg is the property group to look up
 *   lprop is the property within that group to look up
 * Outputs:
 *   res is a pointer to an scf_resources_t.  This is an internal
 *   structure that holds all the handles needed to get a specific
 *   property from the running snapshot; on a successful return it
 *   contains the scf_value_t that should be passed to the desired
 *   scf_value_get_foo() function, and must be freed after use by
 *   calling release_scf_resources().  On a failure return, any
 *   resources that may have been assigned to res are released, so
 *   the caller does not need to do any cleanup in the failure case.
 * Returns:
 *    0 on success
 *   -1 on failure
 */
static int
get_property_value(const char *lpg, const char *lprop, scf_resources_t *res)
{
	res->sr_inst = NULL;
	res->sr_snap = NULL;
	res->sr_pg = NULL;
	res->sr_prop = NULL;
	res->sr_val = NULL;

	if ((res->sr_handle = scf_handle_create(SCF_VERSION)) == NULL) {
		syslog(LOG_ERR, "scf_handle_create() failed: %s",
		    scf_strerror(scf_error()));
		return (-1);
	}

	if (scf_handle_bind(res->sr_handle) != 0) {
		scf_handle_destroy(res->sr_handle);
		syslog(LOG_ERR, "scf_handle_destroy() failed: %s",
		    scf_strerror(scf_error()));
		return (-1);
	}
	if ((res->sr_inst = scf_instance_create(res->sr_handle)) == NULL) {
		syslog(LOG_ERR, "scf_instance_create() failed: %s",
		    scf_strerror(scf_error()));
		goto failure;
	}
	if (scf_handle_decode_fmri(res->sr_handle, OUR_FMRI, NULL, NULL,
	    res->sr_inst, NULL, NULL, SCF_DECODE_FMRI_REQUIRE_INSTANCE) != 0) {
		syslog(LOG_ERR, "scf_handle_decode_fmri() failed: %s",
		    scf_strerror(scf_error()));
		goto failure;
	}
	if ((res->sr_snap = scf_snapshot_create(res->sr_handle)) == NULL) {
		syslog(LOG_ERR, "scf_snapshot_create() failed: %s",
		    scf_strerror(scf_error()));
		goto failure;
	}
	if (scf_instance_get_snapshot(res->sr_inst, "running",
	    res->sr_snap) != 0) {
		syslog(LOG_ERR, "scf_instance_get_snapshot() failed: %s",
		    scf_strerror(scf_error()));
		goto failure;
	}
	if ((res->sr_pg = scf_pg_create(res->sr_handle)) == NULL) {
		syslog(LOG_ERR, "scf_pg_create() failed: %s",
		    scf_strerror(scf_error()));
		goto failure;
	}
	if (scf_instance_get_pg_composed(res->sr_inst, res->sr_snap, lpg,
	    res->sr_pg) != 0) {
		syslog(LOG_ERR, "scf_instance_get_pg_composed(%s) failed: %s",
		    lpg, scf_strerror(scf_error()));
		goto failure;
	}
	if ((res->sr_prop = scf_property_create(res->sr_handle)) == NULL) {
		syslog(LOG_ERR, "scf_property_create() failed: %s",
		    scf_strerror(scf_error()));
		goto failure;
	}
	if (scf_pg_get_property(res->sr_pg, lprop, res->sr_prop) != 0) {
		syslog(LOG_ERR, "scf_pg_get_property(%s) failed: %s",
		    lprop, scf_strerror(scf_error()));
		goto failure;
	}
	if ((res->sr_val = scf_value_create(res->sr_handle)) == NULL) {
		syslog(LOG_ERR, "scf_value_create() failed: %s",
		    scf_strerror(scf_error()));
		goto failure;
	}
	if (scf_property_get_value(res->sr_prop, res->sr_val) != 0) {
		syslog(LOG_ERR, "scf_property_get_value() failed: %s",
		    scf_strerror(scf_error()));
		goto failure;
	}
	return (0);

failure:
	release_scf_resources(res);
	return (-1);
}

/*
 * Inputs:
 *   lpg is the property group to look up
 *   lprop is the property within that group to look up
 * Outputs:
 *   answer is a pointer to the property value
 * Returns:
 *    0 on success
 *   -1 on failure
 * If successful, the property value is retured in *answer.
 * Otherwise, *answer is undefined, and it is up to the caller to decide
 * how to handle that case.
 */
int
lookup_boolean_property(const char *lpg, const char *lprop, boolean_t *answer)
{
	int result = -1;
	scf_resources_t res;
	uint8_t prop_val;

	if (get_property_value(lpg, lprop, &res) != 0) {
		/*
		 * an error was already logged by get_property_value,
		 * and it released any resources assigned to res before
		 * returning.
		 */
		return (result);
	}
	if (scf_value_get_boolean(res.sr_val, &prop_val) != 0) {
		syslog(LOG_ERR, "scf_value_get_boolean() failed: %s",
		    scf_strerror(scf_error()));
		goto cleanup;
	}
	*answer = (boolean_t)prop_val;
	dprintf("lookup_boolean_property(%s, %s) returns %s", lpg, lprop,
	    *answer ? "TRUE" : "FALSE");
	result = 0;
cleanup:
	release_scf_resources(&res);
	return (result);
}

/*
 * Inputs:
 *   lpg is the property group to look up
 *   lprop is the property within that group to look up
 * Outputs:
 *   answer is a pointer to the property value
 * Returns:
 *    0 on success
 *   -1 on failure
 * If successful, the property value is retured in *answer.
 * Otherwise, *answer is undefined, and it is up to the caller to decide
 * how to handle that case.
 */
int
lookup_count_property(const char *lpg, const char *lprop, uint64_t *answer)
{
	int result = -1;
	scf_resources_t res;

	if (get_property_value(lpg, lprop, &res) != 0) {
		/*
		 * an error was already logged by get_property_value,
		 * and it released any resources assigned to res before
		 * returning.
		 */
		return (result);
	}
	if (scf_value_get_count(res.sr_val, answer) != 0) {
		syslog(LOG_ERR, "scf_value_get_count() failed: %s",
		    scf_strerror(scf_error()));
		goto cleanup;
	}
	dprintf("lookup_count_property(%s, %s) returns %lld", lpg, lprop,
	    *answer);
	result = 0;
cleanup:
	release_scf_resources(&res);
	return (result);
}

void
activate_upper_layer_profile(boolean_t do_dhcp, const char *ifname)
{
	FILE *f;
	char buffer[1024], *cp;
	size_t buflen;
	size_t offset;
	const char bringup[] = "/bringup";
	boolean_t should;
	int res;

	/*
	 * exec the net-svc script to update local config with
	 * any DNS information learned from the DHCP server.
	 */
	if (do_dhcp) {
		res = lookup_boolean_property(OUR_PG, "use_net_svc", &should);
		/*
		 * If the look-up failed, try anyway: only avoid this if we
		 * know for sure not to.
		 */
		if ((res == 0 && should) || (res == -1)) {
			(void) start_child(NET_SVC_METHOD, "start", ifname,
			    NULL);
		}
	}
	f = popen(ULP_DIR "/check-conditions", "r");
	if (f == NULL) {
		/* note that this doesn't happen if the file is missing */
		syslog(LOG_ERR, "popen: check-conditions: %m");
		return;
	}
	/*
	 * We want to build a path to the user's upper layer profile script
	 * that looks like ULP_DIR "/<string we read here>/bringup".  If we
	 * leave some space at the beginning of this buffer for ULP_DIR "/"
	 * that saves us some shuffling later.
	 */
	offset = strlcpy(buffer, ULP_DIR "/", sizeof (buffer));
	cp = fgets(buffer + offset,
	    MIN(sizeof (upper_layer_profile), sizeof (buffer) - offset),
	    f);
	buflen = strlen(buffer);
	if (buffer[buflen - 1] == '\n')
		buffer[--buflen] = '\0';

	/* Need to check for script error before interpreting result */
	res = pclose(f);
	if (res == -1) {
		syslog(LOG_ERR, "check-conditions: pclose: %m");
		return;
	}
	if (WIFEXITED(res)) {
		if (WEXITSTATUS(res) == 0) {
			if (cp == NULL || *cp == '\0') {
				syslog(LOG_DEBUG,
				    "check-conditions returned no information");
			} else {
				(void) strlcpy(upper_layer_profile,
				    buffer + offset,
				    sizeof (upper_layer_profile));
				(void) strlcpy(buffer + buflen, bringup,
				    sizeof (buffer) - buflen);
				(void) start_child(PFEXEC, "-P", "basic",
				    buffer, NULL);
				syslog(LOG_NOTICE,
				    "upper layer profile %s activated",
				    upper_layer_profile);
				report_ulp_activated(upper_layer_profile);
			}
		} else if (access(ULP_DIR "/check-conditions", X_OK) == 0) {
			syslog(LOG_ERR,
			    "check-conditions exited with status %d",
			    WEXITSTATUS(res));
		} else if (errno == ENOENT) {
			syslog(LOG_DEBUG, "check-conditions not present");
		} else {
			syslog(LOG_ERR, "check-conditions: %m");
		}
	} else if (WIFSIGNALED(res)) {
		syslog(LOG_ERR, "check-conditions exit on SIG%s",
		    strsignal(WTERMSIG(res)));
	} else {
		syslog(LOG_ERR,
		    "check-conditions terminated in unknown manner");
	}
}

void
deactivate_upper_layer_profile(void)
{
	char buffer[1024];

	/*
	 * If ULP wasn't defined...
	 */
	if (!ulp_is_active())
		return;

	(void) snprintf(buffer, sizeof (buffer), ULP_DIR "/%s/teardown",
	    upper_layer_profile);
	(void) start_child(PFEXEC, "-P", "basic", buffer, NULL);

	syslog(LOG_NOTICE, "upper layer profile %s deactivated",
	    upper_layer_profile);

	report_ulp_deactivated(upper_layer_profile);

	upper_layer_profile[0] = '\0';
}

/*
 * Returns SUCCESS if the interface is successfully brought up,
 * FAILURE if bringup fails, or WAITING if we'll need to wait on the GUI to run.
 * Called only in the main thread or a thread holding machine_lock.
 */
return_vals_t
bringupinterface(const char *ifname, const char *host, const char *ipv6addr,
    boolean_t ipv6onlink)
{
	struct interface *intf;

	intf = get_interface(ifname);
	if (intf == NULL) {
		syslog(LOG_ERR, "could not bring up interface %s: not in list",
		    ifname);
		return (FAILURE);
	}

	/* check current state; no point going on if flags are 0 */
	if ((intf->if_flags = get_ifflags(ifname, intf->if_family)) == 0) {
		dprintf("bringupinterface(%s): get_ifflags() returned 0",
		    ifname);
		return (FAILURE);
	}

	if (intf->if_type == IF_WIRELESS) {
		switch (handle_wireless_lan(ifname)) {
		case WAITING:
			intf->if_up_attempted = B_TRUE;
			return (WAITING);
		case FAILURE:
			syslog(LOG_INFO, "Could not connect to any WLAN, not "
			    "bringing %s up", ifname);
			return (FAILURE);
		}
	}
	intf->if_up_attempted = B_TRUE;

	/* physical level must now be up; bail out if not */
	intf->if_flags = get_ifflags(ifname, intf->if_family);
	if (!(intf->if_flags & IFF_RUNNING)) {
		dprintf("bringupinterface(%s): physical layer down", ifname);
		return (FAILURE);
	}

	/*
	 * If the link layer profile says that we want v6 then plumb it and
	 * bring it up; if there's a static address, configure it as well.
	 */
	if (ipv6onlink) {
		dprintf("bringupinterface: configuring ipv6");
		(void) start_child(IFCONFIG, ifname, "inet6", "plumb", "up",
		    NULL);
		if (ipv6addr) {
			(void) start_child(IFCONFIG, ifname, "inet6", "addif",
			    ipv6addr, "up", NULL);
		}
	}
	intf->if_v6onlink = ipv6onlink;

	if (strcmp(host, "dhcp") == 0) {
		start_dhcp(intf);
	} else {
		(void) start_child(IFCONFIG, ifname, host, NULL);
		(void) start_child(IFCONFIG, ifname, "up", NULL);
	}

	syslog(LOG_DEBUG, "brought up %s", ifname);

	return (SUCCESS);
}

/* Called only in the main thread */
void
takedowninterface(const char *ifname, libnwam_diag_cause_t cause)
{
	uint64_t flags;
	struct interface *ifp;

	dprintf("takedowninterface(%s, %d)", ifname, (int)cause);

	if ((ifp = get_interface(ifname)) == NULL) {
		dprintf("takedowninterface: can't find interface struct for %s",
		    ifname);
	}

	flags = get_ifflags(ifname, AF_INET);
	if (flags & IFF_DHCPRUNNING) {
		/*
		 * We generally prefer doing a release, as that tells the
		 * server that it can relinquish the lease, whereas drop is
		 * just a client-side operation.  But if we never came up,
		 * release will fail, because dhcpagent does not allow an
		 * interface without a lease to release, so we have to drop in
		 * that case.  So try release first, then fall back to drop.
		 */
		if (start_child(IFCONFIG, ifname, "dhcp", "release", NULL)
		    != 0) {
			(void) start_child(IFCONFIG, ifname, "dhcp", "drop",
			    NULL);
		}
	} else {
		if (flags & IFF_UP)
			(void) start_child(IFCONFIG, ifname, "down", NULL);
		/* need to unset a statically configured addr */
		(void) start_child(IFCONFIG, ifname, "0.0.0.0", "netmask",
		    "0", "broadcast", "0.0.0.0", NULL);
	}

	if (ifp == NULL || ifp->if_v6onlink) {
		/*
		 * Unplumbing the link local interface causes dhcp and ndpd to
		 * remove other addresses they have added.
		 */
		(void) start_child(IFCONFIG, ifname, "inet6", "unplumb", NULL);
	}

	if (ifp == NULL || ifp->if_up_attempted)
		report_interface_down(ifname, cause);

	if (ifp != NULL) {
		/* We're no longer expecting the interface to be up */
		ifp->if_flags = flags & ~IFF_UP;
		if (ifp->if_type == IF_WIRELESS) {
			/* and if it's wireless, it's not running, either */
			ifp->if_flags &= ~IFF_RUNNING;
			disconnect_wlan(ifp->if_name);
		}
		dprintf("takedown interface, zero cached ip address");
		ifp->if_lflags &= ~IF_DHCPSTARTED & ~IF_DHCPACQUIRED;
		ifp->if_ipv4addr = INADDR_ANY;
		ifp->if_up_attempted = B_FALSE;
	}
}

/*
 * Called only in the main thread
 *
 * For IPv6, unplumbing the link local interface causes dhcp and ndpd to remove
 * other addresses they have added.  We watch for routing socket events on the
 * IPv4 interface, which is always enabled, so no need to keep IPv6 around on a
 * switch.
 */
void
clear_cached_address(const char *ifname)
{
	struct interface *ifp;
	uint64_t ifflags;

	if ((ifp = get_interface(ifname)) == NULL) {
		dprintf("clear_cached_address: can't find interface struct "
		    "for %s", ifname);
		(void) start_child(IFCONFIG, ifname, "inet6", "unplumb", NULL);
		return;
	}
	if (ifp->if_v6onlink)
		(void) start_child(IFCONFIG, ifname, "inet6", "unplumb", NULL);
	ifflags = get_ifflags(ifname, AF_INET);
	if ((ifflags & IFF_UP) && !(ifflags & IFF_RUNNING))
		zero_out_v4addr(ifname);
	ifp->if_ipv4addr = INADDR_ANY;
	ifp->if_lflags &= ~IF_DHCPFLAGS;
}

/*
 * Add an interface struct to the interface list.  The list is
 * partially ordered; all the wired interfaces appear first,
 * followed by all the wireless interfaces.  New interfaces are
 * added at the end of the appropriate list section.
 */
static void
interface_list_insert(struct interface *ifp)
{
	struct interface **headpp, **lastpp;
	struct interface *pchain, *nextp;

	if (pthread_mutex_lock(&ifs_lock) != 0)
		return;

	switch (ifp->if_type) {
	case IF_WIRELESS:
		/*
		 * Wireless entries are in the wireless list, and are chained
		 * after the wired entries.  If there are no wired entries, then
		 * chain on main list.
		 */
		headpp = &ifs_wireless;
		lastpp = &ifs_wireless_last;
		pchain = ifs_wired_last;
		nextp = NULL;
		break;

	case IF_WIRED:
		/*
		 * Wired entries are on the wired list, and are chained before
		 * the wireless entries.
		 */
		headpp = &ifs_wired;
		lastpp = &ifs_wired_last;
		pchain = NULL;
		nextp = ifs_wireless;
		break;

	default:
		/* don't add to the list */
		(void) pthread_mutex_unlock(&ifs_lock);
		return;
	}

	/* Connect into the correct list */
	if (*lastpp == NULL) {
		/*
		 * If there's a previous list, then wire to the end of
		 * that, as we're the new head here.
		 */
		if (pchain != NULL)
			pchain->if_next = ifp;
		*headpp = ifp;
	} else {
		(*lastpp)->if_next = ifp;
	}
	*lastpp = ifp;

	ifp->if_next = nextp;

	/* Fix up the main list; it's always wired-first */
	ifs_head = ifs_wired == NULL ? ifs_wireless : ifs_wired;

	(void) pthread_mutex_unlock(&ifs_lock);
}

/*
 * Returns the interface structure upon success.  Returns NULL and sets
 * errno upon error.
 */
struct interface *
add_interface(sa_family_t family, const char *name, uint64_t flags)
{
	struct interface *i;
	libnwam_interface_type_t iftype;

	if (name == NULL)
		return (NULL);

	dprintf("add_interface: found interface %s", name);
	if (family == AF_INET6) {
		/*
		 * we don't track IPv6 interfaces separately from their
		 * v4 counterparts; a link either has v4 only, or both
		 * v4 and v6, so we only maintain a v4 interface struct.
		 */
		dprintf("not adding v6 interface for %s", name);
		return (NULL);
	} else if (family != AF_INET) {
		/*
		 * the classic "shouldn't happen"...
		 */
		dprintf("not adding af %d interface for %s", family, name);
		return (NULL);
	}

	if ((iftype = find_if_type(name)) == IF_TUN) {
		/*
		 * for now, we're ignoring tunnel interfaces (we expect
		 * them to be entirely manipulated by higher layer profile
		 * activation/deactivation scripts)
		 */
		dprintf("%s is a tunnel interface; ignoring", name);
		return (NULL);
	}

	if ((i = calloc(1, sizeof (*i))) == NULL) {
		dprintf("add_interface: malloc failed");
		return (NULL);
	}

	(void) strlcpy(i->if_name, name, sizeof (i->if_name));
	i->if_family = family;
	i->if_type = iftype;
	i->if_flags = flags == 0 ? get_ifflags(name, family) : flags;

	dprintf("added interface %s of type %s af %d; is %savailable",
	    i->if_name, if_type_str(i->if_type), i->if_family,
	    (i->if_flags & IFF_RUNNING) ? "" : "not ");

	interface_list_insert(i);

	if (iftype == IF_WIRELESS)
		add_wireless_if(name);

	return (i);
}

/*
 * This is called only by the main thread.
 */
void
remove_interface(const char *ifname)
{
	struct interface *ifp, *prevp = NULL;

	if (pthread_mutex_lock(&ifs_lock) != 0)
		return;
	for (ifp = ifs_head; ifp != NULL; ifp = ifp->if_next) {
		if (strcmp(ifname, ifp->if_name) == 0) {
			if (prevp == NULL)
				ifs_head = ifp->if_next;
			else
				prevp->if_next = ifp->if_next;
			if (ifp == ifs_wired_last) {
				if ((ifs_wired_last = prevp) == NULL)
					ifs_wired = NULL;
			} else if (ifp == ifs_wired) {
				ifs_wired = ifp->if_next;
			}
			if (ifp == ifs_wireless_last) {
				if (prevp != NULL &&
				    prevp->if_type != IF_WIRELESS)
					prevp = NULL;
				if ((ifs_wireless_last = prevp) == NULL)
					ifs_wireless = NULL;
			} else if (ifp == ifs_wireless) {
				ifs_wireless = ifp->if_next;
			}
			break;
		}
		prevp = ifp;
	}
	(void) pthread_mutex_unlock(&ifs_lock);

	remove_wireless_if(ifname);

	if (ifp != NULL && ifp->if_thr != 0) {
		(void) pthread_cancel(ifp->if_thr);
		(void) pthread_join(ifp->if_thr, NULL);
	}
	free(ifp);
}

/*
 * Searches for an interface and returns the interface structure if found.
 * Returns NULL otherwise.  The caller must either be holding ifs_lock, or be
 * in the main thread.
 */
struct interface *
get_interface(const char *name)
{
	struct interface *ifp;

	if (name == NULL)
		return (NULL);

	for (ifp = ifs_head; ifp != NULL; ifp = ifp->if_next) {
		if (strcmp(name, ifp->if_name) == 0)
			break;
	}
	return (ifp);
}

/*
 * Check to see whether the interface could be started.  If the IFF_RUNNING
 * flag is set, then we're in good shape.  Otherwise, wireless interfaces are
 * special: we'll attempt to connect to an Access Point as part of the start-up
 * procedure, and IFF_RUNNING won't be present until that's done, so assume
 * that all wireless interfaces are good to go.  This is just an optimization;
 * we could start everything.
 */
static boolean_t
is_startable(struct interface *ifp)
{
	ifp->if_flags = get_ifflags(ifp->if_name, ifp->if_family);
	if (ifp->if_flags & IFF_RUNNING)
		return (B_TRUE);
	return (ifp->if_type == IF_WIRELESS);
}

/*
 * For wireless interface, we will try to find out available wireless
 * network; for wired, if dhcp should be used, start it now to try to
 * avoid delays there.
 *
 * For the real code, we should pass back the network information
 * gathered.  Note that the state engine will then use the llp to
 * determine which interface should be set up.
 *
 * ifs_lock is not held on entry.  The caller will cancel this thread and wait
 * for it to exit if the interface is to be deleted.
 */
static void *
gather_interface_info(void *arg)
{
	struct interface *i = arg;
	int retv;

	dprintf("Start gathering info for %s", i->if_name);

	switch (i->if_type) {
	case IF_WIRELESS:
		/* This generates EV_NEWAP when successful */
		retv = launch_wireless_scan(i->if_name);
		if (retv != 0)
			dprintf("didn't launch wireless scan: %s",
			    strerror(retv));
		break;
	case IF_WIRED:
		if (llp_get_ipv4src(i->if_name) == IPV4SRC_DHCP) {
			/*
			 * The following is to avoid locking up the state
			 * machine as it is currently the choke point.  We
			 * start dhcp with a wait time of 0; later, if we see
			 * the link go down (IFF_RUNNING is cleared), we will
			 * drop the attempt.
			 */
			if (is_startable(i))
				start_dhcp(i);
		}
		(void) np_queue_add_event(EV_LINKUP, i->if_name);
		break;
	}

	dprintf("Done gathering info for %s", i->if_name);
	i->if_thr = 0;
	return (NULL);
}

/*
 * Caller uses this function to walk through the whole interface list.
 * For each interface, the caller provided walker is called with
 * the interface and arg as parameters, and with the ifs_lock held.
 */
void
walk_interface(void (*walker)(struct interface *, void *), void *arg)
{
	struct interface *ifp;

	if (pthread_mutex_lock(&ifs_lock) != 0)
		return;
	for (ifp = ifs_head; ifp != NULL; ifp = ifp->if_next)
		walker(ifp, arg);
	(void) pthread_mutex_unlock(&ifs_lock);
}

static void
print_interface_list(void)
{
	struct interface *wp;

	dprintf("Walking interface list; starting with wired interfaces");
	for (wp = ifs_head; wp != NULL; wp = wp->if_next) {
		if (wp == ifs_wireless)
			dprintf("Now wireless interfaces");
		dprintf("==> %s", wp->if_name);
	}
}

/*
 * Walker function passed to icfg_iterate_if() below - the icfg_if_it *
 * argument is guaranteed to be non-NULL by icfg_iterate_if(),
 * since the function it uses to generate the list - icfg_get_if_list()) -
 * guarantees this.
 */
/* ARGSUSED */
static int
do_add_interface(icfg_if_t *intf, void *arg)
{
	uint64_t flags = get_ifflags(intf->if_name, intf->if_protocol);

	/* We don't touch loopback interface. */
	if (flags & IFF_LOOPBACK)
		return (ICFG_SUCCESS);

	/* If adding fails, just ignore that interface... */
	(void) add_interface(intf->if_protocol, intf->if_name, flags);

	return (ICFG_SUCCESS);
}

/*
 * Walker function passed to icfg_iterate_if() below - the icfg_if_it *
 * argument is guaranteed to be non-NULL by icfg_iterate_if(),
 * since the function it uses to generate the list - icfg_get_if_list()) -
 * guarantees this.
 */
/* ARGSUSED */
static int
do_unplumb_if(icfg_if_t *intf, void *arg)
{
	uint64_t flags = get_ifflags(intf->if_name, intf->if_protocol);

	/* We don't touch loopback interface. */
	if (flags & IFF_LOOPBACK)
		return (ICFG_SUCCESS);

	(void) start_child(IFCONFIG, intf->if_name,
	    intf->if_protocol == AF_INET6 ? "inet6" : "inet", "unplumb", NULL);

	return (ICFG_SUCCESS);
}

void
initialize_interfaces(void)
{
	int numifs;
	unsigned int wait_time = 1;
	boolean_t found_nonlo_if;

	/*
	 * Bring down all interfaces bar lo0.
	 */
	(void) icfg_iterate_if(AF_INET, ICFG_PLUMBED, NULL, do_unplumb_if);
	(void) icfg_iterate_if(AF_INET6, ICFG_PLUMBED, NULL, do_unplumb_if);

	/*
	 * In case dhcpagent is running...  If it is running, when
	 * we do another DHCP command on the same interface later, it may
	 * be confused.  Just kill dhcpagent to simplify handling.
	 */
	dprintf("killing dhcpagent");
	(void) start_child(PKILL, "-z", zonename, "dhcpagent", NULL);

	/*
	 * Really we should walk the device tree instead of doing
	 * the 'ifconfig -a plumb'.  On the first reconfigure boot
	 * (after install) 'ifconfig -a plumb' comes back quickly
	 * without any devices configured if we start before
	 * 'svc:/system/device/local' finishes.  We can't create a
	 * dependency on device/local because that would create a
	 * dependency loop through 'svc:/system/filesystem/usr'.  So
	 * instead we wait on device/local.
	 */
	if (!check_svc_up(DEV_LOCAL_SVC_FMRI, 60))
		syslog(LOG_WARNING, DEV_LOCAL_SVC_FMRI " never came up");

	for (;;) {
		icfg_if_t *if_list;

		(void) start_child(IFCONFIG, "-a", "plumb", NULL);

		/*
		 * There are cases where we get here and the devices list
		 * still isn't initialized yet.  Hang out until we see
		 * something other than loopback.
		 */
		if (icfg_get_if_list(&if_list, &numifs, AF_INET, ICFG_PLUMBED)
		    != ICFG_SUCCESS) {
			syslog(LOG_ERR, "couldn't get the interface list: %m");
			numifs = 0;
			if_list = NULL;
		} else {
			dprintf("found %d plumbed interfaces", numifs);
		}

		found_nonlo_if = B_FALSE;
		while (numifs > 0 && !found_nonlo_if) {
			if (strcmp(if_list[--numifs].if_name, LOOPBACK_IF) != 0)
				found_nonlo_if = B_TRUE;
		}
		icfg_free_if_list(if_list);

		if (found_nonlo_if)
			break;

		(void) sleep(wait_time);
		wait_time *= 2;
		if (wait_time > NWAM_IF_WAIT_DELTA_MAX)
			wait_time = NWAM_IF_WAIT_DELTA_MAX;
	}

	(void) dladm_init_linkprop(DATALINK_ALL_LINKID, B_FALSE);

	(void) icfg_iterate_if(AF_INET, ICFG_PLUMBED, NULL, do_add_interface);

	print_interface_list();

}

/*
 * Walker function used to start info gathering of each interface.  Caller
 * holds ifs_lock.
 */
void
start_if_info_collect(struct interface *ifp, void *arg)
{
	int retv;
	pthread_attr_t attr;

	/*
	 * In certain cases we need to refresh the cached flags value as
	 * it may be stale.  Notably, we can miss a DL_NOTE_LINK_DOWN
	 * event after we initialize interfaces before the routing thread
	 * is launched.
	 */
	if (arg != NULL)
		ifp->if_flags = get_ifflags(ifp->if_name, ifp->if_family);

	/*
	 * Only if the cable of the wired interface is
	 * plugged in, start gathering info from it.
	 */
	if (!is_startable(ifp)) {
		dprintf("not gathering info on %s; not running", ifp->if_name);
		return;
	}

	/*
	 * This is a "fresh start" for the interface, so clear old DHCP flags.
	 */
	ifp->if_lflags &= ~IF_DHCPFLAGS;

	(void) pthread_attr_init(&attr);
	(void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if ((retv = pthread_create(&ifp->if_thr, &attr, gather_interface_info,
	    ifp)) != 0) {
		syslog(LOG_ERR, "create interface gathering thread: %s",
		    strerror(retv));
		exit(EXIT_FAILURE);
	} else {
		dprintf("interface info thread for %s: %d", ifp->if_name,
		    ifp->if_thr);
	}
}

/*
 * Walker function used to check timer for each interface.
 * If timer has expired, generate a timer event for the
 * interface.
 */
static void
iftimer(struct interface *ifp, void *arg)
{
	uint32_t now = (uint32_t)(uintptr_t)arg;

	if (ifp->if_timer_expire == 0)
		return;

	if (ifp->if_timer_expire > now) {
		start_timer(now, ifp->if_timer_expire - now);
		return;
	}

	ifp->if_timer_expire = 0;

	(void) np_queue_add_event(EV_TIMER, ifp->if_name);
}

void
check_interface_timers(uint32_t now)
{
	walk_interface(iftimer, (void *)(uint32_t)now);
}

libnwam_interface_type_t
find_if_type(const char *name)
{
	uint32_t media;
	libnwam_interface_type_t type;

	if (name == NULL) {
		dprintf("find_if_type: no ifname; returning IF_UNKNOWN");
		return (IF_UNKNOWN);
	}

	type = IF_WIRED;
	if (dladm_name2info(name, NULL, NULL, NULL, &media) !=
	    DLADM_STATUS_OK) {
		if (strncmp(name, "ip.tun", 6) == 0 ||
		    strncmp(name, "ip6.tun", 7) == 0 ||
		    strncmp(name, "ip.6to4tun", 10) == 0)
			/*
			 * We'll need to update our tunnel detection once
			 * the clearview/tun project is integrated; tunnel
			 * names won't necessarily be ip.tunN.
			 */
			type = IF_TUN;
	} else if (media == DL_WIFI) {
		type = IF_WIRELESS;
	}

	return (type);
}

const char *
if_type_str(libnwam_interface_type_t type)
{
	switch (type) {
	case IF_WIRED:
		return ("wired");
	case IF_WIRELESS:
		return ("wireless");
	case IF_TUN:
		return ("tunnel");
	case IF_UNKNOWN:
	default:
		return ("unknown type");
	}
}

/*
 * This is called by the routing socket thread to update the IPv4 address on an
 * interface.  The routing socket thread cannot touch the interface structures
 * without holding the global lock, because interface structures can be
 * deleted.
 */
void
update_interface_v4_address(const char *ifname, in_addr_t addr)
{
	struct in_addr in;
	struct interface *ifp;

	if (pthread_mutex_lock(&ifs_lock) == 0) {
		if ((ifp = get_interface(ifname)) == NULL) {
			dprintf("no interface struct for %s; ignoring message",
			    ifname);
		} else if (ifp->if_ipv4addr != addr) {
			ifp->if_ipv4addr = addr;
			in.s_addr = addr;
			dprintf("cached new address %s for link %s",
			    inet_ntoa(in), ifname);
			(void) np_queue_add_event(EV_NEWADDR, ifname);
		} else {
			dprintf("same address on %s; no event", ifname);
		}
		(void) pthread_mutex_unlock(&ifs_lock);
	}
}

/*
 * This is called by the routing socket thread to update the flags on a given
 * IPv4 interface.  If the interface has changed state, then we launch an event
 * or a thread as appropriate.
 */
void
update_interface_flags(const char *ifname, int newflags)
{
	struct interface *ifp;
	int oldflags;

	if (pthread_mutex_lock(&ifs_lock) == 0) {
		if ((ifp = get_interface(ifname)) == NULL) {
			dprintf("no interface data for %s; ignoring message",
			    ifname);
		} else {
			/*
			 * Check for toggling of the IFF_RUNNING flag.
			 *
			 * On any change in the flag value, we turn off the
			 * DHCP flags; the change in the RUNNING state
			 * indicates a "fresh start" for the interface, so we
			 * should try dhcp again.
			 *
			 * If the interface was not plugged in and now it is,
			 * start info collection.
			 *
			 * If it was plugged in and now it is unplugged,
			 * generate an event.
			 */
			oldflags = ifp->if_flags;
			if ((oldflags & IFF_RUNNING) !=
			    (newflags & IFF_RUNNING)) {
				ifp->if_lflags &= ~IF_DHCPFLAGS;
			}
			if (!(newflags & IFF_DHCPRUNNING))
				ifp->if_lflags &= ~IF_DHCPFLAGS;
			ifp->if_flags = newflags;
			if (!(oldflags & IFF_RUNNING) &&
			    (newflags & IFF_RUNNING)) {
				start_if_info_collect(ifp, NULL);
			} else if ((oldflags & IFF_RUNNING) &&
			    !(newflags & IFF_RUNNING)) {
				(void) np_queue_add_event(EV_LINKDROP, ifname);
			} else {
				dprintf("no-event flag change on %s: %x -> %x",
				    ifp->if_name, oldflags, newflags);
			}
		}
		(void) pthread_mutex_unlock(&ifs_lock);
	}
}

/*
 * Called only in main thread.  Note that wireless interfaces are considered
 * "ok" even if the IFF_RUNNING bit isn't set.  This is because AP attach
 * occurs as part of the LLP selection process.
 */
boolean_t
is_interface_ok(const char *ifname)
{
	boolean_t is_ok = B_FALSE;
	struct interface *ifp;

	if ((ifp = get_interface(ifname)) != NULL &&
	    !(ifp->if_lflags & IF_DHCPFAILED) && is_startable(ifp))
		is_ok = B_TRUE;
	return (is_ok);
}

/*
 * Return the interface type for a given interface name.
 */
libnwam_interface_type_t
get_if_type(const char *ifname)
{
	libnwam_interface_type_t ift = IF_UNKNOWN;
	struct interface *ifp;

	if (pthread_mutex_lock(&ifs_lock) == 0) {
		if ((ifp = get_interface(ifname)) != NULL)
			ift = ifp->if_type;
		(void) pthread_mutex_unlock(&ifs_lock);
	}
	return (ift);
}

/*
 * Get the interface state for storing in llp_t.  This is used only with the
 * doors interface to return status flags.
 */
void
get_interface_state(const char *ifname, boolean_t *dhcp_failed,
    boolean_t *link_up)
{
	struct interface *ifp;

	*dhcp_failed = *link_up = B_FALSE;
	if (pthread_mutex_lock(&ifs_lock) == 0) {
		if ((ifp = get_interface(ifname)) != NULL) {
			if (ifp->if_lflags & IF_DHCPFAILED)
				*dhcp_failed = B_TRUE;
			if (ifp->if_flags & IFF_UP)
				*link_up = B_TRUE;
		}
		(void) pthread_mutex_unlock(&ifs_lock);
	}
}

/*
 * Dump out the interface state via debug messages.
 */
void
print_interface_status(void)
{
	struct interface *ifp;
	struct in_addr ina;

	if (pthread_mutex_lock(&ifs_lock) == 0) {
		if (upper_layer_profile[0] != '\0')
			dprintf("upper layer profile %s active",
			    upper_layer_profile);
		else
			dprintf("no upper layer profile active");
		for (ifp = ifs_head; ifp != NULL; ifp = ifp->if_next) {
			ina.s_addr = ifp->if_ipv4addr;
			dprintf("I/F %s af %d flags %llX lflags %X type %d "
			    "expire %u v6 %son-link up %sattempted addr %s",
			    ifp->if_name, ifp->if_family, ifp->if_flags,
			    ifp->if_lflags, ifp->if_type, ifp->if_timer_expire,
			    ifp->if_v6onlink ? "" : "not ",
			    ifp->if_up_attempted ? "" : "not ",
			    inet_ntoa(ina));
		}
		(void) pthread_mutex_unlock(&ifs_lock);
	}
}
