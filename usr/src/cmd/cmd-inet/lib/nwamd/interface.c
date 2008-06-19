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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains the routines that manipulate interfaces, the
 * list of interfaces present on the system, and upper layer profiles;
 * and various support functions.  It also contains the functions used
 * to display various bits of informations and queries for the user
 * using /usr/bin/zenity, and a set of functions to read property
 * values stored in the SMF repository.  Finally, it contains the
 * functions required for the "gather info" threads.
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
 */

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <sys/sockio.h>
#include <syslog.h>
#include <unistd.h>
#include <libscf.h>
#include <utmpx.h>
#include <pwd.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <inetcfg.h>
#include <locale.h>
#include <libintl.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/sysmacros.h>
#include <libdllink.h>

#include "defines.h"
#include "structures.h"
#include "functions.h"
#include "variables.h"

static struct interface *ifs_head = NULL;
static struct interface *ifs_wired = NULL;
static struct interface *ifs_wireless = NULL;

static char upper_layer_profile[MAXHOSTNAMELEN];

static void print_interface_list();
static struct interface *get_next_interface(struct interface *);

#define	LOOPBACK_IF	"lo0"

void
display(const char *msg)
{
	char cmd[1024];

	dprintf("display('%s')", STRING(msg));
	if (valid_graphical_user(B_FALSE)) {
		(void) snprintf(cmd, sizeof (cmd), "--text=%s", msg);
		(void) start_child(ZENITY, "--info", cmd, NULL);
	} else {
		syslog(LOG_INFO, "%s", msg);
	}
}

void
show_if_status(const char *ifname)
{
	char msg[128];
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
	(void) snprintf(msg, sizeof (msg),
	    gettext("Brought interface %s up, got address %s."), ifname,
	    inet_ntoa(sin.sin_addr));
	display(msg);
}

/*
 * If this interface matches the currently active llp, return B_TRUE.
 * Otherwise, return B_FALSE.
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

	if ((ifp->if_lflags & IF_DHCPSTARTED) != 0) {
		dprintf("start_dhcp: already started; returning");
		return;
	}
	ifp->if_lflags |= IF_DHCPSTARTED;

	(void) start_child(IFCONFIG, ifp->if_name, "dhcp", "wait", "0", NULL);

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
	char buffer[1024];
	size_t buflen;
	size_t offset;
	const char bringup[] = "/bringup";
	boolean_t should;
	int res;

	res = lookup_boolean_property(OUR_PG, "use_net_svc", &should);
	/*
	 * If the look-up failed, try anyway: only avoid this if we
	 * know for sure not to.
	 */
	if ((res == 0 && should) || (res == -1)) {
		if (check_svc_up(NET_SVC_FMRI, 5)) {
			/*
			 * If doing dhcp, pass in specific interface
			 * name to net-svc so dhcpinfo can specify it.
			 */
			(void) start_child(NET_SVC_METHOD, "start",
			    do_dhcp ? ifname : NULL, NULL);
		} else {
			syslog(LOG_WARNING, "timed out when waiting "
			    "for %s to come up, start method %s not "
			    "executed", NET_SVC_FMRI, NET_SVC_METHOD);
		}
	}
	f = popen(ULP_DIR "/check-conditions", "r");
	if (f == NULL)
		return;
	/*
	 * We want to build a path to the user's upper layer profile script
	 * that looks like ULP_DIR "/<string we read here>/bringup".  If we
	 * leave some space at the beginning of this buffer for ULP_DIR "/"
	 * that saves us some shuffling later.
	 */
	offset = sizeof (ULP_DIR);
	if (fgets(buffer + offset,
	    MIN(sizeof (upper_layer_profile), sizeof (buffer) - offset),
	    f) == NULL) {
		(void) pclose(f);
		return; /* EOF before anything read */
	}
	(void) pclose(f);
	(void) memcpy(buffer, ULP_DIR "/", sizeof (ULP_DIR));
	buflen = strlen(buffer);
	if (buffer[buflen - 1] == '\n')
		buffer[--buflen] = '\0';
	(void) memcpy(upper_layer_profile, buffer + offset,
	    buflen + 1 - offset);
	(void) strlcpy(buffer + buflen, bringup, sizeof (buffer) - buflen);
	(void) start_child(PFEXEC, "-P", "basic", buffer, NULL);

	syslog(LOG_NOTICE, "upper layer profile %s activated",
	    upper_layer_profile);
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

	upper_layer_profile[0] = '\0';
}

/*
 * Returns B_TRUE if the interface is successfully brought up;
 * B_FALSE if bringup fails.
 */
boolean_t
bringupinterface(const char *ifname, const char *host, const char *ipv6addr,
    boolean_t ipv6onlink)
{
	boolean_t do_dhcp;
	struct interface *intf;
	uint64_t ifflags;

	intf = get_interface(ifname);
	if (intf == NULL) {
		syslog(LOG_ERR, "could not bring up interface %s: not in list",
		    ifname);
		return (B_FALSE);
	}

	/* check current state; no point going on if flags are 0 */
	if ((ifflags = get_ifflags(ifname, intf->if_family)) == 0) {
		dprintf("bringupinterface(%s): get_ifflags() returned 0",
		    ifname);
		return (B_FALSE);
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

	do_dhcp = (strcmp(host, "dhcp") == 0);

	/*
	 * If we need to use DHCP and DHCP is already controlling
	 * the interface, we don't need to do anything.
	 */
	if (do_dhcp && (ifflags & IFF_DHCPRUNNING) != 0) {
		dprintf("bringupinterface: nothing to do");
		return (B_TRUE);
	}

	if (intf->if_type == IF_WIRELESS) {
		if (!handle_wireless_lan(intf)) {
			syslog(LOG_INFO, "Could not connect to any WLAN, not "
			    "bringing %s up", ifname);
			return (B_FALSE);
		}
	}

	if (do_dhcp) {
		start_dhcp(intf);
	} else {
		(void) start_child(IFCONFIG, ifname, host, NULL);
		(void) start_child(IFCONFIG, ifname, "up", NULL);
	}

	return (B_TRUE);
}

void
takedowninterface(const char *ifname, boolean_t popup, boolean_t v6onlink)
{
	uint64_t flags;
	struct interface *ifp;

	dprintf("takedowninterface(%s, %s, %s)", ifname,
	    BOOLEAN_TO_STRING(popup), BOOLEAN_TO_STRING(v6onlink));

	if ((ifp = get_interface(ifname)) == NULL) {
		dprintf("takedowninterface: can't find interface struct for %s",
		    ifname);
	} else {
		if (ifp->if_lflags & IF_DHCPFAILED) {
			/*
			 * We're here because of a dhcp failure, and
			 * we actually want dhcp to keep trying.  So
			 * don't take the interface down.
			 */
			dprintf("takedowninterface: still trying for dhcp on "
			    "%s, so will not take down interface", ifname);
			return;
		}
	}

	flags = get_ifflags(ifname, AF_INET);
	if ((flags & IFF_DHCPRUNNING) != 0) {
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
		if ((flags & IFF_UP) != 0)
			(void) start_child(IFCONFIG, ifname, "down", NULL);
		/* need to unset a statically configured addr */
		(void) start_child(IFCONFIG, ifname, "0.0.0.0", "netmask",
		    "0", "broadcast", "0.0.0.0", NULL);
	}

	if (v6onlink) {
		/*
		 * Unplumbing the link local interface causes dhcp and ndpd to
		 * remove other addresses they have added.
		 */
		(void) start_child(IFCONFIG, ifname, "inet6", "unplumb", NULL);
	}

	if (ifp->if_type == IF_WIRELESS)
		(void) dladm_wlan_disconnect(ifp->if_linkid);

	dprintf("takedown interface, free cached ip address");
	if (ifp != NULL) {
		free(ifp->if_ipaddr);
		ifp->if_ipaddr = NULL;
	}
	if (popup) {
		char msg[64]; /* enough to hold this string */

		(void) snprintf(msg, sizeof (msg),
		    gettext("Took interface %s down."), ifname);
		display(msg);
	}
}

/*
 * Take down all known interfaces.  If ignore_if is non-null, an
 * active (IFF_UP) interface whose name matches ignore_if will *not*
 * be taken down.
 */
void
take_down_all_ifs(const char *ignore_if)
{
	struct interface *ifp;
	uint64_t flags;
	boolean_t ignore_set = (ignore_if != NULL);

	deactivate_upper_layer_profile();

	for (ifp = get_next_interface(NULL); ifp != NULL;
	    ifp = get_next_interface(ifp)) {
		if (ignore_set && strcmp(ifp->if_name, ignore_if) == 0)
			continue;
		flags = get_ifflags(ifp->if_name, ifp->if_family);
		if ((flags & IFF_UP) != 0) {
			takedowninterface(ifp->if_name, B_FALSE,
			    ifp->if_family == AF_INET6);
		}
	}
}

static struct interface *
get_next_interface(struct interface *ifp)
{
	return (ifp == NULL ? ifs_head : ifp->if_next);
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
	struct interface **wpp;
	struct interface *endp;
	boolean_t first_wireless = B_FALSE;
	boolean_t first_wired = B_FALSE;

	switch (ifp->if_type) {
	case IF_WIRELESS:
		first_wireless = (ifs_wireless == NULL);
		wpp = &ifs_wireless;
		endp = NULL;
		break;

	case IF_WIRED:
		first_wired = (ifs_wired == NULL);
		wpp = &ifs_wired;
		endp = ifs_wireless;
		break;

	default:
		/* don't add to the list */
		return;
	}

	/* set list head if this is the first entry */
	if (ifs_head == NULL) {
		ifs_head = *wpp = ifp;
		ifp->if_next = NULL;
		return;
	}

	if (*wpp != NULL) {
		while (*wpp != endp)
			wpp = &(*wpp)->if_next;
	}
	*wpp = ifp;
	ifp->if_next = endp;

	/* update list head if we just inserted the first wired interface */
	if (first_wired)
		ifs_head = ifs_wired;

	/* link sections if we just inserted the first wireless interface */
	if (first_wireless) {
		wpp = &ifs_wired;
		while (*wpp != NULL)
			wpp = &(*wpp)->if_next;
		*wpp = ifs_wireless;
	}
}

/*
 * Returns the interface structure upon success.  Returns NULL and sets
 * errno upon error.  If lr is null then it will look up the information
 * needed.
 *
 * Note that given the MT nature of this program we are almost certainly
 * racing for this structure.  That needs to be fixed.
 */
struct interface *
add_interface(sa_family_t family, const char *name, uint64_t flags)
{
	struct interface *i;
	datalink_id_t linkid = DATALINK_INVALID_LINKID;
	enum interface_type iftype;

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

	if ((i = malloc(sizeof (*i))) == NULL) {
		dprintf("add_interface: malloc failed");
		return (NULL);
	}

	i->if_name = strdup(name);
	if (i->if_name == NULL) {
		free(i);
		dprintf("add_interface: malloc failed");
		return (NULL);
	}
	i->if_ipaddr = NULL;
	i->if_family = family;
	i->if_type = iftype;
	i->if_flags = flags == 0 ? get_ifflags(name, family) : flags;
	i->if_lflags = 0;
	i->if_timer_expire = 0;

	/*
	 * If linkid is DATALINK_INVALID_LINKID, it is an IP-layer only
	 * interface.
	 */
	(void) dladm_name2info(name, &linkid, NULL, NULL, NULL);
	i->if_linkid = linkid;

	dprintf("added interface %s of type %s af %d; is %savailable",
	    i->if_name, if_type_str(i->if_type), i->if_family,
	    ((i->if_type == IF_WIRELESS) ||
	    ((i->if_flags & IFF_RUNNING) != 0)) ? "" : "not ");

	interface_list_insert(i);

	return (i);
}

/*
 * Searches for an interface and returns the interface structure if found.
 * Returns NULL otherwise.  errno is set upon error exit.
 */
struct interface *
get_interface(const char *name)
{
	struct interface *i;

	if (name == NULL)
		return (NULL);

	for (i = ifs_head; i != NULL; i = i->if_next) {
		if (strcmp(name, i->if_name) == 0) {
			return (i);
		}
	}

	return (NULL);
}

/*
 * Checks interface flags and, if IFF_DHCPRUNNING and !IFF_UP, does
 * an 'ifconfig ifname dhcp drop'.
 */
void
check_drop_dhcp(struct interface *ifp)
{
	uint64_t flags = get_ifflags(ifp->if_name, ifp->if_family);

	if (!(flags & IFF_DHCPRUNNING) || (flags & IFF_UP)) {
		dprintf("check_drop_dhcp: nothing to do (flags=0x%llx)", flags);
		return;
	}

	(void) start_child(IFCONFIG, ifp->if_name, "dhcp", "drop", NULL);
}

/*
 * For wireless interface, we will try to find out available wireless
 * network; for wired, if dhcp should be used, start it now to try to
 * avoid delays there.
 *
 * For the real code, we should pass back the network information
 * gathered.  Note that the state engine will then use the llp to
 * determine which interface should be set up...
 */
static void *
gather_interface_info(void *arg)
{
	struct interface *i = arg;
	llp_t *llp;

	assert(i != NULL);

	dprintf("Start gathering info for %s", i->if_name);

	switch (i->if_type) {
	case IF_WIRELESS:
		(void) scan_wireless_nets(i);
		break;
	case IF_WIRED:
		/*
		 * It should not happen as the llp list should be done when
		 * this function is called.  But let the state engine decide
		 * what to do.
		 */
		if ((llp = llp_lookup(i->if_name)) == NULL)
			break;
		/*
		 * The following is to avoid locking up the state machine
		 * as it is currently the choke point.  We start dhcp with
		 * a wait time of 0; later, if we see the link go down
		 * (IFF_RUNNING is cleared), we will drop the attempt.
		 */
		if (llp->llp_ipv4src == IPV4SRC_DHCP && is_plugged_in(i))
			start_dhcp(i);
		break;
	default:
		/* For other types, do not do anything. */
		return (NULL);
	}

	gen_newif_event(i);

	dprintf("Done gathering info for %s", i->if_name);
	return (NULL);
}

void
gen_newif_event(struct interface *i)
{
	struct np_event *e;

	e = calloc(1, sizeof (struct np_event));
	if (e == NULL) {
		dprintf("gen_newif_event: calloc failed");
		return;
	}
	e->npe_name = strdup(i->if_name);
	if (e->npe_name == NULL) {
		dprintf("gen_newif_event: strdup failed");
		free(e);
		return;
	}
	e->npe_type = EV_ROUTING;

	/*
	 * This event notifies the state machine that a new interface is
	 * (at least nominally) available to be brought up.  When the state
	 * machine processes the event, it will look at the entire list of
	 * interfaces and corresponding LLPs, and make a determination about
	 * the best available LLP under current conditions.
	 */
	np_queue_add_event(e);
	dprintf("gen_newif_event: generated event for if %s", i->if_name);
}

/*
 * Caller uses this function to walk through the whole interface list.
 * For each interface, the caller provided walker is called with
 * the interface and arg as parameters.
 *
 * XXX There is no lock held right now for accessing the interface
 * list.  We probably need that in future.
 */
void
walk_interface(void (*walker)(struct interface *, void *), void *arg)
{
	struct interface *i;

	for (i = ifs_head; i != NULL; i = i->if_next)
		walker(i, arg);
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

	dprintf("initialize_interfaces: setting link_layer_profile(%p) to NULL",
	    (void *)link_layer_profile);
	link_layer_profile = NULL;
	upper_layer_profile[0] = '\0';

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
 * Walker function used to start info gathering of each interface.
 */
void
start_if_info_collect(struct interface *ifp, void *arg)
{
	pthread_t if_thr;
	pthread_attr_t attr;

	/*
	 * In certain cases we need to refresh the cached flags value as
	 * it may be stale.  Notably, we can miss a DL_NOTE_LINK_DOWN
	 * event after we initialize interfaces before the routing thread
	 * is launched.
	 */
	if (arg != NULL && *(boolean_t *)arg)
		ifp->if_flags = get_ifflags(ifp->if_name, ifp->if_family);

	/*
	 * Only if the cable of the wired interface is
	 * plugged in, start gathering info from it.
	 */
	if (!is_plugged_in(ifp))
		return;

	/*
	 * This is a "fresh start" for the interface, so clear old DHCP flags.
	 */
	ifp->if_lflags &= ~IF_DHCPFLAGS;

	(void) pthread_attr_init(&attr);
	(void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (pthread_create(&if_thr, &attr, gather_interface_info,
	    (void *)ifp) != 0) {
		syslog(LOG_ERR, "create interface gathering thread: %m");
		exit(EXIT_FAILURE);
	} else {
		dprintf("interface info thread: %d", if_thr);
	}
}

/*
 * Walker function used to check timer for each interface.
 * If timer has expired, generate a timer event for the
 * interface.
 */
/* ARGSUSED */
void
check_interface_timer(struct interface *ifp, void *arg)
{
	uint32_t now = *(uint32_t *)arg;
	struct np_event *ev;

	if (ifp->if_timer_expire == 0)
		return;

	if (ifp->if_timer_expire > now) {
		start_timer(now, ifp->if_timer_expire - now);
		return;
	}

	ifp->if_timer_expire = 0;

	if ((ev = calloc(1, sizeof (*ev))) == NULL) {
		dprintf("could not allocate timer event for %s; ignoring timer",
		    ifp->if_name);
		return;
	}
	ev->npe_type = EV_TIMER;
	ev->npe_name = strdup(ifp->if_name);
	if (ev->npe_name == NULL) {
		dprintf("could not strdup name for timer event on %s; ignoring",
		    ifp->if_name);
		free(ev);
		return;
	}
	np_queue_add_event(ev);
}

enum interface_type
find_if_type(const char *name)
{
	uint32_t media;
	enum interface_type type;

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
if_type_str(enum interface_type type)
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
