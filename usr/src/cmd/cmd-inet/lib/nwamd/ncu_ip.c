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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <dhcpagent_ipc.h>
#include <dhcp_inittab.h>
#include <dhcp_symbol.h>
#include <dhcpagent_util.h>
#include <errno.h>
#include <execinfo.h>
#include <inetcfg.h>
#include <libnwam.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <ucontext.h>
#include <unistd.h>
#include <libscf.h>

#include "conditions.h"
#include "events.h"
#include "ncp.h"
#include "ncu.h"
#include "objects.h"
#include "util.h"

/*
 * ncu_ip.c - contains routines that are IP interface-specific for NCUs.
 */

#define	STATELESS_RUNNING	(IFF_RUNNING | IFF_UP | IFF_ADDRCONF)
#define	DHCP_RUNNING		(IFF_RUNNING | IFF_UP | IFF_DHCPRUNNING)

static void *start_dhcp_thread(void *);
static void nwamd_down_interface(const char *, uint_t, int);
static boolean_t stateless_running(const nwamd_ncu_t *);

char *
nwamd_sockaddr_to_str(const struct sockaddr *sockaddr, char *str, size_t len)
{
	if (icfg_sockaddr_to_str(sockaddr->sa_family, sockaddr, str, len) !=
	    ICFG_SUCCESS) {
		return (NULL);
	} else {
		return (str);
	}
}

static void
nwamd_log_if_address(int severity, struct nwamd_if_address *nifa)
{
	char str[INET6_ADDRSTRLEN];

	nlog(severity, "%s address %s is %s",
	    nifa->address.sa_family == AF_INET ? "IPv4" : "IPv6",
	    nwamd_sockaddr_to_str(&nifa->address, str, sizeof (str)),
	    nifa->configured ? "configured" : "not configured");
}

void
nwamd_propogate_link_up_down_to_ip(const char *linkname, boolean_t up)
{
	nwamd_object_t ip_ncu = nwamd_ncu_object_find(NWAM_NCU_TYPE_INTERFACE,
	    linkname);
	nwamd_ncu_t *ncu;

	if (ip_ncu == NULL) {
		nlog(LOG_DEBUG, "nwamd_propogate_link_up_down_to_ip: no IP NCU "
		    "for link %s, cannot propogate %s event", linkname,
		    up ? "up" : "down");
		return;
	}
	ncu = ip_ncu->nwamd_object_data;

	if (ncu->ncu_enabled) {
		if (ip_ncu->nwamd_object_aux_state ==
		    NWAM_AUX_STATE_UNINITIALIZED) {
			nlog(LOG_DEBUG,
			    "nwamd_propogate_link_up_down_to_ip: will not "
			    "propogate link %s event as IP NCU %s is being "
			    "removed", up ? "up" : "down", linkname);
		} else {
			nlog(LOG_DEBUG,
			    "nwamd_propogate_link_up_down_to_ip: propogating "
			    "link %s event to interface %s",
			    up ? "up" : "down", linkname);
			nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
			    ip_ncu->nwamd_object_name,
			    up ?
			    NWAM_STATE_OFFLINE_TO_ONLINE :
			    NWAM_STATE_ONLINE_TO_OFFLINE,
			    up ? NWAM_AUX_STATE_INITIALIZED :
			    NWAM_AUX_STATE_CONDITIONS_NOT_MET);
		}
	} else {
		nlog(LOG_DEBUG,
		    "nwamd_propogate_link_up_down_to_ip: not propogating "
		    "link %s event to interface %s, IP NCU is disabled",
		    up ? "up" : "down", linkname);
	}
	nwamd_object_release(ip_ncu);
}

/*
 * Returns the value associated with the given symbol for the given
 * interface.  The interface may be NULL, in which case the primary
 * interface is used.
 * This function substitutes the need to call dhcpinfo(1), thus it is
 * very similar to the implementation of dhcpinfo(1).
 * When multiple values need to be returned (e.g., nameservers), they
 * are separated by a space ' '.
 */
char *
nwamd_get_dhcpinfo_data(const char *sym_name, char *ifname)
{
	dhcp_symbol_t *entry;
	dhcp_optnum_t optnum;
	dhcp_ipc_request_t *request;
	dhcp_ipc_reply_t *reply;
	DHCP_OPT *opt;
	size_t opt_len;
	char *value; /* return value */
	int err;
	char errmsg[LINE_MAX];

	/* if interface is not given, change it to empty string */
	if (ifname == NULL)
		ifname = "";

	/* find code and category in dhcp_inittab(4) */
	entry = inittab_getbyname(ITAB_CAT_SITE | ITAB_CAT_STANDARD |
	    ITAB_CAT_VENDOR | ITAB_CAT_FIELD, ITAB_CONS_INFO, sym_name);

	if (entry == NULL) {
		(void) snprintf(errmsg, LINE_MAX, "unknown identifier: %s",
		    sym_name);
		goto fail;
	}

	/* allocate request */
	optnum.code = entry->ds_code;
	optnum.category = entry->ds_category;
	optnum.size = entry->ds_max * inittab_type_to_size(entry);
	request = dhcp_ipc_alloc_request(DHCP_GET_TAG, ifname, &optnum,
	    sizeof (dhcp_optnum_t), DHCP_TYPE_OPTNUM);
	if (request == NULL) {
		(void) snprintf(errmsg, LINE_MAX, "failed dhcp alloc request");
		goto fail;
	}

	/* make the request */
	err = dhcp_ipc_make_request(request, &reply, DHCP_IPC_WAIT_DEFAULT);
	if (err != 0 || reply->return_code != 0) {
		(void) snprintf(errmsg, LINE_MAX, "%s",
		    dhcp_ipc_strerror(err == 0 ? reply->return_code : err));
	}

	/* get data from the reply */
	opt = dhcp_ipc_get_data(reply, &opt_len, NULL);
	if (opt_len == 0) {
		(void) snprintf(errmsg, LINE_MAX, "invalid data");
		goto fail;
	}

	/* check protocol error */
	if (opt_len < 2 || (opt_len -2 != opt->len)) {
		(void) snprintf(errmsg, LINE_MAX, "data length mismatch");
		goto fail;
	}
	opt_len -= 2;

	/* decode the data into ascii */
	value = inittab_decode(entry, opt->value, opt_len, B_TRUE);
	if (value == NULL) {
		(void) snprintf(errmsg, LINE_MAX, "cannot decode reply");
		goto fail;
	}

	free(request);
	free(reply);
	return (value);

fail:
	nlog(LOG_DEBUG, "get_dhcpinfo_data() failed: %s", errmsg);
	free(request);
	free(reply);
	return (NULL);
}

void
nwamd_dhcp_release(const char *ifname)
{
	dhcp_ipc_reply_t *reply = NULL;
	dhcp_ipc_request_t *request;
	int rc;

	/* Now allocate and send the request */
	request = dhcp_ipc_alloc_request(DHCP_RELEASE, ifname, NULL, 0,
	    DHCP_TYPE_NONE);
	if (request == NULL) {
		nlog(LOG_DEBUG, "nwamd_dhcp_release: dhcp_ipc_alloc_request : "
		    "%s", strerror(errno));
		return;
	}
	rc = dhcp_ipc_make_request(request, &reply, 1);
	free(request);
	free(reply);
	reply = NULL;
	if (rc != 0) {
		/* Fall back to drop request */
		request = dhcp_ipc_alloc_request(DHCP_DROP, ifname, NULL, 0,
		    DHCP_TYPE_NONE);
		if (request == NULL) {
			nlog(LOG_DEBUG, "nwamd_dhcp_release: "
			    "dhcp_ipc_alloc_request : %s", strerror(errno));
			return;
		}
		(void) dhcp_ipc_make_request(request, &reply, 1);
		free(request);
		free(reply);
	}
}

static boolean_t
add_ip_address(const char *ifname, struct nwamd_if_address *nifa,
    boolean_t logical_if)
{
	icfg_handle_t h, newh;
	icfg_if_t intf;
	uint64_t flags;
	int rc;
	struct sockaddr_in bcastaddr;
	char str[INET6_ADDRSTRLEN];

	(void) strlcpy(intf.if_name, ifname, sizeof (intf.if_name));
	intf.if_protocol = nifa->address.sa_family;

	nlog(LOG_DEBUG, "add_ip_address: %s address %s for link %s",
	    logical_if ? "adding" : "setting",
	    nwamd_sockaddr_to_str(&nifa->address, str, sizeof (str)),
	    intf.if_name);

	if (icfg_open(&h, &intf) != ICFG_SUCCESS) {
		nlog(LOG_ERR, "add_ip_address: icfg_open failed on %s", ifname);
		return (B_FALSE);
	}
	/*
	 * When working with the physical interface, we need to be careful
	 * to set the prefixlen and broadcast addresses before setting the
	 * IP address, otherwise RTM_DELADDRs for the old broadcast/netmask
	 * will confuse us into thinking we've lost the address we've just
	 * assigned.
	 */
	if (logical_if) {
		rc = icfg_add_addr(h, &newh,
		    (const struct sockaddr *)&nifa->address,
		    intf.if_protocol == AF_INET ?
		    sizeof (struct sockaddr_in) : sizeof (struct sockaddr_in6));
	} else {
		newh = h;

		/* Make sure DHCP is no longer running */
		if (icfg_get_flags(newh, &flags) == ICFG_SUCCESS) {
			if (flags & IFF_DHCPRUNNING) {
				nlog(LOG_DEBUG, "add_ip_address: "
				    "turning off DHCP for %s", ifname);
				nwamd_dhcp_release(ifname);
			}
		}
		/*
		 * Set interface IFF_UP if not already.  Do this and
		 * setting of prefixlen/broadcast addresses as otherwise
		 * these can trigger an RTM_DELADDR that makes it appear
		 * that the address has gone away.
		 */
		rc = icfg_set_addr(newh,
		    (const struct sockaddr *)&nifa->address,
		    intf.if_protocol == AF_INET ?
		    sizeof (struct sockaddr_in) :
		    sizeof (struct sockaddr_in6));
	}
	if (rc != ICFG_SUCCESS) {
		nlog(LOG_DEBUG, "add_ip_address: add of ipaddr failed "
		    "for %s: %d", ifname, rc);
		goto out;
	}

	if (nifa->prefix != 0) {
		if ((rc = icfg_set_prefixlen(newh, nifa->prefix))
		    != ICFG_SUCCESS) {
			nlog(LOG_ERR, "add_ip_address: icfg_set_prefix %d "
			    "failed on %s: %s", nifa->prefix, ifname,
			    icfg_errmsg(rc));
		} else if (intf.if_protocol == AF_INET) {
			/* Set broadcast address based on address, prefixlen */
			bcastaddr.sin_addr.s_addr =
			/*LINTED*/
			    ((struct sockaddr_in *)&nifa->address)
			    ->sin_addr.s_addr |
			    htonl(0xffffffff >> nifa->prefix);

			if ((rc = icfg_set_broadcast(newh, &bcastaddr))
			    != ICFG_SUCCESS) {
				nlog(LOG_ERR, "add_ip_address: "
				    "icfg_set_broadcast(%s) failed on %s: %s",
				    inet_ntoa(bcastaddr.sin_addr), ifname,
				    icfg_errmsg(rc));
			}
		}
	}
	if (rc == ICFG_SUCCESS) {
		if (icfg_get_flags(newh, &flags) == ICFG_SUCCESS) {
			if ((flags & IFF_UP) == 0)
				rc = icfg_set_flags(newh, flags | IFF_UP);
		} else {
			nlog(LOG_DEBUG, "add_ip_address: couldn't bring up %s",
			    ifname);
		}
	}

out:
	/* Check if address was a duplicate */
	if (rc == ICFG_DAD_FOUND || (flags & IFF_DUPLICATE) != 0) {
		char *object_name;
		nwam_error_t err;

		nlog(LOG_INFO, "add_ip_address: "
		    "duplicate address detected on %s", ifname);
		if ((err = nwam_ncu_name_to_typed_name(ifname,
		    NWAM_NCU_TYPE_INTERFACE, &object_name)) == NWAM_SUCCESS) {
			nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
			    object_name, NWAM_STATE_MAINTENANCE,
			    NWAM_AUX_STATE_IF_DUPLICATE_ADDR);
			free(object_name);
		} else {
			nlog(LOG_ERR, "add_ip_address: could not "
			    "create state event for %s: %s", ifname,
			    nwam_strerror(err));
		}
		rc = ICFG_DAD_FOUND;
	}

	if (h != newh)
		icfg_close(newh);
	icfg_close(h);

	return (rc == ICFG_SUCCESS);
}

void
nwamd_add_default_routes(nwamd_ncu_t *ncu)
{
	nwamd_if_t *nif = &ncu->ncu_node.u_if;
	char str[INET6_ADDRSTRLEN];

	if (nif->nwamd_if_ipv4 && nif->nwamd_if_ipv4_default_route_set) {
		struct sockaddr_in v4dest, v4mask;

		v4dest.sin_addr.s_addr = htonl(INADDR_ANY);
		v4dest.sin_family = AF_INET;

		v4mask.sin_addr.s_addr = 0;
		v4mask.sin_family = AF_INET;

		nlog(LOG_DEBUG, "nwamd_add_default_routes: adding default "
		    "route %s", nwamd_sockaddr_to_str
		    ((struct sockaddr *)&nif->nwamd_if_ipv4_default_route, str,
		    sizeof (str)));
		nwamd_add_route((struct sockaddr *)&v4dest,
		    (struct sockaddr *)&v4mask,
		    (struct sockaddr *)&nif->nwamd_if_ipv4_default_route,
		    ncu->ncu_name);
	}

	if (nif->nwamd_if_ipv6 && nif->nwamd_if_ipv6_default_route_set) {
		struct sockaddr_in6 v6dest, v6mask;

		(void) bzero(&v6dest, sizeof (struct sockaddr_in6));
		v6dest.sin6_family = AF_INET6;

		(void) bzero(&v6mask, sizeof (struct sockaddr_in6));
		v6mask.sin6_family = AF_INET6;

		nlog(LOG_DEBUG, "nwamd_add_default_routes: adding default "
		    "route %s", nwamd_sockaddr_to_str
		    ((struct sockaddr *)&nif->nwamd_if_ipv6_default_route, str,
		    sizeof (str)));
		nwamd_add_route((struct sockaddr *)&v6dest,
		    (struct sockaddr *)&v6mask,
		    (struct sockaddr *)&nif->nwamd_if_ipv6_default_route,
		    ncu->ncu_name);
	}
}

void
nwamd_dhcp_inform(nwamd_ncu_t *ncu)
{
	struct nwamd_dhcp_thread_arg *arg;
	char *name = NULL;
	pthread_attr_t attr;

	arg = malloc(sizeof (*arg));
	if (arg == NULL) {
		nlog(LOG_ERR, "nwamd_dhcp_inform: error allocating memory "
		    "for dhcp request");
		free(name);
		return;
	}

	arg->name = strdup(ncu->ncu_name);
	arg->type = DHCP_INFORM;
	arg->timeout = DHCP_IPC_WAIT_DEFAULT;

	(void) pthread_attr_init(&attr);
	(void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (pthread_create(NULL, &attr, start_dhcp_thread, arg) == -1) {
		nlog(LOG_ERR, "Cannot start dhcp thread");
		free(name);
		free(arg);
		(void) pthread_attr_destroy(&attr);
		return;
	}
	(void) pthread_attr_destroy(&attr);
}

static boolean_t
addresses_match(const struct sockaddr *addr1, const struct sockaddr *addr2)
{
	if (addr1->sa_family != addr2->sa_family)
		return (B_FALSE);

	switch (addr1->sa_family) {
	case AF_INET:
		/*LINTED*/
		return (memcmp(&((struct sockaddr_in *)addr1)->sin_addr,
		/*LINTED*/
		    &((struct sockaddr_in *)addr2)->sin_addr,
		    sizeof (struct in_addr)) == 0);
	case AF_INET6:
		/*LINTED*/
		return (memcmp(&((struct sockaddr_in6 *)addr1)->sin6_addr,
		/*LINTED*/
		    &((struct sockaddr_in6 *)addr2)->sin6_addr,
		    sizeof (struct in6_addr)) == 0);
	default:
		return (B_FALSE);
	}
}

/*
 * Returns the nwamd_if_address structure for the given static address,
 * NULL if not found.
 */
static struct nwamd_if_address *
find_static_address(const struct sockaddr *addr, const nwamd_ncu_t *ncu)
{
	struct nwamd_if_address *n, *nifa = ncu->ncu_node.u_if.nwamd_if_list;
	char str[INET6_ADDRSTRLEN];

	nlog(LOG_DEBUG, "find_static_address %s",
	    nwamd_sockaddr_to_str(addr, str, sizeof (str)));
	for (n = nifa; n != NULL; n = n->next) {
		if (addresses_match(addr, &n->address))
			return (n);
	}
	return (NULL);
}

/*
 * Returns the nwamd_if_address structure representing the non-static address
 * in the NCU.  dhcp is used to detemrine if the DHCP (stateful for v6)
 * structure is needed or the stateless/autoconf structure for the given
 * family.  dhcp should be B_TRUE if looking for v4.  Will only return the
 * nwamd_if_address if the relevant address is configured (v4 DHCP, v6
 * stateless/stateful) for the NCU.
 *
 * Returns NULL if structure is not found.
 */
static struct nwamd_if_address *
find_nonstatic_address(const nwamd_ncu_t *ncu, ushort_t family, boolean_t dhcp)
{
	struct nwamd_if_address *n, *nifa = ncu->ncu_node.u_if.nwamd_if_list;
	const nwamd_if_t *u_if = &ncu->ncu_node.u_if;

	nlog(LOG_DEBUG, "find_nonstatic_address: %s",
	    dhcp ? "dhcp" : "stateless");
	for (n = nifa; n != NULL; n = n->next) {
		if (family == AF_INET) {
			if (!dhcp)
				return (NULL);
			if (n->address.sa_family == family && n->dhcp_if &&
			    u_if->nwamd_if_dhcp_configured)
				return (n);
		} else if (family == AF_INET6) {
			if (n->address.sa_family == family) {
				if (dhcp && n->dhcp_if &&
				    u_if->nwamd_if_stateful_configured)
					return (n);
				else if (!dhcp && n->stateless_if &&
				    u_if->nwamd_if_stateless_configured)
					return (n);
			}
		}
	}
	return (NULL);
}

/*
 * Sets "configured" nwam_if_address value for corresponding address.
 * Used when we process IF_STATE events to handle RTM_NEWADDR/DELADDRs.
 */
static boolean_t
update_address_configured_value(const struct sockaddr *configured_addr,
    nwamd_ncu_t *ncu, boolean_t configured)
{
	struct nwamd_if_address *n;
	char str[INET6_ADDRSTRLEN];

	nlog(LOG_DEBUG, "update_address_configured_value(%s, %s, %s)",
	    nwamd_sockaddr_to_str(configured_addr, str, sizeof (str)),
	    ncu->ncu_name, configured ? "configure" : "unconfigure");
	n = find_static_address(configured_addr, ncu);
	if (n) {
		n->configured = configured;
		nlog(LOG_DEBUG, "update_address_configured_value: marking "
		    "address %s",
		    nwamd_sockaddr_to_str(&n->address, str, sizeof (str)));
		return (B_TRUE);
	}
	return (B_FALSE);
}

void
nwamd_update_addresses_unconfigured(nwamd_ncu_t *ncu, sa_family_t af)
{
	struct nwamd_if_address *n, *nifa = ncu->ncu_node.u_if.nwamd_if_list;

	for (n = nifa; n != NULL; n = n->next)
		if (af == AF_UNSPEC || n->address.sa_family == af) {
			n->configured = B_FALSE;
			nwamd_log_if_address(LOG_DEBUG, n);
		}
}

/*
 * Are one or more static addresses configured?
 */
boolean_t
nwamd_static_addresses_configured(nwamd_ncu_t *ncu, sa_family_t family)
{
	struct nwamd_if_address *n;

	for (n = ncu->ncu_node.u_if.nwamd_if_list; n != NULL; n = n->next) {
		if ((family == AF_UNSPEC || family == n->address.sa_family) &&
		    n->configured && !n->dhcp_if && !n->stateless_if)
			return (B_TRUE);
	}
	nlog(LOG_DEBUG, "no static addresses configured for %s", ncu->ncu_name);
	return (B_FALSE);
}

/*
 * Is DHCP probably managing an address on this index.  We decide that it is
 * probably managing an address if there is an interface with IFF_DHCP set
 * that isn't in our set of static addresses.  Note that IFF_DHCP gets set
 * on static addresses when we do a dhcp inform and if that list has changed
 * recently then the result of this function could be erronous.
 */
boolean_t
nwamd_dhcp_managing(int protocol, nwamd_ncu_t *ncu)
{
	icfg_if_t *iflist;
	icfg_handle_t ifh;
	int numif, i;
	struct sockaddr_storage addr;
	socklen_t len;
	int prefixlen;
	uint64_t flags;
	boolean_t rv = B_FALSE;

	if (icfg_get_if_list(&iflist, &numif, protocol, ICFG_PLUMBED) !=
	    ICFG_SUCCESS) {
		return (B_TRUE);
	}
	for (i = 0; i < numif; i++) {
		if (strncmp(iflist[i].if_name, ncu->ncu_name,
		    strlen(ncu->ncu_name)) != 0)
				continue;

		if (icfg_open(&ifh, &iflist[i]) != ICFG_SUCCESS)
			continue;

		/* is this address an expected static one? */
		len = sizeof (addr);
		if (icfg_get_addr(ifh, (struct sockaddr *)&addr, &len,
		    &prefixlen, B_FALSE) != ICFG_SUCCESS ||
		    find_static_address((struct sockaddr *)&addr, ncu)
		    != NULL) {
			icfg_close(ifh);
			continue;
		}

		/*
		 * For IPv4, DHCPRUNNING flag is set when dhcpagent is in
		 * the process of getting an address, but doesn't have one
		 * yet (interface has 0.0.0.0).  For IPv6, DHCPRUNNING flag
		 * is set on the link-local address if trying to get a
		 * stateful address.  In both cases, consider the interface
		 * as not being managed by DHCP and skip checking of flags.
		 */
		if ((protocol == AF_INET &&
		    ((struct sockaddr_in *)&addr)->sin_addr.s_addr ==
		    INADDR_ANY) ||
		    (protocol == AF_INET6 &&
		    IN6_IS_ADDR_LINKLOCAL(
		    &((struct sockaddr_in6 *)&addr)->sin6_addr))) {
			icfg_close(ifh);
			continue;
		}

		if (icfg_get_flags(ifh, &flags) == ICFG_SUCCESS &&
		    (flags & IFF_DHCPRUNNING)) {
			/*
			 * If we get here we have an address that has the
			 * DHCP flag set and isn't an expected static address.
			 */
			icfg_close(ifh);
			rv = B_TRUE;
			break;
		}
	}

	icfg_free_if_list(iflist);
	return (rv);
}

static boolean_t
nwamd_v4_requested(nwamd_ncu_t *ncu)
{
	boolean_t anyv4_requested;
	nwamd_if_t *u_if;

	anyv4_requested = B_FALSE;
	u_if = &ncu->ncu_node.u_if;
	if (u_if->nwamd_if_dhcp_requested) {
		anyv4_requested = B_TRUE;
	} else {
		struct nwamd_if_address *a;
		for (a = u_if->nwamd_if_list;
		    a != NULL && a->address.sa_family != AF_INET;
		    a = a->next)
			/* Empty loop body */;
		if (a != NULL)
			anyv4_requested = B_TRUE;
	}

	return (anyv4_requested);
}

static boolean_t
nwamd_v6_requested(nwamd_ncu_t *ncu)
{
	boolean_t anyv6_requested;
	nwamd_if_t *u_if;

	anyv6_requested = B_FALSE;
	u_if = &ncu->ncu_node.u_if;
	if (u_if->nwamd_if_stateful_requested ||
	    u_if->nwamd_if_stateless_requested) {
		anyv6_requested = B_TRUE;
	} else {
		struct nwamd_if_address *a;
		for (a = u_if->nwamd_if_list;
		    a != NULL && a->address.sa_family != AF_INET6;
		    a = a->next)
			/* Empty loop body */;
		if (a != NULL)
			anyv6_requested = B_TRUE;
	}

	return (anyv6_requested);
}

/*
 * Bring up the ncu if we have the right combination of requested configuration
 * and actual configuration and up is true, or bring down the ncu if no
 * addresses are configured, and up is false.
 */
static void
interface_ncu_up_down(nwamd_ncu_t *ncu, boolean_t up)
{
	boolean_t ncu_online;
	char *name;

	assert(ncu->ncu_type == NWAM_NCU_TYPE_INTERFACE);

	/*
	 * If V4 with or without V6 is configured then one of its interfaces
	 * needs to be up for the ncu to come online.  If only V6 is requested
	 * then one of its interfaces needs to be up for the ncu to come online.
	 */
	ncu_online = B_FALSE;
	if (nwamd_v4_requested(ncu)) {
		if (nwamd_dhcp_managing(AF_INET, ncu) ||
		    nwamd_static_addresses_configured(ncu, AF_INET))
			ncu_online = B_TRUE;
	} else if (nwamd_v6_requested(ncu)) {
		if ((nwamd_dhcp_managing(AF_INET6, ncu) ||
		    stateless_running(ncu) ||
		    nwamd_static_addresses_configured(ncu, AF_INET6)))
			ncu_online = B_TRUE;
	}

	if (nwam_ncu_name_to_typed_name(ncu->ncu_name, ncu->ncu_type, &name) !=
	    NWAM_SUCCESS) {
		nlog(LOG_DEBUG, "interface_ncu_up_down: "
		    "nwam_ncu_name_to_typed_name failed");
		return;
	}
	if (ncu_online && up) {
		nlog(LOG_DEBUG, "interface_ncu_up_down: "
		    "bringing %s up", name);
		nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU, name,
		    NWAM_STATE_OFFLINE_TO_ONLINE, NWAM_AUX_STATE_UP);
	} else if (!ncu_online && !up) {
		nlog(LOG_DEBUG, "interface_ncu_up_down: "
		    "bringing %s down", name);
		nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU, name,
		    NWAM_STATE_ONLINE_TO_OFFLINE,
		    NWAM_AUX_STATE_DOWN);
	}

	free(name);
}

static void
interface_ncu_up(nwamd_ncu_t *ncu)
{
	interface_ncu_up_down(ncu, B_TRUE);
}

static void
interface_ncu_down(nwamd_ncu_t *ncu)
{
	interface_ncu_up_down(ncu, B_FALSE);
}

/* Callback to find if DHCP is running on the interface index */
static int
flags_set_for_ifindex_cb(icfg_if_t *intf, void *arg, uint64_t flags_wanted)
{
	int *indexp = arg;
	icfg_handle_t h;
	int index;
	uint64_t flags = 0;

	if (icfg_open(&h, intf) != ICFG_SUCCESS) {
		nlog(LOG_ERR, "flags_set_for_ifindex_cb: icfg_open failed");
		return (0);
	}
	if (icfg_get_index(h, &index) != ICFG_SUCCESS) {
		nlog(LOG_ERR,
		    "flags_set_for_ifindex_cb: icfg_get_index failed");
		icfg_close(h);
		return (0);
	}
	if (index != *indexp) {
		icfg_close(h);
		return (0);
	}

	if (icfg_get_flags(h, &flags) != ICFG_SUCCESS) {
		nlog(LOG_ERR,
		    "flags_set_for_ifindex_cb: icfg_get_flags failed");
	}
	icfg_close(h);
	return ((flags & flags_wanted) == flags_wanted);
}

static int
stateless_running_for_ifindex_cb(icfg_if_t *intf, void *arg)
{
	return (flags_set_for_ifindex_cb(intf, arg,
	    IFF_RUNNING | IFF_ADDRCONF | IFF_UP));
}

/*
 * Is autoconf running on the interface with specified ifindex?
 */
static boolean_t
stateless_running_for_ifindex(int ifindex)
{
	return (icfg_iterate_if(AF_INET6, ICFG_PLUMBED, &ifindex,
	    stateless_running_for_ifindex_cb) != 0);
}

static boolean_t
stateless_running(const nwamd_ncu_t *ncu)
{
	int index;
	icfg_if_t intf;
	icfg_handle_t ifh;

	intf.if_protocol = AF_INET6;
	(void) strlcpy(intf.if_name, ncu->ncu_name, sizeof (intf.if_name));
	if (icfg_open(&ifh, &intf) != ICFG_SUCCESS) {
		nlog(LOG_ERR, "stateless_running: icfg_open(%s) failed",
		    ncu->ncu_name);
		return (B_FALSE);
	}

	if (icfg_get_index(ifh, &index) != ICFG_SUCCESS) {
		nlog(LOG_ERR, "stateless_running: icfg_get_index(%s) failed",
		    ncu->ncu_name);
		return (B_FALSE);
	}

	icfg_close(ifh);

	return (stateless_running_for_ifindex(index));
}

void
nwamd_configure_interface_addresses(nwamd_ncu_t *ncu)
{
	struct nwamd_if_address *nifa = ncu->ncu_node.u_if.nwamd_if_list;
	struct nwamd_if_address *n;
	int num_configured_v4 = 0;
	boolean_t add_logical_if;

	nlog(LOG_DEBUG, "nwamd_configure_interface_addresses(%s)",
	    ncu->ncu_name);

	/*
	 * Add static addresses.  For IPv4, we only use the physical interface
	 * (i.e. not a logical interface) if DHCP has not been requested and
	 * this is the first address to be configured.
	 */
	for (n = nifa; n != NULL; n = n->next) {
		if (n->configured || n->dhcp_if || n->stateless_if)
			continue;
		switch (n->address.sa_family) {
		case AF_INET:
			add_logical_if = (num_configured_v4 > 0 ||
			    ncu->ncu_node.u_if.nwamd_if_dhcp_requested);
			num_configured_v4++;
			break;
		case AF_INET6:
			add_logical_if = B_TRUE;
			break;
		}
		n->configured = add_ip_address(ncu->ncu_name, n,
		    add_logical_if);
	}
}

static int
lifnum_from_ifname(const char *ifname)
{
	char *lifstr = strchr(ifname, ':');

	if (lifstr != NULL) {
		lifstr++;
		return (atoi(lifstr));
	}
	return (0);
}

/*
 * Copies the ifname (with lifnum) associated with the given address.
 * Returns B_TRUE if a match is found, B_FASLE otherwise.
 */
static boolean_t
ifname_for_addr(const struct sockaddr *caddr, char *ifname, int len)
{
	struct sockaddr_in6 addr;
	int numif, i, prefixlen;
	icfg_if_t *iflist;
	icfg_handle_t ifh;
	socklen_t slen;

	if (icfg_get_if_list(&iflist, &numif, caddr->sa_family, ICFG_PLUMBED)
	    != ICFG_SUCCESS) {
		nlog(LOG_DEBUG, "ifname_for_addr: icfg_get_if_list failed");
		return (B_FALSE);
	}

	for (i = 0; i < numif; i++) {
		if (icfg_open(&ifh, &iflist[i]) != ICFG_SUCCESS) {
			nlog(LOG_ERR, "ifname_for_addr: icfg_open %s failed",
			    iflist[i].if_name);
			continue;
		}

		slen = sizeof (addr);
		if (icfg_get_addr(ifh, (struct sockaddr *)&addr,
		    &slen, &prefixlen, B_FALSE) != ICFG_SUCCESS) {
			nlog(LOG_ERR, "ifname_for_addr: "
			    "icfg_get_addr %s failed", iflist[i].if_name);
		} else {
			/* Compare addresses */
			if (addresses_match((struct sockaddr *)&addr, caddr)) {
				(void) strlcpy(ifname, iflist[i].if_name, len);
				icfg_close(ifh);
				icfg_free_if_list(iflist);
				return (B_TRUE);
			}
		}
		icfg_close(ifh);
	}
	icfg_free_if_list(iflist);
	return (B_FALSE);
}

/*
 * This event tells us that an interface address has appeared or disappeared,
 * or that the interface flags on an interface have changed.
 */
void
nwamd_ncu_handle_if_state_event(nwamd_event_t event)
{
	nwam_event_t evm;
	nwamd_object_t ncu_obj;
	nwamd_ncu_t *ncu;
	nwam_state_t state;
	nwam_aux_state_t aux_state;

	ncu_obj = nwamd_object_find(NWAM_OBJECT_TYPE_NCU,
	    event->event_object);
	if (ncu_obj == NULL) {
		nlog(LOG_ERR, "nwamd_ncu_handle_if_state_event: no object %s",
		    event->event_object);
		nwamd_event_do_not_send(event);
		return;
	}
	ncu = ncu_obj->nwamd_object_data;
	evm = event->event_msg;
	state = ncu_obj->nwamd_object_state;
	aux_state = ncu_obj->nwamd_object_aux_state;

	nlog(LOG_DEBUG, "nwamd_ncu_handle_if_state_event: "
	    "if %s, state (%s, %s)", event->event_object,
	    nwam_state_to_string(state), nwam_aux_state_to_string(aux_state));

	/* Ensure object is in correct state to handle IF state events */
	switch (state) {
	case NWAM_STATE_OFFLINE_TO_ONLINE:
		if (aux_state != NWAM_AUX_STATE_IF_WAITING_FOR_ADDR &&
		    aux_state != NWAM_AUX_STATE_IF_DHCP_TIMED_OUT) {
			nlog(LOG_DEBUG, "nwamd_ncu_handle_if_state_event: "
			    "if %s is in invalid aux state %s for IF_STATE "
			    "events", event->event_object,
			    nwam_aux_state_to_string(aux_state));
			nwamd_event_do_not_send(event);
			nwamd_object_release(ncu_obj);
			return;
		}
		break;
	case NWAM_STATE_ONLINE:
	/*
	 * We can get addresses from DHCP after we've taken the interface down.
	 * We deal with those below.
	 */
	case NWAM_STATE_ONLINE_TO_OFFLINE:
	case NWAM_STATE_OFFLINE:
		break;
	default:
		nlog(LOG_DEBUG, "nwamd_ncu_handle_if_state_event: "
		    "if %s is in invalid state %s for IF_STATE events",
		    event->event_object, nwam_state_to_string(state));
		nwamd_event_do_not_send(event);
		nwamd_object_release(ncu_obj);
		return;
	}

	if (evm->nwe_data.nwe_if_state.nwe_addr_valid) {
		struct nwam_event_if_state *if_state;
		boolean_t stateless_running;
		char addrstr[INET6_ADDRSTRLEN], ifname[LIFNAMSIZ];
		boolean_t v4dhcp_running;
		boolean_t v6dhcp_running;
		struct nwamd_if_address *nifa;
		struct sockaddr *addr;
		boolean_t static_addr;
		icfg_if_t intf;
		icfg_handle_t ifh;
		nwamd_if_t *u_if;
		ushort_t family;
		uint64_t flags = 0;
		int lifnum;

		if_state = &evm->nwe_data.nwe_if_state;
		u_if = &ncu->ncu_node.u_if;
		family = if_state->nwe_addr.ss_family;
		addr = (struct sockaddr *)&if_state->nwe_addr;

		nlog(LOG_DEBUG,
		    "nwamd_ncu_handle_if_state_event: addr %s %s",
		    nwamd_sockaddr_to_str(addr, addrstr, sizeof (addrstr)),
		    evm->nwe_data.nwe_if_state.nwe_addr_added ?
		    "added" : "removed");

		/* determine the interface name with lifnum */
		if (if_state->nwe_addr_added) {
			/* figure out the ifname for the address */
			if (!ifname_for_addr(addr, ifname, sizeof (ifname))) {
				nlog(LOG_ERR,
				    "nwamd_ncu_handle_if_state_event:"
				    "could not find ifname for %s", addrstr);
				nwamd_event_do_not_send(event);
				goto exit;
			}
		} else {
			/*
			 * Figure out the ifname that had the address that was
			 * removed.  The address is already gone from the
			 * interface, so cannot walk the interface list.
			 */
			struct nwamd_if_address *n;

			if ((n = find_static_address(addr, ncu)) == NULL &&
			    (n = find_nonstatic_address(ncu, family, B_TRUE))
			    == NULL &&
			    (n = find_nonstatic_address(ncu, family, B_FALSE))
			    == NULL) {
				nlog(LOG_ERR,
				    "nwamd_ncu_handle_if_state_event: "
				    "could not find nwamd_if_address for %s",
				    addrstr);
				nwamd_event_do_not_send(event);
				goto exit;
			}
			(void) strlcpy(ifname, n->ifname, sizeof (ifname));
		}

		nlog(LOG_DEBUG, "nwamd_ncu_handle_if_state_event: "
		    "ifname for %s is %s", addrstr, ifname);

		/*
		 * Get interface flags using nwe_ifname as it is logical
		 * interface name.
		 */
		intf.if_protocol = family;
		(void) strlcpy(intf.if_name, ifname, sizeof (intf.if_name));
		lifnum = lifnum_from_ifname(intf.if_name);

		if (icfg_open(&ifh, &intf) != ICFG_SUCCESS) {
			nlog(LOG_ERR, "nwamd_ncu_handle_if_state_event: can't "
			    "find if %s", intf.if_name);
			nwamd_event_do_not_send(event);
			goto exit;
		}
		if (icfg_get_flags(ifh, &flags) != ICFG_SUCCESS) {
			nlog(LOG_INFO, "nwamd_ncu_handle_if_state_event: can't "
			    "get flags for %s", icfg_if_name(ifh));
			/*
			 * If the interface is unplumbed, icfg_get_flags()
			 * will fail.  Don't exit, continue with empty flags.
			 */
			if (if_state->nwe_addr_added) {
				icfg_close(ifh);
				goto exit;
			}
		}

		if (family == AF_INET && !if_state->nwe_addr_added) {
			/*
			 * Check for failure due to CR 6745448: if we get a
			 * report that an address has been deleted, then check
			 * for interface up, datalink down, and actual address
			 * non-zero.  If that combination is seen, then this is
			 * a DHCP cached lease, and we need to remove it from
			 * the system, or it'll louse up the kernel routes
			 * (which aren't smart enough to avoid dead
			 * interfaces).
			 */
			/*LINTED*/
			if (((struct sockaddr_in *)addr)->sin_addr.s_addr
			    == INADDR_ANY) {
				socklen_t slen;
				struct sockaddr_in s;
				int pfxlen;

				if ((flags & IFF_UP) &&
				    !(flags & IFF_RUNNING) &&
				    icfg_get_addr(ifh, (struct sockaddr *)&s,
				    &slen, &pfxlen, B_FALSE) == ICFG_SUCCESS &&
				    s.sin_addr.s_addr != INADDR_ANY) {
					nlog(LOG_DEBUG, "bug workaround: "
					    "clear out addr %s on %s",
					    inet_ntoa(s.sin_addr), ifname);
					s.sin_addr.s_addr = INADDR_ANY;
					(void) icfg_set_addr(ifh,
					    (const struct sockaddr *)&s, slen);
				}
				icfg_close(ifh);
				goto exit;
			}
		}

		/*
		 * Has address really been removed? Sometimes spurious
		 * RTM_DELADDRs are generated, so we need to ensure that
		 * the address is really gone.  If IFF_DUPLICATE is set,
		 * we're getting the RTM_DELADDR due to DAD, so don't test
		 * in that case.
		 */
		if (!if_state->nwe_addr_added && !(flags & IFF_DUPLICATE)) {
			struct sockaddr_storage ifaddr;
			socklen_t len;
			int plen;

			len = family == AF_INET ? sizeof (struct sockaddr_in) :
			    sizeof (struct sockaddr_in6);
			if (icfg_get_addr(ifh, (struct sockaddr *)&ifaddr, &len,
			    &plen, B_FALSE) == ICFG_SUCCESS &&
			    addresses_match(addr, (struct sockaddr *)&ifaddr)) {
				nlog(LOG_DEBUG,
				    "nwamd_ncu_handle_if_state_event: "
				    "address %s is not really gone from %s, "
				    "ignoring IF_STATE event",
				    addrstr, intf.if_name);
				icfg_close(ifh);
				nwamd_event_do_not_send(event);
				goto exit;
			}
		}
		icfg_close(ifh);

		stateless_running = (family == AF_INET6) &&
		    ((flags & STATELESS_RUNNING) == STATELESS_RUNNING);
		v4dhcp_running = (family == AF_INET) &&
		    ((flags & DHCP_RUNNING) == DHCP_RUNNING);
		v6dhcp_running = (family == AF_INET6) &&
		    ((flags & DHCP_RUNNING) == DHCP_RUNNING);
		static_addr = (find_static_address(addr, ncu) != NULL);

		if (if_state->nwe_addr_added) {
			/*
			 * Address has been added.
			 *
			 * We need to make sure that we really want to keep
			 * this address.  There is a race where we requested an
			 * address but by the time we got here we don't really
			 * want it and need to remove it.
			 *
			 * [Note that since we use DHCP inform on interfaces
			 * with static addresses that they will also have the
			 * DHCP flag set on the interface.]
			 *
			 * Once we decide we want the address adjust the ncu
			 * state accordingly.  For example if this address is
			 * enough move online.
			 */

			/* Figure out if we want to keep this address. */
			if (static_addr) {
				nifa = find_static_address(addr, ncu);
				assert(nifa != NULL);
				nifa->configured = B_TRUE;
				(void) strlcpy(nifa->ifname, ifname,
				    sizeof (nifa->ifname));
			} else if (u_if->nwamd_if_dhcp_requested &&
			    v4dhcp_running) {
				u_if->nwamd_if_dhcp_configured = B_TRUE;
				nifa = find_nonstatic_address(ncu, family,
				    B_TRUE);
				assert(nifa != NULL);
				(void) strlcpy(nifa->ifname, ifname,
				    sizeof (nifa->ifname));
			} else if (u_if->nwamd_if_stateful_requested &&
			    v6dhcp_running) {
				u_if->nwamd_if_stateful_configured = B_TRUE;
				nifa = find_nonstatic_address(ncu, family,
				    B_TRUE);
				assert(nifa != NULL);
				(void) strlcpy(nifa->ifname, ifname,
				    sizeof (nifa->ifname));
			} else if (u_if->nwamd_if_stateless_requested &&
			    stateless_running) {
				u_if->nwamd_if_stateless_configured = B_TRUE;
				nifa = find_nonstatic_address(ncu, family,
				    B_FALSE);
				assert(nifa != NULL);
				(void) strlcpy(nifa->ifname, ifname,
				    sizeof (nifa->ifname));
			} else {
				/*
				 * This is something we didn't expect.  Remove
				 * it by unplumbing the logical interface.
				 */
				if (u_if->nwamd_if_dhcp_requested &&
				    v4dhcp_running)
					nwamd_dhcp_release(ncu->ncu_name);
				if (lifnum == 0) {
					nwamd_down_interface(ncu->ncu_name,
					    lifnum, family);
					interface_ncu_down(ncu);
				} else {
					nwamd_unplumb_interface(ncu, lifnum,
					    family);
				}
				goto exit;
			}

			/*
			 * The address looks valid so mark configured and
			 * move online if we either have a v4 address if
			 * v4 is configured or a v6 address if only v6 is
			 * configured.
			 */
			(void) update_address_configured_value(addr, ncu,
			    B_TRUE);
			if (state != NWAM_STATE_ONLINE)
				interface_ncu_up(ncu);

			/*
			 * Refresh network/location since we may also have other
			 * DHCP information.  We might have to restore it first
			 * in case it is in maintenance.
			 */
			nlog(LOG_DEBUG, "nwamd_handle_if_state_event: "
			    "refreshing %s as we may have other "
			    "DHCP information", NET_LOC_FMRI);
			(void) smf_restore_instance(NET_LOC_FMRI);
			if (smf_refresh_instance(NET_LOC_FMRI) != 0) {
				nlog(LOG_ERR,
				    "nwamd_ncu_handle_if_state_"
				    "event: refresh of %s "
				    "failed", NET_LOC_FMRI);
			}
		} else if (state == NWAM_STATE_ONLINE ||
		    state == NWAM_STATE_OFFLINE_TO_ONLINE) {
			/*
			 * Address has been removed.  Only pay attention to
			 * disappearing addresses if we are online or coming
			 * online.
			 *
			 * Undo whatever configuration is necessary.  Note
			 * that this may or may not cause the NCU to go down.
			 * We can get RTM_DELADDRs for duplicate addresses
			 * so deal with this seperately.
			 */
			if (static_addr) {
				(void) update_address_configured_value(addr,
				    ncu, B_FALSE);
			} else if (family == AF_INET) {
				u_if->nwamd_if_dhcp_configured = B_FALSE;
			} else if (family == AF_INET6) {
				/*
				 * The address is already gone.  I'm not sure
				 * how we figure out if this address is
				 * stateful (DHCP) or stateless.  When we
				 * are managing IPv6 more explicitly this will
				 * have to be done more carefully.
				 */
				u_if->nwamd_if_stateful_configured = B_FALSE;
				u_if->nwamd_if_stateless_configured = B_FALSE;
			}

			if (flags & IFF_DUPLICATE) {
				nlog(LOG_INFO,
				    "nwamd_ncu_handle_if_state_event: "
				    "duplicate address detected on %s",
				    ncu->ncu_name);
				nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
				    event->event_object,
				    NWAM_STATE_MAINTENANCE,
				    NWAM_AUX_STATE_IF_DUPLICATE_ADDR);
			} else {
				interface_ncu_down(ncu);
			}
		}
	}
exit:
	nwamd_object_release(ncu_obj);
}

void
nwamd_ncu_handle_if_action_event(nwamd_event_t event)
{
	nwamd_object_t ncu_obj;

	nlog(LOG_DEBUG, "if action event %s",
	    event->event_object[0] == '\0' ? "n/a" : event->event_object);

	ncu_obj = nwamd_object_find(NWAM_OBJECT_TYPE_NCU, event->event_object);
	if (ncu_obj == NULL) {
		nlog(LOG_ERR, "nwamd_ncu_handle_if_action_event: no object");
		nwamd_event_do_not_send(event);
		return;
	}
	nwamd_object_release(ncu_obj);
}

/*
 * This function downs any logical interface and just zeros the address off of
 * the physical interface (logical interface 0).  If you want to unplumb 0 then
 * you need to call nwamd_unplumb_interface() directly.
 */
static void
nwamd_down_interface(const char *linkname, uint_t lifnum, int family)
{
	uint64_t flags;
	icfg_if_t intf;
	icfg_handle_t h;
	icfg_error_t rc;

	if (linkname == NULL) {
		nlog(LOG_ERR, "nwamd_down_interface: linkname null");
		return;
	}

	(void) nwamd_link_to_ifname(linkname, lifnum, intf.if_name,
	    sizeof (intf.if_name));
	intf.if_protocol = family;

	rc = icfg_open(&h, &intf);
	if (rc != ICFG_SUCCESS) {
		nlog(LOG_ERR, "nwamd_down_interface: icfg_open failed for %s: "
		    "%s", intf.if_name, icfg_errmsg(rc));
		return;
	}

	if (lifnum == 0) {
		struct sockaddr_in6 addr;

		(void) memset(&addr, 0, sizeof (addr));
		addr.sin6_family = family;
		if (icfg_set_addr(h, (struct sockaddr *)&addr,
		    family == AF_INET ? sizeof (struct sockaddr_in) :
		    sizeof (struct sockaddr_in6)) != ICFG_SUCCESS)
			nlog(LOG_ERR, "nwamd_down_interface couldn't zero "
			    "address on %s", h->ifh_interface.if_name);
	} else {
		if (icfg_get_flags(h, &flags) == ICFG_SUCCESS) {
			if (icfg_set_flags(h, flags & ~IFF_UP) != ICFG_SUCCESS)
				nlog(LOG_ERR, "nwamd_down_interface: couldn't "
				    "bring %s down", h->ifh_interface.if_name);
		} else {
			nlog(LOG_ERR, "nwamd_down_interface: icfg_get_flags "
			    "failed on %s", h->ifh_interface.if_name);
		}
	}

	icfg_close(h);
}

static void
nwamd_plumb_unplumb_interface(nwamd_ncu_t *ncu, uint_t lifnum,
    int af, boolean_t plumb)
{
	uint64_t flags;
	icfg_if_t intf;
	icfg_handle_t h;
	icfg_error_t rc;
	nwamd_if_t *u_if;
	const char *linkname = ncu->ncu_name;

	if (linkname == NULL) {
		nlog(LOG_ERR, "nwamd_plumb_unplumb_interface: linkname null");
		return;
	}

	(void) nwamd_link_to_ifname(linkname, lifnum, intf.if_name,
	    sizeof (intf.if_name));
	intf.if_protocol = af;

	nlog(LOG_DEBUG, "nwamd_plumb_unplumb_interface: %s %s on link %s",
	    plumb ? "plumbing" : "unplumbing",
	    af == AF_INET ? "IPv4" : "IPv6", linkname);

	/*
	 * Before unplumbing, do a DHCP release if lifnum is 0.  Otherwise
	 * dhcpagent can get confused.
	 */
	if (!plumb && af == AF_INET && lifnum == 0)
		nwamd_dhcp_release(ncu->ncu_name);

	rc = icfg_open(&h, &intf);
	if (rc != ICFG_SUCCESS) {
		nlog(LOG_ERR, "nwamd_plumb_unplumb_interface: "
		    "icfg_open failed for %s: %s", intf.if_name,
		    icfg_errmsg(rc));
		return;
	}
	rc = plumb ? icfg_plumb(h) : icfg_unplumb(h);

	if (rc != ICFG_SUCCESS) {
		if ((plumb && rc != ICFG_EXISTS) ||
		    (!plumb && rc != ICFG_NO_EXIST)) {
			nlog(LOG_ERR, "nwamd_plumb_unplumb_interface: "
			    "%s %s failed for %s: %s",
			    plumb ? "plumb" : "unplumb",
			    af == AF_INET ? "IPv4" : "IPv6",
			    intf.if_name, icfg_errmsg(rc));
		}
	} else if (plumb) {
		if (icfg_get_flags(h, &flags) == ICFG_SUCCESS &&
		    (flags & IFF_UP) == 0) {
			if (icfg_set_flags(h, flags | IFF_UP) != ICFG_SUCCESS)
				nlog(LOG_ERR, "nwamd_plumb_unplumb_interface: "
				    "couldn't bring %s up",
				    h->ifh_interface.if_name);
		} else {
			nlog(LOG_ERR, "nwamd_plumb_unplumb_interface: "
			    "icfg_get_flags failed on %s",
			    h->ifh_interface.if_name);
		}
	}

	u_if = &ncu->ncu_node.u_if;
	if (!plumb) {
		nwamd_update_addresses_unconfigured(ncu, af);
		switch (af) {
			case AF_INET:
				u_if->nwamd_if_dhcp_configured = B_FALSE;
				break;
			case AF_INET6:
				u_if->nwamd_if_stateful_configured = B_FALSE;
				u_if->nwamd_if_stateless_configured = B_FALSE;
				break;
		}
	}

	icfg_close(h);
}

void
nwamd_plumb_interface(nwamd_ncu_t *ncu, uint_t lifnum, int af)
{
	nwamd_plumb_unplumb_interface(ncu, lifnum, af, B_TRUE);
}

void
nwamd_unplumb_interface(nwamd_ncu_t *ncu, uint_t lifnum, int af)
{
	nwamd_plumb_unplumb_interface(ncu, lifnum, af, B_FALSE);
}

static void *
start_dhcp_thread(void *arg)
{
	struct nwamd_dhcp_thread_arg *thread_arg;
	dhcp_ipc_reply_t *reply = NULL;
	dhcp_ipc_request_t *request;
	dhcp_ipc_type_t type;
	int timeout;
	char *name;
	int rc, retries = 0;

	thread_arg = (struct nwamd_dhcp_thread_arg *)arg;
	timeout = thread_arg->timeout;
	name = thread_arg->name;
	type = thread_arg->type;

	/* Try starting agent, though it may already be there */
	nwamd_to_root();
	rc = dhcp_start_agent(DHCP_IPC_MAX_WAIT);
	nwamd_from_root();
	if (rc == -1) {
		nlog(LOG_DEBUG, "Unable to start %s", DHCP_AGENT_PATH);
		goto failed;
	}
retry:
	/* Now allocate and send the request */
	request = dhcp_ipc_alloc_request(type, name, NULL, 0,
	    DHCP_TYPE_NONE);
	if (request == NULL) {
		nlog(LOG_DEBUG, "start_dhcp: dhcp_ipc_alloc_request : %s",
		    strerror(errno));
		goto failed;
	}

	rc = dhcp_ipc_make_request(request, &reply, timeout);
	free(request);
	if (rc != 0) {
		nlog(LOG_DEBUG, "start_dhcp %s: %s", name,
		    dhcp_ipc_strerror(rc));
		goto failed;
	}

	rc = reply->return_code;
	if (rc != 0) {
		if (rc == DHCP_IPC_E_TIMEOUT && timeout == 0) {
			goto failed;
		}

		/*
		 * DHCP timed out: change state for this NCU and enqueue
		 * event to check NCU priority-groups.  Only care for
		 * DHCP requests (not informs).
		 */
		if (rc == DHCP_IPC_E_TIMEOUT && type != DHCP_INFORM) {
			char *object_name;

			nlog(LOG_INFO, "start_dhcp: DHCP timed out for %s",
			    name);
			if (nwam_ncu_name_to_typed_name(name,
			    NWAM_NCU_TYPE_INTERFACE, &object_name)
			    != NWAM_SUCCESS) {
				nlog(LOG_ERR, "start_dhcp: "
				    "nwam_ncu_name_to_typed_name failed");
				goto failed;
			}
			nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
			    object_name, NWAM_STATE_OFFLINE_TO_ONLINE,
			    NWAM_AUX_STATE_IF_DHCP_TIMED_OUT);
			nwamd_create_ncu_check_event(0);

			free(object_name);
			goto failed;

		} else if (rc == DHCP_IPC_E_RUNNING) {
			/*
			 * DHCP is already running.  Check if IP address is
			 * already configured on the interface.
			 */

			icfg_handle_t h;
			icfg_if_t intf;
			struct sockaddr_in sin;
			socklen_t alen = sizeof (struct sockaddr_in);
			int plen, index;
			uint64_t flags;
			nwamd_event_t ip_event;

			nlog(LOG_ERR, "start_dhcp: DHCP already running on %s",
			    name);

			(void) strlcpy(intf.if_name, name,
			    sizeof (intf.if_name));
			intf.if_protocol = AF_INET;

			if (icfg_open(&h, &intf) != ICFG_SUCCESS) {
				nlog(LOG_ERR, "start_dhcp: "
				    "icfg_open failed on %s", name);
				goto failed;
			}

			/* Get address */
			if (icfg_get_addr(h, (struct sockaddr *)&sin, &alen,
			    &plen, B_FALSE) != ICFG_SUCCESS) {
				nlog(LOG_ERR, "start_dhcp: "
				    "icfg_get_addr failed on %s: %s",
				    name, strerror(errno));
				goto bail;
			}
			/* Check if 0.0.0.0 */
			if (sin.sin_addr.s_addr == INADDR_ANY) {
				nlog(LOG_ERR, "start_dhcp: empty address on %s",
				    name);
				goto bail;
			}

			/* valid address exists, get the flags, index of intf */
			if (icfg_get_flags(h, &flags) != ICFG_SUCCESS) {
				nlog(LOG_ERR, "start_dhcp: "
				    "icfg_get_flags failed on %s", name);
				goto bail;
			}
			if (icfg_get_index(h, &index) != ICFG_SUCCESS) {
				nlog(LOG_ERR, "start_dhcp: "
				    "icfg_get_index failed on %s", name);
				goto bail;
			}

			/* synthesize an IF_STATE event with the intf's flags */
			ip_event = nwamd_event_init_if_state(name, flags,
			    B_TRUE, index, (struct sockaddr *)&sin);
			if (ip_event != NULL)
				nwamd_event_enqueue(ip_event);
bail:
			icfg_close(h);
			goto failed;

		} else if ((rc == DHCP_IPC_E_SOCKET ||
		    rc == DHCP_IPC_E_INVIF) && retries++ < NWAMD_DHCP_RETRIES) {
			/*
			 * Retry DHCP request as we may have been unplumbing
			 * as part of the configuration phase.
			 */
			nlog(LOG_ERR, "start_dhcp %s: %s; will retry in %d sec",
			    name, dhcp_ipc_strerror(rc),
			    rc == DHCP_IPC_E_INVIF ?
			    NWAMD_DHCP_RETRY_WAIT_TIME : 0);
			if (rc == DHCP_IPC_E_INVIF)
				(void) sleep(NWAMD_DHCP_RETRY_WAIT_TIME);
			goto retry;
		} else {
			nlog(LOG_ERR, "start_dhcp %s: %s", name,
			    dhcp_ipc_strerror(rc));
			goto failed;
		}
	}

	/* If status was the command, then output the results */
	if (DHCP_IPC_CMD(type) == DHCP_STATUS) {
		nlog(LOG_DEBUG, "%s", dhcp_status_hdr_string());
		nlog(LOG_DEBUG, "%s", dhcp_status_reply_to_string(reply));
	}

failed:
	free(reply);
	if (arg != NULL) {
		free(name);
		free(arg);
	}
	return (NULL);
}

void
nwamd_start_dhcp(nwamd_ncu_t *ncu)
{
	struct nwamd_dhcp_thread_arg *arg;
	char *name = NULL;
	pthread_attr_t attr;

	nlog(LOG_DEBUG, "nwamd_start_dhcp: starting DHCP for %s %d",
	    ncu->ncu_name, ncu->ncu_type);

	arg = malloc(sizeof (*arg));
	if (arg == NULL) {
		nlog(LOG_ERR, "nwamd_start_dhcp: error allocating memory "
		    "for dhcp request");
		free(name);
		return;
	}

	arg->name = strdup(ncu->ncu_name);
	arg->type = DHCP_START;
	arg->timeout = ncu_wait_time;

	(void) pthread_attr_init(&attr);
	(void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (pthread_create(NULL, &attr, start_dhcp_thread, arg) == -1) {
		nlog(LOG_ERR, "nwamd_start_dhcp: cannot start dhcp thread");
		free(name);
		free(arg);
		(void) pthread_attr_destroy(&attr);
		return;
	}
	(void) pthread_attr_destroy(&attr);
}
