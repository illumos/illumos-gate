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

#include <arpa/inet.h>
#include <assert.h>
#include <dhcpagent_ipc.h>
#include <dhcp_inittab.h>
#include <dhcp_symbol.h>
#include <dhcpagent_util.h>
#include <errno.h>
#include <execinfo.h>
#include <libnwam.h>
#include <stdlib.h>
#include <strings.h>
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

static void nwamd_dhcp(const char *, ipadm_addrobj_t, dhcp_ipc_type_t);
static void nwamd_down_interface(const char *, ipadm_addr_type_t, const char *);
static boolean_t stateless_running(const nwamd_ncu_t *);

/*
 * Given a sockaddr representation of an IPv4 or IPv6 address returns the
 * string representation. Note that 'sockaddr' should point at the correct
 * sockaddr structure for the address family (sockaddr_in for AF_INET or
 * sockaddr_in6 for AF_INET6) or alternatively at a sockaddr_storage
 * structure.
 */
static const char *
nwamd_sockaddr2str(const struct sockaddr *addr, char *str, size_t len)
{
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	const char *straddr;

	if (addr == NULL)
		return (NULL);

	if (addr->sa_family == AF_INET) {
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		sin = (struct sockaddr_in *)addr;
		straddr = inet_ntop(AF_INET, (void *)&sin->sin_addr, str, len);
	} else if (addr->sa_family == AF_INET6) {
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		sin6 = (struct sockaddr_in6 *)addr;
		straddr = inet_ntop(AF_INET6, (void *)&sin6->sin6_addr, str,
		    len);
	} else {
		errno = EINVAL;
		return (NULL);
	}
	return (straddr != NULL ? str : NULL);
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
	dhcp_ipc_request_t *request = NULL;
	dhcp_ipc_reply_t *reply;
	DHCP_OPT *opt;
	size_t opt_len;
	char *value; /* return value */
	int err;
	char errmsg[LINE_MAX];

	/* if interface is not given, change it to empty string */
	if (ifname == NULL)
		ifname = "";

	/* find code and category in dhcp_inittab(5) */
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
nwamd_add_default_routes(nwamd_ncu_t *ncu)
{
	nwamd_if_t *nif = &ncu->ncu_if;
	char str[INET6_ADDRSTRLEN];

	if (nif->nwamd_if_ipv4 && nif->nwamd_if_ipv4_default_route_set) {
		struct sockaddr_in v4dest, v4mask;

		v4dest.sin_addr.s_addr = htonl(INADDR_ANY);
		v4dest.sin_family = AF_INET;

		v4mask.sin_addr.s_addr = 0;
		v4mask.sin_family = AF_INET;

		nlog(LOG_DEBUG, "nwamd_add_default_routes: adding default "
		    "route %s", nwamd_sockaddr2str((struct sockaddr *)
		    &nif->nwamd_if_ipv4_default_route, str,
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
		    "route %s", nwamd_sockaddr2str((struct sockaddr *)
		    &nif->nwamd_if_ipv6_default_route, str,
		    sizeof (str)));
		nwamd_add_route((struct sockaddr *)&v6dest,
		    (struct sockaddr *)&v6mask,
		    (struct sockaddr *)&nif->nwamd_if_ipv6_default_route,
		    ncu->ncu_name);
	}
}

/*
 * Returns the nwamd_if_address structure for the given static address,
 * NULL if not found.
 */
static struct nwamd_if_address *
find_static_address(const struct sockaddr_storage *addr, const nwamd_ncu_t *ncu)
{
	struct nwamd_if_address *nifap, *nifa = ncu->ncu_if.nwamd_if_list;
	struct sockaddr_storage saddr;
	char str[INET6_ADDRSTRLEN];

	nlog(LOG_DEBUG, "find_static_address: %s",
	    nwamd_sockaddr2str((struct sockaddr *)addr, str, sizeof (str)));
	for (nifap = nifa; nifap != NULL; nifap = nifap->next) {
		if (nifap->ipaddr_atype != IPADM_ADDR_STATIC ||
		    ipadm_get_addr(nifap->ipaddr, &saddr) != IPADM_SUCCESS)
			continue;

		if (sockaddrcmp(addr, &saddr))
			return (nifap);
	}
	return (NULL);
}

/*
 * Returns the nwamd_if_address structure representing the non-static address
 * in the NCU.  For IPv6, both stateless and stateful (DHCPv6) share the same
 * nwamd_if_address.  Will only return the nwamd_if_address if the relevant
 * address is configured (v4 DHCP, v6 either stateless or stateless) for the
 * NCU.  Returns NULL if the structure is not found.
 */
static struct nwamd_if_address *
find_nonstatic_address(const nwamd_ncu_t *ncu, sa_family_t family)
{
	struct nwamd_if_address *nifap, *nifa = ncu->ncu_if.nwamd_if_list;
	const nwamd_if_t *u_if = &ncu->ncu_if;

	nlog(LOG_DEBUG, "find_nonstatic_address for %s %s",
	    (family == AF_INET ? "IPv4" : "IPv6"),  ncu->ncu_name);
	for (nifap = nifa; nifap != NULL; nifap = nifap->next) {
		if (nifap->ipaddr_atype == IPADM_ADDR_STATIC)
			continue;

		if (family == AF_INET) {
			if (nifap->ipaddr_atype == IPADM_ADDR_DHCP &&
			    u_if->nwamd_if_dhcp_requested)
				return (nifap);
		} else if (family == AF_INET6) {
			if (nifap->ipaddr_atype == IPADM_ADDR_IPV6_ADDRCONF &&
			    (u_if->nwamd_if_stateful_requested ||
			    u_if->nwamd_if_stateless_requested))
				return (nifap);
		}
	}
	return (NULL);
}

/*
 * Returns the nwamd_if_address structure that configured the given address,
 * NULL if not found.
 */
static struct nwamd_if_address *
find_configured_address(const struct sockaddr_storage *addr,
    const nwamd_ncu_t *ncu)
{
	struct nwamd_if_address *nifap, *nifa = ncu->ncu_if.nwamd_if_list;
	char str[INET6_ADDRSTRLEN];

	nlog(LOG_DEBUG, "find_configured_address: %s",
	    nwamd_sockaddr2str((struct sockaddr *)addr, str, sizeof (str)));
	for (nifap = nifa; nifap != NULL; nifap = nifap->next) {
		if (sockaddrcmp(addr, &nifap->conf_addr) ||
		    sockaddrcmp(addr, &nifap->conf_stateless_addr))
			return (nifap);
	}
	return (NULL);
}

/*
 * Are one or more static addresses configured?
 */
boolean_t
nwamd_static_addresses_configured(nwamd_ncu_t *ncu, sa_family_t family)
{
	struct nwamd_if_address *n;

	for (n = ncu->ncu_if.nwamd_if_list; n != NULL; n = n->next) {
		if (n->ipaddr_atype != IPADM_ADDR_STATIC)
			continue;
		if ((family == AF_UNSPEC || family == n->family) &&
		    n->configured)
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
	struct sockaddr_storage addr;
	uint64_t flags;
	boolean_t rv = B_FALSE;
	ipadm_addr_info_t *addrinfo, *a;
	ipadm_status_t ipstatus;

	if ((ipstatus = ipadm_addr_info(ipadm_handle, ncu->ncu_name, &addrinfo,
	    0, 0)) != IPADM_SUCCESS) {
		nlog(LOG_ERR, "nwamd_dhcp_managing: "
		    "ipadm_addr_info failed for %s: %s",
		    ncu->ncu_name, ipadm_status2str(ipstatus));
		return (B_FALSE);
	}

	for (a = addrinfo; a != NULL; a = IA_NEXT(a)) {
		/*
		 * WARNING: This memcpy() assumes knowledge of the
		 * implementation of getifaddrs() and that it always
		 * uses sockaddr_storage as the backing store for
		 * address information, thus making it possible to
		 * copy the entire structure rather than do it on
		 * the size of the sockaddr according to family.
		 * This assumption is made elsewhere in this file.
		 */
		(void) memcpy(&addr, a->ia_ifa.ifa_addr, sizeof (addr));

		/* is this address an expected static one? */
		if (find_static_address(&addr, ncu) != NULL)
			continue;

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
			continue;
		}

		flags = a->ia_ifa.ifa_flags;
		if (flags & IFF_DHCPRUNNING) {
			/*
			 * If we get here we have an address that has the
			 * DHCP flag set and isn't an expected static address.
			 */
			rv = B_TRUE;
			break;
		}
	}

	ipadm_free_addr_info(addrinfo);
	return (rv);
}

/*
 * Return B_TRUE if IPv4 is requested in the given NCU.
 */
static boolean_t
nwamd_v4_requested(nwamd_ncu_t *ncu)
{
	boolean_t anyv4_requested;
	nwamd_if_t *u_if;

	anyv4_requested = B_FALSE;
	u_if = &ncu->ncu_if;
	if (u_if->nwamd_if_dhcp_requested) {
		anyv4_requested = B_TRUE;
	} else {
		struct nwamd_if_address *n;

		for (n = u_if->nwamd_if_list; n != NULL; n = n->next) {
			if (n->family == AF_INET &&
			    n->ipaddr_atype == IPADM_ADDR_STATIC)
				break;
		}
		if (n != NULL)
			anyv4_requested = B_TRUE;
	}

	return (anyv4_requested);
}

/*
 * Returns B_TRUE if IPv6 is requested in the given NCU.
 */
static boolean_t
nwamd_v6_requested(nwamd_ncu_t *ncu)
{
	boolean_t anyv6_requested;
	nwamd_if_t *u_if;

	anyv6_requested = B_FALSE;
	u_if = &ncu->ncu_if;
	if (u_if->nwamd_if_stateful_requested ||
	    u_if->nwamd_if_stateless_requested) {
		anyv6_requested = B_TRUE;
	} else {
		struct nwamd_if_address *n;

		for (n = u_if->nwamd_if_list; n != NULL; n = n->next) {
			if (n->family == AF_INET6 &&
			    n->ipaddr_atype == IPADM_ADDR_STATIC)
				break;
		}
		if (n != NULL)
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

static boolean_t
stateless_running(const nwamd_ncu_t *ncu)
{
	ipadm_addr_info_t *ainfo, *ainfop;
	ipadm_status_t ipstatus;
	boolean_t rv = B_FALSE;
	uint64_t flags;

	if ((ipstatus = ipadm_addr_info(ipadm_handle, ncu->ncu_name, &ainfo,
	    0, 0)) != IPADM_SUCCESS) {
		nlog(LOG_ERR, "stateless_running: "
		    "ipadm_addr_info failed for %s: %s",
		    ncu->ncu_name, ipadm_status2str(ipstatus));
		return (B_FALSE);
	}

	for (ainfop = ainfo; ainfop != NULL; ainfop = IA_NEXT(ainfop)) {
		if (ainfop->ia_ifa.ifa_addr->sa_family != AF_INET6)
			continue;
		flags = ainfop->ia_ifa.ifa_flags;
		if (flags & STATELESS_RUNNING) {
			rv = B_TRUE;
			break;
		}
	}
	ipadm_free_addr_info(ainfo);
	return (rv);
}

/*
 * Returns the addrinfo associated with the given address.  There is always
 * only one addrinfo for each address.
 */
static boolean_t
addrinfo_for_addr(const struct sockaddr_storage *caddr, const char *ifname,
    ipadm_addr_info_t **ainfo)
{
	ipadm_addr_info_t *addrinfo, *ainfop, *last = NULL;
	ipadm_status_t ipstatus;

	ipstatus = ipadm_addr_info(ipadm_handle, ifname, &addrinfo, 0, 0);
	if (ipstatus != IPADM_SUCCESS) {
		nlog(LOG_INFO, "addrinfo_for_addr: "
		    "ipadm_addr_info failed for %s: %s",
		    ifname, ipadm_status2str(ipstatus));
		return (B_FALSE);
	}

	*ainfo = NULL;
	for (ainfop = addrinfo; ainfop != NULL; ainfop = IA_NEXT(ainfop)) {
		struct sockaddr_storage addr;

		(void) memcpy(&addr, ainfop->ia_ifa.ifa_addr, sizeof (addr));
		/*
		 * If addresses match, rearrange pointers so that addrinfo
		 * does not contain a, and return a.
		 */
		if (sockaddrcmp(&addr, caddr)) {
			if (last != NULL)
				last->ia_ifa.ifa_next = ainfop->ia_ifa.ifa_next;
			else
				addrinfo = IA_NEXT(ainfop);

			ainfop->ia_ifa.ifa_next = NULL;
			*ainfo = ainfop;
			break;
		}
		last = ainfop;
	}
	ipadm_free_addr_info(addrinfo);
	return (*ainfo == NULL ? B_FALSE : B_TRUE);
}

/*
 * Returns B_TRUE if the addrinfo associated with the given ipaddr using its
 * aobjname is found.  An addrinfo list is created and returned in ainfo.
 * Stateless and stateful IPv6 addrinfo have the same aobjname, thus the need
 * to create a list of addrinfo.
 */
static boolean_t
addrinfo_for_ipaddr(ipadm_addrobj_t ipaddr, const char *ifname,
    ipadm_addr_info_t **ainfo)
{
	char aobjname[IPADM_AOBJSIZ];
	ipadm_addr_info_t *addrinfo, *ainfop;
	ipadm_addr_info_t *last = NULL;
	ipadm_status_t ipstatus;

	ipstatus = ipadm_get_aobjname(ipaddr, aobjname, sizeof (aobjname));
	if (ipstatus != IPADM_SUCCESS)
		return (B_FALSE);

	ipstatus = ipadm_addr_info(ipadm_handle, ifname, &addrinfo, 0, 0);
	if (ipstatus != IPADM_SUCCESS) {
		nlog(LOG_INFO, "addrinfo_for_ipaddr: "
		    "ipadm_addr_info failed for %s: %s",
		    ifname, ipadm_status2str(ipstatus));
		return (B_FALSE);
	}

	*ainfo = NULL;
	ainfop = addrinfo;
	while (ainfop != NULL) {
		/* If aobjnames match, rearrange pointers to create new list */
		if (strcmp(ainfop->ia_aobjname, aobjname) == 0) {
			ipadm_addr_info_t *match = ainfop;

			ainfop = IA_NEXT(ainfop); /* move iterator */
			if (last != NULL)
				last->ia_ifa.ifa_next = match->ia_ifa.ifa_next;
			else
				addrinfo = ainfop;
			if (*ainfo == NULL)
				match->ia_ifa.ifa_next = NULL;
			else
				match->ia_ifa.ifa_next = &(*ainfo)->ia_ifa;
			*ainfo = match;
		} else {
			last = ainfop;
			ainfop = IA_NEXT(ainfop);
		}
	}
	ipadm_free_addr_info(addrinfo);
	return (*ainfo == NULL ? B_FALSE : B_TRUE);
}

/*
 * Add the address provided in the nwamd_if_address.  If DHCP is required,
 * start DHCP.  If a static address is configured, create the address; then do
 * a DHCP_INFORM (in a separate thread) to get other networking configuration
 * parameters.  RTM_NEWADDRs - translated into IF_STATE events - will then
 * finish the job of bringing the NCU online.
 */
static boolean_t
add_ip_address(const char *ifname, const struct nwamd_if_address *nifa,
    boolean_t *do_inform)
{
	ipadm_status_t ipstatus;
	ipadm_addr_info_t *addrinfo = NULL;
	uint64_t flags;

	if (nifa->ipaddr_atype == IPADM_ADDR_DHCP) {
		/*
		 * To make getting a DHCP address asynchronous, call
		 * ipadm_create_addr() in a new thread.
		 */
		nlog(LOG_DEBUG, "add_ip_address: "
		    "adding IPv4 DHCP address on %s", ifname);
		nwamd_dhcp(ifname, nifa->ipaddr, DHCP_START);
	} else {
		nlog(LOG_DEBUG, "add_ip_address: adding %s address on %s",
		    (nifa->ipaddr_atype == IPADM_ADDR_STATIC ?
		    "STATIC" : "IPv6 ADDRCONF"), ifname);
		if ((ipstatus = ipadm_create_addr(ipadm_handle, nifa->ipaddr,
		    IPADM_OPT_ACTIVE | IPADM_OPT_UP)) != IPADM_SUCCESS) {
			nlog(LOG_ERR, "add_ip_address: "
			    "ipadm_create_addr failed on %s: %s",
			    ifname, ipadm_status2str(ipstatus));
			return (B_FALSE);
		}
		/*
		 * When creating a static address, ipadm_create_addr() returns
		 * SUCCESS even if duplicate address is detected.  Retrieve
		 * the addrinfo to get the flags.
		 */
		if (nifa->ipaddr_atype == IPADM_ADDR_STATIC) {
			/*
			 * Since we are configuring a static address, there
			 * will be just *ONE* addrinfo with the aobjname in
			 * nifa->ipaddr.
			 */
			if (!addrinfo_for_ipaddr(nifa->ipaddr, ifname,
			    &addrinfo)) {
				nlog(LOG_ERR, "add_ip_address: "
				    "could not find addrinfo on %s", ifname);
				return (B_FALSE);
			}

			flags = addrinfo->ia_ifa.ifa_flags;
			ipadm_free_addr_info(addrinfo);
			if (flags & IFF_DUPLICATE) {
				char *object_name;
				nwam_error_t err;

				nlog(LOG_INFO, "add_ip_address: "
				    "duplicate address detected on %s", ifname);
				if ((err = nwam_ncu_name_to_typed_name(ifname,
				    NWAM_NCU_TYPE_INTERFACE, &object_name))
				    == NWAM_SUCCESS) {
					nwamd_object_set_state(
					    NWAM_OBJECT_TYPE_NCU,
					    object_name, NWAM_STATE_MAINTENANCE,
					    NWAM_AUX_STATE_IF_DUPLICATE_ADDR);
					free(object_name);
				} else {
					nlog(LOG_ERR, "add_ip_address: "
					    "could not create state event "
					    "for %s: %s",
					    ifname, nwam_strerror(err));
				}
				return (B_FALSE);
			}
			/*
			 * Do DHCP_INFORM using async ipadm_refresh_addr().
			 * Only need to do this once per interface, and we
			 * do *not* need to do it if we are also getting a
			 * dhcp lease; so we only send the INFORM if the
			 * passed-in flag says to, and we clear the flag
			 * once we've initiated the INFORM transaction.
			 */
			if (*do_inform) {
				nwamd_dhcp(ifname, nifa->ipaddr, DHCP_INFORM);
				*do_inform = B_FALSE;
			}
		}
	}

	return (B_TRUE);
}

/*
 * Adds addresses for the given NCU.
 */
void
nwamd_configure_interface_addresses(nwamd_ncu_t *ncu)
{
	struct nwamd_if_address *nifap, *nifa = ncu->ncu_if.nwamd_if_list;
	boolean_t do_inform;

	/* only need an inform if we're not also getting a dhcp lease */
	do_inform = !ncu->ncu_if.nwamd_if_dhcp_requested;

	nlog(LOG_DEBUG, "nwamd_configure_interface_addresses(%s)",
	    ncu->ncu_name);

	for (nifap = nifa; nifap != NULL; nifap = nifap->next) {
		if (nifap->configured)
			continue;

		nifap->configured = add_ip_address(ncu->ncu_name, nifap,
		    &do_inform);
	}
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
		nlog(LOG_INFO, "nwamd_ncu_handle_if_state_event: no object %s",
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
		char addrstr[INET6_ADDRSTRLEN];
		boolean_t static_addr = B_FALSE, addr_added;
		boolean_t v4dhcp_running, v6dhcp_running, stateless_running;
		ipadm_addr_info_t *ai = NULL, *addrinfo = NULL;
		boolean_t stateless_ai_found = B_FALSE;
		boolean_t stateful_ai_found = B_FALSE;
		struct nwamd_if_address *nifa = NULL;
		nwamd_if_t *u_if;
		struct sockaddr_storage *addr, ai_addr, *aip = NULL;
		ushort_t family;
		uint64_t flags = 0;

		if_state = &evm->nwe_data.nwe_if_state;
		u_if = &ncu->ncu_if;
		family = if_state->nwe_addr.ss_family;
		addr = &if_state->nwe_addr;
		addr_added = if_state->nwe_addr_added;

		v4dhcp_running = B_FALSE;
		v6dhcp_running = B_FALSE;
		stateless_running = B_FALSE;

		nlog(LOG_DEBUG,
		    "nwamd_ncu_handle_if_state_event: addr %s %s",
		    nwamd_sockaddr2str((struct sockaddr *)addr, addrstr,
		    sizeof (addrstr)), addr_added ? "added" : "removed");

		/*
		 * Need to get flags for this interface.  Get the addrinfo for
		 * the address that generated this IF_STATE event.
		 */
		if (addr_added) {
			/*
			 * Address was added.  Find the addrinfo for this
			 * address and the nwamd_if_address corresponding to
			 * this address.
			 */
			if (!addrinfo_for_addr(addr, ncu->ncu_name, &ai)) {
				nlog(LOG_ERR,
				    "nwamd_ncu_handle_if_state_event: "
				    "addrinfo doesn't exist for %s", addrstr);
				nwamd_event_do_not_send(event);
				goto valid_done;
			}
			addrinfo = ai;
			flags = addrinfo->ia_ifa.ifa_flags;
			(void) memcpy(&ai_addr, addrinfo->ia_ifa.ifa_addr,
			    sizeof (ai_addr));
			aip = &ai_addr;

			if (addrinfo->ia_atype == IPADM_ADDR_IPV6_ADDRCONF ||
			    addrinfo->ia_atype == IPADM_ADDR_DHCP)
				nifa = find_nonstatic_address(ncu, family);
			else if (addrinfo->ia_atype == IPADM_ADDR_STATIC)
				nifa = find_static_address(addr, ncu);

			/*
			 * If nwamd_if_address is not found, then this address
			 * isn't one that nwamd created.  Remove it.
			 */
			if (nifa == NULL) {
				nlog(LOG_ERR,
				    "nwamd_ncu_handle_if_state_event: "
				    "address %s not managed by nwam added, "
				    "removing it", addrstr);
				nwamd_down_interface(addrinfo->ia_aobjname,
				    addrinfo->ia_atype, ncu->ncu_name);
				nwamd_event_do_not_send(event);
				goto valid_done;
			}

			/* check flags to determine how intf is configured */
			stateless_running = (family == AF_INET6) &&
			    ((flags & STATELESS_RUNNING) == STATELESS_RUNNING);
			v4dhcp_running = (family == AF_INET) &&
			    ((flags & DHCP_RUNNING) == DHCP_RUNNING);
			v6dhcp_running = (family == AF_INET6) &&
			    ((flags & DHCP_RUNNING) == DHCP_RUNNING);
			static_addr = (addrinfo->ia_atype == IPADM_ADDR_STATIC);

			/* copy the configured address into nwamd_if_address */
			if (stateless_running) {
				(void) memcpy(&nifa->conf_stateless_addr,
				    addrinfo->ia_ifa.ifa_addr,
				    sizeof (struct sockaddr_storage));
			} else {
				(void) memcpy(&nifa->conf_addr,
				    addrinfo->ia_ifa.ifa_addr,
				    sizeof (struct sockaddr_storage));
			}

		} else {
			/*
			 * Address was removed.  Find the nwamd_if_address
			 * that configured this address.
			 */
			nifa = find_configured_address(addr, ncu);
			if (nifa == NULL) {
				nlog(LOG_ERR,
				    "nwamd_ncu_handle_if_state_event: "
				    "address %s not managed by nwam removed, "
				    "nothing to do", addrstr);
				nwamd_event_do_not_send(event);
				goto valid_done;
			}

			if (addrinfo_for_ipaddr(nifa->ipaddr, ncu->ncu_name,
			    &ai)) {
				ipadm_addr_info_t *a;
				for (a = ai; a != NULL; a = IA_NEXT(a)) {
					struct sockaddr_storage stor;

					(void) memcpy(&stor, a->ia_ifa.ifa_addr,
					    sizeof (stor));
					/*
					 * Since multiple addrinfo can have
					 * the same ipaddr, find the one for
					 * the address that generated this
					 * state event.
					 */
					if (sockaddrcmp(addr, &stor)) {
						flags = a->ia_ifa.ifa_flags;
						(void) memcpy(&ai_addr,
						    a->ia_ifa.ifa_addr,
						    sizeof (ai_addr));
						aip = &ai_addr;
						addrinfo = a;
					}
					/*
					 * Stateful and stateless IPv6
					 * addrinfo have the same aobjname.
					 * Use the flags to determine which
					 * address is present in the system.
					 */
					if (family == AF_INET6) {
						stateless_ai_found =
						    (a->ia_ifa.ifa_flags &
						    STATELESS_RUNNING);
						stateful_ai_found =
						    (a->ia_ifa.ifa_flags &
						    DHCP_RUNNING);
					}
				}
			}
		}

		/* Set the flags in the event for listeners */
		evm->nwe_data.nwe_if_state.nwe_flags = flags;

		if (family == AF_INET && !addr_added) {
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
			if (((struct sockaddr_in *)addr)->sin_addr.s_addr
			    == INADDR_ANY && aip != 0) {
				struct sockaddr_in *a;
				char astr[INET6_ADDRSTRLEN];
				a = (struct sockaddr_in *)aip;

				if ((flags & IFF_UP) &&
				    !(flags & IFF_RUNNING) &&
				    a->sin_addr.s_addr != INADDR_ANY) {
					nlog(LOG_DEBUG,
					    "nwamd_ncu_handle_if_state_event: "
					    "bug workaround: clear out addr "
					    "%s on %s", nwamd_sockaddr2str
					    ((struct sockaddr *)a, astr,
					    sizeof (astr)),
					    ncu->ncu_name);
					nwamd_down_interface(
					    addrinfo->ia_aobjname,
					    IPADM_ADDR_DHCP, ncu->ncu_name);
				}
				goto valid_done;
			}
		}

		/*
		 * If we received an RTM_NEWADDR and the IFF_UP flags has not
		 * been set, ignore this IF_STATE event.  Once the IFF_UP flag
		 * is set, we'll get another RTM_NEWADDR message.
		 */
		if (addr_added & !(flags & IFF_UP)) {
			nlog(LOG_INFO, "nwamd_ncu_handle_if_state_event: "
			    "address %s added on %s without IFF_UP flag (%x), "
			    "ignoring IF_STATE event",
			    addrstr, ncu->ncu_name, flags);
			nwamd_event_do_not_send(event);
			goto valid_done;
		}

		/*
		 * Has the address really been removed?  Sometimes spurious
		 * RTM_DELADDRs are generated, so we need to ensure that
		 * the address is really gone.  If IFF_DUPLICATE is set,
		 * we're getting the RTM_DELADDR due to DAD, so don't test
		 * in that case.
		 */
		if (!addr_added && !(flags & IFF_DUPLICATE)) {
			if (aip != 0 && sockaddrcmp(addr, aip)) {
				nlog(LOG_INFO,
				    "nwamd_ncu_handle_if_state_event: "
				    "address %s is not really gone from %s, "
				    "ignoring IF_STATE event",
				    addrstr, ncu->ncu_name);
				nwamd_event_do_not_send(event);
				goto valid_done;
			}
		}

		if (addr_added) {
			/*
			 * Address has been added.
			 *
			 * We need to make sure that we really want to keep
			 * this address.  There is a race where we requested an
			 * address but by the time we got here we don't really
			 * want it and need to remove it.
			 *
			 * Once we decide we want the address adjust the ncu
			 * state accordingly.  For example if this address is
			 * enough move online.
			 */
			if (u_if->nwamd_if_dhcp_requested && v4dhcp_running) {
				u_if->nwamd_if_dhcp_configured = B_TRUE;
			} else if (u_if->nwamd_if_stateful_requested &&
			    v6dhcp_running) {
				u_if->nwamd_if_stateful_configured = B_TRUE;
			} else if (u_if->nwamd_if_stateless_requested &&
			    stateless_running) {
				u_if->nwamd_if_stateless_configured = B_TRUE;
			} else if (!static_addr) {
				/*
				 * This is something we didn't expect.  Remove
				 * the address.
				 */
				nwamd_down_interface(addrinfo->ia_aobjname,
				    addrinfo->ia_atype, ncu->ncu_name);
				nifa->configured = B_FALSE;
				goto valid_done;
			}

			/*
			 * The address looks valid so mark configured and
			 * move online if we either have a v4 address if
			 * v4 is configured or a v6 address if only v6 is
			 * configured.
			 */
			nifa->configured = B_TRUE;
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
			nifa->configured = B_FALSE;

			if (!static_addr && family == AF_INET) {
				u_if->nwamd_if_dhcp_configured = B_FALSE;
			} else if (!static_addr && family == AF_INET6) {
				/*
				 * The address is already gone.  When looking
				 * for the addrinfo (using aobjname in
				 * ipaddr), we found addrinfo for either one
				 * or both stateless and stateful.  Using the
				 * flags we determined whether each was
				 * configured or not.  Update the flags here
				 * accordingly.
				 */
				u_if->nwamd_if_stateful_configured =
				    stateless_ai_found;
				u_if->nwamd_if_stateless_configured =
				    stateful_ai_found;
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
valid_done:
		ipadm_free_addr_info(ai);
	}
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
 * Remove the address in the given aobjname.  IPADM_OPT_RELEASE is specified
 * for a DHCP address and specifies that the DHCP lease should also be released.
 * ifname is only used for nlog().
 */
static void
nwamd_down_interface(const char *aobjname, ipadm_addr_type_t atype,
    const char *ifname)
{
	ipadm_status_t ipstatus;
	uint32_t rflags = (atype == IPADM_ADDR_DHCP ? IPADM_OPT_RELEASE : 0);

	nlog(LOG_DEBUG, "nwamd_down_interface: %s [aobjname = %s]",
	    ifname, aobjname);
	if ((ipstatus = ipadm_delete_addr(ipadm_handle, aobjname,
	    IPADM_OPT_ACTIVE | rflags)) != IPADM_SUCCESS) {
		nlog(LOG_ERR, "nwamd_down_interface: "
		    "ipadm_delete_addr failed on %s: %s",
		    ifname, ipadm_status2str(ipstatus));
	}
}

static void
unconfigure_addresses(nwamd_ncu_t *ncu, sa_family_t af)
{
	struct nwamd_if_address *nifap, *nifa = ncu->ncu_if.nwamd_if_list;

	for (nifap = nifa; nifap != NULL; nifap = nifap->next)
		if (af == AF_UNSPEC || nifap->family == af)
			nifap->configured = B_FALSE;
}

static void
dhcp_release(const char *ifname)
{
	ipadm_addr_info_t *ainfo, *ainfop;

	if (ipadm_addr_info(ipadm_handle, ifname, &ainfo, 0, 0)
	    != IPADM_SUCCESS)
		return;

	for (ainfop = ainfo; ainfop != NULL; ainfop = IA_NEXT(ainfop)) {
		if (ainfop->ia_atype == IPADM_ADDR_DHCP)
			nwamd_down_interface(ainfop->ia_aobjname,
			    ainfop->ia_atype, ifname);
	}
	ipadm_free_addr_info(ainfo);
}

static void
nwamd_plumb_unplumb_interface(nwamd_ncu_t *ncu, sa_family_t af, boolean_t plumb)
{
	char *ifname = ncu->ncu_name;
	nwamd_if_t *u_if = &ncu->ncu_if;
	ipadm_status_t ipstatus;

	nlog(LOG_DEBUG, "nwamd_plumb_unplumb_interface: %s %s %s",
	    (plumb ? "plumb" : "unplumb"), (af == AF_INET ? "IPv4" : "IPv6"),
	    ifname);

	if (plumb) {
		ipstatus = ipadm_create_if(ipadm_handle, ifname, af,
		    IPADM_OPT_ACTIVE);
	} else {
		/* release DHCP address, if any */
		if (af == AF_INET)
			dhcp_release(ifname);
		ipstatus = ipadm_delete_if(ipadm_handle, ifname, af,
		    IPADM_OPT_ACTIVE);
	}

	if (ipstatus != IPADM_SUCCESS) {
		if ((plumb && ipstatus != IPADM_IF_EXISTS) ||
		    (!plumb && ipstatus != IPADM_ENXIO)) {
			nlog(LOG_ERR, "nwamd_plumb_unplumb_interface: "
			    "%s %s failed for %s: %s",
			    (plumb ? "plumb" : "unplumb"),
			    (af == AF_INET ? "IPv4" : "IPv6"),
			    ifname, ipadm_status2str(ipstatus));
		}
	}

	/* Unset flags */
	if (!plumb) {
		unconfigure_addresses(ncu, af);
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
}

void
nwamd_plumb_interface(nwamd_ncu_t *ncu, sa_family_t af)
{
	/*
	 * We get all posssible privs by calling nwamd_deescalate().  During
	 * startup opening /dev/dld (data link management) needs all privs
	 * because we don't have access to /etc/security/device_policy yet.
	 */
	nwamd_escalate();
	nwamd_plumb_unplumb_interface(ncu, af, B_TRUE);
	nwamd_deescalate();
}

void
nwamd_unplumb_interface(nwamd_ncu_t *ncu, sa_family_t af)
{
	nwamd_plumb_unplumb_interface(ncu, af, B_FALSE);
}

static void *
start_dhcp_thread(void *arg)
{
	struct nwamd_dhcp_thread_arg *thread_arg = arg;
	nwamd_object_t ncu_obj;
	dhcp_ipc_type_t type;
	char *name;
	ipadm_addrobj_t ipaddr;
	ipadm_status_t ipstatus;
	int retries = 0;

	name = thread_arg->name;
	type = thread_arg->type;
	ipaddr = thread_arg->ipaddr;

retry:
	/* Make sure the NCU is in appropriate state for DHCP command */
	ncu_obj = nwamd_ncu_object_find(NWAM_NCU_TYPE_INTERFACE, name);
	if (ncu_obj == NULL) {
		nlog(LOG_ERR, "start_dhcp: no IP object %s", name);
		return (NULL);
	}

	if (ncu_obj->nwamd_object_state != NWAM_STATE_OFFLINE_TO_ONLINE &&
	    ncu_obj->nwamd_object_state != NWAM_STATE_ONLINE) {
		nlog(LOG_INFO, "start_dhcp: IP NCU %s is in invalid state "
		    "for DHCP command", ncu_obj->nwamd_object_name);
		nwamd_object_release(ncu_obj);
		return (NULL);
	}
	nwamd_object_release(ncu_obj);

	switch (type) {
	case DHCP_INFORM:
	{
		char aobjname[IPADM_AOBJSIZ];

		if ((ipstatus = ipadm_get_aobjname(ipaddr, aobjname,
		    sizeof (aobjname))) != IPADM_SUCCESS) {
			nlog(LOG_ERR, "start_dhcp: "
			    "ipadm_get_aobjname failed for %s: %s",
			    name, ipadm_status2str(ipstatus));
			goto done;
		}
		ipstatus = ipadm_refresh_addr(ipadm_handle, aobjname,
		    IPADM_OPT_ACTIVE | IPADM_OPT_INFORM);
		break;
	}
	case DHCP_START:
		ipstatus = ipadm_create_addr(ipadm_handle, ipaddr,
		    IPADM_OPT_ACTIVE);
		break;
	default:
		nlog(LOG_ERR, "start_dhcp: invalid dhcp_ipc_type_t: %d", type);
		goto done;
	}

	if (ipstatus == IPADM_DHCP_IPC_TIMEOUT) {
		/*
		 * DHCP timed out: for DHCP_START requests, change state for
		 * this NCU and euqueue event to check NCU priority-groups;
		 * for DHCP_INFORM requests, nothing to do.
		 */
		if (type == DHCP_START) {
			char *object_name;

			nlog(LOG_INFO,
			    "start_dhcp: DHCP_START timed out for %s", name);

			if (nwam_ncu_name_to_typed_name(name,
			    NWAM_NCU_TYPE_INTERFACE, &object_name)
			    != NWAM_SUCCESS) {
				nlog(LOG_ERR, "start_dhcp: "
				    "nwam_ncu_name_to_typed_name failed for %s",
				    name);
				goto done;
			}
			nwamd_object_set_state(NWAM_OBJECT_TYPE_NCU,
			    object_name, NWAM_STATE_OFFLINE_TO_ONLINE,
			    NWAM_AUX_STATE_IF_DHCP_TIMED_OUT);
			nwamd_create_ncu_check_event(0);
			free(object_name);
		} else {
			nlog(LOG_INFO,
			    "start_dhcp: DHCP_INFORM timed out for %s", name);
		}

	} else if ((ipstatus == IPADM_DHCP_IPC_ERROR ||
	    ipstatus == IPADM_IPC_ERROR) && retries++ < NWAMD_DHCP_RETRIES) {
		/*
		 * Retry DHCP request as we may have been unplumbing as part
		 * of the configuration phase.
		 */
		nlog(LOG_ERR, "start_dhcp: ipadm_%s_addr on %s returned: %s, "
		    "retrying in %d sec",
		    (type == DHCP_START ? "create" : "refresh"), name,
		    ipadm_status2str(ipstatus), NWAMD_DHCP_RETRY_WAIT_TIME);
		(void) sleep(NWAMD_DHCP_RETRY_WAIT_TIME);
		goto retry;

	} else if (ipstatus != IPADM_SUCCESS) {
		nlog(LOG_ERR, "start_dhcp: ipadm_%s_addr failed for %s: %s",
		    (type == DHCP_START ? "create" : "refresh"), name,
		    ipadm_status2str(ipstatus));
	}

done:
	free(name);
	free(arg);
	return (NULL);
}

static void
nwamd_dhcp(const char *ifname, ipadm_addrobj_t ipaddr, dhcp_ipc_type_t cmd)
{
	struct nwamd_dhcp_thread_arg *arg;
	pthread_attr_t attr;

	nlog(LOG_DEBUG, "nwamd_dhcp: starting DHCP %s thread for %s",
	    dhcp_ipc_type_to_string(cmd), ifname);

	arg = malloc(sizeof (*arg));
	if (arg == NULL) {
		nlog(LOG_ERR, "nwamd_dhcp: error allocating memory for "
		    "dhcp request");
		return;
	}

	arg->name = strdup(ifname);
	arg->type = cmd;
	arg->ipaddr = ipaddr;

	(void) pthread_attr_init(&attr);
	(void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (pthread_create(NULL, &attr, start_dhcp_thread, arg) == -1) {
		nlog(LOG_ERR, "nwamd_dhcp: cannot start dhcp thread");
		free(arg->name);
		free(arg);
		(void) pthread_attr_destroy(&attr);
		return;
	}
	(void) pthread_attr_destroy(&attr);
}
