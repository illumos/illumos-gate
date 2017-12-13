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
/*
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * Query and configure LAN interfaces over IPMI.  This is done through the
 * complicated get/set LAN Configuration Parameters command.  This queries or
 * sets the parameters one per command in series.  We hide this implementation
 * detail and instead export a single structure to consumers.
 */

#include <stddef.h>
#include <strings.h>

#include <libipmi.h>
#include <netinet/in.h>

#include "ipmi_impl.h"

typedef struct ipmi_cmd_lan_get_config {
	DECL_BITFIELD3(
	    ilgc_number		:4,
	    __reserved		:3,
	    ilgc_revonly	:1);
	uint8_t		ilgc_param;
	uint8_t		ilgc_set;
	uint8_t		ilgc_block;
} ipmi_cmd_lan_get_config_t;

typedef struct ipmi_cmd_lan_set_config {
	DECL_BITFIELD2(
	    ilsc_number		:4,
	    __reserved		:4);
	uint8_t		ilsc_param;
	uint8_t		ilsc_data[18];
} ipmi_cmd_lan_set_config_t;

#define	IPMI_LAN_SET_LEN(dlen)	\
	(offsetof(ipmi_cmd_lan_set_config_t, ilsc_data) + (dlen))

#define	IPMI_LAN_PARAM_SET_IN_PROGRESS		0
#define	IPMI_LAN_PARAM_IP_ADDR			3
#define	IPMI_LAN_PARAM_IP_SOURCE		4
#define	IPMI_LAN_PARAM_MAC_ADDR			5
#define	IPMI_LAN_PARAM_SUBNET_MASK		6
#define	IPMI_LAN_PARAM_GATEWAY_ADDR		12

/* VLAN/IPv6 parameters are currently only supported for GET operations */
#define	IPMI_LAN_PARAM_VLAN_ID			20
#define	IPMI_LAN_PARAM_IPVX_ENABLED		51
#define	IPMI_LAN_PARAM_IPV6_NUM_ADDRS		55
#define	IPMI_LAN_PARAM_IPV6_SADDR		56
#define	IPMI_LAN_PARAM_IPV6_DADDR		59
#define	IPMI_LAN_PARAM_IPV6_ROUTER_CONFIG	64
#define	IPMI_LAN_PARAM_IPV6_STATIC_ROUTE1	65
#define	IPMI_LAN_PARAM_IPV6_STATIC_ROUTE2	68
#define	IPMI_LAN_PARAM_IPV6_NUM_DYN_ROUTES	72
#define	IPMI_LAN_PARAM_IPV6_DYN_ROUTE		73

#define	IPMI_LAN_SET_COMPLETE			0x0
#define	IPMI_LAN_SET_INPROGRESS			0x1
#define	IPMI_LAN_SET_COMMIT			0x2

/* bitfield values of IPMI_LAN_PARAM_IPV6_ROUTER_CONFIG param */
#define	IPMI_LAN_IPV6_STATIC_ROUTES_ENABLED	0x1
#define	IPMI_LAN_IPV6_DYNAMIC_ROUTES_ENABLED	0x2

typedef struct ipmi_lan_entry {
	int	ile_param;
	int	ile_mask;
	int	ile_set;
	int	ile_block;
	size_t	ile_offset;
	size_t	ile_len;
} ipmi_lan_entry_t;

static ipmi_lan_entry_t ipmi_lan_ipv4_table[] = {
	{ IPMI_LAN_PARAM_IP_ADDR, IPMI_LAN_SET_IPADDR, 0, 0,
	    offsetof(ipmi_lan_config_t, ilc_ipaddr), sizeof (uint32_t) },
	{ IPMI_LAN_PARAM_IP_SOURCE, IPMI_LAN_SET_IPADDR_SOURCE, 0, 0,
	    offsetof(ipmi_lan_config_t, ilc_ipaddr_source), sizeof (uint8_t) },
	{ IPMI_LAN_PARAM_MAC_ADDR, IPMI_LAN_SET_MACADDR, 0, 0,
	    offsetof(ipmi_lan_config_t, ilc_macaddr), 6 * sizeof (uint8_t) },
	{ IPMI_LAN_PARAM_SUBNET_MASK, IPMI_LAN_SET_SUBNET, 0, 0,
	    offsetof(ipmi_lan_config_t, ilc_subnet), sizeof (uint32_t) },
	{ IPMI_LAN_PARAM_GATEWAY_ADDR, IPMI_LAN_SET_GATEWAY_ADDR, 0, 0,
	    offsetof(ipmi_lan_config_t, ilc_gateway_addr), sizeof (uint32_t) }
};

#define	IPMI_LAN_IPV4_NENTRIES	\
	(sizeof (ipmi_lan_ipv4_table) / sizeof (ipmi_lan_ipv4_table[0]))

static int
ipmi_lan_get_param(ipmi_handle_t *ihp, int channel, int param, int set,
    int block, void *data, size_t len)
{
	ipmi_cmd_t cmd, *rsp;
	ipmi_cmd_lan_get_config_t lcmd = { 0 };

	lcmd.ilgc_number = channel;
	lcmd.ilgc_param = param;
	lcmd.ilgc_set = set;
	lcmd.ilgc_block = block;

	cmd.ic_netfn = IPMI_NETFN_TRANSPORT;
	cmd.ic_lun = 0;
	cmd.ic_cmd = IPMI_CMD_GET_LAN_CONFIG;
	cmd.ic_data = &lcmd;
	cmd.ic_dlen = sizeof (lcmd);

	if ((rsp = ipmi_send(ihp, &cmd)) == NULL) {
		switch (ihp->ih_completion) {
		case 0x80:
			(void) ipmi_set_error(ihp, EIPMI_BADPARAM, NULL);
			break;
		}
		return (-1);
	}

	if (rsp->ic_dlen < len + 1)
		return (ipmi_set_error(ihp, EIPMI_BAD_RESPONSE_LENGTH, NULL));

	bcopy((uint8_t *)rsp->ic_data + 1, data, len);

	return (0);
}

struct ipmi_lan_ipv6_addr {
	uint8_t		ipva_selector;
	uint8_t		ipva_source;
	uint8_t		ipva_addr[16];
	uint8_t		ipva_prefixlen;
	uint8_t		ipva_status;
};

struct ipmi_lan_ipv6_numaddrs {
	uint8_t	inva_num_saddrs;
	uint8_t inva_num_daddrs;
	uint8_t	inva_support;
};

struct ipmi_lan_vlan_cfg {
	uint8_t	ivla_vlanid_lower;
	DECL_BITFIELD3(
	    ivla_vlanid_upper	:4,
	    __reserved		:3,
	    ivla_vlan_enable	:1);
};

int
ipmi_lan_get_config(ipmi_handle_t *ihp, int channel, ipmi_lan_config_t *cfgp)
{
	uint8_t set, enabled, route_cfg, ndynroutes = 0;
	int i, j;
	ipmi_lan_entry_t *lep;
	struct ipmi_lan_ipv6_numaddrs numaddrs = { 0 };
	struct ipmi_lan_ipv6_addr addrv6 = { 0 };
	struct ipmi_lan_vlan_cfg vlancfg = { 0 };
	struct in6_addr sroute1 = { 0 }, sroute2 = { 0 }, droute = { 0 };
	boolean_t found_addr = B_FALSE;
	boolean_t stat_routes_enabled = B_FALSE, dyn_routes_enabled = B_FALSE;

	if (ipmi_lan_get_param(ihp, channel, IPMI_LAN_PARAM_SET_IN_PROGRESS, 0,
	    0, &set, sizeof (set)) != 0)
		/* errno set */
		return (-1);

	if (set & IPMI_LAN_SET_INPROGRESS)
		cfgp->ilc_set_in_progress = B_TRUE;
	else
		cfgp->ilc_set_in_progress = B_FALSE;

	/*
	 * First determine which IP addressing modes (IPv4/6) are enabled. On
	 * service processors that don't support a version of IPMI that is
	 * IPv6-aware, this parameter won't exist.  If we fail to look it up
	 * then we'll assume that only IPv4 is enabled.
	 */
	if (ipmi_lan_get_param(ihp, channel, IPMI_LAN_PARAM_IPVX_ENABLED, 0, 0,
	    &enabled, sizeof (enabled)) != 0) {
		cfgp->ilc_ipv4_enabled = B_TRUE;
		cfgp->ilc_ipv6_enabled = B_FALSE;
	} else {
		switch (enabled) {
		case 0:
			cfgp->ilc_ipv4_enabled = B_TRUE;
			cfgp->ilc_ipv6_enabled = B_FALSE;
			break;
		case 1:
			cfgp->ilc_ipv4_enabled = B_FALSE;
			cfgp->ilc_ipv6_enabled = B_TRUE;
			break;
		case 2:
			cfgp->ilc_ipv4_enabled = B_TRUE;
			cfgp->ilc_ipv6_enabled = B_TRUE;
			break;
		default:
			return (ipmi_set_error(ihp, EIPMI_BAD_RESPONSE, NULL));
		}
	}

	/* If IPv4 support is enabled, gather the current configuration. */
	if (cfgp->ilc_ipv4_enabled == B_TRUE) {
		for (i = 0; i < IPMI_LAN_IPV4_NENTRIES; i++) {
			lep = &ipmi_lan_ipv4_table[i];
			if (ipmi_lan_get_param(ihp, channel, lep->ile_param,
			    lep->ile_set, lep->ile_block,
			    (char *)cfgp + lep->ile_offset, lep->ile_len) != 0)
				/* errno set */
				return (-1);
		}
	}

	/* Next check if VLAN is enabled, and if so,  grab the VLAN ID. */
	if (ipmi_lan_get_param(ihp, channel, IPMI_LAN_PARAM_VLAN_ID, 0,
	    0, &vlancfg, sizeof (struct ipmi_lan_vlan_cfg)) != 0) {
		/* errno set */
		return (-1);
	}
	cfgp->ilc_vlan_enabled = vlancfg.ivla_vlan_enable;
	if (cfgp->ilc_vlan_enabled == B_TRUE) {
		cfgp->ilc_vlan_id = (vlancfg.ivla_vlanid_upper << 8) |
		    vlancfg.ivla_vlanid_lower;
	}

	/* If IPv6 support isn't enabled, then we're all done here. */
	if (cfgp->ilc_ipv6_enabled != B_TRUE)
		return (0);

	/*
	 * First check for a static address.  If we can't find one, we'll look
	 * for a dynamic address.  The spec allows for multiple IPv6 static and
	 * dynamic addresses to exist in various states.  For simplicity, we
	 * will search for the first address that is configured and active.
	 */
	if (ipmi_lan_get_param(ihp, channel, IPMI_LAN_PARAM_IPV6_NUM_ADDRS, 0,
	    0, &numaddrs, sizeof (numaddrs)) != 0) {
		/* errno set */
		return (-1);
	}

	for (i = 0; i < numaddrs.inva_num_saddrs; i++) {
		if (ipmi_lan_get_param(ihp, channel, IPMI_LAN_PARAM_IPV6_SADDR,
		    i, 0, &addrv6, sizeof (addrv6)) == 0 &&
		    addrv6.ipva_status == 0) {
			found_addr = B_TRUE;
			cfgp->ilc_ipv6_source = IPMI_LAN_SRC_STATIC;
			break;
		}
	}
	for (i = 0; found_addr == B_FALSE && i < numaddrs.inva_num_daddrs;
	    i++) {
		if (ipmi_lan_get_param(ihp, channel, IPMI_LAN_PARAM_IPV6_DADDR,
		    i, 0, &addrv6, sizeof (addrv6)) == 0 &&
		    addrv6.ipva_status == 0) {
			found_addr = B_TRUE;
			cfgp->ilc_ipv6_source = IPMI_LAN_SRC_DHCP;
			break;
		}
	}

	/*
	 * If we didn't find any active static or dynamic addresses, then
	 * while IPv6 support is enabled, no IPv6 interfaces have been
	 * configured.  We reset ilc_ipv6_enabled back to false so that
	 * callers know that the other ilc_ipv6_* fields are not valid.
	 */
	if (found_addr != B_TRUE) {
		cfgp->ilc_ipv6_enabled = B_FALSE;
		return (0);
	}

	(void) memcpy(cfgp->ilc_ipv6_addr, addrv6.ipva_addr,
	    sizeof (addrv6.ipva_addr));

	/*
	 * For the case that static addressing was used for the SP IP then we
	 * need to get the IPMI_LAN_PARAM_IPV6_ROUTER_CONFIG parameter to
	 * determine if static or dynamic routes are enabled (or both).
	 *
	 * If DHCP was used to assign the SP IP, then only dynamic route
	 * discovery is supported.
	 */
	if (cfgp->ilc_ipv6_source == IPMI_LAN_SRC_STATIC &&
	    ipmi_lan_get_param(ihp, channel, IPMI_LAN_PARAM_IPV6_ROUTER_CONFIG,
	    0, 0, &route_cfg, sizeof (route_cfg)) != 0) {
		/* errno set */
		return (-1);
	}

	if (cfgp->ilc_ipv6_source == IPMI_LAN_SRC_STATIC) {
		if (route_cfg & IPMI_LAN_IPV6_STATIC_ROUTES_ENABLED)
			stat_routes_enabled = B_TRUE;
		if (route_cfg & IPMI_LAN_IPV6_DYNAMIC_ROUTES_ENABLED)
			dyn_routes_enabled = B_TRUE;
	} else {
		dyn_routes_enabled = B_TRUE;
	}

	/*
	 * The IPMI spec allows for a max of two static IPv6 routes to be
	 * configured.
	 */
	j = cfgp->ilc_ipv6_nroutes = 0;
	if (stat_routes_enabled == B_TRUE) {
		cfgp->ilc_ipv6_nroutes = 2;
		if (ipmi_lan_get_param(ihp, channel,
		    IPMI_LAN_PARAM_IPV6_STATIC_ROUTE1, 0, 0, &sroute1,
		    sizeof (sroute1)) != 0 ||
		    ipmi_lan_get_param(ihp, channel,
		    IPMI_LAN_PARAM_IPV6_STATIC_ROUTE2, 0, 0, &sroute1,
		    sizeof (sroute2)) != 0) {
			/* errno set */
			return (-1);
		}
		if (IN6_IS_ADDR_UNSPECIFIED(&sroute1)) {
			cfgp->ilc_ipv6_nroutes++;
			(void) memcpy(cfgp->ilc_ipv6_routes[j++], &sroute1,
			    sizeof (sroute1));
		}
		if (IN6_IS_ADDR_UNSPECIFIED(&sroute2) != B_TRUE) {
			cfgp->ilc_ipv6_nroutes++;
			(void) memcpy(cfgp->ilc_ipv6_routes[j++], &sroute2,
			    sizeof (sroute2));
		}
	}

	/*
	 * RFC4861 states that if dynamic routing is used, a host should retain
	 * a minimum of two routes, though more is recommended.  Retrieve the
	 * number of dynamic routes and then iterate through them and gather
	 * up to the first two addresses.
	 */
	if (dyn_routes_enabled == B_TRUE &&
	    ipmi_lan_get_param(ihp, channel, IPMI_LAN_PARAM_IPV6_NUM_DYN_ROUTES,
	    0, 0, &ndynroutes, sizeof (ndynroutes)) != 0) {
		/* errno set */
		return (-1);
	}
	for (i = 0; i < ndynroutes && i < 2; i++) {
		if (ipmi_lan_get_param(ihp, channel,
		    IPMI_LAN_PARAM_IPV6_DYN_ROUTE, i, 0, &droute,
		    sizeof (droute)) != 0)
			/* errno set */
			return (-1);

		if (IN6_IS_ADDR_UNSPECIFIED(&droute) != B_TRUE) {
			(void) memcpy(cfgp->ilc_ipv6_routes[j++], &droute,
			    sizeof (droute));
			cfgp->ilc_ipv6_nroutes++;
		}
	}
	return (0);
}

static int
ipmi_lan_set_param(ipmi_handle_t *ihp, int channel, int param, void *data,
    size_t len)
{
	ipmi_cmd_t cmd;
	ipmi_cmd_lan_set_config_t lcmd = { 0 };

	lcmd.ilsc_number = channel;
	lcmd.ilsc_param = param;
	bcopy(data, lcmd.ilsc_data, len);

	cmd.ic_netfn = IPMI_NETFN_TRANSPORT;
	cmd.ic_lun = 0;
	cmd.ic_cmd = IPMI_CMD_SET_LAN_CONFIG;
	cmd.ic_data = &lcmd;
	cmd.ic_dlen = IPMI_LAN_SET_LEN(len);

	if (ipmi_send(ihp, &cmd) == NULL) {
		switch (ihp->ih_completion) {
		case 0x80:
			(void) ipmi_set_error(ihp, EIPMI_BADPARAM, NULL);
			break;

		case 0x81:
			(void) ipmi_set_error(ihp, EIPMI_BUSY, NULL);
			break;

		case 0x82:
			(void) ipmi_set_error(ihp, EIPMI_READONLY, NULL);
			break;

		case 0x83:
			(void) ipmi_set_error(ihp, EIPMI_WRITEONLY, NULL);
			break;
		}
		return (-1);
	}

	return (0);
}

int
ipmi_lan_set_config(ipmi_handle_t *ihp, int channel, ipmi_lan_config_t *cfgp,
    int mask)
{
	uint8_t set;
	int i;
	ipmi_lan_entry_t *lep;

	/*
	 * Cancel any pending transaction, then open a new transaction.
	 */
	set = IPMI_LAN_SET_COMPLETE;
	if (ipmi_lan_set_param(ihp, channel, IPMI_LAN_PARAM_SET_IN_PROGRESS,
	    &set, sizeof (set)) != 0)
		return (-1);
	set = IPMI_LAN_SET_INPROGRESS;
	if (ipmi_lan_set_param(ihp, channel, IPMI_LAN_PARAM_SET_IN_PROGRESS,
	    &set, sizeof (set)) != 0)
		return (-1);

	/*
	 * Iterate over all parameters and set them.
	 */
	for (i = 0; i < IPMI_LAN_IPV4_NENTRIES; i++) {
		lep = &ipmi_lan_ipv4_table[i];
		if (!(lep->ile_mask & mask))
			continue;

		if (ipmi_lan_set_param(ihp, channel, lep->ile_param,
		    (char *)cfgp + lep->ile_offset, lep->ile_len) != 0) {
			/*
			 * On some systems, setting the mode to DHCP may cause
			 * the command to timeout, presumably because it is
			 * waiting for the setting to take effect.  If we see
			 * completion code 0xc3 (command timeout) while setting
			 * the DHCP value, just ignore it.
			 */
			if (mask != IPMI_LAN_SET_IPADDR_SOURCE ||
			    cfgp->ilc_ipaddr_source != IPMI_LAN_SRC_DHCP ||
			    ihp->ih_completion != 0xC3)
				return (-1);
		}
	}

	/*
	 * Commit the transaction.
	 */
	set = IPMI_LAN_SET_COMPLETE;
	if (ipmi_lan_set_param(ihp, channel, IPMI_LAN_PARAM_SET_IN_PROGRESS,
	    &set, sizeof (set)) != 0)
		return (-1);

	return (0);
}
