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
 * Copyright (c) 1991, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 * Copyright (c) 2013 by Delphix. All rights reserved.
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 */
/* Copyright (c) 1990 Mentat Inc. */

#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/ip_if.h>
#include <inet/ip_ire.h>
#include <inet/ipclassifier.h>
#include <inet/ip_impl.h>
#include <inet/tunables.h>
#include <sys/sunddi.h>
#include <sys/policy.h>

/* How long, in seconds, we allow frags to hang around. */
#define	IP_REASM_TIMEOUT	15
#define	IPV6_REASM_TIMEOUT	60

/*
 * Set ip{,6}_forwarding values. If the value is being set on an ill,
 * find the ill and set the value on it. On the other hand if we are modifying
 * global property, modify the global value and set the value on all the ills.
 */
/* ARGSUSED */
static int
ip_set_forwarding(netstack_t *stack, cred_t *cr, mod_prop_info_t *pinfo,
    const char *ifname, const void* pval, uint_t flags)
{
	char			*end;
	unsigned long		new_value;
	boolean_t		per_ill, isv6;
	ill_walk_context_t	ctx;
	ill_t			*ill;
	ip_stack_t		*ipst = stack->netstack_ip;

	if (flags & MOD_PROP_DEFAULT) {
		new_value = pinfo->prop_def_bval;
	} else {
		if (ddi_strtoul(pval, &end, 10, &new_value) != 0 ||
		    *end != '\0')
			return (EINVAL);
		if (new_value != B_TRUE && new_value != B_FALSE)
			return (EINVAL);
	}

	per_ill = (ifname != NULL && ifname[0] != '\0');
	/*
	 * if it's not per ill then set the global property and bring all the
	 * ills up to date with the new global value.
	 */
	if (!per_ill)
		pinfo->prop_cur_bval = (new_value == 1 ? B_TRUE : B_FALSE);

	isv6 = (pinfo->mpi_proto == MOD_PROTO_IPV6 ? B_TRUE : B_FALSE);
	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	if (isv6)
		ill = ILL_START_WALK_V6(&ctx, ipst);
	else
		ill = ILL_START_WALK_V4(&ctx, ipst);

	for (; ill != NULL; ill = ill_next(&ctx, ill)) {
		/*
		 * if the property needs to be set on a particular
		 * interface, look for that interface.
		 */
		if (per_ill && strcmp(ifname, ill->ill_name) != 0)
			continue;
		(void) ill_forward_set(ill, new_value != 0);
	}
	rw_exit(&ipst->ips_ill_g_lock);

	return (0);
}

static int
ip_get_forwarding(netstack_t *stack, mod_prop_info_t *pinfo, const char *ifname,
    void *pval, uint_t pr_size, uint_t flags)
{
	boolean_t		value;
	ill_walk_context_t	ctx;
	ill_t			*ill;
	ip_stack_t		*ipst = stack->netstack_ip;
	boolean_t		get_def = (flags & MOD_PROP_DEFAULT);
	boolean_t		get_perm = (flags & MOD_PROP_PERM);
	boolean_t		isv6;
	size_t			nbytes = 0;

	if (get_perm) {
		nbytes = snprintf(pval, pr_size, "%d", MOD_PROP_PERM_RW);
		goto ret;
	} else if (get_def) {
		nbytes = snprintf(pval, pr_size, "%d", pinfo->prop_def_bval);
		goto ret;
	}

	/*
	 * if per interface value is not asked for return the current
	 * global value
	 */
	if (ifname == NULL || ifname[0] == '\0') {
		nbytes = snprintf(pval, pr_size, "%d", pinfo->prop_cur_bval);
		goto ret;
	}

	isv6 = (pinfo->mpi_proto == MOD_PROTO_IPV6 ? B_TRUE : B_FALSE);
	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	if (isv6)
		ill = ILL_START_WALK_V6(&ctx, ipst);
	else
		ill = ILL_START_WALK_V4(&ctx, ipst);
	for (; ill != NULL; ill = ill_next(&ctx, ill)) {
		/*
		 * if the property needs to be obtained on a particular
		 * interface, look for that interface.
		 */
		if (strcmp(ifname, ill->ill_name) == 0)
			break;
	}
	if (ill == NULL) {
		rw_exit(&ipst->ips_ill_g_lock);
		return (ENXIO);
	}
	value = ((ill->ill_flags & ILLF_ROUTER) ? B_TRUE : B_FALSE);
	rw_exit(&ipst->ips_ill_g_lock);
	nbytes = snprintf(pval, pr_size, "%d", value);
ret:
	if (nbytes >= pr_size)
		return (ENOBUFS);
	return (0);
}

/*
 * `ip_debug' is a global variable. So, we will be modifying the global
 * variable here.
 */
/* ARGSUSED */
int
ip_set_debug(netstack_t *stack, cred_t *cr, mod_prop_info_t *pinfo,
    const char *ifname, const void* pval, uint_t flags)
{
	unsigned long	new_value;
	int		err;

	if (cr != NULL && secpolicy_net_config(cr, B_FALSE) != 0)
		return (EPERM);

	if ((err = mod_uint32_value(pval, pinfo, flags, &new_value)) != 0)
		return (err);
	ip_debug = (uint32_t)new_value;
	return (0);
}

/*
 * ip_debug is a global property. For default, permission and value range
 * we retrieve the value from `pinfo'. However for the current value we
 * retrieve the value from the global variable `ip_debug'
 */
/* ARGSUSED */
int
ip_get_debug(netstack_t *stack, mod_prop_info_t *pinfo, const char *ifname,
    void *pval, uint_t psize, uint_t flags)
{
	boolean_t	get_def = (flags & MOD_PROP_DEFAULT);
	boolean_t	get_perm = (flags & MOD_PROP_PERM);
	boolean_t	get_range = (flags & MOD_PROP_POSSIBLE);
	size_t		nbytes;

	bzero(pval, psize);
	if (get_perm)
		nbytes = snprintf(pval, psize, "%u", MOD_PROP_PERM_RW);
	else if (get_range)
		nbytes = snprintf(pval, psize, "%u-%u",
		    pinfo->prop_min_uval, pinfo->prop_max_uval);
	else if (get_def)
		nbytes = snprintf(pval, psize, "%u", pinfo->prop_def_uval);
	else
		nbytes = snprintf(pval, psize, "%u", ip_debug);
	if (nbytes >= psize)
		return (ENOBUFS);
	return (0);
}

/*
 * Set the CGTP (multirouting) filtering status. If the status is changed
 * from active to transparent or from transparent to active, forward the
 * new status to the filtering module (if loaded).
 */
/* ARGSUSED */
static int
ip_set_cgtp_filter(netstack_t *stack, cred_t *cr, mod_prop_info_t *pinfo,
    const char *ifname, const void* pval, uint_t flags)
{
	unsigned long	new_value;
	ip_stack_t	*ipst = stack->netstack_ip;
	char		*end;

	if (flags & MOD_PROP_DEFAULT) {
		new_value = pinfo->prop_def_bval;
	} else {
		if (ddi_strtoul(pval, &end, 10, &new_value) != 0 ||
		    *end != '\0' || new_value > 1) {
			return (EINVAL);
		}
	}
	if (!pinfo->prop_cur_bval && new_value) {
		cmn_err(CE_NOTE, "IP: enabling CGTP filtering%s",
		    ipst->ips_ip_cgtp_filter_ops == NULL ?
		    " (module not loaded)" : "");
	}
	if (pinfo->prop_cur_bval && !new_value) {
		cmn_err(CE_NOTE, "IP: disabling CGTP filtering%s",
		    ipst->ips_ip_cgtp_filter_ops == NULL ?
		    " (module not loaded)" : "");
	}
	if (ipst->ips_ip_cgtp_filter_ops != NULL) {
		int	res;
		netstackid_t stackid = ipst->ips_netstack->netstack_stackid;

		res = ipst->ips_ip_cgtp_filter_ops->cfo_change_state(stackid,
		    new_value);
		if (res)
			return (res);
	}
	pinfo->prop_cur_bval = (new_value == 1 ? B_TRUE : B_FALSE);
	ill_set_inputfn_all(ipst);
	return (0);
}

/*
 * Retrieve the default MTU or min-max MTU range for a given interface.
 *
 *  -- ill_max_frag value tells us the maximum MTU that can be handled by the
 *     datalink. This value is advertised by the driver via DLPI messages
 *     (DL_NOTE_SDU_SIZE/DL_INFO_ACK).
 *
 *  -- ill_current_frag for the most link-types will be same as ill_max_frag
 *     to begin with. However it is dynamically computed for some link-types
 *     like tunnels, based on the tunnel PMTU.
 *
 *  -- ill_mtu is the user set MTU using SIOCSLIFMTU and must lie between
 *     (IPV6_MIN_MTU/IP_MIN_MTU) and ill_max_frag.
 *
 *  -- ill_user_mtu is set by in.ndpd using SIOCSLIFLNKINFO and must lie between
 *     (IPV6_MIN_MTU/IP_MIN_MTU) and ill_max_frag.
 */
int
ip_get_mtu(netstack_t *stack, mod_prop_info_t *pinfo, const char *ifname,
    void *pval, uint_t psize, uint_t flags)
{
	ill_walk_context_t	ctx;
	ill_t			*ill;
	ip_stack_t		*ipst = stack->netstack_ip;
	boolean_t		isv6;
	uint32_t		max_mtu, def_mtu;
	size_t			nbytes = 0;

	if (!(flags & (MOD_PROP_DEFAULT|MOD_PROP_POSSIBLE)))
		return (ENOTSUP);

	if (ifname == NULL || ifname[0] == '\0')
		return (ENOTSUP);

	isv6 = (pinfo->mpi_proto == MOD_PROTO_IPV6 ? B_TRUE : B_FALSE);
	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	if (isv6)
		ill = ILL_START_WALK_V6(&ctx, ipst);
	else
		ill = ILL_START_WALK_V4(&ctx, ipst);
	for (; ill != NULL; ill = ill_next(&ctx, ill)) {
		if (strcmp(ifname, ill->ill_name) == 0)
			break;
	}
	if (ill == NULL) {
		rw_exit(&ipst->ips_ill_g_lock);
		return (ENXIO);
	}
	max_mtu = ill->ill_max_frag;
	def_mtu = ill->ill_current_frag;
	rw_exit(&ipst->ips_ill_g_lock);

	if (flags & MOD_PROP_DEFAULT) {
		nbytes = snprintf(pval, psize, "%u", def_mtu);
	} else if (flags & MOD_PROP_POSSIBLE) {
		uint32_t	min_mtu;

		min_mtu = isv6 ? IPV6_MIN_MTU : IP_MIN_MTU;
		nbytes = snprintf(pval, psize, "%u-%u", min_mtu, max_mtu);
	} else {
		return (ENOTSUP);
	}

	if (nbytes >= psize)
		return (ENOBUFS);
	return (0);
}

/*
 * See the comments for ip[6]_strict_src_multihoming for an explanation
 * of the semanitcs.
 */
void
ip_set_src_multihoming_common(ulong_t new_value, ulong_t old_value,
    boolean_t isv6, ip_stack_t *ipst)
{
	if (isv6)
		ipst->ips_ipv6_strict_src_multihoming = new_value;
	else
		ipst->ips_ip_strict_src_multihoming = new_value;
	if (new_value != old_value) {
		if (!isv6) {
			if (old_value == 0) {
				ire_walk_v4(ip_ire_rebind_walker, NULL,
				    ALL_ZONES, ipst);
			} else if (new_value == 0) {
				ire_walk_v4(ip_ire_unbind_walker, NULL,
				    ALL_ZONES, ipst);
			}
			ipcl_walk(conn_ire_revalidate, (void *)B_FALSE, ipst);
		} else {
			if (old_value == 0) {
				ire_walk_v6(ip_ire_rebind_walker, NULL,
				    ALL_ZONES, ipst);
			} else if (new_value == 0) {
				ire_walk_v6(ip_ire_unbind_walker, NULL,
				    ALL_ZONES, ipst);
			}
			ipcl_walk(conn_ire_revalidate, (void *)B_TRUE, ipst);
		}
	}
}

/* ARGSUSED */
static int
ip_set_src_multihoming(netstack_t *stack, cred_t *cr, mod_prop_info_t *pinfo,
    const char *ifname, const void* pval, uint_t flags)
{
	unsigned long	new_value, old_value;
	boolean_t	isv6;
	ip_stack_t	*ipst = stack->netstack_ip;
	int		err;

	old_value = pinfo->prop_cur_uval;

	if ((err = mod_uint32_value(pval, pinfo, flags, &new_value)) != 0)
		return (err);
	pinfo->prop_cur_uval = new_value;
	isv6 = (strcmp(pinfo->mpi_name, "ip6_strict_src_multihoming") == 0);
	ip_set_src_multihoming_common(new_value, old_value, isv6, ipst);
	return (0);
}


/* ARGSUSED */
static int
ip_set_hostmodel(netstack_t *stack, cred_t *cr, mod_prop_info_t *pinfo,
    const char *ifname, const void* pval, uint_t flags)
{
	ip_hostmodel_t	new_value, old_value;
	ip_stack_t	*ipst = stack->netstack_ip;
	uint32_t	old_src_multihoming;
	int		err;
	ulong_t		tmp;
	boolean_t	isv6;

	old_value = pinfo->prop_cur_uval;

	if ((err = mod_uint32_value(pval, pinfo, flags, &tmp)) != 0)
		return (err);
	new_value = tmp;
	pinfo->prop_cur_uval = new_value;

	switch (old_value) {
	case IP_WEAK_ES:
		old_src_multihoming = 0;
		break;
	case IP_SRC_PRI_ES:
		old_src_multihoming = 1;
		break;
	case IP_STRONG_ES:
		old_src_multihoming = 2;
		break;
	default:
		ASSERT(0);
		old_src_multihoming = IP_MAXVAL_ES;
		break;
	}
	/*
	 * Changes to src_multihoming may require ire's to be rebound/unbound,
	 * and also require generation number resets. Changes to dst_multihoming
	 * require a simple reset of the value.
	 */
	isv6 = (pinfo->mpi_proto == MOD_PROTO_IPV6);
	if (new_value != old_value) {
		switch (new_value) {
		case IP_WEAK_ES:
			ip_set_src_multihoming_common(0, old_src_multihoming,
			    isv6, ipst);
			if (isv6)
				ipst->ips_ipv6_strict_dst_multihoming = 0;
			else
				ipst->ips_ip_strict_dst_multihoming = 0;
			break;
		case IP_SRC_PRI_ES:
			ip_set_src_multihoming_common(1, old_src_multihoming,
			    isv6, ipst);
			if (isv6)
				ipst->ips_ipv6_strict_dst_multihoming = 0;
			else
				ipst->ips_ip_strict_dst_multihoming = 0;
			break;
		case IP_STRONG_ES:
			ip_set_src_multihoming_common(2, old_src_multihoming,
			    isv6, ipst);
			if (isv6)
				ipst->ips_ipv6_strict_dst_multihoming = 1;
			else
				ipst->ips_ip_strict_dst_multihoming = 1;
			break;
		default:
			return (EINVAL);
		}
	}
	return (0);
}

/* ARGSUSED */
int
ip_get_hostmodel(netstack_t *stack, mod_prop_info_t *pinfo, const char *ifname,
    void *pval, uint_t psize, uint_t flags)
{
	boolean_t	isv6 = (pinfo->mpi_proto == MOD_PROTO_IPV6);
	ip_stack_t	*ipst = stack->netstack_ip;
	ip_hostmodel_t	hostmodel;

	if (psize < sizeof (hostmodel))
		return (ENOBUFS);
	bzero(pval, psize);
	if (!isv6) {
		if (ipst->ips_ip_strict_src_multihoming == 0 &&
		    ipst->ips_ip_strict_dst_multihoming == 0)
			hostmodel = IP_WEAK_ES;
		else if (ipst->ips_ip_strict_src_multihoming == 1 &&
		    ipst->ips_ip_strict_dst_multihoming == 0)
			hostmodel = IP_SRC_PRI_ES;
		else if (ipst->ips_ip_strict_src_multihoming == 2 &&
		    ipst->ips_ip_strict_dst_multihoming == 1)
			hostmodel = IP_STRONG_ES;
		else
			hostmodel = IP_MAXVAL_ES;
	} else {
		if (ipst->ips_ipv6_strict_src_multihoming == 0 &&
		    ipst->ips_ipv6_strict_dst_multihoming == 0)
			hostmodel = IP_WEAK_ES;
		else if (ipst->ips_ipv6_strict_src_multihoming == 1 &&
		    ipst->ips_ipv6_strict_dst_multihoming == 0)
			hostmodel = IP_SRC_PRI_ES;
		else if (ipst->ips_ipv6_strict_src_multihoming == 2 &&
		    ipst->ips_ipv6_strict_dst_multihoming == 1)
			hostmodel = IP_STRONG_ES;
		else
			hostmodel = IP_MAXVAL_ES;
	}
	bcopy(&hostmodel, pval, sizeof (hostmodel));
	return (0);
}

/*
 * All of these are alterable, within the min/max values given, at run time.
 *
 * Note: All those tunables which do not start with "_" are Committed and
 * therefore are public. See PSARC 2010/080.
 */
mod_prop_info_t ip_propinfo_tbl[] = {
	/* tunable - 0 */
	{ "_respond_to_address_mask_broadcast", MOD_PROTO_IP,
	    mod_set_boolean, mod_get_boolean,
	    {B_FALSE}, {B_FALSE} },

	{ "_respond_to_echo_broadcast", MOD_PROTO_IP,
	    mod_set_boolean, mod_get_boolean,
	    {B_TRUE},  {B_TRUE} },

	{ "_respond_to_echo_multicast", MOD_PROTO_IPV4,
	    mod_set_boolean, mod_get_boolean,
	    {B_TRUE}, {B_TRUE} },

	{ "_respond_to_timestamp", MOD_PROTO_IP,
	    mod_set_boolean, mod_get_boolean,
	    {B_FALSE}, {B_FALSE} },

	{ "_respond_to_timestamp_broadcast", MOD_PROTO_IP,
	    mod_set_boolean, mod_get_boolean,
	    {B_FALSE}, {B_FALSE} },

	{ "_send_redirects", MOD_PROTO_IPV4,
	    mod_set_boolean, mod_get_boolean,
	    {B_TRUE}, {B_TRUE} },

	{ "_forward_directed_broadcasts", MOD_PROTO_IP,
	    mod_set_boolean, mod_get_boolean,
	    {B_FALSE}, {B_FALSE} },

	{ "_mrtdebug", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 10, 0}, {0} },

	{ "_ire_reclaim_fraction", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {1, 8, 3}, {3} },

	{ "_nce_reclaim_fraction", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {1, 8, 3}, {3} },

	/* tunable - 10 */
	{ "_dce_reclaim_fraction", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {1, 8, 3}, {3} },

	{ "ttl", MOD_PROTO_IPV4,
	    mod_set_uint32, mod_get_uint32,
	    {1, 255, 255}, {255} },

	{ "_forward_src_routed", MOD_PROTO_IPV4,
	    mod_set_boolean, mod_get_boolean,
	    {B_FALSE}, {B_FALSE} },

	{ "_wroff_extra", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 256, 32}, {32} },

	/* following tunable is in seconds - a deviant! */
	{ "_pathmtu_interval", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {2, 999999999, 60*20}, {60*20} },

	{ "_icmp_return_data_bytes", MOD_PROTO_IPV4,
	    mod_set_uint32, mod_get_uint32,
	    {8, 65536, 64}, {64} },

	{ "_path_mtu_discovery", MOD_PROTO_IP,
	    mod_set_boolean, mod_get_boolean,
	    {B_TRUE}, {B_TRUE} },

	{ "_pmtu_min", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {68, 65535, 576}, {576} },

	{ "_ignore_redirect", MOD_PROTO_IPV4,
	    mod_set_boolean, mod_get_boolean,
	    {B_FALSE}, {B_FALSE} },

	{ "_arp_icmp_error", MOD_PROTO_IP,
	    mod_set_boolean, mod_get_boolean,
	    {B_FALSE}, {B_FALSE} },

	/* tunable - 20 */
	{ "_broadcast_ttl", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {1, 254, 1}, {1} },

	{ "_icmp_err_interval", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 99999, 100}, {100} },

	{ "_icmp_err_burst", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {1, 99999, 10}, {10} },

	{ "_reass_queue_bytes", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 999999999, 1000000}, {1000000} },

	/*
	 * See comments for ip_strict_src_multihoming for an explanation
	 * of the semantics of ip_strict_dst_multihoming
	 */
	{ "_strict_dst_multihoming", MOD_PROTO_IPV4,
	    mod_set_uint32, mod_get_uint32,
	    {0, 1, 0}, {0} },

	{ "_addrs_per_if", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {1, MAX_ADDRS_PER_IF, 256}, {256} },

	{ "_ipsec_override_persocket_policy", MOD_PROTO_IP,
	    mod_set_boolean, mod_get_boolean,
	    {B_FALSE}, {B_FALSE} },

	{ "_icmp_accept_clear_messages", MOD_PROTO_IP,
	    mod_set_boolean, mod_get_boolean,
	    {B_TRUE}, {B_TRUE} },

	{ "_igmp_accept_clear_messages", MOD_PROTO_IP,
	    mod_set_boolean, mod_get_boolean,
	    {B_TRUE}, {B_TRUE} },

	{ "_ndp_delay_first_probe_time", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {2, 999999999, ND_DELAY_FIRST_PROBE_TIME},
	    {ND_DELAY_FIRST_PROBE_TIME} },

	/* tunable - 30 */
	{ "_ndp_max_unicast_solicit", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {1, 999999999, ND_MAX_UNICAST_SOLICIT}, {ND_MAX_UNICAST_SOLICIT} },

	{ "hoplimit", MOD_PROTO_IPV6,
	    mod_set_uint32, mod_get_uint32,
	    {1, 255, IPV6_MAX_HOPS}, {IPV6_MAX_HOPS} },

	{ "_icmp_return_data_bytes", MOD_PROTO_IPV6,
	    mod_set_uint32, mod_get_uint32,
	    {8, IPV6_MIN_MTU, IPV6_MIN_MTU}, {IPV6_MIN_MTU} },

	{ "_forward_src_routed", MOD_PROTO_IPV6,
	    mod_set_boolean, mod_get_boolean,
	    {B_FALSE}, {B_FALSE} },

	{ "_respond_to_echo_multicast", MOD_PROTO_IPV6,
	    mod_set_boolean, mod_get_boolean,
	    {B_TRUE}, {B_TRUE} },

	{ "_send_redirects", MOD_PROTO_IPV6,
	    mod_set_boolean, mod_get_boolean,
	    {B_TRUE}, {B_TRUE} },

	{ "_ignore_redirect", MOD_PROTO_IPV6,
	    mod_set_boolean, mod_get_boolean,
	    {B_FALSE}, {B_FALSE} },

	/*
	 * See comments for ip6_strict_src_multihoming for an explanation
	 * of the semantics of ip6_strict_dst_multihoming
	 */
	{ "_strict_dst_multihoming", MOD_PROTO_IPV6,
	    mod_set_uint32, mod_get_uint32,
	    {0, 1, 0}, {0} },

	{ "_src_check", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 2, 2}, {2} },

	{ "_ipsec_policy_log_interval", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 999999, 0}, {0} },

	/* tunable - 40 */
	{ "_pim_accept_clear_messages", MOD_PROTO_IP,
	    mod_set_boolean, mod_get_boolean,
	    {B_TRUE}, {B_TRUE} },

	{ "_ndp_unsolicit_interval", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {1000, 20000, 2000}, {2000} },

	{ "_ndp_unsolicit_count", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {1, 20, 3}, {3} },

	{ "_ignore_home_address_opt", MOD_PROTO_IPV6,
	    mod_set_boolean, mod_get_boolean,
	    {B_TRUE}, {B_TRUE} },

	{ "_policy_mask", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 15, 0}, {0} },

	{ "_ecmp_behavior", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 2, 2}, {2} },

	{ "_multirt_ttl", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 255, 1}, {1} },

	/* following tunable is in seconds - a deviant */
	{ "_ire_badcnt_lifetime", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 3600, 60}, {60} },

	{ "_max_temp_idle", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 999999, 60*60*24}, {60*60*24} },

	{ "_max_temp_defend", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 1000, 1}, {1} },

	/* tunable - 50 */
	/*
	 * when a conflict of an active address is detected,
	 * defend up to ip_max_defend times, within any
	 * ip_defend_interval span.
	 */
	{ "_max_defend", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 1000, 3}, {3} },

	{ "_defend_interval", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 999999, 30}, {30} },

	{ "_dup_recovery", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 3600000, 300000}, {300000} },

	{ "_restrict_interzone_loopback", MOD_PROTO_IP,
	    mod_set_boolean, mod_get_boolean,
	    {B_TRUE}, {B_TRUE} },

	{ "_lso_outbound", MOD_PROTO_IP,
	    mod_set_boolean, mod_get_boolean,
	    {B_TRUE}, {B_TRUE} },

	{ "_igmp_max_version", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {IGMP_V1_ROUTER, IGMP_V3_ROUTER, IGMP_V3_ROUTER},
	    {IGMP_V3_ROUTER} },

	{ "_mld_max_version", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {MLD_V1_ROUTER, MLD_V2_ROUTER, MLD_V2_ROUTER}, {MLD_V2_ROUTER} },

	{ "forwarding", MOD_PROTO_IPV4,
	    ip_set_forwarding, ip_get_forwarding,
	    {IP_FORWARD_NEVER}, {IP_FORWARD_NEVER} },

	{ "forwarding", MOD_PROTO_IPV6,
	    ip_set_forwarding, ip_get_forwarding,
	    {IP_FORWARD_NEVER}, {IP_FORWARD_NEVER} },

	{ "_reasm_timeout", MOD_PROTO_IPV4,
	    mod_set_uint32, mod_get_uint32,
	    {5, 255, IP_REASM_TIMEOUT},
	    {IP_REASM_TIMEOUT} },

	/* tunable - 60 */
	{ "_reasm_timeout", MOD_PROTO_IPV6,
	    mod_set_uint32, mod_get_uint32,
	    {5, 255, IPV6_REASM_TIMEOUT},
	    {IPV6_REASM_TIMEOUT} },

	{ "_cgtp_filter", MOD_PROTO_IP,
	    ip_set_cgtp_filter, mod_get_boolean,
	    {B_FALSE}, {B_FALSE} },

	/* delay before sending first probe: */
	{ "_arp_probe_delay", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 20000, 1000}, {1000} },

	{ "_arp_fastprobe_delay", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 20000, 100}, {100} },

	/* interval at which DAD probes are sent: */
	{ "_arp_probe_interval", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {10, 20000, 1500}, {1500} },

	{ "_arp_fastprobe_interval", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {10, 20000, 150}, {150} },

	{ "_arp_probe_count", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 20, 3}, {3} },

	{ "_arp_fastprobe_count", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 20, 3}, {3} },

	{ "_dad_announce_interval", MOD_PROTO_IPV4,
	    mod_set_uint32, mod_get_uint32,
	    {0, 3600000, 15000}, {15000} },

	{ "_dad_announce_interval", MOD_PROTO_IPV6,
	    mod_set_uint32, mod_get_uint32,
	    {0, 3600000, 15000}, {15000} },

	/* tunable - 70 */
	/*
	 * Rate limiting parameters for DAD defense used in
	 * ill_defend_rate_limit():
	 * defend_rate : pkts/hour permitted
	 * defend_interval : time that can elapse before we send out a
	 *			DAD defense.
	 * defend_period: denominator for defend_rate (in seconds).
	 */
	{ "_arp_defend_interval", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 3600000, 300000}, {300000} },

	{ "_arp_defend_rate", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 20000, 100}, {100} },

	{ "_ndp_defend_interval", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 3600000, 300000}, {300000} },

	{ "_ndp_defend_rate", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 20000, 100}, {100} },

	{ "_arp_defend_period", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {5, 86400, 3600}, {3600} },

	{ "_ndp_defend_period", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {5, 86400, 3600}, {3600} },

	{ "_icmp_return_pmtu", MOD_PROTO_IPV4,
	    mod_set_boolean, mod_get_boolean,
	    {B_TRUE}, {B_TRUE} },

	{ "_icmp_return_pmtu", MOD_PROTO_IPV6,
	    mod_set_boolean, mod_get_boolean,
	    {B_TRUE}, {B_TRUE} },

	/*
	 * publish count/interval values used to announce local addresses
	 * for IPv4, IPv6.
	 */
	{ "_arp_publish_count", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {1, 20, 5}, {5} },

	{ "_arp_publish_interval", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {1000, 20000, 2000}, {2000} },

	/* tunable - 80 */
	/*
	 * The ip*strict_src_multihoming and ip*strict_dst_multihoming provide
	 * a range of choices for setting strong/weak/preferred end-system
	 * behavior. The semantics for setting these are:
	 *
	 * ip*_strict_dst_multihoming = 0
	 *    weak end system model for managing ip destination addresses.
	 *    A packet with IP dst D1 that's received on interface I1 will be
	 *    accepted as long as D1 is one of the local addresses on
	 *    the machine, even if D1 is not configured on I1.
	 * ip*strict_dst_multihioming = 1
	 *    strong end system model for managing ip destination addresses.
	 *    A packet with IP dst D1 that's received on interface I1 will be
	 *    accepted if, and only if, D1 is configured on I1.
	 *
	 * ip*strict_src_multihoming = 0
	 *    Source agnostic route selection for outgoing packets: the
	 *    outgoing interface for a packet will be computed using
	 *    default algorithms for route selection, where the route
	 *    with the longest matching prefix is chosen for the output
	 *    unless other route selection constraints are explicitly
	 *    specified during routing table lookup.  This may result
	 *    in packet being sent out on interface I2 with source
	 *    address S1, even though S1 is not a configured address on I2.
	 * ip*strict_src_multihoming = 1
	 *    Preferred source aware route selection for outgoing packets: for
	 *    a packet with source S2, destination D2, the route selection
	 *    algorithm will first attempt to find a route for the destination
	 *    that goes out through an interface where S2 is
	 *    configured. If such a route cannot be found, then the
	 *    best-matching route for D2 will be selected.
	 * ip*strict_src_multihoming = 2
	 *    Source aware route selection for outgoing packets: a packet will
	 *    be sent out on an interface I2 only if the src address S2 of the
	 *    packet is a configured address on I2. In conjunction with
	 *    the setting 'ip_strict_dst_multihoming == 1', this will result in
	 *    the implementation of Strong ES as defined in Section 3.3.4.2 of
	 *    RFC 1122
	 */
	{ "_strict_src_multihoming", MOD_PROTO_IPV4,
	    ip_set_src_multihoming, mod_get_uint32,
	    {0, 2, 0}, {0} },

	{ "_strict_src_multihoming", MOD_PROTO_IPV6,
	    ip_set_src_multihoming, mod_get_uint32,
	    {0, 2, 0}, {0} },

#ifdef DEBUG
	{ "_drop_inbound_icmpv6", MOD_PROTO_IPV6,
	    mod_set_boolean, mod_get_boolean,
	    {B_FALSE}, {B_FALSE} },
#else
	{ "", 0, NULL, NULL, {0}, {0} },
#endif

	{ "_dce_reclaim_threshold", MOD_PROTO_IP,
	    mod_set_uint32, mod_get_uint32,
	    {1, 100000, 32}, {32} },

	{ "mtu", MOD_PROTO_IPV4, NULL, ip_get_mtu, {0}, {0} },

	{ "mtu", MOD_PROTO_IPV6, NULL, ip_get_mtu, {0}, {0} },

	/*
	 * The following entry is a placeholder for `ip_debug' global
	 * variable. Within these callback functions, we will be
	 * setting/getting the global variable
	 */
	{ "_debug", MOD_PROTO_IP,
	    ip_set_debug, ip_get_debug,
	    {0, 20, 0}, {0} },

	{ "hostmodel", MOD_PROTO_IPV4, ip_set_hostmodel, ip_get_hostmodel,
	    {IP_WEAK_ES, IP_STRONG_ES, IP_WEAK_ES}, {IP_WEAK_ES} },

	{ "hostmodel", MOD_PROTO_IPV6, ip_set_hostmodel, ip_get_hostmodel,
	    {IP_WEAK_ES, IP_STRONG_ES, IP_WEAK_ES}, {IP_WEAK_ES} },

	{ "?", MOD_PROTO_IP, NULL, mod_get_allprop, {0}, {0} },

	{ NULL, 0, NULL, NULL, {0}, {0} }
};

int ip_propinfo_count = A_CNT(ip_propinfo_tbl);
