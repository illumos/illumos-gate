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
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */
/* Copyright (c) 1990 Mentat Inc. */

#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/udp_impl.h>
#include <sys/sunddi.h>

static int
udp_set_buf_prop(netstack_t *stack, cred_t *cr, mod_prop_info_t *pinfo,
    const char *ifname, const void *pval, uint_t flags)
{
	return (mod_set_buf_prop(stack->netstack_udp->us_propinfo_tbl, stack,
	    cr, pinfo, ifname, pval, flags));
}

static int
udp_get_buf_prop(netstack_t *stack, mod_prop_info_t *pinfo, const char *ifname,
    void *val, uint_t psize, uint_t flags)
{
	return (mod_get_buf_prop(stack->netstack_udp->us_propinfo_tbl, stack,
	    pinfo, ifname, val, psize, flags));
}

/*
 * Special checkers for smallest/largest anonymous port so they don't
 * ever happen to be (largest < smallest).
 */
/* ARGSUSED */
static int
udp_smallest_anon_set(netstack_t *stack, cred_t *cr, mod_prop_info_t *pinfo,
    const char *ifname, const void *pval, uint_t flags)
{
	unsigned long new_value;
	udp_stack_t *us = stack->netstack_udp;
	int err;

	if ((err = mod_uint32_value(pval, pinfo, flags, &new_value)) != 0)
		return (err);
	/* mod_uint32_value() + pinfo guarantees we're in UDP port range. */
	if (new_value > us->us_largest_anon_port)
		return (ERANGE);
	pinfo->prop_cur_uval = (uint32_t)new_value;
	return (0);
}

/* ARGSUSED */
static int
udp_largest_anon_set(netstack_t *stack, cred_t *cr, mod_prop_info_t *pinfo,
    const char *ifname, const void *pval, uint_t flags)
{
	unsigned long new_value;
	udp_stack_t *us = stack->netstack_udp;
	int err;

	if ((err = mod_uint32_value(pval, pinfo, flags, &new_value)) != 0)
		return (err);
	/* mod_uint32_value() + pinfo guarantees we're in UDP port range. */
	if (new_value < us->us_smallest_anon_port)
		return (ERANGE);
	pinfo->prop_cur_uval = (uint32_t)new_value;
	return (0);
}

/*
 * All of these are alterable, within the min/max values given, at run time.
 *
 * Note: All those tunables which do not start with "_" are Committed and
 * therefore are public. See PSARC 2010/080.
 */
mod_prop_info_t udp_propinfo_tbl[] = {
	/* tunable - 0 */
	{ "_wroff_extra", MOD_PROTO_UDP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 256, 32}, {32} },

	{ "_ipv4_ttl", MOD_PROTO_UDP,
	    mod_set_uint32, mod_get_uint32,
	    {1, 255, 255}, {255} },

	{ "_ipv6_hoplimit", MOD_PROTO_UDP,
	    mod_set_uint32, mod_get_uint32,
	    {0, IPV6_MAX_HOPS, IPV6_DEFAULT_HOPS}, {IPV6_DEFAULT_HOPS} },

	{ "smallest_nonpriv_port", MOD_PROTO_UDP,
	    mod_set_uint32, mod_get_uint32,
	    {1024, (32 * 1024), 1024}, {1024} },

	{ "_do_checksum", MOD_PROTO_UDP,
	    mod_set_boolean, mod_get_boolean,
	    {B_TRUE}, {B_TRUE} },

	{ "smallest_anon_port", MOD_PROTO_UDP,
	    udp_smallest_anon_set, mod_get_uint32,
	    {1024, ULP_MAX_PORT, (32 * 1024)}, {(32 * 1024)} },

	{ "largest_anon_port", MOD_PROTO_UDP,
	    udp_largest_anon_set, mod_get_uint32,
	    {1024, ULP_MAX_PORT, ULP_MAX_PORT}, {ULP_MAX_PORT} },

	{ "send_buf", MOD_PROTO_UDP,
	    udp_set_buf_prop, udp_get_buf_prop,
	    {UDP_XMIT_LOWATER, ULP_MAX_BUF, UDP_XMIT_HIWATER},
	    {UDP_XMIT_HIWATER} },

	{ "_xmit_lowat", MOD_PROTO_UDP,
	    mod_set_uint32, mod_get_uint32,
	    {0, ULP_MAX_BUF, UDP_XMIT_LOWATER},
	    {UDP_XMIT_LOWATER} },

	{ "recv_buf", MOD_PROTO_UDP,
	    udp_set_buf_prop, udp_get_buf_prop,
	    {UDP_RECV_LOWATER, ULP_MAX_BUF, UDP_RECV_HIWATER},
	    {UDP_RECV_HIWATER} },

	/* tunable - 10 */
	{ "max_buf", MOD_PROTO_UDP,
	    mod_set_uint32, mod_get_uint32,
	    {65536, ULP_MAX_BUF, 2*1024*1024}, {2*1024*1024} },

	{ "_pmtu_discovery", MOD_PROTO_UDP,
	    mod_set_boolean, mod_get_boolean,
	    {B_FALSE}, {B_FALSE} },

	{ "_sendto_ignerr", MOD_PROTO_UDP,
	    mod_set_boolean, mod_get_boolean,
	    {B_FALSE}, {B_FALSE} },

	{ "extra_priv_ports", MOD_PROTO_UDP,
	    mod_set_extra_privports, mod_get_extra_privports,
	    {1, ULP_MAX_PORT, 0}, {0} },

	{ "?", MOD_PROTO_UDP, NULL, mod_get_allprop, {0}, {0} },

	{ NULL, 0, NULL, NULL, {0}, {0} }
};

int udp_propinfo_count = A_CNT(udp_propinfo_tbl);
