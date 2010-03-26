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

#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/udp_impl.h>
#include <sys/sunddi.h>

/*
 * All of these are alterable, within the min/max values given, at run time.
 *
 * Note: All those tunables which do not start with "udp_" are Committed and
 * therefore are public. See PSARC 2009/306.
 */
mod_prop_info_t udp_propinfo_tbl[] = {
	/* tunable - 0 */
	{ "udp_wroff_extra", MOD_PROTO_UDP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 256, 32}, {32} },

	{ "udp_ipv4_ttl", MOD_PROTO_UDP,
	    mod_set_uint32, mod_get_uint32,
	    {1, 255, 255}, {255} },

	{ "udp_ipv6_hoplimit", MOD_PROTO_UDP,
	    mod_set_uint32, mod_get_uint32,
	    {0, IPV6_MAX_HOPS, IPV6_DEFAULT_HOPS}, {IPV6_DEFAULT_HOPS} },

	{ "smallest_nonpriv_port", MOD_PROTO_UDP,
	    mod_set_uint32, mod_get_uint32,
	    {1024, (32 * 1024), 1024}, {1024} },

	{ "udp_do_checksum", MOD_PROTO_UDP,
	    mod_set_boolean, mod_get_boolean,
	    {B_TRUE}, {B_TRUE} },

	{ "smallest_anon_port", MOD_PROTO_UDP,
	    mod_set_uint32, mod_get_uint32,
	    {1024, ULP_MAX_PORT, (32 * 1024)}, {(32 * 1024)} },

	{ "largest_anon_port", MOD_PROTO_UDP,
	    mod_set_uint32, mod_get_uint32,
	    {1024, ULP_MAX_PORT, ULP_MAX_PORT}, {ULP_MAX_PORT} },

	{ "send_maxbuf", MOD_PROTO_UDP,
	    mod_set_uint32, mod_get_uint32,
	    {UDP_XMIT_LOWATER, (1<<30), UDP_XMIT_HIWATER},
	    {UDP_XMIT_HIWATER} },

	{ "udp_xmit_lowat", MOD_PROTO_UDP,
	    mod_set_uint32, mod_get_uint32,
	    {0, (1<<30), UDP_XMIT_LOWATER},
	    {UDP_XMIT_LOWATER} },

	{ "recv_maxbuf", MOD_PROTO_UDP,
	    mod_set_uint32, mod_get_uint32,
	    {UDP_RECV_LOWATER, (1<<30), UDP_RECV_HIWATER},
	    {UDP_RECV_HIWATER} },

	/* tunable - 10 */
	{ "udp_max_buf", MOD_PROTO_UDP,
	    mod_set_uint32, mod_get_uint32,
	    {65536, (1<<30), 2*1024*1024}, {2*1024*1024} },

	{ "udp_pmtu_discovery", MOD_PROTO_UDP,
	    mod_set_boolean, mod_get_boolean,
	    {B_FALSE}, {B_FALSE} },

	{ "udp_sendto_ignerr", MOD_PROTO_UDP,
	    mod_set_boolean, mod_get_boolean,
	    {B_FALSE}, {B_FALSE} },

	{ "extra_priv_ports", MOD_PROTO_UDP,
	    mod_set_extra_privports, mod_get_extra_privports,
	    {1, ULP_MAX_PORT, 0}, {0} },

	{ "?", MOD_PROTO_UDP, NULL, mod_get_allprop, {0}, {0} },

	{ NULL, 0, NULL, NULL, {0}, {0} }
};

int udp_propinfo_count = A_CNT(udp_propinfo_tbl);
