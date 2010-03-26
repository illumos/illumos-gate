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
#include <inet/sctp/sctp_stack.h>
#include <inet/sctp/sctp_impl.h>
#include <sys/sunddi.h>

/* Max size IP datagram is 64k - 1 */
#define	SCTP_MSS_MAX_IPV4 (IP_MAXPACKET - (sizeof (ipha_t) + \
					sizeof (sctp_hdr_t)))
#define	SCTP_MSS_MAX_IPV6 (IP_MAXPACKET - (sizeof (ip6_t) + \
					sizeof (sctp_hdr_t)))
/* Max of the above */
#define	SCTP_MSS_MAX	SCTP_MSS_MAX_IPV4

/*
 * All of these are alterable, within the min/max values given, at run time.
 *
 * Note: All those tunables which do not start with "sctp_" are Committed and
 * therefore are public. See PSARC 2009/306.
 */
mod_prop_info_t sctp_propinfo_tbl[] = {
	{ "sctp_max_init_retr", MOD_PROTO_SCTP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 128, 8}, {8} },

	{ "sctp_pa_max_retr", MOD_PROTO_SCTP,
	    mod_set_uint32, mod_get_uint32,
	    {1, 128, 10}, {10} },

	{ "sctp_pp_max_retr", MOD_PROTO_SCTP,
	    mod_set_uint32, mod_get_uint32,
	    {1, 128, 5}, {5} },

	{ "sctp_cwnd_max", MOD_PROTO_SCTP,
	    mod_set_uint32, mod_get_uint32,
	    {128, (1<<30), 1024*1024}, {1024*1024} },

	{ "smallest_nonpriv_port", MOD_PROTO_SCTP,
	    mod_set_uint32, mod_get_uint32,
	    {1024, (32*1024), 1024}, {1024} },

	{ "sctp_ipv4_ttl", MOD_PROTO_SCTP,
	    mod_set_uint32, mod_get_uint32,
	    {1, 255, 64}, {64} },

	{ "sctp_heartbeat_interval", MOD_PROTO_SCTP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 1*DAYS, 30*SECONDS}, {30*SECONDS} },

	{ "sctp_initial_mtu", MOD_PROTO_SCTP,
	    mod_set_uint32, mod_get_uint32,
	    {68, 65535, 1500}, {1500} },

	{ "sctp_mtu_probe_interval", MOD_PROTO_SCTP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 1*DAYS, 10*MINUTES}, {10*MINUTES} },

	{ "sctp_new_secret_interval", MOD_PROTO_SCTP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 1*DAYS, 2*MINUTES}, {2*MINUTES} },

	/* tunable - 10 */
	{ "sctp_deferred_ack_interval", MOD_PROTO_SCTP,
	    mod_set_uint32, mod_get_uint32,
	    {10*MS, 1*MINUTES, 100*MS}, {100*MS} },

	{ "sctp_snd_lowat_fraction", MOD_PROTO_SCTP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 16, 0}, {0} },

	{ "sctp_ignore_path_mtu", MOD_PROTO_SCTP,
	    mod_set_boolean, mod_get_boolean,
	    {B_FALSE}, {B_FALSE} },

	{ "sctp_initial_ssthresh", MOD_PROTO_SCTP,
	    mod_set_uint32, mod_get_uint32,
	    {1024, UINT32_MAX, SCTP_RECV_HIWATER}, { SCTP_RECV_HIWATER} },

	{ "smallest_anon_port", MOD_PROTO_SCTP,
	    mod_set_uint32, mod_get_uint32,
	    {1024, ULP_MAX_PORT, 32*1024}, {32*1024} },

	{ "largest_anon_port", MOD_PROTO_SCTP,
	    mod_set_uint32, mod_get_uint32,
	    {1024, ULP_MAX_PORT, ULP_MAX_PORT}, {ULP_MAX_PORT} },

	{ "send_maxbuf", MOD_PROTO_SCTP,
	    mod_set_uint32, mod_get_uint32,
	    {SCTP_XMIT_LOWATER,  (1<<30),  SCTP_XMIT_HIWATER},
	    {SCTP_XMIT_HIWATER} },

	{ "sctp_xmit_lowat", MOD_PROTO_SCTP,
	    mod_set_uint32, mod_get_uint32,
	    {SCTP_XMIT_LOWATER,  (1<<30),  SCTP_XMIT_LOWATER},
	    {SCTP_XMIT_LOWATER} },

	{ "recv_maxbuf", MOD_PROTO_SCTP,
	    mod_set_uint32, mod_get_uint32,
	    {SCTP_RECV_LOWATER,  (1<<30),  SCTP_RECV_HIWATER},
	    {SCTP_RECV_HIWATER} },

	{ "sctp_max_buf", MOD_PROTO_SCTP,
	    mod_set_uint32, mod_get_uint32,
	    {8192, (1<<30), 1024*1024}, {1024*1024} },

	/* tunable - 20 */
	{ "sctp_rtt_updates", MOD_PROTO_SCTP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 65536, 20}, {20} },

	{ "sctp_ipv6_hoplimit", MOD_PROTO_SCTP,
	    mod_set_uint32, mod_get_uint32,
	    {0, IPV6_MAX_HOPS, IPV6_DEFAULT_HOPS}, {IPV6_DEFAULT_HOPS} },

	{ "sctp_rto_min", MOD_PROTO_SCTP,
	    mod_set_uint32, mod_get_uint32,
	    {500*MS, 60*SECONDS, 1*SECONDS}, {1*SECONDS} },

	{ "sctp_rto_max", MOD_PROTO_SCTP,
	    mod_set_uint32, mod_get_uint32,
	    {1*SECONDS, 60000*SECONDS, 60*SECONDS}, {60*SECONDS} },

	{ "sctp_rto_initial", MOD_PROTO_SCTP,
	    mod_set_uint32, mod_get_uint32,
	    {1*SECONDS, 60000*SECONDS, 3*SECONDS}, {3*SECONDS} },

	{ "sctp_cookie_life", MOD_PROTO_SCTP,
	    mod_set_uint32, mod_get_uint32,
	    {10*MS, 60000*SECONDS, 60*SECONDS}, {60*SECONDS} },

	{ "sctp_max_in_streams", MOD_PROTO_SCTP,
	    mod_set_uint32, mod_get_uint32,
	    {1, UINT16_MAX, 32}, {32} },

	{ "sctp_initial_out_streams", MOD_PROTO_SCTP,
	    mod_set_uint32, mod_get_uint32,
	    {1, UINT16_MAX, 32}, {32} },

	{ "sctp_shutack_wait_bound", MOD_PROTO_SCTP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 300*SECONDS, 60*SECONDS}, {60*SECONDS} },

	{ "sctp_maxburst", MOD_PROTO_SCTP,
	    mod_set_uint32, mod_get_uint32,
	    {2, 8, 4}, {4} },

	/* tunable - 30 */
	{ "sctp_addip_enabled", MOD_PROTO_SCTP,
	    mod_set_boolean, mod_get_boolean,
	    {B_FALSE}, {B_FALSE} },

	{ "sctp_recv_hiwat_minmss", MOD_PROTO_SCTP,
	    mod_set_uint32, mod_get_uint32,
	    {1, 65536, 4}, {4} },

	{ "sctp_slow_start_initial", MOD_PROTO_SCTP,
	    mod_set_uint32, mod_get_uint32,
	    {1, 16, 4}, {4} },

	{ "sctp_slow_start_after_idle", MOD_PROTO_SCTP,
	    mod_set_uint32, mod_get_uint32,
	    {1, 16384, 4}, {4} },

	{ "sctp_prsctp_enabled", MOD_PROTO_SCTP,
	    mod_set_boolean, mod_get_boolean,
	    {B_TRUE}, {B_TRUE} },

	{ "sctp_fast_rxt_thresh", MOD_PROTO_SCTP,
	    mod_set_uint32, mod_get_uint32,
	    {1, 10000, 3}, {3} },

	{ "sctp_deferred_acks_max", MOD_PROTO_SCTP,
	    mod_set_uint32, mod_get_uint32,
	    { 1, 16, 2}, {2} },

	/*
	 * sctp_wroff_xtra is the extra space in front of SCTP/IP header
	 * for link layer header.  It has to be a multiple of 8.
	 */
	{ "sctp_wroff_xtra", MOD_PROTO_SCTP,
	    mod_set_aligned, mod_get_uint32,
	    {0, 256, 32}, {32} },

	{ "extra_priv_ports", MOD_PROTO_SCTP,
	    mod_set_extra_privports, mod_get_extra_privports,
	    {1, ULP_MAX_PORT, 0}, {0} },

	{ "?", MOD_PROTO_SCTP, NULL, mod_get_allprop, {0}, {0} },

	{ NULL, 0, NULL, NULL, {0}, {0} }
};

int sctp_propinfo_count = A_CNT(sctp_propinfo_tbl);
