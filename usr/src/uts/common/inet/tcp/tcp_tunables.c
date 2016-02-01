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
 * Copyright 2016 Joyent, Inc.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */
/* Copyright (c) 1990 Mentat Inc. */

#include <inet/ip.h>
#include <inet/tcp_impl.h>
#include <sys/multidata.h>
#include <sys/sunddi.h>

/* Max size IP datagram is 64k - 1 */
#define	TCP_MSS_MAX_IPV4 (IP_MAXPACKET - (sizeof (ipha_t) + sizeof (tcpha_t)))
#define	TCP_MSS_MAX_IPV6 (IP_MAXPACKET - (sizeof (ip6_t) + sizeof (tcpha_t)))

/* Max of the above */
#define	TCP_MSS_MAX		TCP_MSS_MAX_IPV4

/*
 * Set the RFC 1948 pass phrase
 */
/* ARGSUSED */
static int
tcp_set_1948phrase(netstack_t *stack,  cred_t *cr, mod_prop_info_t *pinfo,
    const char *ifname, const void* pr_val, uint_t flags)
{
	if (flags & MOD_PROP_DEFAULT)
		return (ENOTSUP);

	/*
	 * Basically, value contains a new pass phrase.  Pass it along!
	 */
	tcp_iss_key_init((uint8_t *)pr_val, strlen(pr_val),
	    stack->netstack_tcp);
	return (0);
}

/*
 * returns the current list of listener limit configuration.
 */
/* ARGSUSED */
static int
tcp_listener_conf_get(netstack_t *stack, mod_prop_info_t *pinfo,
    const char *ifname, void *val, uint_t psize, uint_t flags)
{
	tcp_stack_t	*tcps = stack->netstack_tcp;
	tcp_listener_t	*tl;
	char		*pval = val;
	size_t		nbytes = 0, tbytes = 0;
	uint_t		size;
	int		err = 0;

	bzero(pval, psize);
	size = psize;

	if (flags & (MOD_PROP_DEFAULT|MOD_PROP_PERM|MOD_PROP_POSSIBLE))
		return (0);

	mutex_enter(&tcps->tcps_listener_conf_lock);
	for (tl = list_head(&tcps->tcps_listener_conf); tl != NULL;
	    tl = list_next(&tcps->tcps_listener_conf, tl)) {
		if (psize == size)
			nbytes = snprintf(pval, size, "%d:%d",  tl->tl_port,
			    tl->tl_ratio);
		else
			nbytes = snprintf(pval, size, ",%d:%d",  tl->tl_port,
			    tl->tl_ratio);
		size -= nbytes;
		pval += nbytes;
		tbytes += nbytes;
		if (tbytes >= psize) {
			/* Buffer overflow, stop copying information */
			err = ENOBUFS;
			break;
		}
	}

	mutex_exit(&tcps->tcps_listener_conf_lock);
	return (err);
}

/*
 * add a new listener limit configuration.
 */
/* ARGSUSED */
static int
tcp_listener_conf_add(netstack_t *stack, cred_t *cr, mod_prop_info_t *pinfo,
    const char *ifname, const void* pval, uint_t flags)
{
	tcp_listener_t	*new_tl;
	tcp_listener_t	*tl;
	long		lport;
	long		ratio;
	char		*colon;
	tcp_stack_t	*tcps = stack->netstack_tcp;

	if (flags & MOD_PROP_DEFAULT)
		return (ENOTSUP);

	if (ddi_strtol(pval, &colon, 10, &lport) != 0 || lport <= 0 ||
	    lport > USHRT_MAX || *colon != ':') {
		return (EINVAL);
	}
	if (ddi_strtol(colon + 1, NULL, 10, &ratio) != 0 || ratio <= 0)
		return (EINVAL);

	mutex_enter(&tcps->tcps_listener_conf_lock);
	for (tl = list_head(&tcps->tcps_listener_conf); tl != NULL;
	    tl = list_next(&tcps->tcps_listener_conf, tl)) {
		/* There is an existing entry, so update its ratio value. */
		if (tl->tl_port == lport) {
			tl->tl_ratio = ratio;
			mutex_exit(&tcps->tcps_listener_conf_lock);
			return (0);
		}
	}

	if ((new_tl = kmem_alloc(sizeof (tcp_listener_t), KM_NOSLEEP)) ==
	    NULL) {
		mutex_exit(&tcps->tcps_listener_conf_lock);
		return (ENOMEM);
	}

	new_tl->tl_port = lport;
	new_tl->tl_ratio = ratio;
	list_insert_tail(&tcps->tcps_listener_conf, new_tl);
	mutex_exit(&tcps->tcps_listener_conf_lock);
	return (0);
}

/*
 * remove a listener limit configuration.
 */
/* ARGSUSED */
static int
tcp_listener_conf_del(netstack_t *stack, cred_t *cr, mod_prop_info_t *pinfo,
    const char *ifname, const void* pval, uint_t flags)
{
	tcp_listener_t	*tl;
	long		lport;
	tcp_stack_t	*tcps = stack->netstack_tcp;

	if (flags & MOD_PROP_DEFAULT)
		return (ENOTSUP);

	if (ddi_strtol(pval, NULL, 10, &lport) != 0 || lport <= 0 ||
	    lport > USHRT_MAX) {
		return (EINVAL);
	}
	mutex_enter(&tcps->tcps_listener_conf_lock);
	for (tl = list_head(&tcps->tcps_listener_conf); tl != NULL;
	    tl = list_next(&tcps->tcps_listener_conf, tl)) {
		if (tl->tl_port == lport) {
			list_remove(&tcps->tcps_listener_conf, tl);
			mutex_exit(&tcps->tcps_listener_conf_lock);
			kmem_free(tl, sizeof (tcp_listener_t));
			return (0);
		}
	}
	mutex_exit(&tcps->tcps_listener_conf_lock);
	return (ESRCH);
}

static int
tcp_set_buf_prop(netstack_t *stack, cred_t *cr, mod_prop_info_t *pinfo,
    const char *ifname, const void *pval, uint_t flags)
{
	return (mod_set_buf_prop(stack->netstack_tcp->tcps_propinfo_tbl, stack,
	    cr, pinfo, ifname, pval, flags));
}

static int
tcp_get_buf_prop(netstack_t *stack, mod_prop_info_t *pinfo, const char *ifname,
    void *val, uint_t psize, uint_t flags)
{
	return (mod_get_buf_prop(stack->netstack_tcp->tcps_propinfo_tbl, stack,
	    pinfo, ifname, val, psize, flags));
}

/*
 * Special checkers for smallest/largest anonymous port so they don't
 * ever happen to be (largest < smallest).
 */
/* ARGSUSED */
static int
tcp_smallest_anon_set(netstack_t *stack, cred_t *cr, mod_prop_info_t *pinfo,
    const char *ifname, const void *pval, uint_t flags)
{
	unsigned long new_value;
	tcp_stack_t *tcps = stack->netstack_tcp;
	int err;

	if ((err = mod_uint32_value(pval, pinfo, flags, &new_value)) != 0)
		return (err);
	/* mod_uint32_value() + pinfo guarantees we're in TCP port range. */
	if ((uint32_t)new_value > tcps->tcps_largest_anon_port)
		return (ERANGE);
	pinfo->prop_cur_uval = (uint32_t)new_value;
	return (0);
}

/* ARGSUSED */
static int
tcp_largest_anon_set(netstack_t *stack, cred_t *cr, mod_prop_info_t *pinfo,
    const char *ifname, const void *pval, uint_t flags)
{
	unsigned long new_value;
	tcp_stack_t *tcps = stack->netstack_tcp;
	int err;

	if ((err = mod_uint32_value(pval, pinfo, flags, &new_value)) != 0)
		return (err);
	/* mod_uint32_value() + pinfo guarantees we're in TCP port range. */
	if ((uint32_t)new_value < tcps->tcps_smallest_anon_port)
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
mod_prop_info_t tcp_propinfo_tbl[] = {
	/* tunable - 0 */
	{ "_time_wait_interval", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1*SECONDS, TCP_TIME_WAIT_MAX, 1*MINUTES}, {1*MINUTES} },

	{ "_conn_req_max_q", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1, UINT32_MAX, 128}, {128} },

	{ "_conn_req_max_q0", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {0, UINT32_MAX, 1024}, {1024} },

	{ "_conn_req_min", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1, 1024, 1}, {1} },

	{ "_conn_grace_period", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {0*MS, 20*SECONDS, 0*MS}, {0*MS} },

	{ "_cwnd_max", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {128, ULP_MAX_BUF, 1024*1024}, {1024*1024} },

	{ "_debug", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 10, 0}, {0} },

	{ "smallest_nonpriv_port", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1024, (32*1024), 1024}, {1024} },

	{ "_ip_abort_cinterval", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1*SECONDS, UINT32_MAX, 3*MINUTES}, {3*MINUTES} },

	{ "_ip_abort_linterval", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1*SECONDS, UINT32_MAX, 3*MINUTES}, {3*MINUTES} },

	/* tunable - 10 */
	{ "_ip_abort_interval", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {500*MS, UINT32_MAX, 5*MINUTES}, {5*MINUTES} },

	{ "_ip_notify_cinterval", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1*SECONDS, UINT32_MAX, 10*SECONDS},
	    {10*SECONDS} },

	{ "_ip_notify_interval", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {500*MS, UINT32_MAX, 10*SECONDS}, {10*SECONDS} },

	{ "_ipv4_ttl", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1, 255, 64}, {64} },

	{ "_keepalive_interval", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1*SECONDS, 10*DAYS, 2*HOURS}, {2*HOURS} },

	{ "_maxpsz_multiplier", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 100, 10}, {10} },

	{ "_mss_def_ipv4", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1, TCP_MSS_MAX_IPV4, 536}, {536} },

	{ "_mss_max_ipv4", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1, TCP_MSS_MAX_IPV4, TCP_MSS_MAX_IPV4},
	    {TCP_MSS_MAX_IPV4} },

	{ "_mss_min", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1, TCP_MSS_MAX, 108}, {108} },

	{ "_naglim_def", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1, (64*1024)-1, (4*1024)-1}, {(4*1024)-1} },

	/* tunable - 20 */
	{ "_rexmit_interval_initial", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1*MS, 20*SECONDS, 1*SECONDS}, {1*SECONDS} },

	{ "_rexmit_interval_max", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1*MS, 2*HOURS, 60*SECONDS}, {60*SECONDS} },

	{ "_rexmit_interval_min", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1*MS, 2*HOURS, 400*MS}, {400*MS} },

	{ "_deferred_ack_interval", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1*MS, 1*MINUTES, 100*MS}, {100*MS} },

	{ "_snd_lowat_fraction", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 16, 10}, {10} },

	{ "_dupack_fast_retransmit", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1, 10000, 3}, {3} },

	{ "_ignore_path_mtu", MOD_PROTO_TCP,
	    mod_set_boolean, mod_get_boolean,
	    {B_FALSE}, {B_FALSE} },

	{ "smallest_anon_port", MOD_PROTO_TCP,
	    tcp_smallest_anon_set, mod_get_uint32,
	    {1024, ULP_MAX_PORT, 32*1024}, {32*1024} },

	{ "largest_anon_port", MOD_PROTO_TCP,
	    tcp_largest_anon_set, mod_get_uint32,
	    {1024, ULP_MAX_PORT, ULP_MAX_PORT},
	    {ULP_MAX_PORT} },

	{ "send_buf", MOD_PROTO_TCP,
	    tcp_set_buf_prop, tcp_get_buf_prop,
	    {TCP_XMIT_LOWATER, ULP_MAX_BUF, TCP_XMIT_HIWATER},
	    {TCP_XMIT_HIWATER} },

	/* tunable - 30 */
	{ "_xmit_lowat", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {TCP_XMIT_LOWATER, ULP_MAX_BUF, TCP_XMIT_LOWATER},
	    {TCP_XMIT_LOWATER} },

	{ "recv_buf", MOD_PROTO_TCP,
	    tcp_set_buf_prop, tcp_get_buf_prop,
	    {TCP_RECV_LOWATER, ULP_MAX_BUF, TCP_RECV_HIWATER},
	    {TCP_RECV_HIWATER} },

	{ "_recv_hiwat_minmss", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1, 65536, 4}, {4} },

	{ "_fin_wait_2_flush_interval", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1*SECONDS, 2*HOURS, 60*SECONDS},
	    {60*SECONDS} },

	{ "max_buf", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {8192, ULP_MAX_BUF, 1024*1024}, {1024*1024} },

	{ "_strong_iss", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 2, 2}, {2} },

	{ "_rtt_updates", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 65536, 20}, {20} },

	{ "_wscale_always", MOD_PROTO_TCP,
	    mod_set_boolean, mod_get_boolean,
	    {B_TRUE}, {B_TRUE} },

	{ "_tstamp_always", MOD_PROTO_TCP,
	    mod_set_boolean, mod_get_boolean,
	    {B_FALSE}, {B_FALSE} },

	{ "_tstamp_if_wscale", MOD_PROTO_TCP,
	    mod_set_boolean, mod_get_boolean,
	    {B_TRUE}, {B_TRUE} },

	/* tunable - 40 */
	{ "_rexmit_interval_extra", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {0*MS, 2*HOURS, 0*MS}, {0*MS} },

	{ "_deferred_acks_max", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 16, 2}, {2} },

	{ "_slow_start_after_idle", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 16384, 0}, {0} },

	{ "_slow_start_initial", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 16, 0}, {0} },

	{ "sack", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 2, 2}, {2} },

	{ "_ipv6_hoplimit", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {0, IPV6_MAX_HOPS, IPV6_DEFAULT_HOPS},
	    {IPV6_DEFAULT_HOPS} },

	{ "_mss_def_ipv6", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1, TCP_MSS_MAX_IPV6, 1220}, {1220} },

	{ "_mss_max_ipv6", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1, TCP_MSS_MAX_IPV6, TCP_MSS_MAX_IPV6},
	    {TCP_MSS_MAX_IPV6} },

	{ "_rev_src_routes", MOD_PROTO_TCP,
	    mod_set_boolean, mod_get_boolean,
	    {B_FALSE}, {B_FALSE} },

	{ "_local_dack_interval", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {10*MS, 500*MS, 50*MS}, {50*MS} },

	/* tunable - 50 */
	{ "_local_dacks_max", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 16, 8}, {8} },

	{ "ecn", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 2, 1}, {1} },

	{ "_rst_sent_rate_enabled", MOD_PROTO_TCP,
	    mod_set_boolean, mod_get_boolean,
	    {B_TRUE}, {B_TRUE} },

	{ "_rst_sent_rate", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {0, UINT32_MAX, 40}, {40} },

	{ "_push_timer_interval", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 100*MS, 50*MS}, {50*MS} },

	{ "_use_smss_as_mss_opt", MOD_PROTO_TCP,
	    mod_set_boolean, mod_get_boolean,
	    {B_FALSE}, {B_FALSE} },

	{ "_keepalive_abort_interval", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {0, UINT32_MAX, 8*MINUTES}, {8*MINUTES} },

	/*
	 * tcp_wroff_xtra is the extra space in front of TCP/IP header for link
	 * layer header.  It has to be a multiple of 8.
	 */
	{ "_wroff_xtra", MOD_PROTO_TCP,
	    mod_set_aligned, mod_get_uint32,
	    {0, 256, 32}, {32} },

	{ "_dev_flow_ctl", MOD_PROTO_TCP,
	    mod_set_boolean, mod_get_boolean,
	    {B_FALSE}, {B_FALSE} },

	{ "_reass_timeout", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {0, UINT32_MAX, 100*SECONDS}, {100*SECONDS} },

	/* tunable - 60 */
	{ "extra_priv_ports", MOD_PROTO_TCP,
	    mod_set_extra_privports, mod_get_extra_privports,
	    {1, ULP_MAX_PORT, 0}, {0} },

	{ "_1948_phrase", MOD_PROTO_TCP,
	    tcp_set_1948phrase, NULL, {0}, {0} },

	{ "_listener_limit_conf", MOD_PROTO_TCP,
	    NULL, tcp_listener_conf_get, {0}, {0} },

	{ "_listener_limit_conf_add", MOD_PROTO_TCP,
	    tcp_listener_conf_add, NULL, {0}, {0} },

	{ "_listener_limit_conf_del", MOD_PROTO_TCP,
	    tcp_listener_conf_del, NULL, {0}, {0} },

	{ "_iss_incr", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1, ISS_INCR, ISS_INCR},
	    {ISS_INCR} },

	{ "?", MOD_PROTO_TCP, NULL, mod_get_allprop, {0}, {0} },

	{ NULL, 0, NULL, NULL, {0}, {0} }
};

int tcp_propinfo_count = A_CNT(tcp_propinfo_tbl);
