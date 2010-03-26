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
#include <inet/tcp_impl.h>
#include <sys/multidata.h>
#include <sys/sunddi.h>

/* Max size IP datagram is 64k - 1 */
#define	TCP_MSS_MAX_IPV4 (IP_MAXPACKET - (sizeof (ipha_t) + sizeof (tcpha_t)))
#define	TCP_MSS_MAX_IPV6 (IP_MAXPACKET - (sizeof (ip6_t) + sizeof (tcpha_t)))

/* Max of the above */
#define	TCP_MSS_MAX		TCP_MSS_MAX_IPV4

#define	TCP_XMIT_LOWATER	4096
#define	TCP_XMIT_HIWATER	49152
#define	TCP_RECV_LOWATER	2048
#define	TCP_RECV_HIWATER	128000

/*
 * Set the RFC 1948 pass phrase
 */
/* ARGSUSED */
static int
tcp_set_1948phrase(void *cbarg,  cred_t *cr, mod_prop_info_t *pinfo,
    const char *ifname, const void* pr_val, uint_t flags)
{
	tcp_stack_t	*tcps = (tcp_stack_t *)cbarg;

	if (flags & MOD_PROP_DEFAULT)
		return (ENOTSUP);

	/*
	 * Basically, value contains a new pass phrase.  Pass it along!
	 */
	tcp_iss_key_init((uint8_t *)pr_val, strlen(pr_val), tcps);
	return (0);
}

/*
 * returns the current list of listener limit configuration.
 */
/* ARGSUSED */
static int
tcp_listener_conf_get(void *cbarg, mod_prop_info_t *pinfo, const char *ifname,
    void *val, uint_t psize, uint_t flags)
{
	tcp_stack_t	*tcps = (tcp_stack_t *)cbarg;
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
ret:
	mutex_exit(&tcps->tcps_listener_conf_lock);
	return (err);
}

/*
 * add a new listener limit configuration.
 */
/* ARGSUSED */
static int
tcp_listener_conf_add(void *cbarg, cred_t *cr, mod_prop_info_t *pinfo,
    const char *ifname, const void* pval, uint_t flags)
{
	tcp_listener_t	*new_tl;
	tcp_listener_t	*tl;
	long		lport;
	long		ratio;
	char		*colon;
	tcp_stack_t	*tcps = (tcp_stack_t *)cbarg;

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
tcp_listener_conf_del(void *cbarg, cred_t *cr, mod_prop_info_t *pinfo,
    const char *ifname, const void* pval, uint_t flags)
{
	tcp_listener_t	*tl;
	long		lport;
	tcp_stack_t	*tcps = (tcp_stack_t *)cbarg;

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

/*
 * All of these are alterable, within the min/max values given, at run time.
 *
 * Note: All those tunables which do not start with "tcp_" are Committed and
 * therefore are public. See PSARC 2009/306.
 */
mod_prop_info_t tcp_propinfo_tbl[] = {
	/* tunable - 0 */
	{ "tcp_time_wait_interval", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1*SECONDS, 10*MINUTES, 1*MINUTES}, {1*MINUTES} },

	{ "tcp_conn_req_max_q", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1, UINT32_MAX, 128}, {128} },

	{ "tcp_conn_req_max_q0", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {0, UINT32_MAX, 1024}, {1024} },

	{ "tcp_conn_req_min", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1, 1024, 1}, {1} },

	{ "tcp_conn_grace_period", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {0*MS, 20*SECONDS, 0*MS}, {0*MS} },

	{ "tcp_cwnd_max", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {128, (1<<30), 1024*1024}, {1024*1024} },

	{ "tcp_debug", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 10, 0}, {0} },

	{ "smallest_nonpriv_port", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1024, (32*1024), 1024}, {1024} },

	{ "tcp_ip_abort_cinterval", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1*SECONDS, UINT32_MAX, 3*MINUTES}, {3*MINUTES} },

	{ "tcp_ip_abort_linterval", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1*SECONDS, UINT32_MAX, 3*MINUTES}, {3*MINUTES} },

	/* tunable - 10 */
	{ "tcp_ip_abort_interval", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {500*MS, UINT32_MAX, 5*MINUTES}, {5*MINUTES} },

	{ "tcp_ip_notify_cinterval", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1*SECONDS, UINT32_MAX, 10*SECONDS},
	    {10*SECONDS} },

	{ "tcp_ip_notify_interval", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {500*MS, UINT32_MAX, 10*SECONDS}, {10*SECONDS} },

	{ "tcp_ipv4_ttl", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1, 255, 64}, {64} },

	{ "tcp_keepalive_interval", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {10*SECONDS, 10*DAYS, 2*HOURS}, {2*HOURS} },

	{ "tcp_maxpsz_multiplier", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 100, 10}, {10} },

	{ "tcp_mss_def_ipv4", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1, TCP_MSS_MAX_IPV4, 536}, {536} },

	{ "tcp_mss_max_ipv4", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1, TCP_MSS_MAX_IPV4, TCP_MSS_MAX_IPV4},
	    {TCP_MSS_MAX_IPV4} },

	{ "tcp_mss_min", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1, TCP_MSS_MAX, 108}, {108} },

	{ "tcp_naglim_def", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1, (64*1024)-1, (4*1024)-1}, {(4*1024)-1} },

	/* tunable - 20 */
	{ "tcp_rexmit_interval_initial", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1*MS, 20*SECONDS, 1*SECONDS}, {1*SECONDS} },

	{ "tcp_rexmit_interval_max", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1*MS, 2*HOURS, 60*SECONDS}, {60*SECONDS} },

	{ "tcp_rexmit_interval_min", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1*MS, 2*HOURS, 400*MS}, {400*MS} },

	{ "tcp_deferred_ack_interval", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1*MS, 1*MINUTES, 100*MS}, {100*MS} },

	{ "tcp_snd_lowat_fraction", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 16, 0}, {0} },

	{ "tcp_dupack_fast_retransmit", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1, 10000, 3}, {3} },

	{ "tcp_ignore_path_mtu", MOD_PROTO_TCP,
	    mod_set_boolean, mod_get_boolean,
	    {B_FALSE}, {B_FALSE} },

	{ "smallest_anon_port", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1024, ULP_MAX_PORT, 32*1024}, {32*1024} },

	{ "largest_anon_port", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1024, ULP_MAX_PORT, ULP_MAX_PORT},
	    {ULP_MAX_PORT} },

	{ "send_maxbuf", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {TCP_XMIT_LOWATER, (1<<30), TCP_XMIT_HIWATER},
	    {TCP_XMIT_HIWATER} },

	/* tunable - 30 */
	{ "tcp_xmit_lowat", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {TCP_XMIT_LOWATER, (1<<30), TCP_XMIT_LOWATER},
	    {TCP_XMIT_LOWATER} },

	{ "recv_maxbuf", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {TCP_RECV_LOWATER, (1<<30), TCP_RECV_HIWATER},
	    {TCP_RECV_HIWATER} },

	{ "tcp_recv_hiwat_minmss", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1, 65536, 4}, {4} },

	{ "tcp_fin_wait_2_flush_interval", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1*SECONDS, UINT32_MAX, 675*SECONDS},
	    {675*SECONDS} },

	{ "tcp_max_buf", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {8192, (1<<30), 1024*1024}, {1024*1024} },

	/*
	 * Question:  What default value should I set for tcp_strong_iss?
	 */
	{ "tcp_strong_iss", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 2, 1}, {1} },

	{ "tcp_rtt_updates", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 65536, 20}, {20} },

	{ "tcp_wscale_always", MOD_PROTO_TCP,
	    mod_set_boolean, mod_get_boolean,
	    {B_TRUE}, {B_TRUE} },

	{ "tcp_tstamp_always", MOD_PROTO_TCP,
	    mod_set_boolean, mod_get_boolean,
	    {B_FALSE}, {B_FALSE} },

	{ "tcp_tstamp_if_wscale", MOD_PROTO_TCP,
	    mod_set_boolean, mod_get_boolean,
	    {B_TRUE}, {B_TRUE} },

	/* tunable - 40 */
	{ "tcp_rexmit_interval_extra", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {0*MS, 2*HOURS, 0*MS}, {0*MS} },

	{ "tcp_deferred_acks_max", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 16, 2}, {2} },

	{ "tcp_slow_start_after_idle", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1, 16384, 4}, {4} },

	{ "tcp_slow_start_initial", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1, 4, 4}, {4} },

	{ "sack", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 2, 2}, {2} },

	{ "tcp_ipv6_hoplimit", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {0, IPV6_MAX_HOPS, IPV6_DEFAULT_HOPS},
	    {IPV6_DEFAULT_HOPS} },

	{ "tcp_mss_def_ipv6", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1, TCP_MSS_MAX_IPV6, 1220}, {1220} },

	{ "tcp_mss_max_ipv6", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {1, TCP_MSS_MAX_IPV6, TCP_MSS_MAX_IPV6},
	    {TCP_MSS_MAX_IPV6} },

	{ "tcp_rev_src_routes", MOD_PROTO_TCP,
	    mod_set_boolean, mod_get_boolean,
	    {B_FALSE}, {B_FALSE} },

	{ "tcp_local_dack_interval", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {10*MS, 500*MS, 50*MS}, {50*MS} },

	/* tunable - 50 */
	{ "tcp_local_dacks_max", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 16, 8}, {8} },

	{ "ecn", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 2, 1}, {1} },

	{ "tcp_rst_sent_rate_enabled", MOD_PROTO_TCP,
	    mod_set_boolean, mod_get_boolean,
	    {B_TRUE}, {B_TRUE} },

	{ "tcp_rst_sent_rate", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {0, UINT32_MAX, 40}, {40} },

	{ "tcp_push_timer_interval", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 100*MS, 50*MS}, {50*MS} },

	{ "tcp_use_smss_as_mss_opt", MOD_PROTO_TCP,
	    mod_set_boolean, mod_get_boolean,
	    {B_FALSE}, {B_FALSE} },

	{ "tcp_keepalive_abort_interval", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {0, UINT32_MAX, 8*MINUTES}, {8*MINUTES} },

	/*
	 * tcp_wroff_xtra is the extra space in front of TCP/IP header for link
	 * layer header.  It has to be a multiple of 8.
	 */
	{ "tcp_wroff_xtra", MOD_PROTO_TCP,
	    mod_set_aligned, mod_get_uint32,
	    {0, 256, 32}, {32} },

	{ "tcp_dev_flow_ctl", MOD_PROTO_TCP,
	    mod_set_boolean, mod_get_boolean,
	    {B_FALSE}, {B_FALSE} },

	{ "tcp_reass_timeout", MOD_PROTO_TCP,
	    mod_set_uint32, mod_get_uint32,
	    {0, UINT32_MAX, 100*SECONDS}, {100*SECONDS} },

	/* tunable - 60 */
	{ "extra_priv_ports", MOD_PROTO_TCP,
	    mod_set_extra_privports, mod_get_extra_privports,
	    {1, ULP_MAX_PORT, 0}, {0} },

	{ "tcp_1948_phrase", MOD_PROTO_TCP,
	    tcp_set_1948phrase, NULL, {0}, {0} },

	{ "tcp_listener_limit_conf", MOD_PROTO_TCP,
	    NULL, tcp_listener_conf_get, {0}, {0} },

	{ "tcp_listener_limit_conf_add", MOD_PROTO_TCP,
	    tcp_listener_conf_add, NULL, {0}, {0} },

	{ "tcp_listener_limit_conf_del", MOD_PROTO_TCP,
	    tcp_listener_conf_del, NULL, {0}, {0} },

	{ "?", MOD_PROTO_TCP, NULL, mod_get_allprop, {0}, {0} },

	{ NULL, 0, NULL, NULL, {0}, {0} }
};

int tcp_propinfo_count = A_CNT(tcp_propinfo_tbl);
