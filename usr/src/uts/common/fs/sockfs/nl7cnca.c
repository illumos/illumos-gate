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

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/stropts.h>
#define	_SUN_TPI_VERSION 2
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/vtrace.h>
#include <sys/errno.h>
#include <inet/common.h>
#include <inet/led.h>
#include <inet/mi.h>
#include <inet/nd.h>
#include <sys/strsun.h>

#include <fs/sockfs/nl7c.h>
#include <fs/sockfs/nl7curi.h>

#include <inet/nca/nca.h>
#include <inet/nca/ncalogd.h>

/*
 * This file is for NCA compatability, specifically it provides ndd
 * support for existing NCA ndd ...
 */

extern boolean_t	nl7c_logd_enabled;
extern nca_fio_t	*nl7c_logd_fio;
extern clock_t		nl7c_uri_ttl;
extern boolean_t	nl7c_use_kmem;
extern uint64_t		nl7c_file_prefetch;
extern uint64_t		nl7c_uri_max;
extern uint64_t		nl7c_uri_bytes;

extern void		nl7c_mi_report_addr(mblk_t *);

#define	MS	1L
#define	SECONDS	(1000 * MS)
#define	MINUTES	(60 * SECONDS)
#define	HOURS	(60 * MINUTES)
#define	DAYS	(24 * HOURS)

#define	PARAM_MAX UINT_MAX
#define	PARAML_MAX ULONG_MAX

#include <inet/nca/ncandd.h>

uint32_t nca_major_version = 1;
uint32_t nca_minor_version = 3;
uint32_t nca_httpd_version = NCA_HTTP_VERSION1;
uint32_t nca_logd_version = NCA_LOG_VERSION1;

caddr_t	nca_g_nd;	/* Head of 'named dispatch' variable list */

/*
 * min, max, and value are int64_t's, addr is the optional address of an
 * external int64_t to be updated at init/set, name is the ndd name used
 * to access. Note, if min == max then only get is allowed, i.e. RO.
 */

/* BEGIN CSTYLED */
ncaparam_t	nca_param_arr[] = {
 /*min	max		value		name */
 { 0,	1,		1,		"nca_log_cycle"},
 { 0,	1,		0,		"no_caching"},
 { 0,	PARAML_MAX,    	0,		"nca_log_size"},
 { 0,	PARAM_MAX,     	10000000,	"nca_max_cache_size"},
 { 0,	PARAM_MAX,	300*SECONDS,	"nca_http_timeout"},
 { 0,	PARAM_MAX,	15*SECONDS,	"nca_http_keep_alive_timeout"},
 { 0,	PARAM_MAX,	100,		"nca_http_keep_alive_max"},
 { 0,	1,		1,		"nca_inq_nointr"},
 { 0,	1,		1,		"nca_use_hwcksum"},
 { 0,	PARAM_MAX,	0,		"nca_segmap_min_size"},
};

/*
 * Obsolete ip variables, use "/dev/ip" instead.
 */

ncaparam_t	nca_ip_obsolete_arr[] = {
 { 0, 0, 0, "ip_forwarding"},
 { 0, 0, 0, "ip_respond_to_address_mask_broadcast"},
 { 0, 0, 0, "ip_respond_to_echo_broadcast"},
 { 0, 0, 0, "ip_respond_to_timestamp"},
 { 0, 0, 0, "ip_respond_to_timestamp_broadcast"},
 { 0, 0, 0, "ip_send_redirects"},
 { 0, 0, 0, "ip_forward_directed_broadcasts"},
 { 0, 0, 0, "ip_debug"},
 { 0, 0, 0, "ip_mrtdebug"},
 { 0, 0, 0, "ip_ire_cleanup_interval" },
 { 0, 0, 0, "ip_ire_flush_interval" },
 { 0, 0, 0, "ip_ire_redirect_interval" },
 { 0, 0, 0, "ip_def_ttl" },
 { 0, 0, 0, "ip_forward_src_routed"},
 { 0, 0, 0, "ip_wroff_extra" },
 { 0, 0, 0, "ip_ire_pathmtu_interval" },
 { 0, 0, 0, "ip_icmp_return_data_bytes" },
 { 0, 0, 0, "ip_send_source_quench" },
 { 0, 0, 0, "ip_path_mtu_discovery" },
 { 0, 0, 0, "ip_ignore_delete_time" },
 { 0, 0, 0, "ip_ignore_redirect" },
 { 0, 0, 0, "ip_output_queue" },
 { 0, 0, 0, "ip_broadcast_ttl" },
 { 0, 0, 0, "ip_icmp_err_interval" },
 { 0, 0, 0, "ip_reass_queue_bytes" },
 { 0, 0, 0, "ip_strict_dst_multihoming" },
 { 0, 0, 0, "ip_addrs_per_if"},
};

/*
 * Obsolete tcp variables, use "/dev/tcp" instead.
 */

ncaparam_t	nca_tcp_obsolete_arr[] = {
 { 0, 0, 0, "tcp_time_wait_interval"},
 { 0, 0, 0, "tcp_conn_req_max_q" },
 { 0, 0, 0, "tcp_conn_req_max_q0" },
 { 0, 0, 0, "tcp_conn_req_min" },
 { 0, 0, 0, "tcp_conn_grace_period" },
 { 0, 0, 0, "tcp_cwnd_max" },
 { 0, 0, 0, "tcp_debug" },
 { 0, 0, 0, "tcp_smallest_nonpriv_port"},
 { 0, 0, 0, "tcp_ip_abort_cinterval"},
 { 0, 0, 0, "tcp_ip_abort_linterval"},
 { 0, 0, 0, "tcp_ip_abort_interval"},
 { 0, 0, 0, "tcp_ip_notify_cinterval"},
 { 0, 0, 0, "tcp_ip_notify_interval"},
 { 0, 0, 0, "tcp_ip_ttl"},
 { 0, 0, 0, "tcp_keepalive_interval"},
 { 0, 0, 0, "tcp_maxpsz_multiplier" },
 { 0, 0, 0, "tcp_mss_def"},
 { 0, 0, 0, "tcp_mss_max"},
 { 0, 0, 0, "tcp_mss_min"},
 { 0, 0, 0, "tcp_naglim_def"},
 { 0, 0, 0, "tcp_rexmit_interval_initial"},
 { 0, 0, 0, "tcp_rexmit_interval_max"},
 { 0, 0, 0, "tcp_rexmit_interval_min"},
 { 0, 0, 0, "tcp_wroff_xtra" },
 { 0, 0, 0, "tcp_deferred_ack_interval" },
 { 0, 0, 0, "tcp_snd_lowat_fraction" },
 { 0, 0, 0, "tcp_sth_rcv_hiwat" },
 { 0, 0, 0, "tcp_sth_rcv_lowat" },
 { 0, 0, 0, "tcp_dupack_fast_retransmit" },
 { 0, 0, 0, "tcp_ignore_path_mtu" },
 { 0, 0, 0, "tcp_rcv_push_wait" },
 { 0, 0, 0, "tcp_smallest_anon_port"},
 { 0, 0, 0, "tcp_largest_anon_port"},
 { 0, 0, 0, "tcp_xmit_hiwat"},
 { 0, 0, 0, "tcp_xmit_lowat"},
 { 0, 0, 0, "tcp_recv_hiwat"},
 { 0, 0, 0, "tcp_recv_hiwat_minmss"},
 { 0, 0, 0, "tcp_fin_wait_2_flush_interval"},
 { 0, 0, 0, "tcp_max_buf"},
 { 0, 0, 0, "tcp_strong_iss"},
 { 0, 0, 0, "tcp_rtt_updates"},
 { 0, 0, 0, "tcp_wscale_always"},
 { 0, 0, 0, "tcp_tstamp_always"},
 { 0, 0, 0, "tcp_tstamp_if_wscale"},
 { 0, 0, 0, "tcp_rexmit_interval_extra"},
 { 0, 0, 0, "tcp_deferred_acks_max"},
 { 0, 0, 0, "tcp_slow_start_after_idle"},
 { 0, 0, 0, "tcp_slow_start_initial"},
 { 0, 0, 0, "tcp_sack_permitted"},
#ifdef DEBUG
 { 0, 0, 0, "tcp_drop_oob"},
#endif
};

/*
 * Obsolete nca variables, just warn.
 */

ncaparam_t	nca_nca_obsolete_arr[] = {
 { 0, 0, 0, "nca_ipport_table_bucket"},
 { 0, 0, 0, "nca_ipport_table_size"},
 { 0, 0, 0, "nca_ipport_table_expand"},
 { 0, 0, 0, "nca_ipport_table_shrink"},
 { 0, 0, 0, "nca_ip_virtual_hosting"},
 { 0, 0, 0, "httpd_door_address"},
 { 0, 0, 0, "httpd_door_path"},
 { 0, 0, 0, "httpd_downdoor_path"},
 { 0, 0, 0, "nca_ppmax"},
 { 0, 0, 0, "nca_vpmax"},
 { 0, 0, 0, "nca_use_segmap"},
 { 0, 0, 0, "nca_availrmem"},
 { 0, 0, 0, "nca_maxkmem"},
 { 0, 0, 0, "nca_log_file"},
 { 0, 0, 0, "conn_status"},
 { 0, 0, 0, "conn_status_all"},
 { 0, 0, 0, "nca_conn_req_max_q"},
 { 0, 0, 0, "nca_conn_req_max_q0"},
 { 0, 0, 0, "cache_clear"},
 { 0, 0, 0, "nca_node_hash"},
 { 0, 0, 0, "node_status"},
#ifdef DEBUG
 { 0, 0, 0, "nca_debug_counter"},
#endif
};
/* END CSTYLED */

static int
/*ARGSUSED*/
nl7c_uri_ttl_get(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *cr)
{
	(void) mi_mpprintf(mp, "%ld", nl7c_uri_ttl);
	return (0);
}

static int
/*ARGSUSED*/
nl7c_uri_ttl_set(queue_t *q, mblk_t *mp, char *value, caddr_t nu, cred_t *cr)
{
	if (ddi_strtol(value, NULL, 10, &nl7c_uri_ttl) != 0)
		return (EINVAL);
	return (0);
}

static int
/*ARGSUSED*/
nca_logging_on_get(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *cr)
{
	(void) mi_mpprintf(mp, "%d", nl7c_logd_enabled);
	return (0);
}

static int
/*ARGSUSED*/
nca_logging_on_set(queue_t *q, mblk_t *mp, char *value, caddr_t nu, cred_t *cr)
{
	long new_value;

	if (ddi_strtol(value, NULL, 10, &new_value) != 0 || new_value < 0 ||
	    new_value > 1) {
		return (EINVAL);
	}
	if (nca_fio_cnt(nl7c_logd_fio) == 0)
		return (EINVAL);
	nl7c_logd_enabled = new_value;

	return (0);
}

static int
/*ARGSUSED*/
nca_version_get(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *cr)
{
	(void) mi_mpprintf(mp, "%d.%d", nca_major_version, nca_minor_version);
	return (0);
}

static int
/*ARGSUSED*/
nca_httpd_version_get(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *cr)
{
	(void) mi_mpprintf(mp, "%d", nca_httpd_version);
	return (0);
}

static int
/*ARGSUSED*/
nca_logd_version_get(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *cr)
{
	(void) mi_mpprintf(mp, "%d", nca_logd_version);
	return (0);
}

static int
/*ARGSUSED*/
nca_httpd_door_inst_get(queue_t *q, mblk_t *mp, caddr_t nu, cred_t *cr)
{
	nl7c_mi_report_addr(mp);
	return (0);
}

static int
/*ARGSUSED*/
nca_param_get(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *cr)
{
	ncaparam_t	*ncapa = (ncaparam_t *)cp;

	(void) mi_mpprintf(mp, "%ld", ncapa->param_val);
	return (0);
}

static int
/*ARGSUSED*/
nca_param_set(queue_t *q, mblk_t *mp, char *value, caddr_t cp, cred_t *cr)
{
	ulong_t		new_value;
	ncaparam_t	*ncapa = (ncaparam_t *)cp;

	if (ddi_strtoul(value, NULL, 10, &new_value) != 0 ||
	    new_value < ncapa->param_min || new_value > ncapa->param_max) {
		return (EINVAL);
	}
	ncapa->param_val = new_value;
	return (0);
}

static int
/*ARGSUSED*/
nca_obsolete(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *cr)
{
	(void) mi_mpprintf(mp, "obsolete");
	return (0);
}

static int
/*ARGSUSED*/
nca_ip_obsolete(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *cr)
{
	(void) mi_mpprintf(mp, "obsolete for /dev/nca, use /dev/ip");
	return (0);
}

static int
/*ARGSUSED*/
nca_tcp_obsolete(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *cr)
{
	(void) mi_mpprintf(mp, "obsolete for /dev/nca, use /dev/tcp");
	return (0);
}

static int
/*ARGSUSED*/
nca_nca_obsolete(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *cr)
{
	(void) mi_mpprintf(mp, "obsolete for /dev/nca");
	return (0);
}

static boolean_t
nca_param_register(ncaparam_t *ncapa, int cnt)
{
	for (; cnt-- > 0; ncapa++) {
		if (ncapa->param_name && ncapa->param_name[0]) {
			if (!nd_load(&nca_g_nd, ncapa->param_name,
			    nca_param_get, nca_param_set,
			    (caddr_t)ncapa)) {
				goto error;
			}
		}

	}
	if (!nd_load(&nca_g_nd, "nca_version", nca_version_get, nil(pfi_t),
	    nil(caddr_t))) {
		goto error;
	}
	if (!nd_load(&nca_g_nd, "nca_logd_version", nca_logd_version_get,
	    nil(pfi_t), nil(caddr_t))) {
		goto error;
	}
	if (!nd_load(&nca_g_nd, "nca_logging_on", nca_logging_on_get,
	    nca_logging_on_set, nil(caddr_t))) {
		goto error;
	}

	if (!nd_load(&nca_g_nd, "uri_time_to_live", nl7c_uri_ttl_get,
	    nl7c_uri_ttl_set, nil(caddr_t))) {
		goto error;
	}
	if (!nd_load(&nca_g_nd, "nca_httpd_version", nca_httpd_version_get,
	    nil(pfi_t), nil(caddr_t))) {
		goto error;
	}
	if (!nd_load(&nca_g_nd, "httpd_door_instance", nca_httpd_door_inst_get,
	    nil(pfi_t), nil(caddr_t))) {
		nd_free(&nca_g_nd);
		return (B_FALSE);
	}

	ncapa = nca_ip_obsolete_arr;
	cnt = A_CNT(nca_ip_obsolete_arr);
	for (; cnt-- > 0; ncapa++) {
		if (ncapa->param_name && ncapa->param_name[0]) {
			if (!nd_load(&nca_g_nd, ncapa->param_name,
			    nca_ip_obsolete, NULL, (caddr_t)ncapa)) {
				goto error;
			}
		}

	}

	ncapa = nca_tcp_obsolete_arr;
	cnt = A_CNT(nca_tcp_obsolete_arr);
	for (; cnt-- > 0; ncapa++) {
		if (ncapa->param_name && ncapa->param_name[0]) {
			if (!nd_load(&nca_g_nd, ncapa->param_name,
			    nca_tcp_obsolete, NULL, (caddr_t)ncapa)) {
				goto error;
			}
		}

	}

	ncapa = nca_nca_obsolete_arr;
	cnt = A_CNT(nca_nca_obsolete_arr);
	for (; cnt-- > 0; ncapa++) {
		if (ncapa->param_name && ncapa->param_name[0]) {
			if (!nd_load(&nca_g_nd, ncapa->param_name,
			    nca_nca_obsolete, NULL, (caddr_t)ncapa)) {
				goto error;
			}
		}

	}

	return (B_TRUE);

error:
	nd_free(&nca_g_nd);
	return (B_FALSE);
}

void
nl7c_nca_init(void)
{
	if (! nca_g_nd) {
		if (! nca_param_register(nca_param_arr, A_CNT(nca_param_arr)))
			cmn_err(CE_WARN,
			    "nl7c: /dev/nca ndd initialization failed.");
	}
}
