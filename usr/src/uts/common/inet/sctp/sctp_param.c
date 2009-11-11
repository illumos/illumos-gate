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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/stream.h>
#include <sys/socket.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <netinet/in.h>
#include <netinet/ip6.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/mi.h>
#include <inet/mib2.h>
#include <inet/nd.h>
#include <inet/ipclassifier.h>
#include "sctp_impl.h"
#include "sctp_addr.h"

#define	MS	1L
#define	SECONDS	(1000 * MS)
#define	MINUTES	(60 * SECONDS)
#define	HOURS	(60 * MINUTES)
#define	DAYS	(24 * HOURS)

#define	PARAM_MAX (~(uint32_t)0)

/* Max size IP datagram is 64k - 1 */
#define	SCTP_MSS_MAX_IPV4 (IP_MAXPACKET - (sizeof (ipha_t) + \
					sizeof (sctp_hdr_t)))
#define	SCTP_MSS_MAX_IPV6 (IP_MAXPACKET - (sizeof (ip6_t) + \
					sizeof (sctp_hdr_t)))
/* Max of the above */
#define	SCTP_MSS_MAX	SCTP_MSS_MAX_IPV4

/* Largest SCTP port number */
#define	SCTP_MAX_PORT	(64 * 1024 - 1)

/*
 * Extra privileged ports. In host byte order.
 * Protected by sctp_epriv_port_lock.
 */
#define	SCTP_NUM_EPRIV_PORTS	64

/*
 * sctp_wroff_xtra is the extra space in front of SCTP/IP header for link
 * layer header.  It has to be a multiple of 4.
 */
sctpparam_t lcl_sctp_wroff_xtra_param = { 0, 256, 32, "sctp_wroff_xtra" };

/*
 * All of these are alterable, within the min/max values given, at run time.
 * Note that the default value of "sctp_time_wait_interval" is four minutes,
 * per the SCTP spec.
 */
/* BEGIN CSTYLED */
sctpparam_t	lcl_sctp_param_arr[] = {
 /*min		max		value		name */
 { 0,		128,		8,		"sctp_max_init_retr"},
 { 1,		128,		10,		"sctp_pa_max_retr"},
 { 1,		128,		5,		"sctp_pp_max_retr" },
 { 128,		(1<<30),	1024*1024,	"sctp_cwnd_max" },
 { 0,		10,		0,		"sctp_debug" },
 { 1024,	(32*1024),	1024,		"sctp_smallest_nonpriv_port"},
 { 1,		255,		64,		"sctp_ipv4_ttl"},
 { 0,		1*DAYS,		30*SECONDS,	"sctp_heartbeat_interval"},
 { 68,		65535,		1500,		"sctp_initial_mtu" },
 { 0,		1*DAYS,		10*MINUTES,	"sctp_mtu_probe_interval"},
 { 0,		1*DAYS,		2*MINUTES,	"sctp_new_secret_interval"},
 { 10*MS,	1*MINUTES,	100*MS,		"sctp_deferred_ack_interval" },
 { 0,		16,		0,		"sctp_snd_lowat_fraction" },
 { 0,		1,		0,		"sctp_ignore_path_mtu" },
 { 1024,	PARAM_MAX,     SCTP_RECV_HIWATER,"sctp_initial_ssthresh" },
 { 1024,	SCTP_MAX_PORT,	32*1024,	"sctp_smallest_anon_port"},
 { 1024,	SCTP_MAX_PORT,	SCTP_MAX_PORT,	"sctp_largest_anon_port"},
 { SCTP_XMIT_LOWATER, (1<<30), SCTP_XMIT_HIWATER,"sctp_xmit_hiwat"},
 { SCTP_XMIT_LOWATER, (1<<30), SCTP_XMIT_LOWATER,"sctp_xmit_lowat"},
 { SCTP_RECV_LOWATER, (1<<30), SCTP_RECV_HIWATER,"sctp_recv_hiwat"},
 { 8192,	(1<<30),	1024*1024,	"sctp_max_buf"},
 { 0,		65536,		20,		"sctp_rtt_updates"},
 { 0,		IPV6_MAX_HOPS,	IPV6_DEFAULT_HOPS,	"sctp_ipv6_hoplimit"},
 { 500*MS,	60*SECONDS,	1*SECONDS,	"sctp_rto_min"},
 { 1*SECONDS,	60000*SECONDS,	60*SECONDS,	"sctp_rto_max"},
 { 1*SECONDS,	60000*SECONDS,	3*SECONDS,	"sctp_rto_initial"},
 { 10*MS,	60000*SECONDS,	60*SECONDS,	"sctp_cookie_life"},
 { 1,		UINT16_MAX,	32,		"sctp_max_in_streams"},
 { 1,		UINT16_MAX,	32,		"sctp_initial_out_streams"},
 { 0,		300*SECONDS,	60*SECONDS,	"sctp_shutack_wait_bound" },
 { 2,		8,		4,		"sctp_maxburst" },
 { 0,		1,		0,		"sctp_addip_enabled" },
 { 1,		65536,		4,		"sctp_recv_hiwat_minmss" },
 { 1,		16,		4,		"sctp_slow_start_initial"},
 { 1,		16384,		4,		"sctp_slow_start_after_idle"},
 { 0,		1,		1,		"sctp_prsctp_enabled"},
 { 1,		10000,		3,		"sctp_fast_rxt_thresh"},
 { 1,		16,		2,		"sctp_deferred_acks_max"},
};
/* END CSTYLED */

/* Get callback routine passed to nd_load by sctp_param_register */
/* ARGSUSED */
static int
sctp_param_get(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *cr)
{
	sctpparam_t	*sctppa = (sctpparam_t *)cp;

	(void) mi_mpprintf(mp, "%u", sctppa->sctp_param_val);
	return (0);
}

/* Set callback routine passed to nd_load by sctp_param_register */
/* ARGSUSED */
static int
sctp_param_set(queue_t *q, mblk_t *mp, char *value, caddr_t cp, cred_t *cr)
{
	long		new_value;
	sctpparam_t	*sctppa = (sctpparam_t *)cp;

	if (ddi_strtol(value, NULL, 10, &new_value) != 0 ||
	    new_value < sctppa->sctp_param_min ||
	    new_value > sctppa->sctp_param_max) {
		return (EINVAL);
	}
	sctppa->sctp_param_val = new_value;
	return (0);
}

/* ndd set routine for sctp_wroff_xtra. */
/* ARGSUSED */
static int
sctp_wroff_xtra_set(queue_t *q, mblk_t *mp, char *value, caddr_t cp,
    cred_t *cr)
{
	long		new_value;
	sctpparam_t	*sctppa = (sctpparam_t *)cp;

	if (ddi_strtol(value, NULL, 10, &new_value) != 0 ||
	    new_value < sctppa->sctp_param_min ||
	    new_value > sctppa->sctp_param_max) {
		return (EINVAL);
	}
	/*
	 * Need to make sure new_value is a multiple of 8.  If it is not,
	 * round it up.
	 */
	if (new_value & 0x7) {
		new_value = (new_value & ~0x7) + 0x8;
	}
	sctppa->sctp_param_val = new_value;
	return (0);
}

/*
 * Note: No locks are held when inspecting sctp_g_*epriv_ports
 * but instead the code relies on:
 * - the fact that the address of the array and its size never changes
 * - the atomic assignment of the elements of the array
 */
/* ARGSUSED */
static int
sctp_extra_priv_ports_get(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *cr)
{
	int i;
	sctp_stack_t	*sctps = Q_TO_CONN(q)->conn_netstack->netstack_sctp;

	for (i = 0; i < sctps->sctps_g_num_epriv_ports; i++) {
		if (sctps->sctps_g_epriv_ports[i] != 0)
			(void) mi_mpprintf(mp, "%d ",
			    sctps->sctps_g_epriv_ports[i]);
	}
	return (0);
}

/*
 * Hold a lock while changing sctp_g_epriv_ports to prevent multiple
 * threads from changing it at the same time.
 */
/* ARGSUSED */
static int
sctp_extra_priv_ports_add(queue_t *q, mblk_t *mp, char *value, caddr_t cp,
    cred_t *cr)
{
	long	new_value;
	int	i;
	sctp_stack_t	*sctps = Q_TO_CONN(q)->conn_netstack->netstack_sctp;

	/*
	 * Fail the request if the new value does not lie within the
	 * port number limits.
	 */
	if (ddi_strtol(value, NULL, 10, &new_value) != 0 ||
	    new_value <= 0 || new_value >= 65536) {
		return (EINVAL);
	}

	mutex_enter(&sctps->sctps_epriv_port_lock);
	/* Check if the value is already in the list */
	for (i = 0; i < sctps->sctps_g_num_epriv_ports; i++) {
		if (new_value == sctps->sctps_g_epriv_ports[i]) {
			mutex_exit(&sctps->sctps_epriv_port_lock);
			return (EEXIST);
		}
	}
	/* Find an empty slot */
	for (i = 0; i < sctps->sctps_g_num_epriv_ports; i++) {
		if (sctps->sctps_g_epriv_ports[i] == 0)
			break;
	}
	if (i == sctps->sctps_g_num_epriv_ports) {
		mutex_exit(&sctps->sctps_epriv_port_lock);
		return (EOVERFLOW);
	}
	/* Set the new value */
	sctps->sctps_g_epriv_ports[i] = (uint16_t)new_value;
	mutex_exit(&sctps->sctps_epriv_port_lock);
	return (0);
}

/*
 * Hold a lock while changing sctp_g_epriv_ports to prevent multiple
 * threads from changing it at the same time.
 */
/* ARGSUSED */
static int
sctp_extra_priv_ports_del(queue_t *q, mblk_t *mp, char *value, caddr_t cp,
    cred_t *cr)
{
	long	new_value;
	int	i;
	sctp_stack_t	*sctps = Q_TO_CONN(q)->conn_netstack->netstack_sctp;

	/*
	 * Fail the request if the new value does not lie within the
	 * port number limits.
	 */
	if (ddi_strtol(value, NULL, 10, &new_value) != 0 ||
	    new_value <= 0 || new_value >= 65536) {
		return (EINVAL);
	}

	mutex_enter(&sctps->sctps_epriv_port_lock);
	/* Check that the value is already in the list */
	for (i = 0; i < sctps->sctps_g_num_epriv_ports; i++) {
		if (sctps->sctps_g_epriv_ports[i] == new_value)
			break;
	}
	if (i == sctps->sctps_g_num_epriv_ports) {
		mutex_exit(&sctps->sctps_epriv_port_lock);
		return (ESRCH);
	}
	/* Clear the value */
	sctps->sctps_g_epriv_ports[i] = 0;
	mutex_exit(&sctps->sctps_epriv_port_lock);
	return (0);
}

/*
 * Walk through the param array specified registering each element with the
 * named dispatch handler.
 */
boolean_t
sctp_param_register(IDP *ndp, sctpparam_t *sctppa, int cnt, sctp_stack_t *sctps)
{

	if (*ndp != NULL) {
		return (B_TRUE);
	}

	for (; cnt-- > 0; sctppa++) {
		if (sctppa->sctp_param_name && sctppa->sctp_param_name[0]) {
			if (!nd_load(ndp, sctppa->sctp_param_name,
			    sctp_param_get, sctp_param_set,
			    (caddr_t)sctppa)) {
				nd_free(ndp);
				return (B_FALSE);
			}
		}
	}
	sctps->sctps_wroff_xtra_param = kmem_zalloc(sizeof (sctpparam_t),
	    KM_SLEEP);
	bcopy(&lcl_sctp_wroff_xtra_param, sctps->sctps_wroff_xtra_param,
	    sizeof (sctpparam_t));
	if (!nd_load(ndp, sctps->sctps_wroff_xtra_param->sctp_param_name,
	    sctp_param_get, sctp_wroff_xtra_set,
	    (caddr_t)sctps->sctps_wroff_xtra_param)) {
		nd_free(ndp);
		return (B_FALSE);
	}
	if (!nd_load(ndp, "sctp_extra_priv_ports",
	    sctp_extra_priv_ports_get, NULL, NULL)) {
		nd_free(ndp);
		return (B_FALSE);
	}
	if (!nd_load(ndp, "sctp_extra_priv_ports_add",
	    NULL, sctp_extra_priv_ports_add, NULL)) {
		nd_free(ndp);
		return (B_FALSE);
	}
	if (!nd_load(ndp, "sctp_extra_priv_ports_del",
	    NULL, sctp_extra_priv_ports_del, NULL)) {
		nd_free(ndp);
		return (B_FALSE);
	}
	return (B_TRUE);
}

boolean_t
sctp_nd_init(sctp_stack_t *sctps)
{
	sctpparam_t *pa;

	pa = kmem_alloc(sizeof (lcl_sctp_param_arr), KM_SLEEP);
	bcopy(lcl_sctp_param_arr, pa, sizeof (lcl_sctp_param_arr));
	sctps->sctps_params = pa;
	return (sctp_param_register(&sctps->sctps_g_nd, pa,
	    A_CNT(lcl_sctp_param_arr), sctps));
}

int
sctp_nd_getset(queue_t *q, MBLKP mp)
{
	sctp_stack_t	*sctps = Q_TO_CONN(q)->conn_netstack->netstack_sctp;

	return (nd_getset(q, sctps->sctps_g_nd, mp));
}

void
sctp_nd_free(sctp_stack_t *sctps)
{
	nd_free(&sctps->sctps_g_nd);
	kmem_free(sctps->sctps_params, sizeof (lcl_sctp_param_arr));
	sctps->sctps_params = NULL;
	kmem_free(sctps->sctps_wroff_xtra_param, sizeof (sctpparam_t));
	sctps->sctps_wroff_xtra_param = NULL;

}
