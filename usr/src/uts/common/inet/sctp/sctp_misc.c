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

#include <sys/types.h>
#include <inet/common.h>
#include "sctp_impl.h"

/* Control whether SCTP can enter defensive mode when under memory pressure. */
static boolean_t sctp_do_reclaim = B_TRUE;

static void	sctp_reclaim_timer(void *);

/* Diagnostic routine used to return a string associated with the sctp state. */
char *
sctp_display(sctp_t *sctp, char *sup_buf)
{
	char	*buf;
	char	buf1[30];
	static char	priv_buf[INET6_ADDRSTRLEN * 2 + 80];
	char	*cp;
	conn_t	*connp;

	if (sctp == NULL)
		return ("NULL_SCTP");

	connp = sctp->sctp_connp;
	buf = (sup_buf != NULL) ? sup_buf : priv_buf;

	switch (sctp->sctp_state) {
	case SCTPS_IDLE:
		cp = "SCTP_IDLE";
		break;
	case SCTPS_BOUND:
		cp = "SCTP_BOUND";
		break;
	case SCTPS_LISTEN:
		cp = "SCTP_LISTEN";
		break;
	case SCTPS_COOKIE_WAIT:
		cp = "SCTP_COOKIE_WAIT";
		break;
	case SCTPS_COOKIE_ECHOED:
		cp = "SCTP_COOKIE_ECHOED";
		break;
	case SCTPS_ESTABLISHED:
		cp = "SCTP_ESTABLISHED";
		break;
	case SCTPS_SHUTDOWN_PENDING:
		cp = "SCTP_SHUTDOWN_PENDING";
		break;
	case SCTPS_SHUTDOWN_SENT:
		cp = "SCTPS_SHUTDOWN_SENT";
		break;
	case SCTPS_SHUTDOWN_RECEIVED:
		cp = "SCTPS_SHUTDOWN_RECEIVED";
		break;
	case SCTPS_SHUTDOWN_ACK_SENT:
		cp = "SCTPS_SHUTDOWN_ACK_SENT";
		break;
	default:
		(void) mi_sprintf(buf1, "SCTPUnkState(%d)", sctp->sctp_state);
		cp = buf1;
		break;
	}
	(void) mi_sprintf(buf, "[%u, %u] %s",
	    ntohs(connp->conn_lport), ntohs(connp->conn_fport), cp);

	return (buf);
}

void
sctp_display_all(sctp_stack_t *sctps)
{
	sctp_t *sctp_walker;

	mutex_enter(&sctps->sctps_g_lock);
	for (sctp_walker = list_head(&sctps->sctps_g_list);
	    sctp_walker != NULL;
	    sctp_walker = (sctp_t *)list_next(&sctps->sctps_g_list,
	    sctp_walker)) {
		(void) sctp_display(sctp_walker, NULL);
	}
	mutex_exit(&sctps->sctps_g_lock);
}

/*
 * Given a sctp_stack_t and a port (in host byte order), find a listener
 * configuration for that port and return the ratio.
 */
uint32_t
sctp_find_listener_conf(sctp_stack_t *sctps, in_port_t port)
{
	sctp_listener_t	*sl;
	uint32_t ratio = 0;

	mutex_enter(&sctps->sctps_listener_conf_lock);
	for (sl = list_head(&sctps->sctps_listener_conf); sl != NULL;
	    sl = list_next(&sctps->sctps_listener_conf, sl)) {
		if (sl->sl_port == port) {
			ratio = sl->sl_ratio;
			break;
		}
	}
	mutex_exit(&sctps->sctps_listener_conf_lock);
	return (ratio);
}

/*
 * To remove all listener limit configuration in a sctp_stack_t.
 */
void
sctp_listener_conf_cleanup(sctp_stack_t *sctps)
{
	sctp_listener_t	*sl;

	mutex_enter(&sctps->sctps_listener_conf_lock);
	while ((sl = list_head(&sctps->sctps_listener_conf)) != NULL) {
		list_remove(&sctps->sctps_listener_conf, sl);
		kmem_free(sl, sizeof (sctp_listener_t));
	}
	mutex_destroy(&sctps->sctps_listener_conf_lock);
	list_destroy(&sctps->sctps_listener_conf);
}


/*
 * Timeout function to reset the SCTP stack variable sctps_reclaim to false.
 */
static void
sctp_reclaim_timer(void *arg)
{
	sctp_stack_t *sctps = (sctp_stack_t *)arg;
	int64_t tot_assoc = 0;
	int i;
	extern pgcnt_t lotsfree, needfree;

	for (i = 0; i < sctps->sctps_sc_cnt; i++)
		tot_assoc += sctps->sctps_sc[i]->sctp_sc_assoc_cnt;

	/*
	 * This happens only when a stack is going away.  sctps_reclaim_tid
	 * should not be reset to 0 when returning in this case.
	 */
	mutex_enter(&sctps->sctps_reclaim_lock);
	if (!sctps->sctps_reclaim) {
		mutex_exit(&sctps->sctps_reclaim_lock);
		return;
	}

	if ((freemem >= lotsfree + needfree) || tot_assoc < maxusers) {
		sctps->sctps_reclaim = B_FALSE;
		sctps->sctps_reclaim_tid = 0;
	} else {
		/* Stay in defensive mode and restart the timer */
		sctps->sctps_reclaim_tid = timeout(sctp_reclaim_timer,
		    sctps, MSEC_TO_TICK(sctps->sctps_reclaim_period));
	}
	mutex_exit(&sctps->sctps_reclaim_lock);
}

/*
 * Kmem reclaim call back function.  When the system is under memory
 * pressure, we set the SCTP stack variable sctps_reclaim to true.  This
 * variable is reset to false after sctps_reclaim_period msecs.  During this
 * period, SCTP will be more aggressive in aborting connections not making
 * progress, meaning retransmitting for shorter time (sctp_pa_early_abort/
 * sctp_pp_early_abort number of strikes).
 */
/* ARGSUSED */
void
sctp_conn_reclaim(void *arg)
{
	netstack_handle_t nh;
	netstack_t *ns;
	sctp_stack_t *sctps;
	extern pgcnt_t lotsfree, needfree;

	if (!sctp_do_reclaim)
		return;

	/*
	 * The reclaim function may be called even when the system is not
	 * really under memory pressure.
	 */
	if (freemem >= lotsfree + needfree)
		return;

	netstack_next_init(&nh);
	while ((ns = netstack_next(&nh)) != NULL) {
		int i;
		int64_t tot_assoc = 0;

		/*
		 * During boot time, the first netstack_t is created and
		 * initialized before SCTP has registered with the netstack
		 * framework.  If this reclaim function is called before SCTP
		 * has finished its initialization, netstack_next() will
		 * return the first netstack_t (since its netstack_flags is
		 * not NSF_UNINIT).  And its netstack_sctp will be NULL.  We
		 * need to catch it.
		 *
		 * All subsequent netstack_t creation will not have this
		 * problem since the initialization is not finished until SCTP
		 * has finished its own sctp_stack_t initialization.  Hence
		 * netstack_next() will not return one with NULL netstack_sctp.
		 */
		if ((sctps = ns->netstack_sctp) == NULL) {
			netstack_rele(ns);
			continue;
		}

		/*
		 * Even if the system is under memory pressure, the reason may
		 * not be because of SCTP activity.  Check the number of
		 * associations in each stack.  If the number exceeds the
		 * threshold (maxusers), turn on defensive mode.
		 */
		for (i = 0; i < sctps->sctps_sc_cnt; i++)
			tot_assoc += sctps->sctps_sc[i]->sctp_sc_assoc_cnt;
		if (tot_assoc < maxusers) {
			netstack_rele(ns);
			continue;
		}

		mutex_enter(&sctps->sctps_reclaim_lock);
		if (!sctps->sctps_reclaim) {
			sctps->sctps_reclaim = B_TRUE;
			sctps->sctps_reclaim_tid = timeout(sctp_reclaim_timer,
			    sctps, MSEC_TO_TICK(sctps->sctps_reclaim_period));
			SCTP_KSTAT(sctps, sctp_reclaim_cnt);
		}
		mutex_exit(&sctps->sctps_reclaim_lock);
		netstack_rele(ns);
	}
	netstack_next_fini(&nh);
}

/*
 * When a CPU is added, we need to allocate the per CPU stats struct.
 */
void
sctp_stack_cpu_add(sctp_stack_t *sctps, processorid_t cpu_seqid)
{
	int i;

	if (cpu_seqid < sctps->sctps_sc_cnt)
		return;
	for (i = sctps->sctps_sc_cnt; i <= cpu_seqid; i++) {
		ASSERT(sctps->sctps_sc[i] == NULL);
		sctps->sctps_sc[i] = kmem_zalloc(sizeof (sctp_stats_cpu_t),
		    KM_SLEEP);
	}
	membar_producer();
	sctps->sctps_sc_cnt = cpu_seqid + 1;
}
