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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/stropts.h>
#include <sys/strsun.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/xti_inet.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/vtrace.h>
#include <sys/kmem.h>
#include <sys/cpuvar.h>
#include <sys/random.h>
#include <sys/priv.h>
#include <sys/sunldi.h>

#include <sys/errno.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/isa_defs.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/sctp.h>
#include <net/if.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/mi.h>
#include <inet/mib2.h>
#include <inet/kstatcom.h>
#include <inet/nd.h>
#include <inet/optcom.h>
#include <inet/ipclassifier.h>
#include <inet/ipsec_impl.h>
#include <inet/sctp_ip.h>
#include <inet/sctp_crc32.h>

#include "sctp_impl.h"
#include "sctp_addr.h"
#include "sctp_asconf.h"

int sctpdebug;
sin6_t	sctp_sin6_null;	/* Zero address for quick clears */

/*
 * Have to ensure that sctp_g_q_close is not done by an
 * interrupt thread.
 */
static taskq_t *sctp_taskq;

static void	sctp_closei_local(sctp_t *sctp);
static int	sctp_init_values(sctp_t *, sctp_t *, int);
static void	sctp_icmp_error_ipv6(sctp_t *sctp, mblk_t *mp);
static void	sctp_process_recvq(void *);
static void	sctp_rq_tq_init(sctp_stack_t *);
static void	sctp_rq_tq_fini(sctp_stack_t *);
static void	sctp_conn_cache_init();
static void	sctp_conn_cache_fini();
static int	sctp_conn_cache_constructor();
static void	sctp_conn_cache_destructor();
static void	sctp_conn_clear(conn_t *);
void		sctp_g_q_setup(sctp_stack_t *);
void		sctp_g_q_create(sctp_stack_t *);
void		sctp_g_q_destroy(sctp_stack_t *);

static void	*sctp_stack_init(netstackid_t stackid, netstack_t *ns);
static void	sctp_stack_shutdown(netstackid_t stackid, void *arg);
static void	sctp_stack_fini(netstackid_t stackid, void *arg);

/*
 * SCTP receive queue taskq
 *
 * At SCTP initialization time, a default taskq is created for
 * servicing packets received when the interrupt thread cannot
 * get a hold on the sctp_t.  The number of taskq can be increased in
 * sctp_find_next_tq() when an existing taskq cannot be dispatched.
 * The taskqs are never removed.  But the max number of taskq which
 * can be created is controlled by sctp_recvq_tq_list_max_sz.  Note
 * that SCTP recvq taskq is not tied to any specific CPU or ill.
 *
 * Those taskqs are stored in an array recvq_tq_list.  And they are
 * used in a round robin fashion.  The current taskq being used is
 * determined by recvq_tq_list_cur.
 */

/* /etc/system variables */
/* The minimum number of threads for each taskq. */
int		sctp_recvq_tq_thr_min = 4;
/* The maximum number of threads for each taskq. */
int		sctp_recvq_tq_thr_max = 16;
/* The minimum number of tasks for each taskq. */
int		sctp_recvq_tq_task_min = 5;
/* The maxiimum number of tasks for each taskq. */
int		sctp_recvq_tq_task_max = 50;

/*  sctp_t/conn_t kmem cache */
struct kmem_cache	*sctp_conn_cache;

#define	SCTP_CONDEMNED(sctp)				\
	mutex_enter(&(sctp)->sctp_reflock);		\
	((sctp)->sctp_condemned = B_TRUE);		\
	mutex_exit(&(sctp)->sctp_reflock);

/* Link/unlink a sctp_t to/from the global list. */
#define	SCTP_LINK(sctp, sctps)				\
	mutex_enter(&(sctps)->sctps_g_lock);		\
	list_insert_tail(&sctps->sctps_g_list, (sctp));	\
	mutex_exit(&(sctps)->sctps_g_lock);

#define	SCTP_UNLINK(sctp, sctps)				\
	mutex_enter(&(sctps)->sctps_g_lock);		\
	ASSERT((sctp)->sctp_condemned);			\
	list_remove(&(sctps)->sctps_g_list, (sctp));	\
	mutex_exit(&(sctps)->sctps_g_lock);

/*
 * Hooks for Sun Cluster. On non-clustered nodes these will remain NULL.
 * PSARC/2005/602.
 */
void (*cl_sctp_listen)(sa_family_t, uchar_t *, uint_t, in_port_t) = NULL;
void (*cl_sctp_unlisten)(sa_family_t, uchar_t *, uint_t, in_port_t) = NULL;
void (*cl_sctp_connect)(sa_family_t, uchar_t *, uint_t, in_port_t,
    uchar_t *, uint_t, in_port_t, boolean_t, cl_sctp_handle_t) = NULL;
void (*cl_sctp_disconnect)(sa_family_t, cl_sctp_handle_t) = NULL;
void (*cl_sctp_assoc_change)(sa_family_t, uchar_t *, size_t, uint_t,
    uchar_t *, size_t, uint_t, int, cl_sctp_handle_t) = NULL;
void (*cl_sctp_check_addrs)(sa_family_t, in_port_t, uchar_t **, size_t,
    uint_t *, boolean_t) = NULL;
/*
 * Return the version number of the SCTP kernel interface.
 */
int
sctp_itf_ver(int cl_ver)
{
	if (cl_ver != SCTP_ITF_VER)
		return (-1);
	return (SCTP_ITF_VER);
}

/*
 * Called when we need a new sctp instantiation but don't really have a
 * new q to hang it off of. Copy the priv flag from the passed in structure.
 */
sctp_t *
sctp_create_eager(sctp_t *psctp)
{
	sctp_t	*sctp;
	mblk_t	*ack_mp, *hb_mp;
	conn_t	*connp, *pconnp;
	cred_t *credp;
	sctp_stack_t	*sctps = psctp->sctp_sctps;

	if ((connp = ipcl_conn_create(IPCL_SCTPCONN, KM_NOSLEEP,
	    sctps->sctps_netstack)) == NULL) {
		return (NULL);
	}

	connp->conn_ulp_labeled = is_system_labeled();

	sctp = CONN2SCTP(connp);
	sctp->sctp_sctps = sctps;

	if ((ack_mp = sctp_timer_alloc(sctp, sctp_ack_timer,
	    KM_NOSLEEP)) == NULL ||
	    (hb_mp = sctp_timer_alloc(sctp, sctp_heartbeat_timer,
	    KM_NOSLEEP)) == NULL) {
		if (ack_mp != NULL)
			freeb(ack_mp);
		sctp_conn_clear(connp);
		sctp->sctp_sctps = NULL;
		SCTP_G_Q_REFRELE(sctps);
		kmem_cache_free(sctp_conn_cache, connp);
		return (NULL);
	}

	sctp->sctp_ack_mp = ack_mp;
	sctp->sctp_heartbeat_mp = hb_mp;

	/* Inherit information from the "parent" */
	sctp->sctp_ipversion = psctp->sctp_ipversion;
	sctp->sctp_family = psctp->sctp_family;
	pconnp = psctp->sctp_connp;
	connp->conn_af_isv6 = pconnp->conn_af_isv6;
	connp->conn_pkt_isv6 = pconnp->conn_pkt_isv6;
	connp->conn_ipv6_v6only = pconnp->conn_ipv6_v6only;
	if (sctp_init_values(sctp, psctp, KM_NOSLEEP) != 0) {
		freeb(ack_mp);
		freeb(hb_mp);
		sctp_conn_clear(connp);
		sctp->sctp_sctps = NULL;
		SCTP_G_Q_REFRELE(sctps);
		kmem_cache_free(sctp_conn_cache, connp);
		return (NULL);
	}

	/*
	 * If the parent is multilevel, then we'll fix up the remote cred
	 * when we do sctp_accept_comm.
	 */
	if ((credp = pconnp->conn_cred) != NULL) {
		connp->conn_cred = credp;
		crhold(credp);
		/*
		 * If the caller has the process-wide flag set, then default to
		 * MAC exempt mode.  This allows read-down to unlabeled hosts.
		 */
		if (getpflags(NET_MAC_AWARE, credp) != 0)
			connp->conn_mac_exempt = B_TRUE;
	}

	connp->conn_allzones = pconnp->conn_allzones;
	connp->conn_zoneid = pconnp->conn_zoneid;

	sctp->sctp_mss = psctp->sctp_mss;
	sctp->sctp_detached = B_TRUE;
	/*
	 * Link to the global as soon as possible so that this sctp_t
	 * can be found.
	 */
	SCTP_LINK(sctp, sctps);

	return (sctp);
}

/*
 * We are dying for some reason.  Try to do it gracefully.
 */
void
sctp_clean_death(sctp_t *sctp, int err)
{
	ASSERT(sctp != NULL);
	ASSERT((sctp->sctp_family == AF_INET &&
	    sctp->sctp_ipversion == IPV4_VERSION) ||
	    (sctp->sctp_family == AF_INET6 &&
	    (sctp->sctp_ipversion == IPV4_VERSION ||
	    sctp->sctp_ipversion == IPV6_VERSION)));

	dprint(3, ("sctp_clean_death %p, state %d\n", (void *)sctp,
	    sctp->sctp_state));

	sctp->sctp_client_errno = err;
	/*
	 * Check to see if we need to notify upper layer.
	 */
	if ((sctp->sctp_state >= SCTPS_COOKIE_WAIT) &&
	    !SCTP_IS_DETACHED(sctp)) {
		if (sctp->sctp_xmit_head || sctp->sctp_xmit_unsent) {
			sctp_regift_xmitlist(sctp);
		}
		if (sctp->sctp_ulp_disconnected(sctp->sctp_ulpd, err)) {
			/*
			 * Socket is gone, detach.
			 */
			sctp->sctp_detached = B_TRUE;
			sctp->sctp_ulpd = NULL;
			bzero(&sctp->sctp_upcalls, sizeof (sctp_upcalls_t));
		}
	}

	/* Remove this sctp from all hashes. */
	sctp_closei_local(sctp);

	/*
	 * If the sctp_t is detached, we need to finish freeing up
	 * the resources.  At this point, ip_fanout_sctp() should have
	 * a hold on this sctp_t.  Some thread doing snmp stuff can
	 * have a hold.  And a taskq can also have a hold waiting to
	 * work.  sctp_unlink() the sctp_t from the global list so
	 * that no new thread can find it.  Then do a SCTP_REFRELE().
	 * The sctp_t will be freed after all those threads are done.
	 */
	if (SCTP_IS_DETACHED(sctp)) {
		SCTP_CONDEMNED(sctp);
		SCTP_REFRELE(sctp);
	}
}

/*
 * Called by upper layer when it wants to close this association.
 * Depending on the state of this assoication, we need to do
 * different things.
 *
 * If the state is below COOKIE_ECHOED or it is COOKIE_ECHOED but with
 * no sent data, just remove this sctp from all the hashes.  This
 * makes sure that all packets from the other end will go to the default
 * sctp handling.  The upper layer will then do a sctp_close() to clean
 * up.
 *
 * Otherwise, check and see if SO_LINGER is set.  If it is set, check
 * the value.  If the value is 0, consider this an abortive close.  Send
 * an ABORT message and kill the associatiion.
 *
 */
int
sctp_disconnect(sctp_t *sctp)
{
	int	error = 0;

	dprint(3, ("sctp_disconnect %p, state %d\n", (void *)sctp,
	    sctp->sctp_state));

	RUN_SCTP(sctp);

	switch (sctp->sctp_state) {
	case SCTPS_IDLE:
	case SCTPS_BOUND:
	case SCTPS_LISTEN:
		break;
	case SCTPS_COOKIE_WAIT:
	case SCTPS_COOKIE_ECHOED:
		/*
		 * Close during the connect 3-way handshake
		 * but here there may or may not be pending data
		 * already on queue. Process almost same as in
		 * the ESTABLISHED state.
		 */
		if (sctp->sctp_xmit_head == NULL &&
		    sctp->sctp_xmit_unsent == NULL) {
			break;
		}
		/* FALLTHRU */
	default:
		/*
		 * If SO_LINGER has set a zero linger time, abort the
		 * connection with a reset.
		 */
		if (sctp->sctp_linger && sctp->sctp_lingertime == 0) {
			sctp_user_abort(sctp, NULL, B_FALSE);
			break;
		}

		/*
		 * In there is unread data, send an ABORT
		 */
		if (sctp->sctp_rxqueued > 0 || sctp->sctp_irwnd >
		    sctp->sctp_rwnd) {
			sctp_user_abort(sctp, NULL, B_FALSE);
			break;
		}
		/*
		 * Transmit the shutdown before detaching the sctp_t.
		 * After sctp_detach returns this queue/perimeter
		 * no longer owns the sctp_t thus others can modify it.
		 */
		sctp_send_shutdown(sctp, 0);

		/* Pass gathered wisdom to IP for keeping */
		sctp_update_ire(sctp);

		/*
		 * If lingering on close then wait until the shutdown
		 * is complete, or the SO_LINGER time passes, or an
		 * ABORT is sent/received.  Note that sctp_disconnect()
		 * can be called more than once.  Make sure that only
		 * one thread waits.
		 */
		if (sctp->sctp_linger && sctp->sctp_lingertime > 0 &&
		    sctp->sctp_state >= SCTPS_ESTABLISHED &&
		    !sctp->sctp_lingering) {
			clock_t stoptime;	/* in ticks */
			clock_t ret;

			/*
			 * Process the sendq to send the SHUTDOWN out
			 * before waiting.
			 */
			sctp_process_sendq(sctp);

			sctp->sctp_lingering = 1;
			sctp->sctp_client_errno = 0;
			stoptime = lbolt + sctp->sctp_lingertime;

			mutex_enter(&sctp->sctp_lock);
			sctp->sctp_running = B_FALSE;
			while (sctp->sctp_state >= SCTPS_ESTABLISHED &&
			    sctp->sctp_client_errno == 0) {
				cv_broadcast(&sctp->sctp_cv);
				ret = cv_timedwait_sig(&sctp->sctp_cv,
				    &sctp->sctp_lock, stoptime);
				if (ret < 0) {
					/* Stoptime has reached. */
					sctp->sctp_client_errno = EWOULDBLOCK;
					break;
				} else if (ret == 0) {
					/* Got a signal. */
					break;
				}
			}
			error = sctp->sctp_client_errno;
			sctp->sctp_client_errno = 0;
			mutex_exit(&sctp->sctp_lock);
		}

		WAKE_SCTP(sctp);
		sctp_process_sendq(sctp);
		return (error);
	}


	/* Remove this sctp from all hashes so nobody can find it. */
	sctp_closei_local(sctp);
	WAKE_SCTP(sctp);
	return (error);
}

void
sctp_close(sctp_t *sctp)
{
	dprint(3, ("sctp_close %p, state %d\n", (void *)sctp,
	    sctp->sctp_state));

	RUN_SCTP(sctp);
	sctp->sctp_detached = 1;
	sctp->sctp_ulpd = NULL;
	bzero(&sctp->sctp_upcalls, sizeof (sctp_upcalls_t));
	bzero(&sctp->sctp_events, sizeof (sctp->sctp_events));

	/* If the graceful shutdown has not been completed, just return. */
	if (sctp->sctp_state != SCTPS_IDLE) {
		WAKE_SCTP(sctp);
		return;
	}

	/*
	 * Since sctp_t is in SCTPS_IDLE state, so the only thread which
	 * can have a hold on the sctp_t is doing snmp stuff.  Just do
	 * a SCTP_REFRELE() here after the SCTP_UNLINK().  It will
	 * be freed when the other thread is done.
	 */
	SCTP_CONDEMNED(sctp);
	WAKE_SCTP(sctp);
	SCTP_REFRELE(sctp);
}

/*
 * Unlink from global list and do the eager close.
 * Remove the refhold implicit in being on the global list.
 */
void
sctp_close_eager(sctp_t *sctp)
{
	SCTP_CONDEMNED(sctp);
	sctp_closei_local(sctp);
	SCTP_REFRELE(sctp);
}

/*
 * The sctp_t is going away. Remove it from all lists and set it
 * to SCTPS_IDLE. The caller has to remove it from the
 * global list. The freeing up of memory is deferred until
 * sctp_free(). This is needed since a thread in sctp_input() might have
 * done a SCTP_REFHOLD on this structure before it was removed from the
 * hashes.
 */
static void
sctp_closei_local(sctp_t *sctp)
{
	mblk_t	*mp;
	ire_t	*ire = NULL;
	conn_t	*connp = sctp->sctp_connp;

	/* Sanity check, don't do the same thing twice.  */
	if (connp->conn_state_flags & CONN_CLOSING) {
		ASSERT(sctp->sctp_state == SCTPS_IDLE);
		return;
	}

	/* Stop and free the timers */
	sctp_free_faddr_timers(sctp);
	if ((mp = sctp->sctp_heartbeat_mp) != NULL) {
		sctp_timer_free(mp);
		sctp->sctp_heartbeat_mp = NULL;
	}
	if ((mp = sctp->sctp_ack_mp) != NULL) {
		sctp_timer_free(mp);
		sctp->sctp_ack_mp = NULL;
	}

	/* Set the CONN_CLOSING flag so that IP will not cache IRE again. */
	mutex_enter(&connp->conn_lock);
	connp->conn_state_flags |= CONN_CLOSING;
	ire = connp->conn_ire_cache;
	connp->conn_ire_cache = NULL;
	mutex_exit(&connp->conn_lock);
	if (ire != NULL)
		IRE_REFRELE_NOTR(ire);

	/* Remove from all hashes. */
	sctp_bind_hash_remove(sctp);
	sctp_conn_hash_remove(sctp);
	sctp_listen_hash_remove(sctp);
	sctp->sctp_state = SCTPS_IDLE;

	/*
	 * Clean up the recvq as much as possible.  All those packets
	 * will be silently dropped as this sctp_t is now in idle state.
	 */
	mutex_enter(&sctp->sctp_recvq_lock);
	while ((mp = sctp->sctp_recvq) != NULL) {
		mblk_t *ipsec_mp;

		sctp->sctp_recvq = mp->b_next;
		mp->b_next = NULL;
		if ((ipsec_mp = mp->b_prev) != NULL) {
			freeb(ipsec_mp);
			mp->b_prev = NULL;
		}
		freemsg(mp);
	}
	mutex_exit(&sctp->sctp_recvq_lock);
}

/*
 * Free memory associated with the sctp/ip header template.
 */
static void
sctp_headers_free(sctp_t *sctp)
{
	if (sctp->sctp_iphc != NULL) {
		kmem_free(sctp->sctp_iphc, sctp->sctp_iphc_len);
		sctp->sctp_iphc = NULL;
		sctp->sctp_ipha = NULL;
		sctp->sctp_hdr_len = 0;
		sctp->sctp_ip_hdr_len = 0;
		sctp->sctp_iphc_len = 0;
		sctp->sctp_sctph = NULL;
		sctp->sctp_hdr_len = 0;
	}
	if (sctp->sctp_iphc6 != NULL) {
		kmem_free(sctp->sctp_iphc6, sctp->sctp_iphc6_len);
		sctp->sctp_iphc6 = NULL;
		sctp->sctp_ip6h = NULL;
		sctp->sctp_hdr6_len = 0;
		sctp->sctp_ip_hdr6_len = 0;
		sctp->sctp_iphc6_len = 0;
		sctp->sctp_sctph6 = NULL;
		sctp->sctp_hdr6_len = 0;
	}
}

static void
sctp_free_xmit_data(sctp_t *sctp)
{
	mblk_t	*ump = NULL;
	mblk_t	*nump;
	mblk_t	*mp;
	mblk_t	*nmp;

	sctp->sctp_xmit_unacked = NULL;
	ump = sctp->sctp_xmit_head;
	sctp->sctp_xmit_tail = sctp->sctp_xmit_head = NULL;
free_unsent:
	for (; ump != NULL; ump = nump) {
		for (mp = ump->b_cont; mp != NULL; mp = nmp) {
			nmp = mp->b_next;
			mp->b_next = NULL;
			mp->b_prev = NULL;
			freemsg(mp);
		}
		ASSERT(DB_REF(ump) == 1);
		nump = ump->b_next;
		ump->b_next = NULL;
		ump->b_prev = NULL;
		ump->b_cont = NULL;
		freeb(ump);
	}
	if ((ump = sctp->sctp_xmit_unsent) == NULL) {
		ASSERT(sctp->sctp_xmit_unsent_tail == NULL);
		return;
	}
	sctp->sctp_xmit_unsent = sctp->sctp_xmit_unsent_tail = NULL;
	goto free_unsent;
}

/*
 * Cleanup all the messages in the stream queue and the reassembly lists.
 * If 'free' is true, then delete the streams as well.
 */
void
sctp_instream_cleanup(sctp_t *sctp, boolean_t free)
{
	int	i;
	mblk_t	*mp;
	mblk_t	*mp1;

	if (sctp->sctp_instr != NULL) {
		/* walk thru and flush out anything remaining in the Q */
		for (i = 0; i < sctp->sctp_num_istr; i++) {
			mp = sctp->sctp_instr[i].istr_msgs;
			while (mp != NULL) {
				mp1 = mp->b_next;
				mp->b_next = mp->b_prev = NULL;
				freemsg(mp);
				mp = mp1;
			}
			sctp->sctp_instr[i].istr_msgs = NULL;
			sctp->sctp_instr[i].istr_nmsgs = 0;
			sctp_free_reass((sctp->sctp_instr) + i);
			sctp->sctp_instr[i].nextseq = 0;
		}
		if (free) {
			kmem_free(sctp->sctp_instr,
			    sizeof (*sctp->sctp_instr) * sctp->sctp_num_istr);
			sctp->sctp_instr = NULL;
			sctp->sctp_num_istr = 0;
		}
	}
	/* un-ordered fragments */
	if (sctp->sctp_uo_frags != NULL) {
		for (mp = sctp->sctp_uo_frags; mp != NULL; mp = mp1) {
			mp1 = mp->b_next;
			mp->b_next = mp->b_prev = NULL;
			freemsg(mp);
		}
	}
}

/*
 * Last reference to the sctp_t is gone. Free all memory associated with it.
 * Called from SCTP_REFRELE. Called inline in sctp_close()
 */
void
sctp_free(conn_t *connp)
{
	sctp_t *sctp = CONN2SCTP(connp);
	int		cnt;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	ASSERT(sctps != NULL);
	/* Unlink it from the global list */
	SCTP_UNLINK(sctp, sctps);

	ASSERT(connp->conn_ref == 0);
	ASSERT(connp->conn_ulp == IPPROTO_SCTP);
	ASSERT(!MUTEX_HELD(&sctp->sctp_reflock));
	ASSERT(sctp->sctp_refcnt == 0);

	ASSERT(sctp->sctp_ptpbhn == NULL && sctp->sctp_bind_hash == NULL);
	ASSERT(sctp->sctp_conn_hash_next == NULL &&
	    sctp->sctp_conn_hash_prev == NULL);


	/* Free up all the resources. */

	/* blow away sctp stream management */
	if (sctp->sctp_ostrcntrs != NULL) {
		kmem_free(sctp->sctp_ostrcntrs,
		    sizeof (uint16_t) * sctp->sctp_num_ostr);
		sctp->sctp_ostrcntrs = NULL;
	}
	sctp_instream_cleanup(sctp, B_TRUE);

	/* Remove all data transfer resources. */
	sctp->sctp_istr_nmsgs = 0;
	sctp->sctp_rxqueued = 0;
	sctp_free_xmit_data(sctp);
	sctp->sctp_unacked = 0;
	sctp->sctp_unsent = 0;
	if (sctp->sctp_cxmit_list != NULL)
		sctp_asconf_free_cxmit(sctp, NULL);

	sctp->sctp_lastdata = NULL;

	/* Clear out default xmit settings */
	sctp->sctp_def_stream = 0;
	sctp->sctp_def_flags = 0;
	sctp->sctp_def_ppid = 0;
	sctp->sctp_def_context = 0;
	sctp->sctp_def_timetolive = 0;

	if (sctp->sctp_sack_info != NULL) {
		sctp_free_set(sctp->sctp_sack_info);
		sctp->sctp_sack_info = NULL;
	}
	sctp->sctp_sack_gaps = 0;

	if (sctp->sctp_cookie_mp != NULL) {
		freemsg(sctp->sctp_cookie_mp);
		sctp->sctp_cookie_mp = NULL;
	}

	/* Remove all the address resources. */
	sctp_zap_addrs(sctp);
	for (cnt = 0; cnt < SCTP_IPIF_HASH; cnt++) {
		ASSERT(sctp->sctp_saddrs[cnt].ipif_count == 0);
		list_destroy(&sctp->sctp_saddrs[cnt].sctp_ipif_list);
	}

	ip6_pkt_free(&sctp->sctp_sticky_ipp);

	if (sctp->sctp_hopopts != NULL) {
		mi_free(sctp->sctp_hopopts);
		sctp->sctp_hopopts = NULL;
		sctp->sctp_hopoptslen = 0;
	}
	ASSERT(sctp->sctp_hopoptslen == 0);
	if (sctp->sctp_dstopts != NULL) {
		mi_free(sctp->sctp_dstopts);
		sctp->sctp_dstopts = NULL;
		sctp->sctp_dstoptslen = 0;
	}
	ASSERT(sctp->sctp_dstoptslen == 0);
	if (sctp->sctp_rtdstopts != NULL) {
		mi_free(sctp->sctp_rtdstopts);
		sctp->sctp_rtdstopts = NULL;
		sctp->sctp_rtdstoptslen = 0;
	}
	ASSERT(sctp->sctp_rtdstoptslen == 0);
	if (sctp->sctp_rthdr != NULL) {
		mi_free(sctp->sctp_rthdr);
		sctp->sctp_rthdr = NULL;
		sctp->sctp_rthdrlen = 0;
	}
	ASSERT(sctp->sctp_rthdrlen == 0);
	sctp_headers_free(sctp);

	sctp->sctp_shutdown_faddr = NULL;

	if (sctp->sctp_err_chunks != NULL) {
		freemsg(sctp->sctp_err_chunks);
		sctp->sctp_err_chunks = NULL;
		sctp->sctp_err_len = 0;
	}

	/* Clear all the bitfields. */
	bzero(&sctp->sctp_bits, sizeof (sctp->sctp_bits));

	/* It is time to update the global statistics. */
	UPDATE_MIB(&sctps->sctps_mib, sctpOutSCTPPkts, sctp->sctp_opkts);
	UPDATE_MIB(&sctps->sctps_mib, sctpOutCtrlChunks, sctp->sctp_obchunks);
	UPDATE_MIB(&sctps->sctps_mib, sctpOutOrderChunks, sctp->sctp_odchunks);
	UPDATE_MIB(&sctps->sctps_mib,
	    sctpOutUnorderChunks, sctp->sctp_oudchunks);
	UPDATE_MIB(&sctps->sctps_mib, sctpRetransChunks, sctp->sctp_rxtchunks);
	UPDATE_MIB(&sctps->sctps_mib, sctpInSCTPPkts, sctp->sctp_ipkts);
	UPDATE_MIB(&sctps->sctps_mib, sctpInCtrlChunks, sctp->sctp_ibchunks);
	UPDATE_MIB(&sctps->sctps_mib, sctpInOrderChunks, sctp->sctp_idchunks);
	UPDATE_MIB(&sctps->sctps_mib,
	    sctpInUnorderChunks, sctp->sctp_iudchunks);
	UPDATE_MIB(&sctps->sctps_mib, sctpFragUsrMsgs, sctp->sctp_fragdmsgs);
	UPDATE_MIB(&sctps->sctps_mib, sctpReasmUsrMsgs, sctp->sctp_reassmsgs);
	sctp->sctp_opkts = 0;
	sctp->sctp_obchunks = 0;
	sctp->sctp_odchunks = 0;
	sctp->sctp_oudchunks = 0;
	sctp->sctp_rxtchunks = 0;
	sctp->sctp_ipkts = 0;
	sctp->sctp_ibchunks = 0;
	sctp->sctp_idchunks = 0;
	sctp->sctp_iudchunks = 0;
	sctp->sctp_fragdmsgs = 0;
	sctp->sctp_reassmsgs = 0;

	sctp->sctp_autoclose = 0;
	sctp->sctp_tx_adaption_code = 0;

	sctp->sctp_v6label_len = 0;
	sctp->sctp_v4label_len = 0;

	/* Every sctp_t holds one reference on the default queue */
	sctp->sctp_sctps = NULL;
	SCTP_G_Q_REFRELE(sctps);

	sctp_conn_clear(connp);
	kmem_cache_free(sctp_conn_cache, connp);
}

/* Diagnostic routine used to return a string associated with the sctp state. */
char *
sctp_display(sctp_t *sctp, char *sup_buf)
{
	char	*buf;
	char	buf1[30];
	static char	priv_buf[INET6_ADDRSTRLEN * 2 + 80];
	char	*cp;

	if (sctp == NULL)
		return ("NULL_SCTP");

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
	    ntohs(sctp->sctp_lport), ntohs(sctp->sctp_fport), cp);

	return (buf);
}

/*
 * Initialize protocol control block. If a parent exists, inherit
 * all values set through setsockopt().
 */
static int
sctp_init_values(sctp_t *sctp, sctp_t *psctp, int sleep)
{
	int	err;
	int	cnt;
	sctp_stack_t	*sctps = sctp->sctp_sctps;
	conn_t 	*connp, *pconnp;

	ASSERT((sctp->sctp_family == AF_INET &&
	    sctp->sctp_ipversion == IPV4_VERSION) ||
	    (sctp->sctp_family == AF_INET6 &&
	    (sctp->sctp_ipversion == IPV4_VERSION ||
	    sctp->sctp_ipversion == IPV6_VERSION)));

	sctp->sctp_nsaddrs = 0;
	for (cnt = 0; cnt < SCTP_IPIF_HASH; cnt++) {
		sctp->sctp_saddrs[cnt].ipif_count = 0;
		list_create(&sctp->sctp_saddrs[cnt].sctp_ipif_list,
		    sizeof (sctp_saddr_ipif_t), offsetof(sctp_saddr_ipif_t,
		    saddr_ipif));
	}
	sctp->sctp_ports = 0;
	sctp->sctp_running = B_FALSE;
	sctp->sctp_state = SCTPS_IDLE;

	sctp->sctp_refcnt = 1;

	sctp->sctp_strikes = 0;

	sctp->sctp_last_mtu_probe = lbolt64;
	sctp->sctp_mtu_probe_intvl = sctps->sctps_mtu_probe_interval;

	sctp->sctp_sack_gaps = 0;
	sctp->sctp_sack_toggle = 2;

	/* Only need to do the allocation if there is no "cached" one. */
	if (sctp->sctp_pad_mp == NULL) {
		if (sleep == KM_SLEEP) {
			sctp->sctp_pad_mp = allocb_wait(SCTP_ALIGN, BPRI_MED,
			    STR_NOSIG, NULL);
		} else {
			sctp->sctp_pad_mp = allocb(SCTP_ALIGN, BPRI_MED);
			if (sctp->sctp_pad_mp == NULL)
				return (ENOMEM);
		}
		bzero(sctp->sctp_pad_mp->b_rptr, SCTP_ALIGN);
	}

	if (psctp != NULL) {
		/*
		 * Inherit from parent
		 */
		sctp->sctp_iphc = kmem_zalloc(psctp->sctp_iphc_len, sleep);
		if (sctp->sctp_iphc == NULL) {
			sctp->sctp_iphc_len = 0;
			err = ENOMEM;
			goto failure;
		}
		sctp->sctp_iphc_len = psctp->sctp_iphc_len;
		sctp->sctp_hdr_len = psctp->sctp_hdr_len;

		sctp->sctp_iphc6 = kmem_zalloc(psctp->sctp_iphc6_len, sleep);
		if (sctp->sctp_iphc6 == NULL) {
			sctp->sctp_iphc6_len = 0;
			err = ENOMEM;
			goto failure;
		}
		sctp->sctp_iphc6_len = psctp->sctp_iphc6_len;
		sctp->sctp_hdr6_len = psctp->sctp_hdr6_len;

		sctp->sctp_ip_hdr_len = psctp->sctp_ip_hdr_len;
		sctp->sctp_ip_hdr6_len = psctp->sctp_ip_hdr6_len;

		/*
		 * Copy the IP+SCTP header templates from listener
		 */
		bcopy(psctp->sctp_iphc, sctp->sctp_iphc,
		    psctp->sctp_hdr_len);
		sctp->sctp_ipha = (ipha_t *)sctp->sctp_iphc;
		sctp->sctp_sctph = (sctp_hdr_t *)(sctp->sctp_iphc +
		    sctp->sctp_ip_hdr_len);

		bcopy(psctp->sctp_iphc6, sctp->sctp_iphc6,
		    psctp->sctp_hdr6_len);
		if (((ip6i_t *)(sctp->sctp_iphc6))->ip6i_nxt == IPPROTO_RAW) {
			sctp->sctp_ip6h = (ip6_t *)(sctp->sctp_iphc6 +
			    sizeof (ip6i_t));
		} else {
			sctp->sctp_ip6h = (ip6_t *)sctp->sctp_iphc6;
		}
		sctp->sctp_sctph6 = (sctp_hdr_t *)(sctp->sctp_iphc6 +
		    sctp->sctp_ip_hdr6_len);

		sctp->sctp_cookie_lifetime = psctp->sctp_cookie_lifetime;
		sctp->sctp_xmit_lowater = psctp->sctp_xmit_lowater;
		sctp->sctp_xmit_hiwater = psctp->sctp_xmit_hiwater;
		sctp->sctp_cwnd_max = psctp->sctp_cwnd_max;
		sctp->sctp_rwnd = psctp->sctp_rwnd;
		sctp->sctp_irwnd = psctp->sctp_rwnd;
		sctp->sctp_pd_point = psctp->sctp_pd_point;
		sctp->sctp_rto_max = psctp->sctp_rto_max;
		sctp->sctp_init_rto_max = psctp->sctp_init_rto_max;
		sctp->sctp_rto_min = psctp->sctp_rto_min;
		sctp->sctp_rto_initial = psctp->sctp_rto_initial;
		sctp->sctp_pa_max_rxt = psctp->sctp_pa_max_rxt;
		sctp->sctp_pp_max_rxt = psctp->sctp_pp_max_rxt;
		sctp->sctp_max_init_rxt = psctp->sctp_max_init_rxt;

		sctp->sctp_def_stream = psctp->sctp_def_stream;
		sctp->sctp_def_flags = psctp->sctp_def_flags;
		sctp->sctp_def_ppid = psctp->sctp_def_ppid;
		sctp->sctp_def_context = psctp->sctp_def_context;
		sctp->sctp_def_timetolive = psctp->sctp_def_timetolive;

		sctp->sctp_num_istr = psctp->sctp_num_istr;
		sctp->sctp_num_ostr = psctp->sctp_num_ostr;

		sctp->sctp_hb_interval = psctp->sctp_hb_interval;
		sctp->sctp_autoclose = psctp->sctp_autoclose;
		sctp->sctp_tx_adaption_code = psctp->sctp_tx_adaption_code;

		/* xxx should be a better way to copy these flags xxx */
		sctp->sctp_debug = psctp->sctp_debug;
		sctp->sctp_bound_to_all = psctp->sctp_bound_to_all;
		sctp->sctp_cansleep = psctp->sctp_cansleep;
		sctp->sctp_send_adaption = psctp->sctp_send_adaption;
		sctp->sctp_ndelay = psctp->sctp_ndelay;
		sctp->sctp_events = psctp->sctp_events;
		sctp->sctp_ipv6_recvancillary = psctp->sctp_ipv6_recvancillary;

		/* Copy IP-layer options */
		connp = sctp->sctp_connp;
		pconnp = psctp->sctp_connp;

		connp->conn_broadcast = pconnp->conn_broadcast;
		connp->conn_loopback = pconnp->conn_loopback;
		connp->conn_dontroute = pconnp->conn_dontroute;
		connp->conn_reuseaddr = pconnp->conn_reuseaddr;

	} else {
		/*
		 * Initialize the header template
		 */
		if ((err = sctp_header_init_ipv4(sctp, sleep)) != 0) {
			goto failure;
		}
		if ((err = sctp_header_init_ipv6(sctp, sleep)) != 0) {
			goto failure;
		}

		/*
		 * Set to system defaults
		 */
		sctp->sctp_cookie_lifetime =
		    MSEC_TO_TICK(sctps->sctps_cookie_life);
		sctp->sctp_xmit_lowater = sctps->sctps_xmit_lowat;
		sctp->sctp_xmit_hiwater = sctps->sctps_xmit_hiwat;
		sctp->sctp_cwnd_max = sctps->sctps_cwnd_max_;
		sctp->sctp_rwnd = sctps->sctps_recv_hiwat;
		sctp->sctp_irwnd = sctp->sctp_rwnd;
		sctp->sctp_pd_point = sctp->sctp_rwnd;
		sctp->sctp_rto_max = MSEC_TO_TICK(sctps->sctps_rto_maxg);
		sctp->sctp_init_rto_max = sctp->sctp_rto_max;
		sctp->sctp_rto_min = MSEC_TO_TICK(sctps->sctps_rto_ming);
		sctp->sctp_rto_initial = MSEC_TO_TICK(
		    sctps->sctps_rto_initialg);
		sctp->sctp_pa_max_rxt = sctps->sctps_pa_max_retr;
		sctp->sctp_pp_max_rxt = sctps->sctps_pp_max_retr;
		sctp->sctp_max_init_rxt = sctps->sctps_max_init_retr;

		sctp->sctp_num_istr = sctps->sctps_max_in_streams;
		sctp->sctp_num_ostr = sctps->sctps_initial_out_streams;

		sctp->sctp_hb_interval =
		    MSEC_TO_TICK(sctps->sctps_heartbeat_interval);
	}
	sctp->sctp_understands_asconf = B_TRUE;
	sctp->sctp_understands_addip = B_TRUE;
	sctp->sctp_prsctp_aware = B_FALSE;

	sctp->sctp_connp->conn_ref = 1;
	sctp->sctp_connp->conn_fully_bound = B_FALSE;

	sctp->sctp_prsctpdrop = 0;
	sctp->sctp_msgcount = 0;

	return (0);

failure:
	if (sctp->sctp_iphc != NULL) {
		kmem_free(sctp->sctp_iphc, sctp->sctp_iphc_len);
		sctp->sctp_iphc = NULL;
	}
	if (sctp->sctp_iphc6 != NULL) {
		kmem_free(sctp->sctp_iphc6, sctp->sctp_iphc6_len);
		sctp->sctp_iphc6 = NULL;
	}
	return (err);
}

/*
 * Extracts the init tag from an INIT chunk and checks if it matches
 * the sctp's verification tag. Returns 0 if it doesn't match, 1 if
 * it does.
 */
static boolean_t
sctp_icmp_verf(sctp_t *sctp, sctp_hdr_t *sh, mblk_t *mp)
{
	sctp_chunk_hdr_t *sch;
	uint32_t verf, *vp;

	sch = (sctp_chunk_hdr_t *)(sh + 1);
	vp = (uint32_t *)(sch + 1);

	/* Need at least the data chunk hdr and the first 4 bytes of INIT */
	if ((unsigned char *)(vp + 1) > mp->b_wptr) {
		return (B_FALSE);
	}

	bcopy(vp, &verf, sizeof (verf));

	if (verf == sctp->sctp_lvtag) {
		return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * sctp_icmp_error is called by sctp_input() to process ICMP error messages
 * passed up by IP.  The queue is the default queue.  We need to find a sctp_t
 * that corresponds to the returned datagram.  Passes the message back in on
 * the correct queue once it has located the connection.
 * Assumes that IP has pulled up everything up to and including
 * the ICMP header.
 */
void
sctp_icmp_error(sctp_t *sctp, mblk_t *mp)
{
	icmph_t *icmph;
	ipha_t	*ipha;
	int	iph_hdr_length;
	sctp_hdr_t *sctph;
	mblk_t *first_mp;
	uint32_t new_mtu;
	in6_addr_t dst;
	sctp_faddr_t *fp;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	dprint(1, ("sctp_icmp_error: sctp=%p, mp=%p\n", (void *)sctp,
	    (void *)mp));

	first_mp = mp;

	ipha = (ipha_t *)mp->b_rptr;
	if (IPH_HDR_VERSION(ipha) != IPV4_VERSION) {
		ASSERT(IPH_HDR_VERSION(ipha) == IPV6_VERSION);
		sctp_icmp_error_ipv6(sctp, first_mp);
		return;
	}

	iph_hdr_length = IPH_HDR_LENGTH(ipha);
	icmph = (icmph_t *)&mp->b_rptr[iph_hdr_length];
	ipha = (ipha_t *)&icmph[1];
	iph_hdr_length = IPH_HDR_LENGTH(ipha);
	sctph = (sctp_hdr_t *)((char *)ipha + iph_hdr_length);
	if ((uchar_t *)(sctph + 1) >= mp->b_wptr) {
		/* not enough data for SCTP header */
		freemsg(first_mp);
		return;
	}

	switch (icmph->icmph_type) {
	case ICMP_DEST_UNREACHABLE:
		switch (icmph->icmph_code) {
		case ICMP_FRAGMENTATION_NEEDED:
			/*
			 * Reduce the MSS based on the new MTU.  This will
			 * eliminate any fragmentation locally.
			 * N.B.  There may well be some funny side-effects on
			 * the local send policy and the remote receive policy.
			 * Pending further research, we provide
			 * sctp_ignore_path_mtu just in case this proves
			 * disastrous somewhere.
			 *
			 * After updating the MSS, retransmit part of the
			 * dropped segment using the new mss by calling
			 * sctp_wput_slow().  Need to adjust all those
			 * params to make sure sctp_wput_slow() work properly.
			 */
			if (sctps->sctps_ignore_path_mtu)
				break;

			/* find the offending faddr */
			IN6_IPADDR_TO_V4MAPPED(ipha->ipha_dst, &dst);
			fp = sctp_lookup_faddr(sctp, &dst);
			if (fp == NULL) {
				break;
			}

			new_mtu = ntohs(icmph->icmph_du_mtu);

			if (new_mtu - sctp->sctp_hdr_len >= fp->sfa_pmss)
				break;

			/*
			 * Make sure that sfa_pmss is a multiple of
			 * SCTP_ALIGN.
			 */
			fp->sfa_pmss = (new_mtu - sctp->sctp_hdr_len) &
			    ~(SCTP_ALIGN - 1);
			fp->pmtu_discovered = 1;

			break;
		case ICMP_PORT_UNREACHABLE:
		case ICMP_PROTOCOL_UNREACHABLE:
			switch (sctp->sctp_state) {
			case SCTPS_COOKIE_WAIT:
			case SCTPS_COOKIE_ECHOED:
				/* make sure the verification tag matches */
				if (!sctp_icmp_verf(sctp, sctph, mp)) {
					break;
				}
				BUMP_MIB(&sctps->sctps_mib, sctpAborted);
				sctp_assoc_event(sctp, SCTP_CANT_STR_ASSOC, 0,
				    NULL);
				sctp_clean_death(sctp, ECONNREFUSED);
				break;
			}
			break;
		case ICMP_HOST_UNREACHABLE:
		case ICMP_NET_UNREACHABLE:
			/* Record the error in case we finally time out. */
			sctp->sctp_client_errno = (icmph->icmph_code ==
			    ICMP_HOST_UNREACHABLE) ? EHOSTUNREACH : ENETUNREACH;
			break;
		default:
			break;
		}
		break;
	case ICMP_SOURCE_QUENCH: {
		/* Reduce the sending rate as if we got a retransmit timeout */
		break;
	}
	}
	freemsg(first_mp);
}

/*
 * sctp_icmp_error_ipv6() is called by sctp_icmp_error() to process ICMPv6
 * error messages passed up by IP.
 * Assumes that IP has pulled up all the extension headers as well
 * as the ICMPv6 header.
 */
static void
sctp_icmp_error_ipv6(sctp_t *sctp, mblk_t *mp)
{
	icmp6_t *icmp6;
	ip6_t	*ip6h;
	uint16_t	iph_hdr_length;
	sctp_hdr_t *sctpha;
	uint8_t	*nexthdrp;
	uint32_t new_mtu;
	sctp_faddr_t *fp;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	ip6h = (ip6_t *)mp->b_rptr;
	iph_hdr_length = (ip6h->ip6_nxt != IPPROTO_SCTP) ?
	    ip_hdr_length_v6(mp, ip6h) : IPV6_HDR_LEN;

	icmp6 = (icmp6_t *)&mp->b_rptr[iph_hdr_length];
	ip6h = (ip6_t *)&icmp6[1];
	if (!ip_hdr_length_nexthdr_v6(mp, ip6h, &iph_hdr_length, &nexthdrp)) {
		freemsg(mp);
		return;
	}
	ASSERT(*nexthdrp == IPPROTO_SCTP);

	/* XXX need ifindex to find connection */
	sctpha = (sctp_hdr_t *)((char *)ip6h + iph_hdr_length);
	if ((uchar_t *)sctpha >= mp->b_wptr) {
		/* not enough data for SCTP header */
		freemsg(mp);
		return;
	}
	switch (icmp6->icmp6_type) {
	case ICMP6_PACKET_TOO_BIG:
		/*
		 * Reduce the MSS based on the new MTU.  This will
		 * eliminate any fragmentation locally.
		 * N.B.  There may well be some funny side-effects on
		 * the local send policy and the remote receive policy.
		 * Pending further research, we provide
		 * sctp_ignore_path_mtu just in case this proves
		 * disastrous somewhere.
		 *
		 * After updating the MSS, retransmit part of the
		 * dropped segment using the new mss by calling
		 * sctp_wput_slow().  Need to adjust all those
		 * params to make sure sctp_wput_slow() work properly.
		 */
		if (sctps->sctps_ignore_path_mtu)
			break;

		/* find the offending faddr */
		fp = sctp_lookup_faddr(sctp, &ip6h->ip6_dst);
		if (fp == NULL) {
			break;
		}

		new_mtu = ntohs(icmp6->icmp6_mtu);

		if (new_mtu - sctp->sctp_hdr6_len >= fp->sfa_pmss)
			break;

		/* Make sure that sfa_pmss is a multiple of SCTP_ALIGN. */
		fp->sfa_pmss = (new_mtu - sctp->sctp_hdr6_len) &
		    ~(SCTP_ALIGN - 1);
		fp->pmtu_discovered = 1;

		break;

	case ICMP6_DST_UNREACH:
		switch (icmp6->icmp6_code) {
		case ICMP6_DST_UNREACH_NOPORT:
			/* make sure the verification tag matches */
			if (!sctp_icmp_verf(sctp, sctpha, mp)) {
				break;
			}
			if (sctp->sctp_state == SCTPS_COOKIE_WAIT ||
			    sctp->sctp_state == SCTPS_COOKIE_ECHOED) {
				BUMP_MIB(&sctps->sctps_mib, sctpAborted);
				sctp_assoc_event(sctp, SCTP_CANT_STR_ASSOC, 0,
				    NULL);
				sctp_clean_death(sctp, ECONNREFUSED);
			}
			break;

		case ICMP6_DST_UNREACH_ADMIN:
		case ICMP6_DST_UNREACH_NOROUTE:
		case ICMP6_DST_UNREACH_NOTNEIGHBOR:
		case ICMP6_DST_UNREACH_ADDR:
			/* Record the error in case we finally time out. */
			sctp->sctp_client_errno = EHOSTUNREACH;
			break;
		default:
			break;
		}
		break;

	case ICMP6_PARAM_PROB:
		/* If this corresponds to an ICMP_PROTOCOL_UNREACHABLE */
		if (icmp6->icmp6_code == ICMP6_PARAMPROB_NEXTHEADER &&
		    (uchar_t *)ip6h + icmp6->icmp6_pptr ==
		    (uchar_t *)nexthdrp) {
			/* make sure the verification tag matches */
			if (!sctp_icmp_verf(sctp, sctpha, mp)) {
				break;
			}
			if (sctp->sctp_state == SCTPS_COOKIE_WAIT) {
				BUMP_MIB(&sctps->sctps_mib, sctpAborted);
				sctp_assoc_event(sctp, SCTP_CANT_STR_ASSOC, 0,
				    NULL);
				sctp_clean_death(sctp, ECONNREFUSED);
			}
			break;
		}
		break;

	case ICMP6_TIME_EXCEEDED:
	default:
		break;
	}
	freemsg(mp);
}

/*
 * Called by sockfs to create a new sctp instance.
 *
 * If parent pointer is passed in, inherit settings from it.
 */
sctp_t *
sctp_create(void *sctp_ulpd, sctp_t *parent, int family, int flags,
    const sctp_upcalls_t *sctp_upcalls, sctp_sockbuf_limits_t *sbl,
    cred_t *credp)
{
	sctp_t		*sctp, *psctp;
	conn_t		*sctp_connp;
	mblk_t		*ack_mp, *hb_mp;
	int		sleep = flags & SCTP_CAN_BLOCK ? KM_SLEEP : KM_NOSLEEP;
	zoneid_t	zoneid;
	sctp_stack_t	*sctps;

	/* User must supply a credential. */
	if (credp == NULL)
		return (NULL);

	psctp = (sctp_t *)parent;
	if (psctp != NULL) {
		sctps = psctp->sctp_sctps;
		/* Increase here to have common decrease at end */
		netstack_hold(sctps->sctps_netstack);
	} else {
		netstack_t *ns;

		ns = netstack_find_by_cred(credp);
		ASSERT(ns != NULL);
		sctps = ns->netstack_sctp;
		ASSERT(sctps != NULL);

		/*
		 * For exclusive stacks we set the zoneid to zero
		 * to make SCTP operate as if in the global zone.
		 */
		if (sctps->sctps_netstack->netstack_stackid !=
		    GLOBAL_NETSTACKID)
			zoneid = GLOBAL_ZONEID;
		else
			zoneid = crgetzoneid(credp);

		/*
		 * For stackid zero this is done from strplumb.c, but
		 * non-zero stackids are handled here.
		 */
		if (sctps->sctps_g_q == NULL &&
		    sctps->sctps_netstack->netstack_stackid !=
		    GLOBAL_NETSTACKID) {
			sctp_g_q_setup(sctps);
		}
	}
	if ((sctp_connp = ipcl_conn_create(IPCL_SCTPCONN, sleep,
	    sctps->sctps_netstack)) == NULL) {
		netstack_rele(sctps->sctps_netstack);
		SCTP_KSTAT(sctps, sctp_conn_create);
		return (NULL);
	}
	/*
	 * ipcl_conn_create did a netstack_hold. Undo the hold that was
	 * done at top of sctp_create.
	 */
	netstack_rele(sctps->sctps_netstack);
	sctp = CONN2SCTP(sctp_connp);
	sctp->sctp_sctps = sctps;

	sctp_connp->conn_ulp_labeled = is_system_labeled();
	if ((ack_mp = sctp_timer_alloc(sctp, sctp_ack_timer, sleep)) == NULL ||
	    (hb_mp = sctp_timer_alloc(sctp, sctp_heartbeat_timer,
	    sleep)) == NULL) {
		if (ack_mp != NULL)
			freeb(ack_mp);
		sctp_conn_clear(sctp_connp);
		sctp->sctp_sctps = NULL;
		SCTP_G_Q_REFRELE(sctps);
		kmem_cache_free(sctp_conn_cache, sctp_connp);
		return (NULL);
	}

	sctp->sctp_ack_mp = ack_mp;
	sctp->sctp_heartbeat_mp = hb_mp;

	switch (family) {
	case AF_INET6:
		sctp_connp->conn_af_isv6 = B_TRUE;
		sctp->sctp_ipversion = IPV6_VERSION;
		sctp->sctp_family = AF_INET6;
		break;

	case AF_INET:
		sctp_connp->conn_af_isv6 = B_FALSE;
		sctp_connp->conn_pkt_isv6 = B_FALSE;
		sctp->sctp_ipversion = IPV4_VERSION;
		sctp->sctp_family = AF_INET;
		break;
	default:
		ASSERT(0);
		break;
	}
	if (sctp_init_values(sctp, psctp, sleep) != 0) {
		freeb(ack_mp);
		freeb(hb_mp);
		sctp_conn_clear(sctp_connp);
		sctp->sctp_sctps = NULL;
		SCTP_G_Q_REFRELE(sctps);
		kmem_cache_free(sctp_conn_cache, sctp_connp);
		return (NULL);
	}
	sctp->sctp_cansleep = ((flags & SCTP_CAN_BLOCK) == SCTP_CAN_BLOCK);

	sctp->sctp_mss = sctps->sctps_initial_mtu - ((family == AF_INET6) ?
	    sctp->sctp_hdr6_len : sctp->sctp_hdr_len);

	if (psctp != NULL) {
		RUN_SCTP(psctp);
		/*
		 * Inherit local address list, local port. Parent is either
		 * in SCTPS_BOUND, or SCTPS_LISTEN state.
		 */
		ASSERT((psctp->sctp_state == SCTPS_BOUND) ||
		    (psctp->sctp_state == SCTPS_LISTEN));
		if (sctp_dup_saddrs(psctp, sctp, sleep)) {
			WAKE_SCTP(psctp);
			freeb(ack_mp);
			freeb(hb_mp);
			sctp_headers_free(sctp);
			sctp_conn_clear(sctp_connp);
			sctp->sctp_sctps = NULL;
			SCTP_G_Q_REFRELE(sctps);
			kmem_cache_free(sctp_conn_cache, sctp_connp);
			return (NULL);
		}

		/*
		 * If the parent is specified, it'll be immediatelly
		 * followed by sctp_connect(). So don't add this guy to
		 * bind hash.
		 */
		sctp->sctp_lport = psctp->sctp_lport;
		sctp->sctp_state = SCTPS_BOUND;
		sctp->sctp_allzones = psctp->sctp_allzones;
		sctp->sctp_zoneid = psctp->sctp_zoneid;
		WAKE_SCTP(psctp);
	} else {
		sctp->sctp_zoneid = zoneid;
	}

	sctp_connp->conn_cred = credp;
	crhold(credp);

	/*
	 * If the caller has the process-wide flag set, then default to MAC
	 * exempt mode.  This allows read-down to unlabeled hosts.
	 */
	if (getpflags(NET_MAC_AWARE, credp) != 0)
		sctp_connp->conn_mac_exempt = B_TRUE;

	/* Initialize SCTP instance values,  our verf tag must never be 0 */
	(void) random_get_pseudo_bytes((uint8_t *)&sctp->sctp_lvtag,
	    sizeof (sctp->sctp_lvtag));
	if (sctp->sctp_lvtag == 0)
		sctp->sctp_lvtag = (uint32_t)gethrtime();
	ASSERT(sctp->sctp_lvtag != 0);

	sctp->sctp_ltsn = sctp->sctp_lvtag + 1;
	sctp->sctp_lcsn = sctp->sctp_ltsn;
	sctp->sctp_recovery_tsn = sctp->sctp_lastack_rxd = sctp->sctp_ltsn - 1;
	sctp->sctp_adv_pap = sctp->sctp_lastack_rxd;

	/* Information required by upper layer */
	if (sctp_ulpd != NULL) {
		sctp->sctp_ulpd = sctp_ulpd;

		ASSERT(sctp_upcalls != NULL);
		bcopy(sctp_upcalls, &sctp->sctp_upcalls,
		    sizeof (sctp_upcalls_t));
		ASSERT(sbl != NULL);
		/* Fill in the socket buffer limits for sctpsockfs */
		sbl->sbl_txlowat = sctp->sctp_xmit_lowater;
		sbl->sbl_txbuf = sctp->sctp_xmit_hiwater;
		sbl->sbl_rxbuf = sctp->sctp_rwnd;
		sbl->sbl_rxlowat = SCTP_RECV_LOWATER;
	}
	/* If no sctp_ulpd, must be creating the default sctp */
	ASSERT(sctp_ulpd != NULL || sctps->sctps_gsctp == NULL);

	/* Insert this in the global list. */
	SCTP_LINK(sctp, sctps);

	return (sctp);
}

/*
 * Make sure we wait until the default queue is setup, yet allow
 * sctp_g_q_create() to open a SCTP stream.
 * We need to allow sctp_g_q_create() do do an open
 * of sctp, hence we compare curhread.
 * All others have to wait until the sctps_g_q has been
 * setup.
 */
void
sctp_g_q_setup(sctp_stack_t *sctps)
{
	mutex_enter(&sctps->sctps_g_q_lock);
	if (sctps->sctps_g_q != NULL) {
		mutex_exit(&sctps->sctps_g_q_lock);
		return;
	}
	if (sctps->sctps_g_q_creator == NULL) {
		/* This thread will set it up */
		sctps->sctps_g_q_creator = curthread;
		mutex_exit(&sctps->sctps_g_q_lock);
		sctp_g_q_create(sctps);
		mutex_enter(&sctps->sctps_g_q_lock);
		ASSERT(sctps->sctps_g_q_creator == curthread);
		sctps->sctps_g_q_creator = NULL;
		cv_signal(&sctps->sctps_g_q_cv);
		ASSERT(sctps->sctps_g_q != NULL);
		mutex_exit(&sctps->sctps_g_q_lock);
		return;
	}
	/* Everybody but the creator has to wait */
	if (sctps->sctps_g_q_creator != curthread) {
		while (sctps->sctps_g_q == NULL)
			cv_wait(&sctps->sctps_g_q_cv, &sctps->sctps_g_q_lock);
	}
	mutex_exit(&sctps->sctps_g_q_lock);
}

#define	IP	"ip"

#define	SCTP6DEV		"/devices/pseudo/sctp6@0:sctp6"

/*
 * Create a default sctp queue here instead of in strplumb
 */
void
sctp_g_q_create(sctp_stack_t *sctps)
{
	int error;
	ldi_handle_t	lh = NULL;
	ldi_ident_t	li = NULL;
	int		rval;
	cred_t		*cr;
	major_t IP_MAJ;

#ifdef NS_DEBUG
	(void) printf("sctp_g_q_create()for stack %d\n",
	    sctps->sctps_netstack->netstack_stackid);
#endif

	IP_MAJ = ddi_name_to_major(IP);

	ASSERT(sctps->sctps_g_q_creator == curthread);

	error = ldi_ident_from_major(IP_MAJ, &li);
	if (error) {
#ifdef DEBUG
		printf("sctp_g_q_create: lyr ident get failed error %d\n",
		    error);
#endif
		return;
	}

	cr = zone_get_kcred(netstackid_to_zoneid(
	    sctps->sctps_netstack->netstack_stackid));
	ASSERT(cr != NULL);
	/*
	 * We set the sctp default queue to IPv6 because IPv4 falls
	 * back to IPv6 when it can't find a client, but
	 * IPv6 does not fall back to IPv4.
	 */
	error = ldi_open_by_name(SCTP6DEV, FREAD|FWRITE, cr, &lh, li);
	if (error) {
#ifdef DEBUG
		printf("sctp_g_q_create: open of SCTP6DEV failed error %d\n",
		    error);
#endif
		goto out;
	}

	/*
	 * This ioctl causes the sctp framework to cache a pointer to
	 * this stream, so we don't want to close the stream after
	 * this operation.
	 * Use the kernel credentials that are for the zone we're in.
	 */
	error = ldi_ioctl(lh, SCTP_IOC_DEFAULT_Q,
	    (intptr_t)0, FKIOCTL, cr, &rval);
	if (error) {
#ifdef DEBUG
		printf("sctp_g_q_create: ioctl SCTP_IOC_DEFAULT_Q failed "
		    "error %d\n", error);
#endif
		goto out;
	}
	sctps->sctps_g_q_lh = lh;	/* For sctp_g_q_inactive */
	lh = NULL;
out:
	/* Close layered handles */
	if (li)
		ldi_ident_release(li);
	/* Keep cred around until _inactive needs it */
	sctps->sctps_g_q_cr = cr;
}

/*
 * Remove the sctp_default queue so that new connections will not find it.
 * SCTP uses sctp_g_q for all transmission, so all sctp'ts implicitly
 * refer to it. Hence have each one have a reference on sctp_g_q_ref!
 *
 * We decrement the refcnt added in sctp_g_q_create. Once all the
 * sctp_t's which use the default go away, sctp_g_q_close will be called
 * and close the sctp_g_q. Once sctp_g_q is closed, sctp_close() will drop the
 * last reference count on the stack by calling netstack_rele().
 */
void
sctp_g_q_destroy(sctp_stack_t *sctps)
{
	if (sctps->sctps_g_q == NULL) {
		return;	/* Nothing to cleanup */
	}
	/*
	 * Keep sctps_g_q and sctps_gsctp until the last reference has
	 * dropped, since the output is always done using those.
	 * Need to decrement twice to take sctp_g_q_create and
	 * the gsctp reference into account so that sctp_g_q_inactive is called
	 * when all but the default queue remains.
	 */
#ifdef NS_DEBUG
	(void) printf("sctp_g_q_destroy: ref %d\n",
	    sctps->sctps_g_q_ref);
#endif
	SCTP_G_Q_REFRELE(sctps);
}

/*
 * Called when last user (could be sctp_g_q_destroy) drops reference count
 * using SCTP_G_Q_REFRELE.
 * Run by sctp_q_q_inactive using a taskq.
 */
static void
sctp_g_q_close(void *arg)
{
	sctp_stack_t *sctps = arg;
	int error;
	ldi_handle_t	lh = NULL;
	ldi_ident_t	li = NULL;
	cred_t		*cr;
	major_t IP_MAJ;

	IP_MAJ = ddi_name_to_major(IP);

	lh = sctps->sctps_g_q_lh;
	if (lh == NULL)
		return;	/* Nothing to cleanup */

	error = ldi_ident_from_major(IP_MAJ, &li);
	if (error) {
#ifdef NS_DEBUG
		printf("sctp_g_q_inactive: lyr ident get failed error %d\n",
		    error);
#endif
		return;
	}

	cr = sctps->sctps_g_q_cr;
	sctps->sctps_g_q_cr = NULL;
	ASSERT(cr != NULL);

	/*
	 * Make sure we can break the recursion when sctp_close decrements
	 * the reference count causing g_q_inactive to be called again.
	 */
	sctps->sctps_g_q_lh = NULL;

	/* close the default queue */
	(void) ldi_close(lh, FREAD|FWRITE, cr);

	/* Close layered handles */
	ldi_ident_release(li);
	crfree(cr);

	ASSERT(sctps->sctps_g_q != NULL);
	sctps->sctps_g_q = NULL;
	/*
	 * Now free sctps_gsctp.
	 */
	ASSERT(sctps->sctps_gsctp != NULL);
	sctp_closei_local(sctps->sctps_gsctp);
	SCTP_CONDEMNED(sctps->sctps_gsctp);
	SCTP_REFRELE(sctps->sctps_gsctp);
	sctps->sctps_gsctp = NULL;
}

/*
 * Called when last sctp_t drops reference count using SCTP_G_Q_REFRELE.
 *
 * Have to ensure that the ldi routines are not used by an
 * interrupt thread by using a taskq.
 */
void
sctp_g_q_inactive(sctp_stack_t *sctps)
{
	if (sctps->sctps_g_q_lh == NULL)
		return;	/* Nothing to cleanup */

	ASSERT(sctps->sctps_g_q_ref == 0);
	SCTP_G_Q_REFHOLD(sctps); /* Compensate for what g_q_destroy did */

	if (servicing_interrupt()) {
		(void) taskq_dispatch(sctp_taskq, sctp_g_q_close,
		    (void *) sctps, TQ_SLEEP);
	} else {
		sctp_g_q_close(sctps);
	}
}

/* Run at module load time */
void
sctp_ddi_g_init(void)
{
	/* Create sctp_t/conn_t cache */
	sctp_conn_cache_init();

	/* Create the faddr cache */
	sctp_faddr_init();

	/* Create the sets cache */
	sctp_sets_init();

	/* Create the PR-SCTP sets cache */
	sctp_ftsn_sets_init();

	/* Initialize tables used for CRC calculation */
	sctp_crc32_init();

	sctp_taskq = taskq_create("sctp_taskq", 1, minclsyspri, 1, 1,
	    TASKQ_PREPOPULATE);

	/*
	 * We want to be informed each time a stack is created or
	 * destroyed in the kernel, so we can maintain the
	 * set of sctp_stack_t's.
	 */
	netstack_register(NS_SCTP, sctp_stack_init, sctp_stack_shutdown,
	    sctp_stack_fini);
}

static void *
sctp_stack_init(netstackid_t stackid, netstack_t *ns)
{
	sctp_stack_t	*sctps;

	sctps = kmem_zalloc(sizeof (*sctps), KM_SLEEP);
	sctps->sctps_netstack = ns;

	/* Initialize locks */
	mutex_init(&sctps->sctps_g_q_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&sctps->sctps_g_q_cv, NULL, CV_DEFAULT, NULL);
	mutex_init(&sctps->sctps_g_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&sctps->sctps_epriv_port_lock, NULL, MUTEX_DEFAULT, NULL);
	sctps->sctps_g_num_epriv_ports = SCTP_NUM_EPRIV_PORTS;
	sctps->sctps_g_epriv_ports[0] = 2049;
	sctps->sctps_g_epriv_ports[1] = 4045;

	/* Initialize SCTP hash arrays. */
	sctp_hash_init(sctps);

	if (!sctp_nd_init(sctps)) {
		sctp_nd_free(sctps);
	}

	/* Initialize the recvq taskq. */
	sctp_rq_tq_init(sctps);

	/* saddr init */
	sctp_saddr_init(sctps);

	/* Global SCTP PCB list. */
	list_create(&sctps->sctps_g_list, sizeof (sctp_t),
	    offsetof(sctp_t, sctp_list));

	/* Initialize sctp kernel stats. */
	sctps->sctps_mibkp = sctp_kstat_init(stackid);
	sctps->sctps_kstat =
	    sctp_kstat2_init(stackid, &sctps->sctps_statistics);

	return (sctps);
}

/*
 * Called when the module is about to be unloaded.
 */
void
sctp_ddi_g_destroy(void)
{
	/* Destroy sctp_t/conn_t caches */
	sctp_conn_cache_fini();

	/* Destroy the faddr cache */
	sctp_faddr_fini();

	/* Destroy the sets cache */
	sctp_sets_fini();

	/* Destroy the PR-SCTP sets cache */
	sctp_ftsn_sets_fini();

	netstack_unregister(NS_SCTP);
	taskq_destroy(sctp_taskq);
}

/*
 * Shut down the SCTP stack instance.
 */
/* ARGSUSED */
static void
sctp_stack_shutdown(netstackid_t stackid, void *arg)
{
	sctp_stack_t *sctps = (sctp_stack_t *)arg;

	sctp_g_q_destroy(sctps);
}

/*
 * Free the SCTP stack instance.
 */
static void
sctp_stack_fini(netstackid_t stackid, void *arg)
{
	sctp_stack_t *sctps = (sctp_stack_t *)arg;

	sctp_nd_free(sctps);

	/* Destroy the recvq taskqs. */
	sctp_rq_tq_fini(sctps);

	/* Destroy saddr  */
	sctp_saddr_fini(sctps);

	/* Global SCTP PCB list. */
	list_destroy(&sctps->sctps_g_list);

	/* Destroy SCTP hash arrays. */
	sctp_hash_destroy(sctps);

	/* Destroy SCTP kernel stats. */
	sctp_kstat2_fini(stackid, sctps->sctps_kstat);
	sctps->sctps_kstat = NULL;
	bzero(&sctps->sctps_statistics, sizeof (sctps->sctps_statistics));

	sctp_kstat_fini(stackid, sctps->sctps_mibkp);
	sctps->sctps_mibkp = NULL;

	mutex_destroy(&sctps->sctps_g_lock);
	mutex_destroy(&sctps->sctps_epriv_port_lock);
	mutex_destroy(&sctps->sctps_g_q_lock);
	cv_destroy(&sctps->sctps_g_q_cv);

	kmem_free(sctps, sizeof (*sctps));
}

void
sctp_display_all(sctp_stack_t *sctps)
{
	sctp_t *sctp_walker;

	mutex_enter(&sctps->sctps_g_lock);
	for (sctp_walker = sctps->sctps_gsctp; sctp_walker != NULL;
	    sctp_walker = (sctp_t *)list_next(&sctps->sctps_g_list,
	    sctp_walker)) {
		(void) sctp_display(sctp_walker, NULL);
	}
	mutex_exit(&sctps->sctps_g_lock);
}

static void
sctp_rq_tq_init(sctp_stack_t *sctps)
{
	sctps->sctps_recvq_tq_list_max_sz = 16;
	sctps->sctps_recvq_tq_list_cur_sz = 1;
	/*
	 * Initialize the recvq_tq_list and create the first recvq taskq.
	 * What to do if it fails?
	 */
	sctps->sctps_recvq_tq_list =
	    kmem_zalloc(sctps->sctps_recvq_tq_list_max_sz * sizeof (taskq_t *),
	    KM_SLEEP);
	sctps->sctps_recvq_tq_list[0] = taskq_create("sctp_def_recvq_taskq",
	    MIN(sctp_recvq_tq_thr_max, MAX(sctp_recvq_tq_thr_min, ncpus)),
	    minclsyspri, sctp_recvq_tq_task_min, sctp_recvq_tq_task_max,
	    TASKQ_PREPOPULATE);
	mutex_init(&sctps->sctps_rq_tq_lock, NULL, MUTEX_DEFAULT, NULL);
}

static void
sctp_rq_tq_fini(sctp_stack_t *sctps)
{
	int i;

	for (i = 0; i < sctps->sctps_recvq_tq_list_cur_sz; i++) {
		ASSERT(sctps->sctps_recvq_tq_list[i] != NULL);
		taskq_destroy(sctps->sctps_recvq_tq_list[i]);
	}
	kmem_free(sctps->sctps_recvq_tq_list,
	    sctps->sctps_recvq_tq_list_max_sz * sizeof (taskq_t *));
	sctps->sctps_recvq_tq_list = NULL;
}

/* Add another taskq for a new ill. */
void
sctp_inc_taskq(sctp_stack_t *sctps)
{
	taskq_t *tq;
	char tq_name[TASKQ_NAMELEN];

	mutex_enter(&sctps->sctps_rq_tq_lock);
	if (sctps->sctps_recvq_tq_list_cur_sz + 1 >
	    sctps->sctps_recvq_tq_list_max_sz) {
		mutex_exit(&sctps->sctps_rq_tq_lock);
		cmn_err(CE_NOTE, "Cannot create more SCTP recvq taskq");
		return;
	}

	(void) snprintf(tq_name, sizeof (tq_name), "sctp_recvq_taskq_%u",
	    sctps->sctps_recvq_tq_list_cur_sz);
	tq = taskq_create(tq_name,
	    MIN(sctp_recvq_tq_thr_max, MAX(sctp_recvq_tq_thr_min, ncpus)),
	    minclsyspri, sctp_recvq_tq_task_min, sctp_recvq_tq_task_max,
	    TASKQ_PREPOPULATE);
	if (tq == NULL) {
		mutex_exit(&sctps->sctps_rq_tq_lock);
		cmn_err(CE_NOTE, "SCTP recvq taskq creation failed");
		return;
	}
	ASSERT(sctps->sctps_recvq_tq_list[
	    sctps->sctps_recvq_tq_list_cur_sz] == NULL);
	sctps->sctps_recvq_tq_list[sctps->sctps_recvq_tq_list_cur_sz] = tq;
	atomic_add_32(&sctps->sctps_recvq_tq_list_cur_sz, 1);
	mutex_exit(&sctps->sctps_rq_tq_lock);
}

#ifdef DEBUG
uint32_t sendq_loop_cnt = 0;
uint32_t sendq_collision = 0;
uint32_t sendq_empty = 0;
#endif

void
sctp_add_sendq(sctp_t *sctp, mblk_t *mp)
{
	mutex_enter(&sctp->sctp_sendq_lock);
	if (sctp->sctp_sendq == NULL) {
		sctp->sctp_sendq = mp;
		sctp->sctp_sendq_tail = mp;
	} else {
		sctp->sctp_sendq_tail->b_next = mp;
		sctp->sctp_sendq_tail = mp;
	}
	mutex_exit(&sctp->sctp_sendq_lock);
}

void
sctp_process_sendq(sctp_t *sctp)
{
	mblk_t *mp;
#ifdef DEBUG
	uint32_t loop_cnt = 0;
#endif

	mutex_enter(&sctp->sctp_sendq_lock);
	if (sctp->sctp_sendq == NULL || sctp->sctp_sendq_sending) {
#ifdef DEBUG
		if (sctp->sctp_sendq == NULL)
			sendq_empty++;
		else
			sendq_collision++;
#endif
		mutex_exit(&sctp->sctp_sendq_lock);
		return;
	}
	sctp->sctp_sendq_sending = B_TRUE;

	/*
	 * Note that while we are in this loop, other thread can put
	 * new packets in the receive queue.  We may be looping for
	 * quite a while.  This is OK even for an interrupt thread.
	 * The reason is that SCTP should only able to send a limited
	 * number of packets out in a burst.  So the number of times
	 * we go through this loop should not be many.
	 */
	while ((mp = sctp->sctp_sendq) != NULL) {
		sctp->sctp_sendq = mp->b_next;
		ASSERT(sctp->sctp_connp->conn_ref > 0);
		mutex_exit(&sctp->sctp_sendq_lock);
		mp->b_next = NULL;
		CONN_INC_REF(sctp->sctp_connp);
		mp->b_flag |= MSGHASREF;
		/* If we don't have sctp_current, default to IPv4 */
		IP_PUT(mp, sctp->sctp_connp, sctp->sctp_current == NULL ?
		    B_TRUE : sctp->sctp_current->isv4);
		BUMP_LOCAL(sctp->sctp_opkts);
#ifdef DEBUG
		loop_cnt++;
#endif
		mutex_enter(&sctp->sctp_sendq_lock);
	}

	sctp->sctp_sendq_tail = NULL;
	sctp->sctp_sendq_sending = B_FALSE;
#ifdef DEBUG
	if (loop_cnt > sendq_loop_cnt)
		sendq_loop_cnt = loop_cnt;
#endif
	mutex_exit(&sctp->sctp_sendq_lock);
}

#ifdef DEBUG
uint32_t recvq_loop_cnt = 0;
uint32_t recvq_call = 0;
#endif

/*
 * Find the next recvq_tq to use.  This routine will go thru all the
 * taskqs until it can dispatch a job for the sctp.  If this fails,
 * it will create a new taskq and try it.
 */
static boolean_t
sctp_find_next_tq(sctp_t *sctp)
{
	int next_tq, try;
	taskq_t *tq;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	/*
	 * Note that since we don't hold a lock on sctp_rq_tq_lock for
	 * performance reason, recvq_ta_list_cur_sz can be changed during
	 * this loop.  The problem this will create is that the loop may
	 * not have tried all the recvq_tq.  This should be OK.
	 */
	next_tq = atomic_add_32_nv(&sctps->sctps_recvq_tq_list_cur, 1) %
	    sctps->sctps_recvq_tq_list_cur_sz;
	for (try = 0; try < sctps->sctps_recvq_tq_list_cur_sz; try++) {
		tq = sctps->sctps_recvq_tq_list[next_tq];
		if (taskq_dispatch(tq, sctp_process_recvq, sctp,
		    TQ_NOSLEEP) != NULL) {
			sctp->sctp_recvq_tq = tq;
			return (B_TRUE);
		}
		next_tq = (next_tq + 1) % sctps->sctps_recvq_tq_list_cur_sz;
	}

	/*
	 * Create one more taskq and try it.  Note that sctp_inc_taskq()
	 * may not have created another taskq if the number of recvq
	 * taskqs is at the maximum.  We are probably in a pretty bad
	 * shape if this actually happens...
	 */
	sctp_inc_taskq(sctps);
	tq = sctps->sctps_recvq_tq_list[sctps->sctps_recvq_tq_list_cur_sz - 1];
	if (taskq_dispatch(tq, sctp_process_recvq, sctp, TQ_NOSLEEP) != NULL) {
		sctp->sctp_recvq_tq = tq;
		return (B_TRUE);
	}
	SCTP_KSTAT(sctps, sctp_find_next_tq);
	return (B_FALSE);
}

/*
 * To add a message to the recvq.  Note that the sctp_timer_fire()
 * routine also uses this function to add the timer message to the
 * receive queue for later processing.  And it should be the only
 * caller of sctp_add_recvq() which sets the try_harder argument
 * to B_TRUE.
 *
 * If the try_harder argument is B_TRUE, this routine sctp_find_next_tq()
 * will try very hard to dispatch the task.  Refer to the comment
 * for that routine on how it does that.
 */
boolean_t
sctp_add_recvq(sctp_t *sctp, mblk_t *mp, boolean_t caller_hold_lock)
{
	if (!caller_hold_lock)
		mutex_enter(&sctp->sctp_recvq_lock);

	/* If the taskq dispatch has not been scheduled, do it now. */
	if (sctp->sctp_recvq_tq == NULL) {
		ASSERT(sctp->sctp_recvq == NULL);
		if (!sctp_find_next_tq(sctp)) {
			if (!caller_hold_lock)
				mutex_exit(&sctp->sctp_recvq_lock);
			return (B_FALSE);
		}
		/* Make sure the sctp_t will not go away. */
		SCTP_REFHOLD(sctp);
	}

	if (sctp->sctp_recvq == NULL) {
		sctp->sctp_recvq = mp;
		sctp->sctp_recvq_tail = mp;
	} else {
		sctp->sctp_recvq_tail->b_next = mp;
		sctp->sctp_recvq_tail = mp;
	}

	if (!caller_hold_lock)
		mutex_exit(&sctp->sctp_recvq_lock);
	return (B_TRUE);
}

static void
sctp_process_recvq(void *arg)
{
	sctp_t		*sctp = (sctp_t *)arg;
	mblk_t		*mp;
	mblk_t		*ipsec_mp;
#ifdef DEBUG
	uint32_t	loop_cnt = 0;
#endif

#ifdef	_BIG_ENDIAN
#define	IPVER(ip6h)	((((uint32_t *)ip6h)[0] >> 28) & 0x7)
#else
#define	IPVER(ip6h)	((((uint32_t *)ip6h)[0] >> 4) & 0x7)
#endif

	RUN_SCTP(sctp);
	mutex_enter(&sctp->sctp_recvq_lock);

#ifdef DEBUG
	recvq_call++;
#endif
	/*
	 * Note that while we are in this loop, other thread can put
	 * new packets in the receive queue.  We may be looping for
	 * quite a while.
	 */
	while ((mp = sctp->sctp_recvq) != NULL) {
		sctp->sctp_recvq = mp->b_next;
		mutex_exit(&sctp->sctp_recvq_lock);
		mp->b_next = NULL;
#ifdef DEBUG
		loop_cnt++;
#endif
		ipsec_mp = mp->b_prev;
		mp->b_prev = NULL;
		sctp_input_data(sctp, mp, ipsec_mp);

		mutex_enter(&sctp->sctp_recvq_lock);
	}

	sctp->sctp_recvq_tail = NULL;
	sctp->sctp_recvq_tq = NULL;

	mutex_exit(&sctp->sctp_recvq_lock);

	WAKE_SCTP(sctp);

	/* We may have sent something when processing the receive queue. */
	sctp_process_sendq(sctp);
#ifdef DEBUG
	if (loop_cnt > recvq_loop_cnt)
		recvq_loop_cnt = loop_cnt;
#endif
	/* Now it can go away. */
	SCTP_REFRELE(sctp);
}

/* ARGSUSED */
static int
sctp_conn_cache_constructor(void *buf, void *cdrarg, int kmflags)
{
	conn_t	*sctp_connp = (conn_t *)buf;
	sctp_t	*sctp = (sctp_t *)&sctp_connp[1];

	bzero(buf, (char *)&sctp[1] - (char *)buf);

	sctp->sctp_connp = sctp_connp;
	mutex_init(&sctp->sctp_reflock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&sctp->sctp_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&sctp->sctp_recvq_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&sctp->sctp_cv, NULL, CV_DEFAULT, NULL);
	mutex_init(&sctp->sctp_sendq_lock, NULL, MUTEX_DEFAULT, NULL);

	return (0);
}

/* ARGSUSED */
static void
sctp_conn_cache_destructor(void *buf, void *cdrarg)
{
	conn_t	*sctp_connp = (conn_t *)buf;
	sctp_t	*sctp = (sctp_t *)&sctp_connp[1];

	ASSERT(!MUTEX_HELD(&sctp->sctp_lock));
	ASSERT(!MUTEX_HELD(&sctp->sctp_reflock));
	ASSERT(!MUTEX_HELD(&sctp->sctp_recvq_lock));
	ASSERT(!MUTEX_HELD(&sctp->sctp_sendq_lock));
	ASSERT(!MUTEX_HELD(&sctp->sctp_connp->conn_lock));

	ASSERT(sctp->sctp_conn_hash_next == NULL);
	ASSERT(sctp->sctp_conn_hash_prev == NULL);
	ASSERT(sctp->sctp_listen_hash_next == NULL);
	ASSERT(sctp->sctp_listen_hash_prev == NULL);
	ASSERT(sctp->sctp_listen_tfp == NULL);
	ASSERT(sctp->sctp_conn_tfp == NULL);

	ASSERT(sctp->sctp_faddrs == NULL);
	ASSERT(sctp->sctp_nsaddrs == 0);

	ASSERT(sctp->sctp_ulpd == NULL);

	ASSERT(sctp->sctp_lastfaddr == NULL);
	ASSERT(sctp->sctp_primary == NULL);
	ASSERT(sctp->sctp_current == NULL);
	ASSERT(sctp->sctp_lastdata == NULL);

	ASSERT(sctp->sctp_xmit_head == NULL);
	ASSERT(sctp->sctp_xmit_tail == NULL);
	ASSERT(sctp->sctp_xmit_unsent == NULL);
	ASSERT(sctp->sctp_xmit_unsent_tail == NULL);

	ASSERT(sctp->sctp_ostrcntrs == NULL);

	ASSERT(sctp->sctp_sack_info == NULL);
	ASSERT(sctp->sctp_ack_mp == NULL);
	ASSERT(sctp->sctp_instr == NULL);

	ASSERT(sctp->sctp_iphc == NULL);
	ASSERT(sctp->sctp_iphc6 == NULL);
	ASSERT(sctp->sctp_ipha == NULL);
	ASSERT(sctp->sctp_ip6h == NULL);
	ASSERT(sctp->sctp_sctph == NULL);
	ASSERT(sctp->sctp_sctph6 == NULL);

	ASSERT(sctp->sctp_cookie_mp == NULL);

	ASSERT(sctp->sctp_refcnt == 0);
	ASSERT(sctp->sctp_timer_mp == NULL);
	ASSERT(sctp->sctp_connp->conn_ref == 0);
	ASSERT(sctp->sctp_heartbeat_mp == NULL);
	ASSERT(sctp->sctp_ptpbhn == NULL && sctp->sctp_bind_hash == NULL);

	ASSERT(sctp->sctp_shutdown_faddr == NULL);

	ASSERT(sctp->sctp_cxmit_list == NULL);

	ASSERT(sctp->sctp_recvq == NULL);
	ASSERT(sctp->sctp_recvq_tail == NULL);
	ASSERT(sctp->sctp_recvq_tq == NULL);

	ASSERT(sctp->sctp_sendq == NULL);
	ASSERT(sctp->sctp_sendq_tail == NULL);
	ASSERT(sctp->sctp_sendq_sending == B_FALSE);

	ASSERT(sctp->sctp_ipp_hopopts == NULL);
	ASSERT(sctp->sctp_ipp_rtdstopts == NULL);
	ASSERT(sctp->sctp_ipp_rthdr == NULL);
	ASSERT(sctp->sctp_ipp_dstopts == NULL);
	ASSERT(sctp->sctp_ipp_pathmtu == NULL);

	/*
	 * sctp_pad_mp can be NULL if the memory allocation fails
	 * in sctp_init_values() and the conn_t is freed.
	 */
	if (sctp->sctp_pad_mp != NULL) {
		freeb(sctp->sctp_pad_mp);
		sctp->sctp_pad_mp = NULL;
	}

	mutex_destroy(&sctp->sctp_reflock);
	mutex_destroy(&sctp->sctp_lock);
	mutex_destroy(&sctp->sctp_recvq_lock);
	cv_destroy(&sctp->sctp_cv);
	mutex_destroy(&sctp->sctp_sendq_lock);

}

static void
sctp_conn_cache_init()
{
	sctp_conn_cache = kmem_cache_create("sctp_conn_cache",
	    sizeof (sctp_t) + sizeof (conn_t), 0, sctp_conn_cache_constructor,
	    sctp_conn_cache_destructor, NULL, NULL, NULL, 0);
}

static void
sctp_conn_cache_fini()
{
	kmem_cache_destroy(sctp_conn_cache);
}

void
sctp_conn_init(conn_t *connp)
{
	connp->conn_flags = IPCL_SCTPCONN;
	connp->conn_rq = connp->conn_wq = NULL;
	connp->conn_multicast_loop = IP_DEFAULT_MULTICAST_LOOP;
	connp->conn_ulp = IPPROTO_SCTP;
	connp->conn_state_flags |= CONN_INCIPIENT;
	mutex_init(&connp->conn_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&connp->conn_cv, NULL, CV_DEFAULT, NULL);
}

static void
sctp_conn_clear(conn_t *connp)
{
	/* Clean up conn_t stuff */
	if (connp->conn_latch != NULL)
		IPLATCH_REFRELE(connp->conn_latch, connp->conn_netstack);
	if (connp->conn_policy != NULL)
		IPPH_REFRELE(connp->conn_policy, connp->conn_netstack);
	if (connp->conn_ipsec_opt_mp != NULL)
		freemsg(connp->conn_ipsec_opt_mp);
	mutex_destroy(&connp->conn_lock);
	cv_destroy(&connp->conn_cv);
	netstack_rele(connp->conn_netstack);
	bzero(connp, sizeof (struct conn_s));
}
