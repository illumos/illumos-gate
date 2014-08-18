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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */

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
#include <inet/ip_if.h>
#include <inet/ip_ire.h>
#include <inet/ip6.h>
#include <inet/mi.h>
#include <inet/mib2.h>
#include <inet/kstatcom.h>
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
static void	sctp_notify(void *, ip_xmit_attr_t *, ixa_notify_type_t,
    ixa_notify_arg_t);

static void	*sctp_stack_init(netstackid_t stackid, netstack_t *ns);
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
int sctp_recvq_tq_thr_min = 4;
/* The maximum number of threads for each taskq. */
int sctp_recvq_tq_thr_max = 48;
/* The mnimum number of tasks for each taskq. */
int sctp_recvq_tq_task_min = 8;
/* Default value of sctp_recvq_tq_list_max_sz. */
int sctp_recvq_tq_list_max = 16;

/*
 * SCTP tunables related declarations. Definitions are in sctp_tunables.c
 */
extern mod_prop_info_t sctp_propinfo_tbl[];
extern int sctp_propinfo_count;

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
	conn_t	*connp;
	cred_t	*credp;
	sctp_stack_t	*sctps = psctp->sctp_sctps;

	if ((connp = ipcl_conn_create(IPCL_SCTPCONN, KM_NOSLEEP,
	    sctps->sctps_netstack)) == NULL) {
		return (NULL);
	}

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
		kmem_cache_free(sctp_conn_cache, connp);
		return (NULL);
	}

	sctp->sctp_ack_mp = ack_mp;
	sctp->sctp_heartbeat_mp = hb_mp;

	if (sctp_init_values(sctp, psctp, KM_NOSLEEP) != 0) {
		freeb(ack_mp);
		freeb(hb_mp);
		sctp_conn_clear(connp);
		sctp->sctp_sctps = NULL;
		kmem_cache_free(sctp_conn_cache, connp);
		return (NULL);
	}

	if ((credp = psctp->sctp_connp->conn_cred) != NULL) {
		connp->conn_cred = credp;
		crhold(credp);
	}

	sctp->sctp_mss = psctp->sctp_mss;
	sctp->sctp_detached = B_TRUE;
	/*
	 * Link to the global as soon as possible so that this sctp_t
	 * can be found.
	 */
	SCTP_LINK(sctp, sctps);

	/* If the listener has a limit, inherit the counter info. */
	sctp->sctp_listen_cnt = psctp->sctp_listen_cnt;

	return (sctp);
}

/*
 * We are dying for some reason.  Try to do it gracefully.
 */
void
sctp_clean_death(sctp_t *sctp, int err)
{
	ASSERT(sctp != NULL);

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
		if (sctp->sctp_ulp_disconnected(sctp->sctp_ulpd, 0, err)) {
			/*
			 * Socket is gone, detach.
			 */
			sctp->sctp_detached = B_TRUE;
			sctp->sctp_ulpd = NULL;
			sctp->sctp_upcalls = NULL;
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
	int		error = 0;
	conn_t		*connp = sctp->sctp_connp;

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
		 * If SO_LINGER has set a zero linger time, terminate the
		 * association and send an ABORT.
		 */
		if (connp->conn_linger && connp->conn_lingertime == 0) {
			sctp_user_abort(sctp, NULL);
			WAKE_SCTP(sctp);
			return (error);
		}

		/*
		 * If there is unread data, send an ABORT and terminate the
		 * association.
		 */
		if (sctp->sctp_rxqueued > 0 || sctp->sctp_ulp_rxqueued > 0) {
			sctp_user_abort(sctp, NULL);
			WAKE_SCTP(sctp);
			return (error);
		}
		/*
		 * Transmit the shutdown before detaching the sctp_t.
		 * After sctp_detach returns this queue/perimeter
		 * no longer owns the sctp_t thus others can modify it.
		 */
		sctp_send_shutdown(sctp, 0);

		/* Pass gathered wisdom to IP for keeping */
		sctp_update_dce(sctp);

		/*
		 * If lingering on close then wait until the shutdown
		 * is complete, or the SO_LINGER time passes, or an
		 * ABORT is sent/received.  Note that sctp_disconnect()
		 * can be called more than once.  Make sure that only
		 * one thread waits.
		 */
		if (connp->conn_linger && connp->conn_lingertime > 0 &&
		    sctp->sctp_state >= SCTPS_ESTABLISHED &&
		    !sctp->sctp_lingering) {
			clock_t stoptime;	/* in ticks */
			clock_t ret;

			sctp->sctp_lingering = 1;
			sctp->sctp_client_errno = 0;
			stoptime = ddi_get_lbolt() +
			    connp->conn_lingertime * hz;

			mutex_enter(&sctp->sctp_lock);
			sctp->sctp_running = B_FALSE;
			while (sctp->sctp_state >= SCTPS_ESTABLISHED &&
			    sctp->sctp_client_errno == 0) {
				cv_signal(&sctp->sctp_cv);
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
	sctp->sctp_upcalls = NULL;
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
	conn_t	*connp = sctp->sctp_connp;

	/* The counter is incremented only for established associations. */
	if (sctp->sctp_state >= SCTPS_ESTABLISHED)
		SCTPS_ASSOC_DEC(sctp->sctp_sctps);

	if (sctp->sctp_listen_cnt != NULL)
		SCTP_DECR_LISTEN_CNT(sctp);

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
	mutex_exit(&connp->conn_lock);

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
		sctp->sctp_recvq = mp->b_next;
		mp->b_next = NULL;

		if (ip_recv_attr_is_mblk(mp))
			mp = ip_recv_attr_free_mblk(mp);

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
		sctp->sctp_uo_frags = NULL;
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
	ASSERT(connp->conn_proto == IPPROTO_SCTP);
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
	if (sctp->sctp_rthdrdstopts != NULL) {
		mi_free(sctp->sctp_rthdrdstopts);
		sctp->sctp_rthdrdstopts = NULL;
		sctp->sctp_rthdrdstoptslen = 0;
	}
	ASSERT(sctp->sctp_rthdrdstoptslen == 0);
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
	SCTPS_UPDATE_MIB(sctps, sctpOutSCTPPkts, sctp->sctp_opkts);
	SCTPS_UPDATE_MIB(sctps, sctpOutCtrlChunks, sctp->sctp_obchunks);
	SCTPS_UPDATE_MIB(sctps, sctpOutOrderChunks, sctp->sctp_odchunks);
	SCTPS_UPDATE_MIB(sctps, sctpOutUnorderChunks, sctp->sctp_oudchunks);
	SCTPS_UPDATE_MIB(sctps, sctpRetransChunks, sctp->sctp_rxtchunks);
	SCTPS_UPDATE_MIB(sctps, sctpInSCTPPkts, sctp->sctp_ipkts);
	SCTPS_UPDATE_MIB(sctps, sctpInCtrlChunks, sctp->sctp_ibchunks);
	SCTPS_UPDATE_MIB(sctps, sctpInOrderChunks, sctp->sctp_idchunks);
	SCTPS_UPDATE_MIB(sctps, sctpInUnorderChunks, sctp->sctp_iudchunks);
	SCTPS_UPDATE_MIB(sctps, sctpFragUsrMsgs, sctp->sctp_fragdmsgs);
	SCTPS_UPDATE_MIB(sctps, sctpReasmUsrMsgs, sctp->sctp_reassmsgs);
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
	sctp->sctp_outseqtsns = 0;
	sctp->sctp_osacks = 0;
	sctp->sctp_isacks = 0;
	sctp->sctp_idupchunks = 0;
	sctp->sctp_gapcnt = 0;
	sctp->sctp_cum_obchunks = 0;
	sctp->sctp_cum_odchunks = 0;
	sctp->sctp_cum_oudchunks = 0;
	sctp->sctp_cum_rxtchunks = 0;
	sctp->sctp_cum_ibchunks = 0;
	sctp->sctp_cum_idchunks = 0;
	sctp->sctp_cum_iudchunks = 0;

	sctp->sctp_autoclose = 0;
	sctp->sctp_tx_adaptation_code = 0;

	sctp->sctp_v6label_len = 0;
	sctp->sctp_v4label_len = 0;

	sctp->sctp_sctps = NULL;

	sctp_conn_clear(connp);
	kmem_cache_free(sctp_conn_cache, connp);
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
	conn_t 	*connp;

	connp = sctp->sctp_connp;

	sctp->sctp_nsaddrs = 0;
	for (cnt = 0; cnt < SCTP_IPIF_HASH; cnt++) {
		sctp->sctp_saddrs[cnt].ipif_count = 0;
		list_create(&sctp->sctp_saddrs[cnt].sctp_ipif_list,
		    sizeof (sctp_saddr_ipif_t), offsetof(sctp_saddr_ipif_t,
		    saddr_ipif));
	}
	connp->conn_ports = 0;
	sctp->sctp_running = B_FALSE;
	sctp->sctp_state = SCTPS_IDLE;

	sctp->sctp_refcnt = 1;

	sctp->sctp_strikes = 0;

	sctp->sctp_last_mtu_probe = ddi_get_lbolt64();
	sctp->sctp_mtu_probe_intvl = sctps->sctps_mtu_probe_interval;

	sctp->sctp_sack_gaps = 0;
	/* So we will not delay sending the first SACK. */
	sctp->sctp_sack_toggle = sctps->sctps_deferred_acks_max;

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
		 *
		 * Start by inheriting from the conn_t, including conn_ixa and
		 * conn_xmit_ipp.
		 */
		err = conn_inherit_parent(psctp->sctp_connp, connp);
		if (err != 0)
			goto failure;

		sctp->sctp_upcalls = psctp->sctp_upcalls;

		sctp->sctp_cookie_lifetime = psctp->sctp_cookie_lifetime;

		sctp->sctp_cwnd_max = psctp->sctp_cwnd_max;
		sctp->sctp_rwnd = psctp->sctp_rwnd;
		sctp->sctp_arwnd = psctp->sctp_arwnd;
		sctp->sctp_pd_point = psctp->sctp_pd_point;
		sctp->sctp_rto_max = psctp->sctp_rto_max;
		sctp->sctp_rto_max_init = psctp->sctp_rto_max_init;
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
		sctp->sctp_tx_adaptation_code = psctp->sctp_tx_adaptation_code;

		/* xxx should be a better way to copy these flags xxx */
		sctp->sctp_bound_to_all = psctp->sctp_bound_to_all;
		sctp->sctp_cansleep = psctp->sctp_cansleep;
		sctp->sctp_send_adaptation = psctp->sctp_send_adaptation;
		sctp->sctp_ndelay = psctp->sctp_ndelay;
		sctp->sctp_events = psctp->sctp_events;
	} else {
		/*
		 * Set to system defaults
		 */
		sctp->sctp_cookie_lifetime =
		    MSEC_TO_TICK(sctps->sctps_cookie_life);
		connp->conn_sndlowat = sctps->sctps_xmit_lowat;
		connp->conn_sndbuf = sctps->sctps_xmit_hiwat;
		connp->conn_rcvbuf = sctps->sctps_recv_hiwat;

		sctp->sctp_cwnd_max = sctps->sctps_cwnd_max_;
		sctp->sctp_rwnd = connp->conn_rcvbuf;
		sctp->sctp_arwnd = connp->conn_rcvbuf;
		sctp->sctp_pd_point = sctp->sctp_rwnd;
		sctp->sctp_rto_max = MSEC_TO_TICK(sctps->sctps_rto_maxg);
		sctp->sctp_rto_max_init = sctp->sctp_rto_max;
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

		if (connp->conn_family == AF_INET)
			connp->conn_default_ttl = sctps->sctps_ipv4_ttl;
		else
			connp->conn_default_ttl = sctps->sctps_ipv6_hoplimit;

		connp->conn_xmit_ipp.ipp_unicast_hops =
		    connp->conn_default_ttl;

		/*
		 * Initialize the header template
		 */
		if ((err = sctp_build_hdrs(sctp, sleep)) != 0) {
			goto failure;
		}
	}

	sctp->sctp_understands_asconf = B_TRUE;
	sctp->sctp_understands_addip = B_TRUE;
	sctp->sctp_prsctp_aware = B_FALSE;

	sctp->sctp_connp->conn_ref = 1;

	sctp->sctp_prsctpdrop = 0;
	sctp->sctp_msgcount = 0;

	return (0);

failure:
	sctp_headers_free(sctp);
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
 * Update the SCTP state according to change of PMTU.
 *
 * Path MTU might have changed by either increase or decrease, so need to
 * adjust the MSS based on the value of ixa_pmtu.
 */
static void
sctp_update_pmtu(sctp_t *sctp, sctp_faddr_t *fp, boolean_t decrease_only)
{
	uint32_t	pmtu;
	int32_t		mss;
	ip_xmit_attr_t	*ixa = fp->sf_ixa;

	if (sctp->sctp_state < SCTPS_ESTABLISHED)
		return;

	/*
	 * Always call ip_get_pmtu() to make sure that IP has updated
	 * ixa_flags properly.
	 */
	pmtu = ip_get_pmtu(ixa);

	/*
	 * Calculate the MSS by decreasing the PMTU by sctp_hdr_len and
	 * IPsec overhead if applied. Make sure to use the most recent
	 * IPsec information.
	 */
	mss = pmtu - conn_ipsec_length(sctp->sctp_connp);
	if (ixa->ixa_flags & IXAF_IS_IPV4)
		mss -= sctp->sctp_hdr_len;
	else
		mss -= sctp->sctp_hdr6_len;

	/*
	 * Nothing to change, so just return.
	 */
	if (mss == fp->sf_pmss)
		return;

	/*
	 * Currently, for ICMP errors, only PMTU decrease is handled.
	 */
	if (mss > fp->sf_pmss && decrease_only)
		return;

#ifdef DEBUG
	(void) printf("sctp_update_pmtu mss from %d to %d\n",
	    fp->sf_pmss, mss);
#endif
	DTRACE_PROBE2(sctp_update_pmtu, int32_t, fp->sf_pmss, uint32_t, mss);

	/*
	 * Update ixa_fragsize and ixa_pmtu.
	 */
	ixa->ixa_fragsize = ixa->ixa_pmtu = pmtu;

	/*
	 * Make sure that sfa_pmss is a multiple of
	 * SCTP_ALIGN.
	 */
	fp->sf_pmss = mss & ~(SCTP_ALIGN - 1);
	fp->sf_pmtu_discovered = 1;

#ifdef notyet
	if (mss < sctp->sctp_sctps->sctps_mss_min)
		ixa->ixa_flags |= IXAF_PMTU_TOO_SMALL;
#endif
	if (ixa->ixa_flags & IXAF_PMTU_TOO_SMALL)
		ixa->ixa_flags &= ~(IXAF_DONTFRAG | IXAF_PMTU_IPV4_DF);

	/*
	 * If below the min size then ip_get_pmtu cleared IXAF_PMTU_IPV4_DF.
	 * Make sure to clear IXAF_DONTFRAG, which is used by IP to decide
	 * whether to fragment the packet.
	 */
	if (ixa->ixa_flags & IXAF_IS_IPV4) {
		if (!(ixa->ixa_flags & IXAF_PMTU_IPV4_DF)) {
			fp->sf_df = B_FALSE;
			if (fp == sctp->sctp_current) {
				sctp->sctp_ipha->
				    ipha_fragment_offset_and_flags = 0;
			}
		}
	}
}

/*
 * Notify function registered with ip_xmit_attr_t. It's called in the context
 * of conn_ip_output so it's safe to update the SCTP state.
 * Currently only used for pmtu changes.
 */
/* ARGSUSED1 */
static void
sctp_notify(void *arg, ip_xmit_attr_t *ixa, ixa_notify_type_t ntype,
    ixa_notify_arg_t narg)
{
	sctp_t		*sctp = (sctp_t *)arg;
	sctp_faddr_t	*fp;

	switch (ntype) {
	case IXAN_PMTU:
		/* Find the faddr based on the ip_xmit_attr_t pointer */
		for (fp = sctp->sctp_faddrs; fp != NULL; fp = fp->sf_next) {
			if (fp->sf_ixa == ixa)
				break;
		}
		if (fp != NULL)
			sctp_update_pmtu(sctp, fp, B_FALSE);
		break;
	default:
		break;
	}
}

/*
 * sctp_icmp_error is called by sctp_input() to process ICMP error messages
 * passed up by IP.  We need to find a sctp_t
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
	in6_addr_t dst;
	sctp_faddr_t *fp;
	sctp_stack_t	*sctps = sctp->sctp_sctps;

	dprint(1, ("sctp_icmp_error: sctp=%p, mp=%p\n", (void *)sctp,
	    (void *)mp));

	ipha = (ipha_t *)mp->b_rptr;
	if (IPH_HDR_VERSION(ipha) != IPV4_VERSION) {
		ASSERT(IPH_HDR_VERSION(ipha) == IPV6_VERSION);
		sctp_icmp_error_ipv6(sctp, mp);
		return;
	}

	/* account for the ip hdr from the icmp message */
	iph_hdr_length = IPH_HDR_LENGTH(ipha);
	icmph = (icmph_t *)&mp->b_rptr[iph_hdr_length];
	/* now the ip hdr of message resulting in this icmp */
	ipha = (ipha_t *)&icmph[1];
	iph_hdr_length = IPH_HDR_LENGTH(ipha);
	sctph = (sctp_hdr_t *)((char *)ipha + iph_hdr_length);
	/* first_mp must expose the full sctp header. */
	if ((uchar_t *)(sctph + 1) >= mp->b_wptr) {
		/* not enough data for SCTP header */
		freemsg(mp);
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
			sctp_update_pmtu(sctp, fp, B_TRUE);
			/*
			 * It is possible, even likely that a fast retransmit
			 * attempt has been dropped by ip as a result of this
			 * error, retransmission bundles as much as possible.
			 * A retransmit here prevents significant delays waiting
			 * on the timer. Analogous to behaviour of TCP after
			 * ICMP too big.
			 */
			sctp_rexmit(sctp, fp);
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
				SCTPS_BUMP_MIB(sctps, sctpAborted);
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
	freemsg(mp);
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

		sctp_update_pmtu(sctp, fp, B_TRUE);
		/*
		 * It is possible, even likely that a fast retransmit
		 * attempt has been dropped by ip as a result of this
		 * error, retransmission bundles as much as possible.
		 * A retransmit here prevents significant delays waiting
		 * on the timer. Analogous to behaviour of TCP after
		 * ICMP too big.
		 */
		sctp_rexmit(sctp, fp);
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
				SCTPS_BUMP_MIB(sctps, sctpAborted);
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
				SCTPS_BUMP_MIB(sctps, sctpAborted);
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
sctp_create(void *ulpd, sctp_t *parent, int family, int type, int flags,
    sock_upcalls_t *upcalls, sctp_sockbuf_limits_t *sbl,
    cred_t *credp)
{
	sctp_t		*sctp, *psctp;
	conn_t		*connp;
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
		ASSERT(sctps->sctps_recvq_tq_list_cur_sz > 0);
	} else {
		netstack_t *ns;

		ns = netstack_find_by_cred(credp);
		sctps = ns->netstack_sctp;
		/*
		 * Check if the receive queue taskq for this sctp_stack_t has
		 * been set up.
		 */
		if (sctps->sctps_recvq_tq_list_cur_sz == 0)
			sctp_rq_tq_init(sctps);

		/*
		 * For exclusive stacks we set the zoneid to zero
		 * to make SCTP operate as if in the global zone.
		 */
		if (sctps->sctps_netstack->netstack_stackid !=
		    GLOBAL_NETSTACKID)
			zoneid = GLOBAL_ZONEID;
		else
			zoneid = crgetzoneid(credp);
	}
	if ((connp = ipcl_conn_create(IPCL_SCTPCONN, sleep,
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
	sctp = CONN2SCTP(connp);
	sctp->sctp_sctps = sctps;

	if ((ack_mp = sctp_timer_alloc(sctp, sctp_ack_timer, sleep)) == NULL ||
	    (hb_mp = sctp_timer_alloc(sctp, sctp_heartbeat_timer,
	    sleep)) == NULL) {
		if (ack_mp != NULL)
			freeb(ack_mp);
		sctp_conn_clear(connp);
		sctp->sctp_sctps = NULL;
		kmem_cache_free(sctp_conn_cache, connp);
		return (NULL);
	}

	sctp->sctp_ack_mp = ack_mp;
	sctp->sctp_heartbeat_mp = hb_mp;

	/*
	 * Have conn_ip_output drop packets should our outer source
	 * go invalid, and tell us about mtu changes.
	 */
	connp->conn_ixa->ixa_flags |= IXAF_SET_ULP_CKSUM | IXAF_VERIFY_SOURCE |
	    IXAF_VERIFY_PMTU;
	connp->conn_family = family;
	connp->conn_so_type = type;

	if (sctp_init_values(sctp, psctp, sleep) != 0) {
		freeb(ack_mp);
		freeb(hb_mp);
		sctp_conn_clear(connp);
		sctp->sctp_sctps = NULL;
		kmem_cache_free(sctp_conn_cache, connp);
		return (NULL);
	}
	sctp->sctp_cansleep = ((flags & SCTP_CAN_BLOCK) == SCTP_CAN_BLOCK);

	sctp->sctp_mss = sctps->sctps_initial_mtu - ((family == AF_INET6) ?
	    sctp->sctp_hdr6_len : sctp->sctp_hdr_len);

	if (psctp != NULL) {
		conn_t	*pconnp = psctp->sctp_connp;

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
			sctp_conn_clear(connp);
			sctp->sctp_sctps = NULL;
			kmem_cache_free(sctp_conn_cache, connp);
			return (NULL);
		}

		/*
		 * If the parent is specified, it'll be immediatelly
		 * followed by sctp_connect(). So don't add this guy to
		 * bind hash.
		 */
		connp->conn_lport = pconnp->conn_lport;
		sctp->sctp_state = SCTPS_BOUND;
		WAKE_SCTP(psctp);
	} else {
		ASSERT(connp->conn_cred == NULL);
		connp->conn_zoneid = zoneid;
		/*
		 * conn_allzones can not be set this early, hence
		 * no IPCL_ZONEID
		 */
		connp->conn_ixa->ixa_zoneid = zoneid;
		connp->conn_open_time = ddi_get_lbolt64();
		connp->conn_cred = credp;
		crhold(credp);
		connp->conn_cpid = curproc->p_pid;

		/*
		 * If the caller has the process-wide flag set, then default to
		 * MAC exempt mode.  This allows read-down to unlabeled hosts.
		 */
		if (getpflags(NET_MAC_AWARE, credp) != 0)
			connp->conn_mac_mode = CONN_MAC_AWARE;

		connp->conn_zone_is_global =
		    (crgetzoneid(credp) == GLOBAL_ZONEID);
	}

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
	ASSERT(ulpd != NULL);
	sctp->sctp_ulpd = ulpd;

	ASSERT(upcalls != NULL);
	sctp->sctp_upcalls = upcalls;
	ASSERT(sbl != NULL);
	/* Fill in the socket buffer limits for sctpsockfs */
	sbl->sbl_txlowat = connp->conn_sndlowat;
	sbl->sbl_txbuf = connp->conn_sndbuf;
	sbl->sbl_rxbuf = sctp->sctp_rwnd;
	sbl->sbl_rxlowat = SCTP_RECV_LOWATER;

	/* Insert this in the global list. */
	SCTP_LINK(sctp, sctps);

	return (sctp);
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

	/*
	 * We want to be informed each time a stack is created or
	 * destroyed in the kernel, so we can maintain the
	 * set of sctp_stack_t's.
	 */
	netstack_register(NS_SCTP, sctp_stack_init, NULL, sctp_stack_fini);
}

static void *
sctp_stack_init(netstackid_t stackid, netstack_t *ns)
{
	sctp_stack_t	*sctps;
	size_t		arrsz;
	int		i;

	sctps = kmem_zalloc(sizeof (*sctps), KM_SLEEP);
	sctps->sctps_netstack = ns;

	/* Initialize locks */
	mutex_init(&sctps->sctps_g_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&sctps->sctps_epriv_port_lock, NULL, MUTEX_DEFAULT, NULL);
	sctps->sctps_g_num_epriv_ports = SCTP_NUM_EPRIV_PORTS;
	sctps->sctps_g_epriv_ports[0] = ULP_DEF_EPRIV_PORT1;
	sctps->sctps_g_epriv_ports[1] = ULP_DEF_EPRIV_PORT2;

	/* Initialize SCTP hash arrays. */
	sctp_hash_init(sctps);

	arrsz = sctp_propinfo_count * sizeof (mod_prop_info_t);
	sctps->sctps_propinfo_tbl = (mod_prop_info_t *)kmem_alloc(arrsz,
	    KM_SLEEP);
	bcopy(sctp_propinfo_tbl, sctps->sctps_propinfo_tbl, arrsz);

	/* saddr init */
	sctp_saddr_init(sctps);

	/* Global SCTP PCB list. */
	list_create(&sctps->sctps_g_list, sizeof (sctp_t),
	    offsetof(sctp_t, sctp_list));

	/* Initialize SCTP kstats. */
	sctps->sctps_mibkp = sctp_kstat_init(stackid);
	sctps->sctps_kstat = sctp_kstat2_init(stackid);

	mutex_init(&sctps->sctps_reclaim_lock, NULL, MUTEX_DEFAULT, NULL);
	sctps->sctps_reclaim = B_FALSE;
	sctps->sctps_reclaim_tid = 0;
	sctps->sctps_reclaim_period = sctps->sctps_rto_maxg;

	/* Allocate the per netstack stats */
	mutex_enter(&cpu_lock);
	sctps->sctps_sc_cnt = MAX(ncpus, boot_ncpus);
	mutex_exit(&cpu_lock);
	sctps->sctps_sc = kmem_zalloc(max_ncpus  * sizeof (sctp_stats_cpu_t *),
	    KM_SLEEP);
	for (i = 0; i < sctps->sctps_sc_cnt; i++) {
		sctps->sctps_sc[i] = kmem_zalloc(sizeof (sctp_stats_cpu_t),
		    KM_SLEEP);
	}

	mutex_init(&sctps->sctps_listener_conf_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&sctps->sctps_listener_conf, sizeof (sctp_listener_t),
	    offsetof(sctp_listener_t, sl_link));

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
}

/*
 * Free the SCTP stack instance.
 */
static void
sctp_stack_fini(netstackid_t stackid, void *arg)
{
	sctp_stack_t *sctps = (sctp_stack_t *)arg;
	int i;

	/*
	 * Set sctps_reclaim to false tells sctp_reclaim_timer() not to restart
	 * the timer.
	 */
	mutex_enter(&sctps->sctps_reclaim_lock);
	sctps->sctps_reclaim = B_FALSE;
	mutex_exit(&sctps->sctps_reclaim_lock);
	if (sctps->sctps_reclaim_tid != 0)
		(void) untimeout(sctps->sctps_reclaim_tid);
	mutex_destroy(&sctps->sctps_reclaim_lock);

	sctp_listener_conf_cleanup(sctps);

	kmem_free(sctps->sctps_propinfo_tbl,
	    sctp_propinfo_count * sizeof (mod_prop_info_t));
	sctps->sctps_propinfo_tbl = NULL;

	/* Destroy the recvq taskqs. */
	sctp_rq_tq_fini(sctps);

	/* Destroy saddr  */
	sctp_saddr_fini(sctps);

	/* Global SCTP PCB list. */
	list_destroy(&sctps->sctps_g_list);

	/* Destroy SCTP hash arrays. */
	sctp_hash_destroy(sctps);

	/* Destroy SCTP kernel stats. */
	for (i = 0; i < sctps->sctps_sc_cnt; i++)
		kmem_free(sctps->sctps_sc[i], sizeof (sctp_stats_cpu_t));
	kmem_free(sctps->sctps_sc, max_ncpus * sizeof (sctp_stats_cpu_t *));

	sctp_kstat_fini(stackid, sctps->sctps_mibkp);
	sctps->sctps_mibkp = NULL;
	sctp_kstat2_fini(stackid, sctps->sctps_kstat);
	sctps->sctps_kstat = NULL;

	mutex_destroy(&sctps->sctps_g_lock);
	mutex_destroy(&sctps->sctps_epriv_port_lock);

	kmem_free(sctps, sizeof (*sctps));
}

static void
sctp_rq_tq_init(sctp_stack_t *sctps)
{
	char tq_name[TASKQ_NAMELEN];
	int thrs;
	int max_tasks;

	mutex_enter(&sctps->sctps_g_lock);
	/* Someone may have beaten us in creating the taskqs. */
	if (sctps->sctps_recvq_tq_list_cur_sz > 0) {
		mutex_exit(&sctps->sctps_g_lock);
		return;
	}

	thrs = MIN(sctp_recvq_tq_thr_max, MAX(sctp_recvq_tq_thr_min,
	    MAX(ncpus, boot_ncpus)));
	/*
	 * Make sure that the maximum number of tasks is at least thrice as
	 * large as the number of threads.
	 */
	max_tasks = MAX(sctp_recvq_tq_task_min, thrs) * 3;

	/*
	 * This helps differentiate the default taskqs in different IP stacks.
	 */
	(void) snprintf(tq_name, sizeof (tq_name), "sctp_def_rq_taskq_%d",
	    sctps->sctps_netstack->netstack_stackid);

	sctps->sctps_recvq_tq_list_max_sz = sctp_recvq_tq_list_max;
	sctps->sctps_recvq_tq_list_cur_sz = 1;

	/*
	 * Initialize the recvq_tq_list and create the first recvq taskq.
	 * What to do if it fails?
	 */
	sctps->sctps_recvq_tq_list =
	    kmem_zalloc(sctps->sctps_recvq_tq_list_max_sz * sizeof (taskq_t *),
	    KM_SLEEP);
	sctps->sctps_recvq_tq_list[0] = taskq_create(tq_name, thrs,
	    minclsyspri, sctp_recvq_tq_task_min, max_tasks, TASKQ_PREPOPULATE);
	mutex_init(&sctps->sctps_rq_tq_lock, NULL, MUTEX_DEFAULT, NULL);

	mutex_exit(&sctps->sctps_g_lock);
}

static void
sctp_rq_tq_fini(sctp_stack_t *sctps)
{
	int i;

	if (sctps->sctps_recvq_tq_list_cur_sz == 0)
		return;

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
	int thrs;
	int max_tasks;

	thrs = MIN(sctp_recvq_tq_thr_max, MAX(sctp_recvq_tq_thr_min,
	    MAX(ncpus, boot_ncpus)));
	/*
	 * Make sure that the maximum number of tasks is at least thrice as
	 * large as the number of threads.
	 */
	max_tasks = MAX(sctp_recvq_tq_task_min, thrs) * 3;

	mutex_enter(&sctps->sctps_rq_tq_lock);
	if (sctps->sctps_recvq_tq_list_cur_sz + 1 >
	    sctps->sctps_recvq_tq_list_max_sz) {
		mutex_exit(&sctps->sctps_rq_tq_lock);
		cmn_err(CE_NOTE, "Cannot create more SCTP recvq taskq");
		return;
	}

	(void) snprintf(tq_name, sizeof (tq_name), "sctp_rq_taskq_%d_%u",
	    sctps->sctps_netstack->netstack_stackid,
	    sctps->sctps_recvq_tq_list_cur_sz);
	tq = taskq_create(tq_name, thrs, minclsyspri, sctp_recvq_tq_task_min,
	    max_tasks, TASKQ_PREPOPULATE);
	if (tq == NULL) {
		mutex_exit(&sctps->sctps_rq_tq_lock);
		cmn_err(CE_NOTE, "SCTP recvq taskq creation failed");
		return;
	}
	ASSERT(sctps->sctps_recvq_tq_list[
	    sctps->sctps_recvq_tq_list_cur_sz] == NULL);
	sctps->sctps_recvq_tq_list[sctps->sctps_recvq_tq_list_cur_sz] = tq;
	atomic_inc_32(&sctps->sctps_recvq_tq_list_cur_sz);
	mutex_exit(&sctps->sctps_rq_tq_lock);
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
	next_tq = atomic_inc_32_nv(&sctps->sctps_recvq_tq_list_cur) %
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
 *
 * On failure the message has been freed i.e., this routine always consumes the
 * message. It bumps ipIfStatsInDiscards and and uses ip_drop_input to drop.
 */
void
sctp_add_recvq(sctp_t *sctp, mblk_t *mp, boolean_t caller_hold_lock,
    ip_recv_attr_t *ira)
{
	mblk_t	*attrmp;
	ip_stack_t	*ipst = sctp->sctp_sctps->sctps_netstack->netstack_ip;

	ASSERT(ira->ira_ill == NULL);

	if (!caller_hold_lock)
		mutex_enter(&sctp->sctp_recvq_lock);

	/* If the taskq dispatch has not been scheduled, do it now. */
	if (sctp->sctp_recvq_tq == NULL) {
		ASSERT(sctp->sctp_recvq == NULL);
		if (!sctp_find_next_tq(sctp)) {
			if (!caller_hold_lock)
				mutex_exit(&sctp->sctp_recvq_lock);
			BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsInDiscards);
			ip_drop_input("ipIfStatsInDiscards", mp, NULL);
			freemsg(mp);
			return;
		}
		/* Make sure the sctp_t will not go away. */
		SCTP_REFHOLD(sctp);
	}

	attrmp = ip_recv_attr_to_mblk(ira);
	if (attrmp == NULL) {
		if (!caller_hold_lock)
			mutex_exit(&sctp->sctp_recvq_lock);
		BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsInDiscards);
		ip_drop_input("ipIfStatsInDiscards", mp, NULL);
		freemsg(mp);
		return;
	}
	ASSERT(attrmp->b_cont == NULL);
	attrmp->b_cont = mp;
	mp = attrmp;

	if (sctp->sctp_recvq == NULL) {
		sctp->sctp_recvq = mp;
		sctp->sctp_recvq_tail = mp;
	} else {
		sctp->sctp_recvq_tail->b_next = mp;
		sctp->sctp_recvq_tail = mp;
	}

	if (!caller_hold_lock)
		mutex_exit(&sctp->sctp_recvq_lock);
}

static void
sctp_process_recvq(void *arg)
{
	sctp_t		*sctp = (sctp_t *)arg;
	mblk_t		*mp;
#ifdef DEBUG
	uint32_t	loop_cnt = 0;
#endif
	ip_recv_attr_t	iras;

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
		mblk_t *data_mp;

		sctp->sctp_recvq = mp->b_next;
		mutex_exit(&sctp->sctp_recvq_lock);
		mp->b_next = NULL;
#ifdef DEBUG
		loop_cnt++;
#endif
		mp->b_prev = NULL;

		data_mp = mp->b_cont;
		mp->b_cont = NULL;
		if (!ip_recv_attr_from_mblk(mp, &iras)) {
			ip_drop_input("ip_recv_attr_from_mblk", mp, NULL);
			freemsg(mp);
			ira_cleanup(&iras, B_TRUE);
			continue;
		}

		if (iras.ira_flags & IRAF_ICMP_ERROR)
			sctp_icmp_error(sctp, data_mp);
		else
			sctp_input_data(sctp, data_mp, &iras);

		ira_cleanup(&iras, B_TRUE);
		mutex_enter(&sctp->sctp_recvq_lock);
	}

	sctp->sctp_recvq_tail = NULL;
	sctp->sctp_recvq_tq = NULL;

	mutex_exit(&sctp->sctp_recvq_lock);

	WAKE_SCTP(sctp);

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
	conn_t	*connp = (conn_t *)buf;
	sctp_t	*sctp = (sctp_t *)&connp[1];
	int	cnt;

	bzero(connp, sizeof (conn_t));
	bzero(buf, (char *)&sctp[1] - (char *)buf);

	mutex_init(&sctp->sctp_reflock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&sctp->sctp_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&sctp->sctp_recvq_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&sctp->sctp_cv, NULL, CV_DEFAULT, NULL);
	for (cnt = 0; cnt < SCTP_IPIF_HASH; cnt++) {
		rw_init(&sctp->sctp_saddrs[cnt].ipif_hash_lock, NULL,
		    RW_DEFAULT, NULL);
	}

	mutex_init(&connp->conn_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&connp->conn_cv, NULL, CV_DEFAULT, NULL);
	connp->conn_flags = IPCL_SCTPCONN;
	connp->conn_proto = IPPROTO_SCTP;
	connp->conn_sctp = sctp;
	sctp->sctp_connp = connp;
	rw_init(&connp->conn_ilg_lock, NULL, RW_DEFAULT, NULL);

	connp->conn_ixa = kmem_zalloc(sizeof (ip_xmit_attr_t), kmflags);
	if (connp->conn_ixa == NULL) {
		return (ENOMEM);
	}
	connp->conn_ixa->ixa_refcnt = 1;
	connp->conn_ixa->ixa_protocol = connp->conn_proto;
	connp->conn_ixa->ixa_xmit_hint = CONN_TO_XMIT_HINT(connp);
	return (0);
}

/* ARGSUSED */
static void
sctp_conn_cache_destructor(void *buf, void *cdrarg)
{
	conn_t	*connp = (conn_t *)buf;
	sctp_t	*sctp = (sctp_t *)&connp[1];
	int	cnt;

	ASSERT(sctp->sctp_connp == connp);
	ASSERT(!MUTEX_HELD(&sctp->sctp_lock));
	ASSERT(!MUTEX_HELD(&sctp->sctp_reflock));
	ASSERT(!MUTEX_HELD(&sctp->sctp_recvq_lock));

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
	for (cnt = 0; cnt < SCTP_IPIF_HASH; cnt++) {
		rw_destroy(&sctp->sctp_saddrs[cnt].ipif_hash_lock);
	}

	mutex_destroy(&connp->conn_lock);
	cv_destroy(&connp->conn_cv);
	rw_destroy(&connp->conn_ilg_lock);

	/* Can be NULL if constructor failed */
	if (connp->conn_ixa != NULL) {
		ASSERT(connp->conn_ixa->ixa_refcnt == 1);
		ASSERT(connp->conn_ixa->ixa_ire == NULL);
		ASSERT(connp->conn_ixa->ixa_nce == NULL);
		ixa_refrele(connp->conn_ixa);
	}
}

static void
sctp_conn_cache_init()
{
	sctp_conn_cache = kmem_cache_create("sctp_conn_cache",
	    sizeof (sctp_t) + sizeof (conn_t), 0, sctp_conn_cache_constructor,
	    sctp_conn_cache_destructor, sctp_conn_reclaim, NULL, NULL, 0);
}

static void
sctp_conn_cache_fini()
{
	kmem_cache_destroy(sctp_conn_cache);
}

void
sctp_conn_init(conn_t *connp)
{
	ASSERT(connp->conn_flags == IPCL_SCTPCONN);
	connp->conn_rq = connp->conn_wq = NULL;
	connp->conn_ixa->ixa_flags |= IXAF_SET_ULP_CKSUM | IXAF_VERIFY_SOURCE |
	    IXAF_VERIFY_PMTU;

	ASSERT(connp->conn_proto == IPPROTO_SCTP);
	ASSERT(connp->conn_ixa->ixa_protocol == connp->conn_proto);
	connp->conn_state_flags |= CONN_INCIPIENT;

	ASSERT(connp->conn_sctp != NULL);

	/*
	 * Register sctp_notify to listen to capability changes detected by IP.
	 * This upcall is made in the context of the call to conn_ip_output
	 * thus it holds whatever locks sctp holds across conn_ip_output.
	 */
	connp->conn_ixa->ixa_notify = sctp_notify;
	connp->conn_ixa->ixa_notify_cookie = connp->conn_sctp;
}

static void
sctp_conn_clear(conn_t *connp)
{
	/* Clean up conn_t stuff */
	if (connp->conn_latch != NULL) {
		IPLATCH_REFRELE(connp->conn_latch);
		connp->conn_latch = NULL;
	}
	if (connp->conn_latch_in_policy != NULL) {
		IPPOL_REFRELE(connp->conn_latch_in_policy);
		connp->conn_latch_in_policy = NULL;
	}
	if (connp->conn_latch_in_action != NULL) {
		IPACT_REFRELE(connp->conn_latch_in_action);
		connp->conn_latch_in_action = NULL;
	}
	if (connp->conn_policy != NULL) {
		IPPH_REFRELE(connp->conn_policy, connp->conn_netstack);
		connp->conn_policy = NULL;
	}
	if (connp->conn_ipsec_opt_mp != NULL) {
		freemsg(connp->conn_ipsec_opt_mp);
		connp->conn_ipsec_opt_mp = NULL;
	}
	netstack_rele(connp->conn_netstack);
	connp->conn_netstack = NULL;

	/* Leave conn_ixa and other constructed fields in place */
	ipcl_conn_cleanup(connp);
}
