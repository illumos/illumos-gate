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
#include <sys/strlog.h>
#include <sys/policy.h>
#include <sys/strsun.h>
#include <sys/squeue_impl.h>
#include <sys/squeue.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/tcp.h>
#include <inet/tcp_impl.h>

/* Control whether TCP can enter defensive mode when under memory pressure. */
static boolean_t tcp_do_reclaim = B_TRUE;

/*
 * Routines related to the TCP_IOC_ABORT_CONN ioctl command.
 *
 * TCP_IOC_ABORT_CONN is a non-transparent ioctl command used for aborting
 * TCP connections. To invoke this ioctl, a tcp_ioc_abort_conn_t structure
 * (defined in tcp.h) needs to be filled in and passed into the kernel
 * via an I_STR ioctl command (see streamio(7I)). The tcp_ioc_abort_conn_t
 * structure contains the four-tuple of a TCP connection and a range of TCP
 * states (specified by ac_start and ac_end). The use of wildcard addresses
 * and ports is allowed. Connections with a matching four tuple and a state
 * within the specified range will be aborted. The valid states for the
 * ac_start and ac_end fields are in the range TCPS_SYN_SENT to TCPS_TIME_WAIT,
 * inclusive.
 *
 * An application which has its connection aborted by this ioctl will receive
 * an error that is dependent on the connection state at the time of the abort.
 * If the connection state is < TCPS_TIME_WAIT, an application should behave as
 * though a RST packet has been received.  If the connection state is equal to
 * TCPS_TIME_WAIT, the 2MSL timeout will immediately be canceled by the kernel
 * and all resources associated with the connection will be freed.
 */
static mblk_t	*tcp_ioctl_abort_build_msg(tcp_ioc_abort_conn_t *, tcp_t *);
static void	tcp_ioctl_abort_dump(tcp_ioc_abort_conn_t *);
static void	tcp_ioctl_abort_handler(void *arg, mblk_t *mp, void *arg2,
    ip_recv_attr_t *dummy);
static int	tcp_ioctl_abort(tcp_ioc_abort_conn_t *, tcp_stack_t *tcps);
void	tcp_ioctl_abort_conn(queue_t *, mblk_t *);
static int	tcp_ioctl_abort_bucket(tcp_ioc_abort_conn_t *, int, int *,
    boolean_t, tcp_stack_t *);

/*
 * Macros used for accessing the different types of sockaddr
 * structures inside a tcp_ioc_abort_conn_t.
 */
#define	TCP_AC_V4LADDR(acp) ((sin_t *)&(acp)->ac_local)
#define	TCP_AC_V4RADDR(acp) ((sin_t *)&(acp)->ac_remote)
#define	TCP_AC_V4LOCAL(acp) (TCP_AC_V4LADDR(acp)->sin_addr.s_addr)
#define	TCP_AC_V4REMOTE(acp) (TCP_AC_V4RADDR(acp)->sin_addr.s_addr)
#define	TCP_AC_V4LPORT(acp) (TCP_AC_V4LADDR(acp)->sin_port)
#define	TCP_AC_V4RPORT(acp) (TCP_AC_V4RADDR(acp)->sin_port)
#define	TCP_AC_V6LADDR(acp) ((sin6_t *)&(acp)->ac_local)
#define	TCP_AC_V6RADDR(acp) ((sin6_t *)&(acp)->ac_remote)
#define	TCP_AC_V6LOCAL(acp) (TCP_AC_V6LADDR(acp)->sin6_addr)
#define	TCP_AC_V6REMOTE(acp) (TCP_AC_V6RADDR(acp)->sin6_addr)
#define	TCP_AC_V6LPORT(acp) (TCP_AC_V6LADDR(acp)->sin6_port)
#define	TCP_AC_V6RPORT(acp) (TCP_AC_V6RADDR(acp)->sin6_port)

/*
 * Return the correct error code to mimic the behavior
 * of a connection reset.
 */
#define	TCP_AC_GET_ERRCODE(state, err) {	\
		switch ((state)) {		\
		case TCPS_SYN_SENT:		\
		case TCPS_SYN_RCVD:		\
			(err) = ECONNREFUSED;	\
			break;			\
		case TCPS_ESTABLISHED:		\
		case TCPS_FIN_WAIT_1:		\
		case TCPS_FIN_WAIT_2:		\
		case TCPS_CLOSE_WAIT:		\
			(err) = ECONNRESET;	\
			break;			\
		case TCPS_CLOSING:		\
		case TCPS_LAST_ACK:		\
		case TCPS_TIME_WAIT:		\
			(err) = 0;		\
			break;			\
		default:			\
			(err) = ENXIO;		\
		}				\
	}

/*
 * Check if a tcp structure matches the info in acp.
 */
#define	TCP_AC_ADDR_MATCH(acp, connp, tcp)			\
	(((acp)->ac_local.ss_family == AF_INET) ?		\
	((TCP_AC_V4LOCAL((acp)) == INADDR_ANY ||		\
	TCP_AC_V4LOCAL((acp)) == (connp)->conn_laddr_v4) &&	\
	(TCP_AC_V4REMOTE((acp)) == INADDR_ANY ||		\
	TCP_AC_V4REMOTE((acp)) == (connp)->conn_faddr_v4) &&	\
	(TCP_AC_V4LPORT((acp)) == 0 ||				\
	TCP_AC_V4LPORT((acp)) == (connp)->conn_lport) &&	\
	(TCP_AC_V4RPORT((acp)) == 0 ||				\
	TCP_AC_V4RPORT((acp)) == (connp)->conn_fport) &&	\
	(acp)->ac_start <= (tcp)->tcp_state &&			\
	(acp)->ac_end >= (tcp)->tcp_state) :			\
	((IN6_IS_ADDR_UNSPECIFIED(&TCP_AC_V6LOCAL((acp))) ||	\
	IN6_ARE_ADDR_EQUAL(&TCP_AC_V6LOCAL((acp)),		\
	&(connp)->conn_laddr_v6)) &&				\
	(IN6_IS_ADDR_UNSPECIFIED(&TCP_AC_V6REMOTE((acp))) ||	\
	IN6_ARE_ADDR_EQUAL(&TCP_AC_V6REMOTE((acp)),		\
	&(connp)->conn_faddr_v6)) &&				\
	(TCP_AC_V6LPORT((acp)) == 0 ||				\
	TCP_AC_V6LPORT((acp)) == (connp)->conn_lport) &&	\
	(TCP_AC_V6RPORT((acp)) == 0 ||				\
	TCP_AC_V6RPORT((acp)) == (connp)->conn_fport) &&	\
	(acp)->ac_start <= (tcp)->tcp_state &&			\
	(acp)->ac_end >= (tcp)->tcp_state))

#define	TCP_AC_MATCH(acp, connp, tcp)				\
	(((acp)->ac_zoneid == ALL_ZONES ||			\
	(acp)->ac_zoneid == (connp)->conn_zoneid) ?		\
	TCP_AC_ADDR_MATCH(acp, connp, tcp) : 0)

/*
 * Build a message containing a tcp_ioc_abort_conn_t structure
 * which is filled in with information from acp and tp.
 */
static mblk_t *
tcp_ioctl_abort_build_msg(tcp_ioc_abort_conn_t *acp, tcp_t *tp)
{
	mblk_t *mp;
	tcp_ioc_abort_conn_t *tacp;

	mp = allocb(sizeof (uint32_t) + sizeof (*acp), BPRI_LO);
	if (mp == NULL)
		return (NULL);

	*((uint32_t *)mp->b_rptr) = TCP_IOC_ABORT_CONN;
	tacp = (tcp_ioc_abort_conn_t *)((uchar_t *)mp->b_rptr +
	    sizeof (uint32_t));

	tacp->ac_start = acp->ac_start;
	tacp->ac_end = acp->ac_end;
	tacp->ac_zoneid = acp->ac_zoneid;

	if (acp->ac_local.ss_family == AF_INET) {
		tacp->ac_local.ss_family = AF_INET;
		tacp->ac_remote.ss_family = AF_INET;
		TCP_AC_V4LOCAL(tacp) = tp->tcp_connp->conn_laddr_v4;
		TCP_AC_V4REMOTE(tacp) = tp->tcp_connp->conn_faddr_v4;
		TCP_AC_V4LPORT(tacp) = tp->tcp_connp->conn_lport;
		TCP_AC_V4RPORT(tacp) = tp->tcp_connp->conn_fport;
	} else {
		tacp->ac_local.ss_family = AF_INET6;
		tacp->ac_remote.ss_family = AF_INET6;
		TCP_AC_V6LOCAL(tacp) = tp->tcp_connp->conn_laddr_v6;
		TCP_AC_V6REMOTE(tacp) = tp->tcp_connp->conn_faddr_v6;
		TCP_AC_V6LPORT(tacp) = tp->tcp_connp->conn_lport;
		TCP_AC_V6RPORT(tacp) = tp->tcp_connp->conn_fport;
	}
	mp->b_wptr = (uchar_t *)mp->b_rptr + sizeof (uint32_t) + sizeof (*acp);
	return (mp);
}

/*
 * Print a tcp_ioc_abort_conn_t structure.
 */
static void
tcp_ioctl_abort_dump(tcp_ioc_abort_conn_t *acp)
{
	char lbuf[128];
	char rbuf[128];
	sa_family_t af;
	in_port_t lport, rport;
	ushort_t logflags;

	af = acp->ac_local.ss_family;

	if (af == AF_INET) {
		(void) inet_ntop(af, (const void *)&TCP_AC_V4LOCAL(acp),
		    lbuf, 128);
		(void) inet_ntop(af, (const void *)&TCP_AC_V4REMOTE(acp),
		    rbuf, 128);
		lport = ntohs(TCP_AC_V4LPORT(acp));
		rport = ntohs(TCP_AC_V4RPORT(acp));
	} else {
		(void) inet_ntop(af, (const void *)&TCP_AC_V6LOCAL(acp),
		    lbuf, 128);
		(void) inet_ntop(af, (const void *)&TCP_AC_V6REMOTE(acp),
		    rbuf, 128);
		lport = ntohs(TCP_AC_V6LPORT(acp));
		rport = ntohs(TCP_AC_V6RPORT(acp));
	}

	logflags = SL_TRACE | SL_NOTE;
	/*
	 * Don't print this message to the console if the operation was done
	 * to a non-global zone.
	 */
	if (acp->ac_zoneid == GLOBAL_ZONEID || acp->ac_zoneid == ALL_ZONES)
		logflags |= SL_CONSOLE;
	(void) strlog(TCP_MOD_ID, 0, 1, logflags,
	    "TCP_IOC_ABORT_CONN: local = %s:%d, remote = %s:%d, "
	    "start = %d, end = %d\n", lbuf, lport, rbuf, rport,
	    acp->ac_start, acp->ac_end);
}

/*
 * Called using SQ_FILL when a message built using
 * tcp_ioctl_abort_build_msg is put into a queue.
 * Note that when we get here there is no wildcard in acp any more.
 */
/* ARGSUSED2 */
static void
tcp_ioctl_abort_handler(void *arg, mblk_t *mp, void *arg2,
    ip_recv_attr_t *dummy)
{
	conn_t			*connp = (conn_t *)arg;
	tcp_t			*tcp = connp->conn_tcp;
	tcp_ioc_abort_conn_t	*acp;

	/*
	 * Don't accept any input on a closed tcp as this TCP logically does
	 * not exist on the system. Don't proceed further with this TCP.
	 * For eg. this packet could trigger another close of this tcp
	 * which would be disastrous for tcp_refcnt. tcp_close_detached /
	 * tcp_clean_death / tcp_closei_local must be called at most once
	 * on a TCP.
	 */
	if (tcp->tcp_state == TCPS_CLOSED ||
	    tcp->tcp_state == TCPS_BOUND) {
		freemsg(mp);
		return;
	}

	acp = (tcp_ioc_abort_conn_t *)(mp->b_rptr + sizeof (uint32_t));
	if (tcp->tcp_state <= acp->ac_end) {
		/*
		 * If we get here, we are already on the correct
		 * squeue. This ioctl follows the following path
		 * tcp_wput -> tcp_wput_ioctl -> tcp_ioctl_abort_conn
		 * ->tcp_ioctl_abort->squeue_enter (if on a
		 * different squeue)
		 */
		int errcode;

		TCP_AC_GET_ERRCODE(tcp->tcp_state, errcode);
		(void) tcp_clean_death(tcp, errcode);
	}
	freemsg(mp);
}

/*
 * Abort all matching connections on a hash chain.
 */
static int
tcp_ioctl_abort_bucket(tcp_ioc_abort_conn_t *acp, int index, int *count,
    boolean_t exact, tcp_stack_t *tcps)
{
	int nmatch, err = 0;
	tcp_t *tcp;
	MBLKP mp, last, listhead = NULL;
	conn_t	*tconnp;
	connf_t	*connfp;
	ip_stack_t *ipst = tcps->tcps_netstack->netstack_ip;

	connfp = &ipst->ips_ipcl_conn_fanout[index];

startover:
	nmatch = 0;

	mutex_enter(&connfp->connf_lock);
	for (tconnp = connfp->connf_head; tconnp != NULL;
	    tconnp = tconnp->conn_next) {
		tcp = tconnp->conn_tcp;
		/*
		 * We are missing a check on sin6_scope_id for linklocals here,
		 * but current usage is just for aborting based on zoneid
		 * for shared-IP zones.
		 */
		if (TCP_AC_MATCH(acp, tconnp, tcp)) {
			CONN_INC_REF(tconnp);
			mp = tcp_ioctl_abort_build_msg(acp, tcp);
			if (mp == NULL) {
				err = ENOMEM;
				CONN_DEC_REF(tconnp);
				break;
			}
			mp->b_prev = (mblk_t *)tcp;

			if (listhead == NULL) {
				listhead = mp;
				last = mp;
			} else {
				last->b_next = mp;
				last = mp;
			}
			nmatch++;
			if (exact)
				break;
		}

		/* Avoid holding lock for too long. */
		if (nmatch >= 500)
			break;
	}
	mutex_exit(&connfp->connf_lock);

	/* Pass mp into the correct tcp */
	while ((mp = listhead) != NULL) {
		listhead = listhead->b_next;
		tcp = (tcp_t *)mp->b_prev;
		mp->b_next = mp->b_prev = NULL;
		SQUEUE_ENTER_ONE(tcp->tcp_connp->conn_sqp, mp,
		    tcp_ioctl_abort_handler, tcp->tcp_connp, NULL,
		    SQ_FILL, SQTAG_TCP_ABORT_BUCKET);
	}

	*count += nmatch;
	if (nmatch >= 500 && err == 0)
		goto startover;
	return (err);
}

/*
 * Abort all connections that matches the attributes specified in acp.
 */
static int
tcp_ioctl_abort(tcp_ioc_abort_conn_t *acp, tcp_stack_t *tcps)
{
	sa_family_t af;
	uint32_t  ports;
	uint16_t *pports;
	int err = 0, count = 0;
	boolean_t exact = B_FALSE; /* set when there is no wildcard */
	int index = -1;
	ushort_t logflags;
	ip_stack_t	*ipst = tcps->tcps_netstack->netstack_ip;

	af = acp->ac_local.ss_family;

	if (af == AF_INET) {
		if (TCP_AC_V4REMOTE(acp) != INADDR_ANY &&
		    TCP_AC_V4LPORT(acp) != 0 && TCP_AC_V4RPORT(acp) != 0) {
			pports = (uint16_t *)&ports;
			pports[1] = TCP_AC_V4LPORT(acp);
			pports[0] = TCP_AC_V4RPORT(acp);
			exact = (TCP_AC_V4LOCAL(acp) != INADDR_ANY);
		}
	} else {
		if (!IN6_IS_ADDR_UNSPECIFIED(&TCP_AC_V6REMOTE(acp)) &&
		    TCP_AC_V6LPORT(acp) != 0 && TCP_AC_V6RPORT(acp) != 0) {
			pports = (uint16_t *)&ports;
			pports[1] = TCP_AC_V6LPORT(acp);
			pports[0] = TCP_AC_V6RPORT(acp);
			exact = !IN6_IS_ADDR_UNSPECIFIED(&TCP_AC_V6LOCAL(acp));
		}
	}

	/*
	 * For cases where remote addr, local port, and remote port are non-
	 * wildcards, tcp_ioctl_abort_bucket will only be called once.
	 */
	if (index != -1) {
		err = tcp_ioctl_abort_bucket(acp, index,
		    &count, exact, tcps);
	} else {
		/*
		 * loop through all entries for wildcard case
		 */
		for (index = 0;
		    index < ipst->ips_ipcl_conn_fanout_size;
		    index++) {
			err = tcp_ioctl_abort_bucket(acp, index,
			    &count, exact, tcps);
			if (err != 0)
				break;
		}
	}

	logflags = SL_TRACE | SL_NOTE;
	/*
	 * Don't print this message to the console if the operation was done
	 * to a non-global zone.
	 */
	if (acp->ac_zoneid == GLOBAL_ZONEID || acp->ac_zoneid == ALL_ZONES)
		logflags |= SL_CONSOLE;
	(void) strlog(TCP_MOD_ID, 0, 1, logflags, "TCP_IOC_ABORT_CONN: "
	    "aborted %d connection%c\n", count, ((count > 1) ? 's' : ' '));
	if (err == 0 && count == 0)
		err = ENOENT;
	return (err);
}

/*
 * Process the TCP_IOC_ABORT_CONN ioctl request.
 */
void
tcp_ioctl_abort_conn(queue_t *q, mblk_t *mp)
{
	int	err;
	IOCP    iocp;
	MBLKP   mp1;
	sa_family_t laf, raf;
	tcp_ioc_abort_conn_t *acp;
	zone_t		*zptr;
	conn_t		*connp = Q_TO_CONN(q);
	zoneid_t	zoneid = connp->conn_zoneid;
	tcp_t		*tcp = connp->conn_tcp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	iocp = (IOCP)mp->b_rptr;

	if ((mp1 = mp->b_cont) == NULL ||
	    iocp->ioc_count != sizeof (tcp_ioc_abort_conn_t)) {
		err = EINVAL;
		goto out;
	}

	/* check permissions */
	if (secpolicy_ip_config(iocp->ioc_cr, B_FALSE) != 0) {
		err = EPERM;
		goto out;
	}

	if (mp1->b_cont != NULL) {
		freemsg(mp1->b_cont);
		mp1->b_cont = NULL;
	}

	acp = (tcp_ioc_abort_conn_t *)mp1->b_rptr;
	laf = acp->ac_local.ss_family;
	raf = acp->ac_remote.ss_family;

	/* check that a zone with the supplied zoneid exists */
	if (acp->ac_zoneid != GLOBAL_ZONEID && acp->ac_zoneid != ALL_ZONES) {
		zptr = zone_find_by_id(zoneid);
		if (zptr != NULL) {
			zone_rele(zptr);
		} else {
			err = EINVAL;
			goto out;
		}
	}

	/*
	 * For exclusive stacks we set the zoneid to zero
	 * to make TCP operate as if in the global zone.
	 */
	if (tcps->tcps_netstack->netstack_stackid != GLOBAL_NETSTACKID)
		acp->ac_zoneid = GLOBAL_ZONEID;

	if (acp->ac_start < TCPS_SYN_SENT || acp->ac_end > TCPS_TIME_WAIT ||
	    acp->ac_start > acp->ac_end || laf != raf ||
	    (laf != AF_INET && laf != AF_INET6)) {
		err = EINVAL;
		goto out;
	}

	tcp_ioctl_abort_dump(acp);
	err = tcp_ioctl_abort(acp, tcps);

out:
	if (mp1 != NULL) {
		freemsg(mp1);
		mp->b_cont = NULL;
	}

	if (err != 0)
		miocnak(q, mp, 0, err);
	else
		miocack(q, mp, 0, 0);
}

/*
 * Timeout function to reset the TCP stack variable tcps_reclaim to false.
 */
void
tcp_reclaim_timer(void *arg)
{
	tcp_stack_t *tcps = (tcp_stack_t *)arg;
	int64_t tot_conn = 0;
	int i;
	extern pgcnt_t lotsfree, needfree;

	for (i = 0; i < tcps->tcps_sc_cnt; i++)
		tot_conn += tcps->tcps_sc[i]->tcp_sc_conn_cnt;

	/*
	 * This happens only when a stack is going away.  tcps_reclaim_tid
	 * should not be reset to 0 when returning in this case.
	 */
	mutex_enter(&tcps->tcps_reclaim_lock);
	if (!tcps->tcps_reclaim) {
		mutex_exit(&tcps->tcps_reclaim_lock);
		return;
	}

	if ((freemem >= lotsfree + needfree) || tot_conn < maxusers) {
		tcps->tcps_reclaim = B_FALSE;
		tcps->tcps_reclaim_tid = 0;
	} else {
		/* Stay in defensive mode and restart the timer */
		tcps->tcps_reclaim_tid = timeout(tcp_reclaim_timer,
		    tcps, MSEC_TO_TICK(tcps->tcps_reclaim_period));
	}
	mutex_exit(&tcps->tcps_reclaim_lock);
}

/*
 * Kmem reclaim call back function.  When the system is under memory
 * pressure, we set the TCP stack variable tcps_reclaim to true.  This
 * variable is reset to false after tcps_reclaim_period msecs.  During this
 * period, TCP will be more aggressive in aborting connections not making
 * progress, meaning retransmitting for some time (tcp_early_abort seconds).
 * TCP will also not accept new connection request for those listeners whose
 * q or q0 is not empty.
 */
/* ARGSUSED */
void
tcp_conn_reclaim(void *arg)
{
	netstack_handle_t nh;
	netstack_t *ns;
	tcp_stack_t *tcps;
	extern pgcnt_t lotsfree, needfree;

	if (!tcp_do_reclaim)
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
		int64_t tot_conn = 0;

		/*
		 * During boot time, the first netstack_t is created and
		 * initialized before TCP has registered with the netstack
		 * framework.  If this reclaim function is called before TCP
		 * has finished its initialization, netstack_next() will
		 * return the first netstack_t (since its netstack_flags is
		 * not NSF_UNINIT).  And its netstack_tcp will be NULL.  We
		 * need to catch it.
		 *
		 * All subsequent netstack_t creation will not have this
		 * problem since the initialization is not finished until TCP
		 * has finished its own tcp_stack_t initialization.  Hence
		 * netstack_next() will not return one with NULL netstack_tcp.
		 */
		if ((tcps = ns->netstack_tcp) == NULL) {
			netstack_rele(ns);
			continue;
		}

		/*
		 * Even if the system is under memory pressure, the reason may
		 * not be because of TCP activity.  Check the number of
		 * connections in each stack.  If the number exceeds the
		 * threshold (maxusers), turn on defensive mode.
		 */
		for (i = 0; i < tcps->tcps_sc_cnt; i++)
			tot_conn += tcps->tcps_sc[i]->tcp_sc_conn_cnt;
		if (tot_conn < maxusers) {
			netstack_rele(ns);
			continue;
		}

		mutex_enter(&tcps->tcps_reclaim_lock);
		if (!tcps->tcps_reclaim) {
			tcps->tcps_reclaim = B_TRUE;
			tcps->tcps_reclaim_tid = timeout(tcp_reclaim_timer,
			    tcps, MSEC_TO_TICK(tcps->tcps_reclaim_period));
			TCP_STAT(tcps, tcp_reclaim_cnt);
		}
		mutex_exit(&tcps->tcps_reclaim_lock);
		netstack_rele(ns);
	}
	netstack_next_fini(&nh);
}

/*
 * Given a tcp_stack_t and a port (in host byte order), find a listener
 * configuration for that port and return the ratio.
 */
uint32_t
tcp_find_listener_conf(tcp_stack_t *tcps, in_port_t port)
{
	tcp_listener_t	*tl;
	uint32_t ratio = 0;

	mutex_enter(&tcps->tcps_listener_conf_lock);
	for (tl = list_head(&tcps->tcps_listener_conf); tl != NULL;
	    tl = list_next(&tcps->tcps_listener_conf, tl)) {
		if (tl->tl_port == port) {
			ratio = tl->tl_ratio;
			break;
		}
	}
	mutex_exit(&tcps->tcps_listener_conf_lock);
	return (ratio);
}

/*
 * To remove all listener limit configuration in a tcp_stack_t.
 */
void
tcp_listener_conf_cleanup(tcp_stack_t *tcps)
{
	tcp_listener_t	*tl;

	mutex_enter(&tcps->tcps_listener_conf_lock);
	while ((tl = list_head(&tcps->tcps_listener_conf)) != NULL) {
		list_remove(&tcps->tcps_listener_conf, tl);
		kmem_free(tl, sizeof (tcp_listener_t));
	}
	mutex_destroy(&tcps->tcps_listener_conf_lock);
	list_destroy(&tcps->tcps_listener_conf);
}

/*
 * When a CPU is added, we need to allocate the per CPU stats struct.
 */
void
tcp_stack_cpu_add(tcp_stack_t *tcps, processorid_t cpu_seqid)
{
	int i;

	if (cpu_seqid < tcps->tcps_sc_cnt)
		return;
	for (i = tcps->tcps_sc_cnt; i <= cpu_seqid; i++) {
		ASSERT(tcps->tcps_sc[i] == NULL);
		tcps->tcps_sc[i] = kmem_zalloc(sizeof (tcp_stats_cpu_t),
		    KM_SLEEP);
	}
	membar_producer();
	tcps->tcps_sc_cnt = cpu_seqid + 1;
}

/*
 * Diagnostic routine used to return a string associated with the tcp state.
 * Note that if the caller does not supply a buffer, it will use an internal
 * static string.  This means that if multiple threads call this function at
 * the same time, output can be corrupted...  Note also that this function
 * does not check the size of the supplied buffer.  The caller has to make
 * sure that it is big enough.
 */
char *
tcp_display(tcp_t *tcp, char *sup_buf, char format)
{
	char		buf1[30];
	static char	priv_buf[INET6_ADDRSTRLEN * 2 + 80];
	char		*buf;
	char		*cp;
	in6_addr_t	local, remote;
	char		local_addrbuf[INET6_ADDRSTRLEN];
	char		remote_addrbuf[INET6_ADDRSTRLEN];
	conn_t		*connp;

	if (sup_buf != NULL)
		buf = sup_buf;
	else
		buf = priv_buf;

	if (tcp == NULL)
		return ("NULL_TCP");

	connp = tcp->tcp_connp;
	switch (tcp->tcp_state) {
	case TCPS_CLOSED:
		cp = "TCP_CLOSED";
		break;
	case TCPS_IDLE:
		cp = "TCP_IDLE";
		break;
	case TCPS_BOUND:
		cp = "TCP_BOUND";
		break;
	case TCPS_LISTEN:
		cp = "TCP_LISTEN";
		break;
	case TCPS_SYN_SENT:
		cp = "TCP_SYN_SENT";
		break;
	case TCPS_SYN_RCVD:
		cp = "TCP_SYN_RCVD";
		break;
	case TCPS_ESTABLISHED:
		cp = "TCP_ESTABLISHED";
		break;
	case TCPS_CLOSE_WAIT:
		cp = "TCP_CLOSE_WAIT";
		break;
	case TCPS_FIN_WAIT_1:
		cp = "TCP_FIN_WAIT_1";
		break;
	case TCPS_CLOSING:
		cp = "TCP_CLOSING";
		break;
	case TCPS_LAST_ACK:
		cp = "TCP_LAST_ACK";
		break;
	case TCPS_FIN_WAIT_2:
		cp = "TCP_FIN_WAIT_2";
		break;
	case TCPS_TIME_WAIT:
		cp = "TCP_TIME_WAIT";
		break;
	default:
		(void) mi_sprintf(buf1, "TCPUnkState(%d)", tcp->tcp_state);
		cp = buf1;
		break;
	}
	switch (format) {
	case DISP_ADDR_AND_PORT:
		if (connp->conn_ipversion == IPV4_VERSION) {
			/*
			 * Note that we use the remote address in the tcp_b
			 * structure.  This means that it will print out
			 * the real destination address, not the next hop's
			 * address if source routing is used.
			 */
			IN6_IPADDR_TO_V4MAPPED(connp->conn_laddr_v4, &local);
			IN6_IPADDR_TO_V4MAPPED(connp->conn_faddr_v4, &remote);

		} else {
			local = connp->conn_laddr_v6;
			remote = connp->conn_faddr_v6;
		}
		(void) inet_ntop(AF_INET6, &local, local_addrbuf,
		    sizeof (local_addrbuf));
		(void) inet_ntop(AF_INET6, &remote, remote_addrbuf,
		    sizeof (remote_addrbuf));
		(void) mi_sprintf(buf, "[%s.%u, %s.%u] %s",
		    local_addrbuf, ntohs(connp->conn_lport), remote_addrbuf,
		    ntohs(connp->conn_fport), cp);
		break;
	case DISP_PORT_ONLY:
	default:
		(void) mi_sprintf(buf, "[%u, %u] %s",
		    ntohs(connp->conn_lport), ntohs(connp->conn_fport), cp);
		break;
	}

	return (buf);
}
