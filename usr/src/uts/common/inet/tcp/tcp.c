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
 * Copyright (c) 2011, Joyent Inc. All rights reserved.
 * Copyright (c) 2011 Nexenta Systems, Inc. All rights reserved.
 * Copyright (c) 2013,2014 by Delphix. All rights reserved.
 * Copyright 2014, OmniTI Computer Consulting, Inc. All rights reserved.
 */
/* Copyright (c) 1990 Mentat Inc. */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/stropts.h>
#include <sys/strlog.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/timod.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/suntpi.h>
#include <sys/xti_inet.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/sdt.h>
#include <sys/vtrace.h>
#include <sys/kmem.h>
#include <sys/ethernet.h>
#include <sys/cpuvar.h>
#include <sys/dlpi.h>
#include <sys/pattr.h>
#include <sys/policy.h>
#include <sys/priv.h>
#include <sys/zone.h>
#include <sys/sunldi.h>

#include <sys/errno.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockio.h>
#include <sys/isa_defs.h>
#include <sys/md5.h>
#include <sys/random.h>
#include <sys/uio.h>
#include <sys/systm.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <net/if.h>
#include <net/route.h>
#include <inet/ipsec_impl.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip_impl.h>
#include <inet/ip6.h>
#include <inet/ip_ndp.h>
#include <inet/proto_set.h>
#include <inet/mib2.h>
#include <inet/optcom.h>
#include <inet/snmpcom.h>
#include <inet/kstatcom.h>
#include <inet/tcp.h>
#include <inet/tcp_impl.h>
#include <inet/tcp_cluster.h>
#include <inet/udp_impl.h>
#include <net/pfkeyv2.h>
#include <inet/ipdrop.h>

#include <inet/ipclassifier.h>
#include <inet/ip_ire.h>
#include <inet/ip_ftable.h>
#include <inet/ip_if.h>
#include <inet/ipp_common.h>
#include <inet/ip_rts.h>
#include <inet/ip_netinfo.h>
#include <sys/squeue_impl.h>
#include <sys/squeue.h>
#include <sys/tsol/label.h>
#include <sys/tsol/tnet.h>
#include <rpc/pmap_prot.h>
#include <sys/callo.h>

/*
 * TCP Notes: aka FireEngine Phase I (PSARC 2002/433)
 *
 * (Read the detailed design doc in PSARC case directory)
 *
 * The entire tcp state is contained in tcp_t and conn_t structure
 * which are allocated in tandem using ipcl_conn_create() and passing
 * IPCL_TCPCONN as a flag. We use 'conn_ref' and 'conn_lock' to protect
 * the references on the tcp_t. The tcp_t structure is never compressed
 * and packets always land on the correct TCP perimeter from the time
 * eager is created till the time tcp_t dies (as such the old mentat
 * TCP global queue is not used for detached state and no IPSEC checking
 * is required). The global queue is still allocated to send out resets
 * for connection which have no listeners and IP directly calls
 * tcp_xmit_listeners_reset() which does any policy check.
 *
 * Protection and Synchronisation mechanism:
 *
 * The tcp data structure does not use any kind of lock for protecting
 * its state but instead uses 'squeues' for mutual exclusion from various
 * read and write side threads. To access a tcp member, the thread should
 * always be behind squeue (via squeue_enter with flags as SQ_FILL, SQ_PROCESS,
 * or SQ_NODRAIN). Since the squeues allow a direct function call, caller
 * can pass any tcp function having prototype of edesc_t as argument
 * (different from traditional STREAMs model where packets come in only
 * designated entry points). The list of functions that can be directly
 * called via squeue are listed before the usual function prototype.
 *
 * Referencing:
 *
 * TCP is MT-Hot and we use a reference based scheme to make sure that the
 * tcp structure doesn't disappear when its needed. When the application
 * creates an outgoing connection or accepts an incoming connection, we
 * start out with 2 references on 'conn_ref'. One for TCP and one for IP.
 * The IP reference is just a symbolic reference since ip_tcpclose()
 * looks at tcp structure after tcp_close_output() returns which could
 * have dropped the last TCP reference. So as long as the connection is
 * in attached state i.e. !TCP_IS_DETACHED, we have 2 references on the
 * conn_t. The classifier puts its own reference when the connection is
 * inserted in listen or connected hash. Anytime a thread needs to enter
 * the tcp connection perimeter, it retrieves the conn/tcp from q->ptr
 * on write side or by doing a classify on read side and then puts a
 * reference on the conn before doing squeue_enter/tryenter/fill. For
 * read side, the classifier itself puts the reference under fanout lock
 * to make sure that tcp can't disappear before it gets processed. The
 * squeue will drop this reference automatically so the called function
 * doesn't have to do a DEC_REF.
 *
 * Opening a new connection:
 *
 * The outgoing connection open is pretty simple. tcp_open() does the
 * work in creating the conn/tcp structure and initializing it. The
 * squeue assignment is done based on the CPU the application
 * is running on. So for outbound connections, processing is always done
 * on application CPU which might be different from the incoming CPU
 * being interrupted by the NIC. An optimal way would be to figure out
 * the NIC <-> CPU binding at listen time, and assign the outgoing
 * connection to the squeue attached to the CPU that will be interrupted
 * for incoming packets (we know the NIC based on the bind IP address).
 * This might seem like a problem if more data is going out but the
 * fact is that in most cases the transmit is ACK driven transmit where
 * the outgoing data normally sits on TCP's xmit queue waiting to be
 * transmitted.
 *
 * Accepting a connection:
 *
 * This is a more interesting case because of various races involved in
 * establishing a eager in its own perimeter. Read the meta comment on
 * top of tcp_input_listener(). But briefly, the squeue is picked by
 * ip_fanout based on the ring or the sender (if loopback).
 *
 * Closing a connection:
 *
 * The close is fairly straight forward. tcp_close() calls tcp_close_output()
 * via squeue to do the close and mark the tcp as detached if the connection
 * was in state TCPS_ESTABLISHED or greater. In the later case, TCP keep its
 * reference but tcp_close() drop IP's reference always. So if tcp was
 * not killed, it is sitting in time_wait list with 2 reference - 1 for TCP
 * and 1 because it is in classifier's connected hash. This is the condition
 * we use to determine that its OK to clean up the tcp outside of squeue
 * when time wait expires (check the ref under fanout and conn_lock and
 * if it is 2, remove it from fanout hash and kill it).
 *
 * Although close just drops the necessary references and marks the
 * tcp_detached state, tcp_close needs to know the tcp_detached has been
 * set (under squeue) before letting the STREAM go away (because a
 * inbound packet might attempt to go up the STREAM while the close
 * has happened and tcp_detached is not set). So a special lock and
 * flag is used along with a condition variable (tcp_closelock, tcp_closed,
 * and tcp_closecv) to signal tcp_close that tcp_close_out() has marked
 * tcp_detached.
 *
 * Special provisions and fast paths:
 *
 * We make special provisions for sockfs by marking tcp_issocket
 * whenever we have only sockfs on top of TCP. This allows us to skip
 * putting the tcp in acceptor hash since a sockfs listener can never
 * become acceptor and also avoid allocating a tcp_t for acceptor STREAM
 * since eager has already been allocated and the accept now happens
 * on acceptor STREAM. There is a big blob of comment on top of
 * tcp_input_listener explaining the new accept. When socket is POP'd,
 * sockfs sends us an ioctl to mark the fact and we go back to old
 * behaviour. Once tcp_issocket is unset, its never set for the
 * life of that connection.
 *
 * IPsec notes :
 *
 * Since a packet is always executed on the correct TCP perimeter
 * all IPsec processing is defered to IP including checking new
 * connections and setting IPSEC policies for new connection. The
 * only exception is tcp_xmit_listeners_reset() which is called
 * directly from IP and needs to policy check to see if TH_RST
 * can be sent out.
 */

/*
 * Values for squeue switch:
 * 1: SQ_NODRAIN
 * 2: SQ_PROCESS
 * 3: SQ_FILL
 */
int tcp_squeue_wput = 2;	/* /etc/systems */
int tcp_squeue_flag;

/*
 * To prevent memory hog, limit the number of entries in tcp_free_list
 * to 1% of available memory / number of cpus
 */
uint_t tcp_free_list_max_cnt = 0;

#define	TIDUSZ	4096	/* transport interface data unit size */

/*
 * Size of acceptor hash list.  It has to be a power of 2 for hashing.
 */
#define	TCP_ACCEPTOR_FANOUT_SIZE		512

#ifdef	_ILP32
#define	TCP_ACCEPTOR_HASH(accid)					\
		(((uint_t)(accid) >> 8) & (TCP_ACCEPTOR_FANOUT_SIZE - 1))
#else
#define	TCP_ACCEPTOR_HASH(accid)					\
		((uint_t)(accid) & (TCP_ACCEPTOR_FANOUT_SIZE - 1))
#endif	/* _ILP32 */

/*
 * Minimum number of connections which can be created per listener.  Used
 * when the listener connection count is in effect.
 */
static uint32_t tcp_min_conn_listener = 2;

uint32_t tcp_early_abort = 30;

/* TCP Timer control structure */
typedef struct tcpt_s {
	pfv_t	tcpt_pfv;	/* The routine we are to call */
	tcp_t	*tcpt_tcp;	/* The parameter we are to pass in */
} tcpt_t;

/*
 * Functions called directly via squeue having a prototype of edesc_t.
 */
void		tcp_input_listener(void *arg, mblk_t *mp, void *arg2,
    ip_recv_attr_t *ira);
void		tcp_input_data(void *arg, mblk_t *mp, void *arg2,
    ip_recv_attr_t *ira);
static void	tcp_linger_interrupted(void *arg, mblk_t *mp, void *arg2,
    ip_recv_attr_t *dummy);


/* Prototype for TCP functions */
static void	tcp_random_init(void);
int		tcp_random(void);
static int	tcp_connect_ipv4(tcp_t *tcp, ipaddr_t *dstaddrp,
		    in_port_t dstport, uint_t srcid);
static int	tcp_connect_ipv6(tcp_t *tcp, in6_addr_t *dstaddrp,
		    in_port_t dstport, uint32_t flowinfo,
		    uint_t srcid, uint32_t scope_id);
static void	tcp_iss_init(tcp_t *tcp);
static void	tcp_reinit(tcp_t *tcp);
static void	tcp_reinit_values(tcp_t *tcp);

static void	tcp_wsrv(queue_t *q);
static void	tcp_update_lso(tcp_t *tcp, ip_xmit_attr_t *ixa);
static void	tcp_update_zcopy(tcp_t *tcp);
static void	tcp_notify(void *, ip_xmit_attr_t *, ixa_notify_type_t,
    ixa_notify_arg_t);
static void	*tcp_stack_init(netstackid_t stackid, netstack_t *ns);
static void	tcp_stack_fini(netstackid_t stackid, void *arg);

static int	tcp_squeue_switch(int);

static int	tcp_open(queue_t *, dev_t *, int, int, cred_t *, boolean_t);
static int	tcp_openv4(queue_t *, dev_t *, int, int, cred_t *);
static int	tcp_openv6(queue_t *, dev_t *, int, int, cred_t *);

static void	tcp_squeue_add(squeue_t *);

struct module_info tcp_rinfo =  {
	TCP_MOD_ID, TCP_MOD_NAME, 0, INFPSZ, TCP_RECV_HIWATER, TCP_RECV_LOWATER
};

static struct module_info tcp_winfo =  {
	TCP_MOD_ID, TCP_MOD_NAME, 0, INFPSZ, 127, 16
};

/*
 * Entry points for TCP as a device. The normal case which supports
 * the TCP functionality.
 * We have separate open functions for the /dev/tcp and /dev/tcp6 devices.
 */
struct qinit tcp_rinitv4 = {
	NULL, (pfi_t)tcp_rsrv, tcp_openv4, tcp_tpi_close, NULL, &tcp_rinfo
};

struct qinit tcp_rinitv6 = {
	NULL, (pfi_t)tcp_rsrv, tcp_openv6, tcp_tpi_close, NULL, &tcp_rinfo
};

struct qinit tcp_winit = {
	(pfi_t)tcp_wput, (pfi_t)tcp_wsrv, NULL, NULL, NULL, &tcp_winfo
};

/* Initial entry point for TCP in socket mode. */
struct qinit tcp_sock_winit = {
	(pfi_t)tcp_wput_sock, (pfi_t)tcp_wsrv, NULL, NULL, NULL, &tcp_winfo
};

/* TCP entry point during fallback */
struct qinit tcp_fallback_sock_winit = {
	(pfi_t)tcp_wput_fallback, NULL, NULL, NULL, NULL, &tcp_winfo
};

/*
 * Entry points for TCP as a acceptor STREAM opened by sockfs when doing
 * an accept. Avoid allocating data structures since eager has already
 * been created.
 */
struct qinit tcp_acceptor_rinit = {
	NULL, (pfi_t)tcp_rsrv, NULL, tcp_tpi_close_accept, NULL, &tcp_winfo
};

struct qinit tcp_acceptor_winit = {
	(pfi_t)tcp_tpi_accept, NULL, NULL, NULL, NULL, &tcp_winfo
};

/* For AF_INET aka /dev/tcp */
struct streamtab tcpinfov4 = {
	&tcp_rinitv4, &tcp_winit
};

/* For AF_INET6 aka /dev/tcp6 */
struct streamtab tcpinfov6 = {
	&tcp_rinitv6, &tcp_winit
};

/*
 * Following assumes TPI alignment requirements stay along 32 bit
 * boundaries
 */
#define	ROUNDUP32(x) \
	(((x) + (sizeof (int32_t) - 1)) & ~(sizeof (int32_t) - 1))

/* Template for response to info request. */
struct T_info_ack tcp_g_t_info_ack = {
	T_INFO_ACK,		/* PRIM_type */
	0,			/* TSDU_size */
	T_INFINITE,		/* ETSDU_size */
	T_INVALID,		/* CDATA_size */
	T_INVALID,		/* DDATA_size */
	sizeof (sin_t),		/* ADDR_size */
	0,			/* OPT_size - not initialized here */
	TIDUSZ,			/* TIDU_size */
	T_COTS_ORD,		/* SERV_type */
	TCPS_IDLE,		/* CURRENT_state */
	(XPG4_1|EXPINLINE)	/* PROVIDER_flag */
};

struct T_info_ack tcp_g_t_info_ack_v6 = {
	T_INFO_ACK,		/* PRIM_type */
	0,			/* TSDU_size */
	T_INFINITE,		/* ETSDU_size */
	T_INVALID,		/* CDATA_size */
	T_INVALID,		/* DDATA_size */
	sizeof (sin6_t),	/* ADDR_size */
	0,			/* OPT_size - not initialized here */
	TIDUSZ,		/* TIDU_size */
	T_COTS_ORD,		/* SERV_type */
	TCPS_IDLE,		/* CURRENT_state */
	(XPG4_1|EXPINLINE)	/* PROVIDER_flag */
};

/*
 * TCP tunables related declarations. Definitions are in tcp_tunables.c
 */
extern mod_prop_info_t tcp_propinfo_tbl[];
extern int tcp_propinfo_count;

#define	IS_VMLOANED_MBLK(mp) \
	(((mp)->b_datap->db_struioflag & STRUIO_ZC) != 0)

uint32_t do_tcpzcopy = 1;		/* 0: disable, 1: enable, 2: force */

/*
 * Forces all connections to obey the value of the tcps_maxpsz_multiplier
 * tunable settable via NDD.  Otherwise, the per-connection behavior is
 * determined dynamically during tcp_set_destination(), which is the default.
 */
boolean_t tcp_static_maxpsz = B_FALSE;

/*
 * If the receive buffer size is changed, this function is called to update
 * the upper socket layer on the new delayed receive wake up threshold.
 */
static void
tcp_set_recv_threshold(tcp_t *tcp, uint32_t new_rcvthresh)
{
	uint32_t default_threshold = SOCKET_RECVHIWATER >> 3;

	if (IPCL_IS_NONSTR(tcp->tcp_connp)) {
		conn_t *connp = tcp->tcp_connp;
		struct sock_proto_props sopp;

		/*
		 * only increase rcvthresh upto default_threshold
		 */
		if (new_rcvthresh > default_threshold)
			new_rcvthresh = default_threshold;

		sopp.sopp_flags = SOCKOPT_RCVTHRESH;
		sopp.sopp_rcvthresh = new_rcvthresh;

		(*connp->conn_upcalls->su_set_proto_props)
		    (connp->conn_upper_handle, &sopp);
	}
}

/*
 * Figure out the value of window scale opton.  Note that the rwnd is
 * ASSUMED to be rounded up to the nearest MSS before the calculation.
 * We cannot find the scale value and then do a round up of tcp_rwnd
 * because the scale value may not be correct after that.
 *
 * Set the compiler flag to make this function inline.
 */
void
tcp_set_ws_value(tcp_t *tcp)
{
	int i;
	uint32_t rwnd = tcp->tcp_rwnd;

	for (i = 0; rwnd > TCP_MAXWIN && i < TCP_MAX_WINSHIFT;
	    i++, rwnd >>= 1)
		;
	tcp->tcp_rcv_ws = i;
}

/*
 * Remove cached/latched IPsec references.
 */
void
tcp_ipsec_cleanup(tcp_t *tcp)
{
	conn_t		*connp = tcp->tcp_connp;

	ASSERT(connp->conn_flags & IPCL_TCPCONN);

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
}

/*
 * Cleaup before placing on free list.
 * Disassociate from the netstack/tcp_stack_t since the freelist
 * is per squeue and not per netstack.
 */
void
tcp_cleanup(tcp_t *tcp)
{
	mblk_t		*mp;
	conn_t		*connp = tcp->tcp_connp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	netstack_t	*ns = tcps->tcps_netstack;
	mblk_t		*tcp_rsrv_mp;

	tcp_bind_hash_remove(tcp);

	/* Cleanup that which needs the netstack first */
	tcp_ipsec_cleanup(tcp);
	ixa_cleanup(connp->conn_ixa);

	if (connp->conn_ht_iphc != NULL) {
		kmem_free(connp->conn_ht_iphc, connp->conn_ht_iphc_allocated);
		connp->conn_ht_iphc = NULL;
		connp->conn_ht_iphc_allocated = 0;
		connp->conn_ht_iphc_len = 0;
		connp->conn_ht_ulp = NULL;
		connp->conn_ht_ulp_len = 0;
		tcp->tcp_ipha = NULL;
		tcp->tcp_ip6h = NULL;
		tcp->tcp_tcpha = NULL;
	}

	/* We clear any IP_OPTIONS and extension headers */
	ip_pkt_free(&connp->conn_xmit_ipp);

	tcp_free(tcp);

	/*
	 * Since we will bzero the entire structure, we need to
	 * remove it and reinsert it in global hash list. We
	 * know the walkers can't get to this conn because we
	 * had set CONDEMNED flag earlier and checked reference
	 * under conn_lock so walker won't pick it and when we
	 * go the ipcl_globalhash_remove() below, no walker
	 * can get to it.
	 */
	ipcl_globalhash_remove(connp);

	/* Save some state */
	mp = tcp->tcp_timercache;

	tcp_rsrv_mp = tcp->tcp_rsrv_mp;

	if (connp->conn_cred != NULL) {
		crfree(connp->conn_cred);
		connp->conn_cred = NULL;
	}
	ipcl_conn_cleanup(connp);
	connp->conn_flags = IPCL_TCPCONN;

	/*
	 * Now it is safe to decrement the reference counts.
	 * This might be the last reference on the netstack
	 * in which case it will cause the freeing of the IP Instance.
	 */
	connp->conn_netstack = NULL;
	connp->conn_ixa->ixa_ipst = NULL;
	netstack_rele(ns);
	ASSERT(tcps != NULL);
	tcp->tcp_tcps = NULL;

	bzero(tcp, sizeof (tcp_t));

	/* restore the state */
	tcp->tcp_timercache = mp;

	tcp->tcp_rsrv_mp = tcp_rsrv_mp;

	tcp->tcp_connp = connp;

	ASSERT(connp->conn_tcp == tcp);
	ASSERT(connp->conn_flags & IPCL_TCPCONN);
	connp->conn_state_flags = CONN_INCIPIENT;
	ASSERT(connp->conn_proto == IPPROTO_TCP);
	ASSERT(connp->conn_ref == 1);
}

/*
 * Adapt to the information, such as rtt and rtt_sd, provided from the
 * DCE and IRE maintained by IP.
 *
 * Checks for multicast and broadcast destination address.
 * Returns zero if ok; an errno on failure.
 *
 * Note that the MSS calculation here is based on the info given in
 * the DCE and IRE.  We do not do any calculation based on TCP options.  They
 * will be handled in tcp_input_data() when TCP knows which options to use.
 *
 * Note on how TCP gets its parameters for a connection.
 *
 * When a tcp_t structure is allocated, it gets all the default parameters.
 * In tcp_set_destination(), it gets those metric parameters, like rtt, rtt_sd,
 * spipe, rpipe, ... from the route metrics.  Route metric overrides the
 * default.
 *
 * An incoming SYN with a multicast or broadcast destination address is dropped
 * in ip_fanout_v4/v6.
 *
 * An incoming SYN with a multicast or broadcast source address is always
 * dropped in tcp_set_destination, since IPDF_ALLOW_MCBC is not set in
 * conn_connect.
 * The same logic in tcp_set_destination also serves to
 * reject an attempt to connect to a broadcast or multicast (destination)
 * address.
 */
int
tcp_set_destination(tcp_t *tcp)
{
	uint32_t	mss_max;
	uint32_t	mss;
	boolean_t	tcp_detached = TCP_IS_DETACHED(tcp);
	conn_t		*connp = tcp->tcp_connp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	iulp_t		uinfo;
	int		error;
	uint32_t	flags;

	flags = IPDF_LSO | IPDF_ZCOPY;
	/*
	 * Make sure we have a dce for the destination to avoid dce_ident
	 * contention for connected sockets.
	 */
	flags |= IPDF_UNIQUE_DCE;

	if (!tcps->tcps_ignore_path_mtu)
		connp->conn_ixa->ixa_flags |= IXAF_PMTU_DISCOVERY;

	/* Use conn_lock to satify ASSERT; tcp is already serialized */
	mutex_enter(&connp->conn_lock);
	error = conn_connect(connp, &uinfo, flags);
	mutex_exit(&connp->conn_lock);
	if (error != 0)
		return (error);

	error = tcp_build_hdrs(tcp);
	if (error != 0)
		return (error);

	tcp->tcp_localnet = uinfo.iulp_localnet;

	if (uinfo.iulp_rtt != 0) {
		clock_t	rto;

		tcp->tcp_rtt_sa = uinfo.iulp_rtt;
		tcp->tcp_rtt_sd = uinfo.iulp_rtt_sd;
		rto = (tcp->tcp_rtt_sa >> 3) + tcp->tcp_rtt_sd +
		    tcps->tcps_rexmit_interval_extra +
		    (tcp->tcp_rtt_sa >> 5);

		TCP_SET_RTO(tcp, rto);
	}
	if (uinfo.iulp_ssthresh != 0)
		tcp->tcp_cwnd_ssthresh = uinfo.iulp_ssthresh;
	else
		tcp->tcp_cwnd_ssthresh = TCP_MAX_LARGEWIN;
	if (uinfo.iulp_spipe > 0) {
		connp->conn_sndbuf = MIN(uinfo.iulp_spipe,
		    tcps->tcps_max_buf);
		if (tcps->tcps_snd_lowat_fraction != 0) {
			connp->conn_sndlowat = connp->conn_sndbuf /
			    tcps->tcps_snd_lowat_fraction;
		}
		(void) tcp_maxpsz_set(tcp, B_TRUE);
	}
	/*
	 * Note that up till now, acceptor always inherits receive
	 * window from the listener.  But if there is a metrics
	 * associated with a host, we should use that instead of
	 * inheriting it from listener. Thus we need to pass this
	 * info back to the caller.
	 */
	if (uinfo.iulp_rpipe > 0) {
		tcp->tcp_rwnd = MIN(uinfo.iulp_rpipe,
		    tcps->tcps_max_buf);
	}

	if (uinfo.iulp_rtomax > 0) {
		tcp->tcp_second_timer_threshold =
		    uinfo.iulp_rtomax;
	}

	/*
	 * Use the metric option settings, iulp_tstamp_ok and
	 * iulp_wscale_ok, only for active open. What this means
	 * is that if the other side uses timestamp or window
	 * scale option, TCP will also use those options. That
	 * is for passive open.  If the application sets a
	 * large window, window scale is enabled regardless of
	 * the value in iulp_wscale_ok.  This is the behavior
	 * since 2.6.  So we keep it.
	 * The only case left in passive open processing is the
	 * check for SACK.
	 * For ECN, it should probably be like SACK.  But the
	 * current value is binary, so we treat it like the other
	 * cases.  The metric only controls active open.For passive
	 * open, the ndd param, tcp_ecn_permitted, controls the
	 * behavior.
	 */
	if (!tcp_detached) {
		/*
		 * The if check means that the following can only
		 * be turned on by the metrics only IRE, but not off.
		 */
		if (uinfo.iulp_tstamp_ok)
			tcp->tcp_snd_ts_ok = B_TRUE;
		if (uinfo.iulp_wscale_ok)
			tcp->tcp_snd_ws_ok = B_TRUE;
		if (uinfo.iulp_sack == 2)
			tcp->tcp_snd_sack_ok = B_TRUE;
		if (uinfo.iulp_ecn_ok)
			tcp->tcp_ecn_ok = B_TRUE;
	} else {
		/*
		 * Passive open.
		 *
		 * As above, the if check means that SACK can only be
		 * turned on by the metric only IRE.
		 */
		if (uinfo.iulp_sack > 0) {
			tcp->tcp_snd_sack_ok = B_TRUE;
		}
	}

	/*
	 * XXX Note that currently, iulp_mtu can be as small as 68
	 * because of PMTUd.  So tcp_mss may go to negative if combined
	 * length of all those options exceeds 28 bytes.  But because
	 * of the tcp_mss_min check below, we may not have a problem if
	 * tcp_mss_min is of a reasonable value.  The default is 1 so
	 * the negative problem still exists.  And the check defeats PMTUd.
	 * In fact, if PMTUd finds that the MSS should be smaller than
	 * tcp_mss_min, TCP should turn off PMUTd and use the tcp_mss_min
	 * value.
	 *
	 * We do not deal with that now.  All those problems related to
	 * PMTUd will be fixed later.
	 */
	ASSERT(uinfo.iulp_mtu != 0);
	mss = tcp->tcp_initial_pmtu = uinfo.iulp_mtu;

	/* Sanity check for MSS value. */
	if (connp->conn_ipversion == IPV4_VERSION)
		mss_max = tcps->tcps_mss_max_ipv4;
	else
		mss_max = tcps->tcps_mss_max_ipv6;

	if (tcp->tcp_ipsec_overhead == 0)
		tcp->tcp_ipsec_overhead = conn_ipsec_length(connp);

	mss -= tcp->tcp_ipsec_overhead;

	if (mss < tcps->tcps_mss_min)
		mss = tcps->tcps_mss_min;
	if (mss > mss_max)
		mss = mss_max;

	/* Note that this is the maximum MSS, excluding all options. */
	tcp->tcp_mss = mss;

	/*
	 * Update the tcp connection with LSO capability.
	 */
	tcp_update_lso(tcp, connp->conn_ixa);

	/*
	 * Initialize the ISS here now that we have the full connection ID.
	 * The RFC 1948 method of initial sequence number generation requires
	 * knowledge of the full connection ID before setting the ISS.
	 */
	tcp_iss_init(tcp);

	tcp->tcp_loopback = (uinfo.iulp_loopback | uinfo.iulp_local);

	/*
	 * Make sure that conn is not marked incipient
	 * for incoming connections. A blind
	 * removal of incipient flag is cheaper than
	 * check and removal.
	 */
	mutex_enter(&connp->conn_lock);
	connp->conn_state_flags &= ~CONN_INCIPIENT;
	mutex_exit(&connp->conn_lock);
	return (0);
}

/*
 * tcp_clean_death / tcp_close_detached must not be called more than once
 * on a tcp. Thus every function that potentially calls tcp_clean_death
 * must check for the tcp state before calling tcp_clean_death.
 * Eg. tcp_input_data, tcp_eager_kill, tcp_clean_death_wrapper,
 * tcp_timer_handler, all check for the tcp state.
 */
/* ARGSUSED */
void
tcp_clean_death_wrapper(void *arg, mblk_t *mp, void *arg2,
    ip_recv_attr_t *dummy)
{
	tcp_t	*tcp = ((conn_t *)arg)->conn_tcp;

	freemsg(mp);
	if (tcp->tcp_state > TCPS_BOUND)
		(void) tcp_clean_death(((conn_t *)arg)->conn_tcp, ETIMEDOUT);
}

/*
 * We are dying for some reason.  Try to do it gracefully.  (May be called
 * as writer.)
 *
 * Return -1 if the structure was not cleaned up (if the cleanup had to be
 * done by a service procedure).
 * TBD - Should the return value distinguish between the tcp_t being
 * freed and it being reinitialized?
 */
int
tcp_clean_death(tcp_t *tcp, int err)
{
	mblk_t	*mp;
	queue_t	*q;
	conn_t	*connp = tcp->tcp_connp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	if (tcp->tcp_fused)
		tcp_unfuse(tcp);

	if (tcp->tcp_linger_tid != 0 &&
	    TCP_TIMER_CANCEL(tcp, tcp->tcp_linger_tid) >= 0) {
		tcp_stop_lingering(tcp);
	}

	ASSERT(tcp != NULL);
	ASSERT((connp->conn_family == AF_INET &&
	    connp->conn_ipversion == IPV4_VERSION) ||
	    (connp->conn_family == AF_INET6 &&
	    (connp->conn_ipversion == IPV4_VERSION ||
	    connp->conn_ipversion == IPV6_VERSION)));

	if (TCP_IS_DETACHED(tcp)) {
		if (tcp->tcp_hard_binding) {
			/*
			 * Its an eager that we are dealing with. We close the
			 * eager but in case a conn_ind has already gone to the
			 * listener, let tcp_accept_finish() send a discon_ind
			 * to the listener and drop the last reference. If the
			 * listener doesn't even know about the eager i.e. the
			 * conn_ind hasn't gone up, blow away the eager and drop
			 * the last reference as well. If the conn_ind has gone
			 * up, state should be BOUND. tcp_accept_finish
			 * will figure out that the connection has received a
			 * RST and will send a DISCON_IND to the application.
			 */
			tcp_closei_local(tcp);
			if (!tcp->tcp_tconnind_started) {
				CONN_DEC_REF(connp);
			} else {
				tcp->tcp_state = TCPS_BOUND;
				DTRACE_TCP6(state__change, void, NULL,
				    ip_xmit_attr_t *, connp->conn_ixa,
				    void, NULL, tcp_t *, tcp, void, NULL,
				    int32_t, TCPS_CLOSED);
			}
		} else {
			tcp_close_detached(tcp);
		}
		return (0);
	}

	TCP_STAT(tcps, tcp_clean_death_nondetached);

	/*
	 * The connection is dead.  Decrement listener connection counter if
	 * necessary.
	 */
	if (tcp->tcp_listen_cnt != NULL)
		TCP_DECR_LISTEN_CNT(tcp);

	/*
	 * When a connection is moved to TIME_WAIT state, the connection
	 * counter is already decremented.  So no need to decrement here
	 * again.  See SET_TIME_WAIT() macro.
	 */
	if (tcp->tcp_state >= TCPS_ESTABLISHED &&
	    tcp->tcp_state < TCPS_TIME_WAIT) {
		TCPS_CONN_DEC(tcps);
	}

	q = connp->conn_rq;

	/* Trash all inbound data */
	if (!IPCL_IS_NONSTR(connp)) {
		ASSERT(q != NULL);
		flushq(q, FLUSHALL);
	}

	/*
	 * If we are at least part way open and there is error
	 * (err==0 implies no error)
	 * notify our client by a T_DISCON_IND.
	 */
	if ((tcp->tcp_state >= TCPS_SYN_SENT) && err) {
		if (tcp->tcp_state >= TCPS_ESTABLISHED &&
		    !TCP_IS_SOCKET(tcp)) {
			/*
			 * Send M_FLUSH according to TPI. Because sockets will
			 * (and must) ignore FLUSHR we do that only for TPI
			 * endpoints and sockets in STREAMS mode.
			 */
			(void) putnextctl1(q, M_FLUSH, FLUSHR);
		}
		if (connp->conn_debug) {
			(void) strlog(TCP_MOD_ID, 0, 1, SL_TRACE|SL_ERROR,
			    "tcp_clean_death: discon err %d", err);
		}
		if (IPCL_IS_NONSTR(connp)) {
			/* Direct socket, use upcall */
			(*connp->conn_upcalls->su_disconnected)(
			    connp->conn_upper_handle, tcp->tcp_connid, err);
		} else {
			mp = mi_tpi_discon_ind(NULL, err, 0);
			if (mp != NULL) {
				putnext(q, mp);
			} else {
				if (connp->conn_debug) {
					(void) strlog(TCP_MOD_ID, 0, 1,
					    SL_ERROR|SL_TRACE,
					    "tcp_clean_death, sending M_ERROR");
				}
				(void) putnextctl1(q, M_ERROR, EPROTO);
			}
		}
		if (tcp->tcp_state <= TCPS_SYN_RCVD) {
			/* SYN_SENT or SYN_RCVD */
			TCPS_BUMP_MIB(tcps, tcpAttemptFails);
		} else if (tcp->tcp_state <= TCPS_CLOSE_WAIT) {
			/* ESTABLISHED or CLOSE_WAIT */
			TCPS_BUMP_MIB(tcps, tcpEstabResets);
		}
	}

	/*
	 * ESTABLISHED non-STREAMS eagers are not 'detached' because
	 * an upper handle is obtained when the SYN-ACK comes in. So it
	 * should receive the 'disconnected' upcall, but tcp_reinit should
	 * not be called since this is an eager.
	 */
	if (tcp->tcp_listener != NULL && IPCL_IS_NONSTR(connp)) {
		tcp_closei_local(tcp);
		tcp->tcp_state = TCPS_BOUND;
		DTRACE_TCP6(state__change, void, NULL, ip_xmit_attr_t *,
		    connp->conn_ixa, void, NULL, tcp_t *, tcp, void, NULL,
		    int32_t, TCPS_CLOSED);
		return (0);
	}

	tcp_reinit(tcp);
	if (IPCL_IS_NONSTR(connp))
		(void) tcp_do_unbind(connp);

	return (-1);
}

/*
 * In case tcp is in the "lingering state" and waits for the SO_LINGER timeout
 * to expire, stop the wait and finish the close.
 */
void
tcp_stop_lingering(tcp_t *tcp)
{
	clock_t	delta = 0;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	conn_t		*connp = tcp->tcp_connp;

	tcp->tcp_linger_tid = 0;
	if (tcp->tcp_state > TCPS_LISTEN) {
		tcp_acceptor_hash_remove(tcp);
		mutex_enter(&tcp->tcp_non_sq_lock);
		if (tcp->tcp_flow_stopped) {
			tcp_clrqfull(tcp);
		}
		mutex_exit(&tcp->tcp_non_sq_lock);

		if (tcp->tcp_timer_tid != 0) {
			delta = TCP_TIMER_CANCEL(tcp, tcp->tcp_timer_tid);
			tcp->tcp_timer_tid = 0;
		}
		/*
		 * Need to cancel those timers which will not be used when
		 * TCP is detached.  This has to be done before the conn_wq
		 * is cleared.
		 */
		tcp_timers_stop(tcp);

		tcp->tcp_detached = B_TRUE;
		connp->conn_rq = NULL;
		connp->conn_wq = NULL;

		if (tcp->tcp_state == TCPS_TIME_WAIT) {
			tcp_time_wait_append(tcp);
			TCP_DBGSTAT(tcps, tcp_detach_time_wait);
			goto finish;
		}

		/*
		 * If delta is zero the timer event wasn't executed and was
		 * successfully canceled. In this case we need to restart it
		 * with the minimal delta possible.
		 */
		if (delta >= 0) {
			tcp->tcp_timer_tid = TCP_TIMER(tcp, tcp_timer,
			    delta ? delta : 1);
		}
	} else {
		tcp_closei_local(tcp);
		CONN_DEC_REF(connp);
	}
finish:
	tcp->tcp_detached = B_TRUE;
	connp->conn_rq = NULL;
	connp->conn_wq = NULL;

	/* Signal closing thread that it can complete close */
	mutex_enter(&tcp->tcp_closelock);
	tcp->tcp_closed = 1;
	cv_signal(&tcp->tcp_closecv);
	mutex_exit(&tcp->tcp_closelock);

	/* If we have an upper handle (socket), release it */
	if (IPCL_IS_NONSTR(connp)) {
		ASSERT(connp->conn_upper_handle != NULL);
		(*connp->conn_upcalls->su_closed)(connp->conn_upper_handle);
		connp->conn_upper_handle = NULL;
		connp->conn_upcalls = NULL;
	}
}

void
tcp_close_common(conn_t *connp, int flags)
{
	tcp_t		*tcp = connp->conn_tcp;
	mblk_t 		*mp = &tcp->tcp_closemp;
	boolean_t	conn_ioctl_cleanup_reqd = B_FALSE;
	mblk_t		*bp;

	ASSERT(connp->conn_ref >= 2);

	/*
	 * Mark the conn as closing. ipsq_pending_mp_add will not
	 * add any mp to the pending mp list, after this conn has
	 * started closing.
	 */
	mutex_enter(&connp->conn_lock);
	connp->conn_state_flags |= CONN_CLOSING;
	if (connp->conn_oper_pending_ill != NULL)
		conn_ioctl_cleanup_reqd = B_TRUE;
	CONN_INC_REF_LOCKED(connp);
	mutex_exit(&connp->conn_lock);
	tcp->tcp_closeflags = (uint8_t)flags;
	ASSERT(connp->conn_ref >= 3);

	/*
	 * tcp_closemp_used is used below without any protection of a lock
	 * as we don't expect any one else to use it concurrently at this
	 * point otherwise it would be a major defect.
	 */

	if (mp->b_prev == NULL)
		tcp->tcp_closemp_used = B_TRUE;
	else
		cmn_err(CE_PANIC, "tcp_close: concurrent use of tcp_closemp: "
		    "connp %p tcp %p\n", (void *)connp, (void *)tcp);

	TCP_DEBUG_GETPCSTACK(tcp->tcmp_stk, 15);

	/*
	 * Cleanup any queued ioctls here. This must be done before the wq/rq
	 * are re-written by tcp_close_output().
	 */
	if (conn_ioctl_cleanup_reqd)
		conn_ioctl_cleanup(connp);

	/*
	 * As CONN_CLOSING is set, no further ioctls should be passed down to
	 * IP for this conn (see the guards in tcp_ioctl, tcp_wput_ioctl and
	 * tcp_wput_iocdata). If the ioctl was queued on an ipsq,
	 * conn_ioctl_cleanup should have found it and removed it. If the ioctl
	 * was still in flight at the time, we wait for it here. See comments
	 * for CONN_INC_IOCTLREF in ip.h for details.
	 */
	mutex_enter(&connp->conn_lock);
	while (connp->conn_ioctlref > 0)
		cv_wait(&connp->conn_cv, &connp->conn_lock);
	ASSERT(connp->conn_ioctlref == 0);
	ASSERT(connp->conn_oper_pending_ill == NULL);
	mutex_exit(&connp->conn_lock);

	SQUEUE_ENTER_ONE(connp->conn_sqp, mp, tcp_close_output, connp,
	    NULL, tcp_squeue_flag, SQTAG_IP_TCP_CLOSE);

	/*
	 * For non-STREAMS sockets, the normal case is that the conn makes
	 * an upcall when it's finally closed, so there is no need to wait
	 * in the protocol. But in case of SO_LINGER the thread sleeps here
	 * so it can properly deal with the thread being interrupted.
	 */
	if (IPCL_IS_NONSTR(connp) && connp->conn_linger == 0)
		goto nowait;

	mutex_enter(&tcp->tcp_closelock);
	while (!tcp->tcp_closed) {
		if (!cv_wait_sig(&tcp->tcp_closecv, &tcp->tcp_closelock)) {
			/*
			 * The cv_wait_sig() was interrupted. We now do the
			 * following:
			 *
			 * 1) If the endpoint was lingering, we allow this
			 * to be interrupted by cancelling the linger timeout
			 * and closing normally.
			 *
			 * 2) Revert to calling cv_wait()
			 *
			 * We revert to using cv_wait() to avoid an
			 * infinite loop which can occur if the calling
			 * thread is higher priority than the squeue worker
			 * thread and is bound to the same cpu.
			 */
			if (connp->conn_linger && connp->conn_lingertime > 0) {
				mutex_exit(&tcp->tcp_closelock);
				/* Entering squeue, bump ref count. */
				CONN_INC_REF(connp);
				bp = allocb_wait(0, BPRI_HI, STR_NOSIG, NULL);
				SQUEUE_ENTER_ONE(connp->conn_sqp, bp,
				    tcp_linger_interrupted, connp, NULL,
				    tcp_squeue_flag, SQTAG_IP_TCP_CLOSE);
				mutex_enter(&tcp->tcp_closelock);
			}
			break;
		}
	}
	while (!tcp->tcp_closed)
		cv_wait(&tcp->tcp_closecv, &tcp->tcp_closelock);
	mutex_exit(&tcp->tcp_closelock);

	/*
	 * In the case of listener streams that have eagers in the q or q0
	 * we wait for the eagers to drop their reference to us. conn_rq and
	 * conn_wq of the eagers point to our queues. By waiting for the
	 * refcnt to drop to 1, we are sure that the eagers have cleaned
	 * up their queue pointers and also dropped their references to us.
	 *
	 * For non-STREAMS sockets we do not have to wait here; the
	 * listener will instead make a su_closed upcall when the last
	 * reference is dropped.
	 */
	if (tcp->tcp_wait_for_eagers && !IPCL_IS_NONSTR(connp)) {
		mutex_enter(&connp->conn_lock);
		while (connp->conn_ref != 1) {
			cv_wait(&connp->conn_cv, &connp->conn_lock);
		}
		mutex_exit(&connp->conn_lock);
	}

nowait:
	connp->conn_cpid = NOPID;
}

/*
 * Called by tcp_close() routine via squeue when lingering is
 * interrupted by a signal.
 */

/* ARGSUSED */
static void
tcp_linger_interrupted(void *arg, mblk_t *mp, void *arg2, ip_recv_attr_t *dummy)
{
	conn_t	*connp = (conn_t *)arg;
	tcp_t	*tcp = connp->conn_tcp;

	freeb(mp);
	if (tcp->tcp_linger_tid != 0 &&
	    TCP_TIMER_CANCEL(tcp, tcp->tcp_linger_tid) >= 0) {
		tcp_stop_lingering(tcp);
		tcp->tcp_client_errno = EINTR;
	}
}

/*
 * Clean up the b_next and b_prev fields of every mblk pointed at by *mpp.
 * Some stream heads get upset if they see these later on as anything but NULL.
 */
void
tcp_close_mpp(mblk_t **mpp)
{
	mblk_t	*mp;

	if ((mp = *mpp) != NULL) {
		do {
			mp->b_next = NULL;
			mp->b_prev = NULL;
		} while ((mp = mp->b_cont) != NULL);

		mp = *mpp;
		*mpp = NULL;
		freemsg(mp);
	}
}

/* Do detached close. */
void
tcp_close_detached(tcp_t *tcp)
{
	if (tcp->tcp_fused)
		tcp_unfuse(tcp);

	/*
	 * Clustering code serializes TCP disconnect callbacks and
	 * cluster tcp list walks by blocking a TCP disconnect callback
	 * if a cluster tcp list walk is in progress. This ensures
	 * accurate accounting of TCPs in the cluster code even though
	 * the TCP list walk itself is not atomic.
	 */
	tcp_closei_local(tcp);
	CONN_DEC_REF(tcp->tcp_connp);
}

/*
 * The tcp_t is going away. Remove it from all lists and set it
 * to TCPS_CLOSED. The freeing up of memory is deferred until
 * tcp_inactive. This is needed since a thread in tcp_rput might have
 * done a CONN_INC_REF on this structure before it was removed from the
 * hashes.
 */
void
tcp_closei_local(tcp_t *tcp)
{
	conn_t		*connp = tcp->tcp_connp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	int32_t		oldstate;

	if (!TCP_IS_SOCKET(tcp))
		tcp_acceptor_hash_remove(tcp);

	TCPS_UPDATE_MIB(tcps, tcpHCInSegs, tcp->tcp_ibsegs);
	tcp->tcp_ibsegs = 0;
	TCPS_UPDATE_MIB(tcps, tcpHCOutSegs, tcp->tcp_obsegs);
	tcp->tcp_obsegs = 0;

	/*
	 * This can be called via tcp_time_wait_processing() if TCP gets a
	 * SYN with sequence number outside the TIME-WAIT connection's
	 * window.  So we need to check for TIME-WAIT state here as the
	 * connection counter is already decremented.  See SET_TIME_WAIT()
	 * macro
	 */
	if (tcp->tcp_state >= TCPS_ESTABLISHED &&
	    tcp->tcp_state < TCPS_TIME_WAIT) {
		TCPS_CONN_DEC(tcps);
	}

	/*
	 * If we are an eager connection hanging off a listener that
	 * hasn't formally accepted the connection yet, get off his
	 * list and blow off any data that we have accumulated.
	 */
	if (tcp->tcp_listener != NULL) {
		tcp_t	*listener = tcp->tcp_listener;
		mutex_enter(&listener->tcp_eager_lock);
		/*
		 * tcp_tconnind_started == B_TRUE means that the
		 * conn_ind has already gone to listener. At
		 * this point, eager will be closed but we
		 * leave it in listeners eager list so that
		 * if listener decides to close without doing
		 * accept, we can clean this up. In tcp_tli_accept
		 * we take care of the case of accept on closed
		 * eager.
		 */
		if (!tcp->tcp_tconnind_started) {
			tcp_eager_unlink(tcp);
			mutex_exit(&listener->tcp_eager_lock);
			/*
			 * We don't want to have any pointers to the
			 * listener queue, after we have released our
			 * reference on the listener
			 */
			ASSERT(tcp->tcp_detached);
			connp->conn_rq = NULL;
			connp->conn_wq = NULL;
			CONN_DEC_REF(listener->tcp_connp);
		} else {
			mutex_exit(&listener->tcp_eager_lock);
		}
	}

	/* Stop all the timers */
	tcp_timers_stop(tcp);

	if (tcp->tcp_state == TCPS_LISTEN) {
		if (tcp->tcp_ip_addr_cache) {
			kmem_free((void *)tcp->tcp_ip_addr_cache,
			    IP_ADDR_CACHE_SIZE * sizeof (ipaddr_t));
			tcp->tcp_ip_addr_cache = NULL;
		}
	}

	/* Decrement listerner connection counter if necessary. */
	if (tcp->tcp_listen_cnt != NULL)
		TCP_DECR_LISTEN_CNT(tcp);

	mutex_enter(&tcp->tcp_non_sq_lock);
	if (tcp->tcp_flow_stopped)
		tcp_clrqfull(tcp);
	mutex_exit(&tcp->tcp_non_sq_lock);

	tcp_bind_hash_remove(tcp);
	/*
	 * If the tcp_time_wait_collector (which runs outside the squeue)
	 * is trying to remove this tcp from the time wait list, we will
	 * block in tcp_time_wait_remove while trying to acquire the
	 * tcp_time_wait_lock. The logic in tcp_time_wait_collector also
	 * requires the ipcl_hash_remove to be ordered after the
	 * tcp_time_wait_remove for the refcnt checks to work correctly.
	 */
	if (tcp->tcp_state == TCPS_TIME_WAIT)
		(void) tcp_time_wait_remove(tcp, NULL);
	CL_INET_DISCONNECT(connp);
	ipcl_hash_remove(connp);
	oldstate = tcp->tcp_state;
	tcp->tcp_state = TCPS_CLOSED;
	/* Need to probe before ixa_cleanup() is called */
	DTRACE_TCP6(state__change, void, NULL, ip_xmit_attr_t *,
	    connp->conn_ixa, void, NULL, tcp_t *, tcp, void, NULL,
	    int32_t, oldstate);
	ixa_cleanup(connp->conn_ixa);

	/*
	 * Mark the conn as CONDEMNED
	 */
	mutex_enter(&connp->conn_lock);
	connp->conn_state_flags |= CONN_CONDEMNED;
	mutex_exit(&connp->conn_lock);

	ASSERT(tcp->tcp_time_wait_next == NULL);
	ASSERT(tcp->tcp_time_wait_prev == NULL);
	ASSERT(tcp->tcp_time_wait_expire == 0);

	tcp_ipsec_cleanup(tcp);
}

/*
 * tcp is dying (called from ipcl_conn_destroy and error cases).
 * Free the tcp_t in either case.
 */
void
tcp_free(tcp_t *tcp)
{
	mblk_t		*mp;
	conn_t		*connp = tcp->tcp_connp;

	ASSERT(tcp != NULL);
	ASSERT(tcp->tcp_ptpahn == NULL && tcp->tcp_acceptor_hash == NULL);

	connp->conn_rq = NULL;
	connp->conn_wq = NULL;

	tcp_close_mpp(&tcp->tcp_xmit_head);
	tcp_close_mpp(&tcp->tcp_reass_head);
	if (tcp->tcp_rcv_list != NULL) {
		/* Free b_next chain */
		tcp_close_mpp(&tcp->tcp_rcv_list);
	}
	if ((mp = tcp->tcp_urp_mp) != NULL) {
		freemsg(mp);
	}
	if ((mp = tcp->tcp_urp_mark_mp) != NULL) {
		freemsg(mp);
	}

	if (tcp->tcp_fused_sigurg_mp != NULL) {
		ASSERT(!IPCL_IS_NONSTR(tcp->tcp_connp));
		freeb(tcp->tcp_fused_sigurg_mp);
		tcp->tcp_fused_sigurg_mp = NULL;
	}

	if (tcp->tcp_ordrel_mp != NULL) {
		ASSERT(!IPCL_IS_NONSTR(tcp->tcp_connp));
		freeb(tcp->tcp_ordrel_mp);
		tcp->tcp_ordrel_mp = NULL;
	}

	TCP_NOTSACK_REMOVE_ALL(tcp->tcp_notsack_list, tcp);
	bzero(&tcp->tcp_sack_info, sizeof (tcp_sack_info_t));

	if (tcp->tcp_hopopts != NULL) {
		mi_free(tcp->tcp_hopopts);
		tcp->tcp_hopopts = NULL;
		tcp->tcp_hopoptslen = 0;
	}
	ASSERT(tcp->tcp_hopoptslen == 0);
	if (tcp->tcp_dstopts != NULL) {
		mi_free(tcp->tcp_dstopts);
		tcp->tcp_dstopts = NULL;
		tcp->tcp_dstoptslen = 0;
	}
	ASSERT(tcp->tcp_dstoptslen == 0);
	if (tcp->tcp_rthdrdstopts != NULL) {
		mi_free(tcp->tcp_rthdrdstopts);
		tcp->tcp_rthdrdstopts = NULL;
		tcp->tcp_rthdrdstoptslen = 0;
	}
	ASSERT(tcp->tcp_rthdrdstoptslen == 0);
	if (tcp->tcp_rthdr != NULL) {
		mi_free(tcp->tcp_rthdr);
		tcp->tcp_rthdr = NULL;
		tcp->tcp_rthdrlen = 0;
	}
	ASSERT(tcp->tcp_rthdrlen == 0);

	/*
	 * Following is really a blowing away a union.
	 * It happens to have exactly two members of identical size
	 * the following code is enough.
	 */
	tcp_close_mpp(&tcp->tcp_conn.tcp_eager_conn_ind);

	/*
	 * If this is a non-STREAM socket still holding on to an upper
	 * handle, release it. As a result of fallback we might also see
	 * STREAMS based conns with upper handles, in which case there is
	 * nothing to do other than clearing the field.
	 */
	if (connp->conn_upper_handle != NULL) {
		if (IPCL_IS_NONSTR(connp)) {
			(*connp->conn_upcalls->su_closed)(
			    connp->conn_upper_handle);
			tcp->tcp_detached = B_TRUE;
		}
		connp->conn_upper_handle = NULL;
		connp->conn_upcalls = NULL;
	}
}

/*
 * tcp_get_conn/tcp_free_conn
 *
 * tcp_get_conn is used to get a clean tcp connection structure.
 * It tries to reuse the connections put on the freelist by the
 * time_wait_collector failing which it goes to kmem_cache. This
 * way has two benefits compared to just allocating from and
 * freeing to kmem_cache.
 * 1) The time_wait_collector can free (which includes the cleanup)
 * outside the squeue. So when the interrupt comes, we have a clean
 * connection sitting in the freelist. Obviously, this buys us
 * performance.
 *
 * 2) Defence against DOS attack. Allocating a tcp/conn in tcp_input_listener
 * has multiple disadvantages - tying up the squeue during alloc.
 * But allocating the conn/tcp in IP land is also not the best since
 * we can't check the 'q' and 'q0' which are protected by squeue and
 * blindly allocate memory which might have to be freed here if we are
 * not allowed to accept the connection. By using the freelist and
 * putting the conn/tcp back in freelist, we don't pay a penalty for
 * allocating memory without checking 'q/q0' and freeing it if we can't
 * accept the connection.
 *
 * Care should be taken to put the conn back in the same squeue's freelist
 * from which it was allocated. Best results are obtained if conn is
 * allocated from listener's squeue and freed to the same. Time wait
 * collector will free up the freelist is the connection ends up sitting
 * there for too long.
 */
void *
tcp_get_conn(void *arg, tcp_stack_t *tcps)
{
	tcp_t			*tcp = NULL;
	conn_t			*connp = NULL;
	squeue_t		*sqp = (squeue_t *)arg;
	tcp_squeue_priv_t 	*tcp_time_wait;
	netstack_t		*ns;
	mblk_t			*tcp_rsrv_mp = NULL;

	tcp_time_wait =
	    *((tcp_squeue_priv_t **)squeue_getprivate(sqp, SQPRIVATE_TCP));

	mutex_enter(&tcp_time_wait->tcp_time_wait_lock);
	tcp = tcp_time_wait->tcp_free_list;
	ASSERT((tcp != NULL) ^ (tcp_time_wait->tcp_free_list_cnt == 0));
	if (tcp != NULL) {
		tcp_time_wait->tcp_free_list = tcp->tcp_time_wait_next;
		tcp_time_wait->tcp_free_list_cnt--;
		mutex_exit(&tcp_time_wait->tcp_time_wait_lock);
		tcp->tcp_time_wait_next = NULL;
		connp = tcp->tcp_connp;
		connp->conn_flags |= IPCL_REUSED;

		ASSERT(tcp->tcp_tcps == NULL);
		ASSERT(connp->conn_netstack == NULL);
		ASSERT(tcp->tcp_rsrv_mp != NULL);
		ns = tcps->tcps_netstack;
		netstack_hold(ns);
		connp->conn_netstack = ns;
		connp->conn_ixa->ixa_ipst = ns->netstack_ip;
		tcp->tcp_tcps = tcps;
		ipcl_globalhash_insert(connp);

		connp->conn_ixa->ixa_notify_cookie = tcp;
		ASSERT(connp->conn_ixa->ixa_notify == tcp_notify);
		connp->conn_recv = tcp_input_data;
		ASSERT(connp->conn_recvicmp == tcp_icmp_input);
		ASSERT(connp->conn_verifyicmp == tcp_verifyicmp);
		return ((void *)connp);
	}
	mutex_exit(&tcp_time_wait->tcp_time_wait_lock);
	/*
	 * Pre-allocate the tcp_rsrv_mp. This mblk will not be freed until
	 * this conn_t/tcp_t is freed at ipcl_conn_destroy().
	 */
	tcp_rsrv_mp = allocb(0, BPRI_HI);
	if (tcp_rsrv_mp == NULL)
		return (NULL);

	if ((connp = ipcl_conn_create(IPCL_TCPCONN, KM_NOSLEEP,
	    tcps->tcps_netstack)) == NULL) {
		freeb(tcp_rsrv_mp);
		return (NULL);
	}

	tcp = connp->conn_tcp;
	tcp->tcp_rsrv_mp = tcp_rsrv_mp;
	mutex_init(&tcp->tcp_rsrv_mp_lock, NULL, MUTEX_DEFAULT, NULL);

	tcp->tcp_tcps = tcps;

	connp->conn_recv = tcp_input_data;
	connp->conn_recvicmp = tcp_icmp_input;
	connp->conn_verifyicmp = tcp_verifyicmp;

	/*
	 * Register tcp_notify to listen to capability changes detected by IP.
	 * This upcall is made in the context of the call to conn_ip_output
	 * thus it is inside the squeue.
	 */
	connp->conn_ixa->ixa_notify = tcp_notify;
	connp->conn_ixa->ixa_notify_cookie = tcp;

	return ((void *)connp);
}

/*
 * Handle connect to IPv4 destinations, including connections for AF_INET6
 * sockets connecting to IPv4 mapped IPv6 destinations.
 * Returns zero if OK, a positive errno, or a negative TLI error.
 */
static int
tcp_connect_ipv4(tcp_t *tcp, ipaddr_t *dstaddrp, in_port_t dstport,
    uint_t srcid)
{
	ipaddr_t 	dstaddr = *dstaddrp;
	uint16_t 	lport;
	conn_t		*connp = tcp->tcp_connp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	int		error;

	ASSERT(connp->conn_ipversion == IPV4_VERSION);

	/* Check for attempt to connect to INADDR_ANY */
	if (dstaddr == INADDR_ANY)  {
		/*
		 * SunOS 4.x and 4.3 BSD allow an application
		 * to connect a TCP socket to INADDR_ANY.
		 * When they do this, the kernel picks the
		 * address of one interface and uses it
		 * instead.  The kernel usually ends up
		 * picking the address of the loopback
		 * interface.  This is an undocumented feature.
		 * However, we provide the same thing here
		 * in order to have source and binary
		 * compatibility with SunOS 4.x.
		 * Update the T_CONN_REQ (sin/sin6) since it is used to
		 * generate the T_CONN_CON.
		 */
		dstaddr = htonl(INADDR_LOOPBACK);
		*dstaddrp = dstaddr;
	}

	/* Handle __sin6_src_id if socket not bound to an IP address */
	if (srcid != 0 && connp->conn_laddr_v4 == INADDR_ANY) {
		if (!ip_srcid_find_id(srcid, &connp->conn_laddr_v6,
		    IPCL_ZONEID(connp), B_TRUE, tcps->tcps_netstack)) {
			/* Mismatch - conn_laddr_v6 would be v6 address. */
			return (EADDRNOTAVAIL);
		}
		connp->conn_saddr_v6 = connp->conn_laddr_v6;
	}

	IN6_IPADDR_TO_V4MAPPED(dstaddr, &connp->conn_faddr_v6);
	connp->conn_fport = dstport;

	/*
	 * At this point the remote destination address and remote port fields
	 * in the tcp-four-tuple have been filled in the tcp structure. Now we
	 * have to see which state tcp was in so we can take appropriate action.
	 */
	if (tcp->tcp_state == TCPS_IDLE) {
		/*
		 * We support a quick connect capability here, allowing
		 * clients to transition directly from IDLE to SYN_SENT
		 * tcp_bindi will pick an unused port, insert the connection
		 * in the bind hash and transition to BOUND state.
		 */
		lport = tcp_update_next_port(tcps->tcps_next_port_to_try,
		    tcp, B_TRUE);
		lport = tcp_bindi(tcp, lport, &connp->conn_laddr_v6, 0, B_TRUE,
		    B_FALSE, B_FALSE);
		if (lport == 0)
			return (-TNOADDR);
	}

	/*
	 * Lookup the route to determine a source address and the uinfo.
	 * Setup TCP parameters based on the metrics/DCE.
	 */
	error = tcp_set_destination(tcp);
	if (error != 0)
		return (error);

	/*
	 * Don't let an endpoint connect to itself.
	 */
	if (connp->conn_faddr_v4 == connp->conn_laddr_v4 &&
	    connp->conn_fport == connp->conn_lport)
		return (-TBADADDR);

	tcp->tcp_state = TCPS_SYN_SENT;

	return (ipcl_conn_insert_v4(connp));
}

/*
 * Handle connect to IPv6 destinations.
 * Returns zero if OK, a positive errno, or a negative TLI error.
 */
static int
tcp_connect_ipv6(tcp_t *tcp, in6_addr_t *dstaddrp, in_port_t dstport,
    uint32_t flowinfo, uint_t srcid, uint32_t scope_id)
{
	uint16_t 	lport;
	conn_t		*connp = tcp->tcp_connp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	int		error;

	ASSERT(connp->conn_family == AF_INET6);

	/*
	 * If we're here, it means that the destination address is a native
	 * IPv6 address.  Return an error if conn_ipversion is not IPv6.  A
	 * reason why it might not be IPv6 is if the socket was bound to an
	 * IPv4-mapped IPv6 address.
	 */
	if (connp->conn_ipversion != IPV6_VERSION)
		return (-TBADADDR);

	/*
	 * Interpret a zero destination to mean loopback.
	 * Update the T_CONN_REQ (sin/sin6) since it is used to
	 * generate the T_CONN_CON.
	 */
	if (IN6_IS_ADDR_UNSPECIFIED(dstaddrp))
		*dstaddrp = ipv6_loopback;

	/* Handle __sin6_src_id if socket not bound to an IP address */
	if (srcid != 0 && IN6_IS_ADDR_UNSPECIFIED(&connp->conn_laddr_v6)) {
		if (!ip_srcid_find_id(srcid, &connp->conn_laddr_v6,
		    IPCL_ZONEID(connp), B_FALSE, tcps->tcps_netstack)) {
			/* Mismatch - conn_laddr_v6 would be v4-mapped. */
			return (EADDRNOTAVAIL);
		}
		connp->conn_saddr_v6 = connp->conn_laddr_v6;
	}

	/*
	 * Take care of the scope_id now.
	 */
	if (scope_id != 0 && IN6_IS_ADDR_LINKSCOPE(dstaddrp)) {
		connp->conn_ixa->ixa_flags |= IXAF_SCOPEID_SET;
		connp->conn_ixa->ixa_scopeid = scope_id;
	} else {
		connp->conn_ixa->ixa_flags &= ~IXAF_SCOPEID_SET;
	}

	connp->conn_flowinfo = flowinfo;
	connp->conn_faddr_v6 = *dstaddrp;
	connp->conn_fport = dstport;

	/*
	 * At this point the remote destination address and remote port fields
	 * in the tcp-four-tuple have been filled in the tcp structure. Now we
	 * have to see which state tcp was in so we can take appropriate action.
	 */
	if (tcp->tcp_state == TCPS_IDLE) {
		/*
		 * We support a quick connect capability here, allowing
		 * clients to transition directly from IDLE to SYN_SENT
		 * tcp_bindi will pick an unused port, insert the connection
		 * in the bind hash and transition to BOUND state.
		 */
		lport = tcp_update_next_port(tcps->tcps_next_port_to_try,
		    tcp, B_TRUE);
		lport = tcp_bindi(tcp, lport, &connp->conn_laddr_v6, 0, B_TRUE,
		    B_FALSE, B_FALSE);
		if (lport == 0)
			return (-TNOADDR);
	}

	/*
	 * Lookup the route to determine a source address and the uinfo.
	 * Setup TCP parameters based on the metrics/DCE.
	 */
	error = tcp_set_destination(tcp);
	if (error != 0)
		return (error);

	/*
	 * Don't let an endpoint connect to itself.
	 */
	if (IN6_ARE_ADDR_EQUAL(&connp->conn_faddr_v6, &connp->conn_laddr_v6) &&
	    connp->conn_fport == connp->conn_lport)
		return (-TBADADDR);

	tcp->tcp_state = TCPS_SYN_SENT;

	return (ipcl_conn_insert_v6(connp));
}

/*
 * Disconnect
 * Note that unlike other functions this returns a positive tli error
 * when it fails; it never returns an errno.
 */
static int
tcp_disconnect_common(tcp_t *tcp, t_scalar_t seqnum)
{
	conn_t		*lconnp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	conn_t		*connp = tcp->tcp_connp;

	/*
	 * Right now, upper modules pass down a T_DISCON_REQ to TCP,
	 * when the stream is in BOUND state. Do not send a reset,
	 * since the destination IP address is not valid, and it can
	 * be the initialized value of all zeros (broadcast address).
	 */
	if (tcp->tcp_state <= TCPS_BOUND) {
		if (connp->conn_debug) {
			(void) strlog(TCP_MOD_ID, 0, 1, SL_ERROR|SL_TRACE,
			    "tcp_disconnect: bad state, %d", tcp->tcp_state);
		}
		return (TOUTSTATE);
	} else if (tcp->tcp_state >= TCPS_ESTABLISHED) {
		TCPS_CONN_DEC(tcps);
	}

	if (seqnum == -1 || tcp->tcp_conn_req_max == 0) {

		/*
		 * According to TPI, for non-listeners, ignore seqnum
		 * and disconnect.
		 * Following interpretation of -1 seqnum is historical
		 * and implied TPI ? (TPI only states that for T_CONN_IND,
		 * a valid seqnum should not be -1).
		 *
		 *	-1 means disconnect everything
		 *	regardless even on a listener.
		 */

		int old_state = tcp->tcp_state;
		ip_stack_t *ipst = tcps->tcps_netstack->netstack_ip;

		/*
		 * The connection can't be on the tcp_time_wait_head list
		 * since it is not detached.
		 */
		ASSERT(tcp->tcp_time_wait_next == NULL);
		ASSERT(tcp->tcp_time_wait_prev == NULL);
		ASSERT(tcp->tcp_time_wait_expire == 0);
		/*
		 * If it used to be a listener, check to make sure no one else
		 * has taken the port before switching back to LISTEN state.
		 */
		if (connp->conn_ipversion == IPV4_VERSION) {
			lconnp = ipcl_lookup_listener_v4(connp->conn_lport,
			    connp->conn_laddr_v4, IPCL_ZONEID(connp), ipst);
		} else {
			uint_t ifindex = 0;

			if (connp->conn_ixa->ixa_flags & IXAF_SCOPEID_SET)
				ifindex = connp->conn_ixa->ixa_scopeid;

			/* Allow conn_bound_if listeners? */
			lconnp = ipcl_lookup_listener_v6(connp->conn_lport,
			    &connp->conn_laddr_v6, ifindex, IPCL_ZONEID(connp),
			    ipst);
		}
		if (tcp->tcp_conn_req_max && lconnp == NULL) {
			tcp->tcp_state = TCPS_LISTEN;
			DTRACE_TCP6(state__change, void, NULL, ip_xmit_attr_t *,
			    connp->conn_ixa, void, NULL, tcp_t *, tcp, void,
			    NULL, int32_t, old_state);
		} else if (old_state > TCPS_BOUND) {
			tcp->tcp_conn_req_max = 0;
			tcp->tcp_state = TCPS_BOUND;
			DTRACE_TCP6(state__change, void, NULL, ip_xmit_attr_t *,
			    connp->conn_ixa, void, NULL, tcp_t *, tcp, void,
			    NULL, int32_t, old_state);

			/*
			 * If this end point is not going to become a listener,
			 * decrement the listener connection count if
			 * necessary.  Note that we do not do this if it is
			 * going to be a listner (the above if case) since
			 * then it may remove the counter struct.
			 */
			if (tcp->tcp_listen_cnt != NULL)
				TCP_DECR_LISTEN_CNT(tcp);
		}
		if (lconnp != NULL)
			CONN_DEC_REF(lconnp);
		switch (old_state) {
		case TCPS_SYN_SENT:
		case TCPS_SYN_RCVD:
			TCPS_BUMP_MIB(tcps, tcpAttemptFails);
			break;
		case TCPS_ESTABLISHED:
		case TCPS_CLOSE_WAIT:
			TCPS_BUMP_MIB(tcps, tcpEstabResets);
			break;
		}

		if (tcp->tcp_fused)
			tcp_unfuse(tcp);

		mutex_enter(&tcp->tcp_eager_lock);
		if ((tcp->tcp_conn_req_cnt_q0 != 0) ||
		    (tcp->tcp_conn_req_cnt_q != 0)) {
			tcp_eager_cleanup(tcp, 0);
		}
		mutex_exit(&tcp->tcp_eager_lock);

		tcp_xmit_ctl("tcp_disconnect", tcp, tcp->tcp_snxt,
		    tcp->tcp_rnxt, TH_RST | TH_ACK);

		tcp_reinit(tcp);

		return (0);
	} else if (!tcp_eager_blowoff(tcp, seqnum)) {
		return (TBADSEQ);
	}
	return (0);
}

/*
 * Our client hereby directs us to reject the connection request
 * that tcp_input_listener() marked with 'seqnum'.  Rejection consists
 * of sending the appropriate RST, not an ICMP error.
 */
void
tcp_disconnect(tcp_t *tcp, mblk_t *mp)
{
	t_scalar_t seqnum;
	int	error;
	conn_t	*connp = tcp->tcp_connp;

	ASSERT((uintptr_t)(mp->b_wptr - mp->b_rptr) <= (uintptr_t)INT_MAX);
	if ((mp->b_wptr - mp->b_rptr) < sizeof (struct T_discon_req)) {
		tcp_err_ack(tcp, mp, TPROTO, 0);
		return;
	}
	seqnum = ((struct T_discon_req *)mp->b_rptr)->SEQ_number;
	error = tcp_disconnect_common(tcp, seqnum);
	if (error != 0)
		tcp_err_ack(tcp, mp, error, 0);
	else {
		if (tcp->tcp_state >= TCPS_ESTABLISHED) {
			/* Send M_FLUSH according to TPI */
			(void) putnextctl1(connp->conn_rq, M_FLUSH, FLUSHRW);
		}
		mp = mi_tpi_ok_ack_alloc(mp);
		if (mp != NULL)
			putnext(connp->conn_rq, mp);
	}
}

/*
 * Handle reinitialization of a tcp structure.
 * Maintain "binding state" resetting the state to BOUND, LISTEN, or IDLE.
 */
static void
tcp_reinit(tcp_t *tcp)
{
	mblk_t		*mp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	conn_t		*connp  = tcp->tcp_connp;
	int32_t		oldstate;

	/* tcp_reinit should never be called for detached tcp_t's */
	ASSERT(tcp->tcp_listener == NULL);
	ASSERT((connp->conn_family == AF_INET &&
	    connp->conn_ipversion == IPV4_VERSION) ||
	    (connp->conn_family == AF_INET6 &&
	    (connp->conn_ipversion == IPV4_VERSION ||
	    connp->conn_ipversion == IPV6_VERSION)));

	/* Cancel outstanding timers */
	tcp_timers_stop(tcp);

	/*
	 * Reset everything in the state vector, after updating global
	 * MIB data from instance counters.
	 */
	TCPS_UPDATE_MIB(tcps, tcpHCInSegs, tcp->tcp_ibsegs);
	tcp->tcp_ibsegs = 0;
	TCPS_UPDATE_MIB(tcps, tcpHCOutSegs, tcp->tcp_obsegs);
	tcp->tcp_obsegs = 0;

	tcp_close_mpp(&tcp->tcp_xmit_head);
	if (tcp->tcp_snd_zcopy_aware)
		tcp_zcopy_notify(tcp);
	tcp->tcp_xmit_last = tcp->tcp_xmit_tail = NULL;
	tcp->tcp_unsent = tcp->tcp_xmit_tail_unsent = 0;
	mutex_enter(&tcp->tcp_non_sq_lock);
	if (tcp->tcp_flow_stopped &&
	    TCP_UNSENT_BYTES(tcp) <= connp->conn_sndlowat) {
		tcp_clrqfull(tcp);
	}
	mutex_exit(&tcp->tcp_non_sq_lock);
	tcp_close_mpp(&tcp->tcp_reass_head);
	tcp->tcp_reass_tail = NULL;
	if (tcp->tcp_rcv_list != NULL) {
		/* Free b_next chain */
		tcp_close_mpp(&tcp->tcp_rcv_list);
		tcp->tcp_rcv_last_head = NULL;
		tcp->tcp_rcv_last_tail = NULL;
		tcp->tcp_rcv_cnt = 0;
	}
	tcp->tcp_rcv_last_tail = NULL;

	if ((mp = tcp->tcp_urp_mp) != NULL) {
		freemsg(mp);
		tcp->tcp_urp_mp = NULL;
	}
	if ((mp = tcp->tcp_urp_mark_mp) != NULL) {
		freemsg(mp);
		tcp->tcp_urp_mark_mp = NULL;
	}
	if (tcp->tcp_fused_sigurg_mp != NULL) {
		ASSERT(!IPCL_IS_NONSTR(tcp->tcp_connp));
		freeb(tcp->tcp_fused_sigurg_mp);
		tcp->tcp_fused_sigurg_mp = NULL;
	}
	if (tcp->tcp_ordrel_mp != NULL) {
		ASSERT(!IPCL_IS_NONSTR(tcp->tcp_connp));
		freeb(tcp->tcp_ordrel_mp);
		tcp->tcp_ordrel_mp = NULL;
	}

	/*
	 * Following is a union with two members which are
	 * identical types and size so the following cleanup
	 * is enough.
	 */
	tcp_close_mpp(&tcp->tcp_conn.tcp_eager_conn_ind);

	CL_INET_DISCONNECT(connp);

	/*
	 * The connection can't be on the tcp_time_wait_head list
	 * since it is not detached.
	 */
	ASSERT(tcp->tcp_time_wait_next == NULL);
	ASSERT(tcp->tcp_time_wait_prev == NULL);
	ASSERT(tcp->tcp_time_wait_expire == 0);

	/*
	 * Reset/preserve other values
	 */
	tcp_reinit_values(tcp);
	ipcl_hash_remove(connp);
	/* Note that ixa_cred gets cleared in ixa_cleanup */
	ixa_cleanup(connp->conn_ixa);
	tcp_ipsec_cleanup(tcp);

	connp->conn_laddr_v6 = connp->conn_bound_addr_v6;
	connp->conn_saddr_v6 = connp->conn_bound_addr_v6;
	oldstate = tcp->tcp_state;

	if (tcp->tcp_conn_req_max != 0) {
		/*
		 * This is the case when a TLI program uses the same
		 * transport end point to accept a connection.  This
		 * makes the TCP both a listener and acceptor.  When
		 * this connection is closed, we need to set the state
		 * back to TCPS_LISTEN.  Make sure that the eager list
		 * is reinitialized.
		 *
		 * Note that this stream is still bound to the four
		 * tuples of the previous connection in IP.  If a new
		 * SYN with different foreign address comes in, IP will
		 * not find it and will send it to the global queue.  In
		 * the global queue, TCP will do a tcp_lookup_listener()
		 * to find this stream.  This works because this stream
		 * is only removed from connected hash.
		 *
		 */
		tcp->tcp_state = TCPS_LISTEN;
		tcp->tcp_eager_next_q0 = tcp->tcp_eager_prev_q0 = tcp;
		tcp->tcp_eager_next_drop_q0 = tcp;
		tcp->tcp_eager_prev_drop_q0 = tcp;
		/*
		 * Initially set conn_recv to tcp_input_listener_unbound to try
		 * to pick a good squeue for the listener when the first SYN
		 * arrives. tcp_input_listener_unbound sets it to
		 * tcp_input_listener on that first SYN.
		 */
		connp->conn_recv = tcp_input_listener_unbound;

		connp->conn_proto = IPPROTO_TCP;
		connp->conn_faddr_v6 = ipv6_all_zeros;
		connp->conn_fport = 0;

		(void) ipcl_bind_insert(connp);
	} else {
		tcp->tcp_state = TCPS_BOUND;
	}

	/*
	 * Initialize to default values
	 */
	tcp_init_values(tcp, NULL);

	DTRACE_TCP6(state__change, void, NULL, ip_xmit_attr_t *,
	    connp->conn_ixa, void, NULL, tcp_t *, tcp, void, NULL,
	    int32_t, oldstate);

	ASSERT(tcp->tcp_ptpbhn != NULL);
	tcp->tcp_rwnd = connp->conn_rcvbuf;
	tcp->tcp_mss = connp->conn_ipversion != IPV4_VERSION ?
	    tcps->tcps_mss_def_ipv6 : tcps->tcps_mss_def_ipv4;
}

/*
 * Force values to zero that need be zero.
 * Do not touch values asociated with the BOUND or LISTEN state
 * since the connection will end up in that state after the reinit.
 * NOTE: tcp_reinit_values MUST have a line for each field in the tcp_t
 * structure!
 */
static void
tcp_reinit_values(tcp)
	tcp_t *tcp;
{
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	conn_t		*connp = tcp->tcp_connp;

#ifndef	lint
#define	DONTCARE(x)
#define	PRESERVE(x)
#else
#define	DONTCARE(x)	((x) = (x))
#define	PRESERVE(x)	((x) = (x))
#endif	/* lint */

	PRESERVE(tcp->tcp_bind_hash_port);
	PRESERVE(tcp->tcp_bind_hash);
	PRESERVE(tcp->tcp_ptpbhn);
	PRESERVE(tcp->tcp_acceptor_hash);
	PRESERVE(tcp->tcp_ptpahn);

	/* Should be ASSERT NULL on these with new code! */
	ASSERT(tcp->tcp_time_wait_next == NULL);
	ASSERT(tcp->tcp_time_wait_prev == NULL);
	ASSERT(tcp->tcp_time_wait_expire == 0);
	PRESERVE(tcp->tcp_state);
	PRESERVE(connp->conn_rq);
	PRESERVE(connp->conn_wq);

	ASSERT(tcp->tcp_xmit_head == NULL);
	ASSERT(tcp->tcp_xmit_last == NULL);
	ASSERT(tcp->tcp_unsent == 0);
	ASSERT(tcp->tcp_xmit_tail == NULL);
	ASSERT(tcp->tcp_xmit_tail_unsent == 0);

	tcp->tcp_snxt = 0;			/* Displayed in mib */
	tcp->tcp_suna = 0;			/* Displayed in mib */
	tcp->tcp_swnd = 0;
	DONTCARE(tcp->tcp_cwnd);	/* Init in tcp_process_options */

	ASSERT(tcp->tcp_ibsegs == 0);
	ASSERT(tcp->tcp_obsegs == 0);

	if (connp->conn_ht_iphc != NULL) {
		kmem_free(connp->conn_ht_iphc, connp->conn_ht_iphc_allocated);
		connp->conn_ht_iphc = NULL;
		connp->conn_ht_iphc_allocated = 0;
		connp->conn_ht_iphc_len = 0;
		connp->conn_ht_ulp = NULL;
		connp->conn_ht_ulp_len = 0;
		tcp->tcp_ipha = NULL;
		tcp->tcp_ip6h = NULL;
		tcp->tcp_tcpha = NULL;
	}

	/* We clear any IP_OPTIONS and extension headers */
	ip_pkt_free(&connp->conn_xmit_ipp);

	DONTCARE(tcp->tcp_naglim);		/* Init in tcp_init_values */
	DONTCARE(tcp->tcp_ipha);
	DONTCARE(tcp->tcp_ip6h);
	DONTCARE(tcp->tcp_tcpha);
	tcp->tcp_valid_bits = 0;

	DONTCARE(tcp->tcp_timer_backoff);	/* Init in tcp_init_values */
	DONTCARE(tcp->tcp_last_recv_time);	/* Init in tcp_init_values */
	tcp->tcp_last_rcv_lbolt = 0;

	tcp->tcp_init_cwnd = 0;

	tcp->tcp_urp_last_valid = 0;
	tcp->tcp_hard_binding = 0;

	tcp->tcp_fin_acked = 0;
	tcp->tcp_fin_rcvd = 0;
	tcp->tcp_fin_sent = 0;
	tcp->tcp_ordrel_done = 0;

	tcp->tcp_detached = 0;

	tcp->tcp_snd_ws_ok = B_FALSE;
	tcp->tcp_snd_ts_ok = B_FALSE;
	tcp->tcp_zero_win_probe = 0;

	tcp->tcp_loopback = 0;
	tcp->tcp_localnet = 0;
	tcp->tcp_syn_defense = 0;
	tcp->tcp_set_timer = 0;

	tcp->tcp_active_open = 0;
	tcp->tcp_rexmit = B_FALSE;
	tcp->tcp_xmit_zc_clean = B_FALSE;

	tcp->tcp_snd_sack_ok = B_FALSE;
	tcp->tcp_hwcksum = B_FALSE;

	DONTCARE(tcp->tcp_maxpsz_multiplier);	/* Init in tcp_init_values */

	tcp->tcp_conn_def_q0 = 0;
	tcp->tcp_ip_forward_progress = B_FALSE;
	tcp->tcp_ecn_ok = B_FALSE;

	tcp->tcp_cwr = B_FALSE;
	tcp->tcp_ecn_echo_on = B_FALSE;
	tcp->tcp_is_wnd_shrnk = B_FALSE;

	TCP_NOTSACK_REMOVE_ALL(tcp->tcp_notsack_list, tcp);
	bzero(&tcp->tcp_sack_info, sizeof (tcp_sack_info_t));

	tcp->tcp_rcv_ws = 0;
	tcp->tcp_snd_ws = 0;
	tcp->tcp_ts_recent = 0;
	tcp->tcp_rnxt = 0;			/* Displayed in mib */
	DONTCARE(tcp->tcp_rwnd);		/* Set in tcp_reinit() */
	tcp->tcp_initial_pmtu = 0;

	ASSERT(tcp->tcp_reass_head == NULL);
	ASSERT(tcp->tcp_reass_tail == NULL);

	tcp->tcp_cwnd_cnt = 0;

	ASSERT(tcp->tcp_rcv_list == NULL);
	ASSERT(tcp->tcp_rcv_last_head == NULL);
	ASSERT(tcp->tcp_rcv_last_tail == NULL);
	ASSERT(tcp->tcp_rcv_cnt == 0);

	DONTCARE(tcp->tcp_cwnd_ssthresh); /* Init in tcp_set_destination */
	DONTCARE(tcp->tcp_cwnd_max);		/* Init in tcp_init_values */
	tcp->tcp_csuna = 0;

	tcp->tcp_rto = 0;			/* Displayed in MIB */
	DONTCARE(tcp->tcp_rtt_sa);		/* Init in tcp_init_values */
	DONTCARE(tcp->tcp_rtt_sd);		/* Init in tcp_init_values */
	tcp->tcp_rtt_update = 0;

	DONTCARE(tcp->tcp_swl1); /* Init in case TCPS_LISTEN/TCPS_SYN_SENT */
	DONTCARE(tcp->tcp_swl2); /* Init in case TCPS_LISTEN/TCPS_SYN_SENT */

	tcp->tcp_rack = 0;			/* Displayed in mib */
	tcp->tcp_rack_cnt = 0;
	tcp->tcp_rack_cur_max = 0;
	tcp->tcp_rack_abs_max = 0;

	tcp->tcp_max_swnd = 0;

	ASSERT(tcp->tcp_listener == NULL);

	DONTCARE(tcp->tcp_irs);			/* tcp_valid_bits cleared */
	DONTCARE(tcp->tcp_iss);			/* tcp_valid_bits cleared */
	DONTCARE(tcp->tcp_fss);			/* tcp_valid_bits cleared */
	DONTCARE(tcp->tcp_urg);			/* tcp_valid_bits cleared */

	ASSERT(tcp->tcp_conn_req_cnt_q == 0);
	ASSERT(tcp->tcp_conn_req_cnt_q0 == 0);
	PRESERVE(tcp->tcp_conn_req_max);
	PRESERVE(tcp->tcp_conn_req_seqnum);

	DONTCARE(tcp->tcp_first_timer_threshold); /* Init in tcp_init_values */
	DONTCARE(tcp->tcp_second_timer_threshold); /* Init in tcp_init_values */
	DONTCARE(tcp->tcp_first_ctimer_threshold); /* Init in tcp_init_values */
	DONTCARE(tcp->tcp_second_ctimer_threshold); /* in tcp_init_values */

	DONTCARE(tcp->tcp_urp_last);	/* tcp_urp_last_valid is cleared */
	ASSERT(tcp->tcp_urp_mp == NULL);
	ASSERT(tcp->tcp_urp_mark_mp == NULL);
	ASSERT(tcp->tcp_fused_sigurg_mp == NULL);

	ASSERT(tcp->tcp_eager_next_q == NULL);
	ASSERT(tcp->tcp_eager_last_q == NULL);
	ASSERT((tcp->tcp_eager_next_q0 == NULL &&
	    tcp->tcp_eager_prev_q0 == NULL) ||
	    tcp->tcp_eager_next_q0 == tcp->tcp_eager_prev_q0);
	ASSERT(tcp->tcp_conn.tcp_eager_conn_ind == NULL);

	ASSERT((tcp->tcp_eager_next_drop_q0 == NULL &&
	    tcp->tcp_eager_prev_drop_q0 == NULL) ||
	    tcp->tcp_eager_next_drop_q0 == tcp->tcp_eager_prev_drop_q0);

	DONTCARE(tcp->tcp_ka_rinterval);	/* Init in tcp_init_values */
	DONTCARE(tcp->tcp_ka_abort_thres);	/* Init in tcp_init_values */
	DONTCARE(tcp->tcp_ka_cnt);		/* Init in tcp_init_values */

	tcp->tcp_client_errno = 0;

	DONTCARE(connp->conn_sum);		/* Init in tcp_init_values */

	connp->conn_faddr_v6 = ipv6_all_zeros;	/* Displayed in MIB */

	PRESERVE(connp->conn_bound_addr_v6);
	tcp->tcp_last_sent_len = 0;
	tcp->tcp_dupack_cnt = 0;

	connp->conn_fport = 0;			/* Displayed in MIB */
	PRESERVE(connp->conn_lport);

	PRESERVE(tcp->tcp_acceptor_lockp);

	ASSERT(tcp->tcp_ordrel_mp == NULL);
	PRESERVE(tcp->tcp_acceptor_id);
	DONTCARE(tcp->tcp_ipsec_overhead);

	PRESERVE(connp->conn_family);
	/* Remove any remnants of mapped address binding */
	if (connp->conn_family == AF_INET6) {
		connp->conn_ipversion = IPV6_VERSION;
		tcp->tcp_mss = tcps->tcps_mss_def_ipv6;
	} else {
		connp->conn_ipversion = IPV4_VERSION;
		tcp->tcp_mss = tcps->tcps_mss_def_ipv4;
	}

	connp->conn_bound_if = 0;
	connp->conn_recv_ancillary.crb_all = 0;
	tcp->tcp_recvifindex = 0;
	tcp->tcp_recvhops = 0;
	tcp->tcp_closed = 0;
	if (tcp->tcp_hopopts != NULL) {
		mi_free(tcp->tcp_hopopts);
		tcp->tcp_hopopts = NULL;
		tcp->tcp_hopoptslen = 0;
	}
	ASSERT(tcp->tcp_hopoptslen == 0);
	if (tcp->tcp_dstopts != NULL) {
		mi_free(tcp->tcp_dstopts);
		tcp->tcp_dstopts = NULL;
		tcp->tcp_dstoptslen = 0;
	}
	ASSERT(tcp->tcp_dstoptslen == 0);
	if (tcp->tcp_rthdrdstopts != NULL) {
		mi_free(tcp->tcp_rthdrdstopts);
		tcp->tcp_rthdrdstopts = NULL;
		tcp->tcp_rthdrdstoptslen = 0;
	}
	ASSERT(tcp->tcp_rthdrdstoptslen == 0);
	if (tcp->tcp_rthdr != NULL) {
		mi_free(tcp->tcp_rthdr);
		tcp->tcp_rthdr = NULL;
		tcp->tcp_rthdrlen = 0;
	}
	ASSERT(tcp->tcp_rthdrlen == 0);

	/* Reset fusion-related fields */
	tcp->tcp_fused = B_FALSE;
	tcp->tcp_unfusable = B_FALSE;
	tcp->tcp_fused_sigurg = B_FALSE;
	tcp->tcp_loopback_peer = NULL;

	tcp->tcp_lso = B_FALSE;

	tcp->tcp_in_ack_unsent = 0;
	tcp->tcp_cork = B_FALSE;
	tcp->tcp_tconnind_started = B_FALSE;

	PRESERVE(tcp->tcp_squeue_bytes);

	tcp->tcp_closemp_used = B_FALSE;

	PRESERVE(tcp->tcp_rsrv_mp);
	PRESERVE(tcp->tcp_rsrv_mp_lock);

#ifdef DEBUG
	DONTCARE(tcp->tcmp_stk[0]);
#endif

	PRESERVE(tcp->tcp_connid);

	ASSERT(tcp->tcp_listen_cnt == NULL);
	ASSERT(tcp->tcp_reass_tid == 0);

#undef	DONTCARE
#undef	PRESERVE
}

/*
 * Initialize the various fields in tcp_t.  If parent (the listener) is non
 * NULL, certain values will be inheritted from it.
 */
void
tcp_init_values(tcp_t *tcp, tcp_t *parent)
{
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	conn_t		*connp = tcp->tcp_connp;
	clock_t		rto;

	ASSERT((connp->conn_family == AF_INET &&
	    connp->conn_ipversion == IPV4_VERSION) ||
	    (connp->conn_family == AF_INET6 &&
	    (connp->conn_ipversion == IPV4_VERSION ||
	    connp->conn_ipversion == IPV6_VERSION)));

	if (parent == NULL) {
		tcp->tcp_naglim = tcps->tcps_naglim_def;

		tcp->tcp_rto_initial = tcps->tcps_rexmit_interval_initial;
		tcp->tcp_rto_min = tcps->tcps_rexmit_interval_min;
		tcp->tcp_rto_max = tcps->tcps_rexmit_interval_max;

		tcp->tcp_first_ctimer_threshold =
		    tcps->tcps_ip_notify_cinterval;
		tcp->tcp_second_ctimer_threshold =
		    tcps->tcps_ip_abort_cinterval;
		tcp->tcp_first_timer_threshold = tcps->tcps_ip_notify_interval;
		tcp->tcp_second_timer_threshold = tcps->tcps_ip_abort_interval;

		tcp->tcp_fin_wait_2_flush_interval =
		    tcps->tcps_fin_wait_2_flush_interval;

		tcp->tcp_ka_interval = tcps->tcps_keepalive_interval;
		tcp->tcp_ka_abort_thres = tcps->tcps_keepalive_abort_interval;
		tcp->tcp_ka_cnt = 0;
		tcp->tcp_ka_rinterval = 0;

		/*
		 * Default value of tcp_init_cwnd is 0, so no need to set here
		 * if parent is NULL.  But we need to inherit it from parent.
		 */
	} else {
		/* Inherit various TCP parameters from the parent. */
		tcp->tcp_naglim = parent->tcp_naglim;

		tcp->tcp_rto_initial = parent->tcp_rto_initial;
		tcp->tcp_rto_min = parent->tcp_rto_min;
		tcp->tcp_rto_max = parent->tcp_rto_max;

		tcp->tcp_first_ctimer_threshold =
		    parent->tcp_first_ctimer_threshold;
		tcp->tcp_second_ctimer_threshold =
		    parent->tcp_second_ctimer_threshold;
		tcp->tcp_first_timer_threshold =
		    parent->tcp_first_timer_threshold;
		tcp->tcp_second_timer_threshold =
		    parent->tcp_second_timer_threshold;

		tcp->tcp_fin_wait_2_flush_interval =
		    parent->tcp_fin_wait_2_flush_interval;

		tcp->tcp_ka_interval = parent->tcp_ka_interval;
		tcp->tcp_ka_abort_thres = parent->tcp_ka_abort_thres;
		tcp->tcp_ka_cnt = parent->tcp_ka_cnt;
		tcp->tcp_ka_rinterval = parent->tcp_ka_rinterval;

		tcp->tcp_init_cwnd = parent->tcp_init_cwnd;
	}

	/*
	 * Initialize tcp_rtt_sa and tcp_rtt_sd so that the calculated RTO
	 * will be close to tcp_rexmit_interval_initial.  By doing this, we
	 * allow the algorithm to adjust slowly to large fluctuations of RTT
	 * during first few transmissions of a connection as seen in slow
	 * links.
	 */
	tcp->tcp_rtt_sa = tcp->tcp_rto_initial << 2;
	tcp->tcp_rtt_sd = tcp->tcp_rto_initial >> 1;
	rto = (tcp->tcp_rtt_sa >> 3) + tcp->tcp_rtt_sd +
	    tcps->tcps_rexmit_interval_extra + (tcp->tcp_rtt_sa >> 5) +
	    tcps->tcps_conn_grace_period;
	TCP_SET_RTO(tcp, rto);

	tcp->tcp_timer_backoff = 0;
	tcp->tcp_ms_we_have_waited = 0;
	tcp->tcp_last_recv_time = ddi_get_lbolt();
	tcp->tcp_cwnd_max = tcps->tcps_cwnd_max_;
	tcp->tcp_cwnd_ssthresh = TCP_MAX_LARGEWIN;

	tcp->tcp_maxpsz_multiplier = tcps->tcps_maxpsz_multiplier;

	/* NOTE:  ISS is now set in tcp_set_destination(). */

	/* Reset fusion-related fields */
	tcp->tcp_fused = B_FALSE;
	tcp->tcp_unfusable = B_FALSE;
	tcp->tcp_fused_sigurg = B_FALSE;
	tcp->tcp_loopback_peer = NULL;

	/* We rebuild the header template on the next connect/conn_request */

	connp->conn_mlp_type = mlptSingle;

	/*
	 * Init the window scale to the max so tcp_rwnd_set() won't pare
	 * down tcp_rwnd. tcp_set_destination() will set the right value later.
	 */
	tcp->tcp_rcv_ws = TCP_MAX_WINSHIFT;
	tcp->tcp_rwnd = connp->conn_rcvbuf;

	tcp->tcp_cork = B_FALSE;
	/*
	 * Init the tcp_debug option if it wasn't already set.  This value
	 * determines whether TCP
	 * calls strlog() to print out debug messages.  Doing this
	 * initialization here means that this value is not inherited thru
	 * tcp_reinit().
	 */
	if (!connp->conn_debug)
		connp->conn_debug = tcps->tcps_dbg;
}

/*
 * Update the TCP connection according to change of PMTU.
 *
 * Path MTU might have changed by either increase or decrease, so need to
 * adjust the MSS based on the value of ixa_pmtu. No need to handle tiny
 * or negative MSS, since tcp_mss_set() will do it.
 */
void
tcp_update_pmtu(tcp_t *tcp, boolean_t decrease_only)
{
	uint32_t	pmtu;
	int32_t		mss;
	conn_t		*connp = tcp->tcp_connp;
	ip_xmit_attr_t	*ixa = connp->conn_ixa;
	iaflags_t	ixaflags;

	if (tcp->tcp_tcps->tcps_ignore_path_mtu)
		return;

	if (tcp->tcp_state < TCPS_ESTABLISHED)
		return;

	/*
	 * Always call ip_get_pmtu() to make sure that IP has updated
	 * ixa_flags properly.
	 */
	pmtu = ip_get_pmtu(ixa);
	ixaflags = ixa->ixa_flags;

	/*
	 * Calculate the MSS by decreasing the PMTU by conn_ht_iphc_len and
	 * IPsec overhead if applied. Make sure to use the most recent
	 * IPsec information.
	 */
	mss = pmtu - connp->conn_ht_iphc_len - conn_ipsec_length(connp);

	/*
	 * Nothing to change, so just return.
	 */
	if (mss == tcp->tcp_mss)
		return;

	/*
	 * Currently, for ICMP errors, only PMTU decrease is handled.
	 */
	if (mss > tcp->tcp_mss && decrease_only)
		return;

	DTRACE_PROBE2(tcp_update_pmtu, int32_t, tcp->tcp_mss, uint32_t, mss);

	/*
	 * Update ixa_fragsize and ixa_pmtu.
	 */
	ixa->ixa_fragsize = ixa->ixa_pmtu = pmtu;

	/*
	 * Adjust MSS and all relevant variables.
	 */
	tcp_mss_set(tcp, mss);

	/*
	 * If the PMTU is below the min size maintained by IP, then ip_get_pmtu
	 * has set IXAF_PMTU_TOO_SMALL and cleared IXAF_PMTU_IPV4_DF. Since TCP
	 * has a (potentially different) min size we do the same. Make sure to
	 * clear IXAF_DONTFRAG, which is used by IP to decide whether to
	 * fragment the packet.
	 *
	 * LSO over IPv6 can not be fragmented. So need to disable LSO
	 * when IPv6 fragmentation is needed.
	 */
	if (mss < tcp->tcp_tcps->tcps_mss_min)
		ixaflags |= IXAF_PMTU_TOO_SMALL;

	if (ixaflags & IXAF_PMTU_TOO_SMALL)
		ixaflags &= ~(IXAF_DONTFRAG | IXAF_PMTU_IPV4_DF);

	if ((connp->conn_ipversion == IPV4_VERSION) &&
	    !(ixaflags & IXAF_PMTU_IPV4_DF)) {
		tcp->tcp_ipha->ipha_fragment_offset_and_flags = 0;
	}
	ixa->ixa_flags = ixaflags;
}

int
tcp_maxpsz_set(tcp_t *tcp, boolean_t set_maxblk)
{
	conn_t	*connp = tcp->tcp_connp;
	queue_t	*q = connp->conn_rq;
	int32_t	mss = tcp->tcp_mss;
	int	maxpsz;

	if (TCP_IS_DETACHED(tcp))
		return (mss);
	if (tcp->tcp_fused) {
		maxpsz = tcp_fuse_maxpsz(tcp);
		mss = INFPSZ;
	} else if (tcp->tcp_maxpsz_multiplier == 0) {
		/*
		 * Set the sd_qn_maxpsz according to the socket send buffer
		 * size, and sd_maxblk to INFPSZ (-1).  This will essentially
		 * instruct the stream head to copyin user data into contiguous
		 * kernel-allocated buffers without breaking it up into smaller
		 * chunks.  We round up the buffer size to the nearest SMSS.
		 */
		maxpsz = MSS_ROUNDUP(connp->conn_sndbuf, mss);
		mss = INFPSZ;
	} else {
		/*
		 * Set sd_qn_maxpsz to approx half the (receivers) buffer
		 * (and a multiple of the mss).  This instructs the stream
		 * head to break down larger than SMSS writes into SMSS-
		 * size mblks, up to tcp_maxpsz_multiplier mblks at a time.
		 */
		maxpsz = tcp->tcp_maxpsz_multiplier * mss;
		if (maxpsz > connp->conn_sndbuf / 2) {
			maxpsz = connp->conn_sndbuf / 2;
			/* Round up to nearest mss */
			maxpsz = MSS_ROUNDUP(maxpsz, mss);
		}
	}

	(void) proto_set_maxpsz(q, connp, maxpsz);
	if (!(IPCL_IS_NONSTR(connp)))
		connp->conn_wq->q_maxpsz = maxpsz;
	if (set_maxblk)
		(void) proto_set_tx_maxblk(q, connp, mss);
	return (mss);
}

/* For /dev/tcp aka AF_INET open */
static int
tcp_openv4(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	return (tcp_open(q, devp, flag, sflag, credp, B_FALSE));
}

/* For /dev/tcp6 aka AF_INET6 open */
static int
tcp_openv6(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	return (tcp_open(q, devp, flag, sflag, credp, B_TRUE));
}

conn_t *
tcp_create_common(cred_t *credp, boolean_t isv6, boolean_t issocket,
    int *errorp)
{
	tcp_t		*tcp = NULL;
	conn_t		*connp;
	zoneid_t	zoneid;
	tcp_stack_t	*tcps;
	squeue_t	*sqp;

	ASSERT(errorp != NULL);
	/*
	 * Find the proper zoneid and netstack.
	 */
	/*
	 * Special case for install: miniroot needs to be able to
	 * access files via NFS as though it were always in the
	 * global zone.
	 */
	if (credp == kcred && nfs_global_client_only != 0) {
		zoneid = GLOBAL_ZONEID;
		tcps = netstack_find_by_stackid(GLOBAL_NETSTACKID)->
		    netstack_tcp;
		ASSERT(tcps != NULL);
	} else {
		netstack_t *ns;
		int err;

		if ((err = secpolicy_basic_net_access(credp)) != 0) {
			*errorp = err;
			return (NULL);
		}

		ns = netstack_find_by_cred(credp);
		ASSERT(ns != NULL);
		tcps = ns->netstack_tcp;
		ASSERT(tcps != NULL);

		/*
		 * For exclusive stacks we set the zoneid to zero
		 * to make TCP operate as if in the global zone.
		 */
		if (tcps->tcps_netstack->netstack_stackid !=
		    GLOBAL_NETSTACKID)
			zoneid = GLOBAL_ZONEID;
		else
			zoneid = crgetzoneid(credp);
	}

	sqp = IP_SQUEUE_GET((uint_t)gethrtime());
	connp = (conn_t *)tcp_get_conn(sqp, tcps);
	/*
	 * Both tcp_get_conn and netstack_find_by_cred incremented refcnt,
	 * so we drop it by one.
	 */
	netstack_rele(tcps->tcps_netstack);
	if (connp == NULL) {
		*errorp = ENOSR;
		return (NULL);
	}
	ASSERT(connp->conn_ixa->ixa_protocol == connp->conn_proto);

	connp->conn_sqp = sqp;
	connp->conn_initial_sqp = connp->conn_sqp;
	connp->conn_ixa->ixa_sqp = connp->conn_sqp;
	tcp = connp->conn_tcp;

	/*
	 * Besides asking IP to set the checksum for us, have conn_ip_output
	 * to do the following checks when necessary:
	 *
	 * IXAF_VERIFY_SOURCE: drop packets when our outer source goes invalid
	 * IXAF_VERIFY_PMTU: verify PMTU changes
	 * IXAF_VERIFY_LSO: verify LSO capability changes
	 */
	connp->conn_ixa->ixa_flags |= IXAF_SET_ULP_CKSUM | IXAF_VERIFY_SOURCE |
	    IXAF_VERIFY_PMTU | IXAF_VERIFY_LSO;

	if (!tcps->tcps_dev_flow_ctl)
		connp->conn_ixa->ixa_flags |= IXAF_NO_DEV_FLOW_CTL;

	if (isv6) {
		connp->conn_ixa->ixa_src_preferences = IPV6_PREFER_SRC_DEFAULT;
		connp->conn_ipversion = IPV6_VERSION;
		connp->conn_family = AF_INET6;
		tcp->tcp_mss = tcps->tcps_mss_def_ipv6;
		connp->conn_default_ttl = tcps->tcps_ipv6_hoplimit;
	} else {
		connp->conn_ipversion = IPV4_VERSION;
		connp->conn_family = AF_INET;
		tcp->tcp_mss = tcps->tcps_mss_def_ipv4;
		connp->conn_default_ttl = tcps->tcps_ipv4_ttl;
	}
	connp->conn_xmit_ipp.ipp_unicast_hops = connp->conn_default_ttl;

	crhold(credp);
	connp->conn_cred = credp;
	connp->conn_cpid = curproc->p_pid;
	connp->conn_open_time = ddi_get_lbolt64();

	/* Cache things in the ixa without any refhold */
	ASSERT(!(connp->conn_ixa->ixa_free_flags & IXA_FREE_CRED));
	connp->conn_ixa->ixa_cred = credp;
	connp->conn_ixa->ixa_cpid = connp->conn_cpid;

	connp->conn_zoneid = zoneid;
	/* conn_allzones can not be set this early, hence no IPCL_ZONEID */
	connp->conn_ixa->ixa_zoneid = zoneid;
	connp->conn_mlp_type = mlptSingle;
	ASSERT(connp->conn_netstack == tcps->tcps_netstack);
	ASSERT(tcp->tcp_tcps == tcps);

	/*
	 * If the caller has the process-wide flag set, then default to MAC
	 * exempt mode.  This allows read-down to unlabeled hosts.
	 */
	if (getpflags(NET_MAC_AWARE, credp) != 0)
		connp->conn_mac_mode = CONN_MAC_AWARE;

	connp->conn_zone_is_global = (crgetzoneid(credp) == GLOBAL_ZONEID);

	if (issocket) {
		tcp->tcp_issocket = 1;
	}

	connp->conn_rcvbuf = tcps->tcps_recv_hiwat;
	connp->conn_sndbuf = tcps->tcps_xmit_hiwat;
	if (tcps->tcps_snd_lowat_fraction != 0) {
		connp->conn_sndlowat = connp->conn_sndbuf /
		    tcps->tcps_snd_lowat_fraction;
	} else {
		connp->conn_sndlowat = tcps->tcps_xmit_lowat;
	}
	connp->conn_so_type = SOCK_STREAM;
	connp->conn_wroff = connp->conn_ht_iphc_allocated +
	    tcps->tcps_wroff_xtra;

	SOCK_CONNID_INIT(tcp->tcp_connid);
	/* DTrace ignores this - it isn't a tcp:::state-change */
	tcp->tcp_state = TCPS_IDLE;
	tcp_init_values(tcp, NULL);
	return (connp);
}

static int
tcp_open(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp,
    boolean_t isv6)
{
	tcp_t		*tcp = NULL;
	conn_t		*connp = NULL;
	int		err;
	vmem_t		*minor_arena = NULL;
	dev_t		conn_dev;
	boolean_t	issocket;

	if (q->q_ptr != NULL)
		return (0);

	if (sflag == MODOPEN)
		return (EINVAL);

	if ((ip_minor_arena_la != NULL) && (flag & SO_SOCKSTR) &&
	    ((conn_dev = inet_minor_alloc(ip_minor_arena_la)) != 0)) {
		minor_arena = ip_minor_arena_la;
	} else {
		/*
		 * Either minor numbers in the large arena were exhausted
		 * or a non socket application is doing the open.
		 * Try to allocate from the small arena.
		 */
		if ((conn_dev = inet_minor_alloc(ip_minor_arena_sa)) == 0) {
			return (EBUSY);
		}
		minor_arena = ip_minor_arena_sa;
	}

	ASSERT(minor_arena != NULL);

	*devp = makedevice(getmajor(*devp), (minor_t)conn_dev);

	if (flag & SO_FALLBACK) {
		/*
		 * Non streams socket needs a stream to fallback to
		 */
		RD(q)->q_ptr = (void *)conn_dev;
		WR(q)->q_qinfo = &tcp_fallback_sock_winit;
		WR(q)->q_ptr = (void *)minor_arena;
		qprocson(q);
		return (0);
	} else if (flag & SO_ACCEPTOR) {
		q->q_qinfo = &tcp_acceptor_rinit;
		/*
		 * the conn_dev and minor_arena will be subsequently used by
		 * tcp_tli_accept() and tcp_tpi_close_accept() to figure out
		 * the minor device number for this connection from the q_ptr.
		 */
		RD(q)->q_ptr = (void *)conn_dev;
		WR(q)->q_qinfo = &tcp_acceptor_winit;
		WR(q)->q_ptr = (void *)minor_arena;
		qprocson(q);
		return (0);
	}

	issocket = flag & SO_SOCKSTR;
	connp = tcp_create_common(credp, isv6, issocket, &err);

	if (connp == NULL) {
		inet_minor_free(minor_arena, conn_dev);
		q->q_ptr = WR(q)->q_ptr = NULL;
		return (err);
	}

	connp->conn_rq = q;
	connp->conn_wq = WR(q);
	q->q_ptr = WR(q)->q_ptr = connp;

	connp->conn_dev = conn_dev;
	connp->conn_minor_arena = minor_arena;

	ASSERT(q->q_qinfo == &tcp_rinitv4 || q->q_qinfo == &tcp_rinitv6);
	ASSERT(WR(q)->q_qinfo == &tcp_winit);

	tcp = connp->conn_tcp;

	if (issocket) {
		WR(q)->q_qinfo = &tcp_sock_winit;
	} else {
#ifdef  _ILP32
		tcp->tcp_acceptor_id = (t_uscalar_t)RD(q);
#else
		tcp->tcp_acceptor_id = conn_dev;
#endif  /* _ILP32 */
		tcp_acceptor_hash_insert(tcp->tcp_acceptor_id, tcp);
	}

	/*
	 * Put the ref for TCP. Ref for IP was already put
	 * by ipcl_conn_create. Also Make the conn_t globally
	 * visible to walkers
	 */
	mutex_enter(&connp->conn_lock);
	CONN_INC_REF_LOCKED(connp);
	ASSERT(connp->conn_ref == 2);
	connp->conn_state_flags &= ~CONN_INCIPIENT;
	mutex_exit(&connp->conn_lock);

	qprocson(q);
	return (0);
}

/*
 * Build/update the tcp header template (in conn_ht_iphc) based on
 * conn_xmit_ipp. The headers include ip6_t, any extension
 * headers, and the maximum size tcp header (to avoid reallocation
 * on the fly for additional tcp options).
 *
 * Assumes the caller has already set conn_{faddr,laddr,fport,lport,flowinfo}.
 * Returns failure if can't allocate memory.
 */
int
tcp_build_hdrs(tcp_t *tcp)
{
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	conn_t		*connp = tcp->tcp_connp;
	char		buf[TCP_MAX_HDR_LENGTH];
	uint_t		buflen;
	uint_t		ulplen = TCP_MIN_HEADER_LENGTH;
	uint_t		extralen = TCP_MAX_TCP_OPTIONS_LENGTH;
	tcpha_t		*tcpha;
	uint32_t	cksum;
	int		error;

	/*
	 * We might be called after the connection is set up, and we might
	 * have TS options already in the TCP header. Thus we  save any
	 * existing tcp header.
	 */
	buflen = connp->conn_ht_ulp_len;
	if (buflen != 0) {
		bcopy(connp->conn_ht_ulp, buf, buflen);
		extralen -= buflen - ulplen;
		ulplen = buflen;
	}

	/* Grab lock to satisfy ASSERT; TCP is serialized using squeue */
	mutex_enter(&connp->conn_lock);
	error = conn_build_hdr_template(connp, ulplen, extralen,
	    &connp->conn_laddr_v6, &connp->conn_faddr_v6, connp->conn_flowinfo);
	mutex_exit(&connp->conn_lock);
	if (error != 0)
		return (error);

	/*
	 * Any routing header/option has been massaged. The checksum difference
	 * is stored in conn_sum for later use.
	 */
	tcpha = (tcpha_t *)connp->conn_ht_ulp;
	tcp->tcp_tcpha = tcpha;

	/* restore any old tcp header */
	if (buflen != 0) {
		bcopy(buf, connp->conn_ht_ulp, buflen);
	} else {
		tcpha->tha_sum = 0;
		tcpha->tha_urp = 0;
		tcpha->tha_ack = 0;
		tcpha->tha_offset_and_reserved = (5 << 4);
		tcpha->tha_lport = connp->conn_lport;
		tcpha->tha_fport = connp->conn_fport;
	}

	/*
	 * IP wants our header length in the checksum field to
	 * allow it to perform a single pseudo-header+checksum
	 * calculation on behalf of TCP.
	 * Include the adjustment for a source route once IP_OPTIONS is set.
	 */
	cksum = sizeof (tcpha_t) + connp->conn_sum;
	cksum = (cksum >> 16) + (cksum & 0xFFFF);
	ASSERT(cksum < 0x10000);
	tcpha->tha_sum = htons(cksum);

	if (connp->conn_ipversion == IPV4_VERSION)
		tcp->tcp_ipha = (ipha_t *)connp->conn_ht_iphc;
	else
		tcp->tcp_ip6h = (ip6_t *)connp->conn_ht_iphc;

	if (connp->conn_ht_iphc_allocated + tcps->tcps_wroff_xtra >
	    connp->conn_wroff) {
		connp->conn_wroff = connp->conn_ht_iphc_allocated +
		    tcps->tcps_wroff_xtra;
		(void) proto_set_tx_wroff(connp->conn_rq, connp,
		    connp->conn_wroff);
	}
	return (0);
}

/*
 * tcp_rwnd_set() is called to adjust the receive window to a desired value.
 * We do not allow the receive window to shrink.  After setting rwnd,
 * set the flow control hiwat of the stream.
 *
 * This function is called in 2 cases:
 *
 * 1) Before data transfer begins, in tcp_input_listener() for accepting a
 *    connection (passive open) and in tcp_input_data() for active connect.
 *    This is called after tcp_mss_set() when the desired MSS value is known.
 *    This makes sure that our window size is a mutiple of the other side's
 *    MSS.
 * 2) Handling SO_RCVBUF option.
 *
 * It is ASSUMED that the requested size is a multiple of the current MSS.
 *
 * XXX - Should allow a lower rwnd than tcp_recv_hiwat_minmss * mss if the
 * user requests so.
 */
int
tcp_rwnd_set(tcp_t *tcp, uint32_t rwnd)
{
	uint32_t	mss = tcp->tcp_mss;
	uint32_t	old_max_rwnd;
	uint32_t	max_transmittable_rwnd;
	boolean_t	tcp_detached = TCP_IS_DETACHED(tcp);
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	conn_t		*connp = tcp->tcp_connp;

	/*
	 * Insist on a receive window that is at least
	 * tcp_recv_hiwat_minmss * MSS (default 4 * MSS) to avoid
	 * funny TCP interactions of Nagle algorithm, SWS avoidance
	 * and delayed acknowledgement.
	 */
	rwnd = MAX(rwnd, tcps->tcps_recv_hiwat_minmss * mss);

	if (tcp->tcp_fused) {
		size_t sth_hiwat;
		tcp_t *peer_tcp = tcp->tcp_loopback_peer;

		ASSERT(peer_tcp != NULL);
		sth_hiwat = tcp_fuse_set_rcv_hiwat(tcp, rwnd);
		if (!tcp_detached) {
			(void) proto_set_rx_hiwat(connp->conn_rq, connp,
			    sth_hiwat);
			tcp_set_recv_threshold(tcp, sth_hiwat >> 3);
		}

		/* Caller could have changed tcp_rwnd; update tha_win */
		if (tcp->tcp_tcpha != NULL) {
			tcp->tcp_tcpha->tha_win =
			    htons(tcp->tcp_rwnd >> tcp->tcp_rcv_ws);
		}
		if ((tcp->tcp_rcv_ws > 0) && rwnd > tcp->tcp_cwnd_max)
			tcp->tcp_cwnd_max = rwnd;

		/*
		 * In the fusion case, the maxpsz stream head value of
		 * our peer is set according to its send buffer size
		 * and our receive buffer size; since the latter may
		 * have changed we need to update the peer's maxpsz.
		 */
		(void) tcp_maxpsz_set(peer_tcp, B_TRUE);
		return (sth_hiwat);
	}

	if (tcp_detached)
		old_max_rwnd = tcp->tcp_rwnd;
	else
		old_max_rwnd = connp->conn_rcvbuf;


	/*
	 * If window size info has already been exchanged, TCP should not
	 * shrink the window.  Shrinking window is doable if done carefully.
	 * We may add that support later.  But so far there is not a real
	 * need to do that.
	 */
	if (rwnd < old_max_rwnd && tcp->tcp_state > TCPS_SYN_SENT) {
		/* MSS may have changed, do a round up again. */
		rwnd = MSS_ROUNDUP(old_max_rwnd, mss);
	}

	/*
	 * tcp_rcv_ws starts with TCP_MAX_WINSHIFT so the following check
	 * can be applied even before the window scale option is decided.
	 */
	max_transmittable_rwnd = TCP_MAXWIN << tcp->tcp_rcv_ws;
	if (rwnd > max_transmittable_rwnd) {
		rwnd = max_transmittable_rwnd -
		    (max_transmittable_rwnd % mss);
		if (rwnd < mss)
			rwnd = max_transmittable_rwnd;
		/*
		 * If we're over the limit we may have to back down tcp_rwnd.
		 * The increment below won't work for us. So we set all three
		 * here and the increment below will have no effect.
		 */
		tcp->tcp_rwnd = old_max_rwnd = rwnd;
	}
	if (tcp->tcp_localnet) {
		tcp->tcp_rack_abs_max =
		    MIN(tcps->tcps_local_dacks_max, rwnd / mss / 2);
	} else {
		/*
		 * For a remote host on a different subnet (through a router),
		 * we ack every other packet to be conforming to RFC1122.
		 * tcp_deferred_acks_max is default to 2.
		 */
		tcp->tcp_rack_abs_max =
		    MIN(tcps->tcps_deferred_acks_max, rwnd / mss / 2);
	}
	if (tcp->tcp_rack_cur_max > tcp->tcp_rack_abs_max)
		tcp->tcp_rack_cur_max = tcp->tcp_rack_abs_max;
	else
		tcp->tcp_rack_cur_max = 0;
	/*
	 * Increment the current rwnd by the amount the maximum grew (we
	 * can not overwrite it since we might be in the middle of a
	 * connection.)
	 */
	tcp->tcp_rwnd += rwnd - old_max_rwnd;
	connp->conn_rcvbuf = rwnd;

	/* Are we already connected? */
	if (tcp->tcp_tcpha != NULL) {
		tcp->tcp_tcpha->tha_win =
		    htons(tcp->tcp_rwnd >> tcp->tcp_rcv_ws);
	}

	if ((tcp->tcp_rcv_ws > 0) && rwnd > tcp->tcp_cwnd_max)
		tcp->tcp_cwnd_max = rwnd;

	if (tcp_detached)
		return (rwnd);

	tcp_set_recv_threshold(tcp, rwnd >> 3);

	(void) proto_set_rx_hiwat(connp->conn_rq, connp, rwnd);
	return (rwnd);
}

int
tcp_do_unbind(conn_t *connp)
{
	tcp_t *tcp = connp->conn_tcp;
	int32_t oldstate;

	switch (tcp->tcp_state) {
	case TCPS_BOUND:
	case TCPS_LISTEN:
		break;
	default:
		return (-TOUTSTATE);
	}

	/*
	 * Need to clean up all the eagers since after the unbind, segments
	 * will no longer be delivered to this listener stream.
	 */
	mutex_enter(&tcp->tcp_eager_lock);
	if (tcp->tcp_conn_req_cnt_q0 != 0 || tcp->tcp_conn_req_cnt_q != 0) {
		tcp_eager_cleanup(tcp, 0);
	}
	mutex_exit(&tcp->tcp_eager_lock);

	/* Clean up the listener connection counter if necessary. */
	if (tcp->tcp_listen_cnt != NULL)
		TCP_DECR_LISTEN_CNT(tcp);
	connp->conn_laddr_v6 = ipv6_all_zeros;
	connp->conn_saddr_v6 = ipv6_all_zeros;
	tcp_bind_hash_remove(tcp);
	oldstate = tcp->tcp_state;
	tcp->tcp_state = TCPS_IDLE;
	DTRACE_TCP6(state__change, void, NULL, ip_xmit_attr_t *,
	    connp->conn_ixa, void, NULL, tcp_t *, tcp, void, NULL,
	    int32_t, oldstate);

	ip_unbind(connp);
	bzero(&connp->conn_ports, sizeof (connp->conn_ports));

	return (0);
}

/*
 * Collect protocol properties to send to the upper handle.
 */
void
tcp_get_proto_props(tcp_t *tcp, struct sock_proto_props *sopp)
{
	conn_t *connp = tcp->tcp_connp;

	sopp->sopp_flags = SOCKOPT_RCVHIWAT | SOCKOPT_MAXBLK | SOCKOPT_WROFF;
	sopp->sopp_maxblk = tcp_maxpsz_set(tcp, B_FALSE);

	sopp->sopp_rxhiwat = tcp->tcp_fused ?
	    tcp_fuse_set_rcv_hiwat(tcp, connp->conn_rcvbuf) :
	    connp->conn_rcvbuf;
	/*
	 * Determine what write offset value to use depending on SACK and
	 * whether the endpoint is fused or not.
	 */
	if (tcp->tcp_fused) {
		ASSERT(tcp->tcp_loopback);
		ASSERT(tcp->tcp_loopback_peer != NULL);
		/*
		 * For fused tcp loopback, set the stream head's write
		 * offset value to zero since we won't be needing any room
		 * for TCP/IP headers.  This would also improve performance
		 * since it would reduce the amount of work done by kmem.
		 * Non-fused tcp loopback case is handled separately below.
		 */
		sopp->sopp_wroff = 0;
		/*
		 * Update the peer's transmit parameters according to
		 * our recently calculated high water mark value.
		 */
		(void) tcp_maxpsz_set(tcp->tcp_loopback_peer, B_TRUE);
	} else if (tcp->tcp_snd_sack_ok) {
		sopp->sopp_wroff = connp->conn_ht_iphc_allocated +
		    (tcp->tcp_loopback ? 0 : tcp->tcp_tcps->tcps_wroff_xtra);
	} else {
		sopp->sopp_wroff = connp->conn_ht_iphc_len +
		    (tcp->tcp_loopback ? 0 : tcp->tcp_tcps->tcps_wroff_xtra);
	}

	if (tcp->tcp_loopback) {
		sopp->sopp_flags |= SOCKOPT_LOOPBACK;
		sopp->sopp_loopback = B_TRUE;
	}
}

/*
 * Check the usability of ZEROCOPY. It's instead checking the flag set by IP.
 */
boolean_t
tcp_zcopy_check(tcp_t *tcp)
{
	conn_t		*connp = tcp->tcp_connp;
	ip_xmit_attr_t	*ixa = connp->conn_ixa;
	boolean_t	zc_enabled = B_FALSE;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	if (do_tcpzcopy == 2)
		zc_enabled = B_TRUE;
	else if ((do_tcpzcopy == 1) && (ixa->ixa_flags & IXAF_ZCOPY_CAPAB))
		zc_enabled = B_TRUE;

	tcp->tcp_snd_zcopy_on = zc_enabled;
	if (!TCP_IS_DETACHED(tcp)) {
		if (zc_enabled) {
			ixa->ixa_flags |= IXAF_VERIFY_ZCOPY;
			(void) proto_set_tx_copyopt(connp->conn_rq, connp,
			    ZCVMSAFE);
			TCP_STAT(tcps, tcp_zcopy_on);
		} else {
			ixa->ixa_flags &= ~IXAF_VERIFY_ZCOPY;
			(void) proto_set_tx_copyopt(connp->conn_rq, connp,
			    ZCVMUNSAFE);
			TCP_STAT(tcps, tcp_zcopy_off);
		}
	}
	return (zc_enabled);
}

/*
 * Backoff from a zero-copy message by copying data to a new allocated
 * message and freeing the original desballoca'ed segmapped message.
 *
 * This function is called by following two callers:
 * 1. tcp_timer: fix_xmitlist is set to B_TRUE, because it's safe to free
 *    the origial desballoca'ed message and notify sockfs. This is in re-
 *    transmit state.
 * 2. tcp_output: fix_xmitlist is set to B_FALSE. Flag STRUIO_ZCNOTIFY need
 *    to be copied to new message.
 */
mblk_t *
tcp_zcopy_backoff(tcp_t *tcp, mblk_t *bp, boolean_t fix_xmitlist)
{
	mblk_t		*nbp;
	mblk_t		*head = NULL;
	mblk_t		*tail = NULL;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	ASSERT(bp != NULL);
	while (bp != NULL) {
		if (IS_VMLOANED_MBLK(bp)) {
			TCP_STAT(tcps, tcp_zcopy_backoff);
			if ((nbp = copyb(bp)) == NULL) {
				tcp->tcp_xmit_zc_clean = B_FALSE;
				if (tail != NULL)
					tail->b_cont = bp;
				return ((head == NULL) ? bp : head);
			}

			if (bp->b_datap->db_struioflag & STRUIO_ZCNOTIFY) {
				if (fix_xmitlist)
					tcp_zcopy_notify(tcp);
				else
					nbp->b_datap->db_struioflag |=
					    STRUIO_ZCNOTIFY;
			}
			nbp->b_cont = bp->b_cont;

			/*
			 * Copy saved information and adjust tcp_xmit_tail
			 * if needed.
			 */
			if (fix_xmitlist) {
				nbp->b_prev = bp->b_prev;
				nbp->b_next = bp->b_next;

				if (tcp->tcp_xmit_tail == bp)
					tcp->tcp_xmit_tail = nbp;
			}

			/* Free the original message. */
			bp->b_prev = NULL;
			bp->b_next = NULL;
			freeb(bp);

			bp = nbp;
		}

		if (head == NULL) {
			head = bp;
		}
		if (tail == NULL) {
			tail = bp;
		} else {
			tail->b_cont = bp;
			tail = bp;
		}

		/* Move forward. */
		bp = bp->b_cont;
	}

	if (fix_xmitlist) {
		tcp->tcp_xmit_last = tail;
		tcp->tcp_xmit_zc_clean = B_TRUE;
	}

	return (head);
}

void
tcp_zcopy_notify(tcp_t *tcp)
{
	struct stdata	*stp;
	conn_t		*connp;

	if (tcp->tcp_detached)
		return;
	connp = tcp->tcp_connp;
	if (IPCL_IS_NONSTR(connp)) {
		(*connp->conn_upcalls->su_zcopy_notify)
		    (connp->conn_upper_handle);
		return;
	}
	stp = STREAM(connp->conn_rq);
	mutex_enter(&stp->sd_lock);
	stp->sd_flag |= STZCNOTIFY;
	cv_broadcast(&stp->sd_zcopy_wait);
	mutex_exit(&stp->sd_lock);
}

/*
 * Update the TCP connection according to change of LSO capability.
 */
static void
tcp_update_lso(tcp_t *tcp, ip_xmit_attr_t *ixa)
{
	/*
	 * We check against IPv4 header length to preserve the old behavior
	 * of only enabling LSO when there are no IP options.
	 * But this restriction might not be necessary at all. Before removing
	 * it, need to verify how LSO is handled for source routing case, with
	 * which IP does software checksum.
	 *
	 * For IPv6, whenever any extension header is needed, LSO is supressed.
	 */
	if (ixa->ixa_ip_hdr_length != ((ixa->ixa_flags & IXAF_IS_IPV4) ?
	    IP_SIMPLE_HDR_LENGTH : IPV6_HDR_LEN))
		return;

	/*
	 * Either the LSO capability newly became usable, or it has changed.
	 */
	if (ixa->ixa_flags & IXAF_LSO_CAPAB) {
		ill_lso_capab_t	*lsoc = &ixa->ixa_lso_capab;

		ASSERT(lsoc->ill_lso_max > 0);
		tcp->tcp_lso_max = MIN(TCP_MAX_LSO_LENGTH, lsoc->ill_lso_max);

		DTRACE_PROBE3(tcp_update_lso, boolean_t, tcp->tcp_lso,
		    boolean_t, B_TRUE, uint32_t, tcp->tcp_lso_max);

		/*
		 * If LSO to be enabled, notify the STREAM header with larger
		 * data block.
		 */
		if (!tcp->tcp_lso)
			tcp->tcp_maxpsz_multiplier = 0;

		tcp->tcp_lso = B_TRUE;
		TCP_STAT(tcp->tcp_tcps, tcp_lso_enabled);
	} else { /* LSO capability is not usable any more. */
		DTRACE_PROBE3(tcp_update_lso, boolean_t, tcp->tcp_lso,
		    boolean_t, B_FALSE, uint32_t, tcp->tcp_lso_max);

		/*
		 * If LSO to be disabled, notify the STREAM header with smaller
		 * data block. And need to restore fragsize to PMTU.
		 */
		if (tcp->tcp_lso) {
			tcp->tcp_maxpsz_multiplier =
			    tcp->tcp_tcps->tcps_maxpsz_multiplier;
			ixa->ixa_fragsize = ixa->ixa_pmtu;
			tcp->tcp_lso = B_FALSE;
			TCP_STAT(tcp->tcp_tcps, tcp_lso_disabled);
		}
	}

	(void) tcp_maxpsz_set(tcp, B_TRUE);
}

/*
 * Update the TCP connection according to change of ZEROCOPY capability.
 */
static void
tcp_update_zcopy(tcp_t *tcp)
{
	conn_t		*connp = tcp->tcp_connp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	if (tcp->tcp_snd_zcopy_on) {
		tcp->tcp_snd_zcopy_on = B_FALSE;
		if (!TCP_IS_DETACHED(tcp)) {
			(void) proto_set_tx_copyopt(connp->conn_rq, connp,
			    ZCVMUNSAFE);
			TCP_STAT(tcps, tcp_zcopy_off);
		}
	} else {
		tcp->tcp_snd_zcopy_on = B_TRUE;
		if (!TCP_IS_DETACHED(tcp)) {
			(void) proto_set_tx_copyopt(connp->conn_rq, connp,
			    ZCVMSAFE);
			TCP_STAT(tcps, tcp_zcopy_on);
		}
	}
}

/*
 * Notify function registered with ip_xmit_attr_t. It's called in the squeue
 * so it's safe to update the TCP connection.
 */
/* ARGSUSED1 */
static void
tcp_notify(void *arg, ip_xmit_attr_t *ixa, ixa_notify_type_t ntype,
    ixa_notify_arg_t narg)
{
	tcp_t		*tcp = (tcp_t *)arg;
	conn_t		*connp = tcp->tcp_connp;

	switch (ntype) {
	case IXAN_LSO:
		tcp_update_lso(tcp, connp->conn_ixa);
		break;
	case IXAN_PMTU:
		tcp_update_pmtu(tcp, B_FALSE);
		break;
	case IXAN_ZCOPY:
		tcp_update_zcopy(tcp);
		break;
	default:
		break;
	}
}

/*
 * The TCP write service routine should never be called...
 */
/* ARGSUSED */
static void
tcp_wsrv(queue_t *q)
{
	tcp_stack_t	*tcps = Q_TO_TCP(q)->tcp_tcps;

	TCP_STAT(tcps, tcp_wsrv_called);
}

/*
 * Hash list lookup routine for tcp_t structures.
 * Returns with a CONN_INC_REF tcp structure. Caller must do a CONN_DEC_REF.
 */
tcp_t *
tcp_acceptor_hash_lookup(t_uscalar_t id, tcp_stack_t *tcps)
{
	tf_t	*tf;
	tcp_t	*tcp;

	tf = &tcps->tcps_acceptor_fanout[TCP_ACCEPTOR_HASH(id)];
	mutex_enter(&tf->tf_lock);
	for (tcp = tf->tf_tcp; tcp != NULL;
	    tcp = tcp->tcp_acceptor_hash) {
		if (tcp->tcp_acceptor_id == id) {
			CONN_INC_REF(tcp->tcp_connp);
			mutex_exit(&tf->tf_lock);
			return (tcp);
		}
	}
	mutex_exit(&tf->tf_lock);
	return (NULL);
}

/*
 * Hash list insertion routine for tcp_t structures.
 */
void
tcp_acceptor_hash_insert(t_uscalar_t id, tcp_t *tcp)
{
	tf_t	*tf;
	tcp_t	**tcpp;
	tcp_t	*tcpnext;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	tf = &tcps->tcps_acceptor_fanout[TCP_ACCEPTOR_HASH(id)];

	if (tcp->tcp_ptpahn != NULL)
		tcp_acceptor_hash_remove(tcp);
	tcpp = &tf->tf_tcp;
	mutex_enter(&tf->tf_lock);
	tcpnext = tcpp[0];
	if (tcpnext)
		tcpnext->tcp_ptpahn = &tcp->tcp_acceptor_hash;
	tcp->tcp_acceptor_hash = tcpnext;
	tcp->tcp_ptpahn = tcpp;
	tcpp[0] = tcp;
	tcp->tcp_acceptor_lockp = &tf->tf_lock;	/* For tcp_*_hash_remove */
	mutex_exit(&tf->tf_lock);
}

/*
 * Hash list removal routine for tcp_t structures.
 */
void
tcp_acceptor_hash_remove(tcp_t *tcp)
{
	tcp_t	*tcpnext;
	kmutex_t *lockp;

	/*
	 * Extract the lock pointer in case there are concurrent
	 * hash_remove's for this instance.
	 */
	lockp = tcp->tcp_acceptor_lockp;

	if (tcp->tcp_ptpahn == NULL)
		return;

	ASSERT(lockp != NULL);
	mutex_enter(lockp);
	if (tcp->tcp_ptpahn) {
		tcpnext = tcp->tcp_acceptor_hash;
		if (tcpnext) {
			tcpnext->tcp_ptpahn = tcp->tcp_ptpahn;
			tcp->tcp_acceptor_hash = NULL;
		}
		*tcp->tcp_ptpahn = tcpnext;
		tcp->tcp_ptpahn = NULL;
	}
	mutex_exit(lockp);
	tcp->tcp_acceptor_lockp = NULL;
}

/*
 * Type three generator adapted from the random() function in 4.4 BSD:
 */

/*
 * Copyright (c) 1983, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* Type 3 -- x**31 + x**3 + 1 */
#define	DEG_3		31
#define	SEP_3		3


/* Protected by tcp_random_lock */
static int tcp_randtbl[DEG_3 + 1];

static int *tcp_random_fptr = &tcp_randtbl[SEP_3 + 1];
static int *tcp_random_rptr = &tcp_randtbl[1];

static int *tcp_random_state = &tcp_randtbl[1];
static int *tcp_random_end_ptr = &tcp_randtbl[DEG_3 + 1];

kmutex_t tcp_random_lock;

void
tcp_random_init(void)
{
	int i;
	hrtime_t hrt;
	time_t wallclock;
	uint64_t result;

	/*
	 * Use high-res timer and current time for seed.  Gethrtime() returns
	 * a longlong, which may contain resolution down to nanoseconds.
	 * The current time will either be a 32-bit or a 64-bit quantity.
	 * XOR the two together in a 64-bit result variable.
	 * Convert the result to a 32-bit value by multiplying the high-order
	 * 32-bits by the low-order 32-bits.
	 */

	hrt = gethrtime();
	(void) drv_getparm(TIME, &wallclock);
	result = (uint64_t)wallclock ^ (uint64_t)hrt;
	mutex_enter(&tcp_random_lock);
	tcp_random_state[0] = ((result >> 32) & 0xffffffff) *
	    (result & 0xffffffff);

	for (i = 1; i < DEG_3; i++)
		tcp_random_state[i] = 1103515245 * tcp_random_state[i - 1]
		    + 12345;
	tcp_random_fptr = &tcp_random_state[SEP_3];
	tcp_random_rptr = &tcp_random_state[0];
	mutex_exit(&tcp_random_lock);
	for (i = 0; i < 10 * DEG_3; i++)
		(void) tcp_random();
}

/*
 * tcp_random: Return a random number in the range [1 - (128K + 1)].
 * This range is selected to be approximately centered on TCP_ISS / 2,
 * and easy to compute. We get this value by generating a 32-bit random
 * number, selecting out the high-order 17 bits, and then adding one so
 * that we never return zero.
 */
int
tcp_random(void)
{
	int i;

	mutex_enter(&tcp_random_lock);
	*tcp_random_fptr += *tcp_random_rptr;

	/*
	 * The high-order bits are more random than the low-order bits,
	 * so we select out the high-order 17 bits and add one so that
	 * we never return zero.
	 */
	i = ((*tcp_random_fptr >> 15) & 0x1ffff) + 1;
	if (++tcp_random_fptr >= tcp_random_end_ptr) {
		tcp_random_fptr = tcp_random_state;
		++tcp_random_rptr;
	} else if (++tcp_random_rptr >= tcp_random_end_ptr)
		tcp_random_rptr = tcp_random_state;

	mutex_exit(&tcp_random_lock);
	return (i);
}

/*
 * Split this function out so that if the secret changes, I'm okay.
 *
 * Initialize the tcp_iss_cookie and tcp_iss_key.
 */

#define	PASSWD_SIZE 16  /* MUST be multiple of 4 */

void
tcp_iss_key_init(uint8_t *phrase, int len, tcp_stack_t *tcps)
{
	struct {
		int32_t current_time;
		uint32_t randnum;
		uint16_t pad;
		uint8_t ether[6];
		uint8_t passwd[PASSWD_SIZE];
	} tcp_iss_cookie;
	time_t t;

	/*
	 * Start with the current absolute time.
	 */
	(void) drv_getparm(TIME, &t);
	tcp_iss_cookie.current_time = t;

	/*
	 * XXX - Need a more random number per RFC 1750, not this crap.
	 * OTOH, if what follows is pretty random, then I'm in better shape.
	 */
	tcp_iss_cookie.randnum = (uint32_t)(gethrtime() + tcp_random());
	tcp_iss_cookie.pad = 0x365c;  /* Picked from HMAC pad values. */

	/*
	 * The cpu_type_info is pretty non-random.  Ugggh.  It does serve
	 * as a good template.
	 */
	bcopy(&cpu_list->cpu_type_info, &tcp_iss_cookie.passwd,
	    min(PASSWD_SIZE, sizeof (cpu_list->cpu_type_info)));

	/*
	 * The pass-phrase.  Normally this is supplied by user-called NDD.
	 */
	bcopy(phrase, &tcp_iss_cookie.passwd, min(PASSWD_SIZE, len));

	/*
	 * See 4010593 if this section becomes a problem again,
	 * but the local ethernet address is useful here.
	 */
	(void) localetheraddr(NULL,
	    (struct ether_addr *)&tcp_iss_cookie.ether);

	/*
	 * Hash 'em all together.  The MD5Final is called per-connection.
	 */
	mutex_enter(&tcps->tcps_iss_key_lock);
	MD5Init(&tcps->tcps_iss_key);
	MD5Update(&tcps->tcps_iss_key, (uchar_t *)&tcp_iss_cookie,
	    sizeof (tcp_iss_cookie));
	mutex_exit(&tcps->tcps_iss_key_lock);
}

/*
 * Called by IP when IP is loaded into the kernel
 */
void
tcp_ddi_g_init(void)
{
	tcp_timercache = kmem_cache_create("tcp_timercache",
	    sizeof (tcp_timer_t) + sizeof (mblk_t), 0,
	    NULL, NULL, NULL, NULL, NULL, 0);

	tcp_notsack_blk_cache = kmem_cache_create("tcp_notsack_blk_cache",
	    sizeof (notsack_blk_t), 0, NULL, NULL, NULL, NULL, NULL, 0);

	mutex_init(&tcp_random_lock, NULL, MUTEX_DEFAULT, NULL);

	/* Initialize the random number generator */
	tcp_random_init();

	/* A single callback independently of how many netstacks we have */
	ip_squeue_init(tcp_squeue_add);

	tcp_g_kstat = tcp_g_kstat_init(&tcp_g_statistics);

	tcp_squeue_flag = tcp_squeue_switch(tcp_squeue_wput);

	/*
	 * We want to be informed each time a stack is created or
	 * destroyed in the kernel, so we can maintain the
	 * set of tcp_stack_t's.
	 */
	netstack_register(NS_TCP, tcp_stack_init, NULL, tcp_stack_fini);
}


#define	INET_NAME	"ip"

/*
 * Initialize the TCP stack instance.
 */
static void *
tcp_stack_init(netstackid_t stackid, netstack_t *ns)
{
	tcp_stack_t	*tcps;
	int		i;
	int		error = 0;
	major_t		major;
	size_t		arrsz;

	tcps = (tcp_stack_t *)kmem_zalloc(sizeof (*tcps), KM_SLEEP);
	tcps->tcps_netstack = ns;

	/* Initialize locks */
	mutex_init(&tcps->tcps_iss_key_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&tcps->tcps_epriv_port_lock, NULL, MUTEX_DEFAULT, NULL);

	tcps->tcps_g_num_epriv_ports = TCP_NUM_EPRIV_PORTS;
	tcps->tcps_g_epriv_ports[0] = ULP_DEF_EPRIV_PORT1;
	tcps->tcps_g_epriv_ports[1] = ULP_DEF_EPRIV_PORT2;
	tcps->tcps_min_anonpriv_port = 512;

	tcps->tcps_bind_fanout = kmem_zalloc(sizeof (tf_t) *
	    TCP_BIND_FANOUT_SIZE, KM_SLEEP);
	tcps->tcps_acceptor_fanout = kmem_zalloc(sizeof (tf_t) *
	    TCP_ACCEPTOR_FANOUT_SIZE, KM_SLEEP);

	for (i = 0; i < TCP_BIND_FANOUT_SIZE; i++) {
		mutex_init(&tcps->tcps_bind_fanout[i].tf_lock, NULL,
		    MUTEX_DEFAULT, NULL);
	}

	for (i = 0; i < TCP_ACCEPTOR_FANOUT_SIZE; i++) {
		mutex_init(&tcps->tcps_acceptor_fanout[i].tf_lock, NULL,
		    MUTEX_DEFAULT, NULL);
	}

	/* TCP's IPsec code calls the packet dropper. */
	ip_drop_register(&tcps->tcps_dropper, "TCP IPsec policy enforcement");

	arrsz = tcp_propinfo_count * sizeof (mod_prop_info_t);
	tcps->tcps_propinfo_tbl = (mod_prop_info_t *)kmem_alloc(arrsz,
	    KM_SLEEP);
	bcopy(tcp_propinfo_tbl, tcps->tcps_propinfo_tbl, arrsz);

	/*
	 * Note: To really walk the device tree you need the devinfo
	 * pointer to your device which is only available after probe/attach.
	 * The following is safe only because it uses ddi_root_node()
	 */
	tcp_max_optsize = optcom_max_optsize(tcp_opt_obj.odb_opt_des_arr,
	    tcp_opt_obj.odb_opt_arr_cnt);

	/*
	 * Initialize RFC 1948 secret values.  This will probably be reset once
	 * by the boot scripts.
	 *
	 * Use NULL name, as the name is caught by the new lockstats.
	 *
	 * Initialize with some random, non-guessable string, like the global
	 * T_INFO_ACK.
	 */

	tcp_iss_key_init((uint8_t *)&tcp_g_t_info_ack,
	    sizeof (tcp_g_t_info_ack), tcps);

	tcps->tcps_kstat = tcp_kstat2_init(stackid);
	tcps->tcps_mibkp = tcp_kstat_init(stackid);

	major = mod_name_to_major(INET_NAME);
	error = ldi_ident_from_major(major, &tcps->tcps_ldi_ident);
	ASSERT(error == 0);
	tcps->tcps_ixa_cleanup_mp = allocb_wait(0, BPRI_MED, STR_NOSIG, NULL);
	ASSERT(tcps->tcps_ixa_cleanup_mp != NULL);
	cv_init(&tcps->tcps_ixa_cleanup_ready_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&tcps->tcps_ixa_cleanup_done_cv, NULL, CV_DEFAULT, NULL);
	mutex_init(&tcps->tcps_ixa_cleanup_lock, NULL, MUTEX_DEFAULT, NULL);

	mutex_init(&tcps->tcps_reclaim_lock, NULL, MUTEX_DEFAULT, NULL);
	tcps->tcps_reclaim = B_FALSE;
	tcps->tcps_reclaim_tid = 0;
	tcps->tcps_reclaim_period = tcps->tcps_rexmit_interval_max;

	/*
	 * ncpus is the current number of CPUs, which can be bigger than
	 * boot_ncpus.  But we don't want to use ncpus to allocate all the
	 * tcp_stats_cpu_t at system boot up time since it will be 1.  While
	 * we handle adding CPU in tcp_cpu_update(), it will be slow if
	 * there are many CPUs as we will be adding them 1 by 1.
	 *
	 * Note that tcps_sc_cnt never decreases and the tcps_sc[x] pointers
	 * are not freed until the stack is going away.  So there is no need
	 * to grab a lock to access the per CPU tcps_sc[x] pointer.
	 */
	mutex_enter(&cpu_lock);
	tcps->tcps_sc_cnt = MAX(ncpus, boot_ncpus);
	mutex_exit(&cpu_lock);
	tcps->tcps_sc = kmem_zalloc(max_ncpus  * sizeof (tcp_stats_cpu_t *),
	    KM_SLEEP);
	for (i = 0; i < tcps->tcps_sc_cnt; i++) {
		tcps->tcps_sc[i] = kmem_zalloc(sizeof (tcp_stats_cpu_t),
		    KM_SLEEP);
	}

	mutex_init(&tcps->tcps_listener_conf_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&tcps->tcps_listener_conf, sizeof (tcp_listener_t),
	    offsetof(tcp_listener_t, tl_link));

	return (tcps);
}

/*
 * Called when the IP module is about to be unloaded.
 */
void
tcp_ddi_g_destroy(void)
{
	tcp_g_kstat_fini(tcp_g_kstat);
	tcp_g_kstat = NULL;
	bzero(&tcp_g_statistics, sizeof (tcp_g_statistics));

	mutex_destroy(&tcp_random_lock);

	kmem_cache_destroy(tcp_timercache);
	kmem_cache_destroy(tcp_notsack_blk_cache);

	netstack_unregister(NS_TCP);
}

/*
 * Free the TCP stack instance.
 */
static void
tcp_stack_fini(netstackid_t stackid, void *arg)
{
	tcp_stack_t *tcps = (tcp_stack_t *)arg;
	int i;

	freeb(tcps->tcps_ixa_cleanup_mp);
	tcps->tcps_ixa_cleanup_mp = NULL;
	cv_destroy(&tcps->tcps_ixa_cleanup_ready_cv);
	cv_destroy(&tcps->tcps_ixa_cleanup_done_cv);
	mutex_destroy(&tcps->tcps_ixa_cleanup_lock);

	/*
	 * Set tcps_reclaim to false tells tcp_reclaim_timer() not to restart
	 * the timer.
	 */
	mutex_enter(&tcps->tcps_reclaim_lock);
	tcps->tcps_reclaim = B_FALSE;
	mutex_exit(&tcps->tcps_reclaim_lock);
	if (tcps->tcps_reclaim_tid != 0)
		(void) untimeout(tcps->tcps_reclaim_tid);
	mutex_destroy(&tcps->tcps_reclaim_lock);

	tcp_listener_conf_cleanup(tcps);

	for (i = 0; i < tcps->tcps_sc_cnt; i++)
		kmem_free(tcps->tcps_sc[i], sizeof (tcp_stats_cpu_t));
	kmem_free(tcps->tcps_sc, max_ncpus * sizeof (tcp_stats_cpu_t *));

	kmem_free(tcps->tcps_propinfo_tbl,
	    tcp_propinfo_count * sizeof (mod_prop_info_t));
	tcps->tcps_propinfo_tbl = NULL;

	for (i = 0; i < TCP_BIND_FANOUT_SIZE; i++) {
		ASSERT(tcps->tcps_bind_fanout[i].tf_tcp == NULL);
		mutex_destroy(&tcps->tcps_bind_fanout[i].tf_lock);
	}

	for (i = 0; i < TCP_ACCEPTOR_FANOUT_SIZE; i++) {
		ASSERT(tcps->tcps_acceptor_fanout[i].tf_tcp == NULL);
		mutex_destroy(&tcps->tcps_acceptor_fanout[i].tf_lock);
	}

	kmem_free(tcps->tcps_bind_fanout, sizeof (tf_t) * TCP_BIND_FANOUT_SIZE);
	tcps->tcps_bind_fanout = NULL;

	kmem_free(tcps->tcps_acceptor_fanout, sizeof (tf_t) *
	    TCP_ACCEPTOR_FANOUT_SIZE);
	tcps->tcps_acceptor_fanout = NULL;

	mutex_destroy(&tcps->tcps_iss_key_lock);
	mutex_destroy(&tcps->tcps_epriv_port_lock);

	ip_drop_unregister(&tcps->tcps_dropper);

	tcp_kstat2_fini(stackid, tcps->tcps_kstat);
	tcps->tcps_kstat = NULL;

	tcp_kstat_fini(stackid, tcps->tcps_mibkp);
	tcps->tcps_mibkp = NULL;

	ldi_ident_release(tcps->tcps_ldi_ident);
	kmem_free(tcps, sizeof (*tcps));
}

/*
 * Generate ISS, taking into account NDD changes may happen halfway through.
 * (If the iss is not zero, set it.)
 */

static void
tcp_iss_init(tcp_t *tcp)
{
	MD5_CTX context;
	struct { uint32_t ports; in6_addr_t src; in6_addr_t dst; } arg;
	uint32_t answer[4];
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	conn_t		*connp = tcp->tcp_connp;

	tcps->tcps_iss_incr_extra += (tcps->tcps_iss_incr >> 1);
	tcp->tcp_iss = tcps->tcps_iss_incr_extra;
	switch (tcps->tcps_strong_iss) {
	case 2:
		mutex_enter(&tcps->tcps_iss_key_lock);
		context = tcps->tcps_iss_key;
		mutex_exit(&tcps->tcps_iss_key_lock);
		arg.ports = connp->conn_ports;
		arg.src = connp->conn_laddr_v6;
		arg.dst = connp->conn_faddr_v6;
		MD5Update(&context, (uchar_t *)&arg, sizeof (arg));
		MD5Final((uchar_t *)answer, &context);
		tcp->tcp_iss += answer[0] ^ answer[1] ^ answer[2] ^ answer[3];
		/*
		 * Now that we've hashed into a unique per-connection sequence
		 * space, add a random increment per strong_iss == 1.  So I
		 * guess we'll have to...
		 */
		/* FALLTHRU */
	case 1:
		tcp->tcp_iss += (gethrtime() >> ISS_NSEC_SHT) + tcp_random();
		break;
	default:
		tcp->tcp_iss += (uint32_t)gethrestime_sec() *
		    tcps->tcps_iss_incr;
		break;
	}
	tcp->tcp_valid_bits = TCP_ISS_VALID;
	tcp->tcp_fss = tcp->tcp_iss - 1;
	tcp->tcp_suna = tcp->tcp_iss;
	tcp->tcp_snxt = tcp->tcp_iss + 1;
	tcp->tcp_rexmit_nxt = tcp->tcp_snxt;
	tcp->tcp_csuna = tcp->tcp_snxt;
}

/*
 * tcp_{set,clr}qfull() functions are used to either set or clear QFULL
 * on the specified backing STREAMS q. Note, the caller may make the
 * decision to call based on the tcp_t.tcp_flow_stopped value which
 * when check outside the q's lock is only an advisory check ...
 */
void
tcp_setqfull(tcp_t *tcp)
{
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	conn_t	*connp = tcp->tcp_connp;

	if (tcp->tcp_closed)
		return;

	conn_setqfull(connp, &tcp->tcp_flow_stopped);
	if (tcp->tcp_flow_stopped)
		TCP_STAT(tcps, tcp_flwctl_on);
}

void
tcp_clrqfull(tcp_t *tcp)
{
	conn_t  *connp = tcp->tcp_connp;

	if (tcp->tcp_closed)
		return;
	conn_clrqfull(connp, &tcp->tcp_flow_stopped);
}

static int
tcp_squeue_switch(int val)
{
	int rval = SQ_FILL;

	switch (val) {
	case 1:
		rval = SQ_NODRAIN;
		break;
	case 2:
		rval = SQ_PROCESS;
		break;
	default:
		break;
	}
	return (rval);
}

/*
 * This is called once for each squeue - globally for all stack
 * instances.
 */
static void
tcp_squeue_add(squeue_t *sqp)
{
	tcp_squeue_priv_t *tcp_time_wait = kmem_zalloc(
	    sizeof (tcp_squeue_priv_t), KM_SLEEP);

	*squeue_getprivate(sqp, SQPRIVATE_TCP) = (intptr_t)tcp_time_wait;
	if (tcp_free_list_max_cnt == 0) {
		int tcp_ncpus = ((boot_max_ncpus == -1) ?
		    max_ncpus : boot_max_ncpus);

		/*
		 * Limit number of entries to 1% of availble memory / tcp_ncpus
		 */
		tcp_free_list_max_cnt = (freemem * PAGESIZE) /
		    (tcp_ncpus * sizeof (tcp_t) * 100);
	}
	tcp_time_wait->tcp_free_list_cnt = 0;
}
/*
 * Return unix error is tli error is TSYSERR, otherwise return a negative
 * tli error.
 */
int
tcp_do_bind(conn_t *connp, struct sockaddr *sa, socklen_t len, cred_t *cr,
    boolean_t bind_to_req_port_only)
{
	int error;
	tcp_t *tcp = connp->conn_tcp;

	if (tcp->tcp_state >= TCPS_BOUND) {
		if (connp->conn_debug) {
			(void) strlog(TCP_MOD_ID, 0, 1, SL_ERROR|SL_TRACE,
			    "tcp_bind: bad state, %d", tcp->tcp_state);
		}
		return (-TOUTSTATE);
	}

	error = tcp_bind_check(connp, sa, len, cr, bind_to_req_port_only);
	if (error != 0)
		return (error);

	ASSERT(tcp->tcp_state == TCPS_BOUND);
	tcp->tcp_conn_req_max = 0;
	return (0);
}

/*
 * If the return value from this function is positive, it's a UNIX error.
 * Otherwise, if it's negative, then the absolute value is a TLI error.
 * the TPI routine tcp_tpi_connect() is a wrapper function for this.
 */
int
tcp_do_connect(conn_t *connp, const struct sockaddr *sa, socklen_t len,
    cred_t *cr, pid_t pid)
{
	tcp_t		*tcp = connp->conn_tcp;
	sin_t		*sin = (sin_t *)sa;
	sin6_t		*sin6 = (sin6_t *)sa;
	ipaddr_t	*dstaddrp;
	in_port_t	dstport;
	uint_t		srcid;
	int		error;
	uint32_t	mss;
	mblk_t		*syn_mp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	int32_t		oldstate;
	ip_xmit_attr_t	*ixa = connp->conn_ixa;

	oldstate = tcp->tcp_state;

	switch (len) {
	default:
		/*
		 * Should never happen
		 */
		return (EINVAL);

	case sizeof (sin_t):
		sin = (sin_t *)sa;
		if (sin->sin_port == 0) {
			return (-TBADADDR);
		}
		if (connp->conn_ipv6_v6only) {
			return (EAFNOSUPPORT);
		}
		break;

	case sizeof (sin6_t):
		sin6 = (sin6_t *)sa;
		if (sin6->sin6_port == 0) {
			return (-TBADADDR);
		}
		break;
	}
	/*
	 * If we're connecting to an IPv4-mapped IPv6 address, we need to
	 * make sure that the conn_ipversion is IPV4_VERSION.  We
	 * need to this before we call tcp_bindi() so that the port lookup
	 * code will look for ports in the correct port space (IPv4 and
	 * IPv6 have separate port spaces).
	 */
	if (connp->conn_family == AF_INET6 &&
	    connp->conn_ipversion == IPV6_VERSION &&
	    IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
		if (connp->conn_ipv6_v6only)
			return (EADDRNOTAVAIL);

		connp->conn_ipversion = IPV4_VERSION;
	}

	switch (tcp->tcp_state) {
	case TCPS_LISTEN:
		/*
		 * Listening sockets are not allowed to issue connect().
		 */
		if (IPCL_IS_NONSTR(connp))
			return (EOPNOTSUPP);
		/* FALLTHRU */
	case TCPS_IDLE:
		/*
		 * We support quick connect, refer to comments in
		 * tcp_connect_*()
		 */
		/* FALLTHRU */
	case TCPS_BOUND:
		break;
	default:
		return (-TOUTSTATE);
	}

	/*
	 * We update our cred/cpid based on the caller of connect
	 */
	if (connp->conn_cred != cr) {
		crhold(cr);
		crfree(connp->conn_cred);
		connp->conn_cred = cr;
	}
	connp->conn_cpid = pid;

	/* Cache things in the ixa without any refhold */
	ASSERT(!(ixa->ixa_free_flags & IXA_FREE_CRED));
	ixa->ixa_cred = cr;
	ixa->ixa_cpid = pid;
	if (is_system_labeled()) {
		/* We need to restart with a label based on the cred */
		ip_xmit_attr_restore_tsl(ixa, ixa->ixa_cred);
	}

	if (connp->conn_family == AF_INET6) {
		if (!IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
			error = tcp_connect_ipv6(tcp, &sin6->sin6_addr,
			    sin6->sin6_port, sin6->sin6_flowinfo,
			    sin6->__sin6_src_id, sin6->sin6_scope_id);
		} else {
			/*
			 * Destination adress is mapped IPv6 address.
			 * Source bound address should be unspecified or
			 * IPv6 mapped address as well.
			 */
			if (!IN6_IS_ADDR_UNSPECIFIED(
			    &connp->conn_bound_addr_v6) &&
			    !IN6_IS_ADDR_V4MAPPED(&connp->conn_bound_addr_v6)) {
				return (EADDRNOTAVAIL);
			}
			dstaddrp = &V4_PART_OF_V6((sin6->sin6_addr));
			dstport = sin6->sin6_port;
			srcid = sin6->__sin6_src_id;
			error = tcp_connect_ipv4(tcp, dstaddrp, dstport,
			    srcid);
		}
	} else {
		dstaddrp = &sin->sin_addr.s_addr;
		dstport = sin->sin_port;
		srcid = 0;
		error = tcp_connect_ipv4(tcp, dstaddrp, dstport, srcid);
	}

	if (error != 0)
		goto connect_failed;

	CL_INET_CONNECT(connp, B_TRUE, error);
	if (error != 0)
		goto connect_failed;

	/* connect succeeded */
	TCPS_BUMP_MIB(tcps, tcpActiveOpens);
	tcp->tcp_active_open = 1;

	/*
	 * tcp_set_destination() does not adjust for TCP/IP header length.
	 */
	mss = tcp->tcp_mss - connp->conn_ht_iphc_len;

	/*
	 * Just make sure our rwnd is at least rcvbuf * MSS large, and round up
	 * to the nearest MSS.
	 *
	 * We do the round up here because we need to get the interface MTU
	 * first before we can do the round up.
	 */
	tcp->tcp_rwnd = connp->conn_rcvbuf;
	tcp->tcp_rwnd = MAX(MSS_ROUNDUP(tcp->tcp_rwnd, mss),
	    tcps->tcps_recv_hiwat_minmss * mss);
	connp->conn_rcvbuf = tcp->tcp_rwnd;
	tcp_set_ws_value(tcp);
	tcp->tcp_tcpha->tha_win = htons(tcp->tcp_rwnd >> tcp->tcp_rcv_ws);
	if (tcp->tcp_rcv_ws > 0 || tcps->tcps_wscale_always)
		tcp->tcp_snd_ws_ok = B_TRUE;

	/*
	 * Set tcp_snd_ts_ok to true
	 * so that tcp_xmit_mp will
	 * include the timestamp
	 * option in the SYN segment.
	 */
	if (tcps->tcps_tstamp_always ||
	    (tcp->tcp_rcv_ws && tcps->tcps_tstamp_if_wscale)) {
		tcp->tcp_snd_ts_ok = B_TRUE;
	}

	/*
	 * Note that tcp_snd_sack_ok can be set in tcp_set_destination() if
	 * the SACK metric is set.  So here we just check the per stack SACK
	 * permitted param.
	 */
	if (tcps->tcps_sack_permitted == 2) {
		ASSERT(tcp->tcp_num_sack_blk == 0);
		ASSERT(tcp->tcp_notsack_list == NULL);
		tcp->tcp_snd_sack_ok = B_TRUE;
	}

	/*
	 * Should we use ECN?  Note that the current
	 * default value (SunOS 5.9) of tcp_ecn_permitted
	 * is 1.  The reason for doing this is that there
	 * are equipments out there that will drop ECN
	 * enabled IP packets.  Setting it to 1 avoids
	 * compatibility problems.
	 */
	if (tcps->tcps_ecn_permitted == 2)
		tcp->tcp_ecn_ok = B_TRUE;

	/* Trace change from BOUND -> SYN_SENT here */
	DTRACE_TCP6(state__change, void, NULL, ip_xmit_attr_t *,
	    connp->conn_ixa, void, NULL, tcp_t *, tcp, void, NULL,
	    int32_t, TCPS_BOUND);

	TCP_TIMER_RESTART(tcp, tcp->tcp_rto);
	syn_mp = tcp_xmit_mp(tcp, NULL, 0, NULL, NULL,
	    tcp->tcp_iss, B_FALSE, NULL, B_FALSE);
	if (syn_mp != NULL) {
		/*
		 * We must bump the generation before sending the syn
		 * to ensure that we use the right generation in case
		 * this thread issues a "connected" up call.
		 */
		SOCK_CONNID_BUMP(tcp->tcp_connid);
		/*
		 * DTrace sending the first SYN as a
		 * tcp:::connect-request event.
		 */
		DTRACE_TCP5(connect__request, mblk_t *, NULL,
		    ip_xmit_attr_t *, connp->conn_ixa,
		    void_ip_t *, syn_mp->b_rptr, tcp_t *, tcp,
		    tcph_t *,
		    &syn_mp->b_rptr[connp->conn_ixa->ixa_ip_hdr_length]);
		tcp_send_data(tcp, syn_mp);
	}

	if (tcp->tcp_conn.tcp_opts_conn_req != NULL)
		tcp_close_mpp(&tcp->tcp_conn.tcp_opts_conn_req);
	return (0);

connect_failed:
	connp->conn_faddr_v6 = ipv6_all_zeros;
	connp->conn_fport = 0;
	tcp->tcp_state = oldstate;
	if (tcp->tcp_conn.tcp_opts_conn_req != NULL)
		tcp_close_mpp(&tcp->tcp_conn.tcp_opts_conn_req);
	return (error);
}

int
tcp_do_listen(conn_t *connp, struct sockaddr *sa, socklen_t len,
    int backlog, cred_t *cr, boolean_t bind_to_req_port_only)
{
	tcp_t		*tcp = connp->conn_tcp;
	int		error = 0;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	int32_t		oldstate;

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	if (tcp->tcp_state >= TCPS_BOUND) {
		if ((tcp->tcp_state == TCPS_BOUND ||
		    tcp->tcp_state == TCPS_LISTEN) && backlog > 0) {
			/*
			 * Handle listen() increasing backlog.
			 * This is more "liberal" then what the TPI spec
			 * requires but is needed to avoid a t_unbind
			 * when handling listen() since the port number
			 * might be "stolen" between the unbind and bind.
			 */
			goto do_listen;
		}
		if (connp->conn_debug) {
			(void) strlog(TCP_MOD_ID, 0, 1, SL_ERROR|SL_TRACE,
			    "tcp_listen: bad state, %d", tcp->tcp_state);
		}
		return (-TOUTSTATE);
	} else {
		if (sa == NULL) {
			sin6_t	addr;
			sin_t *sin;
			sin6_t *sin6;

			ASSERT(IPCL_IS_NONSTR(connp));
			/* Do an implicit bind: Request for a generic port. */
			if (connp->conn_family == AF_INET) {
				len = sizeof (sin_t);
				sin = (sin_t *)&addr;
				*sin = sin_null;
				sin->sin_family = AF_INET;
			} else {
				ASSERT(connp->conn_family == AF_INET6);
				len = sizeof (sin6_t);
				sin6 = (sin6_t *)&addr;
				*sin6 = sin6_null;
				sin6->sin6_family = AF_INET6;
			}
			sa = (struct sockaddr *)&addr;
		}

		error = tcp_bind_check(connp, sa, len, cr,
		    bind_to_req_port_only);
		if (error)
			return (error);
		/* Fall through and do the fanout insertion */
	}

do_listen:
	ASSERT(tcp->tcp_state == TCPS_BOUND || tcp->tcp_state == TCPS_LISTEN);
	tcp->tcp_conn_req_max = backlog;
	if (tcp->tcp_conn_req_max) {
		if (tcp->tcp_conn_req_max < tcps->tcps_conn_req_min)
			tcp->tcp_conn_req_max = tcps->tcps_conn_req_min;
		if (tcp->tcp_conn_req_max > tcps->tcps_conn_req_max_q)
			tcp->tcp_conn_req_max = tcps->tcps_conn_req_max_q;
		/*
		 * If this is a listener, do not reset the eager list
		 * and other stuffs.  Note that we don't check if the
		 * existing eager list meets the new tcp_conn_req_max
		 * requirement.
		 */
		if (tcp->tcp_state != TCPS_LISTEN) {
			tcp->tcp_state = TCPS_LISTEN;
			DTRACE_TCP6(state__change, void, NULL, ip_xmit_attr_t *,
			    connp->conn_ixa, void, NULL, tcp_t *, tcp,
			    void, NULL, int32_t, TCPS_BOUND);
			/* Initialize the chain. Don't need the eager_lock */
			tcp->tcp_eager_next_q0 = tcp->tcp_eager_prev_q0 = tcp;
			tcp->tcp_eager_next_drop_q0 = tcp;
			tcp->tcp_eager_prev_drop_q0 = tcp;
			tcp->tcp_second_ctimer_threshold =
			    tcps->tcps_ip_abort_linterval;
		}
	}

	/*
	 * We need to make sure that the conn_recv is set to a non-null
	 * value before we insert the conn into the classifier table.
	 * This is to avoid a race with an incoming packet which does an
	 * ipcl_classify().
	 * We initially set it to tcp_input_listener_unbound to try to
	 * pick a good squeue for the listener when the first SYN arrives.
	 * tcp_input_listener_unbound sets it to tcp_input_listener on that
	 * first SYN.
	 */
	connp->conn_recv = tcp_input_listener_unbound;

	/* Insert the listener in the classifier table */
	error = ip_laddr_fanout_insert(connp);
	if (error != 0) {
		/* Undo the bind - release the port number */
		oldstate = tcp->tcp_state;
		tcp->tcp_state = TCPS_IDLE;
		DTRACE_TCP6(state__change, void, NULL, ip_xmit_attr_t *,
		    connp->conn_ixa, void, NULL, tcp_t *, tcp, void, NULL,
		    int32_t, oldstate);
		connp->conn_bound_addr_v6 = ipv6_all_zeros;

		connp->conn_laddr_v6 = ipv6_all_zeros;
		connp->conn_saddr_v6 = ipv6_all_zeros;
		connp->conn_ports = 0;

		if (connp->conn_anon_port) {
			zone_t		*zone;

			zone = crgetzone(cr);
			connp->conn_anon_port = B_FALSE;
			(void) tsol_mlp_anon(zone, connp->conn_mlp_type,
			    connp->conn_proto, connp->conn_lport, B_FALSE);
		}
		connp->conn_mlp_type = mlptSingle;

		tcp_bind_hash_remove(tcp);
		return (error);
	} else {
		/*
		 * If there is a connection limit, allocate and initialize
		 * the counter struct.  Note that since listen can be called
		 * multiple times, the struct may have been allready allocated.
		 */
		if (!list_is_empty(&tcps->tcps_listener_conf) &&
		    tcp->tcp_listen_cnt == NULL) {
			tcp_listen_cnt_t *tlc;
			uint32_t ratio;

			ratio = tcp_find_listener_conf(tcps,
			    ntohs(connp->conn_lport));
			if (ratio != 0) {
				uint32_t mem_ratio, tot_buf;

				tlc = kmem_alloc(sizeof (tcp_listen_cnt_t),
				    KM_SLEEP);
				/*
				 * Calculate the connection limit based on
				 * the configured ratio and maxusers.  Maxusers
				 * are calculated based on memory size,
				 * ~ 1 user per MB.  Note that the conn_rcvbuf
				 * and conn_sndbuf may change after a
				 * connection is accepted.  So what we have
				 * is only an approximation.
				 */
				if ((tot_buf = connp->conn_rcvbuf +
				    connp->conn_sndbuf) < MB) {
					mem_ratio = MB / tot_buf;
					tlc->tlc_max = maxusers / ratio *
					    mem_ratio;
				} else {
					mem_ratio = tot_buf / MB;
					tlc->tlc_max = maxusers / ratio /
					    mem_ratio;
				}
				/* At least we should allow two connections! */
				if (tlc->tlc_max <= tcp_min_conn_listener)
					tlc->tlc_max = tcp_min_conn_listener;
				tlc->tlc_cnt = 1;
				tlc->tlc_drop = 0;
				tcp->tcp_listen_cnt = tlc;
			}
		}
	}
	return (error);
}
