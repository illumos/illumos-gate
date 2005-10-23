/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

const char ipclassifier_version[] = "@(#)ipclassifier.c	1.6	04/03/31 SMI";

/*
 * IP PACKET CLASSIFIER
 *
 * The IP packet classifier provides mapping between IP packets and persistent
 * connection state for connection-oriented protocols. It also provides
 * interface for managing connection states.
 *
 * The connection state is kept in conn_t data structure and contains, among
 * other things:
 *
 *	o local/remote address and ports
 *	o Transport protocol
 *	o squeue for the connection (for TCP only)
 *	o reference counter
 *	o Connection state
 *	o hash table linkage
 *	o interface/ire information
 *	o credentials
 *	o ipsec policy
 *	o send and receive functions.
 *	o mutex lock.
 *
 * Connections use a reference counting scheme. They are freed when the
 * reference counter drops to zero. A reference is incremented when connection
 * is placed in a list or table, when incoming packet for the connection arrives
 * and when connection is processed via squeue (squeue processing may be
 * asynchronous and the reference protects the connection from being destroyed
 * before its processing is finished).
 *
 * send and receive functions are currently used for TCP only. The send function
 * determines the IP entry point for the packet once it leaves TCP to be sent to
 * the destination address. The receive function is used by IP when the packet
 * should be passed for TCP processing. When a new connection is created these
 * are set to ip_output() and tcp_input() respectively. During the lifetime of
 * the connection the send and receive functions may change depending on the
 * changes in the connection state. For example, Once the connection is bound to
 * an addresse, the receive function for this connection is set to
 * tcp_conn_request().  This allows incoming SYNs to go directly into the
 * listener SYN processing function without going to tcp_input() first.
 *
 * Classifier uses several hash tables:
 *
 * 	ipcl_conn_fanout:	contains all TCP connections in CONNECTED state
 *	ipcl_bind_fanout:	contains all connections in BOUND state
 *	ipcl_proto_fanout:	IPv4 protocol fanout
 *	ipcl_proto_fanout_v6:	IPv6 protocol fanout
 *	ipcl_udp_fanout:	contains all UDP connections
 *	ipcl_globalhash_fanout:	contains all connections
 *
 * The ipcl_globalhash_fanout is used for any walkers (like snmp and Clustering)
 * which need to view all existing connections.
 *
 * All tables are protected by per-bucket locks. When both per-bucket lock and
 * connection lock need to be held, the per-bucket lock should be acquired
 * first, followed by the connection lock.
 *
 * All functions doing search in one of these tables increment a reference
 * counter on the connection found (if any). This reference should be dropped
 * when the caller has finished processing the connection.
 *
 *
 * INTERFACES:
 * ===========
 *
 * Connection Lookup:
 * ------------------
 *
 * conn_t *ipcl_classify_v4(mp, protocol, hdr_len, zoneid)
 * conn_t *ipcl_classify_v6(mp, protocol, hdr_len, zoneid)
 *
 * Finds connection for an incoming IPv4 or IPv6 packet. Returns NULL if
 * it can't find any associated connection. If the connection is found, its
 * reference counter is incremented.
 *
 *	mp:	mblock, containing packet header. The full header should fit
 *		into a single mblock. It should also contain at least full IP
 *		and TCP or UDP header.
 *
 *	protocol: Either IPPROTO_TCP or IPPROTO_UDP.
 *
 *	hdr_len: The size of IP header. It is used to find TCP or UDP header in
 *		 the packet.
 *
 * 	zoneid: The zone in which the returned connection must be.
 *
 *	For TCP connections, the lookup order is as follows:
 *		5-tuple {src, dst, protocol, local port, remote port}
 *			lookup in ipcl_conn_fanout table.
 *		3-tuple {dst, remote port, protocol} lookup in
 *			ipcl_bind_fanout table.
 *
 *	For UDP connections, a 5-tuple {src, dst, protocol, local port,
 *	remote port} lookup is done on ipcl_udp_fanout. Note that,
 *	these interfaces do not handle cases where a packets belongs
 *	to multiple UDP clients, which is handled in IP itself.
 *
 * conn_t	*ipcl_tcp_lookup_reversed_ipv4(ipha_t *, tcph_t *, int);
 * conn_t	*ipcl_tcp_lookup_reversed_ipv6(ip6_t *, tcpha_t *, int, uint_t);
 *
 *	Lookup routine to find a exact match for {src, dst, local port,
 *	remote port) for TCP connections in ipcl_conn_fanout. The address and
 *	ports are read from the IP and TCP header respectively.
 *
 * conn_t	*ipcl_lookup_listener_v4(lport, laddr, protocol);
 * conn_t	*ipcl_lookup_listener_v6(lport, laddr, protocol, ifindex);
 *
 * 	Lookup routine to find a listener with the tuple {lport, laddr,
 * 	protocol} in the ipcl_bind_fanout table. For IPv6, an additional
 * 	parameter interface index is also compared.
 *
 * void ipcl_walk(func, arg)
 *
 * 	Apply 'func' to every connection available. The 'func' is called as
 *	(*func)(connp, arg). The walk is non-atomic so connections may be
 *	created and destroyed during the walk. The CONN_CONDEMNED and
 *	CONN_INCIPIENT flags ensure that connections which are newly created
 *	or being destroyed are not selected by the walker.
 *
 * Table Updates
 * -------------
 *
 * int ipcl_conn_insert(connp, protocol, src, dst, ports)
 * int ipcl_conn_insert_v6(connp, protocol, src, dst, ports, ifindex)
 *
 *	Insert 'connp' in the ipcl_conn_fanout.
 *	Arguements :
 *		connp		conn_t to be inserted
 *		protocol	connection protocol
 *		src		source address
 *		dst		destination address
 *		ports		local and remote port
 *		ifindex		interface index for IPv6 connections
 *
 *	Return value :
 *		0		if connp was inserted
 *		EADDRINUSE	if the connection with the same tuple
 *				already exists.
 *
 * int ipcl_bind_insert(connp, protocol, src, lport);
 * int ipcl_bind_insert_v6(connp, protocol, src, lport);
 *
 * 	Insert 'connp' in ipcl_bind_fanout.
 * 	Arguements :
 * 		connp		conn_t to be inserted
 * 		protocol	connection protocol
 * 		src		source address connection wants
 * 				to bind to
 * 		lport		local port connection wants to
 * 				bind to
 *
 *
 * void ipcl_hash_remove(connp);
 *
 * 	Removes the 'connp' from the connection fanout table.
 *
 * Connection Creation/Destruction
 * -------------------------------
 *
 * conn_t *ipcl_conn_create(type, sleep)
 *
 * 	Creates a new conn based on the type flag, inserts it into
 * 	globalhash table.
 *
 *	type:	This flag determines the type of conn_t which needs to be
 *		created.
 *		IPCL_TCPCONN	indicates a TCP connection
 *		IPCL_IPCONN	indicates all non-TCP connections.
 *
 * void ipcl_conn_destroy(connp)
 *
 * 	Destroys the connection state, removes it from the global
 * 	connection hash table and frees its memory.
 */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/dlpi.h>
#include <sys/stropts.h>
#include <sys/sysmacros.h>
#include <sys/strsubr.h>
#include <sys/strlog.h>
#include <sys/strsun.h>
#define	_SUN_TPI_VERSION 2
#include <sys/ddi.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>

#include <sys/systm.h>
#include <sys/param.h>
#include <sys/kmem.h>
#include <sys/isa_defs.h>
#include <inet/common.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/tcp.h>
#include <inet/tcp_trace.h>
#include <inet/ip_multi.h>
#include <inet/ip_if.h>
#include <inet/ip_ire.h>
#include <inet/ip_rts.h>
#include <inet/optcom.h>
#include <inet/ip_ndp.h>
#include <inet/udp_impl.h>
#include <inet/sctp_ip.h>

#include <sys/ethernet.h>
#include <net/if_types.h>
#include <sys/cpuvar.h>

#include <inet/mi.h>
#include <inet/ipclassifier.h>
#include <inet/ipsec_impl.h>

#ifdef DEBUG
#define	IPCL_DEBUG
#else
#undef	IPCL_DEBUG
#endif

#ifdef	IPCL_DEBUG
int	ipcl_debug_level = 0;
#define	IPCL_DEBUG_LVL(level, args)	\
	if (ipcl_debug_level  & level) { printf args; }
#else
#define	IPCL_DEBUG_LVL(level, args) {; }
#endif
connf_t	*ipcl_conn_fanout;
connf_t	*ipcl_bind_fanout;
connf_t	ipcl_proto_fanout[IPPROTO_MAX + 1];
connf_t	ipcl_proto_fanout_v6[IPPROTO_MAX + 1];
connf_t	*ipcl_udp_fanout;

/* A separate hash list for raw socket. */
connf_t *ipcl_raw_fanout;

connf_t rts_clients;

/* Old value for compatibility */
uint_t tcp_conn_hash_size = 0;

/* New value. Zero means choose automatically. */
uint_t ipcl_conn_hash_size = 0;
uint_t ipcl_conn_hash_memfactor = 8192;
uint_t ipcl_conn_hash_maxsize = 82500;

uint_t ipcl_conn_fanout_size = 0;


/* bind/udp fanout table size */
uint_t ipcl_bind_fanout_size = 512;
uint_t ipcl_udp_fanout_size = 256;

/* Raw socket fanout size.  Must be a power of 2. */
uint_t ipcl_raw_fanout_size = 256;

/*
 * Power of 2^N Primes useful for hashing for N of 0-28,
 * these primes are the nearest prime <= 2^N - 2^(N-2).
 */

#define	P2Ps() {0, 0, 0, 5, 11, 23, 47, 89, 191, 383, 761, 1531, 3067,	\
		6143, 12281, 24571, 49139, 98299, 196597, 393209,	\
		786431, 1572853, 3145721, 6291449, 12582893, 25165813,	\
		50331599, 100663291, 201326557, 0}

/*
 * wrapper structure to ensure that conn+tcpb are aligned
 * on cache lines.
 */
typedef struct itc_s {
	union {
		conn_t	itcu_conn;
		char	itcu_filler[CACHE_ALIGN(conn_s)];
	}	itc_u;
	tcp_t	itc_tcp;
} itc_t;

#define	itc_conn	itc_u.itcu_conn

struct kmem_cache  *ipcl_tcpconn_cache;
struct kmem_cache  *ipcl_tcp_cache;
struct kmem_cache  *ipcl_conn_cache;
extern struct kmem_cache  *sctp_conn_cache;
extern struct kmem_cache  *tcp_sack_info_cache;
extern struct kmem_cache  *tcp_iphc_cache;

extern void	tcp_timermp_free(tcp_t *);
extern mblk_t	*tcp_timermp_alloc(int);

static int	ipcl_tcpconn_constructor(void *, void *, int);
static void	ipcl_tcpconn_destructor(void *, void *);

static int conn_g_index;
connf_t	*ipcl_globalhash_fanout;

#ifdef	IPCL_DEBUG
#define	INET_NTOA_BUFSIZE	18

static char *
inet_ntoa_r(uint32_t in, char *b)
{
	unsigned char	*p;

	p = (unsigned char *)&in;
	(void) sprintf(b, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return (b);
}
#endif

/*
 * ipclassifier intialization routine, sets up hash tables and
 * conn caches.
 */
void
ipcl_init(void)
{
	int i;
	int sizes[] = P2Ps();

	ipcl_conn_cache = kmem_cache_create("ipcl_conn_cache",
	    sizeof (conn_t), CACHE_ALIGN_SIZE,
	    NULL, NULL, NULL, NULL, NULL, 0);

	ipcl_tcpconn_cache = kmem_cache_create("ipcl_tcpconn_cache",
	    sizeof (itc_t), CACHE_ALIGN_SIZE,
	    ipcl_tcpconn_constructor, ipcl_tcpconn_destructor,
	    NULL, NULL, NULL, 0);

	/*
	 * Calculate size of conn fanout table.
	 */
	if (ipcl_conn_hash_size != 0) {
		ipcl_conn_fanout_size = ipcl_conn_hash_size;
	} else if (tcp_conn_hash_size != 0) {
		ipcl_conn_fanout_size = tcp_conn_hash_size;
	} else {
		extern pgcnt_t freemem;

		ipcl_conn_fanout_size =
		    (freemem * PAGESIZE) / ipcl_conn_hash_memfactor;

		if (ipcl_conn_fanout_size > ipcl_conn_hash_maxsize)
			ipcl_conn_fanout_size = ipcl_conn_hash_maxsize;
	}

	for (i = 9; i < sizeof (sizes) / sizeof (*sizes) - 1; i++) {
		if (sizes[i] >= ipcl_conn_fanout_size) {
			break;
		}
	}
	if ((ipcl_conn_fanout_size = sizes[i]) == 0) {
		/* Out of range, use the 2^16 value */
		ipcl_conn_fanout_size = sizes[16];
	}
	ipcl_conn_fanout = (connf_t *)kmem_zalloc(ipcl_conn_fanout_size *
	    sizeof (*ipcl_conn_fanout), KM_SLEEP);

	for (i = 0; i < ipcl_conn_fanout_size; i++) {
		mutex_init(&ipcl_conn_fanout[i].connf_lock, NULL,
		    MUTEX_DEFAULT, NULL);
	}

	ipcl_bind_fanout = (connf_t *)kmem_zalloc(ipcl_bind_fanout_size *
	    sizeof (*ipcl_bind_fanout), KM_SLEEP);

	for (i = 0; i < ipcl_bind_fanout_size; i++) {
		mutex_init(&ipcl_bind_fanout[i].connf_lock, NULL,
		    MUTEX_DEFAULT, NULL);
	}

	for (i = 0; i < A_CNT(ipcl_proto_fanout); i++) {
		mutex_init(&ipcl_proto_fanout[i].connf_lock, NULL,
		    MUTEX_DEFAULT, NULL);
	}
	for (i = 0; i < A_CNT(ipcl_proto_fanout_v6); i++) {
		mutex_init(&ipcl_proto_fanout_v6[i].connf_lock, NULL,
		    MUTEX_DEFAULT, NULL);
	}

	mutex_init(&rts_clients.connf_lock, NULL, MUTEX_DEFAULT, NULL);

	ipcl_udp_fanout = (connf_t *)kmem_zalloc(ipcl_udp_fanout_size *
	    sizeof (*ipcl_udp_fanout), KM_SLEEP);

	for (i = 0; i < ipcl_udp_fanout_size; i++) {
		mutex_init(&ipcl_udp_fanout[i].connf_lock, NULL,
		    MUTEX_DEFAULT, NULL);
	}

	ipcl_raw_fanout = (connf_t *)kmem_zalloc(ipcl_raw_fanout_size *
	    sizeof (*ipcl_raw_fanout), KM_SLEEP);

	for (i = 0; i < ipcl_raw_fanout_size; i++) {
		mutex_init(&ipcl_raw_fanout[i].connf_lock, NULL,
		    MUTEX_DEFAULT, NULL);
	}

	ipcl_globalhash_fanout = (connf_t *)kmem_zalloc(sizeof (connf_t) *
	    CONN_G_HASH_SIZE, KM_SLEEP);

	for (i = 0; i < CONN_G_HASH_SIZE; i++) {
		mutex_init(&ipcl_globalhash_fanout[i].connf_lock, NULL,
		    MUTEX_DEFAULT, NULL);
	}
}

void
ipcl_destroy(void)
{
	int i;
	kmem_cache_destroy(ipcl_conn_cache);
	kmem_cache_destroy(ipcl_tcpconn_cache);
	for (i = 0; i < ipcl_conn_fanout_size; i++)
		mutex_destroy(&ipcl_conn_fanout[i].connf_lock);
	kmem_free(ipcl_conn_fanout, ipcl_conn_fanout_size *
	    sizeof (*ipcl_conn_fanout));
	for (i = 0; i < ipcl_bind_fanout_size; i++)
		mutex_destroy(&ipcl_bind_fanout[i].connf_lock);
	kmem_free(ipcl_bind_fanout, ipcl_bind_fanout_size *
	    sizeof (*ipcl_bind_fanout));

	for (i = 0; i < A_CNT(ipcl_proto_fanout); i++)
		mutex_destroy(&ipcl_proto_fanout[i].connf_lock);
	for (i = 0; i < A_CNT(ipcl_proto_fanout_v6); i++)
		mutex_destroy(&ipcl_proto_fanout_v6[i].connf_lock);

	for (i = 0; i < ipcl_udp_fanout_size; i++)
		mutex_destroy(&ipcl_udp_fanout[i].connf_lock);
	kmem_free(ipcl_udp_fanout, ipcl_udp_fanout_size *
	    sizeof (*ipcl_udp_fanout));

	for (i = 0; i < ipcl_raw_fanout_size; i++)
		mutex_destroy(&ipcl_raw_fanout[i].connf_lock);
	kmem_free(ipcl_raw_fanout, ipcl_raw_fanout_size *
	    sizeof (*ipcl_raw_fanout));

	kmem_free(ipcl_globalhash_fanout, sizeof (connf_t) * CONN_G_HASH_SIZE);
	mutex_destroy(&rts_clients.connf_lock);
}

/*
 * conn creation routine. initialize the conn, sets the reference
 * and inserts it in the global hash table.
 */
conn_t *
ipcl_conn_create(uint32_t type, int sleep)
{
	itc_t	*itc;
	conn_t	*connp;

	switch (type) {
	case IPCL_TCPCONN:
		if ((itc = kmem_cache_alloc(ipcl_tcpconn_cache,
		    sleep)) == NULL)
			return (NULL);
		connp = &itc->itc_conn;
		connp->conn_ref = 1;
		IPCL_DEBUG_LVL(1,
		    ("ipcl_conn_create: connp = %p tcp (%p)",
		    (void *)connp, (void *)connp->conn_tcp));
		ipcl_globalhash_insert(connp);
		break;
	case IPCL_SCTPCONN:
		if ((connp = kmem_cache_alloc(sctp_conn_cache, sleep)) == NULL)
			return (NULL);
		connp->conn_flags = IPCL_SCTPCONN;
		break;
	case IPCL_IPCCONN:
		connp = kmem_cache_alloc(ipcl_conn_cache, sleep);
		if (connp == NULL)
			return (NULL);
		bzero(connp, sizeof (conn_t));
		mutex_init(&connp->conn_lock, NULL, MUTEX_DEFAULT, NULL);
		cv_init(&connp->conn_cv, NULL, CV_DEFAULT, NULL);
		connp->conn_flags = IPCL_IPCCONN;
		connp->conn_ref = 1;
		IPCL_DEBUG_LVL(1,
		    ("ipcl_conn_create: connp = %p\n", (void *)connp));
		ipcl_globalhash_insert(connp);
		break;
	default:
		connp = NULL;
		ASSERT(0);
	}

	return (connp);
}

void
ipcl_conn_destroy(conn_t *connp)
{
	mblk_t	*mp;

	ASSERT(!MUTEX_HELD(&connp->conn_lock));
	ASSERT(connp->conn_ref == 0);
	ASSERT(connp->conn_ire_cache == NULL);

	ipcl_globalhash_remove(connp);

	cv_destroy(&connp->conn_cv);
	if (connp->conn_flags & IPCL_TCPCONN) {
		tcp_t	*tcp = connp->conn_tcp;

		mutex_destroy(&connp->conn_lock);
		ASSERT(connp->conn_tcp != NULL);
		tcp_free(tcp);
		mp = tcp->tcp_timercache;

		if (tcp->tcp_sack_info != NULL) {
			bzero(tcp->tcp_sack_info, sizeof (tcp_sack_info_t));
			kmem_cache_free(tcp_sack_info_cache,
			    tcp->tcp_sack_info);
		}
		if (tcp->tcp_iphc != NULL) {
			if (tcp->tcp_hdr_grown) {
				kmem_free(tcp->tcp_iphc, tcp->tcp_iphc_len);
			} else {
				bzero(tcp->tcp_iphc, tcp->tcp_iphc_len);
				kmem_cache_free(tcp_iphc_cache, tcp->tcp_iphc);
			}
			tcp->tcp_iphc_len = 0;
		}
		ASSERT(tcp->tcp_iphc_len == 0);

		if (connp->conn_latch != NULL)
			IPLATCH_REFRELE(connp->conn_latch);
		if (connp->conn_policy != NULL)
			IPPH_REFRELE(connp->conn_policy);
		bzero(connp, sizeof (itc_t));

		tcp->tcp_timercache = mp;
		connp->conn_tcp = tcp;
		connp->conn_flags = IPCL_TCPCONN;
		connp->conn_ulp = IPPROTO_TCP;
		tcp->tcp_connp = connp;
		kmem_cache_free(ipcl_tcpconn_cache, connp);
	} else if (connp->conn_flags & IPCL_SCTPCONN) {
		sctp_free(connp);
	} else {
		ASSERT(connp->conn_udp == NULL);
		mutex_destroy(&connp->conn_lock);
		kmem_cache_free(ipcl_conn_cache, connp);
	}
}

/*
 * Running in cluster mode - deregister listener information
 */

static void
ipcl_conn_unlisten(conn_t *connp)
{
	ASSERT((connp->conn_flags & IPCL_CL_LISTENER) != 0);
	ASSERT(connp->conn_lport != 0);

	if (cl_inet_unlisten != NULL) {
		sa_family_t	addr_family;
		uint8_t		*laddrp;

		if (connp->conn_pkt_isv6) {
			addr_family = AF_INET6;
			laddrp = (uint8_t *)&connp->conn_bound_source_v6;
		} else {
			addr_family = AF_INET;
			laddrp = (uint8_t *)&connp->conn_bound_source;
		}
		(*cl_inet_unlisten)(IPPROTO_TCP, addr_family, laddrp,
		    connp->conn_lport);
	}
	connp->conn_flags &= ~IPCL_CL_LISTENER;
}

/*
 * We set the IPCL_REMOVED flag (instead of clearing the flag indicating
 * which table the conn belonged to). So for debugging we can see which hash
 * table this connection was in.
 */
#define	IPCL_HASH_REMOVE(connp)	{					\
	connf_t	*connfp = (connp)->conn_fanout;				\
	ASSERT(!MUTEX_HELD(&((connp)->conn_lock)));			\
	if (connfp != NULL) {						\
		IPCL_DEBUG_LVL(4, ("IPCL_HASH_REMOVE: connp %p",	\
		    (void *)(connp)));					\
		mutex_enter(&connfp->connf_lock);			\
		if ((connp)->conn_next != NULL)				\
			(connp)->conn_next->conn_prev =			\
			    (connp)->conn_prev;				\
		if ((connp)->conn_prev != NULL)				\
			(connp)->conn_prev->conn_next =			\
			    (connp)->conn_next;				\
		else							\
			connfp->connf_head = (connp)->conn_next;	\
		(connp)->conn_fanout = NULL;				\
		(connp)->conn_next = NULL;				\
		(connp)->conn_prev = NULL;				\
		(connp)->conn_flags |= IPCL_REMOVED;			\
		if (((connp)->conn_flags & IPCL_CL_LISTENER) != 0)	\
			ipcl_conn_unlisten((connp));			\
		CONN_DEC_REF((connp));					\
		mutex_exit(&connfp->connf_lock);			\
	}								\
}

void
ipcl_hash_remove(conn_t *connp)
{
	IPCL_HASH_REMOVE(connp);
}

/*
 * The whole purpose of this function is allow removal of
 * a conn_t from the connected hash for timewait reclaim.
 * This is essentially a TW reclaim fastpath where timewait
 * collector checks under fanout lock (so no one else can
 * get access to the conn_t) that refcnt is 2 i.e. one for
 * TCP and one for the classifier hash list. If ref count
 * is indeed 2, we can just remove the conn under lock and
 * avoid cleaning up the conn under squeue. This gives us
 * improved performance.
 */
void
ipcl_hash_remove_locked(conn_t *connp, connf_t	*connfp)
{
	ASSERT(MUTEX_HELD(&connfp->connf_lock));
	ASSERT(MUTEX_HELD(&connp->conn_lock));
	ASSERT((connp->conn_flags & IPCL_CL_LISTENER) == 0);

	if ((connp)->conn_next != NULL) {
		(connp)->conn_next->conn_prev =
			(connp)->conn_prev;
	}
	if ((connp)->conn_prev != NULL) {
		(connp)->conn_prev->conn_next =
			(connp)->conn_next;
	} else {
		connfp->connf_head = (connp)->conn_next;
	}
	(connp)->conn_fanout = NULL;
	(connp)->conn_next = NULL;
	(connp)->conn_prev = NULL;
	(connp)->conn_flags |= IPCL_REMOVED;
	ASSERT((connp)->conn_ref == 2);
	(connp)->conn_ref--;
}

#define	IPCL_HASH_INSERT_CONNECTED_LOCKED(connfp, connp) {		\
	ASSERT((connp)->conn_fanout == NULL);				\
	ASSERT((connp)->conn_next == NULL);				\
	ASSERT((connp)->conn_prev == NULL);				\
	if ((connfp)->connf_head != NULL) {				\
		(connfp)->connf_head->conn_prev = (connp);		\
		(connp)->conn_next = (connfp)->connf_head;		\
	}								\
	(connp)->conn_fanout = (connfp);				\
	(connfp)->connf_head = (connp);					\
	(connp)->conn_flags = ((connp)->conn_flags & ~IPCL_REMOVED) |	\
	    IPCL_CONNECTED;						\
	CONN_INC_REF(connp);						\
}

#define	IPCL_HASH_INSERT_CONNECTED(connfp, connp) {			\
	IPCL_DEBUG_LVL(8, ("IPCL_HASH_INSERT_CONNECTED: connfp %p "	\
	    "connp %p", (void *)(connfp), (void *)(connp)));		\
	IPCL_HASH_REMOVE((connp));					\
	mutex_enter(&(connfp)->connf_lock);				\
	IPCL_HASH_INSERT_CONNECTED_LOCKED(connfp, connp);		\
	mutex_exit(&(connfp)->connf_lock);				\
}

#define	IPCL_HASH_INSERT_BOUND(connfp, connp) {				\
	conn_t *pconnp = NULL, *nconnp;					\
	IPCL_DEBUG_LVL(32, ("IPCL_HASH_INSERT_BOUND: connfp %p "	\
	    "connp %p", (void *)connfp, (void *)(connp)));		\
	IPCL_HASH_REMOVE((connp));					\
	mutex_enter(&(connfp)->connf_lock);				\
	nconnp = (connfp)->connf_head;					\
	while (nconnp != NULL &&					\
	    !_IPCL_V4_MATCH_ANY(nconnp->conn_srcv6)) {			\
		pconnp = nconnp;					\
		nconnp = nconnp->conn_next;				\
	}								\
	if (pconnp != NULL) {						\
		pconnp->conn_next = (connp);				\
		(connp)->conn_prev = pconnp;				\
	} else {							\
		(connfp)->connf_head = (connp);				\
	}								\
	if (nconnp != NULL) {						\
		(connp)->conn_next = nconnp;				\
		nconnp->conn_prev = (connp);				\
	}								\
	(connp)->conn_fanout = (connfp);				\
	(connp)->conn_flags = ((connp)->conn_flags & ~IPCL_REMOVED) |	\
	    IPCL_BOUND;							\
	CONN_INC_REF(connp);						\
	mutex_exit(&(connfp)->connf_lock);				\
}

#define	IPCL_HASH_INSERT_WILDCARD(connfp, connp) {			\
	conn_t **list, *prev, *next;					\
	boolean_t isv4mapped =						\
	    IN6_IS_ADDR_V4MAPPED(&(connp)->conn_srcv6);			\
	IPCL_DEBUG_LVL(32, ("IPCL_HASH_INSERT_WILDCARD: connfp %p "	\
	    "connp %p", (void *)(connfp), (void *)(connp)));		\
	IPCL_HASH_REMOVE((connp));					\
	mutex_enter(&(connfp)->connf_lock);				\
	list = &(connfp)->connf_head;					\
	prev = NULL;							\
	while ((next = *list) != NULL) {				\
		if (isv4mapped &&					\
		    IN6_IS_ADDR_UNSPECIFIED(&next->conn_srcv6) &&	\
		    connp->conn_zoneid == next->conn_zoneid) {		\
			(connp)->conn_next = next;			\
			if (prev != NULL)				\
				prev = next->conn_prev;			\
			next->conn_prev = (connp);			\
			break;						\
		}							\
		list = &next->conn_next;				\
		prev = next;						\
	}								\
	(connp)->conn_prev = prev;					\
	*list = (connp);						\
	(connp)->conn_fanout = (connfp);				\
	(connp)->conn_flags = ((connp)->conn_flags & ~IPCL_REMOVED) |	\
	    IPCL_BOUND;							\
	CONN_INC_REF((connp));						\
	mutex_exit(&(connfp)->connf_lock);				\
}

void
ipcl_hash_insert_wildcard(connf_t *connfp, conn_t *connp)
{
	IPCL_HASH_INSERT_WILDCARD(connfp, connp);
}

void
ipcl_proto_insert(conn_t *connp, uint8_t protocol)
{
	connf_t	*connfp;

	ASSERT(connp != NULL);

	connp->conn_ulp = protocol;

	/* Insert it in the protocol hash */
	connfp = &ipcl_proto_fanout[protocol];
	IPCL_HASH_INSERT_WILDCARD(connfp, connp);
}

void
ipcl_proto_insert_v6(conn_t *connp, uint8_t protocol)
{
	connf_t	*connfp;

	ASSERT(connp != NULL);

	connp->conn_ulp = protocol;

	/* Insert it in the Bind Hash */
	connfp = &ipcl_proto_fanout_v6[protocol];
	IPCL_HASH_INSERT_WILDCARD(connfp, connp);
}

/*
 * This function is used only for inserting SCTP raw socket now.
 * This may change later.
 *
 * Note that only one raw socket can be bound to a port.  The param
 * lport is in network byte order.
 */
static int
ipcl_sctp_hash_insert(conn_t *connp, in_port_t lport)
{
	connf_t	*connfp;
	conn_t	*oconnp;

	connfp = &ipcl_raw_fanout[IPCL_RAW_HASH(ntohs(lport))];

	/* Check for existing raw socket already bound to the port. */
	mutex_enter(&connfp->connf_lock);
	for (oconnp = connfp->connf_head; oconnp != NULL;
	    oconnp = oconnp->conn_next) {
		if (oconnp->conn_lport == lport &&
		    oconnp->conn_zoneid == connp->conn_zoneid &&
		    oconnp->conn_af_isv6 == connp->conn_af_isv6 &&
		    ((IN6_IS_ADDR_UNSPECIFIED(&connp->conn_srcv6) ||
		    IN6_IS_ADDR_UNSPECIFIED(&oconnp->conn_srcv6) ||
		    IN6_IS_ADDR_V4MAPPED_ANY(&connp->conn_srcv6) ||
		    IN6_IS_ADDR_V4MAPPED_ANY(&oconnp->conn_srcv6)) ||
		    IN6_ARE_ADDR_EQUAL(&oconnp->conn_srcv6,
		    &connp->conn_srcv6))) {
			break;
		}
	}
	mutex_exit(&connfp->connf_lock);
	if (oconnp != NULL)
		return (EADDRNOTAVAIL);

	if (IN6_IS_ADDR_UNSPECIFIED(&connp->conn_remv6) ||
	    IN6_IS_ADDR_V4MAPPED_ANY(&connp->conn_remv6)) {
		if (IN6_IS_ADDR_UNSPECIFIED(&connp->conn_srcv6) ||
		    IN6_IS_ADDR_V4MAPPED_ANY(&connp->conn_srcv6)) {
			IPCL_HASH_INSERT_WILDCARD(connfp, connp);
		} else {
			IPCL_HASH_INSERT_BOUND(connfp, connp);
		}
	} else {
		IPCL_HASH_INSERT_CONNECTED(connfp, connp);
	}
	return (0);
}

/*
 * (v4, v6) bind hash insertion routines
 */
int
ipcl_bind_insert(conn_t *connp, uint8_t protocol, ipaddr_t src, uint16_t lport)
{
	connf_t	*connfp;
#ifdef	IPCL_DEBUG
	char	buf[INET_NTOA_BUFSIZE];
#endif
	int	ret = 0;

	ASSERT(connp);

	IPCL_DEBUG_LVL(64, ("ipcl_bind_insert: connp %p, src = %s, "
	    "port = %d\n", (void *)connp, inet_ntoa_r(src, buf), lport));

	connp->conn_ulp = protocol;
	IN6_IPADDR_TO_V4MAPPED(src, &connp->conn_srcv6);
	connp->conn_lport = lport;

	switch (protocol) {
	case IPPROTO_UDP:
	default:
		if (protocol == IPPROTO_UDP) {
			IPCL_DEBUG_LVL(64,
			    ("ipcl_bind_insert: connp %p - udp\n",
			    (void *)connp));
			connfp = &ipcl_udp_fanout[IPCL_UDP_HASH(lport)];
		} else {
			IPCL_DEBUG_LVL(64,
			    ("ipcl_bind_insert: connp %p - protocol\n",
			    (void *)connp));
			connfp = &ipcl_proto_fanout[protocol];
		}

		if (connp->conn_rem != INADDR_ANY) {
			IPCL_HASH_INSERT_CONNECTED(connfp, connp);
		} else if (connp->conn_src != INADDR_ANY) {
			IPCL_HASH_INSERT_BOUND(connfp, connp);
		} else {
			IPCL_HASH_INSERT_WILDCARD(connfp, connp);
		}
		break;

	case IPPROTO_TCP:

		/* Insert it in the Bind Hash */
		connfp = &ipcl_bind_fanout[IPCL_BIND_HASH(lport)];
		if (connp->conn_src != INADDR_ANY) {
			IPCL_HASH_INSERT_BOUND(connfp, connp);
		} else {
			IPCL_HASH_INSERT_WILDCARD(connfp, connp);
		}
		if (cl_inet_listen != NULL) {
			ASSERT(!connp->conn_pkt_isv6);
			connp->conn_flags |= IPCL_CL_LISTENER;
			(*cl_inet_listen)(IPPROTO_TCP, AF_INET,
			    (uint8_t *)&connp->conn_bound_source, lport);
		}
		break;

	case IPPROTO_SCTP:
		ret = ipcl_sctp_hash_insert(connp, lport);
		break;
	}

	return (ret);
}

int
ipcl_bind_insert_v6(conn_t *connp, uint8_t protocol, const in6_addr_t *src,
    uint16_t lport)
{
	connf_t	*connfp;
	int	ret = 0;

	ASSERT(connp);

	connp->conn_ulp = protocol;
	connp->conn_srcv6 = *src;
	connp->conn_lport = lport;

	switch (protocol) {
	case IPPROTO_UDP:
	default:
		if (protocol == IPPROTO_UDP) {
			IPCL_DEBUG_LVL(128,
			    ("ipcl_bind_insert_v6: connp %p - udp\n",
			    (void *)connp));
			connfp = &ipcl_udp_fanout[IPCL_UDP_HASH(lport)];
		} else {
			IPCL_DEBUG_LVL(128,
			    ("ipcl_bind_insert_v6: connp %p - protocol\n",
			    (void *)connp));
			connfp = &ipcl_proto_fanout_v6[protocol];
		}

		if (!IN6_IS_ADDR_UNSPECIFIED(&connp->conn_remv6)) {
			IPCL_HASH_INSERT_CONNECTED(connfp, connp);
		} else if (!IN6_IS_ADDR_UNSPECIFIED(&connp->conn_srcv6)) {
			IPCL_HASH_INSERT_BOUND(connfp, connp);
		} else {
			IPCL_HASH_INSERT_WILDCARD(connfp, connp);
		}
		break;

	case IPPROTO_TCP:
		/* XXX - Need a separate table for IN6_IS_ADDR_UNSPECIFIED? */

		/* Insert it in the Bind Hash */
		connfp = &ipcl_bind_fanout[IPCL_BIND_HASH(lport)];
		if (!IN6_IS_ADDR_UNSPECIFIED(&connp->conn_srcv6)) {
			IPCL_HASH_INSERT_BOUND(connfp, connp);
		} else {
			IPCL_HASH_INSERT_WILDCARD(connfp, connp);
		}
		if (cl_inet_listen != NULL) {
			sa_family_t	addr_family;
			uint8_t		*laddrp;

			if (connp->conn_pkt_isv6) {
				addr_family = AF_INET6;
				laddrp =
				    (uint8_t *)&connp->conn_bound_source_v6;
			} else {
				addr_family = AF_INET;
				laddrp = (uint8_t *)&connp->conn_bound_source;
			}
			connp->conn_flags |= IPCL_CL_LISTENER;
			(*cl_inet_listen)(IPPROTO_TCP, addr_family, laddrp,
			    lport);
		}
		break;

	case IPPROTO_SCTP:
		ret = ipcl_sctp_hash_insert(connp, lport);
		break;
	}

	return (ret);
}

/*
 * ipcl_conn_hash insertion routines.
 */
int
ipcl_conn_insert(conn_t *connp, uint8_t protocol, ipaddr_t src,
    ipaddr_t rem, uint32_t ports)
{
	connf_t		*connfp;
	uint16_t	*up;
	conn_t		*tconnp;
#ifdef	IPCL_DEBUG
	char	sbuf[INET_NTOA_BUFSIZE], rbuf[INET_NTOA_BUFSIZE];
#endif
	in_port_t	lport;
	int		ret = 0;

	IPCL_DEBUG_LVL(256, ("ipcl_conn_insert: connp %p, src = %s, "
	    "dst = %s, ports = %x, protocol = %x", (void *)connp,
	    inet_ntoa_r(src, sbuf), inet_ntoa_r(rem, rbuf),
	    ports, protocol));

	switch (protocol) {
	case IPPROTO_TCP:
		if (!(connp->conn_flags & IPCL_EAGER)) {
			/*
			 * for a eager connection, i.e connections which
			 * have just been created, the initialization is
			 * already done in ip at conn_creation time, so
			 * we can skip the checks here.
			 */
			IPCL_CONN_INIT(connp, protocol, src, rem, ports);
		}
		connfp = &ipcl_conn_fanout[IPCL_CONN_HASH(connp->conn_rem,
		    connp->conn_ports)];
		mutex_enter(&connfp->connf_lock);
		for (tconnp = connfp->connf_head; tconnp != NULL;
		    tconnp = tconnp->conn_next) {
			if (IPCL_CONN_MATCH(tconnp, connp->conn_ulp,
			    connp->conn_rem, connp->conn_src,
			    connp->conn_ports)) {

				/* Already have a conn. bail out */
				mutex_exit(&connfp->connf_lock);
				return (EADDRINUSE);
			}
		}
		if (connp->conn_fanout != NULL) {
			/*
			 * Probably a XTI/TLI application trying to do a
			 * rebind. Let it happen.
			 */
			mutex_exit(&connfp->connf_lock);
			IPCL_HASH_REMOVE(connp);
			mutex_enter(&connfp->connf_lock);
		}
		IPCL_HASH_INSERT_CONNECTED_LOCKED(connfp, connp);
		mutex_exit(&connfp->connf_lock);
		break;

	case IPPROTO_SCTP:
		/*
		 * The raw socket may have already been bound, remove it
		 * from the hash first.
		 */
		IPCL_HASH_REMOVE(connp);
		lport = htons((uint16_t)(ntohl(ports) & 0xFFFF));
		ret = ipcl_sctp_hash_insert(connp, lport);
		break;

	case IPPROTO_UDP:
	default:
		up = (uint16_t *)&ports;
		IPCL_CONN_INIT(connp, protocol, src, rem, ports);
		if (protocol == IPPROTO_UDP) {
			connfp = &ipcl_udp_fanout[IPCL_UDP_HASH(up[1])];
		} else {
			connfp = &ipcl_proto_fanout[protocol];
		}

		if (connp->conn_rem != INADDR_ANY) {
			IPCL_HASH_INSERT_CONNECTED(connfp, connp);
		} else if (connp->conn_src != INADDR_ANY) {
			IPCL_HASH_INSERT_BOUND(connfp, connp);
		} else {
			IPCL_HASH_INSERT_WILDCARD(connfp, connp);
		}
		break;
	}

	return (ret);
}

int
ipcl_conn_insert_v6(conn_t *connp, uint8_t protocol, const in6_addr_t *src,
    const in6_addr_t *rem, uint32_t ports, uint_t ifindex)
{
	connf_t		*connfp;
	uint16_t	*up;
	conn_t		*tconnp;
	in_port_t	lport;
	int		ret = 0;

	switch (protocol) {
	case IPPROTO_TCP:
		/* Just need to insert a conn struct */
		if (!(connp->conn_flags & IPCL_EAGER)) {
			IPCL_CONN_INIT_V6(connp, protocol, *src, *rem, ports);
		}
		connfp = &ipcl_conn_fanout[IPCL_CONN_HASH_V6(connp->conn_remv6,
		    connp->conn_ports)];
		mutex_enter(&connfp->connf_lock);
		for (tconnp = connfp->connf_head; tconnp != NULL;
		    tconnp = tconnp->conn_next) {
			if (IPCL_CONN_MATCH_V6(tconnp, connp->conn_ulp,
			    connp->conn_remv6, connp->conn_srcv6,
			    connp->conn_ports) &&
			    (tconnp->conn_tcp->tcp_bound_if == 0 ||
			    tconnp->conn_tcp->tcp_bound_if == ifindex)) {
				/* Already have a conn. bail out */
				mutex_exit(&connfp->connf_lock);
				return (EADDRINUSE);
			}
		}
		if (connp->conn_fanout != NULL) {
			/*
			 * Probably a XTI/TLI application trying to do a
			 * rebind. Let it happen.
			 */
			mutex_exit(&connfp->connf_lock);
			IPCL_HASH_REMOVE(connp);
			mutex_enter(&connfp->connf_lock);
		}
		IPCL_HASH_INSERT_CONNECTED_LOCKED(connfp, connp);
		mutex_exit(&connfp->connf_lock);
		break;

	case IPPROTO_SCTP:
		IPCL_HASH_REMOVE(connp);
		lport = htons((uint16_t)(ntohl(ports) & 0xFFFF));
		ret = ipcl_sctp_hash_insert(connp, lport);
		break;

	case IPPROTO_UDP:
	default:
		up = (uint16_t *)&ports;
		IPCL_CONN_INIT_V6(connp, protocol, *src, *rem, ports);
		if (protocol == IPPROTO_UDP) {
			connfp = &ipcl_udp_fanout[IPCL_UDP_HASH(up[1])];
		} else {
			connfp = &ipcl_proto_fanout_v6[protocol];
		}

		if (!IN6_IS_ADDR_UNSPECIFIED(&connp->conn_remv6)) {
			IPCL_HASH_INSERT_CONNECTED(connfp, connp);
		} else if (!IN6_IS_ADDR_UNSPECIFIED(&connp->conn_srcv6)) {
			IPCL_HASH_INSERT_BOUND(connfp, connp);
		} else {
			IPCL_HASH_INSERT_WILDCARD(connfp, connp);
		}
		break;
	}

	return (ret);
}

/*
 * v4 packet classifying function. looks up the fanout table to
 * find the conn, the packet belongs to. returns the conn with
 * the reference held, null otherwise.
 */
conn_t *
ipcl_classify_v4(mblk_t *mp, uint8_t protocol, uint_t hdr_len, zoneid_t zoneid)
{
	ipha_t	*ipha;
	connf_t	*connfp, *bind_connfp;
	uint16_t lport;
	uint16_t fport;
	uint32_t ports;
	conn_t	*connp;
	uint16_t  *up;

	ipha = (ipha_t *)mp->b_rptr;
	up = (uint16_t *)((uchar_t *)ipha + hdr_len + TCP_PORTS_OFFSET);

	switch (protocol) {
	case IPPROTO_TCP:
		ports = *(uint32_t *)up;
		connfp =
		    &ipcl_conn_fanout[IPCL_CONN_HASH(ipha->ipha_src, ports)];
		mutex_enter(&connfp->connf_lock);
		for (connp = connfp->connf_head; connp != NULL;
		    connp = connp->conn_next) {
			if (IPCL_CONN_MATCH(connp, protocol,
			    ipha->ipha_src, ipha->ipha_dst, ports))
				break;
		}

		if (connp != NULL) {
			CONN_INC_REF(connp);
			mutex_exit(&connfp->connf_lock);
			return (connp);
		}

		mutex_exit(&connfp->connf_lock);

		lport = up[1];
		bind_connfp = &ipcl_bind_fanout[IPCL_BIND_HASH(lport)];
		mutex_enter(&bind_connfp->connf_lock);
		for (connp = bind_connfp->connf_head; connp != NULL;
		    connp = connp->conn_next) {
			if (IPCL_BIND_MATCH(connp, protocol,
			    ipha->ipha_dst, lport) &&
			    connp->conn_zoneid == zoneid)
				break;
		}

		if (connp != NULL) {
			/* Have a listner at least */
			CONN_INC_REF(connp);
			mutex_exit(&bind_connfp->connf_lock);
			return (connp);
		}

		mutex_exit(&bind_connfp->connf_lock);

		IPCL_DEBUG_LVL(512,
		    ("ipcl_classify: couldn't classify mp = %p\n",
		    (void *)mp));
		break;

	case IPPROTO_UDP:
		lport = up[1];
		fport = up[0];
		IPCL_DEBUG_LVL(512, ("ipcl_udp_classify %x %x", lport, fport));
		connfp = &ipcl_udp_fanout[IPCL_UDP_HASH(lport)];
		mutex_enter(&connfp->connf_lock);
		for (connp = connfp->connf_head; connp != NULL;
		    connp = connp->conn_next) {
			if (IPCL_UDP_MATCH(connp, lport, ipha->ipha_dst,
			    fport, ipha->ipha_src) &&
			    connp->conn_zoneid == zoneid)
				break;
		}

		if (connp != NULL) {
			CONN_INC_REF(connp);
			mutex_exit(&connfp->connf_lock);
			return (connp);
		}

		/*
		 * We shouldn't come here for multicast/broadcast packets
		 */
		mutex_exit(&connfp->connf_lock);
		IPCL_DEBUG_LVL(512,
		    ("ipcl_classify: cant find udp conn_t for ports : %x %x",
		    lport, fport));
		break;
	}

	return (NULL);
}

conn_t *
ipcl_classify_v6(mblk_t *mp, uint8_t protocol, uint_t hdr_len, zoneid_t zoneid)
{
	ip6_t		*ip6h;
	connf_t		*connfp, *bind_connfp;
	uint16_t	lport;
	uint16_t	fport;
	tcph_t		*tcph;
	uint32_t	ports;
	conn_t		*connp;
	uint16_t	*up;


	ip6h = (ip6_t *)mp->b_rptr;

	switch (protocol) {
	case IPPROTO_TCP:
		tcph = (tcph_t *)&mp->b_rptr[hdr_len];
		up = (uint16_t *)tcph->th_lport;
		ports = *(uint32_t *)up;

		connfp =
		    &ipcl_conn_fanout[IPCL_CONN_HASH_V6(ip6h->ip6_src, ports)];
		mutex_enter(&connfp->connf_lock);
		for (connp = connfp->connf_head; connp != NULL;
		    connp = connp->conn_next) {
			if (IPCL_CONN_MATCH_V6(connp, protocol,
			    ip6h->ip6_src, ip6h->ip6_dst, ports))
				break;
		}

		if (connp != NULL) {
			CONN_INC_REF(connp);
			mutex_exit(&connfp->connf_lock);
			return (connp);
		}

		mutex_exit(&connfp->connf_lock);

		lport = up[1];
		bind_connfp = &ipcl_bind_fanout[IPCL_BIND_HASH(lport)];
		mutex_enter(&bind_connfp->connf_lock);
		for (connp = bind_connfp->connf_head; connp != NULL;
		    connp = connp->conn_next) {
			if (IPCL_BIND_MATCH_V6(connp, protocol,
			    ip6h->ip6_dst, lport) &&
			    connp->conn_zoneid == zoneid)
				break;
		}

		if (connp != NULL) {
			/* Have a listner at least */
			CONN_INC_REF(connp);
			mutex_exit(&bind_connfp->connf_lock);
			IPCL_DEBUG_LVL(512,
			    ("ipcl_classify_v6: found listner "
			    "connp = %p\n", (void *)connp));

			return (connp);
		}

		mutex_exit(&bind_connfp->connf_lock);

		IPCL_DEBUG_LVL(512,
		    ("ipcl_classify_v6: couldn't classify mp = %p\n",
		    (void *)mp));
		break;

	case IPPROTO_UDP:
		up = (uint16_t *)&mp->b_rptr[hdr_len];
		lport = up[1];
		fport = up[0];
		IPCL_DEBUG_LVL(512, ("ipcl_udp_classify_v6 %x %x", lport,
		    fport));
		connfp = &ipcl_udp_fanout[IPCL_UDP_HASH(lport)];
		mutex_enter(&connfp->connf_lock);
		for (connp = connfp->connf_head; connp != NULL;
		    connp = connp->conn_next) {
			if (IPCL_UDP_MATCH_V6(connp, lport, ip6h->ip6_dst,
			    fport, ip6h->ip6_src) &&
			    connp->conn_zoneid == zoneid)
				break;
		}

		if (connp != NULL) {
			CONN_INC_REF(connp);
			mutex_exit(&connfp->connf_lock);
			return (connp);
		}

		/*
		 * We shouldn't come here for multicast/broadcast packets
		 */
		mutex_exit(&connfp->connf_lock);
		IPCL_DEBUG_LVL(512,
		    ("ipcl_classify_v6: cant find udp conn_t for ports : %x %x",
		    lport, fport));
		break;
	}


	return (NULL);
}

/*
 * wrapper around ipcl_classify_(v4,v6) routines.
 */
conn_t *
ipcl_classify(mblk_t *mp, zoneid_t zoneid)
{
	uint16_t	hdr_len;
	ipha_t		*ipha;
	uint8_t		*nexthdrp;

	if (MBLKL(mp) < sizeof (ipha_t))
		return (NULL);

	switch (IPH_HDR_VERSION(mp->b_rptr)) {
	case IPV4_VERSION:
		ipha = (ipha_t *)mp->b_rptr;
		hdr_len = IPH_HDR_LENGTH(ipha);
		return (ipcl_classify_v4(mp, ipha->ipha_protocol, hdr_len,
		    zoneid));
	case IPV6_VERSION:
		if (!ip_hdr_length_nexthdr_v6(mp, (ip6_t *)mp->b_rptr,
		    &hdr_len, &nexthdrp))
			return (NULL);

		return (ipcl_classify_v6(mp, *nexthdrp, hdr_len, zoneid));
	}

	return (NULL);
}

conn_t *
ipcl_classify_raw(uint8_t protocol, zoneid_t zoneid, uint32_t ports,
    ipha_t *hdr)
{
	struct connf_s	*connfp;
	conn_t		*connp;
	in_port_t	lport;
	int		af;

	lport = ((uint16_t *)&ports)[1];
	af = IPH_HDR_VERSION(hdr);
	connfp = &ipcl_raw_fanout[IPCL_RAW_HASH(ntohs(lport))];

	mutex_enter(&connfp->connf_lock);
	for (connp = connfp->connf_head; connp != NULL;
	    connp = connp->conn_next) {
		/* We don't allow v4 fallback for v6 raw socket. */
		if ((af == (connp->conn_af_isv6 ? IPV4_VERSION :
		    IPV6_VERSION)) || (connp->conn_zoneid != zoneid)) {
			continue;
		}
		if (connp->conn_fully_bound) {
			if (af == IPV4_VERSION) {
				if (IPCL_CONN_MATCH(connp, protocol,
				    hdr->ipha_src, hdr->ipha_dst, ports)) {
					break;
				}
			} else {
				if (IPCL_CONN_MATCH_V6(connp, protocol,
				    ((ip6_t *)hdr)->ip6_src,
				    ((ip6_t *)hdr)->ip6_dst, ports)) {
					break;
				}
			}
		} else {
			if (af == IPV4_VERSION) {
				if (IPCL_BIND_MATCH(connp, protocol,
				    hdr->ipha_dst, lport)) {
					break;
				}
			} else {
				if (IPCL_BIND_MATCH_V6(connp, protocol,
				    ((ip6_t *)hdr)->ip6_dst, lport)) {
					break;
				}
			}
		}
	}

	if (connp != NULL)
		goto found;
	mutex_exit(&connfp->connf_lock);

	/* Try to look for a wildcard match. */
	connfp = &ipcl_raw_fanout[IPCL_RAW_HASH(0)];
	mutex_enter(&connfp->connf_lock);
	for (connp = connfp->connf_head; connp != NULL;
	    connp = connp->conn_next) {
		/* We don't allow v4 fallback for v6 raw socket. */
		if ((af == (connp->conn_af_isv6 ? IPV4_VERSION :
		    IPV6_VERSION)) || (connp->conn_zoneid != zoneid)) {
			continue;
		}
		if (af == IPV4_VERSION) {
			if (IPCL_RAW_MATCH(connp, protocol, hdr->ipha_dst))
				break;
		} else {
			if (IPCL_RAW_MATCH_V6(connp, protocol,
			    ((ip6_t *)hdr)->ip6_dst)) {
				break;
			}
		}
	}

	if (connp != NULL)
		goto found;

	mutex_exit(&connfp->connf_lock);
	return (NULL);

found:
	ASSERT(connp != NULL);
	CONN_INC_REF(connp);
	mutex_exit(&connfp->connf_lock);
	return (connp);
}

/* ARGSUSED */
static int
ipcl_tcpconn_constructor(void *buf, void *cdrarg, int kmflags)
{
	itc_t	*itc = (itc_t *)buf;
	conn_t 	*connp = &itc->itc_conn;
	tcp_t	*tcp = &itc->itc_tcp;
	bzero(itc, sizeof (itc_t));
	tcp->tcp_timercache = tcp_timermp_alloc(KM_NOSLEEP);
	connp->conn_tcp = tcp;
	connp->conn_flags = IPCL_TCPCONN;
	connp->conn_ulp = IPPROTO_TCP;
	tcp->tcp_connp = connp;
	return (0);
}

/* ARGSUSED */
static void
ipcl_tcpconn_destructor(void *buf, void *cdrarg)
{
	tcp_timermp_free(((conn_t *)buf)->conn_tcp);
}

/*
 * All conns are inserted in a global multi-list for the benefit of
 * walkers. The walk is guaranteed to walk all open conns at the time
 * of the start of the walk exactly once. This property is needed to
 * achieve some cleanups during unplumb of interfaces. This is achieved
 * as follows.
 *
 * ipcl_conn_create and ipcl_conn_destroy are the only functions that
 * call the insert and delete functions below at creation and deletion
 * time respectively. The conn never moves or changes its position in this
 * multi-list during its lifetime. CONN_CONDEMNED ensures that the refcnt
 * won't increase due to walkers, once the conn deletion has started. Note
 * that we can't remove the conn from the global list and then wait for
 * the refcnt to drop to zero, since walkers would then see a truncated
 * list. CONN_INCIPIENT ensures that walkers don't start looking at
 * conns until ip_open is ready to make them globally visible.
 * The global round robin multi-list locks are held only to get the
 * next member/insertion/deletion and contention should be negligible
 * if the multi-list is much greater than the number of cpus.
 */
void
ipcl_globalhash_insert(conn_t *connp)
{
	int	index;

	/*
	 * No need for atomic here. Approximate even distribution
	 * in the global lists is sufficient.
	 */
	conn_g_index++;
	index = conn_g_index & (CONN_G_HASH_SIZE - 1);

	connp->conn_g_prev = NULL;
	/*
	 * Mark as INCIPIENT, so that walkers will ignore this
	 * for now, till ip_open is ready to make it visible globally.
	 */
	connp->conn_state_flags |= CONN_INCIPIENT;

	/* Insert at the head of the list */
	mutex_enter(&ipcl_globalhash_fanout[index].connf_lock);
	connp->conn_g_next = ipcl_globalhash_fanout[index].connf_head;
	if (connp->conn_g_next != NULL)
		connp->conn_g_next->conn_g_prev = connp;
	ipcl_globalhash_fanout[index].connf_head = connp;

	/* The fanout bucket this conn points to */
	connp->conn_g_fanout = &ipcl_globalhash_fanout[index];

	mutex_exit(&ipcl_globalhash_fanout[index].connf_lock);
}

void
ipcl_globalhash_remove(conn_t *connp)
{
	/*
	 * We were never inserted in the global multi list.
	 * IPCL_NONE variety is never inserted in the global multilist
	 * since it is presumed to not need any cleanup and is transient.
	 */
	if (connp->conn_g_fanout == NULL)
		return;

	mutex_enter(&connp->conn_g_fanout->connf_lock);
	if (connp->conn_g_prev != NULL)
		connp->conn_g_prev->conn_g_next = connp->conn_g_next;
	else
		connp->conn_g_fanout->connf_head = connp->conn_g_next;
	if (connp->conn_g_next != NULL)
		connp->conn_g_next->conn_g_prev = connp->conn_g_prev;
	mutex_exit(&connp->conn_g_fanout->connf_lock);

	/* Better to stumble on a null pointer than to corrupt memory */
	connp->conn_g_next = NULL;
	connp->conn_g_prev = NULL;
}

/*
 * Walk the list of all conn_t's in the system, calling the function provided
 * with the specified argument for each.
 * Applies to both IPv4 and IPv6.
 *
 * IPCs may hold pointers to ipif/ill. To guard against stale pointers
 * ipcl_walk() is called to cleanup the conn_t's, typically when an interface is
 * unplumbed or removed. New conn_t's that are created while we are walking
 * may be missed by this walk, because they are not necessarily inserted
 * at the tail of the list. They are new conn_t's and thus don't have any
 * stale pointers. The CONN_CLOSING flag ensures that no new reference
 * is created to the struct that is going away.
 */
void
ipcl_walk(pfv_t func, void *arg)
{
	int	i;
	conn_t	*connp;
	conn_t	*prev_connp;

	for (i = 0; i < CONN_G_HASH_SIZE; i++) {
		mutex_enter(&ipcl_globalhash_fanout[i].connf_lock);
		prev_connp = NULL;
		connp = ipcl_globalhash_fanout[i].connf_head;
		while (connp != NULL) {
			mutex_enter(&connp->conn_lock);
			if (connp->conn_state_flags &
			    (CONN_CONDEMNED | CONN_INCIPIENT)) {
				mutex_exit(&connp->conn_lock);
				connp = connp->conn_g_next;
				continue;
			}
			CONN_INC_REF_LOCKED(connp);
			mutex_exit(&connp->conn_lock);
			mutex_exit(&ipcl_globalhash_fanout[i].connf_lock);
			(*func)(connp, arg);
			if (prev_connp != NULL)
				CONN_DEC_REF(prev_connp);
			mutex_enter(&ipcl_globalhash_fanout[i].connf_lock);
			prev_connp = connp;
			connp = connp->conn_g_next;
		}
		mutex_exit(&ipcl_globalhash_fanout[i].connf_lock);
		if (prev_connp != NULL)
			CONN_DEC_REF(prev_connp);
	}
}

/*
 * Search for a peer TCP/IPv4 loopback conn by doing a reverse lookup on
 * the {src, dst, lport, fport} quadruplet.  Returns with conn reference
 * held; caller must call CONN_DEC_REF.  Only checks for connected entries
 * (peer tcp in at least ESTABLISHED state).
 */
conn_t *
ipcl_conn_tcp_lookup_reversed_ipv4(conn_t *connp, ipha_t *ipha, tcph_t *tcph)
{
	uint32_t ports;
	uint16_t *pports = (uint16_t *)&ports;
	connf_t	*connfp;
	conn_t	*tconnp;
	boolean_t zone_chk;

	/*
	 * If either the source of destination address is loopback, then
	 * both endpoints must be in the same Zone.  Otherwise, both of
	 * the addresses are system-wide unique (tcp is in ESTABLISHED
	 * state) and the endpoints may reside in different Zones.
	 */
	zone_chk = (ipha->ipha_src == htonl(INADDR_LOOPBACK) ||
	    ipha->ipha_dst == htonl(INADDR_LOOPBACK));

	bcopy(tcph->th_fport, &pports[0], sizeof (uint16_t));
	bcopy(tcph->th_lport, &pports[1], sizeof (uint16_t));

	connfp = &ipcl_conn_fanout[IPCL_CONN_HASH(ipha->ipha_dst, ports)];

	mutex_enter(&connfp->connf_lock);
	for (tconnp = connfp->connf_head; tconnp != NULL;
	    tconnp = tconnp->conn_next) {

		if (IPCL_CONN_MATCH(tconnp, IPPROTO_TCP,
		    ipha->ipha_dst, ipha->ipha_src, ports) &&
		    tconnp->conn_tcp->tcp_state >= TCPS_ESTABLISHED &&
		    (!zone_chk || tconnp->conn_zoneid == connp->conn_zoneid)) {

			ASSERT(tconnp != connp);
			CONN_INC_REF(tconnp);
			mutex_exit(&connfp->connf_lock);
			return (tconnp);
		}
	}
	mutex_exit(&connfp->connf_lock);
	return (NULL);
}

/*
 * Search for a peer TCP/IPv6 loopback conn by doing a reverse lookup on
 * the {src, dst, lport, fport} quadruplet.  Returns with conn reference
 * held; caller must call CONN_DEC_REF.  Only checks for connected entries
 * (peer tcp in at least ESTABLISHED state).
 */
conn_t *
ipcl_conn_tcp_lookup_reversed_ipv6(conn_t *connp, ip6_t *ip6h, tcph_t *tcph)
{
	uint32_t ports;
	uint16_t *pports = (uint16_t *)&ports;
	connf_t	*connfp;
	conn_t	*tconnp;
	boolean_t zone_chk;

	/*
	 * If either the source of destination address is loopback, then
	 * both endpoints must be in the same Zone.  Otherwise, both of
	 * the addresses are system-wide unique (tcp is in ESTABLISHED
	 * state) and the endpoints may reside in different Zones.  We
	 * don't do Zone check for link local address(es) because the
	 * current Zone implementation treats each link local address as
	 * being unique per system node, i.e. they belong to global Zone.
	 */
	zone_chk = (IN6_IS_ADDR_LOOPBACK(&ip6h->ip6_src) ||
	    IN6_IS_ADDR_LOOPBACK(&ip6h->ip6_dst));

	bcopy(tcph->th_fport, &pports[0], sizeof (uint16_t));
	bcopy(tcph->th_lport, &pports[1], sizeof (uint16_t));

	connfp = &ipcl_conn_fanout[IPCL_CONN_HASH_V6(ip6h->ip6_dst, ports)];

	mutex_enter(&connfp->connf_lock);
	for (tconnp = connfp->connf_head; tconnp != NULL;
	    tconnp = tconnp->conn_next) {

		/* We skip tcp_bound_if check here as this is loopback tcp */
		if (IPCL_CONN_MATCH_V6(tconnp, IPPROTO_TCP,
		    ip6h->ip6_dst, ip6h->ip6_src, ports) &&
		    tconnp->conn_tcp->tcp_state >= TCPS_ESTABLISHED &&
		    (!zone_chk || tconnp->conn_zoneid == connp->conn_zoneid)) {

			ASSERT(tconnp != connp);
			CONN_INC_REF(tconnp);
			mutex_exit(&connfp->connf_lock);
			return (tconnp);
		}
	}
	mutex_exit(&connfp->connf_lock);
	return (NULL);
}

/*
 * Find an exact {src, dst, lport, fport} match for a bounced datagram.
 * Returns with conn reference held. Caller must call CONN_DEC_REF.
 * Only checks for connected entries i.e. no INADDR_ANY checks.
 */
conn_t *
ipcl_tcp_lookup_reversed_ipv4(ipha_t *ipha, tcph_t *tcph, int min_state)
{
	uint32_t ports;
	uint16_t *pports;
	connf_t	*connfp;
	conn_t	*tconnp;

	pports = (uint16_t *)&ports;
	bcopy(tcph->th_fport, &pports[0], sizeof (uint16_t));
	bcopy(tcph->th_lport, &pports[1], sizeof (uint16_t));

	connfp = &ipcl_conn_fanout[IPCL_CONN_HASH(ipha->ipha_dst, ports)];

	mutex_enter(&connfp->connf_lock);
	for (tconnp = connfp->connf_head; tconnp != NULL;
	    tconnp = tconnp->conn_next) {

		if (IPCL_CONN_MATCH(tconnp, IPPROTO_TCP,
		    ipha->ipha_dst, ipha->ipha_src, ports) &&
		    tconnp->conn_tcp->tcp_state >= min_state) {

			CONN_INC_REF(tconnp);
			mutex_exit(&connfp->connf_lock);
			return (tconnp);
		}
	}
	mutex_exit(&connfp->connf_lock);
	return (NULL);
}

/*
 * Find an exact {src, dst, lport, fport} match for a bounced datagram.
 * Returns with conn reference held. Caller must call CONN_DEC_REF.
 * Only checks for connected entries i.e. no INADDR_ANY checks.
 * Match on ifindex in addition to addresses.
 */
conn_t *
ipcl_tcp_lookup_reversed_ipv6(ip6_t *ip6h, tcpha_t *tcpha, int min_state,
    uint_t ifindex)
{
	tcp_t	*tcp;
	uint32_t ports;
	uint16_t *pports;
	connf_t	*connfp;
	conn_t	*tconnp;

	pports = (uint16_t *)&ports;
	pports[0] = tcpha->tha_fport;
	pports[1] = tcpha->tha_lport;

	connfp = &ipcl_conn_fanout[IPCL_CONN_HASH_V6(ip6h->ip6_dst, ports)];

	mutex_enter(&connfp->connf_lock);
	for (tconnp = connfp->connf_head; tconnp != NULL;
	    tconnp = tconnp->conn_next) {

		tcp = tconnp->conn_tcp;
		if (IPCL_CONN_MATCH_V6(tconnp, IPPROTO_TCP,
		    ip6h->ip6_dst, ip6h->ip6_src, ports) &&
		    tcp->tcp_state >= min_state &&
		    (tcp->tcp_bound_if == 0 ||
		    tcp->tcp_bound_if == ifindex)) {

			CONN_INC_REF(tconnp);
			mutex_exit(&connfp->connf_lock);
			return (tconnp);
		}
	}
	mutex_exit(&connfp->connf_lock);
	return (NULL);
}

/*
 * To find a TCP listening connection matching the incoming segment.
 */
conn_t *
ipcl_lookup_listener_v4(uint16_t lport, ipaddr_t laddr, zoneid_t zoneid)
{
	connf_t		*bind_connfp;
	conn_t		*connp;
	tcp_t		*tcp;

	/*
	 * Avoid false matches for packets sent to an IP destination of
	 * all zeros.
	 */
	if (laddr == 0)
		return (NULL);

	bind_connfp = &ipcl_bind_fanout[IPCL_BIND_HASH(lport)];
	mutex_enter(&bind_connfp->connf_lock);
	for (connp = bind_connfp->connf_head; connp != NULL;
	    connp = connp->conn_next) {
		tcp = connp->conn_tcp;
		if (IPCL_BIND_MATCH(connp, IPPROTO_TCP, laddr, lport) &&
		    connp->conn_zoneid == zoneid &&
		    (tcp->tcp_listener == NULL)) {
			CONN_INC_REF(connp);
			mutex_exit(&bind_connfp->connf_lock);
			return (connp);
		}
	}
	mutex_exit(&bind_connfp->connf_lock);
	return (NULL);
}


conn_t *
ipcl_lookup_listener_v6(uint16_t lport, in6_addr_t *laddr, uint_t ifindex,
    zoneid_t zoneid)
{
	connf_t		*bind_connfp;
	conn_t		*connp = NULL;
	tcp_t		*tcp;

	/*
	 * Avoid false matches for packets sent to an IP destination of
	 * all zeros.
	 */
	if (IN6_IS_ADDR_UNSPECIFIED(laddr))
		return (NULL);


	bind_connfp = &ipcl_bind_fanout[IPCL_BIND_HASH(lport)];
	mutex_enter(&bind_connfp->connf_lock);
	for (connp = bind_connfp->connf_head; connp != NULL;
	    connp = connp->conn_next) {
		tcp = connp->conn_tcp;
		if (IPCL_BIND_MATCH_V6(connp, IPPROTO_TCP, *laddr, lport) &&
		    connp->conn_zoneid == zoneid &&
		    (tcp->tcp_bound_if == 0 ||
		    tcp->tcp_bound_if == ifindex) &&
		    tcp->tcp_listener == NULL) {
			CONN_INC_REF(connp);
			mutex_exit(&bind_connfp->connf_lock);
			return (connp);
		}
	}
	mutex_exit(&bind_connfp->connf_lock);
	return (NULL);
}

/*
 * ipcl_get_next_conn
 *	get the next entry in the conn global list
 *	and put a reference on the next_conn.
 *	decrement the reference on the current conn.
 *
 * This is an iterator based walker function that also provides for
 * some selection by the caller. It walks through the conn_hash bucket
 * searching for the next valid connp in the list, and selects connections
 * that are neither closed nor condemned. It also REFHOLDS the conn
 * thus ensuring that the conn exists when the caller uses the conn.
 */
conn_t *
ipcl_get_next_conn(connf_t *connfp, conn_t *connp, uint32_t conn_flags)
{
	conn_t	*next_connp;

	if (connfp == NULL)
		return (NULL);

	mutex_enter(&connfp->connf_lock);

	next_connp = (connp == NULL) ?
	    connfp->connf_head : connp->conn_g_next;

	while (next_connp != NULL) {
		mutex_enter(&next_connp->conn_lock);
		if (!(next_connp->conn_flags & conn_flags) ||
		    (next_connp->conn_state_flags &
		    (CONN_CONDEMNED | CONN_INCIPIENT))) {
			/*
			 * This conn has been condemned or
			 * is closing, or the flags don't match
			 */
			mutex_exit(&next_connp->conn_lock);
			next_connp = next_connp->conn_g_next;
			continue;
		}
		CONN_INC_REF_LOCKED(next_connp);
		mutex_exit(&next_connp->conn_lock);
		break;
	}

	mutex_exit(&connfp->connf_lock);

	if (connp != NULL)
		CONN_DEC_REF(connp);

	return (next_connp);
}

#ifdef CONN_DEBUG
/*
 * Trace of the last NBUF refhold/refrele
 */
int
conn_trace_ref(conn_t *connp)
{
	int	last;
	conn_trace_t	*ctb;

	ASSERT(MUTEX_HELD(&connp->conn_lock));
	last = connp->conn_trace_last;
	last++;
	if (last == CONN_TRACE_MAX)
		last = 0;

	ctb = &connp->conn_trace_buf[last];
	ctb->ctb_depth = getpcstack(ctb->ctb_stack, IP_STACK_DEPTH);
	connp->conn_trace_last = last;
	return (1);
}

int
conn_untrace_ref(conn_t *connp)
{
	int	last;
	conn_trace_t	*ctb;

	ASSERT(MUTEX_HELD(&connp->conn_lock));
	last = connp->conn_trace_last;
	last++;
	if (last == CONN_TRACE_MAX)
		last = 0;

	ctb = &connp->conn_trace_buf[last];
	ctb->ctb_depth = getpcstack(ctb->ctb_stack, IP_STACK_DEPTH);
	connp->conn_trace_last = last;
	return (1);
}
#endif
