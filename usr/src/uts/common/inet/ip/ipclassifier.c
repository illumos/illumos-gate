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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

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
 * conn_recv is used to pass up packets to the ULP.
 * For TCP conn_recv changes. It is tcp_input_listener_unbound initially for
 * a listener, and changes to tcp_input_listener as the listener has picked a
 * good squeue. For other cases it is set to tcp_input_data.
 *
 * conn_recvicmp is used to pass up ICMP errors to the ULP.
 *
 * Classifier uses several hash tables:
 *
 * 	ipcl_conn_fanout:	contains all TCP connections in CONNECTED state
 *	ipcl_bind_fanout:	contains all connections in BOUND state
 *	ipcl_proto_fanout:	IPv4 protocol fanout
 *	ipcl_proto_fanout_v6:	IPv6 protocol fanout
 *	ipcl_udp_fanout:	contains all UDP connections
 *	ipcl_iptun_fanout:	contains all IP tunnel connections
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
 * conn_t *ipcl_classify_v4(mp, protocol, hdr_len, ira, ip_stack)
 * conn_t *ipcl_classify_v6(mp, protocol, hdr_len, ira, ip_stack)
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
 * 	ira->ira_zoneid: The zone in which the returned connection must be; the
 *		zoneid corresponding to the ire_zoneid on the IRE located for
 *		the packet's destination address.
 *
 *	ira->ira_flags: Contains the IRAF_TX_MAC_EXEMPTABLE and
 *		IRAF_TX_SHARED_ADDR flags
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
 * If the destination IRE is ALL_ZONES (indicated by zoneid), then we must
 * determine which actual zone gets the segment.  This is used only in a
 * labeled environment.  The matching rules are:
 *
 *	- If it's not a multilevel port, then the label on the packet selects
 *	  the zone.  Unlabeled packets are delivered to the global zone.
 *
 *	- If it's a multilevel port, then only the zone registered to receive
 *	  packets on that port matches.
 *
 * Also, in a labeled environment, packet labels need to be checked.  For fully
 * bound TCP connections, we can assume that the packet label was checked
 * during connection establishment, and doesn't need to be checked on each
 * packet.  For others, though, we need to check for strict equality or, for
 * multilevel ports, membership in the range or set.  This part currently does
 * a tnrh lookup on each packet, but could be optimized to use cached results
 * if that were necessary.  (SCTP doesn't come through here, but if it did,
 * we would apply the same rules as TCP.)
 *
 * An implication of the above is that fully-bound TCP sockets must always use
 * distinct 4-tuples; they can't be discriminated by label alone.
 *
 * Note that we cannot trust labels on packets sent to fully-bound UDP sockets,
 * as there's no connection set-up handshake and no shared state.
 *
 * Labels on looped-back packets within a single zone do not need to be
 * checked, as all processes in the same zone have the same label.
 *
 * Finally, for unlabeled packets received by a labeled system, special rules
 * apply.  We consider only the MLP if there is one.  Otherwise, we prefer a
 * socket in the zone whose label matches the default label of the sender, if
 * any.  In any event, the receiving socket must have SO_MAC_EXEMPT set and the
 * receiver's label must dominate the sender's default label.
 *
 * conn_t *ipcl_tcp_lookup_reversed_ipv4(ipha_t *, tcpha_t *, int, ip_stack);
 * conn_t *ipcl_tcp_lookup_reversed_ipv6(ip6_t *, tcpha_t *, int, uint_t,
 *					 ip_stack);
 *
 *	Lookup routine to find a exact match for {src, dst, local port,
 *	remote port) for TCP connections in ipcl_conn_fanout. The address and
 *	ports are read from the IP and TCP header respectively.
 *
 * conn_t	*ipcl_lookup_listener_v4(lport, laddr, protocol,
 *					 zoneid, ip_stack);
 * conn_t	*ipcl_lookup_listener_v6(lport, laddr, protocol, ifindex,
 *					 zoneid, ip_stack);
 *
 * 	Lookup routine to find a listener with the tuple {lport, laddr,
 * 	protocol} in the ipcl_bind_fanout table. For IPv6, an additional
 * 	parameter interface index is also compared.
 *
 * void ipcl_walk(func, arg, ip_stack)
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
 * int ipcl_conn_insert(connp);
 * int ipcl_conn_insert_v4(connp);
 * int ipcl_conn_insert_v6(connp);
 *
 *	Insert 'connp' in the ipcl_conn_fanout.
 *	Arguements :
 *		connp		conn_t to be inserted
 *
 *	Return value :
 *		0		if connp was inserted
 *		EADDRINUSE	if the connection with the same tuple
 *				already exists.
 *
 * int ipcl_bind_insert(connp);
 * int ipcl_bind_insert_v4(connp);
 * int ipcl_bind_insert_v6(connp);
 *
 * 	Insert 'connp' in ipcl_bind_fanout.
 * 	Arguements :
 * 		connp		conn_t to be inserted
 *
 *
 * void ipcl_hash_remove(connp);
 *
 * 	Removes the 'connp' from the connection fanout table.
 *
 * Connection Creation/Destruction
 * -------------------------------
 *
 * conn_t *ipcl_conn_create(type, sleep, netstack_t *)
 *
 * 	Creates a new conn based on the type flag, inserts it into
 * 	globalhash table.
 *
 *	type:	This flag determines the type of conn_t which needs to be
 *		created i.e., which kmem_cache it comes from.
 *		IPCL_TCPCONN	indicates a TCP connection
 *		IPCL_SCTPCONN	indicates a SCTP connection
 *		IPCL_UDPCONN	indicates a UDP conn_t.
 *		IPCL_RAWIPCONN	indicates a RAWIP/ICMP conn_t.
 *		IPCL_RTSCONN	indicates a RTS conn_t.
 *		IPCL_IPCCONN	indicates all other connections.
 *
 * void ipcl_conn_destroy(connp)
 *
 * 	Destroys the connection state, removes it from the global
 * 	connection hash table and frees its memory.
 */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/sysmacros.h>
#include <sys/strsubr.h>
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
#include <inet/ip_if.h>
#include <inet/ip_ire.h>
#include <inet/ip6.h>
#include <inet/ip_ndp.h>
#include <inet/ip_impl.h>
#include <inet/udp_impl.h>
#include <inet/sctp_ip.h>
#include <inet/sctp/sctp_impl.h>
#include <inet/rawip_impl.h>
#include <inet/rts_impl.h>
#include <inet/iptun/iptun_impl.h>

#include <sys/cpuvar.h>

#include <inet/ipclassifier.h>
#include <inet/tcp.h>
#include <inet/ipsec_impl.h>

#include <sys/tsol/tnet.h>
#include <sys/sockio.h>

/* Old value for compatibility. Setable in /etc/system */
uint_t tcp_conn_hash_size = 0;

/* New value. Zero means choose automatically.  Setable in /etc/system */
uint_t ipcl_conn_hash_size = 0;
uint_t ipcl_conn_hash_memfactor = 8192;
uint_t ipcl_conn_hash_maxsize = 82500;

/* bind/udp fanout table size */
uint_t ipcl_bind_fanout_size = 512;
uint_t ipcl_udp_fanout_size = 16384;

/* Raw socket fanout size.  Must be a power of 2. */
uint_t ipcl_raw_fanout_size = 256;

/*
 * The IPCL_IPTUN_HASH() function works best with a prime table size.  We
 * expect that most large deployments would have hundreds of tunnels, and
 * thousands in the extreme case.
 */
uint_t ipcl_iptun_fanout_size = 6143;

/*
 * Power of 2^N Primes useful for hashing for N of 0-28,
 * these primes are the nearest prime <= 2^N - 2^(N-2).
 */

#define	P2Ps() {0, 0, 0, 5, 11, 23, 47, 89, 191, 383, 761, 1531, 3067,	\
		6143, 12281, 24571, 49139, 98299, 196597, 393209,	\
		786431, 1572853, 3145721, 6291449, 12582893, 25165813,	\
		50331599, 100663291, 201326557, 0}

/*
 * wrapper structure to ensure that conn and what follows it (tcp_t, etc)
 * are aligned on cache lines.
 */
typedef union itc_s {
	conn_t	itc_conn;
	char	itcu_filler[CACHE_ALIGN(conn_s)];
} itc_t;

struct kmem_cache  *tcp_conn_cache;
struct kmem_cache  *ip_conn_cache;
extern struct kmem_cache  *sctp_conn_cache;
struct kmem_cache  *udp_conn_cache;
struct kmem_cache  *rawip_conn_cache;
struct kmem_cache  *rts_conn_cache;

extern void	tcp_timermp_free(tcp_t *);
extern mblk_t	*tcp_timermp_alloc(int);

static int	ip_conn_constructor(void *, void *, int);
static void	ip_conn_destructor(void *, void *);

static int	tcp_conn_constructor(void *, void *, int);
static void	tcp_conn_destructor(void *, void *);

static int	udp_conn_constructor(void *, void *, int);
static void	udp_conn_destructor(void *, void *);

static int	rawip_conn_constructor(void *, void *, int);
static void	rawip_conn_destructor(void *, void *);

static int	rts_conn_constructor(void *, void *, int);
static void	rts_conn_destructor(void *, void *);

/*
 * Global (for all stack instances) init routine
 */
void
ipcl_g_init(void)
{
	ip_conn_cache = kmem_cache_create("ip_conn_cache",
	    sizeof (conn_t), CACHE_ALIGN_SIZE,
	    ip_conn_constructor, ip_conn_destructor,
	    NULL, NULL, NULL, 0);

	tcp_conn_cache = kmem_cache_create("tcp_conn_cache",
	    sizeof (itc_t) + sizeof (tcp_t), CACHE_ALIGN_SIZE,
	    tcp_conn_constructor, tcp_conn_destructor,
	    tcp_conn_reclaim, NULL, NULL, 0);

	udp_conn_cache = kmem_cache_create("udp_conn_cache",
	    sizeof (itc_t) + sizeof (udp_t), CACHE_ALIGN_SIZE,
	    udp_conn_constructor, udp_conn_destructor,
	    NULL, NULL, NULL, 0);

	rawip_conn_cache = kmem_cache_create("rawip_conn_cache",
	    sizeof (itc_t) + sizeof (icmp_t), CACHE_ALIGN_SIZE,
	    rawip_conn_constructor, rawip_conn_destructor,
	    NULL, NULL, NULL, 0);

	rts_conn_cache = kmem_cache_create("rts_conn_cache",
	    sizeof (itc_t) + sizeof (rts_t), CACHE_ALIGN_SIZE,
	    rts_conn_constructor, rts_conn_destructor,
	    NULL, NULL, NULL, 0);
}

/*
 * ipclassifier intialization routine, sets up hash tables.
 */
void
ipcl_init(ip_stack_t *ipst)
{
	int i;
	int sizes[] = P2Ps();

	/*
	 * Calculate size of conn fanout table from /etc/system settings
	 */
	if (ipcl_conn_hash_size != 0) {
		ipst->ips_ipcl_conn_fanout_size = ipcl_conn_hash_size;
	} else if (tcp_conn_hash_size != 0) {
		ipst->ips_ipcl_conn_fanout_size = tcp_conn_hash_size;
	} else {
		extern pgcnt_t freemem;

		ipst->ips_ipcl_conn_fanout_size =
		    (freemem * PAGESIZE) / ipcl_conn_hash_memfactor;

		if (ipst->ips_ipcl_conn_fanout_size > ipcl_conn_hash_maxsize) {
			ipst->ips_ipcl_conn_fanout_size =
			    ipcl_conn_hash_maxsize;
		}
	}

	for (i = 9; i < sizeof (sizes) / sizeof (*sizes) - 1; i++) {
		if (sizes[i] >= ipst->ips_ipcl_conn_fanout_size) {
			break;
		}
	}
	if ((ipst->ips_ipcl_conn_fanout_size = sizes[i]) == 0) {
		/* Out of range, use the 2^16 value */
		ipst->ips_ipcl_conn_fanout_size = sizes[16];
	}

	/* Take values from /etc/system */
	ipst->ips_ipcl_bind_fanout_size = ipcl_bind_fanout_size;
	ipst->ips_ipcl_udp_fanout_size = ipcl_udp_fanout_size;
	ipst->ips_ipcl_raw_fanout_size = ipcl_raw_fanout_size;
	ipst->ips_ipcl_iptun_fanout_size = ipcl_iptun_fanout_size;

	ASSERT(ipst->ips_ipcl_conn_fanout == NULL);

	ipst->ips_ipcl_conn_fanout = kmem_zalloc(
	    ipst->ips_ipcl_conn_fanout_size * sizeof (connf_t), KM_SLEEP);

	for (i = 0; i < ipst->ips_ipcl_conn_fanout_size; i++) {
		mutex_init(&ipst->ips_ipcl_conn_fanout[i].connf_lock, NULL,
		    MUTEX_DEFAULT, NULL);
	}

	ipst->ips_ipcl_bind_fanout = kmem_zalloc(
	    ipst->ips_ipcl_bind_fanout_size * sizeof (connf_t), KM_SLEEP);

	for (i = 0; i < ipst->ips_ipcl_bind_fanout_size; i++) {
		mutex_init(&ipst->ips_ipcl_bind_fanout[i].connf_lock, NULL,
		    MUTEX_DEFAULT, NULL);
	}

	ipst->ips_ipcl_proto_fanout_v4 = kmem_zalloc(IPPROTO_MAX *
	    sizeof (connf_t), KM_SLEEP);
	for (i = 0; i < IPPROTO_MAX; i++) {
		mutex_init(&ipst->ips_ipcl_proto_fanout_v4[i].connf_lock, NULL,
		    MUTEX_DEFAULT, NULL);
	}

	ipst->ips_ipcl_proto_fanout_v6 = kmem_zalloc(IPPROTO_MAX *
	    sizeof (connf_t), KM_SLEEP);
	for (i = 0; i < IPPROTO_MAX; i++) {
		mutex_init(&ipst->ips_ipcl_proto_fanout_v6[i].connf_lock, NULL,
		    MUTEX_DEFAULT, NULL);
	}

	ipst->ips_rts_clients = kmem_zalloc(sizeof (connf_t), KM_SLEEP);
	mutex_init(&ipst->ips_rts_clients->connf_lock,
	    NULL, MUTEX_DEFAULT, NULL);

	ipst->ips_ipcl_udp_fanout = kmem_zalloc(
	    ipst->ips_ipcl_udp_fanout_size * sizeof (connf_t), KM_SLEEP);
	for (i = 0; i < ipst->ips_ipcl_udp_fanout_size; i++) {
		mutex_init(&ipst->ips_ipcl_udp_fanout[i].connf_lock, NULL,
		    MUTEX_DEFAULT, NULL);
	}

	ipst->ips_ipcl_iptun_fanout = kmem_zalloc(
	    ipst->ips_ipcl_iptun_fanout_size * sizeof (connf_t), KM_SLEEP);
	for (i = 0; i < ipst->ips_ipcl_iptun_fanout_size; i++) {
		mutex_init(&ipst->ips_ipcl_iptun_fanout[i].connf_lock, NULL,
		    MUTEX_DEFAULT, NULL);
	}

	ipst->ips_ipcl_raw_fanout = kmem_zalloc(
	    ipst->ips_ipcl_raw_fanout_size * sizeof (connf_t), KM_SLEEP);
	for (i = 0; i < ipst->ips_ipcl_raw_fanout_size; i++) {
		mutex_init(&ipst->ips_ipcl_raw_fanout[i].connf_lock, NULL,
		    MUTEX_DEFAULT, NULL);
	}

	ipst->ips_ipcl_globalhash_fanout = kmem_zalloc(
	    sizeof (connf_t) * CONN_G_HASH_SIZE, KM_SLEEP);
	for (i = 0; i < CONN_G_HASH_SIZE; i++) {
		mutex_init(&ipst->ips_ipcl_globalhash_fanout[i].connf_lock,
		    NULL, MUTEX_DEFAULT, NULL);
	}
}

void
ipcl_g_destroy(void)
{
	kmem_cache_destroy(ip_conn_cache);
	kmem_cache_destroy(tcp_conn_cache);
	kmem_cache_destroy(udp_conn_cache);
	kmem_cache_destroy(rawip_conn_cache);
	kmem_cache_destroy(rts_conn_cache);
}

/*
 * All user-level and kernel use of the stack must be gone
 * by now.
 */
void
ipcl_destroy(ip_stack_t *ipst)
{
	int i;

	for (i = 0; i < ipst->ips_ipcl_conn_fanout_size; i++) {
		ASSERT(ipst->ips_ipcl_conn_fanout[i].connf_head == NULL);
		mutex_destroy(&ipst->ips_ipcl_conn_fanout[i].connf_lock);
	}
	kmem_free(ipst->ips_ipcl_conn_fanout, ipst->ips_ipcl_conn_fanout_size *
	    sizeof (connf_t));
	ipst->ips_ipcl_conn_fanout = NULL;

	for (i = 0; i < ipst->ips_ipcl_bind_fanout_size; i++) {
		ASSERT(ipst->ips_ipcl_bind_fanout[i].connf_head == NULL);
		mutex_destroy(&ipst->ips_ipcl_bind_fanout[i].connf_lock);
	}
	kmem_free(ipst->ips_ipcl_bind_fanout, ipst->ips_ipcl_bind_fanout_size *
	    sizeof (connf_t));
	ipst->ips_ipcl_bind_fanout = NULL;

	for (i = 0; i < IPPROTO_MAX; i++) {
		ASSERT(ipst->ips_ipcl_proto_fanout_v4[i].connf_head == NULL);
		mutex_destroy(&ipst->ips_ipcl_proto_fanout_v4[i].connf_lock);
	}
	kmem_free(ipst->ips_ipcl_proto_fanout_v4,
	    IPPROTO_MAX * sizeof (connf_t));
	ipst->ips_ipcl_proto_fanout_v4 = NULL;

	for (i = 0; i < IPPROTO_MAX; i++) {
		ASSERT(ipst->ips_ipcl_proto_fanout_v6[i].connf_head == NULL);
		mutex_destroy(&ipst->ips_ipcl_proto_fanout_v6[i].connf_lock);
	}
	kmem_free(ipst->ips_ipcl_proto_fanout_v6,
	    IPPROTO_MAX * sizeof (connf_t));
	ipst->ips_ipcl_proto_fanout_v6 = NULL;

	for (i = 0; i < ipst->ips_ipcl_udp_fanout_size; i++) {
		ASSERT(ipst->ips_ipcl_udp_fanout[i].connf_head == NULL);
		mutex_destroy(&ipst->ips_ipcl_udp_fanout[i].connf_lock);
	}
	kmem_free(ipst->ips_ipcl_udp_fanout, ipst->ips_ipcl_udp_fanout_size *
	    sizeof (connf_t));
	ipst->ips_ipcl_udp_fanout = NULL;

	for (i = 0; i < ipst->ips_ipcl_iptun_fanout_size; i++) {
		ASSERT(ipst->ips_ipcl_iptun_fanout[i].connf_head == NULL);
		mutex_destroy(&ipst->ips_ipcl_iptun_fanout[i].connf_lock);
	}
	kmem_free(ipst->ips_ipcl_iptun_fanout,
	    ipst->ips_ipcl_iptun_fanout_size * sizeof (connf_t));
	ipst->ips_ipcl_iptun_fanout = NULL;

	for (i = 0; i < ipst->ips_ipcl_raw_fanout_size; i++) {
		ASSERT(ipst->ips_ipcl_raw_fanout[i].connf_head == NULL);
		mutex_destroy(&ipst->ips_ipcl_raw_fanout[i].connf_lock);
	}
	kmem_free(ipst->ips_ipcl_raw_fanout, ipst->ips_ipcl_raw_fanout_size *
	    sizeof (connf_t));
	ipst->ips_ipcl_raw_fanout = NULL;

	for (i = 0; i < CONN_G_HASH_SIZE; i++) {
		ASSERT(ipst->ips_ipcl_globalhash_fanout[i].connf_head == NULL);
		mutex_destroy(&ipst->ips_ipcl_globalhash_fanout[i].connf_lock);
	}
	kmem_free(ipst->ips_ipcl_globalhash_fanout,
	    sizeof (connf_t) * CONN_G_HASH_SIZE);
	ipst->ips_ipcl_globalhash_fanout = NULL;

	ASSERT(ipst->ips_rts_clients->connf_head == NULL);
	mutex_destroy(&ipst->ips_rts_clients->connf_lock);
	kmem_free(ipst->ips_rts_clients, sizeof (connf_t));
	ipst->ips_rts_clients = NULL;
}

/*
 * conn creation routine. initialize the conn, sets the reference
 * and inserts it in the global hash table.
 */
conn_t *
ipcl_conn_create(uint32_t type, int sleep, netstack_t *ns)
{
	conn_t	*connp;
	struct kmem_cache *conn_cache;

	switch (type) {
	case IPCL_SCTPCONN:
		if ((connp = kmem_cache_alloc(sctp_conn_cache, sleep)) == NULL)
			return (NULL);
		sctp_conn_init(connp);
		netstack_hold(ns);
		connp->conn_netstack = ns;
		connp->conn_ixa->ixa_ipst = ns->netstack_ip;
		connp->conn_ixa->ixa_conn_id = (long)connp;
		ipcl_globalhash_insert(connp);
		return (connp);

	case IPCL_TCPCONN:
		conn_cache = tcp_conn_cache;
		break;

	case IPCL_UDPCONN:
		conn_cache = udp_conn_cache;
		break;

	case IPCL_RAWIPCONN:
		conn_cache = rawip_conn_cache;
		break;

	case IPCL_RTSCONN:
		conn_cache = rts_conn_cache;
		break;

	case IPCL_IPCCONN:
		conn_cache = ip_conn_cache;
		break;

	default:
		connp = NULL;
		ASSERT(0);
	}

	if ((connp = kmem_cache_alloc(conn_cache, sleep)) == NULL)
		return (NULL);

	connp->conn_ref = 1;
	netstack_hold(ns);
	connp->conn_netstack = ns;
	connp->conn_ixa->ixa_ipst = ns->netstack_ip;
	connp->conn_ixa->ixa_conn_id = (long)connp;
	ipcl_globalhash_insert(connp);
	return (connp);
}

void
ipcl_conn_destroy(conn_t *connp)
{
	mblk_t	*mp;
	netstack_t	*ns = connp->conn_netstack;

	ASSERT(!MUTEX_HELD(&connp->conn_lock));
	ASSERT(connp->conn_ref == 0);
	ASSERT(connp->conn_ioctlref == 0);

	DTRACE_PROBE1(conn__destroy, conn_t *, connp);

	if (connp->conn_cred != NULL) {
		crfree(connp->conn_cred);
		connp->conn_cred = NULL;
		/* ixa_cred done in ipcl_conn_cleanup below */
	}

	if (connp->conn_ht_iphc != NULL) {
		kmem_free(connp->conn_ht_iphc, connp->conn_ht_iphc_allocated);
		connp->conn_ht_iphc = NULL;
		connp->conn_ht_iphc_allocated = 0;
		connp->conn_ht_iphc_len = 0;
		connp->conn_ht_ulp = NULL;
		connp->conn_ht_ulp_len = 0;
	}
	ip_pkt_free(&connp->conn_xmit_ipp);

	ipcl_globalhash_remove(connp);

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
		IPPH_REFRELE(connp->conn_policy, ns);
		connp->conn_policy = NULL;
	}

	if (connp->conn_ipsec_opt_mp != NULL) {
		freemsg(connp->conn_ipsec_opt_mp);
		connp->conn_ipsec_opt_mp = NULL;
	}

	if (connp->conn_flags & IPCL_TCPCONN) {
		tcp_t *tcp = connp->conn_tcp;

		tcp_free(tcp);
		mp = tcp->tcp_timercache;

		tcp->tcp_tcps = NULL;

		/*
		 * tcp_rsrv_mp can be NULL if tcp_get_conn() fails to allocate
		 * the mblk.
		 */
		if (tcp->tcp_rsrv_mp != NULL) {
			freeb(tcp->tcp_rsrv_mp);
			tcp->tcp_rsrv_mp = NULL;
			mutex_destroy(&tcp->tcp_rsrv_mp_lock);
		}

		ipcl_conn_cleanup(connp);
		connp->conn_flags = IPCL_TCPCONN;
		if (ns != NULL) {
			ASSERT(tcp->tcp_tcps == NULL);
			connp->conn_netstack = NULL;
			connp->conn_ixa->ixa_ipst = NULL;
			netstack_rele(ns);
		}

		bzero(tcp, sizeof (tcp_t));

		tcp->tcp_timercache = mp;
		tcp->tcp_connp = connp;
		kmem_cache_free(tcp_conn_cache, connp);
		return;
	}

	if (connp->conn_flags & IPCL_SCTPCONN) {
		ASSERT(ns != NULL);
		sctp_free(connp);
		return;
	}

	ipcl_conn_cleanup(connp);
	if (ns != NULL) {
		connp->conn_netstack = NULL;
		connp->conn_ixa->ixa_ipst = NULL;
		netstack_rele(ns);
	}

	/* leave conn_priv aka conn_udp, conn_icmp, etc in place. */
	if (connp->conn_flags & IPCL_UDPCONN) {
		connp->conn_flags = IPCL_UDPCONN;
		kmem_cache_free(udp_conn_cache, connp);
	} else if (connp->conn_flags & IPCL_RAWIPCONN) {
		connp->conn_flags = IPCL_RAWIPCONN;
		connp->conn_proto = IPPROTO_ICMP;
		connp->conn_ixa->ixa_protocol = connp->conn_proto;
		kmem_cache_free(rawip_conn_cache, connp);
	} else if (connp->conn_flags & IPCL_RTSCONN) {
		connp->conn_flags = IPCL_RTSCONN;
		kmem_cache_free(rts_conn_cache, connp);
	} else {
		connp->conn_flags = IPCL_IPCCONN;
		ASSERT(connp->conn_flags & IPCL_IPCCONN);
		ASSERT(connp->conn_priv == NULL);
		kmem_cache_free(ip_conn_cache, connp);
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

		if (connp->conn_ipversion == IPV6_VERSION) {
			addr_family = AF_INET6;
			laddrp = (uint8_t *)&connp->conn_bound_addr_v6;
		} else {
			addr_family = AF_INET;
			laddrp = (uint8_t *)&connp->conn_bound_addr_v4;
		}
		(*cl_inet_unlisten)(connp->conn_netstack->netstack_stackid,
		    IPPROTO_TCP, addr_family, laddrp, connp->conn_lport, NULL);
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
	uint8_t		protocol = connp->conn_proto;

	IPCL_HASH_REMOVE(connp);
	if (protocol == IPPROTO_RSVP)
		ill_set_inputfn_all(connp->conn_netstack->netstack_ip);
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
		(connp)->conn_next->conn_prev = (connp)->conn_prev;
	}
	if ((connp)->conn_prev != NULL) {
		(connp)->conn_prev->conn_next = (connp)->conn_next;
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
	IPCL_HASH_REMOVE((connp));					\
	mutex_enter(&(connfp)->connf_lock);				\
	IPCL_HASH_INSERT_CONNECTED_LOCKED(connfp, connp);		\
	mutex_exit(&(connfp)->connf_lock);				\
}

#define	IPCL_HASH_INSERT_BOUND(connfp, connp) {				\
	conn_t *pconnp = NULL, *nconnp;					\
	IPCL_HASH_REMOVE((connp));					\
	mutex_enter(&(connfp)->connf_lock);				\
	nconnp = (connfp)->connf_head;					\
	while (nconnp != NULL &&					\
	    !_IPCL_V4_MATCH_ANY(nconnp->conn_laddr_v6)) {		\
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
	    IN6_IS_ADDR_V4MAPPED(&(connp)->conn_laddr_v6);		\
	IPCL_HASH_REMOVE((connp));					\
	mutex_enter(&(connfp)->connf_lock);				\
	list = &(connfp)->connf_head;					\
	prev = NULL;							\
	while ((next = *list) != NULL) {				\
		if (isv4mapped &&					\
		    IN6_IS_ADDR_UNSPECIFIED(&next->conn_laddr_v6) &&	\
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

/*
 * Because the classifier is used to classify inbound packets, the destination
 * address is meant to be our local tunnel address (tunnel source), and the
 * source the remote tunnel address (tunnel destination).
 *
 * Note that conn_proto can't be used for fanout since the upper protocol
 * can be both 41 and 4 when IPv6 and IPv4 are over the same tunnel.
 */
conn_t *
ipcl_iptun_classify_v4(ipaddr_t *src, ipaddr_t *dst, ip_stack_t *ipst)
{
	connf_t	*connfp;
	conn_t	*connp;

	/* first look for IPv4 tunnel links */
	connfp = &ipst->ips_ipcl_iptun_fanout[IPCL_IPTUN_HASH(*dst, *src)];
	mutex_enter(&connfp->connf_lock);
	for (connp = connfp->connf_head; connp != NULL;
	    connp = connp->conn_next) {
		if (IPCL_IPTUN_MATCH(connp, *dst, *src))
			break;
	}
	if (connp != NULL)
		goto done;

	mutex_exit(&connfp->connf_lock);

	/* We didn't find an IPv4 tunnel, try a 6to4 tunnel */
	connfp = &ipst->ips_ipcl_iptun_fanout[IPCL_IPTUN_HASH(*dst,
	    INADDR_ANY)];
	mutex_enter(&connfp->connf_lock);
	for (connp = connfp->connf_head; connp != NULL;
	    connp = connp->conn_next) {
		if (IPCL_IPTUN_MATCH(connp, *dst, INADDR_ANY))
			break;
	}
done:
	if (connp != NULL)
		CONN_INC_REF(connp);
	mutex_exit(&connfp->connf_lock);
	return (connp);
}

conn_t *
ipcl_iptun_classify_v6(in6_addr_t *src, in6_addr_t *dst, ip_stack_t *ipst)
{
	connf_t	*connfp;
	conn_t	*connp;

	/* Look for an IPv6 tunnel link */
	connfp = &ipst->ips_ipcl_iptun_fanout[IPCL_IPTUN_HASH_V6(dst, src)];
	mutex_enter(&connfp->connf_lock);
	for (connp = connfp->connf_head; connp != NULL;
	    connp = connp->conn_next) {
		if (IPCL_IPTUN_MATCH_V6(connp, dst, src)) {
			CONN_INC_REF(connp);
			break;
		}
	}
	mutex_exit(&connfp->connf_lock);
	return (connp);
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
	ip_stack_t	*ipst = connp->conn_netstack->netstack_ip;

	connfp = &ipst->ips_ipcl_raw_fanout[IPCL_RAW_HASH(ntohs(lport), ipst)];

	/* Check for existing raw socket already bound to the port. */
	mutex_enter(&connfp->connf_lock);
	for (oconnp = connfp->connf_head; oconnp != NULL;
	    oconnp = oconnp->conn_next) {
		if (oconnp->conn_lport == lport &&
		    oconnp->conn_zoneid == connp->conn_zoneid &&
		    oconnp->conn_family == connp->conn_family &&
		    ((IN6_IS_ADDR_UNSPECIFIED(&connp->conn_laddr_v6) ||
		    IN6_IS_ADDR_UNSPECIFIED(&oconnp->conn_laddr_v6) ||
		    IN6_IS_ADDR_V4MAPPED_ANY(&connp->conn_laddr_v6) ||
		    IN6_IS_ADDR_V4MAPPED_ANY(&oconnp->conn_laddr_v6)) ||
		    IN6_ARE_ADDR_EQUAL(&oconnp->conn_laddr_v6,
		    &connp->conn_laddr_v6))) {
			break;
		}
	}
	mutex_exit(&connfp->connf_lock);
	if (oconnp != NULL)
		return (EADDRNOTAVAIL);

	if (IN6_IS_ADDR_UNSPECIFIED(&connp->conn_faddr_v6) ||
	    IN6_IS_ADDR_V4MAPPED_ANY(&connp->conn_faddr_v6)) {
		if (IN6_IS_ADDR_UNSPECIFIED(&connp->conn_laddr_v6) ||
		    IN6_IS_ADDR_V4MAPPED_ANY(&connp->conn_laddr_v6)) {
			IPCL_HASH_INSERT_WILDCARD(connfp, connp);
		} else {
			IPCL_HASH_INSERT_BOUND(connfp, connp);
		}
	} else {
		IPCL_HASH_INSERT_CONNECTED(connfp, connp);
	}
	return (0);
}

static int
ipcl_iptun_hash_insert(conn_t *connp, ip_stack_t *ipst)
{
	connf_t	*connfp;
	conn_t	*tconnp;
	ipaddr_t laddr = connp->conn_laddr_v4;
	ipaddr_t faddr = connp->conn_faddr_v4;

	connfp = &ipst->ips_ipcl_iptun_fanout[IPCL_IPTUN_HASH(laddr, faddr)];
	mutex_enter(&connfp->connf_lock);
	for (tconnp = connfp->connf_head; tconnp != NULL;
	    tconnp = tconnp->conn_next) {
		if (IPCL_IPTUN_MATCH(tconnp, laddr, faddr)) {
			/* A tunnel is already bound to these addresses. */
			mutex_exit(&connfp->connf_lock);
			return (EADDRINUSE);
		}
	}
	IPCL_HASH_INSERT_CONNECTED_LOCKED(connfp, connp);
	mutex_exit(&connfp->connf_lock);
	return (0);
}

static int
ipcl_iptun_hash_insert_v6(conn_t *connp, ip_stack_t *ipst)
{
	connf_t	*connfp;
	conn_t	*tconnp;
	in6_addr_t *laddr = &connp->conn_laddr_v6;
	in6_addr_t *faddr = &connp->conn_faddr_v6;

	connfp = &ipst->ips_ipcl_iptun_fanout[IPCL_IPTUN_HASH_V6(laddr, faddr)];
	mutex_enter(&connfp->connf_lock);
	for (tconnp = connfp->connf_head; tconnp != NULL;
	    tconnp = tconnp->conn_next) {
		if (IPCL_IPTUN_MATCH_V6(tconnp, laddr, faddr)) {
			/* A tunnel is already bound to these addresses. */
			mutex_exit(&connfp->connf_lock);
			return (EADDRINUSE);
		}
	}
	IPCL_HASH_INSERT_CONNECTED_LOCKED(connfp, connp);
	mutex_exit(&connfp->connf_lock);
	return (0);
}

/*
 * Check for a MAC exemption conflict on a labeled system.  Note that for
 * protocols that use port numbers (UDP, TCP, SCTP), we do this check up in the
 * transport layer.  This check is for binding all other protocols.
 *
 * Returns true if there's a conflict.
 */
static boolean_t
check_exempt_conflict_v4(conn_t *connp, ip_stack_t *ipst)
{
	connf_t	*connfp;
	conn_t *tconn;

	connfp = &ipst->ips_ipcl_proto_fanout_v4[connp->conn_proto];
	mutex_enter(&connfp->connf_lock);
	for (tconn = connfp->connf_head; tconn != NULL;
	    tconn = tconn->conn_next) {
		/* We don't allow v4 fallback for v6 raw socket */
		if (connp->conn_family != tconn->conn_family)
			continue;
		/* If neither is exempt, then there's no conflict */
		if ((connp->conn_mac_mode == CONN_MAC_DEFAULT) &&
		    (tconn->conn_mac_mode == CONN_MAC_DEFAULT))
			continue;
		/* We are only concerned about sockets for a different zone */
		if (connp->conn_zoneid == tconn->conn_zoneid)
			continue;
		/* If both are bound to different specific addrs, ok */
		if (connp->conn_laddr_v4 != INADDR_ANY &&
		    tconn->conn_laddr_v4 != INADDR_ANY &&
		    connp->conn_laddr_v4 != tconn->conn_laddr_v4)
			continue;
		/* These two conflict; fail */
		break;
	}
	mutex_exit(&connfp->connf_lock);
	return (tconn != NULL);
}

static boolean_t
check_exempt_conflict_v6(conn_t *connp, ip_stack_t *ipst)
{
	connf_t	*connfp;
	conn_t *tconn;

	connfp = &ipst->ips_ipcl_proto_fanout_v6[connp->conn_proto];
	mutex_enter(&connfp->connf_lock);
	for (tconn = connfp->connf_head; tconn != NULL;
	    tconn = tconn->conn_next) {
		/* We don't allow v4 fallback for v6 raw socket */
		if (connp->conn_family != tconn->conn_family)
			continue;
		/* If neither is exempt, then there's no conflict */
		if ((connp->conn_mac_mode == CONN_MAC_DEFAULT) &&
		    (tconn->conn_mac_mode == CONN_MAC_DEFAULT))
			continue;
		/* We are only concerned about sockets for a different zone */
		if (connp->conn_zoneid == tconn->conn_zoneid)
			continue;
		/* If both are bound to different addrs, ok */
		if (!IN6_IS_ADDR_UNSPECIFIED(&connp->conn_laddr_v6) &&
		    !IN6_IS_ADDR_UNSPECIFIED(&tconn->conn_laddr_v6) &&
		    !IN6_ARE_ADDR_EQUAL(&connp->conn_laddr_v6,
		    &tconn->conn_laddr_v6))
			continue;
		/* These two conflict; fail */
		break;
	}
	mutex_exit(&connfp->connf_lock);
	return (tconn != NULL);
}

/*
 * (v4, v6) bind hash insertion routines
 * The caller has already setup the conn (conn_proto, conn_laddr_v6, conn_lport)
 */

int
ipcl_bind_insert(conn_t *connp)
{
	if (connp->conn_ipversion == IPV6_VERSION)
		return (ipcl_bind_insert_v6(connp));
	else
		return (ipcl_bind_insert_v4(connp));
}

int
ipcl_bind_insert_v4(conn_t *connp)
{
	connf_t	*connfp;
	int	ret = 0;
	ip_stack_t	*ipst = connp->conn_netstack->netstack_ip;
	uint16_t	lport = connp->conn_lport;
	uint8_t		protocol = connp->conn_proto;

	if (IPCL_IS_IPTUN(connp))
		return (ipcl_iptun_hash_insert(connp, ipst));

	switch (protocol) {
	default:
		if (is_system_labeled() &&
		    check_exempt_conflict_v4(connp, ipst))
			return (EADDRINUSE);
		/* FALLTHROUGH */
	case IPPROTO_UDP:
		if (protocol == IPPROTO_UDP) {
			connfp = &ipst->ips_ipcl_udp_fanout[
			    IPCL_UDP_HASH(lport, ipst)];
		} else {
			connfp = &ipst->ips_ipcl_proto_fanout_v4[protocol];
		}

		if (connp->conn_faddr_v4 != INADDR_ANY) {
			IPCL_HASH_INSERT_CONNECTED(connfp, connp);
		} else if (connp->conn_laddr_v4 != INADDR_ANY) {
			IPCL_HASH_INSERT_BOUND(connfp, connp);
		} else {
			IPCL_HASH_INSERT_WILDCARD(connfp, connp);
		}
		if (protocol == IPPROTO_RSVP)
			ill_set_inputfn_all(ipst);
		break;

	case IPPROTO_TCP:
		/* Insert it in the Bind Hash */
		ASSERT(connp->conn_zoneid != ALL_ZONES);
		connfp = &ipst->ips_ipcl_bind_fanout[
		    IPCL_BIND_HASH(lport, ipst)];
		if (connp->conn_laddr_v4 != INADDR_ANY) {
			IPCL_HASH_INSERT_BOUND(connfp, connp);
		} else {
			IPCL_HASH_INSERT_WILDCARD(connfp, connp);
		}
		if (cl_inet_listen != NULL) {
			ASSERT(connp->conn_ipversion == IPV4_VERSION);
			connp->conn_flags |= IPCL_CL_LISTENER;
			(*cl_inet_listen)(
			    connp->conn_netstack->netstack_stackid,
			    IPPROTO_TCP, AF_INET,
			    (uint8_t *)&connp->conn_bound_addr_v4, lport, NULL);
		}
		break;

	case IPPROTO_SCTP:
		ret = ipcl_sctp_hash_insert(connp, lport);
		break;
	}

	return (ret);
}

int
ipcl_bind_insert_v6(conn_t *connp)
{
	connf_t		*connfp;
	int		ret = 0;
	ip_stack_t	*ipst = connp->conn_netstack->netstack_ip;
	uint16_t	lport = connp->conn_lport;
	uint8_t		protocol = connp->conn_proto;

	if (IPCL_IS_IPTUN(connp)) {
		return (ipcl_iptun_hash_insert_v6(connp, ipst));
	}

	switch (protocol) {
	default:
		if (is_system_labeled() &&
		    check_exempt_conflict_v6(connp, ipst))
			return (EADDRINUSE);
		/* FALLTHROUGH */
	case IPPROTO_UDP:
		if (protocol == IPPROTO_UDP) {
			connfp = &ipst->ips_ipcl_udp_fanout[
			    IPCL_UDP_HASH(lport, ipst)];
		} else {
			connfp = &ipst->ips_ipcl_proto_fanout_v6[protocol];
		}

		if (!IN6_IS_ADDR_UNSPECIFIED(&connp->conn_faddr_v6)) {
			IPCL_HASH_INSERT_CONNECTED(connfp, connp);
		} else if (!IN6_IS_ADDR_UNSPECIFIED(&connp->conn_laddr_v6)) {
			IPCL_HASH_INSERT_BOUND(connfp, connp);
		} else {
			IPCL_HASH_INSERT_WILDCARD(connfp, connp);
		}
		break;

	case IPPROTO_TCP:
		/* Insert it in the Bind Hash */
		ASSERT(connp->conn_zoneid != ALL_ZONES);
		connfp = &ipst->ips_ipcl_bind_fanout[
		    IPCL_BIND_HASH(lport, ipst)];
		if (!IN6_IS_ADDR_UNSPECIFIED(&connp->conn_laddr_v6)) {
			IPCL_HASH_INSERT_BOUND(connfp, connp);
		} else {
			IPCL_HASH_INSERT_WILDCARD(connfp, connp);
		}
		if (cl_inet_listen != NULL) {
			sa_family_t	addr_family;
			uint8_t		*laddrp;

			if (connp->conn_ipversion == IPV6_VERSION) {
				addr_family = AF_INET6;
				laddrp =
				    (uint8_t *)&connp->conn_bound_addr_v6;
			} else {
				addr_family = AF_INET;
				laddrp = (uint8_t *)&connp->conn_bound_addr_v4;
			}
			connp->conn_flags |= IPCL_CL_LISTENER;
			(*cl_inet_listen)(
			    connp->conn_netstack->netstack_stackid,
			    IPPROTO_TCP, addr_family, laddrp, lport, NULL);
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
 * The caller has already set conn_proto and the addresses/ports in the conn_t.
 */

int
ipcl_conn_insert(conn_t *connp)
{
	if (connp->conn_ipversion == IPV6_VERSION)
		return (ipcl_conn_insert_v6(connp));
	else
		return (ipcl_conn_insert_v4(connp));
}

int
ipcl_conn_insert_v4(conn_t *connp)
{
	connf_t		*connfp;
	conn_t		*tconnp;
	int		ret = 0;
	ip_stack_t	*ipst = connp->conn_netstack->netstack_ip;
	uint16_t	lport = connp->conn_lport;
	uint8_t		protocol = connp->conn_proto;

	if (IPCL_IS_IPTUN(connp))
		return (ipcl_iptun_hash_insert(connp, ipst));

	switch (protocol) {
	case IPPROTO_TCP:
		/*
		 * For TCP, we check whether the connection tuple already
		 * exists before allowing the connection to proceed.  We
		 * also allow indexing on the zoneid. This is to allow
		 * multiple shared stack zones to have the same tcp
		 * connection tuple. In practice this only happens for
		 * INADDR_LOOPBACK as it's the only local address which
		 * doesn't have to be unique.
		 */
		connfp = &ipst->ips_ipcl_conn_fanout[
		    IPCL_CONN_HASH(connp->conn_faddr_v4,
		    connp->conn_ports, ipst)];
		mutex_enter(&connfp->connf_lock);
		for (tconnp = connfp->connf_head; tconnp != NULL;
		    tconnp = tconnp->conn_next) {
			if (IPCL_CONN_MATCH(tconnp, connp->conn_proto,
			    connp->conn_faddr_v4, connp->conn_laddr_v4,
			    connp->conn_ports) &&
			    IPCL_ZONE_MATCH(tconnp, connp->conn_zoneid)) {
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

		ASSERT(connp->conn_recv != NULL);
		ASSERT(connp->conn_recvicmp != NULL);

		IPCL_HASH_INSERT_CONNECTED_LOCKED(connfp, connp);
		mutex_exit(&connfp->connf_lock);
		break;

	case IPPROTO_SCTP:
		/*
		 * The raw socket may have already been bound, remove it
		 * from the hash first.
		 */
		IPCL_HASH_REMOVE(connp);
		ret = ipcl_sctp_hash_insert(connp, lport);
		break;

	default:
		/*
		 * Check for conflicts among MAC exempt bindings.  For
		 * transports with port numbers, this is done by the upper
		 * level per-transport binding logic.  For all others, it's
		 * done here.
		 */
		if (is_system_labeled() &&
		    check_exempt_conflict_v4(connp, ipst))
			return (EADDRINUSE);
		/* FALLTHROUGH */

	case IPPROTO_UDP:
		if (protocol == IPPROTO_UDP) {
			connfp = &ipst->ips_ipcl_udp_fanout[
			    IPCL_UDP_HASH(lport, ipst)];
		} else {
			connfp = &ipst->ips_ipcl_proto_fanout_v4[protocol];
		}

		if (connp->conn_faddr_v4 != INADDR_ANY) {
			IPCL_HASH_INSERT_CONNECTED(connfp, connp);
		} else if (connp->conn_laddr_v4 != INADDR_ANY) {
			IPCL_HASH_INSERT_BOUND(connfp, connp);
		} else {
			IPCL_HASH_INSERT_WILDCARD(connfp, connp);
		}
		break;
	}

	return (ret);
}

int
ipcl_conn_insert_v6(conn_t *connp)
{
	connf_t		*connfp;
	conn_t		*tconnp;
	int		ret = 0;
	ip_stack_t	*ipst = connp->conn_netstack->netstack_ip;
	uint16_t	lport = connp->conn_lport;
	uint8_t		protocol = connp->conn_proto;
	uint_t		ifindex = connp->conn_bound_if;

	if (IPCL_IS_IPTUN(connp))
		return (ipcl_iptun_hash_insert_v6(connp, ipst));

	switch (protocol) {
	case IPPROTO_TCP:

		/*
		 * For tcp, we check whether the connection tuple already
		 * exists before allowing the connection to proceed.  We
		 * also allow indexing on the zoneid. This is to allow
		 * multiple shared stack zones to have the same tcp
		 * connection tuple. In practice this only happens for
		 * ipv6_loopback as it's the only local address which
		 * doesn't have to be unique.
		 */
		connfp = &ipst->ips_ipcl_conn_fanout[
		    IPCL_CONN_HASH_V6(connp->conn_faddr_v6, connp->conn_ports,
		    ipst)];
		mutex_enter(&connfp->connf_lock);
		for (tconnp = connfp->connf_head; tconnp != NULL;
		    tconnp = tconnp->conn_next) {
			/* NOTE: need to match zoneid. Bug in onnv-gate */
			if (IPCL_CONN_MATCH_V6(tconnp, connp->conn_proto,
			    connp->conn_faddr_v6, connp->conn_laddr_v6,
			    connp->conn_ports) &&
			    (tconnp->conn_bound_if == 0 ||
			    tconnp->conn_bound_if == ifindex) &&
			    IPCL_ZONE_MATCH(tconnp, connp->conn_zoneid)) {
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
		ret = ipcl_sctp_hash_insert(connp, lport);
		break;

	default:
		if (is_system_labeled() &&
		    check_exempt_conflict_v6(connp, ipst))
			return (EADDRINUSE);
		/* FALLTHROUGH */
	case IPPROTO_UDP:
		if (protocol == IPPROTO_UDP) {
			connfp = &ipst->ips_ipcl_udp_fanout[
			    IPCL_UDP_HASH(lport, ipst)];
		} else {
			connfp = &ipst->ips_ipcl_proto_fanout_v6[protocol];
		}

		if (!IN6_IS_ADDR_UNSPECIFIED(&connp->conn_faddr_v6)) {
			IPCL_HASH_INSERT_CONNECTED(connfp, connp);
		} else if (!IN6_IS_ADDR_UNSPECIFIED(&connp->conn_laddr_v6)) {
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
 *
 * If zoneid is ALL_ZONES, then the search rules described in the "Connection
 * Lookup" comment block are applied.  Labels are also checked as described
 * above.  If the packet is from the inside (looped back), and is from the same
 * zone, then label checks are omitted.
 */
conn_t *
ipcl_classify_v4(mblk_t *mp, uint8_t protocol, uint_t hdr_len,
    ip_recv_attr_t *ira, ip_stack_t *ipst)
{
	ipha_t	*ipha;
	connf_t	*connfp, *bind_connfp;
	uint16_t lport;
	uint16_t fport;
	uint32_t ports;
	conn_t	*connp;
	uint16_t  *up;
	zoneid_t	zoneid = ira->ira_zoneid;

	ipha = (ipha_t *)mp->b_rptr;
	up = (uint16_t *)((uchar_t *)ipha + hdr_len + TCP_PORTS_OFFSET);

	switch (protocol) {
	case IPPROTO_TCP:
		ports = *(uint32_t *)up;
		connfp =
		    &ipst->ips_ipcl_conn_fanout[IPCL_CONN_HASH(ipha->ipha_src,
		    ports, ipst)];
		mutex_enter(&connfp->connf_lock);
		for (connp = connfp->connf_head; connp != NULL;
		    connp = connp->conn_next) {
			if (IPCL_CONN_MATCH(connp, protocol,
			    ipha->ipha_src, ipha->ipha_dst, ports) &&
			    (connp->conn_zoneid == zoneid ||
			    connp->conn_allzones ||
			    ((connp->conn_mac_mode != CONN_MAC_DEFAULT) &&
			    (ira->ira_flags & IRAF_TX_MAC_EXEMPTABLE) &&
			    (ira->ira_flags & IRAF_TX_SHARED_ADDR))))
				break;
		}

		if (connp != NULL) {
			/*
			 * We have a fully-bound TCP connection.
			 *
			 * For labeled systems, there's no need to check the
			 * label here.  It's known to be good as we checked
			 * before allowing the connection to become bound.
			 */
			CONN_INC_REF(connp);
			mutex_exit(&connfp->connf_lock);
			return (connp);
		}

		mutex_exit(&connfp->connf_lock);
		lport = up[1];
		bind_connfp =
		    &ipst->ips_ipcl_bind_fanout[IPCL_BIND_HASH(lport, ipst)];
		mutex_enter(&bind_connfp->connf_lock);
		for (connp = bind_connfp->connf_head; connp != NULL;
		    connp = connp->conn_next) {
			if (IPCL_BIND_MATCH(connp, protocol, ipha->ipha_dst,
			    lport) &&
			    (connp->conn_zoneid == zoneid ||
			    connp->conn_allzones ||
			    ((connp->conn_mac_mode != CONN_MAC_DEFAULT) &&
			    (ira->ira_flags & IRAF_TX_MAC_EXEMPTABLE) &&
			    (ira->ira_flags & IRAF_TX_SHARED_ADDR))))
				break;
		}

		/*
		 * If the matching connection is SLP on a private address, then
		 * the label on the packet must match the local zone's label.
		 * Otherwise, it must be in the label range defined by tnrh.
		 * This is ensured by tsol_receive_local.
		 *
		 * Note that we don't check tsol_receive_local for
		 * the connected case.
		 */
		if (connp != NULL && (ira->ira_flags & IRAF_SYSTEM_LABELED) &&
		    !tsol_receive_local(mp, &ipha->ipha_dst, IPV4_VERSION,
		    ira, connp)) {
			DTRACE_PROBE3(tx__ip__log__info__classify__tcp,
			    char *, "connp(1) could not receive mp(2)",
			    conn_t *, connp, mblk_t *, mp);
			connp = NULL;
		}

		if (connp != NULL) {
			/* Have a listener at least */
			CONN_INC_REF(connp);
			mutex_exit(&bind_connfp->connf_lock);
			return (connp);
		}

		mutex_exit(&bind_connfp->connf_lock);
		break;

	case IPPROTO_UDP:
		lport = up[1];
		fport = up[0];
		connfp = &ipst->ips_ipcl_udp_fanout[IPCL_UDP_HASH(lport, ipst)];
		mutex_enter(&connfp->connf_lock);
		for (connp = connfp->connf_head; connp != NULL;
		    connp = connp->conn_next) {
			if (IPCL_UDP_MATCH(connp, lport, ipha->ipha_dst,
			    fport, ipha->ipha_src) &&
			    (connp->conn_zoneid == zoneid ||
			    connp->conn_allzones ||
			    ((connp->conn_mac_mode != CONN_MAC_DEFAULT) &&
			    (ira->ira_flags & IRAF_TX_MAC_EXEMPTABLE))))
				break;
		}

		if (connp != NULL && (ira->ira_flags & IRAF_SYSTEM_LABELED) &&
		    !tsol_receive_local(mp, &ipha->ipha_dst, IPV4_VERSION,
		    ira, connp)) {
			DTRACE_PROBE3(tx__ip__log__info__classify__udp,
			    char *, "connp(1) could not receive mp(2)",
			    conn_t *, connp, mblk_t *, mp);
			connp = NULL;
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

		break;

	case IPPROTO_ENCAP:
	case IPPROTO_IPV6:
		return (ipcl_iptun_classify_v4(&ipha->ipha_src,
		    &ipha->ipha_dst, ipst));
	}

	return (NULL);
}

conn_t *
ipcl_classify_v6(mblk_t *mp, uint8_t protocol, uint_t hdr_len,
    ip_recv_attr_t *ira, ip_stack_t *ipst)
{
	ip6_t		*ip6h;
	connf_t		*connfp, *bind_connfp;
	uint16_t	lport;
	uint16_t	fport;
	tcpha_t		*tcpha;
	uint32_t	ports;
	conn_t		*connp;
	uint16_t	*up;
	zoneid_t	zoneid = ira->ira_zoneid;

	ip6h = (ip6_t *)mp->b_rptr;

	switch (protocol) {
	case IPPROTO_TCP:
		tcpha = (tcpha_t *)&mp->b_rptr[hdr_len];
		up = &tcpha->tha_lport;
		ports = *(uint32_t *)up;

		connfp =
		    &ipst->ips_ipcl_conn_fanout[IPCL_CONN_HASH_V6(ip6h->ip6_src,
		    ports, ipst)];
		mutex_enter(&connfp->connf_lock);
		for (connp = connfp->connf_head; connp != NULL;
		    connp = connp->conn_next) {
			if (IPCL_CONN_MATCH_V6(connp, protocol,
			    ip6h->ip6_src, ip6h->ip6_dst, ports) &&
			    (connp->conn_zoneid == zoneid ||
			    connp->conn_allzones ||
			    ((connp->conn_mac_mode != CONN_MAC_DEFAULT) &&
			    (ira->ira_flags & IRAF_TX_MAC_EXEMPTABLE) &&
			    (ira->ira_flags & IRAF_TX_SHARED_ADDR))))
				break;
		}

		if (connp != NULL) {
			/*
			 * We have a fully-bound TCP connection.
			 *
			 * For labeled systems, there's no need to check the
			 * label here.  It's known to be good as we checked
			 * before allowing the connection to become bound.
			 */
			CONN_INC_REF(connp);
			mutex_exit(&connfp->connf_lock);
			return (connp);
		}

		mutex_exit(&connfp->connf_lock);

		lport = up[1];
		bind_connfp =
		    &ipst->ips_ipcl_bind_fanout[IPCL_BIND_HASH(lport, ipst)];
		mutex_enter(&bind_connfp->connf_lock);
		for (connp = bind_connfp->connf_head; connp != NULL;
		    connp = connp->conn_next) {
			if (IPCL_BIND_MATCH_V6(connp, protocol,
			    ip6h->ip6_dst, lport) &&
			    (connp->conn_zoneid == zoneid ||
			    connp->conn_allzones ||
			    ((connp->conn_mac_mode != CONN_MAC_DEFAULT) &&
			    (ira->ira_flags & IRAF_TX_MAC_EXEMPTABLE) &&
			    (ira->ira_flags & IRAF_TX_SHARED_ADDR))))
				break;
		}

		if (connp != NULL && (ira->ira_flags & IRAF_SYSTEM_LABELED) &&
		    !tsol_receive_local(mp, &ip6h->ip6_dst, IPV6_VERSION,
		    ira, connp)) {
			DTRACE_PROBE3(tx__ip__log__info__classify__tcp6,
			    char *, "connp(1) could not receive mp(2)",
			    conn_t *, connp, mblk_t *, mp);
			connp = NULL;
		}

		if (connp != NULL) {
			/* Have a listner at least */
			CONN_INC_REF(connp);
			mutex_exit(&bind_connfp->connf_lock);
			return (connp);
		}

		mutex_exit(&bind_connfp->connf_lock);
		break;

	case IPPROTO_UDP:
		up = (uint16_t *)&mp->b_rptr[hdr_len];
		lport = up[1];
		fport = up[0];
		connfp = &ipst->ips_ipcl_udp_fanout[IPCL_UDP_HASH(lport, ipst)];
		mutex_enter(&connfp->connf_lock);
		for (connp = connfp->connf_head; connp != NULL;
		    connp = connp->conn_next) {
			if (IPCL_UDP_MATCH_V6(connp, lport, ip6h->ip6_dst,
			    fport, ip6h->ip6_src) &&
			    (connp->conn_zoneid == zoneid ||
			    connp->conn_allzones ||
			    ((connp->conn_mac_mode != CONN_MAC_DEFAULT) &&
			    (ira->ira_flags & IRAF_TX_MAC_EXEMPTABLE) &&
			    (ira->ira_flags & IRAF_TX_SHARED_ADDR))))
				break;
		}

		if (connp != NULL && (ira->ira_flags & IRAF_SYSTEM_LABELED) &&
		    !tsol_receive_local(mp, &ip6h->ip6_dst, IPV6_VERSION,
		    ira, connp)) {
			DTRACE_PROBE3(tx__ip__log__info__classify__udp6,
			    char *, "connp(1) could not receive mp(2)",
			    conn_t *, connp, mblk_t *, mp);
			connp = NULL;
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
		break;
	case IPPROTO_ENCAP:
	case IPPROTO_IPV6:
		return (ipcl_iptun_classify_v6(&ip6h->ip6_src,
		    &ip6h->ip6_dst, ipst));
	}

	return (NULL);
}

/*
 * wrapper around ipcl_classify_(v4,v6) routines.
 */
conn_t *
ipcl_classify(mblk_t *mp, ip_recv_attr_t *ira, ip_stack_t *ipst)
{
	if (ira->ira_flags & IRAF_IS_IPV4) {
		return (ipcl_classify_v4(mp, ira->ira_protocol,
		    ira->ira_ip_hdr_length, ira, ipst));
	} else {
		return (ipcl_classify_v6(mp, ira->ira_protocol,
		    ira->ira_ip_hdr_length, ira, ipst));
	}
}

/*
 * Only used to classify SCTP RAW sockets
 */
conn_t *
ipcl_classify_raw(mblk_t *mp, uint8_t protocol, uint32_t ports,
    ipha_t *ipha, ip6_t *ip6h, ip_recv_attr_t *ira, ip_stack_t *ipst)
{
	connf_t		*connfp;
	conn_t		*connp;
	in_port_t	lport;
	int		ipversion;
	const void	*dst;
	zoneid_t	zoneid = ira->ira_zoneid;

	lport = ((uint16_t *)&ports)[1];
	if (ira->ira_flags & IRAF_IS_IPV4) {
		dst = (const void *)&ipha->ipha_dst;
		ipversion = IPV4_VERSION;
	} else {
		dst = (const void *)&ip6h->ip6_dst;
		ipversion = IPV6_VERSION;
	}

	connfp = &ipst->ips_ipcl_raw_fanout[IPCL_RAW_HASH(ntohs(lport), ipst)];
	mutex_enter(&connfp->connf_lock);
	for (connp = connfp->connf_head; connp != NULL;
	    connp = connp->conn_next) {
		/* We don't allow v4 fallback for v6 raw socket. */
		if (ipversion != connp->conn_ipversion)
			continue;
		if (!IN6_IS_ADDR_UNSPECIFIED(&connp->conn_faddr_v6) &&
		    !IN6_IS_ADDR_V4MAPPED_ANY(&connp->conn_faddr_v6)) {
			if (ipversion == IPV4_VERSION) {
				if (!IPCL_CONN_MATCH(connp, protocol,
				    ipha->ipha_src, ipha->ipha_dst, ports))
					continue;
			} else {
				if (!IPCL_CONN_MATCH_V6(connp, protocol,
				    ip6h->ip6_src, ip6h->ip6_dst, ports))
					continue;
			}
		} else {
			if (ipversion == IPV4_VERSION) {
				if (!IPCL_BIND_MATCH(connp, protocol,
				    ipha->ipha_dst, lport))
					continue;
			} else {
				if (!IPCL_BIND_MATCH_V6(connp, protocol,
				    ip6h->ip6_dst, lport))
					continue;
			}
		}

		if (connp->conn_zoneid == zoneid ||
		    connp->conn_allzones ||
		    ((connp->conn_mac_mode != CONN_MAC_DEFAULT) &&
		    (ira->ira_flags & IRAF_TX_MAC_EXEMPTABLE) &&
		    (ira->ira_flags & IRAF_TX_SHARED_ADDR)))
			break;
	}

	if (connp != NULL && (ira->ira_flags & IRAF_SYSTEM_LABELED) &&
	    !tsol_receive_local(mp, dst, ipversion, ira, connp)) {
		DTRACE_PROBE3(tx__ip__log__info__classify__rawip,
		    char *, "connp(1) could not receive mp(2)",
		    conn_t *, connp, mblk_t *, mp);
		connp = NULL;
	}

	if (connp != NULL)
		goto found;
	mutex_exit(&connfp->connf_lock);

	/* Try to look for a wildcard SCTP RAW socket match. */
	connfp = &ipst->ips_ipcl_raw_fanout[IPCL_RAW_HASH(0, ipst)];
	mutex_enter(&connfp->connf_lock);
	for (connp = connfp->connf_head; connp != NULL;
	    connp = connp->conn_next) {
		/* We don't allow v4 fallback for v6 raw socket. */
		if (ipversion != connp->conn_ipversion)
			continue;
		if (!IPCL_ZONE_MATCH(connp, zoneid))
			continue;

		if (ipversion == IPV4_VERSION) {
			if (IPCL_RAW_MATCH(connp, protocol, ipha->ipha_dst))
				break;
		} else {
			if (IPCL_RAW_MATCH_V6(connp, protocol, ip6h->ip6_dst)) {
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
tcp_conn_constructor(void *buf, void *cdrarg, int kmflags)
{
	itc_t	*itc = (itc_t *)buf;
	conn_t 	*connp = &itc->itc_conn;
	tcp_t	*tcp = (tcp_t *)&itc[1];

	bzero(connp, sizeof (conn_t));
	bzero(tcp, sizeof (tcp_t));

	mutex_init(&connp->conn_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&connp->conn_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&connp->conn_sq_cv, NULL, CV_DEFAULT, NULL);
	tcp->tcp_timercache = tcp_timermp_alloc(kmflags);
	if (tcp->tcp_timercache == NULL)
		return (ENOMEM);
	connp->conn_tcp = tcp;
	connp->conn_flags = IPCL_TCPCONN;
	connp->conn_proto = IPPROTO_TCP;
	tcp->tcp_connp = connp;
	rw_init(&connp->conn_ilg_lock, NULL, RW_DEFAULT, NULL);

	connp->conn_ixa = kmem_zalloc(sizeof (ip_xmit_attr_t), kmflags);
	if (connp->conn_ixa == NULL) {
		tcp_timermp_free(tcp);
		return (ENOMEM);
	}
	connp->conn_ixa->ixa_refcnt = 1;
	connp->conn_ixa->ixa_protocol = connp->conn_proto;
	connp->conn_ixa->ixa_xmit_hint = CONN_TO_XMIT_HINT(connp);
	return (0);
}

/* ARGSUSED */
static void
tcp_conn_destructor(void *buf, void *cdrarg)
{
	itc_t	*itc = (itc_t *)buf;
	conn_t 	*connp = &itc->itc_conn;
	tcp_t	*tcp = (tcp_t *)&itc[1];

	ASSERT(connp->conn_flags & IPCL_TCPCONN);
	ASSERT(tcp->tcp_connp == connp);
	ASSERT(connp->conn_tcp == tcp);
	tcp_timermp_free(tcp);
	mutex_destroy(&connp->conn_lock);
	cv_destroy(&connp->conn_cv);
	cv_destroy(&connp->conn_sq_cv);
	rw_destroy(&connp->conn_ilg_lock);

	/* Can be NULL if constructor failed */
	if (connp->conn_ixa != NULL) {
		ASSERT(connp->conn_ixa->ixa_refcnt == 1);
		ASSERT(connp->conn_ixa->ixa_ire == NULL);
		ASSERT(connp->conn_ixa->ixa_nce == NULL);
		ixa_refrele(connp->conn_ixa);
	}
}

/* ARGSUSED */
static int
ip_conn_constructor(void *buf, void *cdrarg, int kmflags)
{
	itc_t	*itc = (itc_t *)buf;
	conn_t 	*connp = &itc->itc_conn;

	bzero(connp, sizeof (conn_t));
	mutex_init(&connp->conn_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&connp->conn_cv, NULL, CV_DEFAULT, NULL);
	connp->conn_flags = IPCL_IPCCONN;
	rw_init(&connp->conn_ilg_lock, NULL, RW_DEFAULT, NULL);

	connp->conn_ixa = kmem_zalloc(sizeof (ip_xmit_attr_t), kmflags);
	if (connp->conn_ixa == NULL)
		return (ENOMEM);
	connp->conn_ixa->ixa_refcnt = 1;
	connp->conn_ixa->ixa_xmit_hint = CONN_TO_XMIT_HINT(connp);
	return (0);
}

/* ARGSUSED */
static void
ip_conn_destructor(void *buf, void *cdrarg)
{
	itc_t	*itc = (itc_t *)buf;
	conn_t 	*connp = &itc->itc_conn;

	ASSERT(connp->conn_flags & IPCL_IPCCONN);
	ASSERT(connp->conn_priv == NULL);
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

/* ARGSUSED */
static int
udp_conn_constructor(void *buf, void *cdrarg, int kmflags)
{
	itc_t	*itc = (itc_t *)buf;
	conn_t 	*connp = &itc->itc_conn;
	udp_t	*udp = (udp_t *)&itc[1];

	bzero(connp, sizeof (conn_t));
	bzero(udp, sizeof (udp_t));

	mutex_init(&connp->conn_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&connp->conn_cv, NULL, CV_DEFAULT, NULL);
	connp->conn_udp = udp;
	connp->conn_flags = IPCL_UDPCONN;
	connp->conn_proto = IPPROTO_UDP;
	udp->udp_connp = connp;
	rw_init(&connp->conn_ilg_lock, NULL, RW_DEFAULT, NULL);
	connp->conn_ixa = kmem_zalloc(sizeof (ip_xmit_attr_t), kmflags);
	if (connp->conn_ixa == NULL)
		return (ENOMEM);
	connp->conn_ixa->ixa_refcnt = 1;
	connp->conn_ixa->ixa_protocol = connp->conn_proto;
	connp->conn_ixa->ixa_xmit_hint = CONN_TO_XMIT_HINT(connp);
	return (0);
}

/* ARGSUSED */
static void
udp_conn_destructor(void *buf, void *cdrarg)
{
	itc_t	*itc = (itc_t *)buf;
	conn_t 	*connp = &itc->itc_conn;
	udp_t	*udp = (udp_t *)&itc[1];

	ASSERT(connp->conn_flags & IPCL_UDPCONN);
	ASSERT(udp->udp_connp == connp);
	ASSERT(connp->conn_udp == udp);
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

/* ARGSUSED */
static int
rawip_conn_constructor(void *buf, void *cdrarg, int kmflags)
{
	itc_t	*itc = (itc_t *)buf;
	conn_t 	*connp = &itc->itc_conn;
	icmp_t	*icmp = (icmp_t *)&itc[1];

	bzero(connp, sizeof (conn_t));
	bzero(icmp, sizeof (icmp_t));

	mutex_init(&connp->conn_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&connp->conn_cv, NULL, CV_DEFAULT, NULL);
	connp->conn_icmp = icmp;
	connp->conn_flags = IPCL_RAWIPCONN;
	connp->conn_proto = IPPROTO_ICMP;
	icmp->icmp_connp = connp;
	rw_init(&connp->conn_ilg_lock, NULL, RW_DEFAULT, NULL);
	connp->conn_ixa = kmem_zalloc(sizeof (ip_xmit_attr_t), kmflags);
	if (connp->conn_ixa == NULL)
		return (ENOMEM);
	connp->conn_ixa->ixa_refcnt = 1;
	connp->conn_ixa->ixa_protocol = connp->conn_proto;
	connp->conn_ixa->ixa_xmit_hint = CONN_TO_XMIT_HINT(connp);
	return (0);
}

/* ARGSUSED */
static void
rawip_conn_destructor(void *buf, void *cdrarg)
{
	itc_t	*itc = (itc_t *)buf;
	conn_t 	*connp = &itc->itc_conn;
	icmp_t	*icmp = (icmp_t *)&itc[1];

	ASSERT(connp->conn_flags & IPCL_RAWIPCONN);
	ASSERT(icmp->icmp_connp == connp);
	ASSERT(connp->conn_icmp == icmp);
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

/* ARGSUSED */
static int
rts_conn_constructor(void *buf, void *cdrarg, int kmflags)
{
	itc_t	*itc = (itc_t *)buf;
	conn_t 	*connp = &itc->itc_conn;
	rts_t	*rts = (rts_t *)&itc[1];

	bzero(connp, sizeof (conn_t));
	bzero(rts, sizeof (rts_t));

	mutex_init(&connp->conn_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&connp->conn_cv, NULL, CV_DEFAULT, NULL);
	connp->conn_rts = rts;
	connp->conn_flags = IPCL_RTSCONN;
	rts->rts_connp = connp;
	rw_init(&connp->conn_ilg_lock, NULL, RW_DEFAULT, NULL);
	connp->conn_ixa = kmem_zalloc(sizeof (ip_xmit_attr_t), kmflags);
	if (connp->conn_ixa == NULL)
		return (ENOMEM);
	connp->conn_ixa->ixa_refcnt = 1;
	connp->conn_ixa->ixa_xmit_hint = CONN_TO_XMIT_HINT(connp);
	return (0);
}

/* ARGSUSED */
static void
rts_conn_destructor(void *buf, void *cdrarg)
{
	itc_t	*itc = (itc_t *)buf;
	conn_t 	*connp = &itc->itc_conn;
	rts_t	*rts = (rts_t *)&itc[1];

	ASSERT(connp->conn_flags & IPCL_RTSCONN);
	ASSERT(rts->rts_connp == connp);
	ASSERT(connp->conn_rts == rts);
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

/*
 * Called as part of ipcl_conn_destroy to assert and clear any pointers
 * in the conn_t.
 *
 * Below we list all the pointers in the conn_t as a documentation aid.
 * The ones that we can not ASSERT to be NULL are #ifdef'ed out.
 * If you add any pointers to the conn_t please add an ASSERT here
 * and #ifdef it out if it can't be actually asserted to be NULL.
 * In any case, we bzero most of the conn_t at the end of the function.
 */
void
ipcl_conn_cleanup(conn_t *connp)
{
	ip_xmit_attr_t	*ixa;

	ASSERT(connp->conn_latch == NULL);
	ASSERT(connp->conn_latch_in_policy == NULL);
	ASSERT(connp->conn_latch_in_action == NULL);
#ifdef notdef
	ASSERT(connp->conn_rq == NULL);
	ASSERT(connp->conn_wq == NULL);
#endif
	ASSERT(connp->conn_cred == NULL);
	ASSERT(connp->conn_g_fanout == NULL);
	ASSERT(connp->conn_g_next == NULL);
	ASSERT(connp->conn_g_prev == NULL);
	ASSERT(connp->conn_policy == NULL);
	ASSERT(connp->conn_fanout == NULL);
	ASSERT(connp->conn_next == NULL);
	ASSERT(connp->conn_prev == NULL);
	ASSERT(connp->conn_oper_pending_ill == NULL);
	ASSERT(connp->conn_ilg == NULL);
	ASSERT(connp->conn_drain_next == NULL);
	ASSERT(connp->conn_drain_prev == NULL);
#ifdef notdef
	/* conn_idl is not cleared when removed from idl list */
	ASSERT(connp->conn_idl == NULL);
#endif
	ASSERT(connp->conn_ipsec_opt_mp == NULL);
#ifdef notdef
	/* conn_netstack is cleared by the caller; needed by ixa_cleanup */
	ASSERT(connp->conn_netstack == NULL);
#endif

	ASSERT(connp->conn_helper_info == NULL);
	ASSERT(connp->conn_ixa != NULL);
	ixa = connp->conn_ixa;
	ASSERT(ixa->ixa_refcnt == 1);
	/* Need to preserve ixa_protocol */
	ixa_cleanup(ixa);
	ixa->ixa_flags = 0;

	/* Clear out the conn_t fields that are not preserved */
	bzero(&connp->conn_start_clr,
	    sizeof (conn_t) -
	    ((uchar_t *)&connp->conn_start_clr - (uchar_t *)connp));
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
	struct connf_s	*connfp;
	ip_stack_t	*ipst = connp->conn_netstack->netstack_ip;

	/*
	 * No need for atomic here. Approximate even distribution
	 * in the global lists is sufficient.
	 */
	ipst->ips_conn_g_index++;
	index = ipst->ips_conn_g_index & (CONN_G_HASH_SIZE - 1);

	connp->conn_g_prev = NULL;
	/*
	 * Mark as INCIPIENT, so that walkers will ignore this
	 * for now, till ip_open is ready to make it visible globally.
	 */
	connp->conn_state_flags |= CONN_INCIPIENT;

	connfp = &ipst->ips_ipcl_globalhash_fanout[index];
	/* Insert at the head of the list */
	mutex_enter(&connfp->connf_lock);
	connp->conn_g_next = connfp->connf_head;
	if (connp->conn_g_next != NULL)
		connp->conn_g_next->conn_g_prev = connp;
	connfp->connf_head = connp;

	/* The fanout bucket this conn points to */
	connp->conn_g_fanout = connfp;

	mutex_exit(&connfp->connf_lock);
}

void
ipcl_globalhash_remove(conn_t *connp)
{
	struct connf_s	*connfp;

	/*
	 * We were never inserted in the global multi list.
	 * IPCL_NONE variety is never inserted in the global multilist
	 * since it is presumed to not need any cleanup and is transient.
	 */
	if (connp->conn_g_fanout == NULL)
		return;

	connfp = connp->conn_g_fanout;
	mutex_enter(&connfp->connf_lock);
	if (connp->conn_g_prev != NULL)
		connp->conn_g_prev->conn_g_next = connp->conn_g_next;
	else
		connfp->connf_head = connp->conn_g_next;
	if (connp->conn_g_next != NULL)
		connp->conn_g_next->conn_g_prev = connp->conn_g_prev;
	mutex_exit(&connfp->connf_lock);

	/* Better to stumble on a null pointer than to corrupt memory */
	connp->conn_g_next = NULL;
	connp->conn_g_prev = NULL;
	connp->conn_g_fanout = NULL;
}

/*
 * Walk the list of all conn_t's in the system, calling the function provided
 * With the specified argument for each.
 * Applies to both IPv4 and IPv6.
 *
 * CONNs may hold pointers to ills (conn_dhcpinit_ill and
 * conn_oper_pending_ill). To guard against stale pointers
 * ipcl_walk() is called to cleanup the conn_t's, typically when an interface is
 * unplumbed or removed. New conn_t's that are created while we are walking
 * may be missed by this walk, because they are not necessarily inserted
 * at the tail of the list. They are new conn_t's and thus don't have any
 * stale pointers. The CONN_CLOSING flag ensures that no new reference
 * is created to the struct that is going away.
 */
void
ipcl_walk(pfv_t func, void *arg, ip_stack_t *ipst)
{
	int	i;
	conn_t	*connp;
	conn_t	*prev_connp;

	for (i = 0; i < CONN_G_HASH_SIZE; i++) {
		mutex_enter(&ipst->ips_ipcl_globalhash_fanout[i].connf_lock);
		prev_connp = NULL;
		connp = ipst->ips_ipcl_globalhash_fanout[i].connf_head;
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
			mutex_exit(
			    &ipst->ips_ipcl_globalhash_fanout[i].connf_lock);
			(*func)(connp, arg);
			if (prev_connp != NULL)
				CONN_DEC_REF(prev_connp);
			mutex_enter(
			    &ipst->ips_ipcl_globalhash_fanout[i].connf_lock);
			prev_connp = connp;
			connp = connp->conn_g_next;
		}
		mutex_exit(&ipst->ips_ipcl_globalhash_fanout[i].connf_lock);
		if (prev_connp != NULL)
			CONN_DEC_REF(prev_connp);
	}
}

/*
 * Search for a peer TCP/IPv4 loopback conn by doing a reverse lookup on
 * the {src, dst, lport, fport} quadruplet.  Returns with conn reference
 * held; caller must call CONN_DEC_REF.  Only checks for connected entries
 * (peer tcp in ESTABLISHED state).
 */
conn_t *
ipcl_conn_tcp_lookup_reversed_ipv4(conn_t *connp, ipha_t *ipha, tcpha_t *tcpha,
    ip_stack_t *ipst)
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

	pports[0] = tcpha->tha_fport;
	pports[1] = tcpha->tha_lport;

	connfp = &ipst->ips_ipcl_conn_fanout[IPCL_CONN_HASH(ipha->ipha_dst,
	    ports, ipst)];

	mutex_enter(&connfp->connf_lock);
	for (tconnp = connfp->connf_head; tconnp != NULL;
	    tconnp = tconnp->conn_next) {

		if (IPCL_CONN_MATCH(tconnp, IPPROTO_TCP,
		    ipha->ipha_dst, ipha->ipha_src, ports) &&
		    tconnp->conn_tcp->tcp_state == TCPS_ESTABLISHED &&
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
 * (peer tcp in ESTABLISHED state).
 */
conn_t *
ipcl_conn_tcp_lookup_reversed_ipv6(conn_t *connp, ip6_t *ip6h, tcpha_t *tcpha,
    ip_stack_t *ipst)
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

	pports[0] = tcpha->tha_fport;
	pports[1] = tcpha->tha_lport;

	connfp = &ipst->ips_ipcl_conn_fanout[IPCL_CONN_HASH_V6(ip6h->ip6_dst,
	    ports, ipst)];

	mutex_enter(&connfp->connf_lock);
	for (tconnp = connfp->connf_head; tconnp != NULL;
	    tconnp = tconnp->conn_next) {

		/* We skip conn_bound_if check here as this is loopback tcp */
		if (IPCL_CONN_MATCH_V6(tconnp, IPPROTO_TCP,
		    ip6h->ip6_dst, ip6h->ip6_src, ports) &&
		    tconnp->conn_tcp->tcp_state == TCPS_ESTABLISHED &&
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
ipcl_tcp_lookup_reversed_ipv4(ipha_t *ipha, tcpha_t *tcpha, int min_state,
    ip_stack_t *ipst)
{
	uint32_t ports;
	uint16_t *pports;
	connf_t	*connfp;
	conn_t	*tconnp;

	pports = (uint16_t *)&ports;
	pports[0] = tcpha->tha_fport;
	pports[1] = tcpha->tha_lport;

	connfp = &ipst->ips_ipcl_conn_fanout[IPCL_CONN_HASH(ipha->ipha_dst,
	    ports, ipst)];

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
    uint_t ifindex, ip_stack_t *ipst)
{
	tcp_t	*tcp;
	uint32_t ports;
	uint16_t *pports;
	connf_t	*connfp;
	conn_t	*tconnp;

	pports = (uint16_t *)&ports;
	pports[0] = tcpha->tha_fport;
	pports[1] = tcpha->tha_lport;

	connfp = &ipst->ips_ipcl_conn_fanout[IPCL_CONN_HASH_V6(ip6h->ip6_dst,
	    ports, ipst)];

	mutex_enter(&connfp->connf_lock);
	for (tconnp = connfp->connf_head; tconnp != NULL;
	    tconnp = tconnp->conn_next) {

		tcp = tconnp->conn_tcp;
		if (IPCL_CONN_MATCH_V6(tconnp, IPPROTO_TCP,
		    ip6h->ip6_dst, ip6h->ip6_src, ports) &&
		    tcp->tcp_state >= min_state &&
		    (tconnp->conn_bound_if == 0 ||
		    tconnp->conn_bound_if == ifindex)) {

			CONN_INC_REF(tconnp);
			mutex_exit(&connfp->connf_lock);
			return (tconnp);
		}
	}
	mutex_exit(&connfp->connf_lock);
	return (NULL);
}

/*
 * Finds a TCP/IPv4 listening connection; called by tcp_disconnect to locate
 * a listener when changing state.
 */
conn_t *
ipcl_lookup_listener_v4(uint16_t lport, ipaddr_t laddr, zoneid_t zoneid,
    ip_stack_t *ipst)
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

	ASSERT(zoneid != ALL_ZONES);

	bind_connfp = &ipst->ips_ipcl_bind_fanout[IPCL_BIND_HASH(lport, ipst)];
	mutex_enter(&bind_connfp->connf_lock);
	for (connp = bind_connfp->connf_head; connp != NULL;
	    connp = connp->conn_next) {
		tcp = connp->conn_tcp;
		if (IPCL_BIND_MATCH(connp, IPPROTO_TCP, laddr, lport) &&
		    IPCL_ZONE_MATCH(connp, zoneid) &&
		    (tcp->tcp_listener == NULL)) {
			CONN_INC_REF(connp);
			mutex_exit(&bind_connfp->connf_lock);
			return (connp);
		}
	}
	mutex_exit(&bind_connfp->connf_lock);
	return (NULL);
}

/*
 * Finds a TCP/IPv6 listening connection; called by tcp_disconnect to locate
 * a listener when changing state.
 */
conn_t *
ipcl_lookup_listener_v6(uint16_t lport, in6_addr_t *laddr, uint_t ifindex,
    zoneid_t zoneid, ip_stack_t *ipst)
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

	ASSERT(zoneid != ALL_ZONES);

	bind_connfp = &ipst->ips_ipcl_bind_fanout[IPCL_BIND_HASH(lport, ipst)];
	mutex_enter(&bind_connfp->connf_lock);
	for (connp = bind_connfp->connf_head; connp != NULL;
	    connp = connp->conn_next) {
		tcp = connp->conn_tcp;
		if (IPCL_BIND_MATCH_V6(connp, IPPROTO_TCP, *laddr, lport) &&
		    IPCL_ZONE_MATCH(connp, zoneid) &&
		    (connp->conn_bound_if == 0 ||
		    connp->conn_bound_if == ifindex) &&
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
	ctb->ctb_depth = getpcstack(ctb->ctb_stack, CONN_STACK_DEPTH);
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
	ctb->ctb_depth = getpcstack(ctb->ctb_stack, CONN_STACK_DEPTH);
	connp->conn_trace_last = last;
	return (1);
}
#endif
