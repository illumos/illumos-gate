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
#include <sys/multidata.h>
#include <sys/multidata_impl.h>
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
#include <sys/sodirect.h>
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
#include <inet/nd.h>
#include <inet/optcom.h>
#include <inet/snmpcom.h>
#include <inet/kstatcom.h>
#include <inet/tcp.h>
#include <inet/tcp_impl.h>
#include <net/pfkeyv2.h>
#include <inet/ipsec_info.h>
#include <inet/ipdrop.h>

#include <inet/ipclassifier.h>
#include <inet/ip_ire.h>
#include <inet/ip_ftable.h>
#include <inet/ip_if.h>
#include <inet/ipp_common.h>
#include <inet/ip_netinfo.h>
#include <sys/squeue_impl.h>
#include <sys/squeue.h>
#include <inet/kssl/ksslapi.h>
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
 * IPCL_CONNTCP as a flag. We use 'conn_ref' and 'conn_lock' to protect
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
 * top of tcp_conn_request(). But briefly, the squeue is picked by
 * ip_tcp_input()/ip_fanout_tcp_v6() based on the interrupted CPU.
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
 * We make special provision for (AF_INET, SOCK_STREAM) sockets which
 * can't have 'ipv6_recvpktinfo' set and for these type of sockets, IP
 * will never send a M_CTL to TCP. As such, ip_tcp_input() which handles
 * all TCP packets from the wire makes a IPCL_IS_TCP4_CONNECTED_NO_POLICY
 * check to send packets directly to tcp_rput_data via squeue. Everyone
 * else comes through tcp_input() on the read side.
 *
 * We also make special provisions for sockfs by marking tcp_issocket
 * whenever we have only sockfs on top of TCP. This allows us to skip
 * putting the tcp in acceptor hash since a sockfs listener can never
 * become acceptor and also avoid allocating a tcp_t for acceptor STREAM
 * since eager has already been allocated and the accept now happens
 * on acceptor STREAM. There is a big blob of comment on top of
 * tcp_conn_request explaining the new accept. When socket is POP'd,
 * sockfs sends us an ioctl to mark the fact and we go back to old
 * behaviour. Once tcp_issocket is unset, its never set for the
 * life of that connection.
 *
 * In support of on-board asynchronous DMA hardware (e.g. Intel I/OAT)
 * two consoldiation private KAPIs are used to enqueue M_DATA mblk_t's
 * directly to the socket (sodirect) and start an asynchronous copyout
 * to a user-land receive-side buffer (uioa) when a blocking socket read
 * (e.g. read, recv, ...) is pending.
 *
 * This is accomplished when tcp_issocket is set and tcp_sodirect is not
 * NULL so points to an sodirect_t and if marked enabled then we enqueue
 * all mblk_t's directly to the socket.
 *
 * Further, if the sodirect_t sod_uioa and if marked enabled (due to a
 * blocking socket read, e.g. user-land read, recv, ...) then an asynchronous
 * copyout will be started directly to the user-land uio buffer. Also, as we
 * have a pending read, TCP's push logic can take into account the number of
 * bytes to be received and only awake the blocked read()er when the uioa_t
 * byte count has been satisfied.
 *
 * IPsec notes :
 *
 * Since a packet is always executed on the correct TCP perimeter
 * all IPsec processing is defered to IP including checking new
 * connections and setting IPSEC policies for new connection. The
 * only exception is tcp_xmit_listeners_reset() which is called
 * directly from IP and needs to policy check to see if TH_RST
 * can be sent out.
 *
 * PFHooks notes :
 *
 * For mdt case, one meta buffer contains multiple packets. Mblks for every
 * packet are assembled and passed to the hooks. When packets are blocked,
 * or boundary of any packet is changed, the mdt processing is stopped, and
 * packets of the meta buffer are send to the IP path one by one.
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
 * Macros for sodirect:
 *
 * SOD_PTR_ENTER(tcp, sodp) - for the tcp_t pointer "tcp" set the
 * sodirect_t pointer "sodp" to the socket/tcp shared sodirect_t
 * if it exists and is enabled, else to NULL. Note, in the current
 * sodirect implementation the sod_lockp must not be held across any
 * STREAMS call (e.g. putnext) else a "recursive mutex_enter" PANIC
 * will result as sod_lockp is the streamhead stdata.sd_lock.
 *
 * SOD_NOT_ENABLED(tcp) - return true if not a sodirect tcp_t or the
 * sodirect_t isn't enabled, usefull for ASSERT()ing that a recieve
 * side tcp code path dealing with a tcp_rcv_list or putnext() isn't
 * being used when sodirect code paths should be.
 */

#define	SOD_PTR_ENTER(tcp, sodp)					\
	(sodp) = (tcp)->tcp_sodirect;					\
									\
	if ((sodp) != NULL) {						\
		mutex_enter((sodp)->sod_lockp);				\
		if (!((sodp)->sod_state & SOD_ENABLED)) {		\
			mutex_exit((sodp)->sod_lockp);			\
			(sodp) = NULL;					\
		}							\
	}

#define	SOD_NOT_ENABLED(tcp)						\
	((tcp)->tcp_sodirect == NULL ||					\
	    !((tcp)->tcp_sodirect->sod_state & SOD_ENABLED))

/*
 * This controls how tiny a write must be before we try to copy it
 * into the the mblk on the tail of the transmit queue.  Not much
 * speedup is observed for values larger than sixteen.  Zero will
 * disable the optimisation.
 */
int tcp_tx_pull_len = 16;

/*
 * TCP Statistics.
 *
 * How TCP statistics work.
 *
 * There are two types of statistics invoked by two macros.
 *
 * TCP_STAT(name) does non-atomic increment of a named stat counter. It is
 * supposed to be used in non MT-hot paths of the code.
 *
 * TCP_DBGSTAT(name) does atomic increment of a named stat counter. It is
 * supposed to be used for DEBUG purposes and may be used on a hot path.
 *
 * Both TCP_STAT and TCP_DBGSTAT counters are available using kstat
 * (use "kstat tcp" to get them).
 *
 * There is also additional debugging facility that marks tcp_clean_death()
 * instances and saves them in tcp_t structure. It is triggered by
 * TCP_TAG_CLEAN_DEATH define. Also, there is a global array of counters for
 * tcp_clean_death() calls that counts the number of times each tag was hit. It
 * is triggered by TCP_CLD_COUNTERS define.
 *
 * How to add new counters.
 *
 * 1) Add a field in the tcp_stat structure describing your counter.
 * 2) Add a line in the template in tcp_kstat2_init() with the name
 *    of the counter.
 *
 *    IMPORTANT!! - make sure that both are in sync !!
 * 3) Use either TCP_STAT or TCP_DBGSTAT with the name.
 *
 * Please avoid using private counters which are not kstat-exported.
 *
 * TCP_TAG_CLEAN_DEATH set to 1 enables tagging of tcp_clean_death() instances
 * in tcp_t structure.
 *
 * TCP_MAX_CLEAN_DEATH_TAG is the maximum number of possible clean death tags.
 */

#ifndef TCP_DEBUG_COUNTER
#ifdef DEBUG
#define	TCP_DEBUG_COUNTER 1
#else
#define	TCP_DEBUG_COUNTER 0
#endif
#endif

#define	TCP_CLD_COUNTERS 0

#define	TCP_TAG_CLEAN_DEATH 1
#define	TCP_MAX_CLEAN_DEATH_TAG 32

#ifdef lint
static int _lint_dummy_;
#endif

#if TCP_CLD_COUNTERS
static uint_t tcp_clean_death_stat[TCP_MAX_CLEAN_DEATH_TAG];
#define	TCP_CLD_STAT(x) tcp_clean_death_stat[x]++
#elif defined(lint)
#define	TCP_CLD_STAT(x) ASSERT(_lint_dummy_ == 0);
#else
#define	TCP_CLD_STAT(x)
#endif

#if TCP_DEBUG_COUNTER
#define	TCP_DBGSTAT(tcps, x)	\
	atomic_add_64(&((tcps)->tcps_statistics.x.value.ui64), 1)
#define	TCP_G_DBGSTAT(x)	\
	atomic_add_64(&(tcp_g_statistics.x.value.ui64), 1)
#elif defined(lint)
#define	TCP_DBGSTAT(tcps, x) ASSERT(_lint_dummy_ == 0);
#define	TCP_G_DBGSTAT(x) ASSERT(_lint_dummy_ == 0);
#else
#define	TCP_DBGSTAT(tcps, x)
#define	TCP_G_DBGSTAT(x)
#endif

#define	TCP_G_STAT(x)	(tcp_g_statistics.x.value.ui64++)

tcp_g_stat_t	tcp_g_statistics;
kstat_t		*tcp_g_kstat;

/*
 * Call either ip_output or ip_output_v6. This replaces putnext() calls on the
 * tcp write side.
 */
#define	CALL_IP_WPUT(connp, q, mp) {					\
	ASSERT(((q)->q_flag & QREADR) == 0);				\
	TCP_DBGSTAT(connp->conn_netstack->netstack_tcp, tcp_ip_output);	\
	connp->conn_send(connp, (mp), (q), IP_WPUT);			\
}

/* Macros for timestamp comparisons */
#define	TSTMP_GEQ(a, b)	((int32_t)((a)-(b)) >= 0)
#define	TSTMP_LT(a, b)	((int32_t)((a)-(b)) < 0)

/*
 * Parameters for TCP Initial Send Sequence number (ISS) generation.  When
 * tcp_strong_iss is set to 1, which is the default, the ISS is calculated
 * by adding three components: a time component which grows by 1 every 4096
 * nanoseconds (versus every 4 microseconds suggested by RFC 793, page 27);
 * a per-connection component which grows by 125000 for every new connection;
 * and an "extra" component that grows by a random amount centered
 * approximately on 64000.  This causes the the ISS generator to cycle every
 * 4.89 hours if no TCP connections are made, and faster if connections are
 * made.
 *
 * When tcp_strong_iss is set to 0, ISS is calculated by adding two
 * components: a time component which grows by 250000 every second; and
 * a per-connection component which grows by 125000 for every new connections.
 *
 * A third method, when tcp_strong_iss is set to 2, for generating ISS is
 * prescribed by Steve Bellovin.  This involves adding time, the 125000 per
 * connection, and a one-way hash (MD5) of the connection ID <sport, dport,
 * src, dst>, a "truly" random (per RFC 1750) number, and a console-entered
 * password.
 */
#define	ISS_INCR	250000
#define	ISS_NSEC_SHT	12

static sin_t	sin_null;	/* Zero address for quick clears */
static sin6_t	sin6_null;	/* Zero address for quick clears */

/*
 * This implementation follows the 4.3BSD interpretation of the urgent
 * pointer and not RFC 1122. Switching to RFC 1122 behavior would cause
 * incompatible changes in protocols like telnet and rlogin.
 */
#define	TCP_OLD_URP_INTERPRETATION	1

#define	TCP_IS_DETACHED_NONEAGER(tcp)	\
	(TCP_IS_DETACHED(tcp) && \
	    (!(tcp)->tcp_hard_binding))

/*
 * TCP reassembly macros.  We hide starting and ending sequence numbers in
 * b_next and b_prev of messages on the reassembly queue.  The messages are
 * chained using b_cont.  These macros are used in tcp_reass() so we don't
 * have to see the ugly casts and assignments.
 */
#define	TCP_REASS_SEQ(mp)		((uint32_t)(uintptr_t)((mp)->b_next))
#define	TCP_REASS_SET_SEQ(mp, u)	((mp)->b_next = \
					(mblk_t *)(uintptr_t)(u))
#define	TCP_REASS_END(mp)		((uint32_t)(uintptr_t)((mp)->b_prev))
#define	TCP_REASS_SET_END(mp, u)	((mp)->b_prev = \
					(mblk_t *)(uintptr_t)(u))

/*
 * Implementation of TCP Timers.
 * =============================
 *
 * INTERFACE:
 *
 * There are two basic functions dealing with tcp timers:
 *
 *	timeout_id_t	tcp_timeout(connp, func, time)
 * 	clock_t		tcp_timeout_cancel(connp, timeout_id)
 *	TCP_TIMER_RESTART(tcp, intvl)
 *
 * tcp_timeout() starts a timer for the 'tcp' instance arranging to call 'func'
 * after 'time' ticks passed. The function called by timeout() must adhere to
 * the same restrictions as a driver soft interrupt handler - it must not sleep
 * or call other functions that might sleep. The value returned is the opaque
 * non-zero timeout identifier that can be passed to tcp_timeout_cancel() to
 * cancel the request. The call to tcp_timeout() may fail in which case it
 * returns zero. This is different from the timeout(9F) function which never
 * fails.
 *
 * The call-back function 'func' always receives 'connp' as its single
 * argument. It is always executed in the squeue corresponding to the tcp
 * structure. The tcp structure is guaranteed to be present at the time the
 * call-back is called.
 *
 * NOTE: The call-back function 'func' is never called if tcp is in
 * 	the TCPS_CLOSED state.
 *
 * tcp_timeout_cancel() attempts to cancel a pending tcp_timeout()
 * request. locks acquired by the call-back routine should not be held across
 * the call to tcp_timeout_cancel() or a deadlock may result.
 *
 * tcp_timeout_cancel() returns -1 if it can not cancel the timeout request.
 * Otherwise, it returns an integer value greater than or equal to 0. In
 * particular, if the call-back function is already placed on the squeue, it can
 * not be canceled.
 *
 * NOTE: both tcp_timeout() and tcp_timeout_cancel() should always be called
 * 	within squeue context corresponding to the tcp instance. Since the
 *	call-back is also called via the same squeue, there are no race
 *	conditions described in untimeout(9F) manual page since all calls are
 *	strictly serialized.
 *
 *      TCP_TIMER_RESTART() is a macro that attempts to cancel a pending timeout
 *	stored in tcp_timer_tid and starts a new one using
 *	MSEC_TO_TICK(intvl). It always uses tcp_timer() function as a call-back
 *	and stores the return value of tcp_timeout() in the tcp->tcp_timer_tid
 *	field.
 *
 * NOTE: since the timeout cancellation is not guaranteed, the cancelled
 *	call-back may still be called, so it is possible tcp_timer() will be
 *	called several times. This should not be a problem since tcp_timer()
 *	should always check the tcp instance state.
 *
 *
 * IMPLEMENTATION:
 *
 * TCP timers are implemented using three-stage process. The call to
 * tcp_timeout() uses timeout(9F) function to call tcp_timer_callback() function
 * when the timer expires. The tcp_timer_callback() arranges the call of the
 * tcp_timer_handler() function via squeue corresponding to the tcp
 * instance. The tcp_timer_handler() calls actual requested timeout call-back
 * and passes tcp instance as an argument to it. Information is passed between
 * stages using the tcp_timer_t structure which contains the connp pointer, the
 * tcp call-back to call and the timeout id returned by the timeout(9F).
 *
 * The tcp_timer_t structure is not used directly, it is embedded in an mblk_t -
 * like structure that is used to enter an squeue. The mp->b_rptr of this pseudo
 * mblk points to the beginning of tcp_timer_t structure. The tcp_timeout()
 * returns the pointer to this mblk.
 *
 * The pseudo mblk is allocated from a special tcp_timer_cache kmem cache. It
 * looks like a normal mblk without actual dblk attached to it.
 *
 * To optimize performance each tcp instance holds a small cache of timer
 * mblocks. In the current implementation it caches up to two timer mblocks per
 * tcp instance. The cache is preserved over tcp frees and is only freed when
 * the whole tcp structure is destroyed by its kmem destructor. Since all tcp
 * timer processing happens on a corresponding squeue, the cache manipulation
 * does not require any locks. Experiments show that majority of timer mblocks
 * allocations are satisfied from the tcp cache and do not involve kmem calls.
 *
 * The tcp_timeout() places a refhold on the connp instance which guarantees
 * that it will be present at the time the call-back function fires. The
 * tcp_timer_handler() drops the reference after calling the call-back, so the
 * call-back function does not need to manipulate the references explicitly.
 */

typedef struct tcp_timer_s {
	conn_t	*connp;
	void 	(*tcpt_proc)(void *);
	callout_id_t   tcpt_tid;
} tcp_timer_t;

static kmem_cache_t *tcp_timercache;
kmem_cache_t	*tcp_sack_info_cache;
kmem_cache_t	*tcp_iphc_cache;

/*
 * For scalability, we must not run a timer for every TCP connection
 * in TIME_WAIT state.  To see why, consider (for time wait interval of
 * 4 minutes):
 *	1000 connections/sec * 240 seconds/time wait = 240,000 active conn's
 *
 * This list is ordered by time, so you need only delete from the head
 * until you get to entries which aren't old enough to delete yet.
 * The list consists of only the detached TIME_WAIT connections.
 *
 * Note that the timer (tcp_time_wait_expire) is started when the tcp_t
 * becomes detached TIME_WAIT (either by changing the state and already
 * being detached or the other way around). This means that the TIME_WAIT
 * state can be extended (up to doubled) if the connection doesn't become
 * detached for a long time.
 *
 * The list manipulations (including tcp_time_wait_next/prev)
 * are protected by the tcp_time_wait_lock. The content of the
 * detached TIME_WAIT connections is protected by the normal perimeters.
 *
 * This list is per squeue and squeues are shared across the tcp_stack_t's.
 * Things on tcp_time_wait_head remain associated with the tcp_stack_t
 * and conn_netstack.
 * The tcp_t's that are added to tcp_free_list are disassociated and
 * have NULL tcp_tcps and conn_netstack pointers.
 */
typedef struct tcp_squeue_priv_s {
	kmutex_t	tcp_time_wait_lock;
	callout_id_t	tcp_time_wait_tid;
	tcp_t		*tcp_time_wait_head;
	tcp_t		*tcp_time_wait_tail;
	tcp_t		*tcp_free_list;
	uint_t		tcp_free_list_cnt;
} tcp_squeue_priv_t;

/*
 * TCP_TIME_WAIT_DELAY governs how often the time_wait_collector runs.
 * Running it every 5 seconds seems to give the best results.
 */
#define	TCP_TIME_WAIT_DELAY drv_usectohz(5000000)

/*
 * To prevent memory hog, limit the number of entries in tcp_free_list
 * to 1% of available memory / number of cpus
 */
uint_t tcp_free_list_max_cnt = 0;

#define	TCP_XMIT_LOWATER	4096
#define	TCP_XMIT_HIWATER	49152
#define	TCP_RECV_LOWATER	2048
#define	TCP_RECV_HIWATER	49152

/*
 *  PAWS needs a timer for 24 days.  This is the number of ticks in 24 days
 */
#define	PAWS_TIMEOUT	((clock_t)(24*24*60*60*hz))

#define	TIDUSZ	4096	/* transport interface data unit size */

/*
 * Bind hash list size and has function.  It has to be a power of 2 for
 * hashing.
 */
#define	TCP_BIND_FANOUT_SIZE	512
#define	TCP_BIND_HASH(lport) (ntohs(lport) & (TCP_BIND_FANOUT_SIZE - 1))
/*
 * Size of listen and acceptor hash list.  It has to be a power of 2 for
 * hashing.
 */
#define	TCP_FANOUT_SIZE		256

#ifdef	_ILP32
#define	TCP_ACCEPTOR_HASH(accid)					\
		(((uint_t)(accid) >> 8) & (TCP_FANOUT_SIZE - 1))
#else
#define	TCP_ACCEPTOR_HASH(accid)					\
		((uint_t)(accid) & (TCP_FANOUT_SIZE - 1))
#endif	/* _ILP32 */

#define	IP_ADDR_CACHE_SIZE	2048
#define	IP_ADDR_CACHE_HASH(faddr)					\
	(ntohl(faddr) & (IP_ADDR_CACHE_SIZE -1))

/* Hash for HSPs uses all 32 bits, since both networks and hosts are in table */
#define	TCP_HSP_HASH_SIZE 256

#define	TCP_HSP_HASH(addr)					\
	(((addr>>24) ^ (addr >>16) ^			\
	    (addr>>8) ^ (addr)) % TCP_HSP_HASH_SIZE)

/*
 * TCP options struct returned from tcp_parse_options.
 */
typedef struct tcp_opt_s {
	uint32_t	tcp_opt_mss;
	uint32_t	tcp_opt_wscale;
	uint32_t	tcp_opt_ts_val;
	uint32_t	tcp_opt_ts_ecr;
	tcp_t		*tcp;
} tcp_opt_t;

/*
 * TCP option struct passing information b/w lisenter and eager.
 */
struct tcp_options {
	uint_t			to_flags;
	ssize_t			to_boundif;	/* IPV6_BOUND_IF */
	sock_upper_handle_t	to_handle;
};

#define	TCPOPT_BOUNDIF		0x00000001	/* set IPV6_BOUND_IF */
#define	TCPOPT_RECVPKTINFO	0x00000002	/* set IPV6_RECVPKTINFO */
#define	TCPOPT_UPPERHANDLE	0x00000004	/* set upper handle */

/*
 * RFC1323-recommended phrasing of TSTAMP option, for easier parsing
 */

#ifdef _BIG_ENDIAN
#define	TCPOPT_NOP_NOP_TSTAMP ((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) | \
	(TCPOPT_TSTAMP << 8) | 10)
#else
#define	TCPOPT_NOP_NOP_TSTAMP ((10 << 24) | (TCPOPT_TSTAMP << 16) | \
	(TCPOPT_NOP << 8) | TCPOPT_NOP)
#endif

/*
 * Flags returned from tcp_parse_options.
 */
#define	TCP_OPT_MSS_PRESENT	1
#define	TCP_OPT_WSCALE_PRESENT	2
#define	TCP_OPT_TSTAMP_PRESENT	4
#define	TCP_OPT_SACK_OK_PRESENT	8
#define	TCP_OPT_SACK_PRESENT	16

/* TCP option length */
#define	TCPOPT_NOP_LEN		1
#define	TCPOPT_MAXSEG_LEN	4
#define	TCPOPT_WS_LEN		3
#define	TCPOPT_REAL_WS_LEN	(TCPOPT_WS_LEN+1)
#define	TCPOPT_TSTAMP_LEN	10
#define	TCPOPT_REAL_TS_LEN	(TCPOPT_TSTAMP_LEN+2)
#define	TCPOPT_SACK_OK_LEN	2
#define	TCPOPT_REAL_SACK_OK_LEN	(TCPOPT_SACK_OK_LEN+2)
#define	TCPOPT_REAL_SACK_LEN	4
#define	TCPOPT_MAX_SACK_LEN	36
#define	TCPOPT_HEADER_LEN	2

/* TCP cwnd burst factor. */
#define	TCP_CWND_INFINITE	65535
#define	TCP_CWND_SS		3
#define	TCP_CWND_NORMAL		5

/* Maximum TCP initial cwin (start/restart). */
#define	TCP_MAX_INIT_CWND	8

/*
 * Initialize cwnd according to RFC 3390.  def_max_init_cwnd is
 * either tcp_slow_start_initial or tcp_slow_start_after idle
 * depending on the caller.  If the upper layer has not used the
 * TCP_INIT_CWND option to change the initial cwnd, tcp_init_cwnd
 * should be 0 and we use the formula in RFC 3390 to set tcp_cwnd.
 * If the upper layer has changed set the tcp_init_cwnd, just use
 * it to calculate the tcp_cwnd.
 */
#define	SET_TCP_INIT_CWND(tcp, mss, def_max_init_cwnd)			\
{									\
	if ((tcp)->tcp_init_cwnd == 0) {				\
		(tcp)->tcp_cwnd = MIN(def_max_init_cwnd * (mss),	\
		    MIN(4 * (mss), MAX(2 * (mss), 4380 / (mss) * (mss)))); \
	} else {							\
		(tcp)->tcp_cwnd = (tcp)->tcp_init_cwnd * (mss);		\
	}								\
	tcp->tcp_cwnd_cnt = 0;						\
}

/* TCP Timer control structure */
typedef struct tcpt_s {
	pfv_t	tcpt_pfv;	/* The routine we are to call */
	tcp_t	*tcpt_tcp;	/* The parameter we are to pass in */
} tcpt_t;

/* Host Specific Parameter structure */
typedef struct tcp_hsp {
	struct tcp_hsp	*tcp_hsp_next;
	in6_addr_t	tcp_hsp_addr_v6;
	in6_addr_t	tcp_hsp_subnet_v6;
	uint_t		tcp_hsp_vers;	/* IPV4_VERSION | IPV6_VERSION */
	int32_t		tcp_hsp_sendspace;
	int32_t		tcp_hsp_recvspace;
	int32_t		tcp_hsp_tstamp;
} tcp_hsp_t;
#define	tcp_hsp_addr	V4_PART_OF_V6(tcp_hsp_addr_v6)
#define	tcp_hsp_subnet	V4_PART_OF_V6(tcp_hsp_subnet_v6)

/*
 * Functions called directly via squeue having a prototype of edesc_t.
 */
void		tcp_conn_request(void *arg, mblk_t *mp, void *arg2);
static void	tcp_wput_nondata(void *arg, mblk_t *mp, void *arg2);
void		tcp_accept_finish(void *arg, mblk_t *mp, void *arg2);
static void	tcp_wput_ioctl(void *arg, mblk_t *mp, void *arg2);
static void	tcp_wput_proto(void *arg, mblk_t *mp, void *arg2);
void 		tcp_input(void *arg, mblk_t *mp, void *arg2);
void		tcp_rput_data(void *arg, mblk_t *mp, void *arg2);
static void	tcp_close_output(void *arg, mblk_t *mp, void *arg2);
void		tcp_output(void *arg, mblk_t *mp, void *arg2);
void		tcp_output_urgent(void *arg, mblk_t *mp, void *arg2);
static void	tcp_rsrv_input(void *arg, mblk_t *mp, void *arg2);
static void	tcp_timer_handler(void *arg, mblk_t *mp, void *arg2);
static void	tcp_linger_interrupted(void *arg, mblk_t *mp, void *arg2);


/* Prototype for TCP functions */
static void	tcp_random_init(void);
int		tcp_random(void);
static void	tcp_tli_accept(tcp_t *tcp, mblk_t *mp);
static void	tcp_accept_swap(tcp_t *listener, tcp_t *acceptor,
		    tcp_t *eager);
static int	tcp_adapt_ire(tcp_t *tcp, mblk_t *ire_mp);
static in_port_t tcp_bindi(tcp_t *tcp, in_port_t port, const in6_addr_t *laddr,
    int reuseaddr, boolean_t quick_connect, boolean_t bind_to_req_port_only,
    boolean_t user_specified);
static void	tcp_closei_local(tcp_t *tcp);
static void	tcp_close_detached(tcp_t *tcp);
static boolean_t tcp_conn_con(tcp_t *tcp, uchar_t *iphdr, tcph_t *tcph,
			mblk_t *idmp, mblk_t **defermp);
static void	tcp_tpi_connect(tcp_t *tcp, mblk_t *mp);
static int	tcp_connect_ipv4(tcp_t *tcp, ipaddr_t *dstaddrp,
		    in_port_t dstport, uint_t srcid, cred_t *cr, pid_t pid);
static int 	tcp_connect_ipv6(tcp_t *tcp, in6_addr_t *dstaddrp,
		    in_port_t dstport, uint32_t flowinfo, uint_t srcid,
		    uint32_t scope_id, cred_t *cr, pid_t pid);
static int	tcp_clean_death(tcp_t *tcp, int err, uint8_t tag);
static void	tcp_def_q_set(tcp_t *tcp, mblk_t *mp);
static void	tcp_disconnect(tcp_t *tcp, mblk_t *mp);
static char	*tcp_display(tcp_t *tcp, char *, char);
static boolean_t tcp_eager_blowoff(tcp_t *listener, t_scalar_t seqnum);
static void	tcp_eager_cleanup(tcp_t *listener, boolean_t q0_only);
static void	tcp_eager_unlink(tcp_t *tcp);
static void	tcp_err_ack(tcp_t *tcp, mblk_t *mp, int tlierr,
		    int unixerr);
static void	tcp_err_ack_prim(tcp_t *tcp, mblk_t *mp, int primitive,
		    int tlierr, int unixerr);
static int	tcp_extra_priv_ports_get(queue_t *q, mblk_t *mp, caddr_t cp,
		    cred_t *cr);
static int	tcp_extra_priv_ports_add(queue_t *q, mblk_t *mp,
		    char *value, caddr_t cp, cred_t *cr);
static int	tcp_extra_priv_ports_del(queue_t *q, mblk_t *mp,
		    char *value, caddr_t cp, cred_t *cr);
static int	tcp_tpistate(tcp_t *tcp);
static void	tcp_bind_hash_insert(tf_t *tf, tcp_t *tcp,
    int caller_holds_lock);
static void	tcp_bind_hash_remove(tcp_t *tcp);
static tcp_t	*tcp_acceptor_hash_lookup(t_uscalar_t id, tcp_stack_t *);
void		tcp_acceptor_hash_insert(t_uscalar_t id, tcp_t *tcp);
static void	tcp_acceptor_hash_remove(tcp_t *tcp);
static void	tcp_capability_req(tcp_t *tcp, mblk_t *mp);
static void	tcp_info_req(tcp_t *tcp, mblk_t *mp);
static void	tcp_addr_req(tcp_t *tcp, mblk_t *mp);
static void	tcp_addr_req_ipv6(tcp_t *tcp, mblk_t *mp);
void		tcp_g_q_setup(tcp_stack_t *);
void		tcp_g_q_create(tcp_stack_t *);
void		tcp_g_q_destroy(tcp_stack_t *);
static int	tcp_header_init_ipv4(tcp_t *tcp);
static int	tcp_header_init_ipv6(tcp_t *tcp);
int		tcp_init(tcp_t *tcp, queue_t *q);
static int	tcp_init_values(tcp_t *tcp);
static mblk_t	*tcp_ip_advise_mblk(void *addr, int addr_len, ipic_t **ipic);
static void	tcp_ip_ire_mark_advice(tcp_t *tcp);
static void	tcp_ip_notify(tcp_t *tcp);
static mblk_t	*tcp_ire_mp(mblk_t **mpp);
static void	tcp_iss_init(tcp_t *tcp);
static void	tcp_keepalive_killer(void *arg);
static int	tcp_parse_options(tcph_t *tcph, tcp_opt_t *tcpopt);
static void	tcp_mss_set(tcp_t *tcp, uint32_t size, boolean_t do_ss);
static int	tcp_conprim_opt_process(tcp_t *tcp, mblk_t *mp,
		    int *do_disconnectp, int *t_errorp, int *sys_errorp);
static boolean_t tcp_allow_connopt_set(int level, int name);
int		tcp_opt_default(queue_t *q, int level, int name, uchar_t *ptr);
int		tcp_tpi_opt_get(queue_t *q, int level, int name, uchar_t *ptr);
int		tcp_tpi_opt_set(queue_t *q, uint_t optset_context, int level,
		    int name, uint_t inlen, uchar_t *invalp, uint_t *outlenp,
		    uchar_t *outvalp, void *thisdg_attrs, cred_t *cr,
		    mblk_t *mblk);
static void	tcp_opt_reverse(tcp_t *tcp, ipha_t *ipha);
static int	tcp_opt_set_header(tcp_t *tcp, boolean_t checkonly,
		    uchar_t *ptr, uint_t len);
static int	tcp_param_get(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *cr);
static boolean_t tcp_param_register(IDP *ndp, tcpparam_t *tcppa, int cnt,
    tcp_stack_t *);
static int	tcp_param_set(queue_t *q, mblk_t *mp, char *value,
		    caddr_t cp, cred_t *cr);
static int	tcp_param_set_aligned(queue_t *q, mblk_t *mp, char *value,
		    caddr_t cp, cred_t *cr);
static void	tcp_iss_key_init(uint8_t *phrase, int len, tcp_stack_t *);
static int	tcp_1948_phrase_set(queue_t *q, mblk_t *mp, char *value,
		    caddr_t cp, cred_t *cr);
static void	tcp_process_shrunk_swnd(tcp_t *tcp, uint32_t shrunk_cnt);
static mblk_t	*tcp_reass(tcp_t *tcp, mblk_t *mp, uint32_t start);
static void	tcp_reass_elim_overlap(tcp_t *tcp, mblk_t *mp);
static void	tcp_reinit(tcp_t *tcp);
static void	tcp_reinit_values(tcp_t *tcp);
static void	tcp_report_item(mblk_t *mp, tcp_t *tcp, int hashval,
		    tcp_t *thisstream, cred_t *cr);

static uint_t	tcp_rwnd_reopen(tcp_t *tcp);
static uint_t	tcp_rcv_drain(tcp_t *tcp);
static void	tcp_sack_rxmit(tcp_t *tcp, uint_t *flags);
static boolean_t tcp_send_rst_chk(tcp_stack_t *);
static void	tcp_ss_rexmit(tcp_t *tcp);
static mblk_t	*tcp_rput_add_ancillary(tcp_t *tcp, mblk_t *mp, ip6_pkt_t *ipp);
static void	tcp_process_options(tcp_t *, tcph_t *);
static void	tcp_rput_common(tcp_t *tcp, mblk_t *mp);
static void	tcp_rsrv(queue_t *q);
static int	tcp_rwnd_set(tcp_t *tcp, uint32_t rwnd);
static int	tcp_snmp_state(tcp_t *tcp);
static int	tcp_status_report(queue_t *q, mblk_t *mp, caddr_t cp,
		    cred_t *cr);
static int	tcp_bind_hash_report(queue_t *q, mblk_t *mp, caddr_t cp,
		    cred_t *cr);
static int	tcp_listen_hash_report(queue_t *q, mblk_t *mp, caddr_t cp,
		    cred_t *cr);
static int	tcp_conn_hash_report(queue_t *q, mblk_t *mp, caddr_t cp,
		    cred_t *cr);
static int	tcp_acceptor_hash_report(queue_t *q, mblk_t *mp, caddr_t cp,
		    cred_t *cr);
static void	tcp_timer(void *arg);
static void	tcp_timer_callback(void *);
static in_port_t tcp_update_next_port(in_port_t port, const tcp_t *tcp,
    boolean_t random);
static in_port_t tcp_get_next_priv_port(const tcp_t *);
static void	tcp_wput_sock(queue_t *q, mblk_t *mp);
static void	tcp_wput_fallback(queue_t *q, mblk_t *mp);
void		tcp_tpi_accept(queue_t *q, mblk_t *mp);
static void	tcp_wput_data(tcp_t *tcp, mblk_t *mp, boolean_t urgent);
static void	tcp_wput_flush(tcp_t *tcp, mblk_t *mp);
static void	tcp_wput_iocdata(tcp_t *tcp, mblk_t *mp);
static int	tcp_send(queue_t *q, tcp_t *tcp, const int mss,
		    const int tcp_hdr_len, const int tcp_tcp_hdr_len,
		    const int num_sack_blk, int *usable, uint_t *snxt,
		    int *tail_unsent, mblk_t **xmit_tail, mblk_t *local_time,
		    const int mdt_thres);
static int	tcp_multisend(queue_t *q, tcp_t *tcp, const int mss,
		    const int tcp_hdr_len, const int tcp_tcp_hdr_len,
		    const int num_sack_blk, int *usable, uint_t *snxt,
		    int *tail_unsent, mblk_t **xmit_tail, mblk_t *local_time,
		    const int mdt_thres);
static void	tcp_fill_header(tcp_t *tcp, uchar_t *rptr, clock_t now,
		    int num_sack_blk);
static void	tcp_wsrv(queue_t *q);
static int	tcp_xmit_end(tcp_t *tcp);
static void	tcp_ack_timer(void *arg);
static mblk_t	*tcp_ack_mp(tcp_t *tcp);
static void	tcp_xmit_early_reset(char *str, mblk_t *mp,
		    uint32_t seq, uint32_t ack, int ctl, uint_t ip_hdr_len,
		    zoneid_t zoneid, tcp_stack_t *, conn_t *connp);
static void	tcp_xmit_ctl(char *str, tcp_t *tcp, uint32_t seq,
		    uint32_t ack, int ctl);
static tcp_hsp_t *tcp_hsp_lookup(ipaddr_t addr, tcp_stack_t *);
static tcp_hsp_t *tcp_hsp_lookup_ipv6(in6_addr_t *addr, tcp_stack_t *);
static int	setmaxps(queue_t *q, int maxpsz);
static void	tcp_set_rto(tcp_t *, time_t);
static boolean_t tcp_check_policy(tcp_t *, mblk_t *, ipha_t *, ip6_t *,
		    boolean_t, boolean_t);
static void	tcp_icmp_error_ipv6(tcp_t *tcp, mblk_t *mp,
		    boolean_t ipsec_mctl);
static int	tcp_build_hdrs(tcp_t *);
static void	tcp_time_wait_processing(tcp_t *tcp, mblk_t *mp,
		    uint32_t seg_seq, uint32_t seg_ack, int seg_len,
		    tcph_t *tcph);
boolean_t	tcp_paws_check(tcp_t *tcp, tcph_t *tcph, tcp_opt_t *tcpoptp);
static mblk_t	*tcp_mdt_info_mp(mblk_t *);
static void	tcp_mdt_update(tcp_t *, ill_mdt_capab_t *, boolean_t);
static int	tcp_mdt_add_attrs(multidata_t *, const mblk_t *,
		    const boolean_t, const uint32_t, const uint32_t,
		    const uint32_t, const uint32_t, tcp_stack_t *);
static void	tcp_multisend_data(tcp_t *, ire_t *, const ill_t *, mblk_t *,
		    const uint_t, const uint_t, boolean_t *);
static mblk_t	*tcp_lso_info_mp(mblk_t *);
static void	tcp_lso_update(tcp_t *, ill_lso_capab_t *);
static void	tcp_send_data(tcp_t *, queue_t *, mblk_t *);
extern mblk_t	*tcp_timermp_alloc(int);
extern void	tcp_timermp_free(tcp_t *);
static void	tcp_timer_free(tcp_t *tcp, mblk_t *mp);
static void	tcp_stop_lingering(tcp_t *tcp);
static void	tcp_close_linger_timeout(void *arg);
static void	*tcp_stack_init(netstackid_t stackid, netstack_t *ns);
static void	tcp_stack_shutdown(netstackid_t stackid, void *arg);
static void	tcp_stack_fini(netstackid_t stackid, void *arg);
static void	*tcp_g_kstat_init(tcp_g_stat_t *);
static void	tcp_g_kstat_fini(kstat_t *);
static void	*tcp_kstat_init(netstackid_t, tcp_stack_t *);
static void	tcp_kstat_fini(netstackid_t, kstat_t *);
static void	*tcp_kstat2_init(netstackid_t, tcp_stat_t *);
static void	tcp_kstat2_fini(netstackid_t, kstat_t *);
static int	tcp_kstat_update(kstat_t *kp, int rw);
void		tcp_reinput(conn_t *connp, mblk_t *mp, squeue_t *sqp);
static int	tcp_conn_create_v6(conn_t *lconnp, conn_t *connp, mblk_t *mp,
			tcph_t *tcph, uint_t ipvers, mblk_t *idmp);
static int	tcp_conn_create_v4(conn_t *lconnp, conn_t *connp, ipha_t *ipha,
			tcph_t *tcph, mblk_t *idmp);
static int	tcp_squeue_switch(int);

static int	tcp_open(queue_t *, dev_t *, int, int, cred_t *, boolean_t);
static int	tcp_openv4(queue_t *, dev_t *, int, int, cred_t *);
static int	tcp_openv6(queue_t *, dev_t *, int, int, cred_t *);
static int	tcp_tpi_close(queue_t *, int);
static int	tcpclose_accept(queue_t *);

static void	tcp_squeue_add(squeue_t *);
static boolean_t tcp_zcopy_check(tcp_t *);
static void	tcp_zcopy_notify(tcp_t *);
static mblk_t	*tcp_zcopy_disable(tcp_t *, mblk_t *);
static mblk_t	*tcp_zcopy_backoff(tcp_t *, mblk_t *, int);
static void	tcp_ire_ill_check(tcp_t *, ire_t *, ill_t *, boolean_t);

extern void	tcp_kssl_input(tcp_t *, mblk_t *);

void tcp_eager_kill(void *arg, mblk_t *mp, void *arg2);
void tcp_clean_death_wrapper(void *arg, mblk_t *mp, void *arg2);

static int tcp_accept(sock_lower_handle_t, sock_lower_handle_t,
	    sock_upper_handle_t, cred_t *);
static int tcp_listen(sock_lower_handle_t, int, cred_t *);
static int tcp_post_ip_bind(tcp_t *, mblk_t *, int, cred_t *, pid_t);
static int tcp_do_listen(conn_t *, int, cred_t *);
static int tcp_do_connect(conn_t *, const struct sockaddr *, socklen_t,
    cred_t *, pid_t);
static int tcp_do_bind(conn_t *, struct sockaddr *, socklen_t, cred_t *,
    boolean_t);
static int tcp_do_unbind(conn_t *);
static int tcp_bind_check(conn_t *, struct sockaddr *, socklen_t, cred_t *,
    boolean_t);

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
static void	tcp_ioctl_abort_handler(tcp_t *, mblk_t *);
static int	tcp_ioctl_abort(tcp_ioc_abort_conn_t *, tcp_stack_t *tcps);
static void	tcp_ioctl_abort_conn(queue_t *, mblk_t *);
static int	tcp_ioctl_abort_bucket(tcp_ioc_abort_conn_t *, int, int *,
    boolean_t, tcp_stack_t *);

static struct module_info tcp_rinfo =  {
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
	NULL, (pfi_t)tcp_rsrv, NULL, tcpclose_accept, NULL, &tcp_winfo
};

struct qinit tcp_acceptor_winit = {
	(pfi_t)tcp_tpi_accept, NULL, NULL, NULL, NULL, &tcp_winfo
};

/*
 * Entry points for TCP loopback (read side only)
 * The open routine is only used for reopens, thus no need to
 * have a separate one for tcp_openv6.
 */
struct qinit tcp_loopback_rinit = {
	(pfi_t)0, (pfi_t)tcp_rsrv, tcp_openv4, tcp_tpi_close, (pfi_t)0,
	&tcp_rinfo, NULL, tcp_fuse_rrw, tcp_fuse_rinfop, STRUIOT_STANDARD
};

/* For AF_INET aka /dev/tcp */
struct streamtab tcpinfov4 = {
	&tcp_rinitv4, &tcp_winit
};

/* For AF_INET6 aka /dev/tcp6 */
struct streamtab tcpinfov6 = {
	&tcp_rinitv6, &tcp_winit
};

sock_downcalls_t sock_tcp_downcalls;

/*
 * Have to ensure that tcp_g_q_close is not done by an
 * interrupt thread.
 */
static taskq_t *tcp_taskq;

/* Setable only in /etc/system. Move to ndd? */
boolean_t tcp_icmp_source_quench = B_FALSE;

/*
 * Following assumes TPI alignment requirements stay along 32 bit
 * boundaries
 */
#define	ROUNDUP32(x) \
	(((x) + (sizeof (int32_t) - 1)) & ~(sizeof (int32_t) - 1))

/* Template for response to info request. */
static struct T_info_ack tcp_g_t_info_ack = {
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

static struct T_info_ack tcp_g_t_info_ack_v6 = {
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

#define	MS	1L
#define	SECONDS	(1000 * MS)
#define	MINUTES	(60 * SECONDS)
#define	HOURS	(60 * MINUTES)
#define	DAYS	(24 * HOURS)

#define	PARAM_MAX (~(uint32_t)0)

/* Max size IP datagram is 64k - 1 */
#define	TCP_MSS_MAX_IPV4 (IP_MAXPACKET - (sizeof (ipha_t) + sizeof (tcph_t)))
#define	TCP_MSS_MAX_IPV6 (IP_MAXPACKET - (sizeof (ip6_t) + sizeof (tcph_t)))
/* Max of the above */
#define	TCP_MSS_MAX	TCP_MSS_MAX_IPV4

/* Largest TCP port number */
#define	TCP_MAX_PORT	(64 * 1024 - 1)

/*
 * tcp_wroff_xtra is the extra space in front of TCP/IP header for link
 * layer header.  It has to be a multiple of 4.
 */
static tcpparam_t lcl_tcp_wroff_xtra_param = { 0, 256, 32, "tcp_wroff_xtra" };
#define	tcps_wroff_xtra	tcps_wroff_xtra_param->tcp_param_val

/*
 * All of these are alterable, within the min/max values given, at run time.
 * Note that the default value of "tcp_time_wait_interval" is four minutes,
 * per the TCP spec.
 */
/* BEGIN CSTYLED */
static tcpparam_t	lcl_tcp_param_arr[] = {
 /*min		max		value		name */
 { 1*SECONDS,	10*MINUTES,	1*MINUTES,	"tcp_time_wait_interval"},
 { 1,		PARAM_MAX,	128,		"tcp_conn_req_max_q" },
 { 0,		PARAM_MAX,	1024,		"tcp_conn_req_max_q0" },
 { 1,		1024,		1,		"tcp_conn_req_min" },
 { 0*MS,	20*SECONDS,	0*MS,		"tcp_conn_grace_period" },
 { 128,		(1<<30),	1024*1024,	"tcp_cwnd_max" },
 { 0,		10,		0,		"tcp_debug" },
 { 1024,	(32*1024),	1024,		"tcp_smallest_nonpriv_port"},
 { 1*SECONDS,	PARAM_MAX,	3*MINUTES,	"tcp_ip_abort_cinterval"},
 { 1*SECONDS,	PARAM_MAX,	3*MINUTES,	"tcp_ip_abort_linterval"},
 { 500*MS,	PARAM_MAX,	8*MINUTES,	"tcp_ip_abort_interval"},
 { 1*SECONDS,	PARAM_MAX,	10*SECONDS,	"tcp_ip_notify_cinterval"},
 { 500*MS,	PARAM_MAX,	10*SECONDS,	"tcp_ip_notify_interval"},
 { 1,		255,		64,		"tcp_ipv4_ttl"},
 { 10*SECONDS,	10*DAYS,	2*HOURS,	"tcp_keepalive_interval"},
 { 0,		100,		10,		"tcp_maxpsz_multiplier" },
 { 1,		TCP_MSS_MAX_IPV4, 536,		"tcp_mss_def_ipv4"},
 { 1,		TCP_MSS_MAX_IPV4, TCP_MSS_MAX_IPV4, "tcp_mss_max_ipv4"},
 { 1,		TCP_MSS_MAX,	108,		"tcp_mss_min"},
 { 1,		(64*1024)-1,	(4*1024)-1,	"tcp_naglim_def"},
 { 1*MS,	20*SECONDS,	3*SECONDS,	"tcp_rexmit_interval_initial"},
 { 1*MS,	2*HOURS,	60*SECONDS,	"tcp_rexmit_interval_max"},
 { 1*MS,	2*HOURS,	400*MS,		"tcp_rexmit_interval_min"},
 { 1*MS,	1*MINUTES,	100*MS,		"tcp_deferred_ack_interval" },
 { 0,		16,		0,		"tcp_snd_lowat_fraction" },
 { 0,		128000,		0,		"tcp_sth_rcv_hiwat" },
 { 0,		128000,		0,		"tcp_sth_rcv_lowat" },
 { 1,		10000,		3,		"tcp_dupack_fast_retransmit" },
 { 0,		1,		0,		"tcp_ignore_path_mtu" },
 { 1024,	TCP_MAX_PORT,	32*1024,	"tcp_smallest_anon_port"},
 { 1024,	TCP_MAX_PORT,	TCP_MAX_PORT,	"tcp_largest_anon_port"},
 { TCP_XMIT_LOWATER, (1<<30), TCP_XMIT_HIWATER,"tcp_xmit_hiwat"},
 { TCP_XMIT_LOWATER, (1<<30), TCP_XMIT_LOWATER,"tcp_xmit_lowat"},
 { TCP_RECV_LOWATER, (1<<30), TCP_RECV_HIWATER,"tcp_recv_hiwat"},
 { 1,		65536,		4,		"tcp_recv_hiwat_minmss"},
 { 1*SECONDS,	PARAM_MAX,	675*SECONDS,	"tcp_fin_wait_2_flush_interval"},
 { 8192,	(1<<30),	1024*1024,	"tcp_max_buf"},
/*
 * Question:  What default value should I set for tcp_strong_iss?
 */
 { 0,		2,		1,		"tcp_strong_iss"},
 { 0,		65536,		20,		"tcp_rtt_updates"},
 { 0,		1,		1,		"tcp_wscale_always"},
 { 0,		1,		0,		"tcp_tstamp_always"},
 { 0,		1,		1,		"tcp_tstamp_if_wscale"},
 { 0*MS,	2*HOURS,	0*MS,		"tcp_rexmit_interval_extra"},
 { 0,		16,		2,		"tcp_deferred_acks_max"},
 { 1,		16384,		4,		"tcp_slow_start_after_idle"},
 { 1,		4,		4,		"tcp_slow_start_initial"},
 { 0,		2,		2,		"tcp_sack_permitted"},
 { 0,		1,		1,		"tcp_compression_enabled"},
 { 0,		IPV6_MAX_HOPS,	IPV6_DEFAULT_HOPS,	"tcp_ipv6_hoplimit"},
 { 1,		TCP_MSS_MAX_IPV6, 1220,		"tcp_mss_def_ipv6"},
 { 1,		TCP_MSS_MAX_IPV6, TCP_MSS_MAX_IPV6, "tcp_mss_max_ipv6"},
 { 0,		1,		0,		"tcp_rev_src_routes"},
 { 10*MS,	500*MS,		50*MS,		"tcp_local_dack_interval"},
 { 100*MS,	60*SECONDS,	1*SECONDS,	"tcp_ndd_get_info_interval"},
 { 0,		16,		8,		"tcp_local_dacks_max"},
 { 0,		2,		1,		"tcp_ecn_permitted"},
 { 0,		1,		1,		"tcp_rst_sent_rate_enabled"},
 { 0,		PARAM_MAX,	40,		"tcp_rst_sent_rate"},
 { 0,		100*MS,		50*MS,		"tcp_push_timer_interval"},
 { 0,		1,		0,		"tcp_use_smss_as_mss_opt"},
 { 0,		PARAM_MAX,	8*MINUTES,	"tcp_keepalive_abort_interval"},
};
/* END CSTYLED */

/*
 * tcp_mdt_hdr_{head,tail}_min are the leading and trailing spaces of
 * each header fragment in the header buffer.  Each parameter value has
 * to be a multiple of 4 (32-bit aligned).
 */
static tcpparam_t lcl_tcp_mdt_head_param =
	{ 32, 256, 32, "tcp_mdt_hdr_head_min" };
static tcpparam_t lcl_tcp_mdt_tail_param =
	{ 0,  256, 32, "tcp_mdt_hdr_tail_min" };
#define	tcps_mdt_hdr_head_min	tcps_mdt_head_param->tcp_param_val
#define	tcps_mdt_hdr_tail_min	tcps_mdt_tail_param->tcp_param_val

/*
 * tcp_mdt_max_pbufs is the upper limit value that tcp uses to figure out
 * the maximum number of payload buffers associated per Multidata.
 */
static tcpparam_t lcl_tcp_mdt_max_pbufs_param =
	{ 1, MULTIDATA_MAX_PBUFS, MULTIDATA_MAX_PBUFS, "tcp_mdt_max_pbufs" };
#define	tcps_mdt_max_pbufs	tcps_mdt_max_pbufs_param->tcp_param_val

/* Round up the value to the nearest mss. */
#define	MSS_ROUNDUP(value, mss)		((((value) - 1) / (mss) + 1) * (mss))

/*
 * Set ECN capable transport (ECT) code point in IP header.
 *
 * Note that there are 2 ECT code points '01' and '10', which are called
 * ECT(1) and ECT(0) respectively.  Here we follow the original ECT code
 * point ECT(0) for TCP as described in RFC 2481.
 */
#define	SET_ECT(tcp, iph) \
	if ((tcp)->tcp_ipversion == IPV4_VERSION) { \
		/* We need to clear the code point first. */ \
		((ipha_t *)(iph))->ipha_type_of_service &= 0xFC; \
		((ipha_t *)(iph))->ipha_type_of_service |= IPH_ECN_ECT0; \
	} else { \
		((ip6_t *)(iph))->ip6_vcf &= htonl(0xFFCFFFFF); \
		((ip6_t *)(iph))->ip6_vcf |= htonl(IPH_ECN_ECT0 << 20); \
	}

/*
 * The format argument to pass to tcp_display().
 * DISP_PORT_ONLY means that the returned string has only port info.
 * DISP_ADDR_AND_PORT means that the returned string also contains the
 * remote and local IP address.
 */
#define	DISP_PORT_ONLY		1
#define	DISP_ADDR_AND_PORT	2

#define	NDD_TOO_QUICK_MSG \
	"ndd get info rate too high for non-privileged users, try again " \
	"later.\n"
#define	NDD_OUT_OF_BUF_MSG	"<< Out of buffer >>\n"

#define	IS_VMLOANED_MBLK(mp) \
	(((mp)->b_datap->db_struioflag & STRUIO_ZC) != 0)


/* Enable or disable b_cont M_MULTIDATA chaining for MDT. */
boolean_t tcp_mdt_chain = B_TRUE;

/*
 * MDT threshold in the form of effective send MSS multiplier; we take
 * the MDT path if the amount of unsent data exceeds the threshold value
 * (default threshold is 1*SMSS).
 */
uint_t tcp_mdt_smss_threshold = 1;

uint32_t do_tcpzcopy = 1;		/* 0: disable, 1: enable, 2: force */

/*
 * Forces all connections to obey the value of the tcps_maxpsz_multiplier
 * tunable settable via NDD.  Otherwise, the per-connection behavior is
 * determined dynamically during tcp_adapt_ire(), which is the default.
 */
boolean_t tcp_static_maxpsz = B_FALSE;

/* Setable in /etc/system */
/* If set to 0, pick ephemeral port sequentially; otherwise randomly. */
uint32_t tcp_random_anon_port = 1;

/*
 * To reach to an eager in Q0 which can be dropped due to an incoming
 * new SYN request when Q0 is full, a new doubly linked list is
 * introduced. This list allows to select an eager from Q0 in O(1) time.
 * This is needed to avoid spending too much time walking through the
 * long list of eagers in Q0 when tcp_drop_q0() is called. Each member of
 * this new list has to be a member of Q0.
 * This list is headed by listener's tcp_t. When the list is empty,
 * both the pointers - tcp_eager_next_drop_q0 and tcp_eager_prev_drop_q0,
 * of listener's tcp_t point to listener's tcp_t itself.
 *
 * Given an eager in Q0 and a listener, MAKE_DROPPABLE() puts the eager
 * in the list. MAKE_UNDROPPABLE() takes the eager out of the list.
 * These macros do not affect the eager's membership to Q0.
 */


#define	MAKE_DROPPABLE(listener, eager)					\
	if ((eager)->tcp_eager_next_drop_q0 == NULL) {			\
		(listener)->tcp_eager_next_drop_q0->tcp_eager_prev_drop_q0\
		    = (eager);						\
		(eager)->tcp_eager_prev_drop_q0 = (listener);		\
		(eager)->tcp_eager_next_drop_q0 =			\
		    (listener)->tcp_eager_next_drop_q0;			\
		(listener)->tcp_eager_next_drop_q0 = (eager);		\
	}

#define	MAKE_UNDROPPABLE(eager)						\
	if ((eager)->tcp_eager_next_drop_q0 != NULL) {			\
		(eager)->tcp_eager_next_drop_q0->tcp_eager_prev_drop_q0	\
		    = (eager)->tcp_eager_prev_drop_q0;			\
		(eager)->tcp_eager_prev_drop_q0->tcp_eager_next_drop_q0	\
		    = (eager)->tcp_eager_next_drop_q0;			\
		(eager)->tcp_eager_prev_drop_q0 = NULL;			\
		(eager)->tcp_eager_next_drop_q0 = NULL;			\
	}

/*
 * If tcp_drop_ack_unsent_cnt is greater than 0, when TCP receives more
 * than tcp_drop_ack_unsent_cnt number of ACKs which acknowledge unsent
 * data, TCP will not respond with an ACK.  RFC 793 requires that
 * TCP responds with an ACK for such a bogus ACK.  By not following
 * the RFC, we prevent TCP from getting into an ACK storm if somehow
 * an attacker successfully spoofs an acceptable segment to our
 * peer; or when our peer is "confused."
 */
uint32_t tcp_drop_ack_unsent_cnt = 10;

/*
 * Hook functions to enable cluster networking
 * On non-clustered systems these vectors must always be NULL.
 */

void (*cl_inet_listen)(netstackid_t stack_id, uint8_t protocol,
			    sa_family_t addr_family, uint8_t *laddrp,
			    in_port_t lport, void *args) = NULL;
void (*cl_inet_unlisten)(netstackid_t stack_id, uint8_t protocol,
			    sa_family_t addr_family, uint8_t *laddrp,
			    in_port_t lport, void *args) = NULL;

int (*cl_inet_connect2)(netstackid_t stack_id, uint8_t protocol,
			    boolean_t is_outgoing,
			    sa_family_t addr_family,
			    uint8_t *laddrp, in_port_t lport,
			    uint8_t *faddrp, in_port_t fport,
			    void *args) = NULL;

void (*cl_inet_disconnect)(netstackid_t stack_id, uint8_t protocol,
			    sa_family_t addr_family, uint8_t *laddrp,
			    in_port_t lport, uint8_t *faddrp,
			    in_port_t fport, void *args) = NULL;

/*
 * The following are defined in ip.c
 */
extern int (*cl_inet_isclusterwide)(netstackid_t stack_id, uint8_t protocol,
			    sa_family_t addr_family, uint8_t *laddrp,
			    void *args);
extern uint32_t (*cl_inet_ipident)(netstackid_t stack_id, uint8_t protocol,
			    sa_family_t addr_family, uint8_t *laddrp,
			    uint8_t *faddrp, void *args);


/*
 * int CL_INET_CONNECT(conn_t *cp, tcp_t *tcp, boolean_t is_outgoing, int err)
 */
#define	CL_INET_CONNECT(connp, tcp, is_outgoing, err) {		\
	(err) = 0;						\
	if (cl_inet_connect2 != NULL) {				\
		/*						\
		 * Running in cluster mode - register active connection	\
		 * information						\
		 */							\
		if ((tcp)->tcp_ipversion == IPV4_VERSION) {		\
			if ((tcp)->tcp_ipha->ipha_src != 0) {		\
				(err) = (*cl_inet_connect2)(		\
				    (connp)->conn_netstack->netstack_stackid,\
				    IPPROTO_TCP, is_outgoing, AF_INET,	\
				    (uint8_t *)(&((tcp)->tcp_ipha->ipha_src)),\
				    (in_port_t)(tcp)->tcp_lport,	\
				    (uint8_t *)(&((tcp)->tcp_ipha->ipha_dst)),\
				    (in_port_t)(tcp)->tcp_fport, NULL);	\
			}						\
		} else {						\
			if (!IN6_IS_ADDR_UNSPECIFIED(			\
			    &(tcp)->tcp_ip6h->ip6_src)) {		\
				(err) = (*cl_inet_connect2)(		\
				    (connp)->conn_netstack->netstack_stackid,\
				    IPPROTO_TCP, is_outgoing, AF_INET6,	\
				    (uint8_t *)(&((tcp)->tcp_ip6h->ip6_src)),\
				    (in_port_t)(tcp)->tcp_lport,	\
				    (uint8_t *)(&((tcp)->tcp_ip6h->ip6_dst)),\
				    (in_port_t)(tcp)->tcp_fport, NULL);	\
			}						\
		}							\
	}								\
}

#define	CL_INET_DISCONNECT(connp, tcp)	{				\
	if (cl_inet_disconnect != NULL) {				\
		/*							\
		 * Running in cluster mode - deregister active		\
		 * connection information				\
		 */							\
		if ((tcp)->tcp_ipversion == IPV4_VERSION) {		\
			if ((tcp)->tcp_ip_src != 0) {			\
				(*cl_inet_disconnect)(			\
				    (connp)->conn_netstack->netstack_stackid,\
				    IPPROTO_TCP, AF_INET,		\
				    (uint8_t *)(&((tcp)->tcp_ip_src)),	\
				    (in_port_t)(tcp)->tcp_lport,	\
				    (uint8_t *)(&((tcp)->tcp_ipha->ipha_dst)),\
				    (in_port_t)(tcp)->tcp_fport, NULL);	\
			}						\
		} else {						\
			if (!IN6_IS_ADDR_UNSPECIFIED(			\
			    &(tcp)->tcp_ip_src_v6)) {			\
				(*cl_inet_disconnect)(			\
				    (connp)->conn_netstack->netstack_stackid,\
				    IPPROTO_TCP, AF_INET6,		\
				    (uint8_t *)(&((tcp)->tcp_ip_src_v6)),\
				    (in_port_t)(tcp)->tcp_lport,	\
				    (uint8_t *)(&((tcp)->tcp_ip6h->ip6_dst)),\
				    (in_port_t)(tcp)->tcp_fport, NULL);	\
			}						\
		}							\
	}								\
}

/*
 * Cluster networking hook for traversing current connection list.
 * This routine is used to extract the current list of live connections
 * which must continue to to be dispatched to this node.
 */
int cl_tcp_walk_list(netstackid_t stack_id,
    int (*callback)(cl_tcp_info_t *, void *), void *arg);

static int cl_tcp_walk_list_stack(int (*callback)(cl_tcp_info_t *, void *),
    void *arg, tcp_stack_t *tcps);

#define	DTRACE_IP_FASTPATH(mp, iph, ill, ipha, ip6h) 			\
	DTRACE_IP7(send, mblk_t *, mp, conn_t *, NULL, void_ip_t *,	\
	    iph, __dtrace_ipsr_ill_t *, ill, ipha_t *, ipha,		\
	    ip6_t *, ip6h, int, 0);

/*
 * Figure out the value of window scale opton.  Note that the rwnd is
 * ASSUMED to be rounded up to the nearest MSS before the calculation.
 * We cannot find the scale value and then do a round up of tcp_rwnd
 * because the scale value may not be correct after that.
 *
 * Set the compiler flag to make this function inline.
 */
static void
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
 * Remove a connection from the list of detached TIME_WAIT connections.
 * It returns B_FALSE if it can't remove the connection from the list
 * as the connection has already been removed from the list due to an
 * earlier call to tcp_time_wait_remove(); otherwise it returns B_TRUE.
 */
static boolean_t
tcp_time_wait_remove(tcp_t *tcp, tcp_squeue_priv_t *tcp_time_wait)
{
	boolean_t	locked = B_FALSE;

	if (tcp_time_wait == NULL) {
		tcp_time_wait = *((tcp_squeue_priv_t **)
		    squeue_getprivate(tcp->tcp_connp->conn_sqp, SQPRIVATE_TCP));
		mutex_enter(&tcp_time_wait->tcp_time_wait_lock);
		locked = B_TRUE;
	} else {
		ASSERT(MUTEX_HELD(&tcp_time_wait->tcp_time_wait_lock));
	}

	if (tcp->tcp_time_wait_expire == 0) {
		ASSERT(tcp->tcp_time_wait_next == NULL);
		ASSERT(tcp->tcp_time_wait_prev == NULL);
		if (locked)
			mutex_exit(&tcp_time_wait->tcp_time_wait_lock);
		return (B_FALSE);
	}
	ASSERT(TCP_IS_DETACHED(tcp));
	ASSERT(tcp->tcp_state == TCPS_TIME_WAIT);

	if (tcp == tcp_time_wait->tcp_time_wait_head) {
		ASSERT(tcp->tcp_time_wait_prev == NULL);
		tcp_time_wait->tcp_time_wait_head = tcp->tcp_time_wait_next;
		if (tcp_time_wait->tcp_time_wait_head != NULL) {
			tcp_time_wait->tcp_time_wait_head->tcp_time_wait_prev =
			    NULL;
		} else {
			tcp_time_wait->tcp_time_wait_tail = NULL;
		}
	} else if (tcp == tcp_time_wait->tcp_time_wait_tail) {
		ASSERT(tcp != tcp_time_wait->tcp_time_wait_head);
		ASSERT(tcp->tcp_time_wait_next == NULL);
		tcp_time_wait->tcp_time_wait_tail = tcp->tcp_time_wait_prev;
		ASSERT(tcp_time_wait->tcp_time_wait_tail != NULL);
		tcp_time_wait->tcp_time_wait_tail->tcp_time_wait_next = NULL;
	} else {
		ASSERT(tcp->tcp_time_wait_prev->tcp_time_wait_next == tcp);
		ASSERT(tcp->tcp_time_wait_next->tcp_time_wait_prev == tcp);
		tcp->tcp_time_wait_prev->tcp_time_wait_next =
		    tcp->tcp_time_wait_next;
		tcp->tcp_time_wait_next->tcp_time_wait_prev =
		    tcp->tcp_time_wait_prev;
	}
	tcp->tcp_time_wait_next = NULL;
	tcp->tcp_time_wait_prev = NULL;
	tcp->tcp_time_wait_expire = 0;

	if (locked)
		mutex_exit(&tcp_time_wait->tcp_time_wait_lock);
	return (B_TRUE);
}

/*
 * Add a connection to the list of detached TIME_WAIT connections
 * and set its time to expire.
 */
static void
tcp_time_wait_append(tcp_t *tcp)
{
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	tcp_squeue_priv_t *tcp_time_wait =
	    *((tcp_squeue_priv_t **)squeue_getprivate(tcp->tcp_connp->conn_sqp,
	    SQPRIVATE_TCP));

	tcp_timers_stop(tcp);

	/* Freed above */
	ASSERT(tcp->tcp_timer_tid == 0);
	ASSERT(tcp->tcp_ack_tid == 0);

	/* must have happened at the time of detaching the tcp */
	ASSERT(tcp->tcp_ptpahn == NULL);
	ASSERT(tcp->tcp_flow_stopped == 0);
	ASSERT(tcp->tcp_time_wait_next == NULL);
	ASSERT(tcp->tcp_time_wait_prev == NULL);
	ASSERT(tcp->tcp_time_wait_expire == NULL);
	ASSERT(tcp->tcp_listener == NULL);

	tcp->tcp_time_wait_expire = ddi_get_lbolt();
	/*
	 * The value computed below in tcp->tcp_time_wait_expire may
	 * appear negative or wrap around. That is ok since our
	 * interest is only in the difference between the current lbolt
	 * value and tcp->tcp_time_wait_expire. But the value should not
	 * be zero, since it means the tcp is not in the TIME_WAIT list.
	 * The corresponding comparison in tcp_time_wait_collector() uses
	 * modular arithmetic.
	 */
	tcp->tcp_time_wait_expire +=
	    drv_usectohz(tcps->tcps_time_wait_interval * 1000);
	if (tcp->tcp_time_wait_expire == 0)
		tcp->tcp_time_wait_expire = 1;

	ASSERT(TCP_IS_DETACHED(tcp));
	ASSERT(tcp->tcp_state == TCPS_TIME_WAIT);
	ASSERT(tcp->tcp_time_wait_next == NULL);
	ASSERT(tcp->tcp_time_wait_prev == NULL);
	TCP_DBGSTAT(tcps, tcp_time_wait);

	mutex_enter(&tcp_time_wait->tcp_time_wait_lock);
	if (tcp_time_wait->tcp_time_wait_head == NULL) {
		ASSERT(tcp_time_wait->tcp_time_wait_tail == NULL);
		tcp_time_wait->tcp_time_wait_head = tcp;
	} else {
		ASSERT(tcp_time_wait->tcp_time_wait_tail != NULL);
		ASSERT(tcp_time_wait->tcp_time_wait_tail->tcp_state ==
		    TCPS_TIME_WAIT);
		tcp_time_wait->tcp_time_wait_tail->tcp_time_wait_next = tcp;
		tcp->tcp_time_wait_prev = tcp_time_wait->tcp_time_wait_tail;
	}
	tcp_time_wait->tcp_time_wait_tail = tcp;
	mutex_exit(&tcp_time_wait->tcp_time_wait_lock);
}

/* ARGSUSED */
void
tcp_timewait_output(void *arg, mblk_t *mp, void *arg2)
{
	conn_t	*connp = (conn_t *)arg;
	tcp_t	*tcp = connp->conn_tcp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	ASSERT(tcp != NULL);
	if (tcp->tcp_state == TCPS_CLOSED) {
		return;
	}

	ASSERT((tcp->tcp_family == AF_INET &&
	    tcp->tcp_ipversion == IPV4_VERSION) ||
	    (tcp->tcp_family == AF_INET6 &&
	    (tcp->tcp_ipversion == IPV4_VERSION ||
	    tcp->tcp_ipversion == IPV6_VERSION)));
	ASSERT(!tcp->tcp_listener);

	TCP_STAT(tcps, tcp_time_wait_reap);
	ASSERT(TCP_IS_DETACHED(tcp));

	/*
	 * Because they have no upstream client to rebind or tcp_close()
	 * them later, we axe the connection here and now.
	 */
	tcp_close_detached(tcp);
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
		IPLATCH_REFRELE(connp->conn_latch,
		    connp->conn_netstack);
		connp->conn_latch = NULL;
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
	char		*tcp_iphc;
	int		tcp_iphc_len;
	int		tcp_hdr_grown;
	tcp_sack_info_t	*tcp_sack_info;
	conn_t		*connp = tcp->tcp_connp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	netstack_t	*ns = tcps->tcps_netstack;
	mblk_t		*tcp_rsrv_mp;

	tcp_bind_hash_remove(tcp);

	/* Cleanup that which needs the netstack first */
	tcp_ipsec_cleanup(tcp);

	tcp_free(tcp);

	/* Release any SSL context */
	if (tcp->tcp_kssl_ent != NULL) {
		kssl_release_ent(tcp->tcp_kssl_ent, NULL, KSSL_NO_PROXY);
		tcp->tcp_kssl_ent = NULL;
	}

	if (tcp->tcp_kssl_ctx != NULL) {
		kssl_release_ctx(tcp->tcp_kssl_ctx);
		tcp->tcp_kssl_ctx = NULL;
	}
	tcp->tcp_kssl_pending = B_FALSE;

	conn_delete_ire(connp, NULL);

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

	/*
	 * Now it is safe to decrement the reference counts.
	 * This might be the last reference on the netstack and TCPS
	 * in which case it will cause the tcp_g_q_close and
	 * the freeing of the IP Instance.
	 */
	connp->conn_netstack = NULL;
	netstack_rele(ns);
	ASSERT(tcps != NULL);
	tcp->tcp_tcps = NULL;
	TCPS_REFRELE(tcps);

	/* Save some state */
	mp = tcp->tcp_timercache;

	tcp_sack_info = tcp->tcp_sack_info;
	tcp_iphc = tcp->tcp_iphc;
	tcp_iphc_len = tcp->tcp_iphc_len;
	tcp_hdr_grown = tcp->tcp_hdr_grown;
	tcp_rsrv_mp = tcp->tcp_rsrv_mp;

	if (connp->conn_cred != NULL) {
		crfree(connp->conn_cred);
		connp->conn_cred = NULL;
	}
	if (connp->conn_peercred != NULL) {
		crfree(connp->conn_peercred);
		connp->conn_peercred = NULL;
	}
	ipcl_conn_cleanup(connp);
	connp->conn_flags = IPCL_TCPCONN;
	bzero(tcp, sizeof (tcp_t));

	/* restore the state */
	tcp->tcp_timercache = mp;

	tcp->tcp_sack_info = tcp_sack_info;
	tcp->tcp_iphc = tcp_iphc;
	tcp->tcp_iphc_len = tcp_iphc_len;
	tcp->tcp_hdr_grown = tcp_hdr_grown;
	tcp->tcp_rsrv_mp = tcp_rsrv_mp;

	tcp->tcp_connp = connp;

	ASSERT(connp->conn_tcp == tcp);
	ASSERT(connp->conn_flags & IPCL_TCPCONN);
	connp->conn_state_flags = CONN_INCIPIENT;
	ASSERT(connp->conn_ulp == IPPROTO_TCP);
	ASSERT(connp->conn_ref == 1);
}

/*
 * Blows away all tcps whose TIME_WAIT has expired. List traversal
 * is done forwards from the head.
 * This walks all stack instances since
 * tcp_time_wait remains global across all stacks.
 */
/* ARGSUSED */
void
tcp_time_wait_collector(void *arg)
{
	tcp_t *tcp;
	clock_t now;
	mblk_t *mp;
	conn_t *connp;
	kmutex_t *lock;
	boolean_t removed;

	squeue_t *sqp = (squeue_t *)arg;
	tcp_squeue_priv_t *tcp_time_wait =
	    *((tcp_squeue_priv_t **)squeue_getprivate(sqp, SQPRIVATE_TCP));

	mutex_enter(&tcp_time_wait->tcp_time_wait_lock);
	tcp_time_wait->tcp_time_wait_tid = 0;

	if (tcp_time_wait->tcp_free_list != NULL &&
	    tcp_time_wait->tcp_free_list->tcp_in_free_list == B_TRUE) {
		TCP_G_STAT(tcp_freelist_cleanup);
		while ((tcp = tcp_time_wait->tcp_free_list) != NULL) {
			tcp_time_wait->tcp_free_list = tcp->tcp_time_wait_next;
			tcp->tcp_time_wait_next = NULL;
			tcp_time_wait->tcp_free_list_cnt--;
			ASSERT(tcp->tcp_tcps == NULL);
			CONN_DEC_REF(tcp->tcp_connp);
		}
		ASSERT(tcp_time_wait->tcp_free_list_cnt == 0);
	}

	/*
	 * In order to reap time waits reliably, we should use a
	 * source of time that is not adjustable by the user -- hence
	 * the call to ddi_get_lbolt().
	 */
	now = ddi_get_lbolt();
	while ((tcp = tcp_time_wait->tcp_time_wait_head) != NULL) {
		/*
		 * Compare times using modular arithmetic, since
		 * lbolt can wrapover.
		 */
		if ((now - tcp->tcp_time_wait_expire) < 0) {
			break;
		}

		removed = tcp_time_wait_remove(tcp, tcp_time_wait);
		ASSERT(removed);

		connp = tcp->tcp_connp;
		ASSERT(connp->conn_fanout != NULL);
		lock = &connp->conn_fanout->connf_lock;
		/*
		 * This is essentially a TW reclaim fast path optimization for
		 * performance where the timewait collector checks under the
		 * fanout lock (so that no one else can get access to the
		 * conn_t) that the refcnt is 2 i.e. one for TCP and one for
		 * the classifier hash list. If ref count is indeed 2, we can
		 * just remove the conn under the fanout lock and avoid
		 * cleaning up the conn under the squeue, provided that
		 * clustering callbacks are not enabled. If clustering is
		 * enabled, we need to make the clustering callback before
		 * setting the CONDEMNED flag and after dropping all locks and
		 * so we forego this optimization and fall back to the slow
		 * path. Also please see the comments in tcp_closei_local
		 * regarding the refcnt logic.
		 *
		 * Since we are holding the tcp_time_wait_lock, its better
		 * not to block on the fanout_lock because other connections
		 * can't add themselves to time_wait list. So we do a
		 * tryenter instead of mutex_enter.
		 */
		if (mutex_tryenter(lock)) {
			mutex_enter(&connp->conn_lock);
			if ((connp->conn_ref == 2) &&
			    (cl_inet_disconnect == NULL)) {
				ipcl_hash_remove_locked(connp,
				    connp->conn_fanout);
				/*
				 * Set the CONDEMNED flag now itself so that
				 * the refcnt cannot increase due to any
				 * walker. But we have still not cleaned up
				 * conn_ire_cache. This is still ok since
				 * we are going to clean it up in tcp_cleanup
				 * immediately and any interface unplumb
				 * thread will wait till the ire is blown away
				 */
				connp->conn_state_flags |= CONN_CONDEMNED;
				mutex_exit(lock);
				mutex_exit(&connp->conn_lock);
				if (tcp_time_wait->tcp_free_list_cnt <
				    tcp_free_list_max_cnt) {
					/* Add to head of tcp_free_list */
					mutex_exit(
					    &tcp_time_wait->tcp_time_wait_lock);
					tcp_cleanup(tcp);
					ASSERT(connp->conn_latch == NULL);
					ASSERT(connp->conn_policy == NULL);
					ASSERT(tcp->tcp_tcps == NULL);
					ASSERT(connp->conn_netstack == NULL);

					mutex_enter(
					    &tcp_time_wait->tcp_time_wait_lock);
					tcp->tcp_time_wait_next =
					    tcp_time_wait->tcp_free_list;
					tcp_time_wait->tcp_free_list = tcp;
					tcp_time_wait->tcp_free_list_cnt++;
					continue;
				} else {
					/* Do not add to tcp_free_list */
					mutex_exit(
					    &tcp_time_wait->tcp_time_wait_lock);
					tcp_bind_hash_remove(tcp);
					conn_delete_ire(tcp->tcp_connp, NULL);
					tcp_ipsec_cleanup(tcp);
					CONN_DEC_REF(tcp->tcp_connp);
				}
			} else {
				CONN_INC_REF_LOCKED(connp);
				mutex_exit(lock);
				mutex_exit(&tcp_time_wait->tcp_time_wait_lock);
				mutex_exit(&connp->conn_lock);
				/*
				 * We can reuse the closemp here since conn has
				 * detached (otherwise we wouldn't even be in
				 * time_wait list). tcp_closemp_used can safely
				 * be changed without taking a lock as no other
				 * thread can concurrently access it at this
				 * point in the connection lifecycle.
				 */

				if (tcp->tcp_closemp.b_prev == NULL)
					tcp->tcp_closemp_used = B_TRUE;
				else
					cmn_err(CE_PANIC,
					    "tcp_timewait_collector: "
					    "concurrent use of tcp_closemp: "
					    "connp %p tcp %p\n", (void *)connp,
					    (void *)tcp);

				TCP_DEBUG_GETPCSTACK(tcp->tcmp_stk, 15);
				mp = &tcp->tcp_closemp;
				SQUEUE_ENTER_ONE(connp->conn_sqp, mp,
				    tcp_timewait_output, connp,
				    SQ_FILL, SQTAG_TCP_TIMEWAIT);
			}
		} else {
			mutex_enter(&connp->conn_lock);
			CONN_INC_REF_LOCKED(connp);
			mutex_exit(&tcp_time_wait->tcp_time_wait_lock);
			mutex_exit(&connp->conn_lock);
			/*
			 * We can reuse the closemp here since conn has
			 * detached (otherwise we wouldn't even be in
			 * time_wait list). tcp_closemp_used can safely
			 * be changed without taking a lock as no other
			 * thread can concurrently access it at this
			 * point in the connection lifecycle.
			 */

			if (tcp->tcp_closemp.b_prev == NULL)
				tcp->tcp_closemp_used = B_TRUE;
			else
				cmn_err(CE_PANIC, "tcp_timewait_collector: "
				    "concurrent use of tcp_closemp: "
				    "connp %p tcp %p\n", (void *)connp,
				    (void *)tcp);

			TCP_DEBUG_GETPCSTACK(tcp->tcmp_stk, 15);
			mp = &tcp->tcp_closemp;
			SQUEUE_ENTER_ONE(connp->conn_sqp, mp,
			    tcp_timewait_output, connp,
			    SQ_FILL, SQTAG_TCP_TIMEWAIT);
		}
		mutex_enter(&tcp_time_wait->tcp_time_wait_lock);
	}

	if (tcp_time_wait->tcp_free_list != NULL)
		tcp_time_wait->tcp_free_list->tcp_in_free_list = B_TRUE;

	tcp_time_wait->tcp_time_wait_tid =
	    timeout_generic(CALLOUT_NORMAL, tcp_time_wait_collector, sqp,
	    TICK_TO_NSEC(TCP_TIME_WAIT_DELAY), CALLOUT_TCP_RESOLUTION,
	    CALLOUT_FLAG_ROUNDUP);
	mutex_exit(&tcp_time_wait->tcp_time_wait_lock);
}

/*
 * Reply to a clients T_CONN_RES TPI message. This function
 * is used only for TLI/XTI listener. Sockfs sends T_CONN_RES
 * on the acceptor STREAM and processed in tcp_wput_accept().
 * Read the block comment on top of tcp_conn_request().
 */
static void
tcp_tli_accept(tcp_t *listener, mblk_t *mp)
{
	tcp_t	*acceptor;
	tcp_t	*eager;
	tcp_t   *tcp;
	struct T_conn_res	*tcr;
	t_uscalar_t	acceptor_id;
	t_scalar_t	seqnum;
	mblk_t	*opt_mp = NULL;	/* T_OPTMGMT_REQ messages */
	struct tcp_options *tcpopt;
	mblk_t	*ok_mp;
	mblk_t	*mp1;
	tcp_stack_t	*tcps = listener->tcp_tcps;

	if ((mp->b_wptr - mp->b_rptr) < sizeof (*tcr)) {
		tcp_err_ack(listener, mp, TPROTO, 0);
		return;
	}
	tcr = (struct T_conn_res *)mp->b_rptr;

	/*
	 * Under ILP32 the stream head points tcr->ACCEPTOR_id at the
	 * read side queue of the streams device underneath us i.e. the
	 * read side queue of 'ip'. Since we can't deference QUEUE_ptr we
	 * look it up in the queue_hash.  Under LP64 it sends down the
	 * minor_t of the accepting endpoint.
	 *
	 * Once the acceptor/eager are modified (in tcp_accept_swap) the
	 * fanout hash lock is held.
	 * This prevents any thread from entering the acceptor queue from
	 * below (since it has not been hard bound yet i.e. any inbound
	 * packets will arrive on the listener or default tcp queue and
	 * go through tcp_lookup).
	 * The CONN_INC_REF will prevent the acceptor from closing.
	 *
	 * XXX It is still possible for a tli application to send down data
	 * on the accepting stream while another thread calls t_accept.
	 * This should not be a problem for well-behaved applications since
	 * the T_OK_ACK is sent after the queue swapping is completed.
	 *
	 * If the accepting fd is the same as the listening fd, avoid
	 * queue hash lookup since that will return an eager listener in a
	 * already established state.
	 */
	acceptor_id = tcr->ACCEPTOR_id;
	mutex_enter(&listener->tcp_eager_lock);
	if (listener->tcp_acceptor_id == acceptor_id) {
		eager = listener->tcp_eager_next_q;
		/* only count how many T_CONN_INDs so don't count q0 */
		if ((listener->tcp_conn_req_cnt_q != 1) ||
		    (eager->tcp_conn_req_seqnum != tcr->SEQ_number)) {
			mutex_exit(&listener->tcp_eager_lock);
			tcp_err_ack(listener, mp, TBADF, 0);
			return;
		}
		if (listener->tcp_conn_req_cnt_q0 != 0) {
			/* Throw away all the eagers on q0. */
			tcp_eager_cleanup(listener, 1);
		}
		if (listener->tcp_syn_defense) {
			listener->tcp_syn_defense = B_FALSE;
			if (listener->tcp_ip_addr_cache != NULL) {
				kmem_free(listener->tcp_ip_addr_cache,
				    IP_ADDR_CACHE_SIZE * sizeof (ipaddr_t));
				listener->tcp_ip_addr_cache = NULL;
			}
		}
		/*
		 * Transfer tcp_conn_req_max to the eager so that when
		 * a disconnect occurs we can revert the endpoint to the
		 * listen state.
		 */
		eager->tcp_conn_req_max = listener->tcp_conn_req_max;
		ASSERT(listener->tcp_conn_req_cnt_q0 == 0);
		/*
		 * Get a reference on the acceptor just like the
		 * tcp_acceptor_hash_lookup below.
		 */
		acceptor = listener;
		CONN_INC_REF(acceptor->tcp_connp);
	} else {
		acceptor = tcp_acceptor_hash_lookup(acceptor_id, tcps);
		if (acceptor == NULL) {
			if (listener->tcp_debug) {
				(void) strlog(TCP_MOD_ID, 0, 1,
				    SL_ERROR|SL_TRACE,
				    "tcp_accept: did not find acceptor 0x%x\n",
				    acceptor_id);
			}
			mutex_exit(&listener->tcp_eager_lock);
			tcp_err_ack(listener, mp, TPROVMISMATCH, 0);
			return;
		}
		/*
		 * Verify acceptor state. The acceptable states for an acceptor
		 * include TCPS_IDLE and TCPS_BOUND.
		 */
		switch (acceptor->tcp_state) {
		case TCPS_IDLE:
			/* FALLTHRU */
		case TCPS_BOUND:
			break;
		default:
			CONN_DEC_REF(acceptor->tcp_connp);
			mutex_exit(&listener->tcp_eager_lock);
			tcp_err_ack(listener, mp, TOUTSTATE, 0);
			return;
		}
	}

	/* The listener must be in TCPS_LISTEN */
	if (listener->tcp_state != TCPS_LISTEN) {
		CONN_DEC_REF(acceptor->tcp_connp);
		mutex_exit(&listener->tcp_eager_lock);
		tcp_err_ack(listener, mp, TOUTSTATE, 0);
		return;
	}

	/*
	 * Rendezvous with an eager connection request packet hanging off
	 * 'tcp' that has the 'seqnum' tag.  We tagged the detached open
	 * tcp structure when the connection packet arrived in
	 * tcp_conn_request().
	 */
	seqnum = tcr->SEQ_number;
	eager = listener;
	do {
		eager = eager->tcp_eager_next_q;
		if (eager == NULL) {
			CONN_DEC_REF(acceptor->tcp_connp);
			mutex_exit(&listener->tcp_eager_lock);
			tcp_err_ack(listener, mp, TBADSEQ, 0);
			return;
		}
	} while (eager->tcp_conn_req_seqnum != seqnum);
	mutex_exit(&listener->tcp_eager_lock);

	/*
	 * At this point, both acceptor and listener have 2 ref
	 * that they begin with. Acceptor has one additional ref
	 * we placed in lookup while listener has 3 additional
	 * ref for being behind the squeue (tcp_accept() is
	 * done on listener's squeue); being in classifier hash;
	 * and eager's ref on listener.
	 */
	ASSERT(listener->tcp_connp->conn_ref >= 5);
	ASSERT(acceptor->tcp_connp->conn_ref >= 3);

	/*
	 * The eager at this point is set in its own squeue and
	 * could easily have been killed (tcp_accept_finish will
	 * deal with that) because of a TH_RST so we can only
	 * ASSERT for a single ref.
	 */
	ASSERT(eager->tcp_connp->conn_ref >= 1);

	/* Pre allocate the stroptions mblk also */
	opt_mp = allocb(MAX(sizeof (struct tcp_options),
	    sizeof (struct T_conn_res)), BPRI_HI);
	if (opt_mp == NULL) {
		CONN_DEC_REF(acceptor->tcp_connp);
		CONN_DEC_REF(eager->tcp_connp);
		tcp_err_ack(listener, mp, TSYSERR, ENOMEM);
		return;
	}
	DB_TYPE(opt_mp) = M_SETOPTS;
	opt_mp->b_wptr += sizeof (struct tcp_options);
	tcpopt = (struct tcp_options *)opt_mp->b_rptr;
	tcpopt->to_flags = 0;

	/*
	 * Prepare for inheriting IPV6_BOUND_IF and IPV6_RECVPKTINFO
	 * from listener to acceptor.
	 */
	if (listener->tcp_bound_if != 0) {
		tcpopt->to_flags |= TCPOPT_BOUNDIF;
		tcpopt->to_boundif = listener->tcp_bound_if;
	}
	if (listener->tcp_ipv6_recvancillary & TCP_IPV6_RECVPKTINFO) {
		tcpopt->to_flags |= TCPOPT_RECVPKTINFO;
	}

	/* Re-use mp1 to hold a copy of mp, in case reallocb fails */
	if ((mp1 = copymsg(mp)) == NULL) {
		CONN_DEC_REF(acceptor->tcp_connp);
		CONN_DEC_REF(eager->tcp_connp);
		freemsg(opt_mp);
		tcp_err_ack(listener, mp, TSYSERR, ENOMEM);
		return;
	}

	tcr = (struct T_conn_res *)mp1->b_rptr;

	/*
	 * This is an expanded version of mi_tpi_ok_ack_alloc()
	 * which allocates a larger mblk and appends the new
	 * local address to the ok_ack.  The address is copied by
	 * soaccept() for getsockname().
	 */
	{
		int extra;

		extra = (eager->tcp_family == AF_INET) ?
		    sizeof (sin_t) : sizeof (sin6_t);

		/*
		 * Try to re-use mp, if possible.  Otherwise, allocate
		 * an mblk and return it as ok_mp.  In any case, mp
		 * is no longer usable upon return.
		 */
		if ((ok_mp = mi_tpi_ok_ack_alloc_extra(mp, extra)) == NULL) {
			CONN_DEC_REF(acceptor->tcp_connp);
			CONN_DEC_REF(eager->tcp_connp);
			freemsg(opt_mp);
			/* Original mp has been freed by now, so use mp1 */
			tcp_err_ack(listener, mp1, TSYSERR, ENOMEM);
			return;
		}

		mp = NULL;	/* We should never use mp after this point */

		switch (extra) {
		case sizeof (sin_t): {
				sin_t *sin = (sin_t *)ok_mp->b_wptr;

				ok_mp->b_wptr += extra;
				sin->sin_family = AF_INET;
				sin->sin_port = eager->tcp_lport;
				sin->sin_addr.s_addr =
				    eager->tcp_ipha->ipha_src;
				break;
			}
		case sizeof (sin6_t): {
				sin6_t *sin6 = (sin6_t *)ok_mp->b_wptr;

				ok_mp->b_wptr += extra;
				sin6->sin6_family = AF_INET6;
				sin6->sin6_port = eager->tcp_lport;
				if (eager->tcp_ipversion == IPV4_VERSION) {
					sin6->sin6_flowinfo = 0;
					IN6_IPADDR_TO_V4MAPPED(
					    eager->tcp_ipha->ipha_src,
					    &sin6->sin6_addr);
				} else {
					ASSERT(eager->tcp_ip6h != NULL);
					sin6->sin6_flowinfo =
					    eager->tcp_ip6h->ip6_vcf &
					    ~IPV6_VERS_AND_FLOW_MASK;
					sin6->sin6_addr =
					    eager->tcp_ip6h->ip6_src;
				}
				sin6->sin6_scope_id = 0;
				sin6->__sin6_src_id = 0;
				break;
			}
		default:
			break;
		}
		ASSERT(ok_mp->b_wptr <= ok_mp->b_datap->db_lim);
	}

	/*
	 * If there are no options we know that the T_CONN_RES will
	 * succeed. However, we can't send the T_OK_ACK upstream until
	 * the tcp_accept_swap is done since it would be dangerous to
	 * let the application start using the new fd prior to the swap.
	 */
	tcp_accept_swap(listener, acceptor, eager);

	/*
	 * tcp_accept_swap unlinks eager from listener but does not drop
	 * the eager's reference on the listener.
	 */
	ASSERT(eager->tcp_listener == NULL);
	ASSERT(listener->tcp_connp->conn_ref >= 5);

	/*
	 * The eager is now associated with its own queue. Insert in
	 * the hash so that the connection can be reused for a future
	 * T_CONN_RES.
	 */
	tcp_acceptor_hash_insert(acceptor_id, eager);

	/*
	 * We now do the processing of options with T_CONN_RES.
	 * We delay till now since we wanted to have queue to pass to
	 * option processing routines that points back to the right
	 * instance structure which does not happen until after
	 * tcp_accept_swap().
	 *
	 * Note:
	 * The sanity of the logic here assumes that whatever options
	 * are appropriate to inherit from listner=>eager are done
	 * before this point, and whatever were to be overridden (or not)
	 * in transfer logic from eager=>acceptor in tcp_accept_swap().
	 * [ Warning: acceptor endpoint can have T_OPTMGMT_REQ done to it
	 *   before its ACCEPTOR_id comes down in T_CONN_RES ]
	 * This may not be true at this point in time but can be fixed
	 * independently. This option processing code starts with
	 * the instantiated acceptor instance and the final queue at
	 * this point.
	 */

	if (tcr->OPT_length != 0) {
		/* Options to process */
		int t_error = 0;
		int sys_error = 0;
		int do_disconnect = 0;

		if (tcp_conprim_opt_process(eager, mp1,
		    &do_disconnect, &t_error, &sys_error) < 0) {
			eager->tcp_accept_error = 1;
			if (do_disconnect) {
				/*
				 * An option failed which does not allow
				 * connection to be accepted.
				 *
				 * We allow T_CONN_RES to succeed and
				 * put a T_DISCON_IND on the eager queue.
				 */
				ASSERT(t_error == 0 && sys_error == 0);
				eager->tcp_send_discon_ind = 1;
			} else {
				ASSERT(t_error != 0);
				freemsg(ok_mp);
				/*
				 * Original mp was either freed or set
				 * to ok_mp above, so use mp1 instead.
				 */
				tcp_err_ack(listener, mp1, t_error, sys_error);
				goto finish;
			}
		}
		/*
		 * Most likely success in setting options (except if
		 * eager->tcp_send_discon_ind set).
		 * mp1 option buffer represented by OPT_length/offset
		 * potentially modified and contains results of setting
		 * options at this point
		 */
	}

	/* We no longer need mp1, since all options processing has passed */
	freemsg(mp1);

	putnext(listener->tcp_rq, ok_mp);

	mutex_enter(&listener->tcp_eager_lock);
	if (listener->tcp_eager_prev_q0->tcp_conn_def_q0) {
		tcp_t	*tail;
		mblk_t	*conn_ind;

		/*
		 * This path should not be executed if listener and
		 * acceptor streams are the same.
		 */
		ASSERT(listener != acceptor);

		tcp = listener->tcp_eager_prev_q0;
		/*
		 * listener->tcp_eager_prev_q0 points to the TAIL of the
		 * deferred T_conn_ind queue. We need to get to the head of
		 * the queue in order to send up T_conn_ind the same order as
		 * how the 3WHS is completed.
		 */
		while (tcp != listener) {
			if (!tcp->tcp_eager_prev_q0->tcp_conn_def_q0)
				break;
			else
				tcp = tcp->tcp_eager_prev_q0;
		}
		ASSERT(tcp != listener);
		conn_ind = tcp->tcp_conn.tcp_eager_conn_ind;
		ASSERT(conn_ind != NULL);
		tcp->tcp_conn.tcp_eager_conn_ind = NULL;

		/* Move from q0 to q */
		ASSERT(listener->tcp_conn_req_cnt_q0 > 0);
		listener->tcp_conn_req_cnt_q0--;
		listener->tcp_conn_req_cnt_q++;
		tcp->tcp_eager_next_q0->tcp_eager_prev_q0 =
		    tcp->tcp_eager_prev_q0;
		tcp->tcp_eager_prev_q0->tcp_eager_next_q0 =
		    tcp->tcp_eager_next_q0;
		tcp->tcp_eager_prev_q0 = NULL;
		tcp->tcp_eager_next_q0 = NULL;
		tcp->tcp_conn_def_q0 = B_FALSE;

		/* Make sure the tcp isn't in the list of droppables */
		ASSERT(tcp->tcp_eager_next_drop_q0 == NULL &&
		    tcp->tcp_eager_prev_drop_q0 == NULL);

		/*
		 * Insert at end of the queue because sockfs sends
		 * down T_CONN_RES in chronological order. Leaving
		 * the older conn indications at front of the queue
		 * helps reducing search time.
		 */
		tail = listener->tcp_eager_last_q;
		if (tail != NULL)
			tail->tcp_eager_next_q = tcp;
		else
			listener->tcp_eager_next_q = tcp;
		listener->tcp_eager_last_q = tcp;
		tcp->tcp_eager_next_q = NULL;
		mutex_exit(&listener->tcp_eager_lock);
		putnext(tcp->tcp_rq, conn_ind);
	} else {
		mutex_exit(&listener->tcp_eager_lock);
	}

	/*
	 * Done with the acceptor - free it
	 *
	 * Note: from this point on, no access to listener should be made
	 * as listener can be equal to acceptor.
	 */
finish:
	ASSERT(acceptor->tcp_detached);
	ASSERT(tcps->tcps_g_q != NULL);
	ASSERT(!IPCL_IS_NONSTR(acceptor->tcp_connp));
	acceptor->tcp_rq = tcps->tcps_g_q;
	acceptor->tcp_wq = WR(tcps->tcps_g_q);
	(void) tcp_clean_death(acceptor, 0, 2);
	CONN_DEC_REF(acceptor->tcp_connp);

	/*
	 * In case we already received a FIN we have to make tcp_rput send
	 * the ordrel_ind. This will also send up a window update if the window
	 * has opened up.
	 *
	 * In the normal case of a successful connection acceptance
	 * we give the O_T_BIND_REQ to the read side put procedure as an
	 * indication that this was just accepted. This tells tcp_rput to
	 * pass up any data queued in tcp_rcv_list.
	 *
	 * In the fringe case where options sent with T_CONN_RES failed and
	 * we required, we would be indicating a T_DISCON_IND to blow
	 * away this connection.
	 */

	/*
	 * XXX: we currently have a problem if XTI application closes the
	 * acceptor stream in between. This problem exists in on10-gate also
	 * and is well know but nothing can be done short of major rewrite
	 * to fix it. Now it is possible to take care of it by assigning TLI/XTI
	 * eager same squeue as listener (we can distinguish non socket
	 * listeners at the time of handling a SYN in tcp_conn_request)
	 * and do most of the work that tcp_accept_finish does here itself
	 * and then get behind the acceptor squeue to access the acceptor
	 * queue.
	 */
	/*
	 * We already have a ref on tcp so no need to do one before squeue_enter
	 */
	SQUEUE_ENTER_ONE(eager->tcp_connp->conn_sqp, opt_mp, tcp_accept_finish,
	    eager->tcp_connp, SQ_FILL, SQTAG_TCP_ACCEPT_FINISH);
}

/*
 * Swap information between the eager and acceptor for a TLI/XTI client.
 * The sockfs accept is done on the acceptor stream and control goes
 * through tcp_wput_accept() and tcp_accept()/tcp_accept_swap() is not
 * called. In either case, both the eager and listener are in their own
 * perimeter (squeue) and the code has to deal with potential race.
 *
 * See the block comment on top of tcp_accept() and tcp_wput_accept().
 */
static void
tcp_accept_swap(tcp_t *listener, tcp_t *acceptor, tcp_t *eager)
{
	conn_t	*econnp, *aconnp;

	ASSERT(eager->tcp_rq == listener->tcp_rq);
	ASSERT(eager->tcp_detached && !acceptor->tcp_detached);
	ASSERT(!eager->tcp_hard_bound);
	ASSERT(!TCP_IS_SOCKET(acceptor));
	ASSERT(!TCP_IS_SOCKET(eager));
	ASSERT(!TCP_IS_SOCKET(listener));

	acceptor->tcp_detached = B_TRUE;
	/*
	 * To permit stream re-use by TLI/XTI, the eager needs a copy of
	 * the acceptor id.
	 */
	eager->tcp_acceptor_id = acceptor->tcp_acceptor_id;

	/* remove eager from listen list... */
	mutex_enter(&listener->tcp_eager_lock);
	tcp_eager_unlink(eager);
	ASSERT(eager->tcp_eager_next_q == NULL &&
	    eager->tcp_eager_last_q == NULL);
	ASSERT(eager->tcp_eager_next_q0 == NULL &&
	    eager->tcp_eager_prev_q0 == NULL);
	mutex_exit(&listener->tcp_eager_lock);
	eager->tcp_rq = acceptor->tcp_rq;
	eager->tcp_wq = acceptor->tcp_wq;

	econnp = eager->tcp_connp;
	aconnp = acceptor->tcp_connp;

	eager->tcp_rq->q_ptr = econnp;
	eager->tcp_wq->q_ptr = econnp;

	/*
	 * In the TLI/XTI loopback case, we are inside the listener's squeue,
	 * which might be a different squeue from our peer TCP instance.
	 * For TCP Fusion, the peer expects that whenever tcp_detached is
	 * clear, our TCP queues point to the acceptor's queues.  Thus, use
	 * membar_producer() to ensure that the assignments of tcp_rq/tcp_wq
	 * above reach global visibility prior to the clearing of tcp_detached.
	 */
	membar_producer();
	eager->tcp_detached = B_FALSE;

	ASSERT(eager->tcp_ack_tid == 0);

	econnp->conn_dev = aconnp->conn_dev;
	econnp->conn_minor_arena = aconnp->conn_minor_arena;
	ASSERT(econnp->conn_minor_arena != NULL);
	if (eager->tcp_cred != NULL)
		crfree(eager->tcp_cred);
	eager->tcp_cred = econnp->conn_cred = aconnp->conn_cred;
	ASSERT(econnp->conn_netstack == aconnp->conn_netstack);
	ASSERT(eager->tcp_tcps == acceptor->tcp_tcps);

	aconnp->conn_cred = NULL;

	econnp->conn_zoneid = aconnp->conn_zoneid;
	econnp->conn_allzones = aconnp->conn_allzones;

	econnp->conn_mac_exempt = aconnp->conn_mac_exempt;
	aconnp->conn_mac_exempt = B_FALSE;

	ASSERT(aconnp->conn_peercred == NULL);

	/* Do the IPC initialization */
	CONN_INC_REF(econnp);

	econnp->conn_multicast_loop = aconnp->conn_multicast_loop;
	econnp->conn_af_isv6 = aconnp->conn_af_isv6;
	econnp->conn_pkt_isv6 = aconnp->conn_pkt_isv6;

	/* Done with old IPC. Drop its ref on its connp */
	CONN_DEC_REF(aconnp);
}


/*
 * Adapt to the information, such as rtt and rtt_sd, provided from the
 * ire cached in conn_cache_ire. If no ire cached, do a ire lookup.
 *
 * Checks for multicast and broadcast destination address.
 * Returns zero on failure; non-zero if ok.
 *
 * Note that the MSS calculation here is based on the info given in
 * the IRE.  We do not do any calculation based on TCP options.  They
 * will be handled in tcp_rput_other() and tcp_rput_data() when TCP
 * knows which options to use.
 *
 * Note on how TCP gets its parameters for a connection.
 *
 * When a tcp_t structure is allocated, it gets all the default parameters.
 * In tcp_adapt_ire(), it gets those metric parameters, like rtt, rtt_sd,
 * spipe, rpipe, ... from the route metrics.  Route metric overrides the
 * default.
 *
 * An incoming SYN with a multicast or broadcast destination address, is dropped
 * in 1 of 2 places.
 *
 * 1. If the packet was received over the wire it is dropped in
 * ip_rput_process_broadcast()
 *
 * 2. If the packet was received through internal IP loopback, i.e. the packet
 * was generated and received on the same machine, it is dropped in
 * ip_wput_local()
 *
 * An incoming SYN with a multicast or broadcast source address is always
 * dropped in tcp_adapt_ire. The same logic in tcp_adapt_ire also serves to
 * reject an attempt to connect to a broadcast or multicast (destination)
 * address.
 */
static int
tcp_adapt_ire(tcp_t *tcp, mblk_t *ire_mp)
{
	tcp_hsp_t	*hsp;
	ire_t		*ire;
	ire_t		*sire = NULL;
	iulp_t		*ire_uinfo = NULL;
	uint32_t	mss_max;
	uint32_t	mss;
	boolean_t	tcp_detached = TCP_IS_DETACHED(tcp);
	conn_t		*connp = tcp->tcp_connp;
	boolean_t	ire_cacheable = B_FALSE;
	zoneid_t	zoneid = connp->conn_zoneid;
	int		match_flags = MATCH_IRE_RECURSIVE | MATCH_IRE_DEFAULT |
	    MATCH_IRE_SECATTR;
	ts_label_t	*tsl = crgetlabel(CONN_CRED(connp));
	ill_t		*ill = NULL;
	boolean_t	incoming = (ire_mp == NULL);
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	ip_stack_t	*ipst = tcps->tcps_netstack->netstack_ip;

	ASSERT(connp->conn_ire_cache == NULL);

	if (tcp->tcp_ipversion == IPV4_VERSION) {

		if (CLASSD(tcp->tcp_connp->conn_rem)) {
			BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsInDiscards);
			return (0);
		}
		/*
		 * If IP_NEXTHOP is set, then look for an IRE_CACHE
		 * for the destination with the nexthop as gateway.
		 * ire_ctable_lookup() is used because this particular
		 * ire, if it exists, will be marked private.
		 * If that is not available, use the interface ire
		 * for the nexthop.
		 *
		 * TSol: tcp_update_label will detect label mismatches based
		 * only on the destination's label, but that would not
		 * detect label mismatches based on the security attributes
		 * of routes or next hop gateway. Hence we need to pass the
		 * label to ire_ftable_lookup below in order to locate the
		 * right prefix (and/or) ire cache. Similarly we also need
		 * pass the label to the ire_cache_lookup below to locate
		 * the right ire that also matches on the label.
		 */
		if (tcp->tcp_connp->conn_nexthop_set) {
			ire = ire_ctable_lookup(tcp->tcp_connp->conn_rem,
			    tcp->tcp_connp->conn_nexthop_v4, 0, NULL, zoneid,
			    tsl, MATCH_IRE_MARK_PRIVATE_ADDR | MATCH_IRE_GW,
			    ipst);
			if (ire == NULL) {
				ire = ire_ftable_lookup(
				    tcp->tcp_connp->conn_nexthop_v4,
				    0, 0, IRE_INTERFACE, NULL, NULL, zoneid, 0,
				    tsl, match_flags, ipst);
				if (ire == NULL)
					return (0);
			} else {
				ire_uinfo = &ire->ire_uinfo;
			}
		} else {
			ire = ire_cache_lookup(tcp->tcp_connp->conn_rem,
			    zoneid, tsl, ipst);
			if (ire != NULL) {
				ire_cacheable = B_TRUE;
				ire_uinfo = (ire_mp != NULL) ?
				    &((ire_t *)ire_mp->b_rptr)->ire_uinfo:
				    &ire->ire_uinfo;

			} else {
				if (ire_mp == NULL) {
					ire = ire_ftable_lookup(
					    tcp->tcp_connp->conn_rem,
					    0, 0, 0, NULL, &sire, zoneid, 0,
					    tsl, (MATCH_IRE_RECURSIVE |
					    MATCH_IRE_DEFAULT), ipst);
					if (ire == NULL)
						return (0);
					ire_uinfo = (sire != NULL) ?
					    &sire->ire_uinfo :
					    &ire->ire_uinfo;
				} else {
					ire = (ire_t *)ire_mp->b_rptr;
					ire_uinfo =
					    &((ire_t *)
					    ire_mp->b_rptr)->ire_uinfo;
				}
			}
		}
		ASSERT(ire != NULL);

		if ((ire->ire_src_addr == INADDR_ANY) ||
		    (ire->ire_type & IRE_BROADCAST)) {
			/*
			 * ire->ire_mp is non null when ire_mp passed in is used
			 * ire->ire_mp is set in ip_bind_insert_ire[_v6]().
			 */
			if (ire->ire_mp == NULL)
				ire_refrele(ire);
			if (sire != NULL)
				ire_refrele(sire);
			return (0);
		}

		if (tcp->tcp_ipha->ipha_src == INADDR_ANY) {
			ipaddr_t src_addr;

			/*
			 * ip_bind_connected() has stored the correct source
			 * address in conn_src.
			 */
			src_addr = tcp->tcp_connp->conn_src;
			tcp->tcp_ipha->ipha_src = src_addr;
			/*
			 * Copy of the src addr. in tcp_t is needed
			 * for the lookup funcs.
			 */
			IN6_IPADDR_TO_V4MAPPED(src_addr, &tcp->tcp_ip_src_v6);
		}
		/*
		 * Set the fragment bit so that IP will tell us if the MTU
		 * should change. IP tells us the latest setting of
		 * ip_path_mtu_discovery through ire_frag_flag.
		 */
		if (ipst->ips_ip_path_mtu_discovery) {
			tcp->tcp_ipha->ipha_fragment_offset_and_flags =
			    htons(IPH_DF);
		}
		/*
		 * If ire_uinfo is NULL, this is the IRE_INTERFACE case
		 * for IP_NEXTHOP. No cache ire has been found for the
		 * destination and we are working with the nexthop's
		 * interface ire. Since we need to forward all packets
		 * to the nexthop first, we "blindly" set tcp_localnet
		 * to false, eventhough the destination may also be
		 * onlink.
		 */
		if (ire_uinfo == NULL)
			tcp->tcp_localnet = 0;
		else
			tcp->tcp_localnet = (ire->ire_gateway_addr == 0);
	} else {
		/*
		 * For incoming connection ire_mp = NULL
		 * For outgoing connection ire_mp != NULL
		 * Technically we should check conn_incoming_ill
		 * when ire_mp is NULL and conn_outgoing_ill when
		 * ire_mp is non-NULL. But this is performance
		 * critical path and for IPV*_BOUND_IF, outgoing
		 * and incoming ill are always set to the same value.
		 */
		ill_t	*dst_ill = NULL;
		ipif_t  *dst_ipif = NULL;

		ASSERT(connp->conn_outgoing_ill == connp->conn_incoming_ill);

		if (connp->conn_outgoing_ill != NULL) {
			/* Outgoing or incoming path */
			int   err;

			dst_ill = conn_get_held_ill(connp,
			    &connp->conn_outgoing_ill, &err);
			if (err == ILL_LOOKUP_FAILED || dst_ill == NULL) {
				ip1dbg(("tcp_adapt_ire: ill_lookup failed\n"));
				return (0);
			}
			match_flags |= MATCH_IRE_ILL;
			dst_ipif = dst_ill->ill_ipif;
		}
		ire = ire_ctable_lookup_v6(&tcp->tcp_connp->conn_remv6,
		    0, 0, dst_ipif, zoneid, tsl, match_flags, ipst);

		if (ire != NULL) {
			ire_cacheable = B_TRUE;
			ire_uinfo = (ire_mp != NULL) ?
			    &((ire_t *)ire_mp->b_rptr)->ire_uinfo:
			    &ire->ire_uinfo;
		} else {
			if (ire_mp == NULL) {
				ire = ire_ftable_lookup_v6(
				    &tcp->tcp_connp->conn_remv6,
				    0, 0, 0, dst_ipif, &sire, zoneid,
				    0, tsl, match_flags, ipst);
				if (ire == NULL) {
					if (dst_ill != NULL)
						ill_refrele(dst_ill);
					return (0);
				}
				ire_uinfo = (sire != NULL) ? &sire->ire_uinfo :
				    &ire->ire_uinfo;
			} else {
				ire = (ire_t *)ire_mp->b_rptr;
				ire_uinfo =
				    &((ire_t *)ire_mp->b_rptr)->ire_uinfo;
			}
		}
		if (dst_ill != NULL)
			ill_refrele(dst_ill);

		ASSERT(ire != NULL);
		ASSERT(ire_uinfo != NULL);

		if (IN6_IS_ADDR_UNSPECIFIED(&ire->ire_src_addr_v6) ||
		    IN6_IS_ADDR_MULTICAST(&ire->ire_addr_v6)) {
			/*
			 * ire->ire_mp is non null when ire_mp passed in is used
			 * ire->ire_mp is set in ip_bind_insert_ire[_v6]().
			 */
			if (ire->ire_mp == NULL)
				ire_refrele(ire);
			if (sire != NULL)
				ire_refrele(sire);
			return (0);
		}

		if (IN6_IS_ADDR_UNSPECIFIED(&tcp->tcp_ip6h->ip6_src)) {
			in6_addr_t	src_addr;

			/*
			 * ip_bind_connected_v6() has stored the correct source
			 * address per IPv6 addr. selection policy in
			 * conn_src_v6.
			 */
			src_addr = tcp->tcp_connp->conn_srcv6;

			tcp->tcp_ip6h->ip6_src = src_addr;
			/*
			 * Copy of the src addr. in tcp_t is needed
			 * for the lookup funcs.
			 */
			tcp->tcp_ip_src_v6 = src_addr;
			ASSERT(IN6_ARE_ADDR_EQUAL(&tcp->tcp_ip6h->ip6_src,
			    &connp->conn_srcv6));
		}
		tcp->tcp_localnet =
		    IN6_IS_ADDR_UNSPECIFIED(&ire->ire_gateway_addr_v6);
	}

	/*
	 * This allows applications to fail quickly when connections are made
	 * to dead hosts. Hosts can be labeled dead by adding a reject route
	 * with both the RTF_REJECT and RTF_PRIVATE flags set.
	 */
	if ((ire->ire_flags & RTF_REJECT) &&
	    (ire->ire_flags & RTF_PRIVATE))
		goto error;

	/*
	 * Make use of the cached rtt and rtt_sd values to calculate the
	 * initial RTO.  Note that they are already initialized in
	 * tcp_init_values().
	 * If ire_uinfo is NULL, i.e., we do not have a cache ire for
	 * IP_NEXTHOP, but instead are using the interface ire for the
	 * nexthop, then we do not use the ire_uinfo from that ire to
	 * do any initializations.
	 */
	if (ire_uinfo != NULL) {
		if (ire_uinfo->iulp_rtt != 0) {
			clock_t	rto;

			tcp->tcp_rtt_sa = ire_uinfo->iulp_rtt;
			tcp->tcp_rtt_sd = ire_uinfo->iulp_rtt_sd;
			rto = (tcp->tcp_rtt_sa >> 3) + tcp->tcp_rtt_sd +
			    tcps->tcps_rexmit_interval_extra +
			    (tcp->tcp_rtt_sa >> 5);

			if (rto > tcps->tcps_rexmit_interval_max) {
				tcp->tcp_rto = tcps->tcps_rexmit_interval_max;
			} else if (rto < tcps->tcps_rexmit_interval_min) {
				tcp->tcp_rto = tcps->tcps_rexmit_interval_min;
			} else {
				tcp->tcp_rto = rto;
			}
		}
		if (ire_uinfo->iulp_ssthresh != 0)
			tcp->tcp_cwnd_ssthresh = ire_uinfo->iulp_ssthresh;
		else
			tcp->tcp_cwnd_ssthresh = TCP_MAX_LARGEWIN;
		if (ire_uinfo->iulp_spipe > 0) {
			tcp->tcp_xmit_hiwater = MIN(ire_uinfo->iulp_spipe,
			    tcps->tcps_max_buf);
			if (tcps->tcps_snd_lowat_fraction != 0)
				tcp->tcp_xmit_lowater = tcp->tcp_xmit_hiwater /
				    tcps->tcps_snd_lowat_fraction;
			(void) tcp_maxpsz_set(tcp, B_TRUE);
		}
		/*
		 * Note that up till now, acceptor always inherits receive
		 * window from the listener.  But if there is a metrics
		 * associated with a host, we should use that instead of
		 * inheriting it from listener. Thus we need to pass this
		 * info back to the caller.
		 */
		if (ire_uinfo->iulp_rpipe > 0) {
			tcp->tcp_rwnd = MIN(ire_uinfo->iulp_rpipe,
			    tcps->tcps_max_buf);
		}

		if (ire_uinfo->iulp_rtomax > 0) {
			tcp->tcp_second_timer_threshold =
			    ire_uinfo->iulp_rtomax;
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
			if (ire_uinfo->iulp_tstamp_ok)
				tcp->tcp_snd_ts_ok = B_TRUE;
			if (ire_uinfo->iulp_wscale_ok)
				tcp->tcp_snd_ws_ok = B_TRUE;
			if (ire_uinfo->iulp_sack == 2)
				tcp->tcp_snd_sack_ok = B_TRUE;
			if (ire_uinfo->iulp_ecn_ok)
				tcp->tcp_ecn_ok = B_TRUE;
		} else {
			/*
			 * Passive open.
			 *
			 * As above, the if check means that SACK can only be
			 * turned on by the metric only IRE.
			 */
			if (ire_uinfo->iulp_sack > 0) {
				tcp->tcp_snd_sack_ok = B_TRUE;
			}
		}
	}


	/*
	 * XXX: Note that currently, ire_max_frag can be as small as 68
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
	ASSERT(ire->ire_max_frag != 0);
	mss = tcp->tcp_if_mtu = ire->ire_max_frag;
	if (tcp->tcp_ipp_fields & IPPF_USE_MIN_MTU) {
		if (tcp->tcp_ipp_use_min_mtu == IPV6_USE_MIN_MTU_NEVER) {
			mss = MIN(mss, IPV6_MIN_MTU);
		}
	}

	/* Sanity check for MSS value. */
	if (tcp->tcp_ipversion == IPV4_VERSION)
		mss_max = tcps->tcps_mss_max_ipv4;
	else
		mss_max = tcps->tcps_mss_max_ipv6;

	if (tcp->tcp_ipversion == IPV6_VERSION &&
	    (ire->ire_frag_flag & IPH_FRAG_HDR)) {
		/*
		 * After receiving an ICMPv6 "packet too big" message with a
		 * MTU < 1280, and for multirouted IPv6 packets, the IP layer
		 * will insert a 8-byte fragment header in every packet; we
		 * reduce the MSS by that amount here.
		 */
		mss -= sizeof (ip6_frag_t);
	}

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
	 * Initialize the ISS here now that we have the full connection ID.
	 * The RFC 1948 method of initial sequence number generation requires
	 * knowledge of the full connection ID before setting the ISS.
	 */

	tcp_iss_init(tcp);

	if (ire->ire_type & (IRE_LOOPBACK | IRE_LOCAL))
		tcp->tcp_loopback = B_TRUE;

	if (tcp->tcp_ipversion == IPV4_VERSION) {
		hsp = tcp_hsp_lookup(tcp->tcp_remote, tcps);
	} else {
		hsp = tcp_hsp_lookup_ipv6(&tcp->tcp_remote_v6, tcps);
	}

	if (hsp != NULL) {
		/* Only modify if we're going to make them bigger */
		if (hsp->tcp_hsp_sendspace > tcp->tcp_xmit_hiwater) {
			tcp->tcp_xmit_hiwater = hsp->tcp_hsp_sendspace;
			if (tcps->tcps_snd_lowat_fraction != 0)
				tcp->tcp_xmit_lowater = tcp->tcp_xmit_hiwater /
				    tcps->tcps_snd_lowat_fraction;
		}

		if (hsp->tcp_hsp_recvspace > tcp->tcp_rwnd) {
			tcp->tcp_rwnd = hsp->tcp_hsp_recvspace;
		}

		/* Copy timestamp flag only for active open */
		if (!tcp_detached)
			tcp->tcp_snd_ts_ok = hsp->tcp_hsp_tstamp;
	}

	if (sire != NULL)
		IRE_REFRELE(sire);

	/*
	 * If we got an IRE_CACHE and an ILL, go through their properties;
	 * otherwise, this is deferred until later when we have an IRE_CACHE.
	 */
	if (tcp->tcp_loopback ||
	    (ire_cacheable && (ill = ire_to_ill(ire)) != NULL)) {
		/*
		 * For incoming, see if this tcp may be MDT-capable.  For
		 * outgoing, this process has been taken care of through
		 * tcp_rput_other.
		 */
		tcp_ire_ill_check(tcp, ire, ill, incoming);
		tcp->tcp_ire_ill_check_done = B_TRUE;
	}

	mutex_enter(&connp->conn_lock);
	/*
	 * Make sure that conn is not marked incipient
	 * for incoming connections. A blind
	 * removal of incipient flag is cheaper than
	 * check and removal.
	 */
	connp->conn_state_flags &= ~CONN_INCIPIENT;

	/*
	 * Must not cache forwarding table routes
	 * or recache an IRE after the conn_t has
	 * had conn_ire_cache cleared and is flagged
	 * unusable, (see the CONN_CACHE_IRE() macro).
	 */
	if (ire_cacheable && CONN_CACHE_IRE(connp)) {
		rw_enter(&ire->ire_bucket->irb_lock, RW_READER);
		if (!(ire->ire_marks & IRE_MARK_CONDEMNED)) {
			connp->conn_ire_cache = ire;
			IRE_UNTRACE_REF(ire);
			rw_exit(&ire->ire_bucket->irb_lock);
			mutex_exit(&connp->conn_lock);
			return (1);
		}
		rw_exit(&ire->ire_bucket->irb_lock);
	}
	mutex_exit(&connp->conn_lock);

	if (ire->ire_mp == NULL)
		ire_refrele(ire);
	return (1);

error:
	if (ire->ire_mp == NULL)
		ire_refrele(ire);
	if (sire != NULL)
		ire_refrele(sire);
	return (0);
}

static void
tcp_tpi_bind(tcp_t *tcp, mblk_t *mp)
{
	int	error;
	conn_t	*connp = tcp->tcp_connp;
	struct sockaddr	*sa;
	mblk_t  *mp1;
	struct T_bind_req *tbr;
	int	backlog;
	socklen_t	len;
	sin_t	*sin;
	sin6_t	*sin6;

	ASSERT((uintptr_t)(mp->b_wptr - mp->b_rptr) <= (uintptr_t)INT_MAX);
	if ((mp->b_wptr - mp->b_rptr) < sizeof (*tbr)) {
		if (tcp->tcp_debug) {
			(void) strlog(TCP_MOD_ID, 0, 1, SL_ERROR|SL_TRACE,
			    "tcp_tpi_bind: bad req, len %u",
			    (uint_t)(mp->b_wptr - mp->b_rptr));
		}
		tcp_err_ack(tcp, mp, TPROTO, 0);
		return;
	}
	/* Make sure the largest address fits */
	mp1 = reallocb(mp, sizeof (struct T_bind_ack) + sizeof (sin6_t) + 1, 1);
	if (mp1 == NULL) {
		tcp_err_ack(tcp, mp, TSYSERR, ENOMEM);
		return;
	}
	mp = mp1;
	tbr = (struct T_bind_req *)mp->b_rptr;

	backlog = tbr->CONIND_number;
	len = tbr->ADDR_length;

	switch (len) {
	case 0:		/* request for a generic port */
		tbr->ADDR_offset = sizeof (struct T_bind_req);
		if (tcp->tcp_family == AF_INET) {
			tbr->ADDR_length = sizeof (sin_t);
			sin = (sin_t *)&tbr[1];
			*sin = sin_null;
			sin->sin_family = AF_INET;
			sa = (struct sockaddr *)sin;
			len = sizeof (sin_t);
			mp->b_wptr = (uchar_t *)&sin[1];
		} else {
			ASSERT(tcp->tcp_family == AF_INET6);
			tbr->ADDR_length = sizeof (sin6_t);
			sin6 = (sin6_t *)&tbr[1];
			*sin6 = sin6_null;
			sin6->sin6_family = AF_INET6;
			sa = (struct sockaddr *)sin6;
			len = sizeof (sin6_t);
			mp->b_wptr = (uchar_t *)&sin6[1];
		}
		break;

	case sizeof (sin_t):    /* Complete IPv4 address */
		sa = (struct sockaddr *)mi_offset_param(mp, tbr->ADDR_offset,
		    sizeof (sin_t));
		break;

	case sizeof (sin6_t): /* Complete IPv6 address */
		sa = (struct sockaddr *)mi_offset_param(mp,
		    tbr->ADDR_offset, sizeof (sin6_t));
		break;

	default:
		if (tcp->tcp_debug) {
			(void) strlog(TCP_MOD_ID, 0, 1, SL_ERROR|SL_TRACE,
			    "tcp_tpi_bind: bad address length, %d",
			    tbr->ADDR_length);
		}
		tcp_err_ack(tcp, mp, TBADADDR, 0);
		return;
	}

	error = tcp_bind_check(connp, sa, len, DB_CRED(mp),
	    tbr->PRIM_type != O_T_BIND_REQ);
	if (error == 0) {
		if (tcp->tcp_family == AF_INET) {
			sin = (sin_t *)sa;
			sin->sin_port = tcp->tcp_lport;
		} else {
			sin6 = (sin6_t *)sa;
			sin6->sin6_port = tcp->tcp_lport;
		}

		if (backlog > 0) {
			error = tcp_do_listen(connp, backlog, DB_CRED(mp));
		}
	}
done:
	if (error > 0) {
		tcp_err_ack(tcp, mp, TSYSERR, error);
	} else if (error < 0) {
		tcp_err_ack(tcp, mp, -error, 0);
	} else {
		mp->b_datap->db_type = M_PCPROTO;
		tbr->PRIM_type = T_BIND_ACK;
		putnext(tcp->tcp_rq, mp);
	}
}

/*
 * If the "bind_to_req_port_only" parameter is set, if the requested port
 * number is available, return it, If not return 0
 *
 * If "bind_to_req_port_only" parameter is not set and
 * If the requested port number is available, return it.  If not, return
 * the first anonymous port we happen across.  If no anonymous ports are
 * available, return 0. addr is the requested local address, if any.
 *
 * In either case, when succeeding update the tcp_t to record the port number
 * and insert it in the bind hash table.
 *
 * Note that TCP over IPv4 and IPv6 sockets can use the same port number
 * without setting SO_REUSEADDR. This is needed so that they
 * can be viewed as two independent transport protocols.
 */
static in_port_t
tcp_bindi(tcp_t *tcp, in_port_t port, const in6_addr_t *laddr,
    int reuseaddr, boolean_t quick_connect,
    boolean_t bind_to_req_port_only, boolean_t user_specified)
{
	/* number of times we have run around the loop */
	int count = 0;
	/* maximum number of times to run around the loop */
	int loopmax;
	conn_t *connp = tcp->tcp_connp;
	zoneid_t zoneid = connp->conn_zoneid;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	/*
	 * Lookup for free addresses is done in a loop and "loopmax"
	 * influences how long we spin in the loop
	 */
	if (bind_to_req_port_only) {
		/*
		 * If the requested port is busy, don't bother to look
		 * for a new one. Setting loop maximum count to 1 has
		 * that effect.
		 */
		loopmax = 1;
	} else {
		/*
		 * If the requested port is busy, look for a free one
		 * in the anonymous port range.
		 * Set loopmax appropriately so that one does not look
		 * forever in the case all of the anonymous ports are in use.
		 */
		if (tcp->tcp_anon_priv_bind) {
			/*
			 * loopmax =
			 * 	(IPPORT_RESERVED-1) - tcp_min_anonpriv_port + 1
			 */
			loopmax = IPPORT_RESERVED -
			    tcps->tcps_min_anonpriv_port;
		} else {
			loopmax = (tcps->tcps_largest_anon_port -
			    tcps->tcps_smallest_anon_port + 1);
		}
	}
	do {
		uint16_t	lport;
		tf_t		*tbf;
		tcp_t		*ltcp;
		conn_t		*lconnp;

		lport = htons(port);

		/*
		 * Ensure that the tcp_t is not currently in the bind hash.
		 * Hold the lock on the hash bucket to ensure that
		 * the duplicate check plus the insertion is an atomic
		 * operation.
		 *
		 * This function does an inline lookup on the bind hash list
		 * Make sure that we access only members of tcp_t
		 * and that we don't look at tcp_tcp, since we are not
		 * doing a CONN_INC_REF.
		 */
		tcp_bind_hash_remove(tcp);
		tbf = &tcps->tcps_bind_fanout[TCP_BIND_HASH(lport)];
		mutex_enter(&tbf->tf_lock);
		for (ltcp = tbf->tf_tcp; ltcp != NULL;
		    ltcp = ltcp->tcp_bind_hash) {
			if (lport == ltcp->tcp_lport)
				break;
		}

		for (; ltcp != NULL; ltcp = ltcp->tcp_bind_hash_port) {
			boolean_t not_socket;
			boolean_t exclbind;

			lconnp = ltcp->tcp_connp;

			/*
			 * On a labeled system, we must treat bindings to ports
			 * on shared IP addresses by sockets with MAC exemption
			 * privilege as being in all zones, as there's
			 * otherwise no way to identify the right receiver.
			 */
			if (!(IPCL_ZONE_MATCH(ltcp->tcp_connp, zoneid) ||
			    IPCL_ZONE_MATCH(connp,
			    ltcp->tcp_connp->conn_zoneid)) &&
			    !lconnp->conn_mac_exempt &&
			    !connp->conn_mac_exempt)
				continue;

			/*
			 * If TCP_EXCLBIND is set for either the bound or
			 * binding endpoint, the semantics of bind
			 * is changed according to the following.
			 *
			 * spec = specified address (v4 or v6)
			 * unspec = unspecified address (v4 or v6)
			 * A = specified addresses are different for endpoints
			 *
			 * bound	bind to		allowed
			 * -------------------------------------
			 * unspec	unspec		no
			 * unspec	spec		no
			 * spec		unspec		no
			 * spec		spec		yes if A
			 *
			 * For labeled systems, SO_MAC_EXEMPT behaves the same
			 * as TCP_EXCLBIND, except that zoneid is ignored.
			 *
			 * Note:
			 *
			 * 1. Because of TLI semantics, an endpoint can go
			 * back from, say TCP_ESTABLISHED to TCPS_LISTEN or
			 * TCPS_BOUND, depending on whether it is originally
			 * a listener or not.  That is why we need to check
			 * for states greater than or equal to TCPS_BOUND
			 * here.
			 *
			 * 2. Ideally, we should only check for state equals
			 * to TCPS_LISTEN. And the following check should be
			 * added.
			 *
			 * if (ltcp->tcp_state == TCPS_LISTEN ||
			 *	!reuseaddr || !ltcp->tcp_reuseaddr) {
			 *		...
			 * }
			 *
			 * The semantics will be changed to this.  If the
			 * endpoint on the list is in state not equal to
			 * TCPS_LISTEN and both endpoints have SO_REUSEADDR
			 * set, let the bind succeed.
			 *
			 * Because of (1), we cannot do that for TLI
			 * endpoints.  But we can do that for socket endpoints.
			 * If in future, we can change this going back
			 * semantics, we can use the above check for TLI also.
			 */
			not_socket = !(TCP_IS_SOCKET(ltcp) &&
			    TCP_IS_SOCKET(tcp));
			exclbind = ltcp->tcp_exclbind || tcp->tcp_exclbind;

			if (lconnp->conn_mac_exempt || connp->conn_mac_exempt ||
			    (exclbind && (not_socket ||
			    ltcp->tcp_state <= TCPS_ESTABLISHED))) {
				if (V6_OR_V4_INADDR_ANY(
				    ltcp->tcp_bound_source_v6) ||
				    V6_OR_V4_INADDR_ANY(*laddr) ||
				    IN6_ARE_ADDR_EQUAL(laddr,
				    &ltcp->tcp_bound_source_v6)) {
					break;
				}
				continue;
			}

			/*
			 * Check ipversion to allow IPv4 and IPv6 sockets to
			 * have disjoint port number spaces, if *_EXCLBIND
			 * is not set and only if the application binds to a
			 * specific port. We use the same autoassigned port
			 * number space for IPv4 and IPv6 sockets.
			 */
			if (tcp->tcp_ipversion != ltcp->tcp_ipversion &&
			    bind_to_req_port_only)
				continue;

			/*
			 * Ideally, we should make sure that the source
			 * address, remote address, and remote port in the
			 * four tuple for this tcp-connection is unique.
			 * However, trying to find out the local source
			 * address would require too much code duplication
			 * with IP, since IP needs needs to have that code
			 * to support userland TCP implementations.
			 */
			if (quick_connect &&
			    (ltcp->tcp_state > TCPS_LISTEN) &&
			    ((tcp->tcp_fport != ltcp->tcp_fport) ||
			    !IN6_ARE_ADDR_EQUAL(&tcp->tcp_remote_v6,
			    &ltcp->tcp_remote_v6)))
				continue;

			if (!reuseaddr) {
				/*
				 * No socket option SO_REUSEADDR.
				 * If existing port is bound to
				 * a non-wildcard IP address
				 * and the requesting stream is
				 * bound to a distinct
				 * different IP addresses
				 * (non-wildcard, also), keep
				 * going.
				 */
				if (!V6_OR_V4_INADDR_ANY(*laddr) &&
				    !V6_OR_V4_INADDR_ANY(
				    ltcp->tcp_bound_source_v6) &&
				    !IN6_ARE_ADDR_EQUAL(laddr,
				    &ltcp->tcp_bound_source_v6))
					continue;
				if (ltcp->tcp_state >= TCPS_BOUND) {
					/*
					 * This port is being used and
					 * its state is >= TCPS_BOUND,
					 * so we can't bind to it.
					 */
					break;
				}
			} else {
				/*
				 * socket option SO_REUSEADDR is set on the
				 * binding tcp_t.
				 *
				 * If two streams are bound to
				 * same IP address or both addr
				 * and bound source are wildcards
				 * (INADDR_ANY), we want to stop
				 * searching.
				 * We have found a match of IP source
				 * address and source port, which is
				 * refused regardless of the
				 * SO_REUSEADDR setting, so we break.
				 */
				if (IN6_ARE_ADDR_EQUAL(laddr,
				    &ltcp->tcp_bound_source_v6) &&
				    (ltcp->tcp_state == TCPS_LISTEN ||
				    ltcp->tcp_state == TCPS_BOUND))
					break;
			}
		}
		if (ltcp != NULL) {
			/* The port number is busy */
			mutex_exit(&tbf->tf_lock);
		} else {
			/*
			 * This port is ours. Insert in fanout and mark as
			 * bound to prevent others from getting the port
			 * number.
			 */
			tcp->tcp_state = TCPS_BOUND;
			tcp->tcp_lport = htons(port);
			*(uint16_t *)tcp->tcp_tcph->th_lport = tcp->tcp_lport;

			ASSERT(&tcps->tcps_bind_fanout[TCP_BIND_HASH(
			    tcp->tcp_lport)] == tbf);
			tcp_bind_hash_insert(tbf, tcp, 1);

			mutex_exit(&tbf->tf_lock);

			/*
			 * We don't want tcp_next_port_to_try to "inherit"
			 * a port number supplied by the user in a bind.
			 */
			if (user_specified)
				return (port);

			/*
			 * This is the only place where tcp_next_port_to_try
			 * is updated. After the update, it may or may not
			 * be in the valid range.
			 */
			if (!tcp->tcp_anon_priv_bind)
				tcps->tcps_next_port_to_try = port + 1;
			return (port);
		}

		if (tcp->tcp_anon_priv_bind) {
			port = tcp_get_next_priv_port(tcp);
		} else {
			if (count == 0 && user_specified) {
				/*
				 * We may have to return an anonymous port. So
				 * get one to start with.
				 */
				port =
				    tcp_update_next_port(
				    tcps->tcps_next_port_to_try,
				    tcp, B_TRUE);
				user_specified = B_FALSE;
			} else {
				port = tcp_update_next_port(port + 1, tcp,
				    B_FALSE);
			}
		}
		if (port == 0)
			break;

		/*
		 * Don't let this loop run forever in the case where
		 * all of the anonymous ports are in use.
		 */
	} while (++count < loopmax);
	return (0);
}

/*
 * tcp_clean_death / tcp_close_detached must not be called more than once
 * on a tcp. Thus every function that potentially calls tcp_clean_death
 * must check for the tcp state before calling tcp_clean_death.
 * Eg. tcp_input, tcp_rput_data, tcp_eager_kill, tcp_clean_death_wrapper,
 * tcp_timer_handler, all check for the tcp state.
 */
/* ARGSUSED */
void
tcp_clean_death_wrapper(void *arg, mblk_t *mp, void *arg2)
{
	tcp_t	*tcp = ((conn_t *)arg)->conn_tcp;

	freemsg(mp);
	if (tcp->tcp_state > TCPS_BOUND)
		(void) tcp_clean_death(((conn_t *)arg)->conn_tcp,
		    ETIMEDOUT, 5);
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
static int
tcp_clean_death(tcp_t *tcp, int err, uint8_t tag)
{
	mblk_t	*mp;
	queue_t	*q;
	conn_t	*connp = tcp->tcp_connp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	sodirect_t	*sodp;

	TCP_CLD_STAT(tag);

#if TCP_TAG_CLEAN_DEATH
	tcp->tcp_cleandeathtag = tag;
#endif

	if (tcp->tcp_fused)
		tcp_unfuse(tcp);

	if (tcp->tcp_linger_tid != 0 &&
	    TCP_TIMER_CANCEL(tcp, tcp->tcp_linger_tid) >= 0) {
		tcp_stop_lingering(tcp);
	}

	ASSERT(tcp != NULL);
	ASSERT((tcp->tcp_family == AF_INET &&
	    tcp->tcp_ipversion == IPV4_VERSION) ||
	    (tcp->tcp_family == AF_INET6 &&
	    (tcp->tcp_ipversion == IPV4_VERSION ||
	    tcp->tcp_ipversion == IPV6_VERSION)));

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
			}
		} else {
			tcp_close_detached(tcp);
		}
		return (0);
	}

	TCP_STAT(tcps, tcp_clean_death_nondetached);

	/* If sodirect, not anymore */
	SOD_PTR_ENTER(tcp, sodp);
	if (sodp != NULL) {
		tcp->tcp_sodirect = NULL;
		mutex_exit(sodp->sod_lockp);
	}

	q = tcp->tcp_rq;

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
		if (tcp->tcp_debug) {
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
				if (tcp->tcp_debug) {
					(void) strlog(TCP_MOD_ID, 0, 1,
					    SL_ERROR|SL_TRACE,
					    "tcp_clean_death, sending M_ERROR");
				}
				(void) putnextctl1(q, M_ERROR, EPROTO);
			}
		}
		if (tcp->tcp_state <= TCPS_SYN_RCVD) {
			/* SYN_SENT or SYN_RCVD */
			BUMP_MIB(&tcps->tcps_mib, tcpAttemptFails);
		} else if (tcp->tcp_state <= TCPS_CLOSE_WAIT) {
			/* ESTABLISHED or CLOSE_WAIT */
			BUMP_MIB(&tcps->tcps_mib, tcpEstabResets);
		}
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
static void
tcp_stop_lingering(tcp_t *tcp)
{
	clock_t	delta = 0;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

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
		 * TCP is detached.  This has to be done before the tcp_wq
		 * is set to the global queue.
		 */
		tcp_timers_stop(tcp);

		tcp->tcp_detached = B_TRUE;
		ASSERT(tcps->tcps_g_q != NULL);
		tcp->tcp_rq = tcps->tcps_g_q;
		tcp->tcp_wq = WR(tcps->tcps_g_q);

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
		CONN_DEC_REF(tcp->tcp_connp);
	}
finish:
	/* Signal closing thread that it can complete close */
	mutex_enter(&tcp->tcp_closelock);
	tcp->tcp_detached = B_TRUE;
	ASSERT(tcps->tcps_g_q != NULL);

	tcp->tcp_rq = tcps->tcps_g_q;
	tcp->tcp_wq = WR(tcps->tcps_g_q);

	tcp->tcp_closed = 1;
	cv_signal(&tcp->tcp_closecv);
	mutex_exit(&tcp->tcp_closelock);
}

/*
 * Handle lingering timeouts. This function is called when the SO_LINGER timeout
 * expires.
 */
static void
tcp_close_linger_timeout(void *arg)
{
	conn_t	*connp = (conn_t *)arg;
	tcp_t 	*tcp = connp->conn_tcp;

	tcp->tcp_client_errno = ETIMEDOUT;
	tcp_stop_lingering(tcp);
}

static void
tcp_close_common(conn_t *connp, int flags)
{
	tcp_t		*tcp = connp->conn_tcp;
	mblk_t 		*mp = &tcp->tcp_closemp;
	boolean_t	conn_ioctl_cleanup_reqd = B_FALSE;
	mblk_t		*bp;

	ASSERT(connp->conn_ref >= 2);

	/*
	 * Mark the conn as closing. ill_pending_mp_add will not
	 * add any mp to the pending mp list, after this conn has
	 * started closing. Same for sq_pending_mp_add
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

	SQUEUE_ENTER_ONE(connp->conn_sqp, mp, tcp_close_output, connp,
	    tcp_squeue_flag, SQTAG_IP_TCP_CLOSE);

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
			if (tcp->tcp_linger && tcp->tcp_lingertime > 0) {
				mutex_exit(&tcp->tcp_closelock);
				/* Entering squeue, bump ref count. */
				CONN_INC_REF(connp);
				bp = allocb_wait(0, BPRI_HI, STR_NOSIG, NULL);
				SQUEUE_ENTER_ONE(connp->conn_sqp, bp,
				    tcp_linger_interrupted, connp,
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
	 * we wait for the eagers to drop their reference to us. tcp_rq and
	 * tcp_wq of the eagers point to our queues. By waiting for the
	 * refcnt to drop to 1, we are sure that the eagers have cleaned
	 * up their queue pointers and also dropped their references to us.
	 */
	if (tcp->tcp_wait_for_eagers) {
		mutex_enter(&connp->conn_lock);
		while (connp->conn_ref != 1) {
			cv_wait(&connp->conn_cv, &connp->conn_lock);
		}
		mutex_exit(&connp->conn_lock);
	}
	/*
	 * ioctl cleanup. The mp is queued in the
	 * ill_pending_mp or in the sq_pending_mp.
	 */
	if (conn_ioctl_cleanup_reqd)
		conn_ioctl_cleanup(connp);

	tcp->tcp_cpid = -1;
}

static int
tcp_tpi_close(queue_t *q, int flags)
{
	conn_t		*connp;

	ASSERT(WR(q)->q_next == NULL);

	if (flags & SO_FALLBACK) {
		/*
		 * stream is being closed while in fallback
		 * simply free the resources that were allocated
		 */
		inet_minor_free(WR(q)->q_ptr, (dev_t)(RD(q)->q_ptr));
		qprocsoff(q);
		goto done;
	}

	connp = Q_TO_CONN(q);
	/*
	 * We are being closed as /dev/tcp or /dev/tcp6.
	 */
	tcp_close_common(connp, flags);

	qprocsoff(q);
	inet_minor_free(connp->conn_minor_arena, connp->conn_dev);

	/*
	 * Drop IP's reference on the conn. This is the last reference
	 * on the connp if the state was less than established. If the
	 * connection has gone into timewait state, then we will have
	 * one ref for the TCP and one more ref (total of two) for the
	 * classifier connected hash list (a timewait connections stays
	 * in connected hash till closed).
	 *
	 * We can't assert the references because there might be other
	 * transient reference places because of some walkers or queued
	 * packets in squeue for the timewait state.
	 */
	CONN_DEC_REF(connp);
done:
	q->q_ptr = WR(q)->q_ptr = NULL;
	return (0);
}

static int
tcpclose_accept(queue_t *q)
{
	vmem_t	*minor_arena;
	dev_t	conn_dev;

	ASSERT(WR(q)->q_qinfo == &tcp_acceptor_winit);

	/*
	 * We had opened an acceptor STREAM for sockfs which is
	 * now being closed due to some error.
	 */
	qprocsoff(q);

	minor_arena = (vmem_t *)WR(q)->q_ptr;
	conn_dev = (dev_t)RD(q)->q_ptr;
	ASSERT(minor_arena != NULL);
	ASSERT(conn_dev != 0);
	inet_minor_free(minor_arena, conn_dev);
	q->q_ptr = WR(q)->q_ptr = NULL;
	return (0);
}

/*
 * Called by tcp_close() routine via squeue when lingering is
 * interrupted by a signal.
 */

/* ARGSUSED */
static void
tcp_linger_interrupted(void *arg, mblk_t *mp, void *arg2)
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
 * Called by streams close routine via squeues when our client blows off her
 * descriptor, we take this to mean: "close the stream state NOW, close the tcp
 * connection politely" When SO_LINGER is set (with a non-zero linger time and
 * it is not a nonblocking socket) then this routine sleeps until the FIN is
 * acked.
 *
 * NOTE: tcp_close potentially returns error when lingering.
 * However, the stream head currently does not pass these errors
 * to the application. 4.4BSD only returns EINTR and EWOULDBLOCK
 * errors to the application (from tsleep()) and not errors
 * like ECONNRESET caused by receiving a reset packet.
 */

/* ARGSUSED */
static void
tcp_close_output(void *arg, mblk_t *mp, void *arg2)
{
	char	*msg;
	conn_t	*connp = (conn_t *)arg;
	tcp_t	*tcp = connp->conn_tcp;
	clock_t	delta = 0;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	ASSERT((connp->conn_fanout != NULL && connp->conn_ref >= 4) ||
	    (connp->conn_fanout == NULL && connp->conn_ref >= 3));

	mutex_enter(&tcp->tcp_eager_lock);
	if (tcp->tcp_conn_req_cnt_q0 != 0 || tcp->tcp_conn_req_cnt_q != 0) {
		/* Cleanup for listener */
		tcp_eager_cleanup(tcp, 0);
		tcp->tcp_wait_for_eagers = 1;
	}
	mutex_exit(&tcp->tcp_eager_lock);

	connp->conn_mdt_ok = B_FALSE;
	tcp->tcp_mdt = B_FALSE;

	connp->conn_lso_ok = B_FALSE;
	tcp->tcp_lso = B_FALSE;

	msg = NULL;
	switch (tcp->tcp_state) {
	case TCPS_CLOSED:
	case TCPS_IDLE:
	case TCPS_BOUND:
	case TCPS_LISTEN:
		break;
	case TCPS_SYN_SENT:
		msg = "tcp_close, during connect";
		break;
	case TCPS_SYN_RCVD:
		/*
		 * Close during the connect 3-way handshake
		 * but here there may or may not be pending data
		 * already on queue. Process almost same as in
		 * the ESTABLISHED state.
		 */
		/* FALLTHRU */
	default:
		if (tcp->tcp_sodirect != NULL) {
			/* Ok, no more sodirect */
			tcp->tcp_sodirect = NULL;
		}

		if (tcp->tcp_fused)
			tcp_unfuse(tcp);

		/*
		 * If SO_LINGER has set a zero linger time, abort the
		 * connection with a reset.
		 */
		if (tcp->tcp_linger && tcp->tcp_lingertime == 0) {
			msg = "tcp_close, zero lingertime";
			break;
		}

		ASSERT(tcp->tcp_hard_bound || tcp->tcp_hard_binding);
		/*
		 * Abort connection if there is unread data queued.
		 */
		if (tcp->tcp_rcv_list || tcp->tcp_reass_head) {
			msg = "tcp_close, unread data";
			break;
		}
		/*
		 * tcp_hard_bound is now cleared thus all packets go through
		 * tcp_lookup. This fact is used by tcp_detach below.
		 *
		 * We have done a qwait() above which could have possibly
		 * drained more messages in turn causing transition to a
		 * different state. Check whether we have to do the rest
		 * of the processing or not.
		 */
		if (tcp->tcp_state <= TCPS_LISTEN)
			break;

		/*
		 * Transmit the FIN before detaching the tcp_t.
		 * After tcp_detach returns this queue/perimeter
		 * no longer owns the tcp_t thus others can modify it.
		 */
		(void) tcp_xmit_end(tcp);

		/*
		 * If lingering on close then wait until the fin is acked,
		 * the SO_LINGER time passes, or a reset is sent/received.
		 */
		if (tcp->tcp_linger && tcp->tcp_lingertime > 0 &&
		    !(tcp->tcp_fin_acked) &&
		    tcp->tcp_state >= TCPS_ESTABLISHED) {
			if (tcp->tcp_closeflags & (FNDELAY|FNONBLOCK)) {
				tcp->tcp_client_errno = EWOULDBLOCK;
			} else if (tcp->tcp_client_errno == 0) {

				ASSERT(tcp->tcp_linger_tid == 0);

				tcp->tcp_linger_tid = TCP_TIMER(tcp,
				    tcp_close_linger_timeout,
				    tcp->tcp_lingertime * hz);

				/* tcp_close_linger_timeout will finish close */
				if (tcp->tcp_linger_tid == 0)
					tcp->tcp_client_errno = ENOSR;
				else
					return;
			}

			/*
			 * Check if we need to detach or just close
			 * the instance.
			 */
			if (tcp->tcp_state <= TCPS_LISTEN)
				break;
		}

		/*
		 * Make sure that no other thread will access the tcp_rq of
		 * this instance (through lookups etc.) as tcp_rq will go
		 * away shortly.
		 */
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
		 * TCP is detached.  This has to be done before the tcp_wq
		 * is set to the global queue.
		 */
		tcp_timers_stop(tcp);

		tcp->tcp_detached = B_TRUE;
		if (tcp->tcp_state == TCPS_TIME_WAIT) {
			tcp_time_wait_append(tcp);
			TCP_DBGSTAT(tcps, tcp_detach_time_wait);
			ASSERT(connp->conn_ref >= 3);
			goto finish;
		}

		/*
		 * If delta is zero the timer event wasn't executed and was
		 * successfully canceled. In this case we need to restart it
		 * with the minimal delta possible.
		 */
		if (delta >= 0)
			tcp->tcp_timer_tid = TCP_TIMER(tcp, tcp_timer,
			    delta ? delta : 1);

		ASSERT(connp->conn_ref >= 3);
		goto finish;
	}

	/* Detach did not complete. Still need to remove q from stream. */
	if (msg) {
		if (tcp->tcp_state == TCPS_ESTABLISHED ||
		    tcp->tcp_state == TCPS_CLOSE_WAIT)
			BUMP_MIB(&tcps->tcps_mib, tcpEstabResets);
		if (tcp->tcp_state == TCPS_SYN_SENT ||
		    tcp->tcp_state == TCPS_SYN_RCVD)
			BUMP_MIB(&tcps->tcps_mib, tcpAttemptFails);
		tcp_xmit_ctl(msg, tcp,  tcp->tcp_snxt, 0, TH_RST);
	}

	tcp_closei_local(tcp);
	CONN_DEC_REF(connp);
	ASSERT(connp->conn_ref >= 2);

finish:
	/*
	 * Although packets are always processed on the correct
	 * tcp's perimeter and access is serialized via squeue's,
	 * IP still needs a queue when sending packets in time_wait
	 * state so use WR(tcps_g_q) till ip_output() can be
	 * changed to deal with just connp. For read side, we
	 * could have set tcp_rq to NULL but there are some cases
	 * in tcp_rput_data() from early days of this code which
	 * do a putnext without checking if tcp is closed. Those
	 * need to be identified before both tcp_rq and tcp_wq
	 * can be set to NULL and tcps_g_q can disappear forever.
	 */
	mutex_enter(&tcp->tcp_closelock);
	/*
	 * Don't change the queues in the case of a listener that has
	 * eagers in its q or q0. It could surprise the eagers.
	 * Instead wait for the eagers outside the squeue.
	 */
	if (!tcp->tcp_wait_for_eagers) {
		tcp->tcp_detached = B_TRUE;
		/*
		 * When default queue is closing we set tcps_g_q to NULL
		 * after the close is done.
		 */
		ASSERT(tcps->tcps_g_q != NULL);
		tcp->tcp_rq = tcps->tcps_g_q;
		tcp->tcp_wq = WR(tcps->tcps_g_q);
	}

	/* Signal tcp_close() to finish closing. */
	tcp->tcp_closed = 1;
	cv_signal(&tcp->tcp_closecv);
	mutex_exit(&tcp->tcp_closelock);
}


/*
 * Clean up the b_next and b_prev fields of every mblk pointed at by *mpp.
 * Some stream heads get upset if they see these later on as anything but NULL.
 */
static void
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
static void
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
 * Stop all TCP timers, and free the timer mblks if requested.
 */
void
tcp_timers_stop(tcp_t *tcp)
{
	if (tcp->tcp_timer_tid != 0) {
		(void) TCP_TIMER_CANCEL(tcp, tcp->tcp_timer_tid);
		tcp->tcp_timer_tid = 0;
	}
	if (tcp->tcp_ka_tid != 0) {
		(void) TCP_TIMER_CANCEL(tcp, tcp->tcp_ka_tid);
		tcp->tcp_ka_tid = 0;
	}
	if (tcp->tcp_ack_tid != 0) {
		(void) TCP_TIMER_CANCEL(tcp, tcp->tcp_ack_tid);
		tcp->tcp_ack_tid = 0;
	}
	if (tcp->tcp_push_tid != 0) {
		(void) TCP_TIMER_CANCEL(tcp, tcp->tcp_push_tid);
		tcp->tcp_push_tid = 0;
	}
}

/*
 * The tcp_t is going away. Remove it from all lists and set it
 * to TCPS_CLOSED. The freeing up of memory is deferred until
 * tcp_inactive. This is needed since a thread in tcp_rput might have
 * done a CONN_INC_REF on this structure before it was removed from the
 * hashes.
 */
static void
tcp_closei_local(tcp_t *tcp)
{
	ire_t 	*ire;
	conn_t	*connp = tcp->tcp_connp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	if (!TCP_IS_SOCKET(tcp))
		tcp_acceptor_hash_remove(tcp);

	UPDATE_MIB(&tcps->tcps_mib, tcpHCInSegs, tcp->tcp_ibsegs);
	tcp->tcp_ibsegs = 0;
	UPDATE_MIB(&tcps->tcps_mib, tcpHCOutSegs, tcp->tcp_obsegs);
	tcp->tcp_obsegs = 0;

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
		 * accept, we can clean this up. In tcp_wput_accept
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
			ASSERT(tcps->tcps_g_q != NULL);
			tcp->tcp_rq = tcps->tcps_g_q;
			tcp->tcp_wq = WR(tcps->tcps_g_q);
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
	CL_INET_DISCONNECT(connp, tcp);
	ipcl_hash_remove(connp);

	/*
	 * Delete the cached ire in conn_ire_cache and also mark
	 * the conn as CONDEMNED
	 */
	mutex_enter(&connp->conn_lock);
	connp->conn_state_flags |= CONN_CONDEMNED;
	ire = connp->conn_ire_cache;
	connp->conn_ire_cache = NULL;
	mutex_exit(&connp->conn_lock);
	if (ire != NULL)
		IRE_REFRELE_NOTR(ire);

	/* Need to cleanup any pending ioctls */
	ASSERT(tcp->tcp_time_wait_next == NULL);
	ASSERT(tcp->tcp_time_wait_prev == NULL);
	ASSERT(tcp->tcp_time_wait_expire == 0);
	tcp->tcp_state = TCPS_CLOSED;

	/* Release any SSL context */
	if (tcp->tcp_kssl_ent != NULL) {
		kssl_release_ent(tcp->tcp_kssl_ent, NULL, KSSL_NO_PROXY);
		tcp->tcp_kssl_ent = NULL;
	}
	if (tcp->tcp_kssl_ctx != NULL) {
		kssl_release_ctx(tcp->tcp_kssl_ctx);
		tcp->tcp_kssl_ctx = NULL;
	}
	tcp->tcp_kssl_pending = B_FALSE;

	tcp_ipsec_cleanup(tcp);
}

/*
 * tcp is dying (called from ipcl_conn_destroy and error cases).
 * Free the tcp_t in either case.
 */
void
tcp_free(tcp_t *tcp)
{
	mblk_t	*mp;
	ip6_pkt_t	*ipp;

	ASSERT(tcp != NULL);
	ASSERT(tcp->tcp_ptpahn == NULL && tcp->tcp_acceptor_hash == NULL);

	tcp->tcp_rq = NULL;
	tcp->tcp_wq = NULL;

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

	if (tcp->tcp_sack_info != NULL) {
		if (tcp->tcp_notsack_list != NULL) {
			TCP_NOTSACK_REMOVE_ALL(tcp->tcp_notsack_list);
		}
		bzero(tcp->tcp_sack_info, sizeof (tcp_sack_info_t));
	}

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
	if (tcp->tcp_rtdstopts != NULL) {
		mi_free(tcp->tcp_rtdstopts);
		tcp->tcp_rtdstopts = NULL;
		tcp->tcp_rtdstoptslen = 0;
	}
	ASSERT(tcp->tcp_rtdstoptslen == 0);
	if (tcp->tcp_rthdr != NULL) {
		mi_free(tcp->tcp_rthdr);
		tcp->tcp_rthdr = NULL;
		tcp->tcp_rthdrlen = 0;
	}
	ASSERT(tcp->tcp_rthdrlen == 0);

	ipp = &tcp->tcp_sticky_ipp;
	if (ipp->ipp_fields & (IPPF_HOPOPTS | IPPF_RTDSTOPTS | IPPF_DSTOPTS |
	    IPPF_RTHDR))
		ip6_pkt_free(ipp);

	/*
	 * Free memory associated with the tcp/ip header template.
	 */

	if (tcp->tcp_iphc != NULL)
		bzero(tcp->tcp_iphc, tcp->tcp_iphc_len);

	/*
	 * Following is really a blowing away a union.
	 * It happens to have exactly two members of identical size
	 * the following code is enough.
	 */
	tcp_close_mpp(&tcp->tcp_conn.tcp_eager_conn_ind);
}


/*
 * Put a connection confirmation message upstream built from the
 * address information within 'iph' and 'tcph'.  Report our success or failure.
 */
static boolean_t
tcp_conn_con(tcp_t *tcp, uchar_t *iphdr, tcph_t *tcph, mblk_t *idmp,
    mblk_t **defermp)
{
	sin_t	sin;
	sin6_t	sin6;
	mblk_t	*mp;
	char	*optp = NULL;
	int	optlen = 0;
	cred_t	*cr;

	if (defermp != NULL)
		*defermp = NULL;

	if (tcp->tcp_conn.tcp_opts_conn_req != NULL) {
		/*
		 * Return in T_CONN_CON results of option negotiation through
		 * the T_CONN_REQ. Note: If there is an real end-to-end option
		 * negotiation, then what is received from remote end needs
		 * to be taken into account but there is no such thing (yet?)
		 * in our TCP/IP.
		 * Note: We do not use mi_offset_param() here as
		 * tcp_opts_conn_req contents do not directly come from
		 * an application and are either generated in kernel or
		 * from user input that was already verified.
		 */
		mp = tcp->tcp_conn.tcp_opts_conn_req;
		optp = (char *)(mp->b_rptr +
		    ((struct T_conn_req *)mp->b_rptr)->OPT_offset);
		optlen = (int)
		    ((struct T_conn_req *)mp->b_rptr)->OPT_length;
	}

	if (IPH_HDR_VERSION(iphdr) == IPV4_VERSION) {
		ipha_t *ipha = (ipha_t *)iphdr;

		/* packet is IPv4 */
		if (tcp->tcp_family == AF_INET) {
			sin = sin_null;
			sin.sin_addr.s_addr = ipha->ipha_src;
			sin.sin_port = *(uint16_t *)tcph->th_lport;
			sin.sin_family = AF_INET;
			mp = mi_tpi_conn_con(NULL, (char *)&sin,
			    (int)sizeof (sin_t), optp, optlen);
		} else {
			sin6 = sin6_null;
			IN6_IPADDR_TO_V4MAPPED(ipha->ipha_src, &sin6.sin6_addr);
			sin6.sin6_port = *(uint16_t *)tcph->th_lport;
			sin6.sin6_family = AF_INET6;
			mp = mi_tpi_conn_con(NULL, (char *)&sin6,
			    (int)sizeof (sin6_t), optp, optlen);

		}
	} else {
		ip6_t	*ip6h = (ip6_t *)iphdr;

		ASSERT(IPH_HDR_VERSION(iphdr) == IPV6_VERSION);
		ASSERT(tcp->tcp_family == AF_INET6);
		sin6 = sin6_null;
		sin6.sin6_addr = ip6h->ip6_src;
		sin6.sin6_port = *(uint16_t *)tcph->th_lport;
		sin6.sin6_family = AF_INET6;
		sin6.sin6_flowinfo = ip6h->ip6_vcf & ~IPV6_VERS_AND_FLOW_MASK;
		mp = mi_tpi_conn_con(NULL, (char *)&sin6,
		    (int)sizeof (sin6_t), optp, optlen);
	}

	if (!mp)
		return (B_FALSE);

	if ((cr = DB_CRED(idmp)) != NULL) {
		mblk_setcred(mp, cr);
		DB_CPID(mp) = DB_CPID(idmp);
	}

	if (defermp == NULL) {
		conn_t *connp = tcp->tcp_connp;
		if (IPCL_IS_NONSTR(connp)) {
			(*connp->conn_upcalls->su_connected)
			    (connp->conn_upper_handle, tcp->tcp_connid, cr,
			    DB_CPID(mp));
			freemsg(mp);
		} else {
			putnext(tcp->tcp_rq, mp);
		}
	} else {
		*defermp = mp;
	}

	if (tcp->tcp_conn.tcp_opts_conn_req != NULL)
		tcp_close_mpp(&tcp->tcp_conn.tcp_opts_conn_req);
	return (B_TRUE);
}

/*
 * Defense for the SYN attack -
 * 1. When q0 is full, drop from the tail (tcp_eager_prev_drop_q0) the oldest
 *    one from the list of droppable eagers. This list is a subset of q0.
 *    see comments before the definition of MAKE_DROPPABLE().
 * 2. Don't drop a SYN request before its first timeout. This gives every
 *    request at least til the first timeout to complete its 3-way handshake.
 * 3. Maintain tcp_syn_rcvd_timeout as an accurate count of how many
 *    requests currently on the queue that has timed out. This will be used
 *    as an indicator of whether an attack is under way, so that appropriate
 *    actions can be taken. (It's incremented in tcp_timer() and decremented
 *    either when eager goes into ESTABLISHED, or gets freed up.)
 * 4. The current threshold is - # of timeout > q0len/4 => SYN alert on
 *    # of timeout drops back to <= q0len/32 => SYN alert off
 */
static boolean_t
tcp_drop_q0(tcp_t *tcp)
{
	tcp_t	*eager;
	mblk_t	*mp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	ASSERT(MUTEX_HELD(&tcp->tcp_eager_lock));
	ASSERT(tcp->tcp_eager_next_q0 != tcp->tcp_eager_prev_q0);

	/* Pick oldest eager from the list of droppable eagers */
	eager = tcp->tcp_eager_prev_drop_q0;

	/* If list is empty. return B_FALSE */
	if (eager == tcp) {
		return (B_FALSE);
	}

	/* If allocated, the mp will be freed in tcp_clean_death_wrapper() */
	if ((mp = allocb(0, BPRI_HI)) == NULL)
		return (B_FALSE);

	/*
	 * Take this eager out from the list of droppable eagers since we are
	 * going to drop it.
	 */
	MAKE_UNDROPPABLE(eager);

	if (tcp->tcp_debug) {
		(void) strlog(TCP_MOD_ID, 0, 3, SL_TRACE,
		    "tcp_drop_q0: listen half-open queue (max=%d) overflow"
		    " (%d pending) on %s, drop one", tcps->tcps_conn_req_max_q0,
		    tcp->tcp_conn_req_cnt_q0,
		    tcp_display(tcp, NULL, DISP_PORT_ONLY));
	}

	BUMP_MIB(&tcps->tcps_mib, tcpHalfOpenDrop);

	/* Put a reference on the conn as we are enqueueing it in the sqeue */
	CONN_INC_REF(eager->tcp_connp);

	/* Mark the IRE created for this SYN request temporary */
	tcp_ip_ire_mark_advice(eager);
	SQUEUE_ENTER_ONE(eager->tcp_connp->conn_sqp, mp,
	    tcp_clean_death_wrapper, eager->tcp_connp,
	    SQ_FILL, SQTAG_TCP_DROP_Q0);

	return (B_TRUE);
}

int
tcp_conn_create_v6(conn_t *lconnp, conn_t *connp, mblk_t *mp,
    tcph_t *tcph, uint_t ipvers, mblk_t *idmp)
{
	tcp_t 		*ltcp = lconnp->conn_tcp;
	tcp_t		*tcp = connp->conn_tcp;
	mblk_t		*tpi_mp;
	ipha_t		*ipha;
	ip6_t		*ip6h;
	sin6_t 		sin6;
	in6_addr_t 	v6dst;
	int		err;
	int		ifindex = 0;
	cred_t		*cr;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	if (ipvers == IPV4_VERSION) {
		ipha = (ipha_t *)mp->b_rptr;

		connp->conn_send = ip_output;
		connp->conn_recv = tcp_input;

		IN6_IPADDR_TO_V4MAPPED(ipha->ipha_dst,
		    &connp->conn_bound_source_v6);
		IN6_IPADDR_TO_V4MAPPED(ipha->ipha_dst, &connp->conn_srcv6);
		IN6_IPADDR_TO_V4MAPPED(ipha->ipha_src, &connp->conn_remv6);

		sin6 = sin6_null;
		IN6_IPADDR_TO_V4MAPPED(ipha->ipha_src, &sin6.sin6_addr);
		IN6_IPADDR_TO_V4MAPPED(ipha->ipha_dst, &v6dst);
		sin6.sin6_port = *(uint16_t *)tcph->th_lport;
		sin6.sin6_family = AF_INET6;
		sin6.__sin6_src_id = ip_srcid_find_addr(&v6dst,
		    lconnp->conn_zoneid, tcps->tcps_netstack);
		if (tcp->tcp_recvdstaddr) {
			sin6_t	sin6d;

			sin6d = sin6_null;
			IN6_IPADDR_TO_V4MAPPED(ipha->ipha_dst,
			    &sin6d.sin6_addr);
			sin6d.sin6_port = *(uint16_t *)tcph->th_fport;
			sin6d.sin6_family = AF_INET;
			tpi_mp = mi_tpi_extconn_ind(NULL,
			    (char *)&sin6d, sizeof (sin6_t),
			    (char *)&tcp,
			    (t_scalar_t)sizeof (intptr_t),
			    (char *)&sin6d, sizeof (sin6_t),
			    (t_scalar_t)ltcp->tcp_conn_req_seqnum);
		} else {
			tpi_mp = mi_tpi_conn_ind(NULL,
			    (char *)&sin6, sizeof (sin6_t),
			    (char *)&tcp, (t_scalar_t)sizeof (intptr_t),
			    (t_scalar_t)ltcp->tcp_conn_req_seqnum);
		}
	} else {
		ip6h = (ip6_t *)mp->b_rptr;

		connp->conn_send = ip_output_v6;
		connp->conn_recv = tcp_input;

		connp->conn_bound_source_v6 = ip6h->ip6_dst;
		connp->conn_srcv6 = ip6h->ip6_dst;
		connp->conn_remv6 = ip6h->ip6_src;

		/* db_cksumstuff is set at ip_fanout_tcp_v6 */
		ifindex = (int)DB_CKSUMSTUFF(mp);
		DB_CKSUMSTUFF(mp) = 0;

		sin6 = sin6_null;
		sin6.sin6_addr = ip6h->ip6_src;
		sin6.sin6_port = *(uint16_t *)tcph->th_lport;
		sin6.sin6_family = AF_INET6;
		sin6.sin6_flowinfo = ip6h->ip6_vcf & ~IPV6_VERS_AND_FLOW_MASK;
		sin6.__sin6_src_id = ip_srcid_find_addr(&ip6h->ip6_dst,
		    lconnp->conn_zoneid, tcps->tcps_netstack);

		if (IN6_IS_ADDR_LINKSCOPE(&ip6h->ip6_src)) {
			/* Pass up the scope_id of remote addr */
			sin6.sin6_scope_id = ifindex;
		} else {
			sin6.sin6_scope_id = 0;
		}
		if (tcp->tcp_recvdstaddr) {
			sin6_t	sin6d;

			sin6d = sin6_null;
			sin6.sin6_addr = ip6h->ip6_dst;
			sin6d.sin6_port = *(uint16_t *)tcph->th_fport;
			sin6d.sin6_family = AF_INET;
			tpi_mp = mi_tpi_extconn_ind(NULL,
			    (char *)&sin6d, sizeof (sin6_t),
			    (char *)&tcp, (t_scalar_t)sizeof (intptr_t),
			    (char *)&sin6d, sizeof (sin6_t),
			    (t_scalar_t)ltcp->tcp_conn_req_seqnum);
		} else {
			tpi_mp = mi_tpi_conn_ind(NULL,
			    (char *)&sin6, sizeof (sin6_t),
			    (char *)&tcp, (t_scalar_t)sizeof (intptr_t),
			    (t_scalar_t)ltcp->tcp_conn_req_seqnum);
		}
	}

	if (tpi_mp == NULL)
		return (ENOMEM);

	connp->conn_fport = *(uint16_t *)tcph->th_lport;
	connp->conn_lport = *(uint16_t *)tcph->th_fport;
	connp->conn_flags |= (IPCL_TCP6|IPCL_EAGER);
	connp->conn_fully_bound = B_FALSE;

	/* Inherit information from the "parent" */
	tcp->tcp_ipversion = ltcp->tcp_ipversion;
	tcp->tcp_family = ltcp->tcp_family;

	tcp->tcp_wq = ltcp->tcp_wq;
	tcp->tcp_rq = ltcp->tcp_rq;

	tcp->tcp_mss = tcps->tcps_mss_def_ipv6;
	tcp->tcp_detached = B_TRUE;
	SOCK_CONNID_INIT(tcp->tcp_connid);
	if ((err = tcp_init_values(tcp)) != 0) {
		freemsg(tpi_mp);
		return (err);
	}

	if (ipvers == IPV4_VERSION) {
		if ((err = tcp_header_init_ipv4(tcp)) != 0) {
			freemsg(tpi_mp);
			return (err);
		}
		ASSERT(tcp->tcp_ipha != NULL);
	} else {
		/* ifindex must be already set */
		ASSERT(ifindex != 0);

		if (ltcp->tcp_bound_if != 0)
			tcp->tcp_bound_if = ltcp->tcp_bound_if;
		else if (IN6_IS_ADDR_LINKSCOPE(&ip6h->ip6_src))
			tcp->tcp_bound_if = ifindex;

		tcp->tcp_ipv6_recvancillary = ltcp->tcp_ipv6_recvancillary;
		tcp->tcp_recvifindex = 0;
		tcp->tcp_recvhops = 0xffffffffU;
		ASSERT(tcp->tcp_ip6h != NULL);
	}

	tcp->tcp_lport = ltcp->tcp_lport;

	if (ltcp->tcp_ipversion == tcp->tcp_ipversion) {
		if (tcp->tcp_iphc_len != ltcp->tcp_iphc_len) {
			/*
			 * Listener had options of some sort; eager inherits.
			 * Free up the eager template and allocate one
			 * of the right size.
			 */
			if (tcp->tcp_hdr_grown) {
				kmem_free(tcp->tcp_iphc, tcp->tcp_iphc_len);
			} else {
				bzero(tcp->tcp_iphc, tcp->tcp_iphc_len);
				kmem_cache_free(tcp_iphc_cache, tcp->tcp_iphc);
			}
			tcp->tcp_iphc = kmem_zalloc(ltcp->tcp_iphc_len,
			    KM_NOSLEEP);
			if (tcp->tcp_iphc == NULL) {
				tcp->tcp_iphc_len = 0;
				freemsg(tpi_mp);
				return (ENOMEM);
			}
			tcp->tcp_iphc_len = ltcp->tcp_iphc_len;
			tcp->tcp_hdr_grown = B_TRUE;
		}
		tcp->tcp_hdr_len = ltcp->tcp_hdr_len;
		tcp->tcp_ip_hdr_len = ltcp->tcp_ip_hdr_len;
		tcp->tcp_tcp_hdr_len = ltcp->tcp_tcp_hdr_len;
		tcp->tcp_ip6_hops = ltcp->tcp_ip6_hops;
		tcp->tcp_ip6_vcf = ltcp->tcp_ip6_vcf;

		/*
		 * Copy the IP+TCP header template from listener to eager
		 */
		bcopy(ltcp->tcp_iphc, tcp->tcp_iphc, ltcp->tcp_hdr_len);
		if (tcp->tcp_ipversion == IPV6_VERSION) {
			if (((ip6i_t *)(tcp->tcp_iphc))->ip6i_nxt ==
			    IPPROTO_RAW) {
				tcp->tcp_ip6h =
				    (ip6_t *)(tcp->tcp_iphc +
				    sizeof (ip6i_t));
			} else {
				tcp->tcp_ip6h =
				    (ip6_t *)(tcp->tcp_iphc);
			}
			tcp->tcp_ipha = NULL;
		} else {
			tcp->tcp_ipha = (ipha_t *)tcp->tcp_iphc;
			tcp->tcp_ip6h = NULL;
		}
		tcp->tcp_tcph = (tcph_t *)(tcp->tcp_iphc +
		    tcp->tcp_ip_hdr_len);
	} else {
		/*
		 * only valid case when ipversion of listener and
		 * eager differ is when listener is IPv6 and
		 * eager is IPv4.
		 * Eager header template has been initialized to the
		 * maximum v4 header sizes, which includes space for
		 * TCP and IP options.
		 */
		ASSERT((ltcp->tcp_ipversion == IPV6_VERSION) &&
		    (tcp->tcp_ipversion == IPV4_VERSION));
		ASSERT(tcp->tcp_iphc_len >=
		    TCP_MAX_COMBINED_HEADER_LENGTH);
		tcp->tcp_tcp_hdr_len = ltcp->tcp_tcp_hdr_len;
		/* copy IP header fields individually */
		tcp->tcp_ipha->ipha_ttl =
		    ltcp->tcp_ip6h->ip6_hops;
		bcopy(ltcp->tcp_tcph->th_lport,
		    tcp->tcp_tcph->th_lport, sizeof (ushort_t));
	}

	bcopy(tcph->th_lport, tcp->tcp_tcph->th_fport, sizeof (in_port_t));
	bcopy(tcp->tcp_tcph->th_fport, &tcp->tcp_fport,
	    sizeof (in_port_t));

	if (ltcp->tcp_lport == 0) {
		tcp->tcp_lport = *(in_port_t *)tcph->th_fport;
		bcopy(tcph->th_fport, tcp->tcp_tcph->th_lport,
		    sizeof (in_port_t));
	}

	if (tcp->tcp_ipversion == IPV4_VERSION) {
		ASSERT(ipha != NULL);
		tcp->tcp_ipha->ipha_dst = ipha->ipha_src;
		tcp->tcp_ipha->ipha_src = ipha->ipha_dst;

		/* Source routing option copyover (reverse it) */
		if (tcps->tcps_rev_src_routes)
			tcp_opt_reverse(tcp, ipha);
	} else {
		ASSERT(ip6h != NULL);
		tcp->tcp_ip6h->ip6_dst = ip6h->ip6_src;
		tcp->tcp_ip6h->ip6_src = ip6h->ip6_dst;
	}

	ASSERT(tcp->tcp_conn.tcp_eager_conn_ind == NULL);
	ASSERT(!tcp->tcp_tconnind_started);
	/*
	 * If the SYN contains a credential, it's a loopback packet; attach
	 * the credential to the TPI message.
	 */
	if ((cr = DB_CRED(idmp)) != NULL) {
		mblk_setcred(tpi_mp, cr);
		DB_CPID(tpi_mp) = DB_CPID(idmp);
	}
	tcp->tcp_conn.tcp_eager_conn_ind = tpi_mp;

	/* Inherit the listener's SSL protection state */

	if ((tcp->tcp_kssl_ent = ltcp->tcp_kssl_ent) != NULL) {
		kssl_hold_ent(tcp->tcp_kssl_ent);
		tcp->tcp_kssl_pending = B_TRUE;
	}

	/* Inherit the listener's non-STREAMS flag */
	if (IPCL_IS_NONSTR(lconnp)) {
		connp->conn_flags |= IPCL_NONSTR;
		connp->conn_upcalls = lconnp->conn_upcalls;
	}

	return (0);
}


int
tcp_conn_create_v4(conn_t *lconnp, conn_t *connp, ipha_t *ipha,
    tcph_t *tcph, mblk_t *idmp)
{
	tcp_t 		*ltcp = lconnp->conn_tcp;
	tcp_t		*tcp = connp->conn_tcp;
	sin_t		sin;
	mblk_t		*tpi_mp = NULL;
	int		err;
	cred_t		*cr;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	sin = sin_null;
	sin.sin_addr.s_addr = ipha->ipha_src;
	sin.sin_port = *(uint16_t *)tcph->th_lport;
	sin.sin_family = AF_INET;
	if (ltcp->tcp_recvdstaddr) {
		sin_t	sind;

		sind = sin_null;
		sind.sin_addr.s_addr = ipha->ipha_dst;
		sind.sin_port = *(uint16_t *)tcph->th_fport;
		sind.sin_family = AF_INET;
		tpi_mp = mi_tpi_extconn_ind(NULL,
		    (char *)&sind, sizeof (sin_t), (char *)&tcp,
		    (t_scalar_t)sizeof (intptr_t), (char *)&sind,
		    sizeof (sin_t), (t_scalar_t)ltcp->tcp_conn_req_seqnum);
	} else {
		tpi_mp = mi_tpi_conn_ind(NULL,
		    (char *)&sin, sizeof (sin_t),
		    (char *)&tcp, (t_scalar_t)sizeof (intptr_t),
		    (t_scalar_t)ltcp->tcp_conn_req_seqnum);
	}

	if (tpi_mp == NULL) {
		return (ENOMEM);
	}

	connp->conn_flags |= (IPCL_TCP4|IPCL_EAGER);
	connp->conn_send = ip_output;
	connp->conn_recv = tcp_input;
	connp->conn_fully_bound = B_FALSE;

	IN6_IPADDR_TO_V4MAPPED(ipha->ipha_dst, &connp->conn_bound_source_v6);
	IN6_IPADDR_TO_V4MAPPED(ipha->ipha_dst, &connp->conn_srcv6);
	IN6_IPADDR_TO_V4MAPPED(ipha->ipha_src, &connp->conn_remv6);
	connp->conn_fport = *(uint16_t *)tcph->th_lport;
	connp->conn_lport = *(uint16_t *)tcph->th_fport;

	/* Inherit information from the "parent" */
	tcp->tcp_ipversion = ltcp->tcp_ipversion;
	tcp->tcp_family = ltcp->tcp_family;
	tcp->tcp_wq = ltcp->tcp_wq;
	tcp->tcp_rq = ltcp->tcp_rq;
	tcp->tcp_mss = tcps->tcps_mss_def_ipv4;
	tcp->tcp_detached = B_TRUE;
	SOCK_CONNID_INIT(tcp->tcp_connid);
	if ((err = tcp_init_values(tcp)) != 0) {
		freemsg(tpi_mp);
		return (err);
	}

	/*
	 * Let's make sure that eager tcp template has enough space to
	 * copy IPv4 listener's tcp template. Since the conn_t structure is
	 * preserved and tcp_iphc_len is also preserved, an eager conn_t may
	 * have a tcp_template of total len TCP_MAX_COMBINED_HEADER_LENGTH or
	 * more (in case of re-allocation of conn_t with tcp-IPv6 template with
	 * extension headers or with ip6i_t struct). Note that bcopy() below
	 * copies listener tcp's hdr_len which cannot be greater than TCP_MAX_
	 * COMBINED_HEADER_LENGTH as this listener must be a IPv4 listener.
	 */
	ASSERT(tcp->tcp_iphc_len >= TCP_MAX_COMBINED_HEADER_LENGTH);
	ASSERT(ltcp->tcp_hdr_len <= TCP_MAX_COMBINED_HEADER_LENGTH);

	tcp->tcp_hdr_len = ltcp->tcp_hdr_len;
	tcp->tcp_ip_hdr_len = ltcp->tcp_ip_hdr_len;
	tcp->tcp_tcp_hdr_len = ltcp->tcp_tcp_hdr_len;
	tcp->tcp_ttl = ltcp->tcp_ttl;
	tcp->tcp_tos = ltcp->tcp_tos;

	/* Copy the IP+TCP header template from listener to eager */
	bcopy(ltcp->tcp_iphc, tcp->tcp_iphc, ltcp->tcp_hdr_len);
	tcp->tcp_ipha = (ipha_t *)tcp->tcp_iphc;
	tcp->tcp_ip6h = NULL;
	tcp->tcp_tcph = (tcph_t *)(tcp->tcp_iphc +
	    tcp->tcp_ip_hdr_len);

	/* Initialize the IP addresses and Ports */
	tcp->tcp_ipha->ipha_dst = ipha->ipha_src;
	tcp->tcp_ipha->ipha_src = ipha->ipha_dst;
	bcopy(tcph->th_lport, tcp->tcp_tcph->th_fport, sizeof (in_port_t));
	bcopy(tcph->th_fport, tcp->tcp_tcph->th_lport, sizeof (in_port_t));

	/* Source routing option copyover (reverse it) */
	if (tcps->tcps_rev_src_routes)
		tcp_opt_reverse(tcp, ipha);

	ASSERT(tcp->tcp_conn.tcp_eager_conn_ind == NULL);
	ASSERT(!tcp->tcp_tconnind_started);

	/*
	 * If the SYN contains a credential, it's a loopback packet; attach
	 * the credential to the TPI message.
	 */
	if ((cr = DB_CRED(idmp)) != NULL) {
		mblk_setcred(tpi_mp, cr);
		DB_CPID(tpi_mp) = DB_CPID(idmp);
	}
	tcp->tcp_conn.tcp_eager_conn_ind = tpi_mp;

	/* Inherit the listener's SSL protection state */
	if ((tcp->tcp_kssl_ent = ltcp->tcp_kssl_ent) != NULL) {
		kssl_hold_ent(tcp->tcp_kssl_ent);
		tcp->tcp_kssl_pending = B_TRUE;
	}

	/* Inherit the listener's non-STREAMS flag */
	if (IPCL_IS_NONSTR(lconnp)) {
		connp->conn_flags |= IPCL_NONSTR;
		connp->conn_upcalls = lconnp->conn_upcalls;
	}

	return (0);
}

/*
 * sets up conn for ipsec.
 * if the first mblk is M_CTL it is consumed and mpp is updated.
 * in case of error mpp is freed.
 */
conn_t *
tcp_get_ipsec_conn(tcp_t *tcp, squeue_t *sqp, mblk_t **mpp)
{
	conn_t 		*connp = tcp->tcp_connp;
	conn_t 		*econnp;
	squeue_t 	*new_sqp;
	mblk_t 		*first_mp = *mpp;
	mblk_t		*mp = *mpp;
	boolean_t	mctl_present = B_FALSE;
	uint_t		ipvers;

	econnp = tcp_get_conn(sqp, tcp->tcp_tcps);
	if (econnp == NULL) {
		freemsg(first_mp);
		return (NULL);
	}
	if (DB_TYPE(mp) == M_CTL) {
		if (mp->b_cont == NULL ||
		    mp->b_cont->b_datap->db_type != M_DATA) {
			freemsg(first_mp);
			return (NULL);
		}
		mp = mp->b_cont;
		if ((mp->b_datap->db_struioflag & STRUIO_EAGER) == 0) {
			freemsg(first_mp);
			return (NULL);
		}

		mp->b_datap->db_struioflag &= ~STRUIO_EAGER;
		first_mp->b_datap->db_struioflag &= ~STRUIO_POLICY;
		mctl_present = B_TRUE;
	} else {
		ASSERT(mp->b_datap->db_struioflag & STRUIO_POLICY);
		mp->b_datap->db_struioflag &= ~STRUIO_POLICY;
	}

	new_sqp = (squeue_t *)DB_CKSUMSTART(mp);
	DB_CKSUMSTART(mp) = 0;

	ASSERT(OK_32PTR(mp->b_rptr));
	ipvers = IPH_HDR_VERSION(mp->b_rptr);
	if (ipvers == IPV4_VERSION) {
		uint16_t  	*up;
		uint32_t	ports;
		ipha_t		*ipha;

		ipha = (ipha_t *)mp->b_rptr;
		up = (uint16_t *)((uchar_t *)ipha +
		    IPH_HDR_LENGTH(ipha) + TCP_PORTS_OFFSET);
		ports = *(uint32_t *)up;
		IPCL_TCP_EAGER_INIT(econnp, IPPROTO_TCP,
		    ipha->ipha_dst, ipha->ipha_src, ports);
	} else {
		uint16_t  	*up;
		uint32_t	ports;
		uint16_t	ip_hdr_len;
		uint8_t		*nexthdrp;
		ip6_t 		*ip6h;
		tcph_t		*tcph;

		ip6h = (ip6_t *)mp->b_rptr;
		if (ip6h->ip6_nxt == IPPROTO_TCP) {
			ip_hdr_len = IPV6_HDR_LEN;
		} else if (!ip_hdr_length_nexthdr_v6(mp, ip6h, &ip_hdr_len,
		    &nexthdrp) || *nexthdrp != IPPROTO_TCP) {
			CONN_DEC_REF(econnp);
			freemsg(first_mp);
			return (NULL);
		}
		tcph = (tcph_t *)&mp->b_rptr[ip_hdr_len];
		up = (uint16_t *)tcph->th_lport;
		ports = *(uint32_t *)up;
		IPCL_TCP_EAGER_INIT_V6(econnp, IPPROTO_TCP,
		    ip6h->ip6_dst, ip6h->ip6_src, ports);
	}

	/*
	 * The caller already ensured that there is a sqp present.
	 */
	econnp->conn_sqp = new_sqp;
	econnp->conn_initial_sqp = new_sqp;

	if (connp->conn_policy != NULL) {
		ipsec_in_t *ii;
		ii = (ipsec_in_t *)(first_mp->b_rptr);
		ASSERT(ii->ipsec_in_policy == NULL);
		IPPH_REFHOLD(connp->conn_policy);
		ii->ipsec_in_policy = connp->conn_policy;

		first_mp->b_datap->db_type = IPSEC_POLICY_SET;
		if (!ip_bind_ipsec_policy_set(econnp, first_mp)) {
			CONN_DEC_REF(econnp);
			freemsg(first_mp);
			return (NULL);
		}
	}

	if (ipsec_conn_cache_policy(econnp, ipvers == IPV4_VERSION) != 0) {
		CONN_DEC_REF(econnp);
		freemsg(first_mp);
		return (NULL);
	}

	/*
	 * If we know we have some policy, pass the "IPSEC"
	 * options size TCP uses this adjust the MSS.
	 */
	econnp->conn_tcp->tcp_ipsec_overhead = conn_ipsec_length(econnp);
	if (mctl_present) {
		freeb(first_mp);
		*mpp = mp;
	}

	return (econnp);
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
 * 2) Defence against DOS attack. Allocating a tcp/conn in tcp_conn_request
 * has multiple disadvantages - tying up the squeue during alloc, and the
 * fact that IPSec policy initialization has to happen here which
 * requires us sending a M_CTL and checking for it i.e. real ugliness.
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
		tcp->tcp_tcps = tcps;
		TCPS_REFHOLD(tcps);
		ipcl_globalhash_insert(connp);
		return ((void *)connp);
	}
	mutex_exit(&tcp_time_wait->tcp_time_wait_lock);
	if ((connp = ipcl_conn_create(IPCL_TCPCONN, KM_NOSLEEP,
	    tcps->tcps_netstack)) == NULL)
		return (NULL);
	tcp = connp->conn_tcp;
	/*
	 * Pre-allocate the tcp_rsrv_mp.  This mblk will not be freed
	 * until this conn_t/tcp_t is freed at ipcl_conn_destroy().
	 */
	if ((tcp->tcp_rsrv_mp = allocb(0, BPRI_HI)) == NULL) {
		ipcl_conn_destroy(connp);
		return (NULL);
	}
	mutex_init(&tcp->tcp_rsrv_mp_lock, NULL, MUTEX_DEFAULT, NULL);
	tcp->tcp_tcps = tcps;
	TCPS_REFHOLD(tcps);

	return ((void *)connp);
}

/*
 * Update the cached label for the given tcp_t.  This should be called once per
 * connection, and before any packets are sent or tcp_process_options is
 * invoked.  Returns B_FALSE if the correct label could not be constructed.
 */
static boolean_t
tcp_update_label(tcp_t *tcp, const cred_t *cr)
{
	conn_t *connp = tcp->tcp_connp;

	if (tcp->tcp_ipversion == IPV4_VERSION) {
		uchar_t optbuf[IP_MAX_OPT_LENGTH];
		int added;

		if (tsol_compute_label(cr, tcp->tcp_remote, optbuf,
		    connp->conn_mac_exempt,
		    tcp->tcp_tcps->tcps_netstack->netstack_ip) != 0)
			return (B_FALSE);

		added = tsol_remove_secopt(tcp->tcp_ipha, tcp->tcp_hdr_len);
		if (added == -1)
			return (B_FALSE);
		tcp->tcp_hdr_len += added;
		tcp->tcp_tcph = (tcph_t *)((uchar_t *)tcp->tcp_tcph + added);
		tcp->tcp_ip_hdr_len += added;
		if ((tcp->tcp_label_len = optbuf[IPOPT_OLEN]) != 0) {
			tcp->tcp_label_len = (tcp->tcp_label_len + 3) & ~3;
			added = tsol_prepend_option(optbuf, tcp->tcp_ipha,
			    tcp->tcp_hdr_len);
			if (added == -1)
				return (B_FALSE);
			tcp->tcp_hdr_len += added;
			tcp->tcp_tcph = (tcph_t *)
			    ((uchar_t *)tcp->tcp_tcph + added);
			tcp->tcp_ip_hdr_len += added;
		}
	} else {
		uchar_t optbuf[TSOL_MAX_IPV6_OPTION];

		if (tsol_compute_label_v6(cr, &tcp->tcp_remote_v6, optbuf,
		    connp->conn_mac_exempt,
		    tcp->tcp_tcps->tcps_netstack->netstack_ip) != 0)
			return (B_FALSE);
		if (tsol_update_sticky(&tcp->tcp_sticky_ipp,
		    &tcp->tcp_label_len, optbuf) != 0)
			return (B_FALSE);
		if (tcp_build_hdrs(tcp) != 0)
			return (B_FALSE);
	}

	connp->conn_ulp_labeled = 1;

	return (B_TRUE);
}

/* BEGIN CSTYLED */
/*
 *
 * The sockfs ACCEPT path:
 * =======================
 *
 * The eager is now established in its own perimeter as soon as SYN is
 * received in tcp_conn_request(). When sockfs receives conn_ind, it
 * completes the accept processing on the acceptor STREAM. The sending
 * of conn_ind part is common for both sockfs listener and a TLI/XTI
 * listener but a TLI/XTI listener completes the accept processing
 * on the listener perimeter.
 *
 * Common control flow for 3 way handshake:
 * ----------------------------------------
 *
 * incoming SYN (listener perimeter) 	-> tcp_rput_data()
 *					-> tcp_conn_request()
 *
 * incoming SYN-ACK-ACK (eager perim) 	-> tcp_rput_data()
 * send T_CONN_IND (listener perim)	-> tcp_send_conn_ind()
 *
 * Sockfs ACCEPT Path:
 * -------------------
 *
 * open acceptor stream (tcp_open allocates tcp_wput_accept()
 * as STREAM entry point)
 *
 * soaccept() sends T_CONN_RES on the acceptor STREAM to tcp_wput_accept()
 *
 * tcp_wput_accept() extracts the eager and makes the q->q_ptr <-> eager
 * association (we are not behind eager's squeue but sockfs is protecting us
 * and no one knows about this stream yet. The STREAMS entry point q->q_info
 * is changed to point at tcp_wput().
 *
 * tcp_wput_accept() sends any deferred eagers via tcp_send_pending() to
 * listener (done on listener's perimeter).
 *
 * tcp_wput_accept() calls tcp_accept_finish() on eagers perimeter to finish
 * accept.
 *
 * TLI/XTI client ACCEPT path:
 * ---------------------------
 *
 * soaccept() sends T_CONN_RES on the listener STREAM.
 *
 * tcp_accept() -> tcp_accept_swap() complete the processing and send
 * the bind_mp to eager perimeter to finish accept (tcp_rput_other()).
 *
 * Locks:
 * ======
 *
 * listener->tcp_eager_lock protects the listeners->tcp_eager_next_q0 and
 * and listeners->tcp_eager_next_q.
 *
 * Referencing:
 * ============
 *
 * 1) We start out in tcp_conn_request by eager placing a ref on
 * listener and listener adding eager to listeners->tcp_eager_next_q0.
 *
 * 2) When a SYN-ACK-ACK arrives, we send the conn_ind to listener. Before
 * doing so we place a ref on the eager. This ref is finally dropped at the
 * end of tcp_accept_finish() while unwinding from the squeue, i.e. the
 * reference is dropped by the squeue framework.
 *
 * 3) The ref on listener placed in 1 above is dropped in tcp_accept_finish
 *
 * The reference must be released by the same entity that added the reference
 * In the above scheme, the eager is the entity that adds and releases the
 * references. Note that tcp_accept_finish executes in the squeue of the eager
 * (albeit after it is attached to the acceptor stream). Though 1. executes
 * in the listener's squeue, the eager is nascent at this point and the
 * reference can be considered to have been added on behalf of the eager.
 *
 * Eager getting a Reset or listener closing:
 * ==========================================
 *
 * Once the listener and eager are linked, the listener never does the unlink.
 * If the listener needs to close, tcp_eager_cleanup() is called which queues
 * a message on all eager perimeter. The eager then does the unlink, clears
 * any pointers to the listener's queue and drops the reference to the
 * listener. The listener waits in tcp_close outside the squeue until its
 * refcount has dropped to 1. This ensures that the listener has waited for
 * all eagers to clear their association with the listener.
 *
 * Similarly, if eager decides to go away, it can unlink itself and close.
 * When the T_CONN_RES comes down, we check if eager has closed. Note that
 * the reference to eager is still valid because of the extra ref we put
 * in tcp_send_conn_ind.
 *
 * Listener can always locate the eager under the protection
 * of the listener->tcp_eager_lock, and then do a refhold
 * on the eager during the accept processing.
 *
 * The acceptor stream accesses the eager in the accept processing
 * based on the ref placed on eager before sending T_conn_ind.
 * The only entity that can negate this refhold is a listener close
 * which is mutually exclusive with an active acceptor stream.
 *
 * Eager's reference on the listener
 * ===================================
 *
 * If the accept happens (even on a closed eager) the eager drops its
 * reference on the listener at the start of tcp_accept_finish. If the
 * eager is killed due to an incoming RST before the T_conn_ind is sent up,
 * the reference is dropped in tcp_closei_local. If the listener closes,
 * the reference is dropped in tcp_eager_kill. In all cases the reference
 * is dropped while executing in the eager's context (squeue).
 */
/* END CSTYLED */

/* Process the SYN packet, mp, directed at the listener 'tcp' */

/*
 * THIS FUNCTION IS DIRECTLY CALLED BY IP VIA SQUEUE FOR SYN.
 * tcp_rput_data will not see any SYN packets.
 */
/* ARGSUSED */
void
tcp_conn_request(void *arg, mblk_t *mp, void *arg2)
{
	tcph_t		*tcph;
	uint32_t	seg_seq;
	tcp_t		*eager;
	uint_t		ipvers;
	ipha_t		*ipha;
	ip6_t		*ip6h;
	int		err;
	conn_t		*econnp = NULL;
	squeue_t	*new_sqp;
	mblk_t		*mp1;
	uint_t 		ip_hdr_len;
	conn_t		*connp = (conn_t *)arg;
	tcp_t		*tcp = connp->conn_tcp;
	cred_t		*credp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	ip_stack_t	*ipst;

	if (tcp->tcp_state != TCPS_LISTEN)
		goto error2;

	ASSERT((tcp->tcp_connp->conn_flags & IPCL_BOUND) != 0);

	mutex_enter(&tcp->tcp_eager_lock);
	if (tcp->tcp_conn_req_cnt_q >= tcp->tcp_conn_req_max) {
		mutex_exit(&tcp->tcp_eager_lock);
		TCP_STAT(tcps, tcp_listendrop);
		BUMP_MIB(&tcps->tcps_mib, tcpListenDrop);
		if (tcp->tcp_debug) {
			(void) strlog(TCP_MOD_ID, 0, 1, SL_TRACE|SL_ERROR,
			    "tcp_conn_request: listen backlog (max=%d) "
			    "overflow (%d pending) on %s",
			    tcp->tcp_conn_req_max, tcp->tcp_conn_req_cnt_q,
			    tcp_display(tcp, NULL, DISP_PORT_ONLY));
		}
		goto error2;
	}

	if (tcp->tcp_conn_req_cnt_q0 >=
	    tcp->tcp_conn_req_max + tcps->tcps_conn_req_max_q0) {
		/*
		 * Q0 is full. Drop a pending half-open req from the queue
		 * to make room for the new SYN req. Also mark the time we
		 * drop a SYN.
		 *
		 * A more aggressive defense against SYN attack will
		 * be to set the "tcp_syn_defense" flag now.
		 */
		TCP_STAT(tcps, tcp_listendropq0);
		tcp->tcp_last_rcv_lbolt = lbolt64;
		if (!tcp_drop_q0(tcp)) {
			mutex_exit(&tcp->tcp_eager_lock);
			BUMP_MIB(&tcps->tcps_mib, tcpListenDropQ0);
			if (tcp->tcp_debug) {
				(void) strlog(TCP_MOD_ID, 0, 3, SL_TRACE,
				    "tcp_conn_request: listen half-open queue "
				    "(max=%d) full (%d pending) on %s",
				    tcps->tcps_conn_req_max_q0,
				    tcp->tcp_conn_req_cnt_q0,
				    tcp_display(tcp, NULL,
				    DISP_PORT_ONLY));
			}
			goto error2;
		}
	}
	mutex_exit(&tcp->tcp_eager_lock);

	/*
	 * IP adds STRUIO_EAGER and ensures that the received packet is
	 * M_DATA even if conn_ipv6_recvpktinfo is enabled or for ip6
	 * link local address.  If IPSec is enabled, db_struioflag has
	 * STRUIO_POLICY set (mutually exclusive from STRUIO_EAGER);
	 * otherwise an error case if neither of them is set.
	 */
	if ((mp->b_datap->db_struioflag & STRUIO_EAGER) != 0) {
		new_sqp = (squeue_t *)DB_CKSUMSTART(mp);
		DB_CKSUMSTART(mp) = 0;
		mp->b_datap->db_struioflag &= ~STRUIO_EAGER;
		econnp = (conn_t *)tcp_get_conn(arg2, tcps);
		if (econnp == NULL)
			goto error2;
		ASSERT(econnp->conn_netstack == connp->conn_netstack);
		econnp->conn_sqp = new_sqp;
		econnp->conn_initial_sqp = new_sqp;
	} else if ((mp->b_datap->db_struioflag & STRUIO_POLICY) != 0) {
		/*
		 * mp is updated in tcp_get_ipsec_conn().
		 */
		econnp = tcp_get_ipsec_conn(tcp, arg2, &mp);
		if (econnp == NULL) {
			/*
			 * mp freed by tcp_get_ipsec_conn.
			 */
			return;
		}
		ASSERT(econnp->conn_netstack == connp->conn_netstack);
	} else {
		goto error2;
	}

	ASSERT(DB_TYPE(mp) == M_DATA);

	ipvers = IPH_HDR_VERSION(mp->b_rptr);
	ASSERT(ipvers == IPV6_VERSION || ipvers == IPV4_VERSION);
	ASSERT(OK_32PTR(mp->b_rptr));
	if (ipvers == IPV4_VERSION) {
		ipha = (ipha_t *)mp->b_rptr;
		ip_hdr_len = IPH_HDR_LENGTH(ipha);
		tcph = (tcph_t *)&mp->b_rptr[ip_hdr_len];
	} else {
		ip6h = (ip6_t *)mp->b_rptr;
		ip_hdr_len = ip_hdr_length_v6(mp, ip6h);
		tcph = (tcph_t *)&mp->b_rptr[ip_hdr_len];
	}

	if (tcp->tcp_family == AF_INET) {
		ASSERT(ipvers == IPV4_VERSION);
		err = tcp_conn_create_v4(connp, econnp, ipha, tcph, mp);
	} else {
		err = tcp_conn_create_v6(connp, econnp, mp, tcph, ipvers, mp);
	}

	if (err)
		goto error3;

	eager = econnp->conn_tcp;

	/*
	 * Pre-allocate the T_ordrel_ind mblk for TPI socket so that at close
	 * time, we will always have that to send up.  Otherwise, we need to do
	 * special handling in case the allocation fails at that time.
	 */
	ASSERT(eager->tcp_ordrel_mp == NULL);
	if (!IPCL_IS_NONSTR(econnp) &&
	    (eager->tcp_ordrel_mp = mi_tpi_ordrel_ind()) == NULL)
		goto error3;

	/* Inherit various TCP parameters from the listener */
	eager->tcp_naglim = tcp->tcp_naglim;
	eager->tcp_first_timer_threshold =
	    tcp->tcp_first_timer_threshold;
	eager->tcp_second_timer_threshold =
	    tcp->tcp_second_timer_threshold;

	eager->tcp_first_ctimer_threshold =
	    tcp->tcp_first_ctimer_threshold;
	eager->tcp_second_ctimer_threshold =
	    tcp->tcp_second_ctimer_threshold;

	/*
	 * tcp_adapt_ire() may change tcp_rwnd according to the ire metrics.
	 * If it does not, the eager's receive window will be set to the
	 * listener's receive window later in this function.
	 */
	eager->tcp_rwnd = 0;

	/*
	 * Inherit listener's tcp_init_cwnd.  Need to do this before
	 * calling tcp_process_options() where tcp_mss_set() is called
	 * to set the initial cwnd.
	 */
	eager->tcp_init_cwnd = tcp->tcp_init_cwnd;

	/*
	 * Zones: tcp_adapt_ire() and tcp_send_data() both need the
	 * zone id before the accept is completed in tcp_wput_accept().
	 */
	econnp->conn_zoneid = connp->conn_zoneid;
	econnp->conn_allzones = connp->conn_allzones;

	/* Copy nexthop information from listener to eager */
	if (connp->conn_nexthop_set) {
		econnp->conn_nexthop_set = connp->conn_nexthop_set;
		econnp->conn_nexthop_v4 = connp->conn_nexthop_v4;
	}

	/*
	 * TSOL: tsol_input_proc() needs the eager's cred before the
	 * eager is accepted
	 */
	econnp->conn_cred = eager->tcp_cred = credp = connp->conn_cred;
	crhold(credp);

	/*
	 * If the caller has the process-wide flag set, then default to MAC
	 * exempt mode.  This allows read-down to unlabeled hosts.
	 */
	if (getpflags(NET_MAC_AWARE, credp) != 0)
		econnp->conn_mac_exempt = B_TRUE;

	if (is_system_labeled()) {
		cred_t *cr;

		if (connp->conn_mlp_type != mlptSingle) {
			cr = econnp->conn_peercred = DB_CRED(mp);
			if (cr != NULL)
				crhold(cr);
			else
				cr = econnp->conn_cred;
			DTRACE_PROBE2(mlp_syn_accept, conn_t *,
			    econnp, cred_t *, cr)
		} else {
			cr = econnp->conn_cred;
			DTRACE_PROBE2(syn_accept, conn_t *,
			    econnp, cred_t *, cr)
		}

		if (!tcp_update_label(eager, cr)) {
			DTRACE_PROBE3(
			    tx__ip__log__error__connrequest__tcp,
			    char *, "eager connp(1) label on SYN mp(2) failed",
			    conn_t *, econnp, mblk_t *, mp);
			goto error3;
		}
	}

	eager->tcp_hard_binding = B_TRUE;

	tcp_bind_hash_insert(&tcps->tcps_bind_fanout[
	    TCP_BIND_HASH(eager->tcp_lport)], eager, 0);

	CL_INET_CONNECT(connp, eager, B_FALSE, err);
	if (err != 0) {
		tcp_bind_hash_remove(eager);
		goto error3;
	}

	/*
	 * No need to check for multicast destination since ip will only pass
	 * up multicasts to those that have expressed interest
	 * TODO: what about rejecting broadcasts?
	 * Also check that source is not a multicast or broadcast address.
	 */
	eager->tcp_state = TCPS_SYN_RCVD;


	/*
	 * There should be no ire in the mp as we are being called after
	 * receiving the SYN.
	 */
	ASSERT(tcp_ire_mp(&mp) == NULL);

	/*
	 * Adapt our mss, ttl, ... according to information provided in IRE.
	 */

	if (tcp_adapt_ire(eager, NULL) == 0) {
		/* Undo the bind_hash_insert */
		tcp_bind_hash_remove(eager);
		goto error3;
	}

	/* Process all TCP options. */
	tcp_process_options(eager, tcph);

	/* Is the other end ECN capable? */
	if (tcps->tcps_ecn_permitted >= 1 &&
	    (tcph->th_flags[0] & (TH_ECE|TH_CWR)) == (TH_ECE|TH_CWR)) {
		eager->tcp_ecn_ok = B_TRUE;
	}

	/*
	 * listener->tcp_rq->q_hiwat should be the default window size or a
	 * window size changed via SO_RCVBUF option.  First round up the
	 * eager's tcp_rwnd to the nearest MSS.  Then find out the window
	 * scale option value if needed.  Call tcp_rwnd_set() to finish the
	 * setting.
	 *
	 * Note if there is a rpipe metric associated with the remote host,
	 * we should not inherit receive window size from listener.
	 */
	eager->tcp_rwnd = MSS_ROUNDUP(
	    (eager->tcp_rwnd == 0 ? tcp->tcp_recv_hiwater:
	    eager->tcp_rwnd), eager->tcp_mss);
	if (eager->tcp_snd_ws_ok)
		tcp_set_ws_value(eager);
	/*
	 * Note that this is the only place tcp_rwnd_set() is called for
	 * accepting a connection.  We need to call it here instead of
	 * after the 3-way handshake because we need to tell the other
	 * side our rwnd in the SYN-ACK segment.
	 */
	(void) tcp_rwnd_set(eager, eager->tcp_rwnd);

	/*
	 * We eliminate the need for sockfs to send down a T_SVR4_OPTMGMT_REQ
	 * via soaccept()->soinheritoptions() which essentially applies
	 * all the listener options to the new STREAM. The options that we
	 * need to take care of are:
	 * SO_DEBUG, SO_REUSEADDR, SO_KEEPALIVE, SO_DONTROUTE, SO_BROADCAST,
	 * SO_USELOOPBACK, SO_OOBINLINE, SO_DGRAM_ERRIND, SO_LINGER,
	 * SO_SNDBUF, SO_RCVBUF.
	 *
	 * SO_RCVBUF:	tcp_rwnd_set() above takes care of it.
	 * SO_SNDBUF:	Set the tcp_xmit_hiwater for the eager. When
	 *		tcp_maxpsz_set() gets called later from
	 *		tcp_accept_finish(), the option takes effect.
	 *
	 */
	/* Set the TCP options */
	eager->tcp_recv_hiwater = tcp->tcp_recv_hiwater;
	eager->tcp_recv_lowater = tcp->tcp_recv_lowater;
	eager->tcp_xmit_hiwater = tcp->tcp_xmit_hiwater;
	eager->tcp_dgram_errind = tcp->tcp_dgram_errind;
	eager->tcp_oobinline = tcp->tcp_oobinline;
	eager->tcp_reuseaddr = tcp->tcp_reuseaddr;
	eager->tcp_broadcast = tcp->tcp_broadcast;
	eager->tcp_useloopback = tcp->tcp_useloopback;
	eager->tcp_dontroute = tcp->tcp_dontroute;
	eager->tcp_debug = tcp->tcp_debug;
	eager->tcp_linger = tcp->tcp_linger;
	eager->tcp_lingertime = tcp->tcp_lingertime;
	if (tcp->tcp_ka_enabled)
		eager->tcp_ka_enabled = 1;

	/* Set the IP options */
	econnp->conn_broadcast = connp->conn_broadcast;
	econnp->conn_loopback = connp->conn_loopback;
	econnp->conn_dontroute = connp->conn_dontroute;
	econnp->conn_reuseaddr = connp->conn_reuseaddr;

	/* Put a ref on the listener for the eager. */
	CONN_INC_REF(connp);
	mutex_enter(&tcp->tcp_eager_lock);
	tcp->tcp_eager_next_q0->tcp_eager_prev_q0 = eager;
	eager->tcp_eager_next_q0 = tcp->tcp_eager_next_q0;
	tcp->tcp_eager_next_q0 = eager;
	eager->tcp_eager_prev_q0 = tcp;

	/* Set tcp_listener before adding it to tcp_conn_fanout */
	eager->tcp_listener = tcp;
	eager->tcp_saved_listener = tcp;

	/*
	 * Tag this detached tcp vector for later retrieval
	 * by our listener client in tcp_accept().
	 */
	eager->tcp_conn_req_seqnum = tcp->tcp_conn_req_seqnum;
	tcp->tcp_conn_req_cnt_q0++;
	if (++tcp->tcp_conn_req_seqnum == -1) {
		/*
		 * -1 is "special" and defined in TPI as something
		 * that should never be used in T_CONN_IND
		 */
		++tcp->tcp_conn_req_seqnum;
	}
	mutex_exit(&tcp->tcp_eager_lock);

	if (tcp->tcp_syn_defense) {
		/* Don't drop the SYN that comes from a good IP source */
		ipaddr_t *addr_cache = (ipaddr_t *)(tcp->tcp_ip_addr_cache);
		if (addr_cache != NULL && eager->tcp_remote ==
		    addr_cache[IP_ADDR_CACHE_HASH(eager->tcp_remote)]) {
			eager->tcp_dontdrop = B_TRUE;
		}
	}

	/*
	 * We need to insert the eager in its own perimeter but as soon
	 * as we do that, we expose the eager to the classifier and
	 * should not touch any field outside the eager's perimeter.
	 * So do all the work necessary before inserting the eager
	 * in its own perimeter. Be optimistic that ipcl_conn_insert()
	 * will succeed but undo everything if it fails.
	 */
	seg_seq = ABE32_TO_U32(tcph->th_seq);
	eager->tcp_irs = seg_seq;
	eager->tcp_rack = seg_seq;
	eager->tcp_rnxt = seg_seq + 1;
	U32_TO_ABE32(eager->tcp_rnxt, eager->tcp_tcph->th_ack);
	BUMP_MIB(&tcps->tcps_mib, tcpPassiveOpens);
	eager->tcp_state = TCPS_SYN_RCVD;
	mp1 = tcp_xmit_mp(eager, eager->tcp_xmit_head, eager->tcp_mss,
	    NULL, NULL, eager->tcp_iss, B_FALSE, NULL, B_FALSE);
	if (mp1 == NULL) {
		/*
		 * Increment the ref count as we are going to
		 * enqueueing an mp in squeue
		 */
		CONN_INC_REF(econnp);
		goto error;
	}

	DB_CPID(mp1) = tcp->tcp_cpid;
	mblk_setcred(mp1, CONN_CRED(eager->tcp_connp));
	eager->tcp_cpid = tcp->tcp_cpid;
	eager->tcp_open_time = lbolt64;

	/*
	 * We need to start the rto timer. In normal case, we start
	 * the timer after sending the packet on the wire (or at
	 * least believing that packet was sent by waiting for
	 * CALL_IP_WPUT() to return). Since this is the first packet
	 * being sent on the wire for the eager, our initial tcp_rto
	 * is at least tcp_rexmit_interval_min which is a fairly
	 * large value to allow the algorithm to adjust slowly to large
	 * fluctuations of RTT during first few transmissions.
	 *
	 * Starting the timer first and then sending the packet in this
	 * case shouldn't make much difference since tcp_rexmit_interval_min
	 * is of the order of several 100ms and starting the timer
	 * first and then sending the packet will result in difference
	 * of few micro seconds.
	 *
	 * Without this optimization, we are forced to hold the fanout
	 * lock across the ipcl_bind_insert() and sending the packet
	 * so that we don't race against an incoming packet (maybe RST)
	 * for this eager.
	 *
	 * It is necessary to acquire an extra reference on the eager
	 * at this point and hold it until after tcp_send_data() to
	 * ensure against an eager close race.
	 */

	CONN_INC_REF(eager->tcp_connp);

	TCP_TIMER_RESTART(eager, eager->tcp_rto);

	/*
	 * Insert the eager in its own perimeter now. We are ready to deal
	 * with any packets on eager.
	 */
	if (eager->tcp_ipversion == IPV4_VERSION) {
		if (ipcl_conn_insert(econnp, IPPROTO_TCP, 0, 0, 0) != 0) {
			goto error;
		}
	} else {
		if (ipcl_conn_insert_v6(econnp, IPPROTO_TCP, 0, 0, 0, 0) != 0) {
			goto error;
		}
	}

	/* mark conn as fully-bound */
	econnp->conn_fully_bound = B_TRUE;

	/* Send the SYN-ACK */
	tcp_send_data(eager, eager->tcp_wq, mp1);
	CONN_DEC_REF(eager->tcp_connp);
	freemsg(mp);

	return;
error:
	freemsg(mp1);
	eager->tcp_closemp_used = B_TRUE;
	TCP_DEBUG_GETPCSTACK(eager->tcmp_stk, 15);
	mp1 = &eager->tcp_closemp;
	SQUEUE_ENTER_ONE(econnp->conn_sqp, mp1, tcp_eager_kill,
	    econnp, SQ_FILL, SQTAG_TCP_CONN_REQ_2);

	/*
	 * If a connection already exists, send the mp to that connections so
	 * that it can be appropriately dealt with.
	 */
	ipst = tcps->tcps_netstack->netstack_ip;

	if ((econnp = ipcl_classify(mp, connp->conn_zoneid, ipst)) != NULL) {
		if (!IPCL_IS_CONNECTED(econnp)) {
			/*
			 * Something bad happened. ipcl_conn_insert()
			 * failed because a connection already existed
			 * in connected hash but we can't find it
			 * anymore (someone blew it away). Just
			 * free this message and hopefully remote
			 * will retransmit at which time the SYN can be
			 * treated as a new connection or dealth with
			 * a TH_RST if a connection already exists.
			 */
			CONN_DEC_REF(econnp);
			freemsg(mp);
		} else {
			SQUEUE_ENTER_ONE(econnp->conn_sqp, mp,
			    tcp_input, econnp, SQ_FILL, SQTAG_TCP_CONN_REQ_1);
		}
	} else {
		/* Nobody wants this packet */
		freemsg(mp);
	}
	return;
error3:
	CONN_DEC_REF(econnp);
error2:
	freemsg(mp);
}

/*
 * In an ideal case of vertical partition in NUMA architecture, its
 * beneficial to have the listener and all the incoming connections
 * tied to the same squeue. The other constraint is that incoming
 * connections should be tied to the squeue attached to interrupted
 * CPU for obvious locality reason so this leaves the listener to
 * be tied to the same squeue. Our only problem is that when listener
 * is binding, the CPU that will get interrupted by the NIC whose
 * IP address the listener is binding to is not even known. So
 * the code below allows us to change that binding at the time the
 * CPU is interrupted by virtue of incoming connection's squeue.
 *
 * This is usefull only in case of a listener bound to a specific IP
 * address. For other kind of listeners, they get bound the
 * very first time and there is no attempt to rebind them.
 */
void
tcp_conn_request_unbound(void *arg, mblk_t *mp, void *arg2)
{
	conn_t		*connp = (conn_t *)arg;
	squeue_t	*sqp = (squeue_t *)arg2;
	squeue_t	*new_sqp;
	uint32_t	conn_flags;

	if ((mp->b_datap->db_struioflag & STRUIO_EAGER) != 0) {
		new_sqp = (squeue_t *)DB_CKSUMSTART(mp);
	} else {
		goto done;
	}

	if (connp->conn_fanout == NULL)
		goto done;

	if (!(connp->conn_flags & IPCL_FULLY_BOUND)) {
		mutex_enter(&connp->conn_fanout->connf_lock);
		mutex_enter(&connp->conn_lock);
		/*
		 * No one from read or write side can access us now
		 * except for already queued packets on this squeue.
		 * But since we haven't changed the squeue yet, they
		 * can't execute. If they are processed after we have
		 * changed the squeue, they are sent back to the
		 * correct squeue down below.
		 * But a listner close can race with processing of
		 * incoming SYN. If incoming SYN processing changes
		 * the squeue then the listener close which is waiting
		 * to enter the squeue would operate on the wrong
		 * squeue. Hence we don't change the squeue here unless
		 * the refcount is exactly the minimum refcount. The
		 * minimum refcount of 4 is counted as - 1 each for
		 * TCP and IP, 1 for being in the classifier hash, and
		 * 1 for the mblk being processed.
		 */

		if (connp->conn_ref != 4 ||
		    connp->conn_tcp->tcp_state != TCPS_LISTEN) {
			mutex_exit(&connp->conn_lock);
			mutex_exit(&connp->conn_fanout->connf_lock);
			goto done;
		}
		if (connp->conn_sqp != new_sqp) {
			while (connp->conn_sqp != new_sqp)
				(void) casptr(&connp->conn_sqp, sqp, new_sqp);
		}

		do {
			conn_flags = connp->conn_flags;
			conn_flags |= IPCL_FULLY_BOUND;
			(void) cas32(&connp->conn_flags, connp->conn_flags,
			    conn_flags);
		} while (!(connp->conn_flags & IPCL_FULLY_BOUND));

		mutex_exit(&connp->conn_fanout->connf_lock);
		mutex_exit(&connp->conn_lock);
	}

done:
	if (connp->conn_sqp != sqp) {
		CONN_INC_REF(connp);
		SQUEUE_ENTER_ONE(connp->conn_sqp, mp, connp->conn_recv, connp,
		    SQ_FILL, SQTAG_TCP_CONN_REQ_UNBOUND);
	} else {
		tcp_conn_request(connp, mp, sqp);
	}
}

/*
 * Successful connect request processing begins when our client passes
 * a T_CONN_REQ message into tcp_wput() and ends when tcp_rput() passes
 * our T_OK_ACK reply message upstream.  The control flow looks like this:
 *   upstream -> tcp_wput() -> tcp_wput_proto() -> tcp_tpi_connect() -> IP
 *   upstream <- tcp_rput()		<- IP
 * After various error checks are completed, tcp_tpi_connect() lays
 * the target address and port into the composite header template,
 * preallocates the T_OK_ACK reply message, construct a full 12 byte bind
 * request followed by an IRE request, and passes the three mblk message
 * down to IP looking like this:
 *   O_T_BIND_REQ for IP  --> IRE req --> T_OK_ACK for our client
 * Processing continues in tcp_rput() when we receive the following message:
 *   T_BIND_ACK from IP --> IRE ack --> T_OK_ACK for our client
 * After consuming the first two mblks, tcp_rput() calls tcp_timer(),
 * to fire off the connection request, and then passes the T_OK_ACK mblk
 * upstream that we filled in below.  There are, of course, numerous
 * error conditions along the way which truncate the processing described
 * above.
 */
static void
tcp_tpi_connect(tcp_t *tcp, mblk_t *mp)
{
	sin_t		*sin;
	queue_t		*q = tcp->tcp_wq;
	struct T_conn_req	*tcr;
	struct sockaddr	*sa;
	socklen_t	len;
	int		error;

	tcr = (struct T_conn_req *)mp->b_rptr;

	ASSERT((uintptr_t)(mp->b_wptr - mp->b_rptr) <= (uintptr_t)INT_MAX);
	if ((mp->b_wptr - mp->b_rptr) < sizeof (*tcr)) {
		tcp_err_ack(tcp, mp, TPROTO, 0);
		return;
	}

	/*
	 * Pre-allocate the T_ordrel_ind mblk so that at close time, we
	 * will always have that to send up.  Otherwise, we need to do
	 * special handling in case the allocation fails at that time.
	 * If the end point is TPI, the tcp_t can be reused and the
	 * tcp_ordrel_mp may be allocated already.
	 */
	if (tcp->tcp_ordrel_mp == NULL) {
		if ((tcp->tcp_ordrel_mp = mi_tpi_ordrel_ind()) == NULL) {
			tcp_err_ack(tcp, mp, TSYSERR, ENOMEM);
			return;
		}
	}

	/*
	 * Determine packet type based on type of address passed in
	 * the request should contain an IPv4 or IPv6 address.
	 * Make sure that address family matches the type of
	 * family of the the address passed down
	 */
	switch (tcr->DEST_length) {
	default:
		tcp_err_ack(tcp, mp, TBADADDR, 0);
		return;

	case (sizeof (sin_t) - sizeof (sin->sin_zero)): {
		/*
		 * XXX: The check for valid DEST_length was not there
		 * in earlier releases and some buggy
		 * TLI apps (e.g Sybase) got away with not feeding
		 * in sin_zero part of address.
		 * We allow that bug to keep those buggy apps humming.
		 * Test suites require the check on DEST_length.
		 * We construct a new mblk with valid DEST_length
		 * free the original so the rest of the code does
		 * not have to keep track of this special shorter
		 * length address case.
		 */
		mblk_t *nmp;
		struct T_conn_req *ntcr;
		sin_t *nsin;

		nmp = allocb(sizeof (struct T_conn_req) + sizeof (sin_t) +
		    tcr->OPT_length, BPRI_HI);
		if (nmp == NULL) {
			tcp_err_ack(tcp, mp, TSYSERR, ENOMEM);
			return;
		}
		ntcr = (struct T_conn_req *)nmp->b_rptr;
		bzero(ntcr, sizeof (struct T_conn_req)); /* zero fill */
		ntcr->PRIM_type = T_CONN_REQ;
		ntcr->DEST_length = sizeof (sin_t);
		ntcr->DEST_offset = sizeof (struct T_conn_req);

		nsin = (sin_t *)((uchar_t *)ntcr + ntcr->DEST_offset);
		*nsin = sin_null;
		/* Get pointer to shorter address to copy from original mp */
		sin = (sin_t *)mi_offset_param(mp, tcr->DEST_offset,
		    tcr->DEST_length); /* extract DEST_length worth of sin_t */
		if (sin == NULL || !OK_32PTR((char *)sin)) {
			freemsg(nmp);
			tcp_err_ack(tcp, mp, TSYSERR, EINVAL);
			return;
		}
		nsin->sin_family = sin->sin_family;
		nsin->sin_port = sin->sin_port;
		nsin->sin_addr = sin->sin_addr;
		/* Note:nsin->sin_zero zero-fill with sin_null assign above */
		nmp->b_wptr = (uchar_t *)&nsin[1];
		if (tcr->OPT_length != 0) {
			ntcr->OPT_length = tcr->OPT_length;
			ntcr->OPT_offset = nmp->b_wptr - nmp->b_rptr;
			bcopy((uchar_t *)tcr + tcr->OPT_offset,
			    (uchar_t *)ntcr + ntcr->OPT_offset,
			    tcr->OPT_length);
			nmp->b_wptr += tcr->OPT_length;
		}
		freemsg(mp);	/* original mp freed */
		mp = nmp;	/* re-initialize original variables */
		tcr = ntcr;
	}
	/* FALLTHRU */

	case sizeof (sin_t):
		sa = (struct sockaddr *)mi_offset_param(mp, tcr->DEST_offset,
		    sizeof (sin_t));
		len = sizeof (sin_t);
		break;

	case sizeof (sin6_t):
		sa = (struct sockaddr *)mi_offset_param(mp, tcr->DEST_offset,
		    sizeof (sin6_t));
		len = sizeof (sin6_t);
		break;
	}

	error = proto_verify_ip_addr(tcp->tcp_family, sa, len);
	if (error != 0) {
		tcp_err_ack(tcp, mp, TSYSERR, error);
		return;
	}

	/*
	 * TODO: If someone in TCPS_TIME_WAIT has this dst/port we
	 * should key on their sequence number and cut them loose.
	 */

	/*
	 * If options passed in, feed it for verification and handling
	 */
	if (tcr->OPT_length != 0) {
		mblk_t	*ok_mp;
		mblk_t	*discon_mp;
		mblk_t  *conn_opts_mp;
		int t_error, sys_error, do_disconnect;

		conn_opts_mp = NULL;

		if (tcp_conprim_opt_process(tcp, mp,
		    &do_disconnect, &t_error, &sys_error) < 0) {
			if (do_disconnect) {
				ASSERT(t_error == 0 && sys_error == 0);
				discon_mp = mi_tpi_discon_ind(NULL,
				    ECONNREFUSED, 0);
				if (!discon_mp) {
					tcp_err_ack_prim(tcp, mp, T_CONN_REQ,
					    TSYSERR, ENOMEM);
					return;
				}
				ok_mp = mi_tpi_ok_ack_alloc(mp);
				if (!ok_mp) {
					tcp_err_ack_prim(tcp, NULL, T_CONN_REQ,
					    TSYSERR, ENOMEM);
					return;
				}
				qreply(q, ok_mp);
				qreply(q, discon_mp); /* no flush! */
			} else {
				ASSERT(t_error != 0);
				tcp_err_ack_prim(tcp, mp, T_CONN_REQ, t_error,
				    sys_error);
			}
			return;
		}
		/*
		 * Success in setting options, the mp option buffer represented
		 * by OPT_length/offset has been potentially modified and
		 * contains results of option processing. We copy it in
		 * another mp to save it for potentially influencing returning
		 * it in T_CONN_CONN.
		 */
		if (tcr->OPT_length != 0) { /* there are resulting options */
			conn_opts_mp = copyb(mp);
			if (!conn_opts_mp) {
				tcp_err_ack_prim(tcp, mp, T_CONN_REQ,
				    TSYSERR, ENOMEM);
				return;
			}
			ASSERT(tcp->tcp_conn.tcp_opts_conn_req == NULL);
			tcp->tcp_conn.tcp_opts_conn_req = conn_opts_mp;
			/*
			 * Note:
			 * These resulting option negotiation can include any
			 * end-to-end negotiation options but there no such
			 * thing (yet?) in our TCP/IP.
			 */
		}
	}

	/* call the non-TPI version */
	error = tcp_do_connect(tcp->tcp_connp, sa, len, DB_CRED(mp),
	    DB_CPID(mp));
	if (error < 0) {
		mp = mi_tpi_err_ack_alloc(mp, -error, 0);
	} else if (error > 0) {
		mp = mi_tpi_err_ack_alloc(mp, TSYSERR, error);
	} else {
		mp = mi_tpi_ok_ack_alloc(mp);
	}

	/*
	 * Note: Code below is the "failure" case
	 */
	/* return error ack and blow away saved option results if any */
connect_failed:
	if (mp != NULL)
		putnext(tcp->tcp_rq, mp);
	else {
		tcp_err_ack_prim(tcp, NULL, T_CONN_REQ,
		    TSYSERR, ENOMEM);
	}
}

/*
 * Handle connect to IPv4 destinations, including connections for AF_INET6
 * sockets connecting to IPv4 mapped IPv6 destinations.
 */
static int
tcp_connect_ipv4(tcp_t *tcp, ipaddr_t *dstaddrp, in_port_t dstport,
    uint_t srcid, cred_t *cr, pid_t pid)
{
	tcph_t	*tcph;
	mblk_t	*mp;
	ipaddr_t dstaddr = *dstaddrp;
	int32_t	oldstate;
	uint16_t lport;
	int	error = 0;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	ASSERT(tcp->tcp_ipversion == IPV4_VERSION);

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
	if (srcid != 0 && tcp->tcp_ipha->ipha_src == INADDR_ANY) {
		ip_srcid_find_id(srcid, &tcp->tcp_ip_src_v6,
		    tcp->tcp_connp->conn_zoneid, tcps->tcps_netstack);
		IN6_V4MAPPED_TO_IPADDR(&tcp->tcp_ip_src_v6,
		    tcp->tcp_ipha->ipha_src);
	}

	/*
	 * Don't let an endpoint connect to itself.  Note that
	 * the test here does not catch the case where the
	 * source IP addr was left unspecified by the user. In
	 * this case, the source addr is set in tcp_adapt_ire()
	 * using the reply to the T_BIND message that we send
	 * down to IP here and the check is repeated in tcp_rput_other.
	 */
	if (dstaddr == tcp->tcp_ipha->ipha_src &&
	    dstport == tcp->tcp_lport) {
		error = -TBADADDR;
		goto failed;
	}

	tcp->tcp_ipha->ipha_dst = dstaddr;
	IN6_IPADDR_TO_V4MAPPED(dstaddr, &tcp->tcp_remote_v6);

	/*
	 * Massage a source route if any putting the first hop
	 * in iph_dst. Compute a starting value for the checksum which
	 * takes into account that the original iph_dst should be
	 * included in the checksum but that ip will include the
	 * first hop in the source route in the tcp checksum.
	 */
	tcp->tcp_sum = ip_massage_options(tcp->tcp_ipha, tcps->tcps_netstack);
	tcp->tcp_sum = (tcp->tcp_sum & 0xFFFF) + (tcp->tcp_sum >> 16);
	tcp->tcp_sum -= ((tcp->tcp_ipha->ipha_dst >> 16) +
	    (tcp->tcp_ipha->ipha_dst & 0xffff));
	if ((int)tcp->tcp_sum < 0)
		tcp->tcp_sum--;
	tcp->tcp_sum = (tcp->tcp_sum & 0xFFFF) + (tcp->tcp_sum >> 16);
	tcp->tcp_sum = ntohs((tcp->tcp_sum & 0xFFFF) +
	    (tcp->tcp_sum >> 16));
	tcph = tcp->tcp_tcph;
	*(uint16_t *)tcph->th_fport = dstport;
	tcp->tcp_fport = dstport;

	oldstate = tcp->tcp_state;
	/*
	 * At this point the remote destination address and remote port fields
	 * in the tcp-four-tuple have been filled in the tcp structure. Now we
	 * have to see which state tcp was in so we can take apropriate action.
	 */
	if (oldstate == TCPS_IDLE) {
		/*
		 * We support a quick connect capability here, allowing
		 * clients to transition directly from IDLE to SYN_SENT
		 * tcp_bindi will pick an unused port, insert the connection
		 * in the bind hash and transition to BOUND state.
		 */
		lport = tcp_update_next_port(tcps->tcps_next_port_to_try,
		    tcp, B_TRUE);
		lport = tcp_bindi(tcp, lport, &tcp->tcp_ip_src_v6, 0, B_TRUE,
		    B_FALSE, B_FALSE);
		if (lport == 0) {
			error = -TNOADDR;
			goto failed;
		}
	}
	tcp->tcp_state = TCPS_SYN_SENT;

	mp = allocb(sizeof (ire_t), BPRI_HI);
	if (mp == NULL) {
		tcp->tcp_state = oldstate;
		error = ENOMEM;
		goto failed;
	}

	mp->b_wptr += sizeof (ire_t);
	mp->b_datap->db_type = IRE_DB_REQ_TYPE;
	tcp->tcp_hard_binding = 1;

	/*
	 * We need to make sure that the conn_recv is set to a non-null
	 * value before we insert the conn_t into the classifier table.
	 * This is to avoid a race with an incoming packet which does
	 * an ipcl_classify().
	 */
	tcp->tcp_connp->conn_recv = tcp_input;

	if (tcp->tcp_family == AF_INET) {
		error = ip_proto_bind_connected_v4(tcp->tcp_connp, &mp,
		    IPPROTO_TCP, &tcp->tcp_ipha->ipha_src, tcp->tcp_lport,
		    tcp->tcp_remote, tcp->tcp_fport, B_TRUE, B_TRUE);
	} else {
		in6_addr_t v6src;
		if (tcp->tcp_ipversion == IPV4_VERSION) {
			IN6_IPADDR_TO_V4MAPPED(tcp->tcp_ipha->ipha_src, &v6src);
		} else {
			v6src = tcp->tcp_ip6h->ip6_src;
		}
		error = ip_proto_bind_connected_v6(tcp->tcp_connp, &mp,
		    IPPROTO_TCP, &v6src, tcp->tcp_lport, &tcp->tcp_remote_v6,
		    &tcp->tcp_sticky_ipp, tcp->tcp_fport, B_TRUE, B_TRUE);
	}
	BUMP_MIB(&tcps->tcps_mib, tcpActiveOpens);
	tcp->tcp_active_open = 1;


	return (tcp_post_ip_bind(tcp, mp, error, cr, pid));
failed:
	/* return error ack and blow away saved option results if any */
	if (tcp->tcp_conn.tcp_opts_conn_req != NULL)
		tcp_close_mpp(&tcp->tcp_conn.tcp_opts_conn_req);
	return (error);
}

/*
 * Handle connect to IPv6 destinations.
 */
static int
tcp_connect_ipv6(tcp_t *tcp, in6_addr_t *dstaddrp, in_port_t dstport,
    uint32_t flowinfo, uint_t srcid, uint32_t scope_id, cred_t *cr, pid_t pid)
{
	tcph_t	*tcph;
	mblk_t	*mp;
	ip6_rthdr_t *rth;
	int32_t  oldstate;
	uint16_t lport;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	int	error = 0;
	conn_t	*connp = tcp->tcp_connp;

	ASSERT(tcp->tcp_family == AF_INET6);

	/*
	 * If we're here, it means that the destination address is a native
	 * IPv6 address.  Return an error if tcp_ipversion is not IPv6.  A
	 * reason why it might not be IPv6 is if the socket was bound to an
	 * IPv4-mapped IPv6 address.
	 */
	if (tcp->tcp_ipversion != IPV6_VERSION) {
		return (-TBADADDR);
	}

	/*
	 * Interpret a zero destination to mean loopback.
	 * Update the T_CONN_REQ (sin/sin6) since it is used to
	 * generate the T_CONN_CON.
	 */
	if (IN6_IS_ADDR_UNSPECIFIED(dstaddrp)) {
		*dstaddrp = ipv6_loopback;
	}

	/* Handle __sin6_src_id if socket not bound to an IP address */
	if (srcid != 0 && IN6_IS_ADDR_UNSPECIFIED(&tcp->tcp_ip6h->ip6_src)) {
		ip_srcid_find_id(srcid, &tcp->tcp_ip6h->ip6_src,
		    connp->conn_zoneid, tcps->tcps_netstack);
		tcp->tcp_ip_src_v6 = tcp->tcp_ip6h->ip6_src;
	}

	/*
	 * Take care of the scope_id now and add ip6i_t
	 * if ip6i_t is not already allocated through TCP
	 * sticky options. At this point tcp_ip6h does not
	 * have dst info, thus use dstaddrp.
	 */
	if (scope_id != 0 &&
	    IN6_IS_ADDR_LINKSCOPE(dstaddrp)) {
		ip6_pkt_t *ipp = &tcp->tcp_sticky_ipp;
		ip6i_t  *ip6i;

		ipp->ipp_ifindex = scope_id;
		ip6i = (ip6i_t *)tcp->tcp_iphc;

		if ((ipp->ipp_fields & IPPF_HAS_IP6I) &&
		    ip6i != NULL && (ip6i->ip6i_nxt == IPPROTO_RAW)) {
			/* Already allocated */
			ip6i->ip6i_flags |= IP6I_IFINDEX;
			ip6i->ip6i_ifindex = ipp->ipp_ifindex;
			ipp->ipp_fields |= IPPF_SCOPE_ID;
		} else {
			int reterr;

			ipp->ipp_fields |= IPPF_SCOPE_ID;
			if (ipp->ipp_fields & IPPF_HAS_IP6I)
				ip2dbg(("tcp_connect_v6: SCOPE_ID set\n"));
			reterr = tcp_build_hdrs(tcp);
			if (reterr != 0)
				goto failed;
			ip1dbg(("tcp_connect_ipv6: tcp_bld_hdrs returned\n"));
		}
	}

	/*
	 * Don't let an endpoint connect to itself.  Note that
	 * the test here does not catch the case where the
	 * source IP addr was left unspecified by the user. In
	 * this case, the source addr is set in tcp_adapt_ire()
	 * using the reply to the T_BIND message that we send
	 * down to IP here and the check is repeated in tcp_rput_other.
	 */
	if (IN6_ARE_ADDR_EQUAL(dstaddrp, &tcp->tcp_ip6h->ip6_src) &&
	    (dstport == tcp->tcp_lport)) {
		error = -TBADADDR;
		goto failed;
	}

	tcp->tcp_ip6h->ip6_dst = *dstaddrp;
	tcp->tcp_remote_v6 = *dstaddrp;
	tcp->tcp_ip6h->ip6_vcf =
	    (IPV6_DEFAULT_VERS_AND_FLOW & IPV6_VERS_AND_FLOW_MASK) |
	    (flowinfo & ~IPV6_VERS_AND_FLOW_MASK);

	/*
	 * Massage a routing header (if present) putting the first hop
	 * in ip6_dst. Compute a starting value for the checksum which
	 * takes into account that the original ip6_dst should be
	 * included in the checksum but that ip will include the
	 * first hop in the source route in the tcp checksum.
	 */
	rth = ip_find_rthdr_v6(tcp->tcp_ip6h, (uint8_t *)tcp->tcp_tcph);
	if (rth != NULL) {
		tcp->tcp_sum = ip_massage_options_v6(tcp->tcp_ip6h, rth,
		    tcps->tcps_netstack);
		tcp->tcp_sum = ntohs((tcp->tcp_sum & 0xFFFF) +
		    (tcp->tcp_sum >> 16));
	} else {
		tcp->tcp_sum = 0;
	}

	tcph = tcp->tcp_tcph;
	*(uint16_t *)tcph->th_fport = dstport;
	tcp->tcp_fport = dstport;

	oldstate = tcp->tcp_state;
	/*
	 * At this point the remote destination address and remote port fields
	 * in the tcp-four-tuple have been filled in the tcp structure. Now we
	 * have to see which state tcp was in so we can take apropriate action.
	 */
	if (oldstate == TCPS_IDLE) {
		/*
		 * We support a quick connect capability here, allowing
		 * clients to transition directly from IDLE to SYN_SENT
		 * tcp_bindi will pick an unused port, insert the connection
		 * in the bind hash and transition to BOUND state.
		 */
		lport = tcp_update_next_port(tcps->tcps_next_port_to_try,
		    tcp, B_TRUE);
		lport = tcp_bindi(tcp, lport, &tcp->tcp_ip_src_v6, 0, B_TRUE,
		    B_FALSE, B_FALSE);
		if (lport == 0) {
			error = -TNOADDR;
			goto failed;
		}
	}
	tcp->tcp_state = TCPS_SYN_SENT;

	mp = allocb(sizeof (ire_t), BPRI_HI);
	if (mp != NULL) {
		in6_addr_t v6src;

		mp->b_wptr += sizeof (ire_t);
		mp->b_datap->db_type = IRE_DB_REQ_TYPE;

		tcp->tcp_hard_binding = 1;

		/*
		 * We need to make sure that the conn_recv is set to a non-null
		 * value before we insert the conn_t into the classifier table.
		 * This is to avoid a race with an incoming packet which does
		 * an ipcl_classify().
		 */
		tcp->tcp_connp->conn_recv = tcp_input;

		if (tcp->tcp_ipversion == IPV4_VERSION) {
			IN6_IPADDR_TO_V4MAPPED(tcp->tcp_ipha->ipha_src, &v6src);
		} else {
			v6src = tcp->tcp_ip6h->ip6_src;
		}
		error = ip_proto_bind_connected_v6(connp, &mp, IPPROTO_TCP,
		    &v6src, tcp->tcp_lport, &tcp->tcp_remote_v6,
		    &tcp->tcp_sticky_ipp, tcp->tcp_fport, B_TRUE, B_TRUE);
		BUMP_MIB(&tcps->tcps_mib, tcpActiveOpens);
		tcp->tcp_active_open = 1;

		return (tcp_post_ip_bind(tcp, mp, error, cr, pid));
	}
	/* Error case */
	tcp->tcp_state = oldstate;
	error = ENOMEM;

failed:
	/* return error ack and blow away saved option results if any */
	if (tcp->tcp_conn.tcp_opts_conn_req != NULL)
		tcp_close_mpp(&tcp->tcp_conn.tcp_opts_conn_req);
	return (error);
}

/*
 * We need a stream q for detached closing tcp connections
 * to use.  Our client hereby indicates that this q is the
 * one to use.
 */
static void
tcp_def_q_set(tcp_t *tcp, mblk_t *mp)
{
	struct iocblk *iocp = (struct iocblk *)mp->b_rptr;
	queue_t	*q = tcp->tcp_wq;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

#ifdef NS_DEBUG
	(void) printf("TCP_IOC_DEFAULT_Q for stack %d\n",
	    tcps->tcps_netstack->netstack_stackid);
#endif
	mp->b_datap->db_type = M_IOCACK;
	iocp->ioc_count = 0;
	mutex_enter(&tcps->tcps_g_q_lock);
	if (tcps->tcps_g_q != NULL) {
		mutex_exit(&tcps->tcps_g_q_lock);
		iocp->ioc_error = EALREADY;
	} else {
		int error = 0;
		conn_t *connp = tcp->tcp_connp;
		ip_stack_t *ipst = connp->conn_netstack->netstack_ip;

		tcps->tcps_g_q = tcp->tcp_rq;
		mutex_exit(&tcps->tcps_g_q_lock);
		iocp->ioc_error = 0;
		iocp->ioc_rval = 0;
		/*
		 * We are passing tcp_sticky_ipp as NULL
		 * as it is not useful for tcp_default queue
		 *
		 * Set conn_recv just in case.
		 */
		tcp->tcp_connp->conn_recv = tcp_conn_request;

		ASSERT(connp->conn_af_isv6);
		connp->conn_ulp = IPPROTO_TCP;

		if (ipst->ips_ipcl_proto_fanout_v6[IPPROTO_TCP].connf_head !=
		    NULL || connp->conn_mac_exempt) {
			error = -TBADADDR;
		} else {
			connp->conn_srcv6 = ipv6_all_zeros;
			ipcl_proto_insert_v6(connp, IPPROTO_TCP);
		}

		(void) tcp_post_ip_bind(tcp, NULL, error, NULL, 0);
	}
	qreply(q, mp);
}

static int
tcp_disconnect_common(tcp_t *tcp, t_scalar_t seqnum)
{
	tcp_t	*ltcp = NULL;
	conn_t	*connp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	/*
	 * Right now, upper modules pass down a T_DISCON_REQ to TCP,
	 * when the stream is in BOUND state. Do not send a reset,
	 * since the destination IP address is not valid, and it can
	 * be the initialized value of all zeros (broadcast address).
	 *
	 * XXX There won't be any pending bind request to IP.
	 */
	if (tcp->tcp_state <= TCPS_BOUND) {
		if (tcp->tcp_debug) {
			(void) strlog(TCP_MOD_ID, 0, 1, SL_ERROR|SL_TRACE,
			    "tcp_disconnect: bad state, %d", tcp->tcp_state);
		}
		return (TOUTSTATE);
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
		ltcp = NULL;
		/*
		 * If it used to be a listener, check to make sure no one else
		 * has taken the port before switching back to LISTEN state.
		 */
		if (tcp->tcp_ipversion == IPV4_VERSION) {
			connp = ipcl_lookup_listener_v4(tcp->tcp_lport,
			    tcp->tcp_ipha->ipha_src,
			    tcp->tcp_connp->conn_zoneid, ipst);
			if (connp != NULL)
				ltcp = connp->conn_tcp;
		} else {
			/* Allow tcp_bound_if listeners? */
			connp = ipcl_lookup_listener_v6(tcp->tcp_lport,
			    &tcp->tcp_ip6h->ip6_src, 0,
			    tcp->tcp_connp->conn_zoneid, ipst);
			if (connp != NULL)
				ltcp = connp->conn_tcp;
		}
		if (tcp->tcp_conn_req_max && ltcp == NULL) {
			tcp->tcp_state = TCPS_LISTEN;
		} else if (old_state > TCPS_BOUND) {
			tcp->tcp_conn_req_max = 0;
			tcp->tcp_state = TCPS_BOUND;
		}
		if (ltcp != NULL)
			CONN_DEC_REF(ltcp->tcp_connp);
		if (old_state == TCPS_SYN_SENT || old_state == TCPS_SYN_RCVD) {
			BUMP_MIB(&tcps->tcps_mib, tcpAttemptFails);
		} else if (old_state == TCPS_ESTABLISHED ||
		    old_state == TCPS_CLOSE_WAIT) {
			BUMP_MIB(&tcps->tcps_mib, tcpEstabResets);
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
 * that tcp_conn_request() marked with 'seqnum'.  Rejection consists
 * of sending the appropriate RST, not an ICMP error.
 */
static void
tcp_disconnect(tcp_t *tcp, mblk_t *mp)
{
	t_scalar_t seqnum;
	int	error;

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
			(void) putnextctl1(tcp->tcp_rq, M_FLUSH, FLUSHRW);
		}
		mp = mi_tpi_ok_ack_alloc(mp);
		if (mp)
			putnext(tcp->tcp_rq, mp);
	}
}

/*
 * Diagnostic routine used to return a string associated with the tcp state.
 * Note that if the caller does not supply a buffer, it will use an internal
 * static string.  This means that if multiple threads call this function at
 * the same time, output can be corrupted...  Note also that this function
 * does not check the size of the supplied buffer.  The caller has to make
 * sure that it is big enough.
 */
static char *
tcp_display(tcp_t *tcp, char *sup_buf, char format)
{
	char		buf1[30];
	static char	priv_buf[INET6_ADDRSTRLEN * 2 + 80];
	char		*buf;
	char		*cp;
	in6_addr_t	local, remote;
	char		local_addrbuf[INET6_ADDRSTRLEN];
	char		remote_addrbuf[INET6_ADDRSTRLEN];

	if (sup_buf != NULL)
		buf = sup_buf;
	else
		buf = priv_buf;

	if (tcp == NULL)
		return ("NULL_TCP");
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
		if (tcp->tcp_ipversion == IPV4_VERSION) {
			/*
			 * Note that we use the remote address in the tcp_b
			 * structure.  This means that it will print out
			 * the real destination address, not the next hop's
			 * address if source routing is used.
			 */
			IN6_IPADDR_TO_V4MAPPED(tcp->tcp_ip_src, &local);
			IN6_IPADDR_TO_V4MAPPED(tcp->tcp_remote, &remote);

		} else {
			local = tcp->tcp_ip_src_v6;
			remote = tcp->tcp_remote_v6;
		}
		(void) inet_ntop(AF_INET6, &local, local_addrbuf,
		    sizeof (local_addrbuf));
		(void) inet_ntop(AF_INET6, &remote, remote_addrbuf,
		    sizeof (remote_addrbuf));
		(void) mi_sprintf(buf, "[%s.%u, %s.%u] %s",
		    local_addrbuf, ntohs(tcp->tcp_lport), remote_addrbuf,
		    ntohs(tcp->tcp_fport), cp);
		break;
	case DISP_PORT_ONLY:
	default:
		(void) mi_sprintf(buf, "[%u, %u] %s",
		    ntohs(tcp->tcp_lport), ntohs(tcp->tcp_fport), cp);
		break;
	}

	return (buf);
}

/*
 * Called via squeue to get on to eager's perimeter. It sends a
 * TH_RST if eager is in the fanout table. The listener wants the
 * eager to disappear either by means of tcp_eager_blowoff() or
 * tcp_eager_cleanup() being called. tcp_eager_kill() can also be
 * called (via squeue) if the eager cannot be inserted in the
 * fanout table in tcp_conn_request().
 */
/* ARGSUSED */
void
tcp_eager_kill(void *arg, mblk_t *mp, void *arg2)
{
	conn_t	*econnp = (conn_t *)arg;
	tcp_t	*eager = econnp->conn_tcp;
	tcp_t	*listener = eager->tcp_listener;
	tcp_stack_t	*tcps = eager->tcp_tcps;

	/*
	 * We could be called because listener is closing. Since
	 * the eager is using listener's queue's, its not safe.
	 * Better use the default queue just to send the TH_RST
	 * out.
	 */
	ASSERT(tcps->tcps_g_q != NULL);
	eager->tcp_rq = tcps->tcps_g_q;
	eager->tcp_wq = WR(tcps->tcps_g_q);

	/*
	 * An eager's conn_fanout will be NULL if it's a duplicate
	 * for an existing 4-tuples in the conn fanout table.
	 * We don't want to send an RST out in such case.
	 */
	if (econnp->conn_fanout != NULL && eager->tcp_state > TCPS_LISTEN) {
		tcp_xmit_ctl("tcp_eager_kill, can't wait",
		    eager, eager->tcp_snxt, 0, TH_RST);
	}

	/* We are here because listener wants this eager gone */
	if (listener != NULL) {
		mutex_enter(&listener->tcp_eager_lock);
		tcp_eager_unlink(eager);
		if (eager->tcp_tconnind_started) {
			/*
			 * The eager has sent a conn_ind up to the
			 * listener but listener decides to close
			 * instead. We need to drop the extra ref
			 * placed on eager in tcp_rput_data() before
			 * sending the conn_ind to listener.
			 */
			CONN_DEC_REF(econnp);
		}
		mutex_exit(&listener->tcp_eager_lock);
		CONN_DEC_REF(listener->tcp_connp);
	}

	if (eager->tcp_state > TCPS_BOUND)
		tcp_close_detached(eager);
}

/*
 * Reset any eager connection hanging off this listener marked
 * with 'seqnum' and then reclaim it's resources.
 */
static boolean_t
tcp_eager_blowoff(tcp_t	*listener, t_scalar_t seqnum)
{
	tcp_t	*eager;
	mblk_t 	*mp;
	tcp_stack_t	*tcps = listener->tcp_tcps;

	TCP_STAT(tcps, tcp_eager_blowoff_calls);
	eager = listener;
	mutex_enter(&listener->tcp_eager_lock);
	do {
		eager = eager->tcp_eager_next_q;
		if (eager == NULL) {
			mutex_exit(&listener->tcp_eager_lock);
			return (B_FALSE);
		}
	} while (eager->tcp_conn_req_seqnum != seqnum);

	if (eager->tcp_closemp_used) {
		mutex_exit(&listener->tcp_eager_lock);
		return (B_TRUE);
	}
	eager->tcp_closemp_used = B_TRUE;
	TCP_DEBUG_GETPCSTACK(eager->tcmp_stk, 15);
	CONN_INC_REF(eager->tcp_connp);
	mutex_exit(&listener->tcp_eager_lock);
	mp = &eager->tcp_closemp;
	SQUEUE_ENTER_ONE(eager->tcp_connp->conn_sqp, mp, tcp_eager_kill,
	    eager->tcp_connp, SQ_FILL, SQTAG_TCP_EAGER_BLOWOFF);
	return (B_TRUE);
}

/*
 * Reset any eager connection hanging off this listener
 * and then reclaim it's resources.
 */
static void
tcp_eager_cleanup(tcp_t *listener, boolean_t q0_only)
{
	tcp_t	*eager;
	mblk_t	*mp;
	tcp_stack_t	*tcps = listener->tcp_tcps;

	ASSERT(MUTEX_HELD(&listener->tcp_eager_lock));

	if (!q0_only) {
		/* First cleanup q */
		TCP_STAT(tcps, tcp_eager_blowoff_q);
		eager = listener->tcp_eager_next_q;
		while (eager != NULL) {
			if (!eager->tcp_closemp_used) {
				eager->tcp_closemp_used = B_TRUE;
				TCP_DEBUG_GETPCSTACK(eager->tcmp_stk, 15);
				CONN_INC_REF(eager->tcp_connp);
				mp = &eager->tcp_closemp;
				SQUEUE_ENTER_ONE(eager->tcp_connp->conn_sqp, mp,
				    tcp_eager_kill, eager->tcp_connp,
				    SQ_FILL, SQTAG_TCP_EAGER_CLEANUP);
			}
			eager = eager->tcp_eager_next_q;
		}
	}
	/* Then cleanup q0 */
	TCP_STAT(tcps, tcp_eager_blowoff_q0);
	eager = listener->tcp_eager_next_q0;
	while (eager != listener) {
		if (!eager->tcp_closemp_used) {
			eager->tcp_closemp_used = B_TRUE;
			TCP_DEBUG_GETPCSTACK(eager->tcmp_stk, 15);
			CONN_INC_REF(eager->tcp_connp);
			mp = &eager->tcp_closemp;
			SQUEUE_ENTER_ONE(eager->tcp_connp->conn_sqp, mp,
			    tcp_eager_kill, eager->tcp_connp, SQ_FILL,
			    SQTAG_TCP_EAGER_CLEANUP_Q0);
		}
		eager = eager->tcp_eager_next_q0;
	}
}

/*
 * If we are an eager connection hanging off a listener that hasn't
 * formally accepted the connection yet, get off his list and blow off
 * any data that we have accumulated.
 */
static void
tcp_eager_unlink(tcp_t *tcp)
{
	tcp_t	*listener = tcp->tcp_listener;

	ASSERT(MUTEX_HELD(&listener->tcp_eager_lock));
	ASSERT(listener != NULL);
	if (tcp->tcp_eager_next_q0 != NULL) {
		ASSERT(tcp->tcp_eager_prev_q0 != NULL);

		/* Remove the eager tcp from q0 */
		tcp->tcp_eager_next_q0->tcp_eager_prev_q0 =
		    tcp->tcp_eager_prev_q0;
		tcp->tcp_eager_prev_q0->tcp_eager_next_q0 =
		    tcp->tcp_eager_next_q0;
		ASSERT(listener->tcp_conn_req_cnt_q0 > 0);
		listener->tcp_conn_req_cnt_q0--;

		tcp->tcp_eager_next_q0 = NULL;
		tcp->tcp_eager_prev_q0 = NULL;

		/*
		 * Take the eager out, if it is in the list of droppable
		 * eagers.
		 */
		MAKE_UNDROPPABLE(tcp);

		if (tcp->tcp_syn_rcvd_timeout != 0) {
			/* we have timed out before */
			ASSERT(listener->tcp_syn_rcvd_timeout > 0);
			listener->tcp_syn_rcvd_timeout--;
		}
	} else {
		tcp_t   **tcpp = &listener->tcp_eager_next_q;
		tcp_t	*prev = NULL;

		for (; tcpp[0]; tcpp = &tcpp[0]->tcp_eager_next_q) {
			if (tcpp[0] == tcp) {
				if (listener->tcp_eager_last_q == tcp) {
					/*
					 * If we are unlinking the last
					 * element on the list, adjust
					 * tail pointer. Set tail pointer
					 * to nil when list is empty.
					 */
					ASSERT(tcp->tcp_eager_next_q == NULL);
					if (listener->tcp_eager_last_q ==
					    listener->tcp_eager_next_q) {
						listener->tcp_eager_last_q =
						    NULL;
					} else {
						/*
						 * We won't get here if there
						 * is only one eager in the
						 * list.
						 */
						ASSERT(prev != NULL);
						listener->tcp_eager_last_q =
						    prev;
					}
				}
				tcpp[0] = tcp->tcp_eager_next_q;
				tcp->tcp_eager_next_q = NULL;
				tcp->tcp_eager_last_q = NULL;
				ASSERT(listener->tcp_conn_req_cnt_q > 0);
				listener->tcp_conn_req_cnt_q--;
				break;
			}
			prev = tcpp[0];
		}
	}
	tcp->tcp_listener = NULL;
}

/* Shorthand to generate and send TPI error acks to our client */
static void
tcp_err_ack(tcp_t *tcp, mblk_t *mp, int t_error, int sys_error)
{
	if ((mp = mi_tpi_err_ack_alloc(mp, t_error, sys_error)) != NULL)
		putnext(tcp->tcp_rq, mp);
}

/* Shorthand to generate and send TPI error acks to our client */
static void
tcp_err_ack_prim(tcp_t *tcp, mblk_t *mp, int primitive,
    int t_error, int sys_error)
{
	struct T_error_ack	*teackp;

	if ((mp = tpi_ack_alloc(mp, sizeof (struct T_error_ack),
	    M_PCPROTO, T_ERROR_ACK)) != NULL) {
		teackp = (struct T_error_ack *)mp->b_rptr;
		teackp->ERROR_prim = primitive;
		teackp->TLI_error = t_error;
		teackp->UNIX_error = sys_error;
		putnext(tcp->tcp_rq, mp);
	}
}

/*
 * Note: No locks are held when inspecting tcp_g_*epriv_ports
 * but instead the code relies on:
 * - the fact that the address of the array and its size never changes
 * - the atomic assignment of the elements of the array
 */
/* ARGSUSED */
static int
tcp_extra_priv_ports_get(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *cr)
{
	int i;
	tcp_stack_t	*tcps = Q_TO_TCP(q)->tcp_tcps;

	for (i = 0; i < tcps->tcps_g_num_epriv_ports; i++) {
		if (tcps->tcps_g_epriv_ports[i] != 0)
			(void) mi_mpprintf(mp, "%d ",
			    tcps->tcps_g_epriv_ports[i]);
	}
	return (0);
}

/*
 * Hold a lock while changing tcp_g_epriv_ports to prevent multiple
 * threads from changing it at the same time.
 */
/* ARGSUSED */
static int
tcp_extra_priv_ports_add(queue_t *q, mblk_t *mp, char *value, caddr_t cp,
    cred_t *cr)
{
	long	new_value;
	int	i;
	tcp_stack_t	*tcps = Q_TO_TCP(q)->tcp_tcps;

	/*
	 * Fail the request if the new value does not lie within the
	 * port number limits.
	 */
	if (ddi_strtol(value, NULL, 10, &new_value) != 0 ||
	    new_value <= 0 || new_value >= 65536) {
		return (EINVAL);
	}

	mutex_enter(&tcps->tcps_epriv_port_lock);
	/* Check if the value is already in the list */
	for (i = 0; i < tcps->tcps_g_num_epriv_ports; i++) {
		if (new_value == tcps->tcps_g_epriv_ports[i]) {
			mutex_exit(&tcps->tcps_epriv_port_lock);
			return (EEXIST);
		}
	}
	/* Find an empty slot */
	for (i = 0; i < tcps->tcps_g_num_epriv_ports; i++) {
		if (tcps->tcps_g_epriv_ports[i] == 0)
			break;
	}
	if (i == tcps->tcps_g_num_epriv_ports) {
		mutex_exit(&tcps->tcps_epriv_port_lock);
		return (EOVERFLOW);
	}
	/* Set the new value */
	tcps->tcps_g_epriv_ports[i] = (uint16_t)new_value;
	mutex_exit(&tcps->tcps_epriv_port_lock);
	return (0);
}

/*
 * Hold a lock while changing tcp_g_epriv_ports to prevent multiple
 * threads from changing it at the same time.
 */
/* ARGSUSED */
static int
tcp_extra_priv_ports_del(queue_t *q, mblk_t *mp, char *value, caddr_t cp,
    cred_t *cr)
{
	long	new_value;
	int	i;
	tcp_stack_t	*tcps = Q_TO_TCP(q)->tcp_tcps;

	/*
	 * Fail the request if the new value does not lie within the
	 * port number limits.
	 */
	if (ddi_strtol(value, NULL, 10, &new_value) != 0 || new_value <= 0 ||
	    new_value >= 65536) {
		return (EINVAL);
	}

	mutex_enter(&tcps->tcps_epriv_port_lock);
	/* Check that the value is already in the list */
	for (i = 0; i < tcps->tcps_g_num_epriv_ports; i++) {
		if (tcps->tcps_g_epriv_ports[i] == new_value)
			break;
	}
	if (i == tcps->tcps_g_num_epriv_ports) {
		mutex_exit(&tcps->tcps_epriv_port_lock);
		return (ESRCH);
	}
	/* Clear the value */
	tcps->tcps_g_epriv_ports[i] = 0;
	mutex_exit(&tcps->tcps_epriv_port_lock);
	return (0);
}

/* Return the TPI/TLI equivalent of our current tcp_state */
static int
tcp_tpistate(tcp_t *tcp)
{
	switch (tcp->tcp_state) {
	case TCPS_IDLE:
		return (TS_UNBND);
	case TCPS_LISTEN:
		/*
		 * Return whether there are outstanding T_CONN_IND waiting
		 * for the matching T_CONN_RES. Therefore don't count q0.
		 */
		if (tcp->tcp_conn_req_cnt_q > 0)
			return (TS_WRES_CIND);
		else
			return (TS_IDLE);
	case TCPS_BOUND:
		return (TS_IDLE);
	case TCPS_SYN_SENT:
		return (TS_WCON_CREQ);
	case TCPS_SYN_RCVD:
		/*
		 * Note: assumption: this has to the active open SYN_RCVD.
		 * The passive instance is detached in SYN_RCVD stage of
		 * incoming connection processing so we cannot get request
		 * for T_info_ack on it.
		 */
		return (TS_WACK_CRES);
	case TCPS_ESTABLISHED:
		return (TS_DATA_XFER);
	case TCPS_CLOSE_WAIT:
		return (TS_WREQ_ORDREL);
	case TCPS_FIN_WAIT_1:
		return (TS_WIND_ORDREL);
	case TCPS_FIN_WAIT_2:
		return (TS_WIND_ORDREL);

	case TCPS_CLOSING:
	case TCPS_LAST_ACK:
	case TCPS_TIME_WAIT:
	case TCPS_CLOSED:
		/*
		 * Following TS_WACK_DREQ7 is a rendition of "not
		 * yet TS_IDLE" TPI state. There is no best match to any
		 * TPI state for TCPS_{CLOSING, LAST_ACK, TIME_WAIT} but we
		 * choose a value chosen that will map to TLI/XTI level
		 * state of TSTATECHNG (state is process of changing) which
		 * captures what this dummy state represents.
		 */
		return (TS_WACK_DREQ7);
	default:
		cmn_err(CE_WARN, "tcp_tpistate: strange state (%d) %s",
		    tcp->tcp_state, tcp_display(tcp, NULL,
		    DISP_PORT_ONLY));
		return (TS_UNBND);
	}
}

static void
tcp_copy_info(struct T_info_ack *tia, tcp_t *tcp)
{
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	if (tcp->tcp_family == AF_INET6)
		*tia = tcp_g_t_info_ack_v6;
	else
		*tia = tcp_g_t_info_ack;
	tia->CURRENT_state = tcp_tpistate(tcp);
	tia->OPT_size = tcp_max_optsize;
	if (tcp->tcp_mss == 0) {
		/* Not yet set - tcp_open does not set mss */
		if (tcp->tcp_ipversion == IPV4_VERSION)
			tia->TIDU_size = tcps->tcps_mss_def_ipv4;
		else
			tia->TIDU_size = tcps->tcps_mss_def_ipv6;
	} else {
		tia->TIDU_size = tcp->tcp_mss;
	}
	/* TODO: Default ETSDU is 1.  Is that correct for tcp? */
}

static void
tcp_do_capability_ack(tcp_t *tcp, struct T_capability_ack *tcap,
    t_uscalar_t cap_bits1)
{
	tcap->CAP_bits1 = 0;

	if (cap_bits1 & TC1_INFO) {
		tcp_copy_info(&tcap->INFO_ack, tcp);
		tcap->CAP_bits1 |= TC1_INFO;
	}

	if (cap_bits1 & TC1_ACCEPTOR_ID) {
		tcap->ACCEPTOR_id = tcp->tcp_acceptor_id;
		tcap->CAP_bits1 |= TC1_ACCEPTOR_ID;
	}

}

/*
 * This routine responds to T_CAPABILITY_REQ messages.  It is called by
 * tcp_wput.  Much of the T_CAPABILITY_ACK information is copied from
 * tcp_g_t_info_ack.  The current state of the stream is copied from
 * tcp_state.
 */
static void
tcp_capability_req(tcp_t *tcp, mblk_t *mp)
{
	t_uscalar_t		cap_bits1;
	struct T_capability_ack	*tcap;

	if (MBLKL(mp) < sizeof (struct T_capability_req)) {
		freemsg(mp);
		return;
	}

	cap_bits1 = ((struct T_capability_req *)mp->b_rptr)->CAP_bits1;

	mp = tpi_ack_alloc(mp, sizeof (struct T_capability_ack),
	    mp->b_datap->db_type, T_CAPABILITY_ACK);
	if (mp == NULL)
		return;

	tcap = (struct T_capability_ack *)mp->b_rptr;
	tcp_do_capability_ack(tcp, tcap, cap_bits1);

	putnext(tcp->tcp_rq, mp);
}

/*
 * This routine responds to T_INFO_REQ messages.  It is called by tcp_wput.
 * Most of the T_INFO_ACK information is copied from tcp_g_t_info_ack.
 * The current state of the stream is copied from tcp_state.
 */
static void
tcp_info_req(tcp_t *tcp, mblk_t *mp)
{
	mp = tpi_ack_alloc(mp, sizeof (struct T_info_ack), M_PCPROTO,
	    T_INFO_ACK);
	if (!mp) {
		tcp_err_ack(tcp, mp, TSYSERR, ENOMEM);
		return;
	}
	tcp_copy_info((struct T_info_ack *)mp->b_rptr, tcp);
	putnext(tcp->tcp_rq, mp);
}

/* Respond to the TPI addr request */
static void
tcp_addr_req(tcp_t *tcp, mblk_t *mp)
{
	sin_t	*sin;
	mblk_t	*ackmp;
	struct T_addr_ack *taa;

	/* Make it large enough for worst case */
	ackmp = reallocb(mp, sizeof (struct T_addr_ack) +
	    2 * sizeof (sin6_t), 1);
	if (ackmp == NULL) {
		tcp_err_ack(tcp, mp, TSYSERR, ENOMEM);
		return;
	}

	if (tcp->tcp_ipversion == IPV6_VERSION) {
		tcp_addr_req_ipv6(tcp, ackmp);
		return;
	}
	taa = (struct T_addr_ack *)ackmp->b_rptr;

	bzero(taa, sizeof (struct T_addr_ack));
	ackmp->b_wptr = (uchar_t *)&taa[1];

	taa->PRIM_type = T_ADDR_ACK;
	ackmp->b_datap->db_type = M_PCPROTO;

	/*
	 * Note: Following code assumes 32 bit alignment of basic
	 * data structures like sin_t and struct T_addr_ack.
	 */
	if (tcp->tcp_state >= TCPS_BOUND) {
		/*
		 * Fill in local address
		 */
		taa->LOCADDR_length = sizeof (sin_t);
		taa->LOCADDR_offset = sizeof (*taa);

		sin = (sin_t *)&taa[1];

		/* Fill zeroes and then intialize non-zero fields */
		*sin = sin_null;

		sin->sin_family = AF_INET;

		sin->sin_addr.s_addr = tcp->tcp_ipha->ipha_src;
		sin->sin_port = *(uint16_t *)tcp->tcp_tcph->th_lport;

		ackmp->b_wptr = (uchar_t *)&sin[1];

		if (tcp->tcp_state >= TCPS_SYN_RCVD) {
			/*
			 * Fill in Remote address
			 */
			taa->REMADDR_length = sizeof (sin_t);
			taa->REMADDR_offset = ROUNDUP32(taa->LOCADDR_offset +
			    taa->LOCADDR_length);

			sin = (sin_t *)(ackmp->b_rptr + taa->REMADDR_offset);
			*sin = sin_null;
			sin->sin_family = AF_INET;
			sin->sin_addr.s_addr = tcp->tcp_remote;
			sin->sin_port = tcp->tcp_fport;

			ackmp->b_wptr = (uchar_t *)&sin[1];
		}
	}
	putnext(tcp->tcp_rq, ackmp);
}

/* Assumes that tcp_addr_req gets enough space and alignment */
static void
tcp_addr_req_ipv6(tcp_t *tcp, mblk_t *ackmp)
{
	sin6_t	*sin6;
	struct T_addr_ack *taa;

	ASSERT(tcp->tcp_ipversion == IPV6_VERSION);
	ASSERT(OK_32PTR(ackmp->b_rptr));
	ASSERT(ackmp->b_wptr - ackmp->b_rptr >= sizeof (struct T_addr_ack) +
	    2 * sizeof (sin6_t));

	taa = (struct T_addr_ack *)ackmp->b_rptr;

	bzero(taa, sizeof (struct T_addr_ack));
	ackmp->b_wptr = (uchar_t *)&taa[1];

	taa->PRIM_type = T_ADDR_ACK;
	ackmp->b_datap->db_type = M_PCPROTO;

	/*
	 * Note: Following code assumes 32 bit alignment of basic
	 * data structures like sin6_t and struct T_addr_ack.
	 */
	if (tcp->tcp_state >= TCPS_BOUND) {
		/*
		 * Fill in local address
		 */
		taa->LOCADDR_length = sizeof (sin6_t);
		taa->LOCADDR_offset = sizeof (*taa);

		sin6 = (sin6_t *)&taa[1];
		*sin6 = sin6_null;

		sin6->sin6_family = AF_INET6;
		sin6->sin6_addr = tcp->tcp_ip6h->ip6_src;
		sin6->sin6_port = tcp->tcp_lport;

		ackmp->b_wptr = (uchar_t *)&sin6[1];

		if (tcp->tcp_state >= TCPS_SYN_RCVD) {
			/*
			 * Fill in Remote address
			 */
			taa->REMADDR_length = sizeof (sin6_t);
			taa->REMADDR_offset = ROUNDUP32(taa->LOCADDR_offset +
			    taa->LOCADDR_length);

			sin6 = (sin6_t *)(ackmp->b_rptr + taa->REMADDR_offset);
			*sin6 = sin6_null;
			sin6->sin6_family = AF_INET6;
			sin6->sin6_flowinfo =
			    tcp->tcp_ip6h->ip6_vcf &
			    ~IPV6_VERS_AND_FLOW_MASK;
			sin6->sin6_addr = tcp->tcp_remote_v6;
			sin6->sin6_port = tcp->tcp_fport;

			ackmp->b_wptr = (uchar_t *)&sin6[1];
		}
	}
	putnext(tcp->tcp_rq, ackmp);
}

/*
 * Handle reinitialization of a tcp structure.
 * Maintain "binding state" resetting the state to BOUND, LISTEN, or IDLE.
 */
static void
tcp_reinit(tcp_t *tcp)
{
	mblk_t	*mp;
	int 	err;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	TCP_STAT(tcps, tcp_reinit_calls);

	/* tcp_reinit should never be called for detached tcp_t's */
	ASSERT(tcp->tcp_listener == NULL);
	ASSERT((tcp->tcp_family == AF_INET &&
	    tcp->tcp_ipversion == IPV4_VERSION) ||
	    (tcp->tcp_family == AF_INET6 &&
	    (tcp->tcp_ipversion == IPV4_VERSION ||
	    tcp->tcp_ipversion == IPV6_VERSION)));

	/* Cancel outstanding timers */
	tcp_timers_stop(tcp);

	/*
	 * Reset everything in the state vector, after updating global
	 * MIB data from instance counters.
	 */
	UPDATE_MIB(&tcps->tcps_mib, tcpHCInSegs, tcp->tcp_ibsegs);
	tcp->tcp_ibsegs = 0;
	UPDATE_MIB(&tcps->tcps_mib, tcpHCOutSegs, tcp->tcp_obsegs);
	tcp->tcp_obsegs = 0;

	tcp_close_mpp(&tcp->tcp_xmit_head);
	if (tcp->tcp_snd_zcopy_aware)
		tcp_zcopy_notify(tcp);
	tcp->tcp_xmit_last = tcp->tcp_xmit_tail = NULL;
	tcp->tcp_unsent = tcp->tcp_xmit_tail_unsent = 0;
	mutex_enter(&tcp->tcp_non_sq_lock);
	if (tcp->tcp_flow_stopped &&
	    TCP_UNSENT_BYTES(tcp) <= tcp->tcp_xmit_lowater) {
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

	CL_INET_DISCONNECT(tcp->tcp_connp, tcp);

	/*
	 * The connection can't be on the tcp_time_wait_head list
	 * since it is not detached.
	 */
	ASSERT(tcp->tcp_time_wait_next == NULL);
	ASSERT(tcp->tcp_time_wait_prev == NULL);
	ASSERT(tcp->tcp_time_wait_expire == 0);

	if (tcp->tcp_kssl_pending) {
		tcp->tcp_kssl_pending = B_FALSE;

		/* Don't reset if the initialized by bind. */
		if (tcp->tcp_kssl_ent != NULL) {
			kssl_release_ent(tcp->tcp_kssl_ent, NULL,
			    KSSL_NO_PROXY);
		}
	}
	if (tcp->tcp_kssl_ctx != NULL) {
		kssl_release_ctx(tcp->tcp_kssl_ctx);
		tcp->tcp_kssl_ctx = NULL;
	}

	/*
	 * Reset/preserve other values
	 */
	tcp_reinit_values(tcp);
	ipcl_hash_remove(tcp->tcp_connp);
	conn_delete_ire(tcp->tcp_connp, NULL);
	tcp_ipsec_cleanup(tcp);

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
		tcp->tcp_connp->conn_recv = tcp_conn_request;
		if (tcp->tcp_family == AF_INET6) {
			ASSERT(tcp->tcp_connp->conn_af_isv6);
			(void) ipcl_bind_insert_v6(tcp->tcp_connp, IPPROTO_TCP,
			    &tcp->tcp_ip6h->ip6_src, tcp->tcp_lport);
		} else {
			ASSERT(!tcp->tcp_connp->conn_af_isv6);
			(void) ipcl_bind_insert(tcp->tcp_connp, IPPROTO_TCP,
			    tcp->tcp_ipha->ipha_src, tcp->tcp_lport);
		}
	} else {
		tcp->tcp_state = TCPS_BOUND;
	}

	/*
	 * Initialize to default values
	 * Can't fail since enough header template space already allocated
	 * at open().
	 */
	err = tcp_init_values(tcp);
	ASSERT(err == 0);
	/* Restore state in tcp_tcph */
	bcopy(&tcp->tcp_lport, tcp->tcp_tcph->th_lport, TCP_PORT_LEN);
	if (tcp->tcp_ipversion == IPV4_VERSION)
		tcp->tcp_ipha->ipha_src = tcp->tcp_bound_source;
	else
		tcp->tcp_ip6h->ip6_src = tcp->tcp_bound_source_v6;
	/*
	 * Copy of the src addr. in tcp_t is needed in tcp_t
	 * since the lookup funcs can only lookup on tcp_t
	 */
	tcp->tcp_ip_src_v6 = tcp->tcp_bound_source_v6;

	ASSERT(tcp->tcp_ptpbhn != NULL);
	if (!IPCL_IS_NONSTR(tcp->tcp_connp))
		tcp->tcp_rq->q_hiwat = tcps->tcps_recv_hiwat;
	tcp->tcp_recv_hiwater = tcps->tcps_recv_hiwat;
	tcp->tcp_recv_lowater = tcp_rinfo.mi_lowat;
	tcp->tcp_rwnd = tcps->tcps_recv_hiwat;
	tcp->tcp_mss = tcp->tcp_ipversion != IPV4_VERSION ?
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
	PRESERVE(tcp->tcp_rq);
	PRESERVE(tcp->tcp_wq);

	ASSERT(tcp->tcp_xmit_head == NULL);
	ASSERT(tcp->tcp_xmit_last == NULL);
	ASSERT(tcp->tcp_unsent == 0);
	ASSERT(tcp->tcp_xmit_tail == NULL);
	ASSERT(tcp->tcp_xmit_tail_unsent == 0);

	tcp->tcp_snxt = 0;			/* Displayed in mib */
	tcp->tcp_suna = 0;			/* Displayed in mib */
	tcp->tcp_swnd = 0;
	DONTCARE(tcp->tcp_cwnd);		/* Init in tcp_mss_set */

	ASSERT(tcp->tcp_ibsegs == 0);
	ASSERT(tcp->tcp_obsegs == 0);

	if (tcp->tcp_iphc != NULL) {
		ASSERT(tcp->tcp_iphc_len >= TCP_MAX_COMBINED_HEADER_LENGTH);
		bzero(tcp->tcp_iphc, tcp->tcp_iphc_len);
	}

	DONTCARE(tcp->tcp_naglim);		/* Init in tcp_init_values */
	DONTCARE(tcp->tcp_hdr_len);		/* Init in tcp_init_values */
	DONTCARE(tcp->tcp_ipha);
	DONTCARE(tcp->tcp_ip6h);
	DONTCARE(tcp->tcp_ip_hdr_len);
	DONTCARE(tcp->tcp_tcph);
	DONTCARE(tcp->tcp_tcp_hdr_len);		/* Init in tcp_init_values */
	tcp->tcp_valid_bits = 0;

	DONTCARE(tcp->tcp_xmit_hiwater);	/* Init in tcp_init_values */
	DONTCARE(tcp->tcp_timer_backoff);	/* Init in tcp_init_values */
	DONTCARE(tcp->tcp_last_recv_time);	/* Init in tcp_init_values */
	tcp->tcp_last_rcv_lbolt = 0;

	tcp->tcp_init_cwnd = 0;

	tcp->tcp_urp_last_valid = 0;
	tcp->tcp_hard_binding = 0;
	tcp->tcp_hard_bound = 0;
	PRESERVE(tcp->tcp_cred);
	PRESERVE(tcp->tcp_cpid);
	PRESERVE(tcp->tcp_open_time);
	PRESERVE(tcp->tcp_exclbind);

	tcp->tcp_fin_acked = 0;
	tcp->tcp_fin_rcvd = 0;
	tcp->tcp_fin_sent = 0;
	tcp->tcp_ordrel_done = 0;

	tcp->tcp_debug = 0;
	tcp->tcp_dontroute = 0;
	tcp->tcp_broadcast = 0;

	tcp->tcp_useloopback = 0;
	tcp->tcp_reuseaddr = 0;
	tcp->tcp_oobinline = 0;
	tcp->tcp_dgram_errind = 0;

	tcp->tcp_detached = 0;
	tcp->tcp_bind_pending = 0;
	tcp->tcp_unbind_pending = 0;

	tcp->tcp_snd_ws_ok = B_FALSE;
	tcp->tcp_snd_ts_ok = B_FALSE;
	tcp->tcp_linger = 0;
	tcp->tcp_ka_enabled = 0;
	tcp->tcp_zero_win_probe = 0;

	tcp->tcp_loopback = 0;
	tcp->tcp_refuse = 0;
	tcp->tcp_localnet = 0;
	tcp->tcp_syn_defense = 0;
	tcp->tcp_set_timer = 0;

	tcp->tcp_active_open = 0;
	tcp->tcp_rexmit = B_FALSE;
	tcp->tcp_xmit_zc_clean = B_FALSE;

	tcp->tcp_snd_sack_ok = B_FALSE;
	PRESERVE(tcp->tcp_recvdstaddr);
	tcp->tcp_hwcksum = B_FALSE;

	tcp->tcp_ire_ill_check_done = B_FALSE;
	DONTCARE(tcp->tcp_maxpsz);		/* Init in tcp_init_values */

	tcp->tcp_mdt = B_FALSE;
	tcp->tcp_mdt_hdr_head = 0;
	tcp->tcp_mdt_hdr_tail = 0;

	tcp->tcp_conn_def_q0 = 0;
	tcp->tcp_ip_forward_progress = B_FALSE;
	tcp->tcp_anon_priv_bind = 0;
	tcp->tcp_ecn_ok = B_FALSE;

	tcp->tcp_cwr = B_FALSE;
	tcp->tcp_ecn_echo_on = B_FALSE;

	if (tcp->tcp_sack_info != NULL) {
		if (tcp->tcp_notsack_list != NULL) {
			TCP_NOTSACK_REMOVE_ALL(tcp->tcp_notsack_list);
		}
		kmem_cache_free(tcp_sack_info_cache, tcp->tcp_sack_info);
		tcp->tcp_sack_info = NULL;
	}

	tcp->tcp_rcv_ws = 0;
	tcp->tcp_snd_ws = 0;
	tcp->tcp_ts_recent = 0;
	tcp->tcp_rnxt = 0;			/* Displayed in mib */
	DONTCARE(tcp->tcp_rwnd);		/* Set in tcp_reinit() */
	tcp->tcp_if_mtu = 0;

	ASSERT(tcp->tcp_reass_head == NULL);
	ASSERT(tcp->tcp_reass_tail == NULL);

	tcp->tcp_cwnd_cnt = 0;

	ASSERT(tcp->tcp_rcv_list == NULL);
	ASSERT(tcp->tcp_rcv_last_head == NULL);
	ASSERT(tcp->tcp_rcv_last_tail == NULL);
	ASSERT(tcp->tcp_rcv_cnt == 0);

	DONTCARE(tcp->tcp_cwnd_ssthresh);	/* Init in tcp_adapt_ire */
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

	DONTCARE(tcp->tcp_xmit_lowater);	/* Init in tcp_init_values */

	DONTCARE(tcp->tcp_irs);			/* tcp_valid_bits cleared */
	DONTCARE(tcp->tcp_iss);			/* tcp_valid_bits cleared */
	DONTCARE(tcp->tcp_fss);			/* tcp_valid_bits cleared */
	DONTCARE(tcp->tcp_urg);			/* tcp_valid_bits cleared */

	ASSERT(tcp->tcp_conn_req_cnt_q == 0);
	ASSERT(tcp->tcp_conn_req_cnt_q0 == 0);
	PRESERVE(tcp->tcp_conn_req_max);
	PRESERVE(tcp->tcp_conn_req_seqnum);

	DONTCARE(tcp->tcp_ip_hdr_len);		/* Init in tcp_init_values */
	DONTCARE(tcp->tcp_first_timer_threshold); /* Init in tcp_init_values */
	DONTCARE(tcp->tcp_second_timer_threshold); /* Init in tcp_init_values */
	DONTCARE(tcp->tcp_first_ctimer_threshold); /* Init in tcp_init_values */
	DONTCARE(tcp->tcp_second_ctimer_threshold); /* in tcp_init_values */

	tcp->tcp_lingertime = 0;

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

	tcp->tcp_client_errno = 0;

	DONTCARE(tcp->tcp_sum);			/* Init in tcp_init_values */

	tcp->tcp_remote_v6 = ipv6_all_zeros;	/* Displayed in MIB */

	PRESERVE(tcp->tcp_bound_source_v6);
	tcp->tcp_last_sent_len = 0;
	tcp->tcp_dupack_cnt = 0;

	tcp->tcp_fport = 0;			/* Displayed in MIB */
	PRESERVE(tcp->tcp_lport);

	PRESERVE(tcp->tcp_acceptor_lockp);

	ASSERT(tcp->tcp_ordrel_mp == NULL);
	PRESERVE(tcp->tcp_acceptor_id);
	DONTCARE(tcp->tcp_ipsec_overhead);

	PRESERVE(tcp->tcp_family);
	if (tcp->tcp_family == AF_INET6) {
		tcp->tcp_ipversion = IPV6_VERSION;
		tcp->tcp_mss = tcps->tcps_mss_def_ipv6;
	} else {
		tcp->tcp_ipversion = IPV4_VERSION;
		tcp->tcp_mss = tcps->tcps_mss_def_ipv4;
	}

	tcp->tcp_bound_if = 0;
	tcp->tcp_ipv6_recvancillary = 0;
	tcp->tcp_recvifindex = 0;
	tcp->tcp_recvhops = 0;
	tcp->tcp_closed = 0;
	tcp->tcp_cleandeathtag = 0;
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
	if (tcp->tcp_rtdstopts != NULL) {
		mi_free(tcp->tcp_rtdstopts);
		tcp->tcp_rtdstopts = NULL;
		tcp->tcp_rtdstoptslen = 0;
	}
	ASSERT(tcp->tcp_rtdstoptslen == 0);
	if (tcp->tcp_rthdr != NULL) {
		mi_free(tcp->tcp_rthdr);
		tcp->tcp_rthdr = NULL;
		tcp->tcp_rthdrlen = 0;
	}
	ASSERT(tcp->tcp_rthdrlen == 0);
	PRESERVE(tcp->tcp_drop_opt_ack_cnt);

	/* Reset fusion-related fields */
	tcp->tcp_fused = B_FALSE;
	tcp->tcp_unfusable = B_FALSE;
	tcp->tcp_fused_sigurg = B_FALSE;
	tcp->tcp_direct_sockfs = B_FALSE;
	tcp->tcp_fuse_syncstr_stopped = B_FALSE;
	tcp->tcp_fuse_syncstr_plugged = B_FALSE;
	tcp->tcp_loopback_peer = NULL;
	tcp->tcp_fuse_rcv_hiwater = 0;
	tcp->tcp_fuse_rcv_unread_hiwater = 0;
	tcp->tcp_fuse_rcv_unread_cnt = 0;

	tcp->tcp_lso = B_FALSE;

	tcp->tcp_in_ack_unsent = 0;
	tcp->tcp_cork = B_FALSE;
	tcp->tcp_tconnind_started = B_FALSE;

	PRESERVE(tcp->tcp_squeue_bytes);

	ASSERT(tcp->tcp_kssl_ctx == NULL);
	ASSERT(!tcp->tcp_kssl_pending);
	PRESERVE(tcp->tcp_kssl_ent);

	/* Sodirect */
	tcp->tcp_sodirect = NULL;

	tcp->tcp_closemp_used = B_FALSE;

	PRESERVE(tcp->tcp_rsrv_mp);
	PRESERVE(tcp->tcp_rsrv_mp_lock);

#ifdef DEBUG
	DONTCARE(tcp->tcmp_stk[0]);
#endif

	PRESERVE(tcp->tcp_connid);


#undef	DONTCARE
#undef	PRESERVE
}

/*
 * Allocate necessary resources and initialize state vector.
 * Guaranteed not to fail so that when an error is returned,
 * the caller doesn't need to do any additional cleanup.
 */
int
tcp_init(tcp_t *tcp, queue_t *q)
{
	int	err;

	tcp->tcp_rq = q;
	tcp->tcp_wq = WR(q);
	tcp->tcp_state = TCPS_IDLE;
	if ((err = tcp_init_values(tcp)) != 0)
		tcp_timers_stop(tcp);
	return (err);
}

static int
tcp_init_values(tcp_t *tcp)
{
	int	err;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	ASSERT((tcp->tcp_family == AF_INET &&
	    tcp->tcp_ipversion == IPV4_VERSION) ||
	    (tcp->tcp_family == AF_INET6 &&
	    (tcp->tcp_ipversion == IPV4_VERSION ||
	    tcp->tcp_ipversion == IPV6_VERSION)));

	/*
	 * Initialize tcp_rtt_sa and tcp_rtt_sd so that the calculated RTO
	 * will be close to tcp_rexmit_interval_initial.  By doing this, we
	 * allow the algorithm to adjust slowly to large fluctuations of RTT
	 * during first few transmissions of a connection as seen in slow
	 * links.
	 */
	tcp->tcp_rtt_sa = tcps->tcps_rexmit_interval_initial << 2;
	tcp->tcp_rtt_sd = tcps->tcps_rexmit_interval_initial >> 1;
	tcp->tcp_rto = (tcp->tcp_rtt_sa >> 3) + tcp->tcp_rtt_sd +
	    tcps->tcps_rexmit_interval_extra + (tcp->tcp_rtt_sa >> 5) +
	    tcps->tcps_conn_grace_period;
	if (tcp->tcp_rto < tcps->tcps_rexmit_interval_min)
		tcp->tcp_rto = tcps->tcps_rexmit_interval_min;
	tcp->tcp_timer_backoff = 0;
	tcp->tcp_ms_we_have_waited = 0;
	tcp->tcp_last_recv_time = lbolt;
	tcp->tcp_cwnd_max = tcps->tcps_cwnd_max_;
	tcp->tcp_cwnd_ssthresh = TCP_MAX_LARGEWIN;
	tcp->tcp_snd_burst = TCP_CWND_INFINITE;

	tcp->tcp_maxpsz = tcps->tcps_maxpsz_multiplier;

	tcp->tcp_first_timer_threshold = tcps->tcps_ip_notify_interval;
	tcp->tcp_first_ctimer_threshold = tcps->tcps_ip_notify_cinterval;
	tcp->tcp_second_timer_threshold = tcps->tcps_ip_abort_interval;
	/*
	 * Fix it to tcp_ip_abort_linterval later if it turns out to be a
	 * passive open.
	 */
	tcp->tcp_second_ctimer_threshold = tcps->tcps_ip_abort_cinterval;

	tcp->tcp_naglim = tcps->tcps_naglim_def;

	/* NOTE:  ISS is now set in tcp_adapt_ire(). */

	tcp->tcp_mdt_hdr_head = 0;
	tcp->tcp_mdt_hdr_tail = 0;

	/* Reset fusion-related fields */
	tcp->tcp_fused = B_FALSE;
	tcp->tcp_unfusable = B_FALSE;
	tcp->tcp_fused_sigurg = B_FALSE;
	tcp->tcp_direct_sockfs = B_FALSE;
	tcp->tcp_fuse_syncstr_stopped = B_FALSE;
	tcp->tcp_fuse_syncstr_plugged = B_FALSE;
	tcp->tcp_loopback_peer = NULL;
	tcp->tcp_fuse_rcv_hiwater = 0;
	tcp->tcp_fuse_rcv_unread_hiwater = 0;
	tcp->tcp_fuse_rcv_unread_cnt = 0;

	/* Sodirect */
	tcp->tcp_sodirect = NULL;

	/* Initialize the header template */
	if (tcp->tcp_ipversion == IPV4_VERSION) {
		err = tcp_header_init_ipv4(tcp);
	} else {
		err = tcp_header_init_ipv6(tcp);
	}
	if (err)
		return (err);

	/*
	 * Init the window scale to the max so tcp_rwnd_set() won't pare
	 * down tcp_rwnd. tcp_adapt_ire() will set the right value later.
	 */
	tcp->tcp_rcv_ws = TCP_MAX_WINSHIFT;
	tcp->tcp_xmit_lowater = tcps->tcps_xmit_lowat;
	tcp->tcp_xmit_hiwater = tcps->tcps_xmit_hiwat;

	tcp->tcp_cork = B_FALSE;
	/*
	 * Init the tcp_debug option.  This value determines whether TCP
	 * calls strlog() to print out debug messages.  Doing this
	 * initialization here means that this value is not inherited thru
	 * tcp_reinit().
	 */
	tcp->tcp_debug = tcps->tcps_dbg;

	tcp->tcp_ka_interval = tcps->tcps_keepalive_interval;
	tcp->tcp_ka_abort_thres = tcps->tcps_keepalive_abort_interval;

	return (0);
}

/*
 * Initialize the IPv4 header. Loses any record of any IP options.
 */
static int
tcp_header_init_ipv4(tcp_t *tcp)
{
	tcph_t		*tcph;
	uint32_t	sum;
	conn_t		*connp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	/*
	 * This is a simple initialization. If there's
	 * already a template, it should never be too small,
	 * so reuse it.  Otherwise, allocate space for the new one.
	 */
	if (tcp->tcp_iphc == NULL) {
		ASSERT(tcp->tcp_iphc_len == 0);
		tcp->tcp_iphc_len = TCP_MAX_COMBINED_HEADER_LENGTH;
		tcp->tcp_iphc = kmem_cache_alloc(tcp_iphc_cache, KM_NOSLEEP);
		if (tcp->tcp_iphc == NULL) {
			tcp->tcp_iphc_len = 0;
			return (ENOMEM);
		}
	}

	/* options are gone; may need a new label */
	connp = tcp->tcp_connp;
	connp->conn_mlp_type = mlptSingle;
	connp->conn_ulp_labeled = !is_system_labeled();
	ASSERT(tcp->tcp_iphc_len >= TCP_MAX_COMBINED_HEADER_LENGTH);
	tcp->tcp_ipha = (ipha_t *)tcp->tcp_iphc;
	tcp->tcp_ip6h = NULL;
	tcp->tcp_ipversion = IPV4_VERSION;
	tcp->tcp_hdr_len = sizeof (ipha_t) + sizeof (tcph_t);
	tcp->tcp_tcp_hdr_len = sizeof (tcph_t);
	tcp->tcp_ip_hdr_len = sizeof (ipha_t);
	tcp->tcp_ipha->ipha_length = htons(sizeof (ipha_t) + sizeof (tcph_t));
	tcp->tcp_ipha->ipha_version_and_hdr_length
	    = (IP_VERSION << 4) | IP_SIMPLE_HDR_LENGTH_IN_WORDS;
	tcp->tcp_ipha->ipha_ident = 0;

	tcp->tcp_ttl = (uchar_t)tcps->tcps_ipv4_ttl;
	tcp->tcp_tos = 0;
	tcp->tcp_ipha->ipha_fragment_offset_and_flags = 0;
	tcp->tcp_ipha->ipha_ttl = (uchar_t)tcps->tcps_ipv4_ttl;
	tcp->tcp_ipha->ipha_protocol = IPPROTO_TCP;

	tcph = (tcph_t *)(tcp->tcp_iphc + sizeof (ipha_t));
	tcp->tcp_tcph = tcph;
	tcph->th_offset_and_rsrvd[0] = (5 << 4);
	/*
	 * IP wants our header length in the checksum field to
	 * allow it to perform a single pseudo-header+checksum
	 * calculation on behalf of TCP.
	 * Include the adjustment for a source route once IP_OPTIONS is set.
	 */
	sum = sizeof (tcph_t) + tcp->tcp_sum;
	sum = (sum >> 16) + (sum & 0xFFFF);
	U16_TO_ABE16(sum, tcph->th_sum);
	return (0);
}

/*
 * Initialize the IPv6 header. Loses any record of any IPv6 extension headers.
 */
static int
tcp_header_init_ipv6(tcp_t *tcp)
{
	tcph_t	*tcph;
	uint32_t	sum;
	conn_t	*connp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	/*
	 * This is a simple initialization. If there's
	 * already a template, it should never be too small,
	 * so reuse it. Otherwise, allocate space for the new one.
	 * Ensure that there is enough space to "downgrade" the tcp_t
	 * to an IPv4 tcp_t. This requires having space for a full load
	 * of IPv4 options, as well as a full load of TCP options
	 * (TCP_MAX_COMBINED_HEADER_LENGTH, 120 bytes); this is more space
	 * than a v6 header and a TCP header with a full load of TCP options
	 * (IPV6_HDR_LEN is 40 bytes; TCP_MAX_HDR_LENGTH is 60 bytes).
	 * We want to avoid reallocation in the "downgraded" case when
	 * processing outbound IPv4 options.
	 */
	if (tcp->tcp_iphc == NULL) {
		ASSERT(tcp->tcp_iphc_len == 0);
		tcp->tcp_iphc_len = TCP_MAX_COMBINED_HEADER_LENGTH;
		tcp->tcp_iphc = kmem_cache_alloc(tcp_iphc_cache, KM_NOSLEEP);
		if (tcp->tcp_iphc == NULL) {
			tcp->tcp_iphc_len = 0;
			return (ENOMEM);
		}
	}

	/* options are gone; may need a new label */
	connp = tcp->tcp_connp;
	connp->conn_mlp_type = mlptSingle;
	connp->conn_ulp_labeled = !is_system_labeled();

	ASSERT(tcp->tcp_iphc_len >= TCP_MAX_COMBINED_HEADER_LENGTH);
	tcp->tcp_ipversion = IPV6_VERSION;
	tcp->tcp_hdr_len = IPV6_HDR_LEN + sizeof (tcph_t);
	tcp->tcp_tcp_hdr_len = sizeof (tcph_t);
	tcp->tcp_ip_hdr_len = IPV6_HDR_LEN;
	tcp->tcp_ip6h = (ip6_t *)tcp->tcp_iphc;
	tcp->tcp_ipha = NULL;

	/* Initialize the header template */

	tcp->tcp_ip6h->ip6_vcf = IPV6_DEFAULT_VERS_AND_FLOW;
	tcp->tcp_ip6h->ip6_plen = ntohs(sizeof (tcph_t));
	tcp->tcp_ip6h->ip6_nxt = IPPROTO_TCP;
	tcp->tcp_ip6h->ip6_hops = (uint8_t)tcps->tcps_ipv6_hoplimit;

	tcph = (tcph_t *)(tcp->tcp_iphc + IPV6_HDR_LEN);
	tcp->tcp_tcph = tcph;
	tcph->th_offset_and_rsrvd[0] = (5 << 4);
	/*
	 * IP wants our header length in the checksum field to
	 * allow it to perform a single psuedo-header+checksum
	 * calculation on behalf of TCP.
	 * Include the adjustment for a source route when IPV6_RTHDR is set.
	 */
	sum = sizeof (tcph_t) + tcp->tcp_sum;
	sum = (sum >> 16) + (sum & 0xFFFF);
	U16_TO_ABE16(sum, tcph->th_sum);
	return (0);
}

/* At minimum we need 8 bytes in the TCP header for the lookup */
#define	ICMP_MIN_TCP_HDR	8

/*
 * tcp_icmp_error is called by tcp_rput_other to process ICMP error messages
 * passed up by IP. The message is always received on the correct tcp_t.
 * Assumes that IP has pulled up everything up to and including the ICMP header.
 */
void
tcp_icmp_error(tcp_t *tcp, mblk_t *mp)
{
	icmph_t *icmph;
	ipha_t	*ipha;
	int	iph_hdr_length;
	tcph_t	*tcph;
	boolean_t ipsec_mctl = B_FALSE;
	boolean_t secure;
	mblk_t *first_mp = mp;
	int32_t new_mss;
	uint32_t ratio;
	size_t mp_size = MBLKL(mp);
	uint32_t seg_seq;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	ip_stack_t	*ipst = tcps->tcps_netstack->netstack_ip;

	/* Assume IP provides aligned packets - otherwise toss */
	if (!OK_32PTR(mp->b_rptr)) {
		freemsg(mp);
		return;
	}

	/*
	 * Since ICMP errors are normal data marked with M_CTL when sent
	 * to TCP or UDP, we have to look for a IPSEC_IN value to identify
	 * packets starting with an ipsec_info_t, see ipsec_info.h.
	 */
	if ((mp_size == sizeof (ipsec_info_t)) &&
	    (((ipsec_info_t *)mp->b_rptr)->ipsec_info_type == IPSEC_IN)) {
		ASSERT(mp->b_cont != NULL);
		mp = mp->b_cont;
		/* IP should have done this */
		ASSERT(OK_32PTR(mp->b_rptr));
		mp_size = MBLKL(mp);
		ipsec_mctl = B_TRUE;
	}

	/*
	 * Verify that we have a complete outer IP header. If not, drop it.
	 */
	if (mp_size < sizeof (ipha_t)) {
noticmpv4:
		freemsg(first_mp);
		return;
	}

	ipha = (ipha_t *)mp->b_rptr;
	/*
	 * Verify IP version. Anything other than IPv4 or IPv6 packet is sent
	 * upstream. ICMPv6 is handled in tcp_icmp_error_ipv6.
	 */
	switch (IPH_HDR_VERSION(ipha)) {
	case IPV6_VERSION:
		tcp_icmp_error_ipv6(tcp, first_mp, ipsec_mctl);
		return;
	case IPV4_VERSION:
		break;
	default:
		goto noticmpv4;
	}

	/* Skip past the outer IP and ICMP headers */
	iph_hdr_length = IPH_HDR_LENGTH(ipha);
	icmph = (icmph_t *)&mp->b_rptr[iph_hdr_length];
	/*
	 * If we don't have the correct outer IP header length or if the ULP
	 * is not IPPROTO_ICMP or if we don't have a complete inner IP header
	 * send it upstream.
	 */
	if (iph_hdr_length < sizeof (ipha_t) ||
	    ipha->ipha_protocol != IPPROTO_ICMP ||
	    (ipha_t *)&icmph[1] + 1 > (ipha_t *)mp->b_wptr) {
		goto noticmpv4;
	}
	ipha = (ipha_t *)&icmph[1];

	/* Skip past the inner IP and find the ULP header */
	iph_hdr_length = IPH_HDR_LENGTH(ipha);
	tcph = (tcph_t *)((char *)ipha + iph_hdr_length);
	/*
	 * If we don't have the correct inner IP header length or if the ULP
	 * is not IPPROTO_TCP or if we don't have at least ICMP_MIN_TCP_HDR
	 * bytes of TCP header, drop it.
	 */
	if (iph_hdr_length < sizeof (ipha_t) ||
	    ipha->ipha_protocol != IPPROTO_TCP ||
	    (uchar_t *)tcph + ICMP_MIN_TCP_HDR > mp->b_wptr) {
		goto noticmpv4;
	}

	if (TCP_IS_DETACHED_NONEAGER(tcp)) {
		if (ipsec_mctl) {
			secure = ipsec_in_is_secure(first_mp);
		} else {
			secure = B_FALSE;
		}
		if (secure) {
			/*
			 * If we are willing to accept this in clear
			 * we don't have to verify policy.
			 */
			if (!ipsec_inbound_accept_clear(mp, ipha, NULL)) {
				if (!tcp_check_policy(tcp, first_mp,
				    ipha, NULL, secure, ipsec_mctl)) {
					/*
					 * tcp_check_policy called
					 * ip_drop_packet() on failure.
					 */
					return;
				}
			}
		}
	} else if (ipsec_mctl) {
		/*
		 * This is a hard_bound connection. IP has already
		 * verified policy. We don't have to do it again.
		 */
		freeb(first_mp);
		first_mp = mp;
		ipsec_mctl = B_FALSE;
	}

	seg_seq = ABE32_TO_U32(tcph->th_seq);
	/*
	 * TCP SHOULD check that the TCP sequence number contained in
	 * payload of the ICMP error message is within the range
	 * SND.UNA <= SEG.SEQ < SND.NXT.
	 */
	if (SEQ_LT(seg_seq, tcp->tcp_suna) || SEQ_GEQ(seg_seq, tcp->tcp_snxt)) {
		/*
		 * The ICMP message is bogus, just drop it.  But if this is
		 * an ICMP too big message, IP has already changed
		 * the ire_max_frag to the bogus value.  We need to change
		 * it back.
		 */
		if (icmph->icmph_type == ICMP_DEST_UNREACHABLE &&
		    icmph->icmph_code == ICMP_FRAGMENTATION_NEEDED) {
			conn_t *connp = tcp->tcp_connp;
			ire_t *ire;
			int flag;

			if (tcp->tcp_ipversion == IPV4_VERSION) {
				flag = tcp->tcp_ipha->
				    ipha_fragment_offset_and_flags;
			} else {
				flag = 0;
			}
			mutex_enter(&connp->conn_lock);
			if ((ire = connp->conn_ire_cache) != NULL) {
				mutex_enter(&ire->ire_lock);
				mutex_exit(&connp->conn_lock);
				ire->ire_max_frag = tcp->tcp_if_mtu;
				ire->ire_frag_flag |= flag;
				mutex_exit(&ire->ire_lock);
			} else {
				mutex_exit(&connp->conn_lock);
			}
		}
		goto noticmpv4;
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
			 * tcp_ignore_path_mtu just in case this proves
			 * disastrous somewhere.
			 *
			 * After updating the MSS, retransmit part of the
			 * dropped segment using the new mss by calling
			 * tcp_wput_data().  Need to adjust all those
			 * params to make sure tcp_wput_data() work properly.
			 */
			if (tcps->tcps_ignore_path_mtu ||
			    tcp->tcp_ipha->ipha_fragment_offset_and_flags == 0)
				break;

			/*
			 * Decrease the MSS by time stamp options
			 * IP options and IPSEC options. tcp_hdr_len
			 * includes time stamp option and IP option
			 * length.  Note that new_mss may be negative
			 * if tcp_ipsec_overhead is large and the
			 * icmph_du_mtu is the minimum value, which is 68.
			 */
			new_mss = ntohs(icmph->icmph_du_mtu) -
			    tcp->tcp_hdr_len - tcp->tcp_ipsec_overhead;

			DTRACE_PROBE2(tcp__pmtu__change, tcp_t *, tcp, int,
			    new_mss);

			/*
			 * Only update the MSS if the new one is
			 * smaller than the previous one.  This is
			 * to avoid problems when getting multiple
			 * ICMP errors for the same MTU.
			 */
			if (new_mss >= tcp->tcp_mss)
				break;

			/*
			 * Note that we are using the template header's DF
			 * bit in the fast path sending.  So we need to compare
			 * the new mss with both tcps_mss_min and ip_pmtu_min.
			 * And stop doing IPv4 PMTUd if new_mss is less than
			 * MAX(tcps_mss_min, ip_pmtu_min).
			 */
			if (new_mss < tcps->tcps_mss_min ||
			    new_mss < ipst->ips_ip_pmtu_min) {
				tcp->tcp_ipha->ipha_fragment_offset_and_flags =
				    0;
			}

			ratio = tcp->tcp_cwnd / tcp->tcp_mss;
			ASSERT(ratio >= 1);
			tcp_mss_set(tcp, new_mss, B_TRUE);

			/*
			 * Make sure we have something to
			 * send.
			 */
			if (SEQ_LT(tcp->tcp_suna, tcp->tcp_snxt) &&
			    (tcp->tcp_xmit_head != NULL)) {
				/*
				 * Shrink tcp_cwnd in
				 * proportion to the old MSS/new MSS.
				 */
				tcp->tcp_cwnd = ratio * tcp->tcp_mss;
				if ((tcp->tcp_valid_bits & TCP_FSS_VALID) &&
				    (tcp->tcp_unsent == 0)) {
					tcp->tcp_rexmit_max = tcp->tcp_fss;
				} else {
					tcp->tcp_rexmit_max = tcp->tcp_snxt;
				}
				tcp->tcp_rexmit_nxt = tcp->tcp_suna;
				tcp->tcp_rexmit = B_TRUE;
				tcp->tcp_dupack_cnt = 0;
				tcp->tcp_snd_burst = TCP_CWND_SS;
				tcp_ss_rexmit(tcp);
			}
			break;
		case ICMP_PORT_UNREACHABLE:
		case ICMP_PROTOCOL_UNREACHABLE:
			switch (tcp->tcp_state) {
			case TCPS_SYN_SENT:
			case TCPS_SYN_RCVD:
				/*
				 * ICMP can snipe away incipient
				 * TCP connections as long as
				 * seq number is same as initial
				 * send seq number.
				 */
				if (seg_seq == tcp->tcp_iss) {
					(void) tcp_clean_death(tcp,
					    ECONNREFUSED, 6);
				}
				break;
			}
			break;
		case ICMP_HOST_UNREACHABLE:
		case ICMP_NET_UNREACHABLE:
			/* Record the error in case we finally time out. */
			if (icmph->icmph_code == ICMP_HOST_UNREACHABLE)
				tcp->tcp_client_errno = EHOSTUNREACH;
			else
				tcp->tcp_client_errno = ENETUNREACH;
			if (tcp->tcp_state == TCPS_SYN_RCVD) {
				if (tcp->tcp_listener != NULL &&
				    tcp->tcp_listener->tcp_syn_defense) {
					/*
					 * Ditch the half-open connection if we
					 * suspect a SYN attack is under way.
					 */
					tcp_ip_ire_mark_advice(tcp);
					(void) tcp_clean_death(tcp,
					    tcp->tcp_client_errno, 7);
				}
			}
			break;
		default:
			break;
		}
		break;
	case ICMP_SOURCE_QUENCH: {
		/*
		 * use a global boolean to control
		 * whether TCP should respond to ICMP_SOURCE_QUENCH.
		 * The default is false.
		 */
		if (tcp_icmp_source_quench) {
			/*
			 * Reduce the sending rate as if we got a
			 * retransmit timeout
			 */
			uint32_t npkt;

			npkt = ((tcp->tcp_snxt - tcp->tcp_suna) >> 1) /
			    tcp->tcp_mss;
			tcp->tcp_cwnd_ssthresh = MAX(npkt, 2) * tcp->tcp_mss;
			tcp->tcp_cwnd = tcp->tcp_mss;
			tcp->tcp_cwnd_cnt = 0;
		}
		break;
	}
	}
	freemsg(first_mp);
}

/*
 * tcp_icmp_error_ipv6 is called by tcp_rput_other to process ICMPv6
 * error messages passed up by IP.
 * Assumes that IP has pulled up all the extension headers as well
 * as the ICMPv6 header.
 */
static void
tcp_icmp_error_ipv6(tcp_t *tcp, mblk_t *mp, boolean_t ipsec_mctl)
{
	icmp6_t *icmp6;
	ip6_t	*ip6h;
	uint16_t	iph_hdr_length;
	tcpha_t	*tcpha;
	uint8_t	*nexthdrp;
	uint32_t new_mss;
	uint32_t ratio;
	boolean_t secure;
	mblk_t *first_mp = mp;
	size_t mp_size;
	uint32_t seg_seq;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	/*
	 * The caller has determined if this is an IPSEC_IN packet and
	 * set ipsec_mctl appropriately (see tcp_icmp_error).
	 */
	if (ipsec_mctl)
		mp = mp->b_cont;

	mp_size = MBLKL(mp);

	/*
	 * Verify that we have a complete IP header. If not, send it upstream.
	 */
	if (mp_size < sizeof (ip6_t)) {
noticmpv6:
		freemsg(first_mp);
		return;
	}

	/*
	 * Verify this is an ICMPV6 packet, else send it upstream.
	 */
	ip6h = (ip6_t *)mp->b_rptr;
	if (ip6h->ip6_nxt == IPPROTO_ICMPV6) {
		iph_hdr_length = IPV6_HDR_LEN;
	} else if (!ip_hdr_length_nexthdr_v6(mp, ip6h, &iph_hdr_length,
	    &nexthdrp) ||
	    *nexthdrp != IPPROTO_ICMPV6) {
		goto noticmpv6;
	}
	icmp6 = (icmp6_t *)&mp->b_rptr[iph_hdr_length];
	ip6h = (ip6_t *)&icmp6[1];
	/*
	 * Verify if we have a complete ICMP and inner IP header.
	 */
	if ((uchar_t *)&ip6h[1] > mp->b_wptr)
		goto noticmpv6;

	if (!ip_hdr_length_nexthdr_v6(mp, ip6h, &iph_hdr_length, &nexthdrp))
		goto noticmpv6;
	tcpha = (tcpha_t *)((char *)ip6h + iph_hdr_length);
	/*
	 * Validate inner header. If the ULP is not IPPROTO_TCP or if we don't
	 * have at least ICMP_MIN_TCP_HDR bytes of  TCP header drop the
	 * packet.
	 */
	if ((*nexthdrp != IPPROTO_TCP) ||
	    ((uchar_t *)tcpha + ICMP_MIN_TCP_HDR) > mp->b_wptr) {
		goto noticmpv6;
	}

	/*
	 * ICMP errors come on the right queue or come on
	 * listener/global queue for detached connections and
	 * get switched to the right queue. If it comes on the
	 * right queue, policy check has already been done by IP
	 * and thus free the first_mp without verifying the policy.
	 * If it has come for a non-hard bound connection, we need
	 * to verify policy as IP may not have done it.
	 */
	if (!tcp->tcp_hard_bound) {
		if (ipsec_mctl) {
			secure = ipsec_in_is_secure(first_mp);
		} else {
			secure = B_FALSE;
		}
		if (secure) {
			/*
			 * If we are willing to accept this in clear
			 * we don't have to verify policy.
			 */
			if (!ipsec_inbound_accept_clear(mp, NULL, ip6h)) {
				if (!tcp_check_policy(tcp, first_mp,
				    NULL, ip6h, secure, ipsec_mctl)) {
					/*
					 * tcp_check_policy called
					 * ip_drop_packet() on failure.
					 */
					return;
				}
			}
		}
	} else if (ipsec_mctl) {
		/*
		 * This is a hard_bound connection. IP has already
		 * verified policy. We don't have to do it again.
		 */
		freeb(first_mp);
		first_mp = mp;
		ipsec_mctl = B_FALSE;
	}

	seg_seq = ntohl(tcpha->tha_seq);
	/*
	 * TCP SHOULD check that the TCP sequence number contained in
	 * payload of the ICMP error message is within the range
	 * SND.UNA <= SEG.SEQ < SND.NXT.
	 */
	if (SEQ_LT(seg_seq, tcp->tcp_suna) || SEQ_GEQ(seg_seq, tcp->tcp_snxt)) {
		/*
		 * If the ICMP message is bogus, should we kill the
		 * connection, or should we just drop the bogus ICMP
		 * message? It would probably make more sense to just
		 * drop the message so that if this one managed to get
		 * in, the real connection should not suffer.
		 */
		goto noticmpv6;
	}

	switch (icmp6->icmp6_type) {
	case ICMP6_PACKET_TOO_BIG:
		/*
		 * Reduce the MSS based on the new MTU.  This will
		 * eliminate any fragmentation locally.
		 * N.B.  There may well be some funny side-effects on
		 * the local send policy and the remote receive policy.
		 * Pending further research, we provide
		 * tcp_ignore_path_mtu just in case this proves
		 * disastrous somewhere.
		 *
		 * After updating the MSS, retransmit part of the
		 * dropped segment using the new mss by calling
		 * tcp_wput_data().  Need to adjust all those
		 * params to make sure tcp_wput_data() work properly.
		 */
		if (tcps->tcps_ignore_path_mtu)
			break;

		/*
		 * Decrease the MSS by time stamp options
		 * IP options and IPSEC options. tcp_hdr_len
		 * includes time stamp option and IP option
		 * length.
		 */
		new_mss = ntohs(icmp6->icmp6_mtu) - tcp->tcp_hdr_len -
		    tcp->tcp_ipsec_overhead;

		/*
		 * Only update the MSS if the new one is
		 * smaller than the previous one.  This is
		 * to avoid problems when getting multiple
		 * ICMP errors for the same MTU.
		 */
		if (new_mss >= tcp->tcp_mss)
			break;

		ratio = tcp->tcp_cwnd / tcp->tcp_mss;
		ASSERT(ratio >= 1);
		tcp_mss_set(tcp, new_mss, B_TRUE);

		/*
		 * Make sure we have something to
		 * send.
		 */
		if (SEQ_LT(tcp->tcp_suna, tcp->tcp_snxt) &&
		    (tcp->tcp_xmit_head != NULL)) {
			/*
			 * Shrink tcp_cwnd in
			 * proportion to the old MSS/new MSS.
			 */
			tcp->tcp_cwnd = ratio * tcp->tcp_mss;
			if ((tcp->tcp_valid_bits & TCP_FSS_VALID) &&
			    (tcp->tcp_unsent == 0)) {
				tcp->tcp_rexmit_max = tcp->tcp_fss;
			} else {
				tcp->tcp_rexmit_max = tcp->tcp_snxt;
			}
			tcp->tcp_rexmit_nxt = tcp->tcp_suna;
			tcp->tcp_rexmit = B_TRUE;
			tcp->tcp_dupack_cnt = 0;
			tcp->tcp_snd_burst = TCP_CWND_SS;
			tcp_ss_rexmit(tcp);
		}
		break;

	case ICMP6_DST_UNREACH:
		switch (icmp6->icmp6_code) {
		case ICMP6_DST_UNREACH_NOPORT:
			if (((tcp->tcp_state == TCPS_SYN_SENT) ||
			    (tcp->tcp_state == TCPS_SYN_RCVD)) &&
			    (seg_seq == tcp->tcp_iss)) {
				(void) tcp_clean_death(tcp,
				    ECONNREFUSED, 8);
			}
			break;

		case ICMP6_DST_UNREACH_ADMIN:
		case ICMP6_DST_UNREACH_NOROUTE:
		case ICMP6_DST_UNREACH_BEYONDSCOPE:
		case ICMP6_DST_UNREACH_ADDR:
			/* Record the error in case we finally time out. */
			tcp->tcp_client_errno = EHOSTUNREACH;
			if (((tcp->tcp_state == TCPS_SYN_SENT) ||
			    (tcp->tcp_state == TCPS_SYN_RCVD)) &&
			    (seg_seq == tcp->tcp_iss)) {
				if (tcp->tcp_listener != NULL &&
				    tcp->tcp_listener->tcp_syn_defense) {
					/*
					 * Ditch the half-open connection if we
					 * suspect a SYN attack is under way.
					 */
					tcp_ip_ire_mark_advice(tcp);
					(void) tcp_clean_death(tcp,
					    tcp->tcp_client_errno, 9);
				}
			}


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
			if (tcp->tcp_state == TCPS_SYN_SENT ||
			    tcp->tcp_state == TCPS_SYN_RCVD) {
				(void) tcp_clean_death(tcp,
				    ECONNREFUSED, 10);
			}
			break;
		}
		break;

	case ICMP6_TIME_EXCEEDED:
	default:
		break;
	}
	freemsg(first_mp);
}

/*
 * Notify IP that we are having trouble with this connection.  IP should
 * blow the IRE away and start over.
 */
static void
tcp_ip_notify(tcp_t *tcp)
{
	struct iocblk	*iocp;
	ipid_t	*ipid;
	mblk_t	*mp;

	/* IPv6 has NUD thus notification to delete the IRE is not needed */
	if (tcp->tcp_ipversion == IPV6_VERSION)
		return;

	mp = mkiocb(IP_IOCTL);
	if (mp == NULL)
		return;

	iocp = (struct iocblk *)mp->b_rptr;
	iocp->ioc_count = sizeof (ipid_t) + sizeof (tcp->tcp_ipha->ipha_dst);

	mp->b_cont = allocb(iocp->ioc_count, BPRI_HI);
	if (!mp->b_cont) {
		freeb(mp);
		return;
	}

	ipid = (ipid_t *)mp->b_cont->b_rptr;
	mp->b_cont->b_wptr += iocp->ioc_count;
	bzero(ipid, sizeof (*ipid));
	ipid->ipid_cmd = IP_IOC_IRE_DELETE_NO_REPLY;
	ipid->ipid_ire_type = IRE_CACHE;
	ipid->ipid_addr_offset = sizeof (ipid_t);
	ipid->ipid_addr_length = sizeof (tcp->tcp_ipha->ipha_dst);
	/*
	 * Note: in the case of source routing we want to blow away the
	 * route to the first source route hop.
	 */
	bcopy(&tcp->tcp_ipha->ipha_dst, &ipid[1],
	    sizeof (tcp->tcp_ipha->ipha_dst));

	CALL_IP_WPUT(tcp->tcp_connp, tcp->tcp_wq, mp);
}

/* Unlink and return any mblk that looks like it contains an ire */
static mblk_t *
tcp_ire_mp(mblk_t **mpp)
{
	mblk_t 	*mp = *mpp;
	mblk_t	*prev_mp = NULL;

	for (;;) {
		switch (DB_TYPE(mp)) {
		case IRE_DB_TYPE:
		case IRE_DB_REQ_TYPE:
			if (mp == *mpp) {
				*mpp = mp->b_cont;
			} else {
				prev_mp->b_cont = mp->b_cont;
			}
			mp->b_cont = NULL;
			return (mp);
		default:
			break;
		}
		prev_mp = mp;
		mp = mp->b_cont;
		if (mp == NULL)
			break;
	}
	return (mp);
}

/*
 * Timer callback routine for keepalive probe.  We do a fake resend of
 * last ACKed byte.  Then set a timer using RTO.  When the timer expires,
 * check to see if we have heard anything from the other end for the last
 * RTO period.  If we have, set the timer to expire for another
 * tcp_keepalive_intrvl and check again.  If we have not, set a timer using
 * RTO << 1 and check again when it expires.  Keep exponentially increasing
 * the timeout if we have not heard from the other side.  If for more than
 * (tcp_ka_interval + tcp_ka_abort_thres) we have not heard anything,
 * kill the connection unless the keepalive abort threshold is 0.  In
 * that case, we will probe "forever."
 */
static void
tcp_keepalive_killer(void *arg)
{
	mblk_t	*mp;
	conn_t	*connp = (conn_t *)arg;
	tcp_t  	*tcp = connp->conn_tcp;
	int32_t	firetime;
	int32_t	idletime;
	int32_t	ka_intrvl;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	tcp->tcp_ka_tid = 0;

	if (tcp->tcp_fused)
		return;

	BUMP_MIB(&tcps->tcps_mib, tcpTimKeepalive);
	ka_intrvl = tcp->tcp_ka_interval;

	/*
	 * Keepalive probe should only be sent if the application has not
	 * done a close on the connection.
	 */
	if (tcp->tcp_state > TCPS_CLOSE_WAIT) {
		return;
	}
	/* Timer fired too early, restart it. */
	if (tcp->tcp_state < TCPS_ESTABLISHED) {
		tcp->tcp_ka_tid = TCP_TIMER(tcp, tcp_keepalive_killer,
		    MSEC_TO_TICK(ka_intrvl));
		return;
	}

	idletime = TICK_TO_MSEC(lbolt - tcp->tcp_last_recv_time);
	/*
	 * If we have not heard from the other side for a long
	 * time, kill the connection unless the keepalive abort
	 * threshold is 0.  In that case, we will probe "forever."
	 */
	if (tcp->tcp_ka_abort_thres != 0 &&
	    idletime > (ka_intrvl + tcp->tcp_ka_abort_thres)) {
		BUMP_MIB(&tcps->tcps_mib, tcpTimKeepaliveDrop);
		(void) tcp_clean_death(tcp, tcp->tcp_client_errno ?
		    tcp->tcp_client_errno : ETIMEDOUT, 11);
		return;
	}

	if (tcp->tcp_snxt == tcp->tcp_suna &&
	    idletime >= ka_intrvl) {
		/* Fake resend of last ACKed byte. */
		mblk_t	*mp1 = allocb(1, BPRI_LO);

		if (mp1 != NULL) {
			*mp1->b_wptr++ = '\0';
			mp = tcp_xmit_mp(tcp, mp1, 1, NULL, NULL,
			    tcp->tcp_suna - 1, B_FALSE, NULL, B_TRUE);
			freeb(mp1);
			/*
			 * if allocation failed, fall through to start the
			 * timer back.
			 */
			if (mp != NULL) {
				tcp_send_data(tcp, tcp->tcp_wq, mp);
				BUMP_MIB(&tcps->tcps_mib,
				    tcpTimKeepaliveProbe);
				if (tcp->tcp_ka_last_intrvl != 0) {
					int max;
					/*
					 * We should probe again at least
					 * in ka_intrvl, but not more than
					 * tcp_rexmit_interval_max.
					 */
					max = tcps->tcps_rexmit_interval_max;
					firetime = MIN(ka_intrvl - 1,
					    tcp->tcp_ka_last_intrvl << 1);
					if (firetime > max)
						firetime = max;
				} else {
					firetime = tcp->tcp_rto;
				}
				tcp->tcp_ka_tid = TCP_TIMER(tcp,
				    tcp_keepalive_killer,
				    MSEC_TO_TICK(firetime));
				tcp->tcp_ka_last_intrvl = firetime;
				return;
			}
		}
	} else {
		tcp->tcp_ka_last_intrvl = 0;
	}

	/* firetime can be negative if (mp1 == NULL || mp == NULL) */
	if ((firetime = ka_intrvl - idletime) < 0) {
		firetime = ka_intrvl;
	}
	tcp->tcp_ka_tid = TCP_TIMER(tcp, tcp_keepalive_killer,
	    MSEC_TO_TICK(firetime));
}

int
tcp_maxpsz_set(tcp_t *tcp, boolean_t set_maxblk)
{
	queue_t	*q = tcp->tcp_rq;
	int32_t	mss = tcp->tcp_mss;
	int	maxpsz;
	conn_t	*connp = tcp->tcp_connp;

	if (TCP_IS_DETACHED(tcp))
		return (mss);
	if (tcp->tcp_fused) {
		maxpsz = tcp_fuse_maxpsz_set(tcp);
		mss = INFPSZ;
	} else if (tcp->tcp_mdt || tcp->tcp_lso || tcp->tcp_maxpsz == 0) {
		/*
		 * Set the sd_qn_maxpsz according to the socket send buffer
		 * size, and sd_maxblk to INFPSZ (-1).  This will essentially
		 * instruct the stream head to copyin user data into contiguous
		 * kernel-allocated buffers without breaking it up into smaller
		 * chunks.  We round up the buffer size to the nearest SMSS.
		 */
		maxpsz = MSS_ROUNDUP(tcp->tcp_xmit_hiwater, mss);
		if (tcp->tcp_kssl_ctx == NULL)
			mss = INFPSZ;
		else
			mss = SSL3_MAX_RECORD_LEN;
	} else {
		/*
		 * Set sd_qn_maxpsz to approx half the (receivers) buffer
		 * (and a multiple of the mss).  This instructs the stream
		 * head to break down larger than SMSS writes into SMSS-
		 * size mblks, up to tcp_maxpsz_multiplier mblks at a time.
		 */
		/* XXX tune this with ndd tcp_maxpsz_multiplier */
		maxpsz = tcp->tcp_maxpsz * mss;
		if (maxpsz > tcp->tcp_xmit_hiwater/2) {
			maxpsz = tcp->tcp_xmit_hiwater/2;
			/* Round up to nearest mss */
			maxpsz = MSS_ROUNDUP(maxpsz, mss);
		}
	}

	(void) proto_set_maxpsz(q, connp, maxpsz);
	if (!(IPCL_IS_NONSTR(connp))) {
		/* XXX do it in set_maxpsz()? */
		tcp->tcp_wq->q_maxpsz = maxpsz;
	}

	if (set_maxblk)
		(void) proto_set_tx_maxblk(q, connp, mss);
	return (mss);
}

/*
 * Extract option values from a tcp header.  We put any found values into the
 * tcpopt struct and return a bitmask saying which options were found.
 */
static int
tcp_parse_options(tcph_t *tcph, tcp_opt_t *tcpopt)
{
	uchar_t		*endp;
	int		len;
	uint32_t	mss;
	uchar_t		*up = (uchar_t *)tcph;
	int		found = 0;
	int32_t		sack_len;
	tcp_seq		sack_begin, sack_end;
	tcp_t		*tcp;

	endp = up + TCP_HDR_LENGTH(tcph);
	up += TCP_MIN_HEADER_LENGTH;
	while (up < endp) {
		len = endp - up;
		switch (*up) {
		case TCPOPT_EOL:
			break;

		case TCPOPT_NOP:
			up++;
			continue;

		case TCPOPT_MAXSEG:
			if (len < TCPOPT_MAXSEG_LEN ||
			    up[1] != TCPOPT_MAXSEG_LEN)
				break;

			mss = BE16_TO_U16(up+2);
			/* Caller must handle tcp_mss_min and tcp_mss_max_* */
			tcpopt->tcp_opt_mss = mss;
			found |= TCP_OPT_MSS_PRESENT;

			up += TCPOPT_MAXSEG_LEN;
			continue;

		case TCPOPT_WSCALE:
			if (len < TCPOPT_WS_LEN || up[1] != TCPOPT_WS_LEN)
				break;

			if (up[2] > TCP_MAX_WINSHIFT)
				tcpopt->tcp_opt_wscale = TCP_MAX_WINSHIFT;
			else
				tcpopt->tcp_opt_wscale = up[2];
			found |= TCP_OPT_WSCALE_PRESENT;

			up += TCPOPT_WS_LEN;
			continue;

		case TCPOPT_SACK_PERMITTED:
			if (len < TCPOPT_SACK_OK_LEN ||
			    up[1] != TCPOPT_SACK_OK_LEN)
				break;
			found |= TCP_OPT_SACK_OK_PRESENT;
			up += TCPOPT_SACK_OK_LEN;
			continue;

		case TCPOPT_SACK:
			if (len <= 2 || up[1] <= 2 || len < up[1])
				break;

			/* If TCP is not interested in SACK blks... */
			if ((tcp = tcpopt->tcp) == NULL) {
				up += up[1];
				continue;
			}
			sack_len = up[1] - TCPOPT_HEADER_LEN;
			up += TCPOPT_HEADER_LEN;

			/*
			 * If the list is empty, allocate one and assume
			 * nothing is sack'ed.
			 */
			ASSERT(tcp->tcp_sack_info != NULL);
			if (tcp->tcp_notsack_list == NULL) {
				tcp_notsack_update(&(tcp->tcp_notsack_list),
				    tcp->tcp_suna, tcp->tcp_snxt,
				    &(tcp->tcp_num_notsack_blk),
				    &(tcp->tcp_cnt_notsack_list));

				/*
				 * Make sure tcp_notsack_list is not NULL.
				 * This happens when kmem_alloc(KM_NOSLEEP)
				 * returns NULL.
				 */
				if (tcp->tcp_notsack_list == NULL) {
					up += sack_len;
					continue;
				}
				tcp->tcp_fack = tcp->tcp_suna;
			}

			while (sack_len > 0) {
				if (up + 8 > endp) {
					up = endp;
					break;
				}
				sack_begin = BE32_TO_U32(up);
				up += 4;
				sack_end = BE32_TO_U32(up);
				up += 4;
				sack_len -= 8;
				/*
				 * Bounds checking.  Make sure the SACK
				 * info is within tcp_suna and tcp_snxt.
				 * If this SACK blk is out of bound, ignore
				 * it but continue to parse the following
				 * blks.
				 */
				if (SEQ_LEQ(sack_end, sack_begin) ||
				    SEQ_LT(sack_begin, tcp->tcp_suna) ||
				    SEQ_GT(sack_end, tcp->tcp_snxt)) {
					continue;
				}
				tcp_notsack_insert(&(tcp->tcp_notsack_list),
				    sack_begin, sack_end,
				    &(tcp->tcp_num_notsack_blk),
				    &(tcp->tcp_cnt_notsack_list));
				if (SEQ_GT(sack_end, tcp->tcp_fack)) {
					tcp->tcp_fack = sack_end;
				}
			}
			found |= TCP_OPT_SACK_PRESENT;
			continue;

		case TCPOPT_TSTAMP:
			if (len < TCPOPT_TSTAMP_LEN ||
			    up[1] != TCPOPT_TSTAMP_LEN)
				break;

			tcpopt->tcp_opt_ts_val = BE32_TO_U32(up+2);
			tcpopt->tcp_opt_ts_ecr = BE32_TO_U32(up+6);

			found |= TCP_OPT_TSTAMP_PRESENT;

			up += TCPOPT_TSTAMP_LEN;
			continue;

		default:
			if (len <= 1 || len < (int)up[1] || up[1] == 0)
				break;
			up += up[1];
			continue;
		}
		break;
	}
	return (found);
}

/*
 * Set the mss associated with a particular tcp based on its current value,
 * and a new one passed in. Observe minimums and maximums, and reset
 * other state variables that we want to view as multiples of mss.
 *
 * This function is called mainly because values like tcp_mss, tcp_cwnd,
 * highwater marks etc. need to be initialized or adjusted.
 * 1) From tcp_process_options() when the other side's SYN/SYN-ACK
 *    packet arrives.
 * 2) We need to set a new MSS when ICMP_FRAGMENTATION_NEEDED or
 *    ICMP6_PACKET_TOO_BIG arrives.
 * 3) From tcp_paws_check() if the other side stops sending the timestamp,
 *    to increase the MSS to use the extra bytes available.
 *
 * Callers except tcp_paws_check() ensure that they only reduce mss.
 */
static void
tcp_mss_set(tcp_t *tcp, uint32_t mss, boolean_t do_ss)
{
	uint32_t	mss_max;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	if (tcp->tcp_ipversion == IPV4_VERSION)
		mss_max = tcps->tcps_mss_max_ipv4;
	else
		mss_max = tcps->tcps_mss_max_ipv6;

	if (mss < tcps->tcps_mss_min)
		mss = tcps->tcps_mss_min;
	if (mss > mss_max)
		mss = mss_max;
	/*
	 * Unless naglim has been set by our client to
	 * a non-mss value, force naglim to track mss.
	 * This can help to aggregate small writes.
	 */
	if (mss < tcp->tcp_naglim || tcp->tcp_mss == tcp->tcp_naglim)
		tcp->tcp_naglim = mss;
	/*
	 * TCP should be able to buffer at least 4 MSS data for obvious
	 * performance reason.
	 */
	if ((mss << 2) > tcp->tcp_xmit_hiwater)
		tcp->tcp_xmit_hiwater = mss << 2;

	if (do_ss) {
		/*
		 * Either the tcp_cwnd is as yet uninitialized, or mss is
		 * changing due to a reduction in MTU, presumably as a
		 * result of a new path component, reset cwnd to its
		 * "initial" value, as a multiple of the new mss.
		 */
		SET_TCP_INIT_CWND(tcp, mss, tcps->tcps_slow_start_initial);
	} else {
		/*
		 * Called by tcp_paws_check(), the mss increased
		 * marginally to allow use of space previously taken
		 * by the timestamp option. It would be inappropriate
		 * to apply slow start or tcp_init_cwnd values to
		 * tcp_cwnd, simply adjust to a multiple of the new mss.
		 */
		tcp->tcp_cwnd = (tcp->tcp_cwnd / tcp->tcp_mss) * mss;
		tcp->tcp_cwnd_cnt = 0;
	}
	tcp->tcp_mss = mss;
	(void) tcp_maxpsz_set(tcp, B_TRUE);
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

static conn_t *
tcp_create_common(queue_t *q, cred_t *credp, boolean_t isv6,
    boolean_t issocket, int *errorp)
{
	tcp_t		*tcp = NULL;
	conn_t		*connp;
	int		err;
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
	/*
	 * For stackid zero this is done from strplumb.c, but
	 * non-zero stackids are handled here.
	 */
	if (tcps->tcps_g_q == NULL &&
	    tcps->tcps_netstack->netstack_stackid !=
	    GLOBAL_NETSTACKID) {
		tcp_g_q_setup(tcps);
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
	connp->conn_sqp = sqp;
	connp->conn_initial_sqp = connp->conn_sqp;
	tcp = connp->conn_tcp;

	if (isv6) {
		connp->conn_flags |= (IPCL_TCP6|IPCL_ISV6);
		connp->conn_send = ip_output_v6;
		connp->conn_af_isv6 = B_TRUE;
		connp->conn_pkt_isv6 = B_TRUE;
		connp->conn_src_preferences = IPV6_PREFER_SRC_DEFAULT;
		tcp->tcp_ipversion = IPV6_VERSION;
		tcp->tcp_family = AF_INET6;
		tcp->tcp_mss = tcps->tcps_mss_def_ipv6;
	} else {
		connp->conn_flags |= IPCL_TCP4;
		connp->conn_send = ip_output;
		connp->conn_af_isv6 = B_FALSE;
		connp->conn_pkt_isv6 = B_FALSE;
		tcp->tcp_ipversion = IPV4_VERSION;
		tcp->tcp_family = AF_INET;
		tcp->tcp_mss = tcps->tcps_mss_def_ipv4;
	}

	/*
	 * TCP keeps a copy of cred for cache locality reasons but
	 * we put a reference only once. If connp->conn_cred
	 * becomes invalid, tcp_cred should also be set to NULL.
	 */
	tcp->tcp_cred = connp->conn_cred = credp;
	crhold(connp->conn_cred);
	tcp->tcp_cpid = curproc->p_pid;
	tcp->tcp_open_time = lbolt64;
	connp->conn_zoneid = zoneid;
	connp->conn_mlp_type = mlptSingle;
	connp->conn_ulp_labeled = !is_system_labeled();
	ASSERT(connp->conn_netstack == tcps->tcps_netstack);
	ASSERT(tcp->tcp_tcps == tcps);

	/*
	 * If the caller has the process-wide flag set, then default to MAC
	 * exempt mode.  This allows read-down to unlabeled hosts.
	 */
	if (getpflags(NET_MAC_AWARE, credp) != 0)
		connp->conn_mac_exempt = B_TRUE;

	connp->conn_dev = NULL;
	if (issocket) {
		connp->conn_flags |= IPCL_SOCKET;
		tcp->tcp_issocket = 1;
	}

	tcp->tcp_recv_hiwater = tcps->tcps_recv_hiwat;
	tcp->tcp_rwnd = tcps->tcps_recv_hiwat;
	tcp->tcp_recv_lowater = tcp_rinfo.mi_lowat;

	/* Non-zero default values */
	connp->conn_multicast_loop = IP_DEFAULT_MULTICAST_LOOP;

	if (q == NULL) {
		/*
		 * Create a helper stream for non-STREAMS socket.
		 */
		err = ip_create_helper_stream(connp, tcps->tcps_ldi_ident);
		if (err != 0) {
			ip1dbg(("tcp_create_common: create of IP helper stream "
			    "failed\n"));
			CONN_DEC_REF(connp);
			*errorp = err;
			return (NULL);
		}
		q = connp->conn_rq;
	} else {
		RD(q)->q_hiwat = tcps->tcps_recv_hiwat;
	}

	SOCK_CONNID_INIT(tcp->tcp_connid);
	err = tcp_init(tcp, q);
	if (err != 0) {
		CONN_DEC_REF(connp);
		*errorp = err;
		return (NULL);
	}

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
		 * tcp_wput_accept() and tcpclose_accept() to figure out the
		 * minor device number for this connection from the q_ptr.
		 */
		RD(q)->q_ptr = (void *)conn_dev;
		WR(q)->q_qinfo = &tcp_acceptor_winit;
		WR(q)->q_ptr = (void *)minor_arena;
		qprocson(q);
		return (0);
	}

	issocket = flag & SO_SOCKSTR;
	connp = tcp_create_common(q, credp, isv6, issocket, &err);

	if (connp == NULL) {
		inet_minor_free(minor_arena, conn_dev);
		q->q_ptr = WR(q)->q_ptr = NULL;
		return (err);
	}

	q->q_ptr = WR(q)->q_ptr = connp;

	connp->conn_dev = conn_dev;
	connp->conn_minor_arena = minor_arena;

	ASSERT(q->q_qinfo == &tcp_rinitv4 || q->q_qinfo == &tcp_rinitv6);
	ASSERT(WR(q)->q_qinfo == &tcp_winit);

	if (issocket) {
		WR(q)->q_qinfo = &tcp_sock_winit;
	} else {
		tcp = connp->conn_tcp;
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
 * Some TCP options can be "set" by requesting them in the option
 * buffer. This is needed for XTI feature test though we do not
 * allow it in general. We interpret that this mechanism is more
 * applicable to OSI protocols and need not be allowed in general.
 * This routine filters out options for which it is not allowed (most)
 * and lets through those (few) for which it is. [ The XTI interface
 * test suite specifics will imply that any XTI_GENERIC level XTI_* if
 * ever implemented will have to be allowed here ].
 */
static boolean_t
tcp_allow_connopt_set(int level, int name)
{

	switch (level) {
	case IPPROTO_TCP:
		switch (name) {
		case TCP_NODELAY:
			return (B_TRUE);
		default:
			return (B_FALSE);
		}
		/*NOTREACHED*/
	default:
		return (B_FALSE);
	}
	/*NOTREACHED*/
}

/*
 * this routine gets default values of certain options whose default
 * values are maintained by protocol specific code
 */
/* ARGSUSED */
int
tcp_opt_default(queue_t *q, int level, int name, uchar_t *ptr)
{
	int32_t	*i1 = (int32_t *)ptr;
	tcp_stack_t	*tcps = Q_TO_TCP(q)->tcp_tcps;

	switch (level) {
	case IPPROTO_TCP:
		switch (name) {
		case TCP_NOTIFY_THRESHOLD:
			*i1 = tcps->tcps_ip_notify_interval;
			break;
		case TCP_ABORT_THRESHOLD:
			*i1 = tcps->tcps_ip_abort_interval;
			break;
		case TCP_CONN_NOTIFY_THRESHOLD:
			*i1 = tcps->tcps_ip_notify_cinterval;
			break;
		case TCP_CONN_ABORT_THRESHOLD:
			*i1 = tcps->tcps_ip_abort_cinterval;
			break;
		default:
			return (-1);
		}
		break;
	case IPPROTO_IP:
		switch (name) {
		case IP_TTL:
			*i1 = tcps->tcps_ipv4_ttl;
			break;
		default:
			return (-1);
		}
		break;
	case IPPROTO_IPV6:
		switch (name) {
		case IPV6_UNICAST_HOPS:
			*i1 = tcps->tcps_ipv6_hoplimit;
			break;
		default:
			return (-1);
		}
		break;
	default:
		return (-1);
	}
	return (sizeof (int));
}

static int
tcp_opt_get(conn_t *connp, int level, int name, uchar_t *ptr)
{
	int		*i1 = (int *)ptr;
	tcp_t		*tcp = connp->conn_tcp;
	ip6_pkt_t	*ipp = &tcp->tcp_sticky_ipp;

	switch (level) {
	case SOL_SOCKET:
		switch (name) {
		case SO_LINGER:	{
			struct linger *lgr = (struct linger *)ptr;

			lgr->l_onoff = tcp->tcp_linger ? SO_LINGER : 0;
			lgr->l_linger = tcp->tcp_lingertime;
			}
			return (sizeof (struct linger));
		case SO_DEBUG:
			*i1 = tcp->tcp_debug ? SO_DEBUG : 0;
			break;
		case SO_KEEPALIVE:
			*i1 = tcp->tcp_ka_enabled ? SO_KEEPALIVE : 0;
			break;
		case SO_DONTROUTE:
			*i1 = tcp->tcp_dontroute ? SO_DONTROUTE : 0;
			break;
		case SO_USELOOPBACK:
			*i1 = tcp->tcp_useloopback ? SO_USELOOPBACK : 0;
			break;
		case SO_BROADCAST:
			*i1 = tcp->tcp_broadcast ? SO_BROADCAST : 0;
			break;
		case SO_REUSEADDR:
			*i1 = tcp->tcp_reuseaddr ? SO_REUSEADDR : 0;
			break;
		case SO_OOBINLINE:
			*i1 = tcp->tcp_oobinline ? SO_OOBINLINE : 0;
			break;
		case SO_DGRAM_ERRIND:
			*i1 = tcp->tcp_dgram_errind ? SO_DGRAM_ERRIND : 0;
			break;
		case SO_TYPE:
			*i1 = SOCK_STREAM;
			break;
		case SO_SNDBUF:
			*i1 = tcp->tcp_xmit_hiwater;
			break;
		case SO_RCVBUF:
			*i1 = tcp->tcp_recv_hiwater;
			break;
		case SO_SND_COPYAVOID:
			*i1 = tcp->tcp_snd_zcopy_on ?
			    SO_SND_COPYAVOID : 0;
			break;
		case SO_ALLZONES:
			*i1 = connp->conn_allzones ? 1 : 0;
			break;
		case SO_ANON_MLP:
			*i1 = connp->conn_anon_mlp;
			break;
		case SO_MAC_EXEMPT:
			*i1 = connp->conn_mac_exempt;
			break;
		case SO_EXCLBIND:
			*i1 = tcp->tcp_exclbind ? SO_EXCLBIND : 0;
			break;
		case SO_PROTOTYPE:
			*i1 = IPPROTO_TCP;
			break;
		case SO_DOMAIN:
			*i1 = tcp->tcp_family;
			break;
		case SO_ACCEPTCONN:
			*i1 = (tcp->tcp_state == TCPS_LISTEN);
		default:
			return (-1);
		}
		break;
	case IPPROTO_TCP:
		switch (name) {
		case TCP_NODELAY:
			*i1 = (tcp->tcp_naglim == 1) ? TCP_NODELAY : 0;
			break;
		case TCP_MAXSEG:
			*i1 = tcp->tcp_mss;
			break;
		case TCP_NOTIFY_THRESHOLD:
			*i1 = (int)tcp->tcp_first_timer_threshold;
			break;
		case TCP_ABORT_THRESHOLD:
			*i1 = tcp->tcp_second_timer_threshold;
			break;
		case TCP_CONN_NOTIFY_THRESHOLD:
			*i1 = tcp->tcp_first_ctimer_threshold;
			break;
		case TCP_CONN_ABORT_THRESHOLD:
			*i1 = tcp->tcp_second_ctimer_threshold;
			break;
		case TCP_RECVDSTADDR:
			*i1 = tcp->tcp_recvdstaddr;
			break;
		case TCP_ANONPRIVBIND:
			*i1 = tcp->tcp_anon_priv_bind;
			break;
		case TCP_EXCLBIND:
			*i1 = tcp->tcp_exclbind ? TCP_EXCLBIND : 0;
			break;
		case TCP_INIT_CWND:
			*i1 = tcp->tcp_init_cwnd;
			break;
		case TCP_KEEPALIVE_THRESHOLD:
			*i1 = tcp->tcp_ka_interval;
			break;
		case TCP_KEEPALIVE_ABORT_THRESHOLD:
			*i1 = tcp->tcp_ka_abort_thres;
			break;
		case TCP_CORK:
			*i1 = tcp->tcp_cork;
			break;
		default:
			return (-1);
		}
		break;
	case IPPROTO_IP:
		if (tcp->tcp_family != AF_INET)
			return (-1);
		switch (name) {
		case IP_OPTIONS:
		case T_IP_OPTIONS: {
			/*
			 * This is compatible with BSD in that in only return
			 * the reverse source route with the final destination
			 * as the last entry. The first 4 bytes of the option
			 * will contain the final destination.
			 */
			int	opt_len;

			opt_len = (char *)tcp->tcp_tcph - (char *)tcp->tcp_ipha;
			opt_len -= tcp->tcp_label_len + IP_SIMPLE_HDR_LENGTH;
			ASSERT(opt_len >= 0);
			/* Caller ensures enough space */
			if (opt_len > 0) {
				/*
				 * TODO: Do we have to handle getsockopt on an
				 * initiator as well?
				 */
				return (ip_opt_get_user(tcp->tcp_ipha, ptr));
			}
			return (0);
			}
		case IP_TOS:
		case T_IP_TOS:
			*i1 = (int)tcp->tcp_ipha->ipha_type_of_service;
			break;
		case IP_TTL:
			*i1 = (int)tcp->tcp_ipha->ipha_ttl;
			break;
		case IP_NEXTHOP:
			/* Handled at IP level */
			return (-EINVAL);
		default:
			return (-1);
		}
		break;
	case IPPROTO_IPV6:
		/*
		 * IPPROTO_IPV6 options are only supported for sockets
		 * that are using IPv6 on the wire.
		 */
		if (tcp->tcp_ipversion != IPV6_VERSION) {
			return (-1);
		}
		switch (name) {
		case IPV6_UNICAST_HOPS:
			*i1 = (unsigned int) tcp->tcp_ip6h->ip6_hops;
			break;	/* goto sizeof (int) option return */
		case IPV6_BOUND_IF:
			/* Zero if not set */
			*i1 = tcp->tcp_bound_if;
			break;	/* goto sizeof (int) option return */
		case IPV6_RECVPKTINFO:
			if (tcp->tcp_ipv6_recvancillary & TCP_IPV6_RECVPKTINFO)
				*i1 = 1;
			else
				*i1 = 0;
			break;	/* goto sizeof (int) option return */
		case IPV6_RECVTCLASS:
			if (tcp->tcp_ipv6_recvancillary & TCP_IPV6_RECVTCLASS)
				*i1 = 1;
			else
				*i1 = 0;
			break;	/* goto sizeof (int) option return */
		case IPV6_RECVHOPLIMIT:
			if (tcp->tcp_ipv6_recvancillary &
			    TCP_IPV6_RECVHOPLIMIT)
				*i1 = 1;
			else
				*i1 = 0;
			break;	/* goto sizeof (int) option return */
		case IPV6_RECVHOPOPTS:
			if (tcp->tcp_ipv6_recvancillary & TCP_IPV6_RECVHOPOPTS)
				*i1 = 1;
			else
				*i1 = 0;
			break;	/* goto sizeof (int) option return */
		case IPV6_RECVDSTOPTS:
			if (tcp->tcp_ipv6_recvancillary & TCP_IPV6_RECVDSTOPTS)
				*i1 = 1;
			else
				*i1 = 0;
			break;	/* goto sizeof (int) option return */
		case _OLD_IPV6_RECVDSTOPTS:
			if (tcp->tcp_ipv6_recvancillary &
			    TCP_OLD_IPV6_RECVDSTOPTS)
				*i1 = 1;
			else
				*i1 = 0;
			break;	/* goto sizeof (int) option return */
		case IPV6_RECVRTHDR:
			if (tcp->tcp_ipv6_recvancillary & TCP_IPV6_RECVRTHDR)
				*i1 = 1;
			else
				*i1 = 0;
			break;	/* goto sizeof (int) option return */
		case IPV6_RECVRTHDRDSTOPTS:
			if (tcp->tcp_ipv6_recvancillary &
			    TCP_IPV6_RECVRTDSTOPTS)
				*i1 = 1;
			else
				*i1 = 0;
			break;	/* goto sizeof (int) option return */
		case IPV6_PKTINFO: {
			/* XXX assumes that caller has room for max size! */
			struct in6_pktinfo *pkti;

			pkti = (struct in6_pktinfo *)ptr;
			if (ipp->ipp_fields & IPPF_IFINDEX)
				pkti->ipi6_ifindex = ipp->ipp_ifindex;
			else
				pkti->ipi6_ifindex = 0;
			if (ipp->ipp_fields & IPPF_ADDR)
				pkti->ipi6_addr = ipp->ipp_addr;
			else
				pkti->ipi6_addr = ipv6_all_zeros;
			return (sizeof (struct in6_pktinfo));
		}
		case IPV6_TCLASS:
			if (ipp->ipp_fields & IPPF_TCLASS)
				*i1 = ipp->ipp_tclass;
			else
				*i1 = IPV6_FLOW_TCLASS(
				    IPV6_DEFAULT_VERS_AND_FLOW);
			break;	/* goto sizeof (int) option return */
		case IPV6_NEXTHOP: {
			sin6_t *sin6 = (sin6_t *)ptr;

			if (!(ipp->ipp_fields & IPPF_NEXTHOP))
				return (0);
			*sin6 = sin6_null;
			sin6->sin6_family = AF_INET6;
			sin6->sin6_addr = ipp->ipp_nexthop;
			return (sizeof (sin6_t));
		}
		case IPV6_HOPOPTS:
			if (!(ipp->ipp_fields & IPPF_HOPOPTS))
				return (0);
			if (ipp->ipp_hopoptslen <= tcp->tcp_label_len)
				return (0);
			bcopy((char *)ipp->ipp_hopopts + tcp->tcp_label_len,
			    ptr, ipp->ipp_hopoptslen - tcp->tcp_label_len);
			if (tcp->tcp_label_len > 0) {
				ptr[0] = ((char *)ipp->ipp_hopopts)[0];
				ptr[1] = (ipp->ipp_hopoptslen -
				    tcp->tcp_label_len + 7) / 8 - 1;
			}
			return (ipp->ipp_hopoptslen - tcp->tcp_label_len);
		case IPV6_RTHDRDSTOPTS:
			if (!(ipp->ipp_fields & IPPF_RTDSTOPTS))
				return (0);
			bcopy(ipp->ipp_rtdstopts, ptr, ipp->ipp_rtdstoptslen);
			return (ipp->ipp_rtdstoptslen);
		case IPV6_RTHDR:
			if (!(ipp->ipp_fields & IPPF_RTHDR))
				return (0);
			bcopy(ipp->ipp_rthdr, ptr, ipp->ipp_rthdrlen);
			return (ipp->ipp_rthdrlen);
		case IPV6_DSTOPTS:
			if (!(ipp->ipp_fields & IPPF_DSTOPTS))
				return (0);
			bcopy(ipp->ipp_dstopts, ptr, ipp->ipp_dstoptslen);
			return (ipp->ipp_dstoptslen);
		case IPV6_SRC_PREFERENCES:
			return (ip6_get_src_preferences(connp,
			    (uint32_t *)ptr));
		case IPV6_PATHMTU: {
			struct ip6_mtuinfo *mtuinfo = (struct ip6_mtuinfo *)ptr;

			if (tcp->tcp_state < TCPS_ESTABLISHED)
				return (-1);

			return (ip_fill_mtuinfo(&connp->conn_remv6,
			    connp->conn_fport, mtuinfo,
			    connp->conn_netstack));
		}
		default:
			return (-1);
		}
		break;
	default:
		return (-1);
	}
	return (sizeof (int));
}

/*
 * TCP routine to get the values of options.
 */
int
tcp_tpi_opt_get(queue_t *q, int level, int name, uchar_t *ptr)
{
	return (tcp_opt_get(Q_TO_CONN(q), level, name, ptr));
}

/* returns UNIX error, the optlen is a value-result arg */
int
tcp_getsockopt(sock_lower_handle_t proto_handle, int level, int option_name,
    void *optvalp, socklen_t *optlen, cred_t *cr)
{
	conn_t		*connp = (conn_t *)proto_handle;
	squeue_t	*sqp = connp->conn_sqp;
	int		error;
	t_uscalar_t	max_optbuf_len;
	void		*optvalp_buf;
	int		len;

	error = proto_opt_check(level, option_name, *optlen, &max_optbuf_len,
	    tcp_opt_obj.odb_opt_des_arr,
	    tcp_opt_obj.odb_opt_arr_cnt,
	    tcp_opt_obj.odb_topmost_tpiprovider,
	    B_FALSE, B_TRUE, cr);
	if (error != 0) {
		if (error < 0) {
			error = proto_tlitosyserr(-error);
		}
		return (error);
	}

	optvalp_buf = kmem_alloc(max_optbuf_len, KM_SLEEP);

	error = squeue_synch_enter(sqp, connp, 0);
	if (error == ENOMEM) {
		return (ENOMEM);
	}

	len = tcp_opt_get(connp, level, option_name, optvalp_buf);
	squeue_synch_exit(sqp, connp);

	if (len < 0) {
		/*
		 * Pass on to IP
		 */
		kmem_free(optvalp_buf, max_optbuf_len);
		return (ip_get_options(connp, level, option_name,
		    optvalp, optlen, cr));
	} else {
		/*
		 * update optlen and copy option value
		 */
		t_uscalar_t size = MIN(len, *optlen);
		bcopy(optvalp_buf, optvalp, size);
		bcopy(&size, optlen, sizeof (size));

		kmem_free(optvalp_buf, max_optbuf_len);
		return (0);
	}
}

/*
 * We declare as 'int' rather than 'void' to satisfy pfi_t arg requirements.
 * Parameters are assumed to be verified by the caller.
 */
/* ARGSUSED */
int
tcp_opt_set(conn_t *connp, uint_t optset_context, int level, int name,
    uint_t inlen, uchar_t *invalp, uint_t *outlenp, uchar_t *outvalp,
    void *thisdg_attrs, cred_t *cr, mblk_t *mblk)
{
	tcp_t	*tcp = connp->conn_tcp;
	int	*i1 = (int *)invalp;
	boolean_t onoff = (*i1 == 0) ? 0 : 1;
	boolean_t checkonly;
	int	reterr;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	switch (optset_context) {
	case SETFN_OPTCOM_CHECKONLY:
		checkonly = B_TRUE;
		/*
		 * Note: Implies T_CHECK semantics for T_OPTCOM_REQ
		 * inlen != 0 implies value supplied and
		 * 	we have to "pretend" to set it.
		 * inlen == 0 implies that there is no
		 * 	value part in T_CHECK request and just validation
		 * done elsewhere should be enough, we just return here.
		 */
		if (inlen == 0) {
			*outlenp = 0;
			return (0);
		}
		break;
	case SETFN_OPTCOM_NEGOTIATE:
		checkonly = B_FALSE;
		break;
	case SETFN_UD_NEGOTIATE: /* error on conn-oriented transports ? */
	case SETFN_CONN_NEGOTIATE:
		checkonly = B_FALSE;
		/*
		 * Negotiating local and "association-related" options
		 * from other (T_CONN_REQ, T_CONN_RES,T_UNITDATA_REQ)
		 * primitives is allowed by XTI, but we choose
		 * to not implement this style negotiation for Internet
		 * protocols (We interpret it is a must for OSI world but
		 * optional for Internet protocols) for all options.
		 * [ Will do only for the few options that enable test
		 * suites that our XTI implementation of this feature
		 * works for transports that do allow it ]
		 */
		if (!tcp_allow_connopt_set(level, name)) {
			*outlenp = 0;
			return (EINVAL);
		}
		break;
	default:
		/*
		 * We should never get here
		 */
		*outlenp = 0;
		return (EINVAL);
	}

	ASSERT((optset_context != SETFN_OPTCOM_CHECKONLY) ||
	    (optset_context == SETFN_OPTCOM_CHECKONLY && inlen != 0));

	/*
	 * For TCP, we should have no ancillary data sent down
	 * (sendmsg isn't supported for SOCK_STREAM), so thisdg_attrs
	 * has to be zero.
	 */
	ASSERT(thisdg_attrs == NULL);

	/*
	 * For fixed length options, no sanity check
	 * of passed in length is done. It is assumed *_optcom_req()
	 * routines do the right thing.
	 */
	switch (level) {
	case SOL_SOCKET:
		switch (name) {
		case SO_LINGER: {
			struct linger *lgr = (struct linger *)invalp;

			if (!checkonly) {
				if (lgr->l_onoff) {
					tcp->tcp_linger = 1;
					tcp->tcp_lingertime = lgr->l_linger;
				} else {
					tcp->tcp_linger = 0;
					tcp->tcp_lingertime = 0;
				}
				/* struct copy */
				*(struct linger *)outvalp = *lgr;
			} else {
				if (!lgr->l_onoff) {
					((struct linger *)
					    outvalp)->l_onoff = 0;
					((struct linger *)
					    outvalp)->l_linger = 0;
				} else {
					/* struct copy */
					*(struct linger *)outvalp = *lgr;
				}
			}
			*outlenp = sizeof (struct linger);
			return (0);
		}
		case SO_DEBUG:
			if (!checkonly)
				tcp->tcp_debug = onoff;
			break;
		case SO_KEEPALIVE:
			if (checkonly) {
				/* check only case */
				break;
			}

			if (!onoff) {
				if (tcp->tcp_ka_enabled) {
					if (tcp->tcp_ka_tid != 0) {
						(void) TCP_TIMER_CANCEL(tcp,
						    tcp->tcp_ka_tid);
						tcp->tcp_ka_tid = 0;
					}
					tcp->tcp_ka_enabled = 0;
				}
				break;
			}
			if (!tcp->tcp_ka_enabled) {
				/* Crank up the keepalive timer */
				tcp->tcp_ka_last_intrvl = 0;
				tcp->tcp_ka_tid = TCP_TIMER(tcp,
				    tcp_keepalive_killer,
				    MSEC_TO_TICK(tcp->tcp_ka_interval));
				tcp->tcp_ka_enabled = 1;
			}
			break;
		case SO_DONTROUTE:
			/*
			 * SO_DONTROUTE, SO_USELOOPBACK, and SO_BROADCAST are
			 * only of interest to IP.  We track them here only so
			 * that we can report their current value.
			 */
			if (!checkonly) {
				tcp->tcp_dontroute = onoff;
				tcp->tcp_connp->conn_dontroute = onoff;
			}
			break;
		case SO_USELOOPBACK:
			if (!checkonly) {
				tcp->tcp_useloopback = onoff;
				tcp->tcp_connp->conn_loopback = onoff;
			}
			break;
		case SO_BROADCAST:
			if (!checkonly) {
				tcp->tcp_broadcast = onoff;
				tcp->tcp_connp->conn_broadcast = onoff;
			}
			break;
		case SO_REUSEADDR:
			if (!checkonly) {
				tcp->tcp_reuseaddr = onoff;
				tcp->tcp_connp->conn_reuseaddr = onoff;
			}
			break;
		case SO_OOBINLINE:
			if (!checkonly) {
				tcp->tcp_oobinline = onoff;
				if (IPCL_IS_NONSTR(tcp->tcp_connp))
					proto_set_rx_oob_opt(connp, onoff);
			}
			break;
		case SO_DGRAM_ERRIND:
			if (!checkonly)
				tcp->tcp_dgram_errind = onoff;
			break;
		case SO_SNDBUF: {
			if (*i1 > tcps->tcps_max_buf) {
				*outlenp = 0;
				return (ENOBUFS);
			}
			if (checkonly)
				break;

			tcp->tcp_xmit_hiwater = *i1;
			if (tcps->tcps_snd_lowat_fraction != 0)
				tcp->tcp_xmit_lowater =
				    tcp->tcp_xmit_hiwater /
				    tcps->tcps_snd_lowat_fraction;
			(void) tcp_maxpsz_set(tcp, B_TRUE);
			/*
			 * If we are flow-controlled, recheck the condition.
			 * There are apps that increase SO_SNDBUF size when
			 * flow-controlled (EWOULDBLOCK), and expect the flow
			 * control condition to be lifted right away.
			 */
			mutex_enter(&tcp->tcp_non_sq_lock);
			if (tcp->tcp_flow_stopped &&
			    TCP_UNSENT_BYTES(tcp) < tcp->tcp_xmit_hiwater) {
				tcp_clrqfull(tcp);
			}
			mutex_exit(&tcp->tcp_non_sq_lock);
			break;
		}
		case SO_RCVBUF:
			if (*i1 > tcps->tcps_max_buf) {
				*outlenp = 0;
				return (ENOBUFS);
			}
			/* Silently ignore zero */
			if (!checkonly && *i1 != 0) {
				*i1 = MSS_ROUNDUP(*i1, tcp->tcp_mss);
				(void) tcp_rwnd_set(tcp, *i1);
			}
			/*
			 * XXX should we return the rwnd here
			 * and tcp_opt_get ?
			 */
			break;
		case SO_SND_COPYAVOID:
			if (!checkonly) {
				/* we only allow enable at most once for now */
				if (tcp->tcp_loopback ||
				    (tcp->tcp_kssl_ctx != NULL) ||
				    (!tcp->tcp_snd_zcopy_aware &&
				    (onoff != 1 || !tcp_zcopy_check(tcp)))) {
					*outlenp = 0;
					return (EOPNOTSUPP);
				}
				tcp->tcp_snd_zcopy_aware = 1;
			}
			break;
		case SO_ALLZONES:
			/* Pass option along to IP level for handling */
			return (-EINVAL);
		case SO_ANON_MLP:
			/* Pass option along to IP level for handling */
			return (-EINVAL);
		case SO_MAC_EXEMPT:
			/* Pass option along to IP level for handling */
			return (-EINVAL);
		case SO_EXCLBIND:
			if (!checkonly)
				tcp->tcp_exclbind = onoff;
			break;
		default:
			*outlenp = 0;
			return (EINVAL);
		}
		break;
	case IPPROTO_TCP:
		switch (name) {
		case TCP_NODELAY:
			if (!checkonly)
				tcp->tcp_naglim = *i1 ? 1 : tcp->tcp_mss;
			break;
		case TCP_NOTIFY_THRESHOLD:
			if (!checkonly)
				tcp->tcp_first_timer_threshold = *i1;
			break;
		case TCP_ABORT_THRESHOLD:
			if (!checkonly)
				tcp->tcp_second_timer_threshold = *i1;
			break;
		case TCP_CONN_NOTIFY_THRESHOLD:
			if (!checkonly)
				tcp->tcp_first_ctimer_threshold = *i1;
			break;
		case TCP_CONN_ABORT_THRESHOLD:
			if (!checkonly)
				tcp->tcp_second_ctimer_threshold = *i1;
			break;
		case TCP_RECVDSTADDR:
			if (tcp->tcp_state > TCPS_LISTEN)
				return (EOPNOTSUPP);
			if (!checkonly)
				tcp->tcp_recvdstaddr = onoff;
			break;
		case TCP_ANONPRIVBIND:
			if ((reterr = secpolicy_net_privaddr(cr, 0,
			    IPPROTO_TCP)) != 0) {
				*outlenp = 0;
				return (reterr);
			}
			if (!checkonly) {
				tcp->tcp_anon_priv_bind = onoff;
			}
			break;
		case TCP_EXCLBIND:
			if (!checkonly)
				tcp->tcp_exclbind = onoff;
			break;	/* goto sizeof (int) option return */
		case TCP_INIT_CWND: {
			uint32_t init_cwnd = *((uint32_t *)invalp);

			if (checkonly)
				break;

			/*
			 * Only allow socket with network configuration
			 * privilege to set the initial cwnd to be larger
			 * than allowed by RFC 3390.
			 */
			if (init_cwnd <= MIN(4, MAX(2, 4380 / tcp->tcp_mss))) {
				tcp->tcp_init_cwnd = init_cwnd;
				break;
			}
			if ((reterr = secpolicy_ip_config(cr, B_TRUE)) != 0) {
				*outlenp = 0;
				return (reterr);
			}
			if (init_cwnd > TCP_MAX_INIT_CWND) {
				*outlenp = 0;
				return (EINVAL);
			}
			tcp->tcp_init_cwnd = init_cwnd;
			break;
		}
		case TCP_KEEPALIVE_THRESHOLD:
			if (checkonly)
				break;

			if (*i1 < tcps->tcps_keepalive_interval_low ||
			    *i1 > tcps->tcps_keepalive_interval_high) {
				*outlenp = 0;
				return (EINVAL);
			}
			if (*i1 != tcp->tcp_ka_interval) {
				tcp->tcp_ka_interval = *i1;
				/*
				 * Check if we need to restart the
				 * keepalive timer.
				 */
				if (tcp->tcp_ka_tid != 0) {
					ASSERT(tcp->tcp_ka_enabled);
					(void) TCP_TIMER_CANCEL(tcp,
					    tcp->tcp_ka_tid);
					tcp->tcp_ka_last_intrvl = 0;
					tcp->tcp_ka_tid = TCP_TIMER(tcp,
					    tcp_keepalive_killer,
					    MSEC_TO_TICK(tcp->tcp_ka_interval));
				}
			}
			break;
		case TCP_KEEPALIVE_ABORT_THRESHOLD:
			if (!checkonly) {
				if (*i1 <
				    tcps->tcps_keepalive_abort_interval_low ||
				    *i1 >
				    tcps->tcps_keepalive_abort_interval_high) {
					*outlenp = 0;
					return (EINVAL);
				}
				tcp->tcp_ka_abort_thres = *i1;
			}
			break;
		case TCP_CORK:
			if (!checkonly) {
				/*
				 * if tcp->tcp_cork was set and is now
				 * being unset, we have to make sure that
				 * the remaining data gets sent out. Also
				 * unset tcp->tcp_cork so that tcp_wput_data()
				 * can send data even if it is less than mss
				 */
				if (tcp->tcp_cork && onoff == 0 &&
				    tcp->tcp_unsent > 0) {
					tcp->tcp_cork = B_FALSE;
					tcp_wput_data(tcp, NULL, B_FALSE);
				}
				tcp->tcp_cork = onoff;
			}
			break;
		default:
			*outlenp = 0;
			return (EINVAL);
		}
		break;
	case IPPROTO_IP:
		if (tcp->tcp_family != AF_INET) {
			*outlenp = 0;
			return (ENOPROTOOPT);
		}
		switch (name) {
		case IP_OPTIONS:
		case T_IP_OPTIONS:
			reterr = tcp_opt_set_header(tcp, checkonly,
			    invalp, inlen);
			if (reterr) {
				*outlenp = 0;
				return (reterr);
			}
			/* OK return - copy input buffer into output buffer */
			if (invalp != outvalp) {
				/* don't trust bcopy for identical src/dst */
				bcopy(invalp, outvalp, inlen);
			}
			*outlenp = inlen;
			return (0);
		case IP_TOS:
		case T_IP_TOS:
			if (!checkonly) {
				tcp->tcp_ipha->ipha_type_of_service =
				    (uchar_t)*i1;
				tcp->tcp_tos = (uchar_t)*i1;
			}
			break;
		case IP_TTL:
			if (!checkonly) {
				tcp->tcp_ipha->ipha_ttl = (uchar_t)*i1;
				tcp->tcp_ttl = (uchar_t)*i1;
			}
			break;
		case IP_BOUND_IF:
		case IP_NEXTHOP:
			/* Handled at the IP level */
			return (-EINVAL);
		case IP_SEC_OPT:
			/*
			 * We should not allow policy setting after
			 * we start listening for connections.
			 */
			if (tcp->tcp_state == TCPS_LISTEN) {
				return (EINVAL);
			} else {
				/* Handled at the IP level */
				return (-EINVAL);
			}
		default:
			*outlenp = 0;
			return (EINVAL);
		}
		break;
	case IPPROTO_IPV6: {
		ip6_pkt_t		*ipp;

		/*
		 * IPPROTO_IPV6 options are only supported for sockets
		 * that are using IPv6 on the wire.
		 */
		if (tcp->tcp_ipversion != IPV6_VERSION) {
			*outlenp = 0;
			return (ENOPROTOOPT);
		}
		/*
		 * Only sticky options; no ancillary data
		 */
		ipp = &tcp->tcp_sticky_ipp;

		switch (name) {
		case IPV6_UNICAST_HOPS:
			/* -1 means use default */
			if (*i1 < -1 || *i1 > IPV6_MAX_HOPS) {
				*outlenp = 0;
				return (EINVAL);
			}
			if (!checkonly) {
				if (*i1 == -1) {
					tcp->tcp_ip6h->ip6_hops =
					    ipp->ipp_unicast_hops =
					    (uint8_t)tcps->tcps_ipv6_hoplimit;
					ipp->ipp_fields &= ~IPPF_UNICAST_HOPS;
					/* Pass modified value to IP. */
					*i1 = tcp->tcp_ip6h->ip6_hops;
				} else {
					tcp->tcp_ip6h->ip6_hops =
					    ipp->ipp_unicast_hops =
					    (uint8_t)*i1;
					ipp->ipp_fields |= IPPF_UNICAST_HOPS;
				}
				reterr = tcp_build_hdrs(tcp);
				if (reterr != 0)
					return (reterr);
			}
			break;
		case IPV6_BOUND_IF:
			if (!checkonly) {
				tcp->tcp_bound_if = *i1;
				PASS_OPT_TO_IP(connp);
			}
			break;
		/*
		 * Set boolean switches for ancillary data delivery
		 */
		case IPV6_RECVPKTINFO:
			if (!checkonly) {
				if (onoff)
					tcp->tcp_ipv6_recvancillary |=
					    TCP_IPV6_RECVPKTINFO;
				else
					tcp->tcp_ipv6_recvancillary &=
					    ~TCP_IPV6_RECVPKTINFO;
				/* Force it to be sent up with the next msg */
				tcp->tcp_recvifindex = 0;
				PASS_OPT_TO_IP(connp);
			}
			break;
		case IPV6_RECVTCLASS:
			if (!checkonly) {
				if (onoff)
					tcp->tcp_ipv6_recvancillary |=
					    TCP_IPV6_RECVTCLASS;
				else
					tcp->tcp_ipv6_recvancillary &=
					    ~TCP_IPV6_RECVTCLASS;
				PASS_OPT_TO_IP(connp);
			}
			break;
		case IPV6_RECVHOPLIMIT:
			if (!checkonly) {
				if (onoff)
					tcp->tcp_ipv6_recvancillary |=
					    TCP_IPV6_RECVHOPLIMIT;
				else
					tcp->tcp_ipv6_recvancillary &=
					    ~TCP_IPV6_RECVHOPLIMIT;
				/* Force it to be sent up with the next msg */
				tcp->tcp_recvhops = 0xffffffffU;
				PASS_OPT_TO_IP(connp);
			}
			break;
		case IPV6_RECVHOPOPTS:
			if (!checkonly) {
				if (onoff)
					tcp->tcp_ipv6_recvancillary |=
					    TCP_IPV6_RECVHOPOPTS;
				else
					tcp->tcp_ipv6_recvancillary &=
					    ~TCP_IPV6_RECVHOPOPTS;
				PASS_OPT_TO_IP(connp);
			}
			break;
		case IPV6_RECVDSTOPTS:
			if (!checkonly) {
				if (onoff)
					tcp->tcp_ipv6_recvancillary |=
					    TCP_IPV6_RECVDSTOPTS;
				else
					tcp->tcp_ipv6_recvancillary &=
					    ~TCP_IPV6_RECVDSTOPTS;
				PASS_OPT_TO_IP(connp);
			}
			break;
		case _OLD_IPV6_RECVDSTOPTS:
			if (!checkonly) {
				if (onoff)
					tcp->tcp_ipv6_recvancillary |=
					    TCP_OLD_IPV6_RECVDSTOPTS;
				else
					tcp->tcp_ipv6_recvancillary &=
					    ~TCP_OLD_IPV6_RECVDSTOPTS;
			}
			break;
		case IPV6_RECVRTHDR:
			if (!checkonly) {
				if (onoff)
					tcp->tcp_ipv6_recvancillary |=
					    TCP_IPV6_RECVRTHDR;
				else
					tcp->tcp_ipv6_recvancillary &=
					    ~TCP_IPV6_RECVRTHDR;
				PASS_OPT_TO_IP(connp);
			}
			break;
		case IPV6_RECVRTHDRDSTOPTS:
			if (!checkonly) {
				if (onoff)
					tcp->tcp_ipv6_recvancillary |=
					    TCP_IPV6_RECVRTDSTOPTS;
				else
					tcp->tcp_ipv6_recvancillary &=
					    ~TCP_IPV6_RECVRTDSTOPTS;
				PASS_OPT_TO_IP(connp);
			}
			break;
		case IPV6_PKTINFO:
			if (inlen != 0 && inlen != sizeof (struct in6_pktinfo))
				return (EINVAL);
			if (checkonly)
				break;

			if (inlen == 0) {
				ipp->ipp_fields &= ~(IPPF_IFINDEX|IPPF_ADDR);
			} else {
				struct in6_pktinfo *pkti;

				pkti = (struct in6_pktinfo *)invalp;
				/*
				 * RFC 3542 states that ipi6_addr must be
				 * the unspecified address when setting the
				 * IPV6_PKTINFO sticky socket option on a
				 * TCP socket.
				 */
				if (!IN6_IS_ADDR_UNSPECIFIED(&pkti->ipi6_addr))
					return (EINVAL);
				/*
				 * IP will validate the source address and
				 * interface index.
				 */
				if (IPCL_IS_NONSTR(tcp->tcp_connp)) {
					reterr = ip_set_options(tcp->tcp_connp,
					    level, name, invalp, inlen, cr);
				} else {
					reterr = ip6_set_pktinfo(cr,
					    tcp->tcp_connp, pkti, mblk);
				}
				if (reterr != 0)
					return (reterr);
				ipp->ipp_ifindex = pkti->ipi6_ifindex;
				ipp->ipp_addr = pkti->ipi6_addr;
				if (ipp->ipp_ifindex != 0)
					ipp->ipp_fields |= IPPF_IFINDEX;
				else
					ipp->ipp_fields &= ~IPPF_IFINDEX;
				if (!IN6_IS_ADDR_UNSPECIFIED(&ipp->ipp_addr))
					ipp->ipp_fields |= IPPF_ADDR;
				else
					ipp->ipp_fields &= ~IPPF_ADDR;
			}
			reterr = tcp_build_hdrs(tcp);
			if (reterr != 0)
				return (reterr);
			break;
		case IPV6_TCLASS:
			if (inlen != 0 && inlen != sizeof (int))
				return (EINVAL);
			if (checkonly)
				break;

			if (inlen == 0) {
				ipp->ipp_fields &= ~IPPF_TCLASS;
			} else {
				if (*i1 > 255 || *i1 < -1)
					return (EINVAL);
				if (*i1 == -1) {
					ipp->ipp_tclass = 0;
					*i1 = 0;
				} else {
					ipp->ipp_tclass = *i1;
				}
				ipp->ipp_fields |= IPPF_TCLASS;
			}
			reterr = tcp_build_hdrs(tcp);
			if (reterr != 0)
				return (reterr);
			break;
		case IPV6_NEXTHOP:
			/*
			 * IP will verify that the nexthop is reachable
			 * and fail for sticky options.
			 */
			if (inlen != 0 && inlen != sizeof (sin6_t))
				return (EINVAL);
			if (checkonly)
				break;

			if (inlen == 0) {
				ipp->ipp_fields &= ~IPPF_NEXTHOP;
			} else {
				sin6_t *sin6 = (sin6_t *)invalp;

				if (sin6->sin6_family != AF_INET6)
					return (EAFNOSUPPORT);
				if (IN6_IS_ADDR_V4MAPPED(
				    &sin6->sin6_addr))
					return (EADDRNOTAVAIL);
				ipp->ipp_nexthop = sin6->sin6_addr;
				if (!IN6_IS_ADDR_UNSPECIFIED(
				    &ipp->ipp_nexthop))
					ipp->ipp_fields |= IPPF_NEXTHOP;
				else
					ipp->ipp_fields &= ~IPPF_NEXTHOP;
			}
			reterr = tcp_build_hdrs(tcp);
			if (reterr != 0)
				return (reterr);
			PASS_OPT_TO_IP(connp);
			break;
		case IPV6_HOPOPTS: {
			ip6_hbh_t *hopts = (ip6_hbh_t *)invalp;

			/*
			 * Sanity checks - minimum size, size a multiple of
			 * eight bytes, and matching size passed in.
			 */
			if (inlen != 0 &&
			    inlen != (8 * (hopts->ip6h_len + 1)))
				return (EINVAL);

			if (checkonly)
				break;

			reterr = optcom_pkt_set(invalp, inlen, B_TRUE,
			    (uchar_t **)&ipp->ipp_hopopts,
			    &ipp->ipp_hopoptslen, tcp->tcp_label_len);
			if (reterr != 0)
				return (reterr);
			if (ipp->ipp_hopoptslen == 0)
				ipp->ipp_fields &= ~IPPF_HOPOPTS;
			else
				ipp->ipp_fields |= IPPF_HOPOPTS;
			reterr = tcp_build_hdrs(tcp);
			if (reterr != 0)
				return (reterr);
			break;
		}
		case IPV6_RTHDRDSTOPTS: {
			ip6_dest_t *dopts = (ip6_dest_t *)invalp;

			/*
			 * Sanity checks - minimum size, size a multiple of
			 * eight bytes, and matching size passed in.
			 */
			if (inlen != 0 &&
			    inlen != (8 * (dopts->ip6d_len + 1)))
				return (EINVAL);

			if (checkonly)
				break;

			reterr = optcom_pkt_set(invalp, inlen, B_TRUE,
			    (uchar_t **)&ipp->ipp_rtdstopts,
			    &ipp->ipp_rtdstoptslen, 0);
			if (reterr != 0)
				return (reterr);
			if (ipp->ipp_rtdstoptslen == 0)
				ipp->ipp_fields &= ~IPPF_RTDSTOPTS;
			else
				ipp->ipp_fields |= IPPF_RTDSTOPTS;
			reterr = tcp_build_hdrs(tcp);
			if (reterr != 0)
				return (reterr);
			break;
		}
		case IPV6_DSTOPTS: {
			ip6_dest_t *dopts = (ip6_dest_t *)invalp;

			/*
			 * Sanity checks - minimum size, size a multiple of
			 * eight bytes, and matching size passed in.
			 */
			if (inlen != 0 &&
			    inlen != (8 * (dopts->ip6d_len + 1)))
				return (EINVAL);

			if (checkonly)
				break;

			reterr = optcom_pkt_set(invalp, inlen, B_TRUE,
			    (uchar_t **)&ipp->ipp_dstopts,
			    &ipp->ipp_dstoptslen, 0);
			if (reterr != 0)
				return (reterr);
			if (ipp->ipp_dstoptslen == 0)
				ipp->ipp_fields &= ~IPPF_DSTOPTS;
			else
				ipp->ipp_fields |= IPPF_DSTOPTS;
			reterr = tcp_build_hdrs(tcp);
			if (reterr != 0)
				return (reterr);
			break;
		}
		case IPV6_RTHDR: {
			ip6_rthdr_t *rt = (ip6_rthdr_t *)invalp;

			/*
			 * Sanity checks - minimum size, size a multiple of
			 * eight bytes, and matching size passed in.
			 */
			if (inlen != 0 &&
			    inlen != (8 * (rt->ip6r_len + 1)))
				return (EINVAL);

			if (checkonly)
				break;

			reterr = optcom_pkt_set(invalp, inlen, B_TRUE,
			    (uchar_t **)&ipp->ipp_rthdr,
			    &ipp->ipp_rthdrlen, 0);
			if (reterr != 0)
				return (reterr);
			if (ipp->ipp_rthdrlen == 0)
				ipp->ipp_fields &= ~IPPF_RTHDR;
			else
				ipp->ipp_fields |= IPPF_RTHDR;
			reterr = tcp_build_hdrs(tcp);
			if (reterr != 0)
				return (reterr);
			break;
		}
		case IPV6_V6ONLY:
			if (!checkonly) {
				tcp->tcp_connp->conn_ipv6_v6only = onoff;
			}
			break;
		case IPV6_USE_MIN_MTU:
			if (inlen != sizeof (int))
				return (EINVAL);

			if (*i1 < -1 || *i1 > 1)
				return (EINVAL);

			if (checkonly)
				break;

			ipp->ipp_fields |= IPPF_USE_MIN_MTU;
			ipp->ipp_use_min_mtu = *i1;
			break;
		case IPV6_SEC_OPT:
			/*
			 * We should not allow policy setting after
			 * we start listening for connections.
			 */
			if (tcp->tcp_state == TCPS_LISTEN) {
				return (EINVAL);
			} else {
				/* Handled at the IP level */
				return (-EINVAL);
			}
		case IPV6_SRC_PREFERENCES:
			if (inlen != sizeof (uint32_t))
				return (EINVAL);
			reterr = ip6_set_src_preferences(tcp->tcp_connp,
			    *(uint32_t *)invalp);
			if (reterr != 0) {
				*outlenp = 0;
				return (reterr);
			}
			break;
		default:
			*outlenp = 0;
			return (EINVAL);
		}
		break;
	}		/* end IPPROTO_IPV6 */
	default:
		*outlenp = 0;
		return (EINVAL);
	}
	/*
	 * Common case of OK return with outval same as inval
	 */
	if (invalp != outvalp) {
		/* don't trust bcopy for identical src/dst */
		(void) bcopy(invalp, outvalp, inlen);
	}
	*outlenp = inlen;
	return (0);
}

/* ARGSUSED */
int
tcp_tpi_opt_set(queue_t *q, uint_t optset_context, int level, int name,
    uint_t inlen, uchar_t *invalp, uint_t *outlenp, uchar_t *outvalp,
    void *thisdg_attrs, cred_t *cr, mblk_t *mblk)
{
	conn_t	*connp =  Q_TO_CONN(q);

	return (tcp_opt_set(connp, optset_context, level, name, inlen, invalp,
	    outlenp, outvalp, thisdg_attrs, cr, mblk));
}

int
tcp_setsockopt(sock_lower_handle_t proto_handle, int level, int option_name,
    const void *optvalp, socklen_t optlen, cred_t *cr)
{
	conn_t		*connp = (conn_t *)proto_handle;
	squeue_t	*sqp = connp->conn_sqp;
	int		error;

	/*
	 * Entering the squeue synchronously can result in a context switch,
	 * which can cause a rather sever performance degradation. So we try to
	 * handle whatever options we can without entering the squeue.
	 */
	if (level == IPPROTO_TCP) {
		switch (option_name) {
		case TCP_NODELAY:
			if (optlen != sizeof (int32_t))
				return (EINVAL);
			mutex_enter(&connp->conn_tcp->tcp_non_sq_lock);
			connp->conn_tcp->tcp_naglim = *(int *)optvalp ? 1 :
			    connp->conn_tcp->tcp_mss;
			mutex_exit(&connp->conn_tcp->tcp_non_sq_lock);
			return (0);
		default:
			break;
		}
	}

	error = squeue_synch_enter(sqp, connp, 0);
	if (error == ENOMEM) {
		return (ENOMEM);
	}

	error = proto_opt_check(level, option_name, optlen, NULL,
	    tcp_opt_obj.odb_opt_des_arr,
	    tcp_opt_obj.odb_opt_arr_cnt,
	    tcp_opt_obj.odb_topmost_tpiprovider,
	    B_TRUE, B_FALSE, cr);

	if (error != 0) {
		if (error < 0) {
			error = proto_tlitosyserr(-error);
		}
		squeue_synch_exit(sqp, connp);
		return (error);
	}

	error = tcp_opt_set(connp, SETFN_OPTCOM_NEGOTIATE, level, option_name,
	    optlen, (uchar_t *)optvalp, (uint_t *)&optlen, (uchar_t *)optvalp,
	    NULL, cr, NULL);
	squeue_synch_exit(sqp, connp);

	if (error < 0) {
		/*
		 * Pass on to ip
		 */
		error = ip_set_options(connp, level, option_name, optvalp,
		    optlen, cr);
	}
	return (error);
}

/*
 * Update tcp_sticky_hdrs based on tcp_sticky_ipp.
 * The headers include ip6i_t (if needed), ip6_t, any sticky extension
 * headers, and the maximum size tcp header (to avoid reallocation
 * on the fly for additional tcp options).
 * Returns failure if can't allocate memory.
 */
static int
tcp_build_hdrs(tcp_t *tcp)
{
	char	*hdrs;
	uint_t	hdrs_len;
	ip6i_t	*ip6i;
	char	buf[TCP_MAX_HDR_LENGTH];
	ip6_pkt_t *ipp = &tcp->tcp_sticky_ipp;
	in6_addr_t src, dst;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	conn_t *connp = tcp->tcp_connp;

	/*
	 * save the existing tcp header and source/dest IP addresses
	 */
	bcopy(tcp->tcp_tcph, buf, tcp->tcp_tcp_hdr_len);
	src = tcp->tcp_ip6h->ip6_src;
	dst = tcp->tcp_ip6h->ip6_dst;
	hdrs_len = ip_total_hdrs_len_v6(ipp) + TCP_MAX_HDR_LENGTH;
	ASSERT(hdrs_len != 0);
	if (hdrs_len > tcp->tcp_iphc_len) {
		/* Need to reallocate */
		hdrs = kmem_zalloc(hdrs_len, KM_NOSLEEP);
		if (hdrs == NULL)
			return (ENOMEM);
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
		tcp->tcp_iphc = hdrs;
		tcp->tcp_iphc_len = hdrs_len;
		tcp->tcp_hdr_grown = B_TRUE;
	}
	ip_build_hdrs_v6((uchar_t *)tcp->tcp_iphc,
	    hdrs_len - TCP_MAX_HDR_LENGTH, ipp, IPPROTO_TCP);

	/* Set header fields not in ipp */
	if (ipp->ipp_fields & IPPF_HAS_IP6I) {
		ip6i = (ip6i_t *)tcp->tcp_iphc;
		tcp->tcp_ip6h = (ip6_t *)&ip6i[1];
	} else {
		tcp->tcp_ip6h = (ip6_t *)tcp->tcp_iphc;
	}
	/*
	 * tcp->tcp_ip_hdr_len will include ip6i_t if there is one.
	 *
	 * tcp->tcp_tcp_hdr_len doesn't change here.
	 */
	tcp->tcp_ip_hdr_len = hdrs_len - TCP_MAX_HDR_LENGTH;
	tcp->tcp_tcph = (tcph_t *)(tcp->tcp_iphc + tcp->tcp_ip_hdr_len);
	tcp->tcp_hdr_len = tcp->tcp_ip_hdr_len + tcp->tcp_tcp_hdr_len;

	bcopy(buf, tcp->tcp_tcph, tcp->tcp_tcp_hdr_len);

	tcp->tcp_ip6h->ip6_src = src;
	tcp->tcp_ip6h->ip6_dst = dst;

	/*
	 * If the hop limit was not set by ip_build_hdrs_v6(), set it to
	 * the default value for TCP.
	 */
	if (!(ipp->ipp_fields & IPPF_UNICAST_HOPS))
		tcp->tcp_ip6h->ip6_hops = tcps->tcps_ipv6_hoplimit;

	/*
	 * If we're setting extension headers after a connection
	 * has been established, and if we have a routing header
	 * among the extension headers, call ip_massage_options_v6 to
	 * manipulate the routing header/ip6_dst set the checksum
	 * difference in the tcp header template.
	 * (This happens in tcp_connect_ipv6 if the routing header
	 * is set prior to the connect.)
	 * Set the tcp_sum to zero first in case we've cleared a
	 * routing header or don't have one at all.
	 */
	tcp->tcp_sum = 0;
	if ((tcp->tcp_state >= TCPS_SYN_SENT) &&
	    (tcp->tcp_ipp_fields & IPPF_RTHDR)) {
		ip6_rthdr_t *rth = ip_find_rthdr_v6(tcp->tcp_ip6h,
		    (uint8_t *)tcp->tcp_tcph);
		if (rth != NULL) {
			tcp->tcp_sum = ip_massage_options_v6(tcp->tcp_ip6h,
			    rth, tcps->tcps_netstack);
			tcp->tcp_sum = ntohs((tcp->tcp_sum & 0xFFFF) +
			    (tcp->tcp_sum >> 16));
		}
	}

	/* Try to get everything in a single mblk */
	(void) proto_set_tx_wroff(tcp->tcp_rq, connp,
	    hdrs_len + tcps->tcps_wroff_xtra);
	return (0);
}

/*
 * Transfer any source route option from ipha to buf/dst in reversed form.
 */
static int
tcp_opt_rev_src_route(ipha_t *ipha, char *buf, uchar_t *dst)
{
	ipoptp_t	opts;
	uchar_t		*opt;
	uint8_t		optval;
	uint8_t		optlen;
	uint32_t	len = 0;

	for (optval = ipoptp_first(&opts, ipha);
	    optval != IPOPT_EOL;
	    optval = ipoptp_next(&opts)) {
		opt = opts.ipoptp_cur;
		optlen = opts.ipoptp_len;
		switch (optval) {
			int	off1, off2;
		case IPOPT_SSRR:
		case IPOPT_LSRR:

			/* Reverse source route */
			/*
			 * First entry should be the next to last one in the
			 * current source route (the last entry is our
			 * address.)
			 * The last entry should be the final destination.
			 */
			buf[IPOPT_OPTVAL] = (uint8_t)optval;
			buf[IPOPT_OLEN] = (uint8_t)optlen;
			off1 = IPOPT_MINOFF_SR - 1;
			off2 = opt[IPOPT_OFFSET] - IP_ADDR_LEN - 1;
			if (off2 < 0) {
				/* No entries in source route */
				break;
			}
			bcopy(opt + off2, dst, IP_ADDR_LEN);
			/*
			 * Note: use src since ipha has not had its src
			 * and dst reversed (it is in the state it was
			 * received.
			 */
			bcopy(&ipha->ipha_src, buf + off2,
			    IP_ADDR_LEN);
			off2 -= IP_ADDR_LEN;

			while (off2 > 0) {
				bcopy(opt + off2, buf + off1,
				    IP_ADDR_LEN);
				off1 += IP_ADDR_LEN;
				off2 -= IP_ADDR_LEN;
			}
			buf[IPOPT_OFFSET] = IPOPT_MINOFF_SR;
			buf += optlen;
			len += optlen;
			break;
		}
	}
done:
	/* Pad the resulting options */
	while (len & 0x3) {
		*buf++ = IPOPT_EOL;
		len++;
	}
	return (len);
}


/*
 * Extract and revert a source route from ipha (if any)
 * and then update the relevant fields in both tcp_t and the standard header.
 */
static void
tcp_opt_reverse(tcp_t *tcp, ipha_t *ipha)
{
	char	buf[TCP_MAX_HDR_LENGTH];
	uint_t	tcph_len;
	int	len;

	ASSERT(IPH_HDR_VERSION(ipha) == IPV4_VERSION);
	len = IPH_HDR_LENGTH(ipha);
	if (len == IP_SIMPLE_HDR_LENGTH)
		/* Nothing to do */
		return;
	if (len > IP_SIMPLE_HDR_LENGTH + TCP_MAX_IP_OPTIONS_LENGTH ||
	    (len & 0x3))
		return;

	tcph_len = tcp->tcp_tcp_hdr_len;
	bcopy(tcp->tcp_tcph, buf, tcph_len);
	tcp->tcp_sum = (tcp->tcp_ipha->ipha_dst >> 16) +
	    (tcp->tcp_ipha->ipha_dst & 0xffff);
	len = tcp_opt_rev_src_route(ipha, (char *)tcp->tcp_ipha +
	    IP_SIMPLE_HDR_LENGTH, (uchar_t *)&tcp->tcp_ipha->ipha_dst);
	len += IP_SIMPLE_HDR_LENGTH;
	tcp->tcp_sum -= ((tcp->tcp_ipha->ipha_dst >> 16) +
	    (tcp->tcp_ipha->ipha_dst & 0xffff));
	if ((int)tcp->tcp_sum < 0)
		tcp->tcp_sum--;
	tcp->tcp_sum = (tcp->tcp_sum & 0xFFFF) + (tcp->tcp_sum >> 16);
	tcp->tcp_sum = ntohs((tcp->tcp_sum & 0xFFFF) + (tcp->tcp_sum >> 16));
	tcp->tcp_tcph = (tcph_t *)((char *)tcp->tcp_ipha + len);
	bcopy(buf, tcp->tcp_tcph, tcph_len);
	tcp->tcp_ip_hdr_len = len;
	tcp->tcp_ipha->ipha_version_and_hdr_length =
	    (IP_VERSION << 4) | (len >> 2);
	len += tcph_len;
	tcp->tcp_hdr_len = len;
}

/*
 * Copy the standard header into its new location,
 * lay in the new options and then update the relevant
 * fields in both tcp_t and the standard header.
 */
static int
tcp_opt_set_header(tcp_t *tcp, boolean_t checkonly, uchar_t *ptr, uint_t len)
{
	uint_t	tcph_len;
	uint8_t	*ip_optp;
	tcph_t	*new_tcph;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	conn_t	*connp = tcp->tcp_connp;

	if ((len > TCP_MAX_IP_OPTIONS_LENGTH) || (len & 0x3))
		return (EINVAL);

	if (len > IP_MAX_OPT_LENGTH - tcp->tcp_label_len)
		return (EINVAL);

	if (checkonly) {
		/*
		 * do not really set, just pretend to - T_CHECK
		 */
		return (0);
	}

	ip_optp = (uint8_t *)tcp->tcp_ipha + IP_SIMPLE_HDR_LENGTH;
	if (tcp->tcp_label_len > 0) {
		int padlen;
		uint8_t opt;

		/* convert list termination to no-ops */
		padlen = tcp->tcp_label_len - ip_optp[IPOPT_OLEN];
		ip_optp += ip_optp[IPOPT_OLEN];
		opt = len > 0 ? IPOPT_NOP : IPOPT_EOL;
		while (--padlen >= 0)
			*ip_optp++ = opt;
	}
	tcph_len = tcp->tcp_tcp_hdr_len;
	new_tcph = (tcph_t *)(ip_optp + len);
	ovbcopy(tcp->tcp_tcph, new_tcph, tcph_len);
	tcp->tcp_tcph = new_tcph;
	bcopy(ptr, ip_optp, len);

	len += IP_SIMPLE_HDR_LENGTH + tcp->tcp_label_len;

	tcp->tcp_ip_hdr_len = len;
	tcp->tcp_ipha->ipha_version_and_hdr_length =
	    (IP_VERSION << 4) | (len >> 2);
	tcp->tcp_hdr_len = len + tcph_len;
	if (!TCP_IS_DETACHED(tcp)) {
		/* Always allocate room for all options. */
		(void) proto_set_tx_wroff(tcp->tcp_rq, connp,
		    TCP_MAX_COMBINED_HEADER_LENGTH + tcps->tcps_wroff_xtra);
	}
	return (0);
}

/* Get callback routine passed to nd_load by tcp_param_register */
/* ARGSUSED */
static int
tcp_param_get(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *cr)
{
	tcpparam_t	*tcppa = (tcpparam_t *)cp;

	(void) mi_mpprintf(mp, "%u", tcppa->tcp_param_val);
	return (0);
}

/*
 * Walk through the param array specified registering each element with the
 * named dispatch handler.
 */
static boolean_t
tcp_param_register(IDP *ndp, tcpparam_t *tcppa, int cnt, tcp_stack_t *tcps)
{
	for (; cnt-- > 0; tcppa++) {
		if (tcppa->tcp_param_name && tcppa->tcp_param_name[0]) {
			if (!nd_load(ndp, tcppa->tcp_param_name,
			    tcp_param_get, tcp_param_set,
			    (caddr_t)tcppa)) {
				nd_free(ndp);
				return (B_FALSE);
			}
		}
	}
	tcps->tcps_wroff_xtra_param = kmem_zalloc(sizeof (tcpparam_t),
	    KM_SLEEP);
	bcopy(&lcl_tcp_wroff_xtra_param, tcps->tcps_wroff_xtra_param,
	    sizeof (tcpparam_t));
	if (!nd_load(ndp, tcps->tcps_wroff_xtra_param->tcp_param_name,
	    tcp_param_get, tcp_param_set_aligned,
	    (caddr_t)tcps->tcps_wroff_xtra_param)) {
		nd_free(ndp);
		return (B_FALSE);
	}
	tcps->tcps_mdt_head_param = kmem_zalloc(sizeof (tcpparam_t),
	    KM_SLEEP);
	bcopy(&lcl_tcp_mdt_head_param, tcps->tcps_mdt_head_param,
	    sizeof (tcpparam_t));
	if (!nd_load(ndp, tcps->tcps_mdt_head_param->tcp_param_name,
	    tcp_param_get, tcp_param_set_aligned,
	    (caddr_t)tcps->tcps_mdt_head_param)) {
		nd_free(ndp);
		return (B_FALSE);
	}
	tcps->tcps_mdt_tail_param = kmem_zalloc(sizeof (tcpparam_t),
	    KM_SLEEP);
	bcopy(&lcl_tcp_mdt_tail_param, tcps->tcps_mdt_tail_param,
	    sizeof (tcpparam_t));
	if (!nd_load(ndp, tcps->tcps_mdt_tail_param->tcp_param_name,
	    tcp_param_get, tcp_param_set_aligned,
	    (caddr_t)tcps->tcps_mdt_tail_param)) {
		nd_free(ndp);
		return (B_FALSE);
	}
	tcps->tcps_mdt_max_pbufs_param = kmem_zalloc(sizeof (tcpparam_t),
	    KM_SLEEP);
	bcopy(&lcl_tcp_mdt_max_pbufs_param, tcps->tcps_mdt_max_pbufs_param,
	    sizeof (tcpparam_t));
	if (!nd_load(ndp, tcps->tcps_mdt_max_pbufs_param->tcp_param_name,
	    tcp_param_get, tcp_param_set_aligned,
	    (caddr_t)tcps->tcps_mdt_max_pbufs_param)) {
		nd_free(ndp);
		return (B_FALSE);
	}
	if (!nd_load(ndp, "tcp_extra_priv_ports",
	    tcp_extra_priv_ports_get, NULL, NULL)) {
		nd_free(ndp);
		return (B_FALSE);
	}
	if (!nd_load(ndp, "tcp_extra_priv_ports_add",
	    NULL, tcp_extra_priv_ports_add, NULL)) {
		nd_free(ndp);
		return (B_FALSE);
	}
	if (!nd_load(ndp, "tcp_extra_priv_ports_del",
	    NULL, tcp_extra_priv_ports_del, NULL)) {
		nd_free(ndp);
		return (B_FALSE);
	}
	if (!nd_load(ndp, "tcp_status", tcp_status_report, NULL,
	    NULL)) {
		nd_free(ndp);
		return (B_FALSE);
	}
	if (!nd_load(ndp, "tcp_bind_hash", tcp_bind_hash_report,
	    NULL, NULL)) {
		nd_free(ndp);
		return (B_FALSE);
	}
	if (!nd_load(ndp, "tcp_listen_hash",
	    tcp_listen_hash_report, NULL, NULL)) {
		nd_free(ndp);
		return (B_FALSE);
	}
	if (!nd_load(ndp, "tcp_conn_hash", tcp_conn_hash_report,
	    NULL, NULL)) {
		nd_free(ndp);
		return (B_FALSE);
	}
	if (!nd_load(ndp, "tcp_acceptor_hash",
	    tcp_acceptor_hash_report, NULL, NULL)) {
		nd_free(ndp);
		return (B_FALSE);
	}
	if (!nd_load(ndp, "tcp_1948_phrase", NULL,
	    tcp_1948_phrase_set, NULL)) {
		nd_free(ndp);
		return (B_FALSE);
	}
	/*
	 * Dummy ndd variables - only to convey obsolescence information
	 * through printing of their name (no get or set routines)
	 * XXX Remove in future releases ?
	 */
	if (!nd_load(ndp,
	    "tcp_close_wait_interval(obsoleted - "
	    "use tcp_time_wait_interval)", NULL, NULL, NULL)) {
		nd_free(ndp);
		return (B_FALSE);
	}
	return (B_TRUE);
}

/* ndd set routine for tcp_wroff_xtra, tcp_mdt_hdr_{head,tail}_min. */
/* ARGSUSED */
static int
tcp_param_set_aligned(queue_t *q, mblk_t *mp, char *value, caddr_t cp,
    cred_t *cr)
{
	long new_value;
	tcpparam_t *tcppa = (tcpparam_t *)cp;

	if (ddi_strtol(value, NULL, 10, &new_value) != 0 ||
	    new_value < tcppa->tcp_param_min ||
	    new_value > tcppa->tcp_param_max) {
		return (EINVAL);
	}
	/*
	 * Need to make sure new_value is a multiple of 4.  If it is not,
	 * round it up.  For future 64 bit requirement, we actually make it
	 * a multiple of 8.
	 */
	if (new_value & 0x7) {
		new_value = (new_value & ~0x7) + 0x8;
	}
	tcppa->tcp_param_val = new_value;
	return (0);
}

/* Set callback routine passed to nd_load by tcp_param_register */
/* ARGSUSED */
static int
tcp_param_set(queue_t *q, mblk_t *mp, char *value, caddr_t cp, cred_t *cr)
{
	long	new_value;
	tcpparam_t	*tcppa = (tcpparam_t *)cp;

	if (ddi_strtol(value, NULL, 10, &new_value) != 0 ||
	    new_value < tcppa->tcp_param_min ||
	    new_value > tcppa->tcp_param_max) {
		return (EINVAL);
	}
	tcppa->tcp_param_val = new_value;
	return (0);
}

/*
 * Add a new piece to the tcp reassembly queue.  If the gap at the beginning
 * is filled, return as much as we can.  The message passed in may be
 * multi-part, chained using b_cont.  "start" is the starting sequence
 * number for this piece.
 */
static mblk_t *
tcp_reass(tcp_t *tcp, mblk_t *mp, uint32_t start)
{
	uint32_t	end;
	mblk_t		*mp1;
	mblk_t		*mp2;
	mblk_t		*next_mp;
	uint32_t	u1;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	/* Walk through all the new pieces. */
	do {
		ASSERT((uintptr_t)(mp->b_wptr - mp->b_rptr) <=
		    (uintptr_t)INT_MAX);
		end = start + (int)(mp->b_wptr - mp->b_rptr);
		next_mp = mp->b_cont;
		if (start == end) {
			/* Empty.  Blast it. */
			freeb(mp);
			continue;
		}
		mp->b_cont = NULL;
		TCP_REASS_SET_SEQ(mp, start);
		TCP_REASS_SET_END(mp, end);
		mp1 = tcp->tcp_reass_tail;
		if (!mp1) {
			tcp->tcp_reass_tail = mp;
			tcp->tcp_reass_head = mp;
			BUMP_MIB(&tcps->tcps_mib, tcpInDataUnorderSegs);
			UPDATE_MIB(&tcps->tcps_mib,
			    tcpInDataUnorderBytes, end - start);
			continue;
		}
		/* New stuff completely beyond tail? */
		if (SEQ_GEQ(start, TCP_REASS_END(mp1))) {
			/* Link it on end. */
			mp1->b_cont = mp;
			tcp->tcp_reass_tail = mp;
			BUMP_MIB(&tcps->tcps_mib, tcpInDataUnorderSegs);
			UPDATE_MIB(&tcps->tcps_mib,
			    tcpInDataUnorderBytes, end - start);
			continue;
		}
		mp1 = tcp->tcp_reass_head;
		u1 = TCP_REASS_SEQ(mp1);
		/* New stuff at the front? */
		if (SEQ_LT(start, u1)) {
			/* Yes... Check for overlap. */
			mp->b_cont = mp1;
			tcp->tcp_reass_head = mp;
			tcp_reass_elim_overlap(tcp, mp);
			continue;
		}
		/*
		 * The new piece fits somewhere between the head and tail.
		 * We find our slot, where mp1 precedes us and mp2 trails.
		 */
		for (; (mp2 = mp1->b_cont) != NULL; mp1 = mp2) {
			u1 = TCP_REASS_SEQ(mp2);
			if (SEQ_LEQ(start, u1))
				break;
		}
		/* Link ourselves in */
		mp->b_cont = mp2;
		mp1->b_cont = mp;

		/* Trim overlap with following mblk(s) first */
		tcp_reass_elim_overlap(tcp, mp);

		/* Trim overlap with preceding mblk */
		tcp_reass_elim_overlap(tcp, mp1);

	} while (start = end, mp = next_mp);
	mp1 = tcp->tcp_reass_head;
	/* Anything ready to go? */
	if (TCP_REASS_SEQ(mp1) != tcp->tcp_rnxt)
		return (NULL);
	/* Eat what we can off the queue */
	for (;;) {
		mp = mp1->b_cont;
		end = TCP_REASS_END(mp1);
		TCP_REASS_SET_SEQ(mp1, 0);
		TCP_REASS_SET_END(mp1, 0);
		if (!mp) {
			tcp->tcp_reass_tail = NULL;
			break;
		}
		if (end != TCP_REASS_SEQ(mp)) {
			mp1->b_cont = NULL;
			break;
		}
		mp1 = mp;
	}
	mp1 = tcp->tcp_reass_head;
	tcp->tcp_reass_head = mp;
	return (mp1);
}

/* Eliminate any overlap that mp may have over later mblks */
static void
tcp_reass_elim_overlap(tcp_t *tcp, mblk_t *mp)
{
	uint32_t	end;
	mblk_t		*mp1;
	uint32_t	u1;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	end = TCP_REASS_END(mp);
	while ((mp1 = mp->b_cont) != NULL) {
		u1 = TCP_REASS_SEQ(mp1);
		if (!SEQ_GT(end, u1))
			break;
		if (!SEQ_GEQ(end, TCP_REASS_END(mp1))) {
			mp->b_wptr -= end - u1;
			TCP_REASS_SET_END(mp, u1);
			BUMP_MIB(&tcps->tcps_mib, tcpInDataPartDupSegs);
			UPDATE_MIB(&tcps->tcps_mib,
			    tcpInDataPartDupBytes, end - u1);
			break;
		}
		mp->b_cont = mp1->b_cont;
		TCP_REASS_SET_SEQ(mp1, 0);
		TCP_REASS_SET_END(mp1, 0);
		freeb(mp1);
		BUMP_MIB(&tcps->tcps_mib, tcpInDataDupSegs);
		UPDATE_MIB(&tcps->tcps_mib, tcpInDataDupBytes, end - u1);
	}
	if (!mp1)
		tcp->tcp_reass_tail = mp;
}

static uint_t
tcp_rwnd_reopen(tcp_t *tcp)
{
	uint_t ret = 0;
	uint_t thwin;

	/* Learn the latest rwnd information that we sent to the other side. */
	thwin = ((uint_t)BE16_TO_U16(tcp->tcp_tcph->th_win))
	    << tcp->tcp_rcv_ws;
	/* This is peer's calculated send window (our receive window). */
	thwin -= tcp->tcp_rnxt - tcp->tcp_rack;
	/*
	 * Increase the receive window to max.  But we need to do receiver
	 * SWS avoidance.  This means that we need to check the increase of
	 * of receive window is at least 1 MSS.
	 */
	if (tcp->tcp_recv_hiwater - thwin >= tcp->tcp_mss) {
		/*
		 * If the window that the other side knows is less than max
		 * deferred acks segments, send an update immediately.
		 */
		if (thwin < tcp->tcp_rack_cur_max * tcp->tcp_mss) {
			BUMP_MIB(&tcp->tcp_tcps->tcps_mib, tcpOutWinUpdate);
			ret = TH_ACK_NEEDED;
		}
		tcp->tcp_rwnd = tcp->tcp_recv_hiwater;
	}
	return (ret);
}

/*
 * Send up all messages queued on tcp_rcv_list.
 */
static uint_t
tcp_rcv_drain(tcp_t *tcp)
{
	mblk_t *mp;
	uint_t ret = 0;
#ifdef DEBUG
	uint_t cnt = 0;
#endif
	queue_t	*q = tcp->tcp_rq;

	/* Can't drain on an eager connection */
	if (tcp->tcp_listener != NULL)
		return (ret);

	/* Can't be a non-STREAMS connection or sodirect enabled */
	ASSERT((!IPCL_IS_NONSTR(tcp->tcp_connp)) && SOD_NOT_ENABLED(tcp));

	/* No need for the push timer now. */
	if (tcp->tcp_push_tid != 0) {
		(void) TCP_TIMER_CANCEL(tcp, tcp->tcp_push_tid);
		tcp->tcp_push_tid = 0;
	}

	/*
	 * Handle two cases here: we are currently fused or we were
	 * previously fused and have some urgent data to be delivered
	 * upstream.  The latter happens because we either ran out of
	 * memory or were detached and therefore sending the SIGURG was
	 * deferred until this point.  In either case we pass control
	 * over to tcp_fuse_rcv_drain() since it may need to complete
	 * some work.
	 */
	if ((tcp->tcp_fused || tcp->tcp_fused_sigurg)) {
		ASSERT(IPCL_IS_NONSTR(tcp->tcp_connp) ||
		    tcp->tcp_fused_sigurg_mp != NULL);
		if (tcp_fuse_rcv_drain(q, tcp, tcp->tcp_fused ? NULL :
		    &tcp->tcp_fused_sigurg_mp))
			return (ret);
	}

	while ((mp = tcp->tcp_rcv_list) != NULL) {
		tcp->tcp_rcv_list = mp->b_next;
		mp->b_next = NULL;
#ifdef DEBUG
		cnt += msgdsize(mp);
#endif
		/* Does this need SSL processing first? */
		if ((tcp->tcp_kssl_ctx != NULL) && (DB_TYPE(mp) == M_DATA)) {
			DTRACE_PROBE1(kssl_mblk__ksslinput_rcvdrain,
			    mblk_t *, mp);
			tcp_kssl_input(tcp, mp);
			continue;
		}
		putnext(q, mp);
	}
#ifdef DEBUG
	ASSERT(cnt == tcp->tcp_rcv_cnt);
#endif
	tcp->tcp_rcv_last_head = NULL;
	tcp->tcp_rcv_last_tail = NULL;
	tcp->tcp_rcv_cnt = 0;

	if (canputnext(q))
		return (tcp_rwnd_reopen(tcp));

	return (ret);
}

/*
 * Queue data on tcp_rcv_list which is a b_next chain.
 * tcp_rcv_last_head/tail is the last element of this chain.
 * Each element of the chain is a b_cont chain.
 *
 * M_DATA messages are added to the current element.
 * Other messages are added as new (b_next) elements.
 */
void
tcp_rcv_enqueue(tcp_t *tcp, mblk_t *mp, uint_t seg_len)
{
	ASSERT(seg_len == msgdsize(mp));
	ASSERT(tcp->tcp_rcv_list == NULL || tcp->tcp_rcv_last_head != NULL);

	if (tcp->tcp_rcv_list == NULL) {
		ASSERT(tcp->tcp_rcv_last_head == NULL);
		tcp->tcp_rcv_list = mp;
		tcp->tcp_rcv_last_head = mp;
	} else if (DB_TYPE(mp) == DB_TYPE(tcp->tcp_rcv_last_head)) {
		tcp->tcp_rcv_last_tail->b_cont = mp;
	} else {
		tcp->tcp_rcv_last_head->b_next = mp;
		tcp->tcp_rcv_last_head = mp;
	}

	while (mp->b_cont)
		mp = mp->b_cont;

	tcp->tcp_rcv_last_tail = mp;
	tcp->tcp_rcv_cnt += seg_len;
	tcp->tcp_rwnd -= seg_len;
}

/*
 * The tcp_rcv_sod_XXX() functions enqueue data directly to the socket
 * above, in addition when uioa is enabled schedule an asynchronous uio
 * prior to enqueuing. They implement the combinhed semantics of the
 * tcp_rcv_XXX() functions, tcp_rcv_list push logic, and STREAMS putnext()
 * canputnext(), i.e. flow-control with backenable.
 *
 * tcp_sod_wakeup() is called where tcp_rcv_drain() would be called in the
 * non sodirect connection but as there are no tcp_tcv_list mblk_t's we deal
 * with the rcv_wnd and push timer and call the sodirect wakeup function.
 *
 * Must be called with sodp->sod_lockp held and will return with the lock
 * released.
 */
static uint_t
tcp_rcv_sod_wakeup(tcp_t *tcp, sodirect_t *sodp)
{
	queue_t		*q = tcp->tcp_rq;
	uint_t		thwin;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	uint_t		ret = 0;

	/* Can't be an eager connection */
	ASSERT(tcp->tcp_listener == NULL);

	/* Caller must have lock held */
	ASSERT(MUTEX_HELD(sodp->sod_lockp));

	/* Sodirect mode so must not be a tcp_rcv_list */
	ASSERT(tcp->tcp_rcv_list == NULL);

	if (SOD_QFULL(sodp)) {
		/* Q is full, mark Q for need backenable */
		SOD_QSETBE(sodp);
	}
	/* Last advertised rwnd, i.e. rwnd last sent in a packet */
	thwin = ((uint_t)BE16_TO_U16(tcp->tcp_tcph->th_win))
	    << tcp->tcp_rcv_ws;
	/* This is peer's calculated send window (our available rwnd). */
	thwin -= tcp->tcp_rnxt - tcp->tcp_rack;
	/*
	 * Increase the receive window to max.  But we need to do receiver
	 * SWS avoidance.  This means that we need to check the increase of
	 * of receive window is at least 1 MSS.
	 */
	if (!SOD_QFULL(sodp) && (q->q_hiwat - thwin >= tcp->tcp_mss)) {
		/*
		 * If the window that the other side knows is less than max
		 * deferred acks segments, send an update immediately.
		 */
		if (thwin < tcp->tcp_rack_cur_max * tcp->tcp_mss) {
			BUMP_MIB(&tcps->tcps_mib, tcpOutWinUpdate);
			ret = TH_ACK_NEEDED;
		}
		tcp->tcp_rwnd = q->q_hiwat;
	}

	if (!SOD_QEMPTY(sodp)) {
		/* Wakeup to socket */
		sodp->sod_state &= SOD_WAKE_CLR;
		sodp->sod_state |= SOD_WAKE_DONE;
		(sodp->sod_wakeup)(sodp);
		/* wakeup() does the mutex_ext() */
	} else {
		/* Q is empty, no need to wake */
		sodp->sod_state &= SOD_WAKE_CLR;
		sodp->sod_state |= SOD_WAKE_NOT;
		mutex_exit(sodp->sod_lockp);
	}

	/* No need for the push timer now. */
	if (tcp->tcp_push_tid != 0) {
		(void) TCP_TIMER_CANCEL(tcp, tcp->tcp_push_tid);
		tcp->tcp_push_tid = 0;
	}

	return (ret);
}

/*
 * Called where tcp_rcv_enqueue()/putnext(RD(q)) would be. For M_DATA
 * mblk_t's if uioa enabled then start a uioa asynchronous copy directly
 * to the user-land buffer and flag the mblk_t as such.
 *
 * Also, handle tcp_rwnd.
 */
uint_t
tcp_rcv_sod_enqueue(tcp_t *tcp, sodirect_t *sodp, mblk_t *mp, uint_t seg_len)
{
	uioa_t		*uioap = &sodp->sod_uioa;
	boolean_t	qfull;
	uint_t		thwin;

	/* Can't be an eager connection */
	ASSERT(tcp->tcp_listener == NULL);

	/* Caller must have lock held */
	ASSERT(MUTEX_HELD(sodp->sod_lockp));

	/* Sodirect mode so must not be a tcp_rcv_list */
	ASSERT(tcp->tcp_rcv_list == NULL);

	/* Passed in segment length must be equal to mblk_t chain data size */
	ASSERT(seg_len == msgdsize(mp));

	if (DB_TYPE(mp) != M_DATA) {
		/* Only process M_DATA mblk_t's */
		goto enq;
	}
	if (uioap->uioa_state & UIOA_ENABLED) {
		/* Uioa is enabled */
		mblk_t		*mp1 = mp;
		mblk_t		*lmp = NULL;

		if (seg_len > uioap->uio_resid) {
			/*
			 * There isn't enough uio space for the mblk_t chain
			 * so disable uioa such that this and any additional
			 * mblk_t data is handled by the socket and schedule
			 * the socket for wakeup to finish this uioa.
			 */
			uioap->uioa_state &= UIOA_CLR;
			uioap->uioa_state |= UIOA_FINI;
			if (sodp->sod_state & SOD_WAKE_NOT) {
				sodp->sod_state &= SOD_WAKE_CLR;
				sodp->sod_state |= SOD_WAKE_NEED;
			}
			goto enq;
		}
		do {
			uint32_t	len = MBLKL(mp1);

			if (!uioamove(mp1->b_rptr, len, UIO_READ, uioap)) {
				/* Scheduled, mark dblk_t as such */
				DB_FLAGS(mp1) |= DBLK_UIOA;
			} else {
				/* Error, turn off async processing */
				uioap->uioa_state &= UIOA_CLR;
				uioap->uioa_state |= UIOA_FINI;
				break;
			}
			lmp = mp1;
		} while ((mp1 = mp1->b_cont) != NULL);

		if (mp1 != NULL || uioap->uio_resid == 0) {
			/*
			 * Not all mblk_t(s) uioamoved (error) or all uio
			 * space has been consumed so schedule the socket
			 * for wakeup to finish this uio.
			 */
			sodp->sod_state &= SOD_WAKE_CLR;
			sodp->sod_state |= SOD_WAKE_NEED;

			/* Break the mblk chain if neccessary. */
			if (mp1 != NULL && lmp != NULL) {
				mp->b_next = mp1;
				lmp->b_cont = NULL;
			}
		}
	} else if (uioap->uioa_state & UIOA_FINI) {
		/*
		 * Post UIO_ENABLED waiting for socket to finish processing
		 * so just enqueue and update tcp_rwnd.
		 */
		if (SOD_QFULL(sodp))
			tcp->tcp_rwnd -= seg_len;
	} else if (sodp->sod_want > 0) {
		/*
		 * Uioa isn't enabled but sodirect has a pending read().
		 */
		if (SOD_QCNT(sodp) + seg_len >= sodp->sod_want) {
			if (sodp->sod_state & SOD_WAKE_NOT) {
				/* Schedule socket for wakeup */
				sodp->sod_state &= SOD_WAKE_CLR;
				sodp->sod_state |= SOD_WAKE_NEED;
			}
			tcp->tcp_rwnd -= seg_len;
		}
	} else if (SOD_QCNT(sodp) + seg_len >= tcp->tcp_rq->q_hiwat >> 3) {
		/*
		 * No pending sodirect read() so used the default
		 * TCP push logic to guess that a push is needed.
		 */
		if (sodp->sod_state & SOD_WAKE_NOT) {
			/* Schedule socket for wakeup */
			sodp->sod_state &= SOD_WAKE_CLR;
			sodp->sod_state |= SOD_WAKE_NEED;
		}
		tcp->tcp_rwnd -= seg_len;
	} else {
		/* Just update tcp_rwnd */
		tcp->tcp_rwnd -= seg_len;
	}
enq:
	qfull = SOD_QFULL(sodp);

	(sodp->sod_enqueue)(sodp, mp);

	if (! qfull && SOD_QFULL(sodp)) {
		/* Wasn't QFULL, now QFULL, need back-enable */
		SOD_QSETBE(sodp);
	}

	/*
	 * Check to see if remote avail swnd < mss due to delayed ACK,
	 * first get advertised rwnd.
	 */
	thwin = ((uint_t)BE16_TO_U16(tcp->tcp_tcph->th_win));
	/* Minus delayed ACK count */
	thwin -= tcp->tcp_rnxt - tcp->tcp_rack;
	if (thwin < tcp->tcp_mss) {
		/* Remote avail swnd < mss, need ACK now */
		return (TH_ACK_NEEDED);
	}

	return (0);
}

/*
 * DEFAULT TCP ENTRY POINT via squeue on READ side.
 *
 * This is the default entry function into TCP on the read side. TCP is
 * always entered via squeue i.e. using squeue's for mutual exclusion.
 * When classifier does a lookup to find the tcp, it also puts a reference
 * on the conn structure associated so the tcp is guaranteed to exist
 * when we come here. We still need to check the state because it might
 * as well has been closed. The squeue processing function i.e. squeue_enter,
 * is responsible for doing the CONN_DEC_REF.
 *
 * Apart from the default entry point, IP also sends packets directly to
 * tcp_rput_data for AF_INET fast path and tcp_conn_request for incoming
 * connections.
 */
boolean_t tcp_outbound_squeue_switch = B_FALSE;
void
tcp_input(void *arg, mblk_t *mp, void *arg2)
{
	conn_t	*connp = (conn_t *)arg;
	tcp_t	*tcp = (tcp_t *)connp->conn_tcp;

	/* arg2 is the sqp */
	ASSERT(arg2 != NULL);
	ASSERT(mp != NULL);

	/*
	 * Don't accept any input on a closed tcp as this TCP logically does
	 * not exist on the system. Don't proceed further with this TCP.
	 * For eg. this packet could trigger another close of this tcp
	 * which would be disastrous for tcp_refcnt. tcp_close_detached /
	 * tcp_clean_death / tcp_closei_local must be called at most once
	 * on a TCP. In this case we need to refeed the packet into the
	 * classifier and figure out where the packet should go. Need to
	 * preserve the recv_ill somehow. Until we figure that out, for
	 * now just drop the packet if we can't classify the packet.
	 */
	if (tcp->tcp_state == TCPS_CLOSED ||
	    tcp->tcp_state == TCPS_BOUND) {
		conn_t	*new_connp;
		ip_stack_t *ipst = tcp->tcp_tcps->tcps_netstack->netstack_ip;

		new_connp = ipcl_classify(mp, connp->conn_zoneid, ipst);
		if (new_connp != NULL) {
			tcp_reinput(new_connp, mp, arg2);
			return;
		}
		/* We failed to classify. For now just drop the packet */
		freemsg(mp);
		return;
	}

	if (DB_TYPE(mp) != M_DATA) {
		tcp_rput_common(tcp, mp);
		return;
	}

	if (mp->b_datap->db_struioflag & STRUIO_CONNECT) {
		squeue_t	*final_sqp;

		mp->b_datap->db_struioflag &= ~STRUIO_CONNECT;
		final_sqp = (squeue_t *)DB_CKSUMSTART(mp);
		DB_CKSUMSTART(mp) = 0;
		if (tcp->tcp_state == TCPS_SYN_SENT &&
		    connp->conn_final_sqp == NULL &&
		    tcp_outbound_squeue_switch) {
			ASSERT(connp->conn_initial_sqp == connp->conn_sqp);
			connp->conn_final_sqp = final_sqp;
			if (connp->conn_final_sqp != connp->conn_sqp) {
				CONN_INC_REF(connp);
				SQUEUE_SWITCH(connp, connp->conn_final_sqp);
				SQUEUE_ENTER_ONE(connp->conn_sqp, mp,
				    tcp_rput_data, connp, ip_squeue_flag,
				    SQTAG_CONNECT_FINISH);
				return;
			}
		}
	}
	tcp_rput_data(connp, mp, arg2);
}

/*
 * The read side put procedure.
 * The packets passed up by ip are assume to be aligned according to
 * OK_32PTR and the IP+TCP headers fitting in the first mblk.
 */
static void
tcp_rput_common(tcp_t *tcp, mblk_t *mp)
{
	/*
	 * tcp_rput_data() does not expect M_CTL except for the case
	 * where tcp_ipv6_recvancillary is set and we get a IN_PKTINFO
	 * type. Need to make sure that any other M_CTLs don't make
	 * it to tcp_rput_data since it is not expecting any and doesn't
	 * check for it.
	 */
	if (DB_TYPE(mp) == M_CTL) {
		switch (*(uint32_t *)(mp->b_rptr)) {
		case TCP_IOC_ABORT_CONN:
			/*
			 * Handle connection abort request.
			 */
			tcp_ioctl_abort_handler(tcp, mp);
			return;
		case IPSEC_IN:
			/*
			 * Only secure icmp arrive in TCP and they
			 * don't go through data path.
			 */
			tcp_icmp_error(tcp, mp);
			return;
		case IN_PKTINFO:
			/*
			 * Handle IPV6_RECVPKTINFO socket option on AF_INET6
			 * sockets that are receiving IPv4 traffic. tcp
			 */
			ASSERT(tcp->tcp_family == AF_INET6);
			ASSERT(tcp->tcp_ipv6_recvancillary &
			    TCP_IPV6_RECVPKTINFO);
			tcp_rput_data(tcp->tcp_connp, mp,
			    tcp->tcp_connp->conn_sqp);
			return;
		case MDT_IOC_INFO_UPDATE:
			/*
			 * Handle Multidata information update; the
			 * following routine will free the message.
			 */
			if (tcp->tcp_connp->conn_mdt_ok) {
				tcp_mdt_update(tcp,
				    &((ip_mdt_info_t *)mp->b_rptr)->mdt_capab,
				    B_FALSE);
			}
			freemsg(mp);
			return;
		case LSO_IOC_INFO_UPDATE:
			/*
			 * Handle LSO information update; the following
			 * routine will free the message.
			 */
			if (tcp->tcp_connp->conn_lso_ok) {
				tcp_lso_update(tcp,
				    &((ip_lso_info_t *)mp->b_rptr)->lso_capab);
			}
			freemsg(mp);
			return;
		default:
			/*
			 * tcp_icmp_err() will process the M_CTL packets.
			 * Non-ICMP packets, if any, will be discarded in
			 * tcp_icmp_err(). We will process the ICMP packet
			 * even if we are TCP_IS_DETACHED_NONEAGER as the
			 * incoming ICMP packet may result in changing
			 * the tcp_mss, which we would need if we have
			 * packets to retransmit.
			 */
			tcp_icmp_error(tcp, mp);
			return;
		}
	}

	/* No point processing the message if tcp is already closed */
	if (TCP_IS_DETACHED_NONEAGER(tcp)) {
		freemsg(mp);
		return;
	}

	tcp_rput_other(tcp, mp);
}


/* The minimum of smoothed mean deviation in RTO calculation. */
#define	TCP_SD_MIN	400

/*
 * Set RTO for this connection.  The formula is from Jacobson and Karels'
 * "Congestion Avoidance and Control" in SIGCOMM '88.  The variable names
 * are the same as those in Appendix A.2 of that paper.
 *
 * m = new measurement
 * sa = smoothed RTT average (8 * average estimates).
 * sv = smoothed mean deviation (mdev) of RTT (4 * deviation estimates).
 */
static void
tcp_set_rto(tcp_t *tcp, clock_t rtt)
{
	long m = TICK_TO_MSEC(rtt);
	clock_t sa = tcp->tcp_rtt_sa;
	clock_t sv = tcp->tcp_rtt_sd;
	clock_t rto;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	BUMP_MIB(&tcps->tcps_mib, tcpRttUpdate);
	tcp->tcp_rtt_update++;

	/* tcp_rtt_sa is not 0 means this is a new sample. */
	if (sa != 0) {
		/*
		 * Update average estimator:
		 *	new rtt = 7/8 old rtt + 1/8 Error
		 */

		/* m is now Error in estimate. */
		m -= sa >> 3;
		if ((sa += m) <= 0) {
			/*
			 * Don't allow the smoothed average to be negative.
			 * We use 0 to denote reinitialization of the
			 * variables.
			 */
			sa = 1;
		}

		/*
		 * Update deviation estimator:
		 *	new mdev = 3/4 old mdev + 1/4 (abs(Error) - old mdev)
		 */
		if (m < 0)
			m = -m;
		m -= sv >> 2;
		sv += m;
	} else {
		/*
		 * This follows BSD's implementation.  So the reinitialized
		 * RTO is 3 * m.  We cannot go less than 2 because if the
		 * link is bandwidth dominated, doubling the window size
		 * during slow start means doubling the RTT.  We want to be
		 * more conservative when we reinitialize our estimates.  3
		 * is just a convenient number.
		 */
		sa = m << 3;
		sv = m << 1;
	}
	if (sv < TCP_SD_MIN) {
		/*
		 * We do not know that if sa captures the delay ACK
		 * effect as in a long train of segments, a receiver
		 * does not delay its ACKs.  So set the minimum of sv
		 * to be TCP_SD_MIN, which is default to 400 ms, twice
		 * of BSD DATO.  That means the minimum of mean
		 * deviation is 100 ms.
		 *
		 */
		sv = TCP_SD_MIN;
	}
	tcp->tcp_rtt_sa = sa;
	tcp->tcp_rtt_sd = sv;
	/*
	 * RTO = average estimates (sa / 8) + 4 * deviation estimates (sv)
	 *
	 * Add tcp_rexmit_interval extra in case of extreme environment
	 * where the algorithm fails to work.  The default value of
	 * tcp_rexmit_interval_extra should be 0.
	 *
	 * As we use a finer grained clock than BSD and update
	 * RTO for every ACKs, add in another .25 of RTT to the
	 * deviation of RTO to accomodate burstiness of 1/4 of
	 * window size.
	 */
	rto = (sa >> 3) + sv + tcps->tcps_rexmit_interval_extra + (sa >> 5);

	if (rto > tcps->tcps_rexmit_interval_max) {
		tcp->tcp_rto = tcps->tcps_rexmit_interval_max;
	} else if (rto < tcps->tcps_rexmit_interval_min) {
		tcp->tcp_rto = tcps->tcps_rexmit_interval_min;
	} else {
		tcp->tcp_rto = rto;
	}

	/* Now, we can reset tcp_timer_backoff to use the new RTO... */
	tcp->tcp_timer_backoff = 0;
}

/*
 * tcp_get_seg_mp() is called to get the pointer to a segment in the
 * send queue which starts at the given seq. no.
 *
 * Parameters:
 *	tcp_t *tcp: the tcp instance pointer.
 *	uint32_t seq: the starting seq. no of the requested segment.
 *	int32_t *off: after the execution, *off will be the offset to
 *		the returned mblk which points to the requested seq no.
 *		It is the caller's responsibility to send in a non-null off.
 *
 * Return:
 *	A mblk_t pointer pointing to the requested segment in send queue.
 */
static mblk_t *
tcp_get_seg_mp(tcp_t *tcp, uint32_t seq, int32_t *off)
{
	int32_t	cnt;
	mblk_t	*mp;

	/* Defensive coding.  Make sure we don't send incorrect data. */
	if (SEQ_LT(seq, tcp->tcp_suna) || SEQ_GEQ(seq, tcp->tcp_snxt))
		return (NULL);

	cnt = seq - tcp->tcp_suna;
	mp = tcp->tcp_xmit_head;
	while (cnt > 0 && mp != NULL) {
		cnt -= mp->b_wptr - mp->b_rptr;
		if (cnt < 0) {
			cnt += mp->b_wptr - mp->b_rptr;
			break;
		}
		mp = mp->b_cont;
	}
	ASSERT(mp != NULL);
	*off = cnt;
	return (mp);
}

/*
 * This function handles all retransmissions if SACK is enabled for this
 * connection.  First it calculates how many segments can be retransmitted
 * based on tcp_pipe.  Then it goes thru the notsack list to find eligible
 * segments.  A segment is eligible if sack_cnt for that segment is greater
 * than or equal tcp_dupack_fast_retransmit.  After it has retransmitted
 * all eligible segments, it checks to see if TCP can send some new segments
 * (fast recovery).  If it can, set the appropriate flag for tcp_rput_data().
 *
 * Parameters:
 *	tcp_t *tcp: the tcp structure of the connection.
 *	uint_t *flags: in return, appropriate value will be set for
 *	tcp_rput_data().
 */
static void
tcp_sack_rxmit(tcp_t *tcp, uint_t *flags)
{
	notsack_blk_t	*notsack_blk;
	int32_t		usable_swnd;
	int32_t		mss;
	uint32_t	seg_len;
	mblk_t		*xmit_mp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	ASSERT(tcp->tcp_sack_info != NULL);
	ASSERT(tcp->tcp_notsack_list != NULL);
	ASSERT(tcp->tcp_rexmit == B_FALSE);

	/* Defensive coding in case there is a bug... */
	if (tcp->tcp_notsack_list == NULL) {
		return;
	}
	notsack_blk = tcp->tcp_notsack_list;
	mss = tcp->tcp_mss;

	/*
	 * Limit the num of outstanding data in the network to be
	 * tcp_cwnd_ssthresh, which is half of the original congestion wnd.
	 */
	usable_swnd = tcp->tcp_cwnd_ssthresh - tcp->tcp_pipe;

	/* At least retransmit 1 MSS of data. */
	if (usable_swnd <= 0) {
		usable_swnd = mss;
	}

	/* Make sure no new RTT samples will be taken. */
	tcp->tcp_csuna = tcp->tcp_snxt;

	notsack_blk = tcp->tcp_notsack_list;
	while (usable_swnd > 0) {
		mblk_t		*snxt_mp, *tmp_mp;
		tcp_seq		begin = tcp->tcp_sack_snxt;
		tcp_seq		end;
		int32_t		off;

		for (; notsack_blk != NULL; notsack_blk = notsack_blk->next) {
			if (SEQ_GT(notsack_blk->end, begin) &&
			    (notsack_blk->sack_cnt >=
			    tcps->tcps_dupack_fast_retransmit)) {
				end = notsack_blk->end;
				if (SEQ_LT(begin, notsack_blk->begin)) {
					begin = notsack_blk->begin;
				}
				break;
			}
		}
		/*
		 * All holes are filled.  Manipulate tcp_cwnd to send more
		 * if we can.  Note that after the SACK recovery, tcp_cwnd is
		 * set to tcp_cwnd_ssthresh.
		 */
		if (notsack_blk == NULL) {
			usable_swnd = tcp->tcp_cwnd_ssthresh - tcp->tcp_pipe;
			if (usable_swnd <= 0 || tcp->tcp_unsent == 0) {
				tcp->tcp_cwnd = tcp->tcp_snxt - tcp->tcp_suna;
				ASSERT(tcp->tcp_cwnd > 0);
				return;
			} else {
				usable_swnd = usable_swnd / mss;
				tcp->tcp_cwnd = tcp->tcp_snxt - tcp->tcp_suna +
				    MAX(usable_swnd * mss, mss);
				*flags |= TH_XMIT_NEEDED;
				return;
			}
		}

		/*
		 * Note that we may send more than usable_swnd allows here
		 * because of round off, but no more than 1 MSS of data.
		 */
		seg_len = end - begin;
		if (seg_len > mss)
			seg_len = mss;
		snxt_mp = tcp_get_seg_mp(tcp, begin, &off);
		ASSERT(snxt_mp != NULL);
		/* This should not happen.  Defensive coding again... */
		if (snxt_mp == NULL) {
			return;
		}

		xmit_mp = tcp_xmit_mp(tcp, snxt_mp, seg_len, &off,
		    &tmp_mp, begin, B_TRUE, &seg_len, B_TRUE);
		if (xmit_mp == NULL)
			return;

		usable_swnd -= seg_len;
		tcp->tcp_pipe += seg_len;
		tcp->tcp_sack_snxt = begin + seg_len;

		tcp_send_data(tcp, tcp->tcp_wq, xmit_mp);

		/*
		 * Update the send timestamp to avoid false retransmission.
		 */
		snxt_mp->b_prev = (mblk_t *)lbolt;

		BUMP_MIB(&tcps->tcps_mib, tcpRetransSegs);
		UPDATE_MIB(&tcps->tcps_mib, tcpRetransBytes, seg_len);
		BUMP_MIB(&tcps->tcps_mib, tcpOutSackRetransSegs);
		/*
		 * Update tcp_rexmit_max to extend this SACK recovery phase.
		 * This happens when new data sent during fast recovery is
		 * also lost.  If TCP retransmits those new data, it needs
		 * to extend SACK recover phase to avoid starting another
		 * fast retransmit/recovery unnecessarily.
		 */
		if (SEQ_GT(tcp->tcp_sack_snxt, tcp->tcp_rexmit_max)) {
			tcp->tcp_rexmit_max = tcp->tcp_sack_snxt;
		}
	}
}

/*
 * This function handles policy checking at TCP level for non-hard_bound/
 * detached connections.
 */
static boolean_t
tcp_check_policy(tcp_t *tcp, mblk_t *first_mp, ipha_t *ipha, ip6_t *ip6h,
    boolean_t secure, boolean_t mctl_present)
{
	ipsec_latch_t *ipl = NULL;
	ipsec_action_t *act = NULL;
	mblk_t *data_mp;
	ipsec_in_t *ii;
	const char *reason;
	kstat_named_t *counter;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	ipsec_stack_t	*ipss;
	ip_stack_t	*ipst;

	ASSERT(mctl_present || !secure);

	ASSERT((ipha == NULL && ip6h != NULL) ||
	    (ip6h == NULL && ipha != NULL));

	/*
	 * We don't necessarily have an ipsec_in_act action to verify
	 * policy because of assymetrical policy where we have only
	 * outbound policy and no inbound policy (possible with global
	 * policy).
	 */
	if (!secure) {
		if (act == NULL || act->ipa_act.ipa_type == IPSEC_ACT_BYPASS ||
		    act->ipa_act.ipa_type == IPSEC_ACT_CLEAR)
			return (B_TRUE);
		ipsec_log_policy_failure(IPSEC_POLICY_MISMATCH,
		    "tcp_check_policy", ipha, ip6h, secure,
		    tcps->tcps_netstack);
		ipss = tcps->tcps_netstack->netstack_ipsec;

		ip_drop_packet(first_mp, B_TRUE, NULL, NULL,
		    DROPPER(ipss, ipds_tcp_clear),
		    &tcps->tcps_dropper);
		return (B_FALSE);
	}

	/*
	 * We have a secure packet.
	 */
	if (act == NULL) {
		ipsec_log_policy_failure(IPSEC_POLICY_NOT_NEEDED,
		    "tcp_check_policy", ipha, ip6h, secure,
		    tcps->tcps_netstack);
		ipss = tcps->tcps_netstack->netstack_ipsec;

		ip_drop_packet(first_mp, B_TRUE, NULL, NULL,
		    DROPPER(ipss, ipds_tcp_secure),
		    &tcps->tcps_dropper);
		return (B_FALSE);
	}

	/*
	 * XXX This whole routine is currently incorrect.  ipl should
	 * be set to the latch pointer, but is currently not set, so
	 * we initialize it to NULL to avoid picking up random garbage.
	 */
	if (ipl == NULL)
		return (B_TRUE);

	data_mp = first_mp->b_cont;

	ii = (ipsec_in_t *)first_mp->b_rptr;

	ipst = tcps->tcps_netstack->netstack_ip;

	if (ipsec_check_ipsecin_latch(ii, data_mp, ipl, ipha, ip6h, &reason,
	    &counter, tcp->tcp_connp)) {
		BUMP_MIB(&ipst->ips_ip_mib, ipsecInSucceeded);
		return (B_TRUE);
	}
	(void) strlog(TCP_MOD_ID, 0, 0, SL_ERROR|SL_WARN|SL_CONSOLE,
	    "tcp inbound policy mismatch: %s, packet dropped\n",
	    reason);
	BUMP_MIB(&ipst->ips_ip_mib, ipsecInFailed);

	ip_drop_packet(first_mp, B_TRUE, NULL, NULL, counter,
	    &tcps->tcps_dropper);
	return (B_FALSE);
}

/*
 * tcp_ss_rexmit() is called in tcp_rput_data() to do slow start
 * retransmission after a timeout.
 *
 * To limit the number of duplicate segments, we limit the number of segment
 * to be sent in one time to tcp_snd_burst, the burst variable.
 */
static void
tcp_ss_rexmit(tcp_t *tcp)
{
	uint32_t	snxt;
	uint32_t	smax;
	int32_t		win;
	int32_t		mss;
	int32_t		off;
	int32_t		burst = tcp->tcp_snd_burst;
	mblk_t		*snxt_mp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	/*
	 * Note that tcp_rexmit can be set even though TCP has retransmitted
	 * all unack'ed segments.
	 */
	if (SEQ_LT(tcp->tcp_rexmit_nxt, tcp->tcp_rexmit_max)) {
		smax = tcp->tcp_rexmit_max;
		snxt = tcp->tcp_rexmit_nxt;
		if (SEQ_LT(snxt, tcp->tcp_suna)) {
			snxt = tcp->tcp_suna;
		}
		win = MIN(tcp->tcp_cwnd, tcp->tcp_swnd);
		win -= snxt - tcp->tcp_suna;
		mss = tcp->tcp_mss;
		snxt_mp = tcp_get_seg_mp(tcp, snxt, &off);

		while (SEQ_LT(snxt, smax) && (win > 0) &&
		    (burst > 0) && (snxt_mp != NULL)) {
			mblk_t	*xmit_mp;
			mblk_t	*old_snxt_mp = snxt_mp;
			uint32_t cnt = mss;

			if (win < cnt) {
				cnt = win;
			}
			if (SEQ_GT(snxt + cnt, smax)) {
				cnt = smax - snxt;
			}
			xmit_mp = tcp_xmit_mp(tcp, snxt_mp, cnt, &off,
			    &snxt_mp, snxt, B_TRUE, &cnt, B_TRUE);
			if (xmit_mp == NULL)
				return;

			tcp_send_data(tcp, tcp->tcp_wq, xmit_mp);

			snxt += cnt;
			win -= cnt;
			/*
			 * Update the send timestamp to avoid false
			 * retransmission.
			 */
			old_snxt_mp->b_prev = (mblk_t *)lbolt;
			BUMP_MIB(&tcps->tcps_mib, tcpRetransSegs);
			UPDATE_MIB(&tcps->tcps_mib, tcpRetransBytes, cnt);

			tcp->tcp_rexmit_nxt = snxt;
			burst--;
		}
		/*
		 * If we have transmitted all we have at the time
		 * we started the retranmission, we can leave
		 * the rest of the job to tcp_wput_data().  But we
		 * need to check the send window first.  If the
		 * win is not 0, go on with tcp_wput_data().
		 */
		if (SEQ_LT(snxt, smax) || win == 0) {
			return;
		}
	}
	/* Only call tcp_wput_data() if there is data to be sent. */
	if (tcp->tcp_unsent) {
		tcp_wput_data(tcp, NULL, B_FALSE);
	}
}

/*
 * Process all TCP option in SYN segment.  Note that this function should
 * be called after tcp_adapt_ire() is called so that the necessary info
 * from IRE is already set in the tcp structure.
 *
 * This function sets up the correct tcp_mss value according to the
 * MSS option value and our header size.  It also sets up the window scale
 * and timestamp values, and initialize SACK info blocks.  But it does not
 * change receive window size after setting the tcp_mss value.  The caller
 * should do the appropriate change.
 */
void
tcp_process_options(tcp_t *tcp, tcph_t *tcph)
{
	int options;
	tcp_opt_t tcpopt;
	uint32_t mss_max;
	char *tmp_tcph;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	tcpopt.tcp = NULL;
	options = tcp_parse_options(tcph, &tcpopt);

	/*
	 * Process MSS option.  Note that MSS option value does not account
	 * for IP or TCP options.  This means that it is equal to MTU - minimum
	 * IP+TCP header size, which is 40 bytes for IPv4 and 60 bytes for
	 * IPv6.
	 */
	if (!(options & TCP_OPT_MSS_PRESENT)) {
		if (tcp->tcp_ipversion == IPV4_VERSION)
			tcpopt.tcp_opt_mss = tcps->tcps_mss_def_ipv4;
		else
			tcpopt.tcp_opt_mss = tcps->tcps_mss_def_ipv6;
	} else {
		if (tcp->tcp_ipversion == IPV4_VERSION)
			mss_max = tcps->tcps_mss_max_ipv4;
		else
			mss_max = tcps->tcps_mss_max_ipv6;
		if (tcpopt.tcp_opt_mss < tcps->tcps_mss_min)
			tcpopt.tcp_opt_mss = tcps->tcps_mss_min;
		else if (tcpopt.tcp_opt_mss > mss_max)
			tcpopt.tcp_opt_mss = mss_max;
	}

	/* Process Window Scale option. */
	if (options & TCP_OPT_WSCALE_PRESENT) {
		tcp->tcp_snd_ws = tcpopt.tcp_opt_wscale;
		tcp->tcp_snd_ws_ok = B_TRUE;
	} else {
		tcp->tcp_snd_ws = B_FALSE;
		tcp->tcp_snd_ws_ok = B_FALSE;
		tcp->tcp_rcv_ws = B_FALSE;
	}

	/* Process Timestamp option. */
	if ((options & TCP_OPT_TSTAMP_PRESENT) &&
	    (tcp->tcp_snd_ts_ok || TCP_IS_DETACHED(tcp))) {
		tmp_tcph = (char *)tcp->tcp_tcph;

		tcp->tcp_snd_ts_ok = B_TRUE;
		tcp->tcp_ts_recent = tcpopt.tcp_opt_ts_val;
		tcp->tcp_last_rcv_lbolt = lbolt64;
		ASSERT(OK_32PTR(tmp_tcph));
		ASSERT(tcp->tcp_tcp_hdr_len == TCP_MIN_HEADER_LENGTH);

		/* Fill in our template header with basic timestamp option. */
		tmp_tcph += tcp->tcp_tcp_hdr_len;
		tmp_tcph[0] = TCPOPT_NOP;
		tmp_tcph[1] = TCPOPT_NOP;
		tmp_tcph[2] = TCPOPT_TSTAMP;
		tmp_tcph[3] = TCPOPT_TSTAMP_LEN;
		tcp->tcp_hdr_len += TCPOPT_REAL_TS_LEN;
		tcp->tcp_tcp_hdr_len += TCPOPT_REAL_TS_LEN;
		tcp->tcp_tcph->th_offset_and_rsrvd[0] += (3 << 4);
	} else {
		tcp->tcp_snd_ts_ok = B_FALSE;
	}

	/*
	 * Process SACK options.  If SACK is enabled for this connection,
	 * then allocate the SACK info structure.  Note the following ways
	 * when tcp_snd_sack_ok is set to true.
	 *
	 * For active connection: in tcp_adapt_ire() called in
	 * tcp_rput_other(), or in tcp_rput_other() when tcp_sack_permitted
	 * is checked.
	 *
	 * For passive connection: in tcp_adapt_ire() called in
	 * tcp_accept_comm().
	 *
	 * That's the reason why the extra TCP_IS_DETACHED() check is there.
	 * That check makes sure that if we did not send a SACK OK option,
	 * we will not enable SACK for this connection even though the other
	 * side sends us SACK OK option.  For active connection, the SACK
	 * info structure has already been allocated.  So we need to free
	 * it if SACK is disabled.
	 */
	if ((options & TCP_OPT_SACK_OK_PRESENT) &&
	    (tcp->tcp_snd_sack_ok ||
	    (tcps->tcps_sack_permitted != 0 && TCP_IS_DETACHED(tcp)))) {
		/* This should be true only in the passive case. */
		if (tcp->tcp_sack_info == NULL) {
			ASSERT(TCP_IS_DETACHED(tcp));
			tcp->tcp_sack_info =
			    kmem_cache_alloc(tcp_sack_info_cache, KM_NOSLEEP);
		}
		if (tcp->tcp_sack_info == NULL) {
			tcp->tcp_snd_sack_ok = B_FALSE;
		} else {
			tcp->tcp_snd_sack_ok = B_TRUE;
			if (tcp->tcp_snd_ts_ok) {
				tcp->tcp_max_sack_blk = 3;
			} else {
				tcp->tcp_max_sack_blk = 4;
			}
		}
	} else {
		/*
		 * Resetting tcp_snd_sack_ok to B_FALSE so that
		 * no SACK info will be used for this
		 * connection.  This assumes that SACK usage
		 * permission is negotiated.  This may need
		 * to be changed once this is clarified.
		 */
		if (tcp->tcp_sack_info != NULL) {
			ASSERT(tcp->tcp_notsack_list == NULL);
			kmem_cache_free(tcp_sack_info_cache,
			    tcp->tcp_sack_info);
			tcp->tcp_sack_info = NULL;
		}
		tcp->tcp_snd_sack_ok = B_FALSE;
	}

	/*
	 * Now we know the exact TCP/IP header length, subtract
	 * that from tcp_mss to get our side's MSS.
	 */
	tcp->tcp_mss -= tcp->tcp_hdr_len;
	/*
	 * Here we assume that the other side's header size will be equal to
	 * our header size.  We calculate the real MSS accordingly.  Need to
	 * take into additional stuffs IPsec puts in.
	 *
	 * Real MSS = Opt.MSS - (our TCP/IP header - min TCP/IP header)
	 */
	tcpopt.tcp_opt_mss -= tcp->tcp_hdr_len + tcp->tcp_ipsec_overhead -
	    ((tcp->tcp_ipversion == IPV4_VERSION ?
	    IP_SIMPLE_HDR_LENGTH : IPV6_HDR_LEN) + TCP_MIN_HEADER_LENGTH);

	/*
	 * Set MSS to the smaller one of both ends of the connection.
	 * We should not have called tcp_mss_set() before, but our
	 * side of the MSS should have been set to a proper value
	 * by tcp_adapt_ire().  tcp_mss_set() will also set up the
	 * STREAM head parameters properly.
	 *
	 * If we have a larger-than-16-bit window but the other side
	 * didn't want to do window scale, tcp_rwnd_set() will take
	 * care of that.
	 */
	tcp_mss_set(tcp, MIN(tcpopt.tcp_opt_mss, tcp->tcp_mss), B_TRUE);
}

/*
 * Sends the T_CONN_IND to the listener. The caller calls this
 * functions via squeue to get inside the listener's perimeter
 * once the 3 way hand shake is done a T_CONN_IND needs to be
 * sent. As an optimization, the caller can call this directly
 * if listener's perimeter is same as eager's.
 */
/* ARGSUSED */
void
tcp_send_conn_ind(void *arg, mblk_t *mp, void *arg2)
{
	conn_t			*lconnp = (conn_t *)arg;
	tcp_t			*listener = lconnp->conn_tcp;
	tcp_t			*tcp;
	struct T_conn_ind	*conn_ind;
	ipaddr_t 		*addr_cache;
	boolean_t		need_send_conn_ind = B_FALSE;
	tcp_stack_t		*tcps = listener->tcp_tcps;

	/* retrieve the eager */
	conn_ind = (struct T_conn_ind *)mp->b_rptr;
	ASSERT(conn_ind->OPT_offset != 0 &&
	    conn_ind->OPT_length == sizeof (intptr_t));
	bcopy(mp->b_rptr + conn_ind->OPT_offset, &tcp,
	    conn_ind->OPT_length);

	/*
	 * TLI/XTI applications will get confused by
	 * sending eager as an option since it violates
	 * the option semantics. So remove the eager as
	 * option since TLI/XTI app doesn't need it anyway.
	 */
	if (!TCP_IS_SOCKET(listener)) {
		conn_ind->OPT_length = 0;
		conn_ind->OPT_offset = 0;
	}
	if (listener->tcp_state == TCPS_CLOSED ||
	    TCP_IS_DETACHED(listener)) {
		/*
		 * If listener has closed, it would have caused a
		 * a cleanup/blowoff to happen for the eager. We
		 * just need to return.
		 */
		freemsg(mp);
		return;
	}


	/*
	 * if the conn_req_q is full defer passing up the
	 * T_CONN_IND until space is availabe after t_accept()
	 * processing
	 */
	mutex_enter(&listener->tcp_eager_lock);

	/*
	 * Take the eager out, if it is in the list of droppable eagers
	 * as we are here because the 3W handshake is over.
	 */
	MAKE_UNDROPPABLE(tcp);

	if (listener->tcp_conn_req_cnt_q < listener->tcp_conn_req_max) {
		tcp_t *tail;

		/*
		 * The eager already has an extra ref put in tcp_rput_data
		 * so that it stays till accept comes back even though it
		 * might get into TCPS_CLOSED as a result of a TH_RST etc.
		 */
		ASSERT(listener->tcp_conn_req_cnt_q0 > 0);
		listener->tcp_conn_req_cnt_q0--;
		listener->tcp_conn_req_cnt_q++;

		/* Move from SYN_RCVD to ESTABLISHED list  */
		tcp->tcp_eager_next_q0->tcp_eager_prev_q0 =
		    tcp->tcp_eager_prev_q0;
		tcp->tcp_eager_prev_q0->tcp_eager_next_q0 =
		    tcp->tcp_eager_next_q0;
		tcp->tcp_eager_prev_q0 = NULL;
		tcp->tcp_eager_next_q0 = NULL;

		/*
		 * Insert at end of the queue because sockfs
		 * sends down T_CONN_RES in chronological
		 * order. Leaving the older conn indications
		 * at front of the queue helps reducing search
		 * time.
		 */
		tail = listener->tcp_eager_last_q;
		if (tail != NULL)
			tail->tcp_eager_next_q = tcp;
		else
			listener->tcp_eager_next_q = tcp;
		listener->tcp_eager_last_q = tcp;
		tcp->tcp_eager_next_q = NULL;
		/*
		 * Delay sending up the T_conn_ind until we are
		 * done with the eager. Once we have have sent up
		 * the T_conn_ind, the accept can potentially complete
		 * any time and release the refhold we have on the eager.
		 */
		need_send_conn_ind = B_TRUE;
	} else {
		/*
		 * Defer connection on q0 and set deferred
		 * connection bit true
		 */
		tcp->tcp_conn_def_q0 = B_TRUE;

		/* take tcp out of q0 ... */
		tcp->tcp_eager_prev_q0->tcp_eager_next_q0 =
		    tcp->tcp_eager_next_q0;
		tcp->tcp_eager_next_q0->tcp_eager_prev_q0 =
		    tcp->tcp_eager_prev_q0;

		/* ... and place it at the end of q0 */
		tcp->tcp_eager_prev_q0 = listener->tcp_eager_prev_q0;
		tcp->tcp_eager_next_q0 = listener;
		listener->tcp_eager_prev_q0->tcp_eager_next_q0 = tcp;
		listener->tcp_eager_prev_q0 = tcp;
		tcp->tcp_conn.tcp_eager_conn_ind = mp;
	}

	/* we have timed out before */
	if (tcp->tcp_syn_rcvd_timeout != 0) {
		tcp->tcp_syn_rcvd_timeout = 0;
		listener->tcp_syn_rcvd_timeout--;
		if (listener->tcp_syn_defense &&
		    listener->tcp_syn_rcvd_timeout <=
		    (tcps->tcps_conn_req_max_q0 >> 5) &&
		    10*MINUTES < TICK_TO_MSEC(lbolt64 -
		    listener->tcp_last_rcv_lbolt)) {
			/*
			 * Turn off the defense mode if we
			 * believe the SYN attack is over.
			 */
			listener->tcp_syn_defense = B_FALSE;
			if (listener->tcp_ip_addr_cache) {
				kmem_free((void *)listener->tcp_ip_addr_cache,
				    IP_ADDR_CACHE_SIZE * sizeof (ipaddr_t));
				listener->tcp_ip_addr_cache = NULL;
			}
		}
	}
	addr_cache = (ipaddr_t *)(listener->tcp_ip_addr_cache);
	if (addr_cache != NULL) {
		/*
		 * We have finished a 3-way handshake with this
		 * remote host. This proves the IP addr is good.
		 * Cache it!
		 */
		addr_cache[IP_ADDR_CACHE_HASH(
		    tcp->tcp_remote)] = tcp->tcp_remote;
	}
	mutex_exit(&listener->tcp_eager_lock);
	if (need_send_conn_ind) {
		if (IPCL_IS_NONSTR(lconnp)) {
			ASSERT(tcp->tcp_listener == listener);
			ASSERT(tcp->tcp_saved_listener == listener);
			if ((*lconnp->conn_upcalls->su_newconn)
			    (lconnp->conn_upper_handle,
			    (sock_lower_handle_t)tcp->tcp_connp,
			    &sock_tcp_downcalls, DB_CRED(mp), DB_CPID(mp),
			    &tcp->tcp_connp->conn_upcalls) != NULL) {
				/*
				 * Keep the message around
				 * in case of fallback
				 */
				tcp->tcp_conn.tcp_eager_conn_ind = mp;
			} else {
				freemsg(mp);
			}
		} else {
			putnext(listener->tcp_rq, mp);
		}
	}
}

mblk_t *
tcp_find_pktinfo(tcp_t *tcp, mblk_t *mp, uint_t *ipversp, uint_t *ip_hdr_lenp,
    uint_t *ifindexp, ip6_pkt_t *ippp)
{
	ip_pktinfo_t	*pinfo;
	ip6_t		*ip6h;
	uchar_t		*rptr;
	mblk_t		*first_mp = mp;
	boolean_t	mctl_present = B_FALSE;
	uint_t 		ifindex = 0;
	ip6_pkt_t	ipp;
	uint_t		ipvers;
	uint_t		ip_hdr_len;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	rptr = mp->b_rptr;
	ASSERT(OK_32PTR(rptr));
	ASSERT(tcp != NULL);
	ipp.ipp_fields = 0;

	switch DB_TYPE(mp) {
	case M_CTL:
		mp = mp->b_cont;
		if (mp == NULL) {
			freemsg(first_mp);
			return (NULL);
		}
		if (DB_TYPE(mp) != M_DATA) {
			freemsg(first_mp);
			return (NULL);
		}
		mctl_present = B_TRUE;
		break;
	case M_DATA:
		break;
	default:
		cmn_err(CE_NOTE, "tcp_find_pktinfo: unknown db_type");
		freemsg(mp);
		return (NULL);
	}
	ipvers = IPH_HDR_VERSION(rptr);
	if (ipvers == IPV4_VERSION) {
		if (tcp == NULL) {
			ip_hdr_len = IPH_HDR_LENGTH(rptr);
			goto done;
		}

		ipp.ipp_fields |= IPPF_HOPLIMIT;
		ipp.ipp_hoplimit = ((ipha_t *)rptr)->ipha_ttl;

		/*
		 * If we have IN_PKTINFO in an M_CTL and tcp_ipv6_recvancillary
		 * has TCP_IPV6_RECVPKTINFO set, pass I/F index along in ipp.
		 */
		if ((tcp->tcp_ipv6_recvancillary & TCP_IPV6_RECVPKTINFO) &&
		    mctl_present) {
			pinfo = (ip_pktinfo_t *)first_mp->b_rptr;
			if ((MBLKL(first_mp) == sizeof (ip_pktinfo_t)) &&
			    (pinfo->ip_pkt_ulp_type == IN_PKTINFO) &&
			    (pinfo->ip_pkt_flags & IPF_RECVIF)) {
				ipp.ipp_fields |= IPPF_IFINDEX;
				ipp.ipp_ifindex = pinfo->ip_pkt_ifindex;
				ifindex = pinfo->ip_pkt_ifindex;
			}
			freeb(first_mp);
			mctl_present = B_FALSE;
		}
		ip_hdr_len = IPH_HDR_LENGTH(rptr);
	} else {
		ip6h = (ip6_t *)rptr;

		ASSERT(ipvers == IPV6_VERSION);
		ipp.ipp_fields = IPPF_HOPLIMIT | IPPF_TCLASS;
		ipp.ipp_tclass = (ip6h->ip6_flow & 0x0FF00000) >> 20;
		ipp.ipp_hoplimit = ip6h->ip6_hops;

		if (ip6h->ip6_nxt != IPPROTO_TCP) {
			uint8_t	nexthdrp;
			ip_stack_t *ipst = tcps->tcps_netstack->netstack_ip;

			/* Look for ifindex information */
			if (ip6h->ip6_nxt == IPPROTO_RAW) {
				ip6i_t *ip6i = (ip6i_t *)ip6h;
				if ((uchar_t *)&ip6i[1] > mp->b_wptr) {
					BUMP_MIB(&ipst->ips_ip_mib, tcpInErrs);
					freemsg(first_mp);
					return (NULL);
				}

				if (ip6i->ip6i_flags & IP6I_IFINDEX) {
					ASSERT(ip6i->ip6i_ifindex != 0);
					ipp.ipp_fields |= IPPF_IFINDEX;
					ipp.ipp_ifindex = ip6i->ip6i_ifindex;
					ifindex = ip6i->ip6i_ifindex;
				}
				rptr = (uchar_t *)&ip6i[1];
				mp->b_rptr = rptr;
				if (rptr == mp->b_wptr) {
					mblk_t *mp1;
					mp1 = mp->b_cont;
					freeb(mp);
					mp = mp1;
					rptr = mp->b_rptr;
				}
				if (MBLKL(mp) < IPV6_HDR_LEN +
				    sizeof (tcph_t)) {
					BUMP_MIB(&ipst->ips_ip_mib, tcpInErrs);
					freemsg(first_mp);
					return (NULL);
				}
				ip6h = (ip6_t *)rptr;
			}

			/*
			 * Find any potentially interesting extension headers
			 * as well as the length of the IPv6 + extension
			 * headers.
			 */
			ip_hdr_len = ip_find_hdr_v6(mp, ip6h, &ipp, &nexthdrp);
			/* Verify if this is a TCP packet */
			if (nexthdrp != IPPROTO_TCP) {
				BUMP_MIB(&ipst->ips_ip_mib, tcpInErrs);
				freemsg(first_mp);
				return (NULL);
			}
		} else {
			ip_hdr_len = IPV6_HDR_LEN;
		}
	}

done:
	if (ipversp != NULL)
		*ipversp = ipvers;
	if (ip_hdr_lenp != NULL)
		*ip_hdr_lenp = ip_hdr_len;
	if (ippp != NULL)
		*ippp = ipp;
	if (ifindexp != NULL)
		*ifindexp = ifindex;
	if (mctl_present) {
		freeb(first_mp);
	}
	return (mp);
}

/*
 * Handle M_DATA messages from IP. Its called directly from IP via
 * squeue for AF_INET type sockets fast path. No M_CTL are expected
 * in this path.
 *
 * For everything else (including AF_INET6 sockets with 'tcp_ipversion'
 * v4 and v6), we are called through tcp_input() and a M_CTL can
 * be present for options but tcp_find_pktinfo() deals with it. We
 * only expect M_DATA packets after tcp_find_pktinfo() is done.
 *
 * The first argument is always the connp/tcp to which the mp belongs.
 * There are no exceptions to this rule. The caller has already put
 * a reference on this connp/tcp and once tcp_rput_data() returns,
 * the squeue will do the refrele.
 *
 * The TH_SYN for the listener directly go to tcp_conn_request via
 * squeue.
 *
 * sqp: NULL = recursive, sqp != NULL means called from squeue
 */
void
tcp_rput_data(void *arg, mblk_t *mp, void *arg2)
{
	int32_t		bytes_acked;
	int32_t		gap;
	mblk_t		*mp1;
	uint_t		flags;
	uint32_t	new_swnd = 0;
	uchar_t		*iphdr;
	uchar_t		*rptr;
	int32_t		rgap;
	uint32_t	seg_ack;
	int		seg_len;
	uint_t		ip_hdr_len;
	uint32_t	seg_seq;
	tcph_t		*tcph;
	int		urp;
	tcp_opt_t	tcpopt;
	uint_t		ipvers;
	ip6_pkt_t	ipp;
	boolean_t	ofo_seg = B_FALSE; /* Out of order segment */
	uint32_t	cwnd;
	uint32_t	add;
	int		npkt;
	int		mss;
	conn_t		*connp = (conn_t *)arg;
	squeue_t	*sqp = (squeue_t *)arg2;
	tcp_t		*tcp = connp->conn_tcp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	/*
	 * RST from fused tcp loopback peer should trigger an unfuse.
	 */
	if (tcp->tcp_fused) {
		TCP_STAT(tcps, tcp_fusion_aborted);
		tcp_unfuse(tcp);
	}

	iphdr = mp->b_rptr;
	rptr = mp->b_rptr;
	ASSERT(OK_32PTR(rptr));

	/*
	 * An AF_INET socket is not capable of receiving any pktinfo. Do inline
	 * processing here. For rest call tcp_find_pktinfo to fill up the
	 * necessary information.
	 */
	if (IPCL_IS_TCP4(connp)) {
		ipvers = IPV4_VERSION;
		ip_hdr_len = IPH_HDR_LENGTH(rptr);
	} else {
		mp = tcp_find_pktinfo(tcp, mp, &ipvers, &ip_hdr_len,
		    NULL, &ipp);
		if (mp == NULL) {
			TCP_STAT(tcps, tcp_rput_v6_error);
			return;
		}
		iphdr = mp->b_rptr;
		rptr = mp->b_rptr;
	}
	ASSERT(DB_TYPE(mp) == M_DATA);
	ASSERT(mp->b_next == NULL);

	tcph = (tcph_t *)&rptr[ip_hdr_len];
	seg_seq = ABE32_TO_U32(tcph->th_seq);
	seg_ack = ABE32_TO_U32(tcph->th_ack);
	ASSERT((uintptr_t)(mp->b_wptr - rptr) <= (uintptr_t)INT_MAX);
	seg_len = (int)(mp->b_wptr - rptr) -
	    (ip_hdr_len + TCP_HDR_LENGTH(tcph));
	if ((mp1 = mp->b_cont) != NULL && mp1->b_datap->db_type == M_DATA) {
		do {
			ASSERT((uintptr_t)(mp1->b_wptr - mp1->b_rptr) <=
			    (uintptr_t)INT_MAX);
			seg_len += (int)(mp1->b_wptr - mp1->b_rptr);
		} while ((mp1 = mp1->b_cont) != NULL &&
		    mp1->b_datap->db_type == M_DATA);
	}

	if (tcp->tcp_state == TCPS_TIME_WAIT) {
		tcp_time_wait_processing(tcp, mp, seg_seq, seg_ack,
		    seg_len, tcph);
		return;
	}

	if (sqp != NULL) {
		/*
		 * This is the correct place to update tcp_last_recv_time. Note
		 * that it is also updated for tcp structure that belongs to
		 * global and listener queues which do not really need updating.
		 * But that should not cause any harm.  And it is updated for
		 * all kinds of incoming segments, not only for data segments.
		 */
		tcp->tcp_last_recv_time = lbolt;
	}

	flags = (unsigned int)tcph->th_flags[0] & 0xFF;

	BUMP_LOCAL(tcp->tcp_ibsegs);
	DTRACE_PROBE2(tcp__trace__recv, mblk_t *, mp, tcp_t *, tcp);

	if ((flags & TH_URG) && sqp != NULL) {
		/*
		 * TCP can't handle urgent pointers that arrive before
		 * the connection has been accept()ed since it can't
		 * buffer OOB data.  Discard segment if this happens.
		 *
		 * We can't just rely on a non-null tcp_listener to indicate
		 * that the accept() has completed since unlinking of the
		 * eager and completion of the accept are not atomic.
		 * tcp_detached, when it is not set (B_FALSE) indicates
		 * that the accept() has completed.
		 *
		 * Nor can it reassemble urgent pointers, so discard
		 * if it's not the next segment expected.
		 *
		 * Otherwise, collapse chain into one mblk (discard if
		 * that fails).  This makes sure the headers, retransmitted
		 * data, and new data all are in the same mblk.
		 */
		ASSERT(mp != NULL);
		if (tcp->tcp_detached || !pullupmsg(mp, -1)) {
			freemsg(mp);
			return;
		}
		/* Update pointers into message */
		iphdr = rptr = mp->b_rptr;
		tcph = (tcph_t *)&rptr[ip_hdr_len];
		if (SEQ_GT(seg_seq, tcp->tcp_rnxt)) {
			/*
			 * Since we can't handle any data with this urgent
			 * pointer that is out of sequence, we expunge
			 * the data.  This allows us to still register
			 * the urgent mark and generate the M_PCSIG,
			 * which we can do.
			 */
			mp->b_wptr = (uchar_t *)tcph + TCP_HDR_LENGTH(tcph);
			seg_len = 0;
		}
	}

	switch (tcp->tcp_state) {
	case TCPS_SYN_SENT:
		if (flags & TH_ACK) {
			/*
			 * Note that our stack cannot send data before a
			 * connection is established, therefore the
			 * following check is valid.  Otherwise, it has
			 * to be changed.
			 */
			if (SEQ_LEQ(seg_ack, tcp->tcp_iss) ||
			    SEQ_GT(seg_ack, tcp->tcp_snxt)) {
				freemsg(mp);
				if (flags & TH_RST)
					return;
				tcp_xmit_ctl("TCPS_SYN_SENT-Bad_seq",
				    tcp, seg_ack, 0, TH_RST);
				return;
			}
			ASSERT(tcp->tcp_suna + 1 == seg_ack);
		}
		if (flags & TH_RST) {
			freemsg(mp);
			if (flags & TH_ACK)
				(void) tcp_clean_death(tcp,
				    ECONNREFUSED, 13);
			return;
		}
		if (!(flags & TH_SYN)) {
			freemsg(mp);
			return;
		}

		/* Process all TCP options. */
		tcp_process_options(tcp, tcph);
		/*
		 * The following changes our rwnd to be a multiple of the
		 * MIN(peer MSS, our MSS) for performance reason.
		 */
		(void) tcp_rwnd_set(tcp,
		    MSS_ROUNDUP(tcp->tcp_recv_hiwater, tcp->tcp_mss));

		/* Is the other end ECN capable? */
		if (tcp->tcp_ecn_ok) {
			if ((flags & (TH_ECE|TH_CWR)) != TH_ECE) {
				tcp->tcp_ecn_ok = B_FALSE;
			}
		}
		/*
		 * Clear ECN flags because it may interfere with later
		 * processing.
		 */
		flags &= ~(TH_ECE|TH_CWR);

		tcp->tcp_irs = seg_seq;
		tcp->tcp_rack = seg_seq;
		tcp->tcp_rnxt = seg_seq + 1;
		U32_TO_ABE32(tcp->tcp_rnxt, tcp->tcp_tcph->th_ack);
		if (!TCP_IS_DETACHED(tcp)) {
			/* Allocate room for SACK options if needed. */
			if (tcp->tcp_snd_sack_ok) {
				(void) proto_set_tx_wroff(tcp->tcp_rq, connp,
				    tcp->tcp_hdr_len +
				    TCPOPT_MAX_SACK_LEN +
				    (tcp->tcp_loopback ? 0 :
				    tcps->tcps_wroff_xtra));
			} else {
				(void) proto_set_tx_wroff(tcp->tcp_rq, connp,
				    tcp->tcp_hdr_len +
				    (tcp->tcp_loopback ? 0 :
				    tcps->tcps_wroff_xtra));
			}
		}
		if (flags & TH_ACK) {
			/*
			 * If we can't get the confirmation upstream, pretend
			 * we didn't even see this one.
			 *
			 * XXX: how can we pretend we didn't see it if we
			 * have updated rnxt et. al.
			 *
			 * For loopback we defer sending up the T_CONN_CON
			 * until after some checks below.
			 */
			mp1 = NULL;
			if (!tcp_conn_con(tcp, iphdr, tcph, mp,
			    tcp->tcp_loopback ? &mp1 : NULL)) {
				freemsg(mp);
				return;
			}
			/* SYN was acked - making progress */
			if (tcp->tcp_ipversion == IPV6_VERSION)
				tcp->tcp_ip_forward_progress = B_TRUE;

			/* One for the SYN */
			tcp->tcp_suna = tcp->tcp_iss + 1;
			tcp->tcp_valid_bits &= ~TCP_ISS_VALID;
			tcp->tcp_state = TCPS_ESTABLISHED;

			/*
			 * If SYN was retransmitted, need to reset all
			 * retransmission info.  This is because this
			 * segment will be treated as a dup ACK.
			 */
			if (tcp->tcp_rexmit) {
				tcp->tcp_rexmit = B_FALSE;
				tcp->tcp_rexmit_nxt = tcp->tcp_snxt;
				tcp->tcp_rexmit_max = tcp->tcp_snxt;
				tcp->tcp_snd_burst = tcp->tcp_localnet ?
				    TCP_CWND_INFINITE : TCP_CWND_NORMAL;
				tcp->tcp_ms_we_have_waited = 0;

				/*
				 * Set tcp_cwnd back to 1 MSS, per
				 * recommendation from
				 * draft-floyd-incr-init-win-01.txt,
				 * Increasing TCP's Initial Window.
				 */
				tcp->tcp_cwnd = tcp->tcp_mss;
			}

			tcp->tcp_swl1 = seg_seq;
			tcp->tcp_swl2 = seg_ack;

			new_swnd = BE16_TO_U16(tcph->th_win);
			tcp->tcp_swnd = new_swnd;
			if (new_swnd > tcp->tcp_max_swnd)
				tcp->tcp_max_swnd = new_swnd;

			/*
			 * Always send the three-way handshake ack immediately
			 * in order to make the connection complete as soon as
			 * possible on the accepting host.
			 */
			flags |= TH_ACK_NEEDED;

			/*
			 * Special case for loopback.  At this point we have
			 * received SYN-ACK from the remote endpoint.  In
			 * order to ensure that both endpoints reach the
			 * fused state prior to any data exchange, the final
			 * ACK needs to be sent before we indicate T_CONN_CON
			 * to the module upstream.
			 */
			if (tcp->tcp_loopback) {
				mblk_t *ack_mp;

				ASSERT(!tcp->tcp_unfusable);
				ASSERT(mp1 != NULL);
				/*
				 * For loopback, we always get a pure SYN-ACK
				 * and only need to send back the final ACK
				 * with no data (this is because the other
				 * tcp is ours and we don't do T/TCP).  This
				 * final ACK triggers the passive side to
				 * perform fusion in ESTABLISHED state.
				 */
				if ((ack_mp = tcp_ack_mp(tcp)) != NULL) {
					if (tcp->tcp_ack_tid != 0) {
						(void) TCP_TIMER_CANCEL(tcp,
						    tcp->tcp_ack_tid);
						tcp->tcp_ack_tid = 0;
					}
					tcp_send_data(tcp, tcp->tcp_wq, ack_mp);
					BUMP_LOCAL(tcp->tcp_obsegs);
					BUMP_MIB(&tcps->tcps_mib, tcpOutAck);

					if (!IPCL_IS_NONSTR(connp)) {
						/* Send up T_CONN_CON */
						putnext(tcp->tcp_rq, mp1);
					} else {
						(*connp->conn_upcalls->
						    su_connected)
						    (connp->conn_upper_handle,
						    tcp->tcp_connid,
						    DB_CRED(mp1),
						    DB_CPID(mp1));
						freemsg(mp1);
					}

					freemsg(mp);
					return;
				}
				/*
				 * Forget fusion; we need to handle more
				 * complex cases below.  Send the deferred
				 * T_CONN_CON message upstream and proceed
				 * as usual.  Mark this tcp as not capable
				 * of fusion.
				 */
				TCP_STAT(tcps, tcp_fusion_unfusable);
				tcp->tcp_unfusable = B_TRUE;
				if (!IPCL_IS_NONSTR(connp)) {
					putnext(tcp->tcp_rq, mp1);
				} else {
					(*connp->conn_upcalls->su_connected)
					    (connp->conn_upper_handle,
					    tcp->tcp_connid, DB_CRED(mp1),
					    DB_CPID(mp1));
					freemsg(mp1);
				}
			}

			/*
			 * Check to see if there is data to be sent.  If
			 * yes, set the transmit flag.  Then check to see
			 * if received data processing needs to be done.
			 * If not, go straight to xmit_check.  This short
			 * cut is OK as we don't support T/TCP.
			 */
			if (tcp->tcp_unsent)
				flags |= TH_XMIT_NEEDED;

			if (seg_len == 0 && !(flags & TH_URG)) {
				freemsg(mp);
				goto xmit_check;
			}

			flags &= ~TH_SYN;
			seg_seq++;
			break;
		}
		tcp->tcp_state = TCPS_SYN_RCVD;
		mp1 = tcp_xmit_mp(tcp, tcp->tcp_xmit_head, tcp->tcp_mss,
		    NULL, NULL, tcp->tcp_iss, B_FALSE, NULL, B_FALSE);
		if (mp1) {
			DB_CPID(mp1) = tcp->tcp_cpid;
			tcp_send_data(tcp, tcp->tcp_wq, mp1);
			TCP_TIMER_RESTART(tcp, tcp->tcp_rto);
		}
		freemsg(mp);
		return;
	case TCPS_SYN_RCVD:
		if (flags & TH_ACK) {
			/*
			 * In this state, a SYN|ACK packet is either bogus
			 * because the other side must be ACKing our SYN which
			 * indicates it has seen the ACK for their SYN and
			 * shouldn't retransmit it or we're crossing SYNs
			 * on active open.
			 */
			if ((flags & TH_SYN) && !tcp->tcp_active_open) {
				freemsg(mp);
				tcp_xmit_ctl("TCPS_SYN_RCVD-bad_syn",
				    tcp, seg_ack, 0, TH_RST);
				return;
			}
			/*
			 * NOTE: RFC 793 pg. 72 says this should be
			 * tcp->tcp_suna <= seg_ack <= tcp->tcp_snxt
			 * but that would mean we have an ack that ignored
			 * our SYN.
			 */
			if (SEQ_LEQ(seg_ack, tcp->tcp_suna) ||
			    SEQ_GT(seg_ack, tcp->tcp_snxt)) {
				freemsg(mp);
				tcp_xmit_ctl("TCPS_SYN_RCVD-bad_ack",
				    tcp, seg_ack, 0, TH_RST);
				return;
			}
		}
		break;
	case TCPS_LISTEN:
		/*
		 * Only a TLI listener can come through this path when a
		 * acceptor is going back to be a listener and a packet
		 * for the acceptor hits the classifier. For a socket
		 * listener, this can never happen because a listener
		 * can never accept connection on itself and hence a
		 * socket acceptor can not go back to being a listener.
		 */
		ASSERT(!TCP_IS_SOCKET(tcp));
		/*FALLTHRU*/
	case TCPS_CLOSED:
	case TCPS_BOUND: {
		conn_t	*new_connp;
		ip_stack_t *ipst = tcps->tcps_netstack->netstack_ip;

		new_connp = ipcl_classify(mp, connp->conn_zoneid, ipst);
		if (new_connp != NULL) {
			tcp_reinput(new_connp, mp, connp->conn_sqp);
			return;
		}
		/* We failed to classify. For now just drop the packet */
		freemsg(mp);
		return;
	}
	case TCPS_IDLE:
		/*
		 * Handle the case where the tcp_clean_death() has happened
		 * on a connection (application hasn't closed yet) but a packet
		 * was already queued on squeue before tcp_clean_death()
		 * was processed. Calling tcp_clean_death() twice on same
		 * connection can result in weird behaviour.
		 */
		freemsg(mp);
		return;
	default:
		break;
	}

	/*
	 * Already on the correct queue/perimeter.
	 * If this is a detached connection and not an eager
	 * connection hanging off a listener then new data
	 * (past the FIN) will cause a reset.
	 * We do a special check here where it
	 * is out of the main line, rather than check
	 * if we are detached every time we see new
	 * data down below.
	 */
	if (TCP_IS_DETACHED_NONEAGER(tcp) &&
	    (seg_len > 0 && SEQ_GT(seg_seq + seg_len, tcp->tcp_rnxt))) {
		BUMP_MIB(&tcps->tcps_mib, tcpInClosed);
		DTRACE_PROBE2(tcp__trace__recv, mblk_t *, mp, tcp_t *, tcp);

		freemsg(mp);
		/*
		 * This could be an SSL closure alert. We're detached so just
		 * acknowledge it this last time.
		 */
		if (tcp->tcp_kssl_ctx != NULL) {
			kssl_release_ctx(tcp->tcp_kssl_ctx);
			tcp->tcp_kssl_ctx = NULL;

			tcp->tcp_rnxt += seg_len;
			U32_TO_ABE32(tcp->tcp_rnxt, tcp->tcp_tcph->th_ack);
			flags |= TH_ACK_NEEDED;
			goto ack_check;
		}

		tcp_xmit_ctl("new data when detached", tcp,
		    tcp->tcp_snxt, 0, TH_RST);
		(void) tcp_clean_death(tcp, EPROTO, 12);
		return;
	}

	mp->b_rptr = (uchar_t *)tcph + TCP_HDR_LENGTH(tcph);
	urp = BE16_TO_U16(tcph->th_urp) - TCP_OLD_URP_INTERPRETATION;
	new_swnd = BE16_TO_U16(tcph->th_win) <<
	    ((tcph->th_flags[0] & TH_SYN) ? 0 : tcp->tcp_snd_ws);

	if (tcp->tcp_snd_ts_ok) {
		if (!tcp_paws_check(tcp, tcph, &tcpopt)) {
			/*
			 * This segment is not acceptable.
			 * Drop it and send back an ACK.
			 */
			freemsg(mp);
			flags |= TH_ACK_NEEDED;
			goto ack_check;
		}
	} else if (tcp->tcp_snd_sack_ok) {
		ASSERT(tcp->tcp_sack_info != NULL);
		tcpopt.tcp = tcp;
		/*
		 * SACK info in already updated in tcp_parse_options.  Ignore
		 * all other TCP options...
		 */
		(void) tcp_parse_options(tcph, &tcpopt);
	}
try_again:;
	mss = tcp->tcp_mss;
	gap = seg_seq - tcp->tcp_rnxt;
	rgap = tcp->tcp_rwnd - (gap + seg_len);
	/*
	 * gap is the amount of sequence space between what we expect to see
	 * and what we got for seg_seq.  A positive value for gap means
	 * something got lost.  A negative value means we got some old stuff.
	 */
	if (gap < 0) {
		/* Old stuff present.  Is the SYN in there? */
		if (seg_seq == tcp->tcp_irs && (flags & TH_SYN) &&
		    (seg_len != 0)) {
			flags &= ~TH_SYN;
			seg_seq++;
			urp--;
			/* Recompute the gaps after noting the SYN. */
			goto try_again;
		}
		BUMP_MIB(&tcps->tcps_mib, tcpInDataDupSegs);
		UPDATE_MIB(&tcps->tcps_mib, tcpInDataDupBytes,
		    (seg_len > -gap ? -gap : seg_len));
		/* Remove the old stuff from seg_len. */
		seg_len += gap;
		/*
		 * Anything left?
		 * Make sure to check for unack'd FIN when rest of data
		 * has been previously ack'd.
		 */
		if (seg_len < 0 || (seg_len == 0 && !(flags & TH_FIN))) {
			/*
			 * Resets are only valid if they lie within our offered
			 * window.  If the RST bit is set, we just ignore this
			 * segment.
			 */
			if (flags & TH_RST) {
				freemsg(mp);
				return;
			}

			/*
			 * The arriving of dup data packets indicate that we
			 * may have postponed an ack for too long, or the other
			 * side's RTT estimate is out of shape. Start acking
			 * more often.
			 */
			if (SEQ_GEQ(seg_seq + seg_len - gap, tcp->tcp_rack) &&
			    tcp->tcp_rack_cnt >= 1 &&
			    tcp->tcp_rack_abs_max > 2) {
				tcp->tcp_rack_abs_max--;
			}
			tcp->tcp_rack_cur_max = 1;

			/*
			 * This segment is "unacceptable".  None of its
			 * sequence space lies within our advertized window.
			 *
			 * Adjust seg_len to the original value for tracing.
			 */
			seg_len -= gap;
			if (tcp->tcp_debug) {
				(void) strlog(TCP_MOD_ID, 0, 1, SL_TRACE,
				    "tcp_rput: unacceptable, gap %d, rgap %d, "
				    "flags 0x%x, seg_seq %u, seg_ack %u, "
				    "seg_len %d, rnxt %u, snxt %u, %s",
				    gap, rgap, flags, seg_seq, seg_ack,
				    seg_len, tcp->tcp_rnxt, tcp->tcp_snxt,
				    tcp_display(tcp, NULL,
				    DISP_ADDR_AND_PORT));
			}

			/*
			 * Arrange to send an ACK in response to the
			 * unacceptable segment per RFC 793 page 69. There
			 * is only one small difference between ours and the
			 * acceptability test in the RFC - we accept ACK-only
			 * packet with SEG.SEQ = RCV.NXT+RCV.WND and no ACK
			 * will be generated.
			 *
			 * Note that we have to ACK an ACK-only packet at least
			 * for stacks that send 0-length keep-alives with
			 * SEG.SEQ = SND.NXT-1 as recommended by RFC1122,
			 * section 4.2.3.6. As long as we don't ever generate
			 * an unacceptable packet in response to an incoming
			 * packet that is unacceptable, it should not cause
			 * "ACK wars".
			 */
			flags |=  TH_ACK_NEEDED;

			/*
			 * Continue processing this segment in order to use the
			 * ACK information it contains, but skip all other
			 * sequence-number processing.	Processing the ACK
			 * information is necessary in order to
			 * re-synchronize connections that may have lost
			 * synchronization.
			 *
			 * We clear seg_len and flag fields related to
			 * sequence number processing as they are not
			 * to be trusted for an unacceptable segment.
			 */
			seg_len = 0;
			flags &= ~(TH_SYN | TH_FIN | TH_URG);
			goto process_ack;
		}

		/* Fix seg_seq, and chew the gap off the front. */
		seg_seq = tcp->tcp_rnxt;
		urp += gap;
		do {
			mblk_t	*mp2;
			ASSERT((uintptr_t)(mp->b_wptr - mp->b_rptr) <=
			    (uintptr_t)UINT_MAX);
			gap += (uint_t)(mp->b_wptr - mp->b_rptr);
			if (gap > 0) {
				mp->b_rptr = mp->b_wptr - gap;
				break;
			}
			mp2 = mp;
			mp = mp->b_cont;
			freeb(mp2);
		} while (gap < 0);
		/*
		 * If the urgent data has already been acknowledged, we
		 * should ignore TH_URG below
		 */
		if (urp < 0)
			flags &= ~TH_URG;
	}
	/*
	 * rgap is the amount of stuff received out of window.  A negative
	 * value is the amount out of window.
	 */
	if (rgap < 0) {
		mblk_t	*mp2;

		if (tcp->tcp_rwnd == 0) {
			BUMP_MIB(&tcps->tcps_mib, tcpInWinProbe);
		} else {
			BUMP_MIB(&tcps->tcps_mib, tcpInDataPastWinSegs);
			UPDATE_MIB(&tcps->tcps_mib,
			    tcpInDataPastWinBytes, -rgap);
		}

		/*
		 * seg_len does not include the FIN, so if more than
		 * just the FIN is out of window, we act like we don't
		 * see it.  (If just the FIN is out of window, rgap
		 * will be zero and we will go ahead and acknowledge
		 * the FIN.)
		 */
		flags &= ~TH_FIN;

		/* Fix seg_len and make sure there is something left. */
		seg_len += rgap;
		if (seg_len <= 0) {
			/*
			 * Resets are only valid if they lie within our offered
			 * window.  If the RST bit is set, we just ignore this
			 * segment.
			 */
			if (flags & TH_RST) {
				freemsg(mp);
				return;
			}

			/* Per RFC 793, we need to send back an ACK. */
			flags |= TH_ACK_NEEDED;

			/*
			 * Send SIGURG as soon as possible i.e. even
			 * if the TH_URG was delivered in a window probe
			 * packet (which will be unacceptable).
			 *
			 * We generate a signal if none has been generated
			 * for this connection or if this is a new urgent
			 * byte. Also send a zero-length "unmarked" message
			 * to inform SIOCATMARK that this is not the mark.
			 *
			 * tcp_urp_last_valid is cleared when the T_exdata_ind
			 * is sent up. This plus the check for old data
			 * (gap >= 0) handles the wraparound of the sequence
			 * number space without having to always track the
			 * correct MAX(tcp_urp_last, tcp_rnxt). (BSD tracks
			 * this max in its rcv_up variable).
			 *
			 * This prevents duplicate SIGURGS due to a "late"
			 * zero-window probe when the T_EXDATA_IND has already
			 * been sent up.
			 */
			if ((flags & TH_URG) &&
			    (!tcp->tcp_urp_last_valid || SEQ_GT(urp + seg_seq,
			    tcp->tcp_urp_last))) {
				if (IPCL_IS_NONSTR(connp)) {
					if (!TCP_IS_DETACHED(tcp)) {
						(*connp->conn_upcalls->
						    su_signal_oob)
						    (connp->conn_upper_handle,
						    urp);
					}
				} else {
					mp1 = allocb(0, BPRI_MED);
					if (mp1 == NULL) {
						freemsg(mp);
						return;
					}
					if (!TCP_IS_DETACHED(tcp) &&
					    !putnextctl1(tcp->tcp_rq,
					    M_PCSIG, SIGURG)) {
						/* Try again on the rexmit. */
						freemsg(mp1);
						freemsg(mp);
						return;
					}
					/*
					 * If the next byte would be the mark
					 * then mark with MARKNEXT else mark
					 * with NOTMARKNEXT.
					 */
					if (gap == 0 && urp == 0)
						mp1->b_flag |= MSGMARKNEXT;
					else
						mp1->b_flag |= MSGNOTMARKNEXT;
					freemsg(tcp->tcp_urp_mark_mp);
					tcp->tcp_urp_mark_mp = mp1;
					flags |= TH_SEND_URP_MARK;
				}
				tcp->tcp_urp_last_valid = B_TRUE;
				tcp->tcp_urp_last = urp + seg_seq;
			}
			/*
			 * If this is a zero window probe, continue to
			 * process the ACK part.  But we need to set seg_len
			 * to 0 to avoid data processing.  Otherwise just
			 * drop the segment and send back an ACK.
			 */
			if (tcp->tcp_rwnd == 0 && seg_seq == tcp->tcp_rnxt) {
				flags &= ~(TH_SYN | TH_URG);
				seg_len = 0;
				goto process_ack;
			} else {
				freemsg(mp);
				goto ack_check;
			}
		}
		/* Pitch out of window stuff off the end. */
		rgap = seg_len;
		mp2 = mp;
		do {
			ASSERT((uintptr_t)(mp2->b_wptr - mp2->b_rptr) <=
			    (uintptr_t)INT_MAX);
			rgap -= (int)(mp2->b_wptr - mp2->b_rptr);
			if (rgap < 0) {
				mp2->b_wptr += rgap;
				if ((mp1 = mp2->b_cont) != NULL) {
					mp2->b_cont = NULL;
					freemsg(mp1);
				}
				break;
			}
		} while ((mp2 = mp2->b_cont) != NULL);
	}
ok:;
	/*
	 * TCP should check ECN info for segments inside the window only.
	 * Therefore the check should be done here.
	 */
	if (tcp->tcp_ecn_ok) {
		if (flags & TH_CWR) {
			tcp->tcp_ecn_echo_on = B_FALSE;
		}
		/*
		 * Note that both ECN_CE and CWR can be set in the
		 * same segment.  In this case, we once again turn
		 * on ECN_ECHO.
		 */
		if (tcp->tcp_ipversion == IPV4_VERSION) {
			uchar_t tos = ((ipha_t *)rptr)->ipha_type_of_service;

			if ((tos & IPH_ECN_CE) == IPH_ECN_CE) {
				tcp->tcp_ecn_echo_on = B_TRUE;
			}
		} else {
			uint32_t vcf = ((ip6_t *)rptr)->ip6_vcf;

			if ((vcf & htonl(IPH_ECN_CE << 20)) ==
			    htonl(IPH_ECN_CE << 20)) {
				tcp->tcp_ecn_echo_on = B_TRUE;
			}
		}
	}

	/*
	 * Check whether we can update tcp_ts_recent.  This test is
	 * NOT the one in RFC 1323 3.4.  It is from Braden, 1993, "TCP
	 * Extensions for High Performance: An Update", Internet Draft.
	 */
	if (tcp->tcp_snd_ts_ok &&
	    TSTMP_GEQ(tcpopt.tcp_opt_ts_val, tcp->tcp_ts_recent) &&
	    SEQ_LEQ(seg_seq, tcp->tcp_rack)) {
		tcp->tcp_ts_recent = tcpopt.tcp_opt_ts_val;
		tcp->tcp_last_rcv_lbolt = lbolt64;
	}

	if (seg_seq != tcp->tcp_rnxt || tcp->tcp_reass_head) {
		/*
		 * FIN in an out of order segment.  We record this in
		 * tcp_valid_bits and the seq num of FIN in tcp_ofo_fin_seq.
		 * Clear the FIN so that any check on FIN flag will fail.
		 * Remember that FIN also counts in the sequence number
		 * space.  So we need to ack out of order FIN only segments.
		 */
		if (flags & TH_FIN) {
			tcp->tcp_valid_bits |= TCP_OFO_FIN_VALID;
			tcp->tcp_ofo_fin_seq = seg_seq + seg_len;
			flags &= ~TH_FIN;
			flags |= TH_ACK_NEEDED;
		}
		if (seg_len > 0) {
			/* Fill in the SACK blk list. */
			if (tcp->tcp_snd_sack_ok) {
				ASSERT(tcp->tcp_sack_info != NULL);
				tcp_sack_insert(tcp->tcp_sack_list,
				    seg_seq, seg_seq + seg_len,
				    &(tcp->tcp_num_sack_blk));
			}

			/*
			 * Attempt reassembly and see if we have something
			 * ready to go.
			 */
			mp = tcp_reass(tcp, mp, seg_seq);
			/* Always ack out of order packets */
			flags |= TH_ACK_NEEDED | TH_PUSH;
			if (mp) {
				ASSERT((uintptr_t)(mp->b_wptr - mp->b_rptr) <=
				    (uintptr_t)INT_MAX);
				seg_len = mp->b_cont ? msgdsize(mp) :
				    (int)(mp->b_wptr - mp->b_rptr);
				seg_seq = tcp->tcp_rnxt;
				/*
				 * A gap is filled and the seq num and len
				 * of the gap match that of a previously
				 * received FIN, put the FIN flag back in.
				 */
				if ((tcp->tcp_valid_bits & TCP_OFO_FIN_VALID) &&
				    seg_seq + seg_len == tcp->tcp_ofo_fin_seq) {
					flags |= TH_FIN;
					tcp->tcp_valid_bits &=
					    ~TCP_OFO_FIN_VALID;
				}
			} else {
				/*
				 * Keep going even with NULL mp.
				 * There may be a useful ACK or something else
				 * we don't want to miss.
				 *
				 * But TCP should not perform fast retransmit
				 * because of the ack number.  TCP uses
				 * seg_len == 0 to determine if it is a pure
				 * ACK.  And this is not a pure ACK.
				 */
				seg_len = 0;
				ofo_seg = B_TRUE;
			}
		}
	} else if (seg_len > 0) {
		BUMP_MIB(&tcps->tcps_mib, tcpInDataInorderSegs);
		UPDATE_MIB(&tcps->tcps_mib, tcpInDataInorderBytes, seg_len);
		/*
		 * If an out of order FIN was received before, and the seq
		 * num and len of the new segment match that of the FIN,
		 * put the FIN flag back in.
		 */
		if ((tcp->tcp_valid_bits & TCP_OFO_FIN_VALID) &&
		    seg_seq + seg_len == tcp->tcp_ofo_fin_seq) {
			flags |= TH_FIN;
			tcp->tcp_valid_bits &= ~TCP_OFO_FIN_VALID;
		}
	}
	if ((flags & (TH_RST | TH_SYN | TH_URG | TH_ACK)) != TH_ACK) {
	if (flags & TH_RST) {
		freemsg(mp);
		switch (tcp->tcp_state) {
		case TCPS_SYN_RCVD:
			(void) tcp_clean_death(tcp, ECONNREFUSED, 14);
			break;
		case TCPS_ESTABLISHED:
		case TCPS_FIN_WAIT_1:
		case TCPS_FIN_WAIT_2:
		case TCPS_CLOSE_WAIT:
			(void) tcp_clean_death(tcp, ECONNRESET, 15);
			break;
		case TCPS_CLOSING:
		case TCPS_LAST_ACK:
			(void) tcp_clean_death(tcp, 0, 16);
			break;
		default:
			ASSERT(tcp->tcp_state != TCPS_TIME_WAIT);
			(void) tcp_clean_death(tcp, ENXIO, 17);
			break;
		}
		return;
	}
	if (flags & TH_SYN) {
		/*
		 * See RFC 793, Page 71
		 *
		 * The seq number must be in the window as it should
		 * be "fixed" above.  If it is outside window, it should
		 * be already rejected.  Note that we allow seg_seq to be
		 * rnxt + rwnd because we want to accept 0 window probe.
		 */
		ASSERT(SEQ_GEQ(seg_seq, tcp->tcp_rnxt) &&
		    SEQ_LEQ(seg_seq, tcp->tcp_rnxt + tcp->tcp_rwnd));
		freemsg(mp);
		/*
		 * If the ACK flag is not set, just use our snxt as the
		 * seq number of the RST segment.
		 */
		if (!(flags & TH_ACK)) {
			seg_ack = tcp->tcp_snxt;
		}
		tcp_xmit_ctl("TH_SYN", tcp, seg_ack, seg_seq + 1,
		    TH_RST|TH_ACK);
		ASSERT(tcp->tcp_state != TCPS_TIME_WAIT);
		(void) tcp_clean_death(tcp, ECONNRESET, 18);
		return;
	}
	/*
	 * urp could be -1 when the urp field in the packet is 0
	 * and TCP_OLD_URP_INTERPRETATION is set. This implies that the urgent
	 * byte was at seg_seq - 1, in which case we ignore the urgent flag.
	 */
	if (flags & TH_URG && urp >= 0) {
		if (!tcp->tcp_urp_last_valid ||
		    SEQ_GT(urp + seg_seq, tcp->tcp_urp_last)) {
			if (IPCL_IS_NONSTR(connp)) {
				if (!TCP_IS_DETACHED(tcp)) {
					(*connp->conn_upcalls->su_signal_oob)
					    (connp->conn_upper_handle, urp);
				}
			} else {
				/*
				 * If we haven't generated the signal yet for
				 * this urgent pointer value, do it now.  Also,
				 * send up a zero-length M_DATA indicating
				 * whether or not this is the mark. The latter
				 * is not needed when a T_EXDATA_IND is sent up.
				 * However, if there are allocation failures
				 * this code relies on the sender retransmitting
				 * and the socket code for determining the mark
				 * should not block waiting for the peer to
				 * transmit. Thus, for simplicity we always
				 * send up the mark indication.
				 */
				mp1 = allocb(0, BPRI_MED);
				if (mp1 == NULL) {
					freemsg(mp);
					return;
				}
				if (!TCP_IS_DETACHED(tcp) &&
				    !putnextctl1(tcp->tcp_rq, M_PCSIG,
				    SIGURG)) {
					/* Try again on the rexmit. */
					freemsg(mp1);
					freemsg(mp);
					return;
				}
				/*
				 * Mark with NOTMARKNEXT for now.
				 * The code below will change this to MARKNEXT
				 * if we are at the mark.
				 *
				 * If there are allocation failures (e.g. in
				 * dupmsg below) the next time tcp_rput_data
				 * sees the urgent segment it will send up the
				 * MSGMARKNEXT message.
				 */
				mp1->b_flag |= MSGNOTMARKNEXT;
				freemsg(tcp->tcp_urp_mark_mp);
				tcp->tcp_urp_mark_mp = mp1;
				flags |= TH_SEND_URP_MARK;
#ifdef DEBUG
				(void) strlog(TCP_MOD_ID, 0, 1, SL_TRACE,
				    "tcp_rput: sent M_PCSIG 2 seq %x urp %x "
				    "last %x, %s",
				    seg_seq, urp, tcp->tcp_urp_last,
				    tcp_display(tcp, NULL, DISP_PORT_ONLY));
#endif /* DEBUG */
			}
			tcp->tcp_urp_last_valid = B_TRUE;
			tcp->tcp_urp_last = urp + seg_seq;
		} else if (tcp->tcp_urp_mark_mp != NULL) {
			/*
			 * An allocation failure prevented the previous
			 * tcp_rput_data from sending up the allocated
			 * MSG*MARKNEXT message - send it up this time
			 * around.
			 */
			flags |= TH_SEND_URP_MARK;
		}

		/*
		 * If the urgent byte is in this segment, make sure that it is
		 * all by itself.  This makes it much easier to deal with the
		 * possibility of an allocation failure on the T_exdata_ind.
		 * Note that seg_len is the number of bytes in the segment, and
		 * urp is the offset into the segment of the urgent byte.
		 * urp < seg_len means that the urgent byte is in this segment.
		 */
		if (urp < seg_len) {
			if (seg_len != 1) {
				uint32_t  tmp_rnxt;
				/*
				 * Break it up and feed it back in.
				 * Re-attach the IP header.
				 */
				mp->b_rptr = iphdr;
				if (urp > 0) {
					/*
					 * There is stuff before the urgent
					 * byte.
					 */
					mp1 = dupmsg(mp);
					if (!mp1) {
						/*
						 * Trim from urgent byte on.
						 * The rest will come back.
						 */
						(void) adjmsg(mp,
						    urp - seg_len);
						tcp_rput_data(connp,
						    mp, NULL);
						return;
					}
					(void) adjmsg(mp1, urp - seg_len);
					/* Feed this piece back in. */
					tmp_rnxt = tcp->tcp_rnxt;
					tcp_rput_data(connp, mp1, NULL);
					/*
					 * If the data passed back in was not
					 * processed (ie: bad ACK) sending
					 * the remainder back in will cause a
					 * loop. In this case, drop the
					 * packet and let the sender try
					 * sending a good packet.
					 */
					if (tmp_rnxt == tcp->tcp_rnxt) {
						freemsg(mp);
						return;
					}
				}
				if (urp != seg_len - 1) {
					uint32_t  tmp_rnxt;
					/*
					 * There is stuff after the urgent
					 * byte.
					 */
					mp1 = dupmsg(mp);
					if (!mp1) {
						/*
						 * Trim everything beyond the
						 * urgent byte.  The rest will
						 * come back.
						 */
						(void) adjmsg(mp,
						    urp + 1 - seg_len);
						tcp_rput_data(connp,
						    mp, NULL);
						return;
					}
					(void) adjmsg(mp1, urp + 1 - seg_len);
					tmp_rnxt = tcp->tcp_rnxt;
					tcp_rput_data(connp, mp1, NULL);
					/*
					 * If the data passed back in was not
					 * processed (ie: bad ACK) sending
					 * the remainder back in will cause a
					 * loop. In this case, drop the
					 * packet and let the sender try
					 * sending a good packet.
					 */
					if (tmp_rnxt == tcp->tcp_rnxt) {
						freemsg(mp);
						return;
					}
				}
				tcp_rput_data(connp, mp, NULL);
				return;
			}
			/*
			 * This segment contains only the urgent byte.  We
			 * have to allocate the T_exdata_ind, if we can.
			 */
			if (IPCL_IS_NONSTR(connp)) {
				int error;

				(*connp->conn_upcalls->su_recv)
				    (connp->conn_upper_handle, mp, seg_len,
				    MSG_OOB, &error, NULL);
				mp = NULL;
				goto update_ack;
			} else if (!tcp->tcp_urp_mp) {
				struct T_exdata_ind *tei;
				mp1 = allocb(sizeof (struct T_exdata_ind),
				    BPRI_MED);
				if (!mp1) {
					/*
					 * Sigh... It'll be back.
					 * Generate any MSG*MARK message now.
					 */
					freemsg(mp);
					seg_len = 0;
					if (flags & TH_SEND_URP_MARK) {


						ASSERT(tcp->tcp_urp_mark_mp);
						tcp->tcp_urp_mark_mp->b_flag &=
						    ~MSGNOTMARKNEXT;
						tcp->tcp_urp_mark_mp->b_flag |=
						    MSGMARKNEXT;
					}
					goto ack_check;
				}
				mp1->b_datap->db_type = M_PROTO;
				tei = (struct T_exdata_ind *)mp1->b_rptr;
				tei->PRIM_type = T_EXDATA_IND;
				tei->MORE_flag = 0;
				mp1->b_wptr = (uchar_t *)&tei[1];
				tcp->tcp_urp_mp = mp1;
#ifdef DEBUG
				(void) strlog(TCP_MOD_ID, 0, 1, SL_TRACE,
				    "tcp_rput: allocated exdata_ind %s",
				    tcp_display(tcp, NULL,
				    DISP_PORT_ONLY));
#endif /* DEBUG */
				/*
				 * There is no need to send a separate MSG*MARK
				 * message since the T_EXDATA_IND will be sent
				 * now.
				 */
				flags &= ~TH_SEND_URP_MARK;
				freemsg(tcp->tcp_urp_mark_mp);
				tcp->tcp_urp_mark_mp = NULL;
			}
			/*
			 * Now we are all set.  On the next putnext upstream,
			 * tcp_urp_mp will be non-NULL and will get prepended
			 * to what has to be this piece containing the urgent
			 * byte.  If for any reason we abort this segment below,
			 * if it comes back, we will have this ready, or it
			 * will get blown off in close.
			 */
		} else if (urp == seg_len) {
			/*
			 * The urgent byte is the next byte after this sequence
			 * number. If there is data it is marked with
			 * MSGMARKNEXT and any tcp_urp_mark_mp is discarded
			 * since it is not needed. Otherwise, if the code
			 * above just allocated a zero-length tcp_urp_mark_mp
			 * message, that message is tagged with MSGMARKNEXT.
			 * Sending up these MSGMARKNEXT messages makes
			 * SIOCATMARK work correctly even though
			 * the T_EXDATA_IND will not be sent up until the
			 * urgent byte arrives.
			 */
			if (seg_len != 0) {
				flags |= TH_MARKNEXT_NEEDED;
				freemsg(tcp->tcp_urp_mark_mp);
				tcp->tcp_urp_mark_mp = NULL;
				flags &= ~TH_SEND_URP_MARK;
			} else if (tcp->tcp_urp_mark_mp != NULL) {
				flags |= TH_SEND_URP_MARK;
				tcp->tcp_urp_mark_mp->b_flag &=
				    ~MSGNOTMARKNEXT;
				tcp->tcp_urp_mark_mp->b_flag |= MSGMARKNEXT;
			}
#ifdef DEBUG
			(void) strlog(TCP_MOD_ID, 0, 1, SL_TRACE,
			    "tcp_rput: AT MARK, len %d, flags 0x%x, %s",
			    seg_len, flags,
			    tcp_display(tcp, NULL, DISP_PORT_ONLY));
#endif /* DEBUG */
		}
#ifdef DEBUG
		else {
			/* Data left until we hit mark */
			(void) strlog(TCP_MOD_ID, 0, 1, SL_TRACE,
			    "tcp_rput: URP %d bytes left, %s",
			    urp - seg_len, tcp_display(tcp, NULL,
			    DISP_PORT_ONLY));
		}
#endif /* DEBUG */
	}

process_ack:
	if (!(flags & TH_ACK)) {
		freemsg(mp);
		goto xmit_check;
	}
	}
	bytes_acked = (int)(seg_ack - tcp->tcp_suna);

	if (tcp->tcp_ipversion == IPV6_VERSION && bytes_acked > 0)
		tcp->tcp_ip_forward_progress = B_TRUE;
	if (tcp->tcp_state == TCPS_SYN_RCVD) {
		if ((tcp->tcp_conn.tcp_eager_conn_ind != NULL) &&
		    ((tcp->tcp_kssl_ent == NULL) || !tcp->tcp_kssl_pending)) {
			/* 3-way handshake complete - pass up the T_CONN_IND */
			tcp_t	*listener = tcp->tcp_listener;
			mblk_t	*mp = tcp->tcp_conn.tcp_eager_conn_ind;

			tcp->tcp_tconnind_started = B_TRUE;
			tcp->tcp_conn.tcp_eager_conn_ind = NULL;
			/*
			 * We are here means eager is fine but it can
			 * get a TH_RST at any point between now and till
			 * accept completes and disappear. We need to
			 * ensure that reference to eager is valid after
			 * we get out of eager's perimeter. So we do
			 * an extra refhold.
			 */
			CONN_INC_REF(connp);

			/*
			 * The listener also exists because of the refhold
			 * done in tcp_conn_request. Its possible that it
			 * might have closed. We will check that once we
			 * get inside listeners context.
			 */
			CONN_INC_REF(listener->tcp_connp);
			if (listener->tcp_connp->conn_sqp ==
			    connp->conn_sqp) {
				/*
				 * We optimize by not calling an SQUEUE_ENTER
				 * on the listener since we know that the
				 * listener and eager squeues are the same.
				 * We are able to make this check safely only
				 * because neither the eager nor the listener
				 * can change its squeue. Only an active connect
				 * can change its squeue
				 */
				tcp_send_conn_ind(listener->tcp_connp, mp,
				    listener->tcp_connp->conn_sqp);
				CONN_DEC_REF(listener->tcp_connp);
			} else if (!tcp->tcp_loopback) {
				SQUEUE_ENTER_ONE(listener->tcp_connp->conn_sqp,
				    mp, tcp_send_conn_ind,
				    listener->tcp_connp, SQ_FILL,
				    SQTAG_TCP_CONN_IND);
			} else {
				SQUEUE_ENTER_ONE(listener->tcp_connp->conn_sqp,
				    mp, tcp_send_conn_ind,
				    listener->tcp_connp, SQ_PROCESS,
				    SQTAG_TCP_CONN_IND);
			}
		}

		if (tcp->tcp_active_open) {
			/*
			 * We are seeing the final ack in the three way
			 * hand shake of a active open'ed connection
			 * so we must send up a T_CONN_CON
			 */
			if (!tcp_conn_con(tcp, iphdr, tcph, mp, NULL)) {
				freemsg(mp);
				return;
			}
			/*
			 * Don't fuse the loopback endpoints for
			 * simultaneous active opens.
			 */
			if (tcp->tcp_loopback) {
				TCP_STAT(tcps, tcp_fusion_unfusable);
				tcp->tcp_unfusable = B_TRUE;
			}
		}

		tcp->tcp_suna = tcp->tcp_iss + 1;	/* One for the SYN */
		bytes_acked--;
		/* SYN was acked - making progress */
		if (tcp->tcp_ipversion == IPV6_VERSION)
			tcp->tcp_ip_forward_progress = B_TRUE;

		/*
		 * If SYN was retransmitted, need to reset all
		 * retransmission info as this segment will be
		 * treated as a dup ACK.
		 */
		if (tcp->tcp_rexmit) {
			tcp->tcp_rexmit = B_FALSE;
			tcp->tcp_rexmit_nxt = tcp->tcp_snxt;
			tcp->tcp_rexmit_max = tcp->tcp_snxt;
			tcp->tcp_snd_burst = tcp->tcp_localnet ?
			    TCP_CWND_INFINITE : TCP_CWND_NORMAL;
			tcp->tcp_ms_we_have_waited = 0;
			tcp->tcp_cwnd = mss;
		}

		/*
		 * We set the send window to zero here.
		 * This is needed if there is data to be
		 * processed already on the queue.
		 * Later (at swnd_update label), the
		 * "new_swnd > tcp_swnd" condition is satisfied
		 * the XMIT_NEEDED flag is set in the current
		 * (SYN_RCVD) state. This ensures tcp_wput_data() is
		 * called if there is already data on queue in
		 * this state.
		 */
		tcp->tcp_swnd = 0;

		if (new_swnd > tcp->tcp_max_swnd)
			tcp->tcp_max_swnd = new_swnd;
		tcp->tcp_swl1 = seg_seq;
		tcp->tcp_swl2 = seg_ack;
		tcp->tcp_state = TCPS_ESTABLISHED;
		tcp->tcp_valid_bits &= ~TCP_ISS_VALID;

		/* Fuse when both sides are in ESTABLISHED state */
		if (tcp->tcp_loopback && do_tcp_fusion)
			tcp_fuse(tcp, iphdr, tcph);

	}
	/* This code follows 4.4BSD-Lite2 mostly. */
	if (bytes_acked < 0)
		goto est;

	/*
	 * If TCP is ECN capable and the congestion experience bit is
	 * set, reduce tcp_cwnd and tcp_ssthresh.  But this should only be
	 * done once per window (or more loosely, per RTT).
	 */
	if (tcp->tcp_cwr && SEQ_GT(seg_ack, tcp->tcp_cwr_snd_max))
		tcp->tcp_cwr = B_FALSE;
	if (tcp->tcp_ecn_ok && (flags & TH_ECE)) {
		if (!tcp->tcp_cwr) {
			npkt = ((tcp->tcp_snxt - tcp->tcp_suna) >> 1) / mss;
			tcp->tcp_cwnd_ssthresh = MAX(npkt, 2) * mss;
			tcp->tcp_cwnd = npkt * mss;
			/*
			 * If the cwnd is 0, use the timer to clock out
			 * new segments.  This is required by the ECN spec.
			 */
			if (npkt == 0) {
				TCP_TIMER_RESTART(tcp, tcp->tcp_rto);
				/*
				 * This makes sure that when the ACK comes
				 * back, we will increase tcp_cwnd by 1 MSS.
				 */
				tcp->tcp_cwnd_cnt = 0;
			}
			tcp->tcp_cwr = B_TRUE;
			/*
			 * This marks the end of the current window of in
			 * flight data.  That is why we don't use
			 * tcp_suna + tcp_swnd.  Only data in flight can
			 * provide ECN info.
			 */
			tcp->tcp_cwr_snd_max = tcp->tcp_snxt;
			tcp->tcp_ecn_cwr_sent = B_FALSE;
		}
	}

	mp1 = tcp->tcp_xmit_head;
	if (bytes_acked == 0) {
		if (!ofo_seg && seg_len == 0 && new_swnd == tcp->tcp_swnd) {
			int dupack_cnt;

			BUMP_MIB(&tcps->tcps_mib, tcpInDupAck);
			/*
			 * Fast retransmit.  When we have seen exactly three
			 * identical ACKs while we have unacked data
			 * outstanding we take it as a hint that our peer
			 * dropped something.
			 *
			 * If TCP is retransmitting, don't do fast retransmit.
			 */
			if (mp1 && tcp->tcp_suna != tcp->tcp_snxt &&
			    ! tcp->tcp_rexmit) {
				/* Do Limited Transmit */
				if ((dupack_cnt = ++tcp->tcp_dupack_cnt) <
				    tcps->tcps_dupack_fast_retransmit) {
					/*
					 * RFC 3042
					 *
					 * What we need to do is temporarily
					 * increase tcp_cwnd so that new
					 * data can be sent if it is allowed
					 * by the receive window (tcp_rwnd).
					 * tcp_wput_data() will take care of
					 * the rest.
					 *
					 * If the connection is SACK capable,
					 * only do limited xmit when there
					 * is SACK info.
					 *
					 * Note how tcp_cwnd is incremented.
					 * The first dup ACK will increase
					 * it by 1 MSS.  The second dup ACK
					 * will increase it by 2 MSS.  This
					 * means that only 1 new segment will
					 * be sent for each dup ACK.
					 */
					if (tcp->tcp_unsent > 0 &&
					    (!tcp->tcp_snd_sack_ok ||
					    (tcp->tcp_snd_sack_ok &&
					    tcp->tcp_notsack_list != NULL))) {
						tcp->tcp_cwnd += mss <<
						    (tcp->tcp_dupack_cnt - 1);
						flags |= TH_LIMIT_XMIT;
					}
				} else if (dupack_cnt ==
				    tcps->tcps_dupack_fast_retransmit) {

				/*
				 * If we have reduced tcp_ssthresh
				 * because of ECN, do not reduce it again
				 * unless it is already one window of data
				 * away.  After one window of data, tcp_cwr
				 * should then be cleared.  Note that
				 * for non ECN capable connection, tcp_cwr
				 * should always be false.
				 *
				 * Adjust cwnd since the duplicate
				 * ack indicates that a packet was
				 * dropped (due to congestion.)
				 */
				if (!tcp->tcp_cwr) {
					npkt = ((tcp->tcp_snxt -
					    tcp->tcp_suna) >> 1) / mss;
					tcp->tcp_cwnd_ssthresh = MAX(npkt, 2) *
					    mss;
					tcp->tcp_cwnd = (npkt +
					    tcp->tcp_dupack_cnt) * mss;
				}
				if (tcp->tcp_ecn_ok) {
					tcp->tcp_cwr = B_TRUE;
					tcp->tcp_cwr_snd_max = tcp->tcp_snxt;
					tcp->tcp_ecn_cwr_sent = B_FALSE;
				}

				/*
				 * We do Hoe's algorithm.  Refer to her
				 * paper "Improving the Start-up Behavior
				 * of a Congestion Control Scheme for TCP,"
				 * appeared in SIGCOMM'96.
				 *
				 * Save highest seq no we have sent so far.
				 * Be careful about the invisible FIN byte.
				 */
				if ((tcp->tcp_valid_bits & TCP_FSS_VALID) &&
				    (tcp->tcp_unsent == 0)) {
					tcp->tcp_rexmit_max = tcp->tcp_fss;
				} else {
					tcp->tcp_rexmit_max = tcp->tcp_snxt;
				}

				/*
				 * Do not allow bursty traffic during.
				 * fast recovery.  Refer to Fall and Floyd's
				 * paper "Simulation-based Comparisons of
				 * Tahoe, Reno and SACK TCP" (in CCR?)
				 * This is a best current practise.
				 */
				tcp->tcp_snd_burst = TCP_CWND_SS;

				/*
				 * For SACK:
				 * Calculate tcp_pipe, which is the
				 * estimated number of bytes in
				 * network.
				 *
				 * tcp_fack is the highest sack'ed seq num
				 * TCP has received.
				 *
				 * tcp_pipe is explained in the above quoted
				 * Fall and Floyd's paper.  tcp_fack is
				 * explained in Mathis and Mahdavi's
				 * "Forward Acknowledgment: Refining TCP
				 * Congestion Control" in SIGCOMM '96.
				 */
				if (tcp->tcp_snd_sack_ok) {
					ASSERT(tcp->tcp_sack_info != NULL);
					if (tcp->tcp_notsack_list != NULL) {
						tcp->tcp_pipe = tcp->tcp_snxt -
						    tcp->tcp_fack;
						tcp->tcp_sack_snxt = seg_ack;
						flags |= TH_NEED_SACK_REXMIT;
					} else {
						/*
						 * Always initialize tcp_pipe
						 * even though we don't have
						 * any SACK info.  If later
						 * we get SACK info and
						 * tcp_pipe is not initialized,
						 * funny things will happen.
						 */
						tcp->tcp_pipe =
						    tcp->tcp_cwnd_ssthresh;
					}
				} else {
					flags |= TH_REXMIT_NEEDED;
				} /* tcp_snd_sack_ok */

				} else {
					/*
					 * Here we perform congestion
					 * avoidance, but NOT slow start.
					 * This is known as the Fast
					 * Recovery Algorithm.
					 */
					if (tcp->tcp_snd_sack_ok &&
					    tcp->tcp_notsack_list != NULL) {
						flags |= TH_NEED_SACK_REXMIT;
						tcp->tcp_pipe -= mss;
						if (tcp->tcp_pipe < 0)
							tcp->tcp_pipe = 0;
					} else {
					/*
					 * We know that one more packet has
					 * left the pipe thus we can update
					 * cwnd.
					 */
					cwnd = tcp->tcp_cwnd + mss;
					if (cwnd > tcp->tcp_cwnd_max)
						cwnd = tcp->tcp_cwnd_max;
					tcp->tcp_cwnd = cwnd;
					if (tcp->tcp_unsent > 0)
						flags |= TH_XMIT_NEEDED;
					}
				}
			}
		} else if (tcp->tcp_zero_win_probe) {
			/*
			 * If the window has opened, need to arrange
			 * to send additional data.
			 */
			if (new_swnd != 0) {
				/* tcp_suna != tcp_snxt */
				/* Packet contains a window update */
				BUMP_MIB(&tcps->tcps_mib, tcpInWinUpdate);
				tcp->tcp_zero_win_probe = 0;
				tcp->tcp_timer_backoff = 0;
				tcp->tcp_ms_we_have_waited = 0;

				/*
				 * Transmit starting with tcp_suna since
				 * the one byte probe is not ack'ed.
				 * If TCP has sent more than one identical
				 * probe, tcp_rexmit will be set.  That means
				 * tcp_ss_rexmit() will send out the one
				 * byte along with new data.  Otherwise,
				 * fake the retransmission.
				 */
				flags |= TH_XMIT_NEEDED;
				if (!tcp->tcp_rexmit) {
					tcp->tcp_rexmit = B_TRUE;
					tcp->tcp_dupack_cnt = 0;
					tcp->tcp_rexmit_nxt = tcp->tcp_suna;
					tcp->tcp_rexmit_max = tcp->tcp_suna + 1;
				}
			}
		}
		goto swnd_update;
	}

	/*
	 * Check for "acceptability" of ACK value per RFC 793, pages 72 - 73.
	 * If the ACK value acks something that we have not yet sent, it might
	 * be an old duplicate segment.  Send an ACK to re-synchronize the
	 * other side.
	 * Note: reset in response to unacceptable ACK in SYN_RECEIVE
	 * state is handled above, so we can always just drop the segment and
	 * send an ACK here.
	 *
	 * Should we send ACKs in response to ACK only segments?
	 */
	if (SEQ_GT(seg_ack, tcp->tcp_snxt)) {
		BUMP_MIB(&tcps->tcps_mib, tcpInAckUnsent);
		/* drop the received segment */
		freemsg(mp);

		/*
		 * Send back an ACK.  If tcp_drop_ack_unsent_cnt is
		 * greater than 0, check if the number of such
		 * bogus ACks is greater than that count.  If yes,
		 * don't send back any ACK.  This prevents TCP from
		 * getting into an ACK storm if somehow an attacker
		 * successfully spoofs an acceptable segment to our
		 * peer.
		 */
		if (tcp_drop_ack_unsent_cnt > 0 &&
		    ++tcp->tcp_in_ack_unsent > tcp_drop_ack_unsent_cnt) {
			TCP_STAT(tcps, tcp_in_ack_unsent_drop);
			return;
		}
		mp = tcp_ack_mp(tcp);
		if (mp != NULL) {
			BUMP_LOCAL(tcp->tcp_obsegs);
			BUMP_MIB(&tcps->tcps_mib, tcpOutAck);
			tcp_send_data(tcp, tcp->tcp_wq, mp);
		}
		return;
	}

	/*
	 * TCP gets a new ACK, update the notsack'ed list to delete those
	 * blocks that are covered by this ACK.
	 */
	if (tcp->tcp_snd_sack_ok && tcp->tcp_notsack_list != NULL) {
		tcp_notsack_remove(&(tcp->tcp_notsack_list), seg_ack,
		    &(tcp->tcp_num_notsack_blk), &(tcp->tcp_cnt_notsack_list));
	}

	/*
	 * If we got an ACK after fast retransmit, check to see
	 * if it is a partial ACK.  If it is not and the congestion
	 * window was inflated to account for the other side's
	 * cached packets, retract it.  If it is, do Hoe's algorithm.
	 */
	if (tcp->tcp_dupack_cnt >= tcps->tcps_dupack_fast_retransmit) {
		ASSERT(tcp->tcp_rexmit == B_FALSE);
		if (SEQ_GEQ(seg_ack, tcp->tcp_rexmit_max)) {
			tcp->tcp_dupack_cnt = 0;
			/*
			 * Restore the orig tcp_cwnd_ssthresh after
			 * fast retransmit phase.
			 */
			if (tcp->tcp_cwnd > tcp->tcp_cwnd_ssthresh) {
				tcp->tcp_cwnd = tcp->tcp_cwnd_ssthresh;
			}
			tcp->tcp_rexmit_max = seg_ack;
			tcp->tcp_cwnd_cnt = 0;
			tcp->tcp_snd_burst = tcp->tcp_localnet ?
			    TCP_CWND_INFINITE : TCP_CWND_NORMAL;

			/*
			 * Remove all notsack info to avoid confusion with
			 * the next fast retrasnmit/recovery phase.
			 */
			if (tcp->tcp_snd_sack_ok &&
			    tcp->tcp_notsack_list != NULL) {
				TCP_NOTSACK_REMOVE_ALL(tcp->tcp_notsack_list);
			}
		} else {
			if (tcp->tcp_snd_sack_ok &&
			    tcp->tcp_notsack_list != NULL) {
				flags |= TH_NEED_SACK_REXMIT;
				tcp->tcp_pipe -= mss;
				if (tcp->tcp_pipe < 0)
					tcp->tcp_pipe = 0;
			} else {
				/*
				 * Hoe's algorithm:
				 *
				 * Retransmit the unack'ed segment and
				 * restart fast recovery.  Note that we
				 * need to scale back tcp_cwnd to the
				 * original value when we started fast
				 * recovery.  This is to prevent overly
				 * aggressive behaviour in sending new
				 * segments.
				 */
				tcp->tcp_cwnd = tcp->tcp_cwnd_ssthresh +
				    tcps->tcps_dupack_fast_retransmit * mss;
				tcp->tcp_cwnd_cnt = tcp->tcp_cwnd;
				flags |= TH_REXMIT_NEEDED;
			}
		}
	} else {
		tcp->tcp_dupack_cnt = 0;
		if (tcp->tcp_rexmit) {
			/*
			 * TCP is retranmitting.  If the ACK ack's all
			 * outstanding data, update tcp_rexmit_max and
			 * tcp_rexmit_nxt.  Otherwise, update tcp_rexmit_nxt
			 * to the correct value.
			 *
			 * Note that SEQ_LEQ() is used.  This is to avoid
			 * unnecessary fast retransmit caused by dup ACKs
			 * received when TCP does slow start retransmission
			 * after a time out.  During this phase, TCP may
			 * send out segments which are already received.
			 * This causes dup ACKs to be sent back.
			 */
			if (SEQ_LEQ(seg_ack, tcp->tcp_rexmit_max)) {
				if (SEQ_GT(seg_ack, tcp->tcp_rexmit_nxt)) {
					tcp->tcp_rexmit_nxt = seg_ack;
				}
				if (seg_ack != tcp->tcp_rexmit_max) {
					flags |= TH_XMIT_NEEDED;
				}
			} else {
				tcp->tcp_rexmit = B_FALSE;
				tcp->tcp_xmit_zc_clean = B_FALSE;
				tcp->tcp_rexmit_nxt = tcp->tcp_snxt;
				tcp->tcp_snd_burst = tcp->tcp_localnet ?
				    TCP_CWND_INFINITE : TCP_CWND_NORMAL;
			}
			tcp->tcp_ms_we_have_waited = 0;
		}
	}

	BUMP_MIB(&tcps->tcps_mib, tcpInAckSegs);
	UPDATE_MIB(&tcps->tcps_mib, tcpInAckBytes, bytes_acked);
	tcp->tcp_suna = seg_ack;
	if (tcp->tcp_zero_win_probe != 0) {
		tcp->tcp_zero_win_probe = 0;
		tcp->tcp_timer_backoff = 0;
	}

	/*
	 * If tcp_xmit_head is NULL, then it must be the FIN being ack'ed.
	 * Note that it cannot be the SYN being ack'ed.  The code flow
	 * will not reach here.
	 */
	if (mp1 == NULL) {
		goto fin_acked;
	}

	/*
	 * Update the congestion window.
	 *
	 * If TCP is not ECN capable or TCP is ECN capable but the
	 * congestion experience bit is not set, increase the tcp_cwnd as
	 * usual.
	 */
	if (!tcp->tcp_ecn_ok || !(flags & TH_ECE)) {
		cwnd = tcp->tcp_cwnd;
		add = mss;

		if (cwnd >= tcp->tcp_cwnd_ssthresh) {
			/*
			 * This is to prevent an increase of less than 1 MSS of
			 * tcp_cwnd.  With partial increase, tcp_wput_data()
			 * may send out tinygrams in order to preserve mblk
			 * boundaries.
			 *
			 * By initializing tcp_cwnd_cnt to new tcp_cwnd and
			 * decrementing it by 1 MSS for every ACKs, tcp_cwnd is
			 * increased by 1 MSS for every RTTs.
			 */
			if (tcp->tcp_cwnd_cnt <= 0) {
				tcp->tcp_cwnd_cnt = cwnd + add;
			} else {
				tcp->tcp_cwnd_cnt -= add;
				add = 0;
			}
		}
		tcp->tcp_cwnd = MIN(cwnd + add, tcp->tcp_cwnd_max);
	}

	/* See if the latest urgent data has been acknowledged */
	if ((tcp->tcp_valid_bits & TCP_URG_VALID) &&
	    SEQ_GT(seg_ack, tcp->tcp_urg))
		tcp->tcp_valid_bits &= ~TCP_URG_VALID;

	/* Can we update the RTT estimates? */
	if (tcp->tcp_snd_ts_ok) {
		/* Ignore zero timestamp echo-reply. */
		if (tcpopt.tcp_opt_ts_ecr != 0) {
			tcp_set_rto(tcp, (int32_t)lbolt -
			    (int32_t)tcpopt.tcp_opt_ts_ecr);
		}

		/* If needed, restart the timer. */
		if (tcp->tcp_set_timer == 1) {
			TCP_TIMER_RESTART(tcp, tcp->tcp_rto);
			tcp->tcp_set_timer = 0;
		}
		/*
		 * Update tcp_csuna in case the other side stops sending
		 * us timestamps.
		 */
		tcp->tcp_csuna = tcp->tcp_snxt;
	} else if (SEQ_GT(seg_ack, tcp->tcp_csuna)) {
		/*
		 * An ACK sequence we haven't seen before, so get the RTT
		 * and update the RTO. But first check if the timestamp is
		 * valid to use.
		 */
		if ((mp1->b_next != NULL) &&
		    SEQ_GT(seg_ack, (uint32_t)(uintptr_t)(mp1->b_next)))
			tcp_set_rto(tcp, (int32_t)lbolt -
			    (int32_t)(intptr_t)mp1->b_prev);
		else
			BUMP_MIB(&tcps->tcps_mib, tcpRttNoUpdate);

		/* Remeber the last sequence to be ACKed */
		tcp->tcp_csuna = seg_ack;
		if (tcp->tcp_set_timer == 1) {
			TCP_TIMER_RESTART(tcp, tcp->tcp_rto);
			tcp->tcp_set_timer = 0;
		}
	} else {
		BUMP_MIB(&tcps->tcps_mib, tcpRttNoUpdate);
	}

	/* Eat acknowledged bytes off the xmit queue. */
	for (;;) {
		mblk_t	*mp2;
		uchar_t	*wptr;

		wptr = mp1->b_wptr;
		ASSERT((uintptr_t)(wptr - mp1->b_rptr) <= (uintptr_t)INT_MAX);
		bytes_acked -= (int)(wptr - mp1->b_rptr);
		if (bytes_acked < 0) {
			mp1->b_rptr = wptr + bytes_acked;
			/*
			 * Set a new timestamp if all the bytes timed by the
			 * old timestamp have been ack'ed.
			 */
			if (SEQ_GT(seg_ack,
			    (uint32_t)(uintptr_t)(mp1->b_next))) {
				mp1->b_prev = (mblk_t *)(uintptr_t)lbolt;
				mp1->b_next = NULL;
			}
			break;
		}
		mp1->b_next = NULL;
		mp1->b_prev = NULL;
		mp2 = mp1;
		mp1 = mp1->b_cont;

		/*
		 * This notification is required for some zero-copy
		 * clients to maintain a copy semantic. After the data
		 * is ack'ed, client is safe to modify or reuse the buffer.
		 */
		if (tcp->tcp_snd_zcopy_aware &&
		    (mp2->b_datap->db_struioflag & STRUIO_ZCNOTIFY))
			tcp_zcopy_notify(tcp);
		freeb(mp2);
		if (bytes_acked == 0) {
			if (mp1 == NULL) {
				/* Everything is ack'ed, clear the tail. */
				tcp->tcp_xmit_tail = NULL;
				/*
				 * Cancel the timer unless we are still
				 * waiting for an ACK for the FIN packet.
				 */
				if (tcp->tcp_timer_tid != 0 &&
				    tcp->tcp_snxt == tcp->tcp_suna) {
					(void) TCP_TIMER_CANCEL(tcp,
					    tcp->tcp_timer_tid);
					tcp->tcp_timer_tid = 0;
				}
				goto pre_swnd_update;
			}
			if (mp2 != tcp->tcp_xmit_tail)
				break;
			tcp->tcp_xmit_tail = mp1;
			ASSERT((uintptr_t)(mp1->b_wptr - mp1->b_rptr) <=
			    (uintptr_t)INT_MAX);
			tcp->tcp_xmit_tail_unsent = (int)(mp1->b_wptr -
			    mp1->b_rptr);
			break;
		}
		if (mp1 == NULL) {
			/*
			 * More was acked but there is nothing more
			 * outstanding.  This means that the FIN was
			 * just acked or that we're talking to a clown.
			 */
fin_acked:
			ASSERT(tcp->tcp_fin_sent);
			tcp->tcp_xmit_tail = NULL;
			if (tcp->tcp_fin_sent) {
				/* FIN was acked - making progress */
				if (tcp->tcp_ipversion == IPV6_VERSION &&
				    !tcp->tcp_fin_acked)
					tcp->tcp_ip_forward_progress = B_TRUE;
				tcp->tcp_fin_acked = B_TRUE;
				if (tcp->tcp_linger_tid != 0 &&
				    TCP_TIMER_CANCEL(tcp,
				    tcp->tcp_linger_tid) >= 0) {
					tcp_stop_lingering(tcp);
					freemsg(mp);
					mp = NULL;
				}
			} else {
				/*
				 * We should never get here because
				 * we have already checked that the
				 * number of bytes ack'ed should be
				 * smaller than or equal to what we
				 * have sent so far (it is the
				 * acceptability check of the ACK).
				 * We can only get here if the send
				 * queue is corrupted.
				 *
				 * Terminate the connection and
				 * panic the system.  It is better
				 * for us to panic instead of
				 * continuing to avoid other disaster.
				 */
				tcp_xmit_ctl(NULL, tcp, tcp->tcp_snxt,
				    tcp->tcp_rnxt, TH_RST|TH_ACK);
				panic("Memory corruption "
				    "detected for connection %s.",
				    tcp_display(tcp, NULL,
				    DISP_ADDR_AND_PORT));
				/*NOTREACHED*/
			}
			goto pre_swnd_update;
		}
		ASSERT(mp2 != tcp->tcp_xmit_tail);
	}
	if (tcp->tcp_unsent) {
		flags |= TH_XMIT_NEEDED;
	}
pre_swnd_update:
	tcp->tcp_xmit_head = mp1;
swnd_update:
	/*
	 * The following check is different from most other implementations.
	 * For bi-directional transfer, when segments are dropped, the
	 * "normal" check will not accept a window update in those
	 * retransmitted segemnts.  Failing to do that, TCP may send out
	 * segments which are outside receiver's window.  As TCP accepts
	 * the ack in those retransmitted segments, if the window update in
	 * the same segment is not accepted, TCP will incorrectly calculates
	 * that it can send more segments.  This can create a deadlock
	 * with the receiver if its window becomes zero.
	 */
	if (SEQ_LT(tcp->tcp_swl2, seg_ack) ||
	    SEQ_LT(tcp->tcp_swl1, seg_seq) ||
	    (tcp->tcp_swl1 == seg_seq && new_swnd > tcp->tcp_swnd)) {
		/*
		 * The criteria for update is:
		 *
		 * 1. the segment acknowledges some data.  Or
		 * 2. the segment is new, i.e. it has a higher seq num. Or
		 * 3. the segment is not old and the advertised window is
		 * larger than the previous advertised window.
		 */
		if (tcp->tcp_unsent && new_swnd > tcp->tcp_swnd)
			flags |= TH_XMIT_NEEDED;
		tcp->tcp_swnd = new_swnd;
		if (new_swnd > tcp->tcp_max_swnd)
			tcp->tcp_max_swnd = new_swnd;
		tcp->tcp_swl1 = seg_seq;
		tcp->tcp_swl2 = seg_ack;
	}
est:
	if (tcp->tcp_state > TCPS_ESTABLISHED) {

		switch (tcp->tcp_state) {
		case TCPS_FIN_WAIT_1:
			if (tcp->tcp_fin_acked) {
				tcp->tcp_state = TCPS_FIN_WAIT_2;
				/*
				 * We implement the non-standard BSD/SunOS
				 * FIN_WAIT_2 flushing algorithm.
				 * If there is no user attached to this
				 * TCP endpoint, then this TCP struct
				 * could hang around forever in FIN_WAIT_2
				 * state if the peer forgets to send us
				 * a FIN.  To prevent this, we wait only
				 * 2*MSL (a convenient time value) for
				 * the FIN to arrive.  If it doesn't show up,
				 * we flush the TCP endpoint.  This algorithm,
				 * though a violation of RFC-793, has worked
				 * for over 10 years in BSD systems.
				 * Note: SunOS 4.x waits 675 seconds before
				 * flushing the FIN_WAIT_2 connection.
				 */
				TCP_TIMER_RESTART(tcp,
				    tcps->tcps_fin_wait_2_flush_interval);
			}
			break;
		case TCPS_FIN_WAIT_2:
			break;	/* Shutdown hook? */
		case TCPS_LAST_ACK:
			freemsg(mp);
			if (tcp->tcp_fin_acked) {
				(void) tcp_clean_death(tcp, 0, 19);
				return;
			}
			goto xmit_check;
		case TCPS_CLOSING:
			if (tcp->tcp_fin_acked) {
				tcp->tcp_state = TCPS_TIME_WAIT;
				/*
				 * Unconditionally clear the exclusive binding
				 * bit so this TIME-WAIT connection won't
				 * interfere with new ones.
				 */
				tcp->tcp_exclbind = 0;
				if (!TCP_IS_DETACHED(tcp)) {
					TCP_TIMER_RESTART(tcp,
					    tcps->tcps_time_wait_interval);
				} else {
					tcp_time_wait_append(tcp);
					TCP_DBGSTAT(tcps, tcp_rput_time_wait);
				}
			}
			/*FALLTHRU*/
		case TCPS_CLOSE_WAIT:
			freemsg(mp);
			goto xmit_check;
		default:
			ASSERT(tcp->tcp_state != TCPS_TIME_WAIT);
			break;
		}
	}
	if (flags & TH_FIN) {
		/* Make sure we ack the fin */
		flags |= TH_ACK_NEEDED;
		if (!tcp->tcp_fin_rcvd) {
			tcp->tcp_fin_rcvd = B_TRUE;
			tcp->tcp_rnxt++;
			tcph = tcp->tcp_tcph;
			U32_TO_ABE32(tcp->tcp_rnxt, tcph->th_ack);

			/*
			 * Generate the ordrel_ind at the end unless we
			 * are an eager guy.
			 * In the eager case tcp_rsrv will do this when run
			 * after tcp_accept is done.
			 */
			if (tcp->tcp_listener == NULL &&
			    !TCP_IS_DETACHED(tcp) && (!tcp->tcp_hard_binding))
				flags |= TH_ORDREL_NEEDED;
			switch (tcp->tcp_state) {
			case TCPS_SYN_RCVD:
			case TCPS_ESTABLISHED:
				tcp->tcp_state = TCPS_CLOSE_WAIT;
				/* Keepalive? */
				break;
			case TCPS_FIN_WAIT_1:
				if (!tcp->tcp_fin_acked) {
					tcp->tcp_state = TCPS_CLOSING;
					break;
				}
				/* FALLTHRU */
			case TCPS_FIN_WAIT_2:
				tcp->tcp_state = TCPS_TIME_WAIT;
				/*
				 * Unconditionally clear the exclusive binding
				 * bit so this TIME-WAIT connection won't
				 * interfere with new ones.
				 */
				tcp->tcp_exclbind = 0;
				if (!TCP_IS_DETACHED(tcp)) {
					TCP_TIMER_RESTART(tcp,
					    tcps->tcps_time_wait_interval);
				} else {
					tcp_time_wait_append(tcp);
					TCP_DBGSTAT(tcps, tcp_rput_time_wait);
				}
				if (seg_len) {
					/*
					 * implies data piggybacked on FIN.
					 * break to handle data.
					 */
					break;
				}
				freemsg(mp);
				goto ack_check;
			}
		}
	}
	if (mp == NULL)
		goto xmit_check;
	if (seg_len == 0) {
		freemsg(mp);
		goto xmit_check;
	}
	if (mp->b_rptr == mp->b_wptr) {
		/*
		 * The header has been consumed, so we remove the
		 * zero-length mblk here.
		 */
		mp1 = mp;
		mp = mp->b_cont;
		freeb(mp1);
	}
update_ack:
	tcph = tcp->tcp_tcph;
	tcp->tcp_rack_cnt++;
	{
		uint32_t cur_max;

		cur_max = tcp->tcp_rack_cur_max;
		if (tcp->tcp_rack_cnt >= cur_max) {
			/*
			 * We have more unacked data than we should - send
			 * an ACK now.
			 */
			flags |= TH_ACK_NEEDED;
			cur_max++;
			if (cur_max > tcp->tcp_rack_abs_max)
				tcp->tcp_rack_cur_max = tcp->tcp_rack_abs_max;
			else
				tcp->tcp_rack_cur_max = cur_max;
		} else if (TCP_IS_DETACHED(tcp)) {
			/* We don't have an ACK timer for detached TCP. */
			flags |= TH_ACK_NEEDED;
		} else if (seg_len < mss) {
			/*
			 * If we get a segment that is less than an mss, and we
			 * already have unacknowledged data, and the amount
			 * unacknowledged is not a multiple of mss, then we
			 * better generate an ACK now.  Otherwise, this may be
			 * the tail piece of a transaction, and we would rather
			 * wait for the response.
			 */
			uint32_t udif;
			ASSERT((uintptr_t)(tcp->tcp_rnxt - tcp->tcp_rack) <=
			    (uintptr_t)INT_MAX);
			udif = (int)(tcp->tcp_rnxt - tcp->tcp_rack);
			if (udif && (udif % mss))
				flags |= TH_ACK_NEEDED;
			else
				flags |= TH_ACK_TIMER_NEEDED;
		} else {
			/* Start delayed ack timer */
			flags |= TH_ACK_TIMER_NEEDED;
		}
	}
	tcp->tcp_rnxt += seg_len;
	U32_TO_ABE32(tcp->tcp_rnxt, tcph->th_ack);

	if (mp == NULL)
		goto xmit_check;

	/* Update SACK list */
	if (tcp->tcp_snd_sack_ok && tcp->tcp_num_sack_blk > 0) {
		tcp_sack_remove(tcp->tcp_sack_list, tcp->tcp_rnxt,
		    &(tcp->tcp_num_sack_blk));
	}

	if (tcp->tcp_urp_mp) {
		tcp->tcp_urp_mp->b_cont = mp;
		mp = tcp->tcp_urp_mp;
		tcp->tcp_urp_mp = NULL;
		/* Ready for a new signal. */
		tcp->tcp_urp_last_valid = B_FALSE;
#ifdef DEBUG
		(void) strlog(TCP_MOD_ID, 0, 1, SL_TRACE,
		    "tcp_rput: sending exdata_ind %s",
		    tcp_display(tcp, NULL, DISP_PORT_ONLY));
#endif /* DEBUG */
	}

	/*
	 * Check for ancillary data changes compared to last segment.
	 */
	if (tcp->tcp_ipv6_recvancillary != 0) {
		mp = tcp_rput_add_ancillary(tcp, mp, &ipp);
		ASSERT(mp != NULL);
	}

	if (tcp->tcp_listener || tcp->tcp_hard_binding) {
		/*
		 * Side queue inbound data until the accept happens.
		 * tcp_accept/tcp_rput drains this when the accept happens.
		 * M_DATA is queued on b_cont. Otherwise (T_OPTDATA_IND or
		 * T_EXDATA_IND) it is queued on b_next.
		 * XXX Make urgent data use this. Requires:
		 *	Removing tcp_listener check for TH_URG
		 *	Making M_PCPROTO and MARK messages skip the eager case
		 */

		if (tcp->tcp_kssl_pending) {
			DTRACE_PROBE1(kssl_mblk__ksslinput_pending,
			    mblk_t *, mp);
			tcp_kssl_input(tcp, mp);
		} else {
			tcp_rcv_enqueue(tcp, mp, seg_len);
		}
	} else {
		sodirect_t	*sodp = tcp->tcp_sodirect;

		/*
		 * If an sodirect connection and an enabled sodirect_t then
		 * sodp will be set to point to the tcp_t/sonode_t shared
		 * sodirect_t and the sodirect_t's lock will be held.
		 */
		if (sodp != NULL) {
			mutex_enter(sodp->sod_lockp);
			if (!(sodp->sod_state & SOD_ENABLED) ||
			    (tcp->tcp_kssl_ctx != NULL &&
			    DB_TYPE(mp) == M_DATA)) {
				sodp = NULL;
			}
			mutex_exit(sodp->sod_lockp);
		}
		if (mp->b_datap->db_type != M_DATA ||
		    (flags & TH_MARKNEXT_NEEDED)) {
			if (IPCL_IS_NONSTR(connp)) {
				int error;

				if ((*connp->conn_upcalls->su_recv)
				    (connp->conn_upper_handle, mp,
				    seg_len, 0, &error, NULL) <= 0) {
					if (error == ENOSPC) {
						tcp->tcp_rwnd -= seg_len;
					} else if (error == EOPNOTSUPP) {
						tcp_rcv_enqueue(tcp, mp,
						    seg_len);
					}
				}
			} else if (sodp != NULL) {
				mutex_enter(sodp->sod_lockp);
				SOD_UIOAFINI(sodp);
				if (!SOD_QEMPTY(sodp) &&
				    (sodp->sod_state & SOD_WAKE_NOT)) {
					flags |= tcp_rcv_sod_wakeup(tcp, sodp);
					/* sod_wakeup() did the mutex_exit() */
				} else {
					mutex_exit(sodp->sod_lockp);
				}
			} else if (tcp->tcp_rcv_list != NULL) {
				flags |= tcp_rcv_drain(tcp);
			}
			ASSERT(tcp->tcp_rcv_list == NULL ||
			    tcp->tcp_fused_sigurg);

			if (flags & TH_MARKNEXT_NEEDED) {
#ifdef DEBUG
				(void) strlog(TCP_MOD_ID, 0, 1, SL_TRACE,
				    "tcp_rput: sending MSGMARKNEXT %s",
				    tcp_display(tcp, NULL,
				    DISP_PORT_ONLY));
#endif /* DEBUG */
				mp->b_flag |= MSGMARKNEXT;
				flags &= ~TH_MARKNEXT_NEEDED;
			}

			/* Does this need SSL processing first? */
			if ((tcp->tcp_kssl_ctx != NULL) &&
			    (DB_TYPE(mp) == M_DATA)) {
				DTRACE_PROBE1(kssl_mblk__ksslinput_data1,
				    mblk_t *, mp);
				tcp_kssl_input(tcp, mp);
			} else if (!IPCL_IS_NONSTR(connp)) {
				/* Already handled non-STREAMS case. */
				putnext(tcp->tcp_rq, mp);
				if (!canputnext(tcp->tcp_rq))
					tcp->tcp_rwnd -= seg_len;
			}
		} else if ((tcp->tcp_kssl_ctx != NULL) &&
		    (DB_TYPE(mp) == M_DATA)) {
			/* Does this need SSL processing first? */
			DTRACE_PROBE1(kssl_mblk__ksslinput_data2, mblk_t *, mp);
			tcp_kssl_input(tcp, mp);
		} else if (IPCL_IS_NONSTR(connp)) {
			/* Non-STREAMS socket */
			boolean_t push = flags & (TH_PUSH|TH_FIN);
			int	error;

			if ((*connp->conn_upcalls->su_recv)(
			    connp->conn_upper_handle,
			    mp, seg_len, 0, &error, &push) <= 0) {
				if (error == ENOSPC) {
					tcp->tcp_rwnd -= seg_len;
				} else if (error == EOPNOTSUPP) {
					tcp_rcv_enqueue(tcp, mp, seg_len);
				}
			} else if (push) {
				/*
				 * PUSH bit set and sockfs is not
				 * flow controlled
				 */
				flags |= tcp_rwnd_reopen(tcp);
			}
		} else if (sodp != NULL) {
			/*
			 * Sodirect so all mblk_t's are queued on the
			 * socket directly, check for wakeup of blocked
			 * reader (if any), and last if flow-controled.
			 */
			mutex_enter(sodp->sod_lockp);
			flags |= tcp_rcv_sod_enqueue(tcp, sodp, mp, seg_len);
			if ((sodp->sod_state & SOD_WAKE_NEED) ||
			    (flags & (TH_PUSH|TH_FIN))) {
				flags |= tcp_rcv_sod_wakeup(tcp, sodp);
				/* sod_wakeup() did the mutex_exit() */
			} else {
				if (SOD_QFULL(sodp)) {
					/* Q is full, need backenable */
					SOD_QSETBE(sodp);
				}
				mutex_exit(sodp->sod_lockp);
			}
		} else if ((flags & (TH_PUSH|TH_FIN)) ||
		    tcp->tcp_rcv_cnt + seg_len >= tcp->tcp_recv_hiwater >> 3) {
			if (tcp->tcp_rcv_list != NULL) {
				/*
				 * Enqueue the new segment first and then
				 * call tcp_rcv_drain() to send all data
				 * up.  The other way to do this is to
				 * send all queued data up and then call
				 * putnext() to send the new segment up.
				 * This way can remove the else part later
				 * on.
				 *
				 * We don't do this to avoid one more call to
				 * canputnext() as tcp_rcv_drain() needs to
				 * call canputnext().
				 */
				tcp_rcv_enqueue(tcp, mp, seg_len);
				flags |= tcp_rcv_drain(tcp);
			} else {
				putnext(tcp->tcp_rq, mp);
				if (!canputnext(tcp->tcp_rq))
					tcp->tcp_rwnd -= seg_len;
			}
		} else {
			/*
			 * Enqueue all packets when processing an mblk
			 * from the co queue and also enqueue normal packets.
			 * For packets which belong to SSL stream do SSL
			 * processing first.
			 */
			tcp_rcv_enqueue(tcp, mp, seg_len);
		}
		/*
		 * Make sure the timer is running if we have data waiting
		 * for a push bit. This provides resiliency against
		 * implementations that do not correctly generate push bits.
		 *
		 * Note, for sodirect if Q isn't empty and there's not a
		 * pending wakeup then we need a timer. Also note that sodp
		 * is assumed to be still valid after exit()ing the sod_lockp
		 * above and while the SOD state can change it can only change
		 * such that the Q is empty now even though data was added
		 * above.
		 */
		if (!IPCL_IS_NONSTR(connp) &&
		    ((sodp != NULL && !SOD_QEMPTY(sodp) &&
		    (sodp->sod_state & SOD_WAKE_NOT)) ||
		    (sodp == NULL && tcp->tcp_rcv_list != NULL)) &&
		    tcp->tcp_push_tid == 0) {
			/*
			 * The connection may be closed at this point, so don't
			 * do anything for a detached tcp.
			 */
			if (!TCP_IS_DETACHED(tcp))
				tcp->tcp_push_tid = TCP_TIMER(tcp,
				    tcp_push_timer,
				    MSEC_TO_TICK(
				    tcps->tcps_push_timer_interval));
		}
	}

xmit_check:
	/* Is there anything left to do? */
	ASSERT(!(flags & TH_MARKNEXT_NEEDED));
	if ((flags & (TH_REXMIT_NEEDED|TH_XMIT_NEEDED|TH_ACK_NEEDED|
	    TH_NEED_SACK_REXMIT|TH_LIMIT_XMIT|TH_ACK_TIMER_NEEDED|
	    TH_ORDREL_NEEDED|TH_SEND_URP_MARK)) == 0)
		goto done;

	/* Any transmit work to do and a non-zero window? */
	if ((flags & (TH_REXMIT_NEEDED|TH_XMIT_NEEDED|TH_NEED_SACK_REXMIT|
	    TH_LIMIT_XMIT)) && tcp->tcp_swnd != 0) {
		if (flags & TH_REXMIT_NEEDED) {
			uint32_t snd_size = tcp->tcp_snxt - tcp->tcp_suna;

			BUMP_MIB(&tcps->tcps_mib, tcpOutFastRetrans);
			if (snd_size > mss)
				snd_size = mss;
			if (snd_size > tcp->tcp_swnd)
				snd_size = tcp->tcp_swnd;
			mp1 = tcp_xmit_mp(tcp, tcp->tcp_xmit_head, snd_size,
			    NULL, NULL, tcp->tcp_suna, B_TRUE, &snd_size,
			    B_TRUE);

			if (mp1 != NULL) {
				tcp->tcp_xmit_head->b_prev = (mblk_t *)lbolt;
				tcp->tcp_csuna = tcp->tcp_snxt;
				BUMP_MIB(&tcps->tcps_mib, tcpRetransSegs);
				UPDATE_MIB(&tcps->tcps_mib,
				    tcpRetransBytes, snd_size);
				tcp_send_data(tcp, tcp->tcp_wq, mp1);
			}
		}
		if (flags & TH_NEED_SACK_REXMIT) {
			tcp_sack_rxmit(tcp, &flags);
		}
		/*
		 * For TH_LIMIT_XMIT, tcp_wput_data() is called to send
		 * out new segment.  Note that tcp_rexmit should not be
		 * set, otherwise TH_LIMIT_XMIT should not be set.
		 */
		if (flags & (TH_XMIT_NEEDED|TH_LIMIT_XMIT)) {
			if (!tcp->tcp_rexmit) {
				tcp_wput_data(tcp, NULL, B_FALSE);
			} else {
				tcp_ss_rexmit(tcp);
			}
		}
		/*
		 * Adjust tcp_cwnd back to normal value after sending
		 * new data segments.
		 */
		if (flags & TH_LIMIT_XMIT) {
			tcp->tcp_cwnd -= mss << (tcp->tcp_dupack_cnt - 1);
			/*
			 * This will restart the timer.  Restarting the
			 * timer is used to avoid a timeout before the
			 * limited transmitted segment's ACK gets back.
			 */
			if (tcp->tcp_xmit_head != NULL)
				tcp->tcp_xmit_head->b_prev = (mblk_t *)lbolt;
		}

		/* Anything more to do? */
		if ((flags & (TH_ACK_NEEDED|TH_ACK_TIMER_NEEDED|
		    TH_ORDREL_NEEDED|TH_SEND_URP_MARK)) == 0)
			goto done;
	}
ack_check:
	if (flags & TH_SEND_URP_MARK) {
		ASSERT(tcp->tcp_urp_mark_mp);
		ASSERT(!IPCL_IS_NONSTR(connp));
		/*
		 * Send up any queued data and then send the mark message
		 */
		sodirect_t *sodp;

		SOD_PTR_ENTER(tcp, sodp);

		mp1 = tcp->tcp_urp_mark_mp;
		tcp->tcp_urp_mark_mp = NULL;
		if (sodp != NULL) {
			if (sodp->sod_uioa.uioa_state & UIOA_ENABLED) {
				sodp->sod_uioa.uioa_state &= UIOA_CLR;
				sodp->sod_uioa.uioa_state |= UIOA_FINI;
			}
			ASSERT(tcp->tcp_rcv_list == NULL);

			flags |= tcp_rcv_sod_wakeup(tcp, sodp);
			/* sod_wakeup() does the mutex_exit() */
		} else if (tcp->tcp_rcv_list != NULL) {
			flags |= tcp_rcv_drain(tcp);

			ASSERT(tcp->tcp_rcv_list == NULL ||
			    tcp->tcp_fused_sigurg);

		}
		putnext(tcp->tcp_rq, mp1);
#ifdef DEBUG
		(void) strlog(TCP_MOD_ID, 0, 1, SL_TRACE,
		    "tcp_rput: sending zero-length %s %s",
		    ((mp1->b_flag & MSGMARKNEXT) ? "MSGMARKNEXT" :
		    "MSGNOTMARKNEXT"),
		    tcp_display(tcp, NULL, DISP_PORT_ONLY));
#endif /* DEBUG */
		flags &= ~TH_SEND_URP_MARK;
	}
	if (flags & TH_ACK_NEEDED) {
		/*
		 * Time to send an ack for some reason.
		 */
		mp1 = tcp_ack_mp(tcp);

		if (mp1 != NULL) {
			tcp_send_data(tcp, tcp->tcp_wq, mp1);
			BUMP_LOCAL(tcp->tcp_obsegs);
			BUMP_MIB(&tcps->tcps_mib, tcpOutAck);
		}
		if (tcp->tcp_ack_tid != 0) {
			(void) TCP_TIMER_CANCEL(tcp, tcp->tcp_ack_tid);
			tcp->tcp_ack_tid = 0;
		}
	}
	if (flags & TH_ACK_TIMER_NEEDED) {
		/*
		 * Arrange for deferred ACK or push wait timeout.
		 * Start timer if it is not already running.
		 */
		if (tcp->tcp_ack_tid == 0) {
			tcp->tcp_ack_tid = TCP_TIMER(tcp, tcp_ack_timer,
			    MSEC_TO_TICK(tcp->tcp_localnet ?
			    (clock_t)tcps->tcps_local_dack_interval :
			    (clock_t)tcps->tcps_deferred_ack_interval));
		}
	}
	if (flags & TH_ORDREL_NEEDED) {
		/*
		 * Send up the ordrel_ind unless we are an eager guy.
		 * In the eager case tcp_rsrv will do this when run
		 * after tcp_accept is done.
		 */
		sodirect_t *sodp;

		ASSERT(tcp->tcp_listener == NULL);

		if (IPCL_IS_NONSTR(connp)) {
			ASSERT(tcp->tcp_ordrel_mp == NULL);
			tcp->tcp_ordrel_done = B_TRUE;
			(*connp->conn_upcalls->su_opctl)
			    (connp->conn_upper_handle, SOCK_OPCTL_SHUT_RECV, 0);
			goto done;
		}

		SOD_PTR_ENTER(tcp, sodp);
		if (sodp != NULL) {
			if (sodp->sod_uioa.uioa_state & UIOA_ENABLED) {
				sodp->sod_uioa.uioa_state &= UIOA_CLR;
				sodp->sod_uioa.uioa_state |= UIOA_FINI;
			}
			/* No more sodirect */
			tcp->tcp_sodirect = NULL;
			if (!SOD_QEMPTY(sodp)) {
				/* Mblk(s) to process, notify */
				flags |= tcp_rcv_sod_wakeup(tcp, sodp);
				/* sod_wakeup() does the mutex_exit() */
			} else {
				/* Nothing to process */
				mutex_exit(sodp->sod_lockp);
			}
		} else if (tcp->tcp_rcv_list != NULL) {
			/*
			 * Push any mblk(s) enqueued from co processing.
			 */
			flags |= tcp_rcv_drain(tcp);

			ASSERT(tcp->tcp_rcv_list == NULL ||
			    tcp->tcp_fused_sigurg);
		}

		mp1 = tcp->tcp_ordrel_mp;
		tcp->tcp_ordrel_mp = NULL;
		tcp->tcp_ordrel_done = B_TRUE;
		putnext(tcp->tcp_rq, mp1);
	}
done:
	ASSERT(!(flags & TH_MARKNEXT_NEEDED));
}

/*
 * This function does PAWS protection check. Returns B_TRUE if the
 * segment passes the PAWS test, else returns B_FALSE.
 */
boolean_t
tcp_paws_check(tcp_t *tcp, tcph_t *tcph, tcp_opt_t *tcpoptp)
{
	uint8_t	flags;
	int	options;
	uint8_t *up;

	flags = (unsigned int)tcph->th_flags[0] & 0xFF;
	/*
	 * If timestamp option is aligned nicely, get values inline,
	 * otherwise call general routine to parse.  Only do that
	 * if timestamp is the only option.
	 */
	if (TCP_HDR_LENGTH(tcph) == (uint32_t)TCP_MIN_HEADER_LENGTH +
	    TCPOPT_REAL_TS_LEN &&
	    OK_32PTR((up = ((uint8_t *)tcph) +
	    TCP_MIN_HEADER_LENGTH)) &&
	    *(uint32_t *)up == TCPOPT_NOP_NOP_TSTAMP) {
		tcpoptp->tcp_opt_ts_val = ABE32_TO_U32((up+4));
		tcpoptp->tcp_opt_ts_ecr = ABE32_TO_U32((up+8));

		options = TCP_OPT_TSTAMP_PRESENT;
	} else {
		if (tcp->tcp_snd_sack_ok) {
			tcpoptp->tcp = tcp;
		} else {
			tcpoptp->tcp = NULL;
		}
		options = tcp_parse_options(tcph, tcpoptp);
	}

	if (options & TCP_OPT_TSTAMP_PRESENT) {
		/*
		 * Do PAWS per RFC 1323 section 4.2.  Accept RST
		 * regardless of the timestamp, page 18 RFC 1323.bis.
		 */
		if ((flags & TH_RST) == 0 &&
		    TSTMP_LT(tcpoptp->tcp_opt_ts_val,
		    tcp->tcp_ts_recent)) {
			if (TSTMP_LT(lbolt64, tcp->tcp_last_rcv_lbolt +
			    PAWS_TIMEOUT)) {
				/* This segment is not acceptable. */
				return (B_FALSE);
			} else {
				/*
				 * Connection has been idle for
				 * too long.  Reset the timestamp
				 * and assume the segment is valid.
				 */
				tcp->tcp_ts_recent =
				    tcpoptp->tcp_opt_ts_val;
			}
		}
	} else {
		/*
		 * If we don't get a timestamp on every packet, we
		 * figure we can't really trust 'em, so we stop sending
		 * and parsing them.
		 */
		tcp->tcp_snd_ts_ok = B_FALSE;

		tcp->tcp_hdr_len -= TCPOPT_REAL_TS_LEN;
		tcp->tcp_tcp_hdr_len -= TCPOPT_REAL_TS_LEN;
		tcp->tcp_tcph->th_offset_and_rsrvd[0] -= (3 << 4);
		/*
		 * Adjust the tcp_mss accordingly. We also need to
		 * adjust tcp_cwnd here in accordance with the new mss.
		 * But we avoid doing a slow start here so as to not
		 * to lose on the transfer rate built up so far.
		 */
		tcp_mss_set(tcp, tcp->tcp_mss + TCPOPT_REAL_TS_LEN, B_FALSE);
		if (tcp->tcp_snd_sack_ok) {
			ASSERT(tcp->tcp_sack_info != NULL);
			tcp->tcp_max_sack_blk = 4;
		}
	}
	return (B_TRUE);
}

/*
 * Attach ancillary data to a received TCP segments for the
 * ancillary pieces requested by the application that are
 * different than they were in the previous data segment.
 *
 * Save the "current" values once memory allocation is ok so that
 * when memory allocation fails we can just wait for the next data segment.
 */
static mblk_t *
tcp_rput_add_ancillary(tcp_t *tcp, mblk_t *mp, ip6_pkt_t *ipp)
{
	struct T_optdata_ind *todi;
	int optlen;
	uchar_t *optptr;
	struct T_opthdr *toh;
	uint_t addflag;	/* Which pieces to add */
	mblk_t *mp1;

	optlen = 0;
	addflag = 0;
	/* If app asked for pktinfo and the index has changed ... */
	if ((ipp->ipp_fields & IPPF_IFINDEX) &&
	    ipp->ipp_ifindex != tcp->tcp_recvifindex &&
	    (tcp->tcp_ipv6_recvancillary & TCP_IPV6_RECVPKTINFO)) {
		optlen += sizeof (struct T_opthdr) +
		    sizeof (struct in6_pktinfo);
		addflag |= TCP_IPV6_RECVPKTINFO;
	}
	/* If app asked for hoplimit and it has changed ... */
	if ((ipp->ipp_fields & IPPF_HOPLIMIT) &&
	    ipp->ipp_hoplimit != tcp->tcp_recvhops &&
	    (tcp->tcp_ipv6_recvancillary & TCP_IPV6_RECVHOPLIMIT)) {
		optlen += sizeof (struct T_opthdr) + sizeof (uint_t);
		addflag |= TCP_IPV6_RECVHOPLIMIT;
	}
	/* If app asked for tclass and it has changed ... */
	if ((ipp->ipp_fields & IPPF_TCLASS) &&
	    ipp->ipp_tclass != tcp->tcp_recvtclass &&
	    (tcp->tcp_ipv6_recvancillary & TCP_IPV6_RECVTCLASS)) {
		optlen += sizeof (struct T_opthdr) + sizeof (uint_t);
		addflag |= TCP_IPV6_RECVTCLASS;
	}
	/*
	 * If app asked for hopbyhop headers and it has changed ...
	 * For security labels, note that (1) security labels can't change on
	 * a connected socket at all, (2) we're connected to at most one peer,
	 * (3) if anything changes, then it must be some other extra option.
	 */
	if ((tcp->tcp_ipv6_recvancillary & TCP_IPV6_RECVHOPOPTS) &&
	    ip_cmpbuf(tcp->tcp_hopopts, tcp->tcp_hopoptslen,
	    (ipp->ipp_fields & IPPF_HOPOPTS),
	    ipp->ipp_hopopts, ipp->ipp_hopoptslen)) {
		optlen += sizeof (struct T_opthdr) + ipp->ipp_hopoptslen -
		    tcp->tcp_label_len;
		addflag |= TCP_IPV6_RECVHOPOPTS;
		if (!ip_allocbuf((void **)&tcp->tcp_hopopts,
		    &tcp->tcp_hopoptslen, (ipp->ipp_fields & IPPF_HOPOPTS),
		    ipp->ipp_hopopts, ipp->ipp_hopoptslen))
			return (mp);
	}
	/* If app asked for dst headers before routing headers ... */
	if ((tcp->tcp_ipv6_recvancillary & TCP_IPV6_RECVRTDSTOPTS) &&
	    ip_cmpbuf(tcp->tcp_rtdstopts, tcp->tcp_rtdstoptslen,
	    (ipp->ipp_fields & IPPF_RTDSTOPTS),
	    ipp->ipp_rtdstopts, ipp->ipp_rtdstoptslen)) {
		optlen += sizeof (struct T_opthdr) +
		    ipp->ipp_rtdstoptslen;
		addflag |= TCP_IPV6_RECVRTDSTOPTS;
		if (!ip_allocbuf((void **)&tcp->tcp_rtdstopts,
		    &tcp->tcp_rtdstoptslen, (ipp->ipp_fields & IPPF_RTDSTOPTS),
		    ipp->ipp_rtdstopts, ipp->ipp_rtdstoptslen))
			return (mp);
	}
	/* If app asked for routing headers and it has changed ... */
	if ((tcp->tcp_ipv6_recvancillary & TCP_IPV6_RECVRTHDR) &&
	    ip_cmpbuf(tcp->tcp_rthdr, tcp->tcp_rthdrlen,
	    (ipp->ipp_fields & IPPF_RTHDR),
	    ipp->ipp_rthdr, ipp->ipp_rthdrlen)) {
		optlen += sizeof (struct T_opthdr) + ipp->ipp_rthdrlen;
		addflag |= TCP_IPV6_RECVRTHDR;
		if (!ip_allocbuf((void **)&tcp->tcp_rthdr,
		    &tcp->tcp_rthdrlen, (ipp->ipp_fields & IPPF_RTHDR),
		    ipp->ipp_rthdr, ipp->ipp_rthdrlen))
			return (mp);
	}
	/* If app asked for dest headers and it has changed ... */
	if ((tcp->tcp_ipv6_recvancillary &
	    (TCP_IPV6_RECVDSTOPTS | TCP_OLD_IPV6_RECVDSTOPTS)) &&
	    ip_cmpbuf(tcp->tcp_dstopts, tcp->tcp_dstoptslen,
	    (ipp->ipp_fields & IPPF_DSTOPTS),
	    ipp->ipp_dstopts, ipp->ipp_dstoptslen)) {
		optlen += sizeof (struct T_opthdr) + ipp->ipp_dstoptslen;
		addflag |= TCP_IPV6_RECVDSTOPTS;
		if (!ip_allocbuf((void **)&tcp->tcp_dstopts,
		    &tcp->tcp_dstoptslen, (ipp->ipp_fields & IPPF_DSTOPTS),
		    ipp->ipp_dstopts, ipp->ipp_dstoptslen))
			return (mp);
	}

	if (optlen == 0) {
		/* Nothing to add */
		return (mp);
	}
	mp1 = allocb(sizeof (struct T_optdata_ind) + optlen, BPRI_MED);
	if (mp1 == NULL) {
		/*
		 * Defer sending ancillary data until the next TCP segment
		 * arrives.
		 */
		return (mp);
	}
	mp1->b_cont = mp;
	mp = mp1;
	mp->b_wptr += sizeof (*todi) + optlen;
	mp->b_datap->db_type = M_PROTO;
	todi = (struct T_optdata_ind *)mp->b_rptr;
	todi->PRIM_type = T_OPTDATA_IND;
	todi->DATA_flag = 1;	/* MORE data */
	todi->OPT_length = optlen;
	todi->OPT_offset = sizeof (*todi);
	optptr = (uchar_t *)&todi[1];
	/*
	 * If app asked for pktinfo and the index has changed ...
	 * Note that the local address never changes for the connection.
	 */
	if (addflag & TCP_IPV6_RECVPKTINFO) {
		struct in6_pktinfo *pkti;

		toh = (struct T_opthdr *)optptr;
		toh->level = IPPROTO_IPV6;
		toh->name = IPV6_PKTINFO;
		toh->len = sizeof (*toh) + sizeof (*pkti);
		toh->status = 0;
		optptr += sizeof (*toh);
		pkti = (struct in6_pktinfo *)optptr;
		if (tcp->tcp_ipversion == IPV6_VERSION)
			pkti->ipi6_addr = tcp->tcp_ip6h->ip6_src;
		else
			IN6_IPADDR_TO_V4MAPPED(tcp->tcp_ipha->ipha_src,
			    &pkti->ipi6_addr);
		pkti->ipi6_ifindex = ipp->ipp_ifindex;
		optptr += sizeof (*pkti);
		ASSERT(OK_32PTR(optptr));
		/* Save as "last" value */
		tcp->tcp_recvifindex = ipp->ipp_ifindex;
	}
	/* If app asked for hoplimit and it has changed ... */
	if (addflag & TCP_IPV6_RECVHOPLIMIT) {
		toh = (struct T_opthdr *)optptr;
		toh->level = IPPROTO_IPV6;
		toh->name = IPV6_HOPLIMIT;
		toh->len = sizeof (*toh) + sizeof (uint_t);
		toh->status = 0;
		optptr += sizeof (*toh);
		*(uint_t *)optptr = ipp->ipp_hoplimit;
		optptr += sizeof (uint_t);
		ASSERT(OK_32PTR(optptr));
		/* Save as "last" value */
		tcp->tcp_recvhops = ipp->ipp_hoplimit;
	}
	/* If app asked for tclass and it has changed ... */
	if (addflag & TCP_IPV6_RECVTCLASS) {
		toh = (struct T_opthdr *)optptr;
		toh->level = IPPROTO_IPV6;
		toh->name = IPV6_TCLASS;
		toh->len = sizeof (*toh) + sizeof (uint_t);
		toh->status = 0;
		optptr += sizeof (*toh);
		*(uint_t *)optptr = ipp->ipp_tclass;
		optptr += sizeof (uint_t);
		ASSERT(OK_32PTR(optptr));
		/* Save as "last" value */
		tcp->tcp_recvtclass = ipp->ipp_tclass;
	}
	if (addflag & TCP_IPV6_RECVHOPOPTS) {
		toh = (struct T_opthdr *)optptr;
		toh->level = IPPROTO_IPV6;
		toh->name = IPV6_HOPOPTS;
		toh->len = sizeof (*toh) + ipp->ipp_hopoptslen -
		    tcp->tcp_label_len;
		toh->status = 0;
		optptr += sizeof (*toh);
		bcopy((uchar_t *)ipp->ipp_hopopts + tcp->tcp_label_len, optptr,
		    ipp->ipp_hopoptslen - tcp->tcp_label_len);
		optptr += ipp->ipp_hopoptslen - tcp->tcp_label_len;
		ASSERT(OK_32PTR(optptr));
		/* Save as last value */
		ip_savebuf((void **)&tcp->tcp_hopopts, &tcp->tcp_hopoptslen,
		    (ipp->ipp_fields & IPPF_HOPOPTS),
		    ipp->ipp_hopopts, ipp->ipp_hopoptslen);
	}
	if (addflag & TCP_IPV6_RECVRTDSTOPTS) {
		toh = (struct T_opthdr *)optptr;
		toh->level = IPPROTO_IPV6;
		toh->name = IPV6_RTHDRDSTOPTS;
		toh->len = sizeof (*toh) + ipp->ipp_rtdstoptslen;
		toh->status = 0;
		optptr += sizeof (*toh);
		bcopy(ipp->ipp_rtdstopts, optptr, ipp->ipp_rtdstoptslen);
		optptr += ipp->ipp_rtdstoptslen;
		ASSERT(OK_32PTR(optptr));
		/* Save as last value */
		ip_savebuf((void **)&tcp->tcp_rtdstopts,
		    &tcp->tcp_rtdstoptslen,
		    (ipp->ipp_fields & IPPF_RTDSTOPTS),
		    ipp->ipp_rtdstopts, ipp->ipp_rtdstoptslen);
	}
	if (addflag & TCP_IPV6_RECVRTHDR) {
		toh = (struct T_opthdr *)optptr;
		toh->level = IPPROTO_IPV6;
		toh->name = IPV6_RTHDR;
		toh->len = sizeof (*toh) + ipp->ipp_rthdrlen;
		toh->status = 0;
		optptr += sizeof (*toh);
		bcopy(ipp->ipp_rthdr, optptr, ipp->ipp_rthdrlen);
		optptr += ipp->ipp_rthdrlen;
		ASSERT(OK_32PTR(optptr));
		/* Save as last value */
		ip_savebuf((void **)&tcp->tcp_rthdr, &tcp->tcp_rthdrlen,
		    (ipp->ipp_fields & IPPF_RTHDR),
		    ipp->ipp_rthdr, ipp->ipp_rthdrlen);
	}
	if (addflag & (TCP_IPV6_RECVDSTOPTS | TCP_OLD_IPV6_RECVDSTOPTS)) {
		toh = (struct T_opthdr *)optptr;
		toh->level = IPPROTO_IPV6;
		toh->name = IPV6_DSTOPTS;
		toh->len = sizeof (*toh) + ipp->ipp_dstoptslen;
		toh->status = 0;
		optptr += sizeof (*toh);
		bcopy(ipp->ipp_dstopts, optptr, ipp->ipp_dstoptslen);
		optptr += ipp->ipp_dstoptslen;
		ASSERT(OK_32PTR(optptr));
		/* Save as last value */
		ip_savebuf((void **)&tcp->tcp_dstopts, &tcp->tcp_dstoptslen,
		    (ipp->ipp_fields & IPPF_DSTOPTS),
		    ipp->ipp_dstopts, ipp->ipp_dstoptslen);
	}
	ASSERT(optptr == mp->b_wptr);
	return (mp);
}

/*
 * tcp_rput_other is called by tcp_rput to handle everything other than M_DATA
 * messages.
 */
void
tcp_rput_other(tcp_t *tcp, mblk_t *mp)
{
	uchar_t	*rptr = mp->b_rptr;
	queue_t	*q = tcp->tcp_rq;
	struct T_error_ack *tea;

	switch (mp->b_datap->db_type) {
	case M_PROTO:
	case M_PCPROTO:
		ASSERT((uintptr_t)(mp->b_wptr - rptr) <= (uintptr_t)INT_MAX);
		if ((mp->b_wptr - rptr) < sizeof (t_scalar_t))
			break;
		tea = (struct T_error_ack *)rptr;
		ASSERT(tea->PRIM_type != T_BIND_ACK);
		ASSERT(tea->ERROR_prim != O_T_BIND_REQ &&
		    tea->ERROR_prim != T_BIND_REQ);
		switch (tea->PRIM_type) {
		case T_ERROR_ACK:
			if (tcp->tcp_debug) {
				(void) strlog(TCP_MOD_ID, 0, 1,
				    SL_TRACE|SL_ERROR,
				    "tcp_rput_other: case T_ERROR_ACK, "
				    "ERROR_prim == %d",
				    tea->ERROR_prim);
			}
			switch (tea->ERROR_prim) {
			case T_SVR4_OPTMGMT_REQ:
				if (tcp->tcp_drop_opt_ack_cnt > 0) {
					/* T_OPTMGMT_REQ generated by TCP */
					printf("T_SVR4_OPTMGMT_REQ failed "
					    "%d/%d - dropped (cnt %d)\n",
					    tea->TLI_error, tea->UNIX_error,
					    tcp->tcp_drop_opt_ack_cnt);
					freemsg(mp);
					tcp->tcp_drop_opt_ack_cnt--;
					return;
				}
				break;
			}
			if (tea->ERROR_prim == T_SVR4_OPTMGMT_REQ &&
			    tcp->tcp_drop_opt_ack_cnt > 0) {
				printf("T_SVR4_OPTMGMT_REQ failed %d/%d "
				    "- dropped (cnt %d)\n",
				    tea->TLI_error, tea->UNIX_error,
				    tcp->tcp_drop_opt_ack_cnt);
				freemsg(mp);
				tcp->tcp_drop_opt_ack_cnt--;
				return;
			}
			break;
		case T_OPTMGMT_ACK:
			if (tcp->tcp_drop_opt_ack_cnt > 0) {
				/* T_OPTMGMT_REQ generated by TCP */
				freemsg(mp);
				tcp->tcp_drop_opt_ack_cnt--;
				return;
			}
			break;
		default:
			ASSERT(tea->ERROR_prim != T_UNBIND_REQ);
			break;
		}
		break;
	case M_FLUSH:
		if (*rptr & FLUSHR)
			flushq(q, FLUSHDATA);
		break;
	default:
		/* M_CTL will be directly sent to tcp_icmp_error() */
		ASSERT(DB_TYPE(mp) != M_CTL);
		break;
	}
	/*
	 * Make sure we set this bit before sending the ACK for
	 * bind. Otherwise accept could possibly run and free
	 * this tcp struct.
	 */
	ASSERT(q != NULL);
	putnext(q, mp);
}

/* ARGSUSED */
static void
tcp_rsrv_input(void *arg, mblk_t *mp, void *arg2)
{
	conn_t	*connp = (conn_t *)arg;
	tcp_t	*tcp = connp->conn_tcp;
	queue_t	*q = tcp->tcp_rq;
	uint_t	thwin;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	sodirect_t	*sodp;
	boolean_t	fc;

	mutex_enter(&tcp->tcp_rsrv_mp_lock);
	tcp->tcp_rsrv_mp = mp;
	mutex_exit(&tcp->tcp_rsrv_mp_lock);

	TCP_STAT(tcps, tcp_rsrv_calls);

	if (TCP_IS_DETACHED(tcp) || q == NULL) {
		return;
	}

	if (tcp->tcp_fused) {
		tcp_t *peer_tcp = tcp->tcp_loopback_peer;

		ASSERT(tcp->tcp_fused);
		ASSERT(peer_tcp != NULL && peer_tcp->tcp_fused);
		ASSERT(peer_tcp->tcp_loopback_peer == tcp);
		ASSERT(!TCP_IS_DETACHED(tcp));
		ASSERT(tcp->tcp_connp->conn_sqp ==
		    peer_tcp->tcp_connp->conn_sqp);

		/*
		 * Normally we would not get backenabled in synchronous
		 * streams mode, but in case this happens, we need to plug
		 * synchronous streams during our drain to prevent a race
		 * with tcp_fuse_rrw() or tcp_fuse_rinfop().
		 */
		TCP_FUSE_SYNCSTR_PLUG_DRAIN(tcp);
		if (tcp->tcp_rcv_list != NULL)
			(void) tcp_rcv_drain(tcp);

		if (peer_tcp > tcp) {
			mutex_enter(&peer_tcp->tcp_non_sq_lock);
			mutex_enter(&tcp->tcp_non_sq_lock);
		} else {
			mutex_enter(&tcp->tcp_non_sq_lock);
			mutex_enter(&peer_tcp->tcp_non_sq_lock);
		}

		if (peer_tcp->tcp_flow_stopped &&
		    (TCP_UNSENT_BYTES(peer_tcp) <=
		    peer_tcp->tcp_xmit_lowater)) {
			tcp_clrqfull(peer_tcp);
		}
		mutex_exit(&peer_tcp->tcp_non_sq_lock);
		mutex_exit(&tcp->tcp_non_sq_lock);

		TCP_FUSE_SYNCSTR_UNPLUG_DRAIN(tcp);
		TCP_STAT(tcps, tcp_fusion_backenabled);
		return;
	}

	SOD_PTR_ENTER(tcp, sodp);
	if (sodp != NULL) {
		/* An sodirect connection */
		if (SOD_QFULL(sodp)) {
			/* Flow-controlled, need another back-enable */
			fc = B_TRUE;
			SOD_QSETBE(sodp);
		} else {
			/* Not flow-controlled */
			fc = B_FALSE;
		}
		mutex_exit(sodp->sod_lockp);
	} else if (canputnext(q)) {
		/* STREAMS, not flow-controlled */
		fc = B_FALSE;
	} else {
		/* STREAMS, flow-controlled */
		fc = B_TRUE;
	}
	if (!fc) {
		/* Not flow-controlled, open rwnd */
		tcp->tcp_rwnd = q->q_hiwat;
		thwin = ((uint_t)BE16_TO_U16(tcp->tcp_tcph->th_win))
		    << tcp->tcp_rcv_ws;
		thwin -= tcp->tcp_rnxt - tcp->tcp_rack;
		/*
		 * Send back a window update immediately if TCP is above
		 * ESTABLISHED state and the increase of the rcv window
		 * that the other side knows is at least 1 MSS after flow
		 * control is lifted.
		 */
		if (tcp->tcp_state >= TCPS_ESTABLISHED &&
		    (q->q_hiwat - thwin >= tcp->tcp_mss)) {
			tcp_xmit_ctl(NULL, tcp,
			    (tcp->tcp_swnd == 0) ? tcp->tcp_suna :
			    tcp->tcp_snxt, tcp->tcp_rnxt, TH_ACK);
			BUMP_MIB(&tcps->tcps_mib, tcpOutWinUpdate);
		}
	}
}

/*
 * The read side service routine is called mostly when we get back-enabled as a
 * result of flow control relief.  Since we don't actually queue anything in
 * TCP, we have no data to send out of here.  What we do is clear the receive
 * window, and send out a window update.
 */
static void
tcp_rsrv(queue_t *q)
{
	conn_t		*connp = Q_TO_CONN(q);
	tcp_t		*tcp = connp->conn_tcp;
	mblk_t		*mp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	/* No code does a putq on the read side */
	ASSERT(q->q_first == NULL);

	/* Nothing to do for the default queue */
	if (q == tcps->tcps_g_q) {
		return;
	}

	/*
	 * If tcp->tcp_rsrv_mp == NULL, it means that tcp_rsrv() has already
	 * been run.  So just return.
	 */
	mutex_enter(&tcp->tcp_rsrv_mp_lock);
	if ((mp = tcp->tcp_rsrv_mp) == NULL) {
		mutex_exit(&tcp->tcp_rsrv_mp_lock);
		return;
	}
	tcp->tcp_rsrv_mp = NULL;
	mutex_exit(&tcp->tcp_rsrv_mp_lock);

	CONN_INC_REF(connp);
	SQUEUE_ENTER_ONE(connp->conn_sqp, mp, tcp_rsrv_input, connp,
	    SQ_PROCESS, SQTAG_TCP_RSRV);
}

/*
 * tcp_rwnd_set() is called to adjust the receive window to a desired value.
 * We do not allow the receive window to shrink.  After setting rwnd,
 * set the flow control hiwat of the stream.
 *
 * This function is called in 2 cases:
 *
 * 1) Before data transfer begins, in tcp_accept_comm() for accepting a
 *    connection (passive open) and in tcp_rput_data() for active connect.
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
static int
tcp_rwnd_set(tcp_t *tcp, uint32_t rwnd)
{
	uint32_t	mss = tcp->tcp_mss;
	uint32_t	old_max_rwnd;
	uint32_t	max_transmittable_rwnd;
	boolean_t	tcp_detached = TCP_IS_DETACHED(tcp);
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	if (tcp->tcp_fused) {
		size_t sth_hiwat;
		tcp_t *peer_tcp = tcp->tcp_loopback_peer;

		ASSERT(peer_tcp != NULL);
		/*
		 * Record the stream head's high water mark for
		 * this endpoint; this is used for flow-control
		 * purposes in tcp_fuse_output().
		 */
		sth_hiwat = tcp_fuse_set_rcv_hiwat(tcp, rwnd);
		if (!tcp_detached) {
			(void) proto_set_rx_hiwat(tcp->tcp_rq, tcp->tcp_connp,
			    sth_hiwat);
			if (IPCL_IS_NONSTR(tcp->tcp_connp)) {
				conn_t *connp = tcp->tcp_connp;
				struct sock_proto_props sopp;

				sopp.sopp_flags = SOCKOPT_RCVTHRESH;
				sopp.sopp_rcvthresh = sth_hiwat >> 3;

				(*connp->conn_upcalls->su_set_proto_props)
				    (connp->conn_upper_handle, &sopp);
			}
		}

		/*
		 * In the fusion case, the maxpsz stream head value of
		 * our peer is set according to its send buffer size
		 * and our receive buffer size; since the latter may
		 * have changed we need to update the peer's maxpsz.
		 */
		(void) tcp_maxpsz_set(peer_tcp, B_TRUE);
		return (rwnd);
	}

	if (tcp_detached) {
		old_max_rwnd = tcp->tcp_rwnd;
	} else {
		old_max_rwnd = tcp->tcp_recv_hiwater;
	}

	/*
	 * Insist on a receive window that is at least
	 * tcp_recv_hiwat_minmss * MSS (default 4 * MSS) to avoid
	 * funny TCP interactions of Nagle algorithm, SWS avoidance
	 * and delayed acknowledgement.
	 */
	rwnd = MAX(rwnd, tcps->tcps_recv_hiwat_minmss * mss);

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
	U32_TO_ABE16(tcp->tcp_rwnd >> tcp->tcp_rcv_ws, tcp->tcp_tcph->th_win);
	if ((tcp->tcp_rcv_ws > 0) && rwnd > tcp->tcp_cwnd_max)
		tcp->tcp_cwnd_max = rwnd;

	if (tcp_detached)
		return (rwnd);
	/*
	 * We set the maximum receive window into rq->q_hiwat if it is
	 * a STREAMS socket.
	 * This is not actually used for flow control.
	 */
	if (!IPCL_IS_NONSTR(tcp->tcp_connp))
		tcp->tcp_rq->q_hiwat = rwnd;
	tcp->tcp_recv_hiwater = rwnd;
	/*
	 * Set the STREAM head high water mark. This doesn't have to be
	 * here, since we are simply using default values, but we would
	 * prefer to choose these values algorithmically, with a likely
	 * relationship to rwnd.
	 */
	(void) proto_set_rx_hiwat(tcp->tcp_rq, tcp->tcp_connp,
	    MAX(rwnd, tcps->tcps_sth_rcv_hiwat));
	return (rwnd);
}

/*
 * Return SNMP stuff in buffer in mpdata.
 */
mblk_t *
tcp_snmp_get(queue_t *q, mblk_t *mpctl)
{
	mblk_t			*mpdata;
	mblk_t			*mp_conn_ctl = NULL;
	mblk_t			*mp_conn_tail;
	mblk_t			*mp_attr_ctl = NULL;
	mblk_t			*mp_attr_tail;
	mblk_t			*mp6_conn_ctl = NULL;
	mblk_t			*mp6_conn_tail;
	mblk_t			*mp6_attr_ctl = NULL;
	mblk_t			*mp6_attr_tail;
	struct opthdr		*optp;
	mib2_tcpConnEntry_t	tce;
	mib2_tcp6ConnEntry_t	tce6;
	mib2_transportMLPEntry_t mlp;
	connf_t			*connfp;
	int			i;
	boolean_t 		ispriv;
	zoneid_t 		zoneid;
	int			v4_conn_idx;
	int			v6_conn_idx;
	conn_t			*connp = Q_TO_CONN(q);
	tcp_stack_t		*tcps;
	ip_stack_t		*ipst;
	mblk_t			*mp2ctl;

	/*
	 * make a copy of the original message
	 */
	mp2ctl = copymsg(mpctl);

	if (mpctl == NULL ||
	    (mpdata = mpctl->b_cont) == NULL ||
	    (mp_conn_ctl = copymsg(mpctl)) == NULL ||
	    (mp_attr_ctl = copymsg(mpctl)) == NULL ||
	    (mp6_conn_ctl = copymsg(mpctl)) == NULL ||
	    (mp6_attr_ctl = copymsg(mpctl)) == NULL) {
		freemsg(mp_conn_ctl);
		freemsg(mp_attr_ctl);
		freemsg(mp6_conn_ctl);
		freemsg(mp6_attr_ctl);
		freemsg(mpctl);
		freemsg(mp2ctl);
		return (NULL);
	}

	ipst = connp->conn_netstack->netstack_ip;
	tcps = connp->conn_netstack->netstack_tcp;

	/* build table of connections -- need count in fixed part */
	SET_MIB(tcps->tcps_mib.tcpRtoAlgorithm, 4);   /* vanj */
	SET_MIB(tcps->tcps_mib.tcpRtoMin, tcps->tcps_rexmit_interval_min);
	SET_MIB(tcps->tcps_mib.tcpRtoMax, tcps->tcps_rexmit_interval_max);
	SET_MIB(tcps->tcps_mib.tcpMaxConn, -1);
	SET_MIB(tcps->tcps_mib.tcpCurrEstab, 0);

	ispriv =
	    secpolicy_ip_config((Q_TO_CONN(q))->conn_cred, B_TRUE) == 0;
	zoneid = Q_TO_CONN(q)->conn_zoneid;

	v4_conn_idx = v6_conn_idx = 0;
	mp_conn_tail = mp_attr_tail = mp6_conn_tail = mp6_attr_tail = NULL;

	for (i = 0; i < CONN_G_HASH_SIZE; i++) {
		ipst = tcps->tcps_netstack->netstack_ip;

		connfp = &ipst->ips_ipcl_globalhash_fanout[i];

		connp = NULL;

		while ((connp =
		    ipcl_get_next_conn(connfp, connp, IPCL_TCP)) != NULL) {
			tcp_t *tcp;
			boolean_t needattr;

			if (connp->conn_zoneid != zoneid)
				continue;	/* not in this zone */

			tcp = connp->conn_tcp;
			UPDATE_MIB(&tcps->tcps_mib,
			    tcpHCInSegs, tcp->tcp_ibsegs);
			tcp->tcp_ibsegs = 0;
			UPDATE_MIB(&tcps->tcps_mib,
			    tcpHCOutSegs, tcp->tcp_obsegs);
			tcp->tcp_obsegs = 0;

			tce6.tcp6ConnState = tce.tcpConnState =
			    tcp_snmp_state(tcp);
			if (tce.tcpConnState == MIB2_TCP_established ||
			    tce.tcpConnState == MIB2_TCP_closeWait)
				BUMP_MIB(&tcps->tcps_mib, tcpCurrEstab);

			needattr = B_FALSE;
			bzero(&mlp, sizeof (mlp));
			if (connp->conn_mlp_type != mlptSingle) {
				if (connp->conn_mlp_type == mlptShared ||
				    connp->conn_mlp_type == mlptBoth)
					mlp.tme_flags |= MIB2_TMEF_SHARED;
				if (connp->conn_mlp_type == mlptPrivate ||
				    connp->conn_mlp_type == mlptBoth)
					mlp.tme_flags |= MIB2_TMEF_PRIVATE;
				needattr = B_TRUE;
			}
			if (connp->conn_peercred != NULL) {
				ts_label_t *tsl;

				tsl = crgetlabel(connp->conn_peercred);
				mlp.tme_doi = label2doi(tsl);
				mlp.tme_label = *label2bslabel(tsl);
				needattr = B_TRUE;
			}

			/* Create a message to report on IPv6 entries */
			if (tcp->tcp_ipversion == IPV6_VERSION) {
			tce6.tcp6ConnLocalAddress = tcp->tcp_ip_src_v6;
			tce6.tcp6ConnRemAddress = tcp->tcp_remote_v6;
			tce6.tcp6ConnLocalPort = ntohs(tcp->tcp_lport);
			tce6.tcp6ConnRemPort = ntohs(tcp->tcp_fport);
			tce6.tcp6ConnIfIndex = tcp->tcp_bound_if;
			/* Don't want just anybody seeing these... */
			if (ispriv) {
				tce6.tcp6ConnEntryInfo.ce_snxt =
				    tcp->tcp_snxt;
				tce6.tcp6ConnEntryInfo.ce_suna =
				    tcp->tcp_suna;
				tce6.tcp6ConnEntryInfo.ce_rnxt =
				    tcp->tcp_rnxt;
				tce6.tcp6ConnEntryInfo.ce_rack =
				    tcp->tcp_rack;
			} else {
				/*
				 * Netstat, unfortunately, uses this to
				 * get send/receive queue sizes.  How to fix?
				 * Why not compute the difference only?
				 */
				tce6.tcp6ConnEntryInfo.ce_snxt =
				    tcp->tcp_snxt - tcp->tcp_suna;
				tce6.tcp6ConnEntryInfo.ce_suna = 0;
				tce6.tcp6ConnEntryInfo.ce_rnxt =
				    tcp->tcp_rnxt - tcp->tcp_rack;
				tce6.tcp6ConnEntryInfo.ce_rack = 0;
			}

			tce6.tcp6ConnEntryInfo.ce_swnd = tcp->tcp_swnd;
			tce6.tcp6ConnEntryInfo.ce_rwnd = tcp->tcp_rwnd;
			tce6.tcp6ConnEntryInfo.ce_rto =  tcp->tcp_rto;
			tce6.tcp6ConnEntryInfo.ce_mss =  tcp->tcp_mss;
			tce6.tcp6ConnEntryInfo.ce_state = tcp->tcp_state;

			tce6.tcp6ConnCreationProcess =
			    (tcp->tcp_cpid < 0) ? MIB2_UNKNOWN_PROCESS :
			    tcp->tcp_cpid;
			tce6.tcp6ConnCreationTime = tcp->tcp_open_time;

			(void) snmp_append_data2(mp6_conn_ctl->b_cont,
			    &mp6_conn_tail, (char *)&tce6, sizeof (tce6));

			mlp.tme_connidx = v6_conn_idx++;
			if (needattr)
				(void) snmp_append_data2(mp6_attr_ctl->b_cont,
				    &mp6_attr_tail, (char *)&mlp, sizeof (mlp));
			}
			/*
			 * Create an IPv4 table entry for IPv4 entries and also
			 * for IPv6 entries which are bound to in6addr_any
			 * but don't have IPV6_V6ONLY set.
			 * (i.e. anything an IPv4 peer could connect to)
			 */
			if (tcp->tcp_ipversion == IPV4_VERSION ||
			    (tcp->tcp_state <= TCPS_LISTEN &&
			    !tcp->tcp_connp->conn_ipv6_v6only &&
			    IN6_IS_ADDR_UNSPECIFIED(&tcp->tcp_ip_src_v6))) {
				if (tcp->tcp_ipversion == IPV6_VERSION) {
					tce.tcpConnRemAddress = INADDR_ANY;
					tce.tcpConnLocalAddress = INADDR_ANY;
				} else {
					tce.tcpConnRemAddress =
					    tcp->tcp_remote;
					tce.tcpConnLocalAddress =
					    tcp->tcp_ip_src;
				}
				tce.tcpConnLocalPort = ntohs(tcp->tcp_lport);
				tce.tcpConnRemPort = ntohs(tcp->tcp_fport);
				/* Don't want just anybody seeing these... */
				if (ispriv) {
					tce.tcpConnEntryInfo.ce_snxt =
					    tcp->tcp_snxt;
					tce.tcpConnEntryInfo.ce_suna =
					    tcp->tcp_suna;
					tce.tcpConnEntryInfo.ce_rnxt =
					    tcp->tcp_rnxt;
					tce.tcpConnEntryInfo.ce_rack =
					    tcp->tcp_rack;
				} else {
					/*
					 * Netstat, unfortunately, uses this to
					 * get send/receive queue sizes.  How
					 * to fix?
					 * Why not compute the difference only?
					 */
					tce.tcpConnEntryInfo.ce_snxt =
					    tcp->tcp_snxt - tcp->tcp_suna;
					tce.tcpConnEntryInfo.ce_suna = 0;
					tce.tcpConnEntryInfo.ce_rnxt =
					    tcp->tcp_rnxt - tcp->tcp_rack;
					tce.tcpConnEntryInfo.ce_rack = 0;
				}

				tce.tcpConnEntryInfo.ce_swnd = tcp->tcp_swnd;
				tce.tcpConnEntryInfo.ce_rwnd = tcp->tcp_rwnd;
				tce.tcpConnEntryInfo.ce_rto =  tcp->tcp_rto;
				tce.tcpConnEntryInfo.ce_mss =  tcp->tcp_mss;
				tce.tcpConnEntryInfo.ce_state =
				    tcp->tcp_state;

				tce.tcpConnCreationProcess =
				    (tcp->tcp_cpid < 0) ? MIB2_UNKNOWN_PROCESS :
				    tcp->tcp_cpid;
				tce.tcpConnCreationTime = tcp->tcp_open_time;

				(void) snmp_append_data2(mp_conn_ctl->b_cont,
				    &mp_conn_tail, (char *)&tce, sizeof (tce));

				mlp.tme_connidx = v4_conn_idx++;
				if (needattr)
					(void) snmp_append_data2(
					    mp_attr_ctl->b_cont,
					    &mp_attr_tail, (char *)&mlp,
					    sizeof (mlp));
			}
		}
	}

	/* fixed length structure for IPv4 and IPv6 counters */
	SET_MIB(tcps->tcps_mib.tcpConnTableSize, sizeof (mib2_tcpConnEntry_t));
	SET_MIB(tcps->tcps_mib.tcp6ConnTableSize,
	    sizeof (mib2_tcp6ConnEntry_t));
	/* synchronize 32- and 64-bit counters */
	SYNC32_MIB(&tcps->tcps_mib, tcpInSegs, tcpHCInSegs);
	SYNC32_MIB(&tcps->tcps_mib, tcpOutSegs, tcpHCOutSegs);
	optp = (struct opthdr *)&mpctl->b_rptr[sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_TCP;
	optp->name = 0;
	(void) snmp_append_data(mpdata, (char *)&tcps->tcps_mib,
	    sizeof (tcps->tcps_mib));
	optp->len = msgdsize(mpdata);
	qreply(q, mpctl);

	/* table of connections... */
	optp = (struct opthdr *)&mp_conn_ctl->b_rptr[
	    sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_TCP;
	optp->name = MIB2_TCP_CONN;
	optp->len = msgdsize(mp_conn_ctl->b_cont);
	qreply(q, mp_conn_ctl);

	/* table of MLP attributes... */
	optp = (struct opthdr *)&mp_attr_ctl->b_rptr[
	    sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_TCP;
	optp->name = EXPER_XPORT_MLP;
	optp->len = msgdsize(mp_attr_ctl->b_cont);
	if (optp->len == 0)
		freemsg(mp_attr_ctl);
	else
		qreply(q, mp_attr_ctl);

	/* table of IPv6 connections... */
	optp = (struct opthdr *)&mp6_conn_ctl->b_rptr[
	    sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_TCP6;
	optp->name = MIB2_TCP6_CONN;
	optp->len = msgdsize(mp6_conn_ctl->b_cont);
	qreply(q, mp6_conn_ctl);

	/* table of IPv6 MLP attributes... */
	optp = (struct opthdr *)&mp6_attr_ctl->b_rptr[
	    sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_TCP6;
	optp->name = EXPER_XPORT_MLP;
	optp->len = msgdsize(mp6_attr_ctl->b_cont);
	if (optp->len == 0)
		freemsg(mp6_attr_ctl);
	else
		qreply(q, mp6_attr_ctl);
	return (mp2ctl);
}

/* Return 0 if invalid set request, 1 otherwise, including non-tcp requests  */
/* ARGSUSED */
int
tcp_snmp_set(queue_t *q, int level, int name, uchar_t *ptr, int len)
{
	mib2_tcpConnEntry_t	*tce = (mib2_tcpConnEntry_t *)ptr;

	switch (level) {
	case MIB2_TCP:
		switch (name) {
		case 13:
			if (tce->tcpConnState != MIB2_TCP_deleteTCB)
				return (0);
			/* TODO: delete entry defined by tce */
			return (1);
		default:
			return (0);
		}
	default:
		return (1);
	}
}

/* Translate TCP state to MIB2 TCP state. */
static int
tcp_snmp_state(tcp_t *tcp)
{
	if (tcp == NULL)
		return (0);

	switch (tcp->tcp_state) {
	case TCPS_CLOSED:
	case TCPS_IDLE:	/* RFC1213 doesn't have analogue for IDLE & BOUND */
	case TCPS_BOUND:
		return (MIB2_TCP_closed);
	case TCPS_LISTEN:
		return (MIB2_TCP_listen);
	case TCPS_SYN_SENT:
		return (MIB2_TCP_synSent);
	case TCPS_SYN_RCVD:
		return (MIB2_TCP_synReceived);
	case TCPS_ESTABLISHED:
		return (MIB2_TCP_established);
	case TCPS_CLOSE_WAIT:
		return (MIB2_TCP_closeWait);
	case TCPS_FIN_WAIT_1:
		return (MIB2_TCP_finWait1);
	case TCPS_CLOSING:
		return (MIB2_TCP_closing);
	case TCPS_LAST_ACK:
		return (MIB2_TCP_lastAck);
	case TCPS_FIN_WAIT_2:
		return (MIB2_TCP_finWait2);
	case TCPS_TIME_WAIT:
		return (MIB2_TCP_timeWait);
	default:
		return (0);
	}
}

static char tcp_report_header[] =
	"TCP     " MI_COL_HDRPAD_STR
	"zone dest	    snxt     suna     "
	"swnd       rnxt     rack     rwnd       rto   mss   w sw rw t "
	"recent   [lport,fport] state";

/*
 * TCP status report triggered via the Named Dispatch mechanism.
 */
/* ARGSUSED */
static void
tcp_report_item(mblk_t *mp, tcp_t *tcp, int hashval, tcp_t *thisstream,
    cred_t *cr)
{
	char hash[10], addrbuf[INET6_ADDRSTRLEN];
	boolean_t ispriv = secpolicy_ip_config(cr, B_TRUE) == 0;
	char cflag;
	in6_addr_t	v6dst;
	char buf[80];
	uint_t print_len, buf_len;

	buf_len = mp->b_datap->db_lim - mp->b_wptr;
	if (buf_len <= 0)
		return;

	if (hashval >= 0)
		(void) sprintf(hash, "%03d ", hashval);
	else
		hash[0] = '\0';

	/*
	 * Note that we use the remote address in the tcp_b  structure.
	 * This means that it will print out the real destination address,
	 * not the next hop's address if source routing is used.  This
	 * avoid the confusion on the output because user may not
	 * know that source routing is used for a connection.
	 */
	if (tcp->tcp_ipversion == IPV4_VERSION) {
		IN6_IPADDR_TO_V4MAPPED(tcp->tcp_remote, &v6dst);
	} else {
		v6dst = tcp->tcp_remote_v6;
	}
	(void) inet_ntop(AF_INET6, &v6dst, addrbuf, sizeof (addrbuf));
	/*
	 * the ispriv checks are so that normal users cannot determine
	 * sequence number information using NDD.
	 */

	if (TCP_IS_DETACHED(tcp))
		cflag = '*';
	else
		cflag = ' ';
	print_len = snprintf((char *)mp->b_wptr, buf_len,
	    "%s " MI_COL_PTRFMT_STR "%d %s %08x %08x %010d %08x %08x "
	    "%010d %05ld %05d %1d %02d %02d %1d %08x %s%c\n",
	    hash,
	    (void *)tcp,
	    tcp->tcp_connp->conn_zoneid,
	    addrbuf,
	    (ispriv) ? tcp->tcp_snxt : 0,
	    (ispriv) ? tcp->tcp_suna : 0,
	    tcp->tcp_swnd,
	    (ispriv) ? tcp->tcp_rnxt : 0,
	    (ispriv) ? tcp->tcp_rack : 0,
	    tcp->tcp_rwnd,
	    tcp->tcp_rto,
	    tcp->tcp_mss,
	    tcp->tcp_snd_ws_ok,
	    tcp->tcp_snd_ws,
	    tcp->tcp_rcv_ws,
	    tcp->tcp_snd_ts_ok,
	    tcp->tcp_ts_recent,
	    tcp_display(tcp, buf, DISP_PORT_ONLY), cflag);
	if (print_len < buf_len) {
		((mblk_t *)mp)->b_wptr += print_len;
	} else {
		((mblk_t *)mp)->b_wptr += buf_len;
	}
}

/*
 * TCP status report (for listeners only) triggered via the Named Dispatch
 * mechanism.
 */
/* ARGSUSED */
static void
tcp_report_listener(mblk_t *mp, tcp_t *tcp, int hashval)
{
	char addrbuf[INET6_ADDRSTRLEN];
	in6_addr_t	v6dst;
	uint_t print_len, buf_len;

	buf_len = mp->b_datap->db_lim - mp->b_wptr;
	if (buf_len <= 0)
		return;

	if (tcp->tcp_ipversion == IPV4_VERSION) {
		IN6_IPADDR_TO_V4MAPPED(tcp->tcp_ipha->ipha_src, &v6dst);
		(void) inet_ntop(AF_INET6, &v6dst, addrbuf, sizeof (addrbuf));
	} else {
		(void) inet_ntop(AF_INET6, &tcp->tcp_ip6h->ip6_src,
		    addrbuf, sizeof (addrbuf));
	}
	print_len = snprintf((char *)mp->b_wptr, buf_len,
	    "%03d "
	    MI_COL_PTRFMT_STR
	    "%d %s %05u %08u %d/%d/%d%c\n",
	    hashval, (void *)tcp,
	    tcp->tcp_connp->conn_zoneid,
	    addrbuf,
	    (uint_t)BE16_TO_U16(tcp->tcp_tcph->th_lport),
	    tcp->tcp_conn_req_seqnum,
	    tcp->tcp_conn_req_cnt_q0, tcp->tcp_conn_req_cnt_q,
	    tcp->tcp_conn_req_max,
	    tcp->tcp_syn_defense ? '*' : ' ');
	if (print_len < buf_len) {
		((mblk_t *)mp)->b_wptr += print_len;
	} else {
		((mblk_t *)mp)->b_wptr += buf_len;
	}
}

/* TCP status report triggered via the Named Dispatch mechanism. */
/* ARGSUSED */
static int
tcp_status_report(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *cr)
{
	tcp_t	*tcp;
	int	i;
	conn_t	*connp;
	connf_t	*connfp;
	zoneid_t zoneid;
	tcp_stack_t *tcps;
	ip_stack_t *ipst;

	zoneid = Q_TO_CONN(q)->conn_zoneid;
	tcps = Q_TO_TCP(q)->tcp_tcps;

	/*
	 * Because of the ndd constraint, at most we can have 64K buffer
	 * to put in all TCP info.  So to be more efficient, just
	 * allocate a 64K buffer here, assuming we need that large buffer.
	 * This may be a problem as any user can read tcp_status.  Therefore
	 * we limit the rate of doing this using tcp_ndd_get_info_interval.
	 * This should be OK as normal users should not do this too often.
	 */
	if (cr == NULL || secpolicy_ip_config(cr, B_TRUE) != 0) {
		if (ddi_get_lbolt() - tcps->tcps_last_ndd_get_info_time <
		    drv_usectohz(tcps->tcps_ndd_get_info_interval * 1000)) {
			(void) mi_mpprintf(mp, NDD_TOO_QUICK_MSG);
			return (0);
		}
	}
	if ((mp->b_cont = allocb(ND_MAX_BUF_LEN, BPRI_HI)) == NULL) {
		/* The following may work even if we cannot get a large buf. */
		(void) mi_mpprintf(mp, NDD_OUT_OF_BUF_MSG);
		return (0);
	}

	(void) mi_mpprintf(mp, "%s", tcp_report_header);

	for (i = 0; i < CONN_G_HASH_SIZE; i++) {

		ipst = tcps->tcps_netstack->netstack_ip;
		connfp = &ipst->ips_ipcl_globalhash_fanout[i];

		connp = NULL;

		while ((connp =
		    ipcl_get_next_conn(connfp, connp, IPCL_TCP)) != NULL) {
			tcp = connp->conn_tcp;
			if (zoneid != GLOBAL_ZONEID &&
			    zoneid != connp->conn_zoneid)
				continue;
			tcp_report_item(mp->b_cont, tcp, -1, tcp,
			    cr);
		}

	}

	tcps->tcps_last_ndd_get_info_time = ddi_get_lbolt();
	return (0);
}

/* TCP status report triggered via the Named Dispatch mechanism. */
/* ARGSUSED */
static int
tcp_bind_hash_report(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *cr)
{
	tf_t	*tbf;
	tcp_t	*tcp, *ltcp;
	int	i;
	zoneid_t zoneid;
	tcp_stack_t	*tcps = Q_TO_TCP(q)->tcp_tcps;

	zoneid = Q_TO_CONN(q)->conn_zoneid;

	/* Refer to comments in tcp_status_report(). */
	if (cr == NULL || secpolicy_ip_config(cr, B_TRUE) != 0) {
		if (ddi_get_lbolt() - tcps->tcps_last_ndd_get_info_time <
		    drv_usectohz(tcps->tcps_ndd_get_info_interval * 1000)) {
			(void) mi_mpprintf(mp, NDD_TOO_QUICK_MSG);
			return (0);
		}
	}
	if ((mp->b_cont = allocb(ND_MAX_BUF_LEN, BPRI_HI)) == NULL) {
		/* The following may work even if we cannot get a large buf. */
		(void) mi_mpprintf(mp, NDD_OUT_OF_BUF_MSG);
		return (0);
	}

	(void) mi_mpprintf(mp, "    %s", tcp_report_header);

	for (i = 0; i < TCP_BIND_FANOUT_SIZE; i++) {
		tbf = &tcps->tcps_bind_fanout[i];
		mutex_enter(&tbf->tf_lock);
		for (ltcp = tbf->tf_tcp; ltcp != NULL;
		    ltcp = ltcp->tcp_bind_hash) {
			for (tcp = ltcp; tcp != NULL;
			    tcp = tcp->tcp_bind_hash_port) {
				if (zoneid != GLOBAL_ZONEID &&
				    zoneid != tcp->tcp_connp->conn_zoneid)
					continue;
				CONN_INC_REF(tcp->tcp_connp);
				tcp_report_item(mp->b_cont, tcp, i,
				    Q_TO_TCP(q), cr);
				CONN_DEC_REF(tcp->tcp_connp);
			}
		}
		mutex_exit(&tbf->tf_lock);
	}
	tcps->tcps_last_ndd_get_info_time = ddi_get_lbolt();
	return (0);
}

/* TCP status report triggered via the Named Dispatch mechanism. */
/* ARGSUSED */
static int
tcp_listen_hash_report(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *cr)
{
	connf_t	*connfp;
	conn_t	*connp;
	tcp_t	*tcp;
	int	i;
	zoneid_t zoneid;
	tcp_stack_t *tcps;
	ip_stack_t	*ipst;

	zoneid = Q_TO_CONN(q)->conn_zoneid;
	tcps = Q_TO_TCP(q)->tcp_tcps;

	/* Refer to comments in tcp_status_report(). */
	if (cr == NULL || secpolicy_ip_config(cr, B_TRUE) != 0) {
		if (ddi_get_lbolt() - tcps->tcps_last_ndd_get_info_time <
		    drv_usectohz(tcps->tcps_ndd_get_info_interval * 1000)) {
			(void) mi_mpprintf(mp, NDD_TOO_QUICK_MSG);
			return (0);
		}
	}
	if ((mp->b_cont = allocb(ND_MAX_BUF_LEN, BPRI_HI)) == NULL) {
		/* The following may work even if we cannot get a large buf. */
		(void) mi_mpprintf(mp, NDD_OUT_OF_BUF_MSG);
		return (0);
	}

	(void) mi_mpprintf(mp,
	    "    TCP    " MI_COL_HDRPAD_STR
	    "zone IP addr	 port  seqnum   backlog (q0/q/max)");

	ipst = tcps->tcps_netstack->netstack_ip;

	for (i = 0; i < ipst->ips_ipcl_bind_fanout_size; i++) {
		connfp = &ipst->ips_ipcl_bind_fanout[i];
		connp = NULL;
		while ((connp =
		    ipcl_get_next_conn(connfp, connp, IPCL_TCP)) != NULL) {
			tcp = connp->conn_tcp;
			if (zoneid != GLOBAL_ZONEID &&
			    zoneid != connp->conn_zoneid)
				continue;
			tcp_report_listener(mp->b_cont, tcp, i);
		}
	}

	tcps->tcps_last_ndd_get_info_time = ddi_get_lbolt();
	return (0);
}

/* TCP status report triggered via the Named Dispatch mechanism. */
/* ARGSUSED */
static int
tcp_conn_hash_report(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *cr)
{
	connf_t	*connfp;
	conn_t	*connp;
	tcp_t	*tcp;
	int	i;
	zoneid_t zoneid;
	tcp_stack_t *tcps;
	ip_stack_t *ipst;

	zoneid = Q_TO_CONN(q)->conn_zoneid;
	tcps = Q_TO_TCP(q)->tcp_tcps;
	ipst = tcps->tcps_netstack->netstack_ip;

	/* Refer to comments in tcp_status_report(). */
	if (cr == NULL || secpolicy_ip_config(cr, B_TRUE) != 0) {
		if (ddi_get_lbolt() - tcps->tcps_last_ndd_get_info_time <
		    drv_usectohz(tcps->tcps_ndd_get_info_interval * 1000)) {
			(void) mi_mpprintf(mp, NDD_TOO_QUICK_MSG);
			return (0);
		}
	}
	if ((mp->b_cont = allocb(ND_MAX_BUF_LEN, BPRI_HI)) == NULL) {
		/* The following may work even if we cannot get a large buf. */
		(void) mi_mpprintf(mp, NDD_OUT_OF_BUF_MSG);
		return (0);
	}

	(void) mi_mpprintf(mp, "tcp_conn_hash_size = %d",
	    ipst->ips_ipcl_conn_fanout_size);
	(void) mi_mpprintf(mp, "    %s", tcp_report_header);

	for (i = 0; i < ipst->ips_ipcl_conn_fanout_size; i++) {
		connfp =  &ipst->ips_ipcl_conn_fanout[i];
		connp = NULL;
		while ((connp =
		    ipcl_get_next_conn(connfp, connp, IPCL_TCP)) != NULL) {
			tcp = connp->conn_tcp;
			if (zoneid != GLOBAL_ZONEID &&
			    zoneid != connp->conn_zoneid)
				continue;
			tcp_report_item(mp->b_cont, tcp, i,
			    Q_TO_TCP(q), cr);
		}
	}

	tcps->tcps_last_ndd_get_info_time = ddi_get_lbolt();
	return (0);
}

/* TCP status report triggered via the Named Dispatch mechanism. */
/* ARGSUSED */
static int
tcp_acceptor_hash_report(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *cr)
{
	tf_t	*tf;
	tcp_t	*tcp;
	int	i;
	zoneid_t zoneid;
	tcp_stack_t	*tcps;

	zoneid = Q_TO_CONN(q)->conn_zoneid;
	tcps = Q_TO_TCP(q)->tcp_tcps;

	/* Refer to comments in tcp_status_report(). */
	if (cr == NULL || secpolicy_ip_config(cr, B_TRUE) != 0) {
		if (ddi_get_lbolt() - tcps->tcps_last_ndd_get_info_time <
		    drv_usectohz(tcps->tcps_ndd_get_info_interval * 1000)) {
			(void) mi_mpprintf(mp, NDD_TOO_QUICK_MSG);
			return (0);
		}
	}
	if ((mp->b_cont = allocb(ND_MAX_BUF_LEN, BPRI_HI)) == NULL) {
		/* The following may work even if we cannot get a large buf. */
		(void) mi_mpprintf(mp, NDD_OUT_OF_BUF_MSG);
		return (0);
	}

	(void) mi_mpprintf(mp, "    %s", tcp_report_header);

	for (i = 0; i < TCP_FANOUT_SIZE; i++) {
		tf = &tcps->tcps_acceptor_fanout[i];
		mutex_enter(&tf->tf_lock);
		for (tcp = tf->tf_tcp; tcp != NULL;
		    tcp = tcp->tcp_acceptor_hash) {
			if (zoneid != GLOBAL_ZONEID &&
			    zoneid != tcp->tcp_connp->conn_zoneid)
				continue;
			tcp_report_item(mp->b_cont, tcp, i,
			    Q_TO_TCP(q), cr);
		}
		mutex_exit(&tf->tf_lock);
	}
	tcps->tcps_last_ndd_get_info_time = ddi_get_lbolt();
	return (0);
}

/*
 * tcp_timer is the timer service routine.  It handles the retransmission,
 * FIN_WAIT_2 flush, and zero window probe timeout events.  It figures out
 * from the state of the tcp instance what kind of action needs to be done
 * at the time it is called.
 */
static void
tcp_timer(void *arg)
{
	mblk_t		*mp;
	clock_t		first_threshold;
	clock_t		second_threshold;
	clock_t		ms;
	uint32_t	mss;
	conn_t		*connp = (conn_t *)arg;
	tcp_t		*tcp = connp->conn_tcp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	tcp->tcp_timer_tid = 0;

	if (tcp->tcp_fused)
		return;

	first_threshold =  tcp->tcp_first_timer_threshold;
	second_threshold = tcp->tcp_second_timer_threshold;
	switch (tcp->tcp_state) {
	case TCPS_IDLE:
	case TCPS_BOUND:
	case TCPS_LISTEN:
		return;
	case TCPS_SYN_RCVD: {
		tcp_t	*listener = tcp->tcp_listener;

		if (tcp->tcp_syn_rcvd_timeout == 0 && (listener != NULL)) {
			ASSERT(tcp->tcp_rq == listener->tcp_rq);
			/* it's our first timeout */
			tcp->tcp_syn_rcvd_timeout = 1;
			mutex_enter(&listener->tcp_eager_lock);
			listener->tcp_syn_rcvd_timeout++;
			if (!tcp->tcp_dontdrop && !tcp->tcp_closemp_used) {
				/*
				 * Make this eager available for drop if we
				 * need to drop one to accomodate a new
				 * incoming SYN request.
				 */
				MAKE_DROPPABLE(listener, tcp);
			}
			if (!listener->tcp_syn_defense &&
			    (listener->tcp_syn_rcvd_timeout >
			    (tcps->tcps_conn_req_max_q0 >> 2)) &&
			    (tcps->tcps_conn_req_max_q0 > 200)) {
				/* We may be under attack. Put on a defense. */
				listener->tcp_syn_defense = B_TRUE;
				cmn_err(CE_WARN, "High TCP connect timeout "
				    "rate! System (port %d) may be under a "
				    "SYN flood attack!",
				    BE16_TO_U16(listener->tcp_tcph->th_lport));

				listener->tcp_ip_addr_cache = kmem_zalloc(
				    IP_ADDR_CACHE_SIZE * sizeof (ipaddr_t),
				    KM_NOSLEEP);
			}
			mutex_exit(&listener->tcp_eager_lock);
		} else if (listener != NULL) {
			mutex_enter(&listener->tcp_eager_lock);
			tcp->tcp_syn_rcvd_timeout++;
			if (tcp->tcp_syn_rcvd_timeout > 1 &&
			    !tcp->tcp_closemp_used) {
				/*
				 * This is our second timeout. Put the tcp in
				 * the list of droppable eagers to allow it to
				 * be dropped, if needed. We don't check
				 * whether tcp_dontdrop is set or not to
				 * protect ourselve from a SYN attack where a
				 * remote host can spoof itself as one of the
				 * good IP source and continue to hold
				 * resources too long.
				 */
				MAKE_DROPPABLE(listener, tcp);
			}
			mutex_exit(&listener->tcp_eager_lock);
		}
	}
		/* FALLTHRU */
	case TCPS_SYN_SENT:
		first_threshold =  tcp->tcp_first_ctimer_threshold;
		second_threshold = tcp->tcp_second_ctimer_threshold;
		break;
	case TCPS_ESTABLISHED:
	case TCPS_FIN_WAIT_1:
	case TCPS_CLOSING:
	case TCPS_CLOSE_WAIT:
	case TCPS_LAST_ACK:
		/* If we have data to rexmit */
		if (tcp->tcp_suna != tcp->tcp_snxt) {
			clock_t	time_to_wait;

			BUMP_MIB(&tcps->tcps_mib, tcpTimRetrans);
			if (!tcp->tcp_xmit_head)
				break;
			time_to_wait = lbolt -
			    (clock_t)tcp->tcp_xmit_head->b_prev;
			time_to_wait = tcp->tcp_rto -
			    TICK_TO_MSEC(time_to_wait);
			/*
			 * If the timer fires too early, 1 clock tick earlier,
			 * restart the timer.
			 */
			if (time_to_wait > msec_per_tick) {
				TCP_STAT(tcps, tcp_timer_fire_early);
				TCP_TIMER_RESTART(tcp, time_to_wait);
				return;
			}
			/*
			 * When we probe zero windows, we force the swnd open.
			 * If our peer acks with a closed window swnd will be
			 * set to zero by tcp_rput(). As long as we are
			 * receiving acks tcp_rput will
			 * reset 'tcp_ms_we_have_waited' so as not to trip the
			 * first and second interval actions.  NOTE: the timer
			 * interval is allowed to continue its exponential
			 * backoff.
			 */
			if (tcp->tcp_swnd == 0 || tcp->tcp_zero_win_probe) {
				if (tcp->tcp_debug) {
					(void) strlog(TCP_MOD_ID, 0, 1,
					    SL_TRACE, "tcp_timer: zero win");
				}
			} else {
				/*
				 * After retransmission, we need to do
				 * slow start.  Set the ssthresh to one
				 * half of current effective window and
				 * cwnd to one MSS.  Also reset
				 * tcp_cwnd_cnt.
				 *
				 * Note that if tcp_ssthresh is reduced because
				 * of ECN, do not reduce it again unless it is
				 * already one window of data away (tcp_cwr
				 * should then be cleared) or this is a
				 * timeout for a retransmitted segment.
				 */
				uint32_t npkt;

				if (!tcp->tcp_cwr || tcp->tcp_rexmit) {
					npkt = ((tcp->tcp_timer_backoff ?
					    tcp->tcp_cwnd_ssthresh :
					    tcp->tcp_snxt -
					    tcp->tcp_suna) >> 1) / tcp->tcp_mss;
					tcp->tcp_cwnd_ssthresh = MAX(npkt, 2) *
					    tcp->tcp_mss;
				}
				tcp->tcp_cwnd = tcp->tcp_mss;
				tcp->tcp_cwnd_cnt = 0;
				if (tcp->tcp_ecn_ok) {
					tcp->tcp_cwr = B_TRUE;
					tcp->tcp_cwr_snd_max = tcp->tcp_snxt;
					tcp->tcp_ecn_cwr_sent = B_FALSE;
				}
			}
			break;
		}
		/*
		 * We have something to send yet we cannot send.  The
		 * reason can be:
		 *
		 * 1. Zero send window: we need to do zero window probe.
		 * 2. Zero cwnd: because of ECN, we need to "clock out
		 * segments.
		 * 3. SWS avoidance: receiver may have shrunk window,
		 * reset our knowledge.
		 *
		 * Note that condition 2 can happen with either 1 or
		 * 3.  But 1 and 3 are exclusive.
		 */
		if (tcp->tcp_unsent != 0) {
			if (tcp->tcp_cwnd == 0) {
				/*
				 * Set tcp_cwnd to 1 MSS so that a
				 * new segment can be sent out.  We
				 * are "clocking out" new data when
				 * the network is really congested.
				 */
				ASSERT(tcp->tcp_ecn_ok);
				tcp->tcp_cwnd = tcp->tcp_mss;
			}
			if (tcp->tcp_swnd == 0) {
				/* Extend window for zero window probe */
				tcp->tcp_swnd++;
				tcp->tcp_zero_win_probe = B_TRUE;
				BUMP_MIB(&tcps->tcps_mib, tcpOutWinProbe);
			} else {
				/*
				 * Handle timeout from sender SWS avoidance.
				 * Reset our knowledge of the max send window
				 * since the receiver might have reduced its
				 * receive buffer.  Avoid setting tcp_max_swnd
				 * to one since that will essentially disable
				 * the SWS checks.
				 *
				 * Note that since we don't have a SWS
				 * state variable, if the timeout is set
				 * for ECN but not for SWS, this
				 * code will also be executed.  This is
				 * fine as tcp_max_swnd is updated
				 * constantly and it will not affect
				 * anything.
				 */
				tcp->tcp_max_swnd = MAX(tcp->tcp_swnd, 2);
			}
			tcp_wput_data(tcp, NULL, B_FALSE);
			return;
		}
		/* Is there a FIN that needs to be to re retransmitted? */
		if ((tcp->tcp_valid_bits & TCP_FSS_VALID) &&
		    !tcp->tcp_fin_acked)
			break;
		/* Nothing to do, return without restarting timer. */
		TCP_STAT(tcps, tcp_timer_fire_miss);
		return;
	case TCPS_FIN_WAIT_2:
		/*
		 * User closed the TCP endpoint and peer ACK'ed our FIN.
		 * We waited some time for for peer's FIN, but it hasn't
		 * arrived.  We flush the connection now to avoid
		 * case where the peer has rebooted.
		 */
		if (TCP_IS_DETACHED(tcp)) {
			(void) tcp_clean_death(tcp, 0, 23);
		} else {
			TCP_TIMER_RESTART(tcp,
			    tcps->tcps_fin_wait_2_flush_interval);
		}
		return;
	case TCPS_TIME_WAIT:
		(void) tcp_clean_death(tcp, 0, 24);
		return;
	default:
		if (tcp->tcp_debug) {
			(void) strlog(TCP_MOD_ID, 0, 1, SL_TRACE|SL_ERROR,
			    "tcp_timer: strange state (%d) %s",
			    tcp->tcp_state, tcp_display(tcp, NULL,
			    DISP_PORT_ONLY));
		}
		return;
	}
	if ((ms = tcp->tcp_ms_we_have_waited) > second_threshold) {
		/*
		 * For zero window probe, we need to send indefinitely,
		 * unless we have not heard from the other side for some
		 * time...
		 */
		if ((tcp->tcp_zero_win_probe == 0) ||
		    (TICK_TO_MSEC(lbolt - tcp->tcp_last_recv_time) >
		    second_threshold)) {
			BUMP_MIB(&tcps->tcps_mib, tcpTimRetransDrop);
			/*
			 * If TCP is in SYN_RCVD state, send back a
			 * RST|ACK as BSD does.  Note that tcp_zero_win_probe
			 * should be zero in TCPS_SYN_RCVD state.
			 */
			if (tcp->tcp_state == TCPS_SYN_RCVD) {
				tcp_xmit_ctl("tcp_timer: RST sent on timeout "
				    "in SYN_RCVD",
				    tcp, tcp->tcp_snxt,
				    tcp->tcp_rnxt, TH_RST | TH_ACK);
			}
			(void) tcp_clean_death(tcp,
			    tcp->tcp_client_errno ?
			    tcp->tcp_client_errno : ETIMEDOUT, 25);
			return;
		} else {
			/*
			 * Set tcp_ms_we_have_waited to second_threshold
			 * so that in next timeout, we will do the above
			 * check (lbolt - tcp_last_recv_time).  This is
			 * also to avoid overflow.
			 *
			 * We don't need to decrement tcp_timer_backoff
			 * to avoid overflow because it will be decremented
			 * later if new timeout value is greater than
			 * tcp_rexmit_interval_max.  In the case when
			 * tcp_rexmit_interval_max is greater than
			 * second_threshold, it means that we will wait
			 * longer than second_threshold to send the next
			 * window probe.
			 */
			tcp->tcp_ms_we_have_waited = second_threshold;
		}
	} else if (ms > first_threshold) {
		if (tcp->tcp_snd_zcopy_aware && (!tcp->tcp_xmit_zc_clean) &&
		    tcp->tcp_xmit_head != NULL) {
			tcp->tcp_xmit_head =
			    tcp_zcopy_backoff(tcp, tcp->tcp_xmit_head, 1);
		}
		/*
		 * We have been retransmitting for too long...  The RTT
		 * we calculated is probably incorrect.  Reinitialize it.
		 * Need to compensate for 0 tcp_rtt_sa.  Reset
		 * tcp_rtt_update so that we won't accidentally cache a
		 * bad value.  But only do this if this is not a zero
		 * window probe.
		 */
		if (tcp->tcp_rtt_sa != 0 && tcp->tcp_zero_win_probe == 0) {
			tcp->tcp_rtt_sd += (tcp->tcp_rtt_sa >> 3) +
			    (tcp->tcp_rtt_sa >> 5);
			tcp->tcp_rtt_sa = 0;
			tcp_ip_notify(tcp);
			tcp->tcp_rtt_update = 0;
		}
	}
	tcp->tcp_timer_backoff++;
	if ((ms = (tcp->tcp_rtt_sa >> 3) + tcp->tcp_rtt_sd +
	    tcps->tcps_rexmit_interval_extra + (tcp->tcp_rtt_sa >> 5)) <
	    tcps->tcps_rexmit_interval_min) {
		/*
		 * This means the original RTO is tcp_rexmit_interval_min.
		 * So we will use tcp_rexmit_interval_min as the RTO value
		 * and do the backoff.
		 */
		ms = tcps->tcps_rexmit_interval_min << tcp->tcp_timer_backoff;
	} else {
		ms <<= tcp->tcp_timer_backoff;
	}
	if (ms > tcps->tcps_rexmit_interval_max) {
		ms = tcps->tcps_rexmit_interval_max;
		/*
		 * ms is at max, decrement tcp_timer_backoff to avoid
		 * overflow.
		 */
		tcp->tcp_timer_backoff--;
	}
	tcp->tcp_ms_we_have_waited += ms;
	if (tcp->tcp_zero_win_probe == 0) {
		tcp->tcp_rto = ms;
	}
	TCP_TIMER_RESTART(tcp, ms);
	/*
	 * This is after a timeout and tcp_rto is backed off.  Set
	 * tcp_set_timer to 1 so that next time RTO is updated, we will
	 * restart the timer with a correct value.
	 */
	tcp->tcp_set_timer = 1;
	mss = tcp->tcp_snxt - tcp->tcp_suna;
	if (mss > tcp->tcp_mss)
		mss = tcp->tcp_mss;
	if (mss > tcp->tcp_swnd && tcp->tcp_swnd != 0)
		mss = tcp->tcp_swnd;

	if ((mp = tcp->tcp_xmit_head) != NULL)
		mp->b_prev = (mblk_t *)lbolt;
	mp = tcp_xmit_mp(tcp, mp, mss, NULL, NULL, tcp->tcp_suna, B_TRUE, &mss,
	    B_TRUE);

	/*
	 * When slow start after retransmission begins, start with
	 * this seq no.  tcp_rexmit_max marks the end of special slow
	 * start phase.  tcp_snd_burst controls how many segments
	 * can be sent because of an ack.
	 */
	tcp->tcp_rexmit_nxt = tcp->tcp_suna;
	tcp->tcp_snd_burst = TCP_CWND_SS;
	if ((tcp->tcp_valid_bits & TCP_FSS_VALID) &&
	    (tcp->tcp_unsent == 0)) {
		tcp->tcp_rexmit_max = tcp->tcp_fss;
	} else {
		tcp->tcp_rexmit_max = tcp->tcp_snxt;
	}
	tcp->tcp_rexmit = B_TRUE;
	tcp->tcp_dupack_cnt = 0;

	/*
	 * Remove all rexmit SACK blk to start from fresh.
	 */
	if (tcp->tcp_snd_sack_ok && tcp->tcp_notsack_list != NULL) {
		TCP_NOTSACK_REMOVE_ALL(tcp->tcp_notsack_list);
		tcp->tcp_num_notsack_blk = 0;
		tcp->tcp_cnt_notsack_list = 0;
	}
	if (mp == NULL) {
		return;
	}
	/* Attach credentials to retransmitted initial SYNs. */
	if (tcp->tcp_state == TCPS_SYN_SENT) {
		mblk_setcred(mp, tcp->tcp_cred);
		DB_CPID(mp) = tcp->tcp_cpid;
	}

	tcp->tcp_csuna = tcp->tcp_snxt;
	BUMP_MIB(&tcps->tcps_mib, tcpRetransSegs);
	UPDATE_MIB(&tcps->tcps_mib, tcpRetransBytes, mss);
	tcp_send_data(tcp, tcp->tcp_wq, mp);

}

static int
tcp_do_unbind(conn_t *connp)
{
	tcp_t *tcp = connp->conn_tcp;
	int error = 0;

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

	if (tcp->tcp_ipversion == IPV4_VERSION) {
		tcp->tcp_ipha->ipha_src = 0;
	} else {
		V6_SET_ZERO(tcp->tcp_ip6h->ip6_src);
	}
	V6_SET_ZERO(tcp->tcp_ip_src_v6);
	bzero(tcp->tcp_tcph->th_lport, sizeof (tcp->tcp_tcph->th_lport));
	tcp_bind_hash_remove(tcp);
	tcp->tcp_state = TCPS_IDLE;
	tcp->tcp_mdt = B_FALSE;

	connp = tcp->tcp_connp;
	connp->conn_mdt_ok = B_FALSE;
	ipcl_hash_remove(connp);
	bzero(&connp->conn_ports, sizeof (connp->conn_ports));

	return (error);
}

/* tcp_unbind is called by tcp_wput_proto to handle T_UNBIND_REQ messages. */
static void
tcp_tpi_unbind(tcp_t *tcp, mblk_t *mp)
{
	int error = tcp_do_unbind(tcp->tcp_connp);

	if (error > 0) {
		tcp_err_ack(tcp, mp, TSYSERR, error);
	} else if (error < 0) {
		tcp_err_ack(tcp, mp, -error, 0);
	} else {
		/* Send M_FLUSH according to TPI */
		(void) putnextctl1(tcp->tcp_rq, M_FLUSH, FLUSHRW);

		mp = mi_tpi_ok_ack_alloc(mp);
		putnext(tcp->tcp_rq, mp);
	}
}

/*
 * Don't let port fall into the privileged range.
 * Since the extra privileged ports can be arbitrary we also
 * ensure that we exclude those from consideration.
 * tcp_g_epriv_ports is not sorted thus we loop over it until
 * there are no changes.
 *
 * Note: No locks are held when inspecting tcp_g_*epriv_ports
 * but instead the code relies on:
 * - the fact that the address of the array and its size never changes
 * - the atomic assignment of the elements of the array
 *
 * Returns 0 if there are no more ports available.
 *
 * TS note: skip multilevel ports.
 */
static in_port_t
tcp_update_next_port(in_port_t port, const tcp_t *tcp, boolean_t random)
{
	int i;
	boolean_t restart = B_FALSE;
	tcp_stack_t *tcps = tcp->tcp_tcps;

	if (random && tcp_random_anon_port != 0) {
		(void) random_get_pseudo_bytes((uint8_t *)&port,
		    sizeof (in_port_t));
		/*
		 * Unless changed by a sys admin, the smallest anon port
		 * is 32768 and the largest anon port is 65535.  It is
		 * very likely (50%) for the random port to be smaller
		 * than the smallest anon port.  When that happens,
		 * add port % (anon port range) to the smallest anon
		 * port to get the random port.  It should fall into the
		 * valid anon port range.
		 */
		if (port < tcps->tcps_smallest_anon_port) {
			port = tcps->tcps_smallest_anon_port +
			    port % (tcps->tcps_largest_anon_port -
			    tcps->tcps_smallest_anon_port);
		}
	}

retry:
	if (port < tcps->tcps_smallest_anon_port)
		port = (in_port_t)tcps->tcps_smallest_anon_port;

	if (port > tcps->tcps_largest_anon_port) {
		if (restart)
			return (0);
		restart = B_TRUE;
		port = (in_port_t)tcps->tcps_smallest_anon_port;
	}

	if (port < tcps->tcps_smallest_nonpriv_port)
		port = (in_port_t)tcps->tcps_smallest_nonpriv_port;

	for (i = 0; i < tcps->tcps_g_num_epriv_ports; i++) {
		if (port == tcps->tcps_g_epriv_ports[i]) {
			port++;
			/*
			 * Make sure whether the port is in the
			 * valid range.
			 */
			goto retry;
		}
	}
	if (is_system_labeled() &&
	    (i = tsol_next_port(crgetzone(tcp->tcp_cred), port,
	    IPPROTO_TCP, B_TRUE)) != 0) {
		port = i;
		goto retry;
	}
	return (port);
}

/*
 * Return the next anonymous port in the privileged port range for
 * bind checking.  It starts at IPPORT_RESERVED - 1 and goes
 * downwards.  This is the same behavior as documented in the userland
 * library call rresvport(3N).
 *
 * TS note: skip multilevel ports.
 */
static in_port_t
tcp_get_next_priv_port(const tcp_t *tcp)
{
	static in_port_t next_priv_port = IPPORT_RESERVED - 1;
	in_port_t nextport;
	boolean_t restart = B_FALSE;
	tcp_stack_t *tcps = tcp->tcp_tcps;
retry:
	if (next_priv_port < tcps->tcps_min_anonpriv_port ||
	    next_priv_port >= IPPORT_RESERVED) {
		next_priv_port = IPPORT_RESERVED - 1;
		if (restart)
			return (0);
		restart = B_TRUE;
	}
	if (is_system_labeled() &&
	    (nextport = tsol_next_port(crgetzone(tcp->tcp_cred),
	    next_priv_port, IPPROTO_TCP, B_FALSE)) != 0) {
		next_priv_port = nextport;
		goto retry;
	}
	return (next_priv_port--);
}

/* The write side r/w procedure. */

#if CCS_STATS
struct {
	struct {
		int64_t count, bytes;
	} tot, hit;
} wrw_stats;
#endif

/*
 * Call by tcp_wput() to handle all non data, except M_PROTO and M_PCPROTO,
 * messages.
 */
/* ARGSUSED */
static void
tcp_wput_nondata(void *arg, mblk_t *mp, void *arg2)
{
	conn_t	*connp = (conn_t *)arg;
	tcp_t	*tcp = connp->conn_tcp;
	queue_t	*q = tcp->tcp_wq;

	ASSERT(DB_TYPE(mp) != M_IOCTL);
	/*
	 * TCP is D_MP and qprocsoff() is done towards the end of the tcp_close.
	 * Once the close starts, streamhead and sockfs will not let any data
	 * packets come down (close ensures that there are no threads using the
	 * queue and no new threads will come down) but since qprocsoff()
	 * hasn't happened yet, a M_FLUSH or some non data message might
	 * get reflected back (in response to our own FLUSHRW) and get
	 * processed after tcp_close() is done. The conn would still be valid
	 * because a ref would have added but we need to check the state
	 * before actually processing the packet.
	 */
	if (TCP_IS_DETACHED(tcp) || (tcp->tcp_state == TCPS_CLOSED)) {
		freemsg(mp);
		return;
	}

	switch (DB_TYPE(mp)) {
	case M_IOCDATA:
		tcp_wput_iocdata(tcp, mp);
		break;
	case M_FLUSH:
		tcp_wput_flush(tcp, mp);
		break;
	default:
		CALL_IP_WPUT(connp, q, mp);
		break;
	}
}

/*
 * The TCP fast path write put procedure.
 * NOTE: the logic of the fast path is duplicated from tcp_wput_data()
 */
/* ARGSUSED */
void
tcp_output(void *arg, mblk_t *mp, void *arg2)
{
	int		len;
	int		hdrlen;
	int		plen;
	mblk_t		*mp1;
	uchar_t		*rptr;
	uint32_t	snxt;
	tcph_t		*tcph;
	struct datab	*db;
	uint32_t	suna;
	uint32_t	mss;
	ipaddr_t	*dst;
	ipaddr_t	*src;
	uint32_t	sum;
	int		usable;
	conn_t		*connp = (conn_t *)arg;
	tcp_t		*tcp = connp->conn_tcp;
	uint32_t	msize;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	ip_stack_t	*ipst = tcps->tcps_netstack->netstack_ip;

	/*
	 * Try and ASSERT the minimum possible references on the
	 * conn early enough. Since we are executing on write side,
	 * the connection is obviously not detached and that means
	 * there is a ref each for TCP and IP. Since we are behind
	 * the squeue, the minimum references needed are 3. If the
	 * conn is in classifier hash list, there should be an
	 * extra ref for that (we check both the possibilities).
	 */
	ASSERT((connp->conn_fanout != NULL && connp->conn_ref >= 4) ||
	    (connp->conn_fanout == NULL && connp->conn_ref >= 3));

	ASSERT(DB_TYPE(mp) == M_DATA);
	msize = (mp->b_cont == NULL) ? MBLKL(mp) : msgdsize(mp);

	mutex_enter(&tcp->tcp_non_sq_lock);
	tcp->tcp_squeue_bytes -= msize;
	mutex_exit(&tcp->tcp_non_sq_lock);

	/* Check to see if this connection wants to be re-fused. */
	if (tcp->tcp_refuse && !ipst->ips_ipobs_enabled) {
		if (tcp->tcp_ipversion == IPV4_VERSION) {
			tcp_fuse(tcp, (uchar_t *)&tcp->tcp_saved_ipha,
			    &tcp->tcp_saved_tcph);
		} else {
			tcp_fuse(tcp, (uchar_t *)&tcp->tcp_saved_ip6h,
			    &tcp->tcp_saved_tcph);
		}
	}
	/* Bypass tcp protocol for fused tcp loopback */
	if (tcp->tcp_fused && tcp_fuse_output(tcp, mp, msize))
		return;

	mss = tcp->tcp_mss;
	if (tcp->tcp_xmit_zc_clean)
		mp = tcp_zcopy_backoff(tcp, mp, 0);

	ASSERT((uintptr_t)(mp->b_wptr - mp->b_rptr) <= (uintptr_t)INT_MAX);
	len = (int)(mp->b_wptr - mp->b_rptr);

	/*
	 * Criteria for fast path:
	 *
	 *   1. no unsent data
	 *   2. single mblk in request
	 *   3. connection established
	 *   4. data in mblk
	 *   5. len <= mss
	 *   6. no tcp_valid bits
	 */
	if ((tcp->tcp_unsent != 0) ||
	    (tcp->tcp_cork) ||
	    (mp->b_cont != NULL) ||
	    (tcp->tcp_state != TCPS_ESTABLISHED) ||
	    (len == 0) ||
	    (len > mss) ||
	    (tcp->tcp_valid_bits != 0)) {
		tcp_wput_data(tcp, mp, B_FALSE);
		return;
	}

	ASSERT(tcp->tcp_xmit_tail_unsent == 0);
	ASSERT(tcp->tcp_fin_sent == 0);

	/* queue new packet onto retransmission queue */
	if (tcp->tcp_xmit_head == NULL) {
		tcp->tcp_xmit_head = mp;
	} else {
		tcp->tcp_xmit_last->b_cont = mp;
	}
	tcp->tcp_xmit_last = mp;
	tcp->tcp_xmit_tail = mp;

	/* find out how much we can send */
	/* BEGIN CSTYLED */
	/*
	 *    un-acked	   usable
	 *  |--------------|-----------------|
	 *  tcp_suna       tcp_snxt	  tcp_suna+tcp_swnd
	 */
	/* END CSTYLED */

	/* start sending from tcp_snxt */
	snxt = tcp->tcp_snxt;

	/*
	 * Check to see if this connection has been idled for some
	 * time and no ACK is expected.  If it is, we need to slow
	 * start again to get back the connection's "self-clock" as
	 * described in VJ's paper.
	 *
	 * Refer to the comment in tcp_mss_set() for the calculation
	 * of tcp_cwnd after idle.
	 */
	if ((tcp->tcp_suna == snxt) && !tcp->tcp_localnet &&
	    (TICK_TO_MSEC(lbolt - tcp->tcp_last_recv_time) >= tcp->tcp_rto)) {
		SET_TCP_INIT_CWND(tcp, mss, tcps->tcps_slow_start_after_idle);
	}

	usable = tcp->tcp_swnd;		/* tcp window size */
	if (usable > tcp->tcp_cwnd)
		usable = tcp->tcp_cwnd;	/* congestion window smaller */
	usable -= snxt;		/* subtract stuff already sent */
	suna = tcp->tcp_suna;
	usable += suna;
	/* usable can be < 0 if the congestion window is smaller */
	if (len > usable) {
		/* Can't send complete M_DATA in one shot */
		goto slow;
	}

	mutex_enter(&tcp->tcp_non_sq_lock);
	if (tcp->tcp_flow_stopped &&
	    TCP_UNSENT_BYTES(tcp) <= tcp->tcp_xmit_lowater) {
		tcp_clrqfull(tcp);
	}
	mutex_exit(&tcp->tcp_non_sq_lock);

	/*
	 * determine if anything to send (Nagle).
	 *
	 *   1. len < tcp_mss (i.e. small)
	 *   2. unacknowledged data present
	 *   3. len < nagle limit
	 *   4. last packet sent < nagle limit (previous packet sent)
	 */
	if ((len < mss) && (snxt != suna) &&
	    (len < (int)tcp->tcp_naglim) &&
	    (tcp->tcp_last_sent_len < tcp->tcp_naglim)) {
		/*
		 * This was the first unsent packet and normally
		 * mss < xmit_hiwater so there is no need to worry
		 * about flow control. The next packet will go
		 * through the flow control check in tcp_wput_data().
		 */
		/* leftover work from above */
		tcp->tcp_unsent = len;
		tcp->tcp_xmit_tail_unsent = len;

		return;
	}

	/* len <= tcp->tcp_mss && len == unsent so no silly window */

	if (snxt == suna) {
		TCP_TIMER_RESTART(tcp, tcp->tcp_rto);
	}

	/* we have always sent something */
	tcp->tcp_rack_cnt = 0;

	tcp->tcp_snxt = snxt + len;
	tcp->tcp_rack = tcp->tcp_rnxt;

	if ((mp1 = dupb(mp)) == 0)
		goto no_memory;
	mp->b_prev = (mblk_t *)(uintptr_t)lbolt;
	mp->b_next = (mblk_t *)(uintptr_t)snxt;

	/* adjust tcp header information */
	tcph = tcp->tcp_tcph;
	tcph->th_flags[0] = (TH_ACK|TH_PUSH);

	sum = len + tcp->tcp_tcp_hdr_len + tcp->tcp_sum;
	sum = (sum >> 16) + (sum & 0xFFFF);
	U16_TO_ABE16(sum, tcph->th_sum);

	U32_TO_ABE32(snxt, tcph->th_seq);

	BUMP_MIB(&tcps->tcps_mib, tcpOutDataSegs);
	UPDATE_MIB(&tcps->tcps_mib, tcpOutDataBytes, len);
	BUMP_LOCAL(tcp->tcp_obsegs);

	/* Update the latest receive window size in TCP header. */
	U32_TO_ABE16(tcp->tcp_rwnd >> tcp->tcp_rcv_ws,
	    tcph->th_win);

	tcp->tcp_last_sent_len = (ushort_t)len;

	plen = len + tcp->tcp_hdr_len;

	if (tcp->tcp_ipversion == IPV4_VERSION) {
		tcp->tcp_ipha->ipha_length = htons(plen);
	} else {
		tcp->tcp_ip6h->ip6_plen = htons(plen -
		    ((char *)&tcp->tcp_ip6h[1] - tcp->tcp_iphc));
	}

	/* see if we need to allocate a mblk for the headers */
	hdrlen = tcp->tcp_hdr_len;
	rptr = mp1->b_rptr - hdrlen;
	db = mp1->b_datap;
	if ((db->db_ref != 2) || rptr < db->db_base ||
	    (!OK_32PTR(rptr))) {
		/* NOTE: we assume allocb returns an OK_32PTR */
		mp = allocb(tcp->tcp_ip_hdr_len + TCP_MAX_HDR_LENGTH +
		    tcps->tcps_wroff_xtra, BPRI_MED);
		if (!mp) {
			freemsg(mp1);
			goto no_memory;
		}
		mp->b_cont = mp1;
		mp1 = mp;
		/* Leave room for Link Level header */
		/* hdrlen = tcp->tcp_hdr_len; */
		rptr = &mp1->b_rptr[tcps->tcps_wroff_xtra];
		mp1->b_wptr = &rptr[hdrlen];
	}
	mp1->b_rptr = rptr;

	/* Fill in the timestamp option. */
	if (tcp->tcp_snd_ts_ok) {
		U32_TO_BE32((uint32_t)lbolt,
		    (char *)tcph+TCP_MIN_HEADER_LENGTH+4);
		U32_TO_BE32(tcp->tcp_ts_recent,
		    (char *)tcph+TCP_MIN_HEADER_LENGTH+8);
	} else {
		ASSERT(tcp->tcp_tcp_hdr_len == TCP_MIN_HEADER_LENGTH);
	}

	/* copy header into outgoing packet */
	dst = (ipaddr_t *)rptr;
	src = (ipaddr_t *)tcp->tcp_iphc;
	dst[0] = src[0];
	dst[1] = src[1];
	dst[2] = src[2];
	dst[3] = src[3];
	dst[4] = src[4];
	dst[5] = src[5];
	dst[6] = src[6];
	dst[7] = src[7];
	dst[8] = src[8];
	dst[9] = src[9];
	if (hdrlen -= 40) {
		hdrlen >>= 2;
		dst += 10;
		src += 10;
		do {
			*dst++ = *src++;
		} while (--hdrlen);
	}

	/*
	 * Set the ECN info in the TCP header.  Note that this
	 * is not the template header.
	 */
	if (tcp->tcp_ecn_ok) {
		SET_ECT(tcp, rptr);

		tcph = (tcph_t *)(rptr + tcp->tcp_ip_hdr_len);
		if (tcp->tcp_ecn_echo_on)
			tcph->th_flags[0] |= TH_ECE;
		if (tcp->tcp_cwr && !tcp->tcp_ecn_cwr_sent) {
			tcph->th_flags[0] |= TH_CWR;
			tcp->tcp_ecn_cwr_sent = B_TRUE;
		}
	}

	if (tcp->tcp_ip_forward_progress) {
		ASSERT(tcp->tcp_ipversion == IPV6_VERSION);
		*(uint32_t *)mp1->b_rptr  |= IP_FORWARD_PROG;
		tcp->tcp_ip_forward_progress = B_FALSE;
	}
	tcp_send_data(tcp, tcp->tcp_wq, mp1);
	return;

	/*
	 * If we ran out of memory, we pretend to have sent the packet
	 * and that it was lost on the wire.
	 */
no_memory:
	return;

slow:
	/* leftover work from above */
	tcp->tcp_unsent = len;
	tcp->tcp_xmit_tail_unsent = len;
	tcp_wput_data(tcp, NULL, B_FALSE);
}

/* ARGSUSED */
void
tcp_accept_finish(void *arg, mblk_t *mp, void *arg2)
{
	conn_t			*connp = (conn_t *)arg;
	tcp_t			*tcp = connp->conn_tcp;
	queue_t			*q = tcp->tcp_rq;
	struct tcp_options	*tcpopt;
	tcp_stack_t		*tcps = tcp->tcp_tcps;

	/* socket options */
	uint_t 			sopp_flags;
	ssize_t			sopp_rxhiwat;
	ssize_t			sopp_maxblk;
	ushort_t		sopp_wroff;
	ushort_t		sopp_tail;
	ushort_t		sopp_copyopt;

	tcpopt = (struct tcp_options *)mp->b_rptr;

	/*
	 * Drop the eager's ref on the listener, that was placed when
	 * this eager began life in tcp_conn_request.
	 */
	CONN_DEC_REF(tcp->tcp_saved_listener->tcp_connp);
	if (IPCL_IS_NONSTR(connp)) {
		/* Safe to free conn_ind message */
		freemsg(tcp->tcp_conn.tcp_eager_conn_ind);
		tcp->tcp_conn.tcp_eager_conn_ind = NULL;

		/* The listener tells us which upper handle to use */
		ASSERT(tcpopt->to_flags & TCPOPT_UPPERHANDLE);
		connp->conn_upper_handle = tcpopt->to_handle;
	}

	tcp->tcp_detached = B_FALSE;

	if (tcp->tcp_state <= TCPS_BOUND || tcp->tcp_accept_error) {
		/*
		 * Someone blewoff the eager before we could finish
		 * the accept.
		 *
		 * The only reason eager exists it because we put in
		 * a ref on it when conn ind went up. We need to send
		 * a disconnect indication up while the last reference
		 * on the eager will be dropped by the squeue when we
		 * return.
		 */
		ASSERT(tcp->tcp_listener == NULL);
		if (tcp->tcp_issocket || tcp->tcp_send_discon_ind) {
			if (IPCL_IS_NONSTR(connp)) {
				ASSERT(tcp->tcp_issocket);
				(*connp->conn_upcalls->su_disconnected)(
				    connp->conn_upper_handle, tcp->tcp_connid,
				    ECONNREFUSED);
				freemsg(mp);
			} else {
				struct	T_discon_ind	*tdi;

				(void) putnextctl1(q, M_FLUSH, FLUSHRW);
				/*
				 * Let us reuse the incoming mblk to avoid
				 * memory allocation failure problems. We know
				 * that the size of the incoming mblk i.e.
				 * stroptions is greater than sizeof
				 * T_discon_ind. So the reallocb below can't
				 * fail.
				 */
				freemsg(mp->b_cont);
				mp->b_cont = NULL;
				ASSERT(DB_REF(mp) == 1);
				mp = reallocb(mp, sizeof (struct T_discon_ind),
				    B_FALSE);
				ASSERT(mp != NULL);
				DB_TYPE(mp) = M_PROTO;
				((union T_primitives *)mp->b_rptr)->type =
				    T_DISCON_IND;
				tdi = (struct T_discon_ind *)mp->b_rptr;
				if (tcp->tcp_issocket) {
					tdi->DISCON_reason = ECONNREFUSED;
					tdi->SEQ_number = 0;
				} else {
					tdi->DISCON_reason = ENOPROTOOPT;
					tdi->SEQ_number =
					    tcp->tcp_conn_req_seqnum;
				}
				mp->b_wptr = mp->b_rptr +
				    sizeof (struct T_discon_ind);
				putnext(q, mp);
				return;
			}
		}
		if (tcp->tcp_hard_binding) {
			tcp->tcp_hard_binding = B_FALSE;
			tcp->tcp_hard_bound = B_TRUE;
		}
		return;
	}

	if (tcpopt->to_flags & TCPOPT_BOUNDIF) {
		int boundif = tcpopt->to_boundif;
		uint_t len = sizeof (int);

		(void) tcp_opt_set(connp, SETFN_OPTCOM_NEGOTIATE, IPPROTO_IPV6,
		    IPV6_BOUND_IF, len, (uchar_t *)&boundif, &len,
		    (uchar_t *)&boundif, NULL, tcp->tcp_cred, NULL);
	}
	if (tcpopt->to_flags & TCPOPT_RECVPKTINFO) {
		uint_t on = 1;
		uint_t len = sizeof (uint_t);
		(void) tcp_opt_set(connp, SETFN_OPTCOM_NEGOTIATE, IPPROTO_IPV6,
		    IPV6_RECVPKTINFO, len, (uchar_t *)&on, &len,
		    (uchar_t *)&on, NULL, tcp->tcp_cred, NULL);
	}

	/*
	 * For a loopback connection with tcp_direct_sockfs on, note that
	 * we don't have to protect tcp_rcv_list yet because synchronous
	 * streams has not yet been enabled and tcp_fuse_rrw() cannot
	 * possibly race with us.
	 */

	/*
	 * Set the max window size (tcp_rq->q_hiwat) of the acceptor
	 * properly.  This is the first time we know of the acceptor'
	 * queue.  So we do it here.
	 *
	 * XXX
	 */
	if (tcp->tcp_rcv_list == NULL) {
		/*
		 * Recv queue is empty, tcp_rwnd should not have changed.
		 * That means it should be equal to the listener's tcp_rwnd.
		 */
		if (!IPCL_IS_NONSTR(connp))
			tcp->tcp_rq->q_hiwat = tcp->tcp_rwnd;
		tcp->tcp_recv_hiwater = tcp->tcp_rwnd;
	} else {
#ifdef DEBUG
		mblk_t *tmp;
		mblk_t	*mp1;
		uint_t	cnt = 0;

		mp1 = tcp->tcp_rcv_list;
		while ((tmp = mp1) != NULL) {
			mp1 = tmp->b_next;
			cnt += msgdsize(tmp);
		}
		ASSERT(cnt != 0 && tcp->tcp_rcv_cnt == cnt);
#endif
		/* There is some data, add them back to get the max. */
		if (!IPCL_IS_NONSTR(connp))
			tcp->tcp_rq->q_hiwat = tcp->tcp_rwnd + tcp->tcp_rcv_cnt;
		tcp->tcp_recv_hiwater = tcp->tcp_rwnd + tcp->tcp_rcv_cnt;
	}
	/*
	 * This is the first time we run on the correct
	 * queue after tcp_accept. So fix all the q parameters
	 * here.
	 */
	sopp_flags = SOCKOPT_RCVHIWAT | SOCKOPT_MAXBLK | SOCKOPT_WROFF;
	sopp_maxblk = tcp_maxpsz_set(tcp, B_FALSE);

	/*
	 * Record the stream head's high water mark for this endpoint;
	 * this is used for flow-control purposes.
	 */
	sopp_rxhiwat = tcp->tcp_fused ?
	    tcp_fuse_set_rcv_hiwat(tcp, tcp->tcp_recv_hiwater) :
	    MAX(tcp->tcp_recv_hiwater, tcps->tcps_sth_rcv_hiwat);

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
		sopp_wroff = 0;
		/*
		 * Update the peer's transmit parameters according to
		 * our recently calculated high water mark value.
		 */
		(void) tcp_maxpsz_set(tcp->tcp_loopback_peer, B_TRUE);
	} else if (tcp->tcp_snd_sack_ok) {
		sopp_wroff = tcp->tcp_hdr_len + TCPOPT_MAX_SACK_LEN +
		    (tcp->tcp_loopback ? 0 : tcps->tcps_wroff_xtra);
	} else {
		sopp_wroff = tcp->tcp_hdr_len + (tcp->tcp_loopback ? 0 :
		    tcps->tcps_wroff_xtra);
	}

	/*
	 * If this is endpoint is handling SSL, then reserve extra
	 * offset and space at the end.
	 * Also have the stream head allocate SSL3_MAX_RECORD_LEN packets,
	 * overriding the previous setting. The extra cost of signing and
	 * encrypting multiple MSS-size records (12 of them with Ethernet),
	 * instead of a single contiguous one by the stream head
	 * largely outweighs the statistical reduction of ACKs, when
	 * applicable. The peer will also save on decryption and verification
	 * costs.
	 */
	if (tcp->tcp_kssl_ctx != NULL) {
		sopp_wroff += SSL3_WROFFSET;

		sopp_flags |= SOCKOPT_TAIL;
		sopp_tail = SSL3_MAX_TAIL_LEN;

		sopp_flags |= SOCKOPT_ZCOPY;
		sopp_copyopt = ZCVMUNSAFE;

		sopp_maxblk = SSL3_MAX_RECORD_LEN;
	}

	/* Send the options up */
	if (IPCL_IS_NONSTR(connp)) {
		struct sock_proto_props sopp;

		sopp.sopp_flags = sopp_flags;
		sopp.sopp_wroff = sopp_wroff;
		sopp.sopp_maxblk = sopp_maxblk;
		sopp.sopp_rxhiwat = sopp_rxhiwat;
		if (sopp_flags & SOCKOPT_TAIL) {
			ASSERT(tcp->tcp_kssl_ctx != NULL);
			ASSERT(sopp_flags & SOCKOPT_ZCOPY);
			sopp.sopp_tail = sopp_tail;
			sopp.sopp_zcopyflag = sopp_copyopt;
		}
		(*connp->conn_upcalls->su_set_proto_props)
		    (connp->conn_upper_handle, &sopp);
	} else {
		struct stroptions *stropt;
		mblk_t *stropt_mp = allocb(sizeof (struct stroptions), BPRI_HI);
		if (stropt_mp == NULL) {
			tcp_err_ack(tcp, mp, TSYSERR, ENOMEM);
			return;
		}
		DB_TYPE(stropt_mp) = M_SETOPTS;
		stropt = (struct stroptions *)stropt_mp->b_rptr;
		stropt_mp->b_wptr += sizeof (struct stroptions);
		stropt = (struct stroptions *)stropt_mp->b_rptr;
		stropt->so_flags |= SO_HIWAT | SO_WROFF | SO_MAXBLK;
		stropt->so_hiwat = sopp_rxhiwat;
		stropt->so_wroff = sopp_wroff;
		stropt->so_maxblk = sopp_maxblk;

		if (sopp_flags & SOCKOPT_TAIL) {
			ASSERT(tcp->tcp_kssl_ctx != NULL);

			stropt->so_flags |= SO_TAIL | SO_COPYOPT;
			stropt->so_tail = sopp_tail;
			stropt->so_copyopt = sopp_copyopt;
		}

		/* Send the options up */
		putnext(q, stropt_mp);
	}

	freemsg(mp);
	/*
	 * Pass up any data and/or a fin that has been received.
	 *
	 * Adjust receive window in case it had decreased
	 * (because there is data <=> tcp_rcv_list != NULL)
	 * while the connection was detached. Note that
	 * in case the eager was flow-controlled, w/o this
	 * code, the rwnd may never open up again!
	 */
	if (tcp->tcp_rcv_list != NULL) {
		if (IPCL_IS_NONSTR(connp)) {
			mblk_t *mp;
			int space_left;
			int error;
			boolean_t push = B_TRUE;

			if (!tcp->tcp_fused && (*connp->conn_upcalls->su_recv)
			    (connp->conn_upper_handle, NULL, 0, 0, &error,
			    &push) >= 0) {
				tcp->tcp_rwnd = tcp->tcp_recv_hiwater;
				if (tcp->tcp_state >= TCPS_ESTABLISHED &&
				    tcp_rwnd_reopen(tcp) == TH_ACK_NEEDED) {
					tcp_xmit_ctl(NULL,
					    tcp, (tcp->tcp_swnd == 0) ?
					    tcp->tcp_suna : tcp->tcp_snxt,
					    tcp->tcp_rnxt, TH_ACK);
				}
			}
			while ((mp = tcp->tcp_rcv_list) != NULL) {
				push = B_TRUE;
				tcp->tcp_rcv_list = mp->b_next;
				mp->b_next = NULL;
				space_left = (*connp->conn_upcalls->su_recv)
				    (connp->conn_upper_handle, mp, msgdsize(mp),
				    0, &error, &push);
				if (space_left < 0) {
					/*
					 * At this point the eager is not
					 * visible to anyone, so fallback
					 * can not happen.
					 */
					ASSERT(error != EOPNOTSUPP);
				}
			}
			tcp->tcp_rcv_last_head = NULL;
			tcp->tcp_rcv_last_tail = NULL;
			tcp->tcp_rcv_cnt = 0;
		} else {
			/* We drain directly in case of fused tcp loopback */
			sodirect_t *sodp;

			if (!tcp->tcp_fused && canputnext(q)) {
				tcp->tcp_rwnd = q->q_hiwat;
				if (tcp->tcp_state >= TCPS_ESTABLISHED &&
				    tcp_rwnd_reopen(tcp) == TH_ACK_NEEDED) {
					tcp_xmit_ctl(NULL,
					    tcp, (tcp->tcp_swnd == 0) ?
					    tcp->tcp_suna : tcp->tcp_snxt,
					    tcp->tcp_rnxt, TH_ACK);
				}
			}

			SOD_PTR_ENTER(tcp, sodp);
			if (sodp != NULL) {
				/* Sodirect, move from rcv_list */
				ASSERT(!tcp->tcp_fused);
				while ((mp = tcp->tcp_rcv_list) != NULL) {
					tcp->tcp_rcv_list = mp->b_next;
					mp->b_next = NULL;
					(void) tcp_rcv_sod_enqueue(tcp, sodp,
					    mp, msgdsize(mp));
				}
				tcp->tcp_rcv_last_head = NULL;
				tcp->tcp_rcv_last_tail = NULL;
				tcp->tcp_rcv_cnt = 0;
				(void) tcp_rcv_sod_wakeup(tcp, sodp);
				/* sod_wakeup() did the mutex_exit() */
			} else {
				/* Not sodirect, drain */
				(void) tcp_rcv_drain(tcp);
			}
		}

		/*
		 * For fused tcp loopback, back-enable peer endpoint
		 * if it's currently flow-controlled.
		 */
		if (tcp->tcp_fused) {
			tcp_t *peer_tcp = tcp->tcp_loopback_peer;

			ASSERT(peer_tcp != NULL);
			ASSERT(peer_tcp->tcp_fused);
			/*
			 * In order to change the peer's tcp_flow_stopped,
			 * we need to take locks for both end points. The
			 * highest address is taken first.
			 */
			if (peer_tcp > tcp) {
				mutex_enter(&peer_tcp->tcp_non_sq_lock);
				mutex_enter(&tcp->tcp_non_sq_lock);
			} else {
				mutex_enter(&tcp->tcp_non_sq_lock);
				mutex_enter(&peer_tcp->tcp_non_sq_lock);
			}
			if (peer_tcp->tcp_flow_stopped) {
				tcp_clrqfull(peer_tcp);
				TCP_STAT(tcps, tcp_fusion_backenabled);
			}
			mutex_exit(&peer_tcp->tcp_non_sq_lock);
			mutex_exit(&tcp->tcp_non_sq_lock);
		}
	}
	ASSERT(tcp->tcp_rcv_list == NULL || tcp->tcp_fused_sigurg);
	if (tcp->tcp_fin_rcvd && !tcp->tcp_ordrel_done) {
		tcp->tcp_ordrel_done = B_TRUE;
		if (IPCL_IS_NONSTR(connp)) {
			ASSERT(tcp->tcp_ordrel_mp == NULL);
			(*connp->conn_upcalls->su_opctl)(
			    connp->conn_upper_handle,
			    SOCK_OPCTL_SHUT_RECV, 0);
		} else {
			mp = tcp->tcp_ordrel_mp;
			tcp->tcp_ordrel_mp = NULL;
			putnext(q, mp);
		}
	}
	if (tcp->tcp_hard_binding) {
		tcp->tcp_hard_binding = B_FALSE;
		tcp->tcp_hard_bound = B_TRUE;
	}

	/* We can enable synchronous streams for STREAMS tcp endpoint now */
	if (tcp->tcp_fused && !IPCL_IS_NONSTR(connp) &&
	    tcp->tcp_loopback_peer != NULL &&
	    !IPCL_IS_NONSTR(tcp->tcp_loopback_peer->tcp_connp)) {
		tcp_fuse_syncstr_enable_pair(tcp);
	}

	if (tcp->tcp_ka_enabled) {
		tcp->tcp_ka_last_intrvl = 0;
		tcp->tcp_ka_tid = TCP_TIMER(tcp, tcp_keepalive_killer,
		    MSEC_TO_TICK(tcp->tcp_ka_interval));
	}

	/*
	 * At this point, eager is fully established and will
	 * have the following references -
	 *
	 * 2 references for connection to exist (1 for TCP and 1 for IP).
	 * 1 reference for the squeue which will be dropped by the squeue as
	 *	soon as this function returns.
	 * There will be 1 additonal reference for being in classifier
	 *	hash list provided something bad hasn't happened.
	 */
	ASSERT((connp->conn_fanout != NULL && connp->conn_ref >= 4) ||
	    (connp->conn_fanout == NULL && connp->conn_ref >= 3));
}

/*
 * The function called through squeue to get behind listener's perimeter to
 * send a deffered conn_ind.
 */
/* ARGSUSED */
void
tcp_send_pending(void *arg, mblk_t *mp, void *arg2)
{
	conn_t	*connp = (conn_t *)arg;
	tcp_t *listener = connp->conn_tcp;
	struct T_conn_ind *conn_ind;
	tcp_t *tcp;

	if (listener->tcp_state == TCPS_CLOSED ||
	    TCP_IS_DETACHED(listener)) {
		/*
		 * If listener has closed, it would have caused a
		 * a cleanup/blowoff to happen for the eager.
		 */

		conn_ind = (struct T_conn_ind *)mp->b_rptr;
		bcopy(mp->b_rptr + conn_ind->OPT_offset, &tcp,
		    conn_ind->OPT_length);
		/*
		 * We need to drop the ref on eager that was put
		 * tcp_rput_data() before trying to send the conn_ind
		 * to listener. The conn_ind was deferred in tcp_send_conn_ind
		 * and tcp_wput_accept() is sending this deferred conn_ind but
		 * listener is closed so we drop the ref.
		 */
		CONN_DEC_REF(tcp->tcp_connp);
		freemsg(mp);
		return;
	}
	if (IPCL_IS_NONSTR(connp)) {
		conn_ind = (struct T_conn_ind *)mp->b_rptr;
		bcopy(mp->b_rptr + conn_ind->OPT_offset, &tcp,
		    conn_ind->OPT_length);

		if ((*connp->conn_upcalls->su_newconn)
		    (connp->conn_upper_handle,
		    (sock_lower_handle_t)tcp->tcp_connp,
		    &sock_tcp_downcalls, DB_CRED(mp), DB_CPID(mp),
		    &tcp->tcp_connp->conn_upcalls) != NULL) {
			/* Keep the message around in case of fallback */
			tcp->tcp_conn.tcp_eager_conn_ind = mp;
		} else {
			freemsg(mp);
		}
	} else {
		putnext(listener->tcp_rq, mp);
	}
}

/* ARGSUSED */
static int
tcp_accept_common(conn_t *lconnp, conn_t *econnp,
    sock_upper_handle_t sock_handle, cred_t *cr)
{
	tcp_t *listener, *eager;
	mblk_t *opt_mp;
	struct tcp_options *tcpopt;

	listener = lconnp->conn_tcp;
	ASSERT(listener->tcp_state == TCPS_LISTEN);
	eager = econnp->conn_tcp;
	ASSERT(eager->tcp_listener != NULL);

	ASSERT(eager->tcp_rq != NULL);

	/* If tcp_fused and sodirect enabled disable it */
	if (eager->tcp_fused && eager->tcp_sodirect != NULL) {
		/* Fused, disable sodirect */
		mutex_enter(eager->tcp_sodirect->sod_lockp);
		SOD_DISABLE(eager->tcp_sodirect);
		mutex_exit(eager->tcp_sodirect->sod_lockp);
		eager->tcp_sodirect = NULL;
	}

	opt_mp = allocb(sizeof (struct tcp_options), BPRI_HI);
	if (opt_mp == NULL) {
		return (-TPROTO);
	}
	bzero((char *)opt_mp->b_rptr, sizeof (struct tcp_options));
	eager->tcp_issocket = B_TRUE;

	econnp->conn_upcalls = lconnp->conn_upcalls;
	econnp->conn_zoneid = listener->tcp_connp->conn_zoneid;
	econnp->conn_allzones = listener->tcp_connp->conn_allzones;
	ASSERT(econnp->conn_netstack ==
	    listener->tcp_connp->conn_netstack);
	ASSERT(eager->tcp_tcps == listener->tcp_tcps);

	/* Put the ref for IP */
	CONN_INC_REF(econnp);

	/*
	 * We should have minimum of 3 references on the conn
	 * at this point. One each for TCP and IP and one for
	 * the T_conn_ind that was sent up when the 3-way handshake
	 * completed. In the normal case we would also have another
	 * reference (making a total of 4) for the conn being in the
	 * classifier hash list. However the eager could have received
	 * an RST subsequently and tcp_closei_local could have removed
	 * the eager from the classifier hash list, hence we can't
	 * assert that reference.
	 */
	ASSERT(econnp->conn_ref >= 3);

	opt_mp->b_datap->db_type = M_SETOPTS;
	opt_mp->b_wptr += sizeof (struct tcp_options);

	/*
	 * Prepare for inheriting IPV6_BOUND_IF and IPV6_RECVPKTINFO
	 * from listener to acceptor. In case of non-STREAMS sockets,
	 * we also need to pass the upper handle along.
	 */
	tcpopt = (struct tcp_options *)opt_mp->b_rptr;
	tcpopt->to_flags = 0;

	if (IPCL_IS_NONSTR(econnp)) {
		ASSERT(sock_handle != NULL);
		tcpopt->to_flags |= TCPOPT_UPPERHANDLE;
		tcpopt->to_handle = sock_handle;
	}
	if (listener->tcp_bound_if != 0) {
		tcpopt->to_flags |= TCPOPT_BOUNDIF;
		tcpopt->to_boundif = listener->tcp_bound_if;
	}
	if (listener->tcp_ipv6_recvancillary & TCP_IPV6_RECVPKTINFO) {
		tcpopt->to_flags |= TCPOPT_RECVPKTINFO;
	}

	mutex_enter(&listener->tcp_eager_lock);
	if (listener->tcp_eager_prev_q0->tcp_conn_def_q0) {

		tcp_t *tail;
		tcp_t *tcp;
		mblk_t *mp1;

		tcp = listener->tcp_eager_prev_q0;
		/*
		 * listener->tcp_eager_prev_q0 points to the TAIL of the
		 * deferred T_conn_ind queue. We need to get to the head
		 * of the queue in order to send up T_conn_ind the same
		 * order as how the 3WHS is completed.
		 */
		while (tcp != listener) {
			if (!tcp->tcp_eager_prev_q0->tcp_conn_def_q0 &&
			    !tcp->tcp_kssl_pending)
				break;
			else
				tcp = tcp->tcp_eager_prev_q0;
		}
		/* None of the pending eagers can be sent up now */
		if (tcp == listener)
			goto no_more_eagers;

		mp1 = tcp->tcp_conn.tcp_eager_conn_ind;
		tcp->tcp_conn.tcp_eager_conn_ind = NULL;
		/* Move from q0 to q */
		ASSERT(listener->tcp_conn_req_cnt_q0 > 0);
		listener->tcp_conn_req_cnt_q0--;
		listener->tcp_conn_req_cnt_q++;
		tcp->tcp_eager_next_q0->tcp_eager_prev_q0 =
		    tcp->tcp_eager_prev_q0;
		tcp->tcp_eager_prev_q0->tcp_eager_next_q0 =
		    tcp->tcp_eager_next_q0;
		tcp->tcp_eager_prev_q0 = NULL;
		tcp->tcp_eager_next_q0 = NULL;
		tcp->tcp_conn_def_q0 = B_FALSE;

		/* Make sure the tcp isn't in the list of droppables */
		ASSERT(tcp->tcp_eager_next_drop_q0 == NULL &&
		    tcp->tcp_eager_prev_drop_q0 == NULL);

		/*
		 * Insert at end of the queue because sockfs sends
		 * down T_CONN_RES in chronological order. Leaving
		 * the older conn indications at front of the queue
		 * helps reducing search time.
		 */
		tail = listener->tcp_eager_last_q;
		if (tail != NULL) {
			tail->tcp_eager_next_q = tcp;
		} else {
			listener->tcp_eager_next_q = tcp;
		}
		listener->tcp_eager_last_q = tcp;
		tcp->tcp_eager_next_q = NULL;

		/* Need to get inside the listener perimeter */
		CONN_INC_REF(listener->tcp_connp);
		SQUEUE_ENTER_ONE(listener->tcp_connp->conn_sqp, mp1,
		    tcp_send_pending, listener->tcp_connp, SQ_FILL,
		    SQTAG_TCP_SEND_PENDING);
	}
no_more_eagers:
	tcp_eager_unlink(eager);
	mutex_exit(&listener->tcp_eager_lock);

	/*
	 * At this point, the eager is detached from the listener
	 * but we still have an extra refs on eager (apart from the
	 * usual tcp references). The ref was placed in tcp_rput_data
	 * before sending the conn_ind in tcp_send_conn_ind.
	 * The ref will be dropped in tcp_accept_finish().
	 */
	SQUEUE_ENTER_ONE(econnp->conn_sqp, opt_mp, tcp_accept_finish,
	    econnp, SQ_NODRAIN, SQTAG_TCP_ACCEPT_FINISH_Q0);
	return (0);
}

int
tcp_accept(sock_lower_handle_t lproto_handle,
    sock_lower_handle_t eproto_handle, sock_upper_handle_t sock_handle,
    cred_t *cr)
{
	conn_t *lconnp, *econnp;
	tcp_t *listener, *eager;
	tcp_stack_t	*tcps;

	lconnp = (conn_t *)lproto_handle;
	listener = lconnp->conn_tcp;
	ASSERT(listener->tcp_state == TCPS_LISTEN);
	econnp = (conn_t *)eproto_handle;
	eager = econnp->conn_tcp;
	ASSERT(eager->tcp_listener != NULL);
	tcps = eager->tcp_tcps;

	ASSERT(IPCL_IS_NONSTR(econnp));
	/*
	 * Create helper stream if it is a non-TPI TCP connection.
	 */
	if (ip_create_helper_stream(econnp, tcps->tcps_ldi_ident)) {
		ip1dbg(("tcp_accept: create of IP helper stream"
		    " failed\n"));
		return (EPROTO);
	}
	eager->tcp_rq = econnp->conn_rq;
	eager->tcp_wq = econnp->conn_wq;

	ASSERT(eager->tcp_rq != NULL);

	eager->tcp_sodirect = SOD_SOTOSODP(sock_handle);
	return (tcp_accept_common(lconnp, econnp, sock_handle, cr));
}


/*
 * This is the STREAMS entry point for T_CONN_RES coming down on
 * Acceptor STREAM when  sockfs listener does accept processing.
 * Read the block comment on top of tcp_conn_request().
 */
void
tcp_tpi_accept(queue_t *q, mblk_t *mp)
{
	queue_t *rq = RD(q);
	struct T_conn_res *conn_res;
	tcp_t *eager;
	tcp_t *listener;
	struct T_ok_ack *ok;
	t_scalar_t PRIM_type;
	conn_t *econnp;

	ASSERT(DB_TYPE(mp) == M_PROTO);

	conn_res = (struct T_conn_res *)mp->b_rptr;
	ASSERT((uintptr_t)(mp->b_wptr - mp->b_rptr) <= (uintptr_t)INT_MAX);
	if ((mp->b_wptr - mp->b_rptr) < sizeof (struct T_conn_res)) {
		mp = mi_tpi_err_ack_alloc(mp, TPROTO, 0);
		if (mp != NULL)
			putnext(rq, mp);
		return;
	}
	switch (conn_res->PRIM_type) {
	case O_T_CONN_RES:
	case T_CONN_RES:
		/*
		 * We pass up an err ack if allocb fails. This will
		 * cause sockfs to issue a T_DISCON_REQ which will cause
		 * tcp_eager_blowoff to be called. sockfs will then call
		 * rq->q_qinfo->qi_qclose to cleanup the acceptor stream.
		 * we need to do the allocb up here because we have to
		 * make sure rq->q_qinfo->qi_qclose still points to the
		 * correct function (tcpclose_accept) in case allocb
		 * fails.
		 */
		bcopy(mp->b_rptr + conn_res->OPT_offset,
		    &eager, conn_res->OPT_length);
		PRIM_type = conn_res->PRIM_type;
		mp->b_datap->db_type = M_PCPROTO;
		mp->b_wptr = mp->b_rptr + sizeof (struct T_ok_ack);
		ok = (struct T_ok_ack *)mp->b_rptr;
		ok->PRIM_type = T_OK_ACK;
		ok->CORRECT_prim = PRIM_type;
		econnp = eager->tcp_connp;
		econnp->conn_dev = (dev_t)RD(q)->q_ptr;
		econnp->conn_minor_arena = (vmem_t *)(WR(q)->q_ptr);
		eager->tcp_rq = rq;
		eager->tcp_wq = q;
		rq->q_ptr = econnp;
		rq->q_qinfo = &tcp_rinitv4;	/* No open - same as rinitv6 */
		q->q_ptr = econnp;
		q->q_qinfo = &tcp_winit;
		listener = eager->tcp_listener;

		/*
		 * TCP is _D_SODIRECT and sockfs is directly above so
		 * save shared sodirect_t pointer (if any).
		 */
		eager->tcp_sodirect = SOD_QTOSODP(eager->tcp_rq);
		if (tcp_accept_common(listener->tcp_connp,
		    econnp, NULL, CRED()) < 0) {
			mp = mi_tpi_err_ack_alloc(mp, TPROTO, 0);
			if (mp != NULL)
				putnext(rq, mp);
			return;
		}

		/*
		 * Send the new local address also up to sockfs. There
		 * should already be enough space in the mp that came
		 * down from soaccept().
		 */
		if (eager->tcp_family == AF_INET) {
			sin_t *sin;

			ASSERT((mp->b_datap->db_lim - mp->b_datap->db_base) >=
			    (sizeof (struct T_ok_ack) + sizeof (sin_t)));
			sin = (sin_t *)mp->b_wptr;
			mp->b_wptr += sizeof (sin_t);
			sin->sin_family = AF_INET;
			sin->sin_port = eager->tcp_lport;
			sin->sin_addr.s_addr = eager->tcp_ipha->ipha_src;
		} else {
			sin6_t *sin6;

			ASSERT((mp->b_datap->db_lim - mp->b_datap->db_base) >=
			    sizeof (struct T_ok_ack) + sizeof (sin6_t));
			sin6 = (sin6_t *)mp->b_wptr;
			mp->b_wptr += sizeof (sin6_t);
			sin6->sin6_family = AF_INET6;
			sin6->sin6_port = eager->tcp_lport;
			if (eager->tcp_ipversion == IPV4_VERSION) {
				sin6->sin6_flowinfo = 0;
				IN6_IPADDR_TO_V4MAPPED(
				    eager->tcp_ipha->ipha_src,
				    &sin6->sin6_addr);
			} else {
				ASSERT(eager->tcp_ip6h != NULL);
				sin6->sin6_flowinfo =
				    eager->tcp_ip6h->ip6_vcf &
				    ~IPV6_VERS_AND_FLOW_MASK;
				sin6->sin6_addr = eager->tcp_ip6h->ip6_src;
			}
			sin6->sin6_scope_id = 0;
			sin6->__sin6_src_id = 0;
		}

		putnext(rq, mp);
		return;
	default:
		mp = mi_tpi_err_ack_alloc(mp, TNOTSUPPORT, 0);
		if (mp != NULL)
			putnext(rq, mp);
		return;
	}
}

static int
tcp_getmyname(tcp_t *tcp, struct sockaddr *sa, uint_t *salenp)
{
	sin_t *sin = (sin_t *)sa;
	sin6_t *sin6 = (sin6_t *)sa;

	switch (tcp->tcp_family) {
	case AF_INET:
		ASSERT(tcp->tcp_ipversion == IPV4_VERSION);

		if (*salenp < sizeof (sin_t))
			return (EINVAL);

		*sin = sin_null;
		sin->sin_family = AF_INET;
		sin->sin_port = tcp->tcp_lport;
		sin->sin_addr.s_addr = tcp->tcp_ipha->ipha_src;
		break;

	case AF_INET6:
		if (*salenp < sizeof (sin6_t))
			return (EINVAL);

		*sin6 = sin6_null;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = tcp->tcp_lport;
		if (tcp->tcp_ipversion == IPV4_VERSION) {
			IN6_IPADDR_TO_V4MAPPED(tcp->tcp_ipha->ipha_src,
			    &sin6->sin6_addr);
		} else {
			sin6->sin6_addr = tcp->tcp_ip6h->ip6_src;
		}
		break;
	}

	return (0);
}

static int
i_tcp_getpeername(tcp_t *tcp, struct sockaddr *sa, uint_t *salenp)
{
	sin_t *sin = (sin_t *)sa;
	sin6_t *sin6 = (sin6_t *)sa;

	if (tcp->tcp_state < TCPS_SYN_RCVD)
		return (ENOTCONN);

	switch (tcp->tcp_family) {
	case AF_INET:
		ASSERT(tcp->tcp_ipversion == IPV4_VERSION);

		if (*salenp < sizeof (sin_t))
			return (EINVAL);

		*sin = sin_null;
		sin->sin_family = AF_INET;
		sin->sin_port = tcp->tcp_fport;
		IN6_V4MAPPED_TO_IPADDR(&tcp->tcp_remote_v6,
		    sin->sin_addr.s_addr);
		*salenp = sizeof (sin_t);
		break;

	case AF_INET6:
		if (*salenp < sizeof (sin6_t))
			return (EINVAL);

		*sin6 = sin6_null;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = tcp->tcp_fport;
		sin6->sin6_addr = tcp->tcp_remote_v6;
		if (tcp->tcp_ipversion == IPV6_VERSION) {
			sin6->sin6_flowinfo = tcp->tcp_ip6h->ip6_vcf &
			    ~IPV6_VERS_AND_FLOW_MASK;
		}
		*salenp = sizeof (sin6_t);
		break;
	}

	return (0);
}

/*
 * Handle special out-of-band ioctl requests (see PSARC/2008/265).
 */
static void
tcp_wput_cmdblk(queue_t *q, mblk_t *mp)
{
	void	*data;
	mblk_t	*datamp = mp->b_cont;
	tcp_t	*tcp = Q_TO_TCP(q);
	cmdblk_t *cmdp = (cmdblk_t *)mp->b_rptr;

	if (datamp == NULL || MBLKL(datamp) < cmdp->cb_len) {
		cmdp->cb_error = EPROTO;
		qreply(q, mp);
		return;
	}

	data = datamp->b_rptr;

	switch (cmdp->cb_cmd) {
	case TI_GETPEERNAME:
		cmdp->cb_error = i_tcp_getpeername(tcp, data, &cmdp->cb_len);
		break;
	case TI_GETMYNAME:
		cmdp->cb_error = tcp_getmyname(tcp, data, &cmdp->cb_len);
		break;
	default:
		cmdp->cb_error = EINVAL;
		break;
	}

	qreply(q, mp);
}

void
tcp_wput(queue_t *q, mblk_t *mp)
{
	conn_t	*connp = Q_TO_CONN(q);
	tcp_t	*tcp;
	void (*output_proc)();
	t_scalar_t type;
	uchar_t *rptr;
	struct iocblk	*iocp;
	size_t size;
	tcp_stack_t	*tcps = Q_TO_TCP(q)->tcp_tcps;

	ASSERT(connp->conn_ref >= 2);

	switch (DB_TYPE(mp)) {
	case M_DATA:
		tcp = connp->conn_tcp;
		ASSERT(tcp != NULL);

		size = msgdsize(mp);

		mutex_enter(&tcp->tcp_non_sq_lock);
		tcp->tcp_squeue_bytes += size;
		if (TCP_UNSENT_BYTES(tcp) > tcp->tcp_xmit_hiwater) {
			tcp_setqfull(tcp);
		}
		mutex_exit(&tcp->tcp_non_sq_lock);

		CONN_INC_REF(connp);
		SQUEUE_ENTER_ONE(connp->conn_sqp, mp, tcp_output, connp,
		    tcp_squeue_flag, SQTAG_TCP_OUTPUT);
		return;

	case M_CMD:
		tcp_wput_cmdblk(q, mp);
		return;

	case M_PROTO:
	case M_PCPROTO:
		/*
		 * if it is a snmp message, don't get behind the squeue
		 */
		tcp = connp->conn_tcp;
		rptr = mp->b_rptr;
		if ((mp->b_wptr - rptr) >= sizeof (t_scalar_t)) {
			type = ((union T_primitives *)rptr)->type;
		} else {
			if (tcp->tcp_debug) {
				(void) strlog(TCP_MOD_ID, 0, 1,
				    SL_ERROR|SL_TRACE,
				    "tcp_wput_proto, dropping one...");
			}
			freemsg(mp);
			return;
		}
		if (type == T_SVR4_OPTMGMT_REQ) {
			cred_t	*cr = DB_CREDDEF(mp, tcp->tcp_cred);
			if (snmpcom_req(q, mp, tcp_snmp_set, ip_snmp_get,
			    cr)) {
				/*
				 * This was a SNMP request
				 */
				return;
			} else {
				output_proc = tcp_wput_proto;
			}
		} else {
			output_proc = tcp_wput_proto;
		}
		break;
	case M_IOCTL:
		/*
		 * Most ioctls can be processed right away without going via
		 * squeues - process them right here. Those that do require
		 * squeue (currently TCP_IOC_DEFAULT_Q and _SIOCSOCKFALLBACK)
		 * are processed by tcp_wput_ioctl().
		 */
		iocp = (struct iocblk *)mp->b_rptr;
		tcp = connp->conn_tcp;

		switch (iocp->ioc_cmd) {
		case TCP_IOC_ABORT_CONN:
			tcp_ioctl_abort_conn(q, mp);
			return;
		case TI_GETPEERNAME:
		case TI_GETMYNAME:
			mi_copyin(q, mp, NULL,
			    SIZEOF_STRUCT(strbuf, iocp->ioc_flag));
			return;
		case ND_SET:
			/* nd_getset does the necessary checks */
		case ND_GET:
			if (!nd_getset(q, tcps->tcps_g_nd, mp)) {
				CALL_IP_WPUT(connp, q, mp);
				return;
			}
			qreply(q, mp);
			return;
		case TCP_IOC_DEFAULT_Q:
			/*
			 * Wants to be the default wq. Check the credentials
			 * first, the rest is executed via squeue.
			 */
			if (secpolicy_ip_config(iocp->ioc_cr, B_FALSE) != 0) {
				iocp->ioc_error = EPERM;
				iocp->ioc_count = 0;
				mp->b_datap->db_type = M_IOCACK;
				qreply(q, mp);
				return;
			}
			output_proc = tcp_wput_ioctl;
			break;
		default:
			output_proc = tcp_wput_ioctl;
			break;
		}
		break;
	default:
		output_proc = tcp_wput_nondata;
		break;
	}

	CONN_INC_REF(connp);
	SQUEUE_ENTER_ONE(connp->conn_sqp, mp, output_proc, connp,
	    tcp_squeue_flag, SQTAG_TCP_WPUT_OTHER);
}

/*
 * Initial STREAMS write side put() procedure for sockets. It tries to
 * handle the T_CAPABILITY_REQ which sockfs sends down while setting
 * up the socket without using the squeue. Non T_CAPABILITY_REQ messages
 * are handled by tcp_wput() as usual.
 *
 * All further messages will also be handled by tcp_wput() because we cannot
 * be sure that the above short cut is safe later.
 */
static void
tcp_wput_sock(queue_t *wq, mblk_t *mp)
{
	conn_t			*connp = Q_TO_CONN(wq);
	tcp_t			*tcp = connp->conn_tcp;
	struct T_capability_req	*car = (struct T_capability_req *)mp->b_rptr;

	ASSERT(wq->q_qinfo == &tcp_sock_winit);
	wq->q_qinfo = &tcp_winit;

	ASSERT(IPCL_IS_TCP(connp));
	ASSERT(TCP_IS_SOCKET(tcp));

	if (DB_TYPE(mp) == M_PCPROTO &&
	    MBLKL(mp) == sizeof (struct T_capability_req) &&
	    car->PRIM_type == T_CAPABILITY_REQ) {
		tcp_capability_req(tcp, mp);
		return;
	}

	tcp_wput(wq, mp);
}

/* ARGSUSED */
static void
tcp_wput_fallback(queue_t *wq, mblk_t *mp)
{
#ifdef DEBUG
	cmn_err(CE_CONT, "tcp_wput_fallback: Message during fallback \n");
#endif
	freemsg(mp);
}

static boolean_t
tcp_zcopy_check(tcp_t *tcp)
{
	conn_t	*connp = tcp->tcp_connp;
	ire_t	*ire;
	boolean_t	zc_enabled = B_FALSE;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	if (do_tcpzcopy == 2)
		zc_enabled = B_TRUE;
	else if (tcp->tcp_ipversion == IPV4_VERSION &&
	    IPCL_IS_CONNECTED(connp) &&
	    (connp->conn_flags & IPCL_CHECK_POLICY) == 0 &&
	    connp->conn_dontroute == 0 &&
	    !connp->conn_nexthop_set &&
	    connp->conn_outgoing_ill == NULL &&
	    do_tcpzcopy == 1) {
		/*
		 * the checks above  closely resemble the fast path checks
		 * in tcp_send_data().
		 */
		mutex_enter(&connp->conn_lock);
		ire = connp->conn_ire_cache;
		ASSERT(!(connp->conn_state_flags & CONN_INCIPIENT));
		if (ire != NULL && !(ire->ire_marks & IRE_MARK_CONDEMNED)) {
			IRE_REFHOLD(ire);
			if (ire->ire_stq != NULL) {
				ill_t	*ill = (ill_t *)ire->ire_stq->q_ptr;

				zc_enabled = ill && (ill->ill_capabilities &
				    ILL_CAPAB_ZEROCOPY) &&
				    (ill->ill_zerocopy_capab->
				    ill_zerocopy_flags != 0);
			}
			IRE_REFRELE(ire);
		}
		mutex_exit(&connp->conn_lock);
	}
	tcp->tcp_snd_zcopy_on = zc_enabled;
	if (!TCP_IS_DETACHED(tcp)) {
		if (zc_enabled) {
			(void) proto_set_tx_copyopt(tcp->tcp_rq, connp,
			    ZCVMSAFE);
			TCP_STAT(tcps, tcp_zcopy_on);
		} else {
			(void) proto_set_tx_copyopt(tcp->tcp_rq, connp,
			    ZCVMUNSAFE);
			TCP_STAT(tcps, tcp_zcopy_off);
		}
	}
	return (zc_enabled);
}

static mblk_t *
tcp_zcopy_disable(tcp_t *tcp, mblk_t *bp)
{
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	if (do_tcpzcopy == 2)
		return (bp);
	else if (tcp->tcp_snd_zcopy_on) {
		tcp->tcp_snd_zcopy_on = B_FALSE;
		if (!TCP_IS_DETACHED(tcp)) {
			(void) proto_set_tx_copyopt(tcp->tcp_rq, tcp->tcp_connp,
			    ZCVMUNSAFE);
			TCP_STAT(tcps, tcp_zcopy_disable);
		}
	}
	return (tcp_zcopy_backoff(tcp, bp, 0));
}

/*
 * Backoff from a zero-copy mblk by copying data to a new mblk and freeing
 * the original desballoca'ed segmapped mblk.
 */
static mblk_t *
tcp_zcopy_backoff(tcp_t *tcp, mblk_t *bp, int fix_xmitlist)
{
	mblk_t *head, *tail, *nbp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	if (IS_VMLOANED_MBLK(bp)) {
		TCP_STAT(tcps, tcp_zcopy_backoff);
		if ((head = copyb(bp)) == NULL) {
			/* fail to backoff; leave it for the next backoff */
			tcp->tcp_xmit_zc_clean = B_FALSE;
			return (bp);
		}
		if (bp->b_datap->db_struioflag & STRUIO_ZCNOTIFY) {
			if (fix_xmitlist)
				tcp_zcopy_notify(tcp);
			else
				head->b_datap->db_struioflag |= STRUIO_ZCNOTIFY;
		}
		nbp = bp->b_cont;
		if (fix_xmitlist) {
			head->b_prev = bp->b_prev;
			head->b_next = bp->b_next;
			if (tcp->tcp_xmit_tail == bp)
				tcp->tcp_xmit_tail = head;
		}
		bp->b_next = NULL;
		bp->b_prev = NULL;
		freeb(bp);
	} else {
		head = bp;
		nbp = bp->b_cont;
	}
	tail = head;
	while (nbp) {
		if (IS_VMLOANED_MBLK(nbp)) {
			TCP_STAT(tcps, tcp_zcopy_backoff);
			if ((tail->b_cont = copyb(nbp)) == NULL) {
				tcp->tcp_xmit_zc_clean = B_FALSE;
				tail->b_cont = nbp;
				return (head);
			}
			tail = tail->b_cont;
			if (nbp->b_datap->db_struioflag & STRUIO_ZCNOTIFY) {
				if (fix_xmitlist)
					tcp_zcopy_notify(tcp);
				else
					tail->b_datap->db_struioflag |=
					    STRUIO_ZCNOTIFY;
			}
			bp = nbp;
			nbp = nbp->b_cont;
			if (fix_xmitlist) {
				tail->b_prev = bp->b_prev;
				tail->b_next = bp->b_next;
				if (tcp->tcp_xmit_tail == bp)
					tcp->tcp_xmit_tail = tail;
			}
			bp->b_next = NULL;
			bp->b_prev = NULL;
			freeb(bp);
		} else {
			tail->b_cont = nbp;
			tail = nbp;
			nbp = nbp->b_cont;
		}
	}
	if (fix_xmitlist) {
		tcp->tcp_xmit_last = tail;
		tcp->tcp_xmit_zc_clean = B_TRUE;
	}
	return (head);
}

static void
tcp_zcopy_notify(tcp_t *tcp)
{
	struct stdata	*stp;
	conn_t *connp;

	if (tcp->tcp_detached)
		return;
	connp = tcp->tcp_connp;
	if (IPCL_IS_NONSTR(connp)) {
		(*connp->conn_upcalls->su_zcopy_notify)
		    (connp->conn_upper_handle);
		return;
	}
	stp = STREAM(tcp->tcp_rq);
	mutex_enter(&stp->sd_lock);
	stp->sd_flag |= STZCNOTIFY;
	cv_broadcast(&stp->sd_zcopy_wait);
	mutex_exit(&stp->sd_lock);
}

static boolean_t
tcp_send_find_ire(tcp_t *tcp, ipaddr_t *dst, ire_t **irep)
{
	ire_t	*ire;
	conn_t	*connp = tcp->tcp_connp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	ip_stack_t	*ipst = tcps->tcps_netstack->netstack_ip;

	mutex_enter(&connp->conn_lock);
	ire = connp->conn_ire_cache;
	ASSERT(!(connp->conn_state_flags & CONN_INCIPIENT));

	if ((ire != NULL) &&
	    (((dst != NULL) && (ire->ire_addr == *dst)) || ((dst == NULL) &&
	    IN6_ARE_ADDR_EQUAL(&ire->ire_addr_v6, &tcp->tcp_ip6h->ip6_dst))) &&
	    !(ire->ire_marks & IRE_MARK_CONDEMNED)) {
		IRE_REFHOLD(ire);
		mutex_exit(&connp->conn_lock);
	} else {
		boolean_t cached = B_FALSE;
		ts_label_t *tsl;

		/* force a recheck later on */
		tcp->tcp_ire_ill_check_done = B_FALSE;

		TCP_DBGSTAT(tcps, tcp_ire_null1);
		connp->conn_ire_cache = NULL;
		mutex_exit(&connp->conn_lock);

		if (ire != NULL)
			IRE_REFRELE_NOTR(ire);

		tsl = crgetlabel(CONN_CRED(connp));
		ire = (dst ?
		    ire_cache_lookup(*dst, connp->conn_zoneid, tsl, ipst) :
		    ire_cache_lookup_v6(&tcp->tcp_ip6h->ip6_dst,
		    connp->conn_zoneid, tsl, ipst));

		if (ire == NULL) {
			TCP_STAT(tcps, tcp_ire_null);
			return (B_FALSE);
		}

		IRE_REFHOLD_NOTR(ire);

		mutex_enter(&connp->conn_lock);
		if (CONN_CACHE_IRE(connp)) {
			rw_enter(&ire->ire_bucket->irb_lock, RW_READER);
			if (!(ire->ire_marks & IRE_MARK_CONDEMNED)) {
				TCP_CHECK_IREINFO(tcp, ire);
				connp->conn_ire_cache = ire;
				cached = B_TRUE;
			}
			rw_exit(&ire->ire_bucket->irb_lock);
		}
		mutex_exit(&connp->conn_lock);

		/*
		 * We can continue to use the ire but since it was
		 * not cached, we should drop the extra reference.
		 */
		if (!cached)
			IRE_REFRELE_NOTR(ire);

		/*
		 * Rampart note: no need to select a new label here, since
		 * labels are not allowed to change during the life of a TCP
		 * connection.
		 */
	}

	*irep = ire;

	return (B_TRUE);
}

/*
 * Called from tcp_send() or tcp_send_data() to find workable IRE.
 *
 * 0 = success;
 * 1 = failed to find ire and ill.
 */
static boolean_t
tcp_send_find_ire_ill(tcp_t *tcp, mblk_t *mp, ire_t **irep, ill_t **illp)
{
	ipha_t		*ipha;
	ipaddr_t	dst;
	ire_t		*ire;
	ill_t		*ill;
	mblk_t		*ire_fp_mp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	if (mp != NULL)
		ipha = (ipha_t *)mp->b_rptr;
	else
		ipha = tcp->tcp_ipha;
	dst = ipha->ipha_dst;

	if (!tcp_send_find_ire(tcp, &dst, &ire))
		return (B_FALSE);

	if ((ire->ire_flags & RTF_MULTIRT) ||
	    (ire->ire_stq == NULL) ||
	    (ire->ire_nce == NULL) ||
	    ((ire_fp_mp = ire->ire_nce->nce_fp_mp) == NULL) ||
	    ((mp != NULL) && (ire->ire_max_frag < ntohs(ipha->ipha_length) ||
	    MBLKL(ire_fp_mp) > MBLKHEAD(mp)))) {
		TCP_STAT(tcps, tcp_ip_ire_send);
		IRE_REFRELE(ire);
		return (B_FALSE);
	}

	ill = ire_to_ill(ire);
	ASSERT(ill != NULL);

	if (!tcp->tcp_ire_ill_check_done) {
		tcp_ire_ill_check(tcp, ire, ill, B_TRUE);
		tcp->tcp_ire_ill_check_done = B_TRUE;
	}

	*irep = ire;
	*illp = ill;

	return (B_TRUE);
}

static void
tcp_send_data(tcp_t *tcp, queue_t *q, mblk_t *mp)
{
	ipha_t		*ipha;
	ipaddr_t	src;
	ipaddr_t	dst;
	uint32_t	cksum;
	ire_t		*ire;
	uint16_t	*up;
	ill_t		*ill;
	conn_t		*connp = tcp->tcp_connp;
	uint32_t	hcksum_txflags = 0;
	mblk_t		*ire_fp_mp;
	uint_t		ire_fp_mp_len;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	ip_stack_t	*ipst = tcps->tcps_netstack->netstack_ip;

	ASSERT(DB_TYPE(mp) == M_DATA);

	if (is_system_labeled() && DB_CRED(mp) == NULL)
		mblk_setcred(mp, CONN_CRED(tcp->tcp_connp));

	ipha = (ipha_t *)mp->b_rptr;
	src = ipha->ipha_src;
	dst = ipha->ipha_dst;

	ASSERT(q != NULL);
	DTRACE_PROBE2(tcp__trace__send, mblk_t *, mp, tcp_t *, tcp);

	/*
	 * Drop off fast path for IPv6 and also if options are present or
	 * we need to resolve a TS label.
	 */
	if (tcp->tcp_ipversion != IPV4_VERSION ||
	    !IPCL_IS_CONNECTED(connp) ||
	    !CONN_IS_LSO_MD_FASTPATH(connp) ||
	    (connp->conn_flags & IPCL_CHECK_POLICY) != 0 ||
	    !connp->conn_ulp_labeled ||
	    ipha->ipha_ident == IP_HDR_INCLUDED ||
	    ipha->ipha_version_and_hdr_length != IP_SIMPLE_HDR_VERSION ||
	    IPP_ENABLED(IPP_LOCAL_OUT, ipst)) {
		if (tcp->tcp_snd_zcopy_aware)
			mp = tcp_zcopy_disable(tcp, mp);
		TCP_STAT(tcps, tcp_ip_send);
		CALL_IP_WPUT(connp, q, mp);
		return;
	}

	if (!tcp_send_find_ire_ill(tcp, mp, &ire, &ill)) {
		if (tcp->tcp_snd_zcopy_aware)
			mp = tcp_zcopy_backoff(tcp, mp, 0);
		CALL_IP_WPUT(connp, q, mp);
		return;
	}
	ire_fp_mp = ire->ire_nce->nce_fp_mp;
	ire_fp_mp_len = MBLKL(ire_fp_mp);

	ASSERT(ipha->ipha_ident == 0 || ipha->ipha_ident == IP_HDR_INCLUDED);
	ipha->ipha_ident = (uint16_t)atomic_add_32_nv(&ire->ire_ident, 1);
#ifndef _BIG_ENDIAN
	ipha->ipha_ident = (ipha->ipha_ident << 8) | (ipha->ipha_ident >> 8);
#endif

	/*
	 * Check to see if we need to re-enable LSO/MDT for this connection
	 * because it was previously disabled due to changes in the ill;
	 * note that by doing it here, this re-enabling only applies when
	 * the packet is not dispatched through CALL_IP_WPUT().
	 *
	 * That means for IPv4, it is worth re-enabling LSO/MDT for the fastpath
	 * case, since that's how we ended up here.  For IPv6, we do the
	 * re-enabling work in ip_xmit_v6(), albeit indirectly via squeue.
	 */
	if (connp->conn_lso_ok && !tcp->tcp_lso && ILL_LSO_TCP_USABLE(ill)) {
		/*
		 * Restore LSO for this connection, so that next time around
		 * it is eligible to go through tcp_lsosend() path again.
		 */
		TCP_STAT(tcps, tcp_lso_enabled);
		tcp->tcp_lso = B_TRUE;
		ip1dbg(("tcp_send_data: reenabling LSO for connp %p on "
		    "interface %s\n", (void *)connp, ill->ill_name));
	} else if (connp->conn_mdt_ok && !tcp->tcp_mdt && ILL_MDT_USABLE(ill)) {
		/*
		 * Restore MDT for this connection, so that next time around
		 * it is eligible to go through tcp_multisend() path again.
		 */
		TCP_STAT(tcps, tcp_mdt_conn_resumed1);
		tcp->tcp_mdt = B_TRUE;
		ip1dbg(("tcp_send_data: reenabling MDT for connp %p on "
		    "interface %s\n", (void *)connp, ill->ill_name));
	}

	if (tcp->tcp_snd_zcopy_aware) {
		if ((ill->ill_capabilities & ILL_CAPAB_ZEROCOPY) == 0 ||
		    (ill->ill_zerocopy_capab->ill_zerocopy_flags == 0))
			mp = tcp_zcopy_disable(tcp, mp);
		/*
		 * we shouldn't need to reset ipha as the mp containing
		 * ipha should never be a zero-copy mp.
		 */
	}

	if (ILL_HCKSUM_CAPABLE(ill) && dohwcksum) {
		ASSERT(ill->ill_hcksum_capab != NULL);
		hcksum_txflags = ill->ill_hcksum_capab->ill_hcksum_txflags;
	}

	/* pseudo-header checksum (do it in parts for IP header checksum) */
	cksum = (dst >> 16) + (dst & 0xFFFF) + (src >> 16) + (src & 0xFFFF);

	ASSERT(ipha->ipha_version_and_hdr_length == IP_SIMPLE_HDR_VERSION);
	up = IPH_TCPH_CHECKSUMP(ipha, IP_SIMPLE_HDR_LENGTH);

	IP_CKSUM_XMIT_FAST(ire->ire_ipversion, hcksum_txflags, mp, ipha, up,
	    IPPROTO_TCP, IP_SIMPLE_HDR_LENGTH, ntohs(ipha->ipha_length), cksum);

	/* Software checksum? */
	if (DB_CKSUMFLAGS(mp) == 0) {
		TCP_STAT(tcps, tcp_out_sw_cksum);
		TCP_STAT_UPDATE(tcps, tcp_out_sw_cksum_bytes,
		    ntohs(ipha->ipha_length) - IP_SIMPLE_HDR_LENGTH);
	}

	/* Calculate IP header checksum if hardware isn't capable */
	if (!(DB_CKSUMFLAGS(mp) & HCK_IPV4_HDRCKSUM)) {
		IP_HDR_CKSUM(ipha, cksum, ((uint32_t *)ipha)[0],
		    ((uint16_t *)ipha)[4]);
	}

	ASSERT(DB_TYPE(ire_fp_mp) == M_DATA);
	mp->b_rptr = (uchar_t *)ipha - ire_fp_mp_len;
	bcopy(ire_fp_mp->b_rptr, mp->b_rptr, ire_fp_mp_len);

	UPDATE_OB_PKT_COUNT(ire);
	ire->ire_last_used_time = lbolt;

	BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCOutRequests);
	BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCOutTransmits);
	UPDATE_MIB(ill->ill_ip_mib, ipIfStatsHCOutOctets,
	    ntohs(ipha->ipha_length));

	DTRACE_PROBE4(ip4__physical__out__start,
	    ill_t *, NULL, ill_t *, ill, ipha_t *, ipha, mblk_t *, mp);
	FW_HOOKS(ipst->ips_ip4_physical_out_event,
	    ipst->ips_ipv4firewall_physical_out,
	    NULL, ill, ipha, mp, mp, 0, ipst);
	DTRACE_PROBE1(ip4__physical__out__end, mblk_t *, mp);
	DTRACE_IP_FASTPATH(mp, ipha, ill, ipha, NULL);

	if (mp != NULL) {
		if (ipst->ips_ipobs_enabled) {
			zoneid_t szone;

			szone = ip_get_zoneid_v4(ipha->ipha_src, mp,
			    ipst, ALL_ZONES);
			ipobs_hook(mp, IPOBS_HOOK_OUTBOUND, szone,
			    ALL_ZONES, ill, IPV4_VERSION, ire_fp_mp_len, ipst);
		}

		ILL_SEND_TX(ill, ire, connp, mp, 0);
	}

	IRE_REFRELE(ire);
}

/*
 * This handles the case when the receiver has shrunk its win. Per RFC 1122
 * if the receiver shrinks the window, i.e. moves the right window to the
 * left, the we should not send new data, but should retransmit normally the
 * old unacked data between suna and suna + swnd. We might has sent data
 * that is now outside the new window, pretend that we didn't send  it.
 */
static void
tcp_process_shrunk_swnd(tcp_t *tcp, uint32_t shrunk_count)
{
	uint32_t	snxt = tcp->tcp_snxt;
	mblk_t		*xmit_tail;
	int32_t		offset;

	ASSERT(shrunk_count > 0);

	/* Pretend we didn't send the data outside the window */
	snxt -= shrunk_count;

	/* Get the mblk and the offset in it per the shrunk window */
	xmit_tail = tcp_get_seg_mp(tcp, snxt, &offset);

	ASSERT(xmit_tail != NULL);

	/* Reset all the values per the now shrunk window */
	tcp->tcp_snxt = snxt;
	tcp->tcp_xmit_tail = xmit_tail;
	tcp->tcp_xmit_tail_unsent = xmit_tail->b_wptr - xmit_tail->b_rptr -
	    offset;
	tcp->tcp_unsent += shrunk_count;

	if (tcp->tcp_suna == tcp->tcp_snxt && tcp->tcp_swnd == 0)
		/*
		 * Make sure the timer is running so that we will probe a zero
		 * window.
		 */
		TCP_TIMER_RESTART(tcp, tcp->tcp_rto);
}


/*
 * The TCP normal data output path.
 * NOTE: the logic of the fast path is duplicated from this function.
 */
static void
tcp_wput_data(tcp_t *tcp, mblk_t *mp, boolean_t urgent)
{
	int		len;
	mblk_t		*local_time;
	mblk_t		*mp1;
	uint32_t	snxt;
	int		tail_unsent;
	int		tcpstate;
	int		usable = 0;
	mblk_t		*xmit_tail;
	queue_t		*q = tcp->tcp_wq;
	int32_t		mss;
	int32_t		num_sack_blk = 0;
	int32_t		tcp_hdr_len;
	int32_t		tcp_tcp_hdr_len;
	int		mdt_thres;
	int		rc;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	ip_stack_t	*ipst;

	tcpstate = tcp->tcp_state;
	if (mp == NULL) {
		/*
		 * tcp_wput_data() with NULL mp should only be called when
		 * there is unsent data.
		 */
		ASSERT(tcp->tcp_unsent > 0);
		/* Really tacky... but we need this for detached closes. */
		len = tcp->tcp_unsent;
		goto data_null;
	}

#if CCS_STATS
	wrw_stats.tot.count++;
	wrw_stats.tot.bytes += msgdsize(mp);
#endif
	ASSERT(mp->b_datap->db_type == M_DATA);
	/*
	 * Don't allow data after T_ORDREL_REQ or T_DISCON_REQ,
	 * or before a connection attempt has begun.
	 */
	if (tcpstate < TCPS_SYN_SENT || tcpstate > TCPS_CLOSE_WAIT ||
	    (tcp->tcp_valid_bits & TCP_FSS_VALID) != 0) {
		if ((tcp->tcp_valid_bits & TCP_FSS_VALID) != 0) {
#ifdef DEBUG
			cmn_err(CE_WARN,
			    "tcp_wput_data: data after ordrel, %s",
			    tcp_display(tcp, NULL,
			    DISP_ADDR_AND_PORT));
#else
			if (tcp->tcp_debug) {
				(void) strlog(TCP_MOD_ID, 0, 1,
				    SL_TRACE|SL_ERROR,
				    "tcp_wput_data: data after ordrel, %s\n",
				    tcp_display(tcp, NULL,
				    DISP_ADDR_AND_PORT));
			}
#endif /* DEBUG */
		}
		if (tcp->tcp_snd_zcopy_aware &&
		    (mp->b_datap->db_struioflag & STRUIO_ZCNOTIFY) != 0)
			tcp_zcopy_notify(tcp);
		freemsg(mp);
		mutex_enter(&tcp->tcp_non_sq_lock);
		if (tcp->tcp_flow_stopped &&
		    TCP_UNSENT_BYTES(tcp) <= tcp->tcp_xmit_lowater) {
			tcp_clrqfull(tcp);
		}
		mutex_exit(&tcp->tcp_non_sq_lock);
		return;
	}

	/* Strip empties */
	for (;;) {
		ASSERT((uintptr_t)(mp->b_wptr - mp->b_rptr) <=
		    (uintptr_t)INT_MAX);
		len = (int)(mp->b_wptr - mp->b_rptr);
		if (len > 0)
			break;
		mp1 = mp;
		mp = mp->b_cont;
		freeb(mp1);
		if (!mp) {
			return;
		}
	}

	/* If we are the first on the list ... */
	if (tcp->tcp_xmit_head == NULL) {
		tcp->tcp_xmit_head = mp;
		tcp->tcp_xmit_tail = mp;
		tcp->tcp_xmit_tail_unsent = len;
	} else {
		/* If tiny tx and room in txq tail, pullup to save mblks. */
		struct datab *dp;

		mp1 = tcp->tcp_xmit_last;
		if (len < tcp_tx_pull_len &&
		    (dp = mp1->b_datap)->db_ref == 1 &&
		    dp->db_lim - mp1->b_wptr >= len) {
			ASSERT(len > 0);
			ASSERT(!mp1->b_cont);
			if (len == 1) {
				*mp1->b_wptr++ = *mp->b_rptr;
			} else {
				bcopy(mp->b_rptr, mp1->b_wptr, len);
				mp1->b_wptr += len;
			}
			if (mp1 == tcp->tcp_xmit_tail)
				tcp->tcp_xmit_tail_unsent += len;
			mp1->b_cont = mp->b_cont;
			if (tcp->tcp_snd_zcopy_aware &&
			    (mp->b_datap->db_struioflag & STRUIO_ZCNOTIFY))
				mp1->b_datap->db_struioflag |= STRUIO_ZCNOTIFY;
			freeb(mp);
			mp = mp1;
		} else {
			tcp->tcp_xmit_last->b_cont = mp;
		}
		len += tcp->tcp_unsent;
	}

	/* Tack on however many more positive length mblks we have */
	if ((mp1 = mp->b_cont) != NULL) {
		do {
			int tlen;
			ASSERT((uintptr_t)(mp1->b_wptr - mp1->b_rptr) <=
			    (uintptr_t)INT_MAX);
			tlen = (int)(mp1->b_wptr - mp1->b_rptr);
			if (tlen <= 0) {
				mp->b_cont = mp1->b_cont;
				freeb(mp1);
			} else {
				len += tlen;
				mp = mp1;
			}
		} while ((mp1 = mp->b_cont) != NULL);
	}
	tcp->tcp_xmit_last = mp;
	tcp->tcp_unsent = len;

	if (urgent)
		usable = 1;

data_null:
	snxt = tcp->tcp_snxt;
	xmit_tail = tcp->tcp_xmit_tail;
	tail_unsent = tcp->tcp_xmit_tail_unsent;

	/*
	 * Note that tcp_mss has been adjusted to take into account the
	 * timestamp option if applicable.  Because SACK options do not
	 * appear in every TCP segments and they are of variable lengths,
	 * they cannot be included in tcp_mss.  Thus we need to calculate
	 * the actual segment length when we need to send a segment which
	 * includes SACK options.
	 */
	if (tcp->tcp_snd_sack_ok && tcp->tcp_num_sack_blk > 0) {
		int32_t	opt_len;

		num_sack_blk = MIN(tcp->tcp_max_sack_blk,
		    tcp->tcp_num_sack_blk);
		opt_len = num_sack_blk * sizeof (sack_blk_t) + TCPOPT_NOP_LEN *
		    2 + TCPOPT_HEADER_LEN;
		mss = tcp->tcp_mss - opt_len;
		tcp_hdr_len = tcp->tcp_hdr_len + opt_len;
		tcp_tcp_hdr_len = tcp->tcp_tcp_hdr_len + opt_len;
	} else {
		mss = tcp->tcp_mss;
		tcp_hdr_len = tcp->tcp_hdr_len;
		tcp_tcp_hdr_len = tcp->tcp_tcp_hdr_len;
	}

	if ((tcp->tcp_suna == snxt) && !tcp->tcp_localnet &&
	    (TICK_TO_MSEC(lbolt - tcp->tcp_last_recv_time) >= tcp->tcp_rto)) {
		SET_TCP_INIT_CWND(tcp, mss, tcps->tcps_slow_start_after_idle);
	}
	if (tcpstate == TCPS_SYN_RCVD) {
		/*
		 * The three-way connection establishment handshake is not
		 * complete yet. We want to queue the data for transmission
		 * after entering ESTABLISHED state (RFC793). A jump to
		 * "done" label effectively leaves data on the queue.
		 */
		goto done;
	} else {
		int usable_r;

		/*
		 * In the special case when cwnd is zero, which can only
		 * happen if the connection is ECN capable, return now.
		 * New segments is sent using tcp_timer().  The timer
		 * is set in tcp_rput_data().
		 */
		if (tcp->tcp_cwnd == 0) {
			/*
			 * Note that tcp_cwnd is 0 before 3-way handshake is
			 * finished.
			 */
			ASSERT(tcp->tcp_ecn_ok ||
			    tcp->tcp_state < TCPS_ESTABLISHED);
			return;
		}

		/* NOTE: trouble if xmitting while SYN not acked? */
		usable_r = snxt - tcp->tcp_suna;
		usable_r = tcp->tcp_swnd - usable_r;

		/*
		 * Check if the receiver has shrunk the window.  If
		 * tcp_wput_data() with NULL mp is called, tcp_fin_sent
		 * cannot be set as there is unsent data, so FIN cannot
		 * be sent out.  Otherwise, we need to take into account
		 * of FIN as it consumes an "invisible" sequence number.
		 */
		ASSERT(tcp->tcp_fin_sent == 0);
		if (usable_r < 0) {
			/*
			 * The receiver has shrunk the window and we have sent
			 * -usable_r date beyond the window, re-adjust.
			 *
			 * If TCP window scaling is enabled, there can be
			 * round down error as the advertised receive window
			 * is actually right shifted n bits.  This means that
			 * the lower n bits info is wiped out.  It will look
			 * like the window is shrunk.  Do a check here to
			 * see if the shrunk amount is actually within the
			 * error in window calculation.  If it is, just
			 * return.  Note that this check is inside the
			 * shrunk window check.  This makes sure that even
			 * though tcp_process_shrunk_swnd() is not called,
			 * we will stop further processing.
			 */
			if ((-usable_r >> tcp->tcp_snd_ws) > 0) {
				tcp_process_shrunk_swnd(tcp, -usable_r);
			}
			return;
		}

		/* usable = MIN(swnd, cwnd) - unacked_bytes */
		if (tcp->tcp_swnd > tcp->tcp_cwnd)
			usable_r -= tcp->tcp_swnd - tcp->tcp_cwnd;

		/* usable = MIN(usable, unsent) */
		if (usable_r > len)
			usable_r = len;

		/* usable = MAX(usable, {1 for urgent, 0 for data}) */
		if (usable_r > 0) {
			usable = usable_r;
		} else {
			/* Bypass all other unnecessary processing. */
			goto done;
		}
	}

	local_time = (mblk_t *)lbolt;

	/*
	 * "Our" Nagle Algorithm.  This is not the same as in the old
	 * BSD.  This is more in line with the true intent of Nagle.
	 *
	 * The conditions are:
	 * 1. The amount of unsent data (or amount of data which can be
	 *    sent, whichever is smaller) is less than Nagle limit.
	 * 2. The last sent size is also less than Nagle limit.
	 * 3. There is unack'ed data.
	 * 4. Urgent pointer is not set.  Send urgent data ignoring the
	 *    Nagle algorithm.  This reduces the probability that urgent
	 *    bytes get "merged" together.
	 * 5. The app has not closed the connection.  This eliminates the
	 *    wait time of the receiving side waiting for the last piece of
	 *    (small) data.
	 *
	 * If all are satisified, exit without sending anything.  Note
	 * that Nagle limit can be smaller than 1 MSS.  Nagle limit is
	 * the smaller of 1 MSS and global tcp_naglim_def (default to be
	 * 4095).
	 */
	if (usable < (int)tcp->tcp_naglim &&
	    tcp->tcp_naglim > tcp->tcp_last_sent_len &&
	    snxt != tcp->tcp_suna &&
	    !(tcp->tcp_valid_bits & TCP_URG_VALID) &&
	    !(tcp->tcp_valid_bits & TCP_FSS_VALID)) {
		goto done;
	}

	if (tcp->tcp_cork) {
		/*
		 * if the tcp->tcp_cork option is set, then we have to force
		 * TCP not to send partial segment (smaller than MSS bytes).
		 * We are calculating the usable now based on full mss and
		 * will save the rest of remaining data for later.
		 */
		if (usable < mss)
			goto done;
		usable = (usable / mss) * mss;
	}

	/* Update the latest receive window size in TCP header. */
	U32_TO_ABE16(tcp->tcp_rwnd >> tcp->tcp_rcv_ws,
	    tcp->tcp_tcph->th_win);

	/*
	 * Determine if it's worthwhile to attempt LSO or MDT, based on:
	 *
	 * 1. Simple TCP/IP{v4,v6} (no options).
	 * 2. IPSEC/IPQoS processing is not needed for the TCP connection.
	 * 3. If the TCP connection is in ESTABLISHED state.
	 * 4. The TCP is not detached.
	 *
	 * If any of the above conditions have changed during the
	 * connection, stop using LSO/MDT and restore the stream head
	 * parameters accordingly.
	 */
	ipst = tcps->tcps_netstack->netstack_ip;

	if ((tcp->tcp_lso || tcp->tcp_mdt) &&
	    ((tcp->tcp_ipversion == IPV4_VERSION &&
	    tcp->tcp_ip_hdr_len != IP_SIMPLE_HDR_LENGTH) ||
	    (tcp->tcp_ipversion == IPV6_VERSION &&
	    tcp->tcp_ip_hdr_len != IPV6_HDR_LEN) ||
	    tcp->tcp_state != TCPS_ESTABLISHED ||
	    TCP_IS_DETACHED(tcp) || !CONN_IS_LSO_MD_FASTPATH(tcp->tcp_connp) ||
	    CONN_IPSEC_OUT_ENCAPSULATED(tcp->tcp_connp) ||
	    IPP_ENABLED(IPP_LOCAL_OUT, ipst))) {
		if (tcp->tcp_lso) {
			tcp->tcp_connp->conn_lso_ok = B_FALSE;
			tcp->tcp_lso = B_FALSE;
		} else {
			tcp->tcp_connp->conn_mdt_ok = B_FALSE;
			tcp->tcp_mdt = B_FALSE;
		}

		/* Anything other than detached is considered pathological */
		if (!TCP_IS_DETACHED(tcp)) {
			if (tcp->tcp_lso)
				TCP_STAT(tcps, tcp_lso_disabled);
			else
				TCP_STAT(tcps, tcp_mdt_conn_halted1);
			(void) tcp_maxpsz_set(tcp, B_TRUE);
		}
	}

	/* Use MDT if sendable amount is greater than the threshold */
	if (tcp->tcp_mdt &&
	    (mdt_thres = mss << tcp_mdt_smss_threshold, usable > mdt_thres) &&
	    (tail_unsent > mdt_thres || (xmit_tail->b_cont != NULL &&
	    MBLKL(xmit_tail->b_cont) > mdt_thres)) &&
	    (tcp->tcp_valid_bits == 0 ||
	    tcp->tcp_valid_bits == TCP_FSS_VALID)) {
		ASSERT(tcp->tcp_connp->conn_mdt_ok);
		rc = tcp_multisend(q, tcp, mss, tcp_hdr_len, tcp_tcp_hdr_len,
		    num_sack_blk, &usable, &snxt, &tail_unsent, &xmit_tail,
		    local_time, mdt_thres);
	} else {
		rc = tcp_send(q, tcp, mss, tcp_hdr_len, tcp_tcp_hdr_len,
		    num_sack_blk, &usable, &snxt, &tail_unsent, &xmit_tail,
		    local_time, INT_MAX);
	}

	/* Pretend that all we were trying to send really got sent */
	if (rc < 0 && tail_unsent < 0) {
		do {
			xmit_tail = xmit_tail->b_cont;
			xmit_tail->b_prev = local_time;
			ASSERT((uintptr_t)(xmit_tail->b_wptr -
			    xmit_tail->b_rptr) <= (uintptr_t)INT_MAX);
			tail_unsent += (int)(xmit_tail->b_wptr -
			    xmit_tail->b_rptr);
		} while (tail_unsent < 0);
	}
done:;
	tcp->tcp_xmit_tail = xmit_tail;
	tcp->tcp_xmit_tail_unsent = tail_unsent;
	len = tcp->tcp_snxt - snxt;
	if (len) {
		/*
		 * If new data was sent, need to update the notsack
		 * list, which is, afterall, data blocks that have
		 * not been sack'ed by the receiver.  New data is
		 * not sack'ed.
		 */
		if (tcp->tcp_snd_sack_ok && tcp->tcp_notsack_list != NULL) {
			/* len is a negative value. */
			tcp->tcp_pipe -= len;
			tcp_notsack_update(&(tcp->tcp_notsack_list),
			    tcp->tcp_snxt, snxt,
			    &(tcp->tcp_num_notsack_blk),
			    &(tcp->tcp_cnt_notsack_list));
		}
		tcp->tcp_snxt = snxt + tcp->tcp_fin_sent;
		tcp->tcp_rack = tcp->tcp_rnxt;
		tcp->tcp_rack_cnt = 0;
		if ((snxt + len) == tcp->tcp_suna) {
			TCP_TIMER_RESTART(tcp, tcp->tcp_rto);
		}
	} else if (snxt == tcp->tcp_suna && tcp->tcp_swnd == 0) {
		/*
		 * Didn't send anything. Make sure the timer is running
		 * so that we will probe a zero window.
		 */
		TCP_TIMER_RESTART(tcp, tcp->tcp_rto);
	}
	/* Note that len is the amount we just sent but with a negative sign */
	tcp->tcp_unsent += len;
	mutex_enter(&tcp->tcp_non_sq_lock);
	if (tcp->tcp_flow_stopped) {
		if (TCP_UNSENT_BYTES(tcp) <= tcp->tcp_xmit_lowater) {
			tcp_clrqfull(tcp);
		}
	} else if (TCP_UNSENT_BYTES(tcp) >= tcp->tcp_xmit_hiwater) {
		tcp_setqfull(tcp);
	}
	mutex_exit(&tcp->tcp_non_sq_lock);
}

/*
 * tcp_fill_header is called by tcp_send() and tcp_multisend() to fill the
 * outgoing TCP header with the template header, as well as other
 * options such as time-stamp, ECN and/or SACK.
 */
static void
tcp_fill_header(tcp_t *tcp, uchar_t *rptr, clock_t now, int num_sack_blk)
{
	tcph_t *tcp_tmpl, *tcp_h;
	uint32_t *dst, *src;
	int hdrlen;

	ASSERT(OK_32PTR(rptr));

	/* Template header */
	tcp_tmpl = tcp->tcp_tcph;

	/* Header of outgoing packet */
	tcp_h = (tcph_t *)(rptr + tcp->tcp_ip_hdr_len);

	/* dst and src are opaque 32-bit fields, used for copying */
	dst = (uint32_t *)rptr;
	src = (uint32_t *)tcp->tcp_iphc;
	hdrlen = tcp->tcp_hdr_len;

	/* Fill time-stamp option if needed */
	if (tcp->tcp_snd_ts_ok) {
		U32_TO_BE32((uint32_t)now,
		    (char *)tcp_tmpl + TCP_MIN_HEADER_LENGTH + 4);
		U32_TO_BE32(tcp->tcp_ts_recent,
		    (char *)tcp_tmpl + TCP_MIN_HEADER_LENGTH + 8);
	} else {
		ASSERT(tcp->tcp_tcp_hdr_len == TCP_MIN_HEADER_LENGTH);
	}

	/*
	 * Copy the template header; is this really more efficient than
	 * calling bcopy()?  For simple IPv4/TCP, it may be the case,
	 * but perhaps not for other scenarios.
	 */
	dst[0] = src[0];
	dst[1] = src[1];
	dst[2] = src[2];
	dst[3] = src[3];
	dst[4] = src[4];
	dst[5] = src[5];
	dst[6] = src[6];
	dst[7] = src[7];
	dst[8] = src[8];
	dst[9] = src[9];
	if (hdrlen -= 40) {
		hdrlen >>= 2;
		dst += 10;
		src += 10;
		do {
			*dst++ = *src++;
		} while (--hdrlen);
	}

	/*
	 * Set the ECN info in the TCP header if it is not a zero
	 * window probe.  Zero window probe is only sent in
	 * tcp_wput_data() and tcp_timer().
	 */
	if (tcp->tcp_ecn_ok && !tcp->tcp_zero_win_probe) {
		SET_ECT(tcp, rptr);

		if (tcp->tcp_ecn_echo_on)
			tcp_h->th_flags[0] |= TH_ECE;
		if (tcp->tcp_cwr && !tcp->tcp_ecn_cwr_sent) {
			tcp_h->th_flags[0] |= TH_CWR;
			tcp->tcp_ecn_cwr_sent = B_TRUE;
		}
	}

	/* Fill in SACK options */
	if (num_sack_blk > 0) {
		uchar_t *wptr = rptr + tcp->tcp_hdr_len;
		sack_blk_t *tmp;
		int32_t	i;

		wptr[0] = TCPOPT_NOP;
		wptr[1] = TCPOPT_NOP;
		wptr[2] = TCPOPT_SACK;
		wptr[3] = TCPOPT_HEADER_LEN + num_sack_blk *
		    sizeof (sack_blk_t);
		wptr += TCPOPT_REAL_SACK_LEN;

		tmp = tcp->tcp_sack_list;
		for (i = 0; i < num_sack_blk; i++) {
			U32_TO_BE32(tmp[i].begin, wptr);
			wptr += sizeof (tcp_seq);
			U32_TO_BE32(tmp[i].end, wptr);
			wptr += sizeof (tcp_seq);
		}
		tcp_h->th_offset_and_rsrvd[0] +=
		    ((num_sack_blk * 2 + 1) << 4);
	}
}

/*
 * tcp_mdt_add_attrs() is called by tcp_multisend() in order to attach
 * the destination address and SAP attribute, and if necessary, the
 * hardware checksum offload attribute to a Multidata message.
 */
static int
tcp_mdt_add_attrs(multidata_t *mmd, const mblk_t *dlmp, const boolean_t hwcksum,
    const uint32_t start, const uint32_t stuff, const uint32_t end,
    const uint32_t flags, tcp_stack_t *tcps)
{
	/* Add global destination address & SAP attribute */
	if (dlmp == NULL || !ip_md_addr_attr(mmd, NULL, dlmp)) {
		ip1dbg(("tcp_mdt_add_attrs: can't add global physical "
		    "destination address+SAP\n"));

		if (dlmp != NULL)
			TCP_STAT(tcps, tcp_mdt_allocfail);
		return (-1);
	}

	/* Add global hwcksum attribute */
	if (hwcksum &&
	    !ip_md_hcksum_attr(mmd, NULL, start, stuff, end, flags)) {
		ip1dbg(("tcp_mdt_add_attrs: can't add global hardware "
		    "checksum attribute\n"));

		TCP_STAT(tcps, tcp_mdt_allocfail);
		return (-1);
	}

	return (0);
}

/*
 * Smaller and private version of pdescinfo_t used specifically for TCP,
 * which allows for only two payload spans per packet.
 */
typedef struct tcp_pdescinfo_s PDESCINFO_STRUCT(2) tcp_pdescinfo_t;

/*
 * tcp_multisend() is called by tcp_wput_data() for Multidata Transmit
 * scheme, and returns one the following:
 *
 * -1 = failed allocation.
 *  0 = success; burst count reached, or usable send window is too small,
 *      and that we'd rather wait until later before sending again.
 */
static int
tcp_multisend(queue_t *q, tcp_t *tcp, const int mss, const int tcp_hdr_len,
    const int tcp_tcp_hdr_len, const int num_sack_blk, int *usable,
    uint_t *snxt, int *tail_unsent, mblk_t **xmit_tail, mblk_t *local_time,
    const int mdt_thres)
{
	mblk_t		*md_mp_head, *md_mp, *md_pbuf, *md_pbuf_nxt, *md_hbuf;
	multidata_t	*mmd;
	uint_t		obsegs, obbytes, hdr_frag_sz;
	uint_t		cur_hdr_off, cur_pld_off, base_pld_off, first_snxt;
	int		num_burst_seg, max_pld;
	pdesc_t		*pkt;
	tcp_pdescinfo_t	tcp_pkt_info;
	pdescinfo_t	*pkt_info;
	int		pbuf_idx, pbuf_idx_nxt;
	int		seg_len, len, spill, af;
	boolean_t	add_buffer, zcopy, clusterwide;
	boolean_t	rconfirm = B_FALSE;
	boolean_t	done = B_FALSE;
	uint32_t	cksum;
	uint32_t	hwcksum_flags;
	ire_t		*ire = NULL;
	ill_t		*ill;
	ipha_t		*ipha;
	ip6_t		*ip6h;
	ipaddr_t	src, dst;
	ill_zerocopy_capab_t *zc_cap = NULL;
	uint16_t	*up;
	int		err;
	conn_t		*connp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	ip_stack_t 	*ipst = tcps->tcps_netstack->netstack_ip;
	int		usable_mmd, tail_unsent_mmd;
	uint_t		snxt_mmd, obsegs_mmd, obbytes_mmd;
	mblk_t		*xmit_tail_mmd;
	netstackid_t	stack_id;

#ifdef	_BIG_ENDIAN
#define	IPVER(ip6h)	((((uint32_t *)ip6h)[0] >> 28) & 0x7)
#else
#define	IPVER(ip6h)	((((uint32_t *)ip6h)[0] >> 4) & 0x7)
#endif

#define	PREP_NEW_MULTIDATA() {			\
	mmd = NULL;				\
	md_mp = md_hbuf = NULL;			\
	cur_hdr_off = 0;			\
	max_pld = tcp->tcp_mdt_max_pld;		\
	pbuf_idx = pbuf_idx_nxt = -1;		\
	add_buffer = B_TRUE;			\
	zcopy = B_FALSE;			\
}

#define	PREP_NEW_PBUF() {			\
	md_pbuf = md_pbuf_nxt = NULL;		\
	pbuf_idx = pbuf_idx_nxt = -1;		\
	cur_pld_off = 0;			\
	first_snxt = *snxt;			\
	ASSERT(*tail_unsent > 0);		\
	base_pld_off = MBLKL(*xmit_tail) - *tail_unsent; \
}

	ASSERT(mdt_thres >= mss);
	ASSERT(*usable > 0 && *usable > mdt_thres);
	ASSERT(tcp->tcp_state == TCPS_ESTABLISHED);
	ASSERT(!TCP_IS_DETACHED(tcp));
	ASSERT(tcp->tcp_valid_bits == 0 ||
	    tcp->tcp_valid_bits == TCP_FSS_VALID);
	ASSERT((tcp->tcp_ipversion == IPV4_VERSION &&
	    tcp->tcp_ip_hdr_len == IP_SIMPLE_HDR_LENGTH) ||
	    (tcp->tcp_ipversion == IPV6_VERSION &&
	    tcp->tcp_ip_hdr_len == IPV6_HDR_LEN));

	connp = tcp->tcp_connp;
	ASSERT(connp != NULL);
	ASSERT(CONN_IS_LSO_MD_FASTPATH(connp));
	ASSERT(!CONN_IPSEC_OUT_ENCAPSULATED(connp));

	stack_id = connp->conn_netstack->netstack_stackid;

	usable_mmd = tail_unsent_mmd = 0;
	snxt_mmd = obsegs_mmd = obbytes_mmd = 0;
	xmit_tail_mmd = NULL;
	/*
	 * Note that tcp will only declare at most 2 payload spans per
	 * packet, which is much lower than the maximum allowable number
	 * of packet spans per Multidata.  For this reason, we use the
	 * privately declared and smaller descriptor info structure, in
	 * order to save some stack space.
	 */
	pkt_info = (pdescinfo_t *)&tcp_pkt_info;

	af = (tcp->tcp_ipversion == IPV4_VERSION) ? AF_INET : AF_INET6;
	if (af == AF_INET) {
		dst = tcp->tcp_ipha->ipha_dst;
		src = tcp->tcp_ipha->ipha_src;
		ASSERT(!CLASSD(dst));
	}
	ASSERT(af == AF_INET ||
	    !IN6_IS_ADDR_MULTICAST(&tcp->tcp_ip6h->ip6_dst));

	obsegs = obbytes = 0;
	num_burst_seg = tcp->tcp_snd_burst;
	md_mp_head = NULL;
	PREP_NEW_MULTIDATA();

	/*
	 * Before we go on further, make sure there is an IRE that we can
	 * use, and that the ILL supports MDT.  Otherwise, there's no point
	 * in proceeding any further, and we should just hand everything
	 * off to the legacy path.
	 */
	if (!tcp_send_find_ire(tcp, (af == AF_INET) ? &dst : NULL, &ire))
		goto legacy_send_no_md;

	ASSERT(ire != NULL);
	ASSERT(af != AF_INET || ire->ire_ipversion == IPV4_VERSION);
	ASSERT(af == AF_INET || !IN6_IS_ADDR_V4MAPPED(&(ire->ire_addr_v6)));
	ASSERT(af == AF_INET || ire->ire_nce != NULL);
	ASSERT(!(ire->ire_type & IRE_BROADCAST));
	/*
	 * If we do support loopback for MDT (which requires modifications
	 * to the receiving paths), the following assertions should go away,
	 * and we would be sending the Multidata to loopback conn later on.
	 */
	ASSERT(!IRE_IS_LOCAL(ire));
	ASSERT(ire->ire_stq != NULL);

	ill = ire_to_ill(ire);
	ASSERT(ill != NULL);
	ASSERT(!ILL_MDT_CAPABLE(ill) || ill->ill_mdt_capab != NULL);

	if (!tcp->tcp_ire_ill_check_done) {
		tcp_ire_ill_check(tcp, ire, ill, B_TRUE);
		tcp->tcp_ire_ill_check_done = B_TRUE;
	}

	/*
	 * If the underlying interface conditions have changed, or if the
	 * new interface does not support MDT, go back to legacy path.
	 */
	if (!ILL_MDT_USABLE(ill) || (ire->ire_flags & RTF_MULTIRT) != 0) {
		/* don't go through this path anymore for this connection */
		TCP_STAT(tcps, tcp_mdt_conn_halted2);
		tcp->tcp_mdt = B_FALSE;
		ip1dbg(("tcp_multisend: disabling MDT for connp %p on "
		    "interface %s\n", (void *)connp, ill->ill_name));
		/* IRE will be released prior to returning */
		goto legacy_send_no_md;
	}

	if (ill->ill_capabilities & ILL_CAPAB_ZEROCOPY)
		zc_cap = ill->ill_zerocopy_capab;

	/*
	 * Check if we can take tcp fast-path. Note that "incomplete"
	 * ire's (where the link-layer for next hop is not resolved
	 * or where the fast-path header in nce_fp_mp is not available
	 * yet) are sent down the legacy (slow) path.
	 * NOTE: We should fix ip_xmit_v4 to handle M_MULTIDATA
	 */
	if (ire->ire_nce && ire->ire_nce->nce_state != ND_REACHABLE) {
		/* IRE will be released prior to returning */
		goto legacy_send_no_md;
	}

	/* go to legacy path if interface doesn't support zerocopy */
	if (tcp->tcp_snd_zcopy_aware && do_tcpzcopy != 2 &&
	    (zc_cap == NULL || zc_cap->ill_zerocopy_flags == 0)) {
		/* IRE will be released prior to returning */
		goto legacy_send_no_md;
	}

	/* does the interface support hardware checksum offload? */
	hwcksum_flags = 0;
	if (ILL_HCKSUM_CAPABLE(ill) &&
	    (ill->ill_hcksum_capab->ill_hcksum_txflags &
	    (HCKSUM_INET_FULL_V4 | HCKSUM_INET_FULL_V6 | HCKSUM_INET_PARTIAL |
	    HCKSUM_IPHDRCKSUM)) && dohwcksum) {
		if (ill->ill_hcksum_capab->ill_hcksum_txflags &
		    HCKSUM_IPHDRCKSUM)
			hwcksum_flags = HCK_IPV4_HDRCKSUM;

		if (ill->ill_hcksum_capab->ill_hcksum_txflags &
		    (HCKSUM_INET_FULL_V4 | HCKSUM_INET_FULL_V6))
			hwcksum_flags |= HCK_FULLCKSUM;
		else if (ill->ill_hcksum_capab->ill_hcksum_txflags &
		    HCKSUM_INET_PARTIAL)
			hwcksum_flags |= HCK_PARTIALCKSUM;
	}

	/*
	 * Each header fragment consists of the leading extra space,
	 * followed by the TCP/IP header, and the trailing extra space.
	 * We make sure that each header fragment begins on a 32-bit
	 * aligned memory address (tcp_mdt_hdr_head is already 32-bit
	 * aligned in tcp_mdt_update).
	 */
	hdr_frag_sz = roundup((tcp->tcp_mdt_hdr_head + tcp_hdr_len +
	    tcp->tcp_mdt_hdr_tail), 4);

	/* are we starting from the beginning of data block? */
	if (*tail_unsent == 0) {
		*xmit_tail = (*xmit_tail)->b_cont;
		ASSERT((uintptr_t)MBLKL(*xmit_tail) <= (uintptr_t)INT_MAX);
		*tail_unsent = (int)MBLKL(*xmit_tail);
	}

	/*
	 * Here we create one or more Multidata messages, each made up of
	 * one header buffer and up to N payload buffers.  This entire
	 * operation is done within two loops:
	 *
	 * The outer loop mostly deals with creating the Multidata message,
	 * as well as the header buffer that gets added to it.  It also
	 * links the Multidata messages together such that all of them can
	 * be sent down to the lower layer in a single putnext call; this
	 * linking behavior depends on the tcp_mdt_chain tunable.
	 *
	 * The inner loop takes an existing Multidata message, and adds
	 * one or more (up to tcp_mdt_max_pld) payload buffers to it.  It
	 * packetizes those buffers by filling up the corresponding header
	 * buffer fragments with the proper IP and TCP headers, and by
	 * describing the layout of each packet in the packet descriptors
	 * that get added to the Multidata.
	 */
	do {
		/*
		 * If usable send window is too small, or data blocks in
		 * transmit list are smaller than our threshold (i.e. app
		 * performs large writes followed by small ones), we hand
		 * off the control over to the legacy path.  Note that we'll
		 * get back the control once it encounters a large block.
		 */
		if (*usable < mss || (*tail_unsent <= mdt_thres &&
		    (*xmit_tail)->b_cont != NULL &&
		    MBLKL((*xmit_tail)->b_cont) <= mdt_thres)) {
			/* send down what we've got so far */
			if (md_mp_head != NULL) {
				tcp_multisend_data(tcp, ire, ill, md_mp_head,
				    obsegs, obbytes, &rconfirm);
			}
			/*
			 * Pass control over to tcp_send(), but tell it to
			 * return to us once a large-size transmission is
			 * possible.
			 */
			TCP_STAT(tcps, tcp_mdt_legacy_small);
			if ((err = tcp_send(q, tcp, mss, tcp_hdr_len,
			    tcp_tcp_hdr_len, num_sack_blk, usable, snxt,
			    tail_unsent, xmit_tail, local_time,
			    mdt_thres)) <= 0) {
				/* burst count reached, or alloc failed */
				IRE_REFRELE(ire);
				return (err);
			}

			/* tcp_send() may have sent everything, so check */
			if (*usable <= 0) {
				IRE_REFRELE(ire);
				return (0);
			}

			TCP_STAT(tcps, tcp_mdt_legacy_ret);
			/*
			 * We may have delivered the Multidata, so make sure
			 * to re-initialize before the next round.
			 */
			md_mp_head = NULL;
			obsegs = obbytes = 0;
			num_burst_seg = tcp->tcp_snd_burst;
			PREP_NEW_MULTIDATA();

			/* are we starting from the beginning of data block? */
			if (*tail_unsent == 0) {
				*xmit_tail = (*xmit_tail)->b_cont;
				ASSERT((uintptr_t)MBLKL(*xmit_tail) <=
				    (uintptr_t)INT_MAX);
				*tail_unsent = (int)MBLKL(*xmit_tail);
			}
		}
		/*
		 * Record current values for parameters we may need to pass
		 * to tcp_send() or tcp_multisend_data(). We checkpoint at
		 * each iteration of the outer loop (each multidata message
		 * creation). If we have a failure in the inner loop, we send
		 * any complete multidata messages we have before reverting
		 * to using the traditional non-md path.
		 */
		snxt_mmd = *snxt;
		usable_mmd = *usable;
		xmit_tail_mmd = *xmit_tail;
		tail_unsent_mmd = *tail_unsent;
		obsegs_mmd = obsegs;
		obbytes_mmd = obbytes;

		/*
		 * max_pld limits the number of mblks in tcp's transmit
		 * queue that can be added to a Multidata message.  Once
		 * this counter reaches zero, no more additional mblks
		 * can be added to it.  What happens afterwards depends
		 * on whether or not we are set to chain the Multidata
		 * messages.  If we are to link them together, reset
		 * max_pld to its original value (tcp_mdt_max_pld) and
		 * prepare to create a new Multidata message which will
		 * get linked to md_mp_head.  Else, leave it alone and
		 * let the inner loop break on its own.
		 */
		if (tcp_mdt_chain && max_pld == 0)
			PREP_NEW_MULTIDATA();

		/* adding a payload buffer; re-initialize values */
		if (add_buffer)
			PREP_NEW_PBUF();

		/*
		 * If we don't have a Multidata, either because we just
		 * (re)entered this outer loop, or after we branched off
		 * to tcp_send above, setup the Multidata and header
		 * buffer to be used.
		 */
		if (md_mp == NULL) {
			int md_hbuflen;
			uint32_t start, stuff;

			/*
			 * Calculate Multidata header buffer size large enough
			 * to hold all of the headers that can possibly be
			 * sent at this moment.  We'd rather over-estimate
			 * the size than running out of space; this is okay
			 * since this buffer is small anyway.
			 */
			md_hbuflen = (howmany(*usable, mss) + 1) * hdr_frag_sz;

			/*
			 * Start and stuff offset for partial hardware
			 * checksum offload; these are currently for IPv4.
			 * For full checksum offload, they are set to zero.
			 */
			if ((hwcksum_flags & HCK_PARTIALCKSUM)) {
				if (af == AF_INET) {
					start = IP_SIMPLE_HDR_LENGTH;
					stuff = IP_SIMPLE_HDR_LENGTH +
					    TCP_CHECKSUM_OFFSET;
				} else {
					start = IPV6_HDR_LEN;
					stuff = IPV6_HDR_LEN +
					    TCP_CHECKSUM_OFFSET;
				}
			} else {
				start = stuff = 0;
			}

			/*
			 * Create the header buffer, Multidata, as well as
			 * any necessary attributes (destination address,
			 * SAP and hardware checksum offload) that should
			 * be associated with the Multidata message.
			 */
			ASSERT(cur_hdr_off == 0);
			if ((md_hbuf = allocb(md_hbuflen, BPRI_HI)) == NULL ||
			    ((md_hbuf->b_wptr += md_hbuflen),
			    (mmd = mmd_alloc(md_hbuf, &md_mp,
			    KM_NOSLEEP)) == NULL) || (tcp_mdt_add_attrs(mmd,
			    /* fastpath mblk */
			    ire->ire_nce->nce_res_mp,
			    /* hardware checksum enabled */
			    (hwcksum_flags & (HCK_FULLCKSUM|HCK_PARTIALCKSUM)),
			    /* hardware checksum offsets */
			    start, stuff, 0,
			    /* hardware checksum flag */
			    hwcksum_flags, tcps) != 0)) {
legacy_send:
				/*
				 * We arrive here from a failure within the
				 * inner (packetizer) loop or we fail one of
				 * the conditionals above. We restore the
				 * previously checkpointed values for:
				 *    xmit_tail
				 *    usable
				 *    tail_unsent
				 *    snxt
				 *    obbytes
				 *    obsegs
				 * We should then be able to dispatch any
				 * complete multidata before reverting to the
				 * traditional path with consistent parameters
				 * (the inner loop updates these as it
				 * iterates).
				 */
				*xmit_tail = xmit_tail_mmd;
				*usable = usable_mmd;
				*tail_unsent = tail_unsent_mmd;
				*snxt = snxt_mmd;
				obbytes = obbytes_mmd;
				obsegs = obsegs_mmd;
				if (md_mp != NULL) {
					/* Unlink message from the chain */
					if (md_mp_head != NULL) {
						err = (intptr_t)rmvb(md_mp_head,
						    md_mp);
						/*
						 * We can't assert that rmvb
						 * did not return -1, since we
						 * may get here before linkb
						 * happens.  We do, however,
						 * check if we just removed the
						 * only element in the list.
						 */
						if (err == 0)
							md_mp_head = NULL;
					}
					/* md_hbuf gets freed automatically */
					TCP_STAT(tcps, tcp_mdt_discarded);
					freeb(md_mp);
				} else {
					/* Either allocb or mmd_alloc failed */
					TCP_STAT(tcps, tcp_mdt_allocfail);
					if (md_hbuf != NULL)
						freeb(md_hbuf);
				}

				/* send down what we've got so far */
				if (md_mp_head != NULL) {
					tcp_multisend_data(tcp, ire, ill,
					    md_mp_head, obsegs, obbytes,
					    &rconfirm);
				}
legacy_send_no_md:
				if (ire != NULL)
					IRE_REFRELE(ire);
				/*
				 * Too bad; let the legacy path handle this.
				 * We specify INT_MAX for the threshold, since
				 * we gave up with the Multidata processings
				 * and let the old path have it all.
				 */
				TCP_STAT(tcps, tcp_mdt_legacy_all);
				return (tcp_send(q, tcp, mss, tcp_hdr_len,
				    tcp_tcp_hdr_len, num_sack_blk, usable,
				    snxt, tail_unsent, xmit_tail, local_time,
				    INT_MAX));
			}

			/* link to any existing ones, if applicable */
			TCP_STAT(tcps, tcp_mdt_allocd);
			if (md_mp_head == NULL) {
				md_mp_head = md_mp;
			} else if (tcp_mdt_chain) {
				TCP_STAT(tcps, tcp_mdt_linked);
				linkb(md_mp_head, md_mp);
			}
		}

		ASSERT(md_mp_head != NULL);
		ASSERT(tcp_mdt_chain || md_mp_head->b_cont == NULL);
		ASSERT(md_mp != NULL && mmd != NULL);
		ASSERT(md_hbuf != NULL);

		/*
		 * Packetize the transmittable portion of the data block;
		 * each data block is essentially added to the Multidata
		 * as a payload buffer.  We also deal with adding more
		 * than one payload buffers, which happens when the remaining
		 * packetized portion of the current payload buffer is less
		 * than MSS, while the next data block in transmit queue
		 * has enough data to make up for one.  This "spillover"
		 * case essentially creates a split-packet, where portions
		 * of the packet's payload fragments may span across two
		 * virtually discontiguous address blocks.
		 */
		seg_len = mss;
		do {
			len = seg_len;

			/* one must remain NULL for DTRACE_IP_FASTPATH */
			ipha = NULL;
			ip6h = NULL;

			ASSERT(len > 0);
			ASSERT(max_pld >= 0);
			ASSERT(!add_buffer || cur_pld_off == 0);

			/*
			 * First time around for this payload buffer; note
			 * in the case of a spillover, the following has
			 * been done prior to adding the split-packet
			 * descriptor to Multidata, and we don't want to
			 * repeat the process.
			 */
			if (add_buffer) {
				ASSERT(mmd != NULL);
				ASSERT(md_pbuf == NULL);
				ASSERT(md_pbuf_nxt == NULL);
				ASSERT(pbuf_idx == -1 && pbuf_idx_nxt == -1);

				/*
				 * Have we reached the limit?  We'd get to
				 * this case when we're not chaining the
				 * Multidata messages together, and since
				 * we're done, terminate this loop.
				 */
				if (max_pld == 0)
					break; /* done */

				if ((md_pbuf = dupb(*xmit_tail)) == NULL) {
					TCP_STAT(tcps, tcp_mdt_allocfail);
					goto legacy_send; /* out_of_mem */
				}

				if (IS_VMLOANED_MBLK(md_pbuf) && !zcopy &&
				    zc_cap != NULL) {
					if (!ip_md_zcopy_attr(mmd, NULL,
					    zc_cap->ill_zerocopy_flags)) {
						freeb(md_pbuf);
						TCP_STAT(tcps,
						    tcp_mdt_allocfail);
						/* out_of_mem */
						goto legacy_send;
					}
					zcopy = B_TRUE;
				}

				md_pbuf->b_rptr += base_pld_off;

				/*
				 * Add a payload buffer to the Multidata; this
				 * operation must not fail, or otherwise our
				 * logic in this routine is broken.  There
				 * is no memory allocation done by the
				 * routine, so any returned failure simply
				 * tells us that we've done something wrong.
				 *
				 * A failure tells us that either we're adding
				 * the same payload buffer more than once, or
				 * we're trying to add more buffers than
				 * allowed (max_pld calculation is wrong).
				 * None of the above cases should happen, and
				 * we panic because either there's horrible
				 * heap corruption, and/or programming mistake.
				 */
				pbuf_idx = mmd_addpldbuf(mmd, md_pbuf);
				if (pbuf_idx < 0) {
					cmn_err(CE_PANIC, "tcp_multisend: "
					    "payload buffer logic error "
					    "detected for tcp %p mmd %p "
					    "pbuf %p (%d)\n",
					    (void *)tcp, (void *)mmd,
					    (void *)md_pbuf, pbuf_idx);
				}

				ASSERT(max_pld > 0);
				--max_pld;
				add_buffer = B_FALSE;
			}

			ASSERT(md_mp_head != NULL);
			ASSERT(md_pbuf != NULL);
			ASSERT(md_pbuf_nxt == NULL);
			ASSERT(pbuf_idx != -1);
			ASSERT(pbuf_idx_nxt == -1);
			ASSERT(*usable > 0);

			/*
			 * We spillover to the next payload buffer only
			 * if all of the following is true:
			 *
			 *   1. There is not enough data on the current
			 *	payload buffer to make up `len',
			 *   2. We are allowed to send `len',
			 *   3. The next payload buffer length is large
			 *	enough to accomodate `spill'.
			 */
			if ((spill = len - *tail_unsent) > 0 &&
			    *usable >= len &&
			    MBLKL((*xmit_tail)->b_cont) >= spill &&
			    max_pld > 0) {
				md_pbuf_nxt = dupb((*xmit_tail)->b_cont);
				if (md_pbuf_nxt == NULL) {
					TCP_STAT(tcps, tcp_mdt_allocfail);
					goto legacy_send; /* out_of_mem */
				}

				if (IS_VMLOANED_MBLK(md_pbuf_nxt) && !zcopy &&
				    zc_cap != NULL) {
					if (!ip_md_zcopy_attr(mmd, NULL,
					    zc_cap->ill_zerocopy_flags)) {
						freeb(md_pbuf_nxt);
						TCP_STAT(tcps,
						    tcp_mdt_allocfail);
						/* out_of_mem */
						goto legacy_send;
					}
					zcopy = B_TRUE;
				}

				/*
				 * See comments above on the first call to
				 * mmd_addpldbuf for explanation on the panic.
				 */
				pbuf_idx_nxt = mmd_addpldbuf(mmd, md_pbuf_nxt);
				if (pbuf_idx_nxt < 0) {
					panic("tcp_multisend: "
					    "next payload buffer logic error "
					    "detected for tcp %p mmd %p "
					    "pbuf %p (%d)\n",
					    (void *)tcp, (void *)mmd,
					    (void *)md_pbuf_nxt, pbuf_idx_nxt);
				}

				ASSERT(max_pld > 0);
				--max_pld;
			} else if (spill > 0) {
				/*
				 * If there's a spillover, but the following
				 * xmit_tail couldn't give us enough octets
				 * to reach "len", then stop the current
				 * Multidata creation and let the legacy
				 * tcp_send() path take over.  We don't want
				 * to send the tiny segment as part of this
				 * Multidata for performance reasons; instead,
				 * we let the legacy path deal with grouping
				 * it with the subsequent small mblks.
				 */
				if (*usable >= len &&
				    MBLKL((*xmit_tail)->b_cont) < spill) {
					max_pld = 0;
					break;	/* done */
				}

				/*
				 * We can't spillover, and we are near
				 * the end of the current payload buffer,
				 * so send what's left.
				 */
				ASSERT(*tail_unsent > 0);
				len = *tail_unsent;
			}

			/* tail_unsent is negated if there is a spillover */
			*tail_unsent -= len;
			*usable -= len;
			ASSERT(*usable >= 0);

			if (*usable < mss)
				seg_len = *usable;
			/*
			 * Sender SWS avoidance; see comments in tcp_send();
			 * everything else is the same, except that we only
			 * do this here if there is no more data to be sent
			 * following the current xmit_tail.  We don't check
			 * for 1-byte urgent data because we shouldn't get
			 * here if TCP_URG_VALID is set.
			 */
			if (*usable > 0 && *usable < mss &&
			    ((md_pbuf_nxt == NULL &&
			    (*xmit_tail)->b_cont == NULL) ||
			    (md_pbuf_nxt != NULL &&
			    (*xmit_tail)->b_cont->b_cont == NULL)) &&
			    seg_len < (tcp->tcp_max_swnd >> 1) &&
			    (tcp->tcp_unsent -
			    ((*snxt + len) - tcp->tcp_snxt)) > seg_len &&
			    !tcp->tcp_zero_win_probe) {
				if ((*snxt + len) == tcp->tcp_snxt &&
				    (*snxt + len) == tcp->tcp_suna) {
					TCP_TIMER_RESTART(tcp, tcp->tcp_rto);
				}
				done = B_TRUE;
			}

			/*
			 * Prime pump for IP's checksumming on our behalf;
			 * include the adjustment for a source route if any.
			 * Do this only for software/partial hardware checksum
			 * offload, as this field gets zeroed out later for
			 * the full hardware checksum offload case.
			 */
			if (!(hwcksum_flags & HCK_FULLCKSUM)) {
				cksum = len + tcp_tcp_hdr_len + tcp->tcp_sum;
				cksum = (cksum >> 16) + (cksum & 0xFFFF);
				U16_TO_ABE16(cksum, tcp->tcp_tcph->th_sum);
			}

			U32_TO_ABE32(*snxt, tcp->tcp_tcph->th_seq);
			*snxt += len;

			tcp->tcp_tcph->th_flags[0] = TH_ACK;
			/*
			 * We set the PUSH bit only if TCP has no more buffered
			 * data to be transmitted (or if sender SWS avoidance
			 * takes place), as opposed to setting it for every
			 * last packet in the burst.
			 */
			if (done ||
			    (tcp->tcp_unsent - (*snxt - tcp->tcp_snxt)) == 0)
				tcp->tcp_tcph->th_flags[0] |= TH_PUSH;

			/*
			 * Set FIN bit if this is our last segment; snxt
			 * already includes its length, and it will not
			 * be adjusted after this point.
			 */
			if (tcp->tcp_valid_bits == TCP_FSS_VALID &&
			    *snxt == tcp->tcp_fss) {
				if (!tcp->tcp_fin_acked) {
					tcp->tcp_tcph->th_flags[0] |= TH_FIN;
					BUMP_MIB(&tcps->tcps_mib,
					    tcpOutControl);
				}
				if (!tcp->tcp_fin_sent) {
					tcp->tcp_fin_sent = B_TRUE;
					/*
					 * tcp state must be ESTABLISHED
					 * in order for us to get here in
					 * the first place.
					 */
					tcp->tcp_state = TCPS_FIN_WAIT_1;

					/*
					 * Upon returning from this routine,
					 * tcp_wput_data() will set tcp_snxt
					 * to be equal to snxt + tcp_fin_sent.
					 * This is essentially the same as
					 * setting it to tcp_fss + 1.
					 */
				}
			}

			tcp->tcp_last_sent_len = (ushort_t)len;

			len += tcp_hdr_len;
			if (tcp->tcp_ipversion == IPV4_VERSION)
				tcp->tcp_ipha->ipha_length = htons(len);
			else
				tcp->tcp_ip6h->ip6_plen = htons(len -
				    ((char *)&tcp->tcp_ip6h[1] -
				    tcp->tcp_iphc));

			pkt_info->flags = (PDESC_HBUF_REF | PDESC_PBUF_REF);

			/* setup header fragment */
			PDESC_HDR_ADD(pkt_info,
			    md_hbuf->b_rptr + cur_hdr_off,	/* base */
			    tcp->tcp_mdt_hdr_head,		/* head room */
			    tcp_hdr_len,			/* len */
			    tcp->tcp_mdt_hdr_tail);		/* tail room */

			ASSERT(pkt_info->hdr_lim - pkt_info->hdr_base ==
			    hdr_frag_sz);
			ASSERT(MBLKIN(md_hbuf,
			    (pkt_info->hdr_base - md_hbuf->b_rptr),
			    PDESC_HDRSIZE(pkt_info)));

			/* setup first payload fragment */
			PDESC_PLD_INIT(pkt_info);
			PDESC_PLD_SPAN_ADD(pkt_info,
			    pbuf_idx,				/* index */
			    md_pbuf->b_rptr + cur_pld_off,	/* start */
			    tcp->tcp_last_sent_len);		/* len */

			/* create a split-packet in case of a spillover */
			if (md_pbuf_nxt != NULL) {
				ASSERT(spill > 0);
				ASSERT(pbuf_idx_nxt > pbuf_idx);
				ASSERT(!add_buffer);

				md_pbuf = md_pbuf_nxt;
				md_pbuf_nxt = NULL;
				pbuf_idx = pbuf_idx_nxt;
				pbuf_idx_nxt = -1;
				cur_pld_off = spill;

				/* trim out first payload fragment */
				PDESC_PLD_SPAN_TRIM(pkt_info, 0, spill);

				/* setup second payload fragment */
				PDESC_PLD_SPAN_ADD(pkt_info,
				    pbuf_idx,			/* index */
				    md_pbuf->b_rptr,		/* start */
				    spill);			/* len */

				if ((*xmit_tail)->b_next == NULL) {
					/*
					 * Store the lbolt used for RTT
					 * estimation. We can only record one
					 * timestamp per mblk so we do it when
					 * we reach the end of the payload
					 * buffer.  Also we only take a new
					 * timestamp sample when the previous
					 * timed data from the same mblk has
					 * been ack'ed.
					 */
					(*xmit_tail)->b_prev = local_time;
					(*xmit_tail)->b_next =
					    (mblk_t *)(uintptr_t)first_snxt;
				}

				first_snxt = *snxt - spill;

				/*
				 * Advance xmit_tail; usable could be 0 by
				 * the time we got here, but we made sure
				 * above that we would only spillover to
				 * the next data block if usable includes
				 * the spilled-over amount prior to the
				 * subtraction.  Therefore, we are sure
				 * that xmit_tail->b_cont can't be NULL.
				 */
				ASSERT((*xmit_tail)->b_cont != NULL);
				*xmit_tail = (*xmit_tail)->b_cont;
				ASSERT((uintptr_t)MBLKL(*xmit_tail) <=
				    (uintptr_t)INT_MAX);
				*tail_unsent = (int)MBLKL(*xmit_tail) - spill;
			} else {
				cur_pld_off += tcp->tcp_last_sent_len;
			}

			/*
			 * Fill in the header using the template header, and
			 * add options such as time-stamp, ECN and/or SACK,
			 * as needed.
			 */
			tcp_fill_header(tcp, pkt_info->hdr_rptr,
			    (clock_t)local_time, num_sack_blk);

			/* take care of some IP header businesses */
			if (af == AF_INET) {
				ipha = (ipha_t *)pkt_info->hdr_rptr;

				ASSERT(OK_32PTR((uchar_t *)ipha));
				ASSERT(PDESC_HDRL(pkt_info) >=
				    IP_SIMPLE_HDR_LENGTH);
				ASSERT(ipha->ipha_version_and_hdr_length ==
				    IP_SIMPLE_HDR_VERSION);

				/*
				 * Assign ident value for current packet; see
				 * related comments in ip_wput_ire() about the
				 * contract private interface with clustering
				 * group.
				 */
				clusterwide = B_FALSE;
				if (cl_inet_ipident != NULL) {
					ASSERT(cl_inet_isclusterwide != NULL);
					if ((*cl_inet_isclusterwide)(stack_id,
					    IPPROTO_IP, AF_INET,
					    (uint8_t *)(uintptr_t)src, NULL)) {
						ipha->ipha_ident =
						    (*cl_inet_ipident)(stack_id,
						    IPPROTO_IP, AF_INET,
						    (uint8_t *)(uintptr_t)src,
						    (uint8_t *)(uintptr_t)dst,
						    NULL);
						clusterwide = B_TRUE;
					}
				}

				if (!clusterwide) {
					ipha->ipha_ident = (uint16_t)
					    atomic_add_32_nv(
						&ire->ire_ident, 1);
				}
#ifndef _BIG_ENDIAN
				ipha->ipha_ident = (ipha->ipha_ident << 8) |
				    (ipha->ipha_ident >> 8);
#endif
			} else {
				ip6h = (ip6_t *)pkt_info->hdr_rptr;

				ASSERT(OK_32PTR((uchar_t *)ip6h));
				ASSERT(IPVER(ip6h) == IPV6_VERSION);
				ASSERT(ip6h->ip6_nxt == IPPROTO_TCP);
				ASSERT(PDESC_HDRL(pkt_info) >=
				    (IPV6_HDR_LEN + TCP_CHECKSUM_OFFSET +
				    TCP_CHECKSUM_SIZE));
				ASSERT(tcp->tcp_ipversion == IPV6_VERSION);

				if (tcp->tcp_ip_forward_progress) {
					rconfirm = B_TRUE;
					tcp->tcp_ip_forward_progress = B_FALSE;
				}
			}

			/* at least one payload span, and at most two */
			ASSERT(pkt_info->pld_cnt > 0 && pkt_info->pld_cnt < 3);

			/* add the packet descriptor to Multidata */
			if ((pkt = mmd_addpdesc(mmd, pkt_info, &err,
			    KM_NOSLEEP)) == NULL) {
				/*
				 * Any failure other than ENOMEM indicates
				 * that we have passed in invalid pkt_info
				 * or parameters to mmd_addpdesc, which must
				 * not happen.
				 *
				 * EINVAL is a result of failure on boundary
				 * checks against the pkt_info contents.  It
				 * should not happen, and we panic because
				 * either there's horrible heap corruption,
				 * and/or programming mistake.
				 */
				if (err != ENOMEM) {
					cmn_err(CE_PANIC, "tcp_multisend: "
					    "pdesc logic error detected for "
					    "tcp %p mmd %p pinfo %p (%d)\n",
					    (void *)tcp, (void *)mmd,
					    (void *)pkt_info, err);
				}
				TCP_STAT(tcps, tcp_mdt_addpdescfail);
				goto legacy_send; /* out_of_mem */
			}
			ASSERT(pkt != NULL);

			/* calculate IP header and TCP checksums */
			if (af == AF_INET) {
				/* calculate pseudo-header checksum */
				cksum = (dst >> 16) + (dst & 0xFFFF) +
				    (src >> 16) + (src & 0xFFFF);

				/* offset for TCP header checksum */
				up = IPH_TCPH_CHECKSUMP(ipha,
				    IP_SIMPLE_HDR_LENGTH);
			} else {
				up = (uint16_t *)&ip6h->ip6_src;

				/* calculate pseudo-header checksum */
				cksum = up[0] + up[1] + up[2] + up[3] +
				    up[4] + up[5] + up[6] + up[7] +
				    up[8] + up[9] + up[10] + up[11] +
				    up[12] + up[13] + up[14] + up[15];

				/* Fold the initial sum */
				cksum = (cksum & 0xffff) + (cksum >> 16);

				up = (uint16_t *)(((uchar_t *)ip6h) +
				    IPV6_HDR_LEN + TCP_CHECKSUM_OFFSET);
			}

			if (hwcksum_flags & HCK_FULLCKSUM) {
				/* clear checksum field for hardware */
				*up = 0;
			} else if (hwcksum_flags & HCK_PARTIALCKSUM) {
				uint32_t sum;

				/* pseudo-header checksumming */
				sum = *up + cksum + IP_TCP_CSUM_COMP;
				sum = (sum & 0xFFFF) + (sum >> 16);
				*up = (sum & 0xFFFF) + (sum >> 16);
			} else {
				/* software checksumming */
				TCP_STAT(tcps, tcp_out_sw_cksum);
				TCP_STAT_UPDATE(tcps, tcp_out_sw_cksum_bytes,
				    tcp->tcp_hdr_len + tcp->tcp_last_sent_len);
				*up = IP_MD_CSUM(pkt, tcp->tcp_ip_hdr_len,
				    cksum + IP_TCP_CSUM_COMP);
				if (*up == 0)
					*up = 0xFFFF;
			}

			/* IPv4 header checksum */
			if (af == AF_INET) {
				if (hwcksum_flags & HCK_IPV4_HDRCKSUM) {
					ipha->ipha_hdr_checksum = 0;
				} else {
					IP_HDR_CKSUM(ipha, cksum,
					    ((uint32_t *)ipha)[0],
					    ((uint16_t *)ipha)[4]);
				}
			}

			if (af == AF_INET &&
			    HOOKS4_INTERESTED_PHYSICAL_OUT(ipst) ||
			    af == AF_INET6 &&
			    HOOKS6_INTERESTED_PHYSICAL_OUT(ipst)) {
				mblk_t	*mp, *mp1;
				uchar_t	*hdr_rptr, *hdr_wptr;
				uchar_t	*pld_rptr, *pld_wptr;

				/*
				 * We reconstruct a pseudo packet for the hooks
				 * framework using mmd_transform_link().
				 * If it is a split packet we pullup the
				 * payload. FW_HOOKS expects a pkt comprising
				 * of two mblks: a header and the payload.
				 */
				if ((mp = mmd_transform_link(pkt)) == NULL) {
					TCP_STAT(tcps, tcp_mdt_allocfail);
					goto legacy_send;
				}

				if (pkt_info->pld_cnt > 1) {
					/* split payload, more than one pld */
					if ((mp1 = msgpullup(mp->b_cont, -1)) ==
					    NULL) {
						freemsg(mp);
						TCP_STAT(tcps,
						    tcp_mdt_allocfail);
						goto legacy_send;
					}
					freemsg(mp->b_cont);
					mp->b_cont = mp1;
				} else {
					mp1 = mp->b_cont;
				}
				ASSERT(mp1 != NULL && mp1->b_cont == NULL);

				/*
				 * Remember the message offsets. This is so we
				 * can detect changes when we return from the
				 * FW_HOOKS callbacks.
				 */
				hdr_rptr = mp->b_rptr;
				hdr_wptr = mp->b_wptr;
				pld_rptr = mp->b_cont->b_rptr;
				pld_wptr = mp->b_cont->b_wptr;

				if (af == AF_INET) {
					DTRACE_PROBE4(
					    ip4__physical__out__start,
					    ill_t *, NULL,
					    ill_t *, ill,
					    ipha_t *, ipha,
					    mblk_t *, mp);
					FW_HOOKS(
					    ipst->ips_ip4_physical_out_event,
					    ipst->ips_ipv4firewall_physical_out,
					    NULL, ill, ipha, mp, mp, 0, ipst);
					DTRACE_PROBE1(
					    ip4__physical__out__end,
					    mblk_t *, mp);
				} else {
					DTRACE_PROBE4(
					    ip6__physical__out_start,
					    ill_t *, NULL,
					    ill_t *, ill,
					    ip6_t *, ip6h,
					    mblk_t *, mp);
					FW_HOOKS6(
					    ipst->ips_ip6_physical_out_event,
					    ipst->ips_ipv6firewall_physical_out,
					    NULL, ill, ip6h, mp, mp, 0, ipst);
					DTRACE_PROBE1(
					    ip6__physical__out__end,
					    mblk_t *, mp);
				}

				if (mp == NULL ||
				    (mp1 = mp->b_cont) == NULL ||
				    mp->b_rptr != hdr_rptr ||
				    mp->b_wptr != hdr_wptr ||
				    mp1->b_rptr != pld_rptr ||
				    mp1->b_wptr != pld_wptr ||
				    mp1->b_cont != NULL) {
					/*
					 * We abandon multidata processing and
					 * return to the normal path, either
					 * when a packet is blocked, or when
					 * the boundaries of header buffer or
					 * payload buffer have been changed by
					 * FW_HOOKS[6].
					 */
					if (mp != NULL)
						freemsg(mp);
					goto legacy_send;
				}
				/* Finished with the pseudo packet */
				freemsg(mp);
			}
			DTRACE_IP_FASTPATH(md_hbuf, pkt_info->hdr_rptr,
			    ill, ipha, ip6h);
			/* advance header offset */
			cur_hdr_off += hdr_frag_sz;

			obbytes += tcp->tcp_last_sent_len;
			++obsegs;
		} while (!done && *usable > 0 && --num_burst_seg > 0 &&
		    *tail_unsent > 0);

		if ((*xmit_tail)->b_next == NULL) {
			/*
			 * Store the lbolt used for RTT estimation. We can only
			 * record one timestamp per mblk so we do it when we
			 * reach the end of the payload buffer. Also we only
			 * take a new timestamp sample when the previous timed
			 * data from the same mblk has been ack'ed.
			 */
			(*xmit_tail)->b_prev = local_time;
			(*xmit_tail)->b_next = (mblk_t *)(uintptr_t)first_snxt;
		}

		ASSERT(*tail_unsent >= 0);
		if (*tail_unsent > 0) {
			/*
			 * We got here because we broke out of the above
			 * loop due to of one of the following cases:
			 *
			 *   1. len < adjusted MSS (i.e. small),
			 *   2. Sender SWS avoidance,
			 *   3. max_pld is zero.
			 *
			 * We are done for this Multidata, so trim our
			 * last payload buffer (if any) accordingly.
			 */
			if (md_pbuf != NULL)
				md_pbuf->b_wptr -= *tail_unsent;
		} else if (*usable > 0) {
			*xmit_tail = (*xmit_tail)->b_cont;
			ASSERT((uintptr_t)MBLKL(*xmit_tail) <=
			    (uintptr_t)INT_MAX);
			*tail_unsent = (int)MBLKL(*xmit_tail);
			add_buffer = B_TRUE;
		}
	} while (!done && *usable > 0 && num_burst_seg > 0 &&
	    (tcp_mdt_chain || max_pld > 0));

	if (md_mp_head != NULL) {
		/* send everything down */
		tcp_multisend_data(tcp, ire, ill, md_mp_head, obsegs, obbytes,
		    &rconfirm);
	}

#undef PREP_NEW_MULTIDATA
#undef PREP_NEW_PBUF
#undef IPVER

	IRE_REFRELE(ire);
	return (0);
}

/*
 * A wrapper function for sending one or more Multidata messages down to
 * the module below ip; this routine does not release the reference of the
 * IRE (caller does that).  This routine is analogous to tcp_send_data().
 */
static void
tcp_multisend_data(tcp_t *tcp, ire_t *ire, const ill_t *ill, mblk_t *md_mp_head,
    const uint_t obsegs, const uint_t obbytes, boolean_t *rconfirm)
{
	uint64_t delta;
	nce_t *nce;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	ip_stack_t	*ipst = tcps->tcps_netstack->netstack_ip;

	ASSERT(ire != NULL && ill != NULL);
	ASSERT(ire->ire_stq != NULL);
	ASSERT(md_mp_head != NULL);
	ASSERT(rconfirm != NULL);

	/* adjust MIBs and IRE timestamp */
	DTRACE_PROBE2(tcp__trace__send, mblk_t *, md_mp_head, tcp_t *, tcp);
	tcp->tcp_obsegs += obsegs;
	UPDATE_MIB(&tcps->tcps_mib, tcpOutDataSegs, obsegs);
	UPDATE_MIB(&tcps->tcps_mib, tcpOutDataBytes, obbytes);
	TCP_STAT_UPDATE(tcps, tcp_mdt_pkt_out, obsegs);

	if (tcp->tcp_ipversion == IPV4_VERSION) {
		TCP_STAT_UPDATE(tcps, tcp_mdt_pkt_out_v4, obsegs);
	} else {
		TCP_STAT_UPDATE(tcps, tcp_mdt_pkt_out_v6, obsegs);
	}
	UPDATE_MIB(ill->ill_ip_mib, ipIfStatsHCOutRequests, obsegs);
	UPDATE_MIB(ill->ill_ip_mib, ipIfStatsHCOutTransmits, obsegs);
	UPDATE_MIB(ill->ill_ip_mib, ipIfStatsHCOutOctets, obbytes);

	ire->ire_ob_pkt_count += obsegs;
	if (ire->ire_ipif != NULL)
		atomic_add_32(&ire->ire_ipif->ipif_ob_pkt_count, obsegs);
	ire->ire_last_used_time = lbolt;

	if (ipst->ips_ipobs_enabled) {
		multidata_t *dlmdp = mmd_getmultidata(md_mp_head);
		pdesc_t *dl_pkt;
		pdescinfo_t pinfo;
		mblk_t *nmp;
		zoneid_t szone = tcp->tcp_connp->conn_zoneid;

		for (dl_pkt = mmd_getfirstpdesc(dlmdp, &pinfo);
		    (dl_pkt != NULL);
		    dl_pkt = mmd_getnextpdesc(dl_pkt, &pinfo)) {
			if ((nmp = mmd_transform_link(dl_pkt)) == NULL)
				continue;
			ipobs_hook(nmp, IPOBS_HOOK_OUTBOUND, szone,
			    ALL_ZONES, ill, tcp->tcp_ipversion, 0, ipst);
			freemsg(nmp);
		}
	}

	/* send it down */
	putnext(ire->ire_stq, md_mp_head);

	/* we're done for TCP/IPv4 */
	if (tcp->tcp_ipversion == IPV4_VERSION)
		return;

	nce = ire->ire_nce;

	ASSERT(nce != NULL);
	ASSERT(!(nce->nce_flags & (NCE_F_NONUD|NCE_F_PERMANENT)));
	ASSERT(nce->nce_state != ND_INCOMPLETE);

	/* reachability confirmation? */
	if (*rconfirm) {
		nce->nce_last = TICK_TO_MSEC(lbolt64);
		if (nce->nce_state != ND_REACHABLE) {
			mutex_enter(&nce->nce_lock);
			nce->nce_state = ND_REACHABLE;
			nce->nce_pcnt = ND_MAX_UNICAST_SOLICIT;
			mutex_exit(&nce->nce_lock);
			(void) untimeout(nce->nce_timeout_id);
			if (ip_debug > 2) {
				/* ip1dbg */
				pr_addr_dbg("tcp_multisend_data: state "
				    "for %s changed to REACHABLE\n",
				    AF_INET6, &ire->ire_addr_v6);
			}
		}
		/* reset transport reachability confirmation */
		*rconfirm = B_FALSE;
	}

	delta =  TICK_TO_MSEC(lbolt64) - nce->nce_last;
	ip1dbg(("tcp_multisend_data: delta = %" PRId64
	    " ill_reachable_time = %d \n", delta, ill->ill_reachable_time));

	if (delta > (uint64_t)ill->ill_reachable_time) {
		mutex_enter(&nce->nce_lock);
		switch (nce->nce_state) {
		case ND_REACHABLE:
		case ND_STALE:
			/*
			 * ND_REACHABLE is identical to ND_STALE in this
			 * specific case. If reachable time has expired for
			 * this neighbor (delta is greater than reachable
			 * time), conceptually, the neighbor cache is no
			 * longer in REACHABLE state, but already in STALE
			 * state.  So the correct transition here is to
			 * ND_DELAY.
			 */
			nce->nce_state = ND_DELAY;
			mutex_exit(&nce->nce_lock);
			NDP_RESTART_TIMER(nce,
			    ipst->ips_delay_first_probe_time);
			if (ip_debug > 3) {
				/* ip2dbg */
				pr_addr_dbg("tcp_multisend_data: state "
				    "for %s changed to DELAY\n",
				    AF_INET6, &ire->ire_addr_v6);
			}
			break;
		case ND_DELAY:
		case ND_PROBE:
			mutex_exit(&nce->nce_lock);
			/* Timers have already started */
			break;
		case ND_UNREACHABLE:
			/*
			 * ndp timer has detected that this nce is
			 * unreachable and initiated deleting this nce
			 * and all its associated IREs. This is a race
			 * where we found the ire before it was deleted
			 * and have just sent out a packet using this
			 * unreachable nce.
			 */
			mutex_exit(&nce->nce_lock);
			break;
		default:
			ASSERT(0);
		}
	}
}

/*
 * Derived from tcp_send_data().
 */
static void
tcp_lsosend_data(tcp_t *tcp, mblk_t *mp, ire_t *ire, ill_t *ill, const int mss,
    int num_lso_seg)
{
	ipha_t		*ipha;
	mblk_t		*ire_fp_mp;
	uint_t		ire_fp_mp_len;
	uint32_t	hcksum_txflags = 0;
	ipaddr_t	src;
	ipaddr_t	dst;
	uint32_t	cksum;
	uint16_t	*up;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	ip_stack_t	*ipst = tcps->tcps_netstack->netstack_ip;

	ASSERT(DB_TYPE(mp) == M_DATA);
	ASSERT(tcp->tcp_state == TCPS_ESTABLISHED);
	ASSERT(tcp->tcp_ipversion == IPV4_VERSION);
	ASSERT(tcp->tcp_connp != NULL);
	ASSERT(CONN_IS_LSO_MD_FASTPATH(tcp->tcp_connp));

	ipha = (ipha_t *)mp->b_rptr;
	src = ipha->ipha_src;
	dst = ipha->ipha_dst;

	DTRACE_PROBE2(tcp__trace__send, mblk_t *, mp, tcp_t *, tcp);

	ASSERT(ipha->ipha_ident == 0 || ipha->ipha_ident == IP_HDR_INCLUDED);
	ipha->ipha_ident = (uint16_t)atomic_add_32_nv(&ire->ire_ident,
	    num_lso_seg);
#ifndef _BIG_ENDIAN
	ipha->ipha_ident = (ipha->ipha_ident << 8) | (ipha->ipha_ident >> 8);
#endif
	if (tcp->tcp_snd_zcopy_aware) {
		if ((ill->ill_capabilities & ILL_CAPAB_ZEROCOPY) == 0 ||
		    (ill->ill_zerocopy_capab->ill_zerocopy_flags == 0))
			mp = tcp_zcopy_disable(tcp, mp);
	}

	if (ILL_HCKSUM_CAPABLE(ill) && dohwcksum) {
		ASSERT(ill->ill_hcksum_capab != NULL);
		hcksum_txflags = ill->ill_hcksum_capab->ill_hcksum_txflags;
	}

	/*
	 * Since the TCP checksum should be recalculated by h/w, we can just
	 * zero the checksum field for HCK_FULLCKSUM, or calculate partial
	 * pseudo-header checksum for HCK_PARTIALCKSUM.
	 * The partial pseudo-header excludes TCP length, that was calculated
	 * in tcp_send(), so to zero *up before further processing.
	 */
	cksum = (dst >> 16) + (dst & 0xFFFF) + (src >> 16) + (src & 0xFFFF);

	up = IPH_TCPH_CHECKSUMP(ipha, IP_SIMPLE_HDR_LENGTH);
	*up = 0;

	IP_CKSUM_XMIT_FAST(ire->ire_ipversion, hcksum_txflags, mp, ipha, up,
	    IPPROTO_TCP, IP_SIMPLE_HDR_LENGTH, ntohs(ipha->ipha_length), cksum);

	/*
	 * Append LSO flags and mss to the mp.
	 */
	lso_info_set(mp, mss, HW_LSO);

	ipha->ipha_fragment_offset_and_flags |=
	    (uint32_t)htons(ire->ire_frag_flag);

	ire_fp_mp = ire->ire_nce->nce_fp_mp;
	ire_fp_mp_len = MBLKL(ire_fp_mp);
	ASSERT(DB_TYPE(ire_fp_mp) == M_DATA);
	mp->b_rptr = (uchar_t *)ipha - ire_fp_mp_len;
	bcopy(ire_fp_mp->b_rptr, mp->b_rptr, ire_fp_mp_len);

	UPDATE_OB_PKT_COUNT(ire);
	ire->ire_last_used_time = lbolt;
	BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCOutRequests);
	BUMP_MIB(ill->ill_ip_mib, ipIfStatsHCOutTransmits);
	UPDATE_MIB(ill->ill_ip_mib, ipIfStatsHCOutOctets,
	    ntohs(ipha->ipha_length));

	DTRACE_PROBE4(ip4__physical__out__start,
	    ill_t *, NULL, ill_t *, ill, ipha_t *, ipha, mblk_t *, mp);
	FW_HOOKS(ipst->ips_ip4_physical_out_event,
	    ipst->ips_ipv4firewall_physical_out, NULL,
	    ill, ipha, mp, mp, 0, ipst);
	DTRACE_PROBE1(ip4__physical__out__end, mblk_t *, mp);
	DTRACE_IP_FASTPATH(mp, ipha, ill, ipha, NULL);

	if (mp != NULL) {
		if (ipst->ips_ipobs_enabled) {
			zoneid_t szone;

			szone = ip_get_zoneid_v4(ipha->ipha_src, mp,
			    ipst, ALL_ZONES);
			ipobs_hook(mp, IPOBS_HOOK_OUTBOUND, szone,
			    ALL_ZONES, ill, IPV4_VERSION, ire_fp_mp_len, ipst);
		}

		ILL_SEND_TX(ill, ire, tcp->tcp_connp, mp, 0);
	}
}

/*
 * tcp_send() is called by tcp_wput_data() for non-Multidata transmission
 * scheme, and returns one of the following:
 *
 * -1 = failed allocation.
 *  0 = success; burst count reached, or usable send window is too small,
 *      and that we'd rather wait until later before sending again.
 *  1 = success; we are called from tcp_multisend(), and both usable send
 *      window and tail_unsent are greater than the MDT threshold, and thus
 *      Multidata Transmit should be used instead.
 */
static int
tcp_send(queue_t *q, tcp_t *tcp, const int mss, const int tcp_hdr_len,
    const int tcp_tcp_hdr_len, const int num_sack_blk, int *usable,
    uint_t *snxt, int *tail_unsent, mblk_t **xmit_tail, mblk_t *local_time,
    const int mdt_thres)
{
	int num_burst_seg = tcp->tcp_snd_burst;
	ire_t		*ire = NULL;
	ill_t		*ill = NULL;
	mblk_t		*ire_fp_mp = NULL;
	uint_t		ire_fp_mp_len = 0;
	int		num_lso_seg = 1;
	uint_t		lso_usable;
	boolean_t	do_lso_send = B_FALSE;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	/*
	 * Check LSO capability before any further work. And the similar check
	 * need to be done in for(;;) loop.
	 * LSO will be deployed when therer is more than one mss of available
	 * data and a burst transmission is allowed.
	 */
	if (tcp->tcp_lso &&
	    (tcp->tcp_valid_bits == 0 ||
	    tcp->tcp_valid_bits == TCP_FSS_VALID) &&
	    num_burst_seg >= 2 && (*usable - 1) / mss >= 1) {
		/*
		 * Try to find usable IRE/ILL and do basic check to the ILL.
		 */
		if (tcp_send_find_ire_ill(tcp, NULL, &ire, &ill)) {
			/*
			 * Enable LSO with this transmission.
			 * Since IRE has been hold in
			 * tcp_send_find_ire_ill(), IRE_REFRELE(ire)
			 * should be called before return.
			 */
			do_lso_send = B_TRUE;
			ire_fp_mp = ire->ire_nce->nce_fp_mp;
			ire_fp_mp_len = MBLKL(ire_fp_mp);
			/* Round up to multiple of 4 */
			ire_fp_mp_len = ((ire_fp_mp_len + 3) / 4) * 4;
		} else {
			do_lso_send = B_FALSE;
			ill = NULL;
		}
	}

	for (;;) {
		struct datab	*db;
		tcph_t		*tcph;
		uint32_t	sum;
		mblk_t		*mp, *mp1;
		uchar_t		*rptr;
		int		len;

		/*
		 * If we're called by tcp_multisend(), and the amount of
		 * sendable data as well as the size of current xmit_tail
		 * is beyond the MDT threshold, return to the caller and
		 * let the large data transmit be done using MDT.
		 */
		if (*usable > 0 && *usable > mdt_thres &&
		    (*tail_unsent > mdt_thres || (*tail_unsent == 0 &&
		    MBLKL((*xmit_tail)->b_cont) > mdt_thres))) {
			ASSERT(tcp->tcp_mdt);
			return (1);	/* success; do large send */
		}

		if (num_burst_seg == 0)
			break;		/* success; burst count reached */

		/*
		 * Calculate the maximum payload length we can send in *one*
		 * time.
		 */
		if (do_lso_send) {
			/*
			 * Check whether need to do LSO any more.
			 */
			if (num_burst_seg >= 2 && (*usable - 1) / mss >= 1) {
				lso_usable = MIN(tcp->tcp_lso_max, *usable);
				lso_usable = MIN(lso_usable,
				    num_burst_seg * mss);

				num_lso_seg = lso_usable / mss;
				if (lso_usable % mss) {
					num_lso_seg++;
					tcp->tcp_last_sent_len = (ushort_t)
					    (lso_usable % mss);
				} else {
					tcp->tcp_last_sent_len = (ushort_t)mss;
				}
			} else {
				do_lso_send = B_FALSE;
				num_lso_seg = 1;
				lso_usable = mss;
			}
		}

		ASSERT(num_lso_seg <= IP_MAXPACKET / mss + 1);

		/*
		 * Adjust num_burst_seg here.
		 */
		num_burst_seg -= num_lso_seg;

		len = mss;
		if (len > *usable) {
			ASSERT(do_lso_send == B_FALSE);

			len = *usable;
			if (len <= 0) {
				/* Terminate the loop */
				break;	/* success; too small */
			}
			/*
			 * Sender silly-window avoidance.
			 * Ignore this if we are going to send a
			 * zero window probe out.
			 *
			 * TODO: force data into microscopic window?
			 *	==> (!pushed || (unsent > usable))
			 */
			if (len < (tcp->tcp_max_swnd >> 1) &&
			    (tcp->tcp_unsent - (*snxt - tcp->tcp_snxt)) > len &&
			    !((tcp->tcp_valid_bits & TCP_URG_VALID) &&
			    len == 1) && (! tcp->tcp_zero_win_probe)) {
				/*
				 * If the retransmit timer is not running
				 * we start it so that we will retransmit
				 * in the case when the the receiver has
				 * decremented the window.
				 */
				if (*snxt == tcp->tcp_snxt &&
				    *snxt == tcp->tcp_suna) {
					/*
					 * We are not supposed to send
					 * anything.  So let's wait a little
					 * bit longer before breaking SWS
					 * avoidance.
					 *
					 * What should the value be?
					 * Suggestion: MAX(init rexmit time,
					 * tcp->tcp_rto)
					 */
					TCP_TIMER_RESTART(tcp, tcp->tcp_rto);
				}
				break;	/* success; too small */
			}
		}

		tcph = tcp->tcp_tcph;

		/*
		 * The reason to adjust len here is that we need to set flags
		 * and calculate checksum.
		 */
		if (do_lso_send)
			len = lso_usable;

		*usable -= len; /* Approximate - can be adjusted later */
		if (*usable > 0)
			tcph->th_flags[0] = TH_ACK;
		else
			tcph->th_flags[0] = (TH_ACK | TH_PUSH);

		/*
		 * Prime pump for IP's checksumming on our behalf
		 * Include the adjustment for a source route if any.
		 */
		sum = len + tcp_tcp_hdr_len + tcp->tcp_sum;
		sum = (sum >> 16) + (sum & 0xFFFF);
		U16_TO_ABE16(sum, tcph->th_sum);

		U32_TO_ABE32(*snxt, tcph->th_seq);

		/*
		 * Branch off to tcp_xmit_mp() if any of the VALID bits is
		 * set.  For the case when TCP_FSS_VALID is the only valid
		 * bit (normal active close), branch off only when we think
		 * that the FIN flag needs to be set.  Note for this case,
		 * that (snxt + len) may not reflect the actual seg_len,
		 * as len may be further reduced in tcp_xmit_mp().  If len
		 * gets modified, we will end up here again.
		 */
		if (tcp->tcp_valid_bits != 0 &&
		    (tcp->tcp_valid_bits != TCP_FSS_VALID ||
		    ((*snxt + len) == tcp->tcp_fss))) {
			uchar_t		*prev_rptr;
			uint32_t	prev_snxt = tcp->tcp_snxt;

			if (*tail_unsent == 0) {
				ASSERT((*xmit_tail)->b_cont != NULL);
				*xmit_tail = (*xmit_tail)->b_cont;
				prev_rptr = (*xmit_tail)->b_rptr;
				*tail_unsent = (int)((*xmit_tail)->b_wptr -
				    (*xmit_tail)->b_rptr);
			} else {
				prev_rptr = (*xmit_tail)->b_rptr;
				(*xmit_tail)->b_rptr = (*xmit_tail)->b_wptr -
				    *tail_unsent;
			}
			mp = tcp_xmit_mp(tcp, *xmit_tail, len, NULL, NULL,
			    *snxt, B_FALSE, (uint32_t *)&len, B_FALSE);
			/* Restore tcp_snxt so we get amount sent right. */
			tcp->tcp_snxt = prev_snxt;
			if (prev_rptr == (*xmit_tail)->b_rptr) {
				/*
				 * If the previous timestamp is still in use,
				 * don't stomp on it.
				 */
				if ((*xmit_tail)->b_next == NULL) {
					(*xmit_tail)->b_prev = local_time;
					(*xmit_tail)->b_next =
					    (mblk_t *)(uintptr_t)(*snxt);
				}
			} else
				(*xmit_tail)->b_rptr = prev_rptr;

			if (mp == NULL) {
				if (ire != NULL)
					IRE_REFRELE(ire);
				return (-1);
			}
			mp1 = mp->b_cont;

			if (len <= mss) /* LSO is unusable (!do_lso_send) */
				tcp->tcp_last_sent_len = (ushort_t)len;
			while (mp1->b_cont) {
				*xmit_tail = (*xmit_tail)->b_cont;
				(*xmit_tail)->b_prev = local_time;
				(*xmit_tail)->b_next =
				    (mblk_t *)(uintptr_t)(*snxt);
				mp1 = mp1->b_cont;
			}
			*snxt += len;
			*tail_unsent = (*xmit_tail)->b_wptr - mp1->b_wptr;
			BUMP_LOCAL(tcp->tcp_obsegs);
			BUMP_MIB(&tcps->tcps_mib, tcpOutDataSegs);
			UPDATE_MIB(&tcps->tcps_mib, tcpOutDataBytes, len);
			tcp_send_data(tcp, q, mp);
			continue;
		}

		*snxt += len;	/* Adjust later if we don't send all of len */
		BUMP_MIB(&tcps->tcps_mib, tcpOutDataSegs);
		UPDATE_MIB(&tcps->tcps_mib, tcpOutDataBytes, len);

		if (*tail_unsent) {
			/* Are the bytes above us in flight? */
			rptr = (*xmit_tail)->b_wptr - *tail_unsent;
			if (rptr != (*xmit_tail)->b_rptr) {
				*tail_unsent -= len;
				if (len <= mss) /* LSO is unusable */
					tcp->tcp_last_sent_len = (ushort_t)len;
				len += tcp_hdr_len;
				if (tcp->tcp_ipversion == IPV4_VERSION)
					tcp->tcp_ipha->ipha_length = htons(len);
				else
					tcp->tcp_ip6h->ip6_plen =
					    htons(len -
					    ((char *)&tcp->tcp_ip6h[1] -
					    tcp->tcp_iphc));
				mp = dupb(*xmit_tail);
				if (mp == NULL) {
					if (ire != NULL)
						IRE_REFRELE(ire);
					return (-1);	/* out_of_mem */
				}
				mp->b_rptr = rptr;
				/*
				 * If the old timestamp is no longer in use,
				 * sample a new timestamp now.
				 */
				if ((*xmit_tail)->b_next == NULL) {
					(*xmit_tail)->b_prev = local_time;
					(*xmit_tail)->b_next =
					    (mblk_t *)(uintptr_t)(*snxt-len);
				}
				goto must_alloc;
			}
		} else {
			*xmit_tail = (*xmit_tail)->b_cont;
			ASSERT((uintptr_t)((*xmit_tail)->b_wptr -
			    (*xmit_tail)->b_rptr) <= (uintptr_t)INT_MAX);
			*tail_unsent = (int)((*xmit_tail)->b_wptr -
			    (*xmit_tail)->b_rptr);
		}

		(*xmit_tail)->b_prev = local_time;
		(*xmit_tail)->b_next = (mblk_t *)(uintptr_t)(*snxt - len);

		*tail_unsent -= len;
		if (len <= mss) /* LSO is unusable (!do_lso_send) */
			tcp->tcp_last_sent_len = (ushort_t)len;

		len += tcp_hdr_len;
		if (tcp->tcp_ipversion == IPV4_VERSION)
			tcp->tcp_ipha->ipha_length = htons(len);
		else
			tcp->tcp_ip6h->ip6_plen = htons(len -
			    ((char *)&tcp->tcp_ip6h[1] - tcp->tcp_iphc));

		mp = dupb(*xmit_tail);
		if (mp == NULL) {
			if (ire != NULL)
				IRE_REFRELE(ire);
			return (-1);	/* out_of_mem */
		}

		len = tcp_hdr_len;
		/*
		 * There are four reasons to allocate a new hdr mblk:
		 *  1) The bytes above us are in use by another packet
		 *  2) We don't have good alignment
		 *  3) The mblk is being shared
		 *  4) We don't have enough room for a header
		 */
		rptr = mp->b_rptr - len;
		if (!OK_32PTR(rptr) ||
		    ((db = mp->b_datap), db->db_ref != 2) ||
		    rptr < db->db_base + ire_fp_mp_len) {
			/* NOTE: we assume allocb returns an OK_32PTR */

		must_alloc:;
			mp1 = allocb(tcp->tcp_ip_hdr_len + TCP_MAX_HDR_LENGTH +
			    tcps->tcps_wroff_xtra + ire_fp_mp_len, BPRI_MED);
			if (mp1 == NULL) {
				freemsg(mp);
				if (ire != NULL)
					IRE_REFRELE(ire);
				return (-1);	/* out_of_mem */
			}
			mp1->b_cont = mp;
			mp = mp1;
			/* Leave room for Link Level header */
			len = tcp_hdr_len;
			rptr =
			    &mp->b_rptr[tcps->tcps_wroff_xtra + ire_fp_mp_len];
			mp->b_wptr = &rptr[len];
		}

		/*
		 * Fill in the header using the template header, and add
		 * options such as time-stamp, ECN and/or SACK, as needed.
		 */
		tcp_fill_header(tcp, rptr, (clock_t)local_time, num_sack_blk);

		mp->b_rptr = rptr;

		if (*tail_unsent) {
			int spill = *tail_unsent;

			mp1 = mp->b_cont;
			if (mp1 == NULL)
				mp1 = mp;

			/*
			 * If we're a little short, tack on more mblks until
			 * there is no more spillover.
			 */
			while (spill < 0) {
				mblk_t *nmp;
				int nmpsz;

				nmp = (*xmit_tail)->b_cont;
				nmpsz = MBLKL(nmp);

				/*
				 * Excess data in mblk; can we split it?
				 * If MDT is enabled for the connection,
				 * keep on splitting as this is a transient
				 * send path.
				 */
				if (!do_lso_send && !tcp->tcp_mdt &&
				    (spill + nmpsz > 0)) {
					/*
					 * Don't split if stream head was
					 * told to break up larger writes
					 * into smaller ones.
					 */
					if (tcp->tcp_maxpsz > 0)
						break;

					/*
					 * Next mblk is less than SMSS/2
					 * rounded up to nearest 64-byte;
					 * let it get sent as part of the
					 * next segment.
					 */
					if (tcp->tcp_localnet &&
					    !tcp->tcp_cork &&
					    (nmpsz < roundup((mss >> 1), 64)))
						break;
				}

				*xmit_tail = nmp;
				ASSERT((uintptr_t)nmpsz <= (uintptr_t)INT_MAX);
				/* Stash for rtt use later */
				(*xmit_tail)->b_prev = local_time;
				(*xmit_tail)->b_next =
				    (mblk_t *)(uintptr_t)(*snxt - len);
				mp1->b_cont = dupb(*xmit_tail);
				mp1 = mp1->b_cont;

				spill += nmpsz;
				if (mp1 == NULL) {
					*tail_unsent = spill;
					freemsg(mp);
					if (ire != NULL)
						IRE_REFRELE(ire);
					return (-1);	/* out_of_mem */
				}
			}

			/* Trim back any surplus on the last mblk */
			if (spill >= 0) {
				mp1->b_wptr -= spill;
				*tail_unsent = spill;
			} else {
				/*
				 * We did not send everything we could in
				 * order to remain within the b_cont limit.
				 */
				*usable -= spill;
				*snxt += spill;
				tcp->tcp_last_sent_len += spill;
				UPDATE_MIB(&tcps->tcps_mib,
				    tcpOutDataBytes, spill);
				/*
				 * Adjust the checksum
				 */
				tcph = (tcph_t *)(rptr + tcp->tcp_ip_hdr_len);
				sum += spill;
				sum = (sum >> 16) + (sum & 0xFFFF);
				U16_TO_ABE16(sum, tcph->th_sum);
				if (tcp->tcp_ipversion == IPV4_VERSION) {
					sum = ntohs(
					    ((ipha_t *)rptr)->ipha_length) +
					    spill;
					((ipha_t *)rptr)->ipha_length =
					    htons(sum);
				} else {
					sum = ntohs(
					    ((ip6_t *)rptr)->ip6_plen) +
					    spill;
					((ip6_t *)rptr)->ip6_plen =
					    htons(sum);
				}
				*tail_unsent = 0;
			}
		}
		if (tcp->tcp_ip_forward_progress) {
			ASSERT(tcp->tcp_ipversion == IPV6_VERSION);
			*(uint32_t *)mp->b_rptr  |= IP_FORWARD_PROG;
			tcp->tcp_ip_forward_progress = B_FALSE;
		}

		if (do_lso_send) {
			tcp_lsosend_data(tcp, mp, ire, ill, mss,
			    num_lso_seg);
			tcp->tcp_obsegs += num_lso_seg;

			TCP_STAT(tcps, tcp_lso_times);
			TCP_STAT_UPDATE(tcps, tcp_lso_pkt_out, num_lso_seg);
		} else {
			tcp_send_data(tcp, q, mp);
			BUMP_LOCAL(tcp->tcp_obsegs);
		}
	}

	if (ire != NULL)
		IRE_REFRELE(ire);
	return (0);
}

/* Unlink and return any mblk that looks like it contains a MDT info */
static mblk_t *
tcp_mdt_info_mp(mblk_t *mp)
{
	mblk_t	*prev_mp;

	for (;;) {
		prev_mp = mp;
		/* no more to process? */
		if ((mp = mp->b_cont) == NULL)
			break;

		switch (DB_TYPE(mp)) {
		case M_CTL:
			if (*(uint32_t *)mp->b_rptr != MDT_IOC_INFO_UPDATE)
				continue;
			ASSERT(prev_mp != NULL);
			prev_mp->b_cont = mp->b_cont;
			mp->b_cont = NULL;
			return (mp);
		default:
			break;
		}
	}
	return (mp);
}

/* MDT info update routine, called when IP notifies us about MDT */
static void
tcp_mdt_update(tcp_t *tcp, ill_mdt_capab_t *mdt_capab, boolean_t first)
{
	boolean_t prev_state;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	/*
	 * IP is telling us to abort MDT on this connection?  We know
	 * this because the capability is only turned off when IP
	 * encounters some pathological cases, e.g. link-layer change
	 * where the new driver doesn't support MDT, or in situation
	 * where MDT usage on the link-layer has been switched off.
	 * IP would not have sent us the initial MDT_IOC_INFO_UPDATE
	 * if the link-layer doesn't support MDT, and if it does, it
	 * will indicate that the feature is to be turned on.
	 */
	prev_state = tcp->tcp_mdt;
	tcp->tcp_mdt = (mdt_capab->ill_mdt_on != 0);
	if (!tcp->tcp_mdt && !first) {
		TCP_STAT(tcps, tcp_mdt_conn_halted3);
		ip1dbg(("tcp_mdt_update: disabling MDT for connp %p\n",
		    (void *)tcp->tcp_connp));
	}

	/*
	 * We currently only support MDT on simple TCP/{IPv4,IPv6},
	 * so disable MDT otherwise.  The checks are done here
	 * and in tcp_wput_data().
	 */
	if (tcp->tcp_mdt &&
	    (tcp->tcp_ipversion == IPV4_VERSION &&
	    tcp->tcp_ip_hdr_len != IP_SIMPLE_HDR_LENGTH) ||
	    (tcp->tcp_ipversion == IPV6_VERSION &&
	    tcp->tcp_ip_hdr_len != IPV6_HDR_LEN))
		tcp->tcp_mdt = B_FALSE;

	if (tcp->tcp_mdt) {
		if (mdt_capab->ill_mdt_version != MDT_VERSION_2) {
			cmn_err(CE_NOTE, "tcp_mdt_update: unknown MDT "
			    "version (%d), expected version is %d",
			    mdt_capab->ill_mdt_version, MDT_VERSION_2);
			tcp->tcp_mdt = B_FALSE;
			return;
		}

		/*
		 * We need the driver to be able to handle at least three
		 * spans per packet in order for tcp MDT to be utilized.
		 * The first is for the header portion, while the rest are
		 * needed to handle a packet that straddles across two
		 * virtually non-contiguous buffers; a typical tcp packet
		 * therefore consists of only two spans.  Note that we take
		 * a zero as "don't care".
		 */
		if (mdt_capab->ill_mdt_span_limit > 0 &&
		    mdt_capab->ill_mdt_span_limit < 3) {
			tcp->tcp_mdt = B_FALSE;
			return;
		}

		/* a zero means driver wants default value */
		tcp->tcp_mdt_max_pld = MIN(mdt_capab->ill_mdt_max_pld,
		    tcps->tcps_mdt_max_pbufs);
		if (tcp->tcp_mdt_max_pld == 0)
			tcp->tcp_mdt_max_pld = tcps->tcps_mdt_max_pbufs;

		/* ensure 32-bit alignment */
		tcp->tcp_mdt_hdr_head = roundup(MAX(tcps->tcps_mdt_hdr_head_min,
		    mdt_capab->ill_mdt_hdr_head), 4);
		tcp->tcp_mdt_hdr_tail = roundup(MAX(tcps->tcps_mdt_hdr_tail_min,
		    mdt_capab->ill_mdt_hdr_tail), 4);

		if (!first && !prev_state) {
			TCP_STAT(tcps, tcp_mdt_conn_resumed2);
			ip1dbg(("tcp_mdt_update: reenabling MDT for connp %p\n",
			    (void *)tcp->tcp_connp));
		}
	}
}

/* Unlink and return any mblk that looks like it contains a LSO info */
static mblk_t *
tcp_lso_info_mp(mblk_t *mp)
{
	mblk_t	*prev_mp;

	for (;;) {
		prev_mp = mp;
		/* no more to process? */
		if ((mp = mp->b_cont) == NULL)
			break;

		switch (DB_TYPE(mp)) {
		case M_CTL:
			if (*(uint32_t *)mp->b_rptr != LSO_IOC_INFO_UPDATE)
				continue;
			ASSERT(prev_mp != NULL);
			prev_mp->b_cont = mp->b_cont;
			mp->b_cont = NULL;
			return (mp);
		default:
			break;
		}
	}

	return (mp);
}

/* LSO info update routine, called when IP notifies us about LSO */
static void
tcp_lso_update(tcp_t *tcp, ill_lso_capab_t *lso_capab)
{
	tcp_stack_t *tcps = tcp->tcp_tcps;

	/*
	 * IP is telling us to abort LSO on this connection?  We know
	 * this because the capability is only turned off when IP
	 * encounters some pathological cases, e.g. link-layer change
	 * where the new NIC/driver doesn't support LSO, or in situation
	 * where LSO usage on the link-layer has been switched off.
	 * IP would not have sent us the initial LSO_IOC_INFO_UPDATE
	 * if the link-layer doesn't support LSO, and if it does, it
	 * will indicate that the feature is to be turned on.
	 */
	tcp->tcp_lso = (lso_capab->ill_lso_on != 0);
	TCP_STAT(tcps, tcp_lso_enabled);

	/*
	 * We currently only support LSO on simple TCP/IPv4,
	 * so disable LSO otherwise.  The checks are done here
	 * and in tcp_wput_data().
	 */
	if (tcp->tcp_lso &&
	    (tcp->tcp_ipversion == IPV4_VERSION &&
	    tcp->tcp_ip_hdr_len != IP_SIMPLE_HDR_LENGTH) ||
	    (tcp->tcp_ipversion == IPV6_VERSION)) {
		tcp->tcp_lso = B_FALSE;
		TCP_STAT(tcps, tcp_lso_disabled);
	} else {
		tcp->tcp_lso_max = MIN(TCP_MAX_LSO_LENGTH,
		    lso_capab->ill_lso_max);
	}
}

static void
tcp_ire_ill_check(tcp_t *tcp, ire_t *ire, ill_t *ill, boolean_t check_lso_mdt)
{
	conn_t *connp = tcp->tcp_connp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	ip_stack_t	*ipst = tcps->tcps_netstack->netstack_ip;

	ASSERT(ire != NULL);

	/*
	 * We may be in the fastpath here, and although we essentially do
	 * similar checks as in ip_bind_connected{_v6}/ip_xxinfo_return,
	 * we try to keep things as brief as possible.  After all, these
	 * are only best-effort checks, and we do more thorough ones prior
	 * to calling tcp_send()/tcp_multisend().
	 */
	if ((ipst->ips_ip_lso_outbound || ipst->ips_ip_multidata_outbound) &&
	    check_lso_mdt && !(ire->ire_type & (IRE_LOCAL | IRE_LOOPBACK)) &&
	    ill != NULL && !CONN_IPSEC_OUT_ENCAPSULATED(connp) &&
	    !(ire->ire_flags & RTF_MULTIRT) &&
	    !IPP_ENABLED(IPP_LOCAL_OUT, ipst) &&
	    CONN_IS_LSO_MD_FASTPATH(connp)) {
		if (ipst->ips_ip_lso_outbound && ILL_LSO_CAPABLE(ill)) {
			/* Cache the result */
			connp->conn_lso_ok = B_TRUE;

			ASSERT(ill->ill_lso_capab != NULL);
			if (!ill->ill_lso_capab->ill_lso_on) {
				ill->ill_lso_capab->ill_lso_on = 1;
				ip1dbg(("tcp_ire_ill_check: connp %p enables "
				    "LSO for interface %s\n", (void *)connp,
				    ill->ill_name));
			}
			tcp_lso_update(tcp, ill->ill_lso_capab);
		} else if (ipst->ips_ip_multidata_outbound &&
		    ILL_MDT_CAPABLE(ill)) {
			/* Cache the result */
			connp->conn_mdt_ok = B_TRUE;

			ASSERT(ill->ill_mdt_capab != NULL);
			if (!ill->ill_mdt_capab->ill_mdt_on) {
				ill->ill_mdt_capab->ill_mdt_on = 1;
				ip1dbg(("tcp_ire_ill_check: connp %p enables "
				    "MDT for interface %s\n", (void *)connp,
				    ill->ill_name));
			}
			tcp_mdt_update(tcp, ill->ill_mdt_capab, B_TRUE);
		}
	}

	/*
	 * The goal is to reduce the number of generated tcp segments by
	 * setting the maxpsz multiplier to 0; this will have an affect on
	 * tcp_maxpsz_set().  With this behavior, tcp will pack more data
	 * into each packet, up to SMSS bytes.  Doing this reduces the number
	 * of outbound segments and incoming ACKs, thus allowing for better
	 * network and system performance.  In contrast the legacy behavior
	 * may result in sending less than SMSS size, because the last mblk
	 * for some packets may have more data than needed to make up SMSS,
	 * and the legacy code refused to "split" it.
	 *
	 * We apply the new behavior on following situations:
	 *
	 *   1) Loopback connections,
	 *   2) Connections in which the remote peer is not on local subnet,
	 *   3) Local subnet connections over the bge interface (see below).
	 *
	 * Ideally, we would like this behavior to apply for interfaces other
	 * than bge.  However, doing so would negatively impact drivers which
	 * perform dynamic mapping and unmapping of DMA resources, which are
	 * increased by setting the maxpsz multiplier to 0 (more mblks per
	 * packet will be generated by tcp).  The bge driver does not suffer
	 * from this, as it copies the mblks into pre-mapped buffers, and
	 * therefore does not require more I/O resources than before.
	 *
	 * Otherwise, this behavior is present on all network interfaces when
	 * the destination endpoint is non-local, since reducing the number
	 * of packets in general is good for the network.
	 *
	 * TODO We need to remove this hard-coded conditional for bge once
	 *	a better "self-tuning" mechanism, or a way to comprehend
	 *	the driver transmit strategy is devised.  Until the solution
	 *	is found and well understood, we live with this hack.
	 */
	if (!tcp_static_maxpsz &&
	    (tcp->tcp_loopback || !tcp->tcp_localnet ||
	    (ill->ill_name_length > 3 && bcmp(ill->ill_name, "bge", 3) == 0))) {
		/* override the default value */
		tcp->tcp_maxpsz = 0;

		ip3dbg(("tcp_ire_ill_check: connp %p tcp_maxpsz %d on "
		    "interface %s\n", (void *)connp, tcp->tcp_maxpsz,
		    ill != NULL ? ill->ill_name : ipif_loopback_name));
	}

	/* set the stream head parameters accordingly */
	(void) tcp_maxpsz_set(tcp, B_TRUE);
}

/* tcp_wput_flush is called by tcp_wput_nondata to handle M_FLUSH messages. */
static void
tcp_wput_flush(tcp_t *tcp, mblk_t *mp)
{
	uchar_t	fval = *mp->b_rptr;
	mblk_t	*tail;
	queue_t	*q = tcp->tcp_wq;

	/* TODO: How should flush interact with urgent data? */
	if ((fval & FLUSHW) && tcp->tcp_xmit_head &&
	    !(tcp->tcp_valid_bits & TCP_URG_VALID)) {
		/*
		 * Flush only data that has not yet been put on the wire.  If
		 * we flush data that we have already transmitted, life, as we
		 * know it, may come to an end.
		 */
		tail = tcp->tcp_xmit_tail;
		tail->b_wptr -= tcp->tcp_xmit_tail_unsent;
		tcp->tcp_xmit_tail_unsent = 0;
		tcp->tcp_unsent = 0;
		if (tail->b_wptr != tail->b_rptr)
			tail = tail->b_cont;
		if (tail) {
			mblk_t **excess = &tcp->tcp_xmit_head;
			for (;;) {
				mblk_t *mp1 = *excess;
				if (mp1 == tail)
					break;
				tcp->tcp_xmit_tail = mp1;
				tcp->tcp_xmit_last = mp1;
				excess = &mp1->b_cont;
			}
			*excess = NULL;
			tcp_close_mpp(&tail);
			if (tcp->tcp_snd_zcopy_aware)
				tcp_zcopy_notify(tcp);
		}
		/*
		 * We have no unsent data, so unsent must be less than
		 * tcp_xmit_lowater, so re-enable flow.
		 */
		mutex_enter(&tcp->tcp_non_sq_lock);
		if (tcp->tcp_flow_stopped) {
			tcp_clrqfull(tcp);
		}
		mutex_exit(&tcp->tcp_non_sq_lock);
	}
	/*
	 * TODO: you can't just flush these, you have to increase rwnd for one
	 * thing.  For another, how should urgent data interact?
	 */
	if (fval & FLUSHR) {
		*mp->b_rptr = fval & ~FLUSHW;
		/* XXX */
		qreply(q, mp);
		return;
	}
	freemsg(mp);
}

/*
 * tcp_wput_iocdata is called by tcp_wput_nondata to handle all M_IOCDATA
 * messages.
 */
static void
tcp_wput_iocdata(tcp_t *tcp, mblk_t *mp)
{
	mblk_t	*mp1;
	struct iocblk *iocp = (struct iocblk *)mp->b_rptr;
	STRUCT_HANDLE(strbuf, sb);
	queue_t *q = tcp->tcp_wq;
	int	error;
	uint_t	addrlen;

	/* Make sure it is one of ours. */
	switch (iocp->ioc_cmd) {
	case TI_GETMYNAME:
	case TI_GETPEERNAME:
		break;
	default:
		CALL_IP_WPUT(tcp->tcp_connp, q, mp);
		return;
	}
	switch (mi_copy_state(q, mp, &mp1)) {
	case -1:
		return;
	case MI_COPY_CASE(MI_COPY_IN, 1):
		break;
	case MI_COPY_CASE(MI_COPY_OUT, 1):
		/* Copy out the strbuf. */
		mi_copyout(q, mp);
		return;
	case MI_COPY_CASE(MI_COPY_OUT, 2):
		/* All done. */
		mi_copy_done(q, mp, 0);
		return;
	default:
		mi_copy_done(q, mp, EPROTO);
		return;
	}
	/* Check alignment of the strbuf */
	if (!OK_32PTR(mp1->b_rptr)) {
		mi_copy_done(q, mp, EINVAL);
		return;
	}

	STRUCT_SET_HANDLE(sb, iocp->ioc_flag, (void *)mp1->b_rptr);
	addrlen = tcp->tcp_family == AF_INET ? sizeof (sin_t) : sizeof (sin6_t);
	if (STRUCT_FGET(sb, maxlen) < addrlen) {
		mi_copy_done(q, mp, EINVAL);
		return;
	}

	mp1 = mi_copyout_alloc(q, mp, STRUCT_FGETP(sb, buf), addrlen, B_TRUE);
	if (mp1 == NULL)
		return;

	switch (iocp->ioc_cmd) {
	case TI_GETMYNAME:
		error = tcp_getmyname(tcp, (void *)mp1->b_rptr, &addrlen);
		break;
	case TI_GETPEERNAME:
		error = i_tcp_getpeername(tcp, (void *)mp1->b_rptr, &addrlen);
		break;
	}

	if (error != 0) {
		mi_copy_done(q, mp, error);
	} else {
		mp1->b_wptr += addrlen;
		STRUCT_FSET(sb, len, addrlen);

		/* Copy out the address */
		mi_copyout(q, mp);
	}
}

static void
tcp_disable_direct_sockfs(tcp_t *tcp)
{
#ifdef	_ILP32
	tcp->tcp_acceptor_id = (t_uscalar_t)tcp->tcp_rq;
#else
	tcp->tcp_acceptor_id = tcp->tcp_connp->conn_dev;
#endif
	/*
	 * Insert this socket into the acceptor hash.
	 * We might need it for T_CONN_RES message
	 */
	tcp_acceptor_hash_insert(tcp->tcp_acceptor_id, tcp);

	if (tcp->tcp_fused) {
		/*
		 * This is a fused loopback tcp; disable
		 * read-side synchronous streams interface
		 * and drain any queued data.  It is okay
		 * to do this for non-synchronous streams
		 * fused tcp as well.
		 */
		tcp_fuse_disable_pair(tcp, B_FALSE);
	}
	tcp->tcp_issocket = B_FALSE;
	tcp->tcp_sodirect = NULL;
	TCP_STAT(tcp->tcp_tcps, tcp_sock_fallback);
}

/*
 * tcp_wput_ioctl is called by tcp_wput_nondata() to handle all M_IOCTL
 * messages.
 */
/* ARGSUSED */
static void
tcp_wput_ioctl(void *arg, mblk_t *mp, void *arg2)
{
	conn_t 	*connp = (conn_t *)arg;
	tcp_t	*tcp = connp->conn_tcp;
	queue_t	*q = tcp->tcp_wq;
	struct iocblk	*iocp;

	ASSERT(DB_TYPE(mp) == M_IOCTL);
	/*
	 * Try and ASSERT the minimum possible references on the
	 * conn early enough. Since we are executing on write side,
	 * the connection is obviously not detached and that means
	 * there is a ref each for TCP and IP. Since we are behind
	 * the squeue, the minimum references needed are 3. If the
	 * conn is in classifier hash list, there should be an
	 * extra ref for that (we check both the possibilities).
	 */
	ASSERT((connp->conn_fanout != NULL && connp->conn_ref >= 4) ||
	    (connp->conn_fanout == NULL && connp->conn_ref >= 3));

	iocp = (struct iocblk *)mp->b_rptr;
	switch (iocp->ioc_cmd) {
	case TCP_IOC_DEFAULT_Q:
		/* Wants to be the default wq. */
		if (secpolicy_ip_config(iocp->ioc_cr, B_FALSE) != 0) {
			iocp->ioc_error = EPERM;
			iocp->ioc_count = 0;
			mp->b_datap->db_type = M_IOCACK;
			qreply(q, mp);
			return;
		}
		tcp_def_q_set(tcp, mp);
		return;
	case _SIOCSOCKFALLBACK:
		/*
		 * Either sockmod is about to be popped and the socket
		 * would now be treated as a plain stream, or a module
		 * is about to be pushed so we could no longer use read-
		 * side synchronous streams for fused loopback tcp.
		 * Drain any queued data and disable direct sockfs
		 * interface from now on.
		 */
		if (!tcp->tcp_issocket) {
			DB_TYPE(mp) = M_IOCNAK;
			iocp->ioc_error = EINVAL;
		} else {
			tcp_disable_direct_sockfs(tcp);
			DB_TYPE(mp) = M_IOCACK;
			iocp->ioc_error = 0;
		}
		iocp->ioc_count = 0;
		iocp->ioc_rval = 0;
		qreply(q, mp);
		return;
	}
	CALL_IP_WPUT(connp, q, mp);
}

/*
 * This routine is called by tcp_wput() to handle all TPI requests.
 */
/* ARGSUSED */
static void
tcp_wput_proto(void *arg, mblk_t *mp, void *arg2)
{
	conn_t 	*connp = (conn_t *)arg;
	tcp_t	*tcp = connp->conn_tcp;
	union T_primitives *tprim = (union T_primitives *)mp->b_rptr;
	uchar_t *rptr;
	t_scalar_t type;
	cred_t *cr = DB_CREDDEF(mp, tcp->tcp_cred);

	/*
	 * Try and ASSERT the minimum possible references on the
	 * conn early enough. Since we are executing on write side,
	 * the connection is obviously not detached and that means
	 * there is a ref each for TCP and IP. Since we are behind
	 * the squeue, the minimum references needed are 3. If the
	 * conn is in classifier hash list, there should be an
	 * extra ref for that (we check both the possibilities).
	 */
	ASSERT((connp->conn_fanout != NULL && connp->conn_ref >= 4) ||
	    (connp->conn_fanout == NULL && connp->conn_ref >= 3));

	rptr = mp->b_rptr;
	ASSERT((uintptr_t)(mp->b_wptr - rptr) <= (uintptr_t)INT_MAX);
	if ((mp->b_wptr - rptr) >= sizeof (t_scalar_t)) {
		type = ((union T_primitives *)rptr)->type;
		if (type == T_EXDATA_REQ) {
			tcp_output_urgent(connp, mp->b_cont, arg2);
			freeb(mp);
		} else if (type != T_DATA_REQ) {
			goto non_urgent_data;
		} else {
			/* TODO: options, flags, ... from user */
			/* Set length to zero for reclamation below */
			tcp_wput_data(tcp, mp->b_cont, B_TRUE);
			freeb(mp);
		}
		return;
	} else {
		if (tcp->tcp_debug) {
			(void) strlog(TCP_MOD_ID, 0, 1, SL_ERROR|SL_TRACE,
			    "tcp_wput_proto, dropping one...");
		}
		freemsg(mp);
		return;
	}

non_urgent_data:

	switch ((int)tprim->type) {
	case T_SSL_PROXY_BIND_REQ:	/* an SSL proxy endpoint bind request */
		/*
		 * save the kssl_ent_t from the next block, and convert this
		 * back to a normal bind_req.
		 */
		if (mp->b_cont != NULL) {
			ASSERT(MBLKL(mp->b_cont) >= sizeof (kssl_ent_t));

			if (tcp->tcp_kssl_ent != NULL) {
				kssl_release_ent(tcp->tcp_kssl_ent, NULL,
				    KSSL_NO_PROXY);
				tcp->tcp_kssl_ent = NULL;
			}
			bcopy(mp->b_cont->b_rptr, &tcp->tcp_kssl_ent,
			    sizeof (kssl_ent_t));
			kssl_hold_ent(tcp->tcp_kssl_ent);
			freemsg(mp->b_cont);
			mp->b_cont = NULL;
		}
		tprim->type = T_BIND_REQ;

	/* FALLTHROUGH */
	case O_T_BIND_REQ:	/* bind request */
	case T_BIND_REQ:	/* new semantics bind request */
		tcp_tpi_bind(tcp, mp);
		break;
	case T_UNBIND_REQ:	/* unbind request */
		tcp_tpi_unbind(tcp, mp);
		break;
	case O_T_CONN_RES:	/* old connection response XXX */
	case T_CONN_RES:	/* connection response */
		tcp_tli_accept(tcp, mp);
		break;
	case T_CONN_REQ:	/* connection request */
		tcp_tpi_connect(tcp, mp);
		break;
	case T_DISCON_REQ:	/* disconnect request */
		tcp_disconnect(tcp, mp);
		break;
	case T_CAPABILITY_REQ:
		tcp_capability_req(tcp, mp);	/* capability request */
		break;
	case T_INFO_REQ:	/* information request */
		tcp_info_req(tcp, mp);
		break;
	case T_SVR4_OPTMGMT_REQ:	/* manage options req */
		(void) svr4_optcom_req(tcp->tcp_wq, mp, cr,
		    &tcp_opt_obj, B_TRUE);
		break;
	case T_OPTMGMT_REQ:
		/*
		 * Note:  no support for snmpcom_req() through new
		 * T_OPTMGMT_REQ. See comments in ip.c
		 */
		/* Only IP is allowed to return meaningful value */
		(void) tpi_optcom_req(tcp->tcp_wq, mp, cr, &tcp_opt_obj,
		    B_TRUE);
		break;

	case T_UNITDATA_REQ:	/* unitdata request */
		tcp_err_ack(tcp, mp, TNOTSUPPORT, 0);
		break;
	case T_ORDREL_REQ:	/* orderly release req */
		freemsg(mp);

		if (tcp->tcp_fused)
			tcp_unfuse(tcp);

		if (tcp_xmit_end(tcp) != 0) {
			/*
			 * We were crossing FINs and got a reset from
			 * the other side. Just ignore it.
			 */
			if (tcp->tcp_debug) {
				(void) strlog(TCP_MOD_ID, 0, 1,
				    SL_ERROR|SL_TRACE,
				    "tcp_wput_proto, T_ORDREL_REQ out of "
				    "state %s",
				    tcp_display(tcp, NULL,
				    DISP_ADDR_AND_PORT));
			}
		}
		break;
	case T_ADDR_REQ:
		tcp_addr_req(tcp, mp);
		break;
	default:
		if (tcp->tcp_debug) {
			(void) strlog(TCP_MOD_ID, 0, 1, SL_ERROR|SL_TRACE,
			    "tcp_wput_proto, bogus TPI msg, type %d",
			    tprim->type);
		}
		/*
		 * We used to M_ERROR.  Sending TNOTSUPPORT gives the user
		 * to recover.
		 */
		tcp_err_ack(tcp, mp, TNOTSUPPORT, 0);
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

/* Non overlapping byte exchanger */
static void
tcp_xchg(uchar_t *a, uchar_t *b, int len)
{
	uchar_t	uch;

	while (len-- > 0) {
		uch = a[len];
		a[len] = b[len];
		b[len] = uch;
	}
}

/*
 * Send out a control packet on the tcp connection specified.  This routine
 * is typically called where we need a simple ACK or RST generated.
 */
static void
tcp_xmit_ctl(char *str, tcp_t *tcp, uint32_t seq, uint32_t ack, int ctl)
{
	uchar_t		*rptr;
	tcph_t		*tcph;
	ipha_t		*ipha = NULL;
	ip6_t		*ip6h = NULL;
	uint32_t	sum;
	int		tcp_hdr_len;
	int		tcp_ip_hdr_len;
	mblk_t		*mp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	/*
	 * Save sum for use in source route later.
	 */
	ASSERT(tcp != NULL);
	sum = tcp->tcp_tcp_hdr_len + tcp->tcp_sum;
	tcp_hdr_len = tcp->tcp_hdr_len;
	tcp_ip_hdr_len = tcp->tcp_ip_hdr_len;

	/* If a text string is passed in with the request, pass it to strlog. */
	if (str != NULL && tcp->tcp_debug) {
		(void) strlog(TCP_MOD_ID, 0, 1, SL_TRACE,
		    "tcp_xmit_ctl: '%s', seq 0x%x, ack 0x%x, ctl 0x%x",
		    str, seq, ack, ctl);
	}
	mp = allocb(tcp_ip_hdr_len + TCP_MAX_HDR_LENGTH + tcps->tcps_wroff_xtra,
	    BPRI_MED);
	if (mp == NULL) {
		return;
	}
	rptr = &mp->b_rptr[tcps->tcps_wroff_xtra];
	mp->b_rptr = rptr;
	mp->b_wptr = &rptr[tcp_hdr_len];
	bcopy(tcp->tcp_iphc, rptr, tcp_hdr_len);

	if (tcp->tcp_ipversion == IPV4_VERSION) {
		ipha = (ipha_t *)rptr;
		ipha->ipha_length = htons(tcp_hdr_len);
	} else {
		ip6h = (ip6_t *)rptr;
		ASSERT(tcp != NULL);
		ip6h->ip6_plen = htons(tcp->tcp_hdr_len -
		    ((char *)&tcp->tcp_ip6h[1] - tcp->tcp_iphc));
	}
	tcph = (tcph_t *)&rptr[tcp_ip_hdr_len];
	tcph->th_flags[0] = (uint8_t)ctl;
	if (ctl & TH_RST) {
		BUMP_MIB(&tcps->tcps_mib, tcpOutRsts);
		BUMP_MIB(&tcps->tcps_mib, tcpOutControl);
		/*
		 * Don't send TSopt w/ TH_RST packets per RFC 1323.
		 */
		if (tcp->tcp_snd_ts_ok &&
		    tcp->tcp_state > TCPS_SYN_SENT) {
			mp->b_wptr = &rptr[tcp_hdr_len - TCPOPT_REAL_TS_LEN];
			*(mp->b_wptr) = TCPOPT_EOL;
			if (tcp->tcp_ipversion == IPV4_VERSION) {
				ipha->ipha_length = htons(tcp_hdr_len -
				    TCPOPT_REAL_TS_LEN);
			} else {
				ip6h->ip6_plen = htons(ntohs(ip6h->ip6_plen) -
				    TCPOPT_REAL_TS_LEN);
			}
			tcph->th_offset_and_rsrvd[0] -= (3 << 4);
			sum -= TCPOPT_REAL_TS_LEN;
		}
	}
	if (ctl & TH_ACK) {
		if (tcp->tcp_snd_ts_ok) {
			U32_TO_BE32(lbolt,
			    (char *)tcph+TCP_MIN_HEADER_LENGTH+4);
			U32_TO_BE32(tcp->tcp_ts_recent,
			    (char *)tcph+TCP_MIN_HEADER_LENGTH+8);
		}

		/* Update the latest receive window size in TCP header. */
		U32_TO_ABE16(tcp->tcp_rwnd >> tcp->tcp_rcv_ws,
		    tcph->th_win);
		tcp->tcp_rack = ack;
		tcp->tcp_rack_cnt = 0;
		BUMP_MIB(&tcps->tcps_mib, tcpOutAck);
	}
	BUMP_LOCAL(tcp->tcp_obsegs);
	U32_TO_BE32(seq, tcph->th_seq);
	U32_TO_BE32(ack, tcph->th_ack);
	/*
	 * Include the adjustment for a source route if any.
	 */
	sum = (sum >> 16) + (sum & 0xFFFF);
	U16_TO_BE16(sum, tcph->th_sum);
	tcp_send_data(tcp, tcp->tcp_wq, mp);
}

/*
 * If this routine returns B_TRUE, TCP can generate a RST in response
 * to a segment.  If it returns B_FALSE, TCP should not respond.
 */
static boolean_t
tcp_send_rst_chk(tcp_stack_t *tcps)
{
	clock_t	now;

	/*
	 * TCP needs to protect itself from generating too many RSTs.
	 * This can be a DoS attack by sending us random segments
	 * soliciting RSTs.
	 *
	 * What we do here is to have a limit of tcp_rst_sent_rate RSTs
	 * in each 1 second interval.  In this way, TCP still generate
	 * RSTs in normal cases but when under attack, the impact is
	 * limited.
	 */
	if (tcps->tcps_rst_sent_rate_enabled != 0) {
		now = lbolt;
		/* lbolt can wrap around. */
		if ((tcps->tcps_last_rst_intrvl > now) ||
		    (TICK_TO_MSEC(now - tcps->tcps_last_rst_intrvl) >
		    1*SECONDS)) {
			tcps->tcps_last_rst_intrvl = now;
			tcps->tcps_rst_cnt = 1;
		} else if (++tcps->tcps_rst_cnt > tcps->tcps_rst_sent_rate) {
			return (B_FALSE);
		}
	}
	return (B_TRUE);
}

/*
 * Send down the advice IP ioctl to tell IP to mark an IRE temporary.
 */
static void
tcp_ip_ire_mark_advice(tcp_t *tcp)
{
	mblk_t *mp;
	ipic_t *ipic;

	if (tcp->tcp_ipversion == IPV4_VERSION) {
		mp = tcp_ip_advise_mblk(&tcp->tcp_ipha->ipha_dst, IP_ADDR_LEN,
		    &ipic);
	} else {
		mp = tcp_ip_advise_mblk(&tcp->tcp_ip6h->ip6_dst, IPV6_ADDR_LEN,
		    &ipic);
	}
	if (mp == NULL)
		return;
	ipic->ipic_ire_marks |= IRE_MARK_TEMPORARY;
	CALL_IP_WPUT(tcp->tcp_connp, tcp->tcp_wq, mp);
}

/*
 * Return an IP advice ioctl mblk and set ipic to be the pointer
 * to the advice structure.
 */
static mblk_t *
tcp_ip_advise_mblk(void *addr, int addr_len, ipic_t **ipic)
{
	struct iocblk *ioc;
	mblk_t *mp, *mp1;

	mp = allocb(sizeof (ipic_t) + addr_len, BPRI_HI);
	if (mp == NULL)
		return (NULL);
	bzero(mp->b_rptr, sizeof (ipic_t) + addr_len);
	*ipic = (ipic_t *)mp->b_rptr;
	(*ipic)->ipic_cmd = IP_IOC_IRE_ADVISE_NO_REPLY;
	(*ipic)->ipic_addr_offset = sizeof (ipic_t);

	bcopy(addr, *ipic + 1, addr_len);

	(*ipic)->ipic_addr_length = addr_len;
	mp->b_wptr = &mp->b_rptr[sizeof (ipic_t) + addr_len];

	mp1 = mkiocb(IP_IOCTL);
	if (mp1 == NULL) {
		freemsg(mp);
		return (NULL);
	}
	mp1->b_cont = mp;
	ioc = (struct iocblk *)mp1->b_rptr;
	ioc->ioc_count = sizeof (ipic_t) + addr_len;

	return (mp1);
}

/*
 * Generate a reset based on an inbound packet, connp is set by caller
 * when RST is in response to an unexpected inbound packet for which
 * there is active tcp state in the system.
 *
 * IPSEC NOTE : Try to send the reply with the same protection as it came
 * in.  We still have the ipsec_mp that the packet was attached to. Thus
 * the packet will go out at the same level of protection as it came in by
 * converting the IPSEC_IN to IPSEC_OUT.
 */
static void
tcp_xmit_early_reset(char *str, mblk_t *mp, uint32_t seq,
    uint32_t ack, int ctl, uint_t ip_hdr_len, zoneid_t zoneid,
    tcp_stack_t *tcps, conn_t *connp)
{
	ipha_t		*ipha = NULL;
	ip6_t		*ip6h = NULL;
	ushort_t	len;
	tcph_t		*tcph;
	int		i;
	mblk_t		*ipsec_mp;
	boolean_t	mctl_present;
	ipic_t		*ipic;
	ipaddr_t	v4addr;
	in6_addr_t	v6addr;
	int		addr_len;
	void		*addr;
	queue_t		*q = tcps->tcps_g_q;
	tcp_t		*tcp;
	cred_t		*cr;
	mblk_t		*nmp;
	ip_stack_t	*ipst = tcps->tcps_netstack->netstack_ip;

	if (tcps->tcps_g_q == NULL) {
		/*
		 * For non-zero stackids the default queue isn't created
		 * until the first open, thus there can be a need to send
		 * a reset before then. But we can't do that, hence we just
		 * drop the packet. Later during boot, when the default queue
		 * has been setup, a retransmitted packet from the peer
		 * will result in a reset.
		 */
		ASSERT(tcps->tcps_netstack->netstack_stackid !=
		    GLOBAL_NETSTACKID);
		freemsg(mp);
		return;
	}

	if (connp != NULL)
		tcp = connp->conn_tcp;
	else
		tcp = Q_TO_TCP(q);

	if (!tcp_send_rst_chk(tcps)) {
		tcps->tcps_rst_unsent++;
		freemsg(mp);
		return;
	}

	if (mp->b_datap->db_type == M_CTL) {
		ipsec_mp = mp;
		mp = mp->b_cont;
		mctl_present = B_TRUE;
	} else {
		ipsec_mp = mp;
		mctl_present = B_FALSE;
	}

	if (str && q && tcps->tcps_dbg) {
		(void) strlog(TCP_MOD_ID, 0, 1, SL_TRACE,
		    "tcp_xmit_early_reset: '%s', seq 0x%x, ack 0x%x, "
		    "flags 0x%x",
		    str, seq, ack, ctl);
	}
	if (mp->b_datap->db_ref != 1) {
		mblk_t *mp1 = copyb(mp);
		freemsg(mp);
		mp = mp1;
		if (!mp) {
			if (mctl_present)
				freeb(ipsec_mp);
			return;
		} else {
			if (mctl_present) {
				ipsec_mp->b_cont = mp;
			} else {
				ipsec_mp = mp;
			}
		}
	} else if (mp->b_cont) {
		freemsg(mp->b_cont);
		mp->b_cont = NULL;
	}
	/*
	 * We skip reversing source route here.
	 * (for now we replace all IP options with EOL)
	 */
	if (IPH_HDR_VERSION(mp->b_rptr) == IPV4_VERSION) {
		ipha = (ipha_t *)mp->b_rptr;
		for (i = IP_SIMPLE_HDR_LENGTH; i < (int)ip_hdr_len; i++)
			mp->b_rptr[i] = IPOPT_EOL;
		/*
		 * Make sure that src address isn't flagrantly invalid.
		 * Not all broadcast address checking for the src address
		 * is possible, since we don't know the netmask of the src
		 * addr.  No check for destination address is done, since
		 * IP will not pass up a packet with a broadcast dest
		 * address to TCP.  Similar checks are done below for IPv6.
		 */
		if (ipha->ipha_src == 0 || ipha->ipha_src == INADDR_BROADCAST ||
		    CLASSD(ipha->ipha_src)) {
			freemsg(ipsec_mp);
			BUMP_MIB(&ipst->ips_ip_mib, ipIfStatsInDiscards);
			return;
		}
	} else {
		ip6h = (ip6_t *)mp->b_rptr;

		if (IN6_IS_ADDR_UNSPECIFIED(&ip6h->ip6_src) ||
		    IN6_IS_ADDR_MULTICAST(&ip6h->ip6_src)) {
			freemsg(ipsec_mp);
			BUMP_MIB(&ipst->ips_ip6_mib, ipIfStatsInDiscards);
			return;
		}

		/* Remove any extension headers assuming partial overlay */
		if (ip_hdr_len > IPV6_HDR_LEN) {
			uint8_t *to;

			to = mp->b_rptr + ip_hdr_len - IPV6_HDR_LEN;
			ovbcopy(ip6h, to, IPV6_HDR_LEN);
			mp->b_rptr += ip_hdr_len - IPV6_HDR_LEN;
			ip_hdr_len = IPV6_HDR_LEN;
			ip6h = (ip6_t *)mp->b_rptr;
			ip6h->ip6_nxt = IPPROTO_TCP;
		}
	}
	tcph = (tcph_t *)&mp->b_rptr[ip_hdr_len];
	if (tcph->th_flags[0] & TH_RST) {
		freemsg(ipsec_mp);
		return;
	}
	tcph->th_offset_and_rsrvd[0] = (5 << 4);
	len = ip_hdr_len + sizeof (tcph_t);
	mp->b_wptr = &mp->b_rptr[len];
	if (IPH_HDR_VERSION(mp->b_rptr) == IPV4_VERSION) {
		ipha->ipha_length = htons(len);
		/* Swap addresses */
		v4addr = ipha->ipha_src;
		ipha->ipha_src = ipha->ipha_dst;
		ipha->ipha_dst = v4addr;
		ipha->ipha_ident = 0;
		ipha->ipha_ttl = (uchar_t)tcps->tcps_ipv4_ttl;
		addr_len = IP_ADDR_LEN;
		addr = &v4addr;
	} else {
		/* No ip6i_t in this case */
		ip6h->ip6_plen = htons(len - IPV6_HDR_LEN);
		/* Swap addresses */
		v6addr = ip6h->ip6_src;
		ip6h->ip6_src = ip6h->ip6_dst;
		ip6h->ip6_dst = v6addr;
		ip6h->ip6_hops = (uchar_t)tcps->tcps_ipv6_hoplimit;
		addr_len = IPV6_ADDR_LEN;
		addr = &v6addr;
	}
	tcp_xchg(tcph->th_fport, tcph->th_lport, 2);
	U32_TO_BE32(ack, tcph->th_ack);
	U32_TO_BE32(seq, tcph->th_seq);
	U16_TO_BE16(0, tcph->th_win);
	U16_TO_BE16(sizeof (tcph_t), tcph->th_sum);
	tcph->th_flags[0] = (uint8_t)ctl;
	if (ctl & TH_RST) {
		BUMP_MIB(&tcps->tcps_mib, tcpOutRsts);
		BUMP_MIB(&tcps->tcps_mib, tcpOutControl);
	}

	/* IP trusts us to set up labels when required. */
	if (is_system_labeled() && (cr = DB_CRED(mp)) != NULL &&
	    crgetlabel(cr) != NULL) {
		int err;

		if (IPH_HDR_VERSION(mp->b_rptr) == IPV4_VERSION)
			err = tsol_check_label(cr, &mp,
			    tcp->tcp_connp->conn_mac_exempt,
			    tcps->tcps_netstack->netstack_ip);
		else
			err = tsol_check_label_v6(cr, &mp,
			    tcp->tcp_connp->conn_mac_exempt,
			    tcps->tcps_netstack->netstack_ip);
		if (mctl_present)
			ipsec_mp->b_cont = mp;
		else
			ipsec_mp = mp;
		if (err != 0) {
			freemsg(ipsec_mp);
			return;
		}
		if (IPH_HDR_VERSION(mp->b_rptr) == IPV4_VERSION) {
			ipha = (ipha_t *)mp->b_rptr;
		} else {
			ip6h = (ip6_t *)mp->b_rptr;
		}
	}

	if (mctl_present) {
		ipsec_in_t *ii = (ipsec_in_t *)ipsec_mp->b_rptr;

		ASSERT(ii->ipsec_in_type == IPSEC_IN);
		if (!ipsec_in_to_out(ipsec_mp, ipha, ip6h)) {
			return;
		}
	}
	if (zoneid == ALL_ZONES)
		zoneid = GLOBAL_ZONEID;

	/* Add the zoneid so ip_output routes it properly */
	if ((nmp = ip_prepend_zoneid(ipsec_mp, zoneid, ipst)) == NULL) {
		freemsg(ipsec_mp);
		return;
	}
	ipsec_mp = nmp;

	/*
	 * NOTE:  one might consider tracing a TCP packet here, but
	 * this function has no active TCP state and no tcp structure
	 * that has a trace buffer.  If we traced here, we would have
	 * to keep a local trace buffer in tcp_record_trace().
	 *
	 * TSol note: The mblk that contains the incoming packet was
	 * reused by tcp_xmit_listener_reset, so it already contains
	 * the right credentials and we don't need to call mblk_setcred.
	 * Also the conn's cred is not right since it is associated
	 * with tcps_g_q.
	 */
	CALL_IP_WPUT(tcp->tcp_connp, tcp->tcp_wq, ipsec_mp);

	/*
	 * Tell IP to mark the IRE used for this destination temporary.
	 * This way, we can limit our exposure to DoS attack because IP
	 * creates an IRE for each destination.  If there are too many,
	 * the time to do any routing lookup will be extremely long.  And
	 * the lookup can be in interrupt context.
	 *
	 * Note that in normal circumstances, this marking should not
	 * affect anything.  It would be nice if only 1 message is
	 * needed to inform IP that the IRE created for this RST should
	 * not be added to the cache table.  But there is currently
	 * not such communication mechanism between TCP and IP.  So
	 * the best we can do now is to send the advice ioctl to IP
	 * to mark the IRE temporary.
	 */
	if ((mp = tcp_ip_advise_mblk(addr, addr_len, &ipic)) != NULL) {
		ipic->ipic_ire_marks |= IRE_MARK_TEMPORARY;
		CALL_IP_WPUT(tcp->tcp_connp, tcp->tcp_wq, mp);
	}
}

/*
 * Initiate closedown sequence on an active connection.  (May be called as
 * writer.)  Return value zero for OK return, non-zero for error return.
 */
static int
tcp_xmit_end(tcp_t *tcp)
{
	ipic_t	*ipic;
	mblk_t	*mp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	if (tcp->tcp_state < TCPS_SYN_RCVD ||
	    tcp->tcp_state > TCPS_CLOSE_WAIT) {
		/*
		 * Invalid state, only states TCPS_SYN_RCVD,
		 * TCPS_ESTABLISHED and TCPS_CLOSE_WAIT are valid
		 */
		return (-1);
	}

	tcp->tcp_fss = tcp->tcp_snxt + tcp->tcp_unsent;
	tcp->tcp_valid_bits |= TCP_FSS_VALID;
	/*
	 * If there is nothing more unsent, send the FIN now.
	 * Otherwise, it will go out with the last segment.
	 */
	if (tcp->tcp_unsent == 0) {
		mp = tcp_xmit_mp(tcp, NULL, 0, NULL, NULL,
		    tcp->tcp_fss, B_FALSE, NULL, B_FALSE);

		if (mp) {
			tcp_send_data(tcp, tcp->tcp_wq, mp);
		} else {
			/*
			 * Couldn't allocate msg.  Pretend we got it out.
			 * Wait for rexmit timeout.
			 */
			tcp->tcp_snxt = tcp->tcp_fss + 1;
			TCP_TIMER_RESTART(tcp, tcp->tcp_rto);
		}

		/*
		 * If needed, update tcp_rexmit_snxt as tcp_snxt is
		 * changed.
		 */
		if (tcp->tcp_rexmit && tcp->tcp_rexmit_nxt == tcp->tcp_fss) {
			tcp->tcp_rexmit_nxt = tcp->tcp_snxt;
		}
	} else {
		/*
		 * If tcp->tcp_cork is set, then the data will not get sent,
		 * so we have to check that and unset it first.
		 */
		if (tcp->tcp_cork)
			tcp->tcp_cork = B_FALSE;
		tcp_wput_data(tcp, NULL, B_FALSE);
	}

	/*
	 * If TCP does not get enough samples of RTT or tcp_rtt_updates
	 * is 0, don't update the cache.
	 */
	if (tcps->tcps_rtt_updates == 0 ||
	    tcp->tcp_rtt_update < tcps->tcps_rtt_updates)
		return (0);

	/*
	 * NOTE: should not update if source routes i.e. if tcp_remote if
	 * different from the destination.
	 */
	if (tcp->tcp_ipversion == IPV4_VERSION) {
		if (tcp->tcp_remote !=  tcp->tcp_ipha->ipha_dst) {
			return (0);
		}
		mp = tcp_ip_advise_mblk(&tcp->tcp_ipha->ipha_dst, IP_ADDR_LEN,
		    &ipic);
	} else {
		if (!(IN6_ARE_ADDR_EQUAL(&tcp->tcp_remote_v6,
		    &tcp->tcp_ip6h->ip6_dst))) {
			return (0);
		}
		mp = tcp_ip_advise_mblk(&tcp->tcp_ip6h->ip6_dst, IPV6_ADDR_LEN,
		    &ipic);
	}

	/* Record route attributes in the IRE for use by future connections. */
	if (mp == NULL)
		return (0);

	/*
	 * We do not have a good algorithm to update ssthresh at this time.
	 * So don't do any update.
	 */
	ipic->ipic_rtt = tcp->tcp_rtt_sa;
	ipic->ipic_rtt_sd = tcp->tcp_rtt_sd;

	CALL_IP_WPUT(tcp->tcp_connp, tcp->tcp_wq, mp);

	return (0);
}

/*
 * Generate a "no listener here" RST in response to an "unknown" segment.
 * connp is set by caller when RST is in response to an unexpected
 * inbound packet for which there is active tcp state in the system.
 * Note that we are reusing the incoming mp to construct the outgoing RST.
 */
void
tcp_xmit_listeners_reset(mblk_t *mp, uint_t ip_hdr_len, zoneid_t zoneid,
    tcp_stack_t *tcps, conn_t *connp)
{
	uchar_t		*rptr;
	uint32_t	seg_len;
	tcph_t		*tcph;
	uint32_t	seg_seq;
	uint32_t	seg_ack;
	uint_t		flags;
	mblk_t		*ipsec_mp;
	ipha_t 		*ipha;
	ip6_t 		*ip6h;
	boolean_t	mctl_present = B_FALSE;
	boolean_t	check = B_TRUE;
	boolean_t	policy_present;
	ipsec_stack_t	*ipss = tcps->tcps_netstack->netstack_ipsec;

	TCP_STAT(tcps, tcp_no_listener);

	ipsec_mp = mp;

	if (mp->b_datap->db_type == M_CTL) {
		ipsec_in_t *ii;

		mctl_present = B_TRUE;
		mp = mp->b_cont;

		ii = (ipsec_in_t *)ipsec_mp->b_rptr;
		ASSERT(ii->ipsec_in_type == IPSEC_IN);
		if (ii->ipsec_in_dont_check) {
			check = B_FALSE;
			if (!ii->ipsec_in_secure) {
				freeb(ipsec_mp);
				mctl_present = B_FALSE;
				ipsec_mp = mp;
			}
		}
	}

	if (IPH_HDR_VERSION(mp->b_rptr) == IPV4_VERSION) {
		policy_present = ipss->ipsec_inbound_v4_policy_present;
		ipha = (ipha_t *)mp->b_rptr;
		ip6h = NULL;
	} else {
		policy_present = ipss->ipsec_inbound_v6_policy_present;
		ipha = NULL;
		ip6h = (ip6_t *)mp->b_rptr;
	}

	if (check && policy_present) {
		/*
		 * The conn_t parameter is NULL because we already know
		 * nobody's home.
		 */
		ipsec_mp = ipsec_check_global_policy(
		    ipsec_mp, (conn_t *)NULL, ipha, ip6h, mctl_present,
		    tcps->tcps_netstack);
		if (ipsec_mp == NULL)
			return;
	}
	if (is_system_labeled() && !tsol_can_reply_error(mp)) {
		DTRACE_PROBE2(
		    tx__ip__log__error__nolistener__tcp,
		    char *, "Could not reply with RST to mp(1)",
		    mblk_t *, mp);
		ip2dbg(("tcp_xmit_listeners_reset: not permitted to reply\n"));
		freemsg(ipsec_mp);
		return;
	}

	rptr = mp->b_rptr;

	tcph = (tcph_t *)&rptr[ip_hdr_len];
	seg_seq = BE32_TO_U32(tcph->th_seq);
	seg_ack = BE32_TO_U32(tcph->th_ack);
	flags = tcph->th_flags[0];

	seg_len = msgdsize(mp) - (TCP_HDR_LENGTH(tcph) + ip_hdr_len);
	if (flags & TH_RST) {
		freemsg(ipsec_mp);
	} else if (flags & TH_ACK) {
		tcp_xmit_early_reset("no tcp, reset",
		    ipsec_mp, seg_ack, 0, TH_RST, ip_hdr_len, zoneid, tcps,
		    connp);
	} else {
		if (flags & TH_SYN) {
			seg_len++;
		} else {
			/*
			 * Here we violate the RFC.  Note that a normal
			 * TCP will never send a segment without the ACK
			 * flag, except for RST or SYN segment.  This
			 * segment is neither.  Just drop it on the
			 * floor.
			 */
			freemsg(ipsec_mp);
			tcps->tcps_rst_unsent++;
			return;
		}

		tcp_xmit_early_reset("no tcp, reset/ack",
		    ipsec_mp, 0, seg_seq + seg_len,
		    TH_RST | TH_ACK, ip_hdr_len, zoneid, tcps, connp);
	}
}

/*
 * tcp_xmit_mp is called to return a pointer to an mblk chain complete with
 * ip and tcp header ready to pass down to IP.  If the mp passed in is
 * non-NULL, then up to max_to_send bytes of data will be dup'ed off that
 * mblk. (If sendall is not set the dup'ing will stop at an mblk boundary
 * otherwise it will dup partial mblks.)
 * Otherwise, an appropriate ACK packet will be generated.  This
 * routine is not usually called to send new data for the first time.  It
 * is mostly called out of the timer for retransmits, and to generate ACKs.
 *
 * If offset is not NULL, the returned mblk chain's first mblk's b_rptr will
 * be adjusted by *offset.  And after dupb(), the offset and the ending mblk
 * of the original mblk chain will be returned in *offset and *end_mp.
 */
mblk_t *
tcp_xmit_mp(tcp_t *tcp, mblk_t *mp, int32_t max_to_send, int32_t *offset,
    mblk_t **end_mp, uint32_t seq, boolean_t sendall, uint32_t *seg_len,
    boolean_t rexmit)
{
	int	data_length;
	int32_t	off = 0;
	uint_t	flags;
	mblk_t	*mp1;
	mblk_t	*mp2;
	uchar_t	*rptr;
	tcph_t	*tcph;
	int32_t	num_sack_blk = 0;
	int32_t	sack_opt_len = 0;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	/* Allocate for our maximum TCP header + link-level */
	mp1 = allocb(tcp->tcp_ip_hdr_len + TCP_MAX_HDR_LENGTH +
	    tcps->tcps_wroff_xtra, BPRI_MED);
	if (!mp1)
		return (NULL);
	data_length = 0;

	/*
	 * Note that tcp_mss has been adjusted to take into account the
	 * timestamp option if applicable.  Because SACK options do not
	 * appear in every TCP segments and they are of variable lengths,
	 * they cannot be included in tcp_mss.  Thus we need to calculate
	 * the actual segment length when we need to send a segment which
	 * includes SACK options.
	 */
	if (tcp->tcp_snd_sack_ok && tcp->tcp_num_sack_blk > 0) {
		num_sack_blk = MIN(tcp->tcp_max_sack_blk,
		    tcp->tcp_num_sack_blk);
		sack_opt_len = num_sack_blk * sizeof (sack_blk_t) +
		    TCPOPT_NOP_LEN * 2 + TCPOPT_HEADER_LEN;
		if (max_to_send + sack_opt_len > tcp->tcp_mss)
			max_to_send -= sack_opt_len;
	}

	if (offset != NULL) {
		off = *offset;
		/* We use offset as an indicator that end_mp is not NULL. */
		*end_mp = NULL;
	}
	for (mp2 = mp1; mp && data_length != max_to_send; mp = mp->b_cont) {
		/* This could be faster with cooperation from downstream */
		if (mp2 != mp1 && !sendall &&
		    data_length + (int)(mp->b_wptr - mp->b_rptr) >
		    max_to_send)
			/*
			 * Don't send the next mblk since the whole mblk
			 * does not fit.
			 */
			break;
		mp2->b_cont = dupb(mp);
		mp2 = mp2->b_cont;
		if (!mp2) {
			freemsg(mp1);
			return (NULL);
		}
		mp2->b_rptr += off;
		ASSERT((uintptr_t)(mp2->b_wptr - mp2->b_rptr) <=
		    (uintptr_t)INT_MAX);

		data_length += (int)(mp2->b_wptr - mp2->b_rptr);
		if (data_length > max_to_send) {
			mp2->b_wptr -= data_length - max_to_send;
			data_length = max_to_send;
			off = mp2->b_wptr - mp->b_rptr;
			break;
		} else {
			off = 0;
		}
	}
	if (offset != NULL) {
		*offset = off;
		*end_mp = mp;
	}
	if (seg_len != NULL) {
		*seg_len = data_length;
	}

	/* Update the latest receive window size in TCP header. */
	U32_TO_ABE16(tcp->tcp_rwnd >> tcp->tcp_rcv_ws,
	    tcp->tcp_tcph->th_win);

	rptr = mp1->b_rptr + tcps->tcps_wroff_xtra;
	mp1->b_rptr = rptr;
	mp1->b_wptr = rptr + tcp->tcp_hdr_len + sack_opt_len;
	bcopy(tcp->tcp_iphc, rptr, tcp->tcp_hdr_len);
	tcph = (tcph_t *)&rptr[tcp->tcp_ip_hdr_len];
	U32_TO_ABE32(seq, tcph->th_seq);

	/*
	 * Use tcp_unsent to determine if the PUSH bit should be used assumes
	 * that this function was called from tcp_wput_data. Thus, when called
	 * to retransmit data the setting of the PUSH bit may appear some
	 * what random in that it might get set when it should not. This
	 * should not pose any performance issues.
	 */
	if (data_length != 0 && (tcp->tcp_unsent == 0 ||
	    tcp->tcp_unsent == data_length)) {
		flags = TH_ACK | TH_PUSH;
	} else {
		flags = TH_ACK;
	}

	if (tcp->tcp_ecn_ok) {
		if (tcp->tcp_ecn_echo_on)
			flags |= TH_ECE;

		/*
		 * Only set ECT bit and ECN_CWR if a segment contains new data.
		 * There is no TCP flow control for non-data segments, and
		 * only data segment is transmitted reliably.
		 */
		if (data_length > 0 && !rexmit) {
			SET_ECT(tcp, rptr);
			if (tcp->tcp_cwr && !tcp->tcp_ecn_cwr_sent) {
				flags |= TH_CWR;
				tcp->tcp_ecn_cwr_sent = B_TRUE;
			}
		}
	}

	if (tcp->tcp_valid_bits) {
		uint32_t u1;

		if ((tcp->tcp_valid_bits & TCP_ISS_VALID) &&
		    seq == tcp->tcp_iss) {
			uchar_t	*wptr;

			/*
			 * If TCP_ISS_VALID and the seq number is tcp_iss,
			 * TCP can only be in SYN-SENT, SYN-RCVD or
			 * FIN-WAIT-1 state.  It can be FIN-WAIT-1 if
			 * our SYN is not ack'ed but the app closes this
			 * TCP connection.
			 */
			ASSERT(tcp->tcp_state == TCPS_SYN_SENT ||
			    tcp->tcp_state == TCPS_SYN_RCVD ||
			    tcp->tcp_state == TCPS_FIN_WAIT_1);

			/*
			 * Tack on the MSS option.  It is always needed
			 * for both active and passive open.
			 *
			 * MSS option value should be interface MTU - MIN
			 * TCP/IP header according to RFC 793 as it means
			 * the maximum segment size TCP can receive.  But
			 * to get around some broken middle boxes/end hosts
			 * out there, we allow the option value to be the
			 * same as the MSS option size on the peer side.
			 * In this way, the other side will not send
			 * anything larger than they can receive.
			 *
			 * Note that for SYN_SENT state, the ndd param
			 * tcp_use_smss_as_mss_opt has no effect as we
			 * don't know the peer's MSS option value. So
			 * the only case we need to take care of is in
			 * SYN_RCVD state, which is done later.
			 */
			wptr = mp1->b_wptr;
			wptr[0] = TCPOPT_MAXSEG;
			wptr[1] = TCPOPT_MAXSEG_LEN;
			wptr += 2;
			u1 = tcp->tcp_if_mtu -
			    (tcp->tcp_ipversion == IPV4_VERSION ?
			    IP_SIMPLE_HDR_LENGTH : IPV6_HDR_LEN) -
			    TCP_MIN_HEADER_LENGTH;
			U16_TO_BE16(u1, wptr);
			mp1->b_wptr = wptr + 2;
			/* Update the offset to cover the additional word */
			tcph->th_offset_and_rsrvd[0] += (1 << 4);

			/*
			 * Note that the following way of filling in
			 * TCP options are not optimal.  Some NOPs can
			 * be saved.  But there is no need at this time
			 * to optimize it.  When it is needed, we will
			 * do it.
			 */
			switch (tcp->tcp_state) {
			case TCPS_SYN_SENT:
				flags = TH_SYN;

				if (tcp->tcp_snd_ts_ok) {
					uint32_t llbolt = (uint32_t)lbolt;

					wptr = mp1->b_wptr;
					wptr[0] = TCPOPT_NOP;
					wptr[1] = TCPOPT_NOP;
					wptr[2] = TCPOPT_TSTAMP;
					wptr[3] = TCPOPT_TSTAMP_LEN;
					wptr += 4;
					U32_TO_BE32(llbolt, wptr);
					wptr += 4;
					ASSERT(tcp->tcp_ts_recent == 0);
					U32_TO_BE32(0L, wptr);
					mp1->b_wptr += TCPOPT_REAL_TS_LEN;
					tcph->th_offset_and_rsrvd[0] +=
					    (3 << 4);
				}

				/*
				 * Set up all the bits to tell other side
				 * we are ECN capable.
				 */
				if (tcp->tcp_ecn_ok) {
					flags |= (TH_ECE | TH_CWR);
				}
				break;
			case TCPS_SYN_RCVD:
				flags |= TH_SYN;

				/*
				 * Reset the MSS option value to be SMSS
				 * We should probably add back the bytes
				 * for timestamp option and IPsec.  We
				 * don't do that as this is a workaround
				 * for broken middle boxes/end hosts, it
				 * is better for us to be more cautious.
				 * They may not take these things into
				 * account in their SMSS calculation.  Thus
				 * the peer's calculated SMSS may be smaller
				 * than what it can be.  This should be OK.
				 */
				if (tcps->tcps_use_smss_as_mss_opt) {
					u1 = tcp->tcp_mss;
					U16_TO_BE16(u1, wptr);
				}

				/*
				 * If the other side is ECN capable, reply
				 * that we are also ECN capable.
				 */
				if (tcp->tcp_ecn_ok)
					flags |= TH_ECE;
				break;
			default:
				/*
				 * The above ASSERT() makes sure that this
				 * must be FIN-WAIT-1 state.  Our SYN has
				 * not been ack'ed so retransmit it.
				 */
				flags |= TH_SYN;
				break;
			}

			if (tcp->tcp_snd_ws_ok) {
				wptr = mp1->b_wptr;
				wptr[0] =  TCPOPT_NOP;
				wptr[1] =  TCPOPT_WSCALE;
				wptr[2] =  TCPOPT_WS_LEN;
				wptr[3] = (uchar_t)tcp->tcp_rcv_ws;
				mp1->b_wptr += TCPOPT_REAL_WS_LEN;
				tcph->th_offset_and_rsrvd[0] += (1 << 4);
			}

			if (tcp->tcp_snd_sack_ok) {
				wptr = mp1->b_wptr;
				wptr[0] = TCPOPT_NOP;
				wptr[1] = TCPOPT_NOP;
				wptr[2] = TCPOPT_SACK_PERMITTED;
				wptr[3] = TCPOPT_SACK_OK_LEN;
				mp1->b_wptr += TCPOPT_REAL_SACK_OK_LEN;
				tcph->th_offset_and_rsrvd[0] += (1 << 4);
			}

			/* allocb() of adequate mblk assures space */
			ASSERT((uintptr_t)(mp1->b_wptr - mp1->b_rptr) <=
			    (uintptr_t)INT_MAX);
			u1 = (int)(mp1->b_wptr - mp1->b_rptr);
			/*
			 * Get IP set to checksum on our behalf
			 * Include the adjustment for a source route if any.
			 */
			u1 += tcp->tcp_sum;
			u1 = (u1 >> 16) + (u1 & 0xFFFF);
			U16_TO_BE16(u1, tcph->th_sum);
			BUMP_MIB(&tcps->tcps_mib, tcpOutControl);
		}
		if ((tcp->tcp_valid_bits & TCP_FSS_VALID) &&
		    (seq + data_length) == tcp->tcp_fss) {
			if (!tcp->tcp_fin_acked) {
				flags |= TH_FIN;
				BUMP_MIB(&tcps->tcps_mib, tcpOutControl);
			}
			if (!tcp->tcp_fin_sent) {
				tcp->tcp_fin_sent = B_TRUE;
				switch (tcp->tcp_state) {
				case TCPS_SYN_RCVD:
				case TCPS_ESTABLISHED:
					tcp->tcp_state = TCPS_FIN_WAIT_1;
					break;
				case TCPS_CLOSE_WAIT:
					tcp->tcp_state = TCPS_LAST_ACK;
					break;
				}
				if (tcp->tcp_suna == tcp->tcp_snxt)
					TCP_TIMER_RESTART(tcp, tcp->tcp_rto);
				tcp->tcp_snxt = tcp->tcp_fss + 1;
			}
		}
		/*
		 * Note the trick here.  u1 is unsigned.  When tcp_urg
		 * is smaller than seq, u1 will become a very huge value.
		 * So the comparison will fail.  Also note that tcp_urp
		 * should be positive, see RFC 793 page 17.
		 */
		u1 = tcp->tcp_urg - seq + TCP_OLD_URP_INTERPRETATION;
		if ((tcp->tcp_valid_bits & TCP_URG_VALID) && u1 != 0 &&
		    u1 < (uint32_t)(64 * 1024)) {
			flags |= TH_URG;
			BUMP_MIB(&tcps->tcps_mib, tcpOutUrg);
			U32_TO_ABE16(u1, tcph->th_urp);
		}
	}
	tcph->th_flags[0] = (uchar_t)flags;
	tcp->tcp_rack = tcp->tcp_rnxt;
	tcp->tcp_rack_cnt = 0;

	if (tcp->tcp_snd_ts_ok) {
		if (tcp->tcp_state != TCPS_SYN_SENT) {
			uint32_t llbolt = (uint32_t)lbolt;

			U32_TO_BE32(llbolt,
			    (char *)tcph+TCP_MIN_HEADER_LENGTH+4);
			U32_TO_BE32(tcp->tcp_ts_recent,
			    (char *)tcph+TCP_MIN_HEADER_LENGTH+8);
		}
	}

	if (num_sack_blk > 0) {
		uchar_t *wptr = (uchar_t *)tcph + tcp->tcp_tcp_hdr_len;
		sack_blk_t *tmp;
		int32_t	i;

		wptr[0] = TCPOPT_NOP;
		wptr[1] = TCPOPT_NOP;
		wptr[2] = TCPOPT_SACK;
		wptr[3] = TCPOPT_HEADER_LEN + num_sack_blk *
		    sizeof (sack_blk_t);
		wptr += TCPOPT_REAL_SACK_LEN;

		tmp = tcp->tcp_sack_list;
		for (i = 0; i < num_sack_blk; i++) {
			U32_TO_BE32(tmp[i].begin, wptr);
			wptr += sizeof (tcp_seq);
			U32_TO_BE32(tmp[i].end, wptr);
			wptr += sizeof (tcp_seq);
		}
		tcph->th_offset_and_rsrvd[0] += ((num_sack_blk * 2 + 1) << 4);
	}
	ASSERT((uintptr_t)(mp1->b_wptr - rptr) <= (uintptr_t)INT_MAX);
	data_length += (int)(mp1->b_wptr - rptr);
	if (tcp->tcp_ipversion == IPV4_VERSION) {
		((ipha_t *)rptr)->ipha_length = htons(data_length);
	} else {
		ip6_t *ip6 = (ip6_t *)(rptr +
		    (((ip6_t *)rptr)->ip6_nxt == IPPROTO_RAW ?
		    sizeof (ip6i_t) : 0));

		ip6->ip6_plen = htons(data_length -
		    ((char *)&tcp->tcp_ip6h[1] - tcp->tcp_iphc));
	}

	/*
	 * Prime pump for IP
	 * Include the adjustment for a source route if any.
	 */
	data_length -= tcp->tcp_ip_hdr_len;
	data_length += tcp->tcp_sum;
	data_length = (data_length >> 16) + (data_length & 0xFFFF);
	U16_TO_ABE16(data_length, tcph->th_sum);
	if (tcp->tcp_ip_forward_progress) {
		ASSERT(tcp->tcp_ipversion == IPV6_VERSION);
		*(uint32_t *)mp1->b_rptr  |= IP_FORWARD_PROG;
		tcp->tcp_ip_forward_progress = B_FALSE;
	}
	return (mp1);
}

/* This function handles the push timeout. */
void
tcp_push_timer(void *arg)
{
	conn_t	*connp = (conn_t *)arg;
	tcp_t *tcp = connp->conn_tcp;
	uint_t		flags;
	sodirect_t	*sodp;

	TCP_DBGSTAT(tcp->tcp_tcps, tcp_push_timer_cnt);

	ASSERT(tcp->tcp_listener == NULL);

	ASSERT(!IPCL_IS_NONSTR(connp));

	/*
	 * We need to plug synchronous streams during our drain to prevent
	 * a race with tcp_fuse_rrw() or tcp_fusion_rinfop().
	 */
	TCP_FUSE_SYNCSTR_PLUG_DRAIN(tcp);
	tcp->tcp_push_tid = 0;

	SOD_PTR_ENTER(tcp, sodp);
	if (sodp != NULL) {
		flags = tcp_rcv_sod_wakeup(tcp, sodp);
		/* sod_wakeup() does the mutex_exit() */
	} else if (tcp->tcp_rcv_list != NULL) {
		flags = tcp_rcv_drain(tcp);
	}
	if (flags == TH_ACK_NEEDED)
		tcp_xmit_ctl(NULL, tcp, tcp->tcp_snxt, tcp->tcp_rnxt, TH_ACK);

	TCP_FUSE_SYNCSTR_UNPLUG_DRAIN(tcp);
}

/*
 * This function handles delayed ACK timeout.
 */
static void
tcp_ack_timer(void *arg)
{
	conn_t	*connp = (conn_t *)arg;
	tcp_t *tcp = connp->conn_tcp;
	mblk_t *mp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	TCP_DBGSTAT(tcps, tcp_ack_timer_cnt);

	tcp->tcp_ack_tid = 0;

	if (tcp->tcp_fused)
		return;

	/*
	 * Do not send ACK if there is no outstanding unack'ed data.
	 */
	if (tcp->tcp_rnxt == tcp->tcp_rack) {
		return;
	}

	if ((tcp->tcp_rnxt - tcp->tcp_rack) > tcp->tcp_mss) {
		/*
		 * Make sure we don't allow deferred ACKs to result in
		 * timer-based ACKing.  If we have held off an ACK
		 * when there was more than an mss here, and the timer
		 * goes off, we have to worry about the possibility
		 * that the sender isn't doing slow-start, or is out
		 * of step with us for some other reason.  We fall
		 * permanently back in the direction of
		 * ACK-every-other-packet as suggested in RFC 1122.
		 */
		if (tcp->tcp_rack_abs_max > 2)
			tcp->tcp_rack_abs_max--;
		tcp->tcp_rack_cur_max = 2;
	}
	mp = tcp_ack_mp(tcp);

	if (mp != NULL) {
		BUMP_LOCAL(tcp->tcp_obsegs);
		BUMP_MIB(&tcps->tcps_mib, tcpOutAck);
		BUMP_MIB(&tcps->tcps_mib, tcpOutAckDelayed);
		tcp_send_data(tcp, tcp->tcp_wq, mp);
	}
}


/* Generate an ACK-only (no data) segment for a TCP endpoint */
static mblk_t *
tcp_ack_mp(tcp_t *tcp)
{
	uint32_t	seq_no;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	/*
	 * There are a few cases to be considered while setting the sequence no.
	 * Essentially, we can come here while processing an unacceptable pkt
	 * in the TCPS_SYN_RCVD state, in which case we set the sequence number
	 * to snxt (per RFC 793), note the swnd wouldn't have been set yet.
	 * If we are here for a zero window probe, stick with suna. In all
	 * other cases, we check if suna + swnd encompasses snxt and set
	 * the sequence number to snxt, if so. If snxt falls outside the
	 * window (the receiver probably shrunk its window), we will go with
	 * suna + swnd, otherwise the sequence no will be unacceptable to the
	 * receiver.
	 */
	if (tcp->tcp_zero_win_probe) {
		seq_no = tcp->tcp_suna;
	} else if (tcp->tcp_state == TCPS_SYN_RCVD) {
		ASSERT(tcp->tcp_swnd == 0);
		seq_no = tcp->tcp_snxt;
	} else {
		seq_no = SEQ_GT(tcp->tcp_snxt,
		    (tcp->tcp_suna + tcp->tcp_swnd)) ?
		    (tcp->tcp_suna + tcp->tcp_swnd) : tcp->tcp_snxt;
	}

	if (tcp->tcp_valid_bits) {
		/*
		 * For the complex case where we have to send some
		 * controls (FIN or SYN), let tcp_xmit_mp do it.
		 */
		return (tcp_xmit_mp(tcp, NULL, 0, NULL, NULL, seq_no, B_FALSE,
		    NULL, B_FALSE));
	} else {
		/* Generate a simple ACK */
		int	data_length;
		uchar_t	*rptr;
		tcph_t	*tcph;
		mblk_t	*mp1;
		int32_t	tcp_hdr_len;
		int32_t	tcp_tcp_hdr_len;
		int32_t	num_sack_blk = 0;
		int32_t sack_opt_len;

		/*
		 * Allocate space for TCP + IP headers
		 * and link-level header
		 */
		if (tcp->tcp_snd_sack_ok && tcp->tcp_num_sack_blk > 0) {
			num_sack_blk = MIN(tcp->tcp_max_sack_blk,
			    tcp->tcp_num_sack_blk);
			sack_opt_len = num_sack_blk * sizeof (sack_blk_t) +
			    TCPOPT_NOP_LEN * 2 + TCPOPT_HEADER_LEN;
			tcp_hdr_len = tcp->tcp_hdr_len + sack_opt_len;
			tcp_tcp_hdr_len = tcp->tcp_tcp_hdr_len + sack_opt_len;
		} else {
			tcp_hdr_len = tcp->tcp_hdr_len;
			tcp_tcp_hdr_len = tcp->tcp_tcp_hdr_len;
		}
		mp1 = allocb(tcp_hdr_len + tcps->tcps_wroff_xtra, BPRI_MED);
		if (!mp1)
			return (NULL);

		/* Update the latest receive window size in TCP header. */
		U32_TO_ABE16(tcp->tcp_rwnd >> tcp->tcp_rcv_ws,
		    tcp->tcp_tcph->th_win);
		/* copy in prototype TCP + IP header */
		rptr = mp1->b_rptr + tcps->tcps_wroff_xtra;
		mp1->b_rptr = rptr;
		mp1->b_wptr = rptr + tcp_hdr_len;
		bcopy(tcp->tcp_iphc, rptr, tcp->tcp_hdr_len);

		tcph = (tcph_t *)&rptr[tcp->tcp_ip_hdr_len];

		/* Set the TCP sequence number. */
		U32_TO_ABE32(seq_no, tcph->th_seq);

		/* Set up the TCP flag field. */
		tcph->th_flags[0] = (uchar_t)TH_ACK;
		if (tcp->tcp_ecn_echo_on)
			tcph->th_flags[0] |= TH_ECE;

		tcp->tcp_rack = tcp->tcp_rnxt;
		tcp->tcp_rack_cnt = 0;

		/* fill in timestamp option if in use */
		if (tcp->tcp_snd_ts_ok) {
			uint32_t llbolt = (uint32_t)lbolt;

			U32_TO_BE32(llbolt,
			    (char *)tcph+TCP_MIN_HEADER_LENGTH+4);
			U32_TO_BE32(tcp->tcp_ts_recent,
			    (char *)tcph+TCP_MIN_HEADER_LENGTH+8);
		}

		/* Fill in SACK options */
		if (num_sack_blk > 0) {
			uchar_t *wptr = (uchar_t *)tcph + tcp->tcp_tcp_hdr_len;
			sack_blk_t *tmp;
			int32_t	i;

			wptr[0] = TCPOPT_NOP;
			wptr[1] = TCPOPT_NOP;
			wptr[2] = TCPOPT_SACK;
			wptr[3] = TCPOPT_HEADER_LEN + num_sack_blk *
			    sizeof (sack_blk_t);
			wptr += TCPOPT_REAL_SACK_LEN;

			tmp = tcp->tcp_sack_list;
			for (i = 0; i < num_sack_blk; i++) {
				U32_TO_BE32(tmp[i].begin, wptr);
				wptr += sizeof (tcp_seq);
				U32_TO_BE32(tmp[i].end, wptr);
				wptr += sizeof (tcp_seq);
			}
			tcph->th_offset_and_rsrvd[0] += ((num_sack_blk * 2 + 1)
			    << 4);
		}

		if (tcp->tcp_ipversion == IPV4_VERSION) {
			((ipha_t *)rptr)->ipha_length = htons(tcp_hdr_len);
		} else {
			/* Check for ip6i_t header in sticky hdrs */
			ip6_t *ip6 = (ip6_t *)(rptr +
			    (((ip6_t *)rptr)->ip6_nxt == IPPROTO_RAW ?
			    sizeof (ip6i_t) : 0));

			ip6->ip6_plen = htons(tcp_hdr_len -
			    ((char *)&tcp->tcp_ip6h[1] - tcp->tcp_iphc));
		}

		/*
		 * Prime pump for checksum calculation in IP.  Include the
		 * adjustment for a source route if any.
		 */
		data_length = tcp_tcp_hdr_len + tcp->tcp_sum;
		data_length = (data_length >> 16) + (data_length & 0xFFFF);
		U16_TO_ABE16(data_length, tcph->th_sum);

		if (tcp->tcp_ip_forward_progress) {
			ASSERT(tcp->tcp_ipversion == IPV6_VERSION);
			*(uint32_t *)mp1->b_rptr  |= IP_FORWARD_PROG;
			tcp->tcp_ip_forward_progress = B_FALSE;
		}
		return (mp1);
	}
}

/*
 * Hash list insertion routine for tcp_t structures. Each hash bucket
 * contains a list of tcp_t entries, and each entry is bound to a unique
 * port. If there are multiple tcp_t's that are bound to the same port, then
 * one of them will be linked into the hash bucket list, and the rest will
 * hang off of that one entry. For each port, entries bound to a specific IP
 * address will be inserted before those those bound to INADDR_ANY.
 */
static void
tcp_bind_hash_insert(tf_t *tbf, tcp_t *tcp, int caller_holds_lock)
{
	tcp_t	**tcpp;
	tcp_t	*tcpnext;
	tcp_t	*tcphash;

	if (tcp->tcp_ptpbhn != NULL) {
		ASSERT(!caller_holds_lock);
		tcp_bind_hash_remove(tcp);
	}
	tcpp = &tbf->tf_tcp;
	if (!caller_holds_lock) {
		mutex_enter(&tbf->tf_lock);
	} else {
		ASSERT(MUTEX_HELD(&tbf->tf_lock));
	}
	tcphash = tcpp[0];
	tcpnext = NULL;
	if (tcphash != NULL) {
		/* Look for an entry using the same port */
		while ((tcphash = tcpp[0]) != NULL &&
		    tcp->tcp_lport != tcphash->tcp_lport)
			tcpp = &(tcphash->tcp_bind_hash);

		/* The port was not found, just add to the end */
		if (tcphash == NULL)
			goto insert;

		/*
		 * OK, there already exists an entry bound to the
		 * same port.
		 *
		 * If the new tcp bound to the INADDR_ANY address
		 * and the first one in the list is not bound to
		 * INADDR_ANY we skip all entries until we find the
		 * first one bound to INADDR_ANY.
		 * This makes sure that applications binding to a
		 * specific address get preference over those binding to
		 * INADDR_ANY.
		 */
		tcpnext = tcphash;
		tcphash = NULL;
		if (V6_OR_V4_INADDR_ANY(tcp->tcp_bound_source_v6) &&
		    !V6_OR_V4_INADDR_ANY(tcpnext->tcp_bound_source_v6)) {
			while ((tcpnext = tcpp[0]) != NULL &&
			    !V6_OR_V4_INADDR_ANY(tcpnext->tcp_bound_source_v6))
				tcpp = &(tcpnext->tcp_bind_hash_port);

			if (tcpnext) {
				tcpnext->tcp_ptpbhn = &tcp->tcp_bind_hash_port;
				tcphash = tcpnext->tcp_bind_hash;
				if (tcphash != NULL) {
					tcphash->tcp_ptpbhn =
					    &(tcp->tcp_bind_hash);
					tcpnext->tcp_bind_hash = NULL;
				}
			}
		} else {
			tcpnext->tcp_ptpbhn = &tcp->tcp_bind_hash_port;
			tcphash = tcpnext->tcp_bind_hash;
			if (tcphash != NULL) {
				tcphash->tcp_ptpbhn =
				    &(tcp->tcp_bind_hash);
				tcpnext->tcp_bind_hash = NULL;
			}
		}
	}
insert:
	tcp->tcp_bind_hash_port = tcpnext;
	tcp->tcp_bind_hash = tcphash;
	tcp->tcp_ptpbhn = tcpp;
	tcpp[0] = tcp;
	if (!caller_holds_lock)
		mutex_exit(&tbf->tf_lock);
}

/*
 * Hash list removal routine for tcp_t structures.
 */
static void
tcp_bind_hash_remove(tcp_t *tcp)
{
	tcp_t	*tcpnext;
	kmutex_t *lockp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	if (tcp->tcp_ptpbhn == NULL)
		return;

	/*
	 * Extract the lock pointer in case there are concurrent
	 * hash_remove's for this instance.
	 */
	ASSERT(tcp->tcp_lport != 0);
	lockp = &tcps->tcps_bind_fanout[TCP_BIND_HASH(tcp->tcp_lport)].tf_lock;

	ASSERT(lockp != NULL);
	mutex_enter(lockp);
	if (tcp->tcp_ptpbhn) {
		tcpnext = tcp->tcp_bind_hash_port;
		if (tcpnext != NULL) {
			tcp->tcp_bind_hash_port = NULL;
			tcpnext->tcp_ptpbhn = tcp->tcp_ptpbhn;
			tcpnext->tcp_bind_hash = tcp->tcp_bind_hash;
			if (tcpnext->tcp_bind_hash != NULL) {
				tcpnext->tcp_bind_hash->tcp_ptpbhn =
				    &(tcpnext->tcp_bind_hash);
				tcp->tcp_bind_hash = NULL;
			}
		} else if ((tcpnext = tcp->tcp_bind_hash) != NULL) {
			tcpnext->tcp_ptpbhn = tcp->tcp_ptpbhn;
			tcp->tcp_bind_hash = NULL;
		}
		*tcp->tcp_ptpbhn = tcpnext;
		tcp->tcp_ptpbhn = NULL;
	}
	mutex_exit(lockp);
}


/*
 * Hash list lookup routine for tcp_t structures.
 * Returns with a CONN_INC_REF tcp structure. Caller must do a CONN_DEC_REF.
 */
static tcp_t *
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
static void
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

/* Data for fast netmask macro used by tcp_hsp_lookup */

static ipaddr_t netmasks[] = {
	IN_CLASSA_NET, IN_CLASSA_NET, IN_CLASSB_NET,
	IN_CLASSC_NET | IN_CLASSD_NET  /* Class C,D,E */
};

#define	netmask(addr) (netmasks[(ipaddr_t)(addr) >> 30])

/*
 * XXX This routine should go away and instead we should use the metrics
 * associated with the routes to determine the default sndspace and rcvspace.
 */
static tcp_hsp_t *
tcp_hsp_lookup(ipaddr_t addr, tcp_stack_t *tcps)
{
	tcp_hsp_t *hsp = NULL;

	/* Quick check without acquiring the lock. */
	if (tcps->tcps_hsp_hash == NULL)
		return (NULL);

	rw_enter(&tcps->tcps_hsp_lock, RW_READER);

	/* This routine finds the best-matching HSP for address addr. */

	if (tcps->tcps_hsp_hash) {
		int i;
		ipaddr_t srchaddr;
		tcp_hsp_t *hsp_net;

		/* We do three passes: host, network, and subnet. */

		srchaddr = addr;

		for (i = 1; i <= 3; i++) {
			/* Look for exact match on srchaddr */

			hsp = tcps->tcps_hsp_hash[TCP_HSP_HASH(srchaddr)];
			while (hsp) {
				if (hsp->tcp_hsp_vers == IPV4_VERSION &&
				    hsp->tcp_hsp_addr == srchaddr)
					break;
				hsp = hsp->tcp_hsp_next;
			}
			ASSERT(hsp == NULL ||
			    hsp->tcp_hsp_vers == IPV4_VERSION);

			/*
			 * If this is the first pass:
			 *   If we found a match, great, return it.
			 *   If not, search for the network on the second pass.
			 */

			if (i == 1)
				if (hsp)
					break;
				else
				{
					srchaddr = addr & netmask(addr);
					continue;
				}

			/*
			 * If this is the second pass:
			 *   If we found a match, but there's a subnet mask,
			 *    save the match but try again using the subnet
			 *    mask on the third pass.
			 *   Otherwise, return whatever we found.
			 */

			if (i == 2) {
				if (hsp && hsp->tcp_hsp_subnet) {
					hsp_net = hsp;
					srchaddr = addr & hsp->tcp_hsp_subnet;
					continue;
				} else {
					break;
				}
			}

			/*
			 * This must be the third pass.  If we didn't find
			 * anything, return the saved network HSP instead.
			 */

			if (!hsp)
				hsp = hsp_net;
		}
	}

	rw_exit(&tcps->tcps_hsp_lock);
	return (hsp);
}

/*
 * XXX Equally broken as the IPv4 routine. Doesn't handle longest
 * match lookup.
 */
static tcp_hsp_t *
tcp_hsp_lookup_ipv6(in6_addr_t *v6addr, tcp_stack_t *tcps)
{
	tcp_hsp_t *hsp = NULL;

	/* Quick check without acquiring the lock. */
	if (tcps->tcps_hsp_hash == NULL)
		return (NULL);

	rw_enter(&tcps->tcps_hsp_lock, RW_READER);

	/* This routine finds the best-matching HSP for address addr. */

	if (tcps->tcps_hsp_hash) {
		int i;
		in6_addr_t v6srchaddr;
		tcp_hsp_t *hsp_net;

		/* We do three passes: host, network, and subnet. */

		v6srchaddr = *v6addr;

		for (i = 1; i <= 3; i++) {
			/* Look for exact match on srchaddr */

			hsp = tcps->tcps_hsp_hash[TCP_HSP_HASH(
			    V4_PART_OF_V6(v6srchaddr))];
			while (hsp) {
				if (hsp->tcp_hsp_vers == IPV6_VERSION &&
				    IN6_ARE_ADDR_EQUAL(&hsp->tcp_hsp_addr_v6,
				    &v6srchaddr))
					break;
				hsp = hsp->tcp_hsp_next;
			}

			/*
			 * If this is the first pass:
			 *   If we found a match, great, return it.
			 *   If not, search for the network on the second pass.
			 */

			if (i == 1)
				if (hsp)
					break;
				else {
					/* Assume a 64 bit mask */
					v6srchaddr.s6_addr32[0] =
					    v6addr->s6_addr32[0];
					v6srchaddr.s6_addr32[1] =
					    v6addr->s6_addr32[1];
					v6srchaddr.s6_addr32[2] = 0;
					v6srchaddr.s6_addr32[3] = 0;
					continue;
				}

			/*
			 * If this is the second pass:
			 *   If we found a match, but there's a subnet mask,
			 *    save the match but try again using the subnet
			 *    mask on the third pass.
			 *   Otherwise, return whatever we found.
			 */

			if (i == 2) {
				ASSERT(hsp == NULL ||
				    hsp->tcp_hsp_vers == IPV6_VERSION);
				if (hsp &&
				    !IN6_IS_ADDR_UNSPECIFIED(
				    &hsp->tcp_hsp_subnet_v6)) {
					hsp_net = hsp;
					V6_MASK_COPY(*v6addr,
					    hsp->tcp_hsp_subnet_v6, v6srchaddr);
					continue;
				} else {
					break;
				}
			}

			/*
			 * This must be the third pass.  If we didn't find
			 * anything, return the saved network HSP instead.
			 */

			if (!hsp)
				hsp = hsp_net;
		}
	}

	rw_exit(&tcps->tcps_hsp_lock);
	return (hsp);
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

static int
tcp_conprim_opt_process(tcp_t *tcp, mblk_t *mp, int *do_disconnectp,
    int *t_errorp, int *sys_errorp)
{
	int error;
	int is_absreq_failure;
	t_scalar_t *opt_lenp;
	t_scalar_t opt_offset;
	int prim_type;
	struct T_conn_req *tcreqp;
	struct T_conn_res *tcresp;
	cred_t *cr;

	cr = DB_CREDDEF(mp, tcp->tcp_cred);

	prim_type = ((union T_primitives *)mp->b_rptr)->type;
	ASSERT(prim_type == T_CONN_REQ || prim_type == O_T_CONN_RES ||
	    prim_type == T_CONN_RES);

	switch (prim_type) {
	case T_CONN_REQ:
		tcreqp = (struct T_conn_req *)mp->b_rptr;
		opt_offset = tcreqp->OPT_offset;
		opt_lenp = (t_scalar_t *)&tcreqp->OPT_length;
		break;
	case O_T_CONN_RES:
	case T_CONN_RES:
		tcresp = (struct T_conn_res *)mp->b_rptr;
		opt_offset = tcresp->OPT_offset;
		opt_lenp = (t_scalar_t *)&tcresp->OPT_length;
		break;
	}

	*t_errorp = 0;
	*sys_errorp = 0;
	*do_disconnectp = 0;

	error = tpi_optcom_buf(tcp->tcp_wq, mp, opt_lenp,
	    opt_offset, cr, &tcp_opt_obj,
	    NULL, &is_absreq_failure);

	switch (error) {
	case  0:		/* no error */
		ASSERT(is_absreq_failure == 0);
		return (0);
	case ENOPROTOOPT:
		*t_errorp = TBADOPT;
		break;
	case EACCES:
		*t_errorp = TACCES;
		break;
	default:
		*t_errorp = TSYSERR; *sys_errorp = error;
		break;
	}
	if (is_absreq_failure != 0) {
		/*
		 * The connection request should get the local ack
		 * T_OK_ACK and then a T_DISCON_IND.
		 */
		*do_disconnectp = 1;
	}
	return (-1);
}

/*
 * Split this function out so that if the secret changes, I'm okay.
 *
 * Initialize the tcp_iss_cookie and tcp_iss_key.
 */

#define	PASSWD_SIZE 16  /* MUST be multiple of 4 */

static void
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
 * Set the RFC 1948 pass phrase
 */
/* ARGSUSED */
static int
tcp_1948_phrase_set(queue_t *q, mblk_t *mp, char *value, caddr_t cp,
    cred_t *cr)
{
	tcp_stack_t	*tcps = Q_TO_TCP(q)->tcp_tcps;

	/*
	 * Basically, value contains a new pass phrase.  Pass it along!
	 */
	tcp_iss_key_init((uint8_t *)value, strlen(value), tcps);
	return (0);
}

/* ARGSUSED */
static int
tcp_sack_info_constructor(void *buf, void *cdrarg, int kmflags)
{
	bzero(buf, sizeof (tcp_sack_info_t));
	return (0);
}

/* ARGSUSED */
static int
tcp_iphc_constructor(void *buf, void *cdrarg, int kmflags)
{
	bzero(buf, TCP_MAX_COMBINED_HEADER_LENGTH);
	return (0);
}

/*
 * Make sure we wait until the default queue is setup, yet allow
 * tcp_g_q_create() to open a TCP stream.
 * We need to allow tcp_g_q_create() do do an open
 * of tcp, hence we compare curhread.
 * All others have to wait until the tcps_g_q has been
 * setup.
 */
void
tcp_g_q_setup(tcp_stack_t *tcps)
{
	mutex_enter(&tcps->tcps_g_q_lock);
	if (tcps->tcps_g_q != NULL) {
		mutex_exit(&tcps->tcps_g_q_lock);
		return;
	}
	if (tcps->tcps_g_q_creator == NULL) {
		/* This thread will set it up */
		tcps->tcps_g_q_creator = curthread;
		mutex_exit(&tcps->tcps_g_q_lock);
		tcp_g_q_create(tcps);
		mutex_enter(&tcps->tcps_g_q_lock);
		ASSERT(tcps->tcps_g_q_creator == curthread);
		tcps->tcps_g_q_creator = NULL;
		cv_signal(&tcps->tcps_g_q_cv);
		ASSERT(tcps->tcps_g_q != NULL);
		mutex_exit(&tcps->tcps_g_q_lock);
		return;
	}
	/* Everybody but the creator has to wait */
	if (tcps->tcps_g_q_creator != curthread) {
		while (tcps->tcps_g_q == NULL)
			cv_wait(&tcps->tcps_g_q_cv, &tcps->tcps_g_q_lock);
	}
	mutex_exit(&tcps->tcps_g_q_lock);
}

#define	IP	"ip"

#define	TCP6DEV		"/devices/pseudo/tcp6@0:tcp6"

/*
 * Create a default tcp queue here instead of in strplumb
 */
void
tcp_g_q_create(tcp_stack_t *tcps)
{
	int error;
	ldi_handle_t	lh = NULL;
	ldi_ident_t	li = NULL;
	int		rval;
	cred_t		*cr;
	major_t IP_MAJ;

#ifdef NS_DEBUG
	(void) printf("tcp_g_q_create()\n");
#endif

	IP_MAJ = ddi_name_to_major(IP);

	ASSERT(tcps->tcps_g_q_creator == curthread);

	error = ldi_ident_from_major(IP_MAJ, &li);
	if (error) {
#ifdef DEBUG
		printf("tcp_g_q_create: lyr ident get failed error %d\n",
		    error);
#endif
		return;
	}

	cr = zone_get_kcred(netstackid_to_zoneid(
	    tcps->tcps_netstack->netstack_stackid));
	ASSERT(cr != NULL);
	/*
	 * We set the tcp default queue to IPv6 because IPv4 falls
	 * back to IPv6 when it can't find a client, but
	 * IPv6 does not fall back to IPv4.
	 */
	error = ldi_open_by_name(TCP6DEV, FREAD|FWRITE, cr, &lh, li);
	if (error) {
#ifdef DEBUG
		printf("tcp_g_q_create: open of TCP6DEV failed error %d\n",
		    error);
#endif
		goto out;
	}

	/*
	 * This ioctl causes the tcp framework to cache a pointer to
	 * this stream, so we don't want to close the stream after
	 * this operation.
	 * Use the kernel credentials that are for the zone we're in.
	 */
	error = ldi_ioctl(lh, TCP_IOC_DEFAULT_Q,
	    (intptr_t)0, FKIOCTL, cr, &rval);
	if (error) {
#ifdef DEBUG
		printf("tcp_g_q_create: ioctl TCP_IOC_DEFAULT_Q failed "
		    "error %d\n", error);
#endif
		goto out;
	}
	tcps->tcps_g_q_lh = lh;	/* For tcp_g_q_close */
	lh = NULL;
out:
	/* Close layered handles */
	if (li)
		ldi_ident_release(li);
	/* Keep cred around until _inactive needs it */
	tcps->tcps_g_q_cr = cr;
}

/*
 * We keep tcp_g_q set until all other tcp_t's in the zone
 * has gone away, and then when tcp_g_q_inactive() is called
 * we clear it.
 */
void
tcp_g_q_destroy(tcp_stack_t *tcps)
{
#ifdef NS_DEBUG
	(void) printf("tcp_g_q_destroy()for stack %d\n",
	    tcps->tcps_netstack->netstack_stackid);
#endif

	if (tcps->tcps_g_q == NULL) {
		return;	/* Nothing to cleanup */
	}
	/*
	 * Drop reference corresponding to the default queue.
	 * This reference was added from tcp_open when the default queue
	 * was created, hence we compensate for this extra drop in
	 * tcp_g_q_close. If the refcnt drops to zero here it means
	 * the default queue was the last one to be open, in which
	 * case, then tcp_g_q_inactive will be
	 * called as a result of the refrele.
	 */
	TCPS_REFRELE(tcps);
}

/*
 * Called when last tcp_t drops reference count using TCPS_REFRELE.
 * Run by tcp_q_q_inactive using a taskq.
 */
static void
tcp_g_q_close(void *arg)
{
	tcp_stack_t *tcps = arg;
	int error;
	ldi_handle_t	lh = NULL;
	ldi_ident_t	li = NULL;
	cred_t		*cr;
	major_t IP_MAJ;

	IP_MAJ = ddi_name_to_major(IP);

#ifdef NS_DEBUG
	(void) printf("tcp_g_q_inactive() for stack %d refcnt %d\n",
	    tcps->tcps_netstack->netstack_stackid,
	    tcps->tcps_netstack->netstack_refcnt);
#endif
	lh = tcps->tcps_g_q_lh;
	if (lh == NULL)
		return;	/* Nothing to cleanup */

	ASSERT(tcps->tcps_refcnt == 1);
	ASSERT(tcps->tcps_g_q != NULL);

	error = ldi_ident_from_major(IP_MAJ, &li);
	if (error) {
#ifdef DEBUG
		printf("tcp_g_q_inactive: lyr ident get failed error %d\n",
		    error);
#endif
		return;
	}

	cr = tcps->tcps_g_q_cr;
	tcps->tcps_g_q_cr = NULL;
	ASSERT(cr != NULL);

	/*
	 * Make sure we can break the recursion when tcp_close decrements
	 * the reference count causing g_q_inactive to be called again.
	 */
	tcps->tcps_g_q_lh = NULL;

	/* close the default queue */
	(void) ldi_close(lh, FREAD|FWRITE, cr);
	/*
	 * At this point in time tcps and the rest of netstack_t might
	 * have been deleted.
	 */
	tcps = NULL;

	/* Close layered handles */
	ldi_ident_release(li);
	crfree(cr);
}

/*
 * Called when last tcp_t drops reference count using TCPS_REFRELE.
 *
 * Have to ensure that the ldi routines are not used by an
 * interrupt thread by using a taskq.
 */
void
tcp_g_q_inactive(tcp_stack_t *tcps)
{
	if (tcps->tcps_g_q_lh == NULL)
		return;	/* Nothing to cleanup */

	ASSERT(tcps->tcps_refcnt == 0);
	TCPS_REFHOLD(tcps); /* Compensate for what g_q_destroy did */

	if (servicing_interrupt()) {
		(void) taskq_dispatch(tcp_taskq, tcp_g_q_close,
		    (void *) tcps, TQ_SLEEP);
	} else {
		tcp_g_q_close(tcps);
	}
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

	tcp_sack_info_cache = kmem_cache_create("tcp_sack_info_cache",
	    sizeof (tcp_sack_info_t), 0,
	    tcp_sack_info_constructor, NULL, NULL, NULL, NULL, 0);

	tcp_iphc_cache = kmem_cache_create("tcp_iphc_cache",
	    TCP_MAX_COMBINED_HEADER_LENGTH, 0,
	    tcp_iphc_constructor, NULL, NULL, NULL, NULL, 0);

	mutex_init(&tcp_random_lock, NULL, MUTEX_DEFAULT, NULL);

	/* Initialize the random number generator */
	tcp_random_init();

	/* A single callback independently of how many netstacks we have */
	ip_squeue_init(tcp_squeue_add);

	tcp_g_kstat = tcp_g_kstat_init(&tcp_g_statistics);

	tcp_taskq = taskq_create("tcp_taskq", 1, minclsyspri, 1, 1,
	    TASKQ_PREPOPULATE);

	tcp_squeue_flag = tcp_squeue_switch(tcp_squeue_wput);

	/*
	 * We want to be informed each time a stack is created or
	 * destroyed in the kernel, so we can maintain the
	 * set of tcp_stack_t's.
	 */
	netstack_register(NS_TCP, tcp_stack_init, tcp_stack_shutdown,
	    tcp_stack_fini);
}


#define	INET_NAME	"ip"

/*
 * Initialize the TCP stack instance.
 */
static void *
tcp_stack_init(netstackid_t stackid, netstack_t *ns)
{
	tcp_stack_t	*tcps;
	tcpparam_t	*pa;
	int		i;
	int		error = 0;
	major_t		major;

	tcps = (tcp_stack_t *)kmem_zalloc(sizeof (*tcps), KM_SLEEP);
	tcps->tcps_netstack = ns;

	/* Initialize locks */
	rw_init(&tcps->tcps_hsp_lock, NULL, RW_DEFAULT, NULL);
	mutex_init(&tcps->tcps_g_q_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&tcps->tcps_g_q_cv, NULL, CV_DEFAULT, NULL);
	mutex_init(&tcps->tcps_iss_key_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&tcps->tcps_epriv_port_lock, NULL, MUTEX_DEFAULT, NULL);

	tcps->tcps_g_num_epriv_ports = TCP_NUM_EPRIV_PORTS;
	tcps->tcps_g_epriv_ports[0] = 2049;
	tcps->tcps_g_epriv_ports[1] = 4045;
	tcps->tcps_min_anonpriv_port = 512;

	tcps->tcps_bind_fanout = kmem_zalloc(sizeof (tf_t) *
	    TCP_BIND_FANOUT_SIZE, KM_SLEEP);
	tcps->tcps_acceptor_fanout = kmem_zalloc(sizeof (tf_t) *
	    TCP_FANOUT_SIZE, KM_SLEEP);

	for (i = 0; i < TCP_BIND_FANOUT_SIZE; i++) {
		mutex_init(&tcps->tcps_bind_fanout[i].tf_lock, NULL,
		    MUTEX_DEFAULT, NULL);
	}

	for (i = 0; i < TCP_FANOUT_SIZE; i++) {
		mutex_init(&tcps->tcps_acceptor_fanout[i].tf_lock, NULL,
		    MUTEX_DEFAULT, NULL);
	}

	/* TCP's IPsec code calls the packet dropper. */
	ip_drop_register(&tcps->tcps_dropper, "TCP IPsec policy enforcement");

	pa = (tcpparam_t *)kmem_alloc(sizeof (lcl_tcp_param_arr), KM_SLEEP);
	tcps->tcps_params = pa;
	bcopy(lcl_tcp_param_arr, tcps->tcps_params, sizeof (lcl_tcp_param_arr));

	(void) tcp_param_register(&tcps->tcps_g_nd, tcps->tcps_params,
	    A_CNT(lcl_tcp_param_arr), tcps);

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

	tcps->tcps_kstat = tcp_kstat2_init(stackid, &tcps->tcps_statistics);
	tcps->tcps_mibkp = tcp_kstat_init(stackid, tcps);

	major = mod_name_to_major(INET_NAME);
	error = ldi_ident_from_major(major, &tcps->tcps_ldi_ident);
	ASSERT(error == 0);
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
	kmem_cache_destroy(tcp_sack_info_cache);
	kmem_cache_destroy(tcp_iphc_cache);

	netstack_unregister(NS_TCP);
	taskq_destroy(tcp_taskq);
}

/*
 * Shut down the TCP stack instance.
 */
/* ARGSUSED */
static void
tcp_stack_shutdown(netstackid_t stackid, void *arg)
{
	tcp_stack_t *tcps = (tcp_stack_t *)arg;

	tcp_g_q_destroy(tcps);
}

/*
 * Free the TCP stack instance.
 */
static void
tcp_stack_fini(netstackid_t stackid, void *arg)
{
	tcp_stack_t *tcps = (tcp_stack_t *)arg;
	int i;

	nd_free(&tcps->tcps_g_nd);
	kmem_free(tcps->tcps_params, sizeof (lcl_tcp_param_arr));
	tcps->tcps_params = NULL;
	kmem_free(tcps->tcps_wroff_xtra_param, sizeof (tcpparam_t));
	tcps->tcps_wroff_xtra_param = NULL;
	kmem_free(tcps->tcps_mdt_head_param, sizeof (tcpparam_t));
	tcps->tcps_mdt_head_param = NULL;
	kmem_free(tcps->tcps_mdt_tail_param, sizeof (tcpparam_t));
	tcps->tcps_mdt_tail_param = NULL;
	kmem_free(tcps->tcps_mdt_max_pbufs_param, sizeof (tcpparam_t));
	tcps->tcps_mdt_max_pbufs_param = NULL;

	for (i = 0; i < TCP_BIND_FANOUT_SIZE; i++) {
		ASSERT(tcps->tcps_bind_fanout[i].tf_tcp == NULL);
		mutex_destroy(&tcps->tcps_bind_fanout[i].tf_lock);
	}

	for (i = 0; i < TCP_FANOUT_SIZE; i++) {
		ASSERT(tcps->tcps_acceptor_fanout[i].tf_tcp == NULL);
		mutex_destroy(&tcps->tcps_acceptor_fanout[i].tf_lock);
	}

	kmem_free(tcps->tcps_bind_fanout, sizeof (tf_t) * TCP_BIND_FANOUT_SIZE);
	tcps->tcps_bind_fanout = NULL;

	kmem_free(tcps->tcps_acceptor_fanout, sizeof (tf_t) * TCP_FANOUT_SIZE);
	tcps->tcps_acceptor_fanout = NULL;

	mutex_destroy(&tcps->tcps_iss_key_lock);
	rw_destroy(&tcps->tcps_hsp_lock);
	mutex_destroy(&tcps->tcps_g_q_lock);
	cv_destroy(&tcps->tcps_g_q_cv);
	mutex_destroy(&tcps->tcps_epriv_port_lock);

	ip_drop_unregister(&tcps->tcps_dropper);

	tcp_kstat2_fini(stackid, tcps->tcps_kstat);
	tcps->tcps_kstat = NULL;
	bzero(&tcps->tcps_statistics, sizeof (tcps->tcps_statistics));

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

	tcps->tcps_iss_incr_extra += (ISS_INCR >> 1);
	tcp->tcp_iss = tcps->tcps_iss_incr_extra;
	switch (tcps->tcps_strong_iss) {
	case 2:
		mutex_enter(&tcps->tcps_iss_key_lock);
		context = tcps->tcps_iss_key;
		mutex_exit(&tcps->tcps_iss_key_lock);
		arg.ports = tcp->tcp_ports;
		if (tcp->tcp_ipversion == IPV4_VERSION) {
			IN6_IPADDR_TO_V4MAPPED(tcp->tcp_ipha->ipha_src,
			    &arg.src);
			IN6_IPADDR_TO_V4MAPPED(tcp->tcp_ipha->ipha_dst,
			    &arg.dst);
		} else {
			arg.src = tcp->tcp_ip6h->ip6_src;
			arg.dst = tcp->tcp_ip6h->ip6_dst;
		}
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
		tcp->tcp_iss += (uint32_t)gethrestime_sec() * ISS_INCR;
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
 * Exported routine for extracting active tcp connection status.
 *
 * This is used by the Solaris Cluster Networking software to
 * gather a list of connections that need to be forwarded to
 * specific nodes in the cluster when configuration changes occur.
 *
 * The callback is invoked for each tcp_t structure from all netstacks,
 * if 'stack_id' is less than 0. Otherwise, only for tcp_t structures
 * from the netstack with the specified stack_id. Returning
 * non-zero from the callback routine terminates the search.
 */
int
cl_tcp_walk_list(netstackid_t stack_id,
    int (*cl_callback)(cl_tcp_info_t *, void *), void *arg)
{
	netstack_handle_t nh;
	netstack_t *ns;
	int ret = 0;

	if (stack_id >= 0) {
		if ((ns = netstack_find_by_stackid(stack_id)) == NULL)
			return (EINVAL);

		ret = cl_tcp_walk_list_stack(cl_callback, arg,
		    ns->netstack_tcp);
		netstack_rele(ns);
		return (ret);
	}

	netstack_next_init(&nh);
	while ((ns = netstack_next(&nh)) != NULL) {
		ret = cl_tcp_walk_list_stack(cl_callback, arg,
		    ns->netstack_tcp);
		netstack_rele(ns);
	}
	netstack_next_fini(&nh);
	return (ret);
}

static int
cl_tcp_walk_list_stack(int (*callback)(cl_tcp_info_t *, void *), void *arg,
    tcp_stack_t *tcps)
{
	tcp_t *tcp;
	cl_tcp_info_t	cl_tcpi;
	connf_t	*connfp;
	conn_t	*connp;
	int	i;
	ip_stack_t	*ipst = tcps->tcps_netstack->netstack_ip;

	ASSERT(callback != NULL);

	for (i = 0; i < CONN_G_HASH_SIZE; i++) {
		connfp = &ipst->ips_ipcl_globalhash_fanout[i];
		connp = NULL;

		while ((connp =
		    ipcl_get_next_conn(connfp, connp, IPCL_TCP)) != NULL) {

			tcp = connp->conn_tcp;
			cl_tcpi.cl_tcpi_version = CL_TCPI_V1;
			cl_tcpi.cl_tcpi_ipversion = tcp->tcp_ipversion;
			cl_tcpi.cl_tcpi_state = tcp->tcp_state;
			cl_tcpi.cl_tcpi_lport = tcp->tcp_lport;
			cl_tcpi.cl_tcpi_fport = tcp->tcp_fport;
			/*
			 * The macros tcp_laddr and tcp_faddr give the IPv4
			 * addresses. They are copied implicitly below as
			 * mapped addresses.
			 */
			cl_tcpi.cl_tcpi_laddr_v6 = tcp->tcp_ip_src_v6;
			if (tcp->tcp_ipversion == IPV4_VERSION) {
				cl_tcpi.cl_tcpi_faddr =
				    tcp->tcp_ipha->ipha_dst;
			} else {
				cl_tcpi.cl_tcpi_faddr_v6 =
				    tcp->tcp_ip6h->ip6_dst;
			}

			/*
			 * If the callback returns non-zero
			 * we terminate the traversal.
			 */
			if ((*callback)(&cl_tcpi, arg) != 0) {
				CONN_DEC_REF(tcp->tcp_connp);
				return (1);
			}
		}
	}

	return (0);
}

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
#define	TCP_AC_ADDR_MATCH(acp, tcp)					\
	(((acp)->ac_local.ss_family == AF_INET) ?		\
	((TCP_AC_V4LOCAL((acp)) == INADDR_ANY ||		\
	TCP_AC_V4LOCAL((acp)) == (tcp)->tcp_ip_src) &&	\
	(TCP_AC_V4REMOTE((acp)) == INADDR_ANY ||		\
	TCP_AC_V4REMOTE((acp)) == (tcp)->tcp_remote) &&	\
	(TCP_AC_V4LPORT((acp)) == 0 ||				\
	TCP_AC_V4LPORT((acp)) == (tcp)->tcp_lport) &&		\
	(TCP_AC_V4RPORT((acp)) == 0 ||				\
	TCP_AC_V4RPORT((acp)) == (tcp)->tcp_fport) &&		\
	(acp)->ac_start <= (tcp)->tcp_state &&	\
	(acp)->ac_end >= (tcp)->tcp_state) :		\
	((IN6_IS_ADDR_UNSPECIFIED(&TCP_AC_V6LOCAL((acp))) ||	\
	IN6_ARE_ADDR_EQUAL(&TCP_AC_V6LOCAL((acp)),		\
	&(tcp)->tcp_ip_src_v6)) &&				\
	(IN6_IS_ADDR_UNSPECIFIED(&TCP_AC_V6REMOTE((acp))) ||	\
	IN6_ARE_ADDR_EQUAL(&TCP_AC_V6REMOTE((acp)),		\
	&(tcp)->tcp_remote_v6)) &&				\
	(TCP_AC_V6LPORT((acp)) == 0 ||				\
	TCP_AC_V6LPORT((acp)) == (tcp)->tcp_lport) &&		\
	(TCP_AC_V6RPORT((acp)) == 0 ||				\
	TCP_AC_V6RPORT((acp)) == (tcp)->tcp_fport) &&		\
	(acp)->ac_start <= (tcp)->tcp_state &&	\
	(acp)->ac_end >= (tcp)->tcp_state))

#define	TCP_AC_MATCH(acp, tcp)					\
	(((acp)->ac_zoneid == ALL_ZONES ||			\
	(acp)->ac_zoneid == tcp->tcp_connp->conn_zoneid) ?	\
	TCP_AC_ADDR_MATCH(acp, tcp) : 0)

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

	mp->b_datap->db_type = M_CTL;

	*((uint32_t *)mp->b_rptr) = TCP_IOC_ABORT_CONN;
	tacp = (tcp_ioc_abort_conn_t *)((uchar_t *)mp->b_rptr +
	    sizeof (uint32_t));

	tacp->ac_start = acp->ac_start;
	tacp->ac_end = acp->ac_end;
	tacp->ac_zoneid = acp->ac_zoneid;

	if (acp->ac_local.ss_family == AF_INET) {
		tacp->ac_local.ss_family = AF_INET;
		tacp->ac_remote.ss_family = AF_INET;
		TCP_AC_V4LOCAL(tacp) = tp->tcp_ip_src;
		TCP_AC_V4REMOTE(tacp) = tp->tcp_remote;
		TCP_AC_V4LPORT(tacp) = tp->tcp_lport;
		TCP_AC_V4RPORT(tacp) = tp->tcp_fport;
	} else {
		tacp->ac_local.ss_family = AF_INET6;
		tacp->ac_remote.ss_family = AF_INET6;
		TCP_AC_V6LOCAL(tacp) = tp->tcp_ip_src_v6;
		TCP_AC_V6REMOTE(tacp) = tp->tcp_remote_v6;
		TCP_AC_V6LPORT(tacp) = tp->tcp_lport;
		TCP_AC_V6RPORT(tacp) = tp->tcp_fport;
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
 * Called inside tcp_rput when a message built using
 * tcp_ioctl_abort_build_msg is put into a queue.
 * Note that when we get here there is no wildcard in acp any more.
 */
static void
tcp_ioctl_abort_handler(tcp_t *tcp, mblk_t *mp)
{
	tcp_ioc_abort_conn_t *acp;

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
		(void) tcp_clean_death(tcp, errcode, 26);
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
		if (TCP_AC_MATCH(acp, tcp)) {
			CONN_INC_REF(tcp->tcp_connp);
			mp = tcp_ioctl_abort_build_msg(acp, tcp);
			if (mp == NULL) {
				err = ENOMEM;
				CONN_DEC_REF(tcp->tcp_connp);
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
		SQUEUE_ENTER_ONE(tcp->tcp_connp->conn_sqp, mp, tcp_input,
		    tcp->tcp_connp, SQ_FILL, SQTAG_TCP_ABORT_BUCKET);
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
static void
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
 * tcp_time_wait_processing() handles processing of incoming packets when
 * the tcp is in the TIME_WAIT state.
 * A TIME_WAIT tcp that has an associated open TCP stream is never put
 * on the time wait list.
 */
void
tcp_time_wait_processing(tcp_t *tcp, mblk_t *mp, uint32_t seg_seq,
    uint32_t seg_ack, int seg_len, tcph_t *tcph)
{
	int32_t		bytes_acked;
	int32_t		gap;
	int32_t		rgap;
	tcp_opt_t	tcpopt;
	uint_t		flags;
	uint32_t	new_swnd = 0;
	conn_t		*connp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	BUMP_LOCAL(tcp->tcp_ibsegs);
	DTRACE_PROBE2(tcp__trace__recv, mblk_t *, mp, tcp_t *, tcp);

	flags = (unsigned int)tcph->th_flags[0] & 0xFF;
	new_swnd = BE16_TO_U16(tcph->th_win) <<
	    ((tcph->th_flags[0] & TH_SYN) ? 0 : tcp->tcp_snd_ws);
	if (tcp->tcp_snd_ts_ok) {
		if (!tcp_paws_check(tcp, tcph, &tcpopt)) {
			tcp_xmit_ctl(NULL, tcp, tcp->tcp_snxt,
			    tcp->tcp_rnxt, TH_ACK);
			goto done;
		}
	}
	gap = seg_seq - tcp->tcp_rnxt;
	rgap = tcp->tcp_rwnd - (gap + seg_len);
	if (gap < 0) {
		BUMP_MIB(&tcps->tcps_mib, tcpInDataDupSegs);
		UPDATE_MIB(&tcps->tcps_mib, tcpInDataDupBytes,
		    (seg_len > -gap ? -gap : seg_len));
		seg_len += gap;
		if (seg_len < 0 || (seg_len == 0 && !(flags & TH_FIN))) {
			if (flags & TH_RST) {
				goto done;
			}
			if ((flags & TH_FIN) && seg_len == -1) {
				/*
				 * When TCP receives a duplicate FIN in
				 * TIME_WAIT state, restart the 2 MSL timer.
				 * See page 73 in RFC 793. Make sure this TCP
				 * is already on the TIME_WAIT list. If not,
				 * just restart the timer.
				 */
				if (TCP_IS_DETACHED(tcp)) {
					if (tcp_time_wait_remove(tcp, NULL) ==
					    B_TRUE) {
						tcp_time_wait_append(tcp);
						TCP_DBGSTAT(tcps,
						    tcp_rput_time_wait);
					}
				} else {
					ASSERT(tcp != NULL);
					TCP_TIMER_RESTART(tcp,
					    tcps->tcps_time_wait_interval);
				}
				tcp_xmit_ctl(NULL, tcp, tcp->tcp_snxt,
				    tcp->tcp_rnxt, TH_ACK);
				goto done;
			}
			flags |=  TH_ACK_NEEDED;
			seg_len = 0;
			goto process_ack;
		}

		/* Fix seg_seq, and chew the gap off the front. */
		seg_seq = tcp->tcp_rnxt;
	}

	if ((flags & TH_SYN) && gap > 0 && rgap < 0) {
		/*
		 * Make sure that when we accept the connection, pick
		 * an ISS greater than (tcp_snxt + ISS_INCR/2) for the
		 * old connection.
		 *
		 * The next ISS generated is equal to tcp_iss_incr_extra
		 * + ISS_INCR/2 + other components depending on the
		 * value of tcp_strong_iss.  We pre-calculate the new
		 * ISS here and compare with tcp_snxt to determine if
		 * we need to make adjustment to tcp_iss_incr_extra.
		 *
		 * The above calculation is ugly and is a
		 * waste of CPU cycles...
		 */
		uint32_t new_iss = tcps->tcps_iss_incr_extra;
		int32_t adj;
		ip_stack_t *ipst = tcps->tcps_netstack->netstack_ip;

		switch (tcps->tcps_strong_iss) {
		case 2: {
			/* Add time and MD5 components. */
			uint32_t answer[4];
			struct {
				uint32_t ports;
				in6_addr_t src;
				in6_addr_t dst;
			} arg;
			MD5_CTX context;

			mutex_enter(&tcps->tcps_iss_key_lock);
			context = tcps->tcps_iss_key;
			mutex_exit(&tcps->tcps_iss_key_lock);
			arg.ports = tcp->tcp_ports;
			/* We use MAPPED addresses in tcp_iss_init */
			arg.src = tcp->tcp_ip_src_v6;
			if (tcp->tcp_ipversion == IPV4_VERSION) {
				IN6_IPADDR_TO_V4MAPPED(
				    tcp->tcp_ipha->ipha_dst,
				    &arg.dst);
			} else {
				arg.dst =
				    tcp->tcp_ip6h->ip6_dst;
			}
			MD5Update(&context, (uchar_t *)&arg,
			    sizeof (arg));
			MD5Final((uchar_t *)answer, &context);
			answer[0] ^= answer[1] ^ answer[2] ^ answer[3];
			new_iss += (gethrtime() >> ISS_NSEC_SHT) + answer[0];
			break;
		}
		case 1:
			/* Add time component and min random (i.e. 1). */
			new_iss += (gethrtime() >> ISS_NSEC_SHT) + 1;
			break;
		default:
			/* Add only time component. */
			new_iss += (uint32_t)gethrestime_sec() * ISS_INCR;
			break;
		}
		if ((adj = (int32_t)(tcp->tcp_snxt - new_iss)) > 0) {
			/*
			 * New ISS not guaranteed to be ISS_INCR/2
			 * ahead of the current tcp_snxt, so add the
			 * difference to tcp_iss_incr_extra.
			 */
			tcps->tcps_iss_incr_extra += adj;
		}
		/*
		 * If tcp_clean_death() can not perform the task now,
		 * drop the SYN packet and let the other side re-xmit.
		 * Otherwise pass the SYN packet back in, since the
		 * old tcp state has been cleaned up or freed.
		 */
		if (tcp_clean_death(tcp, 0, 27) == -1)
			goto done;
		/*
		 * We will come back to tcp_rput_data
		 * on the global queue. Packets destined
		 * for the global queue will be checked
		 * with global policy. But the policy for
		 * this packet has already been checked as
		 * this was destined for the detached
		 * connection. We need to bypass policy
		 * check this time by attaching a dummy
		 * ipsec_in with ipsec_in_dont_check set.
		 */
		connp = ipcl_classify(mp, tcp->tcp_connp->conn_zoneid, ipst);
		if (connp != NULL) {
			TCP_STAT(tcps, tcp_time_wait_syn_success);
			tcp_reinput(connp, mp, tcp->tcp_connp->conn_sqp);
			return;
		}
		goto done;
	}

	/*
	 * rgap is the amount of stuff received out of window.  A negative
	 * value is the amount out of window.
	 */
	if (rgap < 0) {
		BUMP_MIB(&tcps->tcps_mib, tcpInDataPastWinSegs);
		UPDATE_MIB(&tcps->tcps_mib, tcpInDataPastWinBytes, -rgap);
		/* Fix seg_len and make sure there is something left. */
		seg_len += rgap;
		if (seg_len <= 0) {
			if (flags & TH_RST) {
				goto done;
			}
			flags |=  TH_ACK_NEEDED;
			seg_len = 0;
			goto process_ack;
		}
	}
	/*
	 * Check whether we can update tcp_ts_recent.  This test is
	 * NOT the one in RFC 1323 3.4.  It is from Braden, 1993, "TCP
	 * Extensions for High Performance: An Update", Internet Draft.
	 */
	if (tcp->tcp_snd_ts_ok &&
	    TSTMP_GEQ(tcpopt.tcp_opt_ts_val, tcp->tcp_ts_recent) &&
	    SEQ_LEQ(seg_seq, tcp->tcp_rack)) {
		tcp->tcp_ts_recent = tcpopt.tcp_opt_ts_val;
		tcp->tcp_last_rcv_lbolt = lbolt64;
	}

	if (seg_seq != tcp->tcp_rnxt && seg_len > 0) {
		/* Always ack out of order packets */
		flags |= TH_ACK_NEEDED;
		seg_len = 0;
	} else if (seg_len > 0) {
		BUMP_MIB(&tcps->tcps_mib, tcpInClosed);
		BUMP_MIB(&tcps->tcps_mib, tcpInDataInorderSegs);
		UPDATE_MIB(&tcps->tcps_mib, tcpInDataInorderBytes, seg_len);
	}
	if (flags & TH_RST) {
		(void) tcp_clean_death(tcp, 0, 28);
		goto done;
	}
	if (flags & TH_SYN) {
		tcp_xmit_ctl("TH_SYN", tcp, seg_ack, seg_seq + 1,
		    TH_RST|TH_ACK);
		/*
		 * Do not delete the TCP structure if it is in
		 * TIME_WAIT state.  Refer to RFC 1122, 4.2.2.13.
		 */
		goto done;
	}
process_ack:
	if (flags & TH_ACK) {
		bytes_acked = (int)(seg_ack - tcp->tcp_suna);
		if (bytes_acked <= 0) {
			if (bytes_acked == 0 && seg_len == 0 &&
			    new_swnd == tcp->tcp_swnd)
				BUMP_MIB(&tcps->tcps_mib, tcpInDupAck);
		} else {
			/* Acks something not sent */
			flags |= TH_ACK_NEEDED;
		}
	}
	if (flags & TH_ACK_NEEDED) {
		/*
		 * Time to send an ack for some reason.
		 */
		tcp_xmit_ctl(NULL, tcp, tcp->tcp_snxt,
		    tcp->tcp_rnxt, TH_ACK);
	}
done:
	if ((mp->b_datap->db_struioflag & STRUIO_EAGER) != 0) {
		DB_CKSUMSTART(mp) = 0;
		mp->b_datap->db_struioflag &= ~STRUIO_EAGER;
		TCP_STAT(tcps, tcp_time_wait_syn_fail);
	}
	freemsg(mp);
}

/*
 * TCP Timers Implementation.
 */
timeout_id_t
tcp_timeout(conn_t *connp, void (*f)(void *), clock_t tim)
{
	mblk_t *mp;
	tcp_timer_t *tcpt;
	tcp_t *tcp = connp->conn_tcp;

	ASSERT(connp->conn_sqp != NULL);

	TCP_DBGSTAT(tcp->tcp_tcps, tcp_timeout_calls);

	if (tcp->tcp_timercache == NULL) {
		mp = tcp_timermp_alloc(KM_NOSLEEP | KM_PANIC);
	} else {
		TCP_DBGSTAT(tcp->tcp_tcps, tcp_timeout_cached_alloc);
		mp = tcp->tcp_timercache;
		tcp->tcp_timercache = mp->b_next;
		mp->b_next = NULL;
		ASSERT(mp->b_wptr == NULL);
	}

	CONN_INC_REF(connp);
	tcpt = (tcp_timer_t *)mp->b_rptr;
	tcpt->connp = connp;
	tcpt->tcpt_proc = f;
	/*
	 * TCP timers are normal timeouts. Plus, they do not require more than
	 * a 10 millisecond resolution. By choosing a coarser resolution and by
	 * rounding up the expiration to the next resolution boundary, we can
	 * batch timers in the callout subsystem to make TCP timers more
	 * efficient. The roundup also protects short timers from expiring too
	 * early before they have a chance to be cancelled.
	 */
	tcpt->tcpt_tid = timeout_generic(CALLOUT_NORMAL, tcp_timer_callback, mp,
	    TICK_TO_NSEC(tim), CALLOUT_TCP_RESOLUTION, CALLOUT_FLAG_ROUNDUP);

	return ((timeout_id_t)mp);
}

static void
tcp_timer_callback(void *arg)
{
	mblk_t *mp = (mblk_t *)arg;
	tcp_timer_t *tcpt;
	conn_t	*connp;

	tcpt = (tcp_timer_t *)mp->b_rptr;
	connp = tcpt->connp;
	SQUEUE_ENTER_ONE(connp->conn_sqp, mp, tcp_timer_handler, connp,
	    SQ_FILL, SQTAG_TCP_TIMER);
}

static void
tcp_timer_handler(void *arg, mblk_t *mp, void *arg2)
{
	tcp_timer_t *tcpt;
	conn_t *connp = (conn_t *)arg;
	tcp_t *tcp = connp->conn_tcp;

	tcpt = (tcp_timer_t *)mp->b_rptr;
	ASSERT(connp == tcpt->connp);
	ASSERT((squeue_t *)arg2 == connp->conn_sqp);

	/*
	 * If the TCP has reached the closed state, don't proceed any
	 * further. This TCP logically does not exist on the system.
	 * tcpt_proc could for example access queues, that have already
	 * been qprocoff'ed off. Also see comments at the start of tcp_input
	 */
	if (tcp->tcp_state != TCPS_CLOSED) {
		(*tcpt->tcpt_proc)(connp);
	} else {
		tcp->tcp_timer_tid = 0;
	}
	tcp_timer_free(connp->conn_tcp, mp);
}

/*
 * There is potential race with untimeout and the handler firing at the same
 * time. The mblock may be freed by the handler while we are trying to use
 * it. But since both should execute on the same squeue, this race should not
 * occur.
 */
clock_t
tcp_timeout_cancel(conn_t *connp, timeout_id_t id)
{
	mblk_t	*mp = (mblk_t *)id;
	tcp_timer_t *tcpt;
	clock_t delta;

	TCP_DBGSTAT(connp->conn_tcp->tcp_tcps, tcp_timeout_cancel_reqs);

	if (mp == NULL)
		return (-1);

	tcpt = (tcp_timer_t *)mp->b_rptr;
	ASSERT(tcpt->connp == connp);

	delta = untimeout_default(tcpt->tcpt_tid, 0);

	if (delta >= 0) {
		TCP_DBGSTAT(connp->conn_tcp->tcp_tcps, tcp_timeout_canceled);
		tcp_timer_free(connp->conn_tcp, mp);
		CONN_DEC_REF(connp);
	}

	return (delta);
}

/*
 * Allocate space for the timer event. The allocation looks like mblk, but it is
 * not a proper mblk. To avoid confusion we set b_wptr to NULL.
 *
 * Dealing with failures: If we can't allocate from the timer cache we try
 * allocating from dblock caches using allocb_tryhard(). In this case b_wptr
 * points to b_rptr.
 * If we can't allocate anything using allocb_tryhard(), we perform a last
 * attempt and use kmem_alloc_tryhard(). In this case we set b_wptr to -1 and
 * save the actual allocation size in b_datap.
 */
mblk_t *
tcp_timermp_alloc(int kmflags)
{
	mblk_t *mp = (mblk_t *)kmem_cache_alloc(tcp_timercache,
	    kmflags & ~KM_PANIC);

	if (mp != NULL) {
		mp->b_next = mp->b_prev = NULL;
		mp->b_rptr = (uchar_t *)(&mp[1]);
		mp->b_wptr = NULL;
		mp->b_datap = NULL;
		mp->b_queue = NULL;
		mp->b_cont = NULL;
	} else if (kmflags & KM_PANIC) {
		/*
		 * Failed to allocate memory for the timer. Try allocating from
		 * dblock caches.
		 */
		/* ipclassifier calls this from a constructor - hence no tcps */
		TCP_G_STAT(tcp_timermp_allocfail);
		mp = allocb_tryhard(sizeof (tcp_timer_t));
		if (mp == NULL) {
			size_t size = 0;
			/*
			 * Memory is really low. Try tryhard allocation.
			 *
			 * ipclassifier calls this from a constructor -
			 * hence no tcps
			 */
			TCP_G_STAT(tcp_timermp_allocdblfail);
			mp = kmem_alloc_tryhard(sizeof (mblk_t) +
			    sizeof (tcp_timer_t), &size, kmflags);
			mp->b_rptr = (uchar_t *)(&mp[1]);
			mp->b_next = mp->b_prev = NULL;
			mp->b_wptr = (uchar_t *)-1;
			mp->b_datap = (dblk_t *)size;
			mp->b_queue = NULL;
			mp->b_cont = NULL;
		}
		ASSERT(mp->b_wptr != NULL);
	}
	/* ipclassifier calls this from a constructor - hence no tcps */
	TCP_G_DBGSTAT(tcp_timermp_alloced);

	return (mp);
}

/*
 * Free per-tcp timer cache.
 * It can only contain entries from tcp_timercache.
 */
void
tcp_timermp_free(tcp_t *tcp)
{
	mblk_t *mp;

	while ((mp = tcp->tcp_timercache) != NULL) {
		ASSERT(mp->b_wptr == NULL);
		tcp->tcp_timercache = tcp->tcp_timercache->b_next;
		kmem_cache_free(tcp_timercache, mp);
	}
}

/*
 * Free timer event. Put it on the per-tcp timer cache if there is not too many
 * events there already (currently at most two events are cached).
 * If the event is not allocated from the timer cache, free it right away.
 */
static void
tcp_timer_free(tcp_t *tcp, mblk_t *mp)
{
	mblk_t *mp1 = tcp->tcp_timercache;

	if (mp->b_wptr != NULL) {
		/*
		 * This allocation is not from a timer cache, free it right
		 * away.
		 */
		if (mp->b_wptr != (uchar_t *)-1)
			freeb(mp);
		else
			kmem_free(mp, (size_t)mp->b_datap);
	} else if (mp1 == NULL || mp1->b_next == NULL) {
		/* Cache this timer block for future allocations */
		mp->b_rptr = (uchar_t *)(&mp[1]);
		mp->b_next = mp1;
		tcp->tcp_timercache = mp;
	} else {
		kmem_cache_free(tcp_timercache, mp);
		TCP_DBGSTAT(tcp->tcp_tcps, tcp_timermp_freed);
	}
}

/*
 * End of TCP Timers implementation.
 */

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

	if (IPCL_IS_NONSTR(connp)) {
		(*connp->conn_upcalls->su_txq_full)
		    (tcp->tcp_connp->conn_upper_handle, B_TRUE);
		tcp->tcp_flow_stopped = B_TRUE;
	} else {
		queue_t *q = tcp->tcp_wq;

		if (!(q->q_flag & QFULL)) {
			mutex_enter(QLOCK(q));
			if (!(q->q_flag & QFULL)) {
				/* still need to set QFULL */
				q->q_flag |= QFULL;
				tcp->tcp_flow_stopped = B_TRUE;
				mutex_exit(QLOCK(q));
				TCP_STAT(tcps, tcp_flwctl_on);
			} else {
				mutex_exit(QLOCK(q));
			}
		}
	}
}

void
tcp_clrqfull(tcp_t *tcp)
{
	conn_t  *connp = tcp->tcp_connp;

	if (tcp->tcp_closed)
		return;

	if (IPCL_IS_NONSTR(connp)) {
		(*connp->conn_upcalls->su_txq_full)
		    (tcp->tcp_connp->conn_upper_handle, B_FALSE);
		tcp->tcp_flow_stopped = B_FALSE;
	} else {
		queue_t *q = tcp->tcp_wq;

		if (q->q_flag & QFULL) {
			mutex_enter(QLOCK(q));
			if (q->q_flag & QFULL) {
				q->q_flag &= ~QFULL;
				tcp->tcp_flow_stopped = B_FALSE;
				mutex_exit(QLOCK(q));
				if (q->q_flag & QWANTW)
					qbackenable(q, 0);
			} else {
				mutex_exit(QLOCK(q));
			}
		}
	}
}

/*
 * kstats related to squeues i.e. not per IP instance
 */
static void *
tcp_g_kstat_init(tcp_g_stat_t *tcp_g_statp)
{
	kstat_t *ksp;

	tcp_g_stat_t template = {
		{ "tcp_timermp_alloced",	KSTAT_DATA_UINT64 },
		{ "tcp_timermp_allocfail",	KSTAT_DATA_UINT64 },
		{ "tcp_timermp_allocdblfail",	KSTAT_DATA_UINT64 },
		{ "tcp_freelist_cleanup",	KSTAT_DATA_UINT64 },
	};

	ksp = kstat_create(TCP_MOD_NAME, 0, "tcpstat_g", "net",
	    KSTAT_TYPE_NAMED, sizeof (template) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);

	if (ksp == NULL)
		return (NULL);

	bcopy(&template, tcp_g_statp, sizeof (template));
	ksp->ks_data = (void *)tcp_g_statp;

	kstat_install(ksp);
	return (ksp);
}

static void
tcp_g_kstat_fini(kstat_t *ksp)
{
	if (ksp != NULL) {
		kstat_delete(ksp);
	}
}


static void *
tcp_kstat2_init(netstackid_t stackid, tcp_stat_t *tcps_statisticsp)
{
	kstat_t *ksp;

	tcp_stat_t template = {
		{ "tcp_time_wait",		KSTAT_DATA_UINT64 },
		{ "tcp_time_wait_syn",		KSTAT_DATA_UINT64 },
		{ "tcp_time_wait_success",	KSTAT_DATA_UINT64 },
		{ "tcp_time_wait_fail",		KSTAT_DATA_UINT64 },
		{ "tcp_reinput_syn",		KSTAT_DATA_UINT64 },
		{ "tcp_ip_output",		KSTAT_DATA_UINT64 },
		{ "tcp_detach_non_time_wait",	KSTAT_DATA_UINT64 },
		{ "tcp_detach_time_wait",	KSTAT_DATA_UINT64 },
		{ "tcp_time_wait_reap",		KSTAT_DATA_UINT64 },
		{ "tcp_clean_death_nondetached",	KSTAT_DATA_UINT64 },
		{ "tcp_reinit_calls",		KSTAT_DATA_UINT64 },
		{ "tcp_eager_err1",		KSTAT_DATA_UINT64 },
		{ "tcp_eager_err2",		KSTAT_DATA_UINT64 },
		{ "tcp_eager_blowoff_calls",	KSTAT_DATA_UINT64 },
		{ "tcp_eager_blowoff_q",	KSTAT_DATA_UINT64 },
		{ "tcp_eager_blowoff_q0",	KSTAT_DATA_UINT64 },
		{ "tcp_not_hard_bound",		KSTAT_DATA_UINT64 },
		{ "tcp_no_listener",		KSTAT_DATA_UINT64 },
		{ "tcp_found_eager",		KSTAT_DATA_UINT64 },
		{ "tcp_wrong_queue",		KSTAT_DATA_UINT64 },
		{ "tcp_found_eager_binding1",	KSTAT_DATA_UINT64 },
		{ "tcp_found_eager_bound1",	KSTAT_DATA_UINT64 },
		{ "tcp_eager_has_listener1",	KSTAT_DATA_UINT64 },
		{ "tcp_open_alloc",		KSTAT_DATA_UINT64 },
		{ "tcp_open_detached_alloc",	KSTAT_DATA_UINT64 },
		{ "tcp_rput_time_wait",		KSTAT_DATA_UINT64 },
		{ "tcp_listendrop",		KSTAT_DATA_UINT64 },
		{ "tcp_listendropq0",		KSTAT_DATA_UINT64 },
		{ "tcp_wrong_rq",		KSTAT_DATA_UINT64 },
		{ "tcp_rsrv_calls",		KSTAT_DATA_UINT64 },
		{ "tcp_eagerfree2",		KSTAT_DATA_UINT64 },
		{ "tcp_eagerfree3",		KSTAT_DATA_UINT64 },
		{ "tcp_eagerfree4",		KSTAT_DATA_UINT64 },
		{ "tcp_eagerfree5",		KSTAT_DATA_UINT64 },
		{ "tcp_timewait_syn_fail",	KSTAT_DATA_UINT64 },
		{ "tcp_listen_badflags",	KSTAT_DATA_UINT64 },
		{ "tcp_timeout_calls",		KSTAT_DATA_UINT64 },
		{ "tcp_timeout_cached_alloc",	KSTAT_DATA_UINT64 },
		{ "tcp_timeout_cancel_reqs",	KSTAT_DATA_UINT64 },
		{ "tcp_timeout_canceled",	KSTAT_DATA_UINT64 },
		{ "tcp_timermp_freed",		KSTAT_DATA_UINT64 },
		{ "tcp_push_timer_cnt",		KSTAT_DATA_UINT64 },
		{ "tcp_ack_timer_cnt",		KSTAT_DATA_UINT64 },
		{ "tcp_ire_null1",		KSTAT_DATA_UINT64 },
		{ "tcp_ire_null",		KSTAT_DATA_UINT64 },
		{ "tcp_ip_send",		KSTAT_DATA_UINT64 },
		{ "tcp_ip_ire_send",		KSTAT_DATA_UINT64 },
		{ "tcp_wsrv_called",		KSTAT_DATA_UINT64 },
		{ "tcp_flwctl_on",		KSTAT_DATA_UINT64 },
		{ "tcp_timer_fire_early",	KSTAT_DATA_UINT64 },
		{ "tcp_timer_fire_miss",	KSTAT_DATA_UINT64 },
		{ "tcp_rput_v6_error",		KSTAT_DATA_UINT64 },
		{ "tcp_out_sw_cksum",		KSTAT_DATA_UINT64 },
		{ "tcp_out_sw_cksum_bytes",	KSTAT_DATA_UINT64 },
		{ "tcp_zcopy_on",		KSTAT_DATA_UINT64 },
		{ "tcp_zcopy_off",		KSTAT_DATA_UINT64 },
		{ "tcp_zcopy_backoff",		KSTAT_DATA_UINT64 },
		{ "tcp_zcopy_disable",		KSTAT_DATA_UINT64 },
		{ "tcp_mdt_pkt_out",		KSTAT_DATA_UINT64 },
		{ "tcp_mdt_pkt_out_v4",		KSTAT_DATA_UINT64 },
		{ "tcp_mdt_pkt_out_v6",		KSTAT_DATA_UINT64 },
		{ "tcp_mdt_discarded",		KSTAT_DATA_UINT64 },
		{ "tcp_mdt_conn_halted1",	KSTAT_DATA_UINT64 },
		{ "tcp_mdt_conn_halted2",	KSTAT_DATA_UINT64 },
		{ "tcp_mdt_conn_halted3",	KSTAT_DATA_UINT64 },
		{ "tcp_mdt_conn_resumed1",	KSTAT_DATA_UINT64 },
		{ "tcp_mdt_conn_resumed2",	KSTAT_DATA_UINT64 },
		{ "tcp_mdt_legacy_small",	KSTAT_DATA_UINT64 },
		{ "tcp_mdt_legacy_all",		KSTAT_DATA_UINT64 },
		{ "tcp_mdt_legacy_ret",		KSTAT_DATA_UINT64 },
		{ "tcp_mdt_allocfail",		KSTAT_DATA_UINT64 },
		{ "tcp_mdt_addpdescfail",	KSTAT_DATA_UINT64 },
		{ "tcp_mdt_allocd",		KSTAT_DATA_UINT64 },
		{ "tcp_mdt_linked",		KSTAT_DATA_UINT64 },
		{ "tcp_fusion_flowctl",		KSTAT_DATA_UINT64 },
		{ "tcp_fusion_backenabled",	KSTAT_DATA_UINT64 },
		{ "tcp_fusion_urg",		KSTAT_DATA_UINT64 },
		{ "tcp_fusion_putnext",		KSTAT_DATA_UINT64 },
		{ "tcp_fusion_unfusable",	KSTAT_DATA_UINT64 },
		{ "tcp_fusion_aborted",		KSTAT_DATA_UINT64 },
		{ "tcp_fusion_unqualified",	KSTAT_DATA_UINT64 },
		{ "tcp_fusion_rrw_busy",	KSTAT_DATA_UINT64 },
		{ "tcp_fusion_rrw_msgcnt",	KSTAT_DATA_UINT64 },
		{ "tcp_fusion_rrw_plugged",	KSTAT_DATA_UINT64 },
		{ "tcp_in_ack_unsent_drop",	KSTAT_DATA_UINT64 },
		{ "tcp_sock_fallback",		KSTAT_DATA_UINT64 },
		{ "tcp_lso_enabled",		KSTAT_DATA_UINT64 },
		{ "tcp_lso_disabled",		KSTAT_DATA_UINT64 },
		{ "tcp_lso_times",		KSTAT_DATA_UINT64 },
		{ "tcp_lso_pkt_out",		KSTAT_DATA_UINT64 },
	};

	ksp = kstat_create_netstack(TCP_MOD_NAME, 0, "tcpstat", "net",
	    KSTAT_TYPE_NAMED, sizeof (template) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL, stackid);

	if (ksp == NULL)
		return (NULL);

	bcopy(&template, tcps_statisticsp, sizeof (template));
	ksp->ks_data = (void *)tcps_statisticsp;
	ksp->ks_private = (void *)(uintptr_t)stackid;

	kstat_install(ksp);
	return (ksp);
}

static void
tcp_kstat2_fini(netstackid_t stackid, kstat_t *ksp)
{
	if (ksp != NULL) {
		ASSERT(stackid == (netstackid_t)(uintptr_t)ksp->ks_private);
		kstat_delete_netstack(ksp, stackid);
	}
}

/*
 * TCP Kstats implementation
 */
static void *
tcp_kstat_init(netstackid_t stackid, tcp_stack_t *tcps)
{
	kstat_t	*ksp;

	tcp_named_kstat_t template = {
		{ "rtoAlgorithm",	KSTAT_DATA_INT32, 0 },
		{ "rtoMin",		KSTAT_DATA_INT32, 0 },
		{ "rtoMax",		KSTAT_DATA_INT32, 0 },
		{ "maxConn",		KSTAT_DATA_INT32, 0 },
		{ "activeOpens",	KSTAT_DATA_UINT32, 0 },
		{ "passiveOpens",	KSTAT_DATA_UINT32, 0 },
		{ "attemptFails",	KSTAT_DATA_UINT32, 0 },
		{ "estabResets",	KSTAT_DATA_UINT32, 0 },
		{ "currEstab",		KSTAT_DATA_UINT32, 0 },
		{ "inSegs",		KSTAT_DATA_UINT64, 0 },
		{ "outSegs",		KSTAT_DATA_UINT64, 0 },
		{ "retransSegs",	KSTAT_DATA_UINT32, 0 },
		{ "connTableSize",	KSTAT_DATA_INT32, 0 },
		{ "outRsts",		KSTAT_DATA_UINT32, 0 },
		{ "outDataSegs",	KSTAT_DATA_UINT32, 0 },
		{ "outDataBytes",	KSTAT_DATA_UINT32, 0 },
		{ "retransBytes",	KSTAT_DATA_UINT32, 0 },
		{ "outAck",		KSTAT_DATA_UINT32, 0 },
		{ "outAckDelayed",	KSTAT_DATA_UINT32, 0 },
		{ "outUrg",		KSTAT_DATA_UINT32, 0 },
		{ "outWinUpdate",	KSTAT_DATA_UINT32, 0 },
		{ "outWinProbe",	KSTAT_DATA_UINT32, 0 },
		{ "outControl",		KSTAT_DATA_UINT32, 0 },
		{ "outFastRetrans",	KSTAT_DATA_UINT32, 0 },
		{ "inAckSegs",		KSTAT_DATA_UINT32, 0 },
		{ "inAckBytes",		KSTAT_DATA_UINT32, 0 },
		{ "inDupAck",		KSTAT_DATA_UINT32, 0 },
		{ "inAckUnsent",	KSTAT_DATA_UINT32, 0 },
		{ "inDataInorderSegs",	KSTAT_DATA_UINT32, 0 },
		{ "inDataInorderBytes",	KSTAT_DATA_UINT32, 0 },
		{ "inDataUnorderSegs",	KSTAT_DATA_UINT32, 0 },
		{ "inDataUnorderBytes",	KSTAT_DATA_UINT32, 0 },
		{ "inDataDupSegs",	KSTAT_DATA_UINT32, 0 },
		{ "inDataDupBytes",	KSTAT_DATA_UINT32, 0 },
		{ "inDataPartDupSegs",	KSTAT_DATA_UINT32, 0 },
		{ "inDataPartDupBytes",	KSTAT_DATA_UINT32, 0 },
		{ "inDataPastWinSegs",	KSTAT_DATA_UINT32, 0 },
		{ "inDataPastWinBytes",	KSTAT_DATA_UINT32, 0 },
		{ "inWinProbe",		KSTAT_DATA_UINT32, 0 },
		{ "inWinUpdate",	KSTAT_DATA_UINT32, 0 },
		{ "inClosed",		KSTAT_DATA_UINT32, 0 },
		{ "rttUpdate",		KSTAT_DATA_UINT32, 0 },
		{ "rttNoUpdate",	KSTAT_DATA_UINT32, 0 },
		{ "timRetrans",		KSTAT_DATA_UINT32, 0 },
		{ "timRetransDrop",	KSTAT_DATA_UINT32, 0 },
		{ "timKeepalive",	KSTAT_DATA_UINT32, 0 },
		{ "timKeepaliveProbe",	KSTAT_DATA_UINT32, 0 },
		{ "timKeepaliveDrop",	KSTAT_DATA_UINT32, 0 },
		{ "listenDrop",		KSTAT_DATA_UINT32, 0 },
		{ "listenDropQ0",	KSTAT_DATA_UINT32, 0 },
		{ "halfOpenDrop",	KSTAT_DATA_UINT32, 0 },
		{ "outSackRetransSegs",	KSTAT_DATA_UINT32, 0 },
		{ "connTableSize6",	KSTAT_DATA_INT32, 0 }
	};

	ksp = kstat_create_netstack(TCP_MOD_NAME, 0, TCP_MOD_NAME, "mib2",
	    KSTAT_TYPE_NAMED, NUM_OF_FIELDS(tcp_named_kstat_t), 0, stackid);

	if (ksp == NULL)
		return (NULL);

	template.rtoAlgorithm.value.ui32 = 4;
	template.rtoMin.value.ui32 = tcps->tcps_rexmit_interval_min;
	template.rtoMax.value.ui32 = tcps->tcps_rexmit_interval_max;
	template.maxConn.value.i32 = -1;

	bcopy(&template, ksp->ks_data, sizeof (template));
	ksp->ks_update = tcp_kstat_update;
	ksp->ks_private = (void *)(uintptr_t)stackid;

	kstat_install(ksp);
	return (ksp);
}

static void
tcp_kstat_fini(netstackid_t stackid, kstat_t *ksp)
{
	if (ksp != NULL) {
		ASSERT(stackid == (netstackid_t)(uintptr_t)ksp->ks_private);
		kstat_delete_netstack(ksp, stackid);
	}
}

static int
tcp_kstat_update(kstat_t *kp, int rw)
{
	tcp_named_kstat_t *tcpkp;
	tcp_t		*tcp;
	connf_t		*connfp;
	conn_t		*connp;
	int 		i;
	netstackid_t	stackid = (netstackid_t)(uintptr_t)kp->ks_private;
	netstack_t	*ns;
	tcp_stack_t	*tcps;
	ip_stack_t	*ipst;

	if ((kp == NULL) || (kp->ks_data == NULL))
		return (EIO);

	if (rw == KSTAT_WRITE)
		return (EACCES);

	ns = netstack_find_by_stackid(stackid);
	if (ns == NULL)
		return (-1);
	tcps = ns->netstack_tcp;
	if (tcps == NULL) {
		netstack_rele(ns);
		return (-1);
	}

	tcpkp = (tcp_named_kstat_t *)kp->ks_data;

	tcpkp->currEstab.value.ui32 = 0;

	ipst = ns->netstack_ip;

	for (i = 0; i < CONN_G_HASH_SIZE; i++) {
		connfp = &ipst->ips_ipcl_globalhash_fanout[i];
		connp = NULL;
		while ((connp =
		    ipcl_get_next_conn(connfp, connp, IPCL_TCP)) != NULL) {
			tcp = connp->conn_tcp;
			switch (tcp_snmp_state(tcp)) {
			case MIB2_TCP_established:
			case MIB2_TCP_closeWait:
				tcpkp->currEstab.value.ui32++;
				break;
			}
		}
	}

	tcpkp->activeOpens.value.ui32 = tcps->tcps_mib.tcpActiveOpens;
	tcpkp->passiveOpens.value.ui32 = tcps->tcps_mib.tcpPassiveOpens;
	tcpkp->attemptFails.value.ui32 = tcps->tcps_mib.tcpAttemptFails;
	tcpkp->estabResets.value.ui32 = tcps->tcps_mib.tcpEstabResets;
	tcpkp->inSegs.value.ui64 = tcps->tcps_mib.tcpHCInSegs;
	tcpkp->outSegs.value.ui64 = tcps->tcps_mib.tcpHCOutSegs;
	tcpkp->retransSegs.value.ui32 =	tcps->tcps_mib.tcpRetransSegs;
	tcpkp->connTableSize.value.i32 = tcps->tcps_mib.tcpConnTableSize;
	tcpkp->outRsts.value.ui32 = tcps->tcps_mib.tcpOutRsts;
	tcpkp->outDataSegs.value.ui32 = tcps->tcps_mib.tcpOutDataSegs;
	tcpkp->outDataBytes.value.ui32 = tcps->tcps_mib.tcpOutDataBytes;
	tcpkp->retransBytes.value.ui32 = tcps->tcps_mib.tcpRetransBytes;
	tcpkp->outAck.value.ui32 = tcps->tcps_mib.tcpOutAck;
	tcpkp->outAckDelayed.value.ui32 = tcps->tcps_mib.tcpOutAckDelayed;
	tcpkp->outUrg.value.ui32 = tcps->tcps_mib.tcpOutUrg;
	tcpkp->outWinUpdate.value.ui32 = tcps->tcps_mib.tcpOutWinUpdate;
	tcpkp->outWinProbe.value.ui32 = tcps->tcps_mib.tcpOutWinProbe;
	tcpkp->outControl.value.ui32 = tcps->tcps_mib.tcpOutControl;
	tcpkp->outFastRetrans.value.ui32 = tcps->tcps_mib.tcpOutFastRetrans;
	tcpkp->inAckSegs.value.ui32 = tcps->tcps_mib.tcpInAckSegs;
	tcpkp->inAckBytes.value.ui32 = tcps->tcps_mib.tcpInAckBytes;
	tcpkp->inDupAck.value.ui32 = tcps->tcps_mib.tcpInDupAck;
	tcpkp->inAckUnsent.value.ui32 = tcps->tcps_mib.tcpInAckUnsent;
	tcpkp->inDataInorderSegs.value.ui32 =
	    tcps->tcps_mib.tcpInDataInorderSegs;
	tcpkp->inDataInorderBytes.value.ui32 =
	    tcps->tcps_mib.tcpInDataInorderBytes;
	tcpkp->inDataUnorderSegs.value.ui32 =
	    tcps->tcps_mib.tcpInDataUnorderSegs;
	tcpkp->inDataUnorderBytes.value.ui32 =
	    tcps->tcps_mib.tcpInDataUnorderBytes;
	tcpkp->inDataDupSegs.value.ui32 = tcps->tcps_mib.tcpInDataDupSegs;
	tcpkp->inDataDupBytes.value.ui32 = tcps->tcps_mib.tcpInDataDupBytes;
	tcpkp->inDataPartDupSegs.value.ui32 =
	    tcps->tcps_mib.tcpInDataPartDupSegs;
	tcpkp->inDataPartDupBytes.value.ui32 =
	    tcps->tcps_mib.tcpInDataPartDupBytes;
	tcpkp->inDataPastWinSegs.value.ui32 =
	    tcps->tcps_mib.tcpInDataPastWinSegs;
	tcpkp->inDataPastWinBytes.value.ui32 =
	    tcps->tcps_mib.tcpInDataPastWinBytes;
	tcpkp->inWinProbe.value.ui32 = tcps->tcps_mib.tcpInWinProbe;
	tcpkp->inWinUpdate.value.ui32 = tcps->tcps_mib.tcpInWinUpdate;
	tcpkp->inClosed.value.ui32 = tcps->tcps_mib.tcpInClosed;
	tcpkp->rttNoUpdate.value.ui32 = tcps->tcps_mib.tcpRttNoUpdate;
	tcpkp->rttUpdate.value.ui32 = tcps->tcps_mib.tcpRttUpdate;
	tcpkp->timRetrans.value.ui32 = tcps->tcps_mib.tcpTimRetrans;
	tcpkp->timRetransDrop.value.ui32 = tcps->tcps_mib.tcpTimRetransDrop;
	tcpkp->timKeepalive.value.ui32 = tcps->tcps_mib.tcpTimKeepalive;
	tcpkp->timKeepaliveProbe.value.ui32 =
	    tcps->tcps_mib.tcpTimKeepaliveProbe;
	tcpkp->timKeepaliveDrop.value.ui32 =
	    tcps->tcps_mib.tcpTimKeepaliveDrop;
	tcpkp->listenDrop.value.ui32 = tcps->tcps_mib.tcpListenDrop;
	tcpkp->listenDropQ0.value.ui32 = tcps->tcps_mib.tcpListenDropQ0;
	tcpkp->halfOpenDrop.value.ui32 = tcps->tcps_mib.tcpHalfOpenDrop;
	tcpkp->outSackRetransSegs.value.ui32 =
	    tcps->tcps_mib.tcpOutSackRetransSegs;
	tcpkp->connTableSize6.value.i32 = tcps->tcps_mib.tcp6ConnTableSize;

	netstack_rele(ns);
	return (0);
}

void
tcp_reinput(conn_t *connp, mblk_t *mp, squeue_t *sqp)
{
	uint16_t	hdr_len;
	ipha_t		*ipha;
	uint8_t		*nexthdrp;
	tcph_t		*tcph;
	tcp_stack_t	*tcps = connp->conn_tcp->tcp_tcps;

	/* Already has an eager */
	if ((mp->b_datap->db_struioflag & STRUIO_EAGER) != 0) {
		TCP_STAT(tcps, tcp_reinput_syn);
		SQUEUE_ENTER_ONE(connp->conn_sqp, mp, connp->conn_recv, connp,
		    SQ_PROCESS, SQTAG_TCP_REINPUT_EAGER);
		return;
	}

	switch (IPH_HDR_VERSION(mp->b_rptr)) {
	case IPV4_VERSION:
		ipha = (ipha_t *)mp->b_rptr;
		hdr_len = IPH_HDR_LENGTH(ipha);
		break;
	case IPV6_VERSION:
		if (!ip_hdr_length_nexthdr_v6(mp, (ip6_t *)mp->b_rptr,
		    &hdr_len, &nexthdrp)) {
			CONN_DEC_REF(connp);
			freemsg(mp);
			return;
		}
		break;
	}

	tcph = (tcph_t *)&mp->b_rptr[hdr_len];
	if ((tcph->th_flags[0] & (TH_SYN|TH_ACK|TH_RST|TH_URG)) == TH_SYN) {
		mp->b_datap->db_struioflag |= STRUIO_EAGER;
		DB_CKSUMSTART(mp) = (intptr_t)sqp;
	}

	SQUEUE_ENTER_ONE(connp->conn_sqp, mp, connp->conn_recv, connp,
	    SQ_FILL, SQTAG_TCP_REINPUT);
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
	tcp_time_wait->tcp_time_wait_tid =
	    timeout_generic(CALLOUT_NORMAL, tcp_time_wait_collector, sqp,
	    TICK_TO_NSEC(TCP_TIME_WAIT_DELAY), CALLOUT_TCP_RESOLUTION,
	    CALLOUT_FLAG_ROUNDUP);
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

static int
tcp_post_ip_bind(tcp_t *tcp, mblk_t *mp, int error, cred_t *cr, pid_t pid)
{
	mblk_t	*ire_mp = NULL;
	mblk_t	*syn_mp;
	mblk_t	*mdti;
	mblk_t	*lsoi;
	int	retval;
	tcph_t	*tcph;
	uint32_t	mss;
	queue_t	*q = tcp->tcp_rq;
	conn_t	*connp = tcp->tcp_connp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

	if (error == 0) {
		/*
		 * Adapt Multidata information, if any.  The
		 * following tcp_mdt_update routine will free
		 * the message.
		 */
		if (mp != NULL && ((mdti = tcp_mdt_info_mp(mp)) != NULL)) {
			tcp_mdt_update(tcp, &((ip_mdt_info_t *)mdti->
			    b_rptr)->mdt_capab, B_TRUE);
			freemsg(mdti);
		}

		/*
		 * Check to update LSO information with tcp, and
		 * tcp_lso_update routine will free the message.
		 */
		if (mp != NULL && ((lsoi = tcp_lso_info_mp(mp)) != NULL)) {
			tcp_lso_update(tcp, &((ip_lso_info_t *)lsoi->
			    b_rptr)->lso_capab);
			freemsg(lsoi);
		}

		/* Get the IRE, if we had requested for it */
		if (mp != NULL)
			ire_mp = tcp_ire_mp(&mp);

		if (tcp->tcp_hard_binding) {
			tcp->tcp_hard_binding = B_FALSE;
			tcp->tcp_hard_bound = B_TRUE;
			CL_INET_CONNECT(tcp->tcp_connp, tcp, B_TRUE, retval);
			if (retval != 0) {
				error = EADDRINUSE;
				goto bind_failed;
			}
		} else {
			if (ire_mp != NULL)
				freeb(ire_mp);
			goto after_syn_sent;
		}

		retval = tcp_adapt_ire(tcp, ire_mp);
		if (ire_mp != NULL)
			freeb(ire_mp);
		if (retval == 0) {
			error = (int)((tcp->tcp_state >= TCPS_SYN_SENT) ?
			    ENETUNREACH : EADDRNOTAVAIL);
			goto ipcl_rm;
		}
		/*
		 * Don't let an endpoint connect to itself.
		 * Also checked in tcp_connect() but that
		 * check can't handle the case when the
		 * local IP address is INADDR_ANY.
		 */
		if (tcp->tcp_ipversion == IPV4_VERSION) {
			if ((tcp->tcp_ipha->ipha_dst ==
			    tcp->tcp_ipha->ipha_src) &&
			    (BE16_EQL(tcp->tcp_tcph->th_lport,
			    tcp->tcp_tcph->th_fport))) {
				error = EADDRNOTAVAIL;
				goto ipcl_rm;
			}
		} else {
			if (IN6_ARE_ADDR_EQUAL(
			    &tcp->tcp_ip6h->ip6_dst,
			    &tcp->tcp_ip6h->ip6_src) &&
			    (BE16_EQL(tcp->tcp_tcph->th_lport,
			    tcp->tcp_tcph->th_fport))) {
				error = EADDRNOTAVAIL;
				goto ipcl_rm;
			}
		}
		ASSERT(tcp->tcp_state == TCPS_SYN_SENT);
		/*
		 * This should not be possible!  Just for
		 * defensive coding...
		 */
		if (tcp->tcp_state != TCPS_SYN_SENT)
			goto after_syn_sent;

		if (is_system_labeled() &&
		    !tcp_update_label(tcp, CONN_CRED(tcp->tcp_connp))) {
			error = EHOSTUNREACH;
			goto ipcl_rm;
		}

		/*
		 * tcp_adapt_ire() does not adjust
		 * for TCP/IP header length.
		 */
		mss = tcp->tcp_mss - tcp->tcp_hdr_len;

		/*
		 * Just make sure our rwnd is at
		 * least tcp_recv_hiwat_mss * MSS
		 * large, and round up to the nearest
		 * MSS.
		 *
		 * We do the round up here because
		 * we need to get the interface
		 * MTU first before we can do the
		 * round up.
		 */
		tcp->tcp_rwnd = MAX(MSS_ROUNDUP(tcp->tcp_rwnd, mss),
		    tcps->tcps_recv_hiwat_minmss * mss);
		if (!IPCL_IS_NONSTR(connp))
			q->q_hiwat = tcp->tcp_rwnd;
		tcp->tcp_recv_hiwater = tcp->tcp_rwnd;
		tcp_set_ws_value(tcp);
		U32_TO_ABE16((tcp->tcp_rwnd >> tcp->tcp_rcv_ws),
		    tcp->tcp_tcph->th_win);
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
		 * tcp_snd_sack_ok can be set in
		 * tcp_adapt_ire() if the sack metric
		 * is set.  So check it here also.
		 */
		if (tcps->tcps_sack_permitted == 2 ||
		    tcp->tcp_snd_sack_ok) {
			if (tcp->tcp_sack_info == NULL) {
				tcp->tcp_sack_info =
				    kmem_cache_alloc(tcp_sack_info_cache,
				    KM_SLEEP);
			}
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

		TCP_TIMER_RESTART(tcp, tcp->tcp_rto);
		syn_mp = tcp_xmit_mp(tcp, NULL, 0, NULL, NULL,
		    tcp->tcp_iss, B_FALSE, NULL, B_FALSE);
		if (syn_mp) {
			if (cr == NULL) {
				cr = tcp->tcp_cred;
				pid = tcp->tcp_cpid;
			}
			mblk_setcred(syn_mp, cr);
			DB_CPID(syn_mp) = pid;
			tcp_send_data(tcp, tcp->tcp_wq, syn_mp);
		}
	after_syn_sent:
		if (mp != NULL) {
			ASSERT(mp->b_cont == NULL);
			freeb(mp);
		}
		return (error);
	} else {
		/* error */
		if (tcp->tcp_debug) {
			(void) strlog(TCP_MOD_ID, 0, 1, SL_TRACE|SL_ERROR,
			    "tcp_post_ip_bind: error == %d", error);
		}
		if (mp != NULL) {
			freeb(mp);
		}
	}

ipcl_rm:
	/*
	 * Need to unbind with classifier since we were just
	 * told that our bind succeeded. a.k.a error == 0 at the entry.
	 */
	tcp->tcp_hard_bound = B_FALSE;
	tcp->tcp_hard_binding = B_FALSE;

	ipcl_hash_remove(connp);

bind_failed:
	tcp->tcp_state = TCPS_IDLE;
	if (tcp->tcp_ipversion == IPV4_VERSION)
		tcp->tcp_ipha->ipha_src = 0;
	else
		V6_SET_ZERO(tcp->tcp_ip6h->ip6_src);
	/*
	 * Copy of the src addr. in tcp_t is needed since
	 * the lookup funcs. can only look at tcp_t
	 */
	V6_SET_ZERO(tcp->tcp_ip_src_v6);

	tcph = tcp->tcp_tcph;
	tcph->th_lport[0] = 0;
	tcph->th_lport[1] = 0;
	tcp_bind_hash_remove(tcp);
	bzero(&connp->u_port, sizeof (connp->u_port));
	/* blow away saved option results if any */
	if (tcp->tcp_conn.tcp_opts_conn_req != NULL)
		tcp_close_mpp(&tcp->tcp_conn.tcp_opts_conn_req);

	conn_delete_ire(tcp->tcp_connp, NULL);

	return (error);
}

static int
tcp_bind_select_lport(tcp_t *tcp, in_port_t *requested_port_ptr,
    boolean_t bind_to_req_port_only, cred_t *cr)
{
	in_port_t	mlp_port;
	mlp_type_t 	addrtype, mlptype;
	boolean_t	user_specified;
	in_port_t	allocated_port;
	in_port_t	requested_port = *requested_port_ptr;
	conn_t		*connp;
	zone_t		*zone;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	in6_addr_t	v6addr = tcp->tcp_ip_src_v6;

	/*
	 * XXX It's up to the caller to specify bind_to_req_port_only or not.
	 */
	if (cr == NULL)
		cr = tcp->tcp_cred;
	/*
	 * Get a valid port (within the anonymous range and should not
	 * be a privileged one) to use if the user has not given a port.
	 * If multiple threads are here, they may all start with
	 * with the same initial port. But, it should be fine as long as
	 * tcp_bindi will ensure that no two threads will be assigned
	 * the same port.
	 *
	 * NOTE: XXX If a privileged process asks for an anonymous port, we
	 * still check for ports only in the range > tcp_smallest_non_priv_port,
	 * unless TCP_ANONPRIVBIND option is set.
	 */
	mlptype = mlptSingle;
	mlp_port = requested_port;
	if (requested_port == 0) {
		requested_port = tcp->tcp_anon_priv_bind ?
		    tcp_get_next_priv_port(tcp) :
		    tcp_update_next_port(tcps->tcps_next_port_to_try,
		    tcp, B_TRUE);
		if (requested_port == 0) {
			return (-TNOADDR);
		}
		user_specified = B_FALSE;

		/*
		 * If the user went through one of the RPC interfaces to create
		 * this socket and RPC is MLP in this zone, then give him an
		 * anonymous MLP.
		 */
		connp = tcp->tcp_connp;
		if (connp->conn_anon_mlp && is_system_labeled()) {
			zone = crgetzone(cr);
			addrtype = tsol_mlp_addr_type(zone->zone_id,
			    IPV6_VERSION, &v6addr,
			    tcps->tcps_netstack->netstack_ip);
			if (addrtype == mlptSingle) {
				return (-TNOADDR);
			}
			mlptype = tsol_mlp_port_type(zone, IPPROTO_TCP,
			    PMAPPORT, addrtype);
			mlp_port = PMAPPORT;
		}
	} else {
		int i;
		boolean_t priv = B_FALSE;

		/*
		 * If the requested_port is in the well-known privileged range,
		 * verify that the stream was opened by a privileged user.
		 * Note: No locks are held when inspecting tcp_g_*epriv_ports
		 * but instead the code relies on:
		 * - the fact that the address of the array and its size never
		 *   changes
		 * - the atomic assignment of the elements of the array
		 */
		if (requested_port < tcps->tcps_smallest_nonpriv_port) {
			priv = B_TRUE;
		} else {
			for (i = 0; i < tcps->tcps_g_num_epriv_ports; i++) {
				if (requested_port ==
				    tcps->tcps_g_epriv_ports[i]) {
					priv = B_TRUE;
					break;
				}
			}
		}
		if (priv) {
			if (secpolicy_net_privaddr(cr, requested_port,
			    IPPROTO_TCP) != 0) {
				if (tcp->tcp_debug) {
					(void) strlog(TCP_MOD_ID, 0, 1,
					    SL_ERROR|SL_TRACE,
					    "tcp_bind: no priv for port %d",
					    requested_port);
				}
				return (-TACCES);
			}
		}
		user_specified = B_TRUE;

		connp = tcp->tcp_connp;
		if (is_system_labeled()) {
			zone = crgetzone(cr);
			addrtype = tsol_mlp_addr_type(zone->zone_id,
			    IPV6_VERSION, &v6addr,
			    tcps->tcps_netstack->netstack_ip);
			if (addrtype == mlptSingle) {
				return (-TNOADDR);
			}
			mlptype = tsol_mlp_port_type(zone, IPPROTO_TCP,
			    requested_port, addrtype);
		}
	}

	if (mlptype != mlptSingle) {
		if (secpolicy_net_bindmlp(cr) != 0) {
			if (tcp->tcp_debug) {
				(void) strlog(TCP_MOD_ID, 0, 1,
				    SL_ERROR|SL_TRACE,
				    "tcp_bind: no priv for multilevel port %d",
				    requested_port);
			}
			return (-TACCES);
		}

		/*
		 * If we're specifically binding a shared IP address and the
		 * port is MLP on shared addresses, then check to see if this
		 * zone actually owns the MLP.  Reject if not.
		 */
		if (mlptype == mlptShared && addrtype == mlptShared) {
			/*
			 * No need to handle exclusive-stack zones since
			 * ALL_ZONES only applies to the shared stack.
			 */
			zoneid_t mlpzone;

			mlpzone = tsol_mlp_findzone(IPPROTO_TCP,
			    htons(mlp_port));
			if (connp->conn_zoneid != mlpzone) {
				if (tcp->tcp_debug) {
					(void) strlog(TCP_MOD_ID, 0, 1,
					    SL_ERROR|SL_TRACE,
					    "tcp_bind: attempt to bind port "
					    "%d on shared addr in zone %d "
					    "(should be %d)",
					    mlp_port, connp->conn_zoneid,
					    mlpzone);
				}
				return (-TACCES);
			}
		}

		if (!user_specified) {
			int err;
			err = tsol_mlp_anon(zone, mlptype, connp->conn_ulp,
			    requested_port, B_TRUE);
			if (err != 0) {
				if (tcp->tcp_debug) {
					(void) strlog(TCP_MOD_ID, 0, 1,
					    SL_ERROR|SL_TRACE,
					    "tcp_bind: cannot establish anon "
					    "MLP for port %d",
					    requested_port);
				}
				return (err);
			}
			connp->conn_anon_port = B_TRUE;
		}
		connp->conn_mlp_type = mlptype;
	}

	allocated_port = tcp_bindi(tcp, requested_port, &v6addr,
	    tcp->tcp_reuseaddr, B_FALSE, bind_to_req_port_only, user_specified);

	if (allocated_port == 0) {
		connp->conn_mlp_type = mlptSingle;
		if (connp->conn_anon_port) {
			connp->conn_anon_port = B_FALSE;
			(void) tsol_mlp_anon(zone, mlptype, connp->conn_ulp,
			    requested_port, B_FALSE);
		}
		if (bind_to_req_port_only) {
			if (tcp->tcp_debug) {
				(void) strlog(TCP_MOD_ID, 0, 1,
				    SL_ERROR|SL_TRACE,
				    "tcp_bind: requested addr busy");
			}
			return (-TADDRBUSY);
		} else {
			/* If we are out of ports, fail the bind. */
			if (tcp->tcp_debug) {
				(void) strlog(TCP_MOD_ID, 0, 1,
				    SL_ERROR|SL_TRACE,
				    "tcp_bind: out of ports?");
			}
			return (-TNOADDR);
		}
	}

	/* Pass the allocated port back */
	*requested_port_ptr = allocated_port;
	return (0);
}

static int
tcp_bind_check(conn_t *connp, struct sockaddr *sa, socklen_t len, cred_t *cr,
    boolean_t bind_to_req_port_only)
{
	tcp_t	*tcp = connp->conn_tcp;

	sin_t	*sin;
	sin6_t  *sin6;
	sin6_t		sin6addr;
	in_port_t requested_port;
	ipaddr_t	v4addr;
	in6_addr_t	v6addr;
	uint_t	origipversion;
	int	error = 0;

	ASSERT((uintptr_t)len <= (uintptr_t)INT_MAX);

	if (tcp->tcp_state == TCPS_BOUND) {
		return (0);
	} else if (tcp->tcp_state > TCPS_BOUND) {
		if (tcp->tcp_debug) {
			(void) strlog(TCP_MOD_ID, 0, 1, SL_ERROR|SL_TRACE,
			    "tcp_bind: bad state, %d", tcp->tcp_state);
		}
		return (-TOUTSTATE);
	}
	origipversion = tcp->tcp_ipversion;

	if (sa != NULL && !OK_32PTR((char *)sa)) {
		if (tcp->tcp_debug) {
			(void) strlog(TCP_MOD_ID, 0, 1,
			    SL_ERROR|SL_TRACE,
			    "tcp_bind: bad address parameter, "
			    "address %p, len %d",
			    (void *)sa, len);
		}
		return (-TPROTO);
	}

	switch (len) {
	case 0:		/* request for a generic port */
		if (tcp->tcp_family == AF_INET) {
			sin = (sin_t *)&sin6addr;
			*sin = sin_null;
			sin->sin_family = AF_INET;
			tcp->tcp_ipversion = IPV4_VERSION;
			IN6_IPADDR_TO_V4MAPPED(INADDR_ANY, &v6addr);
		} else {
			ASSERT(tcp->tcp_family == AF_INET6);
			sin6 = (sin6_t *)&sin6addr;
			*sin6 = sin6_null;
			sin6->sin6_family = AF_INET6;
			tcp->tcp_ipversion = IPV6_VERSION;
			V6_SET_ZERO(v6addr);
		}
		requested_port = 0;
		break;

	case sizeof (sin_t):	/* Complete IPv4 address */
		sin = (sin_t *)sa;
		/*
		 * With sockets sockfs will accept bogus sin_family in
		 * bind() and replace it with the family used in the socket
		 * call.
		 */
		if (sin->sin_family != AF_INET ||
		    tcp->tcp_family != AF_INET) {
			return (EAFNOSUPPORT);
		}
		requested_port = ntohs(sin->sin_port);
		tcp->tcp_ipversion = IPV4_VERSION;
		v4addr = sin->sin_addr.s_addr;
		IN6_IPADDR_TO_V4MAPPED(v4addr, &v6addr);
		break;

	case sizeof (sin6_t): /* Complete IPv6 address */
		sin6 = (sin6_t *)sa;
		if (sin6->sin6_family != AF_INET6 ||
		    tcp->tcp_family != AF_INET6) {
			return (EAFNOSUPPORT);
		}
		requested_port = ntohs(sin6->sin6_port);
		tcp->tcp_ipversion = IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr) ?
		    IPV4_VERSION : IPV6_VERSION;
		v6addr = sin6->sin6_addr;
		break;

	default:
		if (tcp->tcp_debug) {
			(void) strlog(TCP_MOD_ID, 0, 1, SL_ERROR|SL_TRACE,
			    "tcp_bind: bad address length, %d", len);
		}
		return (EAFNOSUPPORT);
		/* return (-TBADADDR); */
	}

	tcp->tcp_bound_source_v6 = v6addr;

	/* Check for change in ipversion */
	if (origipversion != tcp->tcp_ipversion) {
		ASSERT(tcp->tcp_family == AF_INET6);
		error = tcp->tcp_ipversion == IPV6_VERSION ?
		    tcp_header_init_ipv6(tcp) : tcp_header_init_ipv4(tcp);
		if (error) {
			return (ENOMEM);
		}
	}

	/*
	 * Initialize family specific fields. Copy of the src addr.
	 * in tcp_t is needed for the lookup funcs.
	 */
	if (tcp->tcp_ipversion == IPV6_VERSION) {
		tcp->tcp_ip6h->ip6_src = v6addr;
	} else {
		IN6_V4MAPPED_TO_IPADDR(&v6addr, tcp->tcp_ipha->ipha_src);
	}
	tcp->tcp_ip_src_v6 = v6addr;

	bind_to_req_port_only = requested_port != 0 && bind_to_req_port_only;

	error = tcp_bind_select_lport(tcp, &requested_port,
	    bind_to_req_port_only, cr);

	return (error);
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
		if (tcp->tcp_debug) {
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

	/*
	 * We need to make sure that the conn_recv is set to a non-null
	 * value before we insert the conn into the classifier table.
	 * This is to avoid a race with an incoming packet which does an
	 * ipcl_classify().
	 */
	connp->conn_recv = tcp_conn_request;

	if (tcp->tcp_family == AF_INET6) {
		ASSERT(tcp->tcp_connp->conn_af_isv6);
		error = ip_proto_bind_laddr_v6(connp, NULL, IPPROTO_TCP,
		    &tcp->tcp_bound_source_v6, 0, B_FALSE);
	} else {
		ASSERT(!tcp->tcp_connp->conn_af_isv6);
		error = ip_proto_bind_laddr_v4(connp, NULL, IPPROTO_TCP,
		    tcp->tcp_ipha->ipha_src, 0, B_FALSE);
	}
	return (tcp_post_ip_bind(tcp, NULL, error, NULL, 0));
}

int
tcp_bind(sock_lower_handle_t proto_handle, struct sockaddr *sa,
    socklen_t len, cred_t *cr)
{
	int 		error;
	conn_t		*connp = (conn_t *)proto_handle;
	squeue_t	*sqp = connp->conn_sqp;

	ASSERT(sqp != NULL);

	error = squeue_synch_enter(sqp, connp, 0);
	if (error != 0) {
		/* failed to enter */
		return (ENOSR);
	}

	/* binding to a NULL address really means unbind */
	if (sa == NULL) {
		if (connp->conn_tcp->tcp_state < TCPS_LISTEN)
			error = tcp_do_unbind(connp);
		else
			error = EINVAL;
	} else {
		error = tcp_do_bind(connp, sa, len, cr, B_TRUE);
	}

	squeue_synch_exit(sqp, connp);

	if (error < 0) {
		if (error == -TOUTSTATE)
			error = EINVAL;
		else
			error = proto_tlitosyserr(-error);
	}

	return (error);
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
	int		error = 0;

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
		if (tcp->tcp_connp && tcp->tcp_connp->conn_ipv6_v6only) {
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
	 * make sure that the template IP header in the tcp structure is an
	 * IPv4 header, and that the tcp_ipversion is IPV4_VERSION.  We
	 * need to this before we call tcp_bindi() so that the port lookup
	 * code will look for ports in the correct port space (IPv4 and
	 * IPv6 have separate port spaces).
	 */
	if (tcp->tcp_family == AF_INET6 && tcp->tcp_ipversion == IPV6_VERSION &&
	    IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
		int err = 0;

		err = tcp_header_init_ipv4(tcp);
			if (err != 0) {
				error = ENOMEM;
				goto connect_failed;
			}
		if (tcp->tcp_lport != 0)
			*(uint16_t *)tcp->tcp_tcph->th_lport = tcp->tcp_lport;
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
		/*
		 * We must bump the generation before the operation start.
		 * This is done to ensure that any upcall made later on sends
		 * up the right generation to the socket.
		 */
		SOCK_CONNID_BUMP(tcp->tcp_connid);

		if (tcp->tcp_family == AF_INET6) {
			if (!IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
				return (tcp_connect_ipv6(tcp,
				    &sin6->sin6_addr,
				    sin6->sin6_port, sin6->sin6_flowinfo,
				    sin6->__sin6_src_id, sin6->sin6_scope_id,
				    cr, pid));
			}
			/*
			 * Destination adress is mapped IPv6 address.
			 * Source bound address should be unspecified or
			 * IPv6 mapped address as well.
			 */
			if (!IN6_IS_ADDR_UNSPECIFIED(
			    &tcp->tcp_bound_source_v6) &&
			    !IN6_IS_ADDR_V4MAPPED(&tcp->tcp_bound_source_v6)) {
				return (EADDRNOTAVAIL);
			}
			dstaddrp = &V4_PART_OF_V6((sin6->sin6_addr));
			dstport = sin6->sin6_port;
			srcid = sin6->__sin6_src_id;
		} else {
			dstaddrp = &sin->sin_addr.s_addr;
			dstport = sin->sin_port;
			srcid = 0;
		}

		error = tcp_connect_ipv4(tcp, dstaddrp, dstport, srcid, cr,
		    pid);
		break;
	default:
		return (-TOUTSTATE);
	}
	/*
	 * Note: Code below is the "failure" case
	 */
connect_failed:
	if (tcp->tcp_conn.tcp_opts_conn_req != NULL)
		tcp_close_mpp(&tcp->tcp_conn.tcp_opts_conn_req);
	return (error);
}

int
tcp_connect(sock_lower_handle_t proto_handle, const struct sockaddr *sa,
    socklen_t len, sock_connid_t *id, cred_t *cr)
{
	conn_t		*connp = (conn_t *)proto_handle;
	tcp_t		*tcp = connp->conn_tcp;
	squeue_t	*sqp = connp->conn_sqp;
	int		error;

	error = proto_verify_ip_addr(tcp->tcp_family, sa, len);
	if (error != 0) {
		return (error);
	}

	error = squeue_synch_enter(sqp, connp, 0);
	if (error != 0) {
		/* failed to enter */
		return (ENOSR);
	}

	/*
	 * TCP supports quick connect, so no need to do an implicit bind
	 */
	error = tcp_do_connect(connp, sa, len, cr, curproc->p_pid);
	if (error == 0) {
		*id = connp->conn_tcp->tcp_connid;
	} else if (error < 0) {
		if (error == -TOUTSTATE) {
			switch (connp->conn_tcp->tcp_state) {
			case TCPS_SYN_SENT:
				error = EALREADY;
				break;
			case TCPS_ESTABLISHED:
				error = EISCONN;
				break;
			case TCPS_LISTEN:
				error = EOPNOTSUPP;
				break;
			default:
				error = EINVAL;
				break;
			}
		} else {
			error = proto_tlitosyserr(-error);
		}
	}
done:
	squeue_synch_exit(sqp, connp);

	return ((error == 0) ? EINPROGRESS : error);
}

/* ARGSUSED */
sock_lower_handle_t
tcp_create(int family, int type, int proto, sock_downcalls_t **sock_downcalls,
    uint_t *smodep, int *errorp, int flags, cred_t *credp)
{
	conn_t		*connp;
	boolean_t	isv6 = family == AF_INET6;
	if (type != SOCK_STREAM || (family != AF_INET && family != AF_INET6) ||
	    (proto != 0 && proto != IPPROTO_TCP)) {
		*errorp = EPROTONOSUPPORT;
		return (NULL);
	}

	connp = tcp_create_common(NULL, credp, isv6, B_TRUE, errorp);
	if (connp == NULL) {
		return (NULL);
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

	connp->conn_flags |= IPCL_NONSTR;
	mutex_exit(&connp->conn_lock);

	ASSERT(errorp != NULL);
	*errorp = 0;
	*sock_downcalls = &sock_tcp_downcalls;
	*smodep = SM_CONNREQUIRED | SM_EXDATA | SM_ACCEPTSUPP |
	    SM_SENDFILESUPP;

	return ((sock_lower_handle_t)connp);
}

/* ARGSUSED */
void
tcp_activate(sock_lower_handle_t proto_handle, sock_upper_handle_t sock_handle,
    sock_upcalls_t *sock_upcalls, int flags, cred_t *cr)
{
	conn_t *connp = (conn_t *)proto_handle;
	struct sock_proto_props sopp;

	sopp.sopp_flags = SOCKOPT_RCVHIWAT | SOCKOPT_RCVLOWAT |
	    SOCKOPT_MAXPSZ | SOCKOPT_MAXBLK | SOCKOPT_RCVTIMER |
	    SOCKOPT_RCVTHRESH | SOCKOPT_MAXADDRLEN | SOCKOPT_MINPSZ;

	sopp.sopp_rxhiwat = SOCKET_RECVHIWATER;
	sopp.sopp_rxlowat = SOCKET_RECVLOWATER;
	sopp.sopp_maxpsz = INFPSZ;
	sopp.sopp_maxblk = INFPSZ;
	sopp.sopp_rcvtimer = SOCKET_TIMER_INTERVAL;
	sopp.sopp_rcvthresh = SOCKET_RECVHIWATER >> 3;
	sopp.sopp_maxaddrlen = sizeof (sin6_t);
	sopp.sopp_minpsz = (tcp_rinfo.mi_minpsz == 1) ? 0 :
	    tcp_rinfo.mi_minpsz;

	connp->conn_upcalls = sock_upcalls;
	connp->conn_upper_handle = sock_handle;

	(*sock_upcalls->su_set_proto_props)(sock_handle, &sopp);
}

/* ARGSUSED */
int
tcp_close(sock_lower_handle_t proto_handle, int flags, cred_t *cr)
{
	conn_t *connp = (conn_t *)proto_handle;

	tcp_close_common(connp, flags);

	ip_free_helper_stream(connp);

	/*
	 * Drop IP's reference on the conn. This is the last reference
	 * on the connp if the state was less than established. If the
	 * connection has gone into timewait state, then we will have
	 * one ref for the TCP and one more ref (total of two) for the
	 * classifier connected hash list (a timewait connections stays
	 * in connected hash till closed).
	 *
	 * We can't assert the references because there might be other
	 * transient reference places because of some walkers or queued
	 * packets in squeue for the timewait state.
	 */
	CONN_DEC_REF(connp);
	return (0);
}

/* ARGSUSED */
int
tcp_sendmsg(sock_lower_handle_t proto_handle, mblk_t *mp, struct nmsghdr *msg,
    cred_t *cr)
{
	tcp_t		*tcp;
	uint32_t	msize;
	conn_t *connp = (conn_t *)proto_handle;
	int32_t		tcpstate;

	ASSERT(connp->conn_ref >= 2);

	if (msg->msg_controllen != 0) {
		return (EOPNOTSUPP);

	}
	switch (DB_TYPE(mp)) {
	case M_DATA:
		tcp = connp->conn_tcp;
		ASSERT(tcp != NULL);

		tcpstate = tcp->tcp_state;
		if (tcpstate < TCPS_ESTABLISHED) {
			freemsg(mp);
			return (ENOTCONN);
		} else if (tcpstate > TCPS_CLOSE_WAIT) {
			freemsg(mp);
			return (EPIPE);
		}

		msize = msgdsize(mp);

		mutex_enter(&tcp->tcp_non_sq_lock);
		tcp->tcp_squeue_bytes += msize;
		/*
		 * Squeue Flow Control
		 */
		if (TCP_UNSENT_BYTES(tcp) > tcp->tcp_xmit_hiwater) {
			tcp_setqfull(tcp);
		}
		mutex_exit(&tcp->tcp_non_sq_lock);

		/*
		 * The application may pass in an address in the msghdr, but
		 * we ignore the address on connection-oriented sockets.
		 * Just like BSD this code does not generate an error for
		 * TCP (a CONNREQUIRED socket) when sending to an address
		 * passed in with sendto/sendmsg. Instead the data is
		 * delivered on the connection as if no address had been
		 * supplied.
		 */
		CONN_INC_REF(connp);

		if (msg != NULL && msg->msg_flags & MSG_OOB) {
			SQUEUE_ENTER_ONE(connp->conn_sqp, mp,
			    tcp_output_urgent, connp, tcp_squeue_flag,
			    SQTAG_TCP_OUTPUT);
		} else {
			SQUEUE_ENTER_ONE(connp->conn_sqp, mp, tcp_output,
			    connp, tcp_squeue_flag, SQTAG_TCP_OUTPUT);
		}

		return (0);

	default:
		ASSERT(0);
	}

	freemsg(mp);
	return (0);
}

/* ARGSUSED */
void
tcp_output_urgent(void *arg, mblk_t *mp, void *arg2)
{
	int len;
	uint32_t msize;
	conn_t *connp = (conn_t *)arg;
	tcp_t *tcp = connp->conn_tcp;

	msize = msgdsize(mp);

	len = msize - 1;
	if (len < 0) {
		freemsg(mp);
		return;
	}

	/*
	 * Try to force urgent data out on the wire.
	 * Even if we have unsent data this will
	 * at least send the urgent flag.
	 * XXX does not handle more flag correctly.
	 */
	len += tcp->tcp_unsent;
	len += tcp->tcp_snxt;
	tcp->tcp_urg = len;
	tcp->tcp_valid_bits |= TCP_URG_VALID;

	/* Bypass tcp protocol for fused tcp loopback */
	if (tcp->tcp_fused && tcp_fuse_output(tcp, mp, msize))
		return;
	tcp_wput_data(tcp, mp, B_TRUE);
}

/* ARGSUSED */
int
tcp_getpeername(sock_lower_handle_t proto_handle, struct sockaddr *addr,
    socklen_t *addrlen, cred_t *cr)
{
	sin_t   *sin;
	sin6_t  *sin6;
	conn_t	*connp = (conn_t *)proto_handle;
	tcp_t	*tcp = connp->conn_tcp;

	ASSERT(tcp != NULL);
	if (tcp->tcp_state < TCPS_SYN_RCVD)
		return (ENOTCONN);

	addr->sa_family = tcp->tcp_family;
	switch (tcp->tcp_family) {
	case AF_INET:
		if (*addrlen < sizeof (sin_t))
			return (EINVAL);

		sin = (sin_t *)addr;
		*sin = sin_null;
		sin->sin_family = AF_INET;
		if (tcp->tcp_ipversion == IPV4_VERSION) {
			IN6_V4MAPPED_TO_IPADDR(&tcp->tcp_remote_v6,
			    sin->sin_addr.s_addr);
		}
		sin->sin_port = tcp->tcp_fport;
		*addrlen = sizeof (struct sockaddr_in);
		break;
	case AF_INET6:
		sin6 = (sin6_t *)addr;
		*sin6 = sin6_null;
		sin6->sin6_family = AF_INET6;

		if (*addrlen < sizeof (struct sockaddr_in6))
			return (EINVAL);

		if (tcp->tcp_ipversion == IPV6_VERSION) {
			sin6->sin6_flowinfo = tcp->tcp_ip6h->ip6_vcf &
			    ~IPV6_VERS_AND_FLOW_MASK;
		}

		sin6->sin6_addr = tcp->tcp_remote_v6;
		sin6->sin6_port = tcp->tcp_fport;
		*addrlen = sizeof (struct sockaddr_in6);
		break;
	}
	return (0);
}

/* ARGSUSED */
int
tcp_getsockname(sock_lower_handle_t proto_handle, struct sockaddr *addr,
    socklen_t *addrlenp, cred_t *cr)
{
	sin_t   *sin;
	sin6_t  *sin6;
	conn_t	*connp = (conn_t *)proto_handle;
	tcp_t	*tcp = connp->conn_tcp;

	switch (tcp->tcp_family) {
	case AF_INET:
		ASSERT(tcp->tcp_ipversion == IPV4_VERSION);
		if (*addrlenp < sizeof (sin_t))
			return (EINVAL);
		sin = (sin_t *)addr;
		*sin = sin_null;
		sin->sin_family = AF_INET;
		*addrlenp = sizeof (sin_t);
		if (tcp->tcp_state >= TCPS_BOUND) {
			sin->sin_addr.s_addr =  tcp->tcp_ipha->ipha_src;
			sin->sin_port = tcp->tcp_lport;
		}
		break;

	case AF_INET6:
		if (*addrlenp < sizeof (sin6_t))
			return (EINVAL);
		sin6 = (sin6_t *)addr;
		*sin6 = sin6_null;
		sin6->sin6_family = AF_INET6;
		*addrlenp = sizeof (sin6_t);
		if (tcp->tcp_state >= TCPS_BOUND) {
			sin6->sin6_port = tcp->tcp_lport;
			if (tcp->tcp_ipversion == IPV4_VERSION) {
				IN6_IPADDR_TO_V4MAPPED(tcp->tcp_ipha->ipha_src,
				    &sin6->sin6_addr);
			} else {
				sin6->sin6_addr = tcp->tcp_ip6h->ip6_src;
			}
		}
		break;
	}
	return (0);
}

/*
 * tcp_fallback
 *
 * A direct socket is falling back to using STREAMS. Hanging
 * off of the queue is a temporary tcp_t, which was created using
 * tcp_open(). The tcp_open() was called as part of the regular
 * sockfs create path, i.e., the SO_SOCKSTR flag is passed down,
 * and therefore the temporary tcp_t is marked to be a socket
 * (i.e., IPCL_SOCKET, tcp_issocket). So the optimizations
 * introduced by FireEngine will be used.
 *
 * The tcp_t associated with the socket falling back will
 * still be marked as a socket, although the direct socket flag
 * (IPCL_NONSTR) is removed. A fall back to true TPI semantics
 * will not take place until a _SIOCSOCKFALLBACK ioctl is issued.
 *
 * If the above mentioned behavior, i.e., the tmp tcp_t is created
 * as a STREAMS/TPI endpoint, then we will need to do more work here.
 * Such as inserting the direct socket into the acceptor hash.
 */
void
tcp_fallback(sock_lower_handle_t proto_handle, queue_t *q,
    boolean_t direct_sockfs, so_proto_quiesced_cb_t quiesced_cb)
{
	tcp_t			*tcp, *eager;
	conn_t 			*connp = (conn_t *)proto_handle;
	int			error;
	struct T_capability_ack tca;
	struct sockaddr_in6	laddr, faddr;
	socklen_t 		laddrlen, faddrlen;
	short			opts;
	struct stroptions	*stropt;
	mblk_t			*stropt_mp;
	mblk_t			*mp;
	mblk_t			*conn_ind_head = NULL;
	mblk_t			*conn_ind_tail = NULL;
	mblk_t			*ordrel_mp;
	mblk_t			*fused_sigurp_mp;

	tcp = connp->conn_tcp;
	/*
	 * No support for acceptor fallback
	 */
	ASSERT(q->q_qinfo != &tcp_acceptor_rinit);

	stropt_mp = allocb_wait(sizeof (*stropt), BPRI_HI, STR_NOSIG, NULL);

	/* Pre-allocate the T_ordrel_ind mblk. */
	ASSERT(tcp->tcp_ordrel_mp == NULL);
	ordrel_mp = allocb_wait(sizeof (struct T_ordrel_ind), BPRI_HI,
	    STR_NOSIG, NULL);
	ordrel_mp->b_datap->db_type = M_PROTO;
	((struct T_ordrel_ind *)ordrel_mp->b_rptr)->PRIM_type = T_ORDREL_IND;
	ordrel_mp->b_wptr += sizeof (struct T_ordrel_ind);

	/* Pre-allocate the M_PCSIG anyway */
	fused_sigurp_mp = allocb_wait(1, BPRI_HI, STR_NOSIG, NULL);

	/*
	 * Enter the squeue so that no new packets can come in
	 */
	error = squeue_synch_enter(connp->conn_sqp, connp, 0);
	if (error != 0) {
		/* failed to enter, free all the pre-allocated messages. */
		freeb(stropt_mp);
		freeb(ordrel_mp);
		freeb(fused_sigurp_mp);
		return;
	}

	/* Disable I/OAT during fallback */
	tcp->tcp_sodirect = NULL;

	connp->conn_dev = (dev_t)RD(q)->q_ptr;
	connp->conn_minor_arena = WR(q)->q_ptr;

	RD(q)->q_ptr = WR(q)->q_ptr = connp;

	connp->conn_tcp->tcp_rq = connp->conn_rq = RD(q);
	connp->conn_tcp->tcp_wq = connp->conn_wq = WR(q);

	WR(q)->q_qinfo = &tcp_sock_winit;

	if (!direct_sockfs)
		tcp_disable_direct_sockfs(tcp);

	/*
	 * free the helper stream
	 */
	ip_free_helper_stream(connp);

	/*
	 * Notify the STREAM head about options
	 */
	DB_TYPE(stropt_mp) = M_SETOPTS;
	stropt = (struct stroptions *)stropt_mp->b_rptr;
	stropt_mp->b_wptr += sizeof (struct stroptions);
	stropt = (struct stroptions *)stropt_mp->b_rptr;
	stropt->so_flags |= SO_HIWAT | SO_WROFF | SO_MAXBLK;

	stropt->so_wroff = tcp->tcp_hdr_len + (tcp->tcp_loopback ? 0 :
	    tcp->tcp_tcps->tcps_wroff_xtra);
	if (tcp->tcp_snd_sack_ok)
		stropt->so_wroff += TCPOPT_MAX_SACK_LEN;
	stropt->so_hiwat = tcp->tcp_fused ?
	    tcp_fuse_set_rcv_hiwat(tcp, tcp->tcp_recv_hiwater) :
	    MAX(tcp->tcp_recv_hiwater, tcp->tcp_tcps->tcps_sth_rcv_hiwat);
	stropt->so_maxblk = tcp_maxpsz_set(tcp, B_FALSE);

	putnext(RD(q), stropt_mp);

	/*
	 * Collect the information needed to sync with the sonode
	 */
	tcp_do_capability_ack(tcp, &tca, TC1_INFO|TC1_ACCEPTOR_ID);

	laddrlen = faddrlen = sizeof (sin6_t);
	(void) tcp_getsockname(proto_handle, (struct sockaddr *)&laddr,
	    &laddrlen, CRED());
	error = tcp_getpeername(proto_handle, (struct sockaddr *)&faddr,
	    &faddrlen, CRED());
	if (error != 0)
		faddrlen = 0;

	opts = 0;
	if (tcp->tcp_oobinline)
		opts |= SO_OOBINLINE;
	if (tcp->tcp_dontroute)
		opts |= SO_DONTROUTE;

	/*
	 * Notify the socket that the protocol is now quiescent,
	 * and it's therefore safe move data from the socket
	 * to the stream head.
	 */
	(*quiesced_cb)(connp->conn_upper_handle, q, &tca,
	    (struct sockaddr *)&laddr, laddrlen,
	    (struct sockaddr *)&faddr, faddrlen, opts);

	while ((mp = tcp->tcp_rcv_list) != NULL) {
		tcp->tcp_rcv_list = mp->b_next;
		mp->b_next = NULL;
		putnext(q, mp);
	}
	tcp->tcp_rcv_last_head = NULL;
	tcp->tcp_rcv_last_tail = NULL;
	tcp->tcp_rcv_cnt = 0;

	/*
	 * No longer a direct socket
	 */
	connp->conn_flags &= ~IPCL_NONSTR;

	tcp->tcp_ordrel_mp = ordrel_mp;

	if (tcp->tcp_fused) {
		ASSERT(tcp->tcp_fused_sigurg_mp == NULL);
		tcp->tcp_fused_sigurg_mp = fused_sigurp_mp;
	} else {
		freeb(fused_sigurp_mp);
	}

	/*
	 * Send T_CONN_IND messages for all ESTABLISHED connections.
	 */
	mutex_enter(&tcp->tcp_eager_lock);
	for (eager = tcp->tcp_eager_next_q; eager != NULL;
	    eager = eager->tcp_eager_next_q) {
		mp = eager->tcp_conn.tcp_eager_conn_ind;

		eager->tcp_conn.tcp_eager_conn_ind = NULL;
		ASSERT(mp != NULL);
		/*
		 * TLI/XTI applications will get confused by
		 * sending eager as an option since it violates
		 * the option semantics. So remove the eager as
		 * option since TLI/XTI app doesn't need it anyway.
		 */
		if (!TCP_IS_SOCKET(tcp)) {
			struct T_conn_ind *conn_ind;

			conn_ind = (struct T_conn_ind *)mp->b_rptr;
			conn_ind->OPT_length = 0;
			conn_ind->OPT_offset = 0;
		}
		if (conn_ind_head == NULL) {
			conn_ind_head = mp;
		} else {
			conn_ind_tail->b_next = mp;
		}
		conn_ind_tail = mp;
	}
	mutex_exit(&tcp->tcp_eager_lock);

	mp = conn_ind_head;
	while (mp != NULL) {
		mblk_t *nmp = mp->b_next;
		mp->b_next = NULL;

		putnext(tcp->tcp_rq, mp);
		mp = nmp;
	}

	/*
	 * There should be atleast two ref's (IP + TCP)
	 */
	ASSERT(connp->conn_ref >= 2);
	squeue_synch_exit(connp->conn_sqp, connp);
}

/* ARGSUSED */
static void
tcp_shutdown_output(void *arg, mblk_t *mp, void *arg2)
{
	conn_t 	*connp = (conn_t *)arg;
	tcp_t	*tcp = connp->conn_tcp;

	freemsg(mp);

	if (tcp->tcp_fused)
		tcp_unfuse(tcp);

	if (tcp_xmit_end(tcp) != 0) {
		/*
		 * We were crossing FINs and got a reset from
		 * the other side. Just ignore it.
		 */
		if (tcp->tcp_debug) {
			(void) strlog(TCP_MOD_ID, 0, 1,
			    SL_ERROR|SL_TRACE,
			    "tcp_shutdown_output() out of state %s",
			    tcp_display(tcp, NULL, DISP_ADDR_AND_PORT));
		}
	}
}

/* ARGSUSED */
int
tcp_shutdown(sock_lower_handle_t proto_handle, int how, cred_t *cr)
{
	conn_t  *connp = (conn_t *)proto_handle;
	tcp_t   *tcp = connp->conn_tcp;

	/*
	 * X/Open requires that we check the connected state.
	 */
	if (tcp->tcp_state < TCPS_SYN_SENT)
		return (ENOTCONN);

	/* shutdown the send side */
	if (how != SHUT_RD) {
		mblk_t *bp;

		bp = allocb_wait(0, BPRI_HI, STR_NOSIG, NULL);
		CONN_INC_REF(connp);
		SQUEUE_ENTER_ONE(connp->conn_sqp, bp, tcp_shutdown_output,
		    connp, SQ_NODRAIN, SQTAG_TCP_SHUTDOWN_OUTPUT);

		(*connp->conn_upcalls->su_opctl)(connp->conn_upper_handle,
		    SOCK_OPCTL_SHUT_SEND, 0);
	}

	/* shutdown the recv side */
	if (how != SHUT_WR)
		(*connp->conn_upcalls->su_opctl)(connp->conn_upper_handle,
		    SOCK_OPCTL_SHUT_RECV, 0);

	return (0);
}

/*
 * SOP_LISTEN() calls into tcp_listen().
 */
/* ARGSUSED */
int
tcp_listen(sock_lower_handle_t proto_handle, int backlog, cred_t *cr)
{
	conn_t	*connp = (conn_t *)proto_handle;
	int 	error;
	squeue_t *sqp = connp->conn_sqp;

	error = squeue_synch_enter(sqp, connp, 0);
	if (error != 0) {
		/* failed to enter */
		return (ENOBUFS);
	}

	error = tcp_do_listen(connp, backlog, cr);
	if (error == 0) {
		(*connp->conn_upcalls->su_opctl)(connp->conn_upper_handle,
		    SOCK_OPCTL_ENAB_ACCEPT, (uintptr_t)backlog);
	} else if (error < 0) {
		if (error == -TOUTSTATE)
			error = EINVAL;
		else
			error = proto_tlitosyserr(-error);
	}
	squeue_synch_exit(sqp, connp);
	return (error);
}

static int
tcp_do_listen(conn_t *connp, int backlog, cred_t *cr)
{
	tcp_t		*tcp = connp->conn_tcp;
	sin_t		*sin;
	sin6_t  	*sin6;
	int		error = 0;
	tcp_stack_t	*tcps = tcp->tcp_tcps;

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
		if (tcp->tcp_debug) {
			(void) strlog(TCP_MOD_ID, 0, 1, SL_ERROR|SL_TRACE,
			    "tcp_listen: bad state, %d", tcp->tcp_state);
		}
		return (-TOUTSTATE);
	} else {
		int32_t len;
		sin6_t	addr;

		/* Do an implicit bind: Request for a generic port. */
		if (tcp->tcp_family == AF_INET) {
			len = sizeof (sin_t);
			sin = (sin_t *)&addr;
			*sin = sin_null;
			sin->sin_family = AF_INET;
			tcp->tcp_ipversion = IPV4_VERSION;
		} else {
			ASSERT(tcp->tcp_family == AF_INET6);
			len = sizeof (sin6_t);
			sin6 = (sin6_t *)&addr;
			*sin6 = sin6_null;
			sin6->sin6_family = AF_INET6;
			tcp->tcp_ipversion = IPV6_VERSION;
		}

		error = tcp_bind_check(connp, (struct sockaddr *)&addr, len,
		    cr, B_FALSE);
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
			/* Initialize the chain. Don't need the eager_lock */
			tcp->tcp_eager_next_q0 = tcp->tcp_eager_prev_q0 = tcp;
			tcp->tcp_eager_next_drop_q0 = tcp;
			tcp->tcp_eager_prev_drop_q0 = tcp;
			tcp->tcp_second_ctimer_threshold =
			    tcps->tcps_ip_abort_linterval;
		}
	}

	/*
	 * We can call ip_bind directly, the processing continues
	 * in tcp_post_ip_bind().
	 *
	 * We need to make sure that the conn_recv is set to a non-null
	 * value before we insert the conn into the classifier table.
	 * This is to avoid a race with an incoming packet which does an
	 * ipcl_classify().
	 */
	connp->conn_recv = tcp_conn_request;
	if (tcp->tcp_family == AF_INET) {
		error = ip_proto_bind_laddr_v4(connp, NULL,
		    IPPROTO_TCP, tcp->tcp_bound_source, tcp->tcp_lport, B_TRUE);
	} else {
		error = ip_proto_bind_laddr_v6(connp, NULL, IPPROTO_TCP,
		    &tcp->tcp_bound_source_v6, tcp->tcp_lport, B_TRUE);
	}
	return (tcp_post_ip_bind(tcp, NULL, error, NULL, 0));
}

void
tcp_clr_flowctrl(sock_lower_handle_t proto_handle)
{
	conn_t  *connp = (conn_t *)proto_handle;
	tcp_t	*tcp = connp->conn_tcp;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	uint_t thwin;

	(void) squeue_synch_enter(connp->conn_sqp, connp, 0);

	/* Flow control condition has been removed. */
	tcp->tcp_rwnd = tcp->tcp_recv_hiwater;
	thwin = ((uint_t)BE16_TO_U16(tcp->tcp_tcph->th_win))
	    << tcp->tcp_rcv_ws;
	thwin -= tcp->tcp_rnxt - tcp->tcp_rack;
	/*
	 * Send back a window update immediately if TCP is above
	 * ESTABLISHED state and the increase of the rcv window
	 * that the other side knows is at least 1 MSS after flow
	 * control is lifted.
	 */
	if (tcp->tcp_state >= TCPS_ESTABLISHED &&
	    (tcp->tcp_recv_hiwater - thwin >= tcp->tcp_mss)) {
		tcp_xmit_ctl(NULL, tcp,
		    (tcp->tcp_swnd == 0) ? tcp->tcp_suna :
		    tcp->tcp_snxt, tcp->tcp_rnxt, TH_ACK);
		BUMP_MIB(&tcps->tcps_mib, tcpOutWinUpdate);
	}

	squeue_synch_exit(connp->conn_sqp, connp);
}

/* ARGSUSED */
int
tcp_ioctl(sock_lower_handle_t proto_handle, int cmd, intptr_t arg,
    int mode, int32_t *rvalp, cred_t *cr)
{
	conn_t  	*connp = (conn_t *)proto_handle;
	int		error;

	switch (cmd) {
		case ND_SET:
		case ND_GET:
		case TCP_IOC_DEFAULT_Q:
		case _SIOCSOCKFALLBACK:
		case TCP_IOC_ABORT_CONN:
		case TI_GETPEERNAME:
		case TI_GETMYNAME:
			ip1dbg(("tcp_ioctl: cmd 0x%x on non sreams socket",
			    cmd));
			error = EINVAL;
			break;
		default:
			/*
			 * Pass on to IP using helper stream
			 */
			error = ldi_ioctl(connp->conn_helper_info->iphs_handle,
			    cmd, arg, mode, cr, rvalp);
			break;
	}
	return (error);
}

sock_downcalls_t sock_tcp_downcalls = {
	tcp_activate,
	tcp_accept,
	tcp_bind,
	tcp_listen,
	tcp_connect,
	tcp_getpeername,
	tcp_getsockname,
	tcp_getsockopt,
	tcp_setsockopt,
	tcp_sendmsg,
	NULL,
	NULL,
	NULL,
	tcp_shutdown,
	tcp_clr_flowctrl,
	tcp_ioctl,
	tcp_close,
};
