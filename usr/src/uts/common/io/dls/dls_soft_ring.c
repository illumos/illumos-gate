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

/*
 * General Soft rings - Simulating Rx rings in S/W.
 *
 * This is a general purpose high-performance soft ring mechanism. It is
 * similar to a taskq with a single worker thread. The dls creates a
 * set of these rings to simulate the H/W Rx ring (DMA channels) some
 * NICs have. The purpose is to present a common interface to IP
 * so the individual squeues can control these rings and switch them
 * between polling and interrupt mode.
 *
 * This code also serves as a fanout mechanism for fast NIC feeding slow
 * CPU where incoming traffic can be separated into multiple soft rings
 * based on capability negotiation with IP and IP also creates thread
 * affinity to soft ring worker threads to CPU so that conenction to
 * CPU/Squeue affinity is never broken.
 *
 * The soft rings can also be driven by a classifier which can direct
 * traffic to individual soft rings based on the input from IP.
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/cpuvar.h>
#include <sys/condvar_impl.h>
#include <sys/systm.h>
#include <sys/callb.h>
#include <sys/sdt.h>
#include <sys/ddi.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ipsec_impl.h>
#include <inet/sadb.h>
#include <inet/ipsecah.h>

#include <sys/dls_impl.h>
#include <sys/dls_soft_ring.h>

static void soft_ring_fire(void *);
static void soft_ring_drain(soft_ring_t *, clock_t);
static void soft_ring_worker(soft_ring_t *);
static void soft_ring_stop_workers(soft_ring_t **, int);
static void dls_taskq_stop_soft_ring(void *);

typedef struct soft_ring_taskq {
	soft_ring_t	**ringp_list;
	uint_t		ring_size;
} soft_ring_taskq_t;

kmem_cache_t *soft_ring_cache;


int soft_ring_workerwait_ms = 10;
int	soft_ring_max_q_cnt = (4 * 1024 * 1024);

/* The values above converted to ticks */
static int soft_ring_workerwait_tick = 0;

#define	SOFT_RING_WORKER_WAKEUP(ringp) {				\
	timeout_id_t tid = (ringp)->s_ring_tid;				\
									\
	ASSERT(MUTEX_HELD(&(ringp)->s_ring_lock));			\
	/*								\
	 * Queue isn't being processed, so take				\
	 * any post enqueue actions needed before leaving.		\
	 */								\
	if (tid != 0) {							\
		/*							\
		 * Waiting for an enter() to process mblk(s).		\
		 */							\
		clock_t	waited = lbolt - (ringp)->s_ring_awaken;	\
									\
		if (TICK_TO_MSEC(waited) >= (ringp)->s_ring_wait) {	\
			/*						\
			 * Times up and have a worker thread		\
			 * waiting for work, so schedule it.		\
			 */						\
			(ringp)->s_ring_tid = 0;			\
			cv_signal(&(ringp)->s_ring_async);		\
			mutex_exit(&(ringp)->s_ring_lock);		\
			(void) untimeout(tid);				\
		} else {       						\
			mutex_exit(&(ringp)->s_ring_lock);		\
		}							\
	} else if ((ringp)->s_ring_wait != 0) {				\
		(ringp)->s_ring_awaken = lbolt;				\
		(ringp)->s_ring_tid = timeout(soft_ring_fire, (ringp),	\
			(ringp)->s_ring_wait);				\
		mutex_exit(&(ringp)->s_ring_lock);			\
	} else {							\
		/*							\
		 * Schedule the worker thread.				\
		 */							\
		cv_signal(&(ringp)->s_ring_async);			\
		mutex_exit(&(ringp)->s_ring_lock);			\
	}								\
	ASSERT(MUTEX_NOT_HELD(&(ringp)->s_ring_lock)); 			\
}


#define	SOFT_RING_ENQUEUE_CHAIN(ringp, mp, tail, cnt) {			\
	/*								\
	 * Enqueue our mblk chain.					\
	 */								\
	ASSERT(MUTEX_HELD(&(ringp)->s_ring_lock));			\
									\
	if ((ringp)->s_ring_last != NULL)				\
		(ringp)->s_ring_last->b_next = (mp);			\
	else								\
		(ringp)->s_ring_first = (mp);				\
	(ringp)->s_ring_last = (tail);					\
	(ringp)->s_ring_count += (cnt);					\
	ASSERT((ringp)->s_ring_count > 0);				\
}

void
soft_ring_init(void)
{
	soft_ring_cache = kmem_cache_create("soft_ring_cache",
	    sizeof (soft_ring_t), 64, NULL, NULL, NULL, NULL, NULL, 0);

	soft_ring_workerwait_tick =
	    MSEC_TO_TICK_ROUNDUP(soft_ring_workerwait_ms);
}

/* ARGSUSED */
soft_ring_t *
soft_ring_create(char *name, processorid_t bind, clock_t wait,
    uint_t type, pri_t pri)
{
	soft_ring_t *ringp;

	ringp = kmem_cache_alloc(soft_ring_cache, KM_NOSLEEP);
	if (ringp == NULL)
		return (NULL);

	bzero(ringp, sizeof (soft_ring_t));
	(void) strncpy(ringp->s_ring_name, name, S_RING_NAMELEN + 1);
	ringp->s_ring_name[S_RING_NAMELEN] = '\0';
	mutex_init(&ringp->s_ring_lock, NULL, MUTEX_DEFAULT, NULL);

	ringp->s_ring_type = type;
	ringp->s_ring_bind = bind;
	if (bind != S_RING_BIND_NONE)
		soft_ring_bind(ringp, bind);
	ringp->s_ring_wait = MSEC_TO_TICK(wait);

	ringp->s_ring_worker = thread_create(NULL, 0, soft_ring_worker,
	    ringp, 0, &p0, TS_RUN, pri);

	return (ringp);
}

soft_ring_t **
soft_ring_set_create(char *name, processorid_t bind, clock_t wait,
    uint_t type, pri_t pri, int ring_size)
{
	int 		i;
	soft_ring_t	**ringp_list;

	if ((ringp_list =
	    (soft_ring_t **) kmem_zalloc(sizeof (soft_ring_t *) * ring_size,
	    KM_NOSLEEP)) != NULL) {
		for (i = 0; i < ring_size; i++) {
			ringp_list[i] = soft_ring_create(name, bind, wait,
			    type, pri);
			if (ringp_list[i] == NULL)
				break;
		}
		if (i != ring_size) {
			soft_ring_stop_workers(ringp_list, ring_size);
			soft_ring_set_destroy(ringp_list, ring_size);
			ringp_list = NULL;
		}
	}
	return (ringp_list);
}

static void
soft_ring_stop_workers(soft_ring_t **ringp_set, int ring_size)
{
	int 		i;
	soft_ring_t	*ringp;
	timeout_id_t 	tid;
	kt_did_t	t_did = 0;

	for (i = 0; (i < ring_size) && (ringp_set[i] != NULL); i++) {
		ringp = ringp_set[i];

		soft_ring_unbind((void *)ringp);
		mutex_enter(&ringp->s_ring_lock);
		if ((tid = ringp->s_ring_tid) != 0)
			(void) untimeout(tid);

		ringp->s_ring_tid = 0;

		if (!(ringp->s_ring_state & S_RING_DEAD)) {
			ringp->s_ring_state |= S_RING_DESTROY;
			t_did = ringp->s_ring_worker->t_did;


			/* Wake the worker so it can exit */
			cv_signal(&(ringp)->s_ring_async);
		}
		mutex_exit(&ringp->s_ring_lock);

		/*
		 * Here comes the tricky part. IP and driver ensure
		 * that packet flow has stopped but worker thread
		 * might still be draining the soft ring. We have
		 * already set the S_RING_DESTROY flag. We wait till
		 * the worker thread takes notice and stops processing
		 * the soft_ring and exits. It sets S_RING_DEAD on
		 * exiting.
		 */
		if (t_did)
			thread_join(t_did);
	}
}

void
soft_ring_set_destroy(soft_ring_t **ringp_set, int ring_size)
{
	int		i;
	mblk_t		*mp;
	soft_ring_t	*ringp;

	for (i = 0; (i < ring_size) && (ringp_set[i] != NULL); i++) {
		ringp = ringp_set[i];

		mutex_enter(&ringp->s_ring_lock);

		ASSERT(ringp->s_ring_state & S_RING_DEAD);

		while ((mp = ringp->s_ring_first) != NULL) {
			ringp->s_ring_first = mp->b_next;
			mp->b_next = NULL;
			freemsg(mp);
		}
		ringp->s_ring_last = NULL;
		mutex_exit(&ringp->s_ring_lock);

		/*
		 * IP/driver ensure that no packets are flowing
		 * when we are destroying the soft rings otherwise bad
		 * things will happen.
		 */
		kmem_cache_free(soft_ring_cache, ringp);
		ringp_set[i] = NULL;
	}
	kmem_free(ringp_set, sizeof (soft_ring_t *) * ring_size);
}

/* ARGSUSED */
void
soft_ring_bind(void *arg, processorid_t bind)
{
	cpu_t	*cp;
	soft_ring_t *ringp = (soft_ring_t *)arg;

	mutex_enter(&ringp->s_ring_lock);
	if (ringp->s_ring_state & S_RING_BOUND) {
		mutex_exit(&ringp->s_ring_lock);
		return;
	}

	ringp->s_ring_state |= S_RING_BOUND;
	ringp->s_ring_bind = bind;
	mutex_exit(&ringp->s_ring_lock);

	cp = cpu[bind];
	mutex_enter(&cpu_lock);
	if (cpu_is_online(cp)) {
		thread_affinity_set(ringp->s_ring_worker, ringp->s_ring_bind);
	}
	mutex_exit(&cpu_lock);
}

void
soft_ring_unbind(void *arg)
{
	soft_ring_t *ringp = (soft_ring_t *)arg;

	mutex_enter(&ringp->s_ring_lock);
	if (!(ringp->s_ring_state & S_RING_BOUND)) {
		mutex_exit(&ringp->s_ring_lock);
		return;
	}

	ringp->s_ring_state &= ~S_RING_BOUND;
	ringp->s_ring_bind = S_RING_BIND_NONE;
	mutex_exit(&ringp->s_ring_lock);

	thread_affinity_clear(ringp->s_ring_worker);
}

/*
 * soft_ring_enter() - enter soft_ring sqp with mblk mp (which can be
 * a chain), while tail points to the end and cnt in number of
 * mblks in the chain.
 *
 * For a chain of single packet (i.e. mp == tail), go through the
 * fast path if no one is processing the soft_ring and nothing is queued.
 *
 * The proc and arg for each mblk is already stored in the mblk in
 * appropriate places.
 */
/* ARGSUSED */
static void
soft_ring_process(soft_ring_t *ringp,
    mblk_t *mp_chain, mblk_t *tail, uint_t count)
{
	void 		*arg1, *arg2;
	s_ring_proc_t	proc;

	ASSERT(ringp != NULL);
	ASSERT(mp_chain != NULL);
	ASSERT(MUTEX_NOT_HELD(&ringp->s_ring_lock));

	mutex_enter(&ringp->s_ring_lock);

	ringp->s_ring_total_inpkt += count;
	if (!(ringp->s_ring_state & S_RING_PROC) &&
	    !(ringp->s_ring_type == S_RING_WORKER_ONLY)) {
		/*
		 * See if anything is already queued. If we are the
		 * first packet, do inline processing else queue the
		 * packet and do the drain.
		 */
		if (ringp->s_ring_first == NULL && count == 1) {
			/*
			 * Fast-path, ok to process and nothing queued.
			 */
			ringp->s_ring_run = curthread;
			ringp->s_ring_state |= (S_RING_PROC);

			/*
			 * We are the chain of 1 packet so
			 * go through this fast path.
			 */
			ASSERT(mp_chain->b_next == NULL);
			proc = ringp->s_ring_upcall;
			arg1 = ringp->s_ring_upcall_arg1;
			arg2 = ringp->s_ring_upcall_arg2;

			mutex_exit(&ringp->s_ring_lock);
			(*proc)(arg1, arg2, mp_chain, NULL);

			ASSERT(MUTEX_NOT_HELD(&ringp->s_ring_lock));
			mutex_enter(&ringp->s_ring_lock);
			ringp->s_ring_run = NULL;
			ringp->s_ring_state &= ~S_RING_PROC;
			if (ringp->s_ring_first == NULL) {
				/*
				 * We processed inline our packet and
				 * nothing new has arrived. We are done.
				 */
				mutex_exit(&ringp->s_ring_lock);
				return;
			}
		} else {
			SOFT_RING_ENQUEUE_CHAIN(ringp, mp_chain, tail, count);
		}

		/*
		 * We are here because either we couldn't do inline
		 * processing (because something was already queued),
		 * or we had a chanin of more than one packet,
		 * or something else arrived after we were done with
		 * inline processing.
		 */
		ASSERT(MUTEX_HELD(&ringp->s_ring_lock));
		ASSERT(ringp->s_ring_first != NULL);


		soft_ring_drain(ringp, -1);
		mutex_exit(&ringp->s_ring_lock);
		return;
	} else {
		/*
		 * Queue is already being processed. Just enqueue
		 * the packet and go away.
		 */
		if (ringp->s_ring_count > soft_ring_max_q_cnt) {
			freemsgchain(mp_chain);
			DLS_BUMP_STAT(dlss_soft_ring_pkt_drop, count);
		} else
			SOFT_RING_ENQUEUE_CHAIN(ringp, mp_chain, tail, count);
		if (!(ringp->s_ring_state & S_RING_PROC)) {
			SOFT_RING_WORKER_WAKEUP(ringp);
		} else {
			ASSERT(ringp->s_ring_run != NULL);
			mutex_exit(&ringp->s_ring_lock);
		}
		return;
	}
}

/*
 * PRIVATE FUNCTIONS
 */

static void
soft_ring_fire(void *arg)
{
	soft_ring_t	*ringp = arg;

	mutex_enter(&ringp->s_ring_lock);
	if (ringp->s_ring_tid == 0) {
		mutex_exit(&ringp->s_ring_lock);
		return;
	}

	ringp->s_ring_tid = 0;

	if (!(ringp->s_ring_state & S_RING_PROC)) {
		cv_signal(&ringp->s_ring_async);
	}
	mutex_exit(&ringp->s_ring_lock);
}

/* ARGSUSED */
static void
soft_ring_drain(soft_ring_t *ringp, clock_t expire)
{
	mblk_t		*mp;
	s_ring_proc_t 	proc;
	void		*arg1, *arg2;
	timeout_id_t 	tid;

	ringp->s_ring_run = curthread;
	ASSERT(mutex_owned(&ringp->s_ring_lock));
	ASSERT(!(ringp->s_ring_state & S_RING_PROC));

	if ((tid = ringp->s_ring_tid) != 0)
		ringp->s_ring_tid = 0;

	ringp->s_ring_state |= S_RING_PROC;


	proc = ringp->s_ring_upcall;
	arg1 = ringp->s_ring_upcall_arg1;
	arg2 = ringp->s_ring_upcall_arg2;

	while (ringp->s_ring_first != NULL) {
		mp = ringp->s_ring_first;
		ringp->s_ring_first = NULL;
		ringp->s_ring_last = NULL;
		ringp->s_ring_count = 0;
		mutex_exit(&ringp->s_ring_lock);

		if (tid != 0) {
			(void) untimeout(tid);
			tid = 0;
		}

		(*proc)(arg1, arg2, mp, NULL);

		mutex_enter(&ringp->s_ring_lock);
	}

	ringp->s_ring_state &= ~S_RING_PROC;
	ringp->s_ring_run = NULL;
}

static void
soft_ring_worker(soft_ring_t *ringp)
{
	kmutex_t *lock = &ringp->s_ring_lock;
	kcondvar_t *async = &ringp->s_ring_async;
	callb_cpr_t cprinfo;

	CALLB_CPR_INIT(&cprinfo, lock, callb_generic_cpr, "soft_ring");
	mutex_enter(lock);

	for (;;) {
		while (ringp->s_ring_first == NULL ||
		    (ringp->s_ring_state & S_RING_PROC)) {
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			if (ringp->s_ring_state & S_RING_DESTROY)
				goto destroy;
still_wait:
			cv_wait(async, lock);
			if (ringp->s_ring_state & S_RING_DESTROY) {
destroy:
				if (ringp->s_ring_state & S_RING_DESTROY) {
					ringp->s_ring_state |= S_RING_DEAD;
					CALLB_CPR_EXIT(&cprinfo);
					thread_exit();
				}
			}
			if (ringp->s_ring_state & S_RING_PROC) {
				goto still_wait;
			}
			CALLB_CPR_SAFE_END(&cprinfo, lock);
		}
		soft_ring_drain(ringp, -1);
	}
}

void
dls_soft_ring_disable(dls_channel_t dc)
{
	dls_impl_t	*dip = (dls_impl_t *)dc;
	soft_ring_t	**ringp_list = NULL;
	int		ring_size;

	rw_enter(&(dip->di_lock), RW_READER);
	if (dip->di_soft_ring_list != NULL) {
		ringp_list = dip->di_soft_ring_list;
		ring_size = dip->di_soft_ring_size;
	}
	rw_exit(&(dip->di_lock));

	if (ringp_list != NULL)
		soft_ring_stop_workers(ringp_list, ring_size);
}

static void
dls_taskq_stop_soft_ring(void *arg)
{
	soft_ring_taskq_t	*ring_taskq;
	soft_ring_t		**ringp_list;
	int			ring_size;

	ring_taskq = (soft_ring_taskq_t *)arg;
	ringp_list = ring_taskq->ringp_list;
	ring_size = ring_taskq->ring_size;
	kmem_free(ring_taskq, sizeof (soft_ring_taskq_t));

	soft_ring_stop_workers(ringp_list, ring_size);
	soft_ring_set_destroy(ringp_list, ring_size);
}

boolean_t
dls_soft_ring_enable(dls_channel_t dc, dl_capab_dls_t *soft_ringp)
{
	dls_impl_t		*dip;
	int			i;
	soft_ring_t		**softring_set;
	soft_ring_t		*softring;
	mac_rx_fifo_t		mrf;
	soft_ring_taskq_t	*ring_taskq;
	char			name[64];

	dip = (dls_impl_t *)dc;

	rw_enter(&(dip->di_lock), RW_WRITER);

	if (dip->di_soft_ring_list != NULL) {
		/*
		 * Both ds_lock and di_lock are held as writer.
		 * As soft_ring_stop_workers() blocks for the
		 * worker thread(s) to complete, there is a possibility
		 * that the worker thread(s) could be in the process
		 * of draining the queue and is blocked waiting for
		 * either ds_lock or di_lock. Moreover the NIC interrupt
		 * thread could be blocked in dls_accept().
		 * To avoid deadlock condition, taskq thread would be
		 * created to handle soft_ring_stop_workers() and
		 * blocking if required which would avoid holding
		 * both ds_lock and di_lock.
		 * NOTE: we cannot drop either locks here, due to
		 * weird race conditions seen.
		 */
		ring_taskq = (soft_ring_taskq_t *)
		    kmem_zalloc(sizeof (soft_ring_taskq_t), KM_NOSLEEP);
		if (ring_taskq == NULL) {
			rw_exit(&(dip->di_lock));
			return (B_FALSE);
		}
		ring_taskq->ringp_list = dip->di_soft_ring_list;
		ring_taskq->ring_size = dip->di_soft_ring_size;
		if (taskq_dispatch(system_taskq, dls_taskq_stop_soft_ring,
		    ring_taskq, TQ_NOSLEEP) == NULL) {
			rw_exit(&(dip->di_lock));
			kmem_free(ring_taskq, sizeof (soft_ring_taskq_t));
			return (B_FALSE);
		}
		dip->di_soft_ring_list = NULL;
	}
	dip->di_soft_ring_size = 0;

	bzero(name, sizeof (name));
	(void) snprintf(name, sizeof (name), "dls_soft_ring_%p", (void *)dip);
	dip->di_soft_ring_list = soft_ring_set_create(name, S_RING_BIND_NONE,
	    0, S_RING_WORKER_ONLY, minclsyspri, soft_ringp->dls_ring_cnt);

	if (dip->di_soft_ring_list == NULL) {
		rw_exit(&(dip->di_lock));
		return (B_FALSE);
	}

	dip->di_soft_ring_size = soft_ringp->dls_ring_cnt;
	softring_set = dip->di_soft_ring_list;

	dip->di_ring_add = (mac_resource_add_t)soft_ringp->dls_ring_add;
	dip->di_rx = (dls_rx_t)soft_ringp->dls_ring_assign;
	dip->di_rx_arg = (void *)soft_ringp->dls_rx_handle;

	bzero(&mrf, sizeof (mac_rx_fifo_t));
	mrf.mrf_type = MAC_RX_FIFO;
	for (i = 0; i < soft_ringp->dls_ring_cnt; i++) {
		softring = softring_set[i];
		mrf.mrf_arg = softring;
		softring->s_ring_upcall_arg1 =
		    (void *)soft_ringp->dls_rx_handle;
		softring->s_ring_upcall_arg2 =
		    dip->di_ring_add((void *)soft_ringp->dls_rx_handle,
		    (mac_resource_t *)&mrf);
		softring->s_ring_upcall =
		    (s_ring_proc_t)soft_ringp->dls_rx;
	}

	/*
	 * Note that soft_ring is enabled. This prevents further DLIOCHDRINFO
	 * ioctls from overwriting the receive function pointer.
	 */
	rw_exit(&(dip->di_lock));
	return (B_TRUE);
}

int dls_bad_ip_pkt = 0;

static mblk_t *
dls_skip_mblk(mblk_t *bp, mblk_t *mp, int *skip_lenp)
{
	while (MBLKL(bp) <= *skip_lenp) {
		*skip_lenp -= MBLKL(bp);
		bp = bp->b_cont;
		if (bp == NULL) {
			dls_bad_ip_pkt++;
			freemsg(mp);
			return (NULL);
		}
	}
	return (bp);
}

#define	HASH32(x) (((x) >> 24) ^ ((x) >> 16) ^ ((x) >> 8) ^ (x))
#define	COMPUTE_INDEX(key, sz)	(key % sz)

/*
 * dls_soft_ring_fanout():
 */
/* ARGSUSED */
void
dls_soft_ring_fanout(void *rx_handle, void *rx_cookie, mblk_t *mp_chain,
    mac_header_info_t *mhip)
{
	mblk_t		*mp, *bp, *head, *tail;
	ipha_t		*ipha;
	dls_impl_t	*dip = (dls_impl_t *)rx_handle;
	int		indx, saved_indx;
	int		hash = 0;
	int		skip_len;
	uint8_t		protocol;
	int		count = 0;

	head = tail = NULL;

	while (mp_chain != NULL) {
		bp = mp = mp_chain;
		mp_chain = mp_chain->b_next;
		mp->b_next = NULL;
		if ((MBLKL(mp) < sizeof (ipha_t)) || !OK_32PTR(mp->b_rptr)) {
			mp = msgpullup(bp, sizeof (ipha_t));
			freemsg(bp);
			if (mp == NULL) {
				dls_bad_ip_pkt++;
				continue;
			}
			bp = mp;
		}

		ipha = (ipha_t *)mp->b_rptr;
		skip_len = IPH_HDR_LENGTH(ipha);
		protocol = ipha->ipha_protocol;
	again:
		switch (protocol) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
		case IPPROTO_SCTP:
		case IPPROTO_ESP:
			/*
			 * Note that for ESP, we fanout on SPI and it is at the
			 * same offset as the 2x16-bit ports. So it is clumped
			 * along with TCP, UDP and SCTP.
			 */
			if (MBLKL(bp) <= skip_len) {
				bp = dls_skip_mblk(bp, mp, &skip_len);
				if (bp == NULL)
					continue;
			}

			hash = HASH32(*(uint32_t *)(bp->b_rptr + skip_len));
			break;

		case IPPROTO_AH: {
			ah_t *ah;
			uint_t ah_length;

			if (MBLKL(bp) <= skip_len) {
				bp = dls_skip_mblk(bp, mp, &skip_len);
				if (bp == NULL)
					continue;
			}

			ah = (ah_t *)(bp->b_rptr + skip_len);
			protocol = ah->ah_nexthdr;
			ah_length = AH_TOTAL_LEN(ah);
			skip_len += ah_length;
			goto again;
		}

		default:
			/*
			 * Send the packet to a ring based on src/dest addresses
			 */
			hash =
			    (HASH32(ipha->ipha_src) ^ HASH32(ipha->ipha_dst));
			break;
		}

		indx = COMPUTE_INDEX(hash, dip->di_soft_ring_size);
		if (head == NULL) {
			saved_indx = indx;
			head = tail = mp;
			count++;
		} else if (indx == saved_indx) {
			tail->b_next = mp;
			tail = mp;
			count++;
		} else {
			soft_ring_process(dip->di_soft_ring_list[saved_indx],
			    head, tail, count);
			head = tail = mp;
			saved_indx = indx;
			count = 1;
		}
	}
	if (head != NULL)
		soft_ring_process(dip->di_soft_ring_list[saved_indx],
		    head, tail, count);
}
