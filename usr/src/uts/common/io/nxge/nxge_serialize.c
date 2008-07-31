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

#pragma ident	"%Z%%M%	%I%	%E% SMI"
#include <sys/nxge/nxge_impl.h>
#include <sys/proc.h>

uint32_t nxge_maxhrs = MAXHRS;

extern pri_t maxclsyspri;
extern proc_t p0;

extern int servicing_interrupt(void);
extern void bzero(void *, size_t);

extern uint32_t nxge_tx_serial_maxsleep;

#ifdef _KERNEL
static void nxge_onetrack(void *p);
#else
static void *nxge_onetrack(void *p);
#endif

static int nxge_serial_put(nxge_serialize_t *, void *);
static int nxge_serial_getn(nxge_serialize_t *, mblk_t **, mblk_t **);
static void nxge_serial_ungetn(nxge_serialize_t *, mblk_t *, mblk_t *, int);
static int nxge_freelance(nxge_serialize_t *);
static caddr_t nxge_tx_s_begin(nxge_serialize_t *);
static void nxge_tx_s_end(nxge_serialize_t *);

nxge_serialize_t *
nxge_serialize_create(int length, onetrack_t *proc, void *cookie)
{
	nxge_serialize_t *p;

	NXGE_DEBUG_MSG((NULL, TX_CTL,
	    "==> nxge_serialize_create:"));

	p = (nxge_serialize_t *)kmem_alloc(sizeof (nxge_serialize_t), KM_SLEEP);
	mutex_init(&p->lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&p->serial, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&p->timelock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&p->serial_cv, NULL, CV_DRIVER, NULL);
	cv_init(&p->timecv, NULL, CV_DRIVER, NULL);
	p->count = 0;
	p->cookie = cookie;
	p->serialop = proc;
	p->owned = 0;
	p->head = NULL;
	p->tail = NULL;
	p->totaltime = 0;
	p->totalcount = 0;
	/*
	 * An initial estimate of the avg time spent in the serializer function.
	 * Any non-zero value is fine. A large value will induce unnecessary
	 * delays.
	 */
	p->avg = 1;
	p->length = length;
	p->s_state = NXGE_TX_STHREAD_RUNNING;

	p->tx_sthread = thread_create(NULL, 0,
	    nxge_onetrack, p, 0, &p0, TS_RUN, maxclsyspri);
	if (p->tx_sthread == NULL) {
		cv_destroy(&p->serial_cv);
		cv_destroy(&p->timecv);
		mutex_destroy(&p->lock);
		mutex_destroy(&p->serial);
		mutex_destroy(&p->timelock);
		kmem_free(p, sizeof (nxge_serialize_t));

		NXGE_DEBUG_MSG((NULL, TX_CTL,
		    "<== nxge_serialize_create: (NULL)"));

		return (NULL);
	}

	NXGE_DEBUG_MSG((NULL, TX_CTL,
	    "<== nxge_serialize_create: s %p thread %p",
	    p, p->tx_sthread));

	return (p);
}

void
nxge_serialize_destroy(nxge_serialize_t *p)
{
	int n, i;
	mblk_t *mp, *nmp, *t;

	NXGE_DEBUG_MSG((NULL, TX_CTL,
	    "==> nxge_serialize_destroy: s %p", p));
	if (p == NULL) {
		NXGE_DEBUG_MSG((NULL, TX_CTL,
		    "<== nxge_serialize_destroy:"));
		return;
	}

	mutex_enter(&p->serial);
	p->s_state |= NXGE_TX_STHREAD_DESTROY;
	cv_signal(&p->serial_cv);
	cv_signal(&p->timecv);
	while (p->s_state & NXGE_TX_STHREAD_DESTROY) {
		cv_wait(&p->serial_cv, &p->serial);
		NXGE_DEBUG_MSG((NULL, TX_CTL,
		    "==> nxge_serialize_destroy: s %p state %d",
		    p, p->s_state));
		if (p->s_state & NXGE_TX_STHREAD_EXIT) {
			break;
		}
	}

	NXGE_DEBUG_MSG((NULL, TX_CTL,
	    "==> nxge_serialize_destroy: s %p state %d",
	    p, p->s_state));

	n = nxge_serial_getn(p, &mp, &t);
	for (i = 0; i < n; i++) {
		NXGE_DEBUG_MSG((NULL, TX_CTL,
		    "==> nxge_serialize_destroy: s %p mp %p", p, mp));

		nmp = mp->b_next;
		mp->b_next = NULL;
		freemsg(mp);

		mp = nmp;
	}

	mutex_exit(&p->serial);

	cv_destroy(&p->serial_cv);
	cv_destroy(&p->timecv);
	mutex_destroy(&p->lock);
	mutex_destroy(&p->serial);
	mutex_destroy(&p->timelock);
	kmem_free(p, sizeof (nxge_serialize_t));

	NXGE_DEBUG_MSG((NULL, TX_CTL,
	    "<== nxge_serialize_destroy: s %p", p));
}

/*
 * Return values:
 * 0 means put succeeded
 * 1 means we have exclusive access
 */
static int
nxge_serial_put(nxge_serialize_t *p, void *mp)
{
	mblk_t *t;
	int r = 0;
	int block = 0;
	hrtime_t tns;

	NXGE_DEBUG_MSG((NULL, TX_CTL,
	    "==> nxge_serial_put: s %p mp %p", p, mp));

	mutex_enter(&p->lock);
	/*
	 * If the time required to drain all the queued up packets
	 * is greater than a tick, we need to block.
	 */
	if ((tns = (p->count++) * p->avg) > NXGE_TX_AVG_CNT) {
		/*
		 * Sanity check that we will sleep only for less than ~a second
		 */
		if (tns > ONESEC) {
			p->count--;
			mutex_exit(&p->lock);
			freemsg(mp);
			return (0);
		}
		block = 1;
	}
	if (p->owned == 0) {
		r = p->owned = 1;
		block = 0;
	}
	if ((t = p->tail) != NULL) {
		t->b_next = mp;
		p->tail = mp;
	} else {
		p->head = p->tail = mp;
	}
	mutex_exit(&p->lock);

	/*
	 * Block for the number of ticks required to drain half
	 * the queued up packets - but only if we are not within
	 * an interrupt thread.
	 */
	if (block) {
		if (!servicing_interrupt()) {
			long wait = lbolt + drv_usectohz(tns/NXGE_TX_AVG_RES);
			mutex_enter(&p->timelock);
			(void) cv_timedwait(&p->timecv, &p->timelock, wait);
			mutex_exit(&p->timelock);
		}
	}


	return (r);
}

static int
nxge_serial_getn(nxge_serialize_t *p, mblk_t **head, mblk_t **tail)
{
	int c;

	mutex_enter(&p->lock);
	if ((c = p->count) != 0) {
		*head = p->head;
		*tail = p->tail;
		p->head = p->tail = NULL;
		p->count = 0;
	} else {
		p->owned = 0;
	}
	mutex_exit(&p->lock);

	return (c);
}

static void
nxge_serial_ungetn(nxge_serialize_t *p, mblk_t *head, mblk_t *tail, int n)
{
	mutex_enter(&p->lock);
	if (p->tail != NULL) {
		tail->b_next = p->head;
		p->head = head;
	} else {
		p->head = head;
		p->tail = tail;
	}
	p->count += n;
	mutex_exit(&p->lock);
}

#ifdef _KERNEL
static void
#else
static void *
#endif
nxge_onetrack(void *s)
{
	int		k, i;
	mblk_t		*mp, *ignore;
	nxge_serialize_t *p = (nxge_serialize_t *)s;

	NXGE_DEBUG_MSG((NULL, TX_CTL,
	    "==> nxge_onetrack: s %p", s));
	(void) nxge_tx_s_begin(p);
	mutex_enter(&p->serial);
	while (p->s_state & NXGE_TX_STHREAD_RUNNING) {
		CALLB_CPR_SAFE_BEGIN(&p->s_cprinfo);
		if (p->s_state & NXGE_TX_STHREAD_DESTROY) {
			break;
		}
		cv_wait(&p->serial_cv, &p->serial);
		if (p->s_state & NXGE_TX_STHREAD_DESTROY) {
			break;
		}
		CALLB_CPR_SAFE_END(&p->s_cprinfo,
		    &p->serial)
		while (k = nxge_serial_getn(p, &mp, &ignore)) {
			hrtime_t t0 = gethrtime();
			for (i = 0; i < k; i++) {
				mblk_t *n = mp->b_next;
				mp->b_next = NULL;

				NXGE_DEBUG_MSG((NULL, TX_CTL,
				    "==> nxge_onetrack: s %p mp %p", s, mp));

				/*
				 * The queue is full, block and wait for half of
				 * it to drain.
				 */
				while (p->serialop(mp, p->cookie)) {
					hrtime_t tns = p->avg * p->length;
					long wait = lbolt + min(
					    drv_usectohz(tns / NXGE_TX_AVG_RES),
					    nxge_tx_serial_maxsleep);

					(void) cv_timedwait(&p->timecv,
					    &p->serial, wait);
					if (p->s_state &
					    NXGE_TX_STHREAD_DESTROY) {
						NXGE_DEBUG_MSG((NULL,
						    TX_CTL,
						    "==> nxge_onetrack: s $%p "
						    "exiting", s));
						break;
					}
				}
				mp = n;
			}

			ASSERT(mp == NULL);

			/*
			 * Update the total time and count of the serializer
			 * function and * generate the avg time required to
			 * process a packet.
			 */
			p->totaltime += (gethrtime() - t0);
			p->totalcount += k;
			p->avg = p->totaltime/p->totalcount;
		}
	}

	mutex_exit(&p->serial);

	NXGE_DEBUG_MSG((NULL, TX_CTL,
	    "<== nxge_onetrack: s %p", s));
	nxge_tx_s_end(s);
}


/*
 * Return values:
 * 0 : don't need to signal worker
 * 1 : worker needs to be signalled
 */
static int
nxge_freelance(nxge_serialize_t *s)
{
	int i, n, c = 0;
	mblk_t *mp, *t;

	NXGE_DEBUG_MSG((NULL, TX_CTL,
	    "==> nxge_freelance: s %p", s));
	while (n = nxge_serial_getn(s, &mp, &t)) {
		if ((n > nxge_maxhrs) || ((c += n) > nxge_maxhrs)) {
			nxge_serial_ungetn(s, mp, t, n);
			return (1);
		}
		for (i = 0; i < n; i++) {
			mblk_t *next = mp->b_next;
			mp->b_next = NULL;
			if (s->serialop(mp, s->cookie)) {
				mp->b_next = next;
				nxge_serial_ungetn(s, mp, t, n - i);
				return (1);
			}

			NXGE_DEBUG_MSG((NULL, TX_CTL,
			    "==> nxge_freelance: s %p mp %p", s, mp));

			mp = next;
		}
	}
	NXGE_DEBUG_MSG((NULL, TX_CTL,
	    "<== nxge_freelance: s %p", s));

	return (0);
}

void
nxge_serialize_enter(nxge_serialize_t *s, mblk_t *mp)
{
	if (nxge_serial_put(s, mp)) {
		if (nxge_freelance(s)) {
			mutex_enter(&s->serial);
			cv_signal(&s->serial_cv);
			mutex_exit(&s->serial);
		}
	}
}

static caddr_t
nxge_tx_s_begin(nxge_serialize_t *s)
{
	CALLB_CPR_INIT(&s->s_cprinfo, &s->serial,
	    callb_generic_cpr, "nxge_tx_serialize");
	return (s->cookie);
}

static void
nxge_tx_s_end(nxge_serialize_t *s)
{
	callb_cpr_t cprinfo;

	NXGE_DEBUG_MSG((NULL, TX_CTL,
	    "==> nxge_tx_s_end: s %p", s));
	cprinfo = s->s_cprinfo;
	mutex_enter(&s->serial);
	s->s_state |= NXGE_TX_STHREAD_EXIT;
	cv_signal(&s->serial_cv);

	CALLB_CPR_EXIT(&cprinfo);

	NXGE_DEBUG_MSG((NULL, TX_CTL,
	    "<== nxge_tx_s_end: s %p", s));

	thread_exit();
}
