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
 * This file contains the source of the general purpose event channel extension
 * to the sysevent framework. This implementation is made up mainly of four
 * layers of functionality: the event queues (evch_evq_*()), the handling of
 * channels (evch_ch*()), the kernel interface (sysevent_evc_*()) and the
 * interface for the sysevent pseudo driver (evch_usr*()).
 * Libsysevent.so uses the pseudo driver sysevent's ioctl to access the event
 * channel extensions. The driver in turn uses the evch_usr*() functions below.
 *
 * The interfaces for user land and kernel are declared in sys/sysevent.h
 * Internal data structures for event channels are defined in
 * sys/sysevent_impl.h.
 *
 * The basic data structure for an event channel is of type evch_chan_t.
 * All channels are maintained by a list named evch_list. The list head
 * is of type evch_dlist_t.
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/stropts.h>
#include <sys/debug.h>
#include <sys/ddi.h>
#include <sys/vmem.h>
#include <sys/cmn_err.h>
#include <sys/callb.h>
#include <sys/sysevent.h>
#include <sys/sysevent_impl.h>
#include <sys/sysmacros.h>
#include <sys/disp.h>
#include <sys/atomic.h>
#include <sys/door.h>
#include <sys/zone.h>
#include <sys/sdt.h>

/* Back-off delay for door_ki_upcall */
#define	EVCH_MIN_PAUSE	8
#define	EVCH_MAX_PAUSE	128

#define	GEVENT(ev)	((evch_gevent_t *)((char *)ev - \
			    offsetof(evch_gevent_t, ge_payload)))

#define	EVCH_EVQ_EVCOUNT(x)	((&(x)->eq_eventq)->sq_count)
#define	EVCH_EVQ_HIGHWM(x)	((&(x)->eq_eventq)->sq_highwm)

#define	CH_HOLD_PEND		1
#define	CH_HOLD_PEND_INDEF	2

struct evch_globals {
	evch_dlist_t evch_list;
	kmutex_t evch_list_lock;
};

/* Variables used by event channel routines */
static int		evq_initcomplete = 0;
static zone_key_t	evch_zone_key;
static uint32_t		evch_channels_max;
static uint32_t		evch_bindings_max = EVCH_MAX_BINDS_PER_CHANNEL;
static uint32_t		evch_events_max;

static void evch_evq_unsub(evch_eventq_t *, evch_evqsub_t *);
static void evch_evq_destroy(evch_eventq_t *);

/*
 * List handling. These functions handle a doubly linked list. The list has
 * to be protected by the calling functions. evch_dlist_t is the list head.
 * Every node of the list has to put a evch_dlelem_t data type in its data
 * structure as its first element.
 *
 * evch_dl_init		- Initialize list head
 * evch_dl_fini		- Terminate list handling
 * evch_dl_is_init	- Returns one if list is initialized
 * evch_dl_add		- Add element to end of list
 * evch_dl_del		- Remove given element from list
 * evch_dl_search	- Lookup element in list
 * evch_dl_getnum	- Get number of elements in list
 * evch_dl_next		- Get next elements of list
 */

static void
evch_dl_init(evch_dlist_t *hp)
{
	hp->dh_head.dl_prev = hp->dh_head.dl_next = &hp->dh_head;
	hp->dh_count = 0;
}

/*
 * Assumes that list is empty.
 */
static void
evch_dl_fini(evch_dlist_t *hp)
{
	hp->dh_head.dl_prev = hp->dh_head.dl_next = NULL;
}

static int
evch_dl_is_init(evch_dlist_t *hp)
{
	return (hp->dh_head.dl_next != NULL ? 1 : 0);
}

/*
 * Add an element at the end of the list.
 */
static void
evch_dl_add(evch_dlist_t *hp, evch_dlelem_t *el)
{
	evch_dlelem_t	*x = hp->dh_head.dl_prev;
	evch_dlelem_t	*y = &hp->dh_head;

	x->dl_next = el;
	y->dl_prev = el;
	el->dl_next = y;
	el->dl_prev = x;
	hp->dh_count++;
}

/*
 * Remove arbitrary element out of dlist.
 */
static void
evch_dl_del(evch_dlist_t *hp, evch_dlelem_t *p)
{
	ASSERT(hp->dh_count > 0 && p != &hp->dh_head);
	p->dl_prev->dl_next = p->dl_next;
	p->dl_next->dl_prev = p->dl_prev;
	p->dl_prev = NULL;
	p->dl_next = NULL;
	hp->dh_count--;
}

/*
 * Search an element in a list. Caller provides comparison callback function.
 */
static evch_dlelem_t *
evch_dl_search(evch_dlist_t *hp, int (*cmp)(evch_dlelem_t *, char *), char *s)
{
	evch_dlelem_t *p;

	for (p = hp->dh_head.dl_next; p != &hp->dh_head; p = p->dl_next) {
		if (cmp(p, s) == 0) {
			return (p);
		}
	}
	return (NULL);
}

/*
 * Return number of elements in the list.
 */
static int
evch_dl_getnum(evch_dlist_t *hp)
{
	return (hp->dh_count);
}

/*
 * Find next element of a evch_dlist_t list. Find first element if el == NULL.
 * Returns NULL if end of list is reached.
 */
static void *
evch_dl_next(evch_dlist_t *hp, void *el)
{
	evch_dlelem_t *ep = (evch_dlelem_t *)el;

	if (hp->dh_count == 0) {
		return (NULL);
	}
	if (ep == NULL) {
		return (hp->dh_head.dl_next);
	}
	if ((ep = ep->dl_next) == (evch_dlelem_t *)hp) {
		return (NULL);
	}
	return ((void *)ep);
}

/*
 * Queue handling routines. Mutexes have to be entered previously.
 *
 * evch_q_init	- Initialize queue head
 * evch_q_in	- Put element into queue
 * evch_q_out	- Get element out of queue
 * evch_q_next	- Iterate over the elements of a queue
 */
static void
evch_q_init(evch_squeue_t *q)
{
	q->sq_head = NULL;
	q->sq_tail = (evch_qelem_t *)q;
	q->sq_count = 0;
	q->sq_highwm = 0;
}

/*
 * Put element into the queue q
 */
static void
evch_q_in(evch_squeue_t *q, evch_qelem_t *el)
{
	q->sq_tail->q_next = el;
	el->q_next = NULL;
	q->sq_tail = el;
	q->sq_count++;
	if (q->sq_count > q->sq_highwm) {
		q->sq_highwm = q->sq_count;
	}
}

/*
 * Returns NULL if queue is empty.
 */
static evch_qelem_t *
evch_q_out(evch_squeue_t *q)
{
	evch_qelem_t *el;

	if ((el = q->sq_head) != NULL) {
		q->sq_head = el->q_next;
		q->sq_count--;
		if (q->sq_head == NULL) {
			q->sq_tail = (evch_qelem_t *)q;
		}
	}
	return (el);
}

/*
 * Returns element after *el or first if el == NULL. NULL is returned
 * if queue is empty or *el points to the last element in the queue.
 */
static evch_qelem_t *
evch_q_next(evch_squeue_t *q, evch_qelem_t *el)
{
	if (el == NULL)
		return (q->sq_head);
	return (el->q_next);
}

/*
 * Event queue handling functions. An event queue is the basic building block
 * of an event channel. One event queue makes up the publisher-side event queue.
 * Further event queues build the per-subscriber queues of an event channel.
 * Each queue is associated an event delivery thread.
 * These functions support a two-step initialization. First step, when kernel
 * memory is ready and second when threads are ready.
 * Events consist of an administrating evch_gevent_t structure with the event
 * data appended as variable length payload.
 * The internal interface functions for the event queue handling are:
 *
 * evch_evq_create	- create an event queue
 * evch_evq_thrcreate	- create thread for an event queue.
 * evch_evq_destroy	- delete an event queue
 * evch_evq_sub		- Subscribe to event delivery from an event queue
 * evch_evq_unsub	- Unsubscribe
 * evch_evq_pub		- Post an event into an event queue
 * evch_evq_stop	- Put delivery thread on hold
 * evch_evq_continue	- Resume event delivery thread
 * evch_evq_status	- Return status of delivery thread, running or on hold
 * evch_evq_evzalloc	- Allocate an event structure
 * evch_evq_evfree	- Free an event structure
 * evch_evq_evadd_dest	- Add a destructor function to an event structure
 * evch_evq_evnext	- Iterate over events non-destructive
 */

/*ARGSUSED*/
static void *
evch_zoneinit(zoneid_t zoneid)
{
	struct evch_globals *eg;

	eg = kmem_zalloc(sizeof (*eg), KM_SLEEP);
	evch_dl_init(&eg->evch_list);
	return (eg);
}

/*ARGSUSED*/
static void
evch_zonefree(zoneid_t zoneid, void *arg)
{
	struct evch_globals *eg = arg;
	evch_chan_t *chp;
	evch_subd_t *sdp;

	mutex_enter(&eg->evch_list_lock);

	/*
	 * Keep picking the head element off the list until there are no
	 * more.
	 */
	while ((chp = evch_dl_next(&eg->evch_list, NULL)) != NULL) {

		/*
		 * Since all processes are gone, all bindings should be gone,
		 * and only channels with SUB_KEEP subscribers should remain.
		 */
		mutex_enter(&chp->ch_mutex);
		ASSERT(chp->ch_bindings == 0);
		ASSERT(evch_dl_getnum(&chp->ch_subscr) != 0 ||
		    chp->ch_holdpend == CH_HOLD_PEND_INDEF);

		/* Forcibly unsubscribe each remaining subscription */
		while ((sdp = evch_dl_next(&chp->ch_subscr, NULL)) != NULL) {
			/*
			 * We should only be tearing down persistent
			 * subscribers at this point, since all processes
			 * from this zone are gone.
			 */
			ASSERT(sdp->sd_active == 0);
			ASSERT((sdp->sd_persist & EVCH_SUB_KEEP) != 0);
			/*
			 * Disconnect subscriber queue from main event queue.
			 */
			evch_evq_unsub(chp->ch_queue, sdp->sd_msub);

			/* Destruct per subscriber queue */
			evch_evq_unsub(sdp->sd_queue, sdp->sd_ssub);
			evch_evq_destroy(sdp->sd_queue);
			/*
			 * Eliminate the subscriber data from channel list.
			 */
			evch_dl_del(&chp->ch_subscr, &sdp->sd_link);
			kmem_free(sdp->sd_classname, sdp->sd_clnsize);
			kmem_free(sdp->sd_ident, strlen(sdp->sd_ident) + 1);
			kmem_free(sdp, sizeof (evch_subd_t));
		}

		/* Channel must now have no subscribers */
		ASSERT(evch_dl_getnum(&chp->ch_subscr) == 0);

		/* Just like unbind */
		mutex_exit(&chp->ch_mutex);
		evch_dl_del(&eg->evch_list, &chp->ch_link);
		evch_evq_destroy(chp->ch_queue);
		mutex_destroy(&chp->ch_mutex);
		mutex_destroy(&chp->ch_pubmx);
		cv_destroy(&chp->ch_pubcv);
		kmem_free(chp->ch_name, chp->ch_namelen);
		kmem_free(chp, sizeof (evch_chan_t));
	}

	mutex_exit(&eg->evch_list_lock);
	/* all channels should now be gone */
	ASSERT(evch_dl_getnum(&eg->evch_list) == 0);
	kmem_free(eg, sizeof (*eg));
}

/*
 * Frees evch_gevent_t structure including the payload, if the reference count
 * drops to or below zero. Below zero happens when the event is freed
 * without beeing queued into a queue.
 */
static void
evch_gevent_free(evch_gevent_t *evp)
{
	int32_t refcnt;

	refcnt = (int32_t)atomic_dec_32_nv(&evp->ge_refcount);
	if (refcnt <= 0) {
		if (evp->ge_destruct != NULL) {
			evp->ge_destruct((void *)&(evp->ge_payload),
			    evp->ge_dstcookie);
		}
		kmem_free(evp, evp->ge_size);
	}
}

/*
 * Deliver is called for every subscription to the current event
 * It calls the registered filter function and then the registered delivery
 * callback routine. Returns 0 on success. The callback routine returns
 * EVQ_AGAIN or EVQ_SLEEP in case the event could not be delivered.
 */
static int
evch_deliver(evch_evqsub_t *sp, evch_gevent_t *ep)
{
	void		*uep = &ep->ge_payload;
	int		res = EVQ_DELIVER;

	if (sp->su_filter != NULL) {
		res = sp->su_filter(uep, sp->su_fcookie);
	}
	if (res == EVQ_DELIVER) {
		return (sp->su_callb(uep, sp->su_cbcookie));
	}
	return (0);
}

/*
 * Holds event delivery in case of eq_holdmode set or in case the
 * event queue is empty. Mutex must be held when called.
 * Wakes up a thread waiting for the delivery thread reaching the hold mode.
 */
static void
evch_delivery_hold(evch_eventq_t *eqp, callb_cpr_t *cpip)
{
	if (eqp->eq_tabortflag == 0) {
		do {
			if (eqp->eq_holdmode) {
				cv_signal(&eqp->eq_onholdcv);
			}
			CALLB_CPR_SAFE_BEGIN(cpip);
			cv_wait(&eqp->eq_thrsleepcv, &eqp->eq_queuemx);
			CALLB_CPR_SAFE_END(cpip, &eqp->eq_queuemx);
		} while (eqp->eq_holdmode);
	}
}

/*
 * Event delivery thread. Enumerates all subscribers and calls evch_deliver()
 * for each one.
 */
static void
evch_delivery_thr(evch_eventq_t *eqp)
{
	evch_qelem_t	*qep;
	callb_cpr_t	cprinfo;
	int		res;
	evch_evqsub_t	*sub;
	int		deltime;
	int		repeatcount;
	char		thnam[32];

	(void) snprintf(thnam, sizeof (thnam), "sysevent_chan-%d",
	    (int)eqp->eq_thrid);
	CALLB_CPR_INIT(&cprinfo, &eqp->eq_queuemx, callb_generic_cpr, thnam);
	mutex_enter(&eqp->eq_queuemx);
	while (eqp->eq_tabortflag == 0) {
		while (eqp->eq_holdmode == 0 && eqp->eq_tabortflag == 0 &&
		    (qep = evch_q_out(&eqp->eq_eventq)) != NULL) {

			/* Filter and deliver event to all subscribers */
			deltime = EVCH_MIN_PAUSE;
			repeatcount = EVCH_MAX_TRY_DELIVERY;
			eqp->eq_curevent = qep->q_objref;
			sub = evch_dl_next(&eqp->eq_subscr, NULL);
			while (sub != NULL) {
				eqp->eq_dactive = 1;
				mutex_exit(&eqp->eq_queuemx);
				res = evch_deliver(sub, qep->q_objref);
				mutex_enter(&eqp->eq_queuemx);
				eqp->eq_dactive = 0;
				cv_signal(&eqp->eq_dactivecv);
				switch (res) {
				case EVQ_SLEEP:
					/*
					 * Wait for subscriber to return.
					 */
					eqp->eq_holdmode = 1;
					evch_delivery_hold(eqp, &cprinfo);
					if (eqp->eq_tabortflag) {
						break;
					}
					continue;
				case EVQ_AGAIN:
					CALLB_CPR_SAFE_BEGIN(&cprinfo);
					mutex_exit(&eqp->eq_queuemx);
					delay(deltime);
					deltime =
					    deltime > EVCH_MAX_PAUSE ?
					    deltime : deltime << 1;
					mutex_enter(&eqp->eq_queuemx);
					CALLB_CPR_SAFE_END(&cprinfo,
					    &eqp->eq_queuemx);
					if (repeatcount-- > 0) {
						continue;
					}
					break;
				}
				if (eqp->eq_tabortflag) {
					break;
				}
				sub = evch_dl_next(&eqp->eq_subscr, sub);
				repeatcount = EVCH_MAX_TRY_DELIVERY;
			}
			eqp->eq_curevent = NULL;

			/* Free event data and queue element */
			evch_gevent_free((evch_gevent_t *)qep->q_objref);
			kmem_free(qep, qep->q_objsize);
		}

		/* Wait for next event or end of hold mode if set */
		evch_delivery_hold(eqp, &cprinfo);
	}
	CALLB_CPR_EXIT(&cprinfo);	/* Does mutex_exit of eqp->eq_queuemx */
	thread_exit();
}

/*
 * Create the event delivery thread for an existing event queue.
 */
static void
evch_evq_thrcreate(evch_eventq_t *eqp)
{
	kthread_t *thp;

	thp = thread_create(NULL, 0, evch_delivery_thr, (char *)eqp, 0, &p0,
	    TS_RUN, minclsyspri);
	eqp->eq_thrid = thp->t_did;
}

/*
 * Create event queue.
 */
static evch_eventq_t *
evch_evq_create()
{
	evch_eventq_t *p;

	/* Allocate and initialize event queue descriptor */
	p = kmem_zalloc(sizeof (evch_eventq_t), KM_SLEEP);
	mutex_init(&p->eq_queuemx, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&p->eq_thrsleepcv, NULL, CV_DEFAULT, NULL);
	evch_q_init(&p->eq_eventq);
	evch_dl_init(&p->eq_subscr);
	cv_init(&p->eq_dactivecv, NULL, CV_DEFAULT, NULL);
	cv_init(&p->eq_onholdcv, NULL, CV_DEFAULT, NULL);

	/* Create delivery thread */
	if (evq_initcomplete) {
		evch_evq_thrcreate(p);
	}
	return (p);
}

/*
 * Destroy an event queue. All subscribers have to be unsubscribed prior to
 * this call.
 */
static void
evch_evq_destroy(evch_eventq_t *eqp)
{
	evch_qelem_t *qep;

	ASSERT(evch_dl_getnum(&eqp->eq_subscr) == 0);
	/* Kill delivery thread */
	if (eqp->eq_thrid != NULL) {
		mutex_enter(&eqp->eq_queuemx);
		eqp->eq_tabortflag = 1;
		eqp->eq_holdmode = 0;
		cv_signal(&eqp->eq_thrsleepcv);
		mutex_exit(&eqp->eq_queuemx);
		thread_join(eqp->eq_thrid);
	}

	/* Get rid of stale events in the event queue */
	while ((qep = (evch_qelem_t *)evch_q_out(&eqp->eq_eventq)) != NULL) {
		evch_gevent_free((evch_gevent_t *)qep->q_objref);
		kmem_free(qep, qep->q_objsize);
	}

	/* Wrap up event queue structure */
	cv_destroy(&eqp->eq_onholdcv);
	cv_destroy(&eqp->eq_dactivecv);
	cv_destroy(&eqp->eq_thrsleepcv);
	evch_dl_fini(&eqp->eq_subscr);
	mutex_destroy(&eqp->eq_queuemx);

	/* Free descriptor structure */
	kmem_free(eqp, sizeof (evch_eventq_t));
}

/*
 * Subscribe to an event queue. Every subscriber provides a filter callback
 * routine and an event delivery callback routine.
 */
static evch_evqsub_t *
evch_evq_sub(evch_eventq_t *eqp, filter_f filter, void *fcookie,
    deliver_f callb, void *cbcookie)
{
	evch_evqsub_t *sp = kmem_zalloc(sizeof (evch_evqsub_t), KM_SLEEP);

	/* Initialize subscriber structure */
	sp->su_filter = filter;
	sp->su_fcookie = fcookie;
	sp->su_callb = callb;
	sp->su_cbcookie = cbcookie;

	/* Add subscription to queue */
	mutex_enter(&eqp->eq_queuemx);
	evch_dl_add(&eqp->eq_subscr, &sp->su_link);
	mutex_exit(&eqp->eq_queuemx);
	return (sp);
}

/*
 * Unsubscribe from an event queue.
 */
static void
evch_evq_unsub(evch_eventq_t *eqp, evch_evqsub_t *sp)
{
	mutex_enter(&eqp->eq_queuemx);

	/* Wait if delivery is just in progress */
	if (eqp->eq_dactive) {
		cv_wait(&eqp->eq_dactivecv, &eqp->eq_queuemx);
	}
	evch_dl_del(&eqp->eq_subscr, &sp->su_link);
	mutex_exit(&eqp->eq_queuemx);
	kmem_free(sp, sizeof (evch_evqsub_t));
}

/*
 * Publish an event. Returns 0 on success and -1 if memory alloc failed.
 */
static int
evch_evq_pub(evch_eventq_t *eqp, void *ev, int flags)
{
	size_t size;
	evch_qelem_t	*qep;
	evch_gevent_t	*evp = GEVENT(ev);

	size = sizeof (evch_qelem_t);
	if (flags & EVCH_TRYHARD) {
		qep = kmem_alloc_tryhard(size, &size, KM_NOSLEEP);
	} else {
		qep = kmem_alloc(size, flags & EVCH_NOSLEEP ?
		    KM_NOSLEEP : KM_SLEEP);
	}
	if (qep == NULL) {
		return (-1);
	}
	qep->q_objref = (void *)evp;
	qep->q_objsize = size;
	atomic_inc_32(&evp->ge_refcount);
	mutex_enter(&eqp->eq_queuemx);
	evch_q_in(&eqp->eq_eventq, qep);

	/* Wakeup delivery thread */
	cv_signal(&eqp->eq_thrsleepcv);
	mutex_exit(&eqp->eq_queuemx);
	return (0);
}

/*
 * Enter hold mode of an event queue. Event delivery thread stops event
 * handling after delivery of current event (if any).
 */
static void
evch_evq_stop(evch_eventq_t *eqp)
{
	mutex_enter(&eqp->eq_queuemx);
	eqp->eq_holdmode = 1;
	if (evq_initcomplete) {
		cv_signal(&eqp->eq_thrsleepcv);
		cv_wait(&eqp->eq_onholdcv, &eqp->eq_queuemx);
	}
	mutex_exit(&eqp->eq_queuemx);
}

/*
 * Continue event delivery.
 */
static void
evch_evq_continue(evch_eventq_t *eqp)
{
	mutex_enter(&eqp->eq_queuemx);
	eqp->eq_holdmode = 0;
	cv_signal(&eqp->eq_thrsleepcv);
	mutex_exit(&eqp->eq_queuemx);
}

/*
 * Returns status of delivery thread. 0 if running and 1 if on hold.
 */
static int
evch_evq_status(evch_eventq_t *eqp)
{
	return (eqp->eq_holdmode);
}

/*
 * Add a destructor function to an event structure.
 */
static void
evch_evq_evadd_dest(void *ev, destr_f destructor, void *cookie)
{
	evch_gevent_t *evp = GEVENT(ev);

	evp->ge_destruct = destructor;
	evp->ge_dstcookie = cookie;
}

/*
 * Allocate evch_gevent_t structure. Return address of payload offset of
 * evch_gevent_t.  If EVCH_TRYHARD allocation is requested, we use
 * kmem_alloc_tryhard to alloc memory of at least paylsize bytes.
 *
 * If either memory allocation is unsuccessful, we return NULL.
 */
static void *
evch_evq_evzalloc(size_t paylsize, int flag)
{
	evch_gevent_t	*evp;
	size_t		rsize, evsize, ge_size;

	rsize = offsetof(evch_gevent_t, ge_payload) + paylsize;
	if (flag & EVCH_TRYHARD) {
		evp = kmem_alloc_tryhard(rsize, &evsize, KM_NOSLEEP);
		ge_size = evsize;
	} else {
		evp = kmem_alloc(rsize, flag & EVCH_NOSLEEP ? KM_NOSLEEP :
		    KM_SLEEP);
		ge_size = rsize;
	}

	if (evp) {
		bzero(evp, rsize);
		evp->ge_size = ge_size;
		return (&evp->ge_payload);
	}
	return (evp);
}

/*
 * Free event structure. Argument ev is address of payload offset.
 */
static void
evch_evq_evfree(void *ev)
{
	evch_gevent_free(GEVENT(ev));
}

/*
 * Iterate over all events in the event queue. Begin with an event
 * which is currently being delivered. No mutexes are grabbed and no
 * resources allocated so that this function can be called in panic
 * context too. This function has to be called with ev == NULL initially.
 * Actually argument ev is only a flag. Internally the member eq_nextev
 * is used to determine the next event. But ev allows for the convenient
 * use like
 *	ev = NULL;
 *	while ((ev = evch_evq_evnext(evp, ev)) != NULL) ...
 */
static void *
evch_evq_evnext(evch_eventq_t *evq, void *ev)
{
	if (ev == NULL) {
		evq->eq_nextev = NULL;
		if (evq->eq_curevent != NULL)
			return (&evq->eq_curevent->ge_payload);
	}
	evq->eq_nextev = evch_q_next(&evq->eq_eventq, evq->eq_nextev);
	if (evq->eq_nextev == NULL)
		return (NULL);
	return (&((evch_gevent_t *)evq->eq_nextev->q_objref)->ge_payload);
}

/*
 * Channel handling functions. First some support functions. Functions belonging
 * to the channel handling interface start with evch_ch. The following functions
 * make up the channel handling internal interfaces:
 *
 * evch_chinit		- Initialize channel handling
 * evch_chinitthr	- Second step init: initialize threads
 * evch_chbind		- Bind to a channel
 * evch_chunbind	- Unbind from a channel
 * evch_chsubscribe	- Subscribe to a sysevent class
 * evch_chunsubscribe	- Unsubscribe
 * evch_chpublish	- Publish an event
 * evch_chgetnames	- Get names of all channels
 * evch_chgetchdata	- Get data of a channel
 * evch_chrdevent_init  - Init event q traversal
 * evch_chgetnextev	- Read out events queued for a subscriber
 * evch_chrdevent_fini  - Finish event q traversal
 */

/*
 * Compare channel name. Used for evch_dl_search to find a channel with the
 * name s.
 */
static int
evch_namecmp(evch_dlelem_t *ep, char *s)
{
	return (strcmp(((evch_chan_t *)ep)->ch_name, s));
}

/*
 * Simple wildcarded match test of event class string 'class' to
 * wildcarded subscription string 'pat'.  Recursive only if
 * 'pat' includes a wildcard, otherwise essentially just strcmp.
 */
static int
evch_clsmatch(char *class, const char *pat)
{
	char c;

	do {
		if ((c = *pat++) == '\0')
			return (*class == '\0');

		if (c == '*') {
			while (*pat == '*')
				pat++; /* consecutive *'s can be collapsed */

			if (*pat == '\0')
				return (1);

			while (*class != '\0') {
				if (evch_clsmatch(class++, pat) != 0)
					return (1);
			}

			return (0);
		}
	} while (c == *class++);

	return (0);
}

/*
 * Sysevent filter callback routine. Enables event delivery only if it matches
 * the event class pattern string given by parameter cookie.
 */
static int
evch_class_filter(void *ev, void *cookie)
{
	const char *pat = (const char *)cookie;

	if (pat == NULL || evch_clsmatch(SE_CLASS_NAME(ev), pat))
		return (EVQ_DELIVER);

	return (EVQ_IGNORE);
}

/*
 * Callback routine to propagate the event into a per subscriber queue.
 */
static int
evch_subq_deliver(void *evp, void *cookie)
{
	evch_subd_t *p = (evch_subd_t *)cookie;

	(void) evch_evq_pub(p->sd_queue, evp, EVCH_SLEEP);
	return (EVQ_CONT);
}

/*
 * Call kernel callback routine for sysevent kernel delivery.
 */
static int
evch_kern_deliver(void *evp, void *cookie)
{
	sysevent_impl_t	*ev = (sysevent_impl_t *)evp;
	evch_subd_t	*sdp = (evch_subd_t *)cookie;

	return (sdp->sd_callback(ev, sdp->sd_cbcookie));
}

/*
 * Door upcall for user land sysevent delivery.
 */
static int
evch_door_deliver(void *evp, void *cookie)
{
	int		error;
	size_t		size;
	sysevent_impl_t	*ev = (sysevent_impl_t *)evp;
	door_arg_t	darg;
	evch_subd_t	*sdp = (evch_subd_t *)cookie;
	int		nticks = EVCH_MIN_PAUSE;
	uint32_t	retval;
	int		retry = 20;

	/* Initialize door args */
	size = sizeof (sysevent_impl_t) + SE_PAYLOAD_SZ(ev);

	darg.rbuf = (char *)&retval;
	darg.rsize = sizeof (retval);
	darg.data_ptr = (char *)ev;
	darg.data_size = size;
	darg.desc_ptr = NULL;
	darg.desc_num = 0;

	for (;;) {
		if ((error = door_ki_upcall_limited(sdp->sd_door, &darg,
		    NULL, SIZE_MAX, 0)) == 0) {
			break;
		}
		switch (error) {
		case EAGAIN:
			/* Cannot deliver event - process may be forking */
			delay(nticks);
			nticks <<= 1;
			if (nticks > EVCH_MAX_PAUSE) {
				nticks = EVCH_MAX_PAUSE;
			}
			if (retry-- <= 0) {
				cmn_err(CE_CONT, "event delivery thread: "
				    "door_ki_upcall error EAGAIN\n");
				return (EVQ_CONT);
			}
			break;
		case EINTR:
		case EBADF:
			/* Process died */
			return (EVQ_SLEEP);
		default:
			cmn_err(CE_CONT,
			    "event delivery thread: door_ki_upcall error %d\n",
			    error);
			return (EVQ_CONT);
		}
	}
	if (retval == EAGAIN) {
		return (EVQ_AGAIN);
	}
	return (EVQ_CONT);
}

/*
 * Callback routine for evch_dl_search() to compare subscriber id's. Used by
 * evch_subscribe() and evch_chrdevent_init().
 */
static int
evch_subidcmp(evch_dlelem_t *ep, char *s)
{
	return (strcmp(((evch_subd_t *)ep)->sd_ident, s));
}

/*
 * Callback routine for evch_dl_search() to find a subscriber with EVCH_SUB_DUMP
 * set (indicated by sub->sd_dump != 0). Used by evch_chrdevent_init() and
 * evch_subscribe(). Needs to returns 0 if subscriber with sd_dump set is
 * found.
 */
/*ARGSUSED1*/
static int
evch_dumpflgcmp(evch_dlelem_t *ep, char *s)
{
	return (((evch_subd_t *)ep)->sd_dump ? 0 : 1);
}

/*
 * Event destructor function. Used to maintain the number of events per channel.
 */
/*ARGSUSED*/
static void
evch_destr_event(void *ev, void *ch)
{
	evch_chan_t *chp = (evch_chan_t *)ch;

	mutex_enter(&chp->ch_pubmx);
	chp->ch_nevents--;
	cv_signal(&chp->ch_pubcv);
	mutex_exit(&chp->ch_pubmx);
}

/*
 * Integer square root according to Newton's iteration.
 */
static uint32_t
evch_isqrt(uint64_t n)
{
	uint64_t	x = n >> 1;
	uint64_t	xn = x - 1;
	static uint32_t	lowval[] = { 0, 1, 1, 2 };

	if (n < 4) {
		return (lowval[n]);
	}
	while (xn < x) {
		x = xn;
		xn = (x + n / x) / 2;
	}
	return ((uint32_t)xn);
}

/*
 * First step sysevent channel initialization. Called when kernel memory
 * allocator is initialized.
 */
static void
evch_chinit()
{
	size_t k;

	/*
	 * Calculate limits: max no of channels and max no of events per
	 * channel. The smallest machine with 128 MByte will allow for
	 * >= 8 channels and an upper limit of 2048 events per channel.
	 * The event limit is the number of channels times 256 (hence
	 * the shift factor of 8). These number where selected arbitrarily.
	 */
	k = kmem_maxavail() >> 20;
	evch_channels_max = min(evch_isqrt(k), EVCH_MAX_CHANNELS);
	evch_events_max = evch_channels_max << 8;

	/*
	 * Will trigger creation of the global zone's evch state.
	 */
	zone_key_create(&evch_zone_key, evch_zoneinit, NULL, evch_zonefree);
}

/*
 * Second step sysevent channel initialization. Called when threads are ready.
 */
static void
evch_chinitthr()
{
	struct evch_globals *eg;
	evch_chan_t	*chp;
	evch_subd_t	*sdp;

	/*
	 * We're early enough in boot that we know that only the global
	 * zone exists; we only need to initialize its threads.
	 */
	eg = zone_getspecific(evch_zone_key, global_zone);
	ASSERT(eg != NULL);

	for (chp = evch_dl_next(&eg->evch_list, NULL); chp != NULL;
	    chp = evch_dl_next(&eg->evch_list, chp)) {
		for (sdp = evch_dl_next(&chp->ch_subscr, NULL); sdp;
		    sdp = evch_dl_next(&chp->ch_subscr, sdp)) {
			evch_evq_thrcreate(sdp->sd_queue);
		}
		evch_evq_thrcreate(chp->ch_queue);
	}
	evq_initcomplete = 1;
}

/*
 * Sysevent channel bind. Create channel and allocate binding structure.
 */
static int
evch_chbind(const char *chnam, evch_bind_t **scpp, uint32_t flags)
{
	struct evch_globals *eg;
	evch_bind_t	*bp;
	evch_chan_t	*p;
	char		*chn;
	size_t		namlen;
	int		rv;

	eg = zone_getspecific(evch_zone_key, curproc->p_zone);
	ASSERT(eg != NULL);

	/* Create channel if it does not exist */
	ASSERT(evch_dl_is_init(&eg->evch_list));
	if ((namlen = strlen(chnam) + 1) > MAX_CHNAME_LEN) {
		return (EINVAL);
	}
	mutex_enter(&eg->evch_list_lock);
	if ((p = (evch_chan_t *)evch_dl_search(&eg->evch_list, evch_namecmp,
	    (char *)chnam)) == NULL) {
		if (flags & EVCH_CREAT) {
			if (evch_dl_getnum(&eg->evch_list) >=
			    evch_channels_max) {
				mutex_exit(&eg->evch_list_lock);
				return (ENOMEM);
			}
			chn = kmem_alloc(namlen, KM_SLEEP);
			bcopy(chnam, chn, namlen);

			/* Allocate and initialize channel descriptor */
			p = kmem_zalloc(sizeof (evch_chan_t), KM_SLEEP);
			p->ch_name = chn;
			p->ch_namelen = namlen;
			mutex_init(&p->ch_mutex, NULL, MUTEX_DEFAULT, NULL);
			p->ch_queue = evch_evq_create();
			evch_dl_init(&p->ch_subscr);
			if (evq_initcomplete) {
				p->ch_uid = crgetuid(curthread->t_cred);
				p->ch_gid = crgetgid(curthread->t_cred);
			}
			cv_init(&p->ch_pubcv, NULL, CV_DEFAULT, NULL);
			mutex_init(&p->ch_pubmx, NULL, MUTEX_DEFAULT, NULL);
			p->ch_maxev = min(EVCH_DEFAULT_EVENTS, evch_events_max);
			p->ch_maxsubscr = EVCH_MAX_SUBSCRIPTIONS;
			p->ch_maxbinds = evch_bindings_max;
			p->ch_ctime = gethrestime_sec();

			if (flags & (EVCH_HOLD_PEND | EVCH_HOLD_PEND_INDEF)) {
				if (flags & EVCH_HOLD_PEND_INDEF)
					p->ch_holdpend = CH_HOLD_PEND_INDEF;
				else
					p->ch_holdpend = CH_HOLD_PEND;

				evch_evq_stop(p->ch_queue);
			}

			/* Put new descriptor into channel list */
			evch_dl_add(&eg->evch_list, (evch_dlelem_t *)p);
		} else {
			mutex_exit(&eg->evch_list_lock);
			return (ENOENT);
		}
	}

	/* Check for max binds and create binding */
	mutex_enter(&p->ch_mutex);
	if (p->ch_bindings >= p->ch_maxbinds) {
		rv = ENOMEM;
		/*
		 * No need to destroy the channel because this call did not
		 * create it. Other bindings will be present if ch_maxbinds
		 * is exceeded.
		 */
		goto errorexit;
	}
	bp = kmem_alloc(sizeof (evch_bind_t), KM_SLEEP);
	bp->bd_channel = p;
	bp->bd_sublst = NULL;
	p->ch_bindings++;
	rv = 0;
	*scpp = bp;
errorexit:
	mutex_exit(&p->ch_mutex);
	mutex_exit(&eg->evch_list_lock);
	return (rv);
}

/*
 * Unbind: Free bind structure. Remove channel if last binding was freed.
 */
static void
evch_chunbind(evch_bind_t *bp)
{
	struct evch_globals *eg;
	evch_chan_t *chp = bp->bd_channel;

	eg = zone_getspecific(evch_zone_key, curproc->p_zone);
	ASSERT(eg != NULL);

	mutex_enter(&eg->evch_list_lock);
	mutex_enter(&chp->ch_mutex);
	ASSERT(chp->ch_bindings > 0);
	chp->ch_bindings--;
	kmem_free(bp, sizeof (evch_bind_t));
	if (chp->ch_bindings == 0 && evch_dl_getnum(&chp->ch_subscr) == 0 &&
	    (chp->ch_nevents == 0 || chp->ch_holdpend != CH_HOLD_PEND_INDEF)) {
		/*
		 * No more bindings and no persistent subscriber(s).  If there
		 * are no events in the channel then destroy the channel;
		 * otherwise destroy the channel only if we're not holding
		 * pending events indefinitely.
		 */
		mutex_exit(&chp->ch_mutex);
		evch_dl_del(&eg->evch_list, &chp->ch_link);
		evch_evq_destroy(chp->ch_queue);
		if (chp->ch_propnvl)
			nvlist_free(chp->ch_propnvl);
		mutex_destroy(&chp->ch_mutex);
		mutex_destroy(&chp->ch_pubmx);
		cv_destroy(&chp->ch_pubcv);
		kmem_free(chp->ch_name, chp->ch_namelen);
		kmem_free(chp, sizeof (evch_chan_t));
	} else
		mutex_exit(&chp->ch_mutex);
	mutex_exit(&eg->evch_list_lock);
}

static int
wildcard_count(const char *class)
{
	int count = 0;
	char c;

	if (class == NULL)
		return (0);

	while ((c = *class++) != '\0') {
		if (c == '*')
			count++;
	}

	return (count);
}

/*
 * Subscribe to a channel. dtype is either EVCH_DELKERN for kernel callbacks
 * or EVCH_DELDOOR for door upcall delivery to user land. Depending on dtype
 * dinfo gives the call back routine address or the door handle.
 */
static int
evch_chsubscribe(evch_bind_t *bp, int dtype, const char *sid, const char *class,
    void *dinfo, void *cookie, int flags, pid_t pid)
{
	evch_chan_t	*chp = bp->bd_channel;
	evch_eventq_t	*eqp = chp->ch_queue;
	evch_subd_t	*sdp;
	evch_subd_t	*esp;
	int		(*delivfkt)();
	char		*clb = NULL;
	int		clblen = 0;
	char		*subid;
	int		subidblen;

	/*
	 * Check if only known flags are set.
	 */
	if (flags & ~(EVCH_SUB_KEEP | EVCH_SUB_DUMP))
		return (EINVAL);

	/*
	 * Enforce a limit on the number of wildcards allowed in the class
	 * subscription string (limits recursion in pattern matching).
	 */
	if (wildcard_count(class) > EVCH_WILDCARD_MAX)
		return (EINVAL);

	/*
	 * Check if we have already a subscription with that name and if we
	 * have to reconnect the subscriber to a persistent subscription.
	 */
	mutex_enter(&chp->ch_mutex);
	if ((esp = (evch_subd_t *)evch_dl_search(&chp->ch_subscr,
	    evch_subidcmp, (char *)sid)) != NULL) {
		int error = 0;
		if ((flags & EVCH_SUB_KEEP) && (esp->sd_active == 0)) {
			/*
			 * Subscription with the name on hold, reconnect to
			 * existing queue.
			 */
			ASSERT(dtype == EVCH_DELDOOR);
			esp->sd_subnxt = bp->bd_sublst;
			bp->bd_sublst = esp;
			esp->sd_pid = pid;
			esp->sd_door = (door_handle_t)dinfo;
			esp->sd_active++;
			evch_evq_continue(esp->sd_queue);
		} else {
			/* Subscriber with given name already exists */
			error = EEXIST;
		}
		mutex_exit(&chp->ch_mutex);
		return (error);
	}

	if (evch_dl_getnum(&chp->ch_subscr) >= chp->ch_maxsubscr) {
		mutex_exit(&chp->ch_mutex);
		return (ENOMEM);
	}

	if (flags & EVCH_SUB_DUMP && evch_dl_search(&chp->ch_subscr,
	    evch_dumpflgcmp, NULL) != NULL) {
		/*
		 * Subscription with EVCH_SUB_DUMP flagged already exists.
		 * Only one subscription with EVCH_SUB_DUMP possible. Return
		 * error.
		 */
		mutex_exit(&chp->ch_mutex);
		return (EINVAL);
	}

	if (class != NULL) {
		clblen = strlen(class) + 1;
		clb = kmem_alloc(clblen, KM_SLEEP);
		bcopy(class, clb, clblen);
	}

	subidblen = strlen(sid) + 1;
	subid = kmem_alloc(subidblen, KM_SLEEP);
	bcopy(sid, subid, subidblen);

	/* Create per subscriber queue */
	sdp = kmem_zalloc(sizeof (evch_subd_t), KM_SLEEP);
	sdp->sd_queue = evch_evq_create();

	/* Subscribe to subscriber queue */
	sdp->sd_persist = flags & EVCH_SUB_KEEP ? 1 : 0;
	sdp->sd_dump = flags & EVCH_SUB_DUMP ? 1 : 0;
	sdp->sd_type = dtype;
	sdp->sd_cbcookie = cookie;
	sdp->sd_ident = subid;
	if (dtype == EVCH_DELKERN) {
		sdp->sd_callback = (kerndlv_f)dinfo;
		delivfkt = evch_kern_deliver;
	} else {
		sdp->sd_door = (door_handle_t)dinfo;
		delivfkt = evch_door_deliver;
	}
	sdp->sd_ssub =
	    evch_evq_sub(sdp->sd_queue, NULL, NULL, delivfkt, (void *)sdp);

	/* Connect per subscriber queue to main event queue */
	sdp->sd_msub = evch_evq_sub(eqp, evch_class_filter, clb,
	    evch_subq_deliver, (void *)sdp);
	sdp->sd_classname = clb;
	sdp->sd_clnsize = clblen;
	sdp->sd_pid = pid;
	sdp->sd_active++;

	/* Add subscription to binding */
	sdp->sd_subnxt = bp->bd_sublst;
	bp->bd_sublst = sdp;

	/* Add subscription to channel */
	evch_dl_add(&chp->ch_subscr, &sdp->sd_link);
	if (chp->ch_holdpend && evch_dl_getnum(&chp->ch_subscr) == 1) {

		/* Let main event queue run in case of HOLDPEND */
		evch_evq_continue(eqp);
	}
	mutex_exit(&chp->ch_mutex);

	return (0);
}

/*
 * If flag == EVCH_SUB_KEEP only non-persistent subscriptions are deleted.
 * When sid == NULL all subscriptions except the ones with EVCH_SUB_KEEP set
 * are removed.
 */
static void
evch_chunsubscribe(evch_bind_t *bp, const char *sid, uint32_t flags)
{
	evch_subd_t	*sdp;
	evch_subd_t	*next;
	evch_subd_t	*prev;
	evch_chan_t	*chp = bp->bd_channel;

	mutex_enter(&chp->ch_mutex);
	if (chp->ch_holdpend) {
		evch_evq_stop(chp->ch_queue);	/* Hold main event queue */
	}
	prev = NULL;
	for (sdp = bp->bd_sublst; sdp; sdp = next) {
		if (sid == NULL || strcmp(sid, sdp->sd_ident) == 0) {
			if (flags == 0 || sdp->sd_persist == 0) {
				/*
				 * Disconnect subscriber queue from main event
				 * queue.
				 */
				evch_evq_unsub(chp->ch_queue, sdp->sd_msub);

				/* Destruct per subscriber queue */
				evch_evq_unsub(sdp->sd_queue, sdp->sd_ssub);
				evch_evq_destroy(sdp->sd_queue);
				/*
				 * Eliminate the subscriber data from channel
				 * list.
				 */
				evch_dl_del(&chp->ch_subscr, &sdp->sd_link);
				kmem_free(sdp->sd_classname, sdp->sd_clnsize);
				if (sdp->sd_type == EVCH_DELDOOR) {
					door_ki_rele(sdp->sd_door);
				}
				next = sdp->sd_subnxt;
				if (prev) {
					prev->sd_subnxt = next;
				} else {
					bp->bd_sublst = next;
				}
				kmem_free(sdp->sd_ident,
				    strlen(sdp->sd_ident) + 1);
				kmem_free(sdp, sizeof (evch_subd_t));
			} else {
				/*
				 * EVCH_SUB_KEEP case
				 */
				evch_evq_stop(sdp->sd_queue);
				if (sdp->sd_type == EVCH_DELDOOR) {
					door_ki_rele(sdp->sd_door);
				}
				sdp->sd_active--;
				ASSERT(sdp->sd_active == 0);
				next = sdp->sd_subnxt;
				prev = sdp;
			}
			if (sid != NULL) {
				break;
			}
		} else {
			next = sdp->sd_subnxt;
			prev = sdp;
		}
	}
	if (!(chp->ch_holdpend && evch_dl_getnum(&chp->ch_subscr) == 0)) {
		/*
		 * Continue dispatch thread except if no subscribers are present
		 * in HOLDPEND mode.
		 */
		evch_evq_continue(chp->ch_queue);
	}
	mutex_exit(&chp->ch_mutex);
}

/*
 * Publish an event. Returns zero on success and an error code else.
 */
static int
evch_chpublish(evch_bind_t *bp, sysevent_impl_t *ev, int flags)
{
	evch_chan_t *chp = bp->bd_channel;

	DTRACE_SYSEVENT2(post, evch_bind_t *, bp, sysevent_impl_t *, ev);

	mutex_enter(&chp->ch_pubmx);
	if (chp->ch_nevents >= chp->ch_maxev) {
		if (!(flags & EVCH_QWAIT)) {
			evch_evq_evfree(ev);
			mutex_exit(&chp->ch_pubmx);
			return (EAGAIN);
		} else {
			while (chp->ch_nevents >= chp->ch_maxev) {
				if (cv_wait_sig(&chp->ch_pubcv,
				    &chp->ch_pubmx) == 0) {

					/* Got Signal, return EINTR */
					evch_evq_evfree(ev);
					mutex_exit(&chp->ch_pubmx);
					return (EINTR);
				}
			}
		}
	}
	chp->ch_nevents++;
	mutex_exit(&chp->ch_pubmx);
	SE_TIME(ev) = gethrtime();
	SE_SEQ(ev) = log_sysevent_new_id();
	/*
	 * Add the destructor function to the event structure, now that the
	 * event is accounted for. The only task of the descructor is to
	 * decrement the channel event count. The evq_*() routines (including
	 * the event delivery thread) do not have knowledge of the channel
	 * data. So the anonymous destructor handles the channel data for it.
	 */
	evch_evq_evadd_dest(ev, evch_destr_event, (void *)chp);
	return (evch_evq_pub(chp->ch_queue, ev, flags) == 0 ? 0 : EAGAIN);
}

/*
 * Fills a buffer consecutive with the names of all available channels.
 * Returns the length of all name strings or -1 if buffer size was unsufficient.
 */
static int
evch_chgetnames(char *buf, size_t size)
{
	struct evch_globals *eg;
	int		len = 0;
	char		*addr = buf;
	int		max = size;
	evch_chan_t	*chp;

	eg = zone_getspecific(evch_zone_key, curproc->p_zone);
	ASSERT(eg != NULL);

	mutex_enter(&eg->evch_list_lock);
	for (chp = evch_dl_next(&eg->evch_list, NULL); chp != NULL;
	    chp = evch_dl_next(&eg->evch_list, chp)) {
		len += chp->ch_namelen;
		if (len >= max) {
			mutex_exit(&eg->evch_list_lock);
			return (-1);
		}
		bcopy(chp->ch_name, addr, chp->ch_namelen);
		addr += chp->ch_namelen;
	}
	mutex_exit(&eg->evch_list_lock);
	addr[0] = 0;
	return (len + 1);
}

/*
 * Fills the data of one channel and all subscribers of that channel into
 * a buffer. Returns -1 if the channel name is invalid and 0 on buffer overflow.
 */
static int
evch_chgetchdata(char *chname, void *buf, size_t size)
{
	struct evch_globals *eg;
	char		*cpaddr;
	int		bufmax;
	int		buflen;
	evch_chan_t	*chp;
	sev_chinfo_t	*p = (sev_chinfo_t *)buf;
	int		chdlen;
	evch_subd_t	*sdp;
	sev_subinfo_t	*subp;
	int		idlen;
	int		len;

	eg = zone_getspecific(evch_zone_key, curproc->p_zone);
	ASSERT(eg != NULL);

	mutex_enter(&eg->evch_list_lock);
	chp = (evch_chan_t *)evch_dl_search(&eg->evch_list, evch_namecmp,
	    chname);
	if (chp == NULL) {
		mutex_exit(&eg->evch_list_lock);
		return (-1);
	}
	chdlen = offsetof(sev_chinfo_t, cd_subinfo);
	if (size < chdlen) {
		mutex_exit(&eg->evch_list_lock);
		return (0);
	}
	p->cd_version = 0;
	p->cd_suboffs = chdlen;
	p->cd_uid = chp->ch_uid;
	p->cd_gid = chp->ch_gid;
	p->cd_perms = 0;
	p->cd_ctime = chp->ch_ctime;
	p->cd_maxev = chp->ch_maxev;
	p->cd_evhwm = EVCH_EVQ_HIGHWM(chp->ch_queue);
	p->cd_nevents = EVCH_EVQ_EVCOUNT(chp->ch_queue);
	p->cd_maxsub = chp->ch_maxsubscr;
	p->cd_nsub = evch_dl_getnum(&chp->ch_subscr);
	p->cd_maxbinds = chp->ch_maxbinds;
	p->cd_nbinds = chp->ch_bindings;
	p->cd_holdpend = chp->ch_holdpend;
	p->cd_limev = evch_events_max;
	cpaddr = (char *)p + chdlen;
	bufmax = size - chdlen;
	buflen = 0;

	for (sdp = evch_dl_next(&chp->ch_subscr, NULL); sdp != NULL;
	    sdp = evch_dl_next(&chp->ch_subscr, sdp)) {
		idlen = strlen(sdp->sd_ident) + 1;
		len = SE_ALIGN(offsetof(sev_subinfo_t, sb_strings) + idlen +
		    sdp->sd_clnsize);
		buflen += len;
		if (buflen >= bufmax) {
			mutex_exit(&eg->evch_list_lock);
			return (0);
		}
		subp = (sev_subinfo_t *)cpaddr;
		subp->sb_nextoff = len;
		subp->sb_stroff = offsetof(sev_subinfo_t, sb_strings);
		if (sdp->sd_classname) {
			bcopy(sdp->sd_classname, subp->sb_strings + idlen,
			    sdp->sd_clnsize);
			subp->sb_clnamoff = idlen;
		} else {
			subp->sb_clnamoff = idlen - 1;
		}
		subp->sb_pid = sdp->sd_pid;
		subp->sb_nevents = EVCH_EVQ_EVCOUNT(sdp->sd_queue);
		subp->sb_evhwm = EVCH_EVQ_HIGHWM(sdp->sd_queue);
		subp->sb_persist = sdp->sd_persist;
		subp->sb_status = evch_evq_status(sdp->sd_queue);
		subp->sb_active = sdp->sd_active;
		subp->sb_dump = sdp->sd_dump;
		bcopy(sdp->sd_ident, subp->sb_strings, idlen);
		cpaddr += len;
	}
	mutex_exit(&eg->evch_list_lock);
	return (chdlen + buflen);
}

static void
evch_chsetpropnvl(evch_bind_t *bp, nvlist_t *nvl)
{
	evch_chan_t *chp = bp->bd_channel;

	mutex_enter(&chp->ch_mutex);

	if (chp->ch_propnvl)
		nvlist_free(chp->ch_propnvl);

	chp->ch_propnvl = nvl;
	chp->ch_propnvlgen++;

	mutex_exit(&chp->ch_mutex);
}

static int
evch_chgetpropnvl(evch_bind_t *bp, nvlist_t **nvlp, int64_t *genp)
{
	evch_chan_t *chp = bp->bd_channel;
	int rc = 0;

	mutex_enter(&chp->ch_mutex);

	if (chp->ch_propnvl != NULL)
		rc = (nvlist_dup(chp->ch_propnvl, nvlp, 0) == 0) ? 0 : ENOMEM;
	else
		*nvlp = NULL;	/* rc still 0 */

	if (genp)
		*genp = chp->ch_propnvlgen;

	mutex_exit(&chp->ch_mutex);

	if (rc != 0)
		*nvlp = NULL;

	return (rc);

}

/*
 * Init iteration of all events of a channel. This function creates a new
 * event queue and puts all events from the channel into that queue.
 * Subsequent calls to evch_chgetnextev will deliver the events from that
 * queue. Only one thread per channel is allowed to read through the events.
 * Returns 0 on success and 1 if there is already someone reading the
 * events.
 * If argument subid == NULL, we look for a subscriber which has
 * flag EVCH_SUB_DUMP set.
 */
/*
 * Static variables that are used to traverse events of a channel in panic case.
 */
static evch_chan_t	*evch_chan;
static evch_eventq_t	*evch_subq;
static sysevent_impl_t	*evch_curev;

static evchanq_t *
evch_chrdevent_init(evch_chan_t *chp, char *subid)
{
	evch_subd_t	*sdp;
	void		*ev;
	int		pmqstat;	/* Prev status of main queue */
	int		psqstat;	/* Prev status of subscriber queue */
	evchanq_t	*snp;		/* Pointer to q with snapshot of ev */
	compare_f	compfunc;

	compfunc = subid == NULL ? evch_dumpflgcmp : evch_subidcmp;
	if (panicstr != NULL) {
		evch_chan = chp;
		evch_subq = NULL;
		evch_curev = NULL;
		if ((sdp = (evch_subd_t *)evch_dl_search(&chp->ch_subscr,
		    compfunc, subid)) != NULL) {
			evch_subq = sdp->sd_queue;
		}
		return (NULL);
	}
	mutex_enter(&chp->ch_mutex);
	sdp = (evch_subd_t *)evch_dl_search(&chp->ch_subscr, compfunc, subid);
	/*
	 * Stop main event queue and subscriber queue if not already
	 * in stop mode.
	 */
	pmqstat = evch_evq_status(chp->ch_queue);
	if (pmqstat == 0)
		evch_evq_stop(chp->ch_queue);
	if (sdp != NULL) {
		psqstat = evch_evq_status(sdp->sd_queue);
		if (psqstat == 0)
			evch_evq_stop(sdp->sd_queue);
	}
	/*
	 * Create event queue to make a snapshot of all events in the
	 * channel.
	 */
	snp = kmem_alloc(sizeof (evchanq_t), KM_SLEEP);
	snp->sn_queue = evch_evq_create();
	evch_evq_stop(snp->sn_queue);
	/*
	 * Make a snapshot of the subscriber queue and the main event queue.
	 */
	if (sdp != NULL) {
		ev = NULL;
		while ((ev = evch_evq_evnext(sdp->sd_queue, ev)) != NULL) {
			(void) evch_evq_pub(snp->sn_queue, ev, EVCH_SLEEP);
		}
	}
	ev = NULL;
	while ((ev = evch_evq_evnext(chp->ch_queue, ev)) != NULL) {
		(void) evch_evq_pub(snp->sn_queue, ev, EVCH_SLEEP);
	}
	snp->sn_nxtev = NULL;
	/*
	 * Restart main and subscriber queue if previously stopped
	 */
	if (sdp != NULL && psqstat == 0)
		evch_evq_continue(sdp->sd_queue);
	if (pmqstat == 0)
		evch_evq_continue(chp->ch_queue);
	mutex_exit(&chp->ch_mutex);
	return (snp);
}

/*
 * Free all resources of the event queue snapshot. In case of panic
 * context snp must be NULL and no resources need to be free'ed.
 */
static void
evch_chrdevent_fini(evchanq_t *snp)
{
	if (snp != NULL) {
		evch_evq_destroy(snp->sn_queue);
		kmem_free(snp, sizeof (evchanq_t));
	}
}

/*
 * Get address of next event from an event channel.
 * This function might be called in a panic context. In that case
 * no resources will be allocated and no locks grabbed.
 * In normal operation context a snapshot of the event queues of the
 * specified event channel will be taken.
 */
static sysevent_impl_t *
evch_chgetnextev(evchanq_t *snp)
{
	if (panicstr != NULL) {
		if (evch_chan == NULL)
			return (NULL);
		if (evch_subq != NULL) {
			/*
			 * We have a subscriber queue. Traverse this queue
			 * first.
			 */
			if ((evch_curev = (sysevent_impl_t *)
			    evch_evq_evnext(evch_subq, evch_curev)) != NULL) {
				return (evch_curev);
			} else {
				/*
				 * All subscriber events traversed. evch_subq
				 * == NULL indicates to take the main event
				 * queue now.
				 */
				evch_subq = NULL;
			}
		}
		/*
		 * Traverse the main event queue.
		 */
		if ((evch_curev = (sysevent_impl_t *)
		    evch_evq_evnext(evch_chan->ch_queue, evch_curev)) ==
		    NULL) {
			evch_chan = NULL;
		}
		return (evch_curev);
	}
	ASSERT(snp != NULL);
	snp->sn_nxtev = (sysevent_impl_t *)evch_evq_evnext(snp->sn_queue,
	    snp->sn_nxtev);
	return (snp->sn_nxtev);
}

/*
 * The functions below build up the interface for the kernel to bind/unbind,
 * subscribe/unsubscribe and publish to event channels. It consists of the
 * following functions:
 *
 * sysevent_evc_bind	    - Bind to a channel. Create a channel if required
 * sysevent_evc_unbind	    - Unbind from a channel. Destroy ch. if last unbind
 * sysevent_evc_subscribe   - Subscribe to events from a channel
 * sysevent_evc_unsubscribe - Unsubscribe from an event class
 * sysevent_evc_publish	    - Publish an event to an event channel
 * sysevent_evc_control	    - Various control operation on event channel
 * sysevent_evc_setpropnvl  - Set channel property nvlist
 * sysevent_evc_getpropnvl  - Get channel property nvlist
 *
 * The function below are for evaluating a sysevent:
 *
 * sysevent_get_class_name  - Get pointer to event class string
 * sysevent_get_subclass_name - Get pointer to event subclass string
 * sysevent_get_seq	    - Get unique event sequence number
 * sysevent_get_time	    - Get hrestime of event publish
 * sysevent_get_size	    - Get size of event structure
 * sysevent_get_pub	    - Get publisher string
 * sysevent_get_attr_list   - Get copy of attribute list
 *
 * The following interfaces represent stability level project privat
 * and allow to save the events of an event channel even in a panic case.
 *
 * sysevent_evc_walk_init   - Take a snapshot of the events in a channel
 * sysevent_evc_walk_step   - Read next event from snapshot
 * sysevent_evc_walk_fini   - Free resources from event channel snapshot
 * sysevent_evc_event_attr  - Get event payload address and size
 */
/*
 * allocate sysevent structure with optional space for attributes
 */
static sysevent_impl_t *
sysevent_evc_alloc(const char *class, const char *subclass, const char *pub,
    size_t pub_sz, size_t atsz, uint32_t flag)
{
	int		payload_sz;
	int		class_sz, subclass_sz;
	int 		aligned_class_sz, aligned_subclass_sz, aligned_pub_sz;
	sysevent_impl_t	*ev;

	/*
	 * Calculate and reserve space for the class, subclass and
	 * publisher strings in the event buffer
	 */
	class_sz = strlen(class) + 1;
	subclass_sz = strlen(subclass) + 1;

	ASSERT((class_sz <= MAX_CLASS_LEN) && (subclass_sz <=
	    MAX_SUBCLASS_LEN) && (pub_sz <= MAX_PUB_LEN));

	/* String sizes must be 64-bit aligned in the event buffer */
	aligned_class_sz = SE_ALIGN(class_sz);
	aligned_subclass_sz = SE_ALIGN(subclass_sz);
	aligned_pub_sz = SE_ALIGN(pub_sz);

	/*
	 * Calculate payload size. Consider the space needed for alignment
	 * and subtract the size of the uint64_t placeholder variables of
	 * sysevent_impl_t.
	 */
	payload_sz = (aligned_class_sz - sizeof (uint64_t)) +
	    (aligned_subclass_sz - sizeof (uint64_t)) +
	    (aligned_pub_sz - sizeof (uint64_t)) - sizeof (uint64_t) +
	    atsz;

	/*
	 * Allocate event buffer plus additional payload overhead
	 */
	if ((ev = evch_evq_evzalloc(sizeof (sysevent_impl_t) +
	    payload_sz, flag)) == NULL) {
		return (NULL);
	}

	/* Initialize the event buffer data */
	SE_VERSION(ev) = SYS_EVENT_VERSION;
	bcopy(class, SE_CLASS_NAME(ev), class_sz);

	SE_SUBCLASS_OFF(ev) = SE_ALIGN(offsetof(sysevent_impl_t,
	    se_class_name)) + aligned_class_sz;
	bcopy(subclass, SE_SUBCLASS_NAME(ev), subclass_sz);

	SE_PUB_OFF(ev) = SE_SUBCLASS_OFF(ev) + aligned_subclass_sz;
	bcopy(pub, SE_PUB_NAME(ev), pub_sz);

	SE_ATTR_PTR(ev) = (uint64_t)0;
	SE_PAYLOAD_SZ(ev) = payload_sz;

	return (ev);
}

/*
 * Initialize event channel handling queues.
 */
void
sysevent_evc_init()
{
	evch_chinit();
}

/*
 * Second initialization step: create threads, if event channels are already
 * created
 */
void
sysevent_evc_thrinit()
{
	evch_chinitthr();
}

int
sysevent_evc_bind(const char *ch_name, evchan_t **scpp, uint32_t flags)
{
	ASSERT(ch_name != NULL && scpp != NULL);
	ASSERT((flags & ~EVCH_B_FLAGS) == 0);
	return (evch_chbind(ch_name, (evch_bind_t **)scpp, flags));
}

int
sysevent_evc_unbind(evchan_t *scp)
{
	evch_bind_t *bp = (evch_bind_t *)scp;

	ASSERT(scp != NULL);
	evch_chunsubscribe(bp, NULL, 0);
	evch_chunbind(bp);

	return (0);
}

int
sysevent_evc_subscribe(evchan_t *scp, const char *sid, const char *class,
    int (*callb)(sysevent_t *ev, void *cookie),
    void *cookie, uint32_t flags)
{
	ASSERT(scp != NULL && sid != NULL && class != NULL && callb != NULL);
	ASSERT(flags == 0);
	if (strlen(sid) > MAX_SUBID_LEN) {
		return (EINVAL);
	}
	if (strcmp(class, EC_ALL) == 0) {
		class = NULL;
	}
	return (evch_chsubscribe((evch_bind_t *)scp, EVCH_DELKERN, sid, class,
	    (void *)callb, cookie, 0, 0));
}

int
sysevent_evc_unsubscribe(evchan_t *scp, const char *sid)
{
	ASSERT(scp != NULL && sid != NULL);
	if (strcmp(sid, EVCH_ALLSUB) == 0) {
		sid = NULL;
	}
	evch_chunsubscribe((evch_bind_t *)scp, sid, 0);

	return (0);
}

/*
 * Publish kernel event. Returns 0 on success, error code else.
 * Optional attribute data is packed into the event structure.
 */
int
sysevent_evc_publish(evchan_t *scp, const char *class, const char *subclass,
    const char *vendor, const char *pubs, nvlist_t *attr, uint32_t flags)
{
	sysevent_impl_t	*evp;
	char		pub[MAX_PUB_LEN];
	int		pub_sz;		/* includes terminating 0 */
	int		km_flags;
	size_t		asz = 0;
	uint64_t	attr_offset;
	caddr_t		patt;
	int		err;

	ASSERT(scp != NULL && class != NULL && subclass != NULL &&
	    vendor != NULL && pubs != NULL);

	ASSERT((flags & ~(EVCH_SLEEP | EVCH_NOSLEEP | EVCH_TRYHARD |
	    EVCH_QWAIT)) == 0);

	km_flags = flags & (EVCH_SLEEP | EVCH_NOSLEEP | EVCH_TRYHARD);
	ASSERT(km_flags == EVCH_SLEEP || km_flags == EVCH_NOSLEEP ||
	    km_flags == EVCH_TRYHARD);

	pub_sz = snprintf(pub, MAX_PUB_LEN, "%s:kern:%s", vendor, pubs) + 1;
	if (pub_sz > MAX_PUB_LEN)
		return (EINVAL);

	if (attr != NULL) {
		if ((err = nvlist_size(attr, &asz, NV_ENCODE_NATIVE)) != 0) {
			return (err);
		}
	}
	evp = sysevent_evc_alloc(class, subclass, pub, pub_sz, asz, km_flags);
	if (evp == NULL) {
		return (ENOMEM);
	}
	if (attr != NULL) {
		/*
		 * Pack attributes into event buffer. Event buffer already
		 * has enough room for the packed nvlist.
		 */
		attr_offset = SE_ATTR_OFF(evp);
		patt = (caddr_t)evp + attr_offset;

		err = nvlist_pack(attr, &patt, &asz, NV_ENCODE_NATIVE,
		    km_flags & EVCH_SLEEP ? KM_SLEEP : KM_NOSLEEP);

		ASSERT(err != ENOMEM);

		if (err != 0) {
			return (EINVAL);
		}

		evp->seh_attr_off = attr_offset;
		SE_FLAG(evp) = SE_PACKED_BUF;
	}
	return (evch_chpublish((evch_bind_t *)scp, evp, flags));
}

int
sysevent_evc_control(evchan_t *scp, int cmd, ...)
{
	va_list		ap;
	evch_chan_t	*chp = ((evch_bind_t *)scp)->bd_channel;
	uint32_t	*chlenp;
	uint32_t	chlen;
	uint32_t	ochlen;
	int		rc = 0;

	if (scp == NULL) {
		return (EINVAL);
	}

	va_start(ap, cmd);
	mutex_enter(&chp->ch_mutex);
	switch (cmd) {
	case EVCH_GET_CHAN_LEN:
		chlenp = va_arg(ap, uint32_t *);
		*chlenp = chp->ch_maxev;
		break;
	case EVCH_SET_CHAN_LEN:
		chlen = va_arg(ap, uint32_t);
		ochlen = chp->ch_maxev;
		chp->ch_maxev = min(chlen, evch_events_max);
		if (ochlen < chp->ch_maxev) {
			cv_signal(&chp->ch_pubcv);
		}
		break;
	case EVCH_GET_CHAN_LEN_MAX:
		*va_arg(ap, uint32_t *) = evch_events_max;
		break;
	default:
		rc = EINVAL;
	}

	mutex_exit(&chp->ch_mutex);
	va_end(ap);
	return (rc);
}

int
sysevent_evc_setpropnvl(evchan_t *scp, nvlist_t *nvl)
{
	nvlist_t *nvlcp = nvl;

	if (nvl != NULL && nvlist_dup(nvl, &nvlcp, 0) != 0)
		return (ENOMEM);

	evch_chsetpropnvl((evch_bind_t *)scp, nvlcp);

	return (0);
}

int
sysevent_evc_getpropnvl(evchan_t *scp, nvlist_t **nvlp)
{
	return (evch_chgetpropnvl((evch_bind_t *)scp, nvlp, NULL));
}

/*
 * Project private interface to take a snapshot of all events of the
 * specified event channel. Argument subscr may be a subscriber id, the empty
 * string "", or NULL. The empty string indicates that no subscriber is
 * selected, for example if a previous subscriber died. sysevent_evc_walk_next()
 * will deliver events from the main event queue in this case. If subscr is
 * NULL, the subscriber with the EVCH_SUB_DUMP flag set (subd->sd_dump != 0)
 * will be selected.
 *
 * In panic case this function returns NULL. This is legal. The NULL has
 * to be delivered to sysevent_evc_walk_step() and sysevent_evc_walk_fini().
 */
evchanq_t *
sysevent_evc_walk_init(evchan_t *scp, char *subscr)
{
	if (panicstr != NULL && scp == NULL)
		return (NULL);
	ASSERT(scp != NULL);
	return (evch_chrdevent_init(((evch_bind_t *)scp)->bd_channel, subscr));
}

/*
 * Project private interface to read events from a previously taken
 * snapshot (with sysevent_evc_walk_init). In case of panic events
 * are retrieved directly from the channel data structures. No resources
 * are allocated and no mutexes are grabbed in panic context.
 */
sysevent_t *
sysevent_evc_walk_step(evchanq_t *evcq)
{
	return ((sysevent_t *)evch_chgetnextev(evcq));
}

/*
 * Project private interface to free a previously taken snapshot.
 */
void
sysevent_evc_walk_fini(evchanq_t *evcq)
{
	evch_chrdevent_fini(evcq);
}

/*
 * Get address and size of an event payload. Returns NULL when no
 * payload present.
 */
char *
sysevent_evc_event_attr(sysevent_t *ev, size_t *plsize)
{
	char	*attrp;
	size_t	aoff;
	size_t	asz;

	aoff = SE_ATTR_OFF(ev);
	attrp = (char *)ev + aoff;
	asz = *plsize = SE_SIZE(ev) - aoff;
	return (asz ? attrp : NULL);
}

/*
 * sysevent_get_class_name - Get class name string
 */
char *
sysevent_get_class_name(sysevent_t *ev)
{
	return (SE_CLASS_NAME(ev));
}

/*
 * sysevent_get_subclass_name - Get subclass name string
 */
char *
sysevent_get_subclass_name(sysevent_t *ev)
{
	return (SE_SUBCLASS_NAME(ev));
}

/*
 * sysevent_get_seq - Get event sequence id
 */
uint64_t
sysevent_get_seq(sysevent_t *ev)
{
	return (SE_SEQ(ev));
}

/*
 * sysevent_get_time - Get event timestamp
 */
void
sysevent_get_time(sysevent_t *ev, hrtime_t *etime)
{
	*etime = SE_TIME(ev);
}

/*
 * sysevent_get_size - Get event buffer size
 */
size_t
sysevent_get_size(sysevent_t *ev)
{
	return ((size_t)SE_SIZE(ev));
}

/*
 * sysevent_get_pub - Get publisher name string
 */
char *
sysevent_get_pub(sysevent_t *ev)
{
	return (SE_PUB_NAME(ev));
}

/*
 * sysevent_get_attr_list - stores address of a copy of the attribute list
 * associated with the given sysevent buffer. The list must be freed by the
 * caller.
 */
int
sysevent_get_attr_list(sysevent_t *ev, nvlist_t **nvlist)
{
	int		error;
	caddr_t		attr;
	size_t		attr_len;
	uint64_t	attr_offset;

	*nvlist = NULL;
	if (SE_FLAG(ev) != SE_PACKED_BUF) {
		return (EINVAL);
	}
	attr_offset = SE_ATTR_OFF(ev);
	if (SE_SIZE(ev) == attr_offset) {
		return (EINVAL);
	}

	/* unpack nvlist */
	attr = (caddr_t)ev + attr_offset;
	attr_len = SE_SIZE(ev) - attr_offset;
	if ((error = nvlist_unpack(attr, attr_len, nvlist, 0)) != 0) {
		error = error != ENOMEM ? EINVAL : error;
		return (error);
	}
	return (0);
}

/*
 * Functions called by the sysevent driver for general purpose event channels
 *
 * evch_usrchanopen	- Create/Bind to an event channel
 * evch_usrchanclose	- Unbind/Destroy event channel
 * evch_usrallocev	- Allocate event data structure
 * evch_usrfreeev	- Free event data structure
 * evch_usrpostevent	- Publish event
 * evch_usrsubscribe	- Subscribe (register callback function)
 * evch_usrunsubscribe	- Unsubscribe
 * evch_usrcontrol_set	- Set channel properties
 * evch_usrcontrol_get	- Get channel properties
 * evch_usrgetchnames	- Get list of channel names
 * evch_usrgetchdata	- Get data of an event channel
 * evch_usrsetpropnvl	- Set channel properties nvlist
 * evch_usrgetpropnvl	- Get channel properties nvlist
 */
evchan_t *
evch_usrchanopen(const char *name, uint32_t flags, int *err)
{
	evch_bind_t *bp = NULL;

	*err = evch_chbind(name, &bp, flags);
	return ((evchan_t *)bp);
}

/*
 * Unbind from the channel.
 */
void
evch_usrchanclose(evchan_t *cbp)
{
	evch_chunbind((evch_bind_t *)cbp);
}

/*
 * Allocates log_evch_eventq_t structure but returns the pointer of the embedded
 * sysevent_impl_t structure as the opaque sysevent_t * data type
 */
sysevent_impl_t *
evch_usrallocev(size_t evsize, uint32_t flags)
{
	return ((sysevent_impl_t *)evch_evq_evzalloc(evsize, flags));
}

/*
 * Free evch_eventq_t structure
 */
void
evch_usrfreeev(sysevent_impl_t *ev)
{
	evch_evq_evfree((void *)ev);
}

/*
 * Posts an event to the given channel. The event structure has to be
 * allocated by evch_usrallocev(). Returns zero on success and an error
 * code else. Attributes have to be packed and included in the event structure.
 *
 */
int
evch_usrpostevent(evchan_t *bp, sysevent_impl_t *ev, uint32_t flags)
{
	return (evch_chpublish((evch_bind_t *)bp, ev, flags));
}

/*
 * Subscribe function for user land subscriptions
 */
int
evch_usrsubscribe(evchan_t *bp, const char *sid, const char *class,
    int d, uint32_t flags)
{
	door_handle_t	dh = door_ki_lookup(d);
	int		rv;

	if (dh == NULL) {
		return (EINVAL);
	}
	if ((rv = evch_chsubscribe((evch_bind_t *)bp, EVCH_DELDOOR, sid, class,
	    (void *)dh, NULL, flags, curproc->p_pid)) != 0) {
		door_ki_rele(dh);
	}
	return (rv);
}

/*
 * Flag can be EVCH_SUB_KEEP or 0. EVCH_SUB_KEEP preserves persistent
 * subscribers
 */
void
evch_usrunsubscribe(evchan_t *bp, const char *subid, uint32_t flags)
{
	evch_chunsubscribe((evch_bind_t *)bp, subid, flags);
}

/*ARGSUSED*/
int
evch_usrcontrol_set(evchan_t *bp, int cmd, uint32_t value)
{
	evch_chan_t	*chp = ((evch_bind_t *)bp)->bd_channel;
	uid_t		uid = crgetuid(curthread->t_cred);
	int		rc = 0;

	mutex_enter(&chp->ch_mutex);
	switch (cmd) {
	case EVCH_SET_CHAN_LEN:
		if (uid && uid != chp->ch_uid) {
			rc = EACCES;
			break;
		}
		chp->ch_maxev = min(value, evch_events_max);
		break;
	default:
		rc = EINVAL;
	}
	mutex_exit(&chp->ch_mutex);
	return (rc);
}

/*ARGSUSED*/
int
evch_usrcontrol_get(evchan_t *bp, int cmd, uint32_t *value)
{
	evch_chan_t	*chp = ((evch_bind_t *)bp)->bd_channel;
	int		rc = 0;

	mutex_enter(&chp->ch_mutex);
	switch (cmd) {
	case EVCH_GET_CHAN_LEN:
		*value = chp->ch_maxev;
		break;
	case EVCH_GET_CHAN_LEN_MAX:
		*value = evch_events_max;
		break;
	default:
		rc = EINVAL;
	}
	mutex_exit(&chp->ch_mutex);
	return (rc);
}

int
evch_usrgetchnames(char *buf, size_t size)
{
	return (evch_chgetnames(buf, size));
}

int
evch_usrgetchdata(char *chname, void *buf, size_t size)
{
	return (evch_chgetchdata(chname, buf, size));
}

void
evch_usrsetpropnvl(evchan_t *bp, nvlist_t *nvl)
{
	evch_chsetpropnvl((evch_bind_t *)bp, nvl);
}

int
evch_usrgetpropnvl(evchan_t *bp, nvlist_t **nvlp, int64_t *genp)
{
	return (evch_chgetpropnvl((evch_bind_t *)bp, nvlp, genp));
}
