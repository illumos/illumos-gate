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
 * Copyright (c) 2000, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/stropts.h>
#include <sys/debug.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/vmem.h>
#include <sys/cmn_err.h>
#include <sys/callb.h>
#include <sys/sysevent.h>
#include <sys/sysevent_impl.h>
#include <sys/modctl.h>
#include <sys/sysmacros.h>
#include <sys/disp.h>
#include <sys/autoconf.h>
#include <sys/atomic.h>
#include <sys/sdt.h>

/* for doors */
#include <sys/pathname.h>
#include <sys/door.h>
#include <sys/kmem.h>
#include <sys/cpuvar.h>
#include <sys/fs/snode.h>

/*
 * log_sysevent.c - Provides the interfaces for kernel event publication
 *			to the sysevent event daemon (syseventd).
 */

/*
 * Debug stuff
 */
static int log_event_debug = 0;
#define	LOG_DEBUG(args)  if (log_event_debug) cmn_err args
#ifdef DEBUG
#define	LOG_DEBUG1(args)  if (log_event_debug > 1) cmn_err args
#else
#define	LOG_DEBUG1(args)
#endif

/*
 * Local static vars
 */
/* queue of event buffers sent to syseventd */
static log_eventq_t *log_eventq_sent = NULL;

/*
 * Count of event buffers in the queue
 */
int log_eventq_cnt = 0;

/* queue of event buffers awaiting delivery to syseventd */
static log_eventq_t *log_eventq_head = NULL;
static log_eventq_t *log_eventq_tail = NULL;
static uint64_t kernel_event_id = 0;
static int encoding = NV_ENCODE_NATIVE;

/* log event delivery flag */
#define	LOGEVENT_DELIVERY_OK	0	/* OK to deliver event buffers */
#define	LOGEVENT_DELIVERY_CONT	1	/* Continue to deliver event buffers */
#define	LOGEVENT_DELIVERY_HOLD	2	/* Hold delivering of event buffers */

/*
 * Tunable maximum event buffer queue size. Size depends on how many events
 * the queue must hold when syseventd is not available, for example during
 * system startup. Experience showed that more than 2000 events could be posted
 * due to correctable memory errors.
 */
int logevent_max_q_sz = 5000;


static int log_event_delivery = LOGEVENT_DELIVERY_HOLD;
static char logevent_door_upcall_filename[MAXPATHLEN];

static door_handle_t event_door = NULL;		/* Door for upcalls */
static kmutex_t event_door_mutex;		/* To protect event_door */

/*
 * async thread-related variables
 *
 * eventq_head_mutex - synchronizes access to the kernel event queue
 *
 * eventq_sent_mutex - synchronizes access to the queue of event sents to
 *			userlevel
 *
 * log_event_cv - condition variable signaled when an event has arrived or
 *			userlevel ready to process event buffers
 *
 * async_thread - asynchronous event delivery thread to userlevel daemon.
 *
 * sysevent_upcall_status - status of the door upcall link
 */
static kmutex_t eventq_head_mutex;
static kmutex_t eventq_sent_mutex;
static kcondvar_t log_event_cv;
static kthread_id_t async_thread = NULL;

static kmutex_t event_qfull_mutex;
static kcondvar_t event_qfull_cv;
static int event_qfull_blocked = 0;

static int sysevent_upcall_status = -1;
static kmutex_t registered_channel_mutex;

/*
 * Indicates the syseventd daemon has begun taking events
 */
int sysevent_daemon_init = 0;

/*
 * Back-off delay when door_ki_upcall returns EAGAIN.  Typically
 * caused by the server process doing a forkall().  Since all threads
 * but the thread actually doing the forkall() need to be quiesced,
 * the fork may take some time.  The min/max pause are in units
 * of clock ticks.
 */
#define	LOG_EVENT_MIN_PAUSE	8
#define	LOG_EVENT_MAX_PAUSE	128

static kmutex_t	event_pause_mutex;
static kcondvar_t event_pause_cv;
static int event_pause_state = 0;

/*ARGSUSED*/
static void
log_event_busy_timeout(void *arg)
{
	mutex_enter(&event_pause_mutex);
	event_pause_state = 0;
	cv_signal(&event_pause_cv);
	mutex_exit(&event_pause_mutex);
}

static void
log_event_pause(int nticks)
{
	timeout_id_t id;

	/*
	 * Only one use of log_event_pause at a time
	 */
	ASSERT(event_pause_state == 0);

	event_pause_state = 1;
	id = timeout(log_event_busy_timeout, NULL, nticks);
	if (id != 0) {
		mutex_enter(&event_pause_mutex);
		while (event_pause_state)
			cv_wait(&event_pause_cv, &event_pause_mutex);
		mutex_exit(&event_pause_mutex);
	}
	event_pause_state = 0;
}


/*
 * log_event_upcall - Perform the upcall to syseventd for event buffer delivery.
 * 			Check for rebinding errors
 * 			This buffer is reused to by the syseventd door_return
 *			to hold the result code
 */
static int
log_event_upcall(log_event_upcall_arg_t *arg)
{
	int error;
	size_t size;
	sysevent_t *ev;
	door_arg_t darg, save_arg;
	int retry;
	int neagain = 0;
	int neintr = 0;
	int nticks = LOG_EVENT_MIN_PAUSE;

	/* Initialize door args */
	ev = (sysevent_t *)&arg->buf;
	size = sizeof (log_event_upcall_arg_t) + SE_PAYLOAD_SZ(ev);

	darg.rbuf = (char *)arg;
	darg.data_ptr = (char *)arg;
	darg.rsize = size;
	darg.data_size = size;
	darg.desc_ptr = NULL;
	darg.desc_num = 0;

	LOG_DEBUG1((CE_CONT, "log_event_upcall: 0x%llx\n",
	    (longlong_t)SE_SEQ((sysevent_t *)&arg->buf)));

	save_arg = darg;
	for (retry = 0; ; retry++) {

		mutex_enter(&event_door_mutex);
		if (event_door == NULL) {
			mutex_exit(&event_door_mutex);

			return (EBADF);
		}

		if ((error = door_ki_upcall_limited(event_door, &darg, NULL,
		    SIZE_MAX, 0)) == 0) {
			mutex_exit(&event_door_mutex);
			break;
		}

		/*
		 * EBADF is handled outside the switch below because we need to
		 * hold event_door_mutex a bit longer
		 */
		if (error == EBADF) {
			/* Server died */
			door_ki_rele(event_door);
			event_door = NULL;

			mutex_exit(&event_door_mutex);
			return (error);
		}

		mutex_exit(&event_door_mutex);

		/*
		 * The EBADF case is already handled above with event_door_mutex
		 * held
		 */
		switch (error) {
		case EINTR:
			neintr++;
			log_event_pause(2);
			darg = save_arg;
			break;
		case EAGAIN:
			/* cannot deliver upcall - process may be forking */
			neagain++;
			log_event_pause(nticks);
			nticks <<= 1;
			if (nticks > LOG_EVENT_MAX_PAUSE)
				nticks = LOG_EVENT_MAX_PAUSE;
			darg = save_arg;
			break;
		default:
			cmn_err(CE_CONT,
			    "log_event_upcall: door_ki_upcall error %d\n",
			    error);
			return (error);
		}
	}

	if (neagain > 0 || neintr > 0) {
		LOG_DEBUG((CE_CONT, "upcall: eagain=%d eintr=%d nticks=%d\n",
		    neagain, neintr, nticks));
	}

	LOG_DEBUG1((CE_CONT, "log_event_upcall:\n\t"
	    "error=%d rptr1=%p rptr2=%p dptr2=%p ret1=%x ret2=%x\n",
	    error, (void *)arg, (void *)darg.rbuf,
	    (void *)darg.data_ptr,
	    *((int *)(darg.rbuf)), *((int *)(darg.data_ptr))));

	if (!error) {
		/*
		 * upcall was successfully executed. Check return code.
		 */
		error = *((int *)(darg.rbuf));
	}

	return (error);
}

/*
 * log_event_deliver - event delivery thread
 *			Deliver all events on the event queue to syseventd.
 *			If the daemon can not process events, stop event
 *			delivery and wait for an indication from the
 *			daemon to resume delivery.
 *
 *			Once all event buffers have been delivered, wait
 *			until there are more to deliver.
 */
static void
log_event_deliver()
{
	log_eventq_t *q;
	int upcall_err;
	callb_cpr_t cprinfo;

	CALLB_CPR_INIT(&cprinfo, &eventq_head_mutex, callb_generic_cpr,
	    "logevent");

	/*
	 * eventq_head_mutex is exited (released) when there are no more
	 * events to process from the eventq in cv_wait().
	 */
	mutex_enter(&eventq_head_mutex);

	for (;;) {
		LOG_DEBUG1((CE_CONT, "log_event_deliver: head = %p\n",
		    (void *)log_eventq_head));

		upcall_err = 0;
		q = log_eventq_head;

		while (q) {
			if (log_event_delivery == LOGEVENT_DELIVERY_HOLD) {
				upcall_err = EAGAIN;
				break;
			}

			log_event_delivery = LOGEVENT_DELIVERY_OK;

			/*
			 * Release event queue lock during upcall to
			 * syseventd
			 */
			mutex_exit(&eventq_head_mutex);
			if ((upcall_err = log_event_upcall(&q->arg)) != 0) {
				mutex_enter(&eventq_head_mutex);
				break;
			}

			/*
			 * We may be able to add entries to
			 * the queue now.
			 */
			if (event_qfull_blocked > 0 &&
			    log_eventq_cnt < logevent_max_q_sz) {
				mutex_enter(&event_qfull_mutex);
				if (event_qfull_blocked > 0) {
					cv_signal(&event_qfull_cv);
				}
				mutex_exit(&event_qfull_mutex);
			}

			mutex_enter(&eventq_head_mutex);

			/*
			 * Daemon restart can cause entries to be moved from
			 * the sent queue and put back on the event queue.
			 * If this has occurred, replay event queue
			 * processing from the new queue head.
			 */
			if (q != log_eventq_head) {
				q = log_eventq_head;
				LOG_DEBUG((CE_CONT, "log_event_deliver: "
				    "door upcall/daemon restart race\n"));
			} else {
				log_eventq_t *next;

				/*
				 * Move the event to the sent queue when a
				 * successful delivery has been made.
				 */
				mutex_enter(&eventq_sent_mutex);
				next = q->next;
				q->next = log_eventq_sent;
				log_eventq_sent = q;
				q = next;
				log_eventq_head = q;
				log_eventq_cnt--;
				if (q == NULL) {
					ASSERT(log_eventq_cnt == 0);
					log_eventq_tail = NULL;
				}
				mutex_exit(&eventq_sent_mutex);
			}
		}

		switch (upcall_err) {
		case 0:
			/*
			 * Success. The queue is empty.
			 */
			sysevent_upcall_status = 0;
			break;
		case EAGAIN:
			/*
			 * Delivery is on hold (but functional).
			 */
			sysevent_upcall_status = 0;
			/*
			 * If the user has already signaled for delivery
			 * resumption, continue.  Otherwise, we wait until
			 * we are signaled to continue.
			 */
			if (log_event_delivery == LOGEVENT_DELIVERY_CONT)
				continue;
			log_event_delivery = LOGEVENT_DELIVERY_HOLD;

			LOG_DEBUG1((CE_CONT, "log_event_deliver: EAGAIN\n"));
			break;
		default:
			LOG_DEBUG((CE_CONT, "log_event_deliver: "
			    "upcall err %d\n", upcall_err));
			sysevent_upcall_status = upcall_err;
			/*
			 * Signal everyone waiting that transport is down
			 */
			if (event_qfull_blocked > 0) {
				mutex_enter(&event_qfull_mutex);
				if (event_qfull_blocked > 0) {
					cv_broadcast(&event_qfull_cv);
				}
				mutex_exit(&event_qfull_mutex);
			}
			break;
		}

		CALLB_CPR_SAFE_BEGIN(&cprinfo);
		cv_wait(&log_event_cv, &eventq_head_mutex);
		CALLB_CPR_SAFE_END(&cprinfo, &eventq_head_mutex);
	}
	/* NOTREACHED */
}

/*
 * log_event_init - Allocate and initialize log_event data structures.
 */
void
log_event_init()
{
	mutex_init(&event_door_mutex, NULL, MUTEX_DEFAULT, NULL);

	mutex_init(&eventq_head_mutex, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&eventq_sent_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&log_event_cv, NULL, CV_DEFAULT, NULL);

	mutex_init(&event_qfull_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&event_qfull_cv, NULL, CV_DEFAULT, NULL);

	mutex_init(&event_pause_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&event_pause_cv, NULL, CV_DEFAULT, NULL);

	mutex_init(&registered_channel_mutex, NULL, MUTEX_DEFAULT, NULL);
	sysevent_evc_init();
}

/*
 * The following routines are used by kernel event publishers to
 * allocate, append and free event buffers
 */
/*
 * sysevent_alloc - Allocate new eventq struct.  This element contains
 *			an event buffer that will be used in a subsequent
 *			call to log_sysevent.
 */
sysevent_t *
sysevent_alloc(char *class, char *subclass, char *pub, int flag)
{
	int payload_sz;
	int class_sz, subclass_sz, pub_sz;
	int aligned_class_sz, aligned_subclass_sz, aligned_pub_sz;
	sysevent_t *ev;
	log_eventq_t *q;

	ASSERT(class != NULL);
	ASSERT(subclass != NULL);
	ASSERT(pub != NULL);

	/*
	 * Calculate and reserve space for the class, subclass and
	 * publisher strings in the event buffer
	 */
	class_sz = strlen(class) + 1;
	subclass_sz = strlen(subclass) + 1;
	pub_sz = strlen(pub) + 1;

	ASSERT((class_sz <= MAX_CLASS_LEN) && (subclass_sz
	    <= MAX_SUBCLASS_LEN) && (pub_sz <= MAX_PUB_LEN));

	/* String sizes must be 64-bit aligned in the event buffer */
	aligned_class_sz = SE_ALIGN(class_sz);
	aligned_subclass_sz = SE_ALIGN(subclass_sz);
	aligned_pub_sz = SE_ALIGN(pub_sz);

	payload_sz = (aligned_class_sz - sizeof (uint64_t)) +
	    (aligned_subclass_sz - sizeof (uint64_t)) +
	    (aligned_pub_sz - sizeof (uint64_t)) - sizeof (uint64_t);

	/*
	 * Allocate event buffer plus additional sysevent queue
	 * and payload overhead.
	 */
	q = kmem_zalloc(sizeof (log_eventq_t) + payload_sz, flag);
	if (q == NULL) {
		return (NULL);
	}

	/* Initialize the event buffer data */
	ev = (sysevent_t *)&q->arg.buf;
	SE_VERSION(ev) = SYS_EVENT_VERSION;
	bcopy(class, SE_CLASS_NAME(ev), class_sz);

	SE_SUBCLASS_OFF(ev) = SE_ALIGN(offsetof(sysevent_impl_t, se_class_name))
		+ aligned_class_sz;
	bcopy(subclass, SE_SUBCLASS_NAME(ev), subclass_sz);

	SE_PUB_OFF(ev) = SE_SUBCLASS_OFF(ev) + aligned_subclass_sz;
	bcopy(pub, SE_PUB_NAME(ev), pub_sz);

	SE_ATTR_PTR(ev) = UINT64_C(0);
	SE_PAYLOAD_SZ(ev) = payload_sz;

	return (ev);
}

/*
 * sysevent_free - Free event buffer and any attribute data.
 */
void
sysevent_free(sysevent_t *ev)
{
	log_eventq_t *q;
	nvlist_t *nvl;

	ASSERT(ev != NULL);
	q = (log_eventq_t *)((caddr_t)ev - offsetof(log_eventq_t, arg.buf));
	nvl = (nvlist_t *)(uintptr_t)SE_ATTR_PTR(ev);

	if (nvl != NULL) {
		size_t size = 0;
		(void) nvlist_size(nvl, &size, encoding);
		SE_PAYLOAD_SZ(ev) -= size;
		nvlist_free(nvl);
	}
	kmem_free(q, sizeof (log_eventq_t) + SE_PAYLOAD_SZ(ev));
}

/*
 * free_packed_event - Free packed event buffer
 */
static void
free_packed_event(sysevent_t *ev)
{
	log_eventq_t *q;

	ASSERT(ev != NULL);
	q = (log_eventq_t *)((caddr_t)ev - offsetof(log_eventq_t, arg.buf));

	kmem_free(q, sizeof (log_eventq_t) + SE_PAYLOAD_SZ(ev));
}

/*
 * sysevent_add_attr - Add new attribute element to an event attribute list
 *			If attribute list is NULL, start a new list.
 */
int
sysevent_add_attr(sysevent_attr_list_t **ev_attr_list, char *name,
	sysevent_value_t *se_value, int flag)
{
	int error;
	nvlist_t **nvlp = (nvlist_t **)ev_attr_list;

	if (nvlp == NULL || se_value == NULL) {
		return (SE_EINVAL);
	}

	/*
	 * attr_sz is composed of the value data size + the name data size +
	 * any header data.  64-bit aligned.
	 */
	if (strlen(name) >= MAX_ATTR_NAME) {
		return (SE_EINVAL);
	}

	/*
	 * Allocate nvlist
	 */
	if ((*nvlp == NULL) &&
	    (nvlist_alloc(nvlp, NV_UNIQUE_NAME_TYPE, flag) != 0))
		return (SE_ENOMEM);

	/* add the attribute */
	switch (se_value->value_type) {
	case SE_DATA_TYPE_BYTE:
		error = nvlist_add_byte(*ev_attr_list, name,
		    se_value->value.sv_byte);
		break;
	case SE_DATA_TYPE_INT16:
		error = nvlist_add_int16(*ev_attr_list, name,
		    se_value->value.sv_int16);
		break;
	case SE_DATA_TYPE_UINT16:
		error = nvlist_add_uint16(*ev_attr_list, name,
		    se_value->value.sv_uint16);
		break;
	case SE_DATA_TYPE_INT32:
		error = nvlist_add_int32(*ev_attr_list, name,
		    se_value->value.sv_int32);
		break;
	case SE_DATA_TYPE_UINT32:
		error = nvlist_add_uint32(*ev_attr_list, name,
		    se_value->value.sv_uint32);
		break;
	case SE_DATA_TYPE_INT64:
		error = nvlist_add_int64(*ev_attr_list, name,
		    se_value->value.sv_int64);
		break;
	case SE_DATA_TYPE_UINT64:
		error = nvlist_add_uint64(*ev_attr_list, name,
		    se_value->value.sv_uint64);
		break;
	case SE_DATA_TYPE_STRING:
		if (strlen((char *)se_value->value.sv_string) >= MAX_STRING_SZ)
			return (SE_EINVAL);
		error = nvlist_add_string(*ev_attr_list, name,
		    se_value->value.sv_string);
		break;
	case SE_DATA_TYPE_BYTES:
		if (se_value->value.sv_bytes.size > MAX_BYTE_ARRAY)
			return (SE_EINVAL);
		error = nvlist_add_byte_array(*ev_attr_list, name,
		    se_value->value.sv_bytes.data,
		    se_value->value.sv_bytes.size);
		break;
	case SE_DATA_TYPE_TIME:
		error = nvlist_add_hrtime(*ev_attr_list, name,
		    se_value->value.sv_time);
		break;
	default:
		return (SE_EINVAL);
	}

	return (error ? SE_ENOMEM : 0);
}

/*
 * sysevent_free_attr - Free an attribute list not associated with an
 *			event buffer.
 */
void
sysevent_free_attr(sysevent_attr_list_t *ev_attr_list)
{
	nvlist_free((nvlist_t *)ev_attr_list);
}

/*
 * sysevent_attach_attributes - Attach an attribute list to an event buffer.
 *
 *	This data will be re-packed into contiguous memory when the event
 *	buffer is posted to log_sysevent.
 */
int
sysevent_attach_attributes(sysevent_t *ev, sysevent_attr_list_t *ev_attr_list)
{
	size_t size = 0;

	if (SE_ATTR_PTR(ev) != UINT64_C(0)) {
		return (SE_EINVAL);
	}

	SE_ATTR_PTR(ev) = (uintptr_t)ev_attr_list;
	(void) nvlist_size((nvlist_t *)ev_attr_list, &size, encoding);
	SE_PAYLOAD_SZ(ev) += size;
	SE_FLAG(ev) = 0;

	return (0);
}

/*
 * sysevent_detach_attributes - Detach but don't free attribute list from the
 *				event buffer.
 */
void
sysevent_detach_attributes(sysevent_t *ev)
{
	size_t size = 0;
	nvlist_t *nvl;

	if ((nvl = (nvlist_t *)(uintptr_t)SE_ATTR_PTR(ev)) == NULL) {
		return;
	}

	SE_ATTR_PTR(ev) = UINT64_C(0);
	(void) nvlist_size(nvl, &size, encoding);
	SE_PAYLOAD_SZ(ev) -= size;
	ASSERT(SE_PAYLOAD_SZ(ev) >= 0);
}

/*
 * sysevent_attr_name - Get name of attribute
 */
char *
sysevent_attr_name(sysevent_attr_t *attr)
{
	if (attr == NULL) {
		return (NULL);
	}

	return (nvpair_name(attr));
}

/*
 * sysevent_attr_type - Get type of attribute
 */
int
sysevent_attr_type(sysevent_attr_t *attr)
{
	/*
	 * The SE_DATA_TYPE_* are typedef'ed to be the
	 * same value as DATA_TYPE_*
	 */
	return (nvpair_type((nvpair_t *)attr));
}

/*
 * Repack event buffer into contiguous memory
 */
static sysevent_t *
se_repack(sysevent_t *ev, int flag)
{
	size_t copy_len;
	caddr_t attr;
	size_t size;
	uint64_t attr_offset;
	sysevent_t *copy;
	log_eventq_t *qcopy;
	sysevent_attr_list_t *nvl;

	copy_len = sizeof (log_eventq_t) + SE_PAYLOAD_SZ(ev);
	qcopy = kmem_zalloc(copy_len, flag);
	if (qcopy == NULL) {
		return (NULL);
	}
	copy = (sysevent_t *)&qcopy->arg.buf;

	/*
	 * Copy event header, class, subclass and publisher names
	 * Set the attribute offset (in number of bytes) to contiguous
	 * memory after the header.
	 */

	attr_offset = SE_ATTR_OFF(ev);

	ASSERT((caddr_t)copy + attr_offset <= (caddr_t)copy + copy_len);

	bcopy(ev, copy, attr_offset);

	/* Check if attribute list exists */
	if ((nvl = (nvlist_t *)(uintptr_t)SE_ATTR_PTR(ev)) == NULL) {
		return (copy);
	}

	/*
	 * Copy attribute data to contiguous memory
	 */
	attr = (char *)copy + attr_offset;
	(void) nvlist_size(nvl, &size, encoding);
	if (nvlist_pack(nvl, &attr, &size, encoding, flag) != 0) {
		kmem_free(qcopy, copy_len);
		return (NULL);
	}
	SE_ATTR_PTR(copy) = UINT64_C(0);
	SE_FLAG(copy) = SE_PACKED_BUF;

	return (copy);
}

/*
 * The sysevent registration provides a persistent and reliable database
 * for channel information for sysevent channel publishers and
 * subscribers.
 *
 * A channel is created and maintained by the kernel upon the first
 * SE_OPEN_REGISTRATION operation to log_sysevent_register().  Channel
 * event subscription information is updated as publishers or subscribers
 * perform subsequent operations (SE_BIND_REGISTRATION, SE_REGISTER,
 * SE_UNREGISTER and SE_UNBIND_REGISTRATION).
 *
 * For consistency, id's are assigned for every publisher or subscriber
 * bound to a particular channel.  The id's are used to constrain resources
 * and perform subscription lookup.
 *
 * Associated with each channel is a hashed list of the current subscriptions
 * based upon event class and subclasses.  A subscription contains a class name,
 * list of possible subclasses and an array of subscriber ids.  Subscriptions
 * are updated for every SE_REGISTER or SE_UNREGISTER operation.
 *
 * Channels are closed once the last subscriber or publisher performs a
 * SE_CLOSE_REGISTRATION operation.  All resources associated with the named
 * channel are freed upon last close.
 *
 * Locking:
 *	Every operation to log_sysevent() is protected by a single lock,
 *	registered_channel_mutex.  It is expected that the granularity of
 *	a single lock is sufficient given the frequency that updates will
 *	occur.
 *
 *	If this locking strategy proves to be too contentious, a per-hash
 *	or per-channel locking strategy may be implemented.
 */


#define	CHANN_HASH(channel_name)	(hash_func(channel_name) \
					% CHAN_HASH_SZ)

sysevent_channel_descriptor_t *registered_channels[CHAN_HASH_SZ];
static int channel_cnt;
static void remove_all_class(sysevent_channel_descriptor_t *chan,
	uint32_t sub_id);

static uint32_t
hash_func(const char *s)
{
	uint32_t result = 0;
	uint_t g;

	while (*s != '\0') {
		result <<= 4;
		result += (uint32_t)*s++;
		g = result & 0xf0000000;
		if (g != 0) {
			result ^= g >> 24;
			result ^= g;
		}
	}

	return (result);
}

static sysevent_channel_descriptor_t *
get_channel(char *channel_name)
{
	int hash_index;
	sysevent_channel_descriptor_t *chan_list;

	if (channel_name == NULL)
		return (NULL);

	/* Find channel descriptor */
	hash_index = CHANN_HASH(channel_name);
	chan_list = registered_channels[hash_index];
	while (chan_list != NULL) {
		if (strcmp(chan_list->scd_channel_name, channel_name) == 0) {
			break;
		} else {
			chan_list = chan_list->scd_next;
		}
	}

	return (chan_list);
}

static class_lst_t *
create_channel_registration(sysevent_channel_descriptor_t *chan,
    char *event_class, int index)
{
	size_t class_len;
	class_lst_t *c_list;

	class_len = strlen(event_class) + 1;
	c_list = kmem_zalloc(sizeof (class_lst_t), KM_SLEEP);
	c_list->cl_name = kmem_zalloc(class_len, KM_SLEEP);
	bcopy(event_class, c_list->cl_name, class_len);

	c_list->cl_subclass_list =
	    kmem_zalloc(sizeof (subclass_lst_t), KM_SLEEP);
	c_list->cl_subclass_list->sl_name =
	    kmem_zalloc(sizeof (EC_SUB_ALL), KM_SLEEP);
	bcopy(EC_SUB_ALL, c_list->cl_subclass_list->sl_name,
	    sizeof (EC_SUB_ALL));

	c_list->cl_next = chan->scd_class_list_tbl[index];
	chan->scd_class_list_tbl[index] = c_list;

	return (c_list);
}

static void
free_channel_registration(sysevent_channel_descriptor_t *chan)
{
	int i;
	class_lst_t *clist, *next_clist;
	subclass_lst_t *sclist, *next_sc;

	for (i = 0; i <= CLASS_HASH_SZ; ++i) {

		clist = chan->scd_class_list_tbl[i];
		while (clist != NULL) {
			sclist = clist->cl_subclass_list;
			while (sclist != NULL) {
				kmem_free(sclist->sl_name,
				    strlen(sclist->sl_name) + 1);
				next_sc = sclist->sl_next;
				kmem_free(sclist, sizeof (subclass_lst_t));
				sclist = next_sc;
			}
			kmem_free(clist->cl_name,
			    strlen(clist->cl_name) + 1);
			next_clist = clist->cl_next;
			kmem_free(clist, sizeof (class_lst_t));
			clist = next_clist;
		}
	}
	chan->scd_class_list_tbl[0] = NULL;
}

static int
open_channel(char *channel_name)
{
	int hash_index;
	sysevent_channel_descriptor_t *chan, *chan_list;


	if (channel_cnt > MAX_CHAN) {
		return (-1);
	}

	/* Find channel descriptor */
	hash_index = CHANN_HASH(channel_name);
	chan_list = registered_channels[hash_index];
	while (chan_list != NULL) {
		if (strcmp(chan_list->scd_channel_name, channel_name) == 0) {
			chan_list->scd_ref_cnt++;
			kmem_free(channel_name, strlen(channel_name) + 1);
			return (0);
		} else {
			chan_list = chan_list->scd_next;
		}
	}


	/* New channel descriptor */
	chan = kmem_zalloc(sizeof (sysevent_channel_descriptor_t), KM_SLEEP);
	chan->scd_channel_name = channel_name;

	/*
	 * Create subscriber ids in the range [1, MAX_SUBSCRIBERS).
	 * Subscriber id 0 is never allocated, but is used as a reserved id
	 * by libsysevent
	 */
	if ((chan->scd_subscriber_cache = vmem_create(channel_name, (void *)1,
	    MAX_SUBSCRIBERS + 1, 1, NULL, NULL, NULL, 0,
	    VM_NOSLEEP | VMC_IDENTIFIER)) == NULL) {
		kmem_free(chan, sizeof (sysevent_channel_descriptor_t));
		return (-1);
	}
	if ((chan->scd_publisher_cache = vmem_create(channel_name, (void *)1,
	    MAX_PUBLISHERS + 1, 1, NULL, NULL, NULL, 0,
	    VM_NOSLEEP | VMC_IDENTIFIER)) == NULL) {
		vmem_destroy(chan->scd_subscriber_cache);
		kmem_free(chan, sizeof (sysevent_channel_descriptor_t));
		return (-1);
	}

	chan->scd_ref_cnt = 1;

	(void) create_channel_registration(chan, EC_ALL, 0);

	if (registered_channels[hash_index] != NULL)
		chan->scd_next = registered_channels[hash_index];

	registered_channels[hash_index] = chan;

	++channel_cnt;

	return (0);
}

static void
close_channel(char *channel_name)
{
	int hash_index;
	sysevent_channel_descriptor_t *chan, *prev_chan;

	/* Find channel descriptor */
	hash_index = CHANN_HASH(channel_name);
	prev_chan = chan = registered_channels[hash_index];

	while (chan != NULL) {
		if (strcmp(chan->scd_channel_name, channel_name) == 0) {
			break;
		} else {
			prev_chan = chan;
			chan = chan->scd_next;
		}
	}

	if (chan == NULL)
		return;

	chan->scd_ref_cnt--;
	if (chan->scd_ref_cnt > 0)
		return;

	free_channel_registration(chan);
	vmem_destroy(chan->scd_subscriber_cache);
	vmem_destroy(chan->scd_publisher_cache);
	kmem_free(chan->scd_channel_name,
	    strlen(chan->scd_channel_name) + 1);
	if (registered_channels[hash_index] == chan)
		registered_channels[hash_index] = chan->scd_next;
	else
		prev_chan->scd_next = chan->scd_next;
	kmem_free(chan, sizeof (sysevent_channel_descriptor_t));
	--channel_cnt;
}

static id_t
bind_common(sysevent_channel_descriptor_t *chan, int type)
{
	id_t id;

	if (type == SUBSCRIBER) {
		id = (id_t)(uintptr_t)vmem_alloc(chan->scd_subscriber_cache, 1,
		    VM_NOSLEEP | VM_NEXTFIT);
		if (id <= 0 || id > MAX_SUBSCRIBERS)
			return (0);
		chan->scd_subscriber_ids[id] = 1;
	} else {
		id = (id_t)(uintptr_t)vmem_alloc(chan->scd_publisher_cache, 1,
		    VM_NOSLEEP | VM_NEXTFIT);
		if (id <= 0 || id > MAX_PUBLISHERS)
			return (0);
		chan->scd_publisher_ids[id] = 1;
	}

	return (id);
}

static int
unbind_common(sysevent_channel_descriptor_t *chan, int type, id_t id)
{
	if (type == SUBSCRIBER) {
		if (id <= 0 || id > MAX_SUBSCRIBERS)
			return (0);
		if (chan->scd_subscriber_ids[id] == 0)
			return (0);
		(void) remove_all_class(chan, id);
		chan->scd_subscriber_ids[id] = 0;
		vmem_free(chan->scd_subscriber_cache, (void *)(uintptr_t)id, 1);
	} else {
		if (id <= 0 || id > MAX_PUBLISHERS)
			return (0);
		if (chan->scd_publisher_ids[id] == 0)
			return (0);
		chan->scd_publisher_ids[id] = 0;
		vmem_free(chan->scd_publisher_cache, (void *)(uintptr_t)id, 1);
	}

	return (1);
}

static void
release_id(sysevent_channel_descriptor_t *chan, int type, id_t id)
{
	if (unbind_common(chan, type, id))
		close_channel(chan->scd_channel_name);
}

static subclass_lst_t *
find_subclass(class_lst_t *c_list, char *subclass)
{
	subclass_lst_t *sc_list;

	if (c_list == NULL)
		return (NULL);

	sc_list = c_list->cl_subclass_list;

	while (sc_list != NULL) {
		if (strcmp(sc_list->sl_name, subclass) == 0) {
			return (sc_list);
		}
		sc_list = sc_list->sl_next;
	}

	return (NULL);
}

static void
insert_subclass(class_lst_t *c_list, char **subclass_names,
	int subclass_num, uint32_t sub_id)
{
	int i, subclass_sz;
	subclass_lst_t *sc_list;

	for (i = 0; i < subclass_num; ++i) {
		if ((sc_list = find_subclass(c_list, subclass_names[i]))
		    != NULL) {
			sc_list->sl_num[sub_id] = 1;
		} else {

			sc_list = kmem_zalloc(sizeof (subclass_lst_t),
			    KM_SLEEP);
			subclass_sz = strlen(subclass_names[i]) + 1;
			sc_list->sl_name = kmem_zalloc(subclass_sz, KM_SLEEP);
			bcopy(subclass_names[i], sc_list->sl_name,
			    subclass_sz);

			sc_list->sl_num[sub_id] = 1;

			sc_list->sl_next = c_list->cl_subclass_list;
			c_list->cl_subclass_list = sc_list;
		}
	}
}

static class_lst_t *
find_class(sysevent_channel_descriptor_t *chan, char *class_name)
{
	class_lst_t *c_list;

	c_list = chan->scd_class_list_tbl[CLASS_HASH(class_name)];
	while (c_list != NULL) {
		if (strcmp(class_name, c_list->cl_name) == 0)
			break;
		c_list = c_list->cl_next;
	}

	return (c_list);
}

static void
remove_all_class(sysevent_channel_descriptor_t *chan, uint32_t sub_id)
{
	int i;
	class_lst_t *c_list;
	subclass_lst_t *sc_list;

	for (i = 0; i <= CLASS_HASH_SZ; ++i) {

		c_list = chan->scd_class_list_tbl[i];
		while (c_list != NULL) {
			sc_list = c_list->cl_subclass_list;
			while (sc_list != NULL) {
				sc_list->sl_num[sub_id] = 0;
				sc_list = sc_list->sl_next;
			}
			c_list = c_list->cl_next;
		}
	}
}

static void
remove_class(sysevent_channel_descriptor_t *chan, uint32_t sub_id,
	char *class_name)
{
	class_lst_t *c_list;
	subclass_lst_t *sc_list;

	if (strcmp(class_name, EC_ALL) == 0) {
		remove_all_class(chan, sub_id);
		return;
	}

	if ((c_list = find_class(chan, class_name)) == NULL) {
		return;
	}

	sc_list = c_list->cl_subclass_list;
	while (sc_list != NULL) {
		sc_list->sl_num[sub_id] = 0;
		sc_list = sc_list->sl_next;
	}
}

static int
insert_class(sysevent_channel_descriptor_t *chan, char *event_class,
	char **event_subclass_lst, int subclass_num, uint32_t sub_id)
{
	class_lst_t *c_list;

	if (strcmp(event_class, EC_ALL) == 0) {
		insert_subclass(chan->scd_class_list_tbl[0],
		    event_subclass_lst, 1, sub_id);
		return (0);
	}

	if (strlen(event_class) + 1 > MAX_CLASS_LEN)
		return (-1);

	/* New class, add to the registration cache */
	if ((c_list = find_class(chan, event_class)) == NULL) {
		c_list = create_channel_registration(chan, event_class,
		    CLASS_HASH(event_class));
	}

	/* Update the subclass list */
	insert_subclass(c_list, event_subclass_lst, subclass_num, sub_id);

	return (0);
}

static int
add_registration(sysevent_channel_descriptor_t *chan, uint32_t sub_id,
	char *nvlbuf, size_t nvlsize)
{
	uint_t num_elem;
	char *event_class;
	char **event_list;
	nvlist_t *nvl;
	nvpair_t *nvpair = NULL;

	if (nvlist_unpack(nvlbuf, nvlsize, &nvl, KM_SLEEP) != 0)
		return (-1);

	if ((nvpair = nvlist_next_nvpair(nvl, nvpair)) == NULL) {
		nvlist_free(nvl);
		return (-1);
	}

	if ((event_class = nvpair_name(nvpair)) == NULL) {
		nvlist_free(nvl);
		return (-1);
	}
	if (nvpair_value_string_array(nvpair, &event_list,
	    &num_elem) != 0) {
		nvlist_free(nvl);
		return (-1);
	}

	if (insert_class(chan, event_class, event_list, num_elem, sub_id) < 0) {
		nvlist_free(nvl);
		return (-1);
	}

	nvlist_free(nvl);

	return (0);
}

/*
 * get_registration - Return the requested class hash chain
 */
static int
get_registration(sysevent_channel_descriptor_t *chan, char *databuf,
	uint32_t *bufsz, uint32_t class_index)
{
	int num_classes = 0;
	char *nvlbuf = NULL;
	size_t nvlsize;
	nvlist_t *nvl;
	class_lst_t *clist;
	subclass_lst_t *sc_list;

	if (class_index < 0 || class_index > CLASS_HASH_SZ)
		return (EINVAL);

	if ((clist = chan->scd_class_list_tbl[class_index]) == NULL) {
		return (ENOENT);
	}

	if (nvlist_alloc(&nvl, 0, 0) != 0) {
		return (EFAULT);
	}

	while (clist != NULL) {
		if (nvlist_add_string(nvl, CLASS_NAME, clist->cl_name)
		    != 0) {
			nvlist_free(nvl);
			return (EFAULT);
		}

		sc_list = clist->cl_subclass_list;
		while (sc_list != NULL) {
			if (nvlist_add_byte_array(nvl, sc_list->sl_name,
			    sc_list->sl_num, MAX_SUBSCRIBERS) != 0) {
				nvlist_free(nvl);
				return (EFAULT);
			}
			sc_list = sc_list->sl_next;
		}
		num_classes++;
		clist = clist->cl_next;
	}

	if (num_classes == 0) {
		nvlist_free(nvl);
		return (ENOENT);
	}

	if (nvlist_pack(nvl, &nvlbuf, &nvlsize, NV_ENCODE_NATIVE,
	    KM_SLEEP)
	    != 0) {
		nvlist_free(nvl);
		return (EFAULT);
	}

	nvlist_free(nvl);

	if (nvlsize > *bufsz) {
		kmem_free(nvlbuf, nvlsize);
		*bufsz = nvlsize;
		return (EAGAIN);
	}

	bcopy(nvlbuf, databuf, nvlsize);
	kmem_free(nvlbuf, nvlsize);

	return (0);
}

/*
 * log_sysevent_register - Register event subscriber for a particular
 *		event channel.
 */
int
log_sysevent_register(char *channel_name, char *udatabuf, se_pubsub_t *udata)
{
	int error = 0;
	char *kchannel, *databuf = NULL;
	size_t bufsz;
	se_pubsub_t kdata;
	sysevent_channel_descriptor_t *chan;

	if (copyin(udata, &kdata, sizeof (se_pubsub_t)) == -1) {
		return (EFAULT);
	}
	if (kdata.ps_channel_name_len == 0) {
		return (EINVAL);
	}
	kchannel = kmem_alloc(kdata.ps_channel_name_len, KM_SLEEP);
	if (copyin(channel_name, kchannel, kdata.ps_channel_name_len) == -1) {
		kmem_free(kchannel, kdata.ps_channel_name_len);
		return (EFAULT);
	}
	bufsz = kdata.ps_buflen;
	if (bufsz > 0) {
		databuf = kmem_alloc(bufsz, KM_SLEEP);
		if (copyin(udatabuf, databuf, bufsz) == -1) {
			kmem_free(kchannel, kdata.ps_channel_name_len);
			kmem_free(databuf, bufsz);
			return (EFAULT);
		}
	}

	mutex_enter(&registered_channel_mutex);
	if (kdata.ps_op != SE_OPEN_REGISTRATION &&
	    kdata.ps_op != SE_CLOSE_REGISTRATION) {
		chan = get_channel(kchannel);
		if (chan == NULL) {
			mutex_exit(&registered_channel_mutex);
			kmem_free(kchannel, kdata.ps_channel_name_len);
			if (bufsz > 0)
				kmem_free(databuf, bufsz);
			return (ENOENT);
		}
	}

	switch (kdata.ps_op) {
	case SE_OPEN_REGISTRATION:
		if (open_channel(kchannel) != 0) {
			error = ENOMEM;
			if (bufsz > 0)
				kmem_free(databuf, bufsz);
			kmem_free(kchannel, kdata.ps_channel_name_len);
		}

		mutex_exit(&registered_channel_mutex);
		return (error);
	case SE_CLOSE_REGISTRATION:
		close_channel(kchannel);
		break;
	case SE_BIND_REGISTRATION:
		if ((kdata.ps_id = bind_common(chan, kdata.ps_type)) <= 0)
			error = EBUSY;
		break;
	case SE_UNBIND_REGISTRATION:
		(void) unbind_common(chan, kdata.ps_type, (id_t)kdata.ps_id);
		break;
	case SE_REGISTER:
		if (bufsz == 0) {
			error = EINVAL;
			break;
		}
		if (add_registration(chan, kdata.ps_id, databuf, bufsz) == -1)
			error = EINVAL;
		break;
	case SE_UNREGISTER:
		if (bufsz == 0) {
			error = EINVAL;
			break;
		}
		remove_class(chan, kdata.ps_id, databuf);
		break;
	case SE_CLEANUP:
		/* Cleanup the indicated subscriber or publisher */
		release_id(chan, kdata.ps_type, kdata.ps_id);
		break;
	case SE_GET_REGISTRATION:
		error = get_registration(chan, databuf,
		    &kdata.ps_buflen, kdata.ps_id);
		break;
	default:
		error = ENOTSUP;
	}

	mutex_exit(&registered_channel_mutex);

	kmem_free(kchannel, kdata.ps_channel_name_len);

	if (bufsz > 0) {
		if (copyout(databuf, udatabuf, bufsz) == -1)
			error = EFAULT;
		kmem_free(databuf, bufsz);
	}

	if (copyout(&kdata, udata, sizeof (se_pubsub_t)) == -1)
		return (EFAULT);

	return (error);
}

/*
 * log_sysevent_copyout_data - Copyout event data to userland.
 *			This is called from modctl(MODEVENTS, MODEVENTS_GETDATA)
 *			The buffer size is always sufficient.
 */
int
log_sysevent_copyout_data(sysevent_id_t *eid, size_t ubuflen, caddr_t ubuf)
{
	int error = ENOENT;
	log_eventq_t *q;
	sysevent_t *ev;
	sysevent_id_t eid_copy;

	/*
	 * Copy eid
	 */
	if (copyin(eid, &eid_copy, sizeof (sysevent_id_t)) == -1) {
		return (EFAULT);
	}

	mutex_enter(&eventq_sent_mutex);
	q = log_eventq_sent;

	/*
	 * Search for event buffer on the sent queue with matching
	 * event identifier
	 */
	while (q) {
		ev = (sysevent_t *)&q->arg.buf;

		if (SE_TIME(ev) != eid_copy.eid_ts ||
		    SE_SEQ(ev) != eid_copy.eid_seq) {
			q = q->next;
			continue;
		}

		if (ubuflen < SE_SIZE(ev)) {
			error = EFAULT;
			break;
		}
		if (copyout(ev, ubuf, SE_SIZE(ev)) != 0) {
			error = EFAULT;
			LOG_DEBUG((CE_NOTE, "Unable to retrieve system event "
			    "0x%" PRIx64 " from queue: EFAULT\n",
			    eid->eid_seq));
		} else {
			error = 0;
		}
		break;
	}

	mutex_exit(&eventq_sent_mutex);

	return (error);
}

/*
 * log_sysevent_free_data - Free kernel copy of the event buffer identified
 *			by eid (must have already been sent).  Called from
 *			modctl(MODEVENTS, MODEVENTS_FREEDATA).
 */
int
log_sysevent_free_data(sysevent_id_t *eid)
{
	int error = ENOENT;
	sysevent_t *ev;
	log_eventq_t *q, *prev = NULL;
	sysevent_id_t eid_copy;

	/*
	 * Copy eid
	 */
	if (copyin(eid, &eid_copy, sizeof (sysevent_id_t)) == -1) {
		return (EFAULT);
	}

	mutex_enter(&eventq_sent_mutex);
	q = log_eventq_sent;

	/*
	 * Look for the event to be freed on the sent queue.  Due to delayed
	 * processing of the event, it may not be on the sent queue yet.
	 * It is up to the user to retry the free operation to ensure that the
	 * event is properly freed.
	 */
	while (q) {
		ev = (sysevent_t *)&q->arg.buf;

		if (SE_TIME(ev) != eid_copy.eid_ts ||
		    SE_SEQ(ev) != eid_copy.eid_seq) {
			prev = q;
			q = q->next;
			continue;
		}
		/*
		 * Take it out of log_eventq_sent and free it
		 */
		if (prev) {
			prev->next = q->next;
		} else {
			log_eventq_sent = q->next;
		}
		free_packed_event(ev);
		error = 0;
		break;
	}

	mutex_exit(&eventq_sent_mutex);

	return (error);
}

/*
 * log_sysevent_flushq - Begin or resume event buffer delivery.  If neccessary,
 *			create log_event_deliver thread or wake it up
 */
/*ARGSUSED*/
void
log_sysevent_flushq(int cmd, uint_t flag)
{
	mutex_enter(&eventq_head_mutex);

	/*
	 * Start the event delivery thread
	 * Mark the upcall status as active since we should
	 * now be able to begin emptying the queue normally.
	 */
	if (!async_thread) {
		sysevent_upcall_status = 0;
		sysevent_daemon_init = 1;
		setup_ddi_poststartup();
		async_thread = thread_create(NULL, 0, log_event_deliver,
		    NULL, 0, &p0, TS_RUN, minclsyspri);
	}

	log_event_delivery = LOGEVENT_DELIVERY_CONT;
	cv_signal(&log_event_cv);
	mutex_exit(&eventq_head_mutex);
}

/*
 * log_sysevent_filename - Called by syseventd via
 *			modctl(MODEVENTS, MODEVENTS_SET_DOOR_UPCALL_FILENAME)
 *			to subsequently bind the event_door.
 *
 *			This routine is called everytime syseventd (re)starts
 *			and must therefore replay any events buffers that have
 *			been sent but not freed.
 *
 *			Event buffer delivery begins after a call to
 *			log_sysevent_flushq().
 */
int
log_sysevent_filename(char *file)
{
	mutex_enter(&event_door_mutex);

	(void) strlcpy(logevent_door_upcall_filename, file,
	    sizeof (logevent_door_upcall_filename));

	/* Unbind old event door */
	if (event_door != NULL)
		door_ki_rele(event_door);
	/* Establish door connection with user event daemon (syseventd) */
	if (door_ki_open(logevent_door_upcall_filename, &event_door) != 0)
		event_door = NULL;

	mutex_exit(&event_door_mutex);

	/*
	 * We are called when syseventd restarts. Move all sent, but
	 * not committed events from log_eventq_sent to log_eventq_head.
	 * Do it in proper order to maintain increasing event id.
	 */
	mutex_enter(&eventq_head_mutex);

	mutex_enter(&eventq_sent_mutex);
	while (log_eventq_sent) {
		log_eventq_t *tmp = log_eventq_sent->next;
		log_eventq_sent->next = log_eventq_head;
		if (log_eventq_head == NULL) {
			ASSERT(log_eventq_cnt == 0);
			log_eventq_tail = log_eventq_sent;
			log_eventq_tail->next = NULL;
		} else if (log_eventq_head == log_eventq_tail) {
			ASSERT(log_eventq_cnt == 1);
			ASSERT(log_eventq_head->next == NULL);
			ASSERT(log_eventq_tail->next == NULL);
		}
		log_eventq_head = log_eventq_sent;
		log_eventq_sent = tmp;
		log_eventq_cnt++;
	}
	mutex_exit(&eventq_sent_mutex);
	mutex_exit(&eventq_head_mutex);

	return (0);
}

/*
 * queue_sysevent - queue an event buffer
 */
static int
queue_sysevent(sysevent_t *ev, sysevent_id_t *eid, int flag)
{
	log_eventq_t *q;

	ASSERT(flag == SE_SLEEP || flag == SE_NOSLEEP);

	DTRACE_SYSEVENT2(post, evch_bind_t *, NULL, sysevent_impl_t *, ev);

restart:

	/* Max Q size exceeded */
	mutex_enter(&event_qfull_mutex);
	if (sysevent_daemon_init && log_eventq_cnt >= logevent_max_q_sz) {
		/*
		 * If queue full and transport down, return no transport
		 */
		if (sysevent_upcall_status != 0) {
			mutex_exit(&event_qfull_mutex);
			free_packed_event(ev);
			eid->eid_seq = UINT64_C(0);
			eid->eid_ts = INT64_C(0);
			return (SE_NO_TRANSPORT);
		}
		if (flag == SE_NOSLEEP) {
			mutex_exit(&event_qfull_mutex);
			free_packed_event(ev);
			eid->eid_seq = UINT64_C(0);
			eid->eid_ts = INT64_C(0);
			return (SE_EQSIZE);
		}
		event_qfull_blocked++;
		cv_wait(&event_qfull_cv, &event_qfull_mutex);
		event_qfull_blocked--;
		mutex_exit(&event_qfull_mutex);
		goto restart;
	}
	mutex_exit(&event_qfull_mutex);

	mutex_enter(&eventq_head_mutex);

	/* Time stamp and assign ID */
	SE_SEQ(ev) = eid->eid_seq = atomic_add_64_nv(&kernel_event_id,
	    (uint64_t)1);
	SE_TIME(ev) = eid->eid_ts = gethrtime();

	LOG_DEBUG1((CE_CONT, "log_sysevent: class=%d type=%d id=0x%llx\n",
	    SE_CLASS(ev), SE_SUBCLASS(ev), (longlong_t)SE_SEQ(ev)));

	/*
	 * Put event on eventq
	 */
	q = (log_eventq_t *)((caddr_t)ev - offsetof(log_eventq_t, arg.buf));
	q->next = NULL;
	if (log_eventq_head == NULL) {
		ASSERT(log_eventq_cnt == 0);
		log_eventq_head = q;
		log_eventq_tail = q;
	} else {
		if (log_eventq_head == log_eventq_tail) {
			ASSERT(log_eventq_cnt == 1);
			ASSERT(log_eventq_head->next == NULL);
			ASSERT(log_eventq_tail->next == NULL);
		}
		log_eventq_tail->next = q;
		log_eventq_tail = q;
	}
	log_eventq_cnt++;

	/* Signal event delivery thread */
	if (log_eventq_cnt == 1) {
		cv_signal(&log_event_cv);
	}
	mutex_exit(&eventq_head_mutex);

	return (0);
}

/*
 * log_sysevent - kernel system event logger.
 *
 * Returns SE_ENOMEM if buf allocation failed or SE_EQSIZE if the
 * maximum event queue size will be exceeded
 * Returns 0 for successfully queued event buffer
 */
int
log_sysevent(sysevent_t *ev, int flag, sysevent_id_t *eid)
{
	sysevent_t *ev_copy;
	int rval;

	ASSERT(flag == SE_SLEEP || flag == SE_NOSLEEP);
	ASSERT(!(flag == SE_SLEEP && servicing_interrupt()));

	ev_copy = se_repack(ev, flag);
	if (ev_copy == NULL) {
		ASSERT(flag == SE_NOSLEEP);
		return (SE_ENOMEM);
	}
	rval = queue_sysevent(ev_copy, eid, flag);
	ASSERT(rval == 0 || rval == SE_ENOMEM || rval == SE_EQSIZE ||
	    rval == SE_NO_TRANSPORT);
	ASSERT(!(flag == SE_SLEEP && (rval == SE_EQSIZE || rval == SE_ENOMEM)));
	return (rval);
}

/*
 * log_usr_sysevent - user system event logger
 *			Private to devfsadm and accessible only via
 *			modctl(MODEVENTS, MODEVENTS_POST_EVENT)
 */
int
log_usr_sysevent(sysevent_t *ev, int ev_size, sysevent_id_t *eid)
{
	int ret, copy_sz;
	sysevent_t *ev_copy;
	sysevent_id_t new_eid;
	log_eventq_t *qcopy;

	copy_sz = ev_size + offsetof(log_eventq_t, arg) +
	    offsetof(log_event_upcall_arg_t, buf);
	qcopy = kmem_zalloc(copy_sz, KM_SLEEP);
	ev_copy = (sysevent_t *)&qcopy->arg.buf;

	/*
	 * Copy event
	 */
	if (copyin(ev, ev_copy, ev_size) == -1) {
		kmem_free(qcopy, copy_sz);
		return (EFAULT);
	}

	if ((ret = queue_sysevent(ev_copy, &new_eid, SE_NOSLEEP)) != 0) {
		if (ret == SE_ENOMEM || ret == SE_EQSIZE)
			return (EAGAIN);
		else
			return (EIO);
	}

	if (copyout(&new_eid, eid, sizeof (sysevent_id_t)) == -1) {
		return (EFAULT);
	}

	return (0);
}



int
ddi_log_sysevent(
	dev_info_t		*dip,
	char			*vendor,
	char			*class,
	char			*subclass,
	nvlist_t		*attr_list,
	sysevent_id_t		*eidp,
	int			sleep_flag)
{
	sysevent_attr_list_t	*list = (sysevent_attr_list_t *)attr_list;
	char			pubstr[32];
	sysevent_t		*event;
	sysevent_id_t		eid;
	const char		*drvname;
	char			*publisher;
	int			se_flag;
	int			rval;
	int			n;

	if (sleep_flag == DDI_SLEEP && servicing_interrupt()) {
		cmn_err(CE_NOTE, "!ddi_log_syevent: driver %s%d - cannot queue "
		    "event from interrupt context with sleep semantics\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		return (DDI_ECONTEXT);
	}

	drvname = ddi_driver_name(dip);
	n = strlen(vendor) + strlen(drvname) + 7;
	if (n < sizeof (pubstr)) {
		publisher = pubstr;
	} else {
		publisher = kmem_alloc(n,
		    (sleep_flag == DDI_SLEEP) ? KM_SLEEP : KM_NOSLEEP);
		if (publisher == NULL) {
			return (DDI_ENOMEM);
		}
	}
	(void) strcpy(publisher, vendor);
	(void) strcat(publisher, ":kern:");
	(void) strcat(publisher, drvname);

	se_flag = (sleep_flag == DDI_SLEEP) ? SE_SLEEP : SE_NOSLEEP;
	event = sysevent_alloc(class, subclass, publisher, se_flag);

	if (publisher != pubstr) {
		kmem_free(publisher, n);
	}

	if (event == NULL) {
		return (DDI_ENOMEM);
	}

	if (list) {
		(void) sysevent_attach_attributes(event, list);
	}

	rval = log_sysevent(event, se_flag, &eid);
	if (list) {
		sysevent_detach_attributes(event);
	}
	sysevent_free(event);
	if (rval == 0) {
		if (eidp) {
			eidp->eid_seq = eid.eid_seq;
			eidp->eid_ts = eid.eid_ts;
		}
		return (DDI_SUCCESS);
	}
	if (rval == SE_NO_TRANSPORT)
		return (DDI_ETRANSPORT);

	ASSERT(rval == SE_ENOMEM || rval == SE_EQSIZE);
	return ((rval == SE_ENOMEM) ? DDI_ENOMEM : DDI_EBUSY);
}

uint64_t
log_sysevent_new_id(void)
{
	return (atomic_add_64_nv(&kernel_event_id, (uint64_t)1));
}
