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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/signal.h>
#include <sys/modctl.h>
#include <sys/proc.h>
#include <sys/lvm/mdvar.h>

md_ops_t		event_md_ops;
#ifndef lint
char			_depends_on[] = "drv/md";
md_ops_t		*md_interface_ops = &event_md_ops;
#endif

extern void		sigintr();
extern void		sigunintr();
extern md_set_t		md_set[];

extern kmutex_t		md_mx;		/* used to md global stuff */
extern kcondvar_t	md_cv;		/* md_status events */
extern int		md_status;
extern clock_t		md_hz;
extern md_event_queue_t	*md_event_queue;
static void		 md_reaper();
extern void		md_clear_named_service();

/* event handler stuff */
kmutex_t		md_eventq_mx;
int			md_reap_count = 32;	/* check for pid alive */
int			md_reap = 0;
int			md_max_notify_queue = 512;
int			md_reap_off = 0;	/* non-zero turns off reap */
/* don't allow module to be unloaded until all pending ops are complete */
int			global_lock_wait_cnt = 0;

static int
md_flush_queue(md_event_queue_t *queue)
{
	md_event_t	*element, *next_element;
	/*
	 * if there is something waiting on it and the
	 * process/pid no longer exist then signal the defunct
	 * process continue on to clean this up later.
	 */
	if (queue->mdn_waiting)
		return (1);
	/*
	 * this pid no longer exists blow it away
	 * first remove any entries, then unlink it and lastly
	 * free it.
	 */
	element = queue->mdn_front;
	while (element) {
		next_element = element->mdn_next;
		kmem_free(element, sizeof (md_event_t));
		element = next_element;
	}
	queue->mdn_front = queue->mdn_tail = NULL;
	return (0);

}

static void
md_put_event(md_tags_t tag, set_t sp, md_dev64_t dev, int event,
		u_longlong_t user)
{

	md_event_queue_t	*queue;
	md_event_t		*entry;

	if (!md_event_queue)
		return;

	mutex_enter(&md_eventq_mx);
	for (queue = md_event_queue; queue; queue = queue->mdn_nextq) {
		if (queue->mdn_size >= md_max_notify_queue) {
			ASSERT(queue->mdn_front != NULL);
			ASSERT(queue->mdn_front->mdn_next != NULL);
			entry =  queue->mdn_front;
			queue->mdn_front = entry->mdn_next;
			queue->mdn_size--;
			queue->mdn_flags |= MD_EVENT_QUEUE_FULL;
		} else
			entry = (md_event_t *)kmem_alloc(sizeof (md_event_t),
			    KM_NOSLEEP);
		if (entry == NULL) {
			queue->mdn_flags |= MD_EVENT_QUEUE_INVALID;
			continue;
		}
		entry->mdn_tag = tag;
		entry->mdn_set = sp;
		entry->mdn_dev = dev;
		entry->mdn_event = event;
		entry->mdn_user = user;
		entry->mdn_next = NULL;
		uniqtime(&entry->mdn_time);
		if (queue->mdn_front == NULL) {
			queue->mdn_front = entry;
			queue->mdn_tail = entry;
		} else {
			queue->mdn_tail->mdn_next = entry;
			queue->mdn_tail = entry;
		}
		if (queue->mdn_waiting)
			cv_signal(&queue->mdn_cv);

		queue->mdn_size++;
	}
	md_reap++;
	mutex_exit(&md_eventq_mx);

	if (md_reap > md_reap_count)
		md_reaper();
}

static void
md_reaper()
{
	md_event_queue_t	*next = md_event_queue;
	md_event_queue_t	*present, *last = NULL;

	if (md_event_queue == NULL || md_reap_off)
		return;

	mutex_enter(&md_eventq_mx);
	while (next) {
		present = next;
		next = present->mdn_nextq;

		/* check for long term event queue */
		if (present->mdn_flags & MD_EVENT_QUEUE_PERM) {
			last = present;
			continue;
		}

		/* check to see if the pid is still alive */
		if (!md_checkpid(present->mdn_pid, present->mdn_proc))
			present->mdn_flags |= MD_EVENT_QUEUE_DESTROY;

		/* see if queue is a "marked queue" if so destroy */
		if (! (present->mdn_flags & MD_EVENT_QUEUE_DESTROY)) {
			last = present;
			continue;
		}

		/* yeeeha   blow this one away */
		present->mdn_pid = 0;
		present->mdn_proc = NULL;
		/*
		 * if there is something waiting on it and the
		 * process/pid no longer exist then signal the defunct
		 * process continue on to clean this up later.
		 */
		if (md_flush_queue(present)) {
			present->mdn_flags = MD_EVENT_QUEUE_DESTROY;
			cv_broadcast(&present->mdn_cv);
			last = present;
			continue;
		}
		/* remove the entry */
		if (last == NULL)
			md_event_queue = next;
		else
			last->mdn_nextq = next;
		cv_destroy(&present->mdn_cv);
		kmem_free(present, sizeof (md_event_queue_t));
	}
	md_reap = 0;
	mutex_exit(&md_eventq_mx);
}

/* ARGSUSED */
static int
notify_halt(md_haltcmd_t cmd, set_t setno)
{
	md_event_queue_t	*orig_queue, *queue, *queue_free;
	int			i;


	switch (cmd) {
	    case MD_HALT_CLOSE:
	    case MD_HALT_OPEN:
	    case MD_HALT_DOIT:
	    case MD_HALT_CHECK:

		return (0);

	    case MD_HALT_UNLOAD:
		if (setno != MD_LOCAL_SET)
			return (1);
		mutex_enter(&md_eventq_mx);
		if (md_event_queue == NULL) {
			mutex_exit(&md_eventq_mx);
			return (0);
		}

		orig_queue = md_event_queue;
		md_event_queue = NULL;
		for (i = 0; i < MD_NOTIFY_HALT_TRIES; i++) {
			for (queue = orig_queue; queue;
			    queue = queue->mdn_nextq) {
				if (queue->mdn_waiting == 0) {
					continue;
				}
				queue->mdn_flags = MD_EVENT_QUEUE_DESTROY;
				mutex_exit(&md_eventq_mx);
				cv_broadcast(&queue->mdn_cv);
				delay(md_hz);
				mutex_enter(&md_eventq_mx);
			}
		}
		for (queue = orig_queue; queue; ) {
			if (md_flush_queue(queue)) {
				cmn_err(CE_WARN, "md: queue not freed");
				mutex_exit(&md_eventq_mx);
				return (1);
			}
			queue_free = queue;
			queue = queue->mdn_nextq;
			kmem_free(queue_free, sizeof (md_event_queue_t));
		}
		md_event_queue = NULL;
		mutex_exit(&md_eventq_mx);
		return (0);

	    default:
		return (1);
	}
}

static md_event_queue_t *
md_find_event_queue(char *q_name, int lock)
{
	md_event_queue_t	*event_q = md_event_queue;

	if (lock)
		mutex_enter(&md_eventq_mx);
	ASSERT(MUTEX_HELD(&md_eventq_mx));
	while (event_q) {
		if ((*event_q->mdn_name != *q_name) ||
		    (event_q->mdn_flags & MD_EVENT_QUEUE_DESTROY)) {
			event_q = event_q->mdn_nextq;
			continue;
		}

		if (bcmp(q_name, event_q->mdn_name, MD_NOTIFY_NAME_SIZE) == 0)
			break;
		event_q = event_q->mdn_nextq;
	}
	if (lock)
		mutex_exit(&md_eventq_mx);

	return ((md_event_queue_t *)event_q);
}

static intptr_t
notify_interface(md_event_cmds_t cmd, md_tags_t tag, set_t set, md_dev64_t dev,
		md_event_type_t event)
{
	switch (cmd) {
	    case EQ_PUT:
		md_put_event(tag, set, dev, event, (u_longlong_t)0);
		break;
	    default:
		return (-1);
	}
	return (0);
}

static int
notify_fillin_empty_ioctl(void *data, void *ioctl_in, size_t sz,
		int mode)
{

	int	err;
	md_event_ioctl_t	*ioctl = (md_event_ioctl_t *)data;


	ioctl->mdn_event = EQ_EMPTY;
	ioctl->mdn_tag = TAG_EMPTY;
	ioctl->mdn_set = MD_ALLSETS;
	ioctl->mdn_dev =  MD_ALLDEVS;
	uniqtime32(&ioctl->mdn_time);
	ioctl->mdn_user = (u_longlong_t)0;
	err = ddi_copyout(data, ioctl_in, sz, mode);
	return (err);
}

/*
 * md_wait_for_event:
 * IOLOCK_RETURN which drops the md_ioctl_lock is called in this
 * routine to enable other mdioctls to enter the kernel while this
 * thread of execution waits on an event.  When that event occurs, the
 * stopped thread wakes and continues and md_ioctl_lock must be
 * reacquired.  Even though md_ioctl_lock is interruptable, we choose
 * to ignore EINTR.  Returning w/o acquiring md_ioctl_lock is
 * catastrophic since it breaks down ioctl single threading.
 *
 * Return: 0	md_eventq_mx held
 *	   EINTR md_eventq_mx no held
 *	   Always returns with IOCTL lock held
 */

static int
md_wait_for_event(md_event_queue_t *event_queue, void *ioctl_in,
		md_event_ioctl_t *ioctl, size_t sz,
		int mode, IOLOCK *lockp)
{
	int rval = 0;

	while (event_queue->mdn_front == NULL) {
		event_queue->mdn_waiting++;
		(void) IOLOCK_RETURN(0, lockp);
		rval = cv_wait_sig(&event_queue->mdn_cv, &md_eventq_mx);
		event_queue->mdn_waiting--;
		if ((rval == 0) || (event_queue->mdn_flags &
					MD_EVENT_QUEUE_DESTROY)) {
			global_lock_wait_cnt++;
			mutex_exit(&md_eventq_mx);
			/* reenable single threading of ioctls */
			while (md_ioctl_lock_enter() == EINTR);

			(void) notify_fillin_empty_ioctl
			    ((void *)ioctl, ioctl_in, sz, mode);
			mutex_enter(&md_eventq_mx);
			global_lock_wait_cnt--;
			mutex_exit(&md_eventq_mx);
			return (EINTR);
		}
		/*
		 * reacquire single threading ioctls. Drop eventq_mutex
		 * since md_ioctl_lock_enter can sleep.
		 */
		global_lock_wait_cnt++;
		mutex_exit(&md_eventq_mx);
		while (md_ioctl_lock_enter() == EINTR);
		mutex_enter(&md_eventq_mx);
		global_lock_wait_cnt--;
	}
	return (0);
}

/* ARGSUSED */
static int
notify_ioctl(dev_t dev, int icmd, void *ioctl_in, int mode, IOLOCK *lockp)
{
	int			cmd;
	pid_t			pid;
	md_event_queue_t	*event_queue;
	md_event_t		*event;
	cred_t			*credp;
	char			*q_name;
	int			err = 0;
	size_t			sz = 0;
	md_event_ioctl_t	*ioctl;

	sz = sizeof (*ioctl);
	ioctl = kmem_zalloc(sz, KM_SLEEP);

	if (ddi_copyin(ioctl_in, (void *)ioctl, sz, mode)) {
		err = EFAULT;
		goto out;
	}

	if (ioctl->mdn_rev != MD_NOTIFY_REVISION) {
		err = EINVAL;
		goto out;
	}
	if (ioctl->mdn_magic != MD_EVENT_ID) {
		err = EINVAL;
		goto out;
	}

	pid = md_getpid();
	cmd = ioctl->mdn_cmd;
	q_name = ioctl->mdn_name;

	if (((cmd != EQ_OFF) && (cmd != EQ_ON)) && (md_reap >= md_reap_count))
		md_reaper();

	if ((cmd != EQ_ON) && (cmd != EQ_PUT)) {
		mutex_enter(&md_eventq_mx);
		if ((event_queue = md_find_event_queue(q_name, 0)) == NULL) {
			mutex_exit(&md_eventq_mx);
			(void) notify_fillin_empty_ioctl
			    ((void *)ioctl, ioctl_in, sz, mode);
			err = ENOENT;
			goto out;
		}
	}

	switch (cmd) {
	    case EQ_ON:

		md_reaper();

		mutex_enter(&md_eventq_mx);
		if (md_find_event_queue(q_name, 0) != NULL) {
			mutex_exit(&md_eventq_mx);
			err = EEXIST;
			break;
		}

		/* allocate and initialize queue head */
		event_queue = (md_event_queue_t *)
		    kmem_alloc(sizeof (md_event_queue_t), KM_NOSLEEP);
		if (event_queue == NULL) {
			mutex_exit(&md_eventq_mx);
			err = ENOMEM;
			break;
		}

		cv_init(&event_queue->mdn_cv, NULL, CV_DEFAULT, NULL);

		event_queue->mdn_flags = 0;
		event_queue->mdn_pid = pid;
		event_queue->mdn_proc = md_getproc();
		event_queue->mdn_size = 0;
		event_queue->mdn_front = NULL;
		event_queue->mdn_tail = NULL;
		event_queue->mdn_waiting = 0;
		event_queue->mdn_nextq = NULL;
		credp = ddi_get_cred();
		event_queue->mdn_uid = crgetuid(credp);
		bcopy(q_name, event_queue->mdn_name,
		    MD_NOTIFY_NAME_SIZE);
		if (ioctl->mdn_flags & EQ_Q_PERM)
			event_queue->mdn_flags |= MD_EVENT_QUEUE_PERM;

		/* link into the list of event queues */
		if (md_event_queue != NULL)
			event_queue->mdn_nextq = md_event_queue;
		md_event_queue = event_queue;
		mutex_exit(&md_eventq_mx);
		err = 0;
		break;

	    case EQ_OFF:

		if (md_event_queue == NULL)
			return (ENOENT);

		event_queue->mdn_flags = MD_EVENT_QUEUE_DESTROY;
		event_queue->mdn_pid = 0;
		event_queue->mdn_proc = NULL;

		if (event_queue->mdn_waiting != 0)
			cv_broadcast(&event_queue->mdn_cv);

		/*
		 * force the reaper to delete this when it has no process
		 * waiting on it.
		 */
		mutex_exit(&md_eventq_mx);
		md_reaper();
		err = 0;
		break;

	    case EQ_GET_NOWAIT:
	    case EQ_GET_WAIT:
		if (cmd == EQ_GET_WAIT) {
			err = md_wait_for_event(event_queue, ioctl_in,
			    ioctl, sz, mode, lockp);
			if (err == EINTR)
				goto out;
		}
		ASSERT(MUTEX_HELD(&md_eventq_mx));
		if (event_queue->mdn_flags &
		    (MD_EVENT_QUEUE_INVALID | MD_EVENT_QUEUE_FULL)) {
			event_queue->mdn_flags &=
			    ~(MD_EVENT_QUEUE_INVALID | MD_EVENT_QUEUE_FULL);
			mutex_exit(&md_eventq_mx);
			err = notify_fillin_empty_ioctl
			    ((void *)ioctl, ioctl_in, sz, mode);
			ioctl->mdn_event = EQ_NOTIFY_LOST;
			err = ddi_copyout((void *)ioctl, ioctl_in, sz, mode);
			if (err)
				err = EFAULT;
			goto out;
		}
		if (event_queue->mdn_front != NULL) {
			event = event_queue->mdn_front;
			event_queue->mdn_front = event->mdn_next;
			event_queue->mdn_size--;
			if (event_queue->mdn_front == NULL)
				event_queue->mdn_tail = NULL;
			mutex_exit(&md_eventq_mx);
			ioctl->mdn_tag = event->mdn_tag;
			ioctl->mdn_set = event->mdn_set;
			ioctl->mdn_dev = event->mdn_dev;
			ioctl->mdn_event = event->mdn_event;
			ioctl->mdn_user = event->mdn_user;
			ioctl->mdn_time.tv_sec = event->mdn_time.tv_sec;
			ioctl->mdn_time.tv_usec =
					event->mdn_time.tv_usec;
			kmem_free(event, sizeof (md_event_t));
			err = ddi_copyout((void *)ioctl, ioctl_in, sz, mode);
			if (err)
				err = EFAULT;
			goto out;
		} else { /* no elements on queue */
			mutex_exit(&md_eventq_mx);
			err = notify_fillin_empty_ioctl
			    ((void *)ioctl, ioctl_in, sz, mode);
			if (err)
				err = EFAULT;
		}

		if (cmd == EQ_GET_NOWAIT)
			err = EAGAIN;
		goto out;

	    case EQ_PUT:

		if (!md_event_queue) {
			err = ENOENT;
			break;
		}
		md_put_event(ioctl->mdn_tag,
			ioctl->mdn_set, ioctl->mdn_dev,
			ioctl->mdn_event, ioctl->mdn_user);
		err = 0;
		goto out;

	    default:
		err = EINVAL;
		goto out;
	}

out:
	kmem_free(ioctl, sz);
	return (err);
}

/*
 * Turn orphaned queue off for testing purposes.
 */

static intptr_t
notify_reap_off()
{
	md_reap_off = 1;
	return (0);
}

/*
 * Turn reaping back on.
 */

static intptr_t
notify_reap_on()
{
	md_reap_off = 0;
	return (0);
}

/*
 * Return information that is used to test the notification feature.
 */

static intptr_t
notify_test_stats(md_notify_stats_t *stats)
{
	stats->mds_eventq_mx = &md_eventq_mx;
	stats->mds_reap_count = md_reap_count;
	stats->mds_reap = md_reap;
	stats->mds_max_queue = md_max_notify_queue;
	stats->mds_reap_off = md_reap_off;
	return (0);
}

/*
 * put this stuff at end so we don't have to create forward
 * references for everything
 */
static struct modlmisc modlmisc = {
	&mod_miscops,
	"Solaris Volume Manager notification module"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

static md_named_services_t notify_services[] = {
	{notify_interface,	"notify interface"},
	{notify_reap_off,	MD_NOTIFY_REAP_OFF},
	{notify_reap_on,	MD_NOTIFY_REAP_ON},
	{notify_test_stats,	MD_NOTIFY_TEST_STATS},
	{NULL,			0}
};

md_ops_t event_md_ops = {
	NULL,			/* open */
	NULL,			/* close */
	NULL,			/* strategy */
	NULL,			/* print */
	NULL,			/* dump */
	NULL,			/* read */
	NULL,			/* write */
	notify_ioctl,		/* event_ioctls, */
	NULL,			/* snarf */
	notify_halt,		/* halt */
	NULL,			/* aread */
	NULL,			/* awrite */
	NULL,			/* import set */
	notify_services		/* named_services */
};

int
_init()
{
	md_event_queue = NULL;
	mutex_init(&md_eventq_mx, NULL, MUTEX_DEFAULT, NULL);
	return (mod_install(&modlinkage));
}

int
_fini()
{
	int		err = 0;

	/*
	 * Don't allow the module to be unloaded while there is a thread
	 * of execution that is waiting for a global lock.
	 */
	if (global_lock_wait_cnt > 0)
		return (EBUSY);

	if ((err = mod_remove(&modlinkage)) != 0)
		return (err);

	md_clear_named_service();
	mutex_destroy(&md_eventq_mx);
	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
