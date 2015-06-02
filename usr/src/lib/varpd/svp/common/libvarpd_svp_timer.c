/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015, Joyent, Inc.
 */

#include <stddef.h>
#include <libvarpd_svp.h>

/*
 * svp timer backend
 *
 * This implements all of the logic of maintaining a timer for the svp backend.
 * We have a timer that fires at a one second tick. We maintain all of our
 * events in avl tree, sorted by the tick that they need to be processed at.
 *
 * For more information, see the big theory statement in
 * lib/varpd/svp/common/libvarpd_svp.c.
 */

int svp_tickrate = 1;
static svp_event_t svp_timer_event;
static mutex_t svp_timer_lock = ERRORCHECKMUTEX;
static cond_t svp_timer_cv = DEFAULTCV;
static avl_tree_t svp_timer_tree;
static uint64_t svp_timer_nticks;

static int
svp_timer_comparator(const void *l, const void *r)
{
	const svp_timer_t *lt, *rt;

	lt = l;
	rt = r;

	if (lt->st_expire > rt->st_expire)
		return (1);
	else if (lt->st_expire < rt->st_expire)
		return (-1);

	/*
	 * Multiple timers can have the same delivery time, so sort within that
	 * by the address of the timer itself.
	 */
	if ((uintptr_t)lt > (uintptr_t)rt)
		return (1);
	else if ((uintptr_t)lt < (uintptr_t)rt)
		return (-1);

	return (0);
}

/* ARGSUSED */
static void
svp_timer_tick(port_event_t *pe, void *arg)
{
	mutex_enter(&svp_timer_lock);
	svp_timer_nticks++;

	for (;;) {
		svp_timer_t *t;

		t = avl_first(&svp_timer_tree);
		if (t == NULL || t->st_expire > svp_timer_nticks)
			break;

		avl_remove(&svp_timer_tree, t);

		/*
		 * We drop this while performing an operation so that way state
		 * can advance in the face of a long-running callback.
		 */
		t->st_delivering = B_TRUE;
		mutex_exit(&svp_timer_lock);
		t->st_func(t->st_arg);
		mutex_enter(&svp_timer_lock);
		t->st_delivering = B_FALSE;
		(void) cond_broadcast(&svp_timer_cv);
		if (t->st_oneshot == B_FALSE) {
			t->st_expire += t->st_value;
			avl_add(&svp_timer_tree, t);
		}
	}
	mutex_exit(&svp_timer_lock);
}

void
svp_timer_add(svp_timer_t *stp)
{
	if (stp->st_value == 0)
		libvarpd_panic("tried to add svp timer with zero value");

	mutex_enter(&svp_timer_lock);
	stp->st_delivering = B_FALSE;
	stp->st_expire = svp_timer_nticks + stp->st_value;
	avl_add(&svp_timer_tree, stp);
	mutex_exit(&svp_timer_lock);
}

void
svp_timer_remove(svp_timer_t *stp)
{
	mutex_enter(&svp_timer_lock);

	/*
	 * If the event in question is not currently being delivered, then we
	 * can stop it before it next fires. If it is currently being delivered,
	 * we need to wait for that to finish. Because we hold the timer lock,
	 * we know that it cannot be rearmed. Therefore, we make sure the one
	 * shot is set to zero, and wait until it's no longer set to delivering.
	 */
	if (stp->st_delivering == B_FALSE) {
		avl_remove(&svp_timer_tree, stp);
		mutex_exit(&svp_timer_lock);
		return;
	}

	stp->st_oneshot = B_TRUE;
	while (stp->st_delivering == B_TRUE)
		(void) cond_wait(&svp_timer_cv, &svp_timer_lock);

	mutex_exit(&svp_timer_lock);
}

int
svp_timer_init(void)
{
	int ret;

	svp_timer_event.se_func = svp_timer_tick;
	svp_timer_event.se_arg = NULL;

	avl_create(&svp_timer_tree, svp_timer_comparator, sizeof (svp_timer_t),
	    offsetof(svp_timer_t, st_link));

	if ((ret = svp_event_timer_init(&svp_timer_event)) != 0) {
		avl_destroy(&svp_timer_tree);
	}

	return (ret);
}
