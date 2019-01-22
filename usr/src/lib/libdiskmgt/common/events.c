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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stropts.h>
#include <synch.h>
#include <thread.h>
#include <libsysevent.h>
#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/dev.h>
#include <errno.h>
#include <libgen.h>
#include <unistd.h>

#include "libdiskmgt.h"
#include "disks_private.h"

struct event_list {
	struct event_list	*next;
	nvlist_t		*event;
};

static struct event_list	*events = NULL;
static int			event_error = 0;
static int			event_break = 0;
static mutex_t			queue_lock;
static sema_t			semaphore;

/*
 * When we add a controller we get an add event for each drive on the
 * controller.  We don't want to walk the devtree for each drive since
 * we will get the same information each time.  So, the solution is to
 * wait for a few seconds for all of the add events to come in and then
 * do a single walk.  If an add event comes in after we start the walk, we
 * need to do another walk since we might have missed that drive.
 *
 * State: 0 - no walker; 1 - walker waiting; 2 - walker running
 *	0 -> 1; wait a few seconds
 *	1 -> 2; walking the devtree
 *	2 -> either 0 or 1 (see below)
 * While running (state 2), if event comes in, go back to waiting (state 1)
 * after the walk otherwise go back to none (state 0).
 *
 * walker_lock protects walker_state & events_pending
 */
#define	WALK_NONE		0
#define	WALK_WAITING		1
#define	WALK_RUNNING		2
#define	WALK_WAIT_TIME		60	/* wait 60 seconds */

static mutex_t			walker_lock;
static int			walker_state = WALK_NONE;
static int			events_pending = 0;

static int			sendevents = 0;

static void		add_event_to_queue(nvlist_t *event);
static void		cb_watch_events();
static void		event_handler(sysevent_t *ev);
static void		print_nvlist(char *prefix, nvlist_t *list);
static void		walk_devtree();
static void		walker(void *arg);

static void(*callback)(nvlist_t *, int) = NULL;

nvlist_t *
dm_get_event(int *errp)
{
	nvlist_t *event = NULL;

	*errp = 0;

	/* wait until there is an event in the queue */
	/*CONSTCOND*/
	while (1) {
	    (void) sema_wait(&semaphore);

	    if (event_break) {
		event_break = 0;
		*errp = EINTR;
		break;
	    }

	    (void) mutex_lock(&queue_lock);

	    /* first see if we ran out of memory since the last call */
	    if (event_error != 0) {
		*errp = event_error;
		event_error = 0;

	    } else if (events != NULL) {
		struct event_list *tmpp;

		event = events->event;
		tmpp = events->next;
		free(events);
		events = tmpp;
	    }

	    (void) mutex_unlock(&queue_lock);

	    if (*errp != 0 || event != NULL) {
		break;
	    }
	}

	return (event);
}

void
dm_init_event_queue(void (*cb)(nvlist_t *, int), int *errp)
{
	if (sendevents == 1) {
	    /* we were already initialized, see what changes to make */
	    *errp = 0;
	    if (cb != callback) {

		callback = cb;
		if (cb == NULL) {
		    /* clearing the cb so shutdown the internal cb thread */
		    event_break = 1;
		    (void) sema_post(&semaphore);

		} else {
		    /* installing a cb; we didn't have one before */
		    thread_t watch_thread;

		    *errp = thr_create(NULL, 0,
			(void *(*)(void *))cb_watch_events, NULL, THR_DAEMON,
			&watch_thread);
		}
	    }

	} else {
	    /* first time to initialize */
	    sendevents = 1;

	    *errp = sema_init(&semaphore, 0, USYNC_THREAD, NULL);
	    if (*errp != 0) {
		return;
	    }

	    if (cb != NULL) {
		thread_t watch_thread;

		callback = cb;

		*errp = thr_create(NULL, 0,
		    (void *(*)(void *))cb_watch_events, NULL, THR_DAEMON,
		    &watch_thread);
	    }
	}
}

void
events_new_event(char *name, int dtype, char *etype)
{
	nvlist_t	*event = NULL;

	if (!sendevents) {
	    return;
	}

	if (nvlist_alloc(&event, NVATTRS, 0) != 0) {
	    event = NULL;

	} else {
	    int	error = 0;

	    if (name != NULL &&
		nvlist_add_string(event, DM_EV_NAME, name) != 0) {
		error = ENOMEM;
	    }

	    if (dtype != -1 &&
		nvlist_add_uint32(event, DM_EV_DTYPE, dtype) != 0) {
		error = ENOMEM;
	    }

	    if (nvlist_add_string(event, DM_EV_TYPE, etype) != 0) {
		error = ENOMEM;
	    }

	    if (error != 0) {
		nvlist_free(event);
		event = NULL;
	    }
	}

	add_event_to_queue(event);
}

void
events_new_slice_event(char *dev, char *type)
{
	events_new_event(basename(dev), DM_SLICE, type);
}

int
events_start_event_watcher()
{
	sysevent_handle_t *shp;
	const char *subclass_list[1];

	/* Bind event handler and create subscriber handle */
	shp = sysevent_bind_handle(event_handler);
	if (shp == NULL) {
	    if (dm_debug) {
		/* keep going when we're debugging */
		(void) fprintf(stderr, "ERROR: bind failed %d\n", errno);
		return (0);
	    }
	    return (errno);
	}

	subclass_list[0] = ESC_DISK;
	if (sysevent_subscribe_event(shp, EC_DEV_ADD, subclass_list, 1) != 0) {
	    if (dm_debug) {
		/* keep going when we're debugging */
		(void) fprintf(stderr, "ERROR: subscribe failed\n");
		return (0);
	    }
	    return (errno);
	}
	if (sysevent_subscribe_event(shp, EC_DEV_REMOVE, subclass_list, 1)
	    != 0) {
	    if (dm_debug) {
		/* keep going when we're debugging */
		(void) fprintf(stderr, "ERROR: subscribe failed\n");
		return (0);
	    }
	    return (errno);
	}

	return (0);
}

static void
add_event_to_queue(nvlist_t *event)
{
	(void) mutex_lock(&queue_lock);

	if (event == NULL) {
	    event_error = ENOMEM;
	    (void) mutex_unlock(&queue_lock);
	    return;
	}

	if (events == NULL) {

	    events = (struct event_list *)malloc(sizeof (struct event_list));
	    if (events == NULL) {
		event_error = ENOMEM;
		nvlist_free(event);
	    } else {
		events->next = NULL;
		events->event = event;
	    }

	} else {
	    /* already have events in the queue */
	    struct event_list *ep;
	    struct event_list *new_event;

	    /* find the last element in the list */
	    for (ep = events; ep->next != NULL; ep = ep->next);

	    new_event = (struct event_list *)malloc(sizeof (struct event_list));
	    if (new_event == NULL) {
		event_error = ENOMEM;
		nvlist_free(event);
	    } else {
		new_event->next = NULL;
		new_event->event = event;
		ep->next = new_event;
	    }
	}

	(void) mutex_unlock(&queue_lock);

	(void) sema_post(&semaphore);
}

static void
cb_watch_events()
{
	nvlist_t	*event;
	int		error;

	/*CONSTCOND*/
	while (1) {
	    event = dm_get_event(&error);
	    if (callback == NULL) {
		/* end the thread */
		return;
	    }
	    callback(event, error);
	}
}

static void
event_handler(sysevent_t *ev)
{
	char		*class_name;
	char		*pub;

	class_name = sysevent_get_class_name(ev);
	if (dm_debug) {
	    (void) fprintf(stderr, "****EVENT: %s %s ", class_name,
		sysevent_get_subclass_name(ev));
	    if ((pub = sysevent_get_pub_name(ev)) != NULL) {
		(void) fprintf(stderr, "%s\n", pub);
		free(pub);
	    } else {
		(void) fprintf(stderr, "\n");
	    }
	}

	if (libdiskmgt_str_eq(class_name, EC_DEV_ADD)) {
	    /* batch up the adds into a single devtree walk */
	    walk_devtree();

	} else if (libdiskmgt_str_eq(class_name, EC_DEV_REMOVE)) {
	    nvlist_t	*nvlist = NULL;
	    char	*dev_name = NULL;

	    (void) sysevent_get_attr_list(ev, &nvlist);
	    if (nvlist != NULL) {
		(void) nvlist_lookup_string(nvlist, DEV_NAME, &dev_name);

		if (dm_debug) {
		    print_nvlist("**** ", nvlist);
		}
	    }

	    if (dev_name != NULL) {
		cache_update(DM_EV_DISK_DELETE, dev_name);
	    }

	    if (nvlist != NULL) {
		nvlist_free(nvlist);
	    }
	}
}

/*
 * This is a debugging function only.
 */
static void
print_nvlist(char *prefix, nvlist_t *list)
{
	nvpair_t	*nvp;

	nvp = nvlist_next_nvpair(list, NULL);
	while (nvp != NULL) {
	    char	*attrname;
	    char	*str;
	    uint32_t	ui32;
	    uint64_t	ui64;
	    char	**str_array;
	    uint_t	cnt;
	    int		i;

	    attrname = nvpair_name(nvp);
	    switch (nvpair_type(nvp)) {
	    case DATA_TYPE_STRING:
		(void) nvpair_value_string(nvp, &str);
		(void) fprintf(stderr, "%s%s: %s\n", prefix, attrname, str);
		break;

	    case DATA_TYPE_STRING_ARRAY:
		(void) nvpair_value_string_array(nvp, &str_array, &cnt);
		(void) fprintf(stderr, "%s%s:\n", prefix, attrname);
		for (i = 0; i < cnt; i++) {
		    (void) fprintf(stderr, "%s    %s\n", prefix, str_array[i]);
		}
		break;

	    case DATA_TYPE_UINT32:
		(void) nvpair_value_uint32(nvp, &ui32);
		(void) fprintf(stderr, "%s%s: %u\n", prefix, attrname, ui32);
		break;

	    case DATA_TYPE_UINT64:
		(void) nvpair_value_uint64(nvp, &ui64);
#ifdef _LP64
		(void) fprintf(stderr, "%s%s: %lu\n", prefix, attrname, ui64);
#else
		(void) fprintf(stderr, "%s%s: %llu\n", prefix, attrname, ui64);
#endif
		break;


	    case DATA_TYPE_BOOLEAN:
		(void) fprintf(stderr, "%s%s: true\n", prefix, attrname);
		break;

	    default:
		(void) fprintf(stderr, "%s%s: UNSUPPORTED TYPE\n", prefix,
		    attrname);
		break;
	    }

	    nvp = nvlist_next_nvpair(list, nvp);
	}
}

/*
 * Batch up the adds into a single devtree walk.  We can get a bunch of
 * adds when we add a controller since we will get an add event for each
 * drive.
 */
static void
walk_devtree()
{
	thread_t	walk_thread;

	(void) mutex_lock(&walker_lock);

	switch (walker_state) {
	case WALK_NONE:
	    if (thr_create(NULL, 0, (void *(*)(void *))walker, NULL,
		THR_DAEMON, &walk_thread) == 0) {
		walker_state = WALK_WAITING;
	    }
	    break;

	case WALK_WAITING:
	    /* absorb the event and do nothing */
	    break;

	case WALK_RUNNING:
	    events_pending = 1;
	    break;
	}

	(void) mutex_unlock(&walker_lock);
}

/*ARGSUSED*/
static void
walker(void *arg)
{
	int	walk_again = 0;

	do {
	    /* start by wating for a few seconds to absorb extra events */
	    (void) sleep(WALK_WAIT_TIME);

	    (void) mutex_lock(&walker_lock);
	    walker_state = WALK_RUNNING;
	    (void) mutex_unlock(&walker_lock);

	    cache_update(DM_EV_DISK_ADD, NULL);

	    (void) mutex_lock(&walker_lock);

	    if (events_pending) {
		events_pending = 0;
		walker_state = WALK_WAITING;
		walk_again = 1;
	    } else {
		walker_state = WALK_NONE;
		walk_again = 0;
	    }

	    (void) mutex_unlock(&walker_lock);

	} while (walk_again);
}
