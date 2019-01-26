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

#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <door.h>
#include <fcntl.h>
#include <syslog.h>
#include <sys/sunddi.h>
#include <libsysevent.h>
#include <picl.h>
#include <pthread.h>
#include "piclevent.h"
#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/dr.h>

#define	PICLSLM_DOOR_FAILED	gettext("PICL SLM door create failed\n")

/*
 * syseventd event handler
 */
static	int	piclslm_debug = 0;
static	int	piclslm_deliver_event(sysevent_t *ev, int flag);
static	int	door_fd = -1;

typedef struct nvlist_queue {
	char			*nvq_item;	/* packed nvlist */
	size_t			nvq_sz;		/* buf size */
	struct nvlist_queue	*nvq_next;
} nvlist_queue_t;

static nvlist_queue_t	*nvq_head;
static nvlist_queue_t	*nvq_tail;

static mutex_t	nvq_lock;
static cond_t	nvq_cv;
static thread_t	piclslm_deliver_thr_id;
static int	cleanup;

static struct slm_mod_ops piclslm_mod_ops = {
	SE_MAJOR_VERSION, SE_MINOR_VERSION, SE_MAX_RETRY_LIMIT,
	piclslm_deliver_event};


static void
init_queue(void)
{
	nvq_head = NULL;
	nvq_tail = NULL;
}

static int
add_to_queue(char *nvl, size_t sz)
{
	nvlist_queue_t	*new_nvq;

	new_nvq = malloc(sizeof (*new_nvq));
	if (new_nvq == NULL)
		return (-1);

	new_nvq->nvq_item = nvl;
	new_nvq->nvq_sz = sz;
	new_nvq->nvq_next = NULL;

	if (nvq_head == NULL)
		nvq_head = new_nvq;
	else
		nvq_tail->nvq_next = new_nvq;
	nvq_tail = new_nvq;

	return (0);
}

static nvlist_queue_t *
remove_from_queue(void)
{
	nvlist_queue_t	*nvqp;

	if (nvq_head == NULL)
		return (NULL);

	nvqp = nvq_head;
	nvq_head = nvq_head->nvq_next;
	if (nvq_head == NULL)
		nvq_tail = NULL;
	return (nvqp);
}

static void
free_nvqueue(nvlist_queue_t *nvqp)
{
	free(nvqp->nvq_item);
	free(nvqp);
}

/*
 * deliver the event to the plugin if the door exists
 */
static void
post_piclevent(char *pack_buf, size_t nvl_size)
{
	door_arg_t		darg;

	darg.data_ptr = pack_buf;
	darg.data_size = nvl_size;
	darg.desc_ptr = NULL;
	darg.desc_num = 0;
	darg.rbuf = NULL;
	darg.rsize = 0;

	if (door_fd < 0 || door_call(door_fd, &darg) < 0) {
		if (door_fd >= 0) {
			if (errno != EBADF) {
				return;
			}

			/*
			 * It's not a valid door file descriptor.
			 * Close and reopen the door and try again
			 * as "picld" may have restarted.
			 */
			(void) close(door_fd);
		}

		door_fd = open(PICLEVENT_DOOR, O_RDONLY);
		if (piclslm_debug)
			syslog(LOG_INFO,
			    "picl_slm: opened door %s door_fd: %d\n",
			    PICLEVENT_DOOR, door_fd);
		if (door_fd < 0 || door_call(door_fd, &darg) < 0) {
			return;
		}
	}
	if (piclslm_debug)
		syslog(LOG_INFO,
		    "picl_slm: sent sysevent door:%d pack_buf:%p size:0x%x\n",
		    door_fd, pack_buf, nvl_size);
}

/*ARGSUSED*/
static void *
piclslm_deliver_thr(void *args)
{
	nvlist_queue_t		*nvqp;

	for (;;) {
		(void) mutex_lock(&nvq_lock);
		while (nvq_head == NULL && cleanup == 0) {
			(void) cond_wait(&nvq_cv, &nvq_lock);
		}
		nvqp = remove_from_queue();
		(void) mutex_unlock(&nvq_lock);
		while (nvqp) {
			post_piclevent(nvqp->nvq_item, nvqp->nvq_sz);
			free_nvqueue(nvqp);
			(void) mutex_lock(&nvq_lock);
			nvqp = remove_from_queue();
			(void) mutex_unlock(&nvq_lock);
		}
		if (cleanup)
			return (NULL);
	}
	/*NOTREACHED*/
}

/*
 * returns 0 if arguments successfully added to nvl, EINVAL if arguments missing
 * from ev and EAGAIN if nvlist_add_string() fails
 */
static int
piclslm_add_ec_devfs_args(nvlist_t *nvl, sysevent_t *ev)
{
	sysevent_value_t se_val;

	if (sysevent_lookup_attr(ev, DEVFS_PATHNAME, SE_DATA_TYPE_STRING,
	    &se_val) != 0 || se_val.value.sv_string == NULL) {
		return (EINVAL);
	}
	if (nvlist_add_string(nvl, PICLEVENTARG_DEVFS_PATH,
	    se_val.value.sv_string)) {
		return (EAGAIN);
	}
	return (0);
}

/*
 * returns 0 if arguments successfully added to nvl, EINVAL if arguments missing
 * from ev and EAGAIN if nvlist_add_string() fails
 */
static int
piclslm_add_ec_dr_args(nvlist_t *nvl, sysevent_t *ev)
{
	sysevent_value_t se_val;

	if (sysevent_lookup_attr(ev, DR_AP_ID, SE_DATA_TYPE_STRING,
	    &se_val) != 0 || se_val.value.sv_string == NULL) {
		return (EINVAL);
	}
	if (nvlist_add_string(nvl, PICLEVENTARG_AP_ID,
	    se_val.value.sv_string)) {
		return (EAGAIN);
	}
	if (sysevent_lookup_attr(ev, DR_HINT, SE_DATA_TYPE_STRING,
	    &se_val) != 0 || se_val.value.sv_string == NULL) {
		if (nvlist_add_string(nvl, PICLEVENTARG_HINT, ""))
			return (EAGAIN);
	} else {
		if (nvlist_add_string(nvl, PICLEVENTARG_HINT,
		    se_val.value.sv_string))
			return (EAGAIN);
	}
	return (0);
}

/*
 * returns 0 if arguments successfully added to nvl, EINVAL if arguments missing
 * from ev and EAGAIN if nvlist_add_string() fails
 */
static int
piclslm_add_ec_dr_req_args(nvlist_t *nvl, sysevent_t *ev)
{
	nvlist_t *nvlist = NULL;
	char *ap_id = NULL;
	char *dr_req = NULL;

	if (sysevent_get_attr_list(ev, &nvlist)) {
		return (EAGAIN);
	}

	if (nvlist_lookup_string(nvlist, DR_AP_ID, &ap_id) != 0 ||
	    ap_id == NULL) {
		nvlist_free(nvlist);
		return (EINVAL);
	}

	if (nvlist_add_string(nvl, PICLEVENTARG_AP_ID, ap_id)) {
		nvlist_free(nvlist);
		return (EAGAIN);
	}

	dr_req = NULL;
	if (nvlist_lookup_string(nvlist, DR_REQ_TYPE, &dr_req) != 0)
		dr_req = "";

	if (nvlist_add_string(nvl, PICLEVENTARG_DR_REQ_TYPE, dr_req)) {
		nvlist_free(nvlist);
		return (EAGAIN);
	}

	if (piclslm_debug)
		syslog(LOG_DEBUG, "piclevent: dr_req_type = %s on %s\n",
		    (dr_req ? dr_req : "Investigate"), ap_id);

	nvlist_free(nvlist);
	return (0);
}

/*
 * piclslm_deliver_event - called by syseventd to deliver an event buffer.
 *			The event buffer is subsequently delivered to
 *			picld.  If picld, is not responding to the
 *			delivery attempt, we will ignore it.
 */
/*ARGSUSED*/
static int
piclslm_deliver_event(sysevent_t *ev, int flag)
{
	sysevent_t	*dupev;
	nvlist_t	*nvl;
	char		*ec;
	char		*esc;
	char		*ename;
	int		retval;
	char		*pack_buf;
	size_t		nvl_size;
	int		rval;

	/*
	 * Filter out uninteresting events
	 */
	ec = sysevent_get_class_name(ev);
	esc = sysevent_get_subclass_name(ev);
	if (piclslm_debug)
		syslog(LOG_INFO,
		    "picl_slm: got sysevent  ev:%p class:%s subclass:%s\n",
		    ev, (ec) ? ec : "NULL", (esc) ? esc : "NULL");
	if ((ec == NULL) || (esc == NULL)) {
		return (0);
	} else if (strcmp(ec, EC_DEVFS) == 0) {
		if (strcmp(esc, ESC_DEVFS_DEVI_ADD) == 0)
			ename = strdup(PICLEVENT_SYSEVENT_DEVICE_ADDED);
		else if (strcmp(esc, ESC_DEVFS_DEVI_REMOVE) == 0)
			ename = strdup(PICLEVENT_SYSEVENT_DEVICE_REMOVED);
		else
			return (0);
	} else if (strcmp(ec, EC_DR) == 0) {
		if (strcmp(esc, ESC_DR_AP_STATE_CHANGE) == 0)
			ename = strdup(PICLEVENT_DR_AP_STATE_CHANGE);
		else if (strcmp(esc, ESC_DR_REQ) == 0)
			ename = strdup(PICLEVENT_DR_REQ);
		else
			return (0);
	} else {
		return (0);
	}

	if (ename == NULL)
		return (EAGAIN);

	/*
	 * Make a copy to expand attribute list
	 */
	dupev = sysevent_dup(ev);
	if (dupev == NULL) {
		free(ename);
		return (EAGAIN);
	}

	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME_TYPE, 0)) {
		free(ename);
		sysevent_free(dupev);
		return (EAGAIN);
	}

	if (strcmp(ec, EC_DEVFS) == 0) {
		rval = piclslm_add_ec_devfs_args(nvl, dupev);
	} else if (strcmp(ec, EC_DR) == 0) {
		if (strcmp(esc, ESC_DR_REQ) == 0) {
			rval = piclslm_add_ec_dr_req_args(nvl, dupev);
		} else {
			rval = piclslm_add_ec_dr_args(nvl, dupev);
		}
	}

	if (rval != 0) {
		free(ename);
		nvlist_free(nvl);
		sysevent_free(dupev);
		return ((rval == EAGAIN) ? EAGAIN : 0);
	}

	pack_buf = NULL;
	if (nvlist_add_string(nvl, PICLEVENTARG_EVENT_NAME, ename) ||
	    nvlist_add_string(nvl, PICLEVENTARG_DATA_TYPE,
	    PICLEVENTARG_PICLEVENT_DATA) ||
	    nvlist_pack(nvl, &pack_buf, &nvl_size, NV_ENCODE_NATIVE, 0)) {
		free(ename);
		nvlist_free(nvl);
		sysevent_free(dupev);
		return (EAGAIN);
	}

	/*
	 * Add nvlist_t to queue
	 */
	(void) mutex_lock(&nvq_lock);
	retval = add_to_queue(pack_buf, nvl_size);
	(void) cond_signal(&nvq_cv);
	(void) mutex_unlock(&nvq_lock);

	nvlist_free(nvl);
	sysevent_free(dupev);
	free(ename);
	return (retval < 0 ? EAGAIN : 0);
}

struct slm_mod_ops *
slm_init(void)
{
	cleanup = 0;

	init_queue();

	(void) mutex_init(&nvq_lock, USYNC_THREAD, NULL);
	(void) cond_init(&nvq_cv, USYNC_THREAD, NULL);

	if (thr_create(NULL, 0, piclslm_deliver_thr,
	    NULL, THR_BOUND, &piclslm_deliver_thr_id) != 0) {
		(void) mutex_destroy(&nvq_lock);
		(void) cond_destroy(&nvq_cv);
		return (NULL);
	}
	return (&piclslm_mod_ops);
}

void
slm_fini(void)
{
	/*
	 * Wait for all events to be sent
	 */
	(void) mutex_lock(&nvq_lock);
	cleanup = 1;
	(void) cond_signal(&nvq_cv);
	(void) mutex_unlock(&nvq_lock);

	/* Wait for delivery thread to exit */
	(void) thr_join(piclslm_deliver_thr_id, NULL, NULL);

	(void) mutex_destroy(&nvq_lock);
	(void) cond_destroy(&nvq_cv);

	if (door_fd >= 0)
		(void) close(door_fd);
	door_fd = -1;
}
