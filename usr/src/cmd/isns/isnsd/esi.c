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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <time.h>
#include <signal.h>
#include <poll.h>

#include "isns_server.h"
#include "isns_cache.h"
#include "isns_obj.h"
#include "isns_pdu.h"
#include "isns_func.h"
#include "isns_qry.h"
#include "isns_msgq.h"
#include "isns_log.h"
#include "isns_sched.h"
#include "isns_scn.h"
#include "isns_esi.h"

/*
 * global variables.
 */

/*
 * local variables.
 */
static ev_t *ev_list = NULL;

static uint32_t stopwatch = 0;
static pthread_mutex_t stw_mtx = PTHREAD_MUTEX_INITIALIZER;

static int wakeup = 0;
static pthread_mutex_t idl_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t idl_cond = PTHREAD_COND_INITIALIZER;

/*
 * external variables.
 */
extern const int UID_ATTR_INDEX[MAX_OBJ_TYPE_FOR_SIZE];

extern boolean_t time_to_exit;

extern msg_queue_t *sys_q;

extern uint64_t esi_threshold;

#ifdef DEBUG
extern void dump_pdu1(isns_pdu_t *);
#endif

/*
 * local functions.
 */
static void *esi_monitor(void *);

/*
 * ****************************************************************************
 *
 * new_esi_portal:
 *	Make a new portal for ESI event.
 *
 * uid	- the portal object UID.
 * ip6	- the portal IPv6 format IP address.
 * port	- the portal port.
 * esip	- the ESI port.
 * return - the new ESI portal.
 *
 * ****************************************************************************
 */
static esi_portal_t *
new_esi_portal(
	uint32_t uid,
	in6_addr_t *ip6,
	uint32_t port,
	uint32_t esip
)
{
	esi_portal_t *p;

	p = (esi_portal_t *)malloc(sizeof (esi_portal_t));
	if (p != NULL) {
		if (((int *)ip6)[0] == 0x00 &&
		    ((int *)ip6)[1] == 0x00 &&
		    ((uchar_t *)ip6)[8] == 0x00 &&
		    ((uchar_t *)ip6)[9] == 0x00 &&
		    ((uchar_t *)ip6)[10] == 0xFF &&
		    ((uchar_t *)ip6)[11] == 0xFF) {
			p->sz = sizeof (in_addr_t);
			p->ip4 = ((uint32_t *)ip6)[3];
		} else {
			p->sz = sizeof (in6_addr_t);
		}
		p->ip6 = ip6;
		p->port = port;
		p->esip = esip;
		p->ref = uid;
		p->so = 0;
		p->next = NULL;
	}

	return (p);
}

/*
 * ****************************************************************************
 *
 * free_esi_portal:
 *	Free a list of portal of one ESI event.
 *
 * p	- the ESI portal.
 *
 * ****************************************************************************
 */
static void
free_esi_portal(
	esi_portal_t *p
)
{
	esi_portal_t *n;

	while (p != NULL) {
		n = p->next;
		free(p->ip6);
		free(p);
		p = n;
	}
}

/*
 * ****************************************************************************
 *
 * ev_new:
 *	Make a new ESI event.
 *
 * uid	- the Entity object UID.
 * eid	- the Entity object name.
 * len	- the length of the name.
 * return - the ESI event.
 *
 * ****************************************************************************
 */
static ev_t *
ev_new(
	uint32_t uid,
	uchar_t *eid,
	uint32_t len
)
{
	ev_t *ev;

	ev = (ev_t *)malloc(sizeof (ev_t));
	if (ev != NULL) {
		if (pthread_mutex_init(&ev->mtx, NULL) != 0 ||
		    (ev->eid = (uchar_t *)malloc(len)) == NULL) {
			free(ev);
			return (NULL);
		}
		ev->uid = uid;
		(void) strcpy((char *)ev->eid, (char *)eid);
		ev->eid_len = len;
		/* initialization time */
		ev->flags = EV_FLAG_INIT;
	}

	return (ev);
}

/*
 * ****************************************************************************
 *
 * cb_portal_uids:
 *	Callback function which makes a copy of the portal child object
 *	UIDs from a Network Entity object.
 *
 * p1	- the Network Entity object.
 * p2	- the lookup control data.
 * return - the number of portal object UIDs.
 *
 * ****************************************************************************
 */
static int
cb_portal_uids(
	void *p1,
	void *p2
)
{
	isns_obj_t *obj = (isns_obj_t *)p1;
	lookup_ctrl_t *lcp = (lookup_ctrl_t *)p2;

	isns_attr_t *attr;

	uint32_t *cuidp;

	uint32_t num = 0;
	uint32_t *p = NULL;

	cuidp = get_child_t(obj, OBJ_PORTAL);
	if (cuidp != NULL) {
		p = (uint32_t *)malloc(*cuidp * sizeof (*p));
		if (p != NULL) {
			num = *cuidp ++;
			(void) memcpy(p, cuidp, num * sizeof (*p));
			lcp->data[1].ptr = (uchar_t *)p;
		}
	}

	attr = &obj->attrs[ATTR_INDEX_ENTITY(ISNS_ENTITY_REG_PERIOD_ATTR_ID)];
	if (attr->tag != 0 && attr->value.ui != 0) {
		lcp->data[2].ui = attr->value.ui;
	} else {
		/* just one second before the end of the world */
		lcp->data[2].ui = INFINITY - 1;
	}

	return (num);
}

/*
 * ****************************************************************************
 *
 * cb_esi_portal:
 *	Callback function which gets ESI port number and ESI interval
 *	from a portal object.
 *
 * p1	- the Portal object.
 * p2	- the lookup control data.
 * return - the ESI interval.
 *
 * ****************************************************************************
 */
static int
cb_esi_portal(
	void *p1,
	void *p2
)
{
	uint32_t intval = 0;

	isns_obj_t *obj;
	lookup_ctrl_t *lcp;

	in6_addr_t *ip;
	uint32_t esip;

	isns_attr_t *attr;

	if (cb_clone_attrs(p1, p2) == 0) {
		obj = (isns_obj_t *)p1;
		lcp = (lookup_ctrl_t *)p2;
		ip = lcp->data[1].ip;
		esip = lcp->data[2].ui;
		if (esip != 0) {
			attr = &obj->attrs[ATTR_INDEX_PORTAL(
			    ISNS_PORTAL_PORT_ATTR_ID)];
			lcp->data[0].ui = attr->value.ui;
			attr = &obj->attrs[ATTR_INDEX_PORTAL(
			    ISNS_ESI_INTERVAL_ATTR_ID)];
			if (attr->tag != 0 && attr->value.ui != 0) {
				intval = attr->value.ui;
			} else {
				intval = DEFAULT_ESI_INTVAL;
			}
		} else {
			free(ip);
		}
	}

	return ((int)intval);
}

/*
 * ****************************************************************************
 *
 * extract_esi_portal:
 *	Extract a list of portal which have an ESI port for an Entity.
 *
 * uid	- the Entity object UID.
 * intval - the ESI interval for returnning.
 * return - the list of portals.
 *
 * ****************************************************************************
 */
static esi_portal_t *
extract_esi_portal(
	uint32_t uid,
	uint32_t *intval
)
{
	esi_portal_t *list = NULL;
	esi_portal_t *p;

	lookup_ctrl_t lc;

	uint32_t num_of_portal;
	uint32_t *portal_uids;

	uint32_t intv;

	/* prepare for looking up entity object */
	SET_UID_LCP(&lc, OBJ_ENTITY, uid);
	lc.data[1].ptr = NULL;
	lc.data[2].ui = INFINITY - 1;

	/* get the array of the portal uid(s) */
	num_of_portal = (uint32_t)cache_lookup(&lc, NULL, cb_portal_uids);
	portal_uids = (uint32_t *)lc.data[1].ptr;
	*intval = lc.data[2].ui;

	/* prepare for looking up portal object(s) */
	SET_UID_LCP(&lc, OBJ_PORTAL, 0);
	lc.id[1] = ISNS_PORTAL_IP_ADDR_ATTR_ID;
	lc.id[2] = ISNS_ESI_PORT_ATTR_ID;
	FOR_EACH_OBJS(portal_uids, num_of_portal, uid, {
		if (uid != 0) {
			lc.data[0].ui = uid;
			intv = cache_lookup(&lc, NULL, cb_esi_portal);
			if (intv != 0) {
				p = new_esi_portal(uid,
				    (in6_addr_t *)lc.data[1].ip,
				    lc.data[0].ui, lc.data[2].ui);
				if (p != NULL) {
					p->next = list;
					list = p;
					if (*intval > intv) {
						*intval = intv;
					}
				}
			}
		}
	});

	/* free up the portal uid array */
	free(portal_uids);

	return (list);
}

/*
 * ****************************************************************************
 *
 * ev_add:
 *	Add an ESI event.
 *
 * ev	- the ESI event.
 * init	- 0: initialization time, otherwise not.
 * return - error code.
 *
 * ****************************************************************************
 */
static int
ev_add(
	ev_t *ev,
	int init
)
{
	uint32_t intval;
	esi_portal_t *p;

	double rnd;
	uint32_t t = 0;

	/* get the portal(s) which are registered for ESI monitoring */
	/* and the second interval for ESI or registration expiration */
	p = extract_esi_portal(ev->uid, &intval);
	ev->intval = intval;
	if (p != NULL) {
		ev->type = EV_ESI;
		ev->portal = p;
		/* avoid running everything at the same time */
		if (init != 0) {
			/* generate random number within range (0, 1] */
			rnd = (rand() + 1) / (double)(RAND_MAX + 1);
			t = (uint32_t)(intval * rnd);
		}
	} else {
		/* no portal is registered for ESI monitoring, make */
		/* an entry for entity registration expiration */
		ev->type = EV_REG_EXP;
		ev->portal = NULL;
		if (init != 0) {
			t = intval;
		}
	}

	/* schedule the event */
	return (el_add(ev, t, NULL));
}

/*
 * global functions.
 */

/*
 * ****************************************************************************
 *
 * sigalrm:
 *	The signal handler for SIGALRM, the ESI proc uses the SIGALRM
 *	for waking up to perform the client status inquery.
 *
 * sig	- the signal.
 *
 * ****************************************************************************
 */
/*ARGSUSED*/
void
sigalrm(
	int sig
)
{
	/* wake up the idle */
	(void) pthread_mutex_lock(&idl_mtx);
	wakeup = 1; /* wake up naturally */
	(void) pthread_cond_signal(&idl_cond);
	(void) pthread_mutex_unlock(&idl_mtx);
}

/*
 * ****************************************************************************
 *
 * esi_load:
 *	Load an ESI event from data store.
 *
 * uid	- the Entity object UID.
 * eid	- the Entity object name.
 * len	- the length of the name.
 * return - error code.
 *
 * ****************************************************************************
 */
int
esi_load(
	uint32_t uid,
	uchar_t *eid,
	uint32_t len
)
{
	int ec = 0;

	/* make a new event */
	ev_t *ev = ev_new(uid, eid, len);

	/* put the new event to the list */
	if (ev != NULL) {
		ev->next = ev_list;
		ev_list = ev;
	} else {
		ec = ISNS_RSP_INTERNAL_ERROR;
	}

	return (ec);
}

/*
 * ****************************************************************************
 *
 * verify_esi_portal:
 *	Verify ESI port and add the ESI entries after the ESI are loaded.
 *
 * return - error code.
 *
 * ****************************************************************************
 */
int
verify_esi_portal(
)
{
	int ec = 0;

	ev_t *ev;

	/* add each event from the list */
	while (ev_list != NULL && ec == 0) {
		ev = ev_list;
		ev_list = ev->next;
		ev->next = NULL;
		ec = ev_add(ev, 1);
	}

	return (ec);
}

/*
 * ****************************************************************************
 *
 * esi_add:
 *	Add a new ESI event when a new Entity is registered.
 *
 * uid	- the Entity object UID.
 * eid	- the Entity object name.
 * len	- the length of the name.
 * return - error code.
 *
 * ****************************************************************************
 */
int
esi_add(
	uint32_t uid,
	uchar_t *eid,
	uint32_t len
)
{
	int ec = 0;

	/* make a new event */
	ev_t *ev = ev_new(uid, eid, len);

	if (ev != NULL) {
		/* interrupt idle */
		ev->flags |= EV_FLAG_WAKEUP;
		ec = ev_add(ev, 0);
	} else {
		ec = ISNS_RSP_INTERNAL_ERROR;
	}

	return (ec);
}

/*
 * ****************************************************************************
 *
 * esi_remove:
 *	Remove an ESI event immediately.
 *
 * uid	- the Entity object UID.
 * return - always successful.
 *
 * ****************************************************************************
 */
int
esi_remove(
	uint32_t uid
)
{
	(void) el_remove(uid, 0, 0);

	return (0);
}

/*
 * ****************************************************************************
 *
 * esi_remove_obj:
 *	Update an ESI event when a Entity object or a Portal object is
 *	removed from server. If the object is being removed because of
 *	ESI failure, the ESI event will be removed with a pending time,
 *	otherwise, the ESI will be removed immediately.
 *
 * obj	- the object being removed.
 * pending - the pending flag.
 * return - always successful.
 *
 * ****************************************************************************
 */
int
esi_remove_obj(
	const isns_obj_t *obj,
	int pending
)
{
	uint32_t puid, uid;

	switch (obj->type) {
	case OBJ_PORTAL:
		puid = get_parent_uid(obj);
		uid = get_obj_uid(obj);
		break;
	case OBJ_ENTITY:
		puid = get_obj_uid(obj);
		uid = 0;
		break;
	default:
		puid = 0;
		break;
	}

	if (puid != 0) {
		(void) el_remove(puid, uid, pending);
	}

	return (0);
}

/*
 * ****************************************************************************
 *
 * get_stopwatch:
 *	Get the stopwatch. It might need to signal the condition to
 *	wake up the idle so the stopwatch gets updated.
 *
 * flag	- wake up flag.
 * return - the stopwatch.
 *
 * ****************************************************************************
 */
uint32_t
get_stopwatch(
	int flag
)
{
	uint32_t t;

	/* not re-schedule, wake up idle */
	(void) pthread_mutex_lock(&idl_mtx);
	if (flag != 0) {
		wakeup = 2; /* wake up manually */
		(void) pthread_cond_signal(&idl_cond);
	} else {
		wakeup = 0; /* clear previous interruption */
	}
	(void) pthread_mutex_unlock(&idl_mtx);

	/* get most current time */
	(void) pthread_mutex_lock(&stw_mtx);
	t = stopwatch;
	(void) pthread_mutex_unlock(&stw_mtx);

	return (t);
}

/*
 * ****************************************************************************
 *
 * ev_intval:
 *	Get the time interval of an ESI event.
 *
 * p	- the ESI event.
 * return - the time interval.
 *
 * ****************************************************************************
 */
uint32_t
ev_intval(
	void *p
)
{
	return (((ev_t *)p)->intval);
}

/*
 * ****************************************************************************
 *
 * ev_match:
 *	Check the ESI event maching an Entity object.
 *
 * p	- the ESI event.
 * uid	- the Entity object UID.
 * return - 1: match, otherwise not.
 *
 * ****************************************************************************
 */
int
ev_match(
	void *p,
	uint32_t uid
)
{
	if (((ev_t *)p)->uid == uid) {
		return (1);
	} else {
		return (0);
	}
}

/*
 * ****************************************************************************
 *
 * ev_remove:
 *	Remove a portal or an ESI event. If all of ESI portal has been
 *	removed, the ESI event will be marked as removal pending, which
 *	will result in removing the Entity object after the pending time.
 *
 * p	- the ESI event.
 * portal_uid	- the Portal object UID.
 * flag	- 0: the ESI is currently in use, otherwise it is scheduled.
 * pending	- flag for the ESI removal pending.
 * return - 0: the ESI is physically removed, otherwise not.
 *
 * ****************************************************************************
 */
int
ev_remove(
	void *p,
	uint32_t portal_uid,
	int flag,
	int pending
)
{
	ev_t *ev = (ev_t *)p;
	esi_portal_t **pp, *portal;

	int has_portal = 0;
	int state;

	/* remove one portal only */
	if (portal_uid != 0) {
		pp = &ev->portal;
		portal = *pp;
		while (portal != NULL) {
			/* found the match portal */
			if (portal->ref == portal_uid) {
				/* mark it as removed */
				portal->ref = 0;
				if (flag != 0) {
					/* not in use, remove it physically */
					*pp = portal->next;
					portal->next = NULL;
					free_esi_portal(portal);
				} else {
					pp = &portal->next;
				}
			} else {
				/* one or more esi portals are available */
				if (portal->ref != 0) {
					has_portal = 1;
				}
				pp = &portal->next;
			}
			portal = *pp;
		}
	}

	/* no portal available */
	if (has_portal == 0) {
		state = (pending << 1) | flag;
		switch (state) {
		case 0x0:
			/* mark the event as removed */
			ev->flags |= EV_FLAG_REMOVE;
			isnslog(LOG_DEBUG, "ev_remove",
			    "%s [%d] is marked as removed.",
			    ev->type == EV_ESI ? "ESI" : "REG_EXP",
			    ev->uid);
			break;
		case 0x1:
			/* physically remove the event */
			ev_free(ev);
			break;
		case 0x2:
		case 0x3:
			/* mark the event as removal pending */
			isnslog(LOG_DEBUG, "ev_remove",
			    "%s [%d] is marked as removal pending.",
			    ev->type == EV_ESI ? "ESI" : "REG_EXP",
			    ev->uid);
			ev->flags |= EV_FLAG_REM_P1;
			has_portal = 1;
			break;
		default:
			break;
		}
	} else {
		isnslog(LOG_DEBUG, "ev_remove", "%s [%d] removed portal %d.",
		    ev->type == EV_ESI ? "ESI" : "REG_EXP",
		    ev->uid, portal_uid);
	}

	return (has_portal);
}

/*
 * ****************************************************************************
 *
 * ev_free:
 *	Free an ESI event.
 *
 * p	- the ESI event.
 *
 * ****************************************************************************
 */
void
ev_free(
	void *p
)
{
	ev_t *ev = (ev_t *)p;

	/* free up all of portals */
	free_esi_portal(ev->portal);

	isnslog(LOG_DEBUG, "ev_free",
	    "%s [%d] is physically removed.",
	    ev->type == EV_ESI ? "ESI" : "REG_EXP",
	    ev->uid);

	free(ev->eid);

	/* free the event */
	free(ev);
}

/*
 * ****************************************************************************
 *
 * evf_init:
 *	Check the initial flag of an ESI event.
 *
 * p	- the ESI event.
 * return - 0: not initial, otherwise yes.
 *
 * ****************************************************************************
 */
int
evf_init(
	void *p
)
{
	return (((ev_t *)p)->flags & EV_FLAG_INIT);
}

/*
 * ****************************************************************************
 *
 * evf_again:
 *	Check the again flag of an ESI event.
 *	(this flag might be eliminated and use the init flag.)
 *
 * p	- the ESI event.
 * return - 0: not again, otherwise yes.
 *
 * ****************************************************************************
 */
int
evf_again(
	void *p
)
{
	return (((ev_t *)p)->flags & EV_FLAG_AGAIN);
}

/*
 * ****************************************************************************
 *
 * evf_wakeup:
 *	Check the wakeup flag of an ESI event. The idle might need to
 *	wake up before the event is scheduled.
 *
 * p	- the ESI event.
 * return - 0: no wakeup, otherwise yes.
 *
 * ****************************************************************************
 */
int
evf_wakeup(
	void *p
)
{
	return (((ev_t *)p)->flags & EV_FLAG_WAKEUP);
}

/*
 * ****************************************************************************
 *
 * evf_rem:
 *	Check the removal flag of an ESI event. The ESI entry might be
 *	marked as removal.
 *
 * p	- the ESI event.
 * return - 0: not removed, otherwise yes.
 *
 * ****************************************************************************
 */
int
evf_rem(
	void *p
)
{
	return (((ev_t *)p)->flags & EV_FLAG_REMOVE);
}

/*
 * ****************************************************************************
 *
 * evf_rem_pending:
 *	Check the removal pending flag of an ESI event. The ESI entry
 *	might be marked as removal pending. If it is, we will switch the
 *	event type and change the time interval.
 *
 * p	- the ESI event.
 * return - 0: not removal pending, otherwise yes.
 *
 * ****************************************************************************
 */
int
evf_rem_pending(
	void *p
)
{
	ev_t *ev = (ev_t *)p;
	if ((ev->flags & EV_FLAG_REM_P) != 0) {
		if (ev->type != EV_REG_EXP) {
			isnslog(LOG_DEBUG, "ev_rem_pending",
			    "%s [%d] is changed to REG_EXP.",
			    ev->type == EV_ESI ? "ESI" : "REG_EXP",
			    ev->uid);
			ev->type = EV_REG_EXP;
			ev->intval *= 2; /* after 2 ESI interval */
		}
		return (1);
	}

	return (0);
}

/*
 * ****************************************************************************
 *
 * evf_zero:
 *	Reset the event flag.
 *
 * p	- the ESI event.
 *
 * ****************************************************************************
 */
void
evf_zero(
	void *p
)
{
	ev_t *ev = (ev_t *)p;

	/* not acutally clear it, need to set again flag */
	/* and keep the removal pending flag */
	ev->flags = EV_FLAG_AGAIN | (ev->flags & EV_FLAG_REM_P);
}

/*
 * ****************************************************************************
 *
 * evl_append:
 *	Append an ESI event to the list, the list contains all of
 *	ESI events which are being processed at present.
 *
 * p	- the ESI event.
 *
 * ****************************************************************************
 */
void
evl_append(
	void *p
)
{
	ev_t *ev;

	ev = (ev_t *)p;
	ev->next = ev_list;
	ev_list = ev;
}

/*
 * ****************************************************************************
 *
 * evl_strip:
 *	Strip off an ESI event from the list after the event is being
 *	processed, it will be scheduled in the scheduler.
 *
 * p	- the ESI event.
 *
 * ****************************************************************************
 */
void
evl_strip(
	void *p
)
{
	ev_t **evp = &ev_list;
	ev_t *ev = *evp;

	while (ev != NULL) {
		if (ev == p) {
			*evp = ev->next;
			break;
		}
		evp = &ev->next;
		ev = *evp;
	}
}

/*
 * ****************************************************************************
 *
 * evl_remove:
 *	Remove an ESI event or a portal of an ESI event from the event list.
 *
 * id1	- the Entity object UID.
 * id2	- the Portal object UID.
 * pending - the pending flag.
 * return - 1: found a match event, otherwise not.
 *
 * ****************************************************************************
 */
int
evl_remove(
	uint32_t id1,
	uint32_t id2,
	int pending
)
{
	ev_t *ev = ev_list;

	while (ev != NULL) {
		/* found it */
		if (ev_match(ev, id1) != 0) {
			/* lock the event */
			(void) pthread_mutex_lock(&ev->mtx);
			/* mark it as removed */
			(void) ev_remove(ev, id2, 0, pending);
			/* unlock the event */
			(void) pthread_mutex_unlock(&ev->mtx);
			/* tell caller removal is done */
			return (1);
		}
		ev = ev->next;
	}

	/* not found it */
	return (0);
}

#define	ALARM_MAX	(21427200)

/*
 * ****************************************************************************
 *
 * idle:
 *	Idle for certain amount of time or a wakeup signal is recieved.
 *
 * t	- the idle time.
 * return - the time that idle left.
 *
 * ****************************************************************************
 */
static int
idle(
	uint32_t t
)
{
	uint32_t t1, t2, t3 = 0;
	int idl_int = 0;

	/* hold the mutex for stopwatch update */
	(void) pthread_mutex_lock(&stw_mtx);

	do {
		if (t > ALARM_MAX) {
			t1 = ALARM_MAX;
		} else {
			t1 = t;
		}

		/* start alarm */
		(void) alarm(t1);

		/* hold the mutex for idle condition */
		(void) pthread_mutex_lock(&idl_mtx);

		/* wait on condition variable to wake up idle */
		while (wakeup == 0) {
			(void) pthread_cond_wait(&idl_cond, &idl_mtx);
		}
		if (wakeup == 2) {
			idl_int = 1;
		}
		/* clean wakeup flag */
		wakeup = 0;

		/* release the mutex for idle condition */
		(void) pthread_mutex_unlock(&idl_mtx);

		/* stop alarm */
		t2 = alarm(0);

		/* seconds actually slept */
		t3 += t1 - t2;
		t -= t3;
	} while (t > 0 && idl_int == 0);

	/* increate the stopwatch by the actually slept time */
	stopwatch += t3;

	/* release the mutex after stopwatch is updated */
	(void) pthread_mutex_unlock(&stw_mtx);

	/* return the amount of time which is not slept */
	return (t);
}

/*
 * ****************************************************************************
 *
 * ev_ex:
 *	Execute an event. To inquiry the client status or
 *	perform registration expiration.
 *
 * ev	- the event.
 *
 * ****************************************************************************
 */
static void
ev_ex(
	ev_t *ev
)
{
	pthread_t tid;

	switch (ev->type) {
	case EV_ESI:
		if (pthread_create(&tid, NULL,
		    esi_monitor, (void *)ev) != 0) {
			isnslog(LOG_DEBUG, "ev_ex", "pthread_create() failed.");
			/* reschedule for next occurence */
			(void) el_add(ev, 0, NULL);
		} else {
			/* increase the thread ref count */
			inc_thr_count();
		}
		break;
	case EV_REG_EXP:
		(void) queue_msg_set(sys_q, REG_EXP, (void *)ev);
		break;
	default:
		break;
	}
}

/*
 * ****************************************************************************
 *
 * esi_proc:
 *	ESI thread entry, which:
 *	1: fetch an event from schedule,
 *	2: idle for some time,
 *	3: execute the event or re-schedule it,
 *	4: repeat from step 1 before server is being shutdown.
 *
 * arg	- the thread argument.
 *
 * ****************************************************************************
 */
/*ARGSUSED*/
void *
esi_proc(
	void *arg
)
{
	uint32_t t, t1, pt;
	ev_t *ev;

	void *evp;

	while (time_to_exit == B_FALSE) {
		ev = (ev_t *)el_first(&pt);

		/* caculate the idle time */
		if (ev != NULL) {
			if (pt > stopwatch) {
				t = pt - stopwatch;
			} else {
				t = 0;
			}
		} else {
			t = INFINITY;
		}

		do {
			/* block for a certain amount of time */
			if (t > 0) {
				isnslog(LOG_DEBUG, "esi_proc",
				    "idle for %d seconds.", t);
				t1 = idle(t);
			} else {
				t1 = 0;
			}
			if (t1 > 0) {
				isnslog(LOG_DEBUG, "esi_proc",
				    "idle interrupted after idle for "
				    "%d seconds.", t - t1);
			}
			if (time_to_exit != B_FALSE) {
				ev = NULL; /* force break */
			} else if (ev != NULL) {
				if (t1 > 0) {
					/* not naturally waken up */
					/* reschedule current event */
					evp = NULL;
					(void) el_add(ev, pt, &evp);
					ev = (ev_t *)evp;
					t = t1;
				} else {
					/* excute */
					isnslog(LOG_DEBUG, "esi_proc",
					    "excute the cron job[%d].",
					    ev->uid);
					ev_ex(ev);
					ev = NULL;
				}
			}
		} while (ev != NULL);
	}

	return (NULL);
}

/*
 * ****************************************************************************
 *
 * esi_ping:
 *	Ping the client with the ESI retry threshold for status inquiry.
 *
 * so	- the socket descriptor.
 * pdu	- the ESI packet.
 * pl	- the length of packet.
 * return - 1: status inquired, otherwise not.
 *
 * ****************************************************************************
 */
static int
esi_ping(
	int so,
	isns_pdu_t *pdu,
	size_t pl
)
{
	int try_cnt = 0;
	isns_pdu_t *rsp = NULL;
	size_t rsp_sz;

	int alive = 0;

	do {
		if (isns_send_pdu(so, pdu, pl) == 0) {
			if (isns_rcv_pdu(so, &rsp, &rsp_sz,
			    ISNS_RCV_SHORT_TIMEOUT) > 0) {
#ifdef DEBUG
				dump_pdu1(rsp);
#endif
				alive = 1;
				break;
			}
		} else {
			/* retry after 1 second */
			(void) sleep(1);
		}
		try_cnt ++;
	} while (try_cnt < esi_threshold);

	if (rsp != NULL) {
		free(rsp);
	}

	return (alive);
}

/*
 * ****************************************************************************
 *
 * esi_monitor:
 *	Child thread for client status mornitoring.
 *
 * arg	- the ESI event.
 *
 * ****************************************************************************
 */
static void *
esi_monitor(
	void *arg
)
{
	ev_t *ev = (ev_t *)arg;

	esi_portal_t *p;
	int so;

	isns_pdu_t *pdu = NULL;
	size_t sz;
	size_t pl;
	size_t half;

	time_t t;

	int feedback;

	/* lock the event for esi monitoring */
	(void) pthread_mutex_lock(&ev->mtx);

	if (evf_rem(ev) != 0) {
		goto mon_done;
	} else if (evf_rem_pending(ev) != 0) {
		goto mon_done;
	}

	/* timestamp */
	t = time(NULL);

	/* allocate ESI PDU */
	if (pdu_reset_esi(&pdu, &pl, &sz) != 0 ||
	    pdu_add_tlv(&pdu, &pl, &sz,
	    ISNS_TIMESTAMP_ATTR_ID, 8, (void *)&t, 1) != 0 ||
	    pdu_add_tlv(&pdu, &pl, &sz,
	    ISNS_EID_ATTR_ID, ev->eid_len, (void *)ev->eid, 0) != 0) {
		/* no memory, will retry later */
		goto mon_done;
	}

	/* set pdu head */
	pdu->version = htons((uint16_t)ISNSP_VERSION);
	pdu->func_id = htons((uint16_t)ISNS_ESI);
	pdu->xid = htons(get_server_xid());

	/* keep the current lenght of the playload */
	half = pl;

	p = ev->portal;
	while (p != NULL) {
		if (p->ref != 0 &&
		    /* skip IPv6 portal */
		    p->sz != sizeof (in6_addr_t) &&
		    pdu_add_tlv(&pdu, &pl, &sz,
		    ISNS_PORTAL_IP_ADDR_ATTR_ID,
		    sizeof (in6_addr_t), (void *)p->ip6, 0) == 0 &&
		    pdu_add_tlv(&pdu, &pl, &sz,
		    ISNS_PORTAL_PORT_ATTR_ID,
		    4, (void *)p->port, 0) == 0) {
			/* connect once */
			so = connect_to(p->sz, p->ip4, p->ip6, p->esip);
			if (so != -1) {
				feedback = esi_ping(so, pdu, pl);
				(void) close(so);
				/* p->so = so; */
			} else {
				/* cannot connect, portal is dead */
				feedback = 0;
			}
			if (feedback == 0) {
				isnslog(LOG_DEBUG, "esi_monitor",
				    "ESI ping failed.");
				(void) queue_msg_set(sys_q, DEAD_PORTAL,
				    (void *)p->ref);
			} else {
				goto mon_done;
			}
		}
		pl = half;
		p = p->next;
	}

mon_done:
	/* unlock the event after esi monitoring is done */
	(void) pthread_mutex_unlock(&ev->mtx);

	/* clean up pdu */
	if (pdu != NULL) {
		free(pdu);
	}

	/* set reschedule flags */
	ev->flags |= EV_FLAG_WAKEUP;

	/* reschedule for next occurence */
	(void) el_add(ev, 0, NULL);

	/* decrease the thread ref count */
	dec_thr_count();

	return (NULL);
}

/*
 * ****************************************************************************
 *
 * portal_dies:
 *	Handles the dead portal that ESI detected.
 *
 * uid	- the Portal object UID.
 *
 * ****************************************************************************
 */
void
portal_dies(
	uint32_t uid
)
{
	int ec = 0;

	lookup_ctrl_t lc;

	/* prepare the lookup control for deregistration */
	SET_UID_LCP(&lc, OBJ_PORTAL, uid);

	/* lock the cache for object deregistration */
	(void) cache_lock_write();

	/* deregister the portal */
	ec = dereg_object(&lc, 1);

	/* unlock cache and sync with data store */
	(void) cache_unlock_sync(ec);
}

/*
 * ****************************************************************************
 *
 * portal_dies:
 *	Handles the Entity registration expiration.
 *
 * p	- the ESI event.
 *
 * ****************************************************************************
 */
void
reg_expiring(
	void *p
)
{
	int ec = 0;
	ev_t *ev = (ev_t *)p;
	lookup_ctrl_t lc;

	/* prepare the lookup control for deregistration */
	SET_UID_LCP(&lc, OBJ_ENTITY, ev->uid);

	/* lock the cache for object deregistration */
	(void) cache_lock_write();

	if (evf_rem(ev) == 0) {
		/* deregister the entity */
		ec = dereg_object(&lc, 0);

		/* unlock cache and sync with data store */
		ec = cache_unlock_sync(ec);

		if (ec == 0) {
			/* successfuk, mark ev as removed */
			ev->flags |= EV_FLAG_REMOVE;
		} else {
			/* failed, retry after 3 mintues */
			ev->intval = 3 * 60;
			isnslog(LOG_DEBUG, "reg_expiring",
			    "dereg failed, retry after 3 mintues.");
		}
	} else {
		/* ev is marked as removed, no need to dereg */
		(void) cache_unlock_nosync();
	}

	/* reschedule it for next occurence */
	(void) el_add(ev, 0, NULL);
}
