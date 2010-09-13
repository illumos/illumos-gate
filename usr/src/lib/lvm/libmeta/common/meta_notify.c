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
 * Copyright 1995-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Just in case we're not in a build environment, make sure that
 * TEXT_DOMAIN gets set to something.
 */
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif

/*
 * libmeta wrappers for event notification
 */

#include <meta.h>
#include <sys/lvm/md_notify.h>

#if defined(DEBUG)
#include <assert.h>
#endif /* DEBUG */

struct tag2obj_type {
	md_tags_t	tag;
	ev_obj_t	obj;
} tag2obj_typetab[] =
{
	{ TAG_EMPTY,		EVO_EMPTY	},
	{ TAG_METADEVICE,	EVO_METADEV	},
	{ TAG_REPLICA,		EVO_REPLICA	},
	{ TAG_HSP,		EVO_HSP		},
	{ TAG_HS,		EVO_HS		},
	{ TAG_SET,		EVO_SET		},
	{ TAG_DRIVE,		EVO_DRIVE	},
	{ TAG_HOST,		EVO_HOST	},
	{ TAG_MEDIATOR,		EVO_MEDIATOR	},
	{ TAG_UNK,		EVO_UNSPECIFIED	},

	{ TAG_LAST,		EVO_LAST	}
};

struct evdrv2evlib_type {
	md_event_type_t	drv;
	evid_t		lib;
} evdrv2evlib_typetab[] =
{
	{ EQ_EMPTY,		EV_EMPTY		},
	{ EQ_CREATE,		EV_CREATE		},
	{ EQ_DELETE,		EV_DELETE		},
	{ EQ_ADD,		EV_ADD			},
	{ EQ_REMOVE,		EV_REMOVE		},
	{ EQ_REPLACE,		EV_REPLACE		},
	{ EQ_MEDIATOR_ADD,	EV_MEDIATOR_ADD		},
	{ EQ_MEDIATOR_DELETE,	EV_MEDIATOR_DELETE	},
	{ EQ_HOST_ADD,		EV_HOST_ADD		},
	{ EQ_HOST_DELETE,	EV_HOST_DELETE		},
	{ EQ_DRIVE_ADD,		EV_DRIVE_ADD		},
	{ EQ_DRIVE_DELETE,	EV_DRIVE_DELETE		},
	{ EQ_RENAME_SRC,	EV_RENAME_SRC		},
	{ EQ_RENAME_DST,	EV_RENAME_DST		},
	{ EQ_INIT_START,	EV_INIT_START		},
	{ EQ_INIT_FAILED,	EV_INIT_FAILED		},
	{ EQ_INIT_FATAL,	EV_INIT_FATAL		},
	{ EQ_INIT_SUCCESS,	EV_INIT_SUCCESS		},
	{ EQ_IOERR,		EV_IOERR		},
	{ EQ_ERRED,		EV_ERRED		},
	{ EQ_LASTERRED,		EV_LASTERRED		},
	{ EQ_OK,		EV_OK			},
	{ EQ_ENABLE,		EV_ENABLE		},
	{ EQ_RESYNC_START,	EV_RESYNC_START		},
	{ EQ_RESYNC_FAILED,	EV_RESYNC_FAILED	},
	{ EQ_RESYNC_SUCCESS,	EV_RESYNC_SUCCESS	},
	{ EQ_RESYNC_DONE,	EV_RESYNC_DONE		},
	{ EQ_HOTSPARED,		EV_HOTSPARED		},
	{ EQ_HS_FREED,		EV_HS_FREED		},
	{ EQ_TAKEOVER,		EV_TAKEOVER		},
	{ EQ_RELEASE,		EV_RELEASE		},
	{ EQ_OPEN_FAIL,		EV_OPEN_FAIL		},
	{ EQ_OFFLINE,		EV_OFFLINE		},
	{ EQ_ONLINE,		EV_ONLINE		},
	{ EQ_GROW,		EV_GROW			},
	{ EQ_DETACH,		EV_DETACH		},
	{ EQ_DETACHING,		EV_DETACHING		},
	{ EQ_ATTACH,		EV_ATTACH		},
	{ EQ_ATTACHING,		EV_ATTACHING		},
	{ EQ_CHANGE,		EV_CHANGE		},
	{ EQ_EXCHANGE,		EV_EXCHANGE		},
	{ EQ_REGEN_START,	EV_REGEN_START		},
	{ EQ_REGEN_DONE,	EV_REGEN_DONE		},
	{ EQ_REGEN_FAILED,	EV_REGEN_FAILED		},
	{ EQ_USER,		EV_USER			},
	{ EQ_NOTIFY_LOST,	EV_NOTIFY_LOST		},

	{ EQ_LAST,		EV_LAST }
};

static ev_obj_t
dev2tag(md_dev64_t dev, set_t setno, md_error_t *ep)
{
	mdname_t	*np	= NULL;
	mdsetname_t	*sp	= NULL;
	ev_obj_t	 obj	= EVO_METADEV;
	char		*miscname;

	if ((sp = metasetnosetname(setno, ep)) == NULL) {
		goto out;
	}
	if (!(np = metamnumname(&sp, meta_getminor(dev), 0, ep))) {
		goto out;
	}

	/* need to invalidate name in case rename or delete/create done */
	meta_invalidate_name(np);

	if (!(miscname = metagetmiscname(np, ep))) {
		goto out;
	}
	if (strcmp(miscname, MD_STRIPE) == 0) {
		obj = EVO_STRIPE;
	} else if (strcmp(miscname, MD_MIRROR) == 0) {
		obj = EVO_MIRROR;
	} else if (strcmp(miscname, MD_RAID) == 0) {
		obj = EVO_RAID5;
	} else if (strcmp(miscname, MD_TRANS) == 0) {
		obj = EVO_TRANS;
	}
out:
	return (obj);
}

static ev_obj_t
tagdrv_2_objlib(md_tags_t tag)
{
	int i;

	for (i = 0; tag2obj_typetab[i].tag != TAG_LAST; i++) {
		if (tag2obj_typetab[i].tag == tag)
			return (tag2obj_typetab[i].obj);
	}
	return (EVO_UNSPECIFIED);
}

static md_tags_t
objlib_2_tagdrv(ev_obj_t obj)
{
	int i;

	for (i = 0; tag2obj_typetab[i].tag != TAG_LAST; i++) {
		if (tag2obj_typetab[i].obj == obj)
			return (tag2obj_typetab[i].tag);
	}
	return (TAG_UNK);
}


static evid_t
evdrv_2_evlib(md_event_type_t drv_ev)
{
	int	i;

	for (i = 0; evdrv2evlib_typetab[i].drv != EQ_LAST; i++) {
		if (evdrv2evlib_typetab[i].drv == drv_ev)
			return (evdrv2evlib_typetab[i].lib);
	}
	return (EV_UNK);
}

static md_event_type_t
evlib_2_evdrv(evid_t lib_ev)
{
	int	i;

	for (i = 0; evdrv2evlib_typetab[i].drv != EQ_LAST; i++) {
		if (evdrv2evlib_typetab[i].lib == lib_ev)
			return (evdrv2evlib_typetab[i].drv);
	}
	return (EQ_EMPTY);
}


/*
 * meta_event
 *  returns 0 on succcess or < 0 to indicate error.
 *  abs(return code) = errno
 */
static int
meta_event(md_event_ioctl_t *evctl, md_error_t *ep)
{
	int	l;

	if (!evctl || !ep)
		return (-EINVAL);

	l = strlen(evctl->mdn_name);
	if ((l == 0 && evctl->mdn_cmd != EQ_PUT) || l >= MD_NOTIFY_NAME_SIZE) {
		return (-EINVAL);
	}

	MD_SETDRIVERNAME(evctl, MD_NOTIFY, 0);
	mdclrerror(ep);
	errno = 0;

	if (metaioctl(MD_IOCNOTIFY, evctl, ep, evctl->mdn_name) != 0) {
		if (errno == 0) {
			errno = EINVAL;
		}
		if (mdisok(ep)) {
			(void) mdsyserror(ep, errno, evctl->mdn_name);
		}
		return (-errno);
	}

	return (0);
}

static void
init_evctl(char *qname,
	md_tags_t tag,
	md_event_type_t ev,
	uint_t flags,
	set_t set,
	md_dev64_t dev,
	md_event_cmds_t cmd,
	u_longlong_t udata,
	md_event_ioctl_t *evctlp)
{

	assert(evctlp);

	(void) memset(evctlp, 0, sizeof (md_event_ioctl_t));

	evctlp->mdn_magic	= MD_EVENT_ID;
	evctlp->mdn_rev		= MD_NOTIFY_REVISION;

	if (qname)
		(void) strncpy(evctlp->mdn_name, qname, MD_NOTIFY_NAME_SIZE-1);
	else
		(void) memset(evctlp->mdn_name, 0, MD_NOTIFY_NAME_SIZE);

	evctlp->mdn_tag		= tag;
	evctlp->mdn_event	= ev;
	evctlp->mdn_flags	= flags;
	evctlp->mdn_set		= set;
	evctlp->mdn_dev		= dev;
	evctlp->mdn_cmd		= cmd;
	evctlp->mdn_user	= udata;
}

/*
 * meta_notify_createq
 * - creates an eventq
 * - returns 0 on success or errno and sets ep
 */
int
meta_notify_createq(char *qname, ulong_t flags, md_error_t *ep)
{
	md_event_ioctl_t	evctl;
	int			err	= 0;

	mdclrerror(ep);
	if (!qname || strlen(qname) == 0) {
		(void) mdsyserror(ep, EINVAL,
		    dgettext(TEXT_DOMAIN,
			"null or zero-length queue name"));
		return (EINVAL);
	}

	init_evctl(qname,
			TAG_EMPTY,
			EQ_EMPTY,
			(flags & EVFLG_PERMANENT) != 0? EQ_Q_PERM: 0,
			/* set */ 0,
			/* dev */ 0,
			EQ_ON,
			/* user-defined event data */ 0,
			&evctl);

	err = meta_event(&evctl, ep);

	if (err == -EEXIST && !(flags & EVFLG_EXISTERR)) {
		err = 0;
		mdclrerror(ep);
	}
	if (!mdisok(ep) && mdanysyserror(ep)) {
		err = (ep)->info.md_error_info_t_u.ds_error.errnum;
	}
	return (-err);
}

/*
 * meta_notify_deleteq
 * - deletes an eventq
 * - free's any underlying resources
 * - returns 0 on success or errno and sets ep
 */
int
meta_notify_deleteq(char *qname, md_error_t *ep)
{
	md_event_ioctl_t	evctl;
	int			err;

	init_evctl(qname,
			TAG_EMPTY,
			EQ_EMPTY,
			/* flags */ 0,
			/* set */ 0,
			/* dev */ 0,
			EQ_OFF,
			/* user-defined event data */ 0,
			&evctl);

	err = meta_event(&evctl, ep);
	return (-err);
}

/*
 * meta_notify_validq
 * - verifies that the queue exists
 * - returns true or false, ep may be changed as a side-effect
 */
bool_t
meta_notify_validq(char *qname, md_error_t *ep)
{
	md_event_ioctl_t	evctl;

	init_evctl(qname,
			TAG_EMPTY,
			EQ_EMPTY,
			/* flags */ 0,
			/* set */ 0,
			/* dev */ 0,
			EQ_ON,
			/* user-defined event data */ 0,
			&evctl);

	return (meta_event(&evctl, ep) == -EEXIST);
}

/*
 * meta_notify_listq
 * - returns number of (currently) active queus or -errno
 * - allocates qnames array and sets user's pointer to it,
 *   fills in array with vector of qnames
 */
int
meta_notify_listq(char ***qnames, md_error_t *ep)
{

#ifdef lint
	qnames = qnames;
#endif /* lint */

	mdclrerror(ep);
	(void) mdsyserror(ep, EOPNOTSUPP, "EOPNOTSUPP");
	return (-EOPNOTSUPP);
}

/*
 * meta_notify_flushq
 * - calls the underlying notify driver to flush all events
 *   from the named queue
 * - returns 0 on success or errno and sets ep as necessary
 */
int
meta_notify_flushq(char *qname, md_error_t *ep)
{

#ifdef lint
	qname = qname;
#endif /* lint */

	mdclrerror(ep);
	(void) mdsyserror(ep, EOPNOTSUPP, "EOPNOTSUPP");
	return (EOPNOTSUPP);
}

static void
cook_ev(md_event_ioctl_t *evctlp, md_ev_t *evp, md_error_t *ep)
{
	assert(evctlp);
	assert(evp);

	evp->obj_type = tagdrv_2_objlib(evctlp->mdn_tag);

	if (evp->obj_type == EVO_METADEV) {
		evp->obj_type = dev2tag(evctlp->mdn_dev, evctlp->mdn_set, ep);
	}

	evp->setno	= evctlp->mdn_set;
	evp->ev		= evdrv_2_evlib(evctlp->mdn_event);
	evp->obj	= evctlp->mdn_dev;
	evp->uev	= evctlp->mdn_user;
}

/*
 * meta_notify_getev
 * - collects up to 1 event and stores it into md_ev_t
 * - returns number of events found (0 or 1) on success or -errno
 * - flags governs whether an empty queue is waited upon (EVFLG_WAIT)
 */
int
meta_notify_getev(char *qname, ulong_t flags, md_ev_t *evp, md_error_t *ep)
{
	md_event_ioctl_t	evctl;
	int			n_ev;
	int			err	= -EINVAL;

	if (!evp) {
		goto out;
	}

	init_evctl(qname,
			TAG_EMPTY,
			EQ_EMPTY,
			/* flags (unused in get) */ 0,
			(evp->setno == EV_ALLSETS)? MD_ALLSETS: evp->setno,
			(evp->obj == EV_ALLOBJS)? MD_ALLDEVS: evp->obj,
			(flags & EVFLG_WAIT) != 0? EQ_GET_WAIT: EQ_GET_NOWAIT,
			/* user-defined event data */ 0,
			&evctl);

	err = meta_event(&evctl, ep);

	/*
	 * trap EAGAIN so that EV_EMPTY events get returned, but
	 * be sure n_ev = 0 so that users who just watch the count
	 * will also work
	 */
	switch (err) {
	case -EAGAIN:
		err = n_ev = 0;
		cook_ev(&evctl, evp, ep);
		break;
	case 0:
		n_ev = 1;
		cook_ev(&evctl, evp, ep);
		break;
	}
out:
	return (err == 0? n_ev: err);
}


/*
 * meta_notify_getevlist
 * - collects all pending events in the named queue and allocates
 *   an md_evlist_t * to return them
 * - returns the number of events found (may be 0 if !WAIT) on success
 *   or -errno and sets ep as necessary
 */
int
meta_notify_getevlist(char *qname,
			ulong_t  flags,
			md_evlist_t **evpp_arg,
			md_error_t *ep)
{
	md_ev_t		*evp		= NULL;
	md_evlist_t	*evlp		= NULL;
	md_evlist_t	*evlp_head	= NULL;
	md_evlist_t	*new		= NULL;
	int		 n_ev		= 0;
	int		 err		= -EINVAL;

	mdclrerror(ep);
	if (!evpp_arg) {
		(void) mdsyserror(ep, EINVAL, dgettext(TEXT_DOMAIN,
		    "No event list pointer"));
		goto out;
	}

	if (!qname || strlen(qname) == 0) {
		(void) mdsyserror(ep, EINVAL, dgettext(TEXT_DOMAIN,
		    "Null or zero-length queue name"));
		goto out;
	}

	do {
		if (!(evp = (md_ev_t *)Malloc(sizeof (md_ev_t)))) {
			(void) mdsyserror(ep, ENOMEM, qname);
			continue;
		}
		evp->obj_type	= EVO_EMPTY;
		evp->setno	= EV_ALLSETS;
		evp->ev		= EV_EMPTY;
		evp->obj	= EV_ALLOBJS;
		evp->uev	= 0ULL;

		err = meta_notify_getev(qname, flags, evp, ep);

		if (evp->ev != EV_EMPTY) {
			new = (md_evlist_t *)Zalloc(sizeof (md_evlist_t));
			if (evlp_head == NULL) {
				evlp = evlp_head = new;
			} else {
				evlp->next = new;
				evlp = new;
			}
			evlp->evp = evp;
			n_ev++;
		}

	} while (err >= 0 && evp && evp->ev != EV_EMPTY);
out:
	if (err == -EAGAIN) {
		err = 0;
	}

	if (err < 0) {
		meta_notify_freeevlist(evlp_head);
		evlp_head = NULL;
		return (err);
	} else if ((err == 0) && (evp->ev == EV_EMPTY)) {
	    Free(evp);
	    evp = NULL;
	}

	if (evpp_arg) {
		*evpp_arg = evlp_head;
	}

	return (n_ev);
}


/*
 * the guts of meta_notify_putev() and meta_notify_sendev()
 * are within this function.
 *
 * meta_notify_putev() is intended for general use by user-level code,
 * such as the GUI, to send user-defined events.
 *
 * meta_notify_sendev() is for "user-level driver" code, such as
 * set manipulation and the multi-host daemon to generate events.
 *
 * Note- only convention enforces this usage.
 */
int
meta_notify_doputev(md_ev_t *evp, md_error_t *ep)
{
	md_event_ioctl_t	evctl;

	if (!evp || !ep) {
		return (EINVAL);
	}

	/*
	 * users may only put events of type EQ_USER
	 */
	init_evctl(/* qname (unused in put) */ NULL,
			TAG_EMPTY,
			EQ_EMPTY,
			/* flags (unused in put) */ 0,
			(evp->setno == EV_ALLSETS)? MD_ALLSETS: evp->setno,
			(evp->obj == EV_ALLOBJS)? MD_ALLDEVS: evp->obj,
			EQ_PUT,
			evp->uev,
			&evctl);

	evctl.mdn_tag	= objlib_2_tagdrv(evp->obj_type);
	evctl.mdn_event	= evlib_2_evdrv(evp->ev);

	return (-meta_event(&evctl, ep));
}

/*
 * meta_notify_putev
 * - sends an event down to the notify driver (hence, all queues)
 * - returns 0 on success or errno
 */
int
meta_notify_putev(md_ev_t *evp, md_error_t *ep)
{
	if (!evp || !ep) {
		return (EINVAL);
	}

	evp->ev = EV_USER;	/* by definition */

	return (meta_notify_doputev(evp, ep));
}

/*
 * alternate put event entry point which allows
 * more control of event innards (for use by md "user-level drivers")
 *
 * Since this routine isn't for use by clients, the user event data
 * is always forced to be 0. That is only meaningful for events
 * of type EQ_USER (and those go through meta_notify_putev()), so
 * this is consistent.
 */
int
meta_notify_sendev(
	ev_obj_t	tag,
	set_t		set,
	md_dev64_t	dev,
	evid_t		ev)
{
	md_error_t		 status	= mdnullerror;
	md_error_t		*ep	= &status;
	md_ev_t			 ev_packet;
	int			 rc;

	ev_packet.obj_type	= tag;
	ev_packet.setno		= set;
	ev_packet.obj		= dev;
	ev_packet.ev		= ev;
	ev_packet.uev		= 0ULL;

	rc = meta_notify_doputev(&ev_packet, ep);

	if (0 == rc && !mdisok(ep)) {
		rc = EINVAL;
		mdclrerror(ep);
	}
	return (rc);
}

/*
 * meta_notify_putevlist
 * - sends all of the events in the event list
 * - returns number of events sent (>= 0) on success or -errno
 */
int
meta_notify_putevlist(md_evlist_t *evlp, md_error_t *ep)
{
	md_evlist_t	*evlpi;
	int		 n_ev	= 0;
	int		 err;

	if (!evlp) {
		err = 0;
		goto out;	/* that was easy */
	}

	for (n_ev = 0, evlpi = evlp; evlpi; evlpi = evlpi->next) {
		if ((err = meta_notify_putev(evlpi->evp, ep)) < 0) {
			goto out;
		}
		n_ev++;
	}
out:
	return (err != 0? err: n_ev);
}

/*
 * meta_notify_freevlist
 * - frees any memory allocated within the event list
 * - returns 0 on success or errno and sets ep as necessary
 */
void
meta_notify_freeevlist(md_evlist_t *evlp)
{
	md_evlist_t	*i;
	md_evlist_t	*next;

	for (i = evlp; i; i = i->next) {
		if (i && i->evp) {
			Free(i->evp);
			i->evp = NULL;
		}
	}
	for (i = evlp; i; /* NULL */) {
		next = i->next;
		Free(i);
		i = next;
	}
}
