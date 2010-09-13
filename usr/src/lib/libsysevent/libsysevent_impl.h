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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LIBSYSEVENT_IMPL_H
#define	_LIBSYSEVENT_IMPL_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * libsysevent implementation-specific structures
 */

/* sysevent publisher/subscriber handle and related data structures */

#define	CHAN_PATH	"/var/run/sysevent_channels"
#define	REG_DOOR	"reg_door"

/* Subscription size values */
#define	MAX_SUBSCRIPTION_SZ	1024

/* Sysevent Channel Handle */
typedef struct sysevent_impl_handle {
	int		sh_bound;		/* Channel bind status */
	int		sh_type;		/* pub/sub channel binding */
	uint32_t	sh_id;			/* pub/sub within channel */
	int		sh_door_desc;		/* Service door descrip */
	char		*sh_door_name;		/* Service door */
	char		*sh_channel_name;	/* Event Channel name */
	char		*sh_channel_path;	/* Full path to Event Chan */
	void		*sh_priv_data;	/* Pub/Sub private data */
	mutex_t		sh_lock;	/* lock to protect access */
} sysevent_impl_hdl_t;

/* Sysevent queue for subscriber delivery */
typedef struct sysevent_queue {
	struct sysevent_queue	*sq_next;
	sysevent_t		*sq_ev;
} sysevent_queue_t;

/*
 * Subscriber private data stored in the sysevent channel handle
 */
typedef struct subscriber_priv {
	cond_t			sp_cv;		/* cv for event synch */
	mutex_t			sp_qlock;	/* event queue lock */
	char			*sp_door_name;	/* Publisher reg door */
	thread_t		sp_handler_tid; /* delivery handler thread id */
	struct sysevent_queue	*sp_evq_head;   /* event q head */
	struct sysevent_queue	*sp_evq_tail;   /* event q tail */
	void			(*sp_func)(sysevent_t *ev); /* deliver func */
} subscriber_priv_t;

/* Subscriber information stored on the publisher side */
typedef struct subscriber_data {
	int			sd_flag;		/* flag */
	char			*sd_door_name;	/* Client door name */
} subscriber_data_t;

/* Publisher private data stored in the sysevent channel handle */
typedef struct publisher_priv {
	struct class_lst	*pp_class_hash[CLASS_HASH_SZ + 1];
	subscriber_data_t	*pp_subscriber_list[MAX_SUBSCRIBERS + 1];
} publisher_priv_t;

/* Subscriber flag values */
#define	ACTIVE		1	/* Active subscriber */
#define	SEND_AGAIN	2	/* Resend of event requested */

/* Sysevent handle access */
#define	SYSEVENT_IMPL_HNDL(sehp)	((sysevent_impl_hdl_t *)(void *)(sehp))
#define	SH_BOUND(sehp)	(SYSEVENT_IMPL_HNDL(sehp)->sh_bound)
#define	SH_TYPE(sehp)	(SYSEVENT_IMPL_HNDL(sehp)->sh_type)
#define	SH_RESULT(sehp)	(SYSEVENT_IMPL_HNDL(sehp)->sh_result)
#define	SH_ID(sehp)	(SYSEVENT_IMPL_HNDL(sehp)->sh_id)
#define	SH_DOOR_DESC(sehp)	(SYSEVENT_IMPL_HNDL(sehp)->sh_door_desc)
#define	SH_DOOR_NAME(sehp)	(SYSEVENT_IMPL_HNDL(sehp)->sh_door_name)
#define	SH_CHANNEL_NAME(sehp)	(SYSEVENT_IMPL_HNDL(sehp)->sh_channel_name)
#define	SH_CHANNEL_PATH(sehp)	(SYSEVENT_IMPL_HNDL(sehp)->sh_channel_path)
#define	SH_LOCK(sehp)		(&(SYSEVENT_IMPL_HNDL(sehp)->sh_lock))
#define	SH_PRIV_DATA(sehp)	(SYSEVENT_IMPL_HNDL(sehp)->sh_priv_data)

#define	SH_CLASS_HASH(sehp)	(((publisher_priv_t *) \
	SH_PRIV_DATA(sehp))->pp_class_hash)
#define	SH_SUBSCRIBER(sehp, id)	(((publisher_priv_t *) \
	SH_PRIV_DATA(sehp))->pp_subscriber_list[id])

/*
 * GPEC Interface definitions
 */

typedef struct evchan_subscriber evchan_subscr_t;

typedef struct evchan_sub_head {
	evchan_subscr_t *evchan_sub_next;
} evchan_sub_head_t;

/* Event channel handle */
typedef struct evchan_impl_handle {
	pid_t		ev_pid;		/* verify descend via fork() */
	int		ev_fd;		/* descriptor for sev driver */
	mutex_t		ev_lock;	/* lock to protect this structure */
	evchan_sub_head_t ev_sub;	/* anchor of subscriber list */
} evchan_impl_hdl_t;

/* Evchan handle access */
#define	EVCHAN_IMPL_HNDL(evcp)	((evchan_impl_hdl_t *)(void *)(evcp))
#define	EV_PID(evcp)		(EVCHAN_IMPL_HNDL(evcp)->ev_pid)
#define	EV_FD(evcp)		(EVCHAN_IMPL_HNDL(evcp)->ev_fd)
#define	EV_LOCK(evcp)		(&(EVCHAN_IMPL_HNDL(evcp)->ev_lock))
#define	EV_SUB(evcp)		(&(EVCHAN_IMPL_HNDL(evcp)->ev_sub))
#define	EV_SUB_NEXT(evcp)	(EVCHAN_IMPL_HNDL(evcp)->ev_sub.evchan_sub_next)

struct sysevent_subattr_impl {
	door_xcreate_server_func_t *xs_thrcreate;
	void *xs_thrcreate_cookie;
	door_xcreate_thrsetup_func_t *xs_thrsetup;
	void *xs_thrsetup_cookie;
	pthread_attr_t *xs_thrattr;
	sigset_t xs_sigmask;
};

/*
 * Subscriber private data
 */
struct evchan_subscriber {
	evchan_subscr_t *evsub_next;	/* list of subscribers */
	evchan_impl_hdl_t *ev_subhead;	/* link back to channel data */
	int evsub_door_desc;		/* Service door descriptor */
	char *evsub_sid;		/* identifier of subscriber */
	void *evsub_cookie;		/* subscriber cookie */
	int (*evsub_func)(sysevent_t *, void *); /* subscriber event handler */
	struct sysevent_subattr_impl *evsub_attr;
	uint32_t evsub_state;
};

#define	EVCHAN_SUB_STATE_ACTIVE		1
#define	EVCHAN_SUB_STATE_CLOSING	2

/* Access to subscriber data */
#define	EVCHAN_SUBSCR(subp)	((evchan_subscr_t *)(subp))

/* Characters for channel name syntax */
#define	EVCH_ISCHANCHAR(c)	(isalnum(c) || (c) == '.' || (c) == ':' || \
				    (c) == '-' || (c) == '_')

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBSYSEVENT_IMPL_H */
