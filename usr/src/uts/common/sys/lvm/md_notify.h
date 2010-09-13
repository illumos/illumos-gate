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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_MD_NOTIFY_H
#define	_SYS_MD_NOTIFY_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/lvm/mdvar.h>
#include <sys/proc.h>
#include <sys/lvm/md_mirror_shared.h>
#include <sys/time.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	MD_EVENT_ID		(0xda1eab1e)
#define	MD_ALLSETS		((ulong_t)0xffffffff)
#define	MD_ALLDEVS		((ulong_t)0xffffffff)
#define	MD_NOTIFY_HALT_TRIES	(4)
#define	MD_NOTIFY_NAME_SIZE	(64)
#define	MD_NOTIFY_REVISION	1

/* mdn_flags bits in struct md_event_queue */

#define	MD_EVENT_QUEUE_DESTROY	(0x00000001)
#define	MD_EVENT_QUEUE_INVALID	(0x00000002)
#define	MD_EVENT_QUEUE_PERM	(0x00000004) /* do not delete when proc dies */
#define	MD_EVENT_QUEUE_FULL	(0x00000008)

typedef enum md_event_type {

	EQ_EMPTY = 0,

	/* Configuration Changes */
	EQ_CREATE = 1,
	EQ_DELETE,
	EQ_ADD,
	EQ_REMOVE,
	EQ_REPLACE,
	EQ_GROW,
	EQ_RENAME_SRC,
	EQ_RENAME_DST,

	EQ_MEDIATOR_ADD,
	EQ_MEDIATOR_DELETE,
	EQ_HOST_ADD,
	EQ_HOST_DELETE,
	EQ_DRIVE_ADD,
	EQ_DRIVE_DELETE,

	/* State Changes */
	EQ_INIT_START = 0x00000400,
	EQ_INIT_FAILED,
	EQ_INIT_FATAL,
	EQ_INIT_SUCCESS,
	EQ_IOERR,
	EQ_ERRED,
	EQ_LASTERRED,
	EQ_OK,
	EQ_ENABLE,
	EQ_RESYNC_START,
	EQ_RESYNC_FAILED,
	EQ_RESYNC_SUCCESS,	/* resync has succeeded */
	EQ_RESYNC_DONE,		/* resync completed */
	EQ_HOTSPARED,		/* hot spare aquired for use */
	EQ_HS_FREED,		/* hotspare no longer in use */
	EQ_HS_CHANGED,		/* change of metadevice hotspare pool */
	EQ_TAKEOVER,
	EQ_RELEASE,
	EQ_OPEN_FAIL,
	EQ_OFFLINE,
	EQ_ONLINE,
	EQ_DETACH,
	EQ_DETACHING,
	EQ_ATTACH,
	EQ_ATTACHING,
	EQ_CHANGE,
	EQ_EXCHANGE,
	EQ_REGEN_START,
	EQ_REGEN_DONE,
	EQ_REGEN_FAILED,

	/* User defined event */
	EQ_USER = 0x00100000,

	/* Notify Specfic */
	EQ_NOTIFY_LOST,
	EQ_LAST }
	md_event_type_t;

typedef enum md_event_cmds {
	EQ_NONE =	0x00000000,
	EQ_ON =		0x00000001,
	EQ_OFF =	0x00000002,
	EQ_GET_NOWAIT =	0x00000010,
	EQ_GET_WAIT =	0x00000040,
	EQ_PUT =	0x00000020,

	EQ_ALLVALID =	0x00000073
	}md_event_cmds_t;

typedef enum md_tags {
	TAG_EMPTY,
	TAG_METADEVICE,
	TAG_REPLICA,
	TAG_HSP,
	TAG_HS,
	TAG_SET,
	TAG_DRIVE,
	TAG_HOST,
	TAG_MEDIATOR,
	TAG_UNK,
	TAG_LAST
} md_tags_t;

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif
typedef struct md_event_ioctl {
	MD_DRIVER
	md_error_t	mde;		/* error return */
	uint_t		mdn_magic;	/* magic number for structure */
	int		mdn_rev;	/* revision number */
	char		mdn_name[MD_NOTIFY_NAME_SIZE];
					/* queue name */
	int		mdn_flags;	/* ioctl flags */
	md_event_cmds_t	mdn_cmd;	/* command value */
	md_tags_t	mdn_tag;	/* object tag */
	set_t		mdn_set;	/* set number */
	md_dev64_t	mdn_dev;	/* device event occurred on */
	md_event_type_t	mdn_event;	/* event */
	u_longlong_t	mdn_user;	/* user defined event */
	md_timeval32_t	mdn_time;	/* time stamp of event */
} md_event_ioctl_t;

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

/* ioctl flags */
#define	EQ_Q_PERM	(0x00000001)	/* do not delete when proc dies */

#define	EQ_Q_ALLVALID	(0x00000001)	/* all valid notify ioctl flags */

typedef enum notify_cmds_t
	{ EQ_LIST_ADD = 1, EQ_LIST_DELETE }
	notify_cmds_t;

typedef struct notify {
	notify_cmds_t	mdn_cmd;	/* list function (add/delete) */
	md_tags_t	mdn_tag;	/* type of object */
	set_t		mdn_set;	/* set where event occurred */
	md_dev64_t	mdn_dev;	/* device that event occurred on */
	md_event_type_t	mdn_event;	/* event */
}notify_t;


#ifdef _KERNEL

#define	NOTIFY_MD(tag, set, dev, event) 				\
	(void) md_notify_interface(EQ_PUT, (tag), (set), (dev), (event))

#define	SE_NOTIFY(se_class, se_subclass, tag, set, dev)		\
	svm_gen_sysevent((se_class), (se_subclass), (tag), (set), (dev))

typedef struct md_event {
	struct md_event *mdn_next;	/* pointer to next element */
	md_tags_t	mdn_tag;	/* object type */
	set_t		mdn_set;	/* set where event occurred */
	md_dev64_t	mdn_dev;	/* device that event occurred on */
	md_event_type_t	mdn_event;	/* event */
	u_longlong_t	mdn_user;	/* user defined event */
	struct timeval	mdn_time;	/* time stamp of event */
}md_event_t;

typedef struct md_event_queue {
	struct md_event_queue	*mdn_nextq;	/* next event queue */
	char		mdn_name[MD_NOTIFY_NAME_SIZE];
					/* queue name */
	int		mdn_flags;	/* queue flags */
	pid_t		mdn_pid;	/* pid that created the queue */
	proc_t		*mdn_proc;	/* process that created the queue */
	uid_t		mdn_uid;	/* uid of queue creator */
	size_t		mdn_size;	/* size of the queue in elements */
	md_event_t	*mdn_front;	/* front element in queue */
	md_event_t	*mdn_tail;	/* last element of queue */
	int		mdn_waiting;	/* number of process waiting */
	kcondvar_t	mdn_cv;		/* waiting condition varaible */
} md_event_queue_t;

/*
 * The remainder of this file defines items that are used for testing
 * md_notify.
 */

/*
 * Named services for testing
 */

#define	MD_NOTIFY_REAP_OFF	"notify turn reap off"
#define	MD_NOTIFY_REAP_ON	"notify turn reap on"
#define	MD_NOTIFY_TEST_STATS	"notify test statistics"

/*
 * The MD_NOTIFY_TEST_STATS named service can be invoked to get md_notify
 * to set the values of this structure.  The md_tnotify module uses this
 * structure.
 */

typedef struct md_notify_stats {
	kmutex_t	*mds_eventq_mx;	/* Address of mutex protecting */
					/*   event queue. */
	int		mds_max_queue;	/* Max. # events in notify queue. */
	int		mds_reap;	/* events since last reap. */
	int		mds_reap_count;	/* # events between reaps. */
	int		mds_reap_off;	/* non-zero -> reaping is off. */
} md_notify_stats_t;

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MD_NOTIFY_H */
