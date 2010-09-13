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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/*	  All Rights Reserved	*/

#ifndef _SYS_LOG_H
#define	_SYS_LOG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/strlog.h>
#include <sys/stream.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	LOG_CONSMIN	0		/* /dev/conslog minor */
#define	LOG_LOGMIN	5		/* /dev/log minor */
#define	LOG_BACKLOG	LOG_LOGMIN	/* console backlog queue */

#define	LOG_LOGMINIDX	0		/* index of smallest /dev/log clone */
#define	LOG_LOGMAXIDX	15		/* up to 16 /dev/log clones */
#define	LOG_NUMCLONES	(LOG_LOGMAXIDX - LOG_LOGMINIDX + 1)

#define	LOG_MID		44		/* module ID */
#define	LOG_MINPS	0		/* min packet size */
#define	LOG_MAXPS	1024		/* max packet size */
#define	LOG_LOWAT	2048		/* threshold for backenable */
#define	LOG_HIWAT	1048576		/* threshold for tossing messages */

#define	LOG_MAGIC	0xf00d4109U	/* "food for log" - unsent msg magic */
#define	LOG_RECENTSIZE	8192		/* queue of most recent messages */
#define	LOG_MINFREE	4096		/* message cache low water mark */
#define	LOG_MAXFREE	8192		/* message cache high water mark */

typedef struct log log_t;
typedef int (log_filter_t)(log_t *, log_ctl_t *);

struct log {
	queue_t		*log_q;		/* message queue */
	log_filter_t	*log_wanted;	/* message filter */
	mblk_t		*log_data;	/* parameters for filter */
	uint16_t	log_flags;	/* message type (e.g. SL_CONSOLE) */
	short		log_inuse;	/* is this log device open? */
	int		log_overflow;	/* messages lost due to QFULL */
	zoneid_t	log_zoneid;	/* zone id of log */
	major_t		log_major;	/* device type */
	minor_t		log_minor;	/* minor number of associated device */
};

/* Array of /dev/log minor devices */
typedef struct log_zone {
	log_t lz_clones[LOG_NUMCLONES];
	uint16_t lz_active;	/* active types (OR of all log_flags fields) */
} log_zone_t;

#define	LOG_MSGSIZE	200

typedef struct log_dump {
	uint32_t	ld_magic;	/* LOG_MAGIC */
	uint32_t	ld_msgsize;	/* MBLKL(mp->b_cont) */
	uint32_t	ld_csum;	/* checksum32(log_ctl) */
	uint32_t	ld_msum;	/* checksum32(message text) */
	/*
	 * log_ctl and message text follow here -- see dump_messages()
	 */
} log_dump_t;

#ifdef _KERNEL

/* global zone variables */
extern log_zone_t log_global;
extern queue_t *log_consq;	/* primary console reader queue */
extern queue_t *log_backlogq;	/* console backlog queue */
extern queue_t *log_intrq;	/* pending high-level interrupt message queue */

extern log_filter_t log_error;
extern log_filter_t log_trace;
extern log_filter_t log_console;

extern void log_init(void);
extern void log_enter(void);
extern void log_exit(void);
extern void log_update(log_t *, queue_t *, short, log_filter_t);
extern mblk_t *log_makemsg(int, int, int, int, int, void *, size_t, int);
extern void log_freemsg(mblk_t *);
extern void log_sendmsg(mblk_t *, zoneid_t);
extern void log_flushq(queue_t *);
extern void log_printq(queue_t *);
extern log_t *log_alloc(minor_t);
extern void log_free(log_t *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_LOG_H */
