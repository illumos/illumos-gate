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

#ifndef	_FMD_LOG_H
#define	_FMD_LOG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <exacct.h>

#ifdef	__cplusplus
extern "C" {
#endif

#include <fmd_api.h>

typedef struct fmd_log {
	char *log_name;			/* file pathname */
	char *log_tag;			/* file content tag */
	int log_fd;			/* file descriptor */
	struct stat64 log_stat;		/* status of file at log_open() time */
	ea_file_t log_ea;		/* exacct file structure */
	pthread_mutex_t log_lock;	/* lock for flags, refs, off, append */
	pthread_cond_t log_cv;		/* condition variable for waiters */
	int log_flags;			/* file flags (see below) */
	uint_t log_refs;		/* file reference count */
	uint_t log_pending;		/* number of pending log commits */
	off64_t log_toc;		/* offset of table of contents */
	off64_t log_beg;		/* offset of first data record */
	off64_t log_off;		/* offset at which to append */
	off64_t log_skip;		/* offset to skip to for replay */
	uint64_t log_minfree;		/* minimum free bytes for filesystem */
	char *log_uuid;			/* uuid string for this log file */
	uint_t log_uuidlen;		/* length of log_uuid (not incl. \0) */
} fmd_log_t;

#define	FMD_LF_EAOPEN	0x1		/* log_ea is open and valid */
#define	FMD_LF_REPLAY	0x2		/* log records should use replay tag */
#define	FMD_LF_DIRTY	0x4		/* log toc should be updated */
#define	FMD_LF_BUSY	0x8		/* log is busy; skip updates */

typedef void fmd_log_f(fmd_log_t *, fmd_event_t *, void *);

#define	FMD_LOG_ERROR	"error"		/* tag for error log files */
#define	FMD_LOG_FAULT	"fault"		/* tag for fault log files */
#define	FMD_LOG_ASRU	"asru"		/* tag for asru log files */
#define	FMD_LOG_XPRT	"xprt"		/* tag for transport log files */

extern fmd_log_t *fmd_log_tryopen(const char *, const char *, const char *);
extern fmd_log_t *fmd_log_open(const char *, const char *, const char *);
extern void fmd_log_close(fmd_log_t *);

extern void fmd_log_hold_pending(fmd_log_t *);
extern void fmd_log_hold(fmd_log_t *);
extern void fmd_log_rele(fmd_log_t *);

extern void fmd_log_append(fmd_log_t *, fmd_event_t *, fmd_case_t *);
extern void fmd_log_commit(fmd_log_t *, fmd_event_t *);
extern void fmd_log_decommit(fmd_log_t *, fmd_event_t *);
extern void fmd_log_replay(fmd_log_t *, fmd_log_f *, void *);
extern void fmd_log_update(fmd_log_t *);
extern fmd_log_t *fmd_log_rotate(fmd_log_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _FMD_LOG_H */
