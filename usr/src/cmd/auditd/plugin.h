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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

#ifndef	_PLUGIN_H
#define	_PLUGIN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <security/auditd.h>
#include "queue.h"

typedef struct thd {
	pthread_cond_t	thd_cv;
	pthread_mutex_t	thd_mutex;
	int		thd_waiting;
} thr_data_t;

typedef struct plg plugin_t;
struct plg {
	boolean_t	plg_initialized;	/* if threads, pools created */
	boolean_t	plg_reopen;		/* call auditd_plugin_open */
	/*
	 * removed is 1 if last read of audit_control didn't list this
	 * plugin; it needs to be removed.
	 */
	boolean_t	plg_removed;		/* plugin removed */
	boolean_t	plg_to_be_removed;	/* tentative removal state */

	char		*plg_path;		/* plugin path */
	void		*plg_dlptr;		/* dynamic lib pointer */
	auditd_rc_t	(*plg_fplugin)(const char *, size_t, uint64_t, char **);
	auditd_rc_t	(*plg_fplugin_open)(const kva_t *, char **, char **);
	auditd_rc_t	(*plg_fplugin_close)(char **);

	kva_t		*plg_kvlist;		/* plugin inputs */
	size_t		plg_qmax;		/* max queue size */
	size_t		plg_qmin;		/* min queue size */

	uint64_t	plg_sequence;		/* buffer counter */
	uint64_t	plg_last_seq_out;	/* buffer counter (debug) */
	uint32_t	plg_tossed;		/* discards (debug) */
	uint32_t	plg_queued;		/* count buffers queued */
	uint32_t	plg_output;		/* count of buffers output */
	int		plg_priority;		/* current priority */

	au_queue_t	plg_pool;		/* buffer pool */
	au_queue_t	plg_queue;		/* queue drawn from pool */
	int		plg_q_threshold;	/* max preallocated queue */
	audit_q_t	*plg_save_q_copy;	/* tmp holding for a record */

	pthread_t	plg_tid;		/* thread id */
	pthread_cond_t	plg_cv;
	pthread_mutex_t	plg_mutex;
	int		plg_waiting;		/* output thread wait state */

	int		plg_cnt;		/* continue policy */

	int		plg_retry_time;		/* retry (seconds) */

	plugin_t	*plg_next;		/* null is end of list */
};

int	auditd_thread_init();
void	auditd_thread_close();
void	auditd_exit(int);

extern plugin_t		*plugin_head;
extern pthread_mutex_t	plugin_mutex;

#ifdef __cplusplus
}
#endif

#endif	/* _PLUGIN_H */
