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

#ifndef	_SYS_ZIL_IMPL_H
#define	_SYS_ZIL_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/zil.h>
#include <sys/dmu_objset.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum lwb_state_type {
	UNWRITTEN,	/* buffer yet to be written */
	SEQ_INCOMPLETE,	/* buffer written, but there's an unwritten buffer in */
			/* the sequence before this */
	SEQ_COMPLETE,	/* no unwritten buffers before this */
} lwb_state_t;

/*
 * Log write buffer.
 */
typedef struct lwb {
	zilog_t		*lwb_zilog;	/* back pointer to log struct */
	blkptr_t	lwb_blk;	/* on disk address of this log blk */
	int		lwb_nused;	/* # used bytes in buffer */
	int		lwb_sz;		/* size of block and buffer */
	char		*lwb_buf;	/* log write buffer */
	uint64_t	lwb_max_txg;	/* highest txg in this lwb */
	uint64_t	lwb_seq;	/* highest log record seq number */
	txg_handle_t	lwb_txgh;	/* txg handle for txg_exit() */
	list_node_t	lwb_node;	/* zilog->zl_lwb_list linkage */
	lwb_state_t	lwb_state;	/* buffer state */
} lwb_t;

/*
 * [vdev, seq] element for use in flushing device write caches
 */
typedef struct zil_vdev {
	uint64_t	vdev;		/* device written */
	uint64_t	seq;		/* itx sequence */
	list_node_t	vdev_seq_node;	/* zilog->zl_vdev_list linkage */
} zil_vdev_t;

/*
 * Stable storage intent log management structure.  One per dataset.
 */
struct zilog {
	kmutex_t	zl_lock;	/* protects most zilog_t fields */
	struct dsl_pool	*zl_dmu_pool;	/* DSL pool */
	spa_t		*zl_spa;	/* handle for read/write log */
	zil_header_t	*zl_header;	/* log header buffer */
	objset_t	*zl_os;		/* object set we're logging */
	zil_get_data_t	*zl_get_data;	/* callback to get object content */
	uint64_t	zl_itx_seq;	/* itx sequence number */
	uint64_t	zl_ss_seq;	/* last tx on stable storage */
	uint64_t	zl_destroy_txg;	/* txg of last zil_destroy() */
	uint64_t	zl_replay_seq[TXG_SIZE]; /* seq of last replayed rec */
	uint32_t	zl_suspend;	/* log suspend count */
	kcondvar_t	zl_cv_write;	/* for waiting to write to log */
	kcondvar_t	zl_cv_seq;	/* for committing a sequence */
	uint8_t		zl_stop_replay;	/* don't replay any further */
	uint8_t		zl_stop_sync;	/* for debugging */
	uint8_t		zl_writer;	/* boolean: write setup in progress */
	uint8_t		zl_log_error;	/* boolean: log write error */
	list_t		zl_itx_list;	/* in-memory itx list */
	uint64_t	zl_itx_list_sz;	/* total size of records on list */
	uint64_t	zl_cur_used;	/* current commit log size used */
	uint64_t	zl_prev_used;	/* previous commit log size used */
	list_t		zl_lwb_list;	/* in-flight log write list */
	list_t		zl_vdev_list;	/* list of [vdev, seq] pairs */
	taskq_t		*zl_clean_taskq; /* runs lwb and itx clean tasks */
	avl_tree_t	zl_dva_tree;	/* track DVAs during log parse */
	kmutex_t	zl_destroy_lock; /* serializes zil_destroy() calls */
};

typedef struct zil_dva_node {
	dva_t		zn_dva;
	avl_node_t	zn_node;
} zil_dva_node_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ZIL_IMPL_H */
