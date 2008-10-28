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

#ifndef _NBMLOCK_H
#define	_NBMLOCK_H

/*
 * Non-blocking mandatory locking support.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/vnode.h>
#include <sys/rwlock.h>
#include <sys/cred.h>

/*
 * Type of operation; used when checking for lock/share conflict.
 * NBL_READWRITE is used for checking for a conflict with an exclusive lock
 * (F_WRLCK) or a read-write mmap request.  For checking an actual I/O
 * request, use NBL_READ or NBL_WRITE.
 */
typedef enum {NBL_READ, NBL_WRITE, NBL_RENAME, NBL_REMOVE,
	    NBL_READWRITE} nbl_op_t;

/* critical region primitives */
extern void nbl_start_crit(vnode_t *, krw_t);
extern void nbl_end_crit(vnode_t *);
extern int nbl_in_crit(vnode_t *);

/* conflict checking */
extern int nbl_need_check(vnode_t *);
extern int nbl_conflict(vnode_t *, nbl_op_t, u_offset_t, ssize_t, int,
    caller_context_t *);
extern int nbl_share_conflict(vnode_t *, nbl_op_t, caller_context_t *);
extern int nbl_lock_conflict(vnode_t *, nbl_op_t, u_offset_t, ssize_t, int,
    caller_context_t *);
extern int nbl_svmand(vnode_t *, cred_t *, int *);


#ifdef __cplusplus
}
#endif

#endif /* _NBMLOCK_H */
