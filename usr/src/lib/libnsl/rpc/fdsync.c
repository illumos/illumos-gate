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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains functions that enables the rpc library to synchronize
 * between various threads while they compete for a particular file descriptor.
 */

#include "mt.h"
#include "rpc_mt.h"
#include <rpc/rpc.h>
#include <errno.h>
#include <sys/poll.h>
#include <syslog.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

/*
 * A block holds an array of maxBlockSize cell and associated recursive locks
 */

#define	CELLTBLSZ	1024

typedef struct rpcfd_block {
	struct rpcfd_block *next;	/* Next Block */
	struct rpcfd_block *prev;	/* prev Block */
	int 	end;			/* fd of last lock in the list */
	mutex_t	lock[CELLTBLSZ];	/* recursive locks */
} rpcfd_block_t;

mutex_t	rpc_fd_list_lock = DEFAULTMUTEX;	/* protects list manipulation */

/* Following functions create and manipulates the dgfd lock object */

static mutex_t *search(const void *handle, int fd);
static rpcfd_block_t *create_block(const void *handle, int fd);

void *
rpc_fd_init(void)
{
	/*
	 * Create first chunk of CELLTBLSZ
	 * (No lock is required for initial creation.)
	 */
	return (create_block(NULL, 0));
}

/*
 * If rpc_fd_lock() fails to acquire a lock, it returns non-zero (ENOMEM).
 * (The operation can only fail due to a malloc() failure.)
 * The caller of rpc_fd_lock() must call rpc_fd_unlock() even if
 * rpc_fd_lock() failed.  This keeps _sigoff() and _sigon() balanced.
 *
 * If search() and create_block() fail for rpc_fd_lock(), then search()
 * will fail for rpc_fd_unlock(), so mutex_lock() and mutex_unlock()
 * calls will be balanced.  In any case, since the mutex is marked
 * LOCK_ERRORCHECK, an additional mutex_unlock() does nothing.
 */
int
rpc_fd_lock(const void *handle, int fd)
{
	mutex_t *mp;
	rpcfd_block_t *p;

	_sigoff();
	(void) mutex_lock(&rpc_fd_list_lock);
	mp = search(handle, fd);
	if (mp == NULL) {
		p = create_block(handle, fd);
		if (p != NULL)
			mp = &p->lock[fd % CELLTBLSZ];
	}
	(void) mutex_unlock(&rpc_fd_list_lock);
	if (mp == NULL)
		return (ENOMEM);
	(void) mutex_lock(mp);
	return (0);
}

void
rpc_fd_unlock(const void *handle, int fd)
{
	mutex_t *mp;

	(void) mutex_lock(&rpc_fd_list_lock);
	mp = search(handle, fd);
	(void) mutex_unlock(&rpc_fd_list_lock);
	if (mp != NULL)
		(void) mutex_unlock(mp);
	_sigon();
}

static rpcfd_block_t *
create_block(const void *handle, int fd)
{
	rpcfd_block_t *l, *lprev;
	rpcfd_block_t *p;
	int i;

	p = malloc(sizeof (rpcfd_block_t));
	if (p == NULL)
		return (NULL);

	for (i = 0; i < CELLTBLSZ; i++) {
		(void) mutex_init(&p->lock[i],
			USYNC_THREAD | LOCK_RECURSIVE | LOCK_ERRORCHECK, NULL);
	}
	p->end = (((fd + CELLTBLSZ) / CELLTBLSZ) * CELLTBLSZ) - 1;
	lprev = NULL;
	for (l = (rpcfd_block_t *)handle; l; l = l->next) {
		lprev = l;
		if (fd < l->end)
			break;
	}

	p->next = l;
	p->prev = lprev;
	if (lprev)
		lprev->next = p;
	if (l)
		l->prev = p;

	return (p);
}

/*
 * Called with rpc_fd_list_lock held.
 */
static mutex_t *
search(const void *handle, int fd)
{
	rpcfd_block_t *p;

	for (p = (rpcfd_block_t *)handle; p; p = p->next) {
		if (fd <= p->end)
			return (&p->lock[fd % CELLTBLSZ]);
	}

	return (NULL);
}
