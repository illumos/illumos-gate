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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma weak _shmat = shmat
#pragma weak _shmctl = shmctl
#pragma weak _shmctl64 = shmctl64
#pragma weak _shmdt = shmdt
#pragma weak _shmget = shmget
#pragma weak _shmids = shmids

#include "lint.h"
#include "thr_uberdata.h"
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/ipc_impl.h>
#include <sys/shm.h>
#include <sys/shm_impl.h>
#include <sys/syscall.h>
#include <errno.h>

/*
 * List of all shared memory segments.
 * We need this to keep track of the sizes so that we can unregister
 * any robust locks that are contained in a segment that is detached.
 */
static struct shm_size {
	void		*shm_addr;
	size_t		shm_size;
	struct shm_size	*shm_next;
} *shm_list = NULL;

static mutex_t shm_lock = DEFAULTMUTEX;		/* protects shm_list */

extern void unregister_locks(caddr_t, size_t);

/*
 * Add a shared memory address and size to the remembered list.
 */
static void
add_shm_size(void *addr, size_t size)
{
	struct shm_size **list;
	struct shm_size *elem;

	lmutex_lock(&shm_lock);

	for (list = &shm_list; (elem = *list) != NULL; list = &elem->shm_next) {
		if (elem->shm_addr == addr) {	/* won't happen? */
			elem->shm_size = size;
			lmutex_unlock(&shm_lock);
			return;
		}
	}
	elem = lmalloc(sizeof (*elem));
	elem->shm_addr = addr;
	elem->shm_size = size;
	elem->shm_next = NULL;
	*list = elem;

	lmutex_unlock(&shm_lock);
}

/*
 * Delete the shared memory address from the remembered list
 * and unregister all of the robust locks contained therein.
 */
static void
delete_shm_size(void *addr)
{
	struct shm_size **list;
	struct shm_size *elem;
	size_t size = 0;

	lmutex_lock(&shm_lock);

	for (list = &shm_list; (elem = *list) != NULL; list = &elem->shm_next) {
		if (elem->shm_addr == addr) {
			size = elem->shm_size;
			*list = elem->shm_next;
			lfree(elem, sizeof (*elem));
			break;
		}
	}

	lmutex_unlock(&shm_lock);

	if (size != 0)
		unregister_locks(addr, size);
}

void *
shmat(int shmid, const void *shmaddr, int shmflg)
{
	sysret_t rval;
	int error;
	void *addr;
	struct shmid_ds shmds;

	error = __systemcall(&rval, SYS_shmsys, SHMAT, shmid, shmaddr, shmflg);
	addr = (void *)rval.sys_rval1;
	if (error) {
		(void) __set_errno(error);
	} else if (shmctl(shmid, IPC_STAT, &shmds) == 0) {
		add_shm_size(addr, shmds.shm_segsz);
	}
	return (addr);
}

int
shmctl(int shmid, int cmd, struct shmid_ds *buf)
{
	if (cmd == IPC_SET64 || cmd == IPC_STAT64) {
		(void) __set_errno(EINVAL);
		return (-1);
	}
	return (syscall(SYS_shmsys, SHMCTL, shmid, cmd, buf));
}

int
shmctl64(int shmid, int cmd, struct shmid_ds64 *buf)
{
	if (cmd != IPC_SET64 && cmd != IPC_STAT64) {
		(void) __set_errno(EINVAL);
		return (-1);
	}
	return (syscall(SYS_shmsys, SHMCTL, shmid, cmd, buf));
}

int
shmdt(char *shmaddr)
{
	int rval = syscall(SYS_shmsys, SHMDT, shmaddr);
	if (rval == 0)
		delete_shm_size(shmaddr);
	return (rval);
}

int
shmget(key_t key, size_t size, int shmflg)
{
	return (syscall(SYS_shmsys, SHMGET, key, size, shmflg));
}

int
shmids(int *buf, uint_t nids, uint_t *pnids)
{
	return (syscall(SYS_shmsys, SHMIDS, buf, nids, pnids));
}
