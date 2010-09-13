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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#pragma weak _semctl = semctl
#pragma weak _semctl64 = semctl64
#pragma weak _semget = semget
#pragma weak _semop = semop
#pragma weak _semids = semids
#pragma weak _semtimedop = semtimedop

#include "lint.h"
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/ipc_impl.h>
#include <sys/sem.h>
#include <sys/sem_impl.h>
#include <sys/syscall.h>
#include <stdarg.h>
#include <errno.h>

union semun {
	int val;
	struct semid_ds *buf;
	struct semid_ds64 *buf64;
	ushort_t *array;
};

/*
 * The kernel implementation of semsys expects an argument containing the
 * value of the semun argument, but the Sparc compiler passes a pointer
 * to it, since it is a union.  So, we convert here and pass the value,
 * but to keep the naive user from being penalized for the counterintuitive
 * behaviour of the Sparc compiler, we ignore the union if it will not be
 * used by the system call (to protect the caller from SIGSEGVs, e.g.
 * semctl(semid, semnum, cmd, NULL);  which would otherwise always result
 * in a segmentation violation).  We do this partly for consistency, since
 * the ICL port did it.  This all works just fine for the Intel compiler,
 * which actually does pass the union by value.
 */
int
semctl(int semid, int semnum, int cmd, ...)
{
	uintptr_t arg;
	va_list ap;

	switch (cmd) {
	case SETVAL:
		va_start(ap, cmd);
		arg = (uintptr_t)va_arg(ap, union semun).val;
		va_end(ap);
		break;
	case GETALL:
	case SETALL:
		va_start(ap, cmd);
		arg = (uintptr_t)va_arg(ap, union semun).array;
		va_end(ap);
		break;
	case IPC_STAT:
	case IPC_SET:
		va_start(ap, cmd);
		arg = (uintptr_t)va_arg(ap, union semun).buf;
		va_end(ap);
		break;
	case IPC_SET64:
	case IPC_STAT64:
		(void) __set_errno(EINVAL);
		return (-1);
	default:
		arg = 0;
		break;
	}

	return (syscall(SYS_semsys, SEMCTL, semid, semnum, cmd, arg));
}

int
semctl64(int semid, int semnum, int cmd, ...)
{
	struct semid_ds64 *buf;
	va_list ap;

	if (cmd != IPC_SET64 && cmd != IPC_STAT64) {
		(void) __set_errno(EINVAL);
		return (-1);
	}

	va_start(ap, cmd);
	buf = va_arg(ap, union semun).buf64;
	va_end(ap);

	return (syscall(SYS_semsys, SEMCTL, semid, semnum, cmd, buf));
}

int
semget(key_t key, int nsems, int semflg)
{
	return (syscall(SYS_semsys, SEMGET, key, nsems, semflg));
}

int
semop(int semid, struct sembuf *sops, size_t nsops)
{
	return (syscall(SYS_semsys, SEMOP, semid, sops, nsops));
}

int
semids(int *buf, uint_t nids, uint_t *pnids)
{
	return (syscall(SYS_semsys, SEMIDS, buf, nids, pnids));
}

int
semtimedop(int semid, struct sembuf *sops, size_t nsops,
    const timespec_t *timeout)
{
	return (syscall(SYS_semsys, SEMTIMEDOP, semid, sops, nsops,
	    timeout));
}
