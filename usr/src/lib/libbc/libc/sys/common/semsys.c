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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984 AT&T */
/*	  All Rights Reserved   */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/syscall.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>

/* semsys dispatch argument */
#define	SEMCTL	0
#define	SEMGET	1
#define	SEMOP	2

int
semctl(int semid, int semnum, int cmd, union semun *arg)
{
	switch (cmd) {

	case IPC_STAT:
	case IPC_SET:
		cmd += 10;
		/* fall-through */
	case SETVAL:
	case GETALL:
	case SETALL:
		return (_syscall(SYS_semsys, SEMCTL,
		    semid, semnum, cmd, arg->val));

	case IPC_RMID:
		cmd += 10;
		/* fall-through */
	default:
		return (_syscall(SYS_semsys, SEMCTL,
		    semid, semnum, cmd, 0));
	}
}

int
semget(key_t key, int nsems, int semflg)
{
	return (_syscall(SYS_semsys, SEMGET, key, nsems, semflg));
}

int
semop(int semid, struct sembuf *sops, int nsops)
{
	return (_syscall(SYS_semsys, SEMOP, semid, sops, nsops));
}

int
semsys(int sysnum, ...)
{
	va_list ap;
	int semid, cmd;
	int semnum, val;
	union semun arg;
	key_t key;
	int nsems, semflg;
	struct sembuf *sops;
	int nsops;

	va_start(ap, sysnum);
	switch (sysnum) {
	case SEMCTL:
		semid = va_arg(ap, int);
		semnum = va_arg(ap, int);
		cmd = va_arg(ap, int);
		val = va_arg(ap, int);
		if ((cmd == IPC_STAT) || (cmd == IPC_SET) || (cmd == IPC_RMID))
			cmd += 10;
		va_end(ap);
		return (_syscall(SYS_semsys, SEMCTL, semid, semnum, cmd, val));
	case SEMGET:
		key = va_arg(ap, key_t);
		nsems = va_arg(ap, int);
		semflg = va_arg(ap, int);
		va_end(ap);
		return (semget(key, nsems, semflg));
	case SEMOP:
		semid = va_arg(ap, int);
		sops = va_arg(ap, struct sembuf *);
		nsops = va_arg(ap, int);
		va_end(ap);
		return (semop(semid, sops, nsops));
	}
	va_end(ap);
	return (-1);
}
