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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma weak msgctl = _msgctl
#pragma weak msgctl64 = _msgctl64
#pragma weak msgget = _msgget
#pragma weak msgids = _msgids
#pragma weak msgsnap = _msgsnap

#include "synonyms.h"
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/ipc_impl.h>
#include <sys/msg.h>
#include <sys/msg_impl.h>
#include <sys/syscall.h>
#include <errno.h>
#include <limits.h>

int
msgget(key_t key, int msgflg)
{
	return (syscall(SYS_msgsys, MSGGET, key, msgflg));
}

int
msgctl(int msqid, int cmd, struct msqid_ds *buf)
{
	if (cmd == IPC_SET64 || cmd == IPC_STAT64) {
		(void) __set_errno(EINVAL);
		return (-1);
	}

	return (syscall(SYS_msgsys, MSGCTL, msqid, cmd, buf));
}

int
msgctl64(int msqid, int cmd, struct msqid_ds64 *buf)
{
	if (cmd != IPC_SET64 && cmd != IPC_STAT64) {
		(void) __set_errno(EINVAL);
		return (-1);
	}

	return (syscall(SYS_msgsys, MSGCTL, msqid, cmd, buf));
}

ssize_t
__msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg)
{
	if (msgsz > INT_MAX) {
		sysret_t rval;
		int error;

		/*
		 * We have to use __systemcall here because in the
		 * 64-bit case, we need to return a long, while
		 * syscall() is doomed to return an int
		 */
		error = __systemcall(&rval, SYS_msgsys, MSGRCV, msqid,
		    msgp, msgsz, msgtyp, msgflg);
		if (error)
			(void) __set_errno(error);
		return ((ssize_t)rval.sys_rval1);
	}
	return ((ssize_t)syscall(SYS_msgsys, MSGRCV, msqid,
	    msgp, msgsz, msgtyp, msgflg));
}

int
__msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg)
{
	if (msgsz > INT_MAX) {
		sysret_t rval;
		int error;

		error = __systemcall(&rval, SYS_msgsys, MSGSND, msqid,
		    msgp, msgsz, msgflg);
		if (error)
			(void) __set_errno(error);
		return ((int)rval.sys_rval1);
	}
	return (syscall(SYS_msgsys, MSGSND, msqid, msgp, msgsz, msgflg));
}

int
msgids(int *buf, uint_t nids, uint_t *pnids)
{
	return (syscall(SYS_msgsys, MSGIDS, buf, nids, pnids));
}

int
msgsnap(int msqid, void *buf, size_t bufsz, long msgtyp)
{
	return (syscall(SYS_msgsys, MSGSNAP, msqid, buf, bufsz, msgtyp));
}
