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
#include <sys/msg.h>


/* msgsys dispatch argument */
#define	MSGGET	0
#define	MSGCTL	1
#define	MSGRCV	2
#define	MSGSND	3

int
msgget(key_t key, int msgflg)
{
	return (_syscall(SYS_msgsys, MSGGET, key, msgflg));
}

int
msgctl(int msqid, int cmd, struct msqid_ds *buf)
{
	return (_syscall(SYS_msgsys, MSGCTL, msqid, cmd, buf));
}

int
msgrcv(int msqid, struct msgbuf *msgp, int msgsz, long msgtyp, int msgflg)
{
	return (_syscall(SYS_msgsys, MSGRCV,
	    msqid, msgp, msgsz, msgtyp, msgflg));
}

int
msgsnd(int msqid, struct msgbuf *msgp, int msgsz, int msgflg)
{
	return (_syscall(SYS_msgsys, MSGSND,
	    msqid, msgp, msgsz, msgflg));
}

int
msgsys(int sysnum, ...)
{
	va_list ap;
	key_t key;
	int msgflg;
	int msgflag;
	int msqid, cmd;
	struct msqid_ds *buf;
	struct msgbuf *msgp;
	int msgsz;
	long msgtyp;

	va_start(ap, sysnum);
	switch (sysnum) {
	case MSGGET:
		key = va_arg(ap, key_t);
		msgflag = va_arg(ap, int);
		va_end(ap);
		return (msgget(key, msgflag));
	case MSGCTL:
		msqid = va_arg(ap, int);
		cmd = va_arg(ap, int);
		buf = va_arg(ap, struct msqid_ds *);
		va_end(ap);
		return (msgctl(msqid, cmd, buf));
	case MSGRCV:
		msqid = va_arg(ap, int);
		msgp = va_arg(ap, struct msgbuf *);
		msgsz = va_arg(ap, int);
		msgtyp = va_arg(ap, long);
		msgflg = va_arg(ap, int);
		va_end(ap);
		return (msgrcv(msqid, msgp, msgsz, msgtyp, msgflg));
	case MSGSND:
		msqid = va_arg(ap, int);
		msgp = va_arg(ap, struct msgbuf *);
		msgsz = va_arg(ap, int);
		msgflg = va_arg(ap, int);
		va_end(ap);
		return (msgsnd(msqid, msgp, msgsz, msgflg));
	}
	va_end(ap);
	return (-1);
}
