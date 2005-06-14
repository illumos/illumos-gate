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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright  (c) 1985 AT&T
 *	All Rights Reserved
 */
#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.5 */

#include <stdio.h>
#include <signal.h>
#include <sys/types.h>	/* EFT abs k16 */
#include "wish.h"
#include "token.h"
#include "slk.h"
#include "actrec.h"
#include "proc.h"
#include "procdefs.h"
#include "terror.h"

extern struct proc_rec PR_all[];
extern int Vflag;

int
proc_close(rec)
register struct actrec	*rec;
{
	int	i;
	int	id;
	pid_t	pid;		/* EFT abs k16 */
	int	oldsuspend;

	if (Vflag)
		showmail(TRUE);
	id = rec->id;
	pid = PR_all[id].pid;
#ifdef _DEBUG
	_debug(stderr, "closing process table %d, pid=%d\n", id, pid);
#endif
	if (pid != NOPID) {	/* force the user to close by resuming it */
#ifdef _DEBUG
		_debug(stderr, "FORCING CLOSE ON PID %d\n", pid);
#endif
		oldsuspend = suspset(FALSE);	/* disallow suspend */
		PR_all[id].flags |= PR_CLOSING;
		ar_current(rec, TRUE); /* abs k15 */
		suspset(oldsuspend);
	}
	for (i = 0; i < MAX_ARGS && PR_all[id].argv[i]; i++)
		free(PR_all[id].argv[i]);
	PR_all[id].name = NULL;
	PR_all[id].status = ST_DEAD;
	if (rec->path)
		free(rec->path);
	if (rec->odptr)
		free(rec->odptr);
	return SUCCESS;
}
