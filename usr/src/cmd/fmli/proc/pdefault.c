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

/*	Copyright (c) 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <sys/types.h>	/* EFT abs k16 */
#include "wish.h"
#include "terror.h"
#include "token.h"
#include "slk.h"
#include "actrec.h"
#include "proc.h"
#include "procdefs.h"

struct proc_rec PR_all[MAX_PROCS];
static int pflag=1;
static int find_freeproc(void);

/* make a default process, i.e. one that takes over the full screen */

proc_id
proc_default(flags, argv)
int flags;
char *argv[];
{
	register int i;
	int index;
	char *expand();

	if (pflag) {
		proc_init();
		pflag=0;
	}
	if ((index = find_freeproc()) == FAIL) {
		mess_temp("Too many suspended activities!  Use frm-mgmt list to resume and close some.");
		return(FAIL);
	} 
	
#ifdef _DEBUG
	_debug(stderr, "Creating process at %d\n", index);
#endif
	PR_all[index].argv[0] = PR_all[index].name = expand(argv[0]);
#ifdef _DEBUG
	_debug(stderr, "PROCESS: %s", PR_all[index].name);
#endif
	for (i = 1; argv[i]; i++) {
		PR_all[index].argv[i] = expand(argv[i]);
#ifdef _DEBUG
		_debug(stderr, " %s", PR_all[index].argv[i]);
#endif
	}
#ifdef _DEBUG
	_debug(stderr, "\n");
#endif
	PR_all[index].argv[i] = NULL;
	PR_all[index].ar =  NULL;
	PR_all[index].status =  ST_RUNNING;
	PR_all[index].flags = flags;

	PR_all[index].pid = PR_all[index].respid = NOPID;
	return(index);
}

static int
find_freeproc(void)
{
	register int i;

	for (i = 0; i < MAX_PROCS; i++)
		if (PR_all[i].name == NULL)
			return(i);
	return(FAIL);
}

int
proc_init()
{
	register int i, j;

	for (i = 0; i < MAX_PROCS; i++) {
		PR_all[i].name = NULL;
		for (j=0; j < MAX_ARGS +2; j++)
			PR_all[i].argv[j] = NULL;
	}
	return (0);
}

