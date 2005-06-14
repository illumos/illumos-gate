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
/*	Copyright (c) 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <sys/types.h>   /* EFT abs k16 */
#include "wish.h"
#include "token.h"
#include "slk.h"
#include "actrec.h"
#include "proc.h"
#include "procdefs.h"
#include "terror.h"
#include "ctl.h"
#include "sizes.h"


extern struct proc_rec PR_all[];

int
proc_ctl(rec, cmd, arg1, arg2, arg3, arg4, arg5, arg6)
struct actrec *rec;
int cmd;
int arg1, arg2, arg3, arg4, arg5, arg6;
{
    static char title[MAX_WIDTH];
    int p = rec->id;
    register int len, i;

    switch (cmd) {
    case CTGETITLE:
	if (rec->odptr) {
	    **((char ***)(&arg1)) = rec->odptr;
	} else {
	    len = sprintf(title, "%.*s ", MAX_TITLE, PR_all[p].name);
	    i = 1;
	    while (len<MAX_TITLE  && i<MAX_ARGS && PR_all[p].argv[i]) {
		len += sprintf(title+len, "%.*s ", MAX_TITLE-len,
			       filename(PR_all[p].argv[i]));
		i++;
	    }
	    **((char ***)(&arg1)) = &title[0];
	}
	return(SUCCESS);
    case CTGETPID:
	*((pid_t *)arg1) = PR_all[rec->id].respid; /* EFT abs k16 */
	return(SUCCESS);		/* miked k17 */
    case CTSETPID:
	PR_all[rec->id].respid = (pid_t)arg1;      /* EFT abs k16 */
	return(SUCCESS);
    default:
	return(FAIL);
    }
}
