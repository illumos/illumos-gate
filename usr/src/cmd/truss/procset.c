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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <libproc.h>
#include "ramdata.h"
#include "proto.h"

/*
 * Function prototypes for static routines in this module.
 */
const char *idop_enum(private_t *, idop_t);

void
show_procset(private_t *pri, long offset)
{
	procset_t procset;
	procset_t *psp = &procset;

	if (Pread(Proc, psp, sizeof (*psp), offset) == sizeof (*psp)) {
		(void) printf("%s\top=%s",
			pri->pname, idop_enum(pri, psp->p_op));
		(void) printf("  ltyp=%s lid=%ld",
			idtype_enum(pri, psp->p_lidtype), (long)psp->p_lid);
		(void) printf("  rtyp=%s rid=%ld\n",
			idtype_enum(pri, psp->p_ridtype), (long)psp->p_rid);
	}
}

const char *
idop_enum(private_t *pri, idop_t arg)
{
	const char *str;

	switch (arg) {
	case POP_DIFF:	str = "POP_DIFF";	break;
	case POP_AND:	str = "POP_AND";	break;
	case POP_OR:	str = "POP_OR";		break;
	case POP_XOR:	str = "POP_XOR";	break;
	default:
		(void) sprintf(pri->code_buf, "%d", arg);
		str = (const char *)pri->code_buf;
		break;
	}

	return (str);
}

const char *
idtype_enum(private_t *pri, long arg)
{
	const char *str;

	switch (arg) {
	case P_PID:	str = "P_PID";		break;
	case P_PPID:	str = "P_PPID";		break;
	case P_PGID:	str = "P_PGID";		break;
	case P_SID:	str = "P_SID";		break;
	case P_CID:	str = "P_CID";		break;
	case P_UID:	str = "P_UID";		break;
	case P_GID:	str = "P_GID";		break;
	case P_ALL:	str = "P_ALL";		break;
	case P_LWPID:	str = "P_LWPID";	break;
	case P_TASKID:	str = "P_TASKID";	break;
	case P_PROJID:	str = "P_PROJID";	break;
	case P_ZONEID:	str = "P_ZONEID";	break;
	case P_CTID:	str = "P_CTID";		break;
	default:
		(void) sprintf(pri->code_buf, "%ld", arg);
		str = (const char *)pri->code_buf;
		break;
	}

	return (str);
}

const char *
woptions(private_t *pri, int arg)
{
	char *str = pri->code_buf;

	if (arg == 0)
		return ("0");
	if (arg &
	    ~(WEXITED|WTRAPPED|WSTOPPED|WCONTINUED|WNOHANG|WNOWAIT))
		return (NULL);

	*str = '\0';
	if (arg & WEXITED)
		(void) strcat(str, "|WEXITED");
	if (arg & WTRAPPED)
		(void) strcat(str, "|WTRAPPED");
	if (arg & WSTOPPED)
		(void) strcat(str, "|WSTOPPED");
	if (arg & WCONTINUED)
		(void) strcat(str, "|WCONTINUED");
	if (arg & WNOHANG)
		(void) strcat(str, "|WNOHANG");
	if (arg & WNOWAIT)
		(void) strcat(str, "|WNOWAIT");

	return ((const char *)(str+1));
}
