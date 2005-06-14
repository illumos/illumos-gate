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
#include "wish.h"
#include "token.h"
#include "slk.h"
#include "actrec.h"

/* This file contains standard menu functions that can be used for
 * popup internal menus.  They simply take the activation record
 * pointer's id field and call the equivalent menu function.
 */

int
AR_MEN_CLOSE(a)
struct actrec *a;
{ return(menu_close(a->id)); }

int
AR_MEN_CURRENT(a)
struct actrec *a;
{ return(menu_current(a->id)); }

int
AR_MEN_NONCUR(a)
struct actrec *a;
{ return(menu_noncurrent(a->id)); }

int
AR_NOP(a)
struct actrec *a;
{ return(SUCCESS); }

int
AR_NOHELP(a)
struct actrec *a;
{
	mess_temp("No help available here");
	return(SUCCESS);
}

int
AR_MEN_CTL(a, cmd, arg1, arg2, arg3, arg4, arg5, arg6)
struct actrec *a;
int cmd, arg1, arg2, arg3, arg4, arg5, arg6;
{ return(menu_ctl(a->id, cmd, arg1, arg2, arg3, arg4, arg5, arg6)); }

token
AR_MEN_ODSH(a, t)
struct actrec *a;
token t;
{ 
	token menu_stream();

	if (t == TOK_CANCEL)
		t = TOK_CLOSE;
	return(menu_stream(t));
}

void
ar_menu_init(a)
struct actrec *a;
{
	extern struct slk Echslk[];

	a->lifetime = AR_SHORTERM;
	a->path = NULL;
	a->odptr = NULL;
	a->slks = &Echslk[0];
	a->flags = 0;
	a->fcntbl[AR_CLOSE] = AR_MEN_CLOSE;
	a->fcntbl[AR_REREAD] = AR_NOP;
	a->fcntbl[AR_REINIT] = AR_NOP;
	a->fcntbl[AR_CURRENT] = AR_MEN_CURRENT;
	a->fcntbl[AR_TEMP_CUR] = AR_MEN_CURRENT;  /* abs k16 */
	a->fcntbl[AR_NONCUR] = AR_MEN_NONCUR;
	a->fcntbl[AR_CTL] = AR_MEN_CTL;
	a->fcntbl[AR_ODSH] = (int (*)())AR_MEN_ODSH; /* added cast abs */
	a->fcntbl[AR_HELP] = AR_NOHELP;
}
