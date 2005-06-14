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


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.9	*/

#include "stdio.h"

#if	defined(__STDC__)
#include "stdarg.h"
#else
#include "varargs.h"
#endif

#include "msgs.h"

#define	WHO_AM_I	I_AM_LPADMIN
#include "oam.h"

#include "lpadmin.h"


/**
 ** send_message() - HANDLE MESSAGE SENDING TO SPOOLER
 **/

/*VARARGS1*/

void
#if	defined(__STDC__)
send_message (
	int			type,
	...
)
#else
send_message (type, va_alist)
	int			type;
	va_dcl
#endif
{
	va_list			ap;

	int			n;

	char			msgbuf[MSGMAX];


	if (!scheduler_active)
		return;

#if	defined(__STDC__)
	va_start (ap, type);
#else
	va_start (ap);
#endif

	(void)_putmessage (msgbuf, type, ap);

	va_end (ap);

	if (msend(msgbuf) == -1) {
		LP_ERRMSG (ERROR, E_LP_MSEND);
		done(1);
	}

	return;
}
