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
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.2	*/

#if defined(__STDC__)
#include <stdarg.h>
#else
#include <varargs.h>
#endif
#include "lp.h"
#include "msgs.h"
#define WHO_AM_I	I_AM_OZ		/* to get oam.h to unfold */
#include "oam.h"
#include "lpd.h"

/*
 * Format and send message to lpsched
 * (die if any errors occur)
 */
/*VARARGS1*/
void
#if defined (__STDC__)
snd_msg(int type, ...)
#else
snd_msg(type, va_alist)
int	type;
va_dcl
#endif
{
	va_list	ap;

#if defined (__STDC__)
	va_start(ap, type);
#else
	va_start(ap);
#endif
	(void)_putmessage (Msg, type, ap);
	va_end(ap);
	if (msend(Msg) == -1) {
		lp_fatal(E_LP_MSEND); 
		/*NOTREACHED*/
	}
}

/*
 * Recieve message from lpsched
 * (die if any errors occur)
 */
void
#if defined (__STDC__)
rcv_msg(int type, ...)
#else
rcv_msg(type, va_alist)
int	type;
va_dcl
#endif
{
	va_list ap;
	int rc;

	if ((rc = mrecv(Msg, MSGMAX)) != type) {
		if (rc == -1)
			lp_fatal(E_LP_MRECV); 
		else
			lp_fatal(E_LP_BADREPLY, rc); 
		/*NOTREACHED*/
	}
#if defined (__STDC__)
	va_start(ap, type);
#else
	va_start(ap);
#endif
	rc = _getmessage(Msg, type, ap);
	va_end(ap);
	if (rc < 0) {
		lp_fatal(E_LP_GETMSG, PERROR); 
		/*NOTREACHED*/ 
	} 
}
