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


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.3	*/
/* LINTLIBRARY */
# include	<errno.h>

# include	"lp.h"
# include	"msgs.h"

extern MESG	*lp_Md;

/*
** mrecv() - RECEIVE A MESSAGE
*/

int
mrecv (msgbuf, size)
char	*msgbuf;
int	size;
{
    int		n;

    /*
    **	Restart interrupted reads for binary compatibility.
    */
    do
	n = mread(lp_Md, msgbuf, size);
    while (n < 0 && errno == EINTR);

    /*
    **	Return EIDRM on disconnect for binary compatibility.
    */
    if (errno == EPIPE)
	errno = EIDRM;

    if (n <= 0)
	return(-1);

    return(getmessage(msgbuf, I_GET_TYPE));
}
