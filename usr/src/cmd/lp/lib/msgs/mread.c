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


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.6	*/
/* LINTLIBRARY */


#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stropts.h>

#include "lp.h"
#include "msgs.h"

extern int	Lp_prio_msg;

/*
**	Function:	int mread( MESG *, char *, int)
**	Args:		message descriptor
**			message buffer (var)
**			buffer size
**	Return:		The size of the message in message buffer.
**			or -1 on error.  Possible errnos are:
**		EINVAL	Bad value for md or msgbuf.
**		E2BIG	Not enough space for message.
**		EPIPE	Far end dropped the connection.
**		ENOMSG	No valid message available on fifo.
**
**	mread examines message descriptor and either calls read3_2
**	to read 3.2 HPI messages or getmsg(2) to read 4.0 HPI messages.
**	If a message is read, it is returned in message buffer.
*/

#if	defined(__STDC__)
int mread ( MESG * md, char * msgbuf, int size )
#else
int mread ( md, msgbuf, size )
MESG	*md;
char	*msgbuf;
int	size;
#endif
{
    int			flag = 0;
    char		buff [MSGMAX];
    struct strbuf	dat;
    struct strbuf	ctl;

    if (md == NULL || msgbuf == NULL)
    {
	errno = EINVAL;
	return(-1);
    }

    switch(md->type)
    {
      case MD_CHILD:
      case MD_STREAM:
      case MD_BOUND:
	if (size <= 0)
	{
	    errno = E2BIG;
	    return(-1);
	}
	dat.buf = msgbuf;
	dat.maxlen = size;
	dat.len = 0;
	ctl.buf = buff;
	ctl.maxlen = sizeof (buff);
	ctl.len = 0;
	flag = Lp_prio_msg;
	Lp_prio_msg = 0;	/* clean this up so there are no surprises */

	if (Getmsg(md, &ctl, &dat, &flag) < 0)
	{
	    if (errno == EBADF)
		errno = EPIPE;
	    return(-1);
	}

	if (dat.len == 0)
	{
	    (void) Close(md->readfd);
	    return(0);
	}
	break;

      case MD_USR_FIFO:
      case MD_SYS_FIFO:
	if (size < CONTROL_LEN)
	{
	    errno = E2BIG;
	    return(-1);
	}

	if (read3_2(md, msgbuf, size) < 0)
	    return(-1);
	break;
    }

    return((int)msize(msgbuf));
}
