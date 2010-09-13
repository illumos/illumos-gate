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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/



#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.2	*/

#include	<unistd.h>
#include	<signal.h>
#include	<stropts.h>
#include	<errno.h>
#include	"lp.h"
#include	"msgs.h"

extern	int	errno;

/*
 * Putmsg() function
 * Return 0: success,
 *        non-zero: return code of the failed putmsg() system call.
 *		    plus errno for caller to check.
 * NOTE: cannot do TRACE* calls if errno is expected to be returned!
 *	 TRACE* uses fprintf and destroys the content of errno.
 *	 Save errno before the TRACE* calls.
 */

int
Putmsg (MESG *mdp, strbuf_t *ctlp, strbuf_t *datap, int flags)
{
	int	i;
	int	rtncode;
	int	count;
	struct pollfd fds;

	fds.fd = mdp->writefd;
	fds.events = POLLOUT;
	fds.revents = 0;

	(void) poll(&fds, 1, 1000);
	if (fds.revents & (POLLHUP | POLLERR | POLLNVAL)) {
		errno = EBADF;
		return (-1);
	}

	if (!(fds.revents & POLLOUT)) {
		errno = EAGAIN;
		return (-1);
	}

	rtncode = putmsg (mdp->writefd, ctlp, datap, flags);
	return (rtncode);
}

int
Getmsg (MESG *mdp, strbuf_t *ctlp, strbuf_t *datap, int *flagsp)
{
	int	rtncode;

	rtncode = getmsg (mdp->readfd, ctlp, datap, flagsp);
	return (rtncode);
}

char		AuthCode[HEAD_AUTHCODE_LEN];
static void	(*callers_sigpipe_trap)() = SIG_DFL;


/*
**	Function:	static int read3_2( MESG *, char *, int)
**	Args:		message descriptor
**			message buffer (var)
**			buffer size
**	Return:		0 for sucess, -1 for failure
**
**	This performs a 3.2 HPI style read_fifo on the pipe referanced
**	in the message descriptor.  If a message is found, it is returned
**	in message buffer.
*/
int read3_2 ( MESG * md, char *msgbuf, int size )
{
    short	type;

    if (md->type == MD_USR_FIFO)
	(void) Close (Open(md->file, O_RDONLY, 0));

    do
    {
	switch (read_fifo(md->readfd, msgbuf, size))
	{
	  case -1:
	    return (-1);

	  case 0:
	    /*
	     ** The fifo was empty and we have O_NDELAY set,
	     ** or the Spooler closed our FIFO.
	     ** We don't set O_NDELAY in the user process,
	     ** so that should never happen. But be warned
	     ** that we can't tell the difference in some versions
	     ** of the UNIX op. sys.!!
	     **
	     */
	    errno = EPIPE;
	    return (-1);
	}

	if ((type = stoh(msgbuf + HEAD_TYPE)) < 0 || LAST_MESSAGE < type)
	{
	    errno = ENOMSG;
	    return (-1);
	}
    }
    while (type == I_QUEUE_CHK);

    (void)memcpy (AuthCode, msgbuf + HEAD_AUTHCODE, HEAD_AUTHCODE_LEN);

    /*
    **	Get the size from the 3.2 HPI message
    **	minus the size of the control data
    **	Copy the actual message
    **	Reset the message size.
    */
    size = stoh(msgbuf + HEAD_SIZE) - EXCESS_3_2_LEN;
    memmove(msgbuf, msgbuf + HEAD_SIZE, size);
    (void) htos(msgbuf + MESG_SIZE, size);
    return(0);
}

int write3_2 ( MESG * md, char * msgbuf, int size )
{
    char	tmpbuf [MSGMAX + EXCESS_3_2_LEN];
    int		rval;


    (void) memmove(tmpbuf + HEAD_SIZE, msgbuf, size);
    (void) htos(tmpbuf + HEAD_SIZE, size + EXCESS_3_2_LEN);
    (void) memcpy (tmpbuf + HEAD_AUTHCODE, AuthCode, HEAD_AUTHCODE_LEN);

    callers_sigpipe_trap = signal(SIGPIPE, SIG_IGN);

    rval = write_fifo(md->writefd, tmpbuf, size + EXCESS_3_2_LEN);

    (void) signal(SIGPIPE, callers_sigpipe_trap);


    return (rval);
}
