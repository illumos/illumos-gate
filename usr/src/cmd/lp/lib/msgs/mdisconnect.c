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


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.5	*/
/* LINTLIBRARY */

# include	<stropts.h>
# include	<errno.h>
# include	<stdlib.h>

#include "lp.h"
#include "msgs.h"

#if	defined(__STDC__)
static void	disconnect3_2 ( MESG * );
#else
static void	disconnect3_2();
#endif

#if	defined(__STDC__)
int mdisconnect ( MESG * md )
#else
int mdisconnect (md)
    MESG	*md;
#endif
{
    int		retvalue = 0;
    void	(**fnp)();
    MQUE	*p;

    if (!md)
    {
	errno = ENXIO;
	return(-1);
    }

    switch(md->type)
    {
	case MD_CHILD:
	case MD_STREAM:
	case MD_BOUND:
	    if (md->writefd >= 0)
		(void) Close(md->writefd);
	    if (md->readfd >= 0)
		(void) Close(md->readfd);
	    break;

	case MD_USR_FIFO:
	case MD_SYS_FIFO:
	   disconnect3_2(md);
	   break;
    }

    if (md->on_discon)
    {
	for (fnp = md->on_discon; *fnp; fnp++)
	{
	    (*fnp)(md);
	    retvalue++;
	}
	Free(md->on_discon);
    }

    if (md->file)
	Free(md->file);

    if (md->mque)
    {
	while ((p = md->mque) != NULL)
	{
	    md->mque = p->next;
	    Free(p->dat->buf);
	    Free(p->dat);
	    Free(p);
	}
    }
    Free(md);

    return(retvalue);
}

int	discon3_2_is_running = 0;

#if	defined(__STDC__)
static void disconnect3_2 ( MESG * md )
#else
static void disconnect3_2 (md)
    MESG	*md;
#endif
{
    char	*msgbuf = 0;
    int		size;

    discon3_2_is_running = 1;

    if (md->writefd != -1)
    {
	size = putmessage((char *)0, S_GOODBYE);
	if ((msgbuf = (char *)Malloc((unsigned)size)))
	{
	    (void)putmessage (msgbuf, S_GOODBYE);
	    (void)msend (msgbuf);
	    Free (msgbuf);
	}

	(void) Close (md->writefd);
    }

    if (md->readfd != -1)
	(void) Close (md->readfd);

    if (md->file)
    {
	(void) Unlink (md->file);
	Free (md->file);
    }

    discon3_2_is_running = 0;
}
