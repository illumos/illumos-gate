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


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.8	*/
/* LINTLIBRARY */

# include	<errno.h>
# include	<string.h>
# include	<stropts.h>

# include	"lp.h"
# include	"msgs.h"

int	Lp_prio_msg = 0;

static int	_mwrite ( MESG * md , char * msgbuf , int );

/*
 * mflush()
 *	return 0
 *		if it successfully writes all the queued message(s), or
 *		if some of them (errno is EAGAIN in this case).
 *	return -1 (with errno) when it failed.
 */

int
mflush(MESG *md)
{
	MQUE	*p;

	errno = 0;
	if (md == NULL || md->mque == NULL) {
		errno = ENXIO;
		return (-1);
	}

	while ((p = md->mque) != NULL) {
		if (_mwrite(md, p->dat->buf, p->dat->len) != 0)
			return (errno == EAGAIN ? 0 : -1);
		
		/* mwrite successful, get the next and free this entry */
		md->mque = p->next;
		Free(p->dat->buf);
		Free(p->dat);
		Free(p);
	}

	return (0);
}

/*
 * mwrite()
 *	return 0
 *		if it successfully writes the messages, or
 *		if it has been queued  (errno is EAGAIN in this case)
 *			and md->mque is updated.
 *	return -1 (with errno) when it failed.
 */

int mwrite ( MESG * md, char * msgbuf )
{
    short		size;
    MQUE *		p;
    MQUE *		q;

    errno = 0;
    if (md == NULL)
    {
	errno = ENXIO;
	return(-1);
    }
    if (msgbuf == NULL)
    {
	errno = EINVAL;
	return(-1);
    }

    size = stoh(msgbuf);

    if (LAST_MESSAGE < stoh(msgbuf + MESG_TYPE))
    {
	errno = EINVAL;
	return (-1);
    }
    if (md->mque)
	goto queue;	/* if there is a queue already, try to write all */

    if (_mwrite(md, msgbuf, size) == 0)
	return(0);

    if (errno != EAGAIN)
	return(-1);

	/*
	 * fall through to queue the messages that cannot be sent now.
	 */

queue:
    if ((p = (MQUE *)Malloc(sizeof(MQUE))) == NULL
        || (p->dat = (struct strbuf *)Malloc(sizeof(struct strbuf))) == NULL
    	|| (p->dat->buf = (char *)Malloc(size)) == NULL)
    {
	errno = ENOMEM;
	return(-1);
    }
    (void) memcpy(p->dat->buf, msgbuf, size);
    p->dat->len = size;
    p->next = 0;

    if ((q = md->mque) != NULL)
    {
	/* insert the new one to tail */
	while (q->next)
	    q = q->next;
	q->next = p;

    	while ((p = md->mque) != NULL)
    	{
		if (_mwrite(md, p->dat->buf, p->dat->len) != 0) {
	    		return (errno == EAGAIN ? 0 : -1);
		}

		/* mwrite successful, get the next and free this entry */
		md->mque = p->next;
		Free(p->dat->buf);
		Free(p->dat);
		Free(p);
	}
    }
    else
    	md->mque = p;

    return(0);
}

int _mwrite ( MESG * md, char * msgbuf , int size )
{
    int			flag = 0;
    struct strbuf	ctl;
    struct strbuf	dat;

    switch (md->type)
    {
        case MD_CHILD:
	case MD_STREAM:
	case MD_BOUND:
	    if (size <= 0 || size > MSGMAX)
	    {
		errno = EINVAL;
		return(-1);
	    }

	    ctl.buf = "xyzzy";
	    ctl.maxlen = ctl.len = strlen(ctl.buf)+1;
	    dat.buf = msgbuf;
	    dat.maxlen = dat.len = size;
	    flag = Lp_prio_msg;
	    Lp_prio_msg = 0;	/* clean this up so there are no surprises */

	    if (Putmsg(md, &ctl, &dat, flag) == 0)
		return(0);
	    return(-1);

	case MD_SYS_FIFO:
	case MD_USR_FIFO:
	    switch (write3_2(md, msgbuf, size))
	    {
		case -1:
		    return(-1);
		case 0:
		    break;
		default:
		    return(0);
	    }
	    break;

	default:
	    errno = EINVAL;
	    return(-1);
    }
    return 0;
}
