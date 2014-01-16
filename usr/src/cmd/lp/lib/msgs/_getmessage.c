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
/* LINTLIBRARY */

# include	<stdarg.h>
# include	<string.h>
# include	<errno.h>

# include	"msgs.h"

extern char	*_lp_msg_fmts[];
extern int	errno;

/* VARARGS */
#if	defined(__STDC__)
int _getmessage ( char * buf, short rtype, va_list arg )
#else
int _getmessage (buf, rtype, arg)
    char	*buf;
    short	rtype;
    va_list	arg;
#endif
{
    char	*endbuf;
    char	*fmt;
    char	**t_string;
    int		temp = 0;
    long	*t_long;
    short	*t_short;
    short	etype;

    if (buf == (char *)0)
    {
	errno = ENOSPC;
	return(-1);
    }

    /*
     * We assume that we're given a buffer big enough to hold
     * the header.
     */

    endbuf = buf + (long)stoh(buf);
    if ((buf + MESG_DATA) > endbuf)
    {
	errno = ENOMSG;
	return(-1);
    }

    etype = stoh(buf + MESG_TYPE);
    if (etype < 0 || etype > LAST_MESSAGE)
    {
	errno = EBADMSG;
        return(-1);
    }

    if (etype != rtype)
    {
	if (rtype > 0 && rtype <= LAST_MESSAGE)
	    fmt = _lp_msg_fmts[rtype];
	else
	{
	    errno = EINVAL;
	    return(-1);
	}
    }
    else
	fmt = _lp_msg_fmts[etype];

    buf += MESG_LEN;

    while (*fmt != '\0')
	switch(*fmt++)
	{
	    case 'H':
	        if ((buf + 4) > endbuf)
		{
		    errno = ENOMSG;
		    return(-1);
		}

		t_short = va_arg(arg, short *);
		*t_short = stoh(buf);
		buf += 4;
		break;

	    case 'L':
		if ((buf + 8) > endbuf)
		{
		    errno = ENOMSG;
		    return(-1);
		}

		t_long = va_arg(arg, long *);
		*t_long = stol(buf);
		buf += 8;
		break;

	    case 'D':
		if ((buf + 4) > endbuf)
		{
		    errno = ENOMSG;
		    return(-1);
		}

		t_short = va_arg(arg, short *);
		*t_short = stoh(buf);
		buf += 4;
		t_string = va_arg(arg, char **);
		if ((buf + *t_short) > endbuf)
		{
		    errno = ENOMSG;
		    return(-1);
		}
		(*t_short)--;		/* Don't mention the null we added */
		*t_string = buf;
		buf += *t_short;
		break;

	    case 'S':
		if ((buf + 4) > endbuf)
		{
		    errno = ENOMSG;
		    return(-1);
		}

		t_string = va_arg(arg, char **);
		temp = stoh(buf);
		buf += 4;
		if ((buf + temp) > endbuf)
		{
		    errno = ENOMSG;
		    return(-1);
		}

		*t_string = buf;
		buf += temp;
		break;
	}
    return(etype);
}
