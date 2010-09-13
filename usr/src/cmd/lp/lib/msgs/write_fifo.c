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


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.10	*/
/* LINTLIBRARY */

# include	<unistd.h>
# include	<errno.h>
# include	<string.h>

# include	"lp.h"
# include	"msgs.h"

/*
** Choose at least one byte that won't appear in the body or header
** of a message.
*/
unsigned char	Resync[HEAD_RESYNC_LEN]		= { 0x01, 0xFE };
unsigned char	Endsync[HEAD_RESYNC_LEN]	= { 0x02, 0xFD };


/*
** write_fifo() - WRITE A BUFFER WITH HEADER AND CHECKSUM
*/

#if	defined(__STDC__)
int write_fifo ( int fifo, char * buf, unsigned int size )
#else
int write_fifo (fifo, buf, size)
    int			fifo;
    char		*buf;
    unsigned int	size;
#endif
{
    unsigned short	chksum	= 0;
    int			wbytes	= 0;

    (void)memcpy (buf + HEAD_RESYNC, Resync, HEAD_RESYNC_LEN);
    (void)memcpy (buf + TAIL_ENDSYNC(size), Endsync, TAIL_ENDSYNC_LEN);

    CALC_CHKSUM (buf, size, chksum);
    (void)htos (buf + TAIL_CHKSUM(size), chksum);


    /*
    ** A message must be written in one call, to avoid interleaving
    ** messages from several processes.
    **
    ** The caller is responsible for trapping SIGPIPE, so
    ** we just return what the "write()" system call does.
    **
    ** Well, almost.  If the pipe was almost full, we may have
    ** written a partial message.  If this is the case, we lie
    ** and say the pipe was full, so the caller can try again.
    **
    ** read_fifo can deal with a truncated message, so we let it
    ** do the grunt work associated with partial messages.
    **
    ** NOTE:  Writing the remainder of the message is not feasible
    ** as someone else may have written something to the fifo
    ** while we were setting up to retry.
    */

    if ((wbytes = write(fifo, buf, size)) > 0)
	if (wbytes != size)
	    return(0);

    return(wbytes);
}
