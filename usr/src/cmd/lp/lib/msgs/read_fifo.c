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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* LINTLIBRARY */

# include	<errno.h>
# include	<string.h>
#include <syslog.h>

# include	"lp.h"
# include	"msgs.h"

extern char	Resync[];
extern char	Endsync[];
static int	Had_Full_Buffer = 1;
int		Garbage_Bytes	= 0;
int		Garbage_Messages= 0;

static int _buffer(int);

/*
** A real message is written in one piece, and the write
** is atomic. Thus, even if the O_NDELAY flag is set,
** if we read part of the real message, we can continue
** to read the rest of it in as many steps as we want
** (up to the size of the message, of course!) without
** UNIX returning 0 because no data is available.
** So, a real message doesn't have to be read in one piece,
** which is good since we don't know how much to read!
**
** Fake messages, or improperly written messages, don't
** have this nice property.
**
** INTERRUPTED READS:
**
** If a signal occurs during an attempted read, we can exit.
** The caller can retry the read and we will correctly restart
** it. The correctness of this assertion can be seen by noticing
** that at the beginning of each READ below, we can go back
** to the first statement executed (the first READ below)
** and correctly reexecute the code.
**
** If the last writer closed the fifo, we'll read 0 bytes
** (at least on the subsequent read). If we were in the
** middle of reading a message, we were reading a bogus
** message (but see below).
**
** If we read less than we expect, it's because we were
** reading a fake message (but see below).
**
** HOWEVER: In the last two cases, we may have ONE OR MORE
** REAL MESSAGES snuggled in amongst the trash!
**
** All this verbal rambling is preface to let you understand why we
** buffer the data (which is a shame, but necessary).
*/

/*
** As long as we get real messages, we can avoid needless function calls.
** The SYNC argument in this macro should be set if the resynch. bytes
** have been read--i.e. if the rest of the message is trying to be read.
** In this case, if we had not read a full buffer last time, then we
** must be in the middle of a bogus message.
*/

#define UNSYNCHED_READ(N) \
    if (fbp->psave_end - fbp->psave < N || fbp->psave >= fbp->psave_end) \
    { \
	switch (_buffer(fifo)) \
	{ \
	    case -1: \
		return (-1); \
	    case 0: \
		if (fbp->psave_end > fbp->psave) \
		    goto SyncUp; \
		return (0); \
	} \
    }

#define SYNCHED_READ(N) \
    if (fbp->psave_end - fbp->psave < N || fbp->psave >= fbp->psave_end) \
    { \
	switch (_buffer(fifo)) \
	{ \
	    case -1: \
		return (-1); \
	    case 0: \
		if (fbp->psave_end > fbp->psave) \
		    goto SyncUp; \
		return (0); \
	} \
	if (!Had_Full_Buffer) \
	    goto SyncUp; \
    }

/*
** read_fifo() - READ A BUFFER WITH HEADER AND CHECKSUM
*/
int
read_fifo (fifo, buf, size)
int		fifo;
char		*buf;
unsigned int	size;
{
    register fifobuffer_t *fbp;
    register unsigned int real_chksum,
			  chksum,
			  real_size;

    /*
    ** Make sure we start on a message boundary. The first
    ** line of defense is to look for the resync. bytes.
    **
    ** The "SyncUp" label is global to this routine (below this point)
    ** and is called whenever we determine that we're out
    ** of sync. with the incoming bytes.
    */

    if (!(fbp=GetFifoBuffer (fifo)))
	return	-1;

    UNSYNCHED_READ (HEAD_RESYNC_LEN);
    while (*fbp->psave != Resync[0] || *(fbp->psave + 1) != Resync[1])
    {
SyncUp:
#if	defined(TRACE_MESSAGES)
	if (trace_messages)
		syslog(LOG_DEBUG, "DISCARD %c\n", *fbp->psave);
#endif
	fbp->psave++;
	Garbage_Bytes++;
	UNSYNCHED_READ (HEAD_RESYNC_LEN);
    }


    /*
    ** We're sync'd, so read the full header.
    */

    SYNCHED_READ (HEAD_LEN);


    /*
    ** If the header size is smaller than the minimum size for a header,
    ** or larger than allowed, we must assume that we really aren't
    ** synchronized.
    */

    real_size = stoh(fbp->psave + HEAD_SIZE);
    if (real_size < CONTROL_LEN || MSGMAX < real_size)
    {
#if	defined(TRACE_MESSAGES)
	if (trace_messages)
		syslog(LOG_DEBUG, "BAD SIZE\n");
#endif
	goto SyncUp;
    }

    /*
    ** We have the header. Now we can finally read the rest of the
    ** message...
    */

    SYNCHED_READ (real_size);


    /*
    ** ...but did we read a real message?...
    */

    if
    (
	   *(fbp->psave + TAIL_ENDSYNC(real_size)) != Endsync[0] 
	|| *(fbp->psave + TAIL_ENDSYNC(real_size) + 1) != Endsync[1] 
    )
    {
#if	defined(TRACE_MESSAGES)
	if (trace_messages)
		syslog(LOG_DEBUG, "BAD ENDSYNC\n");
#endif
	Garbage_Messages++;
	goto SyncUp;
    }

    chksum = stoh(fbp->psave + TAIL_CHKSUM(real_size));
    CALC_CHKSUM (fbp->psave, real_size, real_chksum);
    if (real_chksum != chksum)
    {
#if	defined(TRACE_MESSAGES)
	if (trace_messages)
		syslog(LOG_DEBUG, "BAD CHKSUM\n");
#endif
	Garbage_Messages++;
	goto SyncUp;
    }

    /*
    ** ...yes!...but can the caller handle the message?
    */

    if (size < real_size)
    {
	errno = E2BIG;
	return (-1);
    }


    /*
    ** Yes!! We can finally copy the message into the caller's buffer
    ** and remove it from our buffer. That wasn't so bad, was it?
    */

#if	defined(TRACE_MESSAGES)
    if (trace_messages)
	syslog(LOG_DEBUG, "MESSAGE: %-.*s", real_size, fbp->psave);
#endif
    (void)memcpy (buf, fbp->psave, real_size);
    fbp->psave += real_size;
    return (real_size);
}

int
peek3_2 (fifo)
int		fifo;
{
    register fifobuffer_t	*fbp;
    register unsigned int	real_size;

    /*
    ** Make sure we start on a message boundary. The first
    ** line of defense is to look for the resync. bytes.
    **
    ** The "SyncUp" label is global to this routine (below this point)
    ** and is called whenever we determine that we're out
    ** of sync. with the incoming bytes.
    */

    if (!(fbp=GetFifoBuffer (fifo)))
	return	-1;
    UNSYNCHED_READ (HEAD_RESYNC_LEN);
    while (*fbp->psave != Resync[0] || *(fbp->psave + 1) != Resync[1])
    {
SyncUp:
	fbp->psave++;
	Garbage_Bytes++;
	UNSYNCHED_READ (HEAD_RESYNC_LEN);
    }


    /*
    ** We're sync'd, so read the full header.
    */

    SYNCHED_READ (HEAD_LEN);


    /*
    ** If the header size is smaller than the minimum size for a header,
    ** or larger than allowed, we must assume that we really aren't
    ** synchronized.
    */

    real_size = stoh(fbp->psave + HEAD_SIZE);
    if (real_size < CONTROL_LEN || MSGMAX < real_size)
    {
	goto SyncUp;
    }

    return(real_size);
}

static int
_buffer(int fifo)
{
	     int	   n, nbytes, count = 0;
    register fifobuffer_t  *fbp;

    /*
    ** As long as we get real messages, and if we chose
    ** SAVE_SIZE well, we shouldn't have to move the data
    ** in the "else" branch below: Each time we call "read"
    ** we aren't likely to get as many bytes as we ask for,
    ** just as many as are in the fifo, AND THIS SHOULD
    ** REPRESENT AN INTEGRAL NUMBER OF MESSAGES. Since
    ** the "read_fifo" routine reads complete messages,
    ** it will end its read at the end of the message,
    ** which (eventually) will make "psave_end" == "psave".
    */

    /*
    ** If the buffer is empty, there's nothing to move.
    */
    if (!(fbp = GetFifoBuffer (fifo)))
	return	-1;
    if (fbp->psave_end == fbp->psave)
	fbp->psave = fbp->psave_end = fbp->save;	/* sane pointers! */

    /*
    ** If the buffer has data at the high end, move it down.
    */
    else
    if (fbp->psave != fbp->save)		/* sane pointers! */
    {
	/*
	** Move the data still left in the buffer to the
	** front, so we can read as much as possible into
	** buffer after it.
	*/

	memmove(fbp->save, fbp->psave, fbp->psave_end - fbp->psave);

	fbp->psave_end = fbp->save + (fbp->psave_end - fbp->psave);
	fbp->psave = fbp->save;	/* sane	pointers! */
    }

    /*
    ** The "fbp->psave" and "fbp->psave_end" pointers must be in a sane
    ** state when we get here, in case the "read()" gets interrupted.
    ** When that happens, we return to the caller who may try
    ** to restart us! Sane: fbp->psave == fbp->save (HERE!)
    */

    nbytes = MSGMAX - (fbp->psave_end - fbp->save);

    while ((n = read(fifo, fbp->psave_end, nbytes)) == 0 && count < 60)
    {
	(void)	sleep ((unsigned) 1);
	count++;
    }

    if (n > 0)
	fbp->psave_end += n;

    Had_Full_Buffer = fbp->full;
    fbp->full = (nbytes == n);

    return (n);
}
