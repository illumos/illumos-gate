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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/* LINTLIBRARY */

# include	<unistd.h>
# include	<fcntl.h>
# include	<errno.h>
# include	<sys/utsname.h>
# include	<stdlib.h>
# include	<sys/types.h>
# include	<sys/stat.h>

#include "lp.h"
#include "msgs.h"

#define TURN_OFF(X,F)	(void)Fcntl(X, F_SETFL, (Fcntl(X, F_GETFL, 0) & ~(F)))

#if	defined(__STDC__)
static MESG *	connect3_2 ( void );
static int	checklock ( void );
#else
static MESG *	connect3_2();
static int	checklock();
#endif

/*
** mconnect() - OPEN A MESSAGE PATH
*/

#if	defined(__STDC__)
MESG * mconnect ( char * path, int id1, int id2 )
#else
MESG * mconnect ()
    char	*path;
    int		id1;
    int		id2;
#endif
{
    int		fd;
    int		wronly = 0;
    int		count = 0;
    MESG	*md;
    struct stat	stbuf;

    /*
    **	invoked as mconnect(path, 0, 0)
    **
    **	Open <path>, if isastream() is true for the returned file
    **	descriptor, then we're done.  If not, proceed with the 3.2
    **	handshaking.
    */

    if (path)
    {
	/*
	**	Verify that the spooler is running and that the
	**	<path> identifies a pipe.
	**	This prevents us from getting hung in the open
	**	and from thinking the <path> is a non-streams pipe.
	*/
	if (checklock() == -1)
	    return(NULL);
Again:	if (stat(path, &stbuf) == -1)
	    return(NULL);
	if ((stbuf.st_mode & S_IFMT) != S_IFIFO) {
            if (count++ > 20)
		return (NULL);
	    sleep(1);
	    goto Again;
	}

	if ((fd = Open(path, O_RDWR, 0)) == -1)
	    if ((fd = Open(path, O_WRONLY, 0)) == -1)
		return(NULL);
	    else
		wronly = 1;
	
	if (isastream(fd) && !wronly)
	{
#if	defined(NOCONNLD)
	    int		fds[2];

	    if (pipe(fds) != 0)
		return(NULL);

	    if (ioctl(fd, I_SENDFD, fds[1]) != 0)
		return(NULL);

	    (void)_Close(fd);
	    
	    fd = fds[0];
	    (void)_Close(fds[1]);
#endif

	    if ((md = (MESG *)Malloc(MDSIZE)) == NULL)
	    {
		errno = ENOMEM;
		return(NULL);
	    }

	    memset(md, 0, sizeof (MESG));
	    md->gid = getgid();
	    md->on_discon = NULL;
	    md->readfd = fd;
	    md->state = MDS_IDLE;
	    md->type = MD_STREAM;
	    md->uid = getuid();
	    md->writefd = fd;

	    ResetFifoBuffer (md->readfd);
	    return(md);
	}

	return(connect3_2());
    }

    if (id1 > 0 && id2 > 0)
    {
	if ((md = (MESG *)Malloc(MDSIZE)) == NULL)
	{
	    errno = ENOMEM;
	    return(NULL);
	}

	memset(md, 0, sizeof (MESG));
	md->gid = getgid();
	md->on_discon = NULL;
	md->readfd = id1;
	md->state = MDS_IDLE;
	md->type = MD_BOUND;
	md->uid = getuid();
	md->writefd = id2;

	ResetFifoBuffer (md->readfd);

	return(md);
    }

    errno = EINVAL;
    return(NULL);
}

#if	defined(__STDC__)
static MESG * connect3_2 ( void )
#else
static MESG * connect3_2()
#endif
{
    char		*msgbuf = 0,
			*fifo_name	= "UUUUUUUUNNNNN";
    int			tmp_fd = -1,
			size;
    short		status;
    struct utsname	ubuf;
    MESG		*md;

    if ((md = (MESG *)Malloc(MDSIZE)) == NULL)
	return(NULL);

    memset(md, 0, sizeof (MESG));
    md->gid = getgid();
    md->state = MDS_IDLE;
    md->type = MD_USR_FIFO;
    md->uid = getuid();

    if ((md->writefd = Open(Lp_FIFO, O_WRONLY, 0222)) == -1)
    {
	errno = ENOENT;
	return (NULL);
    }

    /*
    ** Combine the machine node-name with the process ID to
    ** get a name that will be unique across the network.
    ** The 99999 is just a safety precaution against over-running
    ** the buffer.
    */

    (void)uname (&ubuf);

    sprintf (fifo_name, "%.8s%u", ubuf.nodename, (getpid() & 99999));

    if (!(md->file = makepath(Lp_Public_FIFOs, fifo_name, (char *)0)))
    {
	errno = ENOMEM;
	goto Error;
    }

    (void) Unlink(md->file);
    
    if (Mknod(md->file, S_IFIFO | S_IRUSR, 0) == -1)
	goto Error;

    if ((md->readfd = Open(md->file, O_RDONLY|O_NDELAY, S_IRUSR)) == -1)
	goto Error;
    
    TURN_OFF (md->readfd, O_NDELAY);

    size = putmessage((char *)0, S_NEW_QUEUE, 0, fifo_name, ubuf.nodename);
    if (!(msgbuf = Malloc((unsigned)size)))
    {
	errno = ENOMEM;
	goto Error;
    }
    (void) putmessage(msgbuf, S_NEW_QUEUE, 0, fifo_name, ubuf.nodename);

    if (
	   mwrite(md, msgbuf) == -1
	|| mread(md, msgbuf, size) == -1
	|| getmessage(msgbuf, R_NEW_QUEUE, &status) != R_NEW_QUEUE
       )
    {
	Free (msgbuf);
	goto Error;
    }
    else
	if (status != MOK)
	{
	    Free(msgbuf);
	    errno = ENOSPC;
	    goto Error;
	}

    Free (msgbuf);

    /*
     * Prepare to use the fifo the Spooler created.  This new FIFO can be
     * read ONLY by who we said we are, so if we lied, tough luck for us!
     */

    (void)Unlink (md->file);	/* must exist to get here */
    tmp_fd = md->readfd;			/* save the old fd */

    Free(md->file);

    if (!(md->file = makepath(Lp_Private_FIFOs, fifo_name, (char *)0)))
    {
	errno = ENOMEM;
	goto Error;
    }

    if ((md->readfd = Open(md->file, O_RDONLY|O_NDELAY, S_IRUSR)) == -1)
	goto Error;

    TURN_OFF (md->readfd, O_NDELAY);

    size = putmessage((char *)0, S_NEW_QUEUE, 1, fifo_name, ubuf.nodename);
    if (!(msgbuf = Malloc((unsigned)size)))
    {
        errno = ENOMEM;
        goto Error;
    }
    (void) putmessage(msgbuf, S_NEW_QUEUE, 1, fifo_name, ubuf.nodename);

    if (
	   mwrite(md, msgbuf) == -1
	|| mread(md, msgbuf, size) == -1
	|| getmessage(msgbuf, R_NEW_QUEUE, &status) != R_NEW_QUEUE
       )
    {
	Free (msgbuf);
	goto Error;
    }
    else
	if (status != MOK)
	{
	    Free(msgbuf);
	    errno = ENOSPC;
	    goto Error;
	}

    Free (msgbuf);
    (void) Close(tmp_fd);
    return (md);

Error:
    if (md->writefd != -1)
	(void) Close (md->writefd);
    if (md->writefd != -1)
	(void) Close (md->readfd);
    if (md->file)
    {
	(void) Unlink (md->file);
	Free (md->file);
    }
    if (tmp_fd != -1)
	(void) Close(tmp_fd);
    
    Free(md);

    return(NULL);
}


#if	defined(__STDC__)
static int checklock ( void )
#else
static int checklock()
#endif
{
    int			fd;
    struct flock	lock;

    if ((fd = Open(Lp_Schedlock, O_RDONLY, 0666)) == -1)
	return (-1);

    /*
     * Now, we try to read-lock the lock file. This can only succeed if
     * the Spooler (lpsched) is down.
     */

    lock.l_type = F_RDLCK;
    lock.l_whence = 0;
    lock.l_start = 0;
    lock.l_len = 0;	/* till end of file */

    if (Fcntl(fd, F_SETLK, &lock) != -1 || errno != EAGAIN)
    {
	(void)Close (fd);
	return (-1);
    }

    /*
     * We can get here only when fcntl() == -1 && errno == EAGAIN,
     * i.e., spooler (lpsched) is running.
     */

    (void)Close (fd);

    return(0);
}
