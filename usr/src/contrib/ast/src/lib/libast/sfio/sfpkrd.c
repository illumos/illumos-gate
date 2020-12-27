/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2012 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                 Eclipse Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*          http://www.eclipse.org/org/documents/epl-v10.html           *
*         (with md5 checksum b35adb5213ca9657e911e9befb180842)         *
*                                                                      *
*              Information and Software Systems Research               *
*                            AT&T Research                             *
*                           Florham Park NJ                            *
*                                                                      *
*                 Glenn Fowler <gsf@research.att.com>                  *
*                  David Korn <dgk@research.att.com>                   *
*                   Phong Vo <kpv@research.att.com>                    *
*                                                                      *
***********************************************************************/
#include	"sfhdr.h"
#if !_PACKAGE_ast
#ifndef FIONREAD
#if _sys_ioctl
#include	<sys/ioctl.h>
#endif
#endif
#endif

/*	Read/Peek a record from an unseekable device
**
**	Written by Kiem-Phong Vo.
*/

#define STREAM_PEEK	001
#define SOCKET_PEEK	002

#if __STD_C
ssize_t sfpkrd(int fd, Void_t* argbuf, size_t n, int rc, long tm, int action)
#else
ssize_t sfpkrd(fd, argbuf, n, rc, tm, action)
int	fd;	/* file descriptor */
Void_t*	argbuf;	/* buffer to read data */
size_t	n;	/* buffer size */
int	rc;	/* record character */
long	tm;	/* time-out */
int	action;	/* >0: peeking, if rc>=0, get action records,
		   <0: no peeking, if rc>=0, get -action records,
		   =0: no peeking, if rc>=0, must get a single record
		*/
#endif
{
	reg ssize_t	r;
	reg int		ntry, t;
	reg char	*buf = (char*)argbuf, *endbuf;

	if(rc < 0 && tm < 0 && action <= 0)
		return sysreadf(fd,buf,n);

	t = (action > 0 || rc >= 0) ? (STREAM_PEEK|SOCKET_PEEK) : 0;
#if !_stream_peek
	t &= ~STREAM_PEEK;
#endif
#if !_socket_peek
	t &= ~SOCKET_PEEK;
#endif

	for(ntry = 0; ntry < 2; ++ntry)
	{
		r = -1;
#if _stream_peek
		if((t&STREAM_PEEK) && (ntry == 1 || tm < 0) )
		{
#ifdef __sun
			/*
			 * I_PEEK on stdin can hang rsh+ksh on solaris
			 * this kludge will have to do until sun^H^H^Horacle fixes I_PEEK/rsh
			 */
			static int	stream_peek;
			if (stream_peek == 0) /* this will be done just once */
			{	char	*e;
				stream_peek = (
					getenv("LOGNAME") == 0 &&
					getenv("MAIL") == 0 &&
					((e = getenv("LANG")) == 0 || strcmp(e, "C") == 0) &&
					((e = getenv("PATH")) == 0 || strncmp(e, "/usr/bin:", 9) == 0)
					) ? -1 : 1;
			}
			if(stream_peek < 0)
				t &= ~STREAM_PEEK;
			else
#endif
			{	struct strpeek	pbuf;
				pbuf.flags = 0;
				pbuf.ctlbuf.maxlen = -1;
				pbuf.ctlbuf.len = 0;
				pbuf.ctlbuf.buf = NIL(char*);
				pbuf.databuf.maxlen = n;
				pbuf.databuf.buf = buf;
				pbuf.databuf.len = 0;

				if((r = ioctl(fd,I_PEEK,&pbuf)) < 0)
				{	if(errno == EINTR)
						return -1;
					t &= ~STREAM_PEEK;
				}
				else
				{	t &= ~SOCKET_PEEK;
					if(r > 0 && (r = pbuf.databuf.len) <= 0)
					{	if(action <= 0)	/* read past eof */
							r = sysreadf(fd,buf,1);
						return r;
					}
					if(r == 0)
						r = -1;
					else if(r > 0)
						break;
				}
			}
		}
#endif /* stream_peek */

		if(ntry == 1)
			break;

		/* poll or select to see if data is present.  */
		while(tm >= 0 || action > 0 ||
			/* block until there is data before peeking again */
			((t&STREAM_PEEK) && rc >= 0) ||
			/* let select be interrupted instead of recv which autoresumes */
			(t&SOCKET_PEEK) )
		{	r = -2;
#if _lib_poll
			if(r == -2)
			{
				struct pollfd	po;
				po.fd = fd;
				po.events = POLLIN;
				po.revents = 0;

				if((r = SFPOLL(&po,1,tm)) < 0)
				{	if(errno == EINTR)
						return -1;
					else if(errno == EAGAIN)
					{	errno = 0;
						continue;
					}
					else	r = -2;
				}
				else	r = (po.revents&POLLIN) ? 1 : -1;
			}
#endif /*_lib_poll*/
#if _lib_select
			if(r == -2)
			{
#if _hpux_threads && vt_threaded
#define fd_set	int
#endif
				fd_set		rd;
				struct timeval	tmb, *tmp;
				FD_ZERO(&rd);
				FD_SET(fd,&rd);
				if(tm < 0)
					tmp = NIL(struct timeval*);
				else
				{	tmp = &tmb;
					tmb.tv_sec = tm/SECOND;
					tmb.tv_usec = (tm%SECOND)*SECOND;
				}
				r = select(fd+1,&rd,NIL(fd_set*),NIL(fd_set*),tmp);
				if(r < 0)
				{	if(errno == EINTR)
						return -1;
					else if(errno == EAGAIN)
					{	errno = 0;
						continue;
					}
					else	r = -2;
				}
				else	r = FD_ISSET(fd,&rd) ? 1 : -1;
			}
#endif /*_lib_select*/
			if(r == -2)
			{
#if !_lib_poll && !_lib_select	/* both poll and select can't be used */
#ifdef FIONREAD			/* quick and dirty check for availability */
				long	nsec = tm < 0 ? 0 : (tm+999)/1000;
				while(nsec > 0 && r < 0)
				{	long	avail = -1;
					if((r = ioctl(fd,FIONREAD,&avail)) < 0)
					{	if(errno == EINTR)
							return -1;
						else if(errno == EAGAIN)
						{	errno = 0;
							continue;
						}
						else	/* ioctl failed completely */
						{	r = -2;
							break;
						}
					}
					else	r = avail <= 0 ? -1 : (ssize_t)avail;

					if(r < 0 && nsec-- > 0)
						sleep(1);
				}
#endif
#endif
			}

			if(r > 0)		/* there is data now */
			{	if(action <= 0 && rc < 0)
					return sysreadf(fd,buf,n);
				else	r = -1;
			}
			else if(tm >= 0)	/* timeout exceeded */
				return -1;
			else	r = -1;
			break;
		}

#if _socket_peek
		if(t&SOCKET_PEEK)
		{
#if __MACH__ && __APPLE__ /* check 10.4 recv(MSG_PEEK) bug that consumes pipe data */
			static int	recv_peek_pipe;
			if (recv_peek_pipe == 0) /* this will be done just once */
			{	int	fds[2], r;
				char	tst[2];

				tst[0] = 'a'; tst[1] = 'z';

				/* open a pipe and write to it */
				recv_peek_pipe = 1;
				if(recv_peek_pipe == 1 && pipe(fds) < 0)
					recv_peek_pipe = -1;
				if(recv_peek_pipe == 1 && write(fds[1], tst, 2) != 2)
					recv_peek_pipe = -1;

				/* try recv() to see if it gets anything */
				tst[0] = tst[1] = 0;
				if(recv_peek_pipe == 1 && (r = recv(fds[0], tst, 1, MSG_PEEK)) != 1)
					recv_peek_pipe = -1;
				if(recv_peek_pipe == 1 && tst[0] != 'a')
					recv_peek_pipe = -1;

				/* make sure that recv() did not consume data */
				tst[0] = tst[1] = 0;
				if(recv_peek_pipe == 1 && (r = recv(fds[0], tst, 2, MSG_PEEK)) != 2)
					recv_peek_pipe = -1;
				if(recv_peek_pipe == 1 && (tst[0] != 'a' || tst[1] != 'z') )
					recv_peek_pipe = -1;

				close(fds[0]);
				close(fds[1]);
			}

			if(recv_peek_pipe < 0)
			{	struct stat st; /* recv should work on sockets */
				if(fstat(fd, &st) < 0 || !S_ISSOCK(st.st_mode) )
				{	r = -1;
					t &= ~SOCKET_PEEK;
				}
			}
#endif
			while((t&SOCKET_PEEK) && (r = recv(fd,(char*)buf,n,MSG_PEEK)) < 0)
			{	if(errno == EINTR)
					return -1;
				else if(errno == EAGAIN)
					errno = 0;
				else	t &= ~SOCKET_PEEK;
			}
			if(r >= 0)
			{	t &= ~STREAM_PEEK;
				if(r > 0)
					break;
				else	/* read past eof */
				{	if(action <= 0)
						r = sysreadf(fd,buf,1);
					return r;
				}
			}
		}
#endif
	}

	if(r < 0)
	{	if(tm >= 0 || action > 0)
			return -1;
		else /* get here means: tm < 0 && action <= 0 && rc >= 0 */
		{	/* number of records read at a time */
			if((action = action ? -action : 1) > (int)n)
				action = n;
			r = 0;
			while((t = sysreadf(fd,buf,action)) > 0)
			{	r += t;
				for(endbuf = buf+t; buf < endbuf;)
					if(*buf++ == rc)
						action -= 1;
				if(action == 0 || (int)(n-r) < action)
					break;
			}
			return r == 0 ? t : r;
		}
	}

	/* successful peek, find the record end */
	if(rc >= 0)
	{	reg char*	sp;	

		t = action == 0 ? 1 : action < 0 ? -action : action;
		for(endbuf = (sp = buf)+r; sp < endbuf; )
			if(*sp++ == rc)
				if((t -= 1) == 0)
					break;
		r = sp - buf;
	}

	/* advance */
	if(action <= 0)
		r = sysreadf(fd,buf,r);

	return r;
}
