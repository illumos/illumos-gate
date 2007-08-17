/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*           Copyright (c) 1992-2007 AT&T Knowledge Ventures            *
*                      and is licensed under the                       *
*                  Common Public License, Version 1.0                  *
*                      by AT&T Knowledge Ventures                      *
*                                                                      *
*                A copy of the License is available at                 *
*            http://www.opensource.org/licenses/cpl1.0.txt             *
*         (with md5 checksum 059e8cd6165cb4c31e351f2b69388fd9)         *
*                                                                      *
*              Information and Software Systems Research               *
*                            AT&T Research                             *
*                           Florham Park NJ                            *
*                                                                      *
*                 Glenn Fowler <gsf@research.att.com>                  *
*                  David Korn <dgk@research.att.com>                   *
*                                                                      *
***********************************************************************/
#pragma prototyped

static const char usage[] =
"[-?\n@(#)$Id: fds (AT&T Research) 2006-10-26 $\n]"
USAGE_LICENSE
"[+NAME?fds - list open file descriptor status]"
"[+DESCRIPTION?\bfds\b lists the status for each open file descriptor. "
    "When invoked as a shell builtin it accesses the file descriptors of the "
    "calling shell, otherwise it lists the file descriptors passed across "
    "\bexec\b(2).]"
"[l:long?List file descriptor details.]"
"[+SEE ALSO?\blogname\b(1), \bwho\b(1), \bgetgroups\b(2)]"
;

#include <cmd.h>
#include <ls.h>

#include "FEATURE/sockets"

#if defined(S_IFSOCK) && _sys_socket && _hdr_arpa_inet && _hdr_netinet_in && _lib_getsockname && _lib_getsockopt && _lib_inet_ntoa
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#undef	S_IFSOCK
#endif

#ifndef minor
#define minor(x)	(int)((x)&0xff)
#endif
#ifndef major
#define major(x)	(int)(((unsigned int)(x)>>8)&0xff)
#endif

int
b_fds(int argc, char** argv, void* context)
{
	register char*		s;
	register int		i;
	register char*		m;
	register char*		x;
	int			flags;
	int			details;
	struct stat		st;
#ifdef S_IFSOCK
	struct sockaddr_in	addr;
	socklen_t		len;
	int			type;
	int			prot;
	char			num[32];
#endif

	cmdinit(argc, argv, context, ERROR_CATALOG, 0);
	details = 0;
	for (;;)
	{
		switch (optget(argv, usage))
		{
		case 'l':
			details = opt_info.num;
			continue;
		case '?':
			error(ERROR_USAGE|4, "%s", opt_info.arg);
			continue;
		case ':':
			error(2, "%s", opt_info.arg);
			continue;
		}
		break;
	}
	argv += opt_info.index;
	if (error_info.errors || *argv)
		error(ERROR_USAGE|4, "%s", optusage(NiL));
	for (i = 0; i <= OPEN_MAX; i++)
		if (fstat(i, &st))
			/* not open */;
		else if (details)
		{
			if ((flags = fcntl(i, F_GETFL, (char*)0)) == -1)
				m = "--";
			else
				switch (flags & (O_RDONLY|O_WRONLY|O_RDWR))
				{
				case O_RDONLY:
					m = "r-";
					break;
				case O_WRONLY:
					m = "-w";
					break;
				case O_RDWR:
					m = "rw";
					break;
				default:
					m = "??";
					break;
				}
			x = (fcntl(i, F_GETFD, (char*)0) > 0) ? "x" : "-";
			if (isatty(i) && (s = ttyname(i)))
				sfprintf(sfstdout, "%02d %s%s %s %s\n", i, m, x, fmtmode(st.st_mode, 0), s);
#ifdef S_IFSOCK
			else if ((len = sizeof(addr))
				 && !getsockname(i, (struct sockaddr*)&addr, (void*)&len)
				 && len == sizeof(addr)
				 && addr.sin_family == AF_INET
#ifdef SO_TYPE
				 && (len = sizeof(type))
				 && !getsockopt(i, SOL_SOCKET, SO_TYPE, (void*)&type, (void*)&len)
				 && len == sizeof(type)
#else
				 && !(type = 0)
#endif
#ifdef SO_PROTOTYPE
				 && (len = sizeof(prot))
				 && (!getsockopt(i, SOL_SOCKET, SO_PROTOTYPE, (void*)&prot, (void*)&len) || !(prot = 0))
#else
				 && !(prot = 0)
#endif
				)
			{
				if (!st.st_mode)
					st.st_mode = S_IFSOCK|S_IRUSR|S_IWUSR;
				s = 0;
				switch (type)
				{
				case SOCK_DGRAM:
					s = "udp";
					break;
				case SOCK_STREAM:
					if (prot == 0)
						s = "tcp";
#ifdef IPPROTO_SCTP
					else if (prot == IPPROTO_SCTP)
						s = "sctp";
#endif
					break;
				}
				if (!s)
					sfprintf(sfstdout, s = num, "type.%d.prot.%d", type, prot);
				sfprintf(sfstdout, "%02d %s%s %s /dev/%s/%s/%d\n", i, m, x, fmtmode(st.st_mode, 0), s, inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
			}
#endif
			else
				sfprintf(sfstdout, "%02d %s%s %s /dev/inode/%u/%u\n", i, m, x, fmtmode(st.st_mode, 0), st.st_dev, st.st_ino);
		}
		else
			sfprintf(sfstdout, "%d\n", i);
	return 0;
}
