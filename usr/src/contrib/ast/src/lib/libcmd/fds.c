/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1992-2012 AT&T Intellectual Property          *
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
*                                                                      *
***********************************************************************/
#pragma prototyped

static const char usage[] =
"[-?\n@(#)$Id: fds (AT&T Research) 2009-09-09 $\n]"
USAGE_LICENSE
"[+NAME?fds - list open file descriptor status]"
"[+DESCRIPTION?\bfds\b lists the status for each open file descriptor. "
    "When invoked as a shell builtin it accesses the file descriptors of the "
    "calling shell, otherwise it lists the file descriptors passed across "
    "\bexec\b(2).]"
"[l:long?List file descriptor details.]"
"[u:unit?Write output to \afd\a.]#[fd]"
"[+SEE ALSO?\blogname\b(1), \bwho\b(1), \bgetgroups\b(2), \bgetsockname\b(2), \bgetsockopts\b(2)]"
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

#undef	getconf
#define getconf(x)	strtol(astconf(x,NiL,NiL),NiL,0)

#ifdef S_IFSOCK

typedef struct NV_s
{
	const char*	name;
	int		value;
} NV_t;

static const NV_t	family[] =
{
#ifdef AF_LOCAL
	"pipe",		AF_LOCAL,
#endif
#ifdef AF_UNIX
	"pipe",		AF_UNIX,
#endif
#ifdef AF_FILE
	"FILE",		AF_FILE,
#endif
#ifdef AF_INET
	"INET",		AF_INET,
#endif
#ifdef AF_AX25
	"AX25",		AF_AX25,
#endif
#ifdef AF_IPX
	"IPX",		AF_IPX,
#endif
#ifdef AF_APPLETALK
	"APPLETALK",	AF_APPLETALK,
#endif
#ifdef AF_NETROM
	"NETROM",	AF_NETROM,
#endif
#ifdef AF_BRIDGE
	"BRIDGE",	AF_BRIDGE,
#endif
#ifdef AF_ATMPVC
	"ATMPVC",	AF_ATMPVC,
#endif
#ifdef AF_X25
	"X25",		AF_X25,
#endif
#ifdef AF_INET6
	"INET6",	AF_INET6,
#endif
#ifdef AF_ROSE
	"ROSE",		AF_ROSE,
#endif
#ifdef AF_DECnet
	"DECnet",	AF_DECnet,
#endif
#ifdef AF_NETBEUI
	"NETBEUI",	AF_NETBEUI,
#endif
#ifdef AF_SECURITY
	"SECURITY",	AF_SECURITY,
#endif
#ifdef AF_KEY
	"KEY",		AF_KEY,
#endif
#ifdef AF_NETLINK
	"NETLINK",	AF_NETLINK,
#endif
#ifdef AF_ROUTE
	"ROUTE",	AF_ROUTE,
#endif
#ifdef AF_PACKET
	"PACKET",	AF_PACKET,
#endif
#ifdef AF_ASH
	"ASH",		AF_ASH,
#endif
#ifdef AF_ECONET
	"ECONET",	AF_ECONET,
#endif
#ifdef AF_ATMSVC
	"ATMSVC",	AF_ATMSVC,
#endif
#ifdef AF_SNA
	"SNA",		AF_SNA,
#endif
#ifdef AF_IRDA
	"IRDA",		AF_IRDA,
#endif
#ifdef AF_PPPOX
	"PPPOX",	AF_PPPOX,
#endif
#ifdef AF_WANPIPE
	"WANPIPE",	AF_WANPIPE,
#endif
#ifdef AF_BLUETOOTH
	"BLUETOOTH",	AF_BLUETOOTH,
#endif
	0
};

#endif

int
b_fds(int argc, char** argv, Shbltin_t* context)
{
	register char*		s;
	register int		i;
	register char*		m;
	register char*		x;
	int			flags;
	int			details;
	int			open_max;
	int			unit;
	Sfio_t*			sp;
	struct stat		st;
#ifdef S_IFSOCK
	struct sockaddr_in	addr;
	char*			a;
	unsigned char*		b;
	unsigned char*		e;
	socklen_t		addrlen;
	socklen_t		len;
	int			type;
	int			port;
	int			prot;
	char			num[64];
	char			fam[64];
#ifdef INET6_ADDRSTRLEN
	char			nam[256];
#endif
#endif

	cmdinit(argc, argv, context, ERROR_CATALOG, 0);
	details = 0;
	unit = 1;
	for (;;)
	{
		switch (optget(argv, usage))
		{
		case 'l':
			details = opt_info.num;
			continue;
		case 'u':
			unit = opt_info.num;
			continue;
		case '?':
			error(ERROR_USAGE|4, "%s", opt_info.arg);
			break;
		case ':':
			error(2, "%s", opt_info.arg);
			break;
		}
		break;
	}
	argv += opt_info.index;
	if (error_info.errors || *argv)
		error(ERROR_USAGE|4, "%s", optusage(NiL));
	if ((open_max = getconf("OPEN_MAX")) <= 0)
		open_max = OPEN_MAX;
	if (unit == 1)
		sp = sfstdout;
	else if (fstat(unit, &st) || !(sp = sfnew(NiL, NiL, SF_UNBOUND, unit, SF_WRITE)))
		error(ERROR_SYSTEM|3, "%d: cannot write to file descriptor");
	for (i = 0; i <= open_max; i++)
	{
		if (fstat(i, &st))
		{
			/* not open */
			continue;
		}
		if (!details)
		{
			sfprintf(sp, "%d\n", i);
			continue;
		}
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
		{
			sfprintf(sp, "%02d %s%s %s %s\n", i, m, x, fmtmode(st.st_mode, 0), s);
			continue;
		}
#ifdef S_IFSOCK
		addrlen = sizeof(addr);
		memset(&addr, 0, addrlen);
		if (!getsockname(i, (struct sockaddr*)&addr, (void*)&addrlen))
		{
			type = 0;
			prot = 0;
#ifdef SO_TYPE
			len = sizeof(type);
			if (getsockopt(i, SOL_SOCKET, SO_TYPE, (void*)&type, (void*)&len))
				type = -1;
#endif
#ifdef SO_PROTOTYPE
			len = sizeof(prot);
			if (getsockopt(i, SOL_SOCKET, SO_PROTOTYPE, (void*)&prot, (void*)&len))
				prot = -1;
#endif
			if (!st.st_mode)
				st.st_mode = S_IFSOCK|S_IRUSR|S_IWUSR;
			s = 0;
			switch (type)
			{
			case SOCK_DGRAM:
				switch (addr.sin_family)
				{
				case AF_INET:
#ifdef AF_INET6
				case AF_INET6:
#endif
					s = "udp";
					break;
				}
				break;
			case SOCK_STREAM:
				switch (addr.sin_family)
				{
				case AF_INET:
#ifdef AF_INET6
				case AF_INET6:
#endif
#ifdef IPPROTO_SCTP
					if (prot == IPPROTO_SCTP)
						s = "sctp";
					else
#endif
						s = "tcp";
					break;
				}
				break;
#ifdef SOCK_RAW
			case SOCK_RAW:
				s = "raw";
				break;
#endif
#ifdef SOCK_RDM
			case SOCK_RDM:
				s = "rdm";
				break;
#endif
#ifdef SOCK_SEQPACKET
			case SOCK_SEQPACKET:
				s = "seqpacket";
				break;
#endif
			}
			if (!s)
			{
				for (type = 0; family[type].name && family[type].value != addr.sin_family; type++);
				if (!(s = (char*)family[type].name))
					sfsprintf(s = num, sizeof(num), "family.%d", addr.sin_family);
			}
			port = 0;
#ifdef INET6_ADDRSTRLEN
			if (a = (char*)inet_ntop(addr.sin_family, &addr.sin_addr, nam, sizeof(nam)))
				port = ntohs(addr.sin_port);
			else
#endif
			if (addr.sin_family == AF_INET)
			{
				a = inet_ntoa(addr.sin_addr);
				port = ntohs(addr.sin_port);
			}
			else
			{
				a = fam;
				e = (b = (unsigned char*)&addr) + addrlen;
				while (b < e && a < &fam[sizeof(fam)-1])
					a += sfsprintf(a, &fam[sizeof(fam)] - a - 1, ".%d", *b++);
				a = a == fam ? "0" : fam + 1;
			}
			if (port)
				sfprintf(sp, "%02d %s%s %s /dev/%s/%s/%d\n", i, m, x, fmtmode(st.st_mode, 0), s, a, port);
			else
				sfprintf(sp, "%02d %s%s %s /dev/%s/%s\n", i, m, x, fmtmode(st.st_mode, 0), s, a);
			continue;
		}
#endif
		sfprintf(sp, "%02d %s%s %s /dev/inode/%u/%u\n", i, m, x, fmtmode(st.st_mode, 0), st.st_dev, st.st_ino);
	}
	if (sp != sfstdout)
	{
		sfsetfd(sp, -1);
		sfclose(sp);
	}
	return 0;
}
