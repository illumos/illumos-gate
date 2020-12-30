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
#pragma prototyped
/*
 * syslog implementation
 */

#include <ast.h>

#if _lib_syslog

NoN(syslog)

#else

#define LOG_TABLES

#include "sysloglib.h"

#include <error.h>
#include <tm.h>

Syslog_state_t		log = { LOG_USER, -1, 0, ~0 };

static const Namval_t	attempt[] =
{
#if _UWIN
	"/var/log/syslog",		0,
#endif
	"/dev/log",			0,
	"var/log/syslog",		0,
	"lib/syslog/log",		0,
	"/dev/console",			LOG_CONS,
};

const Namval_t		log_facility[] =
{
	"default",	0,
	"user",		LOG_USER,
	"kernel",	LOG_KERN,
	"mail",		LOG_MAIL,
	"daemon",	LOG_DAEMON,
	"security",	LOG_AUTH,
	"syslog",	LOG_SYSLOG,
	"lpr",		LOG_LPR,
	"news",		LOG_NEWS,
	"uucp",		LOG_UUCP,
	"cron",		LOG_CRON,
	"audit",	LOG_AUDIT,
	"logalert",	LOG_LFMT,
#ifdef LOG_SYSTEM2
	"system2",	LOG_SYSTEM2,
#endif
#ifdef LOG_SYSTEM1
	"system1",	LOG_SYSTEM1,
#endif
#ifdef LOG_SYSTEM0
	"system0",	LOG_SYSTEM0,
#endif
	0,		0
};

const Namval_t		log_severity[] =
{
	"panic",	LOG_EMERG,
	"alert",	LOG_ALERT,
	"critical",	LOG_CRIT,
	"error",	LOG_ERR,
	"warning",	LOG_WARNING,
	"notice",	LOG_NOTICE,
	"info",		LOG_INFO,
	"debug",	LOG_DEBUG,
	0,		0
};

#if _UWIN

/*
 * open /dev/(fdp|tcp|udp)/HOST/SERVICE for read
 */

#include <ctype.h>
#include <ls.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#include <netinet/in.h>

#if !defined(htons) && !_lib_htons
#	define htons(x)	(x)
#endif
#if !defined(htonl) && !_lib_htonl
#	define htonl(x)	(x)
#endif

#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK		0x7f000001L
#endif

/*
 * convert s to sockaddr_in
 * -1 returned on error
 */

static int
str2inet(register char* s, char* prot, struct sockaddr_in* addr)
{
	register int	c;
	register int	v;
	register int	n = 0;
	unsigned long	a = 0;
	unsigned short	p = 0;

	if (!memcmp(s, "local/", 6))
	{
		a = INADDR_LOOPBACK;
		n = 4;
		s += 6;
	}
	else if (!isdigit(*s))
	{
		struct hostent*	hp;
		char*		e = strchr(s, '/');

		if (!(e = strchr(s, '/')))
			return -1;
		*e = 0;
		hp = gethostbyname(s);
		*e = '/';
		if (!hp || hp->h_addrtype != AF_INET || hp->h_length > sizeof(struct in_addr))
			return -1;
		a = (unsigned long)((struct in_addr*)hp->h_addr)->s_addr;
		n = 6;
		s = e + 1;
	}
	for (;;)
	{
		v = 0;
		while ((c = *s++) >= '0' && c <= '9')
			v = v * 10 + c - '0';
		if (++n <= 4)
			a = (a << 8) | (v & 0xff);
		else
		{
			if (n <= 5)
				a = htonl(a);
			if (c)
			{
				struct servent*	sp;

				if (!(sp = getservbyname(s - 1, prot)))
					return -1;
				p = sp->s_port;
			}
			else
				p = htons(v);
			break;
		}
		if (c != '.' && c != '/')
			return -1;
	}
	memset((char*)addr, 0, sizeof(*addr));
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = a;
	addr->sin_port = p;
	return 0;
}

/*
 * call this after open fails to see if path is a socket
 */

int
sockopen(const char* path)
{
	int			fd;
	struct sockaddr_in	addr;
	char			buf[PATH_MAX];

	if (pathgetlink(path, buf, sizeof(buf)) <= 0)
	{
		if (strlen(path) >= sizeof(buf))
			return -1;
		strcpy(buf, path);
	}
#if LOCAL
	{
		int			ul;
		struct sockaddr_un	ua;
		struct stat		st;

		if ((ul = strlen(buf)) < sizeof(ua.sun_path) && !stat(buf, &st) && S_ISSOCK(st.st_mode))
		{
			if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
				return -1;
			ua.sun_family = AF_UNIX;
			strcpy(ua.sun_path, buf);
			ul += sizeof(ua.sun_family) + 1;
			if (!connect(fd, (struct sockaddr*)&ua, ul))
				return fd;
			close(fd);
			return -1;
		}
	}
#endif
	if (!strmatch(buf, "/dev/(tcp|udp)/*/*"))
		return -1;
	buf[8] = 0;
	if (str2inet(buf + 9, buf + 5, &addr))
		return -1;
	if ((fd = socket(AF_INET, buf[5] == 't' ? SOCK_STREAM : SOCK_DGRAM, 0)) < 0)
		return -1;
	if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)))
	{
		close(fd);
		return -1;
	}
	return fd;
}

#else

int
sockopen(const char* path)
{
	return -1;
}

#endif

void
sendlog(const char* msg)
{
	register char*		s;
	register Namval_t*	p;
	register int		n;

	n = msg ? strlen(msg) : 0;
	for (;;)
	{
		if (log.fd < 0)
		{
			char	buf[PATH_MAX];

			if (log.attempt >= elementsof(attempt))
				break;
			p = (Namval_t*)&attempt[log.attempt++];
			if (p->value && !(p->value & log.flags))
				continue;
			if (*(s = p->name) != '/' && !(s = pathpath(buf, s, "", PATH_REGULAR|PATH_READ, sizeof(buf))))
				continue;
			if ((log.fd = open(s, O_WRONLY|O_APPEND|O_NOCTTY|O_cloexec)) < 0 && (log.fd = sockopen(s)) < 0)
				continue;
#if !O_cloexec
			fcntl(log.fd, F_SETFD, FD_CLOEXEC);
#endif
		}
		if (!n || write(log.fd, msg, n) > 0)
			break;
		close(log.fd);
		log.fd = -1;
	}
	if (n && (log.flags & LOG_PERROR))
		write(2, msg, n);
}

static int
extend(Sfio_t* sp, void* vp, Sffmt_t* dp)
{
	if (dp->fmt == 'm')
	{
		dp->flags |= SFFMT_VALUE;
		dp->fmt = 's';
		dp->size = -1;
		*((char**)vp) = fmterror(errno);
	}
	return 0;
}

void
vsyslog(int priority, const char* format, va_list ap)
{
	register int	c;
	register char*	s;
	Sfio_t*		sp;
	Sffmt_t		fmt;
	char		buf[16];

	if (!LOG_FACILITY(priority))
		priority |= log.facility;
	if (!(priority & log.mask))
		return;
	if (sp = sfstropen())
	{
		sfputr(sp, fmttime("%b %d %H:%M:%S", time(NiL)), -1);
		if (log.flags & LOG_LEVEL)
		{
			if ((c = LOG_SEVERITY(priority)) < elementsof(log_severity))
				s = (char*)log_severity[c].name;
			else
				sfsprintf(s = buf, sizeof(buf), "debug%d", c);
			sfprintf(sp, " %-8s ", s);
			if ((c = LOG_FACILITY(priority)) < elementsof(log_facility))
				s = (char*)log_facility[c].name;
			else
				sfsprintf(s = buf, sizeof(buf), "local%d", c);
			sfprintf(sp, " %-8s ", s);
		}
#if _lib_gethostname
		if (!*log.host && gethostname(log.host, sizeof(log.host)-1))
			strcpy(log.host, "localhost");
		sfprintf(sp, " %s", log.host);
#endif
		if (*log.ident)
			sfprintf(sp, " %s", log.ident);
		if (log.flags & LOG_PID)
		{
			if (!*log.ident)
				sfprintf(sp, " ");
			sfprintf(sp, "[%d]", getpid());
		}
		if (format)
		{
			sfprintf(sp, ": ");
			memset(&fmt, 0, sizeof(fmt));
			fmt.version = SFIO_VERSION;
			fmt.form = (char*)format;
			fmt.extf = extend;
			va_copy(fmt.args, ap);
			sfprintf(sp, "%!", &fmt);
		}
		if ((s = sfstrseek(sp, 0, SEEK_CUR)) && *(s - 1) != '\n')
			sfputc(sp, '\n');
		if (s = sfstruse(sp))
			sendlog(s);
		sfstrclose(sp);
	}
}

void
syslog(int priority, const char* format, ...)
{
	va_list		ap;

	va_start(ap, format);
	vsyslog(priority, format, ap);
	va_end(ap);
}

#endif
