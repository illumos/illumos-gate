/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1982-2012 AT&T Intellectual Property          *
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
*                  David Korn <dgk@research.att.com>                   *
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * mkservice varname pathname
 * eloop [-t timeout]
 * Written by David Korn
 * AT&T Labs
 */

static const char mkservice_usage[] =
"[-?\n@(#)$Id: mkservice (AT&T Research) 2001-06-13 $\n]"
USAGE_LICENSE
"[+NAME? mkservice - create a shell server ]"
"[+DESCRIPTION?\bmkservice\b creates a tcp or udp server that is "
	"implemented by shell functions.]"
"[+?The \aservice_path\a must be of the form \b/dev/tcp/localhost/\b\aportno\a "
	"or \b/dev/udp/localhost/\b\aportno\a depending on whether the "
	"\btcp\b or \budp\b protocol is used.  \aportno\a is the port "
	"number that the service will use.]"
"[+?The shell variable \avarname\a is associated with the service.  This "
	"variable can have subvariables that keeps the state of all "
	"active connections.  The functions \avarname\a\b.accept\b, "
	"\avarname\a\b.action\b and \avarname\a\b.close\b implement the "
	"service as follows:]{"
	"[+accept?This function is invoked when a client tries to connect "
		"to the service.  It is called with an argument which "
		"is the file descriptor number associated with the "
		"accepted connection.  If the function returns a non-zero "
		"value, this connection will be closed.]"
	"[+action?This function is invoked when there is data waiting "
		"to be read from one of the active connections.  It is "
		"called with the file descriptor number that has data "
		"to be read.  If the function returns a non-zero "
		"value, this connection will be closed.]" 
	"[+close?This function is invoked when the connection is closed.]"
	"}"
"[+?If \avarname\a is unset, then all active connection, and the service "
	"itself will be closed.]"
""
"\n"
"\nvarname service_path\n"
"\n"
"[+EXIT STATUS?]{"
        "[+0?Success.]"
        "[+>0?An error occurred.]"
"}"
"[+SEE ALSO?\beloop\b(1)]"
;


static const char eloop_usage[] =
"[-?\n@(#)$Id: eloop (AT&T Research) 2001-06-13 $\n]"
USAGE_LICENSE
"[+NAME? eloop - process event loop]"
"[+DESCRIPTION?\beloop\b causes the shell to block waiting for events "
	"to process.  By default, \beloop\b does not return.]"
"[t]#[timeout?\atimeout\a is the number of milliseconds to wait "
	"without receiving any events to process.]"
"\n"
"\n\n"
"\n"
"[+EXIT STATUS?If no timeout is specified, \beloop\b will not return "
	"unless interrupted.  Otherwise]{"
        "[+0?The specified timeout interval occurred.]"
        "[+>0?An error occurred.]"
"}"
"[+SEE ALSO?\bmkservice\b(1)]"
;


#include	"defs.h"

#include	<cmd.h>
#include	<error.h>
#include	<nval.h>
#include	<sys/socket.h>
#include 	<netinet/in.h>

#define ACCEPT	0
#define ACTION	1
#define CLOSE	2

#ifndef O_SERVICE
#   define O_SERVICE	O_NOCTTY
#endif

static const char*	disctab[] =
{
	"accept",
	"action",
	"close",
	0
};

typedef struct Service_s Service_t;

struct Service_s
{
	Namfun_t	fun;
	short		fd;
	int		refcount;
	int		(*acceptf)(Service_t*,int);
	int		(*actionf)(Service_t*,int,int);
	int		(*errorf)(Service_t*,int,const char*, ...);
	void		*context;
	Namval_t*	node;
	Namval_t*	disc[elementsof(disctab)-1];
};

static short		*file_list;
static Sfio_t		**poll_list;
static Service_t	**service_list;
static int		npoll;
static int		nready;
static int		ready;
static int		(*covered_fdnotify)(int, int);

static int fdclose(Service_t *sp, register int fd)
{
	register int i;
	service_list[fd] = 0;
	if(sp->fd==fd)
		sp->fd = -1;
	for(i=0; i < npoll; i++)
	{
		if(file_list[i]==fd)
		{
			file_list[i] = file_list[npoll--];
			if(sp->actionf)
				(*sp->actionf)(sp, fd, 1);
			return(1);
		}
	}
	return(0);
}

static int fdnotify(int fd1, int fd2)
{
	Service_t *sp;
	if (covered_fdnotify)
		(*covered_fdnotify)(fd1, fd2);
	if(fd2!=SH_FDCLOSE)
	{
		register int i;
		service_list[fd2] = service_list[fd1];
		service_list[fd1] = 0;
		for(i=0; i < npoll; i++)
		{
			if(file_list[i]==fd1)
			{
				file_list[i] = fd2;
				return(0);
			}
		}
	}
	else if(sp = service_list[fd1])
	{
		fdclose(sp,fd1);
		if(--sp->refcount==0)
			nv_unset(sp->node);
	}
	return(0);
}

static void process_stream(Sfio_t* iop)
{
	int r=0, fd = sffileno(iop);
	Service_t * sp = service_list[fd];
	if(fd==sp->fd)	/* connection socket */
	{
		struct sockaddr addr;
		socklen_t addrlen = sizeof(addr);
		fd = accept(fd, &addr, &addrlen);
		service_list[fd] = sp;
		sp->refcount++;
		file_list[npoll++] = fd;
		if(fd>=0)
		{
			if(sp->acceptf)
				r = (*sp->acceptf)(sp,fd);
		}
	}
	else if(sp->actionf)
	{
		service_list[fd] = 0;
		r = (*sp->actionf)(sp, fd, 0);
		service_list[fd] = sp;
		if(r<0)
			close(fd);
	}
}
				
static int waitnotify(int fd, long timeout, int rw)
{
	Sfio_t *special=0, **pstream;
	register int	i;

	if (fd >= 0)
		special = sh_fd2sfio(fd);
	while(1)
	{
		pstream = poll_list;
		while(ready < nready)
			process_stream(pstream[ready++]);
		if(special)
			*pstream++ = special;
		for(i=0; i < npoll; i++)
		{
			if(service_list[file_list[i]])
				*pstream++ = sh_fd2sfio(file_list[i]);
		}
#if 1
		for(i=0; i < pstream-poll_list; i++)
			sfset(poll_list[i],SF_WRITE,0);
#endif
		nready = ready = 0;
		errno = 0;
#ifdef DEBUG
		sfprintf(sfstderr,"before poll npoll=%d",pstream-poll_list);
		for(i=0; i < pstream-poll_list; i++)
			sfprintf(sfstderr," %d",sffileno(poll_list[i]));
		sfputc(sfstderr,'\n');
#endif
		nready  = sfpoll(poll_list,pstream-poll_list,timeout);
#ifdef DEBUG
		sfprintf(sfstderr,"after poll nready=%d",nready);
		for(i=0; i < nready; i++)
			sfprintf(sfstderr," %d",sffileno(poll_list[i]));
		sfputc(sfstderr,'\n');
#endif
#if 1
		for(i=0; i < pstream-poll_list; i++)
			sfset(poll_list[i],SF_WRITE,1);
#endif
		if(nready<=0)
			return(errno? -1: 0);
		if(special && poll_list[0]==special)
		{
			ready = 1;
			return(fd);
		}
	}
}

static int service_init(void)
{
	file_list =  newof(NULL,short,n,0);
	poll_list =  newof(NULL,Sfio_t*,n,0);
	service_list =  newof(NULL,Service_t*,n,0);
	covered_fdnotify = sh_fdnotify(fdnotify);
	sh_waitnotify(waitnotify);
	return(1);
}

void service_add(Service_t *sp)
{
	static int init;
	if (!init)
		init = service_init();
	service_list[sp->fd] = sp;
	file_list[npoll++] = sp->fd;
}

static int Accept(register Service_t *sp, int accept_fd)
{
	register Namval_t*	nq = sp->disc[ACCEPT];
	int			fd;

	fd = fcntl(accept_fd, F_DUPFD, 10);
	if (fd >= 0)
	{
		close(accept_fd);
		if (nq)
		{
			char*	av[3];
			char	buff[20];

			av[1] = buff;
			av[2] = 0;
			sfsprintf(buff, sizeof(buff), "%d", fd);
			if (sh_fun(nq, sp->node, av))
			{
				close(fd);
				return -1;
			}
		}
	}
	sfsync(NiL);
	return fd;
}

static int Action(Service_t *sp, int fd, int close)
{
	register Namval_t*	nq;
	int			r=0;

	if(close)
		nq = sp->disc[CLOSE];
	else
		nq = sp->disc[ACTION];
	if (nq)
	{
		char*	av[3];
		char	buff[20];

		av[1] = buff;
		av[2] = 0;
		sfsprintf(buff, sizeof(buff), "%d", fd);
		r=sh_fun(nq, sp->node, av);
	}
	sfsync(NiL);
	return r > 0 ? -1 : 1;
}

static int Error(Service_t *sp, int level, const char* arg, ...)
{
	va_list			ap;

	va_start(ap, arg);
	if(sp->node)
		nv_unset(sp->node);
	free((void*)sp);
        errorv(NiL, ERROR_exit(1), ap);
        va_end(ap);
	return 0;
}

static char* setdisc(Namval_t* np, const char* event, Namval_t* action, Namfun_t* fp)
{
	register Service_t*	sp = (Service_t*)fp;
	register const char*	cp;
	register int		i;
	register int		n = strlen(event) - 1;
	register Namval_t*	nq;

	for (i = 0; cp = disctab[i]; i++)
	{
		if (memcmp(event, cp, n))
			continue;
		if (action == np)
			action = sp->disc[i];
		else
		{
			if (nq = sp->disc[i])
				free((void*)nq);
			if (action)
				sp->disc[i] = action;
			else
				sp->disc[i] = 0;
		}
		return action ? (char*)action : "";
	}
	/* try the next level */
	return nv_setdisc(np, event, action, fp);
}

static void putval(Namval_t* np, const char* val, int flag, Namfun_t* fp)
{
	register Service_t* sp = (Service_t*)fp;
	if (!val)
		fp = nv_stack(np, NiL);
	nv_putv(np, val, flag, fp);
	if (!val)
	{
		register int i;
		for(i=0; i< sh.lim.open_max; i++)
		{
			if(service_list[i]==sp)
			{
				close(i);
				if(--sp->refcount<=0)
					break;
			}
		}
		free((void*)fp);
		return;
	}
}

static const Namdisc_t servdisc =
{
	sizeof(Service_t),
	putval,
	0,
	0,
	setdisc
};

int	b_mkservice(int argc, char** argv, Shbltin_t *context)
{
	register char*		var;
	register char*		path;
	register Namval_t*	np;
	register Service_t*	sp;
	register int		fd;

	NOT_USED(argc);
	NOT_USED(context);
	for (;;)
	{
		switch (optget(argv, mkservice_usage))
		{
		case 0:
			break;
		case ':':
			error(2, opt_info.arg);
			continue;
		case '?':
			error(ERROR_usage(2), opt_info.arg);
			continue;
		}
		break;
	}
	argv += opt_info.index;
	if (error_info.errors || !(var = *argv++) || !(path = *argv++) || *argv)
		error(ERROR_usage(2), optusage(NiL));
	if (!(sp = newof(0, Service_t, 1, 0)))
		error(ERROR_exit(1), "out of space");
	sp->acceptf = Accept;
	sp->actionf = Action;
	sp->errorf = Error;
	sp->refcount = 1;
	sp->context = context;
	sp->node = 0;
	sp->fun.disc = &servdisc;
	if((fd = sh_open(path, O_SERVICE|O_RDWR))<=0)
	{
		free((void*)sp);
		error(ERROR_exit(1), "%s: cannot start service", path);
	}
	if((sp->fd = fcntl(fd, F_DUPFD, 10))>=10)
		close(fd);
	else
		sp->fd = fd;
	np = nv_open(var,sh.var_tree,NV_ARRAY|NV_VARNAME|NV_NOASSIGN);
	sp->node = np;
	nv_putval(np, path, 0); 
	nv_stack(np, (Namfun_t*)sp);
	service_add(sp);
	return(0);
}

int	b_eloop(int argc, char** argv, Shbltin_t *context)
{
	register long	timeout = -1;
	NOT_USED(argc);
	NOT_USED(context);
	for (;;)
	{
		switch (optget(argv, eloop_usage))
		{
		case 0:
			break;
		case 't':
			timeout = opt_info.num;
			continue;
		case ':':
			error(2, opt_info.arg);
			continue;
		case '?':
			error(ERROR_usage(2), opt_info.arg);
			continue;
		}
		break;
	}
	argv += opt_info.index;
	if (error_info.errors  || *argv)
		error(ERROR_usage(2), optusage(NiL));
	while(1)
	{
		if(waitnotify(-1, timeout, 0)==0)
			break;
		sfprintf(sfstderr,"interrupted\n");
	}
	return(errno != 0);
}
