/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1982-2010 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                  Common Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*            http://www.opensource.org/licenses/cpl1.0.txt             *
*         (with md5 checksum 059e8cd6165cb4c31e351f2b69388fd9)         *
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
 * Input/output file processing
 *
 *   David Korn
 *   AT&T Labs
 *
 */

#include	"defs.h"
#include	<fcin.h>
#include	<ls.h>
#include	<stdarg.h>
#include	<regex.h>
#include	"variables.h"
#include	"path.h"
#include	"io.h"
#include	"jobs.h"
#include	"shnodes.h"
#include	"history.h"
#include	"edit.h"
#include	"timeout.h"
#include	"FEATURE/externs"
#include	"FEATURE/dynamic"
#include	"FEATURE/poll"

#ifdef	FNDELAY
#   ifdef EAGAIN
#	if EAGAIN!=EWOULDBLOCK
#	    undef EAGAIN
#	    define EAGAIN       EWOULDBLOCK
#	endif
#   else
#	define EAGAIN   EWOULDBLOCK
#   endif /* EAGAIN */
#   ifndef O_NONBLOCK
#	define O_NONBLOCK	FNDELAY
#   endif /* !O_NONBLOCK */
#endif	/* FNDELAY */

#ifndef O_SERVICE
#   define O_SERVICE	O_NOCTTY
#endif

#define RW_ALL	(S_IRUSR|S_IRGRP|S_IROTH|S_IWUSR|S_IWGRP|S_IWOTH)

static void	*timeout;
static int	(*fdnotify)(int,int);

#if defined(_lib_socket) && defined(_sys_socket) && defined(_hdr_netinet_in)
#   include <sys/socket.h>
#   include <netdb.h>
#   include <netinet/in.h>
#   if !defined(htons) && !_lib_htons
#      define htons(x)	(x)
#   endif
#   if !defined(htonl) && !_lib_htonl
#      define htonl(x)	(x)
#   endif
#   if _pipe_socketpair
#      ifndef SHUT_RD
#         define SHUT_RD         0
#      endif
#      ifndef SHUT_WR
#         define SHUT_WR         1
#      endif
#      if _socketpair_shutdown_mode
#         define pipe(v) ((socketpair(AF_UNIX,SOCK_STREAM,0,v)<0||shutdown((v)[1],SHUT_RD)<0||fchmod((v)[1],S_IWUSR)<0||shutdown((v)[0],SHUT_WR)<0||fchmod((v)[0],S_IRUSR)<0)?(-1):0)
#      else
#         define pipe(v) ((socketpair(AF_UNIX,SOCK_STREAM,0,v)<0||shutdown((v)[1],SHUT_RD)<0||shutdown((v)[0],SHUT_WR)<0)?(-1):0)
#      endif
#   endif

#if !_lib_getaddrinfo

#undef	EAI_SYSTEM

#define EAI_SYSTEM		1

#undef	addrinfo
#undef	getaddrinfo
#undef	freeaddrinfo

#define addrinfo		local_addrinfo
#define getaddrinfo		local_getaddrinfo
#define freeaddrinfo		local_freeaddrinfo

struct addrinfo
{
        int			ai_flags;
        int			ai_family;
        int			ai_socktype;
        int			ai_protocol;
        socklen_t		ai_addrlen;
        struct sockaddr*	ai_addr;
        struct addrinfo*	ai_next;
};

static int
getaddrinfo(const char* node, const char* service, const struct addrinfo* hint, struct addrinfo **addr)
{
	unsigned long	    	ip_addr = 0;
	unsigned short	    	ip_port = 0;
	struct addrinfo*	ap;
	struct hostent*		hp;
	struct sockaddr_in*	ip;
	char*			prot;
	long			n;
	
	if (!(hp = gethostbyname(node)) || hp->h_addrtype!=AF_INET || hp->h_length>sizeof(struct in_addr))
	{
		errno = EADDRNOTAVAIL;
		return EAI_SYSTEM;
	}
	ip_addr = (unsigned long)((struct in_addr*)hp->h_addr)->s_addr;
	if ((n = strtol(service, &prot, 10)) > 0 && n <= USHRT_MAX && !*prot)
		ip_port = htons((unsigned short)n);
	else
	{
		struct servent*	sp;
		const char*	protocol = 0;

		if (hint)
			switch (hint->ai_socktype)
			{
			case SOCK_STREAM:
				switch (hint->ai_protocol)
				{
				case 0: 	  
					protocol = "tcp";
					break;
#ifdef IPPROTO_SCTP
				case IPPROTO_SCTP:
					protocol = "sctp";
					break;
#endif
				}
				break;
			case SOCK_DGRAM:
				protocol = "udp";
				break;
			}
		if (!protocol)
		{
			errno =  EPROTONOSUPPORT;
			return 1;
		}
		if (sp = getservbyname(service, protocol))
			ip_port = sp->s_port;
	}
	if (!ip_port)
	{
		errno = EADDRNOTAVAIL;
		return EAI_SYSTEM;
	}
	if (!(ap = newof(0, struct addrinfo, 1, sizeof(struct sockaddr_in))))
		return EAI_SYSTEM;
	if (hint)
		*ap = *hint;
	ap->ai_family = hp->h_addrtype;
	ap->ai_addrlen 	= sizeof(struct sockaddr_in);
	ap->ai_addr = (struct sockaddr *)(ap+1);
	ip = (struct sockaddr_in *)ap->ai_addr;
	ip->sin_family = AF_INET;
	ip->sin_port = ip_port;
	ip->sin_addr.s_addr = ip_addr;
	*addr = ap;
	return 0;
}

static void
freeaddrinfo(struct addrinfo* ap)
{
	if (ap)
		free(ap);
}

#endif

/*
 * return <protocol>/<host>/<service> fd
 */

typedef int (*Inetintr_f)(struct addrinfo*, void*);

static int
inetopen(const char* path, int server, Inetintr_f onintr, void* handle)
{
	register char*		s;
	register char*		t;
	int			fd;
	int			oerrno;
	struct addrinfo		hint;
	struct addrinfo*	addr;
	struct addrinfo*	p;

	memset(&hint, 0, sizeof(hint));
	hint.ai_family = PF_UNSPEC;
	switch (path[0])
	{
#ifdef IPPROTO_SCTP
	case 's':
		if (path[1]!='c' || path[2]!='t' || path[3]!='p' || path[4]!='/')
		{
			errno = ENOTDIR;
			return -1;
		}
		hint.ai_socktype = SOCK_STREAM;
		hint.ai_protocol = IPPROTO_SCTP;
		path += 5;
		break;
#endif
	case 't':
		if (path[1]!='c' || path[2]!='p' || path[3]!='/')
		{
			errno = ENOTDIR;
			return -1;
		}
		hint.ai_socktype = SOCK_STREAM;
		path += 4;
		break;
	case 'u':
		if (path[1]!='d' || path[2]!='p' || path[3]!='/')
		{
			errno = ENOTDIR;
			return -1;
		}
		hint.ai_socktype = SOCK_DGRAM;
		path += 4;
		break;
	default:
		errno = ENOTDIR;
		return -1;
	}
	if (!(s = strdup(path)))
		return -1;
	if (t = strchr(s, '/'))
	{
		*t++ = 0;
		if (streq(s, "local"))
			s = "localhost";
		fd = getaddrinfo(s, t, &hint, &addr);
	}
	else
		fd = -1;
	free(s);
	if (fd)
	{
		if (fd != EAI_SYSTEM)
			errno = ENOTDIR;
		return -1;
	}
	oerrno = errno;
	errno = 0;
	fd = -1;
	for (p = addr; p; p = p->ai_next)
	{
		/*
		 * some api's don't take the hint
		 */

		if (!p->ai_protocol)
			p->ai_protocol = hint.ai_protocol;
		if (!p->ai_socktype)
			p->ai_socktype = hint.ai_socktype;
		while ((fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) >= 0)
		{
			if (server && !bind(fd, p->ai_addr, p->ai_addrlen) && !listen(fd, 5) || !server && !connect(fd, p->ai_addr, p->ai_addrlen))
				goto done;
			close(fd);
			fd = -1;
			if (errno != EINTR || !onintr)
				break;
			if ((*onintr)(addr, handle))
				return -1;
		}
	}
 done:
	freeaddrinfo(addr);
	if (fd >= 0)
		errno = oerrno;
	return fd;
}

#else

#undef	O_SERVICE

#endif

struct fdsave
{
	int	orig_fd;	/* original file descriptor */
	int	save_fd;	/* saved file descriptor */
	int	subshell;	/* saved for subshell */
	char	*tname;		/* name used with >; */
};

static int  	subexcept(Sfio_t*, int, void*, Sfdisc_t*);
static int  	eval_exceptf(Sfio_t*, int, void*, Sfdisc_t*);
static int  	slowexcept(Sfio_t*, int, void*, Sfdisc_t*);
static int	pipeexcept(Sfio_t*, int, void*, Sfdisc_t*);
static ssize_t	piperead(Sfio_t*, void*, size_t, Sfdisc_t*);
static ssize_t	slowread(Sfio_t*, void*, size_t, Sfdisc_t*);
static ssize_t	subread(Sfio_t*, void*, size_t, Sfdisc_t*);
static ssize_t	tee_write(Sfio_t*,const void*,size_t,Sfdisc_t*);
static int	io_prompt(Sfio_t*,int);
static int	io_heredoc(Shell_t*,register struct ionod*, const char*, int);
static void	sftrack(Sfio_t*,int,void*);
static const Sfdisc_t eval_disc = { NULL, NULL, NULL, eval_exceptf, NULL};
static Sfdisc_t tee_disc = {NULL,tee_write,NULL,NULL,NULL};
static Sfio_t *subopen(Shell_t *,Sfio_t*, off_t, long);
static const Sfdisc_t sub_disc = { subread, 0, 0, subexcept, 0 };

struct subfile
{
	Sfdisc_t	disc;
	Sfio_t		*oldsp;
	off_t		offset;
	long		size;
	long		left;
};

struct Eof
{
	Namfun_t	hdr;
	int		fd;
};

static Sfdouble_t nget_cur_eof(register Namval_t* np, Namfun_t *fp)
{
	struct Eof *ep = (struct Eof*)fp;
	Sfoff_t end, cur =lseek(ep->fd, (Sfoff_t)0, SEEK_CUR);
	if(*np->nvname=='C')
	        return((Sfdouble_t)cur);
	if(cur<0)
		return((Sfdouble_t)-1);
	end =lseek(ep->fd, (Sfoff_t)0, SEEK_END);
	lseek(ep->fd, (Sfoff_t)0, SEEK_CUR);
        return((Sfdouble_t)end);
}

static const Namdisc_t EOF_disc	= { sizeof(struct Eof), 0, 0, nget_cur_eof};

#define	MATCH_BUFF	(64*1024)
struct Match
{
	Sfoff_t	offset;
	char	*base;
};

static int matchf(void *handle, char *ptr, size_t size)
{
	struct Match *mp = (struct Match*)handle;
	mp->offset += (ptr-mp->base);
	return(1);
}


static struct fdsave	*filemap;
static short		filemapsize;

/* ======== input output and file copying ======== */

void sh_ioinit(Shell_t *shp)
{
	register int n;
	filemapsize = 8;
	filemap = (struct fdsave*)malloc(filemapsize*sizeof(struct fdsave));
#if SHOPT_FASTPIPE
	n = shp->lim.open_max+2;
#else
	n = shp->lim.open_max;
#endif /* SHOPT_FASTPIPE */
	shp->fdstatus = (unsigned char*)malloc((unsigned)n);
	memset((char*)shp->fdstatus,0,n);
	shp->fdptrs = (int**)malloc(n*sizeof(int*));
	memset((char*)shp->fdptrs,0,n*sizeof(int*));
	shp->sftable = (Sfio_t**)malloc(n*sizeof(Sfio_t*));
	memset((char*)shp->sftable,0,n*sizeof(Sfio_t*));
	shp->sftable[0] = sfstdin;
	shp->sftable[1] = sfstdout;
	shp->sftable[2] = sfstderr;
	sfnotify(sftrack);
	sh_iostream(shp,0);
	/* all write steams are in the same pool and share outbuff */
	shp->outpool = sfopen(NIL(Sfio_t*),NIL(char*),"sw");  /* pool identifier */
	shp->outbuff = (char*)malloc(IOBSIZE+4);
	shp->errbuff = (char*)malloc(IOBSIZE/4);
	sfsetbuf(sfstderr,shp->errbuff,IOBSIZE/4);
	sfsetbuf(sfstdout,shp->outbuff,IOBSIZE);
	sfpool(sfstdout,shp->outpool,SF_WRITE);
	sfpool(sfstderr,shp->outpool,SF_WRITE);
	sfset(sfstdout,SF_LINE,0);
	sfset(sfstderr,SF_LINE,0);
	sfset(sfstdin,SF_SHARE|SF_PUBLIC,1);
}

/*
 *  Handle output stream exceptions
 */
static int outexcept(register Sfio_t *iop,int type,void *data,Sfdisc_t *handle)
{
	static int	active = 0;

	NOT_USED(handle);
	if(type==SF_DPOP || type==SF_FINAL)
		free((void*)handle);
	else if(type==SF_WRITE && (*(ssize_t*)data)<0 && sffileno(iop)!=2)
		switch (errno)
		{
		case EINTR:
		case EPIPE:
#ifdef ECONNRESET
		case ECONNRESET:
#endif
#ifdef ESHUTDOWN
		case ESHUTDOWN:
#endif
			break;
		default:
			if(!active)
			{
				int mode = ((struct checkpt*)sh.jmplist)->mode;
				int save = errno;
				active = 1;
				((struct checkpt*)sh.jmplist)->mode = 0;
				sfpurge(iop);
				sfpool(iop,NIL(Sfio_t*),SF_WRITE);
				errno = save;
				errormsg(SH_DICT,ERROR_system(1),e_badwrite,sffileno(iop));
				active = 0;
				((struct checkpt*)sh.jmplist)->mode = mode;
				sh_exit(1);
			}
			return(-1);
		}
	return(0);
}

/*
 * create or initialize a stream corresponding to descriptor <fd>
 * a buffer with room for a sentinal is allocated for a read stream.
 * A discipline is inserted when read stream is a tty or a pipe
 * For output streams, the buffer is set to sh.output and put into
 * the sh.outpool synchronization pool
 */
Sfio_t *sh_iostream(Shell_t *shp, register int fd)
{
	register Sfio_t *iop;
	register int status = sh_iocheckfd(shp,fd);
	register int flags = SF_WRITE;
	char *bp;
	Sfdisc_t *dp;
#if SHOPT_FASTPIPE
	if(fd>=shp->lim.open_max)
		return(shp->sftable[fd]);
#endif /* SHOPT_FASTPIPE */
	if(status==IOCLOSE)
	{
		switch(fd)
		{
		    case 0:
			return(sfstdin);
		    case 1:
			return(sfstdout);
		    case 2:
			return(sfstderr);
		}
		return(NIL(Sfio_t*));
	}
	if(status&IOREAD)
	{
		if(!(bp = (char *)malloc(IOBSIZE+1)))
			return(NIL(Sfio_t*));
		flags |= SF_READ;
		if(!(status&IOWRITE))
			flags &= ~SF_WRITE;
	}
	else
		bp = shp->outbuff;
	if(status&IODUP)
		flags |= SF_SHARE|SF_PUBLIC;
	if((iop = shp->sftable[fd]) && sffileno(iop)>=0)
		sfsetbuf(iop, bp, IOBSIZE);
	else if(!(iop=sfnew((fd<=2?iop:0),bp,IOBSIZE,fd,flags)))
		return(NIL(Sfio_t*));
	dp = newof(0,Sfdisc_t,1,0);
	if(status&IOREAD)
	{
		sfset(iop,SF_MALLOC,1);
		if(!(status&IOWRITE))
			sfset(iop,SF_IOCHECK,1);
		dp->exceptf = slowexcept;
		if(status&IOTTY)
			dp->readf = slowread;
		else if(status&IONOSEEK)
		{
			dp->readf = piperead;
			sfset(iop, SF_IOINTR,1);
		}
		else
			dp->readf = 0;
		dp->seekf = 0;
		dp->writef = 0;
	}
	else
	{
		dp->exceptf = outexcept;
		sfpool(iop,shp->outpool,SF_WRITE);
	}
	sfdisc(iop,dp);
	shp->sftable[fd] = iop;
	return(iop);
}

/*
 * preserve the file descriptor or stream by moving it
 */
static void io_preserve(Shell_t* shp, register Sfio_t *sp, register int f2)
{
	register int fd;
	if(sp)
		fd = sfsetfd(sp,10);
	else
		fd = sh_fcntl(f2,F_DUPFD,10);
	if(f2==shp->infd)
		shp->infd = fd;
	if(fd<0)
	{
		shp->toomany = 1;
		((struct checkpt*)shp->jmplist)->mode = SH_JMPERREXIT;
		errormsg(SH_DICT,ERROR_system(1),e_toomany);
	}
	if(shp->fdptrs[fd]=shp->fdptrs[f2])
	{
		if(f2==job.fd)
			job.fd=fd;
		*shp->fdptrs[fd] = fd;
		shp->fdptrs[f2] = 0;
	}
	shp->sftable[fd] = sp;
	shp->fdstatus[fd] = shp->fdstatus[f2];
	if(fcntl(f2,F_GETFD,0)&1)
	{
		fcntl(fd,F_SETFD,FD_CLOEXEC);
		shp->fdstatus[fd] |= IOCLEX;
	}
	shp->sftable[f2] = 0;
}

/*
 * Given a file descriptor <f1>, move it to a file descriptor number <f2>
 * If <f2> is needed move it, otherwise it is closed first.
 * The original stream <f1> is closed.
 *  The new file descriptor <f2> is returned;
 */
int sh_iorenumber(Shell_t *shp, register int f1,register int f2)
{
	register Sfio_t *sp = shp->sftable[f2];
	if(f1!=f2)
	{
		/* see whether file descriptor is in use */
		if(sh_inuse(f2) || (f2>2 && sp))
		{
			if(!(shp->inuse_bits&(1<<f2)))
				io_preserve(shp,sp,f2);
			sp = 0;
		}
		else if(f2==0)
			shp->st.ioset = 1;
		sh_close(f2);
		if(f2<=2 && sp)
		{
			register Sfio_t *spnew = sh_iostream(shp,f1);
			shp->fdstatus[f2] = (shp->fdstatus[f1]&~IOCLEX);
			sfsetfd(spnew,f2);
			sfswap(spnew,sp);
			sfset(sp,SF_SHARE|SF_PUBLIC,1);
		}
		else 
		{
			shp->fdstatus[f2] = (shp->fdstatus[f1]&~IOCLEX);
			if((f2 = sh_fcntl(f1,F_DUPFD, f2)) < 0)
				errormsg(SH_DICT,ERROR_system(1),e_file+4);
			else if(f2 <= 2)
				sh_iostream(shp,f2);
		}
		if(sp)
			shp->sftable[f1] = 0;
		sh_close(f1);
	}
	return(f2);
}

/*
 * close a file descriptor and update stream table and attributes 
 */
int sh_close(register int fd)
{
	register Sfio_t *sp;
	register int r = 0;
	if(fd<0)
		return(-1);
	if(!(sp=sh.sftable[fd]) || sfclose(sp) < 0)
	{
		if(fdnotify)
			(*fdnotify)(fd,SH_FDCLOSE);
		r=close(fd);
	}
	if(fd>2)
		sh.sftable[fd] = 0;
	sh.fdstatus[fd] = IOCLOSE;
	if(sh.fdptrs[fd])
		*sh.fdptrs[fd] = -1;
	sh.fdptrs[fd] = 0;
	if(fd < 10)
		sh.inuse_bits &= ~(1<<fd);
	return(r);
}

#ifdef O_SERVICE

static int
onintr(struct addrinfo* addr, void* handle)
{
	Shell_t*	sh = (Shell_t*)handle;

	if (sh->trapnote&SH_SIGSET)
	{
		freeaddrinfo(addr);
		sh_exit(SH_EXITSIG);
		return -1;
	}
	if (sh->trapnote)
		sh_chktrap();
	return 0;
}

#endif

/*
 * Mimic open(2) with checks for pseudo /dev/ files.
 */
int sh_open(register const char *path, int flags, ...)
{
	Shell_t			*shp = &sh;
	register int		fd = -1;
	mode_t			mode;
	char			*e;
	va_list			ap;
	va_start(ap, flags);
	mode = (flags & O_CREAT) ? va_arg(ap, int) : 0;
	va_end(ap);
	errno = 0;
	if(*path==0)
	{
		errno = ENOENT;
		return(-1);
	}
	if (path[0]=='/' && path[1]=='d' && path[2]=='e' && path[3]=='v' && path[4]=='/')
	{
		switch (path[5])
		{
		case 'f':
			if (path[6]=='d' && path[7]=='/')
			{
				fd = (int)strtol(path+8, &e, 10);
				if (*e)
					fd = -1;
			}
			break;
		case 's':
			if (path[6]=='t' && path[7]=='d')
				switch (path[8])
				{
				case 'e':
					if (path[9]=='r' && path[10]=='r' && !path[11])
						fd = 2;
					break;
				case 'i':
					if (path[9]=='n' && !path[10])
						fd = 0;
					break;
				case 'o':
					if (path[9]=='u' && path[10]=='t' && !path[11])
						fd = 1;
					break;
				}
		}
#ifdef O_SERVICE
		if (fd < 0)
		{
			if ((fd = inetopen(path+5, !!(flags & O_SERVICE), onintr, &sh)) < 0 && errno != ENOTDIR)
				return -1;
			if (fd >= 0)
				goto ok;
		}
#endif
	}
	if (fd >= 0)
	{
		int nfd= -1;
		if (flags & O_CREAT)
		{
			struct stat st;
			if (stat(path,&st) >=0)
				nfd = open(path,flags,st.st_mode);
		}
		else
			nfd = open(path,flags);
		if(nfd>=0)
		{
			fd = nfd;
			goto ok;
		}
		if((mode=sh_iocheckfd(shp,fd))==IOCLOSE)
			return(-1);
		flags &= O_ACCMODE;
		if(!(mode&IOWRITE) && ((flags==O_WRONLY) || (flags==O_RDWR)))
			return(-1);
		if(!(mode&IOREAD) && ((flags==O_RDONLY) || (flags==O_RDWR)))
			return(-1);
		if((fd=dup(fd))<0)
			return(-1);
	}
	else
	{
#if SHOPT_REGRESS
		char	buf[PATH_MAX];
		if(strncmp(path,"/etc/",5)==0)
		{
			sfsprintf(buf, sizeof(buf), "%s%s", sh_regress_etc(path, __LINE__, __FILE__), path+4);
			path = buf;
		}
#endif
		while((fd = open(path, flags, mode)) < 0)
			if(errno!=EINTR || sh.trapnote)
				return(-1);
 	}
 ok:
	flags &= O_ACCMODE;
	if(flags==O_WRONLY)
		mode = IOWRITE;
	else if(flags==O_RDWR)
		mode = (IOREAD|IOWRITE);
	else
		mode = IOREAD;
	sh.fdstatus[fd] = mode;
	return(fd);
}

/*
 * Open a file for reading
 * On failure, print message.
 */
int sh_chkopen(register const char *name)
{
	register int fd = sh_open(name,O_RDONLY,0);
	if(fd < 0)
		errormsg(SH_DICT,ERROR_system(1),e_open,name);
	return(fd);
}

/*
 * move open file descriptor to a number > 2
 */
int sh_iomovefd(register int fdold)
{
	register int fdnew;
	if(fdold<0 || fdold>2)
		return(fdold);
	fdnew = sh_iomovefd(dup(fdold));
	sh.fdstatus[fdnew] = (sh.fdstatus[fdold]&~IOCLEX);
	close(fdold);
	sh.fdstatus[fdold] = IOCLOSE;
	return(fdnew);
}

/*
 * create a pipe and print message on failure
 */
int	sh_pipe(register int pv[])
{
	int fd[2];
	if(pipe(fd)<0 || (pv[0]=fd[0])<0 || (pv[1]=fd[1])<0)
		errormsg(SH_DICT,ERROR_system(1),e_pipe);
	pv[0] = sh_iomovefd(pv[0]);
	pv[1] = sh_iomovefd(pv[1]);
	sh.fdstatus[pv[0]] = IONOSEEK|IOREAD;
	sh.fdstatus[pv[1]] = IONOSEEK|IOWRITE;
	sh_subsavefd(pv[0]);
	sh_subsavefd(pv[1]);
	return(0);
}

static int pat_seek(void *handle, const char *str, size_t sz)
{
	char **bp = (char**)handle;
	*bp = (char*)str;
	return(-1);
}

static int pat_line(const regex_t* rp, const char *buff, register size_t n)
{
	register const char *cp=buff, *sp;
	while(n>0)
	{
		for(sp=cp; n-->0 && *cp++ != '\n';);
		if(regnexec(rp,sp,cp-sp, 0, (regmatch_t*)0, 0)==0)
			return(sp-buff);
	}
	return(cp-buff);
}

static int io_patseek(Shell_t *shp, regex_t *rp, Sfio_t* sp, int flags)
{
	char	*cp, *match;
	int	r, fd=sffileno(sp), close_exec = shp->fdstatus[fd]&IOCLEX;
	int	was_share,s=(PIPE_BUF>SF_BUFSIZE?SF_BUFSIZE:PIPE_BUF);
	size_t	n,m;
	shp->fdstatus[sffileno(sp)] |= IOCLEX;
	if(fd==0)
		was_share = sfset(sp,SF_SHARE,1);
	while((cp=sfreserve(sp, -s, SF_LOCKR)) || (cp=sfreserve(sp,SF_UNBOUND, SF_LOCKR)))
	{
		m = n = sfvalue(sp);
		while(n>0 && cp[n-1]!='\n')
			n--;
		if(n)
			m = n;
		r = regrexec(rp,cp,m,0,(regmatch_t*)0, 0, '\n', (void*)&match, pat_seek);
		if(r<0)
			m = match-cp;
		else if(r==2)
		{
			if((m = pat_line(rp,cp,m)) < n)
				r = -1;
		}
		if(m && (flags&IOCOPY))
			sfwrite(sfstdout,cp,m);
		sfread(sp,cp,m);
		if(r<0)
			break;
	}
	if(!close_exec)
		shp->fdstatus[sffileno(sp)] &= ~IOCLEX;
	if(fd==0 && !(was_share&SF_SHARE))
		sfset(sp, SF_SHARE,0);
	return(0);
}

static Sfoff_t	file_offset(Shell_t *shp, int fn, char *fname)
{
	Sfio_t		*sp = shp->sftable[fn];
	char		*cp;
	Sfoff_t		off;
	struct Eof	endf;
	Namval_t	*mp = nv_open("EOF",shp->var_tree,0);
	Namval_t	*pp = nv_open("CUR",shp->var_tree,0);
	memset(&endf,0,sizeof(struct Eof));
	endf.fd = fn;
	endf.hdr.disc = &EOF_disc;
	endf.hdr.nofree = 1;
	if(mp)
		nv_stack(mp, &endf.hdr);
	if(pp)
		nv_stack(pp, &endf.hdr);
	if(sp)
		sfsync(sp);
	off = sh_strnum(fname, &cp, 0);
	if(mp)
		nv_stack(mp, NiL);
	if(pp)
		nv_stack(pp, NiL);
	return(*cp?(Sfoff_t)-1:off);
}

/*
 * close a pipe
 */
void sh_pclose(register int pv[])
{
	if(pv[0]>=2)
		sh_close(pv[0]);
	if(pv[1]>=2)
		sh_close(pv[1]);
	pv[0] = pv[1] = -1;
}

static char *io_usename(char *name, int *perm, int mode)
{
	struct stat	statb;
	char		*tname, *sp, *ep;
	int		fd,len,n=0;
	if(mode==0)
	{
		if((fd = sh_open(name,O_RDONLY,0)) > 0)
		{
			if(fstat(fd,&statb) < 0)
				return(0);
			if(!S_ISREG(statb.st_mode))
				return(0);
		 	*perm = statb.st_mode&(RW_ALL|(S_IXUSR|S_IXGRP|S_IXOTH));
		}
		else if(fd < 0  && errno!=ENOENT)
			return(0);
	}
	tname = sp = (char*)stakalloc((len=strlen(name)) + 5);
	if(ep = strrchr(name,'/'))
	{
		memcpy(sp,name,n=++ep-name);
		len -=n;
		sp += n;
	}
	else
		ep = name;
	*sp++ = '.';
	memcpy(sp,ep,len);
	strcpy(sp+len,".tmp");
	switch(mode)
	{
	    case 1:
		rename(tname,name);
		break;
	    case 2:
		unlink(tname);
		break;
	}
	return(tname);
}

/*
 * I/O redirection
 * flag = 0 if files are to be restored
 * flag = 2 if files are to be closed on exec
 * flag = 3 when called from $( < ...), just open file and return
 * flag = SH_SHOWME for trace only
 */
int	sh_redirect(Shell_t *shp,struct ionod *iop, int flag)
{
	Sfoff_t off; 
	register char *fname;
	register int 	fd, iof;
	const char *message = e_open;
	int o_mode;		/* mode flag for open */
	static char io_op[7];	/* used for -x trace info */
	int trunc=0, clexec=0, fn, traceon;
	int r, indx = shp->topfd, perm= -1;
	char *tname=0, *after="", *trace = shp->st.trap[SH_DEBUGTRAP];
	Namval_t *np=0;
	int isstring = shp->subshell?(sfset(sfstdout,0,0)&SF_STRING):0;
	if(flag==2)
		clexec = 1;
	if(iop)
		traceon = sh_trace(NIL(char**),0);
	for(;iop;iop=iop->ionxt)
	{
		iof=iop->iofile;
		fn = (iof&IOUFD);
		if(fn==1 && shp->subshell && !shp->subshare && (flag==2 || isstring))
			sh_subfork();
		io_op[0] = '0'+(iof&IOUFD);
		if(iof&IOPUT)
		{
			io_op[1] = '>';
			o_mode = O_WRONLY|O_CREAT;
		}
		else
		{
			io_op[1] = '<';
			o_mode = O_RDONLY|O_NONBLOCK;
		}
		io_op[2] = 0;
		io_op[3] = 0;
		io_op[4] = 0;
		fname = iop->ioname;
		if(!(iof&IORAW))
		{
			if(iof&IOLSEEK)
			{
				struct argnod *ap = (struct argnod*)stakalloc(ARGVAL+strlen(iop->ioname));
				memset(ap, 0, ARGVAL);
				ap->argflag = ARG_MAC;
				strcpy(ap->argval,iop->ioname);
				fname=sh_macpat(shp,ap,(iof&IOARITH)?ARG_ARITH:ARG_EXP);
			}
			else if(iof&IOPROCSUB)
			{
				struct argnod *ap = (struct argnod*)stakalloc(ARGVAL+strlen(iop->ioname));
				memset(ap, 0, ARGVAL);
				if(iof&IOPUT)
					ap->argflag = ARG_RAW;
				ap->argchn.ap = (struct argnod*)fname; 
				ap = sh_argprocsub(shp,ap);
				fname = ap->argval;
			}
			else
				fname=sh_mactrim(shp,fname,(!sh_isoption(SH_NOGLOB)&&sh_isoption(SH_INTERACTIVE))?2:0);
		}
		errno=0;
		np = 0;
		if(iop->iovname)
		{
			np = nv_open(iop->iovname,shp->var_tree,NV_NOASSIGN|NV_VARNAME);
			if(nv_isattr(np,NV_RDONLY))
				errormsg(SH_DICT,ERROR_exit(1),e_readonly, nv_name(np));
			io_op[0] = '}';
			if((iof&IOLSEEK) || ((iof&IOMOV) && *fname=='-'))
				fn = nv_getnum(np);
		}
		if(iof&IOLSEEK)
		{
			io_op[2] = '#';
			if(iof&IOARITH)
			{
				strcpy(&io_op[3]," ((");
				after = "))";
			}
			else if(iof&IOCOPY)
				io_op[3] = '#';
			goto traceit;
		}
		if(*fname)
		{
			if(iof&IODOC)
			{
				if(traceon)
					sfputr(sfstderr,io_op,'<');
				fd = io_heredoc(shp,iop,fname,traceon);
				if(traceon && (flag==SH_SHOWME))
					sh_close(fd);
				fname = 0;
			}
			else if(iof&IOMOV)
			{
				int dupfd,toclose= -1;
				io_op[2] = '&';
				if((fd=fname[0])>='0' && fd<='9')
				{
					char *number = fname;
					dupfd = strtol(fname,&number,10);
					if(*number=='-')
					{
						toclose = dupfd;
						number++;
					}
					if(*number || dupfd > IOUFD)
					{
						message = e_file;
						goto fail;
					}
					if(shp->subshell && dupfd==1 && (sfset(sfstdout,0,0)&SF_STRING))
					{
						sh_subtmpfile(0);
						dupfd = sffileno(sfstdout);
					}
					else if(shp->sftable[dupfd])
						sfsync(shp->sftable[dupfd]);
				}
				else if(fd=='-' && fname[1]==0)
				{
					fd= -1;
					goto traceit;
				}
				else if(fd=='p' && fname[1]==0)
				{
					if(iof&IOPUT)
						dupfd = shp->coutpipe;
					else
						dupfd = shp->cpipe[0];
					if(flag)
						toclose = dupfd;
				}
				else
				{
					message = e_file;
					goto fail;
				}
				if(flag==SH_SHOWME)
					goto traceit;
				if((fd=sh_fcntl(dupfd,F_DUPFD,3))<0)
					goto fail;
				sh_iocheckfd(shp,dupfd);
				shp->fdstatus[fd] = (shp->fdstatus[dupfd]&~IOCLEX);
				if(toclose<0 && shp->fdstatus[fd]&IOREAD)
					shp->fdstatus[fd] |= IODUP;
				else if(dupfd==shp->cpipe[0])
					sh_pclose(shp->cpipe);
				else if(toclose>=0)
				{
					if(flag==0)
						sh_iosave(shp,toclose,indx,(char*)0); /* save file descriptor */
					sh_close(toclose);
				}
			}
			else if(iof&IORDW)
			{
				if(sh_isoption(SH_RESTRICTED))
					errormsg(SH_DICT,ERROR_exit(1),e_restricted,fname);
				io_op[2] = '>';
				o_mode = O_RDWR|O_CREAT;
				if(iof&IOREWRITE)
					trunc = io_op[2] = ';';
				goto openit;
			}
			else if(!(iof&IOPUT))
			{
				if(flag==SH_SHOWME)
					goto traceit;
				fd=sh_chkopen(fname);
			}
			else if(sh_isoption(SH_RESTRICTED))
				errormsg(SH_DICT,ERROR_exit(1),e_restricted,fname);
			else
			{
				if(iof&IOAPP)
				{
					io_op[2] = '>';
					o_mode |= O_APPEND;
				}
				else if((iof&IOREWRITE) && (flag==0 || flag==1 || sh_subsavefd(fn)))
				{
					io_op[2] = ';';
					o_mode |= O_TRUNC;
					tname = io_usename(fname,&perm,0);
				}
				else
				{
					o_mode |= O_TRUNC;
					if(iof&IOCLOB)
						io_op[2] = '|';
					else if(sh_isoption(SH_NOCLOBBER))
					{
						struct stat sb;
						if(stat(fname,&sb)>=0)
						{
#if SHOPT_FS_3D
							if(S_ISREG(sb.st_mode)&&
						                (!shp->lim.fs3d || iview(&sb)==0))
#else
							if(S_ISREG(sb.st_mode))
#endif /* SHOPT_FS_3D */
							{
								errno = EEXIST;
								errormsg(SH_DICT,ERROR_system(1),e_exists,fname);
							}
						}
						else
							o_mode |= O_EXCL;
					}
				}
			openit:
				if(flag!=SH_SHOWME)
				{
					if((fd=sh_open(tname?tname:fname,o_mode,RW_ALL)) <0)
						errormsg(SH_DICT,ERROR_system(1),((o_mode&O_CREAT)?e_create:e_open),fname);
					if(perm>0)
#if _lib_fchmod
						fchmod(fd,perm);
#else
						chmod(tname,perm);
#endif
				}
			}
		traceit:
			if(traceon && fname)
			{
				if(np)
					sfprintf(sfstderr,"{%s",nv_name(np));
				sfprintf(sfstderr,"%s %s%s%c",io_op,fname,after,iop->ionxt?' ':'\n');
			}
			if(flag==SH_SHOWME)
				return(indx);
			if(trace && fname)
			{
				char *argv[7], **av=argv;
				av[3] = io_op;
				av[4] = fname;
				av[5] = 0;
				av[6] = 0;
				if(iof&IOARITH)
					av[5] = after;
				if(np)
				{
					av[0] = "{";
					av[1] = nv_name(np);
					av[2] = "}";
				}
				else
					av +=3;
				sh_debug(shp,trace,(char*)0,(char*)0,av,ARG_NOGLOB);
			}
			if(iof&IOLSEEK)
			{
				Sfio_t *sp = shp->sftable[fn];
				r = shp->fdstatus[fn];
				if(!(r&(IOSEEK|IONOSEEK)))
					r = sh_iocheckfd(shp,fn);
				sfsprintf(io_op,sizeof(io_op),"%d\0",fn);
				if(r==IOCLOSE)
				{
					fname = io_op;
					message = e_file;
					goto fail;
				}
				if(iof&IOARITH)
				{
					if(r&IONOSEEK)
					{
						fname = io_op;
						message = e_notseek;
						goto fail;
					}
					message = e_badseek;
					if((off = file_offset(shp,fn,fname))<0)
						goto fail;
					if(sp)
					{
						off=sfseek(sp, off, SEEK_SET);
						sfsync(sp);
					}
					else
						off=lseek(fn, off, SEEK_SET);
					if(off<0)
						r = -1;
				}
				else
				{
					regex_t *rp;
					extern const char e_notimp[];
					if(!(r&IOREAD))
					{
						message = e_noread;
						goto fail;
					}
					if(!(rp = regcache(fname, REG_SHELL|REG_NOSUB|REG_NEWLINE|REG_AUGMENTED|REG_FIRST|REG_LEFT|REG_RIGHT, &r)))
					{
						message = e_badpattern;
						goto fail;
					}
					if(!sp)
						sp = sh_iostream(shp,fn);
					r=io_patseek(shp,rp,sp,iof);
					if(sp && flag==3)
					{
						/* close stream but not fn */
						sfsetfd(sp,-1);
						sfclose(sp);
					}
				}
				if(r<0)
					goto fail;
				if(flag==3)
					return(fn);
				continue;
			}
			if(!np)
			{
				if(flag==0 || tname)
				{
					if(fd==fn)
					{
						if((r=sh_fcntl(fd,F_DUPFD,10)) > 0)
						{
							fd = r;
							sh_close(fn);
						}
					}
					sh_iosave(shp,fn,indx,tname?fname:(trunc?Empty:0));
				}
				else if(sh_subsavefd(fn))
					sh_iosave(shp,fn,indx|IOSUBSHELL,tname?fname:0);
			}
			if(fd<0)
			{
				if(sh_inuse(fn) || (fn && fn==shp->infd))
				{
					if(fn>9 || !(shp->inuse_bits&(1<<fn)))
						io_preserve(shp,shp->sftable[fn],fn);
				}
				sh_close(fn);
			}
			if(flag==3)
				return(fd);
			if(fd>=0)
			{
				if(np)
				{
					int32_t v;
					fn = fd;
					if(fd<10)
					{
						if((fn=fcntl(fd,F_DUPFD,10)) < 0)
							goto fail;
						shp->fdstatus[fn] = shp->fdstatus[fd];
						sh_close(fd);
						fd = fn;
					}
					nv_unset(np);
					nv_onattr(np,NV_INT32);
					v = fn;
					nv_putval(np,(char*)&v, NV_INT32);
					sh_iocheckfd(shp,fd);
				}
				else
				{
					fd = sh_iorenumber(shp,sh_iomovefd(fd),fn);
					if(fn>2 && fn<10)
						shp->inuse_bits |= (1<<fn);
				}
			}
			if(fd >2 && clexec)
			{
				fcntl(fd,F_SETFD,FD_CLOEXEC);
				shp->fdstatus[fd] |= IOCLEX;
			}
		}
		else 
			goto fail;
	}
	return(indx);
fail:
	errormsg(SH_DICT,ERROR_system(1),message,fname);
	/* NOTREACHED */
	return(0);
}
/*
 * Create a tmp file for the here-document
 */
static int io_heredoc(Shell_t *shp,register struct ionod *iop, const char *name, int traceon)
{
	register Sfio_t	*infile = 0, *outfile;
	register int		fd;
	if(!(iop->iofile&IOSTRG) && (!shp->heredocs || iop->iosize==0))
		return(sh_open(e_devnull,O_RDONLY));
	/* create an unnamed temporary file */
	if(!(outfile=sftmp(0)))
		errormsg(SH_DICT,ERROR_system(1),e_tmpcreate);
	if(iop->iofile&IOSTRG)
	{
		if(traceon)
			sfprintf(sfstderr,"< %s\n",name);
		sfputr(outfile,name,'\n');
	}
	else
	{
		infile = subopen(shp,shp->heredocs,iop->iooffset,iop->iosize);
		if(traceon)
		{
			char *cp = sh_fmtq(iop->iodelim);
			fd = (*cp=='$' || *cp=='\'')?' ':'\\';
			sfprintf(sfstderr," %c%s\n",fd,cp);
			sfdisc(outfile,&tee_disc);
		}
		if(iop->iofile&IOQUOTE)
		{
			/* This is a quoted here-document, not expansion */
			sfmove(infile,outfile,SF_UNBOUND,-1);
			sfclose(infile);
		}
		else
		{
			char *lastpath = shp->lastpath;
			sh_machere(shp,infile,outfile,iop->ioname);
			shp->lastpath = lastpath;
			if(infile)
				sfclose(infile);
		}
	}
	/* close stream outfile, but save file descriptor */
	fd = sffileno(outfile);
	sfsetfd(outfile,-1);
	sfclose(outfile);
	if(traceon && !(iop->iofile&IOSTRG))
		sfputr(sfstderr,iop->ioname,'\n');
	lseek(fd,(off_t)0,SEEK_SET);
	shp->fdstatus[fd] = IOREAD;
	return(fd);
}

/*
 * This write discipline also writes the output on standard error
 * This is used when tracing here-documents
 */
static ssize_t tee_write(Sfio_t *iop,const void *buff,size_t n,Sfdisc_t *unused)
{
	NOT_USED(unused);
	sfwrite(sfstderr,buff,n);
	return(write(sffileno(iop),buff,n));
}

/*
 * copy file <origfd> into a save place
 * The saved file is set close-on-exec
 * if <origfd> < 0, then -origfd is saved, but not duped so that it
 *   will be closed with sh_iorestore.
 */
void sh_iosave(Shell_t *shp, register int origfd, int oldtop, char *name)
{
/*@
	assume oldtop>=0 && oldtop<shp->lim.open_max;
@*/
 
	register int	savefd;
	int flag = (oldtop&IOSUBSHELL);
	oldtop &= ~IOSUBSHELL;
	/* see if already saved, only save once */
	for(savefd=shp->topfd; --savefd>=oldtop; )
	{
		if(filemap[savefd].orig_fd == origfd)
			return;
	}
	/* make sure table is large enough */
	if(shp->topfd >= filemapsize)
	{
		char 	*cp, *oldptr = (char*)filemap;
		char 	*oldend = (char*)&filemap[filemapsize];
		long	moved;
		filemapsize += 8;
		if(!(filemap = (struct fdsave*)realloc(filemap,filemapsize*sizeof(struct fdsave))))
			errormsg(SH_DICT,ERROR_exit(4),e_nospace);
		if(moved = (char*)filemap - oldptr)
		{
#if SHOPT_FASTPIPE
			for(savefd=shp->lim.open_max+2; --savefd>=0; )
#else
			for(savefd=shp->lim.open_max; --savefd>=0; )
#endif /* SHOPT_FASTPIPE */
			{
				cp = (char*)shp->fdptrs[savefd];
				if(cp >= oldptr && cp < oldend)
					shp->fdptrs[savefd] = (int*)(oldptr+moved);
			}
		}
	}
#if SHOPT_DEVFD
	if(origfd <0)
	{
		savefd = origfd;
		origfd = -origfd;
	}
	else
#endif /* SHOPT_DEVFD */
	{
		if((savefd = sh_fcntl(origfd, F_DUPFD, 10)) < 0 && errno!=EBADF)
		{
			shp->toomany=1;
			((struct checkpt*)shp->jmplist)->mode = SH_JMPERREXIT;
			errormsg(SH_DICT,ERROR_system(1),e_toomany);
		}
	}
	filemap[shp->topfd].tname = name;
	filemap[shp->topfd].subshell = flag;
	filemap[shp->topfd].orig_fd = origfd;
	filemap[shp->topfd++].save_fd = savefd;
	if(savefd >=0)
	{
		register Sfio_t* sp = shp->sftable[origfd];
		/* make saved file close-on-exec */
		sh_fcntl(savefd,F_SETFD,FD_CLOEXEC);
		if(origfd==job.fd)
			job.fd = savefd;
		shp->fdstatus[savefd] = shp->fdstatus[origfd];
		shp->fdptrs[savefd] = &filemap[shp->topfd-1].save_fd;
		if(!(shp->sftable[savefd]=sp))
			return;
		sfsync(sp);
		if(origfd <=2)
		{
			/* copy standard stream to new stream */
			sp = sfswap(sp,NIL(Sfio_t*));
			shp->sftable[savefd] = sp;
		}
		else
			shp->sftable[origfd] = 0;
	}
}

/*
 *  close all saved file descriptors
 */
void	sh_iounsave(Shell_t* shp)
{
	register int fd, savefd, newfd;
	for(newfd=fd=0; fd < shp->topfd; fd++)
	{
		if((savefd = filemap[fd].save_fd)< 0)
			filemap[newfd++] = filemap[fd];
		else
		{
			shp->sftable[savefd] = 0;
			sh_close(savefd);
		}
	}
	shp->topfd = newfd;
}

/*
 *  restore saved file descriptors from <last> on
 */
void	sh_iorestore(Shell_t *shp, int last, int jmpval)
{
	register int 	origfd, savefd, fd;
	int flag = (last&IOSUBSHELL);
	last &= ~IOSUBSHELL;
	for (fd = shp->topfd - 1; fd >= last; fd--)
	{
		if(!flag && filemap[fd].subshell)
			continue;
		if(jmpval==SH_JMPSCRIPT)
		{
			if ((savefd = filemap[fd].save_fd) >= 0)
			{
				shp->sftable[savefd] = 0;
				sh_close(savefd);
			}
			continue;
		}
		origfd = filemap[fd].orig_fd;
		if(filemap[fd].tname == Empty && shp->exitval==0)
			ftruncate(origfd,lseek(origfd,0,SEEK_CUR));
		else if(filemap[fd].tname)
			io_usename(filemap[fd].tname,(int*)0,shp->exitval?2:1);
		sh_close(origfd);
		if ((savefd = filemap[fd].save_fd) >= 0)
		{
			sh_fcntl(savefd, F_DUPFD, origfd);
			if(savefd==job.fd)
				job.fd=origfd;
			shp->fdstatus[origfd] = shp->fdstatus[savefd];
			/* turn off close-on-exec if flag if necessary */
			if(shp->fdstatus[origfd]&IOCLEX)
				fcntl(origfd,F_SETFD,FD_CLOEXEC);
			if(origfd<=2)
			{
				sfswap(shp->sftable[savefd],shp->sftable[origfd]);
				if(origfd==0)
					shp->st.ioset = 0;
			}
			else
				shp->sftable[origfd] = shp->sftable[savefd];
			shp->sftable[savefd] = 0;
			sh_close(savefd);
		}
		else
			shp->fdstatus[origfd] = IOCLOSE;
	}
	if(!flag)
	{
		/* keep file descriptors for subshell restore */
		for (fd = last ; fd < shp->topfd; fd++)
		{
			if(filemap[fd].subshell)
				filemap[last++] = filemap[fd];
		}
	}
	if(last < shp->topfd)
		shp->topfd = last;
}

/*
 * returns access information on open file <fd>
 * returns -1 for failure, 0 for success
 * <mode> is the same as for access()
 */
int sh_ioaccess(int fd,register int mode)
{
	Shell_t	*shp = &sh;
	register int flags;
	if(mode==X_OK)
		return(-1);
	if((flags=sh_iocheckfd(shp,fd))!=IOCLOSE)
	{
		if(mode==F_OK)
			return(0);
		if(mode==R_OK && (flags&IOREAD))
			return(0);
		if(mode==W_OK && (flags&IOWRITE))
			return(0);
	}
	return(-1);
}

/*
 *  Handle interrupts for slow streams
 */
static int slowexcept(register Sfio_t *iop,int type,void *data,Sfdisc_t *handle)
{
	register int	n,fno;
	NOT_USED(handle);
	if(type==SF_DPOP || type==SF_FINAL)
		free((void*)handle);
	if(type!=SF_READ)
		return(0);
	if((sh.trapnote&(SH_SIGSET|SH_SIGTRAP)) && errno!=EIO && errno!=ENXIO)
		errno = EINTR;
	fno = sffileno(iop);
	if((n=sfvalue(iop))<=0)
	{
#ifndef FNDELAY
#   ifdef O_NDELAY
		if(errno==0 && (n=fcntl(fno,F_GETFL,0))&O_NDELAY)
		{
			n &= ~O_NDELAY;
			fcntl(fno, F_SETFL, n);
			return(1);
		}
#   endif /* O_NDELAY */
#endif /* !FNDELAY */
#ifdef O_NONBLOCK
		if(errno==EAGAIN)
		{
			n = fcntl(fno,F_GETFL,0);
			n &= ~O_NONBLOCK;
			fcntl(fno, F_SETFL, n);
			return(1);
		}
#endif /* O_NONBLOCK */
		if(errno!=EINTR)
			return(0);
		n=1;
		sh_onstate(SH_TTYWAIT);
	}
	else
		n = 0;
	if(sh.bltinfun && sh.bltindata.sigset)
		return(-1);
	errno = 0;
	if(sh.trapnote&SH_SIGSET)
	{
		if(isatty(fno))
			sfputc(sfstderr,'\n');
		sh_exit(SH_EXITSIG);
	}
	if(sh.trapnote&SH_SIGTRAP)
		sh_chktrap();
	return(n);
}

/*
 * called when slowread times out
 */
static void time_grace(void *handle)
{
	NOT_USED(handle);
	timeout = 0;
	if(sh_isstate(SH_GRACE))
	{
		sh_offstate(SH_GRACE);
		if(!sh_isstate(SH_INTERACTIVE))
			return;
		((struct checkpt*)sh.jmplist)->mode = SH_JMPEXIT;
		errormsg(SH_DICT,2,e_timeout);
		sh.trapnote |= SH_SIGSET;
		return;
	}
	errormsg(SH_DICT,0,e_timewarn);
	sh_onstate(SH_GRACE);
	sigrelease(SIGALRM);
	sh.trapnote |= SH_SIGTRAP;
}

static ssize_t piperead(Sfio_t *iop,void *buff,register size_t size,Sfdisc_t *handle)
{
	int fd = sffileno(iop);
	NOT_USED(handle);
	if(job.waitsafe && job.savesig)
	{
		job_lock();
		job_unlock();
	}
	if(sh.trapnote)
	{
		errno = EINTR;
		return(-1);
	}
	if(sh_isstate(SH_INTERACTIVE) && io_prompt(iop,sh.nextprompt)<0 && errno==EIO)
		return(0);
	sh_onstate(SH_TTYWAIT);
	if(!(sh.fdstatus[sffileno(iop)]&IOCLEX) && (sfset(iop,0,0)&SF_SHARE))
		size = ed_read(sh.ed_context, fd, (char*)buff, size,0);
	else
		size = sfrd(iop,buff,size,handle);
	sh_offstate(SH_TTYWAIT);
	return(size);
}
/*
 * This is the read discipline that is applied to slow devices
 * This routine takes care of prompting for input
 */
static ssize_t slowread(Sfio_t *iop,void *buff,register size_t size,Sfdisc_t *handle)
{
	int	(*readf)(void*, int, char*, int, int);
	int	reedit=0, rsize;
#if SHOPT_HISTEXPAND
	char    *xp=0;
#endif
	NOT_USED(handle);
#   if SHOPT_ESH
	if(sh_isoption(SH_EMACS) || sh_isoption(SH_GMACS))
		readf = ed_emacsread;
	else
#   endif	/* SHOPT_ESH */
#   if SHOPT_VSH
#	if SHOPT_RAWONLY
	    if(sh_isoption(SH_VI) || ((SHOPT_RAWONLY-0) && mbwide()))
#	else
	    if(sh_isoption(SH_VI))
#	endif
		readf = ed_viread;
	else
#   endif	/* SHOPT_VSH */
		readf = ed_read;
	if(sh.trapnote)
	{
		errno = EINTR;
		return(-1);
	}
	while(1)
	{
		if(io_prompt(iop,sh.nextprompt)<0 && errno==EIO)
			return(0);
		if(sh.timeout)
			timeout = (void*)sh_timeradd(sh_isstate(SH_GRACE)?1000L*TGRACE:1000L*sh.timeout,0,time_grace,NIL(void*));
		rsize = (*readf)(sh.ed_context, sffileno(iop), (char*)buff, size, reedit);
		if(timeout)
			timerdel(timeout);
		timeout=0;
#if SHOPT_HISTEXPAND
		if(rsize && *(char*)buff != '\n' && sh.nextprompt==1 && sh_isoption(SH_HISTEXPAND))
		{
			int r;
			((char*)buff)[rsize] = '\0';
			if(xp)
			{
				free(xp);
				xp = 0;
			}
			r = hist_expand(buff, &xp);
			if((r & (HIST_EVENT|HIST_PRINT)) && !(r & HIST_ERROR) && xp)
			{
				strlcpy(buff, xp, size);
				rsize = strlen(buff);
				if(!sh_isoption(SH_HISTVERIFY) || readf==ed_read)
				{
					sfputr(sfstderr, xp, -1);
					break;
				}
				reedit = rsize - 1;
				continue;
			}
			if((r & HIST_ERROR) && sh_isoption(SH_HISTREEDIT))
			{
				reedit  = rsize - 1;
				continue;
			}
			if(r & (HIST_ERROR|HIST_PRINT))
			{
				*(char*)buff = '\n';
				rsize = 1;
			}
		}
#endif
		break;
	}
	return(rsize);
}

/*
 * check and return the attributes for a file descriptor
 */

int sh_iocheckfd(Shell_t *shp, register int fd)
{
	register int flags, n;
	if((n=sh.fdstatus[fd])&IOCLOSE)
		return(n);
	if(!(n&(IOREAD|IOWRITE)))
	{
#ifdef F_GETFL
		if((flags=fcntl(fd,F_GETFL,0)) < 0)
			return(sh.fdstatus[fd]=IOCLOSE);
		if((flags&O_ACCMODE)!=O_WRONLY)
			n |= IOREAD;
		if((flags&O_ACCMODE)!=O_RDONLY)
			n |= IOWRITE;
#else
		struct stat statb;
		if((flags = fstat(fd,&statb))< 0)
			return(sh.fdstatus[fd]=IOCLOSE);
		n |= (IOREAD|IOWRITE);
		if(read(fd,"",0) < 0)
			n &= ~IOREAD;
#endif /* F_GETFL */
	}
	if(!(n&(IOSEEK|IONOSEEK)))
	{
		struct stat statb;
		/* /dev/null check is a workaround for select bug */
		static ino_t null_ino;
		static dev_t null_dev;
		if(null_ino==0 && stat(e_devnull,&statb) >=0)
		{
			null_ino = statb.st_ino;
			null_dev = statb.st_dev;
		}
		if(tty_check(fd))
			n |= IOTTY;
		if(lseek(fd,NIL(off_t),SEEK_CUR)<0)
		{
			n |= IONOSEEK;
#ifdef S_ISSOCK
			if((fstat(fd,&statb)>=0) && S_ISSOCK(statb.st_mode))
				n |= IOREAD|IOWRITE;
#endif /* S_ISSOCK */
		}
		else if((fstat(fd,&statb)>=0) && (
			S_ISFIFO(statb.st_mode) ||
#ifdef S_ISSOCK
			S_ISSOCK(statb.st_mode) ||
#endif /* S_ISSOCK */
			/* The following is for sockets on the sgi */
			(statb.st_ino==0 && (statb.st_mode & ~(S_IRUSR|S_IRGRP|S_IROTH|S_IWUSR|S_IWGRP|S_IWOTH|S_IXUSR|S_IXGRP|S_IXOTH|S_ISUID|S_ISGID))==0) ||
			(S_ISCHR(statb.st_mode) && (statb.st_ino!=null_ino || statb.st_dev!=null_dev))
		))
			n |= IONOSEEK;
		else
			n |= IOSEEK;
	}
	sh.fdstatus[fd] = n;
	return(n);
}

/*
 * Display prompt PS<flag> on standard error
 */

static int	io_prompt(Sfio_t *iop,register int flag)
{
	Shell_t	*shp = &sh;
	register char *cp;
	char buff[1];
	char *endprompt;
	static short cmdno;
	int sfflags;
	if(flag<3 && !sh_isstate(SH_INTERACTIVE))
		flag = 0;
	if(flag==2 && sfpkrd(sffileno(iop),buff,1,'\n',0,1) >= 0)
		flag = 0;
	if(flag==0)
		return(sfsync(sfstderr));
	sfflags = sfset(sfstderr,SF_SHARE|SF_PUBLIC|SF_READ,0);
	if(!(sh.prompt=(char*)sfreserve(sfstderr,0,0)))
		sh.prompt = "";
	switch(flag)
	{
		case 1:
		{
			register int c;
#if defined(TIOCLBIC) && defined(LFLUSHO)
			if(!sh_isoption(SH_VI) && !sh_isoption(SH_EMACS) && !sh_isoption(SH_GMACS))
			{
				/*
				 * re-enable output in case the user has
				 * disabled it.  Not needed with edit mode
				 */
				int mode = LFLUSHO;
				ioctl(sffileno(sfstderr),TIOCLBIC,&mode);
			}
#endif	/* TIOCLBIC */
			cp = sh_mactry(shp,nv_getval(sh_scoped(shp,PS1NOD)));
			for(;c= *cp;cp++)
			{
				if(c==HIST_CHAR)
				{
					/* look at next character */
					c = *++cp;
					/* print out line number if not !! */
					if(c!= HIST_CHAR)
					{
						sfprintf(sfstderr,"%d", sh.hist_ptr?(int)sh.hist_ptr->histind:++cmdno);
					}
					if(c==0)
						goto done;
				}
				sfputc(sfstderr,c);
			}
			goto done;
		}
		case 2:
			cp = nv_getval(sh_scoped(shp,PS2NOD));
			break;
		case 3:
			cp = nv_getval(sh_scoped(shp,PS3NOD));
			break;
		default:
			goto done;
	}
	if(cp)
		sfputr(sfstderr,cp,-1);
done:
	if(*sh.prompt && (endprompt=(char*)sfreserve(sfstderr,0,0)))
		*endprompt = 0;
	sfset(sfstderr,sfflags&SF_READ|SF_SHARE|SF_PUBLIC,1);
	return(sfsync(sfstderr));
}

/*
 * This discipline is inserted on write pipes to prevent SIGPIPE
 * from causing an infinite loop
 */
static int pipeexcept(Sfio_t* iop, int mode, void *data, Sfdisc_t* handle)
{
	NOT_USED(iop);
	if(mode==SF_DPOP || mode==SF_FINAL)
		free((void*)handle);
	else if(mode==SF_WRITE && errno==EINTR && sh.lastsig==SIGPIPE)
		return(-1);
	return(0);
}

/*
 * keep track of each stream that is opened and closed
 */
static void	sftrack(Sfio_t* sp, int flag, void* data)
{
	Shell_t *shp = &sh;
	register int fd = sffileno(sp);
	register struct checkpt *pp;
	register int mode;
	int newfd = integralof(data);
	if(flag==SF_SETFD || flag==SF_CLOSING)
	{
		if(newfd<0)
			flag = SF_CLOSING;
		if(fdnotify)
			(*fdnotify)(sffileno(sp),flag==SF_CLOSING?-1:newfd);
	}
#ifdef DEBUG
	if(flag==SF_READ || flag==SF_WRITE)
	{
		char *z = fmtbase((long)getpid(),0,0);
		write(ERRIO,z,strlen(z));
		write(ERRIO,": ",2);
		write(ERRIO,"attempt to ",11);
		if(flag==SF_READ)
			write(ERRIO,"read from",9);
		else
			write(ERRIO,"write to",8);
		write(ERRIO," locked stream\n",15);
		return;
	}
#endif
	if((unsigned)fd >= shp->lim.open_max)
		return;
	if(sh_isstate(SH_NOTRACK))
		return;
	mode = sfset(sp,0,0);
	if(sp==shp->heredocs && fd < 10 && flag==SF_NEW)
	{
		fd = sfsetfd(sp,10);
		fcntl(fd,F_SETFD,FD_CLOEXEC);
	}
	if(fd < 3)
		return;
	if(flag==SF_NEW)
	{
		if(!shp->sftable[fd] && shp->fdstatus[fd]==IOCLOSE)
		{
			shp->sftable[fd] = sp;
			flag = (mode&SF_WRITE)?IOWRITE:0;
			if(mode&SF_READ)
				flag |= IOREAD;
			shp->fdstatus[fd] = flag;
			sh_iostream(shp,fd);
		}
		if((pp=(struct checkpt*)shp->jmplist) && pp->mode==SH_JMPCMD)
		{
			struct openlist *item;
			/*
			 * record open file descriptors so they can
			 * be closed in case a longjmp prevents
			 * built-ins from cleanup
			 */
			item = new_of(struct openlist, 0);
			item->strm = sp;
			item->next = pp->olist;
			pp->olist = item;
		}
		if(fdnotify)
			(*fdnotify)(-1,sffileno(sp));
	}
	else if(flag==SF_CLOSING || (flag==SF_SETFD  && newfd<=2))
	{
		shp->sftable[fd] = 0;
		shp->fdstatus[fd]=IOCLOSE;
		if(pp=(struct checkpt*)shp->jmplist)
		{
			struct openlist *item;
			for(item=pp->olist; item; item=item->next)
			{
				if(item->strm == sp)
				{
					item->strm = 0;
					break;
				}
			}
		}
	}
}

struct eval
{
	Sfdisc_t	disc;
	char		**argv;
	short		slen;
	char		addspace;
};

/*
 * Create a stream consisting of a space separated argv[] list 
 */

Sfio_t *sh_sfeval(register char *argv[])
{
	register Sfio_t *iop;
	register char *cp;
	if(argv[1])
		cp = "";
	else
		cp = argv[0];
	iop = sfopen(NIL(Sfio_t*),(char*)cp,"s");
	if(argv[1])
	{
		register struct eval *ep;
		if(!(ep = new_of(struct eval,0)))
			return(NIL(Sfio_t*));
		ep->disc = eval_disc;
		ep->argv = argv;
		ep->slen  = -1;
		ep->addspace  = 0;
		sfdisc(iop,&ep->disc);
	}
	return(iop);
}

/*
 * This code gets called whenever an end of string is found with eval
 */

static int eval_exceptf(Sfio_t *iop,int type, void *data, Sfdisc_t *handle)
{
	register struct eval *ep = (struct eval*)handle;
	register char	*cp;
	register int	len;

	/* no more to do */
	if(type!=SF_READ || !(cp = ep->argv[0]))
	{
		if(type==SF_CLOSING)
			sfdisc(iop,SF_POPDISC);
		else if(ep && (type==SF_DPOP || type==SF_FINAL))
			free((void*)ep);
		return(0);
	}

	if(!ep->addspace)
	{
		/* get the length of this string */
		ep->slen = len = strlen(cp);
		/* move to next string */
		ep->argv++;
	}
	else /* insert space between arguments */
	{
		len = 1;
		cp = " ";
	}
	/* insert the new string */
	sfsetbuf(iop,cp,len);
	ep->addspace = !ep->addspace;
	return(1);
}

/*
 * This routine returns a stream pointer to a segment of length <size> from
 * the stream <sp> starting at offset <offset>
 * The stream can be read with the normal stream operations
 */

static Sfio_t *subopen(Shell_t *shp,Sfio_t* sp, off_t offset, long size)
{
	register struct subfile *disp;
	if(sfseek(sp,offset,SEEK_SET) <0)
		return(NIL(Sfio_t*));
	if(!(disp = (struct subfile*)malloc(sizeof(struct subfile)+IOBSIZE+1)))
		return(NIL(Sfio_t*));
	disp->disc = sub_disc;
	disp->oldsp = sp;
	disp->offset = offset;
	disp->size = disp->left = size;
	sp = sfnew(NIL(Sfio_t*),(char*)(disp+1),IOBSIZE,shp->lim.open_max,SF_READ);
	sfdisc(sp,&disp->disc);
	return(sp);
}

/*
 * read function for subfile discipline
 */
static ssize_t subread(Sfio_t* sp,void* buff,register size_t size,Sfdisc_t* handle)
{
	register struct subfile *disp = (struct subfile*)handle;
	NOT_USED(sp);
	if(disp->left == 0)
		return(0);
	if(size > disp->left)
		size = disp->left;
	disp->left -= size;
	return(sfread(disp->oldsp,buff,size));
}

/*
 * exception handler for subfile discipline
 */
static int subexcept(Sfio_t* sp,register int mode, void *data, Sfdisc_t* handle)
{
	register struct subfile *disp = (struct subfile*)handle;
	if(mode==SF_CLOSING)
	{
		sfdisc(sp,SF_POPDISC);
		return(0);
	}
	else if(disp && (mode==SF_DPOP || mode==SF_FINAL))
	{
		free((void*)disp);
		return(0);
	}
#ifdef SF_ATEXIT
	else if (mode==SF_ATEXIT)
	{
		sfdisc(sp, SF_POPDISC);
		return(0);
	}
#endif
	else if(mode==SF_READ)
		return(0);
	return(-1);
}

#define NROW    15      /* number of rows before going to multi-columns */
#define LBLSIZ	3	/* size of label field and interfield spacing */
/* 
 * print a list of arguments in columns
 */
void	sh_menu(Sfio_t *outfile,int argn,char *argv[])
{
	Shell_t *shp = &sh;
	register int i,j;
	register char **arg;
	int nrow, ncol=1, ndigits=1;
	int fldsize, wsize = ed_window();
	char *cp = nv_getval(sh_scoped(shp,LINES));
	nrow = (cp?1+2*((int)strtol(cp, (char**)0, 10)/3):NROW);
	for(i=argn;i >= 10;i /= 10)
		ndigits++;
	if(argn < nrow)
	{
		nrow = argn;
		goto skip;
	}
	i = 0;
	for(arg=argv; *arg;arg++)
	{
		if((j=strlen(*arg)) > i)
			i = j;
	}
	i += (ndigits+LBLSIZ);
	if(i < wsize)
		ncol = wsize/i;
	if(argn > nrow*ncol)
	{
		nrow = 1 + (argn-1)/ncol;
	}
	else
	{
		ncol = 1 + (argn-1)/nrow;
		nrow = 1 + (argn-1)/ncol;
	}
skip:
	fldsize = (wsize/ncol)-(ndigits+LBLSIZ);
	for(i=0;i<nrow;i++)
	{
		if(sh.trapnote&SH_SIGSET)
			return;
		j = i;
		while(1)
		{
			arg = argv+j;
			sfprintf(outfile,"%*d) %s",ndigits,j+1,*arg);
			j += nrow;
			if(j >= argn)
				break;
			sfnputc(outfile,' ',fldsize-strlen(*arg));
		}
		sfputc(outfile,'\n');
	}
}

#undef read
/*
 * shell version of read() for user added builtins
 */
ssize_t sh_read(register int fd, void* buff, size_t n) 
{
	register Sfio_t *sp;
	if(sp=sh.sftable[fd])
		return(sfread(sp,buff,n));
	else
		return(read(fd,buff,n));
}

#undef write
/*
 * shell version of write() for user added builtins
 */
ssize_t sh_write(register int fd, const void* buff, size_t n) 
{
	register Sfio_t *sp;
	if(sp=sh.sftable[fd])
		return(sfwrite(sp,buff,n));
	else
		return(write(fd,buff,n));
}

#undef lseek
/*
 * shell version of lseek() for user added builtins
 */
off_t sh_seek(register int fd, off_t offset, int whence)
{
	register Sfio_t *sp;
	if((sp=sh.sftable[fd]) && (sfset(sp,0,0)&(SF_READ|SF_WRITE)))
		return(sfseek(sp,offset,whence));
	else
		return(lseek(fd,offset,whence));
}

#undef dup
int sh_dup(register int old)
{
	register int fd = dup(old);
	if(fd>=0)
	{
		if(sh.fdstatus[old] == IOCLOSE)
			sh.fdstatus[old] = 0;
		sh.fdstatus[fd] = (sh.fdstatus[old]&~IOCLEX);
		if(fdnotify)
			(*fdnotify)(old,fd);
	}
	return(fd);
}

#undef fcntl
int sh_fcntl(register int fd, int op, ...)
{
	int newfd, arg;
	va_list		ap;
	va_start(ap, op);
	arg =  va_arg(ap, int) ;
	va_end(ap);
	newfd = fcntl(fd,op,arg);
	if(newfd>=0) switch(op)
	{
	    case F_DUPFD:
		if(sh.fdstatus[fd] == IOCLOSE)
			sh.fdstatus[fd] = 0;
		sh.fdstatus[newfd] = (sh.fdstatus[fd]&~IOCLEX);
		if(fdnotify)
			(*fdnotify)(fd,newfd);
		break;
	    case F_SETFD:
		if(sh.fdstatus[fd] == IOCLOSE)
			sh.fdstatus[fd] = 0;
		if(arg&FD_CLOEXEC)
			sh.fdstatus[fd] |= IOCLEX;
		else
			sh.fdstatus[fd] &= ~IOCLEX;
	}
	return(newfd);
}

#undef umask
mode_t	sh_umask(mode_t m)
{
	sh.mask = m;
	return(umask(m));
}

/*
 * give file descriptor <fd> and <mode>, return an iostream pointer
 * <mode> must be SF_READ or SF_WRITE
 * <fd> must be a non-negative number ofr SH_IOCOPROCESS or SH_IOHISTFILE. 
 * returns NULL on failure and may set errno.
 */

Sfio_t *sh_iogetiop(int fd, int mode)
{
	Shell_t	*shp = &sh;
	int n;
	Sfio_t *iop=0;
	if(mode!=SF_READ && mode!=SF_WRITE)
	{
		errno = EINVAL;
		return(iop);
	}
	switch(fd)
	{
	    case SH_IOHISTFILE:
		if(!sh_histinit((void*)shp))
			return(iop);
		fd = sffileno(shp->hist_ptr->histfp);
		break;
	    case SH_IOCOPROCESS:
		if(mode==SF_WRITE)
			fd = shp->coutpipe;
		else
			fd = shp->cpipe[0];
		break;
	    default:
		if(fd<0 || fd >= shp->lim.open_max)
			fd = -1;
	}
	if(fd<0)
	{
		errno = EBADF;
		return(iop);
	}
	if(!(n=shp->fdstatus[fd]))
		n = sh_iocheckfd(shp,fd);
	if(mode==SF_WRITE && !(n&IOWRITE))
		return(iop);
	if(mode==SF_READ && !(n&IOREAD))
		return(iop);
	if(!(iop = shp->sftable[fd]))
		iop=sh_iostream(shp,fd);
	return(iop);
}

typedef int (*Notify_f)(int,int);

Notify_f    sh_fdnotify(Notify_f notify)
{
	Notify_f old;
        old = fdnotify;
        fdnotify = notify;
        return(old);
}

Sfio_t	*sh_fd2sfio(int fd)
{
	Shell_t	*shp = &sh;
	register int status;
	Sfio_t *sp = sh.sftable[fd];
	if(!sp  && (status = sh_iocheckfd(shp,fd))!=IOCLOSE)
	{
		register int flags=0;
		if(status&IOREAD)
			flags |= SF_READ;
		if(status&IOWRITE)
			flags |= SF_WRITE;
		sp = sfnew(NULL, NULL, -1, fd,flags);
		sh.sftable[fd] = sp;
	}
	return(sp);
}

Sfio_t *sh_pathopen(const char *cp)
{
	Shell_t *shp = &sh;
	int n;
#ifdef PATH_BFPATH
	if((n=path_open(cp,path_get(cp))) < 0)
		n = path_open(cp,(Pathcomp_t*)0);
#else
	if((n=path_open(cp,path_get(cp))) < 0)
		n = path_open(cp,"");
#endif
	if(n < 0)
		errormsg(SH_DICT,ERROR_system(1),e_open,cp);
	return(sh_iostream(shp,n));
}
