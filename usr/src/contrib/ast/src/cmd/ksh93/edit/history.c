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
 *   History file manipulation routines
 *
 *   David Korn
 *   AT&T Labs
 *
 */

/*
 * Each command in the history file starts on an even byte is null terminated.
 * The first byte must contain the special character HIST_UNDO and the second
 * byte is the version number.  The sequence HIST_UNDO 0, following a command,
 * nullifies the previous command. A six byte sequence starting with
 * HIST_CMDNO is used to store the command number so that it is not necessary
 * to read the file from beginning to end to get to the last block of
 * commands.  This format of this sequence is different in version 1
 * then in version 0.  Version 1 allows commands to use the full 8 bit
 * character set.  It can understand version 0 format files.
 */


#define HIST_MAX	(sizeof(int)*HIST_BSIZE)
#define HIST_BIG	(0100000-1024)	/* 1K less than maximum short */
#define HIST_LINE	32		/* typical length for history line */
#define HIST_MARKSZ	6
#define HIST_RECENT	600
#define HIST_UNDO	0201		/* invalidate previous command */
#define HIST_CMDNO	0202		/* next 3 bytes give command number */
#define HIST_BSIZE	4096		/* size of history file buffer */
#define HIST_DFLT	512		/* default size of history list */

#if SHOPT_AUDIT
#   define _HIST_AUDIT	Sfio_t	*auditfp; \
			char	*tty; \
			int	auditmask; 
#else
#   define _HIST_AUDIT 
#endif

#define _HIST_PRIVATE \
	void	*histshell; \
	off_t	histcnt;	/* offset into history file */\
	off_t	histmarker;	/* offset of last command marker */ \
	int	histflush;	/* set if flushed outside of hflush() */\
	int	histmask;	/* power of two mask for histcnt */ \
	char	histbuff[HIST_BSIZE+1];	/* history file buffer */ \
	int	histwfail; \
	_HIST_AUDIT \
	off_t	histcmds[2];	/* offset for recent commands, must be last */

#define hist_ind(hp,c)	((int)((c)&(hp)->histmask))

#include	<ast.h>
#include	<sfio.h>
#include	"FEATURE/time"
#include	<error.h>
#include	<ls.h>
#if KSHELL
#   include	"defs.h"
#   include	"variables.h"
#   include	"path.h"
#   include	"builtins.h"
#   include	"io.h"
#else
#   include	<ctype.h>
#endif	/* KSHELL */
#include	"history.h"

#if !KSHELL
#   define new_of(type,x)	((type*)malloc((unsigned)sizeof(type)+(x)))
#   define NIL(type)		((type)0)
#   define path_relative(s,x)	(s,x)
#   ifdef __STDC__
#	define nv_getval(s)	getenv(#s)
#   else
#	define nv_getval(s)	getenv("s")
#   endif /* __STDC__ */
#   define e_unknown	 	"unknown"
#   define sh_translate(x)	(x)
    char login_sh =		0;
    char hist_fname[] =		"/.history";
#endif	/* KSHELL */

#ifndef O_BINARY
#   define O_BINARY	0
#endif /* O_BINARY */

int	_Hist = 0;
static void	hist_marker(char*,long);
static History_t* hist_trim(History_t*, int);
static int	hist_nearend(History_t*,Sfio_t*, off_t);
static int	hist_check(int);
static int	hist_clean(int);
#ifdef SF_BUFCONST
    static ssize_t  hist_write(Sfio_t*, const void*, size_t, Sfdisc_t*);
    static int      hist_exceptf(Sfio_t*, int, void*, Sfdisc_t*);
#else
    static int	hist_write(Sfio_t*, const void*, int, Sfdisc_t*);
    static int	hist_exceptf(Sfio_t*, int, Sfdisc_t*);
#endif


static int	histinit;
static mode_t	histmode;
static History_t *wasopen;
static History_t *hist_ptr;

#if SHOPT_ACCTFILE
    static int	acctfd;
    static char *logname;
#   include <pwd.h>
    
    static int  acctinit(History_t *hp)
    {
	register char *cp, *acctfile;
	Namval_t *np = nv_search("ACCTFILE",((Shell_t*)hp->histshell)->var_tree,0);

	if(!np || !(acctfile=nv_getval(np)))
		return(0);
	if(!(cp = getlogin()))
	{
		struct passwd *userinfo = getpwuid(getuid());
		if(userinfo)
			cp = userinfo->pw_name;
		else
			cp = "unknown";
	}
	logname = strdup(cp);
	if((acctfd=sh_open(acctfile,
		O_BINARY|O_WRONLY|O_APPEND|O_CREAT,S_IRUSR|S_IWUSR))>=0 &&
	    (unsigned)acctfd < 10)
	{
		int n;
		if((n = fcntl(acctfd, F_DUPFD, 10)) >= 0)
		{
			close(acctfd);
			acctfd = n;
		}
	}
	if(acctfd < 0)
	{
		acctfd = 0;
		return(0);
	}
	if(sh_isdevfd(acctfile))
	{
		char newfile[16];
		sfsprintf(newfile,sizeof(newfile),"%.8s%d\0",e_devfdNN,acctfd);
		nv_putval(np,newfile,NV_RDONLY);
	}
	else
		fcntl(acctfd,F_SETFD,FD_CLOEXEC);
	return(1);
    }
#endif /* SHOPT_ACCTFILE */

#if SHOPT_AUDIT
static int sh_checkaudit(History_t *hp, const char *name, char *logbuf, size_t len)
{
	char	*cp, *last;
	int	id1, id2, r=0, n, fd;
	if((fd=open(name, O_RDONLY)) < 0)
		return(0);
	if((n = read(fd, logbuf,len-1)) < 0)
		goto done;
	while(logbuf[n-1]=='\n')
		n--;
	logbuf[n] = 0;
	if(!(cp=strchr(logbuf,';')) && !(cp=strchr(logbuf,' ')))
		goto done;
	*cp = 0;
	do
	{
		cp++;
		id1 = id2 = strtol(cp,&last,10);
		if(*last=='-')
			id1 = strtol(last+1,&last,10);
		if(shgd->euserid >=id1 && shgd->euserid <= id2)
			r |= 1;
		if(shgd->userid >=id1 && shgd->userid <= id2)
			r |= 2;
		cp = last;
	}
	while(*cp==';' ||  *cp==' ');
done:
	close(fd);
	return(r);
	
}
#endif /*SHOPT_AUDIT*/

static const unsigned char hist_stamp[2] = { HIST_UNDO, HIST_VERSION };
static const Sfdisc_t hist_disc = { NULL, hist_write, NULL, hist_exceptf, NULL};

static void hist_touch(void *handle)
{
	touch((char*)handle, (time_t)0, (time_t)0, 0);
}

/*
 * open the history file
 * if HISTNAME is not given and userid==0 then no history file.
 * if login_sh and HISTFILE is longer than HIST_MAX bytes then it is
 * cleaned up.
 * hist_open() returns 1, if history file is open
 */
int  sh_histinit(void *sh_context)
{
	Shell_t *shp = (Shell_t*)sh_context;
	register int fd;
	register History_t *hp;
	register char *histname;
	char *fname=0;
	int histmask, maxlines, hist_start=0;
	register char *cp;
	register off_t hsize = 0;

	if(shgd->hist_ptr=hist_ptr)
		return(1);
	if(!(histname = nv_getval(HISTFILE)))
	{
		int offset = staktell();
		if(cp=nv_getval(HOME))
			stakputs(cp);
		stakputs(hist_fname);
		stakputc(0);
		stakseek(offset);
		histname = stakptr(offset);
	}
#ifdef future
	if(hp=wasopen)
	{
		/* reuse history file if same name */
		wasopen = 0;
		shgd->hist_ptr = hist_ptr = hp;
		if(strcmp(histname,hp->histname)==0)
			return(1);
		else
			hist_free();
	}
#endif
retry:
	cp = path_relative(shp,histname);
	if(!histinit)
		histmode = S_IRUSR|S_IWUSR;
	if((fd=open(cp,O_BINARY|O_APPEND|O_RDWR|O_CREAT,histmode))>=0)
	{
		hsize=lseek(fd,(off_t)0,SEEK_END);
	}
	if((unsigned)fd <=2)
	{
		int n;
		if((n=fcntl(fd,F_DUPFD,10))>=0)
		{
			close(fd);
			fd=n;
		}
	}
	/* make sure that file has history file format */
	if(hsize && hist_check(fd))
	{
		close(fd);
		hsize = 0;
		if(unlink(cp)>=0)
			goto retry;
		fd = -1;
	}
	if(fd < 0)
	{
#if KSHELL
		/* don't allow root a history_file in /tmp */
		if(shgd->userid)
#endif	/* KSHELL */
		{
			if(!(fname = pathtmp(NIL(char*),0,0,NIL(int*))))
				return(0);
			fd = open(fname,O_BINARY|O_APPEND|O_CREAT|O_RDWR,S_IRUSR|S_IWUSR);
		}
	}
	if(fd<0)
		return(0);
	/* set the file to close-on-exec */
	fcntl(fd,F_SETFD,FD_CLOEXEC);
	if(cp=nv_getval(HISTSIZE))
		maxlines = (unsigned)strtol(cp, (char**)0, 10);
	else
		maxlines = HIST_DFLT;
	for(histmask=16;histmask <= maxlines; histmask <<=1 );
	if(!(hp=new_of(History_t,(--histmask)*sizeof(off_t))))
	{
		close(fd);
		return(0);
	}
	shgd->hist_ptr = hist_ptr = hp;
	hp->histshell = (void*)shp;
	hp->histsize = maxlines;
	hp->histmask = histmask;
	hp->histfp= sfnew(NIL(Sfio_t*),hp->histbuff,HIST_BSIZE,fd,SF_READ|SF_WRITE|SF_APPENDWR|SF_SHARE);
	memset((char*)hp->histcmds,0,sizeof(off_t)*(hp->histmask+1));
	hp->histind = 1;
	hp->histcmds[1] = 2;
	hp->histcnt = 2;
	hp->histname = strdup(histname);
	hp->histdisc = hist_disc;
	if(hsize==0)
	{
		/* put special characters at front of file */
		sfwrite(hp->histfp,(char*)hist_stamp,2);
		sfsync(hp->histfp);
	}
	/* initialize history list */
	else
	{
		int first,last;
		off_t mark,size = (HIST_MAX/4)+maxlines*HIST_LINE;
		hp->histind = first = hist_nearend(hp,hp->histfp,hsize-size);
		histinit = 1;
		hist_eof(hp);	 /* this sets histind to last command */
		if((hist_start = (last=(int)hp->histind)-maxlines) <=0)
			hist_start = 1;
		mark = hp->histmarker;
		while(first > hist_start)
		{
			size += size;
			first = hist_nearend(hp,hp->histfp,hsize-size);
			hp->histind = first;
		}
		histinit = hist_start;
		hist_eof(hp);
		if(!histinit)
		{
			sfseek(hp->histfp,hp->histcnt=hsize,SEEK_SET);
			hp->histind = last;
			hp->histmarker = mark;
		}
		histinit = 0;
	}
	if(fname)
	{
		unlink(fname);
		free((void*)fname);
	}
	if(hist_clean(fd) && hist_start>1 && hsize > HIST_MAX)
	{
#ifdef DEBUG
		sfprintf(sfstderr,"%d: hist_trim hsize=%d\n",getpid(),hsize);
		sfsync(sfstderr);
#endif /* DEBUG */
		hp = hist_trim(hp,(int)hp->histind-maxlines);
	}
	sfdisc(hp->histfp,&hp->histdisc);
#if KSHELL
	(HISTCUR)->nvalue.lp = (&hp->histind);
#endif /* KSHELL */
	sh_timeradd(1000L*(HIST_RECENT-30), 1, hist_touch, (void*)hp->histname);
#if SHOPT_ACCTFILE
	if(sh_isstate(SH_INTERACTIVE))
		acctinit(hp);
#endif /* SHOPT_ACCTFILE */
#if SHOPT_AUDIT
	{
		char buff[SF_BUFSIZE];
		hp->auditfp = 0;
		if(sh_isstate(SH_INTERACTIVE) && (hp->auditmask=sh_checkaudit(hp,SHOPT_AUDITFILE, buff, sizeof(buff))))
		{
			if((fd=sh_open(buff,O_BINARY|O_WRONLY|O_APPEND|O_CREAT,S_IRUSR|S_IWUSR))>=0 && fd < 10)
			{
				int n;
				if((n = sh_fcntl(fd,F_DUPFD, 10)) >= 0)
				{
					sh_close(fd);
					fd = n;
				}
			}
			if(fd>=0)
			{
				fcntl(fd,F_SETFD,FD_CLOEXEC);
				hp->tty = strdup(ttyname(2));
				hp->auditfp = sfnew((Sfio_t*)0,NULL,-1,fd,SF_WRITE);
			}
		}
	}
#endif
	return(1);
}

/*
 * close the history file and free the space
 */

void hist_close(register History_t *hp)
{
	sfclose(hp->histfp);
#if SHOPT_AUDIT
	if(hp->auditfp)
	{
		if(hp->tty)
			free((void*)hp->tty);
		sfclose(hp->auditfp);
	}
#endif /* SHOPT_AUDIT */
	free((char*)hp);
	hist_ptr = 0;
	shgd->hist_ptr = 0;
#if SHOPT_ACCTFILE
	if(acctfd)
	{
		close(acctfd);
		acctfd = 0;
	}
#endif /* SHOPT_ACCTFILE */
}

/*
 * check history file format to see if it begins with special byte
 */
static int hist_check(register int fd)
{
	unsigned char magic[2];
	lseek(fd,(off_t)0,SEEK_SET);
	if((read(fd,(char*)magic,2)!=2) || (magic[0]!=HIST_UNDO))
		return(1);
	return(0);
}

/*
 * clean out history file OK if not modified in HIST_RECENT seconds
 */
static int hist_clean(int fd)
{
	struct stat statb;
	return(fstat(fd,&statb)>=0 && (time((time_t*)0)-statb.st_mtime) >= HIST_RECENT);
}

/*
 * Copy the last <n> commands to a new file and make this the history file
 */

static History_t* hist_trim(History_t *hp, int n)
{
	register char *cp;
	register int incmd=1, c=0;
	register History_t *hist_new, *hist_old = hp;
	char *buff, *endbuff, *tmpname=0;
	off_t oldp,newp;
	struct stat statb;
	unlink(hist_old->histname);
	if(access(hist_old->histname,F_OK) >= 0)
	{
		/* The unlink can fail on windows 95 */
		int fd;
		char *last, *name=hist_old->histname;
		close(sffileno(hist_old->histfp));
		tmpname = (char*)malloc(strlen(name)+14);
		if(last = strrchr(name,'/'))
		{
			*last = 0;
			pathtmp(tmpname,name,"hist",NIL(int*));
			*last = '/';
		}
		else
			pathtmp(tmpname,".","hist",NIL(int*));
		if(rename(name,tmpname) < 0)
		{
			free(tmpname);
			tmpname = name;
		}
		fd = open(tmpname,O_RDONLY);
		sfsetfd(hist_old->histfp,fd);
		if(tmpname==name)
			tmpname = 0;
	}
	hist_ptr = 0;
	if(fstat(sffileno(hist_old->histfp),&statb)>=0)
	{
		histinit = 1;
		histmode =  statb.st_mode;
	}
	if(!sh_histinit(hp->histshell))
	{
		/* use the old history file */
		return hist_ptr = hist_old;
	}
	hist_new = hist_ptr;
	hist_ptr = hist_old;
	if(--n < 0)
		n = 0;
	newp = hist_seek(hist_old,++n);
	while(1)
	{
		if(!incmd)
		{
			c = hist_ind(hist_new,++hist_new->histind);
			hist_new->histcmds[c] = hist_new->histcnt;
			if(hist_new->histcnt > hist_new->histmarker+HIST_BSIZE/2)
			{
				char locbuff[HIST_MARKSZ];
				hist_marker(locbuff,hist_new->histind);
				sfwrite(hist_new->histfp,locbuff,HIST_MARKSZ);
				hist_new->histcnt += HIST_MARKSZ;
				hist_new->histmarker = hist_new->histcmds[hist_ind(hist_new,c)] = hist_new->histcnt;
			}
			oldp = newp;
			newp = hist_seek(hist_old,++n);
			if(newp <=oldp)
				break;
		}
		if(!(buff=(char*)sfreserve(hist_old->histfp,SF_UNBOUND,0)))
			break;
		*(endbuff=(cp=buff)+sfvalue(hist_old->histfp)) = 0;
		/* copy to null byte */
		incmd = 0;
		while(*cp++);
		if(cp > endbuff)
			incmd = 1;
		else if(*cp==0)
			cp++;
		if(cp > endbuff)
			cp = endbuff;
		c = cp-buff;
		hist_new->histcnt += c;
		sfwrite(hist_new->histfp,buff,c);
	}
	hist_cancel(hist_new);
	sfclose(hist_old->histfp);
	if(tmpname)
	{
		unlink(tmpname);
		free(tmpname);
	}
	free((char*)hist_old);
	return hist_ptr = hist_new;
}

/*
 * position history file at size and find next command number 
 */
static int hist_nearend(History_t *hp, Sfio_t *iop, register off_t size)
{
        register unsigned char *cp, *endbuff;
        register int n, incmd=1;
        unsigned char *buff, marker[4];
	if(size <= 2L || sfseek(iop,size,SEEK_SET)<0)
		goto begin;
	/* skip to marker command and return the number */
	/* numbering commands occur after a null and begin with HIST_CMDNO */
        while(cp=buff=(unsigned char*)sfreserve(iop,SF_UNBOUND,SF_LOCKR))
        {
		n = sfvalue(iop);
                *(endbuff=cp+n) = 0;
                while(1)
                {
			/* check for marker */
                        if(!incmd && *cp++==HIST_CMDNO && *cp==0)
                        {
                                n = cp+1 - buff;
                                incmd = -1;
                                break;
                        }
                        incmd = 0;
                        while(*cp++);
                        if(cp>endbuff)
                        {
                                incmd = 1;
                                break;
                        }
                        if(*cp==0 && ++cp>endbuff)
                                break;
                }
                size += n;
		sfread(iop,(char*)buff,n);
		if(incmd < 0)
                {
			if((n=sfread(iop,(char*)marker,4))==4)
			{
				n = (marker[0]<<16)|(marker[1]<<8)|marker[2];
				if(n < size/2)
				{
					hp->histmarker = hp->histcnt = size+4;
					return(n);
				}
				n=4;
			}
			if(n >0)
				size += n;
			incmd = 0;
		}
	}
begin:
	sfseek(iop,(off_t)2,SEEK_SET);
	hp->histmarker = hp->histcnt = 2L;
	return(1);
}

/*
 * This routine reads the history file from the present position
 * to the end-of-file and puts the information in the in-core
 * history table
 * Note that HIST_CMDNO is only recognized at the beginning of a command
 * and that HIST_UNDO as the first character of a command is skipped
 * unless it is followed by 0.  If followed by 0 then it cancels
 * the previous command.
 */

void hist_eof(register History_t *hp)
{
	register char *cp,*first,*endbuff;
	register int incmd = 0;
	register off_t count = hp->histcnt;
	int oldind,n,skip=0;
	off_t last = sfseek(hp->histfp,(off_t)0,SEEK_END);
	if(last < count)
	{
		last = -1;
		count = 2+HIST_MARKSZ;
		oldind = hp->histind;
		if((hp->histind -= hp->histsize) < 0)
			hp->histind = 1;
	}
again:
	sfseek(hp->histfp,count,SEEK_SET);
        while(cp=(char*)sfreserve(hp->histfp,SF_UNBOUND,0))
	{
		n = sfvalue(hp->histfp);
		*(endbuff = cp+n) = 0;
		first = cp += skip;
		while(1)
		{
			while(!incmd)
			{
				if(cp>first)
				{
					count += (cp-first);
					n = hist_ind(hp, ++hp->histind);
#ifdef future
					if(count==hp->histcmds[n])
					{
	sfprintf(sfstderr,"count match n=%d\n",n);
						if(histinit)
						{
							histinit = 0;
							return;
						}
					}
					else if(n>=histinit)
#endif
						hp->histcmds[n] = count;
					first = cp;
				}
				switch(*((unsigned char*)(cp++)))
				{
					case HIST_CMDNO:
						if(*cp==0)
						{
							hp->histmarker=count+2;
							cp += (HIST_MARKSZ-1);
							hp->histind--;
							if(!histinit && (cp <= endbuff))
							{
								unsigned char *marker = (unsigned char*)(cp-4);
								hp->histind = ((marker[0]<<16)|(marker[1]<<8)|marker[2] -1);
							}
						}
						break;
					case HIST_UNDO:
						if(*cp==0)
						{
							cp+=1;
							hp->histind-=2;
						}
						break;
					default:
						cp--;
						incmd = 1;
				}
				if(cp > endbuff)
				{
					cp++;
					goto refill;
				}
			}
			first = cp;
			while(*cp++);
			if(cp > endbuff)
				break;
			incmd = 0;
			while(*cp==0)
			{
				if(++cp > endbuff)
					goto refill;
			}
		}
	refill:
		count += (--cp-first);
		skip = (cp-endbuff);
		if(!incmd && !skip)
			hp->histcmds[hist_ind(hp,++hp->histind)] = count;
	}
	hp->histcnt = count;
	if(incmd && last)
	{
		sfputc(hp->histfp,0);
		hist_cancel(hp);
		count = 2;
		skip = 0;
		oldind -= hp->histind;
		hp->histind = hp->histind-hp->histsize + oldind +2;
		if(hp->histind<0)
			hp->histind = 1;
		if(last<0)
		{
			char	buff[HIST_MARKSZ];
			int	fd = open(hp->histname,O_RDWR);
			if(fd>=0)
			{
				hist_marker(buff,hp->histind);
				write(fd,(char*)hist_stamp,2);
				write(fd,buff,HIST_MARKSZ);
				close(fd);
			}
		}
		last = 0;
		goto again;
	}
}

/*
 * This routine will cause the previous command to be cancelled
 */

void hist_cancel(register History_t *hp)
{
	register int c;
	if(!hp)
		return;
	sfputc(hp->histfp,HIST_UNDO);
	sfputc(hp->histfp,0);
	sfsync(hp->histfp);
	hp->histcnt += 2;
	c = hist_ind(hp,--hp->histind);
	hp->histcmds[c] = hp->histcnt;
}

/*
 * flush the current history command
 */

void hist_flush(register History_t *hp)
{
	register char *buff;
	if(hp)
	{
		if(buff=(char*)sfreserve(hp->histfp,0,SF_LOCKR))
		{
			hp->histflush = sfvalue(hp->histfp)+1;
			sfwrite(hp->histfp,buff,0);
		}
		else
			hp->histflush=0;
		if(sfsync(hp->histfp)<0)
		{
			hist_close(hp);
			if(!sh_histinit(hp->histshell))
				sh_offoption(SH_HISTORY);
		}
		hp->histflush = 0;
	}
}

/*
 * This is the write discipline for the history file
 * When called from hist_flush(), trailing newlines are deleted and
 * a zero byte.  Line sequencing is added as required
 */

#ifdef SF_BUFCONST
static ssize_t hist_write(Sfio_t *iop,const void *buff,register size_t insize,Sfdisc_t* handle)
#else
static int hist_write(Sfio_t *iop,const void *buff,register int insize,Sfdisc_t* handle)
#endif
{
	register History_t *hp = (History_t*)handle;
	register char *bufptr = ((char*)buff)+insize;
	register int c,size = insize;
	register off_t cur;
	int saved=0;
	char saveptr[HIST_MARKSZ];
	if(!hp->histflush)
		return(write(sffileno(iop),(char*)buff,size));
	if((cur = lseek(sffileno(iop),(off_t)0,SEEK_END)) <0)
	{
		errormsg(SH_DICT,2,"hist_flush: EOF seek failed errno=%d",errno);
		return(-1);
	}
	hp->histcnt = cur;
	/* remove whitespace from end of commands */
	while(--bufptr >= (char*)buff)
	{
		c= *bufptr;
		if(!isspace(c))
		{
			if(c=='\\' && *(bufptr+1)!='\n')
				bufptr++;
			break;
		}
	}
	/* don't count empty lines */
	if(++bufptr <= (char*)buff)
		return(insize);
	*bufptr++ = '\n';
	*bufptr++ = 0;
	size = bufptr - (char*)buff;
#if	 SHOPT_AUDIT
	if(hp->auditfp)
	{
		time_t	t=time((time_t*)0);
		sfprintf(hp->auditfp,"%u;%u;%s;%*s%c",sh_isoption(SH_PRIVILEGED)?shgd->euserid:shgd->userid,t,hp->tty,size,buff,0);
		sfsync(hp->auditfp);
	}
#endif	/* SHOPT_AUDIT */
#if	SHOPT_ACCTFILE
	if(acctfd)
	{
		int timechars, offset;
		offset = staktell();
		stakputs(buff);
		stakseek(staktell() - 1);
		timechars = sfprintf(staksp, "\t%s\t%x\n",logname,time(NIL(long *)));
		lseek(acctfd, (off_t)0, SEEK_END);
		write(acctfd, stakptr(offset), size - 2 + timechars);
		stakseek(offset);

	}
#endif /* SHOPT_ACCTFILE */
	if(size&01)
	{
		size++;
		*bufptr++ = 0;
	}
	hp->histcnt +=  size;
	c = hist_ind(hp,++hp->histind);
	hp->histcmds[c] = hp->histcnt;
	if(hp->histflush>HIST_MARKSZ && hp->histcnt > hp->histmarker+HIST_BSIZE/2)
	{
		memcpy((void*)saveptr,(void*)bufptr,HIST_MARKSZ);
		saved=1;
		hp->histcnt += HIST_MARKSZ;
		hist_marker(bufptr,hp->histind);
		hp->histmarker = hp->histcmds[hist_ind(hp,c)] = hp->histcnt;
		size += HIST_MARKSZ;
	}
	errno = 0;
	size = write(sffileno(iop),(char*)buff,size);
	if(saved)
		memcpy((void*)bufptr,(void*)saveptr,HIST_MARKSZ);
	if(size>=0)
	{
		hp->histwfail = 0;
		return(insize);
	}
	return(-1);
}

/*
 * Put history sequence number <n> into buffer <buff>
 * The buffer must be large enough to hold HIST_MARKSZ chars
 */

static void hist_marker(register char *buff,register long cmdno)
{
	*buff++ = HIST_CMDNO;
	*buff++ = 0;
	*buff++ = (cmdno>>16);
	*buff++ = (cmdno>>8);
	*buff++ = cmdno;
	*buff++ = 0;
}

/*
 * return byte offset in history file for command <n>
 */
off_t hist_tell(register History_t *hp, int n)
{
	return(hp->histcmds[hist_ind(hp,n)]);
}

/*
 * seek to the position of command <n>
 */
off_t hist_seek(register History_t *hp, int n)
{
	return(sfseek(hp->histfp,hp->histcmds[hist_ind(hp,n)],SEEK_SET));
}

/*
 * write the command starting at offset <offset> onto file <outfile>.
 * if character <last> appears before newline it is deleted
 * each new-line character is replaced with string <nl>.
 */

void hist_list(register History_t *hp,Sfio_t *outfile, off_t offset,int last, char *nl)
{
	register int oldc=0;
	register int c;
	if(offset<0 || !hp)
	{
		sfputr(outfile,sh_translate(e_unknown),'\n');
		return;
	}
	sfseek(hp->histfp,offset,SEEK_SET);
	while((c = sfgetc(hp->histfp)) != EOF)
	{
		if(c && oldc=='\n')
			sfputr(outfile,nl,-1);
		else if(last && (c==0 || (c=='\n' && oldc==last)))
			return;
		else if(oldc)
			sfputc(outfile,oldc);
		oldc = c;
		if(c==0)
			return;
	}
	return;
}
		 
/*
 * find index for last line with given string
 * If flag==0 then line must begin with string
 * direction < 1 for backwards search
*/

Histloc_t hist_find(register History_t*hp,char *string,register int index1,int flag,int direction)
{
	register int index2;
	off_t offset;
	int *coffset=0;
	Histloc_t location;
	location.hist_command = -1;
	location.hist_char = 0;
	location.hist_line = 0;
	if(!hp)
		return(location);
	/* leading ^ means beginning of line unless escaped */
	if(flag)
	{
		index2 = *string;
		if(index2=='\\')
			string++;
		else if(index2=='^')
		{
			flag=0;
			string++;
		}
	}
	if(flag)
		coffset = &location.hist_char;
	index2 = (int)hp->histind;
	if(direction<0)
	{
		index2 -= hp->histsize;
		if(index2<1)
			index2 = 1;
		if(index1 <= index2)
			return(location);
	}
	else if(index1 >= index2)
		return(location);
	while(index1!=index2)
	{
		direction>0?++index1:--index1;
		offset = hist_tell(hp,index1);
		if((location.hist_line=hist_match(hp,offset,string,coffset))>=0)
		{
			location.hist_command = index1;
			return(location);
		}
#if KSHELL
		/* allow a search to be aborted */
		if(((Shell_t*)hp->histshell)->trapnote&SH_SIGSET)
			break;
#endif /* KSHELL */
	}
	return(location);
}

/*
 * search for <string> in history file starting at location <offset>
 * If coffset==0 then line must begin with string
 * returns the line number of the match if successful, otherwise -1
 */

int hist_match(register History_t *hp,off_t offset,char *string,int *coffset)
{
	register unsigned char *first, *cp;
	register int m,n,c=1,line=0;
#if SHOPT_MULTIBYTE
	mbinit();
#endif /* SHOPT_MULTIBYTE */
	sfseek(hp->histfp,offset,SEEK_SET);
	if(!(cp = first = (unsigned char*)sfgetr(hp->histfp,0,0)))
		return(-1);
	m = sfvalue(hp->histfp);
	n = strlen(string);
	while(m > n)
	{
		if(*cp==*string && memcmp(cp,string,n)==0)
		{
			if(coffset)
				*coffset = (cp-first);
			return(line);
		}
		if(!coffset)
			break;
		if(*cp=='\n')
			line++;
#if SHOPT_MULTIBYTE
		if((c=mbsize(cp)) < 0)
			c = 1;
#endif /* SHOPT_MULTIBYTE */
		cp += c;
		m -= c;
	}
	return(-1);
}


#if SHOPT_ESH || SHOPT_VSH
/*
 * copy command <command> from history file to s1
 * at most <size> characters copied
 * if s1==0 the number of lines for the command is returned
 * line=linenumber  for emacs copy and only this line of command will be copied
 * line < 0 for full command copy
 * -1 returned if there is no history file
 */

int hist_copy(char *s1,int size,int command,int line)
{
	register int c;
	register History_t *hp = shgd->hist_ptr;
	register int count = 0;
	register char *s1max = s1+size;
	if(!hp)
		return(-1);
	hist_seek(hp,command);
	while ((c = sfgetc(hp->histfp)) && c!=EOF)
	{
		if(c=='\n')
		{
			if(count++ ==line)
				break;
			else if(line >= 0)	
				continue;
		}
		if(s1 && (line<0 || line==count))
		{
			if(s1 >= s1max)
			{
				*--s1 = 0;
				break;
			}
			*s1++ = c;
		}
			
	}
	sfseek(hp->histfp,(off_t)0,SEEK_END);
	if(s1==0)
		return(count);
	if(count && (c= *(s1-1)) == '\n')
		s1--;
	*s1 = '\0';
	return(count);
}

/*
 * return word number <word> from command number <command>
 */

char *hist_word(char *string,int size,int word)
{
	register int c;
	register char *s1 = string;
	register unsigned char *cp = (unsigned char*)s1;
	register int flag = 0;
	History_t *hp = hist_ptr;
	if(!hp)
		return(NIL(char*));
	hist_copy(string,size,(int)hp->histind-1,-1);
	for(;c = *cp;cp++)
	{
		c = isspace(c);
		if(c && flag)
		{
			*cp = 0;
			if(--word==0)
				break;
			flag = 0;
		}
		else if(c==0 && flag==0)
		{
			s1 = (char*)cp;
			flag++;
		}
	}
	*cp = 0;
	if(s1 != string)
		strcpy(string,s1);
	return(string);
}

#endif	/* SHOPT_ESH */

#if SHOPT_ESH
/*
 * given the current command and line number,
 * and number of lines back or foward,
 * compute the new command and line number.
 */

Histloc_t hist_locate(History_t *hp,register int command,register int line,int lines)
{
	Histloc_t next;
	line += lines;
	if(!hp)
	{
		command = -1;
		goto done;
	}
	if(lines > 0)
	{
		register int count;
		while(command <= hp->histind)
		{
			count = hist_copy(NIL(char*),0, command,-1);
			if(count > line)
				goto done;
			line -= count;
			command++;
		}
	}
	else
	{
		register int least = (int)hp->histind-hp->histsize;
		while(1)
		{
			if(line >=0)
				goto done;
			if(--command < least)
				break;
			line += hist_copy(NIL(char*),0, command,-1);
		}
		command = -1;
	}
done:
	next.hist_line = line;
	next.hist_command = command;
	return(next);
}
#endif	/* SHOPT_ESH */


/*
 * Handle history file exceptions
 */
#ifdef SF_BUFCONST
static int hist_exceptf(Sfio_t* fp, int type, void *data, Sfdisc_t *handle)
#else
static int hist_exceptf(Sfio_t* fp, int type, Sfdisc_t *handle)
#endif
{
	register int newfd,oldfd;
	History_t *hp = (History_t*)handle;
	if(type==SF_WRITE)
	{
		if(errno==ENOSPC || hp->histwfail++ >= 10)
			return(0);
		/* write failure could be NFS problem, try to re-open */
		close(oldfd=sffileno(fp));
		if((newfd=open(hp->histname,O_BINARY|O_APPEND|O_CREAT|O_RDWR,S_IRUSR|S_IWUSR)) >= 0)
		{
			if(fcntl(newfd, F_DUPFD, oldfd) !=oldfd)
				return(-1);
			fcntl(oldfd,F_SETFD,FD_CLOEXEC);
			close(newfd);
			if(lseek(oldfd,(off_t)0,SEEK_END) < hp->histcnt)
			{
				register int index = hp->histind;
				lseek(oldfd,(off_t)2,SEEK_SET);
				hp->histcnt = 2;
				hp->histind = 1;
				hp->histcmds[1] = 2;
				hist_eof(hp);
				hp->histmarker = hp->histcnt;
				hp->histind = index;
			}
			return(1);
		}
		errormsg(SH_DICT,2,"History file write error-%d %s: file unrecoverable",errno,hp->histname);
		return(-1);
	}
	return(0);
}
