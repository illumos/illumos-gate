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
 * UNIX shell
 *
 * S. R. Bourne
 * Rewritten By David Korn
 * AT&T Labs
 *
 */

#include	<ast.h>
#include	<sfio.h>
#include	<stak.h>
#include	<ls.h>
#include	<fcin.h>
#include	"defs.h"
#include	"variables.h"
#include	"path.h"
#include	"io.h"
#include	"jobs.h"
#include	"shlex.h"
#include	"shnodes.h"
#include	"history.h"
#include	"timeout.h"
#include	"FEATURE/time"
#include	"FEATURE/pstat"
#include	"FEATURE/execargs"
#include	"FEATURE/externs"
#ifdef	_hdr_nc
#   include	<nc.h>
#endif	/* _hdr_nc */

#define CMD_LENGTH	64

/* These routines are referenced by this module */
static void	exfile(Shell_t*, Sfio_t*,int);
static void	chkmail(Shell_t *shp, char*);
#if defined(_lib_fork) && !defined(_NEXT_SOURCE)
    static void	fixargs(char**,int);
#else
#   define fixargs(a,b)
#endif

#ifndef environ
    extern char	**environ;
#endif

static struct stat lastmail;
static time_t	mailtime;
static char	beenhere = 0;

#ifdef _lib_sigvec
    void clearsigmask(register int sig)
    {
	struct sigvec vec;
	if(sigvec(sig,NIL(struct sigvec*),&vec)>=0 && vec.sv_mask)
	{
		vec.sv_mask = 0;
		sigvec(sig,&vec,NIL(struct sigvec*));
	}
    }
#endif /* _lib_sigvec */

#ifdef _lib_fts_notify
#   include	<fts.h>
    /* check for interrupts during tree walks */
    static int fts_sigcheck(FTS* fp, FTSENT* ep, void* context)
    {
	Shell_t *shp = (Shell_t*)context;
	NOT_USED(fp);
	NOT_USED(ep);
	if(shp->trapnote&SH_SIGSET)
	{
		errno = EINTR;
		return(-1);
	}
	return(0);
    }
#endif /* _lib_fts_notify */

#ifdef PATH_BFPATH
#define PATHCOMP	NIL(Pathcomp_t*)
#else
#define PATHCOMP	""
#endif

/*
 * search for file and exfile() it if it exists
 * 1 returned if file found, 0 otherwise
 */

int sh_source(Shell_t *shp, Sfio_t *iop, const char *file)
{
	char*	oid;
	char*	nid;
	int	fd;

	if (!file || !*file || (fd = path_open(file, PATHCOMP)) < 0)
	{
		REGRESS(source, "sh_source", ("%s:ENOENT", file));
		return 0;
	}
	oid = error_info.id;
	nid = error_info.id = strdup(file);
	shp->st.filename = path_fullname(stakptr(PATH_OFFSET));
	REGRESS(source, "sh_source", ("%s", file));
	exfile(shp, iop, fd);
	error_info.id = oid;
	free(nid);
	return 1;
}

#ifdef S_ISSOCK
#define REMOTE(m)	(S_ISSOCK(m)||!(m))
#else
#define REMOTE(m)	!(m)
#endif

int sh_main(int ac, char *av[], Shinit_f userinit)
{
	register char	*name;
	register int	fdin;
	register Sfio_t  *iop;
	register Shell_t *shp;
	struct stat	statb;
	int i, rshflag;		/* set for restricted shell */
	char *command;
#ifdef _lib_sigvec
	/* This is to clear mask that may be left on by rlogin */
	clearsigmask(SIGALRM);
	clearsigmask(SIGHUP);
	clearsigmask(SIGCHLD);
#endif /* _lib_sigvec */
#ifdef	_hdr_nc
	_NutConf(_NC_SET_SUFFIXED_SEARCHING, 1);
#endif	/* _hdr_nc */
	fixargs(av,0);
	shp = sh_init(ac,av,userinit);
	time(&mailtime);
	if(rshflag=sh_isoption(SH_RESTRICTED))
		sh_offoption(SH_RESTRICTED);
#ifdef _lib_fts_notify
	fts_notify(fts_sigcheck,(void*)shp);
#endif /* _lib_fts_notify */
	if(sigsetjmp(*((sigjmp_buf*)shp->jmpbuffer),0))
	{
		/* begin script execution here */
		sh_reinit((char**)0);
	}
	shp->fn_depth = shp->dot_depth = 0;
	command = error_info.id;
	/* set pidname '$$' */
	shp->pid = getpid();
	srand(shp->pid&0x7fff);
	shp->ppid = getppid();
	if(nv_isnull(PS4NOD))
		nv_putval(PS4NOD,e_traceprompt,NV_RDONLY);
	path_pwd(1);
	iop = (Sfio_t*)0;
#if SHOPT_BRACEPAT
	sh_onoption(SH_BRACEEXPAND);
#endif
	if((beenhere++)==0)
	{
		sh_onstate(SH_PROFILE);
		((Lex_t*)shp->lex_context)->nonstandard = 0;
		if(shp->ppid==1)
			shp->login_sh++;
		if(shp->login_sh >= 2)
			sh_onoption(SH_LOGIN_SHELL);
		/* decide whether shell is interactive */
		if(!sh_isoption(SH_INTERACTIVE) && !sh_isoption(SH_TFLAG) && !sh_isoption(SH_CFLAG) &&
		   sh_isoption(SH_SFLAG) && tty_check(0) && tty_check(ERRIO))
			sh_onoption(SH_INTERACTIVE);
		if(sh_isoption(SH_INTERACTIVE))
		{
			sh_onoption(SH_BGNICE);
			sh_onoption(SH_RC);
		}
		if(!sh_isoption(SH_RC) && (sh_isoption(SH_BASH) && !sh_isoption(SH_POSIX)
#if SHOPT_REMOTE
		   || !fstat(0, &statb) && REMOTE(statb.st_mode)
#endif
		  ))
			sh_onoption(SH_RC);
		for(i=0; i<elementsof(shp->offoptions.v); i++)
			shp->options.v[i] &= ~shp->offoptions.v[i];
		if(sh_isoption(SH_INTERACTIVE))
		{
#ifdef SIGXCPU
			signal(SIGXCPU,SIG_DFL);
#endif /* SIGXCPU */
#ifdef SIGXFSZ
			signal(SIGXFSZ,SIG_DFL);
#endif /* SIGXFSZ */
			sh_onoption(SH_MONITOR);
		}
		job_init(shp,sh_isoption(SH_LOGIN_SHELL));
		if(sh_isoption(SH_LOGIN_SHELL))
		{
			/*	system profile	*/
			sh_source(shp, iop, e_sysprofile);
			if(!sh_isoption(SH_NOUSRPROFILE) && !sh_isoption(SH_PRIVILEGED))
			{
				char **files = shp->login_files;
				while ((name = *files++) && !sh_source(shp, iop, sh_mactry(shp,name)));
			}
		}
		/* make sure PWD is set up correctly */
		path_pwd(1);
		if(!sh_isoption(SH_NOEXEC))
		{
			if(!sh_isoption(SH_NOUSRPROFILE) && !sh_isoption(SH_PRIVILEGED) && sh_isoption(SH_RC))
			{
#if SHOPT_BASH
				if(sh_isoption(SH_BASH) && !sh_isoption(SH_POSIX))
				{
#if SHOPT_SYSRC
					sh_source(shp, iop, e_bash_sysrc);
#endif
					sh_source(shp, iop, shp->rcfile ? shp->rcfile : sh_mactry(shp,(char*)e_bash_rc));
				}
				else
#endif
				{
					if(name = sh_mactry(shp,nv_getval(ENVNOD)))
						name = *name ? strdup(name) : (char*)0;
#if SHOPT_SYSRC
					if(!strmatch(name, "?(.)/./*"))
						sh_source(shp, iop, e_sysrc);
#endif
					if(name)
					{
						sh_source(shp, iop, name);
						free(name);
					}
				}
			}
			else if(sh_isoption(SH_INTERACTIVE) && sh_isoption(SH_PRIVILEGED))
				sh_source(shp, iop, e_suidprofile);
		}
		shp->st.cmdname = error_info.id = command;
		sh_offstate(SH_PROFILE);
		if(rshflag)
			sh_onoption(SH_RESTRICTED);
		/* open input file if specified */
		if(shp->comdiv)
		{
		shell_c:
			iop = sfnew(NIL(Sfio_t*),shp->comdiv,strlen(shp->comdiv),0,SF_STRING|SF_READ);
		}
		else
		{
			name = error_info.id;
			error_info.id = shp->shname;
			if(sh_isoption(SH_SFLAG))
				fdin = 0;
			else
			{
				char *sp;
				/* open stream should have been passed into shell */
				if(strmatch(name,e_devfdNN))
				{
#if !_WINIX
					char *cp;
					int type;
#endif
					fdin = (int)strtol(name+8, (char**)0, 10);
					if(fstat(fdin,&statb)<0)
						errormsg(SH_DICT,ERROR_system(1),e_open,name);
#if !_WINIX
					/*
					 * try to undo effect of solaris 2.5+
					 * change for argv for setuid scripts
					 */
					if(((type = sh_type(cp = av[0])) & SH_TYPE_SH) && (!(name = nv_getval(L_ARGNOD)) || !((type = sh_type(cp = name)) & SH_TYPE_SH)))
					{
						av[0] = (type & SH_TYPE_LOGIN) ? cp : path_basename(cp);
						/*  exec to change $0 for ps */
						execv(pathshell(),av);
						/* exec fails */
						shp->st.dolv[0] = av[0];
						fixargs(shp->st.dolv,1);
					}
#endif
					name = av[0];
					sh_offoption(SH_VERBOSE);
					sh_offoption(SH_XTRACE);
				}
				else
				{
					int isdir = 0;
					if((fdin=sh_open(name,O_RDONLY,0))>=0 &&(fstat(fdin,&statb)<0 || S_ISDIR(statb.st_mode)))
					{
						close(fdin);
						isdir = 1;
						fdin = -1;
					}
					else
						shp->st.filename = path_fullname(name);
					sp = 0;
					if(fdin < 0 && !strchr(name,'/'))
					{
#ifdef PATH_BFPATH
						if(path_absolute(name,NIL(Pathcomp_t*)))
							sp = stakptr(PATH_OFFSET);
#else
							sp = path_absolute(name,NIL(char*));
#endif
						if(sp)
						{
							if((fdin=sh_open(sp,O_RDONLY,0))>=0)
								shp->st.filename = path_fullname(sp);
						}
					}
					if(fdin<0)
					{
						if(isdir)
							errno = EISDIR;
						 error_info.id = av[0];
						if(sp || errno!=ENOENT)
							errormsg(SH_DICT,ERROR_system(ERROR_NOEXEC),e_open,name);
						/* try sh -c 'name "$@"' */
						sh_onoption(SH_CFLAG);
						shp->comdiv = (char*)malloc(strlen(name)+7);
						name = strcopy(shp->comdiv,name);
						if(shp->st.dolc)
							strcopy(name," \"$@\"");
						goto shell_c;
					}
					if(fdin==0)
						fdin = sh_iomovefd(fdin);
				}
				shp->readscript = shp->shname;
			}
			error_info.id = name;
			shp->comdiv--;
#if SHOPT_ACCT
			sh_accinit();
			if(fdin != 0)
				sh_accbegin(error_info.id);
#endif	/* SHOPT_ACCT */
		}
	}
	else
	{
		fdin = shp->infd;
		fixargs(shp->st.dolv,1);
	}
	if(sh_isoption(SH_INTERACTIVE))
		sh_onstate(SH_INTERACTIVE);
	nv_putval(IFSNOD,(char*)e_sptbnl,NV_RDONLY);
	exfile(shp,iop,fdin);
	sh_done(shp,0);
	/* NOTREACHED */
	return(0);
}

/*
 * iop is not null when the input is a string
 * fdin is the input file descriptor 
 */

static void	exfile(register Shell_t *shp, register Sfio_t *iop,register int fno)
{
	time_t curtime;
	Shnode_t *t;
	int maxtry=IOMAXTRY, tdone=0, execflags;
	int states,jmpval;
	struct checkpt buff;
	sh_pushcontext(&buff,SH_JMPERREXIT);
	/* open input stream */
	nv_putval(SH_PATHNAMENOD, shp->st.filename ,NV_NOFREE);
	if(!iop)
	{
		if(fno > 0)
		{
			int r;
			if(fno < 10 && ((r=sh_fcntl(fno,F_DUPFD,10))>=10))
			{
				shp->fdstatus[r] = shp->fdstatus[fno];
				sh_close(fno);
				fno = r;
			}
			fcntl(fno,F_SETFD,FD_CLOEXEC);
			shp->fdstatus[fno] |= IOCLEX;
			iop = sh_iostream((void*)shp,fno);
		}
		else
			iop = sfstdin;
	}
	else
		fno = -1;
	shp->infd = fno;
	if(sh_isstate(SH_INTERACTIVE))
	{
		if(nv_isnull(PS1NOD))
			nv_putval(PS1NOD,(shp->euserid?e_stdprompt:e_supprompt),NV_RDONLY);
		sh_sigdone();
		if(sh_histinit((void*)shp))
			sh_onoption(SH_HISTORY);
	}
	else
	{
		if(!sh_isstate(SH_PROFILE))
		{
			buff.mode = SH_JMPEXIT;
			sh_onoption(SH_TRACKALL);
			sh_offoption(SH_MONITOR);
		}
		sh_offstate(SH_INTERACTIVE);
		sh_offstate(SH_MONITOR);
		sh_offstate(SH_HISTORY);
		sh_offoption(SH_HISTORY);
	}
	states = sh_getstate();
	jmpval = sigsetjmp(buff.buff,0);
	if(jmpval)
	{
		Sfio_t *top;
		sh_iorestore((void*)shp,0,jmpval);
		hist_flush(shp->hist_ptr);
		sfsync(shp->outpool);
		shp->st.execbrk = shp->st.breakcnt = 0;
		/* check for return from profile or env file */
		if(sh_isstate(SH_PROFILE) && (jmpval==SH_JMPFUN || jmpval==SH_JMPEXIT))
		{
			sh_setstate(states);
			goto done;
		}
		if(!sh_isoption(SH_INTERACTIVE) || sh_isstate(SH_FORKED) || (jmpval > SH_JMPERREXIT && job_close(shp) >=0))
		{
			sh_offstate(SH_INTERACTIVE);
			sh_offstate(SH_MONITOR);
			goto done;
		}
		/* skip over remaining input */
		if(top = fcfile())
		{
			while(fcget()>0);
			fcclose();
			while(top=sfstack(iop,SF_POPSTACK))
				sfclose(top);
		}
		/* make sure that we own the terminal */
#ifdef SIGTSTP
		tcsetpgrp(job.fd,shp->pid);
#endif /* SIGTSTP */
	}
	/* error return here */
	sfclrerr(iop);
	sh_setstate(states);
	shp->st.optindex = 1;
	opt_info.offset = 0;
	shp->st.loopcnt = 0;
	shp->trapnote = 0;
	shp->intrap = 0;
	error_info.line = 1;
	shp->inlineno = 1;
	shp->binscript = 0;
	if(sfeof(iop))
		goto eof_or_error;
	/* command loop */
	while(1)
	{
		shp->nextprompt = 1;
		sh_freeup(shp);
		stakset(NIL(char*),0);
		exitset();
		sh_offstate(SH_STOPOK);
		sh_offstate(SH_ERREXIT);
		sh_offstate(SH_VERBOSE);
		sh_offstate(SH_TIMING);
		sh_offstate(SH_GRACE);
		sh_offstate(SH_TTYWAIT);
		if(sh_isoption(SH_VERBOSE))
			sh_onstate(SH_VERBOSE);
		sh_onstate(SH_ERREXIT);
		/* -eim  flags don't apply to profiles */
		if(sh_isstate(SH_PROFILE))
		{
			sh_offstate(SH_INTERACTIVE);
			sh_offstate(SH_ERREXIT);
			sh_offstate(SH_MONITOR);
		}
		if(sh_isstate(SH_INTERACTIVE) && !tdone)
		{
			register char *mail;
#ifdef JOBS
			sh_offstate(SH_MONITOR);
			if(sh_isoption(SH_MONITOR))
				sh_onstate(SH_MONITOR);
			if(job.pwlist)
			{
				job_walk(sfstderr,job_list,JOB_NFLAG,(char**)0);
				job_wait((pid_t)0);
			}
#endif	/* JOBS */
			if((mail=nv_getval(MAILPNOD)) || (mail=nv_getval(MAILNOD)))
			{
				time(&curtime);
				if ((curtime - mailtime) >= sh_mailchk)
				{
					chkmail(shp,mail);
					mailtime = curtime;
				}
			}
			if(shp->hist_ptr)
				hist_eof(shp->hist_ptr);
			/* sets timeout for command entry */
			shp->timeout = shp->st.tmout;
#if SHOPT_TIMEOUT
			if(shp->timeout <= 0 || shp->timeout > SHOPT_TIMEOUT)
				shp->timeout = SHOPT_TIMEOUT;
#endif /* SHOPT_TIMEOUT */
			shp->inlineno = 1;
			error_info.line = 1;
			shp->exitval = 0;
			shp->trapnote = 0;
			if(buff.mode == SH_JMPEXIT)
			{
				buff.mode = SH_JMPERREXIT;
#ifdef DEBUG
				errormsg(SH_DICT,ERROR_warn(0),"%d: mode changed to JMP_EXIT",getpid());
#endif
			}
		}
		errno = 0;
		if(tdone || !sfreserve(iop,0,0))
		{
		eof_or_error:
			if(sh_isstate(SH_INTERACTIVE) && !sferror(iop)) 
			{
				if(--maxtry>0 && sh_isoption(SH_IGNOREEOF) &&
					 !sferror(sfstderr) && (shp->fdstatus[fno]&IOTTY))
				{
					sfclrerr(iop);
					errormsg(SH_DICT,0,e_logout);
					continue;
				}
				else if(job_close(shp)<0)
					continue;
			}
			if(errno==0 && sferror(iop) && --maxtry>0)
			{
				sfclrlock(iop);
				sfclrerr(iop);
				continue;
			}
			goto done;
		}
		maxtry = IOMAXTRY;
		if(sh_isstate(SH_INTERACTIVE) && shp->hist_ptr)
		{
			job_wait((pid_t)0);
			hist_eof(shp->hist_ptr);
			sfsync(sfstderr);
		}
		if(sh_isoption(SH_HISTORY))
			sh_onstate(SH_HISTORY);
		job.waitall = job.curpgid = 0;
		error_info.flags |= ERROR_INTERACTIVE;
		t = (Shnode_t*)sh_parse(shp,iop,0);
		if(!sh_isstate(SH_INTERACTIVE) && !sh_isstate(SH_CFLAG))
			error_info.flags &= ~ERROR_INTERACTIVE;
		shp->readscript = 0;
		if(sh_isstate(SH_INTERACTIVE) && shp->hist_ptr)
			hist_flush(shp->hist_ptr);
		sh_offstate(SH_HISTORY);
		if(t)
		{
			execflags = sh_state(SH_ERREXIT)|sh_state(SH_INTERACTIVE);
			/* The last command may not have to fork */
			if(!sh_isstate(SH_PROFILE) && !sh_isstate(SH_INTERACTIVE) &&
				(fno<0 || !(shp->fdstatus[fno]&(IOTTY|IONOSEEK)))
				&& !sfreserve(iop,0,0))
			{
					execflags |= sh_state(SH_NOFORK);
			}
			shp->st.execbrk = 0;
			sh_exec(t,execflags);
			if(shp->forked)
			{
				sh_offstate(SH_INTERACTIVE);
				goto done;
			}
			/* This is for sh -t */
			if(sh_isoption(SH_TFLAG) && !sh_isstate(SH_PROFILE))
				tdone++;
		}
	}
done:
	sh_popcontext(&buff);
	if(sh_isstate(SH_INTERACTIVE))
	{
		sfputc(sfstderr,'\n');
		job_close(shp);
	}
	if(jmpval == SH_JMPSCRIPT)
		siglongjmp(*shp->jmplist,jmpval);
	else if(jmpval == SH_JMPEXIT)
		sh_done(shp,0);
	if(fno>0)
		sh_close(fno);
	if(shp->st.filename)
		free((void*)shp->st.filename);
	shp->st.filename = 0;
}


/* prints out messages if files in list have been modified since last call */
static void chkmail(Shell_t *shp, char *files)
{
	register char *cp,*sp,*qp;
	register char save;
	struct argnod *arglist=0;
	int	offset = staktell();
	char 	*savstak=stakptr(0);
	struct stat	statb;
	if(*(cp=files) == 0)
		return;
	sp = cp;
	do
	{
		/* skip to : or end of string saving first '?' */
		for(qp=0;*sp && *sp != ':';sp++)
			if((*sp == '?' || *sp=='%') && qp == 0)
				qp = sp;
		save = *sp;
		*sp = 0;
		/* change '?' to end-of-string */
		if(qp)
			*qp = 0;
		do
		{
			/* see if time has been modified since last checked
			 * and the access time <= the modification time
			 */
			if(stat(cp,&statb) >= 0 && statb.st_mtime >= mailtime
				&& statb.st_atime <= statb.st_mtime)
			{
				/* check for directory */
				if(!arglist && S_ISDIR(statb.st_mode)) 
				{
					/* generate list of directory entries */
					path_complete(cp,"/*",&arglist);
				}
				else
				{
					/*
					 * If the file has shrunk,
					 * or if the size is zero
					 * then don't print anything
					 */
					if(statb.st_size &&
						(  statb.st_ino != lastmail.st_ino
						|| statb.st_dev != lastmail.st_dev
						|| statb.st_size > lastmail.st_size))
					{
						/* save and restore $_ */
						char *save = shp->lastarg;
						shp->lastarg = cp;
						errormsg(SH_DICT,0,sh_mactry(shp,qp?qp+1:(char*)e_mailmsg));
						shp->lastarg = save;
					}
					lastmail = statb;
					break;
				}
			}
			if(arglist)
			{
				cp = arglist->argval;
				arglist = arglist->argchn.ap;
			}
			else
				cp = 0;
		}
		while(cp);
		if(qp)
			*qp = '?';
		*sp++ = save;
		cp = sp;
	}
	while(save);
	stakset(savstak,offset);
}

#undef EXECARGS
#undef PSTAT
#if defined(_hdr_execargs) && defined(pdp11)
#   include	<execargs.h>
#   define EXECARGS	1
#endif

#if defined(_lib_pstat) && defined(_sys_pstat)
#   include	<sys/pstat.h>
#   define PSTAT	1
#endif

#if defined(_lib_fork) && !defined(_NEXT_SOURCE)
/*
 * fix up command line for ps command
 * mode is 0 for initialization
 */
static void fixargs(char **argv, int mode)
{
#if EXECARGS
	*execargs=(char *)argv;
#else
	static char *buff;
	static int command_len;
	register char *cp;
	int offset=0,size;
#   ifdef PSTAT
	union pstun un;
	if(mode==0)
	{
		struct pst_static st;
		un.pst_static = &st;
		if(pstat(PSTAT_STATIC, un, sizeof(struct pst_static), 1, 0)<0)
			return;
		command_len = st.command_length;
		return;
	}
	stakseek(command_len+2);
	buff = stakseek(0);
#   else
	if(mode==0)
	{
		buff = argv[0];
		while(cp = *argv++)
			command_len += strlen(cp)+1;
		if(environ && *environ==buff+command_len)
		{
			for(argv=environ; cp = *argv; cp++)
			{
				if(command_len > CMD_LENGTH)
				{
					command_len = CMD_LENGTH;
					break;
				}
				*argv++ = strdup(cp);
				command_len += strlen(cp)+1;
			}
		}
		command_len -= 1;
		return;
	}
#   endif /* PSTAT */
	if(command_len==0)
		return;
	while((cp = *argv++) && offset < command_len)
	{
		if(offset + (size=strlen(cp)) >= command_len)
			size = command_len - offset;
		memcpy(buff+offset,cp,size);
		offset += size;
		buff[offset++] = ' ';
	}
	buff[offset-1] = 0;
#   ifdef PSTAT
	un.pst_command = stakptr(0);
	pstat(PSTAT_SETCMD,un,0,0,0);
#   endif /* PSTAT */
#endif /* EXECARGS */
}
#endif /* _lib_fork */
