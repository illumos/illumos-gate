/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*           Copyright (c) 1982-2007 AT&T Knowledge Ventures            *
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
*                  David Korn <dgk@research.att.com>                   *
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 *   Create and manage subshells avoiding forks when possible
 *
 *   David Korn
 *   AT&T Labs
 *
 */

#include	"defs.h"
#include	<ls.h>
#include	"io.h"
#include	"fault.h"
#include	"shnodes.h"
#include	"shlex.h"
#include	"jobs.h"
#include	"variables.h"
#include	"path.h"

#ifndef PIPE_BUF
#   define PIPE_BUF	512
#endif

/*
 * Note that the following structure must be the same
 * size as the Dtlink_t structure
 */
struct Link
{
	struct Link	*next;
	Namval_t	*node;
};

/*
 * The following structure is used for command substitution and (...)
 */
static struct subshell
{
	struct subshell	*prev;	/* previous subshell data */
	struct subshell	*pipe;	/* subshell where output goes to pipe on fork */
	Dt_t		*var;	/* variable table at time of subshell */
	struct Link	*svar;	/* save shell variable table */
	Dt_t		*sfun;	/* function scope for subshell */
	Dt_t		*salias;/* alias scope for subshell */
#ifdef PATH_BFPATH
	Pathcomp_t	*pathlist; /* for PATH variable */
#endif
#if (ERROR_VERSION >= 20030214L)
	struct Error_context_s *errcontext;
#else
	struct errorcontext *errcontext;
#endif
	Shopt_t		options;/* save shell options */
	pid_t		subpid;	/* child process id */
	Sfio_t*	saveout;/*saved standard output */
	char		*pwd;	/* present working directory */
	const char	*shpwd;	/* saved pointer to sh.pwd */
	void		*jobs;	/* save job info */
	mode_t		mask;	/* saved umask */
	short		tmpfd;	/* saved tmp file descriptor */
	short		pipefd;	/* read fd if pipe is created */
	char		jobcontrol;
	char		monitor;
	unsigned char	fdstatus;
	int		fdsaved; /* bit make for saved files */
	int		bckpid;
} *subshell_data;

static int subenv;

/*
 * This routine will turn the sftmp() file into a real /tmp file or pipe
 * if the /tmp file create fails
 */
void	sh_subtmpfile(void)
{
	if(sfset(sfstdout,0,0)&SF_STRING)
	{
		register int fd;
		register struct checkpt	*pp = (struct checkpt*)sh.jmplist;
		register struct subshell *sp = subshell_data->pipe;
		/* save file descriptor 1 if open */
		if((sp->tmpfd = fd = fcntl(1,F_DUPFD,10)) >= 0)
		{
			fcntl(fd,F_SETFD,FD_CLOEXEC);
			sh.fdstatus[fd] = sh.fdstatus[1]|IOCLEX;
			close(1);
		}
		else if(errno!=EBADF)
			errormsg(SH_DICT,ERROR_system(1),e_toomany);
		/* popping a discipline forces a /tmp file create */
		sfdisc(sfstdout,SF_POPDISC);
		if((fd=sffileno(sfstdout))<0)
		{
			/* unable to create the /tmp file so use a pipe */
			int fds[2];
			Sfoff_t off;
			sh_pipe(fds);
			sp->pipefd = fds[0];
			sh_fcntl(sp->pipefd,F_SETFD,FD_CLOEXEC);
			/* write the data to the pipe */
			if(off = sftell(sfstdout))
				write(fds[1],sfsetbuf(sfstdout,(Void_t*)sfstdout,0),(size_t)off);
			sfclose(sfstdout);
			if((sh_fcntl(fds[1],F_DUPFD, 1)) != 1)
				errormsg(SH_DICT,ERROR_system(1),e_file+4);
			sh_close(fds[1]);
		}
		else
		{
			sh.fdstatus[fd] = IOREAD|IOWRITE;
			sfsync(sfstdout);
			if(fd==1)
				fcntl(1,F_SETFD,0);
			else
			{
				sfsetfd(sfstdout,1);
				sh.fdstatus[1] = sh.fdstatus[fd];
				sh.fdstatus[fd] = IOCLOSE;
			}
		}
		sh_iostream(1);
		sfset(sfstdout,SF_SHARE|SF_PUBLIC,1);
		sfpool(sfstdout,sh.outpool,SF_WRITE);
		if(pp && pp->olist  && pp->olist->strm == sfstdout)
			pp->olist->strm = 0;
	}
}

/*
 * This routine creates a temp file if necessary and creates a subshell.
 * The parent routine longjmps back to sh_subshell()
 * The child continues possibly with its standard output replaced by temp file
 */
void sh_subfork(void)
{
	register struct subshell *sp = subshell_data;
	pid_t pid;
	/* see whether inside $(...) */
	if(sp->pipe)
		sh_subtmpfile();
	if(pid = sh_fork(0,NIL(int*)))
	{
		/* this is the parent part of the fork */
		if(sp->subpid==0)
			sp->subpid = pid;
		siglongjmp(*sh.jmplist,SH_JMPSUB);
	}
	else
	{
		int16_t subshell;
		/* this is the child part of the fork */
		/* setting subpid to 1 causes subshell to exit when reached */
		sh_onstate(SH_FORKED);
		sh_onstate(SH_NOLOG);
		sh_offstate(SH_MONITOR);
		subshell_data = 0;
		subshell = sh.subshell = 0;
		nv_putval(SH_SUBSHELLNOD, (char*)&subshell, NV_INT16);
		sp->subpid=0;
	}
}

/*
 * This routine will make a copy of the given node in the
 * layer created by the most recent subshell_fork if the
 * node hasn't already been copied
 */
Namval_t *sh_assignok(register Namval_t *np,int add)
{
	register Namval_t *mp;
	register struct Link *lp;
	register struct subshell *sp = (struct subshell*)subshell_data;
	int save;
	/* don't bother with this */
	if(!sp->shpwd || (nv_isnull(np) && !add))
		return(np);
	/* don't bother to save if in newer scope */
	if(nv_search((char*)np,sp->var,HASH_BUCKET)!=np)
		return(np);
	for(lp=subshell_data->svar; lp; lp = lp->next)
	{
		if(lp->node==np)
			return(np);
	}
	mp =  newof(0,Namval_t,1,0);
	lp = (struct Link*)mp;
	lp->node = np;
	lp->next = subshell_data->svar; 
	subshell_data->svar = lp;
	save = sh.subshell;
	sh.subshell = 0;;
	nv_clone(np,mp,NV_NOFREE);
	sh.subshell = save;
	return(np);
}

/*
 * restore the variables
 */
static void nv_restore(struct subshell *sp)
{
	register struct Link *lp, *lq;
	register Namval_t *mp, *np;
	const char *save = sp->shpwd;
	sp->shpwd = 0;	/* make sure sh_assignok doesn't save with nv_unset() */
	for(lp=sp->svar; lp; lp=lq)
	{
		np = (Namval_t*)lp;
		mp = lp->node;
		lq = lp->next;
		if(nv_isarray(mp))
			 nv_putsub(mp,NIL(char*),ARRAY_SCAN);
		_nv_unset(mp,NV_RDONLY);
		nv_setsize(mp,nv_size(np));
		if(!nv_isattr(np,NV_MINIMAL) || nv_isattr(np,NV_EXPORT))
			mp->nvenv = np->nvenv;
		mp->nvfun = np->nvfun;
		mp->nvflag = np->nvflag;
		if((mp==nv_scoped(PATHNOD)) || (mp==nv_scoped(IFSNOD)))
			nv_putval(mp, np->nvalue.cp,0);
		else
			mp->nvalue.cp = np->nvalue.cp;
		np->nvfun = 0;
		if(nv_isattr(mp,NV_EXPORT))
		{
			char *name = nv_name(mp);
			sh_envput(sh.env,mp);
			if(*name=='_' && strcmp(name,"_AST_FEATURES")==0)
				astconf(NiL, NiL, NiL);
		}
		else if(nv_isattr(np,NV_EXPORT))
			env_delete(sh.env,nv_name(mp));
		free((void*)np);
	}
	sp->shpwd=save;
}

/*
 * return pointer to alias tree
 * create new one if in a subshell and one doesn't exist and create is non-zero
 */
Dt_t *sh_subaliastree(int create)
{
	register struct subshell *sp = subshell_data;
	if(!sp || sh.curenv==0)
		return(sh.alias_tree);
	if(!sp->salias && create)
	{
		sp->salias = dtopen(&_Nvdisc,Dtoset);
		dtview(sp->salias,sh.alias_tree);
		sh.alias_tree = sp->salias;
	}
	return(sp->salias);
}

/*
 * return pointer to function tree
 * create new one if in a subshell and one doesn't exist and create is non-zero
 */
Dt_t *sh_subfuntree(int create)
{
	register struct subshell *sp = subshell_data;
	if(!sp || sh.curenv==0)
		return(sh.fun_tree);
	if(!sp->sfun && create)
	{
		sp->sfun = dtopen(&_Nvdisc,Dtoset);
		dtview(sp->sfun,sh.fun_tree);
		sh.fun_tree = sp->sfun;
	}
	return(sp->sfun);
}

static void table_unset(register Dt_t *root)
{
	register Namval_t *np,*nq;
	for(np=(Namval_t*)dtfirst(root);np;np=nq)
	{
		_nv_unset(np,NV_RDONLY);
		nq = (Namval_t*)dtnext(root,np);
		dtdelete(root,np);
		free((void*)np);
	}
}

int sh_subsavefd(register int fd)
{
	register struct subshell *sp = subshell_data;
	register int old=0;
	if(sp)
	{
		old = !(sp->fdsaved&(1<<(fd-1)));
		sp->fdsaved |= (1<<(fd-1));
	}
	return(old);
}

/*
 * Run command tree <t> in a virtual sub-shell
 * If comsub is not null, then output will be placed in temp file (or buffer)
 * If comsub is not null, the return value will be a stream consisting of
 * output of command <t>.  Otherwise, NULL will be returned.
 */

Sfio_t *sh_subshell(Shnode_t *t, int flags, int comsub)
{
	Shell_t *shp = &sh;
	struct subshell sub_data;
	register struct subshell *sp = &sub_data;
	int jmpval,nsig;
	int savecurenv = shp->curenv;
	int16_t subshell;
	char *savsig;
	Sfio_t *iop=0;
	struct checkpt buff;
	struct sh_scoped savst;
	struct dolnod   *argsav=0;
	memset((char*)sp, 0, sizeof(*sp));
	sfsync(shp->outpool);
	argsav = sh_arguse();
	if(shp->curenv==0)
	{
		subshell_data=0;
		subenv = 0;
	}
	shp->curenv = ++subenv;
	savst = shp->st;
	sh_pushcontext(&buff,SH_JMPSUB);
	subshell = shp->subshell+1;
	nv_putval(SH_SUBSHELLNOD, (char*)&subshell, NV_INT16);
	shp->subshell = subshell;
	sp->prev = subshell_data;
	subshell_data = sp;
	sp->errcontext = &buff.err;
	sp->var = shp->var_tree;
	sp->options = shp->options;
	sp->jobs = job_subsave();
#ifdef PATH_BFPATH
	/* make sure initialization has occurred */ 
	if(!shp->pathlist)
		path_get(".");
	sp->pathlist = path_dup((Pathcomp_t*)shp->pathlist);
#endif
	if(!shp->pwd)
		path_pwd(0);
	sp->bckpid = shp->bckpid;
	if(!comsub || !sh_isoption(SH_SUBSHARE))
	{
		sp->shpwd = shp->pwd;
		sp->pwd = (shp->pwd?strdup(shp->pwd):0);
		sp->mask = shp->mask;
		/* save trap table */
		shp->st.otrapcom = 0;
		if((nsig=shp->st.trapmax*sizeof(char*))>0 || shp->st.trapcom[0])
		{
			nsig += sizeof(char*);
			memcpy(savsig=malloc(nsig),(char*)&shp->st.trapcom[0],nsig);
			/* this nonsense needed for $(trap) */
			shp->st.otrapcom = (char**)savsig;
		}
		sh_sigreset(0);
	}
	jmpval = sigsetjmp(buff.buff,0);
	if(jmpval==0)
	{
		if(comsub)
		{
			/* disable job control */
			sp->jobcontrol = job.jobcontrol;
			sp->monitor = (sh_isstate(SH_MONITOR)!=0);
			job.jobcontrol=0;
			sh_offstate(SH_MONITOR);
			sp->pipe = sp;
			/* save sfstdout and status */
			sp->saveout = sfswap(sfstdout,NIL(Sfio_t*));
			sp->fdstatus = shp->fdstatus[1];
			sp->tmpfd = -1;
			sp->pipefd = -1;
			/* use sftmp() file for standard output */
			if(!(iop = sftmp(PIPE_BUF)))
			{
				sfswap(sp->saveout,sfstdout);
				errormsg(SH_DICT,ERROR_system(1),e_tmpcreate);
			}
			sfswap(iop,sfstdout);
			sfset(sfstdout,SF_READ,0);
			shp->fdstatus[1] = IOWRITE;
		}
		else if(sp->prev)
		{
			sp->pipe = sp->prev->pipe;
			flags &= ~sh_state(SH_NOFORK);
		}
		sh_exec(t,flags);
	}
	if(jmpval!=SH_JMPSUB && shp->st.trapcom[0] && shp->subshell)
	{
		/* trap on EXIT not handled by child */
		char *trap=shp->st.trapcom[0];
		shp->st.trapcom[0] = 0;	/* prevent recursion */
		shp->oldexit = shp->exitval;
		sh_trap(trap,0);
		free(trap);
	}
	sh_popcontext(&buff);
	if(shp->subshell==0)	/* must be child process */
	{
		subshell_data = sp->prev;
		if(jmpval==SH_JMPSCRIPT)
			siglongjmp(*shp->jmplist,jmpval);
		sh_done(0);
	}
	if(comsub)
	{
		/* re-enable job control */
		job.jobcontrol = sp->jobcontrol;
		if(sp->monitor)
			sh_onstate(SH_MONITOR);
		if(sp->pipefd>=0)
		{
			/* sftmp() file has been returned into pipe */
			iop = sh_iostream(sp->pipefd);
			sfdisc(iop,SF_POPDISC);
			sfclose(sfstdout);
		}
		else
		{
			/* move tmp file to iop and restore sfstdout */
			iop = sfswap(sfstdout,NIL(Sfio_t*));
			if(!iop)
			{
				/* maybe locked try again */
				sfclrlock(sfstdout);
				iop = sfswap(sfstdout,NIL(Sfio_t*));
			}
			if(iop && sffileno(iop)==1)
			{
				int fd=sfsetfd(iop,3);
				if(fd<0)
					errormsg(SH_DICT,ERROR_system(1),e_toomany);
				shp->sftable[fd] = iop;
				fcntl(fd,F_SETFD,FD_CLOEXEC);
				shp->fdstatus[fd] = (shp->fdstatus[1]|IOCLEX);
				shp->fdstatus[1] = IOCLOSE;
			}
			sfset(iop,SF_READ,1);
		}
		sfswap(sp->saveout,sfstdout);
		/*  check if standard output was preserved */
		if(sp->tmpfd>=0)
		{
			close(1);
			fcntl(sp->tmpfd,F_DUPFD,1);
			sh_close(sp->tmpfd);
		}
		shp->fdstatus[1] = sp->fdstatus;
	}
	if(sp->subpid)
		job_wait(sp->subpid);
	if(comsub && iop)
		sfseek(iop,(off_t)0,SEEK_SET);
	if(shp->subshell)
		shp->subshell--;
	subshell = shp->subshell;
	nv_putval(SH_SUBSHELLNOD, (char*)&subshell, NV_INT16);
#ifdef PATH_BFPATH
	path_delete((Pathcomp_t*)shp->pathlist);
	shp->pathlist = (void*)sp->pathlist;
#endif
	job_subrestore(sp->jobs);
	shp->jobenv = savecurenv;
	shp->bckpid = sp->bckpid;
	if(sp->shpwd)	/* restore environment if saved */
	{
		shp->options = sp->options;
		nv_restore(sp);
		if(sp->salias)
		{
			shp->alias_tree = dtview(sp->salias,0);
			table_unset(sp->salias);
			dtclose(sp->salias);
		}
		if(sp->sfun)
		{
			shp->fun_tree = dtview(sp->sfun,0);
			table_unset(sp->sfun);
			dtclose(sp->sfun);
		}
		sh_sigreset(1);
		shp->st = savst;
		shp->curenv = savecurenv;
		if(nsig)
		{
			memcpy((char*)&shp->st.trapcom[0],savsig,nsig);
			free((void*)savsig);
		}
		shp->options = sp->options;
		if(!shp->pwd || strcmp(sp->pwd,shp->pwd))
		{
			/* restore PWDNOD */
			Namval_t *pwdnod = nv_scoped(PWDNOD);
			if(shp->pwd)
			{
				chdir(shp->pwd=sp->pwd);
#ifdef PATH_BFPATH
				path_newdir(shp->pathlist);
#endif
			}
			if(nv_isattr(pwdnod,NV_NOFREE))
				pwdnod->nvalue.cp = (const char*)sp->pwd;
		}
		else if(sp->shpwd != shp->pwd)
		{
			shp->pwd = sp->pwd;
			if(PWDNOD->nvalue.cp==sp->shpwd)
				PWDNOD->nvalue.cp = sp->pwd;
		}
		else
			free((void*)sp->pwd);
		if(sp->mask!=shp->mask)
			umask(shp->mask);
	}
	subshell_data = sp->prev;
	sh_argfree(argsav,0);
	shp->trapnote = 0;
	if(shp->topfd != buff.topfd)
		sh_iorestore(buff.topfd|IOSUBSHELL,jmpval);
	if(shp->exitval > SH_EXITSIG)
	{
		int sig = shp->exitval&SH_EXITMASK;
		if(sig==SIGINT || sig== SIGQUIT)
			sh_fault(sig);
	}
	return(iop);
}
