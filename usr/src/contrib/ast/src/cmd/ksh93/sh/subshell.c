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

#ifndef O_SEARCH
#   ifdef O_PATH
#	define O_SEARCH	O_PATH
#   else
#	define O_SEARCH	0
#   endif
#endif

/*
 * Note that the following structure must be the same
 * size as the Dtlink_t structure
 */
struct Link
{
	struct Link	*next;
	Namval_t	*child;
	Dt_t		*dict;
	Namval_t	*node;
};

/*
 * The following structure is used for command substitution and (...)
 */
static struct subshell
{
	Shell_t		*shp;	/* shell interpreter */
	struct subshell	*prev;	/* previous subshell data */
	struct subshell	*pipe;	/* subshell where output goes to pipe on fork */
	Dt_t		*var;	/* variable table at time of subshell */
	struct Link	*svar;	/* save shell variable table */
	Dt_t		*sfun;	/* function scope for subshell */
	Dt_t		*salias;/* alias scope for subshell */
	Pathcomp_t	*pathlist; /* for PATH variable */
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
	int		pwdfd;	/* file descritor for pwd */
	mode_t		mask;	/* saved umask */
	short		tmpfd;	/* saved tmp file descriptor */
	short		pipefd;	/* read fd if pipe is created */
	char		jobcontrol;
	char		monitor;
	unsigned char	fdstatus;
	int		fdsaved; /* bit make for saved files */
	int		sig;	/* signal for $$ */
	pid_t		bckpid;
	pid_t		cpid;
	int		coutpipe;
	int		cpipe;
	int		nofork;
	int		subdup;
	char		subshare;
	char		comsub;
	char		pwdclose;
#if SHOPT_COSHELL
	void		*coshell;
#endif /* SHOPT_COSHELL */
} *subshell_data;

static int subenv;


/*
 * This routine will turn the sftmp() file into a real /tmp file or pipe
 * if the /tmp file create fails
 */
void	sh_subtmpfile(Shell_t *shp)
{
	if(sfset(sfstdout,0,0)&SF_STRING)
	{
		register int fd;
		register struct checkpt	*pp = (struct checkpt*)shp->jmplist;
		register struct subshell *sp = subshell_data->pipe;
		/* save file descriptor 1 if open */
		if((sp->tmpfd = fd = fcntl(1,F_DUPFD,10)) >= 0)
		{
			fcntl(fd,F_SETFD,FD_CLOEXEC);
			VALIDATE_FD(shp, fd);
			shp->fdstatus[fd] = shp->fdstatus[1]|IOCLEX;
			close(1);
		}
		else if(errno!=EBADF)
			errormsg(SH_DICT,ERROR_system(1),e_toomany);
		/* popping a discipline forces a /tmp file create */
		sfdisc(sfstdout,SF_POPDISC);
		if((fd=sffileno(sfstdout))<0)
		{
			/* unable to create the /tmp file so use a pipe */
			int fds[3];
			Sfoff_t off;
			fds[2] = 0;
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
			VALIDATE_FD(shp, fd);
			shp->fdstatus[fd] = IOREAD|IOWRITE;
			sfsync(sfstdout);
			if(fd==1)
				fcntl(1,F_SETFD,0);
			else
			{
				sfsetfd(sfstdout,1);
				shp->fdstatus[1] = shp->fdstatus[fd];
				shp->fdstatus[fd] = IOCLOSE;
			}
		}
		sh_iostream(shp,1);
		sfset(sfstdout,SF_SHARE|SF_PUBLIC,1);
		sfpool(sfstdout,shp->outpool,SF_WRITE);
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
	Shell_t	*shp = sp->shp;
	int	curenv = shp->curenv;
	pid_t pid;
	char *trap = shp->st.trapcom[0];
	if(trap)
		trap = strdup(trap);
	/* see whether inside $(...) */
	if(sp->pipe)
		sh_subtmpfile(shp);
	shp->curenv = 0;
	shp->savesig = -1;
	if(pid = sh_fork(shp,FSHOWME,NIL(int*)))
	{
		shp->curenv = curenv;
		/* this is the parent part of the fork */
		if(sp->subpid==0)
			sp->subpid = pid;
		if(trap)
			free((void*)trap);
		siglongjmp(*shp->jmplist,SH_JMPSUB);
	}
	else
	{
		/* this is the child part of the fork */
		/* setting subpid to 1 causes subshell to exit when reached */
		sh_onstate(SH_FORKED);
		sh_onstate(SH_NOLOG);
		sh_offoption(SH_MONITOR);
		sh_offstate(SH_MONITOR);
		subshell_data = 0;
		shp->subshell = 0;
		shp->comsub = 0;
		SH_SUBSHELLNOD->nvalue.s = 0;
		sp->subpid=0;
		shp->st.trapcom[0] = trap;
		shp->savesig = 0;
	}
}

int nv_subsaved(register Namval_t *np)
{
	register struct subshell	*sp;
	register struct Link		*lp;
	for(sp = (struct subshell*)subshell_data; sp; sp=sp->prev)
	{
		for(lp=sp->svar; lp; lp = lp->next)
		{
			if(lp->node==np)
				return(1);
		}
	}
	return(0);
}

/*
 * This routine will make a copy of the given node in the
 * layer created by the most recent subshell_fork if the
 * node hasn't already been copied
 */
Namval_t *sh_assignok(register Namval_t *np,int add)
{
	register Namval_t	*mp;
	register struct Link	*lp;
	register struct subshell *sp;
	Shell_t			*shp;
	Dt_t			*dp;
	Namval_t		*mpnext;
	Namarr_t		*ap;
	int			save;

	sp = (struct subshell*)subshell_data;

	/* don't bother with this */
	if(!sp || !sp->shpwd || np==SH_LEVELNOD || np==L_ARGNOD || np==SH_SUBSCRNOD || np==SH_NAMENOD)
		return(np);

	shp = sp->shp;
	dp = shp->var_tree;

	if((ap=nv_arrayptr(np)) && (mp=nv_opensub(np)))
	{
		shp->last_root = ap->table;
		sh_assignok(mp,add);
		if(!add || array_assoc(ap))
			return(np);
	}
	for(lp=sp->svar; lp;lp = lp->next)
	{
		if(lp->node==np)
			return(np);
	}
	/* first two pointers use linkage from np */
	lp = (struct Link*)malloc(sizeof(*np)+2*sizeof(void*));
	memset(lp,0, sizeof(*mp)+2*sizeof(void*));
	lp->node = np;
	if(!add &&  nv_isvtree(np))
	{
		Namval_t	fake;
		Dt_t		*walk, *root=shp->var_tree;
		char		*name = nv_name(np);
		size_t		len = strlen(name);
		fake.nvname = name;
		mpnext = dtnext(root,&fake);
		dp = root->walk?root->walk:root;
		while(mp=mpnext)
		{
			walk = root->walk?root->walk:root;
			mpnext = dtnext(root,mp);
			if(memcmp(name,mp->nvname,len) || mp->nvname[len]!='.')
				break;
			nv_delete(mp,walk,NV_NOFREE);
			*((Namval_t**)mp) = lp->child;
			lp->child = mp;
			
		}
	}
	lp->dict = dp;
	mp = (Namval_t*)&lp->dict;
	lp->next = subshell_data->svar; 
	subshell_data->svar = lp;
	save = shp->subshell;
	shp->subshell = 0;
	mp->nvname = np->nvname;
	if(nv_isattr(np,NV_NOFREE))
		nv_onattr(mp,NV_IDENT);
	nv_clone(np,mp,(add?(nv_isnull(np)?0:NV_NOFREE)|NV_ARRAY:NV_MOVE));
	shp->subshell = save;
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
	Namval_t	*mpnext;
	int		flags,nofree;
	sp->shpwd = 0;	/* make sure sh_assignok doesn't save with nv_unset() */
	for(lp=sp->svar; lp; lp=lq)
	{
		np = (Namval_t*)&lp->dict;
		lq = lp->next;
		mp = lp->node;
		if(!mp->nvname)
			continue;
		flags = 0;
		if(nv_isattr(mp,NV_MINIMAL) && !nv_isattr(np,NV_EXPORT))
			flags |= NV_MINIMAL;
		if(nv_isarray(mp))
			 nv_putsub(mp,NIL(char*),ARRAY_SCAN);
		nofree = mp->nvfun?mp->nvfun->nofree:0;
		_nv_unset(mp,NV_RDONLY|NV_CLONE);
		if(nv_isarray(np))
		{
			nv_clone(np,mp,NV_MOVE);
			goto skip;
		}
		nv_setsize(mp,nv_size(np));
		if(!(flags&NV_MINIMAL))
			mp->nvenv = np->nvenv;
		if(!nofree)
			mp->nvfun = np->nvfun;
		if(nv_isattr(np,NV_IDENT))
		{
			nv_offattr(np,NV_IDENT);
			flags |= NV_NOFREE;
		}
		mp->nvflag = np->nvflag|(flags&NV_MINIMAL);
		if(nv_cover(mp))
			nv_putval(mp, nv_getval(np),np->nvflag|NV_NOFREE|NV_RDONLY);
		else
			mp->nvalue.cp = np->nvalue.cp;
		if(nofree && np->nvfun && !np->nvfun->nofree)
			free((char*)np->nvfun);
		np->nvfun = 0;
		if(nv_isattr(mp,NV_EXPORT))
		{
			char *name = nv_name(mp);
			sh_envput(sp->shp->env,mp);
			if(*name=='_' && strcmp(name,"_AST_FEATURES")==0)
				astconf(NiL, NiL, NiL);
		}
		else if(nv_isattr(np,NV_EXPORT))
			env_delete(sp->shp->env,nv_name(mp));
		nv_onattr(mp,flags);
	skip:
		for(mp=lp->child; mp; mp=mpnext)
		{
			mpnext = *((Namval_t**)mp);
			dtinsert(lp->dict,mp);
		}
		free((void*)lp);
		sp->svar = lq;
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
	if(!sp || sp->shp->curenv==0)
		return(sh.alias_tree);
	if(!sp->salias && create)
	{
		sp->salias = dtopen(&_Nvdisc,Dtoset);
		dtview(sp->salias,sp->shp->alias_tree);
		sp->shp->alias_tree = sp->salias;
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
	if(!sp || sp->shp->curenv==0)
		return(sh.fun_tree);
	if(!sp->sfun && create)
	{
		sp->sfun = dtopen(&_Nvdisc,Dtoset);
		dtview(sp->sfun,sp->shp->fun_tree);
		sp->shp->fun_tree = sp->sfun;
	}
	return(sp->shp->fun_tree);
}

static void table_unset(register Dt_t *root,int fun)
{
	register Namval_t *np,*nq;
	int flag;
	for(np=(Namval_t*)dtfirst(root);np;np=nq)
	{
		nq = (Namval_t*)dtnext(root,np);
		flag=0;
		if(fun && np->nvalue.rp && np->nvalue.rp->fname && *np->nvalue.rp->fname=='/')
		{
			np->nvalue.rp->fdict = 0;
			flag = NV_NOFREE;
		}
		else
			_nv_unset(np,NV_RDONLY);
		nv_delete(np,root,flag|NV_FUNCTION);
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

void sh_subjobcheck(pid_t pid)
{
	register struct subshell *sp = subshell_data;
	while(sp)
	{
		if(sp->cpid==pid)
		{
			sh_close(sp->coutpipe);
			sh_close(sp->cpipe);
			sp->coutpipe = sp->cpipe = -1;
			return;
		}
		sp = sp->prev;
	}
}

/*
 * Run command tree <t> in a virtual sub-shell
 * If comsub is not null, then output will be placed in temp file (or buffer)
 * If comsub is not null, the return value will be a stream consisting of
 * output of command <t>.  Otherwise, NULL will be returned.
 */

Sfio_t *sh_subshell(Shell_t *shp,Shnode_t *t, volatile int flags, int comsub)
{
	struct subshell sub_data;
	register struct subshell *sp = &sub_data;
	int jmpval,nsig=0,duped=0;
	int savecurenv = shp->curenv;
	int savejobpgid = job.curpgid;
	int *saveexitval = job.exitval;
	int16_t subshell;
	char *savsig;
	Sfio_t *iop=0;
	struct checkpt buff;
	struct sh_scoped savst;
	struct dolnod   *argsav=0;
	int argcnt;
	memset((char*)sp, 0, sizeof(*sp));
	sfsync(shp->outpool);
	sh_sigcheck(shp);
	shp->savesig = -1;
	if(argsav = sh_arguse(shp))
		argcnt = argsav->dolrefcnt;
	if(shp->curenv==0)
	{
		subshell_data=0;
		subenv = 0;
	}
	shp->curenv = ++subenv;
	savst = shp->st;
	sh_pushcontext(shp,&buff,SH_JMPSUB);
	subshell = shp->subshell+1;
	SH_SUBSHELLNOD->nvalue.s = subshell;
	shp->subshell = subshell;
	sp->prev = subshell_data;
	sp->shp = shp;
	sp->sig = 0;
	subshell_data = sp;
	sp->errcontext = &buff.err;
	sp->var = shp->var_tree;
	sp->options = shp->options;
	sp->jobs = job_subsave();
	sp->subdup = shp->subdup;
#if SHOPT_COSHELL
	sp->coshell = shp->coshell;
	shp->coshell = 0;
#endif /* SHOPT_COSHELL */
	/* make sure initialization has occurred */ 
	if(!shp->pathlist)
	{
		shp->pathinit = 1;
		path_get(shp,".");
		shp->pathinit = 0;
	}
	sp->pathlist = path_dup((Pathcomp_t*)shp->pathlist);
	sp->pwdfd = -1;
	if(!shp->pwd)
		path_pwd(shp,0);
	sp->bckpid = shp->bckpid;
	if(comsub)
		sh_stats(STAT_COMSUB);
	else
		job.curpgid = 0;
	sp->subshare = shp->subshare;
	sp->comsub = shp->comsub;
	shp->subshare = comsub==2 ||  (comsub==1 && sh_isoption(SH_SUBSHARE));
	if(comsub)
		shp->comsub = comsub;
	if(!comsub || !shp->subshare)
	{
		struct subshell *xp;
		sp->shpwd = shp->pwd;
#ifdef _lib_fchdir
		for(xp=sp->prev; xp; xp=xp->prev) 
		{
			if(xp->pwdfd>0 && strcmp(xp->pwd,shp->pwd)==0)
			{
				sp->pwdfd = xp->pwdfd;
				break;
			}
		}
		if(sp->pwdfd<0)
		{
			int n = open(".",O_RDONLY);
			if(O_SEARCH && errno==EACCES)
				n =  open(".",O_RDONLY);
			if(n>=0)
			{
				sp->pwdfd = n;
				if(n<10)
				{
					sp->pwdfd =  fcntl(n,F_DUPFD,10);
					close(n);
				}
				if(sp->pwdfd>0)
				{
					fcntl(sp->pwdfd,F_SETFD,FD_CLOEXEC);
					sp->pwdclose = 1;
				}
			}
		}
#endif
		sp->pwd = (shp->pwd?strdup(shp->pwd):0);
		sp->mask = shp->mask;
		sh_stats(STAT_SUBSHELL);
		/* save trap table */
		shp->st.otrapcom = 0;
		shp->st.otrap = savst.trap;
		if((nsig=shp->st.trapmax*sizeof(char*))>0 || shp->st.trapcom[0])
		{
			nsig += sizeof(char*);
			memcpy(savsig=malloc(nsig),(char*)&shp->st.trapcom[0],nsig);
			/* this nonsense needed for $(trap) */
			shp->st.otrapcom = (char**)savsig;
		}
		sp->cpid = shp->cpid;
		sp->coutpipe = shp->coutpipe;
		sp->cpipe = shp->cpipe[1];
		shp->cpid = 0;
		sh_sigreset(0);
	}
	jmpval = sigsetjmp(buff.buff,0);
	if(jmpval==0)
	{
		if(comsub)
		{
			/* disable job control */
			shp->spid = 0;
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
			if(!(sp->nofork = sh_state(SH_NOFORK)))
				sh_onstate(SH_NOFORK);
			flags |= sh_state(SH_NOFORK);
		}
		else if(sp->prev)
		{
			sp->pipe = sp->prev->pipe;
			flags &= ~sh_state(SH_NOFORK);
		}
		if(shp->savesig < 0)
		{
			shp->savesig = 0;
			sh_exec(t,flags);
		}
	}
	if(comsub!=2 && jmpval!=SH_JMPSUB && shp->st.trapcom[0] && shp->subshell)
	{
		/* trap on EXIT not handled by child */
		char *trap=shp->st.trapcom[0];
		shp->st.trapcom[0] = 0;	/* prevent recursion */
		shp->oldexit = shp->exitval;
		sh_trap(trap,0);
		free(trap);
	}
	sh_popcontext(shp,&buff);
	if(shp->subshell==0)	/* must be child process */
	{
		subshell_data = sp->prev;
		if(jmpval==SH_JMPSCRIPT)
			siglongjmp(*shp->jmplist,jmpval);
		shp->exitval &= SH_EXITMASK;
		sh_done(shp,0);
	}
	if(!shp->savesig)
		shp->savesig = -1;
	nv_restore(sp);
	if(comsub)
	{
		/* re-enable job control */
		if(!sp->nofork)
			sh_offstate(SH_NOFORK);
		job.jobcontrol = sp->jobcontrol;
		if(sp->monitor)
			sh_onstate(SH_MONITOR);
		if(sp->pipefd>=0)
		{
			/* sftmp() file has been returned into pipe */
			iop = sh_iostream(shp,sp->pipefd);
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
				int fd=sfsetfd(iop,sh_get_unused_fd(shp, 3));
				if(fd<0)
				{
					shp->toomany = 1;
					((struct checkpt*)shp->jmplist)->mode = SH_JMPERREXIT;
					errormsg(SH_DICT,ERROR_system(1),e_toomany);
				}
				VALIDATE_FD(shp, fd);
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
			if (fcntl(sp->tmpfd,F_DUPFD,1) != 1)
				duped++;
			sh_close(sp->tmpfd);
		}
		shp->fdstatus[1] = sp->fdstatus;
	}
	path_delete((Pathcomp_t*)shp->pathlist);
	shp->pathlist = (void*)sp->pathlist;
	job_subrestore(sp->jobs);
	shp->jobenv = savecurenv;
	job.curpgid = savejobpgid;
	job.exitval = saveexitval;
	shp->bckpid = sp->bckpid;
	if(sp->shpwd)	/* restore environment if saved */
	{
		int n;
		shp->options = sp->options;
		if(sp->salias)
		{
			shp->alias_tree = dtview(sp->salias,0);
			table_unset(sp->salias,0);
			dtclose(sp->salias);
		}
		if(sp->sfun)
		{
			shp->fun_tree = dtview(sp->sfun,0);
			table_unset(sp->sfun,1);
			dtclose(sp->sfun);
		}
		n = shp->st.trapmax-savst.trapmax;
		sh_sigreset(1);
		if(n>0)
			memset(&shp->st.trapcom[savst.trapmax],0,n*sizeof(char*));
		shp->st = savst;
		shp->curenv = savecurenv;
		shp->st.otrap = 0;
		if(nsig)
		{
			memcpy((char*)&shp->st.trapcom[0],savsig,nsig);
			free((void*)savsig);
		}
		shp->options = sp->options;
		if(!shp->pwd || strcmp(sp->pwd,shp->pwd))
		{
			/* restore PWDNOD */
			Namval_t *pwdnod = sh_scoped(shp,PWDNOD);
			if(shp->pwd)
			{
				if(sp->pwdfd >=0)
				{
					if(fchdir(sp->pwdfd)<0)
						chdir(sp->pwd);
				}
				else
					chdir(sp->pwd);
				shp->pwd=sp->pwd;
				path_newdir(shp,shp->pathlist);
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
		if(sp->pwdclose)
			close(sp->pwdfd);
		if(sp->mask!=shp->mask)
			umask(shp->mask=sp->mask);
		if(shp->coutpipe!=sp->coutpipe)
		{
			sh_close(shp->coutpipe);
			sh_close(shp->cpipe[1]);
		}
		shp->cpid = sp->cpid;
		shp->cpipe[1] = sp->cpipe;
		shp->coutpipe = sp->coutpipe;
	}
	shp->subshare = sp->subshare;
	shp->comsub = sp->comsub;
	shp->subdup = sp->subdup;
#if SHOPT_COSHELL
	shp->coshell = sp->coshell;
#endif /* SHOPT_COSHELL */
	if(shp->subshell)
		SH_SUBSHELLNOD->nvalue.s = --shp->subshell;
	subshell = shp->subshell;
	subshell_data = sp->prev;
	if(!argsav  ||  argsav->dolrefcnt==argcnt)
		sh_argfree(shp,argsav,0);
	if(shp->topfd != buff.topfd)
		sh_iorestore(shp,buff.topfd|IOSUBSHELL,jmpval);
	if(sp->sig)
	{
		if(sp->prev)
			sp->prev->sig = sp->sig;
		else
		{
			kill(getpid(),sp->sig);
			sh_chktrap(shp);
		}
	}
	sh_sigcheck(shp);
	shp->trapnote = 0;
	nsig = shp->savesig;
	shp->savesig = 0;
	if(nsig>0)
		kill(getpid(),nsig);
	if(sp->subpid)
		job_wait(sp->subpid);
	if(comsub && iop && sp->pipefd<0)
		sfseek(iop,(off_t)0,SEEK_SET);
	if(shp->trapnote)
		sh_chktrap(shp);
	if(shp->exitval > SH_EXITSIG)
	{
		int sig = shp->exitval&SH_EXITMASK;
		if(sig==SIGINT || sig== SIGQUIT)
			kill(getpid(),sig);
	}
	if(duped)
	{
		((struct checkpt*)shp->jmplist)->mode = SH_JMPERREXIT;
		shp->toomany = 1;
		errormsg(SH_DICT,ERROR_system(1),e_redirect);
	}
	if(shp->ignsig)
		kill(getpid(),shp->ignsig);
	if(jmpval==SH_JMPSUB && shp->lastsig)
		kill(getpid(),shp->lastsig);
	if(jmpval && shp->toomany)
		siglongjmp(*shp->jmplist,jmpval);
	return(iop);
}
