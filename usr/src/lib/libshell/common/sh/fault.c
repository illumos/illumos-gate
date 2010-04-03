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
 * Fault handling routines
 *
 *   David Korn
 *   AT&T Labs
 *
 */

#include	"defs.h"
#include	<fcin.h>
#include	"io.h"
#include	"history.h"
#include	"shlex.h"
#include	"variables.h"
#include	"jobs.h"
#include	"path.h"
#include	"builtins.h"

#define abortsig(sig)	(sig==SIGABRT || sig==SIGBUS || sig==SIGILL || sig==SIGSEGV)

static char	indone;

#if !_std_malloc
#   include	<vmalloc.h>
#endif
#if  defined(VMFL) && (VMALLOC_VERSION>=20031205L)
    /*
     * This exception handler is called after vmalloc() unlocks the region
     */
    static int malloc_done(Vmalloc_t* vm, int type, Void_t* val, Vmdisc_t* dp)
    {
	dp->exceptf = 0;
	sh_exit(SH_EXITSIG);
	return(0);
    }
#endif

/*
 * Most signals caught or ignored by the shell come here
*/
void	sh_fault(register int sig)
{
	register Shell_t	*shp = sh_getinterp();
	register int 		flag=0;
	register char		*trap;
	register struct checkpt	*pp = (struct checkpt*)shp->jmplist;
	int	action=0;
	/* reset handler */
	if(!(sig&SH_TRAP))
		signal(sig, sh_fault);
	sig &= ~SH_TRAP;
#ifdef SIGWINCH
	if(sig==SIGWINCH)
	{
		int rows=0, cols=0;
		int32_t v;
		astwinsize(2,&rows,&cols);
		if(v = cols)
			nv_putval(COLUMNS, (char*)&v, NV_INT32|NV_RDONLY);
		if(v = rows)
			nv_putval(LINES, (char*)&v, NV_INT32|NV_RDONLY);
		shp->winch++;
	}
#endif  /* SIGWINCH */
	if(shp->savesig)
	{
		/* critical region, save and process later */
		shp->savesig = sig;
		return;
	}
	trap = shp->st.trapcom[sig];
	if(sig==SIGALRM && shp->bltinfun==b_sleep)
	{
		if(trap && *trap)
		{
			shp->trapnote |= SH_SIGTRAP;
			shp->sigflag[sig] |= SH_SIGTRAP;
		}
		return;
	}
	if(shp->subshell && sig!=SIGINT && sig!=SIGQUIT && sig!=SIGWINCH && sig!=SIGCONT)
	{
		shp->exitval = SH_EXITSIG|sig;
		sh_subfork();
		shp->exitval = 0;
		return;
	}
	/* handle ignored signals */
	if(trap && *trap==0)
		return;
	flag = shp->sigflag[sig]&~SH_SIGOFF;
	if(!trap)
	{
		if(sig==SIGINT && (shp->trapnote&SH_SIGIGNORE))
			return;
		if(flag&SH_SIGIGNORE)
			return;
		if(flag&SH_SIGDONE)
		{
			void *ptr=0;
			if((flag&SH_SIGINTERACTIVE) && sh_isstate(SH_INTERACTIVE) && !sh_isstate(SH_FORKED) && ! shp->subshell)
			{
				/* check for TERM signal between fork/exec */
				if(sig==SIGTERM && job.in_critical)
					shp->trapnote |= SH_SIGTERM;
				return;
			}
			shp->lastsig = sig;
			sigrelease(sig);
			if(pp->mode < SH_JMPFUN)
				pp->mode = SH_JMPFUN;
			else
				pp->mode = SH_JMPEXIT;
			if(sig==SIGABRT || (abortsig(sig) && (ptr = malloc(1))))
			{
				if(ptr)
					free(ptr);
				if(!shp->subshell)
					sh_done(shp,sig);
				sh_exit(SH_EXITSIG);
			}
			/* mark signal and continue */
			shp->trapnote |= SH_SIGSET;
			if(sig <= shp->sigmax)
				shp->sigflag[sig] |= SH_SIGSET;
#if  defined(VMFL) && (VMALLOC_VERSION>=20031205L)
			if(abortsig(sig))
			{
				/* abort inside malloc, process when malloc returns */
				/* VMFL defined when using vmalloc() */
				Vmdisc_t* dp = vmdisc(Vmregion,0);
				if(dp)
					dp->exceptf = malloc_done;
			}
#endif
			return;
		}
	}
	errno = 0;
	if(pp->mode==SH_JMPCMD)
		shp->lastsig = sig;
	if(trap)
	{
		/*
		 * propogate signal to foreground group
		 */
		if(sig==SIGHUP && job.curpgid)
			killpg(job.curpgid,SIGHUP);
		flag = SH_SIGTRAP;
	}
	else
	{
		shp->lastsig = sig;
		flag = SH_SIGSET;
#ifdef SIGTSTP
		if(sig==SIGTSTP)
		{
			shp->trapnote |= SH_SIGTSTP;
			if(pp->mode==SH_JMPCMD && sh_isstate(SH_STOPOK))
			{
				sigrelease(sig);
				sh_exit(SH_EXITSIG);
				flag = 0;
			}
		}
#endif /* SIGTSTP */
	}
#ifdef ERROR_NOTIFY
	if((error_info.flags&ERROR_NOTIFY) && shp->bltinfun)
		action = (*shp->bltinfun)(-sig,(char**)0,(void*)0);
	if(action>0)
		return;
#endif
	if(shp->bltinfun && shp->bltindata.notify)
	{
		shp->bltindata.sigset = 1;
		return;
	}
	shp->trapnote |= flag;
	if(sig <= shp->sigmax)
		shp->sigflag[sig] |= flag;
	if(pp->mode==SH_JMPCMD && sh_isstate(SH_STOPOK))
	{
		if(action<0)
			return;
		sigrelease(sig);
		sh_exit(SH_EXITSIG);
	}
}

/*
 * initialize signal handling
 */
void sh_siginit(void *ptr)
{
	Shell_t	*shp = (Shell_t*)ptr;
	register int sig, n;
	register const struct shtable2	*tp = shtab_signals;
	sig_begin();
	/* find the largest signal number in the table */
#if defined(SIGRTMIN) && defined(SIGRTMAX)
	if ((n = SIGRTMIN) > 0 && (sig = SIGRTMAX) > n && sig < SH_TRAP)
	{
		shp->sigruntime[SH_SIGRTMIN] = n;
		shp->sigruntime[SH_SIGRTMAX] = sig;
	}
#endif /* SIGRTMIN && SIGRTMAX */
	n = SIGTERM;
	while(*tp->sh_name)
	{
		sig = (tp->sh_number&((1<<SH_SIGBITS)-1));
		if (!(sig-- & SH_TRAP))
		{
			if ((tp->sh_number>>SH_SIGBITS) & SH_SIGRUNTIME)
				sig = shp->sigruntime[sig];
			if(sig>n && sig<SH_TRAP)
				n = sig;
		}
		tp++;
	}
	shp->sigmax = n++;
	shp->st.trapcom = (char**)calloc(n,sizeof(char*));
	shp->sigflag = (unsigned char*)calloc(n,1);
	shp->sigmsg = (char**)calloc(n,sizeof(char*));
	for(tp=shtab_signals; sig=tp->sh_number; tp++)
	{
		n = (sig>>SH_SIGBITS);
		if((sig &= ((1<<SH_SIGBITS)-1)) > (shp->sigmax+1))
			continue;
		sig--;
		if(n&SH_SIGRUNTIME)
			sig = shp->sigruntime[sig];
		if(sig>=0)
		{
			shp->sigflag[sig] = n;
			if(*tp->sh_name)
				shp->sigmsg[sig] = (char*)tp->sh_value;
		}
	}
}

/*
 * Turn on trap handler for signal <sig>
 */
void	sh_sigtrap(register int sig)
{
	register int flag;
	void (*fun)(int);
	sh.st.otrapcom = 0;
	if(sig==0)
		sh_sigdone();
	else if(!((flag=sh.sigflag[sig])&(SH_SIGFAULT|SH_SIGOFF)))
	{
		/* don't set signal if already set or off by parent */
		if((fun=signal(sig,sh_fault))==SIG_IGN) 
		{
			signal(sig,SIG_IGN);
			flag |= SH_SIGOFF;
		}
		else
		{
			flag |= SH_SIGFAULT;
			if(sig==SIGALRM && fun!=SIG_DFL && fun!=sh_fault)
				signal(sig,fun);
		}
		flag &= ~(SH_SIGSET|SH_SIGTRAP);
		sh.sigflag[sig] = flag;
	}
}

/*
 * set signal handler so sh_done is called for all caught signals
 */
void	sh_sigdone(void)
{
	register int 	flag, sig = sh.sigmax;
	sh.sigflag[0] |= SH_SIGFAULT;
	for(sig=sh.sigmax; sig>0; sig--)
	{
		flag = sh.sigflag[sig];
		if((flag&(SH_SIGDONE|SH_SIGIGNORE|SH_SIGINTERACTIVE)) && !(flag&(SH_SIGFAULT|SH_SIGOFF)))
			sh_sigtrap(sig);
	}
}

/*
 * Restore to default signals
 * Free the trap strings if mode is non-zero
 * If mode>1 then ignored traps cause signal to be ignored 
 */
void	sh_sigreset(register int mode)
{
	register char	*trap;
	register int 	flag, sig=sh.st.trapmax;
	while(sig-- > 0)
	{
		if(trap=sh.st.trapcom[sig])
		{
			flag  = sh.sigflag[sig]&~(SH_SIGTRAP|SH_SIGSET);
			if(*trap)
			{
				if(mode)
					free(trap);
				sh.st.trapcom[sig] = 0;
			}
			else if(sig && mode>1)
			{
				if(sig!=SIGCHLD)
					signal(sig,SIG_IGN);
				flag &= ~SH_SIGFAULT;
				flag |= SH_SIGOFF;
			}
			sh.sigflag[sig] = flag;
		}
	}
	for(sig=SH_DEBUGTRAP-1;sig>=0;sig--)
	{
		if(trap=sh.st.trap[sig])
		{
			if(mode)
				free(trap);
			sh.st.trap[sig] = 0;
		}
		
	}
	sh.st.trapcom[0] = 0;
	if(mode)
		sh.st.trapmax = 0;
	sh.trapnote=0;
}

/*
 * free up trap if set and restore signal handler if modified
 */
void	sh_sigclear(register int sig)
{
	register int flag = sh.sigflag[sig];
	register char *trap;
	sh.st.otrapcom=0;
	if(!(flag&SH_SIGFAULT))
		return;
	flag &= ~(SH_SIGTRAP|SH_SIGSET);
	if(trap=sh.st.trapcom[sig])
	{
		if(!sh.subshell)
			free(trap);
		sh.st.trapcom[sig]=0;
	}
	sh.sigflag[sig] = flag;
}

/*
 * check for traps
 */

void	sh_chktrap(void)
{
	register int 	sig=sh.st.trapmax;
	register char *trap;
	if(!(sh.trapnote&~SH_SIGIGNORE))
		sig=0;
	sh.trapnote &= ~SH_SIGTRAP;
	/* execute errexit trap first */
	if(sh_isstate(SH_ERREXIT) && sh.exitval)
	{
		int	sav_trapnote = sh.trapnote;
		sh.trapnote &= ~SH_SIGSET;
		if(sh.st.trap[SH_ERRTRAP])
		{
			trap = sh.st.trap[SH_ERRTRAP];
			sh.st.trap[SH_ERRTRAP] = 0;
			sh_trap(trap,0);
			sh.st.trap[SH_ERRTRAP] = trap;
		}
		sh.trapnote = sav_trapnote;
		if(sh_isoption(SH_ERREXIT))
		{
			struct checkpt	*pp = (struct checkpt*)sh.jmplist;
			pp->mode = SH_JMPEXIT;
			sh_exit(sh.exitval);
		}
	}
	if(sh.sigflag[SIGALRM]&SH_SIGALRM)
		sh_timetraps();
#ifdef SHOPT_BGX
	if((sh.sigflag[SIGCHLD]&SH_SIGTRAP) && sh.st.trapcom[SIGCHLD])
		job_chldtrap(&sh,sh.st.trapcom[SIGCHLD],1);
#endif /* SHOPT_BGX */
	while(--sig>=0)
	{
#ifdef SHOPT_BGX
		if(sig==SIGCHLD)
			continue;
#endif /* SHOPT_BGX */
		if(sh.sigflag[sig]&SH_SIGTRAP)
		{
			sh.sigflag[sig] &= ~SH_SIGTRAP;
			if(trap=sh.st.trapcom[sig])
			{
				Sfio_t *fp;
				if(sig==SIGPIPE && (fp=sfpool((Sfio_t*)0,sh.outpool,SF_WRITE)) && sferror(fp))
					sfclose(fp);
 				sh.oldexit = SH_EXITSIG|sig;
 				sh_trap(trap,0);
 			}
		}
	}
}


/*
 * parse and execute the given trap string, stream or tree depending on mode
 * mode==0 for string, mode==1 for stream, mode==2 for parse tree
 */
int sh_trap(const char *trap, int mode)
{
	Shell_t	*shp = sh_getinterp();
	int	jmpval, savxit = shp->exitval;
	int	was_history = sh_isstate(SH_HISTORY);
	int	was_verbose = sh_isstate(SH_VERBOSE);
	int	staktop = staktell();
	char	*savptr = stakfreeze(0);
	char	ifstable[256];
	struct	checkpt buff;
	Fcin_t	savefc;
	fcsave(&savefc);
	memcpy(ifstable,shp->ifstable,sizeof(ifstable));
	sh_offstate(SH_HISTORY);
	sh_offstate(SH_VERBOSE);
	shp->intrap++;
	sh_pushcontext(&buff,SH_JMPTRAP);
	jmpval = sigsetjmp(buff.buff,0);
	if(jmpval == 0)
	{
		if(mode==2)
			sh_exec((Shnode_t*)trap,sh_isstate(SH_ERREXIT));
		else
		{
			Sfio_t *sp;
			if(mode)
				sp = (Sfio_t*)trap;
			else
				sp = sfopen(NIL(Sfio_t*),trap,"s");
			sh_eval(sp,0);
		}
	}
	else if(indone)
	{
		if(jmpval==SH_JMPSCRIPT)
			indone=0;
		else
		{
			if(jmpval==SH_JMPEXIT)
				savxit = shp->exitval;
			jmpval=SH_JMPTRAP;
		}
	}
	sh_popcontext(&buff);
	shp->intrap--;
	sfsync(shp->outpool);
	if(!shp->indebug && jmpval!=SH_JMPEXIT && jmpval!=SH_JMPFUN)
		shp->exitval=savxit;
	stakset(savptr,staktop);
	fcrestore(&savefc);
	memcpy(shp->ifstable,ifstable,sizeof(ifstable));
	if(was_history)
		sh_onstate(SH_HISTORY);
	if(was_verbose)
		sh_onstate(SH_VERBOSE);
	exitset();
	if(jmpval>SH_JMPTRAP && (((struct checkpt*)shp->jmpbuffer)->prev || ((struct checkpt*)shp->jmpbuffer)->mode==SH_JMPSCRIPT))
		siglongjmp(*shp->jmplist,jmpval);
	return(shp->exitval);
}

/*
 * exit the current scope and jump to an earlier one based on pp->mode
 */
void sh_exit(register int xno)
{
	Shell_t	*shp = &sh;
	register struct checkpt	*pp = (struct checkpt*)shp->jmplist;
	register int		sig=0;
	register Sfio_t*	pool;
	shp->exitval=xno;
	if(xno==SH_EXITSIG)
		shp->exitval |= (sig=shp->lastsig);
#ifdef SIGTSTP
	if(shp->trapnote&SH_SIGTSTP)
	{
		/* ^Z detected by the shell */
		shp->trapnote = 0;
		shp->sigflag[SIGTSTP] = 0;
		if(!shp->subshell && sh_isstate(SH_MONITOR) && !sh_isstate(SH_STOPOK))
			return;
		if(sh_isstate(SH_TIMING))
			return;
		/* Handles ^Z for shell builtins, subshells, and functs */
		shp->lastsig = 0;
		sh_onstate(SH_MONITOR);
		sh_offstate(SH_STOPOK);
		shp->trapnote = 0;
		if(!shp->subshell && (sig=sh_fork(0,NIL(int*))))
		{
			job.curpgid = 0;
			job.parent = (pid_t)-1;
			job_wait(sig);
			job.parent = 0;
			shp->sigflag[SIGTSTP] = 0;
			/* wait for child to stop */
			shp->exitval = (SH_EXITSIG|SIGTSTP);
			/* return to prompt mode */
			pp->mode = SH_JMPERREXIT;
		}
		else
		{
			if(shp->subshell)
				sh_subfork();
			/* child process, put to sleep */
			sh_offstate(SH_STOPOK);
			sh_offstate(SH_MONITOR);
			shp->sigflag[SIGTSTP] = 0;
			/* stop child job */
			killpg(job.curpgid,SIGTSTP);
			/* child resumes */
			job_clear();
			shp->forked = 1;
			shp->exitval = (xno&SH_EXITMASK);
			return;
		}
	}
#endif /* SIGTSTP */
	/* unlock output pool */
	sh_offstate(SH_NOTRACK);
	if(!(pool=sfpool(NIL(Sfio_t*),shp->outpool,SF_WRITE)))
		pool = shp->outpool; /* can't happen? */
	sfclrlock(pool);
#ifdef SIGPIPE
	if(shp->lastsig==SIGPIPE)
		sfpurge(pool);
#endif /* SIGPIPE */
	sfclrlock(sfstdin);
	if(!pp)
		sh_done(shp,sig);
	shp->prefix = 0;
#if SHOPT_TYPEDEF
	shp->mktype = 0;
#endif /* SHOPT_TYPEDEF*/
	if(pp->mode == SH_JMPSCRIPT && !pp->prev) 
		sh_done(shp,sig);
	if(pp->mode)
		siglongjmp(pp->buff,pp->mode);
}

static void array_notify(Namval_t *np, void *data)
{
	Namarr_t	*ap = nv_arrayptr(np);
	NOT_USED(data);
	if(ap && ap->fun)
		(*ap->fun)(np, 0, NV_AFREE);
}

/*
 * This is the exit routine for the shell
 */

void sh_done(void *ptr, register int sig)
{
	Shell_t	*shp = (Shell_t*)ptr;
	register char *t;
	register int savxit = shp->exitval;
	shp->trapnote = 0;
	indone=1;
	if(sig)
		savxit = SH_EXITSIG|sig;
	if(shp->userinit)
		(*shp->userinit)(shp, -1);
	if(t=shp->st.trapcom[0])
	{
		shp->st.trapcom[0]=0; /*should free but not long */
		shp->oldexit = savxit;
		sh_trap(t,0);
		savxit = shp->exitval;
	}
	else
	{
		/* avoid recursive call for set -e */
		sh_offstate(SH_ERREXIT);
		sh_chktrap();
	}
	nv_scan(shp->var_tree,array_notify,(void*)0,NV_ARRAY,NV_ARRAY);
	sh_freeup(shp);
#if SHOPT_ACCT
	sh_accend();
#endif	/* SHOPT_ACCT */
#if SHOPT_VSH || SHOPT_ESH
	if(sh_isoption(SH_EMACS)||sh_isoption(SH_VI)||sh_isoption(SH_GMACS))
		tty_cooked(-1);
#endif
#ifdef JOBS
	if((sh_isoption(SH_INTERACTIVE) && shp->login_sh) || (!sh_isoption(SH_INTERACTIVE) && (sig==SIGHUP)))
		job_walk(sfstderr,job_terminate,SIGHUP,NIL(char**));
#endif	/* JOBS */
	job_close(shp);
	if(nv_search("VMTRACE", shp->var_tree,0))
		strmatch((char*)0,(char*)0);
	sfsync((Sfio_t*)sfstdin);
	sfsync((Sfio_t*)shp->outpool);
	sfsync((Sfio_t*)sfstdout);
	if(savxit&SH_EXITSIG)
		sig = savxit&SH_EXITMASK;
	if(sig)
	{
		/* generate fault termination code */
		signal(sig,SIG_DFL);
		sigrelease(sig);
		kill(getpid(),sig);
		pause();
	}
#if SHOPT_KIA
	if(sh_isoption(SH_NOEXEC))
		kiaclose((Lex_t*)shp->lex_context);
#endif /* SHOPT_KIA */
	exit(savxit&SH_EXITMASK);
}

