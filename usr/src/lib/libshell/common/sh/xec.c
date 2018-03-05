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
 * UNIX shell parse tree executer
 *
 *   David Korn
 *   AT&T Labs
 *
 */

#include	"defs.h"
#include	<fcin.h>
#include	"variables.h"
#include	"path.h"
#include	"name.h"
#include	"io.h"
#include	"shnodes.h"
#include	"jobs.h"
#include	"test.h"
#include	"builtins.h"
#include	"FEATURE/time"
#include	"FEATURE/externs"
#include	"FEATURE/locale"
#include	"streval.h"

#if !_std_malloc
#   include	<vmalloc.h>
#endif

#if     _lib_vfork
#   include     <ast_vfork.h>
#else
#   define vfork()      fork()
#endif

#define SH_NTFORK	SH_TIMING

#if _lib_nice
    extern int	nice(int);
#endif /* _lib_nice */
#if !_lib_spawnveg
#   define spawnveg(a,b,c,d)    spawnve(a,b,c)
#endif /* !_lib_spawnveg */
#if SHOPT_SPAWN
    static pid_t sh_ntfork(Shell_t*,const Shnode_t*,char*[],int*,int);
#endif /* SHOPT_SPAWN */

static void	sh_funct(Shell_t *,Namval_t*, int, char*[], struct argnod*,int);
static int	trim_eq(const char*, const char*);
static void	coproc_init(Shell_t*, int pipes[]);

static void	*timeout;
static char	pipejob;

struct funenv
{
	Namval_t	*node;
	struct argnod	*env;
};

/* ========	command execution	========*/

/*
 * print time <t> in h:m:s format with precision <p>
 */
static void     l_time(Sfio_t *outfile,register clock_t t,int p)
{
	register int  min, sec, frac;
	register int hr;
	if(p)
	{
		frac = t%sh.lim.clk_tck;
		frac = (frac*100)/sh.lim.clk_tck;
	}
	t /= sh.lim.clk_tck;
	sec = t%60;
	t /= 60;
	min = t%60;
	if(hr=t/60)
		sfprintf(outfile,"%dh",hr);
	if(p)
		sfprintf(outfile,"%dm%d%c%0*ds",min,sec,GETDECIMAL(0),p,frac);
	else
		sfprintf(outfile,"%dm%ds",min,sec);
}

static int p_time(Shell_t *shp, Sfio_t *out, const char *format, clock_t *tm)
{
	int		c,p,l,n,offset = staktell();
	const char	*first;
	double		d;
	Stk_t		*stkp = shp->stk;
	for(first=format ; c= *format; format++)
	{
		if(c!='%')
			continue;
		sfwrite(stkp, first, format-first);
		n = l = 0;
		p = 3;
		if((c= *++format) == '%')
		{
			first = format;
			continue;
		}
		if(c>='0' && c <='9')
		{
			p = (c>'3')?3:(c-'0');
			c = *++format;
		}
		else if(c=='P')
		{
			if(d=tm[0])
				d = 100.*(((double)(tm[1]+tm[2]))/d);
			p = 2;
			goto skip;
		}
		if(c=='l')
		{
			l = 1;
			c = *++format;
		}
		if(c=='U')
			n = 1;
		else if(c=='S')
			n = 2;
		else if(c!='R')
		{
			stkseek(stkp,offset);
			errormsg(SH_DICT,ERROR_exit(0),e_badtformat,c);
			return(0);
		}
		d = (double)tm[n]/sh.lim.clk_tck;
	skip:
		if(l)
			l_time(stkp, tm[n], p);
		else
			sfprintf(stkp,"%.*f",p, d);
		first = format+1;
	}
	if(format>first)
		sfwrite(stkp,first, format-first);
	sfputc(stkp,'\n');
	n = stktell(stkp)-offset;
	sfwrite(out,stkptr(stkp,offset),n);
	stkseek(stkp,offset);
	return(n);
}

#if SHOPT_OPTIMIZE
/*
 * clear argument pointers that point into the stack
 */
static int p_arg(struct argnod*,int);
static int p_switch(struct regnod*);
static int p_comarg(register struct comnod *com)
{
	Namval_t *np=com->comnamp;
	int n = p_arg(com->comset,ARG_ASSIGN);
	if(com->comarg && (com->comtyp&COMSCAN))
		n+= p_arg(com->comarg,0);
	if(com->comstate  && np)
	{
		/* call builtin to cleanup state */
		Shbltin_t *bp = &sh.bltindata;
		void  *save_ptr = bp->ptr;
		void  *save_data = bp->data;
		bp->bnode = np;
		bp->vnode = com->comnamq;
		bp->ptr = nv_context(np);
		bp->data = com->comstate;
		bp->flags = SH_END_OPTIM;
		(*funptr(np))(0,(char**)0, bp);
		bp->ptr = save_ptr;
		bp->data = save_data;
	}
	com->comstate = 0;
	if(com->comarg && !np)
		n++;
	return(n);
}

extern void sh_optclear(Shell_t*, void*);

static int sh_tclear(register Shnode_t *t)
{
	int n=0;
	if(!t)
		return(0);
	switch(t->tre.tretyp&COMMSK)
	{
		case TTIME:
		case TPAR:
			return(sh_tclear(t->par.partre)); 
		case TCOM:
			return(p_comarg((struct comnod*)t));
		case TSETIO:
		case TFORK:
			return(sh_tclear(t->fork.forktre));
		case TIF:
			n=sh_tclear(t->if_.iftre);
			n+=sh_tclear(t->if_.thtre);
			n+=sh_tclear(t->if_.eltre);
			return(n);
		case TWH:
			if(t->wh.whinc)
				n=sh_tclear((Shnode_t*)(t->wh.whinc));
			n+=sh_tclear(t->wh.whtre);
			n+=sh_tclear(t->wh.dotre);
			return(n);
		case TLST:
		case TAND:
		case TORF:
		case TFIL:
			n=sh_tclear(t->lst.lstlef);
			return(n+sh_tclear(t->lst.lstrit));
		case TARITH:
			return(p_arg(t->ar.arexpr,ARG_ARITH));
		case TFOR:
			n=sh_tclear(t->for_.fortre);
			return(n+sh_tclear((Shnode_t*)t->for_.forlst));
		case TSW:
			n=p_arg(t->sw.swarg,0);
			return(n+p_switch(t->sw.swlst));
		case TFUN:
			n=sh_tclear(t->funct.functtre);
			return(n+sh_tclear((Shnode_t*)t->funct.functargs));
		case TTST:
			if((t->tre.tretyp&TPAREN)==TPAREN)
				return(sh_tclear(t->lst.lstlef)); 
			else
			{
				n=p_arg(&(t->lst.lstlef->arg),0);
				if(t->tre.tretyp&TBINARY)
					n+=p_arg(&(t->lst.lstrit->arg),0);
			}
	}
	return(n);
}

static int p_arg(register struct argnod *arg,int flag)
{
	while(arg)
	{
		if(strlen(arg->argval) || (arg->argflag==ARG_RAW))
			arg->argchn.ap = 0;
		else if(flag==0)
			sh_tclear((Shnode_t*)arg->argchn.ap);
		else
			sh_tclear(((struct fornod*)arg->argchn.ap)->fortre);
		arg = arg->argnxt.ap;
	}
	return(0);
}

static int p_switch(register struct regnod *reg)
{
	int n=0;
	while(reg)
	{
		n+=p_arg(reg->regptr,0);
		n+=sh_tclear(reg->regcom);
		reg = reg->regnxt;
	}
	return(n);
}
#   define OPTIMIZE_FLAG	(ARG_OPTIMIZE)
#   define OPTIMIZE		(flags&OPTIMIZE_FLAG)
#else
#   define OPTIMIZE_FLAG	(0)
#   define OPTIMIZE		(0)
#   define sh_tclear(x)
#endif /* SHOPT_OPTIMIZE */

static void out_pattern(Sfio_t *iop, register const char *cp, int n)
{
	register int c;
	do
	{
		switch(c= *cp)
		{
		    case 0:
			if(n<0)
				return;
			c = n;
			break;
		    case '\n':
			sfputr(iop,"$'\\n",'\'');
			continue;
		    case '\\':
			if (!(c = *++cp))
				c = '\\';
			/*FALLTHROUGH*/
		    case ' ':
		    case '<': case '>': case ';':
		    case '$': case '`': case '\t':
			sfputc(iop,'\\');
			break;
		}
		sfputc(iop,c);
	}
	while(*cp++);
}

static void out_string(Sfio_t *iop, register const char *cp, int c, int quoted)
{
	if(quoted)
	{
		int n = stktell(stkstd);
		cp = sh_fmtq(cp);
		if(iop==stkstd && cp==stkptr(stkstd,n))
		{
			*stkptr(stkstd,stktell(stkstd)-1) = c;
			return;
		}
	}
	sfputr(iop,cp,c);
}

struct Level
{
	Namfun_t	hdr;
	short		maxlevel;
};

/*
 * this is for a debugger but it hasn't been tested yet
 * if a debug script sets .sh.level it should set up the scope
 *  as if you were executing in that level
 */ 
static void put_level(Namval_t* np,const char *val,int flags,Namfun_t *fp)
{
	Shscope_t	*sp;
	struct Level *lp = (struct Level*)fp;
	int16_t level, oldlevel = (int16_t)nv_getnum(np);
	nv_putv(np,val,flags,fp);
	if(!val)
	{
		fp = nv_stack(np, NIL(Namfun_t*));
		if(fp && !fp->nofree)
			free((void*)fp);
		return;
	}
	level = nv_getnum(np);
	if(level<0 || level > lp->maxlevel)
	{
		nv_putv(np, (char*)&oldlevel, NV_INT16, fp);
		/* perhaps this should be an error */
		return;
	}
	if(level==oldlevel)
		return;
	if(sp = sh_getscope(level,SEEK_SET))
	{
		sh_setscope(sp);
		error_info.id = sp->cmdname;
		
	}
}

static const Namdisc_t level_disc = {  sizeof(struct Level), put_level };

static struct Level *init_level(int level)
{
	struct Level *lp = newof(NiL,struct Level,1,0);
	lp->maxlevel = level;
	_nv_unset(SH_LEVELNOD,0);
	nv_onattr(SH_LEVELNOD,NV_INT16|NV_NOFREE);
	nv_putval(SH_LEVELNOD,(char*)&lp->maxlevel,NV_INT16);
	lp->hdr.disc = &level_disc;
	nv_disc(SH_LEVELNOD,&lp->hdr,NV_FIRST);
	return(lp);
}

/*
 * write the current common on the stack and make it available as .sh.command
 */
int sh_debug(Shell_t *shp, const char *trap, const char *name, const char *subscript, char *const argv[], int flags)
{
	Stk_t			*stkp=shp->stk;
	struct sh_scoped	savst;
	Namval_t		*np = SH_COMMANDNOD;
	char			*sav = stkptr(stkp,0);
	int			n=4, offset=stktell(stkp);
	const char		*cp = "+=( ";
	Sfio_t			*iop = stkstd;
	short			level;
	if(shp->indebug)
		return(0);
	shp->indebug = 1;
	if(name)
	{
		sfputr(iop,name,-1);
		if(subscript)
		{
			sfputc(iop,'[');
			out_string(iop,subscript,']',1);
		}
		if(!(flags&ARG_APPEND))
			cp+=1, n-=1;
		if(!(flags&ARG_ASSIGN))
			n -= 2;
		sfwrite(iop,cp,n);
	}
	if(*argv && !(flags&ARG_RAW))
		out_string(iop, *argv++,' ', 0);
	n = (flags&ARG_ARITH);
	while(cp = *argv++)
	{
		if((flags&ARG_EXP) && argv[1]==0)
			out_pattern(iop, cp,' ');
		else
			out_string(iop, cp,' ',n?0: (flags&(ARG_RAW|ARG_NOGLOB))||*argv);
	}
	if(flags&ARG_ASSIGN)
		sfputc(iop,')');
	else if(iop==stkstd)
		*stkptr(stkp,stktell(stkp)-1) = 0;
	np->nvalue.cp = stkfreeze(stkp,1);
	/* now setup .sh.level variable */
	shp->st.lineno = error_info.line;
	level  = shp->fn_depth+shp->dot_depth;
	if(!SH_LEVELNOD->nvfun || !SH_LEVELNOD->nvfun->disc || nv_isattr(SH_LEVELNOD,NV_INT16|NV_NOFREE)!=(NV_INT16|NV_NOFREE))
		init_level(level);
	else
		nv_putval(SH_LEVELNOD,(char*)&level,NV_INT16);
	savst = shp->st;
	shp->st.trap[SH_DEBUGTRAP] = 0;
	n = sh_trap(trap,0);
	np->nvalue.cp = 0;
	shp->indebug = 0;
	if(shp->st.cmdname)
		error_info.id = shp->st.cmdname;
	nv_putval(SH_PATHNAMENOD,shp->st.filename,NV_NOFREE);
	nv_putval(SH_FUNNAMENOD,shp->st.funname,NV_NOFREE);
	shp->st = savst;
	if(sav != stkptr(stkp,0))
		stkset(stkp,sav,0);
	else
		stkseek(stkp,offset);
	return(n);
}

/*
 * Given stream <iop> compile and execute
 */
int sh_eval(register Sfio_t *iop, int mode)
{
	register Shnode_t *t;
	Shell_t  *shp = sh_getinterp();
	struct slnod *saveslp = shp->st.staklist;
	int jmpval;
	struct checkpt *pp = (struct checkpt*)shp->jmplist;
	struct checkpt buff;
	static Sfio_t *io_save;
	volatile int traceon=0, lineno=0;
	int binscript=shp->binscript;
	io_save = iop; /* preserve correct value across longjmp */
	shp->binscript = 0;
#define SH_TOPFUN	0x8000	/* this is a temporary tksh hack */
	if (mode & SH_TOPFUN)
	{
		mode ^= SH_TOPFUN;
		shp->fn_reset = 1;
	}
	sh_pushcontext(&buff,SH_JMPEVAL);
	buff.olist = pp->olist;
	jmpval = sigsetjmp(buff.buff,0);
	while(jmpval==0)
	{
		if(mode&SH_READEVAL)
		{
			lineno = shp->inlineno;
			if(traceon=sh_isoption(SH_XTRACE))
				sh_offoption(SH_XTRACE);
		}
		t = (Shnode_t*)sh_parse(shp,iop,(mode&(SH_READEVAL|SH_FUNEVAL))?mode&SH_FUNEVAL:SH_NL);
		if(!(mode&SH_FUNEVAL) || !sfreserve(iop,0,0))
		{
			if(!(mode&SH_READEVAL))
				sfclose(iop);
			io_save = 0;
			mode &= ~SH_FUNEVAL;
		}
		mode &= ~SH_READEVAL;
		if(!sh_isoption(SH_VERBOSE))
			sh_offstate(SH_VERBOSE);
		if((mode&~SH_FUNEVAL) && shp->hist_ptr)
		{
			hist_flush(shp->hist_ptr);
			mode = sh_state(SH_INTERACTIVE);
		}
		sh_exec(t,sh_isstate(SH_ERREXIT)|sh_isstate(SH_NOFORK)|(mode&~SH_FUNEVAL));
		if(!(mode&SH_FUNEVAL))
			break;
	}
	sh_popcontext(&buff);
	shp->binscript = binscript;
	if(traceon)
		sh_onoption(SH_XTRACE);
	if(lineno)
		shp->inlineno = lineno;
	if(io_save)
		sfclose(io_save);
	sh_freeup(shp);
	shp->st.staklist = saveslp;
	shp->fn_reset = 0;
	if(jmpval>SH_JMPEVAL)
		siglongjmp(*shp->jmplist,jmpval);
	return(shp->exitval);
}

#if SHOPT_FASTPIPE
static int pipe_exec(Shell_t* shp,int pv[], Shnode_t *t, int errorflg)
{
	struct checkpt buff;
	register Shnode_t *tchild = t->fork.forktre;
	Namval_t *np;
	int jmpval;
	volatile Sfio_t *iop;
	volatile int r;
	if((tchild->tre.tretyp&COMMSK)!=TCOM || !(np=(Namval_t*)(tchild->com.comnamp)))
	{
		sh_pipe(pv);
		return(sh_exec(t,errorflg));
	}
	pv[0] = shp->lim.open_max;
	shp->fdstatus[pv[0]] = IOREAD|IODUP|IOSEEK;
	pv[1] = shp->lim.open_max+1;
	shp->fdstatus[pv[1]] = IOWRITE|IOSEEK;
	iop = sftmp(IOBSIZE+1);
	shp->sftable[shp->lim.open_max+1] = iop;
	sh_pushcontext(&buff,SH_JMPIO);
	if(t->tre.tretyp&FPIN)
		sh_iosave(shp,0,shp->topfd,(char*)0);
	sh_iosave(shp,1,shp->topfd,(char*)0);
	jmpval = sigsetjmp(buff.buff,0);
	if(jmpval==0)
	{
		if(t->tre.tretyp&FPIN)
			sh_iorenumber(shp,shp->inpipe[0],0);
		sh_iorenumber(shp,shp->lim.open_max+1,1);
		r = sh_exec(tchild,errorflg);
		if(sffileno(sfstdout)>=0)
			pv[0] = sfsetfd(sfstdout,10);
		iop = sfswap(sfstdout,0);
	}
	sh_popcontext(&buff);
	shp->sftable[pv[0]] = iop;
	shp->fdstatus[pv[0]] = IOREAD|IODUP|IOSEEK;
	sfset(iop,SF_WRITE,0);
	sfseek(iop,0L,SEEK_SET);
	sh_iorestore(shp,buff.topfd,jmpval);
	if(jmpval>SH_JMPIO)
		siglongjmp(*shp->jmplist,jmpval);
	return(r);
}
#endif /* SHOPT_FASTPIPE */

/*
 * returns 1 when option -<c> is specified
 */
static int checkopt(char *argv[], int c)
{
	char *cp;
	while(cp = *++argv)
	{
		if(*cp=='+')
			continue;
		if(*cp!='-' || cp[1]=='-')
			break;
		if(strchr(++cp,c))
			return(1);
		if(*cp=='h' && cp[1]==0 && *++argv==0)
			break;
	}
	return(0);
}

static void free_list(struct openlist *olist)
{
	struct openlist *item,*next;
	for(item=olist;item;item=next)
	{
		next = item->next;
		free((void*)item);
	}
}

/*
 * set ${.sh.name} and ${.sh.subscript}
 * set _ to reference for ${.sh.name}[$.sh.subscript]
 */
static int set_instance(Shell_t *shp,Namval_t *nq, Namval_t *node, struct Namref *nr)
{
	char		*sp=0,*cp = nv_name(nq);
	Namarr_t	*ap;
	memset(nr,0,sizeof(*nr));
	nr->np = nq;
	nr->root = sh.var_tree;
	nr->table = sh.last_table;
	shp->instance = 1;
	if((ap=nv_arrayptr(nq)) && (sp = nv_getsub(nq)))
		sp = strdup(sp);
	shp->instance = 0;
	if(sh.var_tree!=sh.var_base && !nv_open(cp,nr->root,NV_VARNAME|NV_NOREF|NV_NOSCOPE|NV_NOADD|NV_NOFAIL))
		nr->root = sh.var_base;
	nv_putval(SH_NAMENOD, cp, NV_NOFREE);
	memcpy(node,L_ARGNOD,sizeof(*node));
	L_ARGNOD->nvalue.nrp = nr;
	L_ARGNOD->nvflag = NV_REF|NV_NOFREE;
	L_ARGNOD->nvfun = 0;
	L_ARGNOD->nvenv = 0;
	if(sp)
	{
		nv_putval(SH_SUBSCRNOD,nr->sub=sp,NV_NOFREE);
		return(ap->nelem&ARRAY_SCAN);
	}
	return(0);
}

static void unset_instance(Namval_t *nq, Namval_t *node, struct Namref *nr,long mode)
{
	L_ARGNOD->nvalue.nrp = node->nvalue.nrp;
	L_ARGNOD->nvflag = node->nvflag;
	L_ARGNOD->nvfun = node->nvfun;
	if(nr->sub)
	{
		nv_putsub(nq, nr->sub, mode);
		free((void*)nr->sub);
	}
	nv_unset(SH_NAMENOD);
	nv_unset(SH_SUBSCRNOD);
}

int sh_exec(register const Shnode_t *t, int flags)
{
	register Shell_t	*shp = &sh;
	Stk_t			*stkp = shp->stk;
	sh_sigcheck();
	if(t && !shp->st.execbrk && !sh_isoption(SH_NOEXEC))
	{
		register int 	type = flags;
		register char	*com0 = 0;
		int 		errorflg = (type&sh_state(SH_ERREXIT))|OPTIMIZE;
		int 		execflg = (type&sh_state(SH_NOFORK));
		int 		execflg2 = (type&sh_state(SH_FORKED));
		int 		mainloop = (type&sh_state(SH_INTERACTIVE));
#if SHOPT_AMP || SHOPT_SPAWN
		int		ntflag = (type&sh_state(SH_NTFORK));
#else
		int		ntflag = 0;
#endif
		int		topfd = shp->topfd;
		char 		*sav=stkptr(stkp,0);
		char		*cp=0, **com=0, *comn;
		int		argn;
		int 		skipexitset = 0;
		int		was_interactive = 0;
		int		was_errexit = sh_isstate(SH_ERREXIT);
		int		was_monitor = sh_isstate(SH_MONITOR);
		int		echeck = 0;
		if(flags&sh_state(SH_INTERACTIVE))
		{
			if(pipejob==2)
				job_unlock();
			pipejob = 0;
			job.curpgid = 0;
			flags &= ~sh_state(SH_INTERACTIVE);
		}
		sh_offstate(SH_ERREXIT);
		sh_offstate(SH_DEFPATH);
		if(was_errexit&flags)
			sh_onstate(SH_ERREXIT);
		if(was_monitor&flags)
			sh_onstate(SH_MONITOR);
		type = t->tre.tretyp;
		if(!shp->intrap)
			shp->oldexit=shp->exitval;
		shp->exitval=0;
		shp->lastsig = 0;
		shp->lastpath = 0;
		switch(type&COMMSK)
		{
		    case TCOM:
		    {
			register struct argnod	*argp;
			char		*trap;
			Namval_t	*np, *nq, *last_table;
			struct ionod	*io;
			int		command=0, flgs=NV_ASSIGN;
			shp->bltindata.invariant = type>>(COMBITS+2);
			type &= (COMMSK|COMSCAN);
			sh_stats(STAT_SCMDS);
			error_info.line = t->com.comline-shp->st.firstline;
			com = sh_argbuild(shp,&argn,&(t->com),OPTIMIZE);
			echeck = 1;
			if(t->tre.tretyp&COMSCAN)
			{
				argp = t->com.comarg;
				if(argp && *com && !(argp->argflag&ARG_RAW))
					sh_sigcheck();
			}
			np = (Namval_t*)(t->com.comnamp);
			nq = (Namval_t*)(t->com.comnamq);
			com0 = com[0];
			shp->xargexit = 0;
			while(np==SYSCOMMAND)
			{
				register int n = b_command(0,com,&shp->bltindata);
				if(n==0)
					break;
				command += n;
				np = 0;
				if(!(com0= *(com+=n)))
					break;
				np = nv_bfsearch(com0, shp->bltin_tree, &nq, &cp); 
			}
			if(shp->xargexit)
			{
				shp->xargmin -= command;
				shp->xargmax -= command;
			}
			else
				shp->xargmin = 0;
			argn -= command;
			if(!command && np && is_abuiltin(np))
				np = dtsearch(shp->fun_tree,np);
			if(com0)
			{
				if(!np && !strchr(com0,'/'))
				{
					Dt_t *root = command?shp->bltin_tree:shp->fun_tree;
					np = nv_bfsearch(com0, root, &nq, &cp); 
#if SHOPT_NAMESPACE
					if(shp->namespace && !nq && !cp)
					{
						int offset = stktell(stkp);
						sfputr(stkp,nv_name(shp->namespace),-1);
						sfputc(stkp,'.');
						sfputr(stkp,com0,0);
						stkseek(stkp,offset);
						np = nv_bfsearch(stkptr(stkp,offset), root, &nq, &cp); 
					}
#endif /* SHOPT_NAMESPACE */
				}
				comn = com[argn-1];
			}
			io = t->tre.treio;
			if(shp->envlist = argp = t->com.comset)
			{
				if(argn==0 || (np && nv_isattr(np,BLT_SPC)))
				{
					Namval_t *tp=0;
					if(argn)
					{
						if(checkopt(com,'A'))
							flgs |= NV_ARRAY;
						else if(checkopt(com,'a'))
							flgs |= NV_IARRAY;
					}
#if SHOPT_BASH
					if(np==SYSLOCAL)
					{
						if(!nv_getval(SH_FUNNAMENOD))
							errormsg(SH_DICT,ERROR_exit(1),"%s: can only be used in a function",com0);
						if(!shp->st.var_local)
						{
							sh_scope(shp,(struct argnod*)0,0);
							shp->st.var_local = shp->var_tree;
						}
			
					}
					if(np==SYSTYPESET || np==SYSLOCAL)
#else
					if(np==SYSTYPESET ||  (np && np->nvalue.bfp==SYSTYPESET->nvalue.bfp))
#endif
					{
						if(np!=SYSTYPESET)
						{
							shp->typeinit = np;
							tp = nv_type(np);
						}
						if(checkopt(com,'C'))
							flgs |= NV_COMVAR;
						if(checkopt(com,'S'))
							flgs |= NV_STATIC;
						if(checkopt(com,'n'))
							flgs |= NV_NOREF;
						else if(!shp->typeinit && (checkopt(com,'L') || checkopt(com,'R') || checkopt(com,'Z')))
							flgs |= NV_UNJUST;
#if SHOPT_TYPEDEF
						else if(argn>=3 && checkopt(com,'T'))
						{
							shp->prefix = NV_CLASS;
							flgs |= NV_TYPE;
			
						}
#endif /* SHOPT_TYPEDEF */
						if((shp->fn_depth && !shp->prefix) || np==SYSLOCAL)
							flgs |= NV_NOSCOPE;
					}
					else if(np==SYSEXPORT)
						flgs |= NV_EXPORT;
					if(flgs&(NV_EXPORT|NV_NOREF))
						flgs |= NV_IDENT;
					else
						flgs |= NV_VARNAME;
#if 0
					if(OPTIMIZE)
						flgs |= NV_TAGGED;
#endif
					nv_setlist(argp,flgs,tp);
					if(np==shp->typeinit)
						shp->typeinit = 0;
					shp->envlist = argp;
					argp = NULL;
				}
			}
			last_table = shp->last_table;
			shp->last_table = 0;
			if((io||argn))
			{
				Shbltin_t *bp=0;
				static char *argv[1];
				int tflags = 1;
				if(np &&  nv_isattr(np,BLT_DCL))
					tflags |= 2;
				if(argn==0)
				{
					/* fake 'true' built-in */
					np = SYSTRUE;
					*argv = nv_name(np);
					com = argv;
				}
				/* set +x doesn't echo */
				else if((np!=SYSSET) && sh_isoption(SH_XTRACE))
					sh_trace(com-command,tflags);
				else if((t->tre.tretyp&FSHOWME) && sh_isoption(SH_SHOWME))
				{
					int ison = sh_isoption(SH_XTRACE);
					if(!ison)
						sh_onoption(SH_XTRACE);
					sh_trace(com-command,tflags);
					if(io)
						sh_redirect(shp,io,SH_SHOWME);
					if(!ison)
						sh_offoption(SH_XTRACE);
					break;
				}
				if(trap=shp->st.trap[SH_DEBUGTRAP])
				{
					int n = sh_debug(shp,trap,(char*)0,(char*)0, com, ARG_RAW);
					if(n==255 && shp->fn_depth+shp->dot_depth)
					{
						np = SYSRETURN;
						argn = 1;
						com[0] = np->nvname;
						com[1] = 0;
						io = 0;
						argp = 0;
					}
					else if(n==2)
						break;
				}
				if(io)
					sfsync(shp->outpool);
				shp->lastpath = 0;
				if(!np  && !strchr(com0,'/'))
				{
					if(path_search(com0,NIL(Pathcomp_t**),1))
					{
						error_info.line = t->com.comline-shp->st.firstline;
						if((np=nv_search(com0,shp->fun_tree,0)) && !np->nvalue.ip)
						{
							Namval_t *mp=nv_search(com0,shp->bltin_tree,0);
							if(mp)
								np = mp;
						}
					}
					else
					{
						if((np=nv_search(com0,shp->track_tree,0)) && !nv_isattr(np,NV_NOALIAS) && np->nvalue.cp)
							np=nv_search(nv_getval(np),shp->bltin_tree,0);
						else
							np = 0;
					}
				}
				if(np && pipejob==2)
				{
					job_unlock();
					pipejob = 1;
				}
				/* check for builtins */
				if(np && is_abuiltin(np))
				{
					volatile int scope=0, share=0;
					volatile void *save_ptr;
					volatile void *save_data;
					int jmpval, save_prompt;
					int was_nofork = execflg?sh_isstate(SH_NOFORK):0;
					struct checkpt buff;
					unsigned long was_vi=0, was_emacs=0, was_gmacs=0;
					struct stat statb;
					bp = &shp->bltindata;
					save_ptr = bp->ptr;
					save_data = bp->data;
					memset(&statb, 0, sizeof(struct stat));
					if(strchr(nv_name(np),'/'))
					{
						/*
						 * disable editors for built-in
						 * versions of commands on PATH
						 */
						was_vi = sh_isoption(SH_VI);
						was_emacs = sh_isoption(SH_EMACS);
						was_gmacs = sh_isoption(SH_GMACS);
						sh_offoption(SH_VI);
						sh_offoption(SH_EMACS);
						sh_offoption(SH_GMACS);
					}
					if(execflg)
						sh_onstate(SH_NOFORK);
					sh_pushcontext(&buff,SH_JMPCMD);
					jmpval = sigsetjmp(buff.buff,1);
					if(jmpval == 0)
					{
						if(!(nv_isattr(np,BLT_ENV)))
							error_info.flags |= ERROR_SILENT;
						errorpush(&buff.err,0);
						if(io)
						{
							struct openlist *item;
							if(np==SYSLOGIN)
								type=1;
							else if(np==SYSEXEC)
								type=1+!com[1];
							else
								type = (execflg && !shp->subshell && !shp->st.trapcom[0]);
							sh_redirect(shp,io,type);
							for(item=buff.olist;item;item=item->next)
								item->strm=0;
						}
						if(!(nv_isattr(np,BLT_ENV)))
						{
							if(bp->nosfio)
							{
								if(!shp->pwd)
									path_pwd(0);
								if(shp->pwd)
									stat(".",&statb);
							}
							sfsync(NULL);
							share = sfset(sfstdin,SF_SHARE,0);
							sh_onstate(SH_STOPOK);
							sfpool(sfstderr,NIL(Sfio_t*),SF_WRITE);
							sfset(sfstderr,SF_LINE,1);
							save_prompt = shp->nextprompt;
							shp->nextprompt = 0;
						}
						if(argp)
						{
							scope++;
							sh_scope(shp,argp,0);
						}
						opt_info.index = opt_info.offset = 0;
						opt_info.disc = 0;
						error_info.id = *com;
						if(argn)
							shp->exitval = 0;
						shp->bltinfun = funptr(np);
						bp->bnode = np;
						bp->vnode = nq;
						bp->ptr = nv_context(np);
						bp->data = t->com.comstate;
						bp->sigset = 0;
						bp->notify = 0;
						bp->flags = (OPTIMIZE!=0);
						if(shp->subshell && nv_isattr(np,BLT_NOSFIO))
							sh_subtmpfile(0);
						if(execflg && !shp->subshell &&
							!shp->st.trapcom[0] && !shp->st.trap[SH_ERRTRAP] && shp->fn_depth==0 && !nv_isattr(np,BLT_ENV))
						{
							/* do close-on-exec */
							int fd;
							for(fd=0; fd < shp->lim.open_max; fd++)
								if((shp->fdstatus[fd]&IOCLEX)&&fd!=shp->infd)
									sh_close(fd);
						}
						if(argn)
							shp->exitval = (*shp->bltinfun)(argn,com,(void*)bp);
						if(error_info.flags&ERROR_INTERACTIVE)
							tty_check(ERRIO);
						((Shnode_t*)t)->com.comstate = shp->bltindata.data;
						bp->data = (void*)save_data;
						if(!nv_isattr(np,BLT_EXIT) && shp->exitval!=SH_RUNPROG)
							shp->exitval &= SH_EXITMASK;
					}
					else
					{
						struct openlist *item;
						for(item=buff.olist;item;item=item->next)
						{
							if(item->strm)
							{
								sfclrlock(item->strm);
								if(shp->hist_ptr && item->strm == shp->hist_ptr->histfp)
									hist_close(shp->hist_ptr);
								else
									sfclose(item->strm);
							}
						}
						if(shp->bltinfun && (error_info.flags&ERROR_NOTIFY))
							(*shp->bltinfun)(-2,com,(void*)bp);
						/* failure on special built-ins fatal */
						if(jmpval<=SH_JMPCMD  && (!nv_isattr(np,BLT_SPC) || command))
							jmpval=0;
					}
					if(bp && bp->ptr!= nv_context(np))
						np->nvfun = (Namfun_t*)bp->ptr;
					if(execflg && !was_nofork)
						sh_offstate(SH_NOFORK);
					if(!(nv_isattr(np,BLT_ENV)))
					{
						if(bp->nosfio && shp->pwd)
						{
							struct stat stata;
							stat(".",&stata);
							/* restore directory changed */
							if(statb.st_ino!=stata.st_ino || statb.st_dev!=stata.st_dev)
								chdir(shp->pwd);
						}
						sh_offstate(SH_STOPOK);
						if(share&SF_SHARE)
							sfset(sfstdin,SF_PUBLIC|SF_SHARE,1);
						sfset(sfstderr,SF_LINE,0);
						sfpool(sfstderr,shp->outpool,SF_WRITE);
						sfpool(sfstdin,NIL(Sfio_t*),SF_WRITE);
						shp->nextprompt = save_prompt;
					}
					sh_popcontext(&buff);
					errorpop(&buff.err);
					error_info.flags &= ~(ERROR_SILENT|ERROR_NOTIFY);
					shp->bltinfun = 0;
					if(buff.olist)
						free_list(buff.olist);
					if(was_vi)
						sh_onoption(SH_VI);
					else if(was_emacs)
						sh_onoption(SH_EMACS);
					else if(was_gmacs)
						sh_onoption(SH_GMACS);
					if(scope)
						sh_unscope(shp);
					bp->ptr = (void*)save_ptr;
					bp->data = (void*)save_data;
					/* don't restore for subshell exec */
					if((shp->topfd>topfd) && !(shp->subshell && np==SYSEXEC))
						sh_iorestore(shp,topfd,jmpval);
					if(jmpval)
						siglongjmp(*shp->jmplist,jmpval);
#if 0
					if(flgs&NV_STATIC)
						((Shnode_t*)t)->com.comset = 0;
#endif
					if(shp->exitval >=0)
						goto setexit;
					np = 0;
					type=0;
				}
				/* check for functions */
				if(!command && np && nv_isattr(np,NV_FUNCTION))
				{
					volatile int indx;
					int jmpval=0;
					struct checkpt buff;
					Namval_t node;
					struct Namref	nr;
					long		mode;
					register struct slnod *slp;
					if(!np->nvalue.ip)
					{
						indx = path_search(com0,NIL(Pathcomp_t**),0);
						if(indx==1)
							np = nv_search(com0,shp->fun_tree,HASH_NOSCOPE);
						
						if(!np->nvalue.ip)
						{
							if(indx==1)
							{
								errormsg(SH_DICT,ERROR_exit(0),e_defined,com0);
								shp->exitval = ERROR_NOEXEC;
							}
							else
							{
								errormsg(SH_DICT,ERROR_exit(0),e_found,"function");
								shp->exitval = ERROR_NOENT;
							}
							goto setexit;
						}
					}
					/* increase refcnt for unset */
					slp = (struct slnod*)np->nvenv;
					sh_funstaks(slp->slchild,1);
					staklink(slp->slptr);
					if(nq)
					{
						shp->last_table = last_table;
						mode = set_instance(shp,nq,&node,&nr);
					}
					if(io)
					{
						indx = shp->topfd;
						sh_pushcontext(&buff,SH_JMPCMD);
						jmpval = sigsetjmp(buff.buff,0);
					}
					if(jmpval == 0)
					{
						if(io)
							indx = sh_redirect(shp,io,execflg);
						sh_funct(shp,np,argn,com,t->com.comset,(flags&~OPTIMIZE_FLAG));
					}
					if(io)
					{
						if(buff.olist)
							free_list(buff.olist);
						sh_popcontext(&buff);
						sh_iorestore(shp,indx,jmpval);
					}
					if(nq)
						unset_instance(nq,&node,&nr,mode);
					sh_funstaks(slp->slchild,-1);
					stakdelete(slp->slptr);
					if(jmpval > SH_JMPFUN)
						siglongjmp(*shp->jmplist,jmpval);
					goto setexit;
				}
			}
			else if(!io)
			{
			setexit:
				exitset();
				break;
			}
		    }
		    /* FALLTHROUGH */
		    case TFORK:
		    {
			register pid_t parent;
			int no_fork,jobid;
			int pipes[2];
			if(shp->subshell)
			{
				if(shp->subshare)
					sh_subtmpfile(1);
				else
					sh_subfork();
			}
			no_fork = !ntflag && !(type&(FAMP|FPOU)) &&
			    !shp->st.trapcom[0] && !shp->st.trap[SH_ERRTRAP] &&
				((struct checkpt*)shp->jmplist)->mode!=SH_JMPEVAL &&
				(execflg2 || (execflg && 
				!shp->subshell && shp->fn_depth==0 &&
				!(pipejob && sh_isoption(SH_PIPEFAIL))
			    ));
			if(sh_isstate(SH_PROFILE) || shp->dot_depth)
			{
				/* disable foreground job monitor */
				if(!(type&FAMP))
					sh_offstate(SH_MONITOR);
#if SHOPT_DEVFD
				else if(!(type&FINT))
					sh_offstate(SH_MONITOR);
#endif /* SHOPT_DEVFD */
			}
			if(no_fork)
				job.parent=parent=0;
			else
			{
#ifdef SHOPT_BGX
				int maxjob;
				if(((type&(FAMP|FINT)) == (FAMP|FINT)) && (maxjob=nv_getnum(JOBMAXNOD))>0)
				{
					while(job.numbjob >= maxjob)
					{
						job_lock();
						job_reap(0);
						job_unlock();
					}
				}
#endif /* SHOPT_BGX */
				if(type&FCOOP)
					coproc_init(shp,pipes);
				nv_getval(RANDNOD);
#if SHOPT_AMP
				if((type&(FAMP|FINT)) == (FAMP|FINT))
					parent = sh_ntfork(shp,t,com,&jobid,ntflag);
				else
					parent = sh_fork(type,&jobid);
				if(parent<0)
					break;
#else
#if SHOPT_SPAWN
#   ifdef _lib_fork
				if(com)
					parent = sh_ntfork(shp,t,com,&jobid,ntflag);
				else
					parent = sh_fork(type,&jobid);
#   else
				if((parent = sh_ntfork(shp,t,com,&jobid,ntflag))<=0)
					break;
#   endif /* _lib_fork */
				if(parent<0)
					break;
#else
				parent = sh_fork(type,&jobid);
#endif /* SHOPT_SPAWN */
#endif
			}
			if(job.parent=parent)
			/* This is the parent branch of fork
			 * It may or may not wait for the child
			 */
			{
				if(pipejob==2)
				{
					pipejob = 1;
					job_unlock();
				}
				if(type&FPCL)
					sh_close(shp->inpipe[0]);
				if(type&(FCOOP|FAMP))
					shp->bckpid = parent;
				else if(!(type&(FAMP|FPOU)))
				{
					if(shp->topfd > topfd)
						sh_iorestore(shp,topfd,0);
					if(!sh_isoption(SH_MONITOR))
					{
						if(!(shp->sigflag[SIGINT]&(SH_SIGFAULT|SH_SIGOFF)))
							sh_sigtrap(SIGINT);
						shp->trapnote |= SH_SIGIGNORE;
					}
					if(execflg && shp->subshell && !shp->subshare)
					{
						shp->spid = parent;
						job.pwlist->p_env--;
					}
					else if(shp->pipepid)
						shp->pipepid = parent;
					else
						job_wait(parent);
					if(!sh_isoption(SH_MONITOR))
					{
						shp->trapnote &= ~SH_SIGIGNORE;
						if(shp->exitval == (SH_EXITSIG|SIGINT))
							sh_fault(SIGINT);
					}
				}
				if(type&FAMP)
				{
					if(sh_isstate(SH_PROFILE) || sh_isstate(SH_INTERACTIVE))
					{
						/* print job number */
#ifdef JOBS
						sfprintf(sfstderr,"[%d]\t%d\n",jobid,parent);
#else
						sfprintf(sfstderr,"%d\n",parent);
#endif /* JOBS */
					}
				}
				break;
			}
			else
			/*
			 * this is the FORKED branch (child) of execute
			 */
			{
				volatile int jmpval;
				struct checkpt buff;
				if(no_fork)
					sh_sigreset(2);
				sh_pushcontext(&buff,SH_JMPEXIT);
				jmpval = sigsetjmp(buff.buff,0);
				if(jmpval)
					goto done;
				if((type&FINT) && !sh_isstate(SH_MONITOR))
				{
					/* default std input for & */
					signal(SIGINT,SIG_IGN);
					signal(SIGQUIT,SIG_IGN);
					if(!shp->st.ioset)
					{
						if(sh_close(0)>=0)
							sh_chkopen(e_devnull);
					}
				}
				sh_offstate(SH_MONITOR);
				/* pipe in or out */
#ifdef _lib_nice
				if((type&FAMP) && sh_isoption(SH_BGNICE))
					nice(4);
#endif /* _lib_nice */
				if(type&FPIN)
				{
					sh_iorenumber(shp,shp->inpipe[0],0);
					if(!(type&FPOU) || (type&FCOOP))
						sh_close(shp->inpipe[1]);
				}
				if(type&FPOU)
				{
					sh_iorenumber(shp,shp->outpipe[1],1);
					sh_pclose(shp->outpipe);
				}
				if((type&COMMSK)!=TCOM)
					error_info.line = t->fork.forkline-shp->st.firstline;
				if(shp->topfd)
					sh_iounsave(shp);
				topfd = shp->topfd;
				sh_redirect(shp,t->tre.treio,1);
				if(shp->topfd > topfd)
				{
					job_lock();
					while((parent = vfork()) < 0)
						_sh_fork(parent, 0, (int*)0);
					job_fork(parent);
					if(parent)
					{
						job_clear();
						job_post(parent,0);
						job_wait(parent);
						sh_iorestore(shp,topfd,SH_JMPCMD);
						sh_done(shp,(shp->exitval&SH_EXITSIG)?(shp->exitval&SH_EXITMASK):0);

					}
				}
				if((type&COMMSK)!=TCOM)
				{
					/* don't clear job table for out
					   pipes so that jobs comand can
					   be used in a pipeline
					 */
					if(!no_fork && !(type&FPOU))
						job_clear();
					sh_exec(t->fork.forktre,flags|sh_state(SH_NOFORK)|sh_state(SH_FORKED));
				}
				else if(com0)
				{
					sh_offoption(SH_ERREXIT);
					sh_freeup(shp);
					path_exec(com0,com,t->com.comset);
				}
			done:
				sh_popcontext(&buff);
				if(jmpval>SH_JMPEXIT)
					siglongjmp(*shp->jmplist,jmpval);
				sh_done(shp,0);
			}
		    }
		    /* FALLTHROUGH */

		    case TSETIO:
		    {
		    /*
		     * don't create a new process, just
		     * save and restore io-streams
		     */
			pid_t	pid;
			int 	jmpval, waitall;
			int 	simple = (t->fork.forktre->tre.tretyp&COMMSK)==TCOM;
			struct checkpt buff;
			if(shp->subshell)
				execflg = 0;
			sh_pushcontext(&buff,SH_JMPIO);
			if(type&FPIN)
			{
				was_interactive = sh_isstate(SH_INTERACTIVE);
				sh_offstate(SH_INTERACTIVE);
				sh_iosave(shp,0,shp->topfd,(char*)0);
				shp->pipepid = simple;
				sh_iorenumber(shp,shp->inpipe[0],0);
				/*
				 * if read end of pipe is a simple command
				 * treat as non-sharable to improve performance
				 */
				if(simple)
					sfset(sfstdin,SF_PUBLIC|SF_SHARE,0);
				waitall = job.waitall;
				job.waitall = 0;
				pid = job.parent;
			}
			else
				error_info.line = t->fork.forkline-shp->st.firstline;
			jmpval = sigsetjmp(buff.buff,0);
			if(jmpval==0)
			{
				sh_redirect(shp,t->fork.forkio,execflg);
				(t->fork.forktre)->tre.tretyp |= t->tre.tretyp&FSHOWME;
				sh_exec(t->fork.forktre,flags&~simple);
			}
			else
				sfsync(shp->outpool);
			sh_popcontext(&buff);
			sh_iorestore(shp,buff.topfd,jmpval);
			if(buff.olist)
				free_list(buff.olist);
			if(type&FPIN)
			{
				job.waitall = waitall;
				type = shp->exitval;
				if(!(type&SH_EXITSIG))
				{
					/* wait for remainder of pipline */
					if(shp->pipepid>1)
					{
						job_wait(shp->pipepid);
						type = shp->exitval;
					}
					else
						job_wait(waitall?pid:0);
					if(type || !sh_isoption(SH_PIPEFAIL))
						shp->exitval = type;
				}
				shp->pipepid = 0;
				shp->st.ioset = 0;
				if(simple && was_errexit)
				{
					echeck = 1;
					sh_onstate(SH_ERREXIT);
				}
			}
			if(jmpval>SH_JMPIO)
				siglongjmp(*shp->jmplist,jmpval);
			break;
		    }

		    case TPAR:
			echeck = 1;
			flags &= ~OPTIMIZE_FLAG;
			if(!shp->subshell && !shp->st.trapcom[0] && !shp->st.trap[SH_ERRTRAP] && (flags&sh_state(SH_NOFORK)))
			{
				char *savsig;
				int nsig,jmpval;
				struct checkpt buff;
				shp->st.otrapcom = 0;
				if((nsig=shp->st.trapmax*sizeof(char*))>0 || shp->st.trapcom[0])
				{
					nsig += sizeof(char*);
					memcpy(savsig=malloc(nsig),(char*)&shp->st.trapcom[0],nsig);
					shp->st.otrapcom = (char**)savsig;
				}
				sh_sigreset(0);
				sh_pushcontext(&buff,SH_JMPEXIT);
				jmpval = sigsetjmp(buff.buff,0);
				if(jmpval==0)
					sh_exec(t->par.partre,flags);
				sh_popcontext(&buff);
				if(jmpval > SH_JMPEXIT)
					siglongjmp(*shp->jmplist,jmpval);
				sh_done(shp,0);
			}
			else
				sh_subshell(t->par.partre,flags,0);
			break;

		    case TFIL:
		    {
		    /*
		     * This code sets up a pipe.
		     * All elements of the pipe are started by the parent.
		     * The last element executes in current environment
		     */
			int	pvo[2];	/* old pipe for multi-stage */
			int	pvn[2];	/* current set up pipe */
			int	savepipe = pipejob;
			int	showme = t->tre.tretyp&FSHOWME;
			pid_t	savepgid = job.curpgid;
			job.curpgid = 0;
			if(shp->subshell)
			{
				if(shp->subshare)
					sh_subtmpfile(0);
				else
					sh_subfork();
			}
			shp->inpipe = pvo;
			shp->outpipe = pvn;
			pvo[1] = -1;
			if(sh_isoption(SH_PIPEFAIL))
				job.waitall = 1;
			else
				job.waitall |= !pipejob && sh_isstate(SH_MONITOR);
			job_lock();
			do
			{
#if SHOPT_FASTPIPE
				type = pipe_exec(shp,pvn,t->lst.lstlef, errorflg);
#else
				/* create the pipe */
				sh_pipe(pvn);
				/* execute out part of pipe no wait */
				(t->lst.lstlef)->tre.tretyp |= showme;
				type = sh_exec(t->lst.lstlef, errorflg);
#endif /* SHOPT_FASTPIPE */
				pipejob=1;
				/* save the pipe stream-ids */
				pvo[0] = pvn[0];
				/* close out-part of pipe */
				sh_close(pvn[1]);
				/* pipeline all in one process group */
				t = t->lst.lstrit;
			}
			/* repeat until end of pipeline */
			while(!type && t->tre.tretyp==TFIL);
			shp->inpipe = pvn;
			shp->outpipe = 0;
			pipejob = 2;
			if(type == 0)
			{
				/*
				 * execute last element of pipeline
				 * in the current process
				 */
				((Shnode_t*)t)->tre.tretyp |= showme;
				sh_exec(t,flags);
			}
			else
				/* execution failure, close pipe */
				sh_pclose(pvn);
			if(pipejob==2)
				job_unlock();
			pipejob = savepipe;
#ifdef SIGTSTP
			if(!pipejob && sh_isstate(SH_MONITOR))
				tcsetpgrp(JOBTTY,shp->pid);
#endif /*SIGTSTP */
			job.curpgid = savepgid;
			break;
		    }

		    case TLST:
		    {
			/*  a list of commands are executed here */
			do
			{
				sh_exec(t->lst.lstlef,errorflg|OPTIMIZE);
				t = t->lst.lstrit;
			}
			while(t->tre.tretyp == TLST);
			sh_exec(t,flags);
			break;
		    }

		    case TAND:
			if(type&TTEST)
				skipexitset++;
			if(sh_exec(t->lst.lstlef,OPTIMIZE)==0)
				sh_exec(t->lst.lstrit,flags);
			break;

		    case TORF:
			if(type&TTEST)
				skipexitset++;
			if(sh_exec(t->lst.lstlef,OPTIMIZE)!=0)
				sh_exec(t->lst.lstrit,flags);
			break;

		    case TFOR: /* for and select */
		    {
			register char **args;
			register int nargs;
			register Namval_t *np;
			int flag = errorflg|OPTIMIZE_FLAG;
			struct dolnod	*argsav=0;
			struct comnod	*tp;
			char *cp, *trap, *nullptr = 0;
			int nameref, refresh=1;
			char *av[5];
#if SHOPT_OPTIMIZE
			int  jmpval = ((struct checkpt*)shp->jmplist)->mode;
			struct checkpt buff;
			void *optlist = shp->optlist;
			shp->optlist = 0;
			sh_tclear(t->for_.fortre);
			sh_pushcontext(&buff,jmpval);
			jmpval = sigsetjmp(buff.buff,0);
			if(jmpval)
				goto endfor;
#endif /* SHOPT_OPTIMIZE */
			error_info.line = t->for_.forline-shp->st.firstline;
			if(!(tp=t->for_.forlst))
			{
				args=shp->st.dolv+1;
				nargs = shp->st.dolc;
				argsav=sh_arguse(shp);
			}
			else
			{
				args=sh_argbuild(shp,&argn,tp,0);
				nargs = argn;
			}
			np = nv_open(t->for_.fornam, shp->var_tree,NV_NOASSIGN|NV_NOARRAY|NV_VARNAME|NV_NOREF);
			nameref = nv_isref(np)!=0;
			shp->st.loopcnt++;
			cp = *args;
			while(cp && shp->st.execbrk==0)
			{
				if(t->tre.tretyp&COMSCAN)
				{
					char *val;
					int save_prompt;
					/* reuse register */
					if(refresh)
					{
						sh_menu(sfstderr,nargs,args);
						refresh = 0;
					}
					save_prompt = shp->nextprompt;
					shp->nextprompt = 3;
					shp->timeout = 0;
					shp->exitval=sh_readline(shp,&nullptr,0,1,1000*shp->st.tmout);
					shp->nextprompt = save_prompt;
					if(shp->exitval||sfeof(sfstdin)||sferror(sfstdin))
					{
						shp->exitval = 1;
						break;
					}
					if(!(val=nv_getval(sh_scoped(shp,REPLYNOD))))
						continue;
					else
					{
						if(*(cp=val) == 0)
						{
							refresh++;
							goto check;
						}
						while(type = *cp++)
							if(type < '0' && type > '9')
								break;
						if(type!=0)
							type = nargs;
						else
							type = (int)strtol(val, (char**)0, 10)-1;
						if(type<0 || type >= nargs)
							cp = "";
						else
							cp = args[type];
					}
				}
				if(nameref)
					nv_offattr(np,NV_REF);
				else if(nv_isattr(np, NV_ARRAY))
					nv_putsub(np,NIL(char*),0L);
				nv_putval(np,cp,0);
				if(nameref)
					nv_setref(np,(Dt_t*)0,NV_VARNAME);
				if(trap=shp->st.trap[SH_DEBUGTRAP])
				{
					av[0] = (t->tre.tretyp&COMSCAN)?"select":"for";
					av[1] = t->for_.fornam;
					av[2] = "in";
					av[3] = cp;
					av[4] = 0;
					sh_debug(shp,trap,(char*)0,(char*)0,av,0);
				}
				sh_exec(t->for_.fortre,flag);
				flag &= ~OPTIMIZE_FLAG;
				if(t->tre.tretyp&COMSCAN)
				{
					if((cp=nv_getval(sh_scoped(shp,REPLYNOD))) && *cp==0)
						refresh++;
				}
				else
					cp = *++args;
			check:
				if(shp->st.breakcnt<0)
					shp->st.execbrk = (++shp->st.breakcnt !=0);
			}
#if SHOPT_OPTIMIZE
		endfor:
			sh_popcontext(&buff);
			sh_tclear(t->for_.fortre);
			sh_optclear(shp,optlist);
			if(jmpval)
				siglongjmp(*shp->jmplist,jmpval);
#endif /*SHOPT_OPTIMIZE */
			if(shp->st.breakcnt>0)
				shp->st.execbrk = (--shp->st.breakcnt !=0);
			shp->st.loopcnt--;
			sh_argfree(shp,argsav,0);
			nv_close(np);
			break;
		    }

		    case TWH: /* while and until */
		    {
			volatile int 	r=0;
			int first = OPTIMIZE_FLAG;
			Shnode_t *tt = t->wh.whtre;
#if SHOPT_FILESCAN
			Sfio_t *iop=0;
			int savein,fd;
#endif /*SHOPT_FILESCAN*/
#if SHOPT_OPTIMIZE
			int  jmpval = ((struct checkpt*)shp->jmplist)->mode;
			struct checkpt buff;
			void *optlist = shp->optlist;
			shp->optlist = 0;
			sh_tclear(t->wh.whtre);
			sh_tclear(t->wh.dotre);
			sh_pushcontext(&buff,jmpval);
			jmpval = sigsetjmp(buff.buff,0);
			if(jmpval)
				goto endwhile;
#endif /* SHOPT_OPTIMIZE */
#if SHOPT_FILESCAN
			if(type==TWH && tt->tre.tretyp==TCOM && !tt->com.comarg && tt->com.comio)
			{
				fd = sh_redirect(shp,tt->com.comio,3);
				savein = dup(0);
				if(fd==0)
					fd = savein;
				iop = sfnew(NULL,NULL,SF_UNBOUND,fd,SF_READ);
				close(0);
				open("/dev/null",O_RDONLY);
				shp->offsets[0] = -1;
				shp->offsets[1] = 0;
				if(tt->com.comset)
					nv_setlist(tt->com.comset,NV_IDENT|NV_ASSIGN,0);
			}
#endif /*SHOPT_FILESCAN */
			shp->st.loopcnt++;
			while(shp->st.execbrk==0)
			{
#if SHOPT_FILESCAN
				if(iop)
				{
					if(!(shp->cur_line=sfgetr(iop,'\n',SF_STRING)))
						break;
				}
				else
#endif /*SHOPT_FILESCAN */
				if((sh_exec(tt,first)==0)!=(type==TWH))
					break;
				r = sh_exec(t->wh.dotre,first|errorflg);
				if(shp->st.breakcnt<0)
					shp->st.execbrk = (++shp->st.breakcnt !=0);
				/* This is for the arithmetic for */
				if(shp->st.execbrk==0 && t->wh.whinc)
					sh_exec((Shnode_t*)t->wh.whinc,first);
				first = 0;
				errorflg &= ~OPTIMIZE_FLAG;
#if SHOPT_FILESCAN
				shp->offsets[0] = -1;
				shp->offsets[1] = 0;
#endif /*SHOPT_FILESCAN */
			}
#if SHOPT_OPTIMIZE
		endwhile:
			sh_popcontext(&buff);
			sh_tclear(t->wh.whtre);
			sh_tclear(t->wh.dotre);
			sh_optclear(shp,optlist);
			if(jmpval)
				siglongjmp(*shp->jmplist,jmpval);
#endif /*SHOPT_OPTIMIZE */
			if(shp->st.breakcnt>0)
				shp->st.execbrk = (--shp->st.breakcnt !=0);
			shp->st.loopcnt--;
			shp->exitval= r;
#if SHOPT_FILESCAN
			if(iop)
			{
				sfclose(iop);
				close(0);
				dup(savein);
				shp->cur_line = 0;
			}
#endif /*SHOPT_FILESCAN */
			break;
		    }
		    case TARITH: /* (( expression )) */
		    {
			register char *trap;
			char *arg[4];
			error_info.line = t->ar.arline-shp->st.firstline;
			arg[0] = "((";
			if(!(t->ar.arexpr->argflag&ARG_RAW))
				arg[1] = sh_macpat(shp,t->ar.arexpr,OPTIMIZE|ARG_ARITH);
			else
				arg[1] = t->ar.arexpr->argval;
			arg[2] = "))";
			arg[3] = 0;
			if(trap=shp->st.trap[SH_DEBUGTRAP])
				sh_debug(shp,trap,(char*)0, (char*)0, arg, ARG_ARITH);
			if(sh_isoption(SH_XTRACE))
			{
				sh_trace(NIL(char**),0);
				sfprintf(sfstderr,"((%s))\n",arg[1]);
			}
			if(t->ar.arcomp)
				shp->exitval  = !arith_exec((Arith_t*)t->ar.arcomp);
			else
				shp->exitval = !sh_arith(arg[1]);
			break;
		    }

		    case TIF:
			if(sh_exec(t->if_.iftre,OPTIMIZE)==0)
				sh_exec(t->if_.thtre,flags);
			else if(t->if_.eltre)
				sh_exec(t->if_.eltre, flags);
			else
				shp->exitval=0; /* force zero exit for if-then-fi */
			break;

		    case TSW:
		    {
			Shnode_t *tt = (Shnode_t*)t;
			char *trap, *r = sh_macpat(shp,tt->sw.swarg,OPTIMIZE);
			error_info.line = t->sw.swline-shp->st.firstline;
			t= (Shnode_t*)(tt->sw.swlst);
			if(trap=shp->st.trap[SH_DEBUGTRAP])
			{
				char *av[4];
				av[0] = "case";
				av[1] = r;
				av[2] = "in";
				av[3] = 0;
				sh_debug(shp,trap, (char*)0, (char*)0, av, 0);
			}
			while(t)
			{
				register struct argnod	*rex=(struct argnod*)t->reg.regptr;
				while(rex)
				{
					register char *s;
					if(rex->argflag&ARG_MAC)
					{
						s = sh_macpat(shp,rex,OPTIMIZE|ARG_EXP);
						while(*s=='\\' && s[1]==0)
							s+=2;
					}
					else
						s = rex->argval;
					type = (rex->argflag&ARG_RAW);
					if((type && strcmp(r,s)==0) ||
						(!type && (strmatch(r,s)
						|| trim_eq(r,s))))
					{
						do	sh_exec(t->reg.regcom,(t->reg.regflag?0:flags));
						while(t->reg.regflag &&
							(t=(Shnode_t*)t->reg.regnxt));
						t=0;
						break;
					}
					else
						rex=rex->argnxt.ap;
				}
				if(t)
					t=(Shnode_t*)t->reg.regnxt;
			}
			break;
		    }

		    case TTIME:
		    {
			/* time the command */
			struct tms before,after;
			const char *format = e_timeformat;
			clock_t at, tm[3];
#ifdef timeofday
			struct timeval tb,ta;
#else
			clock_t bt;
#endif	/* timeofday */
			if(type!=TTIME)
			{
				sh_exec(t->par.partre,OPTIMIZE);
				shp->exitval = !shp->exitval;
				break;
			}
			if(t->par.partre)
			{
				long timer_on;
				timer_on = sh_isstate(SH_TIMING);
#ifdef timeofday
				timeofday(&tb);
				times(&before);
#else
				bt = times(&before);
#endif	/* timeofday */
				job.waitall = 1;
				sh_onstate(SH_TIMING);
				sh_exec(t->par.partre,OPTIMIZE);
				if(!timer_on)
					sh_offstate(SH_TIMING);
				job.waitall = 0;
			}
			else
			{
#ifndef timeofday
				bt = 0;
#endif	/* timeofday */
				before.tms_utime = before.tms_cutime = 0;
				before.tms_stime = before.tms_cstime = 0;
			}
#ifdef timeofday
			times(&after);
			timeofday(&ta);
			at = shp->lim.clk_tck*(ta.tv_sec-tb.tv_sec);
			at +=  ((shp->lim.clk_tck*(((1000000L/2)/shp->lim.clk_tck)+(ta.tv_usec-tb.tv_usec)))/1000000L);
#else
			at = times(&after) - bt;
#endif	/* timeofday */
			tm[0] = at;
			if(t->par.partre)
			{
				Namval_t *np = nv_open("TIMEFORMAT",shp->var_tree,NV_NOADD);
				if(np)
				{
					format = nv_getval(np);
					nv_close(np);
				}
				if(!format)
					format = e_timeformat;
			}
			else
				format = strchr(format+1,'\n')+1;
			tm[1] = after.tms_utime - before.tms_utime;
			tm[1] += after.tms_cutime - before.tms_cutime;
			tm[2] = after.tms_stime - before.tms_stime;
			tm[2] += after.tms_cstime - before.tms_cstime;
			if(format && *format)
				p_time(shp,sfstderr,sh_translate(format),tm);
			break;
		    }
		    case TFUN:
		    {
			register Namval_t *np;
			register struct slnod *slp;
			register char *fname = ((struct functnod*)t)->functnam;
			register char *cp = strrchr(fname,'.');
			register Namval_t *npv=0;
#if SHOPT_NAMESPACE
			if(t->tre.tretyp==TNSPACE)
			{
				Dt_t *root,*oldroot, *top=0;
				Namval_t *oldnspace = shp->namespace;
				int offset = stktell(stkp);
				long optindex = shp->st.optindex;
				if(cp)
					errormsg(SH_DICT,ERROR_exit(1),e_ident,fname);
				sfputc(stkp,'.');
				sfputr(stkp,fname,0);
				np = nv_open(stkptr(stkp,offset),shp->var_base,NV_NOASSIGN|NV_NOARRAY|NV_VARNAME);
				offset = stktell(stkp);
				shp->namespace = np;
				if(!(root=nv_dict(np)))
				{
					root = dtopen(&_Nvdisc,Dtoset);
					nv_putval(np,(char*)root,NV_TABLE|NV_NOFREE);
					shp->st.optindex = 1;
				}
				if(oldnspace && dtvnext(dtvnext(shp->var_tree)))
					top = dtview(shp->var_tree,0);
				else if(dtvnext(shp->var_tree))
					top = dtview(shp->var_tree,0);
				oldroot = shp->var_tree;
				dtview(root,shp->var_base);
				shp->var_tree = root;
				if(top)
					dtview(shp->var_tree,top);
				sh_exec(t->for_.fortre,flags);
				if(dtvnext(shp->var_tree))
					top = dtview(shp->var_tree,0);
				shp->var_tree = oldroot;
				if(top)
					dtview(top,shp->var_tree);
				shp->namespace = oldnspace;
				shp->st.optindex = optindex;
				break;
			}
#endif /* SHOPT_NAMESPACE */
			/* look for discipline functions */
			error_info.line = t->funct.functline-shp->st.firstline;
			/* Function names cannot be special builtin */
			if(cp || shp->prefix)
			{
				int offset = stktell(stkp);
				if(shp->prefix)
				{
					cp = shp->prefix;
					shp->prefix = 0;
					npv = nv_open(cp,shp->var_tree,NV_NOASSIGN|NV_NOARRAY|NV_VARNAME);
					shp->prefix = cp;
					cp = fname;
				}
				else
				{
					sfwrite(stkp,fname,cp++-fname);
					sfputc(stkp,0);
					npv = nv_open(stkptr(stkp,offset),shp->var_tree,NV_NOASSIGN|NV_NOARRAY|NV_VARNAME);
				}
				offset = stktell(stkp);
				sfprintf(stkp,"%s.%s%c",nv_name(npv),cp,0);
				fname = stkptr(stkp,offset);
			}
			else if((np=nv_search(fname,shp->bltin_tree,0)) && nv_isattr(np,BLT_SPC))
				errormsg(SH_DICT,ERROR_exit(1),e_badfun,fname);
#if SHOPT_NAMESPACE
			else if(shp->namespace)
			{
				int offset = stktell(stkp);
				sfputr(stkp,nv_name(shp->namespace),-1);
				sfputc(stkp,'.');
				sfputr(stkp,fname,0);
				fname = stkptr(stkp,offset);
			}
#endif /* SHOPT_NAMESPACE */
			np = nv_open(fname,sh_subfuntree(1),NV_NOASSIGN|NV_NOARRAY|NV_VARNAME|NV_NOSCOPE);
			if(npv)
			{
				Namval_t *tp = npv;
				if(!shp->mktype)
				{
					if(shp->typeinit)
					{
						if(tp=nv_open(shp->typeinit->nvname,shp->typedict,NV_IDENT|NV_NOFAIL))
							nv_close(npv);
						else
							tp = npv;
					}
					cp = nv_setdisc(tp,cp,np,(Namfun_t*)tp);
				}
				nv_close(tp);
				if(!cp)
					errormsg(SH_DICT,ERROR_exit(1),e_baddisc,fname);
			}
			if(np->nvalue.rp)
			{
				slp = (struct slnod*)np->nvenv;
				sh_funstaks(slp->slchild,-1);
				stakdelete(slp->slptr);
				if(shp->funload)
				{
					free((void*)np->nvalue.rp);
					np->nvalue.rp = 0;
				}
			
			}
			if(!np->nvalue.rp)
			{
				np->nvalue.rp = new_of(struct Ufunction,shp->funload?sizeof(Dtlink_t):0);
				memset((void*)np->nvalue.rp,0,sizeof(struct Ufunction));
			}
			if(t->funct.functstak)
			{
				static Dtdisc_t		_Rpdisc =
				{
				        offsetof(struct Ufunction,fname), -1, sizeof(struct Ufunction) 
				};
				struct functnod *fp;
				slp = t->funct.functstak;
				sh_funstaks(slp->slchild,1);
				staklink(slp->slptr);
				np->nvenv = (char*)slp;
				nv_funtree(np) = (int*)(t->funct.functtre);
				np->nvalue.rp->hoffset = t->funct.functloc;
				np->nvalue.rp->lineno = t->funct.functline;
				np->nvalue.rp->nspace = shp->namespace;
				np->nvalue.rp->fname = 0;
				np->nvalue.rp->fdict = shp->fun_tree;
				fp = (struct functnod*)(slp+1);
				if(fp->functtyp==(TFUN|FAMP))
					np->nvalue.rp->fname = fp->functnam;
				nv_setsize(np,fp->functline);
				nv_offattr(np,NV_FPOSIX);
				if(shp->funload)
				{
					struct Ufunction *rp = np->nvalue.rp;
					rp->np = np;
					if(!shp->fpathdict)
						shp->fpathdict = dtopen(&_Rpdisc,Dtbag);
					if(shp->fpathdict)
						dtinsert(shp->fpathdict,rp);
				}
			}
			else
				nv_unset(np);
			if(type&FPOSIX)
				nv_onattr(np,NV_FUNCTION|NV_FPOSIX);
			else
				nv_onattr(np,NV_FUNCTION);
			if(type&FPIN)
				nv_onattr(np,NV_FTMP);
			if(type&FOPTGET)
				nv_onattr(np,NV_OPTGET);
			break;
		    }

		    /* new test compound command */
		    case TTST:
		    {
			register int n;
			register char *left;
			int negate = (type&TNEGATE)!=0;
			if(type&TTEST)
				skipexitset++;
			error_info.line = t->tst.tstline-shp->st.firstline;
			echeck = 1;
			if((type&TPAREN)==TPAREN)
			{
				sh_exec(t->lst.lstlef,OPTIMIZE);
				n = !shp->exitval;
			}
			else
			{
				register int traceon=0;
				register char *right;
				register char *trap;
				char *argv[6];
				n = type>>TSHIFT;
				left = sh_macpat(shp,&(t->lst.lstlef->arg),OPTIMIZE);
				if(type&TBINARY)
					right = sh_macpat(shp,&(t->lst.lstrit->arg),((n==TEST_PEQ||n==TEST_PNE)?ARG_EXP:0)|OPTIMIZE);
				if(trap=shp->st.trap[SH_DEBUGTRAP])
					argv[0] = (type&TNEGATE)?((char*)e_tstbegin):"[[";
				if(sh_isoption(SH_XTRACE))
				{
					traceon = sh_trace(NIL(char**),0);
					sfwrite(sfstderr,e_tstbegin,(type&TNEGATE?5:3));
				}
				if(type&TUNARY)
				{
					if(traceon)
						sfprintf(sfstderr,"-%c %s",n,sh_fmtq(left));
					if(trap)
					{
						char unop[3];
						unop[0] = '-';
						unop[1] = n;
						unop[2] = 0;
						argv[1] = unop;
						argv[2] = left;
						argv[3] = "]]";
						argv[4] = 0;
						sh_debug(shp,trap,(char*)0,(char*)0,argv, 0);
					}
					n = test_unop(n,left);
				}
				else if(type&TBINARY)
				{
					char *op;
					int pattern = 0;
					if(trap || traceon)
						op = (char*)(shtab_testops+(n&037)-1)->sh_name;
					type >>= TSHIFT;
					if(type==TEST_PEQ || type==TEST_PNE)
						pattern=ARG_EXP;
					if(trap)
					{
						argv[1] = left;
						argv[2] = op;
						argv[3] = right;
						argv[4] = "]]";
						argv[5] = 0;
						sh_debug(shp,trap,(char*)0,(char*)0,argv, pattern);
					}
					n = test_binop(n,left,right);
					if(traceon)
					{
						sfprintf(sfstderr,"%s %s ",sh_fmtq(left),op);
						if(pattern)
							out_pattern(sfstderr,right,-1);
						else
							sfputr(sfstderr,sh_fmtq(right),-1);
					}
				}
				if(traceon)
					sfwrite(sfstderr,e_tstend,4);
			}
			shp->exitval = ((!n)^negate); 
			if(!skipexitset)
				exitset();
			break;
		    }
		}
		if(shp->trapnote || (shp->exitval && sh_isstate(SH_ERREXIT)) &&
			t && echeck) 
			sh_chktrap();
		/* set $_ */
		if(mainloop && com0)
		{
			/* store last argument here if it fits */
			static char	lastarg[32];
			if(sh_isstate(SH_FORKED))
				sh_done(shp,0);
			if(shp->lastarg!= lastarg && shp->lastarg)
				free(shp->lastarg);
			if(strlen(comn) < sizeof(lastarg))
			{
				nv_onattr(L_ARGNOD,NV_NOFREE);
				shp->lastarg = strcpy(lastarg,comn);
			}
			else
			{
				nv_offattr(L_ARGNOD,NV_NOFREE);
				shp->lastarg = strdup(comn);
			}
		}
		if(!skipexitset)
			exitset();
		if(!(OPTIMIZE))
		{
			if(sav != stkptr(stkp,0))
				stkset(stkp,sav,0);
			else if(stktell(stkp))
				stkseek(stkp,0);
		}
		if(shp->trapnote&SH_SIGSET)
			sh_exit(SH_EXITSIG|shp->lastsig);
		if(was_interactive)
			sh_onstate(SH_INTERACTIVE);
		if(was_monitor && sh_isoption(SH_MONITOR))
			sh_onstate(SH_MONITOR);
		if(was_errexit)
			sh_onstate(SH_ERREXIT);
	}
	return(shp->exitval);
}

int sh_run(int argn, char *argv[])
{
	register struct dolnod	*dp;
	register struct comnod	*t = (struct comnod*)stakalloc(sizeof(struct comnod));
	int			savtop = staktell();
	char			*savptr = stakfreeze(0);
	Opt_t			*op, *np = optctx(0, 0);
	Shbltin_t		bltindata;
	bltindata = sh.bltindata;
	op = optctx(np, 0);
	memset(t, 0, sizeof(struct comnod));
	dp = (struct dolnod*)stakalloc((unsigned)sizeof(struct dolnod) + ARG_SPARE*sizeof(char*) + argn*sizeof(char*));
	dp->dolnum = argn;
	dp->dolbot = ARG_SPARE;
	memcpy(dp->dolval+ARG_SPARE, argv, (argn+1)*sizeof(char*));
	t->comarg = (struct argnod*)dp;
	if(!strchr(argv[0],'/'))
		t->comnamp = (void*)nv_bfsearch(argv[0],sh.fun_tree,(Namval_t**)&t->comnamq,(char**)0);
	argn=sh_exec((Shnode_t*)t,sh_isstate(SH_ERREXIT));
	optctx(op,np);
	sh.bltindata = bltindata;
	if(savptr!=stakptr(0))
		stakset(savptr,savtop);
	else
		stakseek(savtop);
	return(argn);
}

/*
 * test for equality with second argument trimmed
 * returns 1 if r == trim(s) otherwise 0
 */

static int trim_eq(register const char *r,register const char *s)
{
	register char c;
	while(c = *s++)
	{
		if(c=='\\')
			c = *s++;
		if(c && c != *r++)
			return(0);
	}
	return(*r==0);
}

/*
 * print out the command line if set -x is on
 */

int sh_trace(register char *argv[], register int nl)
{
	Shell_t	*shp = &sh;
	register char *cp;
	register int bracket = 0;
	int decl = (nl&2);
	nl &= ~2;
	if(sh_isoption(SH_XTRACE))
	{
		/* make this trace atomic */
		sfset(sfstderr,SF_SHARE|SF_PUBLIC,0);
		if(!(cp=nv_getval(sh_scoped(shp,PS4NOD))))
			cp = "+ ";
		else
		{
			sh_offoption(SH_XTRACE);
			cp = sh_mactry(shp,cp);
			sh_onoption(SH_XTRACE);
		}
		if(*cp)
			sfputr(sfstderr,cp,-1);
		if(argv)
		{
			char *argv0 = *argv;
			nl = (nl?'\n':-1);
			/* don't quote [ and [[ */
			if(*(cp=argv[0])=='[' && (!cp[1] || !cp[2]&&cp[1]=='['))  
			{
				sfputr(sfstderr,cp,*++argv?' ':nl);
				bracket = 1;
			}
			while(cp = *argv++)
			{
				if(bracket==0 || *argv || *cp!=']')
					cp = sh_fmtq(cp);
				if(decl && shp->prefix && cp!=argv0 && *cp!='-')
				{
					if(*cp=='.' && cp[1]==0)
						cp = shp->prefix;
					else
						sfputr(sfstderr,shp->prefix,'.');
				}
				sfputr(sfstderr,cp,*argv?' ':nl);
			}
			sfset(sfstderr,SF_SHARE|SF_PUBLIC,1);
		}
		return(1);
	}
	return(0);
}

/*
 * This routine creates a subshell by calling fork() or vfork()
 * If ((flags&COMASK)==TCOM), then vfork() is permitted
 * If fork fails, the shell sleeps for exponentially longer periods
 *   and tries again until a limit is reached.
 * SH_FORKLIM is the max period between forks - power of 2 usually.
 * Currently shell tries after 2,4,8,16, and 32 seconds and then quits
 * Failures cause the routine to error exit.
 * Parent links to here-documents are removed by the child
 * Traps are reset by the child
 * The process-id of the child is returned to the parent, 0 to the child.
 */

static void timed_out(void *handle)
{
	NOT_USED(handle);
	timeout = 0;
}


/*
 * called by parent and child after fork by sh_fork()
 */
pid_t _sh_fork(register pid_t parent,int flags,int *jobid)
{
	static long forkcnt = 1000L;
	Shell_t	*shp = &sh;
	pid_t	curpgid = job.curpgid;
	pid_t	postid = (flags&FAMP)?0:curpgid;
	int	sig,nochild;
	if(parent<0)
	{
		sh_sigcheck();
		if((forkcnt *= 2) > 1000L*SH_FORKLIM)
		{
			forkcnt=1000L;
			errormsg(SH_DICT,ERROR_system(ERROR_NOEXEC),e_nofork);
		}
		timeout = (void*)sh_timeradd(forkcnt, 0, timed_out, NIL(void*));
		nochild = job_wait((pid_t)1);
		if(timeout)
		{
			if(nochild)
				pause();
			else if(forkcnt>1000L)
				forkcnt /= 2;
			timerdel(timeout);
			timeout = 0;
		}
		return(-1);
	}
	forkcnt = 1000L;
	if(parent)
	{
		int myjob,waitall=job.waitall;
		shp->nforks++;
		if(job.toclear)
			job_clear();
		job.waitall = waitall;
#ifdef JOBS
		/* first process defines process group */
		if(sh_isstate(SH_MONITOR))
		{
			/*
			 * errno==EPERM means that an earlier processes
			 * completed.  Make parent the job group id.
			 */
			if(postid==0)
				job.curpgid = parent;
			if(job.jobcontrol || (flags&FAMP))
			{
				if(setpgid(parent,job.curpgid)<0 && errno==EPERM)
					setpgid(parent,parent);
			}
		}
#endif /* JOBS */
		if(!sh_isstate(SH_MONITOR) && job.waitall && postid==0)
			job.curpgid = parent;
		if(flags&FCOOP)
			shp->cpid = parent;
#ifdef SHOPT_BGX
		if(!postid && (flags&(FAMP|FINT)) == (FAMP|FINT))
			postid = 1;
		myjob = job_post(parent,postid);
		if(postid==1)
			postid = 0;
#else
		myjob = job_post(parent,postid);
#endif /* SHOPT_BGX */
		if(flags&FAMP)
			job.curpgid = curpgid;
		if(jobid)
			*jobid = myjob;
		return(parent);
	}
#if !_std_malloc
	vmtrace(-1);
#endif
	/* This is the child process */
	if(shp->trapnote&SH_SIGTERM)
		sh_exit(SH_EXITSIG|SIGTERM);
	shp->nforks=0;
	timerdel(NIL(void*));
#ifdef JOBS
	if(!job.jobcontrol && !(flags&FAMP))
		sh_offstate(SH_MONITOR);
	if(sh_isstate(SH_MONITOR))
	{
		parent = getpid();
		if(postid==0)
			job.curpgid = parent;
		while(setpgid(0,job.curpgid)<0 && job.curpgid!=parent)
			job.curpgid = parent;
#   ifdef SIGTSTP
		if(job.curpgid==parent &&  !(flags&FAMP))
			tcsetpgrp(job.fd,job.curpgid);
#   endif /* SIGTSTP */
	}
#   ifdef SIGTSTP
	if(job.jobcontrol)
	{
		signal(SIGTTIN,SIG_DFL);
		signal(SIGTTOU,SIG_DFL);
		signal(SIGTSTP,SIG_DFL);
	}
#   endif /* SIGTSTP */
	job.jobcontrol = 0;
#endif /* JOBS */
	job.toclear = 1;
	shp->login_sh = 0;
	sh_offoption(SH_LOGIN_SHELL);
	sh_onstate(SH_FORKED);
	sh_onstate(SH_NOLOG);
	if (shp->fn_reset)
		shp->fn_depth = shp->fn_reset = 0;
#if SHOPT_ACCT
	sh_accsusp();
#endif	/* SHOPT_ACCT */
	/* Reset remaining signals to parent */
	/* except for those `lost' by trap   */
	if(!(flags&FSHOWME))
		sh_sigreset(2);
	shp->subshell = 0;
	if((flags&FAMP) && shp->coutpipe>1)
		sh_close(shp->coutpipe);
	sig = shp->savesig;
	shp->savesig = 0;
	if(sig>0)
		sh_fault(sig);
	sh_sigcheck();
	return(0);
}

pid_t sh_fork(int flags, int *jobid)
{
	register pid_t parent;
	register int sig;
#if SHOPT_FASTPIPE
	if(sffileno(sfstdin)<0)
	{
		off_t current = sfseek(sfstdin,(off_t)0,SEEK_CUR);
		sfseek(sfstdin,(off_t)0,SEEK_END);
		sfdisc(sfstdin,SF_POPDISC);
		fcntl(sffileno(sfstdin),F_SETFD,0);
		sh_iostream(0);
		sfseek(sfstdin,current,SEEK_SET);
	}
#endif /* SHOPT_FASTPIPE */
	if(!sh.pathlist)
		path_get("");
	sfsync(NIL(Sfio_t*));
	sh.trapnote &= ~SH_SIGTERM;
	job_fork(-1);
	sh.savesig = -1;
	while(_sh_fork(parent=fork(),flags,jobid) < 0);
	sh_stats(STAT_FORKS);
	sig = sh.savesig;
	sh.savesig = 0;
	if(sig>0)
		sh_fault(sig);
	job_fork(parent);
	return(parent);
}

/*
 * add exports from previous scope to the new scope
 */
static void  local_exports(register Namval_t *np, void *data)
{
	register Namval_t	*mp;
	register char		*cp;
	if(nv_isarray(np))
		nv_putsub(np,NIL(char*),0);
	if((cp = nv_getval(np)) && (mp = nv_search(nv_name(np), sh.var_tree, NV_ADD|HASH_NOSCOPE)) && nv_isnull(mp))
		nv_putval(mp, cp, 0);
}

/*
 * This routine is used to execute the given function <fun> in a new scope
 * If <fun> is NULL, then arg points to a structure containing a pointer
 *  to a function that will be executed in the current environment.
 */
int sh_funscope(int argn, char *argv[],int(*fun)(void*),void *arg,int execflg)
{
	register char		*trap;
	register int		nsig;
	register Shell_t	*shp =  &sh;
	struct dolnod		*argsav=0,*saveargfor;
	struct sh_scoped	savst, *prevscope = shp->st.self;
	struct argnod		*envlist=0;
	int			jmpval;
	volatile int		r = 0;
	char 			*savstak;
	struct funenv		*fp;
	struct checkpt		buff;
	Namval_t		*nspace = shp->namespace;
	Dt_t			*last_root = shp->last_root;
	Shopt_t			options = shp->options;
	if(shp->fn_depth==0)
		shp->glob_options =  shp->options;
	else
		shp->options = shp->glob_options;
#if 0
	shp->st.lineno = error_info.line;
#endif
	*prevscope = shp->st;
	sh_offoption(SH_ERREXIT);
	shp->st.prevst = prevscope;
	shp->st.self = &savst;
	shp->topscope = (Shscope_t*)shp->st.self;
	shp->st.opterror = shp->st.optchar = 0;
	shp->st.optindex = 1;
	shp->st.loopcnt = 0;
	if(!fun)
	{
		fp = (struct funenv*)arg;
		shp->st.real_fun = (fp->node)->nvalue.rp;
		envlist = fp->env;
	}
	prevscope->save_tree = shp->var_tree;
	sh_scope(shp,envlist,1);
	if(dtvnext(prevscope->save_tree)!= (shp->namespace?shp->var_base:0))
	{
		/* eliminate parent scope */
		nv_scan(prevscope->save_tree, local_exports,(void*)0, NV_EXPORT, NV_EXPORT|NV_NOSCOPE);
	}
	shp->st.save_tree = shp->var_tree;
	if(!fun)
	{
		Namval_t *np;
		if(nv_isattr(fp->node,NV_TAGGED))
			sh_onoption(SH_XTRACE);
		else
			sh_offoption(SH_XTRACE);
#if SHOPT_NAMESPACE
		if((np=(fp->node)->nvalue.rp->nspace) && np!=shp->namespace)
		{
			Dt_t *dt = shp->var_tree;
			dtview(dt,0);
			dtview(dt,nv_dict(np));
			shp->var_tree = nv_dict(np);
			shp->namespace = np;
		}
#endif /* SHOPT_NAMESPACE */
	}
	shp->st.cmdname = argv[0];
	/* save trap table */
	if((nsig=shp->st.trapmax*sizeof(char*))>0 || shp->st.trapcom[0])
	{
		nsig += sizeof(char*);
		memcpy(savstak=stakalloc(nsig),(char*)&shp->st.trapcom[0],nsig);
	}
	sh_sigreset(0);
	argsav = sh_argnew(shp,argv,&saveargfor);
	sh_pushcontext(&buff,SH_JMPFUN);
	errorpush(&buff.err,0);
	error_info.id = argv[0];
	shp->st.var_local = shp->var_tree;
	jmpval = sigsetjmp(buff.buff,0);
	if(!fun)
	{
		shp->st.filename = fp->node->nvalue.rp->fname;
		shp->st.funname = nv_name(fp->node);
		nv_putval(SH_PATHNAMENOD,shp->st.filename,NV_NOFREE);
		nv_putval(SH_FUNNAMENOD,shp->st.funname,NV_NOFREE);
	}
	if(jmpval == 0)
	{
		if(shp->fn_depth++ > MAXDEPTH)
		{
			shp->toomany = 1;
			siglongjmp(*shp->jmplist,SH_JMPERRFN);
		}
		else if(fun)
			r= (*fun)(arg);
		else
		{
			sh_exec((Shnode_t*)(nv_funtree((fp->node))),execflg|SH_ERREXIT);
			r = shp->exitval;
		}
	}
	if(--shp->fn_depth==1 && jmpval==SH_JMPERRFN)
		errormsg(SH_DICT,ERROR_exit(1),e_toodeep,argv[0]);
	sh_popcontext(&buff);
	if (shp->st.self != &savst)
		shp->var_tree = (Dt_t*)savst.save_tree;
	sh_unscope(shp);
	shp->namespace = nspace;
	shp->var_tree = (Dt_t*)prevscope->save_tree;
	if(shp->topscope != (Shscope_t*)shp->st.self)
		sh_setscope(shp->topscope);
	sh_argreset(shp,argsav,saveargfor);
	trap = shp->st.trapcom[0];
	shp->st.trapcom[0] = 0;
	sh_sigreset(1);
	if (shp->st.self != &savst)
		*shp->st.self = shp->st;
	shp->st = *prevscope;
	shp->topscope = (Shscope_t*)prevscope;
	nv_getval(sh_scoped(shp,IFSNOD));
	if(nsig)
		memcpy((char*)&shp->st.trapcom[0],savstak,nsig);
	shp->trapnote=0;
	if(nsig)
		stakset(savstak,0);
	shp->options = options;
	shp->last_root = last_root;
	if(jmpval == SH_JMPSUB)
		siglongjmp(*shp->jmplist,jmpval);
	if(trap)
	{
		sh_trap(trap,0);
		free(trap);
	}
	if(shp->exitval > SH_EXITSIG)
		sh_fault(shp->exitval&SH_EXITMASK);
	if(jmpval > SH_JMPFUN)
	{
		sh_chktrap();
		siglongjmp(*shp->jmplist,jmpval);
	}
	return(r);
}

static void sh_funct(Shell_t *shp,Namval_t *np,int argn, char *argv[],struct argnod *envlist,int execflg)
{
	struct funenv fun;
	char *fname = nv_getval(SH_FUNNAMENOD);
	struct Level	*lp =(struct Level*)(SH_LEVELNOD->nvfun);
	int		level, pipepid=shp->pipepid;
	shp->pipepid = 0;
	sh_stats(STAT_FUNCT);
	if(!lp->hdr.disc)
		lp = init_level(0);
	if((struct sh_scoped*)shp->topscope != shp->st.self)
		sh_setscope(shp->topscope);
	level = lp->maxlevel = shp->dot_depth + shp->fn_depth+1;
	SH_LEVELNOD->nvalue.s = lp->maxlevel;
	shp->st.lineno = error_info.line;
	if(nv_isattr(np,NV_FPOSIX))
	{
		char *save;
		int loopcnt = shp->st.loopcnt;
		shp->posix_fun = np;
		save = argv[-1];
		argv[-1] = 0;
		shp->st.funname = nv_name(np);
		nv_putval(SH_FUNNAMENOD, nv_name(np),NV_NOFREE);
		opt_info.index = opt_info.offset = 0;
		error_info.errors = 0;
		shp->st.loopcnt = 0;
		b_dot_cmd(argn+1,argv-1,&shp->bltindata);
		shp->st.loopcnt = loopcnt;
		argv[-1] = save;
	}
	else
	{
		fun.env = envlist;
		fun.node = np;
		sh_funscope(argn,argv,0,&fun,execflg);
	}
	if(level-- != nv_getnum(SH_LEVELNOD))
	{
		Shscope_t *sp = sh_getscope(0,SEEK_END);
		sh_setscope(sp);
	}
	lp->maxlevel = level;
	SH_LEVELNOD->nvalue.s = lp->maxlevel;
#if 0
	nv_putval(SH_FUNNAMENOD,shp->st.funname,NV_NOFREE);
#else
	nv_putval(SH_FUNNAMENOD,fname,NV_NOFREE);
#endif
	nv_putval(SH_PATHNAMENOD,shp->st.filename,NV_NOFREE);
	shp->pipepid = pipepid;
}

/*
 * external interface to execute a function without arguments
 * <np> is the function node
 * If <nq> is not-null, then sh.name and sh.subscript will be set
 */
int sh_fun(Namval_t *np, Namval_t *nq, char *argv[])
{
	Shell_t		*shp = &sh;
	register int offset;
	register char *base;
	Namval_t node;
	struct Namref	nr;
	long		mode;
	char		*prefix = shp->prefix;
	int n=0;
	char *av[2];
	Fcin_t save;
	fcsave(&save);
	if((offset=staktell())>0)
		base=stakfreeze(0);
	shp->prefix = 0;
	if(!argv)
	{
		argv = av;
		argv[1]=0;
	}
	argv[0] = nv_name(np);
	while(argv[n])
		n++;
	if(nq)
		mode = set_instance(shp,nq,&node, &nr);
	if(is_abuiltin(np))
	{
		int jmpval;
		struct checkpt buff;
		Shbltin_t *bp = &sh.bltindata;
		sh_pushcontext(&buff,SH_JMPCMD);
		jmpval = sigsetjmp(buff.buff,1);
		if(jmpval == 0)
		{
			bp->bnode = np;
			bp->ptr = nv_context(np);
			errorpush(&buff.err,0);
			error_info.id = argv[0];
			opt_info.index = opt_info.offset = 0;
			opt_info.disc = 0;
			sh.exitval = 0;
			sh.exitval = (*funptr(np))(n,argv,(void*)bp);
		}
		sh_popcontext(&buff);
		if(jmpval>SH_JMPCMD)
			siglongjmp(*sh.jmplist,jmpval);
	}
	else
		sh_funct(shp,np,n,argv,(struct argnod*)0,sh_isstate(SH_ERREXIT));
	if(nq)
		unset_instance(nq, &node, &nr, mode);
	fcrestore(&save);
	if(offset>0)
		stakset(base,offset);
	shp->prefix = prefix;
	return(sh.exitval);
}

/*
 * This dummy routine is called by built-ins that do recursion
 * on the file system (chmod, chgrp, chown).  It causes
 * the shell to invoke the non-builtin version in this case
 */
int cmdrecurse(int argc, char* argv[], int ac, char* av[])
{
	NOT_USED(argc);
	NOT_USED(argv[0]);
	NOT_USED(ac);
	NOT_USED(av[0]);
	return(SH_RUNPROG);
}

/*
 * set up pipe for cooperating process 
 */
static void coproc_init(Shell_t *shp, int pipes[])
{
	int outfd;
	if(shp->coutpipe>=0 && shp->cpid)
		errormsg(SH_DICT,ERROR_exit(1),e_pexists);
	shp->cpid = 0;
	if(shp->cpipe[0]<=0 || shp->cpipe[1]<=0)
	{
		/* first co-process */
		sh_pclose(shp->cpipe);
		sh_pipe(shp->cpipe);
		if((outfd=shp->cpipe[1]) < 10) 
		{
		        int fd=fcntl(shp->cpipe[1],F_DUPFD,10);
			if(fd>=10)
			{
			        shp->fdstatus[fd] = (shp->fdstatus[outfd]&~IOCLEX);
				close(outfd);
			        shp->fdstatus[outfd] = IOCLOSE;
				shp->cpipe[1] = fd;
			}
		}
		if(fcntl(*shp->cpipe,F_SETFD,FD_CLOEXEC)>=0)
			shp->fdstatus[shp->cpipe[0]] |= IOCLEX;
		shp->fdptrs[shp->cpipe[0]] = shp->cpipe;
			
		if(fcntl(shp->cpipe[1],F_SETFD,FD_CLOEXEC) >=0)
			shp->fdstatus[shp->cpipe[1]] |= IOCLEX;
	}
	shp->outpipe = shp->cpipe;
	sh_pipe(shp->inpipe=pipes);
	shp->coutpipe = shp->inpipe[1];
	shp->fdptrs[shp->coutpipe] = &shp->coutpipe;
	if(fcntl(shp->outpipe[0],F_SETFD,FD_CLOEXEC)>=0)
		shp->fdstatus[shp->outpipe[0]] |= IOCLEX;
}

#if SHOPT_SPAWN


#if SHOPT_AMP || !defined(_lib_fork)
/*
 * print out function definition
 */
static void print_fun(register Namval_t* np, void *data)
{
	register char *format;
	NOT_USED(data);
	if(!is_afunction(np) || !np->nvalue.ip)
		return;
	if(nv_isattr(np,NV_FPOSIX))
		format="%s()\n{ ";
	else
		format="function %s\n{ ";
	sfprintf(sfstdout,format,nv_name(np));
	sh_deparse(sfstdout,(Shnode_t*)(nv_funtree(np)),0);
	sfwrite(sfstdout,"}\n",2);
}

/*
 * create a shell script consisting of t->fork.forktre and execute it
 */
static int run_subshell(const Shnode_t *t,pid_t grp)
{
	static const char prolog[] = "(print $(typeset +A);set; typeset -p; print .sh.dollar=$$;set +o)";
	register int i, fd, trace = sh_isoption(SH_XTRACE);
	int pin,pout;
	pid_t pid;
	char *arglist[2], *envlist[2], devfd[12], *cp;
	Sfio_t *sp = sftmp(0);
	envlist[0] = "_=" SH_ID;
	envlist[1] = 0;
	arglist[0] = error_info.id?error_info.id:sh.shname;
	if(*arglist[0]=='-')
		arglist[0]++;
	arglist[1] = devfd;
	strncpy(devfd,e_devfdNN,sizeof(devfd));
	arglist[2] = 0;
	sfstack(sfstdout,sp);
	if(trace)
		sh_offoption(SH_XTRACE);
	sfwrite(sfstdout,"typeset -A -- ",14);
	sh_trap(prolog,0);
	nv_scan(sh.fun_tree, print_fun, (void*)0,0, 0);
	if(sh.st.dolc>0)
	{
		/* pass the positional parameters */
		char **argv = sh.st.dolv+1;
		sfwrite(sfstdout,"set --",6);
		while(*argv)
			sfprintf(sfstdout," %s",sh_fmtq(*argv++));
		sfputc(sfstdout,'\n');
	}
	pin = (sh.inpipe?sh.inpipe[1]:0);
	pout = (sh.outpipe?sh.outpipe[0]:0);
	for(i=3; i < 10; i++)
	{
		if(sh.fdstatus[i]&IOCLEX && i!=pin && i!=pout)
		{
			sfprintf(sfstdout,"exec %d<&%d\n",i,i);
			fcntl(i,F_SETFD,0);
		}
	}
	sfprintf(sfstdout,"LINENO=%d\n",t->fork.forkline);
	if(trace)
	{
		sfwrite(sfstdout,"set -x\n",7);
		sh_onoption(SH_XTRACE);
	}
	sfstack(sfstdout,NIL(Sfio_t*));
	sh_deparse(sp,t->fork.forktre,0);
	sfseek(sp,(Sfoff_t)0,SEEK_SET);
	fd = sh_dup(sffileno(sp));
	cp = devfd+8;
	if(fd>9)
		*cp++ = '0' + (fd/10);
	*cp++ = '0' + fd%10;
	*cp = 0;
	sfclose(sp);
	sfsync(NIL(Sfio_t*));
	if(!sh.shpath)
		sh.shpath = pathshell();
	pid = spawnveg(sh.shpath,arglist,envlist,grp);
	close(fd);
	for(i=3; i < 10; i++)
	{
		if(sh.fdstatus[i]&IOCLEX && i!=pin && i!=pout)
			fcntl(i,F_SETFD,FD_CLOEXEC);
	}
	if(pid <=0)
		errormsg(SH_DICT,ERROR_system(ERROR_NOEXEC),e_exec,arglist[0]);
	return(pid);
}
#endif /* !_lib_fork */

static void sigreset(int mode)
{
	register char   *trap;
	register int sig=sh.st.trapmax;
	while(sig-- > 0)
	{
		if((trap=sh.st.trapcom[sig]) && *trap==0)
			signal(sig,mode?sh_fault:SIG_IGN);
	}
}

/*
 * A combined fork/exec for systems with slow or non-existent fork()
 */
static pid_t sh_ntfork(Shell_t *shp,const Shnode_t *t,char *argv[],int *jobid,int flag)
{
	static pid_t	spawnpid;
	static int	savetype;
	static int	savejobid __unused;
	struct checkpt	buff;
	int		otype=0, jmpval;
	volatile int	jobwasset=0, scope=0, sigwasset=0;
	char		**arge, *path;
	volatile pid_t	grp = 0;
	Pathcomp_t	*pp;
	if(flag)
	{
		otype = savetype;
		savetype=0;
	}
#   if SHOPT_AMP || !defined(_lib_fork)
	if(!argv)
	{
		register Shnode_t *tchild = t->fork.forktre;
		int optimize=0;
		otype = t->tre.tretyp;
		savetype = otype;
		spawnpid = 0;
#	ifndef _lib_fork
		if((tchild->tre.tretyp&COMMSK)==TCOM)
		{
			Namval_t *np = (Namval_t*)(tchild->com.comnamp);
			if(np)
			{
				path = nv_name(np);
				if(!nv_isattr(np,BLT_ENV))
					np=0;
				else if(strcmp(path,"echo")==0 || memcmp(path,"print",5)==0)
					np=0;
			}
			else if(!tchild->com.comarg)
				optimize=1;
			else if(tchild->com.comtyp&COMSCAN)
			{
				if(tchild->com.comarg->argflag&ARG_RAW)
					path = tchild->com.comarg->argval;
				else
					path = 0;
			}
			else
				path = ((struct dolnod*)tchild->com.comarg)->dolval[ARG_SPARE];
			if(!np && path && !nv_search(path,shp->fun_tree,0))
				optimize=1;
		}
#	endif
		sh_pushcontext(&buff,SH_JMPIO);
		jmpval = sigsetjmp(buff.buff,0);
		{
			if((otype&FINT) && !sh_isstate(SH_MONITOR))
			{
				signal(SIGQUIT,SIG_IGN);
				signal(SIGINT,SIG_IGN);
				if(!shp->st.ioset)
				{
					sh_iosave(shp,0,buff.topfd,(char*)0);
					sh_iorenumber(shp,sh_chkopen(e_devnull),0);
				}
			}
			if(otype&FPIN)
			{
				int fd = shp->inpipe[1];
				sh_iosave(shp,0,buff.topfd,(char*)0);
				sh_iorenumber(shp,shp->inpipe[0],0);
				if(fd>=0 && (!(otype&FPOU) || (otype&FCOOP)) && fcntl(fd,F_SETFD,FD_CLOEXEC)>=0)
					shp->fdstatus[fd] |= IOCLEX;
			}
			if(otype&FPOU)
			{
				sh_iosave(shp,1,buff.topfd,(char*)0);
				sh_iorenumber(shp,sh_dup(shp->outpipe[1]),1);
				if(fcntl(shp->outpipe[0],F_SETFD,FD_CLOEXEC)>=0)
					shp->fdstatus[shp->outpipe[0]] |= IOCLEX;
			}
	
			if(t->fork.forkio)
				sh_redirect(shp,t->fork.forkio,0);
			if(optimize==0)
			{
#ifdef SIGTSTP
				if(job.jobcontrol)
				{
					signal(SIGTTIN,SIG_DFL);
					signal(SIGTTOU,SIG_DFL);
				}
#endif /* SIGTSTP */
#ifdef JOBS
				if(sh_isstate(SH_MONITOR) && (job.jobcontrol || (otype&FAMP)))
				{
					if((otype&FAMP) || job.curpgid==0)
						grp = 1;
					else
						grp = job.curpgid;
				}
#endif /* JOBS */
				spawnpid = run_subshell(t,grp);
			}
			else
			{
				sh_exec(tchild,SH_NTFORK);
				if(jobid)
					*jobid = savejobid;
			}
		}
		sh_popcontext(&buff);
		if((otype&FINT) && !sh_isstate(SH_MONITOR))
		{
			signal(SIGQUIT,sh_fault);
			signal(SIGINT,sh_fault);
		}
		if((otype&FPIN) && (!(otype&FPOU) || (otype&FCOOP)) && fcntl(shp->inpipe[1],F_SETFD,FD_CLOEXEC)>=0)
			shp->fdstatus[shp->inpipe[1]] &= ~IOCLEX;
		if(t->fork.forkio || otype)
			sh_iorestore(shp,buff.topfd,jmpval);
		if(optimize==0)
		{
#ifdef SIGTSTP
			if(job.jobcontrol)
			{
				signal(SIGTTIN,SIG_IGN);
				signal(SIGTTOU,SIG_IGN);
			}
#endif /* SIGTSTP */
			if(spawnpid>0)
				_sh_fork(spawnpid,otype,jobid);
			if(grp>0 && !(otype&FAMP))
			{
				while(tcsetpgrp(job.fd,job.curpgid)<0 && job.curpgid!=spawnpid)
					job.curpgid = spawnpid;
			}
		}
		savetype=0;
		if(jmpval>SH_JMPIO)
			siglongjmp(*shp->jmplist,jmpval);
		if(spawnpid<0 && (otype&FCOOP))
		{
			sh_close(shp->coutpipe);
			sh_close(shp->cpipe[1]);
			shp->cpipe[1] = -1;
			shp->coutpipe = -1;
		}
		shp->exitval = 0;
		return(spawnpid);
	}
#   endif /* !_lib_fork */
	sh_pushcontext(&buff,SH_JMPCMD);
	errorpush(&buff.err,ERROR_SILENT);
	jmpval = sigsetjmp(buff.buff,0);
	if(jmpval == 0)
	{
		if((otype&FINT) && !sh_isstate(SH_MONITOR))
		{
			signal(SIGQUIT,SIG_IGN);
			signal(SIGINT,SIG_IGN);
		}
		spawnpid = -1;
		if(t->com.comio)
			sh_redirect(shp,t->com.comio,0);
		error_info.id = *argv;
		if(t->com.comset)
		{
			scope++;
			sh_scope(shp,t->com.comset,0);
		}
		if(!strchr(path=argv[0],'/')) 
		{
			Namval_t *np;
			if((np=nv_search(path,shp->track_tree,0)) && !nv_isattr(np,NV_NOALIAS) && np->nvalue.cp)
				path = nv_getval(np);
			else if(path_absolute(path,NIL(Pathcomp_t*)))
			{
			path = stkptr(shp->stk,PATH_OFFSET);
			stkfreeze(shp->stk,0);
		}
		else
		{
			pp=path_get(path);
			while(pp)
			{
				if(pp->len==1 && *pp->name=='.')
					break;
				pp = pp->next;
			}
			if(!pp)
				path = 0;
		}
	}
	else if(sh_isoption(SH_RESTRICTED))
		errormsg(SH_DICT,ERROR_exit(1),e_restricted,path);
	if(!path)
	{
		spawnpid = -1;
		goto fail;
	}
	arge = sh_envgen();
	shp->exitval = 0;
#ifdef SIGTSTP
		if(job.jobcontrol)
		{
			signal(SIGTTIN,SIG_DFL);
			signal(SIGTTOU,SIG_DFL);
			jobwasset++;
		}
#endif /* SIGTSTP */
#ifdef JOBS
		if(sh_isstate(SH_MONITOR) && (job.jobcontrol || (otype&FAMP)))
		{
			if((otype&FAMP) || job.curpgid==0)
				grp = 1;
			else
				grp = job.curpgid;
		}
#endif /* JOBS */

		sfsync(NIL(Sfio_t*));
		sigreset(0);	/* set signals to ignore */
		sigwasset++;
	        /* find first path that has a library component */
		for(pp=path_get(argv[0]); pp && !pp->lib ; pp=pp->next);
		spawnpid = path_spawn(path,argv,arge,pp,(grp<<1)|1);
		if(spawnpid < 0 && errno==ENOEXEC)
		{
			char *devfd;
			int fd = open(path,O_RDONLY);
			argv[-1] = argv[0];
			argv[0] = path;
			if(fd>=0)
			{
				struct stat statb;
				sfprintf(sh.strbuf,"/dev/fd/%d",fd);
				if(stat(devfd=sfstruse(sh.strbuf),&statb)>=0)
					argv[0] =  devfd;
			}
			if(!shp->shpath)
				shp->shpath = pathshell();
			spawnpid = path_spawn(shp->shpath,&argv[-1],arge,pp,(grp<<1)|1);
			if(fd>=0)
				close(fd);
			argv[0] = argv[-1];
		}
	fail:
		if(spawnpid < 0) switch(errno=shp->path_err)
		{
		    case ENOENT:
			errormsg(SH_DICT,ERROR_system(ERROR_NOENT),e_found+4);
			/* FALLTHROUGH */
		    default:
			errormsg(SH_DICT,ERROR_system(ERROR_NOEXEC),e_exec+4);
		}
	}
	else
		exitset();
	sh_popcontext(&buff);
	if(buff.olist)
		free_list(buff.olist);
#ifdef SIGTSTP
	if(jobwasset)
	{
		signal(SIGTTIN,SIG_IGN);
		signal(SIGTTOU,SIG_IGN);
	}
#endif /* SIGTSTP */
	if(sigwasset)
		sigreset(1);	/* restore ignored signals */
	if(scope)
	{
		sh_unscope(shp);
		if(jmpval==SH_JMPSCRIPT)
			nv_setlist(t->com.comset,NV_EXPORT|NV_IDENT|NV_ASSIGN,0);
	}
	if(t->com.comio)
		sh_iorestore(shp,buff.topfd,jmpval);
	if(jmpval>SH_JMPCMD)
		siglongjmp(*shp->jmplist,jmpval);
	if(spawnpid>0)
	{
		_sh_fork(spawnpid,otype,jobid);
#ifdef JOBS
		if(grp==1)
			job.curpgid = spawnpid;
#   ifdef SIGTSTP
		if(grp>0 && !(otype&FAMP))
		{
			while(tcsetpgrp(job.fd,job.curpgid)<0 && job.curpgid!=spawnpid)
				job.curpgid = spawnpid;
		}
#   endif /* SIGTSTP */
#endif /* JOBS */
		savejobid = *jobid;
		if(otype)
			return(0);
	}
	return(spawnpid);
}

#   ifdef _was_lib_fork
#	define _lib_fork	1
#   endif
#   ifndef _lib_fork
	pid_t fork(void)
	{
		errormsg(SH_DICT,ERROR_exit(3),e_notimp,"fork");
		return(-1);
	}
#   endif /* _lib_fork */
#endif /* SHOPT_SPAWN */
