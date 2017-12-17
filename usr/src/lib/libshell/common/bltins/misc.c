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
 * exec [arg...]
 * eval [arg...]
 * jobs [-lnp] [job...]
 * login [arg...]
 * let expr...
 * . file [arg...]
 * :, true, false
 * vpath [top] [base]
 * vmap [top] [base]
 * wait [job...]
 * shift [n]
 *
 *   David Korn
 *   AT&T Labs
 *
 */

#include	"defs.h"
#include	"variables.h"
#include	"shnodes.h"
#include	"path.h"
#include	"io.h"
#include	"name.h"
#include	"history.h"
#include	"builtins.h"
#include	"jobs.h"

#define DOTMAX	MAXDEPTH	/* maximum level of . nesting */

static void     noexport(Namval_t*,void*);

struct login
{
	Shell_t *sh;
	int     clear;
	char    *arg0;
};

int
b_exec(int argc __unused, char *argv[], void *extra)
{
	struct login logdata;
	register int n;
	logdata.clear = 0;
	logdata.arg0 = 0;
	logdata.sh = ((Shbltin_t*)extra)->shp;
        logdata.sh->st.ioset = 0;
	while (n = optget(argv, sh_optexec)) switch (n)
	{
	    case 'a':
		logdata.arg0 = opt_info.arg;
		argc = 0;
		break;
	    case 'c':
		logdata.clear=1;
		break;
	    case ':':
		errormsg(SH_DICT,2, "%s", opt_info.arg);
		break;
	    case '?':
		errormsg(SH_DICT,ERROR_usage(0), "%s", opt_info.arg);
		return(2);
	}
	argv += opt_info.index;
	if(error_info.errors)
		errormsg(SH_DICT,ERROR_usage(2),"%s",optusage((char*)0));
	if(*argv)
                B_login(0,argv,(void*)&logdata);
	return(0);
}

static void     noexport(register Namval_t* np, void *data)
{
	NOT_USED(data);
	nv_offattr(np,NV_EXPORT);
}

int    B_login(int argc,char *argv[],void *extra)
{
	struct checkpt *pp;
	register struct login *logp=0;
	register Shell_t *shp;
	const char *pname;
	if(argc)
		shp = ((Shbltin_t*)extra)->shp;
	else
	{
		logp = (struct login*)extra;
		shp = logp->sh;
	}
	pp = (struct checkpt*)shp->jmplist;
	if(sh_isoption(SH_RESTRICTED))
		errormsg(SH_DICT,ERROR_exit(1),e_restricted,argv[0]);
	else
        {
		register struct argnod *arg=shp->envlist;
		register Namval_t* np;
		register char *cp;
		if(shp->subshell && !shp->subshare)
			sh_subfork();
		if(logp && logp->clear)
		{
#ifdef _ENV_H
			env_close(shp->env);
			shp->env = env_open((char**)0,3);
#else
			nv_scan(shp->var_tree,noexport,0,NV_EXPORT,NV_EXPORT);
#endif
		}
		while(arg)
		{
			if((cp=strchr(arg->argval,'=')) &&
				(*cp=0,np=nv_search(arg->argval,shp->var_tree,0)))
			{
				nv_onattr(np,NV_EXPORT);
				sh_envput(shp->env,np);
			}
			if(cp)
				*cp = '=';
			arg=arg->argnxt.ap;
		}
		pname = argv[0];
		if(logp && logp->arg0)
			argv[0] = logp->arg0;
#ifdef JOBS
		if(job_close(shp) < 0)
			return(1);
#endif /* JOBS */
		/* force bad exec to terminate shell */
		pp->mode = SH_JMPEXIT;
		sh_sigreset(2);
		sh_freeup(shp);
		path_exec(pname,argv,NIL(struct argnod*));
		sh_done(shp,0);
        }
	return(1);
}

int    b_let(int argc,char *argv[],void *extra)
{
	register int r;
	register char *arg;
	NOT_USED(argc);
	NOT_USED(extra);
	while (r = optget(argv,sh_optlet)) switch (r)
	{
	    case ':':
		errormsg(SH_DICT,2, "%s", opt_info.arg);
		break;
	    case '?':
		errormsg(SH_DICT,ERROR_usage(2), "%s", opt_info.arg);
		break;
	}
	argv += opt_info.index;
	if(error_info.errors || !*argv)
		errormsg(SH_DICT,ERROR_usage(2),"%s",optusage((char*)0));
	while(arg= *argv++)
		r = !sh_arith(arg);
	return(r);
}

int    b_eval(int argc,char *argv[], void *extra)
{
	register int r;
	register Shell_t *shp = ((Shbltin_t*)extra)->shp;
	NOT_USED(argc);
	while (r = optget(argv,sh_opteval)) switch (r)
	{
	    case ':':
		errormsg(SH_DICT,2, "%s", opt_info.arg);
		break;
	    case '?':
		errormsg(SH_DICT,ERROR_usage(0), "%s",opt_info.arg);
		return(2);
	}
	if(error_info.errors)
		errormsg(SH_DICT,ERROR_usage(2),"%s",optusage((char*)0));
	argv += opt_info.index;
	if(*argv && **argv)
	{
		sh_offstate(SH_MONITOR);
		sh_eval(sh_sfeval(argv),0);
	}
	return(shp->exitval);
}

int    b_dot_cmd(register int n,char *argv[],void* extra)
{
	register char *script;
	register Namval_t *np;
	register int jmpval;
	register Shell_t *shp = ((Shbltin_t*)extra)->shp;
	struct sh_scoped savst, *prevscope = shp->st.self;
	char *filename=0;
	int	fd;
	struct dolnod   *argsave=0, *saveargfor;
	struct checkpt buff;
	Sfio_t *iop=0;
	short level;
	while (n = optget(argv,sh_optdot)) switch (n)
	{
	    case ':':
		errormsg(SH_DICT,2, "%s", opt_info.arg);
		break;
	    case '?':
		errormsg(SH_DICT,ERROR_usage(0), "%s",opt_info.arg);
		return(2);
	}
	argv += opt_info.index;
	script = *argv;
	if(error_info.errors || !script)
		errormsg(SH_DICT,ERROR_usage(2),"%s",optusage((char*)0));
	if(shp->dot_depth+1 > DOTMAX)
		errormsg(SH_DICT,ERROR_exit(1),e_toodeep,script);
	if(!(np=shp->posix_fun))
	{
		/* check for KornShell style function first */
		np = nv_search(script,shp->fun_tree,0);
		if(np && is_afunction(np) && !nv_isattr(np,NV_FPOSIX))
		{
			if(!np->nvalue.ip)
			{
				path_search(script,NIL(Pathcomp_t**),0);
				if(np->nvalue.ip)
				{
					if(nv_isattr(np,NV_FPOSIX))
						np = 0;
				}
				else
					errormsg(SH_DICT,ERROR_exit(1),e_found,script);
			}
		}
		else
			np = 0;
		if(!np)
		{
			if((fd=path_open(script,path_get(script))) < 0)
				errormsg(SH_DICT,ERROR_system(1),e_open,script);
			filename = path_fullname(stkptr(shp->stk,PATH_OFFSET));
		}
	}
	*prevscope = shp->st;
	shp->st.lineno = np?((struct functnod*)nv_funtree(np))->functline:1;
	shp->st.var_local = shp->st.save_tree = shp->var_tree;
	if(filename)
	{
		shp->st.filename = filename;
		shp->st.lineno = 1;
	}
	level  = shp->fn_depth+shp->dot_depth+1;
	nv_putval(SH_LEVELNOD,(char*)&level,NV_INT16);
	shp->st.prevst = prevscope;
	shp->st.self = &savst;
	shp->topscope = (Shscope_t*)shp->st.self;
	prevscope->save_tree = shp->var_tree;
	shp->st.cmdname = argv[0];
	if(np)
		shp->st.filename = np->nvalue.rp->fname;
	nv_putval(SH_PATHNAMENOD, shp->st.filename ,NV_NOFREE);
	shp->posix_fun = 0;
	if(np || argv[1])
		argsave = sh_argnew(shp,argv,&saveargfor);
	sh_pushcontext(&buff,SH_JMPDOT);
	jmpval = sigsetjmp(buff.buff,0);
	if(jmpval == 0)
	{
		shp->dot_depth++;
		if(np)
			sh_exec((Shnode_t*)(nv_funtree(np)),sh_isstate(SH_ERREXIT));
		else
		{
			char buff[IOBSIZE+1];
			iop = sfnew(NIL(Sfio_t*),buff,IOBSIZE,fd,SF_READ);
			sh_eval(iop,0);
		}
	}
	sh_popcontext(&buff);
	if(!np)
		free((void*)shp->st.filename);
	shp->dot_depth--;
	if((np || argv[1]) && jmpval!=SH_JMPSCRIPT)
		sh_argreset(shp,argsave,saveargfor);
	else
	{
		prevscope->dolc = shp->st.dolc;
		prevscope->dolv = shp->st.dolv;
	}
	if (shp->st.self != &savst)
		*shp->st.self = shp->st;
	/* only restore the top Shscope_t portion for posix functions */
	memcpy((void*)&shp->st, (void*)prevscope, sizeof(Shscope_t));
	shp->topscope = (Shscope_t*)prevscope;
	nv_putval(SH_PATHNAMENOD, shp->st.filename ,NV_NOFREE);
	if(shp->exitval > SH_EXITSIG)
		sh_fault(shp->exitval&SH_EXITMASK);
	if(jmpval && jmpval!=SH_JMPFUN)
		siglongjmp(*shp->jmplist,jmpval);
	return(shp->exitval);
}

/*
 * null, true  command
 */
int    b_true(int argc,register char *argv[],void *extra)
{
	NOT_USED(argc);
	NOT_USED(argv[0]);
	NOT_USED(extra);
	return(0);
}

/*
 * false  command
 */
int    b_false(int argc,register char *argv[], void *extra)
{
	NOT_USED(argc);
	NOT_USED(argv[0]);
	NOT_USED(extra);
	return(1);
}

int    b_shift(register int n, register char *argv[], void *extra)
{
	register char *arg;
	register Shell_t *shp = ((Shbltin_t*)extra)->shp;
	while((n = optget(argv,sh_optshift))) switch(n)
	{
		case ':':
			errormsg(SH_DICT,2, "%s", opt_info.arg);
			break;
		case '?':
			errormsg(SH_DICT,ERROR_usage(0), "%s",opt_info.arg);
			return(2);
	}
	if(error_info.errors)
		errormsg(SH_DICT,ERROR_usage(2),"%s",optusage((char*)0));
	argv += opt_info.index;
	n = ((arg= *argv)?(int)sh_arith(arg):1);
	if(n<0 || shp->st.dolc<n)
		errormsg(SH_DICT,ERROR_exit(1),e_number,arg);
	else
	{
		shp->st.dolv += n;
		shp->st.dolc -= n;
	}
	return(0);
}

int    b_wait(int n,register char *argv[],void *extra)
{
	register Shell_t *shp = ((Shbltin_t*)extra)->shp;
	while((n = optget(argv,sh_optwait))) switch(n)
	{
		case ':':
			errormsg(SH_DICT,2, "%s", opt_info.arg);
			break;
		case '?':
			errormsg(SH_DICT,ERROR_usage(2), "%s",opt_info.arg);
			break;
	}
	if(error_info.errors)
		errormsg(SH_DICT,ERROR_usage(2),"%s",optusage((char*)0));
	argv += opt_info.index;
	job_bwait(argv);
	return(shp->exitval);
}

#ifdef JOBS
#   if 0
    /* for the dictionary generator */
	int    b_fg(int n,char *argv[],void *extra){}
	int    b_disown(int n,char *argv[],void *extra){}
#   endif
int    b_bg(register int n,register char *argv[],void *extra)
{
	register int flag = **argv;
	register Shell_t *shp = ((Shbltin_t*)extra)->shp;
	register const char *optstr = sh_optbg; 
	if(*argv[0]=='f')
		optstr = sh_optfg;
	else if(*argv[0]=='d')
		optstr = sh_optdisown;
	while((n = optget(argv,optstr))) switch(n)
	{
	    case ':':
		errormsg(SH_DICT,2, "%s", opt_info.arg);
		break;
	    case '?':
		errormsg(SH_DICT,ERROR_usage(2), "%s",opt_info.arg);
		break;
	}
	if(error_info.errors)
		errormsg(SH_DICT,ERROR_usage(2),"%s",optusage((char*)0));
	argv += opt_info.index;
	if(!sh_isoption(SH_MONITOR) || !job.jobcontrol)
	{
		if(sh_isstate(SH_INTERACTIVE))
			errormsg(SH_DICT,ERROR_exit(1),e_no_jctl);
		return(1);
	}
	if(flag=='d' && *argv==0)
		argv = (char**)0;
	if(job_walk(sfstdout,job_switch,flag,argv))
		errormsg(SH_DICT,ERROR_exit(1),e_no_job);
	return(shp->exitval);
}

int    b_jobs(register int n,char *argv[],void *extra)
{
	register int flag = 0;
	register Shell_t *shp = ((Shbltin_t*)extra)->shp;
	while((n = optget(argv,sh_optjobs))) switch(n)
	{
	    case 'l':
		flag = JOB_LFLAG;
		break;
	    case 'n':
		flag = JOB_NFLAG;
		break;
	    case 'p':
		flag = JOB_PFLAG;
		break;
	    case ':':
		errormsg(SH_DICT,2, "%s", opt_info.arg);
		break;
	    case '?':
		errormsg(SH_DICT,ERROR_usage(2), "%s",opt_info.arg);
		break;
	}
	argv += opt_info.index;
	if(error_info.errors)
		errormsg(SH_DICT,ERROR_usage(2),"%s",optusage((char*)0));
	if(*argv==0)
		argv = (char**)0;
	if(job_walk(sfstdout,job_list,flag,argv))
		errormsg(SH_DICT,ERROR_exit(1),e_no_job);
	job_wait((pid_t)0);
	return(shp->exitval);
}
#endif

#ifdef _cmd_universe
/*
 * There are several universe styles that are masked by the getuniv(),
 * setuniv() calls.
 */
int	b_universe(int argc, char *argv[],void *extra)
{
	register char *arg;
	register int n;
	NOT_USED(extra);
	while((n = optget(argv,sh_optuniverse))) switch(n)
	{
	    case ':':
		errormsg(SH_DICT,2, "%s", opt_info.arg);
		break;
	    case '?':
		errormsg(SH_DICT,ERROR_usage(2), "%s",opt_info.arg);
		break;
	}
	argv += opt_info.index;
	argc -= opt_info.index;
	if(error_info.errors || argc>1)
		errormsg(SH_DICT,ERROR_usage(2),"%s",optusage((char*)0));
	if(arg = argv[0])
	{
		if(!astconf("UNIVERSE",0,arg))
			errormsg(SH_DICT,ERROR_exit(1), e_badname,arg);
	}
	else
	{
		if(!(arg=astconf("UNIVERSE",0,0)))
			errormsg(SH_DICT,ERROR_exit(1),e_nouniverse);
		else
			sfputr(sfstdout,arg,'\n');
	}
	return(0);
}
#endif /* cmd_universe */

#if SHOPT_FS_3D
#   if 0
    /* for the dictionary generator */
    int	b_vmap(int argc,char *argv[], void *extra){}
#   endif
    int	b_vpath(register int argc,char *argv[], void *extra)
    {
	register int flag, n;
	register const char *optstr; 
	register char *vend; 
	register Shell_t *shp = ((Shbltin_t*)extra)->shp;
	if(argv[0][1]=='p')
	{
		optstr = sh_optvpath;
		flag = FS3D_VIEW;
	}
	else
	{
		optstr = sh_optvmap;
		flag = FS3D_VERSION;
	}
	while(n = optget(argv, optstr)) switch(n)
	{
	    case ':':
		errormsg(SH_DICT,2, "%s", opt_info.arg);
		break;
	    case '?':
		errormsg(SH_DICT,ERROR_usage(2), "%s",opt_info.arg);
		break;
	}
	if(error_info.errors)
		errormsg(SH_DICT,ERROR_usage(2),"%s",optusage((char*)0));
	if(!shp->lim.fs3d)
		goto failed;
	argv += opt_info.index;
	argc -= opt_info.index;
	switch(argc)
	{
	    case 0:
	    case 1:
		flag |= FS3D_GET;
		if((n = mount(*argv,(char*)0,flag,0)) >= 0)
		{
			vend = stkalloc(shp->stk,++n);
			n = mount(*argv,vend,flag|FS3D_SIZE(n),0);
		}
		if(n < 0)
			goto failed;
		if(argc==1)
		{
			sfprintf(sfstdout,"%s\n",vend);
			break;
		}
		n = 0;
		while(flag = *vend++)
		{
			if(flag==' ')
			{
				flag  = e_sptbnl[n+1];
				n = !n;
			}
			sfputc(sfstdout,flag);
		}
		if(n)
			sfputc(sfstdout,'\n');
		break;
	     default:
		if((argc&1))
			errormsg(SH_DICT,ERROR_usage(2),"%s",optusage((char*)0));
		/*FALLTHROUGH*/
	     case 2:
		if(!shp->lim.fs3d)
			goto failed;
		if(shp->subshell && !shp->subshare)
			sh_subfork();
 		for(n=0;n<argc;n+=2)
		{
			if(mount(argv[n+1],argv[n],flag,0)<0)
				goto failed;
		}
	}
	return(0);
failed:
	if(argc>1)
		errormsg(SH_DICT,ERROR_exit(1),e_cantset,flag==2?e_mapping:e_versions);
	else
		errormsg(SH_DICT,ERROR_exit(1),e_cantget,flag==2?e_mapping:e_versions);
	return(1);
    }
#endif /* SHOPT_FS_3D */

