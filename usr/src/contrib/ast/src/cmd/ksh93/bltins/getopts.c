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
 * getopts  optstring name [arg...]
 *
 *   David Korn
 *   AT&T Labs
 *   research!dgk
 *
 */

#include	"defs.h"
#include	"variables.h"
#include	<error.h>
#include	<nval.h>
#include	"builtins.h"

static int infof(Opt_t* op, Sfio_t* sp, const char* s, Optdisc_t* dp)
{
	Shell_t	*shp = *(Shell_t**)(dp+1);
	Stk_t	*stkp = shp->stk;
#if SHOPT_NAMESPACE
	if((shp->namespace && sh_fsearch(shp,s,0)) || nv_search(s,shp->fun_tree,0))
#else
	if(nv_search(s,shp->fun_tree,0))
#endif /* SHOPT_NAMESPACE */
	{
		int savtop = stktell(stkp);
		char *savptr = stkfreeze(stkp,0);
		sfputc(stkp,'$');
		sfputc(stkp,'(');
		sfputr(stkp,s,')');
		sfputr(sp,sh_mactry(shp,stkfreeze(stkp,1)),-1);
		stkset(stkp,savptr,savtop);
	}
        return(1);
}

int	b_getopts(int argc,char *argv[],Shbltin_t *context)
{
	register char *options=error_info.context->id;
	register Namval_t *np;
	register int flag, mode;
	register Shell_t *shp = context->shp;
	char value[2], key[2];
	int jmpval;
	volatile int extended, r= -1;
	struct checkpt buff, *pp;
	struct {
	        Optdisc_t	hdr;
		Shell_t		*sh;
	} disc;
        memset(&disc, 0, sizeof(disc));
        disc.hdr.version = OPT_VERSION;
        disc.hdr.infof = infof;
	disc.sh = shp;
	value[1] = 0;
	key[1] = 0;
	while((flag = optget(argv,sh_optgetopts))) switch(flag)
	{
	    case 'a':
		options = opt_info.arg;
		break;
	    case ':':
		errormsg(SH_DICT,2, "%s", opt_info.arg);
		break;
	    case '?':
		errormsg(SH_DICT,ERROR_usage(2), "%s", opt_info.arg);
		break;
	}
	argv += opt_info.index;
	argc -= opt_info.index;
	if(error_info.errors || argc<2)
		errormsg(SH_DICT,ERROR_usage(2), "%s", optusage((char*)0));
	error_info.context->flags |= ERROR_SILENT;
	error_info.id = options;
	options = argv[0];
	np = nv_open(argv[1],shp->var_tree,NV_NOASSIGN|NV_VARNAME);
	if(argc>2)
	{
		argv +=1;
		argc -=1;
	}
	else
	{
		argv = shp->st.dolv;
		argc = shp->st.dolc;
	}
	opt_info.index = shp->st.optindex;
	opt_info.offset = shp->st.optchar;
	if(mode= (*options==':'))
		options++;
	extended = *options=='\n' && *(options+1)=='[' || *options=='[' && *(options+1)=='-';
	sh_pushcontext(shp,&buff,1);
	jmpval = sigsetjmp(buff.buff,0);
	if(jmpval)
	{
		sh_popcontext(shp,&buff);
		shp->st.opterror = 1;
		if(r==0)
			return(2);
		pp = (struct checkpt*)shp->jmplist;
		pp->mode = SH_JMPERREXIT;
		sh_exit(2);
	}
        opt_info.disc = &disc.hdr;
	switch(opt_info.index>=0 && opt_info.index<=argc?(opt_info.num= LONG_MIN,flag=optget(argv,options)):0)
	{
	    case '?':
		if(mode==0)
			errormsg(SH_DICT,ERROR_usage(2), "%s", opt_info.arg);
		opt_info.option[1] = '?';
		/* FALL THRU */
	    case ':':
		key[0] = opt_info.option[1];
		if(strmatch(opt_info.arg,"*unknown*"))
			flag = '?';
		if(mode)
			opt_info.arg = key;
		else
		{
			errormsg(SH_DICT,2, "%s", opt_info.arg);
			opt_info.arg = 0;
			flag = '?';
		}
		*(options = value) = flag;
		shp->st.opterror = 1;
		if (opt_info.offset != 0 && !argv[opt_info.index][opt_info.offset])
		{
			opt_info.offset = 0;
			opt_info.index++;
		}
		break;
	    case 0:
		if(shp->st.opterror)
		{
			char *com[2];
			com[0] = "-?";
			com[1] = 0;
			flag = opt_info.index;
			opt_info.index = 0;
			optget(com,options);
			opt_info.index = flag;
			if(!mode && strchr(options,' '))
				errormsg(SH_DICT,ERROR_usage(2), "%s", optusage((char*)0));
		}
		opt_info.arg = 0;
		options = value;
		*options = '?';
		r=1;
		opt_info.offset = 0;
		break;
	    default:
		options = opt_info.option + (*opt_info.option!='+');
	}
	if(r<0)
		r = 0;
	error_info.context->flags &= ~ERROR_SILENT;
	shp->st.optindex = opt_info.index;
	shp->st.optchar = opt_info.offset;
	nv_putval(np, options, 0);
	nv_close(np);
	np = nv_open(nv_name(OPTARGNOD),shp->var_tree,0);
	if(opt_info.num == LONG_MIN)
		nv_putval(np, opt_info.arg, NV_RDONLY);
	else if (opt_info.arg && opt_info.num > 0 && isalpha((char)opt_info.num) && !isdigit(opt_info.arg[0]) && opt_info.arg[0] != '-' && opt_info.arg[0] != '+')
	{
		key[0] = (char)opt_info.num;
		key[1] = 0;
		nv_putval(np, key, NV_RDONLY);
	}
	else if(extended)
	{
		Sfdouble_t d;
		d = opt_info.number;
		nv_putval(np, (char*)&d, NV_LDOUBLE|NV_RDONLY);
	}
	else
		nv_putval(np, opt_info.arg, NV_RDONLY);
	nv_close(np);
	sh_popcontext(shp,&buff);
        opt_info.disc = 0;
	return(r);
}

