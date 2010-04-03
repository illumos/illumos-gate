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
 * break [n]
 * continue [n]
 * return [n]
 * exit [n]
 *
 *   David Korn
 *   AT&T Labs
 *   dgk@research.att.com
 *
 */

#include	"defs.h"
#include	<ast.h>
#include	<error.h>
#include	"shnodes.h"
#include	"builtins.h"

/*
 * return and exit
 */
#if 0
    /* for the dictionary generator */
    int	b_exit(int n, register char *argv[],void *extra){}
#endif
int	b_return(register int n, register char *argv[],void *extra)
{
	register char *arg;
	register Shell_t *shp = ((Shbltin_t*)extra)->shp;
	struct checkpt *pp = (struct checkpt*)shp->jmplist;
	const char *options = (**argv=='r'?sh_optreturn:sh_optexit);
	while((n = optget(argv,options))) switch(n)
	{
	    case ':':
		if(!strmatch(argv[opt_info.index],"[+-]+([0-9])"))
			errormsg(SH_DICT,2, "%s", opt_info.arg);
		goto done;
	    case '?':
		errormsg(SH_DICT,ERROR_usage(0), "%s", opt_info.arg);
		return(2);
	}
done:
	if(error_info.errors)
		errormsg(SH_DICT,ERROR_usage(2),"%s",optusage((char*)0));
	pp->mode = (**argv=='e'?SH_JMPEXIT:SH_JMPFUN);
	argv += opt_info.index;
	n = (((arg= *argv)?(int)strtol(arg, (char**)0, 10)&SH_EXITMASK:shp->oldexit));
	/* return outside of function, dotscript and profile is exit */
	if(shp->fn_depth==0 && shp->dot_depth==0 && !sh_isstate(SH_PROFILE))
		pp->mode = SH_JMPEXIT;
	sh_exit(shp->savexit=n);
	return(1);
}


/*
 * break and continue
 */
#if 0
    /* for the dictionary generator */
    int	b_continue(int n, register char *argv[],void *extra){}
#endif
int	b_break(register int n, register char *argv[],void *extra)
{
	char *arg;
	register int cont= **argv=='c';
	register Shell_t *shp = ((Shbltin_t*)extra)->shp;
	while((n = optget(argv,cont?sh_optcont:sh_optbreak))) switch(n)
	{
	    case ':':
		errormsg(SH_DICT,2, "%s", opt_info.arg);
		break;
	    case '?':
		errormsg(SH_DICT,ERROR_usage(0), "%s", opt_info.arg);
		return(2);
	}
	if(error_info.errors)
		errormsg(SH_DICT,ERROR_usage(2),"%s",optusage((char*)0));
	argv += opt_info.index;
	n=1;
	if(arg= *argv)
	{
		n = strtol(arg,&arg,10);
		if(n<=0 || *arg)
			errormsg(SH_DICT,ERROR_exit(1),e_nolabels,*argv);
	}
	if(shp->st.loopcnt)
	{
		shp->st.execbrk = shp->st.breakcnt = n;
		if(shp->st.breakcnt > shp->st.loopcnt)
			shp->st.breakcnt = shp->st.loopcnt;
		if(cont)
			shp->st.breakcnt = -shp->st.breakcnt;
	}
	return(0);
}

