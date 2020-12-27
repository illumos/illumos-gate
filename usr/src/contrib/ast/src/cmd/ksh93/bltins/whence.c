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
 * command [-pvVx] name [arg...]
 * whence [-afvp] name...
 *
 *   David Korn
 *   AT&T Labs
 *
 */

#include	"defs.h"
#include	<error.h>
#include	"shtable.h"
#include	"name.h"
#include	"path.h"
#include	"shlex.h"
#include	"builtins.h"

#define P_FLAG	1
#define V_FLAG	2
#define A_FLAG	4
#define F_FLAG	010
#define X_FLAG	020
#define Q_FLAG	040

static int whence(Shell_t *,char**, int);

/*
 * command is called with argc==0 when checking for -V or -v option
 * In this case return 0 when -v or -V or unknown option, otherwise
 *   the shift count to the command is returned
 */
int	b_command(register int argc,char *argv[],Shbltin_t *context)
{
	register int n, flags=0;
	register Shell_t *shp = context->shp;
	opt_info.index = opt_info.offset = 0;
	while((n = optget(argv,sh_optcommand))) switch(n)
	{
	    case 'p':
		if(sh_isoption(SH_RESTRICTED))
			 errormsg(SH_DICT,ERROR_exit(1),e_restricted,"-p");
		sh_onstate(SH_DEFPATH);
		break;
	    case 'v':
		flags |= X_FLAG;
		break;
	    case 'V':
		flags |= V_FLAG;
		break;
	    case 'x':
		shp->xargexit = 1;
		break;
	    case ':':
		if(argc==0)
			return(0);
		errormsg(SH_DICT,2, "%s", opt_info.arg);
		break;
	    case '?':
		if(argc==0)
			return(0);
		errormsg(SH_DICT,ERROR_usage(2), "%s", opt_info.arg);
		break;
	}
	if(argc==0)
		return(flags?0:opt_info.index);
	argv += opt_info.index;
	if(error_info.errors || !*argv)
		errormsg(SH_DICT,ERROR_usage(2),"%s", optusage((char*)0));
	return(whence(shp,argv, flags));
}

/*
 *  for the whence command
 */
int	b_whence(int argc,char *argv[],Shbltin_t *context)
{
	register int flags=0, n;
	register Shell_t *shp = context->shp;
	NOT_USED(argc);
	if(*argv[0]=='t')
		flags = V_FLAG;
	while((n = optget(argv,sh_optwhence))) switch(n)
	{
	    case 'a':
		flags |= A_FLAG;
		/* FALL THRU */
	    case 'v':
		flags |= V_FLAG;
		break;
	    case 'f':
		flags |= F_FLAG;
		break;
	    case 'p':
		flags |= P_FLAG;
		flags &= ~V_FLAG;
		break;
	    case 'q':
		flags |= Q_FLAG;
		break;
	    case ':':
		errormsg(SH_DICT,2, "%s", opt_info.arg);
		break;
	    case '?':
		errormsg(SH_DICT,ERROR_usage(2), "%s", opt_info.arg);
		break;
	}
	argv += opt_info.index;
	if(error_info.errors || !*argv)
		errormsg(SH_DICT,ERROR_usage(2),optusage((char*)0));
	return(whence(shp, argv, flags));
}

static int whence(Shell_t *shp,char **argv, register int flags)
{
	register const char *name;
	register Namval_t *np;
	register const char *cp;
	register int aflag,r=0;
	register const char *msg;
	int	tofree;
	Dt_t *root;
	Namval_t *nq;
	char *notused;
	Pathcomp_t *pp=0;
	int notrack = 1;
	if(flags&Q_FLAG)
		flags &= ~A_FLAG;
	while(name= *argv++)
	{
		tofree=0;
		aflag = ((flags&A_FLAG)!=0);
		cp = 0;
		np = 0;
		if(flags&P_FLAG)
			goto search;
		if(flags&Q_FLAG)
			goto bltins;
		/* reserved words first */
		if(sh_lookup(name,shtab_reserved))
		{
			sfprintf(sfstdout,"%s%s\n",name,(flags&V_FLAG)?sh_translate(is_reserved):"");
			if(!aflag)
				continue;
			aflag++;
		}
		/* non-tracked aliases */
		if((np=nv_search(name,shp->alias_tree,0))
			&& !nv_isnull(np) && !(notrack=nv_isattr(np,NV_TAGGED))
			&& (cp=nv_getval(np))) 
		{
			if(flags&V_FLAG)
			{
				if(nv_isattr(np,NV_EXPORT))
					msg = sh_translate(is_xalias);
				else
					msg = sh_translate(is_alias);
				sfprintf(sfstdout,msg,name);
			}
			sfputr(sfstdout,sh_fmtq(cp),'\n');
			if(!aflag)
				continue;
			cp = 0;
			aflag++;
		}
		/* built-ins and functions next */
	bltins:
		root = (flags&F_FLAG)?shp->bltin_tree:shp->fun_tree;
		if(np= nv_bfsearch(name, root, &nq, &notused))
		{
			if(is_abuiltin(np) && nv_isnull(np))
				goto search;
			cp = "";
			if(flags&V_FLAG)
			{
				if(nv_isnull(np))
					cp = sh_translate(is_ufunction);
				else if(is_abuiltin(np))
				{
					if(nv_isattr(np,BLT_SPC))
						cp = sh_translate(is_spcbuiltin);
					else
						cp = sh_translate(is_builtin);
				}
				else
					cp = sh_translate(is_function);
			}
			if(flags&Q_FLAG)
				continue;
			sfprintf(sfstdout,"%s%s\n",name,cp);
			if(!aflag)
				continue;
			cp = 0;
			aflag++;
		}
	search:
		if(sh_isstate(SH_DEFPATH))
		{
			cp=0;
			notrack=1;
		}
		do
		{
			if(path_search(shp,name,&pp,2+(aflag>1)))
			{
				cp = name;
				if((flags&P_FLAG) && *cp!='/')
					cp = 0;
			}
			else
			{
				cp = stakptr(PATH_OFFSET);
				if(*cp==0)
					cp = 0;
				else if(*cp!='/')
				{
					cp = path_fullname(shp,cp);
					tofree=1;
				}
			}
			if(flags&Q_FLAG)
			{
				pp = 0;
				r |= !cp;
			}
			else if(cp)
			{
				if(flags&V_FLAG)
				{
					if(*cp!= '/')
					{
						if(!np && (np=nv_search(name,shp->track_tree,0)))
							sfprintf(sfstdout,"%s %s %s/%s\n",name,sh_translate(is_talias),path_pwd(shp,0),cp);
						else if(!np || nv_isnull(np))
							sfprintf(sfstdout,"%s%s\n",name,sh_translate(is_ufunction));
						continue;
					}
					sfputr(sfstdout,sh_fmtq(name),' ');
					/* built-in version of program */
					if(*cp=='/' && (np=nv_search(cp,shp->bltin_tree,0)))
						msg = sh_translate(is_builtver);
					/* tracked aliases next */
					else if(aflag>1 || !notrack || strchr(name,'/'))
						msg = sh_translate("is");
					else
						msg = sh_translate(is_talias);
					sfputr(sfstdout,msg,' ');
				}
				sfputr(sfstdout,sh_fmtq(cp),'\n');
				if(aflag)
				{
					if(aflag<=1)
						aflag++;
					if (pp)
						pp = pp->next;
				}
				else
					pp = 0;
				if(tofree)
				{
					free((char*)cp);
					tofree = 0;
				}
			}
			else if(aflag<=1) 
			{
				r |= 1;
				if(flags&V_FLAG)
					 errormsg(SH_DICT,ERROR_exit(0),e_found,sh_fmtq(name));
			}
		} while(pp);
	}
	return(r);
}

