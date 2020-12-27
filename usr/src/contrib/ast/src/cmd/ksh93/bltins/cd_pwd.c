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
 * cd [-LP]  [dirname]
 * cd [-LP]  [old] [new]
 * pwd [-LP]
 *
 *   David Korn
 *   AT&T Labs
 *   research!dgk
 *
 */

#include	"defs.h"
#include	<stak.h>
#include	<error.h>
#include	"variables.h"
#include	"path.h"
#include	"name.h"
#include	"builtins.h"
#include	<ls.h>

/*
 * Invalidate path name bindings to relative paths
 */
static void rehash(register Namval_t *np,void *data)
{
	Pathcomp_t *pp = (Pathcomp_t*)np->nvalue.cp;
	NOT_USED(data);
	if(pp && *pp->name!='/')
		_nv_unset(np,0);
}

int	b_cd(int argc, char *argv[],Shbltin_t *context)
{
	register char *dir;
	Pathcomp_t *cdpath = 0;
	register const char *dp;
	register Shell_t *shp = context->shp;
	int saverrno=0;
	int rval,flag=0;
	char *oldpwd;
	Namval_t *opwdnod, *pwdnod;
	if(sh_isoption(SH_RESTRICTED))
		errormsg(SH_DICT,ERROR_exit(1),e_restricted+4);
	while((rval = optget(argv,sh_optcd))) switch(rval)
	{
		case 'L':
			flag = 0;
			break;
		case 'P':
			flag = 1;
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
	dir =  argv[0];
	if(error_info.errors>0 || argc >2)
		errormsg(SH_DICT,ERROR_usage(2),"%s",optusage((char*)0));
	oldpwd = path_pwd(shp,0);
	opwdnod = (shp->subshell?sh_assignok(OLDPWDNOD,1):OLDPWDNOD); 
	pwdnod = (shp->subshell?sh_assignok(PWDNOD,1):PWDNOD); 
	if(argc==2)
		dir = sh_substitute(oldpwd,dir,argv[1]);
	else if(!dir)
		dir = nv_getval(HOME);
	else if(*dir == '-' && dir[1]==0)
		dir = nv_getval(opwdnod);
	if(!dir || *dir==0)
		errormsg(SH_DICT,ERROR_exit(1),argc==2?e_subst+4:e_direct);
#if _WINIX
	if(*dir != '/' && (dir[1]!=':'))
#else
	if(*dir != '/')
#endif /* _WINIX */
	{
		if(!(cdpath = (Pathcomp_t*)shp->cdpathlist) && (dp=sh_scoped(shp,CDPNOD)->nvalue.cp))
		{
			if(cdpath=path_addpath(shp,(Pathcomp_t*)0,dp,PATH_CDPATH))
			{
				shp->cdpathlist = (void*)cdpath;
				cdpath->shp = shp;
			}
		}
		if(!oldpwd)
			oldpwd = path_pwd(shp,1);
	}
	if(*dir!='/')
	{
		/* check for leading .. */
		char *cp;
		sfprintf(shp->strbuf,"%s",dir);
		cp = sfstruse(shp->strbuf);
		pathcanon(cp, 0);
		if(cp[0]=='.' && cp[1]=='.' && (cp[2]=='/' || cp[2]==0))
		{
			if(!shp->strbuf2)
				shp->strbuf2 = sfstropen();
			sfprintf(shp->strbuf2,"%s/%s",oldpwd,cp);
			dir = sfstruse(shp->strbuf2);
			pathcanon(dir, 0);
		}
	}
	rval = -1;
	do
	{
		dp = cdpath?cdpath->name:"";
		cdpath = path_nextcomp(shp,cdpath,dir,0);
#if _WINIX
                if(*stakptr(PATH_OFFSET+1)==':' && isalpha(*stakptr(PATH_OFFSET)))
		{
			*stakptr(PATH_OFFSET+1) = *stakptr(PATH_OFFSET);
			*stakptr(PATH_OFFSET)='/';
		}
#endif /* _WINIX */
                if(*stakptr(PATH_OFFSET)!='/')

		{
			char *last=(char*)stakfreeze(1);
			stakseek(PATH_OFFSET);
			stakputs(oldpwd);
			/* don't add '/' of oldpwd is / itself */
			if(*oldpwd!='/' || oldpwd[1])
				stakputc('/');
			stakputs(last+PATH_OFFSET);
			stakputc(0);
		}
		if(!flag)
		{
			register char *cp;
			stakseek(PATH_MAX+PATH_OFFSET);
#if SHOPT_FS_3D
			if(!(cp = pathcanon(stakptr(PATH_OFFSET),PATH_DOTDOT)))
				continue;
			/* eliminate trailing '/' */
			while(*--cp == '/' && cp>stakptr(PATH_OFFSET))
				*cp = 0;
#else
			if(*(cp=stakptr(PATH_OFFSET))=='/')
				if(!pathcanon(cp,PATH_DOTDOT))
					continue;
#endif /* SHOPT_FS_3D */
		}
		if((rval=chdir(path_relative(shp,stakptr(PATH_OFFSET)))) >= 0)
			goto success;
		if(errno!=ENOENT && saverrno==0)
			saverrno=errno;
	}
	while(cdpath);
	if(rval<0 && *dir=='/' && *(path_relative(shp,stakptr(PATH_OFFSET)))!='/')
		rval = chdir(dir);
	/* use absolute chdir() if relative chdir() fails */
	if(rval<0)
	{
		if(saverrno)
			errno = saverrno;
		errormsg(SH_DICT,ERROR_system(1),"%s:",dir);
	}
success:
	if(dir == nv_getval(opwdnod) || argc==2)
		dp = dir;	/* print out directory for cd - */
	if(flag)
	{
		dir = stakptr(PATH_OFFSET);
		if (!(dir=pathcanon(dir,PATH_PHYSICAL)))
		{
			dir = stakptr(PATH_OFFSET);
			errormsg(SH_DICT,ERROR_system(1),"%s:",dir);
		}
		stakseek(dir-stakptr(0));
	}
	dir = (char*)stakfreeze(1)+PATH_OFFSET;
	if(*dp && (*dp!='.'||dp[1]) && strchr(dir,'/'))
		sfputr(sfstdout,dir,'\n');
	if(*dir != '/')
		return(0);
	nv_putval(opwdnod,oldpwd,NV_RDONLY);
	flag = strlen(dir);
	/* delete trailing '/' */
	while(--flag>0 && dir[flag]=='/')
		dir[flag] = 0;
	nv_putval(pwdnod,dir,NV_RDONLY);
	nv_onattr(pwdnod,NV_NOFREE|NV_EXPORT);
	shp->pwd = pwdnod->nvalue.cp;
	nv_scan(shp->track_tree,rehash,(void*)0,NV_TAGGED,NV_TAGGED);
	path_newdir(shp,shp->pathlist);
	path_newdir(shp,shp->cdpathlist);
	if(oldpwd && (oldpwd!=e_dot))
		free(oldpwd);
	return(0);
}

int	b_pwd(int argc, char *argv[],Shbltin_t *context)
{
	register int n, flag = 0;
	register char *cp;
	register Shell_t *shp = context->shp;
	NOT_USED(argc);
	while((n = optget(argv,sh_optpwd))) switch(n)
	{
		case 'L':
			flag = 0;
			break;
		case 'P':
			flag = 1;
			break;
		case ':':
			errormsg(SH_DICT,2, "%s", opt_info.arg);
			break;
		case '?':
			errormsg(SH_DICT,ERROR_usage(2), "%s", opt_info.arg);
			break;
	}
	if(error_info.errors)
		errormsg(SH_DICT,ERROR_usage(2),"%s",optusage((char*)0));
	if(*(cp = path_pwd(shp,0)) != '/')
		errormsg(SH_DICT,ERROR_system(1), e_pwd);
	if(flag)
	{
#if SHOPT_FS_3D
		if(shp->gd->lim.fs3d && (flag = mount(e_dot,NIL(char*),FS3D_GET|FS3D_VIEW,0))>=0)
		{
			cp = (char*)stakseek(++flag+PATH_MAX);
			mount(e_dot,cp,FS3D_GET|FS3D_VIEW|FS3D_SIZE(flag),0);
		}
		else
#endif /* SHOPT_FS_3D */
			cp = strcpy(stakseek(strlen(cp)+PATH_MAX),cp);
		pathcanon(cp,PATH_PHYSICAL);
	}
	sfputr(sfstdout,cp,'\n');
	return(0);
}

