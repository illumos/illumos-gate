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
 * David Korn
 * AT&T Labs
 *
 */
/*
 * Copyright (c) 2007, 2011, Oracle and/or its affiliates. All rights reserved.
 */

#include	"defs.h"
#include	<fcin.h>
#include	<ls.h>
#include	<nval.h>
#include	"variables.h"
#include	"path.h"
#include	"io.h"
#include	"jobs.h"
#include	"history.h"
#include	"test.h"
#include	"FEATURE/dynamic"
#include	"FEATURE/externs"
#if SHOPT_PFSH 
#   ifdef _hdr_exec_attr
#	include	<exec_attr.h>
#   endif
#   if     _lib_vfork
#	include     <ast_vfork.h>
#   else
#	define vfork()      fork()
#   endif
#endif

#define RW_ALL	(S_IRUSR|S_IRGRP|S_IROTH|S_IWUSR|S_IWGRP|S_IWOTH)
#define LIBCMD	"cmd"


static int		canexecute(Shell_t*,char*,int);
static void		funload(Shell_t*,int,const char*);
static void		exscript(Shell_t*,char*, char*[], char**);
static int		path_chkpaths(Shell_t*,Pathcomp_t*,Pathcomp_t*,Pathcomp_t*,int);
static void		path_checkdup(Shell_t *shp,register Pathcomp_t*);

static const char	*std_path;

static int onstdpath(const char *name)
{
	register const char *cp = std_path, *sp;
	if(cp)
		while(*cp)
		{
			for(sp=name; *sp && (*cp == *sp); sp++,cp++);
			if(*sp==0 && (*cp==0 || *cp==':'))
				return(1);
			while(*cp && *cp++!=':');
		}
	return(0);
}

#if SHOPT_PFSH 
int path_xattr(Shell_t *shp, const char *path, char *rpath)
{
	char  resolvedpath[PATH_MAX + 1];
	if (shp->gd->user && *shp->gd->user)
	{
		execattr_t *pf;
		if(!rpath)
			rpath = resolvedpath;
		if (!realpath(path, resolvedpath))
			return -1;
		if(pf=getexecuser(shp->gd->user, KV_COMMAND, resolvedpath, GET_ONE))
		{
			if (!pf->attr || pf->attr->length == 0)
			{
				free_execattr(pf);
				return(0);
			}
			free_execattr(pf);
			return(1);
		}
	}
	errno = ENOENT;
	return(-1);
}
#endif /* SHOPT_PFSH */

static pid_t path_pfexecve(Shell_t *shp,const char *path, char *argv[],char *const envp[],int spawn)
{
#if SHOPT_PFSH 
	char  resolvedpath[PATH_MAX + 1];
	pid_t	pid;
	if(spawn)
	{
		while((pid = vfork()) < 0)
			_sh_fork(shp,pid, 0, (int*)0);
		if(pid)
			return(pid);
	}
	if(!sh_isoption(SH_PFSH))
		return(execve(path, argv, envp));
	/* Solaris implements realpath(3C) using the resolvepath(2) */
	/* system call so we can save us to call access(2) first */

	/* we can exec the command directly instead of via pfexec(1) if */
	/* there is a matching entry without attributes in exec_attr(5) */
	if(!path_xattr(shp,path,resolvedpath))
		return(execve(path, argv, envp));
	--argv;
	argv[0] = argv[1];
	argv[1] = resolvedpath;
	return(execve("/usr/bin/pfexec", argv, envp));
#else
	return(execve(path, argv, envp));
#endif
}


static pid_t _spawnveg(Shell_t *shp,const char *path, char* const argv[], char* const envp[], pid_t pgid)
{
	pid_t pid;
	while(1)
	{
		sh_stats(STAT_SPAWN);
		pid = spawnveg(path,argv,envp,pgid);
		if(pid>=0 || errno!=EAGAIN)
			break;
	}
	return(pid);
}

/*
 * used with command -x to run the command in multiple passes
 * spawn is non-zero when invoked via spawn
 * the exitval is set to the maximum for each execution
 */
static pid_t path_xargs(Shell_t *shp,const char *path, char *argv[],char *const envp[], int spawn)
{
	register char *cp, **av, **xv;
	char **avlast= &argv[shp->xargmax], **saveargs=0;
	char *const *ev;
	long size, left;
	int nlast=1,n,exitval=0;
	pid_t pid;
	if(shp->xargmin < 0)
		return((pid_t)-1);
	size = shp->gd->lim.arg_max-1024;
	for(ev=envp; cp= *ev; ev++)
		size -= strlen(cp)-1;
	for(av=argv; (cp= *av) && av< &argv[shp->xargmin]; av++)  
		size -= strlen(cp)-1;
	for(av=avlast; cp= *av; av++,nlast++)  
		size -= strlen(cp)-1;
	av =  &argv[shp->xargmin];
	if(!spawn)
		job_clear();
	shp->exitval = 0;
	while(av<avlast)
	{
		for(xv=av,left=size; left>0 && av<avlast;)
			left -= strlen(*av++)+1;
		/* leave at least two for last */
		if(left<0 && (avlast-av)<2)
			av--;
		if(xv==&argv[shp->xargmin])
		{
			n = nlast*sizeof(char*);
			saveargs = (char**)malloc(n);
			memcpy((void*)saveargs, (void*)av, n);
			memcpy((void*)av,(void*)avlast,n);
		}
		else
		{
			for(n=shp->xargmin; xv < av; xv++)
				argv[n++] = *xv;
			for(xv=avlast; cp=  *xv; xv++)
				argv[n++] = cp;
			argv[n] = 0;
		}
		if(saveargs || av<avlast || (exitval && !spawn))
		{
			if((pid=_spawnveg(shp,path,argv,envp,0)) < 0)
				return(-1);
			job_post(shp,pid,0);
			job_wait(pid);
			if(shp->exitval>exitval)
				exitval = shp->exitval;
			if(saveargs)
			{
				memcpy((void*)av,saveargs,n);
				free((void*)saveargs);
				saveargs = 0;
			}
		}
		else if(spawn && !sh_isoption(SH_PFSH))
		{
			shp->xargexit = exitval;
			if(saveargs)
				free((void*)saveargs);
			return(_spawnveg(shp,path,argv,envp,spawn>>1));
		}
		else
		{
			if(saveargs)
				free((void*)saveargs);
			return(path_pfexecve(shp,path,argv,envp,spawn));
		}
	}
	if(!spawn)
		exit(exitval);
	return((pid_t)-1);
}

/*
 * make sure PWD is set up correctly
 * Return the present working directory
 * Invokes getcwd() if flag==0 and if necessary
 * Sets the PWD variable to this value
 */
char *path_pwd(Shell_t *shp,int flag)
{
	register char *cp;
	register char *dfault = (char*)e_dot;
	register int count = 0;
	if(shp->pwd)
		return((char*)shp->pwd);
	while(1) 
	{
		/* try from lowest to highest */
		switch(count++)
		{
			case 0:
				cp = nv_getval(PWDNOD);
				break;
			case 1:
				cp = nv_getval(HOME);
				break;
			case 2:
				cp = "/";
				break;
			case 3:
				cp = (char*)e_crondir;
				if(flag) /* skip next case when non-zero flag */
					++count;
				break;
			case 4:
			{
				if(cp=getcwd(NIL(char*),0))
				{  
					nv_offattr(PWDNOD,NV_NOFREE);
					_nv_unset(PWDNOD,0);
					PWDNOD->nvalue.cp = cp;
					goto skip;
				}
				break;
			}
			case 5:
				return(dfault);
		}
		if(cp && *cp=='/' && test_inode(cp,e_dot))
			break;
	}
	if(count>1)
	{
		nv_offattr(PWDNOD,NV_NOFREE);
		nv_putval(PWDNOD,cp,NV_RDONLY);
	}
skip:
	nv_onattr(PWDNOD,NV_NOFREE|NV_EXPORT);
	shp->pwd = (char*)(PWDNOD->nvalue.cp);
	return(cp);
}

/*
 * delete current Pathcomp_t structure
 */
void  path_delete(Pathcomp_t *first)
{
	register Pathcomp_t *pp=first, *old=0, *ppnext;
	while(pp)
	{
		ppnext = pp->next;
		if(--pp->refcount<=0)
		{
			if(pp->lib)
				free((void*)pp->lib);
			if(pp->bbuf)
				free((void*)pp->bbuf);
			free((void*)pp);
			if(old)
				old->next = ppnext;
		}
		else
			old = pp;
		pp = ppnext; 
	}
}

/*
 * returns library variable from .paths
 * The value might be returned on the stack overwriting path
 */
static char *path_lib(Shell_t *shp,Pathcomp_t *pp, char *path)
{
	register char *last = strrchr(path,'/');
	register int r;
	struct stat statb;
	if(last)
		*last = 0;
	else
		path = ".";
	r = stat(path,&statb);
	if(last)
		*last = '/';
	if(r>=0)
	{
		Pathcomp_t pcomp;
		char save[8];
		for( ;pp; pp=pp->next)
		{
			path_checkdup(shp,pp);
			if(pp->ino==statb.st_ino && pp->dev==statb.st_dev && pp->mtime==statb.st_mtime)
				return(pp->lib);
		}
		pcomp.len = 0;
		if(last)
			pcomp.len = last-path;
		memcpy((void*)save, (void*)stakptr(PATH_OFFSET+pcomp.len),sizeof(save));
		if(path_chkpaths(shp,(Pathcomp_t*)0,(Pathcomp_t*)0,&pcomp,PATH_OFFSET))
			return(stakfreeze(1));
		memcpy((void*)stakptr(PATH_OFFSET+pcomp.len),(void*)save,sizeof(save));
	}
	return(0);
}

#if 0
void path_dump(register Pathcomp_t *pp)
{
	sfprintf(sfstderr,"dump\n");
	while(pp)
	{
		sfprintf(sfstderr,"pp=%x dev=%d ino=%d len=%d flags=%o name=%.*s\n",
			pp,pp->dev,pp->ino,pp->len,pp->flags,pp->len,pp->name);
		pp = pp->next;
	}
}
#endif

/*
 * check for duplicate directories on PATH
 */
static void path_checkdup(Shell_t *shp,register Pathcomp_t *pp)
{
	register char		*name = pp->name;
	register Pathcomp_t	*oldpp,*first;
	register int		flag=0;
	struct stat 		statb;
	if(stat(name,&statb)<0 || !S_ISDIR(statb.st_mode))
	{
		pp->flags |= PATH_SKIP;
		pp->dev = *name=='/';
		return;
	}
	pp->mtime = statb.st_mtime;
	pp->ino = statb.st_ino;
	pp->dev = statb.st_dev;
	if(*name=='/' && onstdpath(name))
		flag = PATH_STD_DIR;
	first = (pp->flags&PATH_CDPATH)?(Pathcomp_t*)shp->cdpathlist:path_get(shp,"");
	for(oldpp=first; oldpp && oldpp!=pp; oldpp=oldpp->next)
	{
		if(pp->ino==oldpp->ino && pp->dev==oldpp->dev && pp->mtime==oldpp->mtime)
		{
			flag |= PATH_SKIP;
			break;
		}
	}
	pp->flags |= flag;
	if(((pp->flags&(PATH_PATH|PATH_SKIP))==PATH_PATH))
	{
		int offset = staktell();
		stakputs(name);
		path_chkpaths(shp,first,0,pp,offset);
		stakseek(offset);
	}
}

/*
 * write the next path to search on the current stack
 * if last is given, all paths that come before <last> are skipped
 * the next pathcomp is returned.
 */
Pathcomp_t *path_nextcomp(Shell_t *shp,register Pathcomp_t *pp, const char *name, Pathcomp_t *last)
{
	Pathcomp_t	*ppnext;
	stakseek(PATH_OFFSET);
	if(*name=='/')
		pp = 0;
	else
	{
		for(;pp && pp!=last;pp=ppnext)
		{
			ppnext = pp->next;
			if(!pp->dev && !pp->ino)
				path_checkdup(shp,pp);
			if(pp->flags&PATH_SKIP)
				return(ppnext);
			if(!last || *pp->name!='/')
				break;
		}
		if(!pp)		/* this should not happen */
			pp = last;
	}
	if(pp && (pp->name[0]!='.' || pp->name[1]))
	{
		if(*pp->name!='/')
		{
			stakputs(path_pwd(shp,1));
			if(*stakptr(staktell()-1)!='/')
				stakputc('/');
		}
		stakwrite(pp->name,pp->len);
		if(pp->name[pp->len-1]!='/')
			stakputc('/');
	}
	stakputs(name);
	stakputc(0);
	while(pp && pp!=last && (pp=pp->next))
	{
		if(!(pp->flags&PATH_SKIP))
			return(pp);
	}
	return((Pathcomp_t*)0);
}

static Pathcomp_t* defpath_init(Shell_t *shp)
{
	Pathcomp_t *pp = (void*)path_addpath(shp,(Pathcomp_t*)0,(std_path),PATH_PATH);
	return(pp);
}

static void path_init(Shell_t *shp)
{
	const char *val;
	Pathcomp_t *pp;
	if(!std_path && !(std_path=astconf("PATH",NIL(char*),NIL(char*))))
		std_path = e_defpath;
	if(val=sh_scoped(shp,(PATHNOD))->nvalue.cp)
	{
		shp->pathlist = pp = (void*)path_addpath(shp,(Pathcomp_t*)shp->pathlist,val,PATH_PATH);
	}
	else
	{
		if(!(pp=(Pathcomp_t*)shp->defpathlist))
			pp = defpath_init(shp);
		shp->pathlist = (void*)path_dup(pp);
	}
	if(val=sh_scoped(shp,(FPATHNOD))->nvalue.cp)
	{
		pp = (void*)path_addpath(shp,(Pathcomp_t*)shp->pathlist,val,PATH_FPATH);
	}
}

/*
 * returns that pathlist to search
 */
Pathcomp_t *path_get(register Shell_t *shp,register const char *name)
{
	register Pathcomp_t *pp=0;
	if(*name && strchr(name,'/'))
		return(0);
	if(!sh_isstate(SH_DEFPATH))
	{
		if(!shp->pathlist)
			path_init(shp);
		pp = (Pathcomp_t*)shp->pathlist;
	}
	if(!pp && (!(sh_scoped(shp,PATHNOD)->nvalue.cp)) || sh_isstate(SH_DEFPATH))
	{
		if(!(pp=(Pathcomp_t*)shp->defpathlist))
			pp = defpath_init(shp);
	}
	return(pp);
}

/*
 * open file corresponding to name using path give by <pp>
 */
static int	path_opentype(Shell_t *shp,const char *name, register Pathcomp_t *pp, int fun)
{
	register int fd= -1;
	struct stat statb;
	Pathcomp_t *oldpp;
	if(!pp && !shp->pathlist)
		path_init(shp);
	if(!fun && strchr(name,'/'))
	{
		if(sh_isoption(SH_RESTRICTED))
			errormsg(SH_DICT,ERROR_exit(1),e_restricted,name);
	}
	do
	{
		pp = path_nextcomp(shp,oldpp=pp,name,0);
		while(oldpp && (oldpp->flags&PATH_SKIP))
			oldpp = oldpp->next;
		if(fun && (!oldpp || !(oldpp->flags&PATH_FPATH)))
			continue;
		if((fd = sh_open(path_relative(shp,stakptr(PATH_OFFSET)),O_RDONLY,0)) >= 0)
		{
			if(fstat(fd,&statb)<0 || S_ISDIR(statb.st_mode))
			{
				errno = EISDIR;
				sh_close(fd);
				fd = -1;
			}
		}
	}
	while( fd<0 && pp);
	if(fd>=0 && (fd = sh_iomovefd(fd)) > 0)
	{
		fcntl(fd,F_SETFD,FD_CLOEXEC);
		VALIDATE_FD(shp, fd);
		shp->fdstatus[fd] |= IOCLEX;
	}
	return(fd);
}

/*
 * open file corresponding to name using path give by <pp>
 */
int	path_open(Shell_t *shp,const char *name, register Pathcomp_t *pp)
{
	return(path_opentype(shp,name,pp,0));
}

/*
 * given a pathname return the base name
 */

char	*path_basename(register const char *name)
{
	register const char *start = name;
	while (*name)
		if ((*name++ == '/') && *name)	/* don't trim trailing / */
			start = name;
	return ((char*)start);
}

char *path_fullname(Shell_t *shp,const char *name)
{
	int len=strlen(name)+1,dirlen=0;
	char *path,*pwd;
	if(*name!='/')
	{
		pwd = path_pwd(shp,1);
		dirlen = strlen(pwd)+1;
	}
	path = (char*)malloc(len+dirlen);
	if(dirlen)
	{
		memcpy((void*)path,(void*)pwd,dirlen);
		path[dirlen-1] = '/';
	}
	memcpy((void*)&path[dirlen],(void*)name,len);
	pathcanon(path,0);
	return(path);
}

/*
 * load functions from file <fno>
 */
static void funload(Shell_t *shp,int fno, const char *name)
{
	char		*pname,*oldname=shp->st.filename, buff[IOBSIZE+1];
	Namval_t	*np;
	struct Ufunction *rp,*rpfirst;
	int		 savestates = sh_getstate(), oldload=shp->funload;
	pname = path_fullname(shp,stakptr(PATH_OFFSET));
	if(shp->fpathdict && (rp = dtmatch(shp->fpathdict,(void*)pname)))
	{
		Dt_t	*funtree = sh_subfuntree(1);
		while(1)
		{
			rpfirst = dtprev(shp->fpathdict,rp);
			if(!rpfirst || strcmp(pname,rpfirst->fname))
				break;
			rp = rpfirst;
		}
		do
		{
			if((np = dtsearch(funtree,rp->np)) && is_afunction(np))
			{
				if(np->nvalue.rp)
					np->nvalue.rp->fdict = 0;
				nv_delete(np,funtree,NV_NOFREE);
			}
			dtinsert(funtree,rp->np);
			rp->fdict = funtree;
		}
		while((rp=dtnext(shp->fpathdict,rp)) && strcmp(pname,rp->fname)==0);
		sh_close(fno);
		return;
	}
	sh_onstate(SH_NOLOG);
	sh_onstate(SH_NOALIAS);
	shp->readscript = (char*)name;
	shp->st.filename = pname;
	shp->funload = 1;
	error_info.line = 0;
	sh_eval(sfnew(NIL(Sfio_t*),buff,IOBSIZE,fno,SF_READ),SH_FUNEVAL);
	sh_close(fno);
	shp->readscript = 0;
#if SHOPT_NAMESPACE
	if(shp->namespace)
		np = sh_fsearch(shp,name,0);
	else
#endif /* SHOPT_NAMESPACE */
		np = nv_search(name,shp->fun_tree,0);
	if(!np || !np->nvalue.ip)
		pname = stakcopy(shp->st.filename);
	else
		pname = 0;
	free((void*)shp->st.filename);
	shp->funload = oldload;
	shp->st.filename = oldname;
	sh_setstate(savestates);
	if(pname)
		errormsg(SH_DICT,ERROR_exit(ERROR_NOEXEC),e_funload,name,pname);
}

/*
 * do a path search and track alias if requested
 * if flag is 0, or if name not found, then try autoloading function
 * if flag==2 or 3, returns 1 if name found on FPATH
 * if flag==3 no tracked alias will be set
 * returns 1, if function was autoloaded.
 * If oldpp is not NULL, it will contain a pointer to the path component
 *    where it was found.
 */

int	path_search(Shell_t *shp,register const char *name,Pathcomp_t **oldpp, int flag)
{
	register Namval_t *np;
	register int fno;
	Pathcomp_t *pp=0;
	if(name && strchr(name,'/'))
	{
		stakseek(PATH_OFFSET);
		stakputs(name);
		if(canexecute(shp,stakptr(PATH_OFFSET),0)<0)
		{
			*stakptr(PATH_OFFSET) = 0;
			return(0);
		}
		if(*name=='/')
			return(1);
		stakseek(PATH_OFFSET);
		stakputs(path_pwd(shp,1));
		stakputc('/');
		stakputs(name);
		stakputc(0);
		return(0);
	}
	if(sh_isstate(SH_DEFPATH))
	{
		if(!shp->defpathlist)
			defpath_init(shp);
	}
	else if(!shp->pathlist)
		path_init(shp);
	if(flag)
	{
		if(!(flag&1) && (np=nv_search(name,shp->track_tree,0)) && !nv_isattr(np,NV_NOALIAS) && (pp=(Pathcomp_t*)np->nvalue.cp))
		{
			stakseek(PATH_OFFSET);
			path_nextcomp(shp,pp,name,pp);
			if(oldpp)
				*oldpp = pp;
			stakputc(0);
			return(0);
		}
		pp = path_absolute(shp,name,oldpp?*oldpp:NIL(Pathcomp_t*));
		if(oldpp)
			*oldpp = pp;
		if(!pp && (np=nv_search(name,shp->fun_tree,0))&&np->nvalue.ip)
			return(1);
		if(!pp)
			*stakptr(PATH_OFFSET) = 0;
	}
	if(flag==0 || !pp || (pp->flags&PATH_FPATH))
	{
		if(!pp)
			pp=sh_isstate(SH_DEFPATH)?shp->defpathlist:shp->pathlist;
		if(pp && strmatch(name,e_alphanum)  && (fno=path_opentype(shp,name,pp,1))>=0)
		{
			if(flag==2)
			{
				sh_close(fno);
				return(1);
			}
			funload(shp,fno,name);
			return(1);
		}
		*stakptr(PATH_OFFSET) = 0;
		return(0);
	}
	else if(pp && !sh_isstate(SH_DEFPATH) && *name!='/' && flag<3)
	{
		if(np=nv_search(name,shp->track_tree,NV_ADD))
			path_alias(np,pp);
	}
	return(0);
}

/*
 * do a path search and find the full pathname of file name
 */
Pathcomp_t *path_absolute(Shell_t *shp,register const char *name, Pathcomp_t *pp)
{
	register int	f,isfun;
	int		noexec=0;
	Pathcomp_t	*oldpp;
	Namval_t	*np;
	char		*cp;
	char		*bp;
	shp->path_err = ENOENT;
	if(!pp && !(pp=path_get(shp,"")))
		return(0);
	shp->path_err = 0;
	while(1)
	{
		sh_sigcheck(shp);
		shp->bltin_dir = 0;
		while(oldpp=pp)
		{
			pp = path_nextcomp(shp,pp,name,0);
			if(!(oldpp->flags&PATH_SKIP))
				break;
		}
		if(!oldpp)
		{
			shp->path_err = ENOENT;
			return(0);
		}
		isfun = (oldpp->flags&PATH_FPATH);
		if(!isfun && !sh_isoption(SH_RESTRICTED))
		{
#if SHOPT_DYNAMIC
			Shbltin_f addr;
			int n;
#endif
			if(*stakptr(PATH_OFFSET)=='/' && nv_search(stakptr(PATH_OFFSET),shp->bltin_tree,0))
				return(oldpp);
#if SHOPT_DYNAMIC
			n = staktell();
			stakputs("b_");
			stakputs(name);
			stakputc(0);
			if((addr = sh_getlib(shp, stakptr(n), oldpp)) &&
			   (np = sh_addbuiltin(stakptr(PATH_OFFSET),addr,NiL)) &&
			   nv_isattr(np,NV_BLTINOPT))
			{
				shp->bltin_dir = 0;
				return(oldpp);
			}
			stakseek(n);
			while(bp = oldpp->blib)
			{
				char *fp;
				void *dll;
				int m;
				if(fp = strchr(bp, ':'))
				{
					*fp++ = 0;
					oldpp->blib = fp;
					fp = 0;
				}
				else
				{
					fp = oldpp->bbuf;
					oldpp->blib = oldpp->bbuf = 0;
				}
				n = staktell();
				stakputs("b_");
				stakputs(name);
				stakputc(0);
				m = staktell();
				shp->bltin_dir = oldpp->name;
				if(*bp!='/')
				{
					stakputs(oldpp->name);
					stakputc('/');
				}
				stakputs(bp);
				stakputc(0);
				if(cp = strrchr(stakptr(m),'/'))
					cp++;
				else
					cp = stakptr(m);
				if(!strcmp(cp,LIBCMD) &&
				   (addr=(Shbltin_f)dlllook((void*)0,stakptr(n))) &&
				   (np = sh_addbuiltin(stakptr(PATH_OFFSET),addr,NiL)) &&
				   nv_isattr(np,NV_BLTINOPT))
				{
				found:
					if(fp)
						free(fp);
					shp->bltin_dir = 0;
					return(oldpp);
				}
#ifdef SH_PLUGIN_VERSION
				if (dll = dllplugin(SH_ID, stakptr(m), NiL, SH_PLUGIN_VERSION, NiL, RTLD_LAZY, NiL, 0))
					sh_addlib(shp,dll,stakptr(m),oldpp);
#else
#if (_AST_VERSION>=20040404)
				if (dll = dllplug(SH_ID, stakptr(m), NiL, RTLD_LAZY, NiL, 0))
#else
				if (dll = dllfind(stakptr(m), NiL, RTLD_LAZY, NiL, 0))
#endif
				{
					/*
					 * this detects the 2007-05-11 builtin context change and also
					 * the 2008-03-30 opt_info.num change that hit libcmd::b_head
					 */

					if (libcmd && !dlllook(dll, "b_pids"))
					{
						dlclose(dll);
						dll = 0;
					}
					else
						sh_addlib(shp,dll,stakptr(m),oldpp);
				}
#endif
				if(dll &&
				   (addr=(Shbltin_f)dlllook(dll,stakptr(n))) &&
				   (!(np = sh_addbuiltin(stakptr(PATH_OFFSET),NiL,NiL)) || np->nvalue.bfp!=(Nambfp_f)addr) &&
				   (np = sh_addbuiltin(stakptr(PATH_OFFSET),addr,NiL)))
				{
					np->nvenv = dll;
					goto found;
				}
				if(*stakptr(PATH_OFFSET)=='/' && nv_search(stakptr(PATH_OFFSET),shp->bltin_tree,0))
					goto found;
				if(fp)
					free(fp);
				stakseek(n);
			}
#endif /* SHOPT_DYNAMIC */
		}
		shp->bltin_dir = 0;
		sh_stats(STAT_PATHS);
		f = canexecute(shp,stakptr(PATH_OFFSET),isfun);
		if(isfun && f>=0 && (cp = strrchr(name,'.')))
		{
			*cp = 0;
			if(nv_open(name,sh_subfuntree(1),NV_NOARRAY|NV_IDENT|NV_NOSCOPE))
				f = -1;
			*cp = '.';
		}
		if(isfun && f>=0)
		{
			nv_onattr(nv_open(name,sh_subfuntree(1),NV_NOARRAY|NV_IDENT|NV_NOSCOPE),NV_LTOU|NV_FUNCTION);
			funload(shp,f,name);
			close(f);
			f = -1;
			return(0);
		}
		else if(f>=0 && (oldpp->flags & PATH_STD_DIR))
		{
			int n = staktell();
			stakputs("/bin/");
			stakputs(name);
			stakputc(0);
			np = nv_search(stakptr(n),shp->bltin_tree,0);
			stakseek(n);
			if(np)
			{
				n = np->nvflag;
				np = sh_addbuiltin(stakptr(PATH_OFFSET),(Shbltin_f)np->nvalue.bfp,nv_context(np));
				np->nvflag = n;
			}
		}
		if(!pp || f>=0)
			break;
		if(errno!=ENOENT)
			noexec = errno;
	}
	if(f<0)
	{
		shp->path_err = (noexec?noexec:ENOENT);
		return(0);
	}
	stakputc(0);
	return(oldpp);
}

/*
 * returns 0 if path can execute
 * sets exec_err if file is found but can't be executable
 */
#undef S_IXALL
#ifdef S_IXUSR
#   define S_IXALL	(S_IXUSR|S_IXGRP|S_IXOTH)
#else
#   ifdef S_IEXEC
#	define S_IXALL	(S_IEXEC|(S_IEXEC>>3)|(S_IEXEC>>6))
#   else
#	define S_IXALL	0111
#   endif /*S_EXEC */
#endif /* S_IXUSR */

static int canexecute(Shell_t *shp,register char *path, int isfun)
{
	struct stat statb;
	register int fd=0;
	path = path_relative(shp,path);
	if(isfun)
	{
		if((fd=open(path,O_RDONLY,0))<0 || fstat(fd,&statb)<0)
			goto err;
	}
	else if(stat(path,&statb) < 0)
	{
#if _WINIX
		/* check for .exe or .bat suffix */
		char *cp;
		if(errno==ENOENT && (!(cp=strrchr(path,'.')) || strlen(cp)>4 || strchr(cp,'/')))
		{
			int offset = staktell()-1;
			stakseek(offset);
			stakputs(".bat");
			path = stakptr(PATH_OFFSET);
			if(stat(path,&statb) < 0)
			{
				if(errno!=ENOENT)
					goto err;
				memcpy(stakptr(offset),".sh",4);
				if(stat(path,&statb) < 0)
					goto err;
			}
		}
		else
#endif /* _WINIX */
		goto err;
	}
	errno = EPERM;
	if(S_ISDIR(statb.st_mode))
		errno = EISDIR;
	else if((statb.st_mode&S_IXALL)==S_IXALL || sh_access(path,X_OK)>=0)
		return(fd);
	if(isfun && fd>=0)
		sh_close(fd);
err:
	return(-1);
}

/*
 * Return path relative to present working directory
 */

char *path_relative(Shell_t *shp,register const char* file)
{
	register const char *pwd;
	register const char *fp = file;
	/* can't relpath when shp->pwd not set */
	if(!(pwd=shp->pwd))
		return((char*)fp);
	while(*pwd==*fp)
	{
		if(*pwd++==0)
			return((char*)e_dot);
		fp++;
	}
	if(*pwd==0 && *fp == '/')
	{
		while(*++fp=='/');
		if(*fp)
			return((char*)fp);
		return((char*)e_dot);
	}
	return((char*)file);
}

void	path_exec(Shell_t *shp,register const char *arg0,register char *argv[],struct argnod *local)
{
	char **envp;
	const char *opath;
	Pathcomp_t *libpath, *pp=0;
	int slash=0;
	nv_setlist(local,NV_EXPORT|NV_IDENT|NV_ASSIGN,0);
	envp = sh_envgen();
	if(strchr(arg0,'/'))
	{
		slash=1;
		/* name containing / not allowed for restricted shell */
		if(sh_isoption(SH_RESTRICTED))
			errormsg(SH_DICT,ERROR_exit(1),e_restricted,arg0);
	}
	else
		pp=path_get(shp,arg0);
	shp->path_err= ENOENT;
	sfsync(NIL(Sfio_t*));
	timerdel(NIL(void*));
	/* find first path that has a library component */
	while(pp && (pp->flags&PATH_SKIP))
		pp = pp->next;
	if(pp || slash) do
	{
		sh_sigcheck(shp);
		if(libpath=pp)
		{
			pp = path_nextcomp(shp,pp,arg0,0);
			opath = stakfreeze(1)+PATH_OFFSET;
		}
		else
			opath = arg0;
		path_spawn(shp,opath,argv,envp,libpath,0);
		while(pp && (pp->flags&PATH_FPATH))
			pp = path_nextcomp(shp,pp,arg0,0);
	}
	while(pp);
	/* force an exit */
	((struct checkpt*)shp->jmplist)->mode = SH_JMPEXIT;
	if((errno=shp->path_err)==ENOENT)
		errormsg(SH_DICT,ERROR_exit(ERROR_NOENT),e_found,arg0);
	else
		errormsg(SH_DICT,ERROR_system(ERROR_NOEXEC),e_exec,arg0);
}

pid_t path_spawn(Shell_t *shp,const char *opath,register char **argv, char **envp, Pathcomp_t *libpath, int spawn)
{
	register char *path;
	char **xp=0, *xval, *libenv = (libpath?libpath->lib:0); 
	Namval_t*	np;
	char		*s, *v;
	int		r, n, pidsize;
	pid_t		pid= -1;
	/* leave room for inserting _= pathname in environment */
	envp--;
#if _lib_readlink
	/* save original pathname */
	stakseek(PATH_OFFSET);
	pidsize = sfprintf(stkstd,"*%d*",spawn?getpid():getppid());
	stakputs(opath);
	opath = stakfreeze(1)+PATH_OFFSET+pidsize;
	np=nv_search(argv[0],shp->track_tree,0);
	while(libpath && !libpath->lib)
		libpath=libpath->next;
	if(libpath && (!np || nv_size(np)>0))
	{
		/* check for symlink and use symlink name */
		char buff[PATH_MAX+1];
		char save[PATH_MAX+1];
		stakseek(PATH_OFFSET);
		stakputs(opath);
		path = stakptr(PATH_OFFSET);
		while((n=readlink(path,buff,PATH_MAX))>0)
		{
			buff[n] = 0;
			n = PATH_OFFSET;
			r = 0;
			if((v=strrchr(path,'/')) && *buff!='/')
			{
				if(buff[0]=='.' && buff[1]=='.' && (r = strlen(path) + 1) <= PATH_MAX)
					memcpy(save, path, r);
				else
					r = 0;
				n += (v+1-path);
			}
			stakseek(n);
			stakputs(buff);
			stakputc(0);
			path = stakptr(PATH_OFFSET);
			if(v && buff[0]=='.' && buff[1]=='.')
			{
				pathcanon(path, 0);
				if(r && access(path,X_OK))
				{
					memcpy(path, save, r);
					break;
				}
			}
			if(libenv = path_lib(shp,libpath,path))
				break;
		}
		stakseek(0);
	}
#endif
	if(libenv && (v = strchr(libenv,'=')))
	{
		n = v - libenv;
		*v = 0;
		np = nv_open(libenv,shp->var_tree,0);
		*v = '=';
		s = nv_getval(np);
		stakputs(libenv);
		if(s)
		{
			stakputc(':');
			stakputs(s);
		}
		v = stakfreeze(1);
		r = 1;
		xp = envp + 1;
		while (s = *xp++)
		{
			if (strneq(s, v, n) && s[n] == '=')
			{
				xval = *--xp;
				*xp = v;
				r = 0;
				break;
			}
		}
		if (r)
		{
			*envp-- = v;
			xp = 0;
		}
	}
	if(!opath)
		opath = stakptr(PATH_OFFSET);
	envp[0] =  (char*)opath-(PATH_OFFSET+pidsize);
	envp[0][0] =  '_';
	envp[0][1] =  '=';
	sfsync(sfstderr);
	sh_sigcheck(shp);
	path = path_relative(shp,opath);
#ifdef SHELLMAGIC
	if(*path!='/' && path!=opath)
	{
		/*
		 * The following code because execv(foo,) and execv(./foo,)
		 * may not yield the same results
		 */
		char *sp = (char*)malloc(strlen(path)+3);
		sp[0] = '.';
		sp[1] = '/';
		strcpy(sp+2,path);
		path = sp;
	}
#endif /* SHELLMAGIC */
	if(spawn && !sh_isoption(SH_PFSH))
		pid = _spawnveg(shp,opath, &argv[0],envp, spawn>>1);
	else
		pid = path_pfexecve(shp,opath, &argv[0] ,envp,spawn);
	if(xp)
		*xp = xval;
#ifdef SHELLMAGIC
	if(*path=='.' && path!=opath)
	{
		free(path);
		path = path_relative(shp,opath);
	}
#endif /* SHELLMAGIC */
	if(pid>0)
		return(pid);
retry:
	switch(shp->path_err = errno)
	{
#ifdef apollo
	    /* 
  	     * On apollo's execve will fail with eacces when
	     * file has execute but not read permissions. So,
	     * for now we will pretend that EACCES and ENOEXEC
 	     * mean the same thing.
 	     */
	    case EACCES:
#endif /* apollo */
	    case ENOEXEC:
#if SHOPT_SUID_EXEC
	    case EPERM:
		/* some systems return EPERM if setuid bit is on */
#endif
		errno = ENOEXEC;
		if(spawn)
		{
#ifdef _lib_fork
			if(shp->subshell)
				return(-1);
			do
			{
				if((pid=fork())>0)
					return(pid);
			}
			while(_sh_fork(shp,pid,0,(int*)0) < 0);
			((struct checkpt*)shp->jmplist)->mode = SH_JMPEXIT;
#else
			return(-1);
#endif
		}
		exscript(shp,path,argv,envp);
#ifndef apollo
		/* FALLTHROUGH */
	    case EACCES:
	    {
		struct stat statb;
		if(stat(path,&statb)>=0)
		{
			if(S_ISDIR(statb.st_mode))
				errno = EISDIR;
#ifdef S_ISSOCK
			if(S_ISSOCK(statb.st_mode))
				exscript(shp,path,argv,envp);
#endif
		}
	    }
#endif /* !apollo */
#ifdef ENAMETOOLONG
		/* FALLTHROUGH */
	    case ENAMETOOLONG:
#endif /* ENAMETOOLONG */
#if !SHOPT_SUID_EXEC
	    case EPERM:
#endif
		shp->path_err = errno;
		return(-1);
	    case ENOTDIR:
	    case ENOENT:
	    case EINTR:
#ifdef EMLINK
	    case EMLINK:
#endif /* EMLINK */
		return(-1);
	    case E2BIG:
		if(shp->xargmin)
		{
			pid = path_xargs(shp,opath, &argv[0] ,envp,spawn);
			if(pid<0)
				goto retry;
			return(pid);
		}
		/* FALLTHROUGH */
	    default:
		errormsg(SH_DICT,ERROR_system(ERROR_NOEXEC),e_exec,path);
	}
	return 0;
}

/*
 * File is executable but not machine code.
 * Assume file is a Shell script and execute it.
 */

static void exscript(Shell_t *shp,register char *path,register char *argv[],char **envp)
{
	register Sfio_t *sp;
	path = path_relative(shp,path);
	shp->comdiv=0;
	shp->bckpid = 0;
	shp->coshell = 0;
	shp->st.ioset=0;
	/* clean up any cooperating processes */
	if(shp->cpipe[0]>0)
		sh_pclose(shp->cpipe);
	if(shp->cpid && shp->outpipe)
		sh_close(*shp->outpipe);
	shp->cpid = 0;
	if(sp=fcfile())
		while(sfstack(sp,SF_POPSTACK));
	job_clear();
	VALIDATE_FD(shp, shp->infd);
	if(shp->infd>0 && (shp->fdstatus[shp->infd]&IOCLEX))
		sh_close(shp->infd);
	sh_setstate(sh_state(SH_FORKED));
	sfsync(sfstderr);
#if SHOPT_SUID_EXEC && !SHOPT_PFSH
	/* check if file cannot open for read or script is setuid/setgid  */
	{
		static char name[] = "/tmp/euidXXXXXXXXXX";
		register int n;
		register uid_t euserid;
		char *savet=0;
		struct stat statb;
		if((n=sh_open(path,O_RDONLY,0)) >= 0)
		{
			/* move <n> if n=0,1,2 */
			n = sh_iomovefd(n);
			if(fstat(n,&statb)>=0 && !(statb.st_mode&(S_ISUID|S_ISGID)))
				goto openok;
			sh_close(n);
		}
		if((euserid=geteuid()) != shp->gd->userid)
		{
			strncpy(name+9,fmtbase((long)getpid(),10,0),sizeof(name)-10);
			/* create a suid open file with owner equal effective uid */
			if((n=open(name,O_CREAT|O_TRUNC|O_WRONLY,S_ISUID|S_IXUSR)) < 0)
				goto fail;
			unlink(name);
			/* make sure that file has right owner */
			if(fstat(n,&statb)<0 || statb.st_uid != euserid)
				goto fail;
			if(n!=10)
			{
				sh_close(10);
				fcntl(n, F_DUPFD, 10);
				sh_close(n);
				n=10;
			}
		}
		savet = *--argv;
		*argv = path;
		path_pfexecve(shp,e_suidexec,argv,envp,0);
	fail:
		/*
		 *  The following code is just for compatibility
		 */
		if((n=open(path,O_RDONLY,0)) < 0)
			errormsg(SH_DICT,ERROR_system(ERROR_NOEXEC),e_exec,path);
		if(savet)
			*argv++ = savet;
	openok:
		shp->infd = n;
	}
#else
	if((shp->infd = sh_open(path,O_RDONLY,0)) < 0)
		errormsg(SH_DICT,ERROR_system(ERROR_NOEXEC),e_exec,path);
#endif
	shp->infd = sh_iomovefd(shp->infd);
#if SHOPT_ACCT
	sh_accbegin(path) ;  /* reset accounting */
#endif	/* SHOPT_ACCT */
	shp->arglist = sh_argcreate(argv);
	shp->lastarg = strdup(path);
	/* save name of calling command */
	shp->readscript = error_info.id;
	/* close history file if name has changed */
	if(shp->gd->hist_ptr && (path=nv_getval(HISTFILE)) && strcmp(path,shp->gd->hist_ptr->histname))
	{
		hist_close(shp->gd->hist_ptr);
		(HISTCUR)->nvalue.lp = 0;
	}
	sh_offstate(SH_FORKED);
	if(shp->sigflag[SIGCHLD]==SH_SIGOFF)
		shp->sigflag[SIGCHLD] = SH_SIGFAULT;
	siglongjmp(*shp->jmplist,SH_JMPSCRIPT);
}

#if SHOPT_ACCT
#   include <sys/acct.h>
#   include "FEATURE/time"

    static struct acct sabuf;
    static struct tms buffer;
    static clock_t	before;
    static char *SHACCT; /* set to value of SHACCT environment variable */
    static shaccton;	/* non-zero causes accounting record to be written */
    static int compress(time_t);
    /*
     *	initialize accounting, i.e., see if SHACCT variable set
     */
    void sh_accinit(void)
    {
	SHACCT = getenv("SHACCT");
    }
    /*
    * suspend accounting until turned on by sh_accbegin()
    */
    void sh_accsusp(void)
    {
	shaccton=0;
#ifdef AEXPAND
	sabuf.ac_flag |= AEXPND;
#endif /* AEXPAND */
    }

    /*
     * begin an accounting record by recording start time
     */
    void sh_accbegin(const char *cmdname)
    {
	if(SHACCT)
	{
		sabuf.ac_btime = time(NIL(time_t *));
		before = times(&buffer);
		sabuf.ac_uid = getuid();
		sabuf.ac_gid = getgid();
		strncpy(sabuf.ac_comm, (char*)path_basename(cmdname),
			sizeof(sabuf.ac_comm));
		shaccton = 1;
	}
    }
    /*
     * terminate an accounting record and append to accounting file
     */
    void	sh_accend(void)
    {
	int	fd;
	clock_t	after;

	if(shaccton)
	{
		after = times(&buffer);
		sabuf.ac_utime = compress(buffer.tms_utime + buffer.tms_cutime);
		sabuf.ac_stime = compress(buffer.tms_stime + buffer.tms_cstime);
		sabuf.ac_etime = compress( (time_t)(after-before));
		fd = open( SHACCT , O_WRONLY | O_APPEND | O_CREAT,RW_ALL);
		write(fd, (const char*)&sabuf, sizeof( sabuf ));
		close( fd);
	}
    }
 
    /*
     * Produce a pseudo-floating point representation
     * with 3 bits base-8 exponent, 13 bits fraction.
     */
    static int compress(register time_t t)
    {
	register int exp = 0, rund = 0;

	while (t >= 8192)
	{
		exp++;
		rund = t&04;
		t >>= 3;
	}
	if (rund)
	{
		t++;
		if (t >= 8192)
		{
			t >>= 3;
			exp++;
		}
	}
	return((exp<<13) + t);
    }
#endif	/* SHOPT_ACCT */



/*
 * add a pathcomponent to the path search list and eliminate duplicates
 * and non-existing absolute paths.
 */
static Pathcomp_t *path_addcomp(Shell_t *shp,Pathcomp_t *first, Pathcomp_t *old,const char *name, int flag)
{
	register Pathcomp_t *pp, *oldpp;
	int len, offset=staktell();
	if(!(flag&PATH_BFPATH))
	{
		register const char *cp = name;
		while(*cp && *cp!=':')
			stakputc(*cp++);
		len = staktell()-offset;
		stakputc(0);
		stakseek(offset);
		name = (const char*)stakptr(offset);
	}
	else
		len = strlen(name);
	for(pp=first; pp; pp=pp->next)
	{
		if(len == pp->len && memcmp(name,pp->name,len)==0)
		{
			pp->flags |= flag;
			return(first);
		}
	}
	for(pp=first, oldpp=0; pp; oldpp=pp, pp=pp->next);
	pp = newof((Pathcomp_t*)0,Pathcomp_t,1,len+1);
	pp->shp = shp;
	pp->refcount = 1;
	memcpy((char*)(pp+1),name,len+1);
	pp->name = (char*)(pp+1);
	pp->len = len;
	if(oldpp)
		oldpp->next = pp;
	else
		first = pp;
	pp->flags = flag;
	if(strcmp(name,SH_CMDLIB_DIR)==0)
	{
		pp->dev = 1;
		pp->flags |= PATH_BUILTIN_LIB;
		pp->blib = pp->bbuf = malloc(sizeof(LIBCMD));
		strcpy(pp->blib,LIBCMD);
		return(first);
	}
	if((old||shp->pathinit) &&  ((flag&(PATH_PATH|PATH_SKIP))==PATH_PATH))
		path_chkpaths(shp,first,old,pp,offset);
	return(first);
}

/*
 * This function checks for the .paths file in directory in <pp>
 * it assumes that the directory is on the stack at <offset> 
 */
static int path_chkpaths(Shell_t *shp,Pathcomp_t *first, Pathcomp_t* old,Pathcomp_t *pp, int offset)
{
	struct stat statb;
	int k,m,n,fd;
	char *sp,*cp,*ep;
	stakseek(offset+pp->len);
	if(pp->len==1 && *stakptr(offset)=='/')
		stakseek(offset);
	stakputs("/.paths");
	if((fd=open(stakptr(offset),O_RDONLY))>=0)
	{
		fstat(fd,&statb);
		n = statb.st_size;
		stakseek(offset+pp->len+n+2);
		sp = stakptr(offset+pp->len);
		*sp++ = '/';
		n=read(fd,cp=sp,n);
		sp[n] = 0;
		close(fd);
		for(ep=0; n--; cp++)
		{
			if(*cp=='=')
			{
				ep = cp+1;
				continue;
			}
			else if(*cp!='\r' &&  *cp!='\n')
				continue;
			if(*sp=='#' || sp==cp)
			{
				sp = cp+1;
				continue;
			}
			*cp = 0;
			m = ep ? (ep-sp) : 0;
			if(m==0 || m==6 && memcmp((void*)sp,(void*)"FPATH=",m)==0)
			{
				if(first)
				{
					char *ptr = stakptr(offset+pp->len+1);
					if(ep)
						strcpy(ptr,ep);
					path_addcomp(shp,first,old,stakptr(offset),PATH_FPATH|PATH_BFPATH);
				}
			}
			else if(m==11 && memcmp((void*)sp,(void*)"PLUGIN_LIB=",m)==0)
			{
				if(pp->bbuf)
					free(pp->bbuf);
				pp->blib = pp->bbuf = strdup(ep);
			}
			else if(m)
			{
				pp->lib = (char*)malloc(cp-sp+pp->len+2);
				memcpy((void*)pp->lib,(void*)sp,m);
				memcpy((void*)&pp->lib[m],stakptr(offset),pp->len);
				pp->lib[k=m+pp->len] = '/';
				strcpy((void*)&pp->lib[k+1],ep);
				pathcanon(&pp->lib[m],0);
				if(!first)
				{
					stakseek(0);
					stakputs(pp->lib);
					free((void*)pp->lib);
					return(1);
				}
			}
			sp = cp+1;
			ep = 0;
		}
	}
	return(0);
}


Pathcomp_t *path_addpath(Shell_t *shp,Pathcomp_t *first, register const char *path,int type)
{
	register const char *cp;
	Pathcomp_t *old=0;
	int offset = staktell();
	char *savptr;
	
	if(!path && type!=PATH_PATH)
		return(first);
	if(type!=PATH_FPATH)
	{
		old = first;
		first = 0;
	}
	if(offset)
		savptr = stakfreeze(0);
	if(path) while(*(cp=path))
	{
		if(*cp==':')
		{
			if(type!=PATH_FPATH)
				first = path_addcomp(shp,first,old,".",type);
			while(*++path == ':');
		}
		else
		{
			int c;
			while(*path && *path!=':')
				path++;
			c = *path++;
			first = path_addcomp(shp,first,old,cp,type);
			if(c==0)
				break;
			if(*path==0)
				path--;
		}
	}
	if(old)
	{
		if(!first && !path)
		{
			Pathcomp_t *pp = (Pathcomp_t*)shp->defpathlist;
			if(!pp)
				pp = defpath_init(shp);
			first = path_dup(pp);
		}
		if(cp=(sh_scoped(shp,FPATHNOD))->nvalue.cp)
			first = (void*)path_addpath(shp,(Pathcomp_t*)first,cp,PATH_FPATH);
		path_delete(old);
	}
	if(offset)
		stakset(savptr,offset);
	else
		stakseek(0);
	return(first);
}

/*
 * duplicate the path give by <first> by incremented reference counts
 */
Pathcomp_t *path_dup(Pathcomp_t *first)
{
	register Pathcomp_t *pp=first;
	while(pp)
	{
		pp->refcount++;
		pp = pp->next;
	}
	return(first);
}

/*
 * called whenever the directory is changed
 */
void path_newdir(Shell_t *shp,Pathcomp_t *first)
{
	register Pathcomp_t *pp=first, *next, *pq;
	struct stat statb;
	for(pp=first; pp; pp=pp->next)
	{
		pp->flags &= ~PATH_SKIP;
		if(*pp->name=='/')
			continue;
		/* delete .paths component */
		if((next=pp->next) && (next->flags&PATH_BFPATH))
		{
			pp->next = next->next;
			if(--next->refcount<=0)
				free((void*)next);
		}
		if(stat(pp->name,&statb)<0 || !S_ISDIR(statb.st_mode))
		{
			pp->dev = 0;
			pp->ino = 0;
			continue;
		}
		pp->dev = statb.st_dev;
		pp->ino = statb.st_ino;
		pp->mtime = statb.st_mtime;
		for(pq=first;pq!=pp;pq=pq->next)
		{
			if(pp->ino==pq->ino && pp->dev==pq->dev)
				pp->flags |= PATH_SKIP;
		}
		for(pq=pp;pq=pq->next;)
		{
			if(pp->ino==pq->ino && pp->dev==pq->dev)
				pq->flags |= PATH_SKIP;
		}
		if((pp->flags&(PATH_PATH|PATH_SKIP))==PATH_PATH)
		{
			/* try to insert .paths component */
			int offset = staktell();
			stakputs(pp->name);
			stakseek(offset);
			next = pp->next;
			pp->next = 0;
			path_chkpaths(shp,first,(Pathcomp_t*)0,pp,offset);
			if(pp->next)
				pp = pp->next;
			pp->next = next;
		}
	}
#if 0
	path_dump(first);
#endif
}

Pathcomp_t *path_unsetfpath(Shell_t *shp)
{
	Pathcomp_t	*first = (Pathcomp_t*)shp->pathlist;
	register Pathcomp_t *pp=first, *old=0;
	if(shp->fpathdict)
	{
		struct Ufunction  *rp, *rpnext;
		for(rp=(struct Ufunction*)dtfirst(shp->fpathdict);rp;rp=rpnext)
		{
			rpnext = (struct Ufunction*)dtnext(shp->fpathdict,rp);
			if(rp->fdict)
				nv_delete(rp->np,rp->fdict,NV_NOFREE);
			rp->fdict = 0;
		}
	}
	while(pp)
	{
		if((pp->flags&PATH_FPATH) && !(pp->flags&PATH_BFPATH))
		{
			if(pp->flags&PATH_PATH)
				pp->flags &= ~PATH_FPATH;
			else
			{
				Pathcomp_t *ppsave=pp;
				if(old)
					old->next = pp->next;
				else
					first = pp->next;
				pp = pp->next;
				if(--ppsave->refcount<=0)
				{
					if(ppsave->lib)
						free((void*)ppsave->lib);
					free((void*)ppsave);
				}
				continue;
			}
			
		}
		old = pp;
		pp = pp->next;
	}
	return(first);
}

Pathcomp_t *path_dirfind(Pathcomp_t *first,const char *name,int c)
{
	register Pathcomp_t *pp=first;
	while(pp)
	{
		if(memcmp(name,pp->name,pp->len)==0 && name[pp->len]==c) 
			return(pp);
		pp = pp->next;
	}
	return(0);
}

/*
 * get discipline for tracked alias
 */
static char *talias_get(Namval_t *np, Namfun_t *nvp)
{
	Pathcomp_t *pp = (Pathcomp_t*)np->nvalue.cp;
	char *ptr;
	if(!pp)
		return(NULL);
	pp->shp->last_table = 0;
	path_nextcomp(pp->shp,pp,nv_name(np),pp);
	ptr = stakfreeze(0);
	return(ptr+PATH_OFFSET);
}

static void talias_put(register Namval_t* np,const char *val,int flags,Namfun_t *fp)
{
	if(!val && np->nvalue.cp)
	{
		Pathcomp_t *pp = (Pathcomp_t*)np->nvalue.cp;
		if(--pp->refcount<=0)
			free((void*)pp);
	}
	nv_putv(np,val,flags,fp);
}

static const Namdisc_t talias_disc   = { 0, talias_put, talias_get   };
static Namfun_t  talias_init = { &talias_disc, 1 };

/*
 *  set tracked alias node <np> to value <pp>
 */
void path_alias(register Namval_t *np,register Pathcomp_t *pp)
{
	if(pp)
	{
		struct stat statb;
		char *sp;
		nv_offattr(np,NV_NOPRINT);
		nv_stack(np,&talias_init);
		np->nvalue.cp = (char*)pp;
		pp->refcount++;
		nv_setattr(np,NV_TAGGED|NV_NOFREE);
		path_nextcomp(pp->shp,pp,nv_name(np),pp);
		sp = stakptr(PATH_OFFSET);
		if(sp && lstat(sp,&statb)>=0 && S_ISLNK(statb.st_mode))
			nv_setsize(np,statb.st_size+1);
		else
			nv_setsize(np,0);
	}
	else
		_nv_unset(np,0);
}

