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
 *
 * Shell initialization
 *
 *   David Korn
 *   AT&T Labs
 *
 */

#include        "defs.h"
#include        <stak.h>
#include        <ccode.h>
#include        <pwd.h>
#include        <tmx.h>
#include        <regex.h>
#include        "variables.h"
#include        "path.h"
#include        "fault.h"
#include        "name.h"
#include	"edit.h"
#include	"jobs.h"
#include	"io.h"
#include	"shlex.h"
#include	"builtins.h"
#include	"FEATURE/time"
#include	"FEATURE/dynamic"
#include	"FEATURE/externs"
#include	"lexstates.h"
#include	"version.h"

#if _hdr_wctype
#include	<ast_wchar.h>
#include	<wctype.h>
#endif
#if !_typ_wctrans_t
#undef	wctrans_t
#define wctrans_t	sh_wctrans_t
typedef long wctrans_t;
#endif
#if !_lib_wctrans
#undef	wctrans
#define wctrans		sh_wctrans
static wctrans_t wctrans(const char *name)
{
	if(strcmp(name,e_tolower)==0)
		return(1);
	else if(strcmp(name,e_toupper)==0)
		return(2);
	return(0);
}
#endif
#if !_lib_towctrans
#undef	towctrans
#define towctrans	sh_towctrans
static int towctrans(int c, wctrans_t t)
{
	if(t==1 && isupper(c))
		c = tolower(c);
	else if(t==2 && islower(c))
		c = toupper(c);
	return(c);
}
#endif

char e_version[]	= "\n@(#)$Id: Version "
#if SHOPT_AUDIT
#define ATTRS		1
			"A"
#endif
#if SHOPT_BASH
#define ATTRS		1
			"B"
#endif
#if SHOPT_COSHELL
#define ATTRS		1
			"J"
#else
#if SHOPT_BGX
#define ATTRS		1
			"j"
#endif
#endif
#if SHOPT_ACCT
#define ATTRS		1
			"L"
#endif
#if SHOPT_MULTIBYTE
#define ATTRS		1
			"M"
#endif
#if SHOPT_PFSH && _hdr_exec_attr
#define ATTRS		1
			"P"
#endif
#if SHOPT_REGRESS
#define ATTRS		1
			"R"
#endif
#if ATTRS
			" "
#endif
			SH_RELEASE " $\0\n";

#if SHOPT_BASH
    extern void bash_init(Shell_t*,int);
#endif

#define RANDMASK	0x7fff

#ifndef ARG_MAX
#   define ARG_MAX	(1*1024*1024)
#endif
#ifndef CHILD_MAX
#   define CHILD_MAX	(1*1024)
#endif
#ifndef CLK_TCK
#   define CLK_TCK	60
#endif /* CLK_TCK */

#ifndef environ
    extern char	**environ;
#endif

#undef	getconf
#define getconf(x)	strtol(astconf(x,NiL,NiL),NiL,0)

struct seconds
{
	Namfun_t	hdr;
	Shell_t		*sh;
};

struct rand
{
	Namfun_t	hdr;
	Shell_t		*sh;
	int32_t		rand_last;
};

struct ifs
{
	Namfun_t	hdr;
	Namval_t	*ifsnp;
};

struct match
{
	Namfun_t	hdr;
	const char	*v;
	char		*val;
	char		*rval[2];
	regoff_t	*match;
	char		node[NV_MINSZ+sizeof(char*)];
	regoff_t	first;
	int		vsize;
	int		nmatch;
	int		index;
	int		lastsub[2];
};

typedef struct _init_
{
	Shell_t		*sh;
#if SHOPT_FS_3D
	Namfun_t	VPATH_init;
#endif /* SHOPT_FS_3D */
	struct ifs	IFS_init;
	Namfun_t	PATH_init;
	Namfun_t	FPATH_init;
	Namfun_t	CDPATH_init;
	Namfun_t	SHELL_init;
	Namfun_t	ENV_init;
	Namfun_t	VISUAL_init;
	Namfun_t	EDITOR_init;
	Namfun_t	HISTFILE_init;
	Namfun_t	HISTSIZE_init;
	Namfun_t	OPTINDEX_init;
	struct seconds	SECONDS_init;
	struct rand	RAND_init;
	Namfun_t	LINENO_init;
	Namfun_t	L_ARG_init;
	Namfun_t	SH_VERSION_init;
	struct match	SH_MATCH_init;
	Namfun_t	SH_MATH_init;
#if SHOPT_COSHELL
	Namfun_t	SH_JOBPOOL_init;
#endif /* SHOPT_COSHELL */
#ifdef _hdr_locale
	Namfun_t	LC_TYPE_init;
	Namfun_t	LC_NUM_init;
	Namfun_t	LC_COLL_init;
	Namfun_t	LC_MSG_init;
	Namfun_t	LC_ALL_init;
	Namfun_t	LANG_init;
#endif /* _hdr_locale */
} Init_t;

static Init_t		*ip;
static int		lctype;
static int		nbltins;
static void		env_init(Shell_t*);
static Init_t		*nv_init(Shell_t*);
static Dt_t		*inittree(Shell_t*,const struct shtable2*);
static int		shlvl;

#ifdef _WINIX
#   define EXE	"?(.exe)"
#else
#   define EXE
#endif

static int		rand_shift;


/*
 * Invalidate all path name bindings
 */
static void rehash(register Namval_t *np,void *data)
{
	NOT_USED(data);
	nv_onattr(np,NV_NOALIAS);
}

/*
 * out of memory routine for stak routines
 */
static char *nospace(int unused)
{
	NOT_USED(unused);
	errormsg(SH_DICT,ERROR_exit(3),e_nospace);
	return(NIL(char*));
}

/* Trap for VISUAL and EDITOR variables */
static void put_ed(register Namval_t* np,const char *val,int flags,Namfun_t *fp)
{
	register const char *cp, *name=nv_name(np);
	register int	newopt=0;
	Shell_t *shp = nv_shell(np);
	if(*name=='E' && nv_getval(sh_scoped(shp,VISINOD)))
		goto done;
	if(!(cp=val) && (*name=='E' || !(cp=nv_getval(sh_scoped(shp,EDITNOD)))))
		goto done;
	/* turn on vi or emacs option if editor name is either*/
	cp = path_basename(cp);
	if(strmatch(cp,"*[Vv][Ii]*"))
		newopt=SH_VI;
	else if(strmatch(cp,"*gmacs*"))
		newopt=SH_GMACS;
	else if(strmatch(cp,"*macs*"))
		newopt=SH_EMACS;
	if(newopt)
	{
		sh_offoption(SH_VI);
		sh_offoption(SH_EMACS);
		sh_offoption(SH_GMACS);
		sh_onoption(newopt);
	}
done:
	nv_putv(np, val, flags, fp);
}

/* Trap for HISTFILE and HISTSIZE variables */
static void put_history(register Namval_t* np,const char *val,int flags,Namfun_t *fp)
{
	Shell_t *shp = nv_shell(np);
	void 	*histopen = NULL;
	char	*cp;
	if( shp ) { 
	    histopen = shp->gd->hist_ptr; 
	}
	if(val && histopen)
	{
		if(np==HISTFILE && (cp=nv_getval(np)) && strcmp(val,cp)==0) 
			return;
		if(np==HISTSIZE && sh_arith(shp,val)==nv_getnum(HISTSIZE))
			return;
		hist_close(shp->gd->hist_ptr);
	}
	nv_putv(np, val, flags, fp);
	if(histopen)
	{
		if(val)
			sh_histinit(shp);
		else
			hist_close(histopen);
	}
}

/* Trap for OPTINDEX */
static void put_optindex(Namval_t* np,const char *val,int flags,Namfun_t *fp)
{
	Shell_t *shp = nv_shell(np);
	shp->st.opterror = shp->st.optchar = 0;
	nv_putv(np, val, flags, fp);
	if(!val)
		nv_disc(np,fp,NV_POP);
}

static Sfdouble_t nget_optindex(register Namval_t* np, Namfun_t *fp)
{
	return((Sfdouble_t)*np->nvalue.lp);
}

static Namfun_t *clone_optindex(Namval_t* np, Namval_t *mp, int flags, Namfun_t *fp)
{
	Namfun_t *dp = (Namfun_t*)malloc(sizeof(Namfun_t));
	memcpy((void*)dp,(void*)fp,sizeof(Namfun_t));
	mp->nvalue.lp = np->nvalue.lp;
	dp->nofree = 0;
	return(dp);
}


/* Trap for restricted variables FPATH, PATH, SHELL, ENV */
static void put_restricted(register Namval_t* np,const char *val,int flags,Namfun_t *fp)
{
	Shell_t *shp = nv_shell(np);
	int	path_scoped = 0, fpath_scoped=0;
	Pathcomp_t *pp;
	char *name = nv_name(np);
	if(!(flags&NV_RDONLY) && sh_isoption(SH_RESTRICTED))
		errormsg(SH_DICT,ERROR_exit(1),e_restricted,nv_name(np));
	if(np==PATHNOD	|| (path_scoped=(strcmp(name,PATHNOD->nvname)==0)))		
	{
		nv_scan(shp->track_tree,rehash,(void*)0,NV_TAGGED,NV_TAGGED);
		if(path_scoped && !val)
			val = PATHNOD->nvalue.cp;
	}
	if(val && !(flags&NV_RDONLY) && np->nvalue.cp && strcmp(val,np->nvalue.cp)==0)
		 return;
	if(np==FPATHNOD	|| (fpath_scoped=(strcmp(name,FPATHNOD->nvname)==0)))		
		shp->pathlist = (void*)path_unsetfpath(shp);
	nv_putv(np, val, flags, fp);
	shp->universe = 0;
	if(shp->pathlist)
	{
		val = np->nvalue.cp;
		if(np==PATHNOD || path_scoped)
			pp = (void*)path_addpath(shp,(Pathcomp_t*)shp->pathlist,val,PATH_PATH);
		else if(val && (np==FPATHNOD || fpath_scoped))
			pp = (void*)path_addpath(shp,(Pathcomp_t*)shp->pathlist,val,PATH_FPATH);
		else
			return;
		if(shp->pathlist = (void*)pp)
			pp->shp = shp;
		if(!val && (flags&NV_NOSCOPE))
		{
			Namval_t *mp = dtsearch(shp->var_tree,np);
			if(mp && (val=nv_getval(mp)))
				nv_putval(mp,val,NV_RDONLY);
		}
#if 0
sfprintf(sfstderr,"%d: name=%s val=%s\n",getpid(),name,val);
path_dump((Pathcomp_t*)shp->pathlist);
#endif
	}
}

static void put_cdpath(register Namval_t* np,const char *val,int flags,Namfun_t *fp)
{
	Pathcomp_t *pp;
	Shell_t *shp = nv_shell(np);
	nv_putv(np, val, flags, fp);
	if(!shp->cdpathlist)
		return;
	val = np->nvalue.cp;
	pp = (void*)path_addpath(shp,(Pathcomp_t*)shp->cdpathlist,val,PATH_CDPATH);
	if(shp->cdpathlist = (void*)pp)
		pp->shp = shp;
}

#ifdef _hdr_locale
    /*
     * This function needs to be modified to handle international
     * error message translations
     */
#if ERROR_VERSION >= 20000101L
    static char* msg_translate(const char* catalog, const char* message)
    {
	NOT_USED(catalog);
	return((char*)message);
    }
#else
    static char* msg_translate(const char* message, int type)
    {
	NOT_USED(type);
	return((char*)message);
    }
#endif

    /* Trap for LC_ALL, LC_CTYPE, LC_MESSAGES, LC_COLLATE and LANG */
    static void put_lang(Namval_t* np,const char *val,int flags,Namfun_t *fp)
    {
	Shell_t *shp = nv_shell(np);
	int type;
	char *name = nv_name(np);
	if(name==(LCALLNOD)->nvname)
		type = LC_ALL;
	else if(name==(LCTYPENOD)->nvname)
		type = LC_CTYPE;
	else if(name==(LCMSGNOD)->nvname)
		type = LC_MESSAGES;
	else if(name==(LCCOLLNOD)->nvname)
		type = LC_COLLATE;
	else if(name==(LCNUMNOD)->nvname)
		type = LC_NUMERIC;
#ifdef LC_LANG
	else if(name==(LANGNOD)->nvname)
		type = LC_LANG;
#else
#define LC_LANG		LC_ALL
	else if(name==(LANGNOD)->nvname && (!(name=nv_getval(LCALLNOD)) || !*name))
		type = LC_LANG;
#endif
	else
		type= -1;
	if(!sh_isstate(SH_INIT) && (type>=0 || type==LC_ALL || type==LC_LANG))
	{
		char*		r;
#ifdef AST_LC_setenv
		ast.locale.set |= AST_LC_setenv;
#endif
		r = setlocale(type,val?val:"");
#ifdef AST_LC_setenv
		ast.locale.set ^= AST_LC_setenv;
#endif
		if(!r && val)
		{
			if(!sh_isstate(SH_INIT) || shp->login_sh==0)
				errormsg(SH_DICT,0,e_badlocale,val);
			return;
		}
	}
	nv_putv(np, val, flags, fp);
	if(CC_NATIVE!=CC_ASCII && (type==LC_ALL || type==LC_LANG || type==LC_CTYPE))
	{
		if(sh_lexstates[ST_BEGIN]!=sh_lexrstates[ST_BEGIN])
			free((void*)sh_lexstates[ST_BEGIN]);
		lctype++;
		if(ast.locale.set&(1<<AST_LC_CTYPE))
		{
			register int c;
			char *state[4];
			sh_lexstates[ST_BEGIN] = state[0] = (char*)malloc(4*(1<<CHAR_BIT));
			memcpy(state[0],sh_lexrstates[ST_BEGIN],(1<<CHAR_BIT));
			sh_lexstates[ST_NAME] = state[1] = state[0] + (1<<CHAR_BIT);
			memcpy(state[1],sh_lexrstates[ST_NAME],(1<<CHAR_BIT));
			sh_lexstates[ST_DOL] = state[2] = state[1] + (1<<CHAR_BIT);
			memcpy(state[2],sh_lexrstates[ST_DOL],(1<<CHAR_BIT));
			sh_lexstates[ST_BRACE] = state[3] = state[2] + (1<<CHAR_BIT);
			memcpy(state[3],sh_lexrstates[ST_BRACE],(1<<CHAR_BIT));
			for(c=0; c<(1<<CHAR_BIT); c++)
			{
				if(state[0][c]!=S_REG)
					continue;
				if(state[2][c]!=S_ERR)
					continue;
				if(isblank(c))
				{
					state[0][c]=0;
					state[1][c]=S_BREAK;
					state[2][c]=S_BREAK;
					continue;
				}
				if(!isalpha(c))
					continue;
				state[0][c]=S_NAME;
				if(state[1][c]==S_REG)
					state[1][c]=0;
				state[2][c]=S_ALP;
				if(state[3][c]==S_ERR)
					state[3][c]=0;
			}
		}
		else
		{
			sh_lexstates[ST_BEGIN]=(char*)sh_lexrstates[ST_BEGIN];
			sh_lexstates[ST_NAME]=(char*)sh_lexrstates[ST_NAME];
			sh_lexstates[ST_DOL]=(char*)sh_lexrstates[ST_DOL];
			sh_lexstates[ST_BRACE]=(char*)sh_lexrstates[ST_BRACE];
		}
	}
#if ERROR_VERSION < 20000101L
	if(type==LC_ALL || type==LC_MESSAGES)
		error_info.translate = msg_translate;
#endif
    }
#endif /* _hdr_locale */

/* Trap for IFS assignment and invalidates state table */
static void put_ifs(register Namval_t* np,const char *val,int flags,Namfun_t *fp)
{
	register struct ifs *ip = (struct ifs*)fp;
	ip->ifsnp = 0;
	if(!val)
	{
		fp = nv_stack(np, NIL(Namfun_t*));
		if(fp && !fp->nofree)
		{
			free((void*)fp);
			fp = 0;
		}
	}
	if(val != np->nvalue.cp)
		nv_putv(np, val, flags, fp);
	if(!val)
	{
		if(fp)
			fp->next = np->nvfun;
		np->nvfun = fp;
	}
}

/*
 * This is the lookup function for IFS
 * It keeps the sh.ifstable up to date
 */
static char* get_ifs(register Namval_t* np, Namfun_t *fp)
{
	register struct ifs *ip = (struct ifs*)fp;
	register char *cp, *value;
	register int c,n;
	register Shell_t *shp = nv_shell(np);
	value = nv_getv(np,fp);
	if(np!=ip->ifsnp)
	{
		ip->ifsnp = np;
		memset(shp->ifstable,0,(1<<CHAR_BIT));
		if(cp=value)
		{
#if SHOPT_MULTIBYTE
			while(n=mbsize(cp),c= *(unsigned char*)cp)
#else
			while(c= *(unsigned char*)cp++)
#endif /* SHOPT_MULTIBYTE */
			{
#if SHOPT_MULTIBYTE
				cp++;
				if(n>1)
				{
					cp += (n-1);
					shp->ifstable[c] = S_MBYTE;
					continue;
				}
#endif /* SHOPT_MULTIBYTE */
				n = S_DELIM;
				if(c== *cp)
					cp++;
				else if(c=='\n')
					n = S_NL;
				else if(isspace(c))
					n = S_SPACE;
				shp->ifstable[c] = n;
			}
		}
		else
		{
			shp->ifstable[' '] = shp->ifstable['\t'] = S_SPACE;
			shp->ifstable['\n'] = S_NL;
		}
	}
	return(value);
}

/*
 * these functions are used to get and set the SECONDS variable
 */
#ifdef timeofday
#   define dtime(tp) ((double)((tp)->tv_sec)+1e-6*((double)((tp)->tv_usec)))
#   define tms	timeval
#else
#   define dtime(tp)	(((double)times(tp))/shgd->lim.clk_tck)
#   define timeofday(a)
#endif

static void put_seconds(register Namval_t* np,const char *val,int flags,Namfun_t *fp)
{
	double d;
	struct tms tp;
	if(!val)
	{
		nv_putv(np, val, flags, fp);
		fp = nv_stack(np, NIL(Namfun_t*));
		if(fp && !fp->nofree)
			free((void*)fp);
		return;
	}
	if(!np->nvalue.dp)
	{
		nv_setsize(np,3);
		nv_onattr(np,NV_DOUBLE);
		np->nvalue.dp = new_of(double,0);
	}
	nv_putv(np, val, flags, fp);
	d = *np->nvalue.dp;
	timeofday(&tp);
	*np->nvalue.dp = dtime(&tp)-d;
}

static char* get_seconds(register Namval_t* np, Namfun_t *fp)
{
	Shell_t *shp = nv_shell(np);
	register int places = nv_size(np);
	struct tms tp;
	double d, offset = (np->nvalue.dp?*np->nvalue.dp:0);
	NOT_USED(fp);
	timeofday(&tp);
	d = dtime(&tp)- offset;
	sfprintf(shp->strbuf,"%.*f",places,d);
	return(sfstruse(shp->strbuf));
}

static Sfdouble_t nget_seconds(register Namval_t* np, Namfun_t *fp)
{
	struct tms tp;
	double offset = (np->nvalue.dp?*np->nvalue.dp:0);
	NOT_USED(fp);
	timeofday(&tp);
	return(dtime(&tp)- offset);
}

/*
 * These three functions are used to get and set the RANDOM variable
 */
static void put_rand(register Namval_t* np,const char *val,int flags,Namfun_t *fp)
{
	struct rand *rp = (struct rand*)fp;
	register long n;
	if(!val)
	{
		fp = nv_stack(np, NIL(Namfun_t*));
		if(fp && !fp->nofree)
			free((void*)fp);
		_nv_unset(np,0);
		return;
	}
	if(flags&NV_INTEGER)
		n = *(double*)val;
	else
		n = sh_arith(rp->sh,val);
	srand((int)(n&RANDMASK));
	rp->rand_last = -1;
	if(!np->nvalue.lp)
		np->nvalue.lp = &rp->rand_last;
}

/*
 * get random number in range of 0 - 2**15
 * never pick same number twice in a row
 */
static Sfdouble_t nget_rand(register Namval_t* np, Namfun_t *fp)
{
	register long cur, last= *np->nvalue.lp;
	NOT_USED(fp);
	do
		cur = (rand()>>rand_shift)&RANDMASK;
	while(cur==last);
	*np->nvalue.lp = cur;
	return((Sfdouble_t)cur);
}

static char* get_rand(register Namval_t* np, Namfun_t *fp)
{
	register long n = nget_rand(np,fp);
	return(fmtbase(n, 10, 0));
}

/*
 * These three routines are for LINENO
 */
static Sfdouble_t nget_lineno(Namval_t* np, Namfun_t *fp)
{
	double d=1;
	if(error_info.line >0)
		d = error_info.line;
	else if(error_info.context && error_info.context->line>0)
		d = error_info.context->line;
	NOT_USED(np);
	NOT_USED(fp);
	return(d);
}

static void put_lineno(Namval_t* np,const char *val,int flags,Namfun_t *fp)
{
	register long n;
	Shell_t *shp = nv_shell(np);
	if(!val)
	{
		fp = nv_stack(np, NIL(Namfun_t*));
		if(fp && !fp->nofree)
			free((void*)fp);
		_nv_unset(np,0);
		return;
	}
	if(flags&NV_INTEGER)
		n = *(double*)val;
	else
		n = sh_arith(shp,val);
	shp->st.firstline += nget_lineno(np,fp)+1-n;
}

static char* get_lineno(register Namval_t* np, Namfun_t *fp)
{
	register long n = nget_lineno(np,fp);
	return(fmtbase(n, 10, 0));
}

static char* get_lastarg(Namval_t* np, Namfun_t *fp)
{
	Shell_t	*shp = nv_shell(np);
	char	*cp;
	int	pid;
        if(sh_isstate(SH_INIT) && (cp=shp->lastarg) && *cp=='*' && (pid=strtol(cp+1,&cp,10)) && *cp=='*')
		nv_putval(np,cp+1,0);
	return(shp->lastarg);
}

static void put_lastarg(Namval_t* np,const char *val,int flags,Namfun_t *fp)
{
	Shell_t *shp = nv_shell(np);
	if(flags&NV_INTEGER)
	{
		sfprintf(shp->strbuf,"%.*g",12,*((double*)val));
		val = sfstruse(shp->strbuf);
	}
	if(val)
		val = strdup(val);
	if(shp->lastarg && !nv_isattr(np,NV_NOFREE))
		free((void*)shp->lastarg);
	else
		nv_offattr(np,NV_NOFREE);
	shp->lastarg = (char*)val;
	nv_offattr(np,NV_EXPORT);
	np->nvenv = 0;
}

static int hasgetdisc(register Namfun_t *fp)
{
        while(fp && !fp->disc->getnum && !fp->disc->getval)
                fp = fp->next;
	return(fp!=0);
}

/*
 * store the most recent value for use in .sh.match
 * treat .sh.match as a two dimensional array
 */
void sh_setmatch(Shell_t *shp,const char *v, int vsize, int nmatch, regoff_t match[],int index)
{
	struct match	*mp = &ip->SH_MATCH_init;
	Namval_t	*np = nv_namptr(mp->node,0); 
	register int	i,n,x, savesub=shp->subshell;
	Namarr_t	*ap = nv_arrayptr(SH_MATCHNOD);
	shp->subshell = 0;
#ifndef SHOPT_2DMATCH
	index = 0;
#else
	if(index==0)
#endif /* SHOPT_2DMATCH */
	{
		if(ap->hdr.next != &mp->hdr)
		{
			free((void*)ap);
			ap = nv_arrayptr(np);
			SH_MATCHNOD->nvfun = &ap->hdr;
		}
		if(ap)
		{
			ap->nelem &= ~ARRAY_SCAN;
			i = array_elem(ap);
			ap->nelem++;
			while(--i>= 0)
			{
				nv_putsub(SH_MATCHNOD, (char*)0,i);
				_nv_unset(SH_MATCHNOD,NV_RDONLY);
			}
			ap->nelem--;
		}
		if(!nv_hasdisc(SH_MATCHNOD,mp->hdr.disc))
			nv_disc(SH_MATCHNOD,&mp->hdr,NV_LAST);
		if(nmatch)
			nv_putsub(SH_MATCHNOD, NIL(char*), (nmatch-1)|ARRAY_FILL|ARRAY_SETSUB);
		ap = nv_arrayptr(SH_MATCHNOD);
		ap->nelem = mp->nmatch = nmatch;
		mp->v = v;
		mp->first = match[0];
	}
#ifdef SHOPT_2DMATCH
	else
	{
		if(index==1)
		{
			np->nvalue.cp = Empty;
			np->nvfun = SH_MATCHNOD->nvfun;
			nv_onattr(np,NV_NOFREE|NV_ARRAY);
			SH_MATCHNOD->nvfun = 0;
			for(i=0; i < mp->nmatch; i++)
			{
				nv_putsub(SH_MATCHNOD, (char*)0, i);
				nv_arraychild(SH_MATCHNOD, np,0);
			}
			if(ap = nv_arrayptr(SH_MATCHNOD))
				ap->nelem = mp->nmatch;
		}
		ap = nv_arrayptr(np);
		nv_putsub(np, NIL(char*), index|ARRAY_FILL|ARRAY_SETSUB);
	}
#endif /* SHOPT_2DMATCH */
	shp->subshell = savesub;
	index *= 2*mp->nmatch;
	if(mp->nmatch)
	{
		for(n=mp->first+(mp->v-v),vsize=0,i=0; i < 2*nmatch; i++)
		{
			if(match[i]>=0 && (match[i] - n) > vsize)
				vsize = match[i] -n;
		}
		i = (index+2*mp->nmatch)*sizeof(match[0]);
		if((i+vsize) >= mp->vsize)
		{
			if(mp->vsize)
				mp->match = (int*)realloc(mp->match,i+vsize+1);
			else
				mp->match = (int*)malloc(i+vsize+1);
			mp->vsize = i+vsize+1;
		}
		mp->val =  ((char*)mp->match)+i; 
		memcpy(mp->match+index,match,nmatch*2*sizeof(match[0]));
		for(x=0,i=0; i < 2*nmatch; i++)
		{
			if(match[i]>=0)
				mp->match[index+i] -= n;
			else
				x=1;

		}
		ap->nelem -= x;
		while(i < 2*mp->nmatch)
			mp->match[index+i++] = -1;
		memcpy(mp->val,v+n,vsize);
		mp->val[vsize] = 0;
		mp->lastsub[0] = mp->lastsub[1] = -1;
	}
} 

#define array_scan(np)	((nv_arrayptr(np)->nelem&ARRAY_SCAN))

static char* get_match(register Namval_t* np, Namfun_t *fp)
{
	struct match	*mp = (struct match*)fp;
	int		sub,sub2=0,n,i =!mp->index;
	char		*val;
	sub = nv_aindex(SH_MATCHNOD);
	if(np!=SH_MATCHNOD)
		sub2 = nv_aindex(np);
	if(sub>=mp->nmatch)
		return(0);
	if(sub2>0)
		sub += sub2*mp->nmatch;
	if(sub==mp->lastsub[!i])
		return(mp->rval[!i]);
	else if(sub==mp->lastsub[i])
		return(mp->rval[i]);
	n = mp->match[2*sub+1]-mp->match[2*sub];
	if(n<=0)
		return(mp->match[2*sub]<0?Empty:"");
	val = mp->val+mp->match[2*sub];
	if(mp->val[mp->match[2*sub+1]]==0)
		return(val);
	mp->index = i;
	if(mp->rval[i])
	{
		free((void*)mp->rval[i]);
		mp->rval[i] = 0;
	}
	mp->rval[i] = (char*)malloc(n+1);
	mp->lastsub[i] = sub;
	memcpy(mp->rval[i],val,n);
	mp->rval[i][n] = 0;
	return(mp->rval[i]);
}

static const Namdisc_t SH_MATCH_disc  = { sizeof(struct match), 0, get_match };

static char* get_version(register Namval_t* np, Namfun_t *fp)
{
	return(nv_getv(np,fp));
}

static Sfdouble_t nget_version(register Namval_t* np, Namfun_t *fp)
{
	register const char	*cp = e_version + strlen(e_version)-10;
	register int		c;
	Sflong_t		t = 0;
	NOT_USED(fp);

	while (c = *cp++)
		if (c >= '0' && c <= '9')
		{
			t *= 10;
			t += c - '0';
		}
	return((Sfdouble_t)t);
}

static const Namdisc_t SH_VERSION_disc	= {  0, 0, get_version, nget_version };

#if SHOPT_FS_3D
    /*
     * set or unset the mappings given a colon separated list of directories
     */
    static void vpath_set(char *str, int mode)
    {
	register char *lastp, *oldp=str, *newp=strchr(oldp,':');
	if(!shgd->lim.fs3d)
		return;
	while(newp)
	{
		*newp++ = 0;
		if(lastp=strchr(newp,':'))
			*lastp = 0;
		mount((mode?newp:""),oldp,FS3D_VIEW,0);
		newp[-1] = ':';
		oldp = newp;
		newp=lastp;
	}
    }

    /* catch vpath assignments */
    static void put_vpath(register Namval_t* np,const char *val,int flags,Namfun_t *fp)
    {
	register char *cp;
	if(cp = nv_getval(np))
		vpath_set(cp,0);
	if(val)
		vpath_set((char*)val,1);
	nv_putv(np,val,flags,fp);
    }
    static const Namdisc_t VPATH_disc	= { 0, put_vpath  };
    static Namfun_t VPATH_init	= { &VPATH_disc, 1  };
#endif /* SHOPT_FS_3D */


static const Namdisc_t IFS_disc		= {  sizeof(struct ifs), put_ifs, get_ifs };
const Namdisc_t RESTRICTED_disc	= {  sizeof(Namfun_t), put_restricted };
static const Namdisc_t CDPATH_disc	= {  sizeof(Namfun_t), put_cdpath }; 
static const Namdisc_t EDITOR_disc	= {  sizeof(Namfun_t), put_ed };
static const Namdisc_t HISTFILE_disc	= {  sizeof(Namfun_t), put_history };
static const Namdisc_t OPTINDEX_disc	= {  sizeof(Namfun_t), put_optindex, 0, nget_optindex, 0, 0, clone_optindex };
static const Namdisc_t SECONDS_disc	= {  sizeof(struct seconds), put_seconds, get_seconds, nget_seconds };
static const Namdisc_t RAND_disc	= {  sizeof(struct rand), put_rand, get_rand, nget_rand };
static const Namdisc_t LINENO_disc	= {  sizeof(Namfun_t), put_lineno, get_lineno, nget_lineno };
static const Namdisc_t L_ARG_disc	= {  sizeof(Namfun_t), put_lastarg, get_lastarg };


#define MAX_MATH_ARGS	3

static char *name_math(Namval_t *np, Namfun_t *fp)
{
	Shell_t		*shp = sh_getinterp();
	sfprintf(shp->strbuf,".sh.math.%s",np->nvname);
	return(sfstruse(shp->strbuf));
}

static const Namdisc_t	math_child_disc =
{
	0,0,0,0,0,0,0,
	name_math
};

static Namfun_t	 math_child_fun =
{
	&math_child_disc, 1, 0, sizeof(Namfun_t)
};

static void math_init(Shell_t *shp)
{
	Namval_t	*np;
	char		*name;
	int		i;
	shp->mathnodes = (char*)calloc(1,MAX_MATH_ARGS*(NV_MINSZ+5));
	name = shp->mathnodes+MAX_MATH_ARGS*NV_MINSZ;
	for(i=0; i < MAX_MATH_ARGS; i++)
	{
		np = nv_namptr(shp->mathnodes,i);
		np->nvfun = &math_child_fun;
		memcpy(name,"arg",3);
		name[3] = '1'+i;
		np->nvname = name;
		name+=5;
		nv_onattr(np,NV_MINIMAL|NV_NOFREE|NV_LDOUBLE|NV_RDONLY);
	}
}

static Namval_t *create_math(Namval_t *np,const char *name,int flag,Namfun_t *fp)
{
	Shell_t		*shp = nv_shell(np);
	if(!name)
		return(SH_MATHNOD);
	if(name[0]!='a' || name[1]!='r' || name[2]!='g' || name[4] || !isdigit(name[3]) || (name[3]=='0' || (name[3]-'0')>MAX_MATH_ARGS))
		return(0);
	fp->last = (char*)&name[4];
	return(nv_namptr(shp->mathnodes,name[3]-'1'));
}

static char* get_math(register Namval_t* np, Namfun_t *fp)
{
	Shell_t		*shp = nv_shell(np);
	Namval_t	*mp,fake;
	char		*val;
	int		first=0;
	fake.nvname = ".sh.math.";
	mp = (Namval_t*)dtprev(shp->fun_tree,&fake);
	while(mp=(Namval_t*)dtnext(shp->fun_tree,mp))
	{
		if(memcmp(mp->nvname,".sh.math.",9))
			break;
		if(first++)
			sfputc(shp->strbuf,' ');
		sfputr(shp->strbuf,mp->nvname+9,-1);
	}
	val = sfstruse(shp->strbuf);
	return(val);
	
}

static char *setdisc_any(Namval_t *np, const char *event, Namval_t *action, Namfun_t *fp)
{
	Shell_t		*shp=nv_shell(np);
	Namval_t	*mp,fake;
	char		*name;
	int		getname=0, off=staktell();
	fake.nvname = nv_name(np);
	if(!event)
	{
		if(!action)
		{
			mp = (Namval_t*)dtprev(shp->fun_tree,&fake);
			return((char*)dtnext(shp->fun_tree,mp));
		}
		getname = 1;
	}
	stakputs(fake.nvname);
	stakputc('.');
	stakputs(event);
	stakputc(0);
	name  = stakptr(off);
	mp = nv_search(name, shp->fun_tree, action?NV_ADD:0);
	stakseek(off);
	if(getname)
		return(mp?(char*)dtnext(shp->fun_tree,mp):0);
	if(action==np)
		action = mp;
	return(action?(char*)action:"");
}

static const Namdisc_t SH_MATH_disc  = { 0, 0, get_math, 0, setdisc_any, create_math, };

#if SHOPT_COSHELL
static const Namdisc_t SH_JOBPOOL_disc  = { 0, 0, 0, 0, setdisc_any, 0, };
#endif /*  SHOPT_COSHELL */

#if SHOPT_NAMESPACE
    static char* get_nspace(Namval_t* np, Namfun_t *fp)
    {
	if(sh.namespace)
		return(nv_name(sh.namespace));
	return((char*)np->nvalue.cp);
    }
    static const Namdisc_t NSPACE_disc	= {  0, 0, get_nspace };
    static Namfun_t NSPACE_init	= {  &NSPACE_disc, 1};
#endif /* SHOPT_NAMESPACE */

#ifdef _hdr_locale
    static const Namdisc_t LC_disc	= {  sizeof(Namfun_t), put_lang };
#endif /* _hdr_locale */

/*
 * This function will get called whenever a configuration parameter changes
 */
static int newconf(const char *name, const char *path, const char *value)
{
	Shell_t	*shp = sh_getinterp();
	register char *arg;
	if(!name)
		setenviron(value);
	else if(strcmp(name,"UNIVERSE")==0 && strcmp(astconf(name,0,0),value))
	{
		shp->universe = 0;
		/* set directory in new universe */
		if(*(arg = path_pwd(shp,0))=='/')
			chdir(arg);
		/* clear out old tracked alias */
		stakseek(0);
		stakputs(nv_getval(PATHNOD));
		stakputc(0);
		nv_putval(PATHNOD,stakseek(0),NV_RDONLY);
	}
	return(1);
}

#if	(CC_NATIVE != CC_ASCII)
    static void a2e(char *d, const char *s)
    {
	register const unsigned char *t;
	register int i;
	t = CCMAP(CC_ASCII, CC_NATIVE);
	for(i=0; i<(1<<CHAR_BIT); i++)
		d[t[i]] = s[i];
    }

    static void init_ebcdic(void)
    {
	int i;
	char *cp = (char*)malloc(ST_NONE*(1<<CHAR_BIT));
	for(i=0; i < ST_NONE; i++)
	{
		a2e(cp,sh_lexrstates[i]);
		sh_lexstates[i] = cp;
		cp += (1<<CHAR_BIT);
	}
    }
#endif

/*
 * return SH_TYPE_* bitmask for path
 * 0 for "not a shell"
 */
int sh_type(register const char *path)
{
	register const char*	s;
	register int		t = 0;
	
	if (s = (const char*)strrchr(path, '/'))
	{
		if (*path == '-')
			t |= SH_TYPE_LOGIN;
		s++;
	}
	else
		s = path;
	if (*s == '-')
	{
		s++;
		t |= SH_TYPE_LOGIN;
	}
	for (;;)
	{
		if (!(t & (SH_TYPE_KSH|SH_TYPE_BASH)))
		{
			if (*s == 'k')
			{
				s++;
				t |= SH_TYPE_KSH;
				continue;
			}
#if SHOPT_BASH
			if (*s == 'b' && *(s+1) == 'a')
			{
				s += 2;
				t |= SH_TYPE_BASH;
				continue;
			}
#endif
		}
		if (!(t & (SH_TYPE_PROFILE|SH_TYPE_RESTRICTED)))
		{
#if SHOPT_PFSH
			if (*s == 'p' && *(s+1) == 'f')
			{
				s += 2;
				t |= SH_TYPE_PROFILE;
				continue;
			}
#endif
			if (*s == 'r')
			{
				s++;
				t |= SH_TYPE_RESTRICTED;
				continue;
			}
		}
		break;
	}
	if (*s++ == 's' && (*s == 'h' || *s == 'u'))
	{
		s++;
		t |= SH_TYPE_SH;
		if ((t & SH_TYPE_KSH) && *s == '9' && *(s+1) == '3')
			s += 2;
#if _WINIX
		if (*s == '.' && *(s+1) == 'e' && *(s+2) == 'x' && *(s+3) == 'e')
			s += 4;
#endif
		if (!isalnum(*s))
			return t;
	}
	return t & ~(SH_TYPE_BASH|SH_TYPE_KSH|SH_TYPE_PROFILE|SH_TYPE_RESTRICTED);
}


static char *get_mode(Namval_t* np, Namfun_t* nfp)
{
	mode_t mode = nv_getn(np,nfp);
	return(fmtperm(mode));
}

static void put_mode(Namval_t* np, const char* val, int flag, Namfun_t* nfp)
{
	if(val)
	{
		mode_t mode;
		char *last=0;
		if(flag&NV_INTEGER)
		{
			if(flag&NV_LONG)
				mode = *(Sfdouble_t*)val;
			else
				mode = *(double*)val;
		}
		else
			mode = strperm(val, &last,0);
		if(*last)
			errormsg(SH_DICT,ERROR_exit(1),"%s: invalid mode string",val);
		nv_putv(np,(char*)&mode,NV_INTEGER,nfp);
	}
	else
		nv_putv(np,val,flag,nfp);
}

static const Namdisc_t modedisc =
{
	0,
        put_mode,
        get_mode,
};


/*
 * initialize the shell
 */
Shell_t *sh_init(register int argc,register char *argv[], Shinit_f userinit)
{
	static int beenhere;
	Shell_t	*shp;
	register int n;
	int type;
	static char *login_files[3];
	memfatal();
	n = strlen(e_version);
	if(e_version[n-1]=='$' && e_version[n-2]==' ')
		e_version[n-2]=0;
#if	(CC_NATIVE == CC_ASCII)
	memcpy(sh_lexstates,sh_lexrstates,ST_NONE*sizeof(char*));
#else
	init_ebcdic();
#endif
	if(!beenhere)
	{
		beenhere = 1;
		shp = &sh;
		shgd = newof(0,struct shared,1,0);
		shgd->pid = getpid();
		shgd->ppid = getppid();
		shgd->userid=getuid();
		shgd->euserid=geteuid();
		shgd->groupid=getgid();
		shgd->egroupid=getegid();
		shgd->lim.clk_tck = getconf("CLK_TCK");
		shgd->lim.arg_max = getconf("ARG_MAX");
		shgd->lim.child_max = getconf("CHILD_MAX");
		shgd->lim.ngroups_max = getconf("NGROUPS_MAX");
		shgd->lim.posix_version = getconf("VERSION");
		shgd->lim.posix_jobcontrol = getconf("JOB_CONTROL");
		if(shgd->lim.arg_max <=0)
			shgd->lim.arg_max = ARG_MAX;
		if(shgd->lim.child_max <=0)
			shgd->lim.child_max = CHILD_MAX;
		if(shgd->lim.clk_tck <=0)
			shgd->lim.clk_tck = CLK_TCK;
#if SHOPT_FS_3D
		if(fs3d(FS3D_TEST))
			shgd->lim.fs3d = 1;
#endif /* SHOPT_FS_3D */
		shgd->ed_context = (void*)ed_open(shp);
		error_info.exit = sh_exit;
		error_info.id = path_basename(argv[0]);
	}
	else
		shp = newof(0,Shell_t,1,0);
	umask(shp->mask=umask(0));
	shp->gd = shgd;
	shp->mac_context = sh_macopen(shp);
	shp->arg_context = sh_argopen(shp);
	shp->lex_context = (void*)sh_lexopen(0,shp,1);
	shp->strbuf = sfstropen();
	shp->stk = stkstd;
	sfsetbuf(shp->strbuf,(char*)0,64);
	sh_onstate(SH_INIT);
#if ERROR_VERSION >= 20000102L
	error_info.catalog = e_dict;
#endif
#if SHOPT_REGRESS
	{
		Opt_t*	nopt;
		Opt_t*	oopt;
		char*	a;
		char**	av = argv;
		char*	regress[3];

		sh_regress_init(shp);
		regress[0] = "__regress__";
		regress[2] = 0;
		/* NOTE: only shp is used by __regress__ at this point */
		shp->bltindata.shp = shp;
		while ((a = *++av) && a[0] == '-' && (a[1] == 'I' || a[1] == '-' && a[2] == 'r'))
		{
			if (a[1] == 'I')
			{
				if (a[2])
					regress[1] = a + 2;
				else if (!(regress[1] = *++av))
					break;
			}
			else if (strncmp(a+2, "regress", 7))
				break;
			else if (a[9] == '=')
				regress[1] = a + 10;
			else if (!(regress[1] = *++av))
				break;
			nopt = optctx(0, 0);
			oopt = optctx(nopt, 0);
			b___regress__(2, regress, &shp->bltindata);
			optctx(oopt, nopt);
		}
	}
#endif
	shp->cpipe[0] = -1;
	shp->coutpipe = -1;
	for(n=0;n < 10; n++)
	{
		/* don't use lower bits when rand() generates large numbers */
		if(rand() > RANDMASK)
		{
			rand_shift = 3;
			break;
		}
	}
	sh_ioinit(shp);
	/* initialize signal handling */
	sh_siginit(shp);
	stakinstall(NIL(Stak_t*),nospace);
	/* set up memory for name-value pairs */
	shp->init_context =  nv_init(shp);
	/* read the environment */
	if(argc>0)
	{
		type = sh_type(*argv);
		if(type&SH_TYPE_LOGIN)
			shp->login_sh = 2;
	}
	env_init(shp);
	if(!ENVNOD->nvalue.cp)
	{
		sfprintf(shp->strbuf,"%s/.kshrc",nv_getval(HOME));
		nv_putval(ENVNOD,sfstruse(shp->strbuf),NV_RDONLY);
	}
	*SHLVL->nvalue.ip +=1;
	nv_offattr(SHLVL,NV_IMPORT);
#if SHOPT_SPAWN
	{
		/*
		 * try to find the pathname for this interpreter
		 * try using environment variable _ or argv[0]
		 */
		char *cp=nv_getval(L_ARGNOD);
		char buff[PATH_MAX+1];
		shp->gd->shpath = 0;
#if _AST_VERSION >= 20090202L
		if((n = pathprog(NiL, buff, sizeof(buff))) > 0 && n <= sizeof(buff))
			shp->gd->shpath = strdup(buff);
#else
		sfprintf(shp->strbuf,"/proc/%d/exe",getpid());
		if((n=readlink(sfstruse(shp->strbuf),buff,sizeof(buff)-1))>0)
		{
			buff[n] = 0;
			shp->gd->shpath = strdup(buff);
		}
#endif
		else if((cp && (sh_type(cp)&SH_TYPE_SH)) || (argc>0 && strchr(cp= *argv,'/')))
		{
			if(*cp=='/')
				shp->gd->shpath = strdup(cp);
			else if(cp = nv_getval(PWDNOD))
			{
				int offset = staktell();
				stakputs(cp);
				stakputc('/');
				stakputs(argv[0]);
				pathcanon(stakptr(offset),PATH_DOTDOT);
				shp->gd->shpath = strdup(stakptr(offset));
				stakseek(offset);
			}
		}
	}
#endif
	nv_putval(IFSNOD,(char*)e_sptbnl,NV_RDONLY);
#if SHOPT_FS_3D
	nv_stack(VPATHNOD, &VPATH_init);
#endif /* SHOPT_FS_3D */
	astconfdisc(newconf);
#if SHOPT_TIMEOUT
	shp->st.tmout = SHOPT_TIMEOUT;
#endif /* SHOPT_TIMEOUT */
	/* initialize jobs table */
	job_clear();
	sh_onoption(SH_MULTILINE);
	if(argc>0)
	{
		int dolv_index = -1;
		/* check for restricted shell */
		if(type&SH_TYPE_RESTRICTED)
			sh_onoption(SH_RESTRICTED);
#if SHOPT_PFSH
		/* check for profile shell */
		else if(type&SH_TYPE_PROFILE)
			sh_onoption(SH_PFSH);
#endif
#if SHOPT_BASH
		/* check for invocation as bash */
		if(type&SH_TYPE_BASH)
		{
		        shp>userinit = userinit = bash_init;
			sh_onoption(SH_BASH);
			sh_onstate(SH_PREINIT);
			(*userinit)(shp, 0);
			sh_offstate(SH_PREINIT);
		}
#endif
		/* look for options */
		/* shp->st.dolc is $#	*/
		if((shp->st.dolc = sh_argopts(-argc,argv,shp)) < 0)
		{
			shp->exitval = 2;
			sh_done(shp,0);
		}
		opt_info.disc = 0;
		dolv_index = (argc-1)-shp->st.dolc;
		shp->st.dolv=argv+dolv_index;
		shp->st.repl_index = dolv_index;
		shp->st.repl_arg = argv[dolv_index];	
		shp->st.dolv[0] = argv[0];
		if(shp->st.dolc < 1)
			sh_onoption(SH_SFLAG);
		if(!sh_isoption(SH_SFLAG))
		{
			shp->st.dolc--;
			shp->st.dolv++;
#if _WINIX
			{
				char*	name;
				name = shp->st.dolv[0];
				if(name[1]==':' && (name[2]=='/' || name[2]=='\\'))
				{
#if _lib_pathposix
					char*	p;

					if((n = pathposix(name, NIL(char*), 0)) > 0 && (p = (char*)malloc(++n)))
					{
						pathposix(name, p, n);
						name = p;
					}
					else
#endif
					{
						name[1] = name[0];
						name[0] = name[2] = '/';
					}
				}
			}
#endif /* _WINIX */
		}
		if(beenhere==1)
		{
			struct lconv*	lc;
			shp->decomma = (lc=localeconv()) && lc->decimal_point && *lc->decimal_point==',';
			beenhere = 2;
		}
	}
#if SHOPT_PFSH
	if (sh_isoption(SH_PFSH))
	{
		struct passwd *pw = getpwuid(shp->gd->userid);
		if(pw)
			shp->gd->user = strdup(pw->pw_name);
		
	}
#endif
	/* set[ug]id scripts require the -p flag */
	if(shp->gd->userid!=shp->gd->euserid || shp->gd->groupid!=shp->gd->egroupid)
	{
#ifdef SHOPT_P_SUID
		/* require sh -p to run setuid and/or setgid */
		if(!sh_isoption(SH_PRIVILEGED) && shp->gd->userid >= SHOPT_P_SUID)
		{
			setuid(shp->gd->euserid=shp->gd->userid);
			setgid(shp->gd->egroupid=shp->gd->groupid);
		}
		else
#endif /* SHOPT_P_SUID */
			sh_onoption(SH_PRIVILEGED);
#ifdef SHELLMAGIC
		/* careful of #! setuid scripts with name beginning with - */
		if(shp->login_sh && argv[1] && strcmp(argv[0],argv[1])==0)
			errormsg(SH_DICT,ERROR_exit(1),e_prohibited);
#endif /*SHELLMAGIC*/
	}
	else
		sh_offoption(SH_PRIVILEGED);
	/* shname for $0 in profiles and . scripts */
	if(sh_isdevfd(argv[1]))
		shp->shname = strdup(argv[0]);
	else
		shp->shname = strdup(shp->st.dolv[0]);
	/*
	 * return here for shell script execution
	 * but not for parenthesis subshells
	 */
	error_info.id = strdup(shp->st.dolv[0]); /* error_info.id is $0 */
	shp->jmpbuffer = (void*)&shp->checkbase;
	sh_pushcontext(shp,&shp->checkbase,SH_JMPSCRIPT);
	shp->st.self = &shp->global;
        shp->topscope = (Shscope_t*)shp->st.self;
	sh_offstate(SH_INIT);
	login_files[0] = (char*)e_profile;
	login_files[1] = ".profile";
	shp->gd->login_files = login_files;
	shp->bltindata.version = SH_VERSION;
	shp->bltindata.shp = shp;
	shp->bltindata.shrun = sh_run;
	shp->bltindata.shtrap = sh_trap;
	shp->bltindata.shexit = sh_exit;
	shp->bltindata.shbltin = sh_addbuiltin;
#if _AST_VERSION >= 20080617L
	shp->bltindata.shgetenv = sh_getenv;
	shp->bltindata.shsetenv = sh_setenviron;
	astintercept(&shp->bltindata,1);
#endif
#if 0
#define NV_MKINTTYPE(x,y,z)	nv_mkinttype(#x,sizeof(x),(x)-1<0,(y),(Namdisc_t*)z); 
	NV_MKINTTYPE(pid_t,"process id",0);
	NV_MKINTTYPE(gid_t,"group id",0);
	NV_MKINTTYPE(uid_t,"user id",0);
	NV_MKINTTYPE(size_t,(const char*)0,0);
	NV_MKINTTYPE(ssize_t,(const char*)0,0);
	NV_MKINTTYPE(off_t,"offset in bytes",0);
	NV_MKINTTYPE(ino_t,"\ai-\anode number",0);
	NV_MKINTTYPE(mode_t,(const char*)0,&modedisc);
	NV_MKINTTYPE(dev_t,"device id",0);
	NV_MKINTTYPE(nlink_t,"hard link count",0);
	NV_MKINTTYPE(blkcnt_t,"block count",0);
	NV_MKINTTYPE(time_t,"seconds since the epoch",0);
	nv_mkstat();
#endif
	if(shp->userinit=userinit)
		(*userinit)(shp, 0);
	shp->exittrap = 0;
	shp->errtrap = 0;
	shp->end_fn = 0;
	return(shp);
}

Shell_t *sh_getinterp(void)
{
	return(&sh);
}

/*
 * reinitialize before executing a script
 */
int sh_reinit(char *argv[])
{
	Shell_t	*shp = sh_getinterp();
	Shopt_t opt;
	Namval_t *np,*npnext;
	Dt_t	*dp;
	struct adata
	{
		Shell_t		*sh;
		void		*extra[2];
	} data;
	for(np=dtfirst(shp->fun_tree);np;np=npnext)
	{
		if((dp=shp->fun_tree)->walk)
			dp = dp->walk;
		npnext = (Namval_t*)dtnext(shp->fun_tree,np);
		if(np>= shgd->bltin_cmds && np < &shgd->bltin_cmds[nbltins])
			continue;
		if(is_abuiltin(np) && nv_isattr(np,NV_EXPORT))
			continue;
		if(*np->nvname=='/')
			continue;
		nv_delete(np,dp,NV_NOFREE);
	}
	dtclose(shp->alias_tree);
	shp->alias_tree = inittree(shp,shtab_aliases);
	shp->last_root = shp->var_tree;
	shp->inuse_bits = 0;
	if(shp->userinit)
		(*shp->userinit)(shp, 1);
	if(shp->heredocs)
	{
		sfclose(shp->heredocs);
		shp->heredocs = 0;
	}
	/* remove locals */
	sh_onstate(SH_INIT);
	memset(&data,0,sizeof(data));
	data.sh = shp;
	nv_scan(shp->var_tree,sh_envnolocal,(void*)&data,NV_EXPORT,0);
	nv_scan(shp->var_tree,sh_envnolocal,(void*)&data,NV_ARRAY,NV_ARRAY);
	sh_offstate(SH_INIT);
	memset(shp->st.trapcom,0,(shp->st.trapmax+1)*sizeof(char*));
	memset((void*)&opt,0,sizeof(opt));
#if SHOPT_NAMESPACE
	if(shp->namespace)
	{
		dp=nv_dict(shp->namespace);
		if(dp==shp->var_tree)
			shp->var_tree = dtview(dp,0);
		_nv_unset(shp->namespace,NV_RDONLY);
		shp->namespace = 0;
	}
#endif /* SHOPT_NAMESPACE */
	if(sh_isoption(SH_TRACKALL))
		on_option(&opt,SH_TRACKALL);
	if(sh_isoption(SH_EMACS))
		on_option(&opt,SH_EMACS);
	if(sh_isoption(SH_GMACS))
		on_option(&opt,SH_GMACS);
	if(sh_isoption(SH_VI))
		on_option(&opt,SH_VI);
	if(sh_isoption(SH_VIRAW))
		on_option(&opt,SH_VIRAW);
	shp->options = opt;
	/* set up new args */
	if(argv)
		shp->arglist = sh_argcreate(argv);
	if(shp->arglist)
		sh_argreset(shp,shp->arglist,NIL(struct dolnod*));
	shp->envlist=0;
	shp->curenv = 0;
	shp->shname = error_info.id = strdup(shp->st.dolv[0]);
	sh_offstate(SH_FORKED);
	shp->fn_depth = shp->dot_depth = 0;
	sh_sigreset(0);
	if(!(SHLVL->nvalue.ip))
	{
		shlvl = 0;
		SHLVL->nvalue.ip = &shlvl;
		nv_onattr(SHLVL,NV_INTEGER|NV_EXPORT|NV_NOFREE);
	}
	*SHLVL->nvalue.ip +=1;
	nv_offattr(SHLVL,NV_IMPORT);
	shp->st.filename = strdup(shp->lastarg);
	nv_delete((Namval_t*)0, (Dt_t*)0, 0);
	job.exitval = 0;
	shp->inpipe = shp->outpipe = 0;
	job_clear();
	job.in_critical = 0;
	shp->exittrap = 0;
	shp->errtrap = 0;
	shp->end_fn = 0;
	return(1);
}

/*
 * set when creating a local variable of this name
 */
Namfun_t *nv_cover(register Namval_t *np)
{
	if(np==IFSNOD || np==PATHNOD || np==SHELLNOD || np==FPATHNOD || np==CDPNOD || np==SECONDS || np==ENVNOD || np==LINENO)
		return(np->nvfun);
#ifdef _hdr_locale
	if(np==LCALLNOD || np==LCTYPENOD || np==LCMSGNOD || np==LCCOLLNOD || np==LCNUMNOD || np==LANGNOD)
		return(np->nvfun);
#endif
	 return(0);
}

static const char *shdiscnames[] = { "tilde", 0};

#ifdef SHOPT_STATS
struct Stats
{
	Namfun_t	hdr;
	Shell_t		*sh;
	char		*nodes;
	int		numnodes;
	int		current;
};

static Namval_t *next_stat(register Namval_t* np, Dt_t *root,Namfun_t *fp)
{
	struct Stats *sp = (struct Stats*)fp;
	if(!root)
		sp->current = 0;
	else if(++sp->current>=sp->numnodes)
		return(0);
	return(nv_namptr(sp->nodes,sp->current));
}

static Namval_t *create_stat(Namval_t *np,const char *name,int flag,Namfun_t *fp)
{
	struct Stats		*sp = (struct Stats*)fp;
	register const char	*cp=name;
	register int		i=0,n;
	Namval_t		*nq=0;
	Shell_t			*shp = sp->sh;
	if(!name)
		return(SH_STATS);
	while((i=*cp++) && i != '=' && i != '+' && i!='[');
	n = (cp-1) -name;
	for(i=0; i < sp->numnodes; i++)
	{
		nq = nv_namptr(sp->nodes,i);
		if((n==0||memcmp(name,nq->nvname,n)==0) && nq->nvname[n]==0)
			goto found;
	}
	nq = 0;
found:
	if(nq)
	{
		fp->last = (char*)&name[n];
		shp->last_table = SH_STATS;
	}
	else
		errormsg(SH_DICT,ERROR_exit(1),e_notelem,n,name,nv_name(np));
	return(nq);
}

static const Namdisc_t stat_disc =
{
	0, 0, 0, 0, 0,
	create_stat,
	0, 0,
	next_stat
};

static char *name_stat(Namval_t *np, Namfun_t *fp)
{
	Shell_t	*shp = sh_getinterp();
	sfprintf(shp->strbuf,".sh.stats.%s",np->nvname);
	return(sfstruse(shp->strbuf));
}

static const Namdisc_t	stat_child_disc =
{
	0,0,0,0,0,0,0,
	name_stat
};

static Namfun_t	 stat_child_fun =
{
	&stat_child_disc, 1, 0, sizeof(Namfun_t)
};

static void stat_init(Shell_t *shp)
{
	int		i,nstat = STAT_SUBSHELL+1;
	struct Stats	*sp = newof(0,struct Stats,1,nstat*NV_MINSZ);
	Namval_t	*np;
	sp->numnodes = nstat;
	sp->nodes = (char*)(sp+1);
	shgd->stats = (int*)calloc(sizeof(int),nstat);
	sp->sh = shp;
	for(i=0; i < nstat; i++)
	{
		np = nv_namptr(sp->nodes,i);
		np->nvfun = &stat_child_fun;
		np->nvname = (char*)shtab_stats[i].sh_name;
		nv_onattr(np,NV_RDONLY|NV_MINIMAL|NV_NOFREE|NV_INTEGER);
		nv_setsize(np,10);
		np->nvalue.ip = &shgd->stats[i];
	}
	sp->hdr.dsize = sizeof(struct Stats) + nstat*(sizeof(int)+NV_MINSZ);
	sp->hdr.disc = &stat_disc;
	nv_stack(SH_STATS,&sp->hdr);
	sp->hdr.nofree = 1;
	nv_setvtree(SH_STATS);
}
#else
#   define stat_init(x)
#endif /* SHOPT_STATS */

/*
 * Initialize the shell name and alias table
 */
static Init_t *nv_init(Shell_t *shp)
{
	double d=0;
	ip = newof(0,Init_t,1,0);
	if(!ip)
		return(0);
	shp->nvfun.last = (char*)shp;
	shp->nvfun.nofree = 1;
	ip->sh = shp;
	shp->var_base = shp->var_tree = inittree(shp,shtab_variables);
	SHLVL->nvalue.ip = &shlvl;
	ip->IFS_init.hdr.disc = &IFS_disc;
	ip->PATH_init.disc = &RESTRICTED_disc;
	ip->PATH_init.nofree = 1;
	ip->FPATH_init.disc = &RESTRICTED_disc;
	ip->FPATH_init.nofree = 1;
	ip->CDPATH_init.disc = &CDPATH_disc;
	ip->CDPATH_init.nofree = 1;
	ip->SHELL_init.disc = &RESTRICTED_disc;
	ip->SHELL_init.nofree = 1;
	ip->ENV_init.disc = &RESTRICTED_disc;
	ip->ENV_init.nofree = 1;
	ip->VISUAL_init.disc = &EDITOR_disc;
	ip->VISUAL_init.nofree = 1;
	ip->EDITOR_init.disc = &EDITOR_disc;
	ip->EDITOR_init.nofree = 1;
	ip->HISTFILE_init.disc = &HISTFILE_disc;
	ip->HISTFILE_init.nofree = 1;
	ip->HISTSIZE_init.disc = &HISTFILE_disc;
	ip->HISTSIZE_init.nofree = 1;
	ip->OPTINDEX_init.disc = &OPTINDEX_disc;
	ip->OPTINDEX_init.nofree = 1;
	ip->SECONDS_init.hdr.disc = &SECONDS_disc;
	ip->SECONDS_init.hdr.nofree = 1;
	ip->RAND_init.hdr.disc = &RAND_disc;
	ip->RAND_init.hdr.nofree = 1;
	ip->RAND_init.sh = shp;
	ip->SH_MATCH_init.hdr.disc = &SH_MATCH_disc;
	ip->SH_MATCH_init.hdr.nofree = 1;
	ip->SH_MATH_init.disc = &SH_MATH_disc;
	ip->SH_MATH_init.nofree = 1;
#if SHOPT_COSHELL
	ip->SH_JOBPOOL_init.disc = &SH_JOBPOOL_disc;
	ip->SH_JOBPOOL_init.nofree = 1;
	nv_stack(SH_JOBPOOL, &ip->SH_JOBPOOL_init);
#endif /* SHOPT_COSHELL */
	ip->SH_VERSION_init.disc = &SH_VERSION_disc;
	ip->SH_VERSION_init.nofree = 1;
	ip->LINENO_init.disc = &LINENO_disc;
	ip->LINENO_init.nofree = 1;
	ip->L_ARG_init.disc = &L_ARG_disc;
	ip->L_ARG_init.nofree = 1;
#ifdef _hdr_locale
	ip->LC_TYPE_init.disc = &LC_disc;
	ip->LC_TYPE_init.nofree = 1;
	ip->LC_NUM_init.disc = &LC_disc;
	ip->LC_NUM_init.nofree = 1;
	ip->LC_COLL_init.disc = &LC_disc;
	ip->LC_COLL_init.nofree = 1;
	ip->LC_MSG_init.disc = &LC_disc;
	ip->LC_MSG_init.nofree = 1;
	ip->LC_ALL_init.disc = &LC_disc;
	ip->LC_ALL_init.nofree = 1;
	ip->LANG_init.disc = &LC_disc;
	ip->LANG_init.nofree = 1;
#endif /* _hdr_locale */
	nv_stack(IFSNOD, &ip->IFS_init.hdr);
	ip->IFS_init.hdr.nofree = 1;
	nv_stack(PATHNOD, &ip->PATH_init);
	nv_stack(FPATHNOD, &ip->FPATH_init);
	nv_stack(CDPNOD, &ip->CDPATH_init);
	nv_stack(SHELLNOD, &ip->SHELL_init);
	nv_stack(ENVNOD, &ip->ENV_init);
	nv_stack(VISINOD, &ip->VISUAL_init);
	nv_stack(EDITNOD, &ip->EDITOR_init);
	nv_stack(HISTFILE, &ip->HISTFILE_init);
	nv_stack(HISTSIZE, &ip->HISTSIZE_init);
	nv_stack(OPTINDNOD, &ip->OPTINDEX_init);
	nv_stack(SECONDS, &ip->SECONDS_init.hdr);
	nv_stack(L_ARGNOD, &ip->L_ARG_init);
	nv_putval(SECONDS, (char*)&d, NV_DOUBLE);
	nv_stack(RANDNOD, &ip->RAND_init.hdr);
	d = (shp->gd->pid&RANDMASK);
	nv_putval(RANDNOD, (char*)&d, NV_DOUBLE);
	nv_stack(LINENO, &ip->LINENO_init);
	SH_MATCHNOD->nvfun =  &ip->SH_MATCH_init.hdr;
	nv_putsub(SH_MATCHNOD,(char*)0,10);
	nv_stack(SH_MATHNOD, &ip->SH_MATH_init);
	nv_stack(SH_VERSIONNOD, &ip->SH_VERSION_init);
#ifdef _hdr_locale
	nv_stack(LCTYPENOD, &ip->LC_TYPE_init);
	nv_stack(LCALLNOD, &ip->LC_ALL_init);
	nv_stack(LCMSGNOD, &ip->LC_MSG_init);
	nv_stack(LCCOLLNOD, &ip->LC_COLL_init);
	nv_stack(LCNUMNOD, &ip->LC_NUM_init);
	nv_stack(LANGNOD, &ip->LANG_init);
#endif /* _hdr_locale */
	(PPIDNOD)->nvalue.lp = (&shp->gd->ppid);
	(TMOUTNOD)->nvalue.lp = (&shp->st.tmout);
	(MCHKNOD)->nvalue.lp = (&sh_mailchk);
	(OPTINDNOD)->nvalue.lp = (&shp->st.optindex);
	/* set up the seconds clock */
	shp->alias_tree = inittree(shp,shtab_aliases);
	shp->track_tree = dtopen(&_Nvdisc,Dtset);
	shp->bltin_tree = inittree(shp,(const struct shtable2*)shtab_builtins);
	shp->fun_tree = dtopen(&_Nvdisc,Dtoset);
	dtview(shp->fun_tree,shp->bltin_tree);
	nv_mount(DOTSHNOD, "type", shp->typedict=dtopen(&_Nvdisc,Dtoset));
	nv_adddisc(DOTSHNOD, shdiscnames, (Namval_t**)0);
	DOTSHNOD->nvalue.cp = Empty;
	nv_onattr(DOTSHNOD,NV_RDONLY);
	SH_LINENO->nvalue.ip = &shp->st.lineno;
	VERSIONNOD->nvalue.nrp = newof(0,struct Namref,1,0);
        VERSIONNOD->nvalue.nrp->np = SH_VERSIONNOD;
        VERSIONNOD->nvalue.nrp->root = nv_dict(DOTSHNOD);
        VERSIONNOD->nvalue.nrp->table = DOTSHNOD;
	nv_onattr(VERSIONNOD,NV_REF);
	math_init(shp);
	if(!shgd->stats)
		stat_init(shp);
	return(ip);
}

/*
 * initialize name-value pairs
 */

static Dt_t *inittree(Shell_t *shp,const struct shtable2 *name_vals)
{
	register Namval_t *np;
	register const struct shtable2 *tp;
	register unsigned n = 0;
	register Dt_t *treep;
	Dt_t *base_treep, *dict;
	for(tp=name_vals;*tp->sh_name;tp++)
		n++;
	np = (Namval_t*)calloc(n,sizeof(Namval_t));
	if(!shgd->bltin_nodes)
	{
		shgd->bltin_nodes = np;
		shgd->bltin_nnodes = n;
	}
	else if(name_vals==(const struct shtable2*)shtab_builtins)
	{
		shgd->bltin_cmds = np;
		nbltins = n;
	}
	base_treep = treep = dtopen(&_Nvdisc,Dtoset);
	treep->user = (void*)shp;
	for(tp=name_vals;*tp->sh_name;tp++,np++)
	{
		if((np->nvname = strrchr(tp->sh_name,'.')) && np->nvname!=((char*)tp->sh_name))
			np->nvname++;
		else
		{
			np->nvname = (char*)tp->sh_name;
			treep = base_treep;
		}
		np->nvenv = 0;
		if(name_vals==(const struct shtable2*)shtab_builtins)
			np->nvalue.bfp = (Nambfp_f)((struct shtable3*)tp)->sh_value;
		else
		{
			if(name_vals == shtab_variables)
				np->nvfun = &shp->nvfun;
			np->nvalue.cp = (char*)tp->sh_value;
		}
		nv_setattr(np,tp->sh_number);
		if(nv_isattr(np,NV_TABLE))
			nv_mount(np,(const char*)0,dict=dtopen(&_Nvdisc,Dtoset));
		if(nv_isattr(np,NV_INTEGER))
			nv_setsize(np,10);
		else
			nv_setsize(np,0);
		dtinsert(treep,np);
		if(nv_istable(np))
			treep = dict;
	}
	return(treep);
}

/*
 * read in the process environment and set up name-value pairs
 * skip over items that are not name-value pairs
 */

static void env_init(Shell_t *shp)
{
	register char		*cp;
	register Namval_t	*np,*mp;
	register char		**ep=environ;
	char			*dp,*next=0;
	int			nenv=0,k=0,size=0;
	Namval_t		*np0;
#ifdef _ENV_H
	shp->env = env_open(environ,3);
	env_delete(shp->env,"_");
#endif
	if(!ep)
		goto skip;
	while(*ep++)
		nenv++;
	np = newof(0,Namval_t,nenv,0);
	for(np0=np,ep=environ;cp= *ep; ep++)
	{
		dp = strchr(cp,'=');
		if(!dp)
			continue;
		*dp++ = 0;
		if(mp = dtmatch(shp->var_base,cp))
		{
                        if(strcmp(cp,VERSIONNOD->nvname)==0)
                        {
                                dp[-1] = '=';
                                continue;
                        }
			mp->nvenv = (char*)cp;
			dp[-1] = '=';
		}
		else if(*cp=='A' && cp[1]=='_' && cp[2]=='_' && cp[3]=='z' && cp[4]==0)
		{
			dp[-1] = '=';
			next = cp+4;
			continue;
		}
		else
		{
			k++;
			mp = np++;
			mp->nvname = cp;
			size += strlen(cp);
		}
			nv_onattr(mp,NV_IMPORT);
		if(mp->nvfun || nv_isattr(mp,NV_INTEGER))
			nv_putval(mp,dp,0);
		else
		{
			mp->nvalue.cp = dp;
			nv_onattr(mp,NV_NOFREE);
		}
		nv_onattr(mp,NV_EXPORT|NV_IMPORT);
	}
	np =  (Namval_t*)realloc((void*)np0,k*sizeof(Namval_t));
	dp = (char*)malloc(size+k);
	while(k-->0)
	{
		size = strlen(np->nvname);
		memcpy(dp,np->nvname,size+1);
		np->nvname[size] = '=';
		np->nvenv = np->nvname;
		np->nvname = dp;
		dp += size+1;
		dtinsert(shp->var_base,np++);
	}
	while(cp=next)
	{
		if(next = strchr(++cp,'='))
			*next = 0;
		np = nv_search(cp+2,shp->var_tree,NV_ADD);
		if(np!=SHLVL && nv_isattr(np,NV_IMPORT|NV_EXPORT))
		{
			int flag = *(unsigned char*)cp-' ';
			int size = *(unsigned char*)(cp+1)-' ';
			if((flag&NV_INTEGER) && size==0)
			{
				/* check for floating*/
				char *val = nv_getval(np);
				strtol(val,&dp,10);
				if(*dp=='.' || *dp=='e' || *dp=='E')
				{
					char *lp;
					flag |= NV_DOUBLE;
					if(*dp=='.')
					{
						strtol(dp+1,&lp,10);
						if(*lp)
							dp = lp;
					}
					if(*dp && *dp!='.')
					{
						flag |= NV_EXPNOTE;
						size = dp-val;
					}
					else
						size = strlen(dp);
					size--;
				}
			}
			nv_newattr(np,flag|NV_IMPORT|NV_EXPORT,size);
			if((flag&(NV_INTEGER|NV_UTOL|NV_LTOU))==(NV_UTOL|NV_LTOU))
				nv_mapchar(np,(flag&NV_UTOL)?e_tolower:e_toupper);
		}
		else
			cp += 2;
	}
skip:
#ifdef _ENV_H
	env_delete(shp->env,e_envmarker);
#endif
	if(nv_isnull(PWDNOD) || nv_isattr(PWDNOD,NV_TAGGED))
	{
		nv_offattr(PWDNOD,NV_TAGGED);
		path_pwd(shp,0);
	}
	if((cp = nv_getval(SHELLNOD)) && (sh_type(cp)&SH_TYPE_RESTRICTED))
		sh_onoption(SH_RESTRICTED); /* restricted shell */
	return;
}

/*
 * terminate shell and free up the space
 */
int sh_term(void)
{
	sfdisc(sfstdin,SF_POPDISC);
	free((char*)sh.outbuff);
	stakset(NIL(char*),0);
	return(0);
}

/* function versions of these */

#define DISABLE	/* proto workaround */

unsigned long sh_isoption DISABLE (int opt)
{
	return(sh_isoption(opt));
}

unsigned long sh_onoption DISABLE (int opt)
{
	return(sh_onoption(opt));
}

unsigned long sh_offoption DISABLE (int opt)
{
	return(sh_offoption(opt));
}

void	sh_sigcheck DISABLE (Shell_t *shp)
{
	if(!shp)
		shp = sh_getinterp();
	sh_sigcheck(shp);
}

Dt_t*	sh_bltin_tree DISABLE (void)
{
	return(sh.bltin_tree);
}

/*
 * This code is for character mapped variables with wctrans()
 */
struct Mapchar
{
	Namfun_t	hdr;
	const char	*name;
	wctrans_t	trans;
	int		lctype;
};

static void put_trans(register Namval_t* np,const char *val,int flags,Namfun_t *fp)
{
	struct Mapchar *mp = (struct Mapchar*)fp;
	int	c,offset = staktell(),off=offset;
	if(val)
	{
		if(mp->lctype!=lctype)
		{
			mp->lctype = lctype;
			mp->trans = wctrans(mp->name);	
		}
		if(!mp->trans || (flags&NV_INTEGER))
			goto skip;
		while(c = mbchar(val))
		{
			c = towctrans(c,mp->trans);
			stakseek(off+c);
			stakseek(off);
			c  = mbconv(stakptr(off),c);
			off += c;
			stakseek(off);
		}
		stakputc(0);
		val = stakptr(offset);
	}
	else
	{
		nv_putv(np,val,flags,fp);
		nv_disc(np,fp,NV_POP);
		if(!(fp->nofree&1))
			free((void*)fp);
		stakseek(offset);
		return;
	}
skip:
	nv_putv(np,val,flags,fp);
	stakseek(offset);
}

static const Namdisc_t TRANS_disc      = {  sizeof(struct Mapchar), put_trans };

Namfun_t	*nv_mapchar(Namval_t *np,const char *name)
{
	wctrans_t	trans = name?wctrans(name):0;
	struct Mapchar	*mp=0;
	int		n=0,low;
	if(np)
		mp = (struct Mapchar*)nv_hasdisc(np,&TRANS_disc);
	if(!name)
		return(mp?(Namfun_t*)mp->name:0);
	if(!trans)
		return(0);
	if(!np)
		return(((Namfun_t*)0)+1);
	if((low=strcmp(name,e_tolower)) && strcmp(name,e_toupper))
		n += strlen(name)+1;
	if(mp)
	{
		if(strcmp(name,mp->name)==0)
			return(&mp->hdr);
		nv_disc(np,&mp->hdr,NV_POP);
		if(!(mp->hdr.nofree&1))
			free((void*)mp);
	}
	mp = newof(0,struct Mapchar,1,n);
	mp->trans = trans;
	mp->lctype = lctype;
	if(low==0)
		mp->name = e_tolower;
	else if(n==0)
		mp->name = e_toupper;
	else
	{
		mp->name = (char*)(mp+1);
		strcpy((char*)mp->name,name);
	}
	mp->hdr.disc =  &TRANS_disc;
	return(&mp->hdr);
}
