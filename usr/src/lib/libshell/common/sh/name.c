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
 * AT&T Labs
 *
 */

#define putenv	___putenv

#include	"defs.h"
#include	"variables.h"
#include	"path.h"
#include	"lexstates.h"
#include	"timeout.h"
#include	"FEATURE/externs"
#include	"streval.h"

#define NVCACHE		8	/* must be a power of 2 */
#define Empty	((char*)(e_sptbnl+3))
static char	*savesub = 0;

#if !_lib_pathnative && _lib_uwin_path

#define _lib_pathnative		1

extern int	uwin_path(const char*, char*, int);

size_t
pathnative(const char* path, char* buf, size_t siz)
{
	return uwin_path(path, buf, siz);
}

#endif /* _lib_pathnative */

static void	attstore(Namval_t*,void*);
#ifndef _ENV_H
    static void	pushnam(Namval_t*,void*);
    static char	*staknam(Namval_t*, char*);
#endif
static void	ltou(char*);
static void	utol(char*);
static void	rightjust(char*, int, int);
static char	*lastdot(char*, int);

struct adata
{
	Shell_t		*sh;
	Namval_t	*tp;
	char		**argnam;
	int		attsize;
	char		*attval;
};

#if SHOPT_TYPEDEF
    struct sh_type
    {
	void		*previous;
	Namval_t	**nodes;
	Namval_t	*rp;
	short		numnodes;
	short		maxnodes;
    };
#endif /*SHOPT_TYPEDEF */

#if NVCACHE
    struct Namcache
    {
	struct Cache_entry
	{
		Dt_t		*root;
		Dt_t		*last_root;
		char		*name;
		Namval_t	*np;
		Namval_t	*last_table;
		int		flags;
		short		size;
		short		len;
	} entries[NVCACHE];
	short		index;
	short		ok;
    };
    static struct Namcache nvcache;
#endif

char		nv_local = 0;
#ifndef _ENV_H
static void(*nullscan)(Namval_t*,void*);
#endif

#if ( SFIO_VERSION  <= 20010201L )
#   define _data        data
#endif

#if !SHOPT_MULTIBYTE
#   define mbchar(p)       (*(unsigned char*)p++)
#endif /* SHOPT_MULTIBYTE */

/* ========	name value pair routines	======== */

#include	"shnodes.h"
#include	"builtins.h"

static char *getbuf(size_t len)
{
	static char *buf;
	static size_t buflen;
	if(buflen < len)
	{
		if(buflen==0)
			buf = (char*)malloc(len);
		else
			buf = (char*)realloc(buf,len);
		buflen = len;
	}
	return(buf);
}

#ifdef _ENV_H
void sh_envput(Env_t* ep,Namval_t *np)
{
	int offset = staktell();
	Namarr_t *ap = nv_arrayptr(np);
	char *val;
	if(ap)
	{
		if(ap->nelem&ARRAY_UNDEF)
			nv_putsub(np,"0",0L);
		else if(!(val=nv_getsub(np)) || strcmp(val,"0"))
			return;
	}
	if(!(val = nv_getval(np)))
		return;
	stakputs(nv_name(np));
	stakputc('=');
	stakputs(val);
	stakseek(offset);
	env_add(ep,stakptr(offset),ENV_STRDUP);
}
#endif

/*
 * output variable name in format for re-input
 */
void nv_outname(Sfio_t *out, char *name, int len)
{
	const char *cp=name, *sp;
	int c, offset = staktell();
	while(sp= strchr(cp,'['))
	{
		if(len>0 && cp+len <= sp)
			break;
		sfwrite(out,cp,++sp-cp);
		stakseek(offset);
		while(c= *sp++)
		{
			if(c==']')
				break;
			else if(c=='\\')
			{
				if(*sp=='[' || *sp==']' || *sp=='\\')
					c = *sp++;
			}
			stakputc(c);
		}
		stakputc(0);
		sfputr(out,sh_fmtq(stakptr(offset)),-1);
		if(len>0)
		{
			sfputc(out,']');
			return;
		}
		cp = sp-1;
	}
	if(*cp)
	{
		if(len>0)
			sfwrite(out,cp,len);
		else
			sfputr(out,cp,-1);
	}
	stakseek(offset);
}

#if SHOPT_TYPEDEF
Namval_t *nv_addnode(Namval_t* np, int remove)
{
	register struct sh_type	*sp = (struct sh_type*)sh.mktype;
	register int		i;
	register char		*name=0;
	if(sp->numnodes==0 && !nv_isnull(np) && sh.last_table)
	{
		/* could be an redefine */
		Dt_t *root = nv_dict(sh.last_table);
		sp->rp = np;
		nv_delete(np,root,NV_NOFREE);
		np = nv_search(sp->rp->nvname,root,NV_ADD);
	}
	if(sp->numnodes && memcmp(np->nvname,NV_CLASS,sizeof(NV_CLASS)-1))
	{
		name = (sp->nodes[0])->nvname;
		i = strlen(name);
		if(memcmp(np->nvname,name,i))
			return(np);
	}
	if(sp->rp && sp->numnodes)
	{
		/* check for a redefine */
		if(name && np->nvname[i]=='.' && np->nvname[i+1]=='_' && np->nvname[i+2]==0)
			sp->rp = 0;
		else
		{
			Dt_t *root = nv_dict(sh.last_table);
			nv_delete(sp->nodes[0],root,NV_NOFREE);
			dtinsert(root,sp->rp);
			errormsg(SH_DICT,ERROR_exit(1),e_redef,sp->nodes[0]->nvname);
		}
	}
	for(i=0; i < sp->numnodes; i++)
	{
		if(np == sp->nodes[i])
		{
			if(remove)
			{
				while(++i < sp->numnodes)
					sp->nodes[i-1] = sp->nodes[i];
				sp->numnodes--;
			}
			return(np);
		}
	}
	if(remove)
		return(np);
	if(sp->numnodes==sp->maxnodes)
	{
		sp->maxnodes += 20;
		sp->nodes = (Namval_t**)realloc(sp->nodes,sizeof(Namval_t*)*sp->maxnodes);
	}
	sp->nodes[sp->numnodes++] = np;
	return(np);
}
#endif /* SHOPT_TYPEDEF */

/*
 * given a list of assignments, determine <name> is on the list
   returns a pointer to the argnod on the list or NULL
 */
struct argnod *nv_onlist(struct argnod *arg, const char *name)
{
	char *cp;
	int len = strlen(name);
	for(;arg; arg=arg->argnxt.ap)
	{
		if(*arg->argval==0 && arg->argchn.ap && !(arg->argflag&~(ARG_APPEND|ARG_QUOTED|ARG_MESSAGE))) 
			cp = ((struct fornod*)arg->argchn.ap)->fornam;
		else
			cp = arg->argval;
		if(memcmp(cp,name,len)==0 && (cp[len]==0 || cp[len]=='='))
			return(arg);
	}
	return(0);
}

/*
 * Perform parameter assignment for a linked list of parameters
 * <flags> contains attributes for the parameters
 */
void nv_setlist(register struct argnod *arg,register int flags, Namval_t *typ)
{
	Shell_t		*shp = &sh;
	register char	*cp;
	register Namval_t *np, *mp;
	char		*trap=shp->st.trap[SH_DEBUGTRAP];
	char		*prefix = shp->prefix;
	int		traceon = (sh_isoption(SH_XTRACE)!=0);
	int		array = (flags&(NV_ARRAY|NV_IARRAY));
	Namarr_t	*ap;
	Namval_t	node;
	struct Namref	nr;
#if SHOPT_TYPEDEF
	int		maketype = flags&NV_TYPE;
	struct sh_type	shtp;
	if(maketype)
	{
		shtp.previous = shp->mktype;
		shp->mktype=(void*)&shtp;
		shtp.numnodes=0;
		shtp.maxnodes = 20;
		shtp.rp = 0;
		shtp.nodes =(Namval_t**)malloc(shtp.maxnodes*sizeof(Namval_t*));
	}
#endif /* SHOPT_TYPEDEF*/
	flags &= ~(NV_TYPE|NV_ARRAY|NV_IARRAY);
	if(sh_isoption(SH_ALLEXPORT))
		flags |= NV_EXPORT;
	if(shp->prefix)
	{
		flags &= ~(NV_IDENT|NV_EXPORT);
		flags |= NV_VARNAME;
	}
	for(;arg; arg=arg->argnxt.ap)
	{
		shp->used_pos = 0;
		if(arg->argflag&ARG_MAC)
		{
			shp->prefix = 0;
			cp = sh_mactrim(shp,arg->argval,(flags&NV_NOREF)?-3:-1);
			shp->prefix = prefix;
		}
		else
		{
			stakseek(0);
			if(*arg->argval==0 && arg->argchn.ap && !(arg->argflag&~(ARG_APPEND|ARG_QUOTED|ARG_MESSAGE)))
			{
				int flag = (NV_VARNAME|NV_ARRAY|NV_ASSIGN);
				int sub=0;
				struct fornod *fp=(struct fornod*)arg->argchn.ap;
				register Shnode_t *tp=fp->fortre;
				flag |= (flags&(NV_NOSCOPE|NV_STATIC));
				if(arg->argflag&ARG_QUOTED)
					cp = sh_mactrim(shp,fp->fornam,-1);
				else
					cp = fp->fornam;
				error_info.line = fp->fortyp-shp->st.firstline;
				if(!array && tp->tre.tretyp!=TLST && tp->com.comset && !tp->com.comarg && tp->com.comset->argval[0]==0 && tp->com.comset->argval[1]=='[')
					array |= (tp->com.comset->argflag&ARG_MESSAGE)?NV_IARRAY:NV_ARRAY;
				if(shp->fn_depth && (Namval_t*)tp->com.comnamp==SYSTYPESET)
			                flag |= NV_NOSCOPE;
				if(prefix && tp->com.comset && *cp=='[')
				{
					shp->prefix = 0;
					np = nv_open(prefix,shp->var_tree,flag);
					shp->prefix = prefix;
					if(np)
					{
						if(nv_isvtree(np) && !nv_isarray(np))
						{
							stakputc('.');
							stakputs(cp);
							cp = stakfreeze(1);
						}
						nv_close(np);
					}
				}
				np = nv_open(cp,shp->var_tree,flag|NV_ASSIGN);
				if(typ && !array  && (nv_isnull(np) || nv_isarray(np)))
					nv_settype(np,typ,0);
				if((flags&NV_STATIC) && !nv_isnull(np))
#if SHOPT_TYPEDEF
					goto check_type;
#else
					continue;
#endif /* SHOPT_TYPEDEF */
				if(array && (!(ap=nv_arrayptr(np)) || !ap->hdr.type))
				{
					if(!(arg->argflag&ARG_APPEND))
						nv_unset(np);
					if(array&NV_ARRAY)
					{
						nv_setarray(np,nv_associative);
					}
					else
					{
						nv_onattr(np,NV_ARRAY);
					}
				}
				if(array && tp->tre.tretyp!=TLST && !tp->com.comset && !tp->com.comarg)
				{
#if SHOPT_TYPEDEF
						goto check_type;
#else
						continue;
#endif /* SHOPT_TYPEDEF */
				}
				/* check for array assignment */
				if(tp->tre.tretyp!=TLST && tp->com.comarg && !tp->com.comset && !((mp=tp->com.comnamp) && nv_isattr(mp,BLT_DCL)))
				{
					int argc;
					Dt_t	*last_root = shp->last_root;
					char **argv = sh_argbuild(shp,&argc,&tp->com,0);
					shp->last_root = last_root;
#if SHOPT_TYPEDEF
					if(shp->mktype && shp->dot_depth==0 && np==((struct sh_type*)shp->mktype)->nodes[0])
					{
						shp->mktype = 0;
						errormsg(SH_DICT,ERROR_exit(1),"%s: not a known type name",argv[0]);
					}
#endif /* SHOPT_TYPEDEF */
					if(!(arg->argflag&ARG_APPEND))
					{
						if(!nv_isarray(np) || ((ap=nv_arrayptr(np)) && (ap->nelem&ARRAY_MASK)))
							nv_unset(np);
					}
					nv_setvec(np,(arg->argflag&ARG_APPEND),argc,argv);
					if(traceon || trap)
					{
						int n = -1;
						char *name = nv_name(np);
						if(arg->argflag&ARG_APPEND)
							n = '+';
						if(trap)
							sh_debug(shp,trap,name,(char*)0,argv,(arg->argflag&ARG_APPEND)|ARG_ASSIGN);
						if(traceon)
						{
							sh_trace(NIL(char**),0);
							sfputr(sfstderr,name,n);
							sfwrite(sfstderr,"=( ",3);
							while(cp= *argv++)
								sfputr(sfstderr,sh_fmtq(cp),' ');
							sfwrite(sfstderr,")\n",2);
						}
					}
#if SHOPT_TYPEDEF
					goto check_type;
#else
					continue;
#endif /* SHOPT_TYPEDEF */
				}
				if((tp->tre.tretyp&COMMSK)==TFUN)
					goto skip;
				if(tp->tre.tretyp==TLST || !tp->com.comset || tp->com.comset->argval[0]!='[')
				{
					if(tp->tre.tretyp!=TLST && !tp->com.comnamp && tp->com.comset && tp->com.comset->argval[0]==0 && tp->com.comset->argchn.ap)
					{
						if(prefix)
							cp = stakcopy(nv_name(np));
						shp->prefix = cp;
						if(tp->com.comset->argval[1]=='[')
						{
							if((arg->argflag&ARG_APPEND) && (!nv_isarray(np) || (nv_aindex(np)>=0)))
								nv_unset(np);
							if(!(array&NV_IARRAY) && !(tp->com.comset->argflag&ARG_MESSAGE))
								nv_setarray(np,nv_associative);
						}
						nv_setlist(tp->com.comset,flags,0);
						shp->prefix = prefix;
						if(tp->com.comset->argval[1]!='[')
							 nv_setvtree(np);
						nv_close(np);
#if SHOPT_TYPEDEF
						goto check_type;
#else
						continue;
#endif /* SHOPT_TYPEDEF */
					}
					if(*cp!='.' && *cp!='[' && strchr(cp,'['))
					{
						nv_close(np);
						np = nv_open(cp,shp->var_tree,flag);
					}
					if(arg->argflag&ARG_APPEND)
					{
						if(nv_isarray(np))
						{
							if((sub=nv_aimax(np)) < 0  && nv_arrayptr(np))
								errormsg(SH_DICT,ERROR_exit(1),e_badappend,nv_name(np));
							if(sub>=0)
								sub++;
						}
						if(!nv_isnull(np) && np->nvalue.cp!=Empty && !nv_isvtree(np))
							sub=1;
					}
					else if(np->nvalue.cp && np->nvalue.cp!=Empty && !nv_type(np))
					{
						_nv_unset(np,NV_EXPORT);
					}
				}
				else
				{
					if(!(arg->argflag&ARG_APPEND))
						_nv_unset(np,NV_EXPORT);
					if(!sh_isoption(SH_BASH) && !(array&NV_IARRAY) && !nv_isarray(np))
						nv_setarray(np,nv_associative);
				}
			skip:
				if(sub>0)
				{
					sfprintf(stkstd,"%s[%d]",prefix?nv_name(np):cp,sub);
					shp->prefix = stakfreeze(1);
					nv_putsub(np,(char*)0,ARRAY_ADD|ARRAY_FILL|sub);
				}
				else if(prefix)
					shp->prefix = stakcopy(nv_name(np));
				else
					shp->prefix = cp;
				shp->last_table = 0;
				if(shp->prefix)
				{
					if(*shp->prefix=='_' && shp->prefix[1]=='.' && nv_isref(L_ARGNOD))
					{
						sfprintf(stkstd,"%s%s",nv_name(L_ARGNOD->nvalue.nrp->np),shp->prefix+1);
						shp->prefix = stkfreeze(stkstd,1);
					}
					memset(&nr,0,sizeof(nr));
					memcpy(&node,L_ARGNOD,sizeof(node));
					L_ARGNOD->nvalue.nrp = &nr;
					nr.np = np;
					nr.root = shp->last_root;
					nr.table = shp->last_table;
					L_ARGNOD->nvflag = NV_REF|NV_NOFREE;
					L_ARGNOD->nvfun = 0;
				}
				sh_exec(tp,sh_isstate(SH_ERREXIT));
#if SHOPT_TYPEDEF
				if(shp->prefix)
#endif
				{
					L_ARGNOD->nvalue.nrp = node.nvalue.nrp;
					L_ARGNOD->nvflag = node.nvflag;
					L_ARGNOD->nvfun = node.nvfun;
				}
				shp->prefix = prefix;
				if(nv_isarray(np) && (mp=nv_opensub(np)))
					np = mp;
				while(tp->tre.tretyp==TLST)
				{
					if(!tp->lst.lstlef || !tp->lst.lstlef->tre.tretyp==TCOM || tp->lst.lstlef->com.comarg || tp->lst.lstlef->com.comset && tp->lst.lstlef->com.comset->argval[0]!='[')
						break;
					tp = tp->lst.lstrit;

				}
				if(!nv_isarray(np) && !typ && (tp->com.comarg || !tp->com.comset || tp->com.comset->argval[0]!='['))
				{
					nv_setvtree(np);
					if(tp->com.comarg || tp->com.comset)
						np->nvfun->dsize = 0;
				}
#if SHOPT_TYPEDEF
				goto check_type;
#else
				continue;
#endif /* SHOPT_TYPEDEF */
			}
			cp = arg->argval;
			mp = 0;
		}
		np = nv_open(cp,shp->var_tree,flags);
		if(!np->nvfun && (flags&NV_NOREF))
		{
			if(shp->used_pos)
				nv_onattr(np,NV_PARAM);
			else
				nv_offattr(np,NV_PARAM);
		}
		if(traceon || trap)
		{
			register char *sp=cp;
			char *name=nv_name(np);
			char *sub=0;
			int append = 0;
			if(nv_isarray(np))
				sub = savesub;
			if(cp=lastdot(sp,'='))
			{
				if(cp[-1]=='+')
					append = ARG_APPEND;
				cp++;
			}
			if(traceon)
			{
				sh_trace(NIL(char**),0);
				nv_outname(sfstderr,name,-1);
				if(sub)
					sfprintf(sfstderr,"[%s]",sh_fmtq(sub));
				if(cp)
				{
					if(append)
						sfputc(sfstderr,'+');
					sfprintf(sfstderr,"=%s\n",sh_fmtq(cp));
				}
			}
			if(trap)
			{
					char *av[2];
					av[0] = cp;
					av[1] = 0;
					sh_debug(shp,trap,name,sub,av,append);
			}
		}
#if SHOPT_TYPEDEF
	check_type:
		if(maketype)
		{
			nv_open(shtp.nodes[0]->nvname,shp->var_tree,NV_ASSIGN|NV_VARNAME|NV_NOADD|NV_NOFAIL);
			np = nv_mktype(shtp.nodes,shtp.numnodes);
			free((void*)shtp.nodes);
			shp->mktype = shtp.previous;
			maketype = 0;
			shp->prefix = 0;
			if(nr.np == np)
			{
				L_ARGNOD->nvalue.nrp = node.nvalue.nrp;
				L_ARGNOD->nvflag = node.nvflag;
				L_ARGNOD->nvfun = node.nvfun;
			}
		}
#endif /* SHOPT_TYPEDEF */
	}
}

/*
 * copy the subscript onto the stack
 */
static void stak_subscript(const char *sub, int last)
{
	register int c;
	stakputc('[');
	while(c= *sub++)
	{
		if(c=='[' || c==']' || c=='\\')
			stakputc('\\');
		stakputc(c);
	}
	stakputc(last);
}

/*
 * construct a new name from a prefix and base name on the stack
 */
static char *copystack(const char *prefix, register const char *name, const char *sub)
{
	register int last=0,offset = staktell();
	if(prefix)
	{
		stakputs(prefix);
		if(*stakptr(staktell()-1)=='.')
			stakseek(staktell()-1);
		if(*name=='.' && name[1]=='[')
			last = staktell()+2;
		if(*name!='['  && *name!='.' && *name!='=' && *name!='+')
			stakputc('.');
		if(*name=='.' && (name[1]=='=' || name[1]==0))
			stakputc('.');
	}
	if(last)
	{
		stakputs(name);
		if(sh_checkid(stakptr(last),(char*)0))
			stakseek(staktell()-2);
	}
	if(sub)
		stak_subscript(sub,']');
	if(!last)
		stakputs(name);
	stakputc(0);
	return(stakptr(offset));
}

/*
 * grow this stack string <name> by <n> bytes and move from cp-1 to end
 * right by <n>.  Returns beginning of string on the stack
 */
static char *stack_extend(const char *cname, char *cp, int n)
{
	register char *name = (char*)cname;
	int offset = name - stakptr(0);
	int m = cp-name;
	stakseek(strlen(name)+n+1);
	name = stakptr(offset);
	cp =  name + m;
	m = strlen(cp)+1;
	while(m-->0)
		cp[n+m]=cp[m];
	return((char*)name);
}

Namval_t *nv_create(const char *name,  Dt_t *root, int flags, Namfun_t *dp)
{
	Shell_t			*shp = &sh;
	char			*cp=(char*)name, *sp, *xp;
	register int		c;
	register Namval_t	*np=0, *nq=0;
	Namfun_t		*fp=0;
	long			mode, add=0;
	int			copy=1,isref,top=0,noscope=(flags&NV_NOSCOPE);
	if(root==shp->var_tree)
	{
		if(dtvnext(root))
			top = 1;
		else
			flags &= ~NV_NOSCOPE;
	}
	if(!dp->disc)
		copy = dp->nofree&1;
	if(*cp=='.')
		cp++;
	while(1)
	{
		switch(c = *(unsigned char*)(sp = cp))
		{
		    case '[':
			if(flags&NV_NOARRAY)
			{
				dp->last = cp;
				return(np);
			}
			cp = nv_endsubscript((Namval_t*)0,sp,0);
			if(sp==name || sp[-1]=='.')
				c = *(sp = cp);
			goto skip;
		    case '.':
			if(flags&NV_IDENT)
				return(0);
			if(root==shp->var_tree)
				flags &= ~NV_EXPORT;
			if(!copy && !(flags&NV_NOREF))
			{
				c = sp-name;
				copy = cp-name;
				dp->nofree |= 1;
				name = copystack((const char*)0, name,(const char*)0);
				cp = (char*)name+copy;
				sp = (char*)name+c;
				c = '.';
			}
			/* FALLTHROUGH */
		skip:
		    case '+':
		    case '=':
			*sp = 0;
			/* FALLTHROUGH */
		    case 0:
			isref = 0;
			dp->last = cp;
			mode =  (c=='.' || (flags&NV_NOADD))?add:NV_ADD;
			if((flags&NV_NOSCOPE) && c!='.')
				mode |= HASH_NOSCOPE;
			np=0;
			if(top)
			{
				struct Ufunction *rp;
				if((rp=shp->st.real_fun) && !rp->sdict && (flags&NV_STATIC))
				{
					Dt_t *dp = dtview(shp->var_tree,(Dt_t*)0);
					rp->sdict = dtopen(&_Nvdisc,Dtoset);
					dtview(rp->sdict,shp->var_base);
					dtview(shp->var_tree,rp->sdict);
				}
				if(np = nv_search(name,shp->var_tree,0))
				{
					if(shp->var_tree->walk == shp->var_base)
					{
						nq = np;
						if((flags&NV_NOSCOPE) && *cp!='.')
						{
							if(mode==0)
								root = shp->var_base;
							else
							{
								nv_delete(np,(Dt_t*)0,0);
								np = 0;
							}
						}
					}
					else
					{
						root = shp->var_tree->walk;
						flags |= NV_NOSCOPE;
						noscope = 1;
					}
				}
				if(rp && rp->sdict && (flags&NV_STATIC))
				{
					root = rp->sdict;
					if(np && shp->var_tree->walk==shp->var_tree)
					{
						_nv_unset(np,0);
						nv_delete(np,shp->var_tree,0);
						np = 0;
					}
					if(!np || shp->var_tree->walk!=root)
						np =  nv_search(name,root,HASH_NOSCOPE|NV_ADD);
				}
			}
			if(np ||  (np = nv_search(name,root,mode)))
			{
				isref = nv_isref(np);
				if(top)
				{
					if(nq==np)
					{
						flags &= ~NV_NOSCOPE;
						root = shp->var_base;
					}
					else if(nq)
					{
						if(nv_isnull(np) && c!='.' && (np->nvfun=nv_cover(nq)))
							np->nvname = nq->nvname;
						flags |= NV_NOSCOPE;
					}
				}
				else if(add && nv_isnull(np) && c=='.' && cp[1]!='.')
					nv_setvtree(np);
			}
			if(c)
				*sp = c;
			top = 0;
			if(isref)
			{
				char *sub=0;
#if NVCACHE
				nvcache.ok = 0;
#endif
				if(c=='.') /* don't optimize */
					shp->argaddr = 0;
				else if((flags&NV_NOREF) && (c!='[' && *cp!='.'))
				{
					if(c && !(flags&NV_NOADD))
						nv_unref(np);
					return(np);
				}
				while(nv_isref(np) && np->nvalue.cp)
				{
					root = nv_reftree(np);
					shp->last_root = root;
					shp->last_table = nv_reftable(np);
					sub = nv_refsub(np);
					np = nv_refnode(np);
					if(sub && c!='.')
						nv_putsub(np,sub,0L);
					flags |= NV_NOSCOPE;
					noscope = 1;
				}
				if(nv_isref(np) && (c=='[' || c=='.' || !(flags&NV_ASSIGN)))
					errormsg(SH_DICT,ERROR_exit(1),e_noref,nv_name(np));
				if(sub && c==0)
					return(np);
				if(np==nq)
					flags &= ~(noscope?0:NV_NOSCOPE);
				else if(c)
				{
					c = (cp-sp);
					copy = strlen(cp=nv_name(np));
					dp->nofree |= 1;
					name = copystack(cp,sp,sub);
					sp = (char*)name + copy;
					cp = sp+c;
					c = *sp;
					if(!noscope)
						flags &= ~NV_NOSCOPE;
				}
				flags |= NV_NOREF;
				if(nv_isnull(np))
					nv_onattr(np,NV_NOFREE);
				
			}
			shp->last_root = root;
			if(*cp && cp[1]=='.')
				cp++;
			if(c=='.' && (cp[1]==0 ||  cp[1]=='=' || cp[1]=='+'))
			{
				nv_local = 1;
				return(np);
			}
			if(cp[-1]=='.')
				cp--;
			do
			{
				if(!np)
				{
					if(!nq && *sp=='[' && *cp==0 && cp[-1]==']') 
					{
						/*
						 * for backward compatibility
						 * evaluate subscript for
						 * possible side effects
						 */
						cp[-1] = 0;
						sh_arith(sp+1);
						cp[-1] = ']';
					}
					return(np);
				}
				if(c=='[' || (c=='.' && nv_isarray(np)))
				{
					char *sub=0;
					int n = 0;
					mode &= ~HASH_NOSCOPE;
					if(c=='[')
					{
#if 0
						Namarr_t *ap = nv_arrayptr(np);
						int scan = ap?(ap->nelem&ARRAY_SCAN):0;
#endif
						n = mode|nv_isarray(np);
						if(!mode && (flags&NV_ARRAY) && ((c=sp[1])=='*' || c=='@') && sp[2]==']')
						{
							/* not implemented yet */
							dp->last = cp;
							return(np);
						}
						if((n&NV_ADD)&&(flags&NV_ARRAY))
							n |= ARRAY_FILL;
						if(flags&NV_ASSIGN)
							n |= NV_ADD;
						cp = nv_endsubscript(np,sp,n|(flags&NV_ASSIGN));
#if 0
						if(scan)
							nv_putsub(np,NIL(char*),ARRAY_SCAN);
#endif
					}
					else
						cp = sp;
					if((c = *cp)=='.' || (c=='[' && nv_isarray(np)) || (n&ARRAY_FILL) || (flags&NV_ARRAY))

					{
						int m = cp-sp;
						sub = m?nv_getsub(np):0;
						if(!sub)
						{
							if(m && !(n&NV_ADD))
								return(0);
							sub = "0";
						}
						n = strlen(sub)+2;
						if(!copy)
						{
							copy = cp-name;
							dp->nofree |= 1;
							name = copystack((const char*)0, name,(const char*)0);
							cp = (char*)name+copy;
							sp = cp-m;
						}
						if(n <= m)
						{
							if(n)
							{
								memcpy(sp+1,sub,n-2);
								sp[n-1] = ']';
							}
							if(n < m)
								cp=strcpy(sp+n,cp);
						}
						else
						{
							int r = n-m;
							m = sp-name;
							name = stack_extend(name, cp-1, r);
							sp = (char*)name + m;
							*sp = '[';
							memcpy(sp+1,sub,n-2);
							sp[n-1] = ']';
							cp = sp+n;
							
						}
					}
					else if(c==0 && mode && (n=nv_aindex(np))>0)
						nv_putsub(np,(char*)0,n);
					else if(n==0 && (c==0 || (c=='[' && !nv_isarray(np))))
					{
						/* subscript must be 0*/
						cp[-1] = 0;
						n = sh_arith(sp+1);
						cp[-1] = ']';
						if(n)
							return(0);
						if(c)
							sp = cp;
					}
					dp->last = cp;
					if(nv_isarray(np) && (c=='[' || c=='.' || (flags&NV_ARRAY)))
					{
						sp = cp;
						if(!(nq = nv_opensub(np)))
						{
							Namarr_t *ap = nv_arrayptr(np);
							if(!sub && (flags&NV_NOADD))
								return(0);
							n = mode|((flags&NV_NOADD)?0:NV_ADD);
							if(!ap && (n&NV_ADD))
							{
								nv_putsub(np,sub,ARRAY_FILL);
								ap = nv_arrayptr(np);
							}
							if(n && ap && !ap->table)
								ap->table = dtopen(&_Nvdisc,Dtoset);
							if(ap && ap->table && (nq=nv_search(sub,ap->table,n)))
								nq->nvenv = (char*)np;
							if(nq && nv_isnull(nq))
								nq = nv_arraychild(np,nq,c);
						}
						if(nq)
						{
							if(c=='.' && !nv_isvtree(nq))
							{
								if(flags&NV_NOADD)
									return(0);
								nv_setvtree(nq);
							}
							np = nq;
						}
						else if(memcmp(cp,"[0]",3))
							return(nq);
						else
						{
							/* ignore [0]  */
							dp->last = cp += 3;
							c = *cp;
						}
					}
				}
				else if(nv_isarray(np))
				{
					if(c==0 && (flags&NV_MOVE))
						return(np);
					nv_putsub(np,NIL(char*),ARRAY_UNDEF);
				}
				if(c=='.' && (fp=np->nvfun))
				{
					for(; fp; fp=fp->next)
					{
						if(fp->disc && fp->disc->createf)
							break;
					}
					if(fp)
					{
						if((nq = (*fp->disc->createf)(np,cp+1,flags,fp)) == np)
						{
							add = NV_ADD;
							shp->last_table = 0;
							break;
						}
						else if(np=nq)
						{
							if((c = *(sp=cp=dp->last=fp->last))==0)
							{
								if(nv_isarray(np) && sp[-1]!=']')
									nv_putsub(np,NIL(char*),ARRAY_UNDEF);
								return(np);
							}
						}
					}
				}
			}
			while(c=='[');
			if(c!='.' || cp[1]=='.')
				return(np);
			cp++;
			break;
		    default:
			dp->last = cp;
			if((c = mbchar(cp)) && !isaletter(c))
				return(np);
			while(xp=cp, c=mbchar(cp), isaname(c));
			cp = xp;
		}
	}
	return(np);
}

/*
 * delete the node <np> from the dictionary <root> and clear from the cache
 * if <root> is NULL, only the cache is cleared
 * if flags does not contain NV_NOFREE, the node is freed
 */
void nv_delete(Namval_t* np, Dt_t *root, int flags)
{
#if NVCACHE
	register int		c;
	struct Cache_entry	*xp;
	for(c=0,xp=nvcache.entries ; c < NVCACHE; xp= &nvcache.entries[++c])
	{
		if(xp->np==np)
			xp->root = 0;
	}
#endif
	if(root)
	{
		if(dtdelete(root,np))
		{
			if(!(flags&NV_NOFREE) && ((flags&NV_FUNCTION) || !nv_subsaved(np)))
				free((void*)np);
		}
#if 0
		else
		{
			sfprintf(sfstderr,"%s not deleted\n",nv_name(np));
			sfsync(sfstderr);
		}
#endif
	}
}

/*
 * Put <arg> into associative memory.
 * If <flags> & NV_ARRAY then follow array to next subscript
 * If <flags> & NV_NOARRAY then subscript is not allowed
 * If <flags> & NV_NOSCOPE then use the current scope only
 * If <flags> & NV_ASSIGN then assignment is allowed
 * If <flags> & NV_IDENT then name must be an identifier
 * If <flags> & NV_VARNAME then name must be a valid variable name
 * If <flags> & NV_NOADD then node will not be added if not found
 * If <flags> & NV_NOREF then don't follow reference
 * If <flags> & NV_NOFAIL then don't generate an error message on failure
 * If <flags> & NV_STATIC then unset before an assignment
 * If <flags> & NV_UNJUST then unset attributes before assignment
 * SH_INIT is only set while initializing the environment
 */
Namval_t *nv_open(const char *name, Dt_t *root, int flags)
{
	Shell_t			*shp = &sh;
	register char		*cp=(char*)name;
	register int		c;
	register Namval_t	*np;
	Namfun_t		fun;
	int			append=0;
	const char		*msg = e_varname;
	char			*fname = 0;
	int			offset = staktell();
	Dt_t			*funroot;
#if NVCACHE
	struct Cache_entry	*xp;
#endif
	
	sh_stats(STAT_NVOPEN);
	memset(&fun,0,sizeof(fun));
	shp->last_table = shp->namespace;
	if(!root)
		root = shp->var_tree;
	shp->last_root = root;
	if(root==shp->fun_tree)
	{
		flags |= NV_NOREF;
		msg = e_badfun;
		if((np=shp->namespace) || strchr(name,'.'))
		{
			name = cp = copystack(np?nv_name(np):0,name,(const char*)0);
			fname = strrchr(cp,'.');
			*fname = 0;
			fun.nofree |= 1;
			flags &=  ~NV_IDENT;
			funroot = root;
			root = shp->var_tree;
		}
	}
	else if(!(flags&(NV_IDENT|NV_VARNAME|NV_ASSIGN)))
	{
		long mode = ((flags&NV_NOADD)?0:NV_ADD);
		if(flags&NV_NOSCOPE)
			mode |= HASH_SCOPE|HASH_NOSCOPE;
		np = nv_search(name,root,mode);
		if(np && !(flags&NV_REF))
		{
			while(nv_isref(np))
			{
				shp->last_table = nv_reftable(np);
				np = nv_refnode(np);
			}
		}
		return(np);
	}
	else if(shp->prefix && (flags&NV_ASSIGN))
	{
		name = cp = copystack(shp->prefix,name,(const char*)0);
		fun.nofree |= 1;
	}
	c = *(unsigned char*)cp;
	if(root==shp->alias_tree)
	{
		msg = e_aliname;
		while((c= *(unsigned char*)cp++) && (c!='=') && (c!='/') &&
			(c>=0x200 || !(c=sh_lexstates[ST_NORM][c]) || c==S_EPAT || c==S_COLON));
		if(shp->subshell && c=='=')
			root = sh_subaliastree(1);
		if(c= *--cp)
			*cp = 0;
		np = nv_search(name, root, (flags&NV_NOADD)?0:NV_ADD); 
		if(c)
			*cp = c;
		goto skip;
	}
	else if(flags&NV_IDENT)
		msg = e_ident;
	else if(c=='.')
	{
		c = *++cp;
		flags |= NV_NOREF;
		if(root==shp->var_tree)
			root = shp->var_base;
		shp->last_table = 0;
	}
	if(c= !isaletter(c))
		goto skip;
#if NVCACHE
	for(c=0,xp=nvcache.entries ; c < NVCACHE; xp= &nvcache.entries[++c])
	{
		if(xp->root!=root)
			continue;
		if(*name==*xp->name && (flags&(NV_ARRAY|NV_NOSCOPE))==xp->flags && memcmp(xp->name,name,xp->len)==0 && (name[xp->len]==0 || name[xp->len]=='=' || name[xp->len]=='+'))
		{
			sh_stats(STAT_NVHITS);
			np = xp->np;
			cp = (char*)name+xp->len;
			if(nv_isarray(np))
				 nv_putsub(np,NIL(char*),ARRAY_UNDEF);
			shp->last_table = xp->last_table;
			shp->last_root = xp->last_root;
			goto nocache;
		}
	}
	nvcache.ok = 1;
#endif
	np = nv_create(name, root, flags, &fun);
	cp = fun.last;
#if NVCACHE
	if(np && nvcache.ok && cp[-1]!=']')
	{
		xp = &nvcache.entries[nvcache.index];
		if(*cp)
		{
			char *sp = strchr(name,*cp);
			if(!sp)
				goto nocache;
			xp->len = sp-name;
		}
		else
			xp->len = strlen(name);
		c = roundof(xp->len+1,32);
		if(c > xp->size)
		{
			if(xp->size==0)
				xp->name = malloc(c);
			else
				xp->name = realloc(xp->name,c);
			xp->size = c;
		}
		memcpy(xp->name,name,xp->len);
		xp->name[xp->len] = 0;
		xp->root = root;
		xp->np = np;
		xp->last_table = shp->last_table;
		xp->last_root = shp->last_root;
		xp->flags = (flags&(NV_ARRAY|NV_NOSCOPE));
		nvcache.index = (nvcache.index+1)&(NVCACHE-1);
	}
nocache:
	nvcache.ok = 0;
#endif
	if(fname)
	{
		c = ((flags&NV_NOSCOPE)?HASH_NOSCOPE:0)|((flags&NV_NOADD)?0:NV_ADD);
		*fname = '.';
		np = nv_search(name, funroot, c);
		*fname = 0;
	}
	else
	{
		if(*cp=='.' && cp[1]=='.')
		{
			append |= NV_NODISC;
			cp+=2;
		}
		if(*cp=='+' && cp[1]=='=')
		{
			append |= NV_APPEND;
			cp++;
		}
	}
	c = *cp;
skip:
#if SHOPT_TYPEDEF
	if(np && shp->mktype)
		np = nv_addnode(np,0);
#endif /* SHOPT_TYPEDEF */
	if(c=='=' && np && (flags&NV_ASSIGN))
	{
		cp++;
		if(sh_isstate(SH_INIT))
		{
			nv_putval(np, cp, NV_RDONLY);
			if(np==PWDNOD)
				nv_onattr(np,NV_TAGGED);
		}
		else
		{
			char *sub=0, *prefix= shp->prefix;
			int isref;
			shp->prefix = 0;
			if((flags&NV_STATIC) && !shp->mktype)
			{
				if(!nv_isnull(np))
				{
					shp->prefix = prefix;
					return(np);
				}
			}
			isref = nv_isref(np);
			if(sh_isoption(SH_XTRACE) && nv_isarray(np))
				sub = nv_getsub(np);
			c = msg==e_aliname? 0: (append | (flags&NV_EXPORT)); 
			if(isref)
				nv_offattr(np,NV_REF);
			if(!append && (flags&NV_UNJUST))
			{
				nv_offattr(np,NV_LJUST|NV_RJUST|NV_ZFILL);
				np->nvsize = 0;
			}
			nv_putval(np, cp, c);
			if(isref)
			{
				if(nv_search((char*)np,shp->var_base,HASH_BUCKET))
					shp->last_root = shp->var_base;
				nv_setref(np,(Dt_t*)0,NV_VARNAME);
			}
			savesub = sub;
			shp->prefix = prefix;
		}
		nv_onattr(np, flags&NV_ATTRIBUTES);
	}
	else if(c)
	{
		if(flags&NV_NOFAIL)
			return(0);
		if(c=='.')
			msg = e_noparent;
		else if(c=='[')
			msg = e_noarray;
		errormsg(SH_DICT,ERROR_exit(1),msg,name);
	}
	if(fun.nofree&1)
		stakseek(offset);
	return(np);
}

#if SHOPT_MULTIBYTE
    static int ja_size(char*, int, int);
    static void ja_restore(void);
    static char *savep;
    static char savechars[8+1];
#endif /* SHOPT_MULTIBYTE */

/*
 * put value <string> into name-value node <np>.
 * If <np> is an array, then the element given by the
 *   current index is assigned to.
 * If <flags> contains NV_RDONLY, readonly attribute is ignored
 * If <flags> contains NV_INTEGER, string is a pointer to a number
 * If <flags> contains NV_NOFREE, previous value is freed, and <string>
 * becomes value of node and <flags> becomes attributes
 */
void nv_putval(register Namval_t *np, const char *string, int flags)
{
	register const char *sp=string;
	register union Value *up;
	register char *cp;
	register int size = 0;
	register int dot;
	int	was_local = nv_local;
	union Value u;
	if(!(flags&NV_RDONLY) && nv_isattr (np, NV_RDONLY))
		errormsg(SH_DICT,ERROR_exit(1),e_readonly, nv_name(np));
	/* The following could cause the shell to fork if assignment
	 * would cause a side effect
	 */
	sh.argaddr = 0;
	if(sh.subshell && !nv_local)
		np = sh_assignok(np,1);
	if(np->nvfun && np->nvfun->disc && !(flags&NV_NODISC) && !nv_isref(np))
	{
		/* This function contains disc */
		if(!nv_local)
		{
			nv_local=1;
			nv_putv(np,sp,flags,np->nvfun);
			if(sp && ((flags&NV_EXPORT) || nv_isattr(np,NV_EXPORT)))
				sh_envput(sh.env,np);
			return;
		}
		/* called from disc, assign the actual value */
	}
	flags &= ~NV_NODISC;
	nv_local=0;
	if(flags&(NV_NOREF|NV_NOFREE))
	{
		if(np->nvalue.cp && np->nvalue.cp!=sp && !nv_isattr(np,NV_NOFREE)) 
			free((void*)np->nvalue.cp);
		np->nvalue.cp = (char*)sp;
		nv_setattr(np,(flags&~NV_RDONLY)|NV_NOFREE);
		return;
	}
	up= &np->nvalue;
	if(nv_isattr(np,NV_INT16P) == NV_INT16)
	{
		if(!np->nvalue.up || !nv_isarray(np))
		{
			up = &u;
			up->up = &np->nvalue;
		}
	}
	else if(np->nvalue.up && nv_isarray(np) && nv_arrayptr(np))
		up = np->nvalue.up;
	if(up && up->cp==Empty)
		up->cp = 0;
	if(nv_isattr(np,NV_EXPORT))
		nv_offattr(np,NV_IMPORT);
	if(nv_isattr (np, NV_INTEGER))
	{
		if(nv_isattr(np, NV_DOUBLE) == NV_DOUBLE)
		{
			if(nv_isattr(np, NV_LONG) && sizeof(double)<sizeof(Sfdouble_t))
			{
				Sfdouble_t ld, old=0;
				if(flags&NV_INTEGER)
				{
					if(flags&NV_LONG)
						ld = *((Sfdouble_t*)sp);
					else if(flags&NV_SHORT)
						ld = *((float*)sp);
					else
						ld = *((double*)sp);
				}
				else
					ld = sh_arith(sp);
				if(!up->ldp)
					up->ldp = new_of(Sfdouble_t,0);
				else if(flags&NV_APPEND)
					old = *(up->ldp);
				*(up->ldp) = old?ld+old:ld;
			}
			else
			{
				double d,od=0;
				if(flags&NV_INTEGER)
				{
					if(flags&NV_LONG)
						d = (double)(*(Sfdouble_t*)sp);
					else if(flags&NV_SHORT)
						d = (double)(*(float*)sp);
					else
						d = *(double*)sp;
				}
				else
					d = sh_arith(sp);
				if(!up->dp)
					up->dp = new_of(double,0);
				else if(flags&NV_APPEND)
					od = *(up->dp);
				*(up->dp) = od?d+od:d;
			}
		}
		else
		{
			if(nv_isattr(np, NV_LONG) && sizeof(int32_t)<sizeof(Sflong_t))
			{
				Sflong_t ll=0,oll=0;
				if(flags&NV_INTEGER)
				{
					if((flags&NV_DOUBLE) == NV_DOUBLE)
					{
						if(flags&NV_LONG)
							ll = *((Sfdouble_t*)sp);
						else if(flags&NV_SHORT)
							ll = *((float*)sp);
						else
							ll = *((double*)sp);
					}
					else if(nv_isattr(np,NV_UNSIGN))
					{
						if(flags&NV_LONG)
							ll = *((Sfulong_t*)sp);
						else if(flags&NV_SHORT)
							ll = *((uint16_t*)sp);
						else
							ll = *((uint32_t*)sp);
					}
					else
					{
						if(flags&NV_LONG)
							ll = *((Sflong_t*)sp);
						else if(flags&NV_SHORT)
							ll = *((uint16_t*)sp);
						else
							ll = *((uint32_t*)sp);
					}
				}
				else if(sp)
					ll = (Sflong_t)sh_arith(sp);
				if(!up->llp)
					up->llp = new_of(Sflong_t,0);
				else if(flags&NV_APPEND)
					oll = *(up->llp);
				*(up->llp) = ll+oll;
			}
			else
			{
				int32_t l=0,ol=0;
				if(flags&NV_INTEGER)
				{
					if((flags&NV_DOUBLE) == NV_DOUBLE)
					{
						Sflong_t ll;
						if(flags&NV_LONG)
							ll = *((Sfdouble_t*)sp);
						else if(flags&NV_SHORT)
							ll = *((float*)sp);
						else
							ll = *((double*)sp);
						l = (int32_t)ll;
					}
					else if(nv_isattr(np,NV_UNSIGN))
					{
						if(flags&NV_LONG)
							l = *((Sfulong_t*)sp);
						else if(flags&NV_SHORT)
							l = *((uint16_t*)sp);
						else
							l = *(uint32_t*)sp;
					}
					else
					{
						if(flags&NV_LONG)
							l = *((Sflong_t*)sp);
						else if(flags&NV_SHORT)
							l = *((int16_t*)sp);
						else
							l = *(int32_t*)sp;
					}
				}
				else if(sp)
				{
					Sfdouble_t ld = sh_arith(sp);
					if(ld<0)
						l = (int32_t)ld;
					else
						l = (uint32_t)ld;
				}
				if(nv_size(np) <= 1)
					nv_setsize(np,10);
				if(nv_isattr (np, NV_SHORT))
				{
					int16_t s=0;
					if(flags&NV_APPEND)
						s = *up->sp;
					*(up->sp) = s+(int16_t)l;
					nv_onattr(np,NV_NOFREE);
				}
				else
				{
					if(!up->lp)
						up->lp = new_of(int32_t,0);
					else if(flags&NV_APPEND)	
						ol =  *(up->lp);
					*(up->lp) = l+ol;
				}
			}
		}
	}
	else
	{
		const char *tofree=0;
		int offset;
#if _lib_pathnative
		char buff[PATH_MAX];
#endif /* _lib_pathnative */
		if(flags&NV_INTEGER)
		{
			if((flags&NV_DOUBLE)==NV_DOUBLE)
			{
				if(flags&NV_LONG)
					sfprintf(sh.strbuf,"%.*Lg",LDBL_DIG,*((Sfdouble_t*)sp));
				else
					sfprintf(sh.strbuf,"%.*g",DBL_DIG,*((double*)sp));
			}
			else if(flags&NV_UNSIGN)
			{
				if(flags&NV_LONG)
					sfprintf(sh.strbuf,"%I*lu",sizeof(Sfulong_t),*((Sfulong_t*)sp));
				else
					sfprintf(sh.strbuf,"%lu",(unsigned long)((flags&NV_SHORT)?*((uint16_t*)sp):*((uint32_t*)sp)));
			}
			else
			{
				if(flags&NV_LONG)
					sfprintf(sh.strbuf,"%I*ld",sizeof(Sflong_t),*((Sflong_t*)sp));
				else
					sfprintf(sh.strbuf,"%ld",(long)((flags&NV_SHORT)?*((int16_t*)sp):*((int32_t*)sp)));
			}
			sp = sfstruse(sh.strbuf);
		}
		if(nv_isattr(np, NV_HOST|NV_INTEGER)==NV_HOST && sp)
		{
#ifdef _lib_pathnative
			/*
			 * return the host file name given the UNIX name
			 */
			pathnative(sp,buff,sizeof(buff));
			if(buff[1]==':' && buff[2]=='/')
			{
				buff[2] = '\\';
				if(*buff>='A' &&  *buff<='Z')
					*buff += 'a'-'A';
			}
			sp = buff;
#else
			;
#endif /* _lib_pathnative */
		}
		else if((nv_isattr(np, NV_RJUST|NV_ZFILL|NV_LJUST)) && sp)
		{
			for(;*sp == ' '|| *sp=='\t';sp++);
	        	if((nv_isattr(np,NV_ZFILL)) && (nv_isattr(np,NV_LJUST)))
				for(;*sp=='0';sp++);
			size = nv_size(np);
#if SHOPT_MULTIBYTE
			if(size)
				size = ja_size((char*)sp,size,nv_isattr(np,NV_RJUST|NV_ZFILL));
#endif /* SHOPT_MULTIBYTE */
		}
		if(!up->cp)
			flags &= ~NV_APPEND;
		if((flags&NV_APPEND) && !nv_isattr(np,NV_BINARY))
		{
			offset = staktell();
			stakputs(up->cp);
			stakputs(sp);
			stakputc(0);
			sp = stakptr(offset);
		}
		if(!nv_isattr(np, NV_NOFREE))
		{
			/* delay free in case <sp> points into free region */
			tofree = up->cp;
		}
		if(nv_isattr(np,NV_BINARY) && !(flags&NV_RAW))
			tofree = 0;
		if(nv_isattr(np,NV_LJUST|NV_RJUST) && nv_isattr(np,NV_LJUST|NV_RJUST)!=(NV_LJUST|NV_RJUST))
			tofree = 0;
       	 	if (sp)
		{
			dot = strlen(sp);
#if (_AST_VERSION>=20030127L)
			if(nv_isattr(np,NV_BINARY))
			{
				int oldsize = (flags&NV_APPEND)?nv_size(np):0;
				if(flags&NV_RAW)
				{
					if(tofree)
					{
						free((void*)tofree);
						nv_offattr(np,NV_NOFREE);
					}
					up->cp = sp;
					return;
				}
				size = 0;
				if(nv_isattr(np,NV_ZFILL))
					size = nv_size(np);
				if(size==0)
					size = oldsize + (3*dot/4);
				cp = (char*)malloc(size+1);
				nv_offattr(np,NV_NOFREE);
				if(oldsize)
					memcpy((void*)cp,(void*)up->cp,oldsize);
				up->cp = cp;
				if(size <= oldsize)
					return;
				dot = base64decode(sp,dot, (void**)0, cp+oldsize, size-oldsize,(void**)0);
				dot += oldsize;
				if(!nv_isattr(np,NV_ZFILL) || nv_size(np)==0)
					nv_setsize(np,dot);
				else if(nv_isattr(np,NV_ZFILL) && (size>dot))
					memset((void*)&cp[dot],0,size-dot);
				return;
			}
			else
#endif
			if(size==0 && nv_isattr(np,NV_HOST)!=NV_HOST &&nv_isattr(np,NV_LJUST|NV_RJUST|NV_ZFILL))
				nv_setsize(np,size=dot);
			else if(size > dot)
				dot = size;
			else if(nv_isattr(np,NV_LJUST|NV_RJUST)==NV_LJUST && dot>size)
				dot = size;
			if(size==0 || tofree || !(cp=(char*)up->cp))
			{
				cp = (char*)malloc(((unsigned)dot+1));
				cp[dot] = 0;
				nv_offattr(np,NV_NOFREE);
			}
			
		}
		else
			cp = 0;
		up->cp = cp;
		if(sp)
		{
			int c = cp[dot];
			memcpy(cp,sp,dot);
			cp[dot]=0;
			if(nv_isattr(np, NV_LTOU))
				ltou(cp);
			else if(nv_isattr (np, NV_UTOL))
				utol(cp);
			cp[dot] = c;
			if(nv_isattr(np, NV_RJUST) && nv_isattr(np, NV_ZFILL))
				rightjust(cp,size,'0');
			else if(nv_isattr(np, NV_LJUST|NV_RJUST)==NV_RJUST)
				rightjust(cp,size,' ');
			else if(nv_isattr(np, NV_LJUST|NV_RJUST)==NV_LJUST)
			{
				register char *dp;
				dp = strlen (cp) + cp;
				cp = cp+size;
				for (; dp < cp; *dp++ = ' ');
			 }
#if SHOPT_MULTIBYTE
			/* restore original string */
			if(savep)
				ja_restore();
#endif /* SHOPT_MULTIBYTE */
		}
		if(flags&NV_APPEND)
			stakseek(offset);
		if(tofree && tofree!=Empty)
			free((void*)tofree);
	}
	if(!was_local && ((flags&NV_EXPORT) || nv_isattr(np,NV_EXPORT)))
		sh_envput(sh.env,np);
	return;
}

/*
 *
 *   Right-justify <str> so that it contains no more than
 *   <size> characters.  If <str> contains fewer than <size>
 *   characters, left-pad with <fill>.  Trailing blanks
 *   in <str> will be ignored.
 *
 *   If the leftmost digit in <str> is not a digit, <fill>
 *   will default to a blank.
 */
static void rightjust(char *str, int size, int fill)
{
	register int n;
	register char *cp,*sp;
	n = strlen(str);

	/* ignore trailing blanks */
	for(cp=str+n;n && *--cp == ' ';n--);
	if (n == size)
		return;
	if(n > size)
        {
        	*(str+n) = 0;
        	for (sp = str, cp = str+n-size; sp <= str+size; *sp++ = *cp++);
        	return;
        }
	else *(sp = str+size) = 0;
	if (n == 0)  
        {
        	while (sp > str)
               		*--sp = ' ';
        	return;
        }
	while(n--)
	{
		sp--;
		*sp = *cp--;
	}
	if(!isdigit(*str))
		fill = ' ';
	while(sp>str)
		*--sp = fill;
	return;
}

#if SHOPT_MULTIBYTE
    /*
     * handle left and right justified fields for multi-byte chars
     * given physical size, return a logical size which reflects the
     * screen width of multi-byte characters
     * Multi-width characters replaced by spaces if they cross the boundary
     * <type> is non-zero for right justified  fields
     */

    static int ja_size(char *str,int size,int type)
    {
	register char *cp = str;
	register int c, n=size;
	register int outsize;
	register char *oldcp=cp;
	int oldn;
	wchar_t w;
	while(*cp)
	{
		oldn = n;
		w = mbchar(cp);
		outsize = mbwidth(w);
		size -= outsize;
		c = cp-oldcp;
		n += (c-outsize);
		oldcp = cp;
		if(size<=0 && type==0)
			break;
	}
	/* check for right justified fields that need truncating */
	if(size <0)
	{
		if(type==0)
		{
			/* left justified and character crosses field boundary */
			n = oldn;
			/* save boundary char and replace with spaces */
			size = c;
			savechars[size] = 0;
			while(size--)
			{
				savechars[size] = cp[size];
				cp[size] = ' ';
			}
			savep = cp;
		}
		size = -size;
		if(type)
			n -= (ja_size(str,size,0)-size);
	}
	return(n);
    }

    static void ja_restore(void)
    {
	register char *cp = savechars;
	while(*cp)
		*savep++ = *cp++;
	savep = 0;
    }
#endif /* SHOPT_MULTIBYTE */

#ifndef _ENV_H
static char *staknam(register Namval_t *np, char *value)
{
	register char *p,*q;
	q = stakalloc(strlen(nv_name(np))+(value?strlen(value):0)+2);
	p=strcopy(q,nv_name(np));
	if(value)
	{
		*p++ = '=';
		strcpy(p,value);
	}
	return(q);
}
#endif

/*
 * put the name and attribute into value of attributes variable
 */
#ifdef _ENV_H
static void attstore(register Namval_t *np, void *data)
{
	register int flag, c = ' ';
	NOT_USED(data);
	if(!(nv_isattr(np,NV_EXPORT)))
		return;
	flag = nv_isattr(np,NV_RDONLY|NV_UTOL|NV_LTOU|NV_RJUST|NV_LJUST|NV_ZFILL|NV_INTEGER);
	stakputc('=');
	if((flag&NV_DOUBLE) == NV_DOUBLE)
	{
		/* export doubles as integers for ksh88 compatibility */
		stakputc(c+NV_INTEGER|(flag&~(NV_DOUBLE|NV_EXPNOTE)));
	}
	else
	{
		stakputc(c+flag);
		if(flag&NV_INTEGER)
			c +=  nv_size(np);
	}
	stakputc(c);
	stakputs(nv_name(np));
}
#else
static void attstore(register Namval_t *np, void *data)
{
	register int flag = np->nvflag;
	register struct adata *ap = (struct adata*)data;
	ap->sh = &sh;
	ap->tp = 0;
	if(!(flag&NV_EXPORT) || (flag&NV_FUNCT))
		return;
	flag &= (NV_RDONLY|NV_UTOL|NV_LTOU|NV_RJUST|NV_LJUST|NV_ZFILL|NV_INTEGER);
	*ap->attval++ = '=';
	if((flag&NV_DOUBLE) == NV_DOUBLE)
	{
		/* export doubles as integers for ksh88 compatibility */
		*ap->attval++ = ' '+ NV_INTEGER|(flag&~(NV_DOUBLE|NV_EXPNOTE));
		*ap->attval = ' ';
	}
	else
	{
		*ap->attval++ = ' '+flag;
		if(flag&NV_INTEGER)
			*ap->attval = ' ' + nv_size(np);
		else
			*ap->attval = ' ';
	}
	ap->attval = strcopy(++ap->attval,nv_name(np));
}
#endif

#ifndef _ENV_H
static void pushnam(Namval_t *np, void *data)
{
	register char *value;
	register struct adata *ap = (struct adata*)data;
	ap->sh = &sh;
	ap->tp = 0;
	if(nv_isattr(np,NV_IMPORT) && np->nvenv)
		*ap->argnam++ = np->nvenv;
	else if(value=nv_getval(np))
		*ap->argnam++ = staknam(np,value);
	if(nv_isattr(np,NV_RDONLY|NV_UTOL|NV_LTOU|NV_RJUST|NV_LJUST|NV_ZFILL|NV_INTEGER))
		ap->attsize += (strlen(nv_name(np))+4);
}
#endif

/*
 * Generate the environment list for the child.
 */

#ifdef _ENV_H
char **sh_envgen(void)
{
	int offset,tell;
	register char **er;
	env_delete(sh.env,"_");
	er = env_get(sh.env);
	offset = staktell();
	stakputs(e_envmarker);
	tell = staktell();
	nv_scan(sh.var_tree, attstore,(void*)0,0,(NV_RDONLY|NV_UTOL|NV_LTOU|NV_RJUST|NV_LJUST|NV_ZFILL|NV_INTEGER));
	if(tell ==staktell())
		stakseek(offset);
	else
		*--er = stakfreeze(1)+offset;
	return(er);
}
#else
char **sh_envgen(void)
{
	register char **er;
	register int namec;
	register char *cp;
	struct adata data;
	Shell_t	*shp = sh_getinterp();
	data.sh = shp;
	data.tp = 0;
	/* L_ARGNOD gets generated automatically as full path name of command */
	nv_offattr(L_ARGNOD,NV_EXPORT);
	data.attsize = 6;
	namec = nv_scan(shp->var_tree,nullscan,(void*)0,NV_EXPORT,NV_EXPORT);
	namec += shp->nenv;
	er = (char**)stakalloc((namec+4)*sizeof(char*));
	data.argnam = (er+=2) + shp->nenv;
	if(shp->nenv)
		memcpy((void*)er,environ,shp->nenv*sizeof(char*));
	nv_scan(shp->var_tree, pushnam,&data,NV_EXPORT, NV_EXPORT);
	*data.argnam = (char*)stakalloc(data.attsize);
	cp = data.attval = strcopy(*data.argnam,e_envmarker);
	nv_scan(shp->var_tree, attstore,&data,0,(NV_RDONLY|NV_UTOL|NV_LTOU|NV_RJUST|NV_LJUST|NV_ZFILL|NV_INTEGER));
	*data.attval = 0;
	if(cp!=data.attval)
		data.argnam++;
	*data.argnam = 0;
	return(er);
}
#endif

struct scan
{
	void    (*scanfn)(Namval_t*, void*);
	int     scanmask;
	int     scanflags;
	int     scancount;
	void    *scandata;
};

static int scanfilter(Dt_t *dict, void *arg, void *data)
{
	register Namval_t *np = (Namval_t*)arg;
	register int k=np->nvflag;
	register struct scan *sp = (struct scan*)data;
	register struct adata *tp = (struct adata*)sp->scandata;
	NOT_USED(dict);
#if SHOPT_TYPEDEF
	if(!is_abuiltin(np) && tp && tp->tp && nv_type(np)!=tp->tp)
		return(0);
#endif /*SHOPT_TYPEDEF */
	if(sp->scanmask?(k&sp->scanmask)==sp->scanflags:(!sp->scanflags || (k&sp->scanflags)))
	{
		if(!np->nvalue.cp && !np->nvfun && !nv_isattr(np,~NV_DEFAULT))
			return(0);
		if(sp->scanfn)
		{
			if(nv_isarray(np))
				nv_putsub(np,NIL(char*),0L);
			(*sp->scanfn)(np,sp->scandata);
		}
		sp->scancount++;
	}
	return(0);
}

/*
 * Walk through the name-value pairs
 * if <mask> is non-zero, then only nodes with (nvflags&mask)==flags
 *	are visited
 * If <mask> is zero, and <flags> non-zero, then nodes with one or
 *	more of <flags> is visited
 * If <mask> and <flags> are zero, then all nodes are visted
 */
int nv_scan(Dt_t *root, void (*fn)(Namval_t*,void*), void *data,int mask, int flags)
{
	Dt_t *base=0;
	struct scan sdata;
	int (*hashfn)(Dt_t*, void*, void*);
	sdata.scanmask = mask;
	sdata.scanflags = flags&~NV_NOSCOPE;
	sdata.scanfn = fn;
	sdata.scancount = 0;
	sdata.scandata = data;
	hashfn = scanfilter;
	if(flags&NV_NOSCOPE)
		base = dtview((Dt_t*)root,0);
	dtwalk(root, hashfn,&sdata);
	if(base)
		 dtview((Dt_t*)root,base);
	return(sdata.scancount);
}

/*
 * create a new environment scope
 */
void sh_scope(Shell_t *shp, struct argnod *envlist, int fun)
{
	register Dt_t		*newscope, *newroot=shp->var_base;
	struct Ufunction	*rp;
	newscope = dtopen(&_Nvdisc,Dtoset);
	if(envlist)
	{
		dtview(newscope,(Dt_t*)shp->var_tree);
		shp->var_tree = newscope;
		nv_setlist(envlist,NV_EXPORT|NV_NOSCOPE|NV_IDENT|NV_ASSIGN,0);
		if(!fun)
			return;
		shp->var_tree = dtview(newscope,0);
	}
	if((rp=shp->st.real_fun)  && rp->sdict)
	{
		dtview(rp->sdict,newroot);
		newroot = rp->sdict;
	
	}
	dtview(newscope,(Dt_t*)newroot);
	shp->var_tree = newscope;
}

/* 
 * Remove freeable local space associated with the nvalue field
 * of nnod. This includes any strings representing the value(s) of the
 * node, as well as its dope vector, if it is an array.
 */

void	sh_envnolocal (register Namval_t *np, void *data)
{
	char *cp=0;
	NOT_USED(data);
	if(np==VERSIONNOD && nv_isref(np))
		return;
	if(np==L_ARGNOD)
		return;
	if(nv_isattr(np,NV_EXPORT) && nv_isarray(np))
	{
		nv_putsub(np,NIL(char*),0);
		if(cp = nv_getval(np))
			cp = strdup(cp);
	}
	if(nv_isattr(np,NV_EXPORT|NV_NOFREE))
	{
		if(nv_isref(np) && np!=VERSIONNOD)
		{
			nv_offattr(np,NV_NOFREE|NV_REF);
			free((void*)np->nvalue.nrp);
			np->nvalue.cp = 0;
		}
		if(!cp)
			return;
	}
	if(nv_isarray(np))
		nv_putsub(np,NIL(char*),ARRAY_UNDEF);
	_nv_unset(np,NV_RDONLY);
	nv_setattr(np,0);
	if(cp)
	{
		nv_putval(np,cp,0);
		free((void*)cp);
	}
}

/*
 * Currently this is a dummy, but someday will be needed
 * for reference counting
 */
void	nv_close(Namval_t *np)
{
	NOT_USED(np);
}

static void table_unset(Shell_t *shp, register Dt_t *root, int flags, Dt_t *oroot)
{
	register Namval_t *np,*nq, *npnext;
	for(np=(Namval_t*)dtfirst(root);np;np=npnext)
	{
		if(nv_isref(np))
		{
			free((void*)np->nvalue.nrp);
			np->nvalue.cp = 0;
			np->nvflag = 0;
		}
		if(nq=dtsearch(oroot,np))
		{
			if(nv_cover(nq))
			{
				int subshell = shp->subshell;
				shp->subshell = 0;
				if(nv_isattr(nq, NV_INTEGER))
				{
					Sfdouble_t d = nv_getnum(nq);
					nv_putval(nq,(char*)&d,NV_LDOUBLE);
				}
				else if(shp->test&4)
					nv_putval(nq, strdup(nv_getval(nq)), NV_RDONLY);
				else
					nv_putval(nq, nv_getval(nq), NV_RDONLY);
				shp->subshell = subshell;
				np->nvfun = 0;
			}
			if(nv_isattr(nq,NV_EXPORT))
				sh_envput(shp->env,nq);
		}
		npnext = (Namval_t*)dtnext(root,np);
		shp->last_root = root;
		shp->last_table = 0;
		if(nv_isvtree(np))
		{
			int len = strlen(np->nvname);
			while((nq=npnext) && memcmp(np->nvname,nq->nvname,len)==0 && nq->nvname[len]=='.')

			{
				npnext = (Namval_t*)dtnext(root,nq);
				_nv_unset(nq,flags);
				nv_delete(nq,root,0);
			}
		}
		_nv_unset(np,flags);
		nv_delete(np,root,0);
	}
}

/*
 *
 *   Set the value of <np> to 0, and nullify any attributes
 *   that <np> may have had.  Free any freeable space occupied
 *   by the value of <np>.  If <np> denotes an array member, it
 *   will retain its attributes.
 *   <flags> can contain NV_RDONLY to override the readonly attribute
 *	being cleared.
 *   <flags> can contain NV_EXPORT to override preserve nvenv
 */
void	_nv_unset(register Namval_t *np,int flags)
{
	Shell_t	*shp = &sh;
	register union Value *up;
	if(!(flags&NV_RDONLY) && nv_isattr (np,NV_RDONLY))
		errormsg(SH_DICT,ERROR_exit(1),e_readonly, nv_name(np));
	if(is_afunction(np) && np->nvalue.ip)
	{
		register struct slnod *slp = (struct slnod*)(np->nvenv);
		if(slp && !nv_isattr(np,NV_NOFREE))
		{
			struct Ufunction *rq,*rp = np->nvalue.rp;
			/* free function definition */
			register char *name=nv_name(np),*cp= strrchr(name,'.');
			if(cp)
			{
				Namval_t *npv;
				*cp = 0;
				 npv = nv_open(name,shp->var_tree,NV_NOARRAY|NV_VARNAME|NV_NOADD);
				*cp++ = '.';
				if(npv)
					nv_setdisc(npv,cp,NIL(Namval_t*),(Namfun_t*)npv);
			}
			if(rp->fname && shp->fpathdict && (rq = (struct Ufunction*)nv_search(rp->fname,shp->fpathdict,0)))
			{
				do
				{
					if(rq->np != np)
						continue;
					dtdelete(shp->fpathdict,rq);
					break;
				}
				while(rq = (struct Ufunction*)dtnext(shp->fpathdict,rq));
			}
			if(rp->sdict)
			{
				Namval_t *mp, *nq;
				for(mp=(Namval_t*)dtfirst(rp->sdict);mp;mp=nq)
				{
					nq = dtnext(rp->sdict,mp);
					_nv_unset(mp,NV_RDONLY);
					nv_delete(mp,rp->sdict,0);
				}
				dtclose(rp->sdict);
			}
			stakdelete(slp->slptr);
			free((void*)np->nvalue.ip);
			np->nvalue.ip = 0;
		}
		goto done;
	}
	if(shp->subshell && !nv_isnull(np))
		np = sh_assignok(np,0);
	nv_offattr(np,NV_NODISC);
	if(np->nvfun && !nv_isref(np))
	{
		/* This function contains disc */
		if(!nv_local)
		{
			nv_local=1;
			nv_putv(np,NIL(char*),flags,np->nvfun);
			nv_local=0;
			return;
		}
		/* called from disc, assign the actual value */
		nv_local=0;
	}
	if(nv_isattr(np,NV_INT16P) == NV_INT16)
	{
		np->nvalue.cp = nv_isarray(np)?Empty:0;
		goto done;
	}
	if(nv_isarray(np) && np->nvalue.cp!=Empty && np->nvfun)
		up = np->nvalue.up;
	else
		up = &np->nvalue;
	if(up && up->cp)
	{
		if(up->cp!=Empty && !nv_isattr(np, NV_NOFREE))
			free((void*)up->cp);
		up->cp = 0;
	}
done:
	if(!nv_isarray(np) || !nv_arrayptr(np))
	{
		if(nv_isref(np) && !nv_isattr(np,NV_EXPORT))
			free((void*)np->nvalue.nrp);
		nv_setsize(np,0);
		if(!nv_isattr(np,NV_MINIMAL) || nv_isattr(np,NV_EXPORT))
		{
			if(nv_isattr(np,NV_EXPORT) && !strchr(np->nvname,'['))
				env_delete(shp->env,nv_name(np));
			if(!(flags&NV_EXPORT) ||  nv_isattr(np,NV_IMPORT|NV_EXPORT)==(NV_IMPORT|NV_EXPORT))
				np->nvenv = 0;
			nv_setattr(np,0);
		}
		else
		{
			nv_setattr(np,NV_MINIMAL);
			nv_delete(np,(Dt_t*)0,0);
		}
	}
}

/*
 * return the node pointer in the highest level scope
 */
Namval_t *sh_scoped(Shell_t *shp, register Namval_t *np)
{
	if(!dtvnext(shp->var_tree))
		return(np);
	return(dtsearch(shp->var_tree,np));
}

#if 1
/*
 * return space separated list of names of variables in given tree
 */
static char *tableval(Dt_t *root)
{
	static Sfio_t *out;
	register Namval_t *np;
	register int first=1;
	register Dt_t *base = dtview(root,0);
        if(out)
                sfseek(out,(Sfoff_t)0,SEEK_SET);
        else
                out =  sfnew((Sfio_t*)0,(char*)0,-1,-1,SF_WRITE|SF_STRING);
	for(np=(Namval_t*)dtfirst(root);np;np=(Namval_t*)dtnext(root,np))
	{
                if(!nv_isnull(np) || np->nvfun || nv_isattr(np,~NV_NOFREE))
		{
			if(!first)
				sfputc(out,' ');
			else
				first = 0;
			sfputr(out,np->nvname,-1);
		}
	}
	sfputc(out,0);
	if(base)
		dtview(root,base);
	return((char*)out->_data);
}
#endif

#if SHOPT_OPTIMIZE
struct optimize
{
	Namfun_t	hdr;
	Shell_t		*sh;
	char		**ptr;
	struct optimize	*next;
	Namval_t	*np;
};

static struct optimize *opt_free;

static void optimize_clear(Namval_t* np, Namfun_t *fp)
{
	struct optimize *op = (struct optimize*)fp;
	nv_stack(np,fp);
	nv_stack(np,(Namfun_t*)0);
	for(;op && op->np==np; op=op->next)
	{
		if(op->ptr)
		{
			*op->ptr = 0;
			op->ptr = 0;
		}
	}
}

static void put_optimize(Namval_t* np,const char *val,int flags,Namfun_t *fp)
{
	nv_putv(np,val,flags,fp);
	optimize_clear(np,fp);
}

static Namfun_t *clone_optimize(Namval_t* np, Namval_t *mp, int flags, Namfun_t *fp)
{
	return((Namfun_t*)0);
}

static const Namdisc_t optimize_disc  = {sizeof(struct optimize),put_optimize,0,0,0,0,clone_optimize};

void nv_optimize(Namval_t *np)
{
	register Namfun_t *fp;
	register struct optimize *op, *xp;
	if(sh.argaddr)
	{
		if(np==SH_LINENO)
		{
			sh.argaddr = 0;
			return;
		}
		for(fp=np->nvfun; fp; fp = fp->next)
		{
			if(fp->disc && (fp->disc->getnum || fp->disc->getval))
			{
				sh.argaddr = 0;
				return;
			}
			if(fp->disc== &optimize_disc)
				break;
		}
		if((xp= (struct optimize*)fp) && xp->ptr==sh.argaddr)
			return;
		if(op = opt_free)
			opt_free = op->next;
		else
			op=(struct optimize*)calloc(1,sizeof(struct optimize));
		op->ptr = sh.argaddr;
		op->np = np;
		if(xp)
		{
			op->hdr.disc = 0;
			op->next = xp->next;
			xp->next = op;
		}
		else
		{
			op->hdr.disc = &optimize_disc;
			op->next = (struct optimize*)sh.optlist;
			sh.optlist = (void*)op;
			nv_stack(np,&op->hdr);
		}
	}
}

void sh_optclear(Shell_t *shp, void *old)
{
	register struct optimize *op,*opnext;
	for(op=(struct optimize*)shp->optlist; op; op = opnext)
	{
		opnext = op->next;
		if(op->ptr && op->hdr.disc)
		{
			nv_stack(op->np,&op->hdr);
			nv_stack(op->np,(Namfun_t*)0);
		}
		op->next = opt_free;
		opt_free = op;
	}
	shp->optlist = old;
}

#else
#   define	optimize_clear(np,fp)
#endif /* SHOPT_OPTIMIZE */

/*
 *   Return a pointer to a character string that denotes the value
 *   of <np>.  If <np> refers to an array,  return a pointer to
 *   the value associated with the current index.
 *
 *   If the value of <np> is an integer, the string returned will
 *   be overwritten by the next call to nv_getval.
 *
 *   If <np> has no value, 0 is returned.
 */

char *nv_getval(register Namval_t *np)
{
	register union Value *up= &np->nvalue;
	register int numeric;
#if SHOPT_OPTIMIZE
	if(!nv_local && sh.argaddr)
		nv_optimize(np);
#endif /* SHOPT_OPTIMIZE */
	if((!np->nvfun || !np->nvfun->disc) && !nv_isattr(np,NV_ARRAY|NV_INTEGER|NV_FUNCT|NV_REF|NV_TABLE))
		goto done;
	if(nv_isref(np))
	{
		if(!np->nvalue.cp)
			return(0);
		sh.last_table = nv_reftable(np);
		return(nv_name(nv_refnode(np)));
	}
	if(np->nvfun && np->nvfun->disc)
	{
		if(!nv_local)
		{
			nv_local=1;
			return(nv_getv(np, np->nvfun));
		}
		nv_local=0;
	}
	numeric = ((nv_isattr (np, NV_INTEGER)) != 0);
	if(numeric)
	{
		Sflong_t  ll;
		if(!up->cp)
			return("0");
		if(nv_isattr (np,NV_DOUBLE)==NV_DOUBLE)
		{
			Sfdouble_t ld;
			double d;
			char *format;
			if(nv_isattr(np,NV_LONG))
			{
				ld = *up->ldp;
				if(nv_isattr (np,NV_EXPNOTE))
					format = "%.*Lg";
				else if(nv_isattr (np,NV_HEXFLOAT))
					format = "%.*La";
				else
					format = "%.*Lf";
				sfprintf(sh.strbuf,format,nv_size(np),ld);
			}
			else
			{
				d = *up->dp;
				if(nv_isattr (np,NV_EXPNOTE))
					format = "%.*g";
				else if(nv_isattr (np,NV_HEXFLOAT))
					format = "%.*a";
				else
					format = "%.*f";
				sfprintf(sh.strbuf,format,nv_size(np),d);
			}
			return(sfstruse(sh.strbuf));
		}
		else if(nv_isattr(np,NV_UNSIGN))
		{
	        	if(nv_isattr (np,NV_LONG))
				ll = *(Sfulong_t*)up->llp;
			else if(nv_isattr (np,NV_SHORT))
			{
				if(nv_isattr(np,NV_INT16P)==NV_INT16P)
					ll = *(uint16_t*)(up->sp);
				else
					ll = (uint16_t)up->s;
			}
			else
				ll = *(uint32_t*)(up->lp);
		}
        	else if(nv_isattr (np,NV_LONG))
			ll = *up->llp;
        	else if(nv_isattr (np,NV_SHORT))
		{
			if(nv_isattr(np,NV_INT16P)==NV_INT16P)
				ll = *up->sp;
			else
				ll = up->s;
		}
        	else
			ll = *(up->lp);
		if((numeric=nv_size(np))==10)
		{
			if(nv_isattr(np,NV_UNSIGN))
			{
				sfprintf(sh.strbuf,"%I*u",sizeof(ll),ll);
				return(sfstruse(sh.strbuf));
			}
			numeric = 0;
		}
		return(fmtbasell(ll,numeric, numeric&&numeric!=10));
	}
done:
#if (_AST_VERSION>=20030127L)
	/*
	 * if NV_RAW flag is on, return pointer to binary data 
	 * otherwise, base64 encode the data and return this string
	 */
	if(up->cp && nv_isattr(np,NV_BINARY) && !nv_isattr(np,NV_RAW))
	{
		char *cp;
		char *ep;
		int size= nv_size(np), insize=(4*size)/3+size/45+8;
		base64encode(up->cp, size, (void**)0, cp=getbuf(insize), insize, (void**)&ep); 
		*ep = 0;
		return(cp);
	}
#endif
	if((numeric=nv_size(np)) && up->cp && up->cp[numeric])
	{
		char *cp = getbuf(numeric+1);
		memcpy(cp,up->cp,numeric);
		cp[numeric]=0;
		return(cp);
	}
	return ((char*)up->cp);
}

Sfdouble_t nv_getnum(register Namval_t *np)
{
	register union Value *up;
	register Sfdouble_t r=0;
	register char *str;
#if SHOPT_OPTIMIZE
	if(!nv_local && sh.argaddr)
		nv_optimize(np);
#endif /* SHOPT_OPTIMIZE */
	if(nv_istable(np))
		errormsg(SH_DICT,ERROR_exit(1),e_number,nv_name(np));
     	if(np->nvfun && np->nvfun->disc)
	{
		if(!nv_local)
		{
			nv_local=1;
			return(nv_getn(np, np->nvfun));
		}
		nv_local=0;
	}
	if(nv_isref(np))
	{
		str = nv_refsub(np);
		np = nv_refnode(np);
		if(str)
			nv_putsub(np,str,0L);
	}
     	if(nv_isattr (np, NV_INTEGER))
	{
		up= &np->nvalue;
		if(!up->lp || up->cp==Empty)
			r = 0;
		else if(nv_isattr(np, NV_DOUBLE)==NV_DOUBLE)
		{
			if(nv_isattr(np, NV_LONG))
	                       	r = *up->ldp;
			else
       	                	r = *up->dp;
		}
		else if(nv_isattr(np, NV_UNSIGN))
		{
			if(nv_isattr(np, NV_LONG))
				r = (Sflong_t)*((Sfulong_t*)up->llp);
			else if(nv_isattr(np, NV_SHORT))
			{
				if(nv_isattr(np,NV_INT16P)==NV_INT16P)
					r = (Sflong_t)(*(uint16_t*)up->sp);
				else
					r = (Sflong_t)((uint16_t)up->s);
			}
			else
				r = *((uint32_t*)up->lp);
		}
		else
		{
			if(nv_isattr(np, NV_LONG))
				r = *up->llp;
			else if(nv_isattr(np, NV_SHORT))
			{
				if(nv_isattr(np,NV_INT16P)==NV_INT16P)
					r = *up->sp;
				else
					r = up->s;
			}
			else
				r = *up->lp;
		}
	}
	else if((str=nv_getval(np)) && *str!=0)
	{
		if(np->nvfun ||  nv_isattr(np,NV_LJUST|NV_RJUST|NV_ZFILL))
		{
			while(*str=='0')
				str++;
		}
		r = sh_arith(str);
	}
	return(r);
}
/*
 *   Give <np> the attributes <newatts,> and change its current
 *   value to conform to <newatts>.  The <size> of left and right
 *   justified fields may be given.
 */
void nv_newattr (register Namval_t *np, unsigned newatts, int size)
{
	register char *sp;
	register char *cp = 0;
	register unsigned int n;
	Namarr_t *ap = 0;
	int oldsize,oldatts;
	Namfun_t *fp= (newatts&NV_NODISC)?np->nvfun:0;
	char *prefix = sh.prefix;
	newatts &= ~NV_NODISC;

	/* check for restrictions */
	if(sh_isoption(SH_RESTRICTED) && ((sp=nv_name(np))==nv_name(PATHNOD) || sp==nv_name(SHELLNOD) || sp==nv_name(ENVNOD) || sp==nv_name(FPATHNOD)))
		errormsg(SH_DICT,ERROR_exit(1),e_restricted,nv_name(np));
	/* handle attributes that do not change data separately */
	n = np->nvflag;
	if(newatts&NV_EXPORT)
		nv_offattr(np,NV_IMPORT);
	if(((n^newatts)&NV_EXPORT))
	{
		/* record changes to the environment */
		if(n&NV_EXPORT)
			env_delete(sh.env,nv_name(np));
		else
			sh_envput(sh.env,np);
	}
	oldsize = nv_size(np);
	if((size==oldsize|| (n&NV_INTEGER)) && ((n^newatts)&~NV_NOCHANGE)==0)
	{
		if(size)
			nv_setsize(np,size);
		nv_offattr(np, ~NV_NOFREE);
		nv_onattr(np, newatts);
		return;
	}
	/* for an array, change all the elements */
	if((ap=nv_arrayptr(np)) && ap->nelem>0)
		nv_putsub(np,NIL(char*),ARRAY_SCAN);
	oldsize = nv_size(np);
	oldatts = np->nvflag;
	if(fp)
		np->nvfun = 0;
	if(ap) /* add element to prevent array deletion */
		ap->nelem++;
	do
	{
		nv_setsize(np,oldsize);
		np->nvflag = oldatts;
		if (sp = nv_getval(np))
 		{
			if(nv_isattr(np,NV_ZFILL))
				while(*sp=='0') sp++;
			cp = (char*)malloc((n=strlen (sp)) + 1);
			strcpy(cp, sp);
			if(ap)
			{
				Namval_t *mp;
				ap->nelem &= ~ARRAY_SCAN;
				if(mp=nv_opensub(np))
				{
					nv_unset(mp);
					mp->nvalue.cp = Empty;
				}
				else
					nv_unset(np);
				ap->nelem |= ARRAY_SCAN;
			}
			else
				nv_unset(np);
			if(size==0 && (newatts&NV_HOST)!=NV_HOST && (newatts&(NV_LJUST|NV_RJUST|NV_ZFILL)))
				size = n;
		}
		else
			nv_unset(np);
		nv_setsize(np,size);
		np->nvflag &= NV_ARRAY;
		np->nvflag |= newatts;
		if (cp)
		{
			nv_putval (np, cp, NV_RDONLY);
			free(cp);
		}
	}
	while(ap && nv_nextsub(np));
	if(fp)
		np->nvfun = fp;
	if(ap)
		ap->nelem--;
	sh.prefix = prefix;
	return;
}

static char *oldgetenv(const char *string)
{
	register char c0,c1;
	register const char *cp, *sp;
	register char **av = environ;
	if(!string || (c0= *string)==0)
		return(0);
	if((c1=*++string)==0)
		c1= '=';
	while(cp = *av++)
	{
		if(cp[0]!=c0 || cp[1]!=c1) 
			continue;
		sp = string;
		while(*sp && *sp++ == *++cp);
		if(*sp==0 && *++cp=='=')
			return((char*)(cp+1));
	}
	return(0);
}

/*
 * This version of getenv uses the hash storage to access environment values
 */
char *sh_getenv(const char *name)
/*@
	assume name!=0;
@*/ 
{
	register Namval_t *np;
	if(!sh.var_tree)
	{
#if 0
		if(name[0] == 'P' && name[1] == 'A' && name[2] == 'T' && name[3] == 'H' && name[4] == 0 || name[0] == 'L' && ((name[1] == 'C' || name[1] == 'D') && name[2] == '_' || name[1] == 'A' && name[1] == 'N') || name[0] == 'V' && name[1] == 'P' && name[2] == 'A' && name[3] == 'T' && name[4] == 'H' && name[5] == 0 || name[0] == '_' && name[1] == 'R' && name[2] == 'L' && name[3] == 'D' || name[0] == '_' && name[1] == 'A' && name[2] == 'S' && name[3] == 'T' && name[4] == '_')
#endif
			return(oldgetenv(name));
	}
	else if((np = nv_search(name,sh.var_tree,0)) && nv_isattr(np,NV_EXPORT))
		return(nv_getval(np));
	return(0);
}

#ifndef _NEXT_SOURCE
/*
 * Some dynamic linkers will make this file see the libc getenv(),
 * so sh_getenv() is used for the astintercept() callback.  Plain
 * getenv() is provided for static links.
 */
char *getenv(const char *name)
{
	return sh_getenv(name);
}
#endif /* _NEXT_SOURCE */

#undef putenv
/*
 * This version of putenv uses the hash storage to assign environment values
 */
int putenv(const char *name)
{
	register Namval_t *np;
	if(name)
	{
		np = nv_open(name,sh.var_tree,NV_EXPORT|NV_IDENT|NV_NOARRAY|NV_ASSIGN);
		if(!strchr(name,'='))
			nv_unset(np);
	}
	return(0);
}

/*
 * Override libast setenviron().
 */
char* sh_setenviron(const char *name)
{
	register Namval_t *np;
	if(name)
	{
		np = nv_open(name,sh.var_tree,NV_EXPORT|NV_IDENT|NV_NOARRAY|NV_ASSIGN);
		if(strchr(name,'='))
			return(nv_getval(np));
		nv_unset(np);
	}
	return("");
}

/*
 * Same linker dance as with getenv() above.
 */
char* setenviron(const char *name)
{
	return sh_setenviron(name);
}

/*
 * convert <str> to upper case
 */
static void ltou(register char *str)
{
	register int c;
	for(; c= *((unsigned char*)str); str++)
	{
		if(islower(c))
			*str = toupper(c);
	}
}

/*
 * convert <str> to lower case
 */
static void utol(register char *str)
{
	register int c;
	for(; c= *((unsigned char*)str); str++)
	{
		if(isupper(c))
			*str = tolower(c);
	}
}

/*
 * normalize <cp> and return pointer to subscript if any
 * if <eq> is specified, return pointer to first = not in a subscript
 */
static char *lastdot(register char *cp, int eq)
{
	register char *ep=0;
	register int c;
	if(eq)
		cp++;
	while(c= *cp++)
	{
		if(c=='[')
		{
			if(*cp==']')
				cp++;
			else
				cp = nv_endsubscript((Namval_t*)0,ep=cp,0);
		}
		else if(c=='.')
		{
			if(*cp=='[')
			{
				cp = nv_endsubscript((Namval_t*)0,ep=cp,0);
				if((ep=sh_checkid(ep+1,cp)) < cp)
					cp=strcpy(ep,cp);
			}
			ep = 0;
		}
		else if(eq && c == '=')
			return(cp-1);
	}
	return(eq?0:ep);
}

int nv_rename(register Namval_t *np, int flags)
{
	Shell_t			*shp = &sh;
	register Namval_t	*mp=0,*nr=0;
	register char		*cp;
	int			index= -1;
	Namval_t		*last_table = shp->last_table;
	Dt_t			*last_root = shp->last_root;
	Dt_t			*hp = 0;
	char			*prefix=shp->prefix,*nvenv = 0;
	if(nv_isattr(np,NV_PARAM) && shp->st.prevst)
	{
		if(!(hp=(Dt_t*)shp->st.prevst->save_tree))
			hp = dtvnext(shp->var_tree);
	}
	if(!(cp=nv_getval(np)))
	{
		if(flags&NV_MOVE)
			errormsg(SH_DICT,ERROR_exit(1),e_varname,"");
		return(0);
	}
	if(lastdot(cp,0) && nv_isattr(np,NV_MINIMAL))
		errormsg(SH_DICT,ERROR_exit(1),e_varname,nv_name(np));
	if(nv_isarray(np) && !(mp=nv_opensub(np)))
		index=nv_aindex(np);
	shp->prefix = 0;
	if(!hp)
		hp = shp->var_tree;
	if(!(nr = nv_open(cp, hp, flags|NV_ARRAY|NV_NOREF|NV_NOSCOPE|NV_NOADD|NV_NOFAIL)))
		hp = shp->var_base;
	else if(shp->last_root)
		hp = shp->last_root;
	if(!nr)
		nr= nv_open(cp, hp, flags|NV_NOREF|((flags&NV_MOVE)?0:NV_NOFAIL));
	shp->prefix = prefix;
	if(!nr)
	{
		if(!nv_isvtree(np))
			_nv_unset(np,0);
		return(0);
	}
	if(!mp && index>=0 && nv_isvtree(nr))
	{
		sfprintf(shp->strbuf,"%s[%d]%c",nv_name(np),index,0);
		/* create a virtual node */
		if(mp = nv_open(sfstruse(shp->strbuf),shp->var_tree,NV_VARNAME|NV_ADD|NV_ARRAY))
			mp->nvenv = (void*)np;
	}
	if(mp)
	{
		nvenv = (char*)np;
		np = mp;
	}
	if(nr==np)
	{
		if(index<0)
			return(0);
		if(cp = nv_getval(np))
			cp = strdup(cp);
	}
	_nv_unset(np,0);
	if(!nv_isattr(np,NV_MINIMAL))
		np->nvenv = nvenv;
	if(nr==np)
	{
		nv_putsub(np,(char*)0, index);
		nv_putval(np,cp,0);
		free((void*)cp);
		return(1);
	}
	shp->prev_table = shp->last_table;
	shp->prev_root = shp->last_root;
	shp->last_table = last_table;
	shp->last_root = last_root;
	nv_clone(nr,np,(flags&NV_MOVE)|NV_COMVAR);
	if(flags&NV_MOVE)
		nv_delete(nr,(Dt_t*)0,NV_NOFREE);
	return(1);
}

/*
 * Create a reference node from <np> to $np in dictionary <hp> 
 */
void nv_setref(register Namval_t *np, Dt_t *hp, int flags)
{
	Shell_t		*shp = &sh;
	register Namval_t *nq, *nr=0;
	register char	*ep,*cp;
	Dt_t		*root = shp->last_root;
	Namarr_t	*ap;
	if(nv_isref(np))
		return;
	if(nv_isarray(np))
		errormsg(SH_DICT,ERROR_exit(1),e_badref,nv_name(np));
	if(!(cp=nv_getval(np)))
	{
		nv_unset(np);
		nv_onattr(np,NV_REF);
		return;
	}
	if((ep = lastdot(cp,0)) && nv_isattr(np,NV_MINIMAL))
		errormsg(SH_DICT,ERROR_exit(1),e_badref,nv_name(np));
	if(!hp)
		hp = shp->var_tree;
	if(!(nr = nq = nv_open(cp, hp, flags|NV_NOSCOPE|NV_NOADD|NV_NOFAIL)))
		hp = shp->last_root==shp->var_tree?shp->var_tree:shp->var_base;
	else if(shp->last_root)
		hp = shp->last_root;
	if(nq && ep && nv_isarray(nq) && !nv_getsub(nq))
		nv_endsubscript(nq,ep-1,NV_ADD);
	if(!nr)
	{
		nr= nq = nv_open(cp, hp, flags);
		hp = shp->last_root;
	}
	if(shp->last_root == shp->var_tree && root!=shp->var_tree)
	{
		_nv_unset(np,NV_RDONLY);
		nv_onattr(np,NV_REF);
		errormsg(SH_DICT,ERROR_exit(1),e_globalref,nv_name(np));
	}
	if(nr==np) 
	{
		if(shp->namespace && nv_dict(shp->namespace)==hp)
			errormsg(SH_DICT,ERROR_exit(1),e_selfref,nv_name(np));
		/* bind to earlier scope, or add to global scope */
		if(!(hp=dtvnext(hp)) || (nq=nv_search((char*)np,hp,NV_ADD|HASH_BUCKET))==np)
			errormsg(SH_DICT,ERROR_exit(1),e_selfref,nv_name(np));
	}
	if(nq && !ep && (ap=nv_arrayptr(nq)) && !(ap->nelem&(ARRAY_UNDEF|ARRAY_SCAN)))
		ep =  nv_getsub(nq);
	if(ep)
	{
		/* cause subscript evaluation and return result */
		if(nv_isarray(nq))
			ep = nv_getsub(nq);
		else
		{
			ep[strlen(ep)-1] = 0;
			nv_putsub(nr, ep, 0);
			ep[strlen(ep)-1] = ']';
			if(nq = nv_opensub(nr))
				ep = 0;
			else
				nq = nr;
		}
	}
	nv_unset(np);
	nv_delete(np,(Dt_t*)0,0);
	np->nvalue.nrp = newof(0,struct Namref,1,0);
	np->nvalue.nrp->np = nq;
	np->nvalue.nrp->root = hp;
	if(ep)
		np->nvalue.nrp->sub = strdup(ep);
	np->nvalue.nrp->table = shp->last_table;
	nv_onattr(np,NV_REF|NV_NOFREE);
}

/*
 * get the scope corresponding to <index>
 * whence uses the same values as lseeek()
 */
Shscope_t *sh_getscope(int index, int whence)
{
	register struct sh_scoped *sp, *topmost;
	if(whence==SEEK_CUR)
		sp = &sh.st;
	else
	{
		if ((struct sh_scoped*)sh.topscope != sh.st.self)
			topmost = (struct sh_scoped*)sh.topscope;
		else
			topmost = &(sh.st);
		sp = topmost;
		if(whence==SEEK_SET)
		{
			int n =0;
			while(sp = sp->prevst)
				n++;
			index = n - index;
			sp = topmost;
		}
	}
	if(index < 0)
		return((Shscope_t*)0);
	while(index-- && (sp = sp->prevst));
	return((Shscope_t*)sp);
}

/*
 * make <scoped> the top scope and return previous scope
 */
Shscope_t *sh_setscope(Shscope_t *scope)
{
	Shscope_t *old = (Shscope_t*)sh.st.self;
	*sh.st.self = sh.st;
	sh.st = *((struct sh_scoped*)scope);
	sh.var_tree = scope->var_tree;
	SH_PATHNAMENOD->nvalue.cp = sh.st.filename;
	SH_FUNNAMENOD->nvalue.cp = sh.st.funname;
	return(old);
}

void sh_unscope(Shell_t *shp)
{
	register Dt_t *root = shp->var_tree;
	register Dt_t *dp = dtview(root,(Dt_t*)0);
	table_unset(shp,root,NV_RDONLY|NV_NOSCOPE,dp);
	if(shp->st.real_fun  && dp==shp->st.real_fun->sdict)
	{
		dp = dtview(dp,(Dt_t*)0);
		shp->st.real_fun->sdict->view = dp;
	}
	shp->var_tree=dp;
	dtclose(root);
}

/*
 * The inverse of creating a reference node
 */
void nv_unref(register Namval_t *np)
{
	Namval_t *nq;
	if(!nv_isref(np))
		return;
	nv_offattr(np,NV_NOFREE|NV_REF);
	if(!np->nvalue.nrp)
		return;
	nq = nv_refnode(np);
	free((void*)np->nvalue.nrp);
	np->nvalue.cp = strdup(nv_name(nq));
#if SHOPT_OPTIMIZE
	{
		Namfun_t *fp;
		for(fp=nq->nvfun; fp; fp = fp->next)
		{
			if(fp->disc== &optimize_disc)
			{
				optimize_clear(nq,fp);
				return;
			}
		}
	}
#endif
}

/*
 * These following are for binary compatibility with the old hash library
 * They will be removed someday
 */

#if defined(__IMPORT__) && defined(__EXPORT__)
#   define extern __EXPORT__
#endif

#undef	hashscope

extern Dt_t *hashscope(Dt_t *root)
{
	return(dtvnext(root));
}

#undef	hashfree

extern Dt_t	*hashfree(Dt_t *root)
{
	Dt_t *dp = dtvnext(root);
	dtclose(root);
	return(dp);
}

#undef	hashname

extern char	*hashname(void *obj)
{
	Namval_t *np = (Namval_t*)obj;
	return(np->nvname);
}

#undef	hashlook

extern void *hashlook(Dt_t *root, const char *name, int mode,int size)
{
	NOT_USED(size);
	return((void*)nv_search(name,root,mode));
}

char *nv_name(register Namval_t *np)
{
	register Namval_t *table;
	register Namfun_t *fp;
	char *cp;
	if(is_abuiltin(np) || is_afunction(np))
		return(np->nvname);
	if(!nv_isattr(np,NV_MINIMAL|NV_EXPORT) && np->nvenv)
	{
		Namval_t *nq= sh.last_table, *mp= (Namval_t*)np->nvenv;
		if(np==sh.last_table)
			sh.last_table = 0;
		if(nv_isarray(mp))
			sfprintf(sh.strbuf,"%s[%s]",nv_name(mp),np->nvname);
		else
			sfprintf(sh.strbuf,"%s.%s",nv_name(mp),np->nvname);
		sh.last_table = nq;
		return(sfstruse(sh.strbuf));
	}
	if(nv_istable(np))
#if 1
		sh.last_table = nv_parent(np);
#else
		sh.last_table = nv_create(np,0, NV_LAST,(Namfun_t*)0);
#endif
	else if(!nv_isref(np))
	{
		for(fp= np->nvfun ; fp; fp=fp->next)
		if(fp->disc && fp->disc->namef)
		{
			if(np==sh.last_table)
				sh.last_table = 0;
			return((*fp->disc->namef)(np,fp));
		}
	}
	if(!(table=sh.last_table) || *np->nvname=='.' || table==sh.namespace || np==table)
		return(np->nvname);
	cp = nv_name(table);
	sfprintf(sh.strbuf,"%s.%s",cp,np->nvname);
	return(sfstruse(sh.strbuf));
}

Namval_t *nv_lastdict(void)
{
	return(sh.last_table);
}

#undef nv_context
/*
 * returns the data context for a builtin
 */
void *nv_context(Namval_t *np)
{
	return((void*)np->nvfun);
}

#define DISABLE /* proto workaround */

int nv_isnull DISABLE (register Namval_t *np)
{
	return(nv_isnull(np));
}

#undef nv_setsize
int nv_setsize(register Namval_t *np, int size)
{
	int oldsize = nv_size(np);
	if(size>=0)
		np->nvsize = size;
	return(oldsize);
}

Shell_t	*nv_shell(Namval_t *np)
{
	Namfun_t *fp;
	for(fp=np->nvfun;fp;fp=fp->next)
	{
		if(!fp->disc)
			return((Shell_t*)fp->last);
	}
	return(0);
}

#undef nv_unset

void	nv_unset(register Namval_t *np)
{
	_nv_unset(np,0);
	return;
}
