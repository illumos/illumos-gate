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
 * export [-p] [arg...]
 * readonly [-p] [arg...]
 * typeset [options]  [arg...]
 * alias [-ptx] [arg...]
 * unalias [arg...]
 * builtin [-sd] [-f file] [name...]
 * set [options] [name...]
 * unset [-fnv] [name...]
 *
 *   David Korn
 *   AT&T Labs
 *
 */

#include	"defs.h"
#include	<error.h>
#include	"path.h"
#include	"name.h"
#include	"history.h"
#include	"builtins.h"
#include	"variables.h"
#include	"FEATURE/dynamic"

struct tdata
{
	Shell_t 	*sh;
	Namval_t	*tp;
	const char	*wctname;
	Sfio_t  	*outfile;
	char    	*prefix;
	char    	*tname;
	char		*help;
	short     	aflag;
	short     	pflag;
	int     	argnum;
	int     	scanmask;
	Dt_t 		*scanroot;
	char    	**argnam;
	int		indent;
	int		noref;
};


static int	print_namval(Sfio_t*, Namval_t*, int, struct tdata*);
static void	print_attribute(Namval_t*,void*);
static void	print_all(Sfio_t*, Dt_t*, struct tdata*);
static void	print_scan(Sfio_t*, int, Dt_t*, int, struct tdata*);
static int	unall(int, char**, Dt_t*, Shell_t*);
static int	setall(char**, int, Dt_t*, struct tdata*);
static void	pushname(Namval_t*,void*);
static void(*nullscan)(Namval_t*,void*);

static Namval_t *load_class(const char *name)
{
	errormsg(SH_DICT,ERROR_exit(1),"%s: type not loadable",name);
	return(0);
}

/*
 * Note export and readonly are the same
 */
#if 0
    /* for the dictionary generator */
    int    b_export(int argc,char *argv[],Shbltin_t *context){}
#endif
int    b_readonly(int argc,char *argv[],Shbltin_t *context)
{
	register int flag;
	char *command = argv[0];
	struct tdata tdata;
	NOT_USED(argc);
	memset((void*)&tdata,0,sizeof(tdata));
	tdata.sh = context->shp;
	tdata.aflag = '-';
	while((flag = optget(argv,*command=='e'?sh_optexport:sh_optreadonly))) switch(flag)
	{
		case 'p':
			tdata.prefix = command;
			break;
		case ':':
			errormsg(SH_DICT,2, "%s", opt_info.arg);
			break;
		case '?':
			errormsg(SH_DICT,ERROR_usage(0), "%s", opt_info.arg);
			return(2);
	}
	if(error_info.errors)
		errormsg(SH_DICT,ERROR_usage(2),optusage(NIL(char*)));
	argv += (opt_info.index-1);
	if(*command=='r')
		flag = (NV_ASSIGN|NV_RDONLY|NV_VARNAME);
#ifdef _ENV_H
	else if(!argv[1])
	{
		char *cp,**env=env_get(tdata.sh->env);
		while(cp = *env++)
		{
			if(tdata.prefix)
				sfputr(sfstdout,tdata.prefix,' ');
			sfprintf(sfstdout,"%s\n",sh_fmtq(cp));
		}
		return(0);
	}
#endif
	else
	{
		flag = (NV_ASSIGN|NV_EXPORT|NV_IDENT);
		if(!tdata.sh->prefix)
			tdata.sh->prefix = "";
	}
	return(setall(argv,flag,tdata.sh->var_tree, &tdata));
}


int    b_alias(int argc,register char *argv[],Shbltin_t *context)
{
	register unsigned flag = NV_NOARRAY|NV_NOSCOPE|NV_ASSIGN;
	register Dt_t *troot;
	register int n;
	struct tdata tdata;
	NOT_USED(argc);
	memset((void*)&tdata,0,sizeof(tdata));
	tdata.sh = context->shp;
	troot = tdata.sh->alias_tree;
	if(*argv[0]=='h')
		flag = NV_TAGGED;
	if(argv[1])
	{
		opt_info.offset = 0;
		opt_info.index = 1;
		*opt_info.option = 0;
		tdata.argnum = 0;
		tdata.aflag = *argv[1];
		while((n = optget(argv,sh_optalias))) switch(n)
		{
		    case 'p':
			tdata.prefix = argv[0];
			break;
		    case 't':
			flag |= NV_TAGGED;
			break;
		    case 'x':
			flag |= NV_EXPORT;
			break;
		    case ':':
			errormsg(SH_DICT,2, "%s", opt_info.arg);
			break;
		    case '?':
			errormsg(SH_DICT,ERROR_usage(0), "%s", opt_info.arg);
			return(2);
		}
		if(error_info.errors)
			errormsg(SH_DICT,ERROR_usage(2),"%s",optusage(NIL(char*)));
		argv += (opt_info.index-1);
		if(flag&NV_TAGGED)
		{
			/* hacks to handle hash -r | -- */
			if(argv[1] && argv[1][0]=='-')
			{
				if(argv[1][1]=='r' && argv[1][2]==0)
				{
					Namval_t *np = nv_search((char*)PATHNOD,tdata.sh->var_tree,HASH_BUCKET);
					nv_putval(np,nv_getval(np),NV_RDONLY);
					argv++;
					if(!argv[1])
						return(0);
				}
				if(argv[1][0]=='-')
				{
					if(argv[1][1]=='-' && argv[1][2]==0)
						argv++;
					else
						errormsg(SH_DICT, ERROR_exit(1), e_option, argv[1]);
		}
			}
			troot = tdata.sh->track_tree;
		}
	}
	return(setall(argv,flag,troot,&tdata));
}


#if 0
    /* for the dictionary generator */
    int    b_local(int argc,char *argv[],Shbltin_t *context){}
#endif
int    b_typeset(int argc,register char *argv[],Shbltin_t *context)
{
	register int	n, flag = NV_VARNAME|NV_ASSIGN;
	struct tdata	tdata;
	const char	*optstring = sh_opttypeset;
	Namdecl_t 	*ntp = (Namdecl_t*)context->ptr;
	Dt_t		*troot;
	int		isfloat=0, shortint=0, sflag=0;
	NOT_USED(argc);
	memset((void*)&tdata,0,sizeof(tdata));
	tdata.sh = context->shp;
	if(ntp)
	{
		tdata.tp = ntp->tp;
		opt_info.disc = (Optdisc_t*)ntp->optinfof;
		optstring = ntp->optstring;
	}
	troot = tdata.sh->var_tree;
	while((n = optget(argv,optstring)))
	{
		if(tdata.aflag==0)
			tdata.aflag = *opt_info.option;
		switch(n)
		{
			case 'a':
				flag |= NV_IARRAY;
				if(opt_info.arg && *opt_info.arg!='[')
				{
					opt_info.index--;
					goto endargs;
				}
				tdata.tname = opt_info.arg;
				break;
			case 'A':
				flag |= NV_ARRAY;
				break;
			case 'C':
				flag |= NV_COMVAR;
				break;
			case 'E':
				/* The following is for ksh88 compatibility */
				if(opt_info.offset && !strchr(argv[opt_info.index],'E'))
				{
					tdata.argnum = (int)opt_info.num;
					break;
				}
				/* FALLTHROUGH */
			case 'F':
			case 'X':
				if(!opt_info.arg || (tdata.argnum = opt_info.num) <0)
					tdata.argnum = (n=='X'?2*sizeof(Sfdouble_t):10);
				isfloat = 1;
				if(n=='E')
				{
					flag &= ~NV_HEXFLOAT;
					flag |= NV_EXPNOTE;
				}
				else if(n=='X')
				{
					flag &= ~NV_EXPNOTE;
					flag |= NV_HEXFLOAT;
				}
				break;
			case 'b':
				flag |= NV_BINARY;
				break;
			case 'm':
				flag |= NV_MOVE;
				break;
			case 'n':
				flag &= ~NV_VARNAME;
				flag |= (NV_REF|NV_IDENT);
				break;
			case 'H':
				flag |= NV_HOST;
				break;
			case 'T':
				flag |= NV_TYPE;
				tdata.prefix = opt_info.arg;
				break;
			case 'L': case 'Z': case 'R':
				if(tdata.argnum==0)
					tdata.argnum = (int)opt_info.num;
				if(tdata.argnum < 0)
					errormsg(SH_DICT,ERROR_exit(1), e_badfield, tdata.argnum);
				if(n=='Z')
					flag |= NV_ZFILL;
				else
				{
					flag &= ~(NV_LJUST|NV_RJUST);
					flag |= (n=='L'?NV_LJUST:NV_RJUST);
				}
				break;
			case 'M':
				if((tdata.wctname = opt_info.arg) && !nv_mapchar((Namval_t*)0,tdata.wctname))
					errormsg(SH_DICT, ERROR_exit(1),e_unknownmap, tdata.wctname);
				if(tdata.wctname && strcmp(tdata.wctname,e_tolower)==0)
					flag |= NV_UTOL;
				else
					flag |= NV_LTOU;
				if(!tdata.wctname)
					flag |= NV_UTOL;
				break;
			case 'f':
				flag &= ~(NV_VARNAME|NV_ASSIGN);
				troot = tdata.sh->fun_tree;
				break;
			case 'i':
				if(!opt_info.arg || (tdata.argnum = opt_info.num) <0)
					tdata.argnum = 10;
				flag |= NV_INTEGER;
				break;
			case 'l':
				tdata.wctname = e_tolower;
				flag |= NV_UTOL;
				break;
			case 'p':
				tdata.prefix = argv[0];
				tdata.pflag = 1;
				flag &= ~NV_ASSIGN;
				break;
			case 'r':
				flag |= NV_RDONLY;
				break;
#ifdef SHOPT_TYPEDEF
			case 'S':
				sflag=1;
				break;
			case 'h':
				tdata.help = opt_info.arg;
				break;
#endif /*SHOPT_TYPEDEF*/
			case 's':
				shortint=1;
				break;
			case 't':
				flag |= NV_TAGGED;
				break;
			case 'u':
				tdata.wctname = e_toupper;
				flag |= NV_LTOU;
				break;
			case 'x':
				flag &= ~NV_VARNAME;
				flag |= (NV_EXPORT|NV_IDENT);
				break;
			case ':':
				errormsg(SH_DICT,2, "%s", opt_info.arg);
				break;
			case '?':
				errormsg(SH_DICT,ERROR_usage(0), "%s", opt_info.arg);
				opt_info.disc = 0;
				return(2);
		}
	}
endargs:
	argv += opt_info.index;
	opt_info.disc = 0;
	/* handle argument of + and - specially */
	if(*argv && argv[0][1]==0 && (*argv[0]=='+' || *argv[0]=='-'))
		tdata.aflag = *argv[0];
	else
		argv--;
	if((flag&NV_ZFILL) && !(flag&NV_LJUST))
		flag |= NV_RJUST;
	if((flag&NV_INTEGER) && (flag&(NV_LJUST|NV_RJUST|NV_ZFILL)))
		error_info.errors++;
	if((flag&NV_BINARY) && (flag&(NV_LJUST|NV_UTOL|NV_LTOU)))
		error_info.errors++;
	if((flag&NV_MOVE) && (flag&~(NV_MOVE|NV_VARNAME|NV_ASSIGN)))
		error_info.errors++;
	if((flag&NV_REF) && (flag&~(NV_REF|NV_IDENT|NV_ASSIGN)))
		error_info.errors++;
	if((flag&NV_TYPE) && (flag&~(NV_TYPE|NV_VARNAME|NV_ASSIGN)))
		error_info.errors++;
	if(troot==tdata.sh->fun_tree && ((isfloat || flag&~(NV_FUNCT|NV_TAGGED|NV_EXPORT|NV_LTOU))))
		error_info.errors++;
	if(sflag && troot==tdata.sh->fun_tree)
	{
		/* static function */
		sflag = 0;
		flag |= NV_STATICF;
	}
	if(error_info.errors)
		errormsg(SH_DICT,ERROR_usage(2),"%s", optusage(NIL(char*)));
	if(sizeof(char*)<8 && tdata.argnum > SHRT_MAX)
		errormsg(SH_DICT,ERROR_exit(2),"option argument cannot be greater than %d",SHRT_MAX);
	if(isfloat)
		flag |= NV_DOUBLE;
	if(shortint)
	{
		flag &= ~NV_LONG;
		flag |= NV_SHORT|NV_INTEGER;
	}
	if(sflag)
	{
		if(tdata.sh->mktype)
			flag |= NV_REF|NV_TAGGED;
		else if(!tdata.sh->typeinit)
			flag |= NV_STATIC|NV_IDENT;
	}
	if(tdata.sh->fn_depth && !tdata.pflag)
		flag |= NV_NOSCOPE;
	if(tdata.help)
		tdata.help = strdup(tdata.help);
	if(flag&NV_TYPE)
	{
		Stk_t *stkp = tdata.sh->stk;
		int off=0,offset = stktell(stkp);
		if(!tdata.prefix)
			return(sh_outtype(tdata.sh,sfstdout));
		sfputr(stkp,NV_CLASS,-1);
#if SHOPT_NAMESPACE
		if(tdata.sh->namespace)
		{
			off = stktell(stkp)+1;
			sfputr(stkp,nv_name(tdata.sh->namespace),'.');
		}
		else
#endif /* SHOPT_NAMESPACE */
		if(NV_CLASS[sizeof(NV_CLASS)-2]!='.')
			sfputc(stkp,'.');
		sfputr(stkp,tdata.prefix,0);
		tdata.tp = nv_open(stkptr(stkp,offset),tdata.sh->var_tree,NV_VARNAME|NV_NOARRAY|NV_NOASSIGN);
#if SHOPT_NAMESPACE
		if(!tdata.tp && off)
		{
			*stkptr(stkp,off)=0;
			tdata.tp = nv_open(stkptr(stkp,offset),tdata.sh->var_tree,NV_VARNAME|NV_NOARRAY|NV_NOASSIGN);
		}
#endif /* SHOPT_NAMESPACE */
		stkseek(stkp,offset);
		if(!tdata.tp)
			errormsg(SH_DICT,ERROR_exit(1),"%s: unknown type",tdata.prefix);
		else if(nv_isnull(tdata.tp))
			nv_newtype(tdata.tp);
		tdata.tp->nvenv = tdata.help;
		flag &= ~NV_TYPE;
		if(nv_isattr(tdata.tp,NV_TAGGED))
		{
			nv_offattr(tdata.tp,NV_TAGGED);
			return(0);
		}
	}
	else if(tdata.aflag==0 && ntp && ntp->tp)
		tdata.aflag = '-';
	if(!tdata.sh->mktype)
		tdata.help = 0;
	if(tdata.aflag=='+' && (flag&(NV_ARRAY|NV_IARRAY|NV_COMVAR)) && argv[1])
		errormsg(SH_DICT,ERROR_exit(1),e_nounattr);
	return(setall(argv,flag,troot,&tdata));
}

static void print_value(Sfio_t *iop, Namval_t *np, struct tdata *tp)
{
	char	 *name;
	int	aflag=tp->aflag;
	if(nv_isnull(np))
	{
		if(!np->nvflag)
			return;
		aflag = '+';
	}
	else if(nv_istable(np))
	{
		Dt_t	*root = tp->sh->last_root;
		Namval_t *nsp = tp->sh->namespace;
		char *cp;
		if(!tp->pflag)
			return;
		cp = name = nv_name(np);
		if(*name=='.')
			name++;
		if(tp->indent)
			sfnputc(iop,'\t',tp->indent);
		sfprintf(iop,"namespace %s\n", name);
		if(tp->indent)
			sfnputc(iop,'\t',tp->indent);
		sfprintf(iop,"{\n", name);
		tp->indent++;
		/* output types from namespace */
		tp->sh->namespace = 0;
		tp->sh->prefix = nv_name(np)+1;
		sh_outtype(tp->sh,iop);
		tp->sh->prefix = 0;
		tp->sh->namespace = np;
		tp->sh->last_root = root;
		/* output variables from namespace */
		print_scan(iop,NV_NOSCOPE,nv_dict(np),aflag=='+',tp);
		tp->wctname = cp;
		tp->sh->namespace = 0;
		/* output functions from namespace */
		print_scan(iop,NV_FUNCTION|NV_NOSCOPE,tp->sh->fun_tree,aflag=='+',tp);
		tp->wctname = 0;
		tp->sh->namespace = nsp;
		if(--tp->indent)
			sfnputc(iop,'\t',tp->indent);
		sfwrite(iop,"}\n",2);
		return;
	}
	sfputr(iop,nv_name(np),aflag=='+'?'\n':'=');
	if(aflag=='+')
		return;
	if(nv_isarray(np) && nv_arrayptr(np))
	{
		nv_outnode(np,iop,-1,0);
		sfwrite(iop,")\n",2);
	}
	else
	{
		if(nv_isvtree(np))
			nv_onattr(np,NV_EXPORT);
		if(!(name = nv_getval(np)))
			name = Empty;
		if(!nv_isvtree(np))
			name = sh_fmtq(name);
		sfputr(iop,name,'\n');
	}
}

static int     setall(char **argv,register int flag,Dt_t *troot,struct tdata *tp)
{
	register char *name;
	char *last = 0;
	int nvflags=(flag&(NV_ARRAY|NV_NOARRAY|NV_VARNAME|NV_IDENT|NV_ASSIGN|NV_STATIC|NV_MOVE));
	int r=0, ref=0, comvar=(flag&NV_COMVAR),iarray=(flag&NV_IARRAY);
	Shell_t *shp =tp->sh;
	if(!shp->prefix)
	{
		if(!tp->pflag)
			nvflags |= NV_NOSCOPE;
	}
	else if(*shp->prefix==0)
		shp->prefix = 0;
	if(*argv[0]=='+')
		nvflags |= NV_NOADD;
	flag &= ~(NV_NOARRAY|NV_NOSCOPE|NV_VARNAME|NV_IDENT|NV_STATIC|NV_COMVAR|NV_IARRAY);
	if(argv[1])
	{
		if(flag&NV_REF)
		{
			flag &= ~NV_REF;
			ref=1;
			if(tp->aflag!='-')
				nvflags |= NV_NOREF;
		}
		if(tp->pflag)
			nvflags |= (NV_NOREF|NV_NOADD|NV_NOFAIL);
		while(name = *++argv)
		{
			register unsigned newflag;
			register Namval_t *np;
			Namarr_t	*ap;
			Namval_t	*mp;
			unsigned curflag;
			if(troot == shp->fun_tree)
			{
				/*
				 *functions can be exported or
				 * traced but not set
				 */
				flag &= ~NV_ASSIGN;
				if(flag&NV_LTOU)
				{
					/* Function names cannot be special builtin */
					if((np=nv_search(name,shp->bltin_tree,0)) && nv_isattr(np,BLT_SPC))
						errormsg(SH_DICT,ERROR_exit(1),e_badfun,name);
#if SHOPT_NAMESPACE
					if(shp->namespace)
						np = sh_fsearch(shp,name,NV_ADD|HASH_NOSCOPE);
					else
#endif /* SHOPT_NAMESPACE */
					np = nv_open(name,sh_subfuntree(1),NV_NOARRAY|NV_IDENT|NV_NOSCOPE);
				}
				else 
				{
					if(shp->prefix)
					{
						sfprintf(shp->strbuf,"%s.%s%c",shp->prefix,name,0);
						name = sfstruse(shp->strbuf);
					}
#if SHOPT_NAMESPACE
					np = 0;
					if(shp->namespace)
						np = sh_fsearch(shp,name,HASH_NOSCOPE);
					if(!np)
#endif /* SHOPT_NAMESPACE */
					if(np=nv_search(name,troot,0))
					{
						if(!is_afunction(np))
							np = 0;
					}
					else if(memcmp(name,".sh.math.",9)==0 && sh_mathstd(name+9))
						continue;
				}
				if(np && ((flag&NV_LTOU) || !nv_isnull(np) || nv_isattr(np,NV_LTOU)))
				{
					if(flag==0 && !tp->help)
					{
						print_namval(sfstdout,np,tp->aflag=='+',tp);
						continue;
					}
					if(shp->subshell && !shp->subshare)
						sh_subfork();
					if(tp->aflag=='-')
						nv_onattr(np,flag|NV_FUNCTION);
					else if(tp->aflag=='+')
						nv_offattr(np,flag);
				}
				else
					r++;
				if(tp->help)
				{
					int offset = stktell(shp->stk);
					if(!np)
					{
						sfputr(shp->stk,shp->prefix,'.');
						sfputr(shp->stk,name,0);
						np = nv_search(stkptr(shp->stk,offset),troot,0);
						stkseek(shp->stk,offset);
					}
					if(np && np->nvalue.cp) 
						np->nvalue.rp->help = tp->help;
				}
				continue;
			}
			/* tracked alias */
			if(troot==shp->track_tree && tp->aflag=='-')
			{
				np = nv_search(name,troot,NV_ADD);
				path_alias(np,path_absolute(shp,nv_name(np),NIL(Pathcomp_t*)));
				continue;
			}
			np = nv_open(name,troot,nvflags|((nvflags&NV_ASSIGN)?0:NV_ARRAY)|((iarray|(nvflags&(NV_REF|NV_NOADD)==NV_REF))?NV_FARRAY:0));
			if(!np)
				continue;
			if(nv_isnull(np) && !nv_isarray(np) && nv_isattr(np,NV_NOFREE))
				nv_offattr(np,NV_NOFREE);
			else if(tp->tp && !nv_isattr(np,NV_MINIMAL|NV_EXPORT) && (mp=(Namval_t*)np->nvenv) && (ap=nv_arrayptr(mp)) && (ap->nelem&ARRAY_TREE))
				errormsg(SH_DICT,ERROR_exit(1),e_typecompat,nv_name(np));
			else if((ap=nv_arrayptr(np)) && nv_aindex(np)>0 && ap->nelem==1 && nv_getval(np)==Empty)
			{
				ap->nelem++;
				_nv_unset(np,0);
				ap->nelem--;
			}
			else if(iarray && ap && ap->fun) 
				errormsg(SH_DICT,ERROR_exit(1),"cannot change associative array %s to index array",nv_name(np));
			else if( (iarray||(flag&NV_ARRAY)) && nv_isvtree(np) && !nv_type(np))
				_nv_unset(np,NV_EXPORT);
			if(tp->pflag)
			{
				if(!nv_istable(np))
					nv_attribute(np,sfstdout,tp->prefix,1);
				print_value(sfstdout,np,tp);
				continue;
			}
			if(flag==NV_ASSIGN && !ref && tp->aflag!='-' && !strchr(name,'='))
			{
				if(troot!=shp->var_tree && (nv_isnull(np) || !print_namval(sfstdout,np,0,tp)))
				{
					sfprintf(sfstderr,sh_translate(e_noalias),name);
					r++;
				}
				if(!comvar && !iarray)
					continue;
			}
			if(!nv_isarray(np) && !strchr(name,'=') && !(shp->envlist  && nv_onlist(shp->envlist,name)))
			{
				if(comvar || (shp->last_root==shp->var_tree && (tp->tp || (!shp->st.real_fun && (nvflags&NV_STATIC)) || (!(flag&(NV_EXPORT|NV_RDONLY)) && nv_isattr(np,(NV_EXPORT|NV_IMPORT))==(NV_EXPORT|NV_IMPORT)))))
{
					_nv_unset(np,0);
}
			}
			if(troot==shp->var_tree)
			{
				if(iarray)
				{
					if(tp->tname)
						nv_atypeindex(np,tp->tname+1);
					else if(nv_isnull(np))
						nv_onattr(np,NV_ARRAY|(comvar?NV_NOFREE:0));
					else
					{
						if(ap && comvar)
							ap->nelem |= ARRAY_TREE;
						nv_putsub(np, (char*)0, 0);
					}
				}
				else if(nvflags&NV_ARRAY)
				{
					if(comvar)
					{
						Namarr_t *ap=nv_arrayptr(np);
						if(ap)
							ap->nelem |= ARRAY_TREE;
						else
						{
							_nv_unset(np,NV_RDONLY);
							nv_onattr(np,NV_NOFREE);
						}
					}
					nv_setarray(np,nv_associative);
				}
				else if(comvar && !nv_isvtree(np) && !nv_rename(np,flag|NV_COMVAR))
					nv_setvtree(np);
			}
			if(flag&NV_MOVE)
			{
				nv_rename(np, flag);
				nv_close(np);
				continue;
			}
			if(tp->tp && nv_type(np)!=tp->tp)
			{
				nv_settype(np,tp->tp,tp->aflag=='-'?0:NV_APPEND);
				flag = (np->nvflag&NV_NOCHANGE);
			}
			flag &= ~NV_ASSIGN;
			if(last=strchr(name,'='))
				*last = 0;
			if (shp->typeinit)
				continue;
			curflag = np->nvflag;
			if(!(flag&NV_INTEGER) && (flag&(NV_LTOU|NV_UTOL)))
			{
				Namfun_t *fp;
				char  *cp;
				if(!tp->wctname)
					errormsg(SH_DICT,ERROR_exit(1),e_mapchararg,nv_name(np));
				cp = (char*)nv_mapchar(np,0);
				if(fp=nv_mapchar(np,tp->wctname))
				{
					if(tp->aflag=='+')
					{
						if(cp && strcmp(cp,tp->wctname)==0)
						{
							nv_disc(np,fp,NV_POP);
							if(!(fp->nofree&1))
								free((void*)fp);
							nv_offattr(np,flag&(NV_LTOU|NV_UTOL));
						}
					}
					else if(!cp || strcmp(cp,tp->wctname))
					{
						nv_disc(np,fp,NV_LAST);
						nv_onattr(np,flag&(NV_LTOU|NV_UTOL));
					}
				}
			}
			if (tp->aflag == '-')
			{
				if((flag&NV_EXPORT) && (strchr(name,'.') || nv_isvtree(np)))
					errormsg(SH_DICT,ERROR_exit(1),e_badexport,name);
#if SHOPT_BSH
				if(flag&NV_EXPORT)
					nv_offattr(np,NV_IMPORT);
#endif /* SHOPT_BSH */
				newflag = curflag;
				if(flag&~NV_NOCHANGE)
					newflag &= NV_NOCHANGE;
				newflag |= flag;
				if (flag & (NV_LJUST|NV_RJUST))
				{
					if(!(flag&NV_RJUST))
						newflag &= ~NV_RJUST;
					
					else if(!(flag&NV_LJUST))
						newflag &= ~NV_LJUST;
				}
			}
			else
			{
				if((flag&NV_RDONLY) && (curflag&NV_RDONLY))
					errormsg(SH_DICT,ERROR_exit(1),e_readonly,nv_name(np));
				newflag = curflag & ~flag;
			}
			if (tp->aflag && (tp->argnum>0 || (curflag!=newflag)))
			{
				if(shp->subshell)
					sh_assignok(np,1);
				if(troot!=shp->var_tree)
					nv_setattr(np,newflag&~NV_ASSIGN);
				else
				{
					char *oldname=0;
					int len=strlen(name);
					if(tp->argnum==1 && newflag==NV_INTEGER && nv_isattr(np,NV_INTEGER))
						tp->argnum = 10;
					if(np->nvfun && !nv_isarray(np) && name[len-1]=='.')
						newflag |= NV_NODISC;
					nv_newattr (np, newflag&~NV_ASSIGN,tp->argnum);
					if(oldname)
						np->nvname = oldname;
				}
			}
			if(tp->help && !nv_isattr(np,NV_MINIMAL|NV_EXPORT))
			{
				np->nvenv = tp->help;
				nv_onattr(np,NV_EXPORT);
			}
			if(last)
				*last = '=';
			/* set or unset references */
			if(ref)
			{
				if(tp->aflag=='-')
				{
					Dt_t *hp=0;
					if(nv_isattr(np,NV_PARAM) && shp->st.prevst)
					{
						if(!(hp=(Dt_t*)shp->st.prevst->save_tree))
							hp = dtvnext(shp->var_tree);
					}
					if(tp->sh->mktype)
						nv_onattr(np,NV_REF|NV_FUNCT);
					else
						nv_setref(np,hp,NV_VARNAME);
				}
				else
					nv_unref(np);
			}
			nv_close(np);
		}
	}
	else
	{
		if(shp->prefix)
			errormsg(SH_DICT,2, e_subcomvar,shp->prefix);
		if(tp->aflag)
		{
			if(troot==shp->fun_tree)
			{
				flag |= NV_FUNCTION;
				tp->prefix = 0;
			}
			else if(troot==shp->var_tree)
			{
				flag |= (nvflags&NV_ARRAY);
				if(iarray)
					flag |= NV_ARRAY|NV_IARRAY;
				if(comvar)
					flag |= NV_TABLE;
				if(!(flag&~NV_ASSIGN))
					tp->noref = 1;
			}
			if((flag&(NV_UTOL|NV_LTOU)) ==(NV_UTOL|NV_LTOU))
			{
				print_scan(sfstdout,flag&~NV_UTOL,troot,tp->aflag=='+',tp);
				flag &= ~NV_LTOU;
			}
			print_scan(sfstdout,flag,troot,tp->aflag=='+',tp);
			if(tp->noref)
			{
				tp->noref = 0;
				print_scan(sfstdout,flag|NV_REF,troot,tp->aflag=='+',tp);
			}
		}
		else if(troot==shp->alias_tree)
			print_scan(sfstdout,0,troot,0,tp);
		else
			print_all(sfstdout,troot,tp);
		sfsync(sfstdout);
	}
	return(r);
}

#if SHOPT_DYNAMIC

typedef void (*Libinit_f)(int,void*);

typedef struct Libcomp_s
{
	void*		dll;
	char*		lib;
	dev_t		dev;
	ino_t		ino;
	unsigned int	attr;
} Libcomp_t;

#define GROWLIB	4

static Libcomp_t	*liblist;
static int		nlib;
static int		maxlib;

/*
 * add library to loaded list
 * call (*lib_init)() on first load if defined
 * always move to head of search list
 * return: 0: already loaded 1: first load
 */

int sh_addlib(Shell_t* shp, void* dll, char* name, Pathcomp_t* pp)
{
	register int	n;
	register int	r;
	Libinit_f	initfn;
	Shbltin_t	*sp = &shp->bltindata;

	sp->nosfio = 0;
	for (n = r = 0; n < nlib; n++)
	{
		if (r)
			liblist[n-1] = liblist[n];
		else if (liblist[n].dll == dll)
			r++;
	}
	if (r)
		nlib--;
	else if ((initfn = (Libinit_f)dlllook(dll, "lib_init")))
		(*initfn)(0,sp);
	if (nlib >= maxlib)
	{
		maxlib += GROWLIB;
		liblist = newof(liblist, Libcomp_t, maxlib+1, 0);
	}
	liblist[nlib].dll = dll;
	liblist[nlib].attr = (sp->nosfio?BLT_NOSFIO:0);
	if (name)
		liblist[nlib].lib = strdup(name);
	if (pp)
	{
		liblist[nlib].dev = pp->dev;
		liblist[nlib].ino = pp->ino;
	}
	nlib++;
	return !r;
}

Shbltin_f sh_getlib(Shell_t* shp, char* sym, Pathcomp_t* pp)
{
	register int	n;

	for (n = 0; n < nlib; n++)
		if (liblist[n].ino == pp->ino && liblist[n].dev == pp->dev)
			return (Shbltin_f)dlllook(liblist[n].dll, sym);
	return 0;
}

#else

int sh_addlib(Shell_t* shp, void* library, char* name, Pathcomp_t* pp)
{
	return 0;
}

Shbltin_f sh_getlib(Shell_t* shp, char* name, Pathcomp_t* pp)
{
	return 0;
}

#endif /* SHOPT_DYNAMIC */

/*
 * add change or list built-ins
 * adding builtins requires dlopen() interface
 */
int	b_builtin(int argc,char *argv[],Shbltin_t *context)
{
	register char *arg=0, *name;
	register int n, r=0, flag=0;
	register Namval_t *np;
	long dlete=0;
	struct tdata tdata;
	Shbltin_f addr;
	Stk_t	*stkp;
	void *library=0;
	char *errmsg;
#ifdef SH_PLUGIN_VERSION
	unsigned long ver;
	int list = 0;
	char path[1024];
#endif
	NOT_USED(argc);
	memset(&tdata,0,sizeof(tdata));
	tdata.sh = context->shp;
	stkp = tdata.sh->stk;
	if(!tdata.sh->pathlist)
		path_absolute(tdata.sh,argv[0],NIL(Pathcomp_t*));
	while (n = optget(argv,sh_optbuiltin)) switch (n)
	{
	    case 's':
		flag = BLT_SPC;
		break;
	    case 'd':
		dlete=1;
		break;
	    case 'f':
#if SHOPT_DYNAMIC
		arg = opt_info.arg;
#else
		errormsg(SH_DICT,2, "adding built-ins not supported");
		error_info.errors++;
#endif /* SHOPT_DYNAMIC */
		break;
	    case 'l':
#ifdef SH_PLUGIN_VERSION
		list = 1;
#endif
	        break;
	    case ':':
		errormsg(SH_DICT,2, "%s", opt_info.arg);
		break;
	    case '?':
		errormsg(SH_DICT,ERROR_usage(2), "%s", opt_info.arg);
		break;
	}
	argv += opt_info.index;
	if(error_info.errors)
		errormsg(SH_DICT,ERROR_usage(2),"%s", optusage(NIL(char*)));
	if(arg || *argv)
	{
		if(sh_isoption(SH_RESTRICTED))
			errormsg(SH_DICT,ERROR_exit(1),e_restricted,argv[-opt_info.index]);
		if(sh_isoption(SH_PFSH))
			errormsg(SH_DICT,ERROR_exit(1),e_pfsh,argv[-opt_info.index]);
		if(tdata.sh->subshell && !tdata.sh->subshare)
			sh_subfork();
	}
#if SHOPT_DYNAMIC
	if(arg)
	{
#ifdef SH_PLUGIN_VERSION
		if(!(library = dllplugin(SH_ID, arg, NiL, SH_PLUGIN_VERSION, &ver, RTLD_LAZY, path, sizeof(path))))
		{
			errormsg(SH_DICT,ERROR_exit(0),"%s: %s",arg,dllerror(0));
			return(1);
		}
		if(list)
			sfprintf(sfstdout, "%s %08lu %s\n", arg, ver, path);
#else
#if (_AST_VERSION>=20040404)
		if(!(library = dllplug(SH_ID,arg,NIL(char*),RTLD_LAZY,NIL(char*),0)))
#else
		if(!(library = dllfind(arg,NIL(char*),RTLD_LAZY,NIL(char*),0)))
#endif
		{
			errormsg(SH_DICT,ERROR_exit(0),"%s: %s",arg,dlerror());
			return(1);
		}
#endif
		sh_addlib(tdata.sh,library,arg,NiL);
	}
	else
#endif /* SHOPT_DYNAMIC */
	if(*argv==0 && !dlete)
	{
		print_scan(sfstdout, flag, tdata.sh->bltin_tree, 1, &tdata);
		return(0);
	}
	r = 0;
	flag = stktell(stkp);
	while(arg = *argv)
	{
		name = path_basename(arg);
		sfwrite(stkp,"b_",2);
		sfputr(stkp,name,0);
		errmsg = 0;
		addr = 0;
		if(dlete || liblist)
			for(n=(nlib?nlib:dlete); --n>=0;)
			{
#if SHOPT_DYNAMIC
				if(!dlete && !liblist[n].dll)
					continue;
				if(dlete || (addr = (Shbltin_f)dlllook(liblist[n].dll,stkptr(stkp,flag))))
#else
				if(dlete)
#endif /* SHOPT_DYNAMIC */
				{
					if(np = sh_addbuiltin(arg, addr,pointerof(dlete)))
					{
						if(dlete || nv_isattr(np,BLT_SPC))
							errmsg = "restricted name";
#if SHOPT_DYNAMIC
						else
							nv_onattr(np,liblist[n].attr);
#endif /* SHOPT_DYNAMIC */
					}
					break;
				}
			}
		if(!addr && (np = nv_search(arg,context->shp->bltin_tree,0)))
		{
			if(nv_isattr(np,BLT_SPC))
				errmsg = "restricted name";
			addr = (Shbltin_f)np->nvalue.bfp;
		}
		if(!dlete && !addr && !(np=sh_addbuiltin(arg,(Shbltin_f)0 ,0)))
			errmsg = "not found";
		if(errmsg)
		{
			errormsg(SH_DICT,ERROR_exit(0),"%s: %s",*argv,errmsg);
			r = 1;
		}
		stkseek(stkp,flag);
		argv++;
	}
	return(r);
}

int    b_set(int argc,register char *argv[],Shbltin_t *context)
{
	struct tdata tdata;
	int was_monitor = sh_isoption(SH_MONITOR);
	memset(&tdata,0,sizeof(tdata));
	tdata.sh = context->shp;
	tdata.prefix=0;
	if(argv[1])
	{
		if(sh_argopts(argc,argv,tdata.sh) < 0)
			return(2);
		if(sh_isoption(SH_VERBOSE))
			sh_onstate(SH_VERBOSE);
		else
			sh_offstate(SH_VERBOSE);
		if(sh_isoption(SH_MONITOR) && !was_monitor)
			sh_onstate(SH_MONITOR);
		else if(!sh_isoption(SH_MONITOR)  && was_monitor)
			sh_offstate(SH_MONITOR);
	}
	else
		/*scan name chain and print*/
		print_scan(sfstdout,0,tdata.sh->var_tree,0,&tdata);
	return(0);
}

/*
 * The removing of Shell variable names, aliases, and functions
 * is performed here.
 * Unset functions with unset -f
 * Non-existent items being deleted give non-zero exit status
 */

int    b_unalias(int argc,register char *argv[],Shbltin_t *context)
{
	Shell_t *shp = context->shp;
	return(unall(argc,argv,shp->alias_tree,shp));
}

int    b_unset(int argc,register char *argv[],Shbltin_t *context)
{
	Shell_t *shp = context->shp;
	return(unall(argc,argv,shp->var_tree,shp));
}

static int unall(int argc, char **argv, register Dt_t *troot, Shell_t* shp)
{
	register Namval_t *np;
	register const char *name;
	volatile int r;
	Dt_t	*dp;
	int nflag=0,all=0,isfun,jmpval;
	struct checkpt buff;
	NOT_USED(argc);
	if(troot==shp->alias_tree)
	{
		name = sh_optunalias;
		if(shp->subshell)
			troot = sh_subaliastree(0);
	}
	else
		name = sh_optunset;
	while(r = optget(argv,name)) switch(r)
	{
		case 'f':
			troot = sh_subfuntree(1);
			break;
		case 'a':
			all=1;
			break;
		case 'n':
			nflag = NV_NOREF;
			/* FALLTHROUGH */
		case 'v':
			troot = shp->var_tree;
			break;
		case ':':
			errormsg(SH_DICT,2, "%s", opt_info.arg);
			break;
		case '?':
			errormsg(SH_DICT,ERROR_usage(0), "%s", opt_info.arg);
			return(2);
	}
	argv += opt_info.index;
	if(error_info.errors || (*argv==0 &&!all))
		errormsg(SH_DICT,ERROR_usage(2),"%s",optusage(NIL(char*)));
	if(!troot)
		return(1);
	r = 0;
	if(troot==shp->var_tree)
		nflag |= NV_VARNAME;
	else
		nflag = NV_NOSCOPE;
	if(all)
	{
		dtclear(troot);
		return(r);
	}
	sh_pushcontext(shp,&buff,1);
	while(name = *argv++)
	{
		jmpval = sigsetjmp(buff.buff,0);
		np = 0;
		if(jmpval==0)
		{
#if SHOPT_NAMESPACE
			if(shp->namespace && troot!=shp->var_tree)
				np = sh_fsearch(shp,name,nflag?HASH_NOSCOPE:0);
			if(!np)
#endif /* SHOPT_NAMESPACE */
			np=nv_open(name,troot,NV_NOADD|nflag);
		}
		else
		{
			r = 1;
			continue;
		}
		if(np)
		{
			if(is_abuiltin(np) || nv_isattr(np,NV_RDONLY))
			{
				if(nv_isattr(np,NV_RDONLY))
					errormsg(SH_DICT,ERROR_warn(0),e_readonly, nv_name(np));
				r = 1;
				continue;
			}
			isfun = is_afunction(np);
			if(troot==shp->var_tree)
			{
				Namarr_t *ap;
#if SHOPT_FIXEDARRAY
				if((ap=nv_arrayptr(np)) && !ap->fixed  && name[strlen(name)-1]==']' && !nv_getsub(np))
#else
				if(nv_isarray(np) && name[strlen(name)-1]==']' && !nv_getsub(np))
#endif /* SHOPT_FIXEDARRAY */
				{
					r=1;
					continue;
				}
					
				if(shp->subshell)
					np=sh_assignok(np,0);
			}
			if(!nv_isnull(np) || nv_size(np) || nv_isattr(np,~(NV_MINIMAL|NV_NOFREE)))
				_nv_unset(np,0);
			if(troot==shp->var_tree && shp->st.real_fun && (dp=shp->var_tree->walk) && dp==shp->st.real_fun->sdict)
				nv_delete(np,dp,NV_NOFREE);
			else if(isfun && !(np->nvalue.rp && np->nvalue.rp->running))
				nv_delete(np,troot,0);
#if 0
			/* causes unsetting local variable to expose global */
			else if(shp->var_tree==troot && shp->var_tree!=shp->var_base && nv_search((char*)np,shp->var_tree,HASH_BUCKET|HASH_NOSCOPE))
				nv_delete(np,shp->var_tree,0);
#endif
			else
				nv_close(np);

		}
		else if(troot==shp->alias_tree)
			r = 1;
	}
	sh_popcontext(shp,&buff);
	return(r);
}

/*
 * print out the name and value of a name-value pair <np>
 */

static int print_namval(Sfio_t *file,register Namval_t *np,register int flag, struct tdata *tp)
{
	register char *cp;
	int	indent=tp->indent, outname=0, isfun;
	sh_sigcheck(tp->sh);
	if(flag)
		flag = '\n';
	if(tp->noref && nv_isref(np))
		return(0);
	if(nv_isattr(np,NV_NOPRINT|NV_INTEGER)==NV_NOPRINT)
	{
		if(is_abuiltin(np) && strcmp(np->nvname,".sh.tilde"))
			sfputr(file,nv_name(np),'\n');
		return(0);
	}
	if(nv_istable(np))
	{
		print_value(file,np,tp);
		return(0);
	}
	isfun = is_afunction(np);
	if(tp->prefix)
	{
		outname = (*tp->prefix=='t' &&  (!nv_isnull(np) || nv_isattr(np,NV_FLOAT|NV_RDONLY|NV_BINARY|NV_RJUST|NV_NOPRINT)));
		if(indent && (isfun || outname || *tp->prefix!='t'))
		{
			sfnputc(file,'\t',indent);
			indent = 0;
		}
		if(!isfun)
		{
			if(*tp->prefix=='t')
			nv_attribute(np,tp->outfile,tp->prefix,tp->aflag);
			else
				sfputr(file,tp->prefix,' ');
		}
	}
	if(isfun)
	{
		Sfio_t *iop=0;
		char *fname=0;
		if(nv_isattr(np,NV_NOFREE))
			return(0);
		if(!flag && !np->nvalue.ip)
			sfputr(file,"typeset -fu",' ');
		else if(!flag && !nv_isattr(np,NV_FPOSIX))
			sfputr(file,"function",' ');
		cp = nv_name(np);
		if(tp->wctname)
			cp += strlen(tp->wctname)+1;
		sfputr(file,cp,-1);
		if(nv_isattr(np,NV_FPOSIX))
			sfwrite(file,"()",2);
		if(np->nvalue.ip && np->nvalue.rp->hoffset>=0)
			fname = np->nvalue.rp->fname;
		else
			flag = '\n';
		if(flag)
		{
			if(tp->pflag && np->nvalue.ip && np->nvalue.rp->hoffset>=0)
				sfprintf(file," #line %d %s\n",np->nvalue.rp->lineno,fname?sh_fmtq(fname):"");
			else
				sfputc(file, '\n');
		}
		else
		{
			if(nv_isattr(np,NV_FTMP))
			{
				fname = 0;
				iop = tp->sh->heredocs;
			}
			else if(fname)
				iop = sfopen(iop,fname,"r");
			else if(tp->sh->gd->hist_ptr)
				iop = (tp->sh->gd->hist_ptr)->histfp;
			if(iop && sfseek(iop,(Sfoff_t)np->nvalue.rp->hoffset,SEEK_SET)>=0)
				sfmove(iop,file, nv_size(np), -1);
			else
				flag = '\n';
			if(fname)
				sfclose(iop);
		}
		return(nv_size(np)+1);
	}
	if(nv_arrayptr(np))
	{
		if(indent)
			sfnputc(file,'\t',indent);
		print_value(file,np,tp);
		return(0);
	}
	if(nv_isvtree(np))
		nv_onattr(np,NV_EXPORT);
	if(cp=nv_getval(np))
	{
		if(indent)
			sfnputc(file,'\t',indent);
		sfputr(file,nv_name(np),-1);
		if(!flag)
			flag = '=';
		sfputc(file,flag);
		if(flag != '\n')
		{
			if(nv_isref(np) && nv_refsub(np))
			{
				sfputr(file,sh_fmtq(cp),-1);
				sfprintf(file,"[%s]\n", sh_fmtq(nv_refsub(np)));
			}
			else
#if SHOPT_TYPEDEF
				sfputr(file,nv_isvtree(np)?cp:sh_fmtq(cp),'\n');
#else
				sfputr(file,sh_fmtq(cp),'\n');
#endif /* SHOPT_TYPEDEF */
		}
		return(1);
	}
	else if(outname || (tp->scanmask && tp->scanroot==tp->sh->var_tree))
		sfputr(file,nv_name(np),'\n');
	return(0);
}

/*
 * print attributes at all nodes
 */
static void	print_all(Sfio_t *file,Dt_t *root, struct tdata *tp)
{
	tp->outfile = file;
	nv_scan(root, print_attribute, (void*)tp, 0, 0);
}

/*
 * print the attributes of name value pair give by <np>
 */
static void	print_attribute(register Namval_t *np,void *data)
{
	register struct tdata *dp = (struct tdata*)data;
	nv_attribute(np,dp->outfile,dp->prefix,dp->aflag);
}

/*
 * print the nodes in tree <root> which have attributes <flag> set
 * of <option> is non-zero, no subscript or value is printed.
 */

static void print_scan(Sfio_t *file, int flag, Dt_t *root, int option,struct tdata *tp)
{
	register char **argv;
	register Namval_t *np;
	register int namec;
	Namval_t *onp = 0;
	char	*name=0;
	int	len;
	tp->sh->last_table=0;
	flag &= ~NV_ASSIGN;
	tp->scanmask = flag&~NV_NOSCOPE;
	tp->scanroot = root;
	tp->outfile = file;
#if SHOPT_TYPEDEF
	if(!tp->prefix && tp->tp)
		tp->prefix = nv_name(tp->tp);
#endif /* SHOPT_TYPEDEF */
	if(flag&NV_INTEGER)
		tp->scanmask |= (NV_DOUBLE|NV_EXPNOTE);
	if(flag==NV_LTOU || flag==NV_UTOL)
		tp->scanmask |= NV_UTOL|NV_LTOU;
	namec = nv_scan(root,nullscan,(void*)tp,tp->scanmask,flag);
	argv = tp->argnam  = (char**)stkalloc(tp->sh->stk,(namec+1)*sizeof(char*));
	namec = nv_scan(root, pushname, (void*)tp, tp->scanmask, flag&~NV_IARRAY);
	if(mbcoll())
		strsort(argv,namec,strcoll);
	if(namec==0 && tp->sh->namespace && nv_dict(tp->sh->namespace)==root)
	{
		sfnputc(file,'\t',tp->indent);
		sfwrite(file,":\n",2);
	}
	else while(namec--)
	{
		if((np=nv_search(*argv++,root,0)) && np!=onp && (!nv_isnull(np) || np->nvfun || nv_isattr(np,~NV_NOFREE)))
		{
			onp = np;
			if(name)
			{
				char *newname = nv_name(np);
				if(memcmp(name,newname,len)==0 && newname[len]== '.')
					continue;
				name = 0;
			}
			if(flag&NV_ARRAY)
			{
				if(nv_aindex(np)>=0)
				{
					if(!(flag&NV_IARRAY))
						continue;
				}
				else if((flag&NV_IARRAY))
					continue;
				
			}
			tp->scanmask = flag&~NV_NOSCOPE;
			tp->scanroot = root;
			print_namval(file,np,option,tp);
			if(!is_abuiltin(np) && nv_isvtree(np))
			{
				name = nv_name(np);
				len = strlen(name);
			}
		}
	}
}

/*
 * add the name of the node to the argument list argnam
 */

static void pushname(Namval_t *np,void *data)
{
	struct tdata *tp = (struct tdata*)data;
	*tp->argnam++ = nv_name(np);
}

