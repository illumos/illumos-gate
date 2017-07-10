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
};


static int	print_namval(Sfio_t*, Namval_t*, int, struct tdata*);
static void	print_attribute(Namval_t*,void*);
static void	print_all(Sfio_t*, Dt_t*, struct tdata*);
static void	print_scan(Sfio_t*, int, Dt_t*, int, struct tdata*);
static int	b_unall(int, char**, Dt_t*, Shell_t*);
static int	b_common(char**, int, Dt_t*, struct tdata*);
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
    int    b_export(int argc,char *argv[],void *extra){}
#endif
int    b_readonly(int argc,char *argv[],void *extra)
{
	register int flag;
	char *command = argv[0];
	struct tdata tdata;
	NOT_USED(argc);
	memset((void*)&tdata,0,sizeof(tdata));
	tdata.sh = ((Shbltin_t*)extra)->shp;
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
	return(b_common(argv,flag,tdata.sh->var_tree, &tdata));
}


int    b_alias(int argc,register char *argv[],void *extra)
{
	register unsigned flag = NV_NOARRAY|NV_NOSCOPE|NV_ASSIGN;
	register Dt_t *troot;
	register int n;
	struct tdata tdata;
	NOT_USED(argc);
	memset((void*)&tdata,0,sizeof(tdata));
	tdata.sh = ((Shbltin_t*)extra)->shp;
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
					nv_putval(PATHNOD,nv_getval(PATHNOD),NV_RDONLY);
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
	return(b_common(argv,flag,troot,&tdata));
}


#if 0
    /* for the dictionary generator */
    int    b_local(int argc,char *argv[],void *extra){}
#endif
int    b_typeset(int argc,register char *argv[],void *extra)
{
	register int	n, flag = NV_VARNAME|NV_ASSIGN;
	struct tdata	tdata;
	const char	*optstring = sh_opttypeset;
	Namdecl_t 	*ntp = (Namdecl_t*)((Shbltin_t*)extra)->ptr;
	Dt_t		*troot;
	int		isfloat=0, shortint=0, sflag=0;
	NOT_USED(argc);
	memset((void*)&tdata,0,sizeof(tdata));
	tdata.sh = ((Shbltin_t*)extra)->shp;
	if(ntp)
	{
		tdata.tp = ntp->tp;
		opt_info.disc = (Optdisc_t*)ntp->optinfof;
		optstring = ntp->optstring;
	}
	troot = tdata.sh->var_tree;
	while((n = optget(argv,optstring)))
	{
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
				flag |= NV_UTOL;
				break;
			case 'p':
				tdata.prefix = argv[0];
				tdata.pflag = 1;
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
		if(tdata.aflag==0)
			tdata.aflag = *opt_info.option;
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
	if(troot==tdata.sh->fun_tree && ((isfloat || flag&~(NV_FUNCT|NV_TAGGED|NV_EXPORT|NV_LTOU))))
		error_info.errors++;
	if(error_info.errors)
		errormsg(SH_DICT,ERROR_usage(2),"%s", optusage(NIL(char*)));
	if(isfloat)
		flag |= NV_DOUBLE;
	if(shortint)
		flag |= NV_SHORT|NV_INTEGER;
	if(sflag)
	{
		if(tdata.sh->mktype)
			flag |= NV_REF|NV_TAGGED;
		else if(!tdata.sh->typeinit)
			flag |= NV_STATIC|NV_IDENT;
	}
	if(tdata.sh->fn_depth && !tdata.pflag)
		flag |= NV_NOSCOPE;
	if(flag&NV_TYPE)
	{
		Stk_t *stkp = tdata.sh->stk;
		int offset = stktell(stkp);
		sfputr(stkp,NV_CLASS,-1);
		if(NV_CLASS[sizeof(NV_CLASS)-2]!='.')
			sfputc(stkp,'.');
		sfputr(stkp,tdata.prefix,0);
		tdata.tp = nv_open(stkptr(stkp,offset),tdata.sh->var_tree,NV_VARNAME|NV_NOARRAY|NV_NOASSIGN);
		stkseek(stkp,offset);
		if(!tdata.tp)
			errormsg(SH_DICT,ERROR_exit(1),"%s: unknown type",tdata.prefix);
		else if(nv_isnull(tdata.tp))
			nv_newtype(tdata.tp);
		tdata.tp->nvenv = tdata.help;
		flag &= ~NV_TYPE;
	}
	else if(tdata.aflag==0 && ntp && ntp->tp)
		tdata.aflag = '-';
	if(!tdata.sh->mktype)
		tdata.help = 0;
	return(b_common(argv,flag,troot,&tdata));
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

static int     b_common(char **argv,register int flag,Dt_t *troot,struct tdata *tp)
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
			nvflags |= NV_NOREF;
		while(name = *++argv)
		{
			register unsigned newflag;
			register Namval_t *np;
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
					np = nv_open(name,sh_subfuntree(1),NV_NOARRAY|NV_IDENT|NV_NOSCOPE);
				}
				else  if((np=nv_search(name,troot,0)) && !is_afunction(np))
					np = 0;
				if(np && ((flag&NV_LTOU) || !nv_isnull(np) || nv_isattr(np,NV_LTOU)))
				{
					if(flag==0)
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
					sfputr(shp->stk,shp->prefix,'.');
					sfputr(shp->stk,name,0);
					if((np=nv_search(stkptr(shp->stk,offset),troot,0)) && np->nvalue.cp) 
						np->nvalue.rp->help = tp->help;
					stkseek(shp->stk,offset);
				}
				continue;
			}
			/* tracked alias */
			if(troot==shp->track_tree && tp->aflag=='-')
			{
				np = nv_search(name,troot,NV_ADD);
				path_alias(np,path_absolute(nv_name(np),NIL(Pathcomp_t*)));
				continue;
			}
			np = nv_open(name,troot,nvflags|NV_ARRAY);
			if(tp->pflag)
			{
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
			if(troot==shp->var_tree && ((tp->tp && !nv_isarray(np)) || !shp->st.real_fun && (nvflags&NV_STATIC)) && !strchr(name,'=') && !(shp->envlist  && nv_onlist(shp->envlist,name)))
				_nv_unset(np,0);
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
						Namarr_t *ap=nv_arrayptr(np);
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
			curflag = np->nvflag;
			flag &= ~NV_ASSIGN;
			if(last=strchr(name,'='))
				*last = 0;
			if (shp->typeinit)
				continue;
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
				if(!(flag&NV_INTEGER))
				{
					if (flag & NV_UTOL)
						newflag &= ~NV_LTOU;
					else if (flag & NV_LTOU)
						newflag &= ~NV_UTOL;
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
					/* use reference name for export */
					if((newflag^curflag)&NV_EXPORT)
					{
						oldname = np->nvname;
						np->nvname = name;
					}
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
	else if(!tp->sh->envlist)
	{
		if(shp->prefix)
			errormsg(SH_DICT,2, "%s: compound assignment requires sub-variable name",shp->prefix);
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
				if(flag&NV_IARRAY)
					flag |= NV_ARRAY;
			}
			print_scan(sfstdout,flag,troot,tp->aflag=='+',tp);
		}
		else if(troot==shp->alias_tree)
			print_scan(sfstdout,0,troot,0,tp);
		else
			print_all(sfstdout,troot,tp);
		sfsync(sfstdout);
	}
	return(r);
}

typedef void (*Iptr_t)(int,void*);
typedef int (*Fptr_t)(int, char*[], void*);

#define GROWLIB	4

static void		**liblist;
static unsigned short	*libattr;
static int		nlib;
static int		maxlib;

/*
 * This allows external routines to load from the same library */
void **sh_getliblist(void)
{
	return(liblist);
}

/*
 * add library to loaded list
 * call (*lib_init)() on first load if defined
 * always move to head of search list
 * return: 0: already loaded 1: first load
 */
#if SHOPT_DYNAMIC
int sh_addlib(void* library)
{
	register int	n;
	register int	r;
	Iptr_t		initfn;
	Shbltin_t	*sp = &sh.bltindata;

	sp->nosfio = 0;
	for (n = r = 0; n < nlib; n++)
	{
		if (r)
		{
			liblist[n-1] = liblist[n];
			libattr[n-1] = libattr[n];
		}
		else if (liblist[n] == library)
			r++;
	}
	if (r)
		nlib--;
	else if ((initfn = (Iptr_t)dlllook(library, "lib_init")))
		(*initfn)(0,sp);
	if (nlib >= maxlib)
	{
		maxlib += GROWLIB;
		if (liblist)
		{
			liblist = (void**)realloc((void*)liblist, (maxlib+1)*sizeof(void**));
			libattr = (unsigned short*)realloc((void*)liblist, (maxlib+1)*sizeof(unsigned short*));
		}
		else
		{
			liblist = (void**)malloc((maxlib+1)*sizeof(void**));
			libattr = (unsigned short*)malloc((maxlib+1)*sizeof(unsigned short*));
		}
	}
	libattr[nlib] = (sp->nosfio?BLT_NOSFIO:0);
	liblist[nlib++] = library;
	liblist[nlib] = 0;
	return !r;
}
#else
int sh_addlib(void* library)
{
	return 0;
}
#endif /* SHOPT_DYNAMIC */

/*
 * add change or list built-ins
 * adding builtins requires dlopen() interface
 */
int	b_builtin(int argc,char *argv[],void *extra)
{
	register char *arg=0, *name;
	register int n, r=0, flag=0;
	register Namval_t *np;
	long dlete=0;
	struct tdata tdata;
	Fptr_t addr;
	Stk_t	*stkp;
	void *library=0;
	char *errmsg;
	NOT_USED(argc);
	memset(&tdata,0,sizeof(tdata));
	tdata.sh = ((Shbltin_t*)extra)->shp;
	stkp = tdata.sh->stk;
	if(!tdata.sh->pathlist)
		path_absolute(argv[0],NIL(Pathcomp_t*));
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
#if (_AST_VERSION>=20040404)
		if(!(library = dllplug(SH_ID,arg,NIL(char*),RTLD_LAZY,NIL(char*),0)))
#else
		if(!(library = dllfind(arg,NIL(char*),RTLD_LAZY,NIL(char*),0)))
#endif
		{
			errormsg(SH_DICT,ERROR_exit(0),"%s: %s",arg,dlerror());
			return(1);
		}
		sh_addlib(library);
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
		for(n=(nlib?nlib:dlete); --n>=0;)
		{
			/* (char*) added for some sgi-mips compilers */ 
#if SHOPT_DYNAMIC
			if(dlete || (addr = (Fptr_t)dlllook(liblist[n],stkptr(stkp,flag))))
#else
			if(dlete)
#endif /* SHOPT_DYNAMIC */
			{
				if(np = sh_addbuiltin(arg, addr,pointerof(dlete)))
				{
					if(dlete || nv_isattr(np,BLT_SPC))
						errmsg = "restricted name";
					else
						nv_onattr(np,libattr[n]);
				}
				break;
			}
		}
		if(!dlete && !addr)
		{
			np = sh_addbuiltin(arg, 0 ,0);
			if(np && nv_isattr(np,BLT_SPC))
				errmsg = "restricted name";
			else if(!np)
				errmsg = "not found";
		}
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

int    b_set(int argc,register char *argv[],void *extra)
{
	struct tdata tdata;
	memset(&tdata,0,sizeof(tdata));
	tdata.sh = ((Shbltin_t*)extra)->shp;
	tdata.prefix=0;
	if(argv[1])
	{
		if(sh_argopts(argc,argv,tdata.sh) < 0)
			return(2);
		if(sh_isoption(SH_VERBOSE))
			sh_onstate(SH_VERBOSE);
		else
			sh_offstate(SH_VERBOSE);
		if(sh_isoption(SH_MONITOR))
			sh_onstate(SH_MONITOR);
		else
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

int    b_unalias(int argc,register char *argv[],void *extra)
{
	Shell_t *shp = ((Shbltin_t*)extra)->shp;
	return(b_unall(argc,argv,shp->alias_tree,shp));
}

int    b_unset(int argc,register char *argv[],void *extra)
{
	Shell_t *shp = ((Shbltin_t*)extra)->shp;
	return(b_unall(argc,argv,shp->var_tree,shp));
}

static int b_unall(int argc, char **argv, register Dt_t *troot, Shell_t* shp)
{
	register Namval_t *np;
	register const char *name;
	register int r;
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
	sh_pushcontext(&buff,1);
	while(name = *argv++)
	{
		jmpval = sigsetjmp(buff.buff,0);
		np = 0;
		if(jmpval==0)
			np=nv_open(name,troot,NV_NOADD|nflag);
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
				if(nv_isarray(np) && name[strlen(name)-1]==']' && !nv_getsub(np))
				{
					r=1;
					continue;
				}
					
				if(shp->subshell)
					np=sh_assignok(np,0);
			}
			if(!nv_isnull(np))
				nv_unset(np);
			nv_close(np);
			if(troot==shp->var_tree && shp->st.real_fun && (dp=shp->var_tree->walk) && dp==shp->st.real_fun->sdict)
				nv_delete(np,dp,NV_NOFREE);
			else if(isfun)
				nv_delete(np,troot,NV_NOFREE);
		}
	}
	sh_popcontext(&buff);
	return(r);
}

/*
 * print out the name and value of a name-value pair <np>
 */

static int print_namval(Sfio_t *file,register Namval_t *np,register int flag, struct tdata *tp)
{
	register char *cp;
	sh_sigcheck();
	if(flag)
		flag = '\n';
	if(nv_isattr(np,NV_NOPRINT|NV_INTEGER)==NV_NOPRINT)
	{
		if(is_abuiltin(np))
			sfputr(file,nv_name(np),'\n');
		return(0);
	}
	if(tp->prefix)
	{
		if(*tp->prefix=='t')
			nv_attribute(np,tp->outfile,tp->prefix,tp->aflag);
		else
			sfputr(file,tp->prefix,' ');
	}
	if(is_afunction(np))
	{
		Sfio_t *iop=0;
		char *fname=0;
		if(!flag && !np->nvalue.ip)
			sfputr(file,"typeset -fu",' ');
		else if(!flag && !nv_isattr(np,NV_FPOSIX))
			sfputr(file,"function",' ');
		sfputr(file,nv_name(np),-1);
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
			else if(tp->sh->hist_ptr)
				iop = (tp->sh->hist_ptr)->histfp;
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
		print_value(file,np,tp);
		return(0);
	}
	if(nv_isvtree(np))
		nv_onattr(np,NV_EXPORT);
	if(cp=nv_getval(np))
	{
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
	else if(tp->scanmask && tp->scanroot==tp->sh->var_tree)
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
	namec = nv_scan(root,nullscan,(void*)tp,tp->scanmask,flag);
	argv = tp->argnam  = (char**)stkalloc(tp->sh->stk,(namec+1)*sizeof(char*));
	namec = nv_scan(root, pushname, (void*)tp, tp->scanmask, flag&~NV_IARRAY);
	if(mbcoll())
		strsort(argv,namec,strcoll);
	while(namec--)
	{
		if((np=nv_search(*argv++,root,0)) && np!=onp && (!nv_isnull(np) || np->nvfun || nv_isattr(np,~NV_NOFREE)))
		{
			onp = np;
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
			print_namval(file,np,option,tp);
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

