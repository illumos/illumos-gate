/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1982-2011 AT&T Intellectual Property          *
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
 *	File name expansion
 *
 *	David Korn
 *	AT&T Labs
 *
 */

#if KSHELL
#   include	"defs.h"
#   include	"variables.h"
#   include	"test.h"
#else
#   include	<ast.h>
#   include	<ctype.h>
#   include	<setjmp.h>
#endif /* KSHELL */
#include	<glob.h>
#include	<ls.h>
#include	<stak.h>
#include	<ast_dir.h>
#include	"io.h"
#include	"path.h"

#if !SHOPT_BRACEPAT
#   define SHOPT_BRACEPAT	0
#endif

#if KSHELL
#   define argbegin	argnxt.cp
    static	const char	*sufstr;
    static	int		suflen;
    static int scantree(Dt_t*,const char*, struct argnod**);
#else
#   define sh_sigcheck(sig)	(0)
#   define sh_access		access
#   define suflen		0
#endif /* KSHELL */


/*
 * This routine builds a list of files that match a given pathname
 * Uses external routine strgrpmatch() to match each component
 * A leading . must match explicitly
 *
 */

#ifndef GLOB_AUGMENTED
#   define GLOB_AUGMENTED	0
#endif

#define GLOB_RESCAN 1
#define globptr()	((struct glob*)membase)

static struct glob	 *membase;

#if GLOB_VERSION >= 20010916L
static char *nextdir(glob_t *gp, char *dir)
{
	Shell_t	*shp = sh_getinterp();
	Pathcomp_t *pp = (Pathcomp_t*)gp->gl_handle;
	if(!dir)
		pp = path_get(shp,"");
	else
		pp = pp->next;
	gp->gl_handle = (void*)pp;
	if(pp)
		return(pp->name);
	return(0);
}
#endif

int path_expand(Shell_t *shp,const char *pattern, struct argnod **arghead)
{
	glob_t gdata;
	register struct argnod *ap;
	register glob_t *gp= &gdata;
	register int flags,extra=0;
#if SHOPT_BASH
	register int off;
	register char *sp, *cp, *cp2;
#endif
	sh_stats(STAT_GLOBS);
	memset(gp,0,sizeof(gdata));
	flags = GLOB_GROUP|GLOB_AUGMENTED|GLOB_NOCHECK|GLOB_NOSORT|GLOB_STACK|GLOB_LIST|GLOB_DISC;
	if(sh_isoption(SH_MARKDIRS))
		flags |= GLOB_MARK;
	if(sh_isoption(SH_GLOBSTARS))
		flags |= GLOB_STARSTAR;
#if SHOPT_BASH
#if 0
	if(sh_isoption(SH_BASH) && !sh_isoption(SH_EXTGLOB))
		flags &= ~GLOB_AUGMENTED;
#endif
	if(sh_isoption(SH_NULLGLOB))
		flags &= ~GLOB_NOCHECK;
	if(sh_isoption(SH_NOCASEGLOB))
		flags |= GLOB_ICASE;
#endif
	if(sh_isstate(SH_COMPLETE))
	{
#if KSHELL
		extra += scantree(shp->alias_tree,pattern,arghead); 
		extra += scantree(shp->fun_tree,pattern,arghead); 
#   if GLOB_VERSION >= 20010916L
		gp->gl_nextdir = nextdir;
#   endif
#endif /* KSHELL */
		flags |= GLOB_COMPLETE;
		flags &= ~GLOB_NOCHECK;
	}
#if SHOPT_BASH
	if(off = staktell())
		sp = stakfreeze(0);
	if(sh_isoption(SH_BASH))
	{
		/*
		 * For bash, FIGNORE is a colon separated list of suffixes to
		 * ignore when doing filename/command completion.
		 * GLOBIGNORE is similar to ksh FIGNORE, but colon separated
		 * instead of being an augmented shell pattern.
		 * Generate shell patterns out of those here.
		 */
		if(sh_isstate(SH_FCOMPLETE))
			cp=nv_getval(sh_scoped(shp,FIGNORENOD));
		else
		{
			static Namval_t *GLOBIGNORENOD;
			if(!GLOBIGNORENOD)
				GLOBIGNORENOD = nv_open("GLOBIGNORE",shp->var_tree,0);
			cp=nv_getval(sh_scoped(shp,GLOBIGNORENOD));
		}
		if(cp)
		{
			flags |= GLOB_AUGMENTED;
			stakputs("@(");
			if(!sh_isstate(SH_FCOMPLETE))
			{
				stakputs(cp);
				for(cp=stakptr(off); *cp; cp++)
					if(*cp == ':')
						*cp='|';
			}
			else
			{
				cp2 = strtok(cp, ":");
				if(!cp2)
					cp2=cp;
				do
				{
					stakputc('*');
					stakputs(cp2);
					if(cp2 = strtok(NULL, ":"))
					{
						*(cp2-1)=':';
						stakputc('|');
					}
				} while(cp2);
			}
			stakputc(')');
			gp->gl_fignore = stakfreeze(1);
		}
		else if(!sh_isstate(SH_FCOMPLETE) && sh_isoption(SH_DOTGLOB))
			gp->gl_fignore = "";
	}
	else
#endif
	gp->gl_fignore = nv_getval(sh_scoped(shp,FIGNORENOD));
	if(suflen)
		gp->gl_suffix = sufstr;
	gp->gl_intr = &shp->trapnote; 
	suflen = 0;
	if(memcmp(pattern,"~(N",3)==0)
		flags &= ~GLOB_NOCHECK;
	glob(pattern, flags, 0, gp);
#if SHOPT_BASH
	if(off)
		stakset(sp,off);
	else
		stakseek(0);
#endif
	sh_sigcheck(shp);
	for(ap= (struct argnod*)gp->gl_list; ap; ap = ap->argnxt.ap)
	{
		ap->argchn.ap = ap->argnxt.ap;
		if(!ap->argnxt.ap)
			ap->argchn.ap = *arghead;
	}
	if(gp->gl_list)
		*arghead = (struct argnod*)gp->gl_list;
	return(gp->gl_pathc+extra);
}

#if KSHELL

/*
 * scan tree and add each name that matches the given pattern
 */
static int scantree(Dt_t *tree, const char *pattern, struct argnod **arghead)
{
	register Namval_t *np;
	register struct argnod *ap;
	register int nmatch=0;
	register char *cp;
	np = (Namval_t*)dtfirst(tree);
	for(;np && !nv_isnull(np);(np = (Namval_t*)dtnext(tree,np)))
	{
		if(strmatch(cp=nv_name(np),pattern))
		{
			ap = (struct argnod*)stakseek(ARGVAL);
			stakputs(cp);
			ap = (struct argnod*)stakfreeze(1);
			ap->argbegin = NIL(char*);
			ap->argchn.ap = *arghead;
			ap->argflag = ARG_RAW|ARG_MAKE;
			*arghead = ap;
			nmatch++;
		}
	}
	return(nmatch);
}

/*
 * file name completion
 * generate the list of files found by adding an suffix to end of name
 * The number of matches is returned
 */

int path_complete(Shell_t *shp,const char *name,register const char *suffix, struct argnod **arghead)
{
	sufstr = suffix;
	suflen = strlen(suffix);
	return(path_expand(shp,name,arghead));
}

#endif

#if SHOPT_BRACEPAT

static int checkfmt(Sfio_t* sp, void* vp, Sffmt_t* fp)
{
	return -1;
}

int path_generate(Shell_t *shp,struct argnod *todo, struct argnod **arghead)
/*@
	assume todo!=0;
	return count satisfying count>=1;
@*/
{
	register char *cp;
	register int brace;
	register struct argnod *ap;
	struct argnod *top = 0;
	struct argnod *apin;
	char *pat, *rescan;
	char *format;
	char comma, range=0;
	int first, last, incr, count = 0;
	char tmp[32], end[1];
	todo->argchn.ap = 0;
again:
	apin = ap = todo;
	todo = ap->argchn.ap;
	cp = ap->argval;
	range = comma = brace = 0;
	/* first search for {...,...} */
	while(1) switch(*cp++)
	{
		case '{':
			if(brace++==0)
				pat = cp;
			break;
		case '}':
			if(--brace>0)
				break;
			if(brace==0 && comma && *cp!='(')
				goto endloop1;
			comma = brace = 0;
			break;
		case '.':
			if(brace==1 && *cp=='.')
			{
				char *endc;
				incr = 1;
				if(isdigit(*pat) || *pat=='+' || *pat=='-')
				{
					first = strtol(pat,&endc,0);
					if(endc==(cp-1))
					{
						last = strtol(cp+1,&endc,0);
						if(*endc=='.' && endc[1]=='.')
							incr = strtol(endc+2,&endc,0);
						else if(last<first)
							incr = -1;
						if(incr)
						{
							if(*endc=='%')
							{
								Sffmt_t	fmt;
								memset(&fmt, 0, sizeof(fmt));
								fmt.version = SFIO_VERSION;
								fmt.form = endc;
								fmt.extf = checkfmt;
								sfprintf(sfstdout, "%!", &fmt);
								if(!(fmt.flags&(SFFMT_LLONG|SFFMT_LDOUBLE)))
									switch (fmt.fmt)
									{
									case 'c':
									case 'd':
									case 'i':
									case 'o':
									case 'u':
									case 'x':
									case 'X':
										format = endc;
										endc = fmt.form;
										break;
									}
							}
							else
								format = "%d";
							if(*endc=='}')
							{
								cp = endc+1;
								range = 2;
								goto endloop1;
							}
						}
					}
				}
				else if((cp[2]=='}' || cp[2]=='.' && cp[3]=='.') && ((*pat>='a'  && *pat<='z' && cp[1]>='a' && cp[1]<='z') || (*pat>='A'  && *pat<='Z' && cp[1]>='A' && cp[1]<='Z')))
				{
					first = *pat;
					last = cp[1];
					cp += 2;
					if(*cp=='.')
					{
						incr = strtol(cp+2,&endc,0);
						cp = endc;
					}
					else if(first>last)
						incr = -1;
					if(incr && *cp=='}')
					{
						cp++;
						range = 1;
						goto endloop1;
					}
				}
				cp++;
			}
			break;
		case ',':
			if(brace==1)
				comma = 1;
			break;
		case '\\':
			cp++;
			break;
		case 0:
			/* insert on stack */
			ap->argchn.ap = top;
			top = ap;
			if(todo)
				goto again;
			for(; ap; ap=apin)
			{
				apin = ap->argchn.ap;
				if(!sh_isoption(SH_NOGLOB))
					brace=path_expand(shp,ap->argval,arghead);
				else
				{
					ap->argchn.ap = *arghead;
					*arghead = ap;
					brace=1;
				}
				if(brace)
				{
					count += brace;
					(*arghead)->argflag |= ARG_MAKE;
				}
			}
			return(count);
	}
endloop1:
	rescan = cp;
	cp = pat-1;
	*cp = 0;
	while(1)
	{
		brace = 0;
		if(range)
		{
			if(range==1)
			{
				pat[0] = first;
				cp = &pat[1];
			}
			else
			{
				*(rescan - 1) = 0;
				sfsprintf(pat=tmp,sizeof(tmp),format,first);
				*(rescan - 1) = '}';
				*(cp = end) = 0;
			}
			if(incr*(first+incr) > last*incr)
				*cp = '}';
			else
				first += incr;
		}
		/* generate each pattern and put on the todo list */
		else while(1) switch(*++cp)
		{
			case '\\':
				cp++;
				break;
			case '{':
				brace++;
				break;
			case ',':
				if(brace==0)
					goto endloop2;
				break;
			case '}':
				if(--brace<0)
					goto endloop2;
		}
	endloop2:
		brace = *cp;
		*cp = 0;
		sh_sigcheck(shp);
		ap = (struct argnod*)stakseek(ARGVAL);
		ap->argflag = ARG_RAW;
		ap->argchn.ap = todo;
		stakputs(apin->argval);
		stakputs(pat);
		stakputs(rescan);
		todo = ap = (struct argnod*)stakfreeze(1);
		if(brace == '}')
			break;
		if(!range)
			pat = cp+1;
	}
	goto again;
}

#endif /* SHOPT_BRACEPAT */
