/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*           Copyright (c) 1982-2007 AT&T Knowledge Ventures            *
*                      and is licensed under the                       *
*                  Common Public License, Version 1.0                  *
*                      by AT&T Knowledge Ventures                      *
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
 * KornShell  lexical analyzer
 *
 * Written by David Korn
 * AT&T Labs
 *
 */

#include	<ast.h>
#include	<stak.h>
#include	<fcin.h>
#include	<nval.h>
#include	"FEATURE/options"

#if KSHELL
#   include	"defs.h"
#else
#   include	<shell.h>
#   define	nv_getval(np)	((np)->nvalue)
    Shell_t sh  =  {1};
#endif /* KSHELL */

#include	"argnod.h"
#include	"test.h"
#include	"lexstates.h"
#include	"io.h"

#define TEST_RE		3
#define SYNBAD		3	/* exit value for syntax errors */
#define STACK_ARRAY	3	/* size of depth match stack growth */

#if _lib_iswblank < 0	/* set in lexstates.h to enable this code */

int
local_iswblank(wchar_t wc)
{
	static int      initialized;
	static wctype_t wt;

	if (!initialized)
	{
		initialized = 1;
		wt = wctype("blank");
	}
	return(iswctype(wc, wt));
}

#endif

/*
 * This structure allows for arbitrary depth nesting of (...), {...}, [...]
 */
struct lexstate
{
	char		incase;		/* 1 for case pattern, 2 after case */
	char		intest;		/* 1 inside [[...]] */
	char		testop1;	/* 1 when unary test op legal */
	char		testop2;	/* 1 when binary test op legal */
	char		reservok;	/* >0 for reserved word legal */
	char		skipword;	/* next word can't be reserved */
	char		last_quote;	/* last multi-line quote character */
	char		comp_assign;	/* inside compound assignment */
};

struct lexdata
{
	char		nocopy;
	char		paren;
	char		dolparen;
	char		nest;
	char		docword;
	char 		*docend;
	char		noarg;
	char		balance;
	char		warn;
	char		message;
	char		arith;
	char 		*first;
	int		level;
	int		lastc;
	int		lex_max;
	int		*lex_match;
	int		lex_state;
#if SHOPT_KIA
	off_t		kiaoff;
#endif
};

#define _SHLEX_PRIVATE \
	struct lexdata  _lexd; \
	struct lexstate  _lex;

#include	"shlex.h"

#define lexd	lp->_lexd
#define lex	lp->_lex
#undef shlex
#define shlex	lp->_shlex


#define	pushlevel(c,s)	((lexd.level>=lexd.lex_max?stack_grow(lp):1) &&\
				((lexd.lex_match[lexd.level++]=lexd.lastc),\
				lexd.lastc=(((s)<<CHAR_BIT)|(c))))
#define oldmode()	(lexd.lastc>>CHAR_BIT)	
#define endchar()	(lexd.lastc&0xff)	
#define setchar(c)	(lexd.lastc = ((lexd.lastc&~0xff)|(c)))
#define poplevel()	(lexd.lastc=lexd.lex_match[--lexd.level])

static char		*fmttoken(Lex_t*, int, char*);
#ifdef SF_BUFCONST
    static int          alias_exceptf(Sfio_t*, int, void*, Sfdisc_t*);
#else
    static int 		alias_exceptf(Sfio_t*, int, Sfdisc_t*);
#endif
static void		setupalias(Lex_t*,const char*, Namval_t*);
static int		comsub(Lex_t*);
static void		nested_here(Lex_t*);
static int		here_copy(Lex_t*, struct ionod*);
static int 		stack_grow(Lex_t*);
static const Sfdisc_t alias_disc = { NULL, NULL, NULL, alias_exceptf, NULL };

#if SHOPT_KIA

static void refvar(int type)
{
	register Shell_t *shp = sh_getinterp();
	register Lex_t *lp = (Lex_t*)shp->lex_context;
	off_t off = (fcseek(0)-(type+1))-(lexd.first?lexd.first:fcfirst());
	unsigned long r;
	if(lexd.first)
	{
		off = (fcseek(0)-(type+1)) - lexd.first;
		r=kiaentity(lexd.first+lexd.kiaoff+type,off-lexd.kiaoff,'v',-1,-1,shlex.current,'v',0,"");
	}
	else
	{
		int n,offset = staktell();
		char *savptr,*begin; 
		off = offset + (fcseek(0)-(type+1)) - fcfirst();
		if(lexd.kiaoff < offset)
		{
			/* variable starts on stak, copy remainder */
			if(off>offset)
				stakwrite(fcfirst()+type,off-offset);
			n = staktell()-lexd.kiaoff;
			begin = stakptr(lexd.kiaoff);
		}
		else
		{
			/* variable in data buffer */
			begin = fcfirst()+(type+lexd.kiaoff-offset);
			n = off-lexd.kiaoff;
		}
		savptr = stakfreeze(0);
		r=kiaentity(begin,n,'v',-1,-1,shlex.current,'v',0,"");
		stakset(savptr,offset);
	}
	sfprintf(shlex.kiatmp,"p;%..64d;v;%..64d;%d;%d;r;\n",shlex.current,r,shp->inlineno,shp->inlineno);
}
#endif /* SHOPT_KIA */

/*
 * This routine gets called when reading across a buffer boundary
 * If lexd.nocopy is off, then current token is saved on the stack
 */
static void lex_advance(Sfio_t *iop, const char *buff, register int size)
{
	register Shell_t *shp = sh_getinterp();
	register Lex_t *lp = (Lex_t*)shp->lex_context;
	register Sfio_t *log= shp->funlog;
#if KSHELL
	/* write to history file and to stderr if necessary */
	if(iop && !sfstacked(iop))
	{
		if(sh_isstate(SH_HISTORY) && shp->hist_ptr)
			log = shp->hist_ptr->histfp;
		sfwrite(log, (void*)buff, size);
		if(sh_isstate(SH_VERBOSE))
			sfwrite(sfstderr, buff, size);
	}
#endif
	if(lexd.nocopy)
		return;
	if(lexd.first)
	{
		size -= (lexd.first-(char*)buff);
		buff = lexd.first;
		if(!lexd.noarg)
			shlex.arg = (struct argnod*)stakseek(ARGVAL);
#if SHOPT_KIA
		lexd.kiaoff += ARGVAL;
#endif /* SHOPT_KIA */
	}
	if(size>0 && (shlex.arg||lexd.noarg))
	{
		stakwrite(buff,size);
		lexd.first = 0;
	}
}

/*
 * fill up another input buffer
 * preserves lexical state
 */
static int lexfill(void)
{
	Shell_t *shp = sh_getinterp();
	register int c;
	register Lex_t *lp = (Lex_t*)shp->lex_context;
	struct shlex_t savelex;
	struct lexdata savedata;
	struct lexstate savestate;
	struct argnod *ap;
	int aok;
	savelex = shlex;
	savedata = lexd;
	savestate = lex;
	ap = shlex.arg;
	c = fcfill();
	if(ap)
		shlex.arg = ap;
	lex = savestate;
	lexd = savedata;
	lexd.first = 0;
	aok= shlex.aliasok;
	ap = shlex.arg;
	shlex = savelex;
	shlex.arg = ap;
	shlex.aliasok = aok;
	return(c);
}

/*
 * mode=1 for reinitialization  
 */
Lex_t *sh_lexopen(Lex_t *lp, Shell_t *sp, int mode)
{
	fcnotify(lex_advance);
	if(!lp)
	{
		lp = (Lex_t*)newof(0,Lex_t,1,0);
		lp->_shlex.sh = sp;
	}
	lex.intest = lex.incase = lex.skipword = lexd.warn = 0;
	lex.comp_assign = 0;
	lex.reservok = 1;
	if(!sh_isoption(SH_DICTIONARY) && sh_isoption(SH_NOEXEC))
		lexd.warn=1;
	if(!mode)
	{
		lexd.noarg = lexd.level= lexd.dolparen = 0;
		lexd.nocopy = lexd.docword = lexd.nest = lexd.paren = 0;
	}
	shlex.comsub = 0;
	return(lp);
}

#ifdef DBUG
extern int lextoken(void);
int sh_lex(void)
{
	Shell_t *shp = sh_getinterp();
	register Lex_t *lp = (Lex_t*)shp->lex_context;
	register int flag;
	char *quoted, *macro, *split, *expand; 
	char tokstr[3];
	register int tok = lextoken();
	quoted = macro = split = expand = "";
	if(tok==0 && (flag=shlex.arg->argflag))
	{
		if(flag&ARG_MAC)
			macro = "macro:";
		if(flag&ARG_EXP)
			expand = "expand:";
		if(flag&ARG_QUOTED)
			quoted = "quoted:";
	}
	sfprintf(sfstderr,"line %d: %o:%s%s%s%s %s\n",shp->inlineno,tok,quoted,
		macro, split, expand, fmttoken(lp,tok,tokstr));
	return(tok);
}
#define sh_lex	lextoken
#endif

/*
 * Get the next word and put it on the top of the stak
 * A pointer to the current word is stored in shlex.arg
 * Returns the token type
 */
int sh_lex(void)
{
	register Shell_t *shp = sh_getinterp();
	register const char	*state;
	register int	n, c, mode=ST_BEGIN, wordflags=0;
	register Lex_t *lp = (Lex_t*)shp->lex_context;
	int		inlevel=lexd.level, assignment=0, ingrave=0;
	Sfio_t *sp;
#if SHOPT_MULTIBYTE
	LEN=1;
#endif /* SHOPT_MULTIBYTE */
	if(lexd.paren)
	{
		lexd.paren = 0;
		return(shlex.token=LPAREN);
	}
	if(lex.incase)
		shlex.assignok = 0;
	else
		shlex.assignok |= lex.reservok;
	if(lex.comp_assign==2)
		lex.comp_assign = lex.reservok = 0;
	lexd.arith = (lexd.nest==1);
	if(lexd.nest)
	{
		pushlevel(lexd.nest,ST_NONE);
		lexd.nest = 0;
		mode = lexd.lex_state;
	}
	else if(lexd.docword)
	{
		if(fcgetc(c)=='-' || c=='#')
		{
			lexd.docword++;
			shlex.digits=(c=='#'?3:1);
		}
		else if(c=='<')
		{
			shlex.digits=2;
			lexd.docword=0;
		}
		else if(c>0)
			fcseek(-1);
	}
	if(!lexd.dolparen)
	{
		shlex.arg = 0;
		if(mode!=ST_BEGIN)
			lexd.first = fcseek(0);
		else
			lexd.first = 0;
	}
	shlex.lastline = sh.inlineno;
	while(1)
	{
		/* skip over characters in the current state */
		state = sh_lexstates[mode];
		while((n=STATE(state,c))==0);
		switch(n)
		{
			case S_BREAK:
				fcseek(-1);
				goto breakloop;
			case S_EOF:
				sp = fcfile();
				if((n=lexfill()) > 0)
				{
					fcseek(-1);
					continue;
				}
				/* check for zero byte in file */
				if(n==0 && fcfile())
				{
					if(shp->readscript)
					{
						char *cp = error_info.id;
						errno = ENOEXEC;
						error_info.id = shp->readscript;
						errormsg(SH_DICT,ERROR_system(ERROR_NOEXEC),e_exec,cp);
					}
					else
					{
						shlex.token = -1;
						sh_syntax();
					}
				}
				/* end-of-file */
				if(mode==ST_BEGIN)
					return(shlex.token=EOFSYM);
				if(mode >ST_NORM && lexd.level>0)
				{
					switch(c=endchar())
					{
						case '$':
							if(mode==ST_LIT)
							{
								c = '\'';
								break;
							}
							mode = oldmode();
							poplevel();
							continue;
						case RBRACT:
							c = LBRACT;
							break;
						case 1:	/* for ((...)) */
						case RPAREN:
							c = LPAREN;
							break;
						default:
							c = LBRACE;
							break;
						case '"': case '`': case '\'':
							lexd.balance = c;
							break;
					}
					if(sp && !(sfset(sp,0,0)&SF_STRING))
					{
						shlex.lasttok = c;
						shlex.token = EOFSYM;
						sh_syntax();
					}
					lexd.balance = c;
				}
				goto breakloop;
			case S_COM:
				/* skip one or more comment line(s) */
				lex.reservok = !lex.intest;
				if((n=lexd.nocopy) && lexd.dolparen)
					lexd.nocopy--;
				do
				{
					while(fcgetc(c)>0 && c!='\n');
					if(c<=0 || shlex.heredoc)
						break;
					while(shp->inlineno++,fcpeek(0)=='\n')
						fcseek(1);
					while(state[c=fcpeek(0)]==0)
						fcseek(1);
				}
				while(c=='#');
				lexd.nocopy = n;
				if(c<0)
					return(shlex.token=EOFSYM);
				n = S_NLTOK;
				shp->inlineno--;
				/* FALL THRU */
			case S_NLTOK:
				/* check for here-document */
				if(shlex.heredoc)
				{
					if(!lexd.dolparen)
						lexd.nocopy++;
					c = shp->inlineno;
					if(here_copy(lp,shlex.heredoc)<=0 && shlex.lasttok)
					{
						shlex.lasttok = IODOCSYM;
						shlex.token = EOFSYM;
						shlex.lastline = c;
						sh_syntax();
					}
					if(!lexd.dolparen)
						lexd.nocopy--;
					shlex.heredoc = 0;
				}
				lex.reservok = !lex.intest;
				lex.skipword = 0;
				/* FALL THRU */
			case S_NL:
				/* skip over new-lines */
				lex.last_quote = 0;
				while(shp->inlineno++,fcget()=='\n');
				fcseek(-1);
				if(n==S_NLTOK)
				{
					lex.comp_assign = 0;
					return(shlex.token='\n');
				}
			case S_BLNK:
				if(lex.incase<=TEST_RE)
					continue;
				/* implicit RPAREN for =~ test operator */
				if(inlevel+1==lexd.level)
				{
					fcseek(-1);
					c = RPAREN;
					goto do_pop;
				}
				continue;
			case S_OP:
				/* return operator token */
				if(c=='<' || c=='>')
				{
					if(lex.testop2)
						lex.testop2 = 0;
					else
					{
						shlex.digits = (c=='>');
						lex.skipword = 1;
						shlex.aliasok = lex.reservok;
						lex.reservok = 0;
					}
				}
				else
				{
					lex.reservok = !lex.intest;
					if(c==RPAREN)
					{
						if(!lexd.dolparen)
							lex.incase = 0;
						return(shlex.token=c);
					}
					lex.testop1 = lex.intest;
				}
				if(fcgetc(n)>0)
					fcseek(-1);
				if(state[n]==S_OP || n=='#')
				{
					if(n==c)
					{
						if(c=='<')
							lexd.docword=1;
						else if(n==LPAREN)
						{
							lexd.nest=1;
							shlex.lastline = shp->inlineno;
							lexd.lex_state = ST_NESTED;
							fcseek(1);
							return(sh_lex());
						}
						c  |= SYMREP;
					}
					else if(c=='(' || c==')')
						return(shlex.token=c);
					else if(c=='&')
					{
#if SHOPT_BASH
						if(!sh_isoption(SH_POSIX) && n=='>')
						{
							shlex.digits = -1;
							c = '>';
						}
						else
#endif
							n = 0;
					}
					else if(n=='&')
						c  |= SYMAMP;
					else if(c!='<' && c!='>')
						n = 0;
					else if(n==LPAREN)
					{
						c  |= SYMLPAR;
						lex.reservok = 1;
						lex.skipword = 0;
					}
					else if(n=='|')
						c  |= SYMPIPE;
					else if(c=='<' && n=='>')
						c = IORDWRSYM;
					else if(n=='#' && (c=='<'||c=='>'))
						c |= SYMSHARP;
					else
						n = 0;
					if(n)
					{
						fcseek(1);
						lex.incase = (c==BREAKCASESYM || c==FALLTHRUSYM);
					}
					else
					{
						if((n=fcpeek(0))!=RPAREN && n!=LPAREN && lexd.warn)
							errormsg(SH_DICT,ERROR_warn(0),e_lexspace,shp->inlineno,c,n);
					}
				}
				if(c==LPAREN && lex.comp_assign && !lex.intest && !lex.incase)
					lex.comp_assign = 2;
				else
					lex.comp_assign = 0;
				return(shlex.token=c);
			case S_ESC:
				/* check for \<new-line> */
				fcgetc(n);
				c=2;
#if SHOPT_CRNL
				if(n=='\r')
				{
					if(fcgetc(n)=='\n')
						c=3;
					else
					{
						n='\r';
						fcseek(-1);
					}
				}
#endif /* SHOPT_CRNL */
				if(n=='\n')
				{
					Sfio_t *sp;
					struct argnod *ap;
					shp->inlineno++;
					/* synchronize */
					if(!(sp=fcfile()))
						state=fcseek(0);
					fcclose();
					ap = shlex.arg;
					if(sp)
						fcfopen(sp);
					else
						fcsopen((char*)state);
					/* remove \new-line */
					n = staktell()-c;
					stakseek(n);
					shlex.arg = ap;
					if(n<=ARGVAL)
					{
						mode = 0;
						lexd.first = 0;
					}
					continue;
				}
				wordflags |= ARG_QUOTED;
				if(mode==ST_DOL)
					goto err;
#ifndef STR_MAXIMAL
				else if(mode==ST_NESTED && lexd.warn && 
					endchar()==RBRACE &&
					sh_lexstates[ST_DOL][n]==S_DIG
				)
					errormsg(SH_DICT,ERROR_warn(0),e_lexfuture,shp->inlineno,n);
#endif /* STR_MAXIMAL */
				break;
			case S_NAME:
				if(!lex.skipword)
					lex.reservok *= 2;
				/* FALL THRU */
			case S_TILDE:
			case S_RES:
				if(!lexd.dolparen)
					lexd.first = fcseek(0)-LEN;
				else if(lexd.docword)
					lexd.docend = fcseek(0)-LEN;
				mode = ST_NAME;
				if(c=='.')
					fcseek(-1);
				if(n!=S_TILDE)
					continue;
				fcgetc(n);
				if(n>0)
					fcseek(-1);
				if(n==LPAREN)
					goto epat;
				wordflags = ARG_MAC;
				mode = ST_NORM;
				continue;
			case S_REG:
				if(mode==ST_BEGIN)
				{
					/* skip new-line joining */
					if(c=='\\' && fcpeek(0)=='\n')
					{
						shp->inlineno++;
						fcseek(1);
						continue;
					}
					fcseek(-1);
					if(!lexd.dolparen)
						lexd.first = fcseek(0);
					else if(lexd.docword)
						lexd.docend = fcseek(0);
					if(c=='[' && shlex.assignok>=SH_ASSIGN)
					{
						mode = ST_NAME;
						continue;
					}
				}
				mode = ST_NORM;
				continue;
			case S_LIT:
				if(oldmode()==ST_NONE)	/*  in ((...)) */
				{
					if((c=fcpeek(0))==LPAREN || c==RPAREN || c=='$' || c==LBRACE || c==RBRACE || c=='[' || c==']')
					{
						if(fcpeek(1)=='\'')
							fcseek(2);
					}
					continue;
				}
				wordflags |= ARG_QUOTED;
				if(mode==ST_DOL)
				{
					if(endchar()!='$')
						goto err;
					if(oldmode()==ST_QUOTE) /* $' within "" or `` */
					{
						if(lexd.warn)
							errormsg(SH_DICT,ERROR_warn(0),e_lexslash,shp->inlineno);
						mode = ST_LIT;
					}
				}
				if(mode!=ST_LIT)
				{
					if(lexd.warn && lex.last_quote && shp->inlineno > shlex.lastline)
						errormsg(SH_DICT,ERROR_warn(0),e_lexlongquote,shlex.lastline,lex.last_quote);
					lex.last_quote = 0;
					shlex.lastline = shp->inlineno;
					if(mode!=ST_DOL)
						pushlevel('\'',mode);
					mode = ST_LIT;
					continue;
				}
				/* check for multi-line single-quoted string */
				else if(shp->inlineno > shlex.lastline)
					lex.last_quote = '\'';
				mode = oldmode();
				poplevel();
				break;
			case S_ESC2:
				/* \ inside '' */
				if(endchar()=='$')
				{
					fcgetc(n);
					if(n=='\n')
						shp->inlineno++;
				}
				continue;
			case S_GRAVE:
				if(lexd.warn && (mode!=ST_QUOTE || endchar()!='`'))
					errormsg(SH_DICT,ERROR_warn(0),e_lexobsolete1,shp->inlineno);
				wordflags |=(ARG_MAC|ARG_EXP);
				if(mode==ST_QUOTE)
					ingrave = !ingrave;
				/* FALL THRU */
			case S_QUOTE:
				if(oldmode()==ST_NONE && lexd.arith)	/*  in ((...)) */
					continue;
				if(n==S_QUOTE)
					wordflags |=ARG_QUOTED;
				if(mode!=ST_QUOTE)
				{
					if(c!='"' || mode!=ST_QNEST)
					{
						if(lexd.warn && lex.last_quote && shp->inlineno > shlex.lastline)
							errormsg(SH_DICT,ERROR_warn(0),e_lexlongquote,shlex.lastline,lex.last_quote);
						lex.last_quote=0;
						shlex.lastline = shp->inlineno;
						pushlevel(c,mode);
					}
					ingrave = (c=='`');
					mode = ST_QUOTE;
					continue;
				}
				else if((n=endchar())==c)
				{
					if(shp->inlineno > shlex.lastline)
						lex.last_quote = c;
					mode = oldmode();
					poplevel();
				}
				else if(c=='"' && n==RBRACE)
					mode = ST_QNEST;
				break;
			case S_DOL:
				/* don't check syntax inside `` */
				if(mode==ST_QUOTE && ingrave)
					continue;
#if SHOPT_KIA
				if(lexd.first)
					lexd.kiaoff = fcseek(0)-lexd.first;
				else
					lexd.kiaoff = staktell()+fcseek(0)-fcfirst();
#endif /* SHOPT_KIA */
				pushlevel('$',mode);
				mode = ST_DOL;
				continue;
			case S_PAR:
				wordflags |= ARG_MAC;
				mode = oldmode();
				poplevel();
				fcseek(-1);
				wordflags |= comsub(lp);
				continue;
			case S_RBRA:
				if((n=endchar()) == '$')
					goto err;
				if(mode!=ST_QUOTE || n==RBRACE)
				{
					mode = oldmode();
					poplevel();
				}
				break;
			case S_EDOL:
				/* end $identifier */
#if SHOPT_KIA
				if(shlex.kiafile)
					refvar(0);
#endif /* SHOPT_KIA */
				if(lexd.warn && c==LBRACT)
					errormsg(SH_DICT,ERROR_warn(0),e_lexusebrace,shp->inlineno);
				fcseek(-1);
				mode = oldmode();
				poplevel();
				break;
			case S_DOT:
				/* make sure next character is alpha */
				if(fcgetc(n)>0)
					fcseek(-1);
				if(isaletter(n) || n==LBRACT)
					continue;
				if(mode==ST_NAME)
				{
					if(n=='=')
						continue;
					break;
				}
				else if(n==RBRACE)
					continue;
				if(isastchar(n))
					continue;
				goto err;
			case S_SPC1:
				wordflags |= ARG_MAC;
				if(endchar()==RBRACE)
				{
					setchar(c);
					continue;
				}
				/* FALL THRU */
			case S_ALP:
				if(c=='.' && endchar()=='$')
					goto err;
			case S_SPC2:
			case S_DIG:
				wordflags |= ARG_MAC;
				switch(endchar())
				{
					case '$':
						if(n==S_ALP) /* $identifier */
							mode = ST_DOLNAME;
						else
						{
							mode = oldmode();
							poplevel();
						}
						break;
#if SHOPT_TYPEDEF
					case '@':
#endif /* SHOPT_TYPEDEF */
					case '!':
						if(n!=S_ALP)
							goto dolerr;
					case '#':
					case RBRACE:
						if(n==S_ALP)
						{
							setchar(RBRACE);
							if(c=='.')
								fcseek(-1);
							mode = ST_BRACE;
						}
						else
						{
							if(fcgetc(c)>0)
								fcseek(-1);
							if(state[c]==S_ALP)
								goto err;
							if(n==S_DIG)
								setchar('0');
							else
								setchar('!');
						}
						break;
					case '0':
						if(n==S_DIG)
							break;
					default:
						goto dolerr;
				}
				break;
			dolerr:
			case S_ERR:
				if((n=endchar()) == '$')
					goto err;
				if(c=='*' || (n=sh_lexstates[ST_BRACE][c])!=S_MOD1 && n!=S_MOD2)
				{
					/* see whether inside `...` */
					mode = oldmode();
					poplevel();
					if((n = endchar()) != '`')
						goto err;
					pushlevel(RBRACE,mode);
				}
				else
					setchar(RBRACE);
				mode = ST_NESTED;
				continue;
			case S_MOD1:
				if(oldmode()==ST_QUOTE || oldmode()==ST_NONE)
				{
					/* allow ' inside "${...}" */
					if(c==':' && fcgetc(n)>0)
					{
						n = state[n];
						fcseek(-1);
					}
					if(n==S_MOD1)
					{
						mode = ST_QUOTE;
						continue;
					}
				}
				/* FALL THRU */
			case S_MOD2:
#if SHOPT_KIA
				if(shlex.kiafile)
					refvar(1);
#endif /* SHOPT_KIA */
				if(c!=':' && fcgetc(n)>0)
				{
					if(n!=c)
						c = 0;
					if(!c || (fcgetc(n)>0))
					{
						fcseek(-1);
						if(n==LPAREN)
						{
							if(c!='%')
							{
								shlex.token = n;
								sh_syntax();
							}
							else if(lexd.warn)
								errormsg(SH_DICT,ERROR_warn(0),e_lexquote,shp->inlineno,'%');
						}
					}
				}
				mode = ST_NESTED;
				continue;
			case S_LBRA:
				if((c=endchar()) == '$')
				{
					setchar(RBRACE);
					if(fcgetc(c)>0)
						fcseek(-1);
					if(state[c]!=S_ERR && c!=RBRACE)
						continue;
				}
			err:
				n = endchar();
				mode = oldmode();
				poplevel();
				if(n!='$')
				{
					shlex.token = c;
					sh_syntax();
				}
				else
				{
					if(lexd.warn && c!='/' && sh_lexstates[ST_NORM][c]!=S_BREAK && (c!='"' || mode==ST_QUOTE))
						errormsg(SH_DICT,ERROR_warn(0),e_lexslash,shp->inlineno);
					else if(c=='"' && mode!=ST_QUOTE)
						wordflags |= ARG_MESSAGE;
					fcseek(-1);
				}
				continue;
			case S_META:
				if(lexd.warn && endchar()==RBRACE)
					errormsg(SH_DICT,ERROR_warn(0),e_lexusequote,shp->inlineno,c);
				continue;
			case S_PUSH:
				pushlevel(RPAREN,mode);
				mode = ST_NESTED;
				continue;
			case S_POP:
			do_pop:
				if(lexd.level <= inlevel)
					break;
				n = endchar();
				if(c==RBRACT  && !(n==RBRACT || n==RPAREN))
					continue;
				if((c==RBRACE||c==RPAREN) && n==RPAREN)
				{
					if(fcgetc(n)==LPAREN)
					{
						if(c!=RPAREN)
							fcseek(-1);
						continue;
					}
					if(n>0)
						fcseek(-1);
					n = RPAREN;
				}
				if(c==';' && n!=';')
				{
					if(lexd.warn && n==RBRACE)
						errormsg(SH_DICT,ERROR_warn(0),e_lexusequote,shp->inlineno,c);
					continue;
				}
				if(mode==ST_QNEST)
				{
					if(lexd.warn)
						errormsg(SH_DICT,ERROR_warn(0),e_lexescape,shp->inlineno,c);
					continue;
				}
				mode = oldmode();
				poplevel();
				/* quotes in subscript need expansion */
				if(mode==ST_NAME && (wordflags&ARG_QUOTED))
					wordflags |= ARG_MAC;
				/* check for ((...)) */
				if(n==1 && c==RPAREN)
				{
					if(fcgetc(n)==RPAREN)
					{
						if(mode==ST_NONE && !lexd.dolparen)
							goto breakloop;
						lex.reservok = 1;
						lex.skipword = 0;
						return(shlex.token=EXPRSYM);
					}
					/* backward compatibility */
					if(lexd.dolparen)
						fcseek(-1);
					else
					{
						if(lexd.warn)
							errormsg(SH_DICT,ERROR_warn(0),e_lexnested,shp->inlineno);
						if(!(state=lexd.first))
							state = fcfirst();
						fcseek(state-fcseek(0));
						if(shlex.arg)
						{
							shlex.arg = (struct argnod*)stakfreeze(1);
							setupalias(lp,shlex.arg->argval,NIL(Namval_t*));
						}
						lexd.paren = 1;
					}
					return(shlex.token=LPAREN);
				}
				if(mode==ST_NONE)
					return(0);
				if(c!=n)
				{
					shlex.token = c;
					sh_syntax();
				}
				if(c==RBRACE && (mode==ST_NAME||mode==ST_NORM))
					goto epat;
				continue;
			case S_EQ:
				assignment = shlex.assignok;
				/* FALL THRU */
			case S_COLON:
				if(assignment)
				{
					if((c=fcget())=='~')
						wordflags |= ARG_MAC;
					else if(c!=LPAREN && assignment==SH_COMPASSIGN)
						assignment = 0;
					fcseek(-1);
				}
				break;
			case S_LABEL:
				if(lex.reservok && !lex.incase)
				{
					c = fcget();
					fcseek(-1);
					if(state[c]==S_BREAK)
					{
						assignment = -1;
						goto breakloop;
					}
				}
				break;
			case S_BRACT:
				/* check for possible subscript */
				if((n=endchar())==RBRACT || n==RPAREN || 
					(mode==ST_BRACE) ||
					(oldmode()==ST_NONE) ||
					(mode==ST_NAME && (shlex.assignok||lexd.level)))
				{
					pushlevel(RBRACT,mode);
					wordflags |= ARG_QUOTED;
					mode = ST_NESTED;
					continue;
				}
				wordflags |= ARG_EXP;
				break;
			case S_BRACE:
			{
				int isfirst;
				if(lexd.dolparen)
					break;
				isfirst = (lexd.first&&fcseek(0)==lexd.first+1);
				fcgetc(n);
				/* check for {} */
				if(c==LBRACE && n==RBRACE)
					break;
				if(n>0)
					fcseek(-1);
				else if(lex.reservok)
					break;
				/* check for reserved word { or } */
				if(lex.reservok && state[n]==S_BREAK && isfirst)
					break;
				if(sh_isoption(SH_BRACEEXPAND) && c==LBRACE && !assignment && state[n]!=S_BREAK
					&& !lex.incase && !lex.intest
					&& !lex.skipword)
				{
					wordflags |= ARG_EXP;
				}
				if(c==RBRACE && n==LPAREN)
					goto epat;
				break;
			}
			case S_PAT:
				wordflags |= ARG_EXP;
				/* FALL THRU */
			case S_EPAT:
			epat:
				if(fcgetc(n)==LPAREN)
				{
					if(lex.incase==TEST_RE)
					{
						lex.incase++;
						pushlevel(RPAREN,ST_NORM);
						mode = ST_NESTED;
					}
					wordflags |= ARG_EXP;
					pushlevel(RPAREN,mode);
					mode = ST_NESTED;
					continue;
				}
				if(n>0)
					fcseek(-1);
				if(n=='=' && c=='+' && mode==ST_NAME)
					continue;
				break;
		}
		lex.comp_assign = 0;
		if(mode==ST_NAME)
			mode = ST_NORM;
		else if(mode==ST_NONE)
			return(0);
	}
breakloop:
	if(lexd.dolparen)
	{
		lexd.balance = 0;
		if(lexd.docword)
			nested_here(lp);
		lexd.message = (wordflags&ARG_MESSAGE);
		return(shlex.token=0);
	}
	if(!(state=lexd.first))
		state = fcfirst();
	n = fcseek(0)-(char*)state;
	if(!shlex.arg)
		shlex.arg = (struct argnod*)stakseek(ARGVAL);
	if(n>0)
		stakwrite(state,n);
	/* add balancing character if necessary */
	if(lexd.balance)
	{
		stakputc(lexd.balance);
		lexd.balance = 0;
	}
	stakputc(0);
	stakseek(staktell()-1);
	state = stakptr(ARGVAL);
	n = staktell()-ARGVAL;
	lexd.first=0;
	if(n==1)
	{
		/* check for numbered redirection */
		n = state[0];
		if((c=='<' || c=='>') && isadigit(n))
		{
			c = sh_lex();
			shlex.digits = (n-'0'); 
			return(c);
		}
		if(n==LBRACT)
			c = 0;
		else if(n=='~')
			c = ARG_MAC;
		else
			c = (wordflags&ARG_EXP);
		n = 1;
	}
	else if(n>2 && state[0]=='{' && state[n-1]=='}' && !lex.intest && !lex.incase && (c=='<' || c== '>') && sh_isoption(SH_BRACEEXPAND))
	{
		if(!strchr(state,','))
		{
			stakseek(staktell()-1);
			shlex.arg = (struct argnod*)stakfreeze(1);
			return(shlex.token=IOVNAME);
		}
		c = wordflags;
	}
	else
		c = wordflags;
	if(assignment<0)
	{
		stakseek(staktell()-1);
		shlex.arg = (struct argnod*)stakfreeze(1);
		lex.reservok = 1;
		return(shlex.token=LABLSYM);
	}
	if(assignment || (lex.intest&&!lex.incase) || mode==ST_NONE)
		c &= ~ARG_EXP;
	if((c&ARG_EXP) && (c&ARG_QUOTED))
		c |= ARG_MAC;
	if(mode==ST_NONE)
	{
		/* eliminate trailing )) */
		stakseek(staktell()-2);
	}
	if(c&ARG_MESSAGE)
	{
		if(sh_isoption(SH_DICTIONARY))
			shlex.arg = sh_endword(2);
		if(!sh_isoption(SH_NOEXEC))
		{
			shlex.arg = sh_endword(1);
			c &= ~ARG_MESSAGE;
		}
	}
	if(c==0 || (c&(ARG_MAC|ARG_EXP)) || (lexd.warn && !lexd.docword))
	{
		shlex.arg = (struct argnod*)stakfreeze(1);
		shlex.arg->argflag = (c?c:ARG_RAW);
	}
	else if(mode==ST_NONE)
		shlex.arg = sh_endword(-1);
	else
		shlex.arg = sh_endword(0);
	state = shlex.arg->argval;
	lex.comp_assign = assignment;
	if(assignment)
		shlex.arg->argflag |= ARG_ASSIGN;
	else if(!lex.skipword)
		shlex.assignok = 0;
	shlex.arg->argchn.cp = 0;
	shlex.arg->argnxt.ap = 0;
	if(mode==ST_NONE)
		return(shlex.token=EXPRSYM);
	if(lex.intest)
	{
		if(lex.testop1)
		{
			lex.testop1 = 0;
			if(n==2 && state[0]=='-' && state[2]==0 &&
				strchr(test_opchars,state[1]))
			{
				if(lexd.warn && state[1]=='a')
					errormsg(SH_DICT,ERROR_warn(0),e_lexobsolete2,shp->inlineno);
				shlex.digits = state[1];
				shlex.token = TESTUNOP;
			}
			else if(n==1 && state[0]=='!' && state[1]==0)
			{
				lex.testop1 = 1;
				shlex.token = '!';
			}
			else
			{
				lex.testop2 = 1;
				shlex.token = 0;
			}
			return(shlex.token);
		}
		lex.incase = 0;
		c = sh_lookup(state,shtab_testops);
		switch(c)
		{
		case TEST_END:
			lex.testop2 = lex.intest = 0;
			lex.reservok = 1;
			shlex.token = ETESTSYM;
			return(shlex.token);

		case TEST_SEQ:
			if(lexd.warn && state[1]==0)
				errormsg(SH_DICT,ERROR_warn(0),e_lexobsolete3,shp->inlineno);
			/* FALL THRU */
		default:
			if(lex.testop2)
			{
				if(lexd.warn && (c&TEST_ARITH))
					errormsg(SH_DICT,ERROR_warn(0),e_lexobsolete4,shp->inlineno,state);
				if(c&TEST_PATTERN)
					lex.incase = 1;
				else if(c==TEST_REP)
					lex.incase = TEST_RE;
				lex.testop2 = 0;
				shlex.digits = c;
				shlex.token = TESTBINOP;	
				return(shlex.token);	
			}

		case TEST_OR: case TEST_AND:
		case 0:
			return(shlex.token=0);
		}
	}
	if(lex.reservok /* && !lex.incase*/ && n<=2)
	{
		/* check for {, }, ! */
		c = state[0];
		if(n==1 && (c=='{' || c=='}' || c=='!'))
		{
			if(lexd.warn && c=='{' && lex.incase==2)
				errormsg(SH_DICT,ERROR_warn(0),e_lexobsolete6,shp->inlineno);
			if(lex.incase==1 && c==RBRACE)
				lex.incase = 0;
			return(shlex.token=c);
		}
		else if(!lex.incase && c==LBRACT && state[1]==LBRACT)
		{
			lex.intest = lex.testop1 = 1;
			lex.testop2 = lex.reservok = 0;
			return(shlex.token=BTESTSYM);
		}
	}
	c = 0;
	if(!lex.skipword)
	{
		if(n>1 && lex.reservok==1 && mode==ST_NAME && 
			(c=sh_lookup(state,shtab_reserved)))
		{
			if(lex.incase)
			{
				if(lex.incase >1)
					lex.incase = 1;
				else if(c==ESACSYM)
					lex.incase = 0;
				else
					c = 0;
			}
			else if(c==FORSYM || c==CASESYM || c==SELECTSYM || c==FUNCTSYM || c==NSPACESYM)
			{
				lex.skipword = 1;
				lex.incase = 2*(c==CASESYM);
			}
			else
				lex.skipword = 0;
			if(c==INSYM)
				lex.reservok = 0;
			else if(c==TIMESYM)
			{
				/* yech - POSIX requires time -p */
				while(fcgetc(n)==' ' || n=='\t');
				if(n>0)
					fcseek(-1);
				if(n=='-')
					c=0;
			}
			return(shlex.token=c);
		}
		if(!(wordflags&ARG_QUOTED) && (lex.reservok||shlex.aliasok))
		{
			/* check for aliases */
			Namval_t* np;
			if(!lex.incase && !assignment && fcpeek(0)!=LPAREN &&
				(np=nv_search(state,shp->alias_tree,HASH_SCOPE))
				&& !nv_isattr(np,NV_NOEXPAND)
#if KSHELL
				&& (!sh_isstate(SH_NOALIAS) || nv_isattr(np,NV_NOFREE))
#endif /* KSHELL */
				&& (state=nv_getval(np)))
			{
				setupalias(lp,state,np);
				nv_onattr(np,NV_NOEXPAND);
				lex.reservok = 1;
				shlex.assignok |= lex.reservok;
				return(sh_lex());
			}
		}
		lex.reservok = 0;
	}
	lex.skipword = lexd.docword = 0;
	return(shlex.token=c);
}

/*
 * read to end of command substitution
 */
static int comsub(register Lex_t *lp)
{
	register int	n,c,count=1;
	register int	line=shlex.sh->inlineno;
	char word[5];
	int messages=0, assignok=shlex.assignok;
	struct lexstate	save;
	save = lex;
	sh_lexopen(lp,shlex.sh,1);
	lexd.dolparen++;
	lex.incase=0;
	pushlevel(0,0);
	if(sh_lex()==LPAREN)
	{
		while(1)
		{
			/* look for case and esac */
			n=0;
			while(1)
			{
				fcgetc(c);
				/* skip leading white space */
				if(n==0 && !sh_lexstates[ST_BEGIN][c])
					continue;
				if(n==4)
					break;
				if(sh_lexstates[ST_NAME][c])
					goto skip;
				word[n++] = c;
			}
			if(sh_lexstates[ST_NAME][c]==S_BREAK)
			{
				if(memcmp(word,"case",4)==0)
					lex.incase=1;
				else if(memcmp(word,"esac",4)==0)
					lex.incase=0;
			}
		skip:
			if(c && (c!='#' || n==0))
				fcseek(-1);
			if(c==RBRACE && lex.incase)
				lex.incase=0;
			switch(sh_lex())
			{
			    case LPAREN: case IPROCSYM:	case OPROCSYM:
				if(!lex.incase)
					count++;
				break;
			    case RPAREN:
				if(lex.incase)
					lex.incase=0;
				else if(--count<=0)
					goto done;
				break;
			    case EOFSYM:
				shlex.lastline = line;
				shlex.lasttok = LPAREN;
				sh_syntax();
			    case IOSEEKSYM:
				if(fcgetc(c)!='#' && c>0)
					fcseek(-1);
				break;
			    case IODOCSYM:
				sh_lex();
				break;
			    case 0:
				messages |= lexd.message;
			}
		}
	}
done:
	poplevel();
	shlex.lastline = line;
	lexd.dolparen--;
	lex = save;
	shlex.assignok = (endchar()==RBRACT?assignok:0);
	return(messages);
}

/*
 * here-doc nested in $(...)
 * allocate ionode with delimiter filled in without disturbing stak
 */
static void nested_here(register Lex_t *lp)
{
	register struct ionod *iop;
	register int n,offset;
	struct argnod *arg = shlex.arg;
	char *base;
	if(offset=staktell())
		base = stakfreeze(0);
	n = fcseek(0)-lexd.docend;
	iop = newof(0,struct ionod,1,n+ARGVAL);
	iop->iolst = shlex.heredoc;
	stakseek(ARGVAL);
	stakwrite(lexd.docend,n);
	shlex.arg = sh_endword(0);
	iop->ioname = (char*)(iop+1);
	strcpy(iop->ioname,shlex.arg->argval);
	iop->iofile = (IODOC|IORAW);
	if(lexd.docword>1)
		iop->iofile |= IOSTRIP;
	shlex.heredoc = iop;
	shlex.arg = arg;
	lexd.docword = 0;
	if(offset)
		stakset(base,offset);
	else
		stakseek(0);
}

/*
 * skip to <close> character
 * if <copy> is non,zero, then the characters are copied to the stack
 * <state> is the initial lexical state
 */
void sh_lexskip(int close, register int copy, int  state)
{
	register Lex_t	*lp = (Lex_t*)sh.lex_context;
	register char	*cp;
	lexd.nest = close;
	lexd.lex_state = state;
	lexd.noarg = 1;
	if(copy)
		fcnotify(lex_advance);
	else
		lexd.nocopy++;
	sh_lex();
	lexd.noarg = 0;
	if(copy)
	{
		fcnotify(0);
		if(!(cp=lexd.first))
			cp = fcfirst();
		if((copy = fcseek(0)-cp) > 0)
			stakwrite(cp,copy);
	}
	else
		lexd.nocopy--;
}

#if SHOPT_CRNL
    ssize_t _sfwrite(Sfio_t *sp, const Void_t *buff, size_t n)
    {
	const char *cp = (const char*)buff, *next=cp, *ep = cp + n;
	int m=0,k;
	while(next = (const char*)memchr(next,'\r',ep-next))
		if(*++next=='\n')
		{
			if(k=next-cp-1)
			{
				if((k=sfwrite(sp,cp,k)) < 0)
					return(m>0?m:-1);
				m += k;
			}
			cp = next;
		}
	if((k=sfwrite(sp,cp,ep-cp)) < 0)
		return(m>0?m:-1);
	return(m+k);
    }
#   define sfwrite	_sfwrite
#endif /* SHOPT_CRNL */

/*
 * read in here-document from script
 * quoted here documents, and here-documents without special chars are
 * noted with the IOQUOTE flag
 * returns 1 for complete here-doc, 0 for EOF
 */

static int here_copy(Lex_t *lp,register struct ionod *iop)
{
	register const char	*state;
	register int		c,n;
	register char		*bufp,*cp;
	register Sfio_t		*sp=shlex.sh->heredocs, *funlog;
	int			stripcol=0,stripflg, nsave, special=0;
	if(funlog=shlex.sh->funlog)
	{
		if(fcfill()>0)
			fcseek(-1);
		shlex.sh->funlog = 0;
	}
	if(iop->iolst)
		here_copy(lp,iop->iolst);
	iop->iooffset = sfseek(sp,(off_t)0,SEEK_END);
	iop->iosize = 0;
	iop->iodelim=iop->ioname;
	/* check for and strip quoted characters in delimiter string */
	if(stripflg=iop->iofile&IOSTRIP)
	{
		while(*iop->iodelim=='\t')
			iop->iodelim++;
		/* skip over leading tabs in document */
		if(iop->iofile&IOLSEEK)
		{
			iop->iofile &= ~IOLSEEK;
			while(fcgetc(c)=='\t' || c==' ')
			{
				if(c==' ')
					stripcol++;
				else
					stripcol += 8 - stripcol%8;
			}
		}
		else
			while(fcgetc(c)=='\t');
		if(c>0)
			fcseek(-1);
	}
	if(iop->iofile&IOQUOTE)
		state = sh_lexstates[ST_LIT];
	else
		state = sh_lexstates[ST_QUOTE];
	bufp = fcseek(0);
	n = S_NL;
	while(1)
	{
		if(n!=S_NL)
		{
			/* skip over regular characters */
			while((n=STATE(state,c))==0);
		}
		if(n==S_EOF || !(c=fcget()))
		{
			if(!lexd.dolparen && (c=(fcseek(0)-1)-bufp))
			{
				if(n==S_ESC)
					c--;
				if((c=sfwrite(sp,bufp,c))>0)
					iop->iosize += c;
			}
			if((c=lexfill())<=0)
				break;
			if(n==S_ESC)
			{
#if SHOPT_CRNL
				if(c=='\r' && (c=fcget())!=NL)
					fcseek(-1);
#endif /* SHOPT_CRNL */
				if(c==NL)
					fcseek(1);
				else
					sfputc(sp,'\\');
			}
			bufp = fcseek(-1);
		}
		else
			fcseek(-1);
		switch(n)
		{
		    case S_NL:
			shlex.sh->inlineno++;
			if((stripcol && c==' ') || (stripflg && c=='\t'))
			{
				if(!lexd.dolparen)
				{
					/* write out line */
					n = fcseek(0)-bufp;
					if((n=sfwrite(sp,bufp,n))>0)
						iop->iosize += n;
				}
				/* skip over tabs */
				if(stripcol)
				{
					int col=0;
					do
					{
						fcgetc(c);
						if(c==' ')
							col++;
						else
							col += 8 - col%8;
						if(col>stripcol)
							break;
					}
					while (c==' ' || c=='\t');
				}
				else while(c=='\t')
					fcgetc(c);
				if(c<=0)
					goto done;
				bufp = fcseek(-1);
			}
			if(c!=iop->iodelim[0])
				break;
			cp = fcseek(0);
			nsave = n = 0;
			while(1)
			{
				if(!(c=fcget())) 
				{
					if(!lexd.dolparen && (c=cp-bufp))
					{
						if((c=sfwrite(sp,cp=bufp,c))>0)
							iop->iosize+=c;
					}
					nsave = n;
					if((c=lexfill())<=0)
					{
						c = iop->iodelim[n]==0;
						goto done;
					}
				}
#if SHOPT_CRNL
				if(c=='\r' && (c=fcget())!=NL)
				{
					if(c)
						fcseek(-1);
					c='\r';
				}
#endif /* SHOPT_CRNL */
				if(c==NL)
					shlex.sh->inlineno++;
				if(iop->iodelim[n]==0 && (c==NL||c==RPAREN))
				{
					if(!lexd.dolparen && (n=cp-bufp))
					{
						if((n=sfwrite(sp,bufp,n))>0)
							iop->iosize += n;
					}
					shlex.sh->inlineno--;
					if(c==RPAREN)
						fcseek(-1);
					goto done;
				}
				if(iop->iodelim[n++]!=c)
				{
					/*
					 * The match for delimiter failed.
					 * nsave>0 only when a buffer boundary
					 * was crossed while checking the
					 * delimiter
					 */
					if(!lexd.dolparen && nsave>0)
					{
						if((n=sfwrite(sp,bufp,nsave))>0)
							iop->iosize += n;
						bufp = fcfirst();
					}
					if(c==NL)
						fcseek(-1);
					break;
				}
			}
			break;
		    case S_ESC:
			n=1;
#if SHOPT_CRNL
			if(c=='\r')
			{
				fcseek(1);
				if(c=fcget())
					fcseek(-1);
				if(c==NL)
					n=2;
				else
				{
					special++;
					break;
				}
			}
#endif /* SHOPT_CRNL */
			if(c==NL)
			{
				/* new-line joining */
				shlex.sh->inlineno++;
				if(!lexd.dolparen && (n=(fcseek(0)-bufp)-n)>0)
				{
					if((n=sfwrite(sp,bufp,n))>0)
						iop->iosize += n;
					bufp = fcseek(0)+1;
				}
			}
			else
				special++;
			fcget();
			break;
				
		    case S_GRAVE:
		    case S_DOL:
			special++;
			break;
		}
		n=0;
	}
done:
	shlex.sh->funlog = funlog;
	if(lexd.dolparen)
		free((void*)iop);
	else if(!special)
		iop->iofile |= IOQUOTE;
	return(c);
}

/*
 * generates string for given token
 */
static char	*fmttoken(Lex_t *lp, register int sym, char *tok)
{
	if(sym < 0)
		return((char*)sh_translate(e_lexzerobyte));
	if(sym==0)
		return(shlex.arg?shlex.arg->argval:"?");
	if(lex.intest && shlex.arg && *shlex.arg->argval)
		return(shlex.arg->argval);
	if(sym&SYMRES)
	{
		register const Shtable_t *tp=shtab_reserved;
		while(tp->sh_number && tp->sh_number!=sym)
			tp++;
		return((char*)tp->sh_name);
	}
	if(sym==EOFSYM)
		return((char*)sh_translate(e_endoffile));
	if(sym==NL)
		return((char*)sh_translate(e_newline));
	tok[0] = sym;
	if(sym&SYMREP)
		tok[1] = sym;
	else
	{
		switch(sym&SYMMASK)
		{
			case SYMAMP:
				sym = '&';
				break;
			case SYMPIPE:
				sym = '|';
				break;
			case SYMGT:
				sym = '>';
				break;
			case SYMLPAR:
				sym = LPAREN;
				break;
			case SYMSHARP:
				sym = '#';
				break;
			default:
				sym = 0;
		}
		tok[1] = sym;
	}
	tok[2] = 0;
	return(tok);
}

/*
 * print a bad syntax message
 */

void	sh_syntax(void)
{
	register Shell_t *shp = sh_getinterp();
	register const char *cp = sh_translate(e_unexpected);
	register char *tokstr;
	register Lex_t	*lp = (Lex_t*)shp->lex_context;
	register int tok = shlex.token;
	char tokbuf[3];
	Sfio_t *sp;
	if((tok==EOFSYM) && shlex.lasttok)
	{
		tok = shlex.lasttok;
		cp = sh_translate(e_unmatched);
	}
	else
		shlex.lastline = shp->inlineno;
	tokstr = fmttoken(lp,tok,tokbuf);
	if((sp=fcfile()) || (shp->infd>=0 && (sp=shp->sftable[shp->infd])))
	{
		/* clear out any pending input */
		register Sfio_t *top;
		while(fcget()>0);
		fcclose();
		while(top=sfstack(sp,SF_POPSTACK))
			sfclose(top);
	}
	else
		fcclose();
	shp->inlineno = shlex.inlineno;
	shp->st.firstline = shlex.firstline;
#if KSHELL
	if(!sh_isstate(SH_INTERACTIVE) && !sh_isstate(SH_PROFILE))
#else
	if(shp->inlineno!=1)
#endif
		errormsg(SH_DICT,ERROR_exit(SYNBAD),e_lexsyntax1,shlex.lastline,tokstr,cp);
	else
		errormsg(SH_DICT,ERROR_exit(SYNBAD),e_lexsyntax2,tokstr,cp);
}

static char *stack_shift(register char *sp,char *dp)
{
	register char *ep;
	register int offset = staktell();
	register int left = offset-(sp-stakptr(0));
	register int shift = (dp+1-sp);
	offset += shift;
	stakseek(offset);
	sp = stakptr(offset);
	ep = sp - shift;
	while(left--)
		*--sp = *--ep;
	return(sp);
}

/*
 * Assumes that current word is unfrozen on top of the stak
 * If <mode> is zero, gets rid of quoting and consider argument as string
 *    and returns pointer to frozen arg
 * If mode==1, just replace $"..." strings with international strings
 *    The result is left on the stak
 * If mode==2, the each $"" string is printed on standard output
 */
struct argnod *sh_endword(int mode)
{
	register const char *state = sh_lexstates[ST_NESTED];
	register int n;
	register char *sp,*dp;
	register int inquote=0, inlit=0; /* set within quoted strings */
	struct argnod* argp=0;
	char	*ep=0, *xp=0;
	int bracket=0;
	stakputc(0);
	sp =  stakptr(ARGVAL);
#if SHOPT_MULTIBYTE
	if(mbwide())
	{
		do
		{
			int len;
			switch(len = mbsize(sp))
			{
			    case -1:	/* illegal multi-byte char */
			    case 0:
			    case 1:
				n=state[*sp++];
				break;
			    default:
				/*
				 * None of the state tables contain
				 * entries for multibyte characters,
				 * however, they should be treated
				 * the same as any other alph
				 * character.  Therefore, we'll use
				 * the state of the 'a' character.
				 */
				n=state['a'];
				sp += len;
			}
		}
		while(n == 0);
	}
	else
#endif /* SHOPT_MULTIBYTE */
	while((n=state[*sp++])==0);
	dp = sp;
	if(mode<0)
		inquote = 1;
	while(1)
	{
		switch(n)
		{
		    case S_EOF:
			stakseek(dp-stakptr(0));
			if(mode<=0)
			{
				argp = (struct argnod*)stakfreeze(0);
				argp->argflag = ARG_RAW|ARG_QUOTED;
			}
			return(argp);
		    case S_LIT:
			if(!(inquote&1))
			{
				inlit = !inlit;
				if(mode==0 || (mode<0 && bracket))
				{
					dp--;
					if(ep)
					{
						*dp = 0;
						dp = ep+stresc(ep);
					}
					ep = 0;
				}
			}
			break;
		    case S_QUOTE:
			if(mode<0 && !bracket)
				break;
			if(!inlit)
			{
				if(mode<=0)
					dp--;
				inquote = inquote^1;
				if(ep)
				{
					char *msg;
					if(mode==2)
					{
						sfprintf(sfstdout,"%.*s\n",dp-ep,ep);
						ep = 0;
						break;
					}
					*--dp = 0;
#if ERROR_VERSION >= 20000317L
					msg = ERROR_translate(0,error_info.id,0,ep);
#else
#   if ERROR_VERSION >= 20000101L
					msg = ERROR_translate(error_info.id,ep);
#   else
					msg = ERROR_translate(ep,2);
#   endif
#endif
					n = strlen(msg);
					dp = ep+n;
					if(sp-dp <= 1)
					{
						sp = stack_shift(sp,dp);
						dp = sp-1;
						ep = dp-n;
					}
					memmove(ep,msg,n);
					*dp++ = '"';
				}
				ep = 0;
			}
			break;
		    case S_DOL:	/* check for $'...'  and $"..." */
			if(inlit)
				break;
			if(*sp==LPAREN || *sp==LBRACE)
			{
				inquote <<= 1;
				break;
			}
			if(inquote&1)
				break;
			if(*sp=='\'' || *sp=='"')
			{
				if(*sp=='"')
					inquote |= 1;
				else
					inlit = 1;
				sp++;
				if((mode==0||(mode<0&&bracket)) || (inquote&1))
				{
					if(mode==2)
						ep = dp++;
					else if(mode==1)
						(ep=dp)[-1] = '"';
					else
						ep = --dp;
				}
			}
			break;
		    case S_ESC:
#if SHOPT_CRNL
			if(*sp=='\r' && sp[1]=='\n')
				sp++;
#endif /* SHOPT_CRNL */
			if(inlit || mode>0)
			{
				if(mode<0)
				{
					if(dp>=sp)
					{
						sp = stack_shift(sp,dp+1);
						dp = sp-2;
					}
					*dp++ = '\\';
				}
				if(ep)
					*dp++ = *sp++;
				break;
			}
			n = *sp;
#if SHOPT_DOS
			if(!(inquote&1) && sh_lexstates[ST_NORM][n]==0)
				break;
#endif /* SHOPT_DOS */
			if(!(inquote&1) || (sh_lexstates[ST_QUOTE][n] && n!=RBRACE))
			{
				if(n=='\n')
					dp--;
				else
					dp[-1] = n;
				sp++;
			}
			break;
		    case S_POP:
			if(sp[-1]!=RBRACT)
				break;
			if(!inlit && !(inquote&1))
			{
				inquote >>= 1;
				if(xp)
					dp = sh_checkid(xp,dp);
				xp = 0;
				if(--bracket<=0 && mode<0)
					inquote = 1;
			}
			else if((inlit||inquote) && mode<0)
			{
				dp[-1] = '\\';
				if(dp>=sp)
				{
					sp = stack_shift(sp,dp);
					dp = sp-1;
				}
				*dp++ = ']';
			}
			break;
		    case S_BRACT:
			if(dp[-2]=='.')
				xp = dp;
			if(mode<0)
			{
				if(inlit || (bracket&&inquote))
				{
					dp[-1] = '\\';
					if(dp>=sp)
					{
						sp = stack_shift(sp,dp);
						dp = sp-1;
					}
					*dp++ = '[';
				}
				else if(bracket++==0)
					inquote = 0;
			}
			break;
		}
#if SHOPT_MULTIBYTE
		if(mbwide())
		{
			do
			{
				int len;
				switch(len = mbsize(sp))
				{
				    case -1: /* illegal multi-byte char */
				    case 0:
				    case 1:
					n=state[*dp++ = *sp++];
					break;
				    default:
					/*
					 * None of the state tables contain
					 * entries for multibyte characters,
					 * however, they should be treated
					 * the same as any other alph
					 * character.  Therefore, we'll use
					 * the state of the 'a' character.
					 */
					while(len--)
						*dp++ = *sp++;
					n=state['a'];
				}
			}
			while(n == 0);
		}
		else
#endif /* SHOPT_MULTIBYTE */
		while((n=state[*dp++ = *sp++])==0);
	}
}

struct alias
{
	Sfdisc_t	disc;
	Namval_t	*np;
	int		nextc;
	int		line;
	char		buf[2];
	Lex_t		*lp;
};

/*
 * This code gets called whenever an end of string is found with alias
 */

#ifndef SF_ATEXIT
#   define SF_ATEXIT	0
#endif
/*
 * This code gets called whenever an end of string is found with alias
 */
#ifdef SF_BUFCONST
static int alias_exceptf(Sfio_t *iop,int type,void *data, Sfdisc_t *handle)
#else
static int alias_exceptf(Sfio_t *iop,int type,Sfdisc_t *handle)
#endif
{
	register struct alias *ap = (struct alias*)handle;
	register Namval_t *np;
	register Lex_t	*lp;
	if(type==0 || type==SF_ATEXIT || !ap)
		return(0);
	lp = ap->lp;
	np = ap->np;
	if(type!=SF_READ)
	{
		if(type==SF_CLOSING)
		{
			register Sfdisc_t *dp = sfdisc(iop,SF_POPDISC);
			if(dp!=handle)
				sfdisc(iop,dp);
		}
		else if(type==SF_FINAL)
			free((void*)ap);
		goto done;
	}
	if(ap->nextc)
	{
		/* if last character is a blank, then next work can be alias */
		register int c = fcpeek(-1);
		if(isblank(c))
			shlex.aliasok = 1;
		*ap->buf = ap->nextc;
		ap->nextc = 0;
		sfsetbuf(iop,ap->buf,1);
		return(1);
	}
done:
	if(np)
		nv_offattr(np,NV_NOEXPAND);
	return(0);
}


static void setupalias(Lex_t *lp, const char *string,Namval_t *np)
{
	register Sfio_t *iop, *base;
	struct alias *ap = (struct alias*)malloc(sizeof(struct alias));
	ap->disc = alias_disc;
	ap->lp = lp;
	ap->buf[1] = 0;
	if(ap->np = np)
	{
#if SHOPT_KIA
		if(shlex.kiafile)
		{
			unsigned long r;
			r=kiaentity(nv_name(np),-1,'p',0,0,shlex.current,'a',0,"");
			sfprintf(shlex.kiatmp,"p;%..64d;p;%..64d;%d;%d;e;\n",shlex.current,r,shlex.sh->inlineno,shlex.sh->inlineno);
		}
#endif /* SHOPT_KIA */
		if((ap->nextc=fcget())==0)
			ap->nextc = ' ';
	}
	else
		ap->nextc = 0;
	iop = sfopen(NIL(Sfio_t*),(char*)string,"s");
	sfdisc(iop, &ap->disc);
	lexd.nocopy++;
	if(!(base=fcfile()))
		base = sfopen(NIL(Sfio_t*),fcseek(0),"s");
	fcclose();
	sfstack(base,iop);
	fcfopen(base);
	lexd.nocopy--;
}

/*
 * grow storage stack for nested constructs by STACK_ARRAY
 */
static int stack_grow(Lex_t *lp)
{
	lexd.lex_max += STACK_ARRAY;
	if(lexd.lex_match)
		lexd.lex_match = (int*)realloc((char*)lexd.lex_match,sizeof(int)*lexd.lex_max);
	else
		lexd.lex_match = (int*)malloc(sizeof(int)*STACK_ARRAY);
	return(lexd.lex_match!=0);
}

