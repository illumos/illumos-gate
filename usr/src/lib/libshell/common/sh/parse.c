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
 * UNIX shell
 *
 * S. R. Bourne
 * Rewritten by David Korn
 * AT&T Labs
 *
 *  This is the parser for a shell language
 */

#if KSHELL
#include	"defs.h"
#else
#include	<shell.h>
#include	<ctype.h>
#endif
#include	<fcin.h>
#include	<error.h>
#include	"shlex.h"
#include	"history.h"
#include	"builtins.h"
#include	"test.h"
#include	"history.h"

#define HERE_MEM	1024	/* size of here-docs kept in memory */

#define hash	nvlink.hl._hash

/* These routines are local to this module */

static Shnode_t	*makeparent(Lex_t*, int, Shnode_t*);
static Shnode_t	*makelist(Lex_t*, int, Shnode_t*, Shnode_t*);
static struct argnod	*qscan(struct comnod*, int);
static struct ionod	*inout(Lex_t*,struct ionod*, int);
static Shnode_t	*sh_cmd(Lex_t*,int,int);
static Shnode_t	*term(Lex_t*,int);
static Shnode_t	*list(Lex_t*,int);
static struct regnod	*syncase(Lex_t*,int);
static Shnode_t	*item(Lex_t*,int);
static Shnode_t	*simple(Lex_t*,int, struct ionod*);
static int	skipnl(Lex_t*,int);
static Shnode_t	*test_expr(Lex_t*,int);
static Shnode_t	*test_and(Lex_t*);
static Shnode_t	*test_or(Lex_t*);
static Shnode_t	*test_primary(Lex_t*);

#define	sh_getlineno(lp)	(lp->lastline)

#ifndef NIL
#   define NIL(type)	((type)0)
#endif /* NIL */
#define CNTL(x)		((x)&037)


#if !KSHELL
static struct stdata
{
	struct slnod    *staklist;
	int	cmdline;
} st;
#endif

static int		opt_get;
static int		loop_level;
static struct argnod	*label_list;
static struct argnod	*label_last;

#define getnode(type)	((Shnode_t*)stakalloc(sizeof(struct type)))

#if SHOPT_KIA
#include	"path.h"
/*
 * write out entities for each item in the list
 * type=='V' for variable assignment lists
 * Otherwise type is determined by the command */
static unsigned long writedefs(Lex_t *lexp,struct argnod *arglist, int line, int type, struct argnod *cmd)
{
	register struct argnod *argp = arglist;
	register char *cp;
	register int n,eline;
	int width=0;
	unsigned long r=0;
	static char atbuff[20];
	int  justify=0;
	char *attribute = atbuff;
	unsigned long parent=lexp->script;
	if(type==0)
	{
		parent = lexp->current;
		type = 'v';
		switch(*argp->argval)
		{
		    case 'a':
			type='p';
			justify = 'a';
			break;
		    case 'e':
			*attribute++ =  'x';
			break;
		    case 'r':
			*attribute++ = 'r';
			break;
		    case 'l':
			break;
		}
		while(argp = argp->argnxt.ap)
		{
			if((n= *(cp=argp->argval))!='-' && n!='+')
				break;
			if(cp[1]==n)
				break;
			while((n= *++cp))
			{
				if(isdigit(n))
					width = 10*width + n-'0';
				else if(n=='L' || n=='R' || n =='Z')
					justify=n;
				else
					*attribute++ = n;
			}
		}
	}
	else if(cmd)
		parent=kiaentity(lexp,sh_argstr(cmd),-1,'p',-1,-1,lexp->unknown,'b',0,"");
	*attribute = 0;
	while(argp)
	{
		if((cp=strchr(argp->argval,'='))||(cp=strchr(argp->argval,'?')))
			n = cp-argp->argval;
		else
			n = strlen(argp->argval);
		eline = lexp->sh->inlineno-(lexp->token==NL);
		r=kiaentity(lexp,argp->argval,n,type,line,eline,parent,justify,width,atbuff);
		sfprintf(lexp->kiatmp,"p;%..64d;v;%..64d;%d;%d;s;\n",lexp->current,r,line,eline);
		argp = argp->argnxt.ap;
	}
	return(r);
}
#endif /* SHOPT_KIA */

static void typeset_order(const char *str,int line)
{
	register int		c,n=0;
	unsigned const char	*cp=(unsigned char*)str;
	static unsigned char	*table;
	if(*cp!='+' && *cp!='-')
		return;
	if(!table)
	{
		table = calloc(1,256);
		for(cp=(unsigned char*)"bflmnprstuxACHS";c = *cp; cp++)
			table[c] = 1;
		for(cp=(unsigned char*)"aiEFLRXhTZ";c = *cp; cp++)
			table[c] = 2;
		for(c='0'; c <='9'; c++)
			table[c] = 3;
	}
	for(cp=(unsigned char*)str; c= *cp++; n=table[c])
	{
		if(table[c] < n)
			errormsg(SH_DICT,ERROR_warn(0),e_lextypeset,line,str);
	}
}

/*
 * add type definitions when compiling with -n
 */
static void check_typedef(struct comnod *tp)
{
	char	*cp=0;
	if(tp->comtyp&COMSCAN)
	{
		struct argnod *ap = tp->comarg;
		while(ap = ap->argnxt.ap)
		{
			if(!(ap->argflag&ARG_RAW) || memcmp(ap->argval,"--",2))
				break;
			if(sh_isoption(SH_NOEXEC))
				typeset_order(ap->argval,tp->comline);
			if(memcmp(ap->argval,"-T",2)==0)
			{
				if(ap->argval[2])
					cp = ap->argval+2;
				else if((ap->argnxt.ap)->argflag&ARG_RAW)
					cp = (ap->argnxt.ap)->argval;
				if(cp)
					break;
			}
		}
	}
	else
	{
		struct dolnod *dp = (struct dolnod*)tp->comarg;
		char **argv = dp->dolval + dp->dolbot+1;
		while((cp= *argv++) && memcmp(cp,"--",2))
		{
			if(sh_isoption(SH_NOEXEC))
				typeset_order(cp,tp->comline);
			if(memcmp(cp,"-T",2)==0)
			{
				if(cp[2])
					cp = cp+2;
				else
					cp = *argv;
				break;
			}
		}
	}
	if(cp)
	{
		Namval_t	*mp=(Namval_t*)tp->comnamp ,*bp;
		bp = sh_addbuiltin(cp,mp->nvalue.bfp, (void*)0);
		nv_onattr(bp,nv_isattr(mp,NV_PUBLIC));
	}
}

/*
 * Make a parent node for fork() or io-redirection
 */
static Shnode_t	*makeparent(Lex_t *lp, int flag, Shnode_t *child)
{
	register Shnode_t	*par = getnode(forknod);
	par->fork.forktyp = flag;
	par->fork.forktre = child;
	par->fork.forkio = 0;
	par->fork.forkline = sh_getlineno(lp)-1;
	return(par);
}

static int paramsub(const char *str)
{
	register int c,sub=0,lit=0;
	while(c= *str++)
	{
		if(c=='$' && !lit)
		{
			if(*str=='(')
				return(0);
			if(sub)
				continue;
			if(*str=='{')
				str++;
			if(!isdigit(*str) && strchr("?#@*!$ ",*str)==0)
				return(1);
		}
		else if(c=='`')
			return(0);
		else if(c=='[' && !lit)
			sub++;
		else if(c==']' && !lit)
			sub--;
		else if(c=='\'')
			lit = !lit;
	}
	return(0);
}

static Shnode_t *getanode(Lex_t *lp, struct argnod *ap)
{
	register Shnode_t *t = getnode(arithnod);
	t->ar.artyp = TARITH;
	t->ar.arline = sh_getlineno(lp);
	t->ar.arexpr = ap;
	if(ap->argflag&ARG_RAW)
		t->ar.arcomp = sh_arithcomp(ap->argval);
	else
	{
		if(sh_isoption(SH_NOEXEC) && (ap->argflag&ARG_MAC) && paramsub(ap->argval))
			errormsg(SH_DICT,ERROR_warn(0),"%d: parameter substitution requires unnecessary string to number conversion",lp->sh->inlineno-(lp->token=='\n'));
		t->ar.arcomp = 0;
	}
	return(t);
}

/*
 *  Make a node corresponding to a command list
 */
static Shnode_t	*makelist(Lex_t *lexp, int type, Shnode_t *l, Shnode_t *r)
{
	register Shnode_t	*t;
	if(!l || !r)
		sh_syntax(lexp);
	else
	{
		if((type&COMMSK) == TTST)
			t = getnode(tstnod);
		else
			t = getnode(lstnod);
		t->lst.lsttyp = type;
		t->lst.lstlef = l;
		t->lst.lstrit = r;
	}
	return(t);
}

/*
 * entry to shell parser
 * Flag can be the union of SH_EOF|SH_NL
 */

void	*sh_parse(Shell_t *shp, Sfio_t *iop, int flag)
{
	register Shnode_t	*t;
	Lex_t			*lexp = (Lex_t*)shp->lex_context;
	Fcin_t	sav_input;
	struct argnod *sav_arg = lexp->arg;
	int	sav_prompt = shp->nextprompt;
	if(shp->binscript && (sffileno(iop)==shp->infd || (flag&SH_FUNEVAL)))
		return((void*)sh_trestore(shp,iop));
	fcsave(&sav_input);
	shp->st.staklist = 0;
	lexp->heredoc = 0;
	lexp->inlineno = shp->inlineno;
	lexp->firstline = shp->st.firstline;
	shp->nextprompt = 1;
	loop_level = 0;
	label_list = label_last = 0;
	if(sh_isoption(SH_INTERACTIVE))
		sh_onstate(SH_INTERACTIVE);
	if(sh_isoption(SH_VERBOSE))
		sh_onstate(SH_VERBOSE);
	sh_lexopen(lexp,shp,0);
	if(fcfopen(iop) < 0)
		return(NIL(void*));
	if(fcfile())
	{
		char *cp = fcfirst();
		if( cp[0]==CNTL('k') &&  cp[1]==CNTL('s') && cp[2]==CNTL('h') && cp[3]==0) 
		{
			int version;
			fcseek(4);
			fcgetc(version);
			fcclose();
			fcrestore(&sav_input);
			lexp->arg = sav_arg;
			if(version > 3)
				errormsg(SH_DICT,ERROR_exit(1),e_lexversion);
			if(sffileno(iop)==shp->infd || (flag&SH_FUNEVAL))
				shp->binscript = 1;
			sfgetc(iop);
			return((void*)sh_trestore(shp,iop));
		}
	}
	flag &= ~SH_FUNEVAL;
	if((flag&SH_NL) && (shp->inlineno=error_info.line+shp->st.firstline)==0)
		shp->inlineno=1;
#if KSHELL
	shp->nextprompt = 2;
#endif
	t = sh_cmd(lexp,(flag&SH_EOF)?EOFSYM:'\n',SH_SEMI|SH_EMPTY|(flag&SH_NL));
	fcclose();
	fcrestore(&sav_input);
	lexp->arg = sav_arg;
	/* unstack any completed alias expansions */
	if((sfset(iop,0,0)&SF_STRING) && !sfreserve(iop,0,-1))
	{
		Sfio_t *sp = sfstack(iop,NULL);
		if(sp)
			sfclose(sp);
	}
	shp->nextprompt = sav_prompt;
	if(flag&SH_NL)
	{
		shp->st.firstline = lexp->firstline;
		shp->inlineno = lexp->inlineno;
	}
	stkseek(shp->stk,0);
	return((void*)t);
}

/*
 * This routine parses up the matching right parenthesis and returns
 * the parse tree
 */
Shnode_t *sh_dolparen(Lex_t* lp)
{
	register Shnode_t *t=0;
	Sfio_t *sp = fcfile();
	int line = lp->sh->inlineno;
	lp->sh->inlineno = error_info.line+lp->sh->st.firstline;
	sh_lexopen(lp,lp->sh,1);
	lp->comsub = 1;
	switch(sh_lex(lp))
	{
	    /* ((...)) arithmetic expression */
	    case EXPRSYM:
		t = getanode(lp,lp->arg);
		break;
	    case LPAREN:
		t = sh_cmd(lp,RPAREN,SH_NL|SH_EMPTY);
		break;
	    case LBRACE:
		t = sh_cmd(lp,RBRACE,SH_NL|SH_EMPTY);
		break;
	}
	lp->comsub = 0;
	if(!sp && (sp=fcfile()))
	{
		/*
		 * This code handles the case where string has been converted
		 * to a file by an alias setup
		 */
		register int c;
		char *cp;
		if(fcgetc(c) > 0)
			fcseek(-1);
		cp = fcseek(0);
		fcclose();
		fcsopen(cp);
		sfclose(sp);
	}
	lp->sh->inlineno = line;
	return(t);
}

/*
 * remove temporary files and stacks
 */

void	sh_freeup(Shell_t *shp)
{
	if(shp->st.staklist)
		sh_funstaks(shp->st.staklist,-1);
	shp->st.staklist = 0;
}

/*
 * increase reference count for each stack in function list when flag>0
 * decrease reference count for each stack in function list when flag<=0
 * stack is freed when reference count is zero
 */

void sh_funstaks(register struct slnod *slp,int flag)
{
	register struct slnod *slpold;
	while(slpold=slp)
	{
		if(slp->slchild)
			sh_funstaks(slp->slchild,flag);
		slp = slp->slnext;
		if(flag<=0)
			stakdelete(slpold->slptr);
		else
			staklink(slpold->slptr);
	}
}
/*
 * cmd
 *	empty
 *	list
 *	list & [ cmd ]
 *	list [ ; cmd ]
 */

static Shnode_t	*sh_cmd(Lex_t *lexp, register int sym, int flag)
{
	register Shnode_t	*left, *right;
	register int type = FINT|FAMP;
	if(sym==NL)
		lexp->lasttok = 0;
	left = list(lexp,flag);
	if(lexp->token==NL)
	{
		if(flag&SH_NL)
			lexp->token=';';
	}
	else if(!left && !(flag&SH_EMPTY))
		sh_syntax(lexp);
	switch(lexp->token)
	{
	    case COOPSYM:		/* set up a cooperating process */
		type |= (FPIN|FPOU|FPCL|FCOOP);
		/* FALL THRU */		
	    case '&':
		if(left)
		{
			/* (...)& -> {...;} & */
			if(left->tre.tretyp==TPAR)
				left = left->par.partre;
			left = makeparent(lexp,TFORK|type, left);
		}
		/* FALL THRU */		
	    case ';':
		if(!left)
			sh_syntax(lexp);
		if(right=sh_cmd(lexp,sym,flag|SH_EMPTY))
			left=makelist(lexp,TLST, left, right);
		break;
	    case EOFSYM:
		if(sym==NL)
			break;
	    default:
		if(sym && sym!=lexp->token)
		{
			if(sym!=ELSESYM || (lexp->token!=ELIFSYM && lexp->token!=FISYM))
				sh_syntax(lexp);
		}
	}
	return(left);
}

/*
 * list
 *	term
 *	list && term
 *	list || term
 *      unfortunately, these are equal precedence
 */
static Shnode_t	*list(Lex_t *lexp, register int flag)
{
	register Shnode_t	*t = term(lexp,flag);
	register int 	token;
	while(t && ((token=lexp->token)==ANDFSYM || token==ORFSYM))
		t = makelist(lexp,(token==ANDFSYM?TAND:TORF), t, term(lexp,SH_NL|SH_SEMI));
	return(t);
}

/*
 * term
 *	item
 *	item | term
 */
static Shnode_t	*term(Lex_t *lexp,register int flag)
{
	register Shnode_t	*t;
	register int token;
	if(flag&SH_NL)
		token = skipnl(lexp,flag);
	else
		token = sh_lex(lexp);
	/* check to see if pipeline is to be timed */
	if(token==TIMESYM || token==NOTSYM)
	{
		t = getnode(parnod);
		t->par.partyp=TTIME;
		if(lexp->token==NOTSYM)
			t->par.partyp |= COMSCAN;
		t->par.partre = term(lexp,0);
	}
	else if((t=item(lexp,SH_NL|SH_EMPTY|(flag&SH_SEMI))) && lexp->token=='|')
	{
		register Shnode_t	*tt;
		int showme = t->tre.tretyp&FSHOWME;
		t = makeparent(lexp,TFORK|FPOU,t);
		if(tt=term(lexp,SH_NL))
		{
			switch(tt->tre.tretyp&COMMSK)
			{
			    case TFORK:
				tt->tre.tretyp |= FPIN|FPCL;
				break;
			    case TFIL:
				tt->lst.lstlef->tre.tretyp |= FPIN|FPCL;
				break;
			    default:
				tt= makeparent(lexp,TSETIO|FPIN|FPCL,tt);
			}
			t=makelist(lexp,TFIL,t,tt);
			t->tre.tretyp |= showme;
		}
		else if(lexp->token)
			sh_syntax(lexp);
	}
	return(t);
}

/*
 * case statement
 */
static struct regnod*	syncase(Lex_t *lexp,register int esym)
{
	register int tok = skipnl(lexp,0);
	register struct regnod	*r;
	if(tok==esym)
		return(NIL(struct regnod*));
	r = (struct regnod*)stakalloc(sizeof(struct regnod));
	r->regptr=0;
	r->regflag=0;
	if(tok==LPAREN)
		skipnl(lexp,0);
	while(1)
	{
		if(!lexp->arg)
			sh_syntax(lexp);
		lexp->arg->argnxt.ap=r->regptr;
		r->regptr = lexp->arg;
		if((tok=sh_lex(lexp))==RPAREN)
			break;
		else if(tok=='|')
			sh_lex(lexp);
		else
			sh_syntax(lexp);
	}
	r->regcom=sh_cmd(lexp,0,SH_NL|SH_EMPTY|SH_SEMI);
	if((tok=lexp->token)==BREAKCASESYM)
		r->regnxt=syncase(lexp,esym);
	else if(tok==FALLTHRUSYM)
	{
		r->regflag++;
		r->regnxt=syncase(lexp,esym);
	}
	else
	{
		if(tok!=esym && tok!=EOFSYM)
			sh_syntax(lexp);
		r->regnxt=0;
	}
	if(lexp->token==EOFSYM)
		return(NIL(struct regnod*));
	return(r);
}

/*
 * This routine creates the parse tree for the arithmetic for
 * When called, shlex.arg contains the string inside ((...))
 * When the first argument is missing, a while node is returned
 * Otherise a list containing an arithmetic command and a while
 * is returned.
 */
static Shnode_t	*arithfor(Lex_t *lexp,register Shnode_t *tf)
{
	register Shnode_t	*t, *tw = tf;
	register int	offset;
	register struct argnod *argp;
	register int n;
	Stk_t		*stkp = lexp->sh->stk;
	int argflag = lexp->arg->argflag;
	/* save current input */
	Fcin_t	sav_input;
	fcsave(&sav_input);
	fcsopen(lexp->arg->argval);
	/* split ((...)) into three expressions */
	for(n=0; ; n++)
	{
		register int c;
		argp = (struct argnod*)stkseek(stkp,ARGVAL);
		argp->argnxt.ap = 0;
		argp->argchn.cp = 0;
		argp->argflag = argflag;
		if(n==2)
			break;
		/* copy up to ; onto the stack */
		sh_lexskip(lexp,';',1,ST_NESTED);
		offset = stktell(stkp)-1;
		if((c=fcpeek(-1))!=';')
			break;
		/* remove trailing white space */
		while(offset>ARGVAL && ((c= *stkptr(stkp,offset-1)),isspace(c)))
			offset--;
		/* check for empty initialization expression  */
		if(offset==ARGVAL && n==0)
			continue;
		stkseek(stkp,offset);
		/* check for empty condition and treat as while((1)) */
		if(offset==ARGVAL)
			sfputc(stkp,'1');
		argp = (struct argnod*)stkfreeze(stkp,1);
		t = getanode(lexp,argp);
		if(n==0)
			tf = makelist(lexp,TLST,t,tw);
		else
			tw->wh.whtre = t;
	}
	while((offset=fcpeek(0)) && isspace(offset))
		fcseek(1);
	stakputs(fcseek(0));
	argp = (struct argnod*)stakfreeze(1);
	fcrestore(&sav_input);
	if(n<2)
	{
		lexp->token = RPAREN|SYMREP;
		sh_syntax(lexp);
	}
	/* check whether the increment is present */
	if(*argp->argval)
	{
		t = getanode(lexp,argp);
		tw->wh.whinc = (struct arithnod*)t;
	}
	else
		tw->wh.whinc = 0;
	sh_lexopen(lexp, lexp->sh,1);
	if((n=sh_lex(lexp))==NL)
		n = skipnl(lexp,0);
	else if(n==';')
		n = sh_lex(lexp);
	if(n!=DOSYM && n!=LBRACE)
		sh_syntax(lexp);
	tw->wh.dotre = sh_cmd(lexp,n==DOSYM?DONESYM:RBRACE,SH_NL);
	tw->wh.whtyp = TWH;
	return(tf);

}

static Shnode_t *funct(Lex_t *lexp)
{
	Shell_t	*shp = lexp->sh;
	register Shnode_t *t;
	register int flag;
	struct slnod *volatile slp=0;
	Stak_t *savstak;
	Sfoff_t	first, last;
	struct functnod *volatile fp;
	Sfio_t *iop;
#if SHOPT_KIA
	unsigned long current = lexp->current;
#endif /* SHOPT_KIA */
	int jmpval, saveloop=loop_level;
	struct argnod *savelabel = label_last;
	struct  checkpt buff;
	int save_optget = opt_get;
	void	*in_mktype = shp->mktype;
	shp->mktype = 0;
	opt_get = 0;
	t = getnode(functnod);
	t->funct.functline = shp->inlineno;
	t->funct.functtyp=TFUN;
	t->funct.functargs = 0;
	if(!(flag = (lexp->token==FUNCTSYM)))
		t->funct.functtyp |= FPOSIX;
	else if(sh_lex(lexp))
		sh_syntax(lexp);
	if(!(iop=fcfile()))
	{
		iop = sfopen(NIL(Sfio_t*),fcseek(0),"s");
		fcclose();
		fcfopen(iop);
	}
	t->funct.functloc = first = fctell();
	if(!shp->st.filename || sffileno(iop)<0)
	{
		if(fcfill() >= 0)
			fcseek(-1);
		if(sh_isstate(SH_HISTORY) && shp->hist_ptr)
			t->funct.functloc = sfseek(shp->hist_ptr->histfp,(off_t)0,SEEK_CUR);
		else
		{
			/* copy source to temporary file */
			t->funct.functloc = 0;
			if(lexp->sh->heredocs)
				t->funct.functloc = sfseek(lexp->sh->heredocs,(Sfoff_t)0, SEEK_END);
			else
				lexp->sh->heredocs = sftmp(HERE_MEM);
			lexp->sh->funlog = lexp->sh->heredocs;
			t->funct.functtyp |= FPIN;
		}
	}
	t->funct.functnam= (char*)lexp->arg->argval;
#if SHOPT_KIA
	if(lexp->kiafile)
		lexp->current = kiaentity(lexp,t->funct.functnam,-1,'p',-1,-1,lexp->script,'p',0,"");
#endif /* SHOPT_KIA */
	if(flag)
	{
		lexp->token = sh_lex(lexp);
#if SHOPT_BASH
		if(lexp->token == LPAREN)
		{
			if((lexp->token = sh_lex(lexp)) == RPAREN)
				t->funct.functtyp |= FPOSIX;
			else
				sh_syntax(lexp);
		}
#endif
	}
	if(t->funct.functtyp&FPOSIX)
		skipnl(lexp,0);
	else
	{
		if(lexp->token==0)
			t->funct.functargs = (struct comnod*)simple(lexp,SH_NOIO|SH_FUNDEF,NIL(struct ionod*));
		while(lexp->token==NL)
			lexp->token = sh_lex(lexp);
	}
	if((flag && lexp->token!=LBRACE) || lexp->token==EOFSYM)
		sh_syntax(lexp);
	sh_pushcontext(&buff,1);
	jmpval = sigsetjmp(buff.buff,0);
	if(jmpval == 0)
	{
		/* create a new stak frame to compile the command */
		savstak = stakcreate(STAK_SMALL);
		savstak = stakinstall(savstak, 0);
		slp = (struct slnod*)stakalloc(sizeof(struct slnod)+sizeof(struct functnod));
		slp->slchild = 0;
		slp->slnext = shp->st.staklist;
		shp->st.staklist = 0;
		t->funct.functstak = (struct slnod*)slp;
		/*
		 * store the pathname of function definition file on stack
		 * in name field of fake for node
		 */
		fp = (struct functnod*)(slp+1);
		fp->functtyp = TFUN|FAMP;
		fp->functnam = 0;
		fp->functline = t->funct.functline;
		if(shp->st.filename)
			fp->functnam = stakcopy(shp->st.filename);
		loop_level = 0;
		label_last = label_list;
		if(!flag && lexp->token==0)
		{
			/* copy current word token to current stak frame */
			struct argnod *ap;
			flag = ARGVAL + strlen(lexp->arg->argval);
			ap = (struct argnod*)stakalloc(flag);
			memcpy(ap,lexp->arg,flag);
			lexp->arg = ap;
		}
		t->funct.functtre = item(lexp,SH_NOIO);
	}
	else if(shp->shcomp)
		exit(1);
	sh_popcontext(&buff);
	loop_level = saveloop;
	label_last = savelabel;
	/* restore the old stack */
	if(slp)
	{
		slp->slptr =  stakinstall(savstak,0);
		slp->slchild = shp->st.staklist;
	}
#if SHOPT_KIA
	lexp->current = current;
#endif /* SHOPT_KIA */
	if(jmpval)
	{
		if(slp && slp->slptr)
		{
			shp->st.staklist = slp->slnext;
			stakdelete(slp->slptr);
		}
		siglongjmp(*shp->jmplist,jmpval);
	}
	shp->st.staklist = (struct slnod*)slp;
	last = fctell();
	fp->functline = (last-first);
	fp->functtre = t;
	shp->mktype = in_mktype;
	if(lexp->sh->funlog)
	{
		if(fcfill()>0)
			fcseek(-1);
		lexp->sh->funlog = 0;
	}
#if 	SHOPT_KIA
	if(lexp->kiafile)
		kiaentity(lexp,t->funct.functnam,-1,'p',t->funct.functline,shp->inlineno-1,lexp->current,'p',0,"");
#endif /* SHOPT_KIA */
	t->funct.functtyp |= opt_get;
	opt_get = save_optget;
	return(t);
}

/*
 * Compound assignment
 */
static struct argnod *assign(Lex_t *lexp, register struct argnod *ap, int tdef)
{
	register int n;
	register Shnode_t *t, **tp;
	register struct comnod *ac;
	Stk_t	*stkp = lexp->sh->stk;
	int array=0;
	Namval_t *np;
	n = strlen(ap->argval)-1;
	if(ap->argval[n]!='=')
		sh_syntax(lexp);
	if(ap->argval[n-1]=='+')
	{
		ap->argval[n--]=0;
		array = ARG_APPEND;
	}
	/* shift right */
	while(n > 0)
	{
		ap->argval[n] = ap->argval[n-1];
		n--;
	}
	*ap->argval=0;
	t = getnode(fornod);
	t->for_.fornam = (char*)(ap->argval+1);
	t->for_.fortyp = sh_getlineno(lexp);
	tp = &t->for_.fortre;
	ap->argchn.ap = (struct argnod*)t;
	ap->argflag &= ARG_QUOTED;
	ap->argflag |= array;
	lexp->assignok = SH_ASSIGN;
	lexp->aliasok = 1;
	array=0;
	if((n=skipnl(lexp,0))==RPAREN || n==LPAREN)
	{
		int index= 0;
		struct argnod **settail;
		ac = (struct comnod*)getnode(comnod);
		settail= &ac->comset;
		memset((void*)ac,0,sizeof(*ac));
		ac->comline = sh_getlineno(lexp);
		while(n==LPAREN)
		{
			struct argnod *ap;
			ap = (struct argnod*)stkseek(stkp,ARGVAL);
			ap->argflag= ARG_ASSIGN;
			sfprintf(stkp,"[%d]=",index++);
			ap = (struct argnod*)stkfreeze(stkp,1);
			ap->argnxt.ap = 0;
			ap = assign(lexp,ap,0);
			ap->argflag |= ARG_MESSAGE;
			*settail = ap;
			settail = &(ap->argnxt.ap);
			while((n = skipnl(lexp,0))==0)
			{
				ap = (struct argnod*)stkseek(stkp,ARGVAL);
				ap->argflag= ARG_ASSIGN;
				sfprintf(stkp,"[%d]=",index++);
				stakputs(lexp->arg->argval);
				ap = (struct argnod*)stkfreeze(stkp,1);
				ap->argnxt.ap = 0;
				ap->argflag = lexp->arg->argflag;
				*settail = ap;
				settail = &(ap->argnxt.ap);
			}
		}
	}
	else if(n && n!=FUNCTSYM)
		sh_syntax(lexp);
	else if(n!=FUNCTSYM && !(lexp->arg->argflag&ARG_ASSIGN) && !((np=nv_search(lexp->arg->argval,lexp->sh->fun_tree,0)) && (nv_isattr(np,BLT_DCL)|| np==SYSDOT)))
	{
		array=SH_ARRAY;
		if(fcgetc(n)==LPAREN)
		{
			int c;
			if(fcgetc(c)==RPAREN)
			{
				lexp->token =  SYMRES;
				array = 0;
			}
			else
				fcseek(-2);
		}
		else if(n>0)
			fcseek(-1);
		if(array && tdef)
			sh_syntax(lexp);
	}
	while(1)
	{
		if((n=lexp->token)==RPAREN)
			break;
		if(n==FUNCTSYM || n==SYMRES)
			ac = (struct comnod*)funct(lexp);
		else
			ac = (struct comnod*)simple(lexp,SH_NOIO|SH_ASSIGN|array,NIL(struct ionod*));
		if((n=lexp->token)==RPAREN)
			break;
		if(n!=NL && n!=';')
			sh_syntax(lexp);
		lexp->assignok = SH_ASSIGN;
		if((n=skipnl(lexp,0)) || array)
		{
			if(n==RPAREN)
				break;
			if(array ||  n!=FUNCTSYM)
				sh_syntax(lexp);
		}
		if((n!=FUNCTSYM) && !(lexp->arg->argflag&ARG_ASSIGN) && !((np=nv_search(lexp->arg->argval,lexp->sh->fun_tree,0)) && (nv_isattr(np,BLT_DCL)||np==SYSDOT)))
		{
			struct argnod *arg = lexp->arg;
			if(n!=0)
				sh_syntax(lexp);
			/* check for sys5 style function */
			if(sh_lex(lexp)!=LPAREN || sh_lex(lexp)!=RPAREN)
			{
				lexp->arg = arg;
				lexp->token = 0;
				sh_syntax(lexp);
			}
			lexp->arg = arg;
			lexp->token = SYMRES;
		}
		t = makelist(lexp,TLST,(Shnode_t*)ac,t);
		*tp = t;
		tp = &t->lst.lstrit;
	}
	*tp = (Shnode_t*)ac;
	lexp->assignok = 0;
	return(ap);
}

/*
 * item
 *
 *	( cmd ) [ < in ] [ > out ]
 *	word word* [ < in ] [ > out ]
 *	if ... then ... else ... fi
 *	for ... while ... do ... done
 *	case ... in ... esac
 *	begin ... end
 */

static Shnode_t	*item(Lex_t *lexp,int flag)
{
	register Shnode_t	*t;
	register struct ionod	*io;
	register int tok = (lexp->token&0xff);
	int savwdval = lexp->lasttok;
	int savline = lexp->lastline;
	int showme=0, comsub;
	if(!(flag&SH_NOIO) && (tok=='<' || tok=='>' || lexp->token==IOVNAME))
		io=inout(lexp,NIL(struct ionod*),1);
	else
		io=0;
	if((tok=lexp->token) && tok!=EOFSYM && tok!=FUNCTSYM)
	{
		lexp->lastline =  sh_getlineno(lexp);
		lexp->lasttok = lexp->token;
	}
	switch(tok)
	{
	    /* [[ ... ]] test expression */
	    case BTESTSYM:
		t = test_expr(lexp,ETESTSYM);
		t->tre.tretyp &= ~TTEST;
		break;
	    /* ((...)) arithmetic expression */
	    case EXPRSYM:
		t = getanode(lexp,lexp->arg);
		sh_lex(lexp);
		goto done;

	    /* case statement */
	    case CASESYM:
	    {
		int savetok = lexp->lasttok;
		int saveline = lexp->lastline;
		t = getnode(swnod);
		if(sh_lex(lexp))
			sh_syntax(lexp);
		t->sw.swarg=lexp->arg;
		t->sw.swtyp=TSW;
		t->sw.swio = 0;
		t->sw.swtyp |= FLINENO;
		t->sw.swline =  lexp->sh->inlineno;
		if((tok=skipnl(lexp,0))!=INSYM && tok!=LBRACE)
			sh_syntax(lexp);
		if(!(t->sw.swlst=syncase(lexp,tok==INSYM?ESACSYM:RBRACE)) && lexp->token==EOFSYM)
		{
			lexp->lasttok = savetok;
			lexp->lastline = saveline;
			sh_syntax(lexp);
		}
		break;
	    }

	    /* if statement */
	    case IFSYM:
	    {
		register Shnode_t	*tt;
		t = getnode(ifnod);
		t->if_.iftyp=TIF;
		t->if_.iftre=sh_cmd(lexp,THENSYM,SH_NL);
		t->if_.thtre=sh_cmd(lexp,ELSESYM,SH_NL|SH_SEMI);
		tok = lexp->token;
		t->if_.eltre=(tok==ELSESYM?sh_cmd(lexp,FISYM,SH_NL|SH_SEMI):
			(tok==ELIFSYM?(lexp->token=IFSYM, tt=item(lexp,SH_NOIO)):0));
		if(tok==ELIFSYM)
		{
			if(!tt || tt->tre.tretyp!=TSETIO)
				goto done;
			t->if_.eltre = tt->fork.forktre;
			tt->fork.forktre = t;
			t = tt;
			goto done;
		}
		break;
	    }

	    /* for and select statement */
	    case FORSYM:
	    case SELECTSYM:
	    {
		t = getnode(fornod);
		t->for_.fortyp=(lexp->token==FORSYM?TFOR:TSELECT);
		t->for_.forlst=0;
		t->for_.forline =  lexp->sh->inlineno;
		if(sh_lex(lexp))
		{
			if(lexp->token!=EXPRSYM || t->for_.fortyp!=TFOR)
				sh_syntax(lexp);
			/* arithmetic for */
			t = arithfor(lexp,t);
			break;
		}
		t->for_.fornam=(char*) lexp->arg->argval;
		t->for_.fortyp |= FLINENO;
#if SHOPT_KIA
		if(lexp->kiafile)
			writedefs(lexp,lexp->arg,lexp->sh->inlineno,'v',NIL(struct argnod*));
#endif /* SHOPT_KIA */
		while((tok=sh_lex(lexp))==NL);
		if(tok==INSYM)
		{
			if(sh_lex(lexp))
			{
				if(lexp->token != NL && lexp->token !=';')
					sh_syntax(lexp);
				/* some Linux scripts assume this */
				if(sh_isoption(SH_NOEXEC))
					errormsg(SH_DICT,ERROR_warn(0),e_lexemptyfor,lexp->sh->inlineno-(lexp->token=='\n'));
				t->for_.forlst = (struct comnod*)getnode(comnod);
				(t->for_.forlst)->comarg = 0;
				(t->for_.forlst)->comset = 0;
				(t->for_.forlst)->comnamp = 0;
				(t->for_.forlst)->comnamq = 0;
				(t->for_.forlst)->comstate = 0;
				(t->for_.forlst)->comio = 0;
				(t->for_.forlst)->comtyp = 0;
			}
			else
				t->for_.forlst=(struct comnod*)simple(lexp,SH_NOIO,NIL(struct ionod*));
			if(lexp->token != NL && lexp->token !=';')
				sh_syntax(lexp);
			tok = skipnl(lexp,0);
		}
		/* 'for i;do cmd' is valid syntax */
		else if(tok==';')
			tok=sh_lex(lexp);
		if(tok!=DOSYM && tok!=LBRACE)
			sh_syntax(lexp);
		loop_level++;
		t->for_.fortre=sh_cmd(lexp,tok==DOSYM?DONESYM:RBRACE,SH_NL|SH_SEMI);
		if(--loop_level==0)
			label_last = label_list;
		break;
	    }

	    /* This is the code for parsing function definitions */
	    case FUNCTSYM:
		return(funct(lexp));

#if SHOPT_NAMESPACE
	    case NSPACESYM:
		t = getnode(fornod);
		t->for_.fortyp=TNSPACE;
		t->for_.forlst=0;
		if(sh_lex(lexp))
			sh_syntax(lexp);
		t->for_.fornam=(char*) lexp->arg->argval;
		while((tok=sh_lex(lexp))==NL);
		if(tok!=LBRACE)
			sh_syntax(lexp);
		t->for_.fortre = sh_cmd(lexp,RBRACE,SH_NL);
		break;
#endif /* SHOPT_NAMESPACE */

	    /* while and until */
	    case WHILESYM:
	    case UNTILSYM:
		t = getnode(whnod);
		t->wh.whtyp=(lexp->token==WHILESYM ? TWH : TUN);
		loop_level++;
		t->wh.whtre = sh_cmd(lexp,DOSYM,SH_NL);
		t->wh.dotre = sh_cmd(lexp,DONESYM,SH_NL|SH_SEMI);
		if(--loop_level==0)
			label_last = label_list;
		t->wh.whinc = 0;
		break;

	    case LABLSYM:
	    {
		register struct argnod *argp = label_list;
		while(argp)
		{
			if(strcmp(argp->argval,lexp->arg->argval)==0)
				errormsg(SH_DICT,ERROR_exit(3),e_lexsyntax3,lexp->sh->inlineno,argp->argval);
			argp = argp->argnxt.ap;
		}
		lexp->arg->argnxt.ap = label_list;
		label_list = lexp->arg;
		label_list->argchn.len = sh_getlineno(lexp);
		label_list->argflag = loop_level;
		skipnl(lexp,flag);
		if(!(t = item(lexp,SH_NL)))
			sh_syntax(lexp);
		tok = (t->tre.tretyp&(COMSCAN|COMSCAN-1));
		if(sh_isoption(SH_NOEXEC) && tok!=TWH && tok!=TUN && tok!=TFOR && tok!=TSELECT)
			errormsg(SH_DICT,ERROR_warn(0),e_lexlabignore,label_list->argchn.len,label_list->argval);
		return(t);
	    }

	    /* command group with {...} */
	    case LBRACE:
		comsub = lexp->comsub;
		lexp->comsub = 0;
		t = sh_cmd(lexp,RBRACE,SH_NL|SH_SEMI);
		lexp->comsub = comsub;
		break;

	    case LPAREN:
		t = getnode(parnod);
		t->par.partre=sh_cmd(lexp,RPAREN,SH_NL|SH_SEMI);
		t->par.partyp=TPAR;
		break;

	    default:
		if(io==0)
			return(0);

	    case ';':
		if(io==0)
		{
			if(!(flag&SH_SEMI))
				return(0);
			if(sh_lex(lexp)==';')
				sh_syntax(lexp);
			showme =  FSHOWME;
		}
	    /* simple command */
	    case 0:
		t = (Shnode_t*)simple(lexp,flag,io);
		if(t->com.comarg && lexp->intypeset && (lexp->sh->shcomp || sh_isoption(SH_NOEXEC) || sh.dot_depth))
			check_typedef(&t->com);
		lexp->intypeset = 0;
		lexp->inexec = 0;
		t->tre.tretyp |= showme;
		return(t);
	}
	sh_lex(lexp);
	if(io=inout(lexp,io,0))
	{
		if((tok=t->tre.tretyp&COMMSK) != TFORK)
			tok = TSETIO;
		t=makeparent(lexp,tok,t);
		t->tre.treio=io;
	}
done:
	lexp->lasttok = savwdval;
	lexp->lastline = savline;
	return(t);
}

static struct argnod *process_sub(Lex_t *lexp,int tok)
{
	struct argnod *argp;
	Shnode_t *t;
	int mode = (tok==OPROCSYM);
	t = sh_cmd(lexp,RPAREN,SH_NL);
	argp = (struct argnod*)stkalloc(lexp->sh->stk,sizeof(struct argnod));
	*argp->argval = 0;
	argp->argchn.ap = (struct argnod*)makeparent(lexp,mode?TFORK|FPIN|FAMP|FPCL:TFORK|FPOU,t);
	argp->argflag =  (ARG_EXP|mode);
	return(argp);
}


/*
 * This is for a simple command, for list, or compound assignment
 */
static Shnode_t *simple(Lex_t *lexp,int flag, struct ionod *io)
{
	register struct comnod *t;
	register struct argnod	*argp;
	register int tok;
	Stk_t		*stkp = lexp->sh->stk;
	struct argnod	**argtail;
	struct argnod	**settail;
	int	cmdarg=0;
	int	argno = 0;
	int	assignment = 0;
	int	key_on = (!(flag&SH_NOIO) && sh_isoption(SH_KEYWORD));
	int	associative=0;
	if((argp=lexp->arg) && (argp->argflag&ARG_ASSIGN) && argp->argval[0]=='[')
	{
		flag |= SH_ARRAY;
		associative = 1;
	}
	t = (struct comnod*)getnode(comnod);
	t->comio=io; /*initial io chain*/
	/* set command line number for error messages */
	t->comline = sh_getlineno(lexp);
	argtail = &(t->comarg);
	t->comset = 0;
	t->comnamp = 0;
	t->comnamq = 0;
	t->comstate = 0;
	settail = &(t->comset);
	while(lexp->token==0)
	{
		argp = lexp->arg;
		if(*argp->argval==LBRACE && (flag&SH_FUNDEF) && argp->argval[1]==0)
		{
			lexp->token = LBRACE;
			break;
		}
		if(associative && argp->argval[0]!='[')
			sh_syntax(lexp);
		/* check for assignment argument */
		if((argp->argflag&ARG_ASSIGN) && assignment!=2)
		{
			*settail = argp;
			settail = &(argp->argnxt.ap);
			lexp->assignok = (flag&SH_ASSIGN)?SH_ASSIGN:1;
			if(assignment)
			{
				struct argnod *ap=argp;
				char *last, *cp;
				if(assignment==1)
				{
					last = strchr(argp->argval,'=');
					if(last && (last[-1]==']'|| (last[-1]=='+' && last[-2]==']')) && (cp=strchr(argp->argval,'[')) && (cp < last))
						last = cp;
					stkseek(stkp,ARGVAL);
					sfwrite(stkp,argp->argval,last-argp->argval);
					ap=(struct argnod*)stkfreeze(stkp,1);
					ap->argflag = ARG_RAW;
					ap->argchn.ap = 0;
				}
				*argtail = ap;
				argtail = &(ap->argnxt.ap);
				if(argno>=0)
					argno++;
			}
			else /* alias substitutions allowed */
				lexp->aliasok = 1;
		}
		else
		{
			if(!(argp->argflag&ARG_RAW))
			{
				argno = -1;
			}
			if(argno>=0 && argno++==cmdarg && !(flag&SH_ARRAY) && *argp->argval!='/')
			{
				/* check for builtin command */
				Namval_t *np=nv_bfsearch(argp->argval,lexp->sh->fun_tree, (Namval_t**)&t->comnamq,(char**)0);
				if(cmdarg==0)
					t->comnamp = (void*)np;
				if(np && is_abuiltin(np))
				{
					if(nv_isattr(np,BLT_DCL))
					{
						assignment = 1+(*argp->argval=='a');
						if(np==SYSTYPESET)
							lexp->intypeset = 1;
						key_on = 1;
					}
					else if(np==SYSCOMMAND)
						cmdarg++;
					else if(np==SYSEXEC)
						lexp->inexec = 1;
					else if(np->nvalue.bfp==b_getopts)
						opt_get |= FOPTGET;
				}
			}
			*argtail = argp;
			argtail = &(argp->argnxt.ap);
			if(!(lexp->assignok=key_on)  && !(flag&SH_NOIO) && sh_isoption(SH_NOEXEC))
				lexp->assignok = SH_COMPASSIGN;
			lexp->aliasok = 0;
		}
	retry:
		tok = sh_lex(lexp);
		if(tok==LABLSYM && (flag&SH_ASSIGN))
			lexp->token = tok = 0;
#if SHOPT_DEVFD
		if((tok==IPROCSYM || tok==OPROCSYM))
		{
			argp = process_sub(lexp,tok);
			argno = -1;
			*argtail = argp;
			argtail = &(argp->argnxt.ap);
			goto retry;
		}
#endif	/* SHOPT_DEVFD */
		if(tok==LPAREN)
		{
			if(argp->argflag&ARG_ASSIGN)
			{
				int intypeset = lexp->intypeset;
				int tdef = 0;
				lexp->intypeset = 0;
				if(t->comnamp==SYSTYPESET && t->comarg->argnxt.ap && strcmp(t->comarg->argnxt.ap->argval,"-T")==0)
					tdef = 1;
				argp = assign(lexp,argp,tdef);
				lexp->intypeset = intypeset;
				if(associative)
					lexp->assignok |= SH_ASSIGN;
				goto retry;
			}
			else if(argno==1 && !t->comset)
			{
				/* SVR2 style function */
				if(sh_lex(lexp) == RPAREN)
				{
					lexp->arg = argp;
					return(funct(lexp));
				}
				lexp->token = LPAREN;
			}
		}
		else if(flag&SH_ASSIGN)
		{
			if(tok==RPAREN)
				break;
			else if(tok==NL && (flag&SH_ARRAY))
			{
				lexp->comp_assign = 2;
				goto retry;
			}
			
		}
		if(!(flag&SH_NOIO))
		{
			if(io)
			{
				while(io->ionxt)
					io = io->ionxt;
				io->ionxt = inout(lexp,(struct ionod*)0,0);
			}
			else
				t->comio = io = inout(lexp,(struct ionod*)0,0);
		}
	}
	*argtail = 0;
	t->comtyp = TCOM;
#if SHOPT_KIA
	if(lexp->kiafile && !(flag&SH_NOIO))
	{
		register Namval_t *np=(Namval_t*)t->comnamp;
		unsigned long r=0;
		int line = t->comline;
		argp = t->comarg;
		if(np)
			r = kiaentity(lexp,nv_name(np),-1,'p',-1,0,lexp->unknown,'b',0,"");
		else if(argp)
			r = kiaentity(lexp,sh_argstr(argp),-1,'p',-1,0,lexp->unknown,'c',0,"");
		if(r>0)
			sfprintf(lexp->kiatmp,"p;%..64d;p;%..64d;%d;%d;c;\n",lexp->current,r,line,line);
		if(t->comset && argno==0)
			writedefs(lexp,t->comset,line,'v',t->comarg);
		else if(np && nv_isattr(np,BLT_DCL))
			writedefs(lexp,argp,line,0,NIL(struct argnod*));
		else if(argp && strcmp(argp->argval,"read")==0)
			writedefs(lexp,argp,line,0,NIL(struct argnod*));
#if 0
		else if(argp && strcmp(argp->argval,"unset")==0)
			writedefs(lexp,argp,line,'u',NIL(struct argnod*));
#endif
		else if(argp && *argp->argval=='.' && argp->argval[1]==0 && (argp=argp->argnxt.ap))
		{
			r = kiaentity(lexp,sh_argstr(argp),-1,'p',0,0,lexp->script,'d',0,"");
			sfprintf(lexp->kiatmp,"p;%..64d;p;%..64d;%d;%d;d;\n",lexp->current,r,line,line);
		}
	}
#endif /* SHOPT_KIA */
	if(t->comnamp && (argp=t->comarg->argnxt.ap))
	{ 
		Namval_t *np=(Namval_t*)t->comnamp;
		if((np==SYSBREAK || np==SYSCONT) && (argp->argflag&ARG_RAW) && !isdigit(*argp->argval))
		{
			register char *cp = argp->argval;
			/* convert break/continue labels to numbers */
			tok = 0;
			for(argp=label_list;argp!=label_last;argp=argp->argnxt.ap)
			{
				if(strcmp(cp,argp->argval))
					continue;
				tok = loop_level-argp->argflag;
				if(tok>=1)
				{
					argp = t->comarg->argnxt.ap;
					if(tok>9)
					{
						argp->argval[1] = '0'+tok%10;
						argp->argval[2] = 0;
						tok /= 10;
					}
					else
						argp->argval[1] = 0;
					*argp->argval = '0'+tok;
				}
				break;
			}
			if(sh_isoption(SH_NOEXEC) && tok==0)
				errormsg(SH_DICT,ERROR_warn(0),e_lexlabunknown,lexp->sh->inlineno-(lexp->token=='\n'),cp);
		}
		else if(sh_isoption(SH_NOEXEC) && np==SYSSET && ((tok= *argp->argval)=='-'||tok=='+') &&
			(argp->argval[1]==0||strchr(argp->argval,'k')))
			errormsg(SH_DICT,ERROR_warn(0),e_lexobsolete5,lexp->sh->inlineno-(lexp->token=='\n'),argp->argval);
	}
	/* expand argument list if possible */
	if(argno>0)
		t->comarg = qscan(t,argno);
	else if(t->comarg)
		t->comtyp |= COMSCAN;
	lexp->aliasok = 0;
	return((Shnode_t*)t);
}

/*
 * skip past newlines but issue prompt if interactive
 */
static int	skipnl(Lex_t *lexp,int flag)
{
	register int token;
	while((token=sh_lex(lexp))==NL);
	if(token==';' && !(flag&SH_SEMI))
		sh_syntax(lexp);
	return(token);
}

/*
 * check for and process and i/o redirections
 * if flag>0 then an alias can be in the next word
 * if flag<0 only one redirection will be processed
 */
static struct ionod	*inout(Lex_t *lexp,struct ionod *lastio,int flag)
{
	register int 		iof = lexp->digits, token=lexp->token;
	register struct ionod	*iop;
	Stk_t			*stkp = lexp->sh->stk;
	char *iovname=0;
	register int		errout=0;
	if(token==IOVNAME)
	{
		iovname=lexp->arg->argval+1;
		token= sh_lex(lexp);
		iof = 0;
	}
	switch(token&0xff)
	{
	    case '<':
		if(token==IODOCSYM)
			iof |= (IODOC|IORAW);
		else if(token==IOMOV0SYM)
			iof |= IOMOV;
		else if(token==IORDWRSYMT)
			iof |= IORDW|IOREWRITE;
		else if(token==IORDWRSYM)
			iof |= IORDW;
		else if((token&SYMSHARP) == SYMSHARP)
		{
			int n;
			iof |= IOLSEEK;
			if(fcgetc(n)=='#')
				iof |= IOCOPY;
			else if(n>0)
				fcseek(-1);
		}
		break;

	    case '>':
		if(iof<0)
		{
			errout = 1;
			iof = 1;
		}
		iof |= IOPUT;
		if(token==IOAPPSYM)
			iof |= IOAPP;
		else if(token==IOMOV1SYM)
			iof |= IOMOV;
		else if(token==IOCLOBSYM)
			iof |= IOCLOB;
		else if((token&SYMSHARP) == SYMSHARP)
			iof |= IOLSEEK;
		else if((token&SYMSEMI) == SYMSEMI)
			iof |= IOREWRITE;
		break;

	    default:
		return(lastio);
	}
	lexp->digits=0;
	iop=(struct ionod*) stkalloc(stkp,sizeof(struct ionod));
	iop->iodelim = 0;
	if(token=sh_lex(lexp))
	{
		if(token==RPAREN && (iof&IOLSEEK) && lexp->comsub) 
		{
			lexp->arg = (struct argnod*)stkalloc(stkp,sizeof(struct argnod)+3);
			strcpy(lexp->arg->argval,"CUR");
			lexp->arg->argflag = ARG_RAW;
			iof |= IOARITH;
			fcseek(-1);
		}
		else if(token==EXPRSYM && (iof&IOLSEEK))
			iof |= IOARITH;
		else if(((token==IPROCSYM && !(iof&IOPUT)) || (token==OPROCSYM && (iof&IOPUT))) && !(iof&(IOLSEEK|IOREWRITE|IOMOV|IODOC)))
		{
			lexp->arg = process_sub(lexp,token);
			iof |= IOPROCSUB;
		}
		else
			sh_syntax(lexp);
	}
	if( (iof&IOPROCSUB) && !(iof&IOLSEEK))
		iop->ioname= (char*)lexp->arg->argchn.ap;
	else
		iop->ioname=lexp->arg->argval;
	iop->iovname = iovname;
	if(iof&IODOC)
	{
		if(lexp->digits==2)
		{
			iof |= IOSTRG;
			if(!(lexp->arg->argflag&ARG_RAW))
				iof &= ~IORAW;
		}
		else
		{
			if(!lexp->sh->heredocs)
				lexp->sh->heredocs = sftmp(HERE_MEM);
			iop->iolst=lexp->heredoc;
			lexp->heredoc=iop;
			if(lexp->arg->argflag&ARG_QUOTED)
				iof |= IOQUOTE;
			if(lexp->digits==3)
				iof |= IOLSEEK;
			if(lexp->digits)
				iof |= IOSTRIP;
		}
	}
	else
	{
		iop->iolst = 0;
		if(lexp->arg->argflag&ARG_RAW)
			iof |= IORAW;
	}
	iop->iofile=iof;
	if(flag>0)
		/* allow alias substitutions and parameter assignments */
		lexp->aliasok = lexp->assignok = 1;
#if SHOPT_KIA
	if(lexp->kiafile)
	{
		int n = lexp->sh->inlineno-(lexp->token=='\n');
		if(!(iof&IOMOV))
		{
			unsigned long r=kiaentity(lexp,(iof&IORAW)?sh_fmtq(iop->ioname):iop->ioname,-1,'f',0,0,lexp->script,'f',0,"");
			sfprintf(lexp->kiatmp,"p;%..64d;f;%..64d;%d;%d;%c;%d\n",lexp->current,r,n,n,(iof&IOPUT)?((iof&IOAPP)?'a':'w'):((iof&IODOC)?'h':'r'),iof&IOUFD);
		}
	}
#endif /* SHOPT_KIA */
	if(flag>=0)
	{
		struct ionod *ioq=iop;
		sh_lex(lexp);
		if(errout)
		{
			/* redirect standard output to standard error */
			ioq = (struct ionod*)stkalloc(stkp,sizeof(struct ionod));
			memset(ioq,0,sizeof(*ioq));
			ioq->ioname = "1";
			ioq->iolst = 0;
			ioq->iodelim = 0;
			ioq->iofile = IORAW|IOPUT|IOMOV|2;
			iop->ionxt=ioq;
		}
		ioq->ionxt=inout(lexp,lastio,flag);
	}
	else
		iop->ionxt=0;
	return(iop);
}

/*
 * convert argument chain to argument list when no special arguments
 */

static struct argnod *qscan(struct comnod *ac,int argn)
{
	register char **cp;
	register struct argnod *ap;
	register struct dolnod* dp;
	register int special=0;
	/* special hack for test -t compatibility */
	if((Namval_t*)ac->comnamp==SYSTEST)
		special = 2;
	else if(*(ac->comarg->argval)=='[' && ac->comarg->argval[1]==0)
		special = 3;
	if(special)
	{
		ap = ac->comarg->argnxt.ap;
		if(argn==(special+1) && ap->argval[1]==0 && *ap->argval=='!')
			ap = ap->argnxt.ap;
		else if(argn!=special)
			special=0;
	}
	if(special)
	{
		const char *message;
		if(strcmp(ap->argval,"-t"))
		{
			message = "line %d: Invariant test";
			special=0;
		}
		else
		{
			message = "line %d: -t requires argument";
			argn++;
		}
		if(sh_isoption(SH_NOEXEC))
			errormsg(SH_DICT,ERROR_warn(0),message,ac->comline);
	}
	/* leave space for an extra argument at the front */
	dp = (struct dolnod*)stakalloc((unsigned)sizeof(struct dolnod) + ARG_SPARE*sizeof(char*) + argn*sizeof(char*));
	cp = dp->dolval+ARG_SPARE;
	dp->dolnum = argn;
	dp->dolbot = ARG_SPARE;
	ap = ac->comarg;
	while(ap)
	{
		*cp++ = ap->argval;
		ap = ap->argnxt.ap;
	}
	if(special==3)
	{
		cp[0] = cp[-1];
		cp[-1] = "1";
		cp++;
	}
	else if(special)
		*cp++ = "1";
	*cp = 0;
	return((struct argnod*)dp);
}

static Shnode_t *test_expr(Lex_t *lp,int sym)
{
	register Shnode_t *t = test_or(lp);
	if(lp->token!=sym)
		sh_syntax(lp);
	return(t);
}

static Shnode_t *test_or(Lex_t *lp)
{
	register Shnode_t *t = test_and(lp);
	while(lp->token==ORFSYM)
		t = makelist(lp,TORF|TTEST,t,test_and(lp));
	return(t);
}

static Shnode_t *test_and(Lex_t *lp)
{
	register Shnode_t *t = test_primary(lp);
	while(lp->token==ANDFSYM)
		t = makelist(lp,TAND|TTEST,t,test_primary(lp));
	return(t);
}

/*
 * convert =~ into == ~(E)
 */
static void ere_match(void)
{
	Sfio_t *base, *iop = sfopen((Sfio_t*)0," ~(E)","s");
	register int c;
	while( fcgetc(c),(c==' ' || c=='\t'));
	if(c)
		fcseek(-1);
	if(!(base=fcfile()))
		base = sfopen(NIL(Sfio_t*),fcseek(0),"s");
	fcclose();
        sfstack(base,iop);
        fcfopen(base);
}

static Shnode_t *test_primary(Lex_t *lexp)
{
	register struct argnod *arg;
	register Shnode_t *t;
	register int num,token;
	token = skipnl(lexp,0);
	num = lexp->digits;
	switch(token)
	{
	    case '(':
		t = test_expr(lexp,')');
		t = makelist(lexp,TTST|TTEST|TPAREN ,t, (Shnode_t*)pointerof(lexp->sh->inlineno));
		break;
	    case '!':
		if(!(t = test_primary(lexp)))
			sh_syntax(lexp);
		t->tre.tretyp |= TNEGATE;
		return(t);
	    case TESTUNOP:
		if(sh_lex(lexp))
			sh_syntax(lexp);
#if SHOPT_KIA
		if(lexp->kiafile && !strchr("sntzoOG",num))
		{
			int line = lexp->sh->inlineno- (lexp->token==NL);
			unsigned long r;
			r=kiaentity(lexp,sh_argstr(lexp->arg),-1,'f',0,0,lexp->script,'t',0,"");
			sfprintf(lexp->kiatmp,"p;%..64d;f;%..64d;%d;%d;t;\n",lexp->current,r,line,line);
		}
#endif /* SHOPT_KIA */
		t = makelist(lexp,TTST|TTEST|TUNARY|(num<<TSHIFT),
			(Shnode_t*)lexp->arg,(Shnode_t*)lexp->arg);
		t->tst.tstline =  lexp->sh->inlineno;
		break;
	    /* binary test operators */
	    case 0:
		arg = lexp->arg;
		if((token=sh_lex(lexp))==TESTBINOP)
		{
			num = lexp->digits;
			if(num==TEST_REP)
			{
				ere_match();
				num = TEST_PEQ;
			}
		}
		else if(token=='<')
			num = TEST_SLT;
		else if(token=='>')
			num = TEST_SGT;
		else if(token==ANDFSYM||token==ORFSYM||token==ETESTSYM||token==RPAREN)
		{
			t = makelist(lexp,TTST|TTEST|TUNARY|('n'<<TSHIFT),
				(Shnode_t*)arg,(Shnode_t*)arg);
			t->tst.tstline =  lexp->sh->inlineno;
			return(t);
		}
		else
			sh_syntax(lexp);
#if SHOPT_KIA
		if(lexp->kiafile && (num==TEST_EF||num==TEST_NT||num==TEST_OT))
		{
			int line = lexp->sh->inlineno- (lexp->token==NL);
			unsigned long r;
			r=kiaentity(lexp,sh_argstr(lexp->arg),-1,'f',0,0,lexp->current,'t',0,"");
			sfprintf(lexp->kiatmp,"p;%..64d;f;%..64d;%d;%d;t;\n",lexp->current,r,line,line);
		}
#endif /* SHOPT_KIA */
		if(sh_lex(lexp))
			sh_syntax(lexp);
		if(num&TEST_PATTERN)
		{
			if(lexp->arg->argflag&(ARG_EXP|ARG_MAC))
				num &= ~TEST_PATTERN;
		}
		t = getnode(tstnod);
		t->lst.lsttyp = TTST|TTEST|TBINARY|(num<<TSHIFT);
		t->lst.lstlef = (Shnode_t*)arg;
		t->lst.lstrit = (Shnode_t*)lexp->arg;
		t->tst.tstline =  lexp->sh->inlineno;
#if SHOPT_KIA
		if(lexp->kiafile && (num==TEST_EF||num==TEST_NT||num==TEST_OT))
		{
			int line = lexp->sh->inlineno-(lexp->token==NL);
			unsigned long r;
			r=kiaentity(lexp,sh_argstr(lexp->arg),-1,'f',0,0,lexp->current,'t',0,"");
			sfprintf(lexp->kiatmp,"p;%..64d;f;%..64d;%d;%d;t;\n",lexp->current,r,line,line);
		}
#endif /* SHOPT_KIA */
		break;
	    default:
		return(0);
	}
	skipnl(lexp,0);
	return(t);
}

#if SHOPT_KIA
/*
 * return an entity checksum
 * The entity is created if it doesn't exist
 */
unsigned long kiaentity(Lex_t *lexp,const char *name,int len,int type,int first,int last,unsigned long parent, int pkind, int width, const char *attr)
{
	Stk_t	*stkp = lexp->sh->stk;
	Namval_t *np;
	long offset = stktell(stkp);
	sfputc(stkp,type);
	if(len>0)
		sfwrite(stkp,name,len);
	else
	{
		if(type=='p')
			sfputr(stkp,path_basename(name),0);
		else
			sfputr(stkp,name,0);
	}
	np = nv_search(stakptr(offset),lexp->entity_tree,NV_ADD);
	stkseek(stkp,offset);
	np->nvalue.i = pkind;
	nv_setsize(np,width);
	if(!nv_isattr(np,NV_TAGGED) && first>=0)
	{
		nv_onattr(np,NV_TAGGED);
		if(!pkind)
			pkind = '0';
		if(len>0)
			sfprintf(lexp->kiafile,"%..64d;%c;%.*s;%d;%d;%..64d;%..64d;%c;%d;%s\n",np->hash,type,len,name,first,last,parent,lexp->fscript,pkind,width,attr);
		else
			sfprintf(lexp->kiafile,"%..64d;%c;%s;%d;%d;%..64d;%..64d;%c;%d;%s\n",np->hash,type,name,first,last,parent,lexp->fscript,pkind,width,attr);
	}
	return(np->hash);
}

static void kia_add(register Namval_t *np, void *data)
{
	char *name = nv_name(np);
	Lex_t	*lp = (Lex_t*)data;
	NOT_USED(data);
	kiaentity(lp,name+1,-1,*name,0,-1,(*name=='p'?lp->unknown:lp->script),np->nvalue.i,nv_size(np),"");
}

int kiaclose(Lex_t *lexp)
{
	register off_t off1,off2;
	register int n;
	if(lexp->kiafile)
	{
		unsigned long r = kiaentity(lexp,lexp->scriptname,-1,'p',-1,lexp->sh->inlineno-1,0,'s',0,"");
		kiaentity(lexp,lexp->scriptname,-1,'p',1,lexp->sh->inlineno-1,r,'s',0,"");
		kiaentity(lexp,lexp->scriptname,-1,'f',1,lexp->sh->inlineno-1,r,'s',0,"");
		nv_scan(lexp->entity_tree,kia_add,(void*)lexp,NV_TAGGED,0);
		off1 = sfseek(lexp->kiafile,(off_t)0,SEEK_END);
		sfseek(lexp->kiatmp,(off_t)0,SEEK_SET);
		sfmove(lexp->kiatmp,lexp->kiafile,SF_UNBOUND,-1);
		off2 = sfseek(lexp->kiafile,(off_t)0,SEEK_END);
#ifdef SF_BUFCONST
		if(off2==off1)
			n= sfprintf(lexp->kiafile,"DIRECTORY\nENTITY;%lld;%d\nDIRECTORY;",(Sflong_t)lexp->kiabegin,(size_t)(off1-lexp->kiabegin));
		else
			n= sfprintf(lexp->kiafile,"DIRECTORY\nENTITY;%lld;%d\nRELATIONSHIP;%lld;%d\nDIRECTORY;",(Sflong_t)lexp->kiabegin,(size_t)(off1-lexp->kiabegin),(Sflong_t)off1,(size_t)(off2-off1));
		if(off2 >= INT_MAX)
			off2 = -(n+12);
		sfprintf(lexp->kiafile,"%010.10lld;%010d\n",(Sflong_t)off2+10, n+12);
#else
		if(off2==off1)
			n= sfprintf(lexp->kiafile,"DIRECTORY\nENTITY;%d;%d\nDIRECTORY;",lexp->kiabegin,off1-lexp->kiabegin);
		else
			n= sfprintf(lexp->kiafile,"DIRECTORY\nENTITY;%d;%d\nRELATIONSHIP;%d;%d\nDIRECTORY;",lexp->kiabegin,off1-lexp->kiabegin,off1,off2-off1);
		sfprintf(lexp->kiafile,"%010d;%010d\n",off2+10, n+12);
#endif
	}
	return(sfclose(lexp->kiafile));
}
#endif /* SHOPT_KIA */
