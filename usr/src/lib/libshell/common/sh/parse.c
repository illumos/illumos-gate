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
#endif
#include	<ctype.h>
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

static Shnode_t	*makeparent(int, Shnode_t*);
static Shnode_t	*makelist(int, Shnode_t*, Shnode_t*);
static struct argnod	*qscan(struct comnod*, int);
static struct ionod	*inout(struct ionod*, int);
static Shnode_t	*sh_cmd(int,int);
static Shnode_t	*term(int);
static Shnode_t	*list(int);
static struct regnod	*syncase(int);
static Shnode_t	*item(int);
static Shnode_t	*simple(int, struct ionod*);
static int	skipnl(int);
static Shnode_t	*test_expr(int);
static Shnode_t	*test_and(void);
static Shnode_t	*test_or(void);
static Shnode_t	*test_primary(void);

#define	sh_getlineno()	(shlex.lastline)

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
static unsigned long writedefs(struct argnod *arglist, int line, int type, struct argnod *cmd)
{
	register struct argnod *argp = arglist;
	register char *cp;
	register int n,eline;
	int width=0;
	unsigned long r=0;
	static char atbuff[20];
	int  justify=0;
	char *attribute = atbuff;
	unsigned long parent=shlex.script;
	if(type==0)
	{
		parent = shlex.current;
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
		parent=kiaentity(sh_argstr(cmd),-1,'p',-1,-1,shlex.unknown,'b',0,"");
	*attribute = 0;
	while(argp)
	{
		if((cp=strchr(argp->argval,'='))||(cp=strchr(argp->argval,'?')))
			n = cp-argp->argval;
		else
			n = strlen(argp->argval);
		eline = sh.inlineno-(shlex.token==NL);
		r=kiaentity(argp->argval,n,type,line,eline,parent,justify,width,atbuff);
		sfprintf(shlex.kiatmp,"p;%..64d;v;%..64d;%d;%d;s;\n",shlex.current,r,line,eline);
		argp = argp->argnxt.ap;
	}
	return(r);
}
#endif /* SHOPT_KIA */
/*
 * Make a parent node for fork() or io-redirection
 */
static Shnode_t	*makeparent(int flag, Shnode_t *child)
{
	register Shnode_t	*par = getnode(forknod);
	par->fork.forktyp = flag;
	par->fork.forktre = child;
	par->fork.forkio = 0;
	par->fork.forkline = sh_getlineno()-1;
	return(par);
}

static Shnode_t *getanode(struct argnod *ap)
{
	register Shnode_t *t = getnode(arithnod);
	t->ar.artyp = TARITH;
	t->ar.arline = sh_getlineno();
	t->ar.arexpr = ap;
	if(ap->argflag&ARG_RAW)
		t->ar.arcomp = sh_arithcomp(ap->argval);
	else
		t->ar.arcomp = 0;
	return(t);
}

/*
 *  Make a node corresponding to a command list
 */
static Shnode_t	*makelist(int type, Shnode_t *l, Shnode_t *r)
{
	register Shnode_t	*t;
	if(!l || !r)
		sh_syntax();
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
	Fcin_t	sav_input;
	struct argnod *sav_arg = shlex.arg;
	int	sav_prompt = shp->nextprompt;
	if(shp->binscript && sffileno(iop)==shp->infd)
		return((void*)sh_trestore(iop));
	fcsave(&sav_input);
	shp->st.staklist = 0;
	shlex.heredoc = 0;
	shlex.inlineno = shp->inlineno;
	shlex.firstline = shp->st.firstline;
	shp->nextprompt = 1;
	loop_level = 0;
	label_list = label_last = 0;
	if(sh_isoption(SH_INTERACTIVE))
		sh_onstate(SH_INTERACTIVE);
	if(sh_isoption(SH_VERBOSE))
		sh_onstate(SH_VERBOSE);
	sh_lexopen((Lex_t*)shp->lex_context,shp,0);
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
			shlex.arg = sav_arg;
			if(version > 3)
				errormsg(SH_DICT,ERROR_exit(1),e_lexversion);
			if(sffileno(iop)==shp->infd)
				shp->binscript = 1;
			sfgetc(iop);
			return((void*)sh_trestore(iop));
		}
	}
	if((flag&SH_NL) && (shp->inlineno=error_info.line+shp->st.firstline)==0)
		shp->inlineno=1;
#if KSHELL
	shp->nextprompt = 2;
#endif
	t = sh_cmd((flag&SH_EOF)?EOFSYM:'\n',SH_SEMI|SH_EMPTY|(flag&SH_NL));
	fcclose();
	fcrestore(&sav_input);
	shlex.arg = sav_arg;
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
		shp->st.firstline = shlex.firstline;
		shp->inlineno = shlex.inlineno;
	}
	stakseek(0);
	return((void*)t);
}

/*
 * This routine parses up the matching right parenthesis and returns
 * the parse tree
 */
Shnode_t *sh_dolparen(void)
{
	register Shnode_t *t=0;
	register Lex_t *lp = (Lex_t*)sh.lex_context;
	Sfio_t *sp = fcfile();
	int line = sh.inlineno;
	sh.inlineno = error_info.line+sh.st.firstline;
	sh_lexopen(lp,&sh,1);
	shlex.comsub = 1;
	switch(sh_lex())
	{
	    /* ((...)) arithmetic expression */
	    case EXPRSYM:
		t = getanode(shlex.arg);
		break;
	    case LPAREN:
		t = sh_cmd(RPAREN,SH_NL|SH_EMPTY);
		break;
	}
	shlex.comsub = 0;
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
	sh.inlineno = line;
	return(t);
}

/*
 * remove temporary files and stacks
 */

void	sh_freeup(void)
{
	if(sh.st.staklist)
		sh_funstaks(sh.st.staklist,-1);
	sh.st.staklist = 0;
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

static Shnode_t	*sh_cmd(register int sym, int flag)
{
	register Shnode_t	*left, *right;
	register int type = FINT|FAMP;
	if(sym==NL)
		shlex.lasttok = 0;
	left = list(flag);
	if(shlex.token==NL)
	{
		if(flag&SH_NL)
			shlex.token=';';
	}
	else if(!left && !(flag&SH_EMPTY))
		sh_syntax();
	switch(shlex.token)
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
			left = makeparent(TFORK|type, left);
		}
		/* FALL THRU */		
	    case ';':
		if(!left)
			sh_syntax();
		if(right=sh_cmd(sym,flag|SH_EMPTY))
			left=makelist(TLST, left, right);
		break;
	    case EOFSYM:
		if(sym==NL)
			break;
	    default:
		if(sym && sym!=shlex.token)
		{
			if(sym!=ELSESYM || (shlex.token!=ELIFSYM && shlex.token!=FISYM))
				sh_syntax();
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
static Shnode_t	*list(register int flag)
{
	register Shnode_t	*t = term(flag);
	register int 	token;
	while(t && ((token=shlex.token)==ANDFSYM || token==ORFSYM))
		t = makelist((token==ANDFSYM?TAND:TORF), t, term(SH_NL|SH_SEMI));
	return(t);
}

/*
 * term
 *	item
 *	item | term
 */
static Shnode_t	*term(register int flag)
{
	register Shnode_t	*t;
	register int token;
	if(flag&SH_NL)
		token = skipnl(flag);
	else
		token = sh_lex();
	/* check to see if pipeline is to be timed */
	if(token==TIMESYM || token==NOTSYM)
	{
		t = getnode(parnod);
		t->par.partyp=TTIME;
		if(shlex.token==NOTSYM)
			t->par.partyp |= COMSCAN;
		t->par.partre = term(0);
	}
	else if((t=item(SH_NL|SH_EMPTY|(flag&SH_SEMI))) && shlex.token=='|')
	{
		register Shnode_t	*tt;
		int showme = t->tre.tretyp&FSHOWME;
		t = makeparent(TFORK|FPOU,t);
		if(tt=term(SH_NL))
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
				tt= makeparent(TSETIO|FPIN|FPCL,tt);
			}
			t=makelist(TFIL,t,tt);
			t->tre.tretyp |= showme;
		}
		else if(shlex.token)
			sh_syntax();
	}
	return(t);
}

/*
 * case statement
 */
static struct regnod*	syncase(register int esym)
{
	register int tok = skipnl(0);
	register struct regnod	*r;
	if(tok==esym)
		return(NIL(struct regnod*));
	r = (struct regnod*)stakalloc(sizeof(struct regnod));
	r->regptr=0;
	r->regflag=0;
	if(tok==LPAREN)
		skipnl(0);
	while(1)
	{
		if(!shlex.arg)
			sh_syntax();
		shlex.arg->argnxt.ap=r->regptr;
		r->regptr = shlex.arg;
		if((tok=sh_lex())==RPAREN)
			break;
		else if(tok=='|')
			sh_lex();
		else
			sh_syntax();
	}
	r->regcom=sh_cmd(0,SH_NL|SH_EMPTY|SH_SEMI);
	if((tok=shlex.token)==BREAKCASESYM)
		r->regnxt=syncase(esym);
	else if(tok==FALLTHRUSYM)
	{
		r->regflag++;
		r->regnxt=syncase(esym);
	}
	else
	{
		if(tok!=esym && tok!=EOFSYM)
			sh_syntax();
		r->regnxt=0;
	}
	if(shlex.token==EOFSYM)
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
static Shnode_t	*arithfor(register Shnode_t *tf)
{
	register Shnode_t	*t, *tw = tf;
	register int	offset;
	register struct argnod *argp;
	register int n;
	int argflag = shlex.arg->argflag;
	/* save current input */
	Fcin_t	sav_input;
	fcsave(&sav_input);
	fcsopen(shlex.arg->argval);
	/* split ((...)) into three expressions */
	for(n=0; ; n++)
	{
		register int c;
		argp = (struct argnod*)stakseek(ARGVAL);
		argp->argnxt.ap = 0;
		argp->argchn.cp = 0;
		argp->argflag = argflag;
		if(n==2)
			break;
		/* copy up to ; onto the stack */
		sh_lexskip(';',1,ST_NESTED);
		offset = staktell()-1;
		if((c=fcpeek(-1))!=';')
			break;
		/* remove trailing white space */
		while(offset>ARGVAL && ((c= *stakptr(offset-1)),isspace(c)))
			offset--;
		/* check for empty initialization expression  */
		if(offset==ARGVAL && n==0)
			continue;
		stakseek(offset);
		/* check for empty condition and treat as while((1)) */
		if(offset==ARGVAL)
			stakputc('1');
		argp = (struct argnod*)stakfreeze(1);
		t = getanode(argp);
		if(n==0)
			tf = makelist(TLST,t,tw);
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
		shlex.token = RPAREN|SYMREP;
		sh_syntax();
	}
	/* check whether the increment is present */
	if(*argp->argval)
	{
		t = getanode(argp);
		tw->wh.whinc = (struct arithnod*)t;
	}
	else
		tw->wh.whinc = 0;
	sh_lexopen((Lex_t*)sh.lex_context, &sh,1);
	if((n=sh_lex())==NL)
		n = skipnl(0);
	else if(n==';')
		n = sh_lex();
	if(n!=DOSYM && n!=LBRACE)
		sh_syntax();
	tw->wh.dotre = sh_cmd(n==DOSYM?DONESYM:RBRACE,SH_NL);
	tw->wh.whtyp = TWH;
	return(tf);

}

static Shnode_t *funct(void)
{
	register Shnode_t *t;
	register int flag;
	struct slnod *volatile slp=0;
	Stak_t *savstak;
	Sfoff_t	first, last;
	struct functnod *fp;
	Sfio_t *iop;
#if SHOPT_KIA
	unsigned long current = shlex.current;
#endif /* SHOPT_KIA */
	int jmpval, saveloop=loop_level;
	struct argnod *savelabel = label_last;
	struct  checkpt buff;
	t = getnode(functnod);
	t->funct.functline = sh.inlineno;
	t->funct.functtyp=TFUN;
	t->funct.functargs = 0;
	if(!(flag = (shlex.token==FUNCTSYM)))
		t->funct.functtyp |= FPOSIX;
	else if(sh_lex())
		sh_syntax();
	if(!(iop=fcfile()))
	{
		iop = sfopen(NIL(Sfio_t*),fcseek(0),"s");
		fcclose();
		fcfopen(iop);
	}
	t->funct.functloc = first = fctell();
	if(!sh.st.filename || sffileno(iop)<0)
	{
		if(fcfill() >= 0)
			fcseek(-1);
		if(sh_isstate(SH_HISTORY))
			t->funct.functloc = sfseek(sh.hist_ptr->histfp,(off_t)0,SEEK_CUR);
		else
		{
			/* copy source to temporary file */
			t->funct.functloc = 0;
			if(shlex.sh->heredocs)
				t->funct.functloc = sfseek(shlex.sh->heredocs,(Sfoff_t)0, SEEK_END);
			else
				shlex.sh->heredocs = sftmp(HERE_MEM);
			shlex.sh->funlog = shlex.sh->heredocs;
			t->funct.functtyp |= FPIN;
		}
	}
	t->funct.functnam= (char*)shlex.arg->argval;
#if SHOPT_KIA
	if(shlex.kiafile)
		shlex.current = kiaentity(t->funct.functnam,-1,'p',-1,-1,shlex.script,'p',0,"");
#endif /* SHOPT_KIA */
	if(flag)
	{
		shlex.token = sh_lex();
#if SHOPT_BASH
		if(shlex.token == LPAREN)
		{
			if((shlex.token = sh_lex()) == RPAREN)
				t->funct.functtyp |= FPOSIX;
			else
				sh_syntax();
		}
#endif
	}
	if(t->funct.functtyp&FPOSIX)
		skipnl(0);
	else
	{
		if(shlex.token==0)
			t->funct.functargs = (struct comnod*)simple(SH_NOIO|SH_FUNDEF,NIL(struct ionod*));
		while(shlex.token==NL)
			shlex.token = sh_lex();
	}
	if((flag && shlex.token!=LBRACE) || shlex.token==EOFSYM)
		sh_syntax();
	sh_pushcontext(&buff,1);
	jmpval = sigsetjmp(buff.buff,0);
	if(jmpval == 0)
	{
		/* create a new stak frame to compile the command */
		savstak = stakcreate(STAK_SMALL);
		savstak = stakinstall(savstak, 0);
		slp = (struct slnod*)stakalloc(sizeof(struct slnod)+sizeof(struct functnod));
		slp->slchild = 0;
		slp->slnext = sh.st.staklist;
		sh.st.staklist = 0;
		t->funct.functstak = (struct slnod*)slp;
		/*
		 * store the pathname of function definition file on stack
		 * in name field of fake for node
		 */
		fp = (struct functnod*)(slp+1);
		fp->functtyp = TFUN|FAMP;
		fp->functnam = 0;
		fp->functline = t->funct.functline;
		if(sh.st.filename)
			fp->functnam = stakcopy(sh.st.filename);
		loop_level = 0;
		label_last = label_list;
		if(!flag && shlex.token==0)
		{
			/* copy current word token to current stak frame */
			struct argnod *ap;
			flag = ARGVAL + strlen(shlex.arg->argval);
			ap = (struct argnod*)stakalloc(flag);
			memcpy(ap,shlex.arg,flag);
			shlex.arg = ap;
		}
		t->funct.functtre = item(SH_NOIO);
	}
	sh_popcontext(&buff);
	loop_level = saveloop;
	label_last = savelabel;
	/* restore the old stack */
	if(slp)
	{
		slp->slptr =  stakinstall(savstak,0);
		slp->slchild = sh.st.staklist;
	}
#if SHOPT_KIA
	shlex.current = current;
#endif /* SHOPT_KIA */
	if(jmpval)
	{
		if(slp && slp->slptr)
		{
			sh.st.staklist = slp->slnext;
			stakdelete(slp->slptr);
		}
		siglongjmp(*sh.jmplist,jmpval);
	}
	sh.st.staklist = (struct slnod*)slp;
	last = fctell();
	fp->functline = (last-first);
	fp->functtre = t;
	if(shlex.sh->funlog)
	{
		if(fcfill()>0)
			fcseek(-1);
		shlex.sh->funlog = 0;
	}
#if 	SHOPT_KIA
	if(shlex.kiafile)
		kiaentity(t->funct.functnam,-1,'p',t->funct.functline,sh.inlineno-1,shlex.current,'p',0,"");
#endif /* SHOPT_KIA */
	return(t);
}

/*
 * Compound assignment
 */
static struct argnod *assign(register struct argnod *ap)
{
	register int n;
	register Shnode_t *t, **tp;
	register struct comnod *ac;
	int array=0;
	Namval_t *np;
	n = strlen(ap->argval)-1;
	if(ap->argval[n]!='=')
		sh_syntax();
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
	t->for_.fortyp = sh_getlineno();
	tp = &t->for_.fortre;
	ap->argchn.ap = (struct argnod*)t;
	ap->argflag &= ARG_QUOTED;
	ap->argflag |= array;
	shlex.assignok = SH_ASSIGN;
	array=0;
	if((n=skipnl(0))==RPAREN || n==LPAREN)
	{
		int index= 0;
		struct argnod **settail;
		ac = (struct comnod*)getnode(comnod);
		settail= &ac->comset;
		memset((void*)ac,0,sizeof(*ac));
		ac->comline = sh_getlineno();
		while(n==LPAREN)
		{
			struct argnod *ap;
			ap = (struct argnod*)stakseek(ARGVAL);
			ap->argflag= ARG_ASSIGN;
			sfprintf(stkstd,"[%d]=",index++);
			ap = (struct argnod*)stakfreeze(1);
			ap->argnxt.ap = 0;
			ap = assign(ap);
			ap->argflag |= ARG_MESSAGE;
			*settail = ap;
			settail = &(ap->argnxt.ap);
			n = skipnl(0);
		}
	}
	else if(n)
		sh_syntax();
	else if(!(shlex.arg->argflag&ARG_ASSIGN) && !((np=nv_search(shlex.arg->argval,sh.fun_tree,0)) && nv_isattr(np,BLT_DCL)))
		array=SH_ARRAY;
	while(1)
	{
		if((n=shlex.token)==RPAREN)
			break;
		if(n==FUNCTSYM || n==SYMRES)
			ac = (struct comnod*)funct();
		else
			ac = (struct comnod*)simple(SH_NOIO|SH_ASSIGN|array,NIL(struct ionod*));
		if((n=shlex.token)==RPAREN)
			break;
		if(n!=NL && n!=';')
			sh_syntax();
		shlex.assignok = SH_ASSIGN;
		if((n=skipnl(0)) || array)
		{
			if(n==RPAREN)
				break;
			if(array ||  n!=FUNCTSYM)
				sh_syntax();
		}
		if((n!=FUNCTSYM) && !(shlex.arg->argflag&ARG_ASSIGN) && !((np=nv_search(shlex.arg->argval,sh.fun_tree,0)) && nv_isattr(np,BLT_DCL)))
		{
			struct argnod *arg = shlex.arg;
			if(n!=0)
				sh_syntax();
			/* check for sys5 style function */
			if(sh_lex()!=LPAREN || sh_lex()!=RPAREN)
			{
				shlex.arg = arg;
				shlex.token = 0;
				sh_syntax();
			}
			shlex.arg = arg;
			shlex.token = SYMRES;
		}
		t = makelist(TLST,(Shnode_t*)ac,t);
		*tp = t;
		tp = &t->lst.lstrit;
	}
	*tp = (Shnode_t*)ac;
	shlex.assignok = 0;
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

static Shnode_t	*item(int flag)
{
	register Shnode_t	*t;
	register struct ionod	*io;
	register int tok = (shlex.token&0xff);
	int savwdval = shlex.lasttok;
	int savline = shlex.lastline;
	int showme=0;
	if(!(flag&SH_NOIO) && (tok=='<' || tok=='>'))
		io=inout(NIL(struct ionod*),1);
	else
		io=0;
	if((tok=shlex.token) && tok!=EOFSYM && tok!=FUNCTSYM)
	{
		shlex.lastline =  sh_getlineno();
		shlex.lasttok = shlex.token;
	}
	switch(tok)
	{
	    /* [[ ... ]] test expression */
	    case BTESTSYM:
		t = test_expr(ETESTSYM);
		t->tre.tretyp &= ~TTEST;
		break;
	    /* ((...)) arithmetic expression */
	    case EXPRSYM:
		t = getanode(shlex.arg);
		sh_lex();
		goto done;

	    /* case statement */
	    case CASESYM:
	    {
		int savetok = shlex.lasttok;
		int saveline = shlex.lastline;
		t = getnode(swnod);
		if(sh_lex())
			sh_syntax();
		t->sw.swarg=shlex.arg;
		t->sw.swtyp=TSW;
		t->sw.swio = 0;
		t->sw.swtyp |= FLINENO;
		t->sw.swline =  sh.inlineno;
		if((tok=skipnl(0))!=INSYM && tok!=LBRACE)
			sh_syntax();
		if(!(t->sw.swlst=syncase(tok==INSYM?ESACSYM:RBRACE)) && shlex.token==EOFSYM)
		{
			shlex.lasttok = savetok;
			shlex.lastline = saveline;
			sh_syntax();
		}
		break;
	    }

	    /* if statement */
	    case IFSYM:
	    {
		register Shnode_t	*tt;
		t = getnode(ifnod);
		t->if_.iftyp=TIF;
		t->if_.iftre=sh_cmd(THENSYM,SH_NL);
		t->if_.thtre=sh_cmd(ELSESYM,SH_NL|SH_SEMI);
		tok = shlex.token;
		t->if_.eltre=(tok==ELSESYM?sh_cmd(FISYM,SH_NL|SH_SEMI):
			(tok==ELIFSYM?(shlex.token=IFSYM, tt=item(SH_NOIO)):0));
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
		t->for_.fortyp=(shlex.token==FORSYM?TFOR:TSELECT);
		t->for_.forlst=0;
		t->for_.forline =  sh.inlineno;
		if(sh_lex())
		{
			if(shlex.token!=EXPRSYM || t->for_.fortyp!=TFOR)
				sh_syntax();
			/* arithmetic for */
			t = arithfor(t);
			break;
		}
		t->for_.fornam=(char*) shlex.arg->argval;
		t->for_.fortyp |= FLINENO;
#if SHOPT_KIA
		if(shlex.kiafile)
			writedefs(shlex.arg,sh.inlineno,'v',NIL(struct argnod*));
#endif /* SHOPT_KIA */
		while((tok=sh_lex())==NL);
		if(tok==INSYM)
		{
			if(sh_lex())
			{
				if(shlex.token != NL && shlex.token !=';')
					sh_syntax();
				/* some Linux scripts assume this */
				if(sh_isoption(SH_NOEXEC))
					errormsg(SH_DICT,ERROR_warn(0),e_lexemptyfor,sh.inlineno-(shlex.token=='\n'));
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
				t->for_.forlst=(struct comnod*)simple(SH_NOIO,NIL(struct ionod*));
			if(shlex.token != NL && shlex.token !=';')
				sh_syntax();
			tok = skipnl(0);
		}
		/* 'for i;do cmd' is valid syntax */
		else if(tok==';')
			tok=sh_lex();
		if(tok!=DOSYM && tok!=LBRACE)
			sh_syntax();
		loop_level++;
		t->for_.fortre=sh_cmd(tok==DOSYM?DONESYM:RBRACE,SH_NL|SH_SEMI);
		if(--loop_level==0)
			label_last = label_list;
		break;
	    }

	    /* This is the code for parsing function definitions */
	    case FUNCTSYM:
		return(funct());

#if SHOPT_NAMESPACE
	    case NSPACESYM:
		t = getnode(fornod);
		t->for_.fortyp=TNSPACE;
		t->for_.forlst=0;
		if(sh_lex())
			sh_syntax();
		t->for_.fornam=(char*) shlex.arg->argval;
		while((tok=sh_lex())==NL);
		if(tok!=LBRACE)
			sh_syntax();
		t->for_.fortre = sh_cmd(RBRACE,SH_NL);
		break;
#endif /* SHOPT_NAMESPACE */

	    /* while and until */
	    case WHILESYM:
	    case UNTILSYM:
		t = getnode(whnod);
		t->wh.whtyp=(shlex.token==WHILESYM ? TWH : TUN);
		loop_level++;
		t->wh.whtre = sh_cmd(DOSYM,SH_NL);
		t->wh.dotre = sh_cmd(DONESYM,SH_NL|SH_SEMI);
		if(--loop_level==0)
			label_last = label_list;
		t->wh.whinc = 0;
		break;

	    case LABLSYM:
	    {
		register struct argnod *argp = label_list;
		while(argp)
		{
			if(strcmp(argp->argval,shlex.arg->argval)==0)
				errormsg(SH_DICT,ERROR_exit(3),e_lexsyntax3,sh.inlineno,argp->argval);
			argp = argp->argnxt.ap;
		}
		shlex.arg->argnxt.ap = label_list;
		label_list = shlex.arg;
		label_list->argchn.len = sh_getlineno();
		label_list->argflag = loop_level;
		skipnl(flag);
		if(!(t = item(SH_NL)))
			sh_syntax();
		tok = (t->tre.tretyp&(COMSCAN|COMSCAN-1));
		if(sh_isoption(SH_NOEXEC) && tok!=TWH && tok!=TUN && tok!=TFOR && tok!=TSELECT)
			errormsg(SH_DICT,ERROR_warn(0),e_lexlabignore,label_list->argchn.len,label_list->argval);
		return(t);
	    }

	    /* command group with {...} */
	    case LBRACE:
		t = sh_cmd(RBRACE,SH_NL);
		break;

	    case LPAREN:
		t = getnode(parnod);
		t->par.partre=sh_cmd(RPAREN,SH_NL);
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
			if(sh_lex()==';')
				sh_syntax();
			showme =  FSHOWME;
		}
	    /* simple command */
	    case 0:
		t = (Shnode_t*)simple(flag,io);
		t->tre.tretyp |= showme;
		return(t);
	}
	sh_lex();
	if(io=inout(io,0))
	{
		if((tok=t->tre.tretyp&COMMSK) != TFORK)
			tok = TSETIO;
		t=makeparent(tok,t);
		t->tre.treio=io;
	}
done:
	shlex.lasttok = savwdval;
	shlex.lastline = savline;
	return(t);
}

/*
 * This is for a simple command, for list, or compound assignment
 */
static Shnode_t *simple(int flag, struct ionod *io)
{
	register struct comnod *t;
	register struct argnod	*argp;
	register int tok;
	struct argnod	**argtail;
	struct argnod	**settail;
	int	argno = 0;
	int	assignment = 0;
	int	key_on = (!(flag&SH_NOIO) && sh_isoption(SH_KEYWORD));
	int	associative=0;
	if((argp=shlex.arg) && (argp->argflag&ARG_ASSIGN) && argp->argval[0]=='[')
	{
		flag |= SH_ARRAY;
		associative = 1;
	}
	t = (struct comnod*)getnode(comnod);
	t->comio=io; /*initial io chain*/
	/* set command line number for error messages */
	t->comline = sh_getlineno();
	argtail = &(t->comarg);
	t->comset = 0;
	t->comnamp = 0;
	t->comnamq = 0;
	t->comstate = 0;
	settail = &(t->comset);
	while(shlex.token==0)
	{
		argp = shlex.arg;
		if(*argp->argval==LBRACE && (flag&SH_FUNDEF) && argp->argval[1]==0)
		{
			shlex.token = LBRACE;
			break;
		}
		if(associative && argp->argval[0]!='[')
			sh_syntax();
		/* check for assignment argument */
		if((argp->argflag&ARG_ASSIGN) && assignment!=2)
		{
			*settail = argp;
			settail = &(argp->argnxt.ap);
			shlex.assignok = (flag&SH_ASSIGN)?SH_ASSIGN:1;
			if(assignment)
			{
				struct argnod *ap=argp;
				char *last, *cp;
				if(assignment==1)
				{
					last = strchr(argp->argval,'=');
					if((cp=strchr(argp->argval,'[')) && (cp < last))
						last = cp;
					stakseek(ARGVAL);
					stakwrite(argp->argval,last-argp->argval);
					ap=(struct argnod*)stakfreeze(1);
					ap->argflag = ARG_RAW;
					ap->argchn.ap = 0;
				}
				*argtail = ap;
				argtail = &(ap->argnxt.ap);
				if(argno>=0)
					argno++;
			}
			else /* alias substitutions allowed */
				shlex.aliasok = 1;
		}
		else
		{
			if(!(argp->argflag&ARG_RAW))
				argno = -1;
			if(argno>=0 && argno++==0 && !(flag&SH_ARRAY) && *argp->argval!='/')
			{
				/* check for builtin command */
				Namval_t *np=nv_bfsearch(argp->argval,sh.fun_tree, (Namval_t**)&t->comnamq,(char**)0);
				if((t->comnamp=(void*)np) && is_abuiltin(np) &&
					nv_isattr(np,BLT_DCL))
				{
					assignment = 1+(*argp->argval=='a');
					key_on = 1;
				}
			}
			*argtail = argp;
			argtail = &(argp->argnxt.ap);
			if(!(shlex.assignok=key_on)  && !(flag&SH_NOIO))
				shlex.assignok = SH_COMPASSIGN;
			shlex.aliasok = 0;
		}
	retry:
		tok = sh_lex();
#if SHOPT_DEVFD
		if((tok==IPROCSYM || tok==OPROCSYM))
		{
			Shnode_t *t;
			int mode = (tok==OPROCSYM);
			t = sh_cmd(RPAREN,SH_NL);
			argp = (struct argnod*)stakalloc(sizeof(struct argnod));
			*argp->argval = 0;
			argno = -1;
			*argtail = argp;
			argtail = &(argp->argnxt.ap);
			argp->argchn.ap = (struct argnod*)makeparent(mode?TFORK|FPIN|FAMP|FPCL:TFORK|FPOU,t);
			argp->argflag =  (ARG_EXP|mode);
			goto retry;
		}
#endif	/* SHOPT_DEVFD */
		if(tok==LPAREN)
		{
			if(argp->argflag&ARG_ASSIGN)
			{
				argp = assign(argp);
				if(associative)
					shlex.assignok |= SH_ASSIGN;
				goto retry;
			}
			else if(argno==1 && !t->comset)
			{
				/* SVR2 style function */
				if(sh_lex() == RPAREN)
				{
					shlex.arg = argp;
					return(funct());
				}
				shlex.token = LPAREN;
			}
		}
		else if(flag&SH_ASSIGN)
		{
			if(tok==RPAREN)
				break;
			else if(tok==NL && (flag&SH_ARRAY))
				goto retry;
		}
		if(!(flag&SH_NOIO))
		{
			if(io)
			{
				while(io->ionxt)
					io = io->ionxt;
				io->ionxt = inout((struct ionod*)0,0);
			}
			else
				t->comio = io = inout((struct ionod*)0,0);
		}
	}
	*argtail = 0;
	t->comtyp = TCOM;
#if SHOPT_KIA
	if(shlex.kiafile && !(flag&SH_NOIO))
	{
		register Namval_t *np=(Namval_t*)t->comnamp;
		unsigned long r=0;
		int line = t->comline;
		argp = t->comarg;
		if(np)
			r = kiaentity(nv_name(np),-1,'p',-1,0,shlex.unknown,'b',0,"");
		else if(argp)
			r = kiaentity(sh_argstr(argp),-1,'p',-1,0,shlex.unknown,'c',0,"");
		if(r>0)
			sfprintf(shlex.kiatmp,"p;%..64d;p;%..64d;%d;%d;c;\n",shlex.current,r,line,line);
		if(t->comset && argno==0)
			writedefs(t->comset,line,'v',t->comarg);
		else if(np && nv_isattr(np,BLT_DCL))
			writedefs(argp,line,0,NIL(struct argnod*));
		else if(argp && strcmp(argp->argval,"read")==0)
			writedefs(argp,line,0,NIL(struct argnod*));
#if 0
		else if(argp && strcmp(argp->argval,"unset")==0)
			writedefs(argp,line,'u',NIL(struct argnod*));
#endif
		else if(argp && *argp->argval=='.' && argp->argval[1]==0 && (argp=argp->argnxt.ap))
		{
			r = kiaentity(sh_argstr(argp),-1,'p',0,0,shlex.script,'d',0,"");
			sfprintf(shlex.kiatmp,"p;%..64d;p;%..64d;%d;%d;d;\n",shlex.current,r,line,line);
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
				errormsg(SH_DICT,ERROR_warn(0),e_lexlabunknown,sh.inlineno-(shlex.token=='\n'),cp);
		}
		else if(sh_isoption(SH_NOEXEC) && np==SYSSET && ((tok= *argp->argval)=='-'||tok=='+') &&
			(argp->argval[1]==0||strchr(argp->argval,'k')))
			errormsg(SH_DICT,ERROR_warn(0),e_lexobsolete5,sh.inlineno-(shlex.token=='\n'),argp->argval);
	}
	/* expand argument list if possible */
	if(argno>0)
		t->comarg = qscan(t,argno);
	else if(t->comarg)
		t->comtyp |= COMSCAN;
	shlex.aliasok = 0;
	return((Shnode_t*)t);
}

/*
 * skip past newlines but issue prompt if interactive
 */
static int	skipnl(int flag)
{
	register int token;
	while((token=sh_lex())==NL);
	if(token==';' && !(flag&SH_SEMI))
		sh_syntax();
	return(token);
}

/*
 * check for and process and i/o redirections
 * if flag>0 then an alias can be in the next word
 * if flag<0 only one redirection will be processed
 */
static struct ionod	*inout(struct ionod *lastio,int flag)
{
	register int 		iof = shlex.digits, token=shlex.token;
	register struct ionod	*iop;
	char *iovname=0;
#if SHOPT_BASH
	register int		errout=0;
#endif
	if(token==IOVNAME)
	{
		iovname=shlex.arg->argval+1;
		token= sh_lex();
		iof = 0;
	}
	switch(token&0xff)
	{
	    case '<':
		if(token==IODOCSYM)
			iof |= (IODOC|IORAW);
		else if(token==IOMOV0SYM)
			iof |= IOMOV;
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
#if SHOPT_BASH
		if(iof<0)
		{
			errout = 1;
			iof = 1;
		}
#endif
		iof |= IOPUT;
		if(token==IOAPPSYM)
			iof |= IOAPP;
		else if(token==IOMOV1SYM)
			iof |= IOMOV;
		else if(token==IOCLOBSYM)
			iof |= IOCLOB;
		else if((token&SYMSHARP) == SYMSHARP)
			iof |= IOLSEEK;
		break;

	    default:
		return(lastio);
	}
	shlex.digits=0;
	iop=(struct ionod*) stakalloc(sizeof(struct ionod));
	iop->iodelim = 0;
	if(token=sh_lex())
	{
		if(token==RPAREN && (iof&IOLSEEK) && shlex.comsub) 
		{
			shlex.arg = (struct argnod*)stakalloc(sizeof(struct argnod)+3);
			strcpy(shlex.arg->argval,"CUR");
			shlex.arg->argflag = ARG_RAW;
			iof |= IOARITH;
			fcseek(-1);
		}
		else if(token==EXPRSYM && (iof&IOLSEEK))
			iof |= IOARITH;
		else
			sh_syntax();
	}
	iop->ioname=shlex.arg->argval;
	iop->iovname = iovname;
	if(iof&IODOC)
	{
		if(shlex.digits==2)
		{
			iof |= IOSTRG;
			if(!(shlex.arg->argflag&ARG_RAW))
				iof &= ~IORAW;
		}
		else
		{
			if(!shlex.sh->heredocs)
				shlex.sh->heredocs = sftmp(HERE_MEM);
			iop->iolst=shlex.heredoc;
			shlex.heredoc=iop;
			if(shlex.arg->argflag&ARG_QUOTED)
				iof |= IOQUOTE;
			if(shlex.digits==3)
				iof |= IOLSEEK;
			if(shlex.digits)
				iof |= IOSTRIP;
		}
	}
	else
	{
		iop->iolst = 0;
		if(shlex.arg->argflag&ARG_RAW)
			iof |= IORAW;
	}
	iop->iofile=iof;
	if(flag>0)
		/* allow alias substitutions and parameter assignments */
		shlex.aliasok = shlex.assignok = 1;
#if SHOPT_KIA
	if(shlex.kiafile)
	{
		int n = sh.inlineno-(shlex.token=='\n');
		if(!(iof&IOMOV))
		{
			unsigned long r=kiaentity((iof&IORAW)?sh_fmtq(iop->ioname):iop->ioname,-1,'f',0,0,shlex.script,'f',0,"");
			sfprintf(shlex.kiatmp,"p;%..64d;f;%..64d;%d;%d;%c;%d\n",shlex.current,r,n,n,(iof&IOPUT)?((iof&IOAPP)?'a':'w'):((iof&IODOC)?'h':'r'),iof&IOUFD);
		}
	}
#endif /* SHOPT_KIA */
	if(flag>=0)
	{
		struct ionod *ioq=iop;
		sh_lex();
#if SHOPT_BASH
		if(errout)
		{
			/* redirect standard output to standard error */
			ioq = (struct ionod*)stakalloc(sizeof(struct ionod));
			ioq->ioname = "1";
			ioq->iolst = 0;
			ioq->iodelim = 0;
			ioq->iofile = IORAW|IOPUT|IOMOV|2;
			iop->ionxt=ioq;
		}
#endif
		ioq->ionxt=inout(lastio,flag);
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

static Shnode_t *test_expr(int sym)
{
	register Shnode_t *t = test_or();
	if(shlex.token!=sym)
		sh_syntax();
	return(t);
}

static Shnode_t *test_or(void)
{
	register Shnode_t *t = test_and();
	while(shlex.token==ORFSYM)
		t = makelist(TORF|TTEST,t,test_and());
	return(t);
}

static Shnode_t *test_and(void)
{
	register Shnode_t *t = test_primary();
	while(shlex.token==ANDFSYM)
		t = makelist(TAND|TTEST,t,test_primary());
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

static Shnode_t *test_primary(void)
{
	register struct argnod *arg;
	register Shnode_t *t;
	register int num,token;
	token = skipnl(0);
	num = shlex.digits;
	switch(token)
	{
	    case '(':
		t = test_expr(')');
		t = makelist(TTST|TTEST|TPAREN ,t, (Shnode_t*)pointerof(sh.inlineno));
		break;
	    case '!':
		if(!(t = test_primary()))
			sh_syntax();
		t->tre.tretyp |= TNEGATE;
		return(t);
	    case TESTUNOP:
		if(sh_lex())
			sh_syntax();
#if SHOPT_KIA
		if(shlex.kiafile && !strchr("sntzoOG",num))
		{
			int line = sh.inlineno- (shlex.token==NL);
			unsigned long r;
			r=kiaentity(sh_argstr(shlex.arg),-1,'f',0,0,shlex.script,'t',0,"");
			sfprintf(shlex.kiatmp,"p;%..64d;f;%..64d;%d;%d;t;\n",shlex.current,r,line,line);
		}
#endif /* SHOPT_KIA */
		t = makelist(TTST|TTEST|TUNARY|(num<<TSHIFT),
			(Shnode_t*)shlex.arg,(Shnode_t*)shlex.arg);
		t->tst.tstline =  sh.inlineno;
		break;
	    /* binary test operators */
	    case 0:
		arg = shlex.arg;
		if((token=sh_lex())==TESTBINOP)
		{
			num = shlex.digits;
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
			t = makelist(TTST|TTEST|TUNARY|('n'<<TSHIFT),
				(Shnode_t*)arg,(Shnode_t*)arg);
			t->tst.tstline =  sh.inlineno;
			return(t);
		}
		else
			sh_syntax();
#if SHOPT_KIA
		if(shlex.kiafile && (num==TEST_EF||num==TEST_NT||num==TEST_OT))
		{
			int line = sh.inlineno- (shlex.token==NL);
			unsigned long r;
			r=kiaentity(sh_argstr(shlex.arg),-1,'f',0,0,shlex.current,'t',0,"");
			sfprintf(shlex.kiatmp,"p;%..64d;f;%..64d;%d;%d;t;\n",shlex.current,r,line,line);
		}
#endif /* SHOPT_KIA */
		if(sh_lex())
			sh_syntax();
		if(num&TEST_PATTERN)
		{
			if(shlex.arg->argflag&(ARG_EXP|ARG_MAC))
				num &= ~TEST_PATTERN;
		}
		t = getnode(tstnod);
		t->lst.lsttyp = TTST|TTEST|TBINARY|(num<<TSHIFT);
		t->lst.lstlef = (Shnode_t*)arg;
		t->lst.lstrit = (Shnode_t*)shlex.arg;
		t->tst.tstline =  sh.inlineno;
#if SHOPT_KIA
		if(shlex.kiafile && (num==TEST_EF||num==TEST_NT||num==TEST_OT))
		{
			int line = sh.inlineno-(shlex.token==NL);
			unsigned long r;
			r=kiaentity(sh_argstr(shlex.arg),-1,'f',0,0,shlex.current,'t',0,"");
			sfprintf(shlex.kiatmp,"p;%..64d;f;%..64d;%d;%d;t;\n",shlex.current,r,line,line);
		}
#endif /* SHOPT_KIA */
		break;
	    default:
		return(0);
	}
	skipnl(0);
	return(t);
}

#if SHOPT_KIA
/*
 * return an entity checksum
 * The entity is created if it doesn't exist
 */
unsigned long kiaentity(const char *name,int len,int type,int first,int last,unsigned long parent, int pkind, int width, const char *attr)
{
	Namval_t *np;
	long offset = staktell();
	stakputc(type);
	if(len>0)
		stakwrite(name,len);
	else
	{
		if(type=='p')
			stakputs(path_basename(name));
		else
			stakputs(name);
	}
	stakputc(0);
	np = nv_search(stakptr(offset),shlex.entity_tree,NV_ADD);
	stakseek(offset);
	np->nvalue.i = pkind;
	nv_setsize(np,width);
	if(!nv_isattr(np,NV_TAGGED) && first>=0)
	{
		nv_onattr(np,NV_TAGGED);
		if(!pkind)
			pkind = '0';
		if(len>0)
			sfprintf(shlex.kiafile,"%..64d;%c;%.*s;%d;%d;%..64d;%..64d;%c;%d;%s\n",np->hash,type,len,name,first,last,parent,shlex.fscript,pkind,width,attr);
		else
			sfprintf(shlex.kiafile,"%..64d;%c;%s;%d;%d;%..64d;%..64d;%c;%d;%s\n",np->hash,type,name,first,last,parent,shlex.fscript,pkind,width,attr);
	}
	return(np->hash);
}

static void kia_add(register Namval_t *np, void *data)
{
	char *name = nv_name(np);
	NOT_USED(data);
	kiaentity(name+1,-1,*name,0,-1,(*name=='p'?shlex.unknown:shlex.script),np->nvalue.i,nv_size(np),"");
}

int kiaclose(void)
{
	register off_t off1,off2;
	register int n;
	if(shlex.kiafile)
	{
		unsigned long r = kiaentity(shlex.scriptname,-1,'p',-1,sh.inlineno-1,0,'s',0,"");
		kiaentity(shlex.scriptname,-1,'p',1,sh.inlineno-1,r,'s',0,"");
		kiaentity(shlex.scriptname,-1,'f',1,sh.inlineno-1,r,'s',0,"");
		nv_scan(shlex.entity_tree,kia_add,(void*)0,NV_TAGGED,0);
		off1 = sfseek(shlex.kiafile,(off_t)0,SEEK_END);
		sfseek(shlex.kiatmp,(off_t)0,SEEK_SET);
		sfmove(shlex.kiatmp,shlex.kiafile,SF_UNBOUND,-1);
		off2 = sfseek(shlex.kiafile,(off_t)0,SEEK_END);
#ifdef SF_BUFCONST
		if(off2==off1)
			n= sfprintf(shlex.kiafile,"DIRECTORY\nENTITY;%lld;%d\nDIRECTORY;",(Sflong_t)shlex.kiabegin,(size_t)(off1-shlex.kiabegin));
		else
			n= sfprintf(shlex.kiafile,"DIRECTORY\nENTITY;%lld;%d\nRELATIONSHIP;%lld;%d\nDIRECTORY;",(Sflong_t)shlex.kiabegin,(size_t)(off1-shlex.kiabegin),(Sflong_t)off1,(size_t)(off2-off1));
		if(off2 >= INT_MAX)
			off2 = -(n+12);
		sfprintf(shlex.kiafile,"%010.10lld;%010d\n",(Sflong_t)off2+10, n+12);
#else
		if(off2==off1)
			n= sfprintf(shlex.kiafile,"DIRECTORY\nENTITY;%d;%d\nDIRECTORY;",shlex.kiabegin,off1-shlex.kiabegin);
		else
			n= sfprintf(shlex.kiafile,"DIRECTORY\nENTITY;%d;%d\nRELATIONSHIP;%d;%d\nDIRECTORY;",shlex.kiabegin,off1-shlex.kiabegin,off1,off2-off1);
		sfprintf(shlex.kiafile,"%010d;%010d\n",off2+10, n+12);
#endif
	}
	return(sfclose(shlex.kiafile));
}
#endif /* SHOPT_KIA */
