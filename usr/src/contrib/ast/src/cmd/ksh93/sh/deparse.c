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
 * David Korn
 * AT&T Labs
 *
 * shell deparser
 *
 */

#include	"defs.h"
#include	"shnodes.h"
#include	"test.h"


#define HUGE_INT	(((unsigned)-1)>>1)
#define	BEGIN	0
#define MIDDLE	1
#define	END	2
#define PRE	1
#define POST	2


/* flags that can be specified with p_tree() */
#define NO_NEWLINE	1
#define NEED_BRACE	2
#define NO_BRACKET	4

static void p_comlist(const struct dolnod*,int);
static void p_arg(const struct argnod*, int endchar, int opts);
static void p_comarg(const struct comnod*);
static void p_keyword(const char*,int);
static void p_redirect(const struct ionod*);
static void p_switch(const struct regnod*);
static void here_body(const struct ionod*);
static void p_tree(const Shnode_t*,int);

static int level;
static int begin_line;
static int end_line;
static char io_op[7];
static char un_op[3] = "-?";
static const struct ionod *here_doc;
static Sfio_t *outfile;
static const char *forinit = "";

extern void sh_deparse(Sfio_t*, const Shnode_t*,int);

void sh_deparse(Sfio_t *out, const Shnode_t *t,int tflags)
{
	outfile = out;
	p_tree(t,tflags);
}
/*
 * print script corresponding to shell tree <t>
 */
static void p_tree(register const Shnode_t *t,register int tflags)
{
	register char *cp;
	int save = end_line;
	int needbrace = (tflags&NEED_BRACE);
	tflags &= ~NEED_BRACE;
	if(tflags&NO_NEWLINE)
		end_line = ' ';
	else
		end_line = '\n';
	switch(t->tre.tretyp&COMMSK)
	{
		case TTIME:
			if(t->tre.tretyp&COMSCAN)
				p_keyword("!",BEGIN);
			else
				p_keyword("time",BEGIN);
			if(t->par.partre)
				p_tree(t->par.partre,tflags); 
			level--;
			break;

		case TCOM:
			if(begin_line && level>0)
				sfnputc(outfile,'\t',level);
			begin_line = 0;
			p_comarg((struct comnod*)t);
			break;

		case TSETIO:
			if(t->tre.tretyp&FPCL)
				tflags |= NEED_BRACE;
			else
				tflags = NO_NEWLINE|NEED_BRACE;
			p_tree(t->fork.forktre,tflags);
			p_redirect(t->fork.forkio);
			break;

		case TFORK:
			if(needbrace)
				tflags |= NEED_BRACE;
			if(t->tre.tretyp&(FAMP|FCOOP))
			{
				tflags = NEED_BRACE|NO_NEWLINE;
				end_line = ' ';
			}
			else if(t->fork.forkio)
				tflags = NO_NEWLINE;
			p_tree(t->fork.forktre,tflags);
			if(t->fork.forkio)
				p_redirect(t->fork.forkio);
			if(t->tre.tretyp&FCOOP)
			{
				sfputr(outfile,"|&",'\n');
				begin_line = 1;
			}
			else if(t->tre.tretyp&FAMP)
			{
				sfputr(outfile,"&",'\n');
				begin_line = 1;
			}
			break;
	
		case TIF:
			p_keyword("if",BEGIN);
			p_tree(t->if_.iftre,0);
			p_keyword("then",MIDDLE);
			p_tree(t->if_.thtre,0);
			if(t->if_.eltre)
			{
				p_keyword("else",MIDDLE);
				p_tree(t->if_.eltre,0);
			}
			p_keyword("fi",END);
			break;

		case TWH:
			if(t->wh.whinc)
				cp = "for";
			else if(t->tre.tretyp&COMSCAN)
				cp = "until";
			else
				cp = "while";
			p_keyword(cp,BEGIN);
			if(t->wh.whinc)
			{
				struct argnod *arg = (t->wh.whtre)->ar.arexpr;
				sfprintf(outfile,"(( %s; ",forinit);
				forinit = "";
				sfputr(outfile,arg->argval,';');
				arg = (t->wh.whinc)->arexpr;
				sfprintf(outfile," %s))\n",arg->argval);
			}
			else
				p_tree(t->wh.whtre,0);
			t = t->wh.dotre;
			goto dolist;

		case TLST:
		{
			Shnode_t *tr = t->lst.lstrit;
			if(tr->tre.tretyp==TWH && tr->wh.whinc && t->lst.lstlef->tre.tretyp==TARITH)
			{
				/* arithmetic for statement */
				struct argnod *init = (t->lst.lstlef)->ar.arexpr;
				forinit= init->argval;
				p_tree(t->lst.lstrit,tflags);
				break;
			}
			if(needbrace)
				p_keyword("{",BEGIN);
			p_tree(t->lst.lstlef,0);
			if(needbrace)
				tflags = 0;
			p_tree(t->lst.lstrit,tflags);
			if(needbrace)
				p_keyword("}",END);
			break;
		}

		case TAND:
			cp = "&&";
			goto andor;
		case TORF:
			cp = "||";
			goto andor;
		case TFIL:
			cp = "|";
		andor:
		{
			int bracket = 0;
			if(t->tre.tretyp&TTEST)
			{
				tflags |= NO_NEWLINE;
				if(!(tflags&NO_BRACKET))
				{
					p_keyword("[[",BEGIN);
					tflags |= NO_BRACKET;
					bracket=1;
				}
			}
			p_tree(t->lst.lstlef,NEED_BRACE|NO_NEWLINE|(tflags&NO_BRACKET));
			if(tflags&FALTPIPE)
			{
				Shnode_t *tt = t->lst.lstrit;
				if(tt->tre.tretyp!=TFIL || !(tt->lst.lstlef->tre.tretyp&FALTPIPE))
				{
					sfputc(outfile,'\n');
					return;
				}
			}
			sfputr(outfile,cp,here_doc?'\n':' ');
			if(here_doc)
			{
				here_body(here_doc);
				here_doc = 0;
			}
			level++;
			p_tree(t->lst.lstrit,tflags|NEED_BRACE);
			if(bracket)
				p_keyword("]]",END);
			level--;
			break;
		}
	
		case TPAR:
			p_keyword("(",BEGIN);
			p_tree(t->par.partre,0); 
			p_keyword(")",END);
			break;

		case TARITH:
		{
			register struct argnod *ap = t->ar.arexpr;
			if(begin_line && level)
				sfnputc(outfile,'\t',level);
			sfprintf(outfile,"(( %s ))%c",ap->argval,end_line);
			if(!(tflags&NO_NEWLINE))
				begin_line=1;
			break;
		}

		case TFOR:
			cp = ((t->tre.tretyp&COMSCAN)?"select":"for");
			p_keyword(cp,BEGIN);
			sfputr(outfile,t->for_.fornam,' ');
			if(t->for_.forlst)
			{
				sfputr(outfile,"in",' ');
				tflags = end_line;
				end_line = '\n';
				p_comarg(t->for_.forlst);
				end_line = tflags;
			}
			else
				sfputc(outfile,'\n');
			begin_line = 1;
			t = t->for_.fortre;
		dolist:
			p_keyword("do",MIDDLE);
			p_tree(t,0);
			p_keyword("done",END);
			break;
	
		case TSW:
			p_keyword("case",BEGIN);
			p_arg(t->sw.swarg,' ',0);
			if(t->sw.swlst)
			{
				begin_line = 1;
				sfputr(outfile,"in",'\n');
				tflags = end_line;
				end_line = '\n';
				p_switch(t->sw.swlst);
				end_line = tflags;
			}
			p_keyword("esac",END);
			break;

		case TFUN:
			if(t->tre.tretyp&FPOSIX)
			{
				sfprintf(outfile,"%s",t->funct.functnam);
				p_keyword("()\n",BEGIN);
			}
			else
			{
				p_keyword("function",BEGIN);
				tflags = (t->funct.functargs?' ':'\n');
				sfputr(outfile,t->funct.functnam,tflags);
				if(t->funct.functargs)
				{
					tflags = end_line;
					end_line = '\n';
					p_comarg(t->funct.functargs);
					end_line = tflags;
				}
			}
			begin_line = 1;
			p_keyword("{\n",MIDDLE);
			begin_line = 1;
			p_tree(t->funct.functtre,0); 
			p_keyword("}",END);
			break;
		/* new test compound command */
		case TTST:
			if(!(tflags&NO_BRACKET))
				p_keyword("[[",BEGIN);
			if((t->tre.tretyp&TPAREN)==TPAREN)
			{
				p_keyword("(",BEGIN);
				p_tree(t->lst.lstlef,NO_BRACKET|NO_NEWLINE); 
				p_keyword(")",END);
			}
			else
			{
				int flags = (t->tre.tretyp)>>TSHIFT;
				if(t->tre.tretyp&TNEGATE)
					sfputr(outfile,"!",' ');
				if(t->tre.tretyp&TUNARY)
				{
					un_op[1] = flags;
					sfputr(outfile,un_op,' ');
				}
				else
					cp = ((char*)(shtab_testops+(flags&037)-1)->sh_name);
				p_arg(&(t->lst.lstlef->arg),' ',0);
				if(t->tre.tretyp&TBINARY)
				{
					sfputr(outfile,cp,' ');
					p_arg(&(t->lst.lstrit->arg),' ',0);
				}
			}
			if(!(tflags&NO_BRACKET))
				p_keyword("]]",END);
	}
	while(begin_line && here_doc)
	{
		here_body(here_doc);
		here_doc = 0;
	}
	end_line = save;
	return;
}

/*
 * print a keyword
 * increment indent level for flag==BEGIN
 * decrement indent level for flag==END
 */
static void p_keyword(const char *word,int flag)
{
	register int sep;
	if(flag==END)
		sep = end_line;
	else if(*word=='[' || *word=='(')
		sep = ' ';
	else
		sep = '\t';
	if(flag!=BEGIN)
		level--;
	if(begin_line && level)
		sfnputc(outfile,'\t',level);
	sfputr(outfile,word,sep);
	if(sep=='\n')
		begin_line=1;
	else
		begin_line=0;
	if(flag!=END)
		level++;
}

static void p_arg(register const struct argnod *arg,register int endchar,int opts)
{
	register const char *cp;
	register int flag;
	do
	{
		if(!arg->argnxt.ap)
			flag = endchar;
		else if(opts&PRE)
		{
			/* case alternation lists in reverse order */
			p_arg(arg->argnxt.ap,'|',opts);
			flag = endchar;
		}
		else if(opts)
			flag = ' ';
		cp = arg->argval;
		if(*cp==0 && (arg->argflag&ARG_EXP)  && arg->argchn.ap)
		{
			int c = (arg->argflag&ARG_RAW)?'>':'<';
			sfputc(outfile,c);
			sfputc(outfile,'(');
			p_tree((Shnode_t*)arg->argchn.ap,0);
			sfputc(outfile,')');
		}
		else if(*cp==0 && opts==POST && arg->argchn.ap)
		{
			/* compound assignment */
			struct fornod *fp=(struct fornod*)arg->argchn.ap;
			sfprintf(outfile,"%s=(\n",fp->fornam);
			sfnputc(outfile,'\t',++level);
			p_tree(fp->fortre,0);
			if(--level)
				sfnputc(outfile,'\t',level);
			sfputc(outfile,')');
		}
		else if((arg->argflag&ARG_RAW) && (cp[1] || (*cp!='[' && *cp!=']')))
			cp = sh_fmtq(cp);
		sfputr(outfile,cp,flag);
		if(flag=='\n')
			begin_line = 1;
		arg = arg->argnxt.ap;
	}
	while((opts&POST) && arg);
	return;
}

static void p_redirect(register const struct ionod *iop)
{
	register char *cp;
	register int iof,iof2;
	for(;iop;iop=iop->ionxt)
	{
		iof=iop->iofile;
		cp = io_op;
		if(iop->iovname)
		{
			sfwrite(outfile,"(;",2);
			sfputr(outfile,iop->iovname,')');
			cp++;
		}
		else
			*cp = '0'+(iof&IOUFD);
		if(iof&IOPUT)
		{
			if(*cp == '1' && !iop->iovname)
				cp++;
			io_op[1] = '>';
		}
		else
		{
			if(*cp == '0' && !iop->iovname)
				cp++;
			io_op[1] = '<';
		}
		io_op[2] = 0;
		io_op[3] = 0;
		if(iof&IOLSEEK)
		{
			io_op[1] = '#';
			if(iof&IOARITH)
				strcpy(&io_op[3]," ((");
		}
		else if(iof&IOMOV)
			io_op[2] = '&';
		else if(iof&(IORDW|IOAPP))
			io_op[2] = '>';
		else if(iof&IOCLOB)
			io_op[2] = '|';
		if(iop->iodelim)
		{
			/* here document */
#ifdef xxx
			iop->iolink = (char*)here_doc;
#endif
			here_doc  = iop;
			io_op[2] = '<';
#ifdef future
			if(iof&IOSTRIP)
				io_op[3] = '-';
#endif
		}
		sfputr(outfile,cp,' ');
		if(iop->ionxt)
			iof = ' ';
		else
		{
			if((iof=end_line)=='\n')
				begin_line = 1;
		}
		if((iof&IOLSEEK) && (iof&IOARITH))
			iof2 = iof, iof = ' ';
		if(iop->iodelim)
		{
			if(!(iop->iofile&IODOC))
				sfwrite(outfile,"''",2);
			sfputr(outfile,sh_fmtq(iop->iodelim),iof);
		}
		else if(iop->iofile&IORAW)
			sfputr(outfile,sh_fmtq(iop->ioname),iof);
		else
			sfputr(outfile,iop->ioname,iof);
		if((iof&IOLSEEK) && (iof&IOARITH))
			sfputr(outfile, "))", iof2);
	}
	return;
}

static void p_comarg(register const struct comnod *com)
{
	register int flag = end_line;
	if(com->comtyp&FAMP)
		sfwrite(outfile,"& ",2);
	if(com->comarg || com->comio)
		flag = ' ';
	if(com->comset)
		p_arg(com->comset,flag,POST);
	if(com->comarg)
	{
		if(!com->comio)
			flag = end_line;
		if(com->comtyp&COMSCAN)
			p_arg(com->comarg,flag,POST);
		else
			p_comlist((struct dolnod*)com->comarg,flag);
	}
	if(com->comio)
		p_redirect(com->comio);
	return;
}

static void p_comlist(const struct dolnod *dol,int endchar)
{
	register char *cp, *const*argv;
	register int flag = ' ', special;
	argv = dol->dolval+ARG_SPARE;
	cp = *argv;
	special = (*cp=='[' && cp[1]==0);
	do
	{
		if(cp)
			argv++;
		else
			cp = "";
		if(*argv==0)
		{
			if((flag=endchar)=='\n')
				begin_line = 1;
			special = (*cp==']' && cp[1]==0);
		}
		sfputr(outfile,special?cp:sh_fmtq(cp),flag);
		special = 0;
	}
	while(cp  = *argv);
	return;
}

static void p_switch(register const struct regnod *reg)
{
	if(level>1)
		sfnputc(outfile,'\t',level-1);
	p_arg(reg->regptr,')',PRE);
	begin_line = 0;
	sfputc(outfile,'\t');
	if(reg->regcom)
		p_tree(reg->regcom,0);
	level++;
	if(reg->regflag)
		p_keyword(";&",END);
	else
		p_keyword(";;",END);
	if(reg->regnxt)
		p_switch(reg->regnxt);
	return;
}

/*
 * output here documents
 */
static void here_body(register const struct ionod *iop)
{
	Sfio_t *infile;
#ifdef xxx
	if(iop->iolink)
		here_body((struct inode*)iop->iolink);
	iop->iolink = 0;
#endif
	if(iop->iofile&IOSTRG)
		infile = sfnew((Sfio_t*)0,iop->ioname,iop->iosize,-1,SF_STRING|SF_READ);
	else
		sfseek(infile=sh.heredocs,iop->iooffset,SEEK_SET);
	sfmove(infile,outfile,iop->iosize,-1);
	if(iop->iofile&IOSTRG)
		sfclose(infile);
	sfputr(outfile,iop->iodelim,'\n');
}

