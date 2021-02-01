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
 * shell parse tree dump
 *
 */

#include	"defs.h"
#include	"shnodes.h"
#include	"path.h"
#include	"io.h"
#include	<ccode.h>

static int p_comlist(const struct dolnod*);
static int p_arg(const struct argnod*);
static int p_comarg(const struct comnod*);
static int p_redirect(const struct ionod*);
static int p_switch(const struct regnod*);
static int p_tree(const Shnode_t*);
static int p_string(const char*);

static Sfio_t *outfile;

int sh_tdump(Sfio_t *out, const Shnode_t *t)
{
	outfile = out;
	return(p_tree(t));
}

/*
 *  convert to ASCII to write and back again if needed
 */
static int outstring(Sfio_t *out, const char *string, int n)
{
	int r;
	char *cp = (char*)string;
	ccmaps(cp, n, CC_NATIVE, CC_ASCII);
	r = sfwrite(out,cp,n);
	ccmaps(cp, n, CC_ASCII, CC_NATIVE);
	return(r);
}

/*
 * print script corresponding to shell tree <t>
 */
static int p_tree(register const Shnode_t *t)
{
	if(!t)
		return(sfputl(outfile,-1));
	if(sfputl(outfile,t->tre.tretyp)<0)
		return(-1);
	switch(t->tre.tretyp&COMMSK)
	{
		case TTIME:
		case TPAR:
			return(p_tree(t->par.partre)); 
		case TCOM:
			return(p_comarg((struct comnod*)t));
		case TSETIO:
		case TFORK:
			if(sfputu(outfile,t->fork.forkline)<0)
				return(-1);
			if(p_tree(t->fork.forktre)<0)
				return(-1);
			return(p_redirect(t->fork.forkio));
		case TIF:
			if(p_tree(t->if_.iftre)<0)
				return(-1);
			if(p_tree(t->if_.thtre)<0)
				return(-1);
			return(p_tree(t->if_.eltre));
		case TWH:
			if(t->wh.whinc)
			{
				if(p_tree((Shnode_t*)(t->wh.whinc))<0)
					return(-1);
			}
			else
			{
				if(sfputl(outfile,-1)<0)
					return(-1);
			}
			if(p_tree(t->wh.whtre)<0)
				return(-1);
			return(p_tree(t->wh.dotre));
		case TLST:
		case TAND:
		case TORF:
		case TFIL:
			if(p_tree(t->lst.lstlef)<0)
				return(-1);
			return(p_tree(t->lst.lstrit));
		case TARITH:
			if(sfputu(outfile,t->ar.arline)<0)
				return(-1);
			return(p_arg(t->ar.arexpr));
		case TFOR:
			if(sfputu(outfile,t->for_.forline)<0)
				return(-1);
			if(p_tree(t->for_.fortre)<0)
				return(-1);
			if(p_string(t->for_.fornam)<0)
				return(-1);
			return(p_tree((Shnode_t*)t->for_.forlst));
		case TSW:
			if(sfputu(outfile,t->sw.swline)<0)
				return(-1);
			if(p_arg(t->sw.swarg)<0)
				return(-1);
			return(p_switch(t->sw.swlst));
		case TFUN:
			if(sfputu(outfile,t->funct.functline)<0)
				return(-1);
			if(p_string(t->funct.functnam)<0)
				return(-1);
			if(p_tree(t->funct.functtre)<0)
				return(-1);
			return(p_tree((Shnode_t*)t->funct.functargs));
		case TTST:
			if(sfputu(outfile,t->tst.tstline)<0)
				return(-1);
			if((t->tre.tretyp&TPAREN)==TPAREN)
				return(p_tree(t->lst.lstlef)); 
			else
			{
				if(p_arg(&(t->lst.lstlef->arg))<0)
					return(-1);
				if((t->tre.tretyp&TBINARY))
					return(p_arg(&(t->lst.lstrit->arg)));
				return(0);
			}
	}
	return(-1);
}

static int p_arg(register const struct argnod *arg)
{
	register int n;
	struct fornod *fp;
	while(arg)
	{
		if((n = strlen(arg->argval)) || (arg->argflag&~(ARG_APPEND|ARG_MESSAGE|ARG_QUOTED)))
			fp=0;
		else
		{
			fp=(struct fornod*)arg->argchn.ap;
			n = strlen(fp->fornam)+1;
		}
		sfputu(outfile,n+1);
		if(fp)
		{
			sfputc(outfile,0);
			outstring(outfile,fp->fornam,n-1);
		}
		else
			outstring(outfile,arg->argval,n);
		sfputc(outfile,arg->argflag);
		if(fp)
		{
			sfputu(outfile,fp->fortyp);
			p_tree(fp->fortre);
		}
		else if(n==0 && (arg->argflag&ARG_EXP) && arg->argchn.ap)
			p_tree((Shnode_t*)arg->argchn.ap);
		arg = arg->argnxt.ap;
	}
	return(sfputu(outfile,0));
}

static int p_redirect(register const struct ionod *iop)
{
	while(iop)
	{
		if(iop->iovname)
			sfputl(outfile,iop->iofile|IOVNM);
		else
			sfputl(outfile,iop->iofile);
		p_string(iop->ioname);
		if(iop->iodelim)
		{
			p_string(iop->iodelim);
			sfputl(outfile,iop->iosize);
			sfseek(sh.heredocs,iop->iooffset,SEEK_SET);
			sfmove(sh.heredocs,outfile, iop->iosize,-1);
		}
		else
			sfputu(outfile,0);
		if(iop->iovname)
			p_string(iop->iovname);
		iop = iop->ionxt;
	}
	return(sfputl(outfile,-1));
}

static int p_comarg(register const struct comnod *com)
{
	p_redirect(com->comio);
	p_arg(com->comset);
	if(!com->comarg)
		sfputl(outfile,-1);
	else if(com->comtyp&COMSCAN)
		p_arg(com->comarg);
	else
		p_comlist((struct dolnod*)com->comarg);
	return(sfputu(outfile,com->comline));
}

static int p_comlist(const struct dolnod *dol)
{
	register char *cp, *const*argv;
	register int n;
	argv = dol->dolval+ARG_SPARE;
	while(cp = *argv)
		argv++;
	n = argv - (dol->dolval+1);
	sfputl(outfile,n);
	argv = dol->dolval+ARG_SPARE;
	while(cp  = *argv++)
		p_string(cp);
	return(sfputu(outfile,0));
}

static int p_switch(register const struct regnod *reg)
{
	while(reg)
	{
		sfputl(outfile,reg->regflag);
		p_arg(reg->regptr);
		p_tree(reg->regcom);
		reg = reg->regnxt;
	}
	return(sfputl(outfile,-1));
}

static int p_string(register const char *string)
{
	register size_t n=strlen(string);
	if(sfputu(outfile,n+1)<0)
		return(-1);
	return(outstring(outfile,string,n));
}
