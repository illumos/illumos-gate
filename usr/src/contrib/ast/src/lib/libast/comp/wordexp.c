/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2011 AT&T Intellectual Property          *
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
*                 Glenn Fowler <gsf@research.att.com>                  *
*                  David Korn <dgk@research.att.com>                   *
*                   Phong Vo <kpv@research.att.com>                    *
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * POSIX 1003.2 wordexp implementation
 */ 

#include	<ast.h>
#include	<wordexp.h>
#include	<stak.h>

struct list
{
	struct list *next;
};

/*
 * elimnates shell quoting as inserted with sh_fmtq
 * result relaces <string>
 * length of resulting string is returned.
 */
static int	sh_unquote(char* string)
{
	register char *sp=string, *dp;
	register int c;
	while((c= *sp) && c!='\'')
		sp++;
	if(c==0)
		return(sp-string);
	if((dp=sp) > string && sp[-1]=='$')
	{
		register int n=stresc(sp+1);
		/* copy all but trailing ' */
		while(--n>0)
			*dp++ = *++sp;
	}
	else
	{
		while((c= *++sp) && c!='\'')
			*dp++ = c;
	}
	*dp=0;
	return(dp-string);
}

int	wordexp(const char *string, wordexp_t *wdarg, register int flags)
{
	register Sfio_t *iop;
	register char *cp=(char*)string;
	register int c,quoted=0,literal=0,ac=0;
	int offset;
	char *savebase,**av;
	if(offset=staktell())
		savebase = stakfreeze(0);
	if(flags&WRDE_REUSE)
		wordfree(wdarg);
	else if(!(flags&WRDE_APPEND))
	{
		wdarg->we_wordv = 0;
		wdarg->we_wordc = 0;
	}
	if(flags&WRDE_UNDEF)
		stakwrite("set -u\n",7);
	if(!(flags&WRDE_SHOWERR))
		stakwrite("exec 2> /dev/null\n",18);
	stakwrite("print -f \"%q\\n\" ",16);
	if(*cp=='#')
		stakputc('\\');
	while(c = *cp++)
	{
		if(c=='\'' && !quoted)
			literal = !literal;
		else if(!literal)
		{
			if(c=='\\' && (!quoted || strchr("\\\"`\n$",c)))
			{
				stakputc('\\');
				if(c= *cp)
					cp++;
				else
					c = '\\';
			}
			else if(c=='"')
				quoted = !quoted;
			else if(c=='`' || (c=='$' && *cp=='('))
			{
				if(flags&WRDE_NOCMD)
				{
					c=WRDE_CMDSUB;
					goto err;
				}
				/* only the shell can parse the rest */
				stakputs(cp-1);
				break;
			}
			else if(!quoted && strchr("|&\n;<>"+ac,c))
			{
				c=WRDE_BADCHAR;
				goto err;
			}
			else if(c=='(') /* allow | and & inside pattern */
				ac=2;
		}
		stakputc(c);
	}
	stakputc(0);
	if(!(iop = sfpopen((Sfio_t*)0,stakptr(0),"r")))
	{
		c = WRDE_NOSHELL;
		goto err;
	}
	stakseek(0);
	ac = 0;
	while((c=sfgetc(iop)) != EOF)
	{
		if(c=='\'')
			quoted = ! quoted;
		else if(!quoted && (c==' ' || c=='\n'))
		{
			ac++;
			c = 0;
		}
		stakputc(c);
	}
	if(c=sfclose(iop))
	{
		if(c==3 || !(flags&WRDE_UNDEF))
			c=WRDE_SYNTAX;
		else
			c=WRDE_BADVAL;
		goto err;
	}
	c = ac+2;
	if(flags&WRDE_DOOFFS)
		c += wdarg->we_offs;
	if(flags&WRDE_APPEND)
		av = (char**)realloc((void*)&wdarg->we_wordv[-1], (wdarg->we_wordc+c)*sizeof(char*));
	else if(av = (char**)malloc(c*sizeof(char*)))
	{
		if(flags&WRDE_DOOFFS)
			memset((void*)av,0,(wdarg->we_offs+1)*sizeof(char*));
		else
			av[0] = 0;
	}
	if(!av)
		return(WRDE_NOSPACE);
	c = staktell();
	if(!(cp = (char*)malloc(sizeof(char*)+c)))
	{
		c=WRDE_NOSPACE;
		goto err;
	}
	((struct list*)cp)->next = (struct list*)(*av);
	*av++ = (char*)cp;
	cp += sizeof(char*);
	wdarg->we_wordv = av;
	if(flags&WRDE_APPEND)
		av += wdarg->we_wordc;
	wdarg->we_wordc += ac;
	if(flags&WRDE_DOOFFS)
		av += wdarg->we_offs;
	memcpy((void*)cp,stakptr(offset),c);
	while(ac-- > 0)
	{
		*av++ = cp;
		sh_unquote(cp);
		while(c= *cp++);
	}
	*av = 0;
	c=0;
err:
	if(offset)
		stakset(savebase,offset);
	else
		stakseek(0);
	return(c);
}

/*
 * free fields in <wdarg>
 */
int wordfree(register wordexp_t *wdarg)
{
	struct list *arg, *argnext;
	if(wdarg->we_wordv)
	{
		argnext = (struct list*)wdarg->we_wordv[-1];
		while(arg=argnext)
		{
			argnext = arg->next;
			free((void*)arg);
		}
		free((void*)&wdarg->we_wordv[-1]);
		wdarg->we_wordv = 0;
	}
	wdarg->we_wordc=0;
	return(0);
}
