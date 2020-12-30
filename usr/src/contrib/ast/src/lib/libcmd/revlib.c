/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1992-2011 AT&T Intellectual Property          *
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
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * common support for tail and rev
 */

#include	<cmd.h>
#include	<rev.h>

#define BUFSIZE			SF_BUFSIZE
#define rounddown(n,size)	(((n)-1)&~((size)-1))

/*
 * copy the lines starting at offset <start> from in <in> to <out>
 * in reverse order
 */
int rev_line(Sfio_t *in, Sfio_t *out, off_t start)
{
	register char *cp, *cpold;
	register int n, nleft=0;
	char buff[BUFSIZE];
	off_t offset;
	if(sfseek(in,(off_t)0,SEEK_CUR) < 0)
	{
		Sfio_t *tmp = sftmp(4*SF_BUFSIZE);
		if(!tmp)
			return(-1);
		if(start>0 && sfmove(in, (Sfio_t*)0, start, -1) != start)
			return(-1);
		if(sfmove(in, tmp, SF_UNBOUND, -1) < 0 || !sfeof(in) || sferror(tmp))
			return(-1);
		in = tmp;
		start=0;
	}
	if((offset = sfseek(in,(off_t)0,SEEK_END)) <= start)
		return(0);
	offset = rounddown(offset,BUFSIZE);
	while(1)
	{
		n = BUFSIZE;
		if(offset < start)
		{
			n -= (start-offset);
			offset = start;
		}
		sfseek(in, offset, SEEK_SET);
		if((n=sfread(in, buff, n)) <=0)
			break;
		cp = buff+n;
		n = *buff;
		*buff = '\n';
		while(1)
		{
			cpold = cp;
			if(nleft==0)
				cp--;
			if(cp==buff)
			{
				nleft= 1;
				break;
			}
			while(*--cp != '\n');
			if(cp==buff && n!='\n')
			{
				*cp = n;
				nleft += cpold-cp;
				break;
			}
			else
				cp++;
			if(sfwrite(out,cp,cpold-cp) < 0)
				return(-1);
			if(nleft)
			{
				if(nleft==1)
					sfputc(out,'\n');
				else if(sfmove(in,out,nleft,-1) != nleft)
					return(-1);
				nleft = 0;
			}
		}
		if(offset <= start)
			break;
		offset -= BUFSIZE;
	}
	if(nleft)
	{
		sfseek(in, start, SEEK_SET);
		if(sfmove(in,out,nleft,-1) != nleft)
			return(-1);
	}
	return(0);
}
