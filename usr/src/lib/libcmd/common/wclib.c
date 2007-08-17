/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*           Copyright (c) 1992-2007 AT&T Knowledge Ventures            *
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
*                 Glenn Fowler <gsf@research.att.com>                  *
*                  David Korn <dgk@research.att.com>                   *
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * David Korn
 * AT&T Bell Laboratories
 *
 * library interface for word count
 */

#include <cmd.h>
#include <wc.h>
#include <ctype.h>

#if _hdr_wchar && _hdr_wctype

#include <wchar.h>
#include <wctype.h>

#else

#ifndef iswspace
#define iswspace(x)	isspace(x)
#endif

#endif

#define endline(c)	(((signed char)-1)<0?(c)<0:(c)==((char)-1))
#define mbok(p,n)	(((n)<1)?0:mbwide()?((*ast.mb_towc)(NiL,(char*)(p),n)>=0):1)

Wc_t *wc_init(int mode)
{
	register int	n;
	register int	w;
	Wc_t*		wp;

	if(!(wp = (Wc_t*)stakalloc(sizeof(Wc_t))))
		return(0);
	wp->mode = mode;
	w = mode & WC_WORDS;
	for(n=(1<<CHAR_BIT);--n >=0;)
		wp->space[n] = w ? !!isspace(n) : 0;
	wp->space['\n'] = -1;
	return(wp);
}

/*
 * compute the line, word, and character count for file <fd>
 */
int wc_count(Wc_t *wp, Sfio_t *fd, const char* file)
{
	register signed char	*space = wp->space;
	register unsigned char	*cp;
	register Sfoff_t	nchars;
	register Sfoff_t	nwords;
	register Sfoff_t	nlines;
	register Sfoff_t	eline;
	register Sfoff_t	longest;
	register ssize_t	c;
	register unsigned char	*endbuff;
	register int		lasttype = 1;
	unsigned int		lastchar;
	unsigned char		*buff;
	wchar_t			x;

	sfset(fd,SF_WRITE,1);
	nlines = nwords = nchars = 0;
	wp->longest = 0;
	if (wp->mode & (WC_LONGEST|WC_MBYTE))
	{
		longest = 0;
		eline = -1;
		cp = buff = endbuff = 0;
		for (;;)
		{
			if (!mbok(cp, endbuff-cp))
			{
				if (buff)
					sfread(fd, buff, cp-buff);
				if (!(buff = (unsigned char*)sfreserve(fd, SF_UNBOUND, SF_LOCKR)))
					break;
				endbuff = (cp = buff) + sfvalue(fd);
			}
			nchars++;
			x = mbchar(cp);
			if (x == -1)
			{
				if (eline != nlines && !(wp->mode & WC_QUIET))
				{
					error_info.file = (char*)file;
					error_info.line = eline = nlines;
					error(ERROR_SYSTEM|1, "invalid multibyte character");
					error_info.file = 0;
					error_info.line = 0;
				}
			}
			else if (x == '\n')
			{
				if ((nchars - longest) > wp->longest)
					wp->longest = nchars - longest;
				longest = nchars;
				nlines++;
				lasttype = 1;
			}
			else if (iswspace(x))
				lasttype = 1;
			else if (lasttype)
			{
				lasttype = 0;
				nwords++;
			}
		}
	}
	else
	{
		for (;;)
		{
			/* fill next buffer and check for end-of-file */
			if (!(buff = (unsigned char*)sfreserve(fd, 0, 0)) || (c = sfvalue(fd)) <= 0)
				break;
			sfread(fd,(char*)(cp=buff),c);
			nchars += c;
			/* check to see whether first character terminates word */
			if(c==1)
			{
				if(endline(lasttype))
					nlines++;
				if((c = space[*cp]) && !lasttype)
					nwords++;
				lasttype = c;
				continue;
			}
			if(!lasttype && space[*cp])
				nwords++;
			lastchar = cp[--c];
			cp[c] = '\n';
			endbuff = cp+c;
			c = lasttype;
			/* process each buffer */
			for (;;)
			{
				/* process spaces and new-lines */
				do if (endline(c))
				{
					for (;;)
					{
						/* check for end of buffer */
						if (cp > endbuff)
							goto eob;
						nlines++;
						if (*cp != '\n')
							break;
						cp++;
					}
				} while (c = space[*cp++]);
				/* skip over word characters */
				while(!(c = space[*cp++]));
				nwords++;
			}
		eob:
			if((cp -= 2) >= buff)
				c = space[*cp];
			else
				c  = lasttype;
			lasttype = space[lastchar];
			/* see if was in word */
			if(!c && !lasttype)
				nwords--;
		}
		if(endline(lasttype))
			nlines++;
		else if(!lasttype)
			nwords++;
	}
	wp->chars = nchars;
	wp->words = nwords;
	wp->lines = nlines;
	return(0);
}
