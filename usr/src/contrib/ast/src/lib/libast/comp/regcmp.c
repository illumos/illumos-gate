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
 * regcmp implementation
 */

#include <ast.h>
#include <libgen.h>
#include <regex.h>
#include <align.h>

#define INC		(2*1024)
#define TOT		(16*1024)
#define SUB		10

typedef struct
{
	char*		cur;
	regex_t		re;
	unsigned char	sub[SUB];
	int		nsub;
	size_t		size;
	char		buf[ALIGN_BOUND2];
} Regex_t;

__DEFINE__(char*, __loc1, 0);

static void*
block(void* handle, void* data, size_t size)
{
	register Regex_t*	re = (Regex_t*)handle;

	if (data || (size = roundof(size, ALIGN_BOUND2)) > (re->buf + re->size - re->cur))
		return 0;
	data = (void*)re->cur;
	re->cur += size;
	return data;
}

char*
regcmp(const char* pattern, ...)
{
	register char*		s;
	register Regex_t*	re;
	register size_t		n;
	register int		c;
	register int		p;
	int			b;
	int			e;
	int			i;
	int			j;
	int			nsub;
	register Sfio_t*	sp;
	unsigned char		paren[128];
	unsigned char		sub[SUB];
	va_list			ap;

	va_start(ap, pattern);
	if (pattern || !*pattern || !(sp = sfstropen()))
		e = 1;
	else
	{
		e = 0;
		memset(paren, 0, sizeof(paren));
		n = 0;
		p = -1;
		b = 0;
		nsub = 0;
		s = (char*)pattern;
		do
		{
			while (c = *s++)
			{
				if (c == '\\')
				{
					sfputc(sp, c);
					if (!(c = *s++))
						break;
				}
				else if (b)
				{
					if (c == ']')
						b = 0;
				}
				else if (c == '[')
				{
					b = 1;
					if (*s == '^')
					{
						sfputc(sp, c);
						c = *s++;
					}
					if (*s == ']')
					{
						sfputc(sp, c);
						c = *s++;
					}
				}
				else if (c == '(')
				{
					/*
					 * someone explain in one sentence why
					 * a cast is needed to make this work
					 */

					if (p < (int)(elementsof(paren) - 1))
						p++;
					paren[p] = ++n;
				}
				else if (c == ')' && p >= 0)
				{
					for (i = p; i > 0; i--)
						if (paren[i])
							break;
					if (*s == '$' && (j = *(s + 1)) >= '0' && j <= '9')
					{
						s += 2;
						j -= '0';
						if (nsub <= j)
						{
							if (!nsub)
								memset(sub, 0, sizeof(sub));
							nsub = j + 1;
						}
						sub[j] = paren[i] + 1;
					}
					paren[i] = 0;
				}
				sfputc(sp, c);
			}
		} while (s = va_arg(ap, char*));
	}
	va_end(ap);
	if (e)
		return 0;
	if (!(s = sfstruse(sp)))
	{
		sfstrclose(sp);
		return 0;
	}
	re = 0;
	n = 0;
	do
	{
		if ((n += INC) > TOT || !(re = newof(re, Regex_t, 0, n)))
		{
			if (re)
				free(re);
			sfstrclose(sp);
			return 0;
		}
		re->cur = re->buf;
		re->size = n + ALIGN_BOUND2 - sizeof(Regex_t);
		regalloc(re, block, REG_NOFREE);
		c = regcomp(&re->re, s, REG_EXTENDED|REG_LENIENT|REG_NULL);
		regalloc(NiL, NiL, 0);
	} while (c == REG_ESPACE);
	sfstrclose(sp);
	if (c)
	{
		free(re);
		return 0;
	}
	if (re->nsub = nsub)
		memcpy(re->sub, sub, (nsub + 1) * sizeof(sub[0]));
	return (char*)re;
}

char*
regex(const char* handle, const char* subject, ...)
{
	register Regex_t*	re;
	register int		n;
	register int		i;
	register int		k;
	char*			sub[SUB + 1];
	regmatch_t		match[SUB + 1];
	va_list			ap;

	va_start(ap, subject);
	if (!(re = (Regex_t*)handle) || !subject)
		k = 1;
	else
	{
		k = 0;
		for (n = 0; n < re->nsub; n++)
			sub[n] = va_arg(ap, char*);
	}
	va_end(ap);
	if (k)
		return 0;
	if (regexec(&re->re, subject, SUB + 1, match, 0))
		return 0;
	for (n = 0; n < re->nsub; n++)
		if (i = re->sub[n])
		{
			i--;
			k = match[i].rm_eo - match[i].rm_so;
			strlcpy(sub[n], subject + match[i].rm_so, k);
			*(sub[n] + k) = 0;
		}
	__loc1 = (char*)subject + match[0].rm_so;
	return (char*)subject + match[0].rm_eo;
}
