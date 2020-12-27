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
 * Glenn Fowler
 * AT&T Research
 *
 * return string with expanded escape chars
 */

#include <ast.h>
#include <ccode.h>
#include <ctype.h>
#if _hdr_wchar && _hdr_wctype
#include <wchar.h>
#include <wctype.h>
#endif

/*
 * quote string as of length n with qb...qe
 * (flags&FMT_ALWAYS) always quotes, otherwise quote output only if necessary
 * qe and the usual suspects are \... escaped
 * (flags&FMT_WIDE) doesn't escape 8 bit chars
 * (flags&FMT_ESCAPED) doesn't \... escape the usual suspects
 * (flags&FMT_SHELL) escape $`"#;~&|()<>[]*?
 */

char*
fmtquote(const char* as, const char* qb, const char* qe, size_t n, int flags)
{
	register unsigned char*	s = (unsigned char*)as;
	register unsigned char*	e = s + n;
	register char*		b;
	register int		c;
	register int		m;
	register int		escaped;
	register int		spaced;
	register int		doublequote;
	register int		singlequote;
	int			shell;
	char*			f;
	char*			buf;

	c = 4 * (n + 1);
	if (qb)
		c += strlen((char*)qb);
	if (qe)
		c += strlen((char*)qe);
	b = buf = fmtbuf(c);
	shell = 0;
	doublequote = 0;
	singlequote = 0;
	if (qb)
	{
		if (qb[0] == '$' && qb[1] == '\'' && qb[2] == 0)
			shell = 1;
		else if ((flags & FMT_SHELL) && qb[1] == 0)
		{
			if (qb[0] == '"')
				doublequote = 1;
			else if (qb[0] == '\'')
				singlequote = 1;
		}
		while (*b = *qb++)
			b++;
	}
	else if (flags & FMT_SHELL)
		doublequote = 1;
	f = b;
	escaped = spaced = !!(flags & FMT_ALWAYS);
	while (s < e)
	{
		if ((m = mbsize(s)) > 1 && (s + m) <= e)
		{
#if _hdr_wchar && _hdr_wctype
			c = mbchar(s);
			if (!spaced && !escaped && (iswspace(c) || iswcntrl(c)))
				spaced = 1;
			s -= m;
#endif
			while (m--)
				*b++ = *s++;
		}
		else
		{
			c = *s++;
			if (!(flags & FMT_ESCAPED) && (iscntrl(c) || !isprint(c) || c == '\\'))
			{
				escaped = 1;
				*b++ = '\\';
				switch (c)
				{
				case CC_bel:
					c = 'a';
					break;
				case '\b':
					c = 'b';
					break;
				case '\f':
					c = 'f';
					break;
				case '\n':
					c = 'n';
					break;
				case '\r':
					c = 'r';
					break;
				case '\t':
					c = 't';
					break;
				case CC_vt:
					c = 'v';
					break;
				case CC_esc:
					c = 'E';
					break;
				case '\\':
					break;
				default:
					if (!(flags & FMT_WIDE) || !(c & 0200))
					{
						*b++ = '0' + ((c >> 6) & 07);
						*b++ = '0' + ((c >> 3) & 07);
						c = '0' + (c & 07);
					}
					else
						b--;
					break;
				}
			}
			else if (c == '\\')
			{
				escaped = 1;
				*b++ = c;
				if (*s)
					c = *s++;
			}
			else if (qe && strchr(qe, c))
			{
				if (singlequote && c == '\'')
				{
					spaced = 1;
					*b++ = '\'';
					*b++ = '\\';
					*b++ = '\'';
					c = '\'';
				}
				else
				{
					escaped = 1;
					*b++ = '\\';
				}
			}
			else if (c == '$' || c == '`')
			{
				if (c == '$' && (flags & FMT_PARAM) && (*s == '{' || *s == '('))
				{
					if (singlequote || shell)
					{
						escaped = 1;
						*b++ = '\'';
						*b++ = c;
						*b++ = *s++;
						if (shell)
						{
							spaced = 1;
							*b++ = '$';
						}
						c = '\'';
					}
					else
					{
						escaped = 1;
						*b++ = c;
						c = *s++;
					}
				}
				else if (doublequote)
					*b++ = '\\';
				else if (singlequote || (flags & FMT_SHELL))
					spaced = 1;
			}
			else if (!spaced && !escaped && (isspace(c) || ((flags & FMT_SHELL) || shell) && (strchr("\";~&|()<>[]*?", c) || c == '#' && (b == f || isspace(*(b - 1))))))
				spaced = 1;
			*b++ = c;
		}
	}
	if (qb)
	{
		if (!escaped)
			buf += shell + !spaced;
		if (qe && (escaped || spaced))
			while (*b = *qe++)
				b++;
	}
	*b = 0;
	return buf;
}

/*
 * escape the usual suspects and quote chars in qs
 * in length n string as
 */

char*
fmtnesq(const char* as, const char* qs, size_t n)
{
	return fmtquote(as, NiL, qs, n, 0);
}

/*
 * escape the usual suspects and quote chars in qs
 */

char*
fmtesq(const char* as, const char* qs)
{
	return fmtquote(as, NiL, qs, strlen((char*)as), 0);
}

/*
 * escape the usual suspects
 */

char*
fmtesc(const char* as)
{
	return fmtquote(as, NiL, NiL, strlen((char*)as), 0);
}
