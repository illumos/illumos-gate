/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1986-2008 AT&T Intellectual Property          *
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
*                 Glenn Fowler <gsf@research.att.com>                  *
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * cpp predefined symbol detection support
 *
 * with no args stdin is treated as an a.out for
 * a Reiser derived cpp -- all strings that may
 * be identifiers are listed on fd 3 (1 if no 3)
 *
 * with args the -D argument values are listed on fd 3 (1 if no 3)
 */

#include <ast.h>
#include <ctype.h>

int
main(int argc, char** argv)
{
	register int	state;
	register int	c;
	register char*	s;
	Sfio_t*		out;

	NoP(argc);
	if (dup(3) < 0 || !(out = sfnew(NiL, NiL, -1, 3, SF_WRITE)))
		out = sfstdout;
	if (*++argv)
	{
		while (s = *argv++)
			if (*s++ == '-' && *s++ == 'D' && isalpha(*s))
			{
				while (*s && *s != '=') sfputc(out, *s++);
				sfputc(out, '\n');
			}
		return 0;
	}
	state = 0;
	for (;;)
	{
		switch (c = sfgetc(sfstdin))
		{
		case EOF:
			break;
		case 'a': case 'b': case 'c': case 'd': case 'e': case 'f': 
		case 'g': case 'h': case 'i': case 'j': case 'k': case 'l': 
		case 'm': case 'n': case 'o': case 'p': case 'q': case 'r': 
		case 's': case 't': case 'u': case 'v': case 'w': case 'x':
		case 'y': case 'z': case '_':
		case 'A': case 'B': case 'C': case 'D': case 'E': case 'F': 
		case 'G': case 'H': case 'I': case 'J': case 'K': case 'L': 
		case 'M': case 'N': case 'O': case 'P': case 'Q': case 'R': 
		case 'S': case 'T': case 'U': case 'V': case 'W': case 'X':
		case 'Y': case 'Z': 
			state++;
			sfputc(out, c);
			continue;
		case '0': case '1': case '2': case '3': case '4': case '5': 
		case '6': case '7': case '8': case '9':
			if (state)
			{
				sfputc(out, c);
				continue;
			}
			/*FALLTHROUGH*/
		default:
			if (state)
			{
				sfputc(out, '\n');
				state = 0;
			}
			continue;
		}
		break;
	}
	return 0;
}
