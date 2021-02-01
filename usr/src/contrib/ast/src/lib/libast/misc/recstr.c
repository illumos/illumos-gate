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
 * return the record format descriptor given a format string
 * e!=0 set to the first unrecognized char after the format
 * REC_N_TYPE() returned on error
 *
 *	d[0xNN|delimiter] (delimited, newline default)
 *	[f][+]size (fixed length)
 *	v hN oN zN b|l i|n (variable length with size header)
 *	  h   header size in bytes (ibm V 4)
 *	  o   size offset in bytes (ibm V 0)
 *	  z   size length in bytes (ibm V 2)
 *	  l|b little-endian or big-endian size (ibm V b (0))
 *	  i|n header included/not-included in size (ibm V i (1))
 */

#include <recfmt.h>
#include <ctype.h>

Recfmt_t
recstr(register const char* s, char** e)
{
	char*	t;
	int	n;
	long	v;
	int	a[6];

	while (*s == ' ' || *s == '\t' || *s == ',')
		s++;
	switch (*s)
	{
	case 'd':
	case 'D':
		if (!*++s)
			n = '\n';
		else
		{
			if (*s == '0' && (*(s + 1) == 'x' || *(s + 1) == 'X'))
				n = (int)strtol(s, &t, 0);
			else
				n = chresc(s, &t);
			s = (const char*)t;
		}
		if (e)
			*e = (char*)s;
		return REC_D_TYPE(n);
	case 'f':
	case 'F':
		while (*++s == ' ' || *s == '\t' || *s == ',');
		/*FALLTHROUGH*/
	case '+':
	case '0': case '1': case '2': case '3': case '4':
	case '5': case '6': case '7': case '8': case '9':
		n = strton(s, &t, NiL, 0);
		if (n > 0 && t > (char*)s)
		{
			if (e)
				*e = t;
			return REC_F_TYPE(n);
		}
		break;
	case 'm':
	case 'M':
		while (*++s == ' ' || *s == '\t' || *s == ',');
		for (t = (char*)s; *t && *t != ' ' && *t != '\t' && *t != ','; t++);
		if ((t - s) == 4)
		{
			if (strneq(s, "data", 4))
			{
				if (e)
					*e = t;
				return REC_M_TYPE(REC_M_data);
			}
			else if (strneq(s, "path", 4))
			{
				if (e)
					*e = t;
				return REC_M_TYPE(REC_M_path);
			}
		}

		/*
		 * TBD: look up name in method libraries
		 *	and assign an integer index
		 */

		break;
	case 'u':
	case 'U':
		while (*++s == ' ' || *s == '\t' || *s == ',');
		n = strtol(s, &t, 0);
		if (n < 0 || n > 15 || *t++ != '.')
			break;
		v = strtol(t, &t, 0);
		if (*t)
			break;
		if (e)
			*e = t;
		return REC_U_TYPE(n, v);
	case 'v':
	case 'V':
		a[0] = 0;
		a[1] = 4;
		a[2] = 0;
		a[3] = 2;
		a[4] = 0;
		a[5] = 1;
		n = 0;
		for (;;)
		{
			switch (*++s)
			{
			case 0:
				break;
			case 'm':
			case 'M':
				n = 0;
				continue;
			case 'h':
			case 'H':
				n = 1;
				continue;
			case 'o':
			case 'O':
				n = 2;
				continue;
			case 'z':
			case 'Z':
				n = 3;
				continue;
			case 'b':
			case 'B':
				n = 4;
				a[n++] = 0;
				continue;
			case 'l':
			case 'L':
				n = 4;
				a[n++] = 1;
				continue;
			case 'n':
			case 'N':
				n = 0;
				a[5] = 0;
				continue;
			case 'i':
			case 'I':
				n = 0;
				a[5] = 1;
				continue;
			case ' ':
			case '\t':
			case ',':
			case '-':
			case '+':
				continue;
			case '0': case '1': case '2': case '3': case '4':
			case '5': case '6': case '7': case '8': case '9':
				v = 0;
				a[n++] = strtol(s, &t, 0);
				s = (const char*)t - 1;
				continue;
			}
			break;
		}
		if (e)
			*e = (char*)s;
		if (a[3] > (a[1] - a[2]))
			a[3] = a[1] - a[2];
		return REC_V_RECORD(REC_V_TYPE(a[1], a[2], a[3], a[4], a[5]), a[0]);
	case '%':
		if (e)
			*e = (char*)s + 1;
		return REC_M_TYPE(REC_M_path);
	case '-':
	case '?':
		if (e)
			*e = (char*)s + 1;
		return REC_M_TYPE(REC_M_data);
	}
	if (e)
		*e = (char*)s;
	return REC_N_TYPE();
}
