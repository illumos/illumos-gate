/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2008 AT&T Intellectual Property          *
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
*                  David Korn <dgk@research.att.com>                   *
*                   Phong Vo <kpv@research.att.com>                    *
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * Glenn Fowler
 * AT&T Research
 *
 * Time_t conversion support
 */

#include <tmx.h>
#include <ctype.h>

#define warped(t,n)	((t)<((n)-tmxsns(6L*30L*24L*60L*60L,0))||(t)>((n)+tmxsns(24L*60L*60L,0)))

/*
 * format n with padding p into s
 * return end of s
 *
 * p:	<0	blank padding
 *	 0	no padding
 *	>0	0 padding
 */

static char*
number(register char* s, register char* e, register long n, register int p, int w, int pad)
{
	char*	b;

	if (w)
	{
		if (p > 0 && (pad == 0 || pad == '0'))
			while (w > p)
			{
				p++;
				n *= 10;
			}
		else if (w > p)
			p = w;
	}
	switch (pad)
	{
	case '-':
		p = 0;
		break;
	case '_':
		if (p > 0)
			p = -p;
		break;
	case '0':
		if (p < 0)
			p = -p;
		break;
	}
	b = s;
	if (p > 0)
		s += sfsprintf(s, e - s, "%0*lu", p, n);
	else if (p < 0)
		s += sfsprintf(s, e - s, "%*lu", -p, n);
	else
		s += sfsprintf(s, e - s, "%lu", n);
	if (w && (s - b) > w)
		*(s = b + w) = 0;
	return s;
}

typedef struct Stack_s
{
	char*		format;
	int		delimiter;
} Stack_t;

/*
 * format t into buf of length len
 * end of buf is returned
 */

char*
tmxfmt(char* buf, size_t len, const char* format, Time_t t)
{
	register char*	cp;
	register char*	ep;
	register char*	p;
	register int	n;
	int		c;
	int		i;
	int		flags;
	int		pad;
	int		delimiter;
	int		width;
	int		prec;
	int		parts;
	char*		f;
	const char*	oformat;
	Tm_t*		tp;
	Tm_zone_t*	zp;
	Time_t		now;
	Stack_t*	sp;
	Stack_t		stack[8];
	char		fmt[32];

	tmlocale();
	tp = tmxmake(t);
	if (!format || !*format)
		format = tm_info.deformat;
	oformat = format;
	flags = tm_info.flags;
	sp = &stack[0];
	cp = buf;
	ep = buf + len;
	delimiter = 0;
	for (;;)
	{
		if ((c = *format++) == delimiter)
		{
			delimiter = 0;
			if (sp <= &stack[0])
				break;
			sp--;
			format = sp->format;
			delimiter = sp->delimiter;
			continue;
		}
		if (c != '%')
		{
			if (cp < ep)
				*cp++ = c;
			continue;
		}
		pad = 0;
		width = 0;
		prec = 0;
		parts = 0;
		for (;;)
		{
			switch (c = *format++)
			{
			case '_':
			case '-':
				pad = c;
				continue;
			case 'E':
			case 'O':
				if (!isalpha(*format))
					break;
				continue;
			case '0':
				if (!parts)
				{
					pad = c;
					continue;
				}
				/*FALLTHROUGH*/
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
				switch (parts)
				{
				case 0:
					parts++;
					/*FALLTHROUGH*/
				case 1:
					width = width * 10 + (c - '0');
					break;
				case 2:
					prec = prec * 10 + (c - '0');
					break;
				}
				continue;
			case '.':
				if (!parts++)
					parts++;
				continue;
			default:
				break;
			}
			break;
		}
		switch (c)
		{
		case 0:
			format--;
			continue;
		case '%':
			if (cp < ep)
				*cp++ = '%';
			continue;
		case '?':
			if (tm_info.deformat != tm_info.format[TM_DEFAULT])
				format = tm_info.deformat;
			else if (!*format)
				format = tm_info.format[TM_DEFAULT];
			continue;
		case 'a':	/* abbreviated day of week name */
			n = TM_DAY_ABBREV + tp->tm_wday;
			goto index;
		case 'A':	/* day of week name */
			n = TM_DAY + tp->tm_wday;
			goto index;
		case 'b':	/* abbreviated month name */
		case 'h':
			n = TM_MONTH_ABBREV + tp->tm_mon;
			goto index;
		case 'B':	/* month name */
			n = TM_MONTH + tp->tm_mon;
			goto index;
		case 'c':	/* `ctime(3)' date sans newline */
			p = tm_info.format[TM_CTIME];
			goto push;
		case 'C':	/* 2 digit century */
			cp = number(cp, ep, (long)(1900 + tp->tm_year) / 100, 2, width, pad);
			continue;
		case 'd':	/* day of month */
			cp = number(cp, ep, (long)tp->tm_mday, 2, width, pad);
			continue;
		case 'D':	/* date */
			p = tm_info.format[TM_DATE];
			goto push;
		case 'E':       /* OBSOLETE no pad day of month */
			cp = number(cp, ep, (long)tp->tm_mday, 0, width, pad);
			continue;
		case 'e':       /* blank padded day of month */
			cp = number(cp, ep, (long)tp->tm_mday, -2, width, pad);
			continue;
		case 'f':	/* TM_DEFAULT override */
		case 'o':	/* OBSOLETE */
			p = tm_info.deformat;
			goto push;
		case 'F':	/* ISO 8601:2000 standard date format */
			p = "%Y-%m-%d";
			goto push;
		case 'g':	/* %V 2 digit year */
		case 'G':	/* %V 4 digit year */
			n = tp->tm_year + 1900;
			if (tp->tm_yday < 7)
			{
				if (tmweek(tp, 2, -1, -1) >= 52)
					n--;
			}
			else if (tp->tm_yday > 358)
			{
				if (tmweek(tp, 2, -1, -1) <= 1)
					n++;
			}
			if (c == 'g')
			{
				n %= 100;
				c = 2;
			}
			else
				c = 4;
			cp = number(cp, ep, (long)n, c, width, pad);
			continue;
		case 'H':	/* hour (0 - 23) */
			cp = number(cp, ep, (long)tp->tm_hour, 2, width, pad);
			continue;
		case 'i':	/* international `date(1)' date */
			p = tm_info.format[TM_INTERNATIONAL];
			goto push;
		case 'I':	/* hour (0 - 12) */
			if ((n = tp->tm_hour) > 12) n -= 12;
			else if (n == 0) n = 12;
			cp = number(cp, ep, (long)n, 2, width, pad);
			continue;
		case 'J':	/* Julian date (0 offset) */
			cp = number(cp, ep, (long)tp->tm_yday, 3, width, pad);
			continue;
		case 'j':	/* Julian date (1 offset) */
			cp = number(cp, ep, (long)(tp->tm_yday + 1), 3, width, pad);
			continue;
		case 'k':	/* `date(1)' date */
			p = tm_info.format[TM_DATE_1];
			goto push;
		case 'K':
			p = "%Y-%m-%d+%H:%M:%S";
			goto push;
		case 'l':	/* `ls -l' date */
			if (t)
			{
				now = tmxgettime();
				if (warped(t, now))
				{
					p = tm_info.format[TM_DISTANT];
					goto push;
				}
			}
			p = tm_info.format[TM_RECENT];
			goto push;
		case 'L':	/* TM_DEFAULT */
		case 'O':	/* OBSOLETE */
			p = tm_info.format[TM_DEFAULT];
			goto push;
		case 'm':	/* month number */
			cp = number(cp, ep, (long)(tp->tm_mon + 1), 2, width, pad);
			continue;
		case 'M':	/* minutes */
			cp = number(cp, ep, (long)tp->tm_min, 2, width, pad);
			continue;
		case 'n':
			if (cp < ep)
				*cp++ = '\n';
			continue;
		case 'N':	/* nanosecond part */
			cp = number(cp, ep, (long)tp->tm_nsec, 9, width, pad);
			continue;
		case 'p':	/* meridian */
			n = TM_MERIDIAN + (tp->tm_hour >= 12);
			goto index;
		case 'q':	/* time zone type (nation code) */
			if (!(flags & TM_UTC))
			{
				if ((zp = tm_info.zone) != tm_info.local)
					for (; zp >= tm_data.zone; zp--)
						if (p = zp->type)
							goto string;
				else if (p = zp->type)
					goto string;
			}
			continue;
		case 'Q':	/* %Q<alpha> or %Q<delim>recent<delim>distant<delim> */
			if (c = *format)
			{
				format++;
				if (isalpha(c))
				{
					switch (c)
					{
					case 'd':	/* `ls -l' distant date */
						p = tm_info.format[TM_DISTANT];
						goto push;
					case 'r':	/* `ls -l' recent date */
						p = tm_info.format[TM_RECENT];
						goto push;
					default:
						format--;
						break;
					}
				}
				else
				{
					if (t)
					{
						now = tmxgettime();
						p = warped(t, now) ? (char*)0 : (char*)format;
					}
					else
						p = (char*)format;
					i = 0;
					while (n = *format)
					{
						format++;
						if (n == c)
						{
							if (!p)
								p = (char*)format;
							if (++i == 2)
								goto push_delimiter;
						}
					}
				}
			}
			continue;
		case 'r':
			p = tm_info.format[TM_MERIDIAN_TIME];
			goto push;
		case 'R':
			p = "%H:%M";
			goto push;
		case 's':	/* seconds[.nanoseconds] since the epoch */
		case '#':
			if (t)
				now = t;
			else
				now = tmxgettime();
			f = fmt;
			*f++ = '%';
			if (pad == '0')
				*f++ = pad;
			if (width)
				f += sfsprintf(f, &fmt[sizeof(fmt)] - f, "%d", width);
			f += sfsprintf(f, &fmt[sizeof(fmt)] - f, "I%du", sizeof(Tmxsec_t));
			cp += sfsprintf(cp, ep - cp, fmt, tmxsec(now));
			if (parts > 1)
			{
				n = sfsprintf(cp, ep - cp, ".%09I*u", sizeof(Tmxnsec_t), tmxnsec(now));
				if (prec && n >= prec)
					n = prec + 1;
				cp += n;
			}
			continue;
		case 'S':	/* seconds */
			cp = number(cp, ep, (long)tp->tm_sec, 2, width, pad);
			if ((flags & TM_SUBSECOND) && (format - 2) != oformat)
			{
				p = ".%N";
				goto push;
			}
			continue;
		case 't':
			if (cp < ep)
				*cp++ = '\t';
			continue;
		case 'T':
			p = tm_info.format[TM_TIME];
			goto push;
		case 'u':	/* weekday number [1(Monday)-7] */
			if (!(i = tp->tm_wday))
				i = 7;
			cp = number(cp, ep, (long)i, 0, width, pad);
			continue;
		case 'U':	/* week number, Sunday as first day */
			cp = number(cp, ep, (long)tmweek(tp, 0, -1, -1), 2, width, pad);
			continue;
		case 'V':	/* ISO week number */
			cp = number(cp, ep, (long)tmweek(tp, 2, -1, -1), 2, width, pad);
			continue;
		case 'W':	/* week number, Monday as first day */
			cp = number(cp, ep, (long)tmweek(tp, 1, -1, -1), 2, width, pad);
			continue;
		case 'w':	/* weekday number [0(Sunday)-6] */
			cp = number(cp, ep, (long)tp->tm_wday, 0, width, pad);
			continue;
		case 'x':
			p = tm_info.format[TM_DATE];
			goto push;
		case 'X':
			p = tm_info.format[TM_TIME];
			goto push;
		case 'y':	/* year in the form yy */
			cp = number(cp, ep, (long)(tp->tm_year % 100), 2, width, pad);
			continue;
		case 'Y':	/* year in the form ccyy */
			cp = number(cp, ep, (long)(1900 + tp->tm_year), 4, width, pad);
			continue;
		case 'z':	/* time zone west offset */
			if ((ep - cp) >= 16)
				cp = tmpoff(cp, ep - cp, "", (flags & TM_UTC) ? 0 : tm_info.zone->west - (tp->tm_isdst ? 60 : 0), 24 * 60);
			continue;
		case 'Z':	/* time zone */
			p = (flags & TM_UTC) ? tm_info.format[TM_UT] : tp->tm_isdst && tm_info.zone->daylight ? tm_info.zone->daylight : tm_info.zone->standard;
			goto string;
		case '+':	/* old %+flag */
		case '!':	/* old %!flag */
			format--;
			/*FALLTHROUGH*/
		case '=':	/* %=[=][+-]flag */
			if (i = *format == '=')
				format++;
			if (*format == '+' || *format == '-' || *format == '!')
				c = *format++;
			else
				c = '+';
			switch (*format++)
			{
			case 0:
				format--;
				continue;
			case 'l':
				n = TM_LEAP;
				break;
			case 'n':
			case 's':
				n = TM_SUBSECOND;
				break;
			case 'u':
				n = TM_UTC;
				break;
			}
			if (n)
			{
				/*
				 * right, the global state stinks
				 * but we respect its locale-like status
				 */

				if (c == '+')
				{
					if (!(flags & n))
					{
						flags |= n;
						tm_info.flags |= n;
						tp = tmxmake(t);
						if (!i)
							tm_info.flags &= ~n;
					}
				}
				else if (flags & n)
				{
					flags &= ~n;
					tm_info.flags &= ~n;
					tp = tmxmake(t);
					if (!i)
						tm_info.flags |= n;
				}
			}
			continue;
		default:
			if (cp < ep)
				*cp++ = '%';
			if (cp < ep)
				*cp++ = c;
			continue;
		}
	index:
		p = tm_info.format[n];
	string:
		while (cp < ep && (*cp = *p++))
			cp++;
		continue;
	push:
		c = 0;
	push_delimiter:
		if (sp < &stack[elementsof(stack)])
		{
			sp->format = (char*)format;
			format = p;
			sp->delimiter = delimiter;
			delimiter = c;
			sp++;
		}
		continue;
	}
	tm_info.flags = flags;
	if (cp >= ep)
		cp = ep - 1;
	*cp = 0;
	return cp;
}
