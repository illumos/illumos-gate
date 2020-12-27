/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2012 AT&T Intellectual Property          *
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
 * Time_t conversion support
 *
 * relative times inspired by Steve Bellovin's netnews getdate(3)
 */

#include <tmx.h>
#include <ctype.h>
#include <debug.h>

#define dig1(s,n)	((n)=((*(s)++)-'0'))
#define dig2(s,n)	((n)=((*(s)++)-'0')*10,(n)+=(*(s)++)-'0')
#define dig3(s,n)	((n)=((*(s)++)-'0')*100,(n)+=((*(s)++)-'0')*10,(n)+=(*(s)++)-'0')
#define dig4(s,n)	((n)=((*(s)++)-'0')*1000,(n)+=((*(s)++)-'0')*100,(n)+=((*(s)++)-'0')*10,(n)+=(*(s)++)-'0')

#undef	BREAK

#define BREAK		(1<<0)
#define CCYYMMDDHHMMSS	(1<<1)
#define CRON		(1<<2)
#define DAY		(1<<3)
#define EXACT		(1<<4)
#define FINAL		(1<<5)
#define HOLD		(1<<6)
#define HOUR		(1<<7)
#define LAST		(1<<8)
#define MDAY		(1<<9)
#define MINUTE		(1<<10)
#define MONTH		(1<<11)
#define NEXT		(1<<12)
#define NSEC		(1<<13)
#define ORDINAL		(1<<14)
#define SECOND		(1<<15)
#define THIS		(1L<<16)
#define WDAY		(1L<<17)
#define WORK		(1L<<18)
#define YEAR		(1L<<19)
#define ZONE		(1L<<20)

#define FFMT		"%s%s%s%s%s%s%s|"
#define	FLAGS(f)	(f&EXACT)?"|EXACT":"",(f&LAST)?"|LAST":"",(f&THIS)?"|THIS":"",(f&NEXT)?"|NEXT":"",(f&ORDINAL)?"|ORDINAL":"",(f&FINAL)?"|FINAL":"",(f&WORK)?"|WORK":""
/*
 * parse cron range into set
 * return: -1:error 0:* 1:some
 */

static int
range(register char* s, char** e, char* set, int lo, int hi)
{
	int	n;
	int	m;
	int	i;
	char*	t;

	while (isspace(*s) || *s == '_')
		s++;
	if (*s == '*')
	{
		*e = s + 1;
		return 0;
	}
	memset(set, 0, hi + 1);
	for (;;)
	{
		n = strtol(s, &t, 10);
		if (s == t || n < lo || n > hi)
			return -1;
		i = 1;
		if (*(s = t) == '-')
		{
			m = strtol(++s, &t, 10);
			if (s == t || m < n || m > hi)
				return -1;
			if (*(s = t) == '/')
			{
				i = strtol(++s, &t, 10);
				if (s == t || i < 1)
					return -1;
				s = t;
			}
		}
		else
			m = n;
		for (; n <= m; n += i)
			set[n] = 1;
		if (*s != ',')
			break;
		s++;
	}
	*e = s;
	return 1;
}

/*
 * normalize <p,q> to power of 10 u in tm
 */

static void
powerize(Tm_t* tm, unsigned long p, unsigned long q, unsigned long u)
{
	Time_t	t = p;

	while (q > u)
	{
		q /= 10;
		t /= 10;
	}
	while (q < u)
	{
		q *= 10;
		t *= 10;
	}
	tm->tm_nsec += (int)(t % TMX_RESOLUTION);
	tm->tm_sec += (int)(t / TMX_RESOLUTION);
}

#define K1(c1)			(c1)
#define K2(c1,c2)		(((c1)<<8)|(c2))
#define K3(c1,c2,c3)		(((c1)<<16)|((c2)<<8)|(c3))
#define K4(c1,c2,c3,c4)		(((c1)<<24)|((c2)<<16)|((c3)<<8)|(c4))

#define P_INIT(n)		w = n; p = q = 0; u = (char*)s + 1

/*
 * parse date expression in s and return Time_t value
 *
 * if non-null, e points to the first invalid sequence in s
 * now provides default values
 */

Time_t
tmxdate(register const char* s, char** e, Time_t now)
{
	register Tm_t*	tm;
	register long	n;
	register int	w;
	unsigned long	set;
	unsigned long	state;
	unsigned long	flags;
	Time_t		fix;
	char*		t;
	char*		u;
	const char*	o;
	const char*	x;
	char*		last;
	char*		type;
	int		day;
	int		dir;
	int		dst;
	int		zone;
	int		c;
	int		f;
	int		i;
	int		j;
	int		k;
	int		l;
	long		m;
	unsigned long	p;
	unsigned long	q;
	Tm_zone_t*	zp;
	Tm_t		ts;
	char		skip[UCHAR_MAX + 1];

	/*
	 * check DATEMSK first
	 */

	debug((error(-1, "AHA tmxdate 2009-03-06")));
	fix = tmxscan(s, &last, NiL, &t, now, 0);
	if (t && !*last)
	{
		if (e)
			*e = last;
		return fix;
	}
	o = s;

 reset:

	/*
	 * use now for defaults
	 */

	tm = tmxtm(&ts, now, NiL);
	tm_info.date = tm->tm_zone;
	day = -1;
	dir = 0;
	dst = TM_DST;
	set = state = 0;
	type = 0;
	zone = TM_LOCALZONE;
	skip[0] = 0;
	for (n = 1; n <= UCHAR_MAX; n++)
		skip[n] = isspace(n) || strchr("_,;@=|!^()[]{}", n);

	/*
	 * get <weekday year month day hour minutes seconds ?[ds]t [ap]m>
	 */

 again:
	for (;;)
	{
		state &= (state & HOLD) ? ~(HOLD) : ~(EXACT|LAST|NEXT|THIS);
		if ((set|state) & (YEAR|MONTH|DAY))
			skip['/'] = 1;
		message((-1, "AHA#%d state=" FFMT " set=" FFMT, __LINE__, FLAGS(state), FLAGS(set)));
		for (;;)
		{
			if (*s == '.' || *s == '-' || *s == '+')
			{
				if (((set|state) & (YEAR|MONTH|HOUR|MINUTE|ZONE)) == (YEAR|MONTH|HOUR|MINUTE) && (i = tmgoff(s, &t, TM_LOCALZONE)) != TM_LOCALZONE)
				{
					zone = i;
					state |= ZONE;
					if (!*(s = t))
						break;
				}
				else if (*s == '+')
					break;
			}
			else if (!skip[*s])
				break;
			s++;
		}
		if (!*(last = (char*)s))
			break;
		if (*s == '#')
		{
			if (isdigit(*++s))
			{
				now = strtoull(s, &t, 0);
			sns:
				if (*(s = t) == '.')
				{
					fix = 0;
					m = 1000000000;
					while (isdigit(*++s))
						fix += (*s - '0') * (m /= 10);
					now = tmxsns(now, fix);
				}
				else if (now <= 0x7fffffff)
					now = tmxsns(now, 0);
				goto reset;
			}
			else if (*s++ == '#')
			{
				now = tmxtime(tm, zone);
				goto reset;
			}
			break;
		}
		if ((*s == 'P' || *s == 'p') && (!isalpha(*(s + 1)) || (*(s + 1) == 'T' || *(s + 1) == 't') && !isalpha(*(s + 2))))
		{
			Tm_t	otm;

			/*
			 * iso duration
			 */

			otm = *tm;
			t = (char*)s;
			m = 0;
			P_INIT('Y');
			do
			{
				c = *++s;
			duration_next:
				switch (c)
				{
				case 0:
					m++;
					if ((char*)s > u)
					{
						s--;
						c = '_';
						goto duration_next;
					}
					break;
				case 'T':
				case 't':
					m++;
					if ((char*)s > u)
					{
						s++;
						c = 'D';
						goto duration_next;
					}
					continue;
				case 'Y':
				case 'y':
					m = 0;
					if (q > 1)
						tm->tm_sec += (365L*24L*60L*60L) * p / q;
					else
						tm->tm_year += p;
					P_INIT('M');
					continue;
				case 'm':
					if (!m)
						m = 1;
					/*FALLTHROUGH*/
				case 'M':
					switch (*(s + 1))
					{
					case 'I':
					case 'i':
						s++;
						m = 1;
						w = 'S';
						break;
					case 'O':
					case 'o':
						s++;
						m = 0;
						w = 'H';
						break;
					case 'S':
					case 's':
						s++;
						m = 2;
						w = 's';
						break;
					}
					switch (m)
					{
					case 0:
						m = 1;
						if (q > 1)
							tm->tm_sec += (3042L*24L*60L*60L) * p / q / 100L;
						else
							tm->tm_mon += p;
						break;
					case 1:
						m = 2;
						if (q > 1)
							tm->tm_sec += (60L) * p / q;
						else
							tm->tm_min += p;
						break;
					default:
						if (q > 1)
							powerize(tm, p, q, 1000UL);
						else
							tm->tm_nsec += p * 1000000L;
						break;
					}
					P_INIT(w);
					continue;
				case 'W':
				case 'w':
					m = 0;
					if (q > 1)
						tm->tm_sec += (7L*24L*60L*60L) * p / q;
					else
						tm->tm_mday += 7 * p;
					P_INIT('D');
					continue;
				case 'D':
				case 'd':
					m = 0;
					if (q > 1)
						tm->tm_sec += (24L*60L*60L) * p / q;
					else
						tm->tm_mday += p;
					P_INIT('H');
					continue;
				case 'H':
				case 'h':
					m = 1;
					if (q > 1)
						tm->tm_sec += (60L*60L) * p / q;
					else
						tm->tm_hour += p;
					P_INIT('m');
					continue;
				case 'S':
				case 's':
					m = 2;
					/*FALLTHROUGH*/
				case ' ':
				case '_':
				case '\n':
				case '\r':
				case '\t':
				case '\v':
					if (q > 1)
						powerize(tm, p, q, 1000000000UL);
					else
						tm->tm_sec += p;
					P_INIT('U');
					continue;
				case 'U':
				case 'u':
					switch (*(s + 1))
					{
					case 'S':
					case 's':
						s++;
						break;
					}
					m = 0;
					if (q > 1)
						powerize(tm, p, q, 1000000UL);
					else
						tm->tm_nsec += p * 1000L;
					P_INIT('N');
					continue;
				case 'N':
				case 'n':
					switch (*(s + 1))
					{
					case 'S':
					case 's':
						s++;
						break;
					}
					m = 0;
					if (q > 1)
						powerize(tm, p, q, 1000000000UL);
					else
						tm->tm_nsec += p;
					P_INIT('Y');
					continue;
				case '.':
					if (q)
						goto exact;
					q = 1;
					continue;
				case '-':
					c = 'M';
					u = (char*)s++;
					while (*++u && *u != ':')
						if (*u == '-')
						{
							c = 'Y';
							break;
						}
					goto duration_next;
				case ':':
					c = 'm';
					u = (char*)s++;
					while (*++u)
						if (*u == ':')
						{
							c = 'H';
							break;
						}
					goto duration_next;
				case '0':
				case '1':
				case '2':
				case '3':
				case '4':
				case '5':
				case '6':
				case '7':
				case '8':
				case '9':
					q *= 10;
					p = p * 10 + (c - '0');
					continue;
				default:
				exact:
					*tm = otm;
					s = (const char*)t + 1;
					if (*t == 'p')
					{
						state |= HOLD|EXACT;
						set &= ~(EXACT|LAST|NEXT|THIS);
						set |= state & (EXACT|LAST|NEXT|THIS);
					}
					goto again;
				}
				break;
			} while (c);
			continue;
		}
		f = -1;
		if (*s == '+')
		{
			while (isspace(*++s) || *s == '_');
			n = strtol(s, &t, 0);
			if (w = t - s)
			{
				for (s = t; skip[*s]; s++);
				state |= (f = n) ? NEXT : THIS;
				set &= ~(EXACT|LAST|NEXT|THIS);
				set |= state & (EXACT|LAST|NEXT|THIS);
			}
			else
				s = last;
		}
		if (!(state & CRON))
		{
			/*
			 * check for cron date
			 *
			 *	min hour day-of-month month day-of-week
			 *
			 * if it's cron then determine the next time
			 * that satisfies the specification
			 *
			 * NOTE: the only spacing is ' '||'_'||';'
			 */

			i = 0;
			n = *(t = (char*)s);
			for (;;)
			{
				if (n == '*')
					n = *++s;
				else if (!isdigit(n))
					break;
				else
					while ((n = *++s) == ',' || n == '-' || n == '/' || isdigit(n));
				if (n != ' ' && n != '_' && n != ';')
				{
					if (!n)
						i++;
					break;
				}
				i++;
				while ((n = *++s) == ' ' || n == '_');
			}
			if (i == 5)
			{
				Time_t	tt;
				char	hit[60];
				char	mon[13];
				char	day[7];

				state |= CRON;
				flags = 0;
				tm->tm_sec = 0;
				tm->tm_min++;
				tmfix(tm);

				/*
				 * minute
				 */

				if ((k = range(t, &t, hit, 0, 59)) < 0)
					break;
				if (k && !hit[i = tm->tm_min])
				{
					hit[i] = 1;
					do if (++i > 59)
					{
						i = 0;
						if (++tm->tm_hour > 59)
						{
							tm->tm_min = i;
							tmfix(tm);
						}
					} while (!hit[i]);
					tm->tm_min = i;
				}

				/*
				 * hour
				 */

				if ((k = range(t, &t, hit, 0, 23)) < 0)
					break;
				if (k && !hit[i = tm->tm_hour])
				{
					hit[i] = 1;
					do if (++i > 23)
					{
						i = 0;
						if (++tm->tm_mday > 28)
						{
							tm->tm_hour = i;
							tmfix(tm);
						}
					} while (!hit[i]);
					tm->tm_hour = i;
				}

				/*
				 * day of month
				 */

				if ((k = range(t, &t, hit, 1, 31)) < 0)
					break;
				if (k)
					flags |= DAY|MDAY;

				/*
				 * month
				 */

				if ((k = range(t, &t, mon, 1, 12)) < 0)
					break;
				if (k)
					flags |= MONTH;
				else
					for (i = 1; i <= 12; i++)
						mon[i] = 1;

				/*
				 * day of week
				 */

				if ((k = range(t, &t, day, 0, 6)) < 0)
					break;
				if (k)
					flags |= WDAY;
				s = t;
				if (flags & (MONTH|MDAY|WDAY))
				{
					fix = tmxtime(tm, zone);
					tm = tmxtm(tm, fix, tm->tm_zone);
					i = tm->tm_mon + 1;
					j = tm->tm_mday;
					k = tm->tm_wday;
					for (;;)
					{
						if (!mon[i])
						{
							if (++i > 12)
							{
								i = 1;
								tm->tm_year++;
							}
							tm->tm_mon = i - 1;
							tm->tm_mday = 1;
							tt = tmxtime(tm, zone);
							if (tt < fix)
								goto done;
							tm = tmxtm(tm, tt, tm->tm_zone);
							i = tm->tm_mon + 1;
							j = tm->tm_mday;
							k = tm->tm_wday;
							continue;
						}
						if (flags & (MDAY|WDAY))
						{
							if ((flags & (MDAY|WDAY)) == (MDAY|WDAY))
							{
								if (hit[j] && day[k])
									break;
							}
							else if ((flags & MDAY) && hit[j])
								break;
							else if ((flags & WDAY) && day[k])
								break;
							if (++j > 28)
							{
								tm->tm_mon = i - 1;
								tm->tm_mday = j;
								tm = tmxtm(tm, tmxtime(tm, zone), tm->tm_zone);
								i = tm->tm_mon + 1;
								j = tm->tm_mday;
								k = tm->tm_wday;
							}
							else if ((flags & WDAY) && ++k > 6)
								k = 0;
						}
						else if (flags & MONTH)
							break;
					}
					tm->tm_mon = i - 1;
					tm->tm_mday = j;
					tm->tm_wday = k;
				}
				continue;
			}
			s = t;
		}
		n = -1;
		if (isdigit(*s))
		{
			n = strtol(s, &t, 10);
			if ((w = t - s) && *t == '.' && isdigit(*(t + 1)) && isdigit(*(t + 2)) && isdigit(*(t + 3)))
			{
				now = n;
				goto sns;
			}
			if ((*t == 'T' || *t == 't') && ((set|state) & (YEAR|MONTH|DAY)) == (YEAR|MONTH) && isdigit(*(t + 1)))
				t++;
			u = t + (*t == '-');
			message((-1, "AHA#%d n=%d w=%d u='%c' f=%d t=\"%s\"", __LINE__, n, w, *u, f, t));
			if ((w == 2 || w == 4) && (*u == 'W' || *u == 'w') && isdigit(*(u + 1)))
			{
				if (w == 4)
				{
					if ((n -= 1900) < TM_WINDOW)
						break;
				}
				else if (n < TM_WINDOW)
					n += 100;
				m = n;
				n = strtol(++u, &t, 10);
				if ((i = (t - u)) < 2 || i > 3)
					break;
				if (i == 3)
				{
					k = n % 10;
					n /= 10;
				}
				else if (*t != '-')
					k = 1;
				else if (*++t && dig1(t, k) < 1 || k > 7)
					break;
				if (n < 0 || n > 53)
					break;
				if (k == 7)
					k = 0;
				tm->tm_year = m;
				tmweek(tm, 2, n, k);
				set |= YEAR|MONTH|DAY;
				s = t;
				continue;
			}
			else if (w == 6 || w == 8 && (n / 1000000) > 12)
			{
				t = (char*)s;
				flags = 0;
				if (w == 8 || w == 6 && *u != 'T' && *u != 't')
				{
					dig4(t, m);
					if ((m -= 1900) < TM_WINDOW)
						break;
				}
				else
				{
					dig2(t, m);
					if (m < TM_WINDOW)
						m += 100;
				}
				flags |= YEAR;
				if (dig2(t, l) <= 0 || l > 12)
					break;
				flags |= MONTH;
				if (*t != 'T' && *t != 't' || !isdigit(*++t))
				{
					if (w == 6)
						goto save_yymm;
					if (dig2(t, k) < 1 || k > 31)
						break;
					flags |= DAY;
					goto save_yymmdd;
				}
				n = strtol(s = t, &t, 0);
				if ((t - s) < 2)
					break;
				if (dig2(s, j) > 24)
					break;
				if ((t - s) < 2)
				{
					if ((t - s) == 1 || *t++ != '-')
						break;
					n = strtol(s = t, &t, 0);
					if ((t - s) < 2)
						break;
				}
				if (dig2(s, i) > 59)
					break;
				flags |= HOUR|MINUTE;
				if ((t - s) == 2)
				{
					if (dig2(s, n) > (59 + TM_MAXLEAP))
						break;
					flags |= SECOND;
				}
				else if (t - s)
					break;
				else
					n = 0;
				p = 0;
				if (*t == '.')
				{
					q = 1000000000;
					while (isdigit(*++t))
						p += (*t - '0') * (q /= 10);
					set |= NSEC;
				}
				if (n > (59 + TM_MAXLEAP))
					break;
				goto save;
			}
			else if (f == -1 && isalpha(*t) && tmlex(t, &t, tm_info.format + TM_ORDINAL, TM_ORDINALS - TM_ORDINAL, NiL, 0) >= 0)
			{
				message((-1, "AHA#%d n=%d", __LINE__, n));
 ordinal:
				if (n)
					n--;
				message((-1, "AHA#%d n=%d", __LINE__, n));
				state |= ((f = n) ? NEXT : THIS)|ORDINAL;
				set &= ~(EXACT|LAST|NEXT|THIS);
				set |= state & (EXACT|LAST|NEXT|THIS);
				for (s = t; skip[*s]; s++);
				if (isdigit(*s))
				{
					if (n = strtol(s, &t, 10))
						n--;
					s = t;
					if (*s == '_')
						s++;
				}
				else
					n = -1;
				dir = f;
				message((-1, "AHA#%d f=%d n=%d state=" FFMT, __LINE__, f, n, FLAGS(state)));
			}
			else
			{
				for (u = t; isspace(*u); u++);
				message((-1, "AHA#%d n=%d u=\"%s\"", __LINE__, n, u));
				if ((j = tmlex(u, NiL, tm_info.format, TM_NFORM, tm_info.format + TM_SUFFIXES, TM_PARTS - TM_SUFFIXES)) >= 0 && tm_data.lex[j] == TM_PARTS)
					s = u;
				else
				{
					message((-1, "AHA#%d t=\"%s\"", __LINE__, t));
					if (!(state & (LAST|NEXT|THIS)) && ((i = t - s) == 4 && (*t == '.' && isdigit(*(t + 1)) && isdigit(*(t + 2)) && *(t + 3) != '.' || (!*t || isspace(*t) || *t == '_' || isalnum(*t)) && n >= 0 && (n % 100) < 60 && ((m = (n / 100)) < 20 || m < 24 && !((set|state) & (YEAR|MONTH|HOUR|MINUTE)))) || i > 4 && i <= 12))
					{
						/*
						 * various { date(1) touch(1) } formats
						 *
						 *	[[cc]yy[mm]]ddhhmm[.ss[.nn...]]
						 *	[cc]yyjjj
						 *	hhmm[.ss[.nn...]]
						 */

						message((-1, "AHA#%d t=\"%s\"", __LINE__, t));
						flags = 0;
						if (state & CCYYMMDDHHMMSS)
							break;
						state |= CCYYMMDDHHMMSS;
						p = 0;
						if ((i == 7 || i == 5) && (!*t || *t == 'Z' || *t == 'z'))
						{
							if (i == 7)
							{
								dig4(s, m);
								if ((m -= 1900) < TM_WINDOW)
									break;
							}
							else if (dig2(s, m) < TM_WINDOW)
								m += 100;
							dig3(s, k);
							l = 1;
							j = 0;
							i = 0;
							n = 0;
							flags |= MONTH;
						}
						else if (i & 1)
							break;
						else
						{
							u = t;
							if (i == 12)
							{
								x = s;
								dig2(x, m);
								if (m <= 12)
								{
									u -= 4;
									i -= 4;
									x = s + 8;
									dig4(x, m);
								}
								else
									dig4(s, m);
								if (m < 1969 || m >= 3000)
									break;
								m -= 1900;
							}
							else if (i == 10)
							{
								x = s;
								if (!dig2(x, m) || m > 12 || !dig2(x, m) || m > 31 || dig2(x, m) > 24 || dig2(x, m) > 60 || dig2(x, m) <= 60 && !(tm_info.flags & TM_DATESTYLE))
									dig2(s, m);
								else
								{
									u -= 2;
									i -= 2;
									x = s + 8;
									dig2(x, m);
								}
								if (m < TM_WINDOW)
									m += 100;
							}
							else
								m = tm->tm_year;
							if ((u - s) < 8)
								l = tm->tm_mon + 1;
							else if (dig2(s, l) <= 0 || l > 12)
								break;
							else
								flags |= MONTH;
							if ((u - s) < 6)
								k = tm->tm_mday;
							else if (dig2(s, k) < 1 || k > 31)
								break;
							else
								flags |= DAY;
							if ((u - s) < 4)
								break;
							if (dig2(s, j) > 24)
								break;
							if (dig2(s, i) > 59)
								break;
							flags |= HOUR|MINUTE;
							if ((u - s) == 2)
							{
								dig2(s, n);
								flags |= SECOND;
							}
							else if (u - s)
								break;
							else if (*t != '.')
								n = 0;
							else
							{
								n = strtol(t + 1, &t, 10);
								flags |= SECOND;
								if (*t == '.')
								{
									q = 1000000000;
									while (isdigit(*++t))
										p += (*t - '0') * (q /= 10);
									set |= NSEC;
								}
							}
							if (n > (59 + TM_MAXLEAP))
								break;
						}
					save:
						tm->tm_hour = j;
						tm->tm_min = i;
						tm->tm_sec = n;
						tm->tm_nsec = p;
					save_yymmdd:
						tm->tm_mday = k;
					save_yymm:
						tm->tm_mon = l - 1;
						tm->tm_year = m;
						s = t;
						set |= flags;
						continue;
					}
					for (s = t; skip[*s]; s++);
					message((-1, "AHA#%d s=\"%s\"", __LINE__, s));
					if (*s == ':' || *s == '.' && ((set|state) & (YEAR|MONTH|DAY|HOUR)) == (YEAR|MONTH|DAY))
					{
						c = *s;
						if ((state & HOUR) || n > 24)
							break;
						while (isspace(*++s) || *s == '_');
						if (!isdigit(*s))
							break;
						i = n;
						n = strtol(s, &t, 10);
						for (s = t; isspace(*s) || *s == '_'; s++);
						if (n > 59)
							break;
						j = n;
						m = 0;
						if (*s == c)
						{
							while (isspace(*++s) || *s == '_');
							if (!isdigit(*s))
								break;
							n = strtol(s, &t, 10);
							s = t;
							if (n > (59 + TM_MAXLEAP))
								break;
							set |= SECOND;
							while (isspace(*s))
								s++;
							if (*s == '.')
							{
								q = 1000000000;
								while (isdigit(*++s))
									m += (*s - '0') * (q /= 10);
								set |= NSEC;
							}
						}
						else
							n = 0;
						set |= HOUR|MINUTE;
						skip[':'] = 1;
						k = tm->tm_hour;
						tm->tm_hour = i;
						l = tm->tm_min;
						tm->tm_min = j;
						tm->tm_sec = n;
						tm->tm_nsec = m;
						while (isspace(*s))
							s++;
						switch (tmlex(s, &t, tm_info.format, TM_NFORM, tm_info.format + TM_MERIDIAN, 2))
						{
						case TM_MERIDIAN:
							s = t;
							if (i == 12)
								tm->tm_hour = i = 0;
							break;
						case TM_MERIDIAN+1:
							if (i < 12)
								tm->tm_hour = i += 12;
							break;
						}
						if (f >= 0 || (state & (LAST|NEXT)))
						{
							message((-1, "AHA#%d f=%d i=%d j=%d k=%d l=%d", __LINE__, f, i, j, k, l));
							state &= ~HOLD;
							if (f < 0)
							{
								if (state & LAST)
									f = -1;
								else if (state & NEXT)
									f = 1;
								else
									f = 0;
							}
							if (f > 0)
							{
								if (i > k || i == k && j > l)
									f--;
							}
							else if (i < k || i == k && j < l)
								f++;
							if (f > 0)
							{
								tm->tm_hour += f * 24;
								while (tm->tm_hour >= 24)
								{
									tm->tm_hour -= 24;
									tm->tm_mday++;
								}
							}
							else if (f < 0)
							{
								tm->tm_hour += f * 24;
								while (tm->tm_hour < 24)
								{
									tm->tm_hour += 24;
									tm->tm_mday--;
								}
							}
						}
						continue;
					}
				}
			}
		}
		for (;;)
		{
			message((-1, "AHA#%d s=\"%s\"", __LINE__, s));
			if (*s == '-' || *s == '+')
			{
				if (((set|state) & (MONTH|DAY|HOUR|MINUTE)) == (MONTH|DAY|HOUR|MINUTE) || *s == '+' && (!isdigit(s[1]) || !isdigit(s[2]) || s[3] != ':' && (s[3] != '.' || ((set|state) & (YEAR|MONTH)) != (YEAR|MONTH))))
					break;
				s++;
			}
			else if (skip[*s])
				s++;
			else
				break;
		}
		if (isalpha(*s))
		{
			if (n > 0)
			{
				x = s;
				q = *s++;
				message((-1, "AHA#%d n=%d q='%c'", __LINE__, n, q));
				if (isalpha(*s))
				{
					q <<= 8;
					q |= *s++;
					if (isalpha(*s))
					{
						if (tmlex(s, &t, tm_info.format + TM_SUFFIXES, TM_PARTS - TM_SUFFIXES, NiL, 0) >= 0)
							s = t;
						if (isalpha(*s))
						{
							q <<= 8;
							q |= *s++;
							if (isalpha(*s))
							{
								q <<= 8;
								q |= *s++;
								if (isalpha(*s))
									q = 0;
							}
						}
					}
				}
				switch (q)
				{
				case K1('y'):
				case K1('Y'):
				case K2('y','r'):
				case K2('Y','R'):
					tm->tm_year += n;
					set |= YEAR;
					continue;
				case K1('M'):
				case K2('m','o'):
				case K2('M','O'):
					tm->tm_mon += n;
					set |= MONTH;
					continue;
				case K1('w'):
				case K1('W'):
				case K2('w','k'):
				case K2('W','K'):
					tm->tm_mday += n * 7;
					set |= DAY;
					continue;
				case K1('d'):
				case K1('D'):
				case K2('d','a'):
				case K2('d','y'):
				case K2('D','A'):
				case K2('D','Y'):
					tm->tm_mday += n;
					set |= DAY;
					continue;
				case K1('h'):
				case K1('H'):
				case K2('h','r'):
				case K2('H','R'):
					tm->tm_hour += n;
					set |= HOUR;
					continue;
				case K1('m'):
				case K2('m','n'):
				case K2('M','N'):
					tm->tm_min += n;
					set |= MINUTE;
					continue;
				case K1('s'):
				case K2('s','c'):
				case K1('S'):
				case K2('S','C'):
					tm->tm_sec += n;
					set |= SECOND;
					continue;
				case K2('m','s'):
				case K3('m','s','c'):
				case K4('m','s','e','c'):
				case K2('M','S'):
				case K3('M','S','C'):
				case K4('M','S','E','C'):
					tm->tm_nsec += n * 1000000L;
					continue;
				case K1('u'):
				case K2('u','s'):
				case K3('u','s','c'):
				case K4('u','s','e','c'):
				case K1('U'):
				case K2('U','S'):
				case K3('U','S','C'):
				case K4('U','S','E','C'):
					tm->tm_nsec += n * 1000L;
					continue;
				case K2('n','s'):
				case K3('n','s','c'):
				case K4('n','s','e','c'):
				case K2('N','S'):
				case K3('N','S','C'):
				case K4('N','S','E','C'):
					tm->tm_nsec += n;
					continue;
				}
				s = x;
			}
			if ((j = tmlex(s, &t, tm_info.format, TM_NFORM, tm_info.format + TM_SUFFIXES, TM_PARTS - TM_SUFFIXES)) >= 0)
			{
				if (tm_data.lex[j] == TM_PARTS || n < 1000)
				{
					s = t;
					switch (tm_data.lex[j])
					{
					case TM_EXACT:
						state |= HOLD|EXACT;
						set &= ~(EXACT|LAST|NEXT|THIS);
						set |= state & (EXACT|LAST|NEXT|THIS);
						continue;
					case TM_LAST:
						state |= HOLD|LAST;
						set &= ~(EXACT|LAST|NEXT|THIS);
						set |= state & (EXACT|LAST|NEXT|THIS);
						continue;
					case TM_THIS:
						state |= HOLD|THIS;
						set &= ~(EXACT|LAST|NEXT|THIS);
						set |= state & (EXACT|LAST|NEXT|THIS);
						n = 0;
						continue;
					case TM_NEXT:
						/*
						 * disambiguate english "last ... in" 
						 */

						if (!((state|set) & LAST))
						{
							state |= HOLD|NEXT;
							set &= ~(EXACT|LAST|NEXT|THIS);
							set |= state & (EXACT|LAST|NEXT|THIS);
							continue;
						}
						/*FALLTHROUGH*/
					case TM_FINAL:
						state |= HOLD|THIS|FINAL;
						set &= ~(EXACT|LAST|NEXT|THIS);
						set |= state & (EXACT|LAST|NEXT|THIS|FINAL);
						continue;
					case TM_WORK:
						message((-1, "AHA#%d WORK", __LINE__));
						state |= WORK;
						set |= DAY;
						if (state & LAST)
						{
							state &= ~LAST;
							set &= ~LAST;
							state |= FINAL;
							set |= FINAL;
						}
						goto clear_hour;
					case TM_ORDINAL:
						j += TM_ORDINALS - TM_ORDINAL;
						message((-1, "AHA#%d j=%d", __LINE__, j));
						/*FALLTHROUGH*/
					case TM_ORDINALS:
						n = j - TM_ORDINALS + 1;
						message((-1, "AHA#%d n=%d", __LINE__, n));
						goto ordinal;
					case TM_MERIDIAN:
						if (f >= 0)
							f++;
						else if (state & LAST)
							f = -1;
						else if (state & THIS)
							f = 1;
						else if (state & NEXT)
							f = 2;
						else
							f = 0;
						if (n > 0)
						{
							if (n > 24)
								goto done;
							tm->tm_hour = n;
						}
						for (k = tm->tm_hour; k < 0; k += 24);
						k %= 24;
						if (j == TM_MERIDIAN)
						{
							if (k == 12)
								tm->tm_hour -= 12;
						}
						else if (k < 12)
							tm->tm_hour += 12;
						if (n > 0)
							goto clear_min;
						continue;
					case TM_DAY_ABBREV:
						j += TM_DAY - TM_DAY_ABBREV;
						/*FALLTHROUGH*/
					case TM_DAY:
					case TM_PARTS:
					case TM_HOURS:
						state |= set & (EXACT|LAST|NEXT|THIS);
						if (!(state & (LAST|NEXT|THIS)))
							for (;;)
							{
								while (skip[*s])
									s++;
								if ((k = tmlex(s, &t, tm_info.format + TM_LAST, TM_NOISE - TM_LAST, NiL, 0)) >= 0)
								{
									s = t;
									if (k <= 2)
										state |= LAST;
									else if (k <= 5)
										state |= THIS;
									else if (k <= 8)
										state |= NEXT;
									else
										state |= EXACT;
								}
								else
								{
									state |= (n > 0) ? NEXT : THIS;
									break;
								}
								set &= ~(EXACT|LAST|NEXT|THIS);
								set |= state & (EXACT|LAST|NEXT|THIS);
							}
						/*FALLTHROUGH*/
					case TM_DAYS:
						message((-1, "AHA#%d n=%d j=%d f=%d state=" FFMT, __LINE__, n, j, f, FLAGS(state)));
						if (n == -1)
						{
							/*
							 * disambiguate english "second"
							 */

							if (j == TM_PARTS && f == -1)
							{
								state &= ~(LAST|NEXT|THIS|ORDINAL); /*AHA*/
								n = 2;
								goto ordinal;
							}
							n = 1;
						}

						/*
						 * disambiguate "last" vs. { "previous" "final" }
						 */

						while (isspace(*s))
							s++;
						message((-1, "AHA#%d disambiguate LAST s='%s'", __LINE__, s));
						if ((k = tmlex(s, &t, tm_info.format + TM_NEXT, TM_EXACT - TM_NEXT, NiL, 0)) >= 0 || (k = tmlex(s, &t, tm_info.format + TM_PARTS + 3, 1, NiL, 0)) >= 0)
						{
							s = t;
							if (state & LAST)
							{
								state &= ~LAST;
								set &= ~LAST;
								state |= FINAL;
								set |= FINAL;
								message((-1, "AHA#%d LAST => FINAL", __LINE__));
							}
							else
								state &= ~(THIS|NEXT);
						}
						message((-1, "AHA#%d disambiguate LAST k=%d", __LINE__, k));
						if (state & LAST)
							n = -n;
						else if (!(state & NEXT))
							n--;
						m = (f > 0) ? f * n : n;
						message((-1, "AHA#%d f=%d n=%d i=%d j=%d k=%d l=%d m=%d state=" FFMT, __LINE__, f, n, i, j, k, l, m, FLAGS(state)));
						switch (j)
						{
						case TM_DAYS+0:
							tm->tm_mday--;
							set |= DAY;
							goto clear_hour;
						case TM_DAYS+1:
							set |= DAY;
							goto clear_hour;
						case TM_DAYS+2:
							tm->tm_mday++;
							set |= DAY;
							goto clear_hour;
						case TM_PARTS+0:
							set |= SECOND;
							if ((m < 0 ? -m : m) > (365L*24L*60L*60L))
							{
								now = tmxtime(tm, zone) + tmxsns(m, 0);
								goto reset;
							}
							tm->tm_sec += m;
							goto clear_nsec;
						case TM_PARTS+1:
							tm->tm_min += m;
							set |= MINUTE;
							goto clear_sec;
						case TM_PARTS+2:
							tm->tm_hour += m;
							set |= MINUTE;
							goto clear_min;
						case TM_PARTS+3:
							message((-1, "AHA#%d DAY m=%d n=%d%s", __LINE__, m, n, (state & LAST) ? " LAST" : ""));
							if ((state & (LAST|NEXT|THIS)) == LAST)
								tm->tm_mday = tm_data.days[tm->tm_mon] + (tm->tm_mon == 1 && tmisleapyear(tm->tm_year));
							else if (state & ORDINAL)
								tm->tm_mday = m + 1;
							else
								tm->tm_mday += m;
							if (!(set & (FINAL|WORK)))
								set |= HOUR;
							goto clear_hour;
						case TM_PARTS+4:
							tm = tmxtm(tm, tmxtime(tm, zone), tm->tm_zone);
							tm->tm_mday += 7 * m - tm->tm_wday + 1;
							set |= DAY;
							goto clear_hour;
						case TM_PARTS+5:
							tm->tm_mon += m;
							set |= MONTH;
							goto clear_mday;
						case TM_PARTS+6:
							tm->tm_year += m;
							goto clear_mon;
						case TM_HOURS+0:
							tm->tm_mday += m;
							set |= DAY;
							goto clear_hour;
						case TM_HOURS+1:
							tm->tm_mday += m;
							tm->tm_hour = 6;
							set |= HOUR;
							goto clear_min;
						case TM_HOURS+2:
							tm->tm_mday += m;
							tm->tm_hour = 12;
							set |= HOUR;
							goto clear_min;
						case TM_HOURS+3:
							tm->tm_mday += m;
							tm->tm_hour = 18;
							set |= HOUR;
							goto clear_min;
						}
						if (m >= 0 && (state & ORDINAL))
							tm->tm_mday = 1;
						tm = tmxtm(tm, tmxtime(tm, zone), tm->tm_zone);
						day = j -= TM_DAY;
						if (!dir)
							dir = m;
						message((-1, "AHA#%d j=%d m=%d", __LINE__, j, m));
						j -= tm->tm_wday;
						message((-1, "AHA#%d mday=%d wday=%d day=%d dir=%d f=%d i=%d j=%d l=%d m=%d", __LINE__, tm->tm_mday, tm->tm_wday, day, dir, f, i, j, l, m));
						if (state & (LAST|NEXT|THIS))
						{
							if (state & ORDINAL)
							{
								while (isspace(*s))
									s++;
								if (isdigit(*s) || tmlex(s, &t, tm_info.format, TM_DAY_ABBREV, NiL, 0) >= 0)
								{
									state &= ~(LAST|NEXT|THIS);
									goto clear_hour;
								}
							}
							if (j < 0)
								j += 7;
						}
						else if (j > 0)
							j -= 7;
						message((-1, "AHA#%d day=%d mday=%d f=%d m=%d j=%d state=" FFMT, __LINE__, day, tm->tm_mday, f, m, j, FLAGS(state)));
						set |= DAY;
						if (set & (FINAL|WORK))
							goto clear_hour;
						else if (state & (LAST|NEXT|THIS))
						{
							if (f >= 0)
								day = -1;
							else if (m > 0 && (state & (NEXT|YEAR|MONTH)) == NEXT && j >= 0)
								m--;
							tm->tm_mday += j + m * 7;
							set &= ~(LAST|NEXT|THIS|ORDINAL); /*AHA*/
							state &= ~(LAST|NEXT|THIS|ORDINAL); /*AHA*/
							if (!(state & EXACT))
								goto clear_hour;
						}
						continue;
					case TM_MONTH_ABBREV:
						j += TM_MONTH - TM_MONTH_ABBREV;
						/*FALLTHROUGH*/
					case TM_MONTH:
						if (state & MONTH)
							goto done;
						state |= MONTH;
						i = tm->tm_mon;
						tm->tm_mon = j - TM_MONTH;
						if (n < 0)
						{
							while (skip[*s])
								s++;
							if (isdigit(*s))
							{
								n = strtol(s, &t, 10);
								if (n <= 31 && *t != ':')
									s = t;
								else
									n = -1;
							}
						}
						if (n >= 0)
						{
							if (n > 31)
								goto done;
							state |= DAY|MDAY;
							tm->tm_mday = n;
							if (f > 0)
								tm->tm_year += f;
						}
						if (state & (LAST|NEXT|THIS))
						{
							n = i;
							goto rel_month;
						}
						continue;
					case TM_UT:
						if (state & ZONE)
							goto done;
						state |= ZONE;
						zone = tmgoff(s, &t, 0);
						s = t;
						continue;
					case TM_DT:
						if (!dst)
							goto done;
						if (!(state & ZONE))
						{
							dst = tm->tm_zone->dst;
							zone = tm->tm_zone->west;
						}
						zone += tmgoff(s, &t, dst);
						s = t;
						dst = 0;
						state |= ZONE;
						continue;
					case TM_NOISE:
						continue;
					}
				}
			}
			if (n < 1000)
			{
				if (!(state & ZONE) && (zp = tmzone(s, &t, type, &dst)))
				{
					s = t;
					zone = zp->west + dst;
					tm_info.date = zp;
					state |= ZONE;
					if (n < 0)
						continue;
				}
				else if (!type && (zp = tmtype(s, &t)))
				{
					s = t;
					type = zp->type;
					if (n < 0)
						continue;
				}
				state |= BREAK;
			}
		}
		else if (*s == '/')
		{
			if (!(state & (YEAR|MONTH)) && n >= 1969 && n < 3000 && (i = strtol(s + 1, &t, 10)) > 0 && i <= 12)
			{
				state |= YEAR;
				tm->tm_year = n - 1900;
				s = t;
				i--;
			}
			else
			{
				if ((state & MONTH) || n <= 0 || n > 31)
					break;
				if (isalpha(*++s))
				{
					if ((i = tmlex(s, &t, tm_info.format, TM_DAY_ABBREV, NiL, 0)) < 0)
						break;
					if (i >= TM_MONTH)
						i -= TM_MONTH;
					s = t;
				}
				else
				{
					i = n - 1;
					n = strtol(s, &t, 10);
					s = t;
					if (n <= 0 || n > 31)
						break;
					if (*s == '/' && !isdigit(*(s + 1)))
						break;
				}
				state |= DAY;
				tm->tm_mday = n;
			}
			state |= MONTH;
			n = tm->tm_mon;
			tm->tm_mon = i;
			if (*s == '/')
			{
				n = strtol(++s, &t, 10);
				w = t - s;
				s = t;
				if (*s == '/' || *s == ':' || *s == '-' || *s == '_')
					s++;
			}
			else
			{
				if (state & (LAST|NEXT|THIS))
				{
				rel_month:
					if (state & LAST)
						tm->tm_year -= (tm->tm_mon < n) ? 0 : 1;
					else
						tm->tm_year += ((state & NEXT) ? 1 : 0) + ((tm->tm_mon < n) ? 1 : 0);
					if (state & MDAY)
						goto clear_hour;
					set &= ~(LAST|NEXT|THIS); /*AHA*/
					state &= ~(LAST|NEXT|THIS); /*AHA*/
					goto clear_mday;
				}
				continue;
			}
		}
		if (n < 0 || w > 4)
			break;
		if (w == 4)
		{
			if ((state & YEAR) || n < 1969 || n >= 3000)
				break;
			state |= YEAR;
			tm->tm_year = n - 1900;
		}
		else if (w == 3)
		{
			if (state & (MONTH|MDAY|WDAY))
				break;
			state |= MONTH|DAY|MDAY;
			tm->tm_mon = 0;
			tm->tm_mday = n;
		}
		else if (w == 2 && !(state & YEAR))
		{
			state |= YEAR;
			if (n < TM_WINDOW)
				n += 100;
			tm->tm_year = n;
		}
		else if (!(state & MONTH) && n >= 1 && n <= 12)
		{
			state |= MONTH;
			tm->tm_mon = n - 1;
		}
		else if (!(state & (MDAY|WDAY)) && n >= 1 && n <= 31)
		{
			state |= DAY|MDAY|WDAY;
			tm->tm_mday = n;
		}
		else
			break;
		if (state & BREAK)
		{
			last = t;
			break;
		}
		continue;
	clear_mon:
		if ((set|state) & (EXACT|MONTH))
			continue;
		tm->tm_mon = 0;
	clear_mday:
		set |= MONTH;
		if ((set|state) & (EXACT|DAY|HOUR))
			continue;
		tm->tm_mday = 1;
	clear_hour:
		message((-1, "AHA#%d DAY", __LINE__));
		set |= DAY;
		if ((set|state) & (EXACT|HOUR))
			continue;
		tm->tm_hour = 0;
	clear_min:
		set |= HOUR;
		if ((set|state) & (EXACT|MINUTE))
			continue;
		tm->tm_min = 0;
	clear_sec:
		set |= MINUTE;
		if ((set|state) & (EXACT|SECOND))
			continue;
		tm->tm_sec = 0;
	clear_nsec:
		set |= SECOND;
		if ((set|state) & (EXACT|NSEC))
			continue;
		tm->tm_nsec = 0;
	}
 done:
	if (day >= 0 && !(state & (MDAY|WDAY)))
	{
		message((-1, "AHA#%d day=%d dir=%d state=" FFMT, __LINE__, day, dir, FLAGS(state)));
		tmfix(tm);
		m = dir;
		if (state & MONTH)
			tm->tm_mday = 1;
		else if (m < 0)
			m++;
		tm = tmxtm(tm, tmxtime(tm, zone), tm->tm_zone);
		j = day - tm->tm_wday;
		if (j < 0)
			j += 7;
		tm->tm_mday += j + m * 7;
		if (state & FINAL)
			for (n = tm_data.days[tm->tm_mon] + (tm->tm_mon == 1 && tmisleapyear(tm->tm_year)); (tm->tm_mday + 7) <= n; tm->tm_mday += 7);
	}
	else if (day < 0 && (state & FINAL) && (set & DAY))
	{
		tmfix(tm);
		tm->tm_mday = tm_data.days[tm->tm_mon] + (tm->tm_mon == 1 && tmisleapyear(tm->tm_year));
	}
	if (state & WORK)
	{
		tm->tm_mday = (set & FINAL) ? (tm_data.days[tm->tm_mon] + (tm->tm_mon == 1 && tmisleapyear(tm->tm_year))) : 1;
		tmfix(tm);
		message((-1, "AHA#%d WORK mday=%d wday=%d", __LINE__, tm->tm_mday, tm->tm_wday));
		if (tm->tm_wday == 0 && (j = 1) || tm->tm_wday == 6 && (j = 2))
		{
			if ((tm->tm_mday + j) > (tm_data.days[tm->tm_mon] + (tm->tm_mon == 1 && tmisleapyear(tm->tm_year))))
				j -= 3;
			tm->tm_mday += j;
		}
	}
	now = tmxtime(tm, zone);
	if (tm->tm_year <= 70 && tmxsec(now) > 31536000)
	{
		now = 0;
		last = (char*)o;
	}
	if (e)
		*e = last;
	return now;
}
