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
 * generate a license comment -- see proto(1)
 *
 * NOTE: coded for minimal library dependence
 *	 not so for the legal department
 */

#ifndef	_PPLIB_H
#include <ast.h>
#include <time.h>
#endif

#ifndef O_cloexec
#ifdef	O_CLOEXEC
#define O_cloexec		0
#else
#define O_cloexec		0
#endif
#endif

#undef	copy
#undef	BSD			/* guess who defines this */
#undef	END
#undef	INLINE
#undef	TEST
#undef	VERBOSE

#define NONE			0
#define INLINE			1
#define TEST			2
#define VERBOSE			3
#define USAGE			4
#define OPEN			5
#define CPL			6
#define EPL			7
#define BSD			8
#define ZLIB			9
#define MIT			10
#define GPL			11
#define SPECIAL			12
#define NONEXCLUSIVE		13
#define NONCOMMERCIAL		14
#define PROPRIETARY		15

#define AUTHOR			0
#define CLASS			1
#define COMPANY			2
#define COMPONENT		3
#define CONTRIBUTOR		4
#define CORPORATION		5
#define DOMAIN			6
#define ID			7
#define INCORPORATION		8
#define LICENSE			9
#define LOCATION		10
#define NAME			11
#define NOTICE			12
#define ORGANIZATION		13
#define PACKAGE			14
#define PARENT			15
#define QUERY			16
#define SINCE			17
#define SOURCE			18
#define START			19
#define STYLE			20
#define URL			21
#define URLMD5			22
#define VERSION			23

#define IDS			64

#define COMDATA			70
#define COMLINE			(COMDATA+4)
#define COMLONG			(COMDATA-32)
#define COMMENT(x,b,s,u)	comment(x,b,s,sizeof(s)-1,u)

#define PUT(b,c)		(((b)->nxt<(b)->end)?(*(b)->nxt++=(c)):((c),(-1)))
#define BUF(b)			((b)->buf)
#define USE(b)			((b)->siz=(b)->nxt-(b)->buf,(b)->nxt=(b)->buf,(b)->siz)
#define SIZ(b)			((b)->nxt-(b)->buf)
#define END(b)			(*((b)->nxt>=(b)->end?((b)->nxt=(b)->end-1):(b)->nxt)=0,(b)->nxt-(b)->buf)

#ifndef NiL
#define NiL			((char*)0)
#endif

typedef struct Buffer_s
{
	char*		buf;
	char*		nxt;
	char*		end;
	int		siz;
} Buffer_t;

typedef struct Item_s
{
	char*		data;
	int		size;
	int		quote;
} Item_t;

typedef struct Id_s
{
	Item_t		name;
	Item_t		value;
} Id_t;

/*
 * NOTE: key[] element order must match the corresponding macro
 */

#define KEY(s)			{s,sizeof(s)-1,0}

static const Item_t	key[] =
{
	KEY("author"),
	KEY("class"),
	KEY("company"),
	KEY("component"),
	KEY("contributor"),
	KEY("corporation"),
	KEY("domain"),
	KEY("id"),
	KEY("incorporation"),
	KEY("license"),
	KEY("location"),
	KEY("name"),
	KEY("notice"),
	KEY("organization"),
	KEY("package"),
	KEY("parent"),
	KEY("query"),
	KEY("since"),
	KEY("source"),
	KEY("start"),
	KEY("type"),
	KEY("url"),
	KEY("urlmd5"),
	KEY("version"),
	{0}
};

#define ITEMS			(sizeof(key)/sizeof(key[0])-1)

#define LIC(s,c)		{s,sizeof(s)-1,c}

static const Item_t	lic[] =
{
	LIC("none", NONE),
	LIC("inline", SPECIAL),
	LIC("test", TEST),
	LIC("verbose", VERBOSE),
	LIC("usage", USAGE),
	LIC("open", OPEN),
	LIC("cpl", OPEN),
	LIC("epl", OPEN),
	LIC("bsd", OPEN),
	LIC("zlib", OPEN),
	LIC("mit", OPEN),
	LIC("gpl", GPL),
	LIC("special", SPECIAL),
	LIC("nonexclusive", SPECIAL),
	LIC("noncommercial", SPECIAL),
	LIC("proprietary", PROPRIETARY),
	{0}
};

typedef struct Notice_s
{
	int		test;
	int		type;
	int		verbose;
	int		ids;
	Item_t		item[ITEMS];
	Id_t		id[IDS];
	char		cc[3];
} Notice_t;

/*
 * return index given <name,size>
 */

static int
lookup(register const Item_t* item, const char* name, int size)
{
	register int	c;
	register int	i;

	c = name[0];
	for (i = 0; item[i].data; i++)
		if (c == item[i].data[0] && size == item[i].size && !strncmp(name, item[i].data, size))
			return i;
	return -1;
}

/*
 * copy s of size n to b
 * n<0 means 0 terminated string
 */

static void
copy(register Buffer_t* b, register char* s, int n)
{
	if (n < 0)
		n = strlen(s);
	while (n--)
		PUT(b, *s++);
}

/*
 * center and copy comment line s to p
 * if s==0 then
 *	n>0	first frame line
 *	n=0	blank line
 *	n<0	last frame line
 * if u>0 then s converted to upper case
 * if u<0 then s is left justified
 */

static void
comment(Notice_t* notice, register Buffer_t* b, register char* s, register int n, int u)
{
	register int	i;
	register int	m;
	register int	x;
	int		cc;

	cc = notice->cc[1];
	if (!s)
	{
		if (n)
		{
			PUT(b, notice->cc[n > 0 ? 0 : 1]);
			for (i = 0; i < COMDATA; i++)
				PUT(b, cc);
			PUT(b, notice->cc[n > 0 ? 1 : 2]);
		}
		else
			s = "";
	}
	if (s)
	{
		if (n > COMDATA)
			n = COMDATA;
		PUT(b, cc);
		m = (u < 0) ? 1 : (COMDATA - n) / 2;
		if ((x = COMDATA - m - n) < 0)
			n--;
		while (m-- > 0)
			PUT(b, ' ');
		while (n-- > 0)
		{
			i = *s++;
			if (u > 0 && i >= 'a' && i <= 'z')
				i = i - 'a' + 'A';
			PUT(b, i);
		}
		while (x-- > 0)
			PUT(b, ' ');
		PUT(b, cc);
	}
	PUT(b, '\n');
}

/*
 * expand simple ${...}
 */

static void
expand(Notice_t* notice, register Buffer_t* b, const Item_t* item)
{
	register char*	t;
	register char*	e;
	register int	q;
	register char*	x;
	register char*	z;
	register int	c;
	int		m;
	int		i;
	int		k;

	if (t = item->data)
	{
		q = item->quote;
		e = t + item->size;
		i = 0;
		while (t < e)
		{
			if (*t == '$' && t < (e + 2) && *(t + 1) == '{')
			{
				k = m = 0;
				x = t += 2;
				while (t < e && (c = *t++) != '}')
					if (c == '.')
						x = t;
					else if (c == '-')
					{
						k = 1;
						break;
					}
					else if (c == '/')
					{
						m = 1;
						break;
					}
				if ((c = lookup(key, x, t - x - 1)) >= 0 && (x = notice->item[c].data))
				{
					z = x + notice->item[c].size;
					while (x < z)
					{
						c = *x++;
						if (!m || c >= '0' && c <= '9')
							PUT(b, c);
					}
				}
				else if (k)
				{
					k = 0;
					i++;
				}
				if (k || m)
				{
					k = 1;
					while (t < e)
						if ((c = *t++) == '{')
							k++;
						else if (c == '}' && !--k)
							break;
				}
			}
			else if (q > 0 && *t == '\\' && (*(t + 1) == q || *(t + 1) == '\\'))
				t++;
			else if (*t == '}' && i)
			{
				t++;
				i--;
			}
			else
				PUT(b, *t++);
		}
	}
}

/*
 * generate a copright notice
 */

static void
copyright(Notice_t* notice, register Buffer_t* b)
{
	register char*	x;
	register char*	t;
	time_t		clock;

	copy(b, "Copyright (c) ", -1);
	if (notice->test)
	{
		clock = (time_t)1000212300;
		t = ctime(&clock) + 20;
	}
	else if (!(t = notice->item[SOURCE].data))
	{
		time(&clock);
		t = ctime(&clock) + 20;
	}
	if ((x = notice->item[START].data) && strncmp(t, x, 4) < 0)
		t = x;
	if ((x = notice->item[SINCE].data) && strncmp(x, t, 4) < 0)
	{
		expand(notice, b, &notice->item[SINCE]);
		PUT(b, '-');
	}
	copy(b, t, 4);
	if (notice->item[PARENT].data)
	{
		PUT(b, ' ');
		expand(notice, b, &notice->item[PARENT]);
	}
	if (notice->item[CORPORATION].data)
	{
		PUT(b, ' ');
		expand(notice, b, &notice->item[CORPORATION]);
		if (notice->item[INCORPORATION].data)
		{
			PUT(b, ' ');
			expand(notice, b, &notice->item[INCORPORATION]);
		}
	}
	else if (notice->item[COMPANY].data)
	{
		PUT(b, ' ');
		expand(notice, b, &notice->item[COMPANY]);
	}
}

typedef struct Stack_s
{
	char*	info;
	char*	file;
	int	line;
	int	size;
} Stack_t;

static int
push(Stack_t* sp, char* file, char* parent, char* info, int size, Buffer_t* buf)
{
	char*		s;
	char*		t;
	int		i;
	int		n;
	char		path[1024];

	if (size <= 8)
	{
		copy(buf, file, -1);
		copy(buf, ": no space", -1);
		PUT(buf, 0);
		return -1;
	}
	if (*file != '/' && parent && (s = strrchr(parent, '/')))
	{
		n = s - parent + 1;
		if ((strlen(file) + n + 1) <= sizeof(path))
		{
			memcpy(path, parent, n);
			strcpy(path + n, file);
			file = path;
		}
	}
	if ((i = open(file, O_RDONLY|O_cloexec)) < 0)
	{
		/* this hack viewpath lookup works for default package setups */
		if (file == path)
			for (s = path; *s; s++)
				if (s[0] == '/' && s[1] == 'a' && s[2] == 'r' && s[3] == 'c' && s[4] == 'h' && s[5] == '/')
				{
					t = s;
					for (s += 6; *s && *s != '/'; s++);
					while (*t++ = *s++);
					i = open(file, O_RDONLY|O_cloexec);
				}
		if (i < 0)
		{
			copy(buf, file, -1);
			copy(buf, ": cannot open", -1);
			PUT(buf, 0);
			return -1;
		}
	}
	n = read(i, info, size - 1);
	close(i);
	if (n < 0)
	{
		copy(buf, file, -1);
		copy(buf, ": cannot read", -1);
		PUT(buf, 0);
		return -1;
	}
	info[n++] = 0;
	sp->file = file;
	sp->info = info;
	sp->line = 0;
	sp->size = n;
	return 0;
}

/*
 * read the license file and generate a comment in p, length size
 * license length in p returned, -1 on error
 * -1 return places 0 terminated error string in p
 */

int
astlicense(char* p, int size, char* file, char* options, int cc1, int cc2, int cc3)
{
	register char*	s;
	register char*	v;
	register char*	x;
	register int	c;
	int		i;
	int		h;
	int		k;
	int		n;
	int		q;
	int		contributor;
	int		first;
	int		level;
	int		quote;
	char*		data;
	char		tmpbuf[COMLINE];
	char		info[8 * 1024];
	Stack_t		input[4];
	Notice_t	notice;
	Item_t		item;
	Buffer_t	buf;
	Buffer_t	tmp;

	buf.end = (buf.buf = buf.nxt = p) + size;
	tmp.end = (tmp.buf = tmp.nxt = tmpbuf) + sizeof(tmpbuf);
	level = 0;
	data = info;
	level = -1;
	if (options)
	{
		level++;
		input[level].file = "<options>";
		input[level].info = options;
		input[level].line = 0;
	}
	if (file && *file)
	{
		if (push(&input[++level], file, 0, data, &info[sizeof(info)] - data, &buf))
			return -1;
		data += input[level].size;
	}
	if (level < 0)
		return 0;
	s = input[level].info;
	notice.test = 0;
	notice.type = NONE;
	notice.verbose = 0;
	notice.ids = 0;
	notice.cc[0] = cc1;
	notice.cc[1] = cc2;
	notice.cc[2] = cc3;
	for (i = 0; i < ITEMS; i++)
		notice.item[i].data = 0;
	notice.item[STYLE] = notice.item[CLASS] = lic[notice.type];
	notice.item[STYLE].quote = notice.item[CLASS].quote = 0;
	contributor = i = k = 0;
	for (;;)
	{
		first = 1;
		while (c = *s)
		{
			while (c == ' ' || c == '\t' || c == '\n' && ++input[level].line || c == '\r' || c == ',' || c == ';' || c == ')')
				c = *++s;
			if (!c)
				break;
			if (c == '#')
			{
				while (*++s && *s != '\n');
				if (*s)
					s++;
				input[level].line++;
				continue;
			}
			if (c == '.')
			{
				while ((c = *++s) && (c == ' ' || c == '\t'));
				file = s;
				while (c && c != ' ' && c != '\t' && c != '\r' && c != '\n')
					c = *++s;
				*s = 0;
				while (c && c != '\n')
					c = *++s;
				if (*file)
				{
					input[level].info = s + (c != 0);
					if (++level >= (sizeof(input) / sizeof(input[0])) || push(&input[level], file, input[level-1].file, data, &info[sizeof(info)] - data, &buf))
						return -1;
					data += input[level].size;
					s = input[level].info;
				}
				continue;
			}
			if (c == '\n')
			{
				s++;
				input[level].line++;
				continue;
			}
			if (c == '[')
				c = *++s;
			x = s;
			n = 0;
			while (c && c != '+' && c != '=' && c != ']' && c != ')' && c != ',' && c != ' ' && c != '\t' && c != '\n' && c != '\r')
				c = *++s;
			n = s - x;
			h = lookup(key, x, n);
			if (c == '+' || c == ']')
				c = *++s;
			quote = 0;
			if (c == '=' || first)
			{
				if (c == '=')
				{
					q = ((c = *++s) == '"' || c == '\'') ? *s++ : 0;
					if (c == '(')
					{
						s++;
						if (h == LICENSE)
							contributor = 0;
						else if (h == CONTRIBUTOR)
							contributor = 1;
						else
						{
							q = 1;
							i = 0;
							for (;;)
							{
								switch (*s++)
								{
								case 0:
									s--;
									break;
								case '(':
									if (!i)
										q++;
									continue;
								case ')':
									if (!i && !--q)
										break;
									continue;
								case '"':
								case '\'':
									if (!i)
										i = *(s - 1);
									else if (i == *(s - 1))
										i = 0;
									continue;
								case '\\':
									if (*s == i && i == '"')
										i++;
									continue;
								case '\n':
									input[level].line++;
									continue;
								default:
									continue;
								}
								break;
							}
						}
						continue;
					}
					v = s;
					while ((c = *s) && (q == '"' && (c == '\\' && (*(s + 1) == '"' || *(s + 1) == '\\') && s++ && (quote = q)) || q && c != q || !q && c != ' ' && c != '\t' && c != '\n' && c != '\r' && c != ',' && c != ';'))
					{
						if (c == '\n')
							input[level].line++;
						s++;
					}
				}
				else
				{
					h = STYLE;
					v = x;
				}
				if (c == '\n')
					input[level].line++;
				if (contributor)
				{
					for (i = 0; i < notice.ids; i++)
						if (n == notice.id[i].name.size && !strncmp(x, notice.id[i].name.data, n))
							break;
					if (i < IDS)
					{
						notice.id[i].name.data = x;
						notice.id[i].name.size = n;
						notice.id[i].name.quote = 0;
						notice.id[i].value.data = v;
						notice.id[i].value.size = s - v;
						notice.id[i].value.quote = quote;
						if (notice.ids <= i)
							notice.ids = i + 1;
					}
				}
				else if (h == QUERY)
				{
					if ((s - v) == 3 && v[0] == 'a' && v[1] == 'l' && v[2] == 'l')
					{
						for (i = 0; i < ITEMS; i++)
							if (notice.item[i].size)
							{
								expand(&notice, &buf, &key[i]);
								PUT(&buf, '=');
								for (h = 0;; h++)
									if (h >= notice.item[i].size)
									{
										h = 0;
										break;
									}
									else if (notice.item[i].data[h] == ' ' || notice.item[i].data[h] == '\t')
										break;
								if (h)
									PUT(&buf, '\'');
								expand(&notice, &buf, &notice.item[i]);
								if (h)
									PUT(&buf, '\'');
								PUT(&buf, '\n');
							}
					}
					else
					{
						if ((h = lookup(key, v, s - v)) < 0)
						{
							item.data = v;
							item.size = s - v;
							item.quote = 0;
							expand(&notice, &buf, &item);
						}
						else
							expand(&notice, &buf, &notice.item[h]);
						PUT(&buf, '\n');
					}
					return END(&buf);
				}
				else
				{
					if (h == STYLE)
						switch (c = lookup(lic, v, s - v))
						{
						case NONE:
							return 0;
						case TEST:
							notice.test = 1;
							h = -1;
							break;
						case VERBOSE:
							notice.verbose = 1;
							h = -1;
							break;
						case USAGE:
							notice.type = c;
							h = -1;
							break;
						case -1:
							c = SPECIAL;
							/*FALLTHROUGH*/
						default:
							notice.type = c;
							notice.item[CLASS].data = lic[lic[c].quote].data;
							notice.item[CLASS].size = lic[lic[c].quote].size;
							if (notice.item[STYLE].data != lic[NONE].data)
								h = -1;
							break;
						}
					if (h >= 0)
					{
						notice.item[h].data = (notice.item[h].size = s - v) ? v : (char*)0;
						notice.item[h].quote = quote;
						k = 1;
					}
				}
			}
			else
			{
				if (input[level].file)
				{
					copy(&buf, "\"", -1);
					copy(&buf, input[level].file, -1);
					copy(&buf, "\", line ", -1);
					x = &tmpbuf[sizeof(tmpbuf)];
					*--x = 0;
					n = ++input[level].line;
					do *--x = ("0123456789")[n % 10]; while (n /= 10);
					copy(&buf, x, -1);
					copy(&buf, ": ", -1);
				}
				copy(&buf, "option error: assignment expected", -1);
				PUT(&buf, 0);
				return -1;
			}
			if (*s)
				s++;
			first = 0;
		}
		if (!level--)
			break;
		s = input[level].info;
	}
	if (!k)
		return 0;
	if (notice.type == INLINE && (!notice.verbose || !notice.item[NOTICE].data))
		return 0;
	if (notice.type != USAGE)
	{
		if (!notice.type)
			notice.type = SPECIAL;
		comment(&notice, &buf, NiL, 1, 0);
		comment(&notice, &buf, NiL, 0, 0);
		if (notice.item[PACKAGE].data)
		{
			copy(&tmp, "This software is part of the ", -1);
			expand(&notice, &tmp, &notice.item[PACKAGE]);
			copy(&tmp, " package", -1);
			comment(&notice, &buf, BUF(&tmp), USE(&tmp), 0);
		}
		if (notice.type >= OPEN)
		{
			copyright(&notice, &tmp);
			comment(&notice, &buf, BUF(&tmp), USE(&tmp), 0);
			if (notice.type >= SPECIAL)
				COMMENT(&notice, &buf, "All Rights Reserved", 0);
		}
		if (notice.type == CPL || notice.type == EPL)
		{
			copy(&tmp, notice.item[PACKAGE].data ? "and" : "This software", -1);
			copy(&tmp, " is licensed under the", -1);
			comment(&notice, &buf, BUF(&tmp), USE(&tmp), 0);
			if (notice.type == EPL)
				copy(&tmp, "Eclipse Public License", -1);
			else
				copy(&tmp, "Common Public License", -1);
			if (notice.item[VERSION].data)
			{
				copy(&tmp, ", Version ", -1);
				expand(&notice, &tmp, &notice.item[VERSION]);
			}
			comment(&notice, &buf, BUF(&tmp), USE(&tmp), 0);
			if (notice.item[CORPORATION].data || notice.item[COMPANY].data)
			{
				copy(&tmp, "by ", -1);
				if (notice.item[PARENT].data)
				{
					expand(&notice, &tmp, &notice.item[PARENT]);
					copy(&tmp, " ", -1);
				}
				if (notice.item[CORPORATION].data)
				{
					expand(&notice, &tmp, &notice.item[CORPORATION]);
					if (notice.item[INCORPORATION].data)
					{
						copy(&tmp, " ", -1);
						expand(&notice, &tmp, &notice.item[INCORPORATION]);
					}
				}
				else if (notice.item[COMPANY].data)
					expand(&notice, &tmp, &notice.item[COMPANY]);
				comment(&notice, &buf, BUF(&tmp), USE(&tmp), 0);
			}
			comment(&notice, &buf, NiL, 0, 0);
			COMMENT(&notice, &buf, "A copy of the License is available at", 0);
			if (notice.item[URL].data)
			{
				expand(&notice, &tmp, &notice.item[URL]);
				comment(&notice, &buf, BUF(&tmp), USE(&tmp), 0);
				if (notice.item[URLMD5].data)
				{
					copy(&tmp, "(with md5 checksum ", -1);
					expand(&notice, &tmp, &notice.item[URLMD5]);
					copy(&tmp, ")", -1);
					comment(&notice, &buf, BUF(&tmp), USE(&tmp), 0);
				}
			}
			else if (notice.type == EPL)
				COMMENT(&notice, &buf, "http://www.eclipse.org/org/documents/epl-v10.html", 0);
			else
				COMMENT(&notice, &buf, "http://www.opensource.org/licenses/cpl", 0);
			comment(&notice, &buf, NiL, 0, 0);
		}
		else if (notice.type == OPEN)
		{
			copy(&tmp, notice.item[PACKAGE].data ? "and it" : "This software", -1);
			copy(&tmp, " may only be used by you under license from", -1);
			comment(&notice, &buf, BUF(&tmp), USE(&tmp), 0);
			if (notice.item[i = CORPORATION].data)
			{
				if (notice.item[PARENT].data)
				{
					expand(&notice, &tmp, &notice.item[i = PARENT]);
					copy(&tmp, " ", -1);
				}
				expand(&notice, &tmp, &notice.item[CORPORATION]);
				comment(&notice, &buf, BUF(&tmp), USE(&tmp), 0);
			}
			else if (notice.item[i = COMPANY].data)
			{
				if (notice.item[PARENT].data)
				{
					expand(&notice, &tmp, &notice.item[i = PARENT]);
					copy(&tmp, " ", -1);
				}
				expand(&notice, &tmp, &notice.item[COMPANY]);
				comment(&notice, &buf, BUF(&tmp), USE(&tmp), 0);
			}
			else
				i = -1;
			if (notice.item[URL].data)
			{
				COMMENT(&notice, &buf, "A copy of the Source Code Agreement is available", 0);
				copy(&tmp, "at the ", -1);
				if (i >= 0)
					expand(&notice, &tmp, &notice.item[i]);
				copy(&tmp, " Internet web site URL", -1);
				comment(&notice, &buf, BUF(&tmp), USE(&tmp), 0);
				comment(&notice, &buf, NiL, 0, 0);
				expand(&notice, &tmp, &notice.item[URL]);
				comment(&notice, &buf, BUF(&tmp), USE(&tmp), 0);
				if (notice.item[URLMD5].data)
				{
					copy(&tmp, "(with an md5 checksum of ", -1);
					expand(&notice, &tmp, &notice.item[URLMD5]);
					copy(&tmp, ")", -1);
					comment(&notice, &buf, BUF(&tmp), USE(&tmp), 0);
				}
				comment(&notice, &buf, NiL, 0, 0);
			}
			COMMENT(&notice, &buf, "If you have copied or used this software without agreeing", 0);
			COMMENT(&notice, &buf, "to the terms of the license you are infringing on", 0);
			COMMENT(&notice, &buf, "the license and copyright and are violating", 0);
			if (i >= 0)
				expand(&notice, &tmp, &notice.item[i]);
			copy(&tmp, "'s", -1);
			if (n >= COMLONG)
				comment(&notice, &buf, BUF(&tmp), USE(&tmp), 0);
			else
				PUT(&tmp, ' ');
			copy(&tmp, "intellectual property rights.", -1);
			comment(&notice, &buf, BUF(&tmp), USE(&tmp), 0);
			comment(&notice, &buf, NiL, 0, 0);
		}
		else if (notice.type == GPL)
		{
			comment(&notice, &buf, NiL, 0, 0);
			COMMENT(&notice, &buf, "This is free software; you can redistribute it and/or", 0);
			COMMENT(&notice, &buf, "modify it under the terms of the GNU General Public License", 0);
			COMMENT(&notice, &buf, "as published by the Free Software Foundation;", 0);
			COMMENT(&notice, &buf, "either version 2, or (at your option) any later version.", 0);
			comment(&notice, &buf, NiL, 0, 0);
			COMMENT(&notice, &buf, "This software is distributed in the hope that it", 0);
			COMMENT(&notice, &buf, "will be useful, but WITHOUT ANY WARRANTY;", 0);
			COMMENT(&notice, &buf, "without even the implied warranty of MERCHANTABILITY", 0);
			COMMENT(&notice, &buf, "or FITNESS FOR A PARTICULAR PURPOSE.", 0);
			COMMENT(&notice, &buf, "See the GNU General Public License for more details.", 0);
			comment(&notice, &buf, NiL, 0, 0);
			COMMENT(&notice, &buf, "You should have received a copy of the", 0);
			COMMENT(&notice, &buf, "GNU General Public License", 0);
			COMMENT(&notice, &buf, "along with this software (see the file COPYING.)", 0);
			COMMENT(&notice, &buf, "If not, a copy is available at", 0);
			COMMENT(&notice, &buf, "http://www.gnu.org/copyleft/gpl.html", 0);
			comment(&notice, &buf, NiL, 0, 0);
		}
		else if (notice.type == BSD)
		{
			comment(&notice, &buf, NiL, 0, 0);
			COMMENT(&notice, &buf, "Redistribution and use in source and binary forms, with or", -1);
			COMMENT(&notice, &buf, "without modification, are permitted provided that the following", -1);
			COMMENT(&notice, &buf, "conditions are met:", -1);
			comment(&notice, &buf, NiL, 0, 0);
			COMMENT(&notice, &buf, "   1. Redistributions of source code must retain the above", -1);
			COMMENT(&notice, &buf, "      copyright notice, this list of conditions and the", -1);
			COMMENT(&notice, &buf, "      following disclaimer.", -1);
			comment(&notice, &buf, NiL, 0, 0);
			COMMENT(&notice, &buf, "   2. Redistributions in binary form must reproduce the above", -1);
			COMMENT(&notice, &buf, "      copyright notice, this list of conditions and the", -1);
			COMMENT(&notice, &buf, "      following disclaimer in the documentation and/or other", -1);
			COMMENT(&notice, &buf, "      materials provided with the distribution.", -1);
			comment(&notice, &buf, NiL, 0, 0);
			copy(&tmp, "   3. Neither the name of ", -1);
			if (notice.item[i = PARENT].data || notice.item[i = CORPORATION].data || notice.item[i = COMPANY].data)
				expand(&notice, &tmp, &notice.item[i]);
			else
				copy(&tmp, "the copyright holder", -1);
			copy(&tmp, " nor the", -1);
			comment(&notice, &buf, BUF(&tmp), USE(&tmp), -1);
			COMMENT(&notice, &buf, "      names of its contributors may be used to endorse or", -1);
			COMMENT(&notice, &buf, "      promote products derived from this software without", -1);
			COMMENT(&notice, &buf, "      specific prior written permission.", -1);
			comment(&notice, &buf, NiL, 0, 0);
			COMMENT(&notice, &buf, "THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND", -1);
			COMMENT(&notice, &buf, "CONTRIBUTORS \"AS IS\" AND ANY EXPRESS OR IMPLIED WARRANTIES,", -1);
			COMMENT(&notice, &buf, "INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF", -1);
			COMMENT(&notice, &buf, "MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE", -1);
			COMMENT(&notice, &buf, "DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS", -1);
			COMMENT(&notice, &buf, "BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,", -1);
			COMMENT(&notice, &buf, "EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED", -1);
			COMMENT(&notice, &buf, "TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,", -1);
			COMMENT(&notice, &buf, "DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON", -1);
			COMMENT(&notice, &buf, "ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,", -1);
			COMMENT(&notice, &buf, "OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY", -1);
			COMMENT(&notice, &buf, "OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE", -1);
			COMMENT(&notice, &buf, "POSSIBILITY OF SUCH DAMAGE.", -1);
			comment(&notice, &buf, NiL, 0, 0);
		}
		else if (notice.type == ZLIB)
		{
			comment(&notice, &buf, NiL, 0, 0);
			COMMENT(&notice, &buf, "This software is provided 'as-is', without any express or implied", -1);
			COMMENT(&notice, &buf, "warranty. In no event will the authors be held liable for any", -1);
			COMMENT(&notice, &buf, "damages arising from the use of this software.", -1);
			comment(&notice, &buf, NiL, 0, 0);
			COMMENT(&notice, &buf, "Permission is granted to anyone to use this software for any", -1);
			COMMENT(&notice, &buf, "purpose, including commercial applications, and to alter it and", -1);
			COMMENT(&notice, &buf, "redistribute it freely, subject to the following restrictions:", -1);
			comment(&notice, &buf, NiL, 0, 0);
			COMMENT(&notice, &buf, " 1. The origin of this software must not be misrepresented;", -1);
			COMMENT(&notice, &buf, "    you must not claim that you wrote the original software. If", -1);
			COMMENT(&notice, &buf, "    you use this software in a product, an acknowledgment in the", -1);
			COMMENT(&notice, &buf, "    product documentation would be appreciated but is not", -1);
			COMMENT(&notice, &buf, "    required.", -1);
			comment(&notice, &buf, NiL, 0, 0);
			COMMENT(&notice, &buf, " 2. Altered source versions must be plainly marked as such,", -1);
			COMMENT(&notice, &buf, "    and must not be misrepresented as being the original", -1);
			COMMENT(&notice, &buf, "    software.", -1);
			comment(&notice, &buf, NiL, 0, 0);
			COMMENT(&notice, &buf, " 3. This notice may not be removed or altered from any source", -1);
			COMMENT(&notice, &buf, "    distribution.", -1);
			comment(&notice, &buf, NiL, 0, 0);
		}
		else if (notice.type == MIT)
		{
			comment(&notice, &buf, NiL, 0, 0);
			COMMENT(&notice, &buf, "Permission is hereby granted, free of charge, to any person", 0);
			COMMENT(&notice, &buf, "obtaining a copy of this software and associated", 0);
			COMMENT(&notice, &buf, "documentation files (the \"Software\"), to deal in the", 0);
			COMMENT(&notice, &buf, "Software without restriction, including without limitation", 0);
			COMMENT(&notice, &buf, "the rights to use, copy, modify, merge, publish, distribute,", 0);
			COMMENT(&notice, &buf, "sublicense, and/or sell copies of the Software, and to", 0);
			COMMENT(&notice, &buf, "permit persons to whom the Software is furnished to do so,", 0);
			COMMENT(&notice, &buf, "subject to the following conditions:", 0);
			comment(&notice, &buf, NiL, 0, 0);
			COMMENT(&notice, &buf, "The above copyright notice and this permission notice shall", 0);
			COMMENT(&notice, &buf, "be included in all copies or substantial portions of the", 0);
			COMMENT(&notice, &buf, "Software.", 0);
			comment(&notice, &buf, NiL, 0, 0);
			COMMENT(&notice, &buf, "THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY", 0);
			COMMENT(&notice, &buf, "KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE", 0);
			COMMENT(&notice, &buf, "WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR", 0);
			COMMENT(&notice, &buf, "PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS", 0);
			COMMENT(&notice, &buf, "OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR", 0);
			COMMENT(&notice, &buf, "OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR", 0);
			COMMENT(&notice, &buf, "OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE", 0);
			COMMENT(&notice, &buf, "SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.", 0);
			comment(&notice, &buf, NiL, 0, 0);
		}
		else
		{
			if (notice.type == PROPRIETARY)
			{
				if (notice.item[i = PARENT].data || notice.item[i = CORPORATION].data || notice.item[i = COMPANY].data)
				{
					expand(&notice, &tmp, &notice.item[i]);
					copy(&tmp, " - ", -1);
				}
				else
					i = -1;
				copy(&tmp, "Proprietary", -1);
				comment(&notice, &buf, BUF(&tmp), USE(&tmp), 1);
				comment(&notice, &buf, NiL, 0, 0);
				if (notice.item[URL].data)
				{
					copy(&tmp, "This is proprietary source code", -1);
					if (i >= 0)
						copy(&tmp, " licensed by", -1);
					comment(&notice, &buf, BUF(&tmp), USE(&tmp), 1);
					if (notice.item[PARENT].data)
					{
						expand(&notice, &tmp, &notice.item[PARENT]);
						copy(&tmp, " ", -1);
					}
					if (notice.item[CORPORATION].data)
					{
						expand(&notice, &tmp, &notice.item[CORPORATION]);
						comment(&notice, &buf, BUF(&tmp), USE(&tmp), 1);
					}
					else if (notice.item[COMPANY].data)
					{
						expand(&notice, &tmp, &notice.item[COMPANY]);
						comment(&notice, &buf, BUF(&tmp), USE(&tmp), 1);
					}
				}
				else
				{
					copy(&tmp, "This is unpublished proprietary source code", -1);
					if (i >= 0)
						copy(&tmp, " of", -1);
					comment(&notice, &buf, BUF(&tmp), USE(&tmp), 1);
					if (notice.item[i = PARENT].data || notice.item[i = CORPORATION].data)
						expand(&notice, &tmp, &notice.item[i]);
					if (notice.item[COMPANY].data)
					{
						if (SIZ(&tmp))
							PUT(&tmp, ' ');
						expand(&notice, &tmp, &notice.item[COMPANY]);
					}
					if (SIZ(&tmp))
						comment(&notice, &buf, BUF(&tmp), USE(&tmp), 1);
					COMMENT(&notice, &buf, "and is not to be disclosed or used except in", 1);
					COMMENT(&notice, &buf, "accordance with applicable agreements", 1);
				}
				comment(&notice, &buf, NiL, 0, 0);
			}
			else if (notice.type == NONEXCLUSIVE)
			{
				COMMENT(&notice, &buf, "For nonexclusive individual use", 1);
				comment(&notice, &buf, NiL, 0, 0);
			}
			else if (notice.type == NONCOMMERCIAL)
			{
				COMMENT(&notice, &buf, "For noncommercial use", 1);
				comment(&notice, &buf, NiL, 0, 0);
			}
			if (notice.type >= PROPRIETARY && !notice.item[URL].data)
			{
				COMMENT(&notice, &buf, "Unpublished & Not for Publication", 0);
				comment(&notice, &buf, NiL, 0, 0);
			}
			if (notice.item[URL].data)
			{
				copy(&tmp, "This software is licensed", -1);
				if (notice.item[CORPORATION].data || notice.item[COMPANY].data)
				{
					copy(&tmp, " by", -1);
					if ((notice.item[PARENT].size + (notice.item[CORPORATION].data ? (notice.item[CORPORATION].size + notice.item[INCORPORATION].size) : notice.item[COMPANY].size)) >= (COMLONG - 6))
						comment(&notice, &buf, BUF(&tmp), USE(&tmp), 0);
					else
						PUT(&tmp, ' ');
					if (notice.item[PARENT].data)
					{
						expand(&notice, &tmp, &notice.item[PARENT]);
						copy(&tmp, " ", -1);
					}
					if (notice.item[CORPORATION].data)
					{
						expand(&notice, &tmp, &notice.item[CORPORATION]);
						if (notice.item[INCORPORATION].data)
						{
							copy(&tmp, " ", -1);
							expand(&notice, &tmp, &notice.item[INCORPORATION]);
						}
					}
					else if (notice.item[COMPANY].data)
						expand(&notice, &tmp, &notice.item[COMPANY]);
				}
				comment(&notice, &buf, BUF(&tmp), USE(&tmp), 0);
				COMMENT(&notice, &buf, "under the terms and conditions of the license in", 0);
				expand(&notice, &tmp, &notice.item[URL]);
				comment(&notice, &buf, BUF(&tmp), USE(&tmp), 0);
				if (notice.item[URLMD5].data)
				{
					copy(&tmp, "(with an md5 checksum of ", -1);
					expand(&notice, &tmp, &notice.item[URLMD5]);
					copy(&tmp, ")", -1);
					comment(&notice, &buf, BUF(&tmp), USE(&tmp), 0);
				}
				comment(&notice, &buf, NiL, 0, 0);
			}
			else if (notice.type == PROPRIETARY)
			{
				COMMENT(&notice, &buf, "The copyright notice above does not evidence any", 0);
				COMMENT(&notice, &buf, "actual or intended publication of such source code", 0);
				comment(&notice, &buf, NiL, 0, 0);
			}
		}
		if (v = notice.item[NOTICE].data)
		{
			x = v + notice.item[NOTICE].size;
			if (*v == '\n')
				v++;
			item.quote = notice.item[NOTICE].quote;
			do
			{
				for (item.data = v; v < x && *v != '\n'; v++);
				if ((item.size = v - item.data) && *item.data == '\t')
				{
					item.data++;
					item.size--;
					h = 0;
				}
				else
					h = -1;
				expand(&notice, &tmp, &item);
				comment(&notice, &buf, BUF(&tmp), USE(&tmp), h);
			} while (v++ < x);
			if (item.size)
				comment(&notice, &buf, NiL, 0, 0);
		}
		if (notice.item[ORGANIZATION].data)
		{
			expand(&notice, &tmp, &notice.item[ORGANIZATION]);
			comment(&notice, &buf, BUF(&tmp), USE(&tmp), 0);
			if (notice.item[i = PARENT].data || notice.item[i = CORPORATION].data)
				expand(&notice, &tmp, &notice.item[i]);
			if (notice.item[COMPANY].data)
			{
				if (SIZ(&tmp))
					PUT(&tmp, ' ');
				expand(&notice, &tmp, &notice.item[COMPANY]);
			}
			if (SIZ(&tmp))
				comment(&notice, &buf, BUF(&tmp), USE(&tmp), 0);
			if (notice.item[LOCATION].data)
			{
				expand(&notice, &tmp, &notice.item[LOCATION]);
				comment(&notice, &buf, BUF(&tmp), USE(&tmp), 0);
			}
			comment(&notice, &buf, NiL, 0, 0);
		}
	}
	if (v = notice.item[AUTHOR].data)
	{
		x = v + notice.item[AUTHOR].size;
		q = (x - v) == 1 && (*v == '*' || *v == '-');
		k = q && notice.type != USAGE ? -1 : 0;
		for (;;)
		{
			if (!q)
			{
				while (v < x && (*v == ' ' || *v == '\t' || *v == '\r' || *v == '\n' || *v == ',' || *v == '+'))
					v++;
				if (v >= x)
					break;
				item.data = v;
				while (v < x && *v != ',' && *v != '+' && *v++ != '>');
				item.size = v - item.data;
				item.quote = notice.item[AUTHOR].quote;
			}
			h = 0;
			for (i = 0; i < notice.ids; i++)
				if (q || item.size == notice.id[i].name.size && !strncmp(item.data, notice.id[i].name.data, item.size))
				{
					h = 1;
					if (notice.type == USAGE)
					{
						copy(&buf, "[-author?", -1);
						expand(&notice, &buf, &notice.id[i].value);
						PUT(&buf, ']');
					}
					else
					{
						if (k < 0)
						{
							COMMENT(&notice, &buf, "CONTRIBUTORS", 0);
							comment(&notice, &buf, NiL, 0, 0);
						}
						k = 1;
						expand(&notice, &tmp, &notice.id[i].value);
						comment(&notice, &buf, BUF(&tmp), USE(&tmp), 0);
					}
					if (!q)
						break;
				}
			if (q)
				break;
			if (!h)
			{
				if (notice.type == USAGE)
				{
					copy(&buf, "[-author?", -1);
					expand(&notice, &buf, &item);
					PUT(&buf, ']');
				}
				else
				{
					if (k < 0)
					{
						COMMENT(&notice, &buf, "CONTRIBUTORS", 0);
						comment(&notice, &buf, NiL, 0, 0);
					}
					k = 1;
					expand(&notice, &tmp, &item);
					comment(&notice, &buf, BUF(&tmp), USE(&tmp), 0);
				}
			}
		}
		if (k > 0)
			comment(&notice, &buf, NiL, 0, 0);
	}
	if (notice.type == USAGE)
	{
		copy(&buf, "[-copyright?", -1);
		copyright(&notice, &buf);
		PUT(&buf, ']');
		if (notice.item[URL].data)
		{
			copy(&buf, "[-license?", -1);
			expand(&notice, &buf, &notice.item[URL]);
			PUT(&buf, ']');
		}
		PUT(&buf, '\n');
	}
	else
		comment(&notice, &buf, NiL, -1, 0);
	return END(&buf);
}
