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
/*
 * generate <lc.h> implementation tables from lc.tab
 * this must make it through vanilla cc with no -last
 *
 *	# comment
 *	:charset:
 *		code	name	ms-codepage
 *	:language:
 *		code	name	alt1|alt2...	charset|... attr1|attr2|...
 *		...
 *	:territory:
 *		code	name	lang1|lang2...
 *	:abbreviation:
 */

#include <stdio.h>
#include <ctype.h>
#ifdef __STDC__
#include <stdlib.h>
#include <string.h>
#endif

typedef struct Link_s
{
	struct Link_s*		next;
	char*			code;
	int			index;
} Link_t;

typedef struct Table_s
{
	Link_t*			root;
	int			count;
} Table_t;

typedef struct Abbreviation_s
{
	Link_t			link;
	char*			value;
} Abbreviation_t;

typedef struct Attribute_s
{
	Link_t			link;
} Attribute_t;

typedef struct Attribute_list_s
{
	struct Attribute_list_s*next;
	Attribute_t*		attribute;
} Attribute_list_t;

typedef struct Charset_s
{
	Link_t			link;
	char*			alternates;
	char*			ms;
} Charset_t;

typedef struct Language_s
{
	Link_t			link;
	char*			name;
	char*			alternates;
	Charset_t*		charset;
	Attribute_list_t*	attributes;
} Language_t;

typedef struct Language_list_s
{
	struct Language_list_s*	next;
	Language_t*		language;
} Language_list_t;

typedef struct Territory_s
{
	Link_t			link;
	char*			name;
	Language_list_t*	languages;
	int			primary;
	int			index;
} Territory_t;

typedef struct Map_s
{
	Link_t			link;
	Language_t*		language;
	Territory_t*		territory;
	Charset_t*		charset;
	Attribute_t*		attribute;
} Map_t;

static struct State_s
{
	Table_t			attribute;
	Table_t			charset;
	Table_t			language;
	Table_t			territory;
	Table_t			map;
} state;

#define INIT		0
#define CHARSET		1
#define LANGUAGE	2
#define TERRITORY	3
#define MAP		4

#define elementsof(x)	(sizeof(x)/sizeof(x[0]))
#define newof(p,t,n,x)	((t*)malloc(sizeof(t)*(n)+(x)))

static Link_t*
#if defined(__STDC__) || defined(__cplusplus)
enter(register Table_t* tab, register Link_t* v)
#else
enter(tab, v)
register Table_t*	tab;
register Link_t*	v;
#endif
{
	register Link_t*	x;
	register Link_t*	p;

	for (p = 0, x = tab->root; x; p = x, x = x->next)
		if (!strcmp(x->code, v->code))
			return x;
	if (p)
		p->next = v;
	else
		tab->root = v;
	v->next = 0;
	v->index = tab->count++;
	return v;
}

static Link_t*
#if defined(__STDC__) || defined(__cplusplus)
lookup(register Table_t* tab, register char* s)
#else
lookup(tab, s)
register Table_t*	tab;
register char*		s;
#endif
{
	register Link_t*	x;

	for (x = tab->root; x; x = x->next)
		if (!strcmp(x->code, s))
			return x;
	return 0;
}

static char*
#if defined(__STDC__) || defined(__cplusplus)
copy(char** p, register char* f)
#else
copy(p, f)
char**		p;
register char*	f;
#endif
{
	register char*	t;
	char*		b;

	if (!f)
		return 0;
	b = t = *p;
	while (*t++ = *f++);
	*p = t;
	return b;
}

static void
#if defined(__STDC__) || defined(__cplusplus)
macro(FILE* f, char* p1, char* p2, char* p3)
#else
macro(f, p1, p2, p3)
FILE*		f;
char*		p1;
char*		p2;
char*		p3;
#endif
{
	register int	c;
	register char*	s;
	register char*	b;
	register char*	e;
	int		i;
	int		m;
	int		n;
	char*		part[4];
	char		buf[128];

	part[0] = p1;
	part[1] = p2;
	part[2] = p3;
	part[3] = 0;
	n = 0;
	fprintf(f, "\n");
	do
	{
		i = m = 0;
		b = buf;
		e = &buf[sizeof(buf)-1];
		while (b < e)
		{
			if (!(s = part[i++]))
				break;
			if (i > 1)
				*b++ = '_';
			while ((c = *s++) && b < e)
			{
				if (c == '|')
				{
					part[i-1] = s;
					m = 1;
					break;
				}
				else if (islower(c))
					c = toupper(c);
				else if (!isalnum(c))
					c = '_';
				*b++ = c;
			}
		}
		*b = 0;
		fprintf(f, "#ifdef %s\n%s,\n#else\n", buf, buf);
		n++;
	} while (m);
	fprintf(f, "0,\n");
	while (n-- > 0)
		fprintf(f, "#endif\n");
}

#if defined(__STDC__) || defined(__cplusplus)
int
main(int argc, char** argv)
#else
int
main(argc, argv)
int		argc;
char**		argv;
#endif
{
	register char*		s;
	register char**		vp;
	register char**		ve;
	Attribute_t*		ap;
	Attribute_list_t*	al;
	Attribute_list_t*	az;
	Charset_t*		cp;
	Territory_t*		tp;
	Language_t*		lp;
	Language_list_t*	ll;
	Language_list_t*	lz;
	Map_t*			mp;
	char*			b;
	char*			f;
	char*			command;
	char*			hdr;
	char*			lib;
	FILE*			hf;
	FILE*			lf;
	int			c;
	int			i;
	int			line;
	int			type;
	int			language_attribute_max;
	int			territory_language_max;
	char*			arg[5];
	char			buf[1024];

	command = *argv++;
	line = 0;
	if (!(hdr = *argv++) || !(lib = *argv++) || *argv)
	{
		fprintf(stderr, "%s: { hdr lib tab } arguments expected\n", command);
		return 1;
	}
	if (!(hf = fopen(hdr, "w")))
	{
		fprintf(stderr, "%s: %s: cannot write\n", command, hdr);
		return 1;
	}
	if (!(lf = fopen(lib, "w")))
	{
		fprintf(stderr, "%s: %s: cannot write\n", command, lib);
		return 1;
	}
	type = 0;
	language_attribute_max = 0;
	territory_language_max = 0;
	state.language.count = 2;
	state.territory.count = 3;
	ve = &arg[elementsof(arg)];
	fprintf(hf, "/* : : generated by %s : : */\n", command);
	fprintf(hf, "#pragma prototyped\n");
	fprintf(hf, "\n");
	fprintf(hf, "#ifndef _LC_H\n");
	fprintf(hf, "#define _LC_H\t\t\t1\n");
	fprintf(hf, "\n");
	fprintf(hf, "#include <ast.h>\n");
	fprintf(hf, "\n");
	fprintf(hf, "#define LC_abbreviated\t\t0x00001\n");
	fprintf(hf, "#define LC_checked\t\t0x00002\n");
	fprintf(hf, "#define LC_debug\t\t0x00004\n");
	fprintf(hf, "#define LC_default\t\t0x00008\n");
	fprintf(hf, "#define LC_defined\t\t0x00010\n");
	fprintf(hf, "#define LC_local\t\t0x00020\n");
	fprintf(hf, "#define LC_primary\t\t0x00040\n");
	fprintf(hf, "#define LC_qualified\t\t0x00080\n");
	fprintf(hf, "#define LC_undefined\t\t0x00100\n");
	fprintf(hf, "#define LC_utf8\t\t\t0x00200\n");
	fprintf(hf, "#define LC_verbose\t\t0x00400\n");
	fprintf(hf, "#define LC_setlocale\t\t0x10000\n");
	fprintf(hf, "#define LC_setenv\t\t0x20000\n");
	fprintf(hf, "#define LC_user\t\t\t0x40000\n");
	fprintf(lf, "/* : : generated by %s : : */\n", command);
	fprintf(lf, "\n");
	fprintf(lf, "#include \"lclib.h\"\n");
	fprintf(lf, "#include \"lclang.h\"\n");
	fprintf(lf, "\n");
	while (s = fgets(buf, sizeof(buf), stdin))
	{
		line++;
		while (isspace(*s))
			s++;
		if (!*s || *s == '#')
			continue;
		b = s;
		vp = arg;
		for (;;)
		{
			for (*vp++ = s; *s && !isspace(*s); s++);
			if (!*s)
				break;
			for (*s++ = 0; isspace(*s); s++);
			if (!strcmp(*(vp - 1), "-"))
				*(vp - 1) = 0;
			if (!*s || vp >= ve)
				break;
		}
		while (vp < ve)
			*vp++ = 0;
		if (*arg[0] == ':')
		{
			if (!strcmp(arg[0], ":map:"))
			{
				if (type != TERRITORY)
				{
					fprintf(stderr, "%s: %d: %s: must be specified after :territory:\n", command, line, arg[0]);
					return 1;
				}
				type = MAP;
				continue;
			}
			else if (!strcmp(arg[0], ":charset:"))
			{
				if (type != INIT)
				{
					fprintf(stderr, "%s: %d: %s must be specified first\n", command, line, arg[0]);
					return 1;
				}
				type = CHARSET;
				continue;
			}
			else if (!strcmp(arg[0], ":territory:"))
			{
				if (type != LANGUAGE)
				{
					fprintf(stderr, "%s: %d: %s: must be specified after :language:\n", command, line, arg[0]);
					return 1;
				}
				type = TERRITORY;
				continue;
			}
			else if (!strcmp(arg[0], ":language:"))
			{
				if (type != CHARSET)
				{
					fprintf(stderr, "%s: %d: %s must be specified after :charset:\n", command, line, arg[0]);
					return 1;
				}
				type = LANGUAGE;
				continue;
			}
			else
			{
				fprintf(stderr, "%s: %d: %s invalid\n", command, line, arg[0]);
				return 1;
			}
		}
		if (!arg[1])
		{
			fprintf(stderr, "%s: %d: at least two arguments expected\n", command, line);
			return 1;
		}
		switch (type)
		{
		case CHARSET:
			if (!(cp = newof(0, Charset_t, 1, s - b + 1)))
			{
				fprintf(stderr, "%s: %d: out of space\n", command, line);
				return 1;
			}
			b = (char*)(cp + 1);
			cp->link.code = copy(&b, arg[0]);
			cp->alternates = copy(&b, arg[1]);
			cp->ms = copy(&b, arg[2]);
			if (cp != (Charset_t*)enter(&state.charset, (Link_t*)cp))
			{
				fprintf(stderr, "%s: %d: %s: duplicate charset\n", command, line, cp->link.code);
				return 1;
			}
			break;
		case TERRITORY:
			if (!(tp = newof(0, Territory_t, 1, s - b + 1)))
			{
				fprintf(stderr, "%s: %d: out of space\n", command, line);
				return 1;
			}
			b = (char*)(tp + 1);
			tp->link.code = copy(&b, arg[0]);
			tp->name = copy(&b, arg[1]);
			tp->languages = 0;
			if (s = copy(&b, arg[2]))
			{
				i = 0;
				while (*(b = s))
				{
					for (; *s && *s != ':' && *s != '|'; s++);
					if (c = *s)
						*s++ = 0;
					if (!(lp = (Language_t*)lookup(&state.language, b)))
					{
						fprintf(stderr, "%s: %d: %s: unknown language\n", command, line, b);
						return 1;
					}
					if (!(ll = newof(0, Language_list_t, 1, 0)))
					{
						fprintf(stderr, "%s: %d: out of space\n", command, line);
						return 1;
					}
					if (!tp->languages)
						tp->languages = ll;
					else
						lz->next = ll;
					lz = ll;
					ll->language = lp;
					ll->next = 0;
					i++;
					if (c == ':')
					{
						for (b = s; *s && *s != '|'; s++);
						if (*s)
							*s++ = 0;
						if (!strcmp(b, "primary"))
							tp->primary = 1;
					}
				}
				if (territory_language_max < i)
					territory_language_max = i;
			}
			if (tp != (Territory_t*)enter(&state.territory, (Link_t*)tp))
			{
				fprintf(stderr, "%s: %d: %s: duplicate territory\n", command, line, tp->link.code);
				return 1;
			}
			break;
		case LANGUAGE:
			if (!(lp = newof(0, Language_t, 1, s - b + 1)))
			{
				fprintf(stderr, "%s: %d: out of space\n", command, line);
				return 1;
			}
			b = (char*)(lp + 1);
			lp->link.code = copy(&b, arg[0]);
			lp->name = copy(&b, arg[1]);
			lp->alternates = copy(&b, arg[2]);
			if (!arg[3])
				lp->charset = 0;
			else if (!(lp->charset = (Charset_t*)lookup(&state.charset, arg[3])))
			{
				fprintf(stderr, "%s: %d: %s: unknown charset\n", command, line, arg[3]);
				return 1;
			}
			lp->attributes = 0;
			if (s = copy(&b, arg[4]))
			{
				i = 0;
				fprintf(lf, "\nconst Lc_attribute_t attribute_%s[] =\n{\n", lp->link.code);
				while (*(b = s))
				{
					for (f = 0; *s && *s != '|'; s++)
						if (*s == ':')
						{
							*s++ = 0;
							f = s;
						}
					if (*s)
						*s++ = 0;
					fprintf(lf, "{\"%s\",", b);
					if (f)
						fprintf(lf, "LC_%s,", f);
					else
						fprintf(lf, "0,");
					if (!(ap = newof(0, Attribute_t, 1, 0)))
					{
						fprintf(stderr, "%s: %d: out of space\n", command, line);
						return 1;
					}
					ap->link.code = b;
					ap->link.index = i++;
					if (!(al = newof(0, Attribute_list_t, 1, 0)))
					{
						fprintf(stderr, "%s: %d: out of space\n", command, line);
						return 1;
					}
					if (!lp->attributes)
						lp->attributes = al;
					else
						az->next = al;
					az = al;
					al->attribute = ap;
					al->next = 0;
					macro(lf, "SUBLANG", lp->name, b);
					fprintf(lf, "\n},\n");
				}
				if (language_attribute_max < i)
					language_attribute_max = i;
				fprintf(lf, "};\n");
			}
			if (lp != (Language_t*)enter(&state.language, (Link_t*)lp))
			{
				fprintf(stderr, "%s: %d: %s: duplicate language\n", command, line, lp->link.code);
				return 1;
			}
			break;
		case MAP:
			if (!(mp = newof(0, Map_t, 1, s - b + 1)))
			{
				fprintf(stderr, "%s: %d: out of space\n", command, line);
				return 1;
			}
			b = (char*)(mp + 1);
			mp->link.code = copy(&b, arg[0]);
			if (!arg[2])
			{
				fprintf(stderr, "%s: %d: territory code expected\n", command, line);
				return 1;
			}
			if (!(mp->language = (Language_t*)lookup(&state.language, arg[1])))
			{
				fprintf(stderr, "%s: %d: %s: unknown language\n", command, line, arg[1]);
				return 1;
			}
			if (!(mp->territory = (Territory_t*)lookup(&state.territory, arg[2])))
			{
				fprintf(stderr, "%s: %d: %s: unknown territory\n", command, line, arg[2]);
				return 1;
			}
			if (!arg[3])
				mp->charset = 0;
			else if (!(mp->charset = (Charset_t*)lookup(&state.charset, arg[3])))
			{
				fprintf(stderr, "%s: %d: %s: unknown charset\n", command, line, arg[3]);
				return 1;
			}
			mp->attribute = 0;
			if (arg[4])
			{
				for (al = mp->language->attributes; al; al = al->next)
					if (!strcmp(al->attribute->link.code, arg[4]))
					{
						mp->attribute = al->attribute;
						break;
					}
				if (!mp->attribute)
				{
					fprintf(stderr, "%s: %d: %s: unknown attribute\n", command, line, arg[4]);
					return 1;
				}
			}
			if (mp != (Map_t*)enter(&state.map, (Link_t*)mp))
			{
				fprintf(stderr, "%s: %d: %s: duplicate map\n", command, line, mp->link.code);
				return 1;
			}
			break;
		}
	}
	if (!language_attribute_max)
		language_attribute_max = 1;
	if (!territory_language_max)
		territory_language_max = 1;
	fprintf(hf, "\n#define LC_language_attribute_max\t%d\n", language_attribute_max);
	fprintf(hf, "#define LC_territory_language_max\t%d\n", territory_language_max);
	fprintf(hf, "\nstruct Lc_s;\n");
	fprintf(hf, "\ntypedef struct Lc_info_s\n{\n");
	fprintf(hf, "\tconst struct Lc_s*\tlc;\n");
	fprintf(hf, "\tunsigned long\t\tnumber;\n");
	fprintf(hf, "\tvoid*\t\t\tdata;\n");
	fprintf(hf, "} Lc_info_t;\n");
	fprintf(hf, "\ntypedef struct Lc_attribute_s\n{\n");
	fprintf(hf, "\tconst char*\t\tname;\n");
	fprintf(hf, "\tunsigned long\t\tflags;\n");
	fprintf(hf, "\tunsigned long\t\tindex;\n");
	fprintf(hf, "} Lc_attribute_t;\n");
	fprintf(hf, "\ntypedef struct Lc_charset_s\n{\n");
	fprintf(hf, "\tconst char*\t\tcode;\n");
	fprintf(hf, "\tconst char*\t\talternates;\n");
	fprintf(hf, "\tconst char*\t\tms;\n");
	fprintf(hf, "\tunsigned long\t\tindex;\n");
	fprintf(hf, "} Lc_charset_t;\n");
	fprintf(hf, "\ntypedef struct Lc_language_s\n{\n");
	fprintf(hf, "\tconst char*\t\tcode;\n");
	fprintf(hf, "\tconst char*\t\tname;\n");
	fprintf(hf, "\tconst char*\t\talternates;\n");
	fprintf(hf, "\tconst Lc_charset_t*\tcharset;\n");
	fprintf(hf, "\tunsigned long\t\tflags;\n");
	fprintf(hf, "\tunsigned long\t\tindex;\n");
	fprintf(hf, "\tconst Lc_attribute_t*\tattributes[LC_language_attribute_max];\n");
	fprintf(hf, "} Lc_language_t;\n");
	fprintf(hf, "\ntypedef struct Lc_territory_s\n{\n");
	fprintf(hf, "\tconst char*\t\tcode;\n");
	fprintf(hf, "\tconst char*\t\tname;\n");
	fprintf(hf, "\tunsigned long\t\tflags;\n");
	fprintf(hf, "\tunsigned long\t\tindex;\n");
	fprintf(hf, "\tconst Lc_language_t*\tlanguages[LC_territory_language_max];\n");
	fprintf(hf, "#ifdef _LC_TERRITORY_PRIVATE_\n");
	fprintf(hf, "\t_LC_TERRITORY_PRIVATE_\n");
	fprintf(hf, "#endif\n");
	fprintf(hf, "} Lc_territory_t;\n");
	fprintf(hf, "\ntypedef struct Lc_map_s\n{\n");
	fprintf(hf, "\tconst char*\t\tcode;\n");
	fprintf(hf, "\tconst Lc_language_t*\tlanguage;\n");
	fprintf(hf, "\tconst Lc_territory_t*\tterritory;\n");
	fprintf(hf, "\tconst Lc_charset_t*\tcharset;\n");
	fprintf(hf, "\tconst Lc_attribute_t*\tattribute;\n");
	fprintf(hf, "} Lc_map_t;\n");
	fprintf(hf, "\ntypedef struct Lc_attribute_list_s\n{\n");
	fprintf(hf, "\tstruct Lc_attribute_list_s*\tnext;\n");
	fprintf(hf, "\tconst Lc_attribute_t*\t\tattribute;\n");
	fprintf(hf, "} Lc_attribute_list_t;\n");
	fprintf(hf, "\ntypedef struct Lc_s\n{\n");
	fprintf(hf, "\tconst char*\t\tname;\n");
	fprintf(hf, "\tconst char*\t\tcode;\n");
	fprintf(hf, "\tconst Lc_language_t*\tlanguage;\n");
	fprintf(hf, "\tconst Lc_territory_t*\tterritory;\n");
	fprintf(hf, "\tconst Lc_charset_t*\tcharset;\n");
	fprintf(hf, "\tconst Lc_attribute_list_t*\tattributes;\n");
	fprintf(hf, "\tunsigned long\t\tflags;\n");
	fprintf(hf, "\tunsigned long\t\tindex;\n");
	fprintf(hf, "#ifdef _LC_PRIVATE_\n");
	fprintf(hf, "\t_LC_PRIVATE_\n");
	fprintf(hf, "#endif\n");
	fprintf(hf, "} Lc_t;\n");
	fprintf(hf, "\nstruct Lc_category_s;\n");
	fprintf(hf, "\ntypedef int (*Lc_category_set_f)(struct Lc_category_s*);\n");
	fprintf(hf, "\ntypedef struct Lc_category_s\n{\n");
	fprintf(hf, "\tconst char*\t\tname;\n");
	fprintf(hf, "\tint\t\t\texternal;\n");
	fprintf(hf, "\tint\t\t\tinternal;\n");
	fprintf(hf, "\tLc_category_set_f\tsetf;\n");
	fprintf(hf, "\tLc_t*\t\t\tprev;\n");
	fprintf(hf, "\tunsigned int\t\tflags;\n");
	fprintf(hf, "} Lc_category_t;\n");
	fprintf(hf, "\n");
	fprintf(hf, "#if _BLD_ast && defined(__EXPORT__)\n");
	fprintf(hf, "#define extern\t\t__EXPORT__\n");
	fprintf(hf, "#endif\n");
	fprintf(hf, "\n");
	fprintf(hf, "extern size_t\t\tlccanon(Lc_t*, unsigned long flags, char*, size_t);\n");
	fprintf(hf, "extern Lc_category_t*\tlccategories(void);\n");
	fprintf(hf, "extern int\t\tlcindex(int, int);\n");
	fprintf(hf, "extern Lc_info_t*\tlcinfo(int);\n");
	fprintf(hf, "extern Lc_t*\t\tlcmake(const char*);\n");
	fprintf(hf, "extern Lc_t*\t\tlcscan(Lc_t*);\n");
	fprintf(hf, "\n");
	fprintf(hf, "#undef\textern\n");
	fprintf(lf, "\nconst Lc_charset_t lc_charsets[] =\n{\n");
	for (cp = (Charset_t*)state.charset.root; cp; cp = (Charset_t*)cp->link.next)
	{
		fprintf(lf, "{\"%s\",", cp->link.code);
		if (cp->alternates)
			fprintf(lf, "\"%s\",", cp->alternates);
		else
			fprintf(lf, "0,");
		if (cp->ms)
			fprintf(lf, "\"%s\",", cp->ms);
		else
			fprintf(lf, "0");
		fprintf(lf, "},\n");
	}
	fprintf(lf, "\t0\n};\n");
	fprintf(lf, "\nconst Lc_language_t lc_languages[] =\n{\n");
	fprintf(lf, "{\"C\",\"C\",\"POSIX\",&lc_charsets[0],LC_default,0,");
	for (i = 0; i < language_attribute_max; i++)
		fprintf(lf, "0,");
	fprintf(lf, "},\n");
	fprintf(lf, "{\"debug\",\"debug\",0,&lc_charsets[0],LC_debug,0,");
	for (i = 0; i < language_attribute_max; i++)
		fprintf(lf, "0,");
	fprintf(lf, "},\n");
	for (lp = (Language_t*)state.language.root; lp; lp = (Language_t*)lp->link.next)
	{
		fprintf(lf, "{\"%s\",\"%s\",", lp->link.code, lp->name);
		if (lp->alternates)
			fprintf(lf, "\"%s\",", lp->alternates);
		else
			fprintf(lf, "0,");
		fprintf(lf, "&lc_charsets[%d],0,", lp->charset ? lp->charset->link.index : 0);
		macro(lf, "LANG", lp->name, (char*)0);
		for (i = 0, al = lp->attributes; al; al = al->next, i++)
			fprintf(lf, "&attribute_%s[%d],", lp->link.code, al->attribute->link.index);
		for (; i < language_attribute_max; i++)
			fprintf(lf, "0,");
		fprintf(lf, "\n},\n");
	}
	fprintf(lf, "\t0\n};\n");
	fprintf(lf, "\nconst Lc_territory_t lc_territories[] =\n{\n");
	fprintf(lf, "{\"C\",\"C\",LC_default,0,&lc_languages[0],");
	for (i = 1; i < 2 * territory_language_max; i++)
		fprintf(lf, "0,");
	fprintf(lf, "},\n");
	fprintf(lf, "{\"debug\",\"debug\",LC_debug,0,&lc_languages[1],");
	for (i = 1; i < 2 * territory_language_max; i++)
		fprintf(lf, "0,");
	fprintf(lf, "},\n");
	fprintf(lf, "{\"eu\",\"euro\",0,0,&lc_languages[0],");
	for (i = 1; i < 2 * territory_language_max; i++)
		fprintf(lf, "0,");
	fprintf(lf, "},\n");
	for (tp = (Territory_t*)state.territory.root; tp; tp = (Territory_t*)tp->link.next)
	{
		fprintf(lf, "{\"%s\",\"%s\",", tp->link.code, tp->name);
		if (tp->primary)
			fprintf(lf, "LC_primary,");
		else
			fprintf(lf, "0,");
		macro(lf, "CTRY", tp->name, (char*)0);
		for (i = 0, ll = tp->languages; ll; ll = ll->next, i++)
			fprintf(lf, "&lc_languages[%d],", ll->language->link.index);
		for (; i < territory_language_max; i++)
			fprintf(lf, "0,");
		for (i = 0, ll = tp->languages; ll; ll = ll->next, i++)
			macro(lf, "SUBLANG", ll->language->name, tp->name);
		for (; i < territory_language_max; i++)
			fprintf(lf, "0,");
		fprintf(lf, "\n},\n");
	}
	fprintf(lf, "\t0\n};\n");
	fprintf(lf, "\nconst Lc_map_t lc_maps[] =\n{\n");
	for (mp = (Map_t*)state.map.root; mp; mp = (Map_t*)mp->link.next)
	{
		fprintf(lf, "{\"%s\",", mp->link.code);
		fprintf(lf, "&lc_languages[%d],", mp->language->link.index);
		fprintf(lf, "&lc_territories[%d],", mp->territory->link.index);
		fprintf(lf, "&lc_charsets[%d],", mp->charset ? mp->charset->link.index : 0);
		if (mp->attribute)
			fprintf(lf, "&attribute_%s[%d]", mp->language->link.code, mp->attribute->link.index);
		else
			fprintf(lf, "0");
		fprintf(lf, "},\n");
	}
	fprintf(lf, "\t0\n};\n");
	fclose(lf);
	fprintf(hf, "\n#endif\n");
	fclose(hf);
	return 0;
}
