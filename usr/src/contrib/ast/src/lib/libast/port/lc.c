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
 * locale state implementation
 */

#include "lclib.h"
#include "lclang.h"
#include "FEATURE/locale"

#include <ctype.h>

typedef struct Local_s
{
	const char*	name;
	int		size;
} Local_t;

#undef	setlocale	/* this file deals with the system locale */

static Lc_numeric_t	default_numeric = { '.', -1 };

static Lc_t		default_lc =
{
	"C",
	"POSIX",
	&lc_languages[0],
	&lc_territories[0],
	&lc_charsets[0],
	0, 
	LC_default|LC_checked|LC_local,
	0,
	{
		{ &default_lc, 0, 0 },
		{ &default_lc, 0, 0 },
		{ &default_lc, 0, 0 },
		{ &default_lc, 0, 0 },
		{ &default_lc, 0, 0 },
		{ &default_lc, 0, (void*)&default_numeric },
		{ &default_lc, 0, 0 },
		{ &default_lc, 0, 0 },
		{ &default_lc, 0, 0 },
		{ &default_lc, 0, 0 },
		{ &default_lc, 0, 0 },
		{ &default_lc, 0, 0 },
		{ &default_lc, 0, 0 },
		{ &default_lc, 0, 0 }
	}
};

static Lc_numeric_t	debug_numeric = { ',', '.' };

static Lc_t		debug_lc =
{
	"debug",
	"debug",
	&lc_languages[1],
	&lc_territories[1],
	&lc_charsets[0],
	0, 
	LC_debug|LC_checked|LC_local,
	0,
	{
		{ &debug_lc, 0, 0 },
		{ &debug_lc, 0, 0 },
		{ &debug_lc, 0, 0 },
		{ &debug_lc, 0, 0 },
		{ &debug_lc, 0, 0 },
		{ &debug_lc, 0, (void*)&debug_numeric },
		{ &debug_lc, 0, 0 },
		{ &debug_lc, 0, 0 },
		{ &debug_lc, 0, 0 },
		{ &debug_lc, 0, 0 },
		{ &debug_lc, 0, 0 },
		{ &debug_lc, 0, 0 },
		{ &debug_lc, 0, 0 },
		{ &debug_lc, 0, 0 }
	},
	&default_lc
};

static Lc_t*		lcs = &debug_lc;

Lc_t*			locales[] =
{
	&default_lc,
	&default_lc,
	&default_lc,
	&default_lc,
	&default_lc,
	&default_lc,
	&default_lc,
	&default_lc,
	&default_lc,
	&default_lc,
	&default_lc,
	&default_lc,
	&default_lc,
	&default_lc
};

/*
 * return the internal category index for category
 */

int
lcindex(int category, int min)
{
	switch (category)
	{
	case LC_ALL:		return min ? -1 : AST_LC_ALL;
	case LC_ADDRESS:	return AST_LC_ADDRESS;
	case LC_COLLATE:	return AST_LC_COLLATE;
	case LC_CTYPE:		return AST_LC_CTYPE;
	case LC_IDENTIFICATION:	return AST_LC_IDENTIFICATION;
	case LC_LANG:		return AST_LC_LANG;
	case LC_MEASUREMENT:	return AST_LC_MEASUREMENT;
	case LC_MESSAGES:	return AST_LC_MESSAGES;
	case LC_MONETARY:	return AST_LC_MONETARY;
	case LC_NAME:		return AST_LC_NAME;
	case LC_NUMERIC:	return AST_LC_NUMERIC;
	case LC_PAPER:		return AST_LC_PAPER;
	case LC_TELEPHONE:	return AST_LC_TELEPHONE;
	case LC_TIME:		return AST_LC_TIME;
	case LC_XLITERATE:	return AST_LC_XLITERATE;
	}
	return -1;
}

/*
 * return the first category table entry
 */

Lc_category_t*
lccategories(void)
{
	return (Lc_category_t*)&lc_categories[0];
}

/*
 * return the current info for category
 */

Lc_info_t*
lcinfo(register int category)
{
	if ((category = lcindex(category, 0)) < 0)
		return 0;
	return LCINFO(category);
}

/*
 * return 1 if s matches the alternation pattern p
 * if minimum!=0 then at least that many chars must match
 * if standard!=0 and s[0] is a digit leading non-digits are ignored in p
 */

static int
match(const char* s, register const char* p, int minimum, int standard)
{
	register const char*	t;
	const char*		x;
	int			w;
	int			z;

	z = 0;
	do
	{
		t = s;
		if (standard)
		{
			if (isdigit(*t))
				while (*p && !isdigit(*p))
					p++;
			else if (isdigit(*p))
				while (*t && !isdigit(*t))
					t++;
		}
		if (*p)
		{
			w = 0;
			x = p;
			while (*p && *p != '|')
			{
				if (!*t || *t == ',')
					break;
				else if (*t == *p)
					/*ok*/;
				else if (*t == '-')
				{
					if (standard && isdigit(*p))
					{
						t++;
						continue;
					}
					while (*p && *p != '-')
						p++;
					if (!*p)
						break;
				}
				else if (*p == '-')
				{
					if (standard && isdigit(*t))
					{
						p++;
						continue;
					}
					w = 1;
					while (*t && *t != '-')
						t++;
					if (!*t)
						break;
				}
				else
					break;
				t++;
				p++;
			}
			if ((!*t || *t == ',') && (!*p || *p == '|' || w))
				return p - x;
			if (minimum && z < (p - x) && (p - x) >= minimum)
				z = p - x;
		}
		while (*p && *p != '|')
			p++;
	} while (*p++);
	return z;
}

/*
 * return 1 if s matches the charset names in cp
 */

static int
match_charset(register const char* s, register const Lc_charset_t* cp)
{
	return match(s, cp->code, 0, 1) || match(s, cp->alternates, 3, 1) || cp->ms && match(s, cp->ms, 0, 1);
}

/*
 * low level for lccanon
 */

static size_t
canonical(const Lc_language_t* lp, const Lc_territory_t* tp, const Lc_charset_t* cp, const Lc_attribute_list_t* ap, unsigned long flags, char* buf, size_t siz)
{
	register int		c;
	register int		u;
	register char*		s;
	register char*		e;
	register const char*	t;
	char*			p;
	char*			r;

	if (!(flags & (LC_abbreviated|LC_default|LC_local|LC_qualified|LC_verbose)))
		flags |= LC_abbreviated;
	s = buf;
	e = &buf[siz - 3];
	if (lp)
	{
		if (lp->flags & (LC_debug|LC_default))
		{
			for (t = lp->code; s < e && (*s = *t++); s++);
			*s++ = 0;
			return s - buf;
		}
		if (flags & LC_verbose)
		{
			u = 1;
			t = lp->name;
			while (s < e && (c = *t++))
			{
				if (u)
				{
					u = 0;
					c = toupper(c);
				}
				else if (!isalnum(c))
					u = 1;
				*s++ = c;
			}
		}
		else
			for (t = lp->code; s < e && (*s = *t++); s++);
	}
	if (s < e)
	{
		if (tp && tp != &lc_territories[0])
		{
			r = 0;
			if (lp)
			{
				if ((flags & (LC_abbreviated|LC_default)) && streq(lp->code, tp->code))
					r = s;
				*s++ = '_';
			}
			if (flags & LC_verbose)
			{
				u = 1;
				t = tp->name;
				while (s < e && (c = *t++) && c != '|')
				{
					if (u)
					{
						u = 0;
						c = toupper(c);
					}
					else if (!isalnum(c))
						u = 1;
					*s++ = c;
				}
			}
			else
				for (t = tp->code; s < e && (*s = toupper(*t++)); s++);
			if (r)
			{
				*s = 0;
				if ((p = setlocale(LC_MESSAGES, 0)) && (p = strdup(p)))
				{
					if (!setlocale(LC_MESSAGES, buf))
					{
						*r = 0;
						if (!setlocale(LC_MESSAGES, buf))
							*r = '_';
					}
					setlocale(LC_MESSAGES, p);
					free(p);
				}
			}
		}
		if (lp && (!(flags & (LC_abbreviated|LC_default)) || cp != lp->charset) && s < e)
		{
			*s++ = '.';
			t = cp->code;
			if (streq(cp->code, "utf8") && (t = _locale_utf8_str))
				for (; s < e && (c = *t++); s++)
					*s = c;
			else
				for (t = cp->code; s < e && (c = *t++); s++)
				{
					if (islower(c))
						c = toupper(c);
					*s = c;
				}
		}
		for (c = '@'; ap && s < e; ap = ap->next)
			if (!(flags & (LC_abbreviated|LC_default|LC_verbose)) || !(ap->attribute->flags & LC_default))
			{
				*s++ = c;
				c = ',';
				for (t = ap->attribute->name; s < e && (*s = *t++); s++);
			}
	}
	*s++ = 0;
	return s - buf;
}

/*
 * generate a canonical locale name in buf
 */

size_t
lccanon(Lc_t* lc, unsigned long flags, char* buf, size_t siz)
{
	if ((flags & LC_local) && (!lc->language || !(lc->language->flags & (LC_debug|LC_default))))
	{
#if _WINIX
		char	lang[64];
		char	code[64];
		char	ctry[64];

		if (lc->index &&
		    GetLocaleInfo(lc->index, LOCALE_SENGLANGUAGE, lang, sizeof(lang)) &&
		    GetLocaleInfo(lc->index, LOCALE_SENGCOUNTRY, ctry, sizeof(ctry)))
		{
		    	if (!GetLocaleInfo(lc->index, LOCALE_IDEFAULTANSICODEPAGE, code, sizeof(code)))
				code[0] = 0;
			if (!lc->charset || !lc->charset->ms)
				return sfsprintf(buf, siz, "%s_%s", lang, ctry);
			else if (streq(lc->charset->ms, code))
				return sfsprintf(buf, siz, "%s_%s.%s", lang, ctry, code);
			else
				return sfsprintf(buf, siz, "%s_%s.%s,%s", lang, ctry, code, lc->charset->ms);
		}
#endif
		buf[0] = '-';
		buf[1] = 0;
		return 0;
	}
	return canonical(lc->language, lc->territory, lc->charset, lc->attributes, flags, buf, siz);
}

/*
 * make an Lc_t from a locale name
 */

Lc_t*
lcmake(const char* name)
{
	register int			c;
	register char*			s;
	register char*			e;
	register const char*		t;
	const char*			a;
	char*				w;
	char*				language_name;
	char*				territory_name;
	char*				charset_name;
	char*				attributes_name;
	Lc_t*				lc;
	const Lc_map_t*			mp;
	const Lc_language_t*		lp;
	const Lc_territory_t*		tp;
	const Lc_territory_t*		tpb;
	const Lc_territory_t*		primary;
	const Lc_charset_t*		cp;
	const Lc_charset_t*		ppa;
	const Lc_attribute_t*		ap;
	Lc_attribute_list_t*		ai;
	Lc_attribute_list_t*		al;
	int				i;
	int				n;
	int				z;
	char				buf[PATH_MAX / 2];
	char				tmp[PATH_MAX / 2];
	Local_t				local[2];

	if (!(t = name) || !*t)
		return &default_lc;
	for (lc = lcs; lc; lc = lc->next)
		if (!strcasecmp(t, lc->code) || !strcasecmp(t, lc->name))
			return lc;
	for (mp = lc_maps; mp->code; mp++)
		if (streq(t, mp->code))
		{
			lp = mp->language;
			tp = mp->territory;
			cp = mp->charset;
			if (!mp->attribute)
				al = 0;
			else if (al = newof(0, Lc_attribute_list_t, 1, 0))
				al->attribute = mp->attribute;
			goto mapped;
		}
	language_name = buf;
	territory_name = charset_name = attributes_name = 0;
	s = buf;
	e = &buf[sizeof(buf)-2];
	a = 0;
	n = 0;
	while (s < e && (c = *t++))
	{
		if (isspace(c) || (c == '(' || c == '-' && *t == '-') && ++n)
		{
			while ((c = *t++) && (isspace(c) || (c == '-' || c == '(' || c == ')') && ++n))
			if (!c)
				break;
			if (isalnum(c) && !n)
				*s++ = '-';
			else
			{
				n = 0;
				if (!a)
				{
					a = t - 1;
					while (c && c != '_' && c != '.' && c != '@')
						c = *t++;
					if (!c)
						break;
				}
			}
		}
		if (c == '_' && !territory_name)
		{
			*s++ = 0;
			territory_name = s;
		}
		else if (c == '.' && !charset_name)
		{
			*s++ = 0;
			charset_name = s;
		}
		else if (c == '@' && !attributes_name)
		{
			*s++ = 0;
			attributes_name = s;
		}
		else
		{
			if (isupper(c))
				c = tolower(c);
			*s++ = c;
		}
	}
	if ((t = a) && s < e)
	{
		if (attributes_name)
			*s++ = ',';
		else
		{
			*s++ = 0;
			attributes_name = s;
		}
		while (s < e && (c = *t++))
		{
			if (isspace(c) || (c == '(' || c == ')' || c == '-' && *t == '-') && ++n)
			{
				while ((c = *t++) && (isspace(c) || (c == '-' || c == '(' || c == ')') && ++n))
				if (!c)
					break;
				if (isalnum(c) && !n)
					*s++ = '-';
				else
					n = 0;
			}
			if (c == '_' || c == '.' || c == '@')
				break;
			if (isupper(c))
				c = tolower(c);
			*s++ = c;
		}
	}
	*s = 0;
#if AHA
	if ((ast.locale.set & AST_LC_debug) && !(ast.locale.set & AST_LC_internal))
		sfprintf(sfstderr, "locale make %s language=%s territory=%s charset=%s attributes=%s\n", name, language_name, territory_name, charset_name, attributes_name);
#endif
	tp = 0;
	cp = ppa = 0;
	al = 0;

	/*
	 * language
	 */

	n = strlen(s = language_name);
	if (n == 2)
		for (lp = lc_languages; lp->code && !streq(s, lp->code); lp++);
	else if (n == 3)
	{
		for (lp = lc_languages; lp->code && (!lp->alternates || !match(s, lp->alternates, n, 0)); lp++);
		if (!lp->code)
		{
			c = s[2];
			s[2] = 0;
			for (lp = lc_languages; lp->code && !streq(s, lp->code); lp++);
			s[2] = c;
			if (lp->code)
				n = 1;
		}
	}
	else if (streq(s, "c") || streq(s, "posix"))
		lp = &lc_languages[0];
	else
		lp = 0;
	if (!lp || !lp->code)
	{
		for (lp = lc_languages; lp->code && !match(s, lp->name, 0, 0); lp++);
		if (!lp || !lp->code)
		{
			if (!territory_name)
			{
				if (n == 2)
					for (tp = lc_territories; tp->code && !streq(s, tp->code); tp++);
				else
				{
					z = 0;
					tpb = 0;
					for (tp = lc_territories; tp->name; tp++)
						if ((i = match(s, tp->name, 3, 0)) > z)
						{
							tpb = tp;
							if ((z = i) == n)
								break;
						}
					if (tpb)
						tp = tpb;
				}
				if (tp->code)
					lp = tp->languages[0];
			}
			if (!lp || !lp->code)
			{
				/*
				 * name not in the tables so let
				 * _ast_setlocale() and/or setlocale()
				 * handle the validity checks
				 */

				s = (char*)name;
				z = strlen(s) + 1;
				if (!(lp = newof(0, Lc_language_t, 1, z)))
					return 0;
				name = ((Lc_language_t*)lp)->code = ((Lc_language_t*)lp)->name = (const char*)(lp + 1);
				memcpy((char*)lp->code, s, z - 1);
				tp = &lc_territories[0];
				cp = &lc_charsets[0];
				if (charset_name)
					for (ppa = lc_charsets; ppa->code; ppa++)
						if (match_charset(charset_name, ppa))
						{
							cp = ppa;
							break;
						}
				((Lc_language_t*)lp)->charset = cp;
				al = 0;
				goto override;
			}
		}
	}

	/*
	 * territory
	 */

	if (!tp || !tp->code)
	{
		if (!(s = territory_name))
		{
			n = 0;
			primary = 0;
			for (tp = lc_territories; tp->code; tp++)
				if (tp->languages[0] == lp)
				{
					if (tp->flags & LC_primary)
					{
						n = 1;
						primary = tp;
						break;
					}
					n++;
					primary = tp;
				}
			if (n == 1)
				tp = primary;
			s = (char*)lp->code;
		}
		if (!tp || !tp->code)
		{
			n = strlen(s);
			if (n == 2)
			{
				for (tp = lc_territories; tp->code; tp++)
					if (streq(s, tp->code))
					{
						if (lp != &lc_languages[0])
						{
							for (i = 0; i < elementsof(tp->languages) && lp != tp->languages[i]; i++);
							if (i >= elementsof(tp->languages))
								tp = 0;
						}
						break;
					}
			}
			else
			{
				for (tp = lc_territories; tp->code; tp++)
					if (match(s, tp->name, 3, 0))
					{
						for (i = 0; i < elementsof(tp->languages) && lp != tp->languages[i]; i++);
						if (i < elementsof(tp->languages))
							break;
					}
			}
			if (tp && !tp->code)
				tp = 0;
		}
	}

	/*
	 * attributes -- done here to catch misplaced charset references
	 */

	if (s = attributes_name)
	{
		do
		{
			for (w = s; *s && *s != ','; s++);
			c = *s;
			*s = 0;
			if (!(cp = lp->charset) || !match_charset(w, cp))
				for (cp = lc_charsets; cp->code; cp++)
					if (match_charset(w, cp))
					{
						ppa = cp;
						break;
					}
			if (!cp->code)
			{
				for (i = 0; i < elementsof(lp->attributes) && (ap = lp->attributes[i]); i++)
					if (match(w, ap->name, 5, 0))
					{
						if (ai = newof(0, Lc_attribute_list_t, 1, 0))
						{
							ai->attribute = ap;
							ai->next = al;
							al = ai;
						}
						break;
					}
				if (i >= elementsof(lp->attributes) && (ap = newof(0, Lc_attribute_t, 1, sizeof(Lc_attribute_list_t) + s - w + 1)))
				{
					ai = (Lc_attribute_list_t*)(ap + 1);
					strcpy((char*)(((Lc_attribute_t*)ap)->name = (const char*)(ai + 1)), w);
					ai->attribute = ap;
					ai->next = al;
					al = ai;
				}
			}
			*s = c;
		} while (*s++);
	}

	/*
	 * charset
	 */

	if (s = charset_name)
		for (cp = lc_charsets; cp->code; cp++)
			if (match_charset(s, cp))
				break;
#if AHA
	if ((ast.locale.set & AST_LC_debug) && !(ast.locale.set & AST_LC_internal))
		sfprintf(sfstderr, "locale make %s charset_name=%s cp=%s ppa=%s lp=%s\n", name, charset_name, cp ? cp->code : 0, ppa, lp->charset);
#endif
	if (!cp || !cp->code)
		cp = ppa ? ppa : lp->charset;
 mapped:
	z = canonical(lp, tp, cp, al, 0, s = tmp, sizeof(tmp));

	/*
	 * add to the list of possibly active locales
	 */

 override:
	n = strlen(name) + 1;
	local[0].name = default_lc.name;
	local[0].size = strlen(local[0].name);
	local[1].name = default_lc.code;
	local[1].size = strlen(local[1].name);
	i = -1;
	for (c = 0; c < elementsof(local); ++c)
		if (strneq(name, local[c].name, local[c].size))
		{
			switch (name[local[c].size])
			{
			case '.':
			case '_':
			case 0:
				i = c;
				z += local[!i].size + n;
				break;
			}
			break;
		}
	if (!(lc = newof(0, Lc_t, 1, n + z)))
		return 0;
	strcpy((char*)(lc->name = (const char*)(lc + 1)), name);
	lc->code = lc->name + n;
	if (i >= 0)
	{
		lc->flags |= LC_local;
		strcpy((char*)lc->code, local[!i].name);
		strcpy((char*)lc->code + local[!i].size, name + local[i].size);
	}
	else
		strcpy((char*)lc->code, s);
	lc->language = lp ? lp : &lc_languages[0];
	lc->territory = tp ? tp : &lc_territories[0];
	lc->charset = cp ? cp : &lc_charsets[0];  
	if (streq(lc->charset->code, "utf8"))
		lc->flags |= LC_utf8;
	lc->attributes = al;
	for (i = 0; i < elementsof(lc->info); i++)
		lc->info[i].lc = lc;
#if _WINIX
	n = SUBLANG_DEFAULT;
	if (tp)
		for (i = 0; i < elementsof(tp->languages); i++)
			if (lp == tp->languages[i])
			{
				n = tp->indices[i];
				break;
			}
	lc->index = MAKELCID(MAKELANGID(lp->index, n), SORT_DEFAULT);
#endif
	lc->next = lcs;
	lcs = lc;
	if ((ast.locale.set & AST_LC_debug) && !(ast.locale.set & AST_LC_internal))
		sfprintf(sfstderr, "locale make %17s %16s %16s %16s language=%s territory=%s charset=%s%s\n", "", lc->name, lc->code, "", lc->language->name, lc->territory->name, lc->charset->code, (lc->flags & LC_local) ? " local" : "");
	return lc;
}

/*
 * return an Lc_t* for each locale in the tables
 * one Lc_t is allocated on the first call with lc==0
 * this is freed when 0 returned
 * the return value is not part of the lcmake() cache
 */

typedef struct Lc_scan_s
{
	Lc_t			lc;
	Lc_attribute_list_t	list;
	int			territory;
	int			language;
	int			attribute;
	char			buf[256];
} Lc_scan_t;

Lc_t*
lcscan(Lc_t* lc)
{
	register Lc_scan_t*	ls;

	if (!(ls = (Lc_scan_t*)lc))
	{
		if (!(ls = newof(0, Lc_scan_t, 1, 0)))
			return 0;
		ls->lc.code = ls->lc.name = ls->buf;
		ls->territory = -1;
		ls->language = elementsof(ls->lc.territory->languages);
		ls->attribute = elementsof(ls->lc.language->attributes);
	}
	if (++ls->attribute >= elementsof(ls->lc.language->attributes) || !(ls->list.attribute = ls->lc.language->attributes[ls->attribute]))
	{
		if (++ls->language >= elementsof(ls->lc.territory->languages) || !(ls->lc.language = ls->lc.territory->languages[ls->language]))
		{
			if (!lc_territories[++ls->territory].code)
			{
				free(ls);
				return 0;
			}
			ls->lc.territory = &lc_territories[ls->territory];
			ls->lc.language = ls->lc.territory->languages[ls->language = 0];
		}
		if (ls->lc.language)
		{
			ls->lc.charset = ls->lc.language->charset ? ls->lc.language->charset : &lc_charsets[0];
			ls->list.attribute = ls->lc.language->attributes[ls->attribute = 0];
		}
		else
		{
			ls->lc.charset = &lc_charsets[0];
			ls->list.attribute = 0;
		}
	}
	ls->lc.attributes = ls->list.attribute ? &ls->list : (Lc_attribute_list_t*)0;
#if _WINIX
	if (!ls->lc.language || !ls->lc.language->index)
		ls->lc.index = 0;
	else
	{
		if ((!ls->list.attribute || !(ls->lc.index = ls->list.attribute->index)) &&
		    (!ls->lc.territory || !(ls->lc.index = ls->lc.territory->indices[ls->language])))
			ls->lc.index = SUBLANG_DEFAULT;
		ls->lc.index = MAKELCID(MAKELANGID(ls->lc.language->index, ls->lc.index), SORT_DEFAULT);
	}
#endif
	canonical(ls->lc.language, ls->lc.territory, ls->lc.charset, ls->lc.attributes, 0, ls->buf, sizeof(ls->buf));
	return (Lc_t*)ls;
}
