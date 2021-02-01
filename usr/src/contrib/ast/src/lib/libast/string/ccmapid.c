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
 * 8 bit character code map name/id lookup support
 */

#include <ast.h>
#include <ccode.h>
#include <ctype.h>

static const Ccmap_t	maps[] =
{
	{
	"ascii",
	"a|ascii|?(iso)?(-)646|?(iso)?(-)8859|latin",
	"8 bit ascii",
	"ISO-8859-%s",
	"1",
	CC_ASCII,
	},

	{
	"ebcdic",
	"e|ebcdic?(-)?([1e])",
	"X/Open ebcdic",
	"EBCDIC",
	0,
	CC_EBCDIC_E,
	},

	{
	"ebcdic-o",
	"o|ebcdic?(-)[3o]|?(cp|ibm)1047|open?(-)edition",
	"mvs OpenEdition ebcdic",
	"EBCDIC-O",
	0,
	CC_EBCDIC_O,
	},

	{
	"ebcdic-h",
	"h|ebcdic?(-)h|?(cp|ibm)?(00)37|[oa]s?(/-)400",
	"ibm OS/400 AS/400 ebcdic",
	"EBCDIC-H",
	0,
	CC_EBCDIC_H,
	},

	{
	"ebcdic-s",
	"s|ebcdic?(-)s|siemens|posix-bc",
	"siemens posix-bc ebcdic",
	"EBCDIC-S",
	0,
	CC_EBCDIC_S,
	},

	{
	"ebcdic-i",
	"i|ebcdic?(-)[2i]|ibm",
	"X/Open ibm ebcdic (not idempotent)",
	"EBCDIC-I",
	0,
	CC_EBCDIC_I,
	},

	{
	"ebcdic-m",
	"m|ebcdic?(-)m|mvs",
	"mvs ebcdic",
	"EBCDIC-M",
	0,
	CC_EBCDIC_M,
	},

	{
	"ebcdic-u",
	"u|ebcdic?(-)(u|mf)|microfocus",
	"microfocus cobol ebcdic",
	"EBCDIC-U",
	0,
	CC_EBCDIC_U,
	},

	{
	"native",
	"n|native|local",
	"native code set",
	0,
	0,
	CC_NATIVE,
	},

	{ 0 },
};

/*
 * ccode map list iterator
 */

Ccmap_t*
ccmaplist(Ccmap_t* mp)
{
	return !mp ? (Ccmap_t*)maps : (++mp)->name ? mp : (Ccmap_t*)0;
}

/*
 * return ccode map id given name
 */

int
ccmapid(const char* name)
{
	register const Ccmap_t*	mp;
	register int		c;
	const Ccmap_t*		bp;
	int			n;
	ssize_t			sub[2];

	bp = 0;
	n = 0;
	for (mp = maps; mp->name; mp++)
		if (strgrpmatch(name, mp->match, sub, elementsof(sub) / 2, STR_MAXIMAL|STR_LEFT|STR_ICASE))
		{
			if (!(c = name[sub[1]]))
				return mp->ccode;
			if (sub[1] > n && !isalpha(c))
			{
				n = sub[1];
				bp = mp;
			}
		}
	return bp ? bp->ccode : -1;
}

/*
 * return ccode map name given id
 */

char*
ccmapname(register int id)
{
	register const Ccmap_t*	mp;

	for (mp = maps; mp->name; mp++)
		if (id == mp->ccode)
			return (char*)mp->name;
	return 0;
}
