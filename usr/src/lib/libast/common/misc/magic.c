/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2010 AT&T Intellectual Property          *
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
 * library interface to file
 *
 * the sum of the hacks {s5,v10,planix} is _____ than the parts
 */

static const char id[] = "\n@(#)$Id: magic library (AT&T Research) 2008-09-10 $\0\n";

static const char lib[] = "libast:magic";

#include <ast.h>
#include <ctype.h>
#include <ccode.h>
#include <dt.h>
#include <modex.h>
#include <error.h>
#include <regex.h>
#include <swap.h>

#define T(m)		(*m?ERROR_translate(NiL,NiL,lib,m):m)

#define match(s,p)	strgrpmatch(s,p,NiL,0,STR_LEFT|STR_RIGHT|STR_ICASE)

#define MAXNEST		10		/* { ... } nesting limit	*/
#define MINITEM		4		/* magic buffer rounding	*/

typedef struct				/* identifier dictionary entry	*/
{
	const char	name[16];	/* identifier name		*/
	int		value;		/* identifier value		*/
	Dtlink_t	link;		/* dictionary link		*/
} Info_t;

typedef struct Edit			/* edit substitution		*/
{
	struct Edit*	next;		/* next in list			*/
	regex_t*	from;		/* from pattern			*/
} Edit_t;

struct Entry;

typedef struct				/* loop info			*/
{
	struct Entry*	lab;		/* call this function		*/
	int		start;		/* start here			*/
	int		size;		/* increment by this amount	*/
	int		count;		/* dynamic loop count		*/
	int		offset;		/* dynamic offset		*/
} Loop_t;

typedef struct Entry			/* magic file entry		*/
{
	struct Entry*	next;		/* next in list			*/
	char*		expr;		/* offset expression		*/
	union
	{
	unsigned long	num;
	char*		str;
	struct Entry*	lab;
	regex_t*	sub;
	Loop_t*		loop;
	}		value;		/* comparison value		*/
	char*		desc;		/* file description		*/
	char*		mime;		/* file mime type		*/
	unsigned long	offset;		/* offset in bytes		*/
	unsigned long	mask;		/* mask before compare		*/
	char		cont;		/* continuation operation	*/
	char		type;		/* datum type			*/
	char		op;		/* comparison operation		*/
	char		nest;		/* { or } nesting operation	*/
	char		swap;		/* forced swap order		*/
} Entry_t;

#define CC_BIT		5

#if (CC_MAPS*CC_BIT) <= (CHAR_BIT*2)
typedef unsigned short Cctype_t;
#else
typedef unsigned long Cctype_t;
#endif

#define CC_text		0x01
#define CC_control	0x02
#define CC_latin	0x04
#define CC_binary	0x08
#define CC_utf_8	0x10

#define CC_notext	CC_text		/* CC_text is flipped before checking */

#define CC_MASK		(CC_binary|CC_latin|CC_control|CC_text)

#define CCTYPE(c)	(((c)>0240)?CC_binary:((c)>=0200)?CC_latin:((c)<040&&(c)!=007&&(c)!=011&&(c)!=012&&(c)!=013&&(c)!=015)?CC_control:CC_text)

#define ID_NONE		0
#define ID_ASM		1
#define ID_C		2
#define ID_COBOL	3
#define ID_COPYBOOK	4
#define ID_CPLUSPLUS	5
#define ID_FORTRAN	6
#define ID_HTML		7
#define ID_INCL1	8
#define ID_INCL2	9
#define ID_INCL3	10
#define ID_MAM1		11
#define ID_MAM2		12
#define ID_MAM3		13
#define ID_NOTEXT	14
#define ID_PL1		15
#define ID_YACC		16

#define ID_MAX		ID_YACC

#define INFO_atime	1
#define INFO_blocks	2
#define INFO_ctime	3
#define INFO_fstype	4
#define INFO_gid	5
#define INFO_mode	6
#define INFO_mtime	7
#define INFO_name	8
#define INFO_nlink	9
#define INFO_size	10
#define INFO_uid	11

#define _MAGIC_PRIVATE_ \
	Magicdisc_t*	disc;			/* discipline		*/ \
	Vmalloc_t*	vm;			/* vmalloc region	*/ \
	Entry_t*	magic;			/* parsed magic table	*/ \
	Entry_t*	magiclast;		/* last entry in magic	*/ \
	char*		mime;			/* MIME type		*/ \
	unsigned char*	x2n;			/* CC_ALIEN=>CC_NATIVE	*/ \
	char		fbuf[SF_BUFSIZE + 1];	/* file data		*/ \
	char		xbuf[SF_BUFSIZE + 1];	/* indirect file data	*/ \
	char		nbuf[256];		/* !CC_NATIVE data	*/ \
	char		mbuf[64];		/* mime string		*/ \
	char		sbuf[64];		/* type suffix string	*/ \
	char		tbuf[2 * PATH_MAX];	/* type string		*/ \
	Cctype_t	cctype[UCHAR_MAX + 1];	/* char code types	*/ \
	unsigned int	count[UCHAR_MAX + 1];	/* char frequency count	*/ \
	unsigned int	multi[UCHAR_MAX + 1];	/* muti char count	*/ \
	int		keep[MAXNEST];		/* ckmagic nest stack	*/ \
	char*		cap[MAXNEST];		/* ckmagic mime stack	*/ \
	char*		msg[MAXNEST];		/* ckmagic text stack	*/ \
	Entry_t*	ret[MAXNEST];		/* ckmagic return stack	*/ \
	int		fbsz;			/* fbuf size		*/ \
	int		fbmx;			/* fbuf max size	*/ \
	int		xbsz;			/* xbuf size		*/ \
	int		swap;			/* swap() operation	*/ \
	unsigned long	flags;			/* disc+open flags	*/ \
	long		xoff;			/* xbuf offset		*/ \
	int		identifier[ID_MAX + 1];	/* Info_t identifier	*/ \
	Sfio_t*		fp;			/* fbuf fp		*/ \
	Sfio_t*		tmp;			/* tmp string		*/ \
	regdisc_t	redisc;			/* regex discipline	*/ \
	Dtdisc_t	dtdisc;			/* dict discipline	*/ \
	Dt_t*		idtab;			/* identifier dict	*/ \
	Dt_t*		infotab;		/* info keyword dict	*/

#include <magic.h>

static Info_t		dict[] =		/* keyword dictionary	*/
{
	{ 	"COMMON",	ID_FORTRAN	},
	{ 	"COMPUTE",	ID_COBOL	},
	{ 	"COMP",		ID_COPYBOOK	},
	{ 	"COMPUTATIONAL",ID_COPYBOOK	},
	{ 	"DCL",		ID_PL1		},
	{ 	"DEFINED",	ID_PL1		},
	{ 	"DIMENSION",	ID_FORTRAN	},
	{ 	"DIVISION",	ID_COBOL	},
	{ 	"FILLER",	ID_COPYBOOK	},
	{ 	"FIXED",	ID_PL1		},
	{ 	"FUNCTION",	ID_FORTRAN	},
	{ 	"HTML",		ID_HTML		},
	{ 	"INTEGER",	ID_FORTRAN	},
	{ 	"MAIN",		ID_PL1		},
	{ 	"OPTIONS",	ID_PL1		},
	{ 	"PERFORM",	ID_COBOL	},
	{ 	"PIC",		ID_COPYBOOK	},
	{ 	"REAL",		ID_FORTRAN	},
	{ 	"REDEFINES",	ID_COPYBOOK	},
	{ 	"S9",		ID_COPYBOOK	},
	{ 	"SECTION",	ID_COBOL	},
	{ 	"SELECT",	ID_COBOL	},
	{ 	"SUBROUTINE",	ID_FORTRAN	},
	{ 	"TEXT",		ID_ASM		},
	{ 	"VALUE",	ID_COPYBOOK	},
	{ 	"attr",		ID_MAM3		},
	{ 	"binary",	ID_YACC		},
	{ 	"block",	ID_FORTRAN	},
	{ 	"bss",		ID_ASM		},
	{ 	"byte",		ID_ASM		},
	{ 	"char",		ID_C		},
	{ 	"class",	ID_CPLUSPLUS	},
	{ 	"clr",		ID_NOTEXT	},
	{ 	"comm",		ID_ASM		},
	{ 	"common",	ID_FORTRAN	},
	{ 	"data",		ID_ASM		},
	{ 	"dimension",	ID_FORTRAN	},
	{ 	"done",		ID_MAM2		},
	{ 	"double",	ID_C		},
	{ 	"even",		ID_ASM		},
	{ 	"exec",		ID_MAM3		},
	{ 	"extern",	ID_C		},
	{ 	"float",	ID_C		},
	{ 	"function",	ID_FORTRAN	},
	{ 	"globl",	ID_ASM		},
	{ 	"h",		ID_INCL3	},
	{ 	"html",		ID_HTML		},
	{ 	"include",	ID_INCL1	},
	{ 	"int",		ID_C		},
	{ 	"integer",	ID_FORTRAN	},
	{ 	"jmp",		ID_NOTEXT	},
	{ 	"left",		ID_YACC		},
	{ 	"libc",		ID_INCL2	},
	{ 	"long",		ID_C		},
	{ 	"make",		ID_MAM1		},
	{ 	"mov",		ID_NOTEXT	},
	{ 	"private",	ID_CPLUSPLUS	},
	{ 	"public",	ID_CPLUSPLUS	},
	{ 	"real",		ID_FORTRAN	},
	{ 	"register",	ID_C		},
	{ 	"right",	ID_YACC		},
	{ 	"sfio",		ID_INCL2	},
	{ 	"static",	ID_C		},
	{ 	"stdio",	ID_INCL2	},
	{ 	"struct",	ID_C		},
	{ 	"subroutine",	ID_FORTRAN	},
	{ 	"sys",		ID_NOTEXT	},
	{ 	"term",		ID_YACC		},
	{ 	"text",		ID_ASM		},
	{ 	"tst",		ID_NOTEXT	},
	{ 	"type",		ID_YACC		},
	{ 	"typedef",	ID_C		},
	{ 	"u",		ID_INCL2	},
	{ 	"union",	ID_YACC		},
	{ 	"void",		ID_C		},
};

static Info_t		info[] =
{
	{	"atime",	INFO_atime		},
	{	"blocks",	INFO_blocks		},
	{	"ctime",	INFO_ctime		},
	{	"fstype",	INFO_fstype		},
	{	"gid",		INFO_gid		},
	{	"mode",		INFO_mode		},
	{	"mtime",	INFO_mtime		},
	{	"name",		INFO_name		},
	{	"nlink",	INFO_nlink		},
	{	"size",		INFO_size		},
	{	"uid",		INFO_uid		},
};

/*
 * return pointer to data at offset off and size siz
 */

static char*
getdata(register Magic_t* mp, register long off, register int siz)
{
	register long	n;

	if (off < 0)
		return 0;
	if (off + siz <= mp->fbsz)
		return mp->fbuf + off;
	if (off < mp->xoff || off + siz > mp->xoff + mp->xbsz)
	{
		if (off + siz > mp->fbmx)
			return 0;
		n = (off / (SF_BUFSIZE / 2)) * (SF_BUFSIZE / 2);
		if (sfseek(mp->fp, n, SEEK_SET) != n)
			return 0;
		if ((mp->xbsz = sfread(mp->fp, mp->xbuf, sizeof(mp->xbuf) - 1)) < 0)
		{
			mp->xoff = 0;
			mp->xbsz = 0;
			return 0;
		}
		mp->xbuf[mp->xbsz] = 0;
		mp->xoff = n;
		if (off + siz > mp->xoff + mp->xbsz)
			return 0;
	}
	return mp->xbuf + off - mp->xoff;
}

/*
 * @... evaluator for strexpr()
 */

static long
indirect(const char* cs, char** e, void* handle)
{
	register char*		s = (char*)cs;
	register Magic_t*	mp = (Magic_t*)handle;
	register long		n = 0;
	register char*		p;

	if (s)
	{
		if (*s == '@')
		{
			n = *++s == '(' ? strexpr(s, e, indirect, mp) : strtol(s, e, 0);
			switch (*(s = *e))
			{
			case 'b':
			case 'B':
				s++;
				if (p = getdata(mp, n, 1))
					n = *(unsigned char*)p;
				else
					s = (char*)cs;
				break;
			case 'h':
			case 'H':
				s++;
				if (p = getdata(mp, n, 2))
					n = swapget(mp->swap, p, 2);
				else
					s = (char*)cs;
				break;
			case 'q':
			case 'Q':
				s++;
				if (p = getdata(mp, n, 8))
					n = swapget(mp->swap, p, 8);
				else
					s = (char*)cs;
				break;
			default:
				if (isalnum(*s))
					s++;
				if (p = getdata(mp, n, 4))
					n = swapget(mp->swap, p, 4);
				else
					s = (char*)cs;
				break;
			}
		}
		*e = s;
	}
	else if ((mp->flags & MAGIC_VERBOSE) && mp->disc->errorf)
		(*mp->disc->errorf)(mp, mp->disc, 2, "%s in indirect expression", *e);
	return n;
}

/*
 * emit regex error message
 */

static void
regmessage(Magic_t* mp, regex_t* re, int code)
{
	char	buf[128];

	if ((mp->flags & MAGIC_VERBOSE) && mp->disc->errorf)
	{
		regerror(code, re, buf, sizeof(buf));
		(*mp->disc->errorf)(mp, mp->disc, 3, "regex: %s", buf);
	}
}

/*
 * decompose vcodex(3) method composition
 */

static char*
vcdecomp(char* b, char* e, unsigned char* m, unsigned char* x)
{
	unsigned char*	map;
	const char*	o;
	int		c;
	int		n;
	int		i;
	int		a;

	map = CCMAP(CC_ASCII, CC_NATIVE);
	a = 0;
	i = 1;
	for (;;)
	{
		if (i)
			i = 0;
		else
			*b++ = '^';
		if (m < (x - 1) && !*(m + 1))
		{
			/*
			 * obsolete indices
			 */

			if (!a)
			{
				a = 1;
				o = "old, ";
				while (b < e && (c = *o++))
					*b++ = c;
			}
			switch (*m)
			{
			case 0:		o = "delta"; break;
			case 1:		o = "huffman"; break;
			case 2:		o = "huffgroup"; break;
			case 3:		o = "arith"; break;
			case 4:		o = "bwt"; break;
			case 5:		o = "rle"; break;
			case 6:		o = "mtf"; break;
			case 7:		o = "transpose"; break;
			case 8:		o = "table"; break;
			case 9:		o = "huffpart"; break;
			case 50:	o = "map"; break;
			case 100:	o = "recfm"; break;
			case 101:	o = "ss7"; break;
			default:	o = "UNKNOWN"; break;
			}
			m += 2;
			while (b < e && (c = *o++))
				*b++ = c;
		}
		else
			while (b < e && m < x && (c = *m++))
			{
				if (map)
					c = map[c];
				*b++ = c;
			}
		if (b >= e)
			break;
		n = 0;
		while (m < x)
		{
			n = (n<<7) | (*m & 0x7f);
			if (!(*m++ & 0x80))
				break;
		}
		if (n >= (x - m))
			break;
		m += n;
	}
	return b;
}

/*
 * check for magic table match in buf
 */

static char*
ckmagic(register Magic_t* mp, const char* file, char* buf, struct stat* st, unsigned long off)
{
	register Entry_t*	ep;
	register char*		p;
	register char*		b;
	register int		level = 0;
	int			call = -1;
	int			c;
	char*			q;
	char*			t;
	char*			base = 0;
	unsigned long		num;
	unsigned long		mask;
	regmatch_t		matches[10];

	mp->swap = 0;
	b = mp->msg[0] = buf;
	mp->mime = mp->cap[0] = 0;
	mp->keep[0] = 0;
	for (ep = mp->magic; ep; ep = ep->next)
	{
	fun:
		if (ep->nest == '{')
		{
			if (++level >= MAXNEST)
			{
				call = -1;
				level = 0;
				mp->keep[0] = 0;
				b = mp->msg[0];
				mp->mime = mp->cap[0];
				continue;
			}
			mp->keep[level] = mp->keep[level - 1] != 0;
			mp->msg[level] = b;
			mp->cap[level] = mp->mime;
		}
		switch (ep->cont)
		{
		case '#':
			if (mp->keep[level] && b > buf)
			{
				*b = 0;
				return buf;
			}
			mp->swap = 0;
			b = mp->msg[0] = buf;
			mp->mime = mp->cap[0] = 0;
			if (ep->type == ' ')
				continue;
			break;
		case '$':
			if (mp->keep[level] && call < (MAXNEST - 1))
			{
				mp->ret[++call] = ep;
				ep = ep->value.lab;
				goto fun;
			}
			continue;
		case ':':
			ep = mp->ret[call--];
			if (ep->op == 'l')
				goto fun;
			continue;
		case '|':
			if (mp->keep[level] > 1)
				goto checknest;
			/*FALLTHROUGH*/
		default:
			if (!mp->keep[level])
			{
				b = mp->msg[level];
				mp->mime = mp->cap[level];
				goto checknest;
			}
			break;
		}
		p = "";
		num = 0;
		if (!ep->expr)
			num = ep->offset + off;
		else
			switch (ep->offset)
			{
			case 0:
				num = strexpr(ep->expr, NiL, indirect, mp) + off;
				break;
			case INFO_atime:
				num = st->st_atime;
				ep->type = 'D';
				break;
			case INFO_blocks:
				num = iblocks(st);
				ep->type = 'N';
				break;
			case INFO_ctime:
				num = st->st_ctime;
				ep->type = 'D';
				break;
			case INFO_fstype:
				p = fmtfs(st);
				ep->type = toupper(ep->type);
				break;
			case INFO_gid:
				if (ep->type == 'e' || ep->type == 'm' || ep->type == 's')
				{
					p = fmtgid(st->st_gid);
					ep->type = toupper(ep->type);
				}
				else
				{
					num = st->st_gid;
					ep->type = 'N';
				}
				break;
			case INFO_mode:
				if (ep->type == 'e' || ep->type == 'm' || ep->type == 's')
				{
					p = fmtmode(st->st_mode, 0);
					ep->type = toupper(ep->type);
				}
				else
				{
					num = modex(st->st_mode);
					ep->type = 'N';
				}
				break;
			case INFO_mtime:
				num = st->st_ctime;
				ep->type = 'D';
				break;
			case INFO_name:
				if (!base)
				{
					if (base = strrchr(file, '/'))
						base++;
					else
						base = (char*)file;
				}
				p = base;
				ep->type = toupper(ep->type);
				break;
			case INFO_nlink:
				num = st->st_nlink;
				ep->type = 'N';
				break;
			case INFO_size:
				num = st->st_size;
				ep->type = 'N';
				break;
			case INFO_uid:
				if (ep->type == 'e' || ep->type == 'm' || ep->type == 's')
				{
					p = fmtuid(st->st_uid);
					ep->type = toupper(ep->type);
				}
				else
				{
					num = st->st_uid;
					ep->type = 'N';
				}
				break;
			}
		switch (ep->type)
		{

		case 'b':
			if (!(p = getdata(mp, num, 1)))
				goto next;
			num = *(unsigned char*)p;
			break;

		case 'h':
			if (!(p = getdata(mp, num, 2)))
				goto next;
			num = swapget(ep->swap ? (~ep->swap ^ mp->swap) : mp->swap, p, 2);
			break;

		case 'd':
		case 'l':
		case 'v':
			if (!(p = getdata(mp, num, 4)))
				goto next;
			num = swapget(ep->swap ? (~ep->swap ^ mp->swap) : mp->swap, p, 4);
			break;

		case 'q':
			if (!(p = getdata(mp, num, 8)))
				goto next;
			num = swapget(ep->swap ? (~ep->swap ^ mp->swap) : mp->swap, p, 8);
			break;

		case 'e':
			if (!(p = getdata(mp, num, 0)))
				goto next;
			/*FALLTHROUGH*/
		case 'E':
			if (!ep->value.sub)
				goto next;
			if ((c = regexec(ep->value.sub, p, elementsof(matches), matches, 0)) || (c = regsubexec(ep->value.sub, p, elementsof(matches), matches)))
			{
				c = mp->fbsz;
				if (c >= sizeof(mp->nbuf))
					c = sizeof(mp->nbuf) - 1;
				p = (char*)memcpy(mp->nbuf, p, c);
				p[c] = 0;
				ccmapstr(mp->x2n, p, c);
				if ((c = regexec(ep->value.sub, p, elementsof(matches), matches, 0)) || (c = regsubexec(ep->value.sub, p, elementsof(matches), matches)))
				{
					if (c != REG_NOMATCH)
						regmessage(mp, ep->value.sub, c);
					goto next;
				}
			}
			p = ep->value.sub->re_sub->re_buf;
			q = T(ep->desc);
			t = *q ? q : p;
			if (mp->keep[level]++ && b > buf && *(b - 1) != ' ' && *t && *t != ',' && *t != '.' && *t != '\b')
				*b++ = ' ';
			b += sfsprintf(b, PATH_MAX - (b - buf), *q ? q : "%s", p + (*p == '\b'));
			if (ep->mime)
				mp->mime = ep->mime;
			goto checknest;

		case 's':
			if (!(p = getdata(mp, num, ep->mask)))
				goto next;
			goto checkstr;
		case 'm':
			if (!(p = getdata(mp, num, 0)))
				goto next;
			/*FALLTHROUGH*/
		case 'M':
		case 'S':
		checkstr:
			for (;;)
			{
				if (*ep->value.str == '*' && !*(ep->value.str + 1) && isprint(*p))
					break;
				if ((ep->type == 'm' || ep->type == 'M') ? strmatch(p, ep->value.str) : !memcmp(p, ep->value.str, ep->mask))
					break;
				if (p == mp->nbuf || ep->mask >= sizeof(mp->nbuf))
					goto next;
				p = (char*)memcpy(mp->nbuf, p, ep->mask);
				p[ep->mask] = 0;
				ccmapstr(mp->x2n, p, ep->mask);
			}
			q = T(ep->desc);
			if (mp->keep[level]++ && b > buf && *(b - 1) != ' ' && *q && *q != ',' && *q != '.' && *q != '\b')
				*b++ = ' ';
			for (t = p; (c = *t) >= 0 && c <= 0177 && isprint(c) && c != '\n'; t++);
			*t = 0;
			b += sfsprintf(b, PATH_MAX - (b - buf), q + (*q == '\b'), p);
			*t = c;
			if (ep->mime)
				mp->mime = ep->mime;
			goto checknest;

		}
		if (mask = ep->mask)
			num &= mask;
		switch (ep->op)
		{

		case '=':
		case '@':
			if (num == ep->value.num)
				break;
			if (ep->cont != '#')
				goto next;
			if (!mask)
				mask = ~mask;
			if (ep->type == 'h')
			{
				if ((num = swapget(mp->swap = 1, p, 2) & mask) == ep->value.num)
				{
					if (!(mp->swap & (mp->swap + 1)))
						mp->swap = 7;
					goto swapped;
				}
			}
			else if (ep->type == 'l')
			{
				for (c = 1; c < 4; c++)
					if ((num = swapget(mp->swap = c, p, 4) & mask) == ep->value.num)
					{
						if (!(mp->swap & (mp->swap + 1)))
							mp->swap = 7;
						goto swapped;
					}
			}
			else if (ep->type == 'q')
			{
				for (c = 1; c < 8; c++)
					if ((num = swapget(mp->swap = c, p, 8) & mask) == ep->value.num)
						goto swapped;
			}
			goto next;

		case '!':
			if (num != ep->value.num)
				break;
			goto next;

		case '^':
			if (num ^ ep->value.num)
				break;
			goto next;

		case '>':
			if (num > ep->value.num)
				break;
			goto next;

		case '<':
			if (num < ep->value.num)
				break;
			goto next;

		case 'l':
			if (num > 0 && mp->keep[level] && call < (MAXNEST - 1))
			{
				if (!ep->value.loop->count)
				{
					ep->value.loop->count = num;
					ep->value.loop->offset = off;
					off = ep->value.loop->start;
				}
				else if (!--ep->value.loop->count)
				{
					off = ep->value.loop->offset;
					goto next;
				}
				else
					off += ep->value.loop->size;
				mp->ret[++call] = ep;
				ep = ep->value.loop->lab;
				goto fun;
			}
			goto next;

		case 'm':
			c = mp->swap;
			t = ckmagic(mp, file, b + (b > buf), st, num);
			mp->swap = c;
			if (!t)
				goto next;
			if (b > buf)
				*b = ' ';
			b += strlen(b);
			break;

		case 'r':
#if _UWIN
		{
			char*			e;
			Sfio_t*			rp;
			Sfio_t*			gp;

			if (!(t = strrchr(file, '.')))
				goto next;
			sfprintf(mp->tmp, "/reg/classes_root/%s", t);
			if (!(t = sfstruse(mp->tmp)) || !(rp = sfopen(NiL, t, "r")))
				goto next;
			*ep->desc = 0;
			*ep->mime = 0;
			gp = 0;
			while (t = sfgetr(rp, '\n', 1))
			{
				if (strneq(t, "Content Type=", 13))
				{
					ep->mime = vmnewof(mp->vm, ep->mime, char, sfvalue(rp), 0);
					strcpy(ep->mime, t + 13);
					if (gp)
						break;
				}
				else
				{
					sfprintf(mp->tmp, "/reg/classes_root/%s", t);
					if ((e = sfstruse(mp->tmp)) && (gp = sfopen(NiL, e, "r")))
					{
						ep->desc = vmnewof(mp->vm, ep->desc, char, strlen(t), 1);
						strcpy(ep->desc, t);
						if (*ep->mime)
							break;
					}
				}
			}
			sfclose(rp);
			if (!gp)
				goto next;
			if (!*ep->mime)
			{
				t = T(ep->desc);
				if (!strncasecmp(t, "microsoft", 9))
					t += 9;
				while (isspace(*t))
					t++;
				e = "application/x-ms-";
				ep->mime = vmnewof(mp->vm, ep->mime, char, strlen(t), strlen(e));
				e = strcopy(ep->mime, e);
				while ((c = *t++) && c != '.' && c != ' ')
					*e++ = isupper(c) ? tolower(c) : c;
				*e = 0;
			}
			while (t = sfgetr(gp, '\n', 1))
				if (*t && !streq(t, "\"\""))
				{
					ep->desc = vmnewof(mp->vm, ep->desc, char, sfvalue(gp), 0);
					strcpy(ep->desc, t);
					break;
				}
			sfclose(gp);
			if (!*ep->desc)
				goto next;
			if (!t)
				for (t = T(ep->desc); *t; t++)
					if (*t == '.')
						*t = ' ';
			if (!mp->keep[level])
				mp->keep[level] = 2;
			mp->mime = ep->mime;
			break;
		}
#else
			if (ep->cont == '#' && !mp->keep[level])
				mp->keep[level] = 1;
			goto next;
#endif

		case 'v':
			if (!(p = getdata(mp, num, 4)))
				goto next;
			c = 0;
			do
			{
				num++;
				c = (c<<7) | (*p & 0x7f);
			} while (*p++ & 0x80);
			if (!(p = getdata(mp, num, c)))
				goto next;
			if (mp->keep[level]++ && b > buf && *(b - 1) != ' ')
			{
				*b++ = ',';
				*b++ = ' ';
			}
			b = vcdecomp(b, buf + PATH_MAX, (unsigned char*)p, (unsigned char*)p + c);
			goto checknest;

		}
	swapped:
		q = T(ep->desc);
		if (mp->keep[level]++ && b > buf && *(b - 1) != ' ' && *q && *q != ',' && *q != '.' && *q != '\b')
			*b++ = ' ';
		if (ep->type == 'd' || ep->type == 'D')
			b += sfsprintf(b, PATH_MAX - (b - buf), q + (*q == '\b'), fmttime("%?%l", (time_t)num));
		else if (ep->type == 'v')
			b += sfsprintf(b, PATH_MAX - (b - buf), q + (*q == '\b'), fmtversion(num));
		else
			b += sfsprintf(b, PATH_MAX - (b - buf), q + (*q == '\b'), num);
		if (ep->mime && *ep->mime)
			mp->mime = ep->mime;
	checknest:
		if (ep->nest == '}')
		{
			if (!mp->keep[level])
			{
				b = mp->msg[level];
				mp->mime = mp->cap[level];
			}
			else if (level > 0)
				mp->keep[level - 1] = mp->keep[level];
			if (--level < 0)
			{
				level = 0;
				mp->keep[0] = 0;
			}
		}
		continue;
	next:
		if (ep->cont == '&')
			mp->keep[level] = 0;
		goto checknest;
	}
	if (mp->keep[level] && b > buf)
	{
		*b = 0;
		return buf;
	}
	return 0;
}

/*
 * check english language stats
 */

static int
ckenglish(register Magic_t* mp, int pun, int badpun)
{
	register char*	s;
	register int	vowl = 0;
	register int	freq = 0;
	register int	rare = 0;

	if (5 * badpun > pun)
		return 0;
	if (2 * mp->count[';'] > mp->count['E'] + mp->count['e'])
		return 0;
	if ((mp->count['>'] + mp->count['<'] + mp->count['/']) > mp->count['E'] + mp->count['e'])
		return 0;
	for (s = "aeiou"; *s; s++)
		vowl += mp->count[toupper(*s)] + mp->count[*s];
	for (s = "etaion"; *s; s++)
		freq += mp->count[toupper(*s)] + mp->count[*s];
	for (s = "vjkqxz"; *s; s++)
		rare += mp->count[toupper(*s)] + mp->count[*s];
	return 5 * vowl >= mp->fbsz - mp->count[' '] && freq >= 10 * rare;
}

/*
 * check programming language stats
 */

static char*
cklang(register Magic_t* mp, const char* file, char* buf, struct stat* st)
{
	register int		c;
	register unsigned char*	b;
	register unsigned char*	e;
	register int		q;
	register char*		s;
	char*			t;
	char*			base;
	char*			suff;
	char*			t1;
	char*			t2;
	char*			t3;
	int			n;
	int			badpun;
	int			code;
	int			pun;
	Cctype_t		flags;
	Info_t*			ip;

	b = (unsigned char*)mp->fbuf;
	e = b + mp->fbsz;
	memzero(mp->count, sizeof(mp->count));
	memzero(mp->multi, sizeof(mp->multi));
	memzero(mp->identifier, sizeof(mp->identifier));

	/*
	 * check character coding
	 */

	flags = 0;
	while (b < e)
		flags |= mp->cctype[*b++];
	b = (unsigned char*)mp->fbuf;
	code = 0;
	q = CC_ASCII;
	n = CC_MASK;
	for (c = 0; c < CC_MAPS; c++)
	{
		flags ^= CC_text;
		if ((flags & CC_MASK) < n)
		{
			n = flags & CC_MASK;
			q = c;
		}
		flags >>= CC_BIT;
	}
	flags = n;
	if (!(flags & (CC_binary|CC_notext)))
	{
		if (q != CC_NATIVE)
		{
			code = q;
			ccmaps(mp->fbuf, mp->fbsz, q, CC_NATIVE);
		}
		if (b[0] == '#' && b[1] == '!')
		{
			for (b += 2; b < e && isspace(*b); b++);
			for (s = (char*)b; b < e && isprint(*b); b++);
			c = *b;
			*b = 0;
			if ((st->st_mode & (S_IXUSR|S_IXGRP|S_IXOTH)) || match(s, "/*bin*/*") || !access(s, F_OK))
			{
				if (t = strrchr(s, '/'))
					s = t + 1;
				for (t = s; *t; t++)
					if (isspace(*t))
					{
						*t = 0;
						break;
					}
				sfsprintf(mp->mbuf, sizeof(mp->mbuf), "application/x-%s", *s ? s : "sh");
				mp->mime = mp->mbuf;
				if (match(s, "*sh"))
				{
					t1 = T("command");
					if (streq(s, "sh"))
						*s = 0;
					else
					{
						*b++ = ' ';
						*b = 0;
					}
				}
				else
				{
					t1 = T("interpreter");
					*b++ = ' ';
					*b = 0;
				}
				sfsprintf(mp->sbuf, sizeof(mp->sbuf), T("%s%s script"), s, t1);
				s = mp->sbuf;
				goto qualify;
			}
			*b = c;
			b = (unsigned char*)mp->fbuf;
		}
		badpun = 0;
		pun = 0;
		q = 0;
		s = 0;
		t = 0;
		while (b < e)
		{
			c = *b++;
			mp->count[c]++;
			if (c == q && (q != '*' || *b == '/' && b++))
			{
				mp->multi[q]++;
				q = 0;
			}
			else if (c == '\\')
			{
				s = 0;
				b++;
			}
			else if (!q)
			{
				if (isalpha(c) || c == '_')
				{
					if (!s)
						s = (char*)b - 1;
				}
				else if (!isdigit(c))
				{
					if (s)
					{
						if (s > mp->fbuf)
							switch (*(s - 1))
							{
							case ':':
								if (*b == ':')
									mp->multi[':']++;
								break;
							case '.':
								if (((char*)b - s) == 3 && (s == (mp->fbuf + 1) || *(s - 2) == '\n'))
									mp->multi['.']++;
								break;
							case '\n':
							case '\\':
								if (*b == '{')
									t = (char*)b + 1;
								break;
							case '{':
								if (s == t && *b == '}')
									mp->multi['X']++;
								break;
							}
						if (!mp->idtab)
						{
							if (mp->idtab = dtnew(mp->vm, &mp->dtdisc, Dthash))
								for (q = 0; q < elementsof(dict); q++)
									dtinsert(mp->idtab, &dict[q]);
							else if (mp->disc->errorf)
								(*mp->disc->errorf)(mp, mp->disc, 3, "out of space");
							q = 0;
						}
						if (mp->idtab)
						{
							*(b - 1) = 0;
							if (ip = (Info_t*)dtmatch(mp->idtab, s))
								mp->identifier[ip->value]++;
							*(b - 1) = c;
						}
						s = 0;
					}
					switch (c)
					{
					case '\t':
						if (b == (unsigned char*)(mp->fbuf + 1) || *(b - 2) == '\n')
							mp->multi['\t']++;
						break;
					case '"':
					case '\'':
						q = c;
						break;
					case '/':
						if (*b == '*')
							q = *b++;
						else if (*b == '/')
							q = '\n';
						break;
					case '$':
						if (*b == '(' && *(b + 1) != ' ')
							mp->multi['$']++;
						break;
					case '{':
					case '}':
					case '[':
					case ']':
					case '(':
						mp->multi[c]++;
						break;
					case ')':
						mp->multi[c]++;
						goto punctuation;
					case ':':
						if (*b == ':' && isspace(*(b + 1)) && b > (unsigned char*)(mp->fbuf + 1) && isspace(*(b - 2)))
							mp->multi[':']++;
						goto punctuation;
					case '.':
					case ',':
					case '%':
					case ';':
					case '?':
					punctuation:
						pun++;
						if (*b != ' ' && *b != '\n')
							badpun++;
						break;
					}
				}
			}
		}
	}
	else
		while (b < e)
			mp->count[*b++]++;
	base = (t1 = strrchr(file, '/')) ? t1 + 1 : (char*)file;
	suff = (t1 = strrchr(base, '.')) ? t1 + 1 : "";
	if (!flags)
	{
		if (match(suff, "*sh|bat|cmd"))
			goto id_sh;
		if (match(base, "*@(mkfile)"))
			goto id_mk;
		if (match(base, "*@(makefile|.mk)"))
			goto id_make;
		if (match(base, "*@(mamfile|.mam)"))
			goto id_mam;
		if (match(suff, "[cly]?(pp|xx|++)|cc|ll|yy"))
			goto id_c;
		if (match(suff, "f"))
			goto id_fortran;
		if (match(suff, "htm+(l)"))
			goto id_html;
		if (match(suff, "cpy"))
			goto id_copybook;
		if (match(suff, "cob|cbl|cb2"))
			goto id_cobol;
		if (match(suff, "pl[1i]"))
			goto id_pl1;
		if (match(suff, "tex"))
			goto id_tex;
		if (match(suff, "asm|s"))
			goto id_asm;
		if ((st->st_mode & (S_IXUSR|S_IXGRP|S_IXOTH)) && (!suff || suff != strchr(suff, '.')))
		{
		id_sh:
			s = T("command script");
			mp->mime = "application/sh";
			goto qualify;
		}
		if (strmatch(mp->fbuf, "From * [0-9][0-9]:[0-9][0-9]:[0-9][0-9] *"))
		{
			s = T("mail message");
			mp->mime = "message/rfc822";
			goto qualify;
		}
		if (match(base, "*@(mkfile)"))
		{
		id_mk:
			s = "mkfile";
			mp->mime = "application/mk";
			goto qualify;
		}
		if (match(base, "*@(makefile|.mk)") || mp->multi['\t'] >= mp->count[':'] && (mp->multi['$'] > 0 || mp->multi[':'] > 0))
		{
		id_make:
			s = "makefile";
			mp->mime = "application/make";
			goto qualify;
		}
		if (mp->multi['.'] >= 3)
		{
			s = T("nroff input");
			mp->mime = "application/x-troff";
			goto qualify;
		}
		if (mp->multi['X'] >= 3)
		{
			s = T("TeX input");
			mp->mime = "application/x-tex";
			goto qualify;
		}
		if (mp->fbsz < SF_BUFSIZE &&
		    (mp->multi['('] == mp->multi[')'] &&
		     mp->multi['{'] == mp->multi['}'] &&
		     mp->multi['['] == mp->multi[']']) ||
		    mp->fbsz >= SF_BUFSIZE &&
		    (mp->multi['('] >= mp->multi[')'] &&
		     mp->multi['{'] >= mp->multi['}'] &&
		     mp->multi['['] >= mp->multi[']']))
		{
			c = mp->identifier[ID_INCL1];
			if (c >= 2 && mp->identifier[ID_INCL2] >= c && mp->identifier[ID_INCL3] >= c && mp->count['.'] >= c ||
			    mp->identifier[ID_C] >= 5 && mp->count[';'] >= 5 ||
			    mp->count['='] >= 20 && mp->count[';'] >= 20)
			{
			id_c:
				t1 = "";
				t2 = "c ";
				t3 = T("program");
				switch (*suff)
				{
				case 'c':
				case 'C':
					mp->mime = "application/x-cc";
					break;
				case 'l':
				case 'L':
					t1 = "lex ";
					mp->mime = "application/x-lex";
					break;
				default:
					t3 = T("header");
					if (mp->identifier[ID_YACC] < 5 || mp->count['%'] < 5)
					{
						mp->mime = "application/x-cc";
						break;
					}
					/*FALLTHROUGH*/
				case 'y':
				case 'Y':
					t1 = "yacc ";
					mp->mime = "application/x-yacc";
					break;
				}
				if (mp->identifier[ID_CPLUSPLUS] >= 3)
				{
					t2 = "c++ ";
					mp->mime = "application/x-c++";
				}
				sfsprintf(mp->sbuf, sizeof(mp->sbuf), "%s%s%s", t1, t2, t3);
				s = mp->sbuf;
				goto qualify;
			}
		}
		if (mp->identifier[ID_MAM1] >= 2 && mp->identifier[ID_MAM3] >= 2 &&
		    (mp->fbsz < SF_BUFSIZE && mp->identifier[ID_MAM1] == mp->identifier[ID_MAM2] ||
		     mp->fbsz >= SF_BUFSIZE && mp->identifier[ID_MAM1] >= mp->identifier[ID_MAM2]))
		{
		id_mam:
			s = T("mam program");
			mp->mime = "application/x-mam";
			goto qualify;
		}
		if (mp->identifier[ID_FORTRAN] >= 8)
		{
		id_fortran:
			s = T("fortran program");
			mp->mime = "application/x-fortran";
			goto qualify;
		}
		if (mp->identifier[ID_HTML] > 0 && mp->count['<'] >= 8 && (c = mp->count['<'] - mp->count['>']) >= -2 && c <= 2)
		{
		id_html:
			s = T("html input");
			mp->mime = "text/html";
			goto qualify;
		}
		if (mp->identifier[ID_COPYBOOK] > 0 && mp->identifier[ID_COBOL] == 0 && (c = mp->count['('] - mp->count[')']) >= -2 && c <= 2)
		{
		id_copybook:
			s = T("cobol copybook");
			mp->mime = "application/x-cobol";
			goto qualify;
		}
		if (mp->identifier[ID_COBOL] > 0 && mp->identifier[ID_COPYBOOK] > 0 && (c = mp->count['('] - mp->count[')']) >= -2 && c <= 2)
		{
		id_cobol:
			s = T("cobol program");
			mp->mime = "application/x-cobol";
			goto qualify;
		}
		if (mp->identifier[ID_PL1] > 0 && (c = mp->count['('] - mp->count[')']) >= -2 && c <= 2)
		{
		id_pl1:
			s = T("pl1 program");
			mp->mime = "application/x-pl1";
			goto qualify;
		}
		if (mp->count['{'] >= 6 && (c = mp->count['{'] - mp->count['}']) >= -2 && c <= 2 && mp->count['\\'] >= mp->count['{'])
		{
		id_tex:
			s = T("TeX input");
			mp->mime = "text/tex";
			goto qualify;
		}
		if (mp->identifier[ID_ASM] >= 4)
		{
		id_asm:
			s = T("as program");
			mp->mime = "application/x-as";
			goto qualify;
		}
		if (ckenglish(mp, pun, badpun))
		{
			s = T("english text");
			mp->mime = "text/plain";
			goto qualify;
		}
	}
	else if (streq(base, "core"))
	{
		mp->mime = "x-system/core";
		return T("core dump");
	}
	if (flags & (CC_binary|CC_notext))
	{
		b = (unsigned char*)mp->fbuf;
		e = b + mp->fbsz;
		n = 0;
		for (;;)
		{
			c = *b++;
			q = 0;
			while (c & 0x80)
			{
				c <<= 1;
				q++;
			}
			switch (q)
			{
			case 4:
				if (b < e && (*b++ & 0xc0) != 0x80)
					break;
			case 3:
				if (b < e && (*b++ & 0xc0) != 0x80)
					break;
			case 2:
				if (b < e && (*b++ & 0xc0) != 0x80)
					break;
				n = 1;
			case 0:
				if (b >= e)
				{
					if (n)
					{
						flags &= ~(CC_binary|CC_notext);
						flags |= CC_utf_8;
					}
					break;
				}
				continue;
			}
			break;
		}
	}
	if (flags & (CC_binary|CC_notext))
	{
		unsigned long	d = 0;

		if ((q = mp->fbsz / UCHAR_MAX) >= 2)
		{
			/*
			 * compression/encryption via standard deviation
			 */


			for (c = 0; c < UCHAR_MAX; c++)
			{
				pun = mp->count[c] - q;
				d += pun * pun;
			}
			d /= mp->fbsz;
		}
		if (d <= 0)
			s = T("binary");
		else if (d < 4)
			s = T("encrypted");
		else if (d < 16)
			s = T("packed");
		else if (d < 64)
			s = T("compressed");
		else if (d < 256)
			s = T("delta");
		else
			s = T("data");
		mp->mime = "application/octet-stream";
		return s;
	}
	mp->mime = "text/plain";
	if (flags & CC_utf_8)
		s = (flags & CC_control) ? T("utf-8 text with control characters") : T("utf-8 text");
	else if (flags & CC_latin)
		s = (flags & CC_control) ? T("latin text with control characters") : T("latin text");
	else
		s = (flags & CC_control) ? T("text with control characters") : T("text");
 qualify:
	if (!flags && mp->count['\n'] >= mp->count['\r'] && mp->count['\n'] <= (mp->count['\r'] + 1) && mp->count['\r'])
	{
		t = "dos ";
		mp->mime = "text/dos";
	}
	else
		t = "";
	if (code)
	{
		if (code == CC_ASCII)
			sfsprintf(buf, PATH_MAX, "ascii %s%s", t, s);
		else
		{
			sfsprintf(buf, PATH_MAX, "ebcdic%d %s%s", code - 1, t, s);
			mp->mime = "text/ebcdic";
		}
		s = buf;
	}
	else if (*t)
	{
		sfsprintf(buf, PATH_MAX, "%s%s", t, s);
		s = buf;
	}
	return s;
}

/*
 * return the basic magic string for file,st in buf,size
 */

static char*
type(register Magic_t* mp, const char* file, struct stat* st, char* buf, int size)
{
	register char*	s;
	register char*	t;

	mp->mime = 0;
	if (!S_ISREG(st->st_mode))
	{
		if (S_ISDIR(st->st_mode))
		{
			mp->mime = "x-system/dir";
			return T("directory");
		}
		if (S_ISLNK(st->st_mode))
		{
			mp->mime = "x-system/lnk";
			s = buf;
			s += sfsprintf(s, PATH_MAX, T("symbolic link to "));
			if (pathgetlink(file, s, size - (s - buf)) < 0)
				return T("cannot read symbolic link text");
			return buf;
		}
		if (S_ISBLK(st->st_mode))
		{
			mp->mime = "x-system/blk";
			sfsprintf(buf, PATH_MAX, T("block special (%s)"), fmtdev(st));
			return buf;
		}
		if (S_ISCHR(st->st_mode))
		{
			mp->mime = "x-system/chr";
			sfsprintf(buf, PATH_MAX, T("character special (%s)"), fmtdev(st));
			return buf;
		}
		if (S_ISFIFO(st->st_mode))
		{
			mp->mime = "x-system/fifo";
			return "fifo";
		}
#ifdef S_ISSOCK
		if (S_ISSOCK(st->st_mode))
		{
			mp->mime = "x-system/sock";
			return "socket";
		}
#endif
	}
	if (!(mp->fbmx = st->st_size))
		s = T("empty");
	else if (!mp->fp)
		s = T("cannot read");
	else
	{
		mp->fbsz = sfread(mp->fp, mp->fbuf, sizeof(mp->fbuf) - 1);
		if (mp->fbsz < 0)
			s = fmterror(errno);
		else if (mp->fbsz == 0)
			s = T("empty");
		else
		{
			mp->fbuf[mp->fbsz] = 0;
			mp->xoff = 0;
			mp->xbsz = 0;
			if (!(s = ckmagic(mp, file, buf, st, 0)))
				s = cklang(mp, file, buf, st);
		}
	}
	if (!mp->mime)
		mp->mime = "application/unknown";
	else if ((t = strchr(mp->mime, '%')) && *(t + 1) == 's' && !*(t + 2))
	{
		register char*	b;
		register char*	be;
		register char*	m;
		register char*	me;

		b = mp->mime;
		me = (m = mp->mime = mp->fbuf) + sizeof(mp->fbuf) - 1;
		while (m < me && b < t)
			*m++ = *b++;
		b = t = s;
		for (;;)
		{
			if (!(be = strchr(t, ' ')))
			{
				be = b + strlen(b);
				break;
			}
			if (*(be - 1) == ',' || strneq(be + 1, "data", 4) || strneq(be + 1, "file", 4))
				break;
			b = t;
			t = be + 1;
		}
		while (m < me && b < be)
			if ((*m++ = *b++) == ' ')
				*(m - 1) = '-';
		*m = 0;
	}
	return s;
}

/*
 * low level for magicload()
 */

static int
load(register Magic_t* mp, char* file, register Sfio_t* fp)
{
	register Entry_t*	ep;
	register char*		p;
	register char*		p2;
	char*			p3;
	char*			next;
	int			n;
	int			lge;
	int			lev;
	int			ent;
	int			old;
	int			cont;
	Info_t*			ip;
	Entry_t*		ret;
	Entry_t*		first;
	Entry_t*		last = 0;
	Entry_t*		fun['z' - 'a' + 1];

	memzero(fun, sizeof(fun));
	cont = '$';
	ent = 0;
	lev = 0;
	old = 0;
	ret = 0;
	error_info.file = file;
	error_info.line = 0;
	first = ep = vmnewof(mp->vm, 0, Entry_t, 1, 0);
	while (p = sfgetr(fp, '\n', 1))
	{
		error_info.line++;
		for (; isspace(*p); p++);

		/*
		 * nesting
		 */

		switch (*p)
		{
		case 0:
		case '#':
			cont = '#';
			continue;
		case '{':
			if (++lev < MAXNEST)
				ep->nest = *p;
			else if ((mp->flags & MAGIC_VERBOSE) && mp->disc->errorf)
				(*mp->disc->errorf)(mp, mp->disc, 1, "{ ... } operator nesting too deep -- %d max", MAXNEST);
			continue;
		case '}':
			if (!last || lev <= 0)
			{
				if (mp->disc->errorf)
					(*mp->disc->errorf)(mp, mp->disc, 2, "`%c': invalid nesting", *p);
			}
			else if (lev-- == ent)
			{
				ent = 0;
				ep->cont = ':';
				ep->offset = ret->offset;
				ep->nest = ' ';
				ep->type = ' ';
				ep->op = ' ';
				ep->desc = "[RETURN]";
				last = ep;
				ep = ret->next = vmnewof(mp->vm, 0, Entry_t, 1, 0);
				ret = 0;
			}
			else
				last->nest = *p;
			continue;
		default:
			if (*(p + 1) == '{' || *(p + 1) == '(' && *p != '+' && *p != '>' && *p != '&' && *p != '|')
			{
				n = *p++;
				if (n >= 'a' && n <= 'z')
					n -= 'a';
				else
				{
					if (mp->disc->errorf)
						(*mp->disc->errorf)(mp, mp->disc, 2, "%c: invalid function name", n);
					n = 0;
				}
				if (ret && mp->disc->errorf)
					(*mp->disc->errorf)(mp, mp->disc, 2, "%c: function has no return", ret->offset + 'a');
				if (*p == '{')
				{
					ent = ++lev;
					ret = ep;
					ep->desc = "[FUNCTION]";
				}
				else
				{
					if (*(p + 1) != ')' && mp->disc->errorf)
						(*mp->disc->errorf)(mp, mp->disc, 2, "%c: invalid function call argument list", n + 'a');
					ep->desc = "[CALL]";
				}
				ep->cont = cont;
				ep->offset = n;
				ep->nest = ' ';
				ep->type = ' ';
				ep->op = ' ';
				last = ep;
				ep = ep->next = vmnewof(mp->vm, 0, Entry_t, 1, 0);
				if (ret)
					fun[n] = last->value.lab = ep;
				else if (!(last->value.lab = fun[n]) && mp->disc->errorf)
					(*mp->disc->errorf)(mp, mp->disc, 2, "%c: function not defined", n + 'a');
				continue;
			}
			if (!ep->nest)
				ep->nest = (lev > 0 && lev != ent) ? ('0' + lev - !!ent) : ' ';
			break;
		}

		/*
		 * continuation
		 */

		cont = '$';
		switch (*p)
		{
		case '>':
			old = 1;
			if (*(p + 1) == *p)
			{
				/*
				 * old style nesting push
				 */

				p++;
				old = 2;
				if (!lev && last)
				{
					lev = 1;
					last->nest = '{';
					if (last->cont == '>')
						last->cont = '&';
					ep->nest = '1';
				}
			}
			/*FALLTHROUGH*/
		case '+':
		case '&':
		case '|':
			ep->cont = *p++;
			break;
		default:
			if ((mp->flags & MAGIC_VERBOSE) && !isalpha(*p) && mp->disc->errorf)
				(*mp->disc->errorf)(mp, mp->disc, 1, "`%c': invalid line continuation operator", *p);
			/*FALLTHROUGH*/
		case '*':
		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
			ep->cont = (lev > 0) ? '&' : '#';
			break;
		}
		switch (old)
		{
		case 1:
			old = 0;
			if (lev)
			{
				/*
				 * old style nesting pop
				 */

				lev = 0;
				if (last)
					last->nest = '}';
				ep->nest = ' ';
				if (ep->cont == '&')
					ep->cont = '#';
			}
			break;
		case 2:
			old = 1;
			break;
		}
		if (isdigit(*p))
		{
			/*
			 * absolute offset
			 */

			ep->offset = strton(p, &next, NiL, 0);
			p2 = next;
		}
		else
		{
			for (p2 = p; *p2 && !isspace(*p2); p2++);
			if (!*p2)
			{
				if ((mp->flags & MAGIC_VERBOSE) && mp->disc->errorf)
					(*mp->disc->errorf)(mp, mp->disc, 1, "not enough fields: `%s'", p);
				continue;
			}

			/*
			 * offset expression
			 */

			*p2++ = 0;
			ep->expr = vmstrdup(mp->vm, p);
			if (isalpha(*p))
				ep->offset = (ip = (Info_t*)dtmatch(mp->infotab, p)) ? ip->value : 0;
			else if (*p == '(' && ep->cont == '>')
			{
				/*
				 * convert old style indirection to @
				 */

				p = ep->expr + 1;
				for (;;)
				{
					switch (*p++)
					{
					case 0:
					case '@':
					case '(':
						break;
					case ')':
						break;
					default:
						continue;
					}
					break;
				}
				if (*--p == ')')
				{
					*p = 0;
					*ep->expr = '@';
				}
			}
		}
		for (; isspace(*p2); p2++);
		for (p = p2; *p2 && !isspace(*p2); p2++);
		if (!*p2)
		{
			if ((mp->flags & MAGIC_VERBOSE) && mp->disc->errorf)
				(*mp->disc->errorf)(mp, mp->disc, 1, "not enough fields: `%s'", p);
			continue;
		}
		*p2++ = 0;

		/*
		 * type
		 */

		if ((*p == 'b' || *p == 'l') && *(p + 1) == 'e')
		{
			ep->swap = ~(*p == 'l' ? 7 : 0);
			p += 2;
		}
		if (*p == 's')
		{
			if (*(p + 1) == 'h')
				ep->type = 'h';
			else
				ep->type = 's';
		}
		else if (*p == 'a')
			ep->type = 's';
		else
			ep->type = *p;
		if (p = strchr(p, '&'))
		{
			/*
			 * old style mask
			 */

			ep->mask = strton(++p, NiL, NiL, 0);
		}
		for (; isspace(*p2); p2++);
		if (ep->mask)
			*--p2 = '=';

		/*
		 * comparison operation
		 */

		p = p2;
		if (p2 = strchr(p, '\t'))
			*p2++ = 0;
		else
		{
			int	qe = 0;
			int	qn = 0;

			/*
			 * assume balanced {}[]()\\""'' field
			 */

			for (p2 = p;;)
			{
				switch (n = *p2++)
				{
				case 0:
					break;
				case '{':
					if (!qe)
						qe = '}';
					if (qe == '}')
						qn++;
					continue;
				case '(':
					if (!qe)
						qe = ')';
					if (qe == ')')
						qn++;
					continue;
				case '[':
					if (!qe)
						qe = ']';
					if (qe == ']')
						qn++;
					continue;
				case '}':
				case ')':
				case ']':
					if (qe == n && qn > 0)
						qn--;
					continue;
				case '"':
				case '\'':
					if (!qe)
						qe = n;
					else if (qe == n)
						qe = 0;
					continue;
				case '\\':
					if (*p2)
						p2++;
					continue;
				default:
					if (!qe && isspace(n))
						break;
					continue;
				}
				if (n)
					*(p2 - 1) = 0;
				else
					p2--;
				break;
			}
		}
		lge = 0;
		if (ep->type == 'e' || ep->type == 'm' || ep->type == 's')
			ep->op = '=';
		else
		{
			if (*p == '&')
			{
				ep->mask = strton(++p, &next, NiL, 0);
				p = next;
			}
			switch (*p)
			{
			case '=':
			case '>':
			case '<':
			case '*':
				ep->op = *p++;
				if (*p == '=')
				{
					p++;
					switch (ep->op)
					{
					case '>':
						lge = -1;
						break;
					case '<':
						lge = 1;
						break;
					}
				}
				break;
			case '!':
			case '@':
				ep->op = *p++;
				if (*p == '=')
					p++;
				break;
			case 'x':
				p++;
				ep->op = '*';
				break;
			default:
				ep->op = '=';
				if (ep->mask)
					ep->value.num = ep->mask;
				break;
			}
		}
		if (ep->op != '*' && !ep->value.num)
		{
			if (ep->type == 'e')
			{
				if (ep->value.sub = vmnewof(mp->vm, 0, regex_t, 1, 0))
				{
					ep->value.sub->re_disc = &mp->redisc;
					if (!(n = regcomp(ep->value.sub, p, REG_DELIMITED|REG_LENIENT|REG_NULL|REG_DISCIPLINE)))
					{
						p += ep->value.sub->re_npat;
						if (!(n = regsubcomp(ep->value.sub, p, NiL, 0, 0)))
							p += ep->value.sub->re_npat;
					}
					if (n)
					{
						regmessage(mp, ep->value.sub, n);
						ep->value.sub = 0;
					}
					else if (*p && mp->disc->errorf)
						(*mp->disc->errorf)(mp, mp->disc, 1, "invalid characters after substitution: %s", p);
				}
			}
			else if (ep->type == 'm')
			{
				ep->mask = stresc(p) + 1;
				ep->value.str = vmnewof(mp->vm, 0, char, ep->mask + 1, 0);
				memcpy(ep->value.str, p, ep->mask);
				if ((!ep->expr || !ep->offset) && !strmatch(ep->value.str, "\\!\\(*\\)"))
					ep->value.str[ep->mask - 1] = '*';
			}
			else if (ep->type == 's')
			{
				ep->mask = stresc(p);
				ep->value.str = vmnewof(mp->vm, 0, char, ep->mask, 0);
				memcpy(ep->value.str, p, ep->mask);
			}
			else if (*p == '\'')
			{
				stresc(p);
				ep->value.num = *(unsigned char*)(p + 1) + lge;
			}
			else if (strmatch(p, "+([a-z])\\(*\\)"))
			{
				char*	t;

				t = p;
				ep->type = 'V';
				ep->op = *p;
				while (*p && *p++ != '(');
				switch (ep->op)
				{
				case 'l':
					n = *p++;
					if (n < 'a' || n > 'z')
					{
						if (mp->disc->errorf)
							(*mp->disc->errorf)(mp, mp->disc, 2, "%c: invalid function name", n);
					}
					else if (!fun[n -= 'a'])
					{
						if (mp->disc->errorf)
							(*mp->disc->errorf)(mp, mp->disc, 2, "%c: function not defined", n + 'a');
					}
					else
					{
						ep->value.loop = vmnewof(mp->vm, 0, Loop_t, 1, 0);
						ep->value.loop->lab = fun[n];
						while (*p && *p++ != ',');
						ep->value.loop->start = strton(p, &t, NiL, 0);
						while (*t && *t++ != ',');
						ep->value.loop->size = strton(t, &t, NiL, 0);
					}
					break;
				case 'm':
				case 'r':
					ep->desc = vmnewof(mp->vm, 0, char, 32, 0);
					ep->mime = vmnewof(mp->vm, 0, char, 32, 0);
					break;
				case 'v':
					break;
				default:
					if ((mp->flags & MAGIC_VERBOSE) && mp->disc->errorf)
						(*mp->disc->errorf)(mp, mp->disc, 1, "%-.*s: unknown function", p - t, t);
					break;
				}
			}
			else
			{
				ep->value.num = strton(p, NiL, NiL, 0) + lge;
				if (ep->op == '@')
					ep->value.num = swapget(0, (char*)&ep->value.num, sizeof(ep->value.num));
			}
		}

		/*
		 * file description
		 */

		if (p2)
		{
			for (; isspace(*p2); p2++);
			if (p = strchr(p2, '\t'))
			{
				/*
				 * check for message catalog index
				 */

				*p++ = 0;
				if (isalpha(*p2))
				{
					for (p3 = p2; isalnum(*p3); p3++);
					if (*p3++ == ':')
					{
						for (; isdigit(*p3); p3++);
						if (!*p3)
						{
							for (p2 = p; isspace(*p2); p2++);
							if (p = strchr(p2, '\t'))
								*p++ = 0;
						}
					}
				}
			}
			stresc(p2);
			ep->desc = vmstrdup(mp->vm, p2);
			if (p)
			{
				for (; isspace(*p); p++);
				if (*p)
					ep->mime = vmstrdup(mp->vm, p);
			}
		}
		else
			ep->desc = "";

		/*
		 * get next entry
		 */

		last = ep;
		ep = ep->next = vmnewof(mp->vm, 0, Entry_t, 1, 0);
	}
	if (last)
	{
		last->next = 0;
		if (mp->magiclast)
			mp->magiclast->next = first;
		else
			mp->magic = first;
		mp->magiclast = last;
	}
	vmfree(mp->vm, ep);
	if ((mp->flags & MAGIC_VERBOSE) && mp->disc->errorf)
	{
		if (lev < 0)
			(*mp->disc->errorf)(mp, mp->disc, 1, "too many } operators");
		else if (lev > 0)
			(*mp->disc->errorf)(mp, mp->disc, 1, "not enough } operators");
		if (ret)
			(*mp->disc->errorf)(mp, mp->disc, 2, "%c: function has no return", ret->offset + 'a');
	}
	error_info.file = 0;
	error_info.line = 0;
	return 0;
}

/*
 * load a magic file into mp
 */

int
magicload(register Magic_t* mp, const char* file, unsigned long flags)
{
	register char*		s;
	register char*		e;
	register char*		t;
	int			n;
	int			found;
	int			list;
	Sfio_t*			fp;

	mp->flags = mp->disc->flags | flags;
	found = 0;
	if (list = !(s = (char*)file) || !*s || (*s == '-' || *s == '.') && !*(s + 1))
	{
		if (!(s = getenv(MAGIC_FILE_ENV)) || !*s)
			s = MAGIC_FILE;
	}
	for (;;)
	{
		if (!list)
			e = 0;
		else if (e = strchr(s, ':'))
		{
			/*
			 * ok, so ~ won't work for the last list element
			 * we do it for MAGIC_FILES_ENV anyway
			 */

			if ((strneq(s, "~/", n = 2) || strneq(s, "$HOME/", n = 6) || strneq(s, "${HOME}/", n = 8)) && (t = getenv("HOME")))
			{
				sfputr(mp->tmp, t, -1);
				s += n - 1;
			}
			sfwrite(mp->tmp, s, e - s);
			if (!(s = sfstruse(mp->tmp)))
				goto nospace;
		}
		if (!*s || streq(s, "-"))
			s = MAGIC_FILE;
		if (!(fp = sfopen(NiL, s, "r")))
		{
			if (list)
			{
				if (!(t = pathpath(mp->fbuf, s, "", PATH_REGULAR|PATH_READ)) && !strchr(s, '/'))
				{
					strcpy(mp->fbuf, s);
					sfprintf(mp->tmp, "%s/%s", MAGIC_DIR, mp->fbuf);
					if (!(s = sfstruse(mp->tmp)))
						goto nospace;
					if (!(t = pathpath(mp->fbuf, s, "", PATH_REGULAR|PATH_READ)))
						goto next;
				}
				if (!(fp = sfopen(NiL, t, "r")))
					goto next;
			}
			else
			{
				if (mp->disc->errorf)
					(*mp->disc->errorf)(mp, mp->disc, 3, "%s: cannot open magic file", s);
				return -1;
			}
		}
		found = 1;
		n = load(mp, s, fp);
		sfclose(fp);
		if (n && !list)
			return -1;
	next:
		if (!e)
			break;
		s = e + 1;
	}
	if (!found)
	{
		if (mp->flags & MAGIC_VERBOSE)
		{
			if (mp->disc->errorf)
				(*mp->disc->errorf)(mp, mp->disc, 2, "cannot find magic file");
		}
		return -1;
	}
	return 0;
 nospace:
	if (mp->disc->errorf)
		(*mp->disc->errorf)(mp, mp->disc, 3, "out of space");
	return -1;
}

/*
 * open a magic session
 */

Magic_t*
magicopen(Magicdisc_t* disc)
{
	register Magic_t*	mp;
	register int		i;
	register int		n;
	register int		f;
	register int		c;
	register Vmalloc_t*	vm;
	unsigned char*		map[CC_MAPS + 1];

	if (!(vm = vmopen(Vmdcheap, Vmbest, 0)))
		return 0;
	if (!(mp = vmnewof(vm, 0, Magic_t, 1, 0)))
	{
		vmclose(vm);
		return 0;
	}
	mp->id = lib;
	mp->disc = disc;
	mp->vm = vm;
	mp->flags = disc->flags;
	mp->redisc.re_version = REG_VERSION;
	mp->redisc.re_flags = REG_NOFREE;
	mp->redisc.re_errorf = (regerror_t)disc->errorf;
	mp->redisc.re_resizef = (regresize_t)vmgetmem;
	mp->redisc.re_resizehandle = (void*)mp->vm;
	mp->dtdisc.key = offsetof(Info_t, name);
	mp->dtdisc.link = offsetof(Info_t, link);
	if (!(mp->tmp = sfstropen()) || !(mp->infotab = dtnew(mp->vm, &mp->dtdisc, Dthash)))
		goto bad;
	for (n = 0; n < elementsof(info); n++)
		dtinsert(mp->infotab, &info[n]);
	for (i = 0; i < CC_MAPS; i++)
		map[i] = ccmap(i, CC_ASCII);
	mp->x2n = ccmap(CC_ALIEN, CC_NATIVE);
	for (n = 0; n <= UCHAR_MAX; n++)
	{
		f = 0;
		i = CC_MAPS;
		while (--i >= 0)
		{
			c = ccmapchr(map[i], n);
			f = (f << CC_BIT) | CCTYPE(c);
		}
		mp->cctype[n] = f;
	}
	return mp;
 bad:
	magicclose(mp);
	return 0;
}

/*
 * close a magicopen() session
 */

int
magicclose(register Magic_t* mp)
{
	if (!mp)
		return -1;
	if (mp->tmp)
		sfstrclose(mp->tmp);
	if (mp->vm)
		vmclose(mp->vm);
	return 0;
}

/*
 * return the magic string for file with optional stat info st
 */

char*
magictype(register Magic_t* mp, Sfio_t* fp, const char* file, register struct stat* st)
{
	off_t	off;
	char*	s;

	mp->flags = mp->disc->flags;
	mp->mime = 0;
	if (!st)
		s = T("cannot stat");
	else
	{
		if (mp->fp = fp)
			off = sfseek(mp->fp, (off_t)0, SEEK_CUR);
		s = type(mp, file, st, mp->tbuf, sizeof(mp->tbuf));
		if (mp->fp)
			sfseek(mp->fp, off, SEEK_SET);
		if (!(mp->flags & MAGIC_MIME))
		{
			if (S_ISREG(st->st_mode) && (st->st_size > 0) && (st->st_size < 128))
				sfprintf(mp->tmp, "%s ", T("short"));
			sfprintf(mp->tmp, "%s", s);
			if (!mp->fp && (st->st_mode & (S_IXUSR|S_IXGRP|S_IXOTH)))
				sfprintf(mp->tmp, ", %s", S_ISDIR(st->st_mode) ? T("searchable") : T("executable"));
			if (st->st_mode & S_ISUID)
				sfprintf(mp->tmp, ", setuid=%s", fmtuid(st->st_uid));
			if (st->st_mode & S_ISGID)
				sfprintf(mp->tmp, ", setgid=%s", fmtgid(st->st_gid));
			if (st->st_mode & S_ISVTX)
				sfprintf(mp->tmp, ", sticky");
			if (!(s = sfstruse(mp->tmp)))
				s = T("out of space");
		}
	}
	if (mp->flags & MAGIC_MIME)
		s = mp->mime;
	if (!s)
		s = T("error");
	return s;
}

/*
 * list the magic table in mp on sp
 */

int
magiclist(register Magic_t* mp, register Sfio_t* sp)
{
	register Entry_t*	ep = mp->magic;
	register Entry_t*	rp = 0;

	mp->flags = mp->disc->flags;
	sfprintf(sp, "cont\toffset\ttype\top\tmask\tvalue\tmime\tdesc\n");
	while (ep)
	{
		sfprintf(sp, "%c %c\t", ep->cont, ep->nest);
		if (ep->expr)
			sfprintf(sp, "%s", ep->expr);
		else
			sfprintf(sp, "%ld", ep->offset);
		sfprintf(sp, "\t%s%c\t%c\t%lo\t", ep->swap == (char)~3 ? "L" : ep->swap == (char)~0 ? "B" : "", ep->type, ep->op, ep->mask);
		switch (ep->type)
		{
		case 'm':
		case 's':
			sfputr(sp, fmtesc(ep->value.str), -1);
			break;
		case 'V':
			switch (ep->op)
			{
			case 'l':
				sfprintf(sp, "loop(%d,%d,%d,%d)", ep->value.loop->start, ep->value.loop->size, ep->value.loop->count, ep->value.loop->offset);
				break;
			case 'v':
				sfprintf(sp, "vcodex()");
				break;
			default:
				sfprintf(sp, "%p", ep->value.str);
				break;
			}
			break;
		default:
			sfprintf(sp, "%lo", ep->value.num);
			break;
		}
		sfprintf(sp, "\t%s\t%s\n", ep->mime ? ep->mime : "", fmtesc(ep->desc));
		if (ep->cont == '$' && !ep->value.lab->mask)
		{
			rp = ep;
			ep = ep->value.lab;
		}
		else
		{
			if (ep->cont == ':')
			{
				ep = rp;
				ep->value.lab->mask = 1;
			}
			ep = ep->next;
		}
	}
	return 0;
}
