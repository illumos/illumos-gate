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
 * posix regex decompiler
 */

#include "reglib.h"

#undef	ismeta
#define ismeta(c,t,e,d)	(state.magic[c] && state.magic[c][(t)+(e)] >= T_META || (c) == (d))
#define meta(f,c,t,e,d)	do { if (ismeta(c,t,e,d)) sfputc(f, '\\'); sfputc(f, c); } while (0)

static void
detrie(Trie_node_t* x, Sfio_t* sp, char* b, char* p, char* e, int delimiter)
{
	register Trie_node_t*	y;
	char*			o;
	int			k;

	o = p;
	k = 1;
	do
	{
		if (k)
		{
			o = p;
			if (p < e)
				*p++ = x->c;
		}
		sfputc(sp, x->c);
		for (y = x->sib; y; y = y->sib)
		{
			sfputc(sp, '|');
			sfputc(sp, '<');
			sfwrite(sp, b, p - b);
			sfputc(sp, '>');
			detrie(y, sp, b, p, e, delimiter);
		}
		if (x->end && x->son)
		{
			sfputc(sp, '|');
			sfputc(sp, '{');
			sfwrite(sp, b, p - b);
			sfputc(sp, '}');
			p = o;
		}
	} while (x = x->son);
}

static int
decomp(register Rex_t* e, Sfio_t* sp, int type, int delimiter, regflags_t flags)
{
	Rex_t*		q;
	unsigned char*	s;
	unsigned char*	t;
	int		c;
	int		m;
	int		cb;
	int		cd;
	int		cr;
	int		ib;
	int		ie;
	int		nb;
	int		ne;
	unsigned char	ic[2*UCHAR_MAX];
	unsigned char	nc[2*UCHAR_MAX];

	do
	{
		switch (e->type)
		{
		case REX_ALT:
			if (decomp(e->re.group.expr.binary.left, sp, type, delimiter, flags))
				return 1;
			sfputc(sp, '|');
			if (e->re.group.expr.binary.right && decomp(e->re.group.expr.binary.right, sp, type, delimiter, flags))
				return 1;
			break;
		case REX_BACK:
			sfprintf(sp, "\\%d", e->lo);
			break;
		case REX_BEG:
			if (type < SRE)
				sfputc(sp, '^');
			break;
		case REX_END:
			if (type < SRE)
				sfputc(sp, '$');
			break;
		case REX_WBEG:
			meta(sp, '<', type, 1, delimiter);
			break;
		case REX_WEND:
			meta(sp, '<', type, 1, delimiter);
			break;
		case REX_WORD:
			sfprintf(sp, "\\w");
			break;
		case REX_CLASS:
		case REX_COLL_CLASS:
		case REX_ONECHAR:
		case REX_DOT:
		case REX_REP:
			if (type >= SRE)
			{
				c = ')';
				if (e->hi == RE_DUP_INF)
				{
					if (!e->lo)
						sfputc(sp, '*');
					else if (e->lo == 1)
						sfputc(sp, '+');
					else
						sfprintf(sp, "{%d,}", e->lo);
				}
				else if (e->hi != 1)
					sfprintf(sp, "{%d,%d}", e->lo, e->hi);
				else if (e->lo == 0)
					sfputc(sp, '?');
				else
					c = 0;
			}
			switch (e->type)
			{
			case REX_REP:
				if (decomp(e->re.group.expr.rex, sp, type, delimiter, flags))
					return 1;
				break;
			case REX_CLASS:
				sfputc(sp, '[');
				nb = ne = ib = ie = -2;
				cb = cd = cr = 0;
				s = nc;
				t = ic;
				for (m = 0; m <= UCHAR_MAX; m++)
					if (settst(e->re.charclass, m))
					{
						if (m == ']')
							cb = 1;
						else if (m == '-')
							cr = 1;
						else if (m == delimiter)
							cd = 1;
						else if (nb < 0)
							ne = nb = m;
						else if (ne == (m - 1))
							ne = m;
						else
						{
							if (ne == nb)
								*s++ = ne;
							else
							{
								*s++ = nb;
								*s++ = '-';
								*s++ = ne;
							}
							ne = nb = m;
						}
					}
					else
					{
						if (m == ']')
							cb = -1;
						else if (m == '-')
							cr = -1;
						else if (m == delimiter)
							cd = -1;
						else if (ib < 0)
							ie = ib = m;
						else if (ie == (m - 1))
							ie = m;
						else
						{
							if (ie == ib)
								*t++ = ie;
							else
							{
								*t++ = ib;
								*t++ = '-';
								*t++ = ie;
							}
							ie = ib = m;
						}
					}
				if (nb >= 0)
				{
					*s++ = nb;
					if (ne != nb)
					{
						*s++ = '-';
						*s++ = ne;
					}
				}
				if (ib >= 0)
				{
					*t++ = ib;
					if (ie != ib)
					{
						*t++ = '-';
						*t++ = ie;
					}
				}
				if ((t - ic + 1) < (s - nc + (nc[0] == '^')))
				{
					sfputc(sp, '^');
					if (cb < 0)
						sfputc(sp, ']');
					if (cr < 0)
						sfputc(sp, '-');
					if (cd < 0 && delimiter > 0)
					{
						if (flags & REG_ESCAPE)
							sfputc(sp, '\\');
						sfputc(sp, delimiter);
					}
					sfwrite(sp, ic, t - ic);
				}
				else
				{
					if (cb > 0)
						sfputc(sp, ']');
					if (cr > 0)
						sfputc(sp, '-');
					if (cd > 0 && delimiter > 0)
					{
						if (flags & REG_ESCAPE)
							sfputc(sp, '\\');
						sfputc(sp, delimiter);
					}
					if (nc[0] == '^')
					{
						sfwrite(sp, nc + 1, s - nc - 1);
						sfputc(sp, '^');
					}
					else
						sfwrite(sp, nc, s - nc);
				}
				sfputc(sp, ']');
				break;
			case REX_COLL_CLASS:
				break;
			case REX_ONECHAR:
				meta(sp, e->re.onechar, type, 0, delimiter);
				break;
			case REX_DOT:
				sfputc(sp, '.');
				break;
			}
			if (type < SRE)
			{
				if (e->hi == RE_DUP_INF)
				{
					if (!e->lo)
						sfputc(sp, '*');
					else if (e->lo == 1 && ismeta('+', type, 0, delimiter))
						meta(sp, '+', type, 1, delimiter);
					else
					{
						meta(sp, '{', type, 1, delimiter);
						sfprintf(sp, "%d,", e->lo);
						meta(sp, '}', type, 1, delimiter);
					}
				}
				else if (e->hi != 1 || e->lo == 0 && !ismeta('?', type, 0, delimiter))
				{
					meta(sp, '{', type, 1, delimiter);
					sfprintf(sp, "%d,%d", e->lo, e->hi);
					meta(sp, '}', type, 1, delimiter);
				}
				else if (e->lo == 0)
					meta(sp, '?', type, 1, delimiter);
			}
			else if (c)
				sfputc(sp, c);
			break;
		case REX_STRING:
		case REX_KMP:
			t = (s = e->re.string.base) + e->re.string.size;
			while (s < t)
			{
				c = *s++;
				meta(sp, c, type, 0, delimiter);
			}
			break;
		case REX_TRIE:
			ib = 0;
			for (c = 0; c <= UCHAR_MAX; c++)
				if (e->re.trie.root[c])
				{
					char	pfx[1024];

					if (ib)
						sfputc(sp, '|');
					else
						ib = 1;
					detrie(e->re.trie.root[c], sp, pfx, pfx, &pfx[sizeof(pfx)], delimiter);
				}
			break;
		case REX_NEG:
			if (type >= SRE)
				sfprintf(sp, "!(");
			if (decomp(e->re.group.expr.rex, sp, type, delimiter, flags))
				return 1;
			if (type >= SRE)
				sfputc(sp, ')');
			else
				sfputc(sp, '!');
			break;
		case REX_CONJ:
			if (decomp(e->re.group.expr.binary.left, sp, type, delimiter, flags))
				return 1;
			sfputc(sp, '&');
			if (decomp(e->re.group.expr.binary.right, sp, type, delimiter, flags))
				return 1;
			break;
		case REX_GROUP:
			if (type >= SRE)
				sfputc(sp, '@');
			meta(sp, '(', type, 1, delimiter);
			if (decomp(e->re.group.expr.rex, sp, type, delimiter, flags))
				return 1;
			meta(sp, ')', type, 1, delimiter);
			break;
		case REX_GROUP_AHEAD:
		case REX_GROUP_AHEAD_NOT:
		case REX_GROUP_BEHIND:
		case REX_GROUP_BEHIND_NOT:
			meta(sp, '(', type, 1, delimiter);
			sfputc(sp, '?');
			if (decomp(e->re.group.expr.rex, sp, type, delimiter, flags))
				return 1;
			meta(sp, ')', type, 1, delimiter);
			break;
		case REX_GROUP_COND:
			meta(sp, '(', type, 1, delimiter);
			sfputc(sp, '?');
			if (e->re.group.expr.binary.left && decomp(e->re.group.expr.binary.left, sp, type, delimiter, flags))
				return 1;
			if (q = e->re.group.expr.binary.right)
			{
				sfputc(sp, ':');
				if (q->re.group.expr.binary.left && decomp(q->re.group.expr.binary.left, sp, type, delimiter, flags))
					return 1;
				sfputc(sp, ':');
				if (q->re.group.expr.binary.right && decomp(q->re.group.expr.binary.right, sp, type, delimiter, flags))
					return 1;
			}
			meta(sp, ')', type, 1, delimiter);
			break;
		case REX_GROUP_CUT:
			meta(sp, '(', type, 1, delimiter);
			sfputc(sp, '?');
			if (decomp(e->re.group.expr.rex, sp, type, delimiter, flags))
				return 1;
			meta(sp, ')', type, 1, delimiter);
			break;
		case REX_BM:
			break;
		default:
			sfprintf(sp, "<ERROR:REX_%d>", e->type);
			break;
		}
	} while (e = e->next);
	return 0;
}

/*
 * reconstruct pattern from compiled re p into sp
 */

size_t
regdecomp(regex_t* p, regflags_t flags, char* buf, size_t n)
{
	Sfio_t*		sp;
	char*		s;
	int		type;
	int		delimiter;
	size_t		r;

	if (!(sp = sfstropen()))
		return 0;
	if (flags == (regflags_t)~0)
		flags = p->env->flags;
	switch (flags & (REG_AUGMENTED|REG_EXTENDED|REG_SHELL))
	{
	case 0:
		type = BRE;
		break;
	case REG_AUGMENTED:
	case REG_AUGMENTED|REG_EXTENDED:
		type = ARE;
		break;
	case REG_EXTENDED:
		type = ERE;
		break;
	case REG_SHELL:
		type = SRE;
		break;
	default:
		type = KRE;
		break;
	}
	if (flags & REG_DELIMITED)
	{
		delimiter = '/';
		sfputc(sp, delimiter);
	}
	else
		delimiter = -1;
	if (decomp(p->env->rex, sp, type, delimiter, flags))
		r = 0;
	else
	{
		if (delimiter > 0)
			sfputc(sp, delimiter);
		if ((r = sfstrtell(sp) + 1) <= n)
		{
			if (!(s = sfstruse(sp)))
				r = 0;
			else
				memcpy(buf, s, r);
		}
	}
	sfstrclose(sp);
	return r;
}
