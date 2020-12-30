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
 * posix regex executor
 * single sized-record interface
 */

#include "reglib.h"

#if _AST_REGEX_DEBUG

#define DEBUG_TEST(f,y,n)	((debug&(debug_flag=f))?(y):(n))
#define DEBUG_CODE(f,y,n)	do if(debug&(f)){y}else{n} while(0)
#define DEBUG_INIT()		do { char* t; if (!debug) { debug = 0x80000000; if (t = getenv("_AST_regex_exec_debug")) debug |= strtoul(t, NiL, 0); } } while (0)

static unsigned long	debug;
static unsigned long	debug_flag;

static const char*	rexnames[] =
{
	"REX_NULL",
	"REX_ALT",
	"REX_ALT_CATCH",
	"REX_BACK",
	"REX_BEG",
	"REX_BEG_STR",
	"REX_BM",
	"REX_CAT",
	"REX_CLASS",
	"REX_COLL_CLASS",
	"REX_CONJ",
	"REX_CONJ_LEFT",
	"REX_CONJ_RIGHT",
	"REX_DONE",
	"REX_DOT",
	"REX_END",
	"REX_END_STR",
	"REX_EXEC",
	"REX_FIN_STR",
	"REX_GROUP",
	"REX_GROUP_CATCH",
	"REX_GROUP_AHEAD",
	"REX_GROUP_AHEAD_CATCH",
	"REX_GROUP_AHEAD_NOT",
	"REX_GROUP_BEHIND",
	"REX_GROUP_BEHIND_CATCH",
	"REX_GROUP_BEHIND_NOT",
	"REX_GROUP_BEHIND_NOT_CATCH",
	"REX_GROUP_COND",
	"REX_GROUP_COND_CATCH",
	"REX_GROUP_CUT",
	"REX_GROUP_CUT_CATCH",
	"REX_KMP",
	"REX_NEG",
	"REX_NEG_CATCH",
	"REX_NEST",
	"REX_ONECHAR",
	"REX_REP",
	"REX_REP_CATCH",
	"REX_STRING",
	"REX_TRIE",
	"REX_WBEG",
	"REX_WEND",
	"REX_WORD",
	"REX_WORD_NOT"
};

static const char* rexname(Rex_t* rex)
{
	if (!rex)
		return "NIL";
	if (rex->type >= elementsof(rexnames))
		return "ERROR";
	return rexnames[rex->type];
}

#else

#define DEBUG_INIT()
#define DEBUG_TEST(f,y,n)	(n)
#define DEBUG_CODE(f,y,n)	do {n} while(0)

#endif

#define BEG_ALT		1	/* beginning of an alt			*/
#define BEG_ONE		2	/* beginning of one iteration of a rep	*/
#define BEG_REP		3	/* beginning of a repetition		*/
#define BEG_SUB		4	/* beginning of a subexpression		*/
#define END_ANY		5	/* end of any of above			*/

/*
 * returns from parse()
 */

#define NONE		0	/* no parse found			*/
#define GOOD		1	/* some parse was found			*/
#define CUT		2	/* no match and no backtrack		*/
#define BEST		3	/* an unbeatable parse was found	*/
#define BAD		4	/* error ocurred			*/

/*
 * REG_SHELL_DOT test
 */

#define LEADING(e,r,s)	(*(s)==(e)->leading&&((s)==(e)->beg||*((s)-1)==(r)->explicit))

/*
 * Pos_t is for comparing parses. An entry is made in the
 * array at the beginning and at the end of each Group_t,
 * each iteration in a Group_t, and each Binary_t.
 */

typedef struct
{
	unsigned char*	p;		/* where in string		*/
	size_t		length;		/* length in string		*/
	short		serial;		/* preorder subpattern number	*/
	short		be;		/* which end of pair		*/
} Pos_t;

/* ===== begin library support ===== */

#define vector(t,v,i)	(((i)<(v)->max)?(t*)((v)->vec+(i)*(v)->siz):(t*)vecseek(&(v),i))

static Vector_t*
vecopen(int inc, int siz)
{
	Vector_t*	v;
	Stk_t*		sp;

	if (inc <= 0)
		inc = 16;
	if (!(sp = stkopen(STK_SMALL|STK_NULL)))
		return 0;
	if (!(v = (Vector_t*)stkseek(sp, sizeof(Vector_t) + inc * siz)))
	{
		stkclose(sp);
		return 0;
	}
	v->stk = sp;
	v->vec = (char*)v + sizeof(Vector_t);
	v->max = v->inc = inc;
	v->siz = siz;
	v->cur = 0;
	return v;
}

static void*
vecseek(Vector_t** p, int index)
{
	Vector_t*	v = *p;

	if (index >= v->max)
	{
		while ((v->max += v->inc) <= index);
		if (!(v = (Vector_t*)stkseek(v->stk, sizeof(Vector_t) + v->max * v->siz)))
			return 0;
		*p = v;
		v->vec = (char*)v + sizeof(Vector_t);
	}
	return v->vec + index * v->siz;
}

static void
vecclose(Vector_t* v)
{
	if (v)
		stkclose(v->stk);
}

typedef struct
{
	Stk_pos_t	pos;
	char		data[1];
} Stk_frame_t;

#define stknew(s,p)	((p)->offset=stktell(s),(p)->base=stkfreeze(s,0))
#define stkold(s,p)	stkset(s,(p)->base,(p)->offset)

#define stkframe(s)	(*((Stk_frame_t**)stktop(s)-1))
#define stkdata(s,t)	((t*)stkframe(s)->data)
#define stkpop(s)	stkold(s,&(stkframe(s)->pos))

static void*
stkpush(Stk_t* sp, size_t size)
{
	Stk_frame_t*	f;
	Stk_pos_t	p;

	stknew(sp, &p);
	size = sizeof(Stk_frame_t) + sizeof(size_t) + size - 1;
	if (!(f = (Stk_frame_t*)stkalloc(sp, sizeof(Stk_frame_t) + sizeof(Stk_frame_t*) + size - 1)))
		return 0;
	f->pos = p;
	stkframe(sp) = f;
	return f->data;
}

/* ===== end library support ===== */

/*
 * Match_frame_t is for saving and restoring match records
 * around alternate attempts, so that fossils will not be
 * left in the match array.  These are the only entries in
 * the match array that are not otherwise guaranteed to
 * have current data in them when they get used.
 */

typedef struct
{
	size_t			size;
	regmatch_t*		match;
	regmatch_t		save[1];
} Match_frame_t;

#define matchpush(e,x)	((x)->re.group.number?_matchpush(e,x):0)
#define matchcopy(e,x)	do if ((x)->re.group.number) { Match_frame_t* fp = (void*)stkframe(stkstd)->data; memcpy(fp->match, fp->save, fp->size); } while (0)
#define matchpop(e,x)	do if ((x)->re.group.number) { Match_frame_t* fp = (void*)stkframe(stkstd)->data; memcpy(fp->match, fp->save, fp->size); stkpop(stkstd); } while (0)

#define pospop(e)	(--(e)->pos->cur)

/*
 * allocate a frame and push a match onto the stack
 */

static int
_matchpush(Env_t* env, Rex_t* rex)
{
	Match_frame_t*	f;
	regmatch_t*	m;
	regmatch_t*	e;
	regmatch_t*	s;
	int		num;

	if (rex->re.group.number <= 0 || (num = rex->re.group.last - rex->re.group.number + 1) <= 0)
		num = 0;
	if (!(f = (Match_frame_t*)stkpush(stkstd, sizeof(Match_frame_t) + (num - 1) * sizeof(regmatch_t))))
	{
		env->error = REG_ESPACE;
		return 1;
	}
	f->size = num * sizeof(regmatch_t);
	f->match = m = env->match + rex->re.group.number;
	e = m + num;
	s = f->save;
	while (m < e)
	{
		*s++ = *m;
		*m++ = state.nomatch;
	}
	return 0;
}

/*
 * allocate a frame and push a pos onto the stack
 */

static int
pospush(Env_t* env, Rex_t* rex, unsigned char* p, int be)
{
	Pos_t*	pos;

	if (!(pos = vector(Pos_t, env->pos, env->pos->cur)))
	{
		env->error = REG_ESPACE;
		return 1;
	}
	pos->serial = rex->serial;
	pos->p = p;
	pos->be = be;
	env->pos->cur++;
	return 0;
}

/*
 * two matches are known to have the same length
 * os is start of old pos array, ns is start of new,
 * oend and nend are end+1 pointers to ends of arrays.
 * oe and ne are ends (not end+1) of subarrays.
 * returns 1 if new is better, -1 if old, else 0.
 */

static int
better(Env_t* env, Pos_t* os, Pos_t* ns, Pos_t* oend, Pos_t* nend, int level)
{
	Pos_t*	oe;
	Pos_t*	ne;
	int	k;
	int	n;

	if (env->error)
		return -1;
	for (;;)
	{
		DEBUG_CODE(0x0080,{sfprintf(sfstdout, "   %-*.*sold ", (level + 3) * 4, (level + 3) * 4, "");for (oe = os; oe < oend; oe++)sfprintf(sfstdout, "<%d,%d,%d>", oe->p - env->beg, oe->serial, oe->be);sfprintf(sfstdout, "\n   %-*.*snew ", (level + 3) * 4, (level + 3) * 4, "");for (oe = ns; oe < nend; oe++)sfprintf(sfstdout, "<%d,%d,%d>", oe->p - env->beg, oe->serial, oe->be);sfprintf(sfstdout, "\n");},{0;});
		if (ns >= nend)
			return DEBUG_TEST(0x8000,(os < oend),(0));
		if (os >= oend)
			return DEBUG_TEST(0x8000,(-1),(1));
		n = os->serial;
		if (ns->serial > n)
			return -1;
		if (n > ns->serial)
		{
			env->error = REG_PANIC;
			return -1;
		}
		if (ns->p > os->p)
			return 1;
		if (os->p > ns->p)
			return -1;
		oe = os;
		k = 0;
		for (;;)
			if ((++oe)->serial == n)
			{
				if (oe->be != END_ANY)
					k++;
				else if (k-- <= 0)
					break;
			}
		ne = ns;
		k = 0;
		for (;;)
			if ((++ne)->serial == n)
			{
				if (ne->be != END_ANY)
					k++;
				else if (k-- <= 0)
					break;
			}
		if (ne->p > oe->p)
			return 1;
		if (oe->p > ne->p)
			return -1;
		if (k = better(env, os + 1, ns + 1, oe, ne, level + 1))
			return k;
		os = oe + 1;
		ns = ne + 1;
	}
}

#if _AST_REGEX_DEBUG

static void
showmatch(regmatch_t* p)
{
	sfputc(sfstdout, '(');
	if (p->rm_so < 0)
		sfputc(sfstdout, '?');
	else
		sfprintf(sfstdout, "%z", p->rm_so);
	sfputc(sfstdout, ',');
	if (p->rm_eo < 0)
		sfputc(sfstdout, '?');
	else
		sfprintf(sfstdout, "%z", p->rm_eo);
	sfputc(sfstdout, ')');
}

static int
_better(Env_t* env, Pos_t* os, Pos_t* ns, Pos_t* oend, Pos_t* nend, int level)
{
	int	i;

	DEBUG_CODE(0x0040,{sfprintf(sfstdout, "AHA better old ");for (i = 0; i <= env->nsub; i++)showmatch(&env->best[i]);sfprintf(sfstdout, "\n           new ");for (i = 0; i <= env->nsub; i++)showmatch(&env->match[i]);sfprintf(sfstdout, "\n");},{0;});
	i = better(env, os, ns, oend, nend, 0);
	DEBUG_TEST(0x0040,(sfprintf(sfstdout, "           %s\n", i <= 0 ? "OLD" : "NEW")),(0));
	return i;
}

#define better	_better

#endif

#define follow(e,r,c,s)	((r)->next?parse(e,(r)->next,c,s):(c)?parse(e,c,0,s):BEST)

static int		parse(Env_t*, Rex_t*, Rex_t*, unsigned char*);

static int
parserep(Env_t* env, Rex_t* rex, Rex_t* cont, unsigned char* s, int n)
{
	int	i;
	int	r = NONE;
	Rex_t	catcher;

	DEBUG_TEST(0x0010,(sfprintf(sfstdout, "AHA#%04d 0x%04x parserep %s %d %d %d %d `%-.*s'\n", __LINE__, debug_flag, rexname(rex->re.group.expr.rex), rex->re.group.number, rex->lo, n, rex->hi, env->end - s, s)),(0));
	if ((rex->flags & REG_MINIMAL) && n >= rex->lo && n < rex->hi)
	{
		if (env->stack && pospush(env, rex, s, END_ANY))
			return BAD;
		i = follow(env, rex, cont, s);
		if (env->stack)
			pospop(env);
		switch (i)
		{
		case BAD:
			return BAD;
		case CUT:
			return CUT;
		case BEST:
		case GOOD:
			return BEST;
		}
	}
	if (n < rex->hi)
	{
		catcher.type = REX_REP_CATCH;
		catcher.serial = rex->serial;
		catcher.re.rep_catch.ref = rex;
		catcher.re.rep_catch.cont = cont;
		catcher.re.rep_catch.beg = s;
		catcher.re.rep_catch.n = n + 1;
		catcher.next = rex->next;
		if (n == 0)
			rex->re.rep_catch.beg = s;
		if (env->stack)
		{
			if (matchpush(env, rex))
				return BAD;
			if (pospush(env, rex, s, BEG_ONE))	
				return BAD;
DEBUG_TEST(0x0004,(sfprintf(sfstdout,"AHA#%04d 0x%04x PUSH %d   (%z,%z)(%z,%z)(%z,%z) (%z,%z)(%z,%z)(%z,%z)\n", __LINE__, debug_flag, rex->re.group.number, env->best[0].rm_so, env->best[0].rm_eo, env->best[1].rm_so, env->best[1].rm_eo, env->best[2].rm_so, env->best[2].rm_eo, env->match[0].rm_so, env->match[0].rm_eo, env->match[1].rm_so, env->match[1].rm_eo, env->match[2].rm_so, env->match[2].rm_eo)),(0));
		}
		r = parse(env, rex->re.group.expr.rex, &catcher, s);
		DEBUG_TEST(0x0010,(sfprintf(sfstdout, "AHA#%04d 0x%04x parserep parse %d %d `%-.*s'\n", __LINE__, debug_flag, rex->re.group.number, r, env->end - s, s)),(0));
		if (env->stack)
		{
			pospop(env);
			matchpop(env, rex);
DEBUG_TEST(0x0004,(sfprintf(sfstdout,"AHA#%04d 0x%04x POP  %d %d (%z,%z)(%z,%z)(%z,%z) (%z,%z)(%z,%z)(%z,%z)\n", __LINE__, debug_flag, rex->re.group.number, r, env->best[0].rm_so, env->best[0].rm_eo, env->best[1].rm_so, env->best[1].rm_eo, env->best[2].rm_so, env->best[2].rm_eo, env->match[0].rm_so, env->match[0].rm_eo, env->match[1].rm_so, env->match[1].rm_eo, env->match[2].rm_so, env->match[2].rm_eo)),(0));
		}
		switch (r)
		{
		case BAD:
			return BAD;
		case BEST:
			return BEST;
		case CUT:
			r = NONE;
			break;
		case GOOD:
			if (rex->flags & REG_MINIMAL)
				return BEST;
			r = GOOD;
			break;
		}
	}
	if (n < rex->lo)
		return r;
	if (!(rex->flags & REG_MINIMAL) || n >= rex->hi)
	{
		if (env->stack && pospush(env, rex, s, END_ANY))
			return BAD;
		i = follow(env, rex, cont, s);
		if (env->stack)
			pospop(env);
		switch (i)
		{
		case BAD:
			r = BAD;
			break;
		case CUT:
			r = CUT;
			break;
		case BEST:
			r = BEST;
			break;
		case GOOD:
			r = (rex->flags & REG_MINIMAL) ? BEST : GOOD;
			break;
		}
	}
	return r;
}

static int
parsetrie(Env_t* env, Trie_node_t* x, Rex_t* rex, Rex_t* cont, unsigned char* s)
{
	unsigned char*	p;
	int		r;

	if (p = rex->map)
	{
		for (;;)
		{
			if (s >= env->end)
				return NONE;
			while (x->c != p[*s])
				if (!(x = x->sib))
					return NONE;
			if (x->end)
				break;
			x = x->son;
			s++;
		}
	}
	else
	{
		for (;;)
		{
			if (s >= env->end)
				return NONE;
			while (x->c != *s)
				if (!(x = x->sib))
					return NONE;
			if (x->end)
				break;
			x = x->son;
			s++;
		}
	}
	s++;
	if (rex->flags & REG_MINIMAL)
		switch (follow(env, rex, cont, s))
		{
		case BAD:
			return BAD;
		case CUT:
			return CUT;
		case BEST:
		case GOOD:
			return BEST;
		}
	if (x->son)
		switch (parsetrie(env, x->son, rex, cont, s))
		{
		case BAD:
			return BAD;
		case CUT:
			return CUT;
		case BEST:
			return BEST;
		case GOOD:
			if (rex->flags & REG_MINIMAL)
				return BEST;
			r = GOOD;
			break;
		default:
			r = NONE;
			break;
		}
	else
		r = NONE;
	if (!(rex->flags & REG_MINIMAL))
		switch (follow(env, rex, cont, s))
		{
		case BAD:
			return BAD;
		case CUT:
			return CUT;
		case BEST:
			return BEST;
		case GOOD:
			return GOOD;
	}
	return r;
}

static int
collelt(register Celt_t* ce, char* key, int c, int x)
{
	Ckey_t	elt;

	mbxfrm(elt, key, COLL_KEY_MAX);
	for (;; ce++)
	{
		switch (ce->typ)
		{
		case COLL_call:
			if (!x && (*ce->fun)(c))
				return 1;
			continue;
		case COLL_char:
			if (!strcmp((char*)ce->beg, (char*)elt))
				return 1;
			continue;
		case COLL_range:
			if (strcmp((char*)ce->beg, (char*)elt) <= ce->min && strcmp((char*)elt, (char*)ce->end) <= ce->max)
				return 1;
			continue;
		case COLL_range_lc:
			if (strcmp((char*)ce->beg, (char*)elt) <= ce->min && strcmp((char*)elt, (char*)ce->end) <= ce->max && (iswlower(c) || !iswupper(c)))
				return 1;
			continue;
		case COLL_range_uc:
			if (strcmp((char*)ce->beg, (char*)elt) <= ce->min && strcmp((char*)elt, (char*)ce->end) <= ce->max && (iswupper(c) || !iswlower(c)))
				return 1;
			continue;
		}
		break;
	}
	return 0;
}

static int
collic(register Celt_t* ce, char* key, register char* nxt, int c, int x)
{
	if (!x)
	{
		if (collelt(ce, key, c, x))
			return 1;
		if (iswlower(c))
			c = towupper(c);
		else if (iswupper(c))
			c = towlower(c);
		else
			return 0;
		x = mbconv(key, c);
		key[x] = 0;
		return collelt(ce, key, c, 0);
	}
	while (*nxt)
	{
		if (collic(ce, key, nxt + 1, c, x))
			return 1;
		if (islower(*nxt))
			*nxt = toupper(*nxt);
		else if (isupper(*nxt))
			*nxt = tolower(*nxt);
		else
			return 0;
		nxt++;
	}
	return collelt(ce, key, c, x);
}

static int
collmatch(Rex_t* rex, unsigned char* s, unsigned char* e, unsigned char** p)
{
	unsigned char*		t;
	wchar_t			c;
	int			w;
	int			r;
	int			x;
	int			ic;
	Ckey_t			key;
	Ckey_t			elt;

	ic = (rex->flags & REG_ICASE);
	if ((w = MBSIZE(s)) > 1)
	{
		memcpy((char*)key, (char*)s, w);
		key[w] = 0;
		t = s;
		c = mbchar(t);
#if !_lib_wctype
		c &= 0xff;
#endif
		x = 0;
	}
	else
	{
		c = s[0];
		if (ic && isupper(c))
			c = tolower(c);
		key[0] = c;
		key[1] = 0;
		if (isalpha(c))
		{
			x = e - s;
			if (x > COLL_KEY_MAX)
				x = COLL_KEY_MAX;
			while (w < x)
			{
				c = s[w];
				if (!isalpha(c))
					break;
				r = mbxfrm(elt, key, COLL_KEY_MAX);
				if (ic && isupper(c))
					c = tolower(c);
				key[w] = c;
				key[w + 1] = 0;
				if (mbxfrm(elt, key, COLL_KEY_MAX) != r)
					break;
				w++;
			}
		}
		key[w] = 0;
		c = key[0];
		x = w - 1;
	}
	r = 1;
	for (;;)
	{
		if (ic ? collic(rex->re.collate.elements, (char*)key, (char*)key, c, x) : collelt(rex->re.collate.elements, (char*)key, c, x))
			break;
		if (!x)
		{
			r = 0;
			break;
		}
		w = x--;
		key[w] = 0;
	}
	*p = s + w;
	return rex->re.collate.invert ? !r : r;
}

static unsigned char*
nestmatch(register unsigned char* s, register unsigned char* e, const unsigned short* type, register int co)
{
	register int	c;
	register int	cc;
	unsigned int	n;
	int		oc;

	if (type[co] & (REX_NEST_literal|REX_NEST_quote))
	{
		n = (type[co] & REX_NEST_literal) ? REX_NEST_terminator : (REX_NEST_escape|REX_NEST_terminator);
		while (s < e)
		{
			c = *s++;
			if (c == co)
				return s;
			else if (type[c] & n)
			{
				if (s >= e || (type[c] & REX_NEST_terminator))
					break;
				s++;
			}
		}
	}
	else
	{
		cc = type[co] >> REX_NEST_SHIFT;
		oc = type[co] & (REX_NEST_open|REX_NEST_close);
		n = 1;
		while (s < e)
		{
			c = *s++;
			switch (type[c] & (REX_NEST_escape|REX_NEST_open|REX_NEST_close|REX_NEST_delimiter|REX_NEST_separator|REX_NEST_terminator))
			{
			case REX_NEST_delimiter:
			case REX_NEST_terminator:
				return oc ? 0 : s;
			case REX_NEST_separator:
				if (!oc)
					return s;
				break;
			case REX_NEST_escape:
				if (s >= e)
					return 0;
				s++;
				break;
			case REX_NEST_open|REX_NEST_close:
				if (c == cc)
				{
					if (!--n)
						return s;
				}
				/*FALLTHROUGH*/
			case REX_NEST_open:
				if (c == co)
				{
					if (!++n)
						return 0;
				}
				else if (!(s = nestmatch(s, e, type, c)))
					return 0;
				break;
			case REX_NEST_close:
				if (c != cc)
					return 0;
				if (!--n)
					return s;
				break;
			}
		}
		return (oc || !(type[UCHAR_MAX+1] & REX_NEST_terminator)) ? 0 : s;
	}
	return 0;
}

static int
parse(Env_t* env, Rex_t* rex, Rex_t* cont, unsigned char* s)
{
	int		c;
	int		d;
	int		m;
	int		r;
	ssize_t		i;
	ssize_t		n;
	int*		f;
	unsigned char*	p;
	unsigned char*	t;
	unsigned char*	b;
	unsigned char*	e;
	char*		u;
	regmatch_t*	o;
	Trie_node_t*	x;
	Rex_t*		q;
	Rex_t		catcher;
	Rex_t		next;

	for (;;)
	{
DEBUG_TEST(0x0008,(sfprintf(sfstdout, "AHA#%04d 0x%04x parse %s `%-.*s'\n", __LINE__, debug_flag, rexname(rex), env->end - s, s)),(0));
		switch (rex->type)
		{
		case REX_ALT:
			if (env->stack)
			{
				if (matchpush(env, rex))
					return BAD;
				if (pospush(env, rex, s, BEG_ALT))
					return BAD;
				catcher.type = REX_ALT_CATCH;
				catcher.serial = rex->serial;
				catcher.re.alt_catch.cont = cont;
				catcher.next = rex->next;
				r = parse(env, rex->re.group.expr.binary.left, &catcher, s);
				if (r < BEST || (rex->flags & REG_MINIMAL))
				{
					matchcopy(env, rex);
					((Pos_t*)env->pos->vec + env->pos->cur - 1)->serial = catcher.serial = rex->re.group.expr.binary.serial;
					n = parse(env, rex->re.group.expr.binary.right, &catcher, s);
					if (n != NONE)
						r = n;
				}
				pospop(env);
				matchpop(env, rex);
			}
			else
			{
				if ((r = parse(env, rex->re.group.expr.binary.left, cont, s)) == NONE)
					r = parse(env, rex->re.group.expr.binary.right, cont, s);
				if (r == GOOD)
					r = BEST;
			}
			return r;
		case REX_ALT_CATCH:
			if (pospush(env, rex, s, END_ANY))
				return BAD;
			r = follow(env, rex, rex->re.alt_catch.cont, s);
			pospop(env);
			return r;
		case REX_BACK:
			o = &env->match[rex->lo];
			if (o->rm_so < 0)
				return NONE;
			i = o->rm_eo - o->rm_so;
			e = s + i;
			if (e > env->end)
				return NONE;
			t = env->beg + o->rm_so;
			if (!(p = rex->map))
			{
				while (s < e)
					if (*s++ != *t++)
						return NONE;
			}
			else if (!mbwide())
			{
				while (s < e)
					if (p[*s++] != p[*t++])
						return NONE;
			}
			else
			{
				while (s < e)
				{
					c = mbchar(s);
					d = mbchar(t);
					if (towupper(c) != towupper(d))
						return NONE;
				}
			}
			break;
		case REX_BEG:
			if ((!(rex->flags & REG_NEWLINE) || s <= env->beg || *(s - 1) != '\n') && ((env->flags & REG_NOTBOL) || s != env->beg))
				return NONE;
			break;
		case REX_CLASS:
			if (LEADING(env, rex, s))
				return NONE;
			n = rex->hi;
			if (n > env->end - s)
				n = env->end - s;
			m = rex->lo;
			if (m > n)
				return NONE;
			r = NONE;
			if (!(rex->flags & REG_MINIMAL))
			{
				for (i = 0; i < n; i++)
					if (!settst(rex->re.charclass, s[i]))
					{
						n = i;
						break;
					}
				for (s += n; n-- >= m; s--)
					switch (follow(env, rex, cont, s))
					{
					case BAD:
						return BAD;
					case CUT:
						return CUT;
					case BEST:
						return BEST;
					case GOOD:
						r = GOOD;
						break;
					}
			}
			else
			{
				for (e = s + m; s < e; s++)
					if (!settst(rex->re.charclass, *s))
						return r;
				e += n - m;
				for (;;)
				{
					switch (follow(env, rex, cont, s))
					{
					case BAD:
						return BAD;
					case CUT:
						return CUT;
					case BEST:
					case GOOD:
						return BEST;
					}
					if (s >= e || !settst(rex->re.charclass, *s))
						break;
					s++;
				}
			}
			return r;
		case REX_COLL_CLASS:
			if (LEADING(env, rex, s))
				return NONE;
			n = rex->hi;
			if (n > env->end - s)
				n = env->end - s;
			m = rex->lo;
			if (m > n)
				return NONE;
			r = NONE;
			e = env->end;
			if (!(rex->flags & REG_MINIMAL))
			{
				if (!(b = (unsigned char*)stkpush(stkstd, n)))
				{
					env->error = REG_ESPACE;
					return BAD;
				}
				for (i = 0; s < e && i < n && collmatch(rex, s, e, &t); i++)
				{
					b[i] = t - s;
					s = t;
				}
				for (; i-- >= rex->lo; s -= b[i])
					switch (follow(env, rex, cont, s))
					{
					case BAD:
						stkpop(stkstd);
						return BAD;
					case CUT:
						stkpop(stkstd);
						return CUT;
					case BEST:
						stkpop(stkstd);
						return BEST;
					case GOOD:
						r = GOOD;
						break;
					}
				stkpop(stkstd);
			}
			else
			{
				for (i = 0; i < m && s < e; i++, s = t)
					if (!collmatch(rex, s, e, &t))
						return r;
				while (i++ <= n)
				{
					switch (follow(env, rex, cont, s))
					{
					case BAD:
						return BAD;
					case CUT:
						return CUT;
					case BEST:
					case GOOD:
						return BEST;
					}
					if (s >= e || !collmatch(rex, s, e, &s))
						break;
				}
			}
			return r;
		case REX_CONJ:
			next.type = REX_CONJ_RIGHT;
			next.re.conj_right.cont = cont;
			next.next = rex->next;
			catcher.type = REX_CONJ_LEFT;
			catcher.re.conj_left.right = rex->re.group.expr.binary.right;
			catcher.re.conj_left.cont = &next;
			catcher.re.conj_left.beg = s;
			catcher.next = 0;
			return parse(env, rex->re.group.expr.binary.left, &catcher, s);
		case REX_CONJ_LEFT:
			rex->re.conj_left.cont->re.conj_right.end = s;
			cont = rex->re.conj_left.cont;
			s = rex->re.conj_left.beg;
			rex = rex->re.conj_left.right;
			continue;
		case REX_CONJ_RIGHT:
			if (rex->re.conj_right.end != s)
				return NONE;
			cont = rex->re.conj_right.cont;
			break;
		case REX_DONE:
			if (!env->stack)
				return BEST;
			n = s - env->beg;
			r = env->nsub;
			DEBUG_TEST(0x0100,(sfprintf(sfstdout,"AHA#%04d 0x%04x %s (%z,%z)(%z,%z)(%z,%z)(%z,%z) (%z,%z)(%z,%z)\n", __LINE__, debug_flag, rexname(rex), env->best[0].rm_so, env->best[0].rm_eo, env->best[1].rm_so, env->best[1].rm_eo, env->best[2].rm_so, env->best[2].rm_eo, env->best[3].rm_so, env->best[3].rm_eo, env->match[0].rm_so, env->match[0].rm_eo, env->match[1].rm_so, env->match[1].rm_eo)),(0));
			if ((i = env->best[0].rm_eo) >= 0)
			{
				if (rex->flags & REG_MINIMAL)
				{
					if (n > i)
						return GOOD;
				}
				else
				{
					if (n < i)
						return GOOD;
				}
				if (n == i && better(env,
						     (Pos_t*)env->bestpos->vec,
				   		     (Pos_t*)env->pos->vec,
				   		     (Pos_t*)env->bestpos->vec+env->bestpos->cur,
				   		     (Pos_t*)env->pos->vec+env->pos->cur,
						     0) <= 0)
					return GOOD;
			}
			env->best[0].rm_eo = n;
			memcpy(&env->best[1], &env->match[1], r * sizeof(regmatch_t));
			n = env->pos->cur;
			if (!vector(Pos_t, env->bestpos, n))
			{
				env->error = REG_ESPACE;
				return BAD;
			}
			env->bestpos->cur = n;
			memcpy(env->bestpos->vec, env->pos->vec, n * sizeof(Pos_t));
			DEBUG_TEST(0x0100,(sfprintf(sfstdout,"AHA#%04d 0x%04x %s (%z,%z)(%z,%z)(%z,%z)(%z,%z) (%z,%z)(%z,%z)\n", __LINE__, debug_flag, rexname(rex), env->best[0].rm_so, env->best[0].rm_eo, env->best[1].rm_so, env->best[1].rm_eo, env->best[2].rm_so, env->best[2].rm_eo, env->best[3].rm_so, env->best[3].rm_eo, env->match[0].rm_so, env->match[0].rm_eo, env->match[1].rm_so, env->match[1].rm_eo)),(0));
			return GOOD;
		case REX_DOT:
			if (LEADING(env, rex, s))
				return NONE;
			n = rex->hi;
			if (n > env->end - s)
				n = env->end - s;
			m = rex->lo;
			if (m > n)
				return NONE;
			if ((c = rex->explicit) >= 0 && !mbwide())
				for (i = 0; i < n; i++)
					if (s[i] == c)
					{
						n = i;
						break;
					}
			r = NONE;
			if (!(rex->flags & REG_MINIMAL))
			{
				if (!mbwide())
				{
					for (s += n; n-- >= m; s--)
						switch (follow(env, rex, cont, s))
						{
						case BAD:
							return BAD;
						case CUT:
							return CUT;
						case BEST:
							return BEST;
						case GOOD:
							r = GOOD;
							break;
						}
				}
				else
				{
					if (!(b = (unsigned char*)stkpush(stkstd, n)))
					{
						env->error = REG_ESPACE;
						return BAD;
					}
					e = env->end;
					for (i = 0; s < e && i < n && *s != c; i++)
						s += b[i] = MBSIZE(s);
					for (; i-- >= m; s -= b[i])
						switch (follow(env, rex, cont, s))
						{
						case BAD:
							stkpop(stkstd);
							return BAD;
						case CUT:
							stkpop(stkstd);
							return CUT;
						case BEST:
							stkpop(stkstd);
							return BEST;
						case GOOD:
							r = GOOD;
							break;
						}
					stkpop(stkstd);
				}
			}
			else
			{
				if (!mbwide())
				{
					e = s + n;
					for (s += m; s <= e; s++)
						switch (follow(env, rex, cont, s))
						{
						case BAD:
							return BAD;
						case CUT:
							return CUT;
						case BEST:
						case GOOD:
							return BEST;
						}
				}
				else
				{
					e = env->end;
					for (i = 0; s < e && i < m && *s != c; i++)
						s += MBSIZE(s);
					if (i >= m)
						for (; s <= e && i <= n; s += MBSIZE(s), i++)
							switch (follow(env, rex, cont, s))
							{
							case BAD:
								return BAD;
							case CUT:
								return CUT;
							case BEST:
							case GOOD:
								return BEST;
							}
				}
			}
			return r;
		case REX_END:
			if ((!(rex->flags & REG_NEWLINE) || *s != '\n') && ((env->flags & REG_NOTEOL) || s < env->end))
				return NONE;
			break;
		case REX_GROUP:
DEBUG_TEST(0x0200,(sfprintf(sfstdout,"AHA#%04d 0x%04x parse %s `%-.*s'\n", __LINE__, debug_flag, rexname(rex), env->end - s, s)),(0));
			if (env->stack)
			{
				if (rex->re.group.number)
					env->match[rex->re.group.number].rm_so = s - env->beg;
				if (pospush(env, rex, s, BEG_SUB))
					return BAD;
				catcher.re.group_catch.eo = rex->re.group.number ? &env->match[rex->re.group.number].rm_eo : (regoff_t*)0;
			}
			catcher.type = REX_GROUP_CATCH;
			catcher.serial = rex->serial;
			catcher.re.group_catch.cont = cont;
			catcher.next = rex->next;
			r = parse(env, rex->re.group.expr.rex, &catcher, s);
			if (env->stack)
			{
				pospop(env);
				if (rex->re.group.number)
					env->match[rex->re.group.number].rm_so = -1;
			}
			return r;
		case REX_GROUP_CATCH:
DEBUG_TEST(0x0200,(sfprintf(sfstdout,"AHA#%04d 0x%04x parse %s=>%s `%-.*s'\n", __LINE__, debug_flag, rexname(rex), rexname(rex->re.group_catch.cont), env->end - s, s)),(0));
			if (env->stack)
			{
				if (rex->re.group_catch.eo)
					*rex->re.group_catch.eo = s - env->beg;
				if (pospush(env, rex, s, END_ANY))
					return BAD;
			}
			r = follow(env, rex, rex->re.group_catch.cont, s);
			if (env->stack)
			{
				pospop(env);
				if (rex->re.group_catch.eo)
					*rex->re.group_catch.eo = -1;
			}
			return r;
		case REX_GROUP_AHEAD:
			catcher.type = REX_GROUP_AHEAD_CATCH;
			catcher.flags = rex->flags;
			catcher.serial = rex->serial;
			catcher.re.rep_catch.beg = s;
			catcher.re.rep_catch.cont = cont;
			catcher.next = rex->next;
			return parse(env, rex->re.group.expr.rex, &catcher, s);
		case REX_GROUP_AHEAD_CATCH:
			return follow(env, rex, rex->re.rep_catch.cont, rex->re.rep_catch.beg);
		case REX_GROUP_AHEAD_NOT:
			r = parse(env, rex->re.group.expr.rex, NiL, s);
			if (r == NONE)
				r = follow(env, rex, cont, s);
			else if (r != BAD)
				r = NONE;
			return r;
		case REX_GROUP_BEHIND:
			if ((s - env->beg) < rex->re.group.size)
				return NONE;
			catcher.type = REX_GROUP_BEHIND_CATCH;
			catcher.flags = rex->flags;
			catcher.serial = rex->serial;
			catcher.re.behind_catch.beg = s;
			catcher.re.behind_catch.end = e = env->end;
			catcher.re.behind_catch.cont = cont;
			catcher.next = rex->next;
			for (t = s - rex->re.group.size; t >= env->beg; t--)
			{
				env->end = s;
				r = parse(env, rex->re.group.expr.rex, &catcher, t);
				env->end = e;
				if (r != NONE)
					return r;
			}
			return NONE;
		case REX_GROUP_BEHIND_CATCH:
			if (s != rex->re.behind_catch.beg)
				return NONE;
			env->end = rex->re.behind_catch.end;
			return follow(env, rex, rex->re.behind_catch.cont, rex->re.behind_catch.beg);
		case REX_GROUP_BEHIND_NOT:
			if ((s - env->beg) < rex->re.group.size)
				r = NONE;
			else
			{
				catcher.type = REX_GROUP_BEHIND_NOT_CATCH;
				catcher.re.neg_catch.beg = s;
				catcher.next = 0;
				e = env->end;
				env->end = s;
				for (t = s - rex->re.group.size; t >= env->beg; t--)
				{
					r = parse(env, rex->re.group.expr.rex, &catcher, t);
					if (r != NONE)
						break;
				}
				env->end = e;
			}
			if (r == NONE)
				r = follow(env, rex, cont, s);
			else if (r != BAD)
				r = NONE;
			return r;
		case REX_GROUP_BEHIND_NOT_CATCH:
			return s == rex->re.neg_catch.beg ? GOOD : NONE;
		case REX_GROUP_COND:
			if (q = rex->re.group.expr.binary.right)
			{
				catcher.re.cond_catch.next[0] = q->re.group.expr.binary.right;
				catcher.re.cond_catch.next[1] = q->re.group.expr.binary.left;
			}
			else
				catcher.re.cond_catch.next[0] = catcher.re.cond_catch.next[1] = 0;
			if (q = rex->re.group.expr.binary.left)
			{
				catcher.type = REX_GROUP_COND_CATCH;
				catcher.flags = rex->flags;
				catcher.serial = rex->serial;
				catcher.re.cond_catch.yes = 0;
				catcher.re.cond_catch.beg = s;
				catcher.re.cond_catch.cont = cont;
				catcher.next = rex->next;
				r = parse(env, q, &catcher, s);
				if (r == BAD || catcher.re.cond_catch.yes)
					return r;
			}
			else if (!rex->re.group.size || rex->re.group.size > 0 && env->match[rex->re.group.size].rm_so >= 0)
				r = GOOD;
			else
				r = NONE;
			if (q = catcher.re.cond_catch.next[r != NONE])
			{
				catcher.type = REX_CAT;
				catcher.flags = q->flags;
				catcher.serial = q->serial;
				catcher.re.group_catch.cont = cont;
				catcher.next = rex->next;
				return parse(env, q, &catcher, s);
			}
			return follow(env, rex, cont, s);
		case REX_GROUP_COND_CATCH:
			rex->re.cond_catch.yes = 1;
			catcher.type = REX_CAT;
			catcher.flags = rex->flags;
			catcher.serial = rex->serial;
			catcher.re.group_catch.cont = rex->re.cond_catch.cont;
			catcher.next = rex->next;
			return parse(env, rex->re.cond_catch.next[1], &catcher, rex->re.cond_catch.beg);
		case REX_CAT:
			return follow(env, rex, rex->re.group_catch.cont, s);
		case REX_GROUP_CUT:
			catcher.type = REX_GROUP_CUT_CATCH;
			catcher.flags = rex->flags;
			catcher.serial = rex->serial;
			catcher.re.group_catch.cont = cont;
			catcher.next = rex->next;
			return parse(env, rex->re.group.expr.rex, &catcher, s);
		case REX_GROUP_CUT_CATCH:
			switch (r = follow(env, rex, rex->re.group_catch.cont, s))
			{
			case GOOD:
				r = BEST;
				break;
			case NONE:
				r = CUT;
				break;
			}
			return r;
		case REX_KMP:
			f = rex->re.string.fail;
			b = rex->re.string.base;
			n = rex->re.string.size;
			t = s;
			e = env->end;
			if (p = rex->map)
			{
				while (t + n <= e)
				{
					for (i = -1; t < e; t++)
					{
						while (i >= 0 && b[i+1] != p[*t])
							i = f[i];
						if (b[i+1] == p[*t])
							i++;
						if (i + 1 == n)
						{
							t++;
							if (env->stack)
								env->best[0].rm_so = t - s - n;
							switch (follow(env, rex, cont, t))
							{
							case BAD:
								return BAD;
							case CUT:
								return CUT;
							case BEST:
							case GOOD:
								return BEST;
							}
							t -= n - 1;
							break;
						}
					}
				}
			}
			else
			{
				while (t + n <= e)
				{
					for (i = -1; t < e; t++)
					{
						while (i >= 0 && b[i+1] != *t)
							i = f[i];
						if (b[i+1] == *t)
							i++;
						if (i + 1 == n)
						{
							t++;
							if (env->stack)
								env->best[0].rm_so = t - s - n;
							switch (follow(env, rex, cont, t))
							{
							case BAD:
								return BAD;
							case CUT:
								return CUT;
							case BEST:
							case GOOD:
								return BEST;
							}
							t -= n - 1;
							break;
						}
					}
				}
			}
			return NONE;
		case REX_NEG:
			if (LEADING(env, rex, s))
				return NONE;
			i = env->end - s;
			n = ((i + 7) >> 3) + 1;
			catcher.type = REX_NEG_CATCH;
			catcher.re.neg_catch.beg = s;
			if (!(p = (unsigned char*)stkpush(stkstd, n)))
				return BAD;
			memset(catcher.re.neg_catch.index = p, 0, n);
			catcher.next = rex->next;
			if (parse(env, rex->re.group.expr.rex, &catcher, s) == BAD)
				r = BAD;
			else
			{
				r = NONE;
				for (; i >= 0; i--)
					if (!bittst(p, i))
					{
						switch (follow(env, rex, cont, s + i))
						{
						case BAD:
							r = BAD;
							break;
						case BEST:
							r = BEST;
							break;
						case CUT:
							r = CUT;
							break;
						case GOOD:
							r = GOOD;
							/*FALLTHROUGH*/
						default:
							continue;
						}
						break;
					}
			}
			stkpop(stkstd);
			return r;
		case REX_NEG_CATCH:
			bitset(rex->re.neg_catch.index, s - rex->re.neg_catch.beg);
			return NONE;
		case REX_NEST:
			if (s >= env->end)
				return NONE;
			do
			{
				if ((c = *s++) == rex->re.nest.primary)
				{
					if (s >= env->end || !(s = nestmatch(s, env->end, rex->re.nest.type, c)))
						return NONE;
					break;
				}
				if (rex->re.nest.primary >= 0)
					return NONE;
			    	if (rex->re.nest.type[c] & (REX_NEST_delimiter|REX_NEST_separator|REX_NEST_terminator))
					break;
			    	if (!(s = nestmatch(s, env->end, rex->re.nest.type, c)))
					return NONE;
			} while (s < env->end && !(rex->re.nest.type[*(s-1)] & (REX_NEST_delimiter|REX_NEST_separator|REX_NEST_terminator)));
			break;
		case REX_NULL:
			break;
		case REX_ONECHAR:
			n = rex->hi;
			if (n > env->end - s)
				n = env->end - s;
			m = rex->lo;
			if (m > n)
				return NONE;
			r = NONE;
			c = rex->re.onechar;
			if (!(rex->flags & REG_MINIMAL))
			{
				if (!mbwide())
				{
					if (p = rex->map)
					{
						for (i = 0; i < n; i++, s++)
							if (p[*s] != c)
								break;
					}
					else
					{
						for (i = 0; i < n; i++, s++)
							if (*s != c)
								break;
					}
					for (; i-- >= m; s--)
						switch (follow(env, rex, cont, s))
						{
						case BAD:
							return BAD;
						case BEST:
							return BEST;
						case CUT:
							return CUT;
						case GOOD:
							r = GOOD;
							break;
						}
				}
				else
				{
					if (!(b = (unsigned char*)stkpush(stkstd, n)))
					{
						env->error = REG_ESPACE;
						return BAD;
					}
					e = env->end;
					if (!(rex->flags & REG_ICASE))
					{
						for (i = 0; s < e && i < n; i++, s = t)
						{
							t = s;
							if (mbchar(t) != c)
								break;
							b[i] = t - s;
						}
					}
					else
					{
						for (i = 0; s < e && i < n; i++, s = t)
						{
							t = s;
							if (towupper(mbchar(t)) != c)
								break;
							b[i] = t - s;
						}
					}
					for (; i-- >= m; s -= b[i])
						switch (follow(env, rex, cont, s))
						{
						case BAD:
							stkpop(stkstd);
							return BAD;
						case BEST:
							stkpop(stkstd);
							return BEST;
						case CUT:
							stkpop(stkstd);
							return CUT;
						case GOOD:
							r = GOOD;
							break;
						}
					stkpop(stkstd);
				}
			}
			else
			{
				if (!mbwide())
				{
					e = s + m;
					if (p = rex->map)
					{
						for (; s < e; s++)
							if (p[*s] != c)
								return r;
						e += n - m;
						for (;;)
						{
							switch (follow(env, rex, cont, s))
							{
							case BAD:
								return BAD;
							case CUT:
								return CUT;
							case BEST:
							case GOOD:
								return BEST;
							}
							if (s >= e || p[*s++] != c)
								break;
						}
					}
					else
					{
						for (; s < e; s++)
							if (*s != c)
								return r;
						e += n - m;
						for (;;)
						{
							switch (follow(env, rex, cont, s))
							{
							case BAD:
								return BAD;
							case CUT:
								return CUT;
							case BEST:
							case GOOD:
								return BEST;
							}
							if (s >= e || *s++ != c)
								break;
						}
					}
				}
				else
				{
					e = env->end;
					if (!(rex->flags & REG_ICASE))
					{
						for (i = 0; i < m && s < e; i++, s = t)
						{
							t = s;
							if (mbchar(t) != c)
								return r;
						}
						while (i++ <= n)
						{
							switch (follow(env, rex, cont, s))
							{
							case BAD:
								return BAD;
							case CUT:
								return CUT;
							case BEST:
							case GOOD:
								return BEST;
							}
							if (s >= e || mbchar(s) != c)
								break;
						}
					}
					else
					{
						for (i = 0; i < m && s < e; i++, s = t)
						{
							t = s;
							if (towupper(mbchar(t)) != c)
								return r;
						}
						while (i++ <= n)
						{
							switch (follow(env, rex, cont, s))
							{
							case BAD:
								return BAD;
							case CUT:
								return CUT;
							case BEST:
							case GOOD:
								return BEST;
							}
							if (s >= e || towupper(mbchar(s)) != c)
								break;
						}
					}
				}
			}
			return r;
		case REX_REP:
			if (env->stack && pospush(env, rex, s, BEG_REP))
				return BAD;
			r = parserep(env, rex, cont, s, 0);
			if (env->stack)
				pospop(env);
			return r;
		case REX_REP_CATCH:
			DEBUG_TEST(0x0020,(sfprintf(sfstdout, "AHA#%04d 0x%04x %s n %d len %d s `%-.*s'\n", __LINE__, debug_flag, rexname(rex), rex->re.rep_catch.n, s - rex->re.rep_catch.beg, env->end - s, s)),(0));
			if (env->stack && pospush(env, rex, s, END_ANY))
				return BAD;
			if (s == rex->re.rep_catch.beg && rex->re.rep_catch.n > rex->re.rep_catch.ref->lo)
			{
				/*
				 * optional empty iteration
				 */

DEBUG_TEST(0x0002,(sfprintf(sfstdout, "AHA#%04d %p re.group.back=%d re.group.expr.rex=%s\n", __LINE__, rex->re.rep_catch.ref->re.group.expr.rex, rex->re.rep_catch.ref->re.group.expr.rex->re.group.back, rexname(rex->re.rep_catch.ref->re.group.expr.rex))),(0));
				if (!env->stack || s != rex->re.rep_catch.ref->re.rep_catch.beg && !rex->re.rep_catch.ref->re.group.expr.rex->re.group.back)
					r = NONE;
				else if (pospush(env, rex, s, END_ANY))
					r = BAD;
				else
				{
					r = follow(env, rex, rex->re.rep_catch.cont, s);
					pospop(env);
				}
			}
			else
				r = parserep(env, rex->re.rep_catch.ref, rex->re.rep_catch.cont, s, rex->re.rep_catch.n);
			if (env->stack)
				pospop(env);
			return r;
		case REX_STRING:
DEBUG_TEST(0x0200,(sfprintf(sfstdout,"AHA#%04d 0x%04x parse %s \"%-.*s\" `%-.*s'\n", __LINE__, debug_flag, rexname(rex), rex->re.string.size, rex->re.string.base, env->end - s, s)),(0));
			if (rex->re.string.size > (env->end - s))
				return NONE;
			t = rex->re.string.base;
			e = t + rex->re.string.size;
			if (!(p = rex->map))
			{
				while (t < e)
					if (*s++ != *t++)
						return NONE;
			}
			else if (!mbwide())
			{
				while (t < e)
					if (p[*s++] != *t++)
						return NONE;
			}
			else
			{
				while (t < e)
				{
					c = mbchar(s);
					d = mbchar(t);
					if (towupper(c) != d)
						return NONE;
				}
			}
			break;
		case REX_TRIE:
			if (((s + rex->re.trie.min) > env->end) || !(x = rex->re.trie.root[rex->map ? rex->map[*s] : *s]))
				return NONE;
			return parsetrie(env, x, rex, cont, s);
		case REX_EXEC:
			u = 0;
			r = (*env->disc->re_execf)(env->regex, rex->re.exec.data, rex->re.exec.text, rex->re.exec.size, (const char*)s, env->end - s, &u, env->disc);
			e = (unsigned char*)u;
			if (e >= s && e <= env->end)
				s = e;
			switch (r)
			{
			case 0:
				break;
			case REG_NOMATCH:
				return NONE;
			default:
				env->error = r;
				return BAD;
			}
			break;
		case REX_WBEG:
			if (!isword(*s) || s > env->beg && isword(*(s - 1)))
				return NONE;
			break;
		case REX_WEND:
			if (isword(*s) || s > env->beg && !isword(*(s - 1)))
				return NONE;
			break;
		case REX_WORD:
			if (s > env->beg && isword(*(s - 1)) == isword(*s))
				return NONE;
			break;
		case REX_WORD_NOT:
			if (s == env->beg || isword(*(s - 1)) != isword(*s))
				return NONE;
			break;
		case REX_BEG_STR:
			if (s != env->beg)
				return NONE;
			break;
		case REX_END_STR:
			for (t = s; t < env->end && *t == '\n'; t++);
			if (t < env->end)
				return NONE;
			break;
		case REX_FIN_STR:
			if (s < env->end)
				return NONE;
			break;
		}
		if (!(rex = rex->next))
		{
			if (!(rex = cont))
				break;
			cont = 0;
		}
	}
	return GOOD;
}

#if _AST_REGEX_DEBUG

static void
listnode(Rex_t* e, int level)
{
	int	i;

	if (e)
	{
		do
		{
			for (i = 0; i < level; i++)
				sfprintf(sfstderr, "  ");
			sfprintf(sfstderr, "%s\n", rexname(e));
			switch (e->type)
			{
			case REX_ALT:
			case REX_CONJ:
				listnode(e->re.group.expr.binary.left, level + 1);
				listnode(e->re.group.expr.binary.right, level + 1);
				break;
			case REX_GROUP:
			case REX_GROUP_AHEAD:
			case REX_GROUP_AHEAD_NOT:
			case REX_GROUP_BEHIND:
			case REX_GROUP_BEHIND_NOT:
			case REX_GROUP_CUT:
			case REX_NEG:
			case REX_REP:
				listnode(e->re.group.expr.rex, level + 1);
				break;
			}
		} while (e = e->next);
	}
}

static int
list(Env_t* env, Rex_t* rex)
{
	sfprintf(sfstderr, "AHA regex hard=%d stack=%p\n", env->hard, env->stack);
	if (rex)
		listnode(rex, 1);
	return 0;
}

#endif

/*
 * returning REG_BADPAT or REG_ESPACE is not explicitly
 * countenanced by the standard
 */

int
regnexec(const regex_t* p, const char* s, size_t len, size_t nmatch, regmatch_t* match, regflags_t flags)
{
	register ssize_t	n;
	register int		i;
	int			j;
	int			k;
	int			m;
	int			advance;
	Env_t*			env;
	Rex_t*			e;

	DEBUG_INIT();
	DEBUG_TEST(0x0001,(sfprintf(sfstdout, "AHA#%04d 0x%04x regnexec %d 0x%08x `%-.*s'\n", __LINE__, debug_flag, nmatch, flags, len, s)),(0));
	if (!p || !(env = p->env))
		return REG_BADPAT;
	if (!s)
		return fatal(env->disc, REG_BADPAT, NiL);
	if (len < env->min)
	{
		DEBUG_TEST(0x0080,(sfprintf(sfstdout, "AHA#%04d REG_NOMATCH %d %d\n", __LINE__, len, env->min)),(0));
		return REG_NOMATCH;
	}
	env->regex = p;
	env->beg = (unsigned char*)s;
	env->end = env->beg + len;
	stknew(stkstd, &env->stk);
	env->flags &= ~REG_EXEC;
	env->flags |= (flags & REG_EXEC);
	advance = 0;
	if (env->stack = env->hard || !(env->flags & REG_NOSUB) && nmatch)
	{
		n = env->nsub;
		if (!(env->match = (regmatch_t*)stkpush(stkstd, 2 * (n + 1) * sizeof(regmatch_t))) ||
		    !env->pos && !(env->pos = vecopen(16, sizeof(Pos_t))) ||
		    !env->bestpos && !(env->bestpos = vecopen(16, sizeof(Pos_t))))
		{
			k = REG_ESPACE;
			goto done;
		}
		env->pos->cur = env->bestpos->cur = 0;
		env->best = &env->match[n + 1];
		env->best[0].rm_so = 0;
		env->best[0].rm_eo = -1;
		for (i = 0; i <= n; i++)
			env->match[i] = state.nomatch;
		if (flags & REG_ADVANCE)
			advance = 1;
	}
	DEBUG_TEST(0x1000,(list(env,env->rex)),(0));
	k = REG_NOMATCH;
	if ((e = env->rex)->type == REX_BM)
	{
		DEBUG_TEST(0x0080,(sfprintf(sfstdout, "AHA#%04d REX_BM\n", __LINE__)),(0));
		if (len < e->re.bm.right)
		{
			DEBUG_TEST(0x0080,(sfprintf(sfstdout, "AHA#%04d REG_NOMATCH %d %d\n", __LINE__, len, e->re.bm.right)),(0));
			goto done;
		}
		else if (!(flags & REG_LEFT))
		{
			register unsigned char*	buf = (unsigned char*)s;
			register size_t		index = e->re.bm.left + e->re.bm.size;
			register size_t		mid = len - e->re.bm.right;
			register size_t*	skip = e->re.bm.skip;
			register size_t*	fail = e->re.bm.fail;
			register Bm_mask_t**	mask = e->re.bm.mask;
			Bm_mask_t		m;
			size_t			x;

			DEBUG_TEST(0x0080,(sfprintf(sfstdout, "AHA#%04d REX_BM len=%d right=%d left=%d size=%d %d %d\n", __LINE__, len, e->re.bm.right, e->re.bm.left, e->re.bm.size, index, mid)),(0));
			for (;;)
			{
				while ((index += skip[buf[index]]) < mid);
				if (index < HIT)
				{
					DEBUG_TEST(0x0080,(sfprintf(sfstdout, "AHA#%04d REG_NOMATCH %d %d\n", __LINE__, index, HIT)),(0));
					goto done;
				}
				index -= HIT;
				m = mask[n = e->re.bm.size - 1][buf[index]];
				do
				{
					if (!n--)
					{
						if (e->re.bm.back < 0)
							goto possible;
						if (advance)
						{
							i = index - e->re.bm.back;
							s += i;
							if (env->stack)
								env->best[0].rm_so += i;
							goto possible;
						}
						x = index;
						if (index < e->re.bm.back)
							index = 0;
						else
							index -= e->re.bm.back;
						while (index <= x)
						{
							if ((i = parse(env, e->next, &env->done, buf + index)) != NONE)
							{
								if (env->stack)
									env->best[0].rm_so = index;
								n = env->nsub;
								goto hit;
							}
							index++;
						}
						index += e->re.bm.size;
						break;
					}
				} while (m &= mask[n][buf[--index]]);
				if ((index += fail[n + 1]) >= len)
					goto done;
			}
		}
 possible:
		n = env->nsub;
		e = e->next;
	}
	j = env->once || (flags & REG_LEFT);
	DEBUG_TEST(0x0080,(sfprintf(sfstdout, "AHA#%04d parse once=%d\n", __LINE__, j)),(0));
	while ((i = parse(env, e, &env->done, (unsigned char*)s)) == NONE || advance && !env->best[0].rm_eo && !(advance = 0))
	{
		if (j)
			goto done;
		i = MBSIZE(s);
		s += i;
		if ((unsigned char*)s > env->end - env->min)
			goto done;
		if (env->stack)
			env->best[0].rm_so += i;
	}
	if ((flags & REG_LEFT) && env->stack && env->best[0].rm_so)
		goto done;
 hit:
	if (k = env->error)
		goto done;
	if (i == CUT)
	{
		k = env->error = REG_NOMATCH;
		goto done;
	}
	if (!(env->flags & REG_NOSUB))
	{
		k = (env->flags & (REG_SHELL|REG_AUGMENTED)) == (REG_SHELL|REG_AUGMENTED);
		for (i = j = m = 0; j < nmatch; i++)
			if (!i || !k || (i & 1))
			{
				if (i > n)
					match[j] = state.nomatch;
				else
					match[m = j] = env->best[i];
				j++;
			}
		if (k)
		{
			while (m > 0 && match[m].rm_so == -1 && match[m].rm_eo == -1)
				m--;
			((regex_t*)p)->re_nsub = m;
		}
	}
	k = 0;
 done:
	stkold(stkstd, &env->stk);
	env->stk.base = 0;
	if (k > REG_NOMATCH)
		fatal(p->env->disc, k, NiL);
	return k;
}

void
regfree(regex_t* p)
{
	Env_t*	env;

	if (p && (env = p->env))
	{
#if _REG_subcomp
		if (env->sub)
		{
			regsubfree(p);
			p->re_sub = 0;
		}
#endif
		p->env = 0;
		if (--env->refs <= 0 && !(env->disc->re_flags & REG_NOFREE))
		{
			drop(env->disc, env->rex);
			if (env->pos)
				vecclose(env->pos);
			if (env->bestpos)
				vecclose(env->bestpos);
			if (env->stk.base)
				stkold(stkstd, &env->stk);
			alloc(env->disc, env, 0);
		}
	}
}

/*
 * 20120528: regoff_t changed from int to ssize_t
 */

#if defined(__EXPORT__)
#define extern		__EXPORT__
#endif

#undef	regnexec
#if _map_libc
#define regnexec	_ast_regnexec
#endif

extern int
regnexec(const regex_t* p, const char* s, size_t len, size_t nmatch, oldregmatch_t* oldmatch, regflags_t flags)
{
	if (oldmatch)
	{
		regmatch_t*	match;
		ssize_t		i;
		int		r;

		if (!(match = oldof(0, regmatch_t, nmatch, 0)))
			return -1;
		if (!(r = regnexec_20120528(p, s, len, nmatch, match, flags)))
			for (i = 0; i < nmatch; i++)
			{
				oldmatch[i].rm_so = match[i].rm_so;
				oldmatch[i].rm_eo = match[i].rm_eo;
			}
		free(match);
		return r;
	}
	return regnexec_20120528(p, s, len, 0, NiL, flags);
}
