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
 * posix regex implementation
 *
 * based on Doug McIlroy's C++ implementation
 * Knuth-Morris-Pratt adapted from Corman-Leiserson-Rivest
 * Boyer-Moore from conversations with David Korn, Phong Vo, Andrew Hume
 */

#ifndef _REGLIB_H
#define _REGLIB_H

#define REG_VERSION_EXEC	20020509L
#define REG_VERSION_MAP		20030916L	/* regdisc_t.re_map	*/

#define re_info		env

#define alloc		_reg_alloc
#define classfun	_reg_classfun
#define drop		_reg_drop
#define fatal		_reg_fatal
#define state		_reg_state

typedef struct regsubop_s
{
	int		op;		/* REG_SUB_LOWER,REG_SUB_UPPER	*/
	int		off;		/* re_rhs or match[] offset	*/
	int		len;		/* re_rhs len or len==0 match[]	*/
} regsubop_t;

#define _REG_SUB_PRIVATE_ \
	char*		re_cur;		/* re_buf cursor		*/ \
	char*		re_end;		/* re_buf end			*/ \
	regsubop_t*	re_ops;		/* rhs ops			*/ \
	char		re_rhs[1];	/* substitution rhs		*/

#include <ast.h>
#include <cdt.h>
#include <stk.h>

#include "regex.h"

#include <ctype.h>
#include <errno.h>

#if _BLD_DEBUG && !defined(_AST_REGEX_DEBUG)
#define _AST_REGEX_DEBUG	1
#endif

#define MBSIZE(p)	((ast.tmp_int=mbsize(p))>0?ast.tmp_int:1)

#undef	RE_DUP_MAX			/* posix puts this in limits.h!	*/
#define RE_DUP_MAX	(INT_MAX/2-1)	/* 2*RE_DUP_MAX won't overflow	*/
#define RE_DUP_INF	(RE_DUP_MAX+1)	/* infinity, for *		*/
#define BACK_REF_MAX	9

#define REG_COMP	(~REG_EXEC)
#define REG_EXEC	(REG_ADVANCE|REG_INVERT|REG_NOTBOL|REG_NOTEOL|REG_STARTEND)

#define REX_NULL		0	/* null string (internal)	*/
#define REX_ALT			1	/* a|b				*/
#define REX_ALT_CATCH		2	/* REX_ALT catcher		*/
#define REX_BACK		3	/* \1, \2, etc			*/
#define REX_BEG			4	/* initial ^			*/
#define REX_BEG_STR		5	/* initial ^ w/ no newline	*/
#define REX_BM			6	/* Boyer-Moore			*/
#define REX_CAT			7	/* catenation catcher		*/
#define REX_CLASS		8	/* [...]			*/
#define REX_COLL_CLASS		9	/* collation order [...]	*/
#define REX_CONJ		10	/* a&b				*/
#define REX_CONJ_LEFT		11	/* REX_CONJ left catcher	*/
#define REX_CONJ_RIGHT		12	/* REX_CONJ right catcher	*/
#define REX_DONE		13	/* completed match (internal)	*/
#define REX_DOT			14	/* .				*/
#define REX_END			15	/* final $			*/
#define REX_END_STR		16	/* final $ before tail newline	*/
#define REX_EXEC		17	/* call re.re_exec()		*/
#define REX_FIN_STR		18	/* final $ w/ no newline	*/
#define REX_GROUP		19	/* \(...\)			*/
#define REX_GROUP_CATCH		20	/* REX_GROUP catcher		*/
#define REX_GROUP_AHEAD		21	/* 0-width lookahead		*/
#define REX_GROUP_AHEAD_CATCH	22	/* REX_GROUP_AHEAD catcher	*/
#define REX_GROUP_AHEAD_NOT	23	/* inverted 0-width lookahead	*/
#define REX_GROUP_BEHIND	24	/* 0-width lookbehind		*/
#define REX_GROUP_BEHIND_CATCH	25	/* REX_GROUP_BEHIND catcher	*/
#define REX_GROUP_BEHIND_NOT	26	/* inverted 0-width lookbehind	*/
#define REX_GROUP_BEHIND_NOT_CATCH 27	/* REX_GROUP_BEHIND_NOT catcher	*/
#define REX_GROUP_COND		28	/* conditional group		*/
#define REX_GROUP_COND_CATCH	29	/* conditional group catcher	*/
#define REX_GROUP_CUT		30	/* don't backtrack over this	*/
#define REX_GROUP_CUT_CATCH	31	/* REX_GROUP_CUT catcher	*/
#define REX_KMP			32	/* Knuth-Morris-Pratt		*/
#define REX_NEG			33	/* negation			*/
#define REX_NEG_CATCH		34	/* REX_NEG catcher		*/
#define REX_NEST		35	/* nested match			*/
#define REX_ONECHAR		36	/* a single-character literal	*/
#define REX_REP			37	/* Kleene closure		*/
#define REX_REP_CATCH		38	/* REX_REP catcher		*/
#define REX_STRING		39	/* some chars			*/
#define REX_TRIE		40	/* alternation of strings	*/
#define REX_WBEG		41	/* \<				*/
#define REX_WEND		42	/* \>				*/
#define REX_WORD		43	/* word boundary		*/
#define REX_WORD_NOT		44	/* not word boundary		*/

#define T_META		((int)UCHAR_MAX+1)
#define T_STAR		(T_META+0)
#define T_PLUS		(T_META+1)
#define T_QUES		(T_META+2)
#define T_BANG		(T_META+3)
#define T_AT		(T_META+4)
#define T_TILDE		(T_META+5)
#define T_PERCENT	(T_META+6)
#define T_LEFT		(T_META+7)
#define T_OPEN		(T_META+8)
#define T_CLOSE		(T_OPEN+1)
#define T_RIGHT		(T_OPEN+2)
#define T_CFLX		(T_OPEN+3)
#define T_DOT		(T_OPEN+4)
#define T_DOTSTAR	(T_OPEN+5)
#define T_END		(T_OPEN+6)
#define T_BAD		(T_OPEN+7)
#define T_DOLL		(T_OPEN+8)
#define T_BRA		(T_OPEN+9)
#define T_BAR		(T_OPEN+10)
#define T_AND		(T_OPEN+11)
#define T_LT		(T_OPEN+12)
#define T_GT		(T_OPEN+13)
#define T_SLASHPLUS	(T_OPEN+14)
#define T_GROUP		(T_OPEN+15)
#define T_WORD		(T_OPEN+16)
#define T_WORD_NOT	(T_WORD+1)
#define T_BEG_STR	(T_WORD+2)
#define T_END_STR	(T_WORD+3)
#define T_FIN_STR	(T_WORD+4)
#define T_ESCAPE	(T_WORD+5)
#define T_ALNUM		(T_WORD+6)
#define T_ALNUM_NOT	(T_ALNUM+1)
#define T_DIGIT		(T_ALNUM+2)
#define T_DIGIT_NOT	(T_ALNUM+3)
#define T_SPACE		(T_ALNUM+4)
#define T_SPACE_NOT	(T_ALNUM+5)
#define T_BACK		(T_ALNUM+6)

#define BRE		0
#define ERE		3
#define ARE		6
#define SRE		9
#define KRE		12

#define HIT		SSIZE_MAX

#define bitclr(p,c)	((p)[((c)>>3)&037]&=(~(1<<((c)&07))))
#define bitset(p,c)	((p)[((c)>>3)&037]|=(1<<((c)&07)))
#define bittst(p,c)	((p)[((c)>>3)&037]&(1<<((c)&07)))

#define setadd(p,c)	bitset((p)->bits,c)
#define setclr(p,c)	bitclr((p)->bits,c)
#define settst(p,c)	bittst((p)->bits,c)

#if _hdr_wchar && _lib_wctype && _lib_iswctype

#include <stdio.h> /* because <wchar.h> includes it and we generate it */
#include <wchar.h>
#if _hdr_wctype
#include <wctype.h>
#endif

#if !defined(iswblank) && !_lib_iswblank
#define _need_iswblank	1
#define iswblank(x)	_reg_iswblank(x)
extern int		_reg_iswblank(wint_t);
#endif

#if !defined(towupper) && !_lib_towupper
#define towupper(x)	toupper(x)
#endif

#if !defined(towlower) && !_lib_towlower
#define towlower(x)	tolower(x)
#endif

#else

#undef	_lib_wctype

#ifndef iswalnum
#define iswalnum(x)	isalnum(x)
#endif
#ifndef iswalpha
#define iswalpha(x)	isalpha(x)
#endif
#ifndef iswcntrl
#define iswcntrl(x)	iscntrl(x)
#endif
#ifndef iswdigit
#define iswdigit(x)	isdigit(x)
#endif
#ifndef iswgraph
#define iswgraph(x)	isgraph(x)
#endif
#ifndef iswlower
#define iswlower(x)	islower(x)
#endif
#ifndef iswprint
#define iswprint(x)	isprint(x)
#endif
#ifndef iswpunct
#define iswpunct(x)	ispunct(x)
#endif
#ifndef iswspace
#define iswspace(x)	isspace(x)
#endif
#ifndef iswupper
#define iswupper(x)	isupper(x)
#endif
#ifndef iswxdigit
#define iswxdigit(x)	isxdigit(x)
#endif

#ifndef towlower
#define towlower(x)	tolower(x)
#endif
#ifndef towupper
#define towupper(x)	toupper(x)
#endif

#endif

#ifndef	iswblank
#define	iswblank(x)	((x)==' '||(x)=='\t')
#endif

#ifndef iswgraph
#define	iswgraph(x)	(iswprint(x)&&!iswblank(x))
#endif

#define isword(x)	(isalnum(x)||(x)=='_')

/*
 * collation element support
 */

#define COLL_KEY_MAX	32

#if COLL_KEY_MAX < MB_LEN_MAX
#undef	COLL_KEY_MAX
#define COLL_KEY_MAX	MB_LEN_MAX
#endif

typedef unsigned char Ckey_t[COLL_KEY_MAX+1];

#define COLL_end	0
#define COLL_call	1
#define COLL_char	2
#define COLL_range	3
#define COLL_range_lc	4
#define COLL_range_uc	5

typedef struct Celt_s
{
	short		typ;
	short		min;
	short		max;
	regclass_t	fun;
	Ckey_t		beg;
	Ckey_t		end;
} Celt_t;

/*
 * private stuff hanging off regex_t
 */

typedef struct Stk_pos_s
{
	off_t		offset;
	char*		base;
} Stk_pos_t;

typedef struct Vector_s
{
	Stk_t*		stk;		/* stack pointer		*/
	char*		vec;		/* the data			*/
	int		inc;		/* growth increment		*/
	int		siz;		/* element size			*/
	ssize_t		max;		/* max index			*/
	ssize_t		cur;		/* current index -- user domain	*/
} Vector_t;

/*
 * Rex_t subtypes
 */

typedef struct Cond_s
{
	unsigned char*	beg;		/* beginning of next match	*/
	struct Rex_s*	next[2];	/* 0:no 1:yes next pattern	*/
	struct Rex_s*	cont;		/* right catcher		*/
	int		yes;		/* yes condition hit		*/
} Cond_t;

typedef struct Conj_left_s
{
	unsigned char*	beg;		/* beginning of left match	*/
	struct Rex_s*	right;		/* right pattern		*/
	struct Rex_s*	cont;		/* right catcher		*/
} Conj_left_t;

typedef struct Conj_right_s
{
	unsigned char*	end;		/* end of left match		*/
	struct Rex_s*	cont;		/* ambient continuation		*/
} Conj_right_t;

typedef unsigned int Bm_mask_t;

typedef struct Bm_s
{
	Bm_mask_t**	mask;
	size_t*		skip;
	size_t*		fail;
	size_t		size;
	ssize_t		back;
	ssize_t		left;
	ssize_t		right;
	size_t		complete;
} Bm_t;

typedef struct String_s
{
	int*		fail;
	unsigned char*	base;
	size_t		size;
} String_t;

typedef struct Set_s
{
	unsigned char	bits[(UCHAR_MAX+1)/CHAR_BIT];
} Set_t;

typedef struct Collate_s
{
	int		invert;
	Celt_t*		elements;
} Collate_t;

typedef struct Binary_s
{
	struct Rex_s*	left;
	struct Rex_s*	right;
	int		serial;
} Binary_t;

typedef struct Group_s
{
	int		number;		/* group number			*/
	int		last;		/* last contained group number	*/
	int		size;		/* lookbehind size		*/
	int		back;		/* backreferenced		*/
	regflags_t	flags;		/* group flags			*/
	union
	{
	Binary_t	binary;
	struct Rex_s*	rex;
	}		expr;
} Group_t;

typedef struct Exec_s
{
	void*		data;
	const char*	text;
	size_t		size;
} Exec_t;

#define REX_NEST_open		0x01
#define REX_NEST_close		0x02
#define REX_NEST_escape		0x04
#define REX_NEST_quote		0x08
#define REX_NEST_literal	0x10
#define REX_NEST_delimiter	0x20
#define REX_NEST_terminator	0x40
#define REX_NEST_separator	0x80

#define REX_NEST_SHIFT		8

typedef struct Nest_s
{
	int		primary;
	unsigned short	none;		/* for Nest_t.type[-1] */
	unsigned short	type[1];
} Nest_t;

/*
 * REX_ALT catcher, solely to get control at the end of an
 * alternative to keep records for comparing matches.
 */

typedef struct Alt_catch_s
{
	struct Rex_s*	cont;
} Alt_catch_t;

typedef struct Group_catch_s
{
	struct Rex_s*	cont;
	regoff_t*	eo;
} Group_catch_t;

typedef struct Behind_catch_s
{
	struct Rex_s*	cont;
	unsigned char*	beg;
	unsigned char*	end;
} Behind_catch_t;

/*
 * REX_NEG catcher determines what string lengths can be matched,
 * then Neg investigates continuations of other lengths.
 * This is inefficient.  For !POSITIONS expressions, we can do better:
 * since matches to rex will be enumerated in decreasing order,
 * we can investigate continuations whenever a length is skipped.
 */

typedef struct Neg_catch_s
{
	unsigned char*	beg;
	unsigned char*	index;
} Neg_catch_t;

/*
 * REX_REP catcher.  One is created on the stack for
 * each iteration of a complex repetition.
 */

typedef struct Rep_catch_s
{
	struct Rex_s*	cont;
	struct Rex_s*	ref;
	unsigned char*	beg;
	int		n;
} Rep_catch_t;

/*
 * data structure for an alternation of pure strings
 * son points to a subtree of all strings with a common
 * prefix ending in character c.  sib links alternate
 * letters in the same position of a word.  end=1 if
 * some word ends with c.  the order of strings is
 * irrelevant, except long words must be investigated
 * before short ones.
 */

typedef struct Trie_node_s
{
	unsigned char		c;
	unsigned char		end;
	struct Trie_node_s*	son;
	struct Trie_node_s*	sib;
} Trie_node_t;

typedef struct Trie_s
{
	Trie_node_t**	root;
	int		min;
	int		max;
} Trie_t;

/*
 * Rex_t is a node in a regular expression
 */

typedef struct Rex_s
{
	unsigned char	type;			/* node type		*/
	unsigned char	marked;			/* already marked	*/
	short		serial;			/* subpattern number	*/
	regflags_t	flags;			/* scoped flags		*/
	int		explicit;		/* scoped explicit match*/
	struct Rex_s*	next;			/* remaining parts	*/
	int		lo;			/* lo dup count		*/
	int		hi;			/* hi dup count		*/
	unsigned char*	map;			/* fold and/or ccode map*/
	union
	{
	Alt_catch_t	alt_catch;		/* alt catcher		*/
	Bm_t		bm;			/* bm			*/
	Behind_catch_t	behind_catch;		/* behind catcher	*/
	Set_t*		charclass;		/* char class		*/
	Collate_t	collate;		/* collation class	*/
	Cond_t		cond_catch;		/* cond catcher		*/
	Conj_left_t	conj_left;		/* conj left catcher	*/
	Conj_right_t	conj_right;		/* conj right catcher	*/
	void*		data;			/* data after Rex_t	*/
	Exec_t		exec;			/* re.re_exec() args	*/
	Group_t		group;			/* a|b or rep		*/
	Group_catch_t	group_catch;		/* group catcher	*/
	Neg_catch_t	neg_catch;		/* neg catcher		*/
	Nest_t		nest;			/* nested match		*/
	unsigned char	onechar;		/* single char		*/
	Rep_catch_t	rep_catch;		/* rep catcher		*/
	String_t	string;			/* string/kmp		*/
	Trie_t		trie;			/* trie			*/
	}		re;
} Rex_t;

typedef struct reglib_s			/* library private regex_t info	*/
{
	struct Rex_s*	rex;		/* compiled expression		*/
	regdisc_t*	disc;		/* REG_DISCIPLINE discipline	*/
	const regex_t*	regex;		/* from regexec			*/
	unsigned char*	beg;		/* beginning of string		*/
	unsigned char*	end;		/* end of string		*/
	Vector_t*	pos;		/* posns of certain subpatterns	*/
	Vector_t*	bestpos;	/* ditto for best match		*/
	regmatch_t*	match;		/* subexrs in current match 	*/
	regmatch_t*	best;		/* ditto in best match yet	*/
	Stk_pos_t	stk;		/* exec stack pos		*/
	size_t		min;		/* minimum match length		*/
	size_t		nsub;		/* internal re_nsub		*/
	regflags_t	flags;		/* flags from regcomp()		*/
	int		error;		/* last error			*/
	int		explicit;	/* explicit match on this char	*/
	int		leading;	/* leading match on this char	*/
	int		refs;		/* regcomp()+regdup() references*/
	Rex_t		done;		/* the last continuation	*/
	regstat_t	stats;		/* for regstat()		*/
	unsigned char	fold[UCHAR_MAX+1]; /* REG_ICASE map		*/
	unsigned char	hard;		/* hard comp			*/
	unsigned char	once;		/* if 1st parse fails, quit	*/
	unsigned char	separate;	/* cannot combine		*/
	unsigned char	stack;		/* hard comp or exec		*/
	unsigned char	sub;		/* re_sub is valid		*/
	unsigned char	test;		/* debug/test bitmask		*/
} Env_t;

typedef struct oldregmatch_s		/* pre-20120528 regmatch_t	*/
{
	int		rm_so;		/* offset of start		*/
	int		rm_eo;		/* offset of end		*/
} oldregmatch_t;

typedef struct State_s				/* shared state		*/
{
	regmatch_t	nomatch;
	struct
	{
	unsigned char	key;
	short		val[15];
	}		escape[52];
	short*		magic[UCHAR_MAX+1];
	regdisc_t	disc;
	int		fatal;
	int		initialized;
	Dt_t*		attrs;
	Dt_t*		names;
	Dtdisc_t	dtdisc;
} State_t;

extern State_t		state;

extern void*		alloc(regdisc_t*, void*, size_t);
extern regclass_t	classfun(int);
extern void		drop(regdisc_t*, Rex_t*);
extern int		fatal(regdisc_t*, int, const char*);

#endif
