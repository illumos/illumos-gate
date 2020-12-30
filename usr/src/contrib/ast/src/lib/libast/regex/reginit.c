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
 * posix regex state and alloc
 */

#include "reglib.h"

#if _PACKAGE_ast

#include <ccode.h>

#else

#define CC_bel		'\a'
#define CC_esc		'\033'
#define CC_vt		'\v'

#endif

/*
 * state shared by all threads
 */

State_t		state =
{
	{ -1, -1 },

	/*
	 * escape code table
	 * the "funny" things get special treatment at ends of BRE
	 *
	 *	BRE  0:normal  1:escaped  2:escaped-char-class
	 *	ERE  3:normal  4:escaped  5:escaped-char-class
	 *	ARE  6:normal  7:escaped  8:escaped-char-class
	 *	SRE  9:normal 10:escaped 11:escaped-char-class
	 *	KRE 12:normal 13:escaped 14:escaped-char-class
	 */

	'\\',
		'\\',		'\\',		'\\',
		'\\',		'\\',		'\\',
		'\\',		'\\',		'\\',
		'\\',		'\\',		'\\',
		'\\',		'\\',		'\\',
	'^',	/* funny */
		'^',		'^',		'^',
		T_CFLX,		'^',		'^',
		T_CFLX,		'^',		'^',
		'^',		'^',		'^',
		'^',		'^',		'^',
	'.',
		T_DOT,		'.',		T_BAD,
		T_DOT, 		'.',		T_BAD,
		T_DOT, 		'.',		T_BAD,
		'.',		'.',		T_BAD,
		'.',		'.',		T_BAD,
	'$',	/* funny */
		'$',		'$',		T_BAD,
		T_DOLL, 	'$',		T_BAD,
		T_DOLL, 	'$',		T_BAD,
		'$',		'$',		T_BAD,
		'$',		'$',		T_BAD,
	'*',
		T_STAR,		'*',		T_BAD,
		T_STAR, 	'*',		T_BAD,
		T_STAR, 	'*',		T_BAD,
		T_STAR, 	'*',		'*',
		T_STAR, 	'*',		'*',
	'[',
		T_BRA,		'[',		'[',
		T_BRA,		'[',		'[',
		T_BRA,		'[',		'[',
		T_BRA,		'[',		'[',
		T_BRA,		'[',		'[',
	'|',
		'|',		T_BAD,		T_BAD,
		T_BAR,		'|',		T_BAD,
		T_BAR,		'|',		T_BAD,
		'|',		'|',		T_BAD,
		T_BAR,		'|',		T_BAD,
	'+',
		'+',		T_BAD,		T_BAD,
		T_PLUS,		'+',		T_BAD,
		T_PLUS,		'+',		T_BAD,
		'+',		'+',		T_BAD,
		T_PLUS,		'+',		T_BAD,
	'?',
		'?',		T_BAD,		T_BAD,
		T_QUES, 	'?',		T_BAD,
		T_QUES, 	'?',		T_BAD,
		T_QUES,		'?',		'?',
		T_QUES,		'?',		'?',
	'(',
		'(',		T_OPEN,		T_BAD,
		T_OPEN, 	'(',		T_BAD,
		T_OPEN, 	'(',		T_BAD,
		'(',		'(',		'(',
		T_OPEN,		'(',		'(',
	')',
		')',		T_CLOSE,	T_BAD,
		T_CLOSE,	')',		T_BAD,
		T_CLOSE,	')',		T_BAD,
		')',		')',		')',
		T_CLOSE,	')',		')',
	'{',
		'{',		T_LEFT,		T_BAD,
		T_LEFT,		'{',		T_BAD,
		T_LEFT,		'{',		T_BAD,
		'{',		'{',		'{',
		T_LEFT,		'{',		'{',
	'}',
		'}',		T_RIGHT,	T_BAD,
		'}',		T_BAD,		T_BAD,
		'}',		T_BAD,		T_BAD,
		'}',		'}',		'}',
		'}',		'}',		'}',
	'&',
		'&',		T_BAD,		T_BAD,
		'&',		T_AND,		T_BAD,
		T_AND,		'&',		T_BAD,
		'&',		'&',		T_BAD,
		T_AND,		'&',		T_BAD,
	'!',
		'!',		T_BAD,		T_BAD,
		'!',		T_BANG,		T_BAD,
		T_BANG, 	'!',		T_BAD,
		'!',		'!',		T_BAD,
		T_BANG,		'!',		T_BAD,
	'@',
		'@',		T_BAD,		T_BAD,
		'@',		T_BAD,		T_BAD,
		'@',		T_BAD,		T_BAD,
		'@',		'@',		T_BAD,
		T_AT,		'@',		T_BAD,
	'~',
		'~',		T_BAD,		T_BAD,
		'~',		T_BAD,		T_BAD,
		'~',		T_BAD,		T_BAD,
		'~',		'~',		T_BAD,
		T_TILDE,	'~',		T_BAD,
	'%',
		'%',		T_BAD,		T_BAD,
		'%',		T_BAD,		T_BAD,
		'%',		T_BAD,		T_BAD,
		'%',		'%',		T_BAD,
		T_PERCENT,	'%',		T_BAD,
	'<',
		'<',		T_LT,		T_BAD,
		'<',		T_LT,		T_BAD,
		T_LT,   	'<',		T_BAD,
		'<',		'<',		T_BAD,
		'<',		'<',		T_BAD,
	'>',
		'>',		T_GT,		T_BAD,
		'>',		T_GT,		T_BAD,
		T_GT,   	'>',		T_BAD,
		'>',		'>',		T_BAD,
		'>',		'>',		T_BAD,

	/* backrefs */

	'0',
		'0',		T_BACK+0,	T_ESCAPE,
		'0',		T_BACK+0,	T_ESCAPE,
		'0',		T_BACK+0,	T_ESCAPE,
		'0',		T_BACK+0,	T_ESCAPE,
		'0',		T_BACK+0,	T_ESCAPE,
	'1',
		'1',		T_BACK+1,	T_ESCAPE,
		'1',		T_BACK+1,	T_ESCAPE,
		'1',		T_BACK+1,	T_ESCAPE,
		'1',		T_BACK+1,	T_ESCAPE,
		'1',		T_BACK+1,	T_ESCAPE,
	'2',
		'2',		T_BACK+2,	T_ESCAPE,
		'2',		T_BACK+2,	T_ESCAPE,
		'2',		T_BACK+2,	T_ESCAPE,
		'2',		T_BACK+2,	T_ESCAPE,
		'2',		T_BACK+2,	T_ESCAPE,
	'3',
		'3',		T_BACK+3,	T_ESCAPE,
		'3',		T_BACK+3,	T_ESCAPE,
		'3',		T_BACK+3,	T_ESCAPE,
		'3',		T_BACK+3,	T_ESCAPE,
		'3',		T_BACK+3,	T_ESCAPE,
	'4',
		'4',		T_BACK+4,	T_ESCAPE,
		'4',		T_BACK+4,	T_ESCAPE,
		'4',		T_BACK+4,	T_ESCAPE,
		'4',		T_BACK+4,	T_ESCAPE,
		'4',		T_BACK+4,	T_ESCAPE,
	'5',
		'5',		T_BACK+5,	T_ESCAPE,
		'5',		T_BACK+5,	T_ESCAPE,
		'5',		T_BACK+5,	T_ESCAPE,
		'5',		T_BACK+5,	T_ESCAPE,
		'5',		T_BACK+5,	T_ESCAPE,
	'6',
		'6',		T_BACK+6,	T_ESCAPE,
		'6',		T_BACK+6,	T_ESCAPE,
		'6',		T_BACK+6,	T_ESCAPE,
		'6',		T_BACK+6,	T_ESCAPE,
		'6',		T_BACK+6,	T_ESCAPE,
	'7',
		'7',		T_BACK+7,	T_ESCAPE,
		'7',		T_BACK+7,	T_ESCAPE,
		'7',		T_BACK+7,	T_ESCAPE,
		'7',		T_BACK+7,	T_ESCAPE,
		'7',		T_BACK+7,	T_ESCAPE,
	'8',
		'8',		T_BACK+8,	T_ESCAPE,
		'8',		T_BACK+8,	T_ESCAPE,
		'8',		T_BACK+8,	T_ESCAPE,
		'8',		'8',		T_ESCAPE,
		'8',		T_BACK+8,	T_ESCAPE,
	'9',
		'9',		T_BACK+9,	T_ESCAPE,
		'9',		T_BACK+9,	T_ESCAPE,
		'9',		T_BACK+9,	T_ESCAPE,
		'9',		'9',		T_ESCAPE,
		'9',		T_BACK+9,	T_ESCAPE,

	/* perl */

	'A',
		'A',		T_BEG_STR,	T_BAD,
		'A',		T_BEG_STR,	T_BAD,
		'A',		T_BEG_STR,	T_BAD,
		'A',		T_BEG_STR,	T_BAD,
		'A',		T_BEG_STR,	T_BAD,
	'b',
		'b',		T_WORD,		'\b',
		'b',		T_WORD,		'\b',
		'b',		T_WORD,		'\b',
		'b',		T_WORD,		'\b',
		'b',		T_WORD,		'\b',
	'B',
		'B',		T_WORD_NOT,	T_BAD,
		'B',		T_WORD_NOT,	T_BAD,
		'B',		T_WORD_NOT,	T_BAD,
		'B',		T_WORD_NOT,	T_BAD,
		'B',		T_WORD_NOT,	T_BAD,
	'd',
		'd',		T_DIGIT,	T_DIGIT,
		'd',		T_DIGIT,	T_DIGIT,
		'd',		T_DIGIT,	T_DIGIT,
		'd',		T_DIGIT,	T_DIGIT,
		'd',		T_DIGIT,	T_DIGIT,
	'D',
		'D',		T_DIGIT_NOT,	T_DIGIT_NOT,
		'D',		T_DIGIT_NOT,	T_DIGIT_NOT,
		'D',		T_DIGIT_NOT,	T_DIGIT_NOT,
		'D',		T_DIGIT_NOT,	T_DIGIT_NOT,
		'D',		T_DIGIT_NOT,	T_DIGIT_NOT,
	's',
		's',		T_SPACE,	T_SPACE,
		's',		T_SPACE,	T_SPACE,
		's',		T_SPACE,	T_SPACE,
		's',		T_SPACE,	T_SPACE,
		's',		T_SPACE,	T_SPACE,
	'S',
		'S',		T_SPACE_NOT,	T_SPACE_NOT,
		'S',		T_SPACE_NOT,	T_SPACE_NOT,
		'S',		T_SPACE_NOT,	T_SPACE_NOT,
		'S',		T_SPACE_NOT,	T_SPACE_NOT,
		'S',		T_SPACE_NOT,	T_SPACE_NOT,
	'w',
		'w',		T_ALNUM,	T_ALNUM,
		'w',		T_ALNUM,	T_ALNUM,
		'w',		T_ALNUM,	T_ALNUM,
		'w',		T_ALNUM,	T_ALNUM,
		'w',		T_ALNUM,	T_ALNUM,
	'W',
		'W',		T_ALNUM_NOT,	T_ALNUM_NOT,
		'W',		T_ALNUM_NOT,	T_ALNUM_NOT,
		'W',		T_ALNUM_NOT,	T_ALNUM_NOT,
		'W',		T_ALNUM_NOT,	T_ALNUM_NOT,
		'W',		T_ALNUM_NOT,	T_ALNUM_NOT,
	'z',
		'z',		T_FIN_STR,	T_BAD,
		'z',		T_FIN_STR,	T_BAD,
		'z',		T_FIN_STR,	T_BAD,
		'z',		T_FIN_STR,	T_BAD,
		'z',		T_FIN_STR,	T_BAD,
	'Z',
		'Z',		T_END_STR,	T_BAD,
		'Z',		T_END_STR,	T_BAD,
		'Z',		T_END_STR,	T_BAD,
		'Z',		T_END_STR,	T_BAD,
		'Z',		T_END_STR,	T_BAD,

	/* C escapes */

	'a',
		'a',		CC_bel,		CC_bel,
		'a',		CC_bel,		CC_bel,
		'a',		CC_bel,		CC_bel,
		'a',		CC_bel,		CC_bel,
		'a',		CC_bel,		CC_bel,
	'c',
		'c',		T_ESCAPE,	T_ESCAPE,
		'c',		T_ESCAPE,	T_ESCAPE,
		'c',		T_ESCAPE,	T_ESCAPE,
		'c',		T_ESCAPE,	T_ESCAPE,
		'c',		T_ESCAPE,	T_ESCAPE,
	'C',
		'C',		T_ESCAPE,	T_ESCAPE,
		'C',		T_ESCAPE,	T_ESCAPE,
		'C',		T_ESCAPE,	T_ESCAPE,
		'C',		T_ESCAPE,	T_ESCAPE,
		'C',		T_ESCAPE,	T_ESCAPE,
	'e',
		'e',		CC_esc,		CC_esc,
		'e',		CC_esc,		CC_esc,
		'e',		CC_esc,		CC_esc,
		'e',		CC_esc,		CC_esc,
		'e',		CC_esc,		CC_esc,
	'E',
		'E',		CC_esc,		CC_esc,
		'E',		CC_esc,		CC_esc,
		'E',		CC_esc,		CC_esc,
		'E',		CC_esc,		CC_esc,
		'E',		CC_esc,		CC_esc,
	'f',
		'f',		'\f',		'\f',
		'f',		'\f',		'\f',
		'f',		'\f',		'\f',
		'f',		'\f',		'\f',
		'f',		'\f',		'\f',
	'n',
		'n',		'\n',		'\n',
		'n',		'\n',		'\n',
		'n',		'\n',		'\n',
		'n',		'\n',		'\n',
		'n',		'\n',		'\n',
	'r',
		'r',		'\r',		'\r',
		'r',		'\r',		'\r',
		'r',		'\r',		'\r',
		'r',		'\r',		'\r',
		'r',		'\r',		'\r',
	't',
		't',		'\t',		'\t',
		't',		'\t',		'\t',
		't',		'\t',		'\t',
		't',		'\t',		'\t',
		't',		'\t',		'\t',
	'v',
		'v',		CC_vt,		CC_vt,
		'v',		CC_vt,		CC_vt,
		'v',		CC_vt,		CC_vt,
		'v',		CC_vt,		CC_vt,
		'v',		CC_vt,		CC_vt,
	'x',
		'x',		T_ESCAPE,	T_ESCAPE,
		'x',		T_ESCAPE,	T_ESCAPE,
		'x',		T_ESCAPE,	T_ESCAPE,
		'x',		T_ESCAPE,	T_ESCAPE,
		'x',		T_ESCAPE,	T_ESCAPE,
};

/*
 * all allocation/free done here
 * interface compatible with vmresize()
 *
 *	malloc(n)	alloc(0,n)
 *	realloc(p,n)	alloc(p,n)
 *	free(p)		alloc(p,0)
 */

void*
alloc(register regdisc_t* disc, void* p, size_t n)
{
	if (disc->re_resizef)
	{
		if (!n && (disc->re_flags & REG_NOFREE))
			return 0;
		return (*disc->re_resizef)(disc->re_resizehandle, p, n);
	}
	else if (!n)
	{
		if (!(disc->re_flags & REG_NOFREE))
			free(p);
		return 0;
	}
	else if (p)
		return realloc(p, n);
	else
		return malloc(n);
}
