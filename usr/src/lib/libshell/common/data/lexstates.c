/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1982-2010 AT&T Intellectual Property          *
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
*                  David Korn <dgk@research.att.com>                   *
*                                                                      *
***********************************************************************/
#pragma prototyped

#include	<ast.h>

#include	"FEATURE/options"
#include	"lexstates.h"


/*
 * This is the initial state for tokens
 */
static const char sh_lexstate0[256] =
{
	S_EOF,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
#if SHOPT_CRNL
	S_REG,	0,	S_NLTOK,S_REG,	S_REG,	0,	S_REG,	S_REG,
#else
	S_REG,	0,	S_NLTOK,S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
#endif /* SHOPT_CRNL */
	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,

	0,	S_REG,	S_REG,	S_COM,	S_REG,	S_REG,	S_OP,	S_REG,
	S_OP,	S_OP,	S_REG,	S_REG,	S_REG,	S_REG,	S_NAME,	S_REG,
	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
	S_REG,	S_REG,	S_REG,	S_OP,	S_OP,	S_REG,	S_OP,	S_REG,

	S_REG,	S_NAME,	S_NAME,	S_NAME,	S_NAME,	S_NAME,	S_NAME,	S_NAME,
	S_NAME,	S_NAME,	S_NAME,	S_NAME,	S_NAME,	S_NAME,	S_NAME,	S_NAME,
	S_NAME,	S_NAME,	S_NAME,	S_NAME,	S_NAME,	S_NAME,	S_NAME,	S_NAME,
	S_NAME,	S_NAME,	S_NAME,	S_REG,	S_REG,	S_REG,	S_REG,	S_NAME,

	S_REG,	S_NAME,	S_NAME,	S_RES,	S_RES,	S_RES,	S_RES,	S_NAME,
#if SHOPT_NAMESPACE
	S_NAME,	S_RES,	S_NAME,	S_NAME,	S_NAME,	S_NAME,	S_RES,	S_NAME,
#else
	S_NAME,	S_RES,	S_NAME,	S_NAME,	S_NAME,	S_NAME,	S_NAME,	S_NAME,
#endif /* SHOPT_NAMESPACE */
	S_NAME,	S_NAME,	S_NAME,	S_RES,	S_RES,	S_RES,	S_NAME,	S_RES,
	S_NAME,	S_NAME,	S_NAME,	S_BRACE,S_OP,	S_BRACE,S_TILDE,S_REG,

	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
};

/*
 * This state is for identifiers
 */
static const char sh_lexstate1[256] =
{
	S_EOF,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
#if SHOPT_CRNL
	S_REG,	S_BREAK,S_BREAK,S_REG,	S_REG,	S_BREAK,S_REG,	S_REG,
#else
	S_REG,	S_BREAK,S_BREAK,S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
#endif /* SHOPT_CRNL */
	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,

	S_BREAK,S_EPAT,	S_QUOTE,S_REG,	S_DOL,	S_EPAT,	S_BREAK,S_LIT,
	S_BREAK,S_BREAK,S_PAT,	S_EPAT,	S_REG,	S_EPAT,	S_DOT,	S_REG,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	S_LABEL,S_BREAK,S_BREAK,S_EQ,	S_BREAK,S_PAT,

	S_EPAT,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	S_BRACT,S_ESC,	S_REG,	S_REG,	0,

	S_GRAVE,0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	S_BRACE,S_BREAK,S_BRACE,S_EPAT,	S_REG,

	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,	S_REG,
};

static const char sh_lexstate2[256] =
{
	S_EOF,	0,	0,	0,	0,	0,	0,	0,
#if SHOPT_CRNL
	0,	S_BREAK,S_BREAK,0,	0,	S_BREAK,0,	0,
#else
	0,	S_BREAK,S_BREAK,0,	0,	0,	0,	0,
#endif /* SHOPT_CRNL */
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,

	S_BREAK,S_EPAT,	S_QUOTE,0,	S_DOL,	S_EPAT,	S_BREAK,S_LIT,
	S_BREAK,S_BREAK,S_PAT,	S_EPAT,	0,	S_EPAT,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	S_COLON,S_BREAK,S_BREAK,0,	S_BREAK,S_PAT,

	S_EPAT,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	S_PAT,	S_ESC,	0,	0,	0,

	S_GRAVE,0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	S_BRACE,S_BREAK,S_BRACE,S_EPAT,	0,
};

/*
 * for skipping over  '...'
 */
static const char sh_lexstate3[256] =
{
	S_EOF,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	S_NL,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,

	0,	0,	0,	0,	0,	0,	0,	S_LIT,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,

	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	S_ESC2,	0,	0,	0
};

/*
 * for skipping over  "..." and `...`
 */
static const char sh_lexstate4[256] =
{
	S_EOF,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	S_NL,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	S_QUOTE,0,	S_DOL,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	S_ESC,	0,	0,	0,
	S_GRAVE,0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	S_RBRA,	0,	0
};

/*
 * for skipping over ?(...), [...]
 */
static const char sh_lexstate5[256] =
{
	S_EOF,	0,	0,	0,	0,	0,	0,	0,
	0,	S_BLNK,	S_NL,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	S_BLNK,	0,	S_QUOTE,0,	S_DOL,	0,	S_META,	S_LIT,
	S_PUSH,	S_POP,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	S_POP,	S_META,	0,	S_META,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	S_BRACT,S_ESC,	S_POP,	0,	0,
	S_GRAVE,0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	S_BRACE,S_META,	S_POP,	0,	0
};

/*
 * Defines valid expansion characters
 */
static const char sh_lexstate6[256] =
{
	S_EOF,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,
	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,
	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,
	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,

	S_ERR,	S_SPC1,	S_ERR,	S_SPC1,	S_SPC2,	S_ERR,	S_ERR,	S_LIT,
	S_PAR,	S_ERR,	S_SPC2,	S_ERR,	S_ERR,	S_SPC2,	S_ALP,	S_ERR,
	S_DIG,	S_DIG,	S_DIG,	S_DIG,	S_DIG,	S_DIG,	S_DIG,	S_DIG,
	S_DIG,	S_DIG,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_SPC2,

#if SHOPT_TYPEDEF
	S_SPC1,	S_ALP,	S_ALP,	S_ALP,	S_ALP,	S_ALP,	S_ALP,	S_ALP,
#else
	S_SPC2,	S_ALP,	S_ALP,	S_ALP,	S_ALP,	S_ALP,	S_ALP,	S_ALP,
#endif
	S_ALP,	S_ALP,	S_ALP,	S_ALP,	S_ALP,	S_ALP,	S_ALP,	S_ALP,
	S_ALP,	S_ALP,	S_ALP,	S_ALP,	S_ALP,	S_ALP,	S_ALP,	S_ALP,
	S_ALP,	S_ALP,	S_ALP,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ALP,

	S_ERR,	S_ALP,	S_ALP,	S_ALP,	S_ALP,	S_ALP,	S_ALP,	S_ALP,
	S_ALP,	S_ALP,	S_ALP,	S_ALP,	S_ALP,	S_ALP,	S_ALP,	S_ALP,
	S_ALP,	S_ALP,	S_ALP,	S_ALP,	S_ALP,	S_ALP,	S_ALP,	S_ALP,
	S_ALP,	S_ALP,	S_ALP,	S_LBRA,	S_ERR,	S_RBRA,	S_ERR,	S_ERR,

	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,
	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,
	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,
	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,
	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,
	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,
	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,
	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,
	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,
	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,
	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,
	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,
	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,
	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,
	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,
	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,
};

/*
 * for skipping over ${...} until modifier
 */
static const char sh_lexstate7[256] =
{
	S_EOF,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,
	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,
	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,
	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,

	S_ERR,	S_ERR,	S_ERR,	S_MOD2,	S_ERR,	S_MOD2,	S_ERR,	S_ERR,
	S_ERR,	S_ERR,	S_MOD1,	S_MOD1,	S_ERR,	S_MOD1,	S_DOT,	S_MOD2,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	S_MOD1,	S_ERR,	S_ERR,	S_MOD1,	S_ERR,	S_MOD1,

	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	S_BRACT,S_ESC,	S_ERR,	S_ERR,	0,

	S_ERR,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	S_ERR,	S_ERR,	S_POP,	S_ERR,	S_ERR,

	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,
	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,
	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,
	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,
	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,
	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,
	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,
	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,
	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,
	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,
	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,
	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,
	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,
	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,
	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,
	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,	S_ERR,
};

/*
 * This state is for $name
 */
static const char sh_lexstate8[256] =
{
	S_EOF,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,
	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,
	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,
	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,

	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,
	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,

	S_EDOL,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	0,

	S_EDOL,0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,

	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,
	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,
	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,
	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,
	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,
	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,
	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,
	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,
	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,
	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,
	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,
	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,
	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,
	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,
	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,
	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,	S_EDOL,
};

/*
 * This is used for macro expansion
 */
static const char sh_lexstate9[256] =
{
	S_EOF,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	S_QUOTE,0,	S_DOL,	0,	S_PAT,	S_LIT,
	S_PAT,	S_PAT,	S_PAT,	0,	S_COM,	0,	S_DOT,	S_SLASH,
	S_DIG,	S_DIG,	S_DIG,	S_DIG,	S_DIG,	S_DIG,	S_DIG,	S_DIG,
	S_DIG,	S_DIG,	S_COLON,0,	0,	S_EQ,	0,	S_PAT,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	S_BRACT,S_ESC,	S_ENDCH,0,	0,
	S_GRAVE,0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
#if SHOPT_BRACEPAT
	0,	0,	0,	S_BRACE,S_PAT,	S_ENDCH,0,	0
#else
	0,	0,	0,	0,	S_PAT,	S_ENDCH,0,	0
#endif /* SHOPT_BRACEPAT */
};

const char *sh_lexrstates[ST_NONE] =
{
	sh_lexstate0, sh_lexstate1, sh_lexstate2, sh_lexstate3,
	sh_lexstate4, sh_lexstate5, sh_lexstate6, sh_lexstate7,
	sh_lexstate8, sh_lexstate9, sh_lexstate5
};


const char e_lexversion[]	= "%d: invalid binary script version";
const char e_lexspace[]		= "line %d: use space or tab to separate operators %c and %c";
const char e_lexslash[]		= "line %d: $ not preceded by \\";
const char e_lexsyntax1[]	= "syntax error at line %d: `%s' %s";
const char e_lexsyntax2[]	= "syntax error: `%s' %s";
const char e_lexsyntax3[]	= "syntax error at line %d: duplicate label %s";
const char e_lexlabignore[]	= "line %d: label %s ignored";
const char e_lexlabunknown[]	= "line %d: %s unknown label";
const char e_lexobsolete1[]	= "line %d: `...` obsolete, use $(...)";
const char e_lexobsolete2[]	= "line %d: -a obsolete, use -e";
const char e_lexobsolete3[]	= "line %d: '=' obsolete, use '=='";
const char e_lexobsolete4[]	= "line %d: %s within [[...]] obsolete, use ((...))";
const char e_lexobsolete5[]	= "line %d: set %s obsolete";
const char e_lexobsolete6[]	= "line %d: `{' instead of `in' is obsolete";
const char e_lexnonstandard[]	= "line %d: `&>file' is nonstandard -- interpreted as `>file 2>&1' for profile input only";
const char e_lexusebrace[]	= "line %d: use braces to avoid ambiguities with $id[...]";
const char e_lexusequote[]	= "line %d: %c within ${} should be quoted";
const char e_lexescape[]	= "line %d: escape %c to avoid ambiguities";
const char e_lexquote[]		= "line %d: quote %c to avoid ambiguities";
const char e_lexnested[]	= "line %d: spaces required for nested subshell";
const char e_lexbadchar[]	= "%c: invalid character in expression - %s";
const char e_lexfuture[]	= "line %d: \\ in front of %c reserved for future use";
const char e_lexlongquote[]	= "line %d: %c quote may be missing";
const char e_lexzerobyte[]	= "zero byte";
const char e_lexemptyfor[]	= "line %d: empty for list";
const char e_lextypeset[]	= "line %d: %s invalid typeset option order";
