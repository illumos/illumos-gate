/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1982-2011 AT&T Intellectual Property          *
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
*                  David Korn <dgk@research.att.com>                   *
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * data for string evaluator library
 */

#include	<ast_standards.h>
#include	"FEATURE/options"
#include	"streval.h"

const unsigned char strval_precedence[35] =
	/* opcode	precedence,assignment  */
{
	/* DEFAULT */		MAXPREC|NOASSIGN,
	/* DONE */		0|NOASSIGN|RASSOC,
	/* NEQ */		10|NOASSIGN,
	/* NOT */		MAXPREC|NOASSIGN,
	/* MOD */		14,
	/* ANDAND */		6|NOASSIGN|SEQPOINT,
	/* AND */		9|NOFLOAT,
	/* LPAREN */		MAXPREC|NOASSIGN|SEQPOINT,
	/* RPAREN */		1|NOASSIGN|RASSOC|SEQPOINT,
	/* POW */		14|NOASSIGN|RASSOC,
	/* TIMES */		14,
	/* PLUSPLUS */		15|NOASSIGN|NOFLOAT|SEQPOINT,
	/* PLUS */		13,	
	/* COMMA */		1|NOASSIGN|SEQPOINT,
	/* MINUSMINUS */	15|NOASSIGN|NOFLOAT|SEQPOINT,
	/* MINUS */		13,
	/* DIV */		14,
	/* LSHIFT */		12|NOFLOAT,
	/* LE */		11|NOASSIGN,
	/* LT */		11|NOASSIGN,	
	/* EQ */		10|NOASSIGN,
	/* ASSIGNMENT */	2|RASSOC,
	/* COLON */		0|NOASSIGN,
	/* RSHIFT */		12|NOFLOAT,	
	/* GE */		11|NOASSIGN,
	/* GT */		11|NOASSIGN,
	/* QCOLON */		3|NOASSIGN|SEQPOINT,
	/* QUEST */		3|NOASSIGN|SEQPOINT|RASSOC,
	/* XOR */		8|NOFLOAT,
	/* OROR */		5|NOASSIGN|SEQPOINT,
	/* OR */		7|NOFLOAT,
	/* DEFAULT */		MAXPREC|NOASSIGN,
	/* DEFAULT */		MAXPREC|NOASSIGN,
	/* DEFAULT */		MAXPREC|NOASSIGN,
	/* DEFAULT */		MAXPREC|NOASSIGN
};

/*
 * This is for arithmetic expressions
 */
const char strval_states[64] =
{
	A_EOF,	A_REG,	A_REG,	A_REG,	A_REG,	A_REG,	A_REG,	A_REG,
	A_REG,	0,	0,	A_REG,	A_REG,	A_REG,	A_REG,	A_REG,
	A_REG,	A_REG,	A_REG,	A_REG,	A_REG,	A_REG,	A_REG,	A_REG,
	A_REG,	A_REG,	A_REG,	A_REG,	A_REG,	A_REG,	A_REG,	A_REG,

	0,	A_NOT,	0,	A_REG,	A_REG,	A_MOD,	A_AND,	A_LIT,
	A_LPAR,	A_RPAR,	A_TIMES,A_PLUS,	A_COMMA,A_MINUS,A_DOT,	A_DIV,
	A_DIG,	A_DIG,	A_DIG,	A_DIG,	A_DIG,	A_DIG,	A_DIG,	A_DIG,
	A_DIG,	A_DIG,	A_COLON,A_REG,	A_LT,	A_ASSIGN,A_GT,	A_QUEST

};


const char e_argcount[]		= "%s: function has wrong number of arguments";
const char e_badnum[]		= "%s: bad number";
const char e_moretokens[]	= "%s: more tokens expected";
const char e_paren[]		= "%s: unbalanced parenthesis";
const char e_badcolon[]		= "%s: invalid use of :";
const char e_divzero[]		= "%s: divide by zero";
const char e_synbad[]		= "%s: arithmetic syntax error";
const char e_notlvalue[]	= "%s: assignment requires lvalue";
const char e_recursive[]	= "%s: recursion too deep";
const char e_questcolon[]	= "%s: ':' expected for '?' operator";
const char e_function[]		= "%s: unknown function";
const char e_incompatible[]	= "%s: invalid floating point operation";
const char e_overflow[]		= "%s: overflow exception";
const char e_domain[]		= "%s: domain exception";
const char e_singularity[]	= "%s: singularity exception";
const char e_charconst[]	= "%s: invalid character constant";

#include	"FEATURE/math"
