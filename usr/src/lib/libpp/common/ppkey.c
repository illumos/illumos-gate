/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1986-2008 AT&T Intellectual Property          *
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
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * Glenn Fowler
 * AT&T Research
 *
 * preprocessor C language reserved keyword token table
 * for use by PP_COMPILE
 *
 * "-" keywords entered without SYM_KEYWORD
 * "+" keywords entered without SYM_KEYWORD unless PP_PLUSPLUS was set
 * upper case are pseudo keywords for PP_RESERVED token classes
 */

#include "pplib.h"
#include "ppkey.h"

struct ppkeyword	ppkey[] =
{
	"auto",		T_AUTO,
	"break",	T_BREAK,
	"case",		T_CASE,
	"char",		T_CHAR,
	"continue",	T_CONTINUE,
	"default",	T_DEFAULT,
	"do",		T_DO,
	"double",	T_DOUBLE_T,
	"else",		T_ELSE,
	"extern",	T_EXTERN,
	"float",	T_FLOAT_T,
	"for",		T_FOR,
	"goto",		T_GOTO,
	"if",		T_IF,
	"int",		T_INT,
	"long",		T_LONG,
	"register",	T_REGISTER,
	"return",	T_RETURN,
	"short",	T_SHORT,
	"sizeof",	T_SIZEOF,
	"static",	T_STATIC,
	"struct",	T_STRUCT,
	"switch",	T_SWITCH,
	"typedef",	T_TYPEDEF,
	"union",	T_UNION,
	"unsigned",	T_UNSIGNED,
	"while",	T_WHILE,
	"-const",	T_CONST,
	"-enum",	T_ENUM,
	"-signed",	T_SIGNED,
	"-void",	T_VOID,
	"-volatile",	T_VOLATILE,
	"+asm",		T_ASM,
	"+class",	T_CLASS,
	"+delete",	T_DELETE,
	"+friend",	T_FRIEND,
	"+inline",	T_INLINE,
	"+new",		T_NEW,
	"+operator",	T_OPERATOR,
	"+overload",	T_OVERLOAD,
	"+private",	T_PRIVATE,
	"+public",	T_PUBLIC,
	"+this",	T_THIS,
	"+virtual",	T_VIRTUAL,
	"-and",		T_ANDAND,
	"-and_eq",	T_ANDEQ,
	"-bitand",	'&',
	"-bitor",	'|',
	"-bool",	T_BOOL,
	"-catch",	T_CATCH,
	"-compl",	'~',
	"-const_cast",	T_CONST_CAST,
	"-dynamic_cast",T_DYNAMIC_CAST,
	"-explicit",	T_EXPLICIT,
	"-false",	T_FALSE,
	"-mutable",	T_MUTABLE,
	"-namespace",	T_NAMESPACE,
	"-not",		'!',
	"-not_eq",	T_NE,
	"-or",		T_OROR,
	"-or_eq",	T_OREQ,
	"-protected",	T_PROTECTED,
	"-reinterpret_cast", T_REINTERPRET_CAST,
	"-static_cast",	T_STATIC_CAST,
	"-template",	T_TEMPLATE,
	"-throw",	T_THROW,
	"-true",	T_TRUE,
	"-try",		T_TRY,
	"-typeid",	T_TYPEID,
	"-using",	T_USING,
	"-wchar_t",	T_WCHAR_T,
	"-xor",		'^',
	"-xor_eq",	T_XOREQ,
	"-int64",	T_INT64,
	"-NOISES",	T_NOISES,
	"-NOISE",	T_NOISE,
	"-GROUP",	T_X_GROUP,
	"-LINE",	T_X_LINE,
	"-STATEMENT",	T_X_STATEMENT,
	0, 0, 0
};
