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
 * preprocessor C language keyword token values
 * handles classic, ANSI and C++
 * additional non-standard keyword tokens are
 * crammed into T_NOISE and T_X_*
 */

#ifndef _PPKEY_H
#define _PPKEY_H

/*
 * NOTE: preserve the ranges for is*()
 */

#define ppisnoise(x)	((x)>=T_NOISE&&(x)<T_KEYWORD)

/*
 * classic
 */

#define T_AUTO		(T_TOKEN+0)
#define T_BREAK		(T_TOKEN+1)
#define T_CASE		(T_TOKEN+2)
#define T_CHAR		(T_TOKEN+3)
#define T_CONTINUE	(T_TOKEN+4)
#define T_DEFAULT	(T_TOKEN+5)
#define T_DO		(T_TOKEN+6)
#define T_DOUBLE_T	(T_TOKEN+7)
#define T_ELSE		(T_TOKEN+8)
#define T_EXTERN	(T_TOKEN+9)
#define T_FLOAT_T	(T_TOKEN+10)
#define T_FOR		(T_TOKEN+11)
#define T_GOTO		(T_TOKEN+12)
#define T_IF		(T_TOKEN+13)
#define T_INT		(T_TOKEN+14)
#define T_LONG		(T_TOKEN+15)
#define T_REGISTER	(T_TOKEN+16)
#define T_RETURN	(T_TOKEN+17)
#define T_SHORT		(T_TOKEN+18)
#define T_SIZEOF	(T_TOKEN+19)
#define T_STATIC	(T_TOKEN+20)
#define T_STRUCT	(T_TOKEN+21)
#define T_SWITCH	(T_TOKEN+22)
#define T_TYPEDEF	(T_TOKEN+23)
#define T_UNION		(T_TOKEN+24)
#define T_UNSIGNED	(T_TOKEN+25)
#define T_WHILE		(T_TOKEN+26)

/*
 * ANSI
 */

#define T_CONST		(T_TOKEN+27)
#define T_ENUM		(T_TOKEN+28)
#define T_SIGNED	(T_TOKEN+29)
#define T_VOID		(T_TOKEN+30)
#define T_VOLATILE	(T_TOKEN+31)

/*
 * C++
 */

#define T_ASM		(T_TOKEN+32)
#define T_BOOL		(T_TOKEN+33)
#define T_CATCH		(T_TOKEN+34)
#define T_CLASS		(T_TOKEN+35)
#define T_CONST_CAST	(T_TOKEN+36)
#define T_DELETE	(T_TOKEN+37)
#define T_DYNAMIC_CAST	(T_TOKEN+38)
#define T_EXPLICIT	(T_TOKEN+39)
#define T_FALSE		(T_TOKEN+40)
#define T_FRIEND	(T_TOKEN+41)
#define T_INLINE	(T_TOKEN+42)
#define T_MUTABLE	(T_TOKEN+43)
#define T_NAMESPACE	(T_TOKEN+44)
#define T_NEW		(T_TOKEN+45)
#define T_OPERATOR	(T_TOKEN+46)
#define T_OVERLOAD	(T_TOKEN+47)
#define T_PRIVATE	(T_TOKEN+48)
#define T_PROTECTED	(T_TOKEN+49)
#define T_PUBLIC	(T_TOKEN+50)
#define T_REINTERPRET_CAST (T_TOKEN+51)
#define T_STATIC_CAST	(T_TOKEN+52)
#define T_TEMPLATE	(T_TOKEN+53)
#define T_THIS		(T_TOKEN+54)
#define T_THROW		(T_TOKEN+55)
#define T_TRUE		(T_TOKEN+56)
#define T_TRY		(T_TOKEN+57)
#define T_TYPEID	(T_TOKEN+58)
#define T_USING		(T_TOKEN+59)
#define T_VIRTUAL	(T_TOKEN+60)
#define T_WCHAR_T	(T_TOKEN+61)

/*
 * future
 */

#define T_INT64		(T_TOKEN+62)

/*
 * non-standard
 */

#define T_BUILTIN	(T_TOKEN+63)
#define T_NOISES	(T_TOKEN+64)
#define T_NOISE		(T_TOKEN+65)
#define T_X_GROUP	(T_TOKEN+66)
#define T_X_LINE	(T_TOKEN+67)
#define T_X_STATEMENT	(T_TOKEN+68)

/*
 * first available keyword token value
 */

#define T_KEYWORD	(T_TOKEN+69)

/*
 * implementation globals
 */

extern struct ppkeyword	ppkey[];

#endif
