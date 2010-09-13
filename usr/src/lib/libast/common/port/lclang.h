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
/*
 * lc (sub)lang definitions -- very windowsish
 */

#if _WINIX

#include <ast_windows.h>

#define LANG_CHINESE_SIMPLIFIED			LANG_CHINESE
#define LANG_CHINESE_TRADITIONAL		LANG_CHINESE
#define LANG_NORWEGIAN_BOKMAL			LANG_NORWEGIAN
#define LANG_NORWEGIAN_NYNORSK			LANG_NORWEGIAN
#define LANG_SERBO_CROATIAN			LANG_CROATIAN

#define CTRY_CZECH_REPUBLIC			CTRY_CZECH

#define SUBLANG_CHINESE_SIMPLIFIED_CHINA	SUBLANG_CHINESE_SIMPLIFIED
#define SUBLANG_CHINESE_SIMPLIFIED_HONG_KONG	SUBLANG_CHINESE_HONGKONG
#define SUBLANG_CHINESE_SIMPLIFIED_SINGAPORE	SUBLANG_CHINESE_SINGAPORE
#define SUBLANG_CHINESE_TRADITIONAL_TAIWAN	SUBLANG_CHINESE_TRADITIONAL
#define SUBLANG_DUTCH_NETHERLANDS_ANTILLES	SUBLANG_DUTCH
#define SUBLANG_DUTCH_BELGIUM			SUBLANG_DUTCH_BELGIAN
#define SUBLANG_ENGLISH_AUSTRALIA		SUBLANG_ENGLISH_AUS
#define SUBLANG_ENGLISH_CANADA			SUBLANG_ENGLISH_CAN
#define SUBLANG_ENGLISH_IRELAND			SUBLANG_ENGLISH_EIRE
#define SUBLANG_ENGLISH_NEW_ZEALAND		SUBLANG_ENGLISH_NZ
#define SUBLANG_ENGLISH_TRINIDAD_TOBAGO		SUBLANG_ENGLISH_CARIBBEAN
#define SUBLANG_ENGLISH_UNITED_KINGDOM		SUBLANG_ENGLISH_UK
#define SUBLANG_ENGLISH_UNITED_STATES		SUBLANG_ENGLISH_US
#define SUBLANG_FRENCH_BELGIUM			SUBLANG_FRENCH_BELGIAN
#define SUBLANG_FRENCH_CANADA			SUBLANG_FRENCH_CANADIAN
#define SUBLANG_FRENCH_SWITZERLAND		SUBLANG_FRENCH_SWISS
#define SUBLANG_GERMAN_AUSTRIA			SUBLANG_GERMAN_AUSTRIAN
#define SUBLANG_GERMAN_SWITZERLAND		SUBLANG_GERMAN_SWISS
#define SUBLANG_ITALIAN_SWITZERLAND		SUBLANG_ITALIAN_SWISS
#define SUBLANG_NORWEGIAN_BOKMAL_NORWAY		SUBLANG_NORWEGIAN_BOKMAL
#define SUBLANG_NORWEGIAN_NORWAY		SUBLANG_NORWEGIAN_BOKMAL
#define SUBLANG_NORWEGIAN_NYNORSK_NORWAY	SUBLANG_NORWEGIAN_NYNORSK
#define SUBLANG_PORTUGUESE_BRAZIL		SUBLANG_PORTUGUESE_BRAZILIAN

#endif
