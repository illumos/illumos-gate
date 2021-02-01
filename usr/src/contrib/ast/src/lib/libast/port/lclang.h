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
/*
 * lc (sub)lang definitions -- very windowsish
 */

#if _WINIX

#include <ast_windows.h>

#ifndef LANG_CHINESE_SIMPLIFIED
#define LANG_CHINESE_SIMPLIFIED			LANG_CHINESE
#endif
#ifndef LANG_CHINESE_TRADITIONAL
#define LANG_CHINESE_TRADITIONAL		LANG_CHINESE
#endif
#ifndef LANG_NORWEGIAN_BOKMAL
#define LANG_NORWEGIAN_BOKMAL			LANG_NORWEGIAN
#endif
#ifndef LANG_NORWEGIAN_NYNORSK
#define LANG_NORWEGIAN_NYNORSK			LANG_NORWEGIAN
#endif
#ifndef LANG_SERBO_CROATIAN
#define LANG_SERBO_CROATIAN			LANG_CROATIAN
#endif

#ifndef CTRY_CZECH_REPUBLIC
#define CTRY_CZECH_REPUBLIC			CTRY_CZECH
#endif

#ifndef SUBLANG_CHINESE_SIMPLIFIED_CHINA
#define SUBLANG_CHINESE_SIMPLIFIED_CHINA	SUBLANG_CHINESE_SIMPLIFIED
#endif
#ifndef SUBLANG_CHINESE_SIMPLIFIED_HONG_KONG
#define SUBLANG_CHINESE_SIMPLIFIED_HONG_KONG	SUBLANG_CHINESE_HONGKONG
#endif
#ifndef SUBLANG_CHINESE_SIMPLIFIED_SINGAPORE
#define SUBLANG_CHINESE_SIMPLIFIED_SINGAPORE	SUBLANG_CHINESE_SINGAPORE
#endif
#ifndef SUBLANG_CHINESE_TRADITIONAL_TAIWAN
#define SUBLANG_CHINESE_TRADITIONAL_TAIWAN	SUBLANG_CHINESE_TRADITIONAL
#endif
#ifndef SUBLANG_DUTCH_NETHERLANDS_ANTILLES
#define SUBLANG_DUTCH_NETHERLANDS_ANTILLES	SUBLANG_DUTCH
#endif
#ifndef SUBLANG_DUTCH_BELGIUM		
#define SUBLANG_DUTCH_BELGIUM			SUBLANG_DUTCH_BELGIAN
#endif
#ifndef SUBLANG_ENGLISH_AUSTRALIA	
#define SUBLANG_ENGLISH_AUSTRALIA		SUBLANG_ENGLISH_AUS
#endif
#ifndef SUBLANG_ENGLISH_CANADA		
#define SUBLANG_ENGLISH_CANADA			SUBLANG_ENGLISH_CAN
#endif
#ifndef SUBLANG_ENGLISH_IRELAND		
#define SUBLANG_ENGLISH_IRELAND			SUBLANG_ENGLISH_EIRE
#endif
#ifndef SUBLANG_ENGLISH_NEW_ZEALAND	
#define SUBLANG_ENGLISH_NEW_ZEALAND		SUBLANG_ENGLISH_NZ
#endif
#ifndef SUBLANG_ENGLISH_TRINIDAD_TOBAGO	
#define SUBLANG_ENGLISH_TRINIDAD_TOBAGO		SUBLANG_ENGLISH_CARIBBEAN
#endif
#ifndef SUBLANG_ENGLISH_UNITED_KINGDOM	
#define SUBLANG_ENGLISH_UNITED_KINGDOM		SUBLANG_ENGLISH_UK
#endif
#ifndef SUBLANG_ENGLISH_UNITED_STATES	
#define SUBLANG_ENGLISH_UNITED_STATES		SUBLANG_ENGLISH_US
#endif
#ifndef SUBLANG_FRENCH_BELGIUM		
#define SUBLANG_FRENCH_BELGIUM			SUBLANG_FRENCH_BELGIAN
#endif
#ifndef SUBLANG_FRENCH_CANADA		
#define SUBLANG_FRENCH_CANADA			SUBLANG_FRENCH_CANADIAN
#endif
#ifndef SUBLANG_FRENCH_SWITZERLAND	
#define SUBLANG_FRENCH_SWITZERLAND		SUBLANG_FRENCH_SWISS
#endif
#ifndef SUBLANG_GERMAN_AUSTRIA		
#define SUBLANG_GERMAN_AUSTRIA			SUBLANG_GERMAN_AUSTRIAN
#endif
#ifndef SUBLANG_GERMAN_SWITZERLAND	
#define SUBLANG_GERMAN_SWITZERLAND		SUBLANG_GERMAN_SWISS
#endif
#ifndef SUBLANG_ITALIAN_SWITZERLAND	
#define SUBLANG_ITALIAN_SWITZERLAND		SUBLANG_ITALIAN_SWISS
#endif
#ifndef SUBLANG_NORWEGIAN_BOKMAL_NORWAY	
#define SUBLANG_NORWEGIAN_BOKMAL_NORWAY		SUBLANG_NORWEGIAN_BOKMAL
#endif
#ifndef SUBLANG_NORWEGIAN_NORWAY	
#define SUBLANG_NORWEGIAN_NORWAY		SUBLANG_NORWEGIAN_BOKMAL
#endif
#ifndef SUBLANG_NORWEGIAN_NYNORSK_NORWAY
#define SUBLANG_NORWEGIAN_NYNORSK_NORWAY	SUBLANG_NORWEGIAN_NYNORSK
#endif
#ifndef SUBLANG_PORTUGUESE_BRAZIL	
#define SUBLANG_PORTUGUESE_BRAZIL		SUBLANG_PORTUGUESE_BRAZILIAN
#endif

#endif
