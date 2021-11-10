/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/


/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/euc.h>
#include <stdlib.h>
#include <widec.h>
#include <limits.h>
#include <inttypes.h>
#include <unistd.h>

#pragma weak yyprevious
extern int yyprevious;

#ifndef JLSLEX
#define	CHR    char

#pragma weak yyinput
#pragma weak yyleng
#pragma weak yyunput
#pragma weak yytext
extern CHR yytext[];

#define	YYTEXT yytext
#define	YYLENG yyleng
#define	YYINPUT yyinput
#define	YYUNPUT yyunput
#define	YYOUTPUT yyoutput
#endif

#ifdef WOPTION
#define	CHR    wchar_t

#pragma weak yyinput
#pragma weak yyleng
#pragma weak yyunput
#pragma weak yytext
extern CHR yytext[];

#define	YYTEXT yytext
#define	YYLENG yyleng
#define	YYINPUT yyinput
#define	YYUNPUT yyunput
#define	YYOUTPUT yyoutput
#endif

#ifdef EOPTION
#define	CHR    wchar_t

#pragma weak yyleng
extern int yyleng;
#pragma weak yytext
extern CHR yytext[];
#pragma weak yywinput
#pragma weak yywleng
#pragma weak yywunput
#pragma weak yywtext
extern CHR yywtext[];

#define	YYTEXT yywtext
#define	YYLENG yywleng
#define	YYINPUT yywinput
#define	YYUNPUT yywunput
#define	YYOUTPUT yywoutput
#endif

extern int YYLENG;
extern void YYUNPUT(int);

/* XCU4: type of yyless() changes to int */
int
yyless(int x)
{
	CHR *lastch, *ptr;

	lastch = YYTEXT+YYLENG;
	if (x >= 0 && x <= YYLENG)
		ptr = x + YYTEXT;
	else {
#ifdef	_LP64
		static int seen = 0;

		if (!seen) {
			(void) write(2,
			    "warning: yyless pointer arg truncated\n", 39);
			seen = 1;
		}
#endif	/* _LP64 */
	/*
	 * The cast on the next line papers over an unconscionable nonportable
	 * glitch to allow the caller to hand the function a pointer instead of
	 * an integer and hope that it gets figured out properly.  But it's
	 * that way on all systems.
	 */
		ptr = (CHR *)(intptr_t)x;
	}
	while (lastch > ptr)
		YYUNPUT(*--lastch);
	*lastch = 0;
	if (ptr > YYTEXT)
		yyprevious = *--lastch;
	YYLENG = ptr-YYTEXT;
#ifdef EOPTION
	yyleng = wcstombs((char *)yytext, YYTEXT, YYLENG*MB_LEN_MAX);
#endif
	return (0);
}
