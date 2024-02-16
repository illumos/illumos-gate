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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include "awk.h"

struct tok
{	char *tnm;
	int yval;
} tok[]	= {
"FIRSTTOKEN", 257,
"FINAL", 258,
"FATAL", 259,
"LT", 260,
"LE", 261,
"GT", 262,
"GE", 263,
"EQ", 264,
"NE", 265,
"MATCH", 266,
"NOTMATCH", 267,
"APPEND", 268,
"ADD", 269,
"MINUS", 270,
"MULT", 271,
"DIVIDE", 272,
"MOD", 273,
"UMINUS", 274,
"ASSIGN", 275,
"ADDEQ", 276,
"SUBEQ", 277,
"MULTEQ", 278,
"DIVEQ", 279,
"MODEQ", 280,
"JUMP", 281,
"XBEGIN", 282,
"XEND", 283,
"NL", 284,
"PRINT", 285,
"PRINTF", 286,
"SPRINTF", 287,
"SPLIT", 288,
"IF", 289,
"ELSE", 290,
"WHILE", 291,
"FOR", 292,
"IN", 293,
"NEXT", 294,
"EXIT", 295,
"BREAK", 296,
"CONTINUE", 297,
"PROGRAM", 298,
"PASTAT", 299,
"PASTAT2", 300,
"ASGNOP", 301,
"BOR", 302,
"AND", 303,
"NOT", 304,
"NUMBER", 305,
"VAR", 306,
"ARRAY", 307,
"FNCN", 308,
"SUBSTR", 309,
"LSUBSTR", 310,
"INDEX", 311,
"GETLINE", 312,
"RELOP", 313,
"MATCHOP", 314,
"OR", 315,
"STRING", 316,
"DOT", 317,
"CCL", 318,
"NCCL", 319,
"CHAR", 320,
"CAT", 321,
"STAR", 322,
"PLUS", 323,
"QUEST", 324,
"POSTINCR", 325,
"PREINCR", 326,
"POSTDECR", 327,
"PREDECR", 328,
"INCR", 329,
"DECR", 330,
"FIELD", 331,
"INDIRECT", 332,
"JUMPTRUE", 333,
"JUMPFALSE", 334,
"PUSH", 335,
"GETREC", 336,
"NEWSTAT", 337,
"IN_INIT", 338,
"IN_EXIT", 339,
"LASTTOKEN", 340,
};
void
ptoken(int n)
{
	if (n < 128) printf("lex: %c\n", n);
	else	if (n <= 256) printf("lex:? %o\n", n);
	else	if (n < LASTTOKEN) printf("lex: %s\n", tok[n-257].tnm);
	else	printf("lex:? %o\n", n);
}

char *
tokname(int n)
{
	if (n <= 256 || n >= LASTTOKEN)
		n = 257;
	return (tok[n-257].tnm);
}
