/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include "awk.h"
/* tmaino #define NULL 0 */
#define	XNULL	"(null)"


struct xx
{	int token;
	char *name;
	char *pname;
} proc[] = {
	{ PROGRAM, "program", XNULL},
	{ BOR, "boolop", " || "},
	{ AND, "boolop", " && "},
	{ NOT, "boolop", " !"},
	{ NE, "relop", " != "},
	{ EQ, "relop", " == "},
	{ LE, "relop", " <= "},
	{ LT, "relop", " < "},
	{ GE, "relop", " >= "},
	{ GT, "relop", " > "},
	{ ARRAY, "array", XNULL},
	{ INDIRECT, "indirect", "$("},
	{ SUBSTR, "substr", "substr"},
	{ INDEX, "sindex", "sindex"},
	{ SPRINTF, "a_sprintf", "sprintf "},
	{ ADD, "arith", " + "},
	{ MINUS, "arith", " - "},
	{ MULT, "arith", " * "},
	{ DIVIDE, "arith", " / "},
	{ MOD, "arith", " % "},
	{ UMINUS, "arith", " -"},
	{ PREINCR, "incrdecr", "++"},
	{ POSTINCR, "incrdecr", "++"},
	{ PREDECR, "incrdecr", "--"},
	{ POSTDECR, "incrdecr", "--"},
	{ CAT, "cat", " "},
	{ PASTAT, "pastat", XNULL},
	{ PASTAT2, "dopa2", XNULL},
	{ MATCH, "matchop", " ~ "},
	{ NOTMATCH, "matchop", " !~ "},
	{ PRINTF, "aprintf", "printf"},
	{ PRINT, "print", "print"},
	{ SPLIT, "split", "split"},
	{ ASSIGN, "assign", " = "},
	{ ADDEQ, "assign", " += "},
	{ SUBEQ, "assign", " -= "},
	{ MULTEQ, "assign", " *= "},
	{ DIVEQ, "assign", " /= "},
	{ MODEQ, "assign", " %= "},
	{ IF, "ifstat", "if("},
	{ WHILE, "whilestat", "while("},
	{ FOR, "forstat", "for("},
	{ IN, "instat", "instat"},
	{ NEXT, "jump", "next"},
	{ EXIT, "jump", "exit"},
	{ BREAK, "jump", "break"},
	{ CONTINUE, "jump", "continue"},
	{ FNCN, "fncn", "fncn"},
	{ GETLINE, "getline", "getline"},
	{ 0, ""},
};
#define	SIZE	LASTTOKEN - FIRSTTOKEN
char *table[SIZE];
char *names[SIZE];

int
main(void)
{
	struct xx *p;
	int i;


	printf("#include \"awk.def\"\n");
	printf("CELL *nullproc();\n");
	for (i = SIZE; --i >= 0; /* dummy */)
		names[i] = "";
	for (p = proc; p->token != 0; p++)
		if (p == proc || strcmp(p->name, (p-1)->name))
			printf("extern CELL *%s();\n", p->name);
	for (p = proc; p->token != 0; p++)
		table[p->token-FIRSTTOKEN] = p->name;
	printf("CELL *(*proctab[%d])() = {\n", SIZE);
	for (i = 0; i < SIZE; i++)
		if (table[i] == 0)
			printf("/*%s*/\tnullproc,\n", tokname(i+FIRSTTOKEN));
		else
		printf("/*%s*/\t%s,\n", tokname(i+FIRSTTOKEN), table[i]);
	printf("};\n");
	printf("char *printname[%d] = {\n", SIZE);
	for (p = proc; p->token != 0; p++)
		names[p->token-FIRSTTOKEN] = p->pname;
	for (i = 0; i < SIZE; i++)
		printf("/*%s*/\t\"%s\",\n", tokname(i+FIRSTTOKEN), names[i]);
	printf("};\n");
	return (0);
}
