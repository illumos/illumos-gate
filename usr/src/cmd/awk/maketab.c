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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libintl.h>
#include "awk.h"
#include "y.tab.h"

struct xx {
	int token;
	char *name;
	char *pname;
} proc[] = {
	{ PROGRAM, "program", NULL },
	{ BOR, "boolop", " || " },
	{ AND, "boolop", " && " },
	{ NOT, "boolop", " !" },
	{ NE, "relop", " != " },
	{ EQ, "relop", " == " },
	{ LE, "relop", " <= " },
	{ LT, "relop", " < " },
	{ GE, "relop", " >= " },
	{ GT, "relop", " > " },
	{ ARRAY, "array", NULL },
	{ INDIRECT, "indirect", "$(" },
	{ SUBSTR, "substr", "substr" },
	{ SUB, "sub", "sub" },
	{ GSUB, "gsub", "gsub" },
	{ INDEX, "sindex", "sindex" },
	{ SPRINTF, "a_sprintf", "sprintf " },
	{ ADD, "arith", " + " },
	{ MINUS, "arith", " - " },
	{ MULT, "arith", " * " },
	{ DIVIDE, "arith", " / " },
	{ MOD, "arith", " % " },
	{ UMINUS, "arith", " -" },
	{ POWER, "arith", " **" },
	{ PREINCR, "incrdecr", "++" },
	{ POSTINCR, "incrdecr", "++" },
	{ PREDECR, "incrdecr", "--" },
	{ POSTDECR, "incrdecr", "--" },
	{ CAT, "cat", " " },
	{ PASTAT, "pastat", NULL },
	{ PASTAT2, "dopa2", NULL },
	{ MATCH, "matchop", " ~ " },
	{ NOTMATCH, "matchop", " !~ " },
	{ MATCHFCN, "matchop", "matchop" },
	{ INTEST, "intest", "intest" },
	{ PRINTF, "aprintf", "printf" },
	{ PRINT, "print", "print" },
	{ CLOSE, "closefile", "closefile" },
	{ DELETE, "delete", "delete" },
	{ SPLIT, "split", "split" },
	{ ASSIGN, "assign", " = " },
	{ ADDEQ, "assign", " += " },
	{ SUBEQ, "assign", " -= " },
	{ MULTEQ, "assign", " *= " },
	{ DIVEQ, "assign", " /= " },
	{ MODEQ, "assign", " %= " },
	{ POWEQ, "assign", " ^= " },
	{ CONDEXPR, "condexpr", " ?: " },
	{ IF, "ifstat", "if(" },
	{ WHILE, "whilestat", "while(" },
	{ FOR, "forstat", "for(" },
	{ DO, "dostat", "do" },
	{ IN, "instat", "instat" },
	{ NEXT, "jump", "next" },
	{ EXIT, "jump", "exit" },
	{ BREAK, "jump", "break" },
	{ CONTINUE, "jump", "continue" },
	{ RETURN, "jump", "ret" },
	{ BLTIN, "bltin", "bltin" },
	{ CALL, "call", "call" },
	{ ARG, "arg", "arg" },
	{ VARNF, "getnf", "NF" },
	{ GETLINE, "getline", "getline" },
	{ 0, "", "" },
};

#define	SIZE	LASTTOKEN - FIRSTTOKEN + 1
char *table[SIZE];
char *names[SIZE];

int
main()
{
	struct xx *p;
	int i, n, tok;
	char c;
	FILE *fp;
	char buf[100], name[100], def[100];

	printf("#include \"awk.h\"\n");
	printf("#include \"y.tab.h\"\n\n");

	if ((fp = fopen("y.tab.h", "r")) == NULL) {
		fprintf(stderr, gettext("maketab can't open y.tab.h!\n"));
		exit(1);
	}
	printf("static uchar *printname[%d] = {\n", SIZE);
	i = 0;
	while (fgets(buf, sizeof (buf), fp) != NULL) {
		n = sscanf(buf, "%1c %s %s %d", &c, def, name, &tok);
		/* not a valid #define? */
		if (c != '#' || n != 4 && strcmp(def, "define") != 0)
			continue;
		if (tok < FIRSTTOKEN || tok > LASTTOKEN) {
			fprintf(stderr, gettext("maketab funny token %d %s\n"),
			    tok, buf);
			exit(1);
		}
		names[tok-FIRSTTOKEN] = malloc(strlen(name)+1);
		strcpy(names[tok-FIRSTTOKEN], name);
		printf("\t(uchar *) \"%s\",\t/* %d */\n", name, tok);
		i++;
	}
	printf("};\n\n");

	for (p = proc; p->token != 0; p++)
		table[p->token-FIRSTTOKEN] = p->name;
	printf("\nCell *(*proctab[%d])() = {\n", SIZE);
	for (i = 0; i < SIZE; i++)
		if (table[i] == 0)
			printf("\tnullproc,\t/* %s */\n", names[i]);
		else
			printf("\t%s,\t/* %s */\n", table[i], names[i]);
	printf("};\n\n");

	printf("uchar *\ntokname(int n)\n");	/* print a tokname() function */
	printf("{\n");
	printf("	static char buf[100];\n\n");
	printf("	if (n < FIRSTTOKEN || n > LASTTOKEN) {\n");
	printf("		(void) sprintf(buf, \"token %%d\", n);\n");
	printf("		return ((uchar *)buf);\n");
	printf("	}\n");
	printf("	return printname[n-257];\n");
	printf("}\n");
	exit(0);
}
