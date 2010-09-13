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
/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Read in "high-level" adb script and emit C program.
 * The input may have specifications within {} which
 * we analyze and then emit C code to generate the
 * ultimate adb acript.
 * We are just a filter; no arguments are accepted.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define	streq(s1, s2)	(strcmp(s1, s2) == 0)

#define	LINELEN  	1024	/* max line length expected in input */
#define	STRLEN		128	/* for shorter strings */
#define	NARGS		5	/* number of emitted subroutine arguments */

/*
 * Format specifier strings
 * which are recognized by adbgen when surrounded by {}
 */
#define	FSTR_PTR	"POINTER"
#define	FSTR_LONG_DEC	"LONGDEC"
#define	FSTR_LONG_OCT	"LONGOCT"
#define	FSTR_ULONG_DEC	"ULONGDEC"
#define	FSTR_ULONG_HEX	"ULONGHEX"
#define	FSTR_ULONG_OCT	"ULONGOCT"

/*
 * Types of specifications in {}.
 */
#define	PTR_HEX		0	/* emit hex pointer format char */
#define	LONG_DEC	1	/* emit decimal long format char */
#define	LONG_OCT	2	/* emit octal unsigned long format char */
#define	ULONG_DEC	3	/* emit decimal unsigned long format char */
#define	ULONG_HEX	4	/* emit hexadecimal long format char */
#define	ULONG_OCT	5	/* emit octal unsigned long format char */

#define	FMT_ENTRIES	6	/* number of adbgen format specifier strings */

#define	PRINT   	6	/* print member name with format */
#define	INDIRECT	7	/* fetch member value */
#define	OFFSETOK	8	/* insist that the offset is ok */
#define	SIZEOF		9	/* print sizeof struct */
#define	END		10	/* get offset to end of struct */
#define	OFFSET		11	/* just emit offset */
#define	EXPR		12	/* arbitrary C expression */

/*
 * Special return code from nextchar.
 */
#define	CPP		-2	/* cpp line, restart parsing */

typedef struct adbgen_fmt {
	char *f_str;
	char f_char;
} adbgen_fmt_t;

char struct_name[STRLEN];	/* struct name */
char member[STRLEN];		/* member name */
char format[STRLEN];		/* adb format spec */
char arg[NARGS][STRLEN];	/* arg list for called subroutine */
char *ptr_hex_fmt;		/* adb format character for pointer in hex */
char *long_dec_fmt;		/* adb format character for long in decimal */
char *ulong_dec_fmt;		/* adb format character for ulong in decimal */
char *ulong_hex_fmt;		/* adb format character for ulong in hex */
char *long_oct_fmt;		/* adb format character for long in octal */
char *ulong_oct_fmt;		/* adb format character for ulong in octal */

int line_no = 1;		/* input line number - for error messages */
int specsize;			/* size of {} specification - 1 or 2 parts */
int state;			/* XXX 1 = gathering a printf */
				/* This is a kludge so we emit pending */
				/* printf's when we see a CPP line */

adbgen_fmt_t adbgen_fmt_tbl [FMT_ENTRIES] = {
	{FSTR_PTR},
	{FSTR_LONG_DEC},
	{FSTR_LONG_OCT},
	{FSTR_ULONG_DEC},
	{FSTR_ULONG_HEX},
	{FSTR_ULONG_OCT}
};

void emit_call(char *name, int nargs);
void emit_end(void);
void emit_expr(void);
void emit_indirect(void);
void emit_offset(void);
void emit_offsetok(void);
void emit_print(void);
void emit_printf(char *cp);
void emit_sizeof(void);
void generate(void);
int get_type(void);
int nextchar(char *cp);
void read_spec(void);
char *start_printf(void);

int
main(int argc, char **argv)
{
	char *cp;
	int c;
	int warn_flag = 0;
	int is_lp64 = 0;
	char *usage = "adbgen1 [-w] [-m ilp32|lp64] < <macro file>\n";

	while ((c = getopt(argc, argv, "m:w")) != EOF) {
		switch (c) {
		case 'm':
			if (streq(optarg, "ilp32"))
				is_lp64 = 0;
			else if (streq(optarg, "lp64"))
				is_lp64 = 1;
			else
				fprintf(stderr, usage);
			break;
		case 'w':
			warn_flag++;
			break;
		case '?':
			fprintf(stderr, usage);
			break;
		}
	}
	if (is_lp64) {
		adbgen_fmt_tbl[PTR_HEX].f_char = 'J';
		adbgen_fmt_tbl[LONG_DEC].f_char = 'e';
		adbgen_fmt_tbl[LONG_OCT].f_char = 'g';
		adbgen_fmt_tbl[ULONG_DEC].f_char = 'E';
		adbgen_fmt_tbl[ULONG_HEX].f_char = 'J';
		adbgen_fmt_tbl[ULONG_OCT].f_char = 'G';
	} else {
		adbgen_fmt_tbl[PTR_HEX].f_char = 'X';
		adbgen_fmt_tbl[LONG_DEC].f_char = 'D';
		adbgen_fmt_tbl[LONG_OCT].f_char = 'Q';
		adbgen_fmt_tbl[ULONG_DEC].f_char = 'U';
		adbgen_fmt_tbl[ULONG_HEX].f_char = 'X';
		adbgen_fmt_tbl[ULONG_OCT].f_char = 'O';
	}

	/*
	 * Get structure name.
	 */
	cp = struct_name;
	while ((c = nextchar(NULL)) != '\n') {
		if (c == EOF) {
			fprintf(stderr, "Premature EOF\n");
			exit(1);
		}
		if (c == CPP)
			continue;
		*cp++ = (char)c;
	}
	*cp = '\0';
	/*
	 * Basically, the generated program is just an ongoing printf
	 * with breaks for {} format specifications.
	 */
	printf("\n");
	printf("#include <sys/types.h>\n");
	printf("#include <sys/inttypes.h>\n");
	printf("\n\n");
	printf("int do_fmt(char *acp);\n");
	printf("void format(char *name, size_t size, char *fmt);\n");
	printf("void indirect(off_t offset, size_t size, "
	    "char *base, char *member);\n");
	printf("void offset(off_t off);\n");
	printf("void offsetok(void);\n");
	printf("\n\n");
	printf("main(int argc, char *argv[])\n");
	printf("{\n");
	if (warn_flag) {
		printf("\textern int warnings;\n\n\twarnings = 0;\n");
	}
	cp = start_printf();
	while ((c = nextchar(cp)) != EOF) {
		switch (c) {
		case '"':
			*cp++ = '\\';	/* escape ' in string */
			*cp++ = '"';
			break;
		case '\n':
			*cp++ = '\\';	/* escape newline in string */
			*cp++ = 'n';
			break;
		case '{':
			emit_printf(cp);
			read_spec();
			generate();
			cp = start_printf();
			break;
		case CPP:
			/*
			 * Restart printf after cpp line.
			 */
			cp = start_printf();
			break;
		default:
			*cp++ = c;
			break;
		}
		if (cp - arg[1] >= STRLEN - 10) {
			emit_printf(cp);
			cp = start_printf();
		}
	}
	emit_printf(cp);

	/* terminate program, checking for "error" mode */
	printf("\n\tif (argc > 1 && strcmp(argv[1], \"-e\") == 0) {\n");
	printf("\t\textern int warns;\n\n");
	printf("\t\tif (warns)\n");
	printf("\t\t\treturn (1);\n");
	printf("\t}\n");
	printf("\treturn (0);\n");
	printf("}\n");

	return (0);
}

int
nextchar(char *cp)
{
	int c;
	static int newline = 1;

	c = getchar();
	/*
	 * Lines beginning with '#' and blank lines are passed right through.
	 */
	while (newline) {
		switch (c) {
		case '#':
			if (state)
				emit_printf(cp);
			do {
				putchar(c);
				c = getchar();
				if (c == EOF)
					return (c);
			} while (c != '\n');
			putchar(c);
			line_no++;
			return (CPP);
		case '\n':
			if (state)
				emit_printf(cp);
			putchar(c);
			c = getchar();
			line_no++;
			break;
		default:
			newline = 0;
			break;
		}
	}
	if (c == '\n') {
		newline++;
		line_no++;
	}
	return (c);
}

/*
 * Get started on printf of ongoing adb script.
 */
char *
start_printf(void)
{
	char *cp;

	strcpy(arg[0], "\"%s\"");
	cp = arg[1];
	*cp++ = '"';
	state = 1;			/* XXX */
	return (cp);
}

/*
 * Emit call to printf to print part of ongoing adb script.
 */
void
emit_printf(cp)
	char *cp;
{
	*cp++ = '"';
	*cp = '\0';
	emit_call("printf", 2);
	state = 0;			/* XXX */
}

/*
 * Read {} specification.
 * The first part (up to a comma) is put into "member".
 * The second part, if present, is put into "format".
 */
void
read_spec(void)
{
	char *cp;
	int c;
	int nesting;

	cp = member;
	specsize = 1;
	nesting = 0;
	while ((c = nextchar(NULL)) != '}' || (c == '}' && nesting)) {
		switch (c) {
		case EOF:
			fprintf(stderr, "Unexpected EOF inside {}\n");
			exit(1);
		case '\n':
			fprintf(stderr, "Newline not allowed in {}, line %d\n",
				line_no);
			exit(1);
		case '#':
			fprintf(stderr, "# not allowed in {}, line %d\n",
				line_no);
			exit(1);
		case ',':
			if (specsize == 2) {
				fprintf(stderr, "Excessive commas in {}, ");
				fprintf(stderr, "line %d\n", line_no);
				exit(1);
			}
			specsize = 2;
			*cp = '\0';
			cp = format;
			break;
		case '{':
			/*
			 * Allow up to one set of nested {}'s for adbgen
			 * requests of the form {member, {format string}}
			 */
			if (!nesting) {
				nesting = 1;
				*cp++ = c;
			} else {
				fprintf(stderr, "Too many {'s, line %d\n",
					line_no);
				exit(1);
			}
			break;
		case '}':
			*cp++ = c;
			nesting = 0;
			break;
		default:
			*cp++ = c;
			break;
		}
	}
	*cp = '\0';
	if (cp == member) {
		specsize = 0;
	}
}

/*
 * Decide what type of input specification we have.
 */
int
get_type(void)
{
	int i;

	if (specsize == 1) {
		if (streq(member, "SIZEOF")) {
			return (SIZEOF);
		}
		if (streq(member, "OFFSETOK")) {
			return (OFFSETOK);
		}
		if (streq(member, "END")) {
			return (END);
		}
		for (i = 0; i < FMT_ENTRIES; i++)
			if (streq(member, adbgen_fmt_tbl[i].f_str))
				return (i);
		return (OFFSET);
	}
	if (specsize == 2) {
		if (member[0] == '*') {
			return (INDIRECT);
		}
		if (streq(member, "EXPR")) {
			return (EXPR);
		}
		return (PRINT);
	}
	fprintf(stderr, "Invalid specification, line %d\n", line_no);
	exit(1);
}

/*
 * Generate the appropriate output for an input specification.
 */
void
generate(void)
{
	char *cp;
	int type;

	type = get_type();

	switch (type) {
	case PTR_HEX:
	case LONG_DEC:
	case LONG_OCT:
	case ULONG_DEC:
	case ULONG_HEX:
	case ULONG_OCT:
		cp = start_printf();
		*cp++ = adbgen_fmt_tbl[type].f_char;
		emit_printf(cp);
		break;
	case PRINT:
		emit_print();
		break;
	case OFFSET:
		emit_offset();
		break;
	case INDIRECT:
		emit_indirect();
		break;
	case OFFSETOK:
		emit_offsetok();
		break;
	case SIZEOF:
		emit_sizeof();
		break;
	case EXPR:
		emit_expr();
		break;
	case END:
		emit_end();
		break;
	default:
		fprintf(stderr, "Internal error in generate\n");
		exit(1);
	}
}

/*
 * Emit calls to set the offset and print a member.
 */
void
emit_print(void)
{
	char *cp;
	char fmt_request[STRLEN];
	int i;
	char number[STRLEN];

	emit_offset();
	/*
	 * Emit call to "format" subroutine
	 */
	sprintf(arg[0], "\"%s\"", member);
	sprintf(arg[1], "sizeof ((struct %s *)0)->%s",
		struct_name, member);

	/*
	 * Split the format string into <number><format character string>
	 * This is for format strings that contain format specifier requests
	 * like {POINTER_HEX}, {LONG_DEC}, etc. which need to be substituted
	 * with a format character instead.
	 */
	for (cp = format, i = 0; *cp >= '0' && *cp <= '9' && *cp != '\0';
	    cp++, i++)
		number[i] = *cp;
	number[i] = '\0';

	for (i = 0; i < FMT_ENTRIES; i++) {
		(void) sprintf(fmt_request, "{%s}", adbgen_fmt_tbl[i].f_str);
		if (streq(cp, fmt_request)) {
			sprintf(arg[2], "\"%s%c\"",
				number, adbgen_fmt_tbl[i].f_char);
			break;
		}
	}
	if (i == FMT_ENTRIES)
		sprintf(arg[2], "\"%s\"", format);

	emit_call("format", 3);
}

/*
 * Emit calls to set the offset and print a member.
 */
void
emit_offset(void)
{
	/*
	 * Emit call to "offset" subroutine
	 */
	sprintf(arg[0], "(off_t) &(((struct %s *)0)->%s)",
		struct_name, member);
	emit_call("offset", 1);
}

/*
 * Emit call to indirect routine.
 */
void
emit_indirect(void)
{
	sprintf(arg[0], "(off_t) &(((struct %s *)0)->%s)",
		struct_name, member+1);
	sprintf(arg[1], "sizeof ((struct %s *)0)->%s", struct_name, member+1);
	sprintf(arg[2], "\"%s\"", format);	/* adb register name */
	sprintf(arg[3], "\"%s\"", member);
	emit_call("indirect", 4);
}

/*
 * Emit call to "offsetok" routine.
 */
void
emit_offsetok(void)
{
	emit_call("offsetok", 0);
}

/*
 * Emit call to printf the sizeof the structure.
 */
void
emit_sizeof(void)
{
	sprintf(arg[0], "\"0t%%d\"");
	sprintf(arg[1], "sizeof (struct %s)", struct_name);
	emit_call("printf", 2);
}

/*
 * Emit call to printf an arbitrary C expression.
 */
void
emit_expr(void)
{
	sprintf(arg[0], "\"0t%%d\"");
	sprintf(arg[1], "(%s)", format);
	emit_call("printf", 2);
}

/*
 * Emit call to set offset to end of struct.
 */
void
emit_end(void)
{
	sprintf(arg[0], "sizeof (struct %s)", struct_name);
	emit_call("offset", 1);
}

/*
 * Emit call to subroutine name with nargs arguments from arg array.
 */
void
emit_call(char *name, int nargs)
{
	int i;

	printf("\t%s(", name);		/* name of subroutine */
	for (i = 0; i < nargs; i++) {
		if (i > 0) {
			printf(", ");	/* argument separator */
		}
		printf("%s", arg[i]);	/* argument */
	}
	printf(");\n");			/* end of call */
}
