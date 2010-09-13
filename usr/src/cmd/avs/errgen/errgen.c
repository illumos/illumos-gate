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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *	Read an errgen status resource file (*.err) from standard input and
 *	write an SPCS error code C header file (-c), Java resource file (-j),
 *	libspcs Java exception class file(-e), error text file (-m) or JNI
 *      exception trinket table to standard output. Lines starting with "#"
 *      are ignored.
 *
 *	Use "errgen -h" to get usage info including module codes and example
 *      input and output.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <libgen.h>
#include <limits.h>
#include <sys/param.h>

/* The public error info header file.  */

#include <sys/unistat/spcs_s.h>

/* The private error info header file */

#include <sys/unistat/spcs_s_impl.h>


/*  locals  */

static enum {C_MODE, J_MODE, M_MODE, E_MODE, T_MODE, X_MODE} mode = E_MODE;
static	char key[SPCS_S_MAXKEY];
static	char text[SPCS_S_MAXTEXT];
static int mod_number;

static char help_path[PATH_MAX];

static int count = 1;

static char key[SPCS_S_MAXKEY];
static char text[SPCS_S_MAXTEXT];
static char modname[SPCS_S_MAXMODNAME];

/*
 *	Display help info
 */

static void
help()
{
	char line[SPCS_S_MAXLINE];
	FILE *h = fopen(help_path, "r");

	if (h) {
		while (! feof(h)) {
			(void) fgets(line, SPCS_S_MAXLINE, h);
			if (! feof(h))
				(void) fputs(line, stderr);
		}
	} else {
		perror(strcat("could not open: ", help_path));
		exit(1);
	}
}

/*
 *	Put out a message with terse instructions and err out
 */

static void
fatal(char *msg)
{
	(void) fprintf(stderr, "%s\n\n", msg);
	(void) fprintf(stderr, "use errgen -h for help\n");
	exit(1);
}

/*
 *	Put out the output file preamble
 */

static void
do_preamble()
{
	switch (mode) {
	case M_MODE:
		(void) fprintf(stdout,
			"static\nchar *SPCS_MSG_%s[] = {\n", modname);
		(void) fprintf(stdout, "\t\"\",\n");
		break;
	case T_MODE:
		(void) fprintf(stdout,
			"static\nchar *SPCS_TRNK_%s[] = {\n", modname);
		(void) fprintf(stdout, "\t\"\",\n");
		break;
	}
}

/*
 *	Put out the output file trailer
 */

static void
do_trailer()
{
	switch (mode) {
	case M_MODE:
		(void) fprintf(stdout, "};\n");
		(void) fprintf(stdout,
			"#define\tSPCS_MSGLEN_%s %d\t/* total codes */\n",
			modname, count-1);
		break;
	case T_MODE:
		(void) fprintf(stdout, "};\n");
		(void) fprintf(stdout,
			"#define\tSPCS_TRNKLEN_%s %d\t/* total codes */\n",
			modname, count-1);
		break;
	}
}

/*
 *	Process a single input line
 */

static void
do_line()
{
	spcs_s_udata_t c;
	int fc = 0;
	int len = 0;
	char ptext[SPCS_S_MAXTEXT];
	char keystring[SPCS_S_MAXKEY+SPCS_S_MAXPRE];
	char *p = text;
	int tlen;
	char *pt = ptext;
	char havebytestream = 0;

	c.i = 0;
	(void) sprintf(keystring, "%s_E%s", modname, key);
	while (*p) {
		if (*p == '%') {
			if (*(p + 1) != 's') {
				(void) fprintf(stderr,
				    "ERRGEN: Error in .err file\n");
				(void) fprintf(stderr,
				    "%c is an illegal format spec after %%",
				    *p);
				(void) fprintf(stderr,
				    " at line: %d pos: %d\n", count,
					/* LINTED possible ptrdiff_t overflow */
				    (int)(p - text));
				fatal("");
			}
			len = sprintf(pt, "{%d}", fc);
			pt += len;
			p++;
			fc += 1;
			if (fc > SPCS_S_MAXSUPP) {
				(void) fprintf(stderr,
					"ERRGEN: Error in .err file\n");
				(void) fprintf(stderr,
				    "SPCS_S_MAXSUPP exceeeded\n");
				fatal("Too many %%s specifiers");
			}
		} else
			*pt++ = *p;
		p++;
	}

	/* look for a bytestream indicator */

	tlen = strlen(text);

	if ((tlen > 2) && (text[tlen - 1] == '@') && (text[tlen - 2] == '@')) {
		if (fc)
			fatal("ERRGEN: cannot have %%s and @@ ending too");

		/* bump the item count and set the bytestream flag */
		fc += 1;
		havebytestream = 1;
	}

	*pt = 0;

	switch (mode) {
	case C_MODE:
		c.f.bytestream = havebytestream;
		c.f.sup_count = fc;
		c.f.module = mod_number;
		c.f.code = count;
		(void) fprintf(stdout, "#define\t%s 0x%x /* %s */\n",
			keystring, c.i, text);
		break;
	case J_MODE:
		(void) fprintf(stdout, "`%s` = %s\n", keystring, ptext);
		break;
	case X_MODE:
		(void) fprintf(stdout,
		    "#define\tT_%s \"`%s`\"\n", keystring, keystring);
		break;
	case T_MODE:
		(void) fprintf(stdout, "\t\"`%s`\",\n", keystring);
		break;
	case M_MODE:
		(void) fprintf(stdout, "\t\"%s\",\n", text);
		break;
	case E_MODE:
		(void) fprintf(stdout, "    /**\n     * %s\n    **/\n",
			text);
		(void) fprintf(stdout, "    public static final String %s",
			    keystring);
		(void) fprintf(stdout, " = `%s`;\n\n", keystring);
		break;
	}
}

int
main(int argc, char **argv)
{
	int i;
	int searching = 1;
	char searchname[SPCS_S_MAXMODNAME];
	char line[SPCS_S_MAXLINE];
	char tline[SPCS_S_MAXLINE];
	char *p, *p2;

	(void) strcpy(help_path, dirname(argv[0]));
	(void) strcat(help_path, "/errgen.help");
	if ((argc == 1) || ((argc == 2) && (strcmp(argv[1], "-h") == 0))) {
		help();
		exit(0);
	}

	if (argc != 3)
		fatal("Bad number of arguments");

	p = argv[2];
	p2 = modname;

	while (*p)
		*p2++ = toupper(*p++);
	*p2 = 0;

	switch (argv[1][1]) {
	case 'c':
		mode = C_MODE;
		break;
	case 'j':
		mode = J_MODE;
		break;
	case 'e':
		mode = E_MODE;
		break;
	case 'm':
		mode = M_MODE;
		break;
	case 't':
		mode = T_MODE;
		break;
	case 'x':
		mode = X_MODE;
		break;
	default:
		fatal("Unknown option switch");
	}

	if (strcmp(modname, "DSW") == 0) {
		(void) strcpy(searchname, "II");
	} else if (strcmp(modname, "RDC") == 0) {
		(void) strcpy(searchname, "SNDR");
	} else if (strcmp(modname, "SDCTL") == 0) {
		(void) strcpy(searchname, "NSCTL");
	} else {
		(void) strcpy(searchname, modname);
	}

	i = 0;
	do {
		if (strcmp(module_names[i++], searchname) == 0) {
			searching = 0;
			mod_number = i - 1;
			break;
		}
	} while (module_names[i]);

	if (searching) {
		if (i != SPCS_M_MAX)
			(void) fprintf(stderr,
			"NULL in module_names before SPCS_M_MAX\n");
		fatal("Undefined module name");
	}

	do_preamble();

	while (!feof(stdin)) {
		(void) fgets(line, SPCS_S_MAXLINE, stdin);
		if (feof(stdin)) {
			if (count == 0)
				fatal("errgen file empty");

			do_trailer();
			exit(0);
		}
		line[strlen(line)-1] = 0;
		if ((strlen(line) != 0) && (line[0] != '#')) {
		    (void) strcpy(tline, line);
		    p = strchr(tline, ' ');
		    if (p == NULL) {
			(void) fprintf(stderr,
				    "blank separator missing at line: %d\n",
					    count);
			    fatal("");
		    }
		    *p = 0;
		    if (strlen(p) > SPCS_S_MAXKEY) {
			    (void) fprintf(stderr,
			    "message label too long at line: %d\n", count);
			    fatal("");
		    }
		    (void) strcpy(key, tline);
		    if (strlen(key) == 0) {
			    (void) fprintf(stderr,
				    "leading blank at line: %d\n", count);
			    fatal("");
		    }
		    p++;
		    if (*p != '=') {
			    (void) fprintf(stderr,
				    "= separator missing at line: %d\n", count);
			    fatal("");
		    }
		    p++;
		    if (*p != ' ') {
			    (void) fprintf(stderr,
				"blank separator missing at line: %d\n", count);
			    fatal("");
		    }
		    p++;
		    if (! *p) {
			    (void) fprintf(stderr,
				    "msg text missing at line:%d\n", count);
			    fatal("");
		    }
		    (void) strcpy(text, p);

		    do_line();
		    count++;
		}
	}

	return (0);
}
