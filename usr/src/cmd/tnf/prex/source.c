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
 * Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Includes
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <libintl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>

#include "new.h"
#include "queue.h"
#include "source.h"


/*
 * Typedefs
 */

typedef struct source {
	queue_node_t	qn;
	char		   *path;
	FILE		   *instream;
	int			 linenum;
	boolean_t	   isatty;

}			   source_t;


/*
 * Defines
 */

#define	HOME		"HOME"
#define	PREXRC		".prexrc"


/*
 * Globals
 */

static queue_node_t stack;
static source_t *top;


/*
 * source_init() - initializes the source stack
 */

void
source_init(void)
{
	source_t	   *new_p;
	struct stat	 statbuf;
	char		   *home;
	int			 retval;


	/* initialize the stack queue head */
	queue_init(&stack);

	/* stick the standard input on the bottom of the stack */
	new_p = new(source_t);
	queue_init(&new_p->qn);
	new_p->path = strdup("<STDIN>");
	new_p->instream = stdin;
	new_p->linenum = 1;
	new_p->isatty = isatty(fileno(new_p->instream));

	(void) queue_prepend(&stack, &new_p->qn);
	top = new_p;

	/*
	 * since we are pushing onto a stack, we invert the search order *
	 * and push the prexrc in the current directory on next.
	 */
	retval = stat(PREXRC, &statbuf);
	if (retval != -1) {
		source_file(PREXRC);
	}
	home = getenv(HOME);
	if (home) {
		char			path[MAXPATHLEN];

		if ((strlen(home) + strlen(PREXRC) + 2) < (size_t) MAXPATHLEN) {
			(void) sprintf(path, "%s/%s", home, PREXRC);
			retval = stat(path, &statbuf);
			if (retval != -1) {
				source_file(path);
			}
		}
	}
}				/* end source_init */


/*
 * source_file() - pushes a new source onto the stack
 */

void
source_file(char *path)
{
	FILE		   *newfile;
	source_t	   *new_p;

	newfile = fopen(path, "r");
	if (!newfile) {
		semantic_err(gettext("cannot open \"%s\""), path);
		return;
	}
	new_p = new(source_t);
	queue_init(&new_p->qn);
	new_p->path = strdup(path);
	new_p->instream = newfile;
	new_p->linenum = 1;
	new_p->isatty = isatty(fileno(new_p->instream));

	(void) queue_prepend(&stack, &new_p->qn);
	top = new_p;

}				/* end source_file */


/*
 * source_input() - lexical analyzer input routine
 */

extern void	 quit(boolean_t, boolean_t);

int
source_input(void)
{
	int			 c;

	if (!top)
		return (0);

	c = getc(top->instream);

	if (c == EOF) {
		/*
		 * If we get an EOF at the top level, we quit if we are *
		 * non-interactive, pretend we saw a new-line if we are *
		 * interactive.
		 */
		if (top->instream == stdin) {
			if (top->isatty) {
				source_output('\n');
				return ('\n');
			} else
				quit(B_TRUE, B_TRUE);
		}
		/* we've exhausted the current stream, pop it, delete it ... */
		if (top->path)
			free(top->path);
		(void) fclose(top->instream);
		(void) queue_remove(&top->qn);
		free(top);

		/* point to the new top level i/o stream */
		top = (source_t *) queue_next(&stack, &stack);

		if (!top)
			return (0);

		/* trigger a prompt if neccessary */
		prompt();
		return (source_input());
	}
	return (c);

}				/* end source_input */


/*
 * source_unput() - lexical analyzer unput routine
 */

void
source_unput(int c)
{
	if (top)
		(void) ungetc(c, top->instream);

}				/* end source_unput */


/*
 * source_output() - lexical analyzer output routine
 */

void
source_output(int c)
{
	(void) putc(c, stdout);

}				/* end source_output */


/*
 * source_nl() - increment the line counter
 */

void
source_nl(void)
{
	if (top)
		top->linenum++;

}				/* end source_nl */


/*
 * yyerror() -
 */

extern char	 yytext[];
extern int	  g_linenum;

void
yyerror(char *s)
{
	(void) fprintf(stderr,
		gettext("\"%s\", line %d: %s on or before \"%s\"\n"),
		top->path, top->linenum, s, yytext);

}


/*
 * yywrap() -
 */

int
yywrap()
{
	return (1);

}				/* end yywrap */


/*
 * prompt() -
 */

extern char   **g_argv;

void
prompt(void)
{
	if (top && top->isatty)
		(void) printf("%s> ", g_argv[0]);

}				/* end g_prompt */


/*
 * semantic_err() - reports a semantic error
 */

void
semantic_err(char *format, ...)
{
	va_list		 ap;

	va_start(ap, format);

	if (!top)
		return;

	(void) fprintf(stderr, gettext("\"%s\", line %d: semantic error: "),
		top->path, top->linenum);
	(void) vfprintf(stderr, format, ap);
	(void) fprintf(stderr, gettext("\n"));

}				/* end semantic_err */
