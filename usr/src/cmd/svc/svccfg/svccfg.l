%{
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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <libintl.h>
#include <string.h>

#include "svccfg.h"
#include "svccfg_grammar.h"

/*
 * We need to undefine lex's input, unput, and output macros so that references
 * to these call the functions we provide at the end of this source file,
 * instead of the default versions based on libc's stdio.
 */
#ifdef input
#undef input
#endif

#ifdef unput
#undef unput
#endif

#ifdef output
#undef output
#endif

static int input(void);
static void unput(int);
static void output(int);

int parens = 0;

extern int yyerror(const char *);

%}

/*
 * Since command tokens are only valid at the beginning of the command (or
 * after help), we'll only return them in the INITIAL state, and report them
 * as SCV_WORDs afterwards.
 */
%Start	WORD

/*
 * The default value of lex for transitions is 2000 and it seems we reached it.
 * So we are bumping it up!
 */
%a 3000

%%

#.*$			;	/* comments */

<INITIAL>validate	{ BEGIN WORD; return (SCC_VALIDATE); }
<INITIAL>import		{ BEGIN WORD; return (SCC_IMPORT); }
<INITIAL>cleanup	{ BEGIN WORD; return (SCC_CLEANUP); }
<INITIAL>export		{ BEGIN WORD; return (SCC_EXPORT); }
<INITIAL>archive	{ BEGIN WORD; return (SCC_ARCHIVE); }
<INITIAL>restore	{ BEGIN WORD; return (SCC_RESTORE); }
<INITIAL>apply		{ BEGIN WORD; return (SCC_APPLY); }
<INITIAL>extract	{ BEGIN WORD; return (SCC_EXTRACT); }
<INITIAL>repository	{ BEGIN WORD; return (SCC_REPOSITORY); }
<INITIAL>inventory	{ BEGIN WORD; return (SCC_INVENTORY); }
<INITIAL>set		{ BEGIN WORD; return (SCC_SET); }
<INITIAL>end		{ BEGIN WORD; return (SCC_END); }
<INITIAL>exit		{ BEGIN WORD; return (SCC_END); }
<INITIAL>quit		{ BEGIN WORD; return (SCC_END); }
<INITIAL>help		{ return (SCC_HELP); }

<INITIAL>list		{ BEGIN WORD; return (SCC_LIST); }
<INITIAL>add		{ BEGIN WORD; return (SCC_ADD); }
<INITIAL>delete		{ BEGIN WORD; return (SCC_DELETE); }
<INITIAL>select		{ BEGIN WORD; return (SCC_SELECT); }
<INITIAL>unselect	{ BEGIN WORD; return (SCC_UNSELECT); }

<INITIAL>listpg		{ BEGIN WORD; return (SCC_LISTPG); }
<INITIAL>addpg		{ BEGIN WORD; return (SCC_ADDPG); }
<INITIAL>delpg		{ BEGIN WORD; return (SCC_DELPG); }
<INITIAL>delhash	{ BEGIN WORD; return (SCC_DELHASH); }
<INITIAL>listprop	{ BEGIN WORD; return (SCC_LISTPROP); }
<INITIAL>setprop	{ BEGIN WORD; return (SCC_SETPROP); }
<INITIAL>delprop	{ BEGIN WORD; return (SCC_DELPROP); }
<INITIAL>editprop	{ BEGIN WORD; return (SCC_EDITPROP); }
<INITIAL>describe	{ BEGIN WORD; return (SCC_DESCRIBE); }
<INITIAL>addpropvalue	{ BEGIN WORD; return (SCC_ADDPROPVALUE); }
<INITIAL>delpropvalue	{ BEGIN WORD; return (SCC_DELPROPVALUE); }
<INITIAL>setenv		{ BEGIN WORD; return (SCC_SETENV); }
<INITIAL>unsetenv	{ BEGIN WORD; return (SCC_UNSETENV); }

<INITIAL>listsnap	{ BEGIN WORD; return (SCC_LISTSNAP); }
<INITIAL>selectsnap	{ BEGIN WORD; return (SCC_SELECTSNAP); }
<INITIAL>revert		{ BEGIN WORD; return (SCC_REVERT); }
<INITIAL>refresh	{ BEGIN WORD; return (SCC_REFRESH); }

<INITIAL>delnotify	{ BEGIN WORD; return (SCC_DELNOTIFY); }
<INITIAL>listnotify	{ BEGIN WORD; return (SCC_LISTNOTIFY); }
<INITIAL>setnotify	{ BEGIN WORD; return (SCC_SETNOTIFY); }

[^ \t\n">=()]+		{
				if ((yylval.str = strdup(yytext)) == NULL) {
					yyerror(gettext("Out of memory"));
					exit(UU_EXIT_FATAL);
				}

				return SCV_WORD;
			}

\"([^"\\]|\\.)*\"	{
				/*
				 * double-quoted strings start at a
				 * double-quote, include characters other than
				 * double-quote and backslash, and
				 * backslashed-characters, and end with a
				 * double-quote.
				 */

				char *str, *cp;
				int shift;

				if ((str = strdup(yytext)) == NULL) {
					yyerror(gettext("Out of memory"));
					exit(UU_EXIT_FATAL);
				}

				/* Strip out the backslashes. */
				for (cp = str, shift = 0; *cp != '\0'; ++cp) {
					if (*cp == '\\') {
						++cp;

						/*
						 * This can't be null because
						 * the string always ends with
						 * a double-quote.
						 */

						++shift;
						*(cp - shift) = *cp;
					} else if (shift != 0)
						*(cp - shift) = *cp;
				}

				/* Nullify everything after trailing quote */
				*(cp - shift) = '\0';

				yylval.str = str;
				return SCV_STRING;
			}

\n			{
				est->sc_cmd_lineno++;
				BEGIN INITIAL;
				return (SCS_NEWLINE);
			}

[ \t]+			;

">"			{ return SCS_REDIRECT; }
"="			{ return SCS_EQUALS; }
"("			{ ++parens; return SCS_LPAREN; }
")"			{ --parens; return SCS_RPAREN; }

.			{
				uu_die(gettext("unrecognized character %s\n"),
				    yytext);
			}

%%

int
yyerror(const char *s)
{
	return (0);
}

static int
input(void)
{
	static int saw_eof = 0;

	int c = engine_cmd_getc(est);

	/*
	 * To ensure input is terminated, slip in a newline on EOF.
	 */
	if (c == EOF) {
		if (saw_eof)
			return (0);

		saw_eof = 1;
		return ('\n');
	} else
		saw_eof = 0;

	if (c == '\n')
		yylineno++;

	return (c);
}

static void
unput(int c)
{
	if (c == '\n')
		yylineno--;

	(void) engine_cmd_ungetc(est, c == 0 ? EOF : c);
}

static void
output(int c)
{
	char ch = c;
	engine_cmd_nputs(est, &ch, sizeof (ch));
}
