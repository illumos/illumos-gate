%{
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
 *
 * Copyright (c) 1991, 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>

#define	TRUE	1
#define	FALSE	0

extern int	stdin_only;
extern char	curr_file[];	/* Name of file currently being read. */
extern int	curr_linenum;	/* line number in the current input file */
extern int	warn_linenum;	/* line number of current warning message */
extern int	optind;
extern int	gargc;
extern char	**gargv;

extern void	handle_macro_line(void);
extern void	handle_cplus_comment_line(void);
extern void	handle_open_comment(void);
extern void	handle_close_comment(void);
extern void	handle_gettext(void);
extern void	handle_dgettext(void);
extern void	handle_dcgettext(void);
extern void	handle_textdomain(void);
extern void	handle_character(void);
extern void	handle_open_paren(void);
extern void	handle_close_paren(void);
extern void	handle_esc_newline(void);
extern void	handle_comma(void);
extern void	handle_newline(void);
extern void	handle_quote(void);
extern void	handle_spaces(void);
extern void	handle_spaces(void);
extern void	handle_character(void);

/*
 * The following lex rule basically wants to recognize tokens
 * that can change the current state of scanning source code.
 * Evertime such tokens are recognized, the specific handler will be
 * executed. All other tokens are treated as regular characters and
 * they are all handled the same way.
 * The tricky part was not to miss any specification in ANSI-C code
 * that looks like a meaningful token but not a meaningful one and
 * should be treated as regular characters.
 * For example,
 *	c= '"';d='"'; printf("\"" "\(\)\\\"");
 *	c = ABgettext("Not a gettext");
 *	c = gettextXY("Not a gettext");
 *	c = ABgettextXY("Not a gettext");
 */
%}

IDCHARS		[a-zA-Z0-9_]

%%
^#(.*\\\n)**.*\n	{ handle_macro_line(); }

\/\/		{ handle_cplus_comment_line(); }

\/\* 		{ handle_open_comment(); }

\*\/ 		{ handle_close_comment(); }

dcgettext	{ handle_dcgettext(); }

dgettext	{ handle_dgettext(); }

gettext		{ handle_gettext(); }

textdomain	{ handle_textdomain(); }

{IDCHARS}+	|
\'\"\'		|
\'\\\"\'	|
\\\\		|
\\\"		|
\\\(		|
\\\)		{ handle_character(); }

\(		{ handle_open_paren(); }

\)		{ handle_close_paren(); }

\\\n		{ handle_esc_newline(); }

\,		{ handle_comma(); }

\n		{ handle_newline(); }

\"		{ handle_quote(); }

" "		{ handle_spaces(); }

"\t"		{ handle_spaces(); }

.		{ handle_character(); }

%%

/*
 * Since multiple files can be processed, yywrap() should keep feeding
 * all input files specified.
 */
int
yywrap(void)
{
	FILE	*fp;

	if ((optind >= gargc) || (stdin_only == TRUE)) {
		return (1);
	} else {
		/*
		 * gargv still contains not-processed input files.
		 */
		(void) freopen(gargv[optind], "r", stdin);
		if ((fp = freopen(gargv[optind], "r", stdin)) == NULL) {
			(void) fprintf(stderr, "ERROR, can't open input file: %s\n",
					gargv[optind]);
		}
#ifdef DEBUG
		(void) printf("In yywrap(), opening file  %d, <%s>\n",
				optind, gargv[optind]);
#endif
		/*
		 * Reset global file name and line number for the new file.
		 */
		(void) strcpy(curr_file, gargv[optind]);
		curr_linenum = 0;
		warn_linenum = 0;

		optind++;

		return (0);
	}

} /* yywrap */
