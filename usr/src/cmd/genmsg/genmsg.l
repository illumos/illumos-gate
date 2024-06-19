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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <libintl.h>
#include <locale.h>
#include "genmsg.h"
#include "y.tab.h"

extern int is_cat_found;	/* from main.c */
extern void add_comment(Mode, char *);	/* from util.c */

int lineno = 1;

/*
 * msg_line stores the line number where a msgid is to be replaced.
 */
int msg_line = 0;

int end_of_cat = TRUE;

/*
 * In preprocessor mode, genmsg has to parse both the original
 * soruce code and the code which a preprocessor generates.
 * While genmsg is parsing the original source code,  'pound_is_mine'
 * is set to TRUE.
 */
int pound_is_mine = FALSE;

void warning(char *);

#define	NOLINEMSG	-2

void set_linemsgid(int, int);
int get_linemsgid(int);

/*
 * cat_field indicates which token is currently parsed by lex.
 */
#define	CatdField	0
#define	SetidField	1
#define	MsgidField	2
#define	StrField	3

static int cat_field;

/*
 * This will be turned on when '-' is found in the catgets message
 * number field.
 */
static int save_minus = FALSE;

static char *skip_quoted(int skip_ch);
static char *skip_comment(void);
static void parse_cppline(char *);
%}
%s CAT
%%

[0-9a-zA-Z\_\.]catgets	{
			if (IsActiveMode(ReplaceMode)) {
				(void) fprintf(newfp, "%s", yytext);
			}
		}

catgets[0-9a-zA-Z\_\.]	{
			if (IsActiveMode(ReplaceMode)) {
				(void) fprintf(newfp, "%s", yytext);
			}
		}

catgets		{
			if (end_of_cat) {
				/*
				 * If the previous catgets
				 * state is on, turn it off
				 * first.
				 */
				BEGIN 0;
			}
			if (IsActiveMode(ReplaceMode)) {
				(void) fprintf(newfp, "%s", yytext);
			}
			if (!IsActiveMode(ReplaceMode) ||
			    !IsActiveMode(PreProcessMode)) {
				BEGIN CAT;
				end_of_cat = FALSE;
				cat_field = CatdField;
				return (CATGETS);
			}
		}

<CAT>\,		{	/* punctuation */
			cat_field++;
			if (IsActiveMode(ReplaceMode)) {
				(void) fprintf(newfp, "%c", yytext[0]);
			}
			if (end_of_cat) {
				BEGIN 0;
			} else {
				return (yytext[0]);
			}
		}

<CAT>[+*/();>]	{	/* punctuation */
			if (IsActiveMode(ReplaceMode)) {
				(void) fprintf(newfp, "%c", yytext[0]);
			}
			if (end_of_cat) {
				BEGIN 0;
			} else {
				return (yytext[0]);
			}
		}

<CAT>const	{
			if (IsActiveMode(ReplaceMode)) {
				(void) fprintf(newfp, "%s", yytext);
			}
			if (end_of_cat) {
				BEGIN 0;
			} else {
				return (CONST);
			}
		}

<CAT>nl_catd	{
			if (IsActiveMode(ReplaceMode)) {
				(void) fprintf(newfp, "%s", yytext);
			}
			if (end_of_cat) {
				BEGIN 0;
			} else {
				return (CATD);
			}
		}

<CAT>char	{
			if (IsActiveMode(ReplaceMode)) {
				(void) fprintf(newfp, "%s", yytext);
			}
			if (end_of_cat) {
				BEGIN 0;
			} else {
				return (CHAR);
			}
		}

<CAT>int	{
			if (IsActiveMode(ReplaceMode)) {
				(void) fprintf(newfp, "%s", yytext);
			}
			if (end_of_cat) {
				BEGIN 0;
			} else {
				return (INT);
			}
		}

<CAT>\+\+	{
			if (IsActiveMode(ReplaceMode)) {
				(void) fprintf(newfp, "%s", yytext);
			}
			if (end_of_cat) {
				BEGIN 0;
			} else {
				return (INC);
			}
		}

<CAT>\-\-	{
			if (IsActiveMode(ReplaceMode)) {
				(void) fprintf(newfp, "%s", yytext);
			}
			if (end_of_cat) {
				BEGIN 0;
			} else {
				return (INC);
			}
		}

<CAT>\"		{	/* extract quoted string */
			yylval.str = skip_quoted('"');
			if (IsActiveMode(ReplaceMode)) {
				(void) fprintf(newfp, "\"%s\"", yylval.str);
			}
			if (end_of_cat) { /* just in case */
				BEGIN 0;
				free(yylval.str);
			} else {
				return (QSTR);
			}
		}

<CAT>-		{	/* punctuation */
			if (IsActiveMode(ReplaceMode)) {
				if (cat_field == MsgidField &&
					get_linemsgid(lineno) != NOLINEMSG) {
					save_minus = TRUE; /*  be replaced. */
				} else {
					(void) fprintf(newfp, "%c", yytext[0]);
				}
			}
			if (end_of_cat) { /* just in case */
				BEGIN 0;
			} else {
				return (yytext[0]);
			}
		}

<CAT>[0-9]+	{	/* numbers */
			switch (cat_field) {
			case SetidField:
				yylval.id = atoi(yytext);
				if (IsActiveMode(ReplaceMode)) {
					(void) fprintf(newfp, "%s", yytext);
				}
				if (end_of_cat) {
					BEGIN 0;
				} else {
					return (SETID);
				}
				break;
			case MsgidField:
				yylval.id = atoi(yytext);
				if (IsActiveMode(ReplaceMode)) {
					int id = get_linemsgid(lineno);
					if (id == NOLINEMSG) {
						(void) fprintf(newfp, "%s",
						    yytext);
					} else if (id == NOMSGID &&
						IsActiveMode(ReverseMode)) {
						(void) fprintf(newfp, "%d",
						    NOMSGID);
					} else if (save_minus == TRUE &&
						yylval.id == 1) {
						(void) fprintf(newfp, "%d", id);
					} else { /* just in case */
						(void) fprintf(newfp, "%s",
						    yytext);
					}
					save_minus = FALSE;
				} else {
					msg_line = lineno;
				}
				if (end_of_cat) {
					BEGIN 0;
				} else {
					return (MSGID);
				}
				break;
			default:
				yylval.id = atoi(yytext);
				if (IsActiveMode(ReplaceMode)) {
					(void) fprintf(newfp, "%s", yytext);
				}
				if (end_of_cat) {
					BEGIN 0;
				} else {
					return (DIGIT);
				}
			}
		}

<CAT>[a-zA-Z0-9_\&][a-zA-Z0-9_\>\&\.]*	{
			if (IsActiveMode(ReplaceMode)) {
				(void) fprintf(newfp, "%s", yytext);
			}
			if (end_of_cat) {
				BEGIN 0;
			} else {
				return (STR);
			}
		}

<CAT>\n		{
			lineno++;
			if (IsActiveMode(ReplaceMode)) {
				(void) fprintf(newfp, "\n");
			}
			if (end_of_cat) {
				BEGIN 0;
			}
		}

<CAT>.		{	/* not interested */
			if (IsActiveMode(ReplaceMode)) {
				(void) fprintf(newfp, "%c", yytext[0]);
			}
			if (end_of_cat) {
				BEGIN 0;
			}
		}

-((([ \t]+)1)|1) {	/* -1 */
			if (end_of_cat == FALSE) {
				REJECT
			} else if (IsActiveMode(ReplaceMode)) {
				if (IsActiveMode(PreProcessMode)) {
					int id = get_linemsgid(lineno);
					if (id == NOLINEMSG) {
						(void) fprintf(newfp, "%s",
						    yytext);
					} else { /* could be -1. */
						(void) fprintf(newfp, "%d", id);
					}
				} else {
					(void) fprintf(newfp, "%s", yytext);
				}
			}
		}

[0-9]+		{
			if (IsActiveMode(ReplaceMode)) {
				if (IsActiveMode(PreProcessMode) &&
					IsActiveMode(ReverseMode)) {
					int id = get_linemsgid(lineno);
					if (id == NOLINEMSG) {
						(void) fprintf(newfp, "%s",
						    yytext);
					} else if (id == NOMSGID) {
						(void) fprintf(newfp, "%d", id);
					}
				} else {
					(void) fprintf(newfp, "%s", yytext);
				}
			}
		}

^#[ \t]*[0-9]+.*\n	{	/* pound for c-preprocessor */
			if (IsActiveMode(PreProcessMode)) {
				if (IsActiveMode(ReplaceMode)) {
					(void) fprintf(newfp, "%s", yytext);
				} else {
					parse_cppline(yytext);
				}
			} else if (IsActiveMode(ReplaceMode)) {
				(void) fprintf(newfp, "%s", yytext);
			}
			lineno++;
		}

"/*"		{	/* skip a comment block */
			char *comment = skip_comment();
			if (IsActiveMode(ReplaceMode)) {
				(void) fprintf(newfp, "%s", comment);
			} else {
				if (IsActiveMode(MsgCommentMode)) {
					add_comment(MsgCommentMode, comment);
				}
				if (IsActiveMode(SetCommentMode)) {
					add_comment(SetCommentMode, comment);
				}
			}
			free(comment);
		}

"//".*\n	{	/* skip a c++ comment */
			if (IsActiveMode(ReplaceMode)) {
				(void) fprintf(newfp, "%s", yytext);
			} else {
				if (IsActiveMode(MsgCommentMode)) {
					add_comment(MsgCommentMode, yytext);
				}
				if (IsActiveMode(SetCommentMode)) {
					add_comment(SetCommentMode, yytext);
				}
			}
			lineno++;
		}

\"		{	/* skip quoted string */
			char *qstr = skip_quoted('"');
			if (IsActiveMode(ReplaceMode)) {
				(void) fprintf(newfp, "\"%s\"", qstr);
			}
			free(qstr);
		}

\'		{	/* skip single-quoted character */
			char *qchr = skip_quoted('\'');
			if (IsActiveMode(ReplaceMode)) {
				(void) fprintf(newfp, "\'%s\'", qchr);
			}
			free(qchr);
		}

\n		{
			if (IsActiveMode(ReplaceMode)) {
				(void) fprintf(newfp, "\n");
			}
			lineno++;
		}

.		{
			if (IsActiveMode(ReplaceMode)) {
				(void) fprintf(newfp, "%c", yytext[0]);
			}
		}

%%

static char *
skip_quoted(int skip_ch)
{
	char *buf, *ptr;	/* saved buffer and its pointer */
	int bsize = BUFSIZ;	/* growing buffer size */
	int i = 0;		/* counter */
	int c, old = 0;		/* input character */

	if ((buf = ptr = malloc(bsize)) == NULL) {
		prg_err(gettext("fatal: out of memory"));
		exit(EXIT_FAILURE);
	}
	for (; ; i++) {
		if (i == bsize) {
			bsize += BUFSIZ;
			if ((buf = realloc(buf, bsize)) == NULL) {
				prg_err(gettext("fatal: out of memory"));
				exit(EXIT_FAILURE);
			}
			ptr = buf + i;
		}
		c = input();
		if (c == skip_ch && old != '\\') {
			break;
		} else if (c == '\n') {
			lineno++;
		} else if (c == 0) {
			if (skip_ch == '"') {
				warning(gettext("warning: unmatched \""));
			} else if (skip_ch == '\'') {
				warning(gettext("warning: unmatched '"));
			} else {
				/* Should not happen */
				warning(gettext(
				    "warning: unmatched character"));
			}
			break;
		}
		*ptr++ = c;
		if (old == '\\') {
			old = '\0';
		} else {
			old = c;
		}
	}
	*ptr = '\0';
	return (buf);
}

static char *
skip_comment(void)
{
	char *buf, *ptr;	/* saved buffer and its pointer */
	int bsize = BUFSIZ;	/* growing buffer size */
	int i = 0;		/* counter */
	int c, old = 0;		/* input character */

	if ((buf = ptr = malloc(bsize)) == NULL) {
		prg_err(gettext("fatal: out of memory"));
		exit(EXIT_FAILURE);
	}
	*ptr++ = '/';	i++;
	*ptr++ = '*';	i++;
	for (; ; i++) {
		if (i == bsize) {
			bsize += BUFSIZ;
			if ((buf = realloc(buf, bsize)) == NULL) {
				prg_err(gettext("fatal: out of memory"));
				exit(EXIT_FAILURE);
			}
			ptr = buf + i;
		}
		c = input();
		if (c == '/' && old == '*') {
			*ptr++ = c;
			break;
		} else if (c == '\n') {
			lineno++;
		} else if (c == 0) {
			warning(gettext("warning: unmatched /*"));
			break;
		}
		*ptr++ = old = c;
	}
	*ptr = '\0';
	return (buf);
}

/*
 * parse_cppline() parses the line control information that a C
 * preprocessor generates to indicate the location in the original
 * file.  See the cpp man in the details.
 */
static void
parse_cppline(char *str)
{
	int n, line, len;
	char ch;
	char file[BUFSIZ];
	char *altfile = NULL;
	char *pfile;

	len = strlen(str);
	if (len >= sizeof (file)) {
		if ((altfile = malloc(len + 1)) == NULL) {
			prg_err(gettext("fatal: out of memory"));
			exit(EXIT_FAILURE);
		}
		pfile = altfile;
	} else {
		pfile = file;
	}
	/* LINTED: E_SEC_SCANF_UNBOUNDED_COPY */
	n = sscanf(str, "%c%d%s", &ch, &line, pfile);

	/* 'file' is a quoted string but 'srcfile' is not. */
	len = strlen(pfile) - 2;

	pfile++;
	if (n == 3 && (strncmp(pfile, srcfile, len) == 0)) {
		pound_is_mine = TRUE;
		lineno = line - 1;
	} else if (n == 2 && (pound_is_mine == TRUE)) {
		lineno = line - 1;
	} else {
		pound_is_mine = FALSE;
	}
	if (altfile)
		free(altfile);
}

typedef struct {
	int line;
	int msgid;
} LineMsgID;

static LineMsgID line_msgid[NL_MSGMAX];
static int line_msgcnt;

void
init_lex(void)
{
	lineno = 1;
	end_of_cat = TRUE;
	pound_is_mine = FALSE;
}

void
init_linemsgid(void)
{
	line_msgcnt = 0;
	(void) memset(line_msgid, 0, sizeof (LineMsgID) * NL_MSGMAX);
}

void
set_linemsgid(int line, int msgid)
{
	if (line_msgcnt >= NL_MSGMAX) {
		return; /* oops */
	}
	line_msgid[line_msgcnt].line = line;
	line_msgid[line_msgcnt].msgid = msgid;
	line_msgcnt++;
}

int
get_linemsgid(int line)
{
	int i, left, right;
	left = 0;
	right = line_msgcnt - 1;
	while (left <= right) {
		i = (left + right) >> 1;
		if (line < line_msgid[i].line) {
			right = i - 1;
		} else if (line > line_msgid[i].line) {
			left = i + 1;
		} else {
			return (line_msgid[i].msgid);
		}
	}
	return (NOLINEMSG);
}

int
yyerror(const char *s)
{
	if ((IsActiveMode(PreProcessMode) && pound_is_mine == FALSE) ||
	    IsActiveMode(ReplaceMode)) {
		return (0);
	}
	src_err(srcfile, lineno, gettext("%s before or at: %s"), s, yytext);
	return (0);
}

void
warning(char *s)
{
	if ((IsActiveMode(PreProcessMode) && pound_is_mine == FALSE) ||
	    IsActiveMode(ReplaceMode)) {
		return;
	}
	src_err(srcfile, lineno, "%s", s);
}
