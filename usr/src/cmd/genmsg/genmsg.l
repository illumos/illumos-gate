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
 * Copyright (c) 1995 by Sun Microsystems, Inc.
 */
 
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <libintl.h>
#include <locale.h>
#include "genmsg.h"
#include "y.tab.h"

extern int is_cat_found;	/* from main.c */
extern void add_comment(Mode, char *);/* from util.c */

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

#define NOLINEMSG	-2

void set_linemsgid(int, int);
int get_linemsgid(int);

/*
 * cat_field indicates which token is currently parsed by lex.
 */
#define	CatdField	0
#define	SetidField	1
#define	MsgidField	2
#define StrField	3

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
				fprintf(newfp, "%s", yytext);
			}
		}

catgets[0-9a-zA-Z\_\.]	{
			if (IsActiveMode(ReplaceMode)) {
				fprintf(newfp, "%s", yytext);
			}
		}

catgets		{
			if (end_of_cat) { /* If the previous catgets
					   * state is on, turn it off
					   * first. 
					   */ 
				BEGIN 0;
			}
			if (IsActiveMode(ReplaceMode)) {
				fprintf(newfp, "%s", yytext);
			}
			if (IsActiveMode(ReplaceMode) && 
				IsActiveMode(PreProcessMode)) {
				; /* Okay, do nothing in this mode. */
			} else {
				BEGIN CAT;
				end_of_cat = FALSE;
				cat_field = CatdField;
				return CATGETS;
			}
		}

<CAT>\,		{	/* punctuation */
			cat_field++;
			if (IsActiveMode(ReplaceMode)) {
				fprintf(newfp, "%c", yytext[0]);
			} 
			if (end_of_cat) {
				BEGIN 0;
			} else {
				return yytext[0];
			}
		}

<CAT>[+*/();>]	{	/* punctuation */
			if (IsActiveMode(ReplaceMode)) {
				fprintf(newfp, "%c", yytext[0]);
			} 
			if (end_of_cat) {
				BEGIN 0;
			} else {
				return yytext[0];
			}
		}

<CAT>const	{
			if (IsActiveMode(ReplaceMode)) {
				fprintf(newfp, "%s", yytext);
			} 
			if (end_of_cat) {
				BEGIN 0;
			} else {
				return CONST;
			}
		}

<CAT>nl_catd	{
			if (IsActiveMode(ReplaceMode)) {
				fprintf(newfp, "%s", yytext);
			} 
			if (end_of_cat) {
				BEGIN 0;
			} else {
				return CATD;
			}
		}

<CAT>char	{
			if (IsActiveMode(ReplaceMode)) {
				fprintf(newfp, "%s", yytext);
			} 
			if (end_of_cat) {
				BEGIN 0;
			} else {
				return CHAR;
			}
		}

<CAT>int	{
			if (IsActiveMode(ReplaceMode)) {
				fprintf(newfp, "%s", yytext);
			} 
			if (end_of_cat) {
				BEGIN 0;
			} else {
				return INT;
			}
		}

<CAT>\+\+	{
			if (IsActiveMode(ReplaceMode)) {
				fprintf(newfp, "%s", yytext);
			} 
			if (end_of_cat) {
				BEGIN 0;
			} else {
				return INC;
			}
		}

<CAT>\-\-	{
			if (IsActiveMode(ReplaceMode)) {
				fprintf(newfp, "%s", yytext);
			} 
			if (end_of_cat) {
				BEGIN 0;
			} else {
				return INC;
			}
		}

<CAT>\"		{	/* extract quoted string */
			yylval.str = skip_quoted('"');
			if (IsActiveMode(ReplaceMode)) {
				fprintf(newfp, "\"%s\"", yylval.str);
			} 
			if (end_of_cat) { /* just in case */
				BEGIN 0;
				free(yylval.str);
			} else {
				return QSTR;
			}
		}

<CAT>-		{	/* punctuation */
			if (IsActiveMode(ReplaceMode)) {
				if (cat_field == MsgidField &&
					get_linemsgid(lineno) != NOLINEMSG) {
					save_minus = TRUE; /*  be replaced. */
				} else {
					fprintf(newfp, "%c", yytext[0]);
				}
                        }
			if (end_of_cat) { /* just in case */
				BEGIN 0;
			} else {
				return yytext[0];
			}
		}

<CAT>[0-9]+	{	/* numbers */
			switch (cat_field) {
			case SetidField:
				yylval.id = atoi(yytext);
				if (IsActiveMode(ReplaceMode)) {
					fprintf(newfp, "%s", yytext);
				} 
				if (end_of_cat) {
					BEGIN 0;
				} else {
					return SETID;
				}
			case MsgidField:
				yylval.id = atoi(yytext);
				if (IsActiveMode(ReplaceMode)) {
					int id = get_linemsgid(lineno);
					if (id == NOLINEMSG) {
						fprintf(newfp, "%s", yytext);
					} else if (id == NOMSGID &&
						IsActiveMode(ReverseMode)) {
						fprintf(newfp, "%d", NOMSGID);
					} else if (save_minus == TRUE &&
						yylval.id == 1) {
						fprintf(newfp, "%d",id);
					} else { /* just in case */
						fprintf(newfp, "%s", yytext);
					}
					save_minus = FALSE;
				} else {
					msg_line = lineno;
				}
				if (end_of_cat) {
					BEGIN 0;
				} else {
					return MSGID;
				}
			default:
				yylval.id = atoi(yytext);
				if (IsActiveMode(ReplaceMode)) {
					fprintf(newfp, "%s", yytext);
				}
				if (end_of_cat) {
					BEGIN 0;
				} else {
					return DIGIT;
				}
			}
		}

<CAT>[a-zA-Z0-9_\&][a-zA-Z0-9_\>\&\.]*	{
			if (IsActiveMode(ReplaceMode)) {
				fprintf(newfp, "%s", yytext);
			}
			if (end_of_cat) {
				BEGIN 0;
			} else {
				return STR;
			}
		}

<CAT>\n		{
			lineno++;
			if (IsActiveMode(ReplaceMode)) {
				fprintf(newfp, "\n");
			}
			if (end_of_cat) {
				BEGIN 0;
			} 
		}

<CAT>.		{	/* not interested */
			if (IsActiveMode(ReplaceMode)) {
				fprintf(newfp, "%c", yytext[0]);
			}
			if (end_of_cat) {
				BEGIN 0;
			} 
		}

-((([ \t]+)1)|1) {	/* -1 */
			if (end_of_cat == FALSE) {
				REJECT;
			} else if (IsActiveMode(ReplaceMode)) {
				if (IsActiveMode(PreProcessMode)) {
					int id = get_linemsgid(lineno);
					if (id == NOLINEMSG) {
						fprintf(newfp, "%s", yytext);
					} else { /* could be -1. */
						fprintf(newfp, "%d", id);
					}
				} else {
					fprintf(newfp, "%s", yytext);
				}
			}
		}

[0-9]+		{
			if (IsActiveMode(ReplaceMode)) {
				if (IsActiveMode(PreProcessMode) &&
					IsActiveMode(ReverseMode)) {
					int id = get_linemsgid(lineno);
					if (id == NOLINEMSG) {
						fprintf(newfp, "%s", yytext);
					} else if (id == NOMSGID) {
						fprintf(newfp, "%d", id);
					}
				} else {
					fprintf(newfp, "%s", yytext);
				}
			}
		}

^#[ \t]*[0-9]+.*\n	{	/* pound for c-preprocessor */
			if (IsActiveMode(PreProcessMode)) {
				if (IsActiveMode(ReplaceMode)) {
					fprintf(newfp, "%s", yytext);
				} else {
					parse_cppline(yytext);
				}
			} else if (IsActiveMode(ReplaceMode)) {
				fprintf(newfp, "%s", yytext);
			}
			lineno++;
		}

"/*"		{	/* skip a comment block */
			char *comment = skip_comment();
			if (IsActiveMode(ReplaceMode)) {
				fprintf(newfp, "%s", comment);
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
				fprintf(newfp, "%s", yytext);
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
				fprintf(newfp, "\"%s\"", qstr);
			}
			free(qstr);
		}

\'		{	/* skip single-quoted character */
			char *qchr = skip_quoted('\'');
			if (IsActiveMode(ReplaceMode)) {
				fprintf(newfp, "\'%s\'", qchr);
			}
			free(qchr);
		}

\n		{
			if (IsActiveMode(ReplaceMode)) {
				fprintf(newfp, "\n");
			}
			lineno++;
		}

.		{
			if (IsActiveMode(ReplaceMode)) {
				fprintf(newfp, "%c", yytext[0]);
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

	if ((buf = ptr = (char *) malloc(bsize)) == NULL) {
		prg_err(gettext("fatal: out of memory"));
		exit(EXIT_FAILURE);
	}
	for (;; i++) {
		if (i == bsize) {
			bsize += BUFSIZ;
			if ((buf = (char *) realloc((void *) buf,
				bsize)) == NULL) {
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
				warning(gettext("warning: unmatched \
character"));
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
	return buf;
}

static char *
skip_comment(void)
{
	char *buf, *ptr;	/* saved buffer and its pointer */
	int bsize = BUFSIZ;	/* growing buffer size */
	int i = 0;		/* counter */
	int c, old = 0;		/* input character */

	if ((buf = ptr = (char *) malloc(bsize)) == NULL) {
		prg_err(gettext("fatal: out of memory"));
		exit(EXIT_FAILURE);
	}
	*ptr++ = '/';	i++;
	*ptr++ = '*';	i++;
	for (;; i++) {
		if (i == bsize) {
			bsize += BUFSIZ;
			if ((buf = (char *) realloc((void *) buf,
				bsize)) == NULL) {
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
	return buf;
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
	char file[LINE_MAX];
	char *pfile = &file[0];

	n = sscanf(str, "%c%d%s", &ch, &line, file);

	/* 'file' is a quoted string but 'srcfile' is not. */
	len = strlen(file) - 2;
	pfile++;
	if (n == 3 && (strncmp(pfile, srcfile, len) == 0)) {
		pound_is_mine = TRUE;
		lineno = line - 1;
	} else if (n == 2 && (pound_is_mine == TRUE)) {
		lineno = line - 1;
	} else {
		pound_is_mine = FALSE;
	}
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
	memset(line_msgid, 0, sizeof(LineMsgID) * NL_MSGMAX);
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
	register int i, left, right;
	left = 0;
	right = line_msgcnt - 1;
	while (left <= right) {
		i = (left + right) >> 1;
		if ( line < line_msgid[i].line) {
			right = i - 1;
		} else if (line > line_msgid[i].line) {
			left = i + 1;
		} else {
			return line_msgid[i].msgid;
		}
	}
	return NOLINEMSG;
}

void
yyerror(char *s)
{
	if ((IsActiveMode(PreProcessMode) && pound_is_mine == FALSE) ||
		IsActiveMode(ReplaceMode)) {
		return;
	}
	src_err(srcfile, lineno, gettext("%s before or at: %s"), s, yytext);
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
