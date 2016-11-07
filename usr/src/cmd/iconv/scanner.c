/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * This file contains the "scanner", which tokenizes charmap files
 * for iconv for processing by the higher level grammar processor.
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <limits.h>
#include <string.h>
#include <widec.h>
#include <sys/types.h>
#include <assert.h>
#include "charmap.h"
#include "parser.tab.h"

int			com_char = '#';
int			esc_char = '\\';
int			mb_cur_min = 1;
int			mb_cur_max = MB_LEN_MAX;
int			lineno = 1;
int			warnings = 0;
static int		nextline;
static FILE		*input = stdin;
static const char	*filename = "<stdin>";
static int		instring = 0;
static int		escaped = 0;

/*
 * Token space ... grows on demand.
 */
static char *token = NULL;
static int tokidx;
static int toksz = 0;
static int hadtok = 0;

/*
 * The last keyword seen.  This is useful to trigger the special lexer rules
 * for "copy" and also collating symbols and elements.
 */
int	last_kw = 0;
static int	category = T_END;

static struct token {
	int id;
	const char *name;
} keywords[] = {
	{ T_COM_CHAR,		"comment_char" },
	{ T_ESC_CHAR,		"escape_char" },
	{ T_END,		"END" },

	/*
	 * These are keywords used in the charmap file.  Note that
	 * Solaris orginally used angle brackets to wrap some of them,
	 * but we removed that to simplify our parser.  The first of these
	 * items are "global items."
	 */
	{ T_CHARMAP,		"CHARMAP" },
	{ T_WIDTH,		"WIDTH" },
	{ T_WIDTH_DEFAULT,	"WIDTH_DEFAULT" },

	{ -1, NULL },
};

/*
 * These special words are only used in a charmap file, enclosed in <>.
 */
static struct token symwords[] = {
	{ T_COM_CHAR,		"comment_char" },
	{ T_ESC_CHAR,		"escape_char" },
	{ T_CODE_SET,		"code_set_name" },
	{ T_MB_CUR_MAX,		"mb_cur_max" },
	{ T_MB_CUR_MIN,		"mb_cur_min" },
	{ -1, NULL },
};

static int categories[] = {
	T_CHARMAP,
	0
};

void
reset_scanner(const char *fname)
{
	if (fname == NULL) {
		filename = "<stdin>";
		input = stdin;
	} else {
		if (input != stdin)
			(void) fclose(input);
		if ((input = fopen(fname, "r")) == NULL) {
			perror(fname);
			exit(1);
		}
		filename = fname;
	}
	com_char = '#';
	esc_char = '\\';
	instring = 0;
	escaped = 0;
	lineno = 1;
	nextline = 1;
	tokidx = 0;
	last_kw = 0;
	category = T_END;
}

#define	hex(x)	\
	(isdigit(x) ? (x - '0') : ((islower(x) ? (x - 'a') : (x - 'A')) + 10))
#define	isodigit(x)	((x >= '0') && (x <= '7'))

static int
scanc(void)
{
	int	c;

	c = getc(input);
	lineno = nextline;
	if (c == '\n') {
		nextline++;
	}
	return (c);
}

static void
unscanc(int c)
{
	if (c == '\n') {
		nextline--;
	}
	if (ungetc(c, input) < 0) {
		yyerror(_("ungetc failed"));
	}
}

static int
scan_hex_byte(void)
{
	int	c1, c2;
	int	v;

	c1 = scanc();
	if (!isxdigit(c1)) {
		yyerror(_("malformed hex digit"));
		return (0);
	}
	c2 = scanc();
	if (!isxdigit(c2)) {
		yyerror(_("malformed hex digit"));
		return (0);
	}
	v = ((hex(c1) << 4) | hex(c2));
	return (v);
}

static int
scan_dec_byte(void)
{
	int	c1, c2, c3;
	int	b;

	c1 = scanc();
	if (!isdigit(c1)) {
		yyerror(_("malformed decimal digit"));
		return (0);
	}
	b = c1 - '0';
	c2 = scanc();
	if (!isdigit(c2)) {
		yyerror(_("malformed decimal digit"));
		return (0);
	}
	b *= 10;
	b += (c2 - '0');
	c3 = scanc();
	if (!isdigit(c3)) {
		unscanc(c3);
	} else {
		b *= 10;
		b += (c3 - '0');
	}
	return (b);
}

static int
scan_oct_byte(void)
{
	int c1, c2, c3;
	int	b;

	b = 0;

	c1 = scanc();
	if (!isodigit(c1)) {
		yyerror(_("malformed octal digit"));
		return (0);
	}
	b = c1 - '0';
	c2 = scanc();
	if (!isodigit(c2)) {
		yyerror(_("malformed octal digit"));
		return (0);
	}
	b *= 8;
	b += (c2 - '0');
	c3 = scanc();
	if (!isodigit(c3)) {
		unscanc(c3);
	} else {
		b *= 8;
		b += (c3 - '0');
	}
	return (b);
}

void
add_tok(int c)
{
	if ((tokidx + 1) >= toksz) {
		toksz += 64;
		if ((token = realloc(token, toksz)) == NULL) {
			yyerror(_("out of memory"));
			tokidx = 0;
			toksz = 0;
			return;
		}
	}

	token[tokidx++] = (char)c;
	token[tokidx] = 0;
}

static int
get_byte(void)
{
	int	c;

	if ((c = scanc()) != esc_char) {
		unscanc(c);
		return (EOF);
	}
	c = scanc();

	switch (c) {
	case 'd':
	case 'D':
		return (scan_dec_byte());
	case 'x':
	case 'X':
		return (scan_hex_byte());
	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
		/* put the character back so we can get it */
		unscanc(c);
		return (scan_oct_byte());
	default:
		unscanc(c);
		unscanc(esc_char);
		return (EOF);
	}
}

int
get_escaped(int c)
{
	switch (c) {
	case 'n':
		return ('\n');
	case 'r':
		return ('\r');
	case 't':
		return ('\t');
	case 'f':
		return ('\f');
	case 'v':
		return ('\v');
	case 'b':
		return ('\b');
	case 'a':
		return ('\a');
	default:
		return (c);
	}
}

int
get_wide(void)
{
	/* NB: yylval.mbs[0] is the length */
	char *mbs = &yylval.mbs[1];
	int mbi = 0;
	int c;

	mbs[mbi] = 0;
	if (mb_cur_max > MB_LEN_MAX) {
		yyerror(_("max multibyte character size too big"));
		return (T_NULL);
	}
	for (;;) {
		if ((c = get_byte()) == EOF)
			break;
		if (mbi == mb_cur_max) {
			unscanc(c);
			yyerror(_("length > mb_cur_max"));
			return (T_NULL);
		}
		mbs[mbi++] = c;
		mbs[mbi] = 0;
	}

	/* result in yylval.mbs */
	mbs[-1] = mbi;
	return (T_CHAR);
}

int
get_symbol(void)
{
	int	c;

	while ((c = scanc()) != EOF) {
		if (escaped) {
			escaped = 0;
			if (c == '\n')
				continue;
			add_tok(get_escaped(c));
			continue;
		}
		if (c == esc_char) {
			escaped = 1;
			continue;
		}
		if (c == '\n') {	/* well that's strange! */
			yyerror(_("unterminated symbolic name"));
			continue;
		}
		if (c == '>') {		/* end of symbol */

			/*
			 * This restarts the token from the beginning
			 * the next time we scan a character.  (This
			 * token is complete.)
			 */

			if (token == NULL) {
				yyerror(_("missing symbolic name"));
				return (T_NULL);
			}
			tokidx = 0;

			/*
			 * A few symbols are handled as keywords outside
			 * of the normal categories.
			 */
			if (category == T_END) {
				int i;
				for (i = 0; symwords[i].name != 0; i++) {
					if (strcmp(token, symwords[i].name) ==
					    0) {
						last_kw = symwords[i].id;
						return (last_kw);
					}
				}
			}
			/* its an undefined symbol */
			yylval.token = strdup(token);
			if (yylval.token == NULL) {
				perror("malloc");
				exit(1);
			}
			token = NULL;
			toksz = 0;
			tokidx = 0;
			return (T_SYMBOL);
		}
		add_tok(c);
	}

	yyerror(_("unterminated symbolic name"));
	return (EOF);
}


static int
consume_token(void)
{
	int	len = tokidx;
	int	i;

	tokidx = 0;
	if (token == NULL)
		return (T_NULL);

	/*
	 * this one is special, because we don't want it to alter the
	 * last_kw field.
	 */
	if (strcmp(token, "...") == 0) {
		return (T_ELLIPSIS);
	}

	/* search for reserved words first */
	for (i = 0; keywords[i].name; i++) {
		int j;
		if (strcmp(keywords[i].name, token) != 0) {
			continue;
		}

		last_kw = keywords[i].id;

		/* clear the top level category if we're done with it */
		if (last_kw == T_END) {
			category = T_END;
		}

		/* set the top level category if we're changing */
		for (j = 0; categories[j]; j++) {
			if (categories[j] != last_kw)
				continue;
			category = last_kw;
		}

		return (keywords[i].id);
	}

	/* maybe its a numeric constant? */
	if (isdigit(*token) || (*token == '-' && isdigit(token[1]))) {
		char *eptr;
		yylval.num = strtol(token, &eptr, 10);
		if (*eptr != 0)
			yyerror(_("malformed number"));
		return (T_NUMBER);
	}

	/*
	 * A single lone character is treated as a character literal.
	 * To avoid duplication of effort, we stick in the charmap.
	 */
	if (len == 1) {
		yylval.mbs[0] = 1; /* length */
		yylval.mbs[1] = token[0];
		yylval.mbs[2] = '\0';
		return (T_CHAR);
	}

	/* anything else is treated as a symbolic name */
	yylval.token = strdup(token);
	token = NULL;
	toksz = 0;
	tokidx = 0;
	return (T_NAME);
}

void
scan_to_eol(void)
{
	int	c;
	while ((c = scanc()) != '\n') {
		if (c == EOF) {
			/* end of file without newline! */
			errf(_("missing newline"));
			return;
		}
	}
	assert(c == '\n');
}

int
yylex(void)
{
	int		c;

	while ((c = scanc()) != EOF) {

		/* special handling for quoted string */
		if (instring) {
			if (escaped) {
				escaped = 0;

				/* if newline, just eat and forget it */
				if (c == '\n')
					continue;

				if (strchr("xXd01234567", c)) {
					unscanc(c);
					unscanc(esc_char);
					return (get_wide());
				}
				yylval.mbs[0] = 1; /* length */
				yylval.mbs[1] = get_escaped(c);
				yylval.mbs[2] = '\0';
				return (T_CHAR);
			}
			if (c == esc_char) {
				escaped = 1;
				continue;
			}
			switch (c) {
			case '<':
				return (get_symbol());
			case '>':
				/* oops! should generate syntax error  */
				return (T_GT);
			case '"':
				instring = 0;
				return (T_QUOTE);
			default:
				yylval.mbs[0] = 1; /* length */
				yylval.mbs[1] = c;
				yylval.mbs[2] = '\0';
				return (T_CHAR);
			}
		}

		/* escaped characters first */
		if (escaped) {
			escaped = 0;
			if (c == '\n') {
				/* eat the newline */
				continue;
			}
			hadtok = 1;
			if (tokidx) {
				/* an escape mid-token is nonsense */
				return (T_NULL);
			}

			/* numeric escapes are treated as wide characters */
			if (strchr("xXd01234567", c)) {
				unscanc(c);
				unscanc(esc_char);
				return (get_wide());
			}

			add_tok(get_escaped(c));
			continue;
		}

		/* if it is the escape charter itself note it */
		if (c == esc_char) {
			escaped = 1;
			continue;
		}

		/* remove from the comment char to end of line */
		if (c == com_char) {
			while (c != '\n') {
				if ((c = scanc()) == EOF) {
					/* end of file without newline! */
					return (EOF);
				}
			}
			assert(c == '\n');
			if (!hadtok) {
				/*
				 * If there were no tokens on this line,
				 * then just pretend it didn't exist at all.
				 */
				continue;
			}
			hadtok = 0;
			return (T_NL);
		}

		if (strchr(" \t\n;()<>,\"", c) && (tokidx != 0)) {
			/*
			 * These are all token delimiters.  If there
			 * is a token already in progress, we need to
			 * process it.
			 */
			unscanc(c);
			return (consume_token());
		}

		switch (c) {
		case '\n':
			if (!hadtok) {
				/*
				 * If the line was completely devoid of tokens,
				 * then just ignore it.
				 */
				continue;
			}
			/* we're starting a new line, reset the token state */
			hadtok = 0;
			return (T_NL);
		case ',':
			hadtok = 1;
			return (T_COMMA);
		case ';':
			hadtok = 1;
			return (T_SEMI);
		case '(':
			hadtok = 1;
			return (T_LPAREN);
		case ')':
			hadtok = 1;
			return (T_RPAREN);
		case '>':
			hadtok = 1;
			return (T_GT);
		case '<':
			/* symbol start! */
			hadtok = 1;
			return (get_symbol());
		case ' ':
		case '\t':
			/* whitespace, just ignore it */
			continue;
		case '"':
			hadtok = 1;
			instring = 1;
			return (T_QUOTE);
		default:
			hadtok = 1;
			add_tok(c);
			continue;
		}
	}
	return (EOF);
}

void
yyerror(const char *msg)
{
	(void) fprintf(stderr, _("%s: %d: error: %s\n"),
	    filename, lineno, msg);
	exit(1);
}

void
errf(const char *fmt, ...)
{
	char	*msg;

	va_list	va;
	va_start(va, fmt);
	(void) vasprintf(&msg, fmt, va);
	va_end(va);

	(void) fprintf(stderr, _("%s: %d: error: %s\n"),
	    filename, lineno, msg);
	free(msg);
	exit(1);
}

void
warn(const char *fmt, ...)
{
	char	*msg;

	va_list	va;
	va_start(va, fmt);
	(void) vasprintf(&msg, fmt, va);
	va_end(va);

	(void) fprintf(stderr, _("%s: %d: warning: %s\n"),
	    filename, lineno, msg);
	free(msg);
	warnings++;
}
