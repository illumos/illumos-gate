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
 * Copyright (c) 1997-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "xlator.h"
#include "util.h"
#include "bucket.h"
#include "errlog.h"

/* Types: */
#define	TRUE	1
#define	FALSE	0
#define	MAXLINE 1024


typedef enum {
	PARENT, UNCLE
} RELATION;


/* Statics: */
/* The parser is a dfa, driven by the following: */
static FILE *Fp;
static const char *Filename;
static char Previous[MAXLINE];
static char LeftMostChild[MAXLINE];
static int Selected = FALSE;
static int Line;
static int Errors;


/* The grammar is: */
static int arch(void);
static int comment(void);
static int arch_name(void);
static int set_list(void);
static int set(void);

/* The supporting code is: */
static int accept_token(char *);
static void skip_to(char *);

/* And the tokenizer is: */
static char *tokenize(char *);
static char *currtok(void);
static char *nexttok(void);
static char *skipb(char *);
static char *skipover(char *);
static char *CurrTok = NULL;

static int set_parents(void);

static table_t *Vers;
static table_t *Varch;

static void init_tables(void);

static void add_valid_arch(char *);
static void add_valid_version(char *vers_name);


#define	in_specials(c)  ((c) == '{' || (c) == '}' || (c) == '+' || \
	(c) == '-' || (c) == ';' || (c) == ':' || (c) == ',' || \
	(c) == '[' || (c) == ']')

#define	eq(s1, s2)	(strcmp((s1), (s2)) == 0)


/*
 * parse_versions -- parse the file whose name is passed, return
 *	the number of (fatal) errors encountered. Currently only
 *	knows about reading set files and writing vers files.
 */
int
parse_versions(const char *fileName)
{

	/* Prime the set-file parser dfa: */
	assert(fileName != NULL, "passed null filename to parse_versions");
	errlog(BEGIN, "parse_versions(%s) {", fileName);


	if ((Fp = fopen(fileName, "r")) == NULL) {
		(void) fprintf(stderr, "Cannot open version file \"%s\"\n",
		    fileName);
		errlog(END, "} /* parse_versions */");
		return (1);
	}
	Filename = fileName;
	Line = 0;

	errlog(VERBOSE, "reading set file %s looking for architecture %s",
	    Filename, TargetArchStr);

	/* Run the dfa. */
	while (arch())
		continue;

	(void) fclose(Fp);
	/* print_all_buckets(); */
	errlog(END, "} /* parse_versions */");
	return (Errors);
}


/*
 * The parser. This implements the grammar:
 *    setfile::= (arch())+ <EOF>
 *             | <EOF>
 *    arch::= <ARCHITECTURE> "{" (set_list())* "}"
 *    set_list::= (set())+ ";"
 *    set::= <IDENTIFIER> ["[" "WEAK" "]"] ":" "{" (ancestors) "}" ";"
 *    ancestors::= <IDENTIFIER> | <ancestors> "," <IDENTIFIER>
 *    where <ARCHITECTURE> and <IDENTIFIER> are tokens.
 */
static int
arch(void)
{
	int olderrors;

	errlog(BEGIN, "arch() {");
	if (comment()) {
		errlog(END, "} /* arch */");
		return (TRUE);
	}
	if (arch_name() == FALSE) {
		errlog(END, "} /* arch */");
		return (FALSE);
	}
	if (accept_token("{") == FALSE) {
		errlog(END, "} /* arch */");
		return (FALSE);
	}

	olderrors = Errors;
	if (set_list() == FALSE) {
		if (olderrors != Errors) {
			errlog(END, "} /* arch */");
			return (FALSE);
		}
	}

	errlog(END, "} /* arch */");
	return (TRUE);
}

static int
comment(void)
{
	char *token = currtok();

	if (token == NULL || *token != '#') {
		return (FALSE);
	} else {
		/* Swallow token. */
		token =  nexttok();
		return (TRUE);
	}
}

static int
arch_name(void)
{
	char *token = currtok();

	errlog(BEGIN, "arch_name() {");
	errlog(VERBOSE, "token = '%s';",
		token ? token : "<NULL>");

	if (token == NULL) {
		errlog(END, "} /* arch_name */");
		return (FALSE);

	} else if (in_specials(*token)) {
		/* It's not an architecture */
		Selected = FALSE;

		/* Report a syntax error: TBD */
		errlog(INPUT | ERROR, "found special char. %c "
		    "while looking for an architecture name",
		    *token);

		skip_to("}");	/* The follower set for arch_name. */
		errlog(END, "} /* arch name */");

		Errors++;
		return (FALSE);

	} else if (!eq(token, TargetArchStr)) {
		/* It's an architecture ... */
		errlog(VERBOSE, "Begin unselected architecture: %s", token);
		add_valid_arch(token);
		(void) nexttok();

		/* ... but the the wrong one. */
		Selected = FALSE;
		errlog(END, "} /* arch name */");
		return (TRUE);
	} else {
		/* Found the right architecture. */
		errlog(VERBOSE, "Begin selected architecture: %s", token);
		add_valid_arch(token);
		(void) nexttok();
		Selected = TRUE;
		errlog(END, "} /* arch name */");
		return (TRUE);
	}
}


static int
set_list(void)
{
	int olderrors;
	char *token = currtok();

	errlog(BEGIN, "set_list() {");
	errlog(VERBOSE, "token = '%s'",
	    (token) ? token : "<NULL>");
	if (set() == FALSE) {
		errlog(END, "} /* set_list */");
		return (FALSE);
	}

	olderrors = Errors;
	while (set()) {
		continue;
	}
	if (olderrors != Errors) {
		errlog(END, "} /* set_list */");
		return (FALSE);
	}

	errlog(END, "} /* set_list */");
	return (TRUE);
}


static int
set(void)
{
	char *token = currtok();
	int has_parent = 0;

	errlog(BEGIN, "set() {");
	errlog(VERBOSE, "token = '%s'",
	    (token) ? token : "<NULL>");

	if (in_specials(*token)) {
		errlog(INPUT|ERROR, "unexpected token \"%s\" found. "
		    "Version name expected", token);
		Errors++;
		errlog(END, "} /* set */");
		return (FALSE);
	}

	errlog(VERBOSE, "Begin Version: %s", token);
	*Previous = '\0';
	if (Selected) {
		if (add_parent(token, Previous, 0) == FALSE) {
			errlog(INPUT | ERROR, "unable to add a parent version "
			    "from the set file");
			Errors++;
			errlog(END, "} /* set */");
			return (FALSE);
		}
	}

	add_valid_version(token);
	(void) strncpy(LeftMostChild, token, MAXLINE);
	LeftMostChild[MAXLINE-1] = '\0';
	(void) strncpy(Previous, token, MAXLINE);
	Previous[MAXLINE-1] = '\0';

	token = nexttok();

	switch (*token) {
		case ':':
			errlog(VERBOSE, "token ':' found");
			(void) accept_token(":");
			if (set_parents() == FALSE) {
				errlog(END, "} /* set */");
				return (FALSE);
			}
			if (accept_token(";") == FALSE) {
				errlog(END, "} /* set */");
				return (FALSE);
			}
			errlog(VERBOSE, "End Version");
			break;

		case ';':
			errlog(VERBOSE, "token ';' found");
			(void) accept_token(";");
			errlog(VERBOSE, "End version ':'");
			break;

		case '[':
			(void) accept_token("[");
			if (accept_token("WEAK") == FALSE) {
				errlog(END, "} /* set */");
				return (FALSE);
			}
			if (accept_token("]") == FALSE) {
				errlog(END, "} /* set */");
				return (FALSE);
			}
			token = currtok();
			if (eq(token, ":")) {
				(void) accept_token(":");
				has_parent = 1;
			} else if (eq(token, ";")) {
				(void) accept_token(";");
			} else {
				errlog(ERROR|INPUT,
				    "Unexpected token \"%s\" found. ':'"
				    "or ';' expected.", token);
				Errors++;
				errlog(END, "} /* set */");
				return (FALSE);
			}
			errlog(VERBOSE, "WEAK version detected\n");
			if (Selected)
				set_weak(LeftMostChild, TRUE);

			if (has_parent) {
				if (set_parents() == FALSE) {
					errlog(END, "} /* set */");
					return (FALSE);
				}
				if (accept_token(";") == FALSE) {
					errlog(END, "} /* set */");
					return (FALSE);
				}
			}
			errlog(VERBOSE, "End Version");
			break;
		default:
			/* CSTYLED */
			errlog(ERROR|INPUT,
			    "Unexpected token \"%s\" found. ';' expected.",
			    token);
			Errors++;
			errlog(END, "} /* set */");
			return (FALSE);
	}

	token = currtok();
	if (eq(token, "}")) {
		(void) accept_token("}");
		errlog(VERBOSE, "End architecture");
		errlog(END, "} /* set */");
		return (FALSE);
	}

	errlog(END, "} /* set */");
	return (TRUE);
}

static int
set_parents(void)
{
	char *token = currtok();
	int uncle;

	errlog(BEGIN, "set_parents() {");
	errlog(VERBOSE, "token = '%s'",
	    (token) ? token : "<NULL>");

	if (accept_token("{") == FALSE) {
		errlog(INPUT|ERROR, "set_parents(): Unexpected token: %s\n",
		    token);
		Errors++;
		errlog(END, "} /* set_parents */");
		return (FALSE);
	}

	token = currtok();

	if (in_specials(*token)) {
		errlog(INPUT|ERROR, "set_parents(): Unexpected token: %c "
		    "found. Version token expected", *token);
		Errors++;
		errlog(END, "} /* set_parents */");
		return (FALSE);
	}

	uncle = 0;
	while (token && *token != '}') {
		errlog(VERBOSE, "Begin parent list: %s\n", token);
		if (Selected) {
			if (uncle)
				(void) add_uncle(token, LeftMostChild, 0);
			else
				(void) add_parent(token, Previous, 0);
		}
		(void) strncpy(Previous, token, MAXLINE);
		add_valid_version(token);
		Previous[MAXLINE-1] = '\0';

		token = nexttok();

		if (*token == ',') {
			token = nexttok();
			/* following identifiers are all uncles */
			uncle = 1;
			continue;
		}

		if (*token == '}') {
			if (accept_token("}") == FALSE) {
				errlog(END, "} /* set_parents */");
				return (FALSE);
			}
			errlog(VERBOSE, "set_parent: End of parent list");
			errlog(END, "} /* set_parents */");
			return (TRUE);
		}

		errlog(INPUT|ERROR,
		    "set_parents(): Unexpected token \"%s\" "
		    "found. ',' or '}' were expected", token);
		Errors++;
		errlog(END, "} /* set_parents */");
		return (FALSE);
	}
	errlog(END, "} /* set_parents */");
	return (TRUE);
}


/*
 * parser support routines
 */


/*
 * accept_token -- get a specified token or complain loudly.
 */
static int
accept_token(char *expected)
{
	char *token = currtok();

	assert(expected != NULL, "null token passed to accept_token");
	errlog(OTHER | TRACING, "accept_token, at %s expecting %s",
		(token) ? token : "<NULL>", expected);

	if (token == NULL) {
		/* We're at EOF */
		return (TRUE);
	}
	if (eq(token, expected)) {
		(void) nexttok();
		return (TRUE);
	} else {
		errlog(INPUT | ERROR,
			"accept_token, found %s while looking for %s",
			(token) ? token : "<NULL>", expected);
		++Errors;
		return (FALSE);
	}
}

static void
skip_to(char *target)
{
	char *token = currtok();

	assert(target != NULL, "null target passed to skip_to");
	while (token && !eq(token, target)) {
		errlog(VERBOSE, "skipping over %s",
			(token) ? token : "<NULL>");
		token = nexttok();
	}
}


/*
 * tokenizer -- below the grammar lives this, like a troll
 *	under a bridge.
 */


/*
 * skipb -- skip over blanks (whitespace, actually), stopping
 *      on first non-blank.
 */
static char *
skipb(char *p)
{

	while (*p && isspace(*p))
		++p;
	return (p);
}

/*
 * skipover -- skip over non-separators (alnum, . and _, actually),
 *      stopping on first separator.
 */
static char *
skipover(char *p)
{

	while (*p && (isalnum(*p) || (*p == '_' || *p == '.')))
		++p;
	return (p);
}


/*
 * currtok/nexttok -- get the current/next token
 */
static char *
currtok(void)
{

	if (CurrTok == NULL) {
		(void) nexttok();
	}
	return (CurrTok);
}

static char *
nexttok(void)
{
	static char line[MAXLINE];
	char *p;

	if ((p = tokenize(NULL)) == NULL) {
		/* We're at an end of line. */
		do {
			if (fgets(line, sizeof (line), Fp) == NULL) {
				/* Which is also end of file. */
				CurrTok = NULL;
				return (NULL);
			}
			++Line;
			seterrline(Line, Filename, "", line);
		} while ((p = tokenize(line)) == NULL);
	}
	CurrTok = p;
	return (p);
}



/*
 * tokenize -- a version of the standard strtok with specific behavior.
 */
static char *
tokenize(char *line)
{
	static char *p = NULL;
	static char saved = 0;
	char *q;

	if (line == NULL && p == NULL) {
		/* It's the very first time */
		return (NULL);
	} else if (line != NULL) {
		/* Initialize with a new line */
		q = skipb(line);
	} else {
		/* Restore previous line. */
		*p = saved;
		q = skipb(p);
	}
	/* q is at the beginning of a token or at EOL, p is irrelevant. */

	if (*q == '\0') {
		/* It's at EOL. */
		p = q;
	} else if (in_specials(*q)) {
		/* We have a special-character token. */
		p = q + 1;
	} else if (*q == '#') {
		/* The whole rest of the line is a comment token. */
		return (NULL);
	} else {
		/* We have a word token. */
		p = skipover(q);
	}
	saved = *p;
	*p = '\0';

	if (p == q) {
		/* End of line */
		return (NULL);
	} else {
		return (q);
	}
}


/*
 * valid_version -- see if a version string was mentioned in the set file.
 */
int
valid_version(const char *vers_name)
{

	if (Vers == NULL) {
		init_tables();
	}
	return (in_stringtable(Vers, vers_name));
}

/*
 * valid_arch -- see if the arch was mentioned in the set file.
 */
int
valid_arch(const char *arch_name)
{

	if (Vers == NULL) {
		init_tables();
	}
	return (in_stringtable(Varch, arch_name));
}

/*
 * add_valid_version and _arch -- add a name to the table.
 */
static void
add_valid_version(char *vers_name)
{
	errlog(BEGIN, "add_valid_version(\"%s\") {", vers_name);
	if (Vers == NULL) {
		init_tables();
	}
	Vers = add_to_stringtable(Vers, vers_name);
	errlog(END, "}");
}

static void
add_valid_arch(char *arch_name)
{

	errlog(BEGIN, "add_valid_arch(\"%s\") {", arch_name);
	if (Vers == NULL) {
		init_tables();
	}
	Varch = add_to_stringtable(Varch, arch_name);
	errlog(END, "}");
}

/*
 * init_tables -- creat them when first used.
 */
static void
init_tables(void)
{
	Vers = create_stringtable(TABLE_INITIAL);
	Varch = create_stringtable(TABLE_INITIAL);
}
