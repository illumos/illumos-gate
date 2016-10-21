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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <assert.h>
#include <string.h>
#include <libintl.h>
#include "zonecfg.h"
#include "zonecfg_grammar.tab.h"

/*
 * This constant defines the number of entries added to unclaimed_tokens[]
 * when it runs out of space.
 */
#define	UNCLAIMED_TOKENS_BUFFER_GROWTH	4

/*
 * Invariants:
 *
 *	unclaimed_tokens == NULL IFF unclaimed_tokens_size == 0
 *	unclaimed_tokens_size == 0 IFF num_unclaimed_tokens == 0
 */
static char **unclaimed_tokens;		/* TOKENs produced by Lex (see below) */
					/* but not claimed by YACC reduction */
					/* rules */
static unsigned int unclaimed_tokens_size;	/* size of unclaimed_tokens */
static unsigned int num_unclaimed_tokens;	/* number of unclaimed TOKENs */

int lex_lineno = 1;	/* line number for error reporting */
static int state = INITIAL;
extern boolean_t cmd_file_mode;
extern boolean_t saw_error;
extern void yyerror(char *s);

static char *create_token(char *s);
%}

%a 7000
%p 5000
%e 2000
%n 1000

%{
/*
 * The three states below are for tokens, lists and complex property values.
 * Note that simple property values are a subset of tokens.
 */
%}
%s TSTATE
%s LSTATE
%s CSTATE
%%

<INITIAL>"#"[^\n]*	{ }

<INITIAL>add	{
			BEGIN TSTATE;
			state = TSTATE;
			return ADD;
		}

<INITIAL>cancel	{
			BEGIN TSTATE;
			state = TSTATE;
			return CANCEL;
		}

<INITIAL>commit	{
			BEGIN TSTATE;
			state = TSTATE;
			return COMMIT;
		}

<INITIAL>create	{
			BEGIN TSTATE;
			state = TSTATE;
			return CREATE;
		}

<INITIAL>delete {
			BEGIN TSTATE;
			state = TSTATE;
			return DELETE;
		}

<INITIAL>end	{
			BEGIN TSTATE;
			state = TSTATE;
			return END;
		}

<INITIAL>exit	{
			BEGIN TSTATE;
			state = TSTATE;
			return EXIT;
		}

<INITIAL>export	{
			BEGIN TSTATE;
			state = TSTATE;
			return EXPORT;
		}

<INITIAL>"?"|help {
			BEGIN TSTATE;
			state = TSTATE;
			return HELP;
		}

<INITIAL>info	{
			BEGIN TSTATE;
			state = TSTATE;
			return INFO;
		}

<INITIAL>remove	{
			BEGIN TSTATE;
			state = TSTATE;
			return REMOVE;
		}

<INITIAL>revert	{
			BEGIN TSTATE;
			state = TSTATE;
			return REVERT;
		}

<INITIAL>select {
			BEGIN TSTATE;
			state = TSTATE;
			return SELECT;
		}

<INITIAL>set {
			BEGIN TSTATE;
			state = TSTATE;
			return SET;
		}

<INITIAL>clear {
			BEGIN TSTATE;
			state = TSTATE;
			return CLEAR;
		}

<INITIAL>verify	{
			BEGIN TSTATE;
			state = TSTATE;
			return VERIFY;
		}

<TSTATE>net	{ return NET; }

<TSTATE>fs	{ return FS; }

<TSTATE>device	{ return DEVICE; }

<TSTATE>rctl	{ return RCTL; }

<TSTATE>attr	{ return ATTR; }

<TSTATE>admin	{ return ADMIN; }

<TSTATE>security-flags { return SECFLAGS; }

<TSTATE>zonename	{ return ZONENAME; }
<CSTATE>zonename	{ return ZONENAME; }

<TSTATE>dataset	{ return DATASET; }

<TSTATE>dedicated-cpu	{ return PSET; }

<TSTATE>capped-cpu	{ return PCAP; }

<TSTATE>capped-memory	{ return MCAP; }

<TSTATE>zonepath	{ return ZONEPATH; }
<CSTATE>zonepath	{ return ZONEPATH; }

<TSTATE>brand	{ return BRAND; }
<CSTATE>brand	{ return BRAND; }

<TSTATE>autoboot	{ return AUTOBOOT; }
<CSTATE>autoboot	{ return AUTOBOOT; }

<TSTATE>ip-type		{ return IPTYPE; }
<CSTATE>ip-type		{ return IPTYPE; }

<TSTATE>pool	{ return POOL; }
<CSTATE>pool	{ return POOL; }

<TSTATE>limitpriv	{ return LIMITPRIV; }
<CSTATE>limitpriv	{ return LIMITPRIV; }

<TSTATE>bootargs	{ return BOOTARGS; }
<CSTATE>bootargs	{ return BOOTARGS; }

<TSTATE>type	{ return TYPE; }
<CSTATE>type	{ return TYPE; }

<TSTATE>value	{ return VALUE; }
<CSTATE>value	{ return VALUE; }

<TSTATE>options	{ return OPTIONS; }
<CSTATE>options	{ return OPTIONS; }

<TSTATE>allowed-address { return ALLOWED_ADDRESS; }
<CSTATE>allowed-address { return ALLOWED_ADDRESS; }

<TSTATE>address	{ return ADDRESS; }
<CSTATE>address	{ return ADDRESS; }

<TSTATE>physical	{ return PHYSICAL; }
<CSTATE>physical	{ return PHYSICAL; }

<TSTATE>defrouter	{ return DEFROUTER; }
<CSTATE>defrouter	{ return DEFROUTER; }

<TSTATE>dir	{ return DIR; }
<CSTATE>dir	{ return DIR; }

<TSTATE>special	{ return SPECIAL; }
<CSTATE>special	{ return SPECIAL; }

<TSTATE>raw	{ return RAW; }
<CSTATE>raw	{ return RAW; }

<TSTATE>name	{ return NAME; }
<CSTATE>name	{ return NAME; }

<TSTATE>match	{ return MATCH; }
<CSTATE>match	{ return MATCH; }

<TSTATE>priv	{ return PRIV; }
<CSTATE>priv	{ return PRIV; }

<TSTATE>limit	{ return LIMIT; }
<CSTATE>limit	{ return LIMIT; }

<TSTATE>action	{ return ACTION; }
<CSTATE>action	{ return ACTION; }

<TSTATE>ncpus	{ return NCPUS; }
<CSTATE>ncpus	{ return NCPUS; }

<TSTATE>locked	{ return LOCKED; }
<CSTATE>locked	{ return LOCKED; }

<TSTATE>swap	{ return SWAP; }
<CSTATE>swap	{ return SWAP; }

<TSTATE>importance	{ return IMPORTANCE; }
<CSTATE>importance	{ return IMPORTANCE; }

<TSTATE>cpu-shares	{ return SHARES; }
<CSTATE>cpu-shares	{ return SHARES; }

<TSTATE>max-lwps	{ return MAXLWPS; }
<CSTATE>max-lwps	{ return MAXLWPS; }

<TSTATE>max-processes	{ return MAXPROCS; }
<CSTATE>max-processes	{ return MAXPROCS; }

<TSTATE>max-shm-memory	{ return MAXSHMMEM; }
<CSTATE>max-shm-memory	{ return MAXSHMMEM; }

<TSTATE>max-shm-ids	{ return MAXSHMIDS; }
<CSTATE>max-shm-ids	{ return MAXSHMIDS; }

<TSTATE>max-msg-ids	{ return MAXMSGIDS; }
<CSTATE>max-msg-ids	{ return MAXMSGIDS; }

<TSTATE>max-sem-ids	{ return MAXSEMIDS; }
<CSTATE>max-sem-ids	{ return MAXSEMIDS; }

<TSTATE>scheduling-class	{ return SCHED; }
<CSTATE>scheduling-class	{ return SCHED; }

<TSTATE>hostid		{ return HOSTID; }
<CSTATE>hostid		{ return HOSTID; }

<TSTATE>user	{ return USER; }
<CSTATE>user	{ return USER; }

<TSTATE>auths	{ return AUTHS; }
<CSTATE>auths	{ return AUTHS; }

<TSTATE>fs-allowed	{ return FS_ALLOWED; }
<CSTATE>fs-allowed	{ return FS_ALLOWED; }

<TSTATE>default { return DEFAULT; }
<CSTATE>default { return DEFAULT; }

<TSTATE>lower { return LOWER; }
<CSTATE>lower { return LOWER; }

<TSTATE>upper { return UPPER; }
<CSTATE>upper { return UPPER; }

<TSTATE>=	{ return EQUAL; }
<LSTATE>=	{ return EQUAL; }
<CSTATE>=	{ return EQUAL; }

<TSTATE>"["	{
			BEGIN LSTATE;
			state = LSTATE;
			return OPEN_SQ_BRACKET;
		}

<LSTATE>"]"	{
			BEGIN TSTATE;
			state = TSTATE;
			return CLOSE_SQ_BRACKET;
		}

<TSTATE>"("	{
			BEGIN CSTATE;
			return OPEN_PAREN;
		}

<LSTATE>"("	{
			BEGIN CSTATE;
			return OPEN_PAREN;
		}

<CSTATE>")"	{
			BEGIN state;
			return CLOSE_PAREN;
		}

<LSTATE>","	{ return COMMA; }
<CSTATE>","	{ return COMMA; }

<TSTATE>[^ \t\n\";=\[\]\(\)]+	{
			yylval.strval = create_token(yytext);
			return TOKEN;
		}

<LSTATE>[^ \t\n\",;=\[\]\(\)]+	{
			yylval.strval = create_token(yytext);
			return TOKEN;
		}

<CSTATE>[^ \t\n\",;=\(\)]+	{
			yylval.strval = create_token(yytext);
			return TOKEN;
		}

<TSTATE>\"[^\"\n]*[\"\n] {
			yylval.strval = create_token(yytext + 1);
			if (yylval.strval[yyleng - 2] == '"')
				yylval.strval[yyleng - 2] = 0;
			return TOKEN;
		}

<LSTATE>\"[^\"\n]*[\"\n] {
			yylval.strval = create_token(yytext + 1);
			if (yylval.strval[yyleng - 2] == '"')
				yylval.strval[yyleng - 2] = 0;
			return TOKEN;
		}

";"		{
			BEGIN INITIAL;
			return (yytext[0]);
		}

\n		{
			lex_lineno++;
			BEGIN INITIAL;
			return (yytext[0]);
		}

[ \t]		;	/* Ignore whitespace */

.		{
			return (yytext[0]);
		}

%%

/*
 * Assert that there are no unclaimed tokens.  This function enforces the
 * invariants mentioned at the top of this file.
 */
void
assert_no_unclaimed_tokens(void)
{
	assert(num_unclaimed_tokens == 0);
	assert(unclaimed_tokens == NULL);
	assert(unclaimed_tokens_size == 0);
}

/*
 * Claim the specified unclaimed TOKEN.  YACC reduction rules that
 * use TOKENs should invoke this function immediately before freeing the TOKENs
 * or adding them to data structures that will be cleaned up when the YACC
 * parser finishes or encounters errors.  Reduction rules should only claim the
 * TOKENs that they use.
 *
 * This function returns its argument but does not free its memory.
 */
char *
claim_token(char *token)
{
	unsigned int index;

	/*
	 * Find the token in the list of unclaimed tokens.
	 */
	assert(num_unclaimed_tokens > 0);
	for (index = 0; index < num_unclaimed_tokens; index++) {
		if (unclaimed_tokens[index] == token)
			break;
	}

	/*
	 * Abort if we didn't find the token.
	 */
	assert(index != num_unclaimed_tokens);

	/*
	 * Replace the token with the last unclaimed token.
	 */
	num_unclaimed_tokens--;
	unclaimed_tokens[index] = unclaimed_tokens[num_unclaimed_tokens];

	/*
	 * Delete the list of unclaimed tokens if it's empty.
	 */
	if (num_unclaimed_tokens == 0) {
		free(unclaimed_tokens);
		unclaimed_tokens = NULL;
		unclaimed_tokens_size = 0;
	}

	return (token);
}

/*
 * Free all unclaimed TOKENs.  This should only be invoked when the YACC
 * parser encounters errors.
 */
static void
free_tokens(void)
{
	if (unclaimed_tokens != NULL) {
		while (num_unclaimed_tokens > 0)
			free(unclaimed_tokens[--num_unclaimed_tokens]);
		free(unclaimed_tokens);
		unclaimed_tokens = NULL;
		unclaimed_tokens_size = 0;
	}
	assert_no_unclaimed_tokens();
}

/*
 * Create a TOKEN from the specified string.  The TOKEN is merely a duplicate
 * of the specified string.  TOKENs must be claimed by the YACC reduction rules
 * that use them; see claim_token() above.
 */
char *
create_token(char *s)
{
	char *result;

	if ((result = strdup(s)) == NULL) {
		yyerror("Out of memory");
		exit(Z_ERR);
	}

	/*
	 * Add the new TOKEN to the list of unclaimed TOKENs.  The list might
	 * have to be resized.
	 *
	 * Reduction rules should claim TOKENs via claim_token() (see above).
	 */
	if (num_unclaimed_tokens == unclaimed_tokens_size) {
		char **new_unclaimed_tokens;

		unclaimed_tokens_size += UNCLAIMED_TOKENS_BUFFER_GROWTH;
		new_unclaimed_tokens = (char **)realloc(unclaimed_tokens,
		    unclaimed_tokens_size * sizeof (char *));
		if (new_unclaimed_tokens == NULL) {
			yyerror("Out of memory");
			free(result);
			exit(Z_ERR);
		}
		unclaimed_tokens = new_unclaimed_tokens;
	}
	unclaimed_tokens[num_unclaimed_tokens] = result;
	num_unclaimed_tokens++;
	return (result);
}

void
yyerror(char *s)
{
	/*
	 * Ensure that we won't leak unclaimed tokens.
	 */
	free_tokens();

	/* feof(yyin) is not an error; anything else is, so we set saw_error */
	if (yytext[0] == '\0') {
		if (!feof(yyin)) {
			saw_error = B_TRUE;
			(void) fprintf(stderr, gettext("%s, token expected\n"),
			    s);
		}
		return;
	}

	saw_error = B_TRUE;
	if (cmd_file_mode)
		(void) fprintf(stderr, gettext("%s on line %d at '%s'\n"), s,
		    lex_lineno, (yytext[0] == '\n') ? "\\n" : yytext);
	else
		(void) fprintf(stderr, gettext("%s at '%s'\n"), s,
		    (yytext[0] == '\n') ? "\\n" : yytext);
	usage(B_FALSE, HELP_SUBCMDS);
}
