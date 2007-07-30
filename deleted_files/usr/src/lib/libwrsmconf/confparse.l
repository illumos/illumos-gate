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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * Lexical analyzer used for parsing wrsm cluster configuration files
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <strings.h>
#include <ctype.h>
#include <sys/wrsm_config.h>
#include "confparse.tab.h"

int ErrorCount = 0;
int lineNumber = 1;
int lexdebug = 0;

YYSTYPE yylval;

typedef struct reserved {
	char *name;
	int id;
} reserved_t;

static int lookup_reserved(char *name);

/*
 * For debugging purposes, ECHO can be defined to print tokens 
 * as they are reduced.
 */
#ifdef ECHO
#undef ECHO
#define ECHO
#endif

/*
 * If lexdebug it turned on, print each token value and string
 * before they are returned.
 */
#define Return(x) if (lexdebug) fprintf(stderr,"\"%s\":%d\n", yytext, x); return x;

%}

DIGIT		[0-9]
EXTDIGIT        [0-9a-fA-F]
LETTER          [a-zA-Z]
ID		{LETTER}("_"|"-"|{LETTER}|{DIGIT})*
INTEGER         [-]?{DIGIT}+
HEX             0x{EXTDIGIT}+
WS              [\t ]

%%

"//".*		{ ECHO; }
"#".*		{ ECHO; }
{WS}*		{ ECHO; }
"\n"		{ ECHO; ++lineNumber; }

{INTEGER} { 
	ECHO;
	yylval.ival = strtoull(yytext, 0, NULL);
	Return(INT);
}

{HEX} {
	ECHO;
	yylval.ival = strtoull(yytext, 0, NULL);
	Return(INT);
}

"true"	{ ECHO; yylval.bool = B_TRUE; Return(BOOL); }
"false" { ECHO; yylval.bool = B_FALSE; Return(BOOL); }
"central_switch"	{ 
	ECHO; yylval.tt = topology_central_switch; 
	Return(TT); 
}
"distributed_switch"	{ 
	ECHO; 
	yylval.tt = topology_distributed_switch; 
	Return(TT); 
}
"san_switch"		{ ECHO; yylval.tt = topology_san_switch; Return(TT); }
"multihop"		{ ECHO; yylval.rm = routing_multihop; Return(RM); }
"passthrough"		{ ECHO; yylval.rm = routing_passthrough; Return(RM); }

{ID} {
	int id;
	ECHO;
	if (id = lookup_reserved(yytext)) {
		Return(id);
	}
	yylval.name = malloc(strlen(yytext) + 1);
	strcpy(yylval.name, yytext);
	Return(NAME);
}


"{"	{ ECHO; Return(LB); }
"}"	{ ECHO; Return(RB); }
"("	{ ECHO; Return(LP); }
")"	{ ECHO; Return(RP); }
","	{ ECHO; Return(COMMA); }

. {
	/* 
	 * If none of the rules above matched there must be an
	 * unrecognized character, so fall through to here.
	 */
	ECHO; 
	if (isprint(*yytext))
		fprintf(stderr,"Illegal character: %c\n",*yytext); 
	else
		fprintf(stderr,"Illegal character: %d\n",*yytext); 
	++ErrorCount;
}

%%

reserved_t res_words[] = {
{"fmnodeid", FMNODEID},
{"controller", CONTROLLER},
{"version", VERSION},
{"config_protocol_version", CONF_PROTOCOL_VERSION},
{"local_cnodeid", LOCAL_CNODEID},
{"imported_ncslices", IMPORTED_NCSLICES},
{"exported_ncslices", EXPORTED_NCSLICES},
{"cnodeid", CNODEID},
{"comm_ncslice", COMM_NCSLICE},
{"local_offset", LOCAL_OFFSET},
{"small", SMALL},
{"large", LARGE},
{"wci", WCI},
{"safari_port_id", SAFARI_PORT_ID},
{"wnodeid", WNODEID},
{"gnid", GNID},
{"reachable", REACHABLE},
{"route_map_striping", ROUTE_MAP_STRIPING},
{"topology_type", TOPOLOGY_TYPE},
{"link", LINK},
{"remote_gnid", REMOTE_GNID},
{"remote_link", REMOTE_LINK},
{"remote_wci", REMOTE_WCI},
{"routing_policy", ROUTING_POLICY},
{"preferred_routes", PREFERRED_ROUTES},
{"wcis_balanced", WCIS_BALANCED},
{"striping_important", STRIPING_IMPORTANT},
{"forwarding_ncslices", FORWARDING_NCSLICES},
{"preferred_route", PREFERRED_ROUTE},
{"striping_level", STRIPING_LEVEL},
{"routing_method", ROUTING_METHOD},
{"use_wci", USE_WCI},
{"stripe_group", STRIPE_GROUP},
{"wcis", WCIS},
{"switches", SWITCHES},
{(char *)0,0}
};

/*
 * lookup_reserved is called when an identifier is found (letter 
 * followed by letters, digits or _) to scan the above list of
 * keywords.  If a match is found, return the associated token
 * value, otherwise return 0.
 */
static int lookup_reserved(char *name) 
{
	int i = 0;
	while (res_words[i].name) {
		if (strcmp(name, res_words[i].name) == 0)
			return res_words[i].id;
		++i;
	}
	return 0;
}

/*
 * Called from yyparse if it finds an error.  s is a string
 * describing the type of error found.
 */
void yyerror(char *s)
{
	extern char yytext[1024];
	fprintf(stderr,"Error line %d: %s at \"%s\"\n", lineNumber,s, yytext);
	ErrorCount++;
}

int yywrap()
{
	return 1;
}

void
wrsm_lexx_reset()
{
	ErrorCount = 0;
	lineNumber = 1;
	lexdebug = 0;
}
