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

%{
#pragma ident	"%Z%%M%	%I%	%E% SMI"
%}

%{

#include <stdlib.h>
#include <sys/types.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include "parsertypes.h"
#include "utils.h"
#include "filebench.h"

#include "parser_gram.h"

int lex_lineno = 1;		/* line-number for error reporting */
extern void yyerror(char *s);
extern int dofile;			/* are we processing a file? */
%}

%s WHITESTRINGSTATE

%a 50000
%p 50000
%o 50000
%n 5000

%%

\n			{ lex_lineno++; }

<INITIAL>[ \t]+			;

<INITIAL>#.*			;

eventgen                { return FSC_EVENTGEN; }
create                  { return FSC_CREATE; }
define			{ return FSC_DEFINE; }
debug                   { return FSC_DEBUG; }
echo                    { return FSC_ECHO; }
exit		        { return FSC_QUIT; }
foreach                 { return FSC_FOREACH; }
flowop		        { return FSC_FLOWOP; }
help		        { return FSC_HELP; }
list		        { return FSC_LIST; }
load                    { return FSC_LOAD; }
log		        { return FSC_LOG; }
run                     { return FSC_RUN; }
set                     { return FSC_SET; }
shutdown                { return FSC_SHUTDOWN; }
sleep                   { return FSC_SLEEP; }
stats                   { return FSC_STATS; }
system                  { return FSC_SYSTEM; }
usage                   { return FSC_USAGE; }
vars                    { return FSC_VARS; }
quit		        { return FSC_QUIT; }

file[s]*       	        { return FSE_FILE; }
fileset[s]*             { return FSE_FILESET; }
directory               { return FSE_DIRECTORY; }
command                 { return FSE_COMMAND; }
process[es]*	        { return FSE_PROC; }
thread		        { return FSE_THREAD; }
clear                   { return FSE_CLEAR; }
snap                    { return FSE_SNAP; }
dump                    { return FSE_DUMP; }
xmldump                 { return FSE_XMLDUMP; }
all                     { return FSE_ALL; }
mode                    { return FSE_MODE; }

cached                  { return FSA_CACHED; }
dirwidth                { return FSA_DIRWIDTH; }
dirgamma                { return FSA_DIRGAMMA; }
namelength              { return FSA_NAMELENGTH; }
filesize                { return FSA_FILESIZE; }
filesizegamma           { return FSA_FILESIZEGAMMA; }
directio                { return FSA_DIRECTIO; }
dsync                   { return FSA_DSYNC;  }
fd                      { return FSA_FD; }
srcfd                   { return FSA_SRCFD; }
opennext                { return FSA_ROTATEFD; }
filename                { return FSA_FILE; }
filesetname             { return FSA_FILE; }
instances               { return FSA_INSTANCES;}                  
iosize                  { return FSA_IOSIZE; }
iters                   { return FSA_ITERS;}
memsize                 { return FSA_MEMSIZE; }
name                    { return FSA_NAME;}
nice                    { return FSA_NICE;}
entries                 { return FSA_ENTRIES;}
prealloc                { return FSA_PREALLOC; }
paralloc                { return FSA_PARALLOC; }
reuse                   { return FSA_REUSE; }
path                    { return FSA_PATH; }
procname                { return FSA_PROCESS; }
random                  { return FSA_RANDOM;}
rate                    { return FSA_RATE;}
size                    { return FSA_SIZE; }
target                  { return FSA_TARGET;}
useism                  { return FSA_USEISM;}
value                   { return FSA_VALUE;}
workingset              { return FSA_WSS; }
blocking                { return FSA_BLOCKING; }
highwater               { return FSA_HIGHWATER; }
alldone                 { return FSA_ALLDONE; }
firstdone               { return FSA_FIRSTDONE; }
timeout                 { return FSA_TIMEOUT; }

<INITIAL>\"			{ 
                                BEGIN WHITESTRINGSTATE;
                                return FSK_QUOTE;
                        }

<WHITESTRINGSTATE>\"    {
                                BEGIN INITIAL;
                                return FSK_QUOTE;
                        }

<WHITESTRINGSTATE>[^$^\\^"][^$^"]*[^\\^$^"] {
				if ((yylval.sval = strdup(yytext)) == NULL) {
					yyerror("Out of memory");
					filebench_shutdown(E_ERROR);
				}
 				return FSV_WHITESTRING;
	       	}

<WHITESTRINGSTATE>\\n	{
				yylval.sval = "\n";
 				return FSV_WHITESTRING;
	       	}


<WHITESTRINGSTATE>\\$[^"^$^\\]+	{
				if ((yylval.sval = strdup(yytext + 1)) == NULL) {
					yyerror("Out of memory");
					filebench_shutdown(E_ERROR);
				}
 				return FSV_WHITESTRING;
	       	}

<WHITESTRINGSTATE>[^$^\\^"] {
				if ((yylval.sval = strdup(yytext)) == NULL) {
					yyerror("Out of memory");
					filebench_shutdown(E_ERROR);
				}
 				return FSV_WHITESTRING;
	       	}


<INITIAL>\{			{ return FSK_OPENLST; }
<INITIAL>\}			{ return FSK_CLOSELST; }
<INITIAL>=			{ return FSK_ASSIGN; }
<INITIAL>\,			{ return FSK_SEPLST; }
<INITIAL>in                     { return FSK_IN; }

<INITIAL>[0-9]+	{
                                errno = 0;
				yylval.ival = strtoll(yytext, NULL, 10);
				if (errno == EINVAL || errno == ERANGE) {
                                        (void) filebench_log(LOG_ERROR, 
						"Invalid I value '%s':%s", yytext,
						strerror(errno));
				}
                                return FSV_VAL_INT;
}

<INITIAL>[0-9]+k	{
                                errno = 0;
				yylval.ival = KB * strtoll(yytext, NULL, 10);
				if (errno == EINVAL || errno == ERANGE) {
                                        (void) filebench_log(LOG_ERROR, 
						"Invalid I value '%s':%s", yytext,
						strerror(errno));
				}
                                return FSV_VAL_INT;
}

<INITIAL>[0-9]+m	{
                                errno = 0;
				yylval.ival = MB * strtoll(yytext, NULL, 10);
				if (errno == EINVAL || errno == ERANGE) {
                                        (void) filebench_log(LOG_ERROR, 
						"Invalid I value '%s':%s", yytext,
						strerror(errno));
				}
                                return FSV_VAL_INT;
}

<INITIAL>[0-9]+g	{
                                errno = 0;
				yylval.ival = GB * strtoll(yytext, NULL, 10);
				if (errno == EINVAL || errno == ERANGE) {
                                        (void) filebench_log(LOG_ERROR, 
						"Invalid I value '%s':%s", yytext,
						strerror(errno));
				}
                                return FSV_VAL_INT;
}

<INITIAL>true|false	{
				if (strcmp(yytext, "true") == 0)
					yylval.bval = 1;
				else
					yylval.bval = 0;
				return FSV_VAL_BOOLEAN;
		}



$[({A-Za-z][A-Za-z0-9._]*[A-Za-z0-9][)}]*	{
				if ((yylval.sval = strdup(yytext)) == NULL) {
					yyerror("Out of memory");
					filebench_shutdown(E_ERROR);
				}
 				return FSV_VARIABLE;
			}

<INITIAL>[/A-Za-z-][/A-Za-z0-9._-]*	{
				if ((yylval.sval = strdup(yytext)) == NULL) {
					yyerror("Out of memory");
					filebench_shutdown(E_ERROR);
				}
 				return FSV_STRING;
			}

.			{
				yyerror("Illegal character");
			}

%%

void
yyerror(char *s)
{
	if (dofile == FS_TRUE) {
		if (yytext[0] == '\0') {
			filebench_log(LOG_ERROR, 
				      "%s, token expected",
				      s);
			return;
		}
		(void) filebench_log(LOG_ERROR, 
				     "%s at '%s'", 
				     s,
				     yytext);
	} else {
		if (yytext[0] == '\0') {
			(void) filebench_log(LOG_ERROR, 
					     "%s, token expected", s);
			return;
		}
		(void) filebench_log(LOG_ERROR, "%s at '%s'", s, yytext);
	}
}

struct yy_buffer_state *parent;
struct yy_buffer_state *script;

int
yy_switchfileparent(FILE *file)
{
	script = YY_CURRENT_BUFFER;
	parent = (struct yy_buffer_state *)yy_create_buffer(yyin, 128);
	yy_switch_to_buffer(parent);
	return (0);
}

int
yy_switchfilescript(FILE *file)
{
	yy_switch_to_buffer(script);
	return (0);
}

