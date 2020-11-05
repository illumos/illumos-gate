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
 * Copyright (c) 1995, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <sys/types.h>
#include <libelf.h>
#include "rdb.h"

extern	void	rdb_prompt();

%}

%token	VALUE STEP HELP NUMBER NEWLINE SYMBOL PLUS BREAK CONT DIS GETMAPS
%token	DELETE MAPS PLTSKIP WHERE PRINT OBJPAD QSTRING VARSTRING ECHO_OUT
%token	EVENT LINKMAPS

%union {
	char	*str;
	ulong_t	addr;
	int	num;
}

%type <addr> NUMBER address 
%type <str> SYMBOL QSTRING VARSTRING

%left PLUS

%%
start: commands
	;

commands: /* empty */
	| commands command
	;
command: BREAK NEWLINE
	{
		list_breakpoints(&proch);
		rdb_prompt();
	}
	| BREAK address NEWLINE
	{
		if (set_breakpoint(&proch, $2, FLG_BP_USERDEF) == RET_OK)
			(void) printf("break point set at: 0x%lx\n",
			    (unsigned long)$2);
		else
			(void) printf("unable to set breakpoint.\n");
		rdb_prompt();
	}
	| CONT NEWLINE
	{
		(void) continue_to_break(&proch);
		rdb_prompt();
	}
	| DELETE address NEWLINE
	{
		if (delete_breakpoint(&proch, $2, FLG_BP_USERDEF) != RET_OK)
			(void) printf("unable to delete breakpoint at %#lx\n",
			    (unsigned long)$2);
		else
			(void) printf("breakpoint deleted at 0x%lx\n",
			    (unsigned long)$2);

		rdb_prompt();
	}
	| DIS NEWLINE
	{
		disasm(&proch, 10);
		rdb_prompt();
	}
	| DIS address NEWLINE
	{
		(void) disasm_addr(&proch, (ulong_t)$2, 10);
		rdb_prompt();
	}
	| DIS address NUMBER NEWLINE
	{
		(void) disasm_addr(&proch, (ulong_t)$2, (int)$3);
		rdb_prompt();
	}
	| ECHO_OUT QSTRING NEWLINE
	{
		(void) puts($2);
		free($2);
		rdb_prompt();
	}
	| EVENT SYMBOL NEWLINE
	{
		if (strcmp($2, "on") == 0) {
			(void) printf("rdb: event information enabled.\n");
			rdb_flags |= RDB_FL_EVENTS;
		} else if (strcmp($2, "off") == 0) {
			(void) printf("rdb: event information disabled.\n");
			rdb_flags &= ~RDB_FL_EVENTS;
		} else {
			(void) printf("rdb: unknown event command: %s\n", $2);
		}
		free($2);
		rdb_prompt();
	}
	| GETMAPS NEWLINE
	{
		if (get_linkmaps(&proch) != RET_OK)
			(void) printf("get_linkmaps failed\n");

		rdb_prompt();
	}
	| LINKMAPS NEWLINE
	{
		if (display_linkmaps(&proch) != RET_OK)
			(void) printf("display_linkmaps failed\n");
		rdb_prompt();
	}
	| MAPS NEWLINE
	{
		if (display_maps(&proch) != RET_OK)
			(void) printf("display_maps failed\n");
		rdb_prompt();
	}
	| STEP NEWLINE
	{
		sn_flags_e	sf;

		(void) printf("single step\n");
		sf = FLG_SN_VERBOSE;
		if (proch.pp_flags & FLG_PP_PLTSKIP)
			sf |= FLG_SN_PLTSKIP;

		(void) step_n(&proch, 1, sf);
		rdb_prompt();
	}
	| STEP NUMBER NEWLINE
	{
		sn_flags_e	sf;

		(void) printf("stepping %d\n", (int)$2);
		sf = FLG_SN_VERBOSE;
		if (proch.pp_flags & FLG_PP_PLTSKIP)
			sf |= FLG_SN_PLTSKIP;

		(void) step_n(&proch, $2, sf);
		rdb_prompt();
	}
	| STEP NUMBER SYMBOL NEWLINE
	{
		sn_flags_e	sf;

		sf = FLG_SN_VERBOSE;
		if (proch.pp_flags & FLG_PP_PLTSKIP)
			sf |= FLG_SN_PLTSKIP;

		if (strcmp("silent", $3) == 0)
			(void) step_n(&proch, $2, sf);
		else
			(void) printf("error: step <count> [silent]\n");

		free($3);
		rdb_prompt();
	}
	| HELP NEWLINE
	{
		rdb_help(0);
		rdb_prompt();
	}
	| HELP SYMBOL NEWLINE
	{
		rdb_help($2);
		free($2);
		rdb_prompt();
	}
	| OBJPAD NUMBER NEWLINE
	{
		(void) printf("setting object padding to: %#lx\n", $2);
		(void) set_objpad(&proch, $2);
		rdb_prompt();
	}
	| PLTSKIP NEWLINE
	{
		if (proch.pp_flags & FLG_PP_PLTSKIP) {
			proch.pp_flags &= ~ FLG_PP_PLTSKIP;
			(void) printf("plt skipping disabled\n");
		} else {
			proch.pp_flags |= FLG_PP_PLTSKIP;
			(void) printf("plt skipping enabled\n");
		}

		rdb_prompt();
	}
	| PRINT VARSTRING NEWLINE
	{
		print_varstring(&proch, $2);
		free($2);
		rdb_prompt();
	}
	| PRINT address NEWLINE
	{
		print_mem(&proch, $2, 4, "X");
		rdb_prompt();
	}
	| PRINT address NUMBER NEWLINE
	{
		print_mem(&proch, $2, (int)$3, "X");
		rdb_prompt();
	}
	| PRINT address NUMBER SYMBOL NEWLINE
	{
		print_mem(&proch, $2, (int)$3, $4);
		rdb_prompt();
	}
	| VALUE address NEWLINE
	{
		(void) printf("value: %#lx\n", (unsigned long)$2);
		rdb_prompt();
	}
	| WHERE NEWLINE
	{
		(void) printf("printing stack trace\n");
		CallStack(&proch);
		rdb_prompt();
	}
	| error NEWLINE
	{
		yyerrok;
		rdb_prompt();
	}
	| NEWLINE
	{
		disasm(&proch, 1);
		rdb_prompt();
	}
	;

address: address PLUS address
	{
		$$ = $1 + $3;
	}
	| SYMBOL
	{
		GElf_Sym	sym;
		if (str_to_sym(&proch, $1, &sym) == RET_OK)
			$$ = (ulong_t)sym.st_value;
		else {
			(void) printf("unknown symbol: %s\n", $1);
			$$ = 0;
		}
		free($1);
	}
	| NUMBER
	{
		$$ = $1;
	}
	;
%%

void
rdb_prompt()
{
	if (proch.pp_flags & FLG_PP_PROMPT) {
		(void) fputs("<rdb> ", stdout);
		(void) fflush(stdout);
	}
}
