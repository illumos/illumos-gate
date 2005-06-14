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
 * Copyright 1996 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <libelf.h>
#include <string.h>

#include "rdb.h"


typedef struct {
	char *	ht_key;		/* HELP keyword for topic */
	char *	ht_desc;	/* description of topic */
	void (*	ht_func)();	/* detailed info on topic */
} help_topics;


static void
break_help()
{
	printf("Break Help:\n"
		"\tbreak            - list breakpoints\n"
		"\tbreak <address>  - set break point at <address\n");
}

static void
delete_help()
{
	printf("Delete Help:\n"
		"\tdelete <address> - delete breakpoint at <address>\n");
}

static void
dis_help()
{
	printf("Disassemble Help:\n"
		"\tdis -\t\t\tdisassemble from current PC\n"
		"\tdis <address> [count] -\tdissasemble from address for\n"
		"\t\t\t\t<count> instructions\n");
}

static void
echo_help()
{
	printf("Echo Help:\n"
		"\tEcho '<quoted string>'\n"
		"\t\tthe echo command can be used to display output to\n"
		"\t\tthe main terminal.  This is useful when running\n"
		"\t\tcommand scripts and wanting to display status\n"
		"\n"
		"\t\tcurrently only <quoted strings> may be displayed\n");
}

static void
print_help()
{
	printf("Print Help:\n"
		"\tprint <address> [count [format]]\n"
		"\t\tcount  - number of units to print (default 4)\n"
		"\t\tformat - how to display data:\n"
		"\t\t\t\tX - Hex Words (default)\n"
		"\t\t\t\tb - unsigned hex bytes\n"
		"\t\t\t\ts - string\n"
		"\tprint <varname>\n"
		"\t\thelp varname for more info\n");
}


static void
step_help()
{
	printf("Step Help:\n");
	printf("\tstep -		step one instruction.\n");
	printf("\tstep count [silent] -	step count instructions\n");
	printf("\t\t\t\tif silent is specified to not disassemble\n"
		"\t\t\t\tinstr. durring stepping\n");
}

static void
value_help()
{
	printf("Value Help:\n"
		"\tvalue <symbol name> -\tdisplay the value associated with\n"
	"\t\t\t\tsymbol <symbol name>.\n");
}

static void
varname_help()
{
	printf("Variable Name Help:\n"
		"\tVariable names are in the form of $<name> and are used\n"
		"\tto access special information.  Possible varnames\n"
		"\tare:\n"
		"\t\tcommon:\n"
		"\t\t\t$regs - display all registers\n"
		"\t\tsparc:\n"
		"\t\t\t$ins -   display IN registers\n"
		"\t\t\t$globs - display GLOBAL registers\n"
		"\t\t\t$outs -  display OUT registers\n"
		"\t\t\t$locs -  display LOCAL registers\n"
		"\t\t\t$specs -  display SPECIAL registers\n"
		"\t\ti86pc:\n");
}


static const help_topics	htops[] = {
	{
		"break",
		"Set and display breakpoints",
		break_help
	},
	{
		"cont",
		"continue execution of process",
		0
	},
	{
		"delete",
		"delete breakpoints",
		delete_help
	},
	{
		"dis",
		"Help on the Disassemble Command",
		dis_help
	},
	{
		"echo",
		"Help on the Echo Command",
		echo_help
	},
	{
		"event",
		"event [on|off] to enable or disable event information",
		0
	},
	{
		"getmaps",
		"Read Link_Map structure from run-time linker",
		0
	},
	{
		"linkmaps",
		"Display link-map information",
		0
	},
	{
		"maps",
		"Display memory mapping information",
		0
	},
	{
		"objpad",
		"Set object padding for ld.so.1 mmap'ed objects",
		0
	},
	{
		"pltskip",
		"Enables and disables stepping through PLT's",
		0
	},
	{
		"print",
		"Display memory at <address>",
		print_help
	},
	{
		"step",
		"Help on the Step Command",
		step_help
	},
	{
		"value",
		"Help on the Value Command",
		value_help
	},
	{
		"varname",
		"Help on $variable values",
		varname_help
	},
	{
		"where",
		"Display stack trace",
		0
	},
	{
		0,
		0,
		0
	}
};

void
rdb_help(const char * topic) {
	int	i;
	if (topic) {
		for (i = 0; htops[i].ht_key; i++) {
			if (strcmp(htops[i].ht_key, topic) == 0) {
				if (htops[i].ht_func)
					htops[i].ht_func();
				else
					printf("no additional help available"
					    " for %s\n", htops[i].ht_key);
				return;
			}
		}
		printf("Help not available for topic: %s\n", topic);
	}
	printf("The following commands are available\n");
	for (i = 0; htops[i].ht_key; i++) {
		printf("\t%10s\t%s", htops[i].ht_key, htops[i].ht_desc);
		if (htops[i].ht_func)
			putchar('*');
		putchar('\n');
	}
	printf("\n(*) more help is available by typing 'help <topic>'\n\n");
}
