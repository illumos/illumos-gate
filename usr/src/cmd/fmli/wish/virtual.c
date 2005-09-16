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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<ctype.h>
#include	"wish.h"
#include	"token.h"
#include	"vtdefs.h"
#include	"actrec.h"
#include	"slk.h"
#include	"moremacros.h"
#include 	"message.h"

/*
 * Caution: MAX_ARGS is defined in several files and should ultimately reside
 * in wish.h 
 */
#define MAX_ARGS	25
extern char	*Args[MAX_ARGS];
extern int	Arg_count;
extern bool	Nobang;

static bool	Command_mode = FALSE;		/* abs k17 */
static token done_cmd(char *s, token t);

token
virtual_stream(t)
register token	t;
{
    char	*s;
    char	*tok_to_cmd();

    if ( t > 037 && t < 0177 )
	return t;

    Arg_count = 0;
    if (s = tok_to_cmd(t))
	t = cmd_to_tok(s);
    if (t == TOK_COMMAND)
    {
	/* single equals sign is correct, here */
	if (Command_mode = !Command_mode)
	{
	    char	*cur_cmd();

	    get_string(done_cmd, "--> ", cur_cmd(), 0, TRUE,
		       "$VMSYS/OBJECTS/Menu.h6.list", NULL);
	    t = TOK_NOP;
	}
	else
	    t = TOK_CANCEL;
    }
    else
    {
	if (t >= TOK_SLK1 && t <= TOK_SLK8)
	    t = slk_token(t);
    }
    return t;
}

static token
done_cmd(char *s, token t)
{
    char *strchr();

    if (t == TOK_CANCEL)
	t = TOK_NOP;
    else
    {
	int i;

	/* Remove all blanks in the beginning of the command line */

        while(*s && isspace(*s))
	    s++;
	if (s[0] == '!')	/* execute shell cmd from cmd line */
	    if (Nobang)		/* feature disabled by application developer */
	    {
		mess_temp("Command ignored: the ! prefix is disabled in this application");
		mess_lock();
		t = TOK_NOP;
	    }
	    else
	    {
		char	*tok_to_cmd();

		t = TOK_OPEN;
		for (i=0; i < 5; i++)
		    if (Args[i])
			free(Args[i]); /* les */

		Args[0] = strsave("OPEN");
		Args[1] = strsave("EXECUTABLE");
		Args[2] = strsave("${SHELL:-/bin/sh}");
		Args[3] = strsave("-c");
		Args[4] = strsave(&s[1]);
		Arg_count = 5;
	    }
	else
	{
	    set_Args(s);

	    /* changed if's to switch and added security clauses. abs k17 */

	    t = cmd_to_tok(Args[0]);
	    switch(t)
	    {
	        case TOK_NOP:
	        {
		    /* change to unknown_command which becomes a goto or
		    ** open (see global_stream() ) unless command was
		    ** entered from command line while Nobang is set;
		    ** in this case only change to unknown_command if
		    ** it will turn into a goto.  abs k17
		    */
		    if (!Nobang || (i = atoi(Args[0])) && wdw_to_ar(i) &&
			strspn(Args[0], "0123456789") == strlen(Args[0]))
			t = TOK_UNK_CMD;
		    else
		    {
			mess_temp("Command ignored: open is disabled in this application");
			mess_lock();
		    }
		    break;
		}
	        case TOK_NUNIQUE:
	        {
		    char msg[MESSIZ];

		    sprintf(msg, "Command '%s' not unique.  Type more of its name.", Args[0]);
		    mess_temp(msg);
		    t = TOK_NOP;
		    break;
		}
	        case TOK_RUN:	/* added clause.  abs k17 */
	        {
		    if (Nobang)
		    {
			mess_temp("Command ignored: run is disabled in this application");
			mess_lock();
			t = TOK_NOP;
		    }
		    break;
		}
	        case TOK_OPEN:	/* added clause.  abs k17 */
	        {
		    if (Nobang)
		    {
			mess_temp("Command ignored: open is disabled in this application");
			mess_lock();
			t = TOK_NOP;
		    }
		    break;
		}
	        default:
		{
		    if (t < 0)
			t = do_app_cmd(); /* Application defined command */
		    break;
		}
	    }
	}
    }
    Command_mode = FALSE; 
    return t;
}

int
set_Args(s)
char *s;
{

	for (Arg_count = 0; Arg_count < (MAX_ARGS - 1); Arg_count++) {
		while (*s && isspace(*s))
			s++;
		if (*s == '\0')
			break;

		if (Args[Arg_count] != NULL)
			free(Args[Arg_count]); /* les */

		Args[Arg_count] = s;

		while (*s && !isspace(*s))
			s++;
		if (*s != '\0')
			*s++ = '\0';
		Args[Arg_count] = strsave(Args[Arg_count]);
#ifdef _DEBUG
		_debug(stderr, "Args[%d] = '%s'\n", Arg_count, Args[Arg_count]);
#endif
	}

	if (Args[Arg_count] != NULL)
		free(Args[Arg_count]); /* les */

	Args[Arg_count] = NULL;
	return (0);
}
