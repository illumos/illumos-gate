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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright  (c) 1985 AT&T
 *	All Rights Reserved
 */
#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.13 */

#include <stdio.h>
#include "wish.h"
#include "token.h"
#include "slk.h"
#include "actrec.h"
#include "terror.h"
#include "ctl.h"
#include "menudefs.h"
#include "vtdefs.h"
#include "moremacros.h"

extern	menu_id menu_make();

#define NMUDGES	4

static struct menu_line	Mgmt_lines[NMUDGES] = {
	{ "list",	"list all frames",	0 },
	{ "move",	"move a frame",	0 },
	{ "reshape",	"reshape a frame",	0 },
	{ NULL,		NULL,			0 }
};

static struct menu_line
mgmt_disp(n, ptr)
int n;
char *ptr;
{ 
	if (n >= NMUDGES)
		n = NMUDGES - 1;
	return Mgmt_lines[n];
}

static int
mgmt_odsh(a, t)
struct actrec *a;
token t;
{
	int 	line;
	token	menu_stream();
	struct actrec *curar;

	t = menu_stream(t);
	if (t == TOK_ENTER || t == TOK_OPEN) {
		(void) menu_ctl(a->id, CTGETPOS, &line);
		curar = (struct actrec *)(a->odptr);
		switch (line) {
		case 0: /* list */
			list_create();
			break;
		case 1:	/* move */
			enter_wdw_mode(curar, FALSE);
			break;
		case 2: /* reshape */
			if (curar && (curar->flags & AR_NORESHAPE)) {
				mess_temp("Forms cannot be reshaped");
				t = TOK_NOP;
			}
			else 
				enter_wdw_mode(curar, TRUE);
			break;
		}
		t = TOK_NOP;
	} else if (t == TOK_CANCEL) {
		ar_backup();
		t = TOK_NOP;
	} else if (t == TOK_NEXT)
		t = TOK_NOP;		/* filter out, see menu_stream */
	return t;
}

static int
mgmt_help(a)
struct actrec *a;
{
	return(objop("OPEN", "TEXT", "$VMSYS/OBJECTS/Text.mfhelp", "frm-mgmt", "Frame Management", NULL));
}

int
mgmt_create()
{
	char	*cmd;
	int	len;
	struct	actrec a, *ar, *ar_create(), *window_arg();
	extern	int Arg_count;
	extern	char *Args[];

	switch (Arg_count) {
	case 0:
	case 1:
		/*
		 * no arguments to frm-mgmt
		 *
		 * assume the current frame and prompt the user for 
		 * the command
		 */
		cmd = NULL;
		ar = ar_get_current();
		break;
	case 2:
		/*
		 * One argument to frm-mgmt
		 *
		 * This case is ambiguous, since the argument could be
		 * either one of the three commands "move" "reshape" or "list"
		 * or it could be a window path or number.  So, assume it 
		 * is a window if it isn't a command.  (Hope nobody tries this
		 * on a window named "list")
		 */
		len = strlen(Args[1]);
		if (strnCcmp(Args[1], "move", len) == 0 ||
			strnCcmp(Args[1], "reshape", len) == 0 ||
			strnCcmp(Args[1], "list", len) == 0) {
			cmd = Args[1];
			ar = ar_get_current();
		}
		else {
			cmd = NULL;
			if ((ar = window_arg(1, Args + 1, 1)) == NULL) {
				mess_temp(nstrcat("Unknown command or frame \"",
					 Args[1], "\" ignored", NULL));
				return(FAIL);
			}
		}
		break;
	default:	
		/*
		 * Two arguments to frm-mgmt
		 *
		 * first arg is the command, the second is the frame
		 */
		len = strlen(Args[1]);
		if (strnCcmp(Args[1], "move", len) == 0 ||
		    strnCcmp(Args[1], "reshape", len) == 0) {
			cmd = Args[1];
			if ((ar = window_arg(1, Args + 2, 1)) == NULL) {
				mess_temp(nstrcat("Can't find frame \"",
					 Args[2], "\"", NULL));
				return(FAIL);
			}
		}
		else if (strnCcmp(Args[1], "list", len) == 0)  {
			cmd = Args[1];
			mess_temp("Arguments to \"list\" ignored");
		}
		else {
			mess_temp(nstrcat("Unknown command \"", Args[1],
				  "\" ignored", NULL));
			return(FAIL);
		}
	}

	if (cmd == NULL) {
		/*
		 * if the command (list, reshape, move ...) is not specified
		 * then display a menu of available (frame management) commands
		 */ 
		a.id = (int) menu_make(-1, "Frame Management",
			VT_NONUMBER | VT_CENTER, VT_UNDEFINED, VT_UNDEFINED,
			0, 0, mgmt_disp, NULL);
		if (a.id == FAIL)
			return(FAIL);
		ar_menu_init(&a);
		a.fcntbl[AR_ODSH] = mgmt_odsh;
		a.fcntbl[AR_HELP] = mgmt_help;
		a.odptr = (char *) ar;
		a.flags = 0;
		return(ar_current(ar_create(&a), FALSE) ==     /* abs k15 */
		       NULL? FAIL : SUCCESS);
	}
	else if (strncmp(cmd, "list", strlen(cmd)) == 0) {
		/*
		 * if the command is "list" then generate a menu that
		 * will list all active frames
		 */
		list_create();
	}
	else if (strncmp(cmd, "move", strlen(cmd)) == 0) {
		/*
		 * if the command is "move" then enter "move" mode ...
		 */ 
		enter_wdw_mode(ar, FALSE);
	}
	else if (strncmp(cmd, "reshape", strlen(cmd)) == 0) {
		/*
		 * if the command is "reshape" then make sure the
		 * frame can be reshaped before performing the operation
		 */
		if (ar && (ar->flags & AR_NORESHAPE)) 
			mess_temp("Forms cannot be reshaped");
		else
			enter_wdw_mode(ar, TRUE);	/* reshape it */
	}
	else {
		mess_temp("Bad argument to frmmgmt: try list, move or reshape");
		return(FAIL);
	}
	return(SUCCESS);
}
