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
#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.8 */

#include	<stdio.h>
#include	<ctype.h>
#include	"wish.h"
#include	"token.h"
#include	"var_arrays.h"
#include	"moremacros.h"

/*
 * There should be ONE definition of MAX_ARGS in wish.h
 */
#define MAX_ARGS	25

/*
** Takes a list and turns it into an action.  If there is no action,
** the action is close.
*/
token
make_action(list)
register char	**list;
{
	extern char	*Args[];
	extern int	Arg_count;
	token           setaction();

	if (!list || !array_len(list) || !list[0] || !list[0][0])
		return(TOK_CLOSE);
	return(setaction(list));
}

/*
** Takes the list and sets Args to each member and returns the correct
** token.
*/
token
setaction(list)
char **list;
{
	extern char *Args[MAX_ARGS];
	extern int  Arg_count;
	int	lcv;

	if (!list || !array_len(list) || !list[0] || !list[0][0])
/*	if (!(list && array_len(list)))    above is safer.  abs */
		return(TOK_BADCHAR);
	if (strnCcmp(*list, "RETURN", 7) == 0) {
		if (isdigit(*list[1]))
			return(atoi(list[1]));
		return(mencmd_to_tok(list[1]));
	}
	lcv = array_len(list);
	for (Arg_count = 0; Arg_count < lcv && Arg_count < (MAX_ARGS - 1); Arg_count++) {
		if (Args[Arg_count])
			free(Args[Arg_count]); /* les */
		Args[Arg_count] = strsave(list[Arg_count]);
	}


	if (Args[Arg_count])
		free(Args[Arg_count]);	/* les */

	Args[Arg_count] = NULL;
	return(mencmd_to_tok(list[0]));
}

