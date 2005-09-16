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

/*	Copyright (c) 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include "wish.h"
#include "token.h"
#include "slk.h"
#include "actrec.h"
#include "terror.h"
#include "ctl.h"
#include "menudefs.h"
#include "vtdefs.h"
#include "sizes.h"

extern char *Args[];
extern int Arg_count;
static int eqwaste(char *str);

int
glob_create()
{
    char *errstr;
    static char *argv[3];
    extern char *Filecabinet;
    char *path_to_full(), *bsd_path_to_title(), *cur_path();

    argv[0] = argv[1] = argv[2] = NULL;
    if (parse_n_in_fold(&argv[1], &argv[0]) == FAIL)
	return(TOK_CREATE);
    if (eqwaste(argv[0]))
	return(FAIL);
    if (isfolder(argv[0]) == FALSE) {
	mess_temp("You can only create new objects inside File folders");
	return(FAIL);
    }
    if (access(argv[0], 02) < 0) {
	mess_temp(nstrcat("You don't have permission to create objects in ",
	    bsd_path_to_title(argv[0], MESS_COLS-47), NULL));
	return(FAIL);
    }
    if (argv[1] == NULL) {
	enter_getname("create", "", argv);
	return(TOK_NOP);
    }
    if (namecheck(argv[0], argv[1], NULL, &errstr, TRUE) == FALSE) {
	mess_temp(errstr);
	argv[1] = NULL;
	enter_getname("create", "", argv);
	return(TOK_NOP);
    }
    Create_create(argv);
    return(TOK_NOP);
}

int
Create_create(argv)
char *argv[];
{
	char *bsd_path_to_title();
	char *path;

	working(TRUE);
	path = bsd_path_to_title(argv[1], (COLS-30)/2);
	return(objop("OPEN", "MENU", "$VMSYS/OBJECTS/Menu.create",
	    argv[0], argv[1], path,
	    bsd_path_to_title(argv[0], COLS - strlen(path)), NULL));
}

static int
eqwaste(char *str)
{
	extern char *Wastebasket;

	if (strncmp(str, Wastebasket, strlen(Wastebasket)) == 0) {
		mess_temp("You cannot create objects in your WASTEBASKET");
		return(1);
	}
	return(0);
}
