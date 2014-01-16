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
 * Copyright 1993 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.8	*/
/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "errno.h"
#include "string.h"
#include "stdlib.h"

#include "lp.h"
#include "access.h"

static int		chgaccess ( int , char ** , char * , char * , char * );
static char **		empty_list ( void );

/**
 ** deny_user_form() - DENY USER ACCESS TO FORM
 **/

int
deny_user_form(char **user_list, char *form)
{
	return (chgaccess(0, user_list, form, Lp_A_Forms, ""));
}

/**
 ** allow_user_form() - ALLOW USER ACCESS TO FORM
 **/

int
allow_user_form(char **user_list, char *form)
{
	return (chgaccess(1, user_list, form, Lp_A_Forms, ""));
}

/**
 ** deny_user_printer() - DENY USER ACCESS TO PRINTER
 **/

int
deny_user_printer(char **user_list, char *printer)
{
	return (chgaccess(0, user_list, printer, Lp_A_Printers, UACCESSPREFIX));
}

/**
 ** allow_user_printer() - ALLOW USER ACCESS TO PRINTER
 **/

int
allow_user_printer(char **user_list, char *printer)
{
	return (chgaccess(1, user_list, printer, Lp_A_Printers, UACCESSPREFIX));
}

/**
 ** deny_form_printer() - DENY FORM USE ON PRINTER
 **/

int
deny_form_printer(char **form_list, char *printer)
{
	return (chgaccess(0, form_list, printer, Lp_A_Printers, FACCESSPREFIX));
}

/**
 ** allow_form_printer() - ALLOW FORM USE ON PRINTER
 **/

int
allow_form_printer(char **form_list, char *printer)
{
	return (chgaccess(1, form_list, printer, Lp_A_Printers, FACCESSPREFIX));
}

/**
 ** remove_paper_from_printer() - DENY FORM USE ON PRINTER
 **/

int
remove_paper_from_printer(char **form_list, char *printer)
{
	return (chgaccess(0, form_list, printer, Lp_A_Printers, PACCESSPREFIX));
}

/**
 ** add_paper_to_printer() - ALLOW FORM USE ON PRINTER
 **/

int
add_paper_to_printer(char **form_list, char *printer)
{
	return (chgaccess(1, form_list, printer, Lp_A_Printers, PACCESSPREFIX));
}

/**
 ** chgaccess() - UPDATE ALLOW/DENY ACCESS OF ITEM TO RESOURCE
 **/

static int
chgaccess(int isallow, char **list, char *name, char *dir, char *prefix)
{
	register char		***padd_list,
				***prem_list,
				**pl;

	char			**allow_list,
				**deny_list;

	if (loadaccess(dir, name, prefix, &allow_list, &deny_list) == -1)
		return (-1);

	if (isallow) {
		padd_list = &allow_list;
		prem_list = &deny_list;
	} else {
		padd_list = &deny_list;
		prem_list = &allow_list;
	}

	for (pl = list; *pl; pl++) {

		/*
		 * Do the ``all'' and ``none'' cases explicitly,
		 * so that we can clean up the lists nicely.
		 */
		if (STREQU(*pl, NAME_NONE)) {
			isallow = !isallow;
			goto AllCase;
		}
		if (
			STREQU(*pl, NAME_ALL)
		     || STREQU(*pl, NAME_ANY)
		     || STREQU(*pl, ALL_BANG_ALL)
		) {
AllCase:
			freelist (allow_list);
			freelist (deny_list);
			if (isallow) {
				allow_list = 0;
				deny_list = empty_list();
			} else {
				allow_list = 0;
				deny_list = 0;
			}
			break;

		} else {

			/*
			 * For each regular item in the list,
			 * we add it to the ``add list'' and remove it
			 * from the ``remove list''. This is not
			 * efficient, especially if there are a lot of
			 * items in the caller's list; doing it the
			 * way we do, however, has the side effect
			 * of skipping duplicate names in the caller's
			 * list.
			 *
			 * Do a regular "addlist()"--the resulting
			 * list may have redundancies, but it will
			 * still be correct.
			 */
			if (addlist(padd_list, *pl) == -1)
				return (-1);
			if (bang_dellist(prem_list, *pl) == -1)
				return (-1);

		}

	}

	return (dumpaccess(dir, name, prefix, &allow_list, &deny_list));
}

/**
 ** empty_list() - CREATE AN EMPTY LIST
 **/

static char **
empty_list(void)
{
	register char		**empty;


	if (!(empty = (char **)Malloc(sizeof(char *)))) {
		errno = ENOMEM;
		return (0);
	}
	*empty = 0;
	return (empty);
}
