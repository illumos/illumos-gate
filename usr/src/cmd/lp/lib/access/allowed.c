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


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.7	*/
/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "string.h"
#include "unistd.h"

#include "lp.h"
#include "access.h"

/**
 ** is_user_admin() - CHECK IF CURRENT USER IS AN ADMINISTRATOR
 **/

int
#if	defined(__STDC__)
is_user_admin (
	void
)
#else
is_user_admin ()
#endif
{
	return (Access(Lp_A, W_OK) == -1? 0 : 1);
}

/**
 ** is_user_allowed() - CHECK USER ACCESS ACCORDING TO ALLOW/DENY LISTS
 **/

int
#if	defined(__STDC__)
is_user_allowed (
	char *			user,
	char **			allow,
	char **			deny
)
#else
is_user_allowed (user, allow, deny)
	char			*user,
				**allow,
				**deny;
#endif
{
	if (bangequ(user, LOCAL_LPUSER) || bangequ(user, LOCAL_ROOTUSER))
		return (1);

	return (allowed(user, allow, deny));
}

/**
 ** is_user_allowed_form() - CHECK USER ACCESS TO FORM
 **/

int
#if	defined(__STDC__)
is_user_allowed_form (
	char *			user,
	char *			form
)
#else
is_user_allowed_form (user, form)
	char			*user,
				*form;
#endif
{
	char			**allow,
				**deny;

	if (loadaccess(Lp_A_Forms, form, "", &allow, &deny) == -1)
		return (-1);

	return (is_user_allowed(user, allow, deny));
}

/**
 ** is_user_allowed_printer() - CHECK USER ACCESS TO PRINTER
 **/

int
#if	defined(__STDC__)
is_user_allowed_printer (
	char *			user,
	char *			printer
)
#else
is_user_allowed_printer (user, printer)
	char			*user,
				*printer;
#endif
{
	char			**allow,
				**deny;

	if (loadaccess(Lp_A_Printers, printer, UACCESSPREFIX, &allow, &deny) == -1)
		return (-1);

	return (is_user_allowed(user, allow, deny));
}

/**
 ** is_form_allowed_printer() - CHECK FORM USE ON PRINTER
 **/

int
#if	defined(__STDC__)
is_form_allowed_printer (
	char *			form,
	char *			printer
)
#else
is_form_allowed_printer (form, printer)
	char			*form,
				*printer;
#endif
{
	char			**allow,
				**deny;

	if (loadaccess(Lp_A_Printers, printer, FACCESSPREFIX, &allow, &deny) == -1)
		return (-1);

	return (allowed(form, allow, deny));
}

/**
 ** allowed() - GENERAL ROUTINE TO CHECK ALLOW/DENY LISTS
 **/

int
#if	defined(__STDC__)
allowed (
	char *			item,
	char **			allow,
	char **			deny
)
#else
allowed (item, allow, deny)
	char			*item,
				**allow,
				**deny;
#endif
{
	if (allow) {
		if (bang_searchlist(item, allow))
			return (1);
		else
			return (0);
	}

	if (deny) {
		if (bang_searchlist(item, deny))
			return (0);
		else
			return (1);
	}

	return (0);
}
