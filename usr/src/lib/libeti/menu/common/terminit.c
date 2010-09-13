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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1997, by Sun Mircrosystems, Inc.
 * All rights reserved.
 */

#pragma	ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.1	*/

/*LINTLIBRARY*/

#include <sys/types.h>
#include "private.h"

int
set_menu_init(MENU *m, PTF_void mi)
{
	if (m) {
		SMinit(m) = mi;
	} else {
		SMinit(Dfl_Menu) = mi;
	}
	return (E_OK);
}

PTF_void
menu_init(MENU *m)
{
	return (SMinit(m ? m : Dfl_Menu));
}

int
set_menu_term(MENU *m, PTF_void mt)
{
	if (m) {
		SMterm(m) = mt;
	} else {
		SMterm(Dfl_Menu) = mt;
	}
	return (E_OK);
}

PTF_void
menu_term(MENU *m)
{
	return (SMterm(m ? m : Dfl_Menu));
}

int
set_item_init(MENU *m, PTF_void ii)
{
	if (m) {
		SIinit(m) = ii;
	} else {
		SIinit(Dfl_Menu) = ii;
	}
	return (E_OK);
}

PTF_void
item_init(MENU *m)
{
	return (SIinit(m ? m : Dfl_Menu));
}

int
set_item_term(MENU *m, PTF_void it)
{
	if (m) {
		SIterm(m) = it;
	} else {
		SIterm(Dfl_Menu) = it;
	}
	return (E_OK);
}

PTF_void
item_term(MENU *m)
{
	return (SIterm(m ? m : Dfl_Menu));
}
