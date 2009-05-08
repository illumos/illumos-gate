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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include	<debug.h>
#include	"_debug.h"
#include	"msg.h"

/*
 * This file contains a number of simple title interfaces, that give a basic
 * trace of a link-edit.  These interfaces cross several functional boundaries,
 * but are consolidated here to ensure consistent use of the DBG_C_BASIC and
 * DBG_NOTTIME macros.
 */
void
Dbg_basic_collect(Lm_list *lml)
{
	if (DBG_NOTCLASS(DBG_C_BASIC) && DBG_NOTTIME())
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_BASIC_COLLECT));
	Dbg_util_nl(lml, DBG_NL_STD);
}

void
Dbg_basic_create(Lm_list *lml)
{
	if (DBG_NOTCLASS(DBG_C_BASIC) && DBG_NOTTIME())
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_BASIC_CREATE));
	Dbg_util_nl(lml, DBG_NL_STD);
}

void
Dbg_basic_files(Lm_list *lml)
{
	if (DBG_NOTCLASS(DBG_C_BASIC) && DBG_NOTTIME())
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_BASIC_FILES));
	Dbg_util_nl(lml, DBG_NL_STD);
}
void
Dbg_basic_finish(Lm_list *lml)
{
	if (DBG_NOTCLASS(DBG_C_BASIC) && DBG_NOTTIME())
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_BASIC_FINISHED));
	Dbg_util_nl(lml, DBG_NL_STD);
}

void
Dbg_basic_options(Lm_list *lml)
{
	if (DBG_NOTCLASS(DBG_C_BASIC) && DBG_NOTTIME())
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_BASIC_OPTIONS));
	Dbg_util_nl(lml, DBG_NL_STD);
}

void
Dbg_basic_relocate(Lm_list *lml)
{
	if (DBG_NOTCLASS(DBG_C_BASIC) && DBG_NOTTIME())
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_BASIC_RELOCATE));
	Dbg_util_nl(lml, DBG_NL_STD);
}

void
Dbg_basic_validate(Lm_list *lml)
{
	if (DBG_NOTCLASS(DBG_C_BASIC) && DBG_NOTTIME())
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_BASIC_VALIDATE));
	Dbg_util_nl(lml, DBG_NL_STD);
}
