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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<dlfcn.h>
#include	<stdio.h>
#include	"_debug.h"
#include	"msg.h"
#include	"libld.h"

void
Dbg_audit_version(Lm_list *lml, const char *lib, ulong_t version)
{
	if (DBG_NOTCLASS(DBG_C_AUDITING))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_AUD_VERSION), lib, (int)version);
}

void
Dbg_audit_lib(Lm_list *lml, const char *lib)
{
	if (DBG_NOTCLASS(DBG_C_AUDITING))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_AUD_INIT), lib);
}

void
Dbg_audit_interface(Lm_list *lml, const char *lib, const char *interface)
{
	if (DBG_NOTCLASS(DBG_C_AUDITING))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_AUD_INTERFACE), lib, interface);
}

void
Dbg_audit_object(Lm_list *lml, const char *lib, const char *obj)
{
	if (DBG_NOTCLASS(DBG_C_AUDITING))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_AUD_OBJECT), lib, obj);
}

void
Dbg_audit_symval(Lm_list *lml, const char *lib, const char *func,
    const char *sym, Addr pval, Addr nval)
{
	char	mesg[100];

	if (DBG_NOTCLASS(DBG_C_AUDITING))
		return;
	if (DBG_NOTDETAIL())
		return;

	if (pval == nval)
		mesg[0] = '\0';
	else
		(void) sprintf(mesg, MSG_INTL(MSG_AUD_SYMNEW), EC_XWORD(nval));

	dbg_print(lml, MSG_INTL(MSG_AUD_SYM), lib, func, Dbg_demangle_name(sym),
	    EC_XWORD(pval), mesg);
}

void
Dbg_audit_skip(Lm_list *lml, const char *name, const char *lmid)
{
	if (DBG_NOTCLASS(DBG_C_AUDITING | DBG_C_FILES))
		return;

	dbg_print(lml, MSG_INTL(MSG_AUD_SKIP), name, lmid);
}

void
Dbg_audit_terminate(Lm_list *lml, const char *name)
{
	if (DBG_NOTCLASS(DBG_C_AUDITING | DBG_C_FILES))
		return;

	dbg_print(lml, MSG_INTL(MSG_AUD_TERM), name);
}

void
Dbg_audit_ignore(Rt_map *lmp)
{
	if (DBG_NOTCLASS(DBG_C_AUDITING | DBG_C_FILES))
		return;

	dbg_print(LIST(lmp), MSG_INTL(MSG_AUD_IGNORE), NAME(lmp));
}
