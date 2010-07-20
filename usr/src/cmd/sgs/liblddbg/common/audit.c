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
 * Copyright (c) 1995, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include	<dlfcn.h>
#include	<stdio.h>
#include	"_debug.h"
#include	"msg.h"
#include	"libld.h"

void
Dbg_audit_lib(Rt_map *clmp, const char *lib, int type)
{
	Lm_list		*clml = LIST(clmp);
	const char	*str;

	if (DBG_NOTCLASS(DBG_C_AUDITING))
		return;

	Dbg_util_nl(clml, DBG_NL_STD);
	switch (type) {
	case DBG_AUD_PRELOAD:
		str = MSG_ORIG(MSG_AUD_PRELOAD);
		break;
	case DBG_AUD_GLOBAL:
		str = MSG_ORIG(MSG_AUD_GLOBAL);
		break;
	case DBG_AUD_LOCAL:
		/* FALLTHROUGH */
	default:
		str = MSG_ORIG(MSG_STR_EMPTY);
	}

	dbg_print(clml, MSG_INTL(MSG_AUD_LIB), lib, NAME(clmp), str);
}

void
Dbg_audit_interface(Lm_list *lml, const char *lib, const char *interface)
{
	if (DBG_NOTCLASS(DBG_C_AUDITING))
		return;

	dbg_print(lml, MSG_INTL(MSG_AUD_INTERFACE), lib, interface);
}

void
Dbg_audit_version(Lm_list *lml, const char *lib, uint_t overs, uint_t nvers)
{
	if (DBG_NOTCLASS(DBG_C_AUDITING))
		return;

	dbg_print(lml, MSG_INTL(MSG_AUD_VERSION), lib, overs, nvers);
}

void
Dbg_audit_activity(Lm_list *lml, const char *lib, const char *obj, uint_t flags)
{
	Conv_inv_buf_t	inv_buf;

	if (DBG_NOTCLASS(DBG_C_AUDITING))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_AUD_ACTIVITY), lib, obj,
	    conv_la_activity(flags, CONV_FMT_ALT_DEFAULT, &inv_buf));
}

void
Dbg_audit_preinit(Lm_list *lml, const char *lib, const char *obj)
{
	if (DBG_NOTCLASS(DBG_C_AUDITING))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_AUD_PREINIT), lib, obj);
}

void
Dbg_audit_objsearch(Lm_list *lml, int call, const char *lib,
    const char *oobj, uint_t flags, const char *nobj)
{
	Conv_la_search_buf_t	la_search_buf;

	if (DBG_NOTCLASS(DBG_C_AUDITING))
		return;

	if (call == DBG_AUD_CALL) {
		Dbg_util_nl(lml, DBG_NL_STD);
		dbg_print(lml, MSG_INTL(MSG_AUD_OBJSEARCH), lib, oobj,
		    conv_la_search(flags, &la_search_buf));
	} else {
		if (nobj)
			dbg_print(lml, MSG_INTL(MSG_AUD_OBJSEARCH_R), lib,
			    oobj, nobj);
		else
			dbg_print(lml, MSG_INTL(MSG_AUD_OBJSEARCH_S), lib,
			    oobj);
	}
}

void
Dbg_audit_objfilter(Lm_list *lml, int call, const char *lib,
    const char *filter, const char *filtee, const char *ref)
{
	if (DBG_NOTCLASS(DBG_C_AUDITING))
		return;

	if (call == DBG_AUD_CALL) {
		Dbg_util_nl(lml, DBG_NL_STD);
		dbg_print(lml, MSG_INTL(MSG_AUD_OBJFILTER), lib, filter,
		    filtee, ref);
	} else
		dbg_print(lml, MSG_INTL(MSG_AUD_OBJFILTER_R), lib, filter);
}

void
Dbg_audit_objopen(Lm_list *lml, int call, const char *lib, const char *obj,
    uint_t flags, Boolean ignore)
{
	Conv_la_bind_buf_t	la_bind_buf;

	if (DBG_NOTCLASS(DBG_C_AUDITING))
		return;

	if (call == DBG_AUD_CALL) {
		Dbg_util_nl(lml, DBG_NL_STD);
		dbg_print(lml, MSG_INTL(MSG_AUD_OBJOPEN), lib, obj);
	} else {
		if (ignore)
			dbg_print(lml, MSG_INTL(MSG_AUD_OBJOPEN_RI), lib, obj,
			    conv_la_bind(flags, &la_bind_buf));
		else
			dbg_print(lml, MSG_INTL(MSG_AUD_OBJOPEN_R), lib, obj,
			    conv_la_bind(flags, &la_bind_buf));
	}
}

void
Dbg_audit_objclose(Lm_list *lml, const char *lib, const char *obj)
{
	if (DBG_NOTCLASS(DBG_C_AUDITING))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_AUD_OBJCLOSE), lib, obj);
}

void
Dbg_audit_symbind(Lm_list *lml, int call, const char *lib, const char *name,
    Addr value, uint_t flags)
{
	Conv_la_symbind_buf_t	la_symbind_buf;

	if (DBG_NOTCLASS(DBG_C_AUDITING))
		return;

	if (call == DBG_AUD_CALL) {
		Dbg_util_nl(lml, DBG_NL_STD);
		dbg_print(lml, MSG_INTL(MSG_AUD_SYMBIND), lib, name,
		    EC_XWORD(value), conv_la_symbind(flags, &la_symbind_buf));
	} else {
		dbg_print(lml, MSG_INTL(MSG_AUD_SYMBIND_R), lib, name,
		    EC_XWORD(value), conv_la_symbind(flags, &la_symbind_buf));
	}
}

void
Dbg_audit_pltenter(Lm_list *lml, int call, const char *lib, const char *name,
    Addr value)
{
	if (DBG_NOTCLASS(DBG_C_AUDITING))
		return;

	if (call == DBG_AUD_CALL) {
		Dbg_util_nl(lml, DBG_NL_STD);
		dbg_print(lml, MSG_INTL(MSG_AUD_PLTENTER), lib, name,
		    EC_XWORD(value));
	} else {
		dbg_print(lml, MSG_INTL(MSG_AUD_PLTENTER_R), lib, name,
		    EC_XWORD(value));
	}
}

void
Dbg_audit_pltexit(Lm_list *lml, const char *lib, const char *name)
{
	if (DBG_NOTCLASS(DBG_C_AUDITING))
		return;

	dbg_print(lml, MSG_INTL(MSG_AUD_PLTEXIT), lib, name);
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
	if (DBG_NOTCLASS(DBG_C_FILES))
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
