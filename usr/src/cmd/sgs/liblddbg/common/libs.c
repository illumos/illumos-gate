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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#include	"msg.h"
#include	"_debug.h"
#include	"libld.h"

void
Dbg_libs_audit(Lm_list *lml, const char *opath, const char *npath)
{
	if (DBG_NOTCLASS(DBG_C_LIBS | DBG_C_AUDITING))
		return;

	if (npath == opath)
		return;
	else if (npath == 0)
		dbg_print(lml, MSG_INTL(MSG_LIB_SKIP), opath);
	else
		dbg_print(lml, MSG_INTL(MSG_LIB_ALTER), npath);
}

void
Dbg_libs_find(Lm_list *lml, const char *name)
{
	if (DBG_NOTCLASS(DBG_C_LIBS))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_LIB_FIND), name);
}

void
Dbg_libs_found(Lm_list *lml, const char *path, int alter)
{
	if (DBG_NOTCLASS(DBG_C_LIBS))
		return;

	dbg_print(lml, MSG_INTL(MSG_LIB_TRYING), path, alter ?
	    MSG_INTL(MSG_STR_ALTER) : MSG_ORIG(MSG_STR_EMPTY));
}

void
Dbg_libs_insecure(Lm_list *lml, const char *path, int usable)
{
	if (DBG_NOTCLASS(DBG_C_LIBS))
		return;

	if (usable)
		dbg_print(lml, MSG_INTL(MSG_LIB_INUSE), path);
	else
		dbg_print(lml, MSG_INTL(MSG_LIB_IGNORE), path);
}

static void
Dbg_lib_dir_print(Lm_list *lml, List *libdir)
{
	Listnode	*lnp;
	char		*cp;

	for (LIST_TRAVERSE(libdir, lnp, cp))
		dbg_print(lml, MSG_ORIG(MSG_LIB_FILE), cp);
}

void
Dbg_libs_init(Lm_list *lml, List *ulibdir, List *dlibdir)
{
	if (DBG_NOTCLASS(DBG_C_LIBS))
		return;

	dbg_print(lml, MSG_INTL(MSG_LIB_INITPATH));
	Dbg_lib_dir_print(lml, ulibdir);
	Dbg_lib_dir_print(lml, dlibdir);
}

void
Dbg_libs_l(Lm_list *lml, const char *name, const char *path)
{
	if (DBG_NOTCLASS(DBG_C_LIBS))
		return;
	if (DBG_NOTDETAIL())
		return;

	dbg_print(lml, MSG_INTL(MSG_LIB_LOPT), name, path);
}

void
Dbg_libs_path(Lm_list *lml, const char *path, uint_t orig, const char *obj)
{
	const char	*fmt;

	if (path == (const char *)0)
		return;
	if (DBG_NOTCLASS(DBG_C_LIBS))
		return;

	if (orig & LA_SER_LIBPATH) {
		if (orig & LA_SER_CONFIG)
			fmt = MSG_INTL(MSG_LIB_LDLIBPATHC);
		else
			fmt = MSG_INTL(MSG_LIB_LDLIBPATH);
	} else if (orig & LA_SER_RUNPATH) {
		fmt = MSG_INTL(MSG_LIB_RUNPATH);
	} else if (orig & LA_SER_DEFAULT) {
		if (orig & LA_SER_CONFIG)
			fmt = MSG_INTL(MSG_LIB_DEFAULTC);
		else
			fmt = MSG_INTL(MSG_LIB_DEFAULT);
	}
	dbg_print(lml, fmt, path, obj);
}

void
Dbg_libs_req(Lm_list *lml, const char *so_name, const char *ref_file,
    const char *name)
{
	if (DBG_NOTCLASS(DBG_C_LIBS))
		return;
	if (DBG_NOTDETAIL())
		return;

	dbg_print(lml, MSG_INTL(MSG_LIB_REQUIRED), so_name, name, ref_file);
}

void
Dbg_libs_update(Lm_list *lml, List *ulibdir, List *dlibdir)
{
	if (DBG_NOTCLASS(DBG_C_LIBS))
		return;

	dbg_print(lml, MSG_INTL(MSG_LIB_UPPATH));
	Dbg_lib_dir_print(lml, ulibdir);
	Dbg_lib_dir_print(lml, dlibdir);
}

void
Dbg_libs_yp(Lm_list *lml, const char *path)
{
	if (DBG_NOTCLASS(DBG_C_LIBS))
		return;

	dbg_print(lml, MSG_INTL(MSG_LIB_LIBPATH), path);
}

void
Dbg_libs_ylu(Lm_list *lml, const char *path, const char *orig, int index)
{
	if (DBG_NOTCLASS(DBG_C_LIBS))
		return;

	dbg_print(lml, MSG_INTL(MSG_LIB_YPATH), path, orig,
	    (index == YLDIR) ? 'L' : 'U');
}
