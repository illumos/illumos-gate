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
 *	Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 *	Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<link.h>
#include	<stdio.h>
#include	"msg.h"
#include	"_debug.h"

#if	!defined(_ELF64)
void
Gelf_ver_def_title()
{
	dbg_print(MSG_ORIG(MSG_VER_DEF_2));
}

void
Gelf_ver_need_title()
{
	dbg_print(MSG_ORIG(MSG_VER_NEED_2));
}

void
Gelf_ver_line_1(const char * index, const char * name, const char * dep,
    const char * flags)
{
	if (DBG_NOTLONG())
		dbg_print(MSG_ORIG(MSG_VER_LINE_1), index, name, dep, flags);
	else
		dbg_print(MSG_ORIG(MSG_VER_L_LINE_1), index, name, dep, flags);
}

void
Gelf_ver_line_2(const char * name, const char * dep)
{
	dbg_print(MSG_ORIG(MSG_VER_LINE_2), name, dep);
}

void
Gelf_ver_line_3(const char * name, const char * dep, const char * flags)
{
	dbg_print(MSG_ORIG(MSG_VER_LINE_3), name, dep, flags);
}

void
Dbg_ver_avail_title(const char * file)
{
	if (DBG_NOTCLASS(DBG_VERSIONS))
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_VER_AVAIL_1), file);
	dbg_print(MSG_INTL(MSG_VER_AVAIL_2));
}

void
Dbg_ver_def_title(const char * file)
{
	if (DBG_NOTCLASS(DBG_VERSIONS))
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_VER_DEF_1), file);
	Gelf_ver_def_title();
}

void
Dbg_ver_need_title(const char * file)
{
	if (DBG_NOTCLASS(DBG_VERSIONS))
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_VER_NEED_1), file);
	Gelf_ver_need_title();
}

void
Dbg_ver_need_entry(Half cnt, const char * file, const char * version)
{
	if (DBG_NOTCLASS(DBG_VERSIONS))
		return;

	if (cnt == 0) {
		if (DBG_NOTLONG())
			dbg_print(MSG_ORIG(MSG_VER_LINE_5), file, version);
		else
			dbg_print(MSG_ORIG(MSG_VER_L_LINE_5), file, version);
	} else
		dbg_print(MSG_ORIG(MSG_VER_LINE_4), MSG_ORIG(MSG_STR_EMPTY),
		    version);
}

void
Dbg_ver_symbol(const char * name)
{
	static Boolean	ver_symbol_title = TRUE;

	if (DBG_NOTCLASS(DBG_VERSIONS | DBG_SYMBOLS))
		return;

	if (DBG_NOTCLASS(DBG_VERSIONS))
		if (ver_symbol_title) {
			ver_symbol_title = FALSE;
			dbg_print(MSG_ORIG(MSG_STR_EMPTY));
			dbg_print(MSG_INTL(MSG_SYM_VERSION));
		}

	Dbg_syms_created(name);
}

/*
 * This function doesn't test for any specific debugging category, thus it will
 * be generated for any debugging family.
 */
void
Dbg_ver_nointerface(const char * name)
{
	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_VER_NOINTERFACE), name);
	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
}

#endif	/* !defined(_ELF64) */

/*
 * Print a version descriptor.
 */
void
Dbg_ver_desc_entry(Ver_desc * vdp)
{
	const char *	dep;
	Ver_desc *	_vdp, * __vdp;
	Listnode *	lnp;
	char		index[10];

	if (DBG_NOTCLASS(DBG_VERSIONS))
		return;

	if (vdp->vd_deps.head) {
		_vdp = (Ver_desc *)vdp->vd_deps.head->data;
		dep = _vdp->vd_name;
	} else {
		_vdp = 0;
		dep = MSG_ORIG(MSG_STR_EMPTY);
	}
	(void) sprintf(index, MSG_ORIG(MSG_FMT_INDEX), vdp->vd_ndx);
	Gelf_ver_line_1(index, vdp->vd_name, dep,
	    conv_verflg_str(vdp->vd_flags));

	/*
	 * Loop through the dependency list in case there are more that one
	 * dependency.
	 */
	for (LIST_TRAVERSE(&vdp->vd_deps, lnp, __vdp)) {
		if (_vdp == __vdp)
			continue;
		dbg_print(MSG_ORIG(MSG_VER_LINE_4), MSG_ORIG(MSG_STR_EMPTY),
		    __vdp->vd_name);
	}
}

void
Dbg_ver_avail_entry(Ver_index * vip, const char * select)
{
	if (DBG_NOTCLASS(DBG_VERSIONS))
		return;

	if (select) {
		if (DBG_NOTLONG())
		    dbg_print(MSG_ORIG(MSG_VER_SELECTED), vip->vi_name, select);
		else
		    dbg_print(MSG_ORIG(MSG_VER_L_SELECTED),
		    vip->vi_name, select);
	} else {
		if (DBG_NOTLONG())
		    dbg_print(MSG_ORIG(MSG_VER_ALL), vip->vi_name);
		else
		    dbg_print(MSG_ORIG(MSG_VER_L_ALL), vip->vi_name);
	}
}
