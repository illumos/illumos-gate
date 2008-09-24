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

#include	<stdio.h>
#include	<debug.h>
#include	"msg.h"
#include	"_debug.h"

void
Dbg_ver_avail_title(Lm_list *lml, const char *file)
{
	if (DBG_NOTCLASS(DBG_C_VERSIONS))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_VER_AVAIL_1), file);
	dbg_print(lml, MSG_INTL(MSG_VER_AVAIL_2));
}

void
Dbg_ver_def_title(Lm_list *lml, const char *file)
{
	if (DBG_NOTCLASS(DBG_C_VERSIONS))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_VER_DEF_TITLE), file);
	Elf_ver_def_title(lml);
}

void
Dbg_ver_need_title(Lm_list *lml, const char *file)
{
	if (DBG_NOTCLASS(DBG_C_VERSIONS))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_VER_NEED_TITLE), file);
	Elf_ver_need_title(lml, 0);
}

void
Dbg_ver_need_entry(Lm_list *lml, Half cnt, const char *file,
    const char *version)
{
	if (DBG_NOTCLASS(DBG_C_VERSIONS))
		return;

	if (cnt)
		Elf_ver_line_4(lml, version);
	else
		Elf_ver_line_5(lml, file, version);
}

void
Dbg_ver_symbol(Lm_list *lml, const char *name)
{
	static Boolean	ver_symbol_title = TRUE;

	if (DBG_NOTCLASS(DBG_C_VERSIONS | DBG_C_SYMBOLS))
		return;

	if (DBG_NOTCLASS(DBG_C_VERSIONS))
		if (ver_symbol_title) {
			ver_symbol_title = FALSE;
			Dbg_util_nl(lml, DBG_NL_STD);
			dbg_print(lml, MSG_INTL(MSG_SYM_VERSION));
		}

	Dbg_syms_created(lml, name);
}

/*
 * This function doesn't test for any specific debugging category, thus it will
 * be generated for any debugging family.
 */
void
Dbg_ver_nointerface(Lm_list *lml, const char *name)
{
	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_VER_NOINTERFACE), name);
	Dbg_util_nl(lml, DBG_NL_STD);
}

void
Dbg_ver_desc_entry(Lm_list *lml, Ver_desc *vdp)
{
	Conv_ver_flags_buf_t	ver_flags_buf;
	const char		*dep;
	Ver_desc		*_vdp, *__vdp;
	Listnode 		*lnp;
	char			index[10];

	if (DBG_NOTCLASS(DBG_C_VERSIONS))
		return;

	if (vdp->vd_deps.head) {
		_vdp = (Ver_desc *)vdp->vd_deps.head->data;
		dep = _vdp->vd_name;
	} else {
		_vdp = 0;
		dep = MSG_ORIG(MSG_STR_EMPTY);
	}
	(void) sprintf(index, MSG_ORIG(MSG_FMT_INDEX), vdp->vd_ndx);
	Elf_ver_line_1(lml, index, vdp->vd_name, dep,
	    conv_ver_flags(vdp->vd_flags, 0, &ver_flags_buf));

	/*
	 * Loop through the dependency list in case there are more that one
	 * dependency.
	 */
	for (LIST_TRAVERSE(&vdp->vd_deps, lnp, __vdp)) {
		if (_vdp == __vdp)
			continue;
		Elf_ver_line_4(lml, __vdp->vd_name);
	}
}

void
Dbg_ver_avail_entry(Lm_list *lml, Ver_index *vip, const char *select)
{
	if (DBG_NOTCLASS(DBG_C_VERSIONS))
		return;

	if (select) {
		if (DBG_NOTLONG())
			dbg_print(lml, MSG_ORIG(MSG_VER_SELECTED),
			    vip->vi_name, select);
		else
			dbg_print(lml, MSG_ORIG(MSG_VER_L_SELECTED),
			    vip->vi_name, select);
	} else {
		if (DBG_NOTLONG())
			dbg_print(lml, MSG_ORIG(MSG_VER_ALL), vip->vi_name);
		else
			dbg_print(lml, MSG_ORIG(MSG_VER_L_ALL), vip->vi_name);
	}
}

void
Elf_ver_def_title(Lm_list *lml)
{
	dbg_print(lml, MSG_INTL(MSG_VER_DEF));
}

/*
 * entry:
 *	gnuver - If True (non-zero), the version rules used by the
 *		GNU ld are assumed. If False (0), Solaris ld rules apply.
 */
void
Elf_ver_need_title(Lm_list *lml, int gnuver)
{
	if (gnuver)
		dbg_print(lml, MSG_INTL(MSG_VER_NEED_GNUVER));
	else
		dbg_print(lml, MSG_INTL(MSG_VER_NEED));
}

void
Elf_ver_line_1(Lm_list *lml, const char *index, const char *name,
    const char *dep, const char *flags)
{
	if (DBG_NOTLONG())
		dbg_print(lml, MSG_INTL(MSG_VER_LINE_1), index, name,
		    dep, flags);
	else
		dbg_print(lml, MSG_INTL(MSG_VER_LLINE_1), index, name,
		    dep, flags);
}

void
Elf_ver_line_2(Lm_list *lml, const char *name, const char *dep)
{
	dbg_print(lml, MSG_INTL(MSG_VER_LINE_2), name, dep);
}

void
Elf_ver_line_3(Lm_list *lml, const char *name, const char *dep,
    const char *flags)
{
	dbg_print(lml, MSG_INTL(MSG_VER_LINE_3), name, dep, flags);
}

void
Elf_ver_line_4(Lm_list *lml, const char *version)
{
	dbg_print(lml, MSG_INTL(MSG_VER_LINE_4), version);
}

void
Elf_ver_line_5(Lm_list *lml, const char *file, const char *version)
{
	if (DBG_NOTLONG())
		dbg_print(lml, MSG_INTL(MSG_VER_LINE_5), file, version);
	else
		dbg_print(lml, MSG_INTL(MSG_VER_LLINE_5), file, version);
}
