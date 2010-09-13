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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include	"msg.h"
#include	"_debug.h"
#include	"libld.h"

void
Dbg_dl_iphdr_enter(Rt_map *clmp, u_longlong_t cnt_map, u_longlong_t cnt_unmap)
{
	Lm_list	*lml = LIST(clmp);

	if (DBG_NOTCLASS(DBG_C_DL))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_DL_IPHDR_ENTER), NAME(clmp));
	dbg_print(lml, MSG_INTL(MSG_DL_IPHDR_MAPCNT), cnt_map, cnt_unmap);
}

void
Dbg_dl_iphdr_callback(Lm_list *lml, struct dl_phdr_info *info)
{
	if (DBG_NOTCLASS(DBG_C_DL))
		return;

	dbg_print(lml, MSG_INTL(MSG_DL_IPHDR_CALLBACK));
	dbg_print(lml, MSG_INTL(MSG_DL_IPHDR_NAME), info->dlpi_name);
	dbg_print(lml, MSG_INTL(MSG_DL_IPHDR_ADDR), EC_ADDR(info->dlpi_addr));
	dbg_print(lml, MSG_INTL(MSG_DL_IPHDR_PHDR),
	    EC_ADDR(CAST_PTRINT(Addr, info->dlpi_phdr)),
	    EC_WORD(info->dlpi_phnum));
}

void
Dbg_dl_iphdr_mapchange(Lm_list *lml, u_longlong_t cnt_map,
    u_longlong_t cnt_unmap)
{
	if (DBG_NOTCLASS(DBG_C_DL))
		return;

	dbg_print(lml, MSG_INTL(MSG_DL_IPHDR_MAPCNG));
	dbg_print(lml, MSG_INTL(MSG_DL_IPHDR_MAPCNT), cnt_map, cnt_unmap);
}

void
Dbg_dl_iphdr_unmap_ret(Lm_list *lml)
{
	if (DBG_NOTCLASS(DBG_C_DL))
		return;

	dbg_print(lml, MSG_INTL(MSG_DL_IPHDR_UNMAP));
}

void
Dbg_dl_dlopen(Rt_map *clmp, const char *name, int *in_nfavl, int mode)
{
	Conv_dl_mode_buf_t	dl_mode_buf;
	Lm_list			*lml = LIST(clmp);
	const char		*retry;

	if (DBG_NOTCLASS(DBG_C_FILES | DBG_C_DL))
		return;

	/*
	 * The core functionality of dlopen() can be called twice.  The first
	 * attempt can be affected by path names that exist in the "not-found"
	 * AVL tree.  Should a "not-found" path name be found, a second attempt
	 * is made to locate the required file (in_nfavl is NULL).  This fall-
	 * back provides for file system changes while a process executes.
	 */
	if (in_nfavl)
		retry = MSG_ORIG(MSG_STR_EMPTY);
	else
		retry = MSG_INTL(MSG_STR_RETRY);

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_DL_DLOPEN), name, NAME(clmp), retry,
	    conv_dl_mode(mode, 0, &dl_mode_buf));
}

void
Dbg_dl_dlclose(Rt_map *clmp, const char *name, int flag)
{
	const char	*str;
	Lm_list		*lml = LIST(clmp);

	if (DBG_NOTCLASS(DBG_C_FILES | DBG_C_DL))
		return;

	if (flag == DBG_DLCLOSE_IGNORE)
		str = MSG_INTL(MSG_STR_IGNORE);
	else
		str = MSG_ORIG(MSG_STR_EMPTY);

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_DL_DLCLOSE), name, NAME(clmp), str);
}

void
Dbg_dl_dldump(Rt_map *clmp, const char *ipath, const char *opath, int flags)
{
	Conv_dl_flag_buf_t	dl_flag_buf;
	Lm_list			*lml = LIST(clmp);

	if (DBG_NOTCLASS(DBG_C_FILES | DBG_C_DL))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_DL_DLDUMP), ipath, NAME(clmp),
	    opath ? opath : MSG_INTL(MSG_STR_NULL),
	    conv_dl_flag(flags, 0, &dl_flag_buf));
}

void
Dbg_dl_dlerror(Rt_map *clmp, const char *str)
{
	Lm_list	*lml = LIST(clmp);

	if (DBG_NOTCLASS(DBG_C_DL))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_DL_DLERROR), NAME(clmp),
	    str ? str : MSG_INTL(MSG_STR_NULL));
}

void
Dbg_dl_dladdr(Rt_map *clmp, void *addr)
{
	Lm_list	*lml = LIST(clmp);

	if (DBG_NOTCLASS(DBG_C_DL))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_DL_DLADDR), NAME(clmp), EC_NATPTR(addr));
}

void
Dbg_dl_dlsym(Rt_map *clmp, const char *sym, int *in_nfavl, const char *next,
    int type)
{
	const char	*str, *retry, *from = NAME(clmp);
	Lm_list		*lml = LIST(clmp);

	static const Msg	dlsym_msg[DBG_DLSYM_NUM] = {
		MSG_STR_EMPTY,		/* MSG_ORIG(MSG_STR_EMPTY) */
		MSG_DLSYM_NEXT,		/* MSG_ORIG(MSG_DLSYM_NEXT) */
		MSG_DLSYM_DEFAULT,	/* MSG_ORIG(MSG_DLSYM_DEFAULT) */
		MSG_DLSYM_SELF,		/* MSG_ORIG(MSG_DLSYM_SELF) */
		MSG_DLSYM_PROBE,	/* MSG_ORIG(MSG_DLSYM_PROBE) */
		MSG_DLSYM_SINGLETON	/* MSG_ORIG(MSG_DLSYM_SINGLETON) */
	};
#if	DBG_DLSYM_NUM != (DBG_DLSYM_SINGLETON + 1)
#error	DBG_DLSYM_NUM has grown
#endif
	if (DBG_NOTCLASS(DBG_C_SYMBOLS | DBG_C_DL))
		return;

	/*
	 * The core functionality of dlsym() can be called twice.  The first
	 * attempt can be affected by path names that exist in the "not-found"
	 * AVL tree.  Should a "not-found" path name be found, a second attempt
	 * is made to locate the required file (in_nfavl is NULL).  This fall-
	 * back provides for file system changes while a process executes.
	 */
	if (in_nfavl)
		retry = MSG_ORIG(MSG_STR_EMPTY);
	else
		retry = MSG_INTL(MSG_STR_RETRY);

	if (type >= DBG_DLSYM_NUM)
		type = 0;
	str = MSG_ORIG(dlsym_msg[type]);

	Dbg_util_nl(lml, DBG_NL_STD);
	if (next == 0)
		dbg_print(lml, MSG_INTL(MSG_DLSYM_1), Dbg_demangle_name(sym),
		    from, retry, str);
	else
		dbg_print(lml, MSG_INTL(MSG_DLSYM_2), Dbg_demangle_name(sym),
		    from, next, retry, str);
}

void
Dbg_dl_dlinfo(Rt_map *clmp, const char *name, int request, void *addr)
{
	Lm_list	*lml = LIST(clmp);

	if (DBG_NOTCLASS(DBG_C_DL))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_DL_DLINFO), NAME(clmp), name,
	    conv_dl_info(request), EC_NATPTR(addr));
}
