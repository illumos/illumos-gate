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

#include	<sys/auxv.h>
#include	<string.h>
#include	<unistd.h>
#include	<fcntl.h>
#include	<limits.h>
#include	<stdio.h>
#include	<libld.h>
#include	<rtld.h>
#include	<conv.h>
#include	"msg.h"
#include	"_debug.h"

void
Dbg_file_analyze(Rt_map *lmp)
{
	Conv_dl_mode_buf_t	dl_mode_buf;
	Lm_list			*lml = LIST(lmp);

	if (DBG_NOTCLASS(DBG_C_FILES))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_FIL_ANALYZE), NAME(lmp),
	    conv_dl_mode(MODE(lmp), 1, &dl_mode_buf));
}

void
Dbg_file_aout(Lm_list *lml, const char *name, ulong_t dynamic, ulong_t base,
    ulong_t size, const char *lmid, Aliste lmco)
{
	if (DBG_NOTCLASS(DBG_C_FILES))
		return;

	dbg_print(lml, MSG_INTL(MSG_FIL_AOUT), name);
	dbg_print(lml, MSG_INTL(MSG_FIL_DATA_DB), EC_XWORD(dynamic),
	    EC_ADDR(base));
	dbg_print(lml, MSG_INTL(MSG_FIL_DATA_S), EC_XWORD(size));
	dbg_print(lml, MSG_INTL(MSG_FIL_DATA_LL), lmid, EC_XWORD(lmco));
}

void
Dbg_file_elf(Lm_list *lml, const char *name, ulong_t dynamic, ulong_t base,
    ulong_t size, ulong_t entry, const char *lmid, Aliste lmco)
{
	const char	*str;

	if (DBG_NOTCLASS(DBG_C_FILES))
		return;

	if (base == 0)
		str = MSG_INTL(MSG_STR_TEMPORARY);
	else
		str = MSG_ORIG(MSG_STR_EMPTY);

	dbg_print(lml, MSG_INTL(MSG_FIL_ELF), name, str);
	dbg_print(lml, MSG_INTL(MSG_FIL_DATA_DB), EC_XWORD(dynamic),
	    EC_ADDR(base));
	dbg_print(lml, MSG_INTL(MSG_FIL_DATA_SE), EC_XWORD(size),
	    EC_XWORD(entry));
	dbg_print(lml, MSG_INTL(MSG_FIL_DATA_LL), lmid, EC_XWORD(lmco));
}

void
Dbg_file_ldso(Rt_map *lmp, char **envp, auxv_t *auxv, const char *lmid,
    Aliste lmco)
{
	Lm_list	*lml = LIST(lmp);

	if (DBG_NOTCLASS(DBG_C_FILES))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_FIL_LDSO), PATHNAME(lmp));
	dbg_print(lml, MSG_INTL(MSG_FIL_DATA_DB), EC_NATPTR(DYN(lmp)),
	    EC_ADDR(ADDR(lmp)));
	dbg_print(lml, MSG_INTL(MSG_FIL_DATA_EA), EC_NATPTR(envp),
	    EC_NATPTR(auxv));
	dbg_print(lml, MSG_INTL(MSG_FIL_DATA_LL), lmid, EC_XWORD(lmco));
	Dbg_util_nl(lml, DBG_NL_STD);
}


void
Dbg_file_prot(Rt_map *lmp, int prot)
{
	Lm_list	*lml = LIST(lmp);

	if (DBG_NOTCLASS(DBG_C_FILES))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_FIL_PROT), NAME(lmp), (prot ? '+' : '-'));
}

void
Dbg_file_delete(Rt_map *lmp)
{
	Lm_list	*lml = LIST(lmp);

	if (DBG_NOTCLASS(DBG_C_FILES))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_FIL_DELETE), NAME(lmp));
}

static int	hdl_title = 0;
static Msg	hdl_str = 0;

void
Dbg_file_hdl_title(int type)
{
	static const Msg titles[] = {
		MSG_FIL_HDL_CREATE,	/* MSG_INTL(MSG_FIL_HDL_CREATE) */
		MSG_FIL_HDL_ADD,	/* MSG_INTL(MSG_FIL_HDL_ADD) */
		MSG_FIL_HDL_DELETE,	/* MSG_INTL(MSG_FIL_HDL_DELETE) */
		MSG_FIL_HDL_ORPHAN,	/* MSG_INTL(MSG_FIL_HDL_ORPHAN) */
		MSG_FIL_HDL_REINST,	/* MSG_INTL(MSG_FIL_HDL_REINST) */
	};

	if (DBG_NOTCLASS(DBG_C_FILES))
		return;
	if (DBG_NOTDETAIL())
		return;

	/*
	 * Establish a binding title for later use in Dbg_file_hdl_action.
	 */
	if (type <= DBG_HDL_REINST) {
		hdl_str = titles[type];
		hdl_title = 1;
	} else {
		hdl_str = 0;
		hdl_title = 0;
	}
}

void
Dbg_file_hdl_collect(Grp_hdl *ghp, const char *name)
{
	Conv_grphdl_flags_buf_t	grphdl_flags_buf;
	Lm_list		*lml = ghp->gh_ownlml;
	const char	*str;

	if (DBG_NOTCLASS(DBG_C_FILES))
		return;
	if (DBG_NOTDETAIL())
		return;

	if (ghp->gh_ownlmp)
		str = NAME(ghp->gh_ownlmp);
	else
		str = MSG_INTL(MSG_STR_ORPHAN);

	if (hdl_title) {
		hdl_title = 0;
		Dbg_util_nl(lml, DBG_NL_STD);
	}
	if (name)
		dbg_print(lml, MSG_INTL(MSG_FIL_HDL_RETAIN), str, name);
	else
		dbg_print(lml, MSG_INTL(MSG_FIL_HDL_COLLECT), str,
		    conv_grphdl_flags(ghp->gh_flags, &grphdl_flags_buf));
}

void
Dbg_file_hdl_action(Grp_hdl *ghp, Rt_map *lmp, int type, uint_t flags)
{
	Conv_grpdesc_flags_buf_t grpdesc_flags_buf;
	const char	*mode, *group;
	Lm_list		*lml = LIST(lmp);
	Msg		str;

	static const Msg fmt[] = {
		MSG_FIL_DEP_ADD,	/* MSG_INTL(MSG_FIL_DEP_ADD) */
		MSG_FIL_DEP_UPDATE,	/* MSG_INTL(MSG_FIL_DEP_UPDATE) */
		MSG_FIL_DEP_DELETE,	/* MSG_INTL(MSG_FIL_DEP_DELETE) */
		MSG_FIL_DEP_REMOVE,	/* MSG_INTL(MSG_FIL_DEP_REMOVE) */
		MSG_FIL_DEP_REMAIN,	/* MSG_INTL(MSG_FIL_DEP_REMAIN) */
		MSG_FIL_DEP_ORPHAN,	/* MSG_INTL(MSG_FIL_DEP_ORPHAN) */
		MSG_FIL_DEP_REINST,	/* MSG_INTL(MSG_FIL_DEP_REINST) */
	};
	if (DBG_NOTCLASS(DBG_C_FILES))
		return;
	if (DBG_NOTDETAIL())
		return;

	if (hdl_title) {
		Dbg_util_nl(lml, DBG_NL_STD);
		if (hdl_str) {
			const char	*name;

			/*
			 * Protect ourselves in case this handle has no
			 * originating owner.
			 */
			if (ghp->gh_ownlmp)
				name = NAME(ghp->gh_ownlmp);
			else
				name = MSG_INTL(MSG_STR_UNKNOWN);

			dbg_print(lml, MSG_INTL(hdl_str), name);
		}
		hdl_title = 0;
	}

	/*
	 * Establish a binding descriptor format string.
	 */
	if (type > DBG_DEP_REINST)
		return;

	str = fmt[type];

	if (((type == DBG_DEP_ADD) || (type == DBG_DEP_UPDATE)) && flags)
		group = conv_grpdesc_flags(flags, &grpdesc_flags_buf);
	else
		group = MSG_ORIG(MSG_STR_EMPTY);

	if ((MODE(lmp) & (RTLD_GLOBAL | RTLD_NODELETE)) ==
	    (RTLD_GLOBAL | RTLD_NODELETE))
		mode = MSG_ORIG(MSG_MODE_GLOBNODEL);
	else if (MODE(lmp) & RTLD_GLOBAL)
		mode = MSG_ORIG(MSG_MODE_GLOB);
	else if (MODE(lmp) & RTLD_NODELETE)
		mode = MSG_ORIG(MSG_MODE_NODEL);
	else
		mode = MSG_ORIG(MSG_STR_EMPTY);

	dbg_print(lml, MSG_INTL(str), NAME(lmp), mode, group);
}

void
Dbg_file_bind_entry(Lm_list *lml, Bnd_desc *bdp)
{
	Conv_bnd_type_buf_t bnd_type_buf;

	if (DBG_NOTCLASS(DBG_C_FILES))
		return;
	if (DBG_NOTDETAIL())
		return;

	/*
	 * Print the dependency together with the modes of the binding.
	 */
	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_FIL_BND_ADD), NAME(bdp->b_caller));
	dbg_print(lml, MSG_INTL(MSG_FIL_BND_FILE), NAME(bdp->b_depend),
	    conv_bnd_type(bdp->b_flags, &bnd_type_buf));
}

void
Dbg_file_bindings(Rt_map *lmp, int flag)
{
	Conv_bnd_obj_buf_t	bnd_obj_buf;
	Conv_bnd_type_buf_t	bnd_type_buf;
	const char	*str;
	Rt_map		*tlmp;
	Lm_list		*lml = LIST(lmp);
	int		next = 0;

	if (DBG_NOTCLASS(DBG_C_INIT))
		return;
	if (DBG_NOTDETAIL())
		return;

	if (flag & RT_SORT_REV)
		str = MSG_ORIG(MSG_SCN_INIT);
	else
		str = MSG_ORIG(MSG_SCN_FINI);

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_FIL_DEP_TITLE), str,
	    conv_bnd_obj(lml->lm_flags, &bnd_obj_buf));

	/* LINTED */
	for (tlmp = lmp; tlmp; tlmp = (Rt_map *)NEXT(tlmp)) {
		Bnd_desc	*bdp;
		Aliste		idx;

		/*
		 * For .init processing, only collect objects that have been
		 * relocated and haven't already been collected.
		 * For .fini processing, only collect objects that have had
		 * their .init collected, and haven't already been .fini
		 * collected.
		 */
		if (flag & RT_SORT_REV) {
			if ((FLAGS(tlmp) & (FLG_RT_RELOCED |
			    FLG_RT_INITCLCT)) != FLG_RT_RELOCED)
				continue;

		} else {
			if ((flag & RT_SORT_DELETE) &&
			    ((FLAGS(tlmp) & FLG_RT_DELETE) == 0))
				continue;
			if (((FLAGS(tlmp) &
			    (FLG_RT_INITCLCT | FLG_RT_FINICLCT)) ==
			    FLG_RT_INITCLCT) == 0)
				continue;
		}

		if (next++)
			Dbg_util_nl(lml, DBG_NL_STD);

		if (DEPENDS(tlmp) == NULL)
			dbg_print(lml, MSG_INTL(MSG_FIL_DEP_NONE), NAME(tlmp));
		else {
			dbg_print(lml, MSG_INTL(MSG_FIL_DEP_ENT), NAME(tlmp));

			for (APLIST_TRAVERSE(DEPENDS(tlmp), idx, bdp)) {
				dbg_print(lml, MSG_INTL(MSG_FIL_BND_FILE),
				    NAME(bdp->b_depend),
				    conv_bnd_type(bdp->b_flags,
				    &bnd_type_buf));
			}
		}
	}
	Dbg_util_nl(lml, DBG_NL_STD);
}

void
Dbg_file_dlopen(Rt_map *clmp, const char *name, int *in_nfavl, int mode)
{
	Conv_dl_mode_buf_t	dl_mode_buf;
	Lm_list			*lml = LIST(clmp);
	const char		*retry;

	if (DBG_NOTCLASS(DBG_C_FILES))
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
	dbg_print(lml, MSG_INTL(MSG_FIL_DLOPEN), name, NAME(clmp), retry,
	    conv_dl_mode(mode, 0, &dl_mode_buf));
}

void
Dbg_file_dlclose(Lm_list *lml, const char *name, int flag)
{
	const char	*str;

	if (DBG_NOTCLASS(DBG_C_FILES))
		return;

	if (flag == DBG_DLCLOSE_IGNORE)
		str = MSG_INTL(MSG_STR_IGNORE);
	else
		str = MSG_ORIG(MSG_STR_EMPTY);

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_FIL_DLCLOSE), name, str);
}

void
Dbg_file_dldump(Rt_map *lmp, const char *path, int flags)
{
	Conv_dl_flag_buf_t	dl_flag_buf;
	Lm_list			*lml = LIST(lmp);

	if (DBG_NOTCLASS(DBG_C_FILES))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_FIL_DLDUMP), NAME(lmp), path,
	    conv_dl_flag(flags, 0, &dl_flag_buf));
}

void
Dbg_file_lazyload(Rt_map *clmp, const char *fname, const char *sname)
{
	Lm_list	*lml = LIST(clmp);

	if (DBG_NOTCLASS(DBG_C_FILES))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_FIL_LAZYLOAD), fname, NAME(clmp),
	    Dbg_demangle_name(sname));
}

void
Dbg_file_preload(Lm_list *lml, const char *name)
{
	if (DBG_NOTCLASS(DBG_C_FILES))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_FIL_PRELOAD), name);
}

void
Dbg_file_needed(Rt_map *lmp, const char *name)
{
	Lm_list	*lml = LIST(lmp);

	if (DBG_NOTCLASS(DBG_C_FILES))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_FIL_NEEDED), name, NAME(lmp));
}

void
Dbg_file_filter(Lm_list *lml, const char *filter, const char *filtee,
    int config)
{
	if (DBG_NOTCLASS(DBG_C_FILES))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	if (config)
		dbg_print(lml, MSG_INTL(MSG_FIL_FILTER_1), filter, filtee);
	else
		dbg_print(lml, MSG_INTL(MSG_FIL_FILTER_2), filter, filtee);
}

void
Dbg_file_filtee(Lm_list *lml, const char *filter, const char *filtee, int audit)
{
	if (audit) {
		if (DBG_NOTCLASS(DBG_C_AUDITING | DBG_C_FILES))
			return;

		Dbg_util_nl(lml, DBG_NL_STD);
		dbg_print(lml, MSG_INTL(MSG_FIL_FILTEE_3), filtee);
	} else {
		if (DBG_NOTCLASS(DBG_C_FILES))
			return;

		Dbg_util_nl(lml, DBG_NL_STD);
		if (filter)
			dbg_print(lml, MSG_INTL(MSG_FIL_FILTEE_1), filtee,
			    filter);
		else
			dbg_print(lml, MSG_INTL(MSG_FIL_FILTEE_2), filtee);
	}
}

void
Dbg_file_fixname(Lm_list *lml, const char *oname, const char *nname)
{
	if (DBG_NOTCLASS(DBG_C_FILES))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_FIL_FIXNAME), oname, nname);
}

void
Dbg_file_output(Ofl_desc *ofl)
{
	const char	*prefix = MSG_ORIG(MSG_PTH_OBJECT);
	char		*oname, *nname, *ofile;
	int		fd;

	if (DBG_NOTCLASS(DBG_C_FILES))
		return;
	if (DBG_NOTDETAIL())
		return;

	/*
	 * Obtain the present input object filename for concatenation to the
	 * prefix name.
	 */
	oname = (char *)ofl->ofl_name;
	if ((ofile = strrchr(oname, '/')) == NULL)
		ofile = oname;
	else
		ofile++;

	/*
	 * Concatenate the prefix with the object filename, open the file and
	 * write out the present Elf memory image.  As this is debugging we
	 * ignore all errors.
	 */
	if ((nname = malloc(strlen(prefix) + strlen(ofile) + 1)) != 0) {
		(void) strcpy(nname, prefix);
		(void) strcat(nname, ofile);
		if ((fd = open(nname, O_RDWR | O_CREAT | O_TRUNC,
		    0666)) != -1) {
			(void) write(fd, ofl->ofl_nehdr, ofl->ofl_size);
			(void) close(fd);
		}
		free(nname);
	}
}

void
Dbg_file_config_dis(Lm_list *lml, const char *config, int features)
{
	Conv_config_feat_buf_t	config_feat_buf;
	const char		*str;

	switch (features & ~CONF_FEATMSK) {
	case DBG_CONF_IGNORE:
		str = MSG_INTL(MSG_FIL_CONFIG_ERR_1);
		break;
	case DBG_CONF_VERSION:
		str = MSG_INTL(MSG_FIL_CONFIG_ERR_2);
		break;
	case DBG_CONF_PRCFAIL:
		str = MSG_INTL(MSG_FIL_CONFIG_ERR_3);
		break;
	case DBG_CONF_CORRUPT:
		str = MSG_INTL(MSG_FIL_CONFIG_ERR_4);
		break;
	case DBG_CONF_ABIMISMATCH:
		str = MSG_INTL(MSG_FIL_CONFIG_ERR_5);
		break;
	default:
		str = conv_config_feat(features, &config_feat_buf);
		break;
	}

	Dbg_util_nl(lml, DBG_NL_FRC);
	dbg_print(lml, MSG_INTL(MSG_FIL_CONFIG_ERR), config, str);
	Dbg_util_nl(lml, DBG_NL_FRC);
}

void
Dbg_file_config_obj(Lm_list *lml, const char *dir, const char *file,
    const char *config)
{
	char	*name, _name[PATH_MAX];

	if (DBG_NOTCLASS(DBG_C_FILES))
		return;

	if (file) {
		(void) snprintf(_name, PATH_MAX, MSG_ORIG(MSG_FMT_PATH),
		    dir, file);
		name = _name;
	} else
		name = (char *)dir;

	dbg_print(lml, MSG_INTL(MSG_FIL_CONFIG), name, config);
}

void
Dbg_file_del_rescan(Lm_list *lml)
{
	if (DBG_NOTCLASS(DBG_C_FILES))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_FIL_DEL_RESCAN));
}

void
Dbg_file_mode_promote(Rt_map *lmp, int mode)
{
	Conv_dl_mode_buf_t	dl_mode_buf;
	Lm_list			*lml = LIST(lmp);

	if (DBG_NOTCLASS(DBG_C_FILES))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_FIL_PROMOTE), NAME(lmp),
	    conv_dl_mode(mode, 0, &dl_mode_buf));
	Dbg_util_nl(lml, DBG_NL_STD);
}

void
Dbg_file_cntl(Lm_list *lml, Aliste flmco, Aliste tlmco)
{
	Lm_cntl	*lmc;
	Aliste	off;

	if (DBG_NOTCLASS(DBG_C_FILES))
		return;
	if (DBG_NOTDETAIL())
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_CNTL_TITLE), EC_XWORD(flmco),
	    EC_XWORD(tlmco));

	for (ALIST_TRAVERSE_BY_OFFSET(lml->lm_lists, off, lmc)) {
		Rt_map	*lmp;

		/* LINTED */
		for (lmp = lmc->lc_head; lmp; lmp = (Rt_map *)NEXT(lmp))
			dbg_print(lml, MSG_ORIG(MSG_CNTL_ENTRY), EC_XWORD(off),
			    NAME(lmp));
	}
	Dbg_util_nl(lml, DBG_NL_STD);
}

/*
 * Report archive rescan operation.
 *	argv_start_ndx, argv_end_ndx - Index range of command line arguments
 *		from which archives are to be reprocessed.
 */
void
Dbg_file_ar_rescan(Lm_list *lml, int argv_start_ndx, int argv_end_ndx)
{
	if (DBG_NOTCLASS(DBG_C_FILES))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_FIL_AR_RESCAN),
	    argv_start_ndx, argv_end_ndx);
	Dbg_util_nl(lml, DBG_NL_STD);
}

void
Dbg_file_ar(Lm_list *lml, const char *name, int again)
{
	const char	*str;

	if (DBG_NOTCLASS(DBG_C_FILES))
		return;

	if (again)
		str = MSG_INTL(MSG_STR_AGAIN);
	else
		str = MSG_ORIG(MSG_STR_EMPTY);

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_FIL_ARCHIVE), name, str);
}

void
Dbg_file_generic(Lm_list *lml, Ifl_desc *ifl)
{
	Conv_inv_buf_t inv_buf;

	if (DBG_NOTCLASS(DBG_C_FILES))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_FIL_BASIC), ifl->ifl_name,
	    conv_ehdr_type(ifl->ifl_ehdr->e_type, 0, &inv_buf));
}

static const Msg
reject[] = {
	MSG_STR_EMPTY,
	MSG_REJ_MACH,		/* MSG_INTL(MSG_REJ_MACH) */
	MSG_REJ_CLASS,		/* MSG_INTL(MSG_REJ_CLASS) */
	MSG_REJ_DATA,		/* MSG_INTL(MSG_REJ_DATA) */
	MSG_REJ_TYPE,		/* MSG_INTL(MSG_REJ_TYPE) */
	MSG_REJ_BADFLAG,	/* MSG_INTL(MSG_REJ_BADFLAG) */
	MSG_REJ_MISFLAG,	/* MSG_INTL(MSG_REJ_MISFLAG) */
	MSG_REJ_VERSION,	/* MSG_INTL(MSG_REJ_VERSION) */
	MSG_REJ_HAL,		/* MSG_INTL(MSG_REJ_HAL) */
	MSG_REJ_US3,		/* MSG_INTL(MSG_REJ_US3) */
	MSG_REJ_STR,		/* MSG_INTL(MSG_REJ_STR) */
	MSG_REJ_UNKFILE,	/* MSG_INTL(MSG_REJ_UNKFILE) */
	MSG_REJ_HWCAP_1,	/* MSG_INTL(MSG_REJ_HWCAP_1) */
};

void
Dbg_file_rejected(Lm_list *lml, Rej_desc *rej, Half mach)
{
	Conv_reject_desc_buf_t rej_buf;

	if (DBG_NOTCLASS(DBG_C_FILES))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(reject[rej->rej_type]), rej->rej_name ?
	    rej->rej_name : MSG_INTL(MSG_STR_UNKNOWN),
	    conv_reject_desc(rej, &rej_buf, mach));
	Dbg_util_nl(lml, DBG_NL_STD);
}

void
Dbg_file_reuse(Lm_list *lml, const char *nname, const char *oname)
{
	if (DBG_NOTCLASS(DBG_C_FILES))
		return;

	dbg_print(lml, MSG_INTL(MSG_FIL_REUSE), nname, oname);
}

void
Dbg_file_skip(Lm_list *lml, const char *oname, const char *nname)
{
	if (DBG_NOTCLASS(DBG_C_FILES))
		return;

	if (oname && strcmp(nname, oname))
		dbg_print(lml, MSG_INTL(MSG_FIL_SKIP_1), nname, oname);
	else
		dbg_print(lml, MSG_INTL(MSG_FIL_SKIP_2), nname);
}

void
Dbg_file_modified(Lm_list *lml, const char *obj, const char *oname,
    const char *nname, int ofd, int nfd, Elf *oelf, Elf *nelf)
{
	const char	*str;

	if (DBG_NOTCLASS(DBG_C_FILES | DBG_C_SUPPORT))
		return;
	if (DBG_NOTDETAIL())
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_FIL_MODIFIED), oname, obj);

	if (nname != oname)
		dbg_print(lml, MSG_INTL(MSG_FIL_NAMECHANGE), nname);
	if (nfd != ofd) {
		if (nfd == -1)
			str = MSG_INTL(MSG_FIL_IGNORE);
		else
			str = MSG_ORIG(MSG_STR_EMPTY);
		dbg_print(lml, MSG_INTL(MSG_FIL_FDCHANGE), ofd, nfd, str);
	}
	if (nelf != oelf) {
		if (nelf == 0)
			str = MSG_INTL(MSG_FIL_IGNORE);
		else
			str = MSG_ORIG(MSG_STR_EMPTY);
		dbg_print(lml, MSG_INTL(MSG_FIL_ELFCHANGE), EC_NATPTR(oelf),
		    EC_NATPTR(nelf), str);
	}
	Dbg_util_nl(lml, DBG_NL_STD);
}

void
Dbg_file_cleanup(Lm_list *lml, const char *name, Aliste lmco)
{
	if (DBG_NOTCLASS(DBG_C_FILES))
		return;

	Dbg_util_nl(lml, DBG_NL_STD);
	dbg_print(lml, MSG_INTL(MSG_FIL_CLEANUP), name, EC_XWORD(lmco));
}
