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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	"_synonyms.h"

#include	<sys/auxv.h>
#include	<string.h>
#include	<unistd.h>
#include	<fcntl.h>
#include	<limits.h>
#include	<stdio.h>
#include	"msg.h"
#include	"_debug.h"
#include	"libld.h"
#include	"rtld.h"


void
Dbg_file_generic(Ifl_desc *ifl)
{
	if (DBG_NOTCLASS(DBG_FILES))
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_FIL_BASIC), ifl->ifl_name,
		conv_etype_str(ifl->ifl_ehdr->e_type));
}

void
Dbg_file_skip(const char *nname, const char *oname)
{
	if (DBG_NOTCLASS(DBG_FILES))
		return;

	if (oname && strcmp(nname, oname))
		dbg_print(MSG_INTL(MSG_FIL_SKIP_1), nname, oname);
	else
		dbg_print(MSG_INTL(MSG_FIL_SKIP_2), nname);
}

void
Dbg_file_reuse(const char *nname, const char *oname)
{
	if (DBG_NOTCLASS(DBG_FILES))
		return;

	dbg_print(MSG_INTL(MSG_FIL_REUSE), nname, oname);
}

void
Dbg_file_archive(const char *name, int again)
{
	const char	*str;

	if (DBG_NOTCLASS(DBG_FILES))
		return;

	if (again)
		str = MSG_INTL(MSG_STR_AGAIN);
	else
		str = MSG_ORIG(MSG_STR_EMPTY);

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_FIL_ARCHIVE), name, str);
}

void
Dbg_file_analyze(Rt_map * lmp)
{
	if (DBG_NOTCLASS(DBG_FILES))
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_FIL_ANALYZE), NAME(lmp),
	    conv_dlmode_str(MODE(lmp), 1));
}

void
Dbg_file_aout(const char *name, ulong_t dynamic, ulong_t base, ulong_t size)
{
	if (DBG_NOTCLASS(DBG_FILES))
		return;

	dbg_print(MSG_INTL(MSG_FIL_AOUT), name);
	dbg_print(MSG_INTL(MSG_FIL_DATA_1), EC_XWORD(dynamic),
	    EC_ADDR(base), EC_XWORD(size));
}

void
Dbg_file_elf(const char *name, ulong_t dynamic, ulong_t base,
    ulong_t size, ulong_t entry, Lmid_t lmid, Aliste lmco)
{
	const char	*str;

	if (DBG_NOTCLASS(DBG_FILES))
		return;

	if (base == 0)
		str = MSG_INTL(MSG_STR_TEMPORARY);
	else
		str = MSG_ORIG(MSG_STR_EMPTY);

	dbg_print(MSG_INTL(MSG_FIL_ELF), name, str);
	dbg_print(MSG_INTL(MSG_FIL_DATA_1), EC_XWORD(dynamic),
	    EC_ADDR(base), EC_XWORD(size));
	dbg_print(MSG_INTL(MSG_FIL_DATA_2), EC_XWORD(entry),
	    EC_XWORD(lmid), EC_XWORD(lmco));
}

void
Dbg_file_ldso(const char *name, ulong_t dynamic, ulong_t base, char **envp,
    auxv_t *auxv)
{
	if (DBG_NOTCLASS(DBG_FILES))
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_FIL_LDSO), name);
	dbg_print(MSG_INTL(MSG_FIL_DATA_3), EC_XWORD(dynamic),
	    EC_ADDR(base));
	dbg_print(MSG_INTL(MSG_FIL_DATA_4), EC_ADDR(envp), EC_ADDR(auxv));
	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
}

void
Dbg_file_prot(const char *name, int prot)
{
	if (DBG_NOTCLASS(DBG_FILES))
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_FIL_PROT), name, (prot ? '+' : '-'));
}

void
Dbg_file_delete(const char *name)
{
	if (DBG_NOTCLASS(DBG_FILES))
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_FIL_DELETE), name);
}

static int	hdl_title = 0;
static Msg	hdl_str = 0;

void
Dbg_file_hdl_title(int type)
{
	if (DBG_NOTCLASS(DBG_FILES))
		return;
	if (DBG_NOTDETAIL())
		return;

	hdl_title = 1;

	/*
	 * Establish a binding title for later use in Dbg_file_bind_entry.
	 */
	if (type == DBG_DEP_CREATE)
	    hdl_str = MSG_FIL_HDL_CREATE;  /* MSG_INTL(MSG_FIL_HDL_CREATE) */
	else if (type == DBG_DEP_ADD)
	    hdl_str = MSG_FIL_HDL_ADD;	   /* MSG_INTL(MSG_FIL_HDL_ADD) */
	else if (type == DBG_DEP_DELETE)
	    hdl_str = MSG_FIL_HDL_DELETE;  /* MSG_INTL(MSG_FIL_HDL_DELETE) */
	else if (type == DBG_DEP_ORPHAN)
	    hdl_str = MSG_FIL_HDL_ORPHAN;  /* MSG_INTL(MSG_FIL_HDL_ORPHAN) */
	else if (type == DBG_DEP_REINST)
	    hdl_str = MSG_FIL_HDL_REINST;  /* MSG_INTL(MSG_FIL_HDL_REINST) */
	else
	    hdl_str = 0;
}

void
Dbg_file_hdl_collect(Grp_hdl * ghp, const char *name)
{
	const char *str;

	if (DBG_NOTCLASS(DBG_FILES))
		return;
	if (DBG_NOTDETAIL())
		return;

	if (ghp->gh_owner)
		str = NAME(ghp->gh_owner);
	else
		str = MSG_INTL(MSG_STR_ORPHAN);

	if (hdl_title) {
		hdl_title = 0;
		dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	}
	if (name)
		dbg_print(MSG_INTL(MSG_FIL_HDL_RETAIN), str, name);
	else
		dbg_print(MSG_INTL(MSG_FIL_HDL_COLLECT), str,
		    conv_grphdrflags_str(ghp->gh_flags));
}

void
Dbg_file_hdl_action(Grp_hdl * ghp, Rt_map * lmp, int type)
{
	Msg	str;

	if (DBG_NOTCLASS(DBG_FILES))
		return;
	if (DBG_NOTDETAIL())
		return;

	if (hdl_title) {
		dbg_print(MSG_ORIG(MSG_STR_EMPTY));
		if (hdl_str) {
			const char	*name;

			/*
			 * Protect ourselves in case this handle has no
			 * originating owner.
			 */
			if (ghp->gh_owner)
				name = NAME(ghp->gh_owner);
			else
				name = MSG_INTL(MSG_STR_UNKNOWN);

			dbg_print(MSG_INTL(hdl_str), name);
		}
		hdl_title = 0;
	}

	if (type == DBG_DEP_ADD)
	    str = MSG_FIL_DEP_ADD;	/* MSG_INTL(MSG_FIL_DEP_ADD) */
	else if (type == DBG_DEP_DELETE)
	    str = MSG_FIL_DEP_DELETE;	/* MSG_INTL(MSG_FIL_DEP_DELETE) */
	else if (type == DBG_DEP_REMOVE)
	    str = MSG_FIL_DEP_REMOVE;	/* MSG_INTL(MSG_FIL_DEP_REMOVE) */
	else if (type == DBG_DEP_REMAIN)
	    str = MSG_FIL_DEP_REMAIN;	/* MSG_INTL(MSG_FIL_DEP_REMAIN) */
	else
	    str = 0;

	if (str) {
		const char *mode;

		if ((MODE(lmp) & (RTLD_GLOBAL | RTLD_NODELETE)) ==
		    (RTLD_GLOBAL | RTLD_NODELETE))
			mode = MSG_ORIG(MSG_MODE_GLOBNODEL);
		else if (MODE(lmp) & RTLD_GLOBAL)
			mode = MSG_ORIG(MSG_MODE_GLOB);

		else if (MODE(lmp) & RTLD_NODELETE)
			mode = MSG_ORIG(MSG_MODE_NODEL);
		else
			mode = MSG_ORIG(MSG_STR_EMPTY);

		dbg_print(MSG_INTL(str), NAME(lmp), mode);
	}
}

void
Dbg_file_bind_entry(Bnd_desc *bdp)
{
	if (DBG_NOTCLASS(DBG_FILES))
		return;
	if (DBG_NOTDETAIL())
		return;

	/*
	 * Print the dependency together with the modes of the binding.
	 */
	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_FIL_BND_ADD), NAME(bdp->b_caller));
	dbg_print(MSG_INTL(MSG_FIL_BND_FILE), NAME(bdp->b_depend),
	    conv_bindent_str(bdp->b_flags));
}

void
Dbg_file_bindings(Rt_map *lmp, int flag, Word lmflags)
{
	const char	*str;
	Rt_map		*tlmp;
	int		next = 0;

	if (DBG_NOTCLASS(DBG_INIT))
		return;
	if (DBG_NOTDETAIL())
		return;

	if (flag & RT_SORT_REV)
		str = MSG_ORIG(MSG_SCN_INIT);
	else
		str = MSG_ORIG(MSG_SCN_FINI);

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_FIL_DEP_TITLE), str, conv_binding_str(lmflags));

	/* LINTED */
	for (tlmp = lmp; tlmp; tlmp = (Rt_map *)NEXT(tlmp)) {
		Bnd_desc **	bdpp;
		Aliste		off;

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
			dbg_print(MSG_ORIG(MSG_STR_EMPTY));

		if (DEPENDS(tlmp) == 0)
			dbg_print(MSG_INTL(MSG_FIL_DEP_NONE), NAME(tlmp));
		else {
			dbg_print(MSG_INTL(MSG_FIL_DEP_ENT), NAME(tlmp));

			for (ALIST_TRAVERSE(DEPENDS(tlmp), off, bdpp)) {
				dbg_print(MSG_INTL(MSG_FIL_BND_FILE),
				    NAME((*bdpp)->b_depend),
				    conv_bindent_str((*bdpp)->b_flags));
			}
		}
	}
	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
}

void
Dbg_file_dlopen(const char *name, const char *from, int mode)
{
	if (DBG_NOTCLASS(DBG_FILES))
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_FIL_DLOPEN), name, from,
	    conv_dlmode_str(mode, 1));
}

void
Dbg_file_dlclose(const char *name, int flag)
{
	const char	*str;

	if (DBG_NOTCLASS(DBG_FILES))
		return;

	if (flag == DBG_DLCLOSE_IGNORE)
		str = MSG_INTL(MSG_STR_IGNORE);
	else
		str = MSG_ORIG(MSG_STR_EMPTY);

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_FIL_DLCLOSE), name, str);
}

void
Dbg_file_dldump(const char *ipath, const char *opath, int flags)
{
	if (DBG_NOTCLASS(DBG_FILES))
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_FIL_DLDUMP), ipath, opath,
		conv_dlflag_str(flags, 0));
}

void
Dbg_file_lazyload(const char *file, const char *from, const char *symname)
{
	if (DBG_NOTCLASS(DBG_FILES))
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_FIL_LAZYLOAD), file, from,
	    _Dbg_sym_dem(symname));
}

void
Dbg_file_nl()
{
	if (DBG_NOTCLASS(DBG_FILES))
		return;
	if (DBG_NOTDETAIL())
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
}

void
Dbg_file_preload(const char *name)
{
	if (DBG_NOTCLASS(DBG_FILES))
		return;

	dbg_print(MSG_INTL(MSG_FIL_PRELOAD), name);
}

void
Dbg_file_needed(const char *name, const char *parent)
{
	if (DBG_NOTCLASS(DBG_FILES))
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_FIL_NEEDED), name, parent);
}

void
Dbg_file_filter(const char *filter, const char *filtee, int config)
{
	if (DBG_NOTCLASS(DBG_FILES))
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	if (config)
		dbg_print(MSG_INTL(MSG_FIL_FILTER_1), filter, filtee);
	else
		dbg_print(MSG_INTL(MSG_FIL_FILTER_2), filter, filtee);
}

void
Dbg_file_filtee(const char *filter, const char *filtee, int audit)
{
	if (audit) {
		if (DBG_NOTCLASS(DBG_AUDITING | DBG_FILES))
			return;

		dbg_print(MSG_ORIG(MSG_STR_EMPTY));
		dbg_print(MSG_INTL(MSG_FIL_FILTEE_3), filtee);
	} else {
		if (DBG_NOTCLASS(DBG_FILES))
			return;

		dbg_print(MSG_ORIG(MSG_STR_EMPTY));
		if (filter)
			dbg_print(MSG_INTL(MSG_FIL_FILTEE_1), filtee, filter);
		else
			dbg_print(MSG_INTL(MSG_FIL_FILTEE_2), filtee);
	}
}

void
Dbg_file_fixname(const char *oname, const char *nname)
{
	if (DBG_NOTCLASS(DBG_FILES))
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_FIL_FIXNAME), oname, nname);
}

void
Dbg_file_output(Ofl_desc *ofl)
{
	const char	*prefix = MSG_ORIG(MSG_PTH_OBJECT);
	char		*oname, *nname, *ofile;
	int		fd;

	if (DBG_NOTCLASS(DBG_FILES))
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
	if ((nname = (char *)malloc(strlen(prefix) + strlen(ofile) + 1)) != 0) {
		(void) strcpy(nname, prefix);
		(void) strcat(nname, ofile);
		if ((fd = open(nname, O_RDWR | O_CREAT | O_TRUNC,
		    0666)) != -1) {
			(void) write(fd, ofl->ofl_ehdr, ofl->ofl_size);
			close(fd);
		}
		free(nname);
	}
}

void
Dbg_file_config_dis(const char *config, int features)
{
	const char	*str;
	int		error = features & ~CONF_FEATMSK;

	if (error == DBG_CONF_IGNORE)
		str = MSG_INTL(MSG_FIL_CONFIG_ERR_1);
	else if (error == DBG_CONF_VERSION)
		str = MSG_INTL(MSG_FIL_CONFIG_ERR_2);
	else if (error == DBG_CONF_PRCFAIL)
		str = MSG_INTL(MSG_FIL_CONFIG_ERR_3);
	else if (error == DBG_CONF_CORRUPT)
		str = MSG_INTL(MSG_FIL_CONFIG_ERR_4);
	else
		str = conv_config_str(features);

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_FIL_CONFIG_ERR), config, str);
	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
}

void
Dbg_file_config_obj(const char *dir, const char *file, const char *config)
{
	char	*name, _name[PATH_MAX];

	if (DBG_NOTCLASS(DBG_FILES))
		return;

	if (file) {
		(void) snprintf(_name, PATH_MAX, MSG_ORIG(MSG_FMT_PATH),
		    dir, file);
		name = _name;
	} else
		name = (char *)dir;

	dbg_print(MSG_INTL(MSG_FIL_CONFIG), name, config);
}

#if	!defined(_ELF64)

const Msg
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
Dbg_file_rejected(Rej_desc *rej)
{
	if (DBG_NOTCLASS(DBG_FILES))
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(reject[rej->rej_type]), rej->rej_name ?
	    rej->rej_name : MSG_INTL(MSG_STR_UNKNOWN), conv_reject_str(rej));
	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
}

void
Dbg_file_del_rescan(void)
{
	if (DBG_NOTCLASS(DBG_FILES))
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_FIL_DEL_RESCAN));
}

void
Dbg_file_ar_rescan(void)
{
	if (DBG_NOTCLASS(DBG_FILES))
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_FIL_AR_RESCAN));
	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
}

void
Dbg_file_mode_promote(const char *file, int mode)
{
	if (DBG_NOTCLASS(DBG_FILES))
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_FIL_PROMOTE), file, conv_dlmode_str(mode, 0));
	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
}

void
Dbg_file_cntl(Lm_list *lml, Aliste flmco, Aliste tlmco)
{
	Lm_cntl	*lmc;
	Aliste	off;

	if (DBG_NOTCLASS(DBG_FILES))
		return;
	if (DBG_NOTDETAIL())
		return;

	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
	dbg_print(MSG_INTL(MSG_CNTL_TITLE), EC_XWORD(flmco), EC_XWORD(tlmco));

	for (ALIST_TRAVERSE(lml->lm_lists, off, lmc)) {
		Rt_map	*lmp;

		for (lmp = lmc->lc_head; lmp; lmp = (Rt_map *)NEXT(lmp))
			dbg_print(MSG_ORIG(MSG_CNTL_ENTRY), EC_XWORD(off),
			    NAME(lmp));
	}
	dbg_print(MSG_ORIG(MSG_STR_EMPTY));
}
#endif
