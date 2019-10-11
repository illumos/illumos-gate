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
 * Copyright (c) 2012 by Delphix. All rights reserved.
 * Copyright (c) 2012 Joyent, Inc. All rights reserved.
 */

#include <sys/param.h>
#include <unistd.h>
#include <strings.h>
#include <dlfcn.h>
#include <link.h>

#include <mdb/mdb_module.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ctf.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_callb.h>
#include <mdb/mdb_string.h>
#include <mdb/mdb_ks.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_io.h>
#include <mdb/mdb_frame.h>
#include <mdb/mdb_whatis_impl.h>
#include <mdb/mdb.h>

/*
 * The format of an mdb dcmd changed between MDB_API_VERSION 3 and 4, with an
 * addition of a new field to the public interface. To maintain backwards
 * compatibility with older versions, we know to keep around the old version of
 * the structure so we can correctly read the set of dcmds passed in.
 */
typedef struct mdb_dcmd_v3 {
	const char *dco_name;		/* Command name */
	const char *dco_usage;		/* Usage message (optional) */
	const char *dco_descr;		/* Description */
	mdb_dcmd_f *dco_funcp;		/* Command function */
	void (*dco_help)(void);		/* Command help function (or NULL) */
} mdb_dcmd_v3_t;

/*
 * For builtin modules, we set mod_init to this function, which just
 * returns a constant modinfo struct with no dcmds and walkers.
 */
static const mdb_modinfo_t *
builtin_init(void)
{
	static const mdb_modinfo_t info = { MDB_API_VERSION };
	return (&info);
}

int
mdb_module_validate_name(const char *name, const char **errmsgp)
{
	if (strlen(name) == 0) {
		*errmsgp = "no module name was specified\n";
		return (0);
	}

	if (strlen(name) > MDB_NV_NAMELEN) {
		*errmsgp = "module name '%s' exceeds name length limit\n";
		return (0);
	}

	if (strbadid(name) != NULL) {
		*errmsgp = "module name '%s' contains illegal characters\n";
		return (0);
	}

	if (mdb_nv_lookup(&mdb.m_modules, name) != NULL) {
		*errmsgp = "%s module is already loaded\n";
		return (0);
	}

	return (1);
}

int
mdb_module_create(const char *name, const char *fname, int mode,
    mdb_module_t **mpp)
{
	static const mdb_walker_t empty_walk_list[] = { 0 };
	static const mdb_dcmd_t empty_dcmd_list[] = { 0 };

	int dlmode = (mode & MDB_MOD_GLOBAL) ? RTLD_GLOBAL : RTLD_LOCAL;

	const mdb_modinfo_t *info;
	const mdb_dcmd_t *dcp;
	const mdb_walker_t *wp;

	const mdb_dcmd_v3_t *dcop;
	mdb_dcmd_t *dctp = NULL;

	mdb_module_t *mod;

	mod = mdb_zalloc(sizeof (mdb_module_t), UM_SLEEP);
	mod->mod_info = mdb_alloc(sizeof (mdb_modinfo_t), UM_SLEEP);

	(void) mdb_nv_create(&mod->mod_dcmds, UM_SLEEP);
	(void) mdb_nv_create(&mod->mod_walkers, UM_SLEEP);

	mod->mod_name = strdup(name);
	mdb.m_lmod = mod;		/* Mark module as currently loading */

	if (!(mode & MDB_MOD_BUILTIN)) {
		mdb_dprintf(MDB_DBG_MODULE, "dlopen %s %x\n", fname, dlmode);
		mod->mod_hdl = dlmopen(LM_ID_BASE, fname, RTLD_NOW | dlmode);

		if (mod->mod_hdl == NULL) {
			warn("%s\n", dlerror());
			goto err;
		}

		mod->mod_init = (const mdb_modinfo_t *(*)(void))
		    dlsym(mod->mod_hdl, "_mdb_init");

		mod->mod_fini = (void (*)(void))
		    dlsym(mod->mod_hdl, "_mdb_fini");

		mod->mod_tgt_ctor = (mdb_tgt_ctor_f *)
		    dlsym(mod->mod_hdl, "_mdb_tgt_create");

		mod->mod_dis_ctor = (mdb_dis_ctor_f *)
		    dlsym(mod->mod_hdl, "_mdb_dis_create");

		if (!(mdb.m_flags & MDB_FL_NOCTF))
			mod->mod_ctfp = mdb_ctf_open(fname, NULL);
	} else {
#ifdef _KMDB
		/*
		 * mdb_ks is a special case - a builtin with _mdb_init and
		 * _mdb_fini routines.  If we don't hack it in here, we'll have
		 * to duplicate most of the module creation code elsewhere.
		 */
		if (strcmp(name, "mdb_ks") == 0)
			mod->mod_init = mdb_ks_init;
		else
#endif
			mod->mod_init = builtin_init;
	}

	if (mod->mod_init == NULL) {
		warn("%s module is missing _mdb_init definition\n", name);
		goto err;
	}

	if ((info = mod->mod_init()) == NULL) {
		warn("%s module failed to initialize\n", name);
		goto err;
	}

	/*
	 * Reject modules compiled for a newer version of the debugger.
	 */
	if (info->mi_dvers > MDB_API_VERSION) {
		warn("%s module requires newer mdb API version (%hu) than "
		    "debugger (%d)\n", name, info->mi_dvers, MDB_API_VERSION);
		goto err;
	}

	/*
	 * Load modules compiled for the current API version.
	 */
#if MDB_API_VERSION != 5
#error "MDB_API_VERSION needs to be checked here"
#endif
	switch (info->mi_dvers) {
	case MDB_API_VERSION:
	case 4:
	case 3:
	case 2:
	case 1:
		/*
		 * Current API version -- copy entire modinfo
		 * structure into our own private storage.
		 */
		bcopy(info, mod->mod_info, sizeof (mdb_modinfo_t));
		if (mod->mod_info->mi_dcmds == NULL)
			mod->mod_info->mi_dcmds = empty_dcmd_list;
		if (mod->mod_info->mi_walkers == NULL)
			mod->mod_info->mi_walkers = empty_walk_list;
		break;
	default:
		/*
		 * Too old to be compatible -- abort the load.
		 */
		warn("%s module is compiled for obsolete mdb API "
		    "version %hu\n", name, info->mi_dvers);
		goto err;
	}

	/*
	 * In MDB_API_VERSION 4, the size of the mdb_dcmd_t struct changed. If
	 * our module is from an earlier version, we need to walk it in the old
	 * structure and convert it to the new one.
	 *
	 * Note that we purposefully don't predicate on whether or not we have
	 * the empty list case and duplicate it anyways. That case is rare and
	 * it makes our logic simpler when we need to unload the module.
	 */
	if (info->mi_dvers < 4) {
		int ii = 0;
		for (dcop = (mdb_dcmd_v3_t *)&mod->mod_info->mi_dcmds[0];
		    dcop->dco_name != NULL; dcop++)
			ii++;
		/* Don't forget null terminated one at the end */
		dctp = mdb_zalloc(sizeof (mdb_dcmd_t) * (ii + 1), UM_SLEEP);
		ii = 0;
		for (dcop = (mdb_dcmd_v3_t *)&mod->mod_info->mi_dcmds[0];
		    dcop->dco_name != NULL; dcop++, ii++) {
			dctp[ii].dc_name = dcop->dco_name;
			dctp[ii].dc_usage = dcop->dco_usage;
			dctp[ii].dc_descr = dcop->dco_descr;
			dctp[ii].dc_funcp = dcop->dco_funcp;
			dctp[ii].dc_help = dcop->dco_help;
			dctp[ii].dc_tabp = NULL;
		}
		mod->mod_info->mi_dcmds = dctp;
	}

	/*
	 * Before we actually go ahead with the load, we need to check
	 * each dcmd and walk structure for any invalid values:
	 */
	for (dcp = &mod->mod_info->mi_dcmds[0]; dcp->dc_name != NULL; dcp++) {
		if (strbadid(dcp->dc_name) != NULL) {
			warn("dcmd name '%s' contains illegal characters\n",
			    dcp->dc_name);
			goto err;
		}

		if (dcp->dc_descr == NULL) {
			warn("dcmd '%s' must have a description\n",
			    dcp->dc_name);
			goto err;
		}

		if (dcp->dc_funcp == NULL) {
			warn("dcmd '%s' has a NULL function pointer\n",
			    dcp->dc_name);
			goto err;
		}
	}

	for (wp = &mod->mod_info->mi_walkers[0]; wp->walk_name != NULL; wp++) {
		if (strbadid(wp->walk_name) != NULL) {
			warn("walk name '%s' contains illegal characters\n",
			    wp->walk_name);
			goto err;
		}

		if (wp->walk_descr == NULL) {
			warn("walk '%s' must have a description\n",
			    wp->walk_name);
			goto err;
		}

		if (wp->walk_step == NULL) {
			warn("walk '%s' has a NULL walk_step function\n",
			    wp->walk_name);
			goto err;
		}
	}

	/*
	 * Now that we've established that there are no problems,
	 * we can go ahead and hash the module, and its dcmds and walks:
	 */
	(void) mdb_nv_insert(&mdb.m_modules, mod->mod_name, NULL,
	    (uintptr_t)mod, MDB_NV_RDONLY|MDB_NV_EXTNAME);

	for (dcp = &mod->mod_info->mi_dcmds[0]; dcp->dc_name != NULL; dcp++) {
		if (mdb_module_add_dcmd(mod, dcp, mode) == -1)
			warn("failed to load dcmd %s`%s", name, dcp->dc_name);
	}

	for (wp = &mod->mod_info->mi_walkers[0]; wp->walk_name != NULL; wp++) {
		if (mdb_module_add_walker(mod, wp, mode) == -1)
			warn("failed to load walk %s`%s", name, wp->walk_name);
	}

	/*
	 * Add the module to the end of the list of modules in load-dependency
	 * order.  We maintain this list so we can unload in reverse order.
	 */
	if (mdb.m_mtail != NULL) {
		ASSERT(mdb.m_mtail->mod_next == NULL);
		mdb.m_mtail->mod_next = mod;
		mod->mod_prev = mdb.m_mtail;
		mdb.m_mtail = mod;
	} else {
		ASSERT(mdb.m_mhead == NULL);
		mdb.m_mtail = mdb.m_mhead = mod;
	}

	mdb.m_lmod = NULL;
	if (mpp != NULL)
		*mpp = mod;
	return (0);

err:
	mdb_whatis_unregister_module(mod);

	if (mod->mod_ctfp != NULL)
		ctf_close(mod->mod_ctfp);

	if (mod->mod_hdl != NULL)
		(void) dlclose(mod->mod_hdl);

	mdb_nv_destroy(&mod->mod_dcmds);
	mdb_nv_destroy(&mod->mod_walkers);

	strfree((char *)mod->mod_name);
	mdb_free(mod->mod_info, sizeof (mdb_modinfo_t));
	mdb_free(mod, sizeof (mdb_module_t));

	mdb.m_lmod = NULL;
	return (-1);
}

mdb_module_t *
mdb_module_load_builtin(const char *name)
{
	mdb_module_t *mp;

	if (mdb_module_create(name, NULL, MDB_MOD_BUILTIN, &mp) < 0)
		return (NULL);
	return (mp);
}

int
mdb_module_unload_common(const char *name)
{
	mdb_var_t *v = mdb_nv_lookup(&mdb.m_modules, name);
	mdb_module_t *mod;
	const mdb_dcmd_t *dcp;

	if (v == NULL)
		return (set_errno(EMDB_NOMOD));

	mod = mdb_nv_get_cookie(v);

	if (mod == &mdb.m_rmod || mod->mod_hdl == NULL)
		return (set_errno(EMDB_BUILTINMOD));

	mdb_dprintf(MDB_DBG_MODULE, "unloading %s\n", name);

	if (mod->mod_fini != NULL) {
		mdb_dprintf(MDB_DBG_MODULE, "calling %s`_mdb_fini\n", name);
		mod->mod_fini();
	}

	mdb_whatis_unregister_module(mod);

	if (mod->mod_ctfp != NULL)
		ctf_close(mod->mod_ctfp);

	if (mod->mod_cb != NULL)
		mdb_callb_remove_by_mod(mod);

	if (mod->mod_prev == NULL) {
		ASSERT(mdb.m_mhead == mod);
		mdb.m_mhead = mod->mod_next;
	} else
		mod->mod_prev->mod_next = mod->mod_next;

	if (mod->mod_next == NULL) {
		ASSERT(mdb.m_mtail == mod);
		mdb.m_mtail = mod->mod_prev;
	} else
		mod->mod_next->mod_prev = mod->mod_prev;

	while (mdb_nv_size(&mod->mod_walkers) != 0) {
		mdb_nv_rewind(&mod->mod_walkers);
		v = mdb_nv_peek(&mod->mod_walkers);
		(void) mdb_module_remove_walker(mod, mdb_nv_get_name(v));
	}

	while (mdb_nv_size(&mod->mod_dcmds) != 0) {
		mdb_nv_rewind(&mod->mod_dcmds);
		v = mdb_nv_peek(&mod->mod_dcmds);
		(void) mdb_module_remove_dcmd(mod, mdb_nv_get_name(v));
	}

	v = mdb_nv_lookup(&mdb.m_modules, name);
	ASSERT(v != NULL);
	mdb_nv_remove(&mdb.m_modules, v);

	(void) dlclose(mod->mod_hdl);

	mdb_nv_destroy(&mod->mod_walkers);
	mdb_nv_destroy(&mod->mod_dcmds);

	strfree((char *)mod->mod_name);

	if (mod->mod_info->mi_dvers < 4) {
		int ii = 0;

		for (dcp = &mod->mod_info->mi_dcmds[0]; dcp->dc_name != NULL;
		    dcp++)
			ii++;

		mdb_free((void *)mod->mod_info->mi_dcmds,
		    sizeof (mdb_dcmd_t) * (ii + 1));
	}

	mdb_free(mod->mod_info, sizeof (mdb_modinfo_t));
	mdb_free(mod, sizeof (mdb_module_t));

	return (0);
}

int
mdb_module_add_dcmd(mdb_module_t *mod, const mdb_dcmd_t *dcp, int flags)
{
	mdb_var_t *v = mdb_nv_lookup(&mod->mod_dcmds, dcp->dc_name);
	mdb_idcmd_t *idcp;

	uint_t nflag = MDB_NV_OVERLOAD | MDB_NV_SILENT;

	if (flags & MDB_MOD_FORCE)
		nflag |= MDB_NV_INTERPOS;

	if (v != NULL)
		return (set_errno(EMDB_DCMDEXISTS));

	idcp = mdb_alloc(sizeof (mdb_idcmd_t), UM_SLEEP);

	idcp->idc_usage = dcp->dc_usage;
	idcp->idc_descr = dcp->dc_descr;
	idcp->idc_help = dcp->dc_help;
	idcp->idc_funcp = dcp->dc_funcp;
	idcp->idc_tabp = dcp->dc_tabp;
	idcp->idc_modp = mod;

	v = mdb_nv_insert(&mod->mod_dcmds, dcp->dc_name, NULL,
	    (uintptr_t)idcp, MDB_NV_SILENT | MDB_NV_RDONLY);

	idcp->idc_name = mdb_nv_get_name(v);
	idcp->idc_var = mdb_nv_insert(&mdb.m_dcmds, idcp->idc_name, NULL,
	    (uintptr_t)v, nflag);

	mdb_dprintf(MDB_DBG_DCMD, "added dcmd %s`%s\n",
	    mod->mod_name, idcp->idc_name);

	return (0);
}

int
mdb_module_remove_dcmd(mdb_module_t *mod, const char *dname)
{
	mdb_var_t *v = mdb_nv_lookup(&mod->mod_dcmds, dname);
	mdb_idcmd_t *idcp;
	mdb_cmd_t *cp;

	if (v == NULL)
		return (set_errno(EMDB_NODCMD));

	mdb_dprintf(MDB_DBG_DCMD, "removed dcmd %s`%s\n", mod->mod_name, dname);
	idcp = mdb_nv_get_cookie(v);

	/*
	 * If we're removing a dcmd that is part of the most recent command,
	 * we need to free mdb.m_lastcp so we don't attempt to execute some
	 * text we've removed from our address space if -o repeatlast is set.
	 */
	for (cp = mdb_list_next(&mdb.m_lastc); cp; cp = mdb_list_next(cp)) {
		if (cp->c_dcmd == idcp) {
			while ((cp = mdb_list_next(&mdb.m_lastc)) != NULL) {
				mdb_list_delete(&mdb.m_lastc, cp);
				mdb_cmd_destroy(cp);
			}
			break;
		}
	}

	mdb_nv_remove(&mdb.m_dcmds, idcp->idc_var);
	mdb_nv_remove(&mod->mod_dcmds, v);
	mdb_free(idcp, sizeof (mdb_idcmd_t));

	return (0);
}

/*ARGSUSED*/
static int
default_walk_init(mdb_walk_state_t *wsp)
{
	return (WALK_NEXT);
}

/*ARGSUSED*/
static void
default_walk_fini(mdb_walk_state_t *wsp)
{
	/* Nothing to do here */
}

int
mdb_module_add_walker(mdb_module_t *mod, const mdb_walker_t *wp, int flags)
{
	mdb_var_t *v = mdb_nv_lookup(&mod->mod_walkers, wp->walk_name);
	mdb_iwalker_t *iwp;

	uint_t nflag = MDB_NV_OVERLOAD | MDB_NV_SILENT;

	if (flags & MDB_MOD_FORCE)
		nflag |= MDB_NV_INTERPOS;

	if (v != NULL)
		return (set_errno(EMDB_WALKEXISTS));

	if (wp->walk_descr == NULL || wp->walk_step == NULL)
		return (set_errno(EINVAL));

	iwp = mdb_alloc(sizeof (mdb_iwalker_t), UM_SLEEP);

	iwp->iwlk_descr = strdup(wp->walk_descr);
	iwp->iwlk_init = wp->walk_init;
	iwp->iwlk_step = wp->walk_step;
	iwp->iwlk_fini = wp->walk_fini;
	iwp->iwlk_init_arg = wp->walk_init_arg;
	iwp->iwlk_modp = mod;

	if (iwp->iwlk_init == NULL)
		iwp->iwlk_init = default_walk_init;
	if (iwp->iwlk_fini == NULL)
		iwp->iwlk_fini = default_walk_fini;

	v = mdb_nv_insert(&mod->mod_walkers, wp->walk_name, NULL,
	    (uintptr_t)iwp, MDB_NV_SILENT | MDB_NV_RDONLY);

	iwp->iwlk_name = mdb_nv_get_name(v);
	iwp->iwlk_var = mdb_nv_insert(&mdb.m_walkers, iwp->iwlk_name, NULL,
	    (uintptr_t)v, nflag);

	mdb_dprintf(MDB_DBG_WALK, "added walk %s`%s\n",
	    mod->mod_name, iwp->iwlk_name);

	return (0);
}

int
mdb_module_remove_walker(mdb_module_t *mod, const char *wname)
{
	mdb_var_t *v = mdb_nv_lookup(&mod->mod_walkers, wname);
	mdb_iwalker_t *iwp;

	if (v == NULL)
		return (set_errno(EMDB_NOWALK));

	mdb_dprintf(MDB_DBG_WALK, "removed walk %s`%s\n", mod->mod_name, wname);

	iwp = mdb_nv_get_cookie(v);
	mdb_nv_remove(&mdb.m_walkers, iwp->iwlk_var);
	mdb_nv_remove(&mod->mod_walkers, v);

	strfree(iwp->iwlk_descr);
	mdb_free(iwp, sizeof (mdb_iwalker_t));

	return (0);
}

void
mdb_module_unload_all(int mode)
{
	mdb_module_t *mod, *pmod;

	/*
	 * We unload modules in the reverse order in which they were loaded
	 * so as to allow _mdb_fini routines to invoke code which may be
	 * present in a previously-loaded module (such as mdb_ks, etc.).
	 */
	for (mod = mdb.m_mtail; mod != NULL; mod = pmod) {
		pmod =  mod->mod_prev;
		(void) mdb_module_unload(mod->mod_name, mode);
	}
}
