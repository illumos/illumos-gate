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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2025 Edgecast Cloud LLC.
 */

#include <sys/param.h>
#include <sys/modctl.h>
#include <sys/kobj.h>
#include <sys/kobj_impl.h>
#include <unistd.h>
#include <strings.h>
#include <dlfcn.h>
#include <link.h>

#include <kmdb/kmdb_module.h>
#include <kmdb/kmdb_wr_impl.h>
#include <kmdb/kmdb_kdi.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_string.h>
#include <mdb/mdb_ctf.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_io.h>
#include <mdb/mdb_frame.h>
#include <mdb/mdb.h>

static void kmdb_module_request_unload(kmdb_modctl_t *, const char *, int);

static void
kmc_free(kmdb_modctl_t *kmc)
{
	if (kmc->kmc_modname != NULL)
		strfree(kmc->kmc_modname);
	mdb_free(kmc, sizeof (kmdb_modctl_t));
}

/*
 * Sends a request to the driver to load the module.
 */
int
mdb_module_load(const char *fname, int mode)
{
	const char *modname = strbasename(fname);
	kmdb_wr_load_t *dlr;
	kmdb_modctl_t *kmc = NULL;
	const char *wformat = NULL;
	mdb_var_t *v;

	if (!mdb_module_validate_name(modname, &wformat))
		goto module_load_err;

	if ((v = mdb_nv_lookup(&mdb.m_dmodctl, modname)) != NULL) {
		kmc = MDB_NV_COOKIE(v);

		if (kmc->kmc_state == KMDB_MC_STATE_LOADING)
			wformat = "module %s is already being loaded\n";
		else
			wformat = "module %s is being unloaded\n";
		goto module_load_err;
	}

	kmc = mdb_zalloc(sizeof (kmdb_modctl_t), UM_SLEEP);
	kmc->kmc_loadmode = mode;
	kmc->kmc_modname = strdup(modname);
	kmc->kmc_state = KMDB_MC_STATE_LOADING;

	if (mdb_nv_insert(&mdb.m_dmodctl, modname, NULL, (uintptr_t)kmc, 0) ==
	    NULL) {
		wformat = "module %s can't be registered for load\n";
		kmc_free(kmc);
		goto module_load_err;
	}

	dlr = mdb_zalloc(sizeof (kmdb_wr_load_t), UM_SLEEP);
	dlr->dlr_node.wn_task = WNTASK_DMOD_LOAD;
	dlr->dlr_fname = strdup(fname);

	kmdb_wr_driver_notify(dlr);

	if (!(mode & MDB_MOD_DEFER) &&
	    mdb_tgt_continue(mdb.m_target, NULL) == 0)
		return (0);

	if (!(mode & MDB_MOD_SILENT))
		mdb_printf("%s load pending (:c to complete)\n", modname);

	return (0);

module_load_err:
	if (!(mode & MDB_MOD_SILENT))
		warn(wformat, modname);

	return (-1);
}

/*
 * Module load post processing. Either clean up from error or
 * update modctl state.
 */
boolean_t
kmdb_module_loaded(kmdb_wr_load_t *dlr)
{
	struct modctl *modp = dlr->dlr_modctl;
	const char *modname = strbasename(dlr->dlr_fname);
	struct module *mp;
	kmdb_modctl_t *kmc = NULL;
	mdb_var_t *v;

	v = mdb_nv_lookup(&mdb.m_dmodctl, modname);

	if (dlr->dlr_errno != 0) {
		/*
		 * We're somewhat limited in the diagnostics that we can
		 * provide in the event of a failed load.  In most load-failure
		 * cases, the driver can only send up a generic errno.  We use
		 * EMDB_ENOMOD to signal generic errors, and supply our own
		 * message.  This twists the meaning of EMDB_NOMOD somewhat, but
		 * it's better than defining a new one.
		 */
		if (dlr->dlr_errno == EMDB_NOMOD) {
			mdb_warn("%s does not appear to be a kmdb dmod\n",
			    modname);
		} else {
			(void) set_errno(dlr->dlr_errno);
			mdb_warn("dmod %s failed to load", modname);
		}

		if (v != NULL)
			mdb_nv_remove(&mdb.m_dmodctl, v);
		return (B_FALSE);
	}

	if ((mp = modp->mod_mp) == NULL || mp->symhdr == NULL ||
	    mp->strhdr == NULL || mp->symtbl == NULL || mp->strings == NULL) {
		mdb_warn("dmod %s did not load properly\n");
		return (B_FALSE);
	}

	if (v == NULL) {
		kmc = mdb_zalloc(sizeof (kmdb_modctl_t), UM_SLEEP);
		kmc->kmc_loadmode = MDB_MOD_LOCAL;
		kmc->kmc_modname = strdup(modname);
		kmc->kmc_state = KMDB_MC_STATE_LOADING;

		(void) mdb_nv_insert(&mdb.m_dmodctl, modname, NULL,
		    (uintptr_t)kmc, 0);
	} else {
		kmc = MDB_NV_COOKIE(v);
		ASSERT(kmc->kmc_symtab == NULL);
	}

	kmc->kmc_modctl = modp;
	kmc->kmc_exported = (mp->flags & KOBJ_EXPORTED) != 0;
	mdb_gelf_ehdr_to_gehdr(&mp->hdr, &kmc->kmc_ehdr);

	kmc->kmc_symtab = mdb_gelf_symtab_create_raw(&kmc->kmc_ehdr, mp->symhdr,
	    mp->symtbl, mp->strhdr, mp->strings,
	    MDB_TGT_SYMTAB);

	if (mp->flags & KOBJ_PRIM)
		kmc->kmc_flags |= KMDB_MC_FL_NOUNLOAD;

	if (mdb_module_create(modname, modp->mod_filename,
	    kmc->kmc_loadmode, &kmc->kmc_mod) < 0) {
		if (kmc->kmc_symtab != NULL)
			mdb_gelf_symtab_destroy(kmc->kmc_symtab);

		kmdb_module_request_unload(kmc, kmc->kmc_modname,
		    MDB_MOD_DEFER);
		return (B_FALSE);
	}

	kmc->kmc_state = KMDB_MC_STATE_LOADED;

	return (B_TRUE);
}

void
kmdb_module_load_ack(kmdb_wr_load_t *dlr)
{
	strfree(dlr->dlr_fname);
	mdb_free(dlr, sizeof (kmdb_wr_load_t));
}

void
mdb_module_load_all(int mode)
{
	kmdb_wr_t *wn;

	ASSERT(mode & MDB_MOD_DEFER);

	wn = mdb_zalloc(sizeof (kmdb_wr_t), UM_SLEEP);
	wn->wn_task = WNTASK_DMOD_LOAD_ALL;

	kmdb_wr_driver_notify(wn);
}

void
kmdb_module_load_all_ack(kmdb_wr_t *wn)
{
	mdb_free(wn, sizeof (kmdb_wr_t));
}

static void
kmdb_module_request_unload(kmdb_modctl_t *kmc, const char *modname, int mode)
{
	kmdb_wr_unload_t *dur = mdb_zalloc(sizeof (kmdb_wr_unload_t), UM_SLEEP);
	dur->dur_node.wn_task = WNTASK_DMOD_UNLOAD;
	dur->dur_modname = strdup(modname);
	dur->dur_modctl = kmc->kmc_modctl;

	kmdb_wr_driver_notify(dur);

	kmc->kmc_state = KMDB_MC_STATE_UNLOADING;

	if (!(mode & MDB_MOD_DEFER) &&
	    mdb_tgt_continue(mdb.m_target, NULL) == 0)
		return;

	if (!(mode & MDB_MOD_SILENT))
		mdb_printf("%s unload pending (:c to complete)\n", modname);
}

/*ARGSUSED*/
int
mdb_module_unload(const char *name, int mode)
{
	kmdb_modctl_t *kmc = NULL;
	const char *basename;
	mdb_var_t *v;

	/*
	 * We may have been called with the name from the module itself
	 * if the caller is iterating through the module list, so we need
	 * to make a copy of the name.  If we don't, we can't use it after
	 * the call to unload_common(), which frees the module.
	 */
	name = strdup(name);
	basename = strbasename(name);

	/*
	 * Make sure the module is in the proper state for unloading.  Modules
	 * may only be unloaded if they have properly completed loading.
	 */
	if ((v = mdb_nv_lookup(&mdb.m_dmodctl, basename)) != NULL) {
		kmc = MDB_NV_COOKIE(v);
		switch (kmc->kmc_state) {
		case KMDB_MC_STATE_LOADING:
			warn("%s is in the process of loading\n", basename);
			return (set_errno(EMDB_NOMOD));
		case KMDB_MC_STATE_UNLOADING:
			warn("%s is already being unloaded\n", basename);
			return (set_errno(EMDB_NOMOD));
		default:
			ASSERT(kmc->kmc_state == KMDB_MC_STATE_LOADED);
		}

		if (kmc->kmc_flags & KMDB_MC_FL_NOUNLOAD)
			return (set_errno(EMDB_KMODNOUNLOAD));
	}

	if (mdb_module_unload_common(name) < 0) {
		if (!(mode & MDB_MOD_SILENT)) {
			mdb_dprintf(MDB_DBG_MODULE, "unload of %s failed\n",
			    name);
		}
		return (-1); /* errno is set for us */
	}

	/*
	 * Any modules legitimately not listed in dmodctl (builtins, for
	 * example) will be handled by mdb_module_unload_common.  If any of
	 * them get here, we've got a problem.
	 */
	if (v == NULL) {
		warn("unload of unregistered module %s\n", basename);
		return (set_errno(EMDB_NOMOD));
	}

	ASSERT(kmc->kmc_dlrefcnt == 0);

	mdb_gelf_symtab_destroy(kmc->kmc_symtab);

	kmdb_module_request_unload(kmc, basename, mode);
	return (0);
}

boolean_t
kmdb_module_unloaded(kmdb_wr_unload_t *dur)
{
	mdb_var_t *v;

	if ((v = mdb_nv_lookup(&mdb.m_dmodctl, dur->dur_modname)) == NULL) {
		mdb_warn("unload for unrequested module %s\n",
		    dur->dur_modname);
		return (B_FALSE);
	}

	if (dur->dur_errno != 0) {
		mdb_warn("dmod %s failed to unload", dur->dur_modname);
		return (B_FALSE);
	}

	kmc_free(MDB_NV_COOKIE(v));
	mdb_nv_remove(&mdb.m_dmodctl, v);

	return (B_TRUE);
}

void
kmdb_module_unload_ack(kmdb_wr_unload_t *dur)
{
	if (dur->dur_modname != NULL)
		strfree(dur->dur_modname);
	mdb_free(dur, sizeof (kmdb_wr_unload_t));
}

/*
 * Called by the kmdb_kvm target upon debugger reentry, this routine checks
 * to see if the loaded dmods have changed.  Of particular interest is the
 * exportation of dmod symbol tables, which will happen during the boot
 * process for dmods that were loaded prior to kernel startup.  If this
 * has occurred, we'll need to reconstruct our view of the symbol tables for
 * the affected dmods, since the old symbol tables lived in bootmem
 * and have been moved during the kobj_export_module().
 *
 * Also, any ctf_file_t we might have opened is now invalid, since it
 * has internal pointers to the old data as well.
 */
void
kmdb_module_sync(void)
{
	mdb_var_t *v;

	mdb_nv_rewind(&mdb.m_dmodctl);
	while ((v = mdb_nv_advance(&mdb.m_dmodctl)) != NULL) {
		kmdb_modctl_t *kmc = MDB_NV_COOKIE(v);
		struct module *mp;

		if (kmc->kmc_state != KMDB_MC_STATE_LOADED)
			continue;

		mp = kmc->kmc_modctl->mod_mp;

		if ((mp->flags & (KOBJ_PRIM | KOBJ_EXPORTED)) &&
		    !kmc->kmc_exported) {
			/*
			 * The exporting process moves the symtab from boot
			 * scratch memory to vmem.
			 */
			if (kmc->kmc_symtab != NULL)
				mdb_gelf_symtab_destroy(kmc->kmc_symtab);

			kmc->kmc_symtab = mdb_gelf_symtab_create_raw(
			    &kmc->kmc_ehdr, mp->symhdr, mp->symtbl, mp->strhdr,
			    mp->strings, MDB_TGT_SYMTAB);

			if (kmc->kmc_mod->mod_ctfp != NULL) {
				ctf_close(kmc->kmc_mod->mod_ctfp);
				kmc->kmc_mod->mod_ctfp =
				    mdb_ctf_open(kmc->kmc_modname, NULL);
			}
			kmc->kmc_exported = TRUE;
		}
	}
}
