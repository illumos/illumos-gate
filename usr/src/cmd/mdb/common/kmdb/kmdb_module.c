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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Routines for manipulating the kmdb-specific aspects of dmods.
 */

#include <sys/param.h>

#include <mdb/mdb_target_impl.h>
#include <kmdb/kmdb_module.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb.h>

typedef struct kmod_symarg {
	mdb_tgt_sym_f *sym_cb;		/* Caller's callback function */
	void *sym_data;			/* Callback function argument */
	uint_t sym_type;		/* Symbol type/binding filter */
	mdb_syminfo_t sym_info;		/* Symbol id and table id */
	const char *sym_obj;		/* Containing object */
} kmod_symarg_t;

void
kmdb_module_path_set(const char **path, size_t pathlen)
{
	kmdb_wr_path_t *wr;

	wr = mdb_zalloc(sizeof (kmdb_wr_path_t), UM_SLEEP);
	wr->dpth_node.wn_task = WNTASK_DMOD_PATH_CHANGE;
	wr->dpth_path = mdb_path_dup(path, pathlen, &wr->dpth_pathlen);

	kmdb_wr_driver_notify(wr);
}

void
kmdb_module_path_ack(kmdb_wr_path_t *dpth)
{
	if (dpth->dpth_path != NULL)
		mdb_path_free(dpth->dpth_path, dpth->dpth_pathlen);
	mdb_free(dpth, sizeof (kmdb_wr_path_t));
}

static kmdb_modctl_t *
kmdb_module_lookup_loaded(const char *name)
{
	kmdb_modctl_t *kmc;
	mdb_var_t *v;

	if ((v = mdb_nv_lookup(&mdb.m_dmodctl, name)) == NULL)
		return (NULL);

	kmc = MDB_NV_COOKIE(v);
	if (kmc->kmc_state != KMDB_MC_STATE_LOADED)
		return (NULL);

	return (kmc);
}

/*
 * Given an address, try to match it up with a dmod symbol.
 */
int
kmdb_module_lookup_by_addr(uintptr_t addr, uint_t flags, char *buf,
    size_t nbytes, GElf_Sym *symp, mdb_syminfo_t *sip)
{
	kmdb_modctl_t *sym_kmc = NULL;
	GElf_Sym sym;
	uint_t symid;
	mdb_var_t *v;
	const char *name;

	mdb_nv_rewind(&mdb.m_dmodctl);
	while ((v = mdb_nv_advance(&mdb.m_dmodctl)) != NULL) {
		kmdb_modctl_t *kmc = MDB_NV_COOKIE(v);

		if (kmc->kmc_state != KMDB_MC_STATE_LOADED)
			continue;

		if (mdb_gelf_symtab_lookup_by_addr(kmc->kmc_symtab, addr, flags,
		    buf, nbytes, symp, &sip->sym_id) != 0 ||
		    symp->st_value == 0)
			continue;

		if (flags & MDB_TGT_SYM_EXACT) {
			sym_kmc = kmc;
			goto found;
		}

		/*
		 * If this is the first match we've found, or if this symbol is
		 * closer to the specified address than the last one we found,
		 * use it.
		 */
		if (sym_kmc == NULL || mdb_gelf_sym_closer(symp, &sym, addr)) {
			sym_kmc = kmc;
			sym = *symp;
			symid = sip->sym_id;
		}
	}

	if (sym_kmc == NULL)
		return (set_errno(EMDB_NOSYMADDR));

	*symp = sym;
	sip->sym_id = symid;

found:
	/*
	 * Once we've found something, copy the final name into the caller's
	 * buffer, prefixed with a marker identifying this as a dmod symbol.
	 */
	if (buf != NULL) {
		name = mdb_gelf_sym_name(sym_kmc->kmc_symtab, symp);

		(void) mdb_snprintf(buf, nbytes, "DMOD`%s`%s",
		    sym_kmc->kmc_modname, name);
	}
	sip->sym_table = MDB_TGT_SYMTAB;

	return (0);
}

/*
 * Locate a given dmod symbol
 */
int
kmdb_module_lookup_by_name(const char *obj, const char *name, GElf_Sym *symp,
    mdb_syminfo_t *sip)
{
	kmdb_modctl_t *kmc;

	if ((kmc = kmdb_module_lookup_loaded(obj)) == NULL)
		return (set_errno(EMDB_NOSYMADDR));

	if (mdb_gelf_symtab_lookup_by_name(kmc->kmc_symtab, name,
	    symp, &sip->sym_id) == 0) {
		sip->sym_table = MDB_TGT_SYMTAB;
		return (0);
	}

	return (set_errno(EMDB_NOSYM));
}

ctf_file_t *
kmdb_module_addr_to_ctf(uintptr_t addr)
{
	mdb_var_t *v;

	mdb_nv_rewind(&mdb.m_dmodctl);
	while ((v = mdb_nv_advance(&mdb.m_dmodctl)) != NULL) {
		kmdb_modctl_t *kmc = MDB_NV_COOKIE(v);
		struct module *mp;

		if (kmc->kmc_state != KMDB_MC_STATE_LOADED)
			continue;

		mp = kmc->kmc_modctl->mod_mp;
		if (addr - (uintptr_t)mp->text < mp->text_size ||
		    addr - (uintptr_t)mp->data < mp->data_size ||
		    addr - mp->bss < mp->bss_size) {
			ctf_file_t *ctfp = kmc->kmc_mod->mod_ctfp;

			if (ctfp == NULL) {
				(void) set_errno(EMDB_NOCTF);
				return (NULL);
			}

			return (ctfp);
		}
	}

	(void) set_errno(EMDB_NOMAP);
	return (NULL);
}

ctf_file_t *
kmdb_module_name_to_ctf(const char *obj)
{
	kmdb_modctl_t *kmc;
	ctf_file_t *ctfp;

	if ((kmc = kmdb_module_lookup_loaded(obj)) == NULL) {
		(void) set_errno(EMDB_NOOBJ);
		return (NULL);
	}

	if ((ctfp = kmc->kmc_mod->mod_ctfp) == NULL) {
		(void) set_errno(EMDB_NOCTF);
		return (NULL);
	}

	return (ctfp);
}

static int
kmdb_module_symtab_func(void *data, const GElf_Sym *sym, const char *name,
    uint_t id)
{
	kmod_symarg_t *arg = data;

	if (mdb_tgt_sym_match(sym, arg->sym_type)) {
		arg->sym_info.sym_id = id;

		return (arg->sym_cb(arg->sym_data, sym, name, &arg->sym_info,
		    arg->sym_obj));
	}

	return (0);
}

int
kmdb_module_symbol_iter(const char *obj, uint_t type, mdb_tgt_sym_f *cb,
    void *p)
{
	kmdb_modctl_t *kmc;
	kmod_symarg_t arg;
	mdb_var_t *v;

	if ((v = mdb_nv_lookup(&mdb.m_dmodctl, obj)) == NULL)
		return (set_errno(EMDB_NOMOD));

	kmc = MDB_NV_COOKIE(v);

	if (kmc->kmc_state != KMDB_MC_STATE_LOADED)
		return (set_errno(EMDB_NOMOD));

	arg.sym_cb = cb;
	arg.sym_data = p;
	arg.sym_type = type;
	arg.sym_info.sym_table = kmc->kmc_symtab->gst_tabid;
	arg.sym_obj = obj;

	mdb_gelf_symtab_iter(kmc->kmc_symtab, kmdb_module_symtab_func, &arg);

	return (0);
}
