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
 *
 * Copyright 2018 Joyent, Inc.
 */

/*
 * Kernel Process View Target
 *
 * The kproc target is activated when the user is debugging a kernel using the
 * kvm target and executes a ::context dcmd to change the debugger view to one
 * of the running processes.  The kvm target's t_setcontext operation will
 * create and activate a kproc target in response to this call.  The kproc
 * target itself is built upon the kvm target's libkvm cookie and the ability
 * to read information from the kernel itself and the ability to read the
 * address space of a particular user process with kvm_aread().  It also relies
 * on a special set of functions provided by the kvm target's mdb_ks support
 * module in order to bootstrap: specifically, given the initial proc pointer,
 * mdb_ks provides functions to return the set of address space mappings, the
 * address space pointer itself, the aux vector vector saved in the u-area,
 * and the process data model.  The kproc target maintains a list of address
 * space mappings (kp_map_t) and load objects (kp_file_t), and for each load
 * object will attempt to read the corresponding dynamic symbol table.  In
 * order to bootstrap, the target uses the AT_BASE and AT_ENTRY aux vector
 * elements to locate the dynamic linker and executable mappings.  With these
 * mappings in place, we initialize a librtld_db agent on the target (see
 * mdb_pservice.c for how this is done), and then process each load object
 * found in the link-map chain.  In order to simplify the construction of
 * symbol tables for each load object, we would like make use of our existing
 * library of GElf processing code.  Since the MDB GElf code uses mdb_io
 * objects to read in an ELF file, we simply define a new type of mdb_io object
 * where each read operation is translated into a call to kproc's t_vread
 * function to read from the range of the address space defined by the mapping
 * as if it were a file.
 */

#include <sys/types.h>
#include <sys/proc.h>
#include <sys/auxv.h>

#include <strings.h>
#include <limits.h>
#include <rtld_db.h>
#include <procfs.h>
#include <dlfcn.h>
#include <kvm.h>

#include <mdb/mdb_target_impl.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_string.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_ks.h>
#include <mdb/mdb_gelf.h>
#include <mdb/mdb_io_impl.h>
#include <mdb/mdb.h>

typedef struct kp_symarg {
	mdb_tgt_sym_f *sym_cb;		/* Caller's callback function */
	void *sym_data;			/* Callback function argument */
	uint_t sym_type;		/* Symbol type/binding filter */
	uintptr_t sym_adjust;		/* Symbol value adjustment */
	mdb_syminfo_t sym_info;		/* Symbol id and table id */
	const char *sym_obj;		/* Containing object */
} kp_symarg_t;

typedef struct kp_file {
	mdb_gelf_file_t *kpf_file;	/* ELF file object */
	mdb_io_t *kpf_fio;		/* ELF file back-end */
	mdb_gelf_symtab_t *kpf_dynsym;	/* Dynamic symbol table */
	struct kp_map *kpf_map;		/* Primary (text) mapping */
	const char *kpf_basename;	/* Mapping basename */
	uintptr_t kpf_dyn_base;		/* Load address for ET_DYN files */
	uintptr_t kpf_text_base;	/* Base address of text mapping */
	uintptr_t kpf_data_base;	/* Base address of data mapping */
	struct kp_file *kpf_next;	/* Pointer to next file */
} kp_file_t;

typedef struct kp_map {
	mdb_map_t kpm_map;		/* Mapping information */
	kp_file_t *kpm_file;		/* Pointer to load object */
	struct kp_map *kpm_next;	/* Pointer to next mapping */
} kp_map_t;

typedef struct kp_io {
	mdb_tgt_t *kpi_tgt;		/* Backpointer to kproc target */
	kp_map_t *kpi_map;		/* Mapping for this i/o */
	uintptr_t kpi_ptr;		/* Virtual address pointer */
	uintptr_t kpi_lim;		/* Virtual address limit */
} kp_io_t;

typedef struct kp_data {
	mdb_tgt_t *kp_parent;		/* Parent kvm target */
	kvm_t *kp_cookie;		/* Cookie for libkvm routines */
	rd_agent_t *kp_rap;		/* Cookie for librtld_db routines */
	proc_t *kp_proc;		/* Proc address in dump */
	struct as *kp_as;		/* Proc as address in dump */
	pid_t kp_pid;			/* Process ID */
	auxv_t *kp_auxv;		/* Auxv array from u-area */
	int kp_nauxv;			/* Length of kp_auxv */
	const char *kp_platform;	/* Platform string from kvm target */
	uint_t kp_model;		/* Process data model */
	kp_file_t *kp_file_head;	/* Head of load object list */
	kp_file_t *kp_file_tail;	/* Tail of load object list */
	kp_map_t *kp_map_head;		/* Head of mapping list */
	kp_map_t *kp_map_tail;		/* Tail of mapping list */
	int kp_num_files;		/* Length of load object list */
	int kp_num_maps;		/* Length of mapping list */
	kp_map_t *kp_map_exec;		/* Executable mapping */
	kp_map_t *kp_map_ldso;		/* Interpreter mapping */
	kp_file_t kp_prfile;		/* Fake file for mdb.m_prsym */
} kp_data_t;

static mdb_io_t *kp_io_create(mdb_tgt_t *, kp_map_t *);

static kp_map_t *
kp_addr_to_kpmap(kp_data_t *kp, uintptr_t addr)
{
	kp_map_t *kpm;

	for (kpm = kp->kp_map_head; kpm != NULL; kpm = kpm->kpm_next) {
		if (addr >= kpm->kpm_map.map_base &&
		    addr < kpm->kpm_map.map_base + kpm->kpm_map.map_size)
			return (kpm);
	}

	return (NULL);
}

static long
kp_getauxval(kp_data_t *kp, int type)
{
	auxv_t *auxp;

	for (auxp = kp->kp_auxv; auxp->a_type != AT_NULL; auxp++) {
		if (auxp->a_type == type)
			return (auxp->a_un.a_val);
	}

	return (-1L);
}

static void
kp_add_mapping(const mdb_map_t *pmp, void *data)
{
	kp_map_t *kpm = mdb_zalloc(sizeof (kp_map_t), UM_SLEEP);
	kp_data_t *kp = data;

	bcopy(pmp, &kpm->kpm_map, sizeof (mdb_map_t));

	if (kp->kp_map_tail != NULL)
		kp->kp_map_tail->kpm_next = kpm;
	else
		kp->kp_map_head = kpm;

	kp->kp_map_tail = kpm;
	kp->kp_num_maps++;
}

static kp_file_t *
kp_file_create(mdb_tgt_t *t, kp_map_t *kpm, GElf_Half etype)
{
	kp_file_t *kpf = mdb_zalloc(sizeof (kp_file_t), UM_SLEEP);
	kp_data_t *kp = t->t_data;
	size_t dyns_sz;
	void *dyns;

	kpf->kpf_fio = kp_io_create(t, kpm);
	kpf->kpf_map = kpm;
	kpf->kpf_basename = strbasename(kpm->kpm_map.map_name);
	kpf->kpf_file = mdb_gelf_create(kpf->kpf_fio, etype, GF_PROGRAM);
	kpf->kpf_text_base = kpm->kpm_map.map_base;

	if (kpm != kp->kp_map_exec)
		kpf->kpf_dyn_base = kpf->kpf_text_base;

	if (kpf->kpf_file == NULL)
		goto err; /* Failed to create ELF file */

	mdb_dprintf(MDB_DBG_TGT, "loading symbols for %s\n",
	    kpm->kpm_map.map_name);

	if ((kp->kp_rap != NULL) && (rd_get_dyns(kp->kp_rap,
	    kpf->kpf_text_base, &dyns, &dyns_sz) == RD_OK))
		mdb_gelf_dyns_set(kpf->kpf_file, dyns, dyns_sz);

	kpf->kpf_dynsym = mdb_gelf_symtab_create_dynamic(kpf->kpf_file,
	    MDB_TGT_DYNSYM);

	if (kpf->kpf_dynsym == NULL)
		goto err; /* Failed to create symbol table */

	kpm->kpm_file = kpf;

	if (kp->kp_file_tail != NULL)
		kp->kp_file_tail->kpf_next = kpf;
	else
		kp->kp_file_head = kpf;

	kp->kp_file_tail = kpf;
	kp->kp_num_files++;

	return (kpf);

err:
	if (kpf->kpf_file != NULL)
		mdb_gelf_destroy(kpf->kpf_file);
	else
		mdb_io_destroy(kpf->kpf_fio);
	mdb_free(kpf, sizeof (kp_file_t));
	return (NULL);
}

static void
kp_file_destroy(kp_file_t *kpf)
{
	if (kpf->kpf_dynsym != NULL)
		mdb_gelf_symtab_destroy(kpf->kpf_dynsym);

	mdb_gelf_destroy(kpf->kpf_file);
	mdb_free(kpf, sizeof (kp_file_t));
}

static int
kp_setcontext(mdb_tgt_t *t, void *context)
{
	kp_data_t *kp = t->t_data;

	if (kp->kp_proc != context) {
		mdb_tgt_destroy(t);
		return (mdb_tgt_setcontext(mdb.m_target, context));
	}

	mdb_warn("debugger context is already set to proc %p\n", context);
	return (0);
}

static kp_map_t *
kp_find_data(kp_data_t *kp, kp_file_t *kpf, const rd_loadobj_t *rlp)
{
	GElf_Phdr *gpp = kpf->kpf_file->gf_phdrs;
	size_t i, n = kpf->kpf_file->gf_npload;

	/*
	 * Find the first loadable, writeable Phdr and compute kpf_data_base
	 * as the virtual address at which is was loaded.
	 */
	for (i = 0; i < n; i++, gpp++) {
		if (gpp->p_type == PT_LOAD && (gpp->p_flags & PF_W)) {
			kpf->kpf_data_base = gpp->p_vaddr;
			if (kpf->kpf_map != kp->kp_map_exec)
				kpf->kpf_data_base += rlp->rl_base;
			break;
		}
	}

	/*
	 * If we found a suitable Phdr and set kpf_data_base, return
	 * the mapping information for this address; otherwise fail.
	 */
	if (kpf->kpf_data_base != 0)
		return (kp_addr_to_kpmap(kp, kpf->kpf_data_base));

	return (NULL);
}

static int
kp_iter_mapping(const rd_loadobj_t *rlp, mdb_tgt_t *t)
{
	kp_data_t *kp = t->t_data;
	kp_file_t *kpf;
	kp_map_t *kpm;

	char name[MDB_TGT_MAPSZ];

	if (mdb_tgt_readstr(t, MDB_TGT_AS_VIRT, name,
	    sizeof (name), (mdb_tgt_addr_t)rlp->rl_nameaddr) <= 0) {
		mdb_dprintf(MDB_DBG_TGT, "failed to read name %p",
		    (void *)rlp->rl_nameaddr);
		return (1); /* Keep going; forget this if we can't read name */
	}

	mdb_dprintf(MDB_DBG_TGT, "rd_loadobj name = \"%s\" rl_base = %p\n",
	    name, (void *)rlp->rl_base);

	if ((kpm = kp_addr_to_kpmap(kp, rlp->rl_base)) == NULL)
		return (1); /* Keep going; no mapping at this address */

	(void) strncpy(kpm->kpm_map.map_name, name, MDB_TGT_MAPSZ);
	kpm->kpm_map.map_name[MDB_TGT_MAPSZ - 1] = '\0';

	if ((kpf = kpm->kpm_file) == NULL) {
		if (kpm == kp->kp_map_exec)
			kpf = kp_file_create(t, kpm, ET_EXEC);
		else
			kpf = kp_file_create(t, kpm, ET_DYN);

		if (kpf == NULL)
			return (1); /* Keep going; failed to build ELF file */
	} else
		kpf->kpf_basename = strbasename(kpm->kpm_map.map_name);

	if ((kpm = kp_find_data(kp, kpf, rlp)) != NULL) {
		mdb_dprintf(MDB_DBG_TGT, "found data for %s at %p\n",
		    kpf->kpf_basename, (void *)kpm->kpm_map.map_base);
		kpm->kpm_file = kpf;
	}

	return (1);
}

/*ARGSUSED*/
static int
kp_status_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	kp_data_t *kp = mdb.m_target->t_data;

	mdb_printf("debugging PID %d (%d-bit) in kernel crash dump\n",
	    kp->kp_pid, kp->kp_model == PR_MODEL_ILP32 ? 32 : 64);

	if (kp->kp_map_exec != NULL) {
		mdb_printf("executable file: %s\n",
		    kp->kp_map_exec->kpm_map.map_name);
	}

	return (DCMD_OK);
}

static const mdb_dcmd_t kp_dcmds[] = {
	{ "status", NULL, "print summary of current target", kp_status_dcmd },
	{ NULL }
};

static void
kp_activate(mdb_tgt_t *t)
{
	kp_data_t *kp = t->t_data;

	mdb_prop_postmortem = TRUE;
	mdb_prop_kernel = FALSE;

	if (kp->kp_model == PR_MODEL_ILP32)
		mdb_prop_datamodel = MDB_TGT_MODEL_ILP32;
	else
		mdb_prop_datamodel = MDB_TGT_MODEL_LP64;

	/*
	 * Initialize our rtld_db agent and then iterate over the link map,
	 * instantiating kp_file objects as we go.
	 */
	if ((kp->kp_rap = rd_new((struct ps_prochandle *)t)) != NULL) {
		(void) rd_loadobj_iter(kp->kp_rap, (rl_iter_f *)
		    kp_iter_mapping, t);
	} else {
		mdb_warn("unable to initialize rtld_db agent for proc %p\n",
		    (void *)kp->kp_proc);
	}

	(void) mdb_tgt_register_dcmds(t, &kp_dcmds[0], MDB_MOD_FORCE);

	if (kp->kp_map_exec != NULL && kp->kp_map_exec->kpm_file != NULL)
		mdb_tgt_elf_export(kp->kp_map_exec->kpm_file->kpf_file);
	else
		mdb_tgt_elf_export(NULL);
}

static void
kp_deactivate(mdb_tgt_t *t)
{
	const mdb_dcmd_t *dcp;

	for (dcp = &kp_dcmds[0]; dcp->dc_name != NULL; dcp++) {
		if (mdb_module_remove_dcmd(t->t_module, dcp->dc_name) == -1)
			warn("failed to remove dcmd %s", dcp->dc_name);
	}

	mdb_prop_postmortem = FALSE;
	mdb_prop_kernel = FALSE;
	mdb_prop_datamodel = MDB_TGT_MODEL_UNKNOWN;
}

static void
kp_destroy(mdb_tgt_t *t)
{
	kp_data_t *kp = t->t_data;
	kp_map_t *kpm, *nkpm;
	kp_file_t *kpf, *nkpf;

	if (kp->kp_rap != NULL)
		rd_delete(kp->kp_rap);

	for (kpm = kp->kp_map_head; kpm != NULL; kpm = nkpm) {
		nkpm = kpm->kpm_next;
		mdb_free(kpm, sizeof (kp_map_t));
	}

	for (kpf = kp->kp_file_head; kpf != NULL; kpf = nkpf) {
		nkpf = kpf->kpf_next;
		kp_file_destroy(kpf);
	}

	mdb_free(kp->kp_auxv, kp->kp_nauxv * sizeof (auxv_t));
	mdb_free(kp, sizeof (kp_data_t));
}

/*ARGSUSED*/
static const char *
kp_name(mdb_tgt_t *t)
{
	return ("kproc");
}

static const char *
kp_isa(mdb_tgt_t *t)
{
	kp_data_t *kp = t->t_data;
#ifdef __sparc
	return (kp->kp_model == PR_MODEL_ILP32 ? "sparc" : "sparcv9");
#else
	return (kp->kp_model == PR_MODEL_ILP32 ? "i386" : "amd64");
#endif
}

static const char *
kp_platform(mdb_tgt_t *t)
{
	return (((kp_data_t *)t->t_data)->kp_platform);
}

static int
kp_uname(mdb_tgt_t *t, struct utsname *utsp)
{
	kp_data_t *kp = t->t_data;
	return (mdb_tgt_uname(kp->kp_parent, utsp));
}

static int
kp_dmodel(mdb_tgt_t *t)
{
	kp_data_t *kp = t->t_data;

	switch (kp->kp_model) {
	case PR_MODEL_ILP32:
		return (MDB_TGT_MODEL_ILP32);
	case PR_MODEL_LP64:
		return (MDB_TGT_MODEL_LP64);
	}

	return (MDB_TGT_MODEL_UNKNOWN);
}

static kp_map_t *
kp_name_to_kpmap(kp_data_t *kp, const char *name)
{
	size_t namelen;
	kp_file_t *kpf;
	kp_map_t *kpm;

	/*
	 * Handle special reserved names (except for MDB_TGT_OBJ_EVERY):
	 */
	if (name == MDB_TGT_OBJ_EXEC)
		return (kp->kp_map_exec);

	if (name == MDB_TGT_OBJ_RTLD)
		return (kp->kp_map_ldso);

	/*
	 * First pass: look for exact matches on the entire pathname
	 * associated with the mapping or its basename.
	 */
	for (kpm = kp->kp_map_head; kpm != NULL; kpm = kpm->kpm_next) {
		if ((kpf = kpm->kpm_file) != NULL) {
			if (strcmp(kpm->kpm_map.map_name, name) == 0 ||
			    strcmp(kpf->kpf_basename, name) == 0)
				return (kpf->kpf_map);
		}
	}

	namelen = strlen(name);

	/*
	 * Second pass: look for partial matches (initial basename match
	 * up to a '.' suffix); allows "libc.so" or "libc" to match "libc.so.1"
	 */
	for (kpm = kp->kp_map_head; kpm != NULL; kpm = kpm->kpm_next) {
		if ((kpf = kpm->kpm_file) != NULL) {
			if (strncmp(kpf->kpf_basename, name, namelen) == 0 &&
			    kpf->kpf_basename[namelen] == '.')
				return (kpf->kpf_map);
		}
	}

	/*
	 * One last check: we allow "a.out" to always alias the executable,
	 * assuming this name was not in use for something else.
	 */
	if (strcmp(name, "a.out") == 0)
		return (kp->kp_map_exec);

	return (NULL);
}


static ssize_t
kp_vread(mdb_tgt_t *t, void *buf, size_t nbytes, uintptr_t addr)
{
	kp_data_t *kp = t->t_data;
	ssize_t n = kvm_aread(kp->kp_cookie, addr, buf, nbytes, kp->kp_as);

	if (n == -1)
		return (set_errno(EMDB_NOMAP));

	return (n);
}

static ssize_t
kp_vwrite(mdb_tgt_t *t, const void *buf, size_t nbytes, uintptr_t addr)
{
	kp_data_t *kp = t->t_data;
	ssize_t n = kvm_awrite(kp->kp_cookie, addr, buf, nbytes, kp->kp_as);

	if (n == -1)
		return (set_errno(EMDB_NOMAP));

	return (n);
}


int
kp_vtop(mdb_tgt_t *t, mdb_tgt_as_t as, uintptr_t va, physaddr_t *pap)
{
	kp_data_t *kp = t->t_data;
	physaddr_t pa;

	if (as != MDB_TGT_AS_VIRT)
		return (set_errno(EINVAL));

	if ((pa = kvm_physaddr(kp->kp_cookie, kp->kp_as, va)) != -1ULL) {
		*pap = pa;
		return (0);
	}

	return (set_errno(EMDB_NOMAP));
}

static int
kp_lookup_by_name(mdb_tgt_t *t, const char *object,
    const char *name, GElf_Sym *symp, mdb_syminfo_t *sip)
{
	kp_data_t *kp = t->t_data;
	kp_file_t *kpf;
	int n;

	GElf_Sym sym;
	uint_t symid;
	int rv = -1;

	/*
	 * Simplify our task: if object is EVERY, then we need to search
	 * kp_num_files files beginning at kp_file_head; otherwise we are
	 * searching 1 file whose file pointer is obtained via object_to_map.
	 */
	if (object != MDB_TGT_OBJ_EVERY) {
		kp_map_t *kpm = kp_name_to_kpmap(kp, object);
		if (kpm == NULL || kpm->kpm_file == NULL)
			return (set_errno(EMDB_NOOBJ));
		kpf = kpm->kpm_file;
		n = 1;
	} else {
		kpf = kp->kp_file_head;
		n = kp->kp_num_files;
	}

	/*
	 * Iterate through the load object files and look for the symbol name
	 * in the .dynsym of each.  If we encounter a match with SHN_UNDEF,
	 * keep looking in hopes of finding a better match.  This means that
	 * a name such as "puts" will match the puts function in libc instead
	 * of matching the puts PLT entry in the a.out file.
	 */
	for (; n > 0; n--, kpf = kpf->kpf_next) {
		if (kpf->kpf_dynsym == NULL)
			continue; /* No symbols for this file */

		if (mdb_gelf_symtab_lookup_by_name(kpf->kpf_dynsym,
		    name, symp, &sip->sym_id) != 0)
			continue; /* Symbol name not found */

		symp->st_value += kpf->kpf_dyn_base;

		if (symp->st_shndx != SHN_UNDEF) {
			sip->sym_table = MDB_TGT_DYNSYM;
			return (0);
		}

		if (rv != 0) {
			sym = *symp;
			symid = sip->sym_id;
			rv = 0;
		}
	}

	if (rv != 0)
		return (set_errno(EMDB_NOSYM));

	sip->sym_table = MDB_TGT_DYNSYM;
	sip->sym_id = symid;
	*symp = sym;

	return (0);
}

static int
kp_lookup_by_addr(mdb_tgt_t *t, uintptr_t addr, uint_t flags,
    char *buf, size_t nbytes, GElf_Sym *symp, mdb_syminfo_t *sip)
{
	kp_data_t *kp = t->t_data;
	kp_map_t *kpm = kp_addr_to_kpmap(kp, addr);

	kp_file_t *sym_kpf = NULL;
	GElf_Sym sym;
	uint_t symid;

	const char *name;
	kp_file_t *kpf;
	int n;

	/*
	 * Check the user's private symbol table first; if a match is
	 * found there, we're done or we have a first guess.
	 */
	if (mdb_gelf_symtab_lookup_by_addr(mdb.m_prsym,
	    addr, flags, buf, nbytes, symp, &sip->sym_id) == 0) {
		sym_kpf = &kp->kp_prfile;
		if (flags & MDB_TGT_SYM_EXACT)
			goto found;
		sym = *symp;
		symid = sip->sym_id;
	}

	/*
	 * If no mapping contains the address and EXACT mode is set, we're done.
	 * Otherwise we need to search all the symbol tables in fuzzy mode.
	 * If we find a mapping, then we only need to search that symtab.
	 */
	if (kpm == NULL || kpm->kpm_file == NULL) {
		if (flags & MDB_TGT_SYM_EXACT)
			return (set_errno(EMDB_NOSYMADDR));
		kpf = kp->kp_file_head;
		n = kp->kp_num_files;
	} else {
		kpf = kpm->kpm_file;
		n = 1;
	}

	/*
	 * Iterate through our list of load objects, scanning each one which
	 * has a symbol table.  In fuzzy mode, we continue looking and
	 * improve our choice if we find a closer symbol.
	 */
	for (; n > 0; n--, kpf = kpf->kpf_next) {
		if (kpf->kpf_dynsym == NULL)
			continue; /* No symbols for this file */

		if (mdb_gelf_symtab_lookup_by_addr(kpf->kpf_dynsym,
		    addr - kpf->kpf_dyn_base, flags, buf, nbytes,
		    symp, &sip->sym_id) != 0)
			continue; /* No symbol for this address */

		symp->st_value += kpf->kpf_dyn_base;

		if (flags & MDB_TGT_SYM_EXACT) {
			sym_kpf = kpf;
			goto found;
		}

		if (sym_kpf == NULL || mdb_gelf_sym_closer(symp, &sym, addr)) {
			sym_kpf = kpf;
			sym = *symp;
			symid = sip->sym_id;
		}
	}

	if (sym_kpf == NULL)
		return (set_errno(EMDB_NOSYMADDR));

	*symp = sym;	/* Copy our best symbol into the caller's symbol */
	sip->sym_id = symid;
found:
	/*
	 * Once we've found something, copy the final name into the caller's
	 * buffer and prefix it with the load object name if appropriate.
	 */
	name = mdb_gelf_sym_name(sym_kpf->kpf_dynsym, symp);

	if (sym_kpf != kp->kp_map_exec->kpm_file && sym_kpf != &kp->kp_prfile) {
		(void) mdb_snprintf(buf, nbytes, "%s`%s",
		    sym_kpf->kpf_basename, name);
	} else if (nbytes > 0) {
		(void) strncpy(buf, name, nbytes);
		buf[nbytes - 1] = '\0';
	}

	if (sym_kpf == &kp->kp_prfile)
		sip->sym_table = MDB_TGT_PRVSYM;
	else
		sip->sym_table = MDB_TGT_DYNSYM;

	return (0);
}

static int
kp_symtab_func(void *data, const GElf_Sym *symp, const char *name, uint_t id)
{
	kp_symarg_t *argp = data;
	if (mdb_tgt_sym_match(symp, argp->sym_type)) {
		GElf_Sym sym = *symp;

		sym.st_value += argp->sym_adjust;

		argp->sym_info.sym_id = id;

		return (argp->sym_cb(argp->sym_data, &sym, name,
		    &argp->sym_info, argp->sym_obj));
	}

	return (0);
}

static void
kp_symtab_iter(kp_file_t *kpf, uint_t type, const char *obj,
    mdb_tgt_sym_f *cb, void *data)
{
	if (kpf->kpf_dynsym != NULL) {
		kp_symarg_t arg;

		arg.sym_cb = cb;
		arg.sym_data = data;
		arg.sym_type = type;
		arg.sym_adjust = kpf->kpf_dyn_base;
		arg.sym_info.sym_table = kpf->kpf_dynsym->gst_tabid;
		arg.sym_obj = obj;

		mdb_gelf_symtab_iter(kpf->kpf_dynsym, kp_symtab_func, &arg);
	}
}

/*ARGSUSED*/
static int
kp_symbol_iter(mdb_tgt_t *t, const char *object, uint_t which,
    uint_t type, mdb_tgt_sym_f *func, void *private)
{
	kp_data_t *kp = t->t_data;
	kp_file_t *kpf = NULL;
	kp_map_t *kpm;

	switch ((uintptr_t)object) {
	case (uintptr_t)MDB_TGT_OBJ_EVERY:
		if (kp->kp_map_exec && kp->kp_map_exec->kpm_file) {
			kpf = kp->kp_map_exec->kpm_file;
			kp_symtab_iter(kpf, type, MDB_TGT_OBJ_EXEC, func,
			    private);
		}
		if (kp->kp_map_ldso && kp->kp_map_ldso->kpm_file) {
			kpf = kp->kp_map_ldso->kpm_file;
			kp_symtab_iter(kpf, type, MDB_TGT_OBJ_RTLD, func,
			    private);
		}
		return (0);

	case (uintptr_t)MDB_TGT_OBJ_EXEC:
		if (kp->kp_map_exec && kp->kp_map_exec->kpm_file)
			kpf = kp->kp_map_exec->kpm_file;
		break;

	case (uintptr_t)MDB_TGT_OBJ_RTLD:
		if (kp->kp_map_ldso && kp->kp_map_ldso->kpm_file)
			kpf = kp->kp_map_ldso->kpm_file;
		break;

	default:
		if ((kpm = kp_name_to_kpmap(kp, object)) != NULL) {
			kpf = kpm->kpm_file;
			break;
		} else
			return (set_errno(EMDB_NOOBJ));
	}

	if (kpf != NULL)
		kp_symtab_iter(kpf, type, object, func, private);

	return (0);
}

static int
kp_mapping_iter(mdb_tgt_t *t, mdb_tgt_map_f *func, void *private)
{
	kp_data_t *kp = t->t_data;
	kp_map_t *kpm;

	for (kpm = kp->kp_map_head; kpm != NULL; kpm = kpm->kpm_next) {
		if (func(private, &kpm->kpm_map, kpm->kpm_map.map_name) != 0)
			break;
	}

	return (0);
}

static int
kp_object_iter(mdb_tgt_t *t, mdb_tgt_map_f *func, void *private)
{
	kp_data_t *kp = t->t_data;
	kp_file_t *kpf;

	for (kpf = kp->kp_file_head; kpf != NULL; kpf = kpf->kpf_next) {
		if (func(private, &kpf->kpf_map->kpm_map,
		    kpf->kpf_map->kpm_map.map_name) != 0)
			break;
	}

	return (0);
}

static const mdb_map_t *
kp_addr_to_map(mdb_tgt_t *t, uintptr_t addr)
{
	kp_map_t *kpm = kp_addr_to_kpmap(t->t_data, addr);

	if (kpm != NULL)
		return (&kpm->kpm_map);

	(void) set_errno(EMDB_NOMAP);
	return (NULL);
}

static const mdb_map_t *
kp_name_to_map(mdb_tgt_t *t, const char *name)
{
	kp_map_t *kpm = kp_name_to_kpmap(t->t_data, name);

	if (kpm != NULL)
		return (&kpm->kpm_map);

	(void) set_errno(EMDB_NOOBJ);
	return (NULL);
}

/*ARGSUSED*/
static int
kp_status(mdb_tgt_t *t, mdb_tgt_status_t *tsp)
{
	bzero(tsp, sizeof (mdb_tgt_status_t));
	tsp->st_state = MDB_TGT_DEAD;
	return (0);
}

static int
kp_auxv(mdb_tgt_t *t, const auxv_t **auxvp)
{
	kp_data_t *kp = t->t_data;
	*auxvp = kp->kp_auxv;
	return (0);
}

static const mdb_tgt_ops_t kproc_ops = {
	(int (*)()) mdb_tgt_notsup,		/* t_setflags */
	kp_setcontext,				/* t_setcontext */
	kp_activate,				/* t_activate */
	kp_deactivate,				/* t_deactivate */
	(void (*)()) mdb_tgt_nop,		/* t_periodic */
	kp_destroy,				/* t_destroy */
	kp_name,				/* t_name */
	kp_isa,					/* t_isa */
	kp_platform,				/* t_platform */
	kp_uname,				/* t_uname */
	kp_dmodel,				/* t_dmodel */
	(ssize_t (*)()) mdb_tgt_notsup,		/* t_aread */
	(ssize_t (*)()) mdb_tgt_notsup,		/* t_awrite */
	kp_vread,				/* t_vread */
	kp_vwrite,				/* t_vwrite */
	(ssize_t (*)()) mdb_tgt_notsup,		/* t_pread */
	(ssize_t (*)()) mdb_tgt_notsup,		/* t_pwrite */
	(ssize_t (*)()) mdb_tgt_notsup,		/* t_fread */
	(ssize_t (*)()) mdb_tgt_notsup,		/* t_fwrite */
	(ssize_t (*)()) mdb_tgt_notsup,		/* t_ioread */
	(ssize_t (*)()) mdb_tgt_notsup,		/* t_iowrite */
	kp_vtop,				/* t_vtop */
	kp_lookup_by_name,			/* t_lookup_by_name */
	kp_lookup_by_addr,			/* t_lookup_by_addr */
	kp_symbol_iter,				/* t_symbol_iter */
	kp_mapping_iter,			/* t_mapping_iter */
	kp_object_iter,				/* t_object_iter */
	kp_addr_to_map,				/* t_addr_to_map */
	kp_name_to_map,				/* t_name_to_map */
	(struct ctf_file *(*)()) mdb_tgt_null,	/* t_addr_to_ctf */
	(struct ctf_file *(*)()) mdb_tgt_null,	/* t_name_to_ctf */
	kp_status,				/* t_status */
	(int (*)()) mdb_tgt_notsup,		/* t_run */
	(int (*)()) mdb_tgt_notsup,		/* t_step */
	(int (*)()) mdb_tgt_notsup,		/* t_step_out */
	(int (*)()) mdb_tgt_notsup,		/* t_next */
	(int (*)()) mdb_tgt_notsup,		/* t_cont */
	(int (*)()) mdb_tgt_notsup,		/* t_signal */
	(int (*)()) mdb_tgt_null,		/* t_add_sbrkpt */
	(int (*)()) mdb_tgt_null,		/* t_add_vbrkpt */
	(int (*)()) mdb_tgt_null,		/* t_add_pwapt */
	(int (*)()) mdb_tgt_null,		/* t_add_vwapt */
	(int (*)()) mdb_tgt_null,		/* t_add_iowapt */
	(int (*)()) mdb_tgt_null,		/* t_add_sysenter */
	(int (*)()) mdb_tgt_null,		/* t_add_sysexit */
	(int (*)()) mdb_tgt_null,		/* t_add_signal */
	(int (*)()) mdb_tgt_null,		/* t_add_fault */
	(int (*)()) mdb_tgt_notsup,		/* t_getareg XXX */
	(int (*)()) mdb_tgt_notsup,		/* t_putareg XXX */
	(int (*)()) mdb_tgt_notsup,		/* t_stack_iter XXX */
	kp_auxv					/* t_auxv */
};

int
mdb_kproc_tgt_create(mdb_tgt_t *t, int argc, const char *argv[])
{
	kp_data_t *kp = mdb_zalloc(sizeof (kp_data_t), UM_SLEEP);
	void *proc = (void *)argv[0];
	long at_entry, at_base;
	GElf_Sym sym;

	int (*f_asiter)(uintptr_t, void (*)(const mdb_map_t *, void *), void *);
	int (*f_auxv)(uintptr_t, auxv_t *);
	uintptr_t (*f_as)(uintptr_t);
	uint_t (*f_model)(uintptr_t);
	pid_t (*f_pid)(uintptr_t);

	if (argc != 1)
		return (set_errno(EINVAL));

	t->t_flags &= ~MDB_TGT_F_RDWR;
	t->t_data = kp;
	t->t_ops = &kproc_ops;

	f_asiter = (int (*)()) dlsym(RTLD_NEXT, "mdb_kproc_asiter");
	f_auxv = (int (*)()) dlsym(RTLD_NEXT, "mdb_kproc_auxv");
	f_as = (uintptr_t (*)()) dlsym(RTLD_NEXT, "mdb_kproc_as");
	f_model = (model_t (*)()) dlsym(RTLD_NEXT, "mdb_kproc_model");
	f_pid = (pid_t (*)()) dlsym(RTLD_NEXT, "mdb_kproc_pid");

	if (f_asiter == NULL || f_auxv == NULL ||
	    f_as == NULL || f_model == NULL || f_pid == NULL) {
		warn("required kernel support module is not loaded\n");
		goto err;
	}

	/*
	 * Here the kproc target relies on the fact that at the time of its
	 * instantiation, mdb.m_target is pointing at a kvm target, and
	 * that the kvm target has stored its libkvm handle in t_pshandle.
	 */
	kp->kp_parent = mdb.m_target;
	kp->kp_cookie = mdb.m_target->t_pshandle;
	kp->kp_platform = mdb_tgt_platform(mdb.m_target);
	kp->kp_proc = proc;
	kp->kp_as = (struct as *)f_as((uintptr_t)proc);
	kp->kp_pid = f_pid((uintptr_t)proc);

	if (kp->kp_as == NULL) {
		warn("failed to obtain address space for proc %p\n", proc);
		goto err;
	}

	if (kp->kp_pid == -1) {
		warn("failed to obtain PID for proc %p\n", proc);
		goto err;
	}

	if (mdb_tgt_lookup_by_name(kp->kp_parent, MDB_TGT_OBJ_EXEC, "kas",
	    &sym, NULL) == 0 && kp->kp_as ==
	    (struct as *)(uintptr_t)sym.st_value) {
		warn("specified process is a system process (no context)\n");
		goto err;
	}

	if ((kp->kp_model = f_model((uintptr_t)proc)) == PR_MODEL_UNKNOWN) {
		warn("failed to obtain data model for proc %p\n", proc);
		goto err;
	}

	if (f_asiter((uintptr_t)kp->kp_as, kp_add_mapping, kp) == -1) {
		warn("failed to load mappings for proc %p", proc);
		goto err;
	}

	kp->kp_nauxv = f_auxv((uintptr_t)proc, NULL) + 1;
	kp->kp_auxv = mdb_alloc(sizeof (auxv_t) * kp->kp_nauxv, UM_SLEEP);

	if (f_auxv((uintptr_t)proc, kp->kp_auxv) == -1) {
		warn("failed to load auxv for proc %p", proc);
		goto err;
	}

	kp->kp_auxv[kp->kp_nauxv - 1].a_type = AT_NULL;
	kp->kp_auxv[kp->kp_nauxv - 1].a_un.a_val = 0;

	if ((at_entry = kp_getauxval(kp, AT_ENTRY)) == -1L) {
		warn("auxv for proc %p is missing AT_ENTRY\n", proc);
		goto err;
	}

	if ((at_base = kp_getauxval(kp, AT_BASE)) == -1L) {
		warn("auxv for proc %p is missing AT_BASE\n", proc);
		goto err;
	}

	/*
	 * If we're applying kproc to a live kernel, we need to force libkvm
	 * to set the current process to the process in question so we can
	 * read from its address space.  If kvm_getproc returns NULL, the
	 * process may have gone away since our previous calls to mdb_ks.
	 */
	if (mdb_prop_postmortem == FALSE &&
	    kvm_getproc(kp->kp_cookie, kp->kp_pid) == NULL)
		warn("failed to attach to PID %d\n", (int)kp->kp_pid);

	kp->kp_map_exec = kp_addr_to_kpmap(kp, at_entry);
	kp->kp_map_ldso = kp_addr_to_kpmap(kp, at_base);

	(void) kp_file_create(t, kp->kp_map_exec, ET_EXEC);
	(void) kp_file_create(t, kp->kp_map_ldso, ET_DYN);

	kp->kp_prfile.kpf_dynsym = mdb.m_prsym;

	return (0);

err:
	kp_destroy(t);
	return (-1);
}

static ssize_t
kp_io_read(mdb_io_t *io, void *buf, size_t nbytes)
{
	kp_io_t *kpi = io->io_data;
	kp_data_t *kp = kpi->kpi_tgt->t_data;

	kp_map_t *kpm = kp_addr_to_kpmap(kp, kpi->kpi_ptr);
	size_t left;

	if (kpm != NULL) {
		const mdb_map_t *mp = &kpm->kpm_map;
		left = mp->map_base + mp->map_size - kpi->kpi_ptr;
	} else
		left = 0;

	if (left != 0) {
		ssize_t rbytes = kp_vread(kpi->kpi_tgt,
		    buf, MIN(nbytes, left), kpi->kpi_ptr);

		if (rbytes >= 0)
			kpi->kpi_ptr += rbytes;

		return (rbytes);
	}

	return (0); /* At end of segment or in hole; return EOF */
}

static off64_t
kp_io_seek(mdb_io_t *io, off64_t offset, int whence)
{
	kp_io_t *kpi = io->io_data;
	const mdb_map_t *mp = &kpi->kpi_map->kpm_map;
	uintptr_t nptr;

	if (io->io_next != NULL)
		return (IOP_SEEK(io->io_next, offset, whence));

	switch (whence) {
	case SEEK_SET:
		nptr = mp->map_base + offset;
		break;
	case SEEK_CUR:
		nptr = kpi->kpi_ptr + offset;
		break;
	case SEEK_END:
		nptr = kpi->kpi_lim + offset;
		break;
	default:
		return (set_errno(EINVAL));
	}

	if (nptr < mp->map_base || nptr >= kpi->kpi_lim)
		return (set_errno(EINVAL));

	kpi->kpi_ptr = nptr;
	return ((off64_t)(nptr - mp->map_base));
}

static void
kp_io_close(mdb_io_t *io)
{
	mdb_free(io->io_data, sizeof (kp_io_t));
}

static const char *
kp_io_name(mdb_io_t *io)
{
	kp_io_t *kpi = io->io_data;

	if (io->io_next != NULL)
		return (IOP_NAME(io->io_next));

	return (kpi->kpi_map->kpm_map.map_name);
}

static const mdb_io_ops_t kp_io_ops = {
	kp_io_read,
	no_io_write,
	kp_io_seek,
	no_io_ctl,
	kp_io_close,
	kp_io_name,
	no_io_link,
	no_io_unlink,
	no_io_setattr,
	no_io_suspend,
	no_io_resume
};

static mdb_io_t *
kp_io_create(mdb_tgt_t *t, kp_map_t *kpm)
{
	kp_data_t *kp = t->t_data;
	mdb_map_t *mp = &kp->kp_map_tail->kpm_map;

	mdb_io_t *io = mdb_alloc(sizeof (mdb_io_t), UM_SLEEP);
	kp_io_t *kpi = mdb_alloc(sizeof (kp_io_t), UM_SLEEP);

	kpi->kpi_tgt = t;
	kpi->kpi_map = kpm;
	kpi->kpi_ptr = kpm->kpm_map.map_base;
	kpi->kpi_lim = mp->map_base + mp->map_size;

	io->io_ops = &kp_io_ops;
	io->io_data = kpi;
	io->io_next = NULL;
	io->io_refcnt = 0;

	return (io);
}
