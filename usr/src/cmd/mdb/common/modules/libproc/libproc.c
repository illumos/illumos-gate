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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2025 Oxide Computer Company
 */

#include <libproc.h>
#include <Pcontrol.h>
#include <stddef.h>

#include <mdb/mdb_modapi.h>

typedef struct ps_prochandle ps_prochandle_t;

/*
 * addr::pr_symtab [-a | n]
 *
 *	-a	Sort symbols by address
 *	-n	Sort symbols by name
 *
 * Given a sym_tbl_t, dump its contents in tabular form.  When given '-a' or
 * '-n', we use the sorted tables 'sym_byaddr' or 'sym_byname', respectively.
 */
static int
pr_symtab(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	sym_tbl_t symtab;
	Elf_Data data_pri;
	Elf_Data data_aux;
	Elf_Data *data;
#ifdef _LP64
	Elf64_Sym sym;
	int width = 16;
#else
	Elf32_Sym sym;
	int width = 8;
#endif
	int i, idx, count;
	char name[128];
	int byaddr = FALSE;
	int byname = FALSE;
	uint_t *symlist;
	size_t symlistsz;

	if (mdb_getopts(argc, argv,
	    'a', MDB_OPT_SETBITS, TRUE, &byaddr,
	    'n', MDB_OPT_SETBITS, TRUE, &byname,
	    NULL) != argc)
		return (DCMD_USAGE);

	if (byaddr && byname) {
		mdb_warn("only one of '-a' or '-n' can be specified\n");
		return (DCMD_USAGE);
	}

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&symtab, sizeof (sym_tbl_t), addr) == -1) {
		mdb_warn("failed to read sym_tbl_t at %p", addr);
		return (DCMD_ERR);
	}

	if (symtab.sym_count == 0) {
		mdb_warn("no symbols present\n");
		return (DCMD_ERR);
	}

	/*
	 * As described in the libproc header Pcontrol.h, a sym_tbl_t
	 * contains a primary and an optional auxiliary symbol table.
	 * We treat the combination as a single table, with the auxiliary
	 * values coming before the primary ones.
	 *
	 * Read the primary and auxiliary Elf_Data structs.
	 */
	if (mdb_vread(&data_pri, sizeof (Elf_Data),
	    (uintptr_t)symtab.sym_data_pri) == -1) {
		mdb_warn("failed to read primary Elf_Data at %p",
		    symtab.sym_data_pri);
		return (DCMD_ERR);
	}
	if ((symtab.sym_symn_aux > 0) &&
	    (mdb_vread(&data_aux, sizeof (Elf_Data),
	    (uintptr_t)symtab.sym_data_aux) == -1)) {
		mdb_warn("failed to read auxiliary Elf_Data at %p",
		    symtab.sym_data_aux);
		return (DCMD_ERR);
	}

	symlist = NULL;
	if (byaddr || byname) {
		uintptr_t src = byaddr ? (uintptr_t)symtab.sym_byaddr :
		    (uintptr_t)symtab.sym_byname;

		symlistsz = symtab.sym_count * sizeof (uint_t);
		symlist = mdb_alloc(symlistsz, UM_SLEEP);
		if (mdb_vread(symlist, symlistsz, src) == -1) {
			mdb_warn("failed to read sorted symbols at %p", src);
			return (DCMD_ERR);
		}
		count = symtab.sym_count;
	} else {
		count = symtab.sym_symn;
	}

	mdb_printf("%<u>%*s  %*s  %s%</u>\n", width, "ADDRESS", width,
	    "SIZE", "NAME");

	for (i = 0; i < count; i++) {
		if (byaddr | byname)
			idx = symlist[i];
		else
			idx = i;

		/* If index is in range of primary symtab, look it up there */
		if (idx >= symtab.sym_symn_aux) {
			data = &data_pri;
			idx -= symtab.sym_symn_aux;
		} else {	/* Look it up in the auxiliary symtab */
			data = &data_aux;
		}

		if (mdb_vread(&sym, sizeof (sym), (uintptr_t)data->d_buf +
		    idx * sizeof (sym)) == -1) {
			mdb_warn("failed to read symbol at %p",
			    (uintptr_t)data->d_buf + idx * sizeof (sym));
			if (symlist)
				mdb_free(symlist, symlistsz);
			return (DCMD_ERR);
		}

		if (mdb_readstr(name, sizeof (name),
		    (uintptr_t)symtab.sym_strs + sym.st_name) == -1) {
			mdb_warn("failed to read symbol name at %p",
			    symtab.sym_strs + sym.st_name);
			name[0] = '\0';
		}

		mdb_printf("%0?p  %0?p  %s\n", sym.st_value, sym.st_size,
		    name);
	}

	if (symlist)
		mdb_free(symlist, symlistsz);

	return (DCMD_OK);
}

/*
 * addr::pr_addr2map search
 *
 * Given a ps_prochandle_t, convert the given address to the corresponding
 * map_info_t.  Functionally equivalent to Paddr2mptr().
 */
static int
pr_addr2map(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uintptr_t search;
	ps_prochandle_t psp;
	map_info_t *mp;
	int lo, hi, mid;

	if (!(flags & DCMD_ADDRSPEC) || argc != 1)
		return (DCMD_USAGE);

	search = (uintptr_t)mdb_argtoull(&argv[0]);

	if (mdb_vread(&psp, sizeof (ps_prochandle_t), addr) == -1) {
		mdb_warn("failed to read ps_prochandle at %p", addr);
		return (DCMD_ERR);
	}

	lo = 0;
	hi = psp.map_count;
	while (lo <= hi) {
		mid = (lo + hi) / 2;
		mp = &psp.mappings[mid];

		if ((addr - mp->map_pmap.pr_vaddr) < mp->map_pmap.pr_size) {
			mdb_printf("%#lr\n", addr + offsetof(ps_prochandle_t,
			    mappings) + (mp - psp.mappings) *
			    sizeof (map_info_t));
			return (DCMD_OK);
		}

		if (addr < mp->map_pmap.pr_vaddr)
			hi = mid - 1;
		else
			lo = mid + 1;
	}

	mdb_warn("no corresponding map for %p\n", search);
	return (DCMD_ERR);
}

/*
 * ::walk pr_file_info
 *
 * Given a ps_prochandle_t, walk all its file_info_t structures.
 */
static int
pr_file_info_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == 0) {
		mdb_warn("pr_file_info doesn't support global walks\n");
		return (WALK_ERR);
	}

	wsp->walk_addr += offsetof(ps_prochandle_t, file_head);
	if (mdb_layered_walk("list", wsp) == -1) {
		mdb_warn("failed to walk layered 'list'");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

static int
pr_file_info_walk_step(mdb_walk_state_t *wsp)
{
	return (wsp->walk_callback(wsp->walk_addr, wsp->walk_layer,
	    wsp->walk_cbdata));
}

/*
 * ::walk pr_map_info
 *
 * Given a ps_prochandle_t, walk all its map_info_t structures.
 */
typedef struct {
	uintptr_t	miw_next;
	int		miw_count;
	int		miw_current;
} map_info_walk_t;

static int
pr_map_info_walk_init(mdb_walk_state_t *wsp)
{
	ps_prochandle_t psp;
	map_info_walk_t *miw;

	if (wsp->walk_addr == 0) {
		mdb_warn("pr_map_info doesn't support global walks\n");
		return (WALK_ERR);
	}

	if (mdb_vread(&psp, sizeof (ps_prochandle_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to read ps_prochandle at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	miw = mdb_alloc(sizeof (map_info_walk_t), UM_SLEEP);

	miw->miw_next = (uintptr_t)psp.mappings;
	miw->miw_count = psp.map_count;
	miw->miw_current = 0;
	wsp->walk_data = miw;

	return (WALK_NEXT);
}

static int
pr_map_info_walk_step(mdb_walk_state_t *wsp)
{
	map_info_walk_t *miw = wsp->walk_data;
	map_info_t m;
	int status;

	if (miw->miw_current == miw->miw_count)
		return (WALK_DONE);

	if (mdb_vread(&m, sizeof (map_info_t), miw->miw_next) == -1) {
		mdb_warn("failed to read map_info_t at %p", miw->miw_next);
		return (WALK_DONE);
	}

	status = wsp->walk_callback(miw->miw_next, &m, wsp->walk_cbdata);

	miw->miw_current++;
	miw->miw_next += sizeof (map_info_t);

	return (status);
}

static void
pr_map_info_walk_fini(mdb_walk_state_t *wsp)
{
	map_info_walk_t *miw = wsp->walk_data;
	mdb_free(miw, sizeof (map_info_walk_t));
}

static const mdb_dcmd_t dcmds[] = {
	{ "pr_addr2map",  ":addr", "convert an adress into a map_info_t",
	    pr_addr2map },
	{ "pr_symtab",	":[-a | -n]", "print the contents of a sym_tbl_t",
	    pr_symtab },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "pr_file_info", "given a ps_prochandle, walk its file_info "
	    "structures", pr_file_info_walk_init, pr_file_info_walk_step },
	{ "pr_map_info", "given a ps_prochandle, walk its map_info structures",
	    pr_map_info_walk_init, pr_map_info_walk_step,
	    pr_map_info_walk_fini },
	{ NULL }
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION, dcmds, walkers
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
