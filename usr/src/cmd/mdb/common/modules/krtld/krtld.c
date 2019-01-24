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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/machelf.h>
#include <sys/modctl.h>
#include <sys/kobj.h>

#include <mdb/mdb_modapi.h>

static uintptr_t module_head; /* Head of kernel modctl list */

struct modctl_walk_data {
	uintptr_t mwd_head;
	struct modctl mwd_modctl;
};

static int
modctl_walk_init(mdb_walk_state_t *wsp)
{
	struct modctl_walk_data *mwd = mdb_alloc(
	    sizeof (struct modctl_walk_data), UM_SLEEP);

	mwd->mwd_head = (wsp->walk_addr == 0 ? module_head : wsp->walk_addr);
	wsp->walk_data = mwd;
	wsp->walk_addr = 0;

	return (WALK_NEXT);
}

static int
modctl_walk_step(mdb_walk_state_t *wsp)
{
	struct modctl_walk_data *mwd = wsp->walk_data;
	int	status;

	if (wsp->walk_addr == mwd->mwd_head)
		return (WALK_DONE);

	if (wsp->walk_addr == 0)
		wsp->walk_addr = mwd->mwd_head;

	if (mdb_vread(&mwd->mwd_modctl, sizeof (struct modctl),
	    wsp->walk_addr) == -1) {
		mdb_warn("failed to read modctl at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, &mwd->mwd_modctl,
	    wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)mwd->mwd_modctl.mod_next;

	return (status);
}

static void
modctl_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (struct modctl_walk_data));
}

/*ARGSUSED*/
static int
modctl_format(uintptr_t addr, const void *data, void *private)
{
	const struct modctl *mcp = (const struct modctl *)data;
	char name[MAXPATHLEN], bits[6], *bp = &bits[0];

	if (mdb_readstr(name, sizeof (name),
	    (uintptr_t)mcp->mod_filename) == -1)
		(void) strcpy(name, "???");

	if (mcp->mod_busy)
		*bp++ = 'b';
	if (mcp->mod_want)
		*bp++ = 'w';
	if (mcp->mod_prim)
		*bp++ = 'p';
	if (mcp->mod_loaded)
		*bp++ = 'l';
	if (mcp->mod_installed)
		*bp++ = 'i';
	*bp = '\0';

	mdb_printf("%?p %?p %6s 0x%02x %3d %s\n",
	    (uintptr_t)addr, (uintptr_t)mcp->mod_mp, bits, mcp->mod_loadflags,
	    mcp->mod_ref, name);

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
modctls(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (argc != 0)
		return (DCMD_USAGE);

	if ((flags & DCMD_LOOPFIRST) || !(flags & DCMD_LOOP)) {
		mdb_printf("%<u>%?s %?s %6s %4s %3s %s%</u>\n",
		    "MODCTL", "MODULE", "BITS", "FLAGS", "REF", "FILE");
	}

	if (flags & DCMD_ADDRSPEC) {
		struct modctl mc;

		(void) mdb_vread(&mc, sizeof (mc), addr);
		return (modctl_format(addr, &mc, NULL));
	}

	if (mdb_walk("modctl", modctl_format, NULL) == -1)
		return (DCMD_ERR);

	return (DCMD_OK);
}

static void
dump_ehdr(const Ehdr *ehdr)
{
	mdb_printf("\nELF Header\n");

	mdb_printf("  ei_magic:  { 0x%02x, %c, %c, %c }\n",
	    ehdr->e_ident[EI_MAG0], ehdr->e_ident[EI_MAG1],
	    ehdr->e_ident[EI_MAG2], ehdr->e_ident[EI_MAG3]);

	mdb_printf("  ei_class:  %-18u      ei_data: %-16u\n",
	    ehdr->e_ident[EI_CLASS], ehdr->e_ident[EI_DATA]);

	mdb_printf("  e_machine: %-18hu    e_version: %-16u\n",
	    ehdr->e_machine, ehdr->e_version);

	mdb_printf("  e_type:    %-18hu\n", ehdr->e_type);
	mdb_printf("  e_flags:   %-18u\n", ehdr->e_flags);

	mdb_printf("  e_entry:   0x%16lx  e_ehsize:    %8hu  e_shstrndx: %hu\n",
	    ehdr->e_entry, ehdr->e_ehsize, ehdr->e_shstrndx);

	mdb_printf("  e_shoff:   0x%16lx  e_shentsize: %8hu  e_shnum:    %hu\n",
	    ehdr->e_shoff, ehdr->e_shentsize, ehdr->e_shnum);

	mdb_printf("  e_phoff:   0x%16lx  e_phentsize: %8hu  e_phnum:    %hu\n",
	    ehdr->e_phoff, ehdr->e_phentsize, ehdr->e_phnum);
}

static void
dump_shdr(const Shdr *shdr, int i)
{
	static const mdb_bitmask_t sh_type_masks[] = {
		{ "SHT_NULL", 0xffffffff, SHT_NULL },
		{ "SHT_PROGBITS", 0xffffffff, SHT_PROGBITS },
		{ "SHT_SYMTAB", 0xffffffff, SHT_SYMTAB },
		{ "SHT_STRTAB", 0xffffffff, SHT_STRTAB },
		{ "SHT_RELA", 0xffffffff, SHT_RELA },
		{ "SHT_HASH", 0xffffffff, SHT_HASH },
		{ "SHT_DYNAMIC", 0xffffffff, SHT_DYNAMIC },
		{ "SHT_NOTE", 0xffffffff, SHT_NOTE },
		{ "SHT_NOBITS", 0xffffffff, SHT_NOBITS },
		{ "SHT_REL", 0xffffffff, SHT_REL },
		{ "SHT_SHLIB", 0xffffffff, SHT_SHLIB },
		{ "SHT_DYNSYM", 0xffffffff, SHT_DYNSYM },
		{ "SHT_LOSUNW", 0xffffffff, SHT_LOSUNW },
		{ "SHT_SUNW_COMDAT", 0xffffffff, SHT_SUNW_COMDAT },
		{ "SHT_SUNW_syminfo", 0xffffffff, SHT_SUNW_syminfo },
		{ "SHT_SUNW_verdef", 0xffffffff, SHT_SUNW_verdef },
		{ "SHT_SUNW_verneed", 0xffffffff, SHT_SUNW_verneed },
		{ "SHT_SUNW_versym", 0xffffffff, SHT_SUNW_versym },
		{ "SHT_HISUNW", 0xffffffff, SHT_HISUNW },
		{ "SHT_LOPROC", 0xffffffff, SHT_LOPROC },
		{ "SHT_HIPROC", 0xffffffff, SHT_HIPROC },
		{ "SHT_LOUSER", 0xffffffff, SHT_LOUSER },
		{ "SHT_HIUSER", 0xffffffff, SHT_HIUSER },
		{ NULL, 0, 0 }
	};

	static const mdb_bitmask_t sh_flag_masks[] = {
		{ "SHF_WRITE", SHF_WRITE, SHF_WRITE },
		{ "SHF_ALLOC", SHF_ALLOC, SHF_ALLOC },
		{ "SHF_EXECINSTR", SHF_EXECINSTR, SHF_EXECINSTR },
		{ "SHF_MASKPROC", SHF_MASKPROC, SHF_MASKPROC },
		{ NULL, 0, 0 }
	};

	mdb_printf("\nSection Header[%d]:\n", i);

	mdb_printf("    sh_addr:      0x%-16lx  sh_flags:   [ %#lb ]\n",
	    shdr->sh_addr, shdr->sh_flags, sh_flag_masks);

	mdb_printf("    sh_size:      0x%-16lx  sh_type:    [ %#lb ]\n",
	    shdr->sh_size, shdr->sh_type, sh_type_masks);

	mdb_printf("    sh_offset:    0x%-16lx  sh_entsize: 0x%lx\n",
	    shdr->sh_offset, shdr->sh_entsize);

	mdb_printf("    sh_link:      0x%-16lx  sh_info:    0x%lx\n",
	    shdr->sh_link, shdr->sh_info);

	mdb_printf("    sh_addralign: 0x%-16lx\n", shdr->sh_addralign);
}

/*ARGSUSED*/
static int
modhdrs(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct modctl ctl;
	struct module mod;
	Shdr *shdrs;

	size_t nbytes;
	int i;

	if (!(flags & DCMD_ADDRSPEC)) {
		mdb_warn("expected address of struct modctl before ::\n");
		return (DCMD_USAGE);
	}

	if (argc != 0)
		return (DCMD_USAGE);

	mdb_vread(&ctl, sizeof (struct modctl), addr);
	mdb_vread(&mod, sizeof (struct module), (uintptr_t)ctl.mod_mp);
	dump_ehdr(&mod.hdr);

	nbytes = sizeof (Shdr) * mod.hdr.e_shnum;
	shdrs = mdb_alloc(nbytes, UM_SLEEP | UM_GC);
	mdb_vread(shdrs, nbytes, (uintptr_t)mod.shdrs);

	for (i = 0; i < mod.hdr.e_shnum; i++)
		dump_shdr(&shdrs[i], i);

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
modinfo_format(uintptr_t addr, const void *data, void *private)
{
	const struct modctl *mcp = (const struct modctl *)data;

	struct modlinkage linkage;
	struct modlmisc lmisc;
	struct module mod;

	char info[MODMAXLINKINFOLEN];
	char name[MODMAXNAMELEN];

	mod.text_size = 0;
	mod.data_size = 0;
	mod.text = NULL;

	linkage.ml_rev = 0;

	info[0] = '\0';

	if (mcp->mod_mp != NULL)
		(void) mdb_vread(&mod, sizeof (mod), (uintptr_t)mcp->mod_mp);

	if (mcp->mod_linkage != NULL) {
		(void) mdb_vread(&linkage, sizeof (linkage),
		    (uintptr_t)mcp->mod_linkage);

		if (linkage.ml_linkage[0] != NULL) {
			(void) mdb_vread(&lmisc, sizeof (lmisc),
			    (uintptr_t)linkage.ml_linkage[0]);
			mdb_readstr(info, sizeof (info),
			    (uintptr_t)lmisc.misc_linkinfo);
		}
	}

	if (mdb_readstr(name, sizeof (name), (uintptr_t)mcp->mod_modname) == -1)
		(void) strcpy(name, "???");

	mdb_printf("%3d %?p %8lx %3d %s (%s)\n",
	    mcp->mod_id, mod.text, mod.text_size + mod.data_size,
	    linkage.ml_rev, name, info[0] != '\0' ? info : "?");

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
modinfo(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (argc != 0)
		return (DCMD_USAGE);

	if ((flags & DCMD_LOOPFIRST) || !(flags & DCMD_LOOP)) {
		mdb_printf("%<u>%3s %?s %8s %3s %s%</u>\n",
		    "ID", "LOADADDR", "SIZE", "REV", "MODULE NAME");
	}

	if (flags & DCMD_ADDRSPEC) {
		struct modctl mc;

		(void) mdb_vread(&mc, sizeof (mc), addr);
		return (modinfo_format(addr, &mc, NULL));
	}

	if (mdb_walk("modctl", modinfo_format, NULL) == -1)
		return (DCMD_ERR);

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
ctfinfo_format(uintptr_t addr, const struct modctl *mcp, void *private)
{
	char name[MODMAXNAMELEN];
	struct module mod;

	if (mcp->mod_mp == NULL)
		return (WALK_NEXT); /* module is not loaded */

	if (mdb_vread(&mod, sizeof (mod), (uintptr_t)mcp->mod_mp) == -1) {
		mdb_warn("failed to read module at %p for modctl %p\n",
		    mcp->mod_mp, addr);
		return (WALK_NEXT);
	}

	if (mdb_readstr(name, sizeof (name), (uintptr_t)mcp->mod_modname) == -1)
		(void) mdb_snprintf(name, sizeof (name), "%a", mcp->mod_mp);

	mdb_printf("%-30s %?p %lu\n", name, mod.ctfdata, (ulong_t)mod.ctfsize);
	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
ctfinfo(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if ((flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	mdb_printf("%<u>%-30s %?s %s%</u>\n", "MODULE", "CTFDATA", "CTFSIZE");
	if (mdb_walk("modctl", (mdb_walk_cb_t)ctfinfo_format, NULL) == -1)
		return (DCMD_ERR);

	return (DCMD_OK);
}

static const mdb_dcmd_t dcmds[] = {
	{ "modctl", NULL, "list modctl structures", modctls },
	{ "modhdrs", ":", "given modctl, dump module ehdr and shdrs", modhdrs },
	{ "modinfo", NULL, "list module information", modinfo },
	{ "ctfinfo", NULL, "list module CTF information", ctfinfo },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "modctl", "list of modctl structures",
		modctl_walk_init, modctl_walk_step, modctl_walk_fini },
	{ NULL }
};

static const mdb_modinfo_t krtld_modinfo = { MDB_API_VERSION, dcmds, walkers };

const mdb_modinfo_t *
_mdb_init(void)
{
	GElf_Sym sym;

	if (mdb_lookup_by_name("modules", &sym) == -1) {
		mdb_warn("failed to lookup 'modules'");
		return (NULL);
	}

	module_head = (uintptr_t)sym.st_value;
	return (&krtld_modinfo);
}
