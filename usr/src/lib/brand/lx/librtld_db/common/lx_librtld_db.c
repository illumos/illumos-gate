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

/*
 * Copyright (c) 2014, Joyent, Inc. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/link.h>
#include <libproc.h>
#include <proc_service.h>
#include <rtld_db.h>
#include <synch.h>

#include <sys/lx_brand.h>

/*
 * ATTENTION:
 *	Librtl_db brand plugin libraries should NOT directly invoke any
 *	libproc.so interfaces or be linked against libproc.  If a librtl_db
 *	brand plugin library uses libproc.so interfaces then it may break
 *	any other librtld_db consumers (like mdb) that tries to attach
 *	to a branded process.  The only safe interfaces that the a librtld_db
 *	brand plugin library can use to access a target process are the
 *	proc_service(3PROC) apis.
 */

/*
 * M_DATA comes from some streams header file but is also redifined in
 * _rtld_db.h, so nuke the old streams definition here.
 */
#ifdef M_DATA
#undef M_DATA
#endif /* M_DATA */

/*
 * For 32-bit versions of this library, this file gets compiled once.
 * For 64-bit versions of this library, this file gets compiled twice,
 * once with _ELF64 defined and once without.  The expectation is that
 * the 64-bit version of the library can properly deal with both 32-bit
 * and 64-bit elf files, hence in the 64-bit library there are two copies
 * of all the interfaces in this file, one set named *32 and one named *64.
 *
 * This also means that we need to be careful when declaring local pointers
 * that point to objects in another processes address space, since these
 * pointers may not match the current processes pointer width.  Basically,
 * we should avoid using data types that change size between 32 and 64 bit
 * modes like: long, void *, uintptr_t, caddr_t, psaddr_t, size_t, etc.
 * Instead we should declare all pointers as uint32_t.  Then when we
 * are compiled to deal with 64-bit targets we'll re-define uint32_t
 * to be a uint64_t.
 *
 * Finally, one last important note.  All the 64-bit elf file code
 * is never used and can't be tested.  This is because we don't actually
 * support 64-bit Linux processes yet.  The reason that we have it here
 * is because we want to support debugging 32-bit elf targets with the
 * 64-bit version of this library, so we need to have a 64-bit version
 * of this library.  But a 64-bit version of this library is expected
 * to provide debugging interfaces for both 32 and 64-bit elf targets.
 * So we provide the 64-bit elf target interfaces, but they will never
 * be invoked and are untested.  If we ever add support for 64-bit elf
 * Linux processes, we'll need to verify that this code works correctly
 * for those targets.
 */
#ifdef _LP64
#ifdef _ELF64
#define	lx_ldb_get_dyns32		lx_ldb_get_dyns64
#define	lx_ldb_init32			lx_ldb_init64
#define	lx_ldb_fini32			lx_ldb_fini64
#define	lx_ldb_loadobj_iter32		lx_ldb_loadobj_iter64
#define	lx_ldb_getauxval32		lx_ldb_getauxval64
#define	lx_elf_props32			lx_elf_props64
#define	_rd_get_dyns32			_rd_get_dyns64
#define	_rd_get_ehdr32			_rd_get_ehdr64
#define	uint32_t			uint64_t
#define	Elf32_Dyn			Elf64_Dyn
#define	Elf32_Ehdr			Elf64_Ehdr
#define	Elf32_Phdr			Elf64_Phdr
#endif /* _ELF64 */
#endif /* _LP64 */

/* Included from usr/src/cmd/sgs/librtld_db/common */
#include <_rtld_db.h>

typedef struct lx_rd {
	rd_agent_t		*lr_rap;
	struct ps_prochandle	*lr_php;	/* proc handle pointer */
	uint32_t		lr_rdebug;	/* address of lx r_debug */
	uint32_t		lr_exec;	/* base address of executable */
} lx_rd_t;

typedef struct lx_link_map {
	uint32_t lxm_addr;	/* Base address shared object is loaded at.  */
	uint32_t lxm_name;	/* Absolute file name object was found in.  */
	uint32_t lxm_ld;	/* Dynamic section of the shared object.  */
	uint32_t lxm_next;	/* Chain of loaded objects.  */
} lx_link_map_t;

typedef struct lx_r_debug {
	int r_version;		/* Version number for this protocol.  */
	uint32_t	r_map;	/* Head of the chain of loaded objects. */

	/*
	 * This is the address of a function internal to the run-time linker,
	 * that will always be called when the linker begins to map in a
	 * library or unmap it, and again when the mapping change is complete.
	 * The debugger can set a breakpoint at this address if it wants to
	 * notice shared object mapping changes.
	 */
	uint32_t	r_brk;
	r_state_e	r_state; /* defined the same way between lx/solaris */
	uint32_t	r_ldbase; /* Base address the linker is loaded at. */
} lx_r_debug_t;

static uint32_t
lx_ldb_getauxval32(struct ps_prochandle *php, int type)
{
	const auxv_t		*auxvp = NULL;

	if (ps_pauxv(php, &auxvp) != PS_OK)
		return ((uint32_t)-1);

	while (auxvp->a_type != AT_NULL) {
		if (auxvp->a_type == type)
			return ((uint32_t)(uintptr_t)auxvp->a_un.a_ptr);
		auxvp++;
	}
	return ((uint32_t)-1);
}

/*
 * A key difference between the linux linker and ours' is that the linux
 * linker adds the base address of segments to certain values in the
 * segments' ELF header. As an example, look at the address of the
 * DT_HASH hash table in a Solaris section - it is a relative address
 * which locates the start of the hash table, relative to the beginning
 * of the ELF file. However, when the linux linker loads a section, it
 * modifies the in-memory ELF image by changing address of the hash
 * table to be an absolute address. This is only done for libraries - not for
 * executables.
 *
 * Solaris tools expect the relative address to remain relative, so
 * here we will modify the in-memory ELF image so that it once again
 * contains relative addresses.
 *
 * To accomplish this, we walk through all sections in the target.
 * Linux sections are identified by pointing to the linux linker or libc in the
 * DT_NEEDED section. For all matching sections, we subtract the segment
 * base address to get back to relative addresses.
 */
static rd_err_e
lx_ldb_get_dyns32(rd_helper_data_t rhd,
    psaddr_t addr, void **dynpp, size_t *dynpp_sz)
{
	lx_rd_t			*lx_rd = (lx_rd_t *)rhd;
	rd_agent_t		*rap = lx_rd->lr_rap;
	Elf32_Ehdr		ehdr;
	Elf32_Dyn		*dynp = NULL;
	size_t			dynp_sz;
	uint_t			ndyns;
	int			i;

	ps_plog("lx_ldb_get_dyns: invoked for object at 0x%p", addr);

	/* Read in a copy of the ehdr */
	if (_rd_get_ehdr32(rap, addr, &ehdr, NULL) != RD_OK) {
		ps_plog("lx_ldb_get_dyns: _rd_get_ehdr() failed");
		return (RD_ERR);
	}

	/* read out the PT_DYNAMIC elements for this object */
	if (_rd_get_dyns32(rap, addr, &dynp, &dynp_sz) != RD_OK) {
		ps_plog("lx_ldb_get_dyns: _rd_get_dyns() failed");
		return (RD_ERR);
	}

	/*
	 * From here on out if we encounter an error we'll just return
	 * success and pass back the unmolested dynamic elements that
	 * we've already obtained.
	 */
	if (dynpp != NULL)
		*dynpp = dynp;
	if (dynpp_sz != NULL)
		*dynpp_sz = dynp_sz;
	ndyns = dynp_sz / sizeof (Elf32_Dyn);

	/* If this isn't a dynamic object, there's nothing left todo */
	if (ehdr.e_type != ET_DYN) {
		ps_plog("lx_ldb_get_dyns: done: not a shared object");
		return (RD_OK);
	}

	/*
	 * Before we blindly start changing dynamic section addresses
	 * we need to figure out if the current object that we're looking
	 * at is a linux object or a solaris object.  To do this first
	 * we need to find the string tab dynamic section element.
	 */
	for (i = 0; i < ndyns; i++) {
		if (dynp[i].d_tag == DT_STRTAB)
			break;
	}
	if (i == ndyns) {
		ps_plog("lx_ldb_get_dyns: "
		    "failed to find string tab in the dynamic section");
		return (RD_OK);
	}

	/*
	 * Check if the strtab value looks like an offset or an address.
	 * It's an offset if the value is less then the base address that
	 * the object is loaded at, or if the value is less than the offset
	 * of the section headers in the same elf object.  This check isn't
	 * perfect, but in practice it's good enough.
	 */
	if ((dynp[i].d_un.d_ptr < addr) ||
	    (dynp[i].d_un.d_ptr < ehdr.e_shoff)) {
		ps_plog("lx_ldb_get_dyns: "
		    "doesn't appear to be an lx object");
		return (RD_OK);
	}

	/*
	 * This seems to be a a linux object, so we'll patch up the dynamic
	 * section addresses
	 */
	ps_plog("lx_ldb_get_dyns: "
	    "patching up lx object dynamic section addresses");
	for (i = 0; i < ndyns; i++) {
		switch (dynp[i].d_tag) {
		case DT_PLTGOT:
		case DT_HASH:
		case DT_STRTAB:
		case DT_SYMTAB:
		case DT_RELA:
		case DT_REL:
		case DT_DEBUG:
		case DT_JMPREL:
		case DT_VERSYM:
			if (dynp[i].d_un.d_val > addr) {
				dynp[i].d_un.d_ptr -= addr;
			}
			break;
		default:
			break;
		}
	}
	return (RD_OK);
}

static void
lx_ldb_fini32(rd_helper_data_t rhd)
{
	lx_rd_t *lx_rd = (lx_rd_t *)rhd;
	ps_plog("lx_ldb_fini: cleaning up lx helper");
	free(lx_rd);
}

/*
 * The linux linker has an r_debug structure somewhere in its data section that
 * contains the address of the head of the link map list. To find this, we will
 * use the DT_DEBUG token in the executable's dynamic section. The linux linker
 * wrote the address of its r_debug structure to the DT_DEBUG dynamic entry. We
 * get the address of the executable's program headers from the
 * AT_SUN_BRAND_LX_PHDR aux vector entry. From there, we calculate the
 * address of the Elf header, and from there we can easily get to the DT_DEBUG
 * entry.
 */
static rd_helper_data_t
lx_ldb_init32(rd_agent_t *rap, struct ps_prochandle *php)
{
	lx_rd_t		*lx_rd;
	uint32_t	addr, phdr_addr, dyn_addr;
	uint32_t	symtab, strtab, offs;
	uint32_t	vaddr, memsz;
	caddr_t		mem;
	Elf32_Dyn	*dyn;
	Elf32_Phdr	phdr, *ph, *dph, *phdrs;
	Elf32_Ehdr	ehdr;
	Elf32_Sym	*sym;
	int		i, dyn_count;

	lx_rd = calloc(sizeof (lx_rd_t), 1);
	if (lx_rd == NULL) {
		ps_plog("lx_ldb_init: cannot allocate memory");
		return (NULL);
	}
	lx_rd->lr_rap = rap;
	lx_rd->lr_php = php;

	phdr_addr = lx_ldb_getauxval32(php, AT_SUN_BRAND_LX_PHDR);
	if (phdr_addr == (uint32_t)-1) {
		ps_plog("lx_ldb_init: no LX_PHDR found in aux vector");
		return (NULL);
	}
	ps_plog("lx_ldb_init: found LX_PHDR auxv phdr at: 0x%p",
	    phdr_addr);

	if (ps_pread(php, phdr_addr, &phdr, sizeof (phdr)) != PS_OK) {
		ps_plog("lx_ldb_init: couldn't read phdr at 0x%p",
		    phdr_addr);
		free(lx_rd);
		return (NULL);
	}

	/* The ELF header should be before the program header in memory */
	lx_rd->lr_exec = addr = phdr_addr - phdr.p_offset;
	if (ps_pread(php, addr, &ehdr, sizeof (ehdr)) != PS_OK) {
		ps_plog("lx_ldb_init: couldn't read ehdr at 0x%p",
		    lx_rd->lr_exec);
		free(lx_rd);
		return (NULL);
	}
	ps_plog("lx_ldb_init: read ehdr at: 0x%p", addr);

	if ((phdrs = malloc(ehdr.e_phnum * ehdr.e_phentsize)) == NULL) {
		ps_plog("lx_ldb_init: couldn't alloc phdrs memory");
		free(lx_rd);
		return (NULL);
	}

	if (ps_pread(php, phdr_addr, phdrs, ehdr.e_phnum * ehdr.e_phentsize) !=
	    PS_OK) {
		ps_plog("lx_ldb_init: couldn't read phdrs at 0x%p",
		    phdr_addr);
		free(lx_rd);
		free(phdrs);
		return (NULL);
	}
	ps_plog("lx_ldb_init: read %d phdrs at: 0x%p",
	    ehdr.e_phnum, phdr_addr);

	for (i = 0, ph = phdrs; i < ehdr.e_phnum; i++,
	    /*LINTED */
	    ph = (Elf32_Phdr *)((char *)ph + ehdr.e_phentsize)) {
		if (ph->p_type == PT_DYNAMIC)
			break;
	}
	if (i == ehdr.e_phnum) {
		ps_plog("lx_ldb_init: no PT_DYNAMIC in executable");
		free(lx_rd);
		free(phdrs);
		return (NULL);
	}
	ps_plog("lx_ldb_init: found PT_DYNAMIC phdr[%d] at: 0x%p",
	    i, (phdr_addr + ((char *)ph - (char *)phdrs)));

	if ((dyn = malloc(ph->p_filesz)) == NULL) {
		ps_plog("lx_ldb_init: couldn't alloc for PT_DYNAMIC");
		free(lx_rd);
		free(phdrs);
		return (NULL);
	}

	dyn_addr = addr + ph->p_offset;
	dyn_count = ph->p_filesz / sizeof (Elf32_Dyn);
	if (ps_pread(php, dyn_addr, dyn, ph->p_filesz) != PS_OK) {
		ps_plog("lx_ldb_init: couldn't read dynamic at 0x%p",
		    dyn_addr);
		free(lx_rd);
		free(phdrs);
		free(dyn);
		return (NULL);
	}
	ps_plog("lx_ldb_init: read %d dynamic headers at: 0x%p",
	    dyn_count, dyn_addr);

	for (i = 0; i < dyn_count; i++) {
		if (dyn[i].d_tag == DT_DEBUG) {
			lx_rd->lr_rdebug = dyn[i].d_un.d_ptr;
			break;
		}
	}
	free(phdrs);
	free(dyn);

	if (lx_rd->lr_rdebug != 0) {
		ps_plog("lx_ldb_init: found DT_DEBUG: 0x%p", lx_rd->lr_rdebug);
		return ((rd_helper_data_t)lx_rd);
	}

	ps_plog("lx_ldb_init: no DT_DEBUG found in exe; looking for r_debug");

	/*
	 * If we didn't find DT_DEBUG, we're going to employ the same fallback
	 * as gdb:  pawing through the dynamic linker's symbol table looking
	 * for the r_debug symbol.
	 */
	addr = lx_ldb_getauxval32(php, AT_SUN_BRAND_LX_INTERP);

	if (addr == (uint32_t)-1) {
		ps_plog("lx_ldb_init: no interpreter; failing");
		free(lx_rd);
		return (NULL);
	}

	ps_plog("lx_ldb_init: reading interp ehdr at 0x%p", addr);

	if (ps_pread(php, addr, &ehdr, sizeof (ehdr)) != PS_OK) {
		ps_plog("lx_ldb_init: couldn't read interp ehdr at 0x%p", addr);
		free(lx_rd);
		return (NULL);
	}

	if (ehdr.e_type != ET_DYN) {
		ps_plog("lx_ldb_init: interp ehdr not of type ET_DYN");
		free(lx_rd);
		return (NULL);
	}

	phdr_addr = addr + ehdr.e_phoff;

	if ((phdrs = malloc(ehdr.e_phnum * ehdr.e_phentsize)) == NULL) {
		ps_plog("lx_ldb_init: couldn't alloc interp phdrs memory");
		free(lx_rd);
		return (NULL);
	}

	if (ps_pread(php, phdr_addr, phdrs,
	    ehdr.e_phnum * ehdr.e_phentsize) != PS_OK) {
		ps_plog("lx_ldb_init: couldn't read interp phdrs at 0x%p",
		    phdr_addr);
		free(lx_rd);
		free(phdrs);
		return (NULL);
	}

	ps_plog("lx_ldb_init: read %d interp phdrs at: 0x%p",
	    ehdr.e_phnum, phdr_addr);

	vaddr = (uint32_t)-1;
	memsz = 0;

	for (i = 0, ph = phdrs, dph = NULL; i < ehdr.e_phnum; i++,
	    /*LINTED */
	    ph = (Elf32_Phdr *)((char *)ph + ehdr.e_phentsize)) {
		/*
		 * Keep track of our lowest PT_LOAD address, as this segment
		 * contains the DT_SYMTAB and DT_STRTAB.
		 */
		if (ph->p_type == PT_LOAD && ph->p_vaddr < vaddr) {
			vaddr = ph->p_vaddr;
			memsz = ph->p_memsz;
		}

		if (ph->p_type == PT_DYNAMIC)
			dph = ph;
	}

	if (vaddr == (uint32_t)-1 || memsz == 0) {
		ps_plog("lx_ldb_init: no PT_LOAD section in interp");
		free(lx_rd);
		free(phdrs);
		return (NULL);
	}

	ps_plog("lx_ldb_init: found interp PT_LOAD to be %d bytes at 0x%p",
	    memsz, vaddr);

	if ((ph = dph) == NULL) {
		ps_plog("lx_ldb_init: no PT_DYNAMIC in interp");
		free(lx_rd);
		free(phdrs);
		return (NULL);
	}

	ps_plog("lx_ldb_init: found interp PT_DYNAMIC phdr[%d] at: 0x%p",
	    i, (phdr_addr + ((char *)ph - (char *)phdrs)));

	if ((dyn = malloc(ph->p_filesz)) == NULL) {
		ps_plog("lx_ldb_init: couldn't alloc for interp PT_DYNAMIC");
		free(lx_rd);
		free(phdrs);
		return (NULL);
	}

	dyn_addr = addr + ph->p_offset;
	dyn_count = ph->p_filesz / sizeof (Elf32_Dyn);

	if (ps_pread(php, dyn_addr, dyn, ph->p_filesz) != PS_OK) {
		ps_plog("lx_ldb_init: couldn't read interp dynamic at 0x%p",
		    dyn_addr);
		free(lx_rd);
		free(phdrs);
		free(dyn);
		return (NULL);
	}

	free(phdrs);

	ps_plog("lx_ldb_init: read %d interp dynamic headers at: 0x%p",
	    dyn_count, dyn_addr);

	/*
	 * As noted in lx_ldb_get_dyns32(), in Linux, the PT_DYNAMIC table
	 * is adjusted to represent absolute addresses instead of offsets.
	 * This is not true for the interpreter, however -- where the values
	 * will be represented as offsets from the lowest PT_LOAD p_vaddr.
	 */
	symtab = strtab = (uint32_t)-1;

	for (i = 0; i < dyn_count; i++) {
		if (dyn[i].d_tag == DT_STRTAB)
			strtab = dyn[i].d_un.d_ptr - vaddr;

		if (dyn[i].d_tag == DT_SYMTAB)
			symtab = dyn[i].d_un.d_ptr - vaddr;
	}

	free(dyn);

	if (strtab == (uint32_t)-1 || strtab > memsz) {
		ps_plog("lx_ldb_init: didn't find valid interp strtab");
		free(lx_rd);
		return (NULL);
	}

	if (symtab == (uint32_t)-1 || symtab > memsz) {
		ps_plog("lx_ldb_init: didn't find valid interp symtab");
		free(lx_rd);
		return (NULL);
	}

	ps_plog("lx_ldb_init: strtab is 0x%x, symtab is 0x%x",
	    addr + strtab, addr + symtab);

	if ((mem = malloc(memsz)) == NULL) {
		ps_plog("lx_ldb_init: couldn't allocate interp "
		    "buffer of 0x%p bytes", memsz);
		free(lx_rd);
		return (NULL);
	}

	if (ps_pread(php, addr, mem, memsz) != PS_OK) {
		ps_plog("lx_ldb_init: couldn't read interp at 0x%p", addr);
		free(lx_rd);
		free(mem);
		return (NULL);
	}

	/*
	 * We make an assumption that is made elsewhere in the Linux linker:
	 * that the DT_SYMTAB immediately precedes the DT_STRTAB.
	 */
	for (offs = symtab; offs < strtab; offs += sizeof (Elf32_Sym)) {
		sym = (Elf32_Sym *)&mem[offs];

		if (sym->st_name > memsz) {
			ps_plog("lx_ldb_init: invalid st_name at sym 0x%p",
			    addr + offs);
		}

		ps_plog("lx_ldb_init: found interp symbol %s",
		    &mem[strtab + sym->st_name]);

		if (strcmp(&mem[strtab + sym->st_name], "_r_debug") == 0)
			break;
	}

	if (offs >= strtab) {
		ps_plog("lx_ldb_init: no _r_debug found in interpreter");
		free(mem);
		free(lx_rd);
		return (NULL);
	}

	lx_rd->lr_rdebug = (sym->st_value - vaddr) + addr;
	ps_plog("lx_ldb_init: found _r_debug at 0x%p", lx_rd->lr_rdebug);
	free(mem);

	return ((rd_helper_data_t)lx_rd);
}

/*
 * Given the address of an ELF object in the target, return its size and
 * the proper link map ID.
 */
static size_t
lx_elf_props32(struct ps_prochandle *php, uint32_t addr, psaddr_t *data_addr)
{
	Elf32_Ehdr	ehdr;
	Elf32_Phdr	*phdrs, *ph;
	int		i;
	uint32_t	min = (uint32_t)-1;
	uint32_t	max = 0;
	size_t		sz = NULL;

	if (ps_pread(php, addr, &ehdr, sizeof (ehdr)) != PS_OK) {
		ps_plog("lx_elf_props: Couldn't read ELF header at 0x%p",
		    addr);
		return (0);
	}

	if ((phdrs = malloc(ehdr.e_phnum * ehdr.e_phentsize)) == NULL)
		return (0);

	if (ps_pread(php, addr + ehdr.e_phoff, phdrs, ehdr.e_phnum *
	    ehdr.e_phentsize) != PS_OK) {
		ps_plog("lx_elf_props: Couldn't read program headers at 0x%p",
		    addr + ehdr.e_phoff);
		return (0);
	}

	for (i = 0, ph = phdrs; i < ehdr.e_phnum; i++,
	    /*LINTED */
	    ph = (Elf32_Phdr *)((char *)ph + ehdr.e_phentsize)) {

		if (ph->p_type != PT_LOAD)
			continue;

		if ((ph->p_flags & (PF_W | PF_R)) == (PF_W | PF_R)) {
			*data_addr = ph->p_vaddr;
			if (ehdr.e_type == ET_DYN)
				*data_addr += addr;
			if (*data_addr & (ph->p_align - 1))
				*data_addr = *data_addr & (~(ph->p_align -1));
		}

		if (ph->p_vaddr < min)
			min = ph->p_vaddr;

		if (ph->p_vaddr > max) {
			max = ph->p_vaddr;
			sz = ph->p_memsz + max - min;
			if (sz & (ph->p_align - 1))
				sz = (sz & (~(ph->p_align - 1))) + ph->p_align;
		}
	}

	free(phdrs);
	return (sz);
}

static int
lx_ldb_loadobj_iter32(rd_helper_data_t rhd, rl_iter_f *cb, void *client_data)
{
	lx_rd_t			*lx_rd = (lx_rd_t *)rhd;
	struct ps_prochandle	*php = lx_rd->lr_php;
	lx_r_debug_t		r_debug;
	lx_link_map_t		map;
	uint32_t		p = NULL;
	int			rc;
	rd_loadobj_t		exec;

	if ((rc = ps_pread(php, (psaddr_t)lx_rd->lr_rdebug, &r_debug,
	    sizeof (r_debug))) != PS_OK) {
		ps_plog("lx_ldb_loadobj_iter: "
		    "Couldn't read linux r_debug at 0x%p", lx_rd->lr_rdebug);
		return (rc);
	}

	p = r_debug.r_map;

	/*
	 * The first item on the link map list is for the executable, but it
	 * doesn't give us any useful information about it. We need to
	 * synthesize a rd_loadobj_t for the client.
	 *
	 * Linux doesn't give us the executable name, so we'll get it from
	 * the AT_EXECNAME entry instead.
	 */
	if ((rc = ps_pread(php, (psaddr_t)p, &map, sizeof (map))) != PS_OK) {
		ps_plog("lx_ldb_loadobj_iter: "
		    "Couldn't read linux link map at 0x%p", p);
		return (rc);
	}

	bzero(&exec, sizeof (exec));
	exec.rl_base = lx_rd->lr_exec;
	exec.rl_dynamic = map.lxm_ld;
	exec.rl_nameaddr = lx_ldb_getauxval32(php, AT_SUN_EXECNAME);
	exec.rl_lmident = LM_ID_BASE;

	exec.rl_bend = exec.rl_base +
	    lx_elf_props32(php, lx_rd->lr_exec, &exec.rl_data_base);

	if ((*cb)(&exec, client_data) == 0) {
		ps_plog("lx_ldb_loadobj_iter: "
		    "client callb failed for executable");
		return (PS_ERR);
	}

	for (p = map.lxm_next; p != NULL; p = map.lxm_next) {
		rd_loadobj_t	obj;

		if ((rc = ps_pread(php, (psaddr_t)p, &map, sizeof (map))) !=
		    PS_OK) {
			ps_plog("lx_ldb_loadobj_iter: "
			    "Couldn't read lk map at %p", p);
			return (rc);
		}

		/*
		 * The linux link map has less information than the Solaris one.
		 * We need to go fetch the missing information from the ELF
		 * headers.
		 */

		obj.rl_nameaddr = (psaddr_t)map.lxm_name;
		obj.rl_base = map.lxm_addr;
		obj.rl_refnameaddr = (psaddr_t)map.lxm_name;
		obj.rl_plt_base = NULL;
		obj.rl_plt_size = 0;
		obj.rl_lmident = LM_ID_BASE;

		/*
		 * Ugh - we have to walk the ELF stuff, find the PT_LOAD
		 * sections, and calculate the end of the file's mappings
		 * ourselves.
		 */

		obj.rl_bend = map.lxm_addr +
		    lx_elf_props32(php, map.lxm_addr, &obj.rl_data_base);
		obj.rl_padstart = obj.rl_base;
		obj.rl_padend = obj.rl_bend;
		obj.rl_dynamic = map.lxm_ld;
		obj.rl_tlsmodid = 0;

		ps_plog("lx_ldb_loadobj_iter: 0x%p to 0x%p",
		    obj.rl_base, obj.rl_bend);

		if ((*cb)(&obj, client_data) == 0) {
			ps_plog("lx_ldb_loadobj_iter: "
			    "Client callback failed on %s", map.lxm_name);
			return (rc);
		}
	}
	return (RD_OK);
}

/*
 * Librtld_db plugin linkage struct.
 *
 * When we get loaded by librtld_db, it will look for the symbol below
 * to find our plugin entry points.
 */
rd_helper_ops_t RTLD_DB_BRAND_OPS = {
	LM_ID_BRAND,
	lx_ldb_init32,
	lx_ldb_fini32,
	lx_ldb_loadobj_iter32,
	lx_ldb_get_dyns32
};
