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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <memory.h>
#include <sys/sysmacros.h>
#include <sys/machelf.h>

#include "Pcontrol.h"
#include "Psymtab_machelf.h"


/*
 * This file contains code for use by Psymtab.c that is compiled once
 * for each supported ELFCLASS.
 *
 * When processing ELF files, it is common to encounter a situation where
 * a program with one ELFCLASS (32 or 64-bit) is required to examine a
 * file with a different ELFCLASS. For example, the 32-bit linker (ld) may
 * be used to link a 64-bit program. The simplest solution to this problem
 * is to duplicate each such piece of code, modifying only the data types,
 * and to use if statements to select the code to run. The problem with
 * doing it that way is that the resulting code is difficult to maintain.
 * It is inevitable that the copies will not always get modified identically,
 * and will drift apart. The only robust solution is to generate the
 * multiple instances of code automatically from a single piece of code.
 *
 * The solution used within the Solaris linker is to write the code once,
 * using the data types defined in sys/machelf.h, and then to compile that
 * code twice, once with _ELF64 defined (to generate ELFCLASS64 code) and
 * once without (to generate ELFCLASS32). We use the same approach here.
 *
 * Note that the _ELF64 definition does not refer to the ELFCLASS of
 * the resulting code, but rather, to the ELFCLASS of the data it
 * examines. By repeating the above double-compilation for both 32-bit
 * and 64-bit builds, we end up with 4 instances, which collectively
 * can handle any combination of program and ELF data class:
 *
 *		    \  Compilation class
 *		     \	  32	64
 *		      \------------------
 *		       |
 *		    32 |   X	 X
 *   ELF Data Class    |
 *		    64 |   X	 X
 */



/*
 * Read data from the specified process and construct an in memory
 * image of an ELF file that will let us use libelf for most of the
 * work we need to later (e.g. symbol table lookups). This is used
 * in cases where no usable on-disk image for the process is available.
 * We need sections for the dynsym, dynstr, and plt, and we need
 * the program headers from the text section. The former is used in
 * Pbuild_file_symtab(); the latter is used in several functions in
 * Pcore.c to reconstruct the origin of each mapping from the load
 * object that spawned it.
 *
 * Here are some useful pieces of elf trivia that will help
 * to elucidate this code.
 *
 * All the information we need about the dynstr can be found in these
 * two entries in the dynamic section:
 *
 *	DT_STRTAB	base of dynstr
 *	DT_STRSZ	size of dynstr
 *
 * So deciphering the dynstr is pretty straightforward.
 *
 * The dynsym is a little trickier.
 *
 *	DT_SYMTAB	base of dynsym
 *	DT_SYMENT	size of a dynstr entry (Elf{32,64}_Sym)
 *	DT_HASH		base of hash table for dynamic lookups
 *
 * The DT_SYMTAB entry gives us any easy way of getting to the base
 * of the dynsym, but getting the size involves rooting around in the
 * dynamic lookup hash table. Here's the layout of the hash table:
 *
 *		+-------------------+
 *		|	nbucket	    |	All values are 32-bit
 *		+-------------------+	(Elf32_Word or Elf64_Word)
 *		|	nchain	    |
 *		+-------------------+
 *		|	bucket[0]   |
 *		|	. . .	    |
 *		| bucket[nbucket-1] |
 *		+-------------------+
 *		|	chain[0]    |
 *		|	. . .	    |
 *		|  chain[nchain-1]  |
 *		+-------------------+
 *	(figure 5-12 from the SYS V Generic ABI)
 *
 * Symbols names are hashed into a particular bucket which contains
 * an index into the symbol table. Each entry in the symbol table
 * has a corresponding entry in the chain table which tells the
 * consumer where the next entry in the hash chain is. We can use
 * the nchain field to find out the size of the dynsym.
 *
 * If there is a dynsym present, there may also be an optional
 * section called the SUNW_ldynsym that augments the dynsym by
 * providing local function symbols. When the Solaris linker lays
 * out a file that has both of these sections, it makes sure that
 * the data for the two sections is adjacent with the SUNW_ldynsym
 * in front. This allows the runtime linker to treat these two
 * symbol tables as being a single larger table. There are two
 * items in the dynamic section for this:
 *
 *	DT_SUNW_SYMTAB	base of the SUNW_ldynsym
 *	DT_SUNW_SYMSZ	total size of SUNW_ldynsym and dynsym
 *			added together. We can figure out the
 *			size of the SUNW_ldynsym section by
 *			subtracting the size of the dynsym
 *			(described above) from this value.
 *
 * We can figure out the size of the .plt section, but it takes some
 * doing. We need to use the following information:
 *
 *	DT_PLTGOT	base of the PLT
 *	DT_JMPREL	base of the PLT's relocation section
 *	DT_PLTRELSZ	size of the PLT's relocation section
 *	DT_PLTREL	type of the PLT's relocation section
 *
 * We can use the relocation section to figure out the address of the
 * last entry and subtract off the value of DT_PLTGOT to calculate
 * the size of the PLT.
 *
 * For more information, check out the System V Generic ABI.
 */


/*
 * The fake_elfXX() function generated by this file uses the following
 * string as the string table for the section names. Since it is critical
 * to count correctly, and to improve readability, the SHSTR_NDX_ macros
 * supply the proper offset for each name within the string.
 */
static char shstr[] =
	".shstrtab\0.dynsym\0.dynstr\0.dynamic\0.plt\0.SUNW_ldynsym";

/* Offsets within shstr for each name */
#define	SHSTR_NDX_shstrtab	0
#define	SHSTR_NDX_dynsym	10
#define	SHSTR_NDX_dynstr	18
#define	SHSTR_NDX_dynamic	26
#define	SHSTR_NDX_plt		35
#define	SHSTR_NDX_SUNW_ldynsym	40


/*
 * Section header alignment for 32 and 64-bit ELF files differs
 */
#ifdef _ELF64
#define	SH_ADDRALIGN	8
#else
#define	SH_ADDRALIGN	4
#endif

/*
 * This is the smallest number of PLT relocation entries allowed in a proper
 * .plt section.
 */
#ifdef	__sparc
#define	PLTREL_MIN_ENTRIES	4	/* SPARC psABI 3.0 and SCD 2.4 */
#else
#ifdef	__lint
/*
 * On x86, lint would complain about unsigned comparison with
 * PLTREL_MIN_ENTRIES. This define fakes up the value of PLTREL_MIN_ENTRIES
 * and silences lint. On SPARC, there is no such issue.
 */
#define	PLTREL_MIN_ENTRIES	1
#else
#define	PLTREL_MIN_ENTRIES	0
#endif
#endif

#ifdef _ELF64
Elf *
fake_elf64(struct ps_prochandle *P, file_info_t *fptr, uintptr_t addr,
    Ehdr *ehdr, uint_t phnum, Phdr *phdr)
#else
Elf *
fake_elf32(struct ps_prochandle *P, file_info_t *fptr, uintptr_t addr,
    Ehdr *ehdr, uint_t phnum, Phdr *phdr)
#endif
{
	enum {
		DI_PLTGOT,
		DI_JMPREL,
		DI_PLTRELSZ,
		DI_PLTREL,
		DI_SYMTAB,
		DI_HASH,
		DI_SYMENT,
		DI_STRTAB,
		DI_STRSZ,
		DI_SUNW_SYMTAB,
		DI_SUNW_SYMSZ,
		DI_NENT
	};
	/*
	 * Mask of dynamic options that must be present in a well
	 * formed dynamic section. We need all of these in order to
	 * put together a complete set of elf sections. They are
	 * mandatory in both executables and shared objects so if one
	 * of them is missing, we're in some trouble and should abort.
	 * The PLT items are expected, but we will let them slide if
	 * need be. The DI_SUNW_SYM* items are completely optional, so
	 * we use them if they are present and ignore them otherwise.
	 */
	const int di_req_mask = (1 << DI_SYMTAB) | (1 << DI_HASH) |
		(1 << DI_SYMENT) | (1 << DI_STRTAB) | (1 << DI_STRSZ);
	int di_mask = 0;
	size_t size = 0;
	caddr_t elfdata = NULL;
	Elf *elf;
	size_t dynsym_size, ldynsym_size;
	int dynstr_shndx;
	Ehdr *ep;
	Shdr *sp;
	Dyn *dp;
	Dyn *d[DI_NENT] = { 0 };
	uint_t i;
	Off off;
	size_t pltsz = 0, pltentsz;

	if (ehdr->e_type == ET_DYN)
		phdr->p_vaddr += addr;

	if (P->rap != NULL) {
		if (rd_get_dyns(P->rap, addr, (void **)&dp, NULL) != RD_OK)
			goto bad;
	} else {
		if ((dp = malloc(phdr->p_filesz)) == NULL)
			goto bad;
		if (Pread(P, dp, phdr->p_filesz, phdr->p_vaddr) !=
		    phdr->p_filesz)
			goto bad;
	}

	/*
	 * Iterate over the items in the dynamic section, grabbing
	 * the address of items we want and saving them in dp[].
	 */
	for (i = 0; i < phdr->p_filesz / sizeof (Dyn); i++) {
		switch (dp[i].d_tag) {
		/* For the .plt section */
		case DT_PLTGOT:
			d[DI_PLTGOT] = &dp[i];
			break;
		case DT_JMPREL:
			d[DI_JMPREL] = &dp[i];
			break;
		case DT_PLTRELSZ:
			d[DI_PLTRELSZ] = &dp[i];
			break;
		case DT_PLTREL:
			d[DI_PLTREL] = &dp[i];
			break;

		/* For the .dynsym section */
		case DT_SYMTAB:
			d[DI_SYMTAB] = &dp[i];
			di_mask |= (1 << DI_SYMTAB);
			break;
		case DT_HASH:
			d[DI_HASH] = &dp[i];
			di_mask |= (1 << DI_HASH);
			break;
		case DT_SYMENT:
			d[DI_SYMENT] = &dp[i];
			di_mask |= (1 << DI_SYMENT);
			break;
		case DT_SUNW_SYMTAB:
			d[DI_SUNW_SYMTAB] = &dp[i];
			break;
		case DT_SUNW_SYMSZ:
			d[DI_SUNW_SYMSZ] = &dp[i];
			break;

		/* For the .dynstr section */
		case DT_STRTAB:
			d[DI_STRTAB] = &dp[i];
			di_mask |= (1 << DI_STRTAB);
			break;
		case DT_STRSZ:
			d[DI_STRSZ] = &dp[i];
			di_mask |= (1 << DI_STRSZ);
			break;
		}
	}

	/* Ensure all required entries were collected */
	if ((di_mask & di_req_mask) != di_req_mask) {
		dprintf("text section missing required dynamic entries\n");
		goto bad;
	}

	if (ehdr->e_type == ET_DYN) {
		if (d[DI_PLTGOT] != NULL)
			d[DI_PLTGOT]->d_un.d_ptr += addr;
		if (d[DI_JMPREL] != NULL)
			d[DI_JMPREL]->d_un.d_ptr += addr;
		d[DI_SYMTAB]->d_un.d_ptr += addr;
		d[DI_HASH]->d_un.d_ptr += addr;
		d[DI_STRTAB]->d_un.d_ptr += addr;
		if (d[DI_SUNW_SYMTAB] != NULL)
			d[DI_SUNW_SYMTAB]->d_un.d_ptr += addr;
	}

	/* SUNW_ldynsym must be adjacent to dynsym. Ignore if not */
	if ((d[DI_SUNW_SYMTAB] != NULL) && (d[DI_SUNW_SYMSZ] != NULL) &&
	    ((d[DI_SYMTAB]->d_un.d_ptr <= d[DI_SUNW_SYMTAB]->d_un.d_ptr) ||
	    (d[DI_SYMTAB]->d_un.d_ptr >= (d[DI_SUNW_SYMTAB]->d_un.d_ptr +
	    d[DI_SUNW_SYMSZ]->d_un.d_val)))) {
		d[DI_SUNW_SYMTAB] = NULL;
		d[DI_SUNW_SYMSZ] = NULL;
	}

	/* elf header */
	size = sizeof (Ehdr);

	/* program headers from in-core elf fragment */
	size += phnum * ehdr->e_phentsize;

	/* unused shdr, and .shstrtab section */
	size += sizeof (Shdr);
	size += sizeof (Shdr);
	size += roundup(sizeof (shstr), SH_ADDRALIGN);

	/*
	 * .dynsym and .SUNW_ldynsym sections.
	 *
	 * The string table section used for the symbol table and
	 * dynamic sections lies immediately after the dynsym, so the
	 * presence of SUNW_ldynsym changes the dynstr section index.
	 */
	if (d[DI_SUNW_SYMTAB] != NULL) {
		size += sizeof (Shdr);	/* SUNW_ldynsym shdr */
		ldynsym_size = (size_t)d[DI_SUNW_SYMSZ]->d_un.d_val;
		dynsym_size = ldynsym_size - (d[DI_SYMTAB]->d_un.d_ptr
		    - d[DI_SUNW_SYMTAB]->d_un.d_ptr);
		ldynsym_size -= dynsym_size;
		dynstr_shndx = 4;
	} else {
		Word nchain;

		if (Pread(P, &nchain, sizeof (nchain),
		    d[DI_HASH]->d_un.d_ptr + sizeof (nchain)) !=
		    sizeof (nchain)) {
			dprintf("Pread of .dynsym at %lx failed\n",
			    (long)(d[DI_HASH]->d_un.d_val + sizeof (nchain)));
			goto bad;
		}
		dynsym_size = sizeof (Sym) * nchain;
		ldynsym_size = 0;
		dynstr_shndx = 3;
	}
	size += sizeof (Shdr) + ldynsym_size + dynsym_size;

	/* .dynstr section */
	size += sizeof (Shdr);
	size += roundup(d[DI_STRSZ]->d_un.d_val, SH_ADDRALIGN);

	/* .dynamic section */
	size += sizeof (Shdr);
	size += roundup(phdr->p_filesz, SH_ADDRALIGN);

	/* .plt section */
	if (d[DI_PLTGOT] != NULL && d[DI_JMPREL] != NULL &&
	    d[DI_PLTRELSZ] != NULL && d[DI_PLTREL] != NULL) {
		uintptr_t penult, ult;
		uintptr_t jmprel = d[DI_JMPREL]->d_un.d_ptr;
		size_t pltrelsz = d[DI_PLTRELSZ]->d_un.d_val;

		if (d[DI_PLTREL]->d_un.d_val == DT_RELA) {
			uint_t entries = pltrelsz / sizeof (Rela);
			Rela r[2];

			if (entries < PLTREL_MIN_ENTRIES) {
				dprintf("too few PLT relocation entries "
				    "(found %d, expected at least %d)\n",
				    entries, PLTREL_MIN_ENTRIES);
				goto bad;
			}
			if (entries < PLTREL_MIN_ENTRIES + 2)
				goto done_with_plt;

			if (Pread(P, r, sizeof (r), jmprel + sizeof (r[0]) *
			    entries - sizeof (r)) != sizeof (r)) {
				dprintf("Pread of DT_RELA failed\n");
				goto bad;
			}

			penult = r[0].r_offset;
			ult = r[1].r_offset;

		} else if (d[DI_PLTREL]->d_un.d_val == DT_REL) {
			uint_t entries = pltrelsz / sizeof (Rel);
			Rel r[2];

			if (entries < PLTREL_MIN_ENTRIES) {
				dprintf("too few PLT relocation entries "
				    "(found %d, expected at least %d)\n",
				    entries, PLTREL_MIN_ENTRIES);
				goto bad;
			}
			if (entries < PLTREL_MIN_ENTRIES + 2)
				goto done_with_plt;

			if (Pread(P, r, sizeof (r), jmprel + sizeof (r[0]) *
			    entries - sizeof (r)) != sizeof (r)) {
				dprintf("Pread of DT_REL failed\n");
				goto bad;
			}

			penult = r[0].r_offset;
			ult = r[1].r_offset;
		} else {
			dprintf(".plt: unknown jmprel value\n");
			goto bad;
		}

		pltentsz = ult - penult;

		if (ehdr->e_type == ET_DYN)
			ult += addr;

		pltsz = ult - d[DI_PLTGOT]->d_un.d_ptr + pltentsz;

		size += sizeof (Shdr);
		size += roundup(pltsz, SH_ADDRALIGN);
	}
done_with_plt:

	if ((elfdata = calloc(1, size)) == NULL)
		goto bad;

	/* LINTED - alignment */
	ep = (Ehdr *)elfdata;
	(void) memcpy(ep, ehdr, offsetof(Ehdr, e_phoff));

	ep->e_ehsize = sizeof (Ehdr);
	ep->e_phoff = sizeof (Ehdr);
	ep->e_phentsize = ehdr->e_phentsize;
	ep->e_phnum = phnum;
	ep->e_shoff = ep->e_phoff + phnum * ep->e_phentsize;
	ep->e_shentsize = sizeof (Shdr);
	/*
	 * Plt and SUNW_ldynsym sections are optional. C logical
	 * binary operators return a 0 or 1 value, so the following
	 * adds 1 for each optional section present.
	 */
	ep->e_shnum = 5 + (pltsz != 0) + (d[DI_SUNW_SYMTAB] != NULL);
	ep->e_shstrndx = 1;

	/* LINTED - alignment */
	sp = (Shdr *)(elfdata + ep->e_shoff);
	off = ep->e_shoff + ep->e_shentsize * ep->e_shnum;

	/*
	 * Copying the program headers directly from the process's
	 * address space is a little suspect, but since we only
	 * use them for their address and size values, this is fine.
	 */
	if (Pread(P, &elfdata[ep->e_phoff], phnum * ep->e_phentsize,
	    addr + ehdr->e_phoff) != phnum * ep->e_phentsize) {
		dprintf("failed to read program headers\n");
		goto bad;
	}

	/*
	 * The first elf section is always skipped.
	 */
	sp++;

	/*
	 * Section Header: .shstrtab
	 */
	sp->sh_name = SHSTR_NDX_shstrtab;
	sp->sh_type = SHT_STRTAB;
	sp->sh_flags = SHF_STRINGS;
	sp->sh_addr = 0;
	sp->sh_offset = off;
	sp->sh_size = sizeof (shstr);
	sp->sh_link = 0;
	sp->sh_info = 0;
	sp->sh_addralign = 1;
	sp->sh_entsize = 0;

	(void) memcpy(&elfdata[off], shstr, sizeof (shstr));
	off += roundup(sp->sh_size, SH_ADDRALIGN);
	sp++;

	/*
	 * Section Header: .SUNW_ldynsym
	 */
	if (d[DI_SUNW_SYMTAB] != NULL) {
		sp->sh_name = SHSTR_NDX_SUNW_ldynsym;
		sp->sh_type = SHT_SUNW_LDYNSYM;
		sp->sh_flags = SHF_ALLOC;
		sp->sh_addr = d[DI_SUNW_SYMTAB]->d_un.d_ptr;
		if (ehdr->e_type == ET_DYN)
			sp->sh_addr -= addr;
		sp->sh_offset = off;
		sp->sh_size = ldynsym_size;
		sp->sh_link = dynstr_shndx;
		/* Index of 1st global in table that has none == # items */
		sp->sh_info = sp->sh_size / sizeof (Sym);
		sp->sh_addralign = SH_ADDRALIGN;
		sp->sh_entsize = sizeof (Sym);

		if (Pread(P, &elfdata[off], sp->sh_size,
		    d[DI_SUNW_SYMTAB]->d_un.d_ptr) != sp->sh_size) {
			dprintf("failed to read .SUNW_ldynsym at %lx\n",
			    (long)d[DI_SUNW_SYMTAB]->d_un.d_ptr);
			goto bad;
		}
		off += sp->sh_size;
		/* No need to round up ldynsym data. Dynsym data is same type */
		sp++;
	}

	/*
	 * Section Header: .dynsym
	 */
	sp->sh_name = SHSTR_NDX_dynsym;
	sp->sh_type = SHT_DYNSYM;
	sp->sh_flags = SHF_ALLOC;
	sp->sh_addr = d[DI_SYMTAB]->d_un.d_ptr;
	if (ehdr->e_type == ET_DYN)
		sp->sh_addr -= addr;
	sp->sh_offset = off;
	sp->sh_size = dynsym_size;
	sp->sh_link = dynstr_shndx;
	sp->sh_info = 1;	/* Index of 1st global in table */
	sp->sh_addralign = SH_ADDRALIGN;
	sp->sh_entsize = sizeof (Sym);

	if (Pread(P, &elfdata[off], sp->sh_size,
	    d[DI_SYMTAB]->d_un.d_ptr) != sp->sh_size) {
		dprintf("failed to read .dynsym at %lx\n",
		    (long)d[DI_SYMTAB]->d_un.d_ptr);
		goto bad;
	}

	off += roundup(sp->sh_size, SH_ADDRALIGN);
	sp++;

	/*
	 * Section Header: .dynstr
	 */
	sp->sh_name = SHSTR_NDX_dynstr;
	sp->sh_type = SHT_STRTAB;
	sp->sh_flags = SHF_ALLOC | SHF_STRINGS;
	sp->sh_addr = d[DI_STRTAB]->d_un.d_ptr;
	if (ehdr->e_type == ET_DYN)
		sp->sh_addr -= addr;
	sp->sh_offset = off;
	sp->sh_size = d[DI_STRSZ]->d_un.d_val;
	sp->sh_link = 0;
	sp->sh_info = 0;
	sp->sh_addralign = 1;
	sp->sh_entsize = 0;

	if (Pread(P, &elfdata[off], sp->sh_size,
	    d[DI_STRTAB]->d_un.d_ptr) != sp->sh_size) {
		dprintf("failed to read .dynstr\n");
		goto bad;
	}
	off += roundup(sp->sh_size, SH_ADDRALIGN);
	sp++;

	/*
	 * Section Header: .dynamic
	 */
	sp->sh_name = SHSTR_NDX_dynamic;
	sp->sh_type = SHT_DYNAMIC;
	sp->sh_flags = SHF_WRITE | SHF_ALLOC;
	sp->sh_addr = phdr->p_vaddr;
	if (ehdr->e_type == ET_DYN)
		sp->sh_addr -= addr;
	sp->sh_offset = off;
	sp->sh_size = phdr->p_filesz;
	sp->sh_link = dynstr_shndx;
	sp->sh_info = 0;
	sp->sh_addralign = SH_ADDRALIGN;
	sp->sh_entsize = sizeof (Dyn);

	(void) memcpy(&elfdata[off], dp, sp->sh_size);
	off += roundup(sp->sh_size, SH_ADDRALIGN);
	sp++;

	/*
	 * Section Header: .plt
	 */
	if (pltsz != 0) {
		sp->sh_name = SHSTR_NDX_plt;
		sp->sh_type = SHT_PROGBITS;
		sp->sh_flags = SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR;
		sp->sh_addr = d[DI_PLTGOT]->d_un.d_ptr;
		if (ehdr->e_type == ET_DYN)
			sp->sh_addr -= addr;
		sp->sh_offset = off;
		sp->sh_size = pltsz;
		sp->sh_link = 0;
		sp->sh_info = 0;
		sp->sh_addralign = SH_ADDRALIGN;
		sp->sh_entsize = pltentsz;

		if (Pread(P, &elfdata[off], sp->sh_size,
		    d[DI_PLTGOT]->d_un.d_ptr) != sp->sh_size) {
			dprintf("failed to read .plt\n");
			goto bad;
		}
		off += roundup(sp->sh_size, SH_ADDRALIGN);
		sp++;
	}

	free(dp);
	if ((elf = elf_memory(elfdata, size)) == NULL) {
		free(elfdata);
		return (NULL);
	}

	fptr->file_elfmem = elfdata;

	return (elf);

bad:
	if (dp != NULL)
		free(dp);
	if (elfdata != NULL)
		free(elfdata);
	return (NULL);


}
