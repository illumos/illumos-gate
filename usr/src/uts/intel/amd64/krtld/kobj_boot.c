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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Bootstrap the linker/loader.
 */

#include <sys/types.h>
#include <sys/bootconf.h>
#include <sys/link.h>
#include <sys/auxv.h>
#include <sys/kobj.h>
#include <sys/elf.h>
#include <sys/bootsvcs.h>
#include <sys/kobj_impl.h>

#if !defined(__GNUC__)

/*
 * We don't use the global offset table, but
 * ld may throw in an UNDEFINED reference in
 * our symbol table.
 */
#if !defined(_KERNEL)
#pragma weak _GLOBAL_OFFSET_TABLE_
#endif

#else

/*
 * We -do- use the global offset table, but only by
 * accident -- when you tell gcc to emit PIC code,
 * it -always- generates a reference to the GOT in
 * a register, even if the compilation unit never
 * uses it.
 *
 * Rumoured to be fixed in a later version of gcc..
 */

long	_GLOBAL_OFFSET_TABLE_[1];

#endif

#define	roundup		ALIGN

#define	MAXSECT		64	/* max # of sects. */

#define	HIBITS		0xffffffff80000000	/* upper 32 bits */

/*
 * Boot transfers control here. At this point,
 * we haven't relocated our own symbols, so the
 * world (as we know it) is pretty small right now.
 */
void
_kobj_boot(
	struct boot_syscalls *syscallp,
	void *dvec,
	struct bootops *bootops,
	Boot *ebp)
{
	Shdr *section[MAXSECT];	/* cache */
	val_t bootaux[BA_NUM];
	struct bootops *bop;
	Phdr *phdr;
	auxv_t *auxv = NULL;
	Shdr *sh;
	Half sh_num;
	ulong_t end, edata = 0;
	int i;

	bop = (dvec) ? *(struct bootops **)bootops : bootops;

	for (i = 0; i < BA_NUM; i++)
		bootaux[i].ba_val = NULL;

	/*
	 * Check the bootstrap vector.
	 */
	for (; ebp->eb_tag != EB_NULL; ebp++) {
		switch (ebp->eb_tag) {
#if defined(__GNUC__)
		/*
		 * gcc 2.95, 3.1 cannot be told to not generate GOT references,
		 * which krtld cannot handle.  yet switch statements which
		 * can be mapped to jump tables are a frequent generator
		 * of such references.
		 */
		case 0x12345678:
			/*
			 * deliberately mess up the compilers
			 * temptation to create a jump table
			 */
			break;
#endif
		case EB_AUXV:
			auxv = (auxv_t *)ebp->eb_un.eb_ptr;
			break;
		case EB_DYNAMIC:
			bootaux[BA_DYNAMIC].ba_ptr = (void *)ebp->eb_un.eb_ptr;
			break;
		default:
			break;
		}
	}

	if (auxv == NULL)
		return;

	/*
	 * Now the aux vector.
	 */
	for (; auxv->a_type != AT_NULL; auxv++) {
		switch (auxv->a_type) {
#if defined(__GNUC__)
		case 0x12345678:
			/*
			 * deliberately mess up the compilers
			 * temptation to create a jump table
			 */
			break;
#endif
		case AT_PHDR:
			bootaux[BA_PHDR].ba_ptr = auxv->a_un.a_ptr;
			break;
		case AT_PHENT:
			bootaux[BA_PHENT].ba_val = auxv->a_un.a_val;
			break;
		case AT_PHNUM:
			bootaux[BA_PHNUM].ba_val = auxv->a_un.a_val;
			break;
		case AT_PAGESZ:
			bootaux[BA_PAGESZ].ba_val = auxv->a_un.a_val;
			break;
		case AT_SUN_LDELF:
			bootaux[BA_LDELF].ba_ptr = auxv->a_un.a_ptr;
			break;
		case AT_SUN_LDSHDR:
			bootaux[BA_LDSHDR].ba_ptr = auxv->a_un.a_ptr;
			break;
		case AT_SUN_LDNAME:
			bootaux[BA_LDNAME].ba_ptr = auxv->a_un.a_ptr;
			break;
		case AT_SUN_LPAGESZ:
			bootaux[BA_LPAGESZ].ba_val = auxv->a_un.a_val;
			break;
		case AT_SUN_CPU:
			bootaux[BA_CPU].ba_ptr = auxv->a_un.a_ptr;
			break;
		case AT_SUN_MMU:
			bootaux[BA_MMU].ba_ptr = auxv->a_un.a_ptr;
			break;
		case AT_ENTRY:
			bootaux[BA_ENTRY].ba_ptr = auxv->a_un.a_ptr;
			break;
		default:
			break;
		}
	}


	sh = (Shdr *)bootaux[BA_LDSHDR].ba_ptr;
	sh_num = ((Ehdr *)bootaux[BA_LDELF].ba_ptr)->e_shnum;
	/*
	 * Make sure we won't overflow stack allocated cache
	 */
	if (sh_num >= MAXSECT)
		return;

	/*
	 * Build cache table for section addresses.
	 */
	for (i = 0; i < sh_num; i++) {
		section[i] = sh++;
	}

	/*
	 * Find the end of data
	 * (to allocate bss)
	 */
	phdr = (Phdr *)bootaux[BA_PHDR].ba_ptr;

	for (i = 0; i < bootaux[BA_PHNUM].ba_val; i++) {
		if (phdr->p_type == PT_LOAD &&
		    (phdr->p_flags & PF_W) && (phdr->p_flags & PF_X)) {
			edata = end = phdr->p_vaddr + phdr->p_memsz;
			break;
		}
		phdr = (Phdr *)((ulong_t)phdr + bootaux[BA_PHENT].ba_val);
	}
	if (edata == NULL)
		return;

	/*
	 * Find the symbol table, and then loop
	 * through the symbols adjusting their
	 * values to reflect where the sections
	 * were loaded.
	 */
	for (i = 1; i < sh_num; i++) {
		Shdr *shp;
		Sym *sp;
		ulong_t off;

		shp = section[i];
		if (shp->sh_type != SHT_SYMTAB)
			continue;

		for (off = 0; off < shp->sh_size; off += shp->sh_entsize) {
			sp = (Sym *)(shp->sh_addr + off);

			if (sp->st_shndx == SHN_ABS ||
			    sp->st_shndx == SHN_UNDEF)
				continue;

			/*
			 * Assign the addresses for COMMON
			 * symbols even though we haven't
			 * actually allocated bss yet.
			 */
			if (sp->st_shndx == SHN_COMMON) {
				end = ALIGN(end, sp->st_value);
				sp->st_value = end;
				/*
				 * Squirrel it away for later.
				 */
				if (bootaux[BA_BSS].ba_val == 0)
					bootaux[BA_BSS].ba_val = end;
				end += sp->st_size;
				continue;
			} else if (sp->st_shndx > (Half)sh_num) {
				BSVC_PUTCHAR(syscallp, '>');
				return;
			}

			/*
			 * Symbol's new address.
			 */
			sp->st_value += section[sp->st_shndx]->sh_addr;
		}
	}

	/*
	 * Allocate bss for COMMON, if any.
	 */
	if (end > edata) {
		unsigned long va, bva;
		unsigned long asize;
		unsigned long align;

		if (bootaux[BA_LPAGESZ].ba_val) {
			asize = bootaux[BA_LPAGESZ].ba_val;
			align = bootaux[BA_LPAGESZ].ba_val;
		} else {
			asize = bootaux[BA_PAGESZ].ba_val;
			align = BO_NO_ALIGN;
		}
		va = roundup(edata, asize);
		bva = roundup(end, asize);

		if (bva > va) {
			bva = (unsigned long)BOP_ALLOC(bop, (caddr_t)va,
				bva - va, align);
			if (bva == NULL)
				return;
		}
		/*
		 * Zero it.
		 */
		for (va = edata; va < end; va++)
			*(char *)va = 0;
		/*
		 * Update the size of data.
		 */
		phdr->p_memsz += (end - edata);
	}

	/*
	 * Relocate our own symbols.  We'll handle the
	 * undefined symbols later.
	 */
	for (i = 1; i < sh_num; i++) {
		Shdr *rshp, *shp, *ssp;
		unsigned long baseaddr, reladdr, rend;
		long relocsize;

		rshp = section[i];

		if (rshp->sh_type != SHT_RELA)
			continue;
		/*
		 * Get the section being relocated
		 * and the symbol table.
		 */
		shp = section[rshp->sh_info];
		ssp = section[rshp->sh_link];

		/*
		 * Only perform relocations against allocatable
		 * sections.
		 */
		if ((shp->sh_flags & SHF_ALLOC) == 0)
			continue;

		reladdr = rshp->sh_addr;
		baseaddr = shp->sh_addr;
		rend = reladdr + rshp->sh_size;
		relocsize = rshp->sh_entsize;
		/*
		 * Loop through relocations.
		 */

		while (reladdr < rend) {
			Sym *symref;
			Rela *reloc;
			unsigned long stndx;
			unsigned long off, *offptr;
			long addend, value;
			unsigned long symoff, symsize;
			int rtype;

			reloc = (Rela *)reladdr;
			off = reloc->r_offset;
			addend = (long)reloc->r_addend;
			rtype = ELF_R_TYPE(reloc->r_info);
			stndx = ELF_R_SYM(reloc->r_info);

			reladdr += relocsize;

			if (rtype == R_AMD64_NONE)
				continue;

			off += baseaddr;

			symsize = ssp->sh_entsize;
			symoff = stndx * symsize;

			/*
			 * Check for bad symbol index.
			 */
			if (symoff > ssp->sh_size)
				return;

			symref = (Sym *)(ssp->sh_addr + symoff);


			/*
			 * Just bind our own symbols at this point.
			 */
			if (symref->st_shndx == SHN_UNDEF)
				continue;

			value = symref->st_value;

			if ((rtype == R_AMD64_PC32) ||
			    (rtype == R_AMD64_PLT32))
				/*
				 * If PC-relative, subtract ref addr.
				 */
				value -= off;
			else if (rtype == R_AMD64_32) {
				/*
				 * It's illegal to have any HIBITS
				 * set for R_AMD64_32 reloc.
				 */
				if (value & HIBITS) {
					BSVC_PUTCHAR(syscallp, 'h');
					return;
				}
			} else if (rtype == R_AMD64_32S) {
				/*
				 * All HIBITS for R_AMD64_32S
				 * *must* be set.
				 */
				if ((value & HIBITS) != HIBITS) {
					BSVC_PUTCHAR(syscallp, 'H');
					return;
				}
			}

			offptr = (unsigned long *)off;
			/*
			 * insert value calculated at reference point
			 * 2 cases - normal byte order aligned, normal byte
			 * order unaligned.
			 */
			switch (rtype) {
#if defined(__GNUC__)
			case 0x12345678:
				/*
				 * deliberately mess up the compilers
				 * temptation to create a jump table
				 */
				break;
#endif
			case R_AMD64_64:
				*(unsigned long *)offptr = value + addend;
				break;
			case R_AMD64_PC32:
			case R_AMD64_32S:
			case R_AMD64_PLT32:
				*(uint_t *)offptr = (uint_t)(value + addend);
				break;
			case R_AMD64_GOT32:
				BSVC_PUTCHAR(syscallp, 'G');
				return;
			case R_AMD64_32:
				return;
			default:
				BSVC_PUTCHAR(syscallp, 'R');
				return;
			}
			/*
			 * We only need to do it once.
			 */
			reloc->r_info = ELF_R_INFO(stndx, R_AMD64_NONE);
		} /* while */
	}

	/*
	 * Done relocating all of our *defined*
	 * symbols, so we hand off.
	 */
	kobj_init(syscallp, dvec, bootops, bootaux);
}
