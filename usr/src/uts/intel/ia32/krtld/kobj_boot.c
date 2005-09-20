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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
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

#pragma weak _GLOBAL_OFFSET_TABLE_

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

#define	MASK(n)		((1<<(n))-1)
#define	IN_RANGE(v, n)	((-(1<<((n)-1))) <= (v) && (v) < (1<<((n)-1)))

#define	roundup		ALIGN

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
	Shdr *section[24];	/* cache */
	val_t bootaux[BA_NUM];
	struct bootops *bop;
	Phdr *phdr;
	auxv_t *auxv = NULL;
	Shdr *sh;
	Half sh_num;
	uint_t end, edata = 0;
	int i;

	bop = (dvec) ? *(struct bootops **)bootops : bootops;

	for (i = 0; i < BA_NUM; i++)
		bootaux[i].ba_val = NULL;

	/*
	 * Check the bootstrap vector.
	 */
	for (; ebp->eb_tag != EB_NULL; ebp++) {
		switch (ebp->eb_tag) {
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
		uint_t off;

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
		int relocsize;

		rshp = section[i];

		if (rshp->sh_type != SHT_REL)
			continue;
		/*
		 * Get the section being relocated
		 * and the symbol table.
		 */
		shp = section[rshp->sh_info];
		ssp = section[rshp->sh_link];

		reladdr = rshp->sh_addr;
		baseaddr = shp->sh_addr;
		rend = reladdr + rshp->sh_size;
		relocsize = rshp->sh_entsize;
		/*
		 * Loop through relocations.
		 */
		while (reladdr < rend) {
			Sym *symref;
			Rel *reloc;
			unsigned long stndx;
			unsigned long off, *offptr;
			long value;
			int rtype;

			reloc = (Rel *)reladdr;
			off = reloc->r_offset;
			rtype = ELF32_R_TYPE(reloc->r_info);
			stndx = ELF32_R_SYM(reloc->r_info);

			reladdr += relocsize;

			if (rtype == R_386_NONE) {
				continue;
			}
			off += baseaddr;

			if (rtype == R_386_RELATIVE) {
				/*
				 * add base addr to reloc location
				 */
				value = baseaddr;
			} else {
				unsigned int symoff, symsize;

				symsize = ssp->sh_entsize;

				for (symoff = 0; stndx; stndx--)
					symoff += symsize;
				symref = (Sym *)(ssp->sh_addr + symoff);

				/*
				 * Check for bad symbol index.
				 */
				if (symoff > ssp->sh_size)
					return;

				/*
				 * Just bind our own symbols at this point.
				 */
				if (symref->st_shndx == SHN_UNDEF) {
					continue;
				}

				value = symref->st_value;
				if (ELF32_ST_BIND(symref->st_info) !=
				    STB_LOCAL) {
					/*
					 * If PC-relative, subtract ref addr.
					 */
					if (rtype == R_386_PC32 ||
					    rtype == R_386_PLT32 ||
					    rtype == R_386_GOTPC)
						value -= off;
				}
			}
			offptr = (unsigned long *)off;
			/*
			 * insert value calculated at reference point
			 * 2 cases - normal byte order aligned, normal byte
			 * order unaligned.
			 */
			switch (rtype) {
			case R_386_PC32:
			case R_386_32:
			case R_386_PLT32:
			case R_386_RELATIVE:
				*offptr += value;
				break;

			/*
			 * For now, ignore GOT references ...
			 */

			case R_386_GOTPC:
#if defined(DEBUG)
				BSVC_PUTCHAR(syscallp, 'p');
#endif
				break;
			case R_386_GOTOFF:
				BSVC_PUTCHAR(syscallp, 'g');
				break;
			default:
				BSVC_PUTCHAR(syscallp, 'r');
				return;
			}
			/*
			 * We only need to do it once.
			 */
			reloc->r_info = ELF32_R_INFO(stndx, R_386_NONE);
		} /* while */
	}

	/*
	 * Done relocating all of our *defined*
	 * symbols, so we hand off.
	 */
	kobj_init(syscallp, dvec, bootops, bootaux);
}
