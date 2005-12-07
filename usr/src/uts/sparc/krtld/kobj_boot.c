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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Bootstrap the linker/loader.
 */

#include <sys/types.h>
#include <sys/bootconf.h>
#include <sys/elf.h>
#include <sys/link.h>
#include <sys/auxv.h>
#include <sys/kobj.h>
#include <sys/kobj_impl.h>
#include <sys/archsystm.h>
#include <sys/kdi.h>

/*
 * We don't use the global offset table, but
 * ld may throw in an UNDEFINED reference in
 * our symbol table.
 */
#pragma	weak		_GLOBAL_OFFSET_TABLE_

#define	MASK(n)		((1l<<(n))-1l)
#define	IN_RANGE(v, n)	((-(1l<<((n)-1l))) <= (v) && (v) < (1l<<((n)-1l)))

#define	roundup		ALIGN

/*
 * Note: doflush() must be inlined, since we call it before we
 * have relocated ourselves.
 */

/*
 * Boot transfers control here. At this point,
 * we haven't relocated our own symbols, so the
 * world (as we know it) is pretty small right now.
 */
void
_kobj_boot(
	void *romp,
	kdi_debugvec_t *dvec,
	struct bootops *bootops,
	Boot *ebp)
{
	Shdr *section[24];	/* cache */
	val_t bootaux[BA_NUM];
	Phdr *phdr;
	auxv_t *auxv = NULL;
	uint_t sh, sh_num, sh_size;
	uintptr_t end, edata = 0;
	int i;

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
		case AT_SUN_IFLUSH:
			bootaux[BA_IFLUSH].ba_val = auxv->a_un.a_val;
			break;
		case AT_SUN_CPU:
			bootaux[BA_CPU].ba_ptr = auxv->a_un.a_ptr;
			break;
		case AT_ENTRY:
			bootaux[BA_ENTRY].ba_ptr = auxv->a_un.a_ptr;
			break;
		}
	}

	sh = (uint_t)(uintptr_t)bootaux[BA_LDSHDR].ba_ptr;
	sh_num = ((Ehdr *)bootaux[BA_LDELF].ba_ptr)->e_shnum;
	sh_size = ((Ehdr *)bootaux[BA_LDELF].ba_ptr)->e_shentsize;
	/*
	 * Build cache table for section addresses.
	 */
	for (i = 0; i < sh_num; i++) {
		section[i] = (Shdr *)(uintptr_t)sh;
		sh += sh_size;
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
		phdr = (Phdr *)((uintptr_t)phdr +
		    bootaux[BA_PHENT].ba_val);
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
			} else if (sp->st_shndx > (Half)sh_num)
				return;

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
		uintptr_t va, bva;
		uintptr_t asize;
		size_t align;

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
			boot_cell_t	args[7];
			int	(*bsys_1275_call)(void *);
			char		allocstr[6];

			bsys_1275_call =
			    (int (*)(void *))bootops->bsys_1275_call;
			allocstr[0] = 'a';
			allocstr[1] = 'l';
			allocstr[2] = 'l';
			allocstr[3] = 'o';
			allocstr[4] = 'c';
			allocstr[5] = '\0';
			args[0] = boot_ptr2cell(allocstr);
			args[1] = 3;
			args[2] = 1;
			args[3] = boot_ptr2cell((caddr_t)va);
			args[4] = boot_size2cell(bva - va);
			args[5] = boot_int2cell(align);
			(void) (bsys_1275_call)(args);
			bva = (uintptr_t)((caddr_t)boot_ptr2cell(args[6]));
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
		uintptr_t baseaddr, reladdr, rend;
		int relocsize;

		rshp = section[i];

		if (rshp->sh_type != SHT_RELA)
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
			Rela *reloc;
			register unsigned long stndx;
			unsigned int off, *offptr;
			long addend, value;
			int rtype;

			reloc = (Rela *)reladdr;
			off = reloc->r_offset;
			addend = (long)reloc->r_addend;
			rtype = ELF_R_TYPE(reloc->r_info);
			stndx = ELF_R_SYM(reloc->r_info);

			reladdr += relocsize;

			if (rtype == R_SPARC_NONE) {
				continue;
			}
			off += baseaddr;
			/*
			 * if R_SPARC_RELATIVE, simply add base addr
			 * to reloc location
			 */
			if (rtype == R_SPARC_RELATIVE) {
				value = baseaddr;
			} else {
				register unsigned int symoff, symsize;

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
				if (ELF_ST_BIND(symref->st_info) !=
				    STB_LOCAL) {
					/*
					 * If PC-relative, subtract ref addr.
					 */
					if (rtype == R_SPARC_PC10 ||
					    rtype == R_SPARC_PC22 ||
					    rtype == R_SPARC_DISP8 ||
					    rtype == R_SPARC_DISP16 ||
					    rtype == R_SPARC_DISP32 ||
					    rtype == R_SPARC_WPLT30 ||
					    rtype == R_SPARC_WDISP30 ||
					    rtype == R_SPARC_WDISP22 ||
					    rtype == R_SPARC_WDISP16 ||
					    rtype == R_SPARC_WDISP19)
						value -= off;
				}
			}
			if (rtype != R_SPARC_UA32 && (off & 3) != 0)
				return;
			offptr = (unsigned int *)(uintptr_t)off;
			/*
			 * insert value calculated at reference point
			 * 3 cases - normal byte order aligned, normal byte
			 * order unaligned, and byte swapped
			 * for the swapped and unaligned cases we insert value
			 * a byte at a time
			 */
			switch (rtype) {
			case 40123:
				/*
				 * This isn't a real relocation type.
				 * It just confuses the compiler
				 * sufficiently that it can't generate
				 * a jump table -- tee hee
				 */
				return;
			case R_SPARC_GLOB_DAT:  /* 32bit word aligned */
			case R_SPARC_RELATIVE:
			case R_SPARC_DISP32:
			case R_SPARC_32:
				/*
				 * 7/19/89 rmk adding current value of
				 * *offptr to value.  Should not be needed,
				 * since this is a RELA type and *offptr
				 * should be in addend
				 */
				*offptr = *offptr + value + addend;
				break;
			case R_SPARC_8:
			case R_SPARC_DISP8:
				value += addend;
				if (IN_RANGE(value, 8))
					*offptr |= value;
				else
					return;
				break;
			case R_SPARC_LO10:
			case R_SPARC_PC10:
				value += addend;
				value &= MASK(10);
				*offptr |= value;
				break;
			case R_SPARC_13:
				value += addend;
				if (IN_RANGE(value, 13))
					*offptr |= value;
				else
					return;
				break;
			case R_SPARC_16:
			case R_SPARC_DISP16:
				value += addend;
				if (IN_RANGE(value, 16))
					*offptr |= value;
				else
					return;
				break;
			case R_SPARC_22:
				value += addend;
				if (IN_RANGE(value, 22))
					*offptr |= value;
				else
					return;
				break;
			case R_SPARC_PC22:
				value += addend;
				value = (unsigned)value >> 10;
				if (IN_RANGE(value, 22))
					*offptr |= value;
				else
					return;
				break;
			case R_SPARC_WDISP22:
				value += addend;
				value = (unsigned)value >> 2;
				if (IN_RANGE(value, 22))
					*offptr |= value;
				else
					return;
				break;
			case R_SPARC_HI22:
				value += addend;
				value = (unsigned)value >> 10;
				*offptr |= value;
				break;
			case R_SPARC_WDISP30:
			case R_SPARC_WPLT30:
				value = (unsigned)value >> 2;
				*offptr |= value;
				break;
			case R_SPARC_UA32: {
				union {
					uint32_t l;
					char c[4];
				} symval;

				symval.l = value + addend;

				((char *)(uintptr_t)off)[0] = symval.c[0];
				((char *)(uintptr_t)off)[1] = symval.c[1];
				((char *)(uintptr_t)off)[2] = symval.c[2];
				((char *)(uintptr_t)off)[3] = symval.c[3];
				break;
			}
			case R_SPARC_10:
				value += addend;
				if (IN_RANGE(value, 10))
					*offptr |= value;
				else
					return;
				break;
			case R_SPARC_11:
				value += addend;
				if (IN_RANGE(value, 11))
					*offptr |= value;
				else
					return;
				break;
			case R_SPARC_WDISP16:
				value += addend;
				value = (unsigned)value >> 2;
				if (IN_RANGE(value, 16)) {
					*offptr |= (((value & 0xc000) << 6)
							| (value & 0x3fff));
				} else
					return;
				break;
			case R_SPARC_WDISP19:
				value += addend;
				value = (unsigned)value >> 2;
				if (IN_RANGE(value, 19))
					*offptr |= value;
				else
					return;
				break;
			case R_SPARC_5:
				value += addend;
				if (IN_RANGE(value, 5))
					*offptr |= value;
				else
					return;
				break;
			case R_SPARC_6:
				value += addend;
				if (IN_RANGE(value, 6))
					*offptr |= value;
				else
					return;
				break;
			case R_SPARC_7:
				value += addend;
				if (IN_RANGE(value, 7))
					*offptr |= value;
				else
					return;
				break;
			case R_SPARC_LM22:
				value += addend;
				value = (unsigned)value >> 10;
				*offptr |= value;
				break;
			case R_SPARC_HH22:
				value += addend;
				value = value >> 42;
				*offptr |= value;
				break;
			case R_SPARC_HM10:
				value += addend;
				value = (value >> 32) & 0x3ff;
				*offptr |= value;
				break;
			case R_SPARC_64:
				value += addend;
				*(unsigned long *)offptr |= value;
				break;
			default:
				return;
			}
			if (bootaux[BA_IFLUSH].ba_val)
				doflush((caddr_t)offptr);
			/*
			 * We only need to do it once.
			 */
			reloc->r_info = ELF_R_INFO(stndx, R_SPARC_NONE);
		} /* while */
	}

	/*
	 * Done relocating all of our *defined*
	 * symbols, so we hand off.
	 */
	kobj_init(romp, dvec, bootops, bootaux);
}
