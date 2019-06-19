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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Redirection ld.so.  Based on the 4.x binary compatibility ld.so, used
 * to redirect aliases for ld.so to the real one.
 */

/*
 * Import data structures
 */
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/sysconfig.h>
#include <sys/auxv.h>
#include <elf.h>
#include <link.h>
#include <string.h>
#include "alias_boot.h"

/*
 * Local manifest constants and macros.
 */
#define	ALIGN(x, a)		((int)(x) & ~((int)(a) - 1))
#define	ROUND(x, a)		(((int)(x) + ((int)(a) - 1)) & \
				    ~((int)(a) - 1))

#define	EMPTY	strings[EMPTY_S]
#define	LDSO	strings[LDSO_S]
#define	ZERO	strings[ZERO_S]
#define	CLOSE	(*(funcs[CLOSE_F]))
#define	FSTATAT	(*(funcs[FSTATAT_F]))
#define	MMAP	(*(funcs[MMAP_F]))
#define	MUNMAP	(*(funcs[MUNMAP_F]))
#define	OPENAT	(*(funcs[OPENAT_F]))
#define	PANIC	(*(funcs[PANIC_F]))
#define	SYSCONFIG (*(funcs[SYSCONFIG_F]))

#include <link.h>

/*
 * Alias ld.so entry point -- receives a bootstrap structure and a vector
 * of strings.  The vector is "well-known" to us, and consists of pointers
 * to string constants.  This aliasing bootstrap requires no relocation in
 * order to run, save for the pointers of constant strings.  This second
 * parameter provides this.  Note that this program is carefully coded in
 * order to maintain the "no bootstrapping" requirement -- it calls only
 * local functions, uses no intrinsics, etc.
 */
void *
__rtld(Elf32_Boot *ebp, const char *strings[], int (*funcs[])())
{
	int i, j, p;			/* working */
	int page_size = 0;		/* size of a page */
	const char *program_name = EMPTY; /* our name */
	int ldfd;			/* fd assigned to ld.so */
	int dzfd = 0;			/* fd assigned to /dev/zero */
	Elf32_Ehdr *ehdr;		/* ELF header of ld.so */
	Elf32_Phdr *phdr;		/* first Phdr in file */
	Elf32_Phdr *pptr;		/* working Phdr */
	Elf32_Phdr *lph;		/* last loadable Phdr */
	Elf32_Phdr *fph = 0;		/* first loadable Phdr */
	caddr_t	maddr;			/* pointer to mapping claim */
	Elf32_Off mlen;			/* total mapping claim */
	caddr_t faddr;			/* first program mapping of ld.so */
	Elf32_Off foff;			/* file offset for segment mapping */
	Elf32_Off flen;			/* file length for segment mapping */
	caddr_t addr;			/* working mapping address */
	caddr_t zaddr;			/* /dev/zero working mapping addr */
	struct stat sb;			/* stat buffer for sizing */
	auxv_t *ap;			/* working aux pointer */

	/*
	 * Discover things about our environment: auxiliary vector (if
	 * any), arguments, program name, and the like.
	 */
	while (ebp->eb_tag != 0) {
		switch (ebp->eb_tag) {
		case EB_ARGV:
			program_name = *((char **)ebp->eb_un.eb_ptr);
			break;
		case EB_AUXV:
			for (ap = (auxv_t *)ebp->eb_un.eb_ptr;
			    ap->a_type != AT_NULL; ap++)
				if (ap->a_type == AT_PAGESZ) {
					page_size = ap->a_un.a_val;
					break;
				}
			break;
		}
		ebp++;
	}

	/*
	 * If we didn't get a page size from looking in the auxiliary
	 * vector, we need to get one now.
	 */
	if (page_size == 0) {
		page_size = SYSCONFIG(_CONFIG_PAGESIZE);
		ebp->eb_tag = EB_PAGESIZE, (ebp++)->eb_un.eb_val =
		    (Elf32_Word)page_size;
	}

	/*
	 * Map in the real ld.so.  Note that we're mapping it as
	 * an ELF database, not as a program -- we just want to walk it's
	 * data structures.  Further mappings will actually establish the
	 * program in the address space.
	 */
	if ((ldfd = OPENAT(AT_FDCWD, LDSO, O_RDONLY)) == -1)
		PANIC(program_name);
	if (FSTATAT(ldfd, NULL, &sb, 0) == -1)
		PANIC(program_name);
	ehdr = (Elf32_Ehdr *)MMAP(0, sb.st_size, PROT_READ | PROT_EXEC,
	    MAP_SHARED, ldfd, 0);
	if (ehdr == (Elf32_Ehdr *)-1)
		PANIC(program_name);

	/*
	 * Validate the file we're looking at, ensure it has the correct
	 * ELF structures, such as: ELF magic numbers, coded for 386,
	 * is a ".so", etc.
	 */
	if (ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
	    ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
	    ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
	    ehdr->e_ident[EI_MAG3] != ELFMAG3)
		PANIC(program_name);
	if (ehdr->e_ident[EI_CLASS] != ELFCLASS32 ||
	    ehdr->e_ident[EI_DATA] != ELFDATA2LSB)
		PANIC(program_name);
	if (ehdr->e_type != ET_DYN)
		PANIC(program_name);
	if (ehdr->e_machine != EM_386)
		PANIC(program_name);
	if (ehdr->e_version > EV_CURRENT)
		PANIC(program_name);

	/*
	 * Point at program headers and start figuring out what to load.
	 */
	phdr = (Elf32_Phdr *)((caddr_t)ehdr + ehdr->e_phoff);
	for (p = 0, pptr = phdr; p < (int)ehdr->e_phnum; p++,
	    pptr = (Elf32_Phdr *)((caddr_t)pptr + ehdr->e_phentsize))
		if (pptr->p_type == PT_LOAD) {
			if (fph == 0) {
				fph = pptr;
			} else if (pptr->p_vaddr <= lph->p_vaddr)
				PANIC(program_name);
			lph = pptr;
		}

	/*
	 * We'd better have at least one loadable segment.
	 */
	if (fph == 0)
		PANIC(program_name);

	/*
	 * Map enough address space to hold the program (as opposed to the
	 * file) represented by ld.so.  The amount to be assigned is the
	 * range between the end of the last loadable segment and the
	 * beginning of the first PLUS the alignment of the first segment.
	 * mmap() can assign us any page-aligned address, but the relocations
	 * assume the alignments included in the program header.  As an
	 * optimization, however, let's assume that mmap() will actually
	 * give us an aligned address -- since if it does, we can save
	 * an munmap() later on.  If it doesn't -- then go try it again.
	 */
	mlen = ROUND((lph->p_vaddr + lph->p_memsz) -
	    ALIGN(fph->p_vaddr, page_size), page_size);
	maddr = (caddr_t)MMAP(0, mlen, PROT_READ | PROT_EXEC,
	    MAP_SHARED, ldfd, 0);
	if (maddr == (caddr_t)-1)
		PANIC(program_name);
	faddr = (caddr_t)ROUND(maddr, fph->p_align);

	/*
	 * Check to see whether alignment skew was really needed.
	 */
	if (faddr != maddr) {
		(void) MUNMAP(maddr, mlen);
		mlen = ROUND((lph->p_vaddr + lph->p_memsz) -
		    ALIGN(fph->p_vaddr, fph->p_align) + fph->p_align,
		    page_size);
		maddr = (caddr_t)MMAP(0, mlen, PROT_READ | PROT_EXEC,
		    MAP_SHARED, ldfd, 0);
		if (maddr == (caddr_t)-1)
			PANIC(program_name);
		faddr = (caddr_t)ROUND(maddr, fph->p_align);
	}

	/*
	 * We have the address space reserved, so map each loadable segment.
	 */
	for (p = 0, pptr = phdr; p < (int)ehdr->e_phnum; p++,
	    pptr = (Elf32_Phdr *)((caddr_t)pptr + ehdr->e_phentsize)) {

		/*
		 * Skip non-loadable segments or segments that don't occupy
		 * any memory.
		 */
		if ((pptr->p_type != PT_LOAD) || (pptr->p_memsz == 0))
			continue;

		/*
		 * Determine the file offset to which the mapping will
		 * directed (must be aligned) and how much to map (might
		 * be more than the file in the case of .bss.)
		 */
		foff = ALIGN(pptr->p_offset, page_size);
		flen = pptr->p_memsz + (pptr->p_offset - foff);

		/*
		 * Set address of this segment relative to our base.
		 */
		addr = (caddr_t)ALIGN(faddr + pptr->p_vaddr, page_size);

		/*
		 * If this is the first program header, record our base
		 * address for later use.
		 */
		if (pptr == phdr) {
			ebp->eb_tag = EB_LDSO_BASE;
			(ebp++)->eb_un.eb_ptr = (Elf32_Addr)addr;
		}

		/*
		 * Unmap anything from the last mapping address to this
		 * one.
		 */
		if (addr - maddr) {
			(void) MUNMAP(maddr, addr - maddr);
			mlen -= addr - maddr;
		}

		/*
		 * Determine the mapping protection from the section
		 * attributes.
		 */
		i = 0;
		if (pptr->p_flags & PF_R)
			i |= PROT_READ;
		if (pptr->p_flags & PF_W)
			i |= PROT_WRITE;
		if (pptr->p_flags & PF_X)
			i |= PROT_EXEC;
		if ((caddr_t)MMAP((caddr_t)addr, flen, i,
		    MAP_FIXED | MAP_PRIVATE, ldfd, foff) == (caddr_t)-1)
			PANIC(program_name);

		/*
		 * If the memory occupancy of the segment overflows the
		 * definition in the file, we need to "zero out" the
		 * end of the mapping we've established, and if necessary,
		 * map some more space from /dev/zero.
		 */
		if (pptr->p_memsz > pptr->p_filesz) {
			foff = (int)faddr + pptr->p_vaddr + pptr->p_filesz;
			zaddr = (caddr_t)ROUND(foff, page_size);
			for (j = 0; j < (int)(zaddr - foff); j++)
				*((char *)foff + j) = 0;
			j = (faddr + pptr->p_vaddr + pptr->p_memsz) - zaddr;
			if (j > 0) {
				if (dzfd == 0) {
					dzfd = OPENAT(AT_FDCWD, ZERO, O_RDWR);
					if (dzfd == -1)
						PANIC(program_name);
				}
				if ((caddr_t)MMAP((caddr_t)zaddr, j, i,
				    MAP_FIXED | MAP_PRIVATE, dzfd,
				    0) == (caddr_t)-1)
					PANIC(program_name);
			}
		}

		/*
		 * Update the mapping claim pointer.
		 */
		maddr = addr + ROUND(flen, page_size);
		mlen -= maddr - addr;
	}

	/*
	 * Unmap any final reservation.
	 */
	if (mlen > 0)
		(void) MUNMAP(maddr, mlen);

	/*
	 * Clean up file descriptor space we've consumed.  Pass along
	 * the /dev/zero file descriptor we got -- every cycle counts.
	 */
	(void) CLOSE(ldfd);
	if (dzfd != 0)
		ebp->eb_tag = EB_DEVZERO, (ebp++)->eb_un.eb_val = dzfd;

	ebp->eb_tag = EB_NULL, ebp->eb_un.eb_val = 0;

	/* The two bytes before _rt_boot is for the alias entry point */
	return (void *) (ehdr->e_entry + faddr - 2);
}
