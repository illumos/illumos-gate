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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*	Copyright (c) 1987, 1988 Microsoft Corporation	*/
/*	  All Rights Reserved	*/


#include <errno.h>
#include <libelf.h>
#include "decl.h"
#include "msg.h"

/*
 * Routines for generating a checksum for an elf image. Typically used to create
 * a DT_CHECKSUM entry.  This checksum is intended to remain constant after
 * operations such as strip(1)/mcs(1), thus only allocatable sections are
 * processed, and of those, any that might be modified by these external
 * commands are skipped.
 */
#define	MSW(l)	(((l) >> 16) & 0x0000ffffL)
#define	LSW(l)	((l) & 0x0000ffffL)


/*
 * update and epilogue sum functions (stolen from libcmd)
 */
static long
sumupd(long sum, char *cp, unsigned long cnt)
{
	if ((cp == 0) || (cnt == 0))
		return (sum);

	while (cnt--)
		sum += *cp++ & 0x00ff;

	return (sum);
}

static long
sumepi(long sum)
{
	long	_sum;

	_sum = LSW(sum) + MSW(sum);
	return ((ushort_t)(LSW(_sum) + MSW(_sum)));
}

/*
 * This module is compiled twice, the second time having
 * -D_ELF64 defined.  The following set of macros represent
 * the differences between the two compilations.  Be
 * careful *not* to add any class dependent code (anything
 * that has elf32 or elf64 in the name) to this code
 * without hiding it behind a switchable macro like these.
 */
#if	defined(_ELF64)

#define	elf_checksum		elf64_checksum
#define	Elf_Ehdr		Elf64_Ehdr
#define	Elf_Shdr		Elf64_Shdr
#define	getehdr			elf64_getehdr
#define	getshdr			elf64_getshdr

#else	/* else ELF32 */

#define	elf_checksum		elf32_checksum
#define	Elf_Ehdr		Elf32_Ehdr
#define	Elf_Shdr		Elf32_Shdr
#define	getehdr			elf32_getehdr
#define	getshdr			elf32_getshdr

#endif	/* ELF64 */

long
elf_checksum(Elf * elf)
{
	long		sum = 0;
	Elf_Ehdr *	ehdr;
	Elf_Shdr *	shdr;
	Elf_Scn *	scn;
	Elf_Data *	data, * (* getdata)(Elf_Scn *, Elf_Data *);
	size_t		shnum;

	if ((ehdr = getehdr(elf)) == 0)
		return (0);

	/*
	 * Determine the data information to retrieve.  When called from ld()
	 * we're processing an ELF_C_IMAGE (memory) image and thus need to use
	 * elf_getdata(), as there is not yet a file image (or raw data) backing
	 * this.  When called from utilities like elfdump(1) we're processing a
	 * file image and thus using the elf_rawdata() allows the same byte
	 * stream to be processed from different architectures - presently this
	 * is irrelevant, as the checksum simply sums the data bytes, their
	 * order doesn't matter.  But being uncooked is slightly less overhead.
	 *
	 * If the file is writable, the raw data will not reflect any
	 * changes made in the process, so the uncooked version is only
	 * for readonly files.
	 */
	if ((elf->ed_myflags & (EDF_MEMORY | EDF_WRITE)) != 0)
		getdata = elf_getdata;
	else
		getdata = elf_rawdata;

	for (shnum = 1; shnum < ehdr->e_shnum; shnum++) {
		if ((scn = elf_getscn(elf, shnum)) == 0)
			return (0);
		if ((shdr = getshdr(scn)) == 0)
			return (0);

		/* Exclude strippable sections */
		if (!(shdr->sh_flags & SHF_ALLOC))
			continue;

		/*
		 * Exclude allocable sections that can change:
		 *	- The .dynsym section can contain section symbols
		 *		that strip might remove.
		 *	- The .dynamic section is modified by the setting of
		 *		this checksum value.
		 *	- The .SUNW_dof section uses ftok(3C), which returns
		 *		different values, to define a key for the
		 *		objects in that section.
		 */
		if ((shdr->sh_type == SHT_DYNSYM) ||
		    (shdr->sh_type == SHT_DYNAMIC) ||
		    (shdr->sh_type == SHT_SUNW_dof))
			continue;

		data = 0;
		while ((data = (*getdata)(scn, data)) != 0)
			sum = sumupd(sum, data->d_buf, data->d_size);

	}
	return (sumepi(sum));
}
