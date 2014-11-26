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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * This stuff used to live in cook.c, but was moved out to
 * facilitate dual (Elf32 and Elf64) compilation.  See block
 * comment in cook.c for more info.
 */

#include <string.h>
#include <ar.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/sysmacros.h>
#include "decl.h"
#include "member.h"
#include "msg.h"

/*
 * This module is compiled twice, the second time having
 * -D_ELF64 defined.  The following set of macros, along
 * with machelf.h, represent the differences between the
 * two compilations.  Be careful *not* to add any class-
 * dependent code (anything that has elf32 or elf64 in the
 * name) to this code without hiding it behind a switch-
 * able macro like these.
 */
#if	defined(_ELF64)
#define	Snode		Snode64
#define	ELFCLASS	ELFCLASS64
#define	ElfField	Elf64
#define	_elf_snode_init	_elf64_snode_init
#define	_elf_prepscan	_elf64_prepscan
#define	_elf_cookscn	_elf64_cookscn
#define	_elf_mtype	_elf64_mtype
#define	_elf_msize	_elf64_msize
#define	elf_fsize	elf64_fsize
#define	_elf_snode	_elf64_snode
#define	_elf_ehdr	_elf64_ehdr
#define	elf_xlatetom	elf64_xlatetom
#define	_elf_phdr	_elf64_phdr
#define	_elf_shdr	_elf64_shdr
#define	_elf_prepscn	_elf64_prepscn

#else  /* Elf32 */
#define	Snode		Snode32
#define	ELFCLASS	ELFCLASS32
#define	ElfField	Elf32
#define	_elf_snode_init	_elf32_snode_init
#define	_elf_prepscan	_elf32_prepscan
#define	_elf_cookscn	_elf32_cookscn
#define	_elf_mtype	_elf32_mtype
#define	_elf_msize	_elf32_msize
#define	elf_fsize	elf32_fsize
#define	_elf_snode	_elf32_snode
#define	_elf_ehdr	_elf32_ehdr
#define	elf_xlatetom	elf32_xlatetom
#define	_elf_phdr	_elf32_phdr
#define	_elf_shdr	_elf32_shdr
#define	_elf_prepscn	_elf32_prepscn

#endif /* _ELF64 */


static Okay
_elf_prepscn(Elf *elf, size_t cnt)
{
	NOTE(ASSUMING_PROTECTED(*elf))
	Elf_Scn *	s;
	Elf_Scn *	end;

	if (cnt == 0)
		return (OK_YES);

	if ((s = malloc(cnt * sizeof (Elf_Scn))) == 0) {
		_elf_seterr(EMEM_SCN, errno);
		return (OK_NO);
	}
	NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*s))
	elf->ed_scntabsz = cnt;
	end = s + cnt;
	elf->ed_hdscn = s;
	do {
		*s = _elf_snode_init.sb_scn;
		s->s_elf = elf;
		s->s_next = s + 1;
		s->s_index = s - elf->ed_hdscn;
		s->s_shdr = (Shdr*)s->s_elf->ed_shdr + s->s_index;
		ELFMUTEXINIT(&s->s_mutex);

		/*
		 * Section has not yet been cooked!
		 *
		 * We don't cook a section until it's data is actually
		 * referenced.
		 */
		s->s_myflags = 0;
	} while (++s < end);

	elf->ed_tlscn = --s;
	s->s_next = 0;

	/*
	 * Section index SHN_UNDEF (0) does not and cannot
	 * have a data buffer.  Fix it here.  Also mark the
	 * initial section as being allocated for the block
	 */

	s = elf->ed_hdscn;
	s->s_myflags = SF_ALLOC;
	s->s_hdnode = 0;
	s->s_tlnode = 0;
	NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*s))
	return (OK_YES);
}


Okay
_elf_cookscn(Elf_Scn * s)
{
	NOTE(ASSUMING_PROTECTED(*s, *(s->s_elf)))
	Elf *			elf;
	Shdr *			sh;
	register Dnode *	d = &s->s_dnode;
	size_t			fsz, msz;
	unsigned		work;

	NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*d))
	s->s_hdnode = s->s_tlnode = d;
	s->s_err = 0;
	s->s_shflags = 0;
	s->s_uflags = 0;


	/*
	 * Prepare d_data for inspection, but don't actually
	 * translate data until needed.  Leave the READY
	 * flag off.  NOBITS sections see zero size.
	 */
	elf = s->s_elf;
	sh = s->s_shdr;

	d->db_scn = s;
	d->db_off = sh->sh_offset;
	d->db_data.d_align = sh->sh_addralign;
	d->db_data.d_version = elf->ed_version;
	ELFACCESSDATA(work, _elf_work)
	d->db_data.d_type = _elf_mtype(elf, sh->sh_type, work);
	d->db_data.d_buf = 0;
	d->db_data.d_off = 0;
	fsz = elf_fsize(d->db_data.d_type, 1, elf->ed_version);
	msz = _elf_msize(d->db_data.d_type, elf->ed_version);
	d->db_data.d_size = MAX(sh->sh_size, (sh->sh_size / fsz) * msz);
	d->db_shsz = sh->sh_size;
	d->db_raw = 0;
	d->db_buf = 0;
	d->db_uflags = 0;
	d->db_myflags = 0;
	d->db_next = 0;

	if (sh->sh_type != SHT_NOBITS)
		d->db_fsz = sh->sh_size;
	else
		d->db_fsz = 0;

	s->s_myflags |= SF_READY;

	NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*d))
	return (OK_YES);
}



Snode *
_elf_snode()
{
	register Snode	*s;

	if ((s = malloc(sizeof (Snode))) == 0) {
		_elf_seterr(EMEM_SNODE, errno);
		return (0);
	}
	*s = _elf_snode_init;
	ELFMUTEXINIT(&s->sb_scn.s_mutex);
	s->sb_scn.s_myflags = SF_ALLOC | SF_READY;
	s->sb_scn.s_shdr = &s->sb_shdr;
	return (s);
}



int
_elf_ehdr(Elf * elf, int inplace)
{
	NOTE(ASSUMING_PROTECTED(*elf))
	register size_t	fsz;		/* field size */
	Elf_Data	dst, src;

	fsz = elf_fsize(ELF_T_EHDR, 1, elf->ed_version);
	if (fsz > elf->ed_fsz) {
		_elf_seterr(EFMT_EHDRSZ, 0);
		return (-1);
	}
	if (inplace && (fsz >= sizeof (Ehdr))) {
		/*
		 * The translated Ehdr will fit over the original Ehdr.
		 */
		/* LINTED */
		elf->ed_ehdr = (Ehdr *)elf->ed_ident;
		elf->ed_status = ES_COOKED;
	} else {
		elf->ed_ehdr = malloc(sizeof (Ehdr));
		if (elf->ed_ehdr == 0) {
			_elf_seterr(EMEM_EHDR, errno);
			return (-1);
		}
		elf->ed_myflags |= EDF_EHALLOC;
	}

	/*
	 * Memory size >= fsz, because otherwise the memory version
	 * loses information and cannot accurately implement the
	 * file.
	 */

	src.d_buf = (Elf_Void *)elf->ed_ident;
	src.d_type = ELF_T_EHDR;
	src.d_size = fsz;
	src.d_version = elf->ed_version;
	dst.d_buf = (Elf_Void *)elf->ed_ehdr;
	dst.d_size = sizeof (Ehdr);
	dst.d_version = EV_CURRENT;

	if ((_elf_vm(elf, (size_t)0, fsz) != OK_YES) ||
	    (elf_xlatetom(&dst, &src, elf->ed_encode) == 0)) {
		if (elf->ed_myflags & EDF_EHALLOC) {
			elf->ed_myflags &= ~EDF_EHALLOC;
			free(elf->ed_ehdr);
		}
		elf->ed_ehdr = 0;
		return (-1);
	}

	if (((Ehdr*)elf->ed_ehdr)->e_ident[EI_CLASS] != ELFCLASS) {
		_elf_seterr(EREQ_CLASS, 0);
		if (elf->ed_myflags & EDF_EHALLOC) {
			elf->ed_myflags &= ~EDF_EHALLOC;
			free(elf->ed_ehdr);
		}
		elf->ed_ehdr = 0;
		return (-1);
	}

	if (((Ehdr*)elf->ed_ehdr)->e_version != elf->ed_version) {
		_elf_seterr(EFMT_VER2, 0);
		if (elf->ed_myflags & EDF_EHALLOC) {
			elf->ed_myflags &= ~EDF_EHALLOC;
			free(elf->ed_ehdr);
		}
		elf->ed_ehdr = 0;
		return (-1);
	}

	return (0);
}



int
_elf_phdr(Elf * elf, int inplace)
{
	NOTE(ASSUMING_PROTECTED(*elf))
	register size_t		fsz, msz;
	Elf_Data		dst, src;
	Ehdr *			eh = elf->ed_ehdr;	/* must be present */
	unsigned		work;

	if (eh->e_phnum == 0)
		return (0);

	fsz = elf_fsize(ELF_T_PHDR, 1, elf->ed_version);
	if (eh->e_phentsize != fsz) {
		_elf_seterr(EFMT_PHDRSZ, 0);
		return (-1);
	}

	fsz *= eh->e_phnum;
	ELFACCESSDATA(work, _elf_work)
	msz = _elf_msize(ELF_T_PHDR, work) * eh->e_phnum;
	if ((eh->e_phoff == 0) ||
	    ((fsz + eh->e_phoff) > elf->ed_fsz)) {
		_elf_seterr(EFMT_PHTAB, 0);
		return (-1);
	}

	if (inplace && fsz >= msz && eh->e_phoff % sizeof (ElfField) == 0) {
		elf->ed_phdr = (Elf_Void *)(elf->ed_ident + eh->e_phoff);
		elf->ed_status = ES_COOKED;
	} else {
		if ((elf->ed_phdr = malloc(msz)) == 0) {
			_elf_seterr(EMEM_PHDR, errno);
			return (-1);
		}
		elf->ed_myflags |= EDF_PHALLOC;
	}
	src.d_buf = (Elf_Void *)(elf->ed_ident + eh->e_phoff);
	src.d_type = ELF_T_PHDR;
	src.d_size = fsz;
	src.d_version = elf->ed_version;
	dst.d_buf = elf->ed_phdr;
	dst.d_size = msz;
	dst.d_version = work;
	if ((_elf_vm(elf, (size_t)eh->e_phoff, fsz) != OK_YES) ||
	    (elf_xlatetom(&dst, &src, elf->ed_encode) == 0)) {
		if (elf->ed_myflags & EDF_PHALLOC) {
			elf->ed_myflags &= ~EDF_PHALLOC;
			free(elf->ed_phdr);
		}
		elf->ed_phdr = 0;
		return (-1);
	}
	elf->ed_phdrsz = msz;
	return (0);
}



int
_elf_shdr(Elf * elf, int inplace)
{
	NOTE(ASSUMING_PROTECTED(*elf))
	register size_t		fsz, msz;
	size_t			scncnt;
	Elf_Data		dst, src;
	register Ehdr		*eh = elf->ed_ehdr;	/* must be present */

	if ((eh->e_shnum == 0) && (eh->e_shoff == 0))
		return (0);

	fsz = elf_fsize(ELF_T_SHDR, 1, elf->ed_version);
	if (eh->e_shentsize != fsz) {
		_elf_seterr(EFMT_SHDRSZ, 0);
		return (-1);
	}
	/*
	 * If we are dealing with a file with 'extended section
	 * indexes' - then we need to load the first section
	 * header.  The actual section count is stored in
	 * Shdr[0].sh_size.
	 */
	if ((scncnt = eh->e_shnum) == 0) {
		Shdr	sh;
		if ((eh->e_shoff == 0) ||
		    (elf->ed_fsz <= eh->e_shoff) ||
		    (elf->ed_fsz - eh->e_shoff < fsz)) {
			_elf_seterr(EFMT_SHTAB, 0);
			return (-1);
		}
		src.d_buf = (Elf_Void *)(elf->ed_ident + eh->e_shoff);
		src.d_type = ELF_T_SHDR;
		src.d_size = fsz;
		src.d_version = elf->ed_version;
		dst.d_buf = (Elf_Void *)&sh;
		dst.d_size = sizeof (Shdr);
		dst.d_version = EV_CURRENT;
		if ((_elf_vm(elf, (size_t)eh->e_shoff, fsz) != OK_YES) ||
		    (elf_xlatetom(&dst, &src, elf->ed_encode) == 0)) {
			return (-1);
		}
		scncnt = sh.sh_size;
	}

	fsz *= scncnt;
	msz = scncnt * sizeof (Shdr);
	if ((eh->e_shoff == 0) ||
	    (elf->ed_fsz <= eh->e_shoff) ||
	    (elf->ed_fsz - eh->e_shoff < fsz)) {
		_elf_seterr(EFMT_SHTAB, 0);
		return (-1);
	}

	if (inplace && (fsz >= msz) &&
	    ((eh->e_shoff % sizeof (ElfField)) == 0)) {
		/* LINTED */
		elf->ed_shdr = (Shdr *)(elf->ed_ident + eh->e_shoff);
		elf->ed_status = ES_COOKED;
	} else {
		if ((elf->ed_shdr = malloc(msz)) == 0) {
			_elf_seterr(EMEM_SHDR, errno);
			return (-1);
		}
		elf->ed_myflags |= EDF_SHALLOC;
	}
	src.d_buf = (Elf_Void *)(elf->ed_ident + eh->e_shoff);
	src.d_type = ELF_T_SHDR;
	src.d_size = fsz;
	src.d_version = elf->ed_version;
	dst.d_buf = (Elf_Void *)elf->ed_shdr;
	dst.d_size = msz;
	dst.d_version = EV_CURRENT;
	if ((_elf_vm(elf, (size_t)eh->e_shoff, fsz) != OK_YES) ||
	    (elf_xlatetom(&dst, &src, elf->ed_encode) == 0) ||
	    (_elf_prepscn(elf, scncnt) != OK_YES)) {
		if (elf->ed_myflags & EDF_SHALLOC) {
			elf->ed_myflags &= ~EDF_SHALLOC;
			free(elf->ed_shdr);
		}
		elf->ed_shdr = 0;
		return (-1);
	}
	return (0);
}
