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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 */

#include <memory.h>
#include <malloc.h>
#include <limits.h>

#include <sgs.h>
#include "decl.h"
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

#define	FSZ_LONG	ELF64_FSZ_XWORD
#define	ELFCLASS	ELFCLASS64
#define	_elf_snode_init	_elf64_snode_init
#define	_elfxx_cookscn	_elf64_cookscn
#define	_elf_upd_lib	_elf64_upd_lib
#define	elf_fsize	elf64_fsize
#define	_elf_entsz	_elf64_entsz
#define	_elf_msize	_elf64_msize
#define	_elf_upd_usr	_elf64_upd_usr
#define	wrt		wrt64
#define	elf_xlatetof	elf64_xlatetof
#define	_elfxx_update	_elf64_update
#define	_elfxx_swap_wrimage	_elf64_swap_wrimage

#else	/* ELF32 */

#define	FSZ_LONG	ELF32_FSZ_WORD
#define	ELFCLASS	ELFCLASS32
#define	_elf_snode_init	_elf32_snode_init
#define	_elfxx_cookscn	_elf32_cookscn
#define	_elf_upd_lib	_elf32_upd_lib
#define	elf_fsize	elf32_fsize
#define	_elf_entsz	_elf32_entsz
#define	_elf_msize	_elf32_msize
#define	_elf_upd_usr	_elf32_upd_usr
#define	wrt		wrt32
#define	elf_xlatetof	elf32_xlatetof
#define	_elfxx_update	_elf32_update
#define	_elfxx_swap_wrimage	_elf32_swap_wrimage

#endif /* ELF64 */


#if	!(defined(_LP64) && defined(_ELF64))
#define	TEST_SIZE

/*
 * Handle the decision of whether the current linker can handle the
 * desired object size, and if not, which error to issue.
 *
 * Input is the desired size. On failure, an error has been issued
 * and 0 is returned. On success, 1 is returned.
 */
static int
test_size(Lword hi)
{
#ifndef _LP64			/* 32-bit linker */
	/*
	 * A 32-bit libelf is limited to a 2GB output file. This limit
	 * is due to the fact that off_t is a signed value, and that
	 * libelf cannot support large file support:
	 *	- ABI reasons
	 *	- Memory use generally is 2x output file size anyway,
	 *		so lifting the file size limit will just send
	 *		you crashing into the 32-bit VM limit.
	 * If the output is an ELFCLASS64 object, or an ELFCLASS32 object
	 * under 4GB, switching to the 64-bit version of libelf will help.
	 * However, an ELFCLASS32 object must not exceed 4GB.
	 */
	if (hi > INT_MAX) {	/* Bigger than 2GB */
#ifndef _ELF64
		/* ELFCLASS32 object is fundamentally too big? */
		if (hi > UINT_MAX) {
			_elf_seterr(EFMT_FBIG_CLASS32, 0);
			return (0);
		}
#endif				/* _ELF64 */

		/* Should switch to the 64-bit libelf? */
		_elf_seterr(EFMT_FBIG_LARGEFILE, 0);
		return (0);
	}
#endif				/* !_LP64 */


#if	defined(_LP64) && !defined(_ELF64)   /* 64-bit linker, ELFCLASS32 */
	/*
	 * A 64-bit linker can produce any size output
	 * file, but if the resulting file is ELFCLASS32,
	 * it must not exceed 4GB.
	 */
	if (hi > UINT_MAX) {
		_elf_seterr(EFMT_FBIG_CLASS32, 0);
		return (0);
	}
#endif

	return (1);
}
#endif				/* TEST_SIZE */

/*
 * Output file update
 *	These functions walk an Elf structure, update its information,
 *	and optionally write the output file.  Because the application
 *	may control of the output file layout, two upd_... routines
 *	exist.  They're similar but too different to merge cleanly.
 *
 *	The library defines a "dirty" bit to force parts of the file
 *	to be written on update.  These routines ignore the dirty bit
 *	and do everything.  A minimal update routine might be useful
 *	someday.
 */

static size_t
_elf_upd_lib(Elf * elf)
{
	NOTE(ASSUMING_PROTECTED(*elf))
	Lword		hi;
	Lword		hibit;
	Elf_Scn *	s;
	register Lword	sz;
	Ehdr *		eh = elf->ed_ehdr;
	unsigned	ver = eh->e_version;
	register char	*p = (char *)eh->e_ident;
	size_t		scncnt;

	/*
	 * Ehdr and Phdr table go first
	 */
	p[EI_MAG0] = ELFMAG0;
	p[EI_MAG1] = ELFMAG1;
	p[EI_MAG2] = ELFMAG2;
	p[EI_MAG3] = ELFMAG3;
	p[EI_CLASS] = ELFCLASS;
	/* LINTED */
	p[EI_VERSION] = (Byte)ver;
	hi = elf_fsize(ELF_T_EHDR, 1, ver);
	/* LINTED */
	eh->e_ehsize = (Half)hi;
	if (eh->e_phnum != 0) {
		/* LINTED */
		eh->e_phentsize = (Half)elf_fsize(ELF_T_PHDR, 1, ver);
		/* LINTED */
		eh->e_phoff = (Off)hi;
		hi += eh->e_phentsize * eh->e_phnum;
	} else {
		eh->e_phoff = 0;
		eh->e_phentsize = 0;
	}

	/*
	 * Obtain the first section header.  Typically, this section has NULL
	 * contents, however in the case of Extended ELF Sections this section
	 * is used to hold an alternative e_shnum, e_shstrndx and e_phnum.
	 * On initial allocation (see _elf_snode) the elements of this section
	 * would have been zeroed.  The e_shnum is initialized later, after the
	 * section header count has been determined.  The e_shstrndx and
	 * e_phnum may have already been initialized by the caller (for example,
	 * gelf_update_shdr() in mcs(1)).
	 */
	if ((s = elf->ed_hdscn) == 0) {
		eh->e_shnum = 0;
		scncnt = 0;
	} else {
		s = s->s_next;
		scncnt = 1;
	}

	/*
	 * Loop through sections.  Compute section size before changing hi.
	 * Allow null buffers for NOBITS.
	 */
	hibit = 0;
	for (; s != 0; s = s->s_next) {
		register Dnode	*d;
		register Lword	fsz, j;
		Shdr *sh = s->s_shdr;

		scncnt++;
		if (sh->sh_type == SHT_NULL) {
			*sh = _elf_snode_init.sb_shdr;
			continue;
		}

		if ((s->s_myflags & SF_READY) == 0)
			(void) _elfxx_cookscn(s);

		sh->sh_addralign = 1;
		if ((sz = (Lword)_elf_entsz(elf, sh->sh_type, ver)) != 0)
			/* LINTED */
			sh->sh_entsize = (Half)sz;
		sz = 0;
		for (d = s->s_hdnode; d != 0; d = d->db_next) {
			if ((fsz = elf_fsize(d->db_data.d_type,
			    1, ver)) == 0)
				return (0);

			j = _elf_msize(d->db_data.d_type, ver);
			fsz *= (d->db_data.d_size / j);
			d->db_osz = (size_t)fsz;
			if ((j = d->db_data.d_align) > 1) {
				if (j > sh->sh_addralign)
					sh->sh_addralign = (Xword)j;

				if (sz % j != 0)
					sz += j - sz % j;
			}
			d->db_data.d_off = (off_t)sz;
			d->db_xoff = sz;
			sz += fsz;
		}

		sh->sh_size = (Xword) sz;
		/*
		 * We want to take into account the offsets for NOBITS
		 * sections and let the "sh_offsets" point to where
		 * the section would 'conceptually' fit within
		 * the file (as required by the ABI).
		 *
		 * But - we must also make sure that the NOBITS does
		 * not take up any actual space in the file.  We preserve
		 * the actual offset into the file in the 'hibit' variable.
		 * When we come to the first non-NOBITS section after a
		 * encountering a NOBITS section the hi counter is restored
		 * to its proper place in the file.
		 */
		if (sh->sh_type == SHT_NOBITS) {
			if (hibit == 0)
				hibit = hi;
		} else {
			if (hibit) {
				hi = hibit;
				hibit = 0;
			}
		}
		j = sh->sh_addralign;
		if ((fsz = hi % j) != 0)
			hi += j - fsz;

		/* LINTED */
		sh->sh_offset = (Off)hi;
		hi += sz;
	}

	/*
	 * if last section was a 'NOBITS' section then we need to
	 * restore the 'hi' counter to point to the end of the last
	 * non 'NOBITS' section.
	 */
	if (hibit) {
		hi = hibit;
		hibit = 0;
	}

	/*
	 * Shdr table last
	 */
	if (scncnt != 0) {
		if (hi % FSZ_LONG != 0)
			hi += FSZ_LONG - hi % FSZ_LONG;
		/* LINTED */
		eh->e_shoff = (Off)hi;
		/*
		 * If we are using 'extended sections' then the
		 * e_shnum is stored in the sh_size field of the
		 * first section header.
		 *
		 * NOTE: we set e_shnum to '0' because it's specified
		 * this way in the gABI, and in the hopes that
		 * this will cause less problems to unaware
		 * tools then if we'd set it to SHN_XINDEX (0xffff).
		 */
		if (scncnt < SHN_LORESERVE)
			eh->e_shnum = scncnt;
		else {
			Shdr	*sh;
			sh = (Shdr *)elf->ed_hdscn->s_shdr;
			sh->sh_size = scncnt;
			eh->e_shnum = 0;
		}
		/* LINTED */
		eh->e_shentsize = (Half)elf_fsize(ELF_T_SHDR, 1, ver);
		hi += eh->e_shentsize * scncnt;
	} else {
		eh->e_shoff = 0;
		eh->e_shentsize = 0;
	}

#ifdef TEST_SIZE
	if (test_size(hi) == 0)
		return (0);
#endif

	return ((size_t)hi);
}



static size_t
_elf_upd_usr(Elf * elf)
{
	NOTE(ASSUMING_PROTECTED(*elf))
	Lword		hi;
	Elf_Scn *	s;
	register Lword	sz;
	Ehdr *		eh = elf->ed_ehdr;
	unsigned	ver = eh->e_version;
	register char	*p = (char *)eh->e_ident;
	size_t		scncnt;

	/*
	 * Ehdr and Phdr table go first
	 */
	p[EI_MAG0] = ELFMAG0;
	p[EI_MAG1] = ELFMAG1;
	p[EI_MAG2] = ELFMAG2;
	p[EI_MAG3] = ELFMAG3;
	p[EI_CLASS] = ELFCLASS;
	/* LINTED */
	p[EI_VERSION] = (Byte)ver;
	hi = elf_fsize(ELF_T_EHDR, 1, ver);
	/* LINTED */
	eh->e_ehsize = (Half)hi;

	/*
	 * If phnum is zero, phoff "should" be zero too,
	 * but the application is responsible for it.
	 * Allow a non-zero value here and update the
	 * hi water mark accordingly.
	 */

	if (eh->e_phnum != 0)
		/* LINTED */
		eh->e_phentsize = (Half)elf_fsize(ELF_T_PHDR, 1, ver);
	else
		eh->e_phentsize = 0;
	if ((sz = eh->e_phoff + eh->e_phentsize * eh->e_phnum) > hi)
		hi = sz;

	/*
	 * Loop through sections, skipping index zero.
	 * Compute section size before changing hi.
	 * Allow null buffers for NOBITS.
	 */

	if ((s = elf->ed_hdscn) == 0) {
		eh->e_shnum = 0;
		scncnt = 0;
	} else {
		scncnt = 1;
		s = s->s_next;
	}
	for (; s != 0; s = s->s_next) {
		register Dnode	*d;
		register Lword	fsz, j;
		Shdr *sh = s->s_shdr;

		if ((s->s_myflags & SF_READY) == 0)
			(void) _elfxx_cookscn(s);

		++scncnt;
		sz = 0;
		for (d = s->s_hdnode; d != 0; d = d->db_next) {
			if ((fsz = elf_fsize(d->db_data.d_type, 1,
			    ver)) == 0)
				return (0);
			j = _elf_msize(d->db_data.d_type, ver);
			fsz *= (d->db_data.d_size / j);
			d->db_osz = (size_t)fsz;

			if ((sh->sh_type != SHT_NOBITS) &&
			    ((j = (d->db_data.d_off + d->db_osz)) > sz))
				sz = j;
		}
		if (sh->sh_size < sz) {
			_elf_seterr(EFMT_SCNSZ, 0);
			return (0);
		}
		if ((sh->sh_type != SHT_NOBITS) &&
		    (hi < sh->sh_offset + sh->sh_size))
			hi = sh->sh_offset + sh->sh_size;
	}

	/*
	 * Shdr table last.  Comment above for phnum/phoff applies here.
	 */
	if (scncnt != 0) {
		/* LINTED */
		eh->e_shentsize = (Half)elf_fsize(ELF_T_SHDR, 1, ver);
		if (scncnt < SHN_LORESERVE) {
			eh->e_shnum = scncnt;
		} else {
			Shdr *sh;
			sh = (Shdr *)elf->ed_hdscn->s_shdr;
			sh->sh_size = scncnt;
			eh->e_shnum = 0;
		}
	} else {
		eh->e_shentsize = 0;
	}

	if ((sz = eh->e_shoff + eh->e_shentsize * scncnt) > hi)
		hi = sz;

#ifdef TEST_SIZE
	if (test_size(hi) == 0)
		return (0);
#endif

	return ((size_t)hi);
}


static size_t
wrt(Elf * elf, Xword outsz, unsigned fill, int update_cmd)
{
	NOTE(ASSUMING_PROTECTED(*elf))
	Elf_Data		dst, src;
	unsigned		flag;
	Xword			hi, sz;
	char			*image;
	Elf_Scn			*s;
	Ehdr			*eh = elf->ed_ehdr;
	unsigned		ver = eh->e_version;
	unsigned		encode;
	int			byte;
	_elf_execfill_func_t	*execfill_func;

	/*
	 * If this is an ELF_C_WRIMAGE write, then we encode into the
	 * byte order of the system we are running on rather than that of
	 * of the object. For ld.so.1, this is the same order, but
	 * for 'ld', it might not be in the case where we are cross
	 * linking an object for a different target. In this later case,
	 * the linker-host byte order is necessary so that the linker can
	 * manipulate the resulting  image. It is expected that the linker
	 * will call elf_swap_wrimage() if necessary to convert the image
	 * to the target byte order.
	 */
	encode = (update_cmd == ELF_C_WRIMAGE) ? _elf_sys_encoding() :
	    eh->e_ident[EI_DATA];

	/*
	 * Two issues can cause trouble for the output file.
	 * First, begin() with ELF_C_RDWR opens a file for both
	 * read and write.  On the write update(), the library
	 * has to read everything it needs before truncating
	 * the file.  Second, using mmap for both read and write
	 * is too tricky.  Consequently, the library disables mmap
	 * on the read side.  Using mmap for the output saves swap
	 * space, because that mapping is SHARED, not PRIVATE.
	 *
	 * If the file is write-only, there can be nothing of
	 * interest to bother with.
	 *
	 * The following reads the entire file, which might be
	 * more than necessary.  Better safe than sorry.
	 */

	if ((elf->ed_myflags & EDF_READ) &&
	    (_elf_vm(elf, (size_t)0, elf->ed_fsz) != OK_YES))
		return (0);

	flag = elf->ed_myflags & EDF_WRALLOC;
	if ((image = _elf_outmap(elf->ed_fd, outsz, &flag)) == 0)
		return (0);

	if (flag == 0)
		elf->ed_myflags |= EDF_IMALLOC;

	/*
	 * If an error occurs below, a "dirty" bit may be cleared
	 * improperly.  To save a second pass through the file,
	 * this code sets the dirty bit on the elf descriptor
	 * when an error happens, assuming that will "cover" any
	 * accidents.
	 */

	/*
	 * Hi is needed only when 'fill' is non-zero.
	 * Fill is non-zero only when the library
	 * calculates file/section/data buffer offsets.
	 * The lib guarantees they increase monotonically.
	 * That guarantees proper filling below.
	 */


	/*
	 * Ehdr first
	 */

	src.d_buf = (Elf_Void *)eh;
	src.d_type = ELF_T_EHDR;
	src.d_size = sizeof (Ehdr);
	src.d_version = EV_CURRENT;
	dst.d_buf = (Elf_Void *)image;
	dst.d_size = eh->e_ehsize;
	dst.d_version = ver;
	if (elf_xlatetof(&dst, &src, encode) == 0)
		return (0);
	elf->ed_ehflags &= ~ELF_F_DIRTY;
	hi = eh->e_ehsize;

	/*
	 * Phdr table if one exists
	 */

	if (eh->e_phnum != 0) {
		unsigned	work;
		/*
		 * Unlike other library data, phdr table is
		 * in the user version.  Change src buffer
		 * version here, fix it after translation.
		 */

		src.d_buf = (Elf_Void *)elf->ed_phdr;
		src.d_type = ELF_T_PHDR;
		src.d_size = elf->ed_phdrsz;
		ELFACCESSDATA(work, _elf_work)
		src.d_version = work;
		dst.d_buf = (Elf_Void *)(image + eh->e_phoff);
		dst.d_size = eh->e_phnum * eh->e_phentsize;
		hi = (Xword)(eh->e_phoff + dst.d_size);
		if (elf_xlatetof(&dst, &src, encode) == 0) {
			elf->ed_uflags |= ELF_F_DIRTY;
			return (0);
		}
		elf->ed_phflags &= ~ELF_F_DIRTY;
		src.d_version = EV_CURRENT;
	}

	/*
	 * Loop through sections
	 */

	ELFACCESSDATA(byte, _elf_byte);
	ELFACCESSDATA(execfill_func, _elf_execfill_func);
	for (s = elf->ed_hdscn; s != 0; s = s->s_next) {
		register Dnode	*d, *prevd;
		Xword		off = 0;
		Shdr		*sh = s->s_shdr;
		char		*start = image + sh->sh_offset;
		char		*here;
		_elf_execfill_func_t	*execfill;

		/* Only use the execfill function on SHF_EXECINSTR sections */
		execfill = (sh->sh_flags & SHF_EXECINSTR) ?
		    execfill_func : NULL;

		/*
		 * Just "clean" DIRTY flag for "empty" sections.  Even if
		 * NOBITS needs padding, the next thing in the
		 * file will provide it.  (And if this NOBITS is
		 * the last thing in the file, no padding needed.)
		 */
		if ((sh->sh_type == SHT_NOBITS) ||
		    (sh->sh_type == SHT_NULL)) {
			d = s->s_hdnode, prevd = 0;
			for (; d != 0; prevd = d, d = d->db_next)
				d->db_uflags &= ~ELF_F_DIRTY;
			continue;
		}
		/*
		 * Clear out the memory between the end of the last
		 * section and the begining of this section.
		 */
		if (fill && (sh->sh_offset > hi)) {
			sz = sh->sh_offset - hi;
			(void) memset(start - sz, byte, sz);
		}


		for (d = s->s_hdnode, prevd = 0;
		    d != 0; prevd = d, d = d->db_next) {
			d->db_uflags &= ~ELF_F_DIRTY;
			here = start + d->db_data.d_off;

			/*
			 * Clear out the memory between the end of the
			 * last update and the start of this data buffer.
			 *
			 * These buffers represent input sections that have
			 * been concatenated into an output section, so if
			 * the output section is executable (SHF_EXECINSTR)
			 * and a fill function has been registered, use the
			 * function. Otherwise, use the fill byte.
			 */
			if (fill && (d->db_data.d_off > off)) {
				sz = (Xword)(d->db_data.d_off - off);
				if (execfill != NULL)
					(* execfill)(start,
					    here - start - sz, sz);
				else
					(void) memset(here - sz, byte, sz);
			}

			if ((d->db_myflags & DBF_READY) == 0) {
				SCNLOCK(s);
				if (_elf_locked_getdata(s, &prevd->db_data) !=
				    &d->db_data) {
					elf->ed_uflags |= ELF_F_DIRTY;
					SCNUNLOCK(s);
					return (0);
				}
				SCNUNLOCK(s);
			}
			dst.d_buf = (Elf_Void *)here;
			dst.d_size = d->db_osz;

			/*
			 * Copy the translated bits out to the destination
			 * image.
			 */
			if (elf_xlatetof(&dst, &d->db_data, encode) == 0) {
				elf->ed_uflags |= ELF_F_DIRTY;
				return (0);
			}

			off = (Xword)(d->db_data.d_off + dst.d_size);
		}
		hi = sh->sh_offset + sh->sh_size;
	}

	/*
	 * Shdr table last
	 */

	if (fill && (eh->e_shoff > hi)) {
		sz = eh->e_shoff - hi;
		(void) memset(image + hi, byte, sz);
	}

	src.d_type = ELF_T_SHDR;
	src.d_size = sizeof (Shdr);
	dst.d_buf = (Elf_Void *)(image + eh->e_shoff);
	dst.d_size = eh->e_shentsize;
	for (s = elf->ed_hdscn; s != 0; s = s->s_next) {
		assert((uintptr_t)dst.d_buf < ((uintptr_t)image + outsz));
		s->s_shflags &= ~ELF_F_DIRTY;
		s->s_uflags &= ~ELF_F_DIRTY;
		src.d_buf = s->s_shdr;

		if (elf_xlatetof(&dst, &src, encode) == 0) {
			elf->ed_uflags |= ELF_F_DIRTY;
			return (0);
		}

		dst.d_buf = (char *)dst.d_buf + eh->e_shentsize;
	}
	/*
	 * ELF_C_WRIMAGE signifyes that we build the memory image, but
	 * that we do not actually write it to disk.  This is used
	 * by ld(1) to build up a full image of an elf file and then
	 * to process the file before it's actually written out to
	 * disk.  This saves ld(1) the overhead of having to write
	 * the image out to disk twice.
	 */
	if (update_cmd == ELF_C_WRIMAGE) {
		elf->ed_uflags &= ~ELF_F_DIRTY;
		elf->ed_wrimage = image;
		elf->ed_wrimagesz = outsz;
		return (outsz);
	}

	if (_elf_outsync(elf->ed_fd, image, outsz,
	    ((elf->ed_myflags & EDF_IMALLOC) ? 0 : 1)) != 0) {
		elf->ed_uflags &= ~ELF_F_DIRTY;
		elf->ed_myflags &= ~EDF_IMALLOC;
		return (outsz);
	}

	elf->ed_uflags |= ELF_F_DIRTY;
	return (0);
}




/*
 * The following is a private interface between the linkers (ld & ld.so.1)
 * and libelf:
 *
 * elf_update(elf, ELF_C_WRIMAGE)
 *	This will cause full image representing the elf file
 *	described by the elf pointer to be built in memory.  If the
 *	elf pointer has a valid file descriptor associated with it
 *	we will attempt to build the memory image from mmap()'ed
 *	storage.  If the elf descriptor does not have a valid
 *	file descriptor (opened with elf_begin(0, ELF_C_IMAGE, 0))
 *	then the image will be allocated from dynamic memory (malloc()).
 *
 *	elf_update() will return the size of the memory image built
 *	when sucessful.
 *
 *	When a subsequent call to elf_update() with ELF_C_WRITE as
 *	the command is performed it will sync the image created
 *	by ELF_C_WRIMAGE to disk (if fd available) and
 *	free the memory allocated.
 */

off_t
_elfxx_update(Elf * elf, Elf_Cmd cmd)
{
	size_t		sz;
	unsigned	u;
	Ehdr		*eh = elf->ed_ehdr;

	if (elf == 0)
		return (-1);

	ELFWLOCK(elf)
	switch (cmd) {
	default:
		_elf_seterr(EREQ_UPDATE, 0);
		ELFUNLOCK(elf)
		return (-1);

	case ELF_C_WRIMAGE:
		if ((elf->ed_myflags & EDF_WRITE) == 0) {
			_elf_seterr(EREQ_UPDWRT, 0);
			ELFUNLOCK(elf)
			return (-1);
		}
		break;
	case ELF_C_WRITE:
		if ((elf->ed_myflags & EDF_WRITE) == 0) {
			_elf_seterr(EREQ_UPDWRT, 0);
			ELFUNLOCK(elf)
			return (-1);
		}
		if (elf->ed_wrimage) {
			if (elf->ed_myflags & EDF_WRALLOC) {
				free(elf->ed_wrimage);
				/*
				 * The size is still returned even
				 * though nothing is actually written
				 * out.  This is just to be consistant
				 * with the rest of the interface.
				 */
				sz = elf->ed_wrimagesz;
				elf->ed_wrimage = 0;
				elf->ed_wrimagesz = 0;
				ELFUNLOCK(elf);
				return ((off_t)sz);
			}
			sz = _elf_outsync(elf->ed_fd, elf->ed_wrimage,
			    elf->ed_wrimagesz,
			    (elf->ed_myflags & EDF_IMALLOC ? 0 : 1));
			elf->ed_myflags &= ~EDF_IMALLOC;
			elf->ed_wrimage = 0;
			elf->ed_wrimagesz = 0;
			ELFUNLOCK(elf);
			return ((off_t)sz);
		}
		/* FALLTHROUGH */
	case ELF_C_NULL:
		break;
	}

	if (eh == 0) {
		_elf_seterr(ESEQ_EHDR, 0);
		ELFUNLOCK(elf)
		return (-1);
	}

	if ((u = eh->e_version) > EV_CURRENT) {
		_elf_seterr(EREQ_VER, 0);
		ELFUNLOCK(elf)
		return (-1);
	}

	if (u == EV_NONE)
		eh->e_version = EV_CURRENT;

	if ((u = eh->e_ident[EI_DATA]) == ELFDATANONE) {
		unsigned	encode;

		ELFACCESSDATA(encode, _elf_encode)
		if (encode == ELFDATANONE) {
			_elf_seterr(EREQ_ENCODE, 0);
			ELFUNLOCK(elf)
			return (-1);
		}
		/* LINTED */
		eh->e_ident[EI_DATA] = (Byte)encode;
	}

	u = 1;
	if (elf->ed_uflags & ELF_F_LAYOUT) {
		sz = _elf_upd_usr(elf);
		u = 0;
	} else
		sz = _elf_upd_lib(elf);

	if ((sz != 0) && ((cmd == ELF_C_WRITE) || (cmd == ELF_C_WRIMAGE)))
		sz = wrt(elf, (Xword)sz, u, cmd);

	if (sz == 0) {
		ELFUNLOCK(elf)
		return (-1);
	}

	ELFUNLOCK(elf)
	return ((off_t)sz);
}


/*
 * When wrt() processes an ELF_C_WRIMAGE request, the resulting image
 * gets the byte order (encoding) of the platform running the linker
 * rather than that of the target host. This allows the linker to modify
 * the image, prior to flushing it to the output file. This routine
 * is used to re-translate such an image into the byte order of the
 * target host.
 */
int
_elfxx_swap_wrimage(Elf *elf)
{
	Elf_Data	dst, src;
	Elf_Scn		*s;
	Ehdr		*eh;
	Half		e_phnum;
	unsigned	ver;
	unsigned	encode;

	/*
	 * Ehdr first
	 */

	ELFWLOCK(elf);
	eh = elf->ed_ehdr;
	e_phnum = eh->e_phnum;
	ver = eh->e_version;
	encode = eh->e_ident[EI_DATA];

	src.d_buf = dst.d_buf = (Elf_Void *)eh;
	src.d_type = dst.d_type = ELF_T_EHDR;
	src.d_size = dst.d_size = sizeof (Ehdr);
	src.d_version = dst.d_version = ver;
	if (elf_xlatetof(&dst, &src, encode) == 0) {
		ELFUNLOCK(elf);
		return (1);
	}

	/*
	 * Phdr table if one exists
	 */

	if (e_phnum != 0) {
		unsigned	work;
		/*
		 * Unlike other library data, phdr table is
		 * in the user version.
		 */

		src.d_buf = dst.d_buf = (Elf_Void *)elf->ed_phdr;
		src.d_type = dst.d_type = ELF_T_PHDR;
		src.d_size = dst.d_size = elf->ed_phdrsz;
		ELFACCESSDATA(work, _elf_work)
		src.d_version = dst.d_version = work;
		if (elf_xlatetof(&dst, &src, encode) == 0) {
			ELFUNLOCK(elf);
			return (1);
		}
	}

	/*
	 * Loop through sections
	 */

	for (s = elf->ed_hdscn; s != 0; s = s->s_next) {
		register Dnode	*d, *prevd;
		Shdr		*sh = s->s_shdr;

		if ((sh->sh_type == SHT_NOBITS) || (sh->sh_type == SHT_NULL))
			continue;

		for (d = s->s_hdnode, prevd = 0;
		    d != 0; prevd = d, d = d->db_next) {

			if ((d->db_myflags & DBF_READY) == 0) {
				SCNLOCK(s);
				if (_elf_locked_getdata(s, &prevd->db_data) !=
				    &d->db_data) {
					SCNUNLOCK(s);
					ELFUNLOCK(elf);
					return (1);
				}
				SCNUNLOCK(s);
			}

			dst = d->db_data;
			if (elf_xlatetof(&dst, &d->db_data, encode) == 0) {
				ELFUNLOCK(elf);
				return (1);
			}
		}
	}

	/*
	 * Shdr table
	 */

	src.d_type = dst.d_type = ELF_T_SHDR;
	src.d_version = dst.d_version = ver;
	for (s = elf->ed_hdscn; s != 0; s = s->s_next) {
		src.d_buf = dst.d_buf = s->s_shdr;
		src.d_size = dst.d_size = sizeof (Shdr);
		if (elf_xlatetof(&dst, &src, encode) == 0) {
			ELFUNLOCK(elf);
			return (1);
		}
	}

	ELFUNLOCK(elf);
	return (0);
}



#ifndef _ELF64
/* class-independent, only needs to be compiled once */

off_t
elf_update(Elf *elf, Elf_Cmd cmd)
{
	if (elf == 0)
		return (-1);

	if (elf->ed_class == ELFCLASS32)
		return (_elf32_update(elf, cmd));
	else if (elf->ed_class == ELFCLASS64) {
		return (_elf64_update(elf, cmd));
	}

	_elf_seterr(EREQ_CLASS, 0);
	return (-1);
}

int
_elf_swap_wrimage(Elf *elf)
{
	if (elf == 0)
		return (0);

	if (elf->ed_class == ELFCLASS32)
		return (_elf32_swap_wrimage(elf));

	if (elf->ed_class == ELFCLASS64)
		return (_elf64_swap_wrimage(elf));

	_elf_seterr(EREQ_CLASS, 0);
	return (0);
}

/*
 * 4106312, 4106398, This is an ad-hoc means for the 32-bit
 * Elf64 version of libld.so.3 to get around the limitation
 * of a 32-bit d_off field.  This is only intended to be
 * used by libld to relocate symbols in large NOBITS sections.
 */
Elf64_Off
_elf_getxoff(Elf_Data * d)
{
	return (((Dnode *)d)->db_xoff);
}
#endif /* !_ELF64 */
