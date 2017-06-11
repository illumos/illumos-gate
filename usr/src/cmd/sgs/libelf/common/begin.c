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
 *	Copyright (c) 1988 AT&T
 *	All Rights Reserved
 */

#include <ar.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <libelf.h>
#include <sys/mman.h>
#include "decl.h"
#include "member.h"
#include "msg.h"

static const char	armag[] = ARMAG;


/*
 * Initialize archive member
 */
Elf *
_elf_member(int fd, Elf * ref, unsigned flags)
{
	register Elf	*elf;
	Member		*mh;
	size_t		base;

	if (ref->ed_nextoff >= ref->ed_fsz)
		return (0);
	if (ref->ed_fd == -1)		/* disabled */
		fd = -1;
	if (flags & EDF_WRITE) {
		_elf_seterr(EREQ_ARRDWR, 0);
		return (0);
	}
	if (ref->ed_fd != fd) {
		_elf_seterr(EREQ_ARMEMFD, 0);
		return (0);
	}
	if ((_elf_vm(ref, ref->ed_nextoff, sizeof (struct ar_hdr)) !=
	    OK_YES) || ((mh = _elf_armem(ref,
	    ref->ed_ident + ref->ed_nextoff, ref->ed_fsz)) == 0))
		return (0);

	base = ref->ed_nextoff + sizeof (struct ar_hdr);
	if (ref->ed_fsz - base < mh->m_hdr.ar_size) {
		_elf_seterr(EFMT_ARMEMSZ, 0);
		return (0);
	}
	if ((elf = (Elf *)calloc(1, sizeof (Elf))) == 0) {
		_elf_seterr(EMEM_ELF, errno);
		return (0);
	}
	++ref->ed_activ;
	elf->ed_parent = ref;
	elf->ed_fd = fd;
	elf->ed_myflags |= flags;
	elf->ed_armem = mh;
	elf->ed_fsz = mh->m_hdr.ar_size;
	elf->ed_baseoff = ref->ed_baseoff + base;
	elf->ed_memoff = base - mh->m_slide;
	elf->ed_siboff = base + elf->ed_fsz + (elf->ed_fsz & 1);
	ref->ed_nextoff = elf->ed_siboff;
	elf->ed_image = ref->ed_image;
	elf->ed_imagesz = ref->ed_imagesz;
	elf->ed_vm = ref->ed_vm;
	elf->ed_vmsz = ref->ed_vmsz;
	elf->ed_ident = ref->ed_ident + base - mh->m_slide;

	/*
	 * If this member is the archive string table,
	 * we've already altered the bytes.
	 */

	if (ref->ed_arstroff == ref->ed_nextoff)
		elf->ed_status = ES_COOKED;
	return (elf);
}


Elf *
_elf_regular(int fd, unsigned flags)		/* initialize regular file */
{
	Elf		*elf;

	if ((elf = (Elf *)calloc(1, sizeof (Elf))) == 0) {
		_elf_seterr(EMEM_ELF, errno);
		return (0);
	}

	elf->ed_fd = fd;
	elf->ed_myflags |= flags;
	if (_elf_inmap(elf) != OK_YES) {
		free(elf);
		return (0);
	}
	return (elf);
}


Elf *
_elf_config(Elf * elf)
{
	char		*base;
	unsigned	encode;

	ELFRWLOCKINIT(&elf->ed_rwlock);

	/*
	 * Determine if this is a ELF file.
	 */
	base = elf->ed_ident;
	if ((elf->ed_fsz >= EI_NIDENT) &&
	    (_elf_vm(elf, (size_t)0, (size_t)EI_NIDENT) == OK_YES) &&
	    (base[EI_MAG0] == ELFMAG0) &&
	    (base[EI_MAG1] == ELFMAG1) &&
	    (base[EI_MAG2] == ELFMAG2) &&
	    (base[EI_MAG3] == ELFMAG3)) {
		elf->ed_kind = ELF_K_ELF;
		elf->ed_class = base[EI_CLASS];
		elf->ed_encode = base[EI_DATA];
		if ((elf->ed_version = base[EI_VERSION]) == 0)
			elf->ed_version = 1;
		elf->ed_identsz = EI_NIDENT;

		/*
		 * Allow writing only if originally specified read only.
		 * This is only necessary if the file must be translating
		 * from one encoding to another.
		 */
		ELFACCESSDATA(encode, _elf_encode)
		if ((elf->ed_vm == 0) && ((elf->ed_myflags & EDF_WRITE) == 0) &&
		    (elf->ed_encode != encode)) {
			if (mprotect((char *)elf->ed_image, elf->ed_imagesz,
			    PROT_READ|PROT_WRITE) == -1) {
				_elf_seterr(EIO_VM, errno);
				return (0);
			}
		}
		return (elf);
	}

	/*
	 * Determine if this is an Archive
	 */
	if ((elf->ed_fsz >= SARMAG) &&
	    (_elf_vm(elf, (size_t)0, (size_t)SARMAG) == OK_YES) &&
	    (memcmp(base, armag, SARMAG) == 0)) {
		_elf_arinit(elf);
		elf->ed_kind = ELF_K_AR;
		elf->ed_identsz = SARMAG;
		return (elf);
	}

	/*
	 *	Return a few ident bytes, but not so many that
	 *	getident() must read a large file.  512 is arbitrary.
	 */

	elf->ed_kind = ELF_K_NONE;
	if ((elf->ed_identsz = elf->ed_fsz) > 512)
		elf->ed_identsz = 512;

	return (elf);
}

Elf *
elf_memory(char *image, size_t sz)
{
	Elf		*elf;
	unsigned	work;

	/*
	 * version() no called yet?
	 */
	ELFACCESSDATA(work, _elf_work)
	if (work == EV_NONE) {
		_elf_seterr(ESEQ_VER, 0);
		return (0);
	}

	if ((elf = (Elf *)calloc(1, sizeof (Elf))) == 0) {
		_elf_seterr(EMEM_ELF, errno);
		return (0);
	}
	elf->ed_fd = -1;
	elf->ed_myflags |= EDF_READ | EDF_MEMORY;
	elf->ed_image = elf->ed_ident = image;
	elf->ed_imagesz = elf->ed_fsz = elf->ed_identsz = sz;
	elf->ed_kind = ELF_K_ELF;
	elf->ed_class = image[EI_CLASS];
	elf->ed_encode = image[EI_DATA];
	if ((elf->ed_version = image[EI_VERSION]) == 0)
		elf->ed_version = 1;
	elf->ed_identsz = EI_NIDENT;
	elf->ed_activ = 1;
	elf = _elf_config(elf);
	return (elf);
}

/*
 * The following is a private interface between the linkers (ld & ld.so.1)
 * and libelf.
 *
 * elf_begin(0, ELF_C_IMAGE, ref)
 *	Return a new elf_descriptor which uses the memory image from
 *	ref as the base image of the elf file.  Before this elf_begin()
 *	is called an elf_update(ref, ELF_C_WRIMAGE) must have been
 *	done to the ref elf descriptor.
 *	The ELF_C_IMAGE is unique in that modificatino of the Elf structure
 *	is illegal (no elf_new*()) but you can modify the actual
 *	data image of the file in question.
 *
 *	When you are done processing this file you can then perform a
 *	elf_end() on it.
 *
 *	NOTE: if an elf_update(ref, ELF_C_WRITE) is done on the ref Elf
 *		descriptor then the memory image that the ELF_C_IMAGE
 *		is using has been discarded.  The proper calling convention
 *		for this is as follows:
 *
 *	elf1 = elf_begin(fd, ELF_C_WRITE, 0);
 *	...
 *	elf_update(elf1, ELF_C_WRIMAGE);	 build memory image
 *	elf2 = elf_begin(0, ELF_C_IMAGE, elf1);
 *	...
 *	elf_end(elf2);
 *	elf_updage(elf1, ELF_C_WRITE);		flush memory image to disk
 *	elf_end(elf1);
 *
 *
 * elf_begin(0, ELF_C_IMAGE, 0);
 *	returns a pointer to an elf descriptor as if it were opened
 *	with ELF_C_WRITE except that it has no file descriptor and it
 *	will not create a file.  It's to be used with the command:
 *
 *		elf_update(elf, ELF_C_WRIMAGE)
 *
 *	which will build a memory image instead of a file image.
 *	The memory image is allocated via dynamic memory (malloc) and
 *	can be free with a subsequent call to
 *
 *		elf_update(elf, ELF_C_WRITE)
 *
 *	NOTE: that if elf_end(elf) is called it will not free the
 *		memory image if it is still allocated.  It is then
 *		the callers responsiblity to free it via a call
 *		to free().
 *
 *	Here is a potential calling sequence for this interface:
 *
 *	elf1 = elf_begin(0, ELF_C_IMAGE, 0);
 *	...
 *	elf_update(elf1, ELF_C_WRIMAGE);	build memory image
 *	elf2 = elf_begin(0, ELF_C_IMAGE, elf1);
 *	...
 *	image_ptr = elf32_getehdr(elf2);	get pointer to image
 *	elf_end(elf2);
 *	elf_end(elf1);
 *	...
 *	use image
 *	...
 *	free(image_ptr);
 */

Elf *
elf_begin(int fd, Elf_Cmd cmd, Elf *ref)
{
	register Elf	*elf;
	unsigned	work;
	unsigned	flags = 0;

	ELFACCESSDATA(work, _elf_work)
	if (work == EV_NONE)	/* version() not called yet */
	{
		_elf_seterr(ESEQ_VER, 0);
		return (0);
	}
	switch (cmd) {
	default:
		_elf_seterr(EREQ_BEGIN, 0);
		return (0);

	case ELF_C_NULL:
		return (0);

	case ELF_C_IMAGE:
		if (ref) {
			char	*image;
			size_t	imagesz;
			ELFRLOCK(ref);
			if ((image = ref->ed_wrimage) == 0) {
				_elf_seterr(EREQ_NOWRIMAGE, 0);
				ELFUNLOCK(ref);
				return (0);
			}
			imagesz = ref->ed_wrimagesz;
			ELFUNLOCK(ref);
			return (elf_memory(image, imagesz));
		}
		/* FALLTHROUGH */
	case ELF_C_WRITE:
		if ((elf = (Elf *)calloc(1, sizeof (Elf))) == 0) {
			_elf_seterr(EMEM_ELF, errno);
			return (0);
		}
		ELFRWLOCKINIT(&elf->ed_rwlock);
		elf->ed_fd = fd;
		elf->ed_activ = 1;
		elf->ed_myflags |= EDF_WRITE;
		if (cmd == ELF_C_IMAGE)
			elf->ed_myflags |= EDF_WRALLOC;
		return (elf);
	case ELF_C_RDWR:
		flags = EDF_WRITE | EDF_READ;
		break;

	case ELF_C_READ:
		flags = EDF_READ;
		break;
	}

	/*
	 *	A null ref asks for a new file
	 *	Non-null ref bumps the activation count
	 *		or gets next archive member
	 */

	if (ref == 0) {
		if ((elf = _elf_regular(fd, flags)) == 0)
			return (0);
	} else {
		ELFWLOCK(ref);
		if ((ref->ed_myflags & flags) != flags) {
			_elf_seterr(EREQ_RDWR, 0);
			ELFUNLOCK(ref);
			return (0);
		}
		/*
		 * new activation ?
		 */
		if (ref->ed_kind != ELF_K_AR) {
			++ref->ed_activ;
			ELFUNLOCK(ref);
			return (ref);
		}
		if ((elf = _elf_member(fd, ref, flags)) == 0) {
			ELFUNLOCK(ref);
			return (0);
		}
		ELFUNLOCK(ref);
	}

	elf->ed_activ = 1;
	elf = _elf_config(elf);

	return (elf);
}
