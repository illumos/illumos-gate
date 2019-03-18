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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2019 Joyent, Inc.
 */

#ifndef _ELF_ELF_IMPL_H
#define	_ELF_ELF_IMPL_H

#ifdef	__cplusplus
extern "C" {
#endif

#if	!defined(_LP64) || defined(_ELF32_COMPAT)

/*
 * Definitions for ELF32, native 32-bit or 32-bit compatibility mode.
 */
#define	ELFCLASS	ELFCLASS32
typedef	unsigned int	aux_val_t;
typedef	auxv32_t	aux_entry_t;

#define	USR_LIB_RTLD	"/usr/lib/ld.so.1"

#else	/* !_LP64 || _ELF32_COMPAT */

/*
 * Definitions for native 64-bit ELF
 */
#define	ELFCLASS	ELFCLASS64
typedef	unsigned long	aux_val_t;
typedef	auxv_t		aux_entry_t;

/* put defines for 64-bit architectures here */
#if defined(__sparcv9)
#define	USR_LIB_RTLD	"/usr/lib/sparcv9/ld.so.1"
#endif

#if defined(__amd64)
#define	USR_LIB_RTLD	"/usr/lib/amd64/ld.so.1"
#endif

#endif	/* !_LP64 || _ELF32_COMPAT */

/*
 * Start of an ELF Note.
 */
typedef struct {
	Nhdr	nhdr;
	char	name[8];
} Note;

typedef struct {
	vnode_t		*ecc_vp;
	proc_t		*ecc_p;
	cred_t		*ecc_credp;
	rlim64_t	ecc_rlimit;
	core_content_t	ecc_content;
	u_offset_t	ecc_doffset;
	void		*ecc_buf;
	size_t		ecc_bufsz;
} elf_core_ctx_t;

#ifdef	_ELF32_COMPAT
/*
 * These are defined only for the 32-bit compatibility
 * compilation mode of the 64-bit kernel.
 */
#define	elfexec	elf32exec
#define	elfnote	elf32note
#define	elfcore	elf32core
#define	elfreadhdr		elf32readhdr
#define	mapexec_brand		mapexec32_brand
#define	setup_note_header	setup_note_header32
#define	write_elfnotes		write_elfnotes32
#define	setup_old_note_header	setup_old_note_header32
#define	write_old_elfnotes	write_old_elfnotes32

#if defined(__sparc)
#define	gwindows_t	gwindows32_t
#define	rwindow		rwindow32
#endif

#define	psinfo_t	psinfo32_t
#define	pstatus_t	pstatus32_t
#define	lwpsinfo_t	lwpsinfo32_t
#define	lwpstatus_t	lwpstatus32_t

#define	prgetpsinfo	prgetpsinfo32
#define	prgetstatus	prgetstatus32
#define	prgetlwpsinfo	prgetlwpsinfo32
#define	prgetlwpstatus	prgetlwpstatus32
#define	prgetwindows	prgetwindows32

#define	prpsinfo_t	prpsinfo32_t
#define	prstatus_t	prstatus32_t
#if defined(prfpregset_t)
#undef prfpregset_t
#endif
#define	prfpregset_t	prfpregset32_t

#define	oprgetstatus	oprgetstatus32
#define	oprgetpsinfo	oprgetpsinfo32
#define	prgetprfpregs	prgetprfpregs32

#endif	/*	_ELF32_COMPAT	*/

extern int elfnote(vnode_t *, offset_t *, int, int, void *, rlim64_t, cred_t *);
extern void setup_old_note_header(Phdr *, proc_t *);
extern void setup_note_header(Phdr *, proc_t *);

extern int write_old_elfnotes(proc_t *, int, vnode_t *, offset_t,
    rlim64_t, cred_t *);

extern int write_elfnotes(proc_t *, int, vnode_t *, offset_t,
    rlim64_t, cred_t *, core_content_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _ELF_ELF_IMPL_H */
