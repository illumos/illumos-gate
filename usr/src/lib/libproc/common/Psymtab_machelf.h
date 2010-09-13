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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PSYMTAB_MACHELF_H
#define	_PSYMTAB_MACHELF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif


extern Elf *fake_elf32(struct ps_prochandle *P, file_info_t *fptr,
    uintptr_t addr, Elf32_Ehdr *ehdr, uint_t phnum, Elf32_Phdr *phdr);
#ifdef _LP64
extern Elf *fake_elf64(struct ps_prochandle *P, file_info_t *fptr,
    uintptr_t addr, Elf64_Ehdr *ehdr, uint_t phnum, Elf64_Phdr *phdr);
#endif


#ifdef	__cplusplus
}
#endif

#endif	/* _PSYMTAB_MACHELF_H */
