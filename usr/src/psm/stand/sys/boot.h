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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _BOOT_H
#define	_BOOT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Platform-independent declarations for the secondary bootloader
 * (in psm/stand/boot).
 */

#ifdef __cplusplus
extern "C" {
#endif


#include <sys/link.h>



/*
 * Common variable declarations.
 */
extern	int boothowto;
extern	int verbosemode;
extern	char *systype;

extern	struct memlist *pfreelistp, *vfreelistp, *pinstalledp;



/*
 * Global variables from readfile.c
 */
extern	int (*readfile(int fd, int print))();

#ifdef _ELF64_SUPPORT
extern Elf32_Boot *elfbootvecELF32_64;	/* Bootstrap vector ELF32 LP64 client */
extern Elf64_Boot *elfbootvecELF64;	/* Bootstrap vector for Elf64 LP64 */
#endif



/*
 * Prototypes from heap_kmem.c
 */
extern void	kmem_init(void);
extern void	*kmem_alloc(size_t, int);
extern void	kmem_free(void *, size_t);



#ifdef __cplusplus
}
#endif

#endif /* _BOOT_H */
