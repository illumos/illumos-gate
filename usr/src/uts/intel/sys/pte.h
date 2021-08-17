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

#ifndef _SYS_PTE_H
#define	_SYS_PTE_H

#ifndef _ASM
#include <sys/types.h>
#endif /* _ASM */

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef _ASM

#ifdef	PTE36			/* PTE36 ---------------------------- */

typedef uint64_t	pteval_t;
typedef	pteval_t	*pteptr_t;

#define	PRPTEx		"llx"

typedef struct pte32 {
	uint32_t Present:1;
	uint32_t AccessPermissions:2;
	uint32_t WriteThru:1;
	uint32_t NonCacheable:1;
	uint32_t Referenced:1;
	uint32_t Modified:1;
	uint32_t MustBeZero:1;
	uint32_t GlobalEnable:1;
	uint32_t OSReserved:3;
	uint32_t PhysicalPageNumber:20;
} pte32_t;


typedef struct pte {
	uint32_t Present:1;
	uint32_t AccessPermissions:2;
	uint32_t WriteThru:1;
	uint32_t NonCacheable:1;
	uint32_t Referenced:1;
	uint32_t Modified:1;
	uint32_t MustBeZero:1;
	uint32_t GlobalEnable:1;
	uint32_t OSReserved:3;
	uint32_t PhysicalPageNumberL:20;
	uint32_t PhysicalPageNumberH;
					/*
					 * An easy way to ensure that
					 * reserved bits are zero.
					 */
} pte_t;

struct  pte64 {
	uint32_t	pte64_0_31;
	uint32_t	pte64_32_64;
};

#define	NPTESHIFT	9
#define	NPTEPERPT	512	/* entries in page table */
#define	PTSIZE		(NPTEPERPT * MMU_PAGESIZE)	/* bytes mapped */


#else		/* PTE36 */
				/* PTE32 ---------------------------- */


typedef uint32_t	pteval_t;
typedef	pteval_t	*pteptr_t;

#define	PRPTEx		"x"

typedef struct pte {
	uint_t Present:1;
	uint_t AccessPermissions:2;
	uint_t WriteThru:1;
	uint_t NonCacheable:1;
	uint_t Referenced:1;
	uint_t Modified:1;
	uint_t MustBeZero:1;
	uint_t GlobalEnable:1;
	uint_t OSReserved:3;
	uint_t PhysicalPageNumber:20;
} pte_t;

#define	pte32_t		pte_t

#define	NPTESHIFT	10
#define	NPTEPERPT	1024	/* entries in page table */
#define	PTSIZE		(NPTEPERPT * MMU_PAGESIZE)	/* bytes mapped */

#endif	/* PTE36 */

#define	PTE_VALID	0x01
#define	PTE_LARGEPAGE	0x80
#define	PTE_SRWX	0x02

#endif /* !_ASM */


#ifdef	__cplusplus
}
#endif

#endif /* !_SYS_PTE_H */
