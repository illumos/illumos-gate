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
 *
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef	_SMBSRV_ALLOC_H
#define	_SMBSRV_ALLOC_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Memory management macros to aid in developing code that can
 * be compiled for both user and kernel.
 *
 * Set the AREA parameter to a short text string that is a hint
 * about the subsystem calling the function. example: "smbrdr"
 *
 * Do not mix usage of these macros with malloc/free functions.
 * It will not work.
 *
 * All library code shared between user and kernel must use
 * these functions instead of malloc/free/kmem_*.
 *
 * Quick Summary
 * MEM_MALLOC - allocate memory
 * MEM_ZALLOC - allocate and zero memory
 * MEM_STRDUP - string copy
 * MEM_REALLOC - reallocate memory
 * MEM_FREE -  free memory
 */

#include <sys/types.h>

#if !defined(_KERNEL) && !defined(_FAKE_KERNEL)
#include <stdlib.h>
#include <string.h>

#define	MEM_MALLOC(AREA, SIZE) malloc(SIZE)
#define	MEM_ZALLOC(AREA, SIZE) calloc((SIZE), 1)
#define	MEM_STRDUP(AREA, PTR) strdup(PTR)
#define	MEM_REALLOC(AREA, PTR, SIZE) realloc((PTR), (SIZE))
#define	MEM_FREE(AREA, PTR) free(PTR)

#else /* _KERNEL */

void *smb_mem_alloc(size_t);
void *smb_mem_zalloc(size_t);
void smb_mem_free(void *);
char *smb_mem_strdup(const char *);

#define	MEM_MALLOC(AREA, SIZE)	smb_mem_alloc(SIZE)
#define	MEM_ZALLOC(AREA, SIZE)	smb_mem_zalloc(SIZE)
#define	MEM_FREE(AREA, PTR)	smb_mem_free(PTR)

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif	/* _SMBSRV_ALLOC_H */
