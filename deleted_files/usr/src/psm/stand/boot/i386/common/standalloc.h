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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_STANDALLOC_H
#define	_SYS_STANDALLOC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/saio.h>

#define	NULL		0
#define	roundup(x, y)	((((x)+((y)-1))/(y))*(y))
#define	rounddown(x, y)	(((x)/(y))*(y))

/* backing resources for memory allocation */
caddr_t resalloc(enum RESOURCES type, size_t, caddr_t, int);
void resfree(caddr_t, size_t);
void reset_alloc(void);

/* memory allocation */
void *bkmem_alloc(size_t);
void *bkmem_zalloc(size_t);
void bkmem_free(void *, size_t);
int get_progmemory(caddr_t, size_t, int);
void *vmx_zalloc_identity(size_t);

/*
 * BOPF_X86_ALLOC_IDMAP: identical virtual/physical address
 * BOPF_X86_ALLOC_PHYS:  physical address
 */
caddr_t idmap_mem(uint32_t, size_t, int);
caddr_t phys_alloc_mem(size_t, int);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_STANDALLOC_H */
