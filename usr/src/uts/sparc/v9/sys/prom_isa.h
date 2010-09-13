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

#ifndef	_SYS_PROM_ISA_H
#define	_SYS_PROM_ISA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/feature_tests.h>
#include <sys/obpdefs.h>

/*
 * This file contains external ISA-specific promif interface definitions.
 * There may be none.  This file is included by reference in <sys/promif.h>
 *
 * This version of the file contains definitions for a 64-bit client program
 * calling the 64-bit cell-sized SPARC v9 firmware client interface handler.
 *
 */

#ifdef	__cplusplus
extern "C" {
#endif

#if !defined(_LONGLONG_TYPE)
#error "This header won't work without long long support"
#endif

typedef	unsigned long long cell_t;

#define	p1275_ptr2cell(p)	((cell_t)((uintptr_t)((void *)(p))))
#define	p1275_int2cell(i)	((cell_t)((int)(i)))
#define	p1275_uint2cell(u)	((cell_t)((unsigned int)(u)))
#define	p1275_size2cell(u)	((cell_t)((size_t)(u)))
#define	p1275_phandle2cell(ph)	((cell_t)((unsigned int)((phandle_t)(ph))))
#define	p1275_dnode2cell(d)	((cell_t)((unsigned int)((pnode_t)(d))))
#define	p1275_ihandle2cell(ih)	((cell_t)((unsigned int)((ihandle_t)(ih))))
#define	p1275_ull2cell_high(ll)	(0LL)
#define	p1275_ull2cell_low(ll)	((cell_t)(ll))
#define	p1275_uintptr2cell(i)	((cell_t)((uintptr_t)(i)))

#define	p1275_cell2ptr(p)	((void *)((cell_t)(p)))
#define	p1275_cell2int(i)	((int)((cell_t)(i)))
#define	p1275_cell2uint(u)	((unsigned int)((cell_t)(u)))
#define	p1275_cell2size(u)	((size_t)((cell_t)(u)))
#define	p1275_cell2phandle(ph)	((phandle_t)((cell_t)(ph)))
#define	p1275_cell2dnode(d)	((pnode_t)((cell_t)(d)))
#define	p1275_cell2ihandle(ih)	((ihandle_t)((cell_t)(ih)))
#define	p1275_cells2ull(h, l)	((unsigned long long)(cell_t)(l))
#define	p1275_cell2uintptr(i)	((uintptr_t)((cell_t)(i)))

/*
 * Define default cif handlers:  This port uses SPARC V8 32 bit semantics
 * on the calling side and the prom side.
 */
#define	p1275_cif_init			p1275_sparc_cif_init
#define	p1275_cif_handler		p1275_sparc_cif_handler

extern void	*p1275_sparc_cif_init(void *);
extern int	p1275_cif_handler(void *);

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_PROM_ISA_H */
