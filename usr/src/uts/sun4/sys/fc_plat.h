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

#ifndef	_SYS_FC_PLAT_H
#define	_SYS_FC_PLAT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/inttypes.h>
#include <sys/obpdefs.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Platform specific definitions for the fcode interpreter and driver.
 * Define the cell size for the implementation.
 *
 * These definitions are appropriate for SPARC V9.
 */

/*
 * The cell size is based on the cell size of the underlying "firmware"
 * implementation.  NB: FCode is really a 32-bit language, but we still
 * define our interfaces in terms of the underlying cell size.
 */

typedef unsigned long long fc_cell_t;

/*
 * common typedef for phandles accross the interface.
 */
typedef uint32_t fc_phandle_t;

/*
 * Handy macros for converting from an fc_cell_t to an integral type
 * These are useful because arguments and results are always passed
 * in an array of fc_cell_t's.
 */

#define	fc_ptr2cell(p)		((fc_cell_t)((uintptr_t)((void *)(p))))
#define	fc_int2cell(i)		((fc_cell_t)((int)(i)))
#define	fc_uint2cell(u)		((fc_cell_t)((unsigned int)(u)))
#define	fc_uint32_t2cell(u)	((fc_cell_t)((unsigned int)((uint32_t)(u))))
#define	fc_uint16_t2cell(w)	((fc_cell_t)((unsigned int)((uint16_t)(w))))
#define	fc_uint8_t2cell(b)	((fc_cell_t)((unsigned int)((uint8_t)(b))))
#define	fc_size2cell(u)		((fc_cell_t)((size_t)(u)))
#define	fc_ssize2cell(i)	((fc_cell_t)((ssize_t)(i)))
#define	fc_phandle2cell(ph)	((fc_cell_t)((unsigned int)((phandle_t)(ph))))
#define	fc_dnode2cell(d)	((fc_cell_t)((unsigned int)((pnode_t)(d))))
#define	fc_ull2cell_high(ll)	(0LL)
#define	fc_ull2cell_low(ll)	((fc_cell_t)(ll))
#define	fc_uintptr2cell(i)	((fc_cell_t)((uintptr_t)(i)))
#define	fc_uchar2cell(c)	((fc_cell_t)((unsigned char)(c)))
#define	fc_ushort2cell(w)	((fc_cell_t)((unsigned short)(w)))
#define	fc_ihandle2cell(h)	((fc_cell_t)((fc_ihandle_t)(h)))

#define	fc_cell2ptr(p)		((void *)((fc_cell_t)(p)))
#define	fc_cell2int(i)		((int)((fc_cell_t)(i)))
#define	fc_cell2uint(u)		((unsigned int)((fc_cell_t)(u)))
#define	fc_cell2uint32_t(u)	((uint32_t)((fc_cell_t)(u)))
#define	fc_cell2uint16_t(w)	((uint16_t)((fc_cell_t)(w)))
#define	fc_cell2uint8_t(b)	((uint8_t)((fc_cell_t)(b)))
#define	fc_cell2size(u)		((size_t)((fc_cell_t)(u)))
#define	fc_cell2ssize(i)	((ssize_t)((fc_cell_t)(i)))
#define	fc_cell2phandle(ph)	((phandle_t)((fc_cell_t)(ph)))
#define	fc_cell2dnode(d)	((pnode_t)((fc_cell_t)(d)))
#define	fc_cells2ull(h, l)	((unsigned long long)(fc_cell_t)(l))
#define	fc_cell2uintptr(i)	((uintptr_t)((fc_cell_t)(i)))
#define	fc_cell2uchar(c)	((unsigned char)(fc_cell_t)(c))
#define	fc_cell2ushort(w)	((unsigned short)(fc_cell_t)(w))
#define	fc_cell2ihandle(h)	((fc_ihandle_t)(fc_cell_t)(h))

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_FC_PLAT_H */
