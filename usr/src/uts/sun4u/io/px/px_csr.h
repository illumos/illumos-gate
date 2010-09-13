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

#ifndef	_SYS_PX_CSR_H
#define	_SYS_PX_CSR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* To read and write whole register */
#define	CSR_XR(base, off) \
	(*(volatile uint64_t *)((base) + ((off))))

#define	CSRA_XR(base, off, index) \
	(*(volatile uint64_t *)((base) + ((off) + ((index) * 8))))

#define	CSR_XS(base, off, val) \
	((*(volatile uint64_t *)((base) + ((off)))) = (val))

#define	CSRA_XS(base, off, index, val) \
	((*(volatile uint64_t *)((base) + ((off) + ((index) * 8)))) = (val))

/* To read, set and clear specific fields within a register */
#define	CSR_FR(base, off, bit) \
	(((*(volatile uint64_t *) ((base) + ((off)))) >> \
	(off ## _ ## bit)) & (off ## _ ## bit ## _MASK))

#define	CSRA_FR(base, off, index, bit) \
	(((*(volatile uint64_t *) ((base) + ((off) + ((index) * 8)))) >> \
	(off ## _ ## bit)) & (off ## _ ## bit ## _MASK))

#define	CSR_FS(base, off, bit, val) \
	((*(volatile uint64_t *) ((base) + ((off)))) = \
	(((*(volatile uint64_t *) ((base) + ((off)))) & \
	~(((uint64_t)(off ## _ ## bit ## _MASK)) << \
	(off ## _ ## bit))) | (((uint64_t)(val)) << (off ## _ ## bit))))

#define	CSRA_FS(base, off, index, bit, val) \
	((*(volatile uint64_t *) ((base) + ((off) + ((index) * 8)))) = \
	(((*(volatile uint64_t *) ((base) + ((off) + ((index) * 8)))) & \
	~(((uint64_t)(off ## _ ## bit ## _MASK)) << \
	(off ## _ ## bit))) | (((uint64_t)(val)) << (off ## _ ## bit))))

#define	CSR_FC(base, off, bit) \
	((*(volatile uint64_t *) ((base) + ((off)))) = \
	((*(volatile uint64_t *)((base) + ((off)))) & \
	~(((uint64_t)(off ## _ ## bit ## _MASK)) << (off ## _ ## bit))))

#define	CSRA_FC(base, off, index, bit) \
	((*(volatile uint64_t *) ((base) + ((off) + ((index) * 8)))) = \
	((*(volatile uint64_t *)((base) + ((off) + ((index) * 8)))) & \
	~(((uint64_t)(off ## _ ## bit ## _MASK)) << (off ## _ ## bit))))

/* To read, set and clear specific bit within a register */
#define	CSR_BR(base, off, bit) \
	(((*(volatile uint64_t *)((base) + ((off)))) >> \
	(off ## _ ## bit)) & 0x1)

#define	CSRA_BR(base, off, index, bit) \
	(((*(volatile uint64_t *)((base) + ((off) + ((index) * 8)))) >> \
	(off ## _ ## bit)) & 0x1)

#define	CSR_BS(base, off, bit) \
	((*(volatile uint64_t *)((base) + ((off)))) = \
	((*(volatile uint64_t *)((base) + ((off)))) | \
	(1ull<<(off ## _ ## bit))))

#define	CSRA_BS(base, off, index, bit) \
	((*(volatile uint64_t *)((base) + ((off) + ((index) * 8)))) = \
	((*(volatile uint64_t *)((base) + ((off) + ((index) * 8)))) | \
	(1ull<<(off ## _ ## bit))))

#define	CSR_BC(base, off, bit) \
	((*(volatile uint64_t *)((base) + ((off)))) = \
	((*(volatile uint64_t *)((base) + ((off)))) & \
	~(1ull<<(off ## _ ## bit))))

#define	CSRA_BC(base, off, index, bit) \
	((*(volatile uint64_t *)((base) + ((off) + ((index) * 8)))) = \
	((*(volatile uint64_t *)((base) + ((off) + ((index) * 8)))) & \
	~(1ull<<(off ## _ ## bit))))

#define	BIT_TST(reg, bitno)	(reg & (1ull << bitno))
#define	BITMASK(bitno)		(1ull << bitno)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PX_CSR_H */
