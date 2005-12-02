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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* Read/write user memory procedures for Sparc9 FPU simulator. */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/fpu/fpu_simulator.h>
#include <sys/fpu/globals.h>
#include <sys/systm.h>
#include <vm/seg.h>
#include <sys/privregs.h>
#include <sys/stack.h>
#include <sys/debug.h>
#include <sys/model.h>

/* read the user instruction */
enum ftt_type
_fp_read_inst(
	const uint32_t *address,	/* FPU instruction address. */
	uint32_t *pvalue,		/* Place for instruction value. */
	fp_simd_type *pfpsd)		/* Pointer to fpu simulator data. */
{
	if (((uintptr_t)address & 0x3) != 0)
		return (ftt_alignment);	/* Must be word-aligned. */

	if (get_udatamodel() == DATAMODEL_ILP32) {
		/*
		 * If this is a 32-bit program, chop the address accordingly.
		 * The intermediate uintptr_t casts prevent warnings under a
		 * certain compiler, and the temporary 32 bit storage is
		 * intended to force proper code generation and break up what
		 * would otherwise be a quadruple cast.
		 */
		caddr32_t address32 = (caddr32_t)(uintptr_t)address;
		address = (uint32_t *)(uintptr_t)address32;
	}

	if (fuword32(address, pvalue) == -1) {
		pfpsd->fp_trapaddr = (caddr_t)address;
		pfpsd->fp_traprw = S_READ;
		return (ftt_fault);
	}
	return (ftt_none);
}

enum ftt_type
_fp_read_extword(
	const uint64_t *address,	/* FPU data address. */
	uint64_t *pvalue,		/* Place for extended word value. */
	fp_simd_type *pfpsd)		/* Pointer to fpu simulator data. */
{
	if (((uintptr_t)address & 0x7) != 0)
		return (ftt_alignment);	/* Must be extword-aligned. */

	if (get_udatamodel() == DATAMODEL_ILP32) {
		/*
		 * If this is a 32-bit program, chop the address accordingly.
		 * The intermediate uintptr_t casts prevent warnings under a
		 * certain compiler, and the temporary 32 bit storage is
		 * intended to force proper code generation and break up what
		 * would otherwise be a quadruple cast.
		 */
		caddr32_t address32 = (caddr32_t)(uintptr_t)address;
		address = (uint64_t *)(uintptr_t)address32;
	}

	if (fuword64(address, pvalue) == -1) {
		pfpsd->fp_trapaddr = (caddr_t)address;
		pfpsd->fp_traprw = S_READ;
		return (ftt_fault);
	}
	return (ftt_none);
}

enum ftt_type
_fp_read_word(
	const uint32_t *address,	/* FPU data address. */
	uint32_t *pvalue,		/* Place for word value. */
	fp_simd_type *pfpsd)		/* Pointer to fpu simulator data. */
{
	if (((uintptr_t)address & 0x3) != 0)
		return (ftt_alignment);	/* Must be word-aligned. */

	if (get_udatamodel() == DATAMODEL_ILP32) {
		/*
		 * If this is a 32-bit program, chop the address accordingly.
		 * The intermediate uintptr_t casts prevent warnings under a
		 * certain compiler, and the temporary 32 bit storage is
		 * intended to force proper code generation and break up what
		 * would otherwise be a quadruple cast.
		 */
		caddr32_t address32 = (caddr32_t)(uintptr_t)address;
		address = (uint32_t *)(uintptr_t)address32;
	}

	if (fuword32(address, pvalue) == -1) {
		pfpsd->fp_trapaddr = (caddr_t)address;
		pfpsd->fp_traprw = S_READ;
		return (ftt_fault);
	}
	return (ftt_none);
}

enum ftt_type
_fp_write_extword(
	uint64_t *address,		/* FPU data address. */
	uint64_t value,			/* Extended word value to write. */
	fp_simd_type *pfpsd)		/* Pointer to fpu simulator data. */
{
	if (((uintptr_t)address & 0x7) != 0)
		return (ftt_alignment);	/* Must be extword-aligned. */

	if (get_udatamodel() == DATAMODEL_ILP32) {
		/*
		 * If this is a 32-bit program, chop the address accordingly.
		 * The intermediate uintptr_t casts prevent warnings under a
		 * certain compiler, and the temporary 32 bit storage is
		 * intended to force proper code generation and break up what
		 * would otherwise be a quadruple cast.
		 */
		caddr32_t address32 = (caddr32_t)(uintptr_t)address;
		address = (uint64_t *)(uintptr_t)address32;
	}

	if (suword64(address, value) == -1) {
		pfpsd->fp_trapaddr = (caddr_t)address;
		pfpsd->fp_traprw = S_WRITE;
		return (ftt_fault);
	}
	return (ftt_none);
}

enum ftt_type
_fp_write_word(
	uint32_t *address,		/* FPU data address. */
	uint32_t value,			/* Word value to write. */
	fp_simd_type *pfpsd)		/* Pointer to fpu simulator data. */
{
	if (((uintptr_t)address & 0x3) != 0)
		return (ftt_alignment);	/* Must be word-aligned. */

	if (get_udatamodel() == DATAMODEL_ILP32) {
		/*
		 * If this is a 32-bit program, chop the address accordingly.
		 * The intermediate uintptr_t casts prevent warnings under a
		 * certain compiler, and the temporary 32 bit storage is
		 * intended to force proper code generation and break up what
		 * would otherwise be a quadruple cast.
		 */
		caddr32_t address32 = (caddr32_t)(uintptr_t)address;
		address = (uint32_t *)(uintptr_t)address32;
	}

	if (suword32(address, value) == -1) {
		pfpsd->fp_trapaddr = (caddr_t)address;
		pfpsd->fp_traprw = S_WRITE;
		return (ftt_fault);
	}
	return (ftt_none);
}

/*
 * Reads integer unit's register n.
 */
enum ftt_type
read_iureg(
	fp_simd_type	*pfpsd,		/* Pointer to fpu simulator data */
	uint_t		n,		/* IU register n */
	struct regs	*pregs,		/* Pointer to PCB image of registers. */
	void		*prw,		/* Pointer to locals and ins. */
	uint64_t	*pvalue)	/* Place for extended word value. */
{
	enum ftt_type ftt;

	if (n == 0) {
		*pvalue = 0;
		return (ftt_none);	/* Read global register 0. */
	} else if (n < 16) {
		long long *preg;

		preg = &pregs->r_ps;		/* globals and outs */
		*pvalue = preg[n];
		return (ftt_none);
	} else if (USERMODE(pregs->r_tstate)) { /* locals and ins */
		if (lwp_getdatamodel(curthread->t_lwp) == DATAMODEL_ILP32) {
			uint32_t res, *addr, *rw;
			caddr32_t rw32;

			/*
			 * If this is a 32-bit program, chop the address
			 * accordingly.  The intermediate uintptr_t casts
			 * prevent warnings under a certain compiler, and the
			 * temporary 32 bit storage is intended to force proper
			 * code generation and break up what would otherwise be
			 * a quadruple cast.
			 */
			rw32 = (caddr32_t)(uintptr_t)prw;
			rw = (uint32_t *)(uintptr_t)rw32;

			addr = (uint32_t *)&rw[n - 16];
			ftt = _fp_read_word(addr, &res, pfpsd);
			*pvalue = (uint64_t)res;
		} else {
			uint64_t res, *addr, *rw = (uint64_t *)
					((uintptr_t)prw + STACK_BIAS);

			addr = (uint64_t *)&rw[n - 16];
			ftt = _fp_read_extword(addr, &res, pfpsd);
			*pvalue = res;
		}
		return (ftt);
	} else {
		ulong_t *addr, *rw = (ulong_t *)((uintptr_t)prw + STACK_BIAS);
		ulong_t res;

		addr = (ulong_t *)&rw[n - 16];
		res = *addr;
		*pvalue = res;

		return (ftt_none);
	}
}

/*
 * Writes integer unit's register n.
 */
enum ftt_type
write_iureg(
	fp_simd_type	*pfpsd,		/* Pointer to fpu simulator data. */
	uint_t		n,		/* IU register n. */
	struct regs	*pregs,		/* Pointer to PCB image of registers. */
	void		*prw,		/* Pointer to locals and ins. */
	uint64_t	*pvalue)	/* Extended word value to write. */
{
	long long *preg;
	enum ftt_type ftt;

	if (n == 0) {
		return (ftt_none);	/* Read global register 0. */
	} else if (n < 16) {
		preg = &pregs->r_ps;		/* globals and outs */
		preg[n] = *pvalue;
		return (ftt_none);
	} else if (USERMODE(pregs->r_tstate)) { /* locals and ins */
		if (lwp_getdatamodel(curthread->t_lwp) == DATAMODEL_ILP32) {
			uint32_t res, *addr, *rw;
			caddr32_t rw32;

			/*
			 * If this is a 32-bit program, chop the address
			 * accordingly.  The intermediate uintptr_t casts
			 * prevent warnings under a certain compiler, and the
			 * temporary 32 bit storage is intended to force proper
			 * code generation and break up what would otherwise be
			 * a quadruple cast.
			 */
			rw32 = (caddr32_t)(uintptr_t)prw;
			rw = (uint32_t *)(uintptr_t)rw32;

			addr = &rw[n - 16];
			res = (uint_t)*pvalue;
			ftt = _fp_write_word(addr, res, pfpsd);
		} else {
			uint64_t *addr, *rw = (uint64_t *)
				((uintptr_t)prw + STACK_BIAS);
			uint64_t res;

			addr = &rw[n - 16];
			res = *pvalue;
			ftt = _fp_write_extword(addr, res, pfpsd);
		}
		return (ftt);
	} else {
		ulong_t *addr, *rw = (ulong_t *)((uintptr_t)prw + STACK_BIAS);
		ulong_t res = *pvalue;

		addr = &rw[n - 16];
		*addr = res;

		return (ftt_none);
	}
}
