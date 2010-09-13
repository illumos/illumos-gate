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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_SIMULATE_H
#define	_SYS_SIMULATE_H

#ifdef __cplusplus
extern "C" {
#endif

/* SPARC instruction simulator return codes.  */

#define	SIMU_SUCCESS	1	/* simulation worked */
#define	SIMU_ILLEGAL	2	/* tried to simulate an illegal instuction */
#define	SIMU_FAULT	3	/* simulation generated an illegal access */
#define	SIMU_DZERO	4	/* simulation generated divide by zero */
#define	SIMU_UNALIGN	5	/* simulation generated an unaligned access */
#define	SIMU_RETRY	6	/* fixed up instruction, now retry it */


/*
 * Opcode types.
 */
#define	OP_V8_BRANCH	0
#define	OP_V8_CALL	1
#define	OP_V8_ARITH	2	/* includes control xfer (e.g. JMPL) */
#define	OP_V8_LDSTR	3

/*
 * Relevant instruction opcodes.
 */

/* OP_V8_LDSTR  */
#define	IOP_V8_LD	0x00
#define	IOP_V8_LDA	0x10
#define	IOP_V8_LDUBA	0x11
#define	IOP_V8_LDUHA	0x12
#define	IOP_V8_LDDA	0x13
#define	IOP_V8_STA	0x14
#define	IOP_V8_STBA	0x15
#define	IOP_V8_STHA	0x16
#define	IOP_V8_STDA	0x17
#define	IOP_V8_LDSBA	0x19
#define	IOP_V8_LDSHA	0x1a
#define	IOP_V8_LDSTUBA	0x1d
#define	IOP_V8_SWAPA	0x1f
#define	IOP_V8_LDFSR	0x21
#define	IOP_V8_LDQF	0x22
#define	IOP_V8_STFSR	0x25
#define	IOP_V8_STQF	0x26
#define	IOP_V8_LDQFA	0x32
#define	IOP_V8_LDDFA	0x33
#define	IOP_V8_STQFA	0x36
#define	IOP_V8_STDFA	0x37

/* OP_V8_ARITH */
#define	IOP_V8_ADD	0x00
#define	IOP_V8_AND	0x01
#define	IOP_V8_OR	0x02
#define	IOP_V8_XOR	0x03
#define	IOP_V8_SUB	0x04
#define	IOP_V8_ANDN	0x05
#define	IOP_V8_ORN	0x06
#define	IOP_V8_XNOR	0x07
#define	IOP_V8_ADDC	0x08
#define	IOP_V8_UMUL	0x0a
#define	IOP_V8_SMUL	0x0b
#define	IOP_V8_SUBC	0x0c
#define	IOP_V8_UDIV	0x0e
#define	IOP_V8_SDIV	0x0f
#define	IOP_V8_ADDcc	0x10
#define	IOP_V8_ANDcc	0x11
#define	IOP_V8_ORcc	0x12
#define	IOP_V8_XORcc	0x13
#define	IOP_V8_SUBcc	0x14
#define	IOP_V8_ANDNcc	0x15
#define	IOP_V8_ORNcc	0x16
#define	IOP_V8_XNORcc	0x17
#define	IOP_V8_ADDCcc	0x18
#define	IOP_V8_UMULcc	0x1a
#define	IOP_V8_SMULcc	0x1b
#define	IOP_V8_SUBCcc	0x1c
#define	IOP_V8_UDIVcc	0x1e
#define	IOP_V8_SDIVcc	0x1f
#define	IOP_V8_TADDcc	0x20
#define	IOP_V8_TSUBcc	0x21
#define	IOP_V8_TADDccTV	0x22
#define	IOP_V8_TSUBccTV	0x23
#define	IOP_V8_MULScc	0x24
#define	IOP_V8_SLL	0x25
#define	IOP_V8_SRL	0x26
#define	IOP_V8_SRA	0x27
#define	IOP_V8_RDASR	0x28
#define	IOP_V8_POPC	0x2e
#define	IOP_V8_WRASR	0x30
#define	IOP_V8_FCMP	0x35
#define	IOP_V8_JMPL	0x38
#define	IOP_V8_RETT	0x39
#define	IOP_V8_TCC	0x3a
#define	IOP_V8_FLUSH	0x3b
#define	IOP_V8_SAVE	0x3c
#define	IOP_V8_RESTORE	0x3d

/*
 * Check for a load/store to alternate space. All other ld/st
 * instructions should have bits 12-5 clear, if the i-bit is 0.
 */
#define	IS_LDST_ALT(x) \
	(((x) == IOP_V8_LDA || (x) == IOP_V8_LDDA || \
	    (x) == IOP_V8_LDSBA || (x) == IOP_V8_LDSHA || \
	    (x) == IOP_V8_LDSTUBA || (x) == IOP_V8_LDUBA || \
	    (x) == IOP_V8_LDUHA || (x) == IOP_V8_STA || \
	    (x) == IOP_V8_STBA || (x) == IOP_V8_STDA || \
	    (x) == IOP_V8_STHA || (x) == IOP_V8_SWAPA) ? 1 : 0)


#ifndef _ASM

#include <vm/seg_enum.h>

extern int32_t fetch_user_instr(caddr_t);
extern int simulate_unimp(struct regs *, caddr_t *);
extern int simulate_lddstd(struct regs *, caddr_t *);
extern int simulate_rdtick(struct regs *);
extern int do_unaligned(struct regs *, caddr_t *);
extern int calc_memaddr(struct regs *, caddr_t *);
extern int is_atomic(struct regs *);
extern int instr_size(struct regs *, caddr_t *, enum seg_rw);
extern int getreg(struct regs *, uint_t, uint64_t *, caddr_t *);
extern int putreg(uint64_t *, struct regs *, uint_t, caddr_t *);
extern int extended_asi_size(int asi);

#endif /* _ASM */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_SIMULATE_H */
