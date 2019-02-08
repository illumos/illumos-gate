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
/*
 * Copyright 2019 Peter Tribble.
 */

#ifndef _SYS_MACHINTREG_H
#define	_SYS_MACHINTREG_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Interrupt Receive Data Registers
 *	ASI_SDB_INTR_R or ASI_INTR_RECEIVE; ASI 0x7F; VA 0x40, 0x50, 0x60
 */
#define	IRDR_0		0x40
#define	IRDR_1		0x50
#define	IRDR_2		0x60

#define	UIII_IRDR_0	0x40
#define	UIII_IRDR_1	0x48
#define	UIII_IRDR_2	0x50
#define	UIII_IRDR_3	0x58
#define	UIII_IRDR_4	0x60
#define	UIII_IRDR_5	0x68
#define	UIII_IRDR_6	0x80
#define	UIII_IRDR_7	0x88

/*
 * Interrupt Receive Status Register
 *	ASI_INTR_RECEIVE_STATUS; ASI 0x49; VA 0x0
 *
 *	|---------------------------------------------------|
 *	|    RESERVED (Read as 0)        | BUSY |   PORTID  |
 *	|--------------------------------|------|-----------|
 *	 63                             6    5   4         0
 *
 */
#define	IRSR_BUSY	0x20	/* set when there's a vector received */
#define	IRSR_PID_MASK	0x1F	/* PORTID bit mask <4:0> */

/*
 * Interrupt Dispatch Data Register
 *	ASI_SDB_INTR_W or ASI_INTR_DISPATCH; ASI 0x77; VA 0x40, 0x50, 0x60
 */
#define	IDDR_0		0x40
#define	IDDR_1		0x50
#define	IDDR_2		0x60

#define	UIII_IDDR_0	0x40
#define	UIII_IDDR_1	0x48
#define	UIII_IDDR_2	0x50
#define	UIII_IDDR_3	0x58
#define	UIII_IDDR_4	0x60
#define	UIII_IDDR_5	0x68
#define	UIII_IDDR_6	0x80
#define	UIII_IDDR_7	0x88

#if defined(JALAPENO) || defined(SERRANO)
/*
 * Interrupt Dispatch Command Register
 *	ASI_INTR_DISPATCH or ASI_SDB_INTR_W; ASI 0x77; VA = PORTID<<14|0x70
 *
 *	|------------------------------------------------|
 *	|    0    | PORTID  & BUSY/NACK   |     0x70     |
 *	|---------|-----------------------|--------------|
 *	 63     19 18                   14 13            0
 */
#define	IDCR_OFFSET	0x70		/* IDCR VA<13:0> */
#define	IDCR_PID_SHIFT	14
#define	IDCR_BN_SHIFT	14		/* JBUS only */
#define	IDCR_BN_MASK	0x3		/* JBUS only */
#else /* (JALAPENO || SERRANO) */
/*
 * Interrupt Dispatch Command Register
 *	ASI_INTR_DISPATCH or ASI_SDB_INTR_W; ASI 0x77; VA = PORTID<<14|0x70
 *
 *	|------------------------------------------------|
 *	|    0    | BUSY/NACK |  PORTID   |     0x70     |
 *	|---------|-----------|-----------|--------------|
 *	 63     29 28       24 23       14 13            0
 */
#define	IDCR_OFFSET	0x70		/* IDCR VA<13:0> */
#define	IDCR_PID_SHIFT	14
#define	IDCR_BN_SHIFT	24		/* safari only */
#endif /* (JALAPENO || SERRANO) */

/*
 * Interrupt Dispatch Status Register
 *	ASI_INTR_DISPATCH_STATUS; ASI 0x48; VA 0x0
 *
 *	|---------------------------------------------------|
 *	|     RESERVED (Read as 0)          | NACK  | BUSY  |
 *	|-----------------------------------|-------|-------|
 *	 63                               2    1        0   |
 */
#define	IDSR_NACK	0x2		/* set if interrupt dispatch failed */
#define	IDSR_BUSY	0x1		/* set when there's a dispatch */

/*
 * Safari systems define IDSR as 32 busy/nack pairs
 */
#if defined(JALAPENO) || defined(SERRANO)
#define	IDSR_BN_SETS		4
#define	CPUID_TO_BN_PAIR(x)	((x) & (IDSR_BN_SETS-1))
#else /* (JALAPENO || SERRANO) */
#define	IDSR_BN_SETS		32
#endif /* (JALAPENO || SERRANO) */
#define	IDSR_NACK_BIT(i)	((uint64_t)IDSR_NACK << (2 * (i)))
#define	IDSR_BUSY_BIT(i)	((uint64_t)IDSR_BUSY << (2 * (i)))
#define	IDSR_NACK_TO_BUSY(n)	((n) >> 1)
#define	IDSR_BUSY_TO_NACK(n)	((n) << 1)
#define	IDSR_NACK_IDX(bit)	(((bit) - 1) / 2)
#define	IDSR_BUSY_IDX(bit)	((bit) / 2)

/*
 * Interrupt Number Register
 *	Every interrupt source has a register associated with it
 *
 *	|---------------------------------------------------|
 *	|INT_EN |  PORTID  |RESERVED (Read as 0)| INT_NUMBER|
 *	|       |          |                    | IGN | INO |
 *	|-------|----------|--------------------|-----|-----|
 *	|  31    30      26 25                11 10  6 5   0
 */
#define	INR_EN_SHIFT	31
#define	INR_PID_SHIFT	26
#define	INR_PID_MASK	(IRSR_PID_MASK << (INR_PID_SHIFT))
/*
 * IGN_SIZE can be defined in a platform's makefile. If it is not defined,
 * use a default of 5.
 */
#ifndef IGN_SIZE
#define	IGN_SIZE	5		/* Interrupt Group Number bit size */
#endif
#define	UPAID_TO_IGN(upaid) (upaid)

#define	IR_CPU_CLEAR	0x4		/* clear pending register for cpu */
#define	IR_MASK_OFFSET	0x4
#define	IR_SET_ITR	0x10
#define	IR_SOFT_INT(n)	(0x000010000 << (n))
#define	IR_SOFT_INT4	IR_SOFT_INT(4)	/* r/w - software level 4 interrupt */
#define	IR_CPU_SOFTINT	0x8		/* set soft interrupt for cpu */
#define	IR_CLEAR_OFFSET	0x8


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MACHINTREG_H */
