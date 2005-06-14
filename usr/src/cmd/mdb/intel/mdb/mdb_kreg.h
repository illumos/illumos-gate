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

#ifndef	_MDB_KREG_H
#define	_MDB_KREG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _ASM
#include <sys/types.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef __amd64
#define	KREG_NGREG	31
#ifndef _ASM
typedef uint64_t kreg_t;
#endif	/* !_ASM */
#else	/* __amd64 */
#define	KREG_NGREG	21
#ifndef	_ASM
typedef uint32_t kreg_t;
#endif	/* !_ASM */
#endif	/* __amd64 */

#ifdef __amd64

#define	KREG_SAVFP	0
#define	KREG_SAVPC	1
#define	KREG_RDI	2
#define	KREG_RSI	3
#define	KREG_RDX	4
#define	KREG_RCX	5
#define	KREG_R8		6
#define	KREG_R9		7
#define	KREG_RAX	8
#define	KREG_RBX	9
#define	KREG_RBP	10
#define	KREG_R10	11
#define	KREG_R11	12
#define	KREG_R12	13
#define	KREG_R13	14
#define	KREG_R14	15
#define	KREG_R15	16
#define	KREG_FSBASE	17
#define	KREG_GSBASE	18
#define	KREG_KGSBASE	19
#define	KREG_DS		20
#define	KREG_ES		21
#define	KREG_FS		22
#define	KREG_GS		23
#define	KREG_TRAPNO	24
#define	KREG_ERR	25
#define	KREG_RIP	26
#define	KREG_CS		27
#define	KREG_RFLAGS	28
#define	KREG_RSP	29
#define	KREG_SS		30

#define	KREG_PC		KREG_RIP
#define	KREG_SP		KREG_RSP
#define	KREG_FP		KREG_RBP

#else	/* __amd64 */

/*
 * The order of these registers corresponds to a slightly altered struct regs.
 * %ss appears first, and is followed by the remainder of the struct regs.  This
 * change is necessary to support kmdb state saving.
 */

#define	KREG_SAVFP	0
#define	KREG_SAVPC	1
#define	KREG_SS		2
#define	KREG_GS		3
#define	KREG_FS		4
#define	KREG_ES		5
#define	KREG_DS		6
#define	KREG_EDI	7
#define	KREG_ESI	8
#define	KREG_EBP	9
#define	KREG_ESP	10
#define	KREG_EBX	11
#define	KREG_EDX	12
#define	KREG_ECX	13
#define	KREG_EAX	14
#define	KREG_TRAPNO	15
#define	KREG_ERR	16
#define	KREG_EIP	17
#define	KREG_CS		18
#define	KREG_EFLAGS	19
#define	KREG_UESP	20

#define	KREG_PC		KREG_EIP
#define	KREG_SP		KREG_ESP
#define	KREG_FP		KREG_EBP

#endif	/* __amd64 */

#define	KREG_EFLAGS_ID_MASK	0x00200000
#define	KREG_EFLAGS_ID_SHIFT	21

#define	KREG_EFLAGS_VIP_MASK	0x00100000
#define	KREG_EFLAGS_VIP_SHIFT	20

#define	KREG_EFLAGS_VIF_MASK	0x00080000
#define	KREG_EFLAGS_VIF_SHIFT	19

#define	KREG_EFLAGS_AC_MASK	0x00040000
#define	KREG_EFLAGS_AC_SHIFT	18

#define	KREG_EFLAGS_VM_MASK	0x00020000
#define	KREG_EFLAGS_VM_SHIFT	17

#define	KREG_EFLAGS_RF_MASK	0x00010000
#define	KREG_EFLAGS_RF_SHIFT	16

#define	KREG_EFLAGS_NT_MASK	0x00004000
#define	KREG_EFLAGS_NT_SHIFT	14

#define	KREG_EFLAGS_IOPL_MASK	0x00003000
#define	KREG_EFLAGS_IOPL_SHIFT	12

#define	KREG_EFLAGS_OF_MASK	0x00000800
#define	KREG_EFLAGS_OF_SHIFT	11

#define	KREG_EFLAGS_DF_MASK	0x00000400
#define	KREG_EFLAGS_DF_SHIFT	10

#define	KREG_EFLAGS_IF_MASK	0x00000200
#define	KREG_EFLAGS_IF_SHIFT	9

#define	KREG_EFLAGS_TF_MASK	0x00000100
#define	KREG_EFLAGS_TF_SHIFT	8

#define	KREG_EFLAGS_SF_MASK	0x00000080
#define	KREG_EFLAGS_SF_SHIFT	7

#define	KREG_EFLAGS_ZF_MASK	0x00000040
#define	KREG_EFLAGS_ZF_SHIFT	6

#define	KREG_EFLAGS_AF_MASK	0x00000010
#define	KREG_EFLAGS_AF_SHIFT	4

#define	KREG_EFLAGS_PF_MASK	0x00000004
#define	KREG_EFLAGS_PF_SHIFT	2

#define	KREG_EFLAGS_CF_MASK	0x00000001
#define	KREG_EFLAGS_CF_SHIFT	0

#define	KREG_MAXWPIDX		3

/* %dr7 */
#define	KREG_DRCTL_WP_BASESHIFT	16
#define	KREG_DRCTL_WP_INCRSHIFT	4
#define	KREG_DRCTL_WP_LENSHIFT	2
#define	KREG_DRCTL_WP_LENRWMASK	0xf

#define	KREG_DRCTL_WP_EXEC	0
#define	KREG_DRCTL_WP_WONLY	1
#define	KREG_DRCTL_WP_IORW	2
#define	KREG_DRCTL_WP_RW	3

#define	KREG_DRCTL_WP_SHIFT(n) \
	(KREG_DRCTL_WP_BASESHIFT + KREG_DRCTL_WP_INCRSHIFT * (n))
#define	KREG_DRCTL_WP_MASK(n) \
	(KREG_DRCTL_WP_LENRWMASK << KREG_DRCTL_WP_SHIFT(n))
#define	KREG_DRCTL_WP_LENRW(n, len, rw)	\
	((((len) << KREG_DRCTL_WP_LENSHIFT) | (rw)) << KREG_DRCTL_WP_SHIFT(n))

#define	KREG_DRCTL_WPEN_INCRSHIFT 2
#define	KREG_DRCTL_WPEN_MASK(n) \
	(3 << (KREG_DRCTL_WPEN_INCRSHIFT * (n)))
#define	KREG_DRCTL_WPEN(n)	KREG_DRCTL_WPEN_MASK(n)

#define	KREG_DRCTL_WPALLEN_MASK	0x000000ff

#define	KREG_DRCTL_GD_MASK	0x00002000

#define	KREG_DRCTL_RESERVED	0x00000700

/* %dr6 */
#define	KREG_DRSTAT_BT_MASK	0x00008000
#define	KREG_DRSTAT_BS_MASK	0x00004000
#define	KREG_DRSTAT_BD_MASK	0x00002000

#define	KREG_DRSTAT_WP_MASK(n)	(1 << (n))

#define	KREG_DRSTAT_RESERVED	0xffff0ff0

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_KREG_H */
