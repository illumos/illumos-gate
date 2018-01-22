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
 *
 * Copyright 2018 Joyent, Inc.
 */

#ifndef	_MDB_KREG_H
#define	_MDB_KREG_H

#include <sys/kdi_regs.h>
#ifndef _ASM
#include <sys/types.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef _ASM
#ifdef __amd64
typedef uint64_t kreg_t;
#else	/* __amd64 */
typedef uint32_t kreg_t;
#endif	/* __amd64 */
#endif	/* !_ASM */

#define	KREG_NGREG	KDIREG_NGREG

/*
 * The order of these registers corresponds to a slightly altered struct regs,
 * in the order kmdb entry pushes onto the stack.
 */

#ifdef __amd64

#define	KREG_SAVFP	KDIREG_SAVFP
#define	KREG_SAVPC	KDIREG_SAVPC
#define	KREG_RDI	KDIREG_RDI
#define	KREG_RSI	KDIREG_RSI
#define	KREG_RDX	KDIREG_RDX
#define	KREG_RCX	KDIREG_RCX
#define	KREG_R8		KDIREG_R8
#define	KREG_R9		KDIREG_R9
#define	KREG_RAX	KDIREG_RAX
#define	KREG_RBX	KDIREG_RBX
#define	KREG_RBP	KDIREG_RBP
#define	KREG_R10	KDIREG_R10
#define	KREG_R11	KDIREG_R11
#define	KREG_R12	KDIREG_R12
#define	KREG_R13	KDIREG_R13
#define	KREG_R14	KDIREG_R14
#define	KREG_R15	KDIREG_R15
#define	KREG_DS		KDIREG_DS
#define	KREG_ES		KDIREG_ES
#define	KREG_FS		KDIREG_FS
#define	KREG_GS		KDIREG_GS
#define	KREG_GSBASE	KDIREG_GSBASE
#define	KREG_KGSBASE	KDIREG_KGSBASE
#define	KREG_TRAPNO	KDIREG_TRAPNO
#define	KREG_ERR	KDIREG_ERR
#define	KREG_CR2	KDIREG_CR2
#define	KREG_RIP	KDIREG_RIP
#define	KREG_CS		KDIREG_CS
#define	KREG_RFLAGS	KDIREG_RFLAGS
#define	KREG_RSP	KDIREG_RSP
#define	KREG_SS		KDIREG_SS

#define	KREG_PC		KREG_RIP
#define	KREG_SP		KREG_RSP
#define	KREG_FP		KREG_RBP

#else	/* __amd64 */

#define	KREG_SAVFP	KDIREG_SAVFP
#define	KREG_SAVPC	KDIREG_SAVPC
#define	KREG_SS		KDIREG_SS
#define	KREG_GS		KDIREG_GS
#define	KREG_FS		KDIREG_FS
#define	KREG_ES		KDIREG_ES
#define	KREG_DS		KDIREG_DS
#define	KREG_EDI	KDIREG_EDI
#define	KREG_ESI	KDIREG_ESI
#define	KREG_EBP	KDIREG_EBP
#define	KREG_ESP	KDIREG_ESP
#define	KREG_EBX	KDIREG_EBX
#define	KREG_EDX	KDIREG_EDX
#define	KREG_ECX	KDIREG_ECX
#define	KREG_EAX	KDIREG_EAX
#define	KREG_TRAPNO	KDIREG_TRAPNO
#define	KREG_ERR	KDIREG_ERR
#define	KREG_EIP	KDIREG_EIP
#define	KREG_CS		KDIREG_CS
#define	KREG_EFLAGS	KDIREG_EFLAGS
#define	KREG_UESP	KDIREG_UESP

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

/* %dr6 */
#define	KREG_DRSTAT_BT_MASK	0x00008000
#define	KREG_DRSTAT_BS_MASK	0x00004000
#define	KREG_DRSTAT_BD_MASK	0x00002000

#define	KREG_DRSTAT_WP_MASK(n)	(1 << (n))

#ifdef	__cplusplus
}
#endif

#endif	/* _MDB_KREG_H */
