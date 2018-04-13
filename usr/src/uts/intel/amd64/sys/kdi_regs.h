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

#ifndef _AMD64_SYS_KDI_REGS_H
#define	_AMD64_SYS_KDI_REGS_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * A modified version of struct regs layout.
 */

#define	KDIREG_SAVFP	0
#define	KDIREG_SAVPC	1
#define	KDIREG_RDI	2
#define	KDIREG_RSI	3
#define	KDIREG_RDX	4
#define	KDIREG_RCX	5
#define	KDIREG_R8	6
#define	KDIREG_R9	7
#define	KDIREG_RAX	8
#define	KDIREG_RBX	9
#define	KDIREG_RBP	10
#define	KDIREG_R10	11
#define	KDIREG_R11	12
#define	KDIREG_R12	13
#define	KDIREG_R13	14
#define	KDIREG_R14	15
#define	KDIREG_R15	16
#define	KDIREG_FSBASE	17
#define	KDIREG_GSBASE	18
#define	KDIREG_KGSBASE	19
#define	KDIREG_CR2	20
#define	KDIREG_CR3	21
#define	KDIREG_DS	22
#define	KDIREG_ES	23
#define	KDIREG_FS	24
#define	KDIREG_GS	25
#define	KDIREG_TRAPNO	26
#define	KDIREG_ERR	27
#define	KDIREG_RIP	28
#define	KDIREG_CS	29
#define	KDIREG_RFLAGS	30
#define	KDIREG_RSP	31
#define	KDIREG_SS	32

#define	KDIREG_NGREG	(KDIREG_SS + 1)

#define	KDIREG_PC	KDIREG_RIP
#define	KDIREG_SP	KDIREG_RSP
#define	KDIREG_FP	KDIREG_RBP

#ifdef __cplusplus
}
#endif

#endif /* _AMD64_SYS_KDI_REGS_H */
