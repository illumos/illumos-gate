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

#ifndef _IA32_SYS_KDI_REGS_H
#define	_IA32_SYS_KDI_REGS_H

#ifdef __cplusplus
extern "C" {
#endif

#define	KDIREG_NGREG	21

/*
 * %ss appears in a different place than a typical struct regs, since the
 * machine won't save %ss on a trap entry from the same privilege level.
 */

#define	KDIREG_SAVFP	0
#define	KDIREG_SAVPC	1
#define	KDIREG_SS	2
#define	KDIREG_GS	3
#define	KDIREG_FS	4
#define	KDIREG_ES	5
#define	KDIREG_DS	6
#define	KDIREG_EDI	7
#define	KDIREG_ESI	8
#define	KDIREG_EBP	9
#define	KDIREG_ESP	10
#define	KDIREG_EBX	11
#define	KDIREG_EDX	12
#define	KDIREG_ECX	13
#define	KDIREG_EAX	14
#define	KDIREG_TRAPNO	15
#define	KDIREG_ERR	16
#define	KDIREG_EIP	17
#define	KDIREG_CS	18
#define	KDIREG_EFLAGS	19
#define	KDIREG_UESP	20

#define	KDIREG_PC	KDIREG_EIP
#define	KDIREG_SP	KDIREG_ESP
#define	KDIREG_FP	KDIREG_EBP

#ifdef __cplusplus
}
#endif

#endif /* _IA32_SYS_KDI_REGS_H */
