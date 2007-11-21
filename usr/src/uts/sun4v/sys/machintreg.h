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
 */

#ifndef _SYS_MACHINTREG_H
#define	_SYS_MACHINTREG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * IGN_SIZE can be defined in a platform's makefile. If it is not defined,
 * use a default of 5.
 */
#ifndef IGN_SIZE
#define	IGN_SIZE	5		/* Interrupt Group Number bit size */
#endif
#define	UPAID_TO_IGN(upaid) (upaid)

/*
 * MAXVINTRS is the number of interrupts we require to be allocated
 * in the system intr_vec_table in addition to the hardware interrupts.
 * These interrupts will be used by the sun4v cnex driver for its Logical
 * Domain Channels. Each LDC requires a pair of interrupts, (RX/TX),
 * and the total number of interrupts required will depend on the
 * resources available to the system (CPUs, memory, etc) and how
 * the system domains are configured, (number of virtual disks/networks
 * per domain etc).
 *
 * The service domain requires (at least) a console LDC, Domain Services
 * LDCs, vdisk LDC and vnet LDC per guest domain. It also requires a small
 * number of LDCs for communications with the SP etc.
 *
 * The number of LDCs required is ~(N * 4 + a few more) where N is the
 * possible maximum guest domains. The current possible maximum
 * number of domains is 512, so we require ~2048 LDCs. And as
 * each LDC requires a pair of interrupts we need to add the
 * capacity for ~4096 interrupts to the system interrupt table.
 *
 * We start allocating the LDC interrupts at MINVINTR_COOKIE.
 */
#define	MINVINTR_COOKIE		(MAXDEVINTRS)
#define	MAXVINTRS		4096

/*
 * CPU_MONDO and DEV_MONDO  registers
 * for sun4v class of cpus probably should
 * be moved to a new file
 */
#define	CPU_MONDO_Q_HD	0x3c0
#define	CPU_MONDO_Q_TL	0x3c8
#define	DEV_MONDO_Q_HD	0x3d0
#define	DEV_MONDO_Q_TL	0x3d8

/*
 * RESUMABLE_ERROR and NONRESUMABLE_ERROR registers
 * for sun4v class of cpus
 */
#define	CPU_RQ_HD		0x3e0
#define	CPU_RQ_TL		0x3e8
#define	CPU_NRQ_HD		0x3f0
#define	CPU_NRQ_TL		0x3f8

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MACHINTREG_H */
