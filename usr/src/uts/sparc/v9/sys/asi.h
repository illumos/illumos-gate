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
 * Copyright (c) 1993 by Sun Microsystems, Inc.
 */

#ifndef	_SYS_ASI_H
#define	_SYS_ASI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * alternate address space identifiers
 *
 * 0x00 - 0x7F are privileged
 * 0x80 - 0xFF can be used by users
 */

/*
 * V9 asis
 */
#define	ASI_N			0x04	/* nucleus */
#define	ASI_NL			0x0C	/* nucleus little */
#define	ASI_AIUP		0x10	/* as if user primary */
#define	ASI_AIUS		0x11	/* as if user secondary */
#define	ASI_AIUPL		0x18	/* as if user primary little */
#define	ASI_AIUSL		0x19	/* as if user secondary little */
#define	ASI_P			0x80	/* primary */
#define	ASI_S			0x81	/* secondary */
#define	ASI_PNF			0x82	/* primary no fault */
#define	ASI_SNF			0x83	/* secondary no fault */
#define	ASI_PL			0x88	/* primary little */
#define	ASI_SL			0x89	/* secondary little */
#define	ASI_PNFL		0x8A	/* primary no fault little */
#define	ASI_SNFL		0x8B	/* secondary no fault little */

/*
 * Mnemonic asis
 */
#define	ASI_USER	ASI_AIUS

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ASI_H */
