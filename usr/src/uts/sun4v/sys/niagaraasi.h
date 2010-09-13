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

#ifndef _SYS_NIAGARAASI_H
#define	_SYS_NIAGARAASI_H

/*
 * alternate address space identifiers
 *
 * 0x00 - 0x2F are privileged
 * 0x30 - 0x7f are hyperprivileged
 * 0x80 - 0xFF can be used by users
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * NIAGARA, NIAGARA2, Victoria Falls and KT specific ASIs
 */
#define	ASI_BLK_INIT_QUAD_LDD_AIUS	0x23	/* block as if user secondary */
#define	ASI_BLK_INIT_ST_QUAD_LDD_P	0xE2	/* block initializing primary */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_NIAGARAASI_H */
