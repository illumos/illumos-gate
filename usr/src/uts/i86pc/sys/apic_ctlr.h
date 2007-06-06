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

#ifndef _SYS_APIC_CTLR_H
#define	_SYS_APIC_CTLR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Macros dealing with controller version field returned as part of
 * PSM_INTR_OP_APIC_TYPE.
 */
#define	PSMAT_LOCAL_APIC_VER(ctlr_ver)	((ctlr_ver) & 0xff)
#define	PSMAT_IO_APIC_VER(ctlr_ver)	((ctlr_ver) >> 8)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_APIC_CTLR_H */
