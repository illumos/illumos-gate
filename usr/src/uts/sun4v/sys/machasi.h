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

#ifndef _SYS_MACHASI_H
#define	_SYS_MACHASI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * alternate address space identifiers
 *
 * 0x00 - 0x2F are privileged
 * 0x30 - 0x7f are hyperprivileged
 * 0x80 - 0xFF can be used by users
 */

/*
 * ASIs specific to sun4v compliant  processors.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	ASI_BLK_AIUP		0x16	/* block as if user primary */
#define	ASI_BLK_AIUS		0x17	/* block as if user secondary */
#define	ASI_BLK_AIUPL		0x1E	/* block as if user primary little */
#define	ASI_BLK_AIUSL		0x1F	/* block as if user secondary little */

#define	ASI_NQUAD_LD		0x24	/* 128-bit atomic load */
#define	ASI_NQUAD_LD_L		0x2C	/* 128-bit atomic load little */
#define	ASI_QUAD_LDD_PHYS	0x26	/* 128-bit physical atomic load */
#define	ASI_QUAD_LDD_PHYS_L	0x2E	/* 128-bit phys. atomic load little */

#define	ASI_SCRATCHPAD		0x20	/* sun4v scratch pad registers ASI */
#define	ASI_MMU			0x21	/* sun4v ctx register ASI */
#define	ASI_MMU_CTX		ASI_MMU

#define	ASI_QUEUE		0x25

/*
 * MMU fault status area (see sys/hypervisor_api.h for layout)
 */
#define	MMU_FAULT_STATUS_AREA(REG)	\
	ldxa	[%g0]ASI_SCRATCHPAD, REG

/*
 * Scratch pad registers
 * (0x0 through 0x18 guaranteed fast, rest may be slow)
 */
#define	SCRATCHPAD_MMUMISSAREA	0x0	/* Shared with OBP - set by OBP */
#define	SCRATCHPAD_CPUID	0x8	/* Shared with OBP - set by HV */
#define	SCRATCHPAD_UTSBREG1	0x10
#define	SCRATCHPAD_UTSBREG2	0x18
					/* 0x20 & 0x28 HV only */
#define	SCRATCHPAD_UNUSED1	0x30
#define	SCRATCHPAD_UNUSED2	0x38	/* reserved for OBP */

/*
 * Ancillary state registers, for asrset_t
 */
#define	ASR_GSR	(3)

#ifdef __cplusplus
}
#endif

#endif /* _SYS_MACHASI_H */
