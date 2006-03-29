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
 * Copyright 1994 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_SRAM_H
#define	_SYS_SRAM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* useful debugging stuff */
#define	SRAM_ATTACH_DEBUG	0x1
#define	SRAM_REGISTERS_DEBUG	0x2

/* Use predefined strings to name the kstats from this driver. */
#define	RESETINFO_KSTAT_NAME	"reset-info"

/* Define Maximum size of the reset-info data passed up by POST. */
#define	MX_RSTINFO_SZ		0x2000

#if defined(_KERNEL)

/* Structures used in the driver to manage the hardware */
struct sram_soft_state {
	dev_info_t *dip;	/* dev info of myself */
	dev_info_t *pdip;	/* dev info of my parent */
	int board;		/* Board number for this sram */
	char *sram_base;	/* base of sram */
	int offset;		/* offset into sram of reset info */
	char *reset_info;	/* base of reset-info structure */
	char *os_private;	/* base of OS private area; */
};

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SRAM_H */
