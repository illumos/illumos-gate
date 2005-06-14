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
 * Copyright (c) 1989-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_BUSTYPES_H
#define	_SYS_BUSTYPES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Defines for bus types.  These are magic cookies passed between drivers
 * and their parents to describe their address space.  Configuration mechanisms
 * use this as well.  Root nexus drivers on implementations using
 * "generic-addressing" also use these to describe register properties.
 * Generally, this will be non-self configuring architectures.
 *
 *
 * On machines supporting "generic-addressing" in the root nexus,
 * the generic cookies described in the bootom of the file are used
 * to distinguish the spaces described by device regsiters.
 *
 * Sun machines generally support OBMEM and OBIO spaces.
 */

#define	SP_VIRTUAL	0x0100		/* virtual address */
#define	SP_OBMEM	0x0200		/* on board memory */
#define	SP_OBIO		0x0210		/* on board i/o */

/*
 * The following are some Cookie name/value suggestions...
 * and are not necessarily supported at all (nexi for these devices
 * must handle and convert any requests for these spaces.)
 */

#define	SP_SBUS		0x0400		/* SBus device bus */
#define	SB_XBOX		0x0500		/* XBox device bus */

#define	SP_MBMEM	0x1000		/* MultiBus memory */
#define	SP_MBIO		0x1100		/* MultiBus IO */

#define	SP_ATMEM	0x2000		/* AT Bus Memory */
#define	SP_ATIO		0x2100		/* AT IO */

#define	SP_FBMEM	0x3000		/* FutureBus Memory */
#define	SP_FBIO		0x3100		/* FutureBus IO */

#define	SP_UBMEM	0x4000		/* Arbitrary user bus memory space */
#define	SP_UBIO		0x4100		/* Arbitrary user bus IO space */

#define	SP_INVALID	((unsigned)-1)	/* This value reserved */

/*
 * Anything in the range 0x4000 - 0x4FFF reserved for arbitrary 3rd party use.
 */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_BUSTYPES_H */
