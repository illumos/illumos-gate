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
 * Copyright 1996, 2001, 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_BOOTDEBUG_H
#define	_SYS_BOOTDEBUG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * a collection of usefule debug defines and macros
 */

/* #define	COMPFS_OPS_DEBUG */
/* #define	PCFS_OPS_DEBUG */
/* #define	HSFS_OPS_DEBUG */
/* #define	UFS_OPS_DEBUG */
/* #define	NFS_OPS_DEBUG */
/* #define	CFS_OPS_DEBUG */
/* #define	VERIFY_HASH_REALLOC */

#include <sys/reboot.h>

extern int boothowto;			/* What boot options are set */
extern int verbosemode;

#define	dprintf		if (boothowto & RB_DEBUG) printf
#define	DBFLAGS		(RB_DEBUG | RB_VERBOSE)

/*
 * Debug Message Macros - will print message if CFS_OPS_DEBUG
 * is defined.
 */
#ifdef CFS_OPS_DEBUG

#define	OPS_DEBUG(args)	{ printf args; }
#define	OPS_DEBUG_CK(args)\
	{ if ((boothowto & DBFLAGS) == DBFLAGS) printf args; }

#else /* CFS_OPS_DEBUG */

#define	OPS_DEBUG(args)	/* nothing */
#define	OPS_DEBUG_CK(args)	/* nothing */

#endif /* CFS_OPS_DEBUG */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_BOOTDEBUG_H */
