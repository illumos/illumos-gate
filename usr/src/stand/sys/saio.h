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

#ifndef	_SYS_SAIO_H
#define	_SYS_SAIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI" /* from SunOS 4.1 */

/*
 * NOTE: This header file is a vestige from a previous era.  The RESOURCES
 *	 enum should be move somewhere more appropriate (with an accompanying
 *	 proper prototype for resalloc()) and this should be removed.
 */

#include <sys/types.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Types of resources that can be allocated by resalloc().
 */
enum RESOURCES {
	RES_MAINMEM,		/* Main memory, accessible to CPU */
	RES_RAWVIRT,		/* Raw addr space that can be mapped */
	RES_DMAMEM,		/* Memory acc. by CPU and by all DMA I/O */
	RES_DMAVIRT,		/* Raw addr space accessible by DMA I/O */
	RES_PHYSICAL,		/* Physical address */
	RES_VIRTALLOC,		/* Virtual addresses used */
	RES_BOOTSCRATCH,	/* Memory <4MB used only by boot. */
#ifdef	__sparc
	RES_CHILDVIRT,		/* Virt anywhere, phys > 4MB */
	RES_BOOTSCRATCH_NOFAIL
#else
	RES_CHILDVIRT		/* Virt anywhere, phys > 4MB */
#endif
};

#ifdef __cplusplus
}
#endif

#endif /* _SYS_SAIO_H */
