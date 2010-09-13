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
 * Copyright (c) 1996-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_DADA_IMPL_TYPES_H
#define	_SYS_DADA_IMPL_TYPES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * local types for DADA subsystems
 */

#ifdef _KERNEL

#include	<sys/kmem.h>
#include	<sys/open.h>
#include	<sys/uio.h>
#include	<sys/sysmacros.h>

#include	<sys/buf.h>
#include	<sys/errno.h>
#include	<sys/fcntl.h>
#include	<sys/ioctl.h>

#include	<sys/conf.h>

#include	<sys/dada/impl/services.h>
#include	<sys/dada/impl/transport.h>

#include	<sys/dada/impl/commands.h>
#include	<sys/dada/impl/status.h>

#endif	/* _KERNEL */
#include 	<sys/dada/impl/udcd.h>


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DADA_IMPL_TYPES_H */
