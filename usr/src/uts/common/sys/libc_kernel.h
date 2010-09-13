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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_LIBC_KERNEL_H
#define	_SYS_LIBC_KERNEL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains definitions for miscellaneous consolidation-private
 * interfaces that are private, exclusively between libc and the kernel.
 * These definitions are for implementation details that can change at
 * any time, even in a patch.  Applications should never see this file.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * A vfork() child that calls _exit(_EVAPORATE) without having performed
 * an execve() will disappear without a trace, just as though the parent
 * had set the disposition of the SIGCHLD signal to be ignored.  This is
 * used by the the posix_spawn() implementation in libc.
 */
#define	_EVAPORATE	0xffff0000

#ifdef __cplusplus
}
#endif

#endif /* _SYS_LIBC_KERNEL_H */
