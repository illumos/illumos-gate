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
 * Copyright (c) 1991 by Sun Microsystems, Inc.
 */

#ifndef _SYS_IOREQ_H
#define	_SYS_IOREQ_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The ioreq enables data structures to package several i/o requests
 * into one system call. It is used by the read/write+offset interface.
 */
typedef struct ioreq {
	caddr_t	ior_base;	/* buffer addr */
	int	ior_len;	/* buffer length */
	offset_t ior_offset;	/* file offset */
	int	ior_whence;
	int	ior_errno;
	int	ior_return;
	int	ior_flag;
} ioreq_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_IOREQ_H */
