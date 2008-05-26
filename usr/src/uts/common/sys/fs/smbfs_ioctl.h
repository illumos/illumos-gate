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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SMBFS_IOCTL_H
#define	_SMBFS_IOCTL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Project private IOCTL interface provided by SMBFS.
 */

#include <sys/ioccom.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ioc_sdbuf {
	uint64_t addr;		/* buffer address (user space) */
	uint32_t alloc;		/* allocated length */
	uint32_t used;		/* content length */
	uint32_t selector;	/* i.e. DACL_SECURITY_INFORMATION */
} ioc_sdbuf_t;

/*
 * SMBFS ioctl codes
 *
 * We only need a couple of these, so (re)using some
 * FS-specific ioctl codes from sys/filio.h
 * Data for both is ioc_sdbuf_t
 */

#define	SMBFSIO_GETSD		_IO('f', 81)
#define	SMBFSIO_SETSD		_IO('f', 82)

#ifdef __cplusplus
}
#endif

#endif /* _SMBFS_IOCTL_H */
