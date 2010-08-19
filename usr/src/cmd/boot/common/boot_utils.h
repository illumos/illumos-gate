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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_BOOT_UTILS_H
#define	_BOOT_UTILS_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include <sys/types.h>
#include "bblk_einfo.h"

/* Common return values for various operations. */
#define	BC_SUCCESS		(0)
#define	BC_ERROR		(1)
#define	BC_NOUPDT		(4)
#define	BC_NOEXTRA		(5)
#define	BC_NOEINFO		(6)

#define	SECTOR_SIZE		(512)

extern boolean_t boot_debug;
extern boolean_t nowrite;

#define	BOOT_DEBUG(...)	boot_gdebug(__func__, __VA_ARGS__)

void boot_gdebug(const char *, char *, ...);

int write_out(int, void *, size_t, off_t);
int read_in(int, void *, size_t, off_t);

#ifdef	__cplusplus
}
#endif

#endif /* _BOOT_UTILS_H */
