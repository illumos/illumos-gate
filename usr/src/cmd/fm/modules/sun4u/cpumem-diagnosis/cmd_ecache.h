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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _CMD_EC_H
#define	_CMD_EC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * E-cache flushing
 *
 * Prior to clearing the UE cache, the CPU state code needs to ensure that the
 * CPU's E-cache has been flushed.  The flushing is handled by the routines in
 * in this file, which use the memory controller (mc) driver to perform the
 * flush.
 */

#include <fm/fmd_api.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int cmd_ecache_init(void);

extern int cmd_ecache_flush(int);

#ifdef __cplusplus
}
#endif

#endif /* _CMD_EC_H */
