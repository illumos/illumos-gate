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
 * Copyright 1998, 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _DC_KI_H
#define	_DC_KI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The routine is used for all drivers that are loaded into
 * memory before root is mounted. They are implemented in
 * misc/cl_bootstrap module in SunCluster consolidation.
 */

extern void cluster(void);
extern int clboot_modload(struct modctl *mp);
extern int clboot_loadrootmodules();
extern int clboot_rootconf();
extern void clboot_mountroot();

#ifdef __cplusplus
}
#endif

#endif /* _DC_KI_H */
