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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_GPTWO_CPU_H
#define	_SYS_GPTWO_CPU_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Header file for the CPU component to the Safari Configurator (gptwo_cpu).
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/safari_pcd.h>

gptwocfg_ops_cookie_t gptwocfg_alloc_cpu_ops(int, int);
gptwo_new_nodes_t *gptwocfg_configure_cpu(dev_info_t *, spcd_t *, uint_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_GPTWO_CPU_H */
