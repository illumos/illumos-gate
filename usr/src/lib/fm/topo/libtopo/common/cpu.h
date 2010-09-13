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

#ifndef	_CPU_H
#define	_CPU_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <kstat.h>

#define	CPU_VERSION	1

typedef struct cpu_node {
	kstat_ctl_t *cn_kc;
	kstat_t **cn_cpustats;
	uint_t cn_ncpustats;
} cpu_node_t;

extern int cpu_init(topo_mod_t *, topo_version_t);	/* see cpu.c */
extern void cpu_fini(topo_mod_t *);			/* see cpu.c */

#ifdef	__cplusplus
}
#endif

#endif	/* _CPU_H */
