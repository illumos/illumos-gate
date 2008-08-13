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

#ifndef	_CPUPM_H
#define	_CPUPM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/ddi.h>
#include <sys/sunddi.h>

/*
 * Simple structures used to temporarily keep track of CPU
 * dependencies until the PPM driver can build PPM CPU domains.
 */
typedef struct cpupm_cpu_node {
	struct cpupm_cpu_node	*cn_next;
	dev_info_t		*cn_dip;
} cpupm_cpu_node_t;

typedef struct cpupm_cpu_dependency {
	struct cpupm_cpu_dependency *cd_next;
	cpupm_cpu_node_t	*cd_cpu;
	int			cd_dependency_id;
} cpupm_cpu_dependency_t;

/*
 * If any states are added, then make sure to add them to
 * CPUPM_ALL_STATES.
 */
#define	CPUPM_NO_STATES		0x00
#define	CPUPM_P_STATES		0x01
#define	CPUPM_T_STATES		0x02
#define	CPUPM_ALL_STATES	(CPUPM_P_STATES | CPUPM_T_STATES)

/*
 * Callbacks used for CPU power management.
 */
extern void (*cpupm_rebuild_cpu_domains)(void);
extern void (*cpupm_init_topspeed)(void);
extern void (*cpupm_redefine_topspeed)(void *);
extern int (*cpupm_get_topspeed)(void *);
extern void (*cpupm_set_topspeed)(void *, int);

/*
 * Routines used to manage temporary CPU dependencies.
 */
extern cpupm_cpu_dependency_t *cpupm_get_cpu_dependencies();
extern void cpupm_add_cpu2dependency(dev_info_t *, int);
extern void cpupm_free_cpu_dependencies();

/*
 * Routines to track overall status of CPU power management readiness.
 *
 */
extern boolean_t cpupm_is_ready();
extern boolean_t cpupm_is_enabled(uint32_t);
extern void cpupm_disable(uint32_t);
extern void cpupm_post_startup();

#ifdef __cplusplus
}
#endif

#endif	/* _CPUPM_H */
