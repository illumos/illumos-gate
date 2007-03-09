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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_CPUCAPS_H
#define	_SYS_CPUCAPS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/zone.h>
#include <sys/project.h>
#include <sys/time.h>
#include <sys/rctl.h>

/*
 * CPU caps provide an absolute hard CPU usage limit which is enforced even if
 * some CPUs are idle. It can be enforced at project or zone level.
 */

#ifdef _KERNEL

/*
 * Valid caps values go from 1 to MAXCAP - 1. Specifying the MAXCAP as the cap
 * value is equivalent to disabling the cap.
 */
#define	MAXCAP		UINT_MAX

/*
 * cpucaps_enabled is used to quickly check whether any CPU caps specific code
 * should be invoked. Users outside CPU Caps framework should use CPUCAPS_ON()
 * and CPUCAPS_OFF() macros.
 */
extern boolean_t cpucaps_enabled;

#define	CPUCAPS_ON()	cpucaps_enabled
#define	CPUCAPS_OFF()	(!cpucaps_enabled)

/*
 * Initialize the CPU caps framework.
 */
extern void cpucaps_init(void);

/*
 * Notify caps framework of a new project coming in or existing project
 * going away
 */
extern void cpucaps_project_add(kproject_t *);
extern void cpucaps_project_remove(kproject_t *);

/*
 * Notify caps framework when a zone is going away.
 */
extern void cpucaps_zone_remove(zone_t *);

/*
 * Set project/zone cap to specified value. Value of MAXCAP should disable caps.
 */
extern int cpucaps_project_set(kproject_t *, rctl_qty_t);
extern int cpucaps_zone_set(zone_t *, rctl_qty_t);

/*
 * Get current CPU usage for a project/zone.
 */
extern rctl_qty_t cpucaps_project_get(kproject_t *);
extern rctl_qty_t cpucaps_zone_get(zone_t *);

/*
 * Scheduling class hooks into CPU caps framework.
 */

/*
 * CPU caps specific data for each scheduling class.
 *
 * There is a small amount of accounting data that should be kept by each
 * scheduling class for each thread which is only used by CPU caps code. This
 * data is kept in the caps_sc structure which is transparent for all scheduling
 * classes. The fields in the structure are:
 *
 *     csc_cputime -  Total time spent on CPU during thread lifetime, obtained
 *                    as the sum of user, system and trap time, reported by
 *                    microstate accounting.
 */
typedef struct caps_sc {
	hrtime_t	csc_cputime;
} caps_sc_t;

/*
 * Initialize per-thread cpu-caps specific data.
 */
extern void cpucaps_sc_init(caps_sc_t *);

/*
 * Modus operandi for cpucaps_charge() function.
 *
 *   CPUCAPS_CHARGE_ENFORCE - charge a thread for its CPU time and
 *				flag it to be placed on wait queue.
 *
 *   CPUCAPS_CHARGE_ONLY    - charge a thread for its CPU time.
 */
typedef enum {
	CPUCAPS_CHARGE_ENFORCE,
	CPUCAPS_CHARGE_ONLY
} cpucaps_charge_t;

/*
 * Add accumulated CPU usage of a thread to its cap.
 * Return True if thread should be placed on waitq.
 */
extern boolean_t cpucaps_charge(kthread_t *, caps_sc_t *, cpucaps_charge_t);
#define	CPUCAPS_CHARGE(t, scp, flag) \
	(CPUCAPS_ON() && cpucaps_charge(t, scp, flag))

/*
 * Request a thread to be placed on a wait queue because the cap is exceeded
 */
extern boolean_t cpucaps_enforce(kthread_t *);
#define	CPUCAPS_ENFORCE(t) (CPUCAPS_ON() && cpucaps_enforce(t))

/*
 * CPU Caps hook into clock().
 */
extern void (*cpucaps_clock_callout)(void);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CPUCAPS_H */
