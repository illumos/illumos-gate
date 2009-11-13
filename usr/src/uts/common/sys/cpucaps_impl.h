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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_CPUCAPS_IMPL_H
#define	_SYS_CPUCAPS_IMPL_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

#include <sys/kstat.h>
#include <sys/cpucaps.h>
#include <sys/list.h>
#include <sys/time.h>
#include <sys/waitq.h>

/*
 * When resource control framework sets the cap to NOCAP value the cap
 * is disabled.
 */
#define	NOCAP	MAXCAP

/*
 * Maximum value for the cap usage. Should be the maximum value for hrtime_t
 */
#if defined(_LP64)
#define	MAX_USAGE LONG_MAX
#else
#define	MAX_USAGE 9223372036854775807LL
#endif


/*
 * Most of the per-project or per-zone state related to CPU caps is kept in the
 * cpucap_t structure.
 */
typedef struct cpucap {
	list_node_t	cap_link;	/* next/prev capped entity	*/
	struct kproject	*cap_project;	/* project for the cap		*/
	struct zone	*cap_zone;	/* zone for the cap		*/
	waitq_t		cap_waitq;	/* waitq for capped threads	*/
	kstat_t		*cap_kstat;	/* cpucaps specific kstat	*/
	int64_t		cap_gen;	/* zone cap specific 		*/
	hrtime_t	cap_value;	/* scaled CPU usage cap		*/
	hrtime_t	cap_usage;	/* current CPU usage		*/
	disp_lock_t	cap_usagelock;	/* protects cap_usage above	*/
	/*
	 * Per cap statistics.
	 */
	hrtime_t	cap_maxusage;	/* maximum cap usage		*/
	u_longlong_t	cap_below;	/* # of ticks spend below the cap */
	u_longlong_t	cap_above;	/* # of ticks spend above the cap */
} cpucap_t;

/*
 * Wrapper macros for checking cap state.
 */
#define	CAP_ENABLED(cap) ((cap)->cap_value != 0)
#define	CAP_DISABLED(cap) (!CAP_ENABLED(cap))

#define	PROJECT_IS_CAPPED(project) \
	(((project)->kpj_cpucap != NULL) && \
	CAP_ENABLED((project)->kpj_cpucap))

#define	ZONE_IS_CAPPED(zone) \
	(((zone)->zone_cpucap != NULL) && \
	CAP_ENABLED((zone)->zone_cpucap))

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CPUCAPS_IMPL_H */
