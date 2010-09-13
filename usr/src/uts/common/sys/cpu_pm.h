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

#ifndef	_CPU_PM_H
#define	_CPU_PM_H

#ifdef	__cplusplus
extern "C" {
#endif

#if (defined(_KERNEL) || defined(_KMEMUSER))
#include <sys/cpuvar.h>
#include <sys/processor.h>
#include <sys/types.h>
#include <sys/kstat.h>
#include <sys/cmt.h>

/*
 * CPU Power Manager Policies
 */
typedef enum cpupm_policy {
	CPUPM_POLICY_ELASTIC,
	CPUPM_POLICY_DISABLED,
	CPUPM_NUM_POLICIES
} cpupm_policy_t;

/*
 * Power Managable CPU Domain Types
 */
typedef enum cpupm_dtype {
	CPUPM_DTYPE_ACTIVE,	/* Active Power Domain */
	CPUPM_DTYPE_IDLE	/* Idle Power Domain */
} cpupm_dtype_t;

/*
 * CPUPM state names for policy implementation.
 * The last element is used to size the enumeration.
 */
typedef enum cpupm_state_name {
	CPUPM_STATE_LOW_POWER,
	CPUPM_STATE_MAX_PERF,
	CPUPM_STATE_NAMES
} cpupm_state_name_t;

/*
 * Possible states for the domain's transience governor
 */
typedef enum cpupm_gov_state_t {
	CPUPM_GOV_DISENGAGED,
	CPUPM_GOV_TRANS_IDLE,	/* Transient idleness, lowerings disabled */
	CPUPM_GOV_TRANS_WORK	/* Transient work, raises disabled */
} cpupm_gov_state_t;

/*
 * Utilization events delivered by the dispatcher.
 */
typedef enum cpupm_util_event {
	CPUPM_DOM_BUSY_FROM_IDLE,
	CPUPM_DOM_IDLE_FROM_BUSY,
	CPUPM_DOM_REMAIN_BUSY
} cpupm_util_event_t;

typedef uintptr_t	cpupm_handle_t;	/* Platform handle */

/*
 * CPU Power Domain State
 */
typedef struct cpupm_state {
	uint32_t	cps_speed;
	cpupm_handle_t	cps_handle;
} cpupm_state_t;

/*
 * CPU Power Domain
 */
typedef struct cpupm_domain {
	id_t			cpd_id;		/* Domain ID */
	cpupm_dtype_t		cpd_type;	/* Active or Idle */
	cpupm_state_t		*cpd_states;	/* Available Power States */
	cpupm_state_t		*cpd_state;	/* Current State */
	uint_t			cpd_nstates;	/* Number of States */
	cpupm_state_t		*cpd_named_states[CPUPM_STATE_NAMES];
	hrtime_t		cpd_last_raise;	/* Last raise request time */
	hrtime_t		cpd_last_lower;	/* last lower request time */
	int			cpd_ti;		/* transient idle history */
	int			cpd_tw;		/* transient work history */
	cpupm_gov_state_t	cpd_governor;   /* transience governor */
	struct cpupm_domain	*cpd_next;
} cpupm_domain_t;

#define	CPUPM_NO_DOMAIN ((id_t)-1)

/*
 * CPU power manager domain management interfaces
 */
cpupm_domain_t		*cpupm_domain_init(struct cpu *, cpupm_dtype_t);
id_t			cpupm_domain_id(struct cpu *, cpupm_dtype_t);
int			cpupm_change_state(struct cpu *, cpupm_domain_t *,
    cpupm_state_t *);
extern void		cpupm_redefine_max_activepwr_state(struct cpu *, int);

/*
 * CPU power manager policy engine interfaces
 */
int			cpupm_set_policy(cpupm_policy_t);
cpupm_policy_t		cpupm_get_policy(void);
void			cpupm_utilization_event(struct cpu *, hrtime_t,
			    cpupm_domain_t *, cpupm_util_event_t);

/*
 * CPU power platform driver interfaces
 */
id_t	cpupm_plat_domain_id(struct cpu *, cpupm_dtype_t);
uint_t	cpupm_plat_state_enumerate(struct cpu *, cpupm_dtype_t,
    cpupm_state_t *);
int	cpupm_plat_change_state(struct cpu *, cpupm_state_t *);


#endif	/* !_KERNEL && !_KMEMUSER */

#ifdef	__cplusplus
}
#endif

#endif /* _CPU_PM_H */
