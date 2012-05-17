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
/*
 * Copyright (c) 2009,  Intel Corporation.
 * All Rights Reserved.
 */

#ifndef	_CPUPM_MACH_H
#define	_CPUPM_MACH_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cpuvar.h>
#include <sys/ksynch.h>
#include <sys/cpu_pm.h>

/*
 * CPU power domains
 */
typedef struct cpupm_state_domains {
	struct cpupm_state_domains	*pm_next;
	uint32_t			pm_domain;
	uint32_t			pm_type;
	cpuset_t			pm_cpus;
	kmutex_t			pm_lock;
} cpupm_state_domains_t;

extern cpupm_state_domains_t *cpupm_pstate_domains;
extern cpupm_state_domains_t *cpupm_tstate_domains;
extern cpupm_state_domains_t *cpupm_cstate_domains;

/*
 * Different processor families have their own technologies for supporting
 * CPU power management (i.e., Intel has Enhanced SpeedStep for some of its
 * processors and AMD has PowerNow! for some of its processors). We support
 * these different technologies via modules that export the interfaces
 * described below.
 *
 * If a module implements the technology that should be used to manage
 * the current CPU device, then the cpus_init() module should return
 * succesfully (i.e., return code of 0) and perform any initialization
 * such that future power transistions can be performed by calling
 * the cpus_change() interface. And the cpups_fini() interface can be
 * used to free any resources allocated by cpus_init().
 */
typedef struct cpupm_state_ops {
	char	*cpups_label;
	int	(*cpus_init)(cpu_t *);
	void	(*cpus_fini)(cpu_t *);
	void	(*cpus_change)(cpuset_t, uint32_t);
	void	(*cpus_stop)(cpu_t *);
} cpupm_state_ops_t;

/*
 * Data kept for each C-state power-domain.
 */
typedef struct cma_c_state {
	uint32_t	cs_next_cstate;	/* computed best C-state */

	uint32_t	cs_cnt;		/* times accessed */
	uint32_t	cs_type;	/* current ACPI idle type */

	hrtime_t	cs_idle_enter;	/* entered idle */
	hrtime_t	cs_idle_exit;	/* left idle */

	hrtime_t	cs_smpl_start;	/* accounting sample began */
	hrtime_t	cs_idle;	/* time idle */
	hrtime_t	cs_smpl_len;	/* sample duration */
	hrtime_t	cs_smpl_idle;	/* idle time in last sample */
	uint64_t	cs_smpl_idle_pct;	/* % idle time in last smpl */
} cma_c_state_t;

typedef union cma_state {
	cma_c_state_t	*cstate;
	uint32_t	pstate;
} cma_state_t;

typedef struct cpupm_mach_acpi_state {
	cpupm_state_ops_t	*cma_ops;
	cpupm_state_domains_t   *cma_domain;
	cma_state_t		cma_state;
} cpupm_mach_acpi_state_t;

typedef struct cpupm_mach_turbo_info {
	kstat_t		*turbo_ksp;		/* turbo kstat */
	int		in_turbo;		/* in turbo? */
	int		turbo_supported;	/* turbo flag */
	uint64_t	t_mcnt;			/* turbo mcnt */
	uint64_t	t_acnt;			/* turbo acnt */
} cpupm_mach_turbo_info_t;

typedef struct cpupm_mach_state {
	void			*ms_acpi_handle;
	cpupm_mach_acpi_state_t	ms_pstate;
	cpupm_mach_acpi_state_t	ms_cstate;
	cpupm_mach_acpi_state_t	ms_tstate;
	uint32_t		ms_caps;
	dev_info_t		*ms_dip;
	kmutex_t		ms_lock;
	cpupm_mach_turbo_info_t	*ms_turbo;
	struct cpupm_notification *ms_handlers;
} cpupm_mach_state_t;

/*
 * Constants used by the Processor Device Notification handler
 * that identify what kind of change has occurred.
 */
#define	CPUPM_PPC_CHANGE_NOTIFICATION 0x80
#define	CPUPM_CST_CHANGE_NOTIFICATION 0x81
#define	CPUPM_TPC_CHANGE_NOTIFICATION 0x82

typedef void (*CPUPM_NOTIFY_HANDLER)(void *handle, uint32_t val,
    void *ctx);

typedef struct cpupm_notification {
	struct cpupm_notification	*nq_next;
	CPUPM_NOTIFY_HANDLER		nq_handler;
	void				*nq_ctx;
} cpupm_notification_t;

/*
 * If any states are added, then make sure to add them to
 * CPUPM_ALL_STATES.
 */
#define	CPUPM_NO_STATES		0x00
#define	CPUPM_P_STATES		0x01
#define	CPUPM_T_STATES		0x02
#define	CPUPM_C_STATES		0x04
#define	CPUPM_ALL_STATES	(CPUPM_P_STATES \
				| CPUPM_T_STATES \
				| CPUPM_C_STATES)

/*
 * An error in initializing any of the CPU PM results in disabling
 * CPU power management.
 */
#define	CPUPM_DISABLE() cpupm_disable(CPUPM_ALL_STATES)

#define	CPUPM_SPEED_HZ(unused, mhz) ((uint64_t)mhz * 1000000)

/*
 * Callbacks used for CPU power management.
 */
extern void (*cpupm_ppm_alloc_pstate_domains)(cpu_t *);
extern void (*cpupm_ppm_free_pstate_domains)(cpu_t *);
extern void (*cpupm_redefine_topspeed)(void *);
extern int (*cpupm_get_topspeed_callb)(void *);
extern void (*cpupm_set_topspeed_callb)(void *, int);

extern void cpupm_init(cpu_t *);
extern void cpupm_fini(cpu_t *);
extern void cpupm_start(cpu_t *);
extern void cpupm_stop(cpu_t *);
extern boolean_t cpupm_is_ready(cpu_t *);
extern boolean_t cpupm_is_enabled(uint32_t);
extern void cpupm_disable(uint32_t);
extern void cpupm_alloc_domains(cpu_t *, int);
extern void cpupm_free_domains(cpupm_state_domains_t **);
extern void cpupm_remove_domains(cpu_t *, int, cpupm_state_domains_t **);
extern void cpupm_alloc_ms_cstate(cpu_t *cp);
extern void cpupm_free_ms_cstate(cpu_t *cp);
extern void cpupm_state_change(cpu_t *, int, int);
extern id_t cpupm_plat_domain_id(cpu_t *cp, cpupm_dtype_t type);
extern uint_t cpupm_plat_state_enumerate(cpu_t *, cpupm_dtype_t,
    cpupm_state_t *);
extern int cpupm_plat_change_state(cpu_t *, cpupm_state_t *);
extern uint_t cpupm_get_speeds(cpu_t *, int **);
extern void cpupm_free_speeds(int *, uint_t);
extern boolean_t cpupm_power_ready(cpu_t *);
extern boolean_t cpupm_throttle_ready(cpu_t *);
extern boolean_t cpupm_cstate_ready(cpu_t *);
extern void cpupm_add_notify_handler(cpu_t *, CPUPM_NOTIFY_HANDLER, void *);
extern int cpupm_get_top_speed(cpu_t *);
extern void cpupm_idle_cstate_data(cma_c_state_t *, int);
extern void cpupm_wakeup_cstate_data(cma_c_state_t *, hrtime_t);
extern void cpupm_record_turbo_info(cpupm_mach_turbo_info_t *, uint32_t,
    uint32_t);
extern cpupm_mach_turbo_info_t *cpupm_turbo_init(cpu_t *);
extern void cpupm_turbo_fini(cpupm_mach_turbo_info_t *);

#ifdef __cplusplus
}
#endif

#endif	/* _CPUPM_MACH_H */
