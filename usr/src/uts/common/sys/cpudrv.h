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

#ifndef _SYS_CPUDRV_H
#define	_SYS_CPUDRV_H

#include <sys/promif.h>
#include <sys/cpuvar.h>
#include <sys/taskq.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

/*
 * CPU power management data
 */
/*
 * Data related to a particular speed.
 *
 * All per speed data nodes for a CPU are linked together using down_spd.
 * The link list is ordered with first node containing data for
 * normal (maximum) speed. up_spd points to the next speed up. Currently
 * all up_spd's point to the normal speed but this can be changed in future.
 * quant_cnt is the number of ticks when monitoring system will be called
 * next. There are different quant_cnt for different speeds.
 *
 * Note that 'speed' has different meaning depending upon the platform.
 * On SPARC, the speed is really a divisor of the maximum speed (e.g., a speed
 * of 2 means that it's 1/2 the maximum speed). On x86, speed is a processor
 * frequency.
 */
typedef struct cpudrv_pm_spd {
	uint_t			speed;		/* platform dependent notion */
	uint_t			quant_cnt;	/* quantum count in ticks */
	struct cpudrv_pm_spd	*down_spd;	/* ptr to next speed down */
	struct cpudrv_pm_spd	*up_spd;	/* ptr to next speed up */
	uint_t			idle_hwm;	/* down if idle thread >= hwm */
	uint_t			idle_lwm;	/* up if idle thread < lwm */
	uint_t			idle_bhwm_cnt;	/* # of iters idle is < hwm */
	uint_t			idle_blwm_cnt;	/* # of iters idle is < lwm */
	uint_t			user_hwm;	/* up if user thread > hwm */
	int			user_lwm;	/* down if user thread <= lwm */
	int			pm_level;	/* power level for framework */
} cpudrv_pm_spd_t;

/*
 * Power management data
 */
typedef struct cpudrv_pm {
	cpudrv_pm_spd_t	*head_spd;	/* ptr to head of speed */
	cpudrv_pm_spd_t	*cur_spd;	/* ptr to current speed */
	uint_t		num_spd;	/* number of speeds */
	hrtime_t	lastquan_mstate[NCMSTATES]; /* last quantum's mstate */
	clock_t		lastquan_ticks;	/* last quantum's clock tick */
	int		pm_busycnt;	/* pm_busy_component() count  */
	ddi_taskq_t	*tq;		/* taskq handler for CPU monitor */
	timeout_id_t	timeout_id;	/* cpudrv_monitor()'s timeout_id */
	int		timeout_count;	/* count dispatched timeouts */
	kmutex_t	timeout_lock;	/* protect timeout_count */
	kcondvar_t	timeout_cv;	/* wait on timeout_count change */
#if defined(__x86)
	kthread_t	*pm_governor_thread; /* governor thread */
	cpudrv_pm_spd_t	*top_spd;	/* ptr to effective head speed */
#endif
	boolean_t	pm_started;	/* PM really started */
} cpudrv_pm_t;

/*
 * Idle & user threads water marks in percentage
 */
#if defined(__x86)
#define	CPUDRV_IDLE_HWM		85	/* idle high water mark */
#define	CPUDRV_IDLE_LWM		70	/* idle low water mark */
#define	CPUDRV_IDLE_BLWM_CNT_MAX	1    /* # of iters idle can be < lwm */
#define	CPUDRV_IDLE_BHWM_CNT_MAX	1    /* # of iters idle can be < hwm */
#else
#define	CPUDRV_IDLE_HWM		98	/* idle high water mark */
#define	CPUDRV_IDLE_LWM		8	/* idle low water mark */
#define	CPUDRV_IDLE_BLWM_CNT_MAX	2    /* # of iters idle can be < lwm */
#define	CPUDRV_IDLE_BHWM_CNT_MAX	2    /* # of iters idle can be < hwm */
#endif
#define	CPUDRV_USER_HWM		20	/* user high water mark */
#define	CPUDRV_IDLE_BUF_ZONE		4    /* buffer zone when going down */


/*
 * Maximums for creating 'pm-components' property
 */
#define	CPUDRV_COMP_MAX_DIG	4	/* max digits in power level */
					/* or divisor */
#define	CPUDRV_COMP_MAX_VAL	9999	/* max value in above digits */

/*
 * Component number for calls to PM framework
 */
#define	CPUDRV_COMP_NUM	0	/* first component is 0 */

/*
 * Quantum counts for normal and other clock speeds in terms of ticks.
 *
 * In determining the quantum count, we need to balance two opposing factors:
 *
 *	1) Minimal delay when user start using the CPU that is in low
 *	power mode -- requires that we monitor more frequently,
 *
 *	2) Extra code executed because of frequent monitoring -- requires
 *	that we monitor less frequently.
 *
 * We reach a tradeoff between these two requirements by monitoring
 * more frequently when we are in low speed mode (CPUDRV_QUANT_CNT_OTHR)
 * so we can bring the CPU up without user noticing it. Moreover, at low
 * speed we are not using CPU much so extra code execution should be fine.
 * Since we are in no hurry to bring CPU down and at normal speed and we
 * might really be using the CPU fully, we monitor less frequently
 * (CPUDRV_QUANT_CNT_NORMAL).
 */
#if defined(__x86)
#define	CPUDRV_QUANT_CNT_NORMAL	(hz * 1)	/* 1 sec */
#else
#define	CPUDRV_QUANT_CNT_NORMAL	(hz * 5)	/* 5 sec */
#endif
#define	CPUDRV_QUANT_CNT_OTHR	(hz * 1)	/* 1 sec */

/*
 * Taskq parameters
 */
#define	CPUDRV_TASKQ_THREADS		1    /* # threads to run CPU monitor */
#define	CPUDRV_TASKQ_MIN		2	/* min # of taskq entries */
#define	CPUDRV_TASKQ_MAX		2	/* max # of taskq entries */


/*
 * Device driver state structure
 */
typedef struct cpudrv_devstate {
	dev_info_t	*dip;		/* devinfo handle */
	cpu_t		*cp;		/* CPU data for this node */
	processorid_t	cpu_id;		/* CPU number for this node */
	cpudrv_pm_t	cpudrv_pm;	/* power management data */
	kmutex_t	lock;		/* protects state struct */
} cpudrv_devstate_t;

extern void	*cpudrv_state;
extern boolean_t cpudrv_enabled;

/*
 * Debugging definitions
 */
#ifdef	DEBUG
#define	D_INIT			0x00000001
#define	D_FINI			0x00000002
#define	D_ATTACH		0x00000004
#define	D_DETACH		0x00000008
#define	D_POWER			0x00000010
#define	D_PM_INIT		0x00000020
#define	D_PM_FREE		0x00000040
#define	D_PM_COMP_CREATE	0x00000080
#define	D_PM_MONITOR		0x00000100
#define	D_PM_MONITOR_VERBOSE	0x00000200
#define	D_PM_MONITOR_DELAY	0x00000400

extern uint_t	cpudrv_debug;

#define	_PRINTF prom_printf
#define	DPRINTF(flag, args)	if (cpudrv_debug & flag) _PRINTF args;
#else
#define	DPRINTF(flag, args)
#endif /* DEBUG */

extern int cpudrv_change_speed(cpudrv_devstate_t *, cpudrv_pm_spd_t *);
extern boolean_t cpudrv_get_cpu_id(dev_info_t *, processorid_t *);
extern boolean_t cpudrv_is_governor_thread(cpudrv_pm_t *);
extern boolean_t cpudrv_mach_init(cpudrv_devstate_t *);
extern boolean_t cpudrv_mach_fini(cpudrv_devstate_t *);
extern boolean_t cpudrv_power_ready(cpu_t *);
extern boolean_t cpudrv_is_enabled(cpudrv_devstate_t *);
extern void cpudrv_set_supp_freqs(cpudrv_devstate_t *);
extern int cpudrv_get_cpu(cpudrv_devstate_t *);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_CPUDRV_H */
