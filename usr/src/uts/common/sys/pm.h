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

#ifndef	_SYS_PM_H
#define	_SYS_PM_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>

/*
 *	The following ioctls may not exist or may have a different
 *	interpretation in a future release.
 */

typedef enum {
	PM_SCHEDULE,		/* obsolete, not supported */
	PM_GET_IDLE_TIME,	/* obsolete, not supported  */
	PM_GET_NUM_CMPTS,	/* obsolete, not supported */
	PM_GET_THRESHOLD,	/* obsolete, not supported  */
	PM_SET_THRESHOLD,	/* obsolete */
	PM_GET_NORM_PWR,	/* obsolete */
	PM_SET_CUR_PWR,		/* obsolete */
	PM_GET_CUR_PWR,		/* obsolete */
	PM_GET_NUM_DEPS,	/* obsolete, not supported */
	PM_GET_DEP,		/* obsolete, not supported */
	PM_ADD_DEP,		/* obsolete */
	PM_REM_DEP,		/* obsolete, not supported */
	PM_REM_DEVICE,		/* obsolete, not supported */
	PM_REM_DEVICES,		/* obsolete */
	PM_REPARSE_PM_PROPS,	/* used only by ddivs pm tests */
	PM_DISABLE_AUTOPM,	/* obsolete */
	PM_REENABLE_AUTOPM,	/* obsolete */
	PM_SET_NORM_PWR,	/* obsolete, not supported */
	PM_SET_DEVICE_THRESHOLD,
	PM_GET_SYSTEM_THRESHOLD,
	PM_SET_SYSTEM_THRESHOLD,
	PM_START_PM,
	PM_STOP_PM,
	PM_RESET_PM,
	PM_GET_STATS,
	PM_GET_DEVICE_THRESHOLD,
	PM_GET_POWER_NAME,
	PM_GET_POWER_LEVELS,
	PM_GET_NUM_COMPONENTS,
	PM_GET_COMPONENT_NAME,
	PM_GET_NUM_POWER_LEVELS,
	PM_GET_STATE_CHANGE,
	PM_GET_STATE_CHANGE_WAIT,
	PM_DIRECT_PM,
	PM_RELEASE_DIRECT_PM,
	PM_DIRECT_NOTIFY,
	PM_DIRECT_NOTIFY_WAIT,
	PM_RESET_DEVICE_THRESHOLD,
	PM_GET_PM_STATE,
	PM_GET_DEVICE_TYPE,
	PM_SET_COMPONENT_THRESHOLDS,
	PM_GET_COMPONENT_THRESHOLDS,
	PM_IDLE_DOWN,
	PM_GET_DEVICE_THRESHOLD_BASIS,
	PM_SET_CURRENT_POWER,	/* replaces PM_SET_CUR_PWR */
	PM_GET_CURRENT_POWER,	/* replaces PM_GET_CUR_PWR */
	PM_GET_FULL_POWER,	/* replaces PM_GET_NORM_PWR */
	PM_ADD_DEPENDENT,	/* replaces PM_ADD_DEP */
	PM_GET_TIME_IDLE,	/* replaces PM_IDLE_TIME */
	PM_GET_DEFAULT_SYSTEM_THRESHOLD,
	PM_ADD_DEPENDENT_PROPERTY,
	PM_START_CPUPM,
	PM_START_CPUPM_EV,
	PM_START_CPUPM_POLL,
	PM_STOP_CPUPM,
	PM_GET_CPU_THRESHOLD,
	PM_SET_CPU_THRESHOLD,
	PM_GET_CPUPM_STATE,
	PM_ENABLE_S3,		/* allow pm to go to S3 state */
	PM_DISABLE_S3,		/* do not allow pm to go to S3 state */
	PM_ENTER_S3,		/* obsolete, not supported */
	PM_START_AUTOS3,
	PM_STOP_AUTOS3,
	PM_SEARCH_LIST,		/* search S3 enable/disable list */
	PM_GET_AUTOS3_STATE,
	PM_GET_S3_SUPPORT_STATE,
	PM_GET_CMD_NAME,
	PM_DISABLE_CPU_DEEP_IDLE,
	PM_ENABLE_CPU_DEEP_IDLE,
	PM_DEFAULT_CPU_DEEP_IDLE
} pm_cmds;

/*
 * Old name for these ioctls.
 */
#define	PM_GET_POWER		PM_GET_NORM_PWR
#define	PM_SET_POWER		PM_SET_CUR_PWR

/*
 * This structure is obsolete and will be removed in a later release
 */
typedef struct {
	caddr_t	who;		/* Device to configure */
	int	select;		/* Selects the component or dependent */
				/* of the device */
	int	level;		/* Power or threshold level */
	caddr_t dependent;	/* Buffer to hold name of dependent */
	int	size;		/* Size of dependent buffer */
} pm_request;

/*
 * This is the new struct that replaces pm_request
 */
typedef struct pm_req {
	char	*physpath;	/* physical path of device to configure */
				/* see libdevinfo(3) */
	int	component;	/* Selects the component of the device */
	int	value;		/* power level, threshold value, or count */
	void	*data;		/* command-dependent variable sized data */
	size_t	datasize;	/* Size of data buffer */
} pm_req_t;

/*
 * PM_SEARCH_LIST requires a list name, manufacturer and product name
 * Searches the named list for a matching tuple.
 * NOTE: This structure may be removed in a later release.
 */
typedef struct pm_searchargs {
	char	*pms_listname;		/* name of list to search */
	char	*pms_manufacturer;	/* 1st elment of tuple */
	char	*pms_product;		/* 2nd elment of tuple */
} pm_searchargs_t;

/*
 * Use these for PM_ADD_DEPENDENT and PM_ADD_DEPENDENT_PROPERTY
 */
#define	pmreq_keeper	physpath	/* keeper in the physpath field */
#define	pmreq_kept	data		/* kept in the data field */

/*
 * Possible values for the event field of pm_state_change below
 */
typedef enum {
	PSC_PENDING_CHANGE,	/* device needs to change, is blocked */
	PSC_HAS_CHANGED		/* device level has changed */
} psc_events;

#define	PSC_EVENT_LOST	0x4000	/* buffer overrun */
#define	PSC_ALL_LOWEST	0x8000	/* all devices at lowest power */

/*
 * Special value for power level fields in pm_state_change below
 */
#define	PM_LEVEL_UNKNOWN	-1	/* power level is unknown */

typedef struct pm_state_change {
	caddr_t	physpath;	/* Device which has changed state */
	int	component;	/* which component changed state */
#if defined(_BIG_ENDIAN)
	ushort_t flags;		/* PSC_EVENT_LOST, PSC_ALL_LOWEST */
	ushort_t event;		/* type of event */
#else
	ushort_t event;		/* type of event */
	ushort_t flags;		/* PSC_EVENT_LOST, PSC_ALL_LOWEST */
#endif
	time_t	timestamp;	/* time of state change */
	int	old_level;	/* power level changing from */
	int	new_level;	/* power level changing to */
	size_t	size;		/* size of buffer physpath points to */
} pm_state_change_t;

#ifdef _SYSCALL32

/* Kernel's view of ILP32 structure version. */

/*
 * This struct is obsolete and will be removed in a later release
 */
typedef struct {
	caddr32_t	who;	/* Device to configure */
	int		select;	/* Selects the component or dependent */
				/* of the device */
	int		level;	/* Power or threshold level */
	caddr32_t	dependent;	/* Buffer to hold name of */
					/* dependent */
	size32_t	size;	/* Size of dependent buffer */
} pm_request32;

typedef struct pm_req32 {
	caddr32_t physpath;	/* physical path of device to configure */
				/* see libdevinfo(3) */
	int	component;	/* selects the component of the device */
	int	value;		/* power level, threshold value, or count */
	caddr32_t data;		/* command-dependent variable sized data */
	size32_t datasize;	/* Size of data buffer */
} pm_req32_t;

typedef struct pm_state_change32 {
	caddr32_t	physpath;	/* Device which has changed state */
	int		component;	/* which component changed state */
#if defined(_BIG_ENDIAN)
	ushort_t	flags;		/* PSC_EVENT_LOST, PSC_ALL_LOWEST */
	ushort_t	event;		/* type of event */
#else
	ushort_t	event;		/* type of event */
	ushort_t	flags;		/* PSC_EVENT_LOST, PSC_ALL_LOWEST */
#endif
	time32_t	timestamp;	/* time of state change */
	int		old_level;	/* power level changing from */
	int		new_level;	/* power level changing to */
	size32_t	size;		/* size of buffer physpath points to */
} pm_state_change32_t;

typedef	struct pm_searchargs32_t {
	caddr32_t	pms_listname;
	caddr32_t	pms_manufacturer;
	caddr32_t	pms_product;
} pm_searchargs32_t;


#endif

/*
 * Return values from ioctl commands that return pm state info.
 */

typedef enum {
	PM_SYSTEM_PM_ENABLED,
	PM_SYSTEM_PM_DISABLED,
	PM_NO_PM_COMPONENTS,
	PM_CREATE_COMPONENTS,
	PM_AUTOPM,
	PM_DEFAULT_THRESHOLD,
	PM_DEVICE_THRESHOLD,
	PM_COMPONENT_THRESHOLD,
	PM_OLD_THRESHOLD,
	PM_DIRECTLY_MANAGED,
	PM_CPU_THRESHOLD,
	PM_CPU_PM_ENABLED,
	PM_CPU_PM_DISABLED,
	PM_CPU_PM_NOTSET,
	PM_AUTOS3_ENABLED,
	PM_AUTOS3_DISABLED,
	PM_S3_SUPPORT_ENABLED,
	PM_S3_SUPPORT_DISABLED
} pm_states;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PM_H */
