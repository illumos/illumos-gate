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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PICL_WATCHDOG_H
#define	_PICL_WATCHDOG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <libintl.h>
#include <sys/inttypes.h>
#include <smclib.h>

#define	WD_DEBUG0(fmt) \
	if (wd_debug) { \
		syslog(LOG_DEBUG, fmt);	\
	}
#define	WD_DEBUG1(fmt, d1) \
	if (wd_debug) { \
		syslog(LOG_DEBUG, fmt, d1); \
	}

/* environment variable defs */
#define	WATCHDOG_DEBUG			"SUNW_WATCHDOG_DEBUG"

/* debug flags */
#define	WD_GENERAL_MSGS			0x1
#define	WD_TIME_DEBUG			0x2

/* tunables */
#define	WD_DEFAULT_THREAD_PRIORITY	0
#define	WD_POLL_TIMEOUT			10000	/* 10 sec */
#define	WD_PAT_TIME			5000

/* constants */
#define	WD_SET_CMD_DATA_LEN		6	/* size for set cmd */
#define	PICL_WD_PROPVAL_MAX		20
#define	SUPER_USER			0

/* watchdog status */
#define	WD_ARMED			0x1	/* watchdog is running */
#define	WD_EXPIRED			0x2	/* watchdog is expired */
#define	WD_DISARMED			0x4	/* watchdog is stopped */

/* patting status */
#define	WD_RESET			0x8	/* client chose to pat. */
#define	WD_NORESET			0x0	/* pat state initial value. */

/* auto pat feature for SMC f/w */
#define	ENABLE_AUTO_PAT			0x1
#define	DISABLE_AUTO_PAT		0x0

/* flags used to track user actions */
#define	USER_ARMED_WD			0x1	/* user armed the watchdog */
#define	USER_ARMED_PAT_WD		0x2	/* debug feature */
#define	USER_PAT_WD			0x3	/* debug feature */
#define	USER_DISARMED_WD		0x4	/* user disarmed watchdog */

/* bit masks */
#define	WD_ACTION_NONE1			0x30	/* action none with interrupt */
#define	WD_ACTION_NONE2			0x00	/* no action */
#define	WD_ACTION_HARD_RESET		0x01	/* hard reset */
#define	WD_ACTION_HEALTHY_DOWN_HOST	0x50	/* dont put bridge in reset */
#define	WD_ACTION_HEALTHY_DOWN_SAT	0x40	/* healthy down, bridge reset */
#define	WD_USEFLAG_OS			0x04	/* set os as user of wd */
#define	WD_XPR_FLG_CLR_OS		0x10	/* to clear sms/os expiry bit */
#define	WD_WD_RUNNING			0x40	/* to check wd running or not */
#define	WD_ENABLE_AUTO_PAT		0x20	/* enable auto pat feature */

/* timer max values */
#define	WD_MAX_L2			0xff	/* 255 sec */
#define	WD_MAX_L1   			0xffff	/* 109.22 min */
#define	WD_L1_RESOLUTION		100	/* 100ms/cnt */
#define	WD_L2_RESOLUTION		1000 	/* 1000ms/cnt */

#define	WD1				0x1	/* wd level 1 */
#define	WD2				0x2	/* wd level 2 */
#define	WD1_2				0x3	/* wd level 1 and level 2 */
#define	WD_MAX_SEQN			255

/* PICL node names */
#define	PICL_NODE_CHASSIS		"chassis"
#define	PICL_NODE_SYSMGMT		"sysmgmt"
#define	PICL_NODE_WD_CONTROLLER		"watchdog"
#define	PICL_NODE_WD_L1			"watchdog-level1"
#define	PICL_NODE_WD_L2			"watchdog-level2"

/* debug value for wd_op */
#define	WD_ARM_PAT			"arm-pat"

/* HEALTHY# status */
#define	WD_HEALTHY_DOWN			0x0
#define	WD_HEALTHY_UP			0x1

#define	SHUTDOWN_CMD			"shutdown -y -i 6 -g 60 watchdog "\
					"expired.. rebooting"
/* watchdog config file variables */
#define	PICL_CONFIG_DIR			"/etc/picl/config"
#define	WD_CONF_FILE			"watchdog.conf"
#define	WD_CONF_MAXSIZE			100
#define	WD_DELIMETER			" \t\n"

/* The following values can be tuned using config file */
#define	WD_PAT_THREAD_PRIORITY		"wd_thread_priority"
#define	WD_PATTING_TIME			"wd_pat_time"
#define	WD_ENABLE			"watchdog-enable"

#define	WD_HOST				1
#define	WD_STANDALONE			2

/* HEALTHY# bitmask */
#define	IS_HEALTHY			0x01

#define	DEFAULT_SEQN			15
#define	DEFAULT_FD			-1
#define	SMC_NODE			"/dev/ctsmc"

#define	WD_REGISTER_LEN			8

typedef struct {
	/* properties values */
	uint8_t 	wd1_run_state;	/* L1 status */
	uint8_t 	wd1_action;	/* L1 action */
	uint8_t 	wd2_run_state;	/* L2 status */
	uint8_t 	wd2_action;	/* L2 action */
	int32_t		wd1_timeout;	/* L1 timeout */
	int32_t		wd2_timeout;	/* L2 timeout */
	uchar_t		wd_pat_state;	/* pat state */
	boolean_t 	reboot_action;	/* is reboot action set */
	boolean_t 	is_host;	/* is a host or standalone CPU */

	/* Cache for PICL handles */
	picl_nodehdl_t	wd_ctrl_nodehdl;	/* watchdog controller */
						/* prop handle for op  */
	picl_prophdl_t	wd_ops_hdl;

	picl_prophdl_t	wd1_state_hdl;
	picl_prophdl_t	wd1_timeout_hdl;
	picl_prophdl_t	wd1_action_hdl;
	picl_nodehdl_t	wd1_nodehdl;		/* L1 node handle */

	picl_prophdl_t	wd2_state_hdl;
	picl_prophdl_t	wd2_timeout_hdl;
	picl_prophdl_t	wd2_action_hdl;
	picl_nodehdl_t	wd2_nodehdl;		/* L2 node handle */
} wd_data_t;

/* structure to hold watchdog status */
typedef struct {
	int		present_state;
	uint8_t		action1;
	uint8_t		action2;
	uint8_t		timeout1[2];
	uint8_t		timeout2;
	uint8_t		present_t1[2];
} wd_state_t;

/* Error messages */
#define	WD_PICL_NOSPACE	\
	gettext("SUNW_piclwatchdog: Error in memory allocation")
#define	WD_PICL_REG_ERR	\
	gettext("SUNW_piclwatchdog: Failed to register with picl framework,"\
	" error = %d")
#define	WD_PICL_SMC_OPEN_ERR \
	gettext("SUNW_piclwatchdog: Error in opening SMC drv")
#define	WD_PICL_EXCLUSIVE_ACCESS_ERR \
	gettext("SUNW_piclwatchdog: Error in getting exclusive access "\
	"for watchdog commands")
#define	WD_PICL_THREAD_CREATE_FAILED \
	gettext("SUNW_piclwatchdog: Error in creating %s thread")
#define	WD_PICL_PROP_INIT_ERR \
	gettext("SUNW_piclwatchdog: ptree prop init call failed:%d")
#define	WD_NODE_INIT_ERR \
	gettext("SUNW_piclwatchdog: Error in creating watchdog nodes(%d):%d")
#define	WD_PICL_GET_STAT_ERR \
	gettext("SUNW_piclwatchdog: Error in getting the watchdog status")
#define	WD_PICL_GET_ERR	\
	gettext("SUNW_piclwatchdog: Error in getting watchdog status,"\
	" error = %d")
#define	WD_PICL_PAT_ERR \
	gettext("SUNW_piclwatchdog: Error in patting the watchdog"\
	" error = %d")
#define	WD_PICL_START_ERR \
	gettext("SUNW_piclwatchdog: Error in starting the watchdog, error = %d")
#define	WD_PICL_STOP_ERR \
	gettext("SUNW_piclwatchdog: Error in stopping the watchdog,"\
	" error = %d")
#define	WD_PICL_SET_ATTR_FAILED	\
	gettext("SUNW_piclwatchdog: Error in setting attributes for a stream")
#define	WD_PICL_RT_THRD_FAIL \
	gettext("SUNW_piclwatchdog: Error in creating real time thread")
#define	WD_PICL_RT_THRD_NO_PERM_ERR \
	gettext("SUNW_piclwatchdog: No perm to change the priority of thread")
#define	WD_PICL_NO_WD_ERR \
	gettext("SUNW_piclwatchdog: Watchdog is not running")
#define	WD_PICL_WD1_RUNNING_ERR	\
	gettext("SUNW_piclwatchdog: Disarm the Watchdog level 1")
#define	WD_PICL_WD2_RUNNING_ERR	\
	gettext("SUNW_piclwatchdog: Disarm the Watchdog level 2")
#define	WD_PICL_SMC_READ_ERR \
	gettext("SUNW_piclwatchdog: Error in reading from SMC")
#define	WD_PICL_SMC_WRITE_ERR \
	gettext("SUNW_piclwatchdog: Error in writing to SMC")
#define	WD_NO_ROOT_PERM	\
	gettext("SUNW_piclwatchdog: Root perm are reqd to perform this op.")
#define	WD_PICL_POLL_ERR \
	gettext("SUNW_piclwatchdog: Error in poll system call")
#define	WD_PICL_INVALID_T1 \
	gettext("SUNW_piclwatchdog: Invalid timeout value for wd level 1")
#define	WD_PICL_INVALID_T2 \
	gettext("SUNW_piclwatchdog: Invalid timeout value for wd level 2")
#define	WD_PICL_TMOUT_LV1_LV2_SETTO_0 \
	gettext("SUNW_piclwatchdog: Invalid timeout val for wd level 1 & 2")
#define	WD_PICL_INVALID_ACTION1 \
	gettext("SUNW_piclwatchdog: Invalid action for level one")
#define	WD_PICL_INVALID_ACTION2	\
	gettext("SUNW_piclwatchdog: Invalid action for level two")
#define	WD_PICL_CLEAR_EXCL_ERR \
	gettext("SUNW_piclwatchdog: Error in clearing exclusive "\
			"access for watchdog commands")
#define	WD_PICL_POST_EVENT_ERR \
	gettext("SUNW_piclwatchdog: Error in posting wd expiry event,"\
	" error = %d")
#define	WD_PICL_COND_SIGNAL_ERR	\
	gettext("SUNW_piclwatchdog: Error in cond_signal")
#define	WD_PICL_IS_NOT_SUPPORTED \
	gettext("SUNW_piclwatchdog: This feature is not supported")
#define	WD_PICL_TRY_PAT_ERR \
	gettext("SUNW_piclwatchdog: OS is already patting the watchdog")
#define	WD_PICL_GET_TIMEOUT_ERR	\
	gettext("SUNW_piclwatchdog: Error in getting the timeout values")
#define	WD_PICL_ARM_PAT_ERR \
	gettext("SUNW_piclwatchdog: Illegal timeout values for arm-pat op")
#define	WD_PICL_PERM_DENIED \
	gettext("SUNW_piclwatchdog: This client is not the owner of watchdog")
#define	WD_PICL_PAT_TIME_ERR \
	gettext("SUNW_piclwatchdog: Negative value for pat_time \
	is not allowed")
#define	WD_PICL_STATE_INVALID \
	gettext("SUNW_piclwatchdog: WD operations not allowed while "\
	"chassis state is configuring")
#define	WD_HEALTHY_ERR \
	gettext("SUNW_piclwatchdog: Cannot arm the watchdog, "\
	"action already taken")
#define	WD_GET_OWN_FAILED \
	gettext("SUNW_piclwatchdog: Error in finding active owner of watchdog,"\
	" error = %d")
#define	WD_NVLIST_ERR \
	gettext("SUNW_piclwatchdog: Error in posting watchdog event"\
	"(nvlist error), error = %d")
#define	WD_GET_HEALTH_ERR \
	gettext("SUNW_piclwatchdog: Error in getting HEALTHY# status")
#define	WD_UPDATE_STATE_ERR \
	gettext("SUNW_piclwatchdog: Error in updating watchdog state,"\
	"error = %d")
#define	WD_WD1_EXPIRED \
	gettext("SUNW_piclwatchdog: watchdog level 1 expired")
#ifdef	__cplusplus
}
#endif

#endif	/* _PICL_WATCHDOG_H */
