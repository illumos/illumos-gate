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

#ifndef	_PICLDR_H
#define	_PICLDR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum picl_smc_event {
	NO_EVENT = 0,
	TEMPERATURE_SENSOR_EVENT,
	CPU_NODE_STATE_CHANGE_NOTIFICATION,
	CHANGE_CPCI_STATE,	/* request to config/unconfig cpci i/f */
	CHANGE_CPU_NODE_STATE,	/* request on online/offline node */
	SMC_LOCAL_EVENT
} picl_smc_event_t;

#define	SMC_NODE				"/dev/ctsmc"
#define	SMC_BMC_ADDR				0x20
#define	CPU_NODE_STATE_ONLINE			1
#define	CPU_NODE_STATE_OFFLINE			0

/* event messages */
#define	EVENT_MSG_AC_STATE_CHANGE		0xf5
#define	EVENT_MSG_CHANGE_CPCI_STATE		0x65
#define	EVENT_MSG_CHANGE_CPU_NODE_STATE		0x62
#define	EVENT_MSG_ASYNC_EVENT_NOTIFICATION	0x82
#define	MSG_GET_CPU_NODE_STATE			0x61
#define	SMC_LOCAL_EVENT_BRIDGE_IN_RESET		0x00
#define	SMC_LOCAL_EVENT_BRIDGE_OUT_OF_RESET	0x01
#define	SMC_LOCAL_EVENT_LATCH_OPENED		0x06

#define	CPCI_STATE_OFFLINE			0
#define	CPCI_STATE_ONLINE			1
#define	SATCPU_STATE_ONLINE			0x7
#define	SATCPU_STATE_OFFLINE			0x8
#define	HEALTHY_ASSERT				1
#define	HEALTHY_DEASSERT			2

#define	SMC_MASTER_RW_CMD			0x90
#define	ENV_CONFIG_FILE "/usr/platform/%s/lib/picl/plugins/envmond.conf"
#define	RECORD_MAXSIZE				(256)
#define	RECORD_WHITESPACE			(": \t")
#define	SERVICE_PROCESSOR			"alarmcard"

/* packet lengths */
#define	ENV_RTM_PKT_LEN				3
#define	ENV_SET_GLOBAL_PKT_LEN			2
#define	ENV_SENSOR_EV_ENABLE_PKT_LEN		2
#define	ENV_IPMI_SMC_ENABLE_PKT_LEN		3

/* rtm pkt data */
#define	ENV_RTM_BUS_ID				7
#define	ENV_RTM_SLAVE_ADDR			0xa0
#define	ENV_RTM_READ_SIZE			0xa

/* global enables data */
#define	ENV_IPMI_ENABLE_MASK			0x10
#define	ENV_IPMI_DISABLE_MASK			0xef
#define	ENV_SENSOR_ENABLE_MASK			0xfb
#define	ENV_SENSOR_DISABLE_MASK			0x04

#ifdef	__cplusplus
}
#endif

#endif	/* _PICLDR_H */
