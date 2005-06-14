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

#ifndef	_PICLENVMOND_H
#define	_PICLENVMOND_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* debug flags */
#define	DEBUG		0x1	/* generic debug messages */
#define	EVENTS		0x2	/* only events related debug message */
#define	PTREE		0x4	/* messages relating to picltree search */
#define	SP_MONITOR	0x8	/* AC health monitoring messages only */
#define	CHASSIS_INFO	0x10	/* Chassis related debug information */
#define	PICLEVENTS	0x20	/* Display only PICL events received */

#define	PICL_NODE_CHASSIS	"chassis"
#define	PICL_NODE_CPU		"CPU"
#define	PICL_NODE_RTM		"RTM"
#define	PICL_PROP_CONF_FILE	"conf_name"
#define	TEMPERATURE_SENSOR_TYPE	(0x1u)

typedef enum {
	LOC_STATE_UNKNOWN = 0,
	LOC_STATE_EMPTY,
	LOC_STATE_DISCONNECTING,
	LOC_STATE_DISCONNECTED,
	LOC_STATE_CONNECTING,
	LOC_STATE_CONNECTED,
	FRU_STATE_UNKNOWN,
	FRU_STATE_UNCONFIGURING,
	FRU_STATE_UNCONFIGURED,
	FRU_STATE_CONFIGURING,
	FRU_STATE_CONFIGURED,
	FRU_COND_OK,
	FRU_COND_FAILING,
	FRU_COND_FAILED,
	FRU_COND_DEGRADED,
	FRU_COND_UNKNOWN,
	FRU_COND_TESTING
} env_state_event_t;

typedef enum {NO_COND_TIMEDWAIT = 0, COND_TIMEDWAIT, NO_WAIT} env_wait_state_t;

#define	NULLREAD	(int (*)(ptree_rarg_t *, void *))0
#define	NULLWRITE	(int (*)(ptree_warg_t *, const void *))0
#define	POLL_TIMEOUT	5000
#define	DEFAULT_FD	-1
#define	DEFAULT_SEQN	0xff

/* byte of pointer to signed integer */
#define	BYTE_0(_X)			(*((int8_t *)(_X) + 0))
#define	BYTE_1(_X)			(*((int8_t *)(_X) + 1))
#define	BYTE_2(_X)			(*((int8_t *)(_X) + 2))
#define	BYTE_3(_X)			(*((int8_t *)(_X) + 3))
#define	BYTE_4(_X)			(*((int8_t *)(_X) + 4))
#define	BYTE_5(_X)			(*((int8_t *)(_X) + 5))
#define	BYTE_6(_X)			(*((int8_t *)(_X) + 6))
#define	BYTE_7(_X)			(*((int8_t *)(_X) + 7))
#define	BYTE_8(_X)			(*((int8_t *)(_X) + 8))

#define	BIT_0(_X)			((_X) & 0x01)
#define	BIT_1(_X)			((_X) & 0x02)
#define	BIT_2(_X)			((_X) & 0x04)
#define	BIT_3(_X)			((_X) & 0x08)
#define	BIT_4(_X)			((_X) & 0x10)
#define	BIT_5(_X)			((_X) & 0x20)
#define	BIT_6(_X)			((_X) & 0x40)
#define	BIT_7(_X)			((_X) & 0x80)

#define	PICL_ADMINLOCK_DISABLED	"disabled"
#define	PICL_ADMINLOCK_ENABLED	"enabled"

#define	PTREE_INIT_PROPINFO_FAILED_MSG \
	gettext("SUNW_envmond:ptree_init_propinfo() failed, error = %d")
#define	PTREE_CREATE_AND_ADD_PROP_FAILED_MSG \
	gettext("SUNW_envmond: ptree_create_and_add_prop() failed error = %d")

#ifdef	__cplusplus
}
#endif

#endif	/* _PICLENVMOND_H */
