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
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_SGEVENTS_H
#define	_SYS_SGEVENTS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * sgevents.h - Serengeti Events defintions
 *
 * This header file contains the common definitions and macros for the
 * events support on the Serengeti platform.
 */

/*
 * Serengeti Events Payloads (events are defined in sgsbbc_mailbox.h)
 */

/*
 * there are a class of events which are consider generic. They all have
 * the same msg_type and payload.  There is a detail that comes with it to
 * let the client know what actualy happened. This can be found in the
 * event_details as defined below
 */


#define	SG_EVT_BOARD_ABSENT		0x10
#define	SG_EVT_BOARD_PRESENT		0x11
#define	SG_EVT_UNASSIGN			0x20
#define	SG_EVT_ASSIGN			0x21
#define	SG_EVT_UNAVAILABLE		0x30
#define	SG_EVT_AVAILABLE		0x31
#define	SG_EVT_POWER_OFF		0x40
#define	SG_EVT_POWER_ON			0x41
#define	SG_EVT_PASSED_TEST		0x50
#define	SG_EVT_FAILED_TEST		0x51


/*
 * Miscallaneous defintions
 */

/* Payload of ENV event */
#define	SC_EVENT_FAN		0x4
#define	SC_EVENT_ENV		0x7

/* Payload of PANIC_SHUTDOWN event */
#define	SC_EVENT_PANIC_ENV		0x1
#define	SC_EVENT_PANIC_KEYSWITCH	0x2


/*
 * Generic event payload.
 */
typedef struct {
	int node;		/* wildcat node number */
	int slot;		/* Slot number for this event */
	uint64_t parent_hdl;	/* Parent fru handle */
	uint64_t child_hdl;	/* Child fru handle */
	int event_details;
} sg_system_fru_descriptor_t;


/*
 * Domain State event payload.
 *
 * Possible values for this are defined in serengeti.h (SG_KEY_POSN_XXX)
 */
typedef int	sg_event_key_position_t;


/*
 * Environmental event payloads.
 */
typedef struct sg_event_env_changed {
	int32_t		event_type;

} sg_event_env_changed_t;

typedef struct sg_event_fan_status {
	int32_t		event_type;
	int32_t		node_id;
	int32_t		slot_number;
	int32_t		fan_speed;

} sg_event_fan_status_t;


/*
 * Panic Shutdown event payload.
 */
typedef int	sg_panic_shutdown_t;


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SGEVENTS_H */
