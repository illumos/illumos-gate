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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_LW8_IMPL_H
#define	_SYS_LW8_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * local driver defines and structures
 */

#define	LW8_DEFAULT_MAX_MBOX_WAIT_TIME	30

typedef struct lw8_event {
	int32_t		event_type;
} lw8_event_t;

/*
 * mailbox commands
 */
#define	LW8_MBOX_UPDATE_FW		0
#define	LW8_MBOX_GET_INFO		1
#define	LW8_MBOX_SET_CTL		2
#define	LW8_MBOX_GET_LED		3
#define	LW8_MBOX_SET_LED		4
#define	LW8_MBOX_GET_EVENTS		5
#define	LW8_MBOX_GET_NEXT_MSG		6
#define	LW8_MBOX_WDT_GET		7
#define	LW8_MBOX_WDT_SET		8

/*
 * mailbox events
 */
#define	LW8_EVENT_REQUESTED_SHUTDOWN	0
#define	LW8_EVENT_VOLTAGE_SHUTDOWN	1
#define	LW8_EVENT_TEMPERATURE_SHUTDOWN	2
#define	LW8_EVENT_FANFAIL_SHUTDOWN	3
#define	LW8_EVENT_NO_SCC_SHUTDOWN	4
#define	LW8_EVENT_NEW_LOG_MSG		5
#define	LW8_EVENT_SC_RESTARTED		6

/*
 * led requests
 */
#define	MAX_LEDS_PER_FRU 9
#define	MAX_FRUS 24

typedef struct lw8_get_led_payload {
	char	value[(3 * (MAX_FRUS - 1)) + MAX_LEDS_PER_FRU];
} lw8_get_led_payload_t;

typedef struct lw8_set_led_payload {
	char	offset;
	char	value;
} lw8_set_led_payload_t;

typedef struct {
	int   num; /* no. events requested and no. returned */
	int   level; /* level of events requested */
} lom_eventreq_t;

#define	MAX_EVENTS	128
#define	MAX_EVENT_STR	80

typedef struct {
	int   num; /* no. events requested and no. returned */
	int   level; /* level of events requested */
	char  string[MAX_EVENTS][MAX_EVENT_STR];
} lom_eventresp_t;

#define	MAX_MSG_STR	1012
typedef struct {
	int  level;		/* syslog msg level */
	int  msg_valid;		/* 1 if valid, 0 if not valid */
	int  num_remaining;	/* num of msg's left to retrieve after this */
	char msg[MAX_MSG_STR];	/* the message text */
} lw8_logmsg_t;

/*
 * LW8_MBOX_WDT_GET message: SC <-> Solaris
 *
 * SC and Solaris use this message to learn what its peer has
 * as their current state for these watchdog state-machine
 * variables.
 */
typedef struct {
	int	recovery_enabled;	/* 1/0 => {en,dis}abled */
	int	watchdog_enabled;	/* 1/0 => {en,dis}abled */
	int	timeout;		/* in seconds */
} lw8_get_wdt_t;

/*
 * LW8_MBOX_WDT_SET message: SC <- Solaris
 *
 * Solaris uses this to update the SC with the latest
 * 'value' for the specified 'property_id'.
 *
 * Eg, to specify that the watchdog state-machine is in
 * System Mode, <property_id, value> would be set to:
 *
 *     <LW8_WDT_PROP_MODE, LW8_PROP_MODE_SWDT>
 */
typedef struct {
	int	property_id;
	int	value;
} lw8_set_wdt_t;

/* choices for 'property_id' field: */
#define	LW8_WDT_PROP_RECOV	0	/* recovery_enabled */
#define	LW8_WDT_PROP_WDT	1	/* watchdog_enabled */
#define	LW8_WDT_PROP_TO		2	/* timeout duration */
#define	LW8_WDT_PROP_MODE	3	/* mode: AWDT or SWDT */

/*
 * choices for 'value' field (for the specified 'property_id'):
 */
/* LW8_WDT_PROP_RECOV */
#define	LW8_PROP_RECOV_ENABLED		1
#define	LW8_PROP_RECOV_DISABLED		0

/* LW8_WDT_PROP_WDT */
#define	LW8_PROP_WDT_ENABLED		1
#define	LW8_PROP_WDT_DISABLED		0

/* LW8_WDT_PROP_TO:    integral number of seconds */

/* LW8_WDT_PROP_MODE */
#define	LW8_PROP_MODE_AWDT	1	/* App wdog mode */
#define	LW8_PROP_MODE_SWDT	0	/* System wdog mode */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_LW8_IMPL_H */
