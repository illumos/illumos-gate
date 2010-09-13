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
 * Copyright 2001 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_LW8_H
#define	_SYS_LW8_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * subset of ioctl commands from PSARC 2000/019
 */

#define	LOMIOCALCTL		_IOW('a', 4, lom_aldata_t)
#define	LOMIOCALSTATE		_IOWR('a', 5, lom_aldata_t)
#define	LOMIOCFLEDSTATE		_IOR('a', 24, lom_fled_info_t)
#define	LOMIOCINFO		_IOR('a', 25, lom_info_t)
#define	LOMIOCINFO2		_IOWR('a', 46, lom2_info_t)
#define	LOMIOCCTL		_IOW('a', 27, lom_ctl_t)
#define	LOMIOCCTL2		_IOW('a', 40, lom_ctl2_t)
#define	LOMIOCPROG		_IOWR('a', 28, lom_prog_t)
#define	LOMIOCWTMON		_IOWR('a', 2, int)
#define	LOMIOCMREAD		_IOR('a', 33, lom_mprog_t)
#define	LOMIOCEVENTLOG2		_IOWR('a', 45, lom_eventlog2_t)

#define	LOM_SERIAL_EVENTS_ON	0x100
#define	LOM_SERIAL_EVENTS_OFF	0x200
#define	LOM_SERIAL_EVENTS_DEF 	0x300

typedef struct {
	int alarm_no;
	int state;
} lom_aldata_t;

typedef struct {
	int on;
} lom_fled_info_t;

typedef struct {
	char ser_char;
	char pad1[7];
	int fault_led;
	int pad2[2];
} lom_ctl_t;

typedef struct {
	char escape_chars[6];
	char pad1[2];
	int serial_events;
} lom_ctl2_t;

typedef struct {
	int pad1[4];
	int config;
	int pad2[8];
} lom_mprog_t;

typedef struct {
	char ser_char;
	char pad1[7];
	int fver;
	int fchksum;
	int prod_rev;
	char prod_id[12];
	int pad2[1];
} lom_info_t;

typedef struct {
	char escape_chars[6];
	char pad1[2];
	int serial_events;
	int pad2[1];
	int fver;
	int fchksum;
	int prod_rev;
	char prod_id[12];
	int serial_config;
	int baud_rate;
	int serial_hw_config;
	int phone_home_config;
	char phone_home_script[128];
	int pad3[16];
} lom2_info_t;

typedef struct {
	int index;	/* bit 0x8000 should be set if last buffer */
	uint8_t data[0x400];
	int size;
} lom_prog_t;

#define	MAX_EVENTS	128
#define	MAX_EVENT_STR	80

typedef struct {
	int   num; /* no. events requested and no. returned */
	int   level; /* level of events requested */
	int   pad1[MAX_EVENTS];
	char  string[MAX_EVENTS][MAX_EVENT_STR];
	int   pad2[MAX_EVENTS];
} lom_eventlog2_t;

/*
 * Project private ioctl commands - used by lw8 picl frutree plugin only
 */

#define	LOMIOCGETLED		_IOWR('a', 100, lom_get_led_t)
#define	LOMIOCSETLED		_IOWR('a', 101, lom_set_led_t)

#define	MAX_ID_LEN 16
#define	MAX_LOCATION_LEN 16
#define	MAX_COLOR_LEN 16

#define	LOM_LED_STATUS_OFF	0
#define	LOM_LED_STATUS_ON	1
#define	LOM_LED_STATUS_FLASHING	2
#define	LOM_LED_STATUS_BLINKING	3

#define	LOM_LED_POSITION_FRU		0
#define	LOM_LED_POSITION_LOCATION	1

typedef struct {
	char    location[MAX_LOCATION_LEN];
	char	id[MAX_ID_LEN];
	int 	status;
	int	position;
	char	color[MAX_COLOR_LEN];
	char	next_id[MAX_ID_LEN];
} lom_get_led_t;

typedef struct {
	char    location[MAX_LOCATION_LEN];
	char	id[MAX_ID_LEN];
	int 	status;
} lom_set_led_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_LW8_H */
