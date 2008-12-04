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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _VARIABLES_H
#define	_VARIABLES_H

#include <libdlwlan.h>
#include <sys/zone.h>

extern struct np_event *equeue;

extern pthread_mutex_t machine_lock;
extern pthread_mutex_t queue_mutex;
extern pthread_cond_t queue_cond;
extern pthread_t routing, scan;

extern llp_t *link_layer_profile;

extern sigset_t original_sigmask;
extern pid_t ppid;

extern boolean_t shutting_down;

extern uint32_t timer_expire;

extern uint_t wlan_scan_interval;
extern dladm_wlan_strength_t wireless_scan_level;
extern boolean_t strict_bssid;

extern uint_t door_idle_time;

extern const char *OUR_FMRI;
extern const char *OUR_PG;

extern boolean_t debug;

extern char zonename[ZONENAME_MAX];

#endif /* _VARIABLES_H */
