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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _UTIL_H
#define	_UTIL_H

#include <dhcpagent_ipc.h>
#include <libdlwlan.h>
#include <libnwam.h>
#include <pthread.h>
#include <string.h>
#include <sys/note.h>
#include <sys/time.h>
#include <sys/zone.h>
#include <syslog.h>

#include "events.h"
#include "llp.h"
#include "ncu.h"

/*
 * A few functions here from files other than util.c, saves having
 * .h files for one or two functions.
 */

#define	OUR_FMRI				NWAM_FMRI
#define	OUR_PG					NWAM_PG
#define	OUR_DEBUG_PROP_NAME			"debug"
#define	OUR_AUTOCONF_PROP_NAME			"autoconf"
#define	OUR_STRICT_BSSID_PROP_NAME		"strict_bssid"
#define	OUR_ACTIVE_NCP_PROP_NAME		NWAM_PROP_ACTIVE_NCP
#define	OUR_CONDITION_CHECK_INTERVAL_PROP_NAME	"condition_check_interval"
#define	OUR_WIRELESS_SCAN_INTERVAL_PROP_NAME	"scan_interval"
#define	OUR_WIRELESS_SCAN_LEVEL_PROP_NAME	"scan_level"
#define	OUR_NCU_WAIT_TIME_PROP_NAME		"ncu_wait_time"
#define	OUR_VERSION_PROP_NAME			"version"
#define	NET_LOC_FMRI				"svc:/network/location:default"
#define	NET_LOC_PG				"location"
#define	NET_LOC_SELECTED_PROP			"selected"

#define	NSEC_TO_SEC(nsec)	(nsec) / (long)NANOSEC
#define	NSEC_TO_FRACNSEC(nsec)	(nsec) % (long)NANOSEC
#define	SEC_TO_NSEC(sec)	(sec) * (long)NANOSEC

extern boolean_t debug;
extern boolean_t shutting_down;

/* logging.c: log support functions */
extern void nlog(int, const char *, ...);
extern void pfail(const char *fmt, ...);
extern int syslog_stack(uintptr_t addr, int sig, void *arg);

/* door_if.c: door interface functions */
extern void nwamd_door_init(void);
extern void nwamd_door_fini(void);

/* util.c: utility & ipc functions */
extern int nwamd_start_childv(const char *, const char * const *);
extern boolean_t nwamd_link_belongs_to_this_zone(const char *);
extern void nwamd_to_root(void);
extern void nwamd_from_root(void);
extern void nwamd_drop_unneeded_privs(void);
extern void nwamd_escalate_privs(void);

/* SCF helper functions */
extern int nwamd_lookup_boolean_property(const char *, const char *,
    const char *, boolean_t *);
extern int nwamd_lookup_count_property(const char *, const char *, const char *,
    uint64_t *);
extern int nwamd_lookup_string_property(const char *, const char *,
    const char *, char *, size_t);

extern int nwamd_set_count_property(const char *, const char *, const char *,
    uint64_t);
extern int nwamd_set_string_property(const char *, const char *, const char *,
    const char *);

extern int nwamd_delete_scf_property(const char *, const char *, const char *);

#endif /* _UTIL_H */
