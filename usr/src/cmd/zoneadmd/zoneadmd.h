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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc. All rights reserved.
 * Copyright 2014, Joyent, Inc. All rights reserved.
 */

#ifndef	_ZONEADMD_H
#define	_ZONEADMD_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <libdladm.h>

/*
 * Multi-threaded programs should avoid MT-unsafe library calls (i.e., any-
 * thing which could try to acquire a user-level lock unprotected by an atfork
 * handler) between fork(2) and exec(2).  See the pthread_atfork(3THR) man
 * page for details.  In particular, we want to avoid calls to zerror() in
 * such situations, as it calls setlocale(3c) which is susceptible to such
 * problems.  So instead we have the child use one of the special exit codes
 * below when needed, and the parent look out for such possibilities and call
 * zerror() there.
 *
 * Since 0, 1 and 2 are generally used for success, general error, and usage,
 * we start with 3.
 */
#define	ZEXIT_FORK		3
#define	ZEXIT_EXEC		4
#define	ZEXIT_ZONE_ENTER	5

#define	DEVFSADM	"devfsadm"
#define	DEVFSADM_PATH	"/usr/sbin/devfsadm"

#define	EXEC_PREFIX	"exec "
#define	EXEC_LEN	(strlen(EXEC_PREFIX))

#define	CLUSTER_BRAND_NAME	"cluster"
#define	LABELED_BRAND_NAME	"labeled"

#define	SHUTDOWN_WAIT		60
#define	SHUTDOWN_DEFAULT	"/sbin/init 0"
#define	SHUTDOWN_FMRI	"svc:/system/zones:default"

/* 0755 is the default directory mode. */
#define	DEFAULT_DIR_MODE \
	(S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)
#define	DEFAULT_DIR_USER -1	/* user ID for chown: -1 means don't change */
#define	DEFAULT_DIR_GROUP -1	/* grp ID for chown: -1 means don't change */


typedef struct zlog {
	FILE *logfile;	/* file to log to */

	/*
	 * The following are used if logging to a buffer.
	 */
	char *log;	/* remaining log */
	size_t loglen;	/* size of remaining log */
	char *buf;	/* underlying storage */
	size_t buflen;	/* total len of 'buf' */
	char *locale;	/* locale to use for gettext() */
} zlog_t;

extern zlog_t logsys;

extern mutex_t lock;
extern mutex_t msglock;
extern boolean_t in_death_throes;
extern boolean_t bringup_failure_recovery;
extern char *zone_name;
extern char zonepath[MAXNAMELEN];
extern zone_dochandle_t snap_hndl;
extern char pool_name[MAXNAMELEN];
extern char brand_name[MAXNAMELEN];
extern char default_brand[MAXNAMELEN];
extern char boot_args[BOOTARGS_MAX];
extern boolean_t zone_isnative;
extern boolean_t zone_iscluster;
extern dladm_handle_t dld_handle;

extern void zerror(zlog_t *, boolean_t, const char *, ...);
extern char *localize_msg(char *locale, const char *msg);
extern void nwifent_free_attrs(struct zone_nwiftab *);

/*
 * Eventstream interfaces.
 */
typedef enum {
	Z_EVT_NULL = 0,
	Z_EVT_ZONE_BOOTING,
	Z_EVT_ZONE_REBOOTING,
	Z_EVT_ZONE_HALTED,
	Z_EVT_ZONE_READIED,
	Z_EVT_ZONE_UNINSTALLING,
	Z_EVT_ZONE_BOOTFAILED
} zone_evt_t;

extern int eventstream_init();
extern void eventstream_write(zone_evt_t evt);

/*
 * Zone mount styles.  Boot is the standard mount we do when booting the zone,
 * scratch is the standard scratch zone mount for upgrade and update is a
 * variation on the scratch zone where we don't lofs mount the zone's /etc
 * and /var back into the scratch zone so that we can then do an
 * 'update on attach' within the scratch zone.
 */
typedef enum {
	Z_MNT_BOOT = 0,
	Z_MNT_SCRATCH,
	Z_MNT_UPDATE
} zone_mnt_t;

/*
 * Virtual platform interfaces.
 */
extern zoneid_t vplat_create(zlog_t *, zone_mnt_t, zoneid_t);
extern int vplat_bringup(zlog_t *, zone_mnt_t, zoneid_t);
extern int vplat_teardown(zlog_t *, boolean_t, boolean_t, boolean_t);
extern int vplat_get_iptype(zlog_t *, zone_iptype_t *);

/*
 * Filesystem mounting interfaces.
 */
extern int valid_mount_path(zlog_t *, const char *, const char *,
    const char *, const char *);
extern int make_one_dir(zlog_t *, const char *, const char *,
    mode_t, uid_t, gid_t);
extern void resolve_lofs(zlog_t *zlogp, char *path, size_t pathlen);

/*
 * Console subsystem routines.
 */
extern int init_console(zlog_t *);
extern void serve_console(zlog_t *);
extern void zcons_statechanged();

/*
 * Memory capping thread creation.
 */
extern void create_mcap_thread(zlog_t *, zoneid_t);
extern void destroy_mcap_thread();

/*
 * Zone FD log thread creation.
 */
extern void create_log_thread(zlog_t *, zoneid_t);
extern void destroy_log_thread();

/*
 * Contract handling.
 */
extern int init_template(void);

/*
 * Routine to manage child processes.
 */
extern int do_subproc(zlog_t *, char *, char **, boolean_t);

#ifdef __cplusplus
}
#endif

#endif /* _ZONEADMD_H */
