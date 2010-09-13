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

#ifndef	_DAEMON_UTILS_H
#define	_DAEMON_UTILS_H

#include <sys/stat.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	AUTOMOUNTD	"svc:/system/filesystem/autofs:default"
#define	LOCKD		"svc:/network/nfs/nlockmgr:default"
#define	STATD		"svc:/network/nfs/status:default"
#define	NFSD		"svc:/network/nfs/server:default"
#define	MOUNTD		"svc:/network/nfs/mountd:default"
#define	NFS4CBD		"svc:/network/nfs/cbd:default"
#define	NFSMAPID	"svc:/network/nfs/mapid:default"
#define	RQUOTAD		"svc:/network/nfs/rquota:default"
#define	REPARSED	"svc:/system/filesystem/reparse:default"

#define	DAEMON_UID	 1
#define	DAEMON_GID	12

#define	DAEMON_DIR	"/var/run/daemon"
#define	DAEMON_DIR_MODE	(S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)

extern void _check_services(char **);
extern int _check_daemon_lock(const char *);
extern int _create_daemon_lock(const char *, uid_t, gid_t);
extern pid_t _enter_daemon_lock(const char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _DAEMON_UTILS_H */
