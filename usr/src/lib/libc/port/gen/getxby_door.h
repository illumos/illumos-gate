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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_GETXBY_DOOR_H
#define	_GETXBY_DOOR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Definitions for client side of doors-based name service caching
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <grp.h>
#include <pwd.h>
#include <exec_attr.h>
#include <prof_attr.h>
#include <user_attr.h>
#include <nss_dbdefs.h>

/*
 * nscd version 2 doors interfaces
 * The known, but private NAME_SERVICE_DOOR, filesystem name remains
 * the same, even though the transfer contents is significantly different.
 */

#define	NAME_SERVICE_DOOR_V2 2
#define	NAME_SERVICE_DOOR_VERSION 2
#ifndef NAME_SERVICE_DOOR
#define	NAME_SERVICE_DOOR "/var/run/name_service_door"
#endif
#define	NAME_SERVICE_DOOR_COOKIE ((void*)(0xdeadbeef^NAME_SERVICE_DOOR_VERSION))

/*
 * internal APIs
 */

nss_status_t	_nsc_trydoorcall(void **dptr, size_t *bsize, size_t *dsize);
nss_status_t	_nsc_trydoorcall_ext(void **dptr, size_t *bsize, size_t *dsize);
int		_nsc_getdoorbuf(void **dptr, size_t *bsize);
void		_nsc_resizedoorbuf(size_t bsize);
int		_nsc_proc_is_cache();


struct passwd *
_uncached_getpwuid_r(uid_t uid, struct passwd *result, char *buffer,
	int buflen);

struct passwd *
_uncached_getpwnam_r(const char *name, struct passwd *result, char *buffer,
	int buflen);

struct group *
_uncached_getgrnam_r(const char *name, struct group *result, char *buffer,
    int buflen);

struct group *
_uncached_getgrgid_r(gid_t gid, struct group *result, char *buffer, int buflen);


#ifdef	__cplusplus
}
#endif


#endif	/* _GETXBY_DOOR_H */
