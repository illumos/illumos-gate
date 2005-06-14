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
 * Copyright 1994, 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SERVER_DOOR_H
#define	_SERVER_DOOR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Definitions for server side of doors-based name service caching
 */


typedef struct admin {
	nsc_stat_t	passwd;
	nsc_stat_t	group;
	nsc_stat_t	host;
	nsc_stat_t	node;
	nsc_stat_t	exec;
	nsc_stat_t	prof;
	nsc_stat_t	user;
	int		debug_level;
	int		avoid_nameservice;
		/* set to true for disconnected op */
	int		ret_stats;	/* return status of admin calls */
	char		logfile[128];	/* debug file for logging */
} admin_t;


extern struct group *_uncached_getgrgid_r(gid_t, struct group *, char *, int);

extern struct group *_uncached_getgrnam_r(const char *, struct group *,
    char *, int);

extern struct passwd *_uncached_getpwuid_r(uid_t, struct passwd *, char *, int);

extern struct passwd *_uncached_getpwnam_r(const char *, struct passwd *,
    char *, int);

extern struct hostent  *_uncached_gethostbyname_r(const char *,
    struct hostent *, char *, int, int *h_errnop);

extern struct hostent  *_uncached_gethostbyaddr_r(const char *, int, int,
    struct hostent *, char *, int, int *h_errnop);

extern struct hostent  *_uncached_getipnodebyname(const char *,
    struct hostent *, char *, int, int, int, int *h_errnop);

extern struct hostent  *_uncached_getipnodebyaddr(const char *, int, int,
    struct hostent *, char *, int, int *h_errnop);

extern int _nsc_trydoorcall(nsc_data_t **dptr, int *ndata, int *adata);

#ifdef	__cplusplus
}
#endif

#endif	/* _SERVER_DOOR_H */
