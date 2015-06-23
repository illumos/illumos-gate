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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Header File for Clients of Native Identity Mapping Service
 */

#ifndef _IDMAP_H
#define	_IDMAP_H


#include <stdlib.h>
#include <ctype.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/idmap.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The ifdef's for these two accomodate duplicate definitions in
 * lib/smbsrv/libfksmbsrv/common/sys/kidmap.h  See notes there.
 */

/* Status */
#ifndef	_IDMAP_STAT_TYPE
#define	_IDMAP_STAT_TYPE
typedef int32_t	idmap_stat;
#endif	/* _IDMAP_STAT_TYPE */

/* Opaque get handle */
#ifndef	_IDMAP_GET_HANDLE_T
#define	_IDMAP_GET_HANDLE_T
typedef struct idmap_get_handle idmap_get_handle_t;
#endif	/* _IDMAP_GET_HANDLE_T */

typedef uint32_t	idmap_rid_t;

/* Logger prototype which is based on syslog */
typedef void (*idmap_logger_t)(int, const char *, ...);

/*
 * Setup API
 */

/* Status code to string */
extern const char *idmap_stat2string(idmap_stat);

/* Free memory allocated by the API */
extern void idmap_free(void *);


/*
 * Supported flag values for mapping requests.
 * These flag values are applicable to the batch API and the
 * Windows Name API below.
 */
/* Use the libidmap cache */
#define	IDMAP_REQ_FLG_USE_CACHE	0x00000010

/*
 * API to batch SID to UID/GID mapping requests
 */
/* Create handle */
extern idmap_stat idmap_get_create(idmap_get_handle_t **);

/* Given SID, get UID */
extern idmap_stat idmap_get_uidbysid(idmap_get_handle_t *, char *,
	idmap_rid_t, int, uid_t *, idmap_stat *);

/* Given SID, get GID */
extern idmap_stat idmap_get_gidbysid(idmap_get_handle_t *, char *,
	idmap_rid_t, int, gid_t *, idmap_stat *);

/* Given SID, get UID or GID */
extern idmap_stat idmap_get_pidbysid(idmap_get_handle_t *, char *,
	idmap_rid_t, int, uid_t *, int *, idmap_stat *);

/* Given UID, get SID */
extern idmap_stat idmap_get_sidbyuid(idmap_get_handle_t *, uid_t, int,
	char **, idmap_rid_t *, idmap_stat *);

/* Given GID, get SID */
extern idmap_stat idmap_get_sidbygid(idmap_get_handle_t *, gid_t, int,
	char **, idmap_rid_t *, idmap_stat *);

/* Process the batched requests */
extern idmap_stat idmap_get_mappings(idmap_get_handle_t *);

/* Destroy the handle */
extern void idmap_get_destroy(idmap_get_handle_t *);


/*
 * API to get Windows name by UID/GID and vice-versa
 */
/* Given UID, get Windows name */
extern idmap_stat idmap_getwinnamebyuid(uid_t, int, char **, char **);

/* Given GID, get Windows name */
extern idmap_stat idmap_getwinnamebygid(gid_t, int, char **, char **);

/* Given PID, get Windows name */
extern idmap_stat idmap_getwinnamebypid(uid_t, int, int, char **, char **);

/* Given Windows name, get UID */
extern idmap_stat idmap_getuidbywinname(const char *, const char *,
	int, uid_t *);

/* Given Windows name, get GID */
extern idmap_stat idmap_getgidbywinname(const char *, const char *,
	int, gid_t *);


/* Logger */
extern void idmap_set_logger(idmap_logger_t funct);

#ifdef __cplusplus
}
#endif

#endif /* _IDMAP_H */
