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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	DSVCD_DSVCLOCKD_H
#define	DSVCD_DSVCLOCKD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/types.h>

/*
 * Data structures and constants that are shared between dsvclockd and
 * libdhcpsvc.  This protocol is project-private and is thus subject to
 * change at any time.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#define	DSVCD_DOOR_VERSION	1		/* current protocol version */
#define	DSVCD_PATH		"/usr/lib/inet/dsvclockd"
#define	DSVCD_DOOR_FMT		"/var/run/dsvclockd_%s_door"

typedef enum { DSVCD_LOCK, DSVCD_UNLOCK } dsvcd_reqtype_t;
typedef enum { DSVCD_NOLOCK, DSVCD_RDLOCK, DSVCD_WRLOCK } dsvcd_locktype_t;

typedef struct {
	uint8_t			rq_version;	/* version of the API */
	dsvcd_reqtype_t		rq_reqtype;	/* request type */
} dsvcd_request_t;

typedef struct {
	uint8_t			rp_version;	/* version of the API */
	int32_t			rp_retval;	/* DSVC_* return value */
} dsvcd_reply_t;

typedef struct {
	dsvcd_request_t		lrq_request;	/* generic request header */
	dsvcd_locktype_t	lrq_locktype;	/* reader or writer */
	uint8_t			lrq_nonblock;	/* cannot block if true */
	uint8_t			lrq_crosshost;	/* do cross-host synch */

	/*
	 * The caller filling in this request must provide their current
	 * container version and a name for their container which is
	 * per-datastore unique (but need not be unique across datastores
	 * or different versions of the same container.)
	 *
	 * The `lrq_loctoken' field must contain a token which "names" a
	 * given location where the container exists -- note that a given
	 * location must have exactly one name, though it's permissible for
	 * more than one location to have the same name (in this case,
	 * containers from these locations will be synchronized with one
	 * another, which will hamper performance).  Note that standard
	 * pathnames do not meet the first constraint (e.g., /var/dhcp and
	 * /var/../var/dhcp are two different names for the same location),
	 * but pathnames processed by realpath(3C) do.
	 *
	 * If the caller wants cross-host synchronization, then
	 * `lrq_crosshost' must be set and `lrq_loctoken' must be a
	 * realpath(3C)'d directory that all hosts can access.
	 */
	int			lrq_conver;
	char			lrq_conname[64];
	char			lrq_loctoken[MAXPATHLEN];
} dsvcd_lock_request_t;

typedef struct {
	dsvcd_request_t		urq_request;	/* generic request header */
} dsvcd_unlock_request_t;

#ifdef	__cplusplus
}
#endif

#endif	/* DSVCD_DSVCLOCKD_H */
