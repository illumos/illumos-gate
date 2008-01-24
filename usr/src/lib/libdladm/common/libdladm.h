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

#ifndef _LIBDLADM_H
#define	_LIBDLADM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/dls.h>
#include <sys/dlpi.h>

/*
 * This file includes structures, macros and common routines shared by all
 * data-link administration, and routines which do not directly administrate
 * links. For example, dladm_status2str().
 */

#ifdef	__cplusplus
extern "C" {
#endif

#define	LINKID_STR_WIDTH	10
#define	DLADM_STRSIZE		256

/*
 * option flags taken by the libdladm functions
 *
 *  - DLADM_OPT_ACTIVE:
 *    The function requests to bringup some configuration that only take
 *    effect on active system (not persistent).
 *
 *  - DLADM_OPT_PERSIST:
 *    The function requests to persist some configuration.
 *
 *  - DLADM_OPT_CREATE:
 *    Today, only used by dladm_set_secobj() - requests to create a secobj.
 *
 *  - DLADM_OPT_FORCE:
 *    The function requests to execute a specific operation forcefully.
 *
 *  - DLADM_OPT_PREFIX:
 *    The function requests to generate a link name using the specified prefix.
 */
#define	DLADM_OPT_ACTIVE	0x00000001
#define	DLADM_OPT_PERSIST	0x00000002
#define	DLADM_OPT_CREATE	0x00000004
#define	DLADM_OPT_FORCE		0x00000008
#define	DLADM_OPT_PREFIX	0x00000010

#define	DLADM_WALK_TERMINATE	0
#define	DLADM_WALK_CONTINUE	-1

typedef enum {
	DLADM_STATUS_OK = 0,
	DLADM_STATUS_BADARG,
	DLADM_STATUS_FAILED,
	DLADM_STATUS_TOOSMALL,
	DLADM_STATUS_NOTSUP,
	DLADM_STATUS_NOTFOUND,
	DLADM_STATUS_BADVAL,
	DLADM_STATUS_NOMEM,
	DLADM_STATUS_EXIST,
	DLADM_STATUS_LINKINVAL,
	DLADM_STATUS_PROPRDONLY,
	DLADM_STATUS_BADVALCNT,
	DLADM_STATUS_DBNOTFOUND,
	DLADM_STATUS_DENIED,
	DLADM_STATUS_IOERR,
	DLADM_STATUS_TEMPONLY,
	DLADM_STATUS_TIMEDOUT,
	DLADM_STATUS_ISCONN,
	DLADM_STATUS_NOTCONN,
	DLADM_STATUS_REPOSITORYINVAL,
	DLADM_STATUS_MACADDRINVAL,
	DLADM_STATUS_KEYINVAL,
	DLADM_STATUS_INVALIDMACADDRLEN,
	DLADM_STATUS_INVALIDMACADDRTYPE,
	DLADM_STATUS_LINKBUSY,
	DLADM_STATUS_VIDINVAL,
	DLADM_STATUS_NONOTIF,
	DLADM_STATUS_TRYAGAIN
} dladm_status_t;

typedef enum {
	DLADM_TYPE_STR,
	DLADM_TYPE_BOOLEAN,
	DLADM_TYPE_UINT64
} dladm_datatype_t;

typedef int dladm_conf_t;
#define	DLADM_INVALID_CONF	0

extern const char	*dladm_status2str(dladm_status_t, char *);
extern dladm_status_t	dladm_set_rootdir(const char *);
extern const char	*dladm_class2str(datalink_class_t, char *);
extern const char	*dladm_media2str(uint32_t, char *);
extern boolean_t	dladm_valid_linkname(const char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBDLADM_H */
