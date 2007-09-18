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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _LIBDLADM_H
#define	_LIBDLADM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file includes structures, macros and common routines shared by all
 * data-link administration, and routines which do not directly administrate
 * links. For example, dladm_status2str().
 */

#ifdef	__cplusplus
extern "C" {
#endif

#define	DLADM_STRSIZE		256
#define	DLADM_OPT_TEMP		0x00000001
#define	DLADM_OPT_CREATE	0x00000002
#define	DLADM_OPT_PERSIST	0x00000004

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
	DLADM_STATUS_INVALIDID,
	DLADM_STATUS_INVALIDMACADDRLEN,
	DLADM_STATUS_INVALIDMACADDRTYPE,
	DLADM_STATUS_AUTOIDNOTEMP,
	DLADM_STATUS_AUTOIDNOAVAILABLEID,
	DLADM_STATUS_BUSY
} dladm_status_t;

typedef enum {
	DLADM_PROP_VAL_CURRENT = 1,
	DLADM_PROP_VAL_DEFAULT,
	DLADM_PROP_VAL_MODIFIABLE,
	DLADM_PROP_VAL_PERSISTENT
} dladm_prop_type_t;

extern const char	*dladm_status2str(dladm_status_t, char *);
extern dladm_status_t	dladm_set_rootdir(const char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBDLADM_H */
