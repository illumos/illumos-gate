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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#ifndef	_NIS_LDAP_H
#define	_NIS_LDAP_H

#include "nisdb_ldap.h"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Deferred update modes for the libnisdb/LDAP database:
 *
 *	Mode		Used as state		Used as argument
 *
 *	d_none		Not in deferred mode	No change to current mode
 *	d_defer		Deferred mode is on	Turn on deferred mode
 *	d_commit	<not used>		Commit deferred changes
 *	d_rollback	<not used>		Rollback deferred changes
 */
typedef enum {d_none, d_defer, d_commit, d_rollback} __nis_defer_t;

/* Externally visible functions in nis_ldap.c */
int		__nis_retry_sleep(__nisdb_retry_t *, int);
int		rootDirExpired(void);
int		touchRootDir(void);

#ifdef	__cplusplus
}
#endif	/* __cplusplus */

#endif	/* _NIS_LDAP_H */
