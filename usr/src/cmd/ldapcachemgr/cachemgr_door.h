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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_CACHEMGR_DOOR_H
#define	_CACHEMGR_DOOR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Definitions for server side of doors-based name service caching
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/param.h>
#include "ns_cache_door.h"

typedef struct admin {
	ldap_stat_t	ldap_stat;
	int		debug_level;
	int		ret_stats;
	char		logfile[MAXPATHLEN];
} admin_t;


extern int __ns_ldap_trydoorcall(ldap_data_t **dptr, int *ndata, int *adata);

#ifdef __cplusplus
}
#endif

#endif /* _CACHEMGR_DOOR_H */
