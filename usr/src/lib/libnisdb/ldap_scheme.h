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

#ifndef	_LDAP_SCHEME_H
#define	_LDAP_SCHEME_H

#include <rpcsvc/nis.h>
#include "db_query_c.h"
#include "db_scheme_c.h"
#include "ldap_parse.h"

#ifdef	__cplusplus
extern "C" {
#endif

db_query	*schemeQuery2Query(db_query *qin, db_scheme *s);
nis_attr	*schemeQuery2nisAttr(db_query *q, nis_attr *space,
			db_scheme *s, __nis_table_mapping_t *t, int *numAttr);

#ifdef	__cplusplus
}
#endif

#endif	/* _LDAP_SCHEME_H */
