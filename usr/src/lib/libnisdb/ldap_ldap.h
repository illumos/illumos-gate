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
 * Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LDAP_LDAP_H
#define	_LDAP_LDAP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include "ldap_parse.h"
#include "ldap_structs.h"
#include "ldap_val.h"

__nis_value_t	*lookupLDAP(__nis_search_triple_t *t, char *attrName,
			__nis_rule_value_t *rv, __nis_object_dn_t *def,
			int *np_ldap_stat);
int		storeLDAP(__nis_mapping_item_t *item, int index,
			int numIndexes, __nis_value_t *val,
			__nis_object_dn_t *defDN, char **dn, int numDN);

#ifdef	__cplusplus
}
#endif

#endif	/* _LDAP_LDAP_H */
