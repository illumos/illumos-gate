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

#ifndef	_LDAP_NISPLUS_H
#define	_LDAP_NISPLUS_H

#include <rpcsvc/nis.h>
#include "ldap_parse.h"
#include "ldap_structs.h"


#ifdef	__cplusplus
extern "C" {
#endif

__nis_rule_value_t	*getNisPlusEntry(__nis_index_t *index, char *table,
				__nis_rule_value_t *rvIn, int *numVals);
__nis_rule_value_t	*getNisPlusEntrySimple(char *name, int *numVals);
int			getNisPlusObj(char *name, char *msg,
				nis_result **outRes);
__nis_value_t		*lookupNisPlus(__nis_obj_spec_t *obj, char *col,
				__nis_rule_value_t *rvIn);
nis_error		storeNisPlus(__nis_mapping_item_t *item, int index,
				int numItems, __nis_rule_value_t *rv,
				char *table, __nis_value_t *val);
int			copyColumnNames(nis_object *o, char ***column,
				int *numColumns);
int			initializeColumnNames(char *table, char ***column,
					int *numColumns, zotypes *type,
					nis_object **obj);
void			setOid(nis_object *obj);

#ifdef	__cplusplus
}
#endif	/* __cplusplus */

#endif	/* _LDAP_NISPLUS_H */
