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

#ifndef	_LDAP_NISDBQUERY_H
#define	_LDAP_NISDBQUERY_H

#include <rpcsvc/nis.h>
#include "ldap_parse.h"
#include "db_query_c.h"
#include "ldap_ruleval.h"
#include "ldap_map.h"

#ifdef	__cplusplus
extern "C" {
#endif

/* Exported functions */
item		*buildItem(int len, void *value);
void		freeItem(item *i);
void		freeQcomp(db_qcomp *qc, int doFree);
db_query	*buildQuery(int num_components, db_qcomp *components);
db_query	*cloneQuery(db_query *old, int numComps);
void		freeQuery(db_query *q);
void		freeQueries(db_query **q, int numQ);
db_query	**createQuery(int num, char **index, __nis_table_mapping_t *t,
			__nis_rule_value_t **rvP, int *numVals);
void		printQuery(db_query *q, __nis_table_mapping_t *t);
db_query	**createNisPlusEntry(__nis_table_mapping_t *t,
			__nis_rule_value_t *rv, db_query *qin,
			__nis_obj_attr_t ***objAttr,
			int *numQueries);
db_query	**ruleValue2Query(__nis_table_mapping_t *t,
			__nis_rule_value_t *rv, db_query *qin,
			__nis_obj_attr_t ***objAttr,
			int *numQueries);
db_query	*pseudoEntryObj2Query(entry_obj *e, nis_object *tobj,
			__nis_rule_value_t *rv);
db_query	*queryFromComponent(db_query *q, int index, db_query *qbuf);

#ifdef	__cplusplus
}
#endif	/* __cplusplus */

#endif	/* _LDAP_NISDBQUERY_H */
