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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef	_LDAP_MAP_H
#define	_LDAP_MAP_H

#include <rpcsvc/nis.h>

#include "ldap_parse.h"
#include "ldap_structs.h"
#include "nis_hashitem.h"
#include "db_query_c.h"

#ifdef	__cplusplus
extern "C" {
#endif

extern	__nis_hash_table_mt	ldapMappingList;

typedef struct {
	char		*zo_owner;
	char		*zo_group;
	char		*zo_domain;
	uint_t		zo_access;
	uint32_t	zo_ttl;
} __nis_obj_attr_t;

/* Exported functions */
db_query		**mapFromLDAP(__nis_table_mapping_t *t, db_query *qin,
				int *numQueries, char *dbId, int *ldapStat,
				__nis_obj_attr_t ***objAttr);
int			mapToLDAP(__nis_table_mapping_t *t, int numQueries,
				db_query **oldQ, db_query **newQ,
				__nis_rule_value_t *rvIn, int firstOnly,
				char *dbId);
int			verifyIndexMatch(__nis_table_mapping_t *x,
				db_query *q, __nis_rule_value_t *rv,
				char *name, char *val);
__nis_table_mapping_t	**selectTableMapping(__nis_table_mapping_t *t,
				db_query *q, int wantWrite, int wantObj,
				char *dbId, int *numMatches);
int			haveIndexedMapping(__nis_table_mapping_t *t);
int			objToLDAP(__nis_table_mapping_t *t, nis_object *o,
				entry_obj **ea, int numEa);
int			objFromLDAP(__nis_table_mapping_t *t, nis_object **o,
				entry_obj ***eaP, int *numEaP);
int			deleteLDAPobj(__nis_table_mapping_t *t);
__nis_obj_attr_t	*ruleValue2ObjAttr(__nis_rule_value_t *rv);
void			freeSingleObjAttr(__nis_obj_attr_t *attr);
void			freeObjAttr(__nis_obj_attr_t **attr, int numAttr);
__nis_obj_attr_t	*cloneObjAttr(__nis_obj_attr_t *old);
int			isObjAttrString(char *str);
char			*isObjAttr(__nis_single_value_t *val);
int			setObjAttrField(char *attrName,
				__nis_single_value_t *val,
				__nis_obj_attr_t **objAttr);
int			setColumnNames(__nis_table_mapping_t *t);
__nis_rule_value_t	*addObjAttr2RuleValue(nis_object *obj,
				__nis_rule_value_t *rvIn);

#ifdef	__cplusplus
}
#endif

#endif	/* _LDAP_MAP_H */
