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

#ifndef	_LDAP_RULEVAL_H
#define	_LDAP_RULEVAL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <rpcsvc/nis.h>

#include "ldap_parse.h"
#include "ldap_nisdbquery.h"
#include "ldap_structs.h"
#include "ldap_util.h"

/* Exported functions */
void			freeRuleValue(__nis_rule_value_t *rv, int count);
__nis_rule_value_t	*initRuleValue(int count, __nis_rule_value_t *rvIn);
__nis_rule_value_t	*growRuleValue(int oldCount, int newCount,
				__nis_rule_value_t *old,
				__nis_rule_value_t *rvIn);
int			mergeRuleValue(__nis_rule_value_t *target,
				__nis_rule_value_t *source);
int			addAttr2RuleValue(__nis_value_type_t type, char *name,
				void *value, int valueLen,
				__nis_rule_value_t *rv);
int			addSAttr2RuleValue(char *name, char *value,
				__nis_rule_value_t *rv);
int			addCol2RuleValue(__nis_value_type_t type, char *name,
				void *value, int valueLen,
				__nis_rule_value_t *rv);
int			addSCol2RuleValue(char *name, char *value,
				__nis_rule_value_t *rv);
void			delAttrFromRuleValue(__nis_rule_value_t *rv,
				char *attrName);
void			delColFromRuleValue(__nis_rule_value_t *rv,
				char *colName);
__nis_rule_value_t	*buildNisPlusRuleValue(__nis_table_mapping_t *t,
				db_query *q, __nis_rule_value_t *rv);
__nis_mapping_item_t	*buildLvalue(__nis_mapping_rlhs_t *rl,
				__nis_value_t **rval, int *numItems);
__nis_value_t		*buildRvalue(__nis_mapping_rlhs_t *rl,
				__nis_mapping_item_type_t native,
				__nis_rule_value_t *rv, int *stat);
__nis_rule_value_t	*addLdapRuleValue(__nis_table_mapping_t *t,
				__nis_mapping_rule_t *r,
				__nis_mapping_item_type_t lnative,
				__nis_mapping_item_type_t rnative,
				__nis_rule_value_t *rv,
				int doAssign, int *stat);
__nis_rule_value_t	*addObjectClasses(__nis_rule_value_t *rv,
				char *objClassAttrs);
char			*rvId(__nis_rule_value_t *rv,
				__nis_mapping_item_type_t type);
char			*findVal(char *name, __nis_rule_value_t *rv,
				__nis_mapping_item_type_t type);
__nis_rule_value_t	*mergeRuleValueWithSameDN(__nis_rule_value_t *rv,
				int *numVals);

#ifdef	__cplusplus
}
#endif

#endif	/* _LDAP_RULEVAL_H */
