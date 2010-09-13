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

#ifndef	_LDAP_VAL_H
#define	_LDAP_VAL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <rpcsvc/nis.h>

#include "ldap_parse.h"
#include "ldap_ruleval.h"

/*
 * If we got values for the columns in the ruleval struct (from LDAP
 * or got from the query itself) then we assign the status to
 * NP_LDAP_MAP_SUCCESS. If we have enough NIS+ columns for the
 * rules to produce a value, but none of the rules produce a
 * value, then we pass NP_LDAP_RULES_NO_VALUE from
 * createLdapRequest() as an indication to proceed to the next
 * table mapping. NP_LDAP_NO_VALUE is used to indicate that
 * the element didn't have an entry in the LDAP.
 */
#define	NP_LDAP_MAP_SUCCESS 1
#define	NP_LDAP_RULES_NO_VALUE 2
#define	NP_LDAP_NO_VALUE 3

/* Exported functions */
__nis_mapping_format_t	*cloneMappingFormat(__nis_mapping_format_t *m);
void			freeMappingFormat(__nis_mapping_format_t *m);
void			copyIndex(__nis_index_t *old, __nis_index_t *nnew,
				int *err);
__nis_index_t		*cloneIndex(__nis_index_t *old);
void			freeIndex(__nis_index_t *old, bool_t doFree);
char			**cloneName(char **name, int numNames);
void			freeValue(__nis_value_t *val, int count);
__nis_value_t		*cloneValue(__nis_value_t *val, int count);
__nis_value_t		*getMappingItemVal(__nis_mapping_item_t *i,
				__nis_mapping_item_type_t native,
				__nis_rule_value_t *rv, char *berstring,
				int *np_ldap_stat);
__nis_value_t		*getMappingFormat(__nis_mapping_format_t *f,
				__nis_rule_value_t *rv, __nis_format_arg_t at,
				void *a, int *numArg);
__nis_value_t		*explodeValues(__nis_value_t *v1, __nis_value_t *v2);
__nis_value_t		*getMappingFormatArray(__nis_mapping_format_t *a,
				__nis_rule_value_t *rv, __nis_format_arg_t at,
				int numArgs, void *arg);
char			*getIndex(__nis_index_t *i, int *len);
char			*getObjSpec(__nis_obj_spec_t *o, int *len);
char			*getScope(int scope);
char			*getSearchTriple(__nis_search_triple_t *s, int *len);
__nis_value_t		*getMappingItem(__nis_mapping_item_t *i,
				__nis_mapping_item_type_t native,
				__nis_rule_value_t *rv, char *berstring,
				int *np_ldap_stat);
void			copyObjSpec(__nis_obj_spec_t *old,
				__nis_obj_spec_t *nnew, int *err);
__nis_obj_spec_t	*cloneObjSpec(__nis_obj_spec_t *old);
void			freeObjSpec(__nis_obj_spec_t *old, bool_t doFree);
void			copySearchTriple(__nis_search_triple_t *old,
				__nis_search_triple_t *nnew, int *err);
__nis_search_triple_t	*cloneSearchTriple(__nis_search_triple_t *old);
void			freeSearchTriple(__nis_search_triple_t *old,
				bool_t doFree);
void			copyTripleOrObj(__nis_mapping_item_type_t type,
				__nis_triple_or_obj_t *old,
				__nis_triple_or_obj_t *nnew, int *err);
__nis_triple_or_obj_t	*cloneTripleOrObj(__nis_mapping_item_type_t type,
				__nis_triple_or_obj_t *old);
void			freeTripleOrObj(__nis_mapping_item_type_t type,
				__nis_triple_or_obj_t *old,
				bool_t doFree);
void			copyItem(__nis_mapping_item_t *old,
				__nis_mapping_item_t *nnew, int *err);
__nis_mapping_item_t	*cloneItem(__nis_mapping_item_t *old);
void			freeMappingItem(__nis_mapping_item_t *item,
				int numItems);
__nis_mapping_item_t	*concatenateMappingItem(__nis_mapping_item_t *old,
				int numItems, __nis_mapping_item_t *cat);
__nis_value_t		*concatenateValues(__nis_value_t *v1,
				__nis_value_t *v2);
__nis_value_t		*splitMappingItem(__nis_mapping_item_t *item,
				char delim, __nis_rule_value_t *rv);
char			*scanMappingFormat(__nis_mapping_format_t *f,
				int curf, int nf, char *str, char **val,
				char **fmtstart, char *sepset);
int			verifyMappingMatch(__nis_mapping_format_t *f,
				char *str);
__nis_value_t		**matchMappingItem(__nis_mapping_format_t *f,
				__nis_value_t *inVal, int *numVals,
				char *sepset, char **outstr);
__nis_value_t		*extractMappingItem(__nis_mapping_item_t *item,
				__nis_mapping_format_t *f,
				__nis_rule_value_t *rv, int *np_ldap_stat);
void			stringElide(__nis_value_t *val, char elide);
__nis_value_t		*getMappingSubElement(__nis_mapping_sub_element_t *e,
				__nis_rule_value_t *rv, int *np_ldap_stat);
__nis_value_t		*getMappingElement(__nis_mapping_element_t *e,
				__nis_mapping_item_type_t native,
				__nis_rule_value_t *rv, int *stat);

#ifdef	__cplusplus
}
#endif

#endif	/* _LDAP_VAL_H */
