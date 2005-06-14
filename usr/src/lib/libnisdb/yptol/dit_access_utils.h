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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _DIT_ACCESS_UTILS_H
#define	_DIT_ACCESS_UTILS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef ERROR
#define	ERROR	-1
#endif

/* Keywords */
#define	N2LKEY			"rf_key"
#define	N2LIPKEY		"rf_ipkey"
#define	N2LSEARCHKEY		"rf_searchkey"
#define	N2LSEARCHIPKEY		"rf_searchipkey"
#define	N2LDOMAIN		"rf_domain"
#define	N2LCOMMENT		"rf_comment"

/* libldap ignores usec. Hence using 1 sec timeout */
#define	SINGLE_ACCESS_TIMEOUT_SEC	1
#define	SINGLE_ACCESS_TIMEOUT_USEC	0

extern __yp_domain_context_t	ypDomains;

extern char			*getFullMapName(char *map, char *domain);
extern __nis_value_t		*stringToValue(char *dptr, int dsize);
extern __nis_rule_value_t	*processSplitField(__nis_table_mapping_t *sf,
				__nis_value_t *inVal, int *nv, int *statP);
extern __nis_rule_value_t	*datumToRuleValue(datum *key, datum *value,
				__nis_table_mapping_t *t, int *nv,
				char *domain, bool_t readonly, int *statP);
extern __nis_table_mapping_t	*mappingFromMap(char *map, char *domain,
				int *statP);
extern bool_t			singleReadFromDIT(char *map, char *domain,
				datum *key,
				datum *value, int *statP);
extern suc_code			singleWriteToDIT(char *map, char *domain,
				datum *key, datum *value, bool_t replace);
extern suc_code			buildNISRuleValue(__nis_table_mapping_t *t,
				__nis_rule_value_t *rv, char *domain);
extern suc_code			addSplitFieldValues(__nis_table_mapping_t *t,
				__nis_rule_value_t *rv, __nis_rule_value_t *trv,
				int numVals, char *domain);
extern datum			*ruleValueToDatum(__nis_table_mapping_t *t,
				__nis_rule_value_t *rv, int *statP);
extern datum 			*getKeyFromRuleValue(__nis_table_mapping_t *t,
				__nis_rule_value_t *rv, int *nv, int *statP);
extern const char		*getObjectClass(char *rdn);
extern suc_code			makeNISObject(char *domain, char *dn);
extern suc_code			addNISObject(char *domain, char *dn,
				int *ldap_rc);
extern suc_code			addParent(char *dn, char **attr);
extern bool_t			is_fatal_error(int res);
extern suc_code			alloc_temp_names(char *name,
				char **temp_entries, char **temp_ttl);
extern suc_code			collapseRuleValue(__nis_rule_value_t *rv);

#ifdef	__cplusplus
}
#endif

#endif	/* _DIT_ACCESS_UTILS_H */
