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

#ifndef	_LDAP_PRINT_H
#define	_LDAP_PRINT_H

#include <lber.h>
#include <ldap.h>

#include <rpcsvc/nis.h>

#include "ldap_parse.h"
#include "ldap_val.h"
#include "ldap_ruleval.h"
#include "ldap_map.h"

#ifdef	__cplusplus
extern "C" {
#endif

/* Exported functions */

void		printMappingFormat(__nis_mapping_format_t *f);
void		printMappingFormatArray(__nis_mapping_format_t *a);
void		printIndex(__nis_index_t *i);
void		printObjSpec(__nis_obj_spec_t *o);
void		printMappingItem(__nis_mapping_item_t *i,
			__nis_mapping_item_type_t native);
void		printMappingSubElement(__nis_mapping_sub_element_t *e,
			__nis_mapping_item_type_t native);
void		printMappingElement(__nis_mapping_element_t *e,
			__nis_mapping_item_type_t native);
void		printMappingRLHS(__nis_mapping_rlhs_t *m,
			__nis_mapping_item_type_t native);
void		printMappingRule(__nis_mapping_rule_t *r,
			__nis_mapping_item_type_t nativeLhs,
			__nis_mapping_item_type_t nativeRhs);
void		printObjName(__nis_index_t *index, char *name);
void		printobjectDN(__nis_object_dn_t *o);
void		printTableMapping(__nis_table_mapping_t *t);
void		printRuleValue(__nis_rule_value_t *rv);
void		printLdapMod(LDAPMod **mods, __nis_buffer_t *b);
void		printObjAttr(__nis_obj_attr_t *attr);

#ifdef	__cplusplus
}
#endif	/* __cplusplus */

#endif	/* _LDAP_PRINT_H */
