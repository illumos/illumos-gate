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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LDAP_OP_H
#define	_LDAP_OP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>

/*
 * Need _SOLARIS_SDK in order to get LDAP_CONTROL_SIMPLE_PAGE from new <ldap.h>
 */
#ifndef	_SOLARIS_SDK
#define	_SOLARIS_SDK
#endif

#include <lber.h>
#include <ldap.h>
#include <rpcsvc/nis.h>

#include "ldap_parse.h"
#include "ldap_structs.h"
#include "ldap_ruleval.h"
#include "nis_parse_ldap_conf.h"

/* Exported functions */
__nis_ldap_search_t	*buildLdapSearch(char *base, int scope,
				int numFilterComps, char **filterComp,
				char *filter, char **attrs, int attrsonly,
				int isDN);
void			freeLdapSearch(__nis_ldap_search_t *ls);
__nis_ldap_search_t	*createLdapRequest(__nis_table_mapping_t *t,
				__nis_rule_value_t *rv, char **dn,
				int fromLDAP, int *res,
				__nis_object_dn_t *objectDN);
int			ldapDestroy(void);
int			string2method(char *method);
int			ldapConnect(void);
__nis_rule_value_t	*ldapSearch(__nis_ldap_search_t *ls, int *numValues,
				__nis_rule_value_t *rvIn, int *ldapStat);
LDAPMod			**search2LdapMod(__nis_rule_value_t *rv, int add,
				int oc);
int			ldapModify(char *dn, __nis_rule_value_t *rv,
				char *objClassAttrs, int addFirst);
int			ldapAdd(char *dn, __nis_rule_value_t *rv,
				char *objClassAttrs, void *lcv);
int			ldapChangeDN(char *oldDn, char *dn);

#ifdef	__cplusplus
}
#endif

#endif	/* _LDAP_OP_H */
