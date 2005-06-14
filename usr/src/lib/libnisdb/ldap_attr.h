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

#ifndef	_LDAP_ATTR_H
#define	_LDAP_ATTR_H

#include "ldap_structs.h"
#include "ldap_parse.h"

#ifdef	__cplusplus
extern "C" {
#endif

/* Exported functions */
char			*nisplusLDAPbaseDomain(char *domain);
char			*fullObjName(int deallocate, char *name);
char			*appendBase(char *item, char *base, int *err,
				int dealloc);
char			*domain2base(char *domain);
char			*fullLDAPname(int deallocate, char *name);
char			*makeFilter(char *attr);
char			**makeFilterComp(char *filter, int *numComps);
void			freeFilterComp(char **comp, int numComps);
char			**addFilterComp(char *nf, char **comp, int *numComps);
char			*concatenateFilterComps(int numComps, char **comp);
void			freeDNs(char **dn, int numDN);
char			**findDNs(char *msg, __nis_rule_value_t *rv,
				int nrv, char *defBase, int *numDN);

#ifdef	__cplusplus
}
#endif	/* __cplusplus */

#endif	/* _LDAP_ATTR_H */
