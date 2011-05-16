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


#ifndef	_NIS_DB_H
#define	_NIS_DB_H

#ifdef	__cplusplus
#include "db.h"
extern "C" {
#else
#include "db_c.h"
#endif	/* __cplusplus */

#include "ldap_parse.h"

extern int	useLDAPrespository;

void		db_free_result(db_result *dr);
char		*entryName(const char *msg, char *objName, char **tableP);
nis_object	*dbFindObject(char *objName, db_status *statP);
db_status	dbDeleteObj(char *objName);
db_status	dbTouchObj(char *objName);
db_status	dbRefreshObj(char *name, nis_object *o);
db_status	dbCreateFromLDAP(char *intName, int *ldapStat);
nis_object	*ldapFindObj(__nis_table_mapping_t *t, char *objName,
			int *statP);
nis_object	*findObj(char *name, db_status *statP, int *lstatP);
bool_t		replaceMappingObj(__nis_table_mapping_t *t, nis_object *n);
int		setMappingObjTypeEtc(__nis_table_mapping_t *t, nis_object *o);
int		loadAllLDAP(int fromLDAP, void *cookie, db_status *dstatP);

#ifdef	__cplusplus
}
#endif	/* __cplusplus */

#endif	/* _NIS_DB_H */
