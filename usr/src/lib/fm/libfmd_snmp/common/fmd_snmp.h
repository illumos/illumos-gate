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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SUNFM_H
#define	_SUNFM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * These values are derived from, and must remain consistent with, the
 * MIB definitions.
 */
#define	MODNAME_STR	"sunFM"
#define	SUNFM_OID	1, 3, 6, 1, 4, 1, 42, 2, 195, 1

#define	SUNFMPROBLEMTABLE_OID		SUNFM_OID, 1

#define	SUNFMPROBLEM_COL_UUIDINDEX	1
#define	SUNFMPROBLEM_COL_UUID		2
#define	SUNFMPROBLEM_COL_CODE		3
#define	SUNFMPROBLEM_COL_URL		4
#define	SUNFMPROBLEM_COL_DIAGENGINE	5
#define	SUNFMPROBLEM_COL_DIAGTIME	6
#define	SUNFMPROBLEM_COL_SUSPECTCOUNT	7

#define	SUNFMPROBLEM_COLMIN		SUNFMPROBLEM_COL_UUID
#define	SUNFMPROBLEM_COLMAX		SUNFMPROBLEM_COL_SUSPECTCOUNT

#define	SUNFMFAULTEVENTTABLE_OID	SUNFM_OID, 2

#define	SUNFMFAULTEVENT_COL_UUIDINDEX	1
#define	SUNFMFAULTEVENT_COL_INDEX	2
#define	SUNFMFAULTEVENT_COL_PROBLEMUUID	3
#define	SUNFMFAULTEVENT_COL_CLASS	4
#define	SUNFMFAULTEVENT_COL_CERTAINTY	5
#define	SUNFMFAULTEVENT_COL_ASRU	6
#define	SUNFMFAULTEVENT_COL_FRU		7
#define	SUNFMFAULTEVENT_COL_RESOURCE	8
#define	SUNFMFAULTEVENT_COL_STATUS	9
#define	SUNFMFAULTEVENT_COL_LOCATION	10

#define	SUNFMFAULTEVENT_COLMIN		SUNFMFAULTEVENT_COL_PROBLEMUUID
#define	SUNFMFAULTEVENT_COLMAX		SUNFMFAULTEVENT_COL_LOCATION

#define	SUNFMFAULTEVENT_STATE_OTHER	1
#define	SUNFMFAULTEVENT_STATE_FAULTY	2
#define	SUNFMFAULTEVENT_STATE_REMOVED	3
#define	SUNFMFAULTEVENT_STATE_REPLACED	4
#define	SUNFMFAULTEVENT_STATE_REPAIRED	5
#define	SUNFMFAULTEVENT_STATE_ACQUITTED	6

#define	SUNFMMODULETABLE_OID		SUNFM_OID, 3

#define	SUNFMMODULE_COL_INDEX		1
#define	SUNFMMODULE_COL_NAME		2
#define	SUNFMMODULE_COL_VERSION		3
#define	SUNFMMODULE_COL_STATUS		4
#define	SUNFMMODULE_COL_DESCRIPTION	5

#define	SUNFMMODULE_COLMIN		SUNFMMODULE_COL_NAME
#define	SUNFMMODULE_COLMAX		SUNFMMODULE_COL_DESCRIPTION

#define	SUNFMMODULE_STATE_OTHER		1
#define	SUNFMMODULE_STATE_ACTIVE	2
#define	SUNFMMODULE_STATE_FAILED	3

#define	SUNFMRESOURCECOUNT_OID		SUNFM_OID, 4

#define	SUNFMRESOURCETABLE_OID		SUNFM_OID, 5

#define	SUNFMRESOURCE_COL_INDEX		1
#define	SUNFMRESOURCE_COL_FMRI		2
#define	SUNFMRESOURCE_COL_STATUS	3
#define	SUNFMRESOURCE_COL_DIAGNOSISUUID	4

#define	SUNFMRESOURCE_COLMIN		SUNFMRESOURCE_COL_FMRI
#define	SUNFMRESOURCE_COLMAX		SUNFMRESOURCE_COL_DIAGNOSISUUID

#define	SUNFMRESOURCE_STATE_OTHER	1
#define	SUNFMRESOURCE_STATE_OK		2
#define	SUNFMRESOURCE_STATE_DEGRADED	3
#define	SUNFMRESOURCE_STATE_UNKNOWN	4
#define	SUNFMRESOURCE_STATE_FAULTED	5

#define	SUNFMTRAPS_OID			SUNFM_OID, 7, 0
#define	SUNFMPROBLEMTRAP_OID		SUNFMTRAPS_OID, 1

#define	SNMP_URL_MSG	"snmp-url"

extern int	init_sunFM(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _SUNFM_H */
