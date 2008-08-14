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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef _DB_DEFS_
#define	_DB_DEFS_
#ifndef _DB_DEFS_API_
#include "api/db_defs_api.h"
#endif
#define	DATA_BASE	"lib5"
#define	MIN_PANEL_TYPE	-3

#define	MIN_TAPE_USAGE		0

#define	VOLUME_TABLE_FILLFACTOR		20
#define	VOLUME_TABLE_INDEXFILL		20
#define	VOLUME_TABLE_MAXINDEXFILL	24

#define	VAC_TABLE_FILLFACTOR		26
#define	VAC_TABLE_INDEXFILL		26
#define	VAC_TABLE_MAXINDEXFILL		31


#define	CELL_TABLE_FILLFACTOR		46
#define	CELL_TABLE_INDEXFILL		20
#define	CELL_TABLE_MAXINDEXFILL		24

#define	AUDIT_TABLE_FILLFACTOR		32
#define	AUDIT_TABLE_INDEXFILL		40
#define	AUDIT_TABLE_MAXINDEXFILL	46

#define	LSM_TABLE_FILLFACTOR		1


#define	ACS_TABLE_FILLFACTOR		1


#define	DRIVE_TABLE_FILLFACTOR		1

#define	LOCKID_TABLE_MINPAGES		280
#define	LOCKID_TABLE_FILLFACTOR		25


#define	CAP_TABLE_FILLFACTOR		1

#define	POOL_TABLE_FILLFACTOR		20
#define	POOL_TABLE_INDEXFILL		20
#define	POOL_TABLE_MAXINDEXFILL		24

#define	CSI_TABLE_FILLFACTOR		1

#define	PORT_TABLE_FILLFACTOR		1

#define	PANEL_TABLE_FILLFACTOR		20
#define	PANEL_TABLE_INDEXFILL		20
#define	PANEL_TABLE_MAXINDEXFILL	24



#endif /* _DB_DEFS_ */
