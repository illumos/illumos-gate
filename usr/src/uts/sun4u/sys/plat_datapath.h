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

#ifndef	_PLAT_DATAPATH_H
#define	_PLAT_DATAPATH_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Definitions to support datapath fault diagnosis for Starcat
 * and Serengeti.
 */

#define	FM_ERROR_DATAPATH	"dp"

/* datapath ereport payload member names */
#define	DP_EREPORT_TYPE		"erptype"
#define	DP_TVALUE		"t-value"
#define	DP_LIST_SIZE		"dp-list-sz"
#define	DP_LIST			"dp-list"
#define	SN_LIST			"sn-list"

/* datapath ereport types for DP_EREPORT_TYPE */
#define	DP_ERROR	0
#define	DP_FAULT	1

/*
 * Name definitions for datapath error/fault types
 *
 * Note that "rp" is the Serengeti name for "cp."
 */
#define	DP_ERROR_CDS	"cds"
#define	DP_ERROR_DX	"dx"
#define	DP_ERROR_EX	"sdi"	/* Starcat-only */
#define	DP_ERROR_CP	"cp"
#define	DP_ERROR_RP	"rp"	/* Serengeti name for "cp" */

/*
 * Numeric definitions for datapath error/fault types
 * as received in a mailbox message from the SC.
 */
	/* Shared between Starcat and Serengeti */
#define		DP_CDS_TYPE	0
#define		DP_DX_TYPE	1
	/* Starcat-only */
#define		DP_EX_TYPE	2
#define		DP_CP_TYPE	3
	/* Serengeti-only */
#define		DP_RP_TYPE	2

/*
 * Numeric definitions for datapath error-fault types
 * remapped from values received from the SC to values unique
 * between Starcat and Serengeti.
 */
	/* Starcat types */
#define	SC_DP_CDS_TYPE		0
#define	SC_DP_DX_TYPE		1
#define	SC_DP_EX_TYPE		2
#define	SC_DP_CP_TYPE		3
	/* Serengeti types */
#define	SG_DP_CDS_TYPE		4
#define	SG_DP_DX_TYPE		5
#define	SG_DP_RP_TYPE		6

#ifdef __cplusplus
}
#endif

#endif	/* _PLAT_DATAPATH_H */
