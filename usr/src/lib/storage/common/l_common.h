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

/*
 * Common definitions
 */

#ifndef	_L_COMMON_H
#define	_L_COMMON_H



/*
 * Include any headers you depend on.
 */

/*
 * I18N message number ranges
 *  This file: 14500 - 14999
 *  Shared common messages: 1 - 1999
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include	<sys/scsi/targets/sesio.h>

/*
 * Debug environmental flags.
 */
/* SCSI Commands */
#define	S_DPRINTF	if (getenv("_LUX_S_DEBUG") != NULL) (void) printf

/* General purpose */
#define	P_DPRINTF	if (getenv("_LUX_P_DEBUG") != NULL) (void) printf

/* Opens */
#define	O_DPRINTF	if (getenv("_LUX_O_DEBUG") != NULL) (void) printf

/* Ioctls */
#define	I_DPRINTF	if (getenv("_LUX_I_DEBUG") != NULL) (void) printf

/* Hot-Plug */
#define	H_DPRINTF	if (getenv("_LUX_H_DEBUG") != NULL) (void) printf

/* Convert Name debug variable. */
#define	L_DPRINTF	if (getenv("_LUX_L_DEBUG") != NULL) (void) printf

/* Getting status */
#define	G_DPRINTF	if (getenv("_LUX_G_DEBUG") != NULL) (void) printf

/* Box list */
#define	B_DPRINTF	if (getenv("_LUX_B_DEBUG") != NULL) (void) printf

/* Non-Photon disks */
#define	N_DPRINTF	if (getenv("_LUX_N_DEBUG") != NULL) (void) printf

/* Null WWN FCdisks */
#define	W_DPRINTF	if (getenv("_LUX_W_DEBUG") != NULL) (void) printf

/* Devices */
#define	D_DPRINTF	if (getenv("_LUX_D_DEBUG") != NULL) (void) printf

/* Enable/Bypass */
#define	E_DPRINTF	if (getenv("_LUX_E_DEBUG") != NULL) (void) printf

/* Standard Error messages. */
#define	ER_DPRINTF	if (getenv("_LUX_ER_DEBUG") != NULL) (void) printf

/* Retries */
#define	R_DPRINTF	if (getenv("_LUX_R_DEBUG") != NULL) (void) printf

/* Threads & Timing */
#define	T_DPRINTF	if (getenv("_LUX_T_DEBUG") != NULL) (void) printf

/* Allocation */
#define	A_DPRINTF	if (getenv("_LUX_A_DEBUG") != NULL) (void) printf




/* Warning messages */
#define	L_WARNINGS	if (getenv("_LUX_WARNINGS") != NULL) (void) printf


#define	MIN(a, b)		(a < b ? a : b)

/*
 * format parameter to dump()
 */
#define	HEX_ONLY	0	/* print hex only */
#define	HEX_ASCII	1	/* hex and ascii */

#ifdef	__cplusplus
}
#endif

#endif	/* _L_COMMON_H */
