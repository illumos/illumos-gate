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

#ifndef	_SYS_OBPDEFS_H
#define	_SYS_OBPDEFS_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This file is intended as standalone inclusion by non-prom library
 * functions that need it.
 */

typedef int	ihandle_t;		/* 1275 device instance number */
typedef int	phandle_t;		/* 1275 device tree node ptr */
typedef	phandle_t pnode_t;

/*
 * Device type matching
 */

#define	OBP_NONODE	((pnode_t)0)
#define	OBP_BADNODE	((pnode_t)-1)

/*
 * Property Defines
 */

#define	OBP_NAME		"name"
#define	OBP_REG			"reg"
#define	OBP_INTR		"intr"
#define	OBP_RANGES		"ranges"
#define	OBP_INTERRUPTS		"interrupts"
#define	OBP_COMPATIBLE		"compatible"
#define	OBP_STATUS		"status"
#define	OBP_BOARDNUM		"board#"

#define	OBP_MAC_ADDR		"mac-address"
#define	OBP_STDINPATH		"stdin-path"
#define	OBP_STDOUTPATH		"stdout-path"
#define	OBP_IDPROM		"idprom"

#define	OBP_DEVICETYPE		"device_type"
#define	OBP_DISPLAY		"display"
#define	OBP_NETWORK		"network"
#define	OBP_BYTE		"byte"
#define	OBP_BLOCK		"block"
#define	OBP_SERIAL		"serial"
#define	OBP_HIERARCHICAL	"hierarchical"
#define	OBP_CPU			"cpu"
#define	OBP_ADDRESS		"address"

/*
 * OBP status values defines
 */
#define	OBP_ST_OKAY		"okay"
#define	OBP_ST_DISABLED		"disabled"
#define	OBP_ST_FAIL		"fail"

/*
 * Max size of a path component and a property name (not value)
 * These are standard definitions.
 */
#define	OBP_MAXDRVNAME		32	/* defined in P1275 */
#define	OBP_MAXPROPNAME		32	/* defined in P1275 */

/*
 *
 * NB: Max pathname length is a platform-dependent parameter.
 */
#define	OBP_MAXPATHLEN		256	/* Platform dependent */

/*
 *  Every OBP node must have a `/' followed by at least 2 chars,
 *  so we can deduce the maxdepth of any OBP tree to be
 *  OBP_MAXPATHNAME/3.  This is a good first swag.
 */

#define	OBP_STACKDEPTH		(OBP_MAXPATHLEN/3)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_OBPDEFS_H */
