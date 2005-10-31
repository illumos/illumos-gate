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

#ifndef _AVAILDEVS_H
#define	_AVAILDEVS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Constants
 */

/* Must match the values in XMLDataModel.java */
#define	ELEMENT_ROOT			"zfsconfig"
#define	ELEMENT_AVAILABLE		"available"
#define	ELEMENT_DISK			"disk"
#define	ELEMENT_ALIAS			"alias"
#define	ELEMENT_SLICE			"slice"
#define	ATTR_DISK_NAME			"name"
#define	ATTR_DISK_SIZE			"size"
#define	ATTR_DISK_INUSE			"inuse"
#define	ATTR_ALIAS_NAME			"name"
#define	ATTR_SLICE_NAME			"name"
#define	ATTR_SLICE_SIZE			"size"
#define	ATTR_SLICE_START		"start"
#define	ATTR_SLICE_USED_NAME		"used-name"
#define	ATTR_SLICE_USED_BY		"used-by"
#define	VAL_ATTR_TRUE			"true"
#define	VAL_ATTR_FALSE			"false"

#ifdef __cplusplus
}
#endif

#endif /* _AVAILDEVS_H */
