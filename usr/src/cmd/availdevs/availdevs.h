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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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

/* Command-line arguments */
#define	CLI_ARG_ALL			'a'
#define	CLI_ARG_DEVICES			'd'
#define	CLI_ARG_POOLS			'p'
#define	CLI_OPTSTRING			"apd"

/* Must match the values in XMLDataModel.java */
#define	ELEMENT_ALIAS			"alias"
#define	ELEMENT_AVAILABLE		"available"
#define	ELEMENT_DISK			"disk"
#define	ELEMENT_IMPORTABLE		"importable"
#define	ELEMENT_POOL			"pool"
#define	ELEMENT_ROOT			"zfsconfig"
#define	ELEMENT_SLICE			"slice"

#define	ATTR_ALIAS_NAME			"name"
#define	ATTR_DEVICE_STATE		"devicestate"
#define	ATTR_DEVICE_STATUS		"devicestatus"
#define	ATTR_DISK_INUSE			"inuse"
#define	ATTR_DISK_NAME			"name"
#define	ATTR_DISK_SIZE			"size"
#define	ATTR_POOL_CHECKSUM_ERRORS	"checksumerrors"
#define	ATTR_POOL_ID			"id"
#define	ATTR_POOL_NAME			"name"
#define	ATTR_POOL_READ_BYTES		"readbytes"
#define	ATTR_POOL_READ_ERRORS		"readerrors"
#define	ATTR_POOL_READ_OPERATIONS	"readoperations"
#define	ATTR_POOL_REPLACEMENT_SIZE	"replacementsize"
#define	ATTR_POOL_SIZE			"size"
#define	ATTR_POOL_STATE			"poolstate"
#define	ATTR_POOL_STATUS		"poolstatus"
#define	ATTR_POOL_VERSION		"poolversion"
#define	ATTR_POOL_USED			"used"
#define	ATTR_POOL_WRITE_BYTES		"writebytes"
#define	ATTR_POOL_WRITE_ERRORS		"writeerrors"
#define	ATTR_POOL_WRITE_OPERATIONS	"writeoperations"
#define	ATTR_SLICE_NAME			"name"
#define	ATTR_SLICE_SIZE			"size"
#define	ATTR_SLICE_START		"start"
#define	ATTR_SLICE_USED_BY		"used-by"
#define	ATTR_SLICE_USED_NAME		"used-name"

#define	VAL_ATTR_FALSE			"false"
#define	VAL_ATTR_TRUE			"true"

#ifdef __cplusplus
}
#endif

#endif /* _AVAILDEVS_H */
