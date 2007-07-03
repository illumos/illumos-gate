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

#ifndef _DISK_H
#define	_DISK_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/* Topo plugin version */
#define	DISK_VERSION			TOPO_VERSION

/* Max. number of devices for thumper */
#define	DEVID_MAX		48

/* Properties for binding group */
#define	TOPO_BINDING_PGROUP		"binding"
#define	TOPO_BINDING_OCCUPANT		"occupant-path"

/* Properties added to the "storage" pgroup: */
#define	TOPO_STORAGE_PGROUP		"storage"
#define	TOPO_STORAGE_LOGICAL_DISK_NAME	"logical-disk"
#define	TOPO_STORAGE_MODEL		"model"
#define	TOPO_STORAGE_MANUFACTURER	"manufacturer"
#define	TOPO_STORAGE_SERIAL_NUM		"serial-number"
#define	TOPO_STORAGE_FIRMWARE_REV	"firmware-revision"
#define	TOPO_STORAGE_CAPACITY		"capacity-in-bytes"

#ifdef __cplusplus
}
#endif

#endif /* _DISK_H */
