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

#ifndef _DISK_H
#define	_DISK_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fm/topo_mod.h>
#include <libdevinfo.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Topo plugin version */
#define	DISK_VERSION			TOPO_VERSION

/* Max. number of devices for thumper */
#define	DEVID_MAX		48

/* Properties added to the "storage" pgroup: */
#define	TOPO_PGROUP_STORAGE		"storage"
#define	TOPO_STORAGE_LOGICAL_DISK_NAME	"logical-disk"
#define	TOPO_STORAGE_MODEL		"model"
#define	TOPO_STORAGE_MANUFACTURER	"manufacturer"
#define	TOPO_STORAGE_SERIAL_NUM		"serial-number"
#define	TOPO_STORAGE_FIRMWARE_REV	"firmware-revision"
#define	TOPO_STORAGE_CAPACITY		"capacity-in-bytes"

/*
 * Properties for binding group: The binding group required in platform
 * specific xml that describes 'bay' nodes containing internal disks.
 */
#define	TOPO_PGROUP_BINDING		"binding"
#define	TOPO_BINDING_OCCUPANT		"occupant-path"

struct topo_list;

/* Methods shared with the ses module (disk_common.c) */
extern int disk_list_gather(topo_mod_t *, struct topo_list *);
extern void disk_list_free(topo_mod_t *, struct topo_list *);
extern int disk_declare_path(topo_mod_t *, tnode_t *,
    struct topo_list *, const char *);
extern int disk_declare_addr(topo_mod_t *, tnode_t *,
    struct topo_list *, const char *);

#ifdef __cplusplus
}
#endif

#endif /* _DISK_H */
