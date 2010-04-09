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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _DISK_H
#define	_DISK_H

#include <fm/topo_mod.h>
#include <fm/topo_hc.h>
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

struct topo_list;

/* Methods shared with the ses module (disk_common.c) */
extern int disk_list_gather(topo_mod_t *, struct topo_list *);
extern void disk_list_free(topo_mod_t *, struct topo_list *);
extern int disk_declare_non_enumerated(topo_mod_t *, tnode_t *, tnode_t **);
extern int disk_declare_path(topo_mod_t *, tnode_t *,
    struct topo_list *, const char *);
extern int disk_declare_addr(topo_mod_t *, tnode_t *,
    struct topo_list *, const char *, tnode_t **);
extern char *disk_auth_clean(topo_mod_t *, const char *);

#ifdef __cplusplus
}
#endif

#endif /* _DISK_H */
