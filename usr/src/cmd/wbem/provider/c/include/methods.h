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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_METHODS_H
#define	_METHODS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/* include the cimapi, this in turn includes the cimstructs.h which we need */
#include <cimapi.h>
#include <cimlogsvc.h>
#include <cimauthcheck.h>

/* constant definitions */
#define	PROPTRUE	"1"
#define	PROPFALSE	"0"
#define	DISK_WRITE_RIGHT	"solaris.admin.diskmgr.write"
#define	DISK_READ_RIGHT		"solaris.admin.diskmgr.read"

/* function prototypes */

CCIMProperty *create_default_fdisk_partition(CCIMObjectPath *op);
CCIMProperty *create_filesystem(CCIMObjectPath *op);
CCIMProperty *create_fdisk_partitions(CCIMPropertyList *, CCIMObjectPath *);
CCIMProperty *create_partitions(CCIMPropertyList *, CCIMObjectPath *);
CCIMProperty *get_disk_geometry(CCIMPropertyList *, CCIMObjectPath *);
CCIMProperty *getFdisk(CCIMPropertyList *, CCIMObjectPath *);
CCIMProperty *label_disk(CCIMPropertyList *, CCIMObjectPath *);

#ifdef	__cplusplus
}
#endif

#endif /* _METHODS_H */
