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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _PARTITION_H
#define	_PARTITION_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <libdevinfo.h>
#include <sys/dkio.h>
#include <sys/dktp/fdisk.h>
#include <devid.h>

descriptor_t	**partition_get_descriptors(int filter[], int *errp);
descriptor_t	**partition_get_assoc_descriptors(descriptor_t *desc,
		    dm_desc_type_t type, int *errp);
descriptor_t	**partition_get_assocs(descriptor_t *desc, int *errp);
descriptor_t	*partition_get_descriptor_by_name(char *name, int *errp);
char		*partition_get_name(descriptor_t *desc);
nvlist_t	*partition_get_attributes(descriptor_t *desc, int *errp);
nvlist_t	*partition_get_stats(descriptor_t *desc, int stat_type,
		    int *errp);
int		partition_has_fdisk(disk_t *dp, int fd);
int		partition_make_descriptors();

#ifdef __cplusplus
}
#endif

#endif /* _PARTITION_H */
