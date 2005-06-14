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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _VOLUME_SVM_UTIL_H
#define	_VOLUME_SVM_UTIL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include "volume_devconfig.h"

/*
 * scan existing SVM config for the named diskset
 * and build lists of device, HSP and diskset names.
 */
extern int		scan_svm_names(char *diskset);
extern void		release_svm_names();

extern int		hsp_get_default_for_diskset(char *diskset,
	devconfig_t **hsp);
extern int		hsp_get_by_name(char *diskset, char *hspname,
	devconfig_t **hsp);

extern int		get_next_volume_name(char **name,
	component_type_t type);
extern int		get_next_hsp_name(char **name);
extern int		get_next_submirror_name(char *mname, char **subname);

extern int		reserve_volume_name(char *name);
extern int		reserve_hsp_name(char *name);

extern void		release_volume_name(char *name);
extern void		release_hsp_name(char *name);

extern boolean_t	is_volume_name_valid(char *name);
extern boolean_t	is_hsp_name_valid(char *name);

extern boolean_t	is_volume_name_in_range(char *name);

extern int get_disks_in_diskset(char *dsname, dlist_t **disks);

extern int		is_disk_in_diskset(
	dm_descriptor_t disk, char *diskset, boolean_t *bool);
extern int		is_disk_in_other_diskset(
	dm_descriptor_t disk, char *diskset, boolean_t *bool);

extern boolean_t	diskset_exists(char *name);
extern uint64_t		get_default_stripe_interlace();

extern int		get_n_metadb_replicas(int *nreplicas);
extern int		get_max_number_of_devices(int *max);
extern int		get_max_number_of_disksets(int *max);

extern int		is_reserved_replica_slice_index(
	char *diskset, char *dname, uint32_t index, boolean_t *bool);

#ifdef __cplusplus
}
#endif

#endif /* _VOLUME_SVM_UTIL_H */
