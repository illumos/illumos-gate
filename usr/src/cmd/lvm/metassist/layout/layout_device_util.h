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

#ifndef _LAYOUT_DEVICE_UTIL_H
#define	_LAYOUT_DEVICE_UTIL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <libdiskmgt.h>

extern boolean_t	is_alt_slice_name(char *name);
extern boolean_t	is_did_name(char *name);
extern boolean_t	is_did_slice_name(char *name);
extern boolean_t	is_did_disk_name(char *name);
extern boolean_t	is_ctd_name(char *name);
extern boolean_t	is_ctd_slice_name(char *name);
extern boolean_t	is_ctd_disk_name(char *name);
extern boolean_t	is_ctd_target_name(char *name);
extern boolean_t	is_ctd_ctrl_name(char *name);

extern int	set_display_name(dm_descriptor_t desc, char *name);
extern int	get_display_name(dm_descriptor_t slice, char **name);

extern int	slice_get_by_name(char *name, dm_descriptor_t *slicep);
extern int	disk_get_by_name(char *name, dm_descriptor_t *diskp);
extern int	hba_get_by_name(char *name, dm_descriptor_t *hbap);

extern int	extract_diskname(char *slicename, char **diskname);
extern int	extract_hbaname(char *slicename, char **hbaname);

extern int	get_disk_for_named_slice(char *slicename,
	dm_descriptor_t *diskp);

/*
 * functions to manipulate devices
 */
extern int	group_similar_hbas(dlist_t *hbas, dlist_t **list);
extern int	hba_is_multiplex(dm_descriptor_t hba, boolean_t *bool);

extern int	hba_set_n_avail_disks(dm_descriptor_t hba, uint16_t val);
extern int	hba_get_n_avail_disks(dm_descriptor_t hba, uint16_t *val);

extern int	hba_get_type(dm_descriptor_t hba, char **type);
extern int	hba_is_fast(dm_descriptor_t hba, boolean_t *bool);
extern int	hba_is_fast_20(dm_descriptor_t hba, boolean_t *bool);
extern int	hba_is_fast_40(dm_descriptor_t hba, boolean_t *bool);
extern int	hba_is_fast_80(dm_descriptor_t hba, boolean_t *bool);
extern int	hba_supports_protocol(
	dm_descriptor_t hba, char *attr, boolean_t *bool);
extern int	hba_supports_wide(dm_descriptor_t hba, boolean_t *bool);

extern int	disk_get_available_slice_index(
	dm_descriptor_t diskp, uint32_t *index);

extern int	disk_get_hbas(dm_descriptor_t disk, dlist_t **list);
extern int	disk_get_paths(dm_descriptor_t disk, dlist_t **list);
extern int	disk_get_slices(dm_descriptor_t disk, dlist_t **list);
extern int	disk_get_aliases(dm_descriptor_t disk, dlist_t **list);
extern int	disk_get_blocksize(dm_descriptor_t disk, uint64_t *val);
extern int	disk_get_ncylinders(dm_descriptor_t disk, uint64_t *val);
extern int	disk_get_size_in_blocks(dm_descriptor_t disk, uint64_t *val);
extern int	disk_get_start_block(dm_descriptor_t disk, uint64_t *val);
extern int	disk_get_nheads(dm_descriptor_t disk, uint64_t *val);
extern int	disk_get_nsectors(dm_descriptor_t disk, uint64_t *val);
extern int	disk_get_is_efi(dm_descriptor_t disk, boolean_t *val);
extern int	disk_get_has_fdisk(dm_descriptor_t disk, boolean_t *val);
extern int	disk_get_has_solaris_partition(dm_descriptor_t disk,
	boolean_t *val);
extern int	disk_get_is_online(dm_descriptor_t disk, boolean_t *val);
extern int	disk_get_drive_type(dm_descriptor_t disk, uint32_t *val);
extern int	disk_get_media_type(dm_descriptor_t disk, uint32_t *type);
extern int	disk_reserve_index(dm_descriptor_t disk, uint16_t index);
extern int	disk_release_index(dm_descriptor_t disk, uint16_t index);

extern int	slice_get_hbas(dm_descriptor_t slice, dlist_t **list);
extern int	slice_get_disk(dm_descriptor_t slice, dm_descriptor_t *diskp);
extern int	slice_get_size(dm_descriptor_t slice, uint64_t *val);
extern int	slice_get_index(dm_descriptor_t slice, uint32_t *val);
extern int	slice_get_size_in_blocks(dm_descriptor_t slice, uint64_t *val);
extern int	slice_get_start_block(dm_descriptor_t slice, uint64_t *val);
extern int	slice_get_start(dm_descriptor_t slice, uint64_t *val);

extern int	slice_set_size(dm_descriptor_t slice, uint64_t size);
extern int	slice_set_size_in_blocks(dm_descriptor_t slice, uint64_t size);
extern int	slice_set_start_block(dm_descriptor_t slice, uint64_t start);

/*
 * virtual slice utilities.
 */
extern int	create_virtual_slices(dlist_t *unused);
extern int	add_virtual_slice(char *name, uint32_t index,
	uint64_t startblk, uint64_t sizeblks, dm_descriptor_t disk);

extern void	release_virtual_slices();
extern int	get_virtual_slices(dlist_t **list);
extern boolean_t is_virtual_slice(dm_descriptor_t slice);

/*
 * shared error output functions for dm_descriptor_t objects
 */
extern void print_get_assoc_desc_error(
	dm_descriptor_t desc, char *which, int error);
extern void print_get_desc_attr_error(
	dm_descriptor_t desc, char *devtype, char *attr, int error);

extern void print_set_desc_attr_error(
	dm_descriptor_t desc, char *devtype, char *attr, int error);

#ifdef __cplusplus
}
#endif

#endif /* _LAYOUT_DEVICE_UTIL_H */
