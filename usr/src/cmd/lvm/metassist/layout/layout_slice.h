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

#ifndef _LAYOUT_SLICE_H
#define	_LAYOUT_SLICE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include "libdiskmgt.h"
#include "volume_devconfig.h"
#include "volume_dlist.h"

/*
 * struct to track which slices need to be explicitly "removed" from
 * the system before applying any metassist updates/changes.
 */
typedef struct {
	char		*slice_name;
	uint32_t	slice_index;
} rmvdslice_t;

extern void release_slices_to_remove();
extern dlist_t *get_slices_to_remove();
extern int add_slice_to_remove(char *name, uint32_t index);

/*
 * struct to track which slices have been explicitly modified
 * during the layout process...
 *
 * src_slice_desc is the dm_descriptor_t of the slice which provided the
 *	space (this is only relevant to slices that have been created by
 *	 taking space from some other "source" slice).
 * slice_devconfig is the devconfig_t struct with the modified slice properties.
 * times_modified is the number of times the slice has been modified
 *	(this is only relevant to slices that have been resized to
 *	 provide space for new slices)
 * volume_component is used to control when the slice_devcfg is freed.
 *      if volume_component is B_TRUE, the devconfig is returned as part
 *      of the result of layout and so cannot be freed by
 *	release_modified_slices.
 */
typedef struct {
	dm_descriptor_t	src_slice_desc;
	devconfig_t	*slice_devcfg;
	int		times_modified;
	boolean_t	volume_component;
} modslice_t;

extern dlist_t *get_modified_slices();
extern int release_modified_slices();

extern int make_slicename_for_diskname_and_index(
	char	*diskname,
	uint16_t index,
	char	**slicename);

extern int assemble_modified_slice(
	dm_descriptor_t src_slice_desc,
	char		*mod_name,
	uint32_t	mod_index,
	uint64_t	mod_stblk,
	uint64_t	mod_nblks,
	uint64_t	mod_size,
	devconfig_t	**mod_slice);

extern int choose_slice(
	uint64_t  	nbytes,
	uint16_t  	npaths,
	dlist_t   	*slices,
	dlist_t   	*used,
	dlist_t		*used_hbas,
	dlist_t   	*used_disks,
	boolean_t  	unused_disk,
	boolean_t  	nbytes_is_min,
	boolean_t  	add_extra_cyl,
	devconfig_t 	**chosen);

extern int create_devconfig_for_slice(
	dm_descriptor_t slice,
	devconfig_t 	**newslice);

extern int destroy_new_slice(
	devconfig_t *vol);

/*
 * accessors for the list of used slice names for named diskset.
 */
extern int	is_used_slice(dm_descriptor_t slice, boolean_t *is_used);
extern int	add_used_slice_by_name(char *slicename);
extern int	remove_used_slice_by_name(char *slicename);
extern int	add_used_slice(dm_descriptor_t slice);
extern void	release_used_slices();
extern int	disk_has_used_slice(dm_descriptor_t disk, boolean_t *inuse);

/*
 * accessors to track slices reserved for use in explicit
 * volume requests
 */
extern int	add_reserved_slice(dm_descriptor_t slice);
extern int	is_reserved_slice(dm_descriptor_t slice, boolean_t *is_rsvd);
extern int	get_reserved_slices(dlist_t **list);
extern void	release_reserved_slices();

#ifdef __cplusplus
}
#endif

#endif /* _LAYOUT_SLICE_H */
