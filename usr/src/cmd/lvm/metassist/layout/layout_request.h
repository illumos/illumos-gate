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

#ifndef _LAYOUT_REQUEST_H
#define	_LAYOUT_REQUEST_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include "libdiskmgt.h"

#include "volume_dlist.h"
#include "volume_defaults.h"
#include "volume_devconfig.h"

/* XXX these are really in layout.c */
extern int string_case_compare(char *str1, char *str2);
extern int add_modified_disk(devconfig_t *request, dm_descriptor_t diskx);
extern int add_to_hsp_list(dlist_t *devices);

extern int release_request_caches();

extern int set_request_diskset(char *disksset);
extern char *get_request_diskset();
extern void unset_request_diskset();

extern int set_toplevel_request(devconfig_t *request);
extern void unset_toplevel_request();

extern int set_request_defaults(defaults_t *defaults);
extern void unset_request_defaults();

extern int get_device_access_name(
	devconfig_t	*request,
	dm_descriptor_t desc,
	char		**name);

/*
 * get list of HBAs, disks or slices that are available
 * to satisfy the given request
 */
extern int slice_is_available(
	char		*name,
	devconfig_t	*request,
	boolean_t	*bool);

extern int disks_get_avail_slices(
	devconfig_t	*request,
	dlist_t		*disks,
	dlist_t		**slices);

extern int select_hbas_with_n_disks(
	devconfig_t	*request,
	dlist_t		*hbas,
	int		mindisks,
	dlist_t		**selhbas,
	dlist_t		**seldisks);

extern int hba_get_avail_disks_and_space(
	devconfig_t	*request,
	dm_descriptor_t	hba,
	dlist_t		**list,
	uint64_t	*space);

/*
 * get lists of HBAs and disks that are used by volumes
 */
extern int get_hbas_and_disks_used_by_volumes(
	dlist_t		*volumes,
	dlist_t		**hbas,
	dlist_t		**disks);

extern int get_hbas_and_disks_used_by_volume(
	devconfig_t	*volume,
	dlist_t		**hbas,
	dlist_t		**disks);

/*
 * accessors to get user-settable device parameters,
 * values come from either the request or the diskset
 * or global defaults
 */
extern int get_stripe_min_comp(
	devconfig_t	*request,
	uint16_t	*val);

extern int get_stripe_max_comp(
	devconfig_t	*request,
	uint16_t	*val);

extern int get_stripe_interlace(
	devconfig_t	*request,
	uint64_t	*val);

extern int get_mirror_read_strategy(
	devconfig_t	*request,
	mirror_read_strategy_t	*val);

extern int get_mirror_write_strategy(
	devconfig_t	*request,
	mirror_write_strategy_t	*val);

extern int get_mirror_pass(
	devconfig_t	*request,
	uint16_t	*val);

extern int get_mirror_nsubs(
	devconfig_t	*request,
	uint16_t	*val);

extern int get_volume_faultrecov(
	devconfig_t	*request,
	boolean_t	*val);

extern int get_volume_redundancy_level(
	devconfig_t	*request,
	uint16_t	*val);

extern int get_volume_npaths(
	devconfig_t	*request,
	uint16_t	*val);

extern int get_default_hsp_name(
	devconfig_t	*req,
	char		**name);

extern int get_disks_for_target(
	char		*name,
	dlist_t		**disks);

#ifdef __cplusplus
}
#endif

#endif /* _LAYOUT_REQUEST_H */
