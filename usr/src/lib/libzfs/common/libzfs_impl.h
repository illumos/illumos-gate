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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LIBFS_IMPL_H
#define	_LIBFS_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/dmu.h>
#include <sys/fs/zfs.h>
#include <sys/zfs_ioctl.h>
#include <sys/zfs_acl.h>
#include <sys/nvpair.h>

#include <libuutil.h>
#include <libzfs.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct libzfs_handle {
	int libzfs_error;
	int libzfs_fd;
	FILE *libzfs_mnttab;
	FILE *libzfs_sharetab;
	uu_avl_pool_t *libzfs_ns_avlpool;
	uu_avl_t *libzfs_ns_avl;
	uint64_t libzfs_ns_gen;
	int libzfs_desc_active;
	char libzfs_action[1024];
	char libzfs_desc[1024];
	int libzfs_printerr;
};

struct zfs_handle {
	libzfs_handle_t *zfs_hdl;
	char zfs_name[ZFS_MAXNAMELEN];
	zfs_type_t zfs_type;
	dmu_objset_stats_t zfs_dmustats;
	nvlist_t *zfs_props;
	uint64_t zfs_volsize;
	uint64_t zfs_volblocksize;
	char *zfs_mntopts;
	char zfs_root[MAXPATHLEN];
};

struct zpool_handle {
	libzfs_handle_t *zpool_hdl;
	char zpool_name[ZPOOL_MAXNAMELEN];
	int zpool_state;
	size_t zpool_config_size;
	nvlist_t *zpool_config;
	nvlist_t *zpool_old_config;
	nvlist_t **zpool_error_log;
	size_t zpool_error_count;
};

int zfs_error(libzfs_handle_t *, int, const char *, ...);
void zfs_error_aux(libzfs_handle_t *, const char *, ...);
void *zfs_alloc(libzfs_handle_t *, size_t);
char *zfs_strdup(libzfs_handle_t *, const char *);
int no_memory(libzfs_handle_t *);

int zfs_standard_error(libzfs_handle_t *, int, const char *, ...);
int zpool_standard_error(libzfs_handle_t *, int, const char *, ...);

char **get_dependents(libzfs_handle_t *, const char *, size_t *);

typedef struct prop_changelist prop_changelist_t;

int changelist_prefix(prop_changelist_t *);
int changelist_postfix(prop_changelist_t *);
void changelist_rename(prop_changelist_t *, const char *, const char *);
void changelist_remove(zfs_handle_t *, prop_changelist_t *);
void changelist_free(prop_changelist_t *);
prop_changelist_t *changelist_gather(zfs_handle_t *, zfs_prop_t, int);
int changelist_unshare(prop_changelist_t *);
int changelist_haszonedchild(prop_changelist_t *);

void remove_mountpoint(zfs_handle_t *);

zfs_handle_t *make_dataset_handle(libzfs_handle_t *, const char *);
int set_pool_health(nvlist_t *);

zpool_handle_t *zpool_open_silent(libzfs_handle_t *, const char *);

int zvol_create_link(libzfs_handle_t *, const char *);
int zvol_remove_link(libzfs_handle_t *, const char *);

void namespace_clear(libzfs_handle_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBFS_IMPL_H */
