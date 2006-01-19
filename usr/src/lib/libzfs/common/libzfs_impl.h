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

#include <libzfs.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct zfs_handle {
	char zfs_name[ZFS_MAXNAMELEN];
	zfs_type_t zfs_type;
	dmu_objset_stats_t zfs_dmustats;
	zfs_stats_t zfs_zplstats;
	uint64_t zfs_volsize;
	uint64_t zfs_volblocksize;
	char *zfs_mntopts;
};

struct zpool_handle {
	char zpool_name[ZPOOL_MAXNAMELEN];
	int zpool_state;
	size_t zpool_config_size;
	nvlist_t *zpool_config;
	nvlist_t *zpool_old_config;
};

void zfs_error(const char *, ...);
void zfs_fatal(const char *, ...);
void *zfs_malloc(size_t);
char *zfs_strdup(const char *);
void no_memory(void);

#define	zfs_baderror(err)						\
	(zfs_fatal(dgettext(TEXT_DOMAIN,				\
	"internal error: unexpected error %d at line %d of %s"),	\
	(err), (__LINE__), (__FILE__)))

int zfs_fd;

char **get_dependents(const char *, size_t *);

FILE *mnttab_file;
FILE *sharetab_file;

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

zfs_handle_t *make_dataset_handle(const char *);
void set_pool_health(nvlist_t *config);

zpool_handle_t *zpool_open_silent(const char *pool);

int zvol_create_link(const char *dataset);
int zvol_remove_link(const char *dataset);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBFS_IMPL_H */
