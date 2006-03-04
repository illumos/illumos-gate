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

#ifndef	_SYS_ZFS_IOCTL_H
#define	_SYS_ZFS_IOCTL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/cred.h>
#include <sys/dmu.h>
#include <sys/zio.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Property values for snapdir
 */
#define	ZFS_SNAPDIR_HIDDEN		0
#define	ZFS_SNAPDIR_VISIBLE		1

#define	DMU_BACKUP_VERSION (1ULL)
#define	DMU_BACKUP_MAGIC 0x2F5bacbacULL

/*
 * zfs ioctl command structure
 */
typedef struct dmu_replay_record {
	enum {
		DRR_BEGIN, DRR_OBJECT, DRR_FREEOBJECTS,
		DRR_WRITE, DRR_FREE, DRR_END,
	} drr_type;
	uint32_t drr_pad;
	union {
		struct drr_begin {
			uint64_t drr_magic;
			uint64_t drr_version;
			uint64_t drr_creation_time;
			dmu_objset_type_t drr_type;
			uint32_t drr_pad;
			uint64_t drr_toguid;
			uint64_t drr_fromguid;
			char drr_toname[MAXNAMELEN];
		} drr_begin;
		struct drr_end {
			zio_cksum_t drr_checksum;
		} drr_end;
		struct drr_object {
			uint64_t drr_object;
			dmu_object_type_t drr_type;
			dmu_object_type_t drr_bonustype;
			uint32_t drr_blksz;
			uint32_t drr_bonuslen;
			uint8_t drr_checksum;
			uint8_t drr_compress;
			uint8_t drr_pad[6];
		} drr_object;
		struct drr_freeobjects {
			uint64_t drr_firstobj;
			uint64_t drr_numobjs;
		} drr_freeobjects;
		struct drr_write {
			uint64_t drr_object;
			dmu_object_type_t drr_type;
			uint32_t drr_pad;
			uint64_t drr_offset;
			uint64_t drr_length;
		} drr_write;
		struct drr_free {
			uint64_t drr_object;
			uint64_t drr_offset;
			uint64_t drr_length;
		} drr_free;
	} drr_u;
} dmu_replay_record_t;

typedef struct zinject_record {
	uint64_t	zi_objset;
	uint64_t	zi_object;
	uint64_t	zi_start;
	uint64_t	zi_end;
	uint64_t	zi_guid;
	uint32_t	zi_level;
	uint32_t	zi_error;
	uint64_t	zi_type;
	uint32_t	zi_freq;
} zinject_record_t;

#define	ZINJECT_NULL		0x1
#define	ZINJECT_FLUSH_ARC	0x2
#define	ZINJECT_UNLOAD_SPA	0x4

typedef struct zfs_cmd {
	char		zc_name[MAXNAMELEN];
	char		zc_prop_name[MAXNAMELEN];
	char		zc_prop_value[MAXPATHLEN];
	char		zc_root[MAXPATHLEN];
	char		zc_filename[MAXNAMELEN];
	uint32_t	zc_intsz;
	uint32_t	zc_numints;
	uint64_t	zc_guid;
	uint64_t	zc_config_src;	/* really (char *) */
	uint64_t	zc_config_src_size;
	uint64_t	zc_config_dst;	/* really (char *) */
	uint64_t	zc_config_dst_size;
	uint64_t	zc_cookie;
	uint64_t	zc_cred;
	uint64_t	zc_dev;
	uint64_t	zc_volsize;
	uint64_t	zc_volblocksize;
	uint64_t	zc_objset_type;
	dmu_objset_stats_t zc_objset_stats;
	struct drr_begin zc_begin_record;
	zinject_record_t zc_inject_record;
	zbookmark_t	zc_bookmark;
} zfs_cmd_t;

#define	ZVOL_MAX_MINOR	(1 << 16)
#define	ZFS_MIN_MINOR	(ZVOL_MAX_MINOR + 1)

#ifdef _KERNEL

extern dev_info_t *zfs_dip;

extern int zfs_secpolicy_write(const char *dataset, const char *, cred_t *cr);
extern int zfs_busy(void);

extern int zvol_check_volsize(zfs_cmd_t *zc, uint64_t blocksize);
extern int zvol_check_volblocksize(zfs_cmd_t *zc);
extern int zvol_get_stats(zfs_cmd_t *zc, objset_t *os);
extern void zvol_create_cb(objset_t *os, void *arg, dmu_tx_t *tx);
extern int zvol_create_minor(zfs_cmd_t *zc);
extern int zvol_remove_minor(zfs_cmd_t *zc);
extern int zvol_set_volsize(zfs_cmd_t *zc);
extern int zvol_set_volblocksize(zfs_cmd_t *zc);
extern int zvol_open(dev_t *devp, int flag, int otyp, cred_t *cr);
extern int zvol_close(dev_t dev, int flag, int otyp, cred_t *cr);
extern int zvol_strategy(buf_t *bp);
extern int zvol_read(dev_t dev, uio_t *uiop, cred_t *cr);
extern int zvol_write(dev_t dev, uio_t *uiop, cred_t *cr);
extern int zvol_aread(dev_t dev, struct aio_req *aio, cred_t *cr);
extern int zvol_awrite(dev_t dev, struct aio_req *aio, cred_t *cr);
extern int zvol_ioctl(dev_t dev, int cmd, intptr_t arg, int flag, cred_t *cr,
    int *rvalp);
extern int zvol_busy(void);
extern void zvol_init(void);
extern void zvol_fini(void);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ZFS_IOCTL_H */
