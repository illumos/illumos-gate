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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _LIBZFS_JNI_POOL_H
#define	_LIBZFS_JNI_POOL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <jni.h>
#include <libnvpair.h>
#include <libzfs.h>
#include <libzfs_jni_ipool.h>
#include <libzfs_jni_util.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Types
 */

typedef struct DeviceStatsBean {
	jmethodID method_setSize;
	jmethodID method_setReplacementSize;
	jmethodID method_setUsed;
	jmethodID method_setReadBytes;
	jmethodID method_setWriteBytes;
	jmethodID method_setReadOperations;
	jmethodID method_setWriteOperations;
	jmethodID method_setReadErrors;
	jmethodID method_setWriteErrors;
	jmethodID method_setChecksumErrors;
	jmethodID method_setDeviceState;
	jmethodID method_setDeviceStatus;
} DeviceStatsBean_t;

typedef struct PoolStatsBean {
	DeviceStatsBean_t super;
	jmethodID method_setPoolState;
	jmethodID method_setPoolStatus;
	jmethodID method_setPoolVersion;
} PoolStatsBean_t;

/*
 * Function prototypes
 */

void new_DeviceStats(JNIEnv *, DeviceStatsBean_t *, zjni_Object_t *);
void new_PoolStats(JNIEnv *, PoolStatsBean_t *, zjni_Object_t *);
nvlist_t *zjni_get_root_vdev(zpool_handle_t *);
nvlist_t *zjni_get_vdev(zpool_handle_t *, nvlist_t *, uint64_t, uint64_t *);
jobject zjni_get_VirtualDevice_from_vdev(
    JNIEnv *, zpool_handle_t *, nvlist_t *, uint64_t *p_vdev_id);
jobject zjni_get_VirtualDevices_from_vdev(
    JNIEnv *, zpool_handle_t *, nvlist_t *, uint64_t *p_vdev_id);
int zjni_create_add_ImportablePool(nvlist_t *, void *);
int populate_DeviceStatsBean(
    JNIEnv *, nvlist_t *, DeviceStatsBean_t *, zjni_Object_t *);
jobject zjni_pool_state_to_obj(JNIEnv *, pool_state_t);
jobject zjni_pool_status_to_obj(JNIEnv *, zpool_status_t);

#ifdef __cplusplus
}
#endif

#endif /* _LIBZFS_JNI_POOL_H */
