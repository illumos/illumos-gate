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

#ifndef _LIBZFS_JNI_DATASET_H
#define	_LIBZFS_JNI_DATASET_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libzfs_jni_util.h>
#include <libzfs.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Types
 */

typedef struct zjni_DatasetArrayCallbackData {
	zjni_ArrayCallbackData_t data;
	zfs_type_t typemask;
} zjni_DatasetArrayCallbackData_t;

/*
 * Function prototypes
 */

jobjectArray zjni_get_Datasets_below(JNIEnv *, jstring,
    zfs_type_t, zfs_type_t, char *);
jobjectArray zjni_get_Datasets_dependents(JNIEnv *, jobjectArray);
jobject zjni_get_Dataset(JNIEnv *, jstring, zfs_type_t);
int zjni_create_add_Pool(zpool_handle_t *, void *);
int zjni_create_add_Dataset(zfs_handle_t *, void *);

#ifdef __cplusplus
}
#endif

#endif /* _LIBZFS_JNI_DATASET_H */
