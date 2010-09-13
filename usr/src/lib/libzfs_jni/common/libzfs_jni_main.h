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

#ifndef _ZLIBZFS_JNI_MAIN_H
#define	_ZLIBZFS_JNI_MAIN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Class:     com_sun_zfs_common_model_SystemDataModel
 * Method:    getImportablePools
 * Signature: ([Ljava/lang/String;)[Ljava/lang/String;
 */
JNIEXPORT jobjectArray JNICALL
Java_com_sun_zfs_common_model_SystemDataModel_getImportablePools(
    JNIEnv *, jobject, jobjectArray);

/*
 * Class:     com_sun_zfs_common_model_SystemDataModel
 * Method:    getPools
 * Signature: ()[Lcom/sun/zfs/common/model/Pool;
 */
JNIEXPORT jobjectArray JNICALL
Java_com_sun_zfs_common_model_SystemDataModel_getPools(
    JNIEnv *, jobject);

/*
 * Class:     com_sun_zfs_common_model_SystemDataModel
 * Method:    getPool
 * Signature: (Ljava/lang/String;)
 *            Lcom/sun/zfs/common/model/Pool;
 */
JNIEXPORT jobject JNICALL
Java_com_sun_zfs_common_model_SystemDataModel_getPool(
    JNIEnv *, jobject, jstring);

/*
 * Class:     com_sun_zfs_common_model_SystemDataModel
 * Method:    getFileSystems
 * Signature: (Ljava/lang/String;)
 *            [Lcom/sun/zfs/common/model/FileSystem;
 */
JNIEXPORT jobjectArray JNICALL
Java_com_sun_zfs_common_model_SystemDataModel_getFileSystems(
    JNIEnv *, jobject, jstring);

/*
 * Class:     com_sun_zfs_common_model_SystemDataModel
 * Method:    getFileSystem
 * Signature: (Ljava/lang/String;)
 *            Lcom/sun/zfs/common/model/FileSystem;
 */
JNIEXPORT jobject JNICALL
Java_com_sun_zfs_common_model_SystemDataModel_getFileSystem(
    JNIEnv *, jobject, jstring);

/*
 * Class:     com_sun_zfs_common_model_SystemDataModel
 * Method:    getVolumes
 * Signature: (Ljava/lang/String;)
 *            [Lcom/sun/zfs/common/model/Volume;
 */
JNIEXPORT jobjectArray JNICALL
Java_com_sun_zfs_common_model_SystemDataModel_getVolumes(
    JNIEnv *, jobject, jstring);

/*
 * Class:     com_sun_zfs_common_model_SystemDataModel
 * Method:    getVolume
 * Signature: (Ljava/lang/String;)
 *            Lcom/sun/zfs/common/model/Volume;
 */
JNIEXPORT jobject JNICALL
Java_com_sun_zfs_common_model_SystemDataModel_getVolume(
    JNIEnv *, jobject, jstring);

/*
 * Class:     com_sun_zfs_common_model_SystemDataModel
 * Method:    getSnapshots
 * Signature: (Ljava/lang/String;)
 *            [Lcom/sun/zfs/common/model/Snapshot;
 */
JNIEXPORT jobjectArray JNICALL
Java_com_sun_zfs_common_model_SystemDataModel_getSnapshots(
    JNIEnv *, jobject, jstring);

/*
 * Class:     com_sun_zfs_common_model_SystemDataModel
 * Method:    getSnapshot
 * Signature: (Ljava/lang/String;)
 *            Lcom/sun/zfs/common/model/Snapshot;
 */
JNIEXPORT jobject JNICALL
Java_com_sun_zfs_common_model_SystemDataModel_getSnapshot(
    JNIEnv *, jobject, jstring);

/*
 * Class:     com_sun_zfs_common_model_SystemDataModel
 * Method:    getDatasets
 * Signature: (Ljava/lang/String;)
 *            [Lcom/sun/zfs/common/model/Dataset;
 */
JNIEXPORT jobjectArray JNICALL
Java_com_sun_zfs_common_model_SystemDataModel_getDatasets(
    JNIEnv *, jobject, jstring);

/*
 * Class:     com_sun_zfs_common_model_SystemDataModel
 * Method:    getDataset
 * Signature: (Ljava/lang/String;)
 *            Lcom/sun/zfs/common/model/Dataset;
 */
JNIEXPORT jobject JNICALL
Java_com_sun_zfs_common_model_SystemDataModel_getDataset(
    JNIEnv *, jobject, jstring);

/*
 * Class:     com_sun_zfs_common_model_SystemDataModel
 * Method:    getVirtualDevice
 * Signature: (Ljava/lang/String;J)Lcom/sun/zfs/common/model/VirtualDevice;
 */
JNIEXPORT jobject JNICALL
Java_com_sun_zfs_common_model_SystemDataModel_getVirtualDevice(
    JNIEnv *, jobject, jstring, jlong);

/*
 * Class:     com_sun_zfs_common_model_SystemDataModel
 * Method:    getVirtualDevices
 * Signature: (Ljava/lang/String;)
 *            [Lcom/sun/zfs/common/model/VirtualDevice;
 */
JNIEXPORT jobjectArray JNICALL
/* CSTYLED */
Java_com_sun_zfs_common_model_SystemDataModel_getVirtualDevices__Ljava_lang_String_2(
    JNIEnv *, jobject, jstring);

/*
 * Class:     com_sun_zfs_common_model_SystemDataModel
 * Method:    getVirtualDevices
 * Signature: (Ljava/lang/String;J)[Lcom/sun/zfs/common/model/VirtualDevice;
 */
JNIEXPORT jobjectArray JNICALL
/* CSTYLED */
Java_com_sun_zfs_common_model_SystemDataModel_getVirtualDevices__Ljava_lang_String_2J(
    JNIEnv *, jobject, jstring, jlong);

/*
 * Class:     com_sun_zfs_common_model_SystemDataModel
 * Method:    getAvailableDisks
 * Signature: ()[Lcom/sun/zfs/common/model/DiskDevice;
 */
JNIEXPORT jobjectArray JNICALL
Java_com_sun_zfs_common_model_SystemDataModel_getAvailableDisks(
    JNIEnv *, jobject);

/*
 * Class:     com_sun_zfs_common_model_SystemDataModel
 * Method:    getDependents
 * Signature: ([Ljava/lang/String;)
 *            [Lcom/sun/zfs/common/model/Dataset;
 */
JNIEXPORT jobjectArray JNICALL
Java_com_sun_zfs_common_model_SystemDataModel_getDependents(
    JNIEnv *, jobject, jobjectArray);

/*
 * Class:     com_sun_zfs_common_model_SystemDataModel
 * Method:    getPropertyDefault
 * Signature: (Ljava/lang/String;)
 *            Lcom/sun/zfs/common/model/Property;
 */
JNIEXPORT jobject JNICALL
Java_com_sun_zfs_common_model_SystemDataModel_getPropertyDefault(
    JNIEnv *, jobject, jstring);

/*
 * Class:     com_sun_zfs_common_model_SystemDataModel
 * Method:    getValidPropertyNames
 * Signature: (Ljava/lang/Class;)
 *            [Ljava/lang/String;
 */
JNIEXPORT jobjectArray JNICALL
Java_com_sun_zfs_common_model_SystemDataModel_getValidPropertyNames(
    JNIEnv *, jobject, jclass);

/*
 * Class:     com_sun_zfs_common_model_SystemDataModel
 * Method:    getPoolCurrentVersion
 * Signature: ()J
 *
 */
JNIEXPORT jlong JNICALL
Java_com_sun_zfs_common_model_SystemDataModel_getPoolCurrentVersion(
    JNIEnv *, jobject);

#ifdef __cplusplus
}
#endif

#endif /* _ZLIBZFS_JNI_MAIN_H */
