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

#include <priv.h>
#include "libzfs_jni_main.h"
#include "libzfs_jni_util.h"
#include "libzfs_jni_dataset.h"
#include "libzfs_jni_property.h"
#include "libzfs_jni_pool.h"
#include "libzfs_jni_diskmgt.h"
#include "libzfs_jni_disk.h"

libzfs_handle_t *g_zfs;

/*
 * Function prototypes
 */

static void handle_error(const char *, va_list);
static void init();

/*
 * Static functions
 */

char libdskmgt_err[1024];
static void
handle_error(const char *fmt, va_list ap)
{
	/* Save the error message in case it's needed */
	(void) vsnprintf(libdskmgt_err, sizeof (libdskmgt_err), fmt, ap);
#ifdef	DEBUG
	(void) fprintf(stderr, "caught error: %s\n", libdskmgt_err);
#endif
}

/*
 * Initialize the library.  Sets the error handler.
 */
#pragma init(init)
static void
init()
{
	if ((g_zfs = libzfs_init()) == NULL)
		abort();

	/* diskmgt.o error handler */
	dmgt_set_error_handler(handle_error);
}

/*
 * JNI functions
 */

/*
 * Class:     com_sun_zfs_common_model_SystemDataModel
 * Method:    getImportablePools
 * Signature: ([Ljava/lang/String;)[Ljava/lang/String;
 */
/* ARGSUSED */
JNIEXPORT jobjectArray JNICALL
Java_com_sun_zfs_common_model_SystemDataModel_getImportablePools(
    JNIEnv *env, jobject obj, jobjectArray dirs) {

	int error;
	int argc = 0;
	char **argv = NULL;
	zjni_ArrayCallbackData_t data = {0};
	zjni_ArrayList_t list_obj = {0};
	zjni_ArrayList_t *list = &list_obj;

	if (!priv_ineffect(PRIV_SYS_CONFIG)) {
		zjni_throw_exception(env,
		    "cannot discover pools: permission denied\n");
		return (NULL);
	}

	if (dirs != NULL) {
		argv = zjni_java_string_array_to_c(env, dirs);
		if (argv == NULL) {
			zjni_throw_exception(env, "out of memory");
			return (NULL);
		}

		/* Count elements */
		for (argc = 0; argv[argc] != NULL; argc++);
	}

	/* Create an array list to hold each ImportablePoolBean */
	zjni_new_ArrayList(env, list);

	data.env = env;
	data.list = (zjni_Collection_t *)list;

	/* Iterate through all importable pools, building list */
	error = zjni_ipool_iter(
	    argc, argv, zjni_create_add_ImportablePool, &data);

	zjni_free_array((void **)argv, free);

	if (error) {
		return (NULL);
	}

	return (zjni_Collection_to_array(env, (zjni_Collection_t *)list,
	    ZFSJNI_PACKAGE_DATA "ImportablePool"));
}

/*
 * Class:     com_sun_zfs_common_model_SystemDataModel
 * Method:    getPools
 * Signature: ()[Lcom/sun/zfs/common/model/Pool;
 */
/* ARGSUSED */
JNIEXPORT jobjectArray JNICALL
Java_com_sun_zfs_common_model_SystemDataModel_getPools(JNIEnv *env, jobject obj)
{
	zjni_ArrayCallbackData_t data = {0};
	int result;

	/* Create an array list */
	zjni_ArrayList_t list_obj = {0};
	zjni_ArrayList_t *list = &list_obj;
	zjni_new_ArrayList(env, list);

	data.env = env;
	data.list = (zjni_Collection_t *)list;

	result = zpool_iter(g_zfs, zjni_create_add_Pool, &data);
	if (result && (*env)->ExceptionOccurred(env) != NULL) {
		/* Must not call any more Java methods to preserve exception */
		return (NULL);
	}

	return (zjni_Collection_to_array(env, (zjni_Collection_t *)list,
	    ZFSJNI_PACKAGE_DATA "Pool"));
}

/*
 * Class:     com_sun_zfs_common_model_SystemDataModel
 * Method:    getPool
 * Signature: (Ljava/lang/String;)
 *            Lcom/sun/zfs/common/model/Pool;
 */
/* ARGSUSED */
JNIEXPORT jobject JNICALL
Java_com_sun_zfs_common_model_SystemDataModel_getPool(JNIEnv *env,
    jobject obj, jstring poolUTF)
{
	jobject pool = zjni_get_Dataset(env, poolUTF, ZFS_TYPE_FILESYSTEM);

	/* Verify that object is Pool, not some other Dataset */
	if (pool != NULL) {
		jclass class = (*env)->FindClass(
		    env, ZFSJNI_PACKAGE_DATA "Pool");

		jboolean is_pool = (*env)->IsInstanceOf(env, pool, class);

		if (is_pool != JNI_TRUE)
			pool = NULL;
	}

	return (pool);
}

/*
 * Class:     com_sun_zfs_common_model_SystemDataModel
 * Method:    getFileSystems
 * Signature: (Ljava/lang/String;)
 *            [Lcom/sun/zfs/common/model/FileSystem;
 */
/* ARGSUSED */
JNIEXPORT jobjectArray JNICALL
Java_com_sun_zfs_common_model_SystemDataModel_getFileSystems(JNIEnv *env,
    jobject obj, jstring containerUTF)
{
	if (containerUTF == NULL) {
		return (Java_com_sun_zfs_common_model_SystemDataModel_getPools(
		    env, obj));
	}

	return (zjni_get_Datasets_below(env, containerUTF,
	    ZFS_TYPE_FILESYSTEM, ZFS_TYPE_FILESYSTEM,
	    ZFSJNI_PACKAGE_DATA "FileSystem"));
}

/*
 * Class:     com_sun_zfs_common_model_SystemDataModel
 * Method:    getFileSystem
 * Signature: (Ljava/lang/String;)
 *            Lcom/sun/zfs/common/model/FileSystem;
 */
/* ARGSUSED */
JNIEXPORT jobject JNICALL
Java_com_sun_zfs_common_model_SystemDataModel_getFileSystem(JNIEnv *env,
    jobject obj, jstring nameUTF)
{
	return (zjni_get_Dataset(env, nameUTF, ZFS_TYPE_FILESYSTEM));
}

/*
 * Class:     com_sun_zfs_common_model_SystemDataModel
 * Method:    getVolumes
 * Signature: (Ljava/lang/String;)
 *            [Lcom/sun/zfs/common/model/Volume;
 */
/* ARGSUSED */
JNIEXPORT jobjectArray JNICALL
Java_com_sun_zfs_common_model_SystemDataModel_getVolumes(JNIEnv *env,
    jobject obj, jstring containerUTF)
{
	return (zjni_get_Datasets_below(env, containerUTF,
	    ZFS_TYPE_FILESYSTEM, ZFS_TYPE_VOLUME,
	    ZFSJNI_PACKAGE_DATA "Volume"));
}

/*
 * Class:     com_sun_zfs_common_model_SystemDataModel
 * Method:    getVolume
 * Signature: (Ljava/lang/String;)
 *            Lcom/sun/zfs/common/model/Volume;
 */
/* ARGSUSED */
JNIEXPORT jobject JNICALL
Java_com_sun_zfs_common_model_SystemDataModel_getVolume(JNIEnv *env,
    jobject obj, jstring nameUTF)
{
	return (zjni_get_Dataset(env, nameUTF, ZFS_TYPE_VOLUME));
}

/*
 * Class:     com_sun_zfs_common_model_SystemDataModel
 * Method:    getSnapshots
 * Signature: (Ljava/lang/String;)
 *            [Lcom/sun/zfs/common/model/Snapshot;
 */
/* ARGSUSED */
JNIEXPORT jobjectArray JNICALL
Java_com_sun_zfs_common_model_SystemDataModel_getSnapshots(JNIEnv *env,
    jobject obj, jstring datasetUTF)
{
	return (zjni_get_Datasets_below(env, datasetUTF,
	    ZFS_TYPE_FILESYSTEM | ZFS_TYPE_VOLUME, ZFS_TYPE_SNAPSHOT,
	    ZFSJNI_PACKAGE_DATA "Snapshot"));
}

/*
 * Class:     com_sun_zfs_common_model_SystemDataModel
 * Method:    getSnapshot
 * Signature: (Ljava/lang/String;)
 *            Lcom/sun/zfs/common/model/Snapshot;
 */
/* ARGSUSED */
JNIEXPORT jobject JNICALL
Java_com_sun_zfs_common_model_SystemDataModel_getSnapshot(JNIEnv *env,
    jobject obj, jstring nameUTF)
{
	return (zjni_get_Dataset(env, nameUTF, ZFS_TYPE_SNAPSHOT));
}

/*
 * Class:     com_sun_zfs_common_model_SystemDataModel
 * Method:    getDatasets
 * Signature: (Ljava/lang/String;)
 *            [Lcom/sun/zfs/common/model/Dataset;
 */
/* ARGSUSED */
JNIEXPORT jobjectArray JNICALL
Java_com_sun_zfs_common_model_SystemDataModel_getDatasets(JNIEnv *env,
    jobject obj, jstring containerUTF)
{
	if (containerUTF == NULL) {
		return (Java_com_sun_zfs_common_model_SystemDataModel_getPools(
		    env, obj));
	}

	return (zjni_get_Datasets_below(env, containerUTF,
	    ZFS_TYPE_FILESYSTEM | ZFS_TYPE_VOLUME, ZFS_TYPE_DATASET,
	    ZFSJNI_PACKAGE_DATA "Dataset"));
}

/*
 * Class:     com_sun_zfs_common_model_SystemDataModel
 * Method:    getDataset
 * Signature: (Ljava/lang/String;)
 *            Lcom/sun/zfs/common/model/Dataset;
 */
/* ARGSUSED */
JNIEXPORT jobject JNICALL
Java_com_sun_zfs_common_model_SystemDataModel_getDataset(JNIEnv *env,
    jobject obj, jstring nameUTF)
{
	return (zjni_get_Dataset(env, nameUTF, ZFS_TYPE_DATASET));
}

/*
 * Class:     com_sun_zfs_common_model_SystemDataModel
 * Method:    getVirtualDevice
 * Signature: (Ljava/lang/String;J)Lcom/sun/zfs/common/model/VirtualDevice;
 */
/* ARGSUSED */
JNIEXPORT jobject JNICALL
Java_com_sun_zfs_common_model_SystemDataModel_getVirtualDevice(JNIEnv *env,
    jobject obj, jstring poolUTF, jlong index)
{
	jobject vdev = NULL;

	if (poolUTF != NULL) {
		const char *pool = (*env)->GetStringUTFChars(env, poolUTF,
		    NULL);
		zpool_handle_t *zhp = zpool_open_canfail(g_zfs, pool);
		(*env)->ReleaseStringUTFChars(env, poolUTF, pool);

		if (zhp != NULL) {
			uint64_t p_vdev_id;
			nvlist_t *vdev_cfg = zjni_get_vdev(
			    zhp, NULL, index, &p_vdev_id);

			if (vdev_cfg != NULL) {
				vdev = zjni_get_VirtualDevice_from_vdev(
				    env, zhp, vdev_cfg,
				    p_vdev_id == index ? NULL : &p_vdev_id);
			}
			zpool_close(zhp);
		}
	}

	return (vdev);
}

/*
 * Class:     com_sun_zfs_common_model_SystemDataModel
 * Method:    getVirtualDevices
 * Signature: (Ljava/lang/String;J)
 *            [Lcom/sun/zfs/common/model/VirtualDevice;
 */
/* ARGSUSED */
JNIEXPORT jobjectArray JNICALL
/* CSTYLED */
Java_com_sun_zfs_common_model_SystemDataModel_getVirtualDevices__Ljava_lang_String_2J(
    JNIEnv *env, jobject obj, jstring poolUTF, jlong index)
{
	jobjectArray vdevs = NULL;

	if (poolUTF != NULL) {
		const char *pool = (*env)->GetStringUTFChars(env, poolUTF,
		    NULL);
		zpool_handle_t *zhp = zpool_open_canfail(g_zfs, pool);
		(*env)->ReleaseStringUTFChars(env, poolUTF, pool);

		/* Is the pool valid? */
		if (zhp != NULL) {
			uint64_t p_vdev_id = index;
			nvlist_t *vdev_cfg = zjni_get_vdev(
			    zhp, NULL, index, NULL);

			if (vdev_cfg != NULL) {
				vdevs = zjni_get_VirtualDevices_from_vdev(
				    env, zhp, vdev_cfg, &p_vdev_id);
			}
			zpool_close(zhp);
		}
	}

	return (vdevs);
}

/*
 * Class:     com_sun_zfs_common_model_SystemDataModel
 * Method:    getVirtualDevices
 * Signature: (Ljava/lang/String;)
 *            [Lcom/sun/zfs/common/model/VirtualDevice;
 */
/* ARGSUSED */
JNIEXPORT jobjectArray JNICALL
/* CSTYLED */
Java_com_sun_zfs_common_model_SystemDataModel_getVirtualDevices__Ljava_lang_String_2(
    JNIEnv *env, jobject obj, jstring poolUTF)
{
	jobjectArray vdevs = NULL;

	if (poolUTF != NULL) {
		const char *pool = (*env)->GetStringUTFChars(env,
		    poolUTF, NULL);
		zpool_handle_t *zhp = zpool_open_canfail(g_zfs, pool);
		(*env)->ReleaseStringUTFChars(env, poolUTF, pool);

		/* Is the pool valid? */
		if (zhp != NULL) {
			vdevs = zjni_get_VirtualDevices_from_vdev(env,
			    zhp, NULL, NULL);
			zpool_close(zhp);
		}
	}

	return (vdevs);
}

/*
 * Class:     com_sun_zfs_common_model_SystemDataModel
 * Method:    getAvailableDisks
 * Signature: ()[Lcom/sun/zfs/common/model/DiskDevice;
 */
/* ARGSUSED */
JNIEXPORT jobjectArray JNICALL
Java_com_sun_zfs_common_model_SystemDataModel_getAvailableDisks(JNIEnv *env,
    jobject obj)
{
	int error;
	zjni_ArrayCallbackData_t data = {0};
	jobjectArray array = NULL;

	/* Create an array list */
	zjni_ArrayList_t list_obj = {0};
	zjni_ArrayList_t *list = &list_obj;
	zjni_new_ArrayList(env, list);

	data.env = env;
	data.list = (zjni_Collection_t *)list;
	error = dmgt_avail_disk_iter(zjni_create_add_DiskDevice, &data);

	if (error) {
		zjni_throw_exception(env, "%s", libdskmgt_err);
	} else {
		array = zjni_Collection_to_array(
		    env, (zjni_Collection_t *)list,
		    ZFSJNI_PACKAGE_DATA "DiskDevice");
	}

	return (array);
}

/*
 * Class:     com_sun_zfs_common_model_SystemDataModel
 * Method:    getDependents
 * Signature: ([Ljava/lang/String;)
 *            [Lcom/sun/zfs/common/model/Dataset;
 */
/* ARGSUSED */
JNIEXPORT jobjectArray JNICALL
Java_com_sun_zfs_common_model_SystemDataModel_getDependents(JNIEnv *env,
    jobject obj, jobjectArray paths)
{
	return (zjni_get_Datasets_dependents(env, paths));
}

/*
 * Class:     com_sun_zfs_common_model_SystemDataModel
 * Method:    getPropertyDefault
 * Signature: (Ljava/lang/String;)
 *            Lcom/sun/zfs/common/model/Property;
 */
/* ARGSUSED */
JNIEXPORT jobject JNICALL
Java_com_sun_zfs_common_model_SystemDataModel_getPropertyDefault(JNIEnv *env,
    jobject obj, jstring nameUTF)
{
	jobject defProperty = NULL;

	const char *name = (*env)->GetStringUTFChars(env, nameUTF, NULL);
	zfs_prop_t prop = zjni_get_property_from_name(name);
	(*env)->ReleaseStringUTFChars(env, nameUTF, name);

	if (prop != ZPROP_INVAL) {
		defProperty = zjni_get_default_property(env, prop);
	}

	return (defProperty);
}

typedef struct zjni_class_type_map {
	char *class;
	zfs_type_t type;
} zjni_class_type_map_t;

typedef struct mapping_data {
	JNIEnv			*env;
	zfs_type_t		type;
	zjni_ArrayList_t	*list;
} mapping_data_t;

static int
mapping_cb(int prop, void *cb)
{
	mapping_data_t *map = cb;
	JNIEnv *env = map->env;
	zjni_ArrayList_t *list = map->list;

	if (zfs_prop_valid_for_type(prop, map->type, B_FALSE)) {
		/* Add name of property to list */
		jstring propName = (*env)->NewStringUTF(env,
		    zfs_prop_to_name(prop));
		(*env)->CallBooleanMethod(env, ((zjni_Object_t *)list)->object,
		    ((zjni_Collection_t *)list)->method_add, propName);
	}

	return (ZPROP_CONT);
}

/*
 * Class:     com_sun_zfs_common_model_SystemDataModel
 * Method:    getValidPropertyNames
 * Signature: (Ljava/lang/Class;)
 *            [Ljava/lang/String;
 */
/* ARGSUSED */
JNIEXPORT jobjectArray JNICALL
Java_com_sun_zfs_common_model_SystemDataModel_getValidPropertyNames(JNIEnv *env,
    jobject obj, jclass class)
{
	int i;

	/* Mappings of class names to zfs_type_t */
	static zjni_class_type_map_t mappings[] = {
		{ ZFSJNI_PACKAGE_DATA "FileSystem", ZFS_TYPE_FILESYSTEM },
		{ ZFSJNI_PACKAGE_DATA "Volume", ZFS_TYPE_VOLUME },
		{ ZFSJNI_PACKAGE_DATA "Snapshot", ZFS_TYPE_SNAPSHOT },
	};
	int nmappings = sizeof (mappings) / sizeof (zjni_class_type_map_t);

	jclass class_Class = (*env)->FindClass(env, "java/lang/Class");

	jmethodID isAssignableFrom = (*env)->GetMethodID(
	    env, class_Class, "isAssignableFrom", "(Ljava/lang/Class;)Z");

	/* Create an array list for the property names */
	zjni_ArrayList_t list_obj = {0};
	zjni_ArrayList_t *list = &list_obj;
	zjni_new_ArrayList(env, list);

	/* For each mapping... */
	for (i = 0; i < nmappings; i++) {
		/*
		 * Is the given class an instance of the class in the mapping?
		 */
		jclass typeClass = (*env)->FindClass(env, mappings[i].class);

		jboolean isInstance = (*env)->CallBooleanMethod(
		    env, typeClass, isAssignableFrom, class);

		if (isInstance == JNI_TRUE) {
			mapping_data_t map_data;

			map_data.env = env;
			map_data.type = mappings[i].type;
			map_data.list = list;
			(void) zprop_iter(mapping_cb, &map_data, B_FALSE,
			    B_FALSE, ZFS_TYPE_DATASET);
			break;
		}
	}

	return (zjni_Collection_to_array(
	    env, (zjni_Collection_t *)list, "java/lang/String"));
}

/*
 * Class:     com_sun_zfs_common_model_SystemDataModel
 * Method:    getPoolCurrentVersion
 * Signature: ()J;
 */
/* ARGSUSED */
JNIEXPORT jlong JNICALL
Java_com_sun_zfs_common_model_SystemDataModel_getPoolCurrentVersion(
    JNIEnv *env, jobject obj)
{
	jlong pool_current_version = SPA_VERSION;

	return (pool_current_version);
}
