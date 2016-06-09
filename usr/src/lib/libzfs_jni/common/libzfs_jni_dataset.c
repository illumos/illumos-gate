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

/*
 * Copyright (c) 2015 by Delphix. All rights reserved.
 */

#include "libzfs_jni_util.h"
#include "libzfs_jni_dataset.h"
#include "libzfs_jni_property.h"
#include "libzfs_jni_pool.h"
#include <strings.h>

#define	REGEX_ZFS_NAME "^((([^/]*)(/.+)?)[/@])?([^/]+)/*"
#define	REGEX_ZFS_NAME_NGROUPS	6
#define	REGEX_ZFS_NAME_POOL_GROUP 3
#define	REGEX_ZFS_NAME_PARENT_GROUP 2
#define	REGEX_ZFS_NAME_BASE_GROUP 5

/*
 * Types
 */

typedef struct DatasetBean {
	zjni_Object_t super;

	jmethodID method_setPoolName;
	jmethodID method_setParentName;
	jmethodID method_setBaseName;
	jmethodID method_setProperties;
	jmethodID method_addProperty;
} DatasetBean_t;

typedef struct FileSystemBean {
	DatasetBean_t super;
} FileSystemBean_t;

typedef struct PoolBean {
	FileSystemBean_t super;
	PoolStatsBean_t interface_PoolStats;
} PoolBean_t;

typedef struct VolumeBean {
	DatasetBean_t super;
} VolumeBean_t;

typedef struct SnapshotBean {
	DatasetBean_t super;
} SnapshotBean_t;

typedef struct FileSystemSnapshotBean {
	DatasetBean_t super;
} FileSystemSnapshotBean_t;

typedef struct VolumeSnapshotBean {
	DatasetBean_t super;
} VolumeSnapshotBean_t;

/*
 * Function prototypes
 */

static void new_DatasetBean(JNIEnv *, DatasetBean_t *);
static void new_PoolBean(JNIEnv *, PoolBean_t *);
static void new_FileSystemBean(JNIEnv *, FileSystemBean_t *);
static void new_VolumeBean(JNIEnv *, VolumeBean_t *);
static void new_SnapshotBean(JNIEnv *, SnapshotBean_t *);
static void new_FileSystemSnapshotBean(JNIEnv *, FileSystemSnapshotBean_t *);
static void new_VolumeSnapshotBean(JNIEnv *, VolumeSnapshotBean_t *);
static int set_name_in_DatasetBean(JNIEnv *, char *, DatasetBean_t *);
static int populate_DatasetBean(JNIEnv *, zfs_handle_t *, DatasetBean_t *);
static int populate_PoolBean(
    JNIEnv *, zpool_handle_t *, zfs_handle_t *, PoolBean_t *);
static int populate_FileSystemBean(
    JNIEnv *, zfs_handle_t *, FileSystemBean_t *);
static int populate_VolumeBean(
    JNIEnv *, zfs_handle_t *, VolumeBean_t *);
static int populate_SnapshotBean(JNIEnv *, zfs_handle_t *, SnapshotBean_t *);
static int populate_FileSystemSnapshotBean(
    JNIEnv *, zfs_handle_t *, FileSystemSnapshotBean_t *);
static int populate_VolumeSnapshotBean(
    JNIEnv *, zfs_handle_t *, VolumeSnapshotBean_t *);
static jobject create_PoolBean(JNIEnv *, zpool_handle_t *, zfs_handle_t *);
static jobject create_FileSystemBean(JNIEnv *, zfs_handle_t *);
static jobject create_VolumeBean(JNIEnv *, zfs_handle_t *);
static jobject create_FileSystemSnapshotBean(JNIEnv *, zfs_handle_t *);
static jobject create_VolumeSnapshotBean(JNIEnv *, zfs_handle_t *);
static jobject create_DatasetBean(JNIEnv *, zfs_handle_t *);
static int is_fs_snapshot(zfs_handle_t *);
static int is_pool_name(const char *);

/*
 * Static functions
 */

/* Create a DatasetBean */
static void
new_DatasetBean(JNIEnv *env, DatasetBean_t *bean)
{
	zjni_Object_t *object = (zjni_Object_t *)bean;

	if (object->object == NULL) {
		object->class =
		    (*env)->FindClass(env, ZFSJNI_PACKAGE_DATA "DatasetBean");

		object->constructor =
		    (*env)->GetMethodID(env, object->class, "<init>", "()V");

		object->object =
		    (*env)->NewObject(env, object->class, object->constructor);
	}

	bean->method_setPoolName = (*env)->GetMethodID(
	    env, object->class, "setPoolName", "(Ljava/lang/String;)V");

	bean->method_setParentName = (*env)->GetMethodID(
	    env, object->class, "setParentName", "(Ljava/lang/String;)V");

	bean->method_setBaseName = (*env)->GetMethodID(
	    env, object->class, "setBaseName", "(Ljava/lang/String;)V");

	bean->method_setProperties = (*env)->GetMethodID(
	    env, object->class, "setProperties",
	    "([L" ZFSJNI_PACKAGE_DATA "Property;)V");

	bean->method_addProperty = (*env)->GetMethodID(
	    env, object->class, "addProperty",
	    "(L" ZFSJNI_PACKAGE_DATA "Property;)V");
}

/* Create a PoolBean */
static void
new_PoolBean(JNIEnv *env, PoolBean_t *bean)
{
	zjni_Object_t *object = (zjni_Object_t *)bean;

	if (object->object == NULL) {

		object->class =
		    (*env)->FindClass(env, ZFSJNI_PACKAGE_DATA "PoolBean");

		object->constructor =
		    (*env)->GetMethodID(env, object->class, "<init>", "()V");

		object->object =
		    (*env)->NewObject(env, object->class, object->constructor);
	}

	new_FileSystemBean(env, (FileSystemBean_t *)bean);
	new_PoolStats(env, &(bean->interface_PoolStats), object);
}

/* Create a FileSystemBean */
static void
new_FileSystemBean(JNIEnv *env, FileSystemBean_t *bean)
{
	zjni_Object_t *object = (zjni_Object_t *)bean;

	if (object->object == NULL) {
		object->class =
		    (*env)->FindClass(env,
		    ZFSJNI_PACKAGE_DATA "FileSystemBean");

		object->constructor =
		    (*env)->GetMethodID(env, object->class, "<init>", "()V");

		object->object =
		    (*env)->NewObject(env, object->class, object->constructor);
	}

	new_DatasetBean(env, (DatasetBean_t *)bean);
}

/* Create a VolumeBean */
static void
new_VolumeBean(JNIEnv *env, VolumeBean_t *bean)
{
	zjni_Object_t *object = (zjni_Object_t *)bean;

	if (object->object == NULL) {
		object->class =
		    (*env)->FindClass(env,
		    ZFSJNI_PACKAGE_DATA "VolumeBean");

		object->constructor =
		    (*env)->GetMethodID(env, object->class, "<init>", "()V");

		object->object =
		    (*env)->NewObject(env, object->class, object->constructor);
	}

	new_DatasetBean(env, (DatasetBean_t *)bean);
}

/* Create a SnapshotBean */
static void
new_SnapshotBean(JNIEnv *env, SnapshotBean_t *bean)
{
	zjni_Object_t *object = (zjni_Object_t *)bean;

	if (object->object == NULL) {
		object->class =
		    (*env)->FindClass(env,
		    ZFSJNI_PACKAGE_DATA "SnapshotBean");

		object->constructor =
		    (*env)->GetMethodID(env, object->class, "<init>", "()V");

		object->object =
		    (*env)->NewObject(env, object->class, object->constructor);
	}

	new_DatasetBean(env, (DatasetBean_t *)bean);
}

/* Create a FileSystemSnapshotBean */
static void
new_FileSystemSnapshotBean(JNIEnv *env, FileSystemSnapshotBean_t *bean)
{
	zjni_Object_t *object = (zjni_Object_t *)bean;

	if (object->object == NULL) {
		object->class =
		    (*env)->FindClass(env,
		    ZFSJNI_PACKAGE_DATA "FileSystemSnapshotBean");

		object->constructor =
		    (*env)->GetMethodID(env, object->class, "<init>", "()V");

		object->object =
		    (*env)->NewObject(env, object->class, object->constructor);
	}

	new_SnapshotBean(env, (SnapshotBean_t *)bean);
}

/* Create a VolumeSnapshotBean */
static void
new_VolumeSnapshotBean(JNIEnv *env, VolumeSnapshotBean_t *bean)
{
	zjni_Object_t *object = (zjni_Object_t *)bean;

	if (object->object == NULL) {
		object->class =
		    (*env)->FindClass(env,
		    ZFSJNI_PACKAGE_DATA "VolumeSnapshotBean");

		object->constructor =
		    (*env)->GetMethodID(env, object->class, "<init>", "()V");

		object->object =
		    (*env)->NewObject(env, object->class, object->constructor);
	}

	new_SnapshotBean(env, (SnapshotBean_t *)bean);
}

static int
set_name_in_DatasetBean(JNIEnv *env, char *name, DatasetBean_t *bean)
{
	jstring poolUTF;
	jstring parentUTF;
	jstring baseUTF;
	zjni_Object_t *object = (zjni_Object_t *)bean;

	/*
	 * zhp->zfs_name has the format
	 * <pool>[[/<container...>]/<dataset>[@<snapshot>]]
	 */

	regex_t re;
	regmatch_t matches[REGEX_ZFS_NAME_NGROUPS];

	if (regcomp(&re, REGEX_ZFS_NAME, REG_EXTENDED) != 0 ||
	    regexec(&re, name, REGEX_ZFS_NAME_NGROUPS, matches, 0) != 0) {
		regfree(&re);
		zjni_throw_exception(env, "invalid name: %s", name);
		return (-1);
	}

	regfree(&re);

	/* Set names */
	poolUTF = zjni_get_matched_string(
	    env, name, matches + REGEX_ZFS_NAME_POOL_GROUP);
	parentUTF = zjni_get_matched_string(
	    env, name, matches + REGEX_ZFS_NAME_PARENT_GROUP);
	baseUTF = zjni_get_matched_string(
	    env, name, matches + REGEX_ZFS_NAME_BASE_GROUP);

	if (poolUTF == NULL) {
		poolUTF = baseUTF;
	}

	(*env)->CallVoidMethod(
	    env, object->object, bean->method_setPoolName, poolUTF);
	(*env)->CallVoidMethod(
	    env, object->object, bean->method_setBaseName, baseUTF);

	if (parentUTF != NULL) {
		(*env)->CallVoidMethod(
		    env, object->object, bean->method_setParentName, parentUTF);
	}

	return (0);
}

static int
populate_DatasetBean(JNIEnv *env, zfs_handle_t *zhp, DatasetBean_t *bean)
{
	jobjectArray properties;
	zjni_Object_t *object = (zjni_Object_t *)bean;

	int result = set_name_in_DatasetBean(
	    env, (char *)zfs_get_name(zhp), bean);
	if (result != 0) {
		/* Must not call any more Java methods to preserve exception */
		return (-1);
	}

	properties = zjni_get_Dataset_properties(env, zhp);
	if (properties == NULL) {
		/* Must not call any more Java methods to preserve exception */
		return (-1);
	}

	(*env)->CallVoidMethod(
	    env, object->object, bean->method_setProperties, properties);

	return (0);
}

static int
populate_PoolBean(JNIEnv *env, zpool_handle_t *zphp, zfs_handle_t *zhp,
    PoolBean_t *bean)
{
	int result = 0;
	zjni_Object_t *object = (zjni_Object_t *)bean;
	PoolStatsBean_t *pool_stats = &(bean->interface_PoolStats);
	DeviceStatsBean_t *dev_stats = (DeviceStatsBean_t *)pool_stats;
	nvlist_t *devices = zjni_get_root_vdev(zphp);

	if (devices == NULL ||
	    populate_DeviceStatsBean(env, devices, dev_stats, object)) {
		result = -1;
	} else {
		char *msgid;

		/* Override value set in populate_DeviceStatsBean */
		(*env)->CallVoidMethod(env, object->object,
		    dev_stats->method_setSize,
		    zpool_get_prop_int(zphp, ZPOOL_PROP_SIZE, NULL));

		(*env)->CallVoidMethod(env, object->object,
		    pool_stats->method_setPoolState,
		    zjni_pool_state_to_obj(
		    env, zpool_get_state(zphp)));

		(*env)->CallVoidMethod(env, object->object,
		    pool_stats->method_setPoolStatus,
		    zjni_pool_status_to_obj(env,
		    zpool_get_status(zphp, &msgid)));

		(*env)->CallVoidMethod(env, object->object,
		    pool_stats->method_setPoolVersion,
		    zpool_get_prop_int(zphp, ZPOOL_PROP_VERSION, NULL));

		/*
		 * If a root file system does not exist for this pool, the pool
		 * is likely faulted, so just set its name in the Java object.
		 * Otherwise, populate all fields of the Java object.
		 */
		if (zhp == NULL) {
			result = set_name_in_DatasetBean(env,
			    (char *)zpool_get_name(zphp),
			    (DatasetBean_t *)bean);
		} else {
			result = populate_FileSystemBean(
			    env, zhp, (FileSystemBean_t *)bean);
		}
	}

	return (result != 0);
}

static int
populate_FileSystemBean(JNIEnv *env, zfs_handle_t *zhp, FileSystemBean_t *bean)
{
	return (populate_DatasetBean(env, zhp, (DatasetBean_t *)bean));
}

static int
populate_VolumeBean(JNIEnv *env, zfs_handle_t *zhp, VolumeBean_t *bean)
{
	return (populate_DatasetBean(env, zhp, (DatasetBean_t *)bean));
}

static int
populate_SnapshotBean(JNIEnv *env, zfs_handle_t *zhp, SnapshotBean_t *bean)
{
	return (populate_DatasetBean(env, zhp, (DatasetBean_t *)bean));
}

static int
populate_FileSystemSnapshotBean(JNIEnv *env, zfs_handle_t *zhp,
    FileSystemSnapshotBean_t *bean)
{
	return (populate_SnapshotBean(env, zhp, (SnapshotBean_t *)bean));
}

static int
populate_VolumeSnapshotBean(JNIEnv *env, zfs_handle_t *zhp,
    VolumeSnapshotBean_t *bean)
{
	return (populate_SnapshotBean(env, zhp, (SnapshotBean_t *)bean));
}

static jobject
create_PoolBean(JNIEnv *env, zpool_handle_t *zphp, zfs_handle_t *zhp)
{
	int result;
	PoolBean_t bean_obj = {0};
	PoolBean_t *bean = &bean_obj;

	/* Construct PoolBean */
	new_PoolBean(env, bean);

	result = populate_PoolBean(env, zphp, zhp, bean);
	if (result) {
		/* Must not call any more Java methods to preserve exception */
		return (NULL);
	}

	return (((zjni_Object_t *)bean)->object);
}

static jobject
create_FileSystemBean(JNIEnv *env, zfs_handle_t *zhp)
{
	int result;
	FileSystemBean_t bean_obj = {0};
	FileSystemBean_t *bean = &bean_obj;

	/* Construct FileSystemBean */
	new_FileSystemBean(env, bean);

	result = populate_FileSystemBean(env, zhp, bean);
	if (result) {
		/* Must not call any more Java methods to preserve exception */
		return (NULL);
	}

	return (((zjni_Object_t *)bean)->object);
}

static jobject
create_VolumeBean(JNIEnv *env, zfs_handle_t *zhp)
{
	int result;
	VolumeBean_t bean_obj = {0};
	VolumeBean_t *bean = &bean_obj;

	/* Construct VolumeBean */
	new_VolumeBean(env, bean);

	result = populate_VolumeBean(env, zhp, bean);
	if (result) {
		/* Must not call any more Java methods to preserve exception */
		return (NULL);
	}

	return (((zjni_Object_t *)bean)->object);
}

static jobject
create_FileSystemSnapshotBean(JNIEnv *env, zfs_handle_t *zhp)
{
	int result;
	FileSystemSnapshotBean_t bean_obj = {0};
	FileSystemSnapshotBean_t *bean = &bean_obj;

	/* Construct FileSystemSnapshotBean */
	new_FileSystemSnapshotBean(env, bean);

	result = populate_FileSystemSnapshotBean(env, zhp, bean);
	if (result) {
		/* Must not call any more Java methods to preserve exception */
		return (NULL);
	}

	return (((zjni_Object_t *)bean)->object);
}

static jobject
create_VolumeSnapshotBean(JNIEnv *env, zfs_handle_t *zhp)
{
	int result;
	VolumeSnapshotBean_t bean_obj = {0};
	VolumeSnapshotBean_t *bean = &bean_obj;

	/* Construct VolumeSnapshotBean */
	new_VolumeSnapshotBean(env, bean);

	result = populate_VolumeSnapshotBean(env, zhp, bean);
	if (result) {
		/* Must not call any more Java methods to preserve exception */
		return (NULL);
	}

	return (((zjni_Object_t *)bean)->object);
}

static jobject
create_DatasetBean(JNIEnv *env, zfs_handle_t *zhp)
{
	jobject object = NULL;

	switch (zfs_get_type(zhp)) {
	case ZFS_TYPE_FILESYSTEM:
		object = create_FileSystemBean(env, zhp);
		break;

	case ZFS_TYPE_VOLUME:
		object = create_VolumeBean(env, zhp);
		break;

	case ZFS_TYPE_SNAPSHOT:
		object = is_fs_snapshot(zhp) ?
		    create_FileSystemSnapshotBean(env, zhp) :
		    create_VolumeSnapshotBean(env, zhp);
		break;
	}

	return (object);
}

/*
 * Determines whether the given snapshot is a snapshot of a file
 * system or of a volume.
 *
 * Returns:
 *
 *	0 if it is a volume snapshot
 *	1 if it is a file system snapshot
 *	-1 on error
 */
static int
is_fs_snapshot(zfs_handle_t *zhp)
{
	char parent[ZFS_MAX_DATASET_NAME_LEN];
	zfs_handle_t *parent_zhp;
	int isfs;

	if (zfs_get_type(zhp) != ZFS_TYPE_SNAPSHOT) {
		return (-1);
	}

	zjni_get_dataset_from_snapshot(
	    zfs_get_name(zhp), parent, sizeof (parent));

	parent_zhp = zfs_open(g_zfs, parent, ZFS_TYPE_DATASET);
	if (parent_zhp == NULL) {
		return (-1);
	}

	isfs = zfs_get_type(parent_zhp) == ZFS_TYPE_FILESYSTEM;
	zfs_close(parent_zhp);

	return (isfs);
}

static int
is_pool_name(const char *name)
{
	return (strchr(name, '/') == NULL && strchr(name, '@') == NULL);
}

/*
 * Package-private functions
 */

/*
 * Callback function for zpool_iter().  Creates a Pool and adds it to
 * the given zjni_ArrayList.
 */
int
zjni_create_add_Pool(zpool_handle_t *zphp, void *data)
{
	JNIEnv *env = ((zjni_ArrayCallbackData_t *)data)->env;
	zjni_Collection_t *list = ((zjni_ArrayCallbackData_t *)data)->list;

	/* Get root fs for this pool -- may be NULL if pool is faulted */
	zfs_handle_t *zhp = zfs_open(g_zfs, zpool_get_name(zphp),
	    ZFS_TYPE_FILESYSTEM);

	jobject bean = create_PoolBean(env, zphp, zhp);

	if (zhp != NULL)
		zfs_close(zhp);

	zpool_close(zphp);

	if (bean == NULL) {
		/* Must not call any more Java methods to preserve exception */
		return (-1);
	}

	/* Add pool to zjni_ArrayList */
	(*env)->CallBooleanMethod(env, ((zjni_Object_t *)list)->object,
	    ((zjni_Collection_t *)list)->method_add, bean);

	return (0);
}

/*
 * Callback function for zfs_iter_children().  Creates the appropriate
 * Dataset and adds it to the given zjni_ArrayList.  Per the contract
 * with zfs_iter_children(), calls zfs_close() on the given
 * zfs_handle_t.
 */
int
zjni_create_add_Dataset(zfs_handle_t *zhp, void *data)
{
	JNIEnv *env = ((zjni_ArrayCallbackData_t *)data)->env;
	zjni_Collection_t *list = ((zjni_ArrayCallbackData_t *)data)->list;
	zfs_type_t typemask =
	    ((zjni_DatasetArrayCallbackData_t *)data)->typemask;

	/* Only add allowed types */
	if (zfs_get_type(zhp) & typemask) {

		jobject bean = create_DatasetBean(env, zhp);
		zfs_close(zhp);

		if (bean == NULL) {
			/*
			 * Must not call any more Java methods to preserve
			 * exception
			 */
			return (-1);
		}

		/* Add Dataset to zjni_ArrayList */
		(*env)->CallBooleanMethod(env, ((zjni_Object_t *)list)->object,
		    ((zjni_Collection_t *)list)->method_add, bean);
	} else {
		zfs_close(zhp);
	}

	return (0);
}

jobjectArray
zjni_get_Datasets_below(JNIEnv *env, jstring parentUTF,
    zfs_type_t parent_typemask, zfs_type_t child_typemask, char *arrayClass)
{
	jobjectArray array = NULL;

	if (parentUTF != NULL) {
		zfs_handle_t *zhp;
		int error = 1;
		const char *name =
		    (*env)->GetStringUTFChars(env, parentUTF, NULL);

		/* Create an array list to hold the children */
		zjni_DatasetSet_t list_obj = {0};
		zjni_DatasetSet_t *list = &list_obj;
		zjni_new_DatasetSet(env, list);

		/* Retrieve parent dataset */
		zhp = zfs_open(g_zfs, name, parent_typemask);

		if (zhp != NULL) {
			zjni_DatasetArrayCallbackData_t data = {0};
			data.data.env = env;
			data.data.list = (zjni_Collection_t *)list;
			data.typemask = child_typemask;

			(void) zfs_iter_children(zhp, zjni_create_add_Dataset,
			    &data);

			zfs_close(zhp);

			if ((*env)->ExceptionOccurred(env) == NULL) {
				error = 0;
			}
		} else

		/* Parent is not a dataset -- see if it's a faulted pool */
		if ((parent_typemask & ZFS_TYPE_FILESYSTEM) &&
		    is_pool_name(name)) {
			zpool_handle_t *zphp = zpool_open_canfail(g_zfs, name);

			if (zphp != NULL) {
				/* A faulted pool has no datasets */
				error = 0;
				zpool_close(zphp);
			}
		}

		(*env)->ReleaseStringUTFChars(env, parentUTF, name);

		if (!error) {
			array = zjni_Collection_to_array(
			    env, (zjni_Collection_t *)list, arrayClass);
		}
	}

	return (array);
}

jobjectArray
zjni_get_Datasets_dependents(JNIEnv *env, jobjectArray paths)
{
	jint i;
	jint npaths;
	zjni_DatasetArrayCallbackData_t data = {0};
	jobjectArray array = NULL;

	/* Create a list to hold the children */
	zjni_DatasetSet_t list_obj = {0};
	zjni_DatasetSet_t *list = &list_obj;
	zjni_new_DatasetSet(env, list);

	data.data.env = env;
	data.data.list = (zjni_Collection_t *)list;
	data.typemask = ZFS_TYPE_DATASET;

	npaths = (*env)->GetArrayLength(env, paths);
	for (i = 0; i < npaths; i++) {

		jstring pathUTF = (jstring)
		    ((*env)->GetObjectArrayElement(env, paths, i));

		if (pathUTF != NULL) {
			const char *path =
			    (*env)->GetStringUTFChars(env, pathUTF, NULL);

			zfs_handle_t *zhp = zfs_open(g_zfs, path,
			    ZFS_TYPE_DATASET);
			if (zhp != NULL) {
				/* Add all dependents of this Dataset to list */
				(void) zfs_iter_dependents(zhp, B_FALSE,
				    zjni_create_add_Dataset, &data);

				/* Add this Dataset to list (and close zhp) */
				(void) zjni_create_add_Dataset(zhp, &data);
			} else if (is_pool_name(path)) {
				/*
				 * Path is not a dataset -
				 * see if it's a faulted pool
				 */
				zpool_handle_t *zphp = zpool_open_canfail(g_zfs,
				    path);

				if (zphp != NULL) {
					/*
					 * Add this Pool to list (and
					 * close zphp)
					 */
					(void) zjni_create_add_Pool(zphp,
					    &data.data);
				}
			}

			(*env)->ReleaseStringUTFChars(env, pathUTF, path);
		}
	}

	if ((*env)->ExceptionOccurred(env) == NULL) {
		array = zjni_Collection_to_array(env, (zjni_Collection_t *)list,
		    ZFSJNI_PACKAGE_DATA "Dataset");
	}

	return (array);
}

/*
 * Gets a Dataset of the given name and type, or NULL if no such
 * Dataset exists.
 */
jobject
zjni_get_Dataset(JNIEnv *env, jstring nameUTF, zfs_type_t typemask)
{
	jobject device = NULL;
	const char *name = (*env)->GetStringUTFChars(env, nameUTF, NULL);
	zfs_handle_t *zhp = zfs_open(g_zfs, name, typemask);

	if ((typemask & ZFS_TYPE_FILESYSTEM) && is_pool_name(name)) {
		zpool_handle_t *zphp = zpool_open_canfail(g_zfs, name);

		if (zphp != NULL) {
			device = create_PoolBean(env, zphp, zhp);
			zpool_close(zphp);
		}
	} else if (zhp != NULL) {
		/* Creates a Dataset object of the appropriate class */
		device = create_DatasetBean(env, zhp);
	}

	if (zhp != NULL) {
		zfs_close(zhp);
	}

	(*env)->ReleaseStringUTFChars(env, nameUTF, name);

	return (device);
}
