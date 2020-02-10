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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2020 Joyent, Inc.
 */

#include "libzfs_jni_util.h"
#include "libzfs_jni_pool.h"
#include <libzutil.h>
#include <strings.h>

/*
 * Types
 */

typedef struct ImportablePoolBean {
	zjni_Object_t super;
	PoolStatsBean_t interface_PoolStats;

	jmethodID method_setName;
	jmethodID method_setId;
} ImportablePoolBean_t;

typedef struct VirtualDeviceBean {
	zjni_Object_t super;
	DeviceStatsBean_t interface_DeviceStats;

	jmethodID method_setPoolName;
	jmethodID method_setParentIndex;
	jmethodID method_setIndex;
} VirtualDeviceBean_t;

typedef struct LeafVirtualDeviceBean {
	VirtualDeviceBean_t super;

	jmethodID method_setName;
} LeafVirtualDeviceBean_t;

typedef struct DiskVirtualDeviceBean {
	LeafVirtualDeviceBean_t super;
} DiskVirtualDeviceBean_t;

typedef struct SliceVirtualDeviceBean {
	LeafVirtualDeviceBean_t super;
} SliceVirtualDeviceBean_t;

typedef struct FileVirtualDeviceBean {
	LeafVirtualDeviceBean_t super;
} FileVirtualDeviceBean_t;

typedef struct RAIDVirtualDeviceBean {
	VirtualDeviceBean_t super;

	jmethodID method_setParity;
} RAIDVirtualDeviceBean_t;

typedef struct MirrorVirtualDeviceBean {
	VirtualDeviceBean_t super;
} MirrorVirtualDeviceBean_t;

/*
 * Data
 */

/* vdev_state_t to DeviceStats$DeviceState map */
static zjni_field_mapping_t vdev_state_map[] = {
	{ VDEV_STATE_CANT_OPEN, "VDEV_STATE_CANT_OPEN" },
	{ VDEV_STATE_CLOSED, "VDEV_STATE_CLOSED" },
	{ VDEV_STATE_DEGRADED, "VDEV_STATE_DEGRADED" },
	{ VDEV_STATE_HEALTHY, "VDEV_STATE_HEALTHY" },
	{ VDEV_STATE_OFFLINE, "VDEV_STATE_OFFLINE" },
	{ VDEV_STATE_UNKNOWN, "VDEV_STATE_UNKNOWN" },
	{ -1, NULL },
};

/* vdev_aux_t to DeviceStats$DeviceStatus map */
static zjni_field_mapping_t vdev_aux_map[] = {
	{ VDEV_AUX_NONE, "VDEV_AUX_NONE" },
	{ VDEV_AUX_OPEN_FAILED, "VDEV_AUX_OPEN_FAILED" },
	{ VDEV_AUX_CORRUPT_DATA, "VDEV_AUX_CORRUPT_DATA" },
	{ VDEV_AUX_NO_REPLICAS, "VDEV_AUX_NO_REPLICAS" },
	{ VDEV_AUX_BAD_GUID_SUM, "VDEV_AUX_BAD_GUID_SUM" },
	{ VDEV_AUX_TOO_SMALL, "VDEV_AUX_TOO_SMALL" },
	{ VDEV_AUX_BAD_LABEL, "VDEV_AUX_BAD_LABEL" },
	{ -1, NULL },
};

/* zpool_state_t to PoolStats$PoolState map */
static zjni_field_mapping_t pool_state_map[] = {
	{ POOL_STATE_ACTIVE, "POOL_STATE_ACTIVE" },
	{ POOL_STATE_EXPORTED, "POOL_STATE_EXPORTED" },
	{ POOL_STATE_DESTROYED, "POOL_STATE_DESTROYED" },
	{ POOL_STATE_SPARE, "POOL_STATE_SPARE" },
	{ POOL_STATE_UNINITIALIZED, "POOL_STATE_UNINITIALIZED" },
	{ POOL_STATE_UNAVAIL, "POOL_STATE_UNAVAIL" },
	{ POOL_STATE_POTENTIALLY_ACTIVE, "POOL_STATE_POTENTIALLY_ACTIVE" },
	{ -1, NULL },
};

/* zpool_status_t to PoolStats$PoolStatus map */
static zjni_field_mapping_t zpool_status_map[] = {
	{ ZPOOL_STATUS_CORRUPT_CACHE, "ZPOOL_STATUS_CORRUPT_CACHE" },
	{ ZPOOL_STATUS_MISSING_DEV_R, "ZPOOL_STATUS_MISSING_DEV_R" },
	{ ZPOOL_STATUS_MISSING_DEV_NR, "ZPOOL_STATUS_MISSING_DEV_NR" },
	{ ZPOOL_STATUS_CORRUPT_LABEL_R, "ZPOOL_STATUS_CORRUPT_LABEL_R" },
	{ ZPOOL_STATUS_CORRUPT_LABEL_NR, "ZPOOL_STATUS_CORRUPT_LABEL_NR" },
	{ ZPOOL_STATUS_BAD_GUID_SUM, "ZPOOL_STATUS_BAD_GUID_SUM" },
	{ ZPOOL_STATUS_CORRUPT_POOL, "ZPOOL_STATUS_CORRUPT_POOL" },
	{ ZPOOL_STATUS_CORRUPT_DATA, "ZPOOL_STATUS_CORRUPT_DATA" },
	{ ZPOOL_STATUS_FAILING_DEV, "ZPOOL_STATUS_FAILING_DEV" },
	{ ZPOOL_STATUS_VERSION_NEWER, "ZPOOL_STATUS_VERSION_NEWER" },
	{ ZPOOL_STATUS_HOSTID_MISMATCH, "ZPOOL_STATUS_HOSTID_MISMATCH" },
	{ ZPOOL_STATUS_FAULTED_DEV_R, "ZPOOL_STATUS_FAULTED_DEV_R" },
	{ ZPOOL_STATUS_FAULTED_DEV_NR, "ZPOOL_STATUS_FAULTED_DEV_NR" },
	{ ZPOOL_STATUS_BAD_LOG, "ZPOOL_STATUS_BAD_LOG" },
	{ ZPOOL_STATUS_VERSION_OLDER, "ZPOOL_STATUS_VERSION_OLDER" },
	{ ZPOOL_STATUS_RESILVERING, "ZPOOL_STATUS_RESILVERING" },
	{ ZPOOL_STATUS_OFFLINE_DEV, "ZPOOL_STATUS_OFFLINE_DEV" },
	{ ZPOOL_STATUS_REMOVED_DEV, "ZPOOL_STATUS_REMOVED_DEV" },
	{ ZPOOL_STATUS_OK, "ZPOOL_STATUS_OK" },
	{ -1, NULL }
};

/*
 * Function prototypes
 */

static void new_ImportablePoolBean(JNIEnv *, ImportablePoolBean_t *);
static void new_VirtualDevice(JNIEnv *, VirtualDeviceBean_t *);
static void new_LeafVirtualDevice(JNIEnv *, LeafVirtualDeviceBean_t *);
static void new_DiskVirtualDeviceBean(JNIEnv *, DiskVirtualDeviceBean_t *);
static void new_SliceVirtualDeviceBean(JNIEnv *, SliceVirtualDeviceBean_t *);
static void new_FileVirtualDeviceBean(JNIEnv *, FileVirtualDeviceBean_t *);
static void new_RAIDVirtualDeviceBean(JNIEnv *, RAIDVirtualDeviceBean_t *);
static void new_MirrorVirtualDeviceBean(JNIEnv *, MirrorVirtualDeviceBean_t *);
static int populate_ImportablePoolBean(
    JNIEnv *, ImportablePoolBean_t *, nvlist_t *);
static int populate_VirtualDeviceBean(JNIEnv *, zpool_handle_t *,
    nvlist_t *, uint64_t *p_vdev_id, VirtualDeviceBean_t *);
static int populate_LeafVirtualDeviceBean(JNIEnv *, zpool_handle_t *,
    nvlist_t *, uint64_t *p_vdev_id, LeafVirtualDeviceBean_t *);
static int populate_DiskVirtualDeviceBean(JNIEnv *, zpool_handle_t *,
    nvlist_t *, uint64_t *p_vdev_id, DiskVirtualDeviceBean_t *);
static int populate_SliceVirtualDeviceBean(JNIEnv *, zpool_handle_t *,
    nvlist_t *, uint64_t *p_vdev_id, SliceVirtualDeviceBean_t *);
static int populate_FileVirtualDeviceBean(JNIEnv *, zpool_handle_t *,
    nvlist_t *, uint64_t *p_vdev_id, FileVirtualDeviceBean_t *);
static int populate_RAIDVirtualDeviceBean(JNIEnv *, zpool_handle_t *,
    nvlist_t *, uint64_t *p_vdev_id, RAIDVirtualDeviceBean_t *);
static int populate_MirrorVirtualDeviceBean(JNIEnv *, zpool_handle_t *,
    nvlist_t *, uint64_t *p_vdev_id, MirrorVirtualDeviceBean_t *);
static jobject create_ImportablePoolBean(JNIEnv *, nvlist_t *);
static jobject create_DiskVirtualDeviceBean(
    JNIEnv *, zpool_handle_t *, nvlist_t *, uint64_t *p_vdev_id);
static jobject create_SliceVirtualDeviceBean(
    JNIEnv *, zpool_handle_t *, nvlist_t *, uint64_t *p_vdev_id);
static jobject create_FileVirtualDeviceBean(
    JNIEnv *, zpool_handle_t *, nvlist_t *, uint64_t *p_vdev_id);
static jobject create_RAIDVirtualDeviceBean(
    JNIEnv *, zpool_handle_t *, nvlist_t *, uint64_t *p_vdev_id);
static jobject create_MirrorVirtualDeviceBean(
    JNIEnv *, zpool_handle_t *, nvlist_t *, uint64_t *p_vdev_id);
static char *find_field(const zjni_field_mapping_t *, int);
static jobject zjni_vdev_state_to_obj(JNIEnv *, vdev_state_t);
static jobject zjni_vdev_aux_to_obj(JNIEnv *, vdev_aux_t);

/*
 * Static functions
 */

/* Create a ImportablePoolBean */
static void
new_ImportablePoolBean(JNIEnv *env, ImportablePoolBean_t *bean)
{
	zjni_Object_t *object = (zjni_Object_t *)bean;

	if (object->object == NULL) {
		object->class =
		    (*env)->FindClass(env,
		    ZFSJNI_PACKAGE_DATA "ImportablePoolBean");

		object->constructor =
		    (*env)->GetMethodID(env, object->class, "<init>", "()V");

		object->object =
		    (*env)->NewObject(env, object->class, object->constructor);
	}

	new_PoolStats(env, &(bean->interface_PoolStats), object);

	bean->method_setName = (*env)->GetMethodID(
	    env, object->class, "setName", "(Ljava/lang/String;)V");

	bean->method_setId = (*env)->GetMethodID(
	    env, object->class, "setId", "(J)V");
}

/* Create a VirtualDeviceBean */
static void
new_VirtualDevice(JNIEnv *env, VirtualDeviceBean_t *bean)
{
	zjni_Object_t *object = (zjni_Object_t *)bean;

	if (object->object == NULL) {
		object->class =
		    (*env)->FindClass(env,
		    ZFSJNI_PACKAGE_DATA "VirtualDeviceBean");

		object->constructor =
		    (*env)->GetMethodID(env, object->class, "<init>", "()V");

		object->object =
		    (*env)->NewObject(env, object->class, object->constructor);
	}

	new_DeviceStats(env, &(bean->interface_DeviceStats), object);

	bean->method_setPoolName = (*env)->GetMethodID(
	    env, object->class, "setPoolName", "(Ljava/lang/String;)V");

	bean->method_setParentIndex = (*env)->GetMethodID(
	    env, object->class, "setParentIndex", "(Ljava/lang/Long;)V");

	bean->method_setIndex = (*env)->GetMethodID(
	    env, object->class, "setIndex", "(J)V");
}

/* Create a LeafVirtualDeviceBean */
static void
new_LeafVirtualDevice(JNIEnv *env, LeafVirtualDeviceBean_t *bean)
{
	zjni_Object_t *object = (zjni_Object_t *)bean;

	if (object->object == NULL) {
		object->class =
		    (*env)->FindClass(env,
		    ZFSJNI_PACKAGE_DATA "LeafVirtualDeviceBean");

		object->constructor =
		    (*env)->GetMethodID(env, object->class, "<init>", "()V");

		object->object =
		    (*env)->NewObject(env, object->class, object->constructor);
	}

	new_VirtualDevice(env, (VirtualDeviceBean_t *)bean);

	bean->method_setName = (*env)->GetMethodID(
	    env, object->class, "setName", "(Ljava/lang/String;)V");
}

/* Create a DiskVirtualDeviceBean */
static void
new_DiskVirtualDeviceBean(JNIEnv *env, DiskVirtualDeviceBean_t *bean)
{
	zjni_Object_t *object = (zjni_Object_t *)bean;

	if (object->object == NULL) {
		object->class = (*env)->FindClass(
		    env, ZFSJNI_PACKAGE_DATA "DiskVirtualDeviceBean");

		object->constructor =
		    (*env)->GetMethodID(env, object->class, "<init>", "()V");

		object->object =
		    (*env)->NewObject(env, object->class, object->constructor);
	}

	new_LeafVirtualDevice(env, (LeafVirtualDeviceBean_t *)bean);
}

/* Create a SliceVirtualDeviceBean */
static void
new_SliceVirtualDeviceBean(JNIEnv *env, SliceVirtualDeviceBean_t *bean)
{
	zjni_Object_t *object = (zjni_Object_t *)bean;

	if (object->object == NULL) {
		object->class = (*env)->FindClass(
		    env, ZFSJNI_PACKAGE_DATA "SliceVirtualDeviceBean");

		object->constructor =
		    (*env)->GetMethodID(env, object->class, "<init>", "()V");

		object->object =
		    (*env)->NewObject(env, object->class, object->constructor);
	}

	new_LeafVirtualDevice(env, (LeafVirtualDeviceBean_t *)bean);
}

/* Create a FileVirtualDeviceBean */
static void
new_FileVirtualDeviceBean(JNIEnv *env, FileVirtualDeviceBean_t *bean)
{
	zjni_Object_t *object = (zjni_Object_t *)bean;

	if (object->object == NULL) {
		object->class = (*env)->FindClass(
		    env, ZFSJNI_PACKAGE_DATA "FileVirtualDeviceBean");

		object->constructor =
		    (*env)->GetMethodID(env, object->class, "<init>", "()V");

		object->object =
		    (*env)->NewObject(env, object->class, object->constructor);
	}

	new_LeafVirtualDevice(env, (LeafVirtualDeviceBean_t *)bean);
}

/* Create a RAIDVirtualDeviceBean */
static void
new_RAIDVirtualDeviceBean(JNIEnv *env, RAIDVirtualDeviceBean_t *bean)
{
	zjni_Object_t *object = (zjni_Object_t *)bean;

	if (object->object == NULL) {

		object->class = (*env)->FindClass(
		    env, ZFSJNI_PACKAGE_DATA "RAIDVirtualDeviceBean");

		object->constructor =
		    (*env)->GetMethodID(env, object->class, "<init>", "()V");

		object->object =
		    (*env)->NewObject(env, object->class, object->constructor);
	}

	new_VirtualDevice(env, (VirtualDeviceBean_t *)bean);

	bean->method_setParity = (*env)->GetMethodID(
	    env, object->class, "setParity", "(J)V");
}

/* Create a MirrorVirtualDeviceBean */
static void
new_MirrorVirtualDeviceBean(JNIEnv *env, MirrorVirtualDeviceBean_t *bean)
{
	zjni_Object_t *object = (zjni_Object_t *)bean;

	if (object->object == NULL) {
		object->class = (*env)->FindClass(
		    env, ZFSJNI_PACKAGE_DATA "MirrorVirtualDeviceBean");

		object->constructor =
		    (*env)->GetMethodID(env, object->class, "<init>", "()V");

		object->object =
		    (*env)->NewObject(env, object->class, object->constructor);
	}

	new_VirtualDevice(env, (VirtualDeviceBean_t *)bean);
}

static int
populate_ImportablePoolBean(JNIEnv *env, ImportablePoolBean_t *bean,
    nvlist_t *config)
{
	char *c;
	char *name;
	uint64_t guid;
	uint64_t state;
	uint64_t version;
	nvlist_t *devices;

	zjni_Object_t *object = (zjni_Object_t *)bean;
	PoolStatsBean_t *pool_stats = &(bean->interface_PoolStats);
	DeviceStatsBean_t *dev_stats = (DeviceStatsBean_t *)pool_stats;

	if (nvlist_lookup_string(config, ZPOOL_CONFIG_POOL_NAME, &name) ||
	    nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_GUID, &guid) ||
	    nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_STATE, &state) ||
	    nvlist_lookup_uint64(config, ZPOOL_CONFIG_VERSION, &version) ||
	    nvlist_lookup_nvlist(config, ZPOOL_CONFIG_VDEV_TREE, &devices) ||
	    populate_DeviceStatsBean(env, devices, dev_stats, object)) {
		return (-1);
	}

	(*env)->CallVoidMethod(env, object->object,
	    bean->method_setName, (*env)->NewStringUTF(env, name));

	(*env)->CallVoidMethod(env, object->object,
	    bean->method_setId, (jlong)guid);

	(*env)->CallVoidMethod(env, object->object,
	    pool_stats->method_setPoolState,
	    zjni_pool_state_to_obj(env, (pool_state_t)state));

	(*env)->CallVoidMethod(env, object->object,
	    pool_stats->method_setPoolStatus,
	    zjni_pool_status_to_obj(env, zpool_import_status(config, &c,
	    NULL)));

	(*env)->CallVoidMethod(env, object->object,
	    pool_stats->method_setPoolVersion, (jlong)version);

	return (0);
}

static int
populate_VirtualDeviceBean(JNIEnv *env, zpool_handle_t *zhp,
    nvlist_t *vdev, uint64_t *p_vdev_id, VirtualDeviceBean_t *bean)
{
	int result;
	uint64_t vdev_id;
	jstring poolUTF;

	zjni_Object_t *object = (zjni_Object_t *)bean;
	DeviceStatsBean_t *stats = &(bean->interface_DeviceStats);

	result = populate_DeviceStatsBean(env, vdev, stats, object);
	if (result != 0) {
		return (1);
	}

	/* Set pool name */
	poolUTF = (*env)->NewStringUTF(env, zpool_get_name(zhp));
	(*env)->CallVoidMethod(
	    env, object->object, bean->method_setPoolName, poolUTF);

	/* Set parent vdev index */
	(*env)->CallVoidMethod(
	    env, object->object, bean->method_setParentIndex,
	    p_vdev_id == NULL ? NULL :
	    zjni_long_to_Long(env, *p_vdev_id));

	/* Get index */
	result = nvlist_lookup_uint64(vdev, ZPOOL_CONFIG_GUID, &vdev_id);
	if (result != 0) {
		zjni_throw_exception(env,
		    "could not retrieve virtual device ID (pool %s)",
		    zpool_get_name(zhp));
		return (1);
	}

	(*env)->CallVoidMethod(
	    env, object->object, bean->method_setIndex, (jlong)vdev_id);

	return (0);
}

static int
populate_LeafVirtualDeviceBean(JNIEnv *env, zpool_handle_t *zhp,
    nvlist_t *vdev, uint64_t *p_vdev_id, LeafVirtualDeviceBean_t *bean)
{
	return (populate_VirtualDeviceBean(
	    env, zhp, vdev, p_vdev_id, (VirtualDeviceBean_t *)bean));
}

static int
populate_DiskVirtualDeviceBean(JNIEnv *env, zpool_handle_t *zhp,
    nvlist_t *vdev, uint64_t *p_vdev_id, DiskVirtualDeviceBean_t *bean)
{
	char *path;
	int result = populate_LeafVirtualDeviceBean(
	    env, zhp, vdev, p_vdev_id, (LeafVirtualDeviceBean_t *)bean);

	if (result) {
		/* Must not call any more Java methods to preserve exception */
		return (-1);
	}

	/* Set path */
	result = nvlist_lookup_string(vdev, ZPOOL_CONFIG_PATH, &path);
	if (result != 0) {
		zjni_throw_exception(env,
		    "could not retrieve path from disk virtual device "
		    "(pool %s)", zpool_get_name(zhp));
	} else {

		regex_t re;
		regmatch_t matches[2];
		jstring pathUTF = NULL;

		/* Strip off slice portion of name, if applicable */
		if (regcomp(&re, "^(/dev/dsk/.*)s[0-9]+$", REG_EXTENDED) == 0) {
			if (regexec(&re, path, 2, matches, 0) == 0) {
				regmatch_t *match = matches + 1;
				if (match->rm_so != -1 && match->rm_eo != -1) {
					char *tmp = strdup(path);
					if (tmp != NULL) {
						char *end = tmp + match->rm_eo;
						*end = '\0';
						pathUTF = (*env)->NewStringUTF(
						    env, tmp);
						free(tmp);
					}
				}
			}
			regfree(&re);
		}
		if (regcomp(&re, "^(/dev/dsk/.*)s[0-9]+/old$", REG_EXTENDED) ==
		    0) {
			if (regexec(&re, path, 2, matches, 0) == 0) {
				regmatch_t *match = matches + 1;
				if (match->rm_so != -1 && match->rm_eo != -1) {
					char *tmp = strdup(path);
					if (tmp != NULL) {
						(void) strcpy(tmp +
						    match->rm_eo, "/old");
						pathUTF = (*env)->NewStringUTF(
						    env, tmp);
						free(tmp);
					}
				}
			}
			regfree(&re);
		}

		if (pathUTF == NULL) {
			pathUTF = (*env)->NewStringUTF(env, path);
		}

		(*env)->CallVoidMethod(env, ((zjni_Object_t *)bean)->object,
		    ((LeafVirtualDeviceBean_t *)bean)->method_setName, pathUTF);
	}

	return (result != 0);
}

static int
populate_SliceVirtualDeviceBean(JNIEnv *env, zpool_handle_t *zhp,
    nvlist_t *vdev, uint64_t *p_vdev_id, SliceVirtualDeviceBean_t *bean)
{
	char *path;
	int result = populate_LeafVirtualDeviceBean(
	    env, zhp, vdev, p_vdev_id, (LeafVirtualDeviceBean_t *)bean);

	if (result) {
		/* Must not call any more Java methods to preserve exception */
		return (-1);
	}

	/* Set path */
	result = nvlist_lookup_string(vdev, ZPOOL_CONFIG_PATH, &path);
	if (result != 0) {
		zjni_throw_exception(env,
		    "could not retrieve path from slice virtual device (pool "
		    "%s)", zpool_get_name(zhp));
	} else {

		jstring pathUTF = (*env)->NewStringUTF(env, path);
		(*env)->CallVoidMethod(env, ((zjni_Object_t *)bean)->object,
		    ((LeafVirtualDeviceBean_t *)bean)->method_setName,
		    pathUTF);
	}

	return (result != 0);
}

static int
populate_FileVirtualDeviceBean(JNIEnv *env, zpool_handle_t *zhp,
    nvlist_t *vdev, uint64_t *p_vdev_id, FileVirtualDeviceBean_t *bean)
{
	char *path;
	int result = populate_LeafVirtualDeviceBean(
	    env, zhp, vdev, p_vdev_id, (LeafVirtualDeviceBean_t *)bean);

	if (result) {
		/* Must not call any more Java methods to preserve exception */
		return (-1);
	}

	/* Set path */
	result = nvlist_lookup_string(vdev, ZPOOL_CONFIG_PATH, &path);
	if (result != 0) {
		zjni_throw_exception(env,
		    "could not retrieve path from disk virtual device "
		    "(pool %s)", zpool_get_name(zhp));
	} else {

		jstring pathUTF = (*env)->NewStringUTF(env, path);
		(*env)->CallVoidMethod(env, ((zjni_Object_t *)bean)->object,
		    ((LeafVirtualDeviceBean_t *)bean)->method_setName, pathUTF);
	}

	return (result != 0);
}

static int
populate_RAIDVirtualDeviceBean(JNIEnv *env, zpool_handle_t *zhp,
    nvlist_t *vdev, uint64_t *p_vdev_id, RAIDVirtualDeviceBean_t *bean)
{
	return (populate_VirtualDeviceBean(env, zhp, vdev, p_vdev_id,
	    (VirtualDeviceBean_t *)bean));
}

static int
populate_MirrorVirtualDeviceBean(JNIEnv *env, zpool_handle_t *zhp,
    nvlist_t *vdev, uint64_t *p_vdev_id, MirrorVirtualDeviceBean_t *bean)
{
	return (populate_VirtualDeviceBean(env, zhp, vdev, p_vdev_id,
	    (VirtualDeviceBean_t *)bean));
}

static jobject
create_ImportablePoolBean(JNIEnv *env, nvlist_t *config)
{
	int result;
	ImportablePoolBean_t bean_obj = {0};
	ImportablePoolBean_t *bean = &bean_obj;

	/* Construct ImportablePoolBean */
	new_ImportablePoolBean(env, bean);

	result = populate_ImportablePoolBean(env, bean, config);
	if (result) {
		/* Must not call any more Java methods to preserve exception */
		return (NULL);
	}

	return (((zjni_Object_t *)bean)->object);
}

static jobject
create_DiskVirtualDeviceBean(JNIEnv *env, zpool_handle_t *zhp,
    nvlist_t *vdev, uint64_t *p_vdev_id)
{
	int result;
	DiskVirtualDeviceBean_t bean_obj = {0};
	DiskVirtualDeviceBean_t *bean = &bean_obj;

	/* Construct DiskVirtualDeviceBean */
	new_DiskVirtualDeviceBean(env, bean);

	result = populate_DiskVirtualDeviceBean(
	    env, zhp, vdev, p_vdev_id, bean);
	if (result) {
		/* Must not call any more Java methods to preserve exception */
		return (NULL);
	}

	return (((zjni_Object_t *)bean)->object);
}

static jobject
create_SliceVirtualDeviceBean(JNIEnv *env, zpool_handle_t *zhp,
    nvlist_t *vdev, uint64_t *p_vdev_id)
{
	int result;
	SliceVirtualDeviceBean_t bean_obj = {0};
	SliceVirtualDeviceBean_t *bean = &bean_obj;

	/* Construct SliceVirtualDeviceBean */
	new_SliceVirtualDeviceBean(env, bean);

	result = populate_SliceVirtualDeviceBean(
	    env, zhp, vdev, p_vdev_id, bean);
	if (result) {
		/* Must not call any more Java methods to preserve exception */
		return (NULL);
	}

	return (((zjni_Object_t *)bean)->object);
}

static jobject
create_FileVirtualDeviceBean(JNIEnv *env, zpool_handle_t *zhp,
    nvlist_t *vdev, uint64_t *p_vdev_id)
{
	int result;
	FileVirtualDeviceBean_t bean_obj = {0};
	FileVirtualDeviceBean_t *bean = &bean_obj;

	/* Construct FileVirtualDeviceBean */
	new_FileVirtualDeviceBean(env, bean);

	result = populate_FileVirtualDeviceBean(
	    env, zhp, vdev, p_vdev_id, bean);
	if (result) {
		/* Must not call any more Java methods to preserve exception */
		return (NULL);
	}

	return (((zjni_Object_t *)bean)->object);
}

static jobject
create_RAIDVirtualDeviceBean(JNIEnv *env, zpool_handle_t *zhp,
    nvlist_t *vdev, uint64_t *p_vdev_id)
{
	int result;
	uint64_t parity;
	RAIDVirtualDeviceBean_t bean_obj = {0};
	RAIDVirtualDeviceBean_t *bean = &bean_obj;

	((zjni_Object_t *)bean)->object = NULL;

	/* Construct RAIDVirtualDeviceBean */
	new_RAIDVirtualDeviceBean(env, bean);

	/* Set parity bit */
	result = nvlist_lookup_uint64(vdev, ZPOOL_CONFIG_NPARITY,
	    &parity);
	if (result) {
		/* Default to RAID-Z1 in case of error */
		parity = 1;
	}

	(*env)->CallVoidMethod(
	    env, ((zjni_Object_t *)bean)->object, bean->method_setParity,
	    (jlong)parity);


	result = populate_RAIDVirtualDeviceBean(
	    env, zhp, vdev, p_vdev_id, bean);
	if (result) {
		/* Must not call any more Java methods to preserve exception */
		return (NULL);
	}

	return (((zjni_Object_t *)bean)->object);
}

static jobject
create_MirrorVirtualDeviceBean(JNIEnv *env, zpool_handle_t *zhp,
    nvlist_t *vdev, uint64_t *p_vdev_id)
{
	int result;
	MirrorVirtualDeviceBean_t bean_obj = {0};
	MirrorVirtualDeviceBean_t *bean = &bean_obj;

	/* Construct MirrorVirtualDeviceBean */
	new_MirrorVirtualDeviceBean(env, bean);

	result = populate_MirrorVirtualDeviceBean(
	    env, zhp, vdev, p_vdev_id, bean);
	if (result) {
		/* Must not call any more Java methods to preserve exception */
		return (NULL);
	}

	return (((zjni_Object_t *)bean)->object);
}

static char *
find_field(const zjni_field_mapping_t *mapping, int value)
{
	int i;
	for (i = 0; mapping[i].name != NULL; i++) {
		if (value == mapping[i].value) {
			return (mapping[i].name);
		}
	}
	return (NULL);
}

/*
 * Converts a vdev_state_t to a Java DeviceStats$DeviceState object.
 */
static jobject
zjni_vdev_state_to_obj(JNIEnv *env, vdev_state_t state)
{
	return (zjni_int_to_enum(env, state,
	    ZFSJNI_PACKAGE_DATA "DeviceStats$DeviceState",
	    "VDEV_STATE_UNKNOWN", vdev_state_map));
}

/*
 * Converts a vdev_aux_t to a Java DeviceStats$DeviceStatus object.
 */
static jobject
zjni_vdev_aux_to_obj(JNIEnv *env, vdev_aux_t aux)
{
	return (zjni_int_to_enum(env, aux,
	    ZFSJNI_PACKAGE_DATA "DeviceStats$DeviceStatus",
	    "VDEV_AUX_NONE", vdev_aux_map));
}

/*
 * Package-private functions
 */

/* Create a DeviceStatsBean */
void
new_DeviceStats(JNIEnv *env, DeviceStatsBean_t *bean, zjni_Object_t *object)
{
	bean->method_setSize = (*env)->GetMethodID(
	    env, object->class, "setSize", "(J)V");

	bean->method_setReplacementSize = (*env)->GetMethodID(
	    env, object->class, "setReplacementSize", "(J)V");

	bean->method_setUsed = (*env)->GetMethodID(
	    env, object->class, "setUsed", "(J)V");

	bean->method_setReadBytes = (*env)->GetMethodID(
	    env, object->class, "setReadBytes", "(J)V");

	bean->method_setWriteBytes = (*env)->GetMethodID(
	    env, object->class, "setWriteBytes", "(J)V");

	bean->method_setReadOperations = (*env)->GetMethodID(
	    env, object->class, "setReadOperations", "(J)V");

	bean->method_setWriteOperations = (*env)->GetMethodID(
	    env, object->class, "setWriteOperations", "(J)V");

	bean->method_setReadErrors = (*env)->GetMethodID(
	    env, object->class, "setReadErrors", "(J)V");

	bean->method_setWriteErrors = (*env)->GetMethodID(
	    env, object->class, "setWriteErrors", "(J)V");

	bean->method_setChecksumErrors = (*env)->GetMethodID(
	    env, object->class, "setChecksumErrors", "(J)V");

	bean->method_setDeviceState = (*env)->GetMethodID(
	    env, object->class, "setDeviceState",
	    "(L" ZFSJNI_PACKAGE_DATA "DeviceStats$DeviceState;)V");

	bean->method_setDeviceStatus = (*env)->GetMethodID(
	    env, object->class, "setDeviceStatus",
	    "(L" ZFSJNI_PACKAGE_DATA "DeviceStats$DeviceStatus;)V");
}

/* Create a PoolStatsBean */
void
new_PoolStats(JNIEnv *env, PoolStatsBean_t *bean, zjni_Object_t *object)
{
	new_DeviceStats(env, (DeviceStatsBean_t *)bean, object);

	bean->method_setPoolState = (*env)->GetMethodID(
	    env, object->class, "setPoolState",
	    "(L" ZFSJNI_PACKAGE_DATA "PoolStats$PoolState;)V");

	bean->method_setPoolStatus = (*env)->GetMethodID(
	    env, object->class, "setPoolStatus",
	    "(L" ZFSJNI_PACKAGE_DATA "PoolStats$PoolStatus;)V");

	bean->method_setPoolVersion = (*env)->GetMethodID(
	    env, object->class, "setPoolVersion", "(J)V");
}

/*
 * Gets the root vdev (an nvlist_t *) for the given pool.
 */
nvlist_t *
zjni_get_root_vdev(zpool_handle_t *zhp)
{
	nvlist_t *root = NULL;

	if (zhp != NULL) {
		nvlist_t *attrs = zpool_get_config(zhp, NULL);

		if (attrs != NULL) {
			int result = nvlist_lookup_nvlist(
			    attrs, ZPOOL_CONFIG_VDEV_TREE, &root);
			if (result != 0) {
				root = NULL;
			}
		}
	}

	return (root);
}

/*
 * Gets the vdev (an nvlist_t *) with the given vdev_id, below the
 * given vdev.  If the given vdev is NULL, all vdevs within the given
 * pool are searched.
 *
 * If p_vdev_id is not NULL, it will be set to the ID of the parent
 * vdev, if any, or to vdev_id_to_find if the searched-for vdev is a
 * toplevel vdev.
 */
nvlist_t *
zjni_get_vdev(zpool_handle_t *zhp, nvlist_t *vdev_parent,
    uint64_t vdev_id_to_find, uint64_t *p_vdev_id)
{
	int result;
	uint64_t id = vdev_id_to_find;

	/* Was a vdev specified? */
	if (vdev_parent == NULL) {
		/* No -- retrieve the top-level pool vdev */
		vdev_parent = zjni_get_root_vdev(zhp);
	} else {
		/* Get index of this vdev and compare with vdev_id_to_find */
		result = nvlist_lookup_uint64(
		    vdev_parent, ZPOOL_CONFIG_GUID, &id);
		if (result == 0 && id == vdev_id_to_find) {
			return (vdev_parent);
		}
	}

	if (vdev_parent != NULL) {

		nvlist_t **children;
		uint_t nelem = 0;

		/* Get the vdevs under this vdev */
		result = nvlist_lookup_nvlist_array(
		    vdev_parent, ZPOOL_CONFIG_CHILDREN, &children, &nelem);

		if (result == 0) {

			int i;
			nvlist_t *child;

			/* For each vdev child... */
			for (i = 0; i < nelem; i++) {
				if (p_vdev_id != NULL) {
					/* Save parent vdev id */
					*p_vdev_id = id;
				}

				child = zjni_get_vdev(zhp, children[i],
				    vdev_id_to_find, p_vdev_id);
				if (child != NULL) {
					return (child);
				}
			}
		}
	}

	return (NULL);
}

jobject
zjni_get_VirtualDevice_from_vdev(JNIEnv *env, zpool_handle_t *zhp,
    nvlist_t *vdev, uint64_t *p_vdev_id)
{
	jobject obj = NULL;
	char *type = NULL;
	int result = nvlist_lookup_string(vdev, ZPOOL_CONFIG_TYPE, &type);

	if (result == 0) {
		if (strcmp(type, VDEV_TYPE_DISK) == 0) {
			uint64_t wholedisk;
			if (nvlist_lookup_uint64(vdev, ZPOOL_CONFIG_WHOLE_DISK,
			    &wholedisk) == 0 && wholedisk) {
				obj = create_DiskVirtualDeviceBean(
				    env, zhp, vdev, p_vdev_id);
			} else {
				obj = create_SliceVirtualDeviceBean(
				    env, zhp, vdev, p_vdev_id);
			}
		} else if (strcmp(type, VDEV_TYPE_FILE) == 0) {
			obj = create_FileVirtualDeviceBean(
			    env, zhp, vdev, p_vdev_id);
		} else if (strcmp(type, VDEV_TYPE_RAIDZ) == 0) {
			obj = create_RAIDVirtualDeviceBean(
			    env, zhp, vdev, p_vdev_id);
		} else if (strcmp(type, VDEV_TYPE_MIRROR) == 0) {
			obj = create_MirrorVirtualDeviceBean(
			    env, zhp, vdev, p_vdev_id);
		} else if (strcmp(type, VDEV_TYPE_REPLACING) == 0) {

			/* Get the vdevs under this vdev */
			nvlist_t **children;
			uint_t nelem = 0;
			int result = nvlist_lookup_nvlist_array(
			    vdev, ZPOOL_CONFIG_CHILDREN, &children, &nelem);

			if (result == 0 && nelem > 0) {

				/* Get last vdev child (replacement device) */
				nvlist_t *child = children[nelem - 1];

				obj = zjni_get_VirtualDevice_from_vdev(env,
				    zhp, child, p_vdev_id);
			}
		}
	}

	return (obj);
}

jobject
zjni_get_VirtualDevices_from_vdev(JNIEnv *env, zpool_handle_t *zhp,
    nvlist_t *vdev_parent, uint64_t *p_vdev_id)
{
	/* Create an array list for the vdevs */
	zjni_ArrayList_t list_class = {0};
	zjni_ArrayList_t *list_class_p = &list_class;
	zjni_new_ArrayList(env, list_class_p);

	/* Was a vdev specified? */
	if (vdev_parent == NULL) {
		/* No -- retrieve the top-level pool vdev */
		vdev_parent = zjni_get_root_vdev(zhp);
	}

	if (vdev_parent != NULL) {

		/* Get the vdevs under this vdev */
		nvlist_t **children;
		uint_t nelem = 0;
		int result = nvlist_lookup_nvlist_array(
		    vdev_parent, ZPOOL_CONFIG_CHILDREN, &children, &nelem);

		if (result == 0) {

			/* For each vdev child... */
			int i;
			for (i = 0; i < nelem; i++) {
				nvlist_t *child = children[i];

				/* Create a Java object from this vdev */
				jobject obj =
				    zjni_get_VirtualDevice_from_vdev(env,
				    zhp, child, p_vdev_id);

				if ((*env)->ExceptionOccurred(env) != NULL) {
					/*
					 * Must not call any more Java methods
					 * to preserve exception
					 */
					return (NULL);
				}

				if (obj != NULL) {
				    /* Add child to child vdev list */
					(*env)->CallBooleanMethod(env,
					    ((zjni_Object_t *)
					    list_class_p)->object,
					    ((zjni_Collection_t *)
					    list_class_p)->method_add, obj);
				}
			}
		}
	}

	return (zjni_Collection_to_array(
	    env, (zjni_Collection_t *)list_class_p,
	    ZFSJNI_PACKAGE_DATA "VirtualDevice"));
}

int
zjni_create_add_ImportablePool(nvlist_t *config, void *data)
{

	JNIEnv *env = ((zjni_ArrayCallbackData_t *)data)->env;
	zjni_Collection_t *list = ((zjni_ArrayCallbackData_t *)data)->list;

	/* Construct ImportablePool object */
	jobject bean = create_ImportablePoolBean(env, config);
	if (bean == NULL) {
		return (-1);
	}

	/* Add bean to list */
	(*env)->CallBooleanMethod(env, ((zjni_Object_t *)list)->object,
	    ((zjni_Collection_t *)list)->method_add, bean);

	return (0);
}

int
populate_DeviceStatsBean(JNIEnv *env, nvlist_t *vdev,
    DeviceStatsBean_t *bean, zjni_Object_t *object)
{
	uint_t c;
	vdev_stat_t *vs;

	int result = nvlist_lookup_uint64_array(
	    vdev, ZPOOL_CONFIG_VDEV_STATS, (uint64_t **)&vs, &c);
	if (result != 0) {
		zjni_throw_exception(env,
		    "could not retrieve virtual device statistics");
		return (1);
	}

	(*env)->CallVoidMethod(env, object->object,
	    bean->method_setUsed, (jlong)vs->vs_alloc);

	(*env)->CallVoidMethod(env, object->object,
	    bean->method_setSize, (jlong)vs->vs_space);

	(*env)->CallVoidMethod(env, object->object,
	    bean->method_setReplacementSize, (jlong)vs->vs_rsize);

	(*env)->CallVoidMethod(env, object->object,
	    bean->method_setReadBytes, (jlong)vs->vs_bytes[ZIO_TYPE_READ]);

	(*env)->CallVoidMethod(env, object->object,
	    bean->method_setWriteBytes, (jlong)vs->vs_bytes[ZIO_TYPE_WRITE]);

	(*env)->CallVoidMethod(env, object->object,
	    bean->method_setReadOperations, (jlong)vs->vs_ops[ZIO_TYPE_READ]);

	(*env)->CallVoidMethod(env, object->object,
	    bean->method_setWriteOperations, (jlong)vs->vs_ops[ZIO_TYPE_WRITE]);

	(*env)->CallVoidMethod(env, object->object,
	    bean->method_setReadErrors, (jlong)vs->vs_read_errors);

	(*env)->CallVoidMethod(env, object->object,
	    bean->method_setWriteErrors, (jlong)vs->vs_write_errors);

	(*env)->CallVoidMethod(env, object->object,
	    bean->method_setChecksumErrors, (jlong)vs->vs_checksum_errors);

	(*env)->CallVoidMethod(env, object->object,
	    bean->method_setDeviceState,
	    zjni_vdev_state_to_obj(env, vs->vs_state));

	(*env)->CallVoidMethod(env, object->object,
	    bean->method_setDeviceStatus,
	    zjni_vdev_aux_to_obj(env, vs->vs_aux));

	return (0);
}

/*
 * Converts a pool_state_t to a Java PoolStats$PoolState object.
 */
jobject
zjni_pool_state_to_obj(JNIEnv *env, pool_state_t state)
{
	return (zjni_int_to_enum(env, state,
	    ZFSJNI_PACKAGE_DATA "PoolStats$PoolState",
	    "POOL_STATE_ACTIVE", pool_state_map));
}

/*
 * Converts a zpool_status_t to a Java PoolStats$PoolStatus object.
 */
jobject
zjni_pool_status_to_obj(JNIEnv *env, zpool_status_t status)
{
	return (zjni_int_to_enum(env, status,
	    ZFSJNI_PACKAGE_DATA "PoolStats$PoolStatus",
	    "ZPOOL_STATUS_OK", zpool_status_map));
}

/*
 * Extern functions
 */

/*
 * Iterates through each importable pool on the system.  For each
 * importable pool, runs the given function with the given void as the
 * last arg.
 */
int
zjni_ipool_iter(int argc, char **argv, zjni_ipool_iter_f func, void *data)
{
	nvlist_t *pools;
	importargs_t iarg = { 0 };

	iarg.paths = argc;
	iarg.path = argv;
	iarg.can_be_active = B_TRUE;

	pools = zpool_search_import(g_zfs, &iarg, &libzfs_config_ops);

	if (pools != NULL) {
		nvpair_t *elem = NULL;

		while ((elem = nvlist_next_nvpair(pools, elem)) != NULL) {
			nvlist_t *config;

			if (nvpair_value_nvlist(elem, &config) != 0 ||
			    func(config, data)) {
				return (-1);
			}
		}
	}

	return (0);
}

char *
zjni_vdev_state_to_str(vdev_state_t state)
{
	return (find_field(vdev_state_map, state));
}

char *
zjni_vdev_aux_to_str(vdev_aux_t aux)
{
	return (find_field(vdev_aux_map, aux));
}

char *
zjni_pool_state_to_str(pool_state_t state)
{
	return (find_field(pool_state_map, state));
}

char *
zjni_pool_status_to_str(zpool_status_t status)
{
	return (find_field(zpool_status_map, status));
}
