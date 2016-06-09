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
 * Copyright (c) 2015 by Delphix. All rights reserved.
 */

#include "libzfs_jni_property.h"
#include "libzfs_jni_util.h"
#include <strings.h>

/*
 * Types
 */

/* Signature for function to convert string to a specific Java object */
typedef jobject (*str_to_obj_f)(JNIEnv *, char *);

/* Signature for function to convert uint64_t to a specific Java object */
typedef jobject (*uint64_to_obj_f)(JNIEnv *, uint64_t);

/*
 * Describes a property and the parameters needed to create a Java
 * Property object for it
 */
typedef struct custom_prop_desct {
	zfs_prop_t prop;
	str_to_obj_f convert_str;
	uint64_to_obj_f convert_uint64;
	char *propClass;
	char *valueClass;
} custom_prop_desct_t;

/*
 * Function prototypes
 */

static jobject create_BasicProperty(JNIEnv *, zfs_handle_t *,
    zfs_prop_t, str_to_obj_f, uint64_to_obj_f, char *, char *);
static jobject create_BooleanProperty(JNIEnv *, zfs_handle_t *, zfs_prop_t);
static jobject create_LongProperty(JNIEnv *, zfs_handle_t *, zfs_prop_t);
static jobject create_StringProperty(JNIEnv *, zfs_handle_t *, zfs_prop_t);
static jobject create_ObjectProperty(JNIEnv *, zfs_handle_t *,
    zfs_prop_t, str_to_obj_f, uint64_to_obj_f, char *, char *);
static jobject create_default_BasicProperty(JNIEnv *, zfs_prop_t,
    str_to_obj_f, uint64_to_obj_f, char *, char *);
static jobject create_default_BooleanProperty(JNIEnv *, zfs_prop_t);
static jobject create_default_LongProperty(JNIEnv *, zfs_prop_t);
static jobject create_default_StringProperty(JNIEnv *, zfs_prop_t);
static jobject create_default_ObjectProperty(
    JNIEnv *, zfs_prop_t, str_to_obj_f, uint64_to_obj_f, char *, char *);
static jobject str_to_enum_element(JNIEnv *, char *, char *);
static jobject str_to_aclinherit(JNIEnv *, char *);
static jobject str_to_aclmode(JNIEnv *, char *);
static jobject str_to_checksum(JNIEnv *, char *);
static jobject str_to_compression(JNIEnv *, char *);
static jobject str_to_snapdir(JNIEnv *, char *);
static jobject str_to_string(JNIEnv *, char *);

/*
 * Static data
 */

zfs_prop_t props_boolean[] = {
	ZFS_PROP_ATIME,
	ZFS_PROP_DEVICES,
	ZFS_PROP_EXEC,
	ZFS_PROP_MOUNTED,
	ZFS_PROP_READONLY,
	ZFS_PROP_SETUID,
	ZFS_PROP_ZONED,
	ZFS_PROP_DEFER_DESTROY,
	ZPROP_INVAL
};

zfs_prop_t props_long[] = {
	ZFS_PROP_AVAILABLE,
	ZFS_PROP_CREATETXG,
	ZFS_PROP_QUOTA,
	ZFS_PROP_REFERENCED,
	ZFS_PROP_RESERVATION,
	ZFS_PROP_USED,
	ZFS_PROP_VOLSIZE,
	ZFS_PROP_REFQUOTA,
	ZFS_PROP_REFRESERVATION,
	ZFS_PROP_USERREFS,
	ZPROP_INVAL
};

zfs_prop_t props_string[] = {
	ZFS_PROP_ORIGIN,
	/* ZFS_PROP_TYPE, */
	ZPROP_INVAL
};

custom_prop_desct_t props_custom[] = {
	{ ZFS_PROP_ACLINHERIT, str_to_aclinherit, NULL,
	    ZFSJNI_PACKAGE_DATA "AclInheritProperty",
	    ZFSJNI_PACKAGE_DATA "AclInheritProperty$AclInherit" },

	{ ZFS_PROP_ACLMODE, str_to_aclmode, NULL,
	    ZFSJNI_PACKAGE_DATA "AclModeProperty",
	    ZFSJNI_PACKAGE_DATA "AclModeProperty$AclMode" },

	{ ZFS_PROP_CHECKSUM, str_to_checksum, NULL,
	    ZFSJNI_PACKAGE_DATA "ChecksumProperty",
	    ZFSJNI_PACKAGE_DATA "ChecksumProperty$Checksum" },

	{ ZFS_PROP_COMPRESSION, str_to_compression, NULL,
	    ZFSJNI_PACKAGE_DATA "CompressionProperty",
	    ZFSJNI_PACKAGE_DATA "CompressionProperty$Compression" },

	{ ZFS_PROP_COMPRESSRATIO, NULL, zjni_long_to_Long,
	    ZFSJNI_PACKAGE_DATA "CompressRatioProperty",
	    "java/lang/Long" },

	{ ZFS_PROP_CREATION, zjni_str_to_date, NULL,
	    ZFSJNI_PACKAGE_DATA "CreationProperty",
	    "java/util/Date" },

	{ ZFS_PROP_MOUNTPOINT, str_to_string, NULL,
	    ZFSJNI_PACKAGE_DATA "MountPointProperty",
	    "java/lang/String" },

	{ ZFS_PROP_RECORDSIZE, NULL, zjni_long_to_Long,
	    ZFSJNI_PACKAGE_DATA "RecordSizeProperty",
	    "java/lang/Long" },

	{ ZFS_PROP_SHARENFS, str_to_string, NULL,
	    ZFSJNI_PACKAGE_DATA "ShareNFSProperty",
	    "java/lang/String" },

	{ ZFS_PROP_SNAPDIR, str_to_snapdir, NULL,
	    ZFSJNI_PACKAGE_DATA "SnapDirProperty",
	    ZFSJNI_PACKAGE_DATA "SnapDirProperty$SnapDir" },

	{ ZFS_PROP_VOLBLOCKSIZE, NULL, zjni_long_to_Long,
	    ZFSJNI_PACKAGE_DATA "VolBlockSizeProperty",
	    "java/lang/Long" },

	{ ZPROP_INVAL, NULL, NULL, NULL, NULL },
};

/*
 * Static functions
 */

static jobject
create_BasicProperty(JNIEnv *env, zfs_handle_t *zhp, zfs_prop_t prop,
    str_to_obj_f convert_str, uint64_to_obj_f convert_uint64,
    char *propClass, char *valueClass)
{
	jobject propertyObject = NULL;
	char source[ZFS_MAX_DATASET_NAME_LEN];
	zprop_source_t srctype;
	jobject propValue = NULL;

	if (convert_str != NULL) {
		char propbuf[ZFS_MAXPROPLEN];
		int result = zfs_prop_get(zhp, prop, propbuf,
		    sizeof (propbuf), &srctype, source, sizeof (source), 1);

		if (result == 0)
			propValue = convert_str(env, propbuf);
	} else {
		uint64_t value;
		int result = zfs_prop_get_numeric(
		    zhp, prop, &value, &srctype, source, sizeof (source));

		if (result == 0)
			propValue = convert_uint64(env, value);
	}

	if (propValue != NULL) {

		jmethodID constructor;
		char signature[1024];
		jclass class = (*env)->FindClass(env, propClass);

		jstring propName = (*env)->NewStringUTF(
		    env, zfs_prop_to_name(prop));

		jboolean readOnly = zfs_prop_readonly(prop) ?
		    JNI_TRUE : JNI_FALSE;

		if (srctype == ZPROP_SRC_INHERITED) {

			jstring propSource = (*env)->NewStringUTF(env, source);

			(void) snprintf(signature, sizeof (signature),
			    "(Ljava/lang/String;L%s;ZLjava/lang/String;)V",
			    valueClass);

			constructor = (*env)->GetMethodID(
			    env, class, "<init>", signature);

			propertyObject = (*env)->NewObject(
			    env, class, constructor, propName, propValue,
			    readOnly, propSource);
		} else {
			jobject lineage = zjni_int_to_Lineage(env, srctype);

			(void) snprintf(signature, sizeof (signature),
			    "(Ljava/lang/String;L%s;ZL"
			    ZFSJNI_PACKAGE_DATA "Property$Lineage;)V",
			    valueClass);

			constructor = (*env)->GetMethodID(
			    env, class, "<init>", signature);

			propertyObject = (*env)->NewObject(
			    env, class, constructor, propName, propValue,
			    readOnly, lineage);
		}
	}

	return (propertyObject);
}

static jobject
create_BooleanProperty(JNIEnv *env, zfs_handle_t *zhp, zfs_prop_t prop)
{
	return (create_BasicProperty(env, zhp, prop, NULL, zjni_int_to_boolean,
	    ZFSJNI_PACKAGE_DATA "BooleanProperty", "java/lang/Boolean"));
}

static jobject
create_LongProperty(JNIEnv *env, zfs_handle_t *zhp, zfs_prop_t prop)
{
	return (create_BasicProperty(env, zhp, prop, NULL, zjni_long_to_Long,
	    ZFSJNI_PACKAGE_DATA "LongProperty", "java/lang/Long"));
}

static jobject
create_StringProperty(JNIEnv *env, zfs_handle_t *zhp, zfs_prop_t prop)
{
	return (create_BasicProperty(env, zhp, prop, str_to_string, NULL,
	    ZFSJNI_PACKAGE_DATA "StringProperty", "java/lang/String"));
}

static jobject
create_ObjectProperty(JNIEnv *env, zfs_handle_t *zhp, zfs_prop_t prop,
    str_to_obj_f convert_str, uint64_to_obj_f convert_uint64,
    char *propClass, char *valueClass)
{
	jobject propertyObject = NULL;
	char source[ZFS_MAX_DATASET_NAME_LEN];
	zprop_source_t srctype;
	jobject propValue = NULL;

	if (convert_str != NULL) {
		char propbuf[ZFS_MAXPROPLEN];
		int result = zfs_prop_get(zhp, prop, propbuf,
		    sizeof (propbuf), &srctype, source, sizeof (source), 1);

		if (result == 0)
			propValue = convert_str(env, propbuf);
	} else {
		uint64_t value;
		int result = zfs_prop_get_numeric(
		    zhp, prop, &value, &srctype, source, sizeof (source));

		if (result == 0)
			propValue = convert_uint64(env, value);
	}

	if (propValue != NULL) {

		jmethodID constructor;
		char signature[1024];
		jclass class = (*env)->FindClass(env, propClass);

		if (srctype == ZPROP_SRC_INHERITED) {

			jstring propSource = (*env)->NewStringUTF(env, source);

			(void) snprintf(signature, sizeof (signature),
			    "(L%s;Ljava/lang/String;)V", valueClass);

			constructor = (*env)->GetMethodID(
			    env, class, "<init>", signature);

			propertyObject = (*env)->NewObject(env,
			    class, constructor, propValue, propSource);

		} else {
			jobject lineage = zjni_int_to_Lineage(env, srctype);

			(void) snprintf(signature, sizeof (signature),
			    "(L%s;L" ZFSJNI_PACKAGE_DATA "Property$Lineage;)V",
			    valueClass);

			constructor = (*env)->GetMethodID(
			    env, class, "<init>", signature);

			propertyObject = (*env)->NewObject(env,
			    class, constructor, propValue, lineage);
		}
	}

	return (propertyObject);
}

static jobject
create_default_BasicProperty(JNIEnv *env, zfs_prop_t prop,
    str_to_obj_f convert_str, uint64_to_obj_f convert_uint64,
    char *propClass, char *valueClass)
{
	jobject propertyObject = NULL;

	if (!zfs_prop_readonly(prop)) {
		jobject propValue;

		if (convert_str != NULL) {
			char *propbuf = (char *)zfs_prop_default_string(prop);
			propValue = convert_str(env, propbuf);
		} else {
			uint64_t value = zfs_prop_default_numeric(prop);
			propValue = convert_uint64(env, value);
		}

		if (propValue != NULL) {
			char signature[1024];
			jmethodID constructor;

			jstring propName =
			    (*env)->NewStringUTF(env, zfs_prop_to_name(prop));

			jboolean readOnly = zfs_prop_readonly(prop) ?
			    JNI_TRUE : JNI_FALSE;

			jclass class = (*env)->FindClass(env, propClass);
			jobject lineage =
			    zjni_int_to_Lineage(env, ZPROP_SRC_DEFAULT);

			(void) snprintf(signature, sizeof (signature),
			    "(Ljava/lang/String;L%s;ZL" ZFSJNI_PACKAGE_DATA
			    "Property$Lineage;)V", valueClass);

			constructor = (*env)->GetMethodID(
			    env, class, "<init>", signature);

			propertyObject = (*env)->NewObject(
			    env, class, constructor,
			    propName, propValue, readOnly, lineage);
		}
	}

	return (propertyObject);
}

static jobject
create_default_BooleanProperty(JNIEnv *env, zfs_prop_t prop)
{
	return (create_default_BasicProperty(env, prop, NULL,
	    zjni_int_to_boolean, ZFSJNI_PACKAGE_DATA "BooleanProperty",
	    "java/lang/Boolean"));
}

static jobject
create_default_LongProperty(JNIEnv *env, zfs_prop_t prop)
{
	return (create_default_BasicProperty(env, prop, NULL,
	    zjni_long_to_Long, ZFSJNI_PACKAGE_DATA "LongProperty",
	    "java/lang/Long"));
}

static jobject
create_default_StringProperty(JNIEnv *env, zfs_prop_t prop)
{
	return (create_default_BasicProperty(env, prop, str_to_string, NULL,
	    ZFSJNI_PACKAGE_DATA "StringProperty", "java/lang/String"));
}

static jobject
create_default_ObjectProperty(JNIEnv *env, zfs_prop_t prop,
    str_to_obj_f convert_str, uint64_to_obj_f convert_uint64,
    char *propClass, char *valueClass)
{
	jobject propertyObject = NULL;

	if (!zfs_prop_readonly(prop)) {
		jobject propValue;

		if (convert_str != NULL) {
			char *propbuf = (char *)zfs_prop_default_string(prop);
			propValue = convert_str(env, propbuf);
		} else {
			uint64_t value = zfs_prop_default_numeric(prop);
			propValue = convert_uint64(env, value);
		}

		if (propValue != NULL) {
			char signature[1024];
			jmethodID constructor;

			jclass class = (*env)->FindClass(env, propClass);
			jobject lineage =
			    zjni_int_to_Lineage(env, ZPROP_SRC_DEFAULT);

			(void) snprintf(signature, sizeof (signature),
			    "(L%s;L" ZFSJNI_PACKAGE_DATA "Property$Lineage;)V",
			    valueClass);

			constructor = (*env)->GetMethodID(
			    env, class, "<init>", signature);

			propertyObject = (*env)->NewObject(
			    env, class, constructor, propValue, lineage);
		}
	}

	return (propertyObject);
}

static jobject
str_to_enum_element(JNIEnv *env, char *str, char *valueClass)
{
	char signature[1024];
	jmethodID method_valueOf;

	jstring utf = (*env)->NewStringUTF(env, str);
	jclass class = (*env)->FindClass(env, valueClass);

	(void) snprintf(signature, sizeof (signature),
	    "(Ljava/lang/String;)L%s;", valueClass);

	method_valueOf = (*env)->GetStaticMethodID(
	    env, class, "valueOf", signature);

	return (*env)->CallStaticObjectMethod(env, class, method_valueOf, utf);
}

static jobject
str_to_aclinherit(JNIEnv *env, char *str)
{
	return (str_to_enum_element(env, str,
	    ZFSJNI_PACKAGE_DATA "AclInheritProperty$AclInherit"));
}

static jobject
str_to_aclmode(JNIEnv *env, char *str)
{
	return (str_to_enum_element(env, str,
	    ZFSJNI_PACKAGE_DATA "AclModeProperty$AclMode"));
}

static jobject
str_to_checksum(JNIEnv *env, char *str)
{
	return (str_to_enum_element(env, str,
	    ZFSJNI_PACKAGE_DATA "ChecksumProperty$Checksum"));
}

static jobject
str_to_compression(JNIEnv *env, char *str)
{
	return (str_to_enum_element(env, str,
	    ZFSJNI_PACKAGE_DATA "CompressionProperty$Compression"));
}

static jobject
str_to_snapdir(JNIEnv *env, char *str)
{
	return (str_to_enum_element(env, str,
	    ZFSJNI_PACKAGE_DATA "SnapDirProperty$SnapDir"));
}

static jobject
str_to_string(JNIEnv *env, char *str)
{
	return (*env)->NewStringUTF(env, str);
}

/*
 * Package-private functions
 */

jobject
zjni_get_default_property(JNIEnv *env, zfs_prop_t prop)
{
	int i;
	for (i = 0; props_boolean[i] != ZPROP_INVAL; i++) {
		if (prop == props_boolean[i]) {
			return (create_default_BooleanProperty(env, prop));
		}
	}

	for (i = 0; props_long[i] != ZPROP_INVAL; i++) {
		if (prop == props_long[i]) {
			return (create_default_LongProperty(env, prop));
		}
	}

	for (i = 0; props_string[i] != ZPROP_INVAL; i++) {
		if (prop == props_string[i]) {
			return (create_default_StringProperty(env, prop));
		}
	}

	for (i = 0; props_custom[i].prop != ZPROP_INVAL; i++) {
		if (prop == props_custom[i].prop) {
			return create_default_ObjectProperty(env,
			    props_custom[i].prop,
			    props_custom[i].convert_str,
			    props_custom[i].convert_uint64,
			    props_custom[i].propClass,
			    props_custom[i].valueClass);
		}
	}

	return (NULL);
}

static int
zjni_get_property_from_name_cb(int prop, void *cb)
{
	const char *name = cb;

	if (strcasecmp(name, zfs_prop_to_name(prop)) == 0)
		return (prop);

	return (ZPROP_CONT);
}

zfs_prop_t
zjni_get_property_from_name(const char *name)
{
	zfs_prop_t prop;

	prop = zprop_iter(zjni_get_property_from_name_cb, (void *)name,
	    B_FALSE, B_FALSE, ZFS_TYPE_DATASET);
	return (prop == ZPROP_CONT ? ZPROP_INVAL : prop);
}

jobject
zjni_int_to_Lineage(JNIEnv *env, zprop_source_t srctype)
{
	/* zprop_source_t to Property$Lineage map */
	static zjni_field_mapping_t lineage_map[] = {
		{ ZPROP_SRC_NONE, "ZFS_PROP_LINEAGE_NOTINHERITABLE" },
		{ ZPROP_SRC_DEFAULT, "ZFS_PROP_LINEAGE_DEFAULT" },
		{ ZPROP_SRC_LOCAL, "ZFS_PROP_LINEAGE_LOCAL" },
		{ ZPROP_SRC_TEMPORARY, "ZFS_PROP_LINEAGE_TEMPORARY" },
		{ ZPROP_SRC_INHERITED, "ZFS_PROP_LINEAGE_INHERITED" }
	};

	return (zjni_int_to_enum(env, srctype,
	    ZFSJNI_PACKAGE_DATA "Property$Lineage",
	    "ZFS_PROP_LINEAGE_INHERITED", lineage_map));
}

jobjectArray
zjni_get_Dataset_properties(JNIEnv *env, zfs_handle_t *zhp)
{
	jobject prop;
	int i;

	/* Create an array list for the properties */
	zjni_ArrayList_t proplist_obj = {0};
	zjni_ArrayList_t *proplist = &proplist_obj;
	zjni_new_ArrayList(env, proplist);

	for (i = 0; props_boolean[i] != ZPROP_INVAL; i++) {
		/* Create property and add to list */
		prop = create_BooleanProperty(env, zhp, props_boolean[i]);

		/* Does this property apply to this object? */
		if (prop != NULL) {

			(*env)->CallBooleanMethod(
			    env, ((zjni_Object_t *)proplist)->object,
			    ((zjni_Collection_t *)proplist)->method_add, prop);
		} else {

			if ((*env)->ExceptionOccurred(env) != NULL) {
				return (NULL);
			}
#ifdef	DEBUG
			(void) fprintf(stderr, "Property %s is not appropriate "
			    "for %s\n", zfs_prop_to_name(props_boolean[i]),
			    zfs_get_name(zhp));
#endif
		}
	}

	for (i = 0; props_long[i] != ZPROP_INVAL; i++) {
		/* Create property and add to list */
		prop = create_LongProperty(env, zhp, props_long[i]);

		/* Does this property apply to this object? */
		if (prop != NULL) {

			(*env)->CallBooleanMethod(
			    env, ((zjni_Object_t *)proplist)->object,
			    ((zjni_Collection_t *)proplist)->method_add, prop);
		} else {
			if ((*env)->ExceptionOccurred(env) != NULL) {
				return (NULL);
			}
#ifdef	DEBUG
			(void) fprintf(stderr, "Property %s is not appropriate "
			    "for %s\n", zfs_prop_to_name(props_long[i]),
			    zfs_get_name(zhp));
#endif
		}
	}

	for (i = 0; props_string[i] != ZPROP_INVAL; i++) {
		/* Create property and add to list */
		prop = create_StringProperty(env, zhp, props_string[i]);

		/* Does this property apply to this object? */
		if (prop != NULL) {

			(*env)->CallBooleanMethod(
			    env, ((zjni_Object_t *)proplist)->object,
			    ((zjni_Collection_t *)proplist)->method_add, prop);
		} else {
			if ((*env)->ExceptionOccurred(env) != NULL) {
				return (NULL);
			}
#ifdef	DEBUG
			(void) fprintf(stderr, "Property %s is not appropriate "
			    "for %s\n", zfs_prop_to_name(props_string[i]),
			    zfs_get_name(zhp));
#endif
		}
	}

	for (i = 0; props_custom[i].prop != ZPROP_INVAL; i++) {
		/* Create property and add to list */
		prop = create_ObjectProperty(env, zhp, props_custom[i].prop,
		    props_custom[i].convert_str, props_custom[i].convert_uint64,
		    props_custom[i].propClass, props_custom[i].valueClass);

		/* Does this property apply to this object? */
		if (prop != NULL) {

			(*env)->CallBooleanMethod(
			    env, ((zjni_Object_t *)proplist)->object,
			    ((zjni_Collection_t *)proplist)->method_add, prop);
		} else {
			if ((*env)->ExceptionOccurred(env) != NULL) {
				return (NULL);
			}
#ifdef	DEBUG
			(void) fprintf(stderr, "Property %s is not appropriate "
			    "for %s\n", zfs_prop_to_name(props_custom[i].prop),
			    zfs_get_name(zhp));
#endif
		}
	}

	return (zjni_Collection_to_array(env,
	    (zjni_Collection_t *)proplist, ZFSJNI_PACKAGE_DATA "Property"));
}
