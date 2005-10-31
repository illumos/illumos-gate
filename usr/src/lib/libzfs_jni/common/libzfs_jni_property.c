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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "libzfs_jni_property.h"
#include "libzfs_jni_util.h"
#include <strings.h>

/*
 * Function prototypes
 */

static jobject create_BooleanProperty(JNIEnv *, zfs_handle_t *, zfs_prop_t);
static jobject create_ChecksumProperty(JNIEnv *, zfs_handle_t *);
static jobject create_CompressionProperty(JNIEnv *, zfs_handle_t *);
static jobject create_DateProperty(JNIEnv *, zfs_handle_t *, zfs_prop_t);
static jobject create_LongProperty(JNIEnv *, zfs_handle_t *, zfs_prop_t);
static jobject create_RecordSizeProperty(JNIEnv *, zfs_handle_t *);
static jobject create_StringProperty(JNIEnv *, zfs_handle_t *, zfs_prop_t);
static jobject str_to_checksum(JNIEnv *, char *);
static jobject str_to_compression(JNIEnv *, char *);
static jobject create_default_BooleanProperty(JNIEnv *, zfs_prop_t);
static jobject create_default_LongProperty(JNIEnv *, zfs_prop_t);
static jobject create_default_StringProperty(JNIEnv *, zfs_prop_t);
static jobject create_default_MountPointProperty(JNIEnv *);
static jobject create_default_ShareNFSProperty(JNIEnv *);
static jobject create_default_ChecksumProperty(JNIEnv *);
static jobject create_default_CompressionProperty(JNIEnv *);
static jobject create_default_RecordSizeProperty(JNIEnv *);

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
	ZFS_PROP_INVAL
};

zfs_prop_t props_long[] = {
	ZFS_PROP_AVAILABLE,
	ZFS_PROP_QUOTA,
	/*	ZFS_PROP_RATIO, */
	ZFS_PROP_REFERENCED,
	ZFS_PROP_RESERVATION,
	ZFS_PROP_USED,
	ZFS_PROP_VOLSIZE,
	ZFS_PROP_INVAL
};

zfs_prop_t props_string[] = {
	ZFS_PROP_ORIGIN,
	/*	ZFS_PROP_TYPE, */
	ZFS_PROP_INVAL
};

/*
 * Static functions
 */

static jobject
create_BooleanProperty(JNIEnv *env, zfs_handle_t *zhp, zfs_prop_t prop)
{
	jobject propertyObject = NULL;
	char source[ZFS_MAXNAMELEN];
	uint64_t value;
	zfs_source_t srctype;

	int result = zfs_prop_get_numeric(zhp, prop, &value,
	    &srctype, source, sizeof (source));

	if (result == 0) {
		jclass class_BooleanProperty = (*env)->FindClass(env,
		    ZFSJNI_PACKAGE_DATA "BooleanProperty");

		jstring propName = (*env)->NewStringUTF(
		    env, zfs_prop_to_name(prop));
		jobject propValue = zjni_int_to_boolean(env, value);
		jboolean readOnly = zfs_prop_readonly(prop) ?
		    JNI_TRUE : JNI_FALSE;

		jmethodID constructor_BooleanProperty;

		if (srctype == ZFS_SRC_INHERITED) {

			jstring propSource = (*env)->NewStringUTF(env, source);
			constructor_BooleanProperty = (*env)->GetMethodID(
			    env, class_BooleanProperty, "<init>",
			    "(Ljava/lang/String;Ljava/lang/Boolean;ZL"
			    "java/lang/String;)V");

			propertyObject = (*env)->NewObject(
			    env, class_BooleanProperty,
			    constructor_BooleanProperty,
			    propName, propValue, readOnly, propSource);
		} else {
			jobject lineage = zjni_get_lineage(env, srctype);

			constructor_BooleanProperty = (*env)->GetMethodID(
			    env, class_BooleanProperty, "<init>",
			    "(Ljava/lang/String;Ljava/lang/Boolean;ZL"
			    ZFSJNI_PACKAGE_DATA "Property$Lineage;)V");

			propertyObject = (*env)->NewObject(
			    env, class_BooleanProperty,
			    constructor_BooleanProperty,
			    propName, propValue, readOnly, lineage);
		}
	}

	return (propertyObject);
}

static jobject
create_ChecksumProperty(JNIEnv *env, zfs_handle_t *zhp)
{
	jobject propertyObject = NULL;
	char propbuf[ZFS_MAXPROPLEN];
	char source[ZFS_MAXNAMELEN];
	zfs_source_t srctype;

	int result = zfs_prop_get(zhp, ZFS_PROP_CHECKSUM,
	    propbuf, sizeof (propbuf), &srctype, source, sizeof (source), 1);

	if (result == 0) {
		jobject propValue = str_to_checksum(env, propbuf);

		if (propValue != NULL) {

			jclass class_ChecksumProperty = (*env)->FindClass(env,
			    ZFSJNI_PACKAGE_DATA "ChecksumProperty");

			jmethodID constructor_ChecksumProperty;

			if (srctype == ZFS_SRC_INHERITED) {

				jstring propSource = (*env)->NewStringUTF(env,
				    source);
				constructor_ChecksumProperty =
				    (*env)->GetMethodID(
					env, class_ChecksumProperty, "<init>",
					"(L" ZFSJNI_PACKAGE_DATA
					"ChecksumProperty$Checksum;Ljava/lang/"
					"String;)V");

				propertyObject = (*env)->NewObject(env,
				    class_ChecksumProperty,
				    constructor_ChecksumProperty,
				    propValue, propSource);

			} else {
				jobject lineage =
				    zjni_get_lineage(env, srctype);
				constructor_ChecksumProperty =
				    (*env)->GetMethodID(
					env, class_ChecksumProperty, "<init>",
					"(L" ZFSJNI_PACKAGE_DATA
					"ChecksumProperty$Checksum;L"
					ZFSJNI_PACKAGE_DATA
					"Property$Lineage;)V");

				propertyObject = (*env)->NewObject(env,
				    class_ChecksumProperty,
				    constructor_ChecksumProperty,
				    propValue, lineage);
			}
		}
	}

	return (propertyObject);
}

static jobject
create_CompressionProperty(JNIEnv *env, zfs_handle_t *zhp)
{
	jobject propertyObject = NULL;
	char propbuf[ZFS_MAXPROPLEN];
	char source[ZFS_MAXNAMELEN];
	zfs_source_t srctype;

	int result = zfs_prop_get(zhp, ZFS_PROP_COMPRESSION,
	    propbuf, sizeof (propbuf), &srctype, source, sizeof (source), 1);

	if (result == 0) {
		jobject propValue = str_to_compression(env, propbuf);

		if (propValue != NULL) {

			jclass class_CompressionProperty =
			    (*env)->FindClass(env,
				ZFSJNI_PACKAGE_DATA "CompressionProperty");

			jmethodID constructor_CompressionProperty;

			if (srctype == ZFS_SRC_INHERITED) {

				jstring propSource = (*env)->NewStringUTF(env,
				    source);
				constructor_CompressionProperty =
				    (*env)->GetMethodID(
					env, class_CompressionProperty,
					"<init>",
					"(L" ZFSJNI_PACKAGE_DATA
					"CompressionProperty$Compression;Ljava/"
					"lang/String;)V");

				propertyObject = (*env)->NewObject(env,
				    class_CompressionProperty,
				    constructor_CompressionProperty,
				    propValue, propSource);
			} else {
				jobject lineage = zjni_get_lineage(env,
				    srctype);

				constructor_CompressionProperty =
				    (*env)->GetMethodID(
					env, class_CompressionProperty,
					"<init>",
					"(L" ZFSJNI_PACKAGE_DATA
					"CompressionProperty$Compression;L"
					ZFSJNI_PACKAGE_DATA
					"Property$Lineage;)V");

				propertyObject = (*env)->NewObject(env,
				    class_CompressionProperty,
				    constructor_CompressionProperty,
				    propValue, lineage);
			}
		}
	}

	return (propertyObject);
}

static jobject
create_DateProperty(JNIEnv *env, zfs_handle_t *zhp, zfs_prop_t prop)
{
	jobject propertyObject = NULL;
	char propbuf[ZFS_MAXPROPLEN];
	char source[ZFS_MAXNAMELEN];
	zfs_source_t srctype;

	int result = zfs_prop_get(zhp, prop, propbuf, sizeof (propbuf),
	    &srctype, source, sizeof (source), 1);

	if (result == 0) {

		jobject propValue = zjni_str_to_date(env, propbuf);
		if (propValue != NULL) {

			jclass class_DateProperty = (*env)->FindClass(env,
			    ZFSJNI_PACKAGE_DATA "DateProperty");

			jstring propName = (*env)->NewStringUTF(
			    env, zfs_prop_to_name(prop));
			jboolean readOnly =
			    zfs_prop_readonly(prop) ? JNI_TRUE : JNI_FALSE;

			jmethodID constructor_DateProperty;

			if (srctype == ZFS_SRC_INHERITED) {

				jstring propSource = (*env)->NewStringUTF(env,
				    source);
				constructor_DateProperty = (*env)->GetMethodID(
				    env, class_DateProperty, "<init>",
				    "(Ljava/lang/String;Ljava/util/Date;ZL"
				    "java/lang/String;)V");

				propertyObject = (*env)->NewObject(
				    env, class_DateProperty,
				    constructor_DateProperty,
				    propName, propValue, readOnly, propSource);
			} else {
				jobject lineage = zjni_get_lineage(env,
				    srctype);

				constructor_DateProperty = (*env)->GetMethodID(
				    env, class_DateProperty, "<init>",
				    "(Ljava/lang/String;Ljava/util/Date;ZL"
				    ZFSJNI_PACKAGE_DATA "Property$Lineage;)V");

				propertyObject = (*env)->NewObject(
				    env, class_DateProperty,
				    constructor_DateProperty,
				    propName, propValue, readOnly, lineage);
			}
		}
	}

	return (propertyObject);
}

static jobject
create_LongProperty(JNIEnv *env, zfs_handle_t *zhp, zfs_prop_t prop)
{
	jobject propertyObject = NULL;
	char propbuf[ZFS_MAXPROPLEN];
	char source[ZFS_MAXNAMELEN];
	zfs_source_t srctype;

	int result = zfs_prop_get(zhp, prop, propbuf, sizeof (propbuf),
	    &srctype, source, sizeof (source), 1);

	if (result == 0) {

		jobject propValue = zjni_str_to_long(env, propbuf);
		if (propValue != NULL) {

			jclass class_LongProperty = (*env)->FindClass(env,
			    ZFSJNI_PACKAGE_DATA "LongProperty");

			jstring propName = (*env)->NewStringUTF(
			    env, zfs_prop_to_name(prop));
			jboolean readOnly =
			    zfs_prop_readonly(prop) ? JNI_TRUE : JNI_FALSE;

			jmethodID constructor_LongProperty;

			if (srctype == ZFS_SRC_INHERITED) {

				jstring propSource =
				    (*env)->NewStringUTF(env, source);
				constructor_LongProperty = (*env)->GetMethodID(
				    env, class_LongProperty, "<init>",
				    "(Ljava/lang/String;Ljava/lang/Long;ZL"
				    "java/lang/String;)V");

				propertyObject = (*env)->NewObject(
				    env, class_LongProperty,
				    constructor_LongProperty,
				    propName, propValue, readOnly, propSource);
			} else {
				jobject lineage = zjni_get_lineage(env,
				    srctype);

				constructor_LongProperty = (*env)->GetMethodID(
				    env, class_LongProperty, "<init>",
				    "(Ljava/lang/String;Ljava/lang/Long;ZL"
				    ZFSJNI_PACKAGE_DATA "Property$Lineage;)V");

				propertyObject = (*env)->NewObject(
				    env, class_LongProperty,
				    constructor_LongProperty,
				    propName, propValue, readOnly, lineage);
			}
		}
	}

	return (propertyObject);
}

static jobject
create_RecordSizeProperty(JNIEnv *env, zfs_handle_t *zhp)
{
	jobject propertyObject = NULL;
	char propbuf[ZFS_MAXPROPLEN];
	char source[ZFS_MAXNAMELEN];
	zfs_source_t srctype;

	int result = zfs_prop_get(zhp, ZFS_PROP_RECORDSIZE,
	    propbuf, sizeof (propbuf), &srctype, source, sizeof (source), 1);

	if (result == 0) {

		jobject propValue = zjni_str_to_long(env, propbuf);
		if (propValue != NULL) {

			jclass class_RecordSizeProperty = (*env)->FindClass(env,
			    ZFSJNI_PACKAGE_DATA "RecordSizeProperty");

			jmethodID constructor_RecordSizeProperty;

			if (srctype == ZFS_SRC_INHERITED) {

				jstring propSource =
				    (*env)->NewStringUTF(env, source);
				constructor_RecordSizeProperty =
				    (*env)->GetMethodID(
					env, class_RecordSizeProperty, "<init>",
					"(Ljava/lang/Long;Ljava/lang/"
					"String;)V");

				propertyObject = (*env)->NewObject(env,
				    class_RecordSizeProperty,
				    constructor_RecordSizeProperty,
				    propValue, propSource);
			} else {
				jobject lineage =
				    zjni_get_lineage(env, srctype);

				constructor_RecordSizeProperty =
				    (*env)->GetMethodID(
					env, class_RecordSizeProperty, "<init>",
					"(Ljava/lang/Long;L"
					ZFSJNI_PACKAGE_DATA
					"Property$Lineage;)V");

				propertyObject = (*env)->NewObject(env,
				    class_RecordSizeProperty,
				    constructor_RecordSizeProperty,
				    propValue, lineage);
			}
		}
	}

	return (propertyObject);
}

static jobject
create_StringProperty(JNIEnv *env, zfs_handle_t *zhp, zfs_prop_t prop)
{
	jobject propertyObject = NULL;
	char propbuf[ZFS_MAXPROPLEN];
	char source[ZFS_MAXNAMELEN];
	zfs_source_t srctype;

	int result = zfs_prop_get(zhp, prop, propbuf, sizeof (propbuf),
	    &srctype, source, sizeof (source), 1);

	if (result == 0) {
		jmethodID constructor_StringProperty;

		jclass class_StringProperty =
		    (*env)->FindClass(env, ZFSJNI_PACKAGE_DATA
			"StringProperty");

		jstring propName =
		    (*env)->NewStringUTF(env, zfs_prop_to_name(prop));

		jobject propValue = (*env)->NewStringUTF(env, propbuf);
		jboolean readOnly = zfs_prop_readonly(prop) ?
		    JNI_TRUE : JNI_FALSE;

		if (srctype == ZFS_SRC_INHERITED) {

			jstring propSource = (*env)->NewStringUTF(env, source);
			constructor_StringProperty = (*env)->GetMethodID(
			    env, class_StringProperty, "<init>",
			    "(Ljava/lang/String;Ljava/lang/String;ZL"
			    "java/lang/String;)V");

			propertyObject = (*env)->NewObject(
			    env, class_StringProperty,
			    constructor_StringProperty,
			    propName, propValue, readOnly, propSource);
		} else {
			jobject lineage = zjni_get_lineage(env, srctype);

			constructor_StringProperty = (*env)->GetMethodID(
			    env, class_StringProperty, "<init>",
			    "(Ljava/lang/String;Ljava/lang/String;ZL"
			    ZFSJNI_PACKAGE_DATA "Property$Lineage;)V");

			propertyObject = (*env)->NewObject(
			    env, class_StringProperty,
			    constructor_StringProperty,
			    propName, propValue, readOnly, lineage);
		}
	}

	return (propertyObject);
}

static jobject
create_MountPointProperty(JNIEnv *env, zfs_handle_t *zhp)
{
	jobject propertyObject = NULL;
	char propbuf[ZFS_MAXPROPLEN];
	char source[ZFS_MAXNAMELEN];
	zfs_source_t srctype;

	int result = zfs_prop_get(zhp, ZFS_PROP_MOUNTPOINT,
	    propbuf, sizeof (propbuf), &srctype, source, sizeof (source), 1);

	if (result == 0) {
		jmethodID constructor_MountPointProperty;

		jclass class_MountPointProperty = (*env)->FindClass(
		    env, ZFSJNI_PACKAGE_DATA "MountPointProperty");

		jobject propValue = (*env)->NewStringUTF(env, propbuf);

		if (srctype == ZFS_SRC_INHERITED) {

			jstring propSource = (*env)->NewStringUTF(env, source);
			constructor_MountPointProperty = (*env)->GetMethodID(
			    env, class_MountPointProperty, "<init>",
			    "(Ljava/lang/String;Ljava/lang/String;)V");

			propertyObject = (*env)->NewObject(env,
			    class_MountPointProperty,
			    constructor_MountPointProperty,
			    propValue, propSource);
		} else {
			jobject lineage = zjni_get_lineage(env, srctype);

			constructor_MountPointProperty = (*env)->GetMethodID(
			    env, class_MountPointProperty, "<init>",
			    "(Ljava/lang/String;L"
			    ZFSJNI_PACKAGE_DATA "Property$Lineage;)V");

			propertyObject = (*env)->NewObject(env,
			    class_MountPointProperty,
			    constructor_MountPointProperty,
			    propValue, lineage);
		}
	}

	return (propertyObject);
}

static jobject
create_ShareNFSProperty(JNIEnv *env, zfs_handle_t *zhp)
{
	jobject propertyObject = NULL;
	char propbuf[ZFS_MAXPROPLEN];
	char source[ZFS_MAXNAMELEN];
	zfs_source_t srctype;

	int result = zfs_prop_get(zhp, ZFS_PROP_SHARENFS,
	    propbuf, sizeof (propbuf), &srctype, source, sizeof (source), 1);

	if (result == 0) {
		jmethodID constructor_ShareNFSProperty;

		jclass class_ShareNFSProperty = (*env)->FindClass(
		    env, ZFSJNI_PACKAGE_DATA "ShareNFSProperty");

		jobject propValue = (*env)->NewStringUTF(env, propbuf);

		if (srctype == ZFS_SRC_INHERITED) {

			jstring propSource = (*env)->NewStringUTF(env, source);
			constructor_ShareNFSProperty = (*env)->GetMethodID(
			    env, class_ShareNFSProperty, "<init>",
			    "(Ljava/lang/String;Ljava/lang/String;)V");

			propertyObject = (*env)->NewObject(
			    env, class_ShareNFSProperty,
			    constructor_ShareNFSProperty,
			    propValue, propSource);
		} else {
			jobject lineage = zjni_get_lineage(env, srctype);

			constructor_ShareNFSProperty = (*env)->GetMethodID(
			    env, class_ShareNFSProperty, "<init>",
			    "(Ljava/lang/String;L"
			    ZFSJNI_PACKAGE_DATA "Property$Lineage;)V");

			propertyObject = (*env)->NewObject(
			    env, class_ShareNFSProperty,
			    constructor_ShareNFSProperty,
			    propValue, lineage);
		}
	}

	return (propertyObject);
}

static jobject
str_to_checksum(JNIEnv *env, char *str)
{
	jclass class_Checksum = (*env)->FindClass(
	    env, ZFSJNI_PACKAGE_DATA "ChecksumProperty$Checksum");

	jmethodID method_valueOf = (*env)->GetStaticMethodID(
	    env, class_Checksum, "valueOf",
	    "(Ljava/lang/String;)L"
	    ZFSJNI_PACKAGE_DATA "ChecksumProperty$Checksum;");

	jstring utf = (*env)->NewStringUTF(env, str);

	return (*env)->CallStaticObjectMethod(
	    env, class_Checksum, method_valueOf, utf);
}

static jobject
str_to_compression(JNIEnv *env, char *str)
{
	jclass class_Compression = (*env)->FindClass(
	    env, ZFSJNI_PACKAGE_DATA "CompressionProperty$Compression");

	jmethodID method_valueOf = (*env)->GetStaticMethodID(
	    env, class_Compression, "valueOf",
	    "(Ljava/lang/String;)L"
	    ZFSJNI_PACKAGE_DATA "CompressionProperty$Compression;");

	jstring utf = (*env)->NewStringUTF(env, str);

	return (*env)->CallStaticObjectMethod(
	    env, class_Compression, method_valueOf, utf);
}

/*
 * Package-private functions
 */
jobject
zjni_get_default_property(JNIEnv *env, zfs_prop_t prop)
{
	int i;
	for (i = 0; props_boolean[i] != ZFS_PROP_INVAL; i++) {
		if (prop == props_boolean[i]) {
			return (create_default_BooleanProperty(env, prop));
		}
	}

	for (i = 0; props_long[i] != ZFS_PROP_INVAL; i++) {
		if (prop == props_long[i]) {
			return (create_default_LongProperty(env, prop));
		}
	}

	for (i = 0; props_string[i] != ZFS_PROP_INVAL; i++) {
		if (prop == props_string[i]) {
			return (create_default_StringProperty(env, prop));
		}
	}

	if (prop == ZFS_PROP_MOUNTPOINT) {
		return (create_default_MountPointProperty(env));
	}

	if (prop == ZFS_PROP_SHARENFS) {
		return (create_default_ShareNFSProperty(env));
	}

	if (prop == ZFS_PROP_CHECKSUM) {
		return (create_default_ChecksumProperty(env));
	}

	if (prop == ZFS_PROP_COMPRESSION) {
		return (create_default_CompressionProperty(env));
	}

	if (prop == ZFS_PROP_RECORDSIZE) {
		return (create_default_RecordSizeProperty(env));
	}

	return (NULL);
}

zfs_prop_t
zjni_get_property_from_name(const char *name)
{
	zfs_prop_t prop;
	for (prop = 0; prop < ZFS_NPROP_VISIBLE; prop++) {
		if (strcasecmp(name, zfs_prop_to_name(prop)) == 0) {
			return (prop);
		}
	}

	return (ZFS_PROP_INVAL);
}

jobject
zjni_get_lineage(JNIEnv *env, zfs_source_t srctype)
{
	char *field;
	jclass class_Lineage;
	jfieldID id;

	switch (srctype) {
	case ZFS_SRC_NONE:
		field = "ZFS_PROP_LINEAGE_NOTINHERITABLE";
		break;

	case ZFS_SRC_DEFAULT:
		field = "ZFS_PROP_LINEAGE_DEFAULT";
		break;

	case ZFS_SRC_LOCAL:
		field = "ZFS_PROP_LINEAGE_LOCAL";
		break;

	case ZFS_SRC_TEMPORARY:
		field = "ZFS_PROP_LINEAGE_TEMPORARY";
		break;

	default:
	case ZFS_SRC_INHERITED:
		field = "ZFS_PROP_LINEAGE_INHERITED";
		break;
	}

	class_Lineage = (*env)->FindClass(
	    env, ZFSJNI_PACKAGE_DATA "Property$Lineage");

	id = (*env)->GetStaticFieldID(env, class_Lineage,
	    field, "L" ZFSJNI_PACKAGE_DATA "Property$Lineage;");

	return (*env)->GetStaticObjectField(env, class_Lineage, id);
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

	for (i = 0; props_boolean[i] != ZFS_PROP_INVAL; i++) {
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

	for (i = 0; props_long[i] != ZFS_PROP_INVAL; i++) {
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

	for (i = 0; props_string[i] != ZFS_PROP_INVAL; i++) {
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

	prop = create_MountPointProperty(env, zhp);
	/* Does this property apply to this object? */
	if (prop != NULL) {

		(*env)->CallBooleanMethod(env,
		    ((zjni_Object_t *)proplist)->object,
		    ((zjni_Collection_t *)proplist)->method_add, prop);
	} else {
		if ((*env)->ExceptionOccurred(env) != NULL) {
			return (NULL);
		}
#ifdef	DEBUG
		(void) fprintf(stderr, "Property %s is not appropriate "
		    "for %s\n", zfs_prop_to_name(ZFS_PROP_MOUNTPOINT),
		    zfs_get_name(zhp));
#endif
	}

	prop = create_ShareNFSProperty(env, zhp);
	/* Does this property apply to this object? */
	if (prop != NULL) {

		(*env)->CallBooleanMethod(env,
		    ((zjni_Object_t *)proplist)->object,
		    ((zjni_Collection_t *)proplist)->method_add, prop);
	} else {
		if ((*env)->ExceptionOccurred(env) != NULL) {
			return (NULL);
		}
#ifdef	DEBUG
		(void) fprintf(stderr, "Property %s is not appropriate "
		    "for %s\n", zfs_prop_to_name(ZFS_PROP_SHARENFS),
		    zfs_get_name(zhp));
#endif
	}

	prop = create_ChecksumProperty(env, zhp);
	/* Does this property apply to this object? */
	if (prop != NULL) {

		(*env)->CallBooleanMethod(env,
		    ((zjni_Object_t *)proplist)->object,
		    ((zjni_Collection_t *)proplist)->method_add, prop);
	} else {
		if ((*env)->ExceptionOccurred(env) != NULL) {
			return (NULL);
		}
#ifdef	DEBUG
		(void) fprintf(stderr, "Property %s is not appropriate "
		    "for %s\n", zfs_prop_to_name(ZFS_PROP_CHECKSUM),
		    zfs_get_name(zhp));
#endif
	}

	prop = create_CompressionProperty(env, zhp);
	/* Does this property apply to this object? */
	if (prop != NULL) {

		(*env)->CallBooleanMethod(env,
		    ((zjni_Object_t *)proplist)->object,
		    ((zjni_Collection_t *)proplist)->method_add, prop);
	} else {
		if ((*env)->ExceptionOccurred(env) != NULL) {
			return (NULL);
		}
#ifdef	DEBUG
		(void) fprintf(stderr, "Property %s is not appropriate "
		    "for %s\n", zfs_prop_to_name(ZFS_PROP_COMPRESSION),
		    zfs_get_name(zhp));
#endif
	}

	prop = create_RecordSizeProperty(env, zhp);
	/* Does this property apply to this object? */
	if (prop != NULL) {

		(*env)->CallBooleanMethod(env,
		    ((zjni_Object_t *)proplist)->object,
		    ((zjni_Collection_t *)proplist)->method_add, prop);
	} else {
		if ((*env)->ExceptionOccurred(env) != NULL) {
			return (NULL);
		}
#ifdef	DEBUG
		(void) fprintf(stderr, "Property %s is not appropriate "
		    "for %s\n", zfs_prop_to_name(ZFS_PROP_RECORDSIZE),
		    zfs_get_name(zhp));
#endif
	}

	prop = create_DateProperty(env, zhp, ZFS_PROP_CREATION);
	/* Does this property apply to this object? */
	if (prop != NULL) {

		(*env)->CallBooleanMethod(env,
		    ((zjni_Object_t *)proplist)->object,
		    ((zjni_Collection_t *)proplist)->method_add, prop);
	} else {
		if ((*env)->ExceptionOccurred(env) != NULL) {
			return (NULL);
		}
#ifdef	DEBUG
		(void) fprintf(stderr, "Property %s is not appropriate "
		    "for %s\n", zfs_prop_to_name(ZFS_PROP_CREATION),
		    zfs_get_name(zhp));
#endif
	}

	return (zjni_Collection_to_array(
	    env, (zjni_Collection_t *)proplist,
	    ZFSJNI_PACKAGE_DATA "Property"));
}

static jobject
create_default_BooleanProperty(JNIEnv *env, zfs_prop_t prop)
{
	jobject propertyObject = NULL;

	if (!zfs_prop_readonly(prop)) {

		jclass class_BooleanProperty = (*env)->FindClass(env,
		    ZFSJNI_PACKAGE_DATA "BooleanProperty");

		jmethodID constructor_BooleanProperty = (*env)->GetMethodID(
		    env, class_BooleanProperty, "<init>",
		    "(Ljava/lang/String;Ljava/lang/Boolean;ZL"
		    ZFSJNI_PACKAGE_DATA "Property$Lineage;)V");

		jstring propName =
		    (*env)->NewStringUTF(env, zfs_prop_to_name(prop));
		jobject propValue =
		    zjni_int_to_boolean(env, zfs_prop_default_numeric(prop));
		jboolean readOnly = zfs_prop_readonly(prop) ?
		    JNI_TRUE : JNI_FALSE;
		jobject lineage = zjni_get_lineage(env, ZFS_SRC_DEFAULT);

		propertyObject = (*env)->NewObject(
		    env, class_BooleanProperty, constructor_BooleanProperty,
		    propName, propValue, readOnly, lineage);
	}

	return (propertyObject);
}

static jobject
create_default_LongProperty(JNIEnv *env, zfs_prop_t prop)
{
	jobject propertyObject = NULL;

	if (!zfs_prop_readonly(prop)) {

		jclass class_LongProperty = (*env)->FindClass(env,
		    ZFSJNI_PACKAGE_DATA "LongProperty");

		jmethodID constructor_LongProperty = (*env)->GetMethodID(
		    env, class_LongProperty, "<init>",
		    "(Ljava/lang/String;Ljava/lang/Long;ZL"
		    ZFSJNI_PACKAGE_DATA "Property$Lineage;)V");

		jstring propName =
		    (*env)->NewStringUTF(env, zfs_prop_to_name(prop));
		jobject propValue =
		    zjni_long_to_Long(env, zfs_prop_default_numeric(prop));
		jboolean readOnly = zfs_prop_readonly(prop)
		    ? JNI_TRUE : JNI_FALSE;
		jobject lineage = zjni_get_lineage(env, ZFS_SRC_DEFAULT);

		propertyObject = (*env)->NewObject(
		    env, class_LongProperty, constructor_LongProperty,
		    propName, propValue, readOnly, lineage);
	}

	return (propertyObject);
}

static jobject
create_default_StringProperty(JNIEnv *env, zfs_prop_t prop)
{
	jobject propertyObject = NULL;

	if (zfs_prop_is_string(prop) && !zfs_prop_readonly(prop)) {

		char propbuf[ZFS_MAXPROPLEN];
		jclass class_StringProperty;
		jmethodID constructor_StringProperty;
		jstring propName;
		jobject propValue;
		jboolean readOnly;
		jobject lineage;

		zfs_prop_default_string(prop, propbuf, sizeof (propbuf));

		class_StringProperty =
		    (*env)->FindClass(env,
			ZFSJNI_PACKAGE_DATA "StringProperty");

		constructor_StringProperty = (*env)->GetMethodID(
		    env, class_StringProperty, "<init>",
		    "(Ljava/lang/String;Ljava/lang/String;ZL"
		    ZFSJNI_PACKAGE_DATA "Property$Lineage;)V");

		propName = (*env)->NewStringUTF(env, zfs_prop_to_name(prop));
		propValue = (*env)->NewStringUTF(env, propbuf);
		readOnly = zfs_prop_readonly(prop) ? JNI_TRUE : JNI_FALSE;
		lineage = zjni_get_lineage(env, ZFS_SRC_DEFAULT);

		propertyObject = (*env)->NewObject(
		    env, class_StringProperty, constructor_StringProperty,
		    propName, propValue, readOnly, lineage);
	}

	return (propertyObject);
}

static jobject
create_default_MountPointProperty(JNIEnv *env)
{
	jobject propertyObject = NULL;

	char propbuf[ZFS_MAXPROPLEN];
	jclass class_MountPointProperty;
	jmethodID constructor_MountPointProperty;
	jobject propValue;
	jobject lineage;

	zfs_prop_default_string(ZFS_PROP_MOUNTPOINT, propbuf, sizeof (propbuf));

	class_MountPointProperty = (*env)->FindClass(
	    env, ZFSJNI_PACKAGE_DATA "MountPointProperty");

	propValue = (*env)->NewStringUTF(env, propbuf);
	lineage = zjni_get_lineage(env, ZFS_SRC_DEFAULT);

	constructor_MountPointProperty = (*env)->GetMethodID(
	    env, class_MountPointProperty, "<init>",
	    "(Ljava/lang/String;L"
	    ZFSJNI_PACKAGE_DATA "Property$Lineage;)V");

	propertyObject = (*env)->NewObject(
	    env, class_MountPointProperty, constructor_MountPointProperty,
	    propValue, lineage);

	return (propertyObject);
}

static jobject
create_default_ShareNFSProperty(JNIEnv *env)
{
	jobject propertyObject = NULL;

	char propbuf[ZFS_MAXPROPLEN];
	jclass class_ShareNFSProperty;
	jmethodID constructor_ShareNFSProperty;
	jobject propValue;
	jobject lineage;

	zfs_prop_default_string(ZFS_PROP_SHARENFS, propbuf, sizeof (propbuf));

	class_ShareNFSProperty = (*env)->FindClass(
	    env, ZFSJNI_PACKAGE_DATA "ShareNFSProperty");

	propValue = (*env)->NewStringUTF(env, propbuf);
	lineage = zjni_get_lineage(env, ZFS_SRC_DEFAULT);

	constructor_ShareNFSProperty = (*env)->GetMethodID(
	    env, class_ShareNFSProperty, "<init>",
	    "(Ljava/lang/String;L"
	    ZFSJNI_PACKAGE_DATA "Property$Lineage;)V");

	propertyObject = (*env)->NewObject(
	    env, class_ShareNFSProperty, constructor_ShareNFSProperty,
	    propValue, lineage);

	return (propertyObject);
}

static jobject
create_default_ChecksumProperty(JNIEnv *env)
{
	jobject propertyObject = NULL;

	char propbuf[ZFS_MAXPROPLEN];
	jclass class_ChecksumProperty;
	jmethodID constructor_ChecksumProperty;
	jobject propValue;
	jobject lineage;

	zfs_prop_default_string(ZFS_PROP_CHECKSUM, propbuf, sizeof (propbuf));
	propValue = str_to_checksum(env, propbuf);

	class_ChecksumProperty = (*env)->FindClass(
	    env, ZFSJNI_PACKAGE_DATA "ChecksumProperty");

	lineage = zjni_get_lineage(env, ZFS_SRC_DEFAULT);

	constructor_ChecksumProperty = (*env)->GetMethodID(
	    env, class_ChecksumProperty, "<init>",
	    "(L" ZFSJNI_PACKAGE_DATA "ChecksumProperty$Checksum;L"
	    ZFSJNI_PACKAGE_DATA "Property$Lineage;)V");

	propertyObject = (*env)->NewObject(env,
	    class_ChecksumProperty, constructor_ChecksumProperty,
	    propValue, lineage);

	return (propertyObject);
}

static jobject
create_default_CompressionProperty(JNIEnv *env)
{
	jobject propertyObject = NULL;

	char propbuf[ZFS_MAXPROPLEN];
	jclass class_CompressionProperty;
	jmethodID constructor_CompressionProperty;
	jobject propValue;
	jobject lineage;

	zfs_prop_default_string(
	    ZFS_PROP_COMPRESSION, propbuf, sizeof (propbuf));
	propValue = str_to_compression(env, propbuf);

	class_CompressionProperty = (*env)->FindClass(
	    env, ZFSJNI_PACKAGE_DATA "CompressionProperty");

	lineage = zjni_get_lineage(env, ZFS_SRC_DEFAULT);

	constructor_CompressionProperty = (*env)->GetMethodID(
	    env, class_CompressionProperty, "<init>",
	    "(L" ZFSJNI_PACKAGE_DATA "CompressionProperty$Compression;L"
	    ZFSJNI_PACKAGE_DATA "Property$Lineage;)V");

	propertyObject = (*env)->NewObject(env,
	    class_CompressionProperty, constructor_CompressionProperty,
	    propValue, lineage);

	return (propertyObject);
}

static jobject
create_default_RecordSizeProperty(JNIEnv *env)
{
	jclass class_RecordSizeProperty = (*env)->FindClass(env,
	    ZFSJNI_PACKAGE_DATA "RecordSizeProperty");

	jmethodID constructor_RecordSizeProperty = (*env)->GetMethodID(
	    env, class_RecordSizeProperty, "<init>",
	    "(Ljava/lang/Long;L"
	    ZFSJNI_PACKAGE_DATA "Property$Lineage;)V");

	jobject propValue = zjni_long_to_Long(
	    env, zfs_prop_default_numeric(ZFS_PROP_RECORDSIZE));

	jobject lineage = zjni_get_lineage(env, ZFS_SRC_DEFAULT);

	jobject propertyObject = (*env)->NewObject(
	    env, class_RecordSizeProperty, constructor_RecordSizeProperty,
	    propValue, lineage);

	return (propertyObject);
}
