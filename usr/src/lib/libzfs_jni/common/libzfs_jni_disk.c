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

#include "libzfs_jni_disk.h"

/*
 * Function prototypes
 */

static jobject create_DiskDeviceBean(JNIEnv *, dmgt_disk_t *);
static jobject get_SliceUsage_Use(JNIEnv *, char *);
static jobject create_SliceUsage(JNIEnv *env, dmgt_slice_t *sp);
static jobject create_SliceDeviceBean(JNIEnv *env, dmgt_slice_t *sp);
static jobjectArray create_SliceDeviceBean_array(JNIEnv *, dmgt_slice_t **);

/*
 * Static functions
 */

static jobject
create_DiskDeviceBean(JNIEnv *env, dmgt_disk_t *dp)
{
	jobject disk = NULL;

	int naliases = zjni_count_elements((void **)dp->aliases);
	jobjectArray aliases = zjni_c_string_array_to_java(
	    env, dp->aliases, naliases);
	if (aliases != NULL) {
		jobjectArray slices = create_SliceDeviceBean_array(env,
		    dp->slices);
		if (slices != NULL) {
			jstring nameUTF = (*env)->NewStringUTF(env, dp->name);

			jboolean in_use = dp->in_use ? JNI_TRUE : JNI_FALSE;

			jclass class_DiskDeviceBean = (*env)->FindClass(
			    env, ZFSJNI_PACKAGE_DATA "DiskDeviceBean");

			jmethodID constructor =
			    (*env)->GetMethodID(env, class_DiskDeviceBean,
				"<init>",
				"(JLjava/lang/String;[Ljava/lang/String;[L"
				ZFSJNI_PACKAGE_DATA "SliceDeviceBean;Z)V");

			disk = (*env)->NewObject(env, class_DiskDeviceBean,
			    constructor, dp->size, nameUTF, aliases, slices,
			    in_use);
		}
	}

	return (disk);
}

static jobject
get_SliceUsage_Use(JNIEnv *env, char *dm_usage)
{
	jobject enumVal = NULL;

	if (dm_usage != NULL) {
		jclass class_SliceUsage_Use = (*env)->FindClass(
		    env, ZFSJNI_PACKAGE_DATA "SliceUsage$Use");

		jfieldID id = (*env)->GetStaticFieldID(env,
		    class_SliceUsage_Use,
		    dm_usage, "L" ZFSJNI_PACKAGE_DATA "SliceUsage$Use;");

		if (id != NULL) {
			/* Retrieve the proper SliceUsage$Use enum value */
			enumVal = (*env)->GetStaticObjectField(
			    env, class_SliceUsage_Use, id);
#ifdef	DEBUG
		} else {
			(void) fprintf(stderr, "Unknown slice usage: %s\n",
			    dm_usage);
#endif /* DEBUG */
		}
	}

	return (enumVal);
}

static jobject
create_SliceUsage(JNIEnv *env, dmgt_slice_t *sp)
{
	jobject usage = NULL;
	if (sp->used_name != NULL) {
		jobject use = get_SliceUsage_Use(env, sp->used_name);

		if (use != NULL) {
			jstring usedByUTF =
			    (*env)->NewStringUTF(env, sp->used_by);

			jclass class_SliceUsage = (*env)->FindClass(
			    env, ZFSJNI_PACKAGE_DATA "SliceUsage");

			jmethodID constructor =
			    (*env)->GetMethodID(env, class_SliceUsage, "<init>",
				"(L" ZFSJNI_PACKAGE_DATA
				"SliceUsage$Use;Ljava/lang/String;)V");

			usage = (*env)->NewObject(env,
			    class_SliceUsage, constructor, use, usedByUTF);
		}
	}

	return (usage);
}

static jobject
create_SliceDeviceBean(JNIEnv *env, dmgt_slice_t *sp)
{
	jobject slice = NULL;

	/* May be NULL if unused */
	jobject usage = create_SliceUsage(env, sp);

	jstring nameUTF = (*env)->NewStringUTF(env, sp->name);

	jclass class_SliceDeviceBean = (*env)->FindClass(
	    env, ZFSJNI_PACKAGE_DATA "SliceDeviceBean");

	jmethodID constructor =
	    (*env)->GetMethodID(env, class_SliceDeviceBean, "<init>",
		"(JLjava/lang/String;JL" ZFSJNI_PACKAGE_DATA "SliceUsage;)V");

	slice = (*env)->NewObject(env, class_SliceDeviceBean,
	    constructor, sp->size, nameUTF, sp->start, usage);

	return (slice);
}

static jobjectArray
create_SliceDeviceBean_array(JNIEnv *env, dmgt_slice_t **slices)
{
	/* Create an array list */
	zjni_ArrayList_t list_class = {0};
	zjni_ArrayList_t *list_class_p = &list_class;
	zjni_new_ArrayList(env, list_class_p);

	if (slices != NULL) {
		int i;
		for (i = 0; slices[i] != NULL; i++) {
			dmgt_slice_t *slice = slices[i];
			jobject obj;
			obj = create_SliceDeviceBean(env, slice);
			if (obj != NULL) {
				(*env)->CallBooleanMethod(env,
				    ((zjni_Object_t *)list_class_p)->object,
				    ((zjni_Collection_t *)list_class_p)->
				    method_add, obj);
			}
		}
	}

	return (zjni_Collection_to_array(
	    env, (zjni_Collection_t *)list_class_p,
	    ZFSJNI_PACKAGE_DATA "SliceDeviceBean"));
}

/*
 * Package-private functions
 */

int
zjni_create_add_DiskDevice(dmgt_disk_t *dp, void *data)
{
	JNIEnv *env = ((zjni_ArrayCallbackData_t *)data)->env;
	zjni_Collection_t *list = ((zjni_ArrayCallbackData_t *)data)->list;
	jobject disk = create_DiskDeviceBean(env, dp);

	/* Add disk to zjni_ArrayList */
	(*env)->CallBooleanMethod(env, ((zjni_Object_t *)list)->object,
	    ((zjni_Collection_t *)list)->method_add, disk);

	return (0);
}
