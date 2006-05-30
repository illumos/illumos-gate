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

#ifndef _LIBZFS_JNI_UTIL_H
#define	_LIBZFS_JNI_UTIL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <jni.h>
#include <regex.h>
#include <libnvpair.h>
#include <libzfs.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Constants
 */

#define	ZFSJNI_PACKAGE_DATA	"com/sun/zfs/common/model/"

/*
 * Types
 */

typedef struct zjni_Object {
	jclass class;
	jobject object;
	jmethodID constructor;
} zjni_Object_t;

typedef struct zjni_Collection {
	zjni_Object_t super;

	jmethodID method_add;
	jmethodID method_size;
	jmethodID method_toArray;
} zjni_Collection_t;

typedef struct zjni_ArrayList {
	zjni_Collection_t super;
} zjni_ArrayList_t;

typedef struct zjni_DatasetSet {
	zjni_Collection_t super;
} zjni_DatasetSet_t;

typedef struct zjni_ArrayCallbackData {
	JNIEnv *env;
	zjni_Collection_t *list;
} zjni_ArrayCallbackData_t;

typedef struct zjni_field_mapping {
	int value;
	char *name;
} zjni_field_mapping_t;

/* Signature for function to free data */
typedef void (*zjni_free_f)(void *);

/*
 * Function prototypes
 */

void zjni_free_array(void **array, zjni_free_f);
void zjni_throw_exception(JNIEnv *, const char *, ...);
jstring zjni_get_matched_string(JNIEnv *, char *, regmatch_t *);
void zjni_get_dataset_from_snapshot(const char *, char *, size_t);
jobjectArray zjni_Collection_to_array(JNIEnv *, zjni_Collection_t *, char *);
void zjni_new_ArrayList(JNIEnv *, zjni_ArrayList_t *);
void zjni_new_DatasetSet(JNIEnv *, zjni_DatasetSet_t *);
jobject zjni_int_to_boolean(JNIEnv *, uint64_t);
jobject zjni_int_to_enum(
    JNIEnv *, int, char *, char *, zjni_field_mapping_t *);
jobject zjni_str_to_long(JNIEnv *, char *);
jobject zjni_long_to_Long(JNIEnv *, uint64_t);
jobject zjni_str_to_date(JNIEnv *, char *);
jobjectArray zjni_c_string_array_to_java(JNIEnv *, char **, int);
char **zjni_java_string_array_to_c(JNIEnv *, jobjectArray);
int zjni_count_elements(void **);
nvpair_t *zjni_nvlist_walk_nvpair(
	nvlist_t *, const char *, data_type_t, nvpair_t *);

extern libzfs_handle_t *g_zfs;

#ifdef __cplusplus
}
#endif

#endif /* _LIBZFS_JNI_UTIL_H */
